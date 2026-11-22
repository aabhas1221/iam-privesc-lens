"""Unit tests for the policy evaluator."""

from __future__ import annotations

import pytest

from iam_privesc_lens.policy import (
    Decision,
    PolicyParseError,
    PolicySet,
    action_matches,
    parse_policy_document,
    resource_matches,
)


def ps(*statements: dict, boundary: list[dict] | None = None, variables: dict | None = None) -> PolicySet:
    doc = {"Version": "2012-10-17", "Statement": list(statements)}
    b = parse_policy_document({"Statement": boundary}, name="boundary") if boundary else None
    return PolicySet([parse_policy_document(doc, name="p")], boundary=b, variables=variables or {})


@pytest.mark.parametrize(
    "pattern,action,expected",
    [
        ("*", "iam:CreateUser", True),
        ("iam:*", "iam:CreateUser", True),
        ("iam:*", "sts:AssumeRole", False),
        ("iam:Create*", "iam:CreatePolicyVersion", True),
        ("iam:Create*", "iam:DeletePolicy", False),
        ("IAM:createpolicyVERSION", "iam:CreatePolicyVersion", True),
        ("iam:?ttachUserPolicy", "iam:AttachUserPolicy", True),
        ("*:Get*", "secretsmanager:GetSecretValue", True),
        ("iam:PassRole", "iam:PassRoles", False),
    ],
)
def test_action_matching(pattern: str, action: str, expected: bool) -> None:
    assert action_matches(pattern, action) is expected


def test_resource_matching_is_case_sensitive() -> None:
    assert resource_matches("arn:aws:iam::1:role/ci-*", "arn:aws:iam::1:role/ci-build")
    assert not resource_matches("arn:aws:iam::1:role/CI-*", "arn:aws:iam::1:role/ci-build")
    assert resource_matches("arn:aws:s3:::bucket/*", "arn:aws:s3:::bucket/a/b")


def test_string_or_list_fields() -> None:
    single = ps({"Effect": "Allow", "Action": "iam:PassRole", "Resource": "*"})
    multi = ps({"Effect": "Allow", "Action": ["s3:GetObject", "iam:PassRole"], "Resource": ["*"]})
    assert single.evaluate("iam:PassRole").decision is Decision.ALLOWED
    assert multi.evaluate("iam:passrole").decision is Decision.ALLOWED


def test_single_statement_object() -> None:
    policy = parse_policy_document({"Statement": {"Effect": "Allow", "Action": "*", "Resource": "*"}})
    assert len(policy.statements) == 1


def test_implicit_deny() -> None:
    assert ps({"Effect": "Allow", "Action": "s3:*", "Resource": "*"}).evaluate("iam:CreateUser").decision is Decision.IMPLICIT_DENY


def test_explicit_deny_wins_regardless_of_order() -> None:
    allow = {"Effect": "Allow", "Action": "*", "Resource": "*"}
    deny = {"Effect": "Deny", "Action": "iam:*", "Resource": "*"}
    for order in ((allow, deny), (deny, allow)):
        p = ps(*order)
        assert p.evaluate("iam:AttachUserPolicy").decision is Decision.DENIED
        assert p.evaluate("s3:GetObject").decision is Decision.ALLOWED


def test_narrow_deny_does_not_block_any_resource_question() -> None:
    p = ps(
        {"Effect": "Allow", "Action": "iam:PassRole", "Resource": "*"},
        {"Effect": "Deny", "Action": "iam:PassRole", "Resource": "arn:aws:iam::1:role/admin"},
    )
    assert p.evaluate("iam:PassRole").decision is Decision.ALLOWED
    assert p.evaluate("iam:PassRole", "arn:aws:iam::1:role/admin").decision is Decision.DENIED
    assert p.evaluate("iam:PassRole", "arn:aws:iam::1:role/app").decision is Decision.ALLOWED


def test_not_action() -> None:
    p = ps({"Effect": "Allow", "NotAction": ["iam:*", "organizations:*"], "Resource": "*"})
    assert p.evaluate("iam:CreateUser").decision is Decision.IMPLICIT_DENY
    assert p.evaluate("lambda:CreateFunction").decision is Decision.ALLOWED
    assert p.evaluate("sts:AssumeRole").decision is Decision.ALLOWED


def test_deny_with_not_action() -> None:
    p = ps(
        {"Effect": "Allow", "Action": "*", "Resource": "*"},
        {"Effect": "Deny", "NotAction": "s3:*", "Resource": "*"},
    )
    assert p.evaluate("s3:GetObject").decision is Decision.ALLOWED
    assert p.evaluate("iam:CreateUser").decision is Decision.DENIED


def test_not_resource() -> None:
    p = ps({"Effect": "Allow", "Action": "iam:PassRole", "NotResource": "arn:aws:iam::1:role/admin"})
    assert p.evaluate("iam:PassRole", "arn:aws:iam::1:role/admin").decision is Decision.IMPLICIT_DENY
    assert p.evaluate("iam:PassRole", "arn:aws:iam::1:role/app").decision is Decision.ALLOWED
    assert p.evaluate("iam:PassRole").decision is Decision.ALLOWED


def test_conditional_allow_and_conditional_deny() -> None:
    cond = {"Bool": {"aws:MultiFactorAuthPresent": "true"}}
    p = ps({"Effect": "Allow", "Action": "iam:AttachUserPolicy", "Resource": "*", "Condition": cond})
    assert p.evaluate("iam:AttachUserPolicy").decision is Decision.CONDITIONAL
    p2 = ps(
        {"Effect": "Allow", "Action": "*", "Resource": "*"},
        {"Effect": "Deny", "Action": "iam:*", "Resource": "*", "Condition": cond},
    )
    assert p2.evaluate("iam:AttachUserPolicy").decision is Decision.CONDITIONAL
    assert p2.evaluate("s3:GetObject").decision is Decision.ALLOWED


def test_unconditional_allow_beats_conditional_allow() -> None:
    p = ps(
        {"Effect": "Allow", "Action": "iam:PassRole", "Resource": "*", "Condition": {"StringEquals": {"x": "y"}}},
        {"Effect": "Allow", "Action": "iam:PassRole", "Resource": "*"},
    )
    assert p.evaluate("iam:PassRole").decision is Decision.ALLOWED


def test_permission_boundary_limits_identity_policy() -> None:
    p = ps({"Effect": "Allow", "Action": "*", "Resource": "*"}, boundary=[{"Effect": "Allow", "Action": "s3:*", "Resource": "*"}])
    assert p.evaluate("s3:GetObject").decision is Decision.ALLOWED
    assert p.evaluate("iam:CreateUser").decision is Decision.IMPLICIT_DENY
    assert not p.is_full_admin()


def test_policy_variables() -> None:
    stmt = {"Effect": "Allow", "Action": "iam:CreateAccessKey", "Resource": "arn:aws:iam::1:user/${aws:username}"}
    p = ps(stmt, variables={"aws:username": "alice"})
    assert p.evaluate("iam:CreateAccessKey", "arn:aws:iam::1:user/alice").decision is Decision.ALLOWED
    assert p.evaluate("iam:CreateAccessKey", "arn:aws:iam::1:user/bob").decision is Decision.IMPLICIT_DENY


def test_evidence_records_statement() -> None:
    p = ps({"Sid": "Pass", "Effect": "Allow", "Action": "iam:PassRole", "Resource": "arn:aws:iam::1:role/x"})
    ev = p.evaluate("iam:PassRole")
    assert ev.allows[0].sid == "Pass"
    assert ev.granted_resources == ("arn:aws:iam::1:role/x",)


def test_full_admin_detection() -> None:
    assert ps({"Effect": "Allow", "Action": "*", "Resource": "*"}).is_full_admin()
    assert not ps({"Effect": "Allow", "Action": "iam:*", "Resource": "*"}).is_full_admin()
    assert not ps(
        {"Effect": "Allow", "Action": "*", "Resource": "*"},
        {"Effect": "Deny", "Action": "iam:*", "Resource": "*"},
    ).is_full_admin()


def test_url_encoded_document() -> None:
    encoded = "%7B%22Version%22%3A%222012-10-17%22%2C%22Statement%22%3A%5B%7B%22Effect%22%3A%22Allow%22%2C%22Action%22%3A%22s3%3A*%22%2C%22Resource%22%3A%22*%22%7D%5D%7D"
    policy = parse_policy_document(encoded)
    assert policy.statements[0].actions == ("s3:*",)


@pytest.mark.parametrize(
    "doc",
    [
        {},
        {"Statement": [{"Effect": "Maybe", "Action": "*"}]},
        {"Statement": [{"Effect": "Allow", "Action": "*", "NotAction": "iam:*"}]},
        {"Statement": [{"Effect": "Allow", "Resource": "*", "NotResource": "x"}]},
        {"Statement": "nope"},
        "not json",
    ],
)
def test_invalid_documents(doc: object) -> None:
    with pytest.raises(PolicyParseError):
        parse_policy_document(doc)
