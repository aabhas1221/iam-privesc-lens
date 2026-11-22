"""Per-technique detection tests (single-policy mode) and KB integrity."""

from __future__ import annotations

import pytest

from conftest import policy
from iam_privesc_lens.analyzer import analyze
from iam_privesc_lens.techniques import TECHNIQUES, Severity, get_technique


def ids(statements: list[dict]) -> dict[str, str]:
    report = analyze(policy(*statements))
    return {f.id: f.status for f in report.findings}


def allow(*actions: str, resource: str = "*", condition: dict | None = None) -> dict:
    stmt: dict = {"Effect": "Allow", "Action": list(actions), "Resource": resource}
    if condition:
        stmt["Condition"] = condition
    return stmt


# Minimal policy that should trigger each technique in single-policy mode.
CASES: dict[str, list[str]] = {
    "IAM-001": ["iam:CreatePolicyVersion"],
    "IAM-002": ["iam:SetDefaultPolicyVersion"],
    "IAM-003": ["iam:AttachUserPolicy"],
    "IAM-004": ["iam:AttachGroupPolicy"],
    "IAM-005": ["iam:AttachRolePolicy"],
    "IAM-006": ["iam:PutUserPolicy"],
    "IAM-007": ["iam:PutGroupPolicy"],
    "IAM-008": ["iam:PutRolePolicy"],
    "IAM-009": ["iam:AddUserToGroup"],
    "IAM-010": ["iam:CreateAccessKey"],
    "IAM-011": ["iam:CreateLoginProfile"],
    "IAM-012": ["iam:UpdateLoginProfile"],
    "IAM-013": ["iam:UpdateAssumeRolePolicy", "sts:AssumeRole"],
    "STS-001": ["sts:AssumeRole"],
    "PASS-001": ["iam:PassRole", "lambda:CreateFunction", "lambda:InvokeFunction"],
    "PASS-002": ["iam:PassRole", "lambda:CreateFunction", "lambda:CreateEventSourceMapping"],
    "PASS-003": ["iam:PassRole", "ec2:RunInstances"],
    "PASS-004": ["iam:PassRole", "cloudformation:CreateStack"],
    "PASS-005": ["iam:PassRole", "glue:CreateDevEndpoint"],
    "PASS-006": ["iam:PassRole", "datapipeline:CreatePipeline", "datapipeline:PutPipelineDefinition", "datapipeline:ActivatePipeline"],
    "PASS-007": ["iam:PassRole", "sagemaker:CreateNotebookInstance", "sagemaker:CreatePresignedNotebookInstanceUrl"],
    "PASS-008": ["iam:PassRole", "codebuild:CreateProject", "codebuild:StartBuild"],
    "LAM-001": ["lambda:UpdateFunctionCode"],
    "GLU-001": ["glue:UpdateDevEndpoint"],
    "SSM-001": ["ssm:StartSession"],
    "EC2-001": ["ec2-instance-connect:SendSSHPublicKey"],
}


def test_every_technique_has_a_case() -> None:
    assert set(CASES) == set(TECHNIQUES)


@pytest.mark.parametrize("technique_id", sorted(CASES))
def test_technique_detected(technique_id: str) -> None:
    found = ids([allow(*CASES[technique_id])])
    assert found.get(technique_id) == "confirmed"


@pytest.mark.parametrize("technique_id", sorted(t for t, a in CASES.items() if len(a) > 1))
def test_technique_needs_all_actions(technique_id: str) -> None:
    actions = CASES[technique_id]
    for missing in actions:
        remaining = [a for a in actions if a != missing]
        # Removing any required action must make the technique disappear.
        assert technique_id not in ids([allow(*remaining)]), f"{technique_id} matched without {missing}"


def test_any_of_group_alternatives() -> None:
    assert "SSM-001" in ids([allow("ssm:SendCommand")])
    assert "SSM-001" in ids([allow("ssm:StartSession")])


def test_wildcard_action_triggers_techniques() -> None:
    found = ids([allow("iam:*")])
    for tid in ("IAM-001", "IAM-003", "IAM-006", "IAM-013"):
        assert tid not in found or found[tid] == "confirmed"
    assert "IAM-003" in found


def test_conditional_technique() -> None:
    found = ids([allow("iam:AttachUserPolicy", condition={"Bool": {"aws:MultiFactorAuthPresent": "true"}})])
    assert found["IAM-003"] == "conditional"


def test_explicit_deny_removes_technique() -> None:
    found = ids([allow("iam:*"), {"Effect": "Deny", "Action": "iam:Attach*", "Resource": "*"}])
    assert "IAM-003" not in found
    assert "IAM-006" in found


def test_sts_on_specific_role_not_reported_without_account() -> None:
    found = ids([allow("sts:AssumeRole", resource="arn:aws:iam::1:role/x")])
    assert "STS-001" not in found


def test_dangerous_checks() -> None:
    assert "DNG-001" in ids([allow("*")])
    assert "DNG-002" in ids([{"Effect": "Allow", "NotAction": "iam:*", "Resource": "*"}])
    assert "DNG-003" in ids([allow("s3:*")])
    found = ids([allow("iam:PassRole")])
    assert {"DNG-004", "DNG-005"} <= set(found)
    scoped = ids([allow("iam:PassRole", resource="arn:aws:iam::1:role/app",
                        condition={"StringEquals": {"iam:PassedToService": "lambda.amazonaws.com"}})])
    assert "DNG-004" not in scoped and "DNG-005" not in scoped
    assert "DNG-006" in ids([allow("secretsmanager:GetSecretValue")])
    assert "DNG-007" in ids([allow("kms:Decrypt")])
    assert "DNG-008" in ids([allow("iam:*")])


def test_least_privilege_policy_is_clean() -> None:
    found = ids([allow("s3:GetObject", resource="arn:aws:s3:::bucket/*")])
    assert found == {}


def test_kb_integrity() -> None:
    assert len(TECHNIQUES) >= 20
    for t in TECHNIQUES.values():
        assert t.all_of or t.any_of
        assert t.steps and t.remediation and t.references and t.explanation
        assert isinstance(t.severity, Severity)
        if t.target in ("user", "group"):
            assert t.target_action
    assert get_technique("pass-001").id == "PASS-001"
