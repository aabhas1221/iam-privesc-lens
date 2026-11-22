"""Account model: principals, their policies and role trust relationships.

Two input shapes are supported:

* a single IAM policy document (or a list of them), analysed as one synthetic
  principal, and
* the JSON output of ``aws iam get-account-authorization-details``, from which
  users, groups, roles, managed policies, permission boundaries, trust policies
  and instance profiles are resolved.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable, Literal, Mapping

from .policy import Policy, PolicyParseError, PolicySet, Statement, parse_policy_document

__all__ = ["Principal", "Account", "load_file", "load_data", "BUILTIN_MANAGED_POLICIES"]

PrincipalKind = Literal["user", "role", "group", "policy"]

#: A few AWS-managed policies, used when an export references them by ARN but
#: does not include their documents (e.g. exports filtered to LocalManagedPolicy).
#: These are deliberately simplified approximations of the real AWS documents;
#: exports that include the AWS-managed policy documents always take precedence.
BUILTIN_MANAGED_POLICIES: dict[str, dict[str, Any]] = {
    "arn:aws:iam::aws:policy/AdministratorAccess": {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}],
    },
    "arn:aws:iam::aws:policy/IAMFullAccess": {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Action": ["iam:*", "organizations:DescribeAccount"], "Resource": "*"}],
    },
    "arn:aws:iam::aws:policy/PowerUserAccess": {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "NotAction": ["iam:*", "organizations:*", "account:*"], "Resource": "*"},
            {
                "Effect": "Allow",
                "Action": [
                    "iam:CreateServiceLinkedRole",
                    "iam:DeleteServiceLinkedRole",
                    "iam:ListRoles",
                    "organizations:DescribeOrganization",
                    "account:ListRegions",
                ],
                "Resource": "*",
            },
        ],
    },
    "arn:aws:iam::aws:policy/ReadOnlyAccess": {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": [
                    "*:Describe*",
                    "*:List*",
                    "cloudwatch:Get*",
                    "ec2:Get*",
                    "iam:Get*",
                    "logs:Get*",
                    "s3:GetBucket*",
                ],
                "Resource": "*",
            }
        ],
    },
}


@dataclass
class Principal:
    """A user, role, group, or a standalone policy treated as a principal."""

    kind: PrincipalKind
    name: str
    arn: str
    policies: list[Policy] = field(default_factory=list)
    boundary: Policy | None = None
    groups: list[str] = field(default_factory=list)
    trust_policy: Policy | None = None
    instance_profiles: list[str] = field(default_factory=list)

    @property
    def id(self) -> str:
        """Short stable identifier such as ``user/alice`` or ``role/admin``."""
        return f"{self.kind}/{self.name}"

    @property
    def account_id(self) -> str | None:
        parts = self.arn.split(":")
        return parts[4] if len(parts) > 4 and parts[4] else None

    def policy_set(self) -> PolicySet:
        """The principal's effective policy set (including boundary and variables)."""
        variables = {"aws:username": self.name} if self.kind == "user" else {}
        if self.account_id:
            variables["aws:PrincipalAccount"] = self.account_id
        return PolicySet(policies=list(self.policies), boundary=self.boundary, variables=variables)


@dataclass
class Account:
    """A collection of principals loaded from one input file."""

    principals: dict[str, Principal] = field(default_factory=dict)
    account_id: str | None = None
    warnings: list[str] = field(default_factory=list)
    mode: Literal["policy", "account"] = "account"

    def add(self, principal: Principal) -> None:
        self.principals[principal.id] = principal

    def get(self, name: str) -> Principal | None:
        """Look up a principal by id (``user/alice``), ARN or bare name."""
        if name in self.principals:
            return self.principals[name]
        for principal in self.principals.values():
            if principal.arn == name or principal.name == name:
                return principal
        return None

    def of_kind(self, kind: PrincipalKind) -> list[Principal]:
        return [p for p in self.principals.values() if p.kind == kind]

    def actors(self) -> list[Principal]:
        """Principals that can make API calls (users, roles, standalone policies)."""
        return [p for p in self.principals.values() if p.kind in ("user", "role", "policy")]


def _default_version_document(policy: Mapping[str, Any]) -> Any:
    for version in policy.get("PolicyVersionList", []) or []:
        if version.get("IsDefaultVersion"):
            return version.get("Document")
    versions = policy.get("PolicyVersionList") or []
    return versions[0].get("Document") if versions else None


def _inline(entries: Iterable[Mapping[str, Any]], owner: str) -> list[Policy]:
    out = []
    for entry in entries or []:
        name = entry.get("PolicyName", "inline")
        out.append(parse_policy_document(entry.get("PolicyDocument"), name=f"{owner}:{name}", source="inline"))
    return out


def _is_auth_details(data: Any) -> bool:
    return isinstance(data, Mapping) and any(
        k in data for k in ("UserDetailList", "RoleDetailList", "GroupDetailList", "Policies")
    )


def _load_auth_details(data: Mapping[str, Any]) -> Account:
    account = Account(mode="account")
    managed: dict[str, Policy] = {}
    for raw in data.get("Policies", []) or []:
        arn = raw.get("Arn", "")
        document = _default_version_document(raw)
        if document is None:
            account.warnings.append(f"managed policy {arn} has no default version document")
            continue
        managed[arn] = parse_policy_document(
            document, name=raw.get("PolicyName", arn), source="managed", arn=arn
        )

    def resolve(attached: Iterable[Mapping[str, Any]]) -> list[Policy]:
        out = []
        for item in attached or []:
            arn = item.get("PolicyArn", "")
            if arn in managed:
                out.append(managed[arn])
            elif arn in BUILTIN_MANAGED_POLICIES:
                out.append(
                    parse_policy_document(
                        BUILTIN_MANAGED_POLICIES[arn],
                        name=item.get("PolicyName", arn.rsplit("/", 1)[-1]),
                        source="aws-managed",
                        arn=arn,
                    )
                )
            else:
                account.warnings.append(f"policy {arn} is attached but its document is not in the export; ignored")
        return out

    def boundary(raw: Mapping[str, Any]) -> Policy | None:
        pb = raw.get("PermissionsBoundary") or {}
        arn = pb.get("PermissionsBoundaryArn")
        if not arn:
            return None
        resolved = resolve([{"PolicyArn": arn, "PolicyName": arn.rsplit("/", 1)[-1]}])
        return resolved[0] if resolved else None

    groups: dict[str, Principal] = {}
    for raw in data.get("GroupDetailList", []) or []:
        name = raw["GroupName"]
        group = Principal(
            kind="group",
            name=name,
            arn=raw.get("Arn", f"group:{name}"),
            policies=_inline(raw.get("GroupPolicyList", []), f"group/{name}") + resolve(raw.get("AttachedManagedPolicies", [])),
        )
        groups[name] = group
        account.add(group)

    for raw in data.get("UserDetailList", []) or []:
        name = raw["UserName"]
        user = Principal(
            kind="user",
            name=name,
            arn=raw.get("Arn", f"user:{name}"),
            policies=_inline(raw.get("UserPolicyList", []), f"user/{name}") + resolve(raw.get("AttachedManagedPolicies", [])),
            boundary=boundary(raw),
            groups=list(raw.get("GroupList", []) or []),
        )
        for group_name in user.groups:
            group = groups.get(group_name)
            if group is None:
                account.warnings.append(f"user {name} is in group {group_name}, which is not in the export")
                continue
            user.policies.extend(group.policies)
        account.add(user)

    for raw in data.get("RoleDetailList", []) or []:
        name = raw["RoleName"]
        trust_doc = raw.get("AssumeRolePolicyDocument")
        trust = parse_policy_document(trust_doc, name=f"role/{name}:trust", source="trust") if trust_doc else None
        role = Principal(
            kind="role",
            name=name,
            arn=raw.get("Arn", f"role:{name}"),
            policies=_inline(raw.get("RolePolicyList", []), f"role/{name}") + resolve(raw.get("AttachedManagedPolicies", [])),
            boundary=boundary(raw),
            trust_policy=trust,
            instance_profiles=[ip.get("InstanceProfileName", "") for ip in raw.get("InstanceProfileList", []) or []],
        )
        account.add(role)

    for principal in account.principals.values():
        if principal.account_id:
            account.account_id = principal.account_id
            break
    return account


def load_data(data: Any, label: str = "policy") -> Account:
    """Build an :class:`Account` from already-parsed JSON.

    Raises:
        PolicyParseError: if the JSON is neither a policy nor an authorization-details export.
    """
    if _is_auth_details(data):
        return _load_auth_details(data)

    documents: list[Any]
    if isinstance(data, Mapping) and "PolicyVersion" in data:
        documents = [data["PolicyVersion"].get("Document")]
    elif isinstance(data, Mapping) and "Statement" in data:
        documents = [data]
    elif isinstance(data, list) and all(isinstance(d, Mapping) and "Statement" in d for d in data):
        documents = list(data)
    else:
        raise PolicyParseError(
            "input is neither an IAM policy document nor a get-account-authorization-details export"
        )
    policies = [
        parse_policy_document(doc, name=label if len(documents) == 1 else f"{label}[{i}]", source="file")
        for i, doc in enumerate(documents)
    ]
    account = Account(mode="policy")
    account.add(Principal(kind="policy", name=label, arn=f"policy:{label}", policies=policies))
    return account


def load_file(path: str | Path) -> Account:
    """Load a policy document or authorization-details export from disk."""
    p = Path(path)
    try:
        data = json.loads(p.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise PolicyParseError(f"{p}: not valid JSON ({exc})") from exc
    return load_data(data, label=p.stem)


def trust_admits(role: Principal, caller: Principal) -> tuple[bool, bool, str]:
    """Check whether ``role``'s trust policy lets ``caller`` assume it.

    Returns:
        ``(admitted, conditional, how)`` where ``how`` describes the matching
        trust clause and whether the caller's own identity policy must also
        allow ``sts:AssumeRole`` (it must when trust is granted via the account
        root or ``*``).
    """
    if role.trust_policy is None:
        return False, False, ""
    admitted = False
    conditional = False
    how = ""
    for statement in role.trust_policy.statements:
        if not statement.applies_to_action("sts:AssumeRole"):
            continue
        match = _principal_match(statement, caller)
        if not match:
            continue
        if statement.is_deny:
            if not statement.is_conditional:
                return False, False, "explicit deny in trust policy"
            conditional = True
            continue
        if not admitted or (conditional and not statement.is_conditional):
            admitted = True
            conditional = statement.is_conditional
            how = match
    return admitted, conditional, how


def _principal_values(statement: Statement) -> tuple[list[str], bool]:
    principal = statement.principal
    if principal == "*":
        return ["*"], True
    if isinstance(principal, Mapping):
        aws = principal.get("AWS", [])
        values = [aws] if isinstance(aws, str) else list(aws or [])
        return [str(v) for v in values], "*" in values
    return [], False


def _principal_match(statement: Statement, caller: Principal) -> str:
    values, wildcard = _principal_values(statement)
    if wildcard:
        return "wildcard"
    account = caller.account_id
    for value in values:
        if value == caller.arn:
            return "direct"
        if account and value in (account, f"arn:aws:iam::{account}:root"):
            return "account"
    return ""


def trusts_service(role: Principal, service: str) -> tuple[bool, bool]:
    """Return ``(trusted, conditional)`` for an AWS service principal."""
    if role.trust_policy is None:
        return False, False
    found = False
    conditional = True
    for statement in role.trust_policy.statements:
        if not statement.is_allow or not statement.applies_to_action("sts:AssumeRole"):
            continue
        principal = statement.principal
        services: list[str] = []
        if principal == "*":
            services = ["*"]
        elif isinstance(principal, Mapping):
            svc = principal.get("Service", [])
            services = [svc] if isinstance(svc, str) else list(svc or [])
        if "*" in services or service in services:
            found = True
            conditional = conditional and statement.is_conditional
    return found, (conditional if found else False)


__all__ += ["trust_admits", "trusts_service", "PolicyParseError"]
