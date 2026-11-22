"""IAM policy parsing and evaluation.

This module implements the subset of the AWS IAM policy evaluation logic that
is needed to reason about privilege escalation offline:

* ``Allow`` / ``Deny`` effects, with explicit deny always winning.
* ``Action`` / ``NotAction`` and ``Resource`` / ``NotResource``.
* Wildcards (``*`` and ``?``) in actions and resources. Action matching is
  case-insensitive, resource matching is case-sensitive (as in AWS).
* Fields given either as a single string or as a list.
* Permission boundaries (an action must be allowed by both the identity
  policies and the boundary).

Conditions are **not** evaluated. A statement carrying a ``Condition`` block is
treated as "conditional": an allow that only comes from conditional statements
yields :attr:`Decision.CONDITIONAL` rather than :attr:`Decision.ALLOWED`, so
callers can surface condition-gated paths instead of silently trusting them.
"""

from __future__ import annotations

import json
import re
import urllib.parse
from dataclasses import dataclass, field
from enum import Enum
from functools import lru_cache
from typing import Any, Iterable, Mapping, Sequence

__all__ = [
    "Decision",
    "Statement",
    "Policy",
    "MatchedStatement",
    "Evaluation",
    "PolicySet",
    "PolicyParseError",
    "parse_policy_document",
    "action_matches",
    "resource_matches",
]


class PolicyParseError(ValueError):
    """Raised when a policy document cannot be parsed."""


class Decision(str, Enum):
    """Outcome of evaluating a single action against a set of policies."""

    ALLOWED = "allowed"
    """At least one unconditional Allow applies and no Deny applies."""

    CONDITIONAL = "conditional"
    """Allowed only through condition-gated statements, or a conditional Deny may apply."""

    DENIED = "denied"
    """An unconditional explicit Deny applies."""

    IMPLICIT_DENY = "implicit_deny"
    """No statement allows the action."""

    @property
    def is_possible(self) -> bool:
        """True when the action may be performed (allowed or condition-gated)."""
        return self in (Decision.ALLOWED, Decision.CONDITIONAL)


def _as_list(value: Any) -> list[str]:
    if value is None:
        return []
    if isinstance(value, str):
        return [value]
    if isinstance(value, (list, tuple)):
        return [str(v) for v in value]
    raise PolicyParseError(f"expected string or list, got {type(value).__name__}")


@lru_cache(maxsize=4096)
def _glob_to_regex(pattern: str, case_insensitive: bool) -> re.Pattern[str]:
    parts: list[str] = []
    i = 0
    while i < len(pattern):
        # IAM policy variables such as ${aws:username} are treated as wildcards
        # unless they were substituted beforehand.
        if pattern.startswith("${", i):
            end = pattern.find("}", i)
            if end != -1:
                variable = pattern[i + 2 : end]
                literal = {"*": "*", "?": "?", "$": "$"}.get(variable)
                parts.append(re.escape(literal) if literal else ".*")
                i = end + 1
                continue
        char = pattern[i]
        if char == "*":
            parts.append(".*")
        elif char == "?":
            parts.append(".")
        else:
            parts.append(re.escape(char))
        i += 1
    flags = re.IGNORECASE if case_insensitive else 0
    return re.compile("^" + "".join(parts) + "$", flags | re.DOTALL)


def action_matches(pattern: str, action: str) -> bool:
    """Return True if an IAM action pattern (e.g. ``iam:Create*``) matches ``action``.

    Matching is case-insensitive, mirroring AWS behaviour.
    """
    if pattern == "*":
        return True
    return bool(_glob_to_regex(pattern, True).match(action))


def resource_matches(pattern: str, resource: str) -> bool:
    """Return True if a resource ARN pattern matches ``resource`` (case-sensitive)."""
    if pattern == "*":
        return True
    return bool(_glob_to_regex(pattern, False).match(resource))


@dataclass(frozen=True)
class Statement:
    """A single normalised policy statement."""

    effect: str
    actions: tuple[str, ...] = ()
    not_actions: tuple[str, ...] = ()
    resources: tuple[str, ...] = ()
    not_resources: tuple[str, ...] = ()
    condition: Mapping[str, Any] = field(default_factory=dict)
    sid: str | None = None
    principal: Any = None
    not_principal: Any = None

    @property
    def is_allow(self) -> bool:
        return self.effect == "Allow"

    @property
    def is_deny(self) -> bool:
        return self.effect == "Deny"

    @property
    def is_conditional(self) -> bool:
        return bool(self.condition)

    def applies_to_action(self, action: str) -> bool:
        """True if the statement's Action/NotAction element covers ``action``."""
        if self.not_actions:
            return not any(action_matches(p, action) for p in self.not_actions)
        return any(action_matches(p, action) for p in self.actions)

    def applies_to_resource(self, resource: str) -> bool:
        """True if the statement's Resource/NotResource element covers ``resource``."""
        if self.not_resources:
            return not any(resource_matches(p, resource) for p in self.not_resources)
        if not self.resources:
            # Trust policies and some resource policies omit Resource entirely.
            return True
        return any(resource_matches(p, resource) for p in self.resources)

    @property
    def covers_all_resources(self) -> bool:
        """True if the statement applies to every resource (``Resource: "*"``)."""
        if self.not_resources:
            return False
        return not self.resources or "*" in self.resources

    @property
    def grants_any_resource(self) -> bool:
        """True if the statement applies to at least one resource."""
        if self.not_resources:
            return "*" not in self.not_resources
        return True

    def condition_keys(self) -> set[str]:
        """Lower-cased condition keys referenced by this statement."""
        keys: set[str] = set()
        for operator_block in self.condition.values():
            if isinstance(operator_block, Mapping):
                keys.update(str(k).lower() for k in operator_block)
        return keys

    def substitute(self, variables: Mapping[str, str]) -> "Statement":
        """Return a copy with ``${var}`` policy variables substituted in resources."""
        if not variables:
            return self

        def sub(values: tuple[str, ...]) -> tuple[str, ...]:
            out = []
            for v in values:
                for key, val in variables.items():
                    v = v.replace("${" + key + "}", val)
                out.append(v)
            return tuple(out)

        return Statement(
            effect=self.effect,
            actions=self.actions,
            not_actions=self.not_actions,
            resources=sub(self.resources),
            not_resources=sub(self.not_resources),
            condition=self.condition,
            sid=self.sid,
            principal=self.principal,
            not_principal=self.not_principal,
        )


@dataclass(frozen=True)
class Policy:
    """A named policy document made of statements."""

    name: str
    statements: tuple[Statement, ...]
    source: str = "inline"
    arn: str | None = None

    def to_document(self) -> dict[str, Any]:
        """Serialise back to a (normalised) IAM JSON policy document."""
        out = []
        for s in self.statements:
            doc: dict[str, Any] = {"Effect": s.effect}
            if s.sid:
                doc["Sid"] = s.sid
            if s.actions:
                doc["Action"] = list(s.actions)
            if s.not_actions:
                doc["NotAction"] = list(s.not_actions)
            if s.resources:
                doc["Resource"] = list(s.resources)
            if s.not_resources:
                doc["NotResource"] = list(s.not_resources)
            if s.condition:
                doc["Condition"] = dict(s.condition)
            out.append(doc)
        return {"Version": "2012-10-17", "Statement": out}


def _decode_document(document: Any) -> Mapping[str, Any]:
    if isinstance(document, str):
        text = document.strip()
        if text.startswith("%7B") or text.startswith("%7b"):
            text = urllib.parse.unquote(text)
        try:
            document = json.loads(text)
        except json.JSONDecodeError as exc:
            raise PolicyParseError(f"policy document is not valid JSON: {exc}") from exc
    if not isinstance(document, Mapping):
        raise PolicyParseError("policy document must be a JSON object")
    return document


def parse_policy_document(
    document: Any, name: str = "policy", source: str = "inline", arn: str | None = None
) -> Policy:
    """Parse an IAM policy document (dict, JSON string or URL-encoded JSON).

    Raises:
        PolicyParseError: if the document is structurally invalid.
    """
    doc = _decode_document(document)
    raw_statements = doc.get("Statement")
    if raw_statements is None:
        raise PolicyParseError(f"{name}: policy has no 'Statement' element")
    if isinstance(raw_statements, Mapping):
        raw_statements = [raw_statements]
    if not isinstance(raw_statements, list):
        raise PolicyParseError(f"{name}: 'Statement' must be an object or a list")

    statements: list[Statement] = []
    for index, raw in enumerate(raw_statements):
        if not isinstance(raw, Mapping):
            raise PolicyParseError(f"{name}: statement #{index} is not an object")
        effect = str(raw.get("Effect", "")).strip().capitalize()
        if effect not in ("Allow", "Deny"):
            raise PolicyParseError(f"{name}: statement #{index} has invalid Effect {raw.get('Effect')!r}")
        actions = tuple(_as_list(raw.get("Action")))
        not_actions = tuple(_as_list(raw.get("NotAction")))
        if actions and not_actions:
            raise PolicyParseError(f"{name}: statement #{index} has both Action and NotAction")
        resources = tuple(_as_list(raw.get("Resource")))
        not_resources = tuple(_as_list(raw.get("NotResource")))
        if resources and not_resources:
            raise PolicyParseError(f"{name}: statement #{index} has both Resource and NotResource")
        condition = raw.get("Condition") or {}
        if not isinstance(condition, Mapping):
            raise PolicyParseError(f"{name}: statement #{index} has a non-object Condition")
        statements.append(
            Statement(
                effect=effect,
                actions=actions,
                not_actions=not_actions,
                resources=resources,
                not_resources=not_resources,
                condition=dict(condition),
                sid=str(raw["Sid"]) if raw.get("Sid") else None,
                principal=raw.get("Principal"),
                not_principal=raw.get("NotPrincipal"),
            )
        )
    return Policy(name=name, statements=tuple(statements), source=source, arn=arn)


@dataclass(frozen=True)
class MatchedStatement:
    """Evidence: a statement that contributed to a decision."""

    policy: str
    sid: str | None
    effect: str
    conditional: bool
    resources: tuple[str, ...]

    def label(self) -> str:
        sid = f"#{self.sid}" if self.sid else ""
        cond = " (conditional)" if self.conditional else ""
        return f"{self.policy}{sid} [{self.effect}]{cond}"


@dataclass(frozen=True)
class Evaluation:
    """Result of evaluating one action (optionally on one resource)."""

    action: str
    resource: str | None
    decision: Decision
    allows: tuple[MatchedStatement, ...] = ()
    denies: tuple[MatchedStatement, ...] = ()

    @property
    def is_possible(self) -> bool:
        return self.decision.is_possible

    @property
    def granted_resources(self) -> tuple[str, ...]:
        """Resource patterns of the Allow statements granting this action."""
        out: list[str] = []
        for match in self.allows:
            for r in match.resources or ("*",):
                if r not in out:
                    out.append(r)
        return tuple(out)


def _match(policy: Policy, statement: Statement) -> MatchedStatement:
    resources = statement.resources
    if statement.not_resources:
        resources = tuple(f"NOT {r}" for r in statement.not_resources)
    return MatchedStatement(
        policy=policy.name,
        sid=statement.sid,
        effect=statement.effect,
        conditional=statement.is_conditional,
        resources=resources,
    )


def _evaluate_policies(
    policies: Sequence[Policy],
    action: str,
    resource: str | None,
    variables: Mapping[str, str],
) -> Evaluation:
    allows: list[MatchedStatement] = []
    denies: list[MatchedStatement] = []
    hard_deny = False
    soft_deny = False
    hard_allow = False

    for policy in policies:
        for raw in policy.statements:
            statement = raw.substitute(variables)
            if not statement.applies_to_action(action):
                continue
            if statement.is_deny:
                # With no specific resource we ask "is the action allowed on at
                # least one resource?". Only a deny covering every resource can
                # rule that out; narrower denies are recorded as evidence.
                covers = (
                    statement.covers_all_resources
                    if resource is None
                    else statement.applies_to_resource(resource)
                )
                if not covers:
                    continue
                denies.append(_match(policy, statement))
                if statement.is_conditional:
                    soft_deny = True
                else:
                    hard_deny = True
            else:
                applies = (
                    statement.grants_any_resource
                    if resource is None
                    else statement.applies_to_resource(resource)
                )
                if not applies:
                    continue
                allows.append(_match(policy, statement))
                if not statement.is_conditional:
                    hard_allow = True

    if hard_deny:
        decision = Decision.DENIED
    elif not allows:
        decision = Decision.IMPLICIT_DENY
    elif hard_allow and not soft_deny:
        decision = Decision.ALLOWED
    else:
        decision = Decision.CONDITIONAL
    return Evaluation(action, resource, decision, tuple(allows), tuple(denies))


@dataclass
class PolicySet:
    """The effective identity policies of a principal, plus an optional boundary."""

    policies: list[Policy] = field(default_factory=list)
    boundary: Policy | None = None
    variables: dict[str, str] = field(default_factory=dict)

    def evaluate(self, action: str, resource: str | None = None) -> Evaluation:
        """Evaluate ``action`` against ``resource``.

        If ``resource`` is ``None`` the question becomes "is this action allowed
        on at least one resource?", which is what most privilege-escalation
        checks need when the concrete target is unknown.
        """
        identity = _evaluate_policies(self.policies, action, resource, self.variables)
        if self.boundary is None or not identity.is_possible:
            return identity
        bounded = _evaluate_policies([self.boundary], action, resource, self.variables)
        if not bounded.is_possible:
            return Evaluation(
                action,
                resource,
                Decision.DENIED if bounded.decision is Decision.DENIED else Decision.IMPLICIT_DENY,
                identity.allows,
                identity.denies + bounded.denies,
            )
        decision = (
            Decision.ALLOWED
            if identity.decision is Decision.ALLOWED and bounded.decision is Decision.ALLOWED
            else Decision.CONDITIONAL
        )
        return Evaluation(action, resource, decision, identity.allows, identity.denies + bounded.denies)

    def statements(self) -> Iterable[tuple[Policy, Statement]]:
        """Iterate over every (policy, statement) pair of the identity policies."""
        for policy in self.policies:
            for statement in policy.statements:
                yield policy, statement

    def is_full_admin(self) -> bool:
        """True if an unconditional ``Action: *`` / ``Resource: *`` allow is effective.

        This is a structural check (an explicit full wildcard grant) combined with
        evaluation, so explicit denies and permission boundaries are honoured for
        a set of representative sensitive actions.
        """
        has_wildcard_grant = any(
            s.is_allow
            and not s.is_conditional
            and not s.not_actions
            and any(a in ("*", "*:*") for a in s.actions)
            and s.covers_all_resources
            for _, s in self.statements()
        )
        if not has_wildcard_grant:
            return False
        probes = ("iam:AttachUserPolicy", "iam:PutRolePolicy", "iam:CreateAccessKey", "sts:AssumeRole")
        return all(self.evaluate(p, "*").decision is Decision.ALLOWED for p in probes)
