"""Privilege-escalation analysis: technique matching, risky-permission checks
and multi-hop path search over the principal graph."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Iterable, Literal

from .model import Account, Principal, trust_admits, trusts_service
from .policy import Decision, Evaluation, PolicySet, Statement
from .techniques import TECHNIQUES, Severity, Technique

__all__ = ["ADMIN", "Finding", "Edge", "EscalationPath", "Report", "Analyzer", "analyze"]

ADMIN = "ADMIN"
"""Terminal graph node: full control of the account."""

Status = Literal["confirmed", "conditional"]


@dataclass
class Finding:
    """A single issue attributed to a principal."""

    id: str
    title: str
    severity: Severity
    principal: str
    status: Status
    kind: Literal["privesc", "dangerous", "path"]
    description: str
    evidence: list[str] = field(default_factory=list)
    targets: list[str] = field(default_factory=list)
    steps: list[str] = field(default_factory=list)
    remediation: str = ""
    references: list[str] = field(default_factory=list)
    note: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "title": self.title,
            "severity": self.severity.value,
            "principal": self.principal,
            "status": self.status,
            "kind": self.kind,
            "description": self.description,
            "evidence": self.evidence,
            "targets": self.targets,
            "steps": self.steps,
            "remediation": self.remediation,
            "references": self.references,
            "note": self.note,
        }


@dataclass(frozen=True)
class Edge:
    """A hop in the escalation graph: ``source`` can become / control ``target``."""

    source: str
    target: str
    technique: str
    conditional: bool
    detail: str
    assumption: str = ""

    def to_dict(self) -> dict[str, Any]:
        technique = TECHNIQUES.get(self.technique)
        return {
            "source": self.source,
            "target": self.target,
            "technique": self.technique,
            "technique_name": technique.name if technique else self.technique,
            "conditional": self.conditional,
            "detail": self.detail,
            "assumption": self.assumption,
        }


@dataclass
class EscalationPath:
    """A chain of edges from a starting principal to admin-equivalent access."""

    start: str
    edges: list[Edge]
    end_reason: str

    @property
    def conditional(self) -> bool:
        return any(e.conditional for e in self.edges)

    @property
    def nodes(self) -> list[str]:
        return [self.start] + [e.target for e in self.edges]

    def chain(self) -> str:
        """Human readable chain like ``user/a -> role/b => ADMIN``."""
        text = " -> ".join(self.nodes)
        return text if self.nodes[-1] == ADMIN else f"{text} => {ADMIN}"

    def to_dict(self) -> dict[str, Any]:
        return {
            "start": self.start,
            "chain": self.chain(),
            "hops": len(self.edges),
            "conditional": self.conditional,
            "end_reason": self.end_reason,
            "edges": [e.to_dict() for e in self.edges],
        }


@dataclass
class Report:
    """Everything the analyzer found for one input."""

    source: str
    mode: str
    account_id: str | None
    principals: list[str]
    findings: list[Finding]
    paths: list[EscalationPath]
    warnings: list[str]
    admins: list[str]

    def max_severity(self) -> Severity | None:
        if not self.findings:
            return None
        return max((f.severity for f in self.findings), key=lambda s: s.rank)

    def to_dict(self) -> dict[str, Any]:
        counts: dict[str, int] = {s.value: 0 for s in Severity}
        for f in self.findings:
            counts[f.severity.value] += 1
        return {
            "tool": "iam-privesc-lens",
            "source": self.source,
            "mode": self.mode,
            "account_id": self.account_id,
            "principals_analyzed": self.principals,
            "admin_equivalent_principals": self.admins,
            "summary": {"findings": len(self.findings), "paths": len(self.paths), "by_severity": counts},
            "paths": [p.to_dict() for p in self.paths],
            "findings": [f.to_dict() for f in self.findings],
            "warnings": self.warnings,
        }


@dataclass
class _Match:
    status: Status
    evidence: list[str]
    granted: dict[str, tuple[str, ...]]


def _best(evaluations: Iterable[Evaluation]) -> Evaluation | None:
    best: Evaluation | None = None
    for ev in evaluations:
        if ev.decision is Decision.ALLOWED:
            return ev
        if ev.decision is Decision.CONDITIONAL and best is None:
            best = ev
    return best


def _evidence(ev: Evaluation) -> str:
    sources = ", ".join(m.label() for m in ev.allows) or "-"
    return f"{ev.action} ({ev.decision.value}) <- {sources}"


def _short(principal: Principal) -> str:
    return principal.id


class Analyzer:
    """Analyse an :class:`Account` for privilege escalation.

    Args:
        account: the loaded account or single-policy model.
        max_depth: maximum number of hops in multi-hop path search.
        max_paths: maximum number of paths reported per starting principal.
    """

    def __init__(self, account: Account, max_depth: int = 4, max_paths: int = 5) -> None:
        self.account = account
        self.max_depth = max_depth
        self.max_paths = max_paths
        self._policy_sets: dict[str, PolicySet] = {}
        self._edges: dict[str, list[Edge]] = {}
        self._technique_findings: dict[str, list[Finding]] = {}

    # ------------------------------------------------------------------ helpers
    def policy_set(self, principal: Principal) -> PolicySet:
        if principal.id not in self._policy_sets:
            self._policy_sets[principal.id] = principal.policy_set()
        return self._policy_sets[principal.id]

    def is_admin(self, principal: Principal) -> bool:
        """True if the principal effectively holds ``*`` on ``*``."""
        return self.policy_set(principal).is_full_admin()

    def match_technique(
        self, principal: Principal, technique: Technique, target_arn: str | None = None
    ) -> _Match | None:
        """Check whether ``principal`` satisfies ``technique``'s action requirements.

        ``target_arn`` (when given) is used as the resource for the technique's
        ``target_action``; every other action is checked against "any resource".
        """
        ps = self.policy_set(principal)
        evaluations: list[Evaluation] = []

        def resource_for(action: str) -> str | None:
            if target_arn and technique.target_action and action.lower() == technique.target_action.lower():
                return target_arn
            return None

        for action in technique.all_of:
            ev = ps.evaluate(action, resource_for(action))
            if not ev.is_possible:
                return None
            evaluations.append(ev)
        for group in technique.any_of:
            ev = _best(ps.evaluate(a, resource_for(a)) for a in group)
            if ev is None:
                return None
            evaluations.append(ev)
        status: Status = (
            "conditional" if any(e.decision is Decision.CONDITIONAL for e in evaluations) else "confirmed"
        )
        return _Match(
            status=status,
            evidence=[_evidence(e) for e in evaluations],
            granted={e.action: e.granted_resources for e in evaluations},
        )

    # -------------------------------------------------------------- graph edges
    def _controlled_arns(self, principal: Principal, kind: str) -> list[str]:
        if kind == "user":
            return [principal.arn] if principal.kind == "user" else []
        if kind == "group":
            if principal.kind == "group":
                return [principal.arn]
            return [g.arn for name in principal.groups if (g := self.account.get(f"group/{name}"))]
        if kind == "role":
            arns = [principal.arn] if principal.kind == "role" else []
            for role in self.account.of_kind("role"):
                if role.id == principal.id:
                    continue
                if self._assume_edge(principal, role) is not None:
                    arns.append(role.arn)
            return arns
        if kind == "policy":
            return [p.arn for p in principal.policies if p.arn and p.source == "managed"]
        return []

    def _assume_edge(self, caller: Principal, role: Principal) -> Edge | None:
        admitted, trust_conditional, how = trust_admits(role, caller)
        if not admitted:
            return None
        ev = self.policy_set(caller).evaluate("sts:AssumeRole", role.arn)
        if ev.decision is Decision.DENIED:
            return None
        if how == "direct":
            # Same-account trust policy naming the caller's ARN is sufficient on
            # its own; an identity-policy allow is not required.
            conditional = trust_conditional or ev.decision is Decision.CONDITIONAL
            detail = f"trust policy of {role.id} names {caller.id} directly"
        else:
            if not ev.is_possible:
                return None
            conditional = trust_conditional or ev.decision is Decision.CONDITIONAL
            via = "the account root" if how == "account" else "'*'"
            sources = ", ".join(m.label() for m in ev.allows)
            detail = f"trust policy of {role.id} trusts {via}; sts:AssumeRole on it is allowed by {sources}"
        if trust_conditional:
            detail += "; trust policy statement has a Condition"
        return Edge(caller.id, role.id, "STS-001", conditional, detail)

    def _technique_edges(self, principal: Principal, technique: Technique) -> tuple[list[Edge], Finding | None]:
        """Compute edges (and the corresponding finding) for one technique."""
        if technique.id == "STS-001":
            edges = [
                e
                for role in self.account.of_kind("role")
                if role.id != principal.id and (e := self._assume_edge(principal, role))
            ]
            if not edges:
                # Still worth reporting sts:AssumeRole on '*' in single-policy mode.
                if self.account.mode == "policy":
                    match = self.match_technique(principal, technique)
                    if match and "*" in match.granted.get("sts:AssumeRole", ()):
                        return [], self._finding(
                            principal, technique, match, [],
                            note="sts:AssumeRole is allowed on '*': any role whose trust policy admits this "
                            "principal or its account can be assumed.",
                        )
                return [], None
            status: Status = "conditional" if all(e.conditional for e in edges) else "confirmed"
            finding = self._finding(
                principal,
                technique,
                _Match(status, [e.detail for e in edges], {}),
                [e.target for e in edges],
            )
            return edges, finding

        base = self.match_technique(principal, technique)
        if base is None:
            return [], None

        if technique.target == "admin":
            if self.account.mode == "policy":
                edge = Edge(
                    principal.id, ADMIN, technique.id, base.status == "conditional",
                    technique.name,
                    assumption="the policy's resource scope includes a principal or policy you control",
                )
                return [edge], self._finding(principal, technique, base, [ADMIN], note=edge.assumption)
            controlled = self._controlled_arns(principal, technique.writes or "")
            for arn in controlled:
                action = technique.all_of[0]
                ev = self.policy_set(principal).evaluate(action, arn)
                if ev.is_possible:
                    conditional = ev.decision is Decision.CONDITIONAL or base.status == "conditional"
                    edge = Edge(
                        principal.id, ADMIN, technique.id, conditional,
                        f"{action} is allowed on {arn}, which {principal.id} controls",
                    )
                    match = _Match("conditional" if conditional else "confirmed", [_evidence(ev)], base.granted)
                    return [edge], self._finding(principal, technique, match, [arn])
            granted = ", ".join(base.granted.get(technique.all_of[0], ())) or "-"
            return [], self._finding(
                principal, technique, base, [],
                note=f"Allowed only on resources not controlled by {principal.id} ({granted}); "
                "exploitable if any of those resources can be used by this principal.",
                severity=Severity.MEDIUM,
            )

        if self.account.mode == "policy":
            # No account context: report the capability without concrete targets.
            role_what = f"roles trusting {technique.target_service}" if technique.target_service else "IAM roles"
            what = {"user": "other IAM users", "role": role_what, "group": "IAM groups"}[technique.target]
            granted = base.granted.get(technique.target_action or "", ())
            scope = f" (resource scope: {', '.join(granted)})" if granted else ""
            return [], self._finding(
                principal, technique, base, [], note=f"Targets {what}{scope}; supply an account export to resolve them."
            )

        edges: list[Edge] = []
        for target in self._candidate_targets(principal, technique):
            match = self.match_technique(principal, technique, target.arn) if technique.target_action else base
            if match is None:
                continue
            conditional = match.status == "conditional"
            assumption = ""
            detail = technique.name
            if technique.target_service:
                trusted, trust_cond = trusts_service(target, technique.target_service)
                conditional = conditional or trust_cond
                detail = f"{target.id} trusts {technique.target_service}"
                if technique.target_action:
                    detail += f"; {technique.target_action} allowed on {target.arn}"
                elif technique.needs_instance_profile:
                    assumption = f"an EC2 instance is running with instance profile {', '.join(target.instance_profiles)}"
                else:
                    assumption = f"an existing {technique.target_service.split('.')[0]} resource runs as {target.id}"
            elif technique.target_action:
                detail = f"{technique.target_action} allowed on {target.arn}"
            edges.append(Edge(principal.id, target.id, technique.id, conditional, detail, assumption))
        if not edges:
            return [], None
        status = "conditional" if all(e.conditional for e in edges) else "confirmed"
        finding = self._finding(principal, technique, _Match(status, base.evidence, base.granted), [e.target for e in edges])
        return edges, finding

    def _candidate_targets(self, principal: Principal, technique: Technique) -> list[Principal]:
        if technique.target == "user":
            return [u for u in self.account.of_kind("user") if u.id != principal.id]
        if technique.target == "group":
            if principal.kind != "user":
                return []
            return [g for g in self.account.of_kind("group") if g.name not in principal.groups]
        roles = [r for r in self.account.of_kind("role") if r.id != principal.id]
        if technique.target_service:
            roles = [r for r in roles if trusts_service(r, technique.target_service)[0]]
        if technique.needs_instance_profile:
            roles = [r for r in roles if r.instance_profiles]
        return roles

    def _finding(
        self,
        principal: Principal,
        technique: Technique,
        match: _Match,
        targets: list[str],
        note: str = "",
        severity: Severity | None = None,
    ) -> Finding:
        return Finding(
            id=technique.id,
            title=technique.name,
            severity=severity or technique.severity,
            principal=principal.id,
            status=match.status,
            kind="privesc",
            description=technique.explanation,
            evidence=match.evidence,
            targets=targets,
            steps=list(technique.steps),
            remediation=technique.remediation,
            references=list(technique.references),
            note=note,
        )

    def edges_from(self, principal: Principal) -> list[Edge]:
        """All outgoing escalation edges for a principal (memoised)."""
        if principal.id in self._edges:
            return self._edges[principal.id]
        edges: list[Edge] = []
        findings: list[Finding] = []
        self._edges[principal.id] = edges  # guards against recursion via _controlled_arns
        for technique in TECHNIQUES.values():
            new_edges, finding = self._technique_edges(principal, technique)
            edges.extend(new_edges)
            if finding:
                findings.append(finding)
        self._technique_findings[principal.id] = findings
        return edges

    # -------------------------------------------------------------- path search
    def find_paths(self, start: Principal) -> list[EscalationPath]:
        """Depth-limited DFS for chains from ``start`` to admin-equivalent access."""
        results: list[EscalationPath] = []

        def visit(node: Principal, trail: list[Edge], seen: set[str]) -> None:
            if len(trail) >= self.max_depth:
                return
            for edge in self.edges_from(node):
                if edge.target in seen:
                    continue
                new_trail = trail + [edge]
                if edge.target == ADMIN:
                    results.append(EscalationPath(start.id, new_trail, "grants itself arbitrary permissions"))
                    continue
                target = self.account.principals.get(edge.target)
                if target is None:
                    continue
                if self.is_admin(target):
                    results.append(EscalationPath(start.id, new_trail, f"{target.id} has full administrator access"))
                    continue
                visit(target, new_trail, seen | {edge.target})

        visit(start, [], {start.id})
        results.sort(key=lambda p: (p.conditional, len(p.edges), p.chain()))
        unique: list[EscalationPath] = []
        seen_chains: set[tuple[str, ...]] = set()
        for path in results:
            key = tuple(f"{e.target}:{e.technique}" for e in path.edges)
            if key not in seen_chains:
                seen_chains.add(key)
                unique.append(path)
        return unique[: self.max_paths]

    # --------------------------------------------------------- dangerous checks
    def dangerous_findings(self, principal: Principal) -> list[Finding]:
        """Risky permissions that are not necessarily escalation paths."""
        ps = self.policy_set(principal)
        out: list[Finding] = []

        def add(fid: str, title: str, severity: Severity, statements: list[tuple[str, Statement]], desc: str, fix: str) -> None:
            if not statements:
                return
            conditional = all(s.is_conditional for _, s in statements)
            out.append(
                Finding(
                    id=fid, title=title, severity=severity, principal=principal.id,
                    status="conditional" if conditional else "confirmed", kind="dangerous",
                    description=desc,
                    evidence=[f"{name}{'#' + s.sid if s.sid else ''}" + (" (conditional)" if s.is_conditional else "") for name, s in statements],
                    remediation=fix,
                    references=["https://docs.aws.amazon.com/IAM/latest/UserGuide/best-practices.html"],
                )
            )

        def allows(stmt: Statement, action: str) -> bool:
            return stmt.is_allow and stmt.applies_to_action(action) and ps.evaluate(action).is_possible

        def full_wildcard(stmt: Statement) -> bool:
            return any(a in ("*", "*:*") for a in stmt.actions)

        stmts = list(ps.statements())
        if ps.is_full_admin():
            add("DNG-001", "Full administrator access (*:*)", Severity.HIGH,
                [(p.name, s) for p, s in stmts if s.is_allow and full_wildcard(s) and s.covers_all_resources],
                "The principal is allowed every action on every resource. Any compromise of it is a full account compromise.",
                "Reserve '*:*' for a small number of break-glass roles protected by MFA; use job-function policies elsewhere.")
        add("DNG-002", "Allow statement with NotAction", Severity.MEDIUM,
            [(p.name, s) for p, s in stmts if s.is_allow and s.not_actions],
            "Allow + NotAction grants every action except those listed, including all future AWS services and actions. "
            "It is easy to under-estimate (e.g. NotAction iam:* still allows sts:AssumeRole and iam-free escalation via PassRole-like services).",
            "Replace NotAction allows with explicit Action allow-lists, or pair them with a tight Resource scope.")
        add("DNG-003", "s3:* on all resources", Severity.MEDIUM,
            [(p.name, s) for p, s in stmts if allows(s, "s3:DeleteBucket") and any(a.lower() == "s3:*" for a in s.actions) and s.covers_all_resources],
            "Full S3 control on every bucket: read/modify/delete any data and change bucket policies (including making buckets public).",
            "Scope S3 permissions to specific bucket ARNs and to the actions actually needed.")
        add("DNG-004", "iam:PassRole on all resources", Severity.HIGH,
            [(p.name, s) for p, s in stmts if allows(s, "iam:PassRole") and s.covers_all_resources and not full_wildcard(s) and not s.not_actions],
            "PassRole on '*' lets the principal hand any role in the account to an AWS service, the building block of most service-based escalation paths.",
            "Restrict iam:PassRole to explicit role ARNs.")
        add("DNG-005", "iam:PassRole without an iam:PassedToService condition", Severity.MEDIUM,
            [(p.name, s) for p, s in stmts if allows(s, "iam:PassRole") and not full_wildcard(s) and not s.not_actions
             and "iam:passedtoservice" not in s.condition_keys()],
            "Without iam:PassedToService the role can be passed to any service, not just the one the workload uses.",
            "Add Condition {\"StringEquals\": {\"iam:PassedToService\": \"<service>.amazonaws.com\"}}.")
        add("DNG-006", "secretsmanager:GetSecretValue on all secrets", Severity.HIGH,
            [(p.name, s) for p, s in stmts if allows(s, "secretsmanager:GetSecretValue") and s.covers_all_resources and not full_wildcard(s)],
            "The principal can read every secret in Secrets Manager, often including database and third-party credentials.",
            "Scope GetSecretValue to specific secret ARNs or use tag-based (ABAC) conditions.")
        add("DNG-007", "kms:Decrypt on all keys", Severity.HIGH,
            [(p.name, s) for p, s in stmts if allows(s, "kms:Decrypt") and s.covers_all_resources and not full_wildcard(s)],
            "kms:Decrypt on '*' removes KMS as a second layer of access control for encrypted data (subject to key policies).",
            "Scope kms:Decrypt to key ARNs and add kms:ViaService / kms:EncryptionContext conditions.")
        add("DNG-008", "iam:* on all resources", Severity.HIGH,
            [(p.name, s) for p, s in stmts if allows(s, "iam:CreateUser") and any(a.lower() == "iam:*" for a in s.actions) and s.covers_all_resources],
            "Full IAM control is equivalent to administrator access: the principal can grant itself any permission.",
            "Delegate IAM administration with scoped actions and a mandatory permissions boundary.")
        add("DNG-009", "sts:AssumeRole on all roles", Severity.LOW,
            [(p.name, s) for p, s in stmts if allows(s, "sts:AssumeRole") and s.covers_all_resources and not full_wildcard(s) and not s.not_actions],
            "The principal may assume any role whose trust policy admits it or its account.",
            "Scope sts:AssumeRole to the role ARNs that are required.")

        if principal.kind == "role" and principal.trust_policy is not None:
            wildcard = []
            root = []
            for s in principal.trust_policy.statements:
                if not s.is_allow:
                    continue
                values = s.principal
                aws: list[str] = []
                if values == "*":
                    aws = ["*"]
                elif isinstance(values, dict):
                    raw = values.get("AWS", [])
                    aws = [raw] if isinstance(raw, str) else list(raw)
                if "*" in aws:
                    wildcard.append((principal.trust_policy.name, s))
                elif any(a.endswith(":root") or a.isdigit() for a in aws):
                    root.append((principal.trust_policy.name, s))
            sev = Severity.CRITICAL if any(not s.is_conditional for _, s in wildcard) else Severity.MEDIUM
            add("TRUST-001", "Role trust policy allows any AWS principal", sev, wildcard,
                "Principal '*' in a trust policy lets any AWS account assume the role unless a Condition restricts it.",
                "Name explicit principal ARNs; for third parties require sts:ExternalId; never use bare '*'.")
            add("TRUST-002", "Role trusts an entire account root", Severity.INFO, root,
                "Trusting ':root' delegates the decision to identity policies: any principal in that account allowed sts:AssumeRole on this role can assume it.",
                "Prefer trusting specific role/user ARNs, or add aws:PrincipalArn / aws:PrincipalTag conditions.")
        return out

    # -------------------------------------------------------------------- entry
    def analyze(self, principal_name: str | None = None) -> Report:
        """Run the full analysis, optionally restricted to one starting principal.

        Raises:
            KeyError: if ``principal_name`` does not match any principal.
        """
        if principal_name:
            principal = self.account.get(principal_name)
            if principal is None:
                raise KeyError(principal_name)
            starts = [principal]
        else:
            starts = sorted(self.account.actors(), key=lambda p: p.id)

        findings: list[Finding] = []
        paths: list[EscalationPath] = []
        admins: list[str] = []
        for principal in starts:
            self.edges_from(principal)
            admin = self.is_admin(principal)
            if admin:
                admins.append(principal.id)
            findings.extend(self.dangerous_findings(principal))
            if admin:
                # Every technique trivially matches an administrator; listing them
                # all would only bury the DNG-001 finding that matters.
                continue
            findings.extend(self._technique_findings.get(principal.id, []))
            for path in self.find_paths(principal):
                paths.append(path)
                findings.append(
                    Finding(
                        id="PATH",
                        title=f"Escalation path to admin in {len(path.edges)} hop(s)",
                        severity=Severity.CRITICAL if not path.conditional else Severity.HIGH,
                        principal=principal.id,
                        status="conditional" if path.conditional else "confirmed",
                        kind="path",
                        description=path.chain(),
                        evidence=[f"{e.source} -[{e.technique}]-> {e.target}: {e.detail}" for e in path.edges],
                        targets=[path.nodes[-1]],
                        remediation="Break the chain at its cheapest hop: see the remediation of each technique involved.",
                    )
                )

        findings.sort(key=lambda f: (-f.severity.rank, f.principal, f.status != "confirmed", f.id))
        return Report(
            source="",
            mode=self.account.mode,
            account_id=self.account.account_id,
            principals=[p.id for p in starts],
            findings=findings,
            paths=paths,
            warnings=list(self.account.warnings),
            admins=admins,
        )


def analyze(account: Account, principal: str | None = None, max_depth: int = 4, source: str = "") -> Report:
    """Convenience wrapper around :class:`Analyzer`."""
    report = Analyzer(account, max_depth=max_depth).analyze(principal)
    report.source = source
    return report
