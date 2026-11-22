"""Multi-hop path search over synthetic account exports."""

from __future__ import annotations

from iam_privesc_lens.analyzer import ADMIN, Analyzer, analyze
from iam_privesc_lens.model import Account


def chains(report) -> dict[str, list[tuple[str, bool]]]:
    out: dict[str, list[tuple[str, bool]]] = {}
    for p in report.paths:
        out.setdefault(p.start, []).append((p.chain(), p.conditional))
    return out


def test_model_resolution(multihop_account: Account) -> None:
    eve = multihop_account.get("eve")
    assert eve is not None and eve.kind == "user"
    assert any(p.name == "group/staff:staff" for p in eve.policies)
    gina = multihop_account.get("user/gina")
    assert gina is not None and gina.boundary is not None
    support = multihop_account.get("arn:aws:iam::111122223333:role/support")
    assert support is not None and support.trust_policy is not None
    assert multihop_account.account_id == "111122223333"


def test_two_hop_path_via_assume_role_and_access_key(multihop_account: Account) -> None:
    report = analyze(multihop_account, principal="eve")
    path = report.paths[0]
    assert path.nodes == ["user/eve", "role/support", "user/ops-admin"]
    assert [e.technique for e in path.edges] == ["STS-001", "IAM-010"]
    assert not path.conditional
    assert path.chain().endswith("=> ADMIN")
    assert "names user/eve directly" in path.edges[0].detail


def test_group_join_path(multihop_account: Account) -> None:
    report = analyze(multihop_account, principal="frank")
    assert ("user/frank -> group/admins => ADMIN", False) in chains(report)["user/frank"]


def test_permission_boundary_blocks_escalation(multihop_account: Account) -> None:
    report = analyze(multihop_account, principal="gina")
    assert report.paths == []
    assert not any(f.kind == "privesc" for f in report.findings)
    assert not any(f.id == "DNG-008" for f in report.findings)


def test_conditional_trust_and_explicit_trust_deny(multihop_account: Account) -> None:
    report = analyze(multihop_account, principal="hank")
    hank = chains(report)["user/hank"]
    assert ("user/hank -> role/mfa-only => ADMIN", True) in hank
    assert not any("role/denied" in c for c, _ in hank)


def test_admin_principals_skip_paths(multihop_account: Account) -> None:
    report = analyze(multihop_account)
    assert "user/ops-admin" in report.admins
    assert "user/ops-admin" not in chains(report)
    assert any(f.id == "DNG-001" and f.principal == "user/ops-admin" for f in report.findings)


def test_depth_limit(multihop_account: Account) -> None:
    shallow = Analyzer(multihop_account, max_depth=1).analyze("eve")
    assert shallow.paths == []
    deep = Analyzer(multihop_account, max_depth=2).analyze("eve")
    assert len(deep.paths[0].edges) == 2


def test_example_account_two_hop(example_account: Account) -> None:
    report = analyze(example_account)
    by_start = chains(report)
    assert by_start["user/dev-alice"][0] == (
        "user/dev-alice -> role/ci-deployer -> role/lambda-ops-automation => ADMIN",
        False,
    )
    assert by_start["user/intern-bob"] == [("user/intern-bob -> ADMIN", True)]
    assert "user/ops-carol" not in by_start  # blocked by permissions boundary
    ids = {(f.principal, f.id) for f in report.findings}
    assert ("role/legacy-partner-access", "TRUST-001") in ids
    assert ("user/svc-backup", "DNG-003") in ids
    assert ("role/ci-deployer", "DNG-005") in ids
    assert report.warnings == []


def test_path_edge_end_reason(example_account: Account) -> None:
    report = analyze(example_account, principal="dev-alice")
    path = report.paths[0]
    assert path.edges[-1].target != ADMIN
    assert "full administrator access" in path.end_reason
