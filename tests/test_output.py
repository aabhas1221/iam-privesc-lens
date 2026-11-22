"""Renderer and CLI tests."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from iam_privesc_lens.analyzer import analyze
from iam_privesc_lens.cli import main
from iam_privesc_lens.model import Account
from iam_privesc_lens.render import render_json, render_markdown, render_mermaid

ROOT = Path(__file__).resolve().parent.parent
EXAMPLE = ROOT / "examples" / "vulnerable-account.json"
FIXTURE = Path(__file__).resolve().parent / "fixtures" / "multihop-account.json"


def test_json_structure(example_account: Account) -> None:
    data = json.loads(render_json(analyze(example_account, source="x.json")))
    assert data["tool"] == "iam-privesc-lens"
    assert data["account_id"] == "123456789012"
    assert data["summary"]["paths"] == len(data["paths"]) > 0
    assert sum(data["summary"]["by_severity"].values()) == data["summary"]["findings"]
    alice = next(p for p in data["paths"] if p["start"] == "user/dev-alice")
    assert alice["hops"] == 2
    assert [e["technique"] for e in alice["edges"]] == ["STS-001", "PASS-001"]


def test_mermaid_graph(example_account: Account) -> None:
    text = render_mermaid(analyze(example_account, principal="dev-alice"))
    lines = text.splitlines()
    assert lines[0] == "flowchart LR"
    assert 'user_dev_alice(["user/dev-alice"])' in text
    assert "user_dev_alice -->|\"STS-001: Assume a role that trusts this principal\"| role_ci_deployer" in text
    assert "role_ci_deployer -->|\"PASS-001" in text
    assert 'role_lambda_ops_automation ==>|"holds *:*"| ADMIN' in text
    assert "class ADMIN admin" in text
    assert text.count("ADMIN{{") == 1


def test_mermaid_conditional_edges_are_dotted(example_account: Account) -> None:
    text = render_mermaid(analyze(example_account, principal="intern-bob"))
    assert "user_intern_bob -.->|" in text and "(conditional)" in text


def test_mermaid_no_paths() -> None:
    from conftest import policy

    text = render_mermaid(analyze(policy({"Effect": "Allow", "Action": "s3:GetObject", "Resource": "*"})))
    assert "No privilege-escalation paths found" in text


def test_markdown_contains_mermaid_and_steps(example_account: Account) -> None:
    md = render_markdown(analyze(example_account, principal="dev-alice", source="examples/vulnerable-account.json"))
    assert "```mermaid" in md
    assert "aws lambda create-function" in md
    assert "| Severity | Principal |" in md


def test_cli_table(capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["analyze", str(EXAMPLE), "--principal", "dev-alice", "--no-color", "--details"]) == 0
    out = capsys.readouterr().out
    assert "Escalation paths" in out and "PASS-001" in out


def test_cli_json_and_fail_on(capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["analyze", str(EXAMPLE), "-f", "json", "--fail-on", "critical"]) == 1
    data = json.loads(capsys.readouterr().out)
    assert data["mode"] == "account"


def test_cli_fail_on_ignore_conditional(capsys: pytest.CaptureFixture[str]) -> None:
    args = ["analyze", str(ROOT / "examples" / "policies" / "mfa-gated-attach.json"), "-f", "json", "--fail-on", "high"]
    assert main(args) == 1
    assert main(args + ["--ignore-conditional"]) == 0


def test_cli_clean_policy_passes(capsys: pytest.CaptureFixture[str]) -> None:
    args = ["analyze", str(ROOT / "examples" / "policies" / "least-privilege.json"), "--fail-on", "low", "--no-color"]
    assert main(args) == 0


def test_cli_output_file(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    out = tmp_path / "graph.mmd"
    assert main(["analyze", str(FIXTURE), "-f", "mermaid", "-o", str(out)]) == 0
    assert out.read_text().startswith("flowchart LR")


def test_cli_errors(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["analyze", str(tmp_path / "missing.json")]) == 2
    bad = tmp_path / "bad.json"
    bad.write_text('{"foo": 1}')
    assert main(["analyze", str(bad)]) == 2
    assert main(["analyze", str(EXAMPLE), "--principal", "nobody"]) == 2


def test_cli_techniques(capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["techniques", "-f", "json"]) == 0
    data = json.loads(capsys.readouterr().out)
    assert len(data) >= 20
    assert main(["techniques", "iam-013"]) == 0
    assert "update-assume-role-policy" in capsys.readouterr().out
    assert main(["techniques", "NOPE-1"]) == 2
