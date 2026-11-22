"""Command-line interface."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Sequence

from rich.console import Console
from rich.markup import escape

from . import __version__
from .analyzer import analyze
from .model import load_file
from .policy import PolicyParseError
from .render import render_json, render_markdown, render_mermaid, render_table, render_techniques
from .techniques import TECHNIQUES, Severity

__all__ = ["main", "build_parser"]

EXIT_OK = 0
EXIT_FINDINGS = 1
EXIT_ERROR = 2


def build_parser() -> argparse.ArgumentParser:
    """Construct the argument parser."""
    parser = argparse.ArgumentParser(
        prog="iam-privesc-lens",
        description="Offline AWS IAM privilege-escalation analyzer.",
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    a = sub.add_parser(
        "analyze",
        help="analyze a policy document or an authorization-details export",
        description="Analyze an IAM policy JSON or the output of "
        "'aws iam get-account-authorization-details'. Never calls AWS.",
    )
    a.add_argument("input", type=Path, help="policy.json or auth-details.json")
    a.add_argument("--principal", "-p", help="only analyze paths starting at this principal (name, user/x, role/x or ARN)")
    a.add_argument("--format", "-f", choices=["table", "json", "markdown", "mermaid"], default="table")
    a.add_argument("--output", "-o", type=Path, help="write the report to a file instead of stdout")
    a.add_argument("--max-depth", type=int, default=4, help="maximum hops in multi-hop path search (default: 4)")
    a.add_argument(
        "--fail-on",
        choices=[s.value for s in Severity],
        help="exit with status 1 if any finding has this severity or higher",
    )
    a.add_argument("--ignore-conditional", action="store_true", help="exclude condition-gated findings from --fail-on")
    a.add_argument("--details", action="store_true", help="table format: print evidence and remediation per finding")
    a.add_argument("--no-color", action="store_true", help="disable colored output")

    t = sub.add_parser("techniques", help="list the privilege-escalation knowledge base")
    t.add_argument("technique_id", nargs="?", help="show full details for one technique")
    t.add_argument("--format", "-f", choices=["table", "json"], default="table")
    t.add_argument("--no-color", action="store_true", help="disable colored output")

    f = sub.add_parser(
        "fetch",
        help="export authorization details from AWS (read-only, needs boto3)",
        description="Calls only iam:GetAccountAuthorizationDetails (read-only) and saves the JSON "
        "for offline analysis. Requires the [aws] extra.",
    )
    f.add_argument("--output", "-o", type=Path, default=Path("auth-details.json"))
    f.add_argument("--profile", help="AWS named profile")
    f.add_argument("--region", help="AWS region for the session (IAM is global)")
    return parser


def _cmd_analyze(args: argparse.Namespace, console: Console) -> int:
    try:
        account = load_file(args.input)
    except FileNotFoundError:
        console.print(f"[red]error:[/red] file not found: {escape(str(args.input))}")
        return EXIT_ERROR
    except PolicyParseError as exc:
        console.print(f"[red]error:[/red] {escape(str(exc))}")
        return EXIT_ERROR
    if args.max_depth < 1:
        console.print("[red]error:[/red] --max-depth must be at least 1")
        return EXIT_ERROR
    try:
        report = analyze(account, principal=args.principal, max_depth=args.max_depth, source=str(args.input))
    except KeyError:
        names = ", ".join(sorted(p.id for p in account.actors()))
        console.print(f"[red]error:[/red] principal {args.principal!r} not found. Known: {escape(names)}")
        return EXIT_ERROR

    if args.format == "table" and args.output is None:
        render_table(report, console, details=args.details)
    else:
        if args.format == "json":
            text = render_json(report)
        elif args.format == "markdown":
            text = render_markdown(report)
        elif args.format == "mermaid":
            text = render_mermaid(report)
        else:
            file_console = Console(record=True, width=140, force_terminal=False, no_color=True)
            with file_console.capture():
                render_table(report, file_console, details=args.details)
            text = file_console.export_text()
        if args.output:
            args.output.write_text(text if text.endswith("\n") else text + "\n", encoding="utf-8")
            console.print(f"report written to {args.output}", highlight=False)
        else:
            sys.stdout.write(text if text.endswith("\n") else text + "\n")

    if args.fail_on:
        threshold = Severity(args.fail_on).rank
        failing = [
            f for f in report.findings
            if f.severity.rank >= threshold and not (args.ignore_conditional and f.status == "conditional")
        ]
        if failing:
            print(
                f"iam-privesc-lens: {len(failing)} finding(s) at or above '{args.fail_on}'",
                file=sys.stderr,
            )
            return EXIT_FINDINGS
    return EXIT_OK


def _cmd_techniques(args: argparse.Namespace, console: Console) -> int:
    techniques = list(TECHNIQUES.values())
    if args.technique_id:
        technique = TECHNIQUES.get(args.technique_id.upper())
        if technique is None:
            console.print(f"[red]error:[/red] unknown technique {args.technique_id!r}")
            return EXIT_ERROR
        techniques = [technique]
    if args.format == "json":
        payload = [
            {
                "id": t.id,
                "name": t.name,
                "severity": t.severity.value,
                "gains": t.target,
                "all_of": list(t.all_of),
                "any_of": [list(g) for g in t.any_of],
                "explanation": t.explanation,
                "steps": list(t.steps),
                "remediation": t.remediation,
                "references": list(t.references),
            }
            for t in techniques
        ]
        sys.stdout.write(json.dumps(payload, indent=2) + "\n")
        return EXIT_OK
    if args.technique_id:
        t = techniques[0]
        console.print(f"[bold]{t.id}[/bold] {t.name}  ([bold]{t.severity.value}[/bold], gains: {t.target})")
        console.print(f"[bold]Requires:[/bold] {', '.join(t.required_actions)}")
        console.print(f"\n{t.explanation}\n")
        console.print("[bold]Exploitation:[/bold]")
        for step in t.steps:
            console.print(f"  [dim]{step}[/dim]", highlight=False)
        console.print(f"\n[bold]Remediation:[/bold] {t.remediation}")
        for ref in t.references:
            console.print(f"  ref: {ref}", highlight=False)
        return EXIT_OK
    render_techniques(techniques, console)
    return EXIT_OK


def _cmd_fetch(args: argparse.Namespace, console: Console) -> int:
    from .fetch import BotoUnavailableError, fetch_authorization_details

    console.print("Calling iam:GetAccountAuthorizationDetails (read-only)...")
    try:
        counts = fetch_authorization_details(args.output, profile=args.profile, region=args.region)
    except BotoUnavailableError as exc:
        console.print(f"[red]error:[/red] {escape(str(exc))}")
        return EXIT_ERROR
    except Exception as exc:  # noqa: BLE001 - surface any botocore error cleanly
        console.print(f"[red]error:[/red] AWS call failed: {escape(str(exc))}")
        return EXIT_ERROR
    summary = ", ".join(f"{v} {k}" for k, v in counts.items())
    console.print(f"Saved {escape(str(args.output))} ({summary}). Analyze with: iam-privesc-lens analyze {escape(str(args.output))}")
    return EXIT_OK


def main(argv: Sequence[str] | None = None) -> int:
    """CLI entry point. Returns the process exit status."""
    parser = build_parser()
    args = parser.parse_args(argv)
    no_color = getattr(args, "no_color", False)
    console = Console(stderr=False, no_color=no_color, highlight=False)
    if args.command == "analyze":
        return _cmd_analyze(args, console)
    if args.command == "techniques":
        return _cmd_techniques(args, console)
    return _cmd_fetch(args, console)
