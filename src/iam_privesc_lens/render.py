"""Output renderers: rich tables, JSON, Markdown and Mermaid."""

from __future__ import annotations

import json
import re

from rich.console import Console, Group
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from rich.tree import Tree

from .analyzer import ADMIN, Edge, Finding, Report
from .techniques import TECHNIQUES, Severity, Technique

__all__ = ["render_json", "render_markdown", "render_mermaid", "render_table", "render_techniques"]

SEVERITY_STYLE = {
    Severity.CRITICAL: "bold white on red",
    Severity.HIGH: "bold red",
    Severity.MEDIUM: "yellow",
    Severity.LOW: "cyan",
    Severity.INFO: "dim",
}


def _technique_name(technique_id: str) -> str:
    technique = TECHNIQUES.get(technique_id)
    return technique.name if technique else technique_id


# ----------------------------------------------------------------------- JSON
def render_json(report: Report) -> str:
    """Machine-readable report."""
    return json.dumps(report.to_dict(), indent=2)


# -------------------------------------------------------------------- Mermaid
def _node_id(name: str) -> str:
    return re.sub(r"[^A-Za-z0-9_]", "_", name)


def _node_decl(name: str) -> str:
    nid = _node_id(name)
    if name == ADMIN:
        return f'{nid}{{{{"ADMIN<br/>full account control"}}}}'
    kind = name.split("/", 1)[0]
    if kind == "user":
        return f'{nid}(["{name}"])'
    if kind == "group":
        return f'{nid}[["{name}"]]'
    if kind == "role":
        return f'{nid}("{name}")'
    return f'{nid}["{name}"]'


def render_mermaid(report: Report) -> str:
    """Mermaid flowchart of every escalation path in the report."""
    lines = ["flowchart LR"]
    edges: list[Edge] = []
    seen: set[tuple[str, str, str]] = set()
    admin_ends: set[str] = set()
    for path in report.paths:
        for edge in path.edges:
            key = (edge.source, edge.target, edge.technique)
            if key not in seen:
                seen.add(key)
                edges.append(edge)
        if path.nodes[-1] != ADMIN:
            admin_ends.add(path.nodes[-1])
    if not edges:
        lines.append('    none["No privilege-escalation paths found"]')
        return "\n".join(lines) + "\n"

    nodes: list[str] = []
    for edge in edges:
        for n in (edge.source, edge.target):
            if n not in nodes:
                nodes.append(n)
    if admin_ends and ADMIN not in nodes:
        nodes.append(ADMIN)
    for n in nodes:
        lines.append(f"    {_node_decl(n)}")
    for edge in edges:
        arrow = "-.->" if edge.conditional else "-->"
        label = f"{edge.technique}: {_technique_name(edge.technique)}"
        if edge.conditional:
            label += " (conditional)"
        label = label.replace('"', "'")
        lines.append(f'    {_node_id(edge.source)} {arrow}|"{label}"| {_node_id(edge.target)}')
    for n in sorted(admin_ends):
        lines.append(f'    {_node_id(n)} ==>|"holds *:*"| {_node_id(ADMIN)}')
    starts = sorted({p.start for p in report.paths})
    lines.append("    classDef admin fill:#d7263d,stroke:#7a0010,color:#fff,font-weight:bold")
    lines.append("    classDef start fill:#1b4965,stroke:#0b2537,color:#fff")
    lines.append("    classDef privileged fill:#f4a259,stroke:#9c5a14,color:#111")
    lines.append(f"    class {_node_id(ADMIN)} admin")
    if starts:
        lines.append(f"    class {','.join(_node_id(s) for s in starts)} start")
    if admin_ends:
        lines.append(f"    class {','.join(_node_id(n) for n in sorted(admin_ends))} privileged")
    return "\n".join(lines) + "\n"


# ------------------------------------------------------------------- Markdown
def _md_escape(text: str) -> str:
    return text.replace("|", "\\|")


def render_markdown(report: Report) -> str:
    """A self-contained Markdown report (renders well on GitHub)."""
    data = report.to_dict()
    out: list[str] = ["# IAM privilege-escalation report", ""]
    out.append(f"- **Source:** `{report.source or '-'}`")
    out.append(f"- **Mode:** {report.mode}")
    if report.account_id:
        out.append(f"- **Account:** {report.account_id}")
    out.append(f"- **Principals analysed:** {len(report.principals)}")
    out.append(f"- **Admin-equivalent principals:** {', '.join(report.admins) or 'none'}")
    sev = data["summary"]["by_severity"]
    out.append(
        f"- **Findings:** {len(report.findings)} "
        f"(critical {sev['critical']}, high {sev['high']}, medium {sev['medium']}, low {sev['low']}, info {sev['info']})"
    )
    out.append(f"- **Escalation paths:** {len(report.paths)}")
    out.append("")

    out.append("## Escalation graph")
    out.append("")
    out.append("```mermaid")
    out.append(render_mermaid(report).rstrip())
    out.append("```")
    out.append("")

    if report.paths:
        out.append("## Escalation paths")
        out.append("")
        for i, path in enumerate(report.paths, 1):
            status = "conditional" if path.conditional else "confirmed"
            out.append(f"### {i}. `{path.chain()}` ({status})")
            out.append("")
            for n, edge in enumerate(path.edges, 1):
                technique = TECHNIQUES.get(edge.technique)
                out.append(f"{n}. **{edge.source} → {edge.target}** via `{edge.technique}` {_technique_name(edge.technique)}")
                out.append(f"   - Why: {edge.detail}")
                if edge.assumption:
                    out.append(f"   - Assumes: {edge.assumption}")
                if edge.conditional:
                    out.append("   - Gated by an IAM Condition: verify whether it can be satisfied.")
                if technique:
                    out.append("   - Exploitation:")
                    for step in technique.steps:
                        out.append(f"     - `{step}`")
                    out.append(f"   - Fix: {technique.remediation}")
            out.append(f"{len(path.edges) + 1}. **Result:** {path.end_reason}.")
            out.append("")

    out.append("## Findings")
    out.append("")
    if report.findings:
        out.append("| Severity | Principal | ID | Finding | Status | Targets |")
        out.append("|---|---|---|---|---|---|")
        for f in report.findings:
            targets = ", ".join(f.targets[:4]) + (" …" if len(f.targets) > 4 else "")
            out.append(
                f"| {f.severity.value} | `{f.principal}` | {f.id} | {_md_escape(f.title)} | {f.status} | {_md_escape(targets) or '-'} |"
            )
        out.append("")
        out.append("<details><summary>Finding details</summary>")
        out.append("")
        for f in report.findings:
            if f.kind == "path":
                continue
            out.append(f"#### {f.id} · {f.title} · `{f.principal}`")
            out.append("")
            out.append(f"{f.description}")
            out.append("")
            if f.note:
                out.append(f"> {f.note}")
                out.append("")
            out.append("Evidence:")
            out.extend(f"- `{e}`" for e in f.evidence)
            out.append("")
            out.append(f"Remediation: {f.remediation}")
            out.append("")
        out.append("</details>")
    else:
        out.append("No findings.")
    out.append("")
    if report.warnings:
        out.append("## Warnings")
        out.append("")
        out.extend(f"- {w}" for w in report.warnings)
        out.append("")
    return "\n".join(out)


# ---------------------------------------------------------------------- rich
def _sev(severity: Severity) -> Text:
    return Text(severity.value.upper(), style=SEVERITY_STYLE[severity])


def _status(status: str) -> Text:
    return Text(status, style="green" if status == "confirmed" else "magenta")


def render_table(report: Report, console: Console, details: bool = False) -> None:
    """Pretty terminal output."""
    data = report.to_dict()
    sev = data["summary"]["by_severity"]
    header = Table.grid(padding=(0, 2))
    header.add_column(style="bold")
    header.add_column()
    header.add_row("Source", report.source or "-")
    header.add_row("Mode", report.mode + (f" (account {report.account_id})" if report.account_id else ""))
    header.add_row("Principals", str(len(report.principals)))
    header.add_row("Admin-equivalent", ", ".join(report.admins) or "none")
    header.add_row(
        "Findings",
        Text.assemble(
            (f"{sev['critical']} critical", SEVERITY_STYLE[Severity.CRITICAL]), "  ",
            (f"{sev['high']} high", SEVERITY_STYLE[Severity.HIGH]), "  ",
            (f"{sev['medium']} medium", SEVERITY_STYLE[Severity.MEDIUM]), "  ",
            (f"{sev['low']} low", SEVERITY_STYLE[Severity.LOW]), "  ",
            (f"{sev['info']} info", SEVERITY_STYLE[Severity.INFO]),
        ),
    )
    header.add_row("Escalation paths", str(len(report.paths)))
    console.print(Panel(header, title="[bold]iam-privesc-lens[/bold]", border_style="blue", expand=False))

    if report.paths:
        console.print()
        console.rule("[bold]Escalation paths")
        for i, path in enumerate(report.paths, 1):
            status = "conditional" if path.conditional else "confirmed"
            tree = Tree(Text.assemble((f"{i}. ", "bold"), (path.chain(), "bold cyan"), "  ", _status(status)))
            for n, edge in enumerate(path.edges, 1):
                technique = TECHNIQUES.get(edge.technique)
                hop = tree.add(
                    Text.assemble(
                        (f"hop {n}: ", "bold"), (f"{edge.source} -> {edge.target}", "cyan"),
                        "  ", (f"[{edge.technique}] {_technique_name(edge.technique)}", "yellow"),
                    )
                )
                hop.add(Text(f"why: {edge.detail}"))
                if edge.assumption:
                    hop.add(Text(f"assumes: {edge.assumption}", style="italic"))
                if edge.conditional:
                    hop.add(Text("gated by an IAM Condition - verify whether it can be satisfied", style="magenta"))
                if technique:
                    steps = hop.add(Text("exploitation", style="bold"))
                    for step in technique.steps:
                        steps.add(Text(step, style="dim"))
                    hop.add(Text(f"fix: {technique.remediation}", style="green"))
            tree.add(Text(f"result: {path.end_reason}", style="bold red"))
            console.print(tree)

    console.print()
    console.rule("[bold]Findings")
    if not report.findings:
        console.print("[green]No findings.[/green]")
    else:
        table = Table(show_lines=False, header_style="bold", expand=True)
        table.add_column("Severity", no_wrap=True)
        table.add_column("Principal", style="cyan", no_wrap=True)
        table.add_column("ID", no_wrap=True)
        table.add_column("Finding", ratio=2)
        table.add_column("Status", no_wrap=True)
        table.add_column("Targets / evidence", ratio=2, overflow="fold")
        for f in report.findings:
            targets = ", ".join(f.targets[:3]) + (f" (+{len(f.targets) - 3})" if len(f.targets) > 3 else "")
            if f.kind == "path":
                extra = f.description
            elif targets:
                extra = targets
            else:
                extra = f.note or ", ".join(f.evidence[:2])
            title = f.title
            table.add_row(_sev(f.severity), f.principal, f.id, title, _status(f.status), extra)
        console.print(table)

    if details:
        for f in report.findings:
            if f.kind == "path":
                continue
            body: list[Text | str] = [Text(f.description)]
            if f.note:
                body.append(Text(f"note: {f.note}", style="italic"))
            body.append(Text("evidence:", style="bold"))
            body.extend(Text(f"  {e}", style="dim") for e in f.evidence)
            if f.steps:
                body.append(Text("exploitation:", style="bold"))
                body.extend(Text(f"  {s}", style="dim") for s in f.steps)
            body.append(Text(f"fix: {f.remediation}", style="green"))
            console.print(
                Panel(
                    Group(*body),
                    title=Text.assemble(_sev(f.severity), f" {f.id} {f.title} ", (f.principal, "cyan")),
                    title_align="left",
                    border_style=SEVERITY_STYLE[f.severity].split()[-1],
                )
            )
    elif any(f.kind != "path" for f in report.findings):
        console.print("[dim]Run with --details for evidence, exploitation steps and remediation per finding.[/dim]")

    for warning in report.warnings:
        console.print(f"[yellow]warning:[/yellow] {warning}")


def render_techniques(techniques: list[Technique], console: Console) -> None:
    """Table of the technique knowledge base."""
    table = Table(header_style="bold", expand=True, title="Privilege-escalation techniques")
    table.add_column("ID", no_wrap=True)
    table.add_column("Severity", no_wrap=True)
    table.add_column("Technique")
    table.add_column("Required actions", style="cyan")
    table.add_column("Gains", no_wrap=True)
    for t in techniques:
        table.add_row(t.id, _sev(t.severity), t.name, "\n".join(t.required_actions), t.target)
    console.print(table)
