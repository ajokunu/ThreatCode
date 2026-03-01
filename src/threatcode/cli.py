"""Click CLI for ThreatCode."""

from __future__ import annotations

import sys
from pathlib import Path
from typing import TYPE_CHECKING

import click

from threatcode import __version__

if TYPE_CHECKING:
    from threatcode.config import ThreatCodeConfig
    from threatcode.engine.llm.client import BaseLLMClient
    from threatcode.ir.graph import InfraGraph
    from threatcode.models.report import ThreatReport


@click.group()
@click.version_option(version=__version__, prog_name="threatcode")
def cli() -> None:
    """ThreatCode — STRIDE threat model generator from Infrastructure-as-Code."""


@cli.command()
@click.argument("input_file", type=click.Path(exists=True))
@click.option(
    "--format",
    "-f",
    "output_format",
    default="json",
    type=click.Choice(["json", "sarif", "markdown", "bitbucket", "matrix", "diagram"]),
    help="Output format.",
)
@click.option(
    "--output",
    "-o",
    "output_path",
    type=click.Path(),
    default=None,
    help="Write output to file instead of stdout.",
)
@click.option("--no-llm", is_flag=True, default=False, help="Disable LLM analysis, use rules only.")
@click.option(
    "--dry-run",
    is_flag=True,
    default=False,
    help="Show what would be sent to LLM without calling it.",
)
@click.option(
    "--min-severity",
    default="info",
    type=click.Choice(["critical", "high", "medium", "low", "info"]),
    help="Minimum severity to include in output.",
)
@click.option(
    "--config",
    "-c",
    "config_path",
    type=click.Path(),
    default=None,
    help="Path to .threatcode.yml config file.",
)
@click.option(
    "--rules",
    "-r",
    "extra_rules",
    type=click.Path(exists=True),
    multiple=True,
    help="Additional rule files to load.",
)
def scan(
    input_file: str,
    output_format: str,
    output_path: str | None,
    no_llm: bool,
    dry_run: bool,
    min_severity: str,
    config_path: str | None,
    extra_rules: tuple[str, ...],
) -> None:
    """Scan an IaC file and generate a STRIDE threat model."""
    from threatcode.config import load_config
    from threatcode.engine.hybrid import HybridEngine
    from threatcode.ir.graph import InfraGraph
    from threatcode.models.threat import Severity
    from threatcode.parsers import detect_and_parse

    # Load config
    cfg_path = Path(config_path) if config_path else None
    config = load_config(cfg_path)
    config.no_llm = no_llm or config.no_llm
    config.dry_run = dry_run or config.dry_run
    config.output_format = output_format

    # Parse input
    try:
        parsed = detect_and_parse(input_file)
    except Exception as e:
        click.echo(f"Error parsing {input_file}: {e}", err=True)
        sys.exit(1)

    # Build IR graph
    graph = InfraGraph.from_parsed(parsed)

    # Build LLM client if needed
    llm_client = None
    if not config.no_llm:
        llm_client = _build_llm_client(config, dry_run)

    # Run engine
    extra_paths = [Path(p) for p in extra_rules]
    engine = HybridEngine(config=config, extra_rule_paths=extra_paths, llm_client=llm_client)
    report = engine.analyze(graph, input_file=input_file)

    # Filter by severity
    if min_severity != "info":
        report.threats = report.filter_by_severity(Severity(min_severity))

    # Format output
    output = _format_output(report, output_format, graph=graph)

    if output_path:
        Path(output_path).write_text(output, encoding="utf-8")
        click.echo(f"Output written to {output_path}")
    else:
        click.echo(output)

    # Summary to stderr
    total = len(report.threats)
    click.echo(
        f"\nScanned {report.scanned_resources} resources, found {total} threats.",
        err=True,
    )
    if total > 0:
        sys.exit(1)


@cli.command()
@click.argument("baseline", type=click.Path(exists=True))
@click.argument("current", type=click.Path(exists=True))
@click.option(
    "--format",
    "-f",
    "output_format",
    default="json",
    type=click.Choice(["json", "markdown"]),
    help="Output format for diff.",
)
def diff(baseline: str, current: str, output_format: str) -> None:
    """Compare two threat model reports and show differences."""
    from threatcode.formatters.diff import compute_diff, format_diff

    result = compute_diff(baseline, current)
    output = format_diff(result, output_format)
    click.echo(output)


def _build_llm_client(config: ThreatCodeConfig, dry_run: bool) -> BaseLLMClient | None:
    """Build the appropriate LLM client based on config."""
    from threatcode.engine.llm.client import (
        AnthropicLLMClient,
        DryRunLLMClient,
        OpenAICompatibleLLMClient,
    )

    if dry_run:
        return DryRunLLMClient()

    if config.llm.provider == "anthropic":
        api_key = config.llm.api_key
        if not api_key:
            import os

            api_key = os.environ.get("ANTHROPIC_API_KEY", "")
        if not api_key:
            click.echo(
                "Warning: No Anthropic API key. Use --no-llm or set ANTHROPIC_API_KEY.",
                err=True,
            )
            return None
        return AnthropicLLMClient(
            api_key=api_key,
            model=config.llm.model,
            max_tokens=config.llm.max_tokens,
        )

    if config.llm.provider in ("openai", "ollama", "local"):
        return OpenAICompatibleLLMClient(
            base_url=config.llm.base_url,
            api_key=config.llm.api_key,
            model=config.llm.model,
            max_tokens=config.llm.max_tokens,
        )

    return None


def _format_output(
    report: ThreatReport,
    fmt: str,
    *,
    graph: InfraGraph | None = None,
) -> str:
    if fmt == "json":
        from threatcode.formatters.json_out import format_json

        return format_json(report)
    elif fmt == "sarif":
        from threatcode.formatters.sarif import format_sarif

        return format_sarif(report)
    elif fmt == "markdown":
        from threatcode.formatters.markdown import format_markdown

        return format_markdown(report)
    elif fmt == "bitbucket":
        from threatcode.formatters.bitbucket import format_bitbucket

        return format_bitbucket(report)
    elif fmt == "matrix":
        from threatcode.formatters.attack_navigator import format_attack_navigator

        return format_attack_navigator(report)
    elif fmt == "diagram":
        from threatcode.formatters.diagram import format_diagram

        if graph is None:
            raise click.ClickException("Diagram format requires graph context.")
        return format_diagram(report, graph)
    else:
        from threatcode.formatters.json_out import format_json

        return format_json(report)
