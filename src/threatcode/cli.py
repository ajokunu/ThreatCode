"""Click CLI for ThreatCode."""

from __future__ import annotations

import logging
import sys
from pathlib import Path
from typing import TYPE_CHECKING

import click

from threatcode import __version__
from threatcode.exceptions import ConfigError, LLMError, ThreatCodeError

logger = logging.getLogger(__name__)

if TYPE_CHECKING:
    from threatcode.config import ThreatCodeConfig
    from threatcode.engine.llm.client import BaseLLMClient
    from threatcode.ir.graph import InfraGraph
    from threatcode.models.report import ThreatReport


def _describe_error(exc: BaseException) -> str:
    """Describe an error for the user: ThreatCode errors are already written for people."""
    if isinstance(exc, ThreatCodeError):
        return str(exc)
    return f"{type(exc).__name__}: {exc}"


@click.group(context_settings={"help_option_names": ["-h", "--help"]})
@click.version_option(version=__version__, prog_name="threatcode")
def cli() -> None:
    """ThreatCode: STRIDE threat models from infrastructure code and AI-agent configs.

    Commands: scan builds a threat model from an input file, diff compares two reports.
    """


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
    """Scan an IaC file, a Terraform directory or an MCP config and build a STRIDE threat model.

    INPUT_FILE is a Terraform plan JSON, a .tf file or a directory of them, a
    CloudFormation template, a Kubernetes manifest, a Helm Chart.yaml, a Dockerfile or
    an MCP client config. Exit status is 1 when any threat is found.
    """
    from threatcode.config import load_config
    from threatcode.engine.hybrid import HybridEngine
    from threatcode.ir.graph import InfraGraph
    from threatcode.models.threat import Severity
    from threatcode.parsers import detect_and_parse

    cfg_path = Path(config_path) if config_path else None
    try:
        config = load_config(cfg_path)
    except ConfigError as e:
        click.echo(f"Error: {e}", err=True)
        sys.exit(1)
    config.no_llm = no_llm or config.no_llm
    config.dry_run = dry_run or config.dry_run
    config.output_format = output_format  # type: ignore[assignment]

    try:
        parsed = detect_and_parse(input_file)
    except Exception as e:
        click.echo(f"Error parsing input file: {_describe_error(e)}", err=True)
        sys.exit(1)

    try:
        graph = InfraGraph.from_parsed(parsed)
    except Exception as e:
        click.echo(f"Error building infrastructure graph: {_describe_error(e)}", err=True)
        sys.exit(1)

    llm_client = None
    if not config.no_llm:
        try:
            llm_client = _build_llm_client(config, dry_run)
        except LLMError as e:
            click.echo(f"Error: invalid LLM configuration: {e}", err=True)
            sys.exit(1)

    extra_paths = [Path(p) for p in extra_rules]
    try:
        engine = HybridEngine(config=config, extra_rule_paths=extra_paths, llm_client=llm_client)
        report = engine.analyze(graph, input_file=input_file)
    except Exception as e:
        click.echo(f"Error during analysis: {_describe_error(e)}", err=True)
        sys.exit(1)

    if min_severity != "info":
        report.threats = report.filter_by_severity(Severity(min_severity))

    output = _format_output(report, output_format, graph=graph)
    if output_path:
        out = Path(output_path)
        if out.is_dir():
            click.echo("Error: output path is a directory, not a file.", err=True)
            sys.exit(1)
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(output, encoding="utf-8")
        click.echo(f"Output written to {out.name}")
    else:
        click.echo(output)

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

    try:
        result = compute_diff(baseline, current)
        output = format_diff(result, output_format)
    except Exception as e:
        click.echo(f"Error computing diff: {_describe_error(e)}", err=True)
        sys.exit(1)
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
        if not config.llm.base_url:
            raise LLMError(f"provider '{config.llm.provider}' requires llm.base_url")
        return OpenAICompatibleLLMClient(
            base_url=config.llm.base_url,
            api_key=config.llm.api_key,
            model=config.llm.model,
            max_tokens=config.llm.max_tokens,
            # Config validation already limits this to ollama and local.
            allow_local_network=config.llm.allow_local_network,
        )

    click.echo(
        f"Warning: Unknown LLM provider '{config.llm.provider}'. "
        "Supported: anthropic, openai, ollama, local. Falling back to rules-only.",
        err=True,
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
