"""Click CLI for ThreatCode."""

from __future__ import annotations

import sys
from pathlib import Path
from typing import TYPE_CHECKING, Any

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
@click.option(
    "--scanners",
    "-s",
    "scanners",
    default="misconfig",
    help="Comma-separated scanner types: misconfig,secret,vuln,license. Default: misconfig.",
)
@click.option(
    "--ignore-unfixed",
    is_flag=True,
    default=False,
    help="Skip unfixed vulnerabilities (for vuln scanner).",
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
    scanners: str,
    ignore_unfixed: bool,
) -> None:
    """Scan an IaC file and generate a STRIDE threat model."""
    import json as json_mod

    from threatcode.config import load_config
    from threatcode.engine.hybrid import HybridEngine
    from threatcode.ir.graph import InfraGraph
    from threatcode.models.threat import Severity
    from threatcode.parsers import detect_and_parse

    scanner_list = [s.strip() for s in scanners.split(",") if s.strip()]
    valid_scanners = {"misconfig", "secret", "vuln", "license"}
    for s in scanner_list:
        if s not in valid_scanners:
            click.echo(
                f"Unknown scanner '{s}'. Valid: {', '.join(sorted(valid_scanners))}",
                err=True,
            )
            sys.exit(1)

    has_issues = False
    combined: dict[str, Any] = {"scanners": scanner_list}

    # ── Misconfig scanner (default) ──────────────────────────────────
    if "misconfig" in scanner_list:
        cfg_path = Path(config_path) if config_path else None
        config = load_config(cfg_path)
        config.no_llm = no_llm or config.no_llm
        config.dry_run = dry_run or config.dry_run
        config.output_format = output_format

        try:
            parsed = detect_and_parse(input_file)
        except Exception as e:
            click.echo(f"Error parsing input file: {type(e).__name__}: {e}", err=True)
            sys.exit(1)

        try:
            graph = InfraGraph.from_parsed(parsed)
        except Exception as e:
            click.echo(
                f"Error building infrastructure graph: {type(e).__name__}: {e}",
                err=True,
            )
            sys.exit(1)

        llm_client = None
        if not config.no_llm:
            llm_client = _build_llm_client(config, dry_run)

        extra_paths = [Path(p) for p in extra_rules]
        try:
            engine = HybridEngine(
                config=config, extra_rule_paths=extra_paths, llm_client=llm_client
            )
            report = engine.analyze(graph, input_file=input_file)
        except Exception as e:
            click.echo(f"Error during analysis: {type(e).__name__}: {e}", err=True)
            sys.exit(1)

        if min_severity != "info":
            report.threats = report.filter_by_severity(Severity(min_severity))

        # If misconfig is the only scanner, use the original output path
        if len(scanner_list) == 1:
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
            return

        combined["misconfig"] = report.to_dict()
        if report.threats:
            has_issues = True
        click.echo(
            f"[misconfig] Scanned {report.scanned_resources} resources, "
            f"found {len(report.threats)} threats.",
            err=True,
        )

    # ── Secret scanner ───────────────────────────────────────────────
    if "secret" in scanner_list:
        from threatcode.engine.secrets.scanner import SecretScanner

        secret_scanner = SecretScanner()
        secret_findings = secret_scanner.scan(input_file)
        combined["secret"] = {
            "total_secrets": len(secret_findings),
            "findings": [f.to_dict() for f in secret_findings],
        }
        if secret_findings:
            has_issues = True
        click.echo(f"[secret] Found {len(secret_findings)} secrets.", err=True)

    # ── Vulnerability scanner ────────────────────────────────────────
    if "vuln" in scanner_list:
        from threatcode.engine.vulns.db import VulnDB
        from threatcode.engine.vulns.scanner import VulnerabilityScanner

        try:
            parsed_vuln = detect_and_parse(input_file)
            deps = [
                r.properties
                for r in parsed_vuln.resources
                if r.resource_type.startswith("dependency_")
            ]
        except Exception:
            deps = []

        if not deps:
            combined["vuln"] = {
                "total_vulnerabilities": 0,
                "dependencies_scanned": 0,
                "findings": [],
            }
            click.echo("[vuln] No dependencies found.", err=True)
        else:
            db = VulnDB()
            if not db.exists():
                click.echo(
                    "[vuln] Database not found. Run 'threatcode db update' first.",
                    err=True,
                )
                combined["vuln"] = {"error": "Database not found"}
            else:
                vuln_scanner = VulnerabilityScanner(db=db)
                vuln_findings = vuln_scanner.scan_dependencies(deps, ignore_unfixed=ignore_unfixed)
                combined["vuln"] = {
                    "total_vulnerabilities": len(vuln_findings),
                    "dependencies_scanned": len(deps),
                    "findings": [f.to_dict() for f in vuln_findings],
                }
                if vuln_findings:
                    has_issues = True
                click.echo(
                    f"[vuln] Scanned {len(deps)} deps, found {len(vuln_findings)} vulnerabilities.",
                    err=True,
                )

    # ── License scanner ──────────────────────────────────────────────
    if "license" in scanner_list:
        from threatcode.engine.licenses.scanner import LicenseScanner

        try:
            parsed_lic = detect_and_parse(input_file)
            lic_deps = [
                r.properties
                for r in parsed_lic.resources
                if r.resource_type.startswith("dependency_")
            ]
        except Exception:
            lic_deps = []

        if not lic_deps:
            combined["license"] = {
                "total_issues": 0,
                "dependencies_scanned": 0,
                "findings": [],
            }
            click.echo("[license] No dependencies found.", err=True)
        else:
            lic_scanner = LicenseScanner()
            lic_findings = lic_scanner.scan_dependencies(lic_deps)
            combined["license"] = {
                "total_issues": len(lic_findings),
                "dependencies_scanned": len(lic_deps),
                "findings": [f.to_dict() for f in lic_findings],
            }
            if lic_findings:
                has_issues = True
            click.echo(
                f"[license] Scanned {len(lic_deps)} deps, "
                f"found {len(lic_findings)} license issues.",
                err=True,
            )

    # ── Multi-scanner output ─────────────────────────────────────────
    output = json_mod.dumps(combined, indent=2)
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

    if has_issues:
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
        click.echo(f"Error computing diff: {type(e).__name__}: {e}", err=True)
        sys.exit(1)
    click.echo(output)


@cli.command()
@click.argument("path", type=click.Path(exists=True))
@click.option(
    "--format",
    "-f",
    "output_format",
    default="json",
    type=click.Choice(["json", "sarif", "markdown"]),
    help="Output format.",
)
@click.option(
    "--output",
    "-o",
    "output_path",
    type=click.Path(),
    default=None,
    help="Write output to file.",
)
def secret(path: str, output_format: str, output_path: str | None) -> None:
    """Scan files for hardcoded secrets."""
    import json

    from threatcode.engine.secrets.scanner import SecretScanner

    scanner = SecretScanner()
    findings = scanner.scan(path)

    if output_format == "json":
        output = json.dumps(
            {
                "total_secrets": len(findings),
                "findings": [f.to_dict() for f in findings],
            },
            indent=2,
        )
    else:
        output = json.dumps(
            {"total_secrets": len(findings), "findings": [f.to_dict() for f in findings]},
            indent=2,
        )

    if output_path:
        out = Path(output_path)
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(output, encoding="utf-8")
        click.echo(f"Output written to {out.name}")
    else:
        click.echo(output)

    click.echo(f"\nFound {len(findings)} secrets.", err=True)
    if findings:
        sys.exit(1)


@cli.command()
@click.argument("path", type=click.Path(exists=True))
@click.option(
    "--format",
    "-f",
    "output_format",
    default="json",
    type=click.Choice(["json", "sarif", "markdown"]),
    help="Output format.",
)
@click.option("--output", "-o", "output_path", type=click.Path(), default=None)
@click.option("--ignore-unfixed", is_flag=True, default=False, help="Skip unfixed vulnerabilities.")
def vuln(path: str, output_format: str, output_path: str | None, ignore_unfixed: bool) -> None:
    """Scan dependencies for known vulnerabilities."""
    import json as json_mod

    from threatcode.engine.vulns.db import VulnDB
    from threatcode.engine.vulns.scanner import VulnerabilityScanner
    from threatcode.parsers import detect_and_parse

    try:
        parsed = detect_and_parse(path)
    except Exception as e:
        click.echo(f"Error parsing input: {type(e).__name__}: {e}", err=True)
        sys.exit(1)

    # Extract dependencies from parsed resources
    deps = [r.properties for r in parsed.resources if r.resource_type.startswith("dependency_")]

    if not deps:
        click.echo("No dependencies found in the input file.", err=True)
        sys.exit(0)

    db = VulnDB()
    if not db.exists():
        click.echo(
            "Vulnerability database not found. Run 'threatcode db update' first.",
            err=True,
        )
        sys.exit(1)

    scanner = VulnerabilityScanner(db=db)
    findings = scanner.scan_dependencies(deps, ignore_unfixed=ignore_unfixed)

    output = json_mod.dumps(
        {
            "total_vulnerabilities": len(findings),
            "dependencies_scanned": len(deps),
            "findings": [f.to_dict() for f in findings],
        },
        indent=2,
    )

    if output_path:
        out = Path(output_path)
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(output, encoding="utf-8")
        click.echo(f"Output written to {out.name}")
    else:
        click.echo(output)

    click.echo(
        f"\nScanned {len(deps)} dependencies, found {len(findings)} vulnerabilities.",
        err=True,
    )
    if findings:
        sys.exit(1)


@cli.command()
@click.argument("path", type=click.Path(exists=True))
@click.option(
    "--format",
    "-f",
    "output_format",
    default="cyclonedx",
    type=click.Choice(["cyclonedx"]),
    help="SBOM format.",
)
@click.option("--output", "-o", "output_path", type=click.Path(), default=None)
def sbom(path: str, output_format: str, output_path: str | None) -> None:
    """Generate a Software Bill of Materials (SBOM)."""
    from threatcode.formatters.cyclonedx import format_cyclonedx
    from threatcode.parsers import detect_and_parse

    try:
        parsed = detect_and_parse(path)
    except Exception as e:
        click.echo(f"Error parsing input: {type(e).__name__}: {e}", err=True)
        sys.exit(1)

    deps = [r.properties for r in parsed.resources if r.resource_type.startswith("dependency_")]

    if not deps:
        click.echo("No dependencies found in the input file.", err=True)
        sys.exit(0)

    output = format_cyclonedx(deps, source_path=path)

    if output_path:
        out = Path(output_path)
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(output, encoding="utf-8")
        click.echo(f"SBOM written to {out.name}")
    else:
        click.echo(output)

    click.echo(f"\nGenerated SBOM with {len(deps)} components.", err=True)


@cli.command(name="license")
@click.argument("path", type=click.Path(exists=True))
@click.option(
    "--format",
    "-f",
    "output_format",
    default="json",
    type=click.Choice(["json"]),
    help="Output format.",
)
@click.option("--output", "-o", "output_path", type=click.Path(), default=None)
def license_cmd(path: str, output_format: str, output_path: str | None) -> None:
    """Scan dependencies for license compliance issues."""
    import json as json_mod

    from threatcode.engine.licenses.scanner import LicenseScanner
    from threatcode.parsers import detect_and_parse

    try:
        parsed = detect_and_parse(path)
    except Exception as e:
        click.echo(f"Error parsing input: {type(e).__name__}: {e}", err=True)
        sys.exit(1)

    deps = [r.properties for r in parsed.resources if r.resource_type.startswith("dependency_")]

    if not deps:
        click.echo("No dependencies found in the input file.", err=True)
        sys.exit(0)

    scanner = LicenseScanner()
    findings = scanner.scan_dependencies(deps)

    output = json_mod.dumps(
        {
            "total_issues": len(findings),
            "dependencies_scanned": len(deps),
            "findings": [f.to_dict() for f in findings],
        },
        indent=2,
    )

    if output_path:
        out = Path(output_path)
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(output, encoding="utf-8")
        click.echo(f"Output written to {out.name}")
    else:
        click.echo(output)

    click.echo(
        f"\nScanned {len(deps)} dependencies, found {len(findings)} license issues.",
        err=True,
    )
    if findings:
        sys.exit(1)


@cli.group()
def db() -> None:
    """Manage the vulnerability database."""


@db.command("status")
def db_status() -> None:
    """Show vulnerability database status."""
    from threatcode.engine.vulns.db import VulnDB

    info = VulnDB().status()
    if not info["exists"]:
        click.echo("Vulnerability database not found.")
        click.echo(f"Expected location: {info['path']}")
        click.echo("Run 'threatcode db update' to download it.")
        return

    click.echo(f"Database: {info['path']}")
    click.echo(f"Size: {info['size_mb']} MB")
    click.echo(f"Entries: {info['entry_count']}")
    click.echo(f"Last updated: {info['last_updated']}")


@db.command("update")
def db_update() -> None:
    """Download/refresh the vulnerability database from OSV."""
    import io
    import json as json_mod
    import urllib.request
    import zipfile

    from threatcode.engine.vulns.db import VulnDB

    db_instance = VulnDB()
    db_instance.init_db()

    ecosystems = {
        "npm": "npm",
        "PyPI": "pypi",
        "Go": "go",
        "crates.io": "crates.io",
        "RubyGems": "rubygems",
        "Packagist": "packagist",
    }

    total = 0
    for osv_eco, tc_eco in ecosystems.items():
        url = f"https://osv-vulnerabilities.storage.googleapis.com/{osv_eco}/all.zip"
        click.echo(f"Downloading {osv_eco} vulnerabilities...")

        try:
            with urllib.request.urlopen(url, timeout=120) as resp:
                zip_data = io.BytesIO(resp.read())

            records: list[dict[str, Any]] = []
            with zipfile.ZipFile(zip_data) as zf:
                for name in zf.namelist():
                    if not name.endswith(".json"):
                        continue
                    try:
                        entry = json_mod.loads(zf.read(name))
                    except (json_mod.JSONDecodeError, KeyError):
                        continue

                    vuln_id = entry.get("id", "")
                    summary = entry.get("summary", "")[:500]
                    aliases = entry.get("aliases", [])
                    severity = "medium"
                    cvss_score = 0.0

                    # Extract CVSS from severity field
                    for sev in entry.get("severity", []):
                        if isinstance(sev, dict) and sev.get("type") == "CVSS_V3":
                            score_str = sev.get("score", "")
                            try:
                                cvss_score = float(score_str)
                            except (ValueError, TypeError):
                                pass
                            if cvss_score >= 9.0:
                                severity = "critical"
                            elif cvss_score >= 7.0:
                                severity = "high"
                            elif cvss_score >= 4.0:
                                severity = "medium"
                            else:
                                severity = "low"

                    for affected in entry.get("affected", []):
                        pkg = affected.get("package", {})
                        pkg_name = pkg.get("name", "")
                        if not pkg_name:
                            continue

                        for rng in affected.get("ranges", []):
                            if rng.get("type") != "SEMVER" and rng.get("type") != "ECOSYSTEM":
                                continue
                            introduced = ""
                            fixed = ""
                            for evt in rng.get("events", []):
                                if "introduced" in evt:
                                    introduced = evt["introduced"]
                                if "fixed" in evt:
                                    fixed = evt["fixed"]

                            if introduced == "0":
                                introduced = ""

                            records.append(
                                {
                                    "id": vuln_id,
                                    "ecosystem": tc_eco,
                                    "package": pkg_name,
                                    "version_introduced": introduced,
                                    "version_fixed": fixed,
                                    "severity": severity,
                                    "cvss_score": cvss_score,
                                    "summary": summary,
                                    "aliases": aliases,
                                }
                            )

            count = db_instance.bulk_insert(records)
            total += count
            click.echo(f"  {osv_eco}: {count} entries")

        except Exception as e:
            click.echo(f"  {osv_eco}: Failed - {e}", err=True)

    click.echo(f"\nTotal: {total} vulnerability entries loaded.")
    info = db_instance.status()
    click.echo(f"Database size: {info['size_mb']} MB")


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
