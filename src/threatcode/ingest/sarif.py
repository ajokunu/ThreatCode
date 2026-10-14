"""SARIF 2.1.0 results from any tool (Checkov, Gitleaks, Trivy, Semgrep, CodeQL and others).

Detected by a ``runs`` list whose runs each carry ``tool.driver``, in a document whose ``version``
starts with ``2.1`` or whose ``$schema`` names SARIF.
Each run becomes its own report, named after ``tool.driver.name`` lowercased, with its
``semanticVersion`` or ``version``.

Severity
--------
In order: the result's ``properties.security-severity``, the rule's ``properties.security-severity``
(a 0-10 score, banded at 9.0, 7.0 and 4.0), then the level of the result, of the rule's
``defaultConfiguration``, or ``warning``: ``error`` is high, ``warning`` medium, ``note`` low and
``none`` info.

Kind
----
A rule id that is a CVE, GHSA or similar advisory id marks a vulnerability.
Otherwise the tool decides: secret scanners (Gitleaks, TruffleHog, detect-secrets, GGShield and
others) report secrets, infrastructure scanners (Checkov, Trivy, tfsec, KICS, Terrascan and others)
report misconfigurations, and the rule's tags settle the rest.
Anything else is ``other`` and is kept.

Location
--------
The first location of a result is its file and line: ``artifactLocation.uri`` with ``file://``
removed and percent-escapes decoded, and ``region.startLine`` and ``endLine``.
A result of Trivy's SARIF output for a package vulnerability also names its package, installed and
fixed version in the message text, which is read back.
Results the tool marked suppressed, and results of kind ``pass`` or ``notApplicable``, are counted
in ``skipped``.
"""

from __future__ import annotations

import re
from typing import Any
from urllib.parse import unquote

from threatcode.ingest.model import (
    ExternalFinding,
    Kind,
    PackageInfo,
    ScannerReport,
    clean_text,
    severity_from_level,
    severity_from_score,
    to_float,
)

_ADVISORY_ID = re.compile(
    r"^(CVE-\d{4}-\d{4,}|GHSA-[0-9a-z]{4}-[0-9a-z]{4}-[0-9a-z]{4}|OSV-\d{4}-\d+|"
    r"PYSEC-\d{4}-\d+|RUSTSEC-\d{4}-\d+|GO-\d{4}-\d+|GMS-\d{4}-\d+|NSWG-ECO-\d+|"
    r"SNYK-[A-Z0-9-]+|DSA-\d+-\d+|USN-\d+-\d+|RHSA-\d{4}:\d+|ALAS\d*-\d{4}-\d+)$",
    re.IGNORECASE,
)
_SECRET_TOOLS = frozenset(
    {
        "gitleaks",
        "trufflehog",
        "detect-secrets",
        "ggshield",
        "git-secrets",
        "secretlint",
        "whispers",
        "noseyparker",
        "kingfisher",
    }
)
_IAC_TOOLS = frozenset(
    {
        "checkov",
        "tfsec",
        "kics",
        "terrascan",
        "snyk-iac",
        "conftest",
        "kube-linter",
        "kubescape",
        "hadolint",
        "dockle",
        "cfn-lint",
        "cfn-nag",
        "regula",
        "cloudformation-guard",
        "terraform-compliance",
        "datree",
        "polaris",
    }
)
_IAC_RULE_PREFIXES = ("CKV", "AVD-", "KSV", "DS0", "AWS-", "KICS", "TF-", "AZU-", "GCP-")
_SKIPPED_KINDS = frozenset({"pass", "notapplicable"})
_DESCRIPTION_LIMIT = 700
_MESSAGE_FIELD = re.compile(
    r"^\s*(Package|Installed Version|Fixed Version|Link)\s*:\s*(.+?)\s*$", re.MULTILINE
)
_MARKDOWN_LINK = re.compile(r"\]\(([^)\s]+)\)")


def detect(data: object) -> bool:
    if not isinstance(data, dict) or not isinstance(data.get("runs"), list):
        return False
    version = data.get("version")
    schema = data.get("$schema")
    sarif_marked = (isinstance(version, str) and version.startswith("2.1")) or (
        isinstance(schema, str) and "sarif" in schema.lower()
    )
    if not sarif_marked:
        return False
    return all(
        isinstance(run, dict)
        and isinstance(run.get("tool"), dict)
        and isinstance(run["tool"].get("driver"), dict)
        for run in data["runs"]
    )


def load(data: dict[str, Any]) -> list[ScannerReport]:
    return [_load_run(run) for run in data["runs"]]


def tool_slug(name: str) -> str:
    """A tool's name as it appears in rule ids: lowercase, words joined with hyphens."""
    return re.sub(r"[^a-z0-9]+", "-", name.lower()).strip("-") or "sarif"


def _load_run(run: dict[str, Any]) -> ScannerReport:
    driver: dict[str, Any] = run["tool"]["driver"]
    name = clean_text(driver.get("name")) or "sarif"
    version = clean_text(driver.get("semanticVersion")) or clean_text(driver.get("version"))
    report = ScannerReport(tool=tool_slug(name), version=version)
    rules = [r for r in driver.get("rules") or [] if isinstance(r, dict)]
    by_id = {clean_text(r.get("id")): r for r in rules if r.get("id")}
    for result in run.get("results") or []:
        if not isinstance(result, dict):
            continue
        if clean_text(result.get("kind")).lower() in _SKIPPED_KINDS:
            report.skip("passed_checks")
            continue
        if _suppressed(result):
            report.skip("suppressed")
            continue
        rule = _rule_of(result, rules, by_id)
        report.findings.append(_finding(report.tool, result, rule))
    return report


def _suppressed(result: dict[str, Any]) -> bool:
    for entry in result.get("suppressions") or []:
        if isinstance(entry, dict) and clean_text(entry.get("status")).lower() in (
            "",
            "accepted",
        ):
            return True
    return False


def _rule_of(
    result: dict[str, Any], rules: list[dict[str, Any]], by_id: dict[str, dict[str, Any]]
) -> dict[str, Any]:
    index = result.get("ruleIndex")
    if isinstance(index, int) and not isinstance(index, bool) and 0 <= index < len(rules):
        return rules[index]
    return by_id.get(_rule_id(result), {})


def _rule_id(result: dict[str, Any]) -> str:
    rule_id = clean_text(result.get("ruleId"))
    if rule_id:
        return rule_id
    nested = result.get("rule")
    return clean_text(nested.get("id")) if isinstance(nested, dict) else ""


def _text(node: object) -> str:
    """The ``text`` of a SARIF message-like object."""
    if isinstance(node, dict):
        return clean_text(node.get("text"))
    return ""


def _score(result: dict[str, Any], rule: dict[str, Any]) -> float | None:
    for holder in (result, rule):
        props = holder.get("properties")
        if isinstance(props, dict):
            score = to_float(props.get("security-severity"))
            if score is not None:
                return score
    return None


def _level(result: dict[str, Any], rule: dict[str, Any]) -> object:
    if result.get("level"):
        return result["level"]
    default = rule.get("defaultConfiguration")
    if isinstance(default, dict) and default.get("level"):
        return default["level"]
    return "warning"


def _tags(rule: dict[str, Any]) -> set[str]:
    props = rule.get("properties")
    tags = props.get("tags") if isinstance(props, dict) else None
    return {t.lower() for t in tags if isinstance(t, str)} if isinstance(tags, list) else set()


def _kind(tool: str, rule_id: str, tags: set[str]) -> Kind:
    if _ADVISORY_ID.match(rule_id):
        return "vulnerability"
    if tool in _SECRET_TOOLS or "secret" in tags or "secrets" in tags:
        return "secret"
    if "vulnerability" in tags:
        return "vulnerability"
    if (
        tool in _IAC_TOOLS
        or "misconfiguration" in tags
        or "infrastructure-as-code" in tags
        or rule_id.upper().startswith(_IAC_RULE_PREFIXES)
    ):
        return "misconfiguration"
    return "other"


def _location(result: dict[str, Any]) -> tuple[str, int | None, int | None]:
    for location in result.get("locations") or []:
        if not isinstance(location, dict):
            continue
        physical = location.get("physicalLocation")
        if not isinstance(physical, dict):
            continue
        artifact = physical.get("artifactLocation")
        uri = clean_text(artifact.get("uri")) if isinstance(artifact, dict) else ""
        if not uri:
            continue
        region = physical.get("region")
        start = end = None
        if isinstance(region, dict):
            start = _line(region.get("startLine"))
            end = _line(region.get("endLine"))
        return _uri_to_path(uri), start, end
    return "", None, None


def _line(value: object) -> int | None:
    number = to_float(value)
    return int(number) if number is not None and number >= 1 else None


def _uri_to_path(uri: str) -> str:
    text = uri
    if text.lower().startswith("file://"):
        text = text[7:]
        # file:///C:/x and file://host/x: drop an empty or Windows-drive authority slash
        if re.match(r"^/[A-Za-z]:/", text):
            text = text[1:]
    return unquote(text).replace("\\", "/")


def _finding(tool: str, result: dict[str, Any], rule: dict[str, Any]) -> ExternalFinding:
    rule_id = _rule_id(result) or clean_text(rule.get("id")) or "unknown"
    message = _text(result.get("message"))
    short = _text(rule.get("shortDescription"))
    full = _text(rule.get("fullDescription"))
    first_line = message.splitlines()[0] if message else ""
    title = short or clean_text(rule.get("name")) or first_line
    kind = _kind(tool, rule_id, _tags(rule))
    score = _score(result, rule)
    severity = (
        severity_from_score(score)
        if score is not None
        else severity_from_level(_level(result, rule))
    )
    file, start, end = _location(result)
    fields = {m.group(1): m.group(2) for m in _MESSAGE_FIELD.finditer(message)}
    package = None
    if kind == "vulnerability" and fields.get("Package"):
        package = PackageInfo(name=fields["Package"], version=fields.get("Installed Version", ""))
    help_node = rule.get("help")
    link = _MARKDOWN_LINK.search(fields.get("Link", ""))
    references = [link.group(1) if link else fields["Link"]] if fields.get("Link") else []
    helper = rule.get("helpUri")
    if isinstance(helper, str) and helper:
        references.append(clean_text(helper))
    return ExternalFinding(
        tool=tool,
        kind=kind,
        id=rule_id,
        severity=severity,
        title=clean_text(title, 300),
        description=clean_text(message or full, _DESCRIPTION_LIMIT),
        cvss_score=score if kind == "vulnerability" else None,
        package=package,
        fixed_version=fields.get("Fixed Version", ""),
        target=file,
        file=file,
        line=start,
        end_line=end,
        mitigation=clean_text(_text(help_node), _DESCRIPTION_LIMIT),
        references=references,
    )
