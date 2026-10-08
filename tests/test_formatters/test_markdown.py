"""Tests for threatcode.formatters.markdown: structure, safety, grouping and the size cap."""

from __future__ import annotations

import re
from typing import Any

import pytest

from threatcode.formatters.markdown import MARKER, MAX_CHARS, format_markdown
from threatcode.models.attack_path import AttackHop, AttackPath
from threatcode.models.report import Coverage, ThreatReport
from threatcode.models.threat import Severity, Threat, ThreatSource

ZWJ = "‍"


def make_threat(index: int = 0, severity: Severity = Severity.MEDIUM, **fields: Any) -> Threat:
    return Threat(
        id=fields.pop("threat_id", f"t{index}"),
        title=fields.pop("title", f"Threat {index}"),
        description=fields.pop("description", f"Description {index}"),
        stride_category=fields.pop("stride", "tampering"),
        severity=severity,
        source=fields.pop("source", ThreatSource.RULE),
        resource_type="aws_s3_bucket",
        resource_address=fields.pop("address", f"aws_s3_bucket.test{index}"),
        mitigation=fields.pop("mitigation", f"Fix {index}"),
        **fields,
    )


def make_report(*severities: Severity, **fields: Any) -> ThreatReport:
    report = ThreatReport(scanned_resources=5, **fields)
    for i, sev in enumerate(severities):
        report.add(make_threat(i, sev))
    return report


def headings(text: str) -> list[str]:
    return [line for line in text.splitlines() if line.startswith("#")]


class TestStructure:
    def test_title_then_the_hidden_marker(self) -> None:
        lines = format_markdown(make_report(Severity.HIGH)).splitlines()
        assert lines[0] == "# ThreatCode Threat Model Report"
        assert lines[1] == MARKER == "<!-- threatcode-report -->"
        assert format_markdown(make_report()).count(MARKER) == 1

    def test_the_verdict_line_comes_first_and_uses_effective_severity(self) -> None:
        report = make_report(Severity.HIGH, Severity.HIGH, Severity.LOW)
        report.threats[2].effective_severity = Severity.CRITICAL
        text = format_markdown(report)
        assert "- **Verdict:** 1 critical, 2 high" in text
        assert text.index("**Verdict:**") < text.index("## Summary")

    def test_summary_table(self) -> None:
        text = format_markdown(make_report(Severity.HIGH, Severity.HIGH, Severity.LOW))
        assert "| Severity | Count |" in text
        assert "| [HIGH] | 2 |" in text
        assert "| [LOW] | 1 |" in text
        assert "[CRITICAL]" not in text.split("## Top risks")[0].split("## Summary")[1]

    def test_the_resource_count_and_totals_are_listed(self) -> None:
        text = format_markdown(make_report(Severity.HIGH, Severity.LOW))
        assert "- **Scanned resources:** 5" in text
        assert "- **Total threats:** 2" in text

    def test_the_timestamp_appears_only_when_the_report_has_one(self) -> None:
        stamped = format_markdown(make_report(Severity.LOW, timestamp="2026-01-01T00:00:00+00:00"))
        assert "**Timestamp:** 2026-01-01T00:00:00+00:00" in stamped
        assert "Timestamp" not in format_markdown(make_report(Severity.LOW, timestamp=""))

    def test_two_renders_are_byte_identical(self) -> None:
        report = make_report(Severity.HIGH, Severity.LOW, Severity.CRITICAL, timestamp="")
        assert format_markdown(report) == format_markdown(report)

    def test_empty_report(self) -> None:
        text = format_markdown(ThreatReport(scanned_resources=0))
        assert "No threats detected." in text
        assert "- **Verdict:** no findings" in text
        assert "## Summary" not in text

    def test_mitigation_blockquote(self) -> None:
        assert "> **Mitigation:** Fix 0" in format_markdown(make_report(Severity.HIGH))

    def test_the_resource_is_in_the_heading_so_repeated_titles_differ(self) -> None:
        report = ThreatReport()
        for i in range(2):
            report.add(make_threat(i, Severity.HIGH, title="Same title", address=f"res.n{i}"))
        text = format_markdown(report)
        assert "### [HIGH] Same title - `res.n0`" in text
        assert "### [HIGH] Same title - `res.n1`" in text

    def test_the_location_is_shown_when_known(self) -> None:
        report = ThreatReport()
        report.add(make_threat(1, location_file="infra/main.tf", location_start_line=12))
        assert "**Location:** `infra/main.tf:12`" in format_markdown(report)

    def test_a_base_severity_that_context_changed_is_explained(self) -> None:
        report = ThreatReport()
        report.add(
            make_threat(
                1,
                Severity.MEDIUM,
                effective_severity=Severity.HIGH,
                severity_reason="internet reachable",
            )
        )
        text = format_markdown(report)
        assert "**Severity:** High (base medium, internet reachable)" in text
        assert "### [HIGH]" in text

    def test_the_severity_explanation_is_one_sentence_with_one_colon_at_most(self) -> None:
        report = ThreatReport()
        report.add(
            make_threat(
                1,
                Severity.LOW,
                effective_severity=Severity.MEDIUM,
                severity_reason=(
                    "raised one level: the data store is tagged dataclassification=confidential"
                ),
            )
        )
        report.add(
            make_threat(
                2,
                Severity.HIGH,
                effective_severity=Severity.MEDIUM,
                severity_reason="lowered one level: marked intentional: tagged public-site",
            )
        )
        text = format_markdown(report)
        assert (
            "**Severity:** Medium (base low, raised one level because the data store is tagged "
            "dataclassification=confidential)" in text
        )
        assert (
            "**Severity:** Medium (base high, lowered one level because marked intentional "
            "(tagged public-site))" in text
        )
        for line in text.splitlines():
            if line.startswith("**Severity:**"):
                severity = line.split(" | ")[0]
                assert severity.count(":") == 1, severity

    def test_a_long_reason_is_not_cut_in_the_middle_of_a_route(self) -> None:
        route = " -> ".join(f"aws_resource.node{i}" for i in range(12))
        report = ThreatReport()
        report.add(
            make_threat(
                1,
                Severity.LOW,
                effective_severity=Severity.MEDIUM,
                severity_reason=f"raised one level: n is reachable from the internet ({route})",
            )
        )
        severity_line = next(
            line for line in format_markdown(report).splitlines() if "**Severity:**" in line
        )
        assert route in severity_line.replace("\\", "")
        assert "..." not in severity_line

    def test_llm_findings_are_marked_advisory(self) -> None:
        report = ThreatReport()
        report.add(make_threat(1, source=ThreatSource.LLM))
        assert "**Source:** llm (advisory)" in format_markdown(report)


class TestLocationFallback:
    def test_a_finding_without_a_location_takes_its_nodes(self) -> None:
        from threatcode.ir.graph import InfraGraph
        from threatcode.parsers.base import ParsedOutput, ParsedResource

        graph = InfraGraph.from_parsed(
            ParsedOutput(
                source_path="net/main.tf",
                format_type="terraform_hcl",
                resources=[
                    ParsedResource(
                        resource_type="aws_s3_bucket",
                        name="x",
                        provider="aws",
                        address="aws_s3_bucket.x",
                        source_location="net/main.tf",
                        start_line=12,
                    )
                ],
            )
        )
        report = ThreatReport()
        report.add(make_threat(1, address="aws_s3_bucket.x"))
        assert "**Location:** `net/main.tf:12`" in format_markdown(report, graph)
        assert "**Location:**" not in format_markdown(report)


class TestStrideOrderAndLabels:
    def test_sections_follow_the_stride_order_with_readable_labels(self) -> None:
        report = ThreatReport()
        for i, category in enumerate(
            [
                "elevation_of_privilege",
                "denial_of_service",
                "information_disclosure",
                "repudiation",
                "tampering",
                "spoofing",
            ]
        ):
            report.add(make_threat(i, Severity.LOW, stride=category))
        sections = [h for h in headings(format_markdown(report)) if h.startswith("## ")]
        names = [h[3:] for h in sections]
        stride = names[names.index("Spoofing") : names.index("Spoofing") + 6]
        assert stride == [
            "Spoofing",
            "Tampering",
            "Repudiation",
            "Information Disclosure",
            "Denial of Service",
            "Elevation of Privilege",
        ]

    def test_a_section_is_only_written_for_categories_with_findings(self) -> None:
        text = format_markdown(make_report(Severity.MEDIUM))
        assert "## Tampering" in text
        assert "## Spoofing" not in text

    def test_within_a_section_the_most_severe_comes_first(self) -> None:
        report = ThreatReport()
        report.add(make_threat(1, Severity.LOW, title="Low one"))
        report.add(make_threat(2, Severity.CRITICAL, title="Critical one"))
        text = format_markdown(report).split("## Tampering")[1]
        assert text.index("Critical one") < text.index("Low one")


class TestTopRisks:
    def test_criticals_lead_whatever_their_category(self) -> None:
        report = ThreatReport()
        report.add(make_threat(1, Severity.LOW, stride="spoofing", title="Spoof low"))
        report.add(
            make_threat(2, Severity.CRITICAL, stride="elevation_of_privilege", title="EoP crit")
        )
        report.add(make_threat(3, Severity.HIGH, stride="tampering", title="Tamper high"))
        table = format_markdown(report).split("## Top risks")[1].split("\n\n## ")[0]
        rows = [line for line in table.splitlines() if line.startswith("| ") and "---" not in line]
        titles = [row.split("|")[3].strip() for row in rows[1:]]
        assert titles == ["EoP crit", "Tamper high", "Spoof low"]

    def test_the_table_is_capped_at_ten_rows(self) -> None:
        text = format_markdown(make_report(*[Severity.MEDIUM] * 25))
        table = text.split("## Top risks (10)")[1].split("\n\n## ")[0]
        assert len([ln for ln in table.splitlines() if re.match(r"\| \d+ \|", ln)]) == 10

    def test_technique_ids_link_to_attack_mitre_org(self) -> None:
        report = ThreatReport()
        report.add(make_threat(1, mitre_techniques=["T1530", "T1552.005", "T9999"]))
        text = format_markdown(report)
        assert "[T1530](https://attack.mitre.org/techniques/T1530/)" in text
        assert "[T1552.005](https://attack.mitre.org/techniques/T1552/005/)" in text
        assert "[T9999]" not in text and "T9999" in text


class TestNoEmoji:
    def test_severities_are_text_labels(self) -> None:
        text = format_markdown(
            make_report(
                Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO
            )
        )
        for label in ("[CRITICAL]", "[HIGH]", "[MEDIUM]", "[LOW]", "[INFO]"):
            assert label in text
        assert not re.search(r":[a-z_]+_(circle|square):", text)
        assert ":red_circle:" not in text

    def test_the_output_is_ascii_when_the_input_is(self) -> None:
        text = format_markdown(make_report(Severity.CRITICAL, Severity.LOW))
        assert text.isascii()


class TestEscaping:
    HOSTILE = (
        "\n\n# Fake heading\n- injected list\n| a | b |\nCC @octocat and @org/security-team"
        "\n\n---\n1. numbered\n> quote\n```\ncode\n```"
    )

    def report(self) -> ThreatReport:
        report = ThreatReport()
        report.add(
            make_threat(
                1,
                Severity.HIGH,
                title="Title | with * and _ and & and ~ and <b>html</b>",
                description=self.HOSTILE,
                mitigation="Step one\n\n## Another heading\n\n- list [x](http://evil.example)",
                address='module.net.aws_instance.web["a"][0]',
            )
        )
        return report

    def test_hostile_text_stays_inline(self) -> None:
        text = format_markdown(self.report())
        assert headings(text) == [
            "# ThreatCode Threat Model Report",
            "## Summary",
            "## Top risks (1)",
            "## Tampering",
            "### [HIGH] Title \\| with \\* and \\_ and \\& and \\~ and \\<b>html\\</b> - "
            '`module.net.aws_instance.web["a"][0]`',
            "## Coverage",
        ]
        body = [line for line in text.splitlines() if "Fake heading" in line]
        assert len(body) == 1 and not body[0].startswith("#")
        assert not any(
            line.startswith(("- injected", "| a |", "---", "> quote")) for line in text.splitlines()
        )

    def test_mentions_are_defused(self) -> None:
        text = format_markdown(self.report())
        assert f"@{ZWJ}octocat" in text
        assert f"@{ZWJ}org/security-team" in text
        assert "@octocat" not in text and "@org" not in text

    def test_the_mitigation_cannot_leave_its_blockquote(self) -> None:
        lines = format_markdown(self.report()).splitlines()
        quoted = [line for line in lines if line.startswith("> ")]
        assert len(quoted) == 1
        assert "Another heading" in quoted[0]
        assert quoted[0].count("\\[x\\]") == 1
        assert "[x](" not in quoted[0]

    def test_html_and_links_are_neutralised(self) -> None:
        text = format_markdown(self.report())
        assert "<b>" not in text.replace("\\<b>", "")
        assert "](http://evil" not in text

    def test_the_address_renders_literally_in_a_code_span(self) -> None:
        text = format_markdown(self.report())
        assert '`module.net.aws_instance.web["a"][0]`' in text
        assert 'web\\["a"\\]' not in text

    def test_an_address_with_backticks_gets_a_longer_fence(self) -> None:
        report = ThreatReport()
        report.add(make_threat(1, address="res.a`b``c"))
        text = format_markdown(report)
        assert "```res.a`b``c```" in text

    def test_an_address_in_the_top_risks_table_cannot_add_a_cell(self) -> None:
        report = ThreatReport()
        report.add(make_threat(1, address="res.a|b"))
        text = format_markdown(report)
        row = next(line for line in text.splitlines() if line.startswith("| 1 |"))
        assert "`res.a\\|b`" in row
        assert row.count("|") - row.count("\\|") == 6

    def test_arrows_and_parentheses_stay_readable(self) -> None:
        report = ThreatReport()
        report.add(
            make_threat(1, title="internet -> private (cpu, memory)", description="dmz -> data (x)")
        )
        text = format_markdown(report)
        assert "internet -> private (cpu, memory)" in text
        assert "dmz -> data (x)" in text
        assert "\\(" not in text and "-\\>" not in text

    def test_underscores_in_identifiers_are_not_escaped(self) -> None:
        report = ThreatReport()
        report.add(make_threat(1, description="aws_flow_log and http_tokens are missing"))
        assert "aws_flow_log and http_tokens" in format_markdown(report)

    def test_a_hostile_coverage_message_stays_inline(self) -> None:
        coverage = Coverage(
            errors=[{"file": "bad.tf", "code": "parse.failed", "message": "x\n# Heading\n- item"}],
            gaps=[{"level": "warning", "code": "g.c", "message": "y\n## Another", "file": "a.tf"}],
        )
        text = format_markdown(ThreatReport(coverage=coverage))
        assert not any(
            line.startswith(("# Heading", "## Another", "- item")) for line in text.splitlines()
        )

    def test_no_line_outside_the_formatters_own_structure_starts_with_a_block_marker(self) -> None:
        allowed = (
            "# ThreatCode",
            "<!--",
            "- ",
            "## ",
            "### [",
            "| ",
            "|--",
            "**",
            "> **Mitigation:** ",
            "```",
            "_",
            "  - ",
        )
        text = format_markdown(self.report())
        for line in text.splitlines():
            if not line.strip():
                continue
            assert line.startswith(allowed) or line[0].isalpha(), line
        hostile_start = re.compile(
            r"^(#+|[-*+>|]|\d+\.)\s*"
            r"(Fake heading|injected list|Another heading|numbered|quote|code)"
        )
        assert not [line for line in text.splitlines() if hostile_start.match(line)]


class TestRootCauseGrouping:
    def grouped_report(self) -> ThreatReport:
        report = ThreatReport()
        for i, (rule, sev) in enumerate(
            [
                ("NO_SECURITY_CONTEXT", Severity.MEDIUM),
                ("RUN_AS_ROOT", Severity.HIGH),
                ("WRITABLE_ROOT_FS", Severity.MEDIUM),
            ]
        ):
            report.add(
                make_threat(
                    i,
                    sev,
                    title=f"Container finding {rule}",
                    rule_id=rule,
                    address="kubernetes_deployment.web",
                    root_cause="container-hardening",
                    stride="elevation_of_privilege",
                )
            )
        report.add(
            make_threat(
                9,
                Severity.LOW,
                address="kubernetes_deployment.other",
                root_cause="container-hardening",
                stride="elevation_of_privilege",
            )
        )
        return report

    def test_findings_sharing_a_root_cause_on_one_resource_are_one_entry(self) -> None:
        text = format_markdown(self.grouped_report())
        grouped = [h for h in headings(text) if h.startswith("### ") and "ontainer hardening" in h]
        assert grouped == [
            "### [HIGH] Container hardening (3 findings) - `kubernetes_deployment.web`"
        ]
        bullets = [line for line in text.splitlines() if line.startswith("- [")]
        assert len(bullets) == 3
        assert bullets[0].startswith("- [HIGH] Container finding RUN_AS_ROOT (`RUN_AS_ROOT`)")
        assert "`NO_SECURITY_CONTEXT`" in "\n".join(bullets)

    def test_a_lone_finding_with_a_root_cause_is_not_grouped(self) -> None:
        text = format_markdown(self.grouped_report())
        assert "### [LOW] Threat 9 - `kubernetes_deployment.other`" in text

    def test_the_totals_show_both_counts(self) -> None:
        text = format_markdown(self.grouped_report())
        assert "- **Total threats:** 4 (2 entries after grouping by root cause)" in text


class TestAttackPaths:
    def path(self, address: str = "aws_db_instance.main") -> AttackPath:
        return AttackPath(
            id="0123456789ab",
            entry="internet",
            target=address,
            hops=[
                AttackHop(
                    node_id="internet",
                    zone="internet",
                    edge_type_to_next="network_flow",
                    via={"ports": [443]},
                ),
                AttackHop(
                    node_id="aws_lb.web",
                    zone="dmz",
                    edge_type_to_next="network_flow",
                    enabled_by=["t0", "gone"],
                    techniques=["T1190"],
                ),
                AttackHop(node_id=address, zone="data", techniques=["T1530"]),
            ],
            severity=Severity.CRITICAL,
            score=90.0,
            rationale="The database is reachable.",
            techniques=["T1190", "T1530"],
        )

    def report(self, address: str = "aws_db_instance.main") -> ThreatReport:
        report = make_report(Severity.HIGH)
        report.attack_paths.append(self.path(address))
        return report

    def test_the_attack_paths_section_comes_before_the_top_risks(self) -> None:
        text = format_markdown(self.report())
        assert text.index("## Attack paths") < text.index("## Top risks")
        assert "- **Verdict:** 1 high, 1 attack path from the internet to data" in text

    def test_each_hop_is_listed_with_its_zone_edge_and_enabling_finding(self) -> None:
        text = format_markdown(self.report())
        assert (
            "### 1. [CRITICAL] `internet` to `aws_db_instance.main` (2 hops)" in text.splitlines()
        )
        assert "1. `internet` (internet zone), then sends traffic on HTTPS 443" in text
        assert "2. `aws_lb.web` (dmz zone), then sends traffic to the next hop" in text
        assert "3. `aws_db_instance.main` (data zone)" in text
        assert "   - enabled by [HIGH] Threat 0 (`rule`)" in text
        assert "   - enabled by finding `gone`" in text
        assert "[T1190](https://attack.mitre.org/techniques/T1190/)" in text

    def test_a_mermaid_flowchart_follows_the_paths(self) -> None:
        text = format_markdown(self.report())
        block = text.split("```mermaid\n")[1].split("```")[0]
        assert block.startswith("flowchart TB")
        assert 'subgraph z1["internet"]' in block
        assert 'n1 ==>|"HTTPS 443"| n2' in block

    def test_a_hostile_address_cannot_break_out_of_the_diagram_or_the_text(self) -> None:
        hostile = 'a"]; click n1 call alert(1) <img src=x onerror=alert(1)> `x`'
        text = format_markdown(self.report(hostile))
        block = text.split("```mermaid\n")[1].split("```")[0]
        for line in block.splitlines():
            assert "click" not in line or line.strip().startswith(("n", "subgraph"))
        assert "<img" not in block and '"]' not in block.replace('"]\n', "\n")
        assert len([line for line in block.splitlines() if "click" in line]) <= 1
        outside_code = re.sub(r"(`+).+?\1", "", text)
        assert "<img" not in outside_code

    def test_no_paths_means_no_section_and_no_diagram(self) -> None:
        text = format_markdown(make_report(Severity.HIGH))
        assert "## Attack paths" not in text and "mermaid" not in text

    def test_only_ten_paths_are_listed_and_the_rest_counted(self) -> None:
        report = make_report(Severity.HIGH)
        for i in range(13):
            path = self.path(f"db{i}")
            path.id = f"{i:012d}"
            report.attack_paths.append(path)
        text = format_markdown(report)
        assert len([h for h in headings(text) if re.match(r"### \d+\. ", h)]) == 10
        assert "3 more attack paths are in the JSON report." in text


class TestCoverage:
    def test_a_clean_scan_says_so(self) -> None:
        text = format_markdown(
            make_report(Severity.LOW, coverage=Coverage(files_discovered=2, units_parsed=2))
        )
        assert "## Coverage" in text
        assert "- 2 files discovered, 2 units parsed" in text
        assert "No input errors or coverage gaps were recorded." in text

    def test_errors_gaps_and_set_aside_counts_are_listed(self) -> None:
        coverage = Coverage(
            files_discovered=3,
            units_parsed=2,
            not_iac_count=1,
            suppressed=2,
            baselined=1,
            rule_errors=1,
            errors=[{"file": "bad.tf", "code": "parse.failed", "message": "unexpected token"}],
            gaps=[
                {
                    "level": "warning",
                    "code": "hcl.module",
                    "message": "module skipped",
                    "file": "m.tf",
                }
            ],
        )
        text = format_markdown(make_report(Severity.LOW, coverage=coverage))
        assert "Set aside: 2 suppressed, 1 baselined" in text
        assert "**Input errors (1):**" in text and "`bad.tf`: unexpected token" in text
        assert "**Coverage gaps (1):**" in text and "`hcl.module` `m.tf`: module skipped" in text
        assert "Rule errors: 1 rule evaluation failed" in text
        assert "No input errors" not in text

    def test_the_llm_status_is_reported(self) -> None:
        ran = make_report(
            Severity.LOW, llm={"status": "ran", "provider": "p", "model": "m", "threat_count": 3}
        )
        assert "LLM analysis ran (p/m): 3 advisory findings." in format_markdown(ran)
        failed = make_report(Severity.LOW, llm={"status": "failed", "error": "boom\n# x"})
        text = format_markdown(failed)
        assert "**LLM analysis failed**" in text and "boom # x" in text
        assert "LLM analysis" not in format_markdown(
            make_report(Severity.LOW, llm={"status": "skipped"})
        )


class TestSizeCap:
    def big_report(self) -> ThreatReport:
        report = ThreatReport(scanned_resources=660, timestamp="")
        categories = [
            "spoofing",
            "tampering",
            "repudiation",
            "information_disclosure",
            "denial_of_service",
            "elevation_of_privilege",
        ]
        severities = [Severity.LOW, Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL]
        for i in range(660):
            report.add(
                make_threat(
                    i,
                    severities[i % 4],
                    stride=categories[i % 6],
                    description="A long description that repeats itself. " * 20,
                    mitigation="A long mitigation. " * 20,
                )
            )
        return report

    def test_the_report_fits_the_comment_limit_and_ends_with_the_footer(self) -> None:
        text = format_markdown(self.big_report())
        assert len(text) <= MAX_CHARS == 60_000
        assert text.rstrip().endswith("see the full report artifact._")
        match = re.search(r"_(\d+) more threats omitted", text)
        assert match and int(match.group(1)) > 0

    def test_the_omitted_count_matches_what_is_missing(self) -> None:
        text = format_markdown(self.big_report())
        shown = len(re.findall(r"^### \[", text, flags=re.MULTILINE))
        omitted = int(re.search(r"_(\d+) more threats omitted", text).group(1))  # type: ignore[union-attr]
        assert shown + omitted == 660

    def test_the_most_severe_findings_are_kept(self) -> None:
        text = format_markdown(self.big_report())
        shown = re.findall(r"^### \[(\w+)\]", text, flags=re.MULTILINE)
        rank = {"CRITICAL": 3, "HIGH": 2, "MEDIUM": 1, "LOW": 0}
        assert shown[:1] == ["CRITICAL"]
        assert [rank[s] for s in shown] == sorted((rank[s] for s in shown), reverse=True)
        # Anything lower is only kept once every more severe finding fit
        if "HIGH" in shown:
            assert shown.count("CRITICAL") == 165

    def test_the_summary_and_the_top_table_survive_the_cap(self) -> None:
        text = format_markdown(self.big_report())
        assert "| [CRITICAL] | 165 |" in text and "| [LOW] | 165 |" in text
        assert "## Top risks (10)" in text and "## Coverage" in text

    def test_a_small_cap_still_produces_a_valid_report(self) -> None:
        text = format_markdown(self.big_report(), max_chars=6000)
        assert len(text) <= 6000
        assert text.startswith("# ThreatCode Threat Model Report")
        assert "more threats omitted" in text

    def test_a_cap_below_the_fixed_parts_cuts_cleanly(self) -> None:
        text = format_markdown(self.big_report(), max_chars=800)
        assert len(text) <= 800
        assert text.count("```") % 2 == 0

    def test_a_report_under_the_cap_has_no_footer(self) -> None:
        assert "omitted" not in format_markdown(make_report(Severity.HIGH))


def hop(
    node_id: str,
    next_edge: str | None = None,
    *,
    zone: str = "private",
    via: dict[str, Any] | None = None,
    enabled_by: list[str] | None = None,
    resource_type: str = "",
) -> AttackHop:
    return AttackHop(
        node_id=node_id,
        zone=zone,
        resource_type=resource_type,
        edge_type_to_next=next_edge,
        via=via or {},
        enabled_by=enabled_by or [],
    )


def path_over(*hops: AttackHop, path_id: str = "aaaaaaaaaaaa", score: float = 9.0) -> AttackPath:
    return AttackPath(
        id=path_id,
        entry=hops[0].node_id,
        target=hops[-1].node_id,
        hops=list(hops),
        severity=Severity.HIGH,
        score=score,
    )


def lines_of(text: str, start: str) -> list[str]:
    """The lines of the first attack path section that starts at the heading ``start``."""
    block = text.split(start, 1)[1]
    block = block.split("\n### ")[0].split("\n## ")[0].split("\n_The diagram")[0]
    return block.splitlines()


class TestPathWords:
    """FV-18: an edge reads as words, never as the engine's token."""

    def test_no_edge_token_reaches_the_report(self) -> None:
        report = make_report(Severity.HIGH)
        report.attack_paths.append(
            path_over(
                hop("internet", "network_flow", via={"ports": ["443"], "protocol": "tcp"}),
                hop("aws_lb.front", "network_flow", via={"ports": ["8080"]}),
                hop("aws_instance.app", "iam_binding", via={"relation": "instance_profile"}),
                hop("aws_iam_instance_profile.app", "iam_binding", via={"relation": "assumes"}),
                hop("aws_iam_role.app", "data_flow", via={"relation": "returns_content"}),
                hop("aws_s3_bucket.data", None, zone="data"),
            )
        )
        text = format_markdown(report)
        # Addresses sit in code spans in the text and in node labels in the Mermaid block
        before, _, block = text.partition("```mermaid")
        prose = re.sub(r"(`+).+?\1", "", before)
        edge_labels = " ".join(re.findall(r'\|"([^"]*)"\|', block))
        for token in (
            "network_flow",
            "iam_binding",
            "data_flow",
            "instance_profile",
            "returns_content",
        ):
            assert token not in prose, token
            assert token not in edge_labels, token
        assert "then sends traffic on HTTPS 443" in text
        assert "then sends traffic on tcp/8080" in text
        assert "then runs with the next hop" in text
        assert "then assumes the next hop" in text

    @pytest.mark.parametrize(
        ("edge_type", "via", "target_type", "phrase"),
        [
            ("network_flow", {"ports": ["443"]}, "aws_lb", "sends traffic on HTTPS 443"),
            ("network_flow", {"ports": ["5432"]}, "aws_db_instance", "on PostgreSQL 5432"),
            (
                "iam_binding",
                {"relation": "instance_profile"},
                "aws_iam_instance_profile",
                "runs with the instance profile",
            ),
            ("iam_binding", {"relation": "assumes"}, "aws_iam_role", "assumes the role"),
            (
                "iam_binding",
                {"relation": "invokes", "protocol": "stdio"},
                "mcp_server",
                "invokes the MCP server",
            ),
            (
                "iam_binding",
                {"relation": "permission", "access": "read", "actions": ["s3:GetObject"]},
                "aws_s3_bucket",
                "can read the bucket (s3:GetObject)",
            ),
            ("data_flow", {"relation": "reads_secret"}, "kubernetes_secret", "reads the secret"),
            (
                "iam_binding",
                {"relation": "bound_role"},
                "kubernetes_cluster_role",
                "is bound to the cluster role",
            ),
        ],
    )
    def test_each_relation_has_a_phrase(
        self, edge_type: str, via: dict[str, Any], target_type: str, phrase: str
    ) -> None:
        report = make_report(Severity.HIGH)
        report.attack_paths.append(
            path_over(
                hop("a.one", edge_type, via=via),
                hop("b.two", None, resource_type=target_type),
            )
        )
        assert phrase in format_markdown(report)

    def test_an_unknown_relation_is_words_without_the_edge_type_prefix(self) -> None:
        report = make_report(Severity.HIGH)
        report.attack_paths.append(
            path_over(
                hop("a.one", "iam_binding", via={"relation": "grants_temporary_access"}),
                hop("b.two", None),
            )
        )
        text = format_markdown(report)
        assert "grants temporary access" in text
        assert "iam_binding" not in text and "grants_temporary_access" not in text

    def test_a_boundary_description_reads_in_words(self) -> None:
        report = ThreatReport()
        report.add(
            make_threat(
                1,
                Severity.HIGH,
                description="Traffic crosses a trust boundary (network_flow). Nothing checks it.",
            )
        )
        text = format_markdown(report)
        assert "(network traffic)" in text and "network_flow" not in text


class TestSharedHops:
    """FV-18: hops an earlier path already lists are said once."""

    def report(self) -> ThreatReport:
        report = make_report(Severity.HIGH)
        first = path_over(
            hop("internet", "network_flow", zone="internet", via={"ports": ["443"]}),
            hop("aws_lb.front", "network_flow", zone="dmz", via={"ports": ["8080"]}),
            hop("aws_instance.app", "iam_binding", via={"relation": "instance_profile"}),
            hop("aws_iam_instance_profile.app", "iam_binding", via={"relation": "assumes"}),
            hop("aws_s3_bucket.data", None, zone="data"),
            path_id="000000000001",
            score=9.5,
        )
        second = path_over(
            hop("internet", "network_flow", zone="internet", via={"ports": ["443"]}),
            hop("aws_lb.front", "network_flow", zone="dmz", via={"ports": ["8080"]}),
            hop("aws_instance.app", "network_flow", via={"ports": ["5432"]}),
            hop("aws_db_instance.orders", None, zone="data"),
            path_id="000000000002",
            score=9.0,
        )
        report.attack_paths.extend([first, second])
        return report

    def test_the_second_path_refers_to_the_first_for_the_hops_they_share(self) -> None:
        text = format_markdown(self.report())
        second = lines_of(text, "### 2. ")
        assert "Hops 1 to 2 are the same as in path 1: `internet`, `aws_lb.front`." in second
        assert not any(line.startswith(("1. ", "2. ")) for line in second)
        assert (
            "3. `aws_instance.app` (private zone), then sends traffic on PostgreSQL 5432" in second
        )
        assert "4. `aws_db_instance.orders` (data zone)" in second

    def test_the_first_path_lists_every_hop(self) -> None:
        first = lines_of(format_markdown(self.report()), "### 1. ")
        listed = [line for line in first if re.match(r"\d+\. ", line)]
        assert len(listed) == 5
        assert not any("are the same as" in line for line in first)

    def test_one_shared_hop_is_not_worth_a_reference(self) -> None:
        report = make_report(Severity.HIGH)
        report.attack_paths.append(
            path_over(
                hop("internet", "network_flow", via={"ports": ["443"]}),
                hop("aws_lb.one", None, zone="data"),
                path_id="000000000001",
                score=9.5,
            )
        )
        report.attack_paths.append(
            path_over(
                hop("internet", "network_flow", via={"ports": ["443"]}),
                hop("aws_lb.two", None, zone="data"),
                path_id="000000000002",
                score=9.0,
            )
        )
        second = lines_of(format_markdown(report), "### 2. ")
        assert "1. `internet` (private zone), then sends traffic on HTTPS 443" in second
        assert not any("are the same as" in line for line in second)

    def test_a_hop_with_a_different_next_step_is_listed_again(self) -> None:
        second = lines_of(format_markdown(self.report()), "### 2. ")
        # app is on both paths, but one goes on to the profile and the other to the database
        assert sum("aws_instance.app" in line for line in second) == 1

    def test_the_mermaid_block_still_draws_every_path(self) -> None:
        block = format_markdown(self.report()).split("```mermaid\n")[1].split("```")[0]
        assert block.count("==>") == 5  # shared hops once, then the two branches


class TestEnablerListing:
    """FV-18: a finding is listed on the first hop it enables, not again on the next."""

    def report(self) -> ThreatReport:
        report = ThreatReport(scanned_resources=3)
        report.add(
            make_threat(1, Severity.LOW, threat_id="sg", title="Open group", rule_id="SG_OPEN")
        )
        report.add(
            make_threat(2, Severity.HIGH, threat_id="cve", title="Bad image", rule_id="CVE-1")
        )
        report.add(
            make_threat(3, Severity.MEDIUM, threat_id="imds", title="IMDSv1", rule_id="IMDS")
        )
        report.attack_paths.append(
            path_over(
                hop("internet", "network_flow", enabled_by=["sg"]),
                hop("aws_lb.front", "network_flow", enabled_by=["sg"]),
                hop("aws_instance.app", "network_flow", enabled_by=["imds", "cve"]),
                hop("aws_db_instance.db", None, zone="data", enabled_by=["sg"]),
            )
        )
        return report

    def test_a_finding_on_two_consecutive_hops_is_listed_once(self) -> None:
        path = lines_of(format_markdown(self.report()), "### 1. ")
        assert sum("Open group" in line for line in path) == 2  # hop 1 and hop 4
        index = next(i for i, line in enumerate(path) if line.startswith("2. "))
        assert not path[index + 1].startswith("   - enabled by")

    def test_every_enabler_of_a_hop_is_listed_worst_first_with_its_rule_id(self) -> None:
        path = lines_of(format_markdown(self.report()), "### 1. ")
        index = next(i for i, line in enumerate(path) if line.startswith("3. "))
        assert path[index + 1] == "   - enabled by [HIGH] Bad image (`CVE-1`)"
        assert path[index + 2] == "   - enabled by [MEDIUM] IMDSv1 (`IMDS`)"


class TestSectionOrder:
    """FV-19: the section with the worst finding comes first."""

    def report(self) -> ThreatReport:
        report = ThreatReport()
        report.add(make_threat(1, Severity.LOW, stride="spoofing", title="Spoof low"))
        report.add(make_threat(2, Severity.MEDIUM, stride="tampering", title="Tamper medium"))
        report.add(make_threat(3, Severity.CRITICAL, stride="elevation_of_privilege", title="Crit"))
        report.add(make_threat(4, Severity.MEDIUM, stride="repudiation", title="Repudiate medium"))
        return report

    def sections(self, report: ThreatReport) -> list[str]:
        return [h[3:] for h in headings(format_markdown(report)) if h.startswith("## ")]

    def test_the_section_with_the_critical_finding_is_first(self) -> None:
        names = self.sections(self.report())
        stride = [
            n
            for n in names
            if n in {"Spoofing", "Tampering", "Repudiation", "Elevation of Privilege"}
        ]
        assert stride[0] == "Elevation of Privilege"

    def test_equal_severities_keep_the_stride_order(self) -> None:
        stride = [
            n
            for n in self.sections(self.report())
            if n in {"Spoofing", "Tampering", "Repudiation", "Elevation of Privilege"}
        ]
        assert stride == ["Elevation of Privilege", "Tampering", "Repudiation", "Spoofing"]

    def test_the_effective_severity_decides_not_the_base(self) -> None:
        report = self.report()
        report.threats[0].effective_severity = Severity.CRITICAL
        report.threats[2].effective_severity = Severity.HIGH
        stride = [n for n in self.sections(report) if n in {"Spoofing", "Elevation of Privilege"}]
        assert stride == ["Spoofing", "Elevation of Privilege"]


class TestHeadings:
    """FV-19: a heading names a resource once."""

    def test_a_boundary_heading_does_not_repeat_the_resource(self) -> None:
        report = ThreatReport()
        address = "kubernetes_ingress.platform.storefront"
        report.add(
            make_threat(
                1,
                Severity.HIGH,
                address=address,
                title=f"Trust boundary crossing: {address} (dmz) -> svc.x (private)",
            )
        )
        (heading,) = [h for h in headings(format_markdown(report)) if "Trust boundary" in h]
        assert heading.endswith("(private)")
        assert heading.count(address) == 1
        assert f"**Resource:** `{address}`" in format_markdown(report)

    def test_a_title_that_does_not_name_the_resource_gets_it_as_a_suffix(self) -> None:
        report = ThreatReport()
        report.add(make_threat(1, Severity.HIGH, address="res.a", title="Open"))
        assert "### [HIGH] Open - `res.a`" in format_markdown(report)

    def test_a_group_title_starts_with_a_capital(self) -> None:
        report = ThreatReport()
        for i in range(2):
            report.add(
                make_threat(i, Severity.HIGH, address="res.a", root_cause="container-hardening")
            )
        assert "### [HIGH] Container hardening (2 findings) - `res.a`" in format_markdown(report)


class TestUrls:
    """FV-20: a URL in running text is a code span, not text with an invisible character."""

    URL = "http://169.254.169.254"

    def report(self, description: str) -> ThreatReport:
        report = ThreatReport()
        report.add(make_threat(1, Severity.HIGH, description=description))
        return report

    def test_the_url_is_copyable(self) -> None:
        text = format_markdown(self.report(f"The role is read from {self.URL} by a request."))
        assert f"read from `{self.URL}` by a request." in text
        assert ZWJ not in text.split("## Tampering")[1].split("**Mitigation")[0]
        assert "http:" + ZWJ + "//" not in text

    def test_trailing_punctuation_stays_outside_the_span(self) -> None:
        text = format_markdown(
            self.report(f"See {self.URL}. Then (see {self.URL}), or {self.URL}!")
        )
        assert f"See `{self.URL}`." in text
        assert f"(see `{self.URL}`)," in text
        assert f"or `{self.URL}`!" in text

    def test_a_hostile_url_never_becomes_a_link_or_a_mention(self) -> None:
        hostile = (
            "go to https://evil.example/x?a=1&b=<script> or [click](https://evil.example) @octocat"
        )
        text = format_markdown(self.report(hostile))
        outside_code = re.sub(r"(`+).+?\1", "", text)
        assert "://" not in outside_code
        assert "](http" not in outside_code
        assert not re.search(r"(?<!\\)<script>", outside_code)
        assert f"@{ZWJ}octocat" in text

    def test_private_use_characters_cannot_forge_a_url_slot(self) -> None:
        text = format_markdown(self.report("odd 0 text  end"))
        assert "" not in text and "" not in text
        assert "odd 0 text end" in text

    def test_a_url_in_a_table_cell_title_keeps_the_table_intact(self) -> None:
        report = ThreatReport()
        report.add(make_threat(1, Severity.HIGH, title=f"Reads {self.URL}/a|b path"))
        rows = [line for line in format_markdown(report).splitlines() if line.startswith("| 1 ")]
        assert len(rows) == 1
        assert rows[0].count("|") - rows[0].count("\\|") == 6


class TestDiagramNote:
    def test_the_embedded_diagram_says_it_shows_the_hops_only(self) -> None:
        report = make_report(Severity.HIGH)
        report.attack_paths.append(path_over(hop("internet", "network_flow"), hop("db.x", None)))
        text = format_markdown(report)
        note = "The diagram draws the hops of these paths only."
        assert note in text
        assert text.index(note) < text.index("```mermaid")
