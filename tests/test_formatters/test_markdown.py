"""Tests for threatcode.formatters.markdown: structure, safety, grouping and the size cap."""

from __future__ import annotations

import re
from typing import Any

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
        assert "**Severity:** High (base medium: internet reachable)" in text
        assert "### [HIGH]" in text

    def test_llm_findings_are_marked_advisory(self) -> None:
        report = ThreatReport()
        report.add(make_threat(1, source=ThreatSource.LLM))
        assert "**Source:** llm (advisory)" in format_markdown(report)


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
        grouped = [h for h in headings(text) if h.startswith("### ") and "container hardening" in h]
        assert grouped == [
            "### [HIGH] container hardening (3 findings) - `kubernetes_deployment.web`"
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
        assert "1. `internet` (internet zone), then network_flow on 443 to the next hop" in text
        assert "2. `aws_lb.web` (dmz zone), then network_flow to the next hop" in text
        assert "3. `aws_db_instance.main` (data zone)" in text
        assert "   - enabled by [HIGH] Threat 0 (`rule`)" in text
        assert "   - enabled by finding `gone`" in text
        assert "[T1190](https://attack.mitre.org/techniques/T1190/)" in text

    def test_a_mermaid_flowchart_follows_the_paths(self) -> None:
        text = format_markdown(self.report())
        block = text.split("```mermaid\n")[1].split("```")[0]
        assert block.startswith("flowchart LR")
        assert 'subgraph z1["internet"]' in block
        assert 'n1 ==>|"network_flow 443"| n2' in block

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
