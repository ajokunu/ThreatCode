# API reference

The Python API goes through the same pipeline as `threatcode scan`, so a call and the command line cannot disagree.
Importing `threatcode` is cheap: the names below load on first use.

## The public surface

`threatcode.__all__` is the supported API.
Everything else is internal and can change between releases.

<!-- gen:public-api -->
| Name | Kind | What it is |
| --- | --- | --- |
| `AnalysisResult` | class | Result of analyze() - wraps the infrastructure graph and threat report. |
| `ConfigError` | exception | Raised when configuration is invalid. |
| `LLMError` | exception | Raised when LLM communication fails. |
| `ParseError` | exception | Raised when IaC input cannot be parsed. |
| `RuleLoadError` | exception | Raised when a rule file cannot be loaded or is invalid. |
| `ScanRequest` | class | Everything one scan needs: the paths and the resolved settings. |
| `ScanResult` | class | The outcome of ``run_scan``. |
| `Severity` | class | Orders members by ``rank``. |
| `Threat` | class | Threat(id: 'str', title: 'str', description: 'str', stride_category: 'str', severity: 'Severity', source: 'ThreatSource', resource_type: 'str', resource_address: 'str', mitigation: 'str' = '', rule_id: 'str' = '', confidence: 'float' = 1.0, metadata: 'dict[str, Any]' = <factory>, mitre_techniques: 'list[str]' = <factory>, mitre_tactics: 'list[str]' = <factory>, location_file: 'str' = '', location_start_line: 'int \| None' = None, location_end_line: 'int \| None' = None, fingerprint: 'str' = '', evidence: 'str' = 'config', tool: 'str' = '', aliases: 'list[str]' = <factory>, target_address: 'str' = '', effective_severity: 'Severity \| None' = None, severity_reason: 'str' = '', path_ids: 'list[str]' = <factory>, root_cause: 'str' = '') |
| `ThreatCodeError` | exception | Base exception for all ThreatCode errors. |
| `ThreatReport` | class | ThreatReport(threats: 'list[Threat]' = <factory>, scanned_resources: 'int' = 0, input_file: 'str' = '', timestamp: 'str' = <factory>, version: 'str' = '', attack_paths: 'list[AttackPath]' = <factory>, llm: 'dict[str, Any] \| None' = None, rule_errors: 'list[dict[str, str]]' = <factory>, coverage: 'Coverage' = <factory>, input_paths: 'list[str]' = <factory>) |
| `UnsupportedFormatError` | exception | Raised when the input format is not recognized. |
| `UsageError` | exception | Raised when the command line or a named input file is unusable. |
| `__version__` | str | The installed version. |
| `analyze` | function | Like ``scan``, but return the graph and the report together. |
| `run_scan` | function | Run one scan end to end. The pipeline never prints and never exits. |
| `scan` | function | Scan files and directories and return the threat report as a dict. |
<!-- /gen:public-api -->

## `scan()`

```python
threatcode.scan(paths, **settings) -> dict
```

Scans files and directories and returns the report as a dict, exactly what `threatcode scan -f json` prints.
`paths` is a path or a sequence of paths, or `"-"` for standard input.

<!-- runnable -->

```python
import threatcode

report = threatcode.scan("examples/aws-webapp", fail_on="none")

print(report["schema_version"], report["total_threats"], "findings")
print(report["summary"])
for path in report["attack_paths"]:
    print(path["severity"], path["entry"], "->", path["target"], f"({len(path['hops'])} hops)")
assert report["coverage"]["errors"] == []
```

The settings are the command-line flags under their Python names: `fail_on`, `min_severity`, `strict`, `config_path`, `extra_rule_paths`, `llm` (False unless set), `dry_run`, `ignore_file`, `no_ignore`, `baseline`, `write_baseline`, `ingest`, `stdin_name`, `no_timestamp`, `max_nodes` and `max_edges`.
`scan` takes no `output_format`: it returns a dict, and `threatcode.formatters.render(name, analysis)` renders any other format.

A finding never raises, so the exit code contract does not apply to the return value: look at `report["attack_paths"]` and the severities, or use `run_scan` for the exit code.
An input that could not be analysed does raise:

<!-- runnable -->

```python
import threatcode

try:
    threatcode.scan("examples/no-such-directory")
except threatcode.UsageError as error:
    print("usage error:", error)
else:
    raise SystemExit("a missing path must raise")
```

**Raises:** `ThreatCodeError` when an input could not be analysed or a setting is invalid, and `UsageError` for a path that does not exist.

### The report

| Key | Meaning |
|-----|---------|
| `schema_version` | The report schema, `"2"`. |
| `version`, `timestamp` | The ThreatCode version, and the time (left out with `no_timestamp`; `SOURCE_DATE_EPOCH` fixes it). |
| `input_file`, `scanned_resources` | What was scanned: `.` for a directory, and the number of resources the rules ran on. |
| `summary`, `total_threats` | Findings per effective severity (zero buckets are left out), and their number. |
| `threats` | The findings, most severe first. |
| `attack_paths` | The attack paths, highest score first. |
| `coverage` | What was not analysed: errors, gaps, rule errors, files set aside, suppressed and baselined counts. |
| `llm` | Present only when the model review ran or failed: provider, model, status and counts. |
| `ingest` | Present only when scanner results were ingested: one record per tool run. |

A finding has `id`, `title`, `description`, `stride_category`, `severity` (the rule's base severity), `effective_severity` and `severity_reason` (when context changed it), `source` (`rule`, `boundary`, `secret`, `scanner` or `llm`), `resource_type`, `resource_address`, `mitigation`, `rule_id`, `confidence`, `mitre_techniques`, `mitre_tactics`, `location_file`, `location_start_line`, `fingerprint` and `path_ids`.
Fields that carry their default are left out.

An attack path has `id` (a hash of its node sequence, stable across runs), `entry`, `target`, `severity`, `score`, `rationale`, `techniques`, `tactics`, `alternatives` and `hops`.
A hop has `node_id`, `resource_type`, `zone`, `edge_type_to_next`, `via`, `enabled_by` and `techniques`.

## `analyze()`

```python
threatcode.analyze(paths, **settings) -> AnalysisResult
```

Like `scan`, but returns the graph and the report together.

<!-- runnable -->

```python
import threatcode
from threatcode.formatters import render

result = threatcode.analyze("examples/aws-webapp", fail_on="none")

print(result.graph.node_count, "nodes")
print(len(result.report.threats), "findings", len(result.attack_paths), "attack paths")
print(sorted({node.exposure for node in result.graph.nodes.values()}))

sarif = render("sarif", result)
assert '"version": "2.1.0"' in sarif
svg = result.to_svg()
assert svg.startswith("<svg")
```

`AnalysisResult` has `.graph` (the `InfraGraph`), `.report` (a `ThreatReport`), `.attack_paths`, `.root` (the scan root that report paths are relative to) and `.ingest_sources`.

## `run_scan()`

```python
threatcode.run_scan(request: ScanRequest) -> ScanResult
```

The full pipeline.
It never prints and never exits, and it returns the partial result when an input failed, so it is the call for tools that wrap ThreatCode.
Build the request with `threatcode.pipeline.prepare_request(paths, **settings)`, which resolves flags, environment and config exactly as the command line does.

<!-- runnable -->

```python
from threatcode import run_scan
from threatcode.pipeline import prepare_request

prepared = prepare_request(["examples/aws-webapp"], no_timestamp=True)
result = run_scan(prepared.request)

print("exit code", result.exit_code)  # 0, 1 or 2, as the command line would exit
print(result.coverage.errors, result.coverage.gaps)
assert result.exit_code == 1
```

`ScanResult` has `.analysis`, `.exit_code`, `.coverage`, `.report`, `.graph`, `.notices` (warnings about suppressions and baselines), `.ingest_sources`, and `.to_dict()`.

## Exceptions

`ThreatCodeError` is the base class.
`UsageError` is a wrong path or option, `ParseError` and `UnsupportedFormatError` come from parsers, `RuleLoadError` from rule files, `ConfigError` from configuration and `LLMError` from the model client.
The command line turns each of them into `Error: <message>` and exit 2.

## Internal APIs

For deeper integration you can use the components directly.
These can change between releases.

```python
from threatcode.parsers import detect_and_parse, register_parser
from threatcode.ir.graph import InfraGraph
from threatcode.engine.hybrid import HybridEngine
from threatcode.engine.rules.loader import load_builtin_rules, load_all_rules
from threatcode.engine.mitre import TECHNIQUE_DB, tactics_for_techniques
from threatcode.formatters import FORMATTERS, render
```

### Register a custom parser

`register_parser(name, detector, factory, extensions=None, priority=100)` adds a parser.
`detector(path, content, data)` returns whether the parser claims the file (`data` is the parsed JSON or YAML when the file has one, else `None`), and `factory()` returns a `BaseParser` whose `parse(data, source_path)` returns a `ParsedOutput`.
The registry asks detectors in priority order, lowest first, and only for files whose suffix is in `extensions` when you give any.
A parser that claims a file and raises makes the scan fail with a `ParseError` that names the parser and the file.

<!-- runnable -->

```python
from pathlib import Path
from typing import Any

import threatcode
from threatcode.parsers import detect_and_parse, register_parser
from threatcode.parsers.base import BaseParser, ParsedOutput, ParsedResource


class QueueListParser(BaseParser):
    """Reads a file with one `<name> <encrypted|plain>` line per queue."""

    def parse(self, data: Any, source_path: str = "") -> ParsedOutput:
        resources = []
        for number, line in enumerate(str(data).splitlines(), start=1):
            if not line.strip():
                continue
            name, mode = line.split()
            resources.append(
                ParsedResource(
                    resource_type="aws_sqs_queue",
                    address=f"aws_sqs_queue.{name}",
                    name=name,
                    provider="aws",
                    properties={"sqs_managed_sse_enabled": mode == "encrypted"},
                    source_location=source_path,
                    start_line=number,
                )
            )
        return ParsedOutput(resources=resources, source_path=source_path, format_type="queue_list")


def detect_queue_list(path: Path, content: str, data: Any | None) -> bool:
    return path.suffix == ".queues"


register_parser(
    "queue_list", detect_queue_list, QueueListParser, extensions={".queues"}, priority=50
)

Path("jobs.queues").write_text("orders encrypted\nevents plain\n", encoding="utf-8")

parsed = detect_and_parse("jobs.queues")
assert [r.address for r in parsed.resources] == ["aws_sqs_queue.orders", "aws_sqs_queue.events"]

report = threatcode.scan("jobs.queues", fail_on="none")
flagged = {(t["rule_id"], t["resource_address"]) for t in report["threats"]}
assert ("SQS_NO_ENCRYPTION", "aws_sqs_queue.events") in flagged
```

The built-in rules apply to the resources your parser produces, because rules match on resource type.
Give a resource the type and attribute names a built-in rule reads, or write rules for your own types.

### The infrastructure graph

<!-- runnable -->

```python
import threatcode

graph = threatcode.analyze("examples/aws-webapp", fail_on="none").graph

for node_id, node in list(graph.nodes.items())[:5]:
    print(node_id, node.category.value, node.trust_zone.value, node.exposure)

crossings = graph.get_boundary_crossing_edges()
print(len(crossings), "edges cross a trust zone")
assert graph.internet_node is not None
```

Node categories are compute, storage, network, database, iam, serverless, cdn, dns, monitoring, messaging, container, secret, api and unknown.
Trust zones are internet, dmz, private, data and management.
The edge types and what each means are in [architecture](architecture.md#edges).
`InfraGraph.to_export_dict()` returns the nodes and edges in a stable order, without properties, for tools that draw or diff the graph.
