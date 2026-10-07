# Real-shape corpus

Inputs written in the exact shapes the tools emit and teams commit.
The fixtures in `tests/fixtures/realistic` read well but were shaped for the parsers: plan JSON with attribute values that hold addresses, no `resource_changes`, no unknown values.
Tests built on them pass while containment, security-group inference and unknown-value handling rarely fire on real inputs.

Each directory names its source shape in a sidecar `README.md`.
Plan captures marked `source: handbuilt` were written by hand from the documented JSON schema because no Terraform or OpenTofu binary was available.
`scripts/capture_plans.md` describes how to replace them with captures from a real run.

These files live outside `tests/fixtures/realistic` and `tests/fixtures/golden`, so the recorded golden inputs are unchanged.
Per-format graph tests in `tests/test_ir/test_graph_realistic_*.py` assert the nodes, edges, zones and exposure each fixture should yield.
Assertions that depend on work not yet merged carry `pending("WP-x-y", reason)` naming the package that delivers them.

`hardened/` holds one input per format that is hardened throughout: every pod workload kind with pod-level and container-level hardening, init and sidecar containers, a default-deny NetworkPolicy and a labelled Namespace; a multi-stage Dockerfile with a pinned, non-root final stage; an MCP config with pinned packages, environment-referenced secrets and a loopback server.
`tests/test_quality/test_hardened_corpus.py` expects a scan of each to report nothing.
