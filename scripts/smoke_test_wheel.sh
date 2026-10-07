#!/usr/bin/env bash
# Install a built ThreatCode wheel into a fresh virtualenv and prove it works
# outside the source checkout, with the core dependencies only (no llm extra).
# Guards against packaging regressions such as a wheel that ships without the
# builtin rule files (fixed in 0.9.1), without the py.typed marker, or one that
# pulls in the anthropic SDK or needs it to run a rules-only scan.
#
# Usage: scripts/smoke_test_wheel.sh path/to/threatcode-*.whl
set -euo pipefail

WHEEL=$(realpath "$1")
REPO=$(realpath "$(dirname "$0")/..")
WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT

rule_files=$(unzip -l "$WHEEL" | grep -c 'threatcode/engine/rules/builtin/.*\.yml$' || true)
echo "Builtin rule files in wheel: $rule_files"
if [ "$rule_files" -lt 50 ]; then
  echo "FAIL: expected at least 50 builtin rule files in the wheel" >&2
  exit 1
fi

typed_markers=$(unzip -l "$WHEEL" | grep -c 'threatcode/py\.typed$' || true)
if [ "$typed_markers" -lt 1 ]; then
  echo "FAIL: the wheel does not ship threatcode/py.typed" >&2
  exit 1
fi

python -m venv "$WORK/venv"
"$WORK/venv/bin/python" -m pip install --quiet --disable-pip-version-check "$WHEEL"

# Run from an empty directory so the source tree cannot shadow the installed package.
cd "$WORK"
"$WORK/venv/bin/threatcode" --version
"$WORK/venv/bin/python" - <<'PY'
import importlib.util

from threatcode.engine.rules.loader import load_builtin_rules

count = len(load_builtin_rules())
print(f"Builtin rules loaded: {count}")
assert count >= 220, f"expected at least 220 builtin rules, got {count}"

assert importlib.util.find_spec("anthropic") is None, (
    "the core wheel must not install the anthropic SDK; it belongs to the llm extra"
)
PY

# threatcode scan exits 1 when it finds threats, which is the expected outcome here.
"$WORK/venv/bin/threatcode" scan "$REPO/tests/fixtures/kubernetes/insecure_deployment.yml" \
  --no-llm -o "$WORK/k8s.json" || true
"$WORK/venv/bin/python" - "$WORK/k8s.json" <<'PY'
import json
import sys

with open(sys.argv[1], encoding="utf-8") as fh:
    total = len(json.load(fh)["threats"])
print(f"Findings on insecure_deployment.yml: {total}")
assert total > 0, "the installed wheel found no threats in the insecure Kubernetes fixture"
PY

echo "Wheel smoke test passed"
