#!/usr/bin/env bash
# Install a built ThreatCode wheel into a fresh virtualenv and prove it works
# outside the source checkout. Guards against packaging regressions such as a
# wheel that ships without the builtin rule files (fixed in 0.9.1).
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

python -m venv "$WORK/venv"
"$WORK/venv/bin/python" -m pip install --quiet --disable-pip-version-check "$WHEEL"

# Run from an empty directory so the source tree cannot shadow the installed package.
cd "$WORK"
"$WORK/venv/bin/threatcode" --version
"$WORK/venv/bin/python" - <<'PY'
from threatcode.engine.rules.loader import load_builtin_rules

count = len(load_builtin_rules())
print(f"Builtin rules loaded: {count}")
assert count >= 220, f"expected at least 220 builtin rules, got {count}"
PY

# threatcode fs exits 1 when it finds threats, which is the expected outcome here.
"$WORK/venv/bin/threatcode" fs "$REPO/tests/fixtures/kubernetes" \
  --scanners misconfig --no-llm -o "$WORK/k8s.json" || true
"$WORK/venv/bin/python" - "$WORK/k8s.json" <<'PY'
import json
import sys

with open(sys.argv[1], encoding="utf-8") as fh:
    total = json.load(fh)["misconfig"]["total_threats"]
print(f"Findings on tests/fixtures/kubernetes: {total}")
assert total > 0, "the installed wheel found no threats in the insecure Kubernetes fixtures"
PY

echo "Wheel smoke test passed"
