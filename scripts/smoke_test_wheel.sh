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

# threatcode scan exits 0 for a clean scan, 1 when it finds something at or above --fail-on
# (the default is high) and 2 for a usage or input error. Findings are the expected outcome
# here, so 0 and 1 pass and anything else fails the smoke test.
expect_scan_exit() {
  local label=$1 allowed=$2
  shift 2
  set +e
  "$@"
  local status=$?
  set -e
  case " $allowed " in
    *" $status "*) ;;
    *)
      echo "FAIL: $label exited $status, expected one of: $allowed" >&2
      exit 1
      ;;
  esac
}

# A directory of manifests is scanned as one graph.
expect_scan_exit "scan of a directory" "0 1" \
  "$WORK/venv/bin/threatcode" scan "$REPO/tests/fixtures/kubernetes" -o "$WORK/k8s.json"
"$WORK/venv/bin/python" - "$WORK/k8s.json" <<'PY'
import json
import sys

with open(sys.argv[1], encoding="utf-8") as fh:
    report = json.load(fh)
total = len(report["threats"])
coverage = report["coverage"]
print(f"Findings on the kubernetes fixtures: {total}, units parsed: {coverage['units_parsed']}")
assert total > 0, "the installed wheel found no threats in the insecure Kubernetes fixtures"
assert report["schema_version"] == "2", report["schema_version"]
assert coverage["units_parsed"] == 3, coverage
assert coverage["errors"] == [], coverage["errors"]
PY

# Standard input works with a name that selects the format.
printf 'resource "aws_s3_bucket" "b" {\n  bucket = "b"\n}\n' > "$WORK/main.tf"
expect_scan_exit "scan of standard input" "0 1" \
  "$WORK/venv/bin/threatcode" scan - --stdin-name main.tf --fail-on none -o "$WORK/stdin.json" \
  < "$WORK/main.tf"
test -s "$WORK/stdin.json"

# A scan that finds nothing to model must fail loudly, never exit 0.
mkdir "$WORK/empty"
expect_scan_exit "scan of an empty directory" "2" \
  "$WORK/venv/bin/threatcode" scan "$WORK/empty" -o "$WORK/empty.json"

echo "Wheel smoke test passed"
