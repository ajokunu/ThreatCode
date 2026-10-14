#!/usr/bin/env bash
# Install a built ThreatCode wheel into a fresh virtualenv and prove it works outside the source
# checkout, with the core dependencies only (no llm extra).
# Guards against packaging regressions: a wheel that ships a different set of builtin rule files
# or rule ids than the checkout it was built from, one without the py.typed marker, a version
# that differs between the metadata and the command, one that pulls in the anthropic SDK or needs
# it for a rules-only scan, or an llm extra that does not install.
#
# Usage: scripts/smoke_test_wheel.sh path/to/threatcode-*.whl
# PYTHON selects the interpreter that creates the virtualenv (default: python3).
set -euo pipefail

PYTHON=${PYTHON:-python3}
WHEEL=$(realpath "$1")
REPO=$(realpath "$(dirname "$0")/..")
WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT

# The packaged rule files are exactly the rule files in the checkout, not a count that a deleted
# file could still satisfy.
RULES_DIR=src/threatcode/engine/rules/builtin
unzip -Z1 "$WHEEL" | grep '^threatcode/engine/rules/builtin/.*\.yml$' | sort > "$WORK/wheel_rule_files.txt" || true
(cd "$REPO/src" && find threatcode/engine/rules/builtin -name '*.yml' | sort) > "$WORK/source_rule_files.txt"
echo "Builtin rule files in wheel: $(wc -l < "$WORK/wheel_rule_files.txt" | tr -d ' ')"
if [ ! -s "$WORK/source_rule_files.txt" ]; then
  echo "FAIL: found no rule files under $RULES_DIR in the checkout" >&2
  exit 1
fi
if ! diff "$WORK/source_rule_files.txt" "$WORK/wheel_rule_files.txt"; then
  echo "FAIL: the wheel's builtin rule files differ from the checkout's (< checkout, > wheel)" >&2
  exit 1
fi

typed_markers=$(unzip -Z1 "$WHEEL" | grep -c '^threatcode/py\.typed$' || true)
if [ "$typed_markers" -lt 1 ]; then
  echo "FAIL: the wheel does not ship threatcode/py.typed" >&2
  exit 1
fi

WHEEL_VERSION=$(unzip -p "$WHEEL" '*.dist-info/METADATA' | sed -n 's/^Version: //p' | head -n 1)
if [ -z "$WHEEL_VERSION" ]; then
  echo "FAIL: could not read the version from the wheel metadata" >&2
  exit 1
fi
echo "Wheel version: $WHEEL_VERSION"

"$PYTHON" -m venv "$WORK/venv"
"$WORK/venv/bin/python" -m pip install --quiet --disable-pip-version-check "$WHEEL"

# Run from an empty directory so the source tree cannot shadow the installed package.
cd "$WORK"
VERSION_LINE=$("$WORK/venv/bin/threatcode" --version)
echo "$VERSION_LINE"
if [ "$VERSION_LINE" != "threatcode, version $WHEEL_VERSION" ]; then
  echo "FAIL: 'threatcode --version' says '$VERSION_LINE', the wheel metadata says $WHEEL_VERSION" >&2
  exit 1
fi

# The installed package carries the same rules as the checkout: every rule id in the source files
# is loaded, and nothing else is.
"$WORK/venv/bin/python" - "$REPO" "$WHEEL_VERSION" <<'PY'
import importlib.metadata
import importlib.util
import pathlib
import sys

import yaml

import threatcode
from threatcode.engine.rules.loader import load_builtin_rules

source_root = pathlib.Path(sys.argv[1]).resolve()
expected_version = sys.argv[2]
assert threatcode.__version__ == expected_version, (threatcode.__version__, expected_version)
assert importlib.metadata.version("threatcode") == expected_version

source_ids = set()
for path in (source_root / "src/threatcode/engine/rules/builtin").rglob("*.yml"):
    data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    source_ids.update(rule["id"] for rule in data.get("rules", []))

loaded = load_builtin_rules()
loaded_ids = {rule.id for rule in loaded}
print(f"Builtin rules loaded: {len(loaded)}")
assert len(loaded) == len(loaded_ids), "the wheel loads a rule id twice"
assert loaded_ids == source_ids, (
    f"missing from the wheel: {sorted(source_ids - loaded_ids)}; "
    f"not in the checkout: {sorted(loaded_ids - source_ids)}"
)
assert loaded_ids, "no builtin rules loaded"

assert importlib.util.find_spec("anthropic") is None, (
    "the core wheel must not install the anthropic SDK; it belongs to the llm extra"
)
try:
    import anthropic  # noqa: F401
except ImportError:
    pass
else:
    raise AssertionError("import anthropic succeeded in the core-only environment")
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

# The worked example: the Terraform plan of examples/aws-webapp.
# Findings are expected (exit 1 when one is at or above the default gate), a clean pass is fine,
# and an input error is not.
expect_scan_exit "scan of examples/aws-webapp" "0 1" \
  "$WORK/venv/bin/threatcode" scan "$REPO/examples/aws-webapp/tfplan.json" -o "$WORK/aws.json"
"$WORK/venv/bin/python" - "$WORK/aws.json" <<'PY'
import json
import sys

with open(sys.argv[1], encoding="utf-8") as fh:
    report = json.load(fh)
print(f"Findings on examples/aws-webapp: {len(report['threats'])}")
assert report["threats"], "the installed wheel found nothing in the AWS example"
assert report["scanned_resources"] > 20, report["scanned_resources"]
assert report["coverage"]["errors"] == [], report["coverage"]["errors"]
PY

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
assert coverage["units_parsed"] > 1, coverage
assert coverage["units_parsed"] == coverage["files_discovered"], coverage
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

# Without the llm extra --llm is an error that names the extra, and it never sends anything.
# The key is a placeholder: the check for the SDK comes before any network call.
set +e
LLM_OUTPUT=$(ANTHROPIC_API_KEY=placeholder "$WORK/venv/bin/threatcode" scan \
  "$REPO/examples/aws-webapp/tfplan.json" --llm -o "$WORK/llm.json" 2>&1)
LLM_STATUS=$?
set -e
if [ "$LLM_STATUS" -ne 2 ] || ! printf '%s' "$LLM_OUTPUT" | grep -q 'threatcode\[llm\]'; then
  echo "FAIL: --llm without the extra exited $LLM_STATUS and said: $LLM_OUTPUT" >&2
  exit 1
fi
echo "--llm without the extra: exit $LLM_STATUS, names threatcode[llm]"

# The extra installs, and it brings the SDK.
"$WORK/venv/bin/python" -m pip install --quiet --disable-pip-version-check "${WHEEL}[llm]"
"$WORK/venv/bin/python" -c "import anthropic; print('anthropic', anthropic.__version__)"
expect_scan_exit "dry-run scan with the llm extra" "0 1" \
  "$WORK/venv/bin/threatcode" scan "$REPO/examples/aws-webapp/tfplan.json" --dry-run \
  --dry-run-output "$WORK/dry-run.json" -o "$WORK/dry.json"
test -s "$WORK/dry-run.json"

echo "Wheel smoke test passed"
