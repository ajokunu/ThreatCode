#!/usr/bin/env python3
"""Generate src/threatcode/engine/mitre_data.py from the official ATT&CK STIX bundle.

The module is generated from the enterprise-attack STIX 2.1 bundle published in the
mitre-attack/attack-stix-data releases.
The pinned version is whatever ``ATTACK_VERSION`` the committed module already carries.
Bump it with ``--version X.Y``.

Usage:
    python scripts/gen_mitre_db.py                      # download pinned bundle, rewrite module
    python scripts/gen_mitre_db.py --check              # exit 1 if the committed module is stale
    python scripts/gen_mitre_db.py --version 19.3       # move the pin
    python scripts/gen_mitre_db.py --stix bundle.json   # offline, version taken from the bundle
    python scripts/gen_mitre_db.py --stix bundle.json --out /tmp/mitre_excerpt.py

Exit codes: 0 success, 1 --check found a difference, 2 usage or input error.
Only the standard library is used so the script runs without installing ThreatCode.
"""

from __future__ import annotations

import argparse
import difflib
import json
import re
import sys
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_OUT = REPO_ROOT / "src" / "threatcode" / "engine" / "mitre_data.py"
BUNDLE_URL = (
    "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/"
    "v{version}/enterprise-attack/enterprise-attack-{version}.json"
)
LINE_LENGTH = 100
ATTACK_SOURCE = "mitre-attack"
VERSION_RE = re.compile(r'^ATTACK_VERSION: str = "([^"]+)"$', re.MULTILINE)
TECHNIQUE_ID_RE = re.compile(r"^T\d{4}(\.\d{3})?$")
TACTIC_ID_RE = re.compile(r"^TA\d{4}$")


class GenError(Exception):
    """An input problem that should end the run with exit code 2."""


def _external_id(obj: dict[str, Any]) -> str | None:
    for ref in obj.get("external_references", []):
        if ref.get("source_name") == ATTACK_SOURCE and "external_id" in ref:
            return str(ref["external_id"])
    return None


def _technique_sort_key(tid: str) -> tuple[int, int]:
    base, _, sub = tid.partition(".")
    return int(base[1:]), int(sub) if sub else -1


def _technique_url(tid: str) -> str:
    return "https://attack.mitre.org/techniques/" + tid.replace(".", "/") + "/"


def _tactic_url(ta_id: str) -> str:
    return f"https://attack.mitre.org/tactics/{ta_id}/"


def build_data(
    bundle: dict[str, Any],
) -> tuple[str, dict[str, dict[str, str]], dict[str, dict[str, Any]], dict[str, str]]:
    """Reduce a STIX bundle to (version, tactics, techniques, revoked aliases)."""
    objects = bundle.get("objects")
    if not isinstance(objects, list):
        raise GenError("not a STIX bundle: no 'objects' list")

    collections = [o for o in objects if o.get("type") == "x-mitre-collection"]
    if len(collections) != 1 or not collections[0].get("x_mitre_version"):
        raise GenError("bundle must contain exactly one x-mitre-collection with x_mitre_version")
    version = str(collections[0]["x_mitre_version"])

    tactics: dict[str, dict[str, str]] = {}
    shortname_to_id: dict[str, str] = {}
    for obj in objects:
        if obj.get("type") != "x-mitre-tactic":
            continue
        ta_id = _external_id(obj)
        shortname = obj.get("x_mitre_shortname")
        if not ta_id or not TACTIC_ID_RE.match(ta_id) or not shortname:
            raise GenError(f"malformed tactic object {obj.get('id')}")
        tactics[ta_id] = {
            "name": str(obj["name"]),
            "shortname": str(shortname),
            "url": _tactic_url(ta_id),
        }
        shortname_to_id[str(shortname)] = ta_id
    if not tactics:
        raise GenError("bundle contains no tactics")

    patterns: dict[str, dict[str, Any]] = {}
    stix_to_tid: dict[str, str] = {}
    for obj in objects:
        if obj.get("type") != "attack-pattern":
            continue
        tid = _external_id(obj)
        if not tid or not TECHNIQUE_ID_RE.match(tid):
            continue
        patterns[tid] = obj
        stix_to_tid[str(obj["id"])] = tid
    if not patterns:
        raise GenError("bundle contains no techniques")

    revoked_by: dict[str, str] = {}
    for obj in objects:
        if obj.get("type") != "relationship" or obj.get("relationship_type") != "revoked-by":
            continue
        if obj.get("revoked") or obj.get("x_mitre_deprecated"):
            continue
        old = stix_to_tid.get(str(obj.get("source_ref")))
        new = stix_to_tid.get(str(obj.get("target_ref")))
        if old is None or new is None:
            continue
        if old in revoked_by and revoked_by[old] != new:
            raise GenError(f"{old} is revoked by more than one technique")
        revoked_by[old] = new

    techniques: dict[str, dict[str, Any]] = {}
    for tid in sorted(patterns, key=_technique_sort_key):
        obj = patterns[tid]
        name = str(obj["name"])
        if "." in tid:
            parent = patterns.get(tid.split(".")[0])
            if parent is None:
                raise GenError(f"sub-technique {tid} has no parent technique in the bundle")
            name = f"{parent['name']}: {name}"
        tactic_ids: set[str] = set()
        for phase in obj.get("kill_chain_phases", []):
            if phase.get("kill_chain_name") != ATTACK_SOURCE:
                continue
            phase_name = str(phase.get("phase_name"))
            if phase_name not in shortname_to_id:
                raise GenError(f"{tid} references unknown tactic shortname {phase_name!r}")
            tactic_ids.add(shortname_to_id[phase_name])
        is_revoked = bool(obj.get("revoked")) or tid in revoked_by
        techniques[tid] = {
            "name": name,
            "tactic_ids": sorted(tactic_ids),
            "url": _technique_url(tid),
            "platforms": sorted(str(p) for p in obj.get("x_mitre_platforms", [])),
            "deprecated": bool(obj.get("x_mitre_deprecated")),
            "revoked": is_revoked,
            "revoked_by": revoked_by.get(tid),
        }
    return version, tactics, techniques, dict(sorted(revoked_by.items(), key=_alias_key))


def _alias_key(item: tuple[str, str]) -> tuple[int, int]:
    return _technique_sort_key(item[0])


def _q(value: str) -> str:
    return json.dumps(value, ensure_ascii=False)


def _fmt_list(prefix: str, items: list[str], indent: int) -> list[str]:
    """Format `prefix[items],` the way ruff format would (one line if it fits)."""
    pad = " " * indent
    if not items:
        return [f"{pad}{prefix}[],"]
    one = f"{pad}{prefix}[{', '.join(_q(i) for i in items)}],"
    if len(one) <= LINE_LENGTH:
        return [one]
    return [f"{pad}{prefix}[", *[f"{pad}    {_q(i)}," for i in items], f"{pad}],"]


def render(
    version: str,
    tactics: dict[str, dict[str, str]],
    techniques: dict[str, dict[str, Any]],
    aliases: dict[str, str],
) -> str:
    source_url = BUNDLE_URL.format(version=version)
    out: list[str] = [
        '"""MITRE ATT&CK enterprise data. GENERATED FILE, DO NOT EDIT BY HAND.',
        "",
        f"Generated by scripts/gen_mitre_db.py from ATT&CK v{version} (enterprise STIX 2.1).",
        f"Source: {source_url}",
        "Regenerate with `python scripts/gen_mitre_db.py` and verify with `--check`.",
        "See docs/mitre-attack.md.",
        '"""',
        "",
        "from __future__ import annotations",
        "",
        "from typing import TypedDict",
        "",
        "",
        "class TacticEntry(TypedDict):",
        "    name: str",
        "    shortname: str",
        "    url: str",
        "",
        "",
        "class TechniqueEntry(TypedDict):",
        "    name: str",
        "    tactic_ids: list[str]",
        "    url: str",
        "    platforms: list[str]",
        "    deprecated: bool",
        "    revoked: bool",
        "    revoked_by: str | None",
        "",
        "",
        f'ATTACK_VERSION: str = "{version}"',
        f"ATTACK_SOURCE_URL: str = {_q(source_url)}",
        "",
        "TACTICS: dict[str, TacticEntry] = {",
    ]
    for ta_id in sorted(tactics):
        t = tactics[ta_id]
        out += [
            f'    "{ta_id}": {{',
            f'        "name": {_q(t["name"])},',
            f'        "shortname": {_q(t["shortname"])},',
            f'        "url": {_q(t["url"])},',
            "    },",
        ]
    out += ["}", "", "TECHNIQUES: dict[str, TechniqueEntry] = {"]
    for tid, tech in techniques.items():
        out.append(f'    "{tid}": {{')
        name_line = f'        "name": {_q(tech["name"])},'
        out.append(name_line + ("  # noqa: E501" if len(name_line) > LINE_LENGTH else ""))
        out += _fmt_list('"tactic_ids": ', tech["tactic_ids"], 8)
        out.append(f'        "url": {_q(tech["url"])},')
        out += _fmt_list('"platforms": ', tech["platforms"], 8)
        out.append(f'        "deprecated": {tech["deprecated"]},')
        out.append(f'        "revoked": {tech["revoked"]},')
        rb = tech["revoked_by"]
        out.append(f'        "revoked_by": {_q(rb) if rb else "None"},')
        out.append("    },")
    out += [
        "}",
        "",
        "# Revoked technique ID -> the ID that replaced it, from STIX revoked-by relationships.",
        "",
    ]
    if aliases:
        out.append("REVOKED_ALIASES: dict[str, str] = {")
        out += [f'    "{old}": "{new}",' for old, new in aliases.items()]
        out.append("}")
    else:
        out.append("REVOKED_ALIASES: dict[str, str] = {}")
    return "\n".join(out) + "\n"


def generate(bundle: dict[str, Any]) -> tuple[str, str]:
    """Return (version, module source) for a parsed bundle."""
    version, tactics, techniques, aliases = build_data(bundle)
    return version, render(version, tactics, techniques, aliases)


def _committed_version(out_path: Path) -> str | None:
    try:
        text = out_path.read_text(encoding="utf-8")
    except OSError:
        return None
    match = VERSION_RE.search(text)
    return match.group(1) if match else None


def _download(url: str) -> bytes:
    request = urllib.request.Request(url, headers={"User-Agent": "threatcode-gen-mitre-db"})
    last: Exception | None = None
    for _ in range(3):
        try:
            with urllib.request.urlopen(request, timeout=120) as response:
                data: bytes = response.read()
                return data
        except (urllib.error.URLError, TimeoutError, OSError) as exc:
            last = exc
    raise GenError(f"could not download {url}: {last}")


def _load_bundle(args: argparse.Namespace, out_path: Path) -> dict[str, Any]:
    if args.stix:
        try:
            raw = Path(args.stix).read_bytes()
        except OSError as exc:
            raise GenError(f"cannot read {args.stix}: {exc}")
    else:
        version = args.version or _committed_version(out_path)
        if not version:
            raise GenError("no pinned version: pass --version X.Y or --stix PATH")
        raw = _download(BUNDLE_URL.format(version=version))
    try:
        bundle = json.loads(raw)
    except ValueError as exc:
        raise GenError(f"input is not valid JSON: {exc}")
    if not isinstance(bundle, dict):
        raise GenError("not a STIX bundle: top level is not an object")
    return bundle


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0] if __doc__ else None)
    parser.add_argument("--stix", help="read this local enterprise-attack STIX bundle (offline)")
    parser.add_argument("--version", help="ATT&CK version to download (default: the committed pin)")
    parser.add_argument("--out", help=f"output module path (default: {DEFAULT_OUT})")
    parser.add_argument(
        "--check",
        action="store_true",
        help="do not write; exit 1 if the output module differs from what the bundle produces",
    )
    args = parser.parse_args(argv)
    out_path = Path(args.out) if args.out else DEFAULT_OUT

    try:
        bundle = _load_bundle(args, out_path)
        version, source = generate(bundle)
        if args.version and args.version != version:
            raise GenError(f"bundle is ATT&CK {version} but --version asked for {args.version}")
    except GenError as exc:
        print(f"gen_mitre_db: error: {exc}", file=sys.stderr)
        return 2

    if args.check:
        try:
            current = out_path.read_text(encoding="utf-8")
        except OSError as exc:
            print(f"gen_mitre_db: error: cannot read {out_path}: {exc}", file=sys.stderr)
            return 2
        if current == source:
            print(f"{out_path}: up to date with ATT&CK v{version}")
            return 0
        diff = difflib.unified_diff(
            current.splitlines(),
            source.splitlines(),
            fromfile=f"{out_path} (committed)",
            tofile=f"ATT&CK v{version} (generated)",
            lineterm="",
        )
        for line, _ in zip(diff, range(60)):
            print(line, file=sys.stderr)
        print(
            f"gen_mitre_db: {out_path} is stale; run `python scripts/gen_mitre_db.py`",
            file=sys.stderr,
        )
        return 1

    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(source, encoding="utf-8", newline="\n")
    print(f"wrote {out_path} (ATT&CK v{version})")
    return 0


if __name__ == "__main__":
    sys.exit(main())
