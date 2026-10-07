# Vendored schemas

JSON Schemas the output-format tests validate against.
All were retrieved on 2026-10-07 and are not modified, except where a file says it was derived.

## SARIF 2.1.0

File: `sarif-schema-2.1.0.json`, the JSON Schema of SARIF 2.1.0 (JSON Schema draft-04, internal `$ref` only).
Source: https://github.com/oasis-tcs/sarif-spec/blob/main/sarif-2.1/schema/sarif-schema-2.1.0.json
Source commit: `a560296ca8c921f3bdb8d4a8db57ab83dae968a7` (2024-05-02), the last commit that touched the file.
The file carries the OASIS `$id` https://docs.oasis-open.org/sarif/sarif/v2.1.0/errata01/os/schemas/sarif-schema-2.1.0.json.
License: OASIS Standard, contributed under the OASIS IPR Policy (RF on RAND terms), see https://github.com/oasis-tcs/sarif-spec/blob/main/LICENSE.md.
JSON cannot carry a comment, so the license statement lives here.
Validate with `jsonschema.Draft4Validator`.

## ATT&CK Navigator layer 4.5

MITRE publishes the layer file format as a document (`layers/spec/v4.5/layerformat.md`) and no JSON Schema for it.
`attack-navigator-layer-4.5.schema.json` is a hand-written JSON Schema (draft-07) derived from the property tables of that document.
It checks structure and types only: required properties, enums the document lists (domain, sorting, layout values) and technique id shape.
Values that depend on the ATT&CK release, such as tactic shortnames, platform names and a full Navigator version, are checked by the semantic checks in `tests/test_formatters/test_schema_conformance.py`.
A property the document does not list is rejected, which catches misspelled keys.

`attack-navigator-layerformat-4.5.md` is the source document, kept so the derivation can be checked and repeated.
Source: https://github.com/mitre-attack/attack-navigator/blob/master/layers/spec/v4.5/layerformat.md
Source commit: `db05f442e84038f967b082a82d7ccfa77b7593c7` (2025-10-28, "chore: bump version to 5.2.0"), the last commit that touched the file when retrieved.
License: Apache-2.0, https://github.com/mitre-attack/attack-navigator/blob/master/LICENSE.txt.
Copyright the MITRE Corporation.
Validate with `jsonschema.Draft7Validator`.

## Updating

Fetch the file again, record the new source commit and date above, and run `pytest tests/test_formatters/test_schema_conformance.py`.
