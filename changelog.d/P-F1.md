### Added
- **`-q`, `-v` and `--no-color` work after the command.**
  `threatcode scan infra/ -q` used to fail with `No such option: -q` (and `--no-color` suggested `--no-ignore`).
  Both `scan` and `diff` accept the three options now, they add to the same options given before the command, and each command's help lists them.
  `--debug` stays a group option.
- **`-o -` and `-o /dev/stdout` write the report to standard output.**
  `-o -` used to create a file named `-`, and `-o /dev/stdout` failed the readability check of the path option.
  Neither prints the `Report written to` line, since nothing was written to a file.
- **The format follows the `-o` extension when `-f` is absent.**
  `-o results.sarif` writes SARIF, `-o report.md` Markdown, `-o flow.mmd` Mermaid, `-o map.svg` the diagram and `-o out.json` the JSON report; a name with no extension, or one no format claims, still writes JSON.
  `-f json -o results.sarif` still writes JSON and now says on stderr that the file name suggests SARIF (the warning survives `-q`).
  A format set by `THREATCODE_FORMAT` or the config counts as given.
- **`--source-root DIR`** sets the repository root that SARIF and Bitbucket paths are relative to, for a checkout with no `.git` directory.
- **`--diagram-max-rows N`, `--diagram-expand-docker` and `--diagram-detail auto|full|collapsed`** reach the SVG diagram.
  They were renderer options with no way to set them.
  Giving one with another format is a usage error instead of being ignored.
- **The removed 0.9 commands `fs`, `repo`, `image`, `vuln`, `db`, `secret`, `sbom` and `license` answer with what replaces them** and a pointer to `docs/migrating.md` (exit 2), instead of `No such command`.
  They stay out of `--help`.

### Changed
- **`-f matrix` is hidden from `--help` and from the invalid-value error but still accepted,** and every use prints `Warning: -f matrix is deprecated, use -f navigator` on stderr, once, even with `-q`.
- **`--format` shows a short `FORMAT` metavar** with the formats and the default in its description, `--max-nodes` and `--max-edges` state their defaults (10,000 and 50,000), and `diff --fail-on-new` takes the same choices as `scan --fail-on`, including `none`.
- **`-f diagram` and `-f navigator` (and `matrix`) are refused when standard output is a terminal,** before the scan runs, with the `-o file` form to use instead.
  Only the diagram was refused before.
- **`--llm` checks for the anthropic SDK before it says anything about sending.**
  Without the SDK it is one exit-2 line that names `pip install 'threatcode[llm]'`, with or without an API key (before, a missing key printed the "sending" line and a warning, exit 1, and the key was the first of two errors).
  Without a key the scan still continues with rules only, and the `LLM enrichment enabled: sending ...` line is printed only when a request can actually be sent.
  `--dry-run` needs neither.
- **The Environment block is one list** shared by the main help and the help of `scan` and `diff`, so `scan --help` now lists `THREATCODE_MAX_NODES`, `THREATCODE_MAX_EDGES` and `THREATCODE_DEBUG` too.

### Fixed
- **`--fail-on none -f bitbucket` is reported PASSED, not FAILED:** the CLI now hands the gate to the Bitbucket renderer.
- **The closing `Scanned ...` line says `incomplete` when part of the input was left out:** a Helm template that was skipped or only approximated, or an error-level coverage gap, joins the input errors it already named.
  `found 0 findings` over a chart whose templates were skipped no longer reads as clean.
- **The duplicate-id warning of `threatcode.scan()` also runs on the command line.**
- **No golden recording changes.**
  The package changes the command line and the values it hands to renderers; the recorded scans and reports are byte-identical.
