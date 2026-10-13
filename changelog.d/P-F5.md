### Changed
- **The documentation describes the build it ships with.**
  The getting-started walkthrough explains the text report as it is printed: the `P1` numbers, the findings under `enabled by:` for each hop, `ignore id`, the `BOUNDARY_*` ids, `trivy:CVE-...` style ids for scanner results, the PATHS column and the `^` and `v` severity marks.
  The CLI reference, the CI page and the migration page now state what the SARIF writer does: paths relative to the top of the git checkout (`--source-root` for a tree with no `.git`), the `sarif.paths.unanchored` and `sarif.paths.outside_repository` warnings, the `<id>/<severity>` variant rule ids and that the bare id is the rule's highest base severity, and the note-level notifications `suppressions.applied`, `baseline.applied`, `min_severity.hidden`, `ingest.source` and `llm.ran`.
  They also say that the Bitbucket `result` follows `--fail-on`, that `-f` may be left out when `-o` names the format, that `-o -` writes to standard output, that `-q`, `-v` and `--no-color` work after the command name, and that the removed commands print a pointer to the migration page.
- **The deprecated `matrix` format is named only on the migration page.**
  The generated format tables and option lists leave it out, as `--help` does, and a test fails when any other page lists it.
- **The support matrix has a Coverage gaps section.**
  It lists the gaps a scan can report with what raises each and what to do, including `hcl.default_disabled` (a resource a variable default switches off; a `terraform.tfvars` or `*.auto.tfvars` value settles it) and `enrich.unresolved_companion` (a companion resource whose target cannot be resolved, which holds back the findings that rest on its facts and fails `--strict`).
  It also says that an unparseable file that looks like a plan, template or manifest is an input error, that a plan-named file over 50 MB is an input error, and how the multiline secret rule and the templated-file argument behave.
- **The ATT&CK page explains the Navigator layer as it is drawn:** one entry per path step, with the tactic the step plays, and no longer says that a technique appears in every tactic ATT&CK lists for it.
  The rule-writing page documents the `_exposure` pseudo-property and the MCP agent node, and the ATT&CK page lists the four `BOUNDARY_*` kinds.
- **A new `CONTRIBUTING.md`** covers setup, the checks, tests, the generated documentation, golden recordings and the changelog.

### Fixed
- **`make lint` and CI checked only `src/` and `tests/`,** although `scripts/` has its own lint configuration.
  Both run `ruff check .` and `ruff format --check .` now.
- **`make clean` left `src/threatcode.egg-info` behind,** because its pattern only matched the top level.
- **The source distribution could not run its tests.**
  A new `MANIFEST.in` ships the tests with their fixtures and the documentation, examples and scripts they read, and the CI package job checks the archive.
  The suite expects a git checkout, so run `git init` in an unpacked sdist first; `CONTRIBUTING.md` says so.
- **`tomli` is a development dependency now.**
  The package never reads TOML, but it was installed for every Python 3.10 user.
  The tests that read `pyproject.toml` get it from the `dev` extra under the same `python_version<'3.11'` marker.
- **`scripts/check_golden_scope.py` told a package that a deleted recording was out of scope** when the globs were given unquoted, because the shell expands an unquoted glob into the files that exist now.
  The script's help and `CONTRIBUTING.md` say to quote them.
- **The Dockerfile parser tests passed only from the repository root;** they read their fixtures from the test file's directory now, and the working-directory gate lost one entry.
- **A permanently skipped test is gone.**
  The parametrization over expected findings that wait for a package was always empty; a test now fails if an `expected.yml` entry is marked pending.

### Internal
- `python-hcl2` stays `>=4.3,<9`; the 4.x reading is compensated in the adapter and CI tests both ends.
- Test comments no longer carry work-package ids.
- The golden recordings are unchanged.
