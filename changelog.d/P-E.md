### Changed
- **The version is 1.0.0.**
  `threatcode --version` and the `version` field of a report now tell the reworked line from 0.9.1, which stays the release on PyPI until the first release of this line is published.
  `CHANGELOG.md` keeps its Unreleased heading until then, and `docs/releasing.md` says what to move at release time.
- **The config keys are `format` and `rules`,** the names of the `--format` and `--rules` flags.
  `output_format` and `extra_rule_paths` still load and print a notice that names the new spelling, and giving both spellings of one key is an error.
  An auto-discovered `.threatcode.yml` may set `format`, as it could set `output_format`, and still cannot set `rules` or `extra_rule_paths`.
  `docs/configuration.md` has one table of the name each setting has as a flag, an environment variable, a config key, an Action input and a `scan()` argument.
- **`threatcode diff` lists findings in the order of the report:** severity, resource address, rule id and id.
  The two instances of a finding on `aws_instance.app[0]` and `aws_instance.app[1]` used to swap places with the fingerprint.
  The text format also pads the severity and resource columns, so every title starts in one column.

### Fixed
- **The first command in the README and in the getting-started page ran only from a clone.**
  The demo stacks in `examples/` are not in the pip package, so `threatcode scan examples/aws-webapp` failed with `path not found` after the documented install.
  Both pages now clone the repository, install from it and run the command from its top directory, and say that the demo stacks come with the clone.
  A test fails when the first demo scan comes before the clone.
- **Six pages said an attack path cannot be suppressed or baselined, which stopped being true.**
  The README, the CLI reference, the getting-started page, the CI page, the security model and the changelog now describe what `--write-baseline`, `--baseline` and `.threatcodeignore` do with attack paths, and a test fails when the old wording comes back.
  A second test baselines the demo stack, checks that the baseline hides every path, removes one recorded path and checks that the scan exits 1 again.
- **The generated options table listed `--version` twice,** once from the command group and once from a hand-written row.
  A test fails when any generated option table repeats an option.
- **The `allow_local_network` error named two providers where three are allowed.**
  It is built from the allowed set now: `requires provider 'ollama' or 'local' (or 'anthropic' behind a gateway)`.
- **The pre-commit example pinned `v0.9.1`, a release that predates the hook,** while the CI page pinned `main`.
  Both say `main` until the first release of this line is tagged, and a test fails when they differ.
- **The changelog fragment left behind by the quality-gates package is folded into `CHANGELOG.md`** and deleted, and a test fails when a work-package id or a fragment path appears in the changelog.

### Internal
- `ThreatReport.duplicate_ids()` returns the ids that more than one threat carries, `threatcode.scan()` and `analyze()` log a warning when it is not empty, and a test checks that the three demo stacks report none.
- `tests/test_meta.py` fails the build when `__version__` is a number that `CHANGELOG.md` already released, when a test opens `Path("tests/...")` relative to the working directory, and when a function, method or class in `src` is never referenced.
  The last two keep a list of the known offenders, so a new one fails and a fixed one has to leave the list.
- The runnable blocks of the documentation get their own `python` and `python3`, so `tests/test_docs.py` passes where only `python3` exists and without a virtual environment on `PATH`.
- The golden recordings are unchanged.
