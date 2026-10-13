# Contributing

Thank you for helping.
This page says how to set up, which checks a change has to pass, and the few conventions that keep the repository coherent.
To report a vulnerability, follow [SECURITY.md](SECURITY.md) and do not open a public issue.

## Set up

ThreatCode needs Python 3.10 or newer.

```bash
git clone https://github.com/ajokunu/ThreatCode.git
cd ThreatCode
python3 -m venv .venv
.venv/bin/pip install -e ".[dev,llm]"
```

Install `.[docs]` as well to build the documentation.
After a change to the version or the dependencies, run the install again, because the installed metadata is read by a test.

## Checks

| Command | What it runs |
|---------|--------------|
| `make lint` | `ruff check .` and `ruff format --check .` over the whole repository, scripts included |
| `make typecheck` | `mypy --strict` over `src/threatcode` |
| `make test` | the full test suite with coverage |
| `make docs-check` | `mkdocs build --strict` |
| `make smoke` | builds the wheel and scans an example with it in a clean environment |
| `make ci` | all of the above and the dependency audit |

`make format` fixes what the formatter and the safe lint fixes can.
A failure that the change did not cause is still a failure: fix it, or say in the pull request why it is not yours.

## Tests

- Write a test that fails without your change, and a negative test for the case that must stay quiet.
- Open fixtures from `Path(__file__).parent`, never from a path relative to the working directory, so the suite passes from any directory.
- A rule needs a bad and a good example under `tests/test_rules/cases/<group>/`, or an entry in `tests/test_rules/uncovered/<group>.txt` that says it has none yet (`tests/test_rules/README.md` has the layout).
- Run a part of the suite while you work, for example `pytest tests/test_parsers -q`, and the whole suite before you push.

The suite expects to run inside a git checkout, because the SARIF and Bitbucket paths are relative to the repository root.
To run it from an unpacked source distribution, run `git init` in the unpacked directory first.

## Documentation

The pages under `docs/` and the README are tested.
A block marked `<!-- runnable -->` is run, every `threatcode` command is parsed by the real CLI, and the counts, option tables and example reports are generated from the code:

```bash
python scripts/gen_docs_counts.py --write   # after a change to a rule, a format, an option or a parser
python scripts/gen_docs_counts.py --check   # what CI runs
```

Write one sentence per line, use a plain hyphen and no emoji, and say only what the code does.
Where a page and the code disagree, the code is right and the page is the bug.

## Golden recordings

`tests/fixtures/golden/` holds one directory per input with the graph, the findings and the model the build produces for it.
A change that moves a recording on purpose re-records it and explains each difference in the changelog entry:

```bash
THREATCODE_UPDATE_GOLDEN=1 pytest tests/test_ir/test_golden.py
python scripts/check_golden_scope.py --allow 'tests/fixtures/golden/*/findings/aws__s3.json'
```

The second command fails when a recording outside the globs you name has changed.
Quote the globs, so the shell does not expand them.

## Changelog

Add a line for every change a user can see under `[Unreleased]` in `CHANGELOG.md`, in the style of the entries around it, and keep one sentence per line.
`docs/releasing.md` says what happens to that section at release time.

## Commits

Use conventional messages (`fix(parsers): ...`, `docs: ...`), keep a commit to one change, and do not add co-author trailers.
