### Changed
- **Each finding in the terminal report is a block that reads the same way every time.**
  The first line is the severity, the resource, the rule and the attack paths it enables.
  The second line is the finding, wrapped with a hanging indent when it is long.
  The third line, dim, holds where it is, its ATT&CK techniques and its STRIDE category in columns that line up from one finding to the next: `tfplan.json:484  T1552.005  EoP`.
  The header names the same lines in the same order (`FINDING`, then `LOCATION  ATT&CK  STRIDE` over the same columns), where it used to be one line of double-spaced words that the rows did not follow.
  A column that no finding fills is left out, and a location that is longer than its column wraps inside it while the techniques and the category stay where they are.
  On a terminal too narrow to line the columns up they flow in the same order, and `Info disclosure` is never broken between its words.
- **The rule moves under the resource, for the whole table, when the two do not fit side by side.**
  A long address such as `kubernetes_deployment.platform.storefront` was wrapped after a dot at 80 columns to leave room for the rule; now it stays whole on its own line and the rule and the attack paths follow under it.
  The layout is decided once from the widest cell of each column, so one table never mixes the two shapes.
  A rule id still keeps a line to itself before it is wrapped, and the paths take the next line when they cannot sit beside it.
- **A chart that lost templates says so in the verdict (RW-09).**
  `Verdict: incomplete (2 templates not analysed); in the rest: 5 medium, 9 low` replaces `5 medium, 9 low`, and a chart with nothing else to report reads `incomplete (1 template not analysed); in the rest: nothing found`, never `no findings`.
  The count is the number of templates that Helm render warnings name; a warning about the chart as a whole (a dependency that is not vendored) reads `Helm chart not fully analysed` when no template is named.
  A gap of level error is counted too.
  Gaps that only approximate (a chart rendered without helm) or that describe a module the scan was not asked to read (`hcl.module_call_skipped`) do not change the verdict; the coverage block lists them.
  A scan that already says `incomplete` or `no result` because of an input error keeps its own wording.
- **Path scores print with one decimal.**
  `score 9.0` is no longer `score 9` beside `score 9.2`.
- **The coverage block names the files no parser recognised.**
  `Coverage: 3 files discovered, 1 unit parsed` is followed by `Not infrastructure: expected.yml, scanner/trivy-app-image.json`.
  The first five are named and the rest counted (`and 27 more files`), and the count stays in the first line when only some of the names are shown.
- **A severity stays with its rule id when a line wraps.**
  `the worst being HIGH EC2_IMDSV1`, `enabled by` steps and the verdict's `worst critical` move to the next line as a unit, where `HIGH` was left at the end of one line and its rule at the start of the next.
- **A key under the findings is set apart by a blank line,** so it is read as a note on the table and not as a row.

### Fixed
- **A scanner finding that matched no resource reads `(unmatched)` in the RESOURCE column,** where it read `-`, the mark of a rule finding that names no resource.
- **A raised severity on a long severity word kept the columns apart.**
  `CRITICAL^` is nine characters in an eight character column and pushed its row one column to the right of the others.
  The severity column is as wide as its widest mark.
- **A gap whose message already begins with its file name is not given the file twice.**
  `[helm.fallback_render] Chart.yaml: Chart.yaml was rendered without helm` is now `[helm.fallback_render] Chart.yaml was rendered without helm`.
  A gap with a line keeps `file:line:` in front, because that is the part an editor jumps to.
- **A table too narrow for its widest rule id and its attack paths no longer wraps the rule id.**
  The paths take a line of their own, because the rule id is a key that is copied whole.
- **A line number is never left alone at the start of a line.**
  A location that was one or two characters wider than its column could wrap as `0000000000000000000:` over `1`, and a name too long for a line could be cut right before its number.
  The piece that carries the number now always carries at least one character of the file name before it, in the table and anywhere else a `file:line` is wrapped.
  A location in a column of its own wraps after its slashes only (`src/app/` over `handler.py:12`), so a directory or a file name is not cut when it fits.
  When the column would have to cut a name to line up, as with a file name that has no slash in it, the techniques and the category flow beside the location in the same order instead.

### Internal
- `formatters/terminal_table.py` holds the findings table (rows, layout, header and blocks), `formatters/terminal_verdict.py` the Helm-aware verdict, and `formatters/terminal_layout.py` gains `columns()`, `wrap_path()` and the `TIE` that joins two words across a wrap.
- The golden recordings are unchanged.
- The generated blocks in `README.md`, `docs/getting-started.md` and the three example READMEs embed the text report, so `python scripts/gen_docs_counts.py --write` has to run once this is merged.
