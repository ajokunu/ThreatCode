### Changed
- **The terminal report never cuts a name.**
  The RESOURCE, RULE and FINDING cells used to end in `...` or lose their middle (`aws_in...ce.app[0]`, `kubern...xporter`), so rows could not be told apart, and a rule id could not be pasted into `.threatcodeignore`.
  A cell that is wider than its column now wraps onto a further line, after a dot or a slash when there is one, so every resource address, rule id, file and line is printed whole at any width from 40 columns up.
  Each finding takes two lines: the severity, the resource, the rule and the attack paths it enables, then the finding with its file and line, its ATT&CK techniques and its STRIDE category.
  A column that would be empty is left out, and a technique list ends in a count (`T1548,T1611,T1105 +2`) instead of cutting an id in half.
- **Trust boundary findings are told apart.**
  Two crossings from `aws_lb.front` used to print as the same row because the part of the title that differs came last.
  A crossing now prints its kind in the RULE column (`BOUNDARY_GENERIC_FLOW`, `BOUNDARY_UNENCRYPTED_FLOW`, ...), which is also the id a suppression accepts, and its title leads with the zones and the other end: `Trust boundary crossing, dmz > private: to aws_instance.app[0] (tcp/8080)`.
  The engine's own title in the JSON report is unchanged.
- **The heading reconciles with the rows.**
  `Findings (30, 23 rows after grouping)` says that findings with one root cause on one resource share an entry.
  The entry lists the other rules in full on an `also` line, where the old table cut `(+2 related: ...)` away.
- **A severity changed by context is marked.**
  `HIGH^` was raised from the rule's own severity (`v` is lowered), and a key under the findings says so.
  A finding that enables an attack path carries the number of the path (`P1`, `P1,P2+1`) and sorts first inside its severity band.
- **Attack paths say why they exist.**
  The terminal report numbers the paths, gives the target kind, the length, the score and the worst enabling finding in one sentence, counts the equivalent routes through other instances, and lists for each step the findings that enable it by rule id and effective severity, with the port the step uses: `internet -> aws_lb.front on tcp/443: LOW SG_WEB_PORT_OPEN_TO_WORLD`.
  Up to three findings are named per step, then `+N more`, and findings that a filter or a baseline removed from the report are counted as `+N not shown`.
  The path id is labelled `ignore id`, because it is the key a `.threatcodeignore` entry or a baseline uses.
  A route that wraps always breaks before an arrow.
- **The verdict names what a path ends at and how bad the worst one is.**
  `2 attack paths from the internet to private` is now `2 attack paths from the internet to private data, worst high`, and the aws example reads `to data stores and secret stores, worst critical`, so a critical path is not hidden behind a verdict that counts only findings.
  The verdict is shared with the Markdown report.
- **A scan that failed never reads as clean.**
  With an input error the verdict says `no result (1 input error; nothing was analysed)` or `incomplete (1 input error); in the rest: ...`, never `no findings`.
  When a baseline accepted everything it says `no new findings (6 findings and 2 attack paths baselined)`, and when `--min-severity` hid everything it says what was hidden.
- **`--min-severity` says what it hid.**
  The header reads `0 of 12 findings shown`, the coverage block has a `Hidden: 12 findings and 2 attack paths below critical (--min-severity)` line, and the `Scanned` line on stderr repeats it.
  `Set aside` counts findings and attack paths apart (`6 findings and 2 attack paths baselined`), where it used to add them together.
- **Coverage gaps and input errors are said once.**
  With the text report on standard output stderr keeps one line for the gaps and the last line for the exit code, because the report already lists them; every other format, and `-o`, keeps the full list on stderr.
  A gap reported twice by a parser is counted and listed once (the JSON `coverage.gaps` too), and a file's many gaps of one code are one line with a count: `[hcl.unresolved_reference] modules/iam/iam.tf: 252 times, first at line 12: ...`.
  An input error no longer repeats the file name its message already carries.
- **Every nonzero exit says why, on the last line of stderr.**
  Exit 2 ends with `Error: scan incomplete (1 input error), exiting 2: <the first error>`, the line a CI step quotes.
  Exit 1 ends with `Gate failed: 5 findings and 3 attack paths at or above high (--fail-on high), exiting 1`, counted before `--min-severity` hid anything, so a report that shows `0 findings` can still explain exit 1.
- **Long lines wrap with a hanging indent.**
  The header, the verdict, the path header, gaps, errors and the messages on stderr wrap at the terminal width.
  On a terminal the width is the terminal's; into a pipe or a log stderr messages stay on one line, so a tool that reads the last line gets all of it.
  The report lays out down to 40 columns, where it used to assume 60.
- The `Scanned ... found ...` line on stderr is left out when the text report went to standard output, because the header says the same.
  It stays for every other format and for `-o`.

### Added
- `threatcode scan --include-graph` adds the graph (nodes and edges, no properties) to the JSON report.

### Fixed
- The header names what was scanned in every format.
  `ThreatCode scan of .` for a directory is now `ThreatCode scan of examples/aws-webapp`, and the same name is in the JSON `input_file`, the Markdown `Input` line, the SVG title, the Navigator description (which no longer ends `..`) and the error of an empty directory.
  This was fixed in the pipeline before this package; the package pins it with tests.
- Names from the scanned input are printed as visible escapes (`\x1b`), never as terminal control sequences, in the new path, verdict and coverage lines as in the table.
  The tests drive the whole report and stderr with an escape and a bell in a server key, a file name and an attack path.

### Internal
- `formatters/terminal_layout.py` holds the wrapping primitives (`split_token`, `wrap`, `hanging`, `flow`) and `formatters/terminal_coverage.py` the rules for listing gaps and errors, both pure and tested with hypothesis properties: no line is wider than the width and no character is lost.
- `formatters/_utils.py` gains `verdict_items`, `rule_label`, `set_aside_phrase` and `join_words`.
  A verdict is built from fixed words: a target kind or a zone the tables do not know is never echoed.
- The generated blocks in `README.md`, `docs/getting-started.md`, `docs/cli.md` and the example READMEs are regenerated for the new report.
- The golden recordings are unchanged.
