### Fixed
- **SARIF and Bitbucket name files from the repository root, wherever the scan was started.**
  Before, paths were relative to the current directory, so `cd examples && threatcode scan aws-webapp -f sarif` wrote `aws-webapp/tfplan.json` and GitHub could not place the alert.
  The repository root is now the git top level above the scan root (`.git` as a directory or as a file, so worktrees work), and the same scan from the repository root, from a subdirectory and from the scanned directory writes `examples/aws-webapp/tfplan.json`.
  A scan root that is in no checkout and not below the current directory is reported as a `sarif.paths.unanchored` notification, and a file outside the repository as `sarif.paths.outside_repository`, because GitHub cannot place either.
  Such a file is named by its file name alone and never with `..`, and no absolute path of the machine reaches the report.
  `originalUriBaseIds` is deliberately not written, because it would put the path of the build machine into the document, and GitHub resolves `%SRCROOT%` itself.
  The Bitbucket report mentions files it could not place in `report.details`.
- **GitHub ranks an alert by its rule's severity, so a rule now has one severity.**
  Before, `K8S_AUTOMOUNT_SA_TOKEN` was one rule at `warning` with results at `note` and `warning`, and the Security tab showed a low finding as medium.
  A finding whose effective severity differs from its rule's belongs to a variant rule, `<id>/<severity>` (for example `EC2_IMDSV1/high` beside `EC2_IMDSV1`), with the level and `security-severity` of that severity.
  The bare id keeps the findings at the rule's reference severity, the highest base severity it has, so an alert that context did not change keeps its id from run to run.
  Alerts that context raised or lowered move to the variant id once, and GitHub shows them as new alerts.
  The one case where a bare id can still move is a rule whose instances have different base severities in one scan, which only a trust boundary crossing does (an encrypted and authenticated flow is one level lower): when the instances at the highest base severity are fixed, the remaining ones become the reference and change id once.
  Attack paths follow the same rule: `THREATCODE_ATTACK_PATH` is a critical path and `THREATCODE_ATTACK_PATH/high`, `/medium` and so on are the others.
  Every result also carries its own `properties.security-severity`, which is the same value as its rule's.
- **The rule id `trivy:trivy:CVE-2022-37434` is `trivy:CVE-2022-37434`.**
  The ingest readers already prefix the id with the tool, and the formatter prefixed it again.
  Rule names no longer repeat the title in PascalCase (`CVE202237434ZlibHeapBasedBufferOverRead...`, 99 characters).
  The name is made from the id: an advisory id is its own name (`CVE-2022-37434`), any other becomes words (`K8S_NO_SECCOMP_PROFILE` is `K8SNoSeccompProfile`), and a long one is cut at a word, at 64 characters.
- **A SARIF result message is one sentence about the instance.**
  It was the title, the STRIDE category, the resource and the whole rule description, up to 879 characters, repeated in every alert and in `fullDescription`.
  It is now `<title> on <address>`, for example `EC2 instance metadata service allows IMDSv1 on aws_instance.app[0]`.
  A trust boundary crossing, a scanner finding, a secret and a model finding add the first sentence of their description, because that sentence is about the instance.
  The explanation that is the same for every instance stays in the rule's `fullDescription` and `help`, which GitHub shows once.
  The message of an attack path is its route and where it enters; the rationale moved to the code flow.
- **SARIF attack paths are anchored where the fix goes and every hop has a file.**
  The result was anchored at the target (the bucket), and `Hop 1: internet` had no physical location, so GitHub's code-flow view dropped it.
  The result is now anchored at the first resource of the path that has a file, for example the load balancer.
  A hop with no file of its own (the internet) is shown at the resource it enters and says so, and the hop messages name the ports of the flow and the rule ids of the findings that enable the hop, for example `Hop 3: aws_instance.app[0] -> aws_iam_instance_profile.app (iam_binding); enabled by EC2_IMDSV1/high`.
- **Navigator layer: a technique is drawn once per path step.**
  `T1078.004` was drawn in four tactic columns at 100 with no findings, because the attack path lists every tactic of every technique it uses.
  The entry step is now initial access, and a later step takes the tactic that moves the attacker closest to the target (privilege escalation for a role assumption).
  A finding that names its tactic keeps it.
  The gradient has five stops that are the five legend colors at 0, 25, 50, 75 and 100, so a score of 25 is the Low blue and not a gray-yellow.
  The description no longer ends a sentence twice (`scan of .. 14 threats`), names `.` as the current directory, uses the singular for one, and counts only the threats that name a technique.
- **Bitbucket: `report.result` can follow the gate, and annotations are short.**
  The result was `FAILED` for any high or critical finding even with `--fail-on none`.
  `format_bitbucket(fail_on=...)` and `RenderOptions(fail_on=...)` make it `FAILED` when a finding or attack path at or above the gate remains (model findings never count), and the default gate is `high`.
  The command line passes the gate to the formatter once `cli.py` sets `RenderOptions.fail_on`; until then `threatcode scan -f bitbucket` keeps the default gate, `high`, whatever `--fail-on` says.
  An annotation was 600 to 1047 characters of generic rule text.
  It is now the resource, the first sentence for findings that are about the instance, the reason for the severity and a mitigation cut at 300 characters.
  `annotations` and `annotation_batches` still carry the same annotations twice, on purpose: one is for a client that posts one report, the other for the bulk endpoint, which takes at most 100.
- **A SARIF run says what it left out and what it was joined to.**
  Findings and attack paths removed by `.threatcodeignore` (`suppressions.applied`), by the baseline (`baseline.applied`) or by `--min-severity` (`min_severity.hidden`, which the gate still counted) are counted in note-level notifications, so a smaller report never reads as a safer one.
  Each ingested scanner result is an `ingest.source` notification (tool, file, findings, how many attached to a resource and how many did not), and a finished LLM phase is an `llm.ran` notification that says its findings are advisory.
  None of them fails the invocation.
- **The GitHub Action.**
  The `format` input lists the formats the CLI advertises (`sarif, json, markdown, bitbucket, navigator, mermaid, diagram, text`), and a test keeps the list equal to the registry.
  A Mermaid report was saved as `threatcode-results.json`; it is now `threatcode-results.mmd`.
  The sticky comment is found by the marker anywhere in its body, not only at its start, because the Markdown report carries the marker on its second line.
  CI checks that the SARIF the action writes names files from the repository root.
  A new `code-scanning` job uploads the SARIF of `examples/aws-webapp` to this repository on pushes to `main`, the only run of the `upload: true` path.

### Added
- `threatcode.formatters.RepoPaths`, `find_repo_root`, `format_for_extension`, `extension_mismatch`, `deprecation_notice` and `visible_format_names`.
  `format_for_extension("results.sarif")` is `"sarif"`, `"report.md"` is `"markdown"`, `"flow.mmd"` is `"mermaid"`, `"map.svg"` is `"diagram"` and `"x.json"` is `"json"`.
  `extension_mismatch("json", "results.sarif")` returns the warning to print when the format written does not fit the file name.
- `RenderOptions.repo_root` and `RenderOptions.fail_on`, and the `repo_root` and `fail_on` arguments of `format_sarif` and `format_bitbucket`.

### Changed
- Rendering `matrix` logs `-f matrix is deprecated, use -f navigator` on the `threatcode` logger, which the CLI shows on stderr unless `--quiet` is set.
  The alias still renders the same layer as `navigator`, and `visible_format_names()` leaves it out.
- The golden recordings are unchanged: no golden covers a formatter.
  The Navigator sample in `docs/mitre-attack.md` and the format list in `docs/cicd.md` are generated from the code, and were regenerated.
