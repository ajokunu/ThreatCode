### Fixed

#### The SVG diagram (`-f diagram`)

- **Attack paths are the one emphasised thing on the diagram.**
  Every connector that crossed a trust zone used to be drawn as a thick red line with a glow, so a path hop, a boundary crossing and a Terraform reference looked the same, and 19 connectors of `examples/aws-webapp` glowed.
  The hops of an attack path are now thick, glow, and take the color of the worst path over them.
  A flow that crosses a trust boundary keeps the look of its type (blue dashed for traffic, green for data) and carries a zone label.
  A reference or an IAM binding that only spans two zones is a thin grey line with no label, because only traffic and data flows are crossings.
  A hop the graph has no connector for is drawn too, so every hop of every path is on the diagram.
- **Path numbers are `P1`, `P2`, not red circles.**
  The numbers sat in the same round badge as the severity count of a resource, and the legend explained only one of them.
  A path number is now an outlined square (`P1`, `P1 P3`, or `P1-P3` for a run), the legend has an entry for it, and the placement keeps it off nodes, severity badges, other labels and the line between two zones.
- **One zone label per transition.**
  `DMZ -> PRIVATE` appeared seven times in the AWS example.
  Each transition now has one label on the longest route that makes it, with the number of connectors (`DMZ -> PRIVATE x7`), and the tooltip lists them.
- **Every connector tooltip names both ends**, then lists what each merged edge says (`Network Flow: tcp/8080`), the crossing, and the attack paths and steps that use it.
- **Two edges between the same nodes are one connector.**
  A reference and an IAM binding between a role and its policy were drawn on the same coordinates and showed as one arrow with two tooltips.
  The stronger type decides how the connector looks and both appear in the tooltip.
- **Nodes that share a name say what they are.**
  The AWS example had four nodes labelled `app`, and the Kubernetes example three labelled `storefront`.
  A name that another drawn node shares takes the short type in front: `role.app`, `profile.app`, `sg.app`, `target_group.app`, `ingress/storefront`, `service/storefront`, `deployment/storefront`.
  Two namespaces with the same kind and name keep the namespace.
- **Type captions are not cut where the type is told apart.**
  They were 8px and cut after 22 characters (`aws_lb_target_gro...`).
  They are 9px, the box is 176 pixels wide, and a caption over 31 characters is cut in the middle so both ends stay.
  The name line is cut in the middle too.
- **A data store's settings are folded into it.**
  `aws_s3_bucket_public_access_block` and `aws_s3_bucket_server_side_encryption_configuration` were two more cylinders labelled like the bucket.
  A data store whose type extends the type of the data store it references now shares that node, its findings count on the badge, and the tooltip lists them.
- **The legend matches the shapes.**
  The legend promised a diamond for data flows and the diagram drew diamonds for security groups, route tables and the internet.
  Network and delivery components (network, cdn, dns, messaging) are boxes with a dashed outline, the internet is an external entity, and the legend shows both.
  The legend has four columns and an entry for attack path hops, path numbers and boundary crossings.
- **Attack path strips say everything the path says.**
  The rationale is wrapped to up to three lines (it was one clipped line), each box holds the full address (`kubernetes_ingress.platform.storefront`), and each hop lists every finding that enables it with its rule id and title, up to three and then a count.
  A finding that enables two hops in a row is listed under the first.
  ATT&CK ids sit under their hop, which also annotates the IAM hops.
  Arrows between hops say `HTTPS 443`, `assumes`, `invokes` and `can read` where they said `network`, `iam` and `data`.
  The full list for a hop is in its tooltip, and the height of a strip follows what it holds.
- **The findings table groups, cuts at a sentence, and says where.**
  Findings that share a root cause on one resource are one row (`Container without a seccomp profile (+2 related: container hardening)`), as in the terminal report.
  The description is the first sentence of the rule's text, up to four lines, and the edge type tokens read as words (`network traffic`).
  A new Location column gives `file:line`, and a long address or path is cut in the middle.
  An address breaks where its type ends, so `aws_secretsmanager_secret.db_credentials` no longer wraps as `...secret.db_` and `credentials`.
- **Text is readable.**
  Zone titles were the pastel of the zone border on the zone fill, with a contrast between 1.3 and 1.7.
  They are a dark variant of the hue now.
  Severity text, the grey type captions, the source column, the legend notes and the summary pills all reach 4.5 to 1, and a badge is white on red and blue and dark on orange, yellow and grey.
  A test measures the contrast of every text of the three examples against what it is drawn on.
- **Frames say which part they are, and no line strikes through a label.**
  A VPC with members in three zones drew three frames that all said `aws_vpc.main`.
  They say `aws_vpc.main (internet)`, `(dmz)` and `(private)`.
  Labels are drawn above the connectors on a backing, and each one slides along the top of its frame to the first spot no connector crosses.
  A label that a connector still crosses had no clear spot anywhere on its frame, and a test checks that.
- **The ids of one diagram differ from the ids of another.**
  Every scan of the current directory gave the id prefix `tc3a52ce78`, so two reports in one HTML page collided.
  The prefix is a hash of the input name, the resources, the findings and the paths, and it does not change with the time of the scan.
- **Wide attack paths widen the lanes.**
  The nodes of a lane use the width of the canvas (at most eight columns) instead of five columns on the left.

#### Mermaid (`-f mermaid` and the chart in the Markdown report)

- **The charts run top to bottom.**
  `flowchart TB` draws `examples/aws-webapp` 919 pixels wide, where `flowchart LR` drew it 3213 pixels wide in one row.
- **Edge labels are words.**
  `network_flow 443`, `iam_binding invokes` and `data_flow returns_content` are `HTTPS 443`, `invokes` and `returns content`.
  Edges between the same two resources share one arrow with their labels joined, and two edges that run in opposite directions are one arrow with a head at each end, so labels no longer sit on top of each other.
- **An alternative instance is drawn as one.**
  The path report said that a route through `app[1]` exists, and the chart drew `app[1]` like any other node.
  Another instance of a counted resource that a path runs through now has a dashed red outline and dashed red connectors.
- **Long addresses keep their resource name.**
  A scan of a template repository gave `python3.10/step-func-conn/{{cookiecutter.project_name}}/t...` for dozens of different nodes.
  A path segment that every address shares is replaced by `...`, whole middle segments go before characters do, and the end is kept, so the nodes read `python3.10/step-func-conn/.../template.yaml::StockBuyerFunction`.
- **The embedded chart says what it is.**
  The chart in the Markdown report draws the hops of the attack paths only, and the full `mermaid` format draws every resource an attacker can act through.
  A comment line in the chart and a line above it in the report say so.

#### Markdown report

- **Attack path hops say what they do.**
  `then network_flow on 443 to the next hop` is `then sends traffic on HTTPS 443`, and `then iam_binding to the next hop` is `then assumes the role`.
- **Shared hops are listed once.**
  A path that starts with hops an earlier path lists says `Hops 1 to 4 are the same as in path 1` and numbers its own hops from there.
  A finding that enables two hops in a row is listed under the first one.
- **The section with the worst finding comes first.**
  The findings were in STRIDE order, so the only critical finding of a scan was in the last section.
  Sections are ordered by their worst effective severity, then by STRIDE order.
- **Headings are shorter and group titles start with a capital.**
  A heading drops the resource when the title already names it (`Trust boundary crossing: a (dmz) -> b (private)`), and `container hardening (3 findings)` is `Container hardening (3 findings)`.
- **The severity explanation is one clause.**
  `Medium (base low: raised one level: the data store is tagged ...)` is `Medium (base low, raised one level because the data store is tagged ...)`.
  The reason is no longer cut in the middle of a route.
- **A URL in running text is a code span.**
  The report put an invisible zero-width joiner inside `://` to keep a bare address from becoming a link, and `http://169.254.169.254` could not be copied into a terminal.
  A URL now sits in a code span, which is inert and copies exactly.
  Mentions and issue references still get the joiner.
- **Descriptions read in words.**
  `(network_flow)` in the text of a finding reads `(network traffic)`.

### Changed

- The diagram's `NODE_W` is 176 (it was 160), a diagram is at least 968 pixels wide (it was 900), and the findings table has a Location column.

### Internal

- `formatters/diagram_labels.py` is the one place that says an edge in words, shortens an address, and lists the findings that enable each hop.
  The diagram, the Mermaid charts and the Markdown report use it.
