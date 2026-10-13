### Fixed

#### Markdown, SARIF and the GitHub Action

- **Markdown "enabled by" lines name boundary findings by their rule.**
  A trust boundary finding was labelled `boundary` (its source) under each attack path hop.
  It now reads `BOUNDARY_GENERIC_FLOW`, the id the suppressions file accepts, through the same label the terminal report uses.
  The SVG diagram's enabler captions use the same label.
- **SARIF attack path hops say what the edge does.**
  A hop read `aws_lb.web -> aws_instance.app (network_flow tcp/8080)`.
  It now reads `(sends traffic on tcp 8080)`, the wording the diagram and the Markdown report use.
- **A web address in Markdown is a code span, not text with an invisible character.**
  `md_inline` used to put a zero-width joiner inside `://` to keep GitHub from linking an address, which broke a copied address.
  An address is now an inline code span, which GitHub does not link and which copies exactly, with trailing punctuation left outside it.
  An `@mention` or issue number inside an address stays as written.
  This affects the Markdown report, the diff report and the Markdown in SARIF rule help and LLM results.
  The joiner after `@` and before an issue number remains.
- **The Action names the report file from the format registry.**
  The extension table in the action script is gone: the extension comes from the same registry as `-o` format inference, so a format added later cannot be saved under the wrong name.
  `format: mermaid` writes `threatcode-results.mmd`, and the deprecated `matrix` alias still writes JSON.
  The `format` input lists the real formats (navigator and mermaid, not matrix); the input names `extra-rules` and `config-file` are unchanged.

#### The SVG diagram

- **Connectors keep clear of frame labels.**
  The router now knows where each frame's label and each node's badge sit and moves the port of a framed node, and the vertical run through a column gap, out from under them while the room allows.
  When a frame has no free spot left, its label gives up its zone part (`aws_subnet.public_a`, not `aws_subnet.public_a (dmz)`) and then loses characters from the middle, instead of hiding a line behind it.
  The full name stays in the frame's tooltip.
  No connector runs through any frame label of the three examples or of the realistic fixtures that have frames; before, `aws-webapp` had four labels with a line behind them.
- **The findings table is in the text report's order.**
  Worst first, then the findings that enable an attack path, then by resource and rule, so the rows of the SVG, the terminal report and the Markdown report read the same way.
  The grouping by root cause and the "N rows after grouping" heading were already shared.
