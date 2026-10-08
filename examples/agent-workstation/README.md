# agent-workstation

The MCP configuration of a coding agent, with all three legs of the lethal trifecta in one agent: it can read private data, ingest untrusted content, and act on the outside.

`.mcp.json` configures three servers:

| Server | What it gives the agent |
|--------|-------------------------|
| `filesystem` | Read access to `/Users/dev`, the whole home directory. |
| `fetch` | Web content, written by anyone, started with `uvx mcp-server-fetch` and no version pin. |
| `team-tools` | A remote server over plain `http`, with a literal bearer token in the `Authorization` header. |

ThreatCode reads the config offline and never starts or contacts a server.
It models the agent as one node that holds the union of what its servers can do, and follows content from the servers that ingest untrusted input, through the agent, to the servers that read private data.

## Scan the config

<!-- runnable exit=1 -->

```bash
threatcode scan examples/agent-workstation
```

<!-- gen:report -->
```text
ThreatCode scan of examples/agent-workstation: 4 resources, 6 findings

Verdict: 1 critical, 4 high, 1 medium, 2 attack paths from the internet to private

Attack paths (2)
HIGH      internet -> mcp_server.filesystem  (3 hops, id 09e365839d4b)
          internet > mcp_server.team-tools > mcp_agent.config > mcp_server.filesystem
HIGH      internet -> mcp_server.filesystem  (3 hops, id 84e870ec46f2)
          internet > mcp_server.fetch > mcp_agent.config > mcp_server.filesystem

Findings (6)
SEVERITY  RESOURCE             RULE                     FINDING                         LOCATION
CRITICAL  mcp_ser...eam-tools  MCP_SECRET_IN_CONFIG     Literal credential in MCP s...  .mcp.json:11
HIGH      mcp_agent.config     MCP_LETHAL_TRIFECTA      Agent can read private data...  .mcp.json:2
HIGH      mcp_ser...ilesystem  MCP_BROAD_FILESYSTEM     MCP server given the whole...   .mcp.json:7
HIGH      mcp_ser...eam-tools  boundary                 Trust boundary crossing: mc...  .mcp.json:11
HIGH      mcp_ser...eam-tools  MCP_PLAINTEXT_TRANSPORT  Remote MCP server over unen...  .mcp.json:11
MEDIUM    mcp_server.fetch     MCP_UNPINNED_PACKAGE     MCP server launched from an...  .mcp.json:3

Coverage: 2 files discovered, 1 unit parsed, 1 not infrastructure
  No input errors or coverage gaps were recorded.
```
<!-- /gen:report -->

The attack paths:

<!-- gen:paths -->
1. **high**, 3 hops, id `09e365839d4b`: `internet` -> `mcp_server.team-tools` -> `mcp_agent.config` -> `mcp_server.filesystem`
   ATT&CK techniques: T1659, T1005.
2. **high**, 3 hops, id `84e870ec46f2`: `internet` -> `mcp_server.fetch` -> `mcp_agent.config` -> `mcp_server.filesystem`
   ATT&CK techniques: T1659, T1005.
<!-- /gen:paths -->

Both paths end at the filesystem server.
Web content fetched by the agent can instruct it to read the home directory, and the remote server, reached over plain http with a literal token, sits in the same agent.
The findings explain the hops: `MCP_LETHAL_TRIFECTA` on the agent, `MCP_BROAD_FILESYSTEM`, `MCP_PLAINTEXT_TRANSPORT` and `MCP_SECRET_IN_CONFIG` on the remote server, and `MCP_UNPINNED_PACKAGE` on `fetch`.
The token's value is never copied into the report, in any format.

Fix them in `.mcp.json` and scan again: pin the fetch server, root the filesystem server at a project directory instead of the home directory, use `https`, and move the token to an environment reference.
