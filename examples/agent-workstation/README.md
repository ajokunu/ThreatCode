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

Verdict: 1 critical, 4 high, 1 medium, 2 attack paths from the internet to private data, worst high

Attack paths (2)
P1  HIGH      internet -> mcp_server.filesystem
    private data, 3 hops, score 7.5; 4 findings enable it, the worst being
    CRITICAL MCP_SECRET_IN_CONFIG.
    internet > mcp_server.team-tools > mcp_agent.config > mcp_server.filesystem
    enabled by:
      mcp_server.team-tools -> mcp_agent.config over http: CRITICAL MCP_SECRET_IN_CONFIG,
        HIGH MCP_PLAINTEXT_TRANSPORT
      mcp_agent.config -> mcp_server.filesystem over stdio: HIGH MCP_LETHAL_TRIFECTA
      mcp_server.filesystem: HIGH MCP_BROAD_FILESYSTEM
    ignore id: 09e365839d4b

P2  HIGH      internet -> mcp_server.filesystem
    private data, 3 hops, score 7.5; 3 findings enable it, the worst being
    HIGH MCP_BROAD_FILESYSTEM.
    internet > mcp_server.fetch > mcp_agent.config > mcp_server.filesystem
    enabled by:
      mcp_server.fetch -> mcp_agent.config over stdio: MEDIUM MCP_UNPINNED_PACKAGE
      mcp_agent.config -> mcp_server.filesystem over stdio: HIGH MCP_LETHAL_TRIFECTA
      mcp_server.filesystem: HIGH MCP_BROAD_FILESYSTEM
    ignore id: 84e870ec46f2

Findings (6)
SEVERITY  RESOURCE               RULE                       PATHS
          FINDING
          LOCATION      ATT&CK       STRIDE
CRITICAL  mcp_server.team-tools  MCP_SECRET_IN_CONFIG       P1
          Literal credential in MCP server configuration
          .mcp.json:11  T1552.001    Info disclosure
HIGH      mcp_agent.config       MCP_LETHAL_TRIFECTA        P1,P2
          Agent can read private data, ingest untrusted content and exfiltrate or act
          .mcp.json:2   T1567        Info disclosure
HIGH      mcp_server.filesystem  MCP_BROAD_FILESYSTEM       P1,P2
          MCP server given the whole disk or a home directory
          .mcp.json:7   T1005        EoP
HIGH      mcp_server.team-tools  MCP_PLAINTEXT_TRANSPORT    P1
          Remote MCP server over unencrypted HTTP
          .mcp.json:11  T1040,T1557  Info disclosure
HIGH      mcp_server.team-tools  BOUNDARY_UNENCRYPTED_FLOW
          Trust boundary crossing, internet > private: to mcp_agent.config (http), unencrypted
          .mcp.json:11  T1040        Info disclosure
MEDIUM    mcp_server.fetch       MCP_UNPINNED_PACKAGE       P2
          MCP server launched from an unpinned package or image
          .mcp.json:3   T1195.002    Tampering

Key: P1, P2: the attack paths above that the finding enables

Coverage: 2 files discovered, 1 unit parsed
  Not infrastructure: expected.yml
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
