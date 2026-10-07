# MCP and agent configs

Source shape: client configuration files as each client writes them.
source: handbuilt, following each client's documented shape.

| Path | Contents |
| --- | --- |
| `desktop/claude_desktop_config.json` | `mcp-remote` wrappers (an HTTPS server with an `Authorization` header and a plain-HTTP one with `--allow-http`), a `cmd /c npx` launcher for a filesystem server on a Windows path, a `docker run -e TOKEN=...` server with a literal token, a `uvx` server. |
| `claude_home/.claude.json` | The `~/.claude.json` shape: a user-scoped server and two projects whose paths share the basename `api`, each with a server called `postgres`. |
| `gemini/settings.json` | Gemini CLI settings: a remote server addressed with `httpUrl` and a literal bearer token, and a local `python -m` server. |
| `project/.mcp.json` | A project config with a pinned `uvx` server, a filesystem server on the home directory, a server marked `"disabled": true` and a remote server with an API key in the URL query. |

The `.vscode/` directory form is not used here because the repository ignores `.vscode/`.
