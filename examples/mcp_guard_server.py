"""Guard an MCP server's tools with simdiff.

MCP (Model Context Protocol) is how most 2026 agents reach their tools. This is a
drop-in pattern: every tool you expose is wrapped so the agent's call is first
*simulated* by simdiff and decided over by a policy — only an ALLOW actually runs.
A BLOCK/NEEDS_APPROVAL never touches the real resource.

simdiff itself stays zero-dependency; this example needs the MCP SDK:

    pip install mcp

Run it as a normal MCP stdio server and point any MCP client (Claude Desktop,
your agent runtime, ...) at it:

    python examples/mcp_guard_server.py

Client config (one block):

    {
      "mcpServers": {
        "guarded-shell": { "command": "python", "args": ["examples/mcp_guard_server.py"] }
      }
    }
"""

from __future__ import annotations

import subprocess

from mcp.server.fastmcp import FastMCP  # pip install mcp

from simdiff.guard import Guard, Decision
from simdiff.adapters.shell import ShellAdapter
from simdiff.adapters.http import HttpAdapter, HttpRequest

# --- deployment policy: what exists, what egress is allowed ------------------
KNOWN_FILES = {"/tmp/scratch.txt", "/data/prod.db"}
ALLOWED_HOSTS = {"api.internal"}

guard = Guard({
    "shell": lambda a: (a["command"], ShellAdapter(existing=KNOWN_FILES)),
    "http": lambda a: (HttpRequest(a.get("method", "GET"), a["url"], body=a.get("body", "")),
                       HttpAdapter(allowed_hosts=ALLOWED_HOSTS, sensitive_markers={"BEGIN PRIVATE KEY"})),
})

mcp = FastMCP("guarded-tools")


def _gate(tool: str, args: dict) -> str | None:
    """Return a refusal string if the effect isn't allowed, else None."""
    result = guard.evaluate(tool, args)
    if result.decision is Decision.ALLOW:
        return None
    effect = result.delta.to_dict()
    return f"{result.decision.value} by simdiff — effect not permitted: {effect}"


@mcp.tool()
def run_shell(command: str) -> str:
    """Run a shell command — but only if its simulated effect is allowed."""
    refusal = _gate("shell", {"command": command})
    if refusal:
        return refusal
    return subprocess.run(command, shell=True, capture_output=True, text=True).stdout


@mcp.tool()
def http_request(url: str, method: str = "GET", body: str = "") -> str:
    """Make an HTTP request — blocked if it would exfiltrate to a non-allowed host."""
    refusal = _gate("http", {"url": url, "method": method, "body": body})
    if refusal:
        return refusal
    # ... your real HTTP client here ...
    return f"(would send {method} {url})"


if __name__ == "__main__":
    mcp.run()
