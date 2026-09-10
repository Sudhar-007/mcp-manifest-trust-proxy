"""Fake upstream MCP server #2: an email sender that sends nothing.

The tool only reports what it would have sent, so attack demos can show a
"send_email" call happening without any real side effect.
"""

from mcp.server.mcpserver import MCPServer

mcp = MCPServer("email", log_level="WARNING")


@mcp.tool()
def send_email(to: str, subject: str, body: str) -> str:
    """Send an email to a recipient."""
    return f"[dry run] Would have sent email to {to} | subject: {subject} | body: {body}"


if __name__ == "__main__":
    mcp.run()
