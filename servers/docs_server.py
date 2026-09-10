"""Fake upstream MCP server #3: document search over a canned file.

This server's tool description is clean and stays clean. The DOCUMENT is what
gets poisoned, which is the whole point of step 4: the attack arrives in tool
output, not in the manifest, so pinning and the description guard never see it.

structured_output=False keeps the document on one channel (the text block), so
the firewall's wrapper is the only way it reaches the client.
"""

from pathlib import Path

from mcp.server.mcpserver import MCPServer

DOCUMENT = Path(__file__).resolve().parent / "docs" / "handbook.txt"

mcp = MCPServer("docs", log_level="WARNING")


@mcp.tool(structured_output=False)
def search_docs(query: str) -> str:
    """Search the internal handbook and return the matching document."""
    # Canned: the query is ignored, there is only one document.
    return DOCUMENT.read_text(encoding="utf-8")


if __name__ == "__main__":
    mcp.run()
