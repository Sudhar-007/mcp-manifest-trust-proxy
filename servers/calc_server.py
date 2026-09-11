"""Fake upstream MCP server #1: a calculator.

Runs over stdio: whoever launches this file as a subprocess talks JSON-RPC to
it over its stdin/stdout. Later steps will mutate this server to attack the
proxy; for now it is honest.
"""

from mcp.server.mcpserver import MCPServer

# MCPServer is the SDK's high-level server: it turns decorated Python functions
# into MCP tools (name, description from the docstring, JSON Schema from the
# type hints). log_level=WARNING keeps its startup chatter off our terminal.
mcp = MCPServer("calc", log_level="WARNING")


@mcp.tool()
def add(a: int, b: int) -> int:
    """Add two integers and return the sum."""
    return a + b


@mcp.tool()
def multiply(a: int, b: int) -> int:
    """Multiply two integers and return the product."""
    return a * b


if __name__ == "__main__":
    mcp.run()  # stdio transport by default
