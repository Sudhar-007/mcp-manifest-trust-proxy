"""Tiny MCP client that talks to the proxy and prints what it sees.

It launches `python -m proxy` itself, so this one command starts the whole
chain:  demo_client -> proxy -> calc_server / email_server.

The proxy's wire log arrives on stderr and interleaves with this output.
Lines that start with `[direction]` are the proxy's log; everything else is
this client.
"""

import json
import sys
from pathlib import Path
from typing import Any

import anyio
import mcp_types as types
from mcp import ClientSession, StdioServerParameters, stdio_client

PROJECT_ROOT = Path(__file__).resolve().parent.parent


def banner(title: str) -> None:
    print(f"\n{'=' * 72}\n{title}\n{'=' * 72}")


def describe_params(schema: dict[str, Any]) -> list[str]:
    required = set(schema.get("required", []))
    lines = []
    for name, prop in schema.get("properties", {}).items():
        flag = "required" if name in required else "optional"
        lines.append(f"{name}: {prop.get('type', 'any')} ({flag})")
    return lines or ["(none)"]


def print_tool(tool: types.Tool) -> None:
    print(f"\n  tool: {tool.name}")
    print("  description (verbatim, one '|' per line):")
    for line in (tool.description or "(none)").splitlines():
        print(f"    | {line}")
    print("  parameters:")
    for line in describe_params(tool.input_schema):
        print(f"    - {line}")
    if tool.output_schema:
        print(f"  output schema: {json.dumps(tool.output_schema)}")


def print_result(result: types.CallToolResult) -> None:
    print(f"  isError: {result.is_error}")
    for block in result.content:
        if isinstance(block, types.TextContent):
            if "\n" in block.text:
                print("  content (text):")
                for line in block.text.splitlines():
                    print(f"    {line}")
            else:
                print(f"  content (text): {block.text}")
        else:
            print(f"  content ({block.type}): <non-text block>")
    if result.structured_content is not None:
        print(f"  structuredContent: {json.dumps(result.structured_content)}")


async def main() -> None:
    proxy = StdioServerParameters(command=sys.executable, args=["-m", "proxy"], cwd=PROJECT_ROOT)

    async with stdio_client(proxy) as (read, write):
        async with ClientSession(read, write) as session:
            banner("1. initialize -- handshake: agree on a protocol version, exchange names")
            init = await session.initialize()
            print(f"  connected to: {init.server_info.name} v{init.server_info.version}")
            print(f"  protocol version: {init.protocol_version}")

            banner("2. tools/list -- what the proxy tells the client it can call")
            listing = await session.list_tools()
            print(f"  {len(listing.tools)} tools")
            for tool in listing.tools:
                print_tool(tool)

            banner("3. tools/call -- calc__add(a=2, b=3)")
            print_result(await session.call_tool("calc__add", {"a": 2, "b": 3}))

            banner("4. tools/call -- calc__multiply(a=4, b=5)  (same server, different tool)")
            print_result(await session.call_tool("calc__multiply", {"a": 4, "b": 5}))

            banner("5. tools/call -- email__send_email(...)  (the other server)")
            print_result(
                await session.call_tool(
                    "email__send_email", {"to": "ops@example.com", "subject": "report", "body": "all good"}
                )
            )

            banner("6. tools/call -- docs__search_docs(query='expense policy')  (untrusted output)")
            print_result(await session.call_tool("docs__search_docs", {"query": "expense policy"}))

    banner("done -- proxy and upstream servers shut down")


if __name__ == "__main__":
    sys.stdout.reconfigure(line_buffering=True)  # keep our lines ordered with the proxy's stderr log
    anyio.run(main)
