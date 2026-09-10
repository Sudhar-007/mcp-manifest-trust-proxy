"""MCP trust proxy (step 3: manifest pinning, drift detection, description guard).

One process, two roles:
  - downstream: an MCP *server* on our own stdin/stdout, facing the client.
  - upstream:   one MCP *client* session per configured server, each talking
                to that server's subprocess over its stdin/stdout.

On connect and on every client tools/list we do two independent things:
  1. check_drift against the signed pin in trust.db (step 2)
  2. run both description detectors over every live description (step 3)
A tool flagged by either one is hidden from the client and refused on
tools/call. Everything else keeps working.

Our stdout IS the protocol wire to the client, so every log line goes to
stderr. Printing anything to stdout would corrupt the JSON-RPC stream.
"""

from __future__ import annotations

import json
import os
import sys
from contextlib import AsyncExitStack
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import anyio
import httpx2
import mcp_types as types
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from mcp import ClientSession, MCPError, StdioServerParameters, stdio_client
from mcp.server import Server
from mcp.server.stdio import stdio_server
from mcp.shared.message import SessionMessage
from mcp_types.jsonrpc import JSONRPCNotification, JSONRPCRequest, JSONRPCResponse

from . import keys
from .classify import classify_change
from .detect import agent_directed_imperatives, cross_server_refs
from .drift import STATUS_FOR_CHANGE, DriftReport, ToolChange, check_drift
from .firewall import describe as describe_finding
from .firewall import scan_output, wrap_untrusted
from .store import TrustStore

PROJECT_ROOT = Path(__file__).resolve().parent.parent
CONFIG_PATH = Path(__file__).resolve().parent / "config.json"
NAMESPACE_SEP = "__"
LOG_PREVIEW_CHARS = 400

# The console is optional. If it is not running, the push is skipped and the
# proxy carries on: nothing here may ever break the protocol path.
CONSOLE_URL = os.environ.get("MCP_TRUST_CONSOLE", "http://127.0.0.1:8765")
CONSOLE_PUSH_TIMEOUT = 0.4  # localhost; long enough to send, short enough not to stall a console-less run

REFUSAL_REASONS = {
    "modified": "it is suspended because its definition changed after it was approved. "
    "Re-approval is required before it can be called.",
    "removed": "it is suspended because the server removed it after it was approved. "
    "Re-approval is required before it can be called.",
    "added": "the server added it after approval and it has never been approved. "
    "Approval is required before it can be called.",
    "tampered": "the trust store record for its server failed verification. "
    "Re-approval is required before it can be called.",
}


# --------------------------------------------------------------------------
# Wire logging
# --------------------------------------------------------------------------


def log(direction: str, text: str) -> None:
    print(f"[{direction:<15}] {text}", file=sys.stderr, flush=True)


def describe(item: SessionMessage | Exception) -> str:
    """One log line for one JSON-RPC message, as it looks on the wire."""
    if isinstance(item, Exception):
        return f"TRANSPORT ERROR {item!r}"
    msg = item.message
    if isinstance(msg, JSONRPCRequest):
        kind = f"request  id={msg.id} {msg.method}"
    elif isinstance(msg, JSONRPCNotification):
        kind = f"notify   {msg.method}"
    elif isinstance(msg, JSONRPCResponse):
        kind = f"response id={msg.id}"
    else:
        kind = f"error    id={msg.id}"
    wire = msg.model_dump_json(by_alias=True, exclude_unset=True)
    if len(wire) > LOG_PREVIEW_CHARS:
        wire = f"{wire[:LOG_PREVIEW_CHARS]}... (+{len(wire) - LOG_PREVIEW_CHARS} chars)"
    return f"{kind} | {wire}"


def log_report(report: DriftReport) -> None:
    log("trust", f"{report.server}: {report.verdict.value} | {report.detail}")
    for change in report.changes:
        status = STATUS_FOR_CHANGE[change.kind]
        log("trust", f"  {report.server}{NAMESPACE_SEP}{change.tool}: {change.kind} -> {status}, hidden from client")
        if change.diff:
            log("trust", f"    diff: {change.diff}")


class LoggingReadStream:
    """Wraps a transport's read stream; logs each message as it is received."""

    def __init__(self, inner: Any, direction: str) -> None:
        self._inner = inner
        self._direction = direction

    async def receive(self) -> SessionMessage | Exception:
        item = await self._inner.receive()
        log(self._direction, describe(item))
        return item

    def __aiter__(self) -> LoggingReadStream:
        return self

    async def __anext__(self) -> SessionMessage | Exception:
        item = await self._inner.__anext__()
        log(self._direction, describe(item))
        return item

    async def aclose(self) -> None:
        await self._inner.aclose()

    async def __aenter__(self) -> LoggingReadStream:
        return self

    async def __aexit__(self, *exc_info: object) -> None:
        await self.aclose()

    def __getattr__(self, name: str) -> Any:
        # Forward anything else (e.g. `last_context`, read by the server runner).
        return getattr(self._inner, name)


class LoggingWriteStream:
    """Wraps a transport's write stream; logs each message before it is sent."""

    def __init__(self, inner: Any, direction: str) -> None:
        self._inner = inner
        self._direction = direction

    async def send(self, item: SessionMessage) -> None:
        log(self._direction, describe(item))
        await self._inner.send(item)

    async def aclose(self) -> None:
        await self._inner.aclose()

    async def __aenter__(self) -> LoggingWriteStream:
        return self

    async def __aexit__(self, *exc_info: object) -> None:
        await self.aclose()

    def __getattr__(self, name: str) -> Any:
        return getattr(self._inner, name)


# --------------------------------------------------------------------------
# Upstream side: we are the client
# --------------------------------------------------------------------------


def load_config() -> list[dict[str, Any]]:
    servers = json.loads(CONFIG_PATH.read_text(encoding="utf-8"))["servers"]
    names = [s["name"] for s in servers]
    if len(names) != len(set(names)):
        raise ValueError(f"duplicate server names in {CONFIG_PATH}: {names}")
    for name in names:
        if NAMESPACE_SEP in name:
            raise ValueError(f"server name {name!r} must not contain {NAMESPACE_SEP!r}")
    return servers


def launch_params(server: dict[str, Any]) -> StdioServerParameters:
    command = server["command"]
    if command == "python":
        # Use the interpreter running the proxy, so upstreams share its venv.
        command = sys.executable
    return StdioServerParameters(command=command, args=server.get("args", []), cwd=PROJECT_ROOT)


async def connect_upstream(stack: AsyncExitStack, server: dict[str, Any]) -> ClientSession:
    """Spawn one upstream server and do the MCP handshake."""
    name = server["name"]
    read, write = await stack.enter_async_context(stdio_client(launch_params(server)))
    session = await stack.enter_async_context(
        ClientSession(LoggingReadStream(read, f"{name} -> proxy"), LoggingWriteStream(write, f"proxy -> {name}"))
    )
    await session.initialize()
    return session


async def fetch_tools(session: ClientSession) -> list[types.Tool]:
    tools: list[types.Tool] = []
    cursor: str | None = None
    while True:
        page = await session.list_tools(params=types.PaginatedRequestParams(cursor=cursor) if cursor else None)
        tools.extend(page.tools)
        cursor = page.next_cursor
        if cursor is None:
            return tools


@dataclass
class Upstream:
    name: str
    session: ClientSession
    tools: list[types.Tool] = field(default_factory=list)  # latest live listing
    blocked: dict[str, str] = field(default_factory=dict)  # tool -> reason, from the latest drift check
    quarantined: dict[str, str] = field(default_factory=dict)  # tool -> findings, from the description guard
    classified: dict[str, str] = field(default_factory=dict)  # tool -> last classification bucket
    report: DriftReport | None = None  # latest drift report, for the console
    changes: dict[str, ToolChange] = field(default_factory=dict)  # tool -> latest change, for the console


async def push_state(snapshot: dict[str, Any]) -> None:
    """Best-effort POST of live state to the console. Never raises.

    The console cannot read this from trust.db: quarantine is in-memory only,
    and for a modified tool the database still holds the *old* pinned text.
    """
    try:
        async with httpx2.AsyncClient(timeout=CONSOLE_PUSH_TIMEOUT) as client:
            await client.post(f"{CONSOLE_URL}/api/proxy-state", json=snapshot)
    except Exception as exc:  # noqa: BLE001 - the console is optional, any failure is ignorable
        log("console", f"state push skipped ({type(exc).__name__}); is the console running?")


class Proxy:
    def __init__(self, store: TrustStore, key: Ed25519PrivateKey) -> None:
        self.store = store
        self.key = key
        self.upstreams: dict[str, Upstream] = {}
        self.registry: dict[str, list[str]] = {}
        self._refresh_lock = anyio.Lock()

    async def refresh(self, trigger: str) -> None:
        """Re-fetch every upstream's tools, run drift detection, then the description guard."""
        async with self._refresh_lock:
            drift_results: dict[str, tuple[DriftReport, dict[str, dict[str, Any]]]] = {}
            for upstream in self.upstreams.values():
                upstream.tools = await fetch_tools(upstream.session)
                live = [tool.model_dump(by_alias=True, mode="json") for tool in upstream.tools]
                report = check_drift(upstream.name, live, store=self.store, key=self.key, trigger=trigger)
                upstream.blocked = report.blocked
                upstream.report = report
                upstream.changes = {change.tool: change for change in report.changes}
                log_report(report)
                drift_results[upstream.name] = (report, {tool["name"]: tool for tool in live})

            # The guard needs every server's tool names to spot cross-server references.
            self.registry = {name: [tool.name for tool in up.tools] for name, up in self.upstreams.items()}

            for upstream in self.upstreams.values():
                report, live_by_name = drift_results[upstream.name]
                self._run_guard(upstream)
                self._classify_drift(upstream, report, live_by_name)

            await push_state(self.snapshot(trigger))

    def _run_guard(self, upstream: Upstream) -> None:
        """Scan every live description with both detectors; quarantine anything with findings."""
        found: dict[str, str] = {}
        for tool in upstream.tools:
            description = tool.description or ""
            findings = agent_directed_imperatives(description) + cross_server_refs(
                description, self.registry, upstream.name
            )
            if findings:
                found[tool.name] = "; ".join(finding.describe() for finding in findings)

        for name, reason in found.items():
            if upstream.quarantined.get(name) != reason:
                self.store.append_audit(upstream.name, name, "tool_quarantined", reason)
                log("trust", f"{upstream.name}: QUARANTINED {upstream.name}{NAMESPACE_SEP}{name}, hidden from client")
                log("trust", f"    {reason}")
        for name in upstream.quarantined:
            if name not in found:
                self.store.append_audit(upstream.name, name, "tool_unquarantined", "description guard findings cleared")
                log("trust", f"{upstream.name}: quarantine cleared on {upstream.name}{NAMESPACE_SEP}{name}")
        upstream.quarantined = found

    def _classify_drift(
        self, upstream: Upstream, report: DriftReport, live_by_name: dict[str, dict[str, Any]]
    ) -> None:
        """Give every drift change a classification bucket."""
        buckets: dict[str, str] = {}
        for change in report.changes:
            new_tool = live_by_name.get(change.tool) or {}
            if change.kind == "modified":
                old_tool: dict[str, Any] | None = None
                try:
                    record = self.store.get_tools(upstream.name).get(change.tool)
                    if record is not None:
                        old_tool = {"description": record.description_text}
                except ValueError:
                    old_tool = None
                bucket, why = classify_change(
                    old_tool, new_tool, self.registry, upstream.name, definition_changed=True
                )
            elif change.kind == "added":
                bucket, why = classify_change(None, new_tool, self.registry, upstream.name)
            else:  # removed: there is no new text to classify
                continue

            buckets[change.tool] = bucket.value
            if upstream.classified.get(change.tool) != bucket.value:
                self.store.append_audit(upstream.name, change.tool, "drift_classified", f"{bucket.value}: {why}")
                log(
                    "trust",
                    f"  {upstream.name}{NAMESPACE_SEP}{change.tool}: drift classified {bucket.value} ({why})",
                )
        upstream.classified = buckets

    # ---- console snapshot. Read-only: it reports decisions, it does not make them.

    def snapshot(self, trigger: str) -> dict[str, Any]:
        """Everything the console needs to draw the screen, as plain JSON."""
        servers = []
        for upstream in self.upstreams.values():
            try:
                pin = self.store.get_server(upstream.name)
                records = self.store.get_tools(upstream.name)
            except ValueError:  # a malformed row; check_drift already reported TAMPERED
                pin, records = None, {}

            live_by_name = {tool.name: tool for tool in upstream.tools}
            report = upstream.report
            servers.append(
                {
                    "name": upstream.name,
                    "verdict": report.verdict.value if report else "UNKNOWN",
                    "detail": report.detail if report else "",
                    "pinned_root": pin.signed_root.hex() if pin else None,
                    "first_approved_at": pin.first_approved_at if pin else None,
                    # Union of live and recorded names, so a tool the server dropped still shows.
                    "tools": [
                        self._tool_snapshot(upstream, name, live_by_name.get(name), records.get(name))
                        for name in sorted(set(live_by_name) | set(records))
                    ],
                }
            )
        return {"trigger": trigger, "registry": self.registry, "servers": servers}

    def _tool_snapshot(
        self, upstream: Upstream, name: str, live: types.Tool | None, record: Any
    ) -> dict[str, Any]:
        definition = live.model_dump(by_alias=True, mode="json") if live is not None else None
        description = (live.description or "") if live is not None else ""

        # Re-run the detectors rather than reuse the guard's joined string: the
        # console needs the spans, and these are pure functions of the text.
        findings = (
            agent_directed_imperatives(description) + cross_server_refs(description, self.registry, upstream.name)
            if live is not None
            else []
        )

        drift_kind = upstream.blocked.get(name)
        pills: list[list[str]] = []
        if drift_kind == "added":
            pills.append(["pending_approval", "added after approval, never approved"])
        elif drift_kind == "modified":
            pills.append(["suspended", "definition changed after it was approved"])
        elif drift_kind == "removed":
            pills.append(["suspended", "approved tool no longer offered"])
        elif drift_kind == "tampered":
            pills.append(["suspended", "trust store record failed verification"])
        if findings:
            pills.append(["quarantined", "description guard found an injected instruction"])
        if not pills:
            status = record.status if record is not None else "active"
            pills.append([status, "live definition matches the signed pin"])

        bucket = why = None
        if (drift_kind or findings) and definition is not None:
            old = {"description": record.description_text} if record is not None else None
            change_class, why = classify_change(
                old, definition, self.registry, upstream.name, definition_changed=(drift_kind == "modified")
            )
            bucket = change_class.value

        change = upstream.changes.get(name)
        return {
            "name": name,
            "pills": pills,
            "needs_review": bool(drift_kind or findings),
            "drift_kind": drift_kind,
            "bucket": bucket,
            "bucket_why": why,
            "diff": change.diff if change is not None else "",
            "description": description,
            "definition": definition,
            "pinned_description": record.description_text if record is not None else None,
            "pinned_leaf": record.leaf_hash.hex() if record is not None else None,
            "findings": [
                {
                    "detector": finding.detector,
                    "signal": finding.signal,
                    "text": finding.text,
                    "start": finding.start,
                    "end": finding.end,
                    "owner": finding.owner,
                    "describe": finding.describe(),
                }
                for finding in findings
            ],
        }

    def visible_tools(self) -> list[types.Tool]:
        """Namespaced tools the client may see: not drift-blocked and not quarantined."""
        visible = []
        for upstream in self.upstreams.values():
            hidden = set(upstream.blocked) | set(upstream.quarantined)
            for tool in upstream.tools:
                if tool.name not in hidden:
                    visible.append(tool.model_copy(update={"name": f"{upstream.name}{NAMESPACE_SEP}{tool.name}"}))
        return visible

    def resolve(self, namespaced: str) -> tuple[Upstream, str] | None:
        # Server names cannot contain the separator, so the first one splits correctly.
        server, sep, tool_name = namespaced.partition(NAMESPACE_SEP)
        upstream = self.upstreams.get(server)
        if not sep or upstream is None:
            return None
        return upstream, tool_name


# --------------------------------------------------------------------------
# Downstream side: we are the server
# --------------------------------------------------------------------------


def apply_firewall(
    proxy: Proxy, upstream: Upstream, tool_name: str, arguments: dict[str, Any], result: types.CallToolResult
) -> types.CallToolResult:
    """Wrap every tool result as untrusted data before it reaches the client.

    The text is never edited: findings are reported in the wrapper's header and
    the original content is passed through intact.
    """
    texts = [block.text for block in result.content if isinstance(block, types.TextContent)]
    others = [block for block in result.content if not isinstance(block, types.TextContent)]
    body = "\n".join(texts)

    findings = scan_output(body, arguments)
    result.content = [types.TextContent(text=wrap_untrusted(body, upstream.name, findings))] + others

    if findings:
        detail = "; ".join(describe_finding(finding) for finding in findings)
        proxy.store.append_audit(upstream.name, tool_name, "output_findings", detail)
        log("trust", f"{upstream.name}{NAMESPACE_SEP}{tool_name}: output wrapped, {len(findings)} findings")
        for finding in findings:
            log("trust", f"    {describe_finding(finding)}")
    else:
        proxy.store.append_audit(upstream.name, tool_name, "output_scanned", "0 findings; wrapped as untrusted")
    return result


def build_server(proxy: Proxy) -> Server:
    async def on_list_tools(ctx: Any, params: types.PaginatedRequestParams | None) -> types.ListToolsResult:
        await proxy.refresh(trigger="tools/list")
        return types.ListToolsResult(tools=proxy.visible_tools())

    async def on_call_tool(ctx: Any, params: types.CallToolRequestParams) -> types.CallToolResult:
        target = proxy.resolve(params.name)
        if target is None:
            raise MCPError(code=types.INVALID_PARAMS, message=f"Unknown tool: {params.name}")
        upstream, tool_name = target

        quarantine = upstream.quarantined.get(tool_name)
        if quarantine is not None:
            message = (
                f"mcp-trust-proxy refused '{params.name}': its description is quarantined by the description "
                f"guard and re-approval is required before it can be called. Findings: {quarantine}"
            )
            proxy.store.append_audit(upstream.name, tool_name, "call_blocked", message)
            log("trust", message)
            return types.CallToolResult(content=[types.TextContent(text=message)], is_error=True)

        reason = upstream.blocked.get(tool_name)
        if reason is not None:
            message = f"mcp-trust-proxy refused '{params.name}': {REFUSAL_REASONS[reason]}"
            proxy.store.append_audit(upstream.name, tool_name, "call_blocked", message)
            log("trust", message)
            return types.CallToolResult(content=[types.TextContent(text=message)], is_error=True)

        if all(tool.name != tool_name for tool in upstream.tools):
            raise MCPError(code=types.INVALID_PARAMS, message=f"Unknown tool: {params.name}")
        result = await upstream.session.call_tool(tool_name, params.arguments)
        return apply_firewall(proxy, upstream, tool_name, params.arguments or {}, result)

    return Server("mcp-trust-proxy", version="0.1.0", on_list_tools=on_list_tools, on_call_tool=on_call_tool)


async def serve() -> None:
    store = TrustStore()
    key = keys.load_or_create_key()
    proxy = Proxy(store, key)

    async with AsyncExitStack() as stack:
        stack.callback(store.close)  # registered first, so it closes last
        for server in load_config():
            proxy.upstreams[server["name"]] = Upstream(server["name"], await connect_upstream(stack, server))
        await proxy.refresh(trigger="connect")

        downstream = build_server(proxy)
        log("proxy", f"serving {len(proxy.visible_tools())} tools to the client over stdio")
        async with stdio_server() as (read, write):
            await downstream.run(
                LoggingReadStream(read, "client -> proxy"),
                LoggingWriteStream(write, "proxy -> client"),
                downstream.create_initialization_options(),
            )


def main() -> None:
    anyio.run(serve)
