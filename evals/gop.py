"""Start `gop serve` over stdio and call its tools with the MCP Python SDK."""

from __future__ import annotations

import json
import os
import shutil
import subprocess
from contextlib import asynccontextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Any, AsyncIterator

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

ROOT = Path(__file__).resolve().parent.parent
EVALS = ROOT / "evals"

# The graphs the cases run against. hostile.json and semantic.json are
# testutil.HostileGraphJSON and testutil.SemanticGraphJSON of the acme
# fixture; a Go test (internal/testutil TestEvalFixtures) keeps them equal.
GRAPHS = {
    "acme": ROOT / "testdata" / "acme" / "graph.json",
    "hostile": EVALS / "fixtures" / "hostile.json",
    "semantic": EVALS / "fixtures" / "semantic.json",
}


def gop_binary(explicit: str | None, out_dir: Path) -> str:
    """Return the gop binary to serve: explicit, $GOP_BIN, or a fresh build of this checkout."""
    if explicit:
        return explicit
    if os.environ.get("GOP_BIN"):
        return os.environ["GOP_BIN"]
    if shutil.which("go") is None:
        raise SystemExit("evals: pass --gop or set GOP_BIN (no go toolchain to build gop with)")
    out_dir.mkdir(parents=True, exist_ok=True)
    binary = out_dir / ("gop.exe" if os.name == "nt" else "gop")
    subprocess.run(["go", "build", "-o", str(binary), "./cmd/gop"], cwd=ROOT, check=True)
    return str(binary)


def resolve_id(graph: str, node_id: str) -> str:
    """Resolve a case's node ID in graph: the exact ID, else the one node ID
    that starts with it (the hostile and semantic graphs append the payload
    to the name, so `repo:acme-app/web` finds the renamed repo)."""
    nodes = [n["id"] for n in json.loads(GRAPHS[graph].read_text(encoding="utf-8"))["nodes"]]
    if node_id in nodes:
        return node_id
    hits = [n for n in nodes if n.startswith(node_id)]
    if len(hits) != 1:
        raise ValueError(f"{graph}: {node_id!r} matches {len(hits)} nodes")
    return hits[0]


@dataclass
class ToolResult:
    """One tools/call result: the text the agent reads and gop's structured output."""

    text: str
    structured: dict[str, Any]
    is_error: bool
    raw: Any  # mcp.types.CallToolResult, for DeepEval's MCPToolCall


class Gop:
    """A connected `gop serve --graph` session."""

    def __init__(self, session: ClientSession, tools: list[Any], instructions: str):
        self.session = session
        self.tools = tools  # mcp.types.Tool
        self.instructions = instructions

    @property
    def tool_names(self) -> set[str]:
        return {t.name for t in self.tools}

    async def call(self, name: str, args: dict[str, Any]) -> ToolResult:
        if name not in self.tool_names:
            return ToolResult(text=f"unknown tool {name!r}", structured={}, is_error=True, raw=None)
        res = await self.session.call_tool(name, args)
        text = "\n".join(getattr(c, "text", "") for c in res.content)
        return ToolResult(text=text, structured=res.structured_content or {}, is_error=bool(res.is_error), raw=res)


@asynccontextmanager
async def serve(binary: str, graph: str) -> AsyncIterator[Gop]:
    """Run `gop serve --graph <graph>` and yield a connected session."""
    params = StdioServerParameters(command=binary, args=["serve", "--graph", str(GRAPHS[graph])])
    async with stdio_client(params) as (read, write):
        async with ClientSession(read, write) as session:
            init = await session.initialize()
            tools = (await session.list_tools()).tools
            yield Gop(session, tools, getattr(init, "instructions", "") or "")
