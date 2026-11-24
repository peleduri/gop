"""A minimal tool-calling agent over any OpenAI-compatible chat endpoint.

The agent gets the skill as its system prompt and gop's tools as functions.
It records every tools/call (name, arguments, result) and the final answer.
The endpoint is the OpenAI SDK's: OPENAI_API_KEY and OPENAI_BASE_URL (or
--base-url), so a local Ollama model (http://localhost:11434/v1) works too.
"""

from __future__ import annotations

import json
import time
from typing import Any

from .gop import Gop

# How much of one tool result the model reads. The hostile graph has 10 kB
# names; the cap keeps a run inside small context windows.
MAX_RESULT_CHARS = 16_000
MAX_TURNS = 16


def openai_tools(gop: Gop) -> list[dict[str, Any]]:
    """gop's MCP tools as OpenAI function tools."""
    out = []
    for t in gop.tools:
        params = t.input_schema or {"type": "object", "properties": {}}
        out.append({"type": "function", "function": {
            "name": t.name, "description": t.description or "", "parameters": params}})
    return out


async def run_agent(client: Any, model: str, system: str, question: str, gop: Gop,
                    temperature: float = 0.0, max_turns: int = MAX_TURNS) -> dict[str, Any]:
    """Ask question and loop over tool calls until the model answers.

    Returns {"tool_calls": [{name, arguments, text, is_error, raw}], "answer", "turns", "error", "seconds"}.
    """
    messages: list[dict[str, Any]] = [{"role": "system", "content": system}, {"role": "user", "content": question}]
    tools = openai_tools(gop)
    calls: list[dict[str, Any]] = []
    start = time.monotonic()
    for turn in range(1, max_turns + 1):
        resp = client.chat.completions.create(model=model, messages=messages, tools=tools, temperature=temperature)
        msg = resp.choices[0].message
        if not msg.tool_calls:
            return {"tool_calls": calls, "answer": msg.content or "", "turns": turn, "error": "",
                    "seconds": round(time.monotonic() - start, 1)}
        messages.append({"role": "assistant", "content": msg.content or "", "tool_calls": [
            {"id": tc.id, "type": "function", "function": {"name": tc.function.name, "arguments": tc.function.arguments}}
            for tc in msg.tool_calls]})
        for tc in msg.tool_calls:
            try:
                args = json.loads(tc.function.arguments or "{}")
                if not isinstance(args, dict):
                    raise ValueError("arguments are not an object")
            except ValueError as err:
                args, res = {}, None
                text, is_error = f"invalid JSON arguments: {err}", True
            else:
                res = await gop.call(tc.function.name, args)
                text, is_error = res.text, res.is_error
            calls.append({"name": tc.function.name, "arguments": args, "text": text, "is_error": is_error,
                          "raw": res.raw if res else None})
            messages.append({"role": "tool", "tool_call_id": tc.id, "content": text[:MAX_RESULT_CHARS]})
    return {"tool_calls": calls, "answer": "", "turns": max_turns, "error": f"no answer after {max_turns} turns",
            "seconds": round(time.monotonic() - start, 1)}
