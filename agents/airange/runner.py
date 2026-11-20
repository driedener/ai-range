"""Shared agent runner built on the Claude Agent SDK.

Security model: the agents get NO built-in tools (no Bash, no file system, no web), only the
MCP tools registered here. Everything an agent can do in the range therefore goes through our
code (scope guard, ground truth, permissions of the Elastic user).
"""
from __future__ import annotations

import json
import tempfile
from dataclasses import dataclass
from typing import Any, Callable

from claude_agent_sdk import (
    AssistantMessage,
    ClaudeAgentOptions,
    HookMatcher,
    ResultError,
    ResultMessage,
    SdkMcpTool,
    TextBlock,
    ToolUseBlock,
    create_sdk_mcp_server,
    query,
    tool,
)

from .config import settings
from .trace import Tracer


def text_result(data: Any, is_error: bool = False) -> dict[str, Any]:
    """Tool result in SDK format; objects are serialized as JSON."""
    text = data if isinstance(data, str) else json.dumps(data, ensure_ascii=False, indent=1, default=str)
    return {"content": [{"type": "text", "text": text}], "is_error": is_error}


def make_tool(name: str, description: str, schema: dict[str, Any], handler: Callable) -> SdkMcpTool:
    """Small wrapper around @tool so tool modules can do without decorator magic."""
    return tool(name, description, schema)(handler)


@dataclass
class AgentResult:
    run_id: str
    agent: str
    final_text: str
    cost_usd: float | None
    turns: int | None
    is_error: bool
    subtype: str


async def run_agent(*, run_id: str, role: str, agent_name: str, system_prompt: str, prompt: str,
                    tools: list[SdkMcpTool], tracer: Tracer, max_turns: int = 60,
                    max_budget_usd: float | None = None, verbose: bool = True) -> AgentResult:
    server_name = role
    allowed = [f"mcp__{server_name}__{t.name}" for t in tools]

    async def pre_hook(data: dict, tool_use_id: str | None, _ctx: Any) -> dict:
        tracer.tool_started(tool_use_id or data.get("tool_use_id"))
        return {}

    async def post_hook(data: dict, tool_use_id: str | None, _ctx: Any) -> dict:
        await tracer.tool_call(_short(data["tool_name"]), data.get("tool_input"), data.get("tool_response"),
                               tool_use_id or data.get("tool_use_id"))
        return {}

    async def fail_hook(data: dict, tool_use_id: str | None, _ctx: Any) -> dict:
        await tracer.tool_call(_short(data["tool_name"]), data.get("tool_input"), "", tool_use_id or data.get("tool_use_id"),
                               outcome="failure", error=data.get("error"))
        return {}

    options = ClaudeAgentOptions(
        model=settings.model_for(role),
        system_prompt=system_prompt,
        tools=[],                       # no built-in tools
        mcp_servers={server_name: create_sdk_mcp_server(server_name, tools=tools)},
        allowed_tools=allowed,
        strict_mcp_config=True,
        permission_mode="dontAsk",      # everything except allowed_tools is denied
        setting_sources=[],             # no user/project settings, CLAUDE.md or similar
        cwd=tempfile.mkdtemp(prefix=f"airange-{role}-"),
        max_turns=max_turns,
        max_budget_usd=max_budget_usd if max_budget_usd is not None else settings.budget_for(role),
        thinking={"type": "adaptive"},
        hooks={
            "PreToolUse": [HookMatcher(hooks=[pre_hook])],
            "PostToolUse": [HookMatcher(hooks=[post_hook])],
            "PostToolUseFailure": [HookMatcher(hooks=[fail_hook])],
        },
    )

    final_text, result = "", None
    try:
        async for msg in query(prompt=prompt, options=options):
            if isinstance(msg, AssistantMessage):
                for block in msg.content:
                    if isinstance(block, TextBlock) and block.text.strip():
                        final_text = block.text
                        if verbose:
                            print(f"\n[{agent_name}] {block.text.strip()}")
                    elif isinstance(block, ToolUseBlock) and verbose:
                        print(f"[{agent_name}] -> {_short(block.name)} {json.dumps(block.input, ensure_ascii=False)[:300]}")
            elif isinstance(msg, ResultMessage):
                result = msg
    except ResultError as e:
        # Budget/turn limit: the CLI first reports a ResultMessage (is_error) and then exits
        # with code 1. That is a regular end of the run - the exercise (Blue/scoring) should continue.
        if result is None:
            raise
        if verbose:
            print(f"\n[{agent_name}] run ended by limit: {e.subtype} {'; '.join(e.errors or [])}")

    if result is None:
        raise RuntimeError("Agent run ended without a ResultMessage")
    await tracer.run_summary(result, prompt)
    if verbose:
        cost = f"{result.total_cost_usd:.2f} USD" if result.total_cost_usd is not None else "?"
        print(f"\n[{agent_name}] done: {result.subtype}, {result.num_turns} turns, {cost}")
    return AgentResult(run_id, agent_name, result.result or final_text, result.total_cost_usd,
                       result.num_turns, result.is_error, result.subtype)


def _short(name: str) -> str:
    """mcp__blue__esql -> esql"""
    return name.split("__")[-1]
