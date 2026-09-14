"""Required conversation loop with private persistence and checked releases.

Optional observers, steering text, automatic retries, provider fallback and
ordinary history are deliberately outside this path. Shared transcript repair
and ContextCompressor still define transcript normalization and compaction.
"""

from __future__ import annotations

import json

from agent.agent_runtime_helpers import repair_message_sequence
from agent.turn_context import build_private_turn_context
from agent.turn_finalizer import finalize_private_turn
from hermes_cli.private_boundary import PrivateBoundaryError
from hermes_cli.private_conversation import encoded, require_conversation


def run_private_conversation(agent, turn, *, system_message=None, conversation_history=None,
                             stream_callback=None, persist_user_message=None, moa_config=None):
    context = require_conversation(agent._private_boundary_context)
    if any(value is not None for value in (
        system_message, conversation_history, stream_callback, persist_user_message, moa_config,
    )):
        raise PrivateBoundaryError("PRIVATE_BOUNDARY_CONTEXT_INVALID")
    with context.execution_scope():
        return _run(agent, turn, context)


def _run(agent, turn, context):
    messages = build_private_turn_context(agent, turn)
    status = "failed"
    api_calls = 0
    try:
        context.persist(messages)
        for _ in range(agent.max_iterations):
            context.assert_execution()
            repair_message_sequence(agent, messages)
            from agent.model_metadata import estimate_messages_tokens_rough
            tokens = estimate_messages_tokens_rough(messages)
            if agent.context_compressor.should_compress(tokens):
                full = [{"role": "system", "content": context.policy.system_prompt}, *messages]
                compacted = agent.context_compressor.compress(full, current_tokens=tokens)
                if compacted[0] != full[0]:
                    raise PrivateBoundaryError("PRIVATE_BOUNDARY_CONTEXT_INVALID")
                messages = compacted[1:]
                context.persist(messages)
            response = context.provider_call(messages)
            api_calls += 1
            calls = response.get("tool_calls") or []
            if not isinstance(calls, list):
                raise PrivateBoundaryError("PRIVATE_BOUNDARY_CONTEXT_INVALID")
            seen = set()
            for call in calls:
                if (not isinstance(call, dict) or set(call) != {"id", "type", "function"}
                        or not isinstance(call["id"], str) or not call["id"] or call["id"] in seen
                        or call["type"] != "function" or not isinstance(call["function"], dict)
                        or set(call["function"]) != {"name", "arguments"}
                        or not isinstance(call["function"]["name"], str)
                        or not isinstance(call["function"]["arguments"], str)):
                    raise PrivateBoundaryError("PRIVATE_BOUNDARY_CONTEXT_INVALID")
                seen.add(call["id"])
            messages.append(response)
            # Crash evidence exists before the first requested tool executes.
            context.persist(messages)
            if not calls:
                if not isinstance(response.get("content"), str) or not response["content"]:
                    raise PrivateBoundaryError("PRIVATE_BOUNDARY_CONTEXT_INVALID")
                status = "completed"
                break
            failure = None
            for call in calls:
                result = encoded({"status": "not_executed"})
                if failure is None:
                    try:
                        from model_tools import handle_function_call
                        args = json.loads(call["function"]["arguments"])
                        result = handle_function_call(
                            call["function"]["name"], args, boundary_context=context,
                        )
                    except Exception as exc:
                        # Do not preserve the exception text in ordinary output.
                        failure = exc
                        result = encoded({"status": "unavailable"})
                messages.append({"role": "tool", "tool_call_id": call["id"], "content": result})
                context.persist(messages)
            if failure is not None:
                raise PrivateBoundaryError("PRIVATE_BOUNDARY_NOT_READY") from None
        if context._cancelled.is_set():
            status = "cancelled"
    except Exception:
        status = "cancelled" if context._cancelled.is_set() else "failed"
    finally:
        try:
            result = finalize_private_turn(agent, messages, status=status, api_call_count=api_calls)
        finally:
            context.end()
    return result
