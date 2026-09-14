"""Captured conversation authority for required private profiles.

The installed boundary implements authentication, durable execution claims,
private history, permits and audited dispatch. Hermes supplies immutable schemas
and a mandatory caller path. None of these objects authorize ordinary SDK calls.
"""

from __future__ import annotations

import inspect
import json
import threading
from concurrent.futures import Future
from contextlib import contextmanager
from dataclasses import dataclass, field
from types import MappingProxyType
from typing import Any, Callable

from hermes_cli.private_boundary import PrivateBoundaryError, PrivateToolRegistration, _ID

PRIVATE_MARKER = "[Private turn]"
_MAX_REQUEST_BYTES = 24 * 1024 * 1024
_UNSUPPORTED_TOOLS = frozenset({
    "execute_code", "delegate_task", "tool_search", "tool_describe", "tool_call",
    "send_message", "cronjob", "memory", "session_search", "clarify",
})


def encoded(value: Any, *, limit: int = _MAX_REQUEST_BYTES) -> str:
    try:
        result = json.dumps(value, ensure_ascii=False, sort_keys=True,
                            separators=(",", ":"), allow_nan=False)
        if len(result.encode("utf-8")) > limit:
            raise ValueError()
        return result
    except Exception:
        raise PrivateBoundaryError("PRIVATE_BOUNDARY_CONTEXT_INVALID") from None


def completed(value):
    if inspect.isawaitable(value):
        from model_tools import _run_async
        return _run_async(value)
    return value


@dataclass(frozen=True)
class ConversationBinding:
    conversation_id: str
    session_id: str
    epoch: str

    def __post_init__(self):
        if any(not isinstance(v, str) or not _ID.fullmatch(v)
               for v in (self.conversation_id, self.session_id, self.epoch)):
            raise PrivateBoundaryError("PRIVATE_BOUNDARY_CONTEXT_INVALID")


@dataclass(frozen=True)
class AcceptedTurn:
    """Private references only; the private resolver must authenticate and claim them."""
    binding: ConversationBinding
    input_refs: tuple[str, ...]
    kind: str = "command"

    def __post_init__(self):
        if (not isinstance(self.binding, ConversationBinding)
                or type(self.input_refs) is not tuple or not 1 <= len(self.input_refs) <= 32
                or len(set(self.input_refs)) != len(self.input_refs)
                or any(not isinstance(v, str) or not _ID.fullmatch(v) for v in self.input_refs)
                or self.kind not in {"command", "context", "control"}):
            raise PrivateBoundaryError("PRIVATE_BOUNDARY_CONTEXT_INVALID")


@dataclass(frozen=True)
class AdmissionNotice:
    """No executable input: empty ingress or a privately settled contender."""
    status: str

    def __post_init__(self):
        if type(self.status) is not str or self.status not in {"idle", "duplicate", "refused"}:
            raise PrivateBoundaryError("PRIVATE_BOUNDARY_CONTEXT_INVALID")


@dataclass(frozen=True)
class ConversationPolicy:
    """Trusted, non-customer policy captured before the first provider request."""
    model: str
    system_prompt: str = field(repr=False)
    compaction_prompt: str = field(repr=False)
    local_endpoint: str = field(repr=False)
    public_tools: tuple[str, ...] = ()
    context_length: int = 32768
    hosted_model: str | None = None
    hosted_endpoint: str | None = field(default=None, repr=False)


@dataclass(frozen=True)
class ResolvedTurn:
    """Returned only after the private store's atomic group execution claim."""
    binding: ConversationBinding
    run_id: str
    lease: Any = field(repr=False)
    messages: list[dict] = field(repr=False)


@dataclass(frozen=True)
class PreparedProviderRequest:
    """Exact immutable wire request plus a private single-use dispatch permit."""
    request_json: str = field(repr=False)
    endpoint: str = field(repr=False)
    disposition: str
    purpose: str
    run_id: str
    permit: Any = field(repr=False)


@dataclass(frozen=True)
class OwnedOperation:
    """Completion and actual producer join are separate evidence.

    join() must return True only after all producers have stopped. cancel()
    signals the operation; it must not merely cancel its Future. The private
    coordinator starts this operation synchronously after audit/permit consume.
    """
    future: Future = field(repr=False)
    join: Callable[[], bool] = field(repr=False)
    cancel: Callable[[], None] = field(repr=False)


@dataclass(frozen=True)
class PrivateTurnResult:
    status: str
    output_ref: str | None = None

    def __post_init__(self):
        if (self.status not in {"completed", "failed", "cancelled", "context", "control"}
                or self.output_ref is not None and (
                    not isinstance(self.output_ref, str) or not _ID.fullmatch(self.output_ref))):
            raise PrivateBoundaryError("PRIVATE_BOUNDARY_CONTEXT_INVALID")


class BoundaryConversation:
    """One runtime/session epoch, one immutable prompt/catalog, one active run."""

    def __init__(self, runtime, binding: ConversationBinding):
        runtime.assert_ready()
        self.runtime = runtime
        self.binding = binding
        self._backend = runtime._implementation
        self._run_lock = threading.Lock()
        self._operation_lock = threading.RLock()
        self._operation = None
        self._resolved = None
        self._cancelled = threading.Event()
        self._withheld = False
        for method in ("conversation_policy", "validate_conversation", "validate_execution",
                       "resolve", "prepare", "dispatch_provider", "authorize_tool",
                       "dispatch_tool", "project", "consume_control"):
            if not callable(getattr(self._backend, method, None)):
                raise PrivateBoundaryError("PRIVATE_BOUNDARY_INCOMPATIBLE")
        policy = completed(self._backend.conversation_policy(binding))
        if (not isinstance(policy, ConversationPolicy)
                or any(not isinstance(v, str) or not v for v in
                       (policy.model, policy.system_prompt, policy.compaction_prompt))
                or type(policy.public_tools) is not tuple
                or type(policy.context_length) is not int or policy.context_length < 1024
                or any(not isinstance(v, str) for v in policy.public_tools)
                or len(set(policy.public_tools)) != len(policy.public_tools)):
            raise PrivateBoundaryError("PRIVATE_BOUNDARY_INCOMPATIBLE")
        self.policy = policy
        from agent.secret_scope import build_profile_secret_scope
        self._secrets = MappingProxyType(dict(build_profile_secret_scope(runtime.home)))
        from urllib.parse import urlsplit
        local = urlsplit(policy.local_endpoint)
        if (local.scheme not in {"http", "https"} or local.hostname not in {"127.0.0.1", "::1"}
                or local.username is not None or local.password is not None
                or local.query or local.fragment):
            raise PrivateBoundaryError("PRIVATE_BOUNDARY_INCOMPATIBLE")
        if (policy.hosted_model is None) != (policy.hosted_endpoint is None):
            raise PrivateBoundaryError("PRIVATE_BOUNDARY_INCOMPATIBLE")
        if policy.hosted_endpoint is not None:
            hosted = urlsplit(policy.hosted_endpoint)
            if (not isinstance(policy.hosted_model, str) or not policy.hosted_model
                    or hosted.scheme != "https" or not hosted.hostname
                    or hosted.username is not None or hosted.password is not None
                    or hosted.query or hosted.fragment):
                raise PrivateBoundaryError("PRIVATE_BOUNDARY_INCOMPATIBLE")
        runtime.tool_definitions()  # Detect public-name collisions before capturing schemas.
        tools = {tool.name: tool for tool in runtime.registration.tools}
        from tools.registry import registry
        for name in policy.public_tools:
            entry = registry.get_entry(name)
            if (name in tools or name in _UNSUPPORTED_TOOLS or name.startswith("mcp_")
                    or entry is None or not callable(entry.check_fn)):
                raise PrivateBoundaryError("PRIVATE_BOUNDARY_INCOMPATIBLE")
            tools[name] = PrivateToolRegistration(
                name=name, toolset=entry.toolset, schema_json=encoded(entry.schema),
                handler=entry.handler, check_fn=lambda runtime, check=entry.check_fn: check(),
            )
        self._tools = MappingProxyType(tools)
        from jsonschema import Draft202012Validator
        for tool in tools.values():
            schema = json.loads(tool.schema_json)
            if (schema.get("name") != tool.name or not callable(tool.handler)
                    or not isinstance(schema.get("description"), str)
                    or set(schema) - {"name", "description", "parameters", "strict"}
                    or schema.get("parameters", {}).get("type") != "object"):
                raise PrivateBoundaryError("PRIVATE_BOUNDARY_INCOMPATIBLE")
            Draft202012Validator.check_schema(schema["parameters"])
        self._schemas = encoded([tools[name].definition() for name in sorted(tools)])
        self.allowed_names = frozenset(tools)
        self.assert_valid()
        for tool in tools.values():
            if completed(tool.check_fn(runtime)) is not True:
                raise PrivateBoundaryError("PRIVATE_BOUNDARY_NOT_READY")

    def assert_valid(self):
        self.runtime.assert_ready()
        if self._withheld or completed(self._backend.validate_conversation(self.binding)) is not True:
            raise PrivateBoundaryError("PRIVATE_BOUNDARY_CONTEXT_INVALID")

    @contextmanager
    def execution_scope(self):
        from hermes_constants import set_hermes_home_override, reset_hermes_home_override
        from agent.secret_scope import set_secret_scope, reset_secret_scope
        home_token = set_hermes_home_override(str(self.runtime.home))
        secret_token = set_secret_scope(self._secrets)
        try:
            yield
        finally:
            reset_secret_scope(secret_token)
            reset_hermes_home_override(home_token)

    def definitions(self):
        self.assert_valid()
        return json.loads(self._schemas)

    def begin(self, turn: AcceptedTurn, cancellation=None):
        self.assert_valid()
        if not isinstance(turn, AcceptedTurn) or turn.binding != self.binding or turn.kind != "command":
            raise PrivateBoundaryError("PRIVATE_BOUNDARY_CONTEXT_INVALID")
        if not self._run_lock.acquire(blocking=False):
            raise PrivateBoundaryError("PRIVATE_BOUNDARY_NOT_READY")
        try:
            self._cancelled = cancellation if cancellation is not None else threading.Event()
            if self._cancelled.is_set():
                raise PrivateBoundaryError("PRIVATE_BOUNDARY_NOT_READY")
            try:
                resolved = completed(self._backend.resolve(turn))
            except Exception:
                # The store may have committed a claim before raising. Retain
                # ownership until recovery can determine that claim's outcome.
                self._withheld = True
                self.runtime.retire()
                raise PrivateBoundaryError("PRIVATE_BOUNDARY_NOT_READY") from None
            if (not isinstance(resolved, ResolvedTurn) or resolved.binding != self.binding
                    or not isinstance(resolved.run_id, str) or not _ID.fullmatch(resolved.run_id)
                    or not isinstance(resolved.messages, list) or not resolved.messages
                    or any(not isinstance(m, dict) for m in resolved.messages)
                    or resolved.messages[-1].get("role") != "user"):
                self._withheld = True
                self.runtime.retire()
                raise PrivateBoundaryError("PRIVATE_BOUNDARY_CONTEXT_INVALID")
            self._resolved = resolved
            self.assert_execution()
            return json.loads(encoded(resolved.messages))
        except BaseException:
            if self._resolved is not None:
                self._withheld = True
                self.runtime.retire()
            if not self._withheld:
                self._run_lock.release()
            raise

    def assert_execution(self):
        self.assert_valid()
        if self._resolved is None or self._cancelled.is_set():
            raise PrivateBoundaryError("PRIVATE_BOUNDARY_NOT_READY")
        if completed(self._backend.validate_execution(self._resolved)) is not True:
            raise PrivateBoundaryError("PRIVATE_BOUNDARY_CONTEXT_INVALID")

    def cancel(self):
        with self._operation_lock:
            self._cancelled.set()
            if self._operation is not None:
                try:
                    self._operation.cancel()
                except Exception:
                    self._withheld = True
                    self.runtime.retire()
                    raise PrivateBoundaryError("PRIVATE_BOUNDARY_NOT_READY") from None

    def start_operation(self, dispatch):
        # Serialize the last live check and synchronous producer start with
        # cancellation. A dispatcher that raises cannot prove producer join.
        with self._operation_lock:
            self.assert_execution()
            try:
                operation = dispatch()
            except BaseException:
                self._withheld = True
                self.runtime.retire()
                raise PrivateBoundaryError("PRIVATE_BOUNDARY_NOT_READY") from None
            self._operation = operation
        return self.await_operation(operation)

    def await_operation(self, operation):
        if (not isinstance(operation, OwnedOperation) or not isinstance(operation.future, Future)
                or not callable(operation.join) or not callable(operation.cancel)):
            self._withheld = True
            self.runtime.retire()
            raise PrivateBoundaryError("PRIVATE_BOUNDARY_INCOMPATIBLE")
        with self._operation_lock:
            self._operation = operation
        try:
            if self._cancelled.is_set():
                try:
                    operation.cancel()
                except Exception:
                    self._withheld = True
                    self.runtime.retire()
                    raise PrivateBoundaryError("PRIVATE_BOUNDARY_NOT_READY") from None
            return operation.future.result()
        finally:
            try:
                joined = operation.join() is True
            except Exception:
                joined = False
            if not joined:
                self._withheld = True
                self.runtime.retire()
                raise PrivateBoundaryError("PRIVATE_BOUNDARY_NOT_READY") from None
            with self._operation_lock:
                self._operation = None

    def provider_call(self, messages, *, purpose="conversation"):
        from hermes_cli.runtime_provider import checked_private_provider_call
        return checked_private_provider_call(self, messages, purpose=purpose)

    def execute_tool(self, name, arguments):
        self.assert_execution()
        tool = self._tools.get(name)
        if tool is None or not isinstance(arguments, dict):
            raise PrivateBoundaryError("PRIVATE_BOUNDARY_CONTEXT_INVALID")
        try:
            from jsonschema import Draft202012Validator
            Draft202012Validator(json.loads(tool.schema_json)["parameters"]).validate(arguments)
            if completed(tool.check_fn(self.runtime)) is not True:
                raise PrivateBoundaryError("PRIVATE_BOUNDARY_NOT_READY")
            args_json = encoded(arguments, limit=256 * 1024)
            permit = completed(self._backend.authorize_tool(self._resolved, name, args_json))
            if permit is None:
                raise PrivateBoundaryError("PRIVATE_BOUNDARY_NOT_READY")
            self.assert_execution()
            result = self.start_operation(lambda: self._backend.dispatch_tool(
                self._resolved, name, args_json, permit, tool.handler,
            ))
            self.assert_execution()
            return encoded(result, limit=256 * 1024)
        except Exception:
            raise PrivateBoundaryError("PRIVATE_BOUNDARY_NOT_READY") from None

    def persist(self, messages, *, status="running"):
        # Final/failure projection is also required after cancellation/retirement;
        # the private backend checks the pinned owner before any terminal write.
        if self._resolved is None or self._withheld:
            raise PrivateBoundaryError("PRIVATE_BOUNDARY_NOT_READY")
        try:
            result = completed(self._backend.project(
                self._resolved, json.loads(encoded(messages)), status,
            ))
            if status == "running":
                if result is not True:
                    raise PrivateBoundaryError("PRIVATE_BOUNDARY_NOT_READY")
            elif not isinstance(result, PrivateTurnResult) or result.status != status:
                raise PrivateBoundaryError("PRIVATE_BOUNDARY_CONTEXT_INVALID")
            return result
        except Exception:
            self._withheld = True
            self.runtime.retire()
            raise PrivateBoundaryError("PRIVATE_BOUNDARY_NOT_READY") from None

    def end(self):
        if self._withheld:
            # Retain the run and its producer references until owner recovery.
            return
        self._resolved = None
        self._run_lock.release()

    def consume_control(self, turn):
        self.assert_valid()
        if (not isinstance(turn, AcceptedTurn) or turn.binding != self.binding
                or turn.kind not in {"context", "control"}):
            raise PrivateBoundaryError("PRIVATE_BOUNDARY_CONTEXT_INVALID")
        result = completed(self._backend.consume_control(turn))
        if not isinstance(result, PrivateTurnResult) or result.status != turn.kind:
            raise PrivateBoundaryError("PRIVATE_BOUNDARY_CONTEXT_INVALID")
        return result


def require_conversation(context):
    if not isinstance(context, BoundaryConversation):
        raise PrivateBoundaryError("PRIVATE_BOUNDARY_CONTEXT_INVALID")
    context.assert_valid()
    return context
