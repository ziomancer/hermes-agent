"""Required private-boundary policy and profile-owned plugin registration.

This module is intentionally independent of any client implementation. Factory
discovery cannot open private state, and private tool schemas never enter the
process-global tool registry.
"""

from __future__ import annotations

import hashlib
import inspect
import json
import os
import re
import stat
import threading
from contextlib import contextmanager
from contextvars import ContextVar
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Mapping

import yaml

BOUNDARY_API_VERSION = 1
LEGACY_WHATSAPP_SEND_REFUSAL = "This profile sends only through the private lane."
_NAME = re.compile(r"[A-Za-z0-9_][A-Za-z0-9_.-]{0,127}\Z")
MAX_POLICY_CONFIG_BYTES = 1024 * 1024


class PrivateBoundaryError(RuntimeError):
    """A fixed public failure code; never attach private exception text."""

    def __init__(
        self,
        code: str = "PRIVATE_BOUNDARY_UNAVAILABLE",
        context: Mapping[str, str] | None = None,
    ) -> None:
        if code not in {
            "PRIVATE_BOUNDARY_UNAVAILABLE",
            "PRIVATE_BOUNDARY_POLICY_INVALID",
            "PRIVATE_BOUNDARY_REGISTRATION_INVALID",
            "PRIVATE_BOUNDARY_DUPLICATE",
            "PRIVATE_BOUNDARY_INCOMPATIBLE",
            "PRIVATE_BOUNDARY_CONTEXT_INVALID",
            "PRIVATE_BOUNDARY_NOT_READY",
            "PRIVATE_BOUNDARY_TRANSPORT_UNAVAILABLE",
            "PRIVATE_BOUNDARY_LEGACY_CUTOVER_REQUIRED",
        }:
            code = "PRIVATE_BOUNDARY_UNAVAILABLE"
        self.code = code
        self.context = dict(context or {})
        super().__init__(code)


def canonical_home(home: str | Path) -> Path:
    try:
        return Path(home).expanduser().resolve()
    except (OSError, RuntimeError, TypeError, ValueError):
        raise PrivateBoundaryError("PRIVATE_BOUNDARY_POLICY_INVALID") from None


def _read_policy_config(home: Path) -> str | None:
    """Read a regular config in the captured home without following links."""
    path = home / "config.yaml"
    try:
        entry = path.lstat()
    except FileNotFoundError:
        return None
    except OSError:
        raise PrivateBoundaryError("PRIVATE_BOUNDARY_POLICY_INVALID") from None
    if (not stat.S_ISREG(entry.st_mode) or not entry.st_mode & 0o444
            or entry.st_size > MAX_POLICY_CONFIG_BYTES):
        raise PrivateBoundaryError("PRIVATE_BOUNDARY_POLICY_INVALID")
    flags = (os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
             | getattr(os, "O_NONBLOCK", 0))
    try:
        fd = os.open(path, flags)
        try:
            opened = os.fstat(fd)
            if (not stat.S_ISREG(opened.st_mode) or not opened.st_mode & 0o444
                    or (opened.st_dev, opened.st_ino) != (entry.st_dev, entry.st_ino)
                    or opened.st_size > MAX_POLICY_CONFIG_BYTES):
                raise PrivateBoundaryError("PRIVATE_BOUNDARY_POLICY_INVALID")
            with os.fdopen(fd, "rb", closefd=False) as stream:
                raw = stream.read(MAX_POLICY_CONFIG_BYTES + 1)
            if len(raw) > MAX_POLICY_CONFIG_BYTES:
                raise PrivateBoundaryError("PRIVATE_BOUNDARY_POLICY_INVALID")
            return raw.decode("utf-8")
        finally:
            os.close(fd)
    except (OSError, UnicodeError):
        raise PrivateBoundaryError("PRIVATE_BOUNDARY_POLICY_INVALID") from None


def _policy_section(home: Path) -> object:
    """Read only the named policy; reject ambiguous YAML at that boundary.

    Do not feed a permissively merged application config back into this loader:
    duplicate privacy keys must remain observable even if a later value is false.
    Ordinary plugin configuration is not interpreted here.
    """
    raw = _read_policy_config(home)
    if raw is None:
        return None
    try:
        loader = yaml.SafeLoader(raw)
    except Exception:
        raise PrivateBoundaryError("PRIVATE_BOUNDARY_POLICY_INVALID") from None
    try:
        root = loader.get_single_node()
        if root is None:
            return None
        # Limit work before constructing aliases or merged values. The byte
        # limit also caps the parser's token input; this caps node traversal.
        pending = [(root, 0)]
        seen = set()
        while pending:
            node, depth = pending.pop()
            if depth > 100:
                raise PrivateBoundaryError("PRIVATE_BOUNDARY_POLICY_INVALID")
            if id(node) in seen:
                continue
            seen.add(id(node))
            if len(seen) > 10000:
                raise PrivateBoundaryError("PRIVATE_BOUNDARY_POLICY_INVALID")
            if isinstance(node, yaml.MappingNode):
                pending.extend((child, depth + 1) for pair in node.value for child in pair)
            elif isinstance(node, yaml.SequenceNode):
                pending.extend((child, depth + 1) for child in node.value)
        if not isinstance(root, yaml.MappingNode):
            raise PrivateBoundaryError("PRIVATE_BOUNDARY_POLICY_INVALID")
        if any(key.value == "<<" for key, _ in root.value):
            # A merged privacy selector can be hidden from a direct top-level
            # lookup. Require the security policy to be explicit in this file.
            merged = loader.construct_object(root, deep=True)
            if "privacy_boundary" in merged:
                raise PrivateBoundaryError("PRIVATE_BOUNDARY_POLICY_INVALID")
            return None
        nodes = [value for key, value in root.value if key.value == "privacy_boundary"]
        if not nodes:
            return None
        if len(nodes) != 1 or not isinstance(nodes[0], yaml.MappingNode):
            raise PrivateBoundaryError("PRIVATE_BOUNDARY_POLICY_INVALID")
        keys = [key.value for key, _ in nodes[0].value]
        if len(keys) != len(set(keys)) or "<<" in keys:
            raise PrivateBoundaryError("PRIVATE_BOUNDARY_POLICY_INVALID")
        return loader.construct_object(nodes[0], deep=True)
    except Exception:
        raise PrivateBoundaryError("PRIVATE_BOUNDARY_POLICY_INVALID") from None
    finally:
        try:
            loader.dispose()
        except Exception:
            raise PrivateBoundaryError("PRIVATE_BOUNDARY_POLICY_INVALID") from None


@dataclass(frozen=True)
class BoundaryPolicy:
    home: Path
    required: bool
    adapter: str | None
    api_version: int
    digest: str


def load_boundary_policy(home: str | Path) -> BoundaryPolicy:
    """Resolve the same strict captured-home policy for CLI and gateway."""
    captured = canonical_home(home)
    section = _policy_section(captured)
    if section is None:
        section = {"required": False}
    if not isinstance(section, dict) or set(section) - {"required", "adapter", "api_version"}:
        raise PrivateBoundaryError("PRIVATE_BOUNDARY_POLICY_INVALID")
    required = section.get("required")
    adapter = section.get("adapter")
    version = section.get("api_version", BOUNDARY_API_VERSION)
    if type(required) is not bool or type(version) is not int or version < 1:
        raise PrivateBoundaryError("PRIVATE_BOUNDARY_POLICY_INVALID")
    if adapter is not None and (not isinstance(adapter, str) or not _NAME.fullmatch(adapter)):
        raise PrivateBoundaryError("PRIVATE_BOUNDARY_POLICY_INVALID")
    if required and adapter is None:
        raise PrivateBoundaryError("PRIVATE_BOUNDARY_POLICY_INVALID")
    encoded = json.dumps(
        {"required": required, "adapter": adapter, "api_version": version},
        sort_keys=True, separators=(",", ":"),
    ).encode()
    return BoundaryPolicy(captured, required, adapter, version, hashlib.sha256(encoded).hexdigest())


def legacy_whatsapp_send_refused() -> bool:
    """Fail closed for a required or unreadable policy in the active home."""
    from hermes_constants import get_hermes_home

    try:
        return load_boundary_policy(get_hermes_home()).required
    except PrivateBoundaryError:
        return True


@dataclass(frozen=True)
class PrivateToolRegistration:
    name: str
    toolset: str
    schema_json: str = field(repr=False)
    handler: Callable = field(repr=False, compare=False)
    check_fn: Callable = field(repr=False, compare=False)

    @classmethod
    def create(
        cls, *, name: str, toolset: str, schema: Mapping[str, Any],
        handler: Callable, check_fn: Callable,
    ) -> PrivateToolRegistration:
        from tools.registry import registry

        if (not isinstance(name, str) or not _NAME.fullmatch(name)
                or not isinstance(toolset, str) or not _NAME.fullmatch(toolset)
                or not callable(handler) or not callable(check_fn)):
            raise PrivateBoundaryError("PRIVATE_BOUNDARY_REGISTRATION_INVALID")
        if registry.get_entry(name) is not None:
            raise PrivateBoundaryError("PRIVATE_BOUNDARY_DUPLICATE")
        if (not isinstance(schema, dict) or schema.get("name") != name
                or set(schema) - {"name", "description", "parameters", "strict"}
                or not isinstance(schema.get("description"), str)
                or not isinstance(schema.get("parameters"), dict)
                or schema["parameters"].get("type") != "object"):
            raise PrivateBoundaryError("PRIVATE_BOUNDARY_REGISTRATION_INVALID")
        try:
            # Optional for ordinary Hermes profiles, mandatory for a plugin
            # supplying private schemas. Never silently skip schema validation.
            from jsonschema import Draft202012Validator

            Draft202012Validator.check_schema(schema["parameters"])
            frozen = json.dumps(schema, sort_keys=True, separators=(",", ":"), allow_nan=False)
            frozen.encode("utf-8", "strict")
        except Exception:
            raise PrivateBoundaryError("PRIVATE_BOUNDARY_REGISTRATION_INVALID") from None
        return cls(name, toolset, frozen, handler, check_fn)

    def definition(self) -> dict:
        """Return a fresh copy so request adapters cannot mutate the catalog."""
        return {"type": "function", "function": json.loads(self.schema_json)}


@dataclass(frozen=True)
class BoundaryRegistration:
    home: Path
    name: str
    api_version: int
    plugin: str
    factory: Callable = field(repr=False, compare=False)
    tools: tuple[PrivateToolRegistration, ...] = field(default=(), repr=False)

    @classmethod
    def create(
        cls, *, home: Path, name: str, api_version: int, plugin: str,
        factory: Callable, tools: tuple[PrivateToolRegistration, ...] = (),
    ) -> BoundaryRegistration:
        if (not isinstance(name, str) or not _NAME.fullmatch(name)
                or type(api_version) is not int or api_version < 1 or not callable(factory)
                or any(not isinstance(tool, PrivateToolRegistration) for tool in tools)):
            raise PrivateBoundaryError("PRIVATE_BOUNDARY_REGISTRATION_INVALID")
        if len({tool.name for tool in tools}) != len(tools):
            raise PrivateBoundaryError("PRIVATE_BOUNDARY_DUPLICATE")
        return cls(canonical_home(home), name, api_version, plugin, factory, tuple(tools))


def resolve_boundary_registration(
    policy: BoundaryPolicy, registrations: tuple[BoundaryRegistration, ...],
) -> BoundaryRegistration | None:
    """Select a captured-home factory without opening its store or probing tools."""
    if not policy.required:
        return None
    if policy.api_version != BOUNDARY_API_VERSION:
        raise PrivateBoundaryError("PRIVATE_BOUNDARY_INCOMPATIBLE")
    matching = [r for r in registrations if r.home == policy.home and r.name == policy.adapter]
    if len(matching) != 1:
        raise PrivateBoundaryError(
            "PRIVATE_BOUNDARY_DUPLICATE" if matching else "PRIVATE_BOUNDARY_UNAVAILABLE"
        )
    selected = matching[0]
    if selected.api_version != policy.api_version:
        raise PrivateBoundaryError("PRIVATE_BOUNDARY_INCOMPATIBLE")
    return selected


@dataclass(frozen=True)
class BoundaryProfileContext:
    """Explicit factory input; worker code must not consult ambient home state."""

    home: Path
    policy: BoundaryPolicy
    owner_pid: int


_RUNTIME_METHODS = (
    "recover", "retire", "close", "close_unstarted", "assert_ready", "accept", "prepare",
    "deliver", "project", "resolve", "authorize_tool",
)
_RUNTIME_CAPABILITIES = frozenset({
    "admission", "provider", "delivery", "persistence", "tools", "lifecycle",
})
_ID = re.compile(r"[0-9a-f]{32}\Z")
# An unclosed failed factory retains ownership for the life of this process.
# Startup must not GC its private lock and then silently try a replacement.
_FAILED_INITIALIZATIONS: dict[Path, Any] = {}
_OPEN_LOCK = threading.RLock()
_CONSTRUCTION_RUNTIME: ContextVar[BoundaryRuntime | None] = ContextVar(
    "private_boundary_construction_runtime", default=None,
)


@contextmanager
def boundary_construction_scope(runtime: BoundaryRuntime):
    """Pass an owner through existing synchronous plugin adapter factories."""
    runtime.assert_owner()
    token = _CONSTRUCTION_RUNTIME.set(runtime)
    try:
        yield
    finally:
        _CONSTRUCTION_RUNTIME.reset(token)


def capture_adapter_boundary(home: str | Path, *, supported: bool) -> BoundaryRuntime | None:
    """Required direct construction refuses before any legacy adapter caches."""
    policy = load_boundary_policy(home)
    runtime = _CONSTRUCTION_RUNTIME.get()
    if not policy.required:
        if runtime is not None:
            raise PrivateBoundaryError("PRIVATE_BOUNDARY_CONTEXT_INVALID")
        return None
    if not supported or runtime is None:
        raise PrivateBoundaryError("PRIVATE_BOUNDARY_TRANSPORT_UNAVAILABLE")
    runtime.assert_owner()
    if runtime.context.policy != policy or runtime.state not in {"RECOVERING", "READY"}:
        raise PrivateBoundaryError("PRIVATE_BOUNDARY_CONTEXT_INVALID")
    return runtime


class BoundaryRuntime:
    """One captured profile owner, independent of replaceable bridge generations.

    The private implementation owns locks, durable recovery and release proofs.
    This wrapper owns generic identity/epoch checks and the immutable catalog.
    A successful factory call alone is never READY.
    """

    def __init__(
        self, context: BoundaryProfileContext, registration: BoundaryRegistration,
        implementation: Any,
    ) -> None:
        self.context = context
        self.registration = registration
        self._implementation = implementation
        self._state = "RECOVERING"
        self._lock = threading.RLock()
        self._recovery_running = False
        self._close_running = False
        self._fence_failed = False
        self._transport = None
        self._transport_generation: str | None = None
        self.profile_id = implementation.profile_id
        self.configuration_epoch = implementation.configuration_epoch
        self._catalog = tuple(registration.tools)
        self._conversations = {}
        self._local_call_gate = threading.Lock()
        self._local_call_waiter = threading.Lock()
        self._agent_worker_slots = threading.BoundedSemaphore(2)
        self._control_worker_slot = threading.BoundedSemaphore(1)
        self._conversation_workers = set()
        self._handoff_tasks = set()
        self._ingress_command_slots = threading.BoundedSemaphore(2)
        self._ingress_control_slot = threading.BoundedSemaphore(1)

    @property
    def home(self) -> Path:
        return self.context.home

    @property
    def state(self) -> str:
        return self._state

    def assert_owner(self) -> None:
        if os.getpid() != self.context.owner_pid or self._state == "CLOSED":
            raise PrivateBoundaryError("PRIVATE_BOUNDARY_CONTEXT_INVALID")
        try:
            current = load_boundary_policy(self.home)
        except PrivateBoundaryError:
            self.retire()
            raise PrivateBoundaryError("PRIVATE_BOUNDARY_CONTEXT_INVALID") from None
        if current != self.context.policy:
            self.retire()
            raise PrivateBoundaryError("PRIVATE_BOUNDARY_CONTEXT_INVALID")
        try:
            identity_matches = (
                self._implementation.context is self.context
                and self._implementation.profile_id == self.profile_id
                and self._implementation.configuration_epoch == self.configuration_epoch
            )
        except Exception:
            identity_matches = False
        if not identity_matches:
            self.retire()
            raise PrivateBoundaryError("PRIVATE_BOUNDARY_CONTEXT_INVALID")

    def assert_ready(self) -> None:
        self.assert_owner()
        if self._state != "READY":
            raise PrivateBoundaryError("PRIVATE_BOUNDARY_NOT_READY")
        try:
            if self._implementation.assert_ready() is not True:
                raise PrivateBoundaryError("PRIVATE_BOUNDARY_NOT_READY")
        except Exception:
            self.retire()
            raise PrivateBoundaryError("PRIVATE_BOUNDARY_NOT_READY") from None

    async def recover(self) -> None:
        """Complete private safety recovery before allowing transport activation."""
        self.assert_owner()
        with self._lock:
            if self._state != "RECOVERING" or self._recovery_running:
                raise PrivateBoundaryError("PRIVATE_BOUNDARY_CONTEXT_INVALID")
            self._recovery_running = True
        try:
            result = self._implementation.recover()
            if inspect.isawaitable(result):
                result = await result
            if result is not True:
                raise PrivateBoundaryError("PRIVATE_BOUNDARY_NOT_READY")
            self.assert_owner()
            with self._lock:
                if self._state != "RECOVERING":
                    raise PrivateBoundaryError("PRIVATE_BOUNDARY_NOT_READY")
                self._state = "READY"
            self.assert_ready()
        except Exception:
            self.retire()
            raise PrivateBoundaryError("PRIVATE_BOUNDARY_NOT_READY") from None
        except BaseException:
            self.retire()
            raise
        finally:
            with self._lock:
                self._recovery_running = False

    def retire(self) -> None:
        """Fence synchronously; cancellation is not producer-join evidence."""
        with self._lock:
            if self._state in {"RETIRING", "CLOSED"}:
                return
            self._state = "RETIRING"
        try:
            result = self._implementation.retire()
            if inspect.isawaitable(result):
                if inspect.iscoroutine(result):
                    result.close()
                raise PrivateBoundaryError("PRIVATE_BOUNDARY_INCOMPATIBLE")
            for conversation in tuple(self._conversations.values()):
                conversation.cancel()
        except Exception:
            self._fence_failed = True
            raise PrivateBoundaryError("PRIVATE_BOUNDARY_UNAVAILABLE") from None

    async def close(self) -> None:
        if os.getpid() != self.context.owner_pid:
            raise PrivateBoundaryError("PRIVATE_BOUNDARY_CONTEXT_INVALID")
        self.retire()
        with self._lock:
            if self._state == "CLOSED":
                return
            if (self._transport is not None or self._recovery_running
                    or any(c._run_lock.locked() for c in self._conversations.values())
                    or self._conversation_workers
                    or self._handoff_tasks
                    or self._close_running or self._fence_failed):
                raise PrivateBoundaryError("PRIVATE_BOUNDARY_NOT_READY")
            self._close_running = True
        try:
            result = self._implementation.close()
            if inspect.isawaitable(result):
                result = await result
            if result is not True:
                raise PrivateBoundaryError("PRIVATE_BOUNDARY_UNAVAILABLE")
        except Exception:
            # Keep the owner reachable and fenced. A failed close is not proof
            # that its children, model call or store lock can be replaced.
            raise PrivateBoundaryError("PRIVATE_BOUNDARY_UNAVAILABLE") from None
        else:
            with self._lock:
                self._state = "CLOSED"
        finally:
            with self._lock:
                self._close_running = False

    def close_unstarted(self) -> None:
        """Dispose a constructor-owned runtime without claiming producer join."""
        with self._lock:
            if os.getpid() != self.context.owner_pid:
                raise PrivateBoundaryError("PRIVATE_BOUNDARY_CONTEXT_INVALID")
            if self._state == "CLOSED":
                return
            if self._state != "RECOVERING" or self._recovery_running or self._transport is not None:
                raise PrivateBoundaryError("PRIVATE_BOUNDARY_NOT_READY")
            try:
                result = self._implementation.close_unstarted()
                if inspect.isawaitable(result):
                    if inspect.iscoroutine(result):
                        result.close()
                    raise PrivateBoundaryError("PRIVATE_BOUNDARY_INCOMPATIBLE")
                if result is not True:
                    raise PrivateBoundaryError("PRIVATE_BOUNDARY_UNAVAILABLE")
            except BaseException:
                _FAILED_INITIALIZATIONS[self.home] = self._implementation
                raise PrivateBoundaryError("PRIVATE_BOUNDARY_UNAVAILABLE") from None
            self._state = "CLOSED"

    def tool_definitions(self) -> tuple[dict, ...]:
        """Snapshot once at conversation creation; later calls are not a refresh."""
        self.assert_ready()
        from tools.registry import registry

        if any(registry.get_entry(tool.name) is not None for tool in self._catalog):
            self.retire()
            raise PrivateBoundaryError("PRIVATE_BOUNDARY_DUPLICATE")
        return tuple(tool.definition() for tool in sorted(self._catalog, key=lambda t: t.name))

    def conversation(self, binding):
        from hermes_cli.private_conversation import BoundaryConversation, ConversationBinding

        self.assert_ready()
        if not isinstance(binding, ConversationBinding):
            raise PrivateBoundaryError("PRIVATE_BOUNDARY_CONTEXT_INVALID")
        with self._lock:
            existing = self._conversations.get(binding)
            if existing is not None:
                existing.assert_valid()
                return existing
            # The adopted store permits at most 32 retained sessions/profile.
            if len(self._conversations) >= 32:
                raise PrivateBoundaryError("PRIVATE_BOUNDARY_NOT_READY")
            try:
                conversation = BoundaryConversation(self, binding)
            except Exception:
                raise PrivateBoundaryError("PRIVATE_BOUNDARY_UNAVAILABLE") from None
            self._conversations[binding] = conversation
            return conversation

    async def accept(self, event, authenticated_context, cancellation=None):
        """Run mandatory private admission without exposing raw input on failure."""
        from hermes_cli.private_conversation import AcceptedTurn, AdmissionNotice

        self.assert_ready()
        try:
            result = self._implementation.accept(event, authenticated_context, cancellation)
            if inspect.isawaitable(result):
                result = await result
            if not isinstance(result, (AcceptedTurn, AdmissionNotice)):
                raise PrivateBoundaryError("PRIVATE_BOUNDARY_CONTEXT_INVALID")
            self.assert_ready()
            return result
        except BaseException:
            # Admission may have committed a durable claim before losing its
            # acknowledgement. Recovery, never the raw caller, settles it.
            self.retire()
            raise PrivateBoundaryError("PRIVATE_BOUNDARY_NOT_READY") from None

    def submit_handoff(self, event, handler, on_result):
        """Bound ingress tasks so receiving the next control never awaits a turn.

        The private transport owns opaque result delivery and must join these
        tasks during shutdown. Runtime close also refuses while any remain.
        """
        import asyncio
        from hermes_cli.private_conversation import AcceptedTurn, PrivateTurnResult
        self.assert_ready()
        turn = event.private_turn
        if not isinstance(turn, AcceptedTurn):
            raise PrivateBoundaryError("PRIVATE_BOUNDARY_CONTEXT_INVALID")
        slots = self._ingress_command_slots if turn.kind == "command" else self._ingress_control_slot
        if not slots.acquire(blocking=False):
            raise PrivateBoundaryError("PRIVATE_BOUNDARY_NOT_READY")

        async def dispatch():
            try:
                result = await handler(event)
                if not isinstance(result, PrivateTurnResult):
                    raise PrivateBoundaryError("PRIVATE_BOUNDARY_CONTEXT_INVALID")
                await on_result(turn, result)
            except BaseException:
                self.retire()
                raise PrivateBoundaryError("PRIVATE_BOUNDARY_NOT_READY") from None
            finally:
                slots.release()

        task = asyncio.create_task(dispatch())
        self._handoff_tasks.add(task)

        def finished(done):
            self._handoff_tasks.discard(done)
            if not done.cancelled():
                done.exception()

        task.add_done_callback(finished)

    async def join_handoffs(self):
        """Actual transport shutdown awaits completion, not just cancellation."""
        import asyncio
        tasks = tuple(self._handoff_tasks)
        if tasks:
            await asyncio.shield(asyncio.gather(*tasks, return_exceptions=True))

    async def run_handoff(self, turn, create_agent):
        """Bound gateway workers; caller cancellation never discards a live worker."""
        import asyncio
        from hermes_cli.private_conversation import AcceptedTurn

        self.assert_ready()
        if not isinstance(turn, AcceptedTurn):
            raise PrivateBoundaryError("PRIVATE_BOUNDARY_CONTEXT_INVALID")
        context = self.conversation(turn.binding)
        slots = self._agent_worker_slots if turn.kind == "command" else self._control_worker_slot
        if not slots.acquire(blocking=False):
            raise PrivateBoundaryError("PRIVATE_BOUNDARY_NOT_READY")
        cancellation = threading.Event()
        worker = object()
        try:
            with self._lock:
                self.assert_ready()
                self._conversation_workers.add(worker)
        except BaseException:
            slots.release()
            raise

        def work():
            try:
                if turn.kind != "command":
                    return context.consume_control(turn)
                agent = create_agent(context)
                agent._private_turn_cancel = cancellation
                return agent.run_conversation(turn)["boundary_result"]
            except Exception:
                raise PrivateBoundaryError("PRIVATE_BOUNDARY_NOT_READY") from None
            finally:
                with self._lock:
                    self._conversation_workers.discard(worker)
                slots.release()

        try:
            task = asyncio.create_task(asyncio.to_thread(work))
        except BaseException:
            with self._lock:
                self._conversation_workers.discard(worker)
            slots.release()
            raise

        def finished(done):
            if not done.cancelled():
                done.exception()  # Observe a failure even if its caller was cancelled.

        task.add_done_callback(finished)
        try:
            return await asyncio.shield(task)
        except asyncio.CancelledError:
            if turn.kind == "command":
                cancellation.set()
                if context._cancelled is cancellation:
                    context.cancel()
            raise

    def bind_transport(self, transport: Any, generation: str) -> None:
        self.assert_owner()
        if transport is None or not isinstance(generation, str) or not _ID.fullmatch(generation):
            raise PrivateBoundaryError("PRIVATE_BOUNDARY_CONTEXT_INVALID")
        with self._lock:
            if self._state not in {"RECOVERING", "READY"}:
                raise PrivateBoundaryError("PRIVATE_BOUNDARY_NOT_READY")
            if self._transport is not None and (
                self._transport is not transport or self._transport_generation != generation
            ):
                raise PrivateBoundaryError("PRIVATE_BOUNDARY_CONTEXT_INVALID")
            self._transport = transport
            self._transport_generation = generation

    def release_transport(self, transport: Any, generation: str) -> None:
        """Called by the transport owner only after its actual join completes."""
        # Cleanup remains possible after policy/epoch drift has fenced new work.
        # This only releases the exact existing binding; it grants no authority.
        if os.getpid() != self.context.owner_pid:
            raise PrivateBoundaryError("PRIVATE_BOUNDARY_CONTEXT_INVALID")
        with self._lock:
            if (transport is None or self._state == "CLOSED"
                    or self._transport is not transport or self._transport_generation != generation):
                raise PrivateBoundaryError("PRIVATE_BOUNDARY_CONTEXT_INVALID")
            self._transport = None
            self._transport_generation = None

    def transport_for_shutdown(self) -> Any:
        """Retain access to a binding even if its adapter factory never returned."""
        if os.getpid() != self.context.owner_pid:
            raise PrivateBoundaryError("PRIVATE_BOUNDARY_CONTEXT_INVALID")
        with self._lock:
            return self._transport


def open_boundary_runtime(
    home: str | Path, policy: BoundaryPolicy,
    registrations: tuple[BoundaryRegistration, ...],
) -> BoundaryRuntime | None:
    """Create a recovery-only owner; never fall back to an optional boundary.

    Factories are synchronous and must clean up partial initialization before
    raising. They may acquire the private store lock, but cannot launch model,
    helper or transport work during construction.
    """
    with _OPEN_LOCK:
        return _open_boundary_runtime(home, policy, registrations)


def _open_boundary_runtime(home, policy, registrations):
    captured = canonical_home(home)
    if captured in _FAILED_INITIALIZATIONS:
        raise PrivateBoundaryError("PRIVATE_BOUNDARY_UNAVAILABLE")
    if captured != policy.home or load_boundary_policy(captured) != policy:
        raise PrivateBoundaryError("PRIVATE_BOUNDARY_CONTEXT_INVALID")
    registration = resolve_boundary_registration(policy, registrations)
    if registration is None:
        return None
    context = BoundaryProfileContext(captured, policy, os.getpid())
    implementation = None
    try:
        implementation = registration.factory(context)
        if inspect.isawaitable(implementation):
            if inspect.iscoroutine(implementation):
                implementation.close()
            raise PrivateBoundaryError("PRIVATE_BOUNDARY_INCOMPATIBLE")
        if (implementation is None or getattr(implementation, "context", None) is not context
                or getattr(implementation, "api_version", None) != BOUNDARY_API_VERSION
                or type(implementation.api_version) is not int
                or not _RUNTIME_CAPABILITIES.issubset(implementation.capabilities)
                or not isinstance(implementation.profile_id, str)
                or not _ID.fullmatch(implementation.profile_id)
                or not isinstance(implementation.configuration_epoch, str)
                or not _ID.fullmatch(implementation.configuration_epoch)
                or any(not callable(getattr(implementation, name, None)) for name in _RUNTIME_METHODS)):
            raise PrivateBoundaryError("PRIVATE_BOUNDARY_INCOMPATIBLE")
        for name in ("retire", "assert_ready", "close_unstarted"):
            method = getattr(implementation, name)
            if (inspect.iscoroutinefunction(method)
                    or inspect.iscoroutinefunction(getattr(method, "__call__", None))):
                raise PrivateBoundaryError("PRIVATE_BOUNDARY_INCOMPATIBLE")
        runtime = BoundaryRuntime(context, registration, implementation)
        for tool in registration.tools:
            result = tool.check_fn(runtime)
            if inspect.isawaitable(result):
                if inspect.iscoroutine(result):
                    result.close()
                raise PrivateBoundaryError("PRIVATE_BOUNDARY_INCOMPATIBLE")
            if result is not True:
                raise PrivateBoundaryError("PRIVATE_BOUNDARY_NOT_READY")
        runtime.assert_owner()
        return runtime
    except Exception:
        # Only dispose an object that acknowledges this exact factory context;
        # a wrong-profile object may belong to another active runtime.
        if getattr(implementation, "context", None) is context:
            try:
                close = getattr(implementation, "close_unstarted", None)
                result = close() if callable(close) else None
                if inspect.isawaitable(result):
                    if inspect.iscoroutine(result):
                        result.close()
                    result = None
                if result is not True:
                    _FAILED_INITIALIZATIONS[captured] = implementation
            except Exception:
                _FAILED_INITIALIZATIONS[captured] = implementation
        raise PrivateBoundaryError("PRIVATE_BOUNDARY_UNAVAILABLE") from None


def discover_private_boundary_registrations(home: str | Path) -> tuple[BoundaryRegistration, ...]:
    """Use the real plugin loader under a captured home, without global discovery."""
    from hermes_cli.plugins import PluginManager
    from hermes_constants import reset_hermes_home_override, set_hermes_home_override

    captured = canonical_home(home)
    manager = PluginManager(private_boundary_only=True)
    token = set_hermes_home_override(captured)
    try:
        manager.discover_and_load()
        return manager.get_private_boundary_registrations(captured)
    except Exception:
        raise PrivateBoundaryError("PRIVATE_BOUNDARY_UNAVAILABLE") from None
    finally:
        reset_hermes_home_override(token)


class BoundaryRuntimeOwners:
    """Gateway-owned runtimes; reconnect reuses the owner, never reopens a store."""

    def __init__(self) -> None:
        self._runtimes: dict[Path, BoundaryRuntime] = {}
        self._failed: set[Path] = set()
        self._lock = threading.RLock()
        self._closing = False
        self._close_running = False

    def requires_boundary(self, home: str | Path) -> bool:
        """A captured owner cannot downgrade into ordinary gateway handling."""
        captured = canonical_home(home)
        with self._lock:
            return (captured in self._runtimes or captured in self._failed
                    or load_boundary_policy(captured).required)

    def get_or_open(self, home: str | Path) -> BoundaryRuntime | None:
        captured = canonical_home(home)
        with self._lock:
            if self._closing:
                raise PrivateBoundaryError("PRIVATE_BOUNDARY_NOT_READY")
            if captured in self._failed:
                raise PrivateBoundaryError("PRIVATE_BOUNDARY_UNAVAILABLE")
            existing = self._runtimes.get(captured)
            if existing is not None:
                existing.assert_owner()
                if existing.state not in {"RECOVERING", "READY"}:
                    raise PrivateBoundaryError("PRIVATE_BOUNDARY_NOT_READY")
                return existing
            try:
                policy = load_boundary_policy(captured)
                if not policy.required:
                    return None
                registrations = discover_private_boundary_registrations(captured)
                runtime = open_boundary_runtime(captured, policy, registrations)
                if runtime is None:
                    raise PrivateBoundaryError("PRIVATE_BOUNDARY_UNAVAILABLE")
                self._runtimes[captured] = runtime
                return runtime
            except Exception:
                self._failed.add(captured)
                raise PrivateBoundaryError("PRIVATE_BOUNDARY_UNAVAILABLE") from None

    def transports_for_shutdown(self) -> tuple:
        """Stop accepting owners, then expose exact children for actual join."""
        with self._lock:
            self._closing = True
            runtimes = tuple(self._runtimes.values())
        return tuple(
            transport for runtime in runtimes
            if (transport := runtime.transport_for_shutdown()) is not None
        )

    async def close(self) -> None:
        with self._lock:
            if self._close_running:
                raise PrivateBoundaryError("PRIVATE_BOUNDARY_NOT_READY")
            self._closing = True
            self._close_running = True
            runtimes = tuple(self._runtimes.values())
        failed = False
        try:
            for runtime in runtimes:
                try:
                    await runtime.close()
                except Exception:
                    failed = True
        finally:
            with self._lock:
                self._close_running = False
        if failed:
            raise PrivateBoundaryError("PRIVATE_BOUNDARY_UNAVAILABLE")

    async def recover(self) -> None:
        with self._lock:
            if self._closing:
                raise PrivateBoundaryError("PRIVATE_BOUNDARY_NOT_READY")
            runtimes = tuple(self._runtimes.values())
        for runtime in runtimes:
            if runtime.state == "RECOVERING":
                await runtime.recover()
            runtime.assert_ready()

    def close_unstarted(self) -> None:
        with self._lock:
            self._closing = True
            runtimes = tuple(self._runtimes.values())
        failed = False
        for runtime in runtimes:
            try:
                runtime.close_unstarted()
            except PrivateBoundaryError:
                failed = True
        if failed:
            raise PrivateBoundaryError("PRIVATE_BOUNDARY_UNAVAILABLE")
