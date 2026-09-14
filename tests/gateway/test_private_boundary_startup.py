"""Required startup goes through real gateway, registry and base constructors."""

import asyncio
import errno
import logging
import os
import socket
import subprocess
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from types import SimpleNamespace
from unittest.mock import AsyncMock, Mock

import pytest

from gateway.config import GatewayConfig, Platform, PlatformConfig, load_gateway_config
from gateway.platform_registry import PlatformEntry, PlatformRegistry
from gateway.platforms.base import BasePlatformAdapter
from gateway.run import GatewayRunner, _profile_runtime_scope
from hermes_cli.private_boundary import BoundaryRuntimeOwners, PrivateBoundaryError
from tests.gateway._plugin_adapter_loader import load_plugin_adapter
from tests.test_private_boundary_runtime import SyntheticBoundary, install_plugin, required_home


class SyntheticAdapter(BasePlatformAdapter):
    supports_private_boundary = True

    def __init__(self, config):
        super().__init__(config, Platform.WHATSAPP)
        self.connected = 0

    async def connect(self, *, is_reconnect=False):
        self._private_boundary.assert_ready()
        self.connected += 1
        return True

    async def disconnect(self):
        pass

    async def close_private_transport(self):
        await self.disconnect()
        return True

    async def send(self, *args, **kwargs):
        raise AssertionError("Synthetic startup adapter cannot send")

    async def get_chat_info(self, chat_id):
        return {"id": chat_id}


def runner_with_registry(monkeypatch, factory):
    from gateway import platform_registry as module

    registry = PlatformRegistry()
    registry.register(PlatformEntry(
        name="whatsapp", label="Synthetic", adapter_factory=factory, check_fn=lambda: True,
    ))
    monkeypatch.setattr(module, "platform_registry", registry)
    runner = GatewayRunner.__new__(GatewayRunner)
    runner.config = GatewayConfig()
    runner._private_boundary_owners = BoundaryRuntimeOwners()
    return runner


def free_legacy_port():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
        probe.bind(("127.0.0.1", 0))
        return probe.getsockname()[1]


def cutover_adapter(tmp_path):
    adapter_class = load_plugin_adapter("whatsapp").WhatsAppAdapter
    adapter = adapter_class.__new__(adapter_class)
    adapter._private_boundary = object()
    adapter._session_path = tmp_path / "session"
    adapter._session_path.mkdir()
    adapter._bridge_port = free_legacy_port()
    adapter._poll_task = None
    adapter._bridge_process = None
    return adapter


def test_malformed_required_policy_precedes_gateway_constructor_side_effects(tmp_path):
    (tmp_path / "config.yaml").write_text(
        "privacy_boundary: {required: true, required: false, adapter: synthetic}"
    )
    with _profile_runtime_scope(tmp_path):
        with pytest.raises(PrivateBoundaryError, match="POLICY_INVALID"):
            load_gateway_config()
        with pytest.raises(PrivateBoundaryError, match="POLICY_INVALID"):
            GatewayRunner(config=GatewayConfig())
    assert not (tmp_path / "sessions").exists()


def test_direct_whatsapp_construction_refuses_before_legacy_bridge_cache(tmp_path):
    required_home(tmp_path)
    adapter_class = load_plugin_adapter("whatsapp").WhatsAppAdapter
    instance = adapter_class.__new__(adapter_class)
    with _profile_runtime_scope(tmp_path):
        with pytest.raises(PrivateBoundaryError, match="TRANSPORT_UNAVAILABLE"):
            instance.__init__(PlatformConfig(enabled=True))
    assert not hasattr(instance, "_gated_context")
    assert not hasattr(instance, "_message_queue")
    assert not (tmp_path / "platforms").exists()


@pytest.mark.parametrize("is_reconnect", [False, True])
@pytest.mark.parametrize("legacy_owner", ["pidfile", "listener"])
@pytest.mark.asyncio
async def test_private_whatsapp_cutover_refuses_live_legacy_owner_with_fixed_code(
    tmp_path, is_reconnect, legacy_owner,
):
    """T5: the cutover probe observes, but never contacts or kills, legacy state."""
    adapter = cutover_adapter(tmp_path)
    listener = None
    if legacy_owner == "pidfile":
        from gateway.status import get_process_start_time

        start = get_process_start_time(os.getpid())
        assert start is not None
        (adapter._session_path / "bridge.pid").write_text(f"{os.getpid()}\n{start}\n")
    else:
        listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        listener.bind(("127.0.0.1", 0))
        listener.listen()
        listener.settimeout(0.01)
        adapter._bridge_port = listener.getsockname()[1]
    try:
        with pytest.raises(PrivateBoundaryError) as caught:
            await adapter.connect(is_reconnect=is_reconnect)
        assert caught.value.code == "PRIVATE_BOUNDARY_LEGACY_CUTOVER_REQUIRED"
        assert str(caught.value) == "PRIVATE_BOUNDARY_LEGACY_CUTOVER_REQUIRED"
        assert caught.value.context == {
            "reason": "pidfile_live" if legacy_owner == "pidfile" else "port_busy"
        }
        assert adapter._poll_task is None
        assert adapter._bridge_process is None
        if listener is not None:
            with pytest.raises(socket.timeout):
                listener.accept()
            assert listener.fileno() >= 0
    finally:
        if listener is not None:
            listener.close()


@pytest.mark.asyncio
async def test_fake_healthy_bridge_refuses_cold_and_reconnect_without_contact_or_kill(
    tmp_path, monkeypatch,
):
    """T5: one healthy legacy fake stays untouched across both connect shapes."""
    adapter_module = load_plugin_adapter("whatsapp")
    requests = []

    class HealthyBridge(BaseHTTPRequestHandler):
        def do_GET(self):
            requests.append(self.path)
            body = b'{"status":"connected","scriptHash":"synthetic"}'
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *_args):
            pass

    server = ThreadingHTTPServer(("127.0.0.1", 0), HealthyBridge)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    adapter = cutover_adapter(tmp_path)
    adapter._bridge_port = server.server_address[1]
    kill_port = Mock()
    monkeypatch.setattr(adapter_module, "_kill_port_process", kill_port)
    try:
        for is_reconnect in (False, True):
            with pytest.raises(PrivateBoundaryError) as caught:
                await adapter.connect(is_reconnect=is_reconnect)
            assert caught.value.code == "PRIVATE_BOUNDARY_LEGACY_CUTOVER_REQUIRED"
            assert caught.value.context == {"reason": "port_busy"}
        assert requests == []
        assert adapter._poll_task is None
        assert adapter._bridge_process is None
        kill_port.assert_not_called()
        assert thread.is_alive()
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


def test_cutover_loopback_probe_refuses_without_listener_process_lookup(tmp_path, monkeypatch):
    """The socket probe independently detects the address used by bridge.js."""
    adapter_module = load_plugin_adapter("whatsapp")
    adapter = cutover_adapter(tmp_path)
    monkeypatch.setattr(adapter_module, "_listener_pids_on_port", lambda port: [])
    pidfile = adapter._session_path / "bridge.pid"
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.bind(("127.0.0.1", 0))
    listener.listen()
    listener.settimeout(0.01)
    adapter._bridge_port = listener.getsockname()[1]
    try:
        with pytest.raises(PrivateBoundaryError) as caught:
            adapter._check_private_legacy_cutover()
        assert caught.value.code == "PRIVATE_BOUNDARY_LEGACY_CUTOVER_REQUIRED"
        assert caught.value.context == {"reason": "port_busy"}
        assert not pidfile.exists()
        with pytest.raises(socket.timeout):
            listener.accept()
        assert listener.fileno() >= 0
    finally:
        listener.close()


@pytest.mark.parametrize(
    ("method", "args", "kwargs"),
    [
        ("send", ("client", "text"), {}),
        ("edit_message", ("client", "message", "text"), {}),
        ("_send_media_to_bridge", ("client", "/synthetic", "document"), {}),
        ("send_location", ("client", 1.0, 2.0), {}),
        ("send_image", ("client", "https://synthetic.invalid/image"), {}),
        ("send_image_file", ("client", "/synthetic/image"), {}),
        ("send_video", ("client", "/synthetic/video"), {}),
        ("send_voice", ("client", "/synthetic/audio"), {}),
        ("send_document", ("client", "/synthetic/document"), {}),
        ("send_typing", ("client",), {}),
        ("get_chat_info", ("client",), {}),
    ],
)
@pytest.mark.asyncio
async def test_required_mode_refuses_every_legacy_operation(method, args, kwargs):
    adapter_class = load_plugin_adapter("whatsapp").WhatsAppAdapter
    adapter = adapter_class.__new__(adapter_class)
    adapter._private_boundary = object()

    with pytest.raises(PrivateBoundaryError, match="^PRIVATE_BOUNDARY_TRANSPORT_UNAVAILABLE$"):
        await getattr(adapter, method)(*args, **kwargs)


@pytest.mark.asyncio
async def test_required_send_poll_refuses_with_live_http_session():
    import aiohttp

    adapter_class = load_plugin_adapter("whatsapp").WhatsAppAdapter
    adapter = adapter_class.__new__(adapter_class)
    adapter._private_boundary = object()
    async with aiohttp.ClientSession() as session:
        adapter._http_session = session
        assert not session.closed
        with pytest.raises(
            PrivateBoundaryError, match="^PRIVATE_BOUNDARY_TRANSPORT_UNAVAILABLE$"
        ):
            await adapter.send_poll("synthetic@g.us", "question", ["one", "two"])


@pytest.mark.asyncio
async def test_required_send_clarify_refuses_with_live_http_session():
    import aiohttp

    adapter_class = load_plugin_adapter("whatsapp").WhatsAppAdapter
    adapter = adapter_class.__new__(adapter_class)
    adapter._private_boundary = object()
    async with aiohttp.ClientSession() as session:
        adapter._http_session = session
        assert not session.closed
        with pytest.raises(
            PrivateBoundaryError, match="^PRIVATE_BOUNDARY_TRANSPORT_UNAVAILABLE$"
        ):
            await adapter.send_clarify(
                "synthetic@g.us", "question", ["one", "two"], "clarify", "session"
            )


@pytest.mark.asyncio
async def test_private_handoff_calls_no_legacy_cache_helper(tmp_path, monkeypatch):
    from gateway.platforms import base
    from hermes_cli.private_conversation import AcceptedTurn
    from tests.private_boundary_support import install_conversation_plugin

    adapter_module = load_plugin_adapter("whatsapp")
    adapter_class = adapter_module.WhatsAppAdapter
    install_conversation_plugin(tmp_path)
    with _profile_runtime_scope(tmp_path):
        runner = GatewayRunner(config=GatewayConfig())
    runtime = runner._private_boundary_owners.get_or_open(tmp_path)
    await runner._private_boundary_owners.recover()
    backend = runtime._implementation
    input_ref = "4" * 32
    backend.inputs[input_ref] = "Synthetic private cache bypass witness"
    delivered = asyncio.Event()

    class PrivateWhatsAppAdapter(adapter_class):
        async def handle_private_result(self, turn, result):
            delivered.set()

    adapter = PrivateWhatsAppAdapter.__new__(PrivateWhatsAppAdapter)
    adapter._private_boundary = runtime
    adapter._message_handler = runner._handle_message
    spies = {
        "image_url": AsyncMock(),
        "audio_url": AsyncMock(),
        "image_bytes": Mock(),
        "audio_bytes": Mock(),
        "document_bytes": Mock(),
    }
    monkeypatch.setattr(adapter_module, "cache_image_from_url", spies["image_url"])
    monkeypatch.setattr(adapter_module, "cache_audio_from_url", spies["audio_url"])
    monkeypatch.setattr(base, "cache_image_from_bytes", spies["image_bytes"])
    monkeypatch.setattr(base, "cache_audio_from_bytes", spies["audio_bytes"])
    monkeypatch.setattr(base, "cache_document_from_bytes", spies["document_bytes"])
    turn = AcceptedTurn(backend.binding, (input_ref,))
    handoff = SimpleNamespace(
        turn=turn, session_ref="5" * 32, principal_ref="6" * 32, chat_type="group"
    )

    await adapter._accept_native_handoff(handoff)
    await asyncio.wait_for(delivered.wait(), 5)
    await asyncio.wait_for(runtime.join_handoffs(), 5)

    assert backend.requests
    assert backend.requests[0]["messages"][-1]["content"] == (
        "Synthetic private cache bypass witness"
    )
    for spy in spies.values():
        spy.assert_not_called()
    await runner.stop()


@pytest.mark.asyncio
async def test_retained_reply_and_document_delivery_make_zero_legacy_port_connections(
    tmp_path, monkeypatch,
):
    """T5 bullet 7 on the retained path: admission plus the real private
    conversation open zero sockets of any kind, therefore zero to the
    configured legacy port.

    The adapter is the one already accepted for bullets 1/5/6/8 (built through
    ``__new__`` with the real runtime injected), so no ``connect()`` success path
    is involved. Every outbound socket target open during the whole run is
    recorded and the configured legacy port must appear zero times.

    Reply and document delivery are NOT witnessed here: the retained path refuses
    delivery (``gateway/platforms/base.py:4667``, ``infuzd_private/boundary.py:509``),
    so the delivery point this test drives belongs to the subclass below, not to
    production.
    """
    from hermes_cli.private_conversation import AcceptedTurn
    from tests.private_boundary_support import install_conversation_plugin

    adapter_class = load_plugin_adapter("whatsapp").WhatsAppAdapter
    install_conversation_plugin(tmp_path)
    with _profile_runtime_scope(tmp_path):
        runner = GatewayRunner(config=GatewayConfig())
    runtime = runner._private_boundary_owners.get_or_open(tmp_path)
    await runner._private_boundary_owners.recover()
    backend = runtime._implementation
    input_ref = "7" * 32
    backend.inputs[input_ref] = "Synthetic retained bullet 7 input"

    session = tmp_path / "retained-bridge-session"
    session.mkdir()
    legacy_port = free_legacy_port()
    assert not (session / "bridge.pid").exists()

    observed = []

    def record(address):
        if isinstance(address, tuple) and len(address) >= 2:
            observed.append((address[0], address[1]))
        else:
            observed.append(address)

    real_connect = socket.socket.connect
    real_connect_ex = socket.socket.connect_ex
    real_create_connection = socket.create_connection

    def spy_connect(instance, address):
        record(address)
        return real_connect(instance, address)

    def spy_connect_ex(instance, address):
        record(address)
        return real_connect_ex(instance, address)

    def spy_create_connection(address, *args, **kwargs):
        record(address)
        return real_create_connection(address, *args, **kwargs)

    monkeypatch.setattr(socket.socket, "connect", spy_connect)
    monkeypatch.setattr(socket.socket, "connect_ex", spy_connect_ex)
    monkeypatch.setattr(socket, "create_connection", spy_create_connection)

    deliveries = []
    replied = asyncio.Event()

    class RetainedAdapter(adapter_class):
        async def handle_private_result(self, turn, result):
            deliveries.append(result)
            if result.status == "completed":
                replied.set()

    adapter = RetainedAdapter.__new__(RetainedAdapter)
    adapter._private_boundary = runtime
    adapter._message_handler = runner._handle_message
    adapter._bridge_port = legacy_port
    adapter._session_path = session
    adapter._poll_task = None
    adapter._bridge_process = None

    turn = AcceptedTurn(backend.binding, (input_ref,))
    handoff = SimpleNamespace(
        turn=turn, session_ref="8" * 32, principal_ref="9" * 32, chat_type="group"
    )

    await adapter._accept_native_handoff(handoff)
    await asyncio.wait_for(replied.wait(), 5)
    await asyncio.wait_for(runtime.join_handoffs(), 5)

    reply = deliveries[0]
    assert reply.status == "completed"
    assert backend.requests
    assert backend.requests[0]["messages"][-1]["content"] == (
        "Synthetic retained bullet 7 input"
    )

    legacy_targets = [
        target for target in observed
        if isinstance(target, tuple) and len(target) == 2 and target[1] == legacy_port
    ]
    assert legacy_targets == []
    await runner.stop()


@pytest.mark.asyncio
async def test_required_mode_adapter_connects_and_closes_without_touching_legacy(tmp_path, monkeypatch):
    """T9 bullets 1, 2 and 5 on the real class, the real flag, real capture.

    No legacy pidfile exists and nothing listens on the configured legacy port.
    The production ``WhatsAppAdapter`` is built through the real platform
    registry with its own ``supports_private_boundary`` flag, connects for both
    ``is_reconnect`` values without spawning, probing, adopting, polling or
    opening anything, records zero connections to the legacy port, and closes
    through ``close_private_transport()`` so the runtime releases it. A profile
    whose policy is not required captures no boundary at all.
    """
    from hermes_cli.private_boundary import capture_adapter_boundary
    from tests.private_boundary_support import install_conversation_plugin

    adapter_module = load_plugin_adapter("whatsapp")
    adapter_class = adapter_module.WhatsAppAdapter
    install_conversation_plugin(tmp_path)
    session = tmp_path / "required-bridge-session"
    session.mkdir()
    legacy_port = free_legacy_port()
    assert not (session / "bridge.pid").exists()

    observed = []

    def record(address):
        if isinstance(address, tuple) and len(address) >= 2:
            observed.append((address[0], address[1]))
        else:
            observed.append(address)

    real_connect = socket.socket.connect
    real_connect_ex = socket.socket.connect_ex
    real_create_connection = socket.create_connection

    def spy_connect(instance, address):
        record(address)
        return real_connect(instance, address)

    def spy_connect_ex(instance, address):
        record(address)
        return real_connect_ex(instance, address)

    def spy_create_connection(address, *args, **kwargs):
        record(address)
        return real_create_connection(address, *args, **kwargs)

    monkeypatch.setattr(socket.socket, "connect", spy_connect)
    monkeypatch.setattr(socket.socket, "connect_ex", spy_connect_ex)
    monkeypatch.setattr(socket, "create_connection", spy_create_connection)

    with _profile_runtime_scope(tmp_path):
        runner = GatewayRunner(config=GatewayConfig())
        runtime = runner._private_boundary_owners.get_or_open(tmp_path)
        await runner._private_boundary_owners.recover()
        adapter = runner._create_adapter(
            Platform.WHATSAPP,
            PlatformConfig(enabled=True, extra={
                "bridge_port": legacy_port,
                "session_path": str(session),
            }),
        )
        assert adapter._private_boundary is runtime
        assert adapter.supports_private_boundary is True
        assert await runner._connect_adapter_with_timeout(adapter, Platform.WHATSAPP) is True
        assert adapter.is_connected is True
        assert await adapter.connect(is_reconnect=True) is True
        assert adapter._bridge_process is None
        assert adapter._poll_task is None
        assert getattr(adapter, "_http_session", None) is None
        legacy_targets = [
            target for target in observed
            if isinstance(target, tuple) and len(target) == 2 and target[1] == legacy_port
        ]
        assert legacy_targets == []
        await runner._disconnect_private_adapter(adapter)
        assert adapter._private_transport_released is True
        assert adapter.is_connected is False

    legacy_home = tmp_path / "legacy-profile"
    legacy_home.mkdir()
    (legacy_home / "config.yaml").write_text("privacy_boundary: {required: false}\n")
    with _profile_runtime_scope(legacy_home):
        assert capture_adapter_boundary(
            legacy_home, supported=adapter_class.supports_private_boundary,
        ) is None
        legacy_adapter = adapter_class(PlatformConfig(enabled=True, extra={
            "bridge_port": free_legacy_port(),
            "session_path": str(tmp_path / "legacy-session"),
        }))
    assert getattr(legacy_adapter, "_private_boundary", None) is None
    await runner._private_boundary_owners.close()


def _production_adapter(adapter_class, runtime, runner, session):
    adapter = adapter_class.__new__(adapter_class)
    adapter._private_boundary = runtime
    adapter._message_handler = runner._handle_message
    adapter._bridge_port = free_legacy_port()
    adapter._session_path = session
    adapter._poll_task = None
    adapter._bridge_process = None
    return adapter


async def _hand_off(adapter, backend, input_ref):
    from hermes_cli.private_conversation import AcceptedTurn

    backend.inputs[input_ref] = "Synthetic rule 5 input"
    turn = AcceptedTurn(backend.binding, (input_ref,))
    event = SimpleNamespace(
        turn=turn, session_ref="8" * 32, principal_ref="9" * 32, chat_type="group",
    )
    await adapter._accept_native_handoff(event)


@pytest.mark.asyncio
async def test_production_adapter_counts_each_private_delivery_refusal(tmp_path, monkeypatch):
    """T9 bullet 6 (revision 6.1): the real adapter counts NOT_READY refusals.

    Neither the production class nor its flag is monkeypatched. The conversation
    runs and projects ``completed``; delivery is refused with the NOT_READY
    refusal, which the override catches without retiring the runtime, so the
    counter reads 1 after one handoff and 2 after a second, with
    ``assert_ready()`` holding in both cases. The same adapter then receives a
    handoff whose ``deliver`` accepts delivery, which leaves the counter
    unchanged at 2 and ``backend.requests`` at 3.
    """
    from tests.private_boundary_support import install_conversation_plugin

    adapter_class = load_plugin_adapter("whatsapp").WhatsAppAdapter
    install_conversation_plugin(tmp_path)
    with _profile_runtime_scope(tmp_path):
        runner = GatewayRunner(config=GatewayConfig())
    runtime = runner._private_boundary_owners.get_or_open(tmp_path)
    await runner._private_boundary_owners.recover()
    backend = runtime._implementation
    session = tmp_path / "required-bridge-session"
    session.mkdir()
    adapter = _production_adapter(adapter_class, runtime, runner, session)

    await _hand_off(adapter, backend, "7" * 32)
    await asyncio.wait_for(runtime.join_handoffs(), 5)
    runtime.assert_ready()
    assert adapter._private_delivery_refusals == 1
    assert len(backend.requests) == 1
    assert backend.persisted[-1][0] == "completed"

    await _hand_off(adapter, backend, "a" * 32)
    await asyncio.wait_for(runtime.join_handoffs(), 5)
    runtime.assert_ready()
    assert adapter._private_delivery_refusals == 2
    assert len(backend.requests) == 2

    monkeypatch.setattr(backend, "deliver", lambda *args, **kwargs: None)
    await _hand_off(adapter, backend, "b" * 32)
    await asyncio.wait_for(runtime.join_handoffs(), 5)
    runtime.assert_ready()
    assert adapter._private_delivery_refusals == 2
    assert len(backend.requests) == 3
    await runner.stop()


@pytest.mark.asyncio
async def test_unknown_private_delivery_fault_retires_the_runtime(tmp_path, monkeypatch):
    """T9 bullet 7 (revision 6.1): unknown delivery faults stay loud.

    A ``deliver()`` raising anything other than the NOT_READY refusal propagates
    out of the override; ``dispatch()`` catches it and retires the runtime, so
    ``assert_ready()`` raises NOT_READY afterwards with the refusal counter
    untouched.
    """
    from tests.private_boundary_support import install_conversation_plugin

    adapter_class = load_plugin_adapter("whatsapp").WhatsAppAdapter
    install_conversation_plugin(tmp_path)
    with _profile_runtime_scope(tmp_path):
        runner = GatewayRunner(config=GatewayConfig())
    runtime = runner._private_boundary_owners.get_or_open(tmp_path)
    await runner._private_boundary_owners.recover()
    backend = runtime._implementation
    session = tmp_path / "required-bridge-session"
    session.mkdir()
    adapter = _production_adapter(adapter_class, runtime, runner, session)

    def explode(*args, **kwargs):
        raise ValueError("synthetic-unknown-fault")

    monkeypatch.setattr(backend, "deliver", explode)

    await _hand_off(adapter, backend, "c" * 32)
    await asyncio.wait_for(runtime.join_handoffs(), 5)
    with pytest.raises(PrivateBoundaryError) as caught:
        runtime.assert_ready()
    assert caught.value.code == "PRIVATE_BOUNDARY_NOT_READY"
    assert adapter._private_delivery_refusals == 0
    assert backend.requests and backend.persisted[-1][0] == "completed"
    await runner.stop()


@pytest.mark.asyncio
async def test_base_identity_guard_refuses_handoff_without_result_override(tmp_path):
    """R15-C-6: the base identity guard refuses a handoff it cannot deliver.

    A throwaway adapter binds the real runtime and the real message handler but
    keeps ``BasePlatformAdapter.handle_private_result``, so the guard at
    ``gateway/platforms/base.py:4686-4687`` raises the fixed
    ``PRIVATE_BOUNDARY_TRANSPORT_UNAVAILABLE`` code before anything is
    submitted and the backend never sees a request.
    """
    from hermes_cli.private_conversation import AcceptedTurn
    from tests.private_boundary_support import install_conversation_plugin

    class IdentityGuardAdapter(BasePlatformAdapter):
        supports_private_boundary = True

        async def connect(self, *, is_reconnect=False):
            return True

        async def disconnect(self):
            pass

        async def close_private_transport(self):
            await self.disconnect()
            return True

        async def send(self, *args, **kwargs):
            raise AssertionError("IdentityGuardAdapter cannot send")

        async def get_chat_info(self, chat_id):
            return {"id": chat_id}

    install_conversation_plugin(tmp_path)
    with _profile_runtime_scope(tmp_path):
        runner = GatewayRunner(config=GatewayConfig())
    runtime = runner._private_boundary_owners.get_or_open(tmp_path)
    await runner._private_boundary_owners.recover()
    backend = runtime._implementation
    adapter = IdentityGuardAdapter.__new__(IdentityGuardAdapter)
    adapter._private_boundary = runtime
    adapter._message_handler = runner._handle_message

    event = SimpleNamespace(private_turn=AcceptedTurn(backend.binding, ("d" * 32,)))
    with pytest.raises(PrivateBoundaryError) as caught:
        await adapter.handle_message(event)
    assert caught.value.code == "PRIVATE_BOUNDARY_TRANSPORT_UNAVAILABLE"
    await asyncio.wait_for(runtime.join_handoffs(), 5)
    assert backend.requests == []
    await runner.stop()


def test_bridge_port_is_coerced_to_int(tmp_path):
    adapter_class = load_plugin_adapter("whatsapp").WhatsAppAdapter
    port = free_legacy_port()
    with _profile_runtime_scope(tmp_path):
        adapter = adapter_class(PlatformConfig(extra={
            "bridge_port": str(port),
            "session_path": str(tmp_path / "session"),
        }))
    assert adapter._bridge_port == port
    assert type(adapter._bridge_port) is int


@pytest.mark.parametrize("port", [0, -1, 65536])
def test_bridge_port_must_be_in_bindable_range(tmp_path, port):
    adapter_class = load_plugin_adapter("whatsapp").WhatsAppAdapter
    with _profile_runtime_scope(tmp_path):
        with pytest.raises(ValueError, match="^bridge_port must be between 1 and 65535$"):
            adapter_class(PlatformConfig(extra={
                "bridge_port": port,
                "session_path": str(tmp_path / "session"),
            }))


def test_cutover_ignores_dead_pid(tmp_path):
    adapter = cutover_adapter(tmp_path)
    process = subprocess.Popen([sys.executable, "-c", "pass"])
    process.wait(timeout=10)
    (adapter._session_path / "bridge.pid").write_text(f"{process.pid}\n")

    adapter._check_private_legacy_cutover()


@pytest.mark.parametrize("contents", ["", "not-a-pid\n"])
def test_cutover_ignores_malformed_pidfile(tmp_path, contents):
    adapter = cutover_adapter(tmp_path)
    (adapter._session_path / "bridge.pid").write_text(contents)

    adapter._check_private_legacy_cutover()


def test_cutover_ignores_reused_pid(tmp_path, monkeypatch):
    from gateway import status

    adapter = cutover_adapter(tmp_path)
    (adapter._session_path / "bridge.pid").write_text(f"{os.getpid()}\n100\n")
    monkeypatch.setattr(status, "get_process_start_time", lambda pid: 200)

    adapter._check_private_legacy_cutover()


def test_cutover_ignores_unavailable_ipv6(tmp_path, monkeypatch):
    adapter = cutover_adapter(tmp_path)
    real_socket = socket.socket

    def without_ipv6(family, *args, **kwargs):
        if family == socket.AF_INET6:
            raise OSError(errno.EAFNOSUPPORT, "synthetic no IPv6")
        return real_socket(family, *args, **kwargs)

    monkeypatch.setattr(socket, "socket", without_ipv6)
    adapter._check_private_legacy_cutover()


def test_cutover_ignores_time_wait_socket(tmp_path):
    adapter = cutover_adapter(tmp_path)
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.bind(("127.0.0.1", 0))
    listener.listen()
    adapter._bridge_port = listener.getsockname()[1]
    client = socket.create_connection(listener.getsockname())
    accepted, _ = listener.accept()
    accepted.close()
    client.close()
    listener.close()

    adapter._check_private_legacy_cutover()


@pytest.mark.asyncio
async def test_real_primary_secondary_factories_capture_and_reuse_only_their_owner(tmp_path, monkeypatch):
    first_home, second_home = tmp_path / "a", tmp_path / "b"
    install_plugin(first_home)
    install_plugin(second_home)
    runner = runner_with_registry(monkeypatch, SyntheticAdapter)
    with _profile_runtime_scope(first_home):
        first = runner._create_adapter(Platform.WHATSAPP, PlatformConfig(enabled=True))
        assert await runner._connect_adapter_with_timeout(first, Platform.WHATSAPP)
        await runner._disconnect_private_adapter(first)
        replacement = runner._create_adapter(Platform.WHATSAPP, PlatformConfig(enabled=True))
    with _profile_runtime_scope(second_home):
        second = runner._create_adapter(Platform.WHATSAPP, PlatformConfig(enabled=True))
        assert await runner._connect_adapter_with_timeout(second, Platform.WHATSAPP)
    assert first._private_boundary is replacement._private_boundary
    assert first._private_boundary is not second._private_boundary
    assert first._private_boundary.home == first_home
    assert second._private_boundary.home == second_home
    await runner._disconnect_private_adapter(replacement)
    await runner._disconnect_private_adapter(second)
    await runner._private_boundary_owners.close()


@pytest.mark.asyncio
async def test_policy_downgrade_cannot_reconnect_through_optional_factory(tmp_path, monkeypatch):
    install_plugin(tmp_path)
    created = []

    def factory(config):
        adapter = SyntheticAdapter(config)
        created.append(adapter)
        return adapter

    runner = runner_with_registry(monkeypatch, factory)
    with _profile_runtime_scope(tmp_path):
        runner._create_adapter(Platform.WHATSAPP, PlatformConfig(enabled=True))
        (tmp_path / "config.yaml").write_text("privacy_boundary: {required: false}")
        with pytest.raises(PrivateBoundaryError, match="CONTEXT_INVALID"):
            runner._create_adapter(Platform.WHATSAPP, PlatformConfig(enabled=True))
    assert len(created) == 1
    assert created[0]._private_boundary.state == "RETIRING"
    await runner._disconnect_private_adapter(created[0])
    await runner._private_boundary_owners.close()


@pytest.mark.parametrize("failure", ["none", "throw", "unbound"])
@pytest.mark.asyncio
async def test_required_factory_failure_never_falls_back_or_logs_private_exception(
    tmp_path, monkeypatch, caplog, failure,
):
    install_plugin(tmp_path)

    def factory(config):
        if failure == "throw":
            raise RuntimeError("synthetic-secret-factory-detail")
        return None if failure == "none" else object()

    runner = runner_with_registry(monkeypatch, factory)
    with _profile_runtime_scope(tmp_path):
        with pytest.raises(PrivateBoundaryError, match="TRANSPORT_UNAVAILABLE"):
            runner._create_adapter(Platform.WHATSAPP, PlatformConfig(enabled=True))
        with pytest.raises(PrivateBoundaryError):
            runner._private_boundary_owners.get_or_open(tmp_path)
    assert "synthetic-secret-factory-detail" not in caplog.text
    await runner._private_boundary_owners.close()


@pytest.mark.parametrize("failure", ["false", "throw", "timeout", "cancel"])
@pytest.mark.asyncio
async def test_required_connect_failure_is_fatal_and_keeps_owner(tmp_path, monkeypatch, failure):
    install_plugin(tmp_path)
    entered = asyncio.Event()

    class FailingAdapter(SyntheticAdapter):
        async def connect(self, *, is_reconnect=False):
            self._private_boundary.assert_ready()
            entered.set()
            if failure in {"timeout", "cancel"}:
                await asyncio.Event().wait()
            if failure == "throw":
                raise RuntimeError("synthetic-secret-connect-detail")
            return False

    runner = runner_with_registry(monkeypatch, FailingAdapter)
    runner._platform_connect_timeout_secs = lambda: 0.01 if failure == "timeout" else 0
    with _profile_runtime_scope(tmp_path):
        adapter = runner._create_adapter(Platform.WHATSAPP, PlatformConfig(enabled=True))
    task = asyncio.create_task(runner._connect_adapter_with_timeout(adapter, Platform.WHATSAPP))
    await entered.wait()
    if failure == "cancel":
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task
    else:
        with pytest.raises(PrivateBoundaryError, match="^PRIVATE_BOUNDARY_TRANSPORT_UNAVAILABLE$"):
            await task
    assert adapter._private_boundary.state == "RETIRING"
    with pytest.raises(PrivateBoundaryError):
        runner._private_boundary_owners.get_or_open(tmp_path)
    await runner._disconnect_private_adapter(adapter)
    await runner._private_boundary_owners.close()


@pytest.mark.asyncio
async def test_run_path_logs_cutover_code_and_reason_before_substitution(tmp_path):
    adapter = cutover_adapter(tmp_path)
    retire = Mock()
    runtime = SimpleNamespace(state="READY", assert_ready=lambda: None, retire=retire)
    adapter._private_boundary = runtime
    from gateway.status import get_process_start_time

    start = get_process_start_time(os.getpid())
    assert start is not None
    pidfile = adapter._session_path / "bridge.pid"
    contents = f"{os.getpid()}\n{start}\n"
    pidfile.write_text(contents)
    runner = GatewayRunner.__new__(GatewayRunner)
    runner._platform_connect_timeout_secs = lambda: 0
    records = []

    class RecordHandler(logging.Handler):
        def emit(self, record):
            records.append(record)

    gateway_logger = logging.getLogger("gateway.run")
    handler = RecordHandler()
    original_level = gateway_logger.level
    gateway_logger.setLevel(logging.WARNING)
    gateway_logger.addHandler(handler)

    try:
        with pytest.raises(PrivateBoundaryError) as caught:
            await runner._connect_adapter_with_timeout(adapter, Platform.WHATSAPP)
    finally:
        gateway_logger.removeHandler(handler)
        gateway_logger.setLevel(original_level)

    assert caught.value.code == "PRIVATE_BOUNDARY_TRANSPORT_UNAVAILABLE"
    assert str(caught.value) == "PRIVATE_BOUNDARY_TRANSPORT_UNAVAILABLE"
    retire.assert_called_once_with()
    assert pidfile.read_text() == contents
    assert len(records) == 1
    assert records[0].levelno == logging.WARNING
    assert records[0].getMessage() == (
        "Private boundary adapter connect failed: "
        "type=PrivateBoundaryError code=PRIVATE_BOUNDARY_LEGACY_CUTOVER_REQUIRED "
        "context={'reason': 'pidfile_live'}"
    )


@pytest.mark.asyncio
async def test_run_path_logs_timeout_type_before_transport_substitution(caplog):
    entered = asyncio.Event()

    class TimedOutAdapter:
        async def connect(self, *, is_reconnect=False):
            entered.set()
            raise asyncio.TimeoutError("synthetic private detail")

    runtime = SimpleNamespace(state="READY", assert_ready=lambda: None, retire=Mock())
    adapter = TimedOutAdapter()
    adapter._private_boundary = runtime
    runner = GatewayRunner.__new__(GatewayRunner)
    runner._platform_connect_timeout_secs = lambda: 0

    caplog.set_level(logging.WARNING, logger="gateway.run")
    with pytest.raises(PrivateBoundaryError) as caught:
        await runner._connect_adapter_with_timeout(adapter, Platform.WHATSAPP)

    assert entered.is_set()
    assert caught.value.code == "PRIVATE_BOUNDARY_TRANSPORT_UNAVAILABLE"
    assert caught.value.__cause__ is None
    runtime.retire.assert_called_once_with()
    records = [record for record in caplog.records if record.name == "gateway.run"]
    assert len(records) == 1
    assert records[0].levelno == logging.WARNING
    assert records[0].getMessage() == (
        "Private boundary adapter connect failed: type=TimeoutError"
    )
    assert "synthetic private detail" not in caplog.text


@pytest.mark.asyncio
async def test_run_path_logs_cutover_before_failed_retirement(tmp_path, caplog):
    adapter = cutover_adapter(tmp_path)

    def failed_retire():
        raise PrivateBoundaryError("PRIVATE_BOUNDARY_UNAVAILABLE")

    runtime = SimpleNamespace(
        state="READY", assert_ready=lambda: None, retire=Mock(side_effect=failed_retire)
    )
    adapter._private_boundary = runtime
    from gateway.status import get_process_start_time

    start = get_process_start_time(os.getpid())
    assert start is not None
    (adapter._session_path / "bridge.pid").write_text(f"{os.getpid()}\n{start}\n")
    runner = GatewayRunner.__new__(GatewayRunner)
    runner._platform_connect_timeout_secs = lambda: 0

    caplog.set_level(logging.WARNING, logger="gateway.run")
    with pytest.raises(PrivateBoundaryError) as caught:
        await runner._connect_adapter_with_timeout(adapter, Platform.WHATSAPP)

    assert caught.value.code == "PRIVATE_BOUNDARY_TRANSPORT_UNAVAILABLE"
    assert caught.value.__cause__ is None
    runtime.retire.assert_called_once_with()
    records = [record for record in caplog.records if record.name == "gateway.run"]
    assert [record.getMessage() for record in records] == [
        (
            "Private boundary adapter connect failed: "
            "type=PrivateBoundaryError code=PRIVATE_BOUNDARY_LEGACY_CUTOVER_REQUIRED "
            "context={'reason': 'pidfile_live'}"
        ),
        "Private boundary runtime retirement failed: type=PrivateBoundaryError",
    ]


@pytest.mark.parametrize("retire_error", [RuntimeError, SystemExit])
@pytest.mark.asyncio
async def test_cancelled_connect_survives_failed_retirement_without_private_log(
    caplog, retire_error,
):
    entered = asyncio.Event()

    class PendingAdapter:
        async def connect(self, *, is_reconnect=False):
            entered.set()
            await asyncio.Event().wait()

    runtime = SimpleNamespace(
        state="READY",
        assert_ready=lambda: None,
        retire=Mock(side_effect=retire_error("synthetic private retirement detail")),
    )
    adapter = PendingAdapter()
    adapter._private_boundary = runtime
    runner = GatewayRunner.__new__(GatewayRunner)
    runner._platform_connect_timeout_secs = lambda: 0

    caplog.set_level(logging.WARNING, logger="gateway.run")
    task = asyncio.create_task(
        runner._connect_adapter_with_timeout(adapter, Platform.WHATSAPP)
    )
    await entered.wait()
    task.cancel()
    with pytest.raises(asyncio.CancelledError) as caught:
        await task

    assert task.cancelled() is True
    assert caught.value.__cause__ is None
    runtime.retire.assert_called_once_with()
    records = [record for record in caplog.records if record.name == "gateway.run"]
    assert len(records) == 1
    assert records[0].levelno == logging.WARNING
    assert records[0].getMessage() == (
        f"Private boundary runtime retirement failed: type={retire_error.__name__}"
    )
    assert "synthetic private retirement detail" not in caplog.text


@pytest.mark.parametrize("retire_error", [RuntimeError, SystemExit])
@pytest.mark.asyncio
async def test_cancelled_disconnect_survives_failed_retirement_without_private_log(
    caplog, retire_error,
):
    entered = asyncio.Event()
    release = asyncio.Event()

    class PendingAdapter:
        _private_transport_released = False
        _private_disconnect_task = None

        async def close_private_transport(self):
            entered.set()
            await release.wait()
            return True

    runtime = SimpleNamespace(
        retire=Mock(side_effect=retire_error("synthetic private retirement detail")),
    )
    adapter = PendingAdapter()
    adapter._private_boundary = runtime
    runner = GatewayRunner.__new__(GatewayRunner)

    caplog.set_level(logging.WARNING, logger="gateway.run")
    task = asyncio.create_task(runner._disconnect_private_adapter(adapter))
    await entered.wait()
    task.cancel()
    with pytest.raises(asyncio.CancelledError) as caught:
        await task

    assert task.cancelled() is True
    assert caught.value.__cause__ is None
    runtime.retire.assert_called_once_with()
    records = [record for record in caplog.records if record.name == "gateway.run"]
    assert len(records) == 1
    assert records[0].levelno == logging.WARNING
    assert records[0].getMessage() == (
        f"Private boundary runtime retirement failed: type={retire_error.__name__}"
    )
    assert "synthetic private retirement detail" not in caplog.text
    release.set()
    await adapter._private_disconnect_task


@pytest.mark.asyncio
async def test_failed_private_join_logs_bounded_type_before_retirement(caplog):
    class FailedJoinAdapter:
        _private_transport_released = False
        _private_disconnect_task = None

        async def close_private_transport(self):
            return False

    runtime = SimpleNamespace(retire=Mock())
    adapter = FailedJoinAdapter()
    adapter._private_boundary = runtime
    runner = GatewayRunner.__new__(GatewayRunner)

    caplog.set_level(logging.WARNING, logger="gateway.run")
    with pytest.raises(PrivateBoundaryError, match="PRIVATE_BOUNDARY_NOT_READY"):
        await runner._disconnect_private_adapter(adapter)

    runtime.retire.assert_called_once_with()
    records = [record for record in caplog.records if record.name == "gateway.run"]
    assert [record.getMessage() for record in records] == [
        "Private boundary adapter disconnect failed: type=PrivateBoundaryError"
    ]


def test_create_adapter_retire_failure_preserves_transport_error_and_bounded_log(
    tmp_path, caplog,
):
    required_home(tmp_path)
    runtime = SimpleNamespace(
        retire=Mock(side_effect=RuntimeError("synthetic private retirement detail")),
    )
    runner = GatewayRunner.__new__(GatewayRunner)
    runner._private_boundary_home = tmp_path
    runner._private_boundary_owners = SimpleNamespace(get_or_open=lambda home: runtime)
    runner._create_platform_adapter = Mock(
        side_effect=RuntimeError("synthetic private factory detail")
    )

    caplog.set_level(logging.WARNING, logger="gateway.run")
    with _profile_runtime_scope(tmp_path):
        with pytest.raises(PrivateBoundaryError) as caught:
            runner._create_adapter(Platform.WHATSAPP, PlatformConfig(enabled=True))

    assert caught.value.code == "PRIVATE_BOUNDARY_TRANSPORT_UNAVAILABLE"
    assert caught.value.__cause__ is None
    runtime.retire.assert_called_once_with()
    records = [record for record in caplog.records if record.name == "gateway.run"]
    assert [record.getMessage() for record in records] == [
        "Private boundary runtime retirement failed: type=RuntimeError"
    ]
    assert "synthetic private" not in caplog.text


def test_create_adapter_system_exit_retirement_propagates_without_private_log(
    tmp_path, caplog,
):
    required_home(tmp_path)
    canary = "SYNTHETIC_PRIVATE_FACTORY_CANARY_15550000001"
    retire_error = SystemExit("synthetic retirement interrupt")
    runtime = SimpleNamespace(retire=Mock(side_effect=retire_error))
    runner = GatewayRunner.__new__(GatewayRunner)
    runner._private_boundary_home = tmp_path
    runner._private_boundary_owners = SimpleNamespace(get_or_open=lambda home: runtime)
    runner._create_platform_adapter = Mock(side_effect=RuntimeError(canary))

    caplog.set_level(logging.WARNING, logger="gateway.run")
    with _profile_runtime_scope(tmp_path):
        with pytest.raises(SystemExit) as caught:
            runner._create_adapter(Platform.WHATSAPP, PlatformConfig(enabled=True))

    assert caught.value is retire_error
    assert caught.value.__cause__ is None
    assert not isinstance(caught.value, PrivateBoundaryError)
    runtime.retire.assert_called_once_with()
    records = [record for record in caplog.records if record.name == "gateway.run"]
    assert len(records) == 1
    assert records[0].levelno == logging.WARNING
    assert records[0].getMessage() == (
        "Private boundary runtime retirement failed: type=SystemExit"
    )
    assert canary not in caplog.text


@pytest.mark.asyncio
async def test_connect_adapter_system_exit_retirement_propagates_without_private_log(
    caplog,
):
    canary = "SYNTHETIC_PRIVATE_CONNECT_CANARY_15550000001"
    retire_error = SystemExit("synthetic retirement interrupt")

    class FailedAdapter:
        async def connect(self, *, is_reconnect=False):
            raise RuntimeError(canary)

    runtime = SimpleNamespace(
        state="READY",
        assert_ready=lambda: None,
        retire=Mock(side_effect=retire_error),
    )
    adapter = FailedAdapter()
    adapter._private_boundary = runtime
    runner = GatewayRunner.__new__(GatewayRunner)
    runner._platform_connect_timeout_secs = lambda: 0

    caplog.set_level(logging.WARNING, logger="gateway.run")
    with pytest.raises(SystemExit) as caught:
        await runner._connect_adapter_with_timeout(adapter, Platform.WHATSAPP)

    assert caught.value is retire_error
    assert caught.value.__cause__ is None
    assert not isinstance(caught.value, PrivateBoundaryError)
    runtime.retire.assert_called_once_with()
    records = [record for record in caplog.records if record.name == "gateway.run"]
    assert [record.levelno for record in records] == [logging.WARNING, logging.WARNING]
    assert [record.getMessage() for record in records] == [
        "Private boundary adapter connect failed: type=RuntimeError",
        "Private boundary runtime retirement failed: type=SystemExit",
    ]
    assert canary not in caplog.text


@pytest.mark.asyncio
async def test_timed_out_transport_join_retains_task_binding_and_store_owner(tmp_path, monkeypatch):
    install_plugin(tmp_path)
    release = asyncio.Event()

    class PendingJoin(SyntheticAdapter):
        async def close_private_transport(self):
            await release.wait()
            return True

    monkeypatch.setattr("gateway.run._PRIVATE_BOUNDARY_JOIN_TIMEOUT", 0.01)
    runner = runner_with_registry(monkeypatch, PendingJoin)
    with _profile_runtime_scope(tmp_path):
        adapter = runner._create_adapter(Platform.WHATSAPP, PlatformConfig(enabled=True))
    await runner._bounded_adapter_teardown(adapter, Platform.WHATSAPP)
    assert not adapter._private_disconnect_task.done()
    with pytest.raises(PrivateBoundaryError):
        await runner._private_boundary_owners.close()
    assert adapter._private_boundary.state == "RETIRING"
    release.set()
    await runner._disconnect_private_adapter(adapter)
    await runner._private_boundary_owners.close()
    assert adapter._private_boundary.state == "CLOSED"


def test_missing_primary_factory_refuses_even_with_no_platforms(tmp_path, monkeypatch):
    required_home(tmp_path)
    store = Mock(side_effect=AssertionError("Legacy SessionStore must not be constructed"))
    monkeypatch.setattr("gateway.run.SessionStore", store)
    with _profile_runtime_scope(tmp_path):
        with pytest.raises(PrivateBoundaryError):
            GatewayRunner(config=GatewayConfig())
    store.assert_not_called()


def test_secondary_preflight_failure_disposes_prior_unstarted_owner(tmp_path, monkeypatch):
    a, b = tmp_path / "a", tmp_path / "b"
    install_plugin(a)
    required_home(b)
    closed = []
    original = SyntheticBoundary.close_unstarted

    def close_unstarted(instance):
        closed.append(instance.context.home)
        return original(instance)

    monkeypatch.setattr(SyntheticBoundary, "close_unstarted", close_unstarted)
    monkeypatch.setattr("hermes_cli.profiles.profiles_to_serve", lambda **kwargs: [("a", a), ("b", b)])
    with _profile_runtime_scope(a):
        with pytest.raises(PrivateBoundaryError):
            GatewayRunner(config=GatewayConfig(multiplex_profiles=True))
    assert closed == [a]


@pytest.mark.parametrize("stage", ["deferred", "check", "validate", "factory"])
def test_registry_required_failures_have_fixed_errors_and_no_raw_logs(stage, caplog):
    registry = PlatformRegistry()

    def fail(*args):
        raise RuntimeError("synthetic-private-registry-detail")

    if stage == "deferred":
        registry.register_deferred("synthetic", fail)
    else:
        registry.register(PlatformEntry(
            name="synthetic", label="Synthetic", adapter_factory=fail if stage == "factory" else lambda c: None,
            check_fn=fail if stage == "check" else lambda: True,
            validate_config=fail if stage == "validate" else None,
        ))
    with pytest.raises(PrivateBoundaryError, match="TRANSPORT_UNAVAILABLE"):
        registry.create_adapter("synthetic", PlatformConfig(), required_boundary=True)
    assert "synthetic-private-registry-detail" not in caplog.text


@pytest.mark.asyncio
async def test_retryable_live_fatal_path_joins_before_replacement(tmp_path, monkeypatch):
    install_plugin(tmp_path)
    runner = runner_with_registry(monkeypatch, SyntheticAdapter)
    config = PlatformConfig(enabled=True)
    runner.config.platforms[Platform.WHATSAPP] = config
    with _profile_runtime_scope(tmp_path):
        adapter = runner._create_adapter(Platform.WHATSAPP, config)
    runner.adapters = {Platform.WHATSAPP: adapter}
    runner.delivery_router = SimpleNamespace(adapters=runner.adapters)
    runner._failed_platforms = {}
    runner._update_platform_runtime_status = Mock()
    adapter._set_fatal_error("synthetic_network_failure", "synthetic", retryable=True)
    await runner._handle_adapter_fatal_error(adapter)
    assert adapter._private_transport_released
    assert Platform.WHATSAPP in runner._failed_platforms
    with _profile_runtime_scope(tmp_path):
        replacement = runner._create_adapter(Platform.WHATSAPP, config)
    assert replacement._private_boundary is adapter._private_boundary
    await runner._disconnect_private_adapter(replacement)
    await runner._private_boundary_owners.close()


@pytest.mark.asyncio
async def test_required_start_failure_cleans_up_and_sets_fatal_exit_code():
    runner = GatewayRunner.__new__(GatewayRunner)
    runner._start_impl = AsyncMock(side_effect=PrivateBoundaryError())
    runner.stop = AsyncMock()
    runner._request_clean_exit = Mock()
    assert await runner.start() is True
    runner.stop.assert_awaited_once()
    assert runner._exit_code == 78
    runner._request_clean_exit.assert_called_once_with("PRIVATE_BOUNDARY_UNAVAILABLE")


@pytest.mark.parametrize("join_succeeds", [True, False])
@pytest.mark.asyncio
async def test_partial_required_constructor_is_joined_by_real_shutdown(
    tmp_path, monkeypatch, join_succeeds,
):
    # Regression for N2O-10: an adapter need not reach the routing map to require join.
    install_plugin(tmp_path)
    constructed = []

    class PartialAdapter(SyntheticAdapter):
        def __init__(self, config):
            super().__init__(config)
            constructed.append(self)
            self.join_calls = 0
            raise RuntimeError("synthetic partial constructor detail")

        async def close_private_transport(self):
            self.join_calls += 1
            return join_succeeds

    # Use the actual constructor and stop path; startup stops at the failing factory.
    runner_with_registry(monkeypatch, PartialAdapter)
    with _profile_runtime_scope(tmp_path):
        runner = GatewayRunner(config=GatewayConfig())

        async def start_factory():
            runner._create_adapter(Platform.WHATSAPP, PlatformConfig(enabled=True))

        monkeypatch.setattr(runner, "_start_impl", start_factory)
        assert await runner.start() is True
    adapter = constructed[0]
    assert adapter.join_calls == 1
    assert runner._exit_code == 78
    assert adapter._private_transport_released is join_succeeds
    assert adapter._private_boundary.state == ("CLOSED" if join_succeeds else "RETIRING")
    if not join_succeeds:
        with pytest.raises(PrivateBoundaryError):
            await runner._private_boundary_owners.close()
