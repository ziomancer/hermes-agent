"""Synthetic lifecycle witnesses for captured private runtime ownership."""

import asyncio
import uuid

import pytest

from hermes_cli.private_boundary import (
    BoundaryRegistration,
    BoundaryRuntimeOwners,
    PrivateBoundaryError,
    PrivateToolRegistration,
    discover_private_boundary_registrations,
    load_boundary_policy,
    open_boundary_runtime,
)
from hermes_constants import get_hermes_home
from tools.registry import registry


class SyntheticBoundary:
    api_version = 1
    capabilities = {"admission", "provider", "delivery", "persistence", "tools", "lifecycle"}
    profile_id = "1" * 32
    configuration_epoch = "2" * 32

    def __init__(self, context):
        self.context = context
        self.ready = False
        self.closed = False
        self.retires = 0
        self.closes = 0
        self.unstarted_closes = 0

    async def recover(self):
        self.ready = True
        return True

    def assert_ready(self):
        return self.ready

    def retire(self):
        self.retires += 1
        self.ready = False

    async def close(self):
        self.closes += 1
        self.closed = True
        return True

    def close_unstarted(self):
        self.unstarted_closes += 1
        self.closed = True
        return True

    def accept(self):
        raise AssertionError("No operation is authorized by this fixture")

    prepare = deliver = project = resolve = authorize_tool = accept


def required_home(home):
    home.mkdir(exist_ok=True)
    (home / "config.yaml").write_text(
        "privacy_boundary: {required: true, adapter: synthetic}\n"
        "plugins: {enabled: [synthetic]}\n"
    )
    return load_boundary_policy(home)


def make_runtime(home, *, factory=SyntheticBoundary, tools=()):
    policy = required_home(home)
    instances = []

    def tracked(context):
        instance = factory(context)
        instances.append(instance)
        return instance

    registration = BoundaryRegistration.create(
        home=home, name="synthetic", api_version=1, plugin="synthetic",
        factory=tracked, tools=tools,
    )
    runtime = open_boundary_runtime(home, policy, (registration,))
    return runtime, instances[0]


def private_tool(check):
    return PrivateToolRegistration.create(
        name="synthetic_private_probe", toolset="synthetic",
        schema={"name": "synthetic_private_probe", "description": "Synthetic probe",
                "parameters": {"type": "object", "properties": {}}},
        handler=lambda: None, check_fn=check,
    )


@pytest.mark.asyncio
async def test_runtime_admission_returns_only_typed_private_references(tmp_path):
    from hermes_cli.private_conversation import AcceptedTurn, ConversationBinding

    binding = ConversationBinding(uuid.uuid4().hex, uuid.uuid4().hex, uuid.uuid4().hex)

    class AdmissionBoundary(SyntheticBoundary):
        async def accept(self, event, authenticated_context, cancellation):
            assert event is raw and authenticated_context is auth and cancellation is cancel
            return AcceptedTurn(binding, (uuid.uuid4().hex,))

    runtime, _ = make_runtime(tmp_path, factory=AdmissionBoundary)
    await runtime.recover()
    raw, auth, cancel = object(), object(), object()
    accepted = await runtime.accept(raw, auth, cancel)
    assert isinstance(accepted, AcceptedTurn) and accepted.binding == binding
    await runtime.close()


@pytest.mark.asyncio
async def test_uncertain_admission_failure_fences_runtime_owner(tmp_path):
    class FailedAdmission(SyntheticBoundary):
        def accept(self, event, authenticated_context, cancellation):
            raise RuntimeError("synthetic private detail")

    runtime, implementation = make_runtime(tmp_path, factory=FailedAdmission)
    await runtime.recover()
    with pytest.raises(PrivateBoundaryError, match="NOT_READY"):
        await runtime.accept(object(), object())
    assert runtime.state == "RETIRING" and implementation.retires == 1
    await runtime.close()


@pytest.mark.asyncio
async def test_recovery_and_close_are_explicit_and_idempotent(tmp_path):
    runtime, implementation = make_runtime(tmp_path)
    with pytest.raises(PrivateBoundaryError, match="NOT_READY"):
        runtime.tool_definitions()
    await runtime.recover()
    runtime.assert_ready()
    await runtime.close()
    await runtime.close()
    assert implementation.closes == implementation.retires == 1
    assert runtime.state == "CLOSED"


@pytest.mark.asyncio
async def test_concurrent_close_never_calls_cleanup_twice(tmp_path):
    entered, release = asyncio.Event(), asyncio.Event()

    class BlockingClose(SyntheticBoundary):
        async def close(self):
            self.closes += 1
            entered.set()
            await release.wait()
            return True

    runtime, implementation = make_runtime(tmp_path, factory=BlockingClose)
    task = asyncio.create_task(runtime.close())
    await entered.wait()
    with pytest.raises(PrivateBoundaryError, match="NOT_READY"):
        await runtime.close()
    assert implementation.closes == 1
    release.set()
    await task
    assert runtime.state == "CLOSED"


@pytest.mark.asyncio
async def test_recovery_cancellation_fences_without_proving_close(tmp_path):
    entered = asyncio.Event()

    class BlockingRecovery(SyntheticBoundary):
        async def recover(self):
            entered.set()
            await asyncio.Event().wait()

    runtime, implementation = make_runtime(tmp_path, factory=BlockingRecovery)
    task = asyncio.create_task(runtime.recover())
    await entered.wait()
    with pytest.raises(PrivateBoundaryError):
        await runtime.recover()
    with pytest.raises(PrivateBoundaryError, match="NOT_READY"):
        await runtime.close()
    assert implementation.closes == 0
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task
    assert runtime.state == "RETIRING"
    assert not implementation.closed
    await runtime.close()


@pytest.mark.asyncio
async def test_transport_binding_blocks_close_until_exact_owner_release(tmp_path):
    runtime, implementation = make_runtime(tmp_path)
    transport, impostor = object(), object()
    runtime.bind_transport(transport, "3" * 32)
    with pytest.raises(PrivateBoundaryError):
        runtime.bind_transport(impostor, "4" * 32)
    (tmp_path / "config.yaml").write_text("privacy_boundary: {required: false}")
    with pytest.raises(PrivateBoundaryError, match="CONTEXT_INVALID"):
        runtime.assert_owner()
    with pytest.raises(PrivateBoundaryError, match="NOT_READY"):
        await runtime.close()
    assert not implementation.closed
    with pytest.raises(PrivateBoundaryError):
        runtime.release_transport(impostor, "3" * 32)
    runtime.release_transport(transport, "3" * 32)
    await runtime.close()
    assert implementation.closed


@pytest.mark.asyncio
async def test_failed_close_keeps_runtime_fenced_and_owned(tmp_path):
    class FailedClose(SyntheticBoundary):
        async def close(self):
            raise RuntimeError("synthetic private detail")

    runtime, _ = make_runtime(tmp_path, factory=FailedClose)
    with pytest.raises(PrivateBoundaryError, match="^PRIVATE_BOUNDARY_UNAVAILABLE$"):
        await runtime.close()
    assert runtime.state == "RETIRING"
    with pytest.raises(PrivateBoundaryError):
        await runtime.recover()


@pytest.mark.asyncio
async def test_catalog_is_private_immutable_and_checks_are_uncached_per_owner(tmp_path):
    checked = []
    tool = private_tool(lambda runtime: checked.append(runtime.home) or True)
    first, _ = make_runtime(tmp_path / "a", tools=(tool,))
    second, _ = make_runtime(tmp_path / "b", tools=(tool,))
    assert checked == [first.home, second.home]
    await first.recover()
    await second.recover()
    definitions = first.tool_definitions()
    definitions[0]["function"]["parameters"]["properties"]["injected"] = {"type": "string"}
    assert first.tool_definitions() == second.tool_definitions()
    assert len(checked) == 2
    assert registry.get_entry(tool.name) is None
    await first.close()
    await second.close()


@pytest.mark.parametrize("failure", ["false_check", "throw_check", "missing_method", "wrong_api"])
def test_failed_construction_closes_only_its_own_unstarted_instance(tmp_path, failure):
    instances = []

    def factory(context):
        instance = SyntheticBoundary(context)
        instances.append(instance)
        if failure == "missing_method":
            instance.accept = None
        if failure == "wrong_api":
            instance.api_version = True
        return instance

    def check(runtime):
        if failure == "throw_check":
            raise RuntimeError("synthetic private detail")
        return failure != "false_check"

    with pytest.raises(PrivateBoundaryError, match="^PRIVATE_BOUNDARY_UNAVAILABLE$"):
        make_runtime(tmp_path, factory=factory, tools=(private_tool(check),))
    assert instances[0].unstarted_closes == 1


def install_plugin(home, *, global_tool=False):
    required_home(home)
    directory = home / "plugins" / "synthetic"
    directory.mkdir(parents=True)
    (directory / "plugin.yaml").write_text("name: synthetic\nkind: private-boundary\nversion: 1.0.0\n")
    source = '''
from tests.test_private_boundary_runtime import SyntheticBoundary
def register(ctx):
    ctx.register_private_boundary("synthetic", 1, SyntheticBoundary)
'''
    if global_tool:
        source += '''
    ctx.register_tool("synthetic_global_leak", "synthetic", {}, lambda: None)
'''
    (directory / "__init__.py").write_text(source)


@pytest.mark.asyncio
async def test_real_profile_discovery_reconnect_reuses_owner_without_ambient_home_change(tmp_path):
    before = get_hermes_home()
    owners = BoundaryRuntimeOwners()
    a, b = tmp_path / "a", tmp_path / "b"
    install_plugin(a)
    install_plugin(b)
    first = owners.get_or_open(a)
    second = owners.get_or_open(b)
    assert first is owners.get_or_open(a)
    assert first is not second
    assert first.home == a and second.home == b
    assert get_hermes_home() == before
    await first.recover()
    assert owners.get_or_open(a) is first
    await owners.close()
    with pytest.raises(PrivateBoundaryError):
        owners.get_or_open(a)


def test_private_plugin_cannot_publish_global_schema(tmp_path):
    install_plugin(tmp_path, global_tool=True)
    assert discover_private_boundary_registrations(tmp_path) == ()
    assert registry.get_entry("synthetic_global_leak") is None


@pytest.mark.asyncio
async def test_owner_shutdown_prevents_opening_any_new_profile(tmp_path):
    owners = BoundaryRuntimeOwners()
    await owners.close()
    install_plugin(tmp_path)
    with pytest.raises(PrivateBoundaryError, match="NOT_READY"):
        owners.get_or_open(tmp_path)


@pytest.mark.parametrize("method", ["retire", "assert_ready", "close_unstarted"])
def test_async_synchronous_lifecycle_method_refuses_construction(tmp_path, method):
    async def incompatible():
        return True

    def factory(context):
        instance = SyntheticBoundary(context)
        setattr(instance, method, incompatible)
        return instance

    with pytest.raises(PrivateBoundaryError):
        make_runtime(tmp_path, factory=factory)


@pytest.mark.asyncio
async def test_same_key_relative_plugin_imports_are_profile_scoped(tmp_path):
    owners = BoundaryRuntimeOwners()
    runtimes = []
    for name, identifier in (("a", "a" * 32), ("b", "b" * 32)):
        home = tmp_path / name
        install_plugin(home)
        directory = home / "plugins/synthetic"
        (directory / "helpers.py").write_text(
            "from tests.test_private_boundary_runtime import SyntheticBoundary\n"
            f"class LocalBoundary(SyntheticBoundary):\n    profile_id = {identifier!r}\n"
        )
        (directory / "__init__.py").write_text(
            "from .helpers import LocalBoundary\n"
            "def register(ctx):\n    ctx.register_private_boundary('synthetic', 1, LocalBoundary)\n"
        )
        runtimes.append(owners.get_or_open(home))
    assert [runtime.profile_id for runtime in runtimes] == ["a" * 32, "b" * 32]
    owners.close_unstarted()


@pytest.mark.parametrize("method", ["register_platform", "register_secret_source", "register_hook", "llm"])
def test_private_plugin_facade_has_no_global_registration_or_dispatch(tmp_path, method):
    install_plugin(tmp_path)
    (tmp_path / "plugins/synthetic/__init__.py").write_text(
        "def register(ctx):\n"
        "    ctx.register_private_boundary('synthetic', 1, lambda context: None)\n"
        f"    getattr(ctx, {method!r})\n"
    )
    assert discover_private_boundary_registrations(tmp_path) == ()


@pytest.mark.asyncio
@pytest.mark.parametrize("status", ["idle", "duplicate", "refused"])
async def test_settled_admission_notice_does_not_create_turn_or_retire(tmp_path, status):
    # N2O-10: a settled duplicate/refusal is distinct from uncertain admission.
    from hermes_cli.private_conversation import AdmissionNotice

    class NoticeBoundary(SyntheticBoundary):
        def accept(self, event, authenticated_context, cancellation):
            return AdmissionNotice(status)

    runtime, implementation = make_runtime(tmp_path, factory=NoticeBoundary)
    await runtime.recover()
    result = await runtime.accept(object(), object())
    assert result.status == status and implementation.retires == 0
    runtime.assert_ready()
    await runtime.close()


@pytest.mark.parametrize("status", ["accepted", "withheld", "raw private text", None, []])
def test_admission_notice_vocabulary_cannot_carry_raw_content(status):
    from hermes_cli.private_conversation import AdmissionNotice
    with pytest.raises(PrivateBoundaryError):
        AdmissionNotice(status)
