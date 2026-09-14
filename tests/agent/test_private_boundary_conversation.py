"""N2O-10: actual plugin, agent, request, tool and finalizer paths with synthetic data."""

import asyncio
import json
import uuid
from dataclasses import replace
from unittest.mock import Mock

import pytest

from gateway.run import GatewayRunner, _profile_runtime_scope
from gateway.platforms.base import MessageEvent
from hermes_cli.private_boundary import BoundaryRuntimeOwners, PrivateBoundaryError
from hermes_cli.private_conversation import AcceptedTurn, PRIVATE_MARKER
from tests.private_boundary_support import install_conversation_plugin


def handoff(backend, text='Synthetic unknown identity canary', kind='command'):
    ref = uuid.uuid4().hex
    backend.inputs[ref] = text
    return AcceptedTurn(backend.binding, (ref,), kind)


async def runtime_at(home, name='private_probe'):
    install_conversation_plugin(home, name)
    owners = BoundaryRuntimeOwners()
    runtime = owners.get_or_open(home)
    await owners.recover()
    return owners, runtime, runtime._implementation


def agent_at(home, runtime, **kwargs):
    from run_agent import AIAgent
    with _profile_runtime_scope(home):
        return AIAgent(boundary_context=runtime.conversation(runtime._implementation.binding), **kwargs)


@pytest.mark.asyncio
async def test_real_agent_calls_private_provider_and_never_ordinary_observers(tmp_path, monkeypatch, caplog):
    owners, runtime, backend = await runtime_at(tmp_path)
    from run_agent import AIAgent
    forbidden = Mock(side_effect=AssertionError('ordinary path reached'))
    monkeypatch.setattr('run_agent.OpenAI', forbidden)
    monkeypatch.setattr('hermes_cli.plugins.invoke_hook', forbidden)
    monkeypatch.setattr(AIAgent, '_save_session_log', forbidden)
    monkeypatch.setattr(AIAgent, '_flush_messages_to_session_db', forbidden)
    agent = agent_at(tmp_path, runtime, stream_delta_callback=forbidden, step_callback=forbidden)
    result = await asyncio.to_thread(agent.run_conversation, handoff(backend))
    assert backend.requests[0]['messages'][-1]['content'] == 'Synthetic unknown identity canary'
    assert result['final_response'] == PRIVATE_MARKER
    assert 'canary' not in json.dumps(result['messages']) + caplog.text
    assert backend.persisted[-1][0] == 'completed'
    forbidden.assert_not_called()
    await owners.close()


@pytest.mark.asyncio
async def test_raw_turn_and_unbound_agent_refuse_before_provider(tmp_path, monkeypatch):
    owners, runtime, backend = await runtime_at(tmp_path)
    from run_agent import AIAgent
    forbidden = Mock(side_effect=AssertionError('SDK constructed'))
    monkeypatch.setattr('run_agent.OpenAI', forbidden)
    with _profile_runtime_scope(tmp_path), pytest.raises(PrivateBoundaryError):
        AIAgent()
    agent = agent_at(tmp_path, runtime)
    with pytest.raises(PrivateBoundaryError):
        agent.run_conversation('raw text')
    forbidden.assert_not_called()
    assert not backend.requests
    await owners.close()


@pytest.mark.asyncio
async def test_fixed_schemas_across_tools_turns_and_ambient_home(tmp_path):
    from model_tools import get_tool_definitions, handle_function_call
    from tools.registry import registry
    a, c = tmp_path / 'a', tmp_path / 'c'
    owners_a, runtime_a, backend_a = await runtime_at(a, 'private_a')
    owners_c, runtime_c, backend_c = await runtime_at(c, 'private_c')
    agent_a, agent_c = agent_at(a, runtime_a), agent_at(c, runtime_c)
    first = get_tool_definitions(boundary_context=agent_a._private_boundary_context)
    assert [t['function']['name'] for t in first] == ['private_a']
    assert [t['function']['name'] for t in agent_c.tools] == ['private_c']
    assert registry.get_entry('private_a') is None
    assert registry.get_entry('private_c') is None
    agent_a.tools[0]['function']['description'] = 'mutated copy'
    backend_a.responses = [
        {'role': 'assistant', 'content': None, 'tool_calls': [
            {'id': 'one', 'type': 'function', 'function': {'name': 'private_a', 'arguments': '{}'}},
            {'id': 'two', 'type': 'function', 'function': {'name': 'private_a', 'arguments': '{}'}}]},
        {'role': 'assistant', 'content': 'Synthetic first answer'},
    ]
    with _profile_runtime_scope(c):
        result = await asyncio.to_thread(agent_a.run_conversation, handoff(backend_a, 'First actual turn'))
    assert not result['failed']
    await asyncio.to_thread(agent_a.run_conversation, handoff(backend_a, 'Second actual turn'))
    assert len(backend_a.tool_calls) == 2
    assert all(r['tools'] == first for r in backend_a.requests)
    assert all(r['messages'][0]['content'] == backend_a.policy.system_prompt for r in backend_a.requests)
    assert not backend_c.requests
    with _profile_runtime_scope(tmp_path):
        assert all(t['function']['name'] not in {'private_a', 'private_c'}
                   for t in get_tool_definitions(enabled_toolsets=[], quiet_mode=True))
        with pytest.raises(PrivateBoundaryError):
            handle_function_call('private_c', {}, boundary_context=agent_a._private_boundary_context)
    await owners_a.close()
    await owners_c.close()


@pytest.mark.asyncio
async def test_provider_fault_has_no_fallback_and_preserves_only_private_history(tmp_path):
    owners, runtime, backend = await runtime_at(tmp_path)
    agent = agent_at(tmp_path, runtime)
    backend.prepare_fault = 'Synthetic private exception canary'
    result = await asyncio.to_thread(agent.run_conversation, handoff(backend))
    assert result['failed'] and not backend.requests
    assert backend.persisted[-1][0] == 'failed'
    assert 'canary' not in str(result)
    await owners.close()


@pytest.mark.asyncio
async def test_partial_tool_failure_closes_all_call_ids_before_later_user_turn(tmp_path):
    owners, runtime, backend = await runtime_at(tmp_path)
    agent = agent_at(tmp_path, runtime)
    backend.responses = [{'role': 'assistant', 'content': None, 'tool_calls': [
        {'id': 'denied', 'type': 'function', 'function': {'name': 'execute_code', 'arguments': '{}'}},
        {'id': 'later', 'type': 'function', 'function': {'name': 'private_probe', 'arguments': '{}'}},
    ]}]
    result = await asyncio.to_thread(agent.run_conversation, handoff(backend))
    assert result['failed'] and not backend.tool_calls
    assert [m['tool_call_id'] for m in backend.history if m['role'] == 'tool'] == ['denied', 'later']
    assert backend.history[-1]['role'] == 'assistant'
    await asyncio.to_thread(agent.run_conversation, handoff(backend, 'Later actual user'))
    assert backend.requests[-1]['messages'][-1] == {'role': 'user', 'content': 'Later actual user'}
    await owners.close()


@pytest.mark.asyncio
async def test_actual_gateway_primary_and_secondary_context_handoffs(tmp_path):
    from gateway.config import GatewayConfig
    a, b = tmp_path / 'a', tmp_path / 'b'
    install_conversation_plugin(a, 'private_a')
    install_conversation_plugin(b, 'private_b')
    with _profile_runtime_scope(a):
        runner = GatewayRunner(config=GatewayConfig())
    runtime_a = runner._private_boundary_owners.get_or_open(a)
    runtime_b = runner._private_boundary_owners.get_or_open(b)
    await runner._private_boundary_owners.recover()
    backend_a, backend_b = runtime_a._implementation, runtime_b._implementation
    first = MessageEvent(text=PRIVATE_MARKER, private_turn=handoff(backend_a, 'Unaddressed canary', 'context'))
    result = await runner._handle_message(first)
    assert result.status == 'context' and not backend_a.requests
    await runner._handle_message(MessageEvent(text=PRIVATE_MARKER, private_turn=handoff(backend_a, 'Addressed A')))
    secondary = runner._make_profile_message_handler('synthetic-secondary', b)
    await secondary(MessageEvent(text=PRIVATE_MARKER, private_turn=handoff(backend_b, 'Addressed B')))
    assert backend_a.requests[-1]['messages'][-1]['content'] == 'Unaddressed canary\nAddressed A'
    assert backend_b.requests[-1]['messages'][-1]['content'] == 'Addressed B'
    assert backend_a.requests[-1]['tools'][0]['function']['name'] == 'private_a'
    assert backend_b.requests[-1]['tools'][0]['function']['name'] == 'private_b'
    await runner.stop()


@pytest.mark.asyncio
async def test_real_compactor_uses_checked_local_policy_and_keeps_main_prefix(tmp_path):
    owners, runtime, backend = await runtime_at(tmp_path)
    backend.policy = replace(backend.policy, context_length=8192)
    backend.history = [m for i in range(18) for m in (
        {'role': 'user', 'content': ('Synthetic prior user ' + str(i) + ' ') * 300},
        {'role': 'assistant', 'content': ('Synthetic prior answer ' + str(i) + ' ') * 300},
    )]
    agent = agent_at(tmp_path, runtime)
    result = await asyncio.to_thread(agent.run_conversation, handoff(backend, 'Actual latest user'))
    assert not result['failed']
    assert any(p.purpose == 'compaction' for p in backend.preparations)
    assert backend.requests[0]['messages'][0]['content'] == backend.policy.compaction_prompt
    assert backend.requests[-1]['messages'][0]['content'] == backend.policy.system_prompt
    assert backend.requests[-1]['messages'][-1]['content'] == 'Actual latest user'
    assert all(r['tools'] == agent.tools for r in backend.requests)
    await owners.close()


@pytest.mark.asyncio
@pytest.mark.parametrize('mutation', ['model', 'extra', 'endpoint', 'tools', 'system', 'unconfigured_hosted'])
async def test_prepared_request_cannot_change_captured_route_or_policy(tmp_path, mutation):
    from hermes_cli.private_conversation import encoded
    owners, runtime, backend = await runtime_at(tmp_path)
    agent = agent_at(tmp_path, runtime)
    prepare = backend.prepare

    async def changed(request, resolved, purpose):
        result = await prepare(request, resolved, purpose)
        payload = json.loads(result.request_json)
        if mutation == 'model':
            payload['model'] = 'wrong-model'
        elif mutation == 'extra':
            payload['extra_body'] = {'model': 'wrong-model'}
        elif mutation == 'endpoint':
            result = replace(result, endpoint='https://example.invalid')
        elif mutation == 'tools':
            payload['tools'] = []
        elif mutation == 'system':
            payload['messages'][0]['content'] = 'changed prefix'
        else:
            result = replace(result, disposition='HOSTED')
        return replace(result, request_json=encoded(payload))

    backend.prepare = changed
    result = await asyncio.to_thread(agent.run_conversation, handoff(backend))
    assert result['failed'] and not backend.requests
    await owners.close()


@pytest.mark.asyncio
async def test_failed_cancellation_signal_still_joins_and_withholds_local_gate(tmp_path):
    from concurrent.futures import Future
    from hermes_cli.private_conversation import OwnedOperation
    owners, runtime, backend = await runtime_at(tmp_path)
    context = runtime.conversation(backend.binding)
    context.begin(handoff(backend))
    future = Future()
    future.set_result({'role': 'assistant', 'content': 'Synthetic reply'})
    joined = Mock(return_value=True)
    cancelled = Mock(side_effect=RuntimeError('private exception canary'))

    def dispatch(*args):
        context._cancelled.set()  # Cancellation races with the returned operation.
        return OwnedOperation(future, joined, cancelled)

    backend.dispatch_provider = dispatch
    with pytest.raises(PrivateBoundaryError):
        await asyncio.to_thread(context.provider_call, [{'role': 'user', 'content': 'Synthetic'}])
    joined.assert_called_once()
    assert cancelled.called
    assert runtime._local_call_gate.locked() and context._run_lock.locked()
    with pytest.raises(PrivateBoundaryError):
        await owners.close()


@pytest.mark.asyncio
@pytest.mark.parametrize('failure', ['unjoined', 'dispatch_raises'])
async def test_uncertain_producer_retains_owner_and_gate(tmp_path, failure):
    owners, runtime, backend = await runtime_at(tmp_path)
    agent = agent_at(tmp_path, runtime)
    if failure == 'unjoined':
        backend.joined = False
    else:
        backend.dispatch_provider = Mock(side_effect=RuntimeError('started then failed'))
    with pytest.raises(PrivateBoundaryError):
        await asyncio.to_thread(agent.run_conversation, handoff(backend))
    assert runtime._local_call_gate.locked()
    assert runtime.state == 'RETIRING'
    with pytest.raises(PrivateBoundaryError):
        await owners.close()


@pytest.mark.asyncio
async def test_direct_legacy_entrypoints_refuse_for_private_agent(tmp_path, monkeypatch):
    from agent.context_compressor import ContextCompressor
    owners, runtime, backend = await runtime_at(tmp_path)
    agent = agent_at(tmp_path, runtime)
    forbidden = Mock(side_effect=AssertionError('ordinary SDK'))
    monkeypatch.setattr('run_agent.OpenAI', forbidden)
    for action in (
        lambda: agent._create_openai_client({}, reason='synthetic', shared=False),
        lambda: agent._get_transport('chat_completions'),
        lambda: agent._persist_session([{'role': 'user', 'content': 'private canary'}]),
        lambda: agent._save_session_log([]),
        lambda: agent.reset_session_state(),
        lambda: agent._compress_context([], 'Synthetic private prompt'),
    ):
        with pytest.raises(PrivateBoundaryError):
            action()
    with _profile_runtime_scope(tmp_path), pytest.raises(PrivateBoundaryError):
        ContextCompressor('synthetic', config_context_length=8192)
    forbidden.assert_not_called()
    assert not backend.requests
    await owners.close()


@pytest.mark.asyncio
async def test_actual_adapter_control_bypasses_both_busy_guards_while_command_waits(tmp_path):
    from concurrent.futures import Future
    from gateway.config import GatewayConfig, PlatformConfig
    from hermes_cli.private_boundary import boundary_construction_scope
    from tests.gateway.test_private_boundary_startup import SyntheticAdapter
    install_conversation_plugin(tmp_path)
    with _profile_runtime_scope(tmp_path):
        runner = GatewayRunner(config=GatewayConfig())
    runtime = runner._private_boundary_owners.get_or_open(tmp_path)
    await runner._private_boundary_owners.recover()
    backend = runtime._implementation
    backend.pending = Future()
    results = []
    delivered = asyncio.Event()

    class Adapter(SyntheticAdapter):
        async def handle_private_result(self, turn, result):
            results.append(result.status)
            if result.status == 'control':
                delivered.set()

    with _profile_runtime_scope(tmp_path), boundary_construction_scope(runtime):
        adapter = Adapter(PlatformConfig())
    adapter.set_message_handler(runner._handle_message)
    # No usable source/session is supplied: touching either legacy guard fails.
    adapter._active_sessions = {'synthetic-busy': object()}
    runner._running_agents = {'synthetic-busy': object()}
    await adapter.handle_message(MessageEvent(text=PRIVATE_MARKER, private_turn=handoff(backend)))
    for _ in range(200):
        if backend.requests:
            break
        await asyncio.sleep(.01)
    assert backend.requests and not results
    await adapter.handle_message(MessageEvent(text=PRIVATE_MARKER, private_turn=handoff(backend, 'Cancel', 'control')))
    await asyncio.wait_for(delivered.wait(), 3)
    assert backend.control_release.is_set() and not backend.pending.done()
    backend.pending.set_result({'role': 'assistant', 'content': 'Synthetic complete'})
    await asyncio.wait_for(runtime.join_handoffs(), 3)
    assert sorted(results) == ['completed', 'control']
    runner._running_agents = {}
    await runner.stop()


@pytest.mark.asyncio
async def test_gateway_captured_required_owner_cannot_downgrade_to_ordinary(tmp_path, monkeypatch):
    from gateway.config import GatewayConfig
    install_conversation_plugin(tmp_path)
    with _profile_runtime_scope(tmp_path):
        runner = GatewayRunner(config=GatewayConfig())
    runtime = runner._private_boundary_owners.get_or_open(tmp_path)
    await runner._private_boundary_owners.recover()
    (tmp_path / 'config.yaml').write_text('privacy_boundary:\n  required: false\n')
    with pytest.raises(PrivateBoundaryError):
        await runner._handle_message(MessageEvent(text='Synthetic raw text'))
    assert not runtime._implementation.requests
    await runner.stop()


@pytest.mark.asyncio
async def test_public_handler_and_schema_remain_frozen_but_check_is_uncached(tmp_path, monkeypatch):
    from hermes_constants import get_hermes_home
    from agent.secret_scope import get_secret
    from tools.registry import registry, ToolEntry
    owners, runtime, backend = await runtime_at(tmp_path)
    (tmp_path / '.env').write_text('SYNTHETIC_PROFILE_TOKEN=alpha\n')
    calls = []
    checked = []
    available = [True]

    def handler(args, **kwargs):
        calls.append((get_hermes_home(), get_secret('SYNTHETIC_PROFILE_TOKEN')))
        return {'status': 'synthetic ok'}

    def check():
        checked.append(1)
        return available[0]

    entry = ToolEntry('synthetic_public', 'synthetic', {
        'name': 'synthetic_public', 'description': 'Captured public tool',
        'parameters': {'type': 'object', 'properties': {}, 'additionalProperties': False},
    }, handler, check, [], False, '', '')
    monkeypatch.setitem(registry._tools, 'synthetic_public', entry)
    backend.policy = replace(backend.policy, public_tools=('synthetic_public',))
    agent = agent_at(tmp_path, runtime)
    frozen = json.loads(json.dumps(agent.tools))
    entry.schema['description'] = 'Changed after capture'
    entry.handler = Mock(side_effect=AssertionError('new handler used'))
    entry.check_fn = lambda: True
    call = {'role': 'assistant', 'content': None, 'tool_calls': [
        {'id': 'public', 'type': 'function', 'function': {'name': 'synthetic_public', 'arguments': '{}'}},
    ]}
    backend.responses = [call]
    with _profile_runtime_scope(tmp_path / 'ambient-other'):
        result = await asyncio.to_thread(agent.run_conversation, handoff(backend))
    assert not result['failed']
    assert calls == [(tmp_path.resolve(), 'alpha')]
    assert len(checked) == 2
    assert all(request['tools'] == frozen for request in backend.requests)
    available[0] = False
    backend.responses = [call]
    result = await asyncio.to_thread(agent.run_conversation, handoff(backend))
    assert result['failed'] and len(calls) == 1 and len(checked) == 3
    await owners.close()


@pytest.mark.asyncio
async def test_cancelled_caller_cannot_release_live_worker_ownership(tmp_path):
    import threading
    owners, runtime, backend = await runtime_at(tmp_path)
    entered, release = threading.Event(), threading.Event()

    def create(context):
        entered.set()
        assert release.wait(3)
        return agent_at(tmp_path, runtime)

    task = asyncio.create_task(runtime.run_handoff(handoff(backend), create))
    assert await asyncio.to_thread(entered.wait, 3)
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task
    assert runtime._conversation_workers
    with pytest.raises(PrivateBoundaryError):
        await owners.close()
    release.set()
    for _ in range(200):
        if not runtime._conversation_workers:
            break
        await asyncio.sleep(.01)
    assert not runtime._conversation_workers and not backend.requests and not backend.claims
    await owners.close()


@pytest.mark.asyncio
async def test_replayed_accepted_turn_never_releases_again(tmp_path):
    owners, runtime, backend = await runtime_at(tmp_path)
    agent = agent_at(tmp_path, runtime)
    turn = handoff(backend)
    await asyncio.to_thread(agent.run_conversation, turn)
    count = len(backend.requests)
    with pytest.raises(PrivateBoundaryError):
        await asyncio.to_thread(agent.run_conversation, turn)
    assert len(backend.requests) == count
    assert runtime.state == 'RETIRING'  # An uncertain store claim requires recovery.


@pytest.mark.asyncio
async def test_transport_reconnect_keeps_snapshot_and_health_loss_retires_epoch(tmp_path):
    owners, runtime, backend = await runtime_at(tmp_path)
    agent = agent_at(tmp_path, runtime)
    context = agent._private_boundary_context
    snapshot = context.definitions()
    transport = object()
    runtime.bind_transport(transport, 'd' * 32)
    await asyncio.to_thread(agent.run_conversation, handoff(backend))
    runtime.release_transport(transport, 'd' * 32)
    replacement = object()
    runtime.bind_transport(replacement, 'e' * 32)
    assert runtime.conversation(backend.binding) is context
    await asyncio.to_thread(agent.run_conversation, handoff(backend))
    assert all(request['tools'] == snapshot for request in backend.requests)
    runtime.release_transport(replacement, 'e' * 32)
    backend.ready = False
    with pytest.raises(PrivateBoundaryError):
        await asyncio.to_thread(agent.run_conversation, handoff(backend))
    backend.ready = True
    with pytest.raises(PrivateBoundaryError):
        runtime.conversation(backend.binding)
    assert runtime.state == 'RETIRING'
    await owners.close()


@pytest.mark.asyncio
@pytest.mark.parametrize('order', [('a', 'b', 'c'), ('c', 'b', 'a')])
async def test_required_optional_required_actual_constructors_are_order_independent(tmp_path, monkeypatch, order):
    from run_agent import AIAgent
    monkeypatch.setattr('run_agent.OpenAI', Mock())
    monkeypatch.setattr('run_agent.check_toolset_requirements', lambda *a, **k: {})
    agents, owners = {}, []
    for name in order:
        home = tmp_path / name
        if name == 'b':
            home.mkdir()
            (home / 'config.yaml').write_text('{}\n')
            with _profile_runtime_scope(home):
                agents[name] = AIAgent(
                    model='synthetic-optional', api_key='synthetic-test-key',
                    base_url='http://127.0.0.1:1', enabled_toolsets=[],
                    quiet_mode=True, skip_context_files=True, skip_memory=True,
                )
        else:
            owner, runtime, backend = await runtime_at(home, 'private_' + name)
            owners.append(owner)
            agents[name] = agent_at(home, runtime)
            result = await asyncio.to_thread(agents[name].run_conversation, handoff(backend))
            assert not result['failed']
    assert agents['b']._private_boundary_context is None
    assert not any(t['function']['name'].startswith('private_') for t in agents['b'].tools)
    assert [t['function']['name'] for t in agents['a'].tools] == ['private_a']
    assert [t['function']['name'] for t in agents['c'].tools] == ['private_c']
    for owner in owners:
        await owner.close()


@pytest.mark.asyncio
async def test_tool_cancellation_closes_transcript_before_next_genuine_turn(tmp_path):
    import threading
    from concurrent.futures import Future
    from hermes_cli.private_conversation import OwnedOperation
    owners, runtime, backend = await runtime_at(tmp_path)
    agent = agent_at(tmp_path, runtime)
    started = threading.Event()
    future = Future()
    joined = Mock(return_value=True)
    backend.responses = [{'role': 'assistant', 'content': None, 'tool_calls': [
        {'id': 'cancelled-tool', 'type': 'function', 'function': {
            'name': 'private_probe', 'arguments': '{}'}},
        {'id': 'not-started', 'type': 'function', 'function': {
            'name': 'private_probe', 'arguments': '{}'}},
    ]}]

    def dispatch(*args):
        started.set()
        return OwnedOperation(future, joined, lambda: future.set_exception(
            RuntimeError('Synthetic tool cancelled')) if not future.done() else None)

    backend.dispatch_tool = dispatch
    pending = asyncio.create_task(asyncio.to_thread(agent.run_conversation, handoff(backend)))
    assert await asyncio.to_thread(started.wait, 3)
    agent.interrupt()
    result = await asyncio.wait_for(pending, 3)
    assert result['interrupted'] and backend.persisted[-1][0] == 'cancelled'
    joined.assert_called_once()
    assert [m['tool_call_id'] for m in backend.history if m['role'] == 'tool'] == [
        'cancelled-tool', 'not-started']
    assert backend.history[-1]['role'] == 'assistant'
    result = await asyncio.to_thread(agent.run_conversation, handoff(backend, 'Next actual user'))
    assert not result['failed']
    messages = backend.requests[-1]['messages']
    assert messages[-1] == {'role': 'user', 'content': 'Next actual user'}
    assert sum(m['role'] == 'user' for m in messages) == 2
    await owners.close()
