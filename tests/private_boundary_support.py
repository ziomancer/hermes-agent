"""Synthetic private-service implementation for real generic caller tests."""

import copy
import json
import threading
import uuid
from concurrent.futures import Future

from hermes_cli.private_conversation import (
    ConversationBinding, ConversationPolicy, OwnedOperation, PreparedProviderRequest,
    PrivateTurnResult, ResolvedTurn,
)
from tests.test_private_boundary_runtime import SyntheticBoundary, required_home


class ConversationBackend(SyntheticBoundary):
    def __init__(self, context):
        super().__init__(context)
        self.binding = ConversationBinding('a' * 32, 'b' * 32, 'c' * 32)
        self.history = []
        self.context_inputs = []
        self.inputs = {}
        self.claims = set()
        self.active = None
        self.policy = ConversationPolicy('synthetic-private-model', 'Fixed conversation policy.',
                                         'Fixed private compaction policy.', 'http://127.0.0.1:1/synthetic')
        self.requests = []
        self.preparations = []
        self.responses = []
        self.tool_calls = []
        self.persisted = []
        self.controls = []
        self.claim_lock = threading.Lock()
        self.valid = True
        self.tool_available = True
        self.prepare_fault = None
        self.joined = True
        self.pending = None
        self.join_release = threading.Event()
        self.control_release = threading.Event()
        self.used_permits = set()

    def conversation_policy(self, binding):
        assert binding == self.binding
        return self.policy

    def validate_conversation(self, binding):
        return self.valid and binding == self.binding

    def validate_execution(self, resolved):
        return self.valid and resolved is self.active

    def resolve(self, turn):
        with self.claim_lock:
            assert turn.binding == self.binding
            assert all(ref in self.inputs and ref not in self.claims for ref in turn.input_refs)
            assert self.active is None
            self.claims.update(turn.input_refs)
            text = '\n'.join([*self.context_inputs, *(self.inputs[ref] for ref in turn.input_refs)])
            self.context_inputs.clear()
            self.active = ResolvedTurn(self.binding, uuid.uuid4().hex, object(),
                                       copy.deepcopy(self.history) + [{'role': 'user', 'content': text}])
            return self.active

    async def prepare(self, request_json, resolved, purpose):
        assert self.validate_execution(resolved)
        if self.prepare_fault:
            raise RuntimeError(self.prepare_fault)
        prepared = PreparedProviderRequest(request_json, 'http://127.0.0.1:1/synthetic',
                                           'LOCAL', purpose, resolved.run_id, uuid.uuid4().hex)
        self.preparations.append(prepared)
        return prepared

    def dispatch_provider(self, prepared, resolved):
        assert self.validate_execution(resolved)
        assert prepared.permit not in self.used_permits
        self.used_permits.add(prepared.permit)
        self.requests.append(json.loads(prepared.request_json))
        if self.pending is not None:
            future = self.pending
        else:
            future = Future()
            response = self.responses.pop(0) if self.responses else {
                'role': 'assistant', 'content': 'Synthetic private reply.'}
            future.set_result(response)
        return OwnedOperation(future, lambda: self.joined, lambda: future.set_exception(
            RuntimeError('synthetic cancelled')) if not future.done() else None)

    def authorize_tool(self, resolved, name, args_json):
        assert self.validate_execution(resolved)
        return uuid.uuid4().hex

    def dispatch_tool(self, resolved, name, args_json, permit, handler):
        assert self.validate_execution(resolved)
        assert permit not in self.used_permits
        self.used_permits.add(permit)
        self.tool_calls.append((name, json.loads(args_json)))
        future = Future()
        try:
            future.set_result(handler(json.loads(args_json), boundary_context=resolved))
        except Exception as exc:
            future.set_exception(exc)
        return OwnedOperation(future, lambda: True, lambda: None)

    def project(self, resolved, messages, status):
        assert resolved is self.active
        self.persisted.append((status, copy.deepcopy(messages)))
        if status == 'running':
            return True
        self.history = copy.deepcopy(messages)
        self.active = None
        return PrivateTurnResult(status, uuid.uuid4().hex if status == 'completed' else None)

    def deliver(self, *args, **kwargs):
        # Mirrors infuzd_private/boundary.py:518-519: the retained tree has no
        # owned delivery producer yet, so the refusal is a bare RuntimeError
        # carrying PRIVATE_BOUNDARY_NOT_READY.
        raise RuntimeError("PRIVATE_BOUNDARY_NOT_READY")

    def consume_control(self, turn):
        assert self.validate_conversation(turn.binding)
        assert all(ref in self.inputs for ref in turn.input_refs)
        if turn.kind == 'context':
            self.context_inputs.extend(self.inputs[ref] for ref in turn.input_refs)
        else:
            self.controls.append(turn)
            self.control_release.set()
        return PrivateTurnResult(turn.kind)


def install_conversation_plugin(home, name='private_probe'):
    required_home(home)
    directory = home / 'plugins' / 'synthetic'
    directory.mkdir(parents=True)
    (directory / 'plugin.yaml').write_text('name: synthetic\nkind: private-boundary\n')
    (directory / '__init__.py').write_text(f'''
from tests.private_boundary_support import ConversationBackend
from hermes_cli.private_boundary import PrivateToolRegistration

def register(ctx):
    tool = PrivateToolRegistration.create(
        name={name!r}, toolset='synthetic',
        schema={{'name': {name!r}, 'description': 'Synthetic private probe',
                'parameters': {{'type': 'object', 'properties': {{}}, 'additionalProperties': False}}}},
        handler=lambda args, **kwargs: {{'status': 'ok'}},
        check_fn=lambda runtime: runtime._implementation.tool_available)
    ctx.register_private_boundary('synthetic', 1, ConversationBackend, tools=(tool,))
''')
