import assert from 'node:assert/strict';
import {test} from 'node:test';
import http from 'node:http';
import net from 'node:net';
import {once} from 'node:events';
import {PrivateController} from './private_controller.mjs';
import {PrivateNativeServices} from './private_native.mjs';
import {PrivateWire, sha256, typedBytes} from './private_wire.mjs';
import {strictJSON, readFrame} from './private_framing.mjs';

const profile = '1'.repeat(32), generation = '2'.repeat(32), contractDigest = '3'.repeat(64);
const bearers = {bulk: '4'.repeat(64), control: '5'.repeat(64), owner: '6'.repeat(64)};
const object = properties => ({type: 'object', properties, required: Object.keys(properties), additionalProperties: false});
const id = {type: 'string', pattern: '^[0-9a-f]{32}$'};
const digest = {type: 'string', pattern: '^[0-9a-f]{64}$'};

function wire() {
  // Synthetic generic schema. The private package separately runs the complete
  // adopted schema over this same service; no client contract enters this repo.
  const schema = {$defs: {}, 'x-endpoints': {}};
  schema.$defs.id = id;
  schema.$defs.envelope = {type: 'object'};
  schema.$defs.descriptor = {type: 'object'};
  schema.$defs.admission_tombstone = {type: 'object'};
  const definitions = {
    health: {lane: 'owner', data: object({}), result: object({
      runtime: {enum: ['RECOVERING', 'READY', 'RETIRING', 'CLOSED']},
      bridge: {enum: ['SUSPENDED', 'ACTIVE', 'DRAINING', 'CLOSED']},
      reason: {anyOf: [{type: 'null'}, {type: 'string'}]}, transport_ready: {type: 'boolean'}, contract_digest: digest,
    })},
    activate: {lane: 'owner', data: object({contract_digest: digest}), result: object({state: {const: 'ACTIVE'}})},
    next: {lane: 'control', data: object({}), result: {type: 'null'}},
  };
  for (const name of ['media_fetch', 'media_state', 'poll_resolve', 'poll_state', 'poll_send']) {
    definitions[name] = {lane: 'control', data: object({}), result: object({})};
  }
  for (const [name, definition] of Object.entries(definitions)) {
    const common = {v: {const: 5}, profile_id: id, generation: id, request_id: id, op: {const: name}};
    schema.$defs[`${name}_request`] = object({...common, data: definition.data});
    schema.$defs[`${name}_response`] = object({...common, request_digest: digest, result: definition.result});
    schema['x-endpoints'][name] = {method: 'POST', path: `/${name}`, lane: definition.lane,
      request: `${name}_request`, response: `${name}_response`, request_bytes: 8192, response_bytes: 8192};
  }
  schema.$defs.error = object({v: {const: 5}, request_id: {anyOf: [id, {type: 'null'}]}, code: {type: 'string'}});
  const bytes = Buffer.from(JSON.stringify(schema));
  return new PrivateWire(bytes, sha256(bytes));
}

function body(operation, data = {}) {
  return Buffer.from(JSON.stringify({v: 5, profile_id: profile, generation, request_id: '7'.repeat(32), op: operation, data}));
}

function request(origin, lane, operation, data = {}, overrides = {}) {
  const bytes = body(operation, data);
  return new Promise((resolve, reject) => {
    const outgoing = http.request(origin + `/${operation}`, {
      method: 'POST', agent: false,
      headers: {Authorization: `Bearer ${bearers[lane]}`, 'X-Private-Profile': profile,
        'X-Private-Generation': generation, 'Content-Type': 'application/json', 'Content-Length': bytes.length, ...overrides},
    }, response => {
      const chunks = [];
      response.on('data', chunk => chunks.push(chunk));
      response.on('end', () => resolve({status: response.statusCode, value: JSON.parse(Buffer.concat(chunks)), bytes}));
      response.on('error', reject);
    });
    outgoing.on('error', reject);
    outgoing.end(bytes);
  });
}

async function fixture(t, extra = {}) {
  const counters = {activated: 0, fenced: 0, closed: 0};
  const services = {
    runtimeState: () => 'READY',
    activate: async () => { counters.activated++; return true; },
    fence: () => { counters.fenced++; },
    close: async () => { counters.closed++; return true; },
    next: async () => null,
    ...extra,
  };
  const controller = new PrivateController({wire: wire(), profile, generation, contractDigest, bearers, services});
  const endpoints = await controller.open();
  t.after(() => controller.close());
  return {controller, endpoints, counters};
}

test('suspended startup, authenticated readiness and single activation', async t => {
  const {controller, endpoints, counters} = await fixture(t);
  const before = await request(endpoints.owner, 'owner', 'health');
  assert.equal(before.value.result.bridge, 'SUSPENDED');
  assert.equal(before.value.result.transport_ready, false);
  assert.equal(counters.activated, 0);
  assert.equal((await request(endpoints.control, 'control', 'next')).status, 409);
  const active = await request(endpoints.owner, 'owner', 'activate', {contract_digest: contractDigest});
  assert.equal(active.status, 200);
  assert.equal(active.value.request_digest, sha256(active.bytes));
  await request(endpoints.owner, 'owner', 'activate', {contract_digest: contractDigest});
  assert.equal(counters.activated, 1);
  assert.equal((await request(endpoints.control, 'control', 'next')).value.result, null);
  controller.drain('capacity');
  assert.equal((await request(endpoints.owner, 'owner', 'activate', {contract_digest: contractDigest})).status, 409);
  const drained = await request(endpoints.owner, 'owner', 'health');
  assert.equal(drained.value.result.runtime, 'READY'); // transport loss does not retire the private run
  assert.equal(drained.value.result.bridge, 'DRAINING');
});

test('removed media and poll endpoints all answer not_ready', async t => {
  const native = new PrivateNativeServices({wire: wire(), profile, generation,
    nativeOwner: {start() {}, account() {}, cancel() {}, join() {}},
    runtimeState: () => 'READY', onDrain() {}});
  const realServices = native.services();
  for (const operation of ['media_fetch', 'media_state', 'poll_resolve', 'poll_state', 'poll_send']) {
    assert.equal(Object.hasOwn(realServices, operation), false);
  }
  const {endpoints} = await fixture(t);
  assert.equal((await request(endpoints.owner, 'owner', 'activate', {
    contract_digest: contractDigest,
  })).status, 200);
  for (const operation of ['media_fetch', 'media_state', 'poll_resolve', 'poll_state', 'poll_send']) {
    const response = await request(endpoints.control, 'control', operation);
    assert.equal(response.status, 409);
    assert.equal(response.value.code, 'not_ready');
  }
});

test('lane credentials, header bindings and duplicate headers cannot reach activation', async t => {
  const {endpoints, counters} = await fixture(t);
  for (const headers of [
    {Authorization: `Bearer ${bearers.bulk}`}, {'X-Private-Profile': '8'.repeat(32)},
    {'X-Private-Generation': '8'.repeat(32)}, {'Content-Encoding': 'gzip'},
    {'Content-Length': ['1', '1']},
  ]) {
    await assert.rejects(request(endpoints.owner, 'owner', 'activate', {contract_digest: contractDigest}, headers));
  }
  assert.equal(counters.activated, 0);
});

test('pre-header bulk and control socket limits preserve the owner lane', async t => {
  const {endpoints} = await fixture(t);
  const sockets = [];
  t.after(() => sockets.forEach(socket => socket.destroy()));
  for (const [lane, limit] of [['bulk', 2], ['control', 4]]) {
    for (let index = 0; index < limit; index++) {
      const socket = net.connect(Number(new URL(endpoints[lane]).port), '127.0.0.1');
      sockets.push(socket);
      await once(socket, 'connect');
    }
    const excess = net.connect(Number(new URL(endpoints[lane]).port), '127.0.0.1');
    excess.on('error', () => {});
    sockets.push(excess);
    await once(excess, 'close');
  }
  assert.equal((await request(endpoints.owner, 'owner', 'health')).status, 200);
});

test('close retains activation until the actual producer exits', async t => {
  let finish, started;
  const producer = new Promise(resolve => { finish = resolve; });
  const entered = new Promise(resolve => { started = resolve; });
  const {controller, endpoints} = await fixture(t, {
    activate: () => { started(); return producer; },
    close: async () => { await producer; return true; },
  });
  const activation = request(endpoints.owner, 'owner', 'activate', {contract_digest: contractDigest}).catch(() => null);
  await entered;
  let closed = false;
  const closing = controller.close().then(() => { closed = true; });
  await new Promise(resolve => setImmediate(resolve));
  assert.equal(controller.state, 'DRAINING');
  assert.equal(closed, false);
  finish(true);
  await closing;
  await activation;
  assert.equal(controller.state, 'CLOSED');
});

test('strict numbers, Unicode, duplicate keys and typed vectors', () => {
  for (const bytes of [Buffer.from('{"x":1,"x":2}'), Buffer.from('1.00000000000000001'),
    Buffer.from('9007199254740992'), Buffer.from('1e-999'), Buffer.from('"\\ud800"'), Buffer.from([0xff]),
    Buffer.from('\ufeff{}'), Buffer.from('['.repeat(22) + ']'.repeat(22))]) {
    assert.throws(() => strictJSON(bytes, 8192));
  }
  assert.equal(strictJSON(Buffer.from('39.75'), 10), 39.75);
  assert.equal(typedBytes([3, 'é', null, '', false, [0]]).toString(), 'a6:[i3;s2:éns0:fa1:[i0;]]');
});

test('binary frame limits, exact digest and bounded consumption', async () => {
  const metadata = Buffer.from('{"size":70000}'), payload = Buffer.alloc(70000, 97);
  const prefix = Buffer.alloc(4); prefix.writeUInt32BE(metadata.length);
  const frame = Buffer.concat([prefix, metadata, payload]);
  let count = 0, maxPiece = 0;
  const config = {metadataLimit: 1024, payloadLimit: 70000, expectedBytes: 70000, expectedSHA: sha256(payload),
    validateMetadata: value => assert.equal(value.size, 70000),
    consume: async bytes => { count += bytes.length; maxPiece = Math.max(maxPiece, bytes.length); }};
  await readFrame([frame], config);
  assert.equal(count, 70000);
  assert.ok(maxPiece <= 65536);
  await assert.rejects(readFrame([frame.subarray(0, frame.length - 1)], config));
  await assert.rejects(readFrame([Buffer.concat([frame, Buffer.from('x')])], config));
});
