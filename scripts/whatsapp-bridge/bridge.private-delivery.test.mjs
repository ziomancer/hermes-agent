import assert from 'node:assert/strict';
import {test} from 'node:test';
import {readFile} from 'node:fs/promises';
import {randomBytes} from 'node:crypto';
import http from 'node:http';
import {PrivateWire, sha256} from './private_wire.mjs';
import {PrivateDeliveries} from './private_delivery.mjs';
import {PrivateTombstones} from './private_admissions.mjs';
import {PrivateNativeServices} from './private_native.mjs';
import {PrivateController} from './private_controller.mjs';

const bytes = await readFile(new URL('./private-delivery-test-schema.json', import.meta.url));
const wire = new PrivateWire(bytes, sha256(bytes));
const id = () => randomBytes(16).toString('hex');
const profile = id(), generation = id();
const context = () => ({operation_id: id(), conversation_ref: id(), epoch: id()});
const text = () => ({context: context(), text: 'synthetic private text', reply: null, audit_ref: id()});
const poll = () => ({context: context(), poll_ref: id(), question: 'synthetic question', options: ['first', 'second'],
  selectable_count: 1, secret: Buffer.alloc(32, 7).toString('base64'), audit_ref: id()});
const artifact = () => ({context: context(), handle: id(), size: 4, sha256: 'a'.repeat(64),
  mime: 'text/plain', file_name: 'synthetic.txt', reply: null});
const cancel = operation_id => ({operation_id, purpose: 'delivery', ticket: null, submission_id: null, envelope_digest: null});
const settle = operation_id => ({operation_id, outcome_digest: 'b'.repeat(64), durable_outcome_ref: id(), cleanup_ref: id()});
const tick = () => new Promise(resolve => setImmediate(resolve));
const deferred = () => { let resolve; const promise = new Promise(r => { resolve = r; }); return {promise, resolve}; };
const key = () => ({id: id(), remote_jid: 'synthetic@g.us', participant: null, from_me: true});

function fixture(extra = {}) {
  const counts = {created: 0, sent: 0, cancelled: 0, joined: 0, drained: 0};
  const pool = extra.pool ?? new PrivateTombstones();
  const deliveries = new PrivateDeliveries({wire, profile, generation, tombstones: pool,
    classifyText: extra.classifyText ?? (() => 'text'), onDrain: () => { counts.drained++; },
    createProducer: (kind, data) => {
      counts.created++;
      return {prepare: async () => true,
        dispatch: async () => { counts.sent++; return key(); },
        cancel: () => { counts.cancelled++; }, join: async () => { counts.joined++; return true; },
        ...extra.producer?.(kind, data)};
    }});
  deliveries.activate();
  return {deliveries, pool, counts};
}

test('send, exact replay and settlement retain known sent evidence without another producer', async () => {
  const {deliveries: d, pool, counts} = fixture(), request = text();
  const operation_id = request.context.operation_id;
  const result = await d.request('text_send', request);
  assert.equal(result.state, 'sent');
  assert.deepEqual(await d.request('text_send', structuredClone(request)), result);
  const receipt = settle(operation_id), summary = d.settle(receipt);
  assert.equal(d.slots, 0);
  assert.equal(summary.state, 'settled');
  assert.deepEqual(d.settle(receipt), summary);
  assert.deepEqual(await d.request('text_send', request), summary);
  assert.deepEqual(await d.cancel(cancel(operation_id)), summary);
  assert.equal(pool.get(operation_id).state, 'sent');
  assert.equal(counts.created, 1); assert.equal(counts.sent, 1);
  assert.throws(() => d.settle({...receipt, cleanup_ref: id()}), {message: 'conflict'});
  assert.equal(await d.close(), true);
});

test('cancellation retains pending producer; known successful completion wins after actual join', async () => {
  const send = deferred(), join = deferred();
  const {deliveries: d, pool} = fixture({producer: () => ({dispatch: () => send.promise, join: () => join.promise})});
  const request = text(), operation_id = request.context.operation_id;
  const sending = d.request('text_send', request);
  await tick();
  let cancelled = false;
  const cancelling = d.cancel(cancel(operation_id)).then(value => { cancelled = true; return value; });
  assert.equal(pool.get(operation_id).state, 'fenced');
  assert.throws(() => d.settle(settle(operation_id)), {message: 'unknown'});
  const sentKey = key(); send.resolve(sentKey); await tick();
  assert.equal(cancelled, false);
  assert.equal(d.state({operation_id}).state, 'dispatch_started');
  join.resolve(true);
  assert.equal((await cancelling).state, 'sent');
  assert.deepEqual((await sending).sent_key, sentKey);
  assert.equal(await d.close(), true);
});

test('failed send is quiescent unknown and cannot be retried by state recovery', async () => {
  const {deliveries: d, counts} = fixture({producer: () => ({dispatch: async () => { throw Error('synthetic failure'); }})});
  const request = text();
  assert.equal((await d.request('text_send', request)).state, 'unknown');
  assert.equal((await d.request('text_send', request)).state, 'unknown');
  assert.equal(counts.created, 1);
  d.settle(settle(request.context.operation_id));
  assert.equal(await d.close(), true);
});

test('failed join cannot become terminal or release a result slot', async () => {
  const {deliveries: d, pool} = fixture({producer: () => ({join: async () => false})});
  const request = text(), operation_id = request.context.operation_id;
  assert.equal((await d.request('text_send', request)).state, 'dispatch_started');
  assert.equal((await d.cancel(cancel(operation_id))).producers_joined, false);
  assert.equal(pool.get(operation_id).state, 'fenced');
  assert.throws(() => d.settle(settle(operation_id)), {message: 'unknown'});
  assert.equal(d.slots, 1); assert.equal(await d.close(), false);
});

test('pre-request cancellation never learns a late payload or ticket', async () => {
  const {deliveries: d, pool, counts} = fixture(), request = text();
  const operation_id = request.context.operation_id;
  assert.equal((await d.cancel(cancel(operation_id))).proof, 'never_dispatched');
  assert.equal(pool.get(operation_id).request_digest, null);
  await assert.rejects(d.request('text_send', request), {message: 'conflict'});
  assert.equal(pool.get(operation_id).request_digest, null);
  assert.equal(counts.created, 0); assert.equal(await d.close(), true);
});

test('artifact commit binds context and ticket and dispatches once', async () => {
  const {deliveries: d, counts} = fixture(), request = artifact();
  const prepared = await d.request('artifact_prepare', request);
  assert.equal(prepared.state, 'prepared'); assert.equal(counts.sent, 0);
  const commit = {context: request.context, ticket: prepared.ticket, audit_ref: id()};
  const started = await d.commit(commit);
  assert.equal(started.state, 'dispatch_started');
  await tick();
  const sent = d.state({operation_id: request.context.operation_id});
  assert.equal(sent.state, 'sent'); assert.deepEqual(await d.commit(commit), sent);
  assert.equal(counts.sent, 1);
  await assert.rejects(d.commit({...commit, context: {...commit.context, epoch: id()}}), {message: 'conflict'});
  assert.equal(await d.close(), true);
});

test('artifact cancellation during prepare does not issue a late ticket', async () => {
  const gate = deferred();
  const {deliveries: d, pool, counts} = fixture({producer: () => ({prepare: () => gate.promise})});
  const request = artifact(), operation_id = request.context.operation_id;
  const preparing = d.request('artifact_prepare', request);
  await tick(); const cancelling = d.cancel(cancel(operation_id));
  gate.resolve(true);
  assert.equal((await preparing).state, 'cancelled');
  assert.equal((await cancelling).ticket, null);
  assert.equal(pool.get(operation_id).ticket, null); assert.equal(counts.sent, 0);
  assert.equal(await d.close(), true);
});

test('expired artifact ticket fences before dispatch and waits for the actual producer join', async t => {
  let now = 1000000;
  t.mock.method(Date, 'now', () => now);
  const joined = deferred();
  const {deliveries: d, counts, pool} = fixture({producer: () => ({expiresAt: now + 100, join: () => joined.promise})});
  const request = artifact(), operation_id = request.context.operation_id;
  const prepared = await d.request('artifact_prepare', request);
  now += 100;
  let finished = false;
  const commit = d.commit({context: request.context, ticket: prepared.ticket, audit_ref: id()})
    .then(value => { finished = true; return value; });
  await tick();
  assert.equal(counts.sent, 0); assert.equal(finished, false);
  assert.equal(pool.get(operation_id).state, 'fenced');
  assert.equal(pool.get(operation_id).quiesced, false);
  assert.throws(() => d.settle(settle(operation_id)), {message: 'unknown'});
  joined.resolve(true);
  assert.equal((await commit).state, 'cancelled');
  assert.equal(d.slots, 1); // Full result remains owned until durable settlement.
  assert.equal(await d.close(), true);
});

test('one artifact, one status and two text full results consume all four slots', async () => {
  const status = text(), ordinary = text(), p = text(), a = artifact();
  const {deliveries: d, counts} = fixture({classifyText: c => c.operation_id === status.context.operation_id ? 'status' : 'text'});
  await d.request('artifact_prepare', a);
  await d.request('text_send', status);
  await d.request('text_send', ordinary);
  await d.request('text_send', p);
  assert.equal(d.slots, 4);
  await assert.rejects(d.request('text_send', text()), {message: 'capacity'});
  assert.equal(counts.created, 4);
  assert.equal(await d.close(), true);
});

test('delivery and admission cells share the same 8192-cell exhaustion bound', async () => {
  const pool = new PrivateTombstones();
  for (let n = 0; n < 8191; n++) pool.reserve(`offer:${id()}`);
  const {deliveries: d, counts} = fixture({pool});
  const request = text(); await d.request('text_send', request);
  d.settle(settle(request.context.operation_id));
  assert.equal(pool.size, 8192);
  await assert.rejects(d.request('text_send', text()), {message: 'capacity'});
  assert.equal(counts.created, 1); assert.equal(await d.close(), true);
});

test('changed payload and foreign-purpose cancellation cannot overwrite delivery ownership', async () => {
  const {deliveries: d, counts} = fixture(), request = text();
  await d.request('text_send', request);
  await assert.rejects(d.cancel({...cancel(request.context.operation_id), purpose: 'poll'}), {message: 'invalid_context'});
  await assert.rejects(d.request('text_send', {...request, text: 'changed'}), {message: 'conflict'});
  assert.equal(counts.sent, 1); assert.equal(await d.close(), true);
});

test('actual controller authenticates native delivery services and closed settlement responses', async t => {
  const native = new PrivateNativeServices({wire, profile, generation,
    runtimeState: () => 'READY', onDrain() {}, nativeOwner: {
      start: async () => true, account: () => ({id: '100@s.whatsapp.net'}), cancel() {}, join: async () => true},
    delivery: {classifyText: () => 'text', createProducer: () => ({
      dispatch: async () => key(), cancel() {}, join: async () => true})}});
  const bearers = {bulk: '1'.repeat(64), control: '2'.repeat(64), owner: '3'.repeat(64)};
  const controller = new PrivateController({wire, profile, generation, contractDigest: 'a'.repeat(64),
    bearers, services: native.services()});
  const endpoints = await controller.open();
  t.after(() => controller.close());
  async function call(op, data, authenticated = true) {
    const endpoint = wire.endpoint(op), request = {v: 5, profile_id: profile, generation, request_id: id(), op, data};
    const raw = Buffer.from(JSON.stringify(request));
    return new Promise((resolve, reject) => {
      const req = http.request(endpoints[endpoint.lane] + endpoint.path, {method: 'POST', agent: false, headers: {
        Authorization: `Bearer ${authenticated ? bearers[endpoint.lane] : '0'.repeat(64)}`,
        'X-Private-Profile': profile, 'X-Private-Generation': generation, 'Content-Type': 'application/json',
        'Content-Length': raw.length}}, response => {
        const chunks = [];
        response.on('data', chunk => chunks.push(chunk));
        response.on('error', reject);
        response.on('end', () => {
          try {
            const body = JSON.parse(Buffer.concat(chunks));
            if (response.statusCode === 200) wire.validate(body, endpoint.response);
            resolve({status: response.statusCode, body});
          } catch (error) { reject(error); }
        });
      });
      req.on('error', reject); req.end(raw);
    });
  }
  assert.equal((await call('activate', {contract_digest: 'a'.repeat(64)})).status, 200);
  const request = text();
  await assert.rejects(call('text_send', request, false), {code: 'ECONNRESET'});
  assert.equal((await call('text_send', request)).body.result.state, 'sent');
  const acknowledged = (await call('cancel', cancel(request.context.operation_id))).body.result;
  assert.deepEqual(acknowledged, {operation_id: request.context.operation_id, state: 'sent',
    prior_dispatch_possible: true, producers_joined: true});
  assert.equal((await call('delivery_state', {operation_id: request.context.operation_id})).body.result.proof, 'sent');
  assert.equal((await call('delivery_settle', settle(request.context.operation_id))).body.result.state, 'settled');
  assert.equal((await call('cancel', cancel(request.context.operation_id))).body.result.state, 'settled');
  const cancelled = id();
  assert.deepEqual((await call('cancel', cancel(cancelled))).body.result, {operation_id: cancelled,
    state: 'cancelled', prior_dispatch_possible: false, producers_joined: true});
  assert.equal((await call('delivery_state', {operation_id: cancelled})).body.result.proof, 'never_dispatched');
});

test('R1 refuses poll delivery before allocating a producer or slot', async () => {
  const {deliveries: d, counts} = fixture();
  await assert.rejects(d.request('poll_send', poll()), {message: 'not_ready'});
  assert.equal(d.slots, 0); assert.equal(counts.created, 0);
  assert.equal(await d.close(), true);
});
