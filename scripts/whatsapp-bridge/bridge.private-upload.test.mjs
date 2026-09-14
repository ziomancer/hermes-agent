import assert from 'node:assert/strict';
import {test} from 'node:test';
import {readFile, mkdtemp, open, rm} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import path from 'node:path';
import http from 'node:http';
import {randomBytes} from 'node:crypto';
import {Readable} from 'node:stream';
import {PrivateWire, sha256} from './private_wire.mjs';
import {PrivateUpload} from './private_framing.mjs';
import {PrivateNativeServices} from './private_native.mjs';
import {PrivateController} from './private_controller.mjs';

const bytes = await readFile(new URL('./private-delivery-test-schema.json', import.meta.url));
const wire = new PrivateWire(bytes, sha256(bytes));
const id = () => randomBytes(16).toString('hex');
const profile = id(), generation = id();
function metadata(payload) {
  return {v: 5, profile_id: profile, generation, request_id: id(), op: 'artifact_prepare', data: {
    context: {operation_id: id(), conversation_ref: id(), epoch: id()}, handle: id(),
    size: payload.length, sha256: sha256(payload), mime: 'text/plain', file_name: 'synthetic.txt', reply: null}};
}
function frame(meta, payload) {
  const raw = Buffer.isBuffer(meta) ? meta : Buffer.from(JSON.stringify(meta));
  const prefix = Buffer.alloc(4); prefix.writeUInt32BE(raw.length);
  return Buffer.concat([prefix, raw, payload]);
}
async function upload(raw, extra = {}) {
  return PrivateUpload.open(Readable.from(extra.chunks ?? [raw]), {
    metadataLimit: 262144, frameLimit: 17039364, contentLength: raw.length,
    validateMetadata: value => wire.validate(value, 'artifact_prepare_request'), abort() {}, ...extra});
}

test('all framing boundaries and large source buffers keep sink writes at 64 KiB', async () => {
  const payload = Buffer.alloc(16777216, 7), meta = metadata(payload), raw = frame(meta, payload);
  for (const chunks of [[raw], [raw.subarray(0, 1), raw.subarray(1, 3), raw.subarray(3, 17), raw.subarray(17)]]) {
    const u = await upload(raw, {chunks});
    let count = 0, max = 0;
    assert.equal(await u.consume(async piece => { count += piece.length; max = Math.max(max, piece.length); }), true);
    assert.equal(count, payload.length); assert.ok(max <= 65536);
    assert.equal(u.digest, sha256(raw)); assert.equal(await u.join(), true);
    await assert.rejects(u.consume(async () => {}), {message: 'conflict'});
  }
  const empty = frame(metadata(Buffer.alloc(0)), Buffer.alloc(0));
  const u = await upload(empty); await u.consume(() => assert.fail('empty payload called sink'));
  assert.equal(u.digest, sha256(empty)); assert.equal(await u.join(), true);
});

for (const fault of ['prefix', 'metadata_limit', 'duplicate', 'fraction', 'short', 'excess', 'hash', 'length']) {
  test(`bad ${fault} cannot complete an upload`, async () => {
    const payload = Buffer.from('synthetic'), meta = metadata(payload);
    let raw = frame(meta, payload), opts = {};
    if (fault === 'prefix') raw = raw.subarray(0, 3);
    if (fault === 'metadata_limit') raw.writeUInt32BE(262145);
    if (fault === 'duplicate') raw = frame(Buffer.from(JSON.stringify(meta).replace('"v":5', '"v":5,"v":5')), payload);
    if (fault === 'fraction') raw = frame(Buffer.from(JSON.stringify(meta).replace('"size":9', '"size":9.0000000000000001')), payload);
    if (fault === 'short') opts = {chunks: [raw.subarray(0, raw.length - 1)]};
    if (fault === 'excess') opts = {chunks: [Buffer.concat([raw, Buffer.from('x')])]};
    if (fault === 'hash') raw[raw.length - 1] ^= 1;
    if (fault === 'length') opts = {contentLength: raw.length + 1};
    let u;
    await assert.rejects(async () => { u = await upload(raw, opts); await u.consume(async () => {}); });
    if (u) { assert.equal(u.complete, false); u.cancel(); assert.equal(await u.join(), true); }
  });
}

test('cancellation signals the retained sink and join waits for actual sink completion', async () => {
  const payload = Buffer.from('synthetic'), raw = frame(metadata(payload), payload);
  const u = await upload(raw);
  let release, entered;
  const inside = new Promise(resolve => { entered = resolve; });
  const paused = new Promise(resolve => { release = resolve; });
  let cancelled = 0, joined = false;
  u.onCancel(() => { cancelled++; });
  const work = u.consume(async () => { entered(); await paused; });
  await inside; u.cancel();
  const joining = u.join().then(value => { joined = true; return value; });
  await new Promise(resolve => setImmediate(resolve));
  assert.equal(joined, false); assert.equal(cancelled, 1);
  release(); await assert.rejects(work, {message: 'cancelled'});
  assert.equal(await joining, true); assert.equal(u.complete, false);
});

async function fixture(t, extra = {}) {
  const directory = await mkdtemp(path.join(tmpdir(), 'private-upload-'));
  t.after(() => rm(directory, {recursive: true, force: true}));
  const counts = {created: 0, writes: 0, sent: 0, joined: 0, cancelled: 0};
  let controller;
  const native = new PrivateNativeServices({wire, profile, generation,
    runtimeState: () => 'READY', onDrain: reason => controller?.drain(reason), nativeOwner: {
      start: async () => true, account: () => ({id: '100@s.whatsapp.net'}), cancel() {}, join: async () => true},
    delivery: {classifyText: () => 'text', createProducer: (_kind, data) => {
      counts.created++;
      let file = null;
      return {
        prepare: async source => {
          file = await open(path.join(directory, data.context.operation_id), 'wx', 0o600);
          await source.consume(async piece => {
            counts.writes++;
            assert.ok(piece.length <= 65536);
            if (extra.sink) await extra.sink(piece);
            let offset = 0;
            while (offset < piece.length) offset += (await file.write(piece, offset, piece.length - offset)).bytesWritten;
          });
          await file.sync();
          return true;
        },
        dispatch: async () => { counts.sent++; throw Error('send not installed'); },
        cancel: () => { counts.cancelled++; extra.cancel?.(); },
        join: async () => { await file?.close(); file = null; counts.joined++; return true; },
      };
    }}});
  const bearers = {bulk: '1'.repeat(64), control: '2'.repeat(64), owner: '3'.repeat(64)};
  controller = new PrivateController({wire, profile, generation, contractDigest: 'a'.repeat(64), bearers, services: native.services()});
  const endpoints = await controller.open();
  t.after(() => controller.close());
  function call(op, data, options = {}) {
    const endpoint = wire.endpoint(op);
    const raw = options.raw ?? Buffer.from(JSON.stringify({v: 5, profile_id: profile, generation, request_id: id(), op, data}));
    return new Promise((resolve, reject) => {
      const req = http.request(endpoints[options.lane ?? endpoint.lane] + endpoint.path, {method: 'POST', agent: false, headers: {
        Authorization: `Bearer ${options.bearer ?? bearers[endpoint.lane]}`,
        'X-Private-Profile': profile, 'X-Private-Generation': generation,
        'Content-Type': options.raw ? endpoint.stream.content_type : 'application/json',
        'Content-Length': options.length ?? raw.length}}, response => {
        const chunks = [];
        response.on('data', chunk => chunks.push(chunk)); response.on('error', reject);
        response.on('end', () => {
          try {
            const reply = JSON.parse(Buffer.concat(chunks));
            wire.validate(reply, response.statusCode === 409 ? 'error' : endpoint.response);
            resolve(reply);
          } catch (error) { reject(error); }
        });
      });
      req.on('error', reject);
      if (options.write) options.write(req, raw); else req.end(raw);
    });
  }
  await call('activate', {contract_digest: 'a'.repeat(64)});
  return {call, counts, directory};
}

const cancel = operation_id => ({operation_id, purpose: 'delivery', ticket: null, submission_id: null, envelope_digest: null});
test('authenticated HTTP prepares a real file; exact retry verifies without a second spool or send', async t => {
  const {call, counts, directory} = await fixture(t);
  const payload = Buffer.alloc(180000, 9), meta = metadata(payload), raw = frame(meta, payload);
  const first = await call('artifact_prepare', null, {raw});
  assert.equal(first.result.state, 'prepared'); assert.equal(first.request_digest, sha256(raw));
  assert.deepEqual(await readFile(path.join(directory, meta.data.context.operation_id)), payload);
  const repeated = frame({...meta, request_id: id()}, payload);
  assert.deepEqual((await call('artifact_prepare', null, {raw: repeated})).result, first.result);
  assert.equal(counts.created, 1); assert.equal(counts.sent, 0);
  const result = await call('cancel', cancel(meta.data.context.operation_id));
  assert.equal(result.result.producers_joined, true); assert.equal(result.result.state, 'cancelled');
  assert.equal(counts.joined, 1);
});

for (const fault of ['bearer', 'lane', 'json', 'hash', 'metadata_context', 'length', 'trailing']) {
  test(`actual HTTP rejects ${fault} and never sends`, async t => {
    const {call, counts} = await fixture(t);
    const payload = Buffer.from('synthetic'), meta = metadata(payload);
    let raw = frame(meta, payload), options = {raw};
    if (fault === 'bearer') options.bearer = '0'.repeat(64);
    if (fault === 'lane') options.lane = 'control';
    if (fault === 'json') options = {};
    if (fault === 'hash') raw[raw.length - 1] ^= 1;
    if (fault === 'metadata_context') { meta.generation = id(); options.raw = frame(meta, payload); }
    if (fault === 'length') options.length = raw.length + 1;
    if (fault === 'trailing') options.raw = Buffer.concat([raw, Buffer.from('x')]);
    await assert.rejects(call('artifact_prepare', meta.data, options));
    assert.equal(counts.sent, 0);
    if (fault !== 'hash') assert.equal(counts.created, 0);
    else {
      const result = await call('cancel', cancel(meta.data.context.operation_id));
      assert.equal(result.result.producers_joined, true);
    }
  });
}

test('owner health and control cancellation remain available while upload sink is paused', async t => {
  let entered, release;
  const inside = new Promise(resolve => { entered = resolve; });
  const gate = new Promise(resolve => { release = resolve; });
  const {call, counts} = await fixture(t, {sink: async () => { entered(); await gate; }, cancel: release});
  const payload = Buffer.alloc(100000, 8), meta = metadata(payload);
  const preparing = call('artifact_prepare', null, {raw: frame(meta, payload)});
  // Attach rejection before cancellation closes the HTTP exchange.
  const failed = assert.rejects(preparing);
  await inside;
  assert.equal((await call('health', {})).result.bridge, 'ACTIVE');
  const result = await call('cancel', cancel(meta.data.context.operation_id));
  assert.equal(result.result.producers_joined, true);
  await failed;
  assert.equal(counts.sent, 0); assert.equal(counts.cancelled, 1);
});

test('body idle deadline cancels and joins a stalled sink without occupying control', async t => {
  let entered, release;
  const inside = new Promise(resolve => { entered = resolve; });
  const gate = new Promise(resolve => { release = resolve; });
  const {call, counts} = await fixture(t, {sink: async () => { entered(); await gate; }, cancel: release});
  t.mock.timers.enable({apis: ['setTimeout']});
  const payload = Buffer.alloc(100000, 8), meta = metadata(payload);
  const preparing = call('artifact_prepare', null, {raw: frame(meta, payload)});
  const failed = assert.rejects(preparing);
  await inside;
  // The original five-second prelude must have ended after authenticated headers.
  t.mock.timers.tick(5001);
  assert.equal((await call('health', {})).result.bridge, 'ACTIVE');
  t.mock.timers.tick(24999);
  await failed;
  const result = await call('cancel', cancel(meta.data.context.operation_id));
  assert.equal(result.result.producers_joined, true);
  assert.equal(counts.sent, 0); assert.equal(counts.cancelled, 1);
});

test('absolute upload deadline cannot be extended by continuing payload progress', async t => {
  let nextPiece;
  const {call, counts} = await fixture(t, {sink: async () => { nextPiece?.(); }});
  t.mock.timers.enable({apis: ['setTimeout']});
  const payload = Buffer.alloc(200000, 6), meta = metadata(payload), raw = frame(meta, payload);
  let request;
  const failed = assert.rejects(call('artifact_prepare', null, {raw, write: (req, frameBytes) => {
    request = req;
    req.write(frameBytes.subarray(0, frameBytes.length - payload.length));
  }}));
  // Ten intervals stay below the idle ceiling. Another chunk renews idle but
  // cannot move the one absolute timer installed before metadata was parsed.
  for (let n = 0; n < 10; n++) {
    const consumed = new Promise(resolve => { nextPiece = resolve; });
    request.write(payload.subarray(n * 10000, (n + 1) * 10000));
    await consumed;
    t.mock.timers.tick(29000);
  }
  const consumed = new Promise(resolve => { nextPiece = resolve; });
  request.write(payload.subarray(100000, 110000));
  await consumed;
  t.mock.timers.tick(10000);
  await failed;
  const result = await call('cancel', cancel(meta.data.context.operation_id));
  assert.equal(result.result.producers_joined, true);
  assert.equal(counts.sent, 0); assert.equal(counts.cancelled, 1);
});
