import assert from 'node:assert/strict';
import {test} from 'node:test';
import {EventEmitter, once} from 'node:events';
import net from 'node:net';
import {PrivateSocketOwner} from './private_socket.mjs';
import {PrivateNativeServices} from './private_native.mjs';
import {PrivateWire, sha256} from './private_wire.mjs';

const tick = () => new Promise(resolve => setImmediate(resolve));
function deferred() {
  let resolve, reject;
  const promise = new Promise((yes, no) => { resolve = yes; reject = no; });
  return {promise, resolve, reject};
}
function fixture(options = {}) {
  const ev = new EventEmitter(), ws = {isClosed: false};
  const counts = {opens: 0, ends: 0, saves: 0, drained: 0};
  const socket = {ev, ws, user: {id: 'bot'}, end: async () => { counts.ends++; ws.isClosed = true; }};
  const owner = new PrivateSocketOwner({
    openSocket: () => { counts.opens++; return options.openSocket?.(socket) ?? socket; },
    credentials: {save: async () => { counts.saves++; return options.save ? options.save() : true; },
      join: options.joinCredentials ?? (async () => true)},
  });
  const schema = Buffer.from(JSON.stringify({$defs: {id: {type: 'string', pattern: '^[0-9a-f]{32}$'},
    envelope: {type: 'object'}, descriptor: {type: 'object'}}, 'x-endpoints': {}}));
  const native = new PrivateNativeServices({wire: new PrivateWire(schema, sha256(schema)),
    profile: '1'.repeat(32), generation: '2'.repeat(32), nativeOwner: owner,
    runtimeState: options.runtimeState ?? (() => 'READY'), onDrain: () => counts.drained++});
  return {owner, socket, ev, ws, counts, native, services: native.services()};
}
function message(id = 'event') {
  return {key: {id, remoteJid: 'group@g.us', participant: 'sender', fromMe: false},
    messageTimestamp: 1800000000, message: {conversation: 'synthetic private body'}};
}

test('one activation owns projection and suppresses every late native callback after fence', async () => {
  const f = fixture();
  assert.equal(f.counts.opens, 0);
  const first = f.native.activate();
  assert.equal(first, f.native.activate());
  await tick(); f.ev.emit('connection.update', {connection: 'open'});
  assert.equal(await first, true);
  f.ev.emit('messages.upsert', {type: 'notify', messages: [message()]});
  const offered = f.services.next();
  assert.equal(offered.body, 'synthetic private body');
  const late = f.ev.listeners('messages.upsert')[0];
  f.services.fence();
  late({get messages() { throw Error('must not inspect fenced native data'); }});
  assert.equal(await f.native.close(), true);
  assert.deepEqual(f.services.next(), offered); // offered ownership survives drain
  assert.equal(f.counts.opens, 1);
  assert.equal(f.counts.ends, 1);
  assert.equal(f.counts.drained, 1);
  await assert.rejects(f.native.activate());
});

test('close during pending connection cancels startup and waits for actual socket close', async () => {
  const f = fixture(), ended = deferred();
  f.socket.end = async () => { await ended.promise; f.ws.isClosed = true; };
  const activation = f.native.activate();
  await tick();
  const closing = f.native.close();
  let completed = false; closing.then(() => { completed = true; });
  await assert.rejects(activation);
  await tick(); assert.equal(completed, false);
  ended.resolve();
  assert.equal(await closing, true);
  assert.equal(f.native.close(), closing);
});

test('close before scheduled activation opens no socket', async () => {
  const f = fixture();
  const activation = f.native.activate();
  const closing = f.native.close();
  await assert.rejects(activation);
  assert.equal(await closing, true);
  assert.equal(f.counts.opens, 0);
});

test('ambiguous constructor start cannot provide join proof or retry', async () => {
  const f = fixture({openSocket: () => { throw Error('synthetic partial start'); }});
  await assert.rejects(f.native.activate(), {message: 'transport_fault'});
  assert.equal(await f.native.close(), false);
  await assert.rejects(f.native.activate());
  assert.equal(f.counts.opens, 1);
});

test('remote disconnect fences rather than reconnecting the same owner', async () => {
  const f = fixture();
  const activation = f.native.activate();
  await tick(); f.ev.emit('connection.update', {connection: 'open'}); await activation;
  f.ev.emit('connection.update', {connection: 'close'});
  assert.equal(await f.native.close(), true);
  assert.equal(f.ev.listenerCount('messages.upsert'), 0);
  assert.equal(f.counts.opens, 1);
});

test('credential updates coalesce while a write is held; close awaits the final write', async () => {
  const held = deferred(); let writes = 0;
  const f = fixture({save: async () => { if (++writes === 1) await held.promise; return true; }});
  const activation = f.native.activate();
  await tick(); f.ev.emit('connection.update', {connection: 'open'}); await activation;
  f.ev.emit('creds.update', {}); await tick();
  for (let n = 0; n < 1000; n++) f.ev.emit('creds.update', {});
  assert.equal(writes, 1);
  const closing = f.native.close();
  let joined = false; closing.then(() => { joined = true; });
  await tick(); assert.equal(joined, false);
  held.resolve();
  assert.equal(await closing, true);
  assert.equal(writes, 2);
});

test('failed credential storage fences the transport but completed failure still joins', async () => {
  const f = fixture({save: async () => { throw Error('private canary'); }});
  const activation = f.native.activate();
  await tick(); f.ev.emit('connection.update', {connection: 'open'}); await activation;
  f.ev.emit('creds.update', {}); await tick();
  assert.equal(await f.native.close(), true);
  assert.equal(f.counts.drained, 1);
  await assert.rejects(f.native.activate());
});

test('native end completion with an open socket is not join evidence', async () => {
  const f = fixture(); f.socket.end = async () => {};
  const activation = f.native.activate();
  await tick(); f.ev.emit('connection.update', {connection: 'open'}); await activation;
  assert.equal(await f.native.close(), false);
});

test('real loopback socket owner joins only after the owned socket emits close', async t => {
  const server = net.createServer(socket => { socket.on('error', () => {}); });
  server.listen(0, '127.0.0.1'); await once(server, 'listening');
  t.after(() => new Promise(resolve => server.close(resolve)));
  const f = fixture({openSocket: socket => {
    const tcp = net.connect(server.address().port, '127.0.0.1');
    tcp.on('error', () => {});
    tcp.on('connect', () => socket.ev.emit('connection.update', {connection: 'open'}));
    const closed = new Promise(resolve => tcp.once('close', () => { socket.ws.isClosed = true; resolve(); }));
    socket.end = async () => { tcp.destroy(); await closed; };
    return socket;
  }});
  assert.equal(await f.native.activate(), true);
  assert.equal(f.ws.isClosed, false);
  assert.equal(await f.native.close(), true);
  assert.equal(f.ws.isClosed, true);
});
