import assert from 'node:assert/strict';
import {test} from 'node:test';
import {EventEmitter, once} from 'node:events';
import {Readable} from 'node:stream';
import {mkdtemp, realpath, writeFile, readFile, rm, lstat, mkdir, open, readdir} from 'node:fs/promises';
import path from 'node:path';
import os from 'node:os';
import {createHmac, randomBytes} from 'node:crypto';
import {WebSocketServer} from 'ws';
import * as sdk from '@whiskeysockets/baileys';
import {PrivateBaileysOwner} from './private_baileys.mjs';
import {PrivateNativeServices} from './private_native.mjs';
import {PrivateTombstones, PrivateAdmissions} from './private_admissions.mjs';
import {PrivateProjection} from './private_projection.mjs';
import {PrivateWire, sha256, typedBytes} from './private_wire.mjs';
import {allocate} from './private-auth-test-support.mjs';

const profile = '1'.repeat(32), tick = () => new Promise(resolve => setImmediate(resolve));
const id = () => randomBytes(16).toString('hex');
function typed(value) {
  if (Array.isArray(value)) return ['array', value.map(typed)];
  if (value !== null && typeof value === 'object') {
    return ['object', Object.keys(value).sort().map(key => [key, typed(value[key])])];
  }
  return value;
}
async function fixture(t, makeSocket, {withLid = true, sdkFactory = null} = {}) {
  const directory = await realpath(await mkdtemp(path.join(os.tmpdir(), 'private-sdk-test-')));
  t.after(() => rm(directory, {recursive: true, force: true}));
  const creds = sdk.initAuthCreds(); creds.registered = true;
  creds.me = {id: '100:1@s.whatsapp.net', ...(withLid ? {lid: '200@lid'} : {}),
    name: 'synthetic private account'};
  await writeFile(path.join(directory, 'account.json'), JSON.stringify({v: 1, profile, creds, keys: []}, sdk.BufferJSON.replacer), {mode: 0o600});
  let opens = 0, loads = 0, drains = 0;
  const owner = new PrivateBaileysOwner({directory, profile, allocation_digest: await allocate(directory, profile), loadSDK: async () => {
    loads++;
    const loaded = {...sdk, makeWASocket: config => { opens++; return makeSocket(config); }};
    return sdkFactory ? sdkFactory(loaded) : loaded;
  }});
  const schema = Buffer.from(JSON.stringify({$defs: {id: {type: 'string', pattern: '^[0-9a-f]{32}$'},
    envelope: {type: 'object'}, descriptor: {type: 'object'}, admission_tombstone: {type: 'object'}},
  'x-endpoints': {}}));
  const native = new PrivateNativeServices({wire: new PrivateWire(schema, sha256(schema)), profile,
    generation: '2'.repeat(32), nativeOwner: owner, runtimeState: () => 'READY', onDrain: () => { drains++; }});
  return {owner, native, directory, counts: () => ({opens, loads, drains})};
}
function syntheticSocket(config) {
  const ev = new EventEmitter(), ws = {isClosed: false};
  const socket = {ev, ws, user: config.auth.creds.me, end: async () => { ws.isClosed = true; }};
  queueMicrotask(() => ev.emit('connection.update', {connection: 'open'}));
  return socket;
}

function echoAwareSocket(config) {
  const eventLogger = {debug() {}, trace() {}, warn() {}, error() {}};
  const ev = new EventEmitter(), events = sdk.makeEventBuffer(eventLogger), ws = {isClosed: false};
  events.on('messages.upsert', value => ev.emit('messages.upsert', value));
  const upsertMessage = events.createBufferedFunction(async (message, type) => {
    events.emit('messages.upsert', {messages: [message], type});
  });
  let sends = 0;
  const socket = {
    ev, ws, user: config.auth.creds.me,
    end: async () => { ws.isClosed = true; events.destroy(); },
    offerMessage: async (message, type) => {
      await upsertMessage(message, type);
      events.flush();
    },
    sendMessage: async (recipient, content) => {
      if (content.document?.stream) for await (const _ of content.document.stream) { /* consume checked stream */ }
      const message = {key: {id: `echo-aware-${++sends}`, remoteJid: recipient, fromMe: true},
        messageTimestamp: 1800000000,
        message: content.document ? {documentMessage: {mimetype: content.mimetype, fileName: content.fileName}} :
          {conversation: content.text}};
      if (config.emitOwnEvents) {
        await upsertMessage(message, 'append');
        events.flush();
      }
      return message;
    },
  };
  queueMicrotask(() => ev.emit('connection.update', {connection: 'open'}));
  return socket;
}

test('inert factory activates one SDK socket with private auth, then projects native evidence', async t => {
  let socket, getMessage;
  const f = await fixture(t, config => {
    assert.equal(config.markOnlineOnConnect, false);
    assert.equal(config.emitOwnEvents, false);
    assert.equal(config.syncFullHistory, false);
    assert.equal(config.shouldSyncHistoryMessage({syncType: 0}), false);
    getMessage = config.getMessage;
    assert.equal(config.maxMsgRetryCount, 0);
    const hostile = {toString() { throw Error('logger inspected private payload'); }};
    config.logger.child(hostile).warn(hostile);
    socket = syntheticSocket(config); return socket;
  });
  assert.deepEqual(f.counts(), {opens: 0, loads: 0, drains: 0});
  assert.equal(await f.native.activate(), true);
  assert.equal(await getMessage({remoteJid: 'synthetic@g.us', id: 'missing'}), undefined);
  socket.ev.emit('messages.upsert', {type: 'notify', messages: [{
    key: {id: 'native-event', remoteJid: 'synthetic@g.us', participant: '300@s.whatsapp.net', fromMe: false},
    messageTimestamp: 1800000000, message: {conversation: 'synthetic private input'},
  }]});
  const offer = f.native.services().next();
  assert.equal(offer.body, 'synthetic private input');
  assert.ok(offer.account_aliases.includes('100@s.whatsapp.net'));
  assert.equal(await f.native.close(), true);
  assert.deepEqual(f.counts(), {opens: 1, loads: 1, drains: 1});
});

test('close during SDK import retains startup and never opens auth or a socket', async t => {
  let release, imports = 0;
  const pending = new Promise(resolve => { release = resolve; });
  const owner = new PrivateBaileysOwner({directory: '/absent-private-directory', profile,
    loadSDK: async () => { imports++; await pending; return sdk; }});
  const starting = owner.start({disconnected() {}});
  let joined = false; const closing = owner.join().then(value => { joined = true; return value; });
  await tick(); assert.equal(joined, false);
  release(); await assert.rejects(starting);
  assert.equal(await closing, true); assert.equal(imports, 1);
});

test('account conflict after readiness fences before projection', async t => {
  let socket;
  const f = await fixture(t, config => { socket = syntheticSocket(config); return socket; });
  await f.native.activate();
  socket.user.id = '999@s.whatsapp.net';
  assert.throws(() => f.owner.account());
  assert.equal(await f.native.close(), true);
  assert.equal(f.counts().drains, 1);
});

test('first LID migration filters its self-chat event while credentials persist', async t => {
  let socket;
  const f = await fixture(t, config => { socket = syntheticSocket(config); return socket; }, {withLid: false});
  assert.equal(await f.native.activate(), true);
  assert.deepEqual(f.owner.account(), {id: '100:1@s.whatsapp.net'});
  socket.user.lid = '200:3@lid';
  socket.ev.emit('creds.update', {me: socket.user});
  socket.ev.emit('messages.upsert', {type: 'append', messages: [{
    key: {id: 'lid-migration', remoteJid: '200@lid', fromMe: true},
    get message() { throw Error('LID self-chat content was inspected'); },
    messageTimestamp: 1800000000,
  }]});
  assert.equal(f.native.services().next(), null);
  assert.deepEqual(f.owner.account(), {id: '100:1@s.whatsapp.net', lid: '200:3@lid'});
  const deadline = Date.now() + 3000;
  let durable;
  while (Date.now() < deadline) {
    durable = JSON.parse(await readFile(path.join(f.directory, 'account.json')), sdk.BufferJSON.reviver);
    if (durable.creds.me.lid === '200:3@lid') break;
    await new Promise(resolve => setTimeout(resolve, 10));
  }
  assert.equal(durable.creds.me.lid, '200:3@lid');
  socket.ev.emit('messages.upsert', {type: 'notify', messages: [{
    key: {id: 'after-migration', remoteJid: 'synthetic@g.us', participant: '300@s.whatsapp.net', fromMe: false},
    messageTimestamp: 1800000001, message: {conversation: 'after LID migration'},
  }]});
  assert.equal(f.native.services().next().body, 'after LID migration');
  assert.equal(f.counts().drains, 0);
  assert.equal(await f.native.close(), true);
});

test('owner-typed one-to-one client message is not mistaken for an alternate-JID self-chat', async t => {
  let socket;
  const f = await fixture(t, config => { socket = syntheticSocket(config); return socket; });
  assert.equal(await f.native.activate(), true);
  socket.ev.emit('messages.upsert', {type: 'notify', messages: [{
    key: {id: 'owner-client-dm', remoteJid: '300@s.whatsapp.net', remoteJidAlt: '200@lid', fromMe: true},
    messageTimestamp: 1800000000, message: {conversation: 'owner typed client DM'},
  }]});
  assert.equal(f.native.services().next().body, 'owner typed client DM');
  assert.equal(f.counts().drains, 0);
  assert.equal(await f.native.close(), true);
});

test('hosted and trailing-space account JIDs remain key-only self-chat controls', async t => {
  let socket;
  const f = await fixture(t, config => { socket = syntheticSocket(config); return socket; });
  assert.equal(await f.native.activate(), true);
  for (const [id, remoteJid] of [
    ['hosted-pn-self-chat', '100@hosted'],
    ['hosted-lid-self-chat', '200@hosted.lid'],
    ['trailing-space-self-chat', '100@s.whatsapp.net '],
  ]) {
    socket.ev.emit('messages.upsert', {type: 'append', messages: [{
      key: {id, remoteJid, fromMe: true},
      get message() { throw Error(`${id} content was inspected`); },
      messageTimestamp: 1800000000,
    }]});
    assert.equal(f.native.services().next(), null);
  }
  assert.equal(f.counts().drains, 0);
  assert.equal(await f.native.close(), true);
});

test('SDK text and document producers preserve private bytes and poll creation refuses', async t => {
  const sent = [];
  const f = await fixture(t, config => {
    const socket = syntheticSocket(config);
    socket.sendMessage = async (recipient, content, options) => {
      let document = null;
      if (content.document?.stream) {
        const chunks = [];
        for await (const piece of content.document.stream) chunks.push(piece);
        document = Buffer.concat(chunks);
      }
      sent.push({recipient, content, options, document});
      return {key: {id: `sent-${sent.length}`, remoteJid: recipient, fromMe: true}};
    };
    return socket;
  });
  await f.native.activate();
  const text = f.owner.deliveryProducer('synthetic@g.us', 'text', {text: 'unchanged synthetic body', reply: null});
  assert.equal(sent.length, 0);
  assert.equal((await text.dispatch()).id, 'sent-1');
  await assert.rejects(async () => text.dispatch());
  assert.equal(await text.join(), true);
  assert.deepEqual(sent[0].content, {text: 'unchanged synthetic body'});
  const stream = Readable.from([Buffer.from('synthetic '), Buffer.from('document')]);
  const document = f.owner.deliveryProducer('synthetic@g.us', 'artifact', {
    mime: 'text/plain', file_name: 'synthetic.txt', reply: null,
  }, {stream});
  assert.equal((await document.dispatch()).id, 'sent-2');
  assert.equal(await document.join(), true);
  assert.equal(sent[1].content.document.stream, stream);
  assert.equal(sent[1].content.mimetype, 'text/plain');
  assert.equal(sent[1].content.fileName, 'synthetic.txt');
  assert.equal(sent[1].content.caption, undefined);
  assert.equal(sent[1].document.toString(), 'synthetic document');
  assert.throws(() => f.owner.deliveryProducer('synthetic@g.us', 'poll', {}), {message: 'not_ready'});
  assert.equal(sent.length, 2);
  assert.equal(await f.native.close(), true);
});

test('private SDK path calls no legacy media helper and graph imports none', async t => {
  const sdkForbidden = ['downloadMediaMessage', 'downloadContentFromMessage', 'updateMediaMessage',
    'decryptPollVote', 'getAggregateVotesInPollMessage'];
  const graphForbidden = [...sdkForbidden, 'saveMedia'];
  const calls = Object.fromEntries(sdkForbidden.map(name => [name, 0]));
  let socket;
  const f = await fixture(t, config => { socket = syntheticSocket(config); return socket; }, {
    sdkFactory: loaded => new Proxy(loaded, {get(target, property, receiver) {
      if (sdkForbidden.includes(property)) calls[property]++;
      return Reflect.get(target, property, receiver);
    }}),
  });
  await f.native.activate();
  socket.ev.emit('messages.upsert', {type: 'notify', messages: [{
    key: {id: 'media-without-fetch', remoteJid: 'synthetic@g.us',
      participant: '300@s.whatsapp.net', fromMe: false},
    messageTimestamp: 1800000000,
    message: {imageMessage: {mimetype: 'image/png', caption: 'synthetic'}},
  }]});
  const offered = f.native.services().next();
  assert.equal(offered.native.kind, 'image');
  assert.deepEqual(offered.media, []);
  assert.deepEqual(calls, Object.fromEntries(sdkForbidden.map(name => [name, 0])));
  assert.equal(await f.native.close(), true);

  const entry = new URL('./private_controller_entry.mjs', import.meta.url);
  const entrySource = await readFile(entry, 'utf8');
  const filesLiteral = entrySource.match(/const FILES = \[([\s\S]*?)\];/);
  assert.ok(filesLiteral, 'private controller FILES inventory is present');
  const inventory = [...filesLiteral[1].matchAll(/'([^']+)'/g)].map(match => match[1])
    .filter(name => !['bridge.js', 'bridge_helpers.js'].includes(name));
  assert.ok(inventory.length >= 12, 'private controller inventory is non-vacuous');
  const bridgeFiles = (await readdir(new URL('.', import.meta.url)))
    .filter(name => name.startsWith('private_') && name.endsWith('.mjs')).sort();
  assert.deepEqual([...inventory].sort(), bridgeFiles);
  const pending = inventory.map(name => new URL(name, import.meta.url));
  const graph = new Map();
  while (pending.length) {
    const url = pending.pop();
    if (graph.has(url.href)) continue;
    const source = await readFile(url, 'utf8');
    graph.set(url.href, source);
    for (const match of source.matchAll(/(?:from\s+|import\s*)['"](\.[^'"]+)['"]/g)) {
      pending.push(new URL(match[1], url));
    }
  }
  assert.deepEqual([...graph.keys()].map(name => path.basename(new URL(name).pathname)).sort(),
    [...inventory].sort());
  for (const [name, source] of graph) {
    for (const symbol of graphForbidden) {
      assert.equal(source.includes(symbol), false, `${name} imports or names ${symbol}`);
    }
  }
});

test('emitOwnEvents counterfactual offers and reserves checked send echoes', async t => {
  const originalReserve = PrivateTombstones.prototype.reserve;
  let reserves = 0;
  t.mock.method(PrivateTombstones.prototype, 'reserve', function (...args) {
    reserves++;
    return originalReserve.apply(this, args);
  });
  let config;
  const f = await fixture(t, value => {
    config = value;
    config.emitOwnEvents = true;
    return echoAwareSocket(config);
  });
  await f.native.activate();
  const services = f.native.services();
  assert.equal(config.emitOwnEvents, true);

  const text = f.owner.deliveryProducer('synthetic@g.us', 'text', {
    text: 'checked text', reply: null,
  });
  assert.equal((await text.dispatch()).id, 'echo-aware-1');
  assert.equal(await text.join(), true);
  const textEcho = services.next();
  assert.equal(textEcho.body, 'checked text');
  assert.equal(reserves, 1);
  const operation = id();
  services.claim_transfer({operation_id: operation, submission_id: textEcho.submission_id,
    envelope_digest: sha256(Buffer.from(JSON.stringify(textEcho))), claim_audit_ref: id()});
  const revoked = await services.revoke({operation_id: operation, capabilities: []});
  services.settle({operation_id: operation, revocation_ref: revoked.revocation_ref,
    receipt_digest: 'a'.repeat(64)});

  const document = f.owner.deliveryProducer('synthetic@g.us', 'artifact', {
    mime: 'text/plain', file_name: 'checked.txt', reply: null,
  }, {stream: Readable.from([Buffer.from('checked document')])});
  assert.equal((await document.dispatch()).id, 'echo-aware-2');
  assert.equal(await document.join(), true);
  assert.equal(services.next().native.kind, 'document');
  assert.equal(reserves, 2);
  assert.equal(await f.native.close(), true);
});

test('T8 composed send controls offline append and successor stay active', async t => {
  const originalReserve = PrivateTombstones.prototype.reserve;
  let reserves = 0;
  t.mock.method(PrivateTombstones.prototype, 'reserve', function (...args) {
    reserves++;
    return originalReserve.apply(this, args);
  });
  let config, socket;
  const f = await fixture(t, value => {
    config = value;
    socket = echoAwareSocket(value);
    return socket;
  });
  await f.native.activate();
  const services = f.native.services();
  const text = f.owner.deliveryProducer('synthetic@g.us', 'text', {
    text: 'checked text',
    reply: {native_kind: 'text', text: 'checked quote', key: {id: 'quoted-text',
      remote_jid: 'synthetic@g.us', participant: '300@s.whatsapp.net', from_me: false}},
  });
  assert.equal((await text.dispatch()).id, 'echo-aware-1');
  assert.equal(await text.join(), true);
  await tick();
  assert.equal(services.next(), null);
  assert.equal(reserves, 0);
  const document = f.owner.deliveryProducer('synthetic@g.us', 'artifact', {
    mime: 'text/plain', file_name: 'checked.txt', reply: null,
  }, {stream: Readable.from([Buffer.from('checked document')])});
  assert.equal((await document.dispatch()).id, 'echo-aware-2');
  assert.equal(await document.join(), true);
  await tick();
  assert.equal(services.next(), null);
  assert.equal(reserves, 0);
  assert.equal(config.emitOwnEvents, false);

  const controls = [
    {appStateSyncKeyShare: {keys: []}},
    {historySyncNotification: {syncType: 0}},
    {lidMigrationMappingSyncMessage: {encodedMappingPayload: Buffer.alloc(0)}},
    {peerDataOperationRequestMessage: {placeholderMessageResendRequest: []}},
  ];
  for (let index = 0; index < controls.length; index++) {
    await socket.offerMessage({
      key: {id: `self-control-${index}`, remoteJid: index % 2 ? '200@lid' : '100@s.whatsapp.net', fromMe: true},
      messageTimestamp: 1800000000 + index, message: controls[index],
    }, 'append');
    assert.equal(services.next(), null);
    assert.equal(reserves, 0);
  }

  await socket.offerMessage({
    key: {id: 'offline-text', remoteJid: 'synthetic@g.us',
      participant: '300@s.whatsapp.net', fromMe: false},
    messageTimestamp: 1800000010, message: {conversation: 'authorized offline append'},
  }, 'append');
  const offline = services.next();
  assert.equal(offline.body, 'authorized offline append');
  assert.equal(reserves, 1);
  const operation = id();
  services.claim_transfer({operation_id: operation, submission_id: offline.submission_id,
    envelope_digest: sha256(Buffer.from(JSON.stringify(offline))), claim_audit_ref: id()});
  const revoked = await services.revoke({operation_id: operation, capabilities: []});
  services.settle({operation_id: operation, revocation_ref: revoked.revocation_ref,
    receipt_digest: 'a'.repeat(64)});

  await socket.offerMessage({
    key: {id: 'next-text', remoteJid: 'synthetic@g.us',
      participant: '300@s.whatsapp.net', fromMe: false},
    messageTimestamp: 1800000011, message: {conversation: 'next authorized text'},
  }, 'notify');
  assert.equal(services.next().body, 'next authorized text');
  assert.equal(reserves, 2);
  assert.equal(f.counts().drains, 0);
  assert.equal(await services.activate(), true);
  assert.equal(await f.native.close(), true);
});

test('T1 update traffic is unwired and a 33-refusal burst drains without a partial offer', async t => {
  const originalUpsert = PrivateProjection.prototype.upsert;
  let projections = 0;
  t.mock.method(PrivateProjection.prototype, 'upsert', function (...args) {
    projections++;
    return originalUpsert.apply(this, args);
  });
  let socket;
  const f = await fixture(t, config => { socket = syntheticSocket(config); return socket; });
  await f.native.activate();
  const services = f.native.services();
  const key = index => ({id: `update-${index}`, remoteJid: 'synthetic@g.us',
    participant: '300@s.whatsapp.net', fromMe: false});

  socket.ev.emit('messages.update', [{key: key('receipt'), update: {status: 3}}]);
  socket.ev.emit('messages.update', Array.from({length: 33}, (_, index) => (
    {key: key(index), update: {status: 3}}
  )));
  socket.ev.emit('messages.update', [{key: key('poll'), update: {pollUpdates: [{pollUpdateMessageKey: key('vote')}]} }]);
  await tick();
  assert.equal(projections, 0);
  assert.equal(services.next(), null);
  assert.equal(f.counts().drains, 0);

  socket.ev.emit('messages.upsert', {type: 'notify', messages: Array.from({length: 33}, (_, index) => ({
    key: {id: `refused-${index}`, remoteJid: 'synthetic@g.us',
      participant: '300@s.whatsapp.net', fromMe: false},
    messageTimestamp: 1800000000 + index,
    message: {imageMessage: {}},
  }))});
  await tick();
  assert.equal(projections, 1);
  assert.equal(f.counts().drains, 1);
  assert.equal(services.next(), null);
  await assert.rejects(f.native.activate(), {message: 'not_ready'});
  assert.equal(await f.native.close(), true);
});

test('R7-P2-B mixed 33-message offline flush drains an authorized client text without emitting its bytes', async t => {
  const canary = 'N2O10-SYNTHETIC-OFFLINE-FLUSH-CANARY-7f3a91';
  const originalReserve = PrivateTombstones.prototype.reserve;
  const originalDrain = PrivateAdmissions.prototype.drain;
  let reserves = 0;
  const drainReasons = [];
  t.mock.method(PrivateTombstones.prototype, 'reserve', function (...args) {
    reserves++;
    return originalReserve.apply(this, args);
  });
  t.mock.method(PrivateAdmissions.prototype, 'drain', function (...args) {
    drainReasons.push(args[0]);
    return originalDrain.apply(this, args);
  });
  let socket;
  const f = await fixture(t, config => { socket = syntheticSocket(config); return socket; });
  await f.native.activate();
  const services = f.native.services();
  const key = index => ({id: `offline-flush-${index}`, remoteJid: 'synthetic@g.us',
    participant: '300@s.whatsapp.net', fromMe: false});
  // One authorized client text addressed to the bot (a mention of the account), then the
  // media-kind controls that make the batch exactly 33 envelopes, one past the 32 slots.
  const messages = Array.from({length: 33}, (_, index) => ({
    key: key(index), messageTimestamp: 1800000000 + index,
    message: index === 0
      ? {extendedTextMessage: {text: canary, contextInfo: {mentionedJid: ['100@s.whatsapp.net']}}}
      : {imageMessage: {}},
  }));
  // Non-vacuity: the canary really is in the batch the lane received, exactly once.
  assert.equal(messages.filter(message => JSON.stringify(message).includes(canary)).length, 1);
  assert.equal(messages[0].message.extendedTextMessage.text, canary);

  socket.ev.emit('messages.upsert', {type: 'append', messages});
  await tick();
  // The whole batch is drained by the capacity rule: no slot, no offer, no reservation.
  assert.equal(f.counts().drains, 1);
  assert.ok(drainReasons.length > 0);
  assert.deepEqual([...new Set(drainReasons)], ['capacity']);
  assert.equal(services.next(), null);
  assert.equal(reserves, 0);
  // The lane latches unhealthy: activation can never succeed again on this generation.
  const rejection = await services.activate().then(() => null, error => error);
  assert.ok(rejection instanceof Error);
  assert.equal(rejection.message, 'not_ready');
  // Every byte the drain path DOES emit carries none of the text's bytes.
  const emitted = [...drainReasons, rejection.message];
  for (const payload of emitted) assert.equal(String(payload).includes(canary), false);
  assert.equal(await f.native.close(), true);
});

test('validated spool streams through the SDK document producer in bounded pieces', async t => {
  const payload = Buffer.alloc(140001, 7), recipient = 'synthetic@g.us', generation = '2'.repeat(32);
  let sent = null, maxPiece = 0;
  const f = await fixture(t, config => {
    const socket = syntheticSocket(config);
    socket.sendMessage = async (jid, content, options) => {
      const chunks = [];
      for await (const piece of content.document.stream) {
        maxPiece = Math.max(maxPiece, piece.length); chunks.push(piece);
      }
      sent = {jid, content, options, bytes: Buffer.concat(chunks)};
      return {key: {id: 'spooled-document', remoteJid: jid, fromMe: true}};
    };
    return socket;
  });
  await f.native.activate();
  const authority = {directory: path.join(f.directory, 'spools'), files: path.join(f.directory, 'files'), key: 'a'.repeat(64)};
  await mkdir(authority.directory, {mode: 0o700}); await mkdir(authority.files, {mode: 0o700});
  const operation = id(), stage = id() + '.stage', final = id() + '.spool';
  const data = {context: {operation_id: operation, conversation_ref: id(), epoch: id()}, handle: id(),
    size: payload.length, sha256: sha256(payload), mime: 'application/pdf', file_name: 'synthetic.pdf', reply: null};
  const stageFile = await open(path.join(authority.files, stage), 'wx+', 0o600);
  const fileInfo = await stageFile.stat({bigint: true}); await stageFile.close();
  const directoryInfo = await lstat(authority.files, {bigint: true});
  const grant = {v: 1, profile, generation, owner_pid: process.pid, owner_start: 'os1:synthetic',
    operation, conversation: data.context.conversation_ref, epoch: data.context.epoch, run: id(),
    handle: data.handle, file_ref: id(), stage, final, device: Number(fileInfo.dev), inode: Number(fileInfo.ino),
    directory_device: Number(directoryInfo.dev), directory_inode: Number(directoryInfo.ino), size: data.size,
    sha256: data.sha256, request_digest: sha256(typedBytes([3, 'delivery-request-v1', profile, generation,
      operation, 'artifact_prepare', typed(data)])), expires: Date.now() + 60000, allocation_bytes: 16777216};
  const body = JSON.stringify(grant);
  await writeFile(path.join(authority.directory, operation + '.spool.json'), JSON.stringify({body,
    mac: createHmac('sha256', Buffer.from(authority.key, 'hex')).update(body).digest('hex')}), {mode: 0o600});
  const producer = f.owner.documentProducer({recipient, generation, authority, data});
  assert.equal(await producer.prepare({consume: async sink => {
    await sink(payload.subarray(0, 60000)); await sink(payload.subarray(60000, 120000));
    await sink(payload.subarray(120000));
  }}), true);
  assert.equal((await producer.dispatch()).id, 'spooled-document');
  assert.equal(await producer.join(), true);
  assert.equal(sent.jid, recipient); assert.equal(sent.options && Object.keys(sent.options).length, 0);
  assert.equal(sent.content.mimetype, data.mime); assert.equal(sent.content.fileName, data.file_name);
  assert.deepEqual(sent.bytes, payload); assert.ok(maxPiece <= 65536);
  assert.equal(await f.native.close(), true);
});

test('SDK cancellation cuts the socket but retains a late successful send until join', async t => {
  let release;
  const pending = new Promise(resolve => { release = resolve; });
  const f = await fixture(t, config => {
    const socket = syntheticSocket(config); socket.sendMessage = () => pending; return socket;
  });
  await f.native.activate();
  const producer = f.owner.deliveryProducer('synthetic@g.us', 'text', {text: 'synthetic', reply: null});
  const sending = producer.dispatch(); await tick();
  producer.cancel();
  let joined = false;
  const closing = f.native.close().then(result => { joined = true; return result; });
  await tick(); assert.equal(joined, false);
  release({key: {id: 'late-success', remoteJid: 'synthetic@g.us', fromMe: true}});
  assert.equal((await sending).id, 'late-success');
  assert.equal(await closing, true);
});

test('real pinned SDK connects only to synthetic loopback and joins its actual WebSocket', {timeout: 15000}, async t => {
  const server = new WebSocketServer({host: '127.0.0.1', port: 0});
  await once(server, 'listening');
  t.after(() => new Promise(resolve => { for (const peer of server.clients) peer.terminate(); server.close(resolve); }));
  let socket;
  const f = await fixture(t, config => {
    // Only the external peer is replaced. Use the real SDK constructor,
    // auth transaction wrapper, event buffer, socket-end handlers and WS.
    socket = sdk.makeWASocket({...config, waWebSocketUrl: `ws://127.0.0.1:${server.address().port}`, connectTimeoutMs: 1000});
    return socket;
  });
  const connection = once(server, 'connection');
  const activation = f.native.activate();
  const [peer] = await connection;
  assert.equal(socket.ws.isClosed, false);
  const peerClosed = once(peer, 'close');
  const closing = f.native.close();
  await assert.rejects(activation);
  assert.equal(await closing, true);
  await peerClosed;
  assert.equal(socket.ws.isClosed, true);
  assert.equal(f.counts().opens, 1);
  await assert.rejects(lstat(path.join(f.directory, 'owner.lock')), {code: 'ENOENT'});
});
