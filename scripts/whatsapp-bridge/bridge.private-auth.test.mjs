import assert from 'node:assert/strict';
import {test} from 'node:test';
import {mkdtemp, realpath, writeFile, readFile, rm, chmod, symlink, lstat, open} from 'node:fs/promises';
import path from 'node:path';
import os from 'node:os';
import {spawn, spawnSync} from 'node:child_process';
import {once} from 'node:events';
import {fileURLToPath} from 'node:url';
import {BufferJSON, initAuthCreds, proto} from '@whiskeysockets/baileys';
import {PrivateAuthStore, AUTH_BYTES} from './private_auth.mjs';
import {allocate} from './private-auth-test-support.mjs';

const profile = '1'.repeat(32);
const codec = {...BufferJSON, appStateKey: value => proto.Message.AppStateSyncKeyData.fromObject(value)};
const tick = () => new Promise(resolve => setImmediate(resolve));
async function fixture(t) {
  const directory = await realpath(await mkdtemp(path.join(os.tmpdir(), 'private-auth-test-')));
  t.after(() => rm(directory, {recursive: true, force: true}));
  const creds = initAuthCreds();
  creds.registered = true; creds.me = {id: '100:1@s.whatsapp.net', lid: '200@lid', name: 'synthetic private name'};
  const file = path.join(directory, 'account.json');
  await writeFile(file, JSON.stringify({v: 1, profile, creds, keys: []}, BufferJSON.replacer), {mode: 0o600});
  let faults = 0;
  const options = {directory, profile, codec, allocation_digest: await allocate(directory, profile), onFault: () => { faults++; }};
  return {directory, file, creds, options, faults: () => faults};
}

test('real SDK keys, binary credentials and profile survive atomic close/reopen', async t => {
  const f = await fixture(t), store = await PrivateAuthStore.open(f.options);
  const original = Buffer.from(store.state.creds.noiseKey.private);
  const value = Buffer.from('synthetic-session');
  await store.state.keys.set({session: {'../same:key': value}, 'app-state-sync-key': {
    key1: proto.Message.AppStateSyncKeyData.fromObject({keyData: Buffer.from('synthetic-key')})}});
  value.fill(0);
  const first = await store.state.keys.get('session', ['../same:key']);
  assert.equal(first['../same:key'].toString(), 'synthetic-session');
  first['../same:key'].fill(0);
  assert.equal((await store.state.keys.get('session', ['../same:key']))['../same:key'].toString(), 'synthetic-session');
  assert.deepEqual(store.account(), {id: f.creds.me.id, lid: f.creds.me.lid});
  assert.equal(await store.join(), true);
  const reopened = await PrivateAuthStore.open(f.options);
  assert.deepEqual(reopened.state.creds.noiseKey.private, original);
  const appState = (await reopened.state.keys.get('app-state-sync-key', ['key1'])).key1;
  assert.ok(appState instanceof proto.Message.AppStateSyncKeyData);
  assert.equal(appState.keyData.toString(), 'synthetic-key');
  await reopened.state.keys.set({session: {'../same:key': null}});
  assert.equal(Object.keys(await reopened.state.keys.get('session', ['../same:key'])).length, 0);
  assert.equal(await reopened.join(), true);
  assert.equal((await lstat(f.file)).mode & 0o777, 0o600);
});

test('one exclusive owner; simultaneous writes retain every committed key', async t => {
  const f = await fixture(t), store = await PrivateAuthStore.open(f.options);
  await assert.rejects(PrivateAuthStore.open(f.options), {message: 'private_auth_fault'});
  await Promise.all(Array.from({length: 16}, (_, n) => store.state.keys.set({session: {[String(n)]: Buffer.from([n])}})));
  assert.equal(Object.keys(await store.state.keys.get('session', Array.from({length: 16}, (_, n) => String(n)))).length, 16);
  assert.equal(await store.join(), true);
});

test('allocation replacement or unaccounted growth fences before another snapshot write', async t => {
  for (const fault of ['allocation', 'unknown']) {
    const f = await fixture(t), store = await PrivateAuthStore.open(f.options);
    const before = await readFile(f.file);
    if (fault === 'allocation') await allocate(f.directory, profile);
    else await writeFile(path.join(f.directory, 'unexpected'), 'synthetic', {mode: 0o600});
    await assert.rejects(store.save(), {message: 'private_auth_fault'});
    assert.deepEqual(await readFile(f.file), before);
    assert.equal(await store.join(), true);
    assert.ok((await lstat(path.join(f.directory, 'owner.lock'))).isFile());
  }
});

test('absent or another process allocation cannot open a credential writer', async t => {
  const f = await fixture(t);
  await assert.rejects(PrivateAuthStore.open({...f.options, allocation_digest: undefined}));
  const digest = await allocate(f.directory, profile, process.pid + 1);
  await assert.rejects(PrivateAuthStore.open({...f.options, allocation_digest: digest}));
  await assert.rejects(lstat(path.join(f.directory, 'owner.lock')), {code: 'ENOENT'});
});

for (const kind of ['missing', 'malformed', 'duplicate', 'profile', 'unregistered', 'symlink', 'mode', 'directory', 'fifo', 'oversized', 'interrupted']) {
  test(`bootstrap refuses ${kind} state without creating credentials`, async t => {
    const f = await fixture(t);
    if (kind === 'missing') await rm(f.file);
    if (kind === 'malformed') await writeFile(f.file, '{"private canary"');
    if (kind === 'duplicate') await writeFile(f.file, '{"v":1,"v":1}');
    if (kind === 'profile') f.options.profile = '2'.repeat(32);
    if (kind === 'unregistered') {
      f.creds.registered = false;
      await writeFile(f.file, JSON.stringify({v: 1, profile, creds: f.creds, keys: []}, BufferJSON.replacer));
    }
    if (kind === 'symlink') { await rm(f.file); await symlink('absent-private-target', f.file); }
    if (kind === 'mode') await chmod(f.file, 0o644);
    if (kind === 'directory') { await chmod(f.directory, 0o755); }
    if (kind === 'fifo') {
      await rm(f.file);
      assert.equal(spawnSync('mkfifo', ['-m', '600', f.file]).status, 0);
    }
    if (kind === 'oversized') await writeFile(f.file, Buffer.alloc(AUTH_BYTES + 1));
    if (kind === 'interrupted') await writeFile(path.join(f.directory, 'account.next'), 'partial', {mode: 0o600});
    await assert.rejects(PrivateAuthStore.open(f.options), {message: 'private_auth_fault'});
    if (kind === 'missing') await assert.rejects(lstat(f.file), {code: 'ENOENT'});
  });
}

test('invalid mutation fences the writer and preserves durable bytes for recovery', async t => {
  const f = await fixture(t), store = await PrivateAuthStore.open(f.options);
  const before = await readFile(f.file), state = store.state;
  await assert.rejects(state.keys.set({unknown: {canary: 'private'}}), {message: 'private_auth_fault'});
  await assert.rejects(state.keys.set({session: {other: Buffer.from('no-write')}}));
  assert.equal(f.faults(), 1);
  assert.equal(await store.join(), true); // failed outcome, completed producer
  assert.deepEqual(await readFile(f.file), before);
  await assert.rejects(PrivateAuthStore.open(f.options)); // explicit recovery required
});

test('account change and externally replaced snapshot cannot overwrite captured identity', async t => {
  for (const change of ['account', 'snapshot']) {
    const f = await fixture(t), store = await PrivateAuthStore.open(f.options);
    if (change === 'account') store.state.creds.me.id = '999@s.whatsapp.net';
    else await writeFile(f.file, '{}');
    const before = await readFile(f.file);
    await assert.rejects(store.save(), {message: 'private_auth_fault'});
    assert.deepEqual(await readFile(f.file), before);
    assert.equal(await store.join(), true);
  }
});

test('replaced owner lock fences storage and cannot delete the replacement', async t => {
  const f = await fixture(t), store = await PrivateAuthStore.open(f.options), before = await readFile(f.file);
  const lock = path.join(f.directory, 'owner.lock');
  await rm(lock); await writeFile(lock, 'replacement-owner', {mode: 0o600});
  await assert.rejects(store.save(), {message: 'private_auth_fault'});
  assert.equal(await store.join(), false);
  assert.equal(await readFile(lock, 'utf8'), 'replacement-owner');
  assert.deepEqual(await readFile(f.file), before);
});

test('join waits for actual file sync and fences late SDK writes', async t => {
  const f = await fixture(t), store = await PrivateAuthStore.open(f.options), state = store.state;
  const handle = await open(f.file), prototype = Object.getPrototypeOf(handle);
  await handle.close();
  const originalSync = prototype.sync;
  let release, entered;
  const blocked = new Promise(resolve => { release = resolve; });
  const reached = new Promise(resolve => { entered = resolve; });
  let once = true;
  t.mock.method(prototype, 'sync', async function () {
    if (once) { once = false; entered(); await blocked; }
    return originalSync.call(this);
  });
  const saving = store.save(); await reached;
  let finished = false;
  const joining = store.join().then(value => { finished = true; return value; });
  await tick(); assert.equal(finished, false);
  release();
  assert.equal(await saving, true); assert.equal(await joining, true);
  await assert.rejects(state.keys.set({session: {late: Buffer.from('ignored')}}));
});

test('bounded pending auth work faults once without a promise per key', async t => {
  const f = await fixture(t), store = await PrivateAuthStore.open(f.options);
  const outcomes = await Promise.allSettled(Array.from({length: 40}, () => store.save()));
  assert.ok(outcomes.every(value => value.status === 'rejected'));
  assert.equal(f.faults(), 1);
  assert.equal(await store.join(), true);
});

for (const kind of ['bytes', 'depth', 'key-count', 'duplicate-read']) {
  test(`auth ${kind} bound refuses without replacing durable state`, async t => {
    const f = await fixture(t), store = await PrivateAuthStore.open(f.options), before = await readFile(f.file);
    let work;
    if (kind === 'bytes') work = store.state.keys.set({session: {large: Buffer.alloc(AUTH_BYTES)}});
    if (kind === 'depth') {
      let value = 'synthetic'; for (let n = 0; n < 25; n++) value = {nested: value};
      work = store.state.keys.set({session: {deep: value}});
    }
    if (kind === 'key-count') work = store.state.keys.set({session: Object.fromEntries(
      Array.from({length: 4097}, (_, n) => [String(n), 'synthetic']))});
    if (kind === 'duplicate-read') work = store.state.keys.get('session', ['same', 'same']);
    await assert.rejects(work, {message: 'private_auth_fault'});
    assert.equal(await store.join(), true);
    assert.deepEqual(await readFile(f.file), before);
    assert.equal(f.faults(), 1);
  });
}

test('actual writer death before sync retains the previous snapshot and withholds reopen', {timeout: 10000}, async t => {
  const f = await fixture(t), before = await readFile(f.file);
  const child = spawn(process.execPath, ['--input-type=module', '-e', `
    import {open} from 'node:fs/promises';
    import {BufferJSON, proto} from '@whiskeysockets/baileys';
    import {PrivateAuthStore} from './private_auth.mjs';
    import {allocate} from './private-auth-test-support.mjs';
    const store = await PrivateAuthStore.open({directory: process.argv[1], profile: '${profile}',
      allocation_digest: await allocate(process.argv[1], '${profile}'),
      codec: {...BufferJSON, appStateKey: value => proto.Message.AppStateSyncKeyData.fromObject(value)}, onFault() {}});
    const handle = await open(process.argv[1] + '/account.json');
    const prototype = Object.getPrototypeOf(handle); await handle.close();
    prototype.sync = async function () { process.send('write-held'); await new Promise(() => {}); };
    process.on('message', () => {});
    await store.state.keys.set({session: {new: Buffer.from('synthetic-uncommitted')}});
  `, f.directory], {cwd: fileURLToPath(new URL('.', import.meta.url)),
    env: {LANG: 'C.UTF-8', TZ: 'UTC'}, stdio: ['ignore', 'ignore', 'ignore', 'ipc']});
  t.after(() => { if (child.exitCode === null && child.signalCode === null) child.kill('SIGKILL'); });
  const [message] = await once(child, 'message'); assert.equal(message, 'write-held');
  const exited = once(child, 'exit'); child.kill('SIGKILL'); await exited;
  assert.deepEqual(await readFile(f.file), before);
  assert.ok((await lstat(path.join(f.directory, 'account.next'))).isFile());
  await assert.rejects(PrivateAuthStore.open(f.options), {message: 'private_auth_fault'});
});
