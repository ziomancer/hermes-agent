// Explicit private account store. Never creates an account, pairs, imports an
// ordinary session directory, or repairs unreadable state. Requires a captured
// runtime allocation for this process and the snapshot/replacement pair.
// Native activation remains disabled pending complete production qualification.
import {constants} from 'node:fs';
import {open, lstat, realpath, rename, unlink, readdir, statfs} from 'node:fs/promises';
import path from 'node:path';
import {createHash} from 'node:crypto';
import {strictJSON} from './private_framing.mjs';

export const AUTH_BYTES = 8 * 1024 * 1024;
export const AUTH_ALLOCATION_BYTES = 2 * AUTH_BYTES + 65536;
const MAX_KEYS = 4096, MAX_PENDING = 32;
const TYPES = new Set(['pre-key', 'session', 'sender-key', 'sender-key-memory',
  'app-state-sync-key', 'app-state-sync-version', 'lid-mapping', 'device-list', 'tctoken', 'identity-key']);
const fail = () => Error('private_auth_fault');
const object = value => value !== null && typeof value === 'object' && !Array.isArray(value);
function key(type, id) {
  if (!TYPES.has(type) || typeof id !== 'string' || !id || Buffer.byteLength(id) > 256) throw fail();
  return JSON.stringify([type, id]);
}
function account(creds) {
  const me = creds?.me;
  if (!object(creds) || creds.registered !== true || !object(me) ||
      typeof me.id !== 'string' || !/^[0-9]+(?::[0-9]+)?@s\.whatsapp\.net$/.test(me.id) ||
      Buffer.byteLength(me.id) > 256 || (me.lid !== undefined &&
      (typeof me.lid !== 'string' || !/^[0-9]+(?::[0-9]+)?@lid$/.test(me.lid) || Buffer.byteLength(me.lid) > 256))) throw fail();
  return Object.freeze({id: me.id, ...(me.lid === undefined ? {} : {lid: me.lid})});
}
function privateStat(stat, directory = false) {
  if (!(directory ? stat.isDirectory() : stat.isFile()) ||
      (stat.mode & 0o777) !== (directory ? 0o700 : 0o600) ||
      stat.uid !== process.getuid() || (!directory && stat.nlink !== 1)) throw fail();
}
function boundedValue(value) {
  // Bound traversal before JSON.stringify/Buffer.toJSON allocates an encoded
  // copy. SDK auth data may contain peer-provided arrays and strings.
  let nodes = 0, bytes = 0;
  const seen = new Set();
  function walk(item, depth) {
    if (++nodes > 16384 || depth > 20) throw fail();
    if (typeof item === 'string') bytes += Buffer.byteLength(item);
    else if (Buffer.isBuffer(item) || item instanceof Uint8Array) bytes += item.byteLength * 2;
    else if (item !== null && typeof item === 'object') {
      if (seen.has(item)) throw fail();
      seen.add(item);
      if (Array.isArray(item) && item.length > MAX_KEYS) throw fail();
      for (const name of Object.keys(item)) {
        bytes += Buffer.byteLength(name);
        if (bytes > AUTH_BYTES) throw fail();
        walk(item[name], depth + 1);
      }
      seen.delete(item);
    } else if (!['number', 'boolean', 'undefined'].includes(typeof item) && item !== null) throw fail();
    if (bytes > AUTH_BYTES) throw fail();
  }
  walk(value, 0);
}

export class PrivateAuthStore {
  #directory;
  #directoryStat;
  #directoryHandle;
  #lock;
  #codec;
  #profile;
  #creds;
  #account;
  #keys = new Map();
  #tail = Promise.resolve();
  #pending = 0;
  #failed = false;
  #closed = false;
  #joining = null;
  #onFault;
  #state;
  #digest;
  #allocationDigest;

  static async open({directory, profile, codec, onFault, allocation_digest}) {
    const store = new PrivateAuthStore();
    try {
      if (typeof process.getuid !== 'function' || typeof directory !== 'string' ||
          !path.isAbsolute(directory) || path.normalize(directory) !== directory ||
          typeof profile !== 'string' || !/^[0-9a-f]{32}$/.test(profile) ||
          typeof codec?.replacer !== 'function' || typeof codec?.reviver !== 'function' ||
          typeof codec?.appStateKey !== 'function' || typeof onFault !== 'function' ||
          typeof allocation_digest !== 'string' || !/^[0-9a-f]{64}$/.test(allocation_digest)) throw fail();
      // realpath equality rejects symlink components, including an ordinary
      // session symlink. No mkdir or default HOME/session fallback.
      if (await realpath(directory) !== directory) throw fail();
      store.#directory = directory; store.#profile = profile;
      store.#codec = codec; store.#onFault = onFault;
      store.#directoryStat = await lstat(directory);
      privateStat(store.#directoryStat, true);
      store.#directoryHandle = await open(directory, constants.O_RDONLY | constants.O_DIRECTORY | constants.O_NOFOLLOW);
      await store.#checkDirectory();
      const allocationBytes = await store.#read('allocation.json', 4096);
      if (createHash('sha256').update(allocationBytes).digest('hex') !== allocation_digest) throw fail();
      const allocation = strictJSON(allocationBytes, 4096);
      if (!object(allocation) || Object.keys(allocation).sort().join() !==
          'account,allocation_bytes,device,directory,generation,inode,owner_pid,owner_start,profile,snapshot_bytes,token,v' ||
          allocation.v !== 1 || allocation.profile !== profile || allocation.directory !== directory ||
          allocation.owner_pid !== process.pid || allocation.device !== store.#directoryStat.dev ||
          allocation.inode !== store.#directoryStat.ino || allocation.snapshot_bytes !== AUTH_BYTES ||
          allocation.allocation_bytes !== AUTH_ALLOCATION_BYTES || !/^[0-9a-f]{32}$/.test(allocation.generation) ||
          !/^[0-9a-f]{32}$/.test(allocation.token) || typeof allocation.owner_start !== 'string' ||
          !allocation.owner_start || Buffer.byteLength(allocation.owner_start) > 128 ||
          typeof allocation.account !== 'string') throw fail();
      store.#allocationDigest = allocation_digest;
      await store.#checkBudget();
      store.#lock = await open(path.join(directory, 'owner.lock'), constants.O_WRONLY | constants.O_CREAT |
        constants.O_EXCL | constants.O_NOFOLLOW, 0o600);
      await store.#lock.writeFile(allocation_digest);
      await store.#lock.sync(); await store.#directoryHandle.sync();
      try { await lstat(path.join(directory, 'account.next')); throw fail(); }
      catch (error) { if (error.code !== 'ENOENT') throw fail(); }
      const bytes = await store.#read();
      store.#digest = createHash('sha256').update(bytes).digest('hex');
      const value = strictJSON(bytes, AUTH_BYTES);
      if (!object(value) || Object.keys(value).sort().join() !== 'creds,keys,profile,v' ||
          value.v !== 1 || value.profile !== profile || !Array.isArray(value.keys) || value.keys.length > MAX_KEYS) throw fail();
      store.#creds = store.#decode(value.creds);
      store.#account = account(store.#creds);
      if (store.#account.id !== allocation.account) throw fail();
      for (const entry of value.keys) {
        if (!Array.isArray(entry) || entry.length !== 3 || entry[2] === null) throw fail();
        const name = key(entry[0], entry[1]);
        if (store.#keys.has(name)) throw fail();
        store.#keys.set(name, entry[2]);
      }
      store.#state = Object.freeze({creds: store.#creds, keys: Object.freeze({
        get: (type, ids) => store.#get(type, ids), set: values => store.#set(values),
      })});
      return store;
    } catch {
      // Only remove this opener's exclusive lock; never steal a pre-existing
      // lock after a crash. Recovery requires the parent owner's death proof.
      await store.join().catch(() => {});
      throw fail();
    }
  }

  get state() { if (this.#closed || this.#failed) throw fail(); return this.#state; }
  account() { if (this.#closed || this.#failed) throw fail(); return this.#account; }

  async #checkDirectory() {
    const current = await lstat(this.#directory), held = await this.#directoryHandle.stat();
    privateStat(current, true); privateStat(held, true);
    if (current.ino !== held.ino || current.dev !== held.dev || held.ino !== this.#directoryStat.ino ||
        held.dev !== this.#directoryStat.dev || await realpath(this.#directory) !== this.#directory) throw fail();
    if (this.#lock) {
      const owner = await this.#lock.stat(), named = await lstat(path.join(this.#directory, 'owner.lock'));
      privateStat(owner); privateStat(named);
      if (owner.ino !== named.ino || owner.dev !== named.dev) throw fail();
    }
  }

  async #read(name = 'account.json', limit = AUTH_BYTES) {
    await this.#checkDirectory();
    const handle = await open(path.join(this.#directory, name), constants.O_RDONLY |
      constants.O_NOFOLLOW | constants.O_NONBLOCK);
    try {
      const before = await handle.stat(); privateStat(before);
      if (before.size < 1 || before.size > limit) throw fail();
      const bytes = Buffer.alloc(before.size + 1);
      let used = 0;
      while (used < bytes.length) {
        const {bytesRead} = await handle.read(bytes, used, bytes.length - used, used);
        if (!bytesRead) break;
        used += bytesRead;
      }
      const after = await handle.stat(); privateStat(after);
      const named = await lstat(path.join(this.#directory, name)); privateStat(named);
      if (used !== before.size || before.size !== after.size || before.mtimeMs !== after.mtimeMs ||
          before.ctimeMs !== after.ctimeMs || named.dev !== after.dev || named.ino !== after.ino ||
          named.size !== after.size || named.mtimeMs !== after.mtimeMs || named.ctimeMs !== after.ctimeMs) throw fail();
      await this.#checkDirectory();
      return bytes.subarray(0, used);
    } finally { await handle.close(); }
  }

  async #checkBudget() {
    if (createHash('sha256').update(await this.#read('allocation.json', 4096)).digest('hex') !== this.#allocationDigest) throw fail();
    const limits = {'account.json': AUTH_BYTES, 'account.next': AUTH_BYTES, 'owner.lock': 64, 'allocation.json': 4096};
    for (const name of await readdir(this.#directory)) {
      if (!Object.hasOwn(limits, name)) throw fail();
      const info = await lstat(path.join(this.#directory, name));
      privateStat(info);
      if (info.size > limits[name]) throw fail();
    }
    const space = await statfs(this.#directory);
    if (space.bavail * space.bsize < AUTH_ALLOCATION_BYTES + 67108864) throw fail();
  }

  #decode(value) { return JSON.parse(JSON.stringify(value), this.#codec.reviver); }
  #encode(value) {
    // Round-trip through the bounded strict parser before retaining a caller
    // object. Buffers/protobuf objects are copied, never shared with key callers.
    boundedValue(value);
    const text = JSON.stringify(value, this.#codec.replacer);
    if (typeof text !== 'string' || Buffer.byteLength(text) > AUTH_BYTES) throw fail();
    return strictJSON(Buffer.from(text), AUTH_BYTES);
  }
  #fault() {
    if (!this.#failed) { this.#failed = true; try { this.#onFault?.(); } catch { /* fixed failure only */ } }
  }
  #enqueue(work) {
    if (this.#closed || this.#failed || this.#pending >= MAX_PENDING) {
      this.#fault(); return Promise.reject(fail());
    }
    this.#pending++;
    const result = this.#tail.then(async () => {
      if (this.#failed) throw fail();
      try { return await work(); } catch { this.#fault(); throw fail(); }
    });
    this.#tail = result.catch(() => {}).finally(() => { this.#pending--; });
    return result;
  }
  #get(type, ids) {
    if (!Array.isArray(ids) || ids.length > MAX_KEYS) { this.#fault(); return Promise.reject(fail()); }
    ids = [...ids];
    if (new Set(ids).size !== ids.length) { this.#fault(); return Promise.reject(fail()); }
    return this.#enqueue(async () => {
      if (!Array.isArray(ids) || ids.length > MAX_KEYS) throw fail();
      const result = Object.create(null);
      for (const id of ids) {
        const value = this.#keys.get(key(type, id));
        if (value !== undefined) {
          const decoded = this.#decode(value);
          result[id] = type === 'app-state-sync-key' ? this.#codec.appStateKey(decoded) : decoded;
        }
      }
      return result;
    });
  }
  #set(values) {
    // Capture mutations at invocation time, before any asynchronous queue wait.
    let copy;
    if (this.#closed || this.#failed || this.#pending >= MAX_PENDING) { this.#fault(); return Promise.reject(fail()); }
    try { copy = this.#encode(values); } catch { this.#fault(); return Promise.reject(fail()); }
    return this.#enqueue(async () => {
      if (!object(copy)) throw fail();
      const next = new Map(this.#keys);
      for (const [type, values] of Object.entries(copy)) {
        if (!TYPES.has(type) || !object(values)) throw fail();
        for (const [id, value] of Object.entries(values)) {
          const name = key(type, id);
          if (value === null) next.delete(name); else next.set(name, value);
          if (next.size > MAX_KEYS) throw fail();
        }
      }
      await this.#persist(next);
      this.#keys = next;
    });
  }
  save() { return this.#enqueue(async () => { await this.#persist(this.#keys); return true; }); }

  async #persist(keys) {
    const observed = account(this.#creds);
    // The device-qualified PN is fixed; the authenticated SDK may learn the
    // LID once. A later conflicting alias must not rebind this account.
    if (observed.id !== this.#account.id || (this.#account.lid !== undefined && observed.lid !== this.#account.lid)) throw fail();
    const entries = Array.from(keys, ([name, value]) => [...JSON.parse(name), value]);
    const encoded = Buffer.from(JSON.stringify({v: 1, profile: this.#profile,
      creds: this.#encode(this.#creds), keys: entries}));
    if (encoded.length > AUTH_BYTES) throw fail();
    await this.#checkDirectory();
    await this.#checkBudget();
    // Validate the current snapshot too. Unexpected deletion/mode changes are
    // failures, never permission to recreate or overwrite an unknown file.
    if (createHash('sha256').update(await this.#read()).digest('hex') !== this.#digest) throw fail();
    const temporary = path.join(this.#directory, 'account.next');
    const handle = await open(temporary, constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | constants.O_NOFOLLOW, 0o600);
    try {
      await handle.writeFile(encoded); await handle.sync();
    } finally { await handle.close(); }
    await this.#checkDirectory();
    await rename(temporary, path.join(this.#directory, 'account.json'));
    await this.#directoryHandle.sync();
    this.#digest = createHash('sha256').update(encoded).digest('hex');
    this.#account = observed;
  }

  join() {
    if (this.#joining) return this.#joining;
    this.#closed = true; // late SDK callbacks cannot enqueue another write
    this.#joining = (async () => {
      try {
        await this.#tail;
        if (this.#lock) {
          await this.#checkDirectory();
          // A failed operation retains the lock as a recovery marker even after
          // producers quiesce. Never silently reopen a possibly uncertain write.
          if (!this.#failed) {
            await unlink(path.join(this.#directory, 'owner.lock'));
            await this.#directoryHandle.sync();
          }
        }
        return true;
      } finally {
        // Failed open has no caller to retain this object. Close every acquired
        // descriptor even if path verification or lock cleanup failed.
        const results = await Promise.allSettled([this.#lock?.close(), this.#directoryHandle?.close()]);
        this.#lock = null; this.#directoryHandle = null;
        if (results.some(result => result.status === 'rejected')) throw fail();
      }
    })().catch(() => { this.#fault(); return false; });
    return this.#joining;
  }
}
