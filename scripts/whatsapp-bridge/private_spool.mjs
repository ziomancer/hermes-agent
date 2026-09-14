// Private allocation-backed destination. No path comes from HTTP metadata.
// The runtime provisions this authority over its inherited private channel.
import {constants} from 'node:fs';
import {open, lstat, realpath, rename, statfs} from 'node:fs/promises';
import {join, isAbsolute} from 'node:path';
import {createHash, createHmac, timingSafeEqual} from 'node:crypto';
import {Readable} from 'node:stream';
import {strictJSON} from './private_framing.mjs';
import {sha256, typedBytes} from './private_wire.mjs';

const fail = () => Error('storage_fault');
const id = value => typeof value === 'string' && /^[0-9a-f]{32}$/.test(value);
const hex = value => typeof value === 'string' && /^[0-9a-f]{64}$/.test(value);
const identity = s => [s.dev, s.ino, s.size, s.mtimeNs, s.ctimeNs, s.mode, s.uid, s.nlink].join(':');
function privateStat(s, directory = false) {
  if ((directory ? !s.isDirectory() : !s.isFile()) || Number(s.mode & 0o777n) !== (directory ? 0o700 : 0o600) ||
      Number(s.uid) !== process.getuid() || !directory && (s.nlink !== 1n || s.size < 0n || s.size > 16777216n)) throw fail();
}
function typed(value) {
  if (Array.isArray(value)) return ['array', value.map(typed)];
  if (value !== null && typeof value === 'object') return ['object', Object.keys(value).sort().map(key => [key, typed(value[key])])];
  return value;
}

export class PrivateSpoolProducer {
  #authority;
  #profile;
  #generation;
  #data;
  #grant;
  #file;
  #directories = [];
  #cancelled = false;
  #work = null;
  #sending = null;
  #joining = null;
  #expires = 0;
  #prepared = false;
  #dispatching = false;
  #streamComplete = false;
  #stream;
  #sender;

  constructor({authority, profile, generation, data, createSender}) {
    if (!authority || Object.keys(authority).sort().join() !== 'directory,files,key' || !hex(authority.key) ||
        ![authority.directory, authority.files].every(path => typeof path === 'string' && isAbsolute(path)) ||
        !id(profile) || !id(generation) || !id(data?.context?.operation_id) || typeof createSender !== 'function') throw fail();
    this.#authority = structuredClone(authority); this.#profile = profile;
    this.#generation = generation; this.#data = structuredClone(data);
    this.#stream = Readable.from(this.#pieces(), {objectMode: false, highWaterMark: 65536});
    try {
      this.#sender = createSender(this.#stream);
      if (!this.#sender || ['dispatch', 'cancel', 'join'].some(name => typeof this.#sender[name] !== 'function')) throw fail();
    } catch {
      this.#stream.destroy();
      throw fail();
    }
  }

  get expiresAt() { return this.#expires; }
  async #directory(path) {
    if (await realpath(path) !== path) throw fail();
    const handle = await open(path, constants.O_RDONLY | constants.O_DIRECTORY | constants.O_NOFOLLOW);
    this.#directories.push({path, handle});
    await this.#checkDirectories();
    return handle;
  }
  async #checkDirectories() {
    for (const {path, handle} of this.#directories) {
      const actual = await handle.stat({bigint: true}), named = await lstat(path, {bigint: true});
      privateStat(actual, true); privateStat(named, true);
      if (actual.dev !== named.dev || actual.ino !== named.ino || await realpath(path) !== path) throw fail();
    }
  }
  async #readGrant() {
    const path = join(this.#authority.directory, this.#data.context.operation_id + '.spool.json');
    const file = await open(path, constants.O_RDONLY | constants.O_NONBLOCK | constants.O_NOFOLLOW);
    try {
      const before = await file.stat({bigint: true}); privateStat(before);
      if (before.size > 8192n) throw fail();
      const buffer = Buffer.alloc(8193);
      let size = 0;
      while (size < buffer.length) {
        const read = await file.read(buffer, size, buffer.length - size, size);
        if (!read.bytesRead) break;
        size += read.bytesRead;
      }
      if (BigInt(size) !== before.size || identity(before) !== identity(await file.stat({bigint: true})) ||
          identity(before) !== identity(await lstat(path, {bigint: true}))) throw fail();
      const envelope = strictJSON(buffer.subarray(0, size), 8192);
      if (Object.keys(envelope).sort().join() !== 'body,mac' || typeof envelope.body !== 'string' || !hex(envelope.mac)) throw fail();
      const mac = createHmac('sha256', Buffer.from(this.#authority.key, 'hex')).update(envelope.body).digest();
      if (!timingSafeEqual(mac, Buffer.from(envelope.mac, 'hex'))) throw fail();
      return strictJSON(Buffer.from(envelope.body), 4096);
    } finally { await file.close(); }
  }
  #checkGrant(grant, directory) {
    const keys = ['v', 'profile', 'generation', 'owner_pid', 'owner_start', 'operation', 'conversation', 'epoch',
      'run', 'handle', 'file_ref', 'stage', 'final', 'device', 'inode', 'directory_device', 'directory_inode',
      'size', 'sha256', 'request_digest', 'expires', 'allocation_bytes'];
    const data = this.#data;
    if (Object.keys(grant).sort().join() !== keys.sort().join() || grant.v !== 1 ||
        grant.profile !== this.#profile || grant.generation !== this.#generation || grant.owner_pid !== process.pid ||
        typeof grant.owner_start !== 'string' || !grant.owner_start.startsWith('os1:') ||
        grant.operation !== data.context.operation_id || grant.conversation !== data.context.conversation_ref ||
        grant.epoch !== data.context.epoch || grant.handle !== data.handle || !id(grant.run) || !id(grant.file_ref) ||
        !/^[0-9a-f]{32}\.stage$/.test(grant.stage) || !/^[0-9a-f]{32}\.spool$/.test(grant.final) ||
        grant.size !== data.size || grant.sha256 !== data.sha256 || grant.allocation_bytes !== 16777216 ||
        !['device', 'inode', 'directory_device', 'directory_inode', 'expires', 'size'].every(
          name => Number.isSafeInteger(grant[name]) && grant[name] >= 0) || grant.size > 16777216 ||
        BigInt(grant.directory_device) !== directory.dev || BigInt(grant.directory_inode) !== directory.ino ||
        grant.request_digest !== sha256(typedBytes([3, 'delivery-request-v1', this.#profile, this.#generation,
          data.context.operation_id, 'artifact_prepare', typed(data)])) || Date.now() >= grant.expires) throw fail();
  }
  async #margin() {
    const disk = await statfs(this.#authority.files, {bigint: true});
    if (disk.bavail * disk.bsize < 67108864n + 65536n) throw fail();
  }
  async #checkFile(name, exact = false) {
    const info = await this.#file.stat({bigint: true}); privateStat(info);
    if (info.dev !== BigInt(this.#grant.device) || info.ino !== BigInt(this.#grant.inode) ||
        info.size > BigInt(this.#grant.size) || exact && info.size !== BigInt(this.#grant.size) ||
        identity(info) !== identity(await lstat(join(this.#authority.files, name), {bigint: true}))) throw fail();
    await this.#checkDirectories();
  }
  prepare(upload) {
    if (this.#work || this.#cancelled) return Promise.reject(fail());
    this.#work = this.#prepare(upload);
    return this.#work;
  }
  async #prepare(upload) {
    await this.#directory(this.#authority.directory);
    const directory = await this.#directory(this.#authority.files);
    const grant = await this.#readGrant();
    this.#checkGrant(grant, await directory.stat({bigint: true}));
    this.#grant = grant;
    this.#file = await open(join(this.#authority.files, grant.stage), constants.O_RDWR | constants.O_NONBLOCK | constants.O_NOFOLLOW);
    await this.#checkFile(grant.stage);
    if ((await this.#file.stat()).size !== 0 || this.#cancelled) throw fail();
    let size = 0;
    const digest = createHash('sha256');
    await upload.consume(async piece => {
      if (this.#cancelled || Date.now() >= grant.expires || piece.length > 65536 || size + piece.length > grant.size) throw fail();
      await this.#margin();
      let offset = 0;
      while (offset < piece.length) {
        const {bytesWritten} = await this.#file.write(piece, offset, piece.length - offset, size + offset);
        if (bytesWritten <= 0) throw fail();
        offset += bytesWritten;
      }
      size += piece.length; digest.update(piece);
    });
    if (this.#cancelled || size !== grant.size || digest.digest('hex') !== grant.sha256) throw fail();
    await this.#file.sync();
    await this.#checkFile(grant.stage, true);
    // Hash the same open destination descriptor, independently of received bytes.
    const stored = createHash('sha256'), buffer = Buffer.alloc(65536);
    const before = await this.#file.stat({bigint: true});
    for (let offset = 0; offset < size;) {
      const {bytesRead} = await this.#file.read(buffer, 0, Math.min(buffer.length, size - offset), offset);
      if (!bytesRead || this.#cancelled) throw fail();
      stored.update(buffer.subarray(0, bytesRead)); offset += bytesRead;
    }
    if (stored.digest('hex') !== grant.sha256 || identity(before) !== identity(await this.#file.stat({bigint: true}))) throw fail();
    try { await lstat(join(this.#authority.files, grant.final)); throw fail(); }
    catch (error) { if (error.code !== 'ENOENT') throw error; }
    if (JSON.stringify(grant) !== JSON.stringify(await this.#readGrant()) || this.#cancelled || Date.now() >= grant.expires) throw fail();
    await directory.sync();
    await rename(join(this.#authority.files, grant.stage), join(this.#authority.files, grant.final));
    await directory.sync();
    await this.#checkFile(grant.final, true);
    if (this.#cancelled || Date.now() >= grant.expires) throw fail();
    this.#expires = Math.min(grant.expires, Date.now() + 300000);
    this.#prepared = true;
    return true;
  }

  async *#pieces() {
    if (!this.#dispatching || !this.#prepared || this.#cancelled || !this.#file || !this.#grant) throw fail();
    const digest = createHash('sha256');
    let offset = 0;
    while (offset < this.#grant.size) {
      if (this.#cancelled || Date.now() >= this.#expires) throw fail();
      const buffer = Buffer.alloc(Math.min(65536, this.#grant.size - offset));
      const {bytesRead} = await this.#file.read(buffer, 0, buffer.length, offset);
      if (bytesRead <= 0) throw fail();
      const piece = buffer.subarray(0, bytesRead);
      offset += bytesRead; digest.update(piece);
      yield piece;
    }
    if (offset !== this.#grant.size || digest.digest('hex') !== this.#grant.sha256) throw fail();
    await this.#checkFile(this.#grant.final, true);
    this.#streamComplete = true;
  }

  dispatch() {
    if (this.#sending || this.#cancelled || !this.#prepared || Date.now() >= this.#expires) return Promise.reject(fail());
    this.#dispatching = true;
    this.#sending = (async () => {
      const key = await this.#sender.dispatch();
      if (!this.#streamComplete) throw fail();
      return key;
    })();
    this.#sending.catch(() => {});
    return this.#sending;
  }
  cancel() {
    this.#cancelled = true;
    this.#stream.destroy();
    this.#sender.cancel();
  }
  join() {
    this.#cancelled = true;
    this.#stream.destroy();
    if (!this.#joining) this.#joining = (async () => {
      await this.#work?.catch(() => {});
      await this.#sending?.catch(() => {});
      let closed = true;
      try { if (await this.#sender.join() !== true) closed = false; } catch { closed = false; }
      try { await this.#file?.close(); } catch { closed = false; }
      for (const {handle} of this.#directories) {
        try { await handle.close(); } catch { closed = false; }
      }
      return closed;
    })();
    return this.#joining;
  }
}
