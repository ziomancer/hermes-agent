// Owned, initially suspended private control service. Native producers are
// supplied by the bridge only after the required boundary installs its routes.
import http from 'node:http';
import {timingSafeEqual} from 'node:crypto';
import {sha256} from './private_wire.mjs';
import {PrivateUpload} from './private_framing.mjs';

const LANES = Object.freeze({bulk: 2, control: 4, owner: 2});
const HEX_ID = /^[0-9a-f]{32}$/;
const DIGEST = /^[0-9a-f]{64}$/;
const safeEqual = (left, right) => {
  const a = Buffer.from(left ?? ''), b = Buffer.from(right);
  return a.length === b.length && timingSafeEqual(a, b);
};

export class PrivateController {
  #wire;
  #profile;
  #generation;
  #digest;
  #bearers;
  #services;
  #state = 'SUSPENDED';
  #reason = null;
  #servers = new Map();
  #sockets = new Set();
  #tasks = new Set();
  #opening = false;
  #closing = null;
  #activation = null;
  #ready = false;

  constructor({wire, profile, generation, contractDigest, bearers, services}) {
    if (![profile, generation].every(value => typeof value === 'string' && HEX_ID.test(value)) ||
        typeof contractDigest !== 'string' || !DIGEST.test(contractDigest) ||
        Object.keys(bearers).sort().join() !== 'bulk,control,owner' ||
        Object.values(bearers).some(value => typeof value !== 'string' || !DIGEST.test(value)) ||
        new Set(Object.values(bearers)).size !== 3) throw Error('invalid_context');
    this.#wire = wire;
    this.#profile = profile;
    this.#generation = generation;
    this.#digest = contractDigest;
    this.#bearers = Object.freeze({...bearers});
    this.#services = Object.freeze({...services});
  }

  get state() { return this.#state; }

  async open() {
    if (this.#opening || this.#state !== 'SUSPENDED') throw Error('invalid_context');
    this.#opening = true;
    const endpoints = {};
    try {
      for (const [lane, limit] of Object.entries(LANES)) {
        const owned = {server: null, occupied: 0};
        const leases = new WeakMap();
        const server = http.createServer({maxHeaderSize: 8192, insecureHTTPParser: false});
        owned.server = server;
        this.#servers.set(lane, owned);
        server.headersTimeout = 5000;
        // Per-connection prelude and upload timers below own the body budget.
        server.requestTimeout = 0;
        server.keepAliveTimeout = 1;
        server.maxHeadersCount = 33;
        server.on('connection', socket => {
          if (owned.occupied >= limit || this.#state === 'CLOSED') { socket.destroy(); return; }
          owned.occupied++;
          const lease = {closed: false, busy: false, used: false, released: false};
          // The absolute prelude deadline cannot be extended by trickling
          // headers or body bytes. It ends only after strict request validation.
          const prelude = setTimeout(() => socket.destroy(), 5000);
          lease.parsed = () => clearTimeout(prelude);
          lease.release = () => {
            if (lease.closed && !lease.busy && !lease.released) {
              lease.released = true;
              owned.occupied--;
            }
          };
          leases.set(socket, lease);
          this.#sockets.add(socket);
          socket.setTimeout(5000, () => socket.destroy());
          socket.on('error', () => {});
          socket.on('close', () => {
            clearTimeout(prelude);
            lease.closed = true;
            this.#sockets.delete(socket);
            lease.release();
          });
        });
        server.on('request', (request, response) => {
          const lease = leases.get(request.socket);
          if (!lease || lease.used || this.#state === 'CLOSED') { request.socket.destroy(); return; }
          lease.used = lease.busy = true;
          response.shouldKeepAlive = false;
          response.setHeader('Connection', 'close');
          const task = this.#request(lane, request, response, lease)
            .catch(() => { request.socket.destroy(); })
            .finally(() => { lease.busy = false; lease.release(); this.#tasks.delete(task); });
          this.#tasks.add(task);
        });
        server.on('checkContinue', request => request.socket.destroy());
        server.on('checkExpectation', request => request.socket.destroy());
        server.on('upgrade', request => request.socket.destroy());
        server.on('connect', request => request.socket.destroy());
        server.on('clientError', (_error, socket) => socket.destroy());
        await new Promise((resolve, reject) => {
          server.once('error', reject);
          server.listen({host: '127.0.0.1', port: 0, backlog: limit}, () => {
            server.removeListener('error', reject);
            server.on('error', () => { this.drain('transport_fault'); });
            resolve();
          });
        });
        endpoints[lane] = `http://127.0.0.1:${server.address().port}`;
      }
      return Object.freeze(endpoints);
    } catch {
      await this.close();
      throw Error('transport_fault');
    }
  }

  drain(reason = 'transport_fault') {
    if (this.#state === 'CLOSED') return;
    this.#state = 'DRAINING';
    this.#ready = false;
    this.#reason ??= reason;
    // Fencing is synchronous; abort/join is performed by close and the explicit
    // cancel/revoke services. No new activation can race through this cut.
    this.#services?.fence?.();
  }

  async #request(lane, request, response, lease) {
    const raw = request.rawHeaders;
    if (raw.length / 2 > 32 || Buffer.byteLength(request.url) > 256 || request.method !== 'POST') throw Error('invalid_schema');
    const seen = new Set();
    for (let index = 0; index < raw.length; index += 2) {
      const key = raw[index].toLowerCase();
      if (seen.has(key)) throw Error('invalid_schema');
      seen.add(key);
    }
    for (const key of ['transfer-encoding', 'content-encoding', 'trailer', 'upgrade', 'expect']) {
      if (seen.has(key)) throw Error('invalid_schema');
    }
    if (!safeEqual(request.headers.authorization, `Bearer ${this.#bearers[lane]}`) ||
        request.headers['x-private-profile'] !== this.#profile ||
        request.headers['x-private-generation'] !== this.#generation) throw Error('invalid_context');
    const operation = this.#wire.operations().find(name => this.#wire.endpoint(name).path === request.url);
    if (!operation) throw Error('invalid_schema');
    const endpoint = this.#wire.endpoint(operation);
    const streaming = endpoint.stream?.direction === 'request';
    if (endpoint.lane !== lane || request.headers['content-type'] !==
        (streaming ? endpoint.stream.content_type : 'application/json')) throw Error('invalid_schema');
    const lengthText = request.headers['content-length'];
    if (typeof lengthText !== 'string' || !/^(0|[1-9][0-9]*)$/.test(lengthText)) throw Error('invalid_schema');
    const length = Number(lengthText);
    if (!Number.isSafeInteger(length) || length < 1 || length > (streaming ? endpoint.stream.max_frame_bytes : endpoint.request_bytes)) throw Error('invalid_schema');
    if (streaming) return this.#upload(operation, endpoint, request, response, lease, length);
    const bytes = Buffer.alloc(length);
    let count = 0;
    for await (const piece of request) {
      if (count + piece.length > length) throw Error('invalid_schema');
      piece.copy(bytes, count);
      count += piece.length;
    }
    if (count !== length || request.rawTrailers.length) throw Error('invalid_schema');
    const parsed = this.#wire.decode(bytes, endpoint.request, endpoint.request_bytes);
    if (parsed.profile_id !== this.#profile || parsed.generation !== this.#generation || parsed.op !== operation) throw Error('invalid_context');
    lease.parsed();
    try {
      const result = await this.#dispatch(operation, parsed);
      const reply = {v: parsed.v, profile_id: this.#profile, generation: this.#generation,
        request_id: parsed.request_id, request_digest: sha256(bytes), op: operation, result};
      this.#wire.validate(reply, endpoint.response);
      const body = Buffer.from(JSON.stringify(reply));
      if (body.length > endpoint.response_bytes) throw Error('invalid_schema');
      response.writeHead(200, {'Content-Type': 'application/json', 'Content-Length': body.length});
      response.end(body);
    } catch (error) {
      const known = new Set(['invalid_schema', 'invalid_context', 'not_ready', 'capacity', 'expired',
        'conflict', 'cancelled', 'unknown', 'not_found', 'integrity', 'audit_fault', 'storage_fault', 'transport_fault']);
      const code = known.has(error?.message) ? error.message : 'transport_fault';
      const value = {v: 5, request_id: parsed.request_id, code};
      this.#wire.validate(value, 'error');
      const body = Buffer.from(JSON.stringify(value));
      response.writeHead(409, {'Content-Type': 'application/json', 'Content-Length': body.length});
      response.end(body);
    }
  }

  async #upload(operation, endpoint, request, response, lease, length) {
    if (this.#state !== 'ACTIVE' || typeof this.#services[operation] !== 'function') throw Error('not_ready');
    // The pre-header deadline ends only after authenticated headers. One body
    // idle timer and one absolute budget cover prefix, metadata and sink waits.
    lease.parsed();
    let upload = null, expired = false;
    const abort = () => { request.destroy(); };
    let idle;
    const touch = () => { clearTimeout(idle); idle = setTimeout(expire, 30000); };
    const expire = () => { expired = true; upload?.cancel(); abort(); };
    const total = setTimeout(expire, 300000);
    request.socket.setTimeout(30000, expire);
    const source = (async function* () {
      for await (const piece of request) { touch(); yield piece; }
    })();
    touch();
    try {
      upload = await PrivateUpload.open(source, {
        metadataLimit: endpoint.stream.metadata_max_bytes, frameLimit: endpoint.stream.max_frame_bytes,
        contentLength: length, abort,
        validateMetadata: parsed => {
          this.#wire.validate(parsed, endpoint.request);
          if (parsed.profile_id !== this.#profile || parsed.generation !== this.#generation ||
              parsed.op !== operation) throw Error('invalid_context');
        },
      });
      if (expired || this.#state !== 'ACTIVE') throw Error('not_ready');
      const parsed = upload.metadata;
      const result = await this.#services[operation](parsed.data, upload);
      if (expired || !upload.complete || request.rawTrailers.length) throw Error('transport_fault');
      const reply = {v: parsed.v, profile_id: this.#profile, generation: this.#generation,
        request_id: parsed.request_id, request_digest: upload.digest, op: operation, result};
      this.#wire.validate(reply, endpoint.response);
      const body = Buffer.from(JSON.stringify(reply));
      if (body.length > endpoint.response_bytes) throw Error('invalid_schema');
      response.writeHead(200, {'Content-Type': 'application/json', 'Content-Length': body.length});
      response.end(body);
    } catch {
      // A partial binary exchange closes. Cancellation of a created delivery
      // is owned by its service; no JSON error is appended to the stream.
      upload?.cancel(); abort();
      throw Error('transport_fault');
    } finally {
      clearTimeout(total); clearTimeout(idle);
      if (upload && !await upload.join()) this.drain('transport_fault');
    }
  }

  async #dispatch(operation, parsed) {
    let result;
    if (operation === 'health') {
      result = {
        runtime: this.#services.runtimeState?.() ?? 'RECOVERING',
        bridge: this.#state, reason: this.#reason, transport_ready: this.#ready, contract_digest: this.#digest,
      };
    } else if (operation === 'activate') {
      if (parsed.data.contract_digest !== this.#digest || this.#state === 'DRAINING' || this.#state === 'CLOSED') throw Error('invalid_context');
      if (this.#services.runtimeState?.() !== 'READY') throw Error('not_ready');
      if (!this.#activation) {
        if (['activate', 'fence', 'close'].some(name => typeof this.#services[name] !== 'function')) throw Error('not_ready');
        // Retain the exact activation producer on success, failure and lost HTTP
        // response. An identical repeat observes it; it never starts another socket.
        this.#activation = Promise.resolve().then(() => {
          if (this.#state !== 'SUSPENDED') throw Error('not_ready');
          return this.#services.activate();
        });
      }
      try {
        const ready = await this.#activation;
        if (ready !== true || !['SUSPENDED', 'ACTIVE'].includes(this.#state)) throw Error('not_ready');
        this.#state = 'ACTIVE';
        this.#ready = true;
        result = {state: 'ACTIVE'};
      } catch {
        this.drain();
        throw Error('transport_fault');
      }
    } else {
      if (this.#state === 'SUSPENDED' || this.#state === 'CLOSED') throw Error('not_ready');
      const service = this.#services?.[operation];
      if (typeof service !== 'function') throw Error('not_ready');
      result = await service(parsed.data);
    }
    return result;
  }

  close() {
    if (this.#closing) return this.#closing;
    this.drain();
    this.#closing = (async () => {
      const closingServers = [...this.#servers.values()].map(({server}) =>
        new Promise((resolve, reject) => server.close(error => error && error.code !== 'ERR_SERVER_NOT_RUNNING' ? reject(error) : resolve())));
      for (const socket of this.#sockets) socket.destroy();
      // The producer service signals cancellation and joins its actual workers.
      // A rejected join leaves this promise rejected and the generation fenced.
      if (this.#services?.close && await this.#services.close() !== true) throw Error('producer_live');
      await Promise.allSettled([...this.#tasks]);
      await Promise.all(closingServers);
      this.#state = 'CLOSED';
      return true;
    })();
    return this.#closing;
  }
}
