// Generation-owned delivery lifecycle. Private Python authorizes content/routes
// and commits outcome/audit/cleanup before settlement. These services own actual
// producers, finite result slots and replay evidence, never ordinary adapter sends.
import {randomBytes} from 'node:crypto';
import {PrivateUpload} from './private_framing.mjs';
import {PrivateTombstones} from './private_admissions.mjs';
import {sha256, typedBytes} from './private_wire.mjs';

const id = () => randomBytes(16).toString('hex');
const isId = value => typeof value === 'string' && /^[0-9a-f]{32}$/.test(value);
function typed(value) {
  if (Array.isArray(value)) return ['array', value.map(typed)];
  if (value !== null && typeof value === 'object') {
    return ['object', Object.keys(value).sort().map(key => [key, typed(value[key])])];
  }
  return value;
}

export class PrivateDeliveries {
  #wire;
  #profile;
  #generation;
  #pool;
  #factory;
  #classify;
  #fault;
  #active = false;
  #fenced = false;
  #slots = new Map();
  #closing = null;

  constructor({wire, profile, generation, tombstones, createProducer, classifyText, onDrain}) {
    if (!isId(profile) || !isId(generation) || !(tombstones instanceof PrivateTombstones) ||
        [createProducer, classifyText, onDrain].some(fn => typeof fn !== 'function')) throw Error('invalid_context');
    this.#wire = wire; this.#profile = profile; this.#generation = generation;
    this.#pool = tombstones; this.#factory = createProducer; this.#classify = classifyText; this.#fault = onDrain;
  }

  get slots() { return this.#slots.size; }
  activate() { if (this.#fenced) throw Error('not_ready'); this.#active = true; }
  #validate(operation, data) {
    this.#wire.validate({v: 5, profile_id: this.#profile, generation: this.#generation,
      request_id: '0'.repeat(32), op: operation, data}, `${operation}_request`);
  }
  #drain(reason = 'transport_fault') {
    if (this.#fenced) return;
    this.#active = false; this.#fenced = true;
    for (const slot of this.#slots.values()) this.#fence(slot);
    this.#fault(reason);
  }
  #conflict() { this.#drain('invalid_context'); throw Error('conflict'); }
  #reserve(operation, kind, requestDigest) {
    const family = kind;
    const count = [...this.#slots.values()].filter(slot => slot.family === family).length;
    if (count >= (family === 'text' ? 2 : 1)) { this.#drain('capacity'); throw Error('capacity'); }
    try { this.#pool.reserve(operation); }
    catch (error) { this.#drain(error.message === 'capacity' ? 'capacity' : 'invalid_context'); throw error; }
    const slot = {operation, family, kind, requestDigest, ticket: null, producer: null,
      work: null, finishing: null, prepared: false, dispatched: false, fenced: false,
      uncertain: false, key: null, joined: false, cell: null, result: null};
    this.#slots.set(operation, slot);
    return slot;
  }
  #cell(slot, state, never = false) {
    const next = {operation_id: slot.operation, purpose: 'delivery', request_digest: slot.requestDigest,
      outcome_digest: null, settle_digest: null, ticket: slot.ticket, state,
      prior_dispatch_possible: slot.dispatched, quiesced: state !== 'fenced', never_dispatched: never};
    this.#wire.validate(next, 'delivery_tombstone'); // includes mandatory semantic predicate
    if (slot.cell) {
      // A fenced row never learns a later request, ticket or dispatch binding.
      if (slot.cell.state !== 'fenced' || ['request_digest', 'ticket', 'prior_dispatch_possible'].some(
        name => slot.cell[name] !== next[name])) throw Error('conflict');
      Object.assign(slot.cell, next);
    } else {
      this.#pool.bind(slot.operation, slot.operation, next);
      slot.cell = next;
    }
  }
  #fence(slot) {
    if (slot.fenced || slot.joined) return;
    slot.fenced = true;
    this.#cell(slot, 'fenced'); // synchronous cut before cancellation/await
    try { slot.upload?.cancel(); slot.producer?.cancel(); } catch { slot.uncertain = true; }
  }
  #finish(slot) {
    if (slot.finishing) return slot.finishing;
    slot.finishing = (async () => {
      await slot.work?.catch(() => {});
      if (slot.uncertain) return false;
      let joined = true;
      try { if (slot.producer) joined = await slot.producer.join() === true; }
      catch { joined = false; }
      if (slot.upload && !await slot.upload.join()) joined = false;
      if (!joined) return false;
      const never = !slot.dispatched;
      const state = slot.key !== null ? 'sent' : never ? 'cancelled' : 'unknown';
      const result = {operation_id: slot.operation, state, ticket: slot.ticket, sent_key: slot.key,
        proof: state === 'sent' ? 'sent' : never ? 'never_dispatched' : 'joined'};
      this.#wire.validate(result, 'delivery_result');
      if (Buffer.byteLength(JSON.stringify(result)) > 8192) return false;
      this.#cell(slot, state, never);
      slot.result = result; slot.joined = true;
      slot.producer = null; // release native arguments only after actual join
      slot.work = null; slot.key = null; slot.upload = null;
      return true;
    })().catch(() => false);
    return slot.finishing;
  }

  async request(operation, data, upload = null) {
    if (operation === 'poll_send') throw Error('not_ready');
    if (!['text_send', 'artifact_prepare'].includes(operation)) throw Error('invalid_schema');
    this.#validate(operation, data);
    if (upload !== null && (operation !== 'artifact_prepare' || !(upload instanceof PrivateUpload))) throw Error('invalid_context');
    const operationId = data.context.operation_id;
    const digest = sha256(typedBytes([3, 'delivery-request-v1', this.#profile, this.#generation,
      operationId, operation, typed(data)]));
    const prior = this.#slots.get(operationId), cell = this.#pool.get(operationId);
    if (prior || cell) {
      if ((prior?.requestDigest ?? cell?.request_digest) !== digest) this.#conflict();
      // Exact retries verify and discard their body; they cannot allocate a second spool.
      if (upload) await upload.consume(async () => {});
      return this.state({operation_id: operationId});
    }
    if (!this.#active || this.#fenced) throw Error('not_ready');
    const kind = operation === 'artifact_prepare' ? 'artifact' : this.#classify(data.context);
    if (operation === 'text_send' && !['text', 'status'].includes(kind)) throw Error('invalid_context');
    const slot = this.#reserve(operationId, kind, digest);
    slot.upload = upload;
    upload?.onCancel(() => this.#fence(slot));
    slot.contextDigest = sha256(typedBytes(typed(data.context)));
    try {
      // Factories are synchronous and inert. Retain before any producer start.
      slot.uncertain = true;
      slot.producer = this.#factory(kind, structuredClone(data));
      if (!slot.producer || ['dispatch', 'cancel', 'join'].some(name => typeof slot.producer[name] !== 'function') ||
          (kind === 'artifact' && typeof slot.producer.prepare !== 'function')) throw Error('transport_fault');
      slot.uncertain = false;
      if (kind === 'artifact') {
        slot.work = Promise.resolve().then(async () => {
          if (slot.fenced) return;
          if (await slot.producer.prepare(upload) !== true) throw Error('storage_fault');
          if (upload && !upload.complete) throw Error('storage_fault');
          if (!slot.fenced) {
            slot.expires = Math.min(Date.now() + 300000, slot.producer.expiresAt ?? Infinity);
            if (!Number.isSafeInteger(slot.expires) || Date.now() >= slot.expires) throw Error('expired');
            slot.ticket = id(); slot.prepared = true;
          }
        });
        await slot.work;
        if (slot.fenced) { await this.#finish(slot); return this.state({operation_id: operationId}); }
      } else {
        this.#dispatch(slot, data.audit_ref);
        await this.#finish(slot);
      }
      return this.state({operation_id: operationId});
    } catch {
      this.#fence(slot);
      await this.#finish(slot);
      this.#drain();
      throw Error('transport_fault');
    }
  }

  #dispatch(slot, auditRef) {
    slot.dispatched = true; // potential dispatch is recorded before SDK entry
    slot.work = Promise.resolve().then(async () => {
      if (slot.fenced) return;
      const key = await slot.producer.dispatch(auditRef);
      this.#wire.validate(key, 'key');
      slot.key = structuredClone(key);
    });
    slot.work.catch(() => { this.#fence(slot); });
  }

  async commit(data) {
    this.#validate('artifact_commit', data);
    const slot = this.#slots.get(data.context.operation_id);
    if (!slot || slot.kind !== 'artifact' || !slot.prepared || slot.ticket !== data.ticket) this.#conflict();
    if (sha256(typedBytes(typed(data.context))) !== slot.contextDigest) this.#conflict();
    // Commit is one-shot. Repeats observe state; they never dispatch again.
    if (slot.dispatched || slot.finishing || slot.fenced) return this.state({operation_id: slot.operation});
    if (!this.#active || this.#fenced) throw Error('not_ready');
    if (Date.now() >= slot.expires) {
      this.#fence(slot); await this.#finish(slot);
      return this.state({operation_id: slot.operation});
    }
    this.#dispatch(slot, data.audit_ref);
    // The authenticated commit response is the dispatch-start handshake. Send
    // completion and producer joins continue under the retained full-result
    // slot and are observed independently through delivery_state/cancel.
    this.#finish(slot);
    return this.state({operation_id: slot.operation});
  }

  state(data) {
    this.#validate('delivery_state', data);
    const cell = this.#pool.get(data.operation_id), slot = this.#slots.get(data.operation_id);
    if (cell?.purpose === 'delivery' && cell.settle_digest !== null) return {
      operation_id: data.operation_id, state: 'settled', outcome_digest: cell.outcome_digest};
    if (!slot) throw Error('not_found');
    if (slot.result) return structuredClone(slot.result);
    if (slot.dispatched) return {operation_id: slot.operation, state: 'dispatch_started',
      ticket: slot.ticket, sent_key: null, proof: 'none'};
    if (slot.prepared && !slot.fenced) return {operation_id: slot.operation, state: 'prepared',
      ticket: slot.ticket, sent_key: null, proof: 'none'};
    throw Error('unknown'); // no terminal receipt while prepare/join is pending
  }

  async cancel(data) {
    this.#validate('cancel', data);
    if (data.purpose !== 'delivery' || data.submission_id !== null || data.envelope_digest !== null) throw Error('invalid_context');
    let slot = this.#slots.get(data.operation_id);
    const cell = this.#pool.get(data.operation_id);
    if (!slot && cell) {
      if (cell.purpose !== 'delivery' || data.ticket !== null && cell.ticket !== data.ticket) this.#conflict();
      return this.state({operation_id: data.operation_id});
    }
    if (!slot) {
      if (data.ticket !== null || !this.#active) throw Error('invalid_context');
      slot = this.#reserve(data.operation_id, 'text', null);
    }
    if (data.ticket !== null && data.ticket !== slot.ticket) this.#conflict();
    this.#fence(slot);
    const joined = await this.#finish(slot);
    if (joined) return this.state({operation_id: slot.operation});
    return {operation_id: slot.operation, state: 'cancelling',
      prior_dispatch_possible: slot.dispatched, producers_joined: false};
  }

  async cancelControl(data) {
    const result = await this.cancel(data);
    if (result.state === 'settled' || result.state === 'cancelling') return result;
    const cell = this.#pool.get(data.operation_id);
    if (!cell || cell.purpose !== 'delivery' || !cell.quiesced || cell.state !== result.state) throw Error('unknown');
    // The closed cancel endpoint carries ownership evidence, not a delivery
    // result/key. Full results remain queryable until private settlement.
    return {operation_id: data.operation_id, state: cell.state,
      prior_dispatch_possible: cell.prior_dispatch_possible, producers_joined: cell.quiesced};
  }

  settle(data) {
    this.#validate('delivery_settle', data);
    const cell = this.#pool.get(data.operation_id), slot = this.#slots.get(data.operation_id);
    if (!cell || cell.purpose !== 'delivery' || !cell.quiesced || cell.state === 'fenced') throw Error('unknown');
    const digest = sha256(typedBytes([3, 'delivery-settle-v1', this.#profile, this.#generation,
      data.operation_id, data.outcome_digest, data.durable_outcome_ref, data.cleanup_ref]));
    if (cell.settle_digest !== null) {
      if (cell.settle_digest !== digest || cell.outcome_digest !== data.outcome_digest) this.#conflict();
    } else {
      if (!slot?.joined || !slot.result) throw Error('unknown');
      const next = {...cell, outcome_digest: data.outcome_digest, settle_digest: digest};
      this.#wire.validate(next, 'delivery_tombstone');
      Object.assign(cell, next); // both digests fixed before releasing full result
      this.#slots.delete(data.operation_id);
    }
    return this.state({operation_id: data.operation_id});
  }

  close() {
    if (!this.#closing) {
      this.#drain();
      this.#closing = Promise.all([...this.#slots.values()].map(slot => this.#finish(slot)))
        .then(results => results.every(result => result === true));
    }
    return this.#closing;
  }
}
