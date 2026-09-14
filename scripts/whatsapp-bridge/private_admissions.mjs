// Finite offered/held admission ownership. The controller authenticates every
// method call; durable claims/audit/publication remain the private owner's job.
import {randomBytes} from 'node:crypto';
import {sha256, typedBytes} from './private_wire.mjs';
import {strictJSON} from './private_framing.mjs';

const id = () => randomBytes(16).toString('hex');
const isId = value => typeof value === 'string' && /^[0-9a-f]{32}$/.test(value);
const isDigest = value => typeof value === 'string' && /^[0-9a-f]{64}$/.test(value);

export class PrivateTombstones {
  #cells = new Map();
  get size() { return this.#cells.size; }
  reserve(key) {
    if (!isId(key) && !(typeof key === 'string' && key.startsWith('offer:') && isId(key.slice(6)))) throw Error('invalid_schema');
    if (this.#cells.has(key)) throw Error('conflict');
    if (this.#cells.size >= 8192) throw Error('capacity');
    this.#cells.set(key, null);
  }
  bind(key, operation, value) {
    if (!isId(operation) || !this.#cells.has(key) || this.#cells.get(key) !== null || (key !== operation && this.#cells.has(operation))) throw Error('conflict');
    this.#cells.delete(key);
    this.#cells.set(operation, value);
  }
  get(operation) { return this.#cells.get(operation); }
  hasSubmission(submission) {
    for (const [key, value] of this.#cells) {
      if (key === `offer:${submission}` || value?.submission_id === submission) return true;
    }
    return false;
  }
}

export class PrivateAdmissions {
  #wire;
  #profile;
  #generation;
  #pool;
  #mode = 'SUSPENDED';
  #queue = [];
  #offer = null;
  #held = new Map();
  #bytes = 0;
  #descriptorBytes = 0;
  #fatal;

  constructor({wire, profile, generation, tombstones, onDrain}) {
    if (!isId(profile) || !isId(generation) || !(tombstones instanceof PrivateTombstones) || typeof onDrain !== 'function') throw Error('invalid_context');
    this.#wire = wire; this.#profile = profile; this.#generation = generation;
    this.#pool = tombstones; this.#fatal = onDrain;
  }

  get state() { return this.#mode; }
  get slots() { return this.#queue.length + Number(this.#offer !== null) + this.#held.size; }
  get bytes() { return this.#bytes; }

  activate() {
    if (!['SUSPENDED', 'ACTIVE'].includes(this.#mode)) throw Error('not_ready');
    this.#mode = 'ACTIVE';
  }

  drain(reason = 'transport_fault') {
    if (this.#mode === 'DRAINING') return;
    this.#mode = 'DRAINING';
    for (const slot of this.#queue) {
      this.#bytes -= slot.raw.length;
      this.#descriptorBytes -= slot.descriptorBytes;
    }
    this.#queue = [];
    this.#fatal(reason);
  }

  #conflict() { this.drain('invalid_context'); throw Error('conflict'); }

  enqueue(envelope, descriptors = []) {
    if (this.#mode !== 'ACTIVE') return false;
    if (this.slots >= 32) { this.drain('capacity'); return false; }
    try {
      this.#wire.validate(envelope, 'envelope');
      if (envelope.profile_id !== this.#profile || envelope.generation !== this.#generation || !Array.isArray(descriptors) || descriptors.length !== envelope.media.length) throw Error('invalid_context');
      const capabilities = envelope.media.map(item => item.capability);
      if (new Set(capabilities).size !== capabilities.length) throw Error('invalid_context');
      let descriptorBytes = 0;
      const retained = descriptors.map((descriptor, ordinal) => {
        this.#wire.validate(descriptor, 'descriptor');
        const media = envelope.media[ordinal];
        if (descriptor.generation !== this.#generation || descriptor.submission_id !== envelope.submission_id ||
            descriptor.ordinal !== ordinal || descriptor.capability !== media.capability || descriptor.kind !== media.kind ||
            descriptor.declared_plaintext_bytes !== media.declared_bytes || (descriptor.url === null && descriptor.direct_path === null)) throw Error('invalid_context');
        const raw = Buffer.from(JSON.stringify(descriptor));
        descriptorBytes += raw.length;
        return raw;
      });
      const raw = Buffer.from(JSON.stringify(envelope));
      if (this.#pool.hasSubmission(envelope.submission_id) || this.#queue.some(slot => slot.submission === envelope.submission_id)) this.#conflict();
      if (this.slots >= 32 || this.#bytes + raw.length > 33554432 || this.#descriptorBytes + descriptorBytes > 6291456) {
        this.drain('capacity'); return false;
      }
      this.#queue.push({raw, digest: sha256(raw), submission: envelope.submission_id, capabilities,
        descriptors: retained, descriptorBytes, producers: new Map(), cancelled: false, quiesced: false});
      this.#bytes += raw.length;
      this.#descriptorBytes += descriptorBytes;
      return true;
    } catch (error) {
      const code = ['capacity', 'conflict', 'invalid_context'].includes(error?.message) ? error.message : 'invalid_schema';
      this.drain(code === 'capacity' ? 'capacity' : 'invalid_context');
      throw Error(code);
    }
  }

  next() {
    if (this.#offer) return strictJSON(this.#offer.raw, 1048576);
    if (this.#mode !== 'ACTIVE' || !this.#queue.length) return null;
    const slot = this.#queue[0];
    try { this.#pool.reserve(`offer:${slot.submission}`); }
    catch (error) { this.drain('capacity'); throw error; }
    this.#offer = this.#queue.shift();
    return strictJSON(this.#offer.raw, 1048576);
  }

  #claimDigest(data) {
    if (!isId(data.operation_id) || !isId(data.submission_id) || !isDigest(data.envelope_digest) || !isId(data.claim_audit_ref)) throw Error('invalid_schema');
    return sha256(typedBytes(['claim-transfer-v1', this.#profile, this.#generation,
      data.operation_id, data.submission_id, data.envelope_digest, data.claim_audit_ref]));
  }

  #capsDigest(operation, capabilities) {
    if (!Array.isArray(capabilities) || capabilities.length > 12 || capabilities.some(cap => !isId(cap)) || new Set(capabilities).size !== capabilities.length) throw Error('invalid_schema');
    return sha256(typedBytes(['capability-set-v1', this.#profile, this.#generation, operation, [...capabilities].sort()]));
  }

  #bind(data, claimDigest) {
    if (!isId(data.operation_id) || !isId(data.submission_id) || !isDigest(data.envelope_digest)) throw Error('invalid_schema');
    const slot = this.#offer;
    if (!slot || slot.submission !== data.submission_id || slot.digest !== data.envelope_digest) this.#conflict();
    // 'held' is a reserved cell owned by a full slot, not a published tombstone.
    // Only the closed cancelled/settled shape survives full-slot compaction.
    const cell = {operation_id: data.operation_id, submission_id: data.submission_id,
      envelope_digest: data.envelope_digest, outcome_digest: null, state: 'held', claim_digest: claimDigest,
      revocation_ref: null, caps_digest: this.#capsDigest(data.operation_id, slot.capabilities)};
    try { this.#pool.bind(`offer:${slot.submission}`, data.operation_id, cell); }
    catch { this.#conflict(); }
    this.#held.set(data.operation_id, slot);
    this.#offer = null;
    return cell;
  }

  transfer(data) {
    let cell = this.#pool.get(data.operation_id);
    const claimDigest = this.#claimDigest(data);
    if (cell) {
      if (cell.submission_id !== data.submission_id || cell.envelope_digest !== data.envelope_digest ||
          (cell.claim_digest !== null && cell.claim_digest !== claimDigest)) this.#conflict();
    } else cell = this.#bind(data, claimDigest);
    return this.transferState({operation_id: data.operation_id});
  }

  transferState({operation_id: operation}) {
    const cell = this.#pool.get(operation);
    if (!cell || !cell.submission_id) throw Error('not_found');
    return {operation_id: operation, state: cell.state, envelope_digest: cell.envelope_digest};
  }

  async #fence(operation) {
    const cell = this.#pool.get(operation), slot = this.#held.get(operation);
    if (!cell || !cell.submission_id) throw Error('not_found');
    if (cell.state === 'held') cell.state = 'cancelled';
    cell.revocation_ref ??= id();
    if (slot) {
      slot.cancelled = true;
      // The media/poll producer services install owned operations here before
      // starting external work. No cancellation flag substitutes for their join.
      for (const producer of slot.producers.values()) producer.cancel();
      const joined = await Promise.all([...slot.producers.values()].map(producer => producer.join()));
      if (joined.some(value => value !== true)) return {operation_id: operation, revocation_ref: cell.revocation_ref, producers_joined: false};
      slot.quiesced = true;
    } else if (cell.state !== 'settled') throw Error('unknown');
    return {operation_id: operation, revocation_ref: cell.revocation_ref, producers_joined: true};
  }

  async cancel(data) {
    if (data.purpose !== 'admission' || data.ticket !== null || !isId(data.operation_id) ||
        !isId(data.submission_id) || !isDigest(data.envelope_digest)) throw Error('invalid_context');
    let cell = this.#pool.get(data.operation_id);
    if (cell) {
      if (cell.submission_id !== data.submission_id || cell.envelope_digest !== data.envelope_digest) this.#conflict();
    } else cell = this.#bind(data, null);
    const proof = await this.#fence(data.operation_id);
    return {operation_id: data.operation_id, state: proof.producers_joined ? 'cancelled' : 'cancelling',
      prior_dispatch_possible: false, producers_joined: proof.producers_joined};
  }

  async revoke(data) {
    const cell = this.#pool.get(data.operation_id);
    if (!cell || !cell.submission_id) throw Error('not_found');
    if (cell.caps_digest !== this.#capsDigest(data.operation_id, data.capabilities)) this.#conflict();
    return this.#fence(data.operation_id);
  }

  settle(data) {
    if (!isId(data.operation_id) || !isId(data.revocation_ref) || !isDigest(data.receipt_digest)) throw Error('invalid_schema');
    const cell = this.#pool.get(data.operation_id), slot = this.#held.get(data.operation_id);
    if (!cell || !cell.submission_id || cell.revocation_ref !== data.revocation_ref) this.#conflict();
    if (cell.state === 'settled') {
      if (cell.outcome_digest !== data.receipt_digest) this.#conflict();
    } else {
      if (cell.state !== 'cancelled' || !slot?.quiesced) throw Error('unknown');
      const settled = {...cell, state: 'settled', outcome_digest: data.receipt_digest};
      this.#wire.validate(settled, 'admission_tombstone');
      Object.assign(cell, settled);
      this.#bytes -= slot.raw.length;
      this.#descriptorBytes -= slot.descriptorBytes;
      this.#held.delete(data.operation_id);
    }
    return {operation_id: data.operation_id, receipt_digest: cell.outcome_digest, state: 'settled'};
  }

  async close() {
    this.drain();
    const results = await Promise.all([...this.#held.keys()].map(operation => this.#fence(operation)));
    return results.every(result => result.producers_joined);
  }
}
