// Generic closed-schema validation for the privately bootstrapped protocol.
// Schema bytes are supplied by the owning boundary; this module has no client
// package import, data path, environment lookup or network side effect.
import {createHash} from 'node:crypto';
import {strictJSON} from './private_framing.mjs';

export const sha256 = bytes => createHash('sha256').update(bytes).digest('hex');
const fail = () => { throw Error('invalid_schema'); };

export function typedBytes(value, depth = 0) {
  if (depth > 20) fail();
  if (value === null) return Buffer.from('n');
  if (typeof value === 'boolean') return Buffer.from(value ? 't' : 'f');
  if (typeof value === 'number') {
    if (!Number.isSafeInteger(value) || value < 0) fail();
    return Buffer.from(`i${value};`);
  }
  if (typeof value === 'string') {
    for (const c of value) {
      const point = c.codePointAt(0);
      if (point >= 0xd800 && point <= 0xdfff) fail();
    }
    const bytes = Buffer.from(value);
    return Buffer.concat([Buffer.from(`s${bytes.length}:`), bytes]);
  }
  if (Array.isArray(value)) {
    return Buffer.concat([
      Buffer.from(`a${value.length}:[`),
      ...value.map(item => typedBytes(item, depth + 1)), Buffer.from(']'),
    ]);
  }
  fail();
}

function deliveryState(value) {
  if ([value.prior_dispatch_possible, value.quiesced, value.never_dispatched].some(v => typeof v !== 'boolean')) fail();
  if (!['fenced', 'cancelled', 'unknown', 'sent'].includes(value.state)) fail();
  if ((value.outcome_digest === null) !== (value.settle_digest === null)) fail();
  if (value.request_digest === null && (value.ticket !== null || value.prior_dispatch_possible || ['unknown', 'sent'].includes(value.state))) fail();
  if (value.state === 'fenced') {
    if (value.quiesced || value.never_dispatched || value.outcome_digest !== null) fail();
  } else {
    if (!value.quiesced || value.never_dispatched !== (value.state === 'cancelled')) fail();
    if (['unknown', 'sent'].includes(value.state) && !value.prior_dispatch_possible) fail();
  }
}

export class PrivateWire {
  #schema;
  constructor(bytes, expectedDigest) {
    if (!Buffer.isBuffer(bytes) || sha256(bytes) !== expectedDigest) fail();
    this.#schema = strictJSON(bytes, 1048576);
    if (!this.#schema.$defs || !this.#schema['x-endpoints']) fail();
    this.digest = expectedDigest;
  }

  endpoint(operation) {
    const endpoint = this.#schema['x-endpoints'][operation];
    if (!endpoint) fail();
    // A caller cannot mutate the captured schema/policy through a returned view.
    return structuredClone(endpoint);
  }

  operations() { return Object.keys(this.#schema['x-endpoints']); }

  decode(bytes, definition, maxBytes = 1048576) {
    const value = strictJSON(bytes, maxBytes);
    this.validate(value, definition);
    return value;
  }

  validate(value, definition) {
    const schema = this.#schema.$defs[definition];
    if (!schema) fail();
    this.#check(value, schema, 0);
    return value;
  }

  #check(value, schema, depth) {
    if (depth > 20) fail();
    if (schema.$ref) {
      const target = this.#schema.$defs[schema.$ref.split('/').at(-1)];
      if (!target) fail();
      return this.#check(value, target, depth);
    }
    for (const union of ['oneOf', 'anyOf']) if (schema[union]) {
      let matches = 0;
      for (const member of schema[union]) {
        try { this.#check(value, member, depth); matches++; } catch { /* closed union */ }
      }
      if (union === 'oneOf' ? matches !== 1 : matches === 0) fail();
    }
    if ('const' in schema && value !== schema.const) fail();
    if (schema.enum && !schema.enum.includes(value)) fail();
    if (schema.type === 'null' && value !== null) fail();
    if (schema.type === 'boolean' && typeof value !== 'boolean') fail();
    if (['integer', 'number'].includes(schema.type)) {
      if (typeof value !== 'number' || !Number.isFinite(value)) fail();
      if (schema.type === 'integer' && !Number.isSafeInteger(value)) fail();
      if (value < schema.minimum || value > schema.maximum) fail();
    }
    if (schema.type === 'string') {
      if (typeof value !== 'string') fail();
      const length = [...value].length;
      if (length < (schema.minLength ?? 0) || length > (schema.maxLength ?? Infinity)) fail();
      if (schema.pattern && new RegExp(schema.pattern).exec(value)?.[0] !== value) fail();
      for (const c of value) {
        const point = c.codePointAt(0);
        if (point >= 0xd800 && point <= 0xdfff) fail();
      }
      if (Buffer.byteLength(value) > (schema['x-maxUtf8Bytes'] ?? Infinity)) fail();
      if (schema['x-uint64'] && BigInt(value) > 18446744073709551615n) fail();
      if ('x-base64DecodedBytes' in schema || 'x-base64MaxDecodedBytes' in schema) {
        const bytes = Buffer.from(value, 'base64');
        if (bytes.toString('base64') !== value) fail();
        if (bytes.length > (schema['x-base64MaxDecodedBytes'] ?? Infinity)) fail();
        if ('x-base64DecodedBytes' in schema && bytes.length !== schema['x-base64DecodedBytes']) fail();
      }
    }
    if (schema.type === 'array') {
      if (!Array.isArray(value) || value.length < (schema.minItems ?? 0) || value.length > (schema.maxItems ?? Infinity)) fail();
      for (const child of value) this.#check(child, schema.items, depth + 1);
    }
    if (schema.type === 'object') {
      if (value === null || typeof value !== 'object' || Array.isArray(value)) fail();
      const prototype = Object.getPrototypeOf(value);
      if (prototype !== Object.prototype && prototype !== null) fail();
      if ((schema.required ?? []).some(key => !Object.hasOwn(value, key))) fail();
      for (const [key, child] of Object.entries(value)) {
        if (Object.hasOwn(schema.properties ?? {}, key)) this.#check(child, schema.properties[key], depth + 1);
        else if (schema.additionalProperties === false) fail();
      }
    }
    if (Buffer.byteLength(JSON.stringify(value)) > (schema['x-maxEncodedBytes'] ?? Infinity)) fail();
    if (schema['x-semantic-validator']) deliveryState(value);
  }
}
