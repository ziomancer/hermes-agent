// Synchronous native ingress for an exclusively owned private socket. Nothing
// here logs, caches native objects, decrypts votes, downloads, or grants routing.
import {randomBytes} from 'node:crypto';

const id = () => randomBytes(16).toString('hex');
const fail = (reason = 'invalid_content') => { throw Error(reason); };
const object = value => value !== null && typeof value === 'object' && !Array.isArray(value);
const present = value => value !== null && value !== undefined;
const wrappers = ['ephemeralMessage', 'viewOnceMessage', 'viewOnceMessageV2',
  'viewOnceMessageV2Extension', 'documentWithCaptionMessage', 'associatedChildMessage'];
const kinds = {conversation: 'text', extendedTextMessage: 'text', imageMessage: 'image',
  videoMessage: 'video', audioMessage: 'audio', documentMessage: 'document', stickerMessage: 'sticker',
  locationMessage: 'location', liveLocationMessage: 'location', contactMessage: 'contact',
  contactsArrayMessage: 'contacts', reactionMessage: 'reaction', pollCreationMessage: 'poll_creation',
  pollCreationMessageV2: 'poll_creation', pollCreationMessageV3: 'poll_creation',
  pollUpdateMessage: 'poll_vote', albumMessage: 'album'};

function string(value, limit, fallback) {
  if (!present(value) && fallback !== undefined) return fallback;
  if (typeof value !== 'string') fail();
  if (value.length > limit || Buffer.byteLength(value, 'utf8') > limit) fail('content_too_large');
  // Do not let JSON replace a malformed native UTF-16 string during encoding.
  for (let i = 0; i < value.length; i++) {
    const n = value.charCodeAt(i);
    if (n >= 0xd800 && n <= 0xdbff) {
      const next = value.charCodeAt(++i);
      if (!(next >= 0xdc00 && next <= 0xdfff)) fail();
    } else if (n >= 0xdc00 && n <= 0xdfff) fail();
  }
  return value;
}

function boolean(value) {
  if (!present(value)) return false; // protobuf boolean default
  if (typeof value !== 'boolean') fail();
  return value;
}

function integer(value, max, fallback) {
  if (!present(value) && fallback !== undefined) return fallback;
  if (!Number.isSafeInteger(value) || value < 0 || value > max) fail();
  return value;
}

function uint64(value, multiplier = 1n) {
  let result;
  if (typeof value === 'number' && Number.isSafeInteger(value) && value >= 0) result = BigInt(value);
  else if (typeof value === 'bigint') result = value;
  else if (typeof value === 'string' && /^(0|[1-9][0-9]{0,19})$/.test(value)) result = BigInt(value);
  else if (object(value) && Number.isInteger(value.low) && Number.isInteger(value.high) &&
      value.low >= -2147483648 && value.low <= 2147483647 && value.high >= -2147483648 &&
      value.high <= 2147483647 && typeof value.unsigned === 'boolean') {
    // Read protobuf Long bits; never call an arbitrary object's toString/valueOf.
    if (!value.unsigned && value.high < 0) fail();
    result = (BigInt(value.high >>> 0) << 32n) | BigInt(value.low >>> 0);
  } else fail();
  result *= multiplier;
  if (result < 0n || result > 18446744073709551615n) fail();
  return result.toString();
}

function array(value, limit, project) {
  if (!Array.isArray(value)) fail();
  if (value.length > limit) fail('content_too_large');
  const result = [];
  for (let i = 0; i < value.length; i++) result.push(project(value[i]));
  return result;
}

function key(value) {
  if (!object(value)) fail();
  const result = {id: string(value.id, 256), remote_jid: string(value.remoteJid, 256),
    participant: present(value.participant) ? string(value.participant, 256) : null,
    from_me: boolean(value.fromMe)};
  if (!result.id || !result.remote_jid || result.participant === '') fail();
  if (result.remote_jid.endsWith('@g.us') && !result.from_me && result.participant === null) fail();
  return result;
}

function userJid(value) {
  // Keep the original crypto alias alongside this device/agent-free evidence.
  // Do not collapse PN and LID users, or infer a relation from their user part.
  const match = /^([^:@_]+)(?:_[0-9]+)?(?::[0-9]+)?@(s\.whatsapp\.net|c\.us|lid|hosted|hosted\.lid)\s*$/.exec(value);
  const server = match?.[2] === 'hosted.lid' ? 'lid' :
    ['c.us', 'hosted'].includes(match?.[2]) ? 's.whatsapp.net' : match?.[2];
  return match ? `${match[1]}@${server}` : value;
}

function aliases(values) {
  const result = [];
  for (const value of values) {
    if (!present(value)) continue;
    const alias = string(value, 256);
    if (!alias) fail();
    if (!result.includes(alias)) result.push(alias);
  }
  if (!result.length || result.length > 4) fail();
  return result;
}

function content(raw) {
  let value = raw, association = null;
  for (let depth = 0; depth <= 5; depth++) {
    if (!object(value)) fail();
    const candidate = value.messageContextInfo?.messageAssociation;
    if (present(candidate)) {
      if (association !== null || !object(candidate) || candidate.associationType !== 1) fail();
      association = {parent_key: key(candidate.parentMessageKey),
        member_index: present(candidate.messageIndex) ? integer(candidate.messageIndex, 11) : null};
    }
    let wrapper = null, field = null;
    for (const name of wrappers) if (present(value[name])) {
      if (wrapper !== null) fail();
      wrapper = name;
    }
    for (const name of Object.keys(kinds)) if (present(value[name])) {
      if (field !== null) fail();
      field = name;
    }
    if (wrapper !== null) {
      if (field !== null || depth === 5) fail();
      value = value[wrapper]?.message;
      continue;
    }
    if (field === null) fail('unsupported_content');
    const payload = value[field];
    if (field !== 'conversation' && !object(payload)) fail();
    return {field, payload, kind: kinds[field], association};
  }
  fail();
}

function textOf(item) {
  if (item.field === 'conversation') return string(item.payload, 32768);
  if (item.field === 'extendedTextMessage') return string(item.payload.text, 32768, '');
  return string(item.payload.caption, 32768, '');
}

function quote(context, envelope) {
  if (!present(context.quotedMessage) && !present(context.stanzaId)) return null;
  let quotedKey;
  try {
    const participant = present(context.participant) ? string(context.participant, 256) : null;
    quotedKey = key({id: context.stanzaId, remoteJid: context.remoteJid ?? envelope.key.remote_jid,
      participant, fromMe: participant !== null && envelope.account_aliases.some(alias => userJid(alias) === userJid(participant))});
    if (quotedKey.remote_jid !== envelope.key.remote_jid) return null;
  } catch { return null; }
  try {
    const quoted = content(context.quotedMessage);
    return {key: quotedKey, text: textOf(quoted), native_kind: quoted.kind};
  } catch {
    return {key: quotedKey, text: '', native_kind: 'unknown'};
  }
}

function native(item) {
  const p = item.payload, kind = item.kind;
  if (kind === 'text') return {kind};
  if (['image', 'video', 'audio', 'document', 'sticker'].includes(kind)) return {kind,
    mime: string(p.mimetype, 128, ''), file_name: string(p.fileName, 1024, ''),
    voice_note: boolean(p.ptt), animated: boolean(p.isAnimated), gif_playback: boolean(p.gifPlayback)};
  if (kind === 'location') return {kind, latitude: p.degreesLatitude, longitude: p.degreesLongitude,
    label: string(p.name, 1024, ''), address: string(p.address, 4096, ''), live: item.field === 'liveLocationMessage'};
  if (kind === 'contact') return {kind, display_name: string(p.displayName, 256, ''), vcard: string(p.vcard, 16384)};
  if (kind === 'contacts') return {kind, contacts: array(p.contacts, 12,
    value => ({display_name: string(value?.displayName, 256, ''), vcard: string(value?.vcard, 1024)}))};
  if (kind === 'reaction') return {kind, text: string(p.text, 128, ''), target: key(p.key)};
  if (kind === 'poll_creation') return {kind, question: string(p.name, 4096, ''),
    options: array(p.options, 12, value => string(value?.optionName, 256)),
    selectable_count: integer(p.selectableOptionsCount, 12, 0),
    variant: item.field === 'pollCreationMessage' ? 'v1' : item.field === 'pollCreationMessageV2' ? 'v2' : 'v3'};
  if (kind === 'poll_vote') return {kind: 'invalid', reason: 'unsupported_content'};
  if (kind === 'album') return {kind, expected_images: integer(p.expectedImageCount, 12, 0),
    expected_videos: integer(p.expectedVideoCount, 12, 0)};
  fail('unsupported_content');
}

export class PrivateProjection {
  #wire; #profile; #generation; #admissions; #account;

  constructor({wire, profile, generation, admissions, account}) {
    wire.validate(profile, 'id'); wire.validate(generation, 'id');
    if (typeof account !== 'function') throw Error('invalid_context');
    this.#wire = wire; this.#profile = profile; this.#generation = generation;
    this.#admissions = admissions; this.#account = account;
  }

  #capacity() {
    if (this.#admissions.state !== 'ACTIVE') return false;
    if (this.#admissions.slots >= 32) { this.#admissions.drain('capacity'); return false; }
    return true;
  }

  #identity(rawKey, timestamp) {
    const k = key(rawKey), account = this.#account();
    if (!object(account)) fail();
    const rawAccounts = aliases([account.id, account.lid]);
    const accountAliases = aliases([...rawAccounts, ...rawAccounts.map(userJid)]);
    const sender = k.from_me ? accountAliases : aliases(k.participant !== null
      ? [rawKey.participant, rawKey.participantAlt] : [rawKey.remoteJid, rawKey.remoteJidAlt]);
    const envelope = {schema_version: 5, profile_id: this.#profile, generation: this.#generation,
      submission_id: id(), transport: 'whatsapp', key: k, timestamp_ms: timestamp,
      sender_aliases: sender, account_aliases: accountAliases, from_owner: k.from_me,
      body: '', quote: null, mentions: [], native: {kind: 'invalid', reason: 'invalid_content'}, media: [], album: null};
    this.#wire.validate(envelope, 'envelope');
    return envelope;
  }

  #retain(envelope, project) {
    let descriptors = [];
    try {
      descriptors = project();
      for (const value of descriptors) this.#wire.validate(value, 'descriptor');
      this.#wire.validate(envelope, 'envelope');
    } catch (error) {
      const reason = ['content_too_large', 'unsupported_content'].includes(error?.message) ? error.message : 'invalid_content';
      // Keep only already-validated stable identity, never the invalid content.
      Object.assign(envelope, {body: '', quote: null, mentions: [], native: {kind: 'invalid', reason}, media: [], album: null});
      descriptors = [];
    }
    return this.#admissions.enqueue(envelope, descriptors);
  }

  upsert(event) {
    if (this.#admissions.state !== 'ACTIVE') return;
    try {
      if (!object(event) || !Array.isArray(event.messages)) fail();
      if (!['notify', 'append'].includes(event.type)) return;
      for (let i = 0; i < event.messages.length; i++) {
        const message = event.messages[i];
        // R2: self-chat protocol traffic is filtered using keys only, before
        // capacity checks, identity allocation, content access or tombstones.
        if (message?.key?.fromMe === true && typeof message.key.remoteJid === 'string') {
          const account = this.#account();
          if ([account?.id, account?.lid].some(alias => typeof alias === 'string' &&
              userJid(message.key.remoteJid) === userJid(alias))) continue;
        }
        if (!this.#capacity()) return;
        const envelope = this.#identity(message?.key, uint64(message?.messageTimestamp, 1000n));
        if (!this.#retain(envelope, () => {
          const item = content(message?.message);
          if (item.kind === 'poll_vote') {
            envelope.native = {kind: 'invalid', reason: 'unsupported_content'};
            return [];
          }
          envelope.body = textOf(item);
          const context = item.payload?.contextInfo ?? {};
          if (!object(context)) fail();
          envelope.quote = quote(context, envelope);
          envelope.mentions = array(context.mentionedJid ?? [], 32, value => string(value, 256));
          envelope.native = native(item); envelope.album = item.association;
          return [];
        })) return;
      }
    } catch { this.#admissions.drain('invalid_context'); }
  }

}
