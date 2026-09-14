// The concrete SDK owner is inert until authenticated native activation. There
// is no ordinary bridge import, ambient session path, pairing or reconnect.
import {PrivateAuthStore} from './private_auth.mjs';
import {PrivateSocketOwner} from './private_socket.mjs';
import {PrivateSpoolProducer} from './private_spool.mjs';
import {Readable} from 'node:stream';

const logger = {level: 'silent'};
for (const name of ['trace', 'debug', 'info', 'warn', 'error', 'fatal']) logger[name] = () => {};
logger.child = () => logger;
Object.freeze(logger);

export class PrivateBaileysOwner {
  #directory;
  #profile;
  #loadSDK;
  #auth = null;
  #socket = null;
  #starting = null;
  #closing = null;
  #cancelled = false;
  #ready = false;
  #handlers = null;
  #allocationDigest;

  constructor({directory, profile, allocation_digest, loadSDK = () => import('@whiskeysockets/baileys')}) {
    if (typeof directory !== 'string' || typeof profile !== 'string' || typeof loadSDK !== 'function') throw Error('invalid_context');
    this.#directory = directory; this.#profile = profile; this.#loadSDK = loadSDK;
    this.#allocationDigest = allocation_digest;
  }

  account() {
    if (!this.#ready || this.#cancelled) throw Error('not_ready');
    const captured = this.#auth.account(), observed = this.#socket.account();
    const learnedLid = captured.lid === undefined && typeof observed?.lid === 'string' &&
      /^[0-9]+(?::[0-9]+)?@lid$/.test(observed.lid) && Buffer.byteLength(observed.lid) <= 256;
    if (captured.id !== observed?.id || (!learnedLid && captured.lid !== observed?.lid)) {
      this.#fault(); throw Error('invalid_context');
    }
    // A first LID can be needed to filter the migration's own self-chat event
    // while the credential writer is still fsyncing it. Return only validated
    // identity fields, never the SDK's display name or mutable object.
    return learnedLid ? Object.freeze({id: captured.id, lid: observed.lid}) : captured;
  }

  #fault() {
    const first = !this.#cancelled;
    this.cancel();
    if (first) { try { this.#handlers?.disconnected(); } catch { /* closed code only */ } }
  }

  deliveryProducer(recipient, kind, data, media = null) {
    this.account();
    if (typeof recipient !== 'string' || Buffer.byteLength(recipient) > 256 ||
        !/^[^@\s]+@(s\.whatsapp\.net|g\.us|lid)$/.test(recipient)) throw Error('invalid_context');
    let content, options = {};
    if (kind === 'text' || kind === 'status') {
      if (media !== null) throw Error('invalid_context');
      if (typeof data.text !== 'string' || Buffer.byteLength(data.text) > 32768) throw Error('invalid_schema');
      content = {text: data.text};
      if (data.reply !== null) {
        // Other native quote kinds require the qualified private reply builder.
        if (data.reply?.native_kind !== 'text' || data.reply.key.remote_jid !== recipient) throw Error('not_ready');
        const key = data.reply.key;
        options = {quoted: {key: {id: key.id, remoteJid: key.remote_jid,
          participant: key.participant ?? undefined, fromMe: key.from_me},
          message: {conversation: data.reply.text}}};
      }
    } else if (kind === 'artifact') {
      if (data.reply !== null || typeof data.mime !== 'string' || Buffer.byteLength(data.mime) > 128 ||
          typeof data.file_name !== 'string' || Buffer.byteLength(data.file_name) > 1024 ||
          !media || Object.keys(media).join() !== 'stream' || !(media.stream instanceof Readable)) throw Error('invalid_schema');
      content = {document: {stream: media.stream}, mimetype: data.mime || 'application/octet-stream',
        fileName: data.file_name || 'document'};
    } else throw Error('not_ready');
    return this.#socket.deliveryProducer(recipient, content, options);
  }

  documentProducer({recipient, generation, authority, data}) {
    return new PrivateSpoolProducer({authority, profile: this.#profile, generation, data,
      createSender: stream => this.deliveryProducer(recipient, 'artifact', data, {stream})});
  }

  start(handlers) {
    if (this.#starting || this.#cancelled) return Promise.reject(Error('not_ready'));
    this.#handlers = handlers;
    this.#starting = (async () => {
      const sdk = await this.#loadSDK();
      if (this.#cancelled || typeof sdk.makeWASocket !== 'function') throw Error('not_ready');
      this.#auth = await PrivateAuthStore.open({directory: this.#directory, profile: this.#profile,
        allocation_digest: this.#allocationDigest,
        codec: {replacer: sdk.BufferJSON?.replacer, reviver: sdk.BufferJSON?.reviver,
          appStateKey: value => sdk.proto.Message.AppStateSyncKeyData.fromObject(value)},
        onFault: () => this.#fault()});
      if (this.#cancelled) throw Error('not_ready');
      this.#socket = new PrivateSocketOwner({credentials: this.#auth, openSocket: () => sdk.makeWASocket({
        auth: this.#auth.state, logger,
        // Use the installed SDK's pinned protocol version; no latest-version
        // HTTP request, ordinary message store, history download or retry send.
        markOnlineOnConnect: false, syncFullHistory: false, fireInitQueries: false, emitOwnEvents: false,
        shouldSyncHistoryMessage: () => false, getMessage: async () => undefined,
        maxMsgRetryCount: 0, enableAutoSessionRecreation: false, enableRecentMessageCache: false,
        transactionOpts: {maxCommitRetries: 1, delayBetweenTriesMs: 0},
      })});
      const ready = await this.#socket.start({
        upsert: value => { if (this.#ready && !this.#cancelled) handlers.upsert(value); else this.#fault(); },
        disconnected: () => this.#fault(),
      });
      // Account evidence is released only after its actual credential write.
      if (ready !== true || this.#cancelled || await this.#auth.save() !== true || this.#cancelled) throw Error('not_ready');
      this.#ready = true;
      this.account();
      return true;
    })().catch(() => { this.#fault(); throw Error('transport_fault'); });
    this.#starting.catch(() => {});
    return this.#starting;
  }

  cancel() {
    this.#cancelled = true; this.#ready = false;
    this.#socket?.cancel();
  }

  join() {
    this.cancel();
    if (!this.#closing) this.#closing = (async () => {
      // Retain an in-flight import/auth open, even if caller cancellation wins.
      await this.#starting?.catch(() => {});
      if (this.#socket) return await this.#socket.join();
      return this.#auth ? await this.#auth.join() : true;
    })().catch(() => false);
    return this.#closing;
  }
}
