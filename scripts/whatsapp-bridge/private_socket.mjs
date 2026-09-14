// Own the native SDK socket and its credential writer. Account/auth loading is
// supplied by the private bootstrap, never inherited from the ordinary bridge.
// Process death remains the final join authority for SDK-internal producers.
export class PrivateSocketOwner {
  #openSocket;
  #credentials;
  #socket = null;
  #handlers = null;
  #started = false;
  #cancelled = false;
  #uncertain = false;
  #ready = null;
  #resolveReady;
  #rejectReady;
  #ending = null;
  #writing = null;
  #dirty = false;
  #writerFailed = false;
  #listeners = [];
  #deliveries = new Set();

  deliveryProducer(recipient, content, options = {}) {
    if (this.#cancelled || !this.#socket || typeof this.#socket.sendMessage !== 'function' ||
        this.#deliveries.size >= 4) throw Error('not_ready');
    let work = null, cancelled = false;
    const producer = Object.freeze({
      dispatch: () => {
        if (work || cancelled || this.#cancelled) throw Error('not_ready');
        work = Promise.resolve().then(async () => {
          if (cancelled || this.#cancelled) throw Error('not_ready');
          const result = await this.#socket.sendMessage(recipient, content, options);
          const key = result?.key;
          if (!key || key.remoteJid !== recipient || key.fromMe !== true) throw Error('transport_fault');
          return {id: key.id, remote_jid: key.remoteJid, participant: key.participant ?? null, from_me: true};
        });
        work.catch(() => {});
        return work;
      },
      cancel: () => {
        cancelled = true;
        // The SDK has no qualified per-send abort. Cut this owned socket; never
        // replace it while a send or an internal SDK producer can still run.
        if (work) this.#fault();
      },
      join: async () => {
        cancelled = true;
        await work?.catch(() => {});
        this.#deliveries.delete(producer);
        return true;
      },
    });
    this.#deliveries.add(producer);
    return producer;
  }

  constructor({openSocket, credentials}) {
    if (typeof openSocket !== 'function' || !credentials ||
        typeof credentials.save !== 'function' || typeof credentials.join !== 'function') throw Error('invalid_context');
    this.#openSocket = openSocket;
    this.#credentials = credentials;
  }

  account() {
    if (!this.#socket || this.#cancelled) throw Error('not_ready');
    return this.#socket.user;
  }

  start(handlers) {
    if (this.#started || this.#cancelled) throw Error('not_ready');
    this.#started = true;
    this.#handlers = handlers;
    this.#ready = new Promise((resolve, reject) => {
      this.#resolveReady = resolve; this.#rejectReady = reject;
    });
    // Observe failure even if native construction throws before returning ready.
    this.#ready.catch(() => {});
    try {
      // Must be the synchronous SDK constructor. An ambiguous constructor start
      // fences this process; no caller retries it or substitutes another socket.
      this.#uncertain = true;
      this.#socket = this.#openSocket();
      if (!this.#socket || typeof this.#socket.then === 'function' ||
          !this.#socket.ev || ['on', 'off'].some(name => typeof this.#socket.ev[name] !== 'function') ||
          typeof this.#socket.end !== 'function' || !this.#socket.ws) throw Error('transport_fault');
      this.#uncertain = false;
      this.#listen('messages.upsert', value => { if (!this.#cancelled) handlers.upsert(value); });
      this.#listen('creds.update', () => this.#writeCredentials());
      this.#listen('connection.update', value => {
        if (this.#cancelled) return;
        if (value?.connection === 'open') this.#resolveReady(true);
        else if (value?.connection === 'close' || value?.qr) this.#fault();
      });
    } catch {
      this.#fault();
    }
    return this.#ready;
  }

  #listen(name, callback) {
    // Retain before registration: partial listener installation still cleans up.
    this.#listeners.push([name, callback]);
    this.#socket.ev.on(name, callback);
  }

  #fault() {
    this.cancel();
    this.#handlers?.disconnected();
  }

  #writeCredentials() {
    if (this.#cancelled) return;
    this.#dirty = true;
    this.#ensureWriter();
  }

  #ensureWriter() {
    if (this.#writing) return;
    // One writer and one coalesced dirty bit, not a Promise/task per update.
    this.#writing = Promise.resolve().then(async () => {
      while (this.#dirty) {
        this.#dirty = false;
        if (await this.#credentials.save() !== true) throw Error('storage_fault');
      }
    }).catch(() => { this.#writerFailed = true; this.#fault(); })
      .finally(() => {
        this.#writing = null;
        if (this.#dirty && !this.#writerFailed) this.#ensureWriter();
      });
  }

  cancel() {
    if (this.#cancelled) return;
    this.#cancelled = true;
    this.#rejectReady?.(Error('transport_fault'));
    for (const [name, callback] of this.#listeners) {
      try { this.#socket.ev.off(name, callback); } catch { this.#uncertain = true; }
    }
    // Retain the exact native end Promise, even when the peer already closed.
    this.#ending = Promise.resolve().then(() => this.#socket?.end(Error('private_transport_closed')));
    this.#ending.catch(() => {});
  }

  async join() {
    this.cancel();
    const results = await Promise.allSettled([this.#ending, (async () => {
      while (this.#writing) await this.#writing;
    })(), ...[...this.#deliveries].map(producer => producer.join())]);
    let credentialsJoined = false;
    try { credentialsJoined = await this.#credentials.join() === true; } catch { /* retain */ }
    // A failed write fences readiness, but a completed failed writer is still
    // quiescent. Keep operation outcome separate from native join evidence.
    return !this.#uncertain && results.every(result => result.status === 'fulfilled') && credentialsJoined &&
      (this.#socket === null || this.#socket.ws.isClosed === true);
  }
}
