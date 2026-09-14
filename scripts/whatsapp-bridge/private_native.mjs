// One native socket lifetime per privately bootstrapped generation. This module
// never imports the legacy bridge or opens an account during module evaluation.
import {PrivateAdmissions, PrivateTombstones} from './private_admissions.mjs';
import {PrivateProjection} from './private_projection.mjs';
import {PrivateDeliveries} from './private_delivery.mjs';

export class PrivateNativeServices {
  #owner;
  #queue;
  #projection;
  #runtime;
  #onDrain;
  #accepting = false;
  #fenced = false;
  #cancelFailed = false;
  #activation = null;
  #closing = null;
  #deliveries = null;

  constructor({wire, profile, generation, nativeOwner, runtimeState, onDrain, delivery}) {
    // The owner is retained before start, including a partially failed start.
    // Construction of that owner must be inert; all producers start in start().
    if (!nativeOwner || ['start', 'account', 'cancel', 'join'].some(
      name => typeof nativeOwner[name] !== 'function') || typeof runtimeState !== 'function' ||
      typeof onDrain !== 'function') throw Error('invalid_context');
    this.#owner = nativeOwner;
    this.#runtime = runtimeState;
    this.#onDrain = onDrain;
    const tombstones = new PrivateTombstones();
    this.#queue = new PrivateAdmissions({wire, profile, generation,
      tombstones, onDrain: reason => this.#drain(reason)});
    if (delivery) this.#deliveries = new PrivateDeliveries({wire, profile, generation, tombstones,
      createProducer: delivery.createProducer, classifyText: delivery.classifyText,
      onDrain: reason => this.#drain(reason)});
    this.#projection = new PrivateProjection({wire, profile, generation,
      admissions: this.#queue, account: () => this.#owner.account()});
  }

  #drain(reason = 'transport_fault') {
    if (this.#fenced) return;
    this.#fenced = true;
    this.#accepting = false; // synchronous cut before cancellation or callbacks
    this.#queue.drain(reason);
    this.#deliveries?.close();
    try { this.#owner.cancel(); } catch { this.#cancelFailed = true; }
    this.#onDrain(reason);
  }

  #ingress(kind, value) {
    if (!this.#accepting || this.#fenced) return;
    try {
      // No Promise, native object queue, logging, cache or ordinary observer.
      this.#projection[kind](value);
    } catch { this.#drain('invalid_context'); }
  }

  activate() {
    if (this.#fenced || this.#runtime() !== 'READY') return Promise.reject(Error('not_ready'));
    if (!this.#activation) {
      this.#activation = Promise.resolve().then(async () => {
        if (this.#fenced || this.#runtime() !== 'READY') throw Error('not_ready');
        this.#queue.activate();
        this.#accepting = true;
        const ready = await this.#owner.start(Object.freeze({
          upsert: value => this.#ingress('upsert', value),
          disconnected: () => this.#drain(),
        }));
        if (ready !== true || this.#fenced || this.#runtime() !== 'READY') throw Error('not_ready');
        this.#deliveries?.activate();
        return true;
      }).catch(() => { this.#drain(); throw Error('transport_fault'); });
    }
    return this.#activation;
  }

  close() {
    if (!this.#closing) {
      this.#drain();
      this.#closing = (async () => {
        // cancel must also stop a pending start. A timeout/settled Promise never
        // substitutes for native join, and the parent still joins the process.
        const results = await Promise.allSettled([
          this.#activation, Promise.resolve().then(() => this.#owner.join()),
          Promise.resolve().then(() => this.#queue.close()),
          Promise.resolve().then(() => this.#deliveries?.close() ?? true),
        ]);
        return !this.#cancelFailed && results[1].status === 'fulfilled' && results[1].value === true &&
          results[2].status === 'fulfilled' && results[2].value === true &&
          results[3].status === 'fulfilled' && results[3].value === true;
      })();
    }
    return this.#closing;
  }

  services() {
    return Object.freeze({
      runtimeState: () => this.#runtime(), activate: () => this.activate(),
      fence: () => this.#drain(), close: () => this.close(),
      next: () => this.#queue.next(), claim_transfer: data => this.#queue.transfer(data),
      transfer_state: data => this.#queue.transferState(data), revoke: data => this.#queue.revoke(data),
      cancel: data => {
        if (data.purpose === 'admission') return this.#queue.cancel(data);
        if (data.purpose === 'delivery' && this.#deliveries) return this.#deliveries.cancelControl(data);
        throw Error('not_ready');
      }, settle: data => this.#queue.settle(data),
      ...(this.#deliveries ? {
        text_send: data => this.#deliveries.request('text_send', data),
        artifact_prepare: (data, upload) => this.#deliveries.request('artifact_prepare', data, upload),
        artifact_commit: data => this.#deliveries.commit(data),
        delivery_state: data => this.#deliveries.state(data),
        delivery_settle: data => this.#deliveries.settle(data),
      } : {}),
    });
  }
}
