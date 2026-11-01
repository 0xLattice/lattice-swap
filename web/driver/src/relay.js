// A swap relay, as the CLI's buyer uses one: its board, its pipe to the
// seller, carrying an ivy session end to end, and its watchtower.

import { wasm } from './wasm.js';

/** The offers `relay` lists, each as its text, which `decodeOffer` reads. */
export async function offers(relay, fetchImpl = globalThis.fetch) {
  const response = await fetchImpl(`${relay.replace(/\/+$/, '')}/offers`, { cache: 'no-store' });
  if (!response.ok) throw new Error(`${relay}/offers: ${response.status}`);
  return (await response.json()).map((offer) => JSON.stringify(offer));
}

/** `path` at `relay`, an http:// or https:// URL, as a WebSocket URL. */
export function socketUrl(relay, path) {
  const base = relay.replace(/\/+$/, '');
  if (base.startsWith('https://')) return `wss://${base.slice(8)}/${path}`;
  if (base.startsWith('http://')) return `ws://${base.slice(7)}/${path}`;
  throw new Error(`${relay} is not an http:// or https:// URL`);
}

/** Hands `watch`, from `watchRequest`, to the watchtower at `relay`:
 * whether it took it. As plain text, which needs no CORS preflight. */
export async function postWatch(relay, watch, fetchImpl = globalThis.fetch) {
  const response = await fetchImpl(`${relay.replace(/\/+$/, '')}/watch`, {
    method: 'POST',
    headers: { 'Content-Type': 'text/plain' },
    body: watch,
  });
  return response.ok;
}

/** The ivy session to the seller of `offer`, through the relay it names:
 * messages arrive at `onMessage`, as JSON. Once it ends, by the relay or
 * the seller, or a record that fails, `closed` holds and nothing more is
 * sent or received. */
export class Session {
  /** Opens it, and waits up to `timeout` ms for the handshake. */
  static async open(offer, onMessage, { WebSocket = globalThis.WebSocket, timeout = 30_000 } = {}) {
    const swapId = offer.terms.swap_id;
    const socket = new WebSocket(socketUrl(offer.relay, `take/${swapId}`));
    socket.binaryType = 'arraybuffer';
    const session = new Session(socket, new wasm.Ivy(offer.buyer_session, offer.seller, swapId), onMessage);
    await new Promise((resolve, reject) => {
      const timer = setTimeout(() => fail(new Error('the handshake timed out')), timeout);
      const fail = (e) => {
        clearTimeout(timer);
        session.close();
        reject(e);
      };
      session.opened = () => {
        clearTimeout(timer);
        session.failed = null;
        resolve();
      };
      session.failed = fail;
      socket.onopen = () => session.flush();
    });
    return session;
  }

  constructor(socket, ivy, onMessage) {
    this.socket = socket;
    this.ivy = ivy;
    this.closed = false;
    socket.onmessage = (event) => this.#receive(event.data);
    socket.onclose = () => this.close();
    socket.onerror = () => this.close();
    this.onMessage = onMessage;
  }

  #receive(data) {
    if (this.closed) return;
    // The relay speaks text only before it pairs: none belongs in a session.
    if (typeof data === 'string') return this.close();
    let messages;
    try {
      messages = this.ivy.receive(new Uint8Array(data));
    } catch {
      return this.close();
    }
    this.flush();
    if (this.ivy.isOpen() && this.opened) {
      const opened = this.opened;
      this.opened = null;
      opened();
    }
    for (const message of messages) this.onMessage(message);
  }

  /** Writes what the session has queued. */
  flush() {
    for (let bytes = this.ivy.outbound(); bytes.length > 0; bytes = this.ivy.outbound()) {
      this.socket.send(bytes);
    }
  }

  /** Sends `message`, as JSON; throws once the session has ended. */
  send(message) {
    if (this.closed) throw new Error('the session ended');
    this.ivy.send(message);
    this.flush();
  }

  close() {
    if (this.closed) return;
    this.closed = true;
    try {
      this.socket.close();
    } catch {
      // Closed already.
    }
    this.failed?.(new Error('the session ended'));
  }
}
