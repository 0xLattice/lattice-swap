// A swap relay, as the CLI's buyer uses one: its board, and its pipe to
// the seller, carrying an ivy session end to end.

import { wasm } from './wasm.js';

/** The offers `relay` lists, each as its text, which `decodeOffer` reads:
 * its `quote` holds the `price`, in sat a NEX of 1,000,000 base units,
 * and the `min_btc_amount` and `max_btc_amount` a buyer picks between. */
export async function offers(relay, fetchImpl = globalThis.fetch) {
  // No redirects, as the native engine's clients follow none.
  const response = await fetchImpl(`${relay.replace(/\/+$/, '')}/offers`, { cache: 'no-store', redirect: 'error' });
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

/** How often a session pings the seller, and how many pings in a row may
 * go unanswered before it ends: as the CLI's `swap::transport::PING` and
 * `PINGS_MISSED`. A socket whose other end is gone without a word, a
 * laptop asleep or a network changed, stays open; only a keepalive tells
 * it from a quiet one, as libp2p's ping and SSH's `ServerAliveInterval` do. */
export const PING = 15_000;
export const PINGS_MISSED = 3;

/** The ivy session to the seller of `offer`, through the relay it names:
 * messages arrive at `onMessage`, as JSON. Once it ends, by the relay or
 * the seller, a record that fails, or pings that go unanswered, `closed`
 * holds and nothing more is sent or received. */
export class Session {
  /** Opens it, and waits up to `timeout` ms for the handshake: by taking
   * the offer, or, given `rejoin` (`buyerRejoin`), by meeting the seller
   * again at its rendezvous, under its key, once the relay says it has
   * come. `signal` aborts the wait. */
  static async open(offer, onMessage, { WebSocket = globalThis.WebSocket, timeout = 30_000, rejoin = null, signal = null, ping = PING } = {}) {
    const swapId = offer.template.swap_id;
    const socket = new WebSocket(socketUrl(offer.relay, rejoin === null ? `take/${swapId}` : `rejoin/${rejoin.id}`));
    socket.binaryType = 'arraybuffer';
    const key = rejoin === null ? offer.buyer_session : rejoin.key;
    const session = new Session(socket, new wasm.Ivy(key, offer.seller, swapId), onMessage, { paired: rejoin === null, ping });
    await new Promise((resolve, reject) => {
      const timer = setTimeout(() => fail(new Error('the handshake timed out')), timeout);
      const aborted = () => fail(new Error('aborted'));
      const fail = (e) => {
        clearTimeout(timer);
        signal?.removeEventListener('abort', aborted);
        // Why it failed, not that closing it ended it.
        session.failed = null;
        session.close();
        reject(e);
      };
      session.opened = () => {
        clearTimeout(timer);
        signal?.removeEventListener('abort', aborted);
        session.failed = null;
        resolve();
      };
      session.failed = fail;
      if (signal?.aborted) return aborted();
      signal?.addEventListener('abort', aborted, { once: true });
      socket.onopen = () => session.flush();
    });
    return session;
  }

  constructor(socket, ivy, onMessage, { paired = true, ping = PING } = {}) {
    this.socket = socket;
    this.ivy = ivy;
    this.closed = false;
    /** Whether the relay pipes this socket to the seller: at a rendezvous,
     * only once it says `paired`. */
    this.paired = paired;
    socket.onmessage = (event) => this.#receive(event.data);
    socket.onclose = () => this.close();
    socket.onerror = () => this.close();
    this.onMessage = onMessage;
    /** Pings sent since the seller was last heard. */
    this.unanswered = 0;
    this.pinger = setInterval(() => this.#ping(), ping);
  }

  #ping() {
    if (!this.ivy.isOpen()) return;
    if (this.unanswered >= PINGS_MISSED) return this.close();
    try {
      this.ivy.ping();
    } catch {
      return this.close();
    }
    this.unanswered += 1;
    this.flush();
  }

  #receive(data) {
    if (this.closed) return;
    // The relay speaks text only before it pairs: none belongs in a session.
    if (typeof data === 'string') {
      if (data !== 'paired' || this.paired) return this.close();
      this.paired = true;
      return this.flush();
    }
    let messages;
    try {
      messages = this.ivy.receive(new Uint8Array(data));
    } catch {
      return this.close();
    }
    this.unanswered = 0;
    this.flush();
    if (this.ivy.isOpen() && this.opened) {
      const opened = this.opened;
      this.opened = null;
      opened();
    }
    for (const message of messages) this.onMessage(message);
  }

  /** Writes what the session has queued, once paired. */
  flush() {
    if (!this.paired) return;
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
    clearInterval(this.pinger);
    try {
      this.socket.close();
    } catch {
      // Closed already.
    }
    this.failed?.(new Error('the session ended'));
  }
}
