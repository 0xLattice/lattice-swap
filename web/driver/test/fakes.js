// Fake servers on loopback for the driver's tests: two Esploras, a Nexus
// node and a relay, each answering only what a test set, and a seller,
// swap-wasm's own machine, standing in for the session.

import { createServer } from 'node:http';
import { readFileSync } from 'node:fs';
import { call, load } from '../src/wasm.js';

export async function loadWasm() {
  await load(readFileSync(new URL('../pkg/swap_wasm_bg.wasm', import.meta.url)));
}

/** Serves `route(method, path, body)` -> `[status, body]` on loopback. */
export async function serve(route) {
  const server = createServer((request, response) => {
    let body = '';
    request.on('data', (chunk) => (body += chunk));
    request.on('end', async () => {
      const [status, answer] = (await route(request.method, request.url, body)) ?? [404, 'not found'];
      response.writeHead(status, { 'Content-Type': typeof answer === 'string' ? 'text/plain' : 'application/json' });
      response.end(typeof answer === 'string' ? answer : JSON.stringify(answer));
    });
  });
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  return {
    url: `http://127.0.0.1:${server.address().port}`,
    close: () => {
      server.close();
      server.closeAllConnections();
    },
  };
}

/** A chain as an Esplora shows it: its tip, transactions and outputs. */
export class Chain {
  constructor(height = 100) {
    this.height = height;
    this.time = Math.floor(Date.now() / 1000);
    /** txid -> {hex, height|null} */
    this.txs = new Map();
    /** address -> [{txid, vout, value, height|null}] */
    this.utxos = new Map();
    /** "txid:vout" -> spending txid */
    this.spends = new Map();
    this.fees = {};
  }

  get hash() {
    return this.height.toString(16).padStart(64, '0');
  }

  mine(blocks = 1) {
    this.height += blocks;
    this.time = Math.floor(Date.now() / 1000);
  }
}

/** An Esplora over `chain`: what it posts is logged in `posted`, and
 * `onPost(hex)` runs first. */
export async function esplora(chain, onPost = () => {}) {
  const posted = [];
  const server = await serve(async (method, path, body) => {
    if (method === 'POST' && path === '/tx') {
      await onPost(body);
      posted.push(body);
      return [200, 'txid'];
    }
    if (path === '/blocks/tip/hash') return [200, chain.hash];
    if (path === `/block/${chain.hash}`) return [200, { height: chain.height, timestamp: chain.time }];
    if (path === '/fee-estimates') return [200, chain.fees];
    let m = path.match(/^\/tx\/(\w+)(\/hex)?$/);
    if (m) {
      const tx = chain.txs.get(m[1]);
      if (!tx) return [404, 'Transaction not found'];
      if (m[2]) return [200, tx.hex];
      return [200, { txid: m[1], status: tx.height === null ? { confirmed: false } : { confirmed: true, block_height: tx.height } }];
    }
    m = path.match(/^\/tx\/(\w+)\/outspend\/(\d+)$/);
    if (m) {
      const txid = chain.spends.get(`${m[1]}:${m[2]}`);
      return [200, txid ? { spent: true, txid } : { spent: false }];
    }
    m = path.match(/^\/address\/(\w+)\/utxo$/);
    if (m) {
      const utxos = chain.utxos.get(m[1]) ?? [];
      return [200, utxos.map(({ txid, vout, value, height }) => ({
        txid, vout, value,
        status: height === null ? { confirmed: false } : { confirmed: true, block_height: height },
      }))];
    }
  });
  return { ...server, posted };
}

/** A Nexus node at height 1 on the test offer's genesis. */
export function nexus() {
  return serve((method, path) => {
    if (path === '/api/chain/info') return [200, { chain: ['Nexus'], genesisHash: 'genesis', minRelayFee: '1', height: '1' }];
    if (path === '/health') return [200, { status: 'ok', height: '1', tip: 'tip', chain: 'Nexus' }];
  });
}

/** A relay listing `offer` until taken; its watchtower answers
 * `watchStatus()` and logs what it is handed in `watches`. */
export async function relay(offer, watchStatus = () => 200) {
  const watches = [];
  const listed = { offer };
  const server = await serve((method, path, body) => {
    if (path === '/offers') return [200, listed.offer ? [JSON.parse(listed.offer)] : []];
    if (method === 'POST' && path === '/watch') {
      const status = watchStatus();
      watches.push({ body, status });
      return [status, status === 200 ? 'cancel-txid' : 'cancel not yet seen'];
    }
  });
  return { ...server, watches, listed };
}

/** The test offer, its relay `relay`: signed by the seller of key 4. */
export function testOffer(relay) {
  const offer = JSON.parse(readFileSync(new URL('./offer.json', import.meta.url), 'utf8'));
  offer.relay = relay;
  return JSON.stringify(offer);
}

/** What `prepare` is given for the test offer. */
export const POLICY = {
  btc_amount: 1_000_000, nex_amount: 500_000, max_t1: 20, min_t2: 20,
  min_btc_confirmations: 1, min_nex_confirmations: 1, min_margin: 3,
  min_refund_window: 19, min_btc_fee_rate: 1,
};

/** The seller of `offer`, in swap-wasm, behind a session the driver opens:
 * `log` holds what the buyer sent, in order. */
export function seller(offer) {
  const terms = JSON.stringify(JSON.parse(offer).terms);
  const key = () => call('newBitcoinKey', 'regtest').script_pubkey;
  let state = JSON.stringify(call('newSeller', terms, call('newNexKey').address, key(), key()));
  const log = [];
  const open = async (_offer, onMessage) => {
    const session = {
      closed: false,
      send(message) {
        if (session.closed) throw new Error('closed');
        log.push(JSON.parse(message));
        let step = call('stepSeller', state, JSON.stringify({ Message: JSON.parse(message) }));
        state = JSON.stringify(step.state);
        for (const action of step.actions.filter((a) => a.Send)) {
          setTimeout(() => !session.closed && onMessage(JSON.stringify(action.Send)), 1);
          step = call('stepSeller', state, '"Sent"');
          state = JSON.stringify(step.state);
        }
      },
      close() {
        session.closed = true;
      },
    };
    return session;
  };
  return { open, log };
}

/** Polls `done` until it holds, failing after `ms`. */
export async function until(done, ms = 5_000) {
  const end = Date.now() + ms;
  while (!(await done())) {
    if (Date.now() > end) throw new Error('timed out');
    await new Promise((resolve) => setTimeout(resolve, 5));
  }
}

/** The state's variant. */
export const kind = (state) => {
  const value = JSON.parse(state);
  return typeof value === 'string' ? value : Object.keys(value)[0];
};
