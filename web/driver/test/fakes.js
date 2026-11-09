// Fake servers on loopback for the driver's tests: an Esplora, a Nexus
// node and a relay, each answering only what a test set, and a seller,
// swap-wasm's own machine, standing in for the session.

import { createHash } from 'node:crypto';
import { createServer } from 'node:http';
import { readFileSync } from 'node:fs';
import { call, load, wasm } from '../src/wasm.js';

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

/** A server on loopback that redirects every request to the same path at
 * `to`, logging each path asked in `paths`. */
export async function redirecting(to, paths = []) {
  const server = createServer((request, response) => {
    paths.push(request.url);
    response.writeHead(302, { Location: `${to}${request.url}` });
    response.end();
  });
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  return {
    url: `http://127.0.0.1:${server.address().port}`,
    paths,
    close: () => {
      server.close();
      server.closeAllConnections();
    },
  };
}

/** A chain as an Esplora shows it: its block 0, by default regtest's, its
 * tip, transactions and outputs. */
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
    this.genesis = wasm.bitcoinGenesis('regtest');
  }

  get hash() {
    return this.height.toString(16).padStart(64, '0');
  }

  mine(blocks = 1) {
    this.height += blocks;
    this.time = Math.floor(Date.now() / 1000);
  }
}

/** `hex` as a transaction: `{txid, inputs: [{txid, vout, witness}],
 * outputs: [{value, script}]}`, scripts and witness items in hex. */
export function parseTx(hex) {
  const b = Buffer.from(hex, 'hex');
  let i = 0;
  const take = (n) => b.subarray((i += n) - n, i);
  const varint = () => {
    const first = b[i++];
    if (first < 0xfd) return first;
    return first === 0xfd ? take(2).readUInt16LE() : take(4).readUInt32LE();
  };
  take(4);
  const segwit = b[i] === 0 && b[i + 1] === 1;
  if (segwit) i += 2;
  const body = i;
  const inputs = Array.from({ length: varint() }, () => {
    const txid = Buffer.from(take(32)).reverse().toString('hex');
    const vout = take(4).readUInt32LE();
    take(varint());
    take(4);
    return { txid, vout, witness: [] };
  });
  const outputs = Array.from({ length: varint() }, () => ({
    value: Number(take(8).readBigUInt64LE()),
    script: take(varint()).toString('hex'),
  }));
  const end = i;
  if (segwit) for (const input of inputs) input.witness = Array.from({ length: varint() }, () => take(varint()).toString('hex'));
  const stripped = Buffer.concat([b.subarray(0, 4), b.subarray(body, end), take(4)]);
  const sha = (data) => createHash('sha256').update(data).digest();
  return { txid: Buffer.from(sha(sha(stripped))).reverse().toString('hex'), inputs, outputs };
}

/** Why `hex` cannot spend what it spends, as far as an Esplora over
 * `chain` that took `posted` can tell, or null: each input spends an
 * output of a transaction it knows, or one paying an address, and an input
 * signed as P2WPKH spends a P2WPKH output. */
function unspendable(chain, posted, hex) {
  const known = new Map(posted.map((tx) => [parseTx(tx).txid, tx]));
  for (const [txid, { hex: tx }] of chain.txs) if (!known.has(txid)) known.set(txid, tx);
  for (const input of parseTx(hex).inputs) {
    const outpoint = `${input.txid}:${input.vout}`;
    if ([...chain.utxos.values()].flat().some((utxo) => `${utxo.txid}:${utxo.vout}` === outpoint)) continue;
    let parent;
    try {
      parent = parseTx(known.get(input.txid));
    } catch {
      return `bad-txns-inputs-missingorspent: ${outpoint}`;
    }
    const output = parent.outputs[input.vout];
    if (!output) return `bad-txns-inputs-missingorspent: ${outpoint}`;
    const p2wpkh = input.witness.length === 2 && input.witness[1].length === 66;
    if (p2wpkh && !/^0014[0-9a-f]{40}$/.test(output.script)) return `mandatory-script-verify-flag-failed: ${outpoint}`;
  }
  return null;
}

/** An Esplora over `chain`: what it takes is logged in `posted`, and
 * `onPost(hex)` runs first; it refuses a transaction that spends what it
 * cannot. It logs each path asked in `chain.paths`, if given. */
export async function esplora(chain, onPost = () => {}) {
  const posted = [];
  const server = await serve(async (method, path, body) => {
    chain.paths?.push(path);
    if (method === 'POST' && path === '/tx') {
      if (chain.postDown) return [503, 'down'];
      await onPost(body);
      const refused = unspendable(chain, posted, body);
      if (refused) return [400, `sendrawtransaction RPC error: ${refused}`];
      posted.push(body);
      return [200, parseTx(body).txid];
    }
    const { height, hash } = chain;
    if (path === '/blocks/tip/hash') return [200, hash];
    if (path === `/block/${hash}`) return [200, { height, timestamp: chain.time }];
    if (path === '/fee-estimates') return [200, chain.fees];
    if (path === '/block-height/0') return [200, chain.genesis];
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
    if (m && chain.utxosDown) return [503, 'down'];
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

/** A Nexus node's public read port at height 1 on the test offer's
 * genesis, or on `genesis`, that takes submits unless `acceptsSubmit` is
 * false, its relay floor 1 or `minRelayFee`; its `/api/chain/info` is at `height` and `tip`, if given, while
 * its `/health`, a snapshot, stays at height 1, synced if `synced` holds.
 * It shows the accounts in `accounts`, by address, and logs what is
 * submitted to it in `submitted`, if given. It logs each path asked in
 * `paths`, if given, answers 503 to everything while `down` holds, never
 * answers while `hangs` holds, and otherwise calls `onRead(path)` before it
 * answers. */
export function nexus(node = {}) {
  return serve((method, path, body) => {
    node.paths?.push(path);
    if (node.down) return [503, 'down'];
    if (node.hangs) return new Promise(() => {});
    node.onRead?.(path);
    if (method === 'POST' && path === '/transactions' && node.submitted) {
      node.submitted.push(body);
      return [200, {}];
    }
    const account = path.match(/^\/api\/state\/account\/(\w+)$/);
    if (account && node.accounts?.[account[1]]) return [200, node.accounts[account[1]]];
    if (path === '/api/chain/info') {
      return [200, {
        chain: ['Nexus'], genesisHash: node.genesis ?? 'genesis', minRelayFee: node.minRelayFee ?? '1',
        height: node.height ?? '1', tipCID: node.tip ?? 'tip', acceptsSubmit: node.acceptsSubmit ?? true,
      }];
    }
    if (path === '/health') return [200, { phase: 'active', height: '1', tipCID: 'tip', ...(node.synced ? { bestHeaderHeight: '1' } : {}) }];
    // The block halfway up, and the state after it, if it keeps them.
    if (path.startsWith('/api/block/') && node.keepsState) return [200, { hash: 'half' }];
    if (path.startsWith('/accounts/') && node.keepsState) return [200, { balance: '0', nonce: '0' }];
  });
}

/** The test offer, its relay `relay`: signed by the seller of key 4. */
export function testOffer(relay) {
  const offer = JSON.parse(readFileSync(new URL('./offer.json', import.meta.url), 'utf8'));
  offer.relay = relay;
  return JSON.stringify(offer);
}

/** What `prepare` is given for the test offer: the most it takes. */
export const POLICY = {
  btc_amount: 1_000_000, price: 2_000_000, max_t1: 20, min_t2: 20,
  min_btc_confirmations: 1, min_nex_confirmations: 1, min_margin: 3,
  min_refund_window: 19, min_btc_fee_rate: 1,
};

/** The seller of `offer`, in swap-wasm, behind a session the driver opens:
 * `log` holds what the buyer sent, in order. It answers the buyer's
 * request with `answer(request, terms)`, by default the terms at the
 * amount asked for, then starts its machine on them; once it answers
 * anything else, it says nothing more. A session opened at a rendezvous
 * reaches it only at its own (`sellerRejoin`), and is first sent its last
 * message again. `step(event)` feeds its machine what its chains show,
 * signing its NEX lock with its own key: what it sends goes into the
 * session open, if one is, and is lost otherwise. `state()` is its
 * state. */
export function seller(offer, answer = (_request, terms) => ({ Terms: terms })) {
  const decoded = JSON.parse(offer);
  const key = () => call('newBitcoinKey', 'regtest').script_pubkey;
  const nexKey = call('newNexKey');
  let state = null;
  let reply = () => {};
  const log = [];
  const step = (event) => {
    let stepped = call('stepSeller', state, JSON.stringify(event));
    state = JSON.stringify(stepped.state);
    for (const action of stepped.actions) {
      if (action.Send) {
        reply(action.Send);
        step('Sent');
      } else if (action.SignNex) {
        step({ NexSigned: call('signNex', nexKey.seed, JSON.stringify(action.SignNex)) });
      }
    }
  };
  const open = async (_offer, onMessage, { rejoin = null } = {}) => {
    // Only the buyer comes to the seller's rendezvous, under its rejoin key.
    const at = state === null ? null : call('sellerRejoin', state);
    if (rejoin !== null && (at?.id !== rejoin.id || at.key !== rejoin.key)) throw new Error('no one came');
    reply = (message) => setTimeout(() => !session.closed && onMessage(JSON.stringify(message)), 1);
    const session = {
      closed: false,
      send(message) {
        if (session.closed) throw new Error('closed');
        log.push(JSON.parse(message));
        const { Request } = JSON.parse(message);
        if (Request) {
          const terms = call('offerTerms', { offer: decoded, btc_amount: Request.btc_amount });
          const answered = answer(Request, terms);
          if (answered === null) return;
          reply({ Answer: answered });
          if (answered.Terms) {
            state = JSON.stringify(call('newSeller', JSON.stringify(answered.Terms), nexKey.address, key(), key()));
          }
          return;
        }
        if (state === null) return;
        step({ Message: JSON.parse(message) });
      },
      close() {
        session.closed = true;
      },
    };
    const again = rejoin === null ? null : call('sellerResend', state);
    if (again) reply(again);
    return session;
  };
  return { open, log, step, state: () => state };
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

/** The Web Locks an origin's tabs share, exclusive only: `tab()` is one
 * tab's `navigator.locks`, and `close(tab)` lets go of what it holds, as
 * closing the tab does. */
export class Locks {
  constructor() {
    this.held = new Map();
    this.waiting = [];
  }

  tab() {
    const tab = { closed: false, request: (name, options, callback) => this.#request(tab, name, options, callback) };
    return tab;
  }

  close(tab) {
    tab.closed = true;
    this.waiting = this.waiting.filter((waiter) => waiter.tab !== tab);
    for (const [name, holder] of this.held) if (holder === tab) this.#release(name, tab);
  }

  #request(tab, name, options, callback) {
    if (typeof options === 'function') [options, callback] = [{}, options];
    return new Promise((resolve, reject) => {
      const grant = () => {
        this.held.set(name, tab);
        Promise.resolve(callback({ name, mode: 'exclusive' }))
          .then(resolve, reject)
          .finally(() => this.#release(name, tab));
      };
      if (!this.held.has(name)) grant();
      else if (options.ifAvailable) Promise.resolve(callback(null)).then(resolve, reject);
      else this.waiting.push({ name, tab, grant });
    });
  }

  #release(name, tab) {
    if (this.held.get(name) !== tab) return;
    this.held.delete(name);
    const next = this.waiting.findIndex((waiter) => waiter.name === name);
    if (next >= 0) this.waiting.splice(next, 1)[0].grant();
  }
}
