// Fake servers on loopback for the driver's tests: two Esploras, a Nexus
// node and a relay, each answering only what a test set, and a seller,
// swap-wasm's own machine, standing in for the session.

import { createHash } from 'node:crypto';
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
 * cannot. `source.fees`, if set, are its estimates instead of the chain's,
 * `source.txs` transactions it shows beside the chain's, as `chain.txs`,
 * and while `source.down` holds it answers nothing. */
export async function esplora(chain, onPost = () => {}, source = {}) {
  const posted = [];
  const server = await serve(async (method, path, body) => {
    if (source.down) return [503, 'down'];
    if (method === 'POST' && path === '/tx') {
      await onPost(body);
      const refused = unspendable(chain, posted, body);
      if (refused) return [400, `sendrawtransaction RPC error: ${refused}`];
      posted.push(body);
      return [200, parseTx(body).txid];
    }
    if (path === '/blocks/tip/hash') return [200, chain.hash];
    if (path === `/block/${chain.hash}`) return [200, { height: chain.height, timestamp: chain.time }];
    if (path === '/fee-estimates') return [200, source.fees ?? chain.fees];
    let m = path.match(/^\/tx\/(\w+)(\/hex)?$/);
    if (m) {
      const tx = source.txs?.get(m[1]) ?? chain.txs.get(m[1]);
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
    if (path === '/health') return [200, { phase: 'active', height: '1', tipCID: 'tip' }];
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
