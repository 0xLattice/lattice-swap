// Bitcoin through an Esplora API, as mempool.space and blockstream.info
// serve one: the reads a buyer's view needs, broadcasts, and the reads and
// package submit its refund's CPFP bump needs, as the native
// `swap::esplora` bumps.

import { wasm } from './wasm.js';

/** How long one request may take, in ms, as the native Esplora client's
 * timeout. */
export const ESPLORA_TIMEOUT = 30_000;

/** How long a round's refund bump may take, in ms, all its requests
 * together: as the Nexus reads' `NEXUS_BUDGET`, an Esplora that hangs
 * delays the next round by this at most. */
export const BUMP_BUDGET = 10_000;

/** A signal that aborts once `a` or `b` does: `AbortSignal.any`, and by
 * hand where a browser lacks it (before Chrome 116, Firefox 124, Safari
 * 17.4). */
export function either(a, b) {
  if (typeof AbortSignal.any === 'function') return AbortSignal.any([a, b]);
  const controller = new AbortController();
  const abort = () => controller.abort();
  if (a.aborted || b.aborted) abort();
  a.addEventListener('abort', abort, { once: true });
  b.addEventListener('abort', abort, { once: true });
  return controller.signal;
}

/** One Esplora API at `url`, e.g. `https://mempool.space/api`. */
export class Esplora {
  constructor(url, fetchImpl = globalThis.fetch, timeout = ESPLORA_TIMEOUT) {
    this.url = url.replace(/\/+$/, '');
    this.fetch = fetchImpl;
    this.timeout = timeout;
    /** What also ends each of this instance's requests, if set: a
     * bump's, by {@link Esplora#within}. */
    this.deadline = null;
  }

  /** This Esplora for one round's bump: every request it makes also ends
   * at `deadline`, while the wallet's own, which others share, keep only
   * their timeout. */
  within(deadline) {
    const esplora = new Esplora(this.url, this.fetch, this.timeout);
    esplora.deadline = deadline;
    return esplora;
  }

  /** `path` fetched, its answer read within `timeout` ms, and before the
   * `deadline`, if set. No redirects, as the native client follows none:
   * one could move an https Esplora's reads to plain http, where anyone on
   * the way can change them. */
  async #fetch(path, init, read) {
    const timeout = AbortSignal.timeout(this.timeout);
    const deadline = this.deadline;
    const signal = deadline === null ? timeout : either(timeout, deadline);
    try {
      return await read(await this.fetch(`${this.url}${path}`, { ...init, redirect: 'error', signal }));
    } catch (e) {
      // As the Nexus client's: which server failed to answer, not a bare abort.
      if (deadline?.aborted) throw new Error(`${this.url}${path}: no answer within the round's bump budget`);
      if (signal.aborted) throw new Error(`${this.url}${path}: no answer within ${this.timeout} ms`);
      throw e;
    }
  }

  /** The answer's text; null on 404 if `missing` is allowed. */
  async #get(path, missing = false) {
    return this.#fetch(path, { cache: 'no-store' }, async (response) => {
      if (missing && response.status === 404) return null;
      if (!response.ok) throw new Error(`${this.url}${path}: ${response.status} ${await response.text()}`);
      return response.text();
    });
  }

  /** Refuses an Esplora on another chain than `network`, whose blocks
   * would never show the swap's transactions: its block 0 must be
   * `network`'s genesis, as the native app's `Esplora::check_network`
   * checks. */
  async checkNetwork(network) {
    const expected = wasm.bitcoinGenesis(network);
    const genesis = (await this.#get('/block-height/0')).trim();
    if (genesis !== expected) throw new Error(`refused: the Esplora's genesis is ${genesis}, not ${network}'s ${expected}`);
  }

  /** The tip as `swap::view::Tip`: Esplora shows its blocks, not a header
   * chain ahead of them, so `headers` is the tip's own height. */
  async tip() {
    const hash = (await this.#get('/blocks/tip/hash')).trim();
    const block = JSON.parse(await this.#get(`/block/${hash}`));
    return { height: block.height, headers: block.height, time: block.timestamp, hash };
  }

  /** A transaction, if Esplora holds it: `{hex, height}`, `height` null in
   * the mempool. `/tx/{txid}` answers 404 for one it never saw; its
   * `/status` would answer unconfirmed. Trusted for where a transaction
   * is, never for what it is: a forged refund would read as a punish. */
  async transaction(txid) {
    const tx = await this.#get(`/tx/${txid}`, true);
    if (tx === null) return null;
    const { status } = JSON.parse(tx);
    const hex = await this.#get(`/tx/${txid}/hex`, true);
    if (hex === null) return null;
    if (wasm.txidOf(hex) !== txid) throw new Error(`${this.url}/tx/${txid}/hex is another transaction`);
    return { hex: hex.trim(), height: status.confirmed ? status.block_height : null };
  }

  /** How `/tx/{txid}` shows a transaction: `{fee, weight, confirmed}`, or
   * null for one it never saw. */
  async shown(txid) {
    const tx = await this.#get(`/tx/${txid}`, true);
    if (tx === null) return null;
    const { fee, weight, status } = JSON.parse(tx);
    return { fee, weight, confirmed: status.confirmed };
  }

  /** The unconfirmed transaction that spends `txid:vout`, if any, as
   * {@link Esplora#shown} shows it, with its `txid`: as the native
   * Esplora's `pooled_spender`. */
  async pooledSpender(txid, vout) {
    const spend = JSON.parse(await this.#get(`/tx/${txid}/outspend/${vout}`));
    if (!spend.spent || !spend.txid || spend.status?.confirmed) return null;
    const shown = await this.shown(spend.txid);
    return shown === null ? null : { txid: spend.txid, ...shown };
  }

  /** The txid that spends `txid:vout`, in the mempool or a block, if any. */
  async spender(txid, vout) {
    const spend = JSON.parse(await this.#get(`/tx/${txid}/outspend/${vout}`));
    return spend.spent ? spend.txid : null;
  }

  /** What pays `address`: `[{txid, vout, value, height}]`, `height` null
   * in the mempool. */
  async utxos(address) {
    const utxos = JSON.parse(await this.#get(`/address/${address}/utxo`));
    return utxos.map(({ txid, vout, value, status }) => ({
      txid,
      vout,
      value,
      height: status.confirmed ? status.block_height : null,
    }));
  }

  /** The fee rate, in sat/vB, to confirm within `blocks`, or null. */
  async feeRate(blocks) {
    const estimates = JSON.parse(await this.#get('/fee-estimates'));
    const rate = estimates[String(blocks)];
    return typeof rate === 'number' ? rate : null;
  }

  /** Submits `hexes`, a parent and its child, as one package to
   * `POST /txs/package`, Bitcoin Core's `submitpackage`; throws unless it
   * answers success, as the native Esplora's bump. */
  async submitPackage(hexes) {
    const init = { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(hexes) };
    return this.#fetch('/txs/package', init, async (response) => {
      const text = await response.text();
      if (!response.ok) throw new Error(`${this.url}/txs/package: ${response.status} ${text}`);
      let answer;
      try {
        answer = JSON.parse(text);
      } catch (e) {
        throw new Error(`${this.url}/txs/package: ${e.message}`);
      }
      if (answer.package_msg !== 'success') throw new Error(`${this.url}/txs/package: ${text}`);
    });
  }

  /** Broadcasts `hex`; throws with Esplora's reason if it refuses it. */
  async broadcast(hex) {
    const init = { method: 'POST', headers: { 'Content-Type': 'text/plain' }, body: hex };
    return this.#fetch('/tx', init, async (response) => {
      const text = await response.text();
      if (!response.ok) throw new Error(`${this.url}: ${response.status} ${text}`);
      return text.trim();
    });
  }
}
