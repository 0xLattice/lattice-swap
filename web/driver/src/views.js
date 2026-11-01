// The views a buyer's machine is fed, read as `swap::view` says and the
// native driver reads them, over the sources a browser has.
//
// Two-source rule: a Bitcoin view, or a deposit, is acted on only when
// every Esplora source, read independently, shows exactly the same: the
// same tip, and the same transactions at the same depths. One source that
// lies or lags then cannot make the buyer act on a chain the other does not
// show; a disagreement, or a source that fails, means wait and read again,
// never act. The Nexus view comes from one node, and is one view only when
// `nexusOneTip` holds for the health read before and after it.

import { call, wasm } from './wasm.js';

/** `lookups`, as a watch names them, read from one Esplora: `{tip, view}`,
 * the view a `swap::BitcoinView` but for `stale`, or null if the tip
 * moved while it was read. */
export async function bitcoinView(esplora, lookups) {
  const tip = await esplora.tip();
  const depth = (tx) => (tx.height === null ? 0 : tip.height - tx.height + 1);
  const spent = async (txids) => {
    for (const txid of txids) {
      const tx = await esplora.transaction(txid);
      if (tx) return { tx: tx.hex, confirmations: depth(tx) };
    }
    return null;
  };
  const funding = await esplora.transaction(lookups.lock.split(':')[0]);
  const lockSpend = await spent(lookups.lock_spends);
  let cancelSpend = await spent(lookups.cancel_spends);
  const from = call('cancelSearchFrom', {
    lookups,
    height: tip.height,
    lock_spend: lockSpend,
    cancel_spend: cancelSpend,
  });
  if (from !== null) {
    const [txid, vout] = lookups.cancel_output.split(':');
    const spender = await esplora.spender(txid, vout);
    cancelSpend = spender === null ? null : await spent([spender]);
  }
  const after = await esplora.tip();
  if (after.hash !== tip.hash) return null;
  const view = {
    height: tip.height,
    funding: funding === null ? null : depth(funding),
    lock_spend: lockSpend,
    cancel_spend: cancelSpend,
  };
  return { tip, view };
}

/** What every source in `sources` shows alike, by `read(source)`, or null
 * if any fails, shows nothing, or shows otherwise. */
export async function agreed(sources, read) {
  const seen = await Promise.all(sources.map((source) => read(source).catch(() => null)));
  if (seen.some((one) => one === null)) return null;
  const first = JSON.stringify(seen[0]);
  return seen.every((one) => JSON.stringify(one) === first) ? seen[0] : null;
}

/** The outputs paying `address` that every source shows alike, in one
 * order, with the tip they were read at: `{tip, utxos}`, or null. */
export function agreedUtxos(sources, address) {
  return agreed(sources, async (esplora) => {
    const tip = (await esplora.tip()).height;
    const utxos = await esplora.utxos(address);
    utxos.sort((a, b) => (a.txid === b.txid ? a.vout - b.vout : a.txid < b.txid ? -1 : 1));
    return { tip, utxos };
  });
}

/** One Nexus node's read API, at `url`: its public read port. */
export class Nexus {
  constructor(url, fetchImpl = globalThis.fetch) {
    this.url = url.replace(/\/+$/, '');
    this.fetch = fetchImpl;
  }

  /** A route's JSON; null on 404 if `missing` is allowed. The public port
   * marks live reads cacheable for seconds, so none is read from a cache
   * here. */
  async get(path, missing = false) {
    const response = await this.fetch(`${this.url}${path}`, { cache: 'no-store' });
    if (missing && response.status === 404) return null;
    if (!response.ok) throw new Error(`${this.url}${path}: ${response.status} ${await response.text()}`);
    return response.json();
  }

  /** Submits `body`, from `nexusSubmitBody`. As plain text: a JSON body
   * would need a CORS preflight, which a public read port behind a proxy
   * may refuse, and the node reads the body as JSON whatever its type. */
  async submit(body) {
    const response = await this.fetch(`${this.url}/transactions`, {
      method: 'POST',
      headers: { 'Content-Type': 'text/plain' },
      body,
    });
    if (!response.ok) throw new Error(`${this.url}: ${response.status} ${await response.text()}`);
  }
}

/** The view for `watch`, a watch's `nexus`, in the native driver's
 * order, or null if the tip moved under it. */
export async function nexusView(nexus, watch) {
  const account = (address) => nexus.get(`/api/state/account/${encodeURIComponent(address)}`);
  const transaction = (cid) => nexus.get(`/api/transaction/${encodeURIComponent(cid)}`, true);
  const health = await nexus.get('/health');
  const own = await account(watch.own_address);
  const lock = await account(watch.lock_address);
  const chainInfo = await nexus.get('/api/chain/info');
  let watched = null;
  if (watch.cid !== null) {
    const before = await transaction(watch.cid);
    const tip = await nexus.get('/health');
    watched = { before, health: tip, after: before === null ? null : await transaction(watch.cid) };
  }
  const blockAt = watch.block_at === null ? null : await nexus.get(`/api/block/${watch.block_at}`, true);
  const after = await nexus.get('/health');
  return call('nexusView', {
    health,
    own,
    lock,
    chain_info: chainInfo,
    watched,
    block_at: blockAt,
    health_after: after,
  });
}

/** Refuses a node on another Nexus than `genesis`, where a NEX lock is
 * worthless, or one that keeps no state of past blocks and so cannot say
 * how deep a transaction is: the CLI's own checks. */
export async function checkNexus(nexus, genesis) {
  const info = await nexus.get('/api/chain/info');
  if (JSON.stringify(info.chain) !== '["Nexus"]' || info.genesisHash !== genesis) {
    throw new Error(`refused: the Nexus node follows the chain of genesis ${info.genesisHash}, not ${genesis}`);
  }
  const height = Number((await nexus.get('/health')).height);
  if (height < 2) return;
  const block = await nexus.get(`/api/block/${Math.ceil(height / 2)}`, true);
  const probe = block && (await nexus.get(`/accounts/${wasm.nexusProbeAddress()}?block=${block.hash}`, true));
  if (!probe) {
    throw new Error('the Nexus node keeps no state of past blocks, so it cannot tell how deep a transaction is');
  }
}
