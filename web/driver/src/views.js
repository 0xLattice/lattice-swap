// The views a buyer's machine is fed, read as `swap::view` says and the
// native driver reads them, each from the one backend its chain is set to:
// an Esplora for Bitcoin, a Nexus node's public read port for Nexus. Each
// is trusted for what it shows, as eigenwallet trusts its Electrum server
// and Monero node; a buyer that trusts neither points both at its own.

import { call, wasm } from './wasm.js';

/** `lookups`, as a watch names them, read from `esplora`: `{tip, view}`,
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
 * how deep a transaction is: the CLI's own checks, swap-wasm's
 * `checkNexus`, on what this reads. */
export async function checkNexus(nexus, genesis) {
  const chainInfo = await nexus.get('/api/chain/info');
  const health = await nexus.get('/health');
  const at = call('nexusProbeHeight', health);
  let pastState = null;
  if (at !== null) {
    const block = await nexus.get(`/api/block/${at}`, true);
    const probe = block && (await nexus.get(`/accounts/${wasm.nexusProbeAddress()}?block=${block.hash}`, true));
    pastState = Boolean(probe);
  }
  const refused = wasm.checkNexus(JSON.stringify({ genesis, chain_info: chainInfo, health, past_state: pastState }));
  if (refused !== undefined && refused !== null) throw new Error(refused);
}
