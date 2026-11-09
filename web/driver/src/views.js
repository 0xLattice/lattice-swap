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
  // Trusted for where a transaction is, never for what it is: a spend of
  // the lock or of cancel's output must spend it, or an unrelated
  // transaction named as cancel's spender would read as the seller's punish.
  for (const [spent, outpoint] of [[lockSpend, lookups.lock], [cancelSpend, lookups.cancel_output]]) {
    if (spent && !wasm.spendsOutpoint(spent.tx, outpoint)) throw new Error(`${wasm.txidOf(spent.tx)} does not spend ${outpoint}`);
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

/** How long a round's Nexus reads and the submits they lead to may take,
 * in ms, as the native driver's `NEXUS_BUDGET`. */
export const NEXUS_BUDGET = 10_000;

/** One Nexus node's read API, at `url`: its public read port. */
export class Nexus {
  constructor(url, fetchImpl = globalThis.fetch, budget = NEXUS_BUDGET) {
    this.url = url.replace(/\/+$/, '');
    this.fetch = fetchImpl;
    this.budget = budget;
    /** What ends the round's Nexus requests, while a round reads it: as the
     * native driver's `nexus_budget`, a node that hangs delays the next
     * Bitcoin round by the budget at most. */
    this.deadline = null;
  }

  /** `read` of the answer to `path`, fetched and read under the round's
   * deadline, else a budget of its own. No redirects, as the native client
   * follows none: one could move an https node's reads to plain http. */
  async #fetch(path, init, read) {
    const signal = this.deadline ?? AbortSignal.timeout(this.budget);
    try {
      return await read(await this.fetch(`${this.url}${path}`, { ...init, redirect: 'error', signal }));
    } catch (e) {
      if (signal.aborted) throw new Error(`${this.url}${path}: no answer within the Nexus budget (nexusBudget)`);
      throw e;
    }
  }

  /** A route's JSON; null on 404 if `missing` is allowed. The public port
   * marks live reads cacheable for seconds, so none is read from a cache
   * here. */
  async get(path, missing = false) {
    return this.#fetch(path, { cache: 'no-store' }, async (response) => {
      if (missing && response.status === 404) return null;
      if (!response.ok) throw new Error(`${this.url}${path}: ${response.status} ${await response.text()}`);
      return response.json();
    });
  }

  /** `/health`, its height and tip read live from `/api/chain/info`, as
   * the native `Client::public` reads them: a public read port answers
   * `/health` from a snapshot up to a few seconds old and every other read
   * live, so a depth worked out against the snapshot's height would miss a
   * block the other reads show. `/api/chain/info` names no best header,
   * so, as there, the node counts as synced only if the snapshot was (its
   * best header at its height) and the live tip has reached that header;
   * otherwise no best header is given. */
  async health() {
    const { bestHeaderHeight, ...health } = await this.get('/health');
    const { height, tipCID } = await this.get('/api/chain/info');
    const synced = bestHeaderHeight != null && health.height != null && height != null
      && BigInt(bestHeaderHeight) === BigInt(health.height) && BigInt(height) >= BigInt(bestHeaderHeight);
    return { ...health, height, tipCID, ...(synced ? { bestHeaderHeight: height } : {}) };
  }

  /** Submits `body`, from `nexusSubmitBody`. As plain text: a JSON body
   * would need a CORS preflight, which a public read port behind a proxy
   * may refuse, and the node reads the body as JSON whatever its type. */
  async submit(body) {
    const init = { method: 'POST', headers: { 'Content-Type': 'text/plain' }, body };
    await this.#fetch('/transactions', init, async (response) => {
      if (!response.ok) throw new Error(`${this.url}: ${response.status} ${await response.text()}`);
    });
  }
}

/** The node's `/api/chain/info`, once it shows the Nexus of `genesis`:
 * swap-wasm's `checkGenesis`, as the native driver checks it first every
 * round. Throws its refusal otherwise. */
export async function nexusGenesis(nexus, genesis) {
  const chainInfo = await nexus.get('/api/chain/info');
  const refused = wasm.checkGenesis(JSON.stringify({ genesis, chain_info: chainInfo }));
  if (refused !== undefined && refused !== null) throw new Error(refused);
  return chainInfo;
}

/** The view for `watch`, a watch's `nexus`, in the native driver's
 * order, or null if the tip moved under it. A node on another Nexus than
 * `genesis` is refused before anything else is read of it, in the native
 * driver's words. */
export async function nexusView(nexus, watch, genesis) {
  const account = (address) => nexus.get(`/api/state/account/${encodeURIComponent(address)}`);
  const transaction = (cid) => nexus.get(`/api/transaction/${encodeURIComponent(cid)}`, true);
  let chainInfo;
  try {
    chainInfo = await nexusGenesis(nexus, genesis);
  } catch (e) {
    throw new Error(`nexus: ${e.message}: Nexus is not read until it passes; Bitcoin goes on`);
  }
  const health = await nexus.health();
  const own = await account(watch.own_address);
  const lock = await account(watch.lock_address);
  let watched = null;
  if (watch.cid !== null) {
    const before = await transaction(watch.cid);
    const tip = await nexus.health();
    watched = { before, health: tip, after: before === null ? null : await transaction(watch.cid) };
  }
  const blockAt = watch.block_at === null ? null : await nexus.get(`/api/block/${watch.block_at}`, true);
  const after = await nexus.health();
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

/** Refuses a node that takes no transactions, as the page submits its
 * claim through it, then a node on another Nexus than `genesis`, where a
 * NEX lock is worthless, or one that keeps no state of past blocks and so
 * cannot say how deep a transaction is: the CLI's own checks of a public
 * node, swap-wasm's `checkNexus`, on what this reads. */
export async function checkNexus(nexus, genesis) {
  const chainInfo = await nexus.get('/api/chain/info');
  if (chainInfo.acceptsSubmit !== true) throw new Error(`refused: ${nexus.url} takes no transactions: give a Nexus node that does`);
  const health = await nexus.health();
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
