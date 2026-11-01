// The buyer's side of a swap in a browser: what `swap::driver::Driver`
// does for a buyer, over browser I/O. The machine, and every rule it and
// its views are judged by, is swap-wasm's; this reads the chains, carries
// the session, keeps the record and carries out what the machine asks.
//
// A browser has no wallet: the buyer deposits to the address of a fresh
// key, and once the deposit confirms the driver takes the offer and funds
// the lock from it. A deposit that does not fit, an offer gone before it
// confirms, or a swap aborted before the lock is funded, sends the deposit
// back to the refund address, and no swap runs.

import { call, safe, wasm } from './wasm.js';
import { Esplora } from './esplora.js';
import { agreed, agreedUtxos, bitcoinView, checkNexus, Nexus, nexusView } from './views.js';
import { offers, postWatch, Session } from './relay.js';

/** The CLI's own settings, where it has one. */
export const DEFAULTS = {
  /** Where each swap's record is kept, e.g. an `IndexedDBStore`: none is
   * assumed, so a page chooses. */
  store: undefined,
  network: 'bitcoin',
  esplora: ['https://mempool.space/api', 'https://blockstream.info/api'],
  nexus: 'https://lattice-mainnet-read.fly.dev',
  nexusGenesis: 'bafyreiggtg4ezifboyekbf4gxst2jr3mpjqcxsbmopy7w6fp46g4ngpgxa',
  /** The relay whose watchtower gets the refund; the offer's by default. */
  watchtower: undefined,
  /** Between two rounds of reads, in ms. */
  poll: 10_000,
  /** How long the seller may stay quiet before anything is at stake. */
  messageTimeout: 60_000,
  /** The least time between two tries to hand the refund over. */
  watchRetry: 60_000,
  /** The oldest a Bitcoin tip may be, in seconds, for a view not to be
   * stale. */
  maxTipAge: 90 * 60,
  /** The fee rate, in sat/vB, the funding pays where no source has an
   * estimate, as on regtest. */
  fallbackFeeRate: 10,
  fetch: undefined,
  WebSocket: undefined,
  /** Opens the session to the seller, as `Session.open`; tests stand a
   * seller in. */
  openSession: undefined,
  now: () => Date.now(),
};

/** The blocks a fee estimate aims to confirm in, as the CLI's. */
const FEE_TARGET = 6;
/** No transaction here pays below 1 sat/vB, the default relay floor. */
const MIN_RELAY = 1;
/** About ten minutes a Bitcoin block. */
const BLOCK_MS = 600_000;

/** The variant a state is in: what the native driver times a quiet
 * counterparty by. */
/** `f` on `input` as JSON, for a wasm call that answers plain text or
 * none: its text, or null. */
const text = (f, input) => f(JSON.stringify(input)) ?? null;

const kind = (state) => {
  const value = JSON.parse(state);
  return typeof value === 'string' ? value : Object.keys(value)[0];
};

export class Buyer extends EventTarget {
  #c;
  #r;
  #esplora;
  #nexus;
  #session = null;
  #inbox = [];
  #awaits = false;
  #kind;
  #since;
  #view = null;
  #tip = null;
  #firstSeen = null;
  #bumpedAt = null;
  #watchTried = null;
  #deposit = null;
  #warning = null;
  #status = '';
  #wake = null;

  constructor(config, record) {
    super();
    this.#c = { ...DEFAULTS, ...config };
    this.#c.fetch ??= (...args) => globalThis.fetch(...args);
    this.#c.WebSocket ??= globalThis.WebSocket;
    this.#r = record;
    this.#esplora = this.#c.esplora.map((url) => new Esplora(url, this.#c.fetch));
    this.#nexus = new Nexus(this.#c.nexus, this.#c.fetch);
    this.#since = this.#c.now();
    if (record) {
      this.#kind = kind(record.state);
      this.#awaits = call('buyerStatus', record.state).awaits_message;
    }
  }

  /** A swap of `offer`, an offer's text from a relay's board, that the
   * buyer agreed to by `policy` (`swap::offer::Policy`: the amounts, and
   * any bound to hold other than the CLI's): its record saved, nothing
   * sent. The NEX goes to `nexAddress`; any BTC back to `refundAddress`.
   * Refuses the offer as the CLI's `take` would. */
  static async prepare(config, { offer, policy, refundAddress, nexAddress }) {
    const c = { ...DEFAULTS, ...config };
    const decoded = call('decodeOffer', offer);
    if (!safe(decoded) || !safe(policy)) throw new Error('refused: an amount JavaScript cannot hold exactly');
    if (!decoded.relay) throw new Error('refused: the offer names no relay to reach the seller through');
    if (!wasm.isCid(nexAddress)) throw new Error(`${nexAddress} is not a Nexus address`);
    const refundScript = wasm.scriptOf(refundAddress, c.network);
    // Reads only, before there is a record.
    const driver = new Buyer(c, null);
    await checkNexus(driver.#nexus, c.nexusGenesis);
    const estimate = await driver.#estimate();
    const minRelayFee = Number((await driver.#nexus.get('/api/chain/info')).minRelayFee);
    const refused = text(wasm.checkOffer, {
      offer: decoded,
      policy,
      network: c.network,
      nexus_genesis: c.nexusGenesis,
      fee_estimate: estimate === null ? null : Math.ceil(estimate * 1000),
      min_relay_fee: minRelayFee,
    });
    if (refused !== null) throw new Error(refused);
    const started = call('startBuyer', JSON.stringify(decoded.terms), refundScript, nexAddress);
    const deposit = call('newBitcoinKey', c.network);
    const quote = call('depositQuote', {
      btc_amount: decoded.terms.btc_amount,
      fee_rate: driver.#rate(estimate),
      deposit_wif: deposit.wif,
      refund_script: refundScript,
    });
    const record = {
      swap_id: decoded.terms.swap_id,
      offer: decoded,
      state: JSON.stringify(started.state),
      // The hello, sent once the deposit confirms and the offer is taken.
      pending: started.actions,
      deposit,
      refund_script: refundScript,
      quote,
      backed_up: false,
      taken: false,
      utxos: null,
      fee_rate: null,
      funding: null,
      child: null,
      deposit_refund: null,
      watch_posted: false,
    };
    await c.store.save(record);
    driver.#r = record;
    driver.#kind = kind(record.state);
    driver.#awaits = started.awaits_message;
    return driver;
  }

  /** The swap `swapId` in the store, carried on from where it stopped. Its
   * session, if it had one, is gone: the swap goes on from the chains, as
   * after `lattice-swap resume`. */
  static async resume(config, swapId) {
    const record = await config.store.load(swapId);
    if (!record) throw new Error(`no swap ${swapId} in the store`);
    const driver = new Buyer(config, record);
    await checkNexus(driver.#nexus, driver.#c.nexusGenesis);
    return driver;
  }

  /** The swap in a backup `file`, from {@link Buyer#backup}, carried on
   * from the chains alone; any BTC back to `refundAddress`. */
  static async restore(config, { file, refundAddress }) {
    const c = { ...DEFAULTS, ...config };
    const restored = call('restore', file);
    if (restored.side !== 'buyer') throw new Error('not a buyer’s swap');
    const state = JSON.stringify(restored.state);
    const swapId = call('backup', state, undefined).name.replace(/\.json$/, '');
    const record = {
      swap_id: swapId,
      offer: null,
      state,
      pending: [],
      deposit: restored.deposit && call('bitcoinKeyOf', restored.deposit, c.network),
      refund_script: wasm.scriptOf(refundAddress, c.network),
      quote: null,
      backed_up: true,
      taken: true,
      utxos: null,
      fee_rate: null,
      funding: null,
      child: null,
      deposit_refund: null,
      watch_posted: false,
    };
    await c.store.save(record);
    const driver = new Buyer(c, record);
    await checkNexus(driver.#nexus, c.nexusGenesis);
    return driver;
  }

  /** The swap file for the buyer to keep, `{name, file}`: the state as it
   * stands and the deposit key, which `lattice-swap resume` and
   * {@link Buyer.restore} read. The deposit address is shown only once
   * this was called. A file holds the swap as it stood when taken: one
   * taken before the lock is funded recovers the deposit, not a swap
   * under way, whose refund needs the seller's later signatures; the
   * store holds those. */
  async backup() {
    const file = call('backup', this.#r.state, this.#r.deposit?.wif);
    if (!this.#r.backed_up) {
      this.#r.backed_up = true;
      await this.#save();
    }
    return file;
  }

  get swapId() {
    return this.#r.swap_id;
  }

  /** Where the swap is, for a page to show:
   * - `step`: `backup` until {@link Buyer#backup}, `deposit` until the
   *   deposit confirms, `locking` until the seller's NEX lock is trusted,
   *   `finishing` once the redeem is signed, then `swapped`; `refunding`
   *   and `refunded` when the BTC comes back; or `punished`, `drained`;
   * - `deposit`: once backed up, `{address, amount, received,
   *   confirmations}`, `amount` in sat;
   * - `mustStayOpen`: the redeem is signed and the swap not settled:
   *   nothing but this page refunds or claims for the buyer then;
   * - `deadlines`: `cancel`, the height from which the lock refunds, and
   *   `punish`, the height the refund must confirm before, each with `eta`
   *   in ms since the epoch, once known;
   * - `tip`, and `warning`, the last failure, if any. */
  status() {
    const r = this.#r;
    const status = {
      swapId: r.swap_id,
      step: null,
      deposit: null,
      mustStayOpen: false,
      deadlines: { cancel: null, punish: null },
      tip: this.#tip,
      warning: this.#warning,
    };
    if (!r.backed_up) status.step = 'backup';
    else if (r.deposit_refund) status.step = r.deposit_refund.confirmed ? 'refunded' : 'refunding';
    else if (!r.taken) status.step = 'deposit';
    else {
      const machine = call('buyerStatus', r.state, this.#view && JSON.stringify(this.#view));
      status.step = machine.phase === 'aborted' ? 'refunding' : machine.phase;
      status.mustStayOpen = machine.must_stay_open;
      const eta = (height) => this.#c.now() + Math.max(0, height - (this.#tip ?? height)) * BLOCK_MS;
      for (const [name, height] of [['cancel', machine.cancel_at], ['punish', machine.punish_at]]) {
        if (height !== null) status.deadlines[name] = { height, eta: eta(height) };
      }
    }
    if (r.backed_up && r.deposit && !r.taken) {
      status.deposit = { address: r.deposit.address, amount: r.quote, ...(this.#deposit ?? {}) };
    }
    return status;
  }

  /** Runs the swap until it ends, or `signal` aborts: the final step. A
   * `status` event follows every change of {@link Buyer#status}. */
  async run(signal) {
    while (!signal?.aborted) {
      let done = null;
      try {
        done = await this.#round();
        this.#warning = null;
      } catch (e) {
        this.#warn(e);
      }
      this.#announce();
      if (done) return done;
      await new Promise((resolve) => {
        const timer = setTimeout(resolve, this.#c.poll);
        this.#wake = () => {
          clearTimeout(timer);
          resolve();
        };
        signal?.addEventListener('abort', this.#wake, { once: true });
      });
      this.#wake = null;
    }
    this.#session?.close();
    return null;
  }

  /** One round: the final step once the swap is over, else null. */
  async #round() {
    const r = this.#r;
    if (r.deposit_refund) return this.#refunding();
    if (!r.taken) {
      if (r.backed_up) await this.#awaitDeposit();
      return null;
    }
    for (const message of this.#inbox.splice(0)) await this.#apply({ Message: JSON.parse(message) });
    if (this.#awaits && this.#c.now() - this.#since > this.#c.messageTimeout) await this.#apply('Timeout');
    await this.#observeBitcoin();
    await this.#observeNexus();
    await this.#watchtower();
    const { phase } = call('buyerStatus', r.state);
    if (phase === 'aborted') {
      // Only a swap that never broadcast its funding aborts: the deposit
      // is still there to send back.
      await this.#refundDeposit('the swap stopped before the lock was funded');
      return null;
    }
    return ['swapped', 'refunded', 'punished', 'drained'].includes(phase) ? phase : null;
  }

  /** Feeds `event` to the machine, saves what changed, then does what it
   * asks: nothing is sent or broadcast that a restart would not know of. */
  async #apply(event) {
    const stepped = call('stepBuyer', this.#r.state, JSON.stringify(event));
    const next = JSON.stringify(stepped.state);
    if (next !== this.#r.state) {
      this.#r.state = next;
      await this.#save();
    }
    this.#awaits = stepped.awaits_message;
    if (kind(next) !== this.#kind) {
      this.#kind = kind(next);
      this.#since = this.#c.now();
    }
    for (const action of stepped.actions) await this.#act(action);
  }

  async #act(action) {
    const r = this.#r;
    if (action.Send) {
      if (!this.#session || this.#session.closed) return;
      try {
        this.#session.send(JSON.stringify(action.Send));
      } catch (e) {
        this.#warn(`session ended: ${e.message}`);
        this.#session = null;
        return;
      }
      await this.#apply('Sent');
    } else if (action.FundLock) {
      // Before anything is at stake: a deposit that cannot fund the lock
      // leaves the machine waiting, and the seller's silence aborts it.
      const funded = call('fundLock', {
        wif: r.deposit.wif,
        utxos: r.utxos,
        script_pubkey: action.FundLock.script_pubkey,
        amount: action.FundLock.amount,
        fee_rate: r.fee_rate,
        refund_script: r.refund_script,
      });
      r.funding = funded;
      await this.#apply({ Funded: funded.tx });
    } else if (action.Broadcast) {
      await this.#broadcast(action.Broadcast);
      if (r.funding && action.Broadcast === r.funding.tx) await this.#child(r.fee_rate);
    } else if (action.Submit) {
      try {
        await this.#nexus.submit(wasm.nexusSubmitBody(JSON.stringify(action.Submit)));
      } catch (e) {
        this.#warn(`nexus submit: ${e.message}`);
      }
    }
  }

  /** Broadcasts `hex` through every source; refused by all is logged, and
   * the machine asks again. */
  async #broadcast(hex) {
    const sent = await Promise.allSettled(this.#esplora.map((esplora) => esplora.broadcast(hex)));
    if (sent.every((one) => one.status === 'rejected')) this.#warn(`broadcast: ${sent[0].reason.message}`);
  }

  /** Sends the funding's change on to the refund address, its child paying
   * for the two together at `rate`, if not at this rate already; then
   * broadcasts it. The way a stuck funding is bumped: by CPFP, since the
   * seller's signatures pin the funding's txid. */
  async #child(rate) {
    const r = this.#r;
    if (!r.funding?.change) return;
    if (!r.child || rate > r.child.rate) {
      const child = call('changeChild', {
        wif: r.deposit.wif,
        funding: r.funding.tx,
        funding_fee: r.funding.fee,
        change: r.funding.change,
        refund_script: r.refund_script,
        fee_rate: rate,
      });
      r.child = { ...child, rate };
      await this.#save();
    }
    await this.#broadcast(r.child.tx);
  }

  async #observeBitcoin() {
    const watch = call('watchBuyer', this.#r.state).bitcoin;
    if (!watch) return;
    const seen = await agreed(this.#esplora, (esplora) => bitcoinView(esplora, watch));
    if (seen === null) return;
    const { stale, first_seen } = call('bitcoinStale', {
      tip: seen.tip,
      first_seen: this.#firstSeen,
      max_tip_age: this.#c.maxTipAge,
      now: Math.floor(this.#c.now() / 1000),
    });
    this.#firstSeen = first_seen;
    this.#tip = seen.tip.height;
    this.#view = { ...seen.view, stale };
    await this.#apply({ Bitcoin: this.#view });
    await this.#bump(this.#view);
  }

  /** At each new block while the funding waits unconfirmed, raises its
   * child to the fee estimate, if that is a rate above the last: by at
   * least 1 sat/vB, which a replacement must add. */
  async #bump(view) {
    const r = this.#r;
    const waiting = r.funding?.change && r.child && (view.funding === null || view.funding === 0);
    if (!waiting || view.height === this.#bumpedAt) return;
    this.#bumpedAt = view.height;
    const rate = this.#rate(await this.#estimate());
    await this.#broadcast(r.funding.tx);
    await this.#child(rate);
  }

  async #observeNexus() {
    const watch = call('watchBuyer', this.#r.state).nexus;
    if (!watch) return;
    const view = await nexusView(this.#nexus, watch);
    // The tip moved while the view was read: read again next round.
    if (view !== null) await this.#apply({ Nexus: view });
  }

  /** Hands the watchtower the cancel and the signed refund, in exactly the
   * CLI's condition (`Buyer::watchtower`), every `watchRetry` until it
   * takes them. */
  async #watchtower() {
    const relay = this.#c.watchtower === undefined ? this.#r.offer?.relay : this.#c.watchtower;
    if (!relay || this.#r.watch_posted) return;
    if (this.#watchTried !== null && this.#c.now() - this.#watchTried < this.#c.watchRetry) return;
    const watch = wasm.watchRequest(this.#r.state, this.#c.network);
    if (watch === undefined || watch === null) return;
    this.#watchTried = this.#c.now();
    if (await postWatch(relay, watch, this.#c.fetch).catch(() => false)) {
      this.#r.watch_posted = true;
      await this.#save();
    }
  }

  /** Waits for the deposit to confirm, then takes the offer, or sends the
   * deposit back. */
  async #awaitDeposit() {
    const r = this.#r;
    const seen = await agreedUtxos(this.#esplora, r.deposit.address);
    if (seen === null) return;
    const confirmations = seen.utxos.map((utxo) => (utxo.height === null ? 0 : seen.tip - utxo.height + 1));
    this.#tip = seen.tip;
    this.#deposit = {
      received: seen.utxos.reduce((sum, utxo) => sum + utxo.value, 0),
      confirmations: confirmations.length ? Math.min(...confirmations) : 0,
    };
    if (seen.utxos.length === 0 || this.#deposit.confirmations < 1) return;
    r.utxos = seen.utxos.map(({ txid, vout, value }) => ({ txid, vout, value }));
    r.fee_rate = this.#rate(await this.#estimate());
    const refused = text(wasm.depositRefused, {
      utxos: r.utxos,
      btc_amount: r.offer.terms.btc_amount,
      quote: r.quote,
      fee_rate: r.fee_rate,
    });
    if (refused !== null) return this.#refundDeposit(refused);
    const listed = (await offers(r.offer.relay, this.#c.fetch)).map((text) => JSON.parse(text).terms?.swap_id);
    if (!listed.includes(r.swap_id)) return this.#refundDeposit('the offer is no longer listed');
    const open = this.#c.openSession ?? Session.open;
    this.#session = await open(r.offer, (message) => this.#receive(message), {
      WebSocket: this.#c.WebSocket,
    });
    r.taken = true;
    await this.#save();
    this.#since = this.#c.now();
    const pending = r.pending;
    r.pending = [];
    for (const action of pending) await this.#act(action);
  }

  #receive(message) {
    this.#inbox.push(message);
    this.#wake?.();
  }

  /** Sends the deposit back to the refund address, once it is confirmed,
   * at the fee estimate: no swap runs. */
  async #refundDeposit(why) {
    const r = this.#r;
    if (!r.deposit) return;
    if (!r.utxos) {
      const seen = await agreedUtxos(this.#esplora, r.deposit.address);
      const confirmed = seen?.utxos.filter((utxo) => utxo.height !== null) ?? [];
      if (confirmed.length === 0) return;
      r.utxos = confirmed.map(({ txid, vout, value }) => ({ txid, vout, value }));
    }
    const { tx, txid } = call('refundDeposit', {
      wif: r.deposit.wif,
      utxos: r.utxos,
      refund_script: r.refund_script,
      fee_rate: this.#rate(await this.#estimate()),
    });
    r.deposit_refund = { tx, txid, why, confirmed: false };
    await this.#save();
    await this.#broadcast(tx);
  }

  /** The deposit's refund, broadcast again until both sources show it in a
   * block. */
  async #refunding() {
    const refund = this.#r.deposit_refund;
    if (refund.confirmed) return 'refunded';
    const seen = await agreed(this.#esplora, async (esplora) => {
      const tx = await esplora.transaction(refund.txid);
      return { seen: tx !== null, confirmed: tx?.height != null };
    });
    if (seen?.confirmed) {
      refund.confirmed = true;
      await this.#save();
      return 'refunded';
    }
    if (!seen?.seen) await this.#broadcast(refund.tx);
    return null;
  }

  /** The best estimate any source gives for the CLI's target, in sat/vB,
   * or null: a source that answers low would only slow the funding, and
   * one that answers high only spends the deposit's headroom. */
  async #estimate() {
    const rates = await Promise.all(this.#esplora.map((esplora) => esplora.feeRate(FEE_TARGET).catch(() => null)));
    const known = rates.filter((rate) => rate !== null);
    return known.length ? Math.max(...known) : null;
  }

  /** The rate to pay, in whole sat/vB: the estimate, else the fallback,
   * never below the relay floor. */
  #rate(estimate) {
    return Math.max(MIN_RELAY, Math.ceil(estimate ?? this.#c.fallbackFeeRate));
  }

  async #save() {
    await this.#c.store.save(this.#r);
  }

  #warn(e) {
    this.#warning = typeof e === 'string' ? e : e.message;
  }

  #announce() {
    const status = this.status();
    const text = JSON.stringify(status);
    if (text !== this.#status) {
      this.#status = text;
      this.dispatchEvent(new CustomEvent('status', { detail: status }));
    }
  }
}
