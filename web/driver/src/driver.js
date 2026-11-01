// The buyer's side of a swap in a browser: what `swap::driver::Driver`
// does for a buyer, over browser I/O. The machine, and every rule it and
// its views are judged by, is swap-wasm's; this reads the chains, carries
// the session, keeps the record and carries out what the machine asks.
//
// A browser has no wallet: the buyer deposits to the address of a fresh
// key, and once the deposit confirms the driver takes the offer and funds
// the lock from it. A deposit that does not fit, an offer gone or no longer
// acceptable before it confirms, or a swap aborted before the lock is
// funded, sends the deposit back to the refund address, and no swap runs.
// The swap's own refund pays the deposit key too, and is sent on from there
// to the refund address by a child that can bump it, at swap-wasm's
// `refundRate`: the highest estimate, uncapped, doubling as the punish
// nears.
//
// The buyer's signatures, after which the funding goes out, are held until
// the seller's are durable: the browser keeps the store, or the buyer took
// the backup again since they came (`status().step` is `save-backup`).

import { call, safe, wasm } from './wasm.js';
import { Esplora } from './esplora.js';
import { agreed, agreedUtxos, alike, bitcoinView, checkNexus, Nexus, nexusView } from './views.js';
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
  /** The page's `navigator.locks`, so that one tab alone drives a swap,
   * and `navigator.storage`, asked to keep the store; the browser's own
   * where it has them. */
  locks: undefined,
  storage: undefined,
  now: () => Date.now(),
};

/** The blocks a fee estimate aims to confirm in, as the CLI's. */
const FEE_TARGET = 6;
/** About ten minutes a Bitcoin block. */
const BLOCK_MS = 600_000;

/** `f` on `input` as JSON, for a wasm call that answers plain text or
 * none: its text, or null. */
const text = (f, input) => f(JSON.stringify(input)) ?? null;

/** The variant a state is in: what the native driver times a quiet
 * counterparty by. */
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
  #persisted = null;
  #elsewhere = false;
  /** The last Bitcoin view stepped on, one source's or all of theirs. */
  #seen = null;
  /** The buyer's signatures, held until the seller's are durable. */
  #held = null;

  constructor(config, record) {
    super();
    this.#c = { ...DEFAULTS, ...config };
    this.#c.fetch ??= (...args) => globalThis.fetch(...args);
    this.#c.WebSocket ??= globalThis.WebSocket;
    if (this.#c.locks === undefined) this.#c.locks = globalThis.navigator?.locks ?? null;
    if (this.#c.storage === undefined) this.#c.storage = globalThis.navigator?.storage ?? null;
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
    const estimates = await driver.#estimates();
    const refused = await driver.#refusal(decoded, policy, estimates);
    if (refused !== null) throw new Error(refused);
    const deposit = call('newBitcoinKey', c.network);
    // The machine's refund pays the deposit key, which sends it on.
    const started = call('startBuyer', JSON.stringify(decoded.terms), deposit.script_pubkey, nexAddress);
    const quoteRate = call('feeRate', { estimates, fallback: c.fallbackFeeRate });
    const quote = call('depositQuote', {
      btc_amount: decoded.terms.btc_amount,
      fee_rate: quoteRate,
      deposit_wif: deposit.wif,
      refund_script: refundScript,
    });
    const record = {
      swap_id: decoded.terms.swap_id,
      offer: decoded,
      policy,
      relay: decoded.relay,
      state: JSON.stringify(started.state),
      // The hello, sent once the deposit confirms and the offer is taken.
      pending: started.actions,
      deposit,
      refund_script: refundScript,
      quote,
      quote_rate: quoteRate,
      btc_fee: decoded.terms.btc_fee,
      backed_up: false,
      backup_stale: false,
      taken: false,
      utxos: null,
      fee_rate: null,
      funding: null,
      child: null,
      refund_child: null,
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
   * from the chains alone; any BTC back to `refundAddress`. The funding,
   * if the file holds one, is the state's own: its change, found by the
   * deposit key's script, is sent on as before, its child paying as if the
   * funding paid no fee, at most the funding's fee more. */
  static async restore(config, { file, refundAddress }) {
    const c = { ...DEFAULTS, ...config };
    const restored = call('restore', file);
    if (restored.side !== 'buyer') throw new Error('not a buyer’s swap');
    const state = JSON.stringify(restored.state);
    const swapId = call('backup', state, undefined).name.replace(/\.json$/, '');
    const { browser } = restored;
    const status = JSON.parse(wasm.buyerStatus(state, undefined, false));
    const record = {
      swap_id: swapId,
      offer: null,
      policy: null,
      relay: browser?.relay ?? null,
      state,
      pending: [],
      deposit: browser && call('bitcoinKeyOf', browser.deposit, c.network),
      refund_script: wasm.scriptOf(refundAddress, c.network),
      quote: null,
      quote_rate: browser?.quote_rate ?? null,
      btc_fee: status.btc_fee,
      backed_up: true,
      backup_stale: false,
      taken: true,
      utxos: null,
      fee_rate: null,
      funding: status.funding && { tx: status.funding, fee: 0 },
      child: null,
      refund_child: null,
      deposit_refund: null,
      watch_posted: false,
    };
    await c.store.save(record);
    const driver = new Buyer(c, record);
    await checkNexus(driver.#nexus, c.nexusGenesis);
    return driver;
  }

  /** The swap file for the buyer to keep, `{name, file}`: the state as it
   * stands, the deposit key, the relay and the quote's fee rate, which
   * {@link Buyer.restore} reads; `lattice-swap resume` refuses it, since
   * its refund pays the deposit key. The deposit address is shown only
   * once this was called. A file holds the swap as it stood when taken:
   * one taken before the seller's signatures recovers the deposit, not a
   * swap under way, whose refund needs them; the store holds those, and
   * `status().backupStale` says to take the file again. */
  async backup() {
    const r = this.#r;
    const browser = r.deposit && {
      deposit: r.deposit.wif,
      relay: r.relay,
      quote_rate: r.quote_rate ?? this.#c.fallbackFeeRate,
    };
    const file = call('backup', r.state, browser && JSON.stringify(browser));
    if (!r.backed_up || r.backup_stale) {
      r.backed_up = true;
      r.backup_stale = false;
      await this.#save();
      // Signatures held for this backup go out.
      this.#wake?.();
    }
    return file;
  }

  get swapId() {
    return this.#r.swap_id;
  }

  /** Where the swap is, for a page to show:
   * - `step`: `backup` until {@link Buyer#backup}, `deposit` until the
   *   deposit confirms, `locking` until the seller's NEX lock is trusted,
   *   but `save-backup` while the seller's signatures are in, and only in,
   *   a store the browser has not agreed to keep (`persisted`): the
   *   buyer's signatures, and so the funding, are held until the buyer
   *   takes {@link Buyer#backup} again, whose file can then refund it; a
   *   buyer that does not within `messageTimeout` gets the deposit back,
   *   the swap aborted,
   *   `finishing` once the redeem is signed, then `swapped`; `refunding`
   *   and `refunded` when the BTC comes back; or `punished`, `drained`;
   * - `deposit`: once backed up, `{address, amount, received,
   *   confirmations}`, `amount` in sat;
   * - `mustStayOpen`: from the funding's broadcast until the swap is
   *   settled, nothing but this page acts for the buyer, and a lapse can
   *   cost it; except once it has given up with the redeem unsigned and a
   *   watchtower holds its refund (`Buyer::must_stay_open`);
   * - `backupStale`: the seller's signatures are saved since the last
   *   {@link Buyer#backup}, whose file then recovers the deposit but not a
   *   swap under way: take it again;
   * - `persisted`: whether the browser agreed to keep the store under
   *   storage pressure, null if unknown: if not, a page should warn;
   * - `elsewhere`: another tab drives this swap, and this one does not;
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
      backupStale: Boolean(r.backup_stale),
      persisted: this.#persisted,
      elsewhere: this.#elsewhere,
      deadlines: { cancel: null, punish: null },
      tip: this.#tip,
      warning: this.#warning,
    };
    if (!r.backed_up) status.step = 'backup';
    else if (this.#held) status.step = 'save-backup';
    else if (r.deposit_refund) status.step = r.deposit_refund.confirmed ? 'refunded' : 'refunding';
    else if (!r.taken) status.step = 'deposit';
    else {
      const machine = JSON.parse(wasm.buyerStatus(r.state, this.#view ? JSON.stringify(this.#view) : undefined, r.watch_posted));
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
   * `status` event follows every change of {@link Buyer#status}. Only one
   * tab drives a swap: in another, this waits, with `status().elsewhere`
   * set, until that tab closes, then drives it. */
  async run(signal) {
    try {
      this.#persisted = (await this.#c.storage?.persist?.()) ?? null;
    } catch {
      this.#persisted = false;
    }
    const locks = this.#c.locks;
    if (!locks) return this.#loop(signal);
    const name = `lattice-swap:${this.swapId}`;
    const drive = () => {
      this.#elsewhere = false;
      return this.#loop(signal);
    };
    // Free, it drives at once; held, it says so, then waits in line.
    let free = false;
    const done = await locks.request(name, { ifAvailable: true }, (lock) => {
      if (lock === null) return null;
      free = true;
      return drive();
    });
    if (free) return done;
    this.#elsewhere = true;
    this.#announce();
    try {
      return await locks.request(name, signal ? { signal } : {}, drive);
    } catch (e) {
      if (signal?.aborted) return null;
      throw e;
    }
  }

  async #loop(signal) {
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
    const held = this.#held;
    this.#held = null;
    if (held && kind(r.state) === 'SendingSignatures') await this.#act(held);
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
    if (phase === 'refunded' && r.deposit) {
      await this.#forward();
      return null;
    }
    return ['swapped', 'refunded', 'punished', 'drained'].includes(phase) ? phase : null;
  }

  /** Feeds `event` to the machine, saves what changed, then does what it
   * asks: nothing is sent or broadcast that a restart would not know of.
   * `oneSource`: `event` is one Bitcoin source's view, which the machine
   * takes only as far as `Buyer::step_one_source` says. */
  async #apply(event, oneSource = false) {
    const stepped = oneSource
      ? call('stepBuyerOneSource', this.#r.state, JSON.stringify(event.Bitcoin))
      : call('stepBuyer', this.#r.state, JSON.stringify(event));
    const next = JSON.stringify(stepped.state);
    if (next !== this.#r.state) {
      // The file taken before holds none of the seller's signatures.
      if (kind(next) === 'SendingSignatures') this.#r.backup_stale = true;
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
      // After these the funding goes out, and its refund needs the
      // seller's signatures: none until they are durable. The machine
      // waits, and the seller's silence aborts it.
      if (kind(r.state) === 'SendingSignatures' && this.#persisted !== true && r.backup_stale) {
        this.#held = action;
        return;
      }
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
      // The funding's change, or the refund, sent on from the deposit key.
      await this.#child(action.Broadcast);
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

  /** Sends what `parent`, the funding or the swap's refund, pays the
   * deposit key on to the refund address, its child paying for the two
   * together at `rate`, by default the spend rate for the funding and the
   * refund rate for the refund, if not at this rate already; then
   * broadcasts it. The way either is bumped while it waits: by CPFP, since
   * the seller's signatures pin both txids. A parent that pays the deposit
   * key nothing, as cancel, has no child. */
  async #child(parent, rate) {
    const r = this.#r;
    if (!r.deposit) return;
    const funding = parent === r.funding?.tx;
    const slot = funding ? 'child' : 'refund_child';
    rate ??= funding ? await this.#spendRate() : await this.#refundRate(r.refund_child);
    if (!r[slot] || rate > r[slot].rate) {
      const child = call('changeChild', {
        wif: r.deposit.wif,
        parent,
        parent_fee: funding ? r.funding.fee : (r.btc_fee ?? 0),
        refund_script: r.refund_script,
        fee_rate: rate,
      });
      if (child === null) return;
      // Each one replaced, in case it is the one that confirms.
      const replaced = r[slot] ? [...(r[slot].replaced ?? []), r[slot].txid].filter((txid) => txid !== child.txid) : [];
      r[slot] = { ...child, rate, height: this.#seen?.height ?? null, replaced };
      await this.#save();
    }
    await this.#broadcast(r[slot].tx);
  }

  /** Reads every Bitcoin source. A view they all show alike goes to the
   * machine; otherwise each one's goes to it as one source's view, which it
   * acts on only as far as no lie can turn against the buyer: so a source
   * down for good still lets it cancel, refund a redeem never signed, and
   * claim on a redeem; a signed redeem's refund waits for both. */
  async #observeBitcoin() {
    const watch = call('watchBuyer', this.#r.state).bitcoin;
    if (!watch) return;
    const seen = await Promise.all(this.#esplora.map((esplora) => bitcoinView(esplora, watch).catch(() => null)));
    const all = alike(seen);
    if (all !== null) {
      const { stale, first_seen } = call('bitcoinStale', {
        tip: all.tip,
        first_seen: this.#firstSeen,
        max_tip_age: this.#c.maxTipAge,
        now: Math.floor(this.#c.now() / 1000),
      });
      this.#firstSeen = first_seen;
      this.#tip = all.tip.height;
      this.#view = { ...all.view, stale };
      this.#seen = this.#view;
      await this.#apply({ Bitcoin: this.#view });
    } else {
      for (const one of seen.filter((one) => one !== null)) {
        this.#tip = Math.max(this.#tip ?? 0, one.tip.height);
        this.#seen = { ...one.view, stale: null };
        await this.#apply({ Bitcoin: this.#seen }, true);
      }
    }
    for (const one of seen.filter((one) => one !== null)) await this.#bump(one.view);
  }

  /** At each new block while the funding waits unconfirmed, by any
   * source, raises its child to the spend rate, if that is a rate above
   * the last: by at least 1 sat/vB, which a replacement must add. The
   * refund's child is raised each time the machine broadcasts the refund
   * again. */
  async #bump(view) {
    const r = this.#r;
    const waiting = r.funding && r.child && (view.funding === null || view.funding === 0);
    if (!waiting || view.height === this.#bumpedAt) return;
    this.#bumpedAt = view.height;
    const rate = await this.#spendRate();
    await this.#broadcast(r.funding.tx);
    await this.#child(r.funding.tx, rate);
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
    const relay = this.#c.watchtower === undefined ? this.#r.relay : this.#c.watchtower;
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
    const estimates = await this.#estimates();
    r.fee_rate = this.#feeRate(estimates);
    const refused = text(wasm.depositRefused, {
      utxos: r.utxos,
      btc_amount: r.offer.terms.btc_amount,
      quote: r.quote,
      fee_rate: r.fee_rate,
    });
    if (refused !== null) return this.#refundDeposit(refused);
    const listed = (await offers(r.offer.relay, this.#c.fetch)).map((text) => JSON.parse(text).terms?.swap_id);
    if (!listed.includes(r.swap_id)) return this.#refundDeposit('the offer is no longer listed');
    // Judged again at today's fees: the offer's own fee may have fallen
    // below them while the deposit confirmed.
    const stale = await this.#refusal(r.offer, r.policy, estimates);
    if (stale !== null) return this.#refundDeposit(stale);
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
   * at `rate`, the spend rate by default: no swap runs. */
  async #refundDeposit(why, rate) {
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
      fee_rate: rate ?? (await this.#spendRate()),
    });
    r.deposit_refund = { tx, txid, why, confirmed: false };
    await this.#save();
    await this.#broadcast(tx);
  }

  /** Once the swap refunded to the deposit key, sends it on to the
   * refund address: by the child of the refund this driver broadcast, or,
   * for a refund a watchtower broadcast while the buyer was away, by
   * sending on what the deposit key holds. */
  async #forward() {
    const r = this.#r;
    const child = r.refund_child;
    if (child) {
      const { tx, txid, replaced } = child;
      r.deposit_refund = { tx, txid, replaced, why: 'the swap refunded', confirmed: false };
      await this.#save();
      await this.#broadcast(tx);
      return;
    }
    // The deposit's own outputs were spent by the funding: read anew.
    r.utxos = null;
    await this.#refundDeposit('the swap refunded', await this.#refundRate(null));
  }

  /** The deposit's refund, broadcast again until both sources show it, or
   * a version it replaced, in a block. */
  async #refunding() {
    const refund = this.#r.deposit_refund;
    if (refund.confirmed) return 'refunded';
    const seen = await agreed(this.#esplora, async (esplora) => {
      for (const txid of [refund.txid, ...(refund.replaced ?? [])]) {
        const tx = await esplora.transaction(txid);
        if (tx !== null) return { seen: true, confirmed: tx.height !== null };
      }
      return { seen: false, confirmed: false };
    });
    if (seen?.confirmed) {
      refund.confirmed = true;
      await this.#save();
      return 'refunded';
    }
    if (!seen?.seen) await this.#broadcast(refund.tx);
    return null;
  }

  /** Each source's estimate for the CLI's target, in sat/vB, null where
   * one has none. */
  #estimates() {
    return Promise.all(this.#esplora.map((esplora) => esplora.feeRate(FEE_TARGET).catch(() => null)));
  }

  /** The rate a spend from the deposit key pays, by swap-wasm's `feeRate`:
   * the lowest estimate, bounded by the quote's headroom. */
  #feeRate(estimates) {
    return call('feeRate', {
      estimates,
      fallback: this.#c.fallbackFeeRate,
      quote_rate: this.#r.quote_rate ?? this.#c.fallbackFeeRate,
    });
  }

  async #spendRate() {
    return this.#feeRate(await this.#estimates());
  }

  /** The rate the swap's refund and what sends it on pay, by swap-wasm's
   * `refundRate`, `last` its child before, if any: the highest estimate,
   * not bounded by the quote, doubled at each block once the punish is
   * near on the view last stepped on. */
  async #refundRate(last) {
    const seen = this.#seen;
    return call('refundRate', {
      estimates: await this.#estimates(),
      fallback: this.#c.fallbackFeeRate,
      punish_at: seen && call('buyerStatus', this.#r.state, seen).punish_at,
      tip: seen?.height ?? null,
      last: last?.height == null ? null : { rate: last.rate, height: last.height },
    });
  }

  /** Why the buyer refuses `offer` under `policy`, as the CLI's `take`, at
   * the highest of `estimates` for its fee floor, or null: a source that
   * answers low must not pass an offer whose cancel would not confirm. */
  async #refusal(offer, policy, estimates) {
    const known = estimates.filter((rate) => rate !== null);
    const minRelayFee = Number((await this.#nexus.get('/api/chain/info')).minRelayFee);
    return text(wasm.checkOffer, {
      offer,
      policy,
      network: this.#c.network,
      nexus_genesis: this.#c.nexusGenesis,
      fee_estimate: known.length ? Math.ceil(Math.max(...known) * 1000) : null,
      min_relay_fee: minRelayFee,
    });
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
