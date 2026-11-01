// The buyer's side of a swap in a browser: what `swap::driver::Driver`
// does for a buyer, over browser I/O. The machine, and every rule it and
// its views are judged by, is swap-wasm's; this reads the chains, carries
// the session, keeps the record and carries out what the machine asks.
//
// The swap is funded from the page's wallet (wallet.js), as eigenwallet
// funds one from its internal wallet: the offer is taken once the wallet's
// spendable balance pays for the lock, and the refund pays the wallet back.
// Each record is saved before anything it asks for is sent or broadcast,
// as the native driver saves its swap file. There is no watchtower: the
// buyer opens the page again within the deadlines `status()` shows, as
// eigenwallet asks its user to resume a swap before its timelocks.

import { call, safe, wasm } from './wasm.js';
import { bitcoinView, checkNexus, nexusView } from './views.js';
import { Session } from './relay.js';
import { ended, swapKey } from './wallet.js';

/** About ten minutes a Bitcoin block. */
const BLOCK_MS = 600_000;

/** The variant a state is in: what the native driver times a quiet
 * counterparty by. */
const kind = (state) => Object.keys(JSON.parse(state))[0];

/** `status().step` for each of the machine's phases. */
const STEPS = {
  swapping: 'swapping',
  finishing: 'finishing',
  refunding: 'refunding',
  refunded: 'refunded',
  swapped: 'done',
  punished: 'done',
  drained: 'done',
  aborted: 'done',
};

export class Buyer extends EventTarget {
  #wallet;
  #c;
  #r;
  #session = null;
  #inbox = [];
  #since;
  #kind;
  #view = null;
  #tip = null;
  #firstSeen = null;
  #balance = null;
  #need = null;
  #nexusDepth = null;
  #warning = null;
  #status = '';
  #wake = null;

  constructor(wallet, record) {
    super();
    this.#wallet = wallet;
    this.#c = wallet.config;
    this.#r = record;
    this.#kind = kind(record.state);
    this.#since = this.#c.now();
  }

  /** A swap of `offer`, an offer's text from a relay's board, that the
   * buyer agreed to by `policy` (`swap::offer::Policy`: the amounts, and
   * any bound to hold other than the CLI's), funded from `wallet`: its
   * record saved, nothing sent. The NEX goes to `nexAddress`, and a refund
   * to the wallet. Refuses the offer as the CLI's `take` would, and while
   * another swap runs. A swap prepared before that never took its offer is
   * dropped: nothing was sent for it. */
  static async prepare(wallet, { offer, policy, nexAddress }) {
    const decoded = call('decodeOffer', offer);
    if (!safe(decoded) || !safe(policy)) throw new Error('refused: an amount JavaScript cannot hold exactly');
    if (!decoded.relay) throw new Error('refused: the offer names no relay to reach the seller through');
    if (!wasm.isCid(nexAddress)) throw new Error(`${nexAddress} is not a Nexus address`);
    const running = await wallet.running();
    if (running !== null) throw new Error(`refused: swap ${running} is running; one swap at a time`);
    await checkNexus(wallet.nexus, wallet.config.nexusGenesis);
    const refused = await refusal(wallet, decoded, policy);
    if (refused !== null) throw new Error(refused);
    const { store } = wallet.config;
    for (const id of await wallet.swaps()) {
      if (!(await store.get(swapKey(id))).taken) await store.delete(swapKey(id));
    }
    const started = call('startBuyer', JSON.stringify(decoded.terms), wallet.key.script_pubkey, nexAddress);
    const record = {
      swap_id: decoded.terms.swap_id,
      offer: decoded,
      policy,
      state: JSON.stringify(started.state),
      // The hello, sent once the offer is taken.
      pending: started.actions,
      taken: false,
    };
    await store.put(swapKey(record.swap_id), record);
    return new Buyer(wallet, record);
  }

  /** The swap `swapId` in the wallet's store, carried on from where it
   * stopped. Its session, if it had one, is gone: the swap goes on from
   * the chains, as after `lattice-swap resume`. */
  static async resume(wallet, swapId) {
    const record = await wallet.config.store.get(swapKey(swapId));
    if (!record) throw new Error(`no swap ${swapId} in the store`);
    await checkNexus(wallet.nexus, wallet.config.nexusGenesis);
    return new Buyer(wallet, record);
  }

  get swapId() {
    return this.#r.swap_id;
  }

  /** Where the swap is, for a page to show:
   * - `step`: `fund-wallet` until the wallet can fund the lock and the
   *   offer is taken, then `swapping`, `finishing` once the redeem is
   *   signed, and `done`; or `refunding` and `refunded`;
   * - `outcome`: once ended, the machine's: `swapped`, `refunded`,
   *   `punished`, `drained` or `aborted`;
   * - `wallet`: `{address, confirmed, unconfirmed}`, in sat, and `need`,
   *   in `fund-wallet`, the spendable balance the lock needs;
   * - `confirmations`: `{funding, lockSpend, cancelSpend, nexLock}`, as
   *   last seen, null where unseen;
   * - `deadlines`: once the lock is in a block, `cancel`, the first block
   *   cancel can be in, and `punish`, the first the seller's punish can be
   *   in (the earliest it could be, until cancel is in a block), each
   *   `{height, eta}`, `eta` in ms since the epoch; and `refund`, `{from,
   *   until}`, the heights between which the page must be open once for
   *   the refund to be in a block before the punish. A page shows them as
   *   eigenwallet does: "open this page once between X and Y";
   * - `mustStayOpen`: the redeem is signed and the swap not yet settled
   *   (`Buyer::must_stay_open`);
   * - `tip`, and `warning`, the last failure, if any. */
  status() {
    const r = this.#r;
    const machine = call('buyerStatus', r.state, this.#view);
    const status = {
      swapId: r.swap_id,
      step: r.taken ? STEPS[machine.phase] : 'fund-wallet',
      outcome: ended(r.state) ? machine.phase : null,
      wallet: { address: this.#wallet.address, ...(this.#balance ?? { confirmed: null, unconfirmed: null }) },
      need: r.taken ? null : this.#need,
      confirmations: {
        funding: machine.confirmations.funding,
        lockSpend: machine.confirmations.lock_spend,
        cancelSpend: machine.confirmations.cancel_spend,
        nexLock: this.#nexusDepth,
      },
      deadlines: { cancel: null, refund: null, punish: null },
      mustStayOpen: machine.must_stay_open,
      tip: this.#tip,
      warning: this.#warning,
    };
    const { cancel, punish } = machine.deadlines;
    const at = (height) => ({ height, eta: this.#c.now() + Math.max(0, height - (this.#tip ?? height)) * BLOCK_MS });
    if (cancel !== null && !ended(r.state)) {
      status.deadlines = { cancel: at(cancel), refund: { from: cancel, until: punish }, punish: at(punish) };
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
        this.#warning = e.message;
      }
      this.#announce();
      if (done) break;
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
    return ended(this.#r.state) ? this.status().outcome : null;
  }

  /** One round: whether the swap is over. */
  async #round() {
    this.#balance = await this.#wallet.balance();
    if (!this.#r.taken) {
      await this.#take();
      return false;
    }
    for (const message of this.#inbox.splice(0)) await this.#apply({ Message: JSON.parse(message) });
    if (this.#awaits() && this.#c.now() - this.#since > this.#c.messageTimeout) await this.#apply('Timeout');
    await this.#observeBitcoin();
    await this.#observeNexus();
    return ended(this.#r.state);
  }

  #awaits() {
    return call('buyerStatus', this.#r.state, null).awaits_message;
  }

  /** Takes the offer once the wallet's spendable balance pays for the
   * lock: judged again first, as the CLI's `take` judges it just before it
   * dials, at today's fees. */
  async #take() {
    const r = this.#r;
    const amount = r.offer.terms.btc_amount;
    const fee_rate = await this.#wallet.feeRate();
    const { enough, need } = call('walletNeed', { utxos: await this.#wallet.spendable(), amount, fee_rate });
    this.#need = need;
    if (!enough) return;
    const refused = await refusal(this.#wallet, r.offer, r.policy);
    if (refused !== null) throw new Error(refused);
    const open = this.#c.openSession ?? Session.open;
    this.#session = await open(r.offer, (message) => this.#receive(message), { WebSocket: this.#c.WebSocket });
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

  /** Feeds `event` to the machine, saves what changed, then does what it
   * asks: nothing is sent or broadcast that a restart would not know of. */
  async #apply(event) {
    const stepped = call('stepBuyer', this.#r.state, JSON.stringify(event));
    const next = JSON.stringify(stepped.state);
    if (next !== this.#r.state) {
      this.#r.state = next;
      await this.#save();
    }
    if (kind(next) !== this.#kind) {
      this.#kind = kind(next);
      this.#since = this.#c.now();
    }
    for (const action of stepped.actions) await this.#act(action);
  }

  async #act(action) {
    if (action.Send) {
      if (!this.#session || this.#session.closed) return;
      try {
        this.#session.send(JSON.stringify(action.Send));
      } catch (e) {
        this.#warning = `session ended: ${e.message}`;
        this.#session = null;
        return;
      }
      await this.#apply('Sent');
    } else if (action.FundLock) {
      // Before anything is at stake: a wallet that cannot fund the lock
      // leaves the machine waiting, and the seller's silence aborts it.
      const funded = call('walletFund', {
        wif: this.#wallet.key.wif,
        utxos: await this.#wallet.spendable(),
        script_pubkey: action.FundLock.script_pubkey,
        amount: action.FundLock.amount,
        fee_rate: await this.#wallet.feeRate(),
      });
      await this.#apply({ Funded: funded.tx });
    } else if (action.Broadcast) {
      try {
        await this.#wallet.esplora.broadcast(action.Broadcast);
      } catch (e) {
        // The machine asks again while it is needed.
        this.#warning = `broadcast: ${e.message}`;
      }
    } else if (action.Submit) {
      try {
        await this.#wallet.nexus.submit(wasm.nexusSubmitBody(JSON.stringify(action.Submit)));
      } catch (e) {
        this.#warning = `nexus submit: ${e.message}`;
      }
    }
  }

  async #observeBitcoin() {
    const watch = call('watchBuyer', this.#r.state).bitcoin;
    if (!watch) return;
    const seen = await bitcoinView(this.#wallet.esplora, watch);
    // The tip moved while the view was read: read again next round.
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
  }

  async #observeNexus() {
    const watch = call('watchBuyer', this.#r.state).nexus;
    if (!watch) return;
    const view = await nexusView(this.#wallet.nexus, watch);
    // The tip moved while the view was read: read again next round.
    if (view === null) return;
    this.#nexusDepth = view.watched?.[1] ?? null;
    await this.#apply({ Nexus: view });
  }

  async #save() {
    await this.#c.store.put(swapKey(this.#r.swap_id), this.#r);
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

/** Why the buyer refuses `offer` under `policy`, as the CLI's `take`, at
 * the wallet's Esplora's estimate, or null. */
async function refusal(wallet, offer, policy) {
  const estimate = await wallet.esplora.feeRate(6);
  const minRelayFee = Number((await wallet.nexus.get('/api/chain/info')).minRelayFee);
  const refused = wasm.checkOffer(
    JSON.stringify({
      offer,
      policy,
      network: wallet.config.network,
      nexus_genesis: wallet.config.nexusGenesis,
      fee_estimate: estimate === null ? null : Math.ceil(estimate * 1000),
      min_relay_fee: minRelayFee,
    }),
  );
  return refused ?? null;
}
