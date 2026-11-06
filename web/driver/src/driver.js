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
import { ended, isRunning, swapKey } from './wallet.js';

/** About ten minutes a Bitcoin block. */
const BLOCK_MS = 600_000;

/** The least time between two attempts to meet the seller again, as the
 * CLI's `swap::transport::RETRY`. */
const REJOIN_PAUSE = 5_000;

/** The variant a state is in: what the native driver times a quiet
 * counterparty by. */
const kind = (state) => Object.keys(JSON.parse(state))[0];

/** `status().step` for each of the machine's phases. */
const STEPS = {
  swapping: 'swapping',
  finishing: 'finishing',
  asking: 'asking',
  received: 'received',
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
  /** Why the offer could not be taken, once it cannot. */
  #gone = null;
  #status = '';
  #wake = null;
  /** Whether the Nexus node is known to follow the swap's Nexus, and the
   * Esplora the page's network: `prepare` checks both first; a resumed
   * swap checks each the first round it reads it. */
  #nexusChecked;
  #bitcoinChecked;
  /** When the chains may next be read: a poll after the last round of
   * reads ended, however many messages come in between. */
  #readAt = -Infinity;
  /** A swap that ended: its terms, which its state no longer holds. */
  #doneTerms = null;
  /** Whether {@link Buyer#cancel} dropped the swap before it was taken. */
  #cancelled = false;
  /** The attempt to meet the seller again, while one runs; when the last
   * began; and whether a session it opened has yet to be sent the last
   * message again. */
  #rejoining = null;
  #rejoinedAt = -Infinity;
  #rejoined = false;
  /** Whether {@link Buyer#run} is running, and what aborts a rejoin it
   * leaves in flight once it returns. */
  #running = false;
  #halt = new AbortController();

  constructor(wallet, record, checked) {
    super();
    this.#wallet = wallet;
    this.#c = wallet.config;
    this.#r = record;
    this.#kind = kind(record.state);
    this.#since = this.#c.now();
    this.#nexusChecked = checked;
    this.#bitcoinChecked = checked;
  }

  /** A swap of `offer`, an offer's text from a relay's board, that the
   * buyer agreed to by `policy` (`swap::offer::Policy`: `btc_amount`, in
   * sat, in the offer's range, the `price` agreed to, in sat a NEX of
   * 1,000,000 base units, and any bound to hold other than the CLI's),
   * funded from `wallet`: its record saved, nothing sent. It buys
   * `floor(btc_amount * 1000000 / price)` base units.
   * The NEX goes to `nexAddress`, and a refund to the wallet. Refuses the
   * offer as the CLI's `take` would, and while another swap runs. A swap
   * prepared before that never took its offer is dropped: nothing was sent
   * for it.
   * @returns {Promise<Buyer>} */
  static async prepare(wallet, { offer, policy, nexAddress }) {
    const decoded = call('decodeOffer', offer);
    if (!safe(decoded) || !safe(policy)) throw new Error('refused: an amount JavaScript cannot hold exactly');
    if (!decoded.relay) throw new Error('refused: the offer names no relay to reach the seller through');
    if (!wasm.isCid(nexAddress)) throw new Error(`${nexAddress} is not a Nexus address`);
    return wallet.exclusive(async () => {
      const running = await wallet.running();
      if (running !== null) throw new Error(`refused: swap ${running} is running; one swap at a time`);
      await wallet.check();
      const refused = await refusal(wallet, decoded, policy);
      if (refused !== null) throw new Error(refused);
      const { store } = wallet.config;
      for (const id of await wallet.swaps()) {
        if (!(await store.get(swapKey(id))).taken) await store.delete(swapKey(id));
      }
      const terms = call('offerTerms', { offer: decoded, btc_amount: policy.btc_amount });
      const started = call('startBuyer', JSON.stringify(terms), wallet.key.script_pubkey, nexAddress);
      const record = {
        swap_id: decoded.template.swap_id,
        offer: decoded,
        policy,
        state: JSON.stringify(started.state),
        // The hello, sent once the seller has answered with these terms.
        pending: started.actions,
        taken: false,
        // Where the NEX goes, for `status()`.
        nex_address: nexAddress,
      };
      await store.put(swapKey(record.swap_id), record);
      return new Buyer(wallet, record, true);
    });
  }

  /** The swap `swapId` in the wallet's store, carried on from where it
   * stopped. Its session, if it had one, is gone: the swap goes on from
   * the chains and, while it needs one, a new session to the seller, as
   * after `lattice-swap resume`. Reads no backend: the
   * Nexus node is checked by `run`, the first round it is needed, and a
   * failed check is a round's warning, retried the next, as eigenwallet
   * resumes a swap and retries its backends. A refunding swap watches no
   * Nexus, and never waits on one. A punished swap asks the seller for
   * `s` once again (`Buyer::resumed`), as eigenwallet asks its ASB to
   * redeem cooperatively on every resume, and claims the NEX with it.
   * @returns {Promise<Buyer>} */
  static async resume(wallet, swapId) {
    const record = await wallet.config.store.get(swapKey(swapId));
    if (!record) throw new Error(`no swap ${swapId} in the store`);
    const resumed = JSON.stringify(call('resumeBuyer', record.state));
    if (resumed !== record.state) {
      record.state = resumed;
      await wallet.config.store.put(swapKey(swapId), record);
    }
    return new Buyer(wallet, record, false);
  }

  /** @returns {string} */
  get swapId() {
    return this.#r.swap_id;
  }

  /** Where the swap is, for a page to show:
   * - `step`: `fund-wallet` until the wallet can fund the lock and the
   *   offer is taken, then `swapping`, `finishing` once the redeem is
   *   signed, `received` once the claim is in a block, and `done` once
   *   it is `nex_confirmations` deep; or `refunding` and `refunded`; or
   *   `asking`, punished and resumed, while it asks the seller for `s`,
   *   then `finishing` once given it; or `offer-gone`
   *   if the session to the seller would not open, or the seller refused
   *   the amount or answered other terms, as the CLI's `take` fails once:
   *   nothing of the swap was sent, and the buyer picks another offer; or
   *   `cancelled`, once {@link Buyer#cancel} dropped it untaken;
   * - `outcome`: once ended, the machine's: `swapped`, `refunded`,
   *   `punished`, `drained` or `aborted`;
   * - `wallet`: `{address, confirmed, unconfirmed}`, in sat, and `need`,
   *   in `fund-wallet`, the spendable balance the lock needs;
   * - `confirmations`: `{funding, lockSpend, cancelSpend, nexLock}`, as
   *   last seen, null where unseen; `nexLock` is the watched Nexus
   *   transaction's depth: the NEX lock's, then, once claiming, the
   *   claim's, from the state while `received`, so a resumed page shows
   *   it before its first Nexus round;
   * - `deadlines`: once the lock is in a block, `cancel`, the first block
   *   cancel can be in, and `punish`, the first the seller's punish can be
   *   in (the earliest it could be, until cancel is in a block), each
   *   `{height, eta}`, `eta` in ms since the epoch; and `refund`, `{from,
   *   until}`: the first block the refund can be in, once cancel is deep
   *   enough (the earliest, until cancel is in a block), and the punish's,
   *   which it must come before. Cancel and refund run as one flow, as
   *   eigenwallet's `cancel-and-refund`: a page shows "come back by
   *   <cancel> and keep the page open until your refund confirms";
   * - `mustStayOpen`: the redeem is signed and the swap not yet settled
   *   (`Buyer::must_stay_open`), or cancel is due and the refund not yet
   *   confirmed;
   * - `backupCovers`: what a recovery file taken now covers: `wallet`, or
   *   `lock` once the funding may be broadcast, from when a page asks the
   *   buyer to download it, as Boltz asks for its refund file;
   * - `running`: the swap has taken its offer and not ended, as
   *   {@link Wallet#running} judges it: while it does, no other swap is
   *   prepared and the wallet withdraws nothing;
   * - `btc_amount`, in sat, `price`, in sat a NEX of 1,000,000 base units,
   *   and `nex_amount`, in base units: the swap's terms, read from its
   *   state as the CLI reads them, and once it ends, from the offer at the
   *   policy's amount, the only terms `#request` accepts;
   *   `btc_confirmations` and `nex_confirmations`, how deep each lock must
   *   be, for "1 of N";
   * - `nexAddress`, where the NEX goes (null for a swap prepared before
   *   it was recorded);
   * - `tip`, and `warning`, the last failure, if any.
   * @returns {object} */
  status() {
    const r = this.#r;
    const machine = call('buyerStatus', r.state, this.#view);
    if (machine.terms === null) this.#doneTerms ??= call('offerTerms', { offer: r.offer, btc_amount: r.policy.btc_amount });
    const terms = machine.terms ?? this.#doneTerms;
    const status = {
      swapId: r.swap_id,
      step: this.#cancelled ? 'cancelled' : this.#gone !== null ? 'offer-gone' : r.taken ? STEPS[machine.phase] : 'fund-wallet',
      outcome: ended(r.state) ? machine.phase : null,
      wallet: { address: this.#wallet.address, ...(this.#balance ?? { confirmed: null, unconfirmed: null }) },
      need: r.taken ? null : this.#need,
      confirmations: {
        funding: machine.confirmations.funding,
        lockSpend: machine.confirmations.lock_spend,
        cancelSpend: machine.confirmations.cancel_spend,
        nexLock: machine.confirmations.claim ?? this.#nexusDepth,
      },
      deadlines: { cancel: null, refund: null, punish: null },
      mustStayOpen: machine.must_stay_open || machine.phase === 'refunding',
      backupCovers: machine.backup_covers,
      running: isRunning(r),
      btc_amount: terms.btc_amount,
      price: r.policy.price,
      nex_amount: terms.nex_amount,
      btc_confirmations: terms.btc_confirmations,
      nex_confirmations: terms.nex_confirmations,
      nexAddress: r.nex_address ?? null,
      tip: this.#tip,
      warning: this.#gone ?? this.#warning,
    };
    const { cancel, refund, punish } = machine.deadlines;
    const at = (height) => ({ height, eta: this.#c.now() + Math.max(0, height - (this.#tip ?? height)) * BLOCK_MS });
    if (cancel !== null && !ended(r.state)) {
      status.deadlines = { cancel: at(cancel), refund: { from: refund, until: punish }, punish: at(punish) };
    }
    return status;
  }

  /** Cancels the swap while it has not taken its offer, as eigenwallet's
   * GUI lets its user cancel while it waits for the Bitcoin deposit, before
   * the swap is set up: its record dropped, as `prepare` drops an untaken
   * one, and {@link Buyer#run} returns null, `status().step` `cancelled`.
   * Under the swap lock, which `#take` holds from before it dials until
   * the swap is saved as taken, so it comes either before the take, which
   * then never dials, or after it, and refuses. Nothing is at stake while
   * untaken: the only message sent before then is the request, under that
   * lock, and a declined one drops the record itself; the hello, the lock's
   * funding and every broadcast and Nexus submit are the machine's actions,
   * carried out only once taken. Refuses a swap that has taken its offer,
   * which runs on to its end or its refund.
   * @returns {Promise<void>} */
  async cancel() {
    const r = this.#r;
    const key = swapKey(r.swap_id);
    await this.#wallet.exclusive(async () => {
      const held = await this.#c.store.get(key);
      if (r.taken || held?.taken) throw new Error(`refused: swap ${r.swap_id} has taken its offer; it runs on to its end or its refund`);
      // Only this swap's record: a later `prepare` of the same offer may
      // hold the id, and it is that swap's to cancel.
      if (held?.state === r.state) await this.#c.store.delete(key);
      this.#cancelled = true;
    });
    this.#wake?.();
    this.#announce();
  }

  /** Runs the swap until it ends, its offer is gone, it is cancelled, or
   * `signal` aborts: the outcome, once it ends. A `status` event follows
   * every change of {@link Buyer#status}. A failed round, a backend's or
   * the Nexus check's, is the status's `warning`, and the next round tries
   * again. Refuses while a run of this Buyer is running already.
   * @returns {Promise<string | null>} */
  async run(signal) {
    if (this.#running) throw new Error('refused: this swap is running already');
    this.#running = true;
    this.#halt = new AbortController();
    try {
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
          const timer = setTimeout(resolve, Math.max(0, this.#readAt - this.#c.now()));
          this.#wake = () => {
            clearTimeout(timer);
            resolve();
          };
          signal?.addEventListener('abort', this.#wake, { once: true });
        });
        this.#wake = null;
      }
    } finally {
      this.#running = false;
      this.#halt.abort();
      this.#session?.close();
    }
    return ended(this.#r.state) ? this.status().outcome : null;
  }

  /** One round: whether the swap is over, its offer gone, or it is
   * cancelled. The messages are taken as they come, and the chains read
   * only once a poll has passed since the last reads ended, as the native
   * driver's `run_until`: however many messages the seller sends, the
   * backends are read no more often, so it cannot spend their rate
   * limits. */
  async #round() {
    if (this.#cancelled) return true;
    if (this.#r.taken) {
      await this.#rejoin();
      for (const message of this.#inbox.splice(0)) await this.#apply({ Message: JSON.parse(message) });
      if (this.#awaits() && this.#c.now() - this.#since > this.#c.messageTimeout) await this.#apply('Timeout');
    }
    if (this.#c.now() < this.#readAt) return ended(this.#r.state);
    try {
      if (!this.#r.taken) {
        this.#balance = await this.#wallet.balance();
        await this.#take();
        return this.#gone !== null || this.#cancelled;
      }
      await this.#observeBitcoin();
      await this.#observeNexus();
      // Last: the balance is shown, and a failed read of it skips nothing.
      this.#balance = await this.#wallet.balance();
      return ended(this.#r.state);
    } finally {
      this.#readAt = this.#c.now() + this.#c.poll;
    }
  }

  /** While the swap needs its session and has none, meets the seller
   * again at the offer's relay (`Buyer::rejoin`), as the CLI does: in the
   * background, one attempt at a time, the next at least
   * {@link REJOIN_PAUSE} after the last began, so the rounds go on reading
   * the chains meanwhile. A session it opened is first sent the last
   * message again, which the seller ignores if it has it. */
  async #rejoin() {
    if (this.#rejoined) {
      this.#rejoined = false;
      const resend = call('buyerResend', this.#r.state);
      if (resend) await this.#act({ Send: resend });
    }
    if (this.#rejoining || (this.#session && !this.#session.closed)) return;
    if (this.#c.now() - this.#rejoinedAt < REJOIN_PAUSE) return;
    const rejoin = call('buyerRejoin', this.#r.state);
    if (rejoin === null) return;
    this.#rejoinedAt = this.#c.now();
    const open = this.#c.openSession ?? Session.open;
    const options = { WebSocket: this.#c.WebSocket, rejoin, signal: this.#halt.signal };
    this.#rejoining = open(this.#r.offer, (message) => this.#receive(message), options)
      .then(
        (session) => {
          if (!this.#running) return session.close();
          this.#session = session;
          this.#rejoined = true;
        },
        () => {},
      )
      .finally(() => {
        this.#rejoining = null;
        this.#wake?.();
      });
  }

  #awaits() {
    return call('buyerStatus', this.#r.state, null).awaits_message;
  }

  /** Takes the offer once the wallet's spendable balance pays for the
   * lock: judged again first, as the CLI's `take` judges it just before it
   * dials, at today's fees. Under the wallet's lock until it is saved as
   * taken, so nothing else spends the outputs it counted. */
  async #take() {
    const r = this.#r;
    const taken = await this.#wallet.exclusive(async () => {
      // Cancelled while this waited for the lock: never dialed.
      if (this.#cancelled) return false;
      const running = await this.#wallet.running();
      if (running !== null) throw new Error(`refused: swap ${running} is running; one swap at a time`);
      // Only while the store still holds this record, which a later
      // `prepare` drops: checked before acting, as an HTTP `If-Match`
      // refuses a write to what changed since it was read.
      if ((await this.#c.store.get(swapKey(r.swap_id)))?.state !== r.state) {
        this.#gone = 'refused: this swap was dropped when another was prepared';
        return false;
      }
      const { enough, need } = await this.#wallet.need(r.policy.btc_amount);
      this.#need = need;
      if (!enough) return false;
      await this.#checkBitcoin();
      await this.#checkNexus();
      const refused = await refusal(this.#wallet, r.offer, r.policy);
      if (refused !== null) throw new Error(refused);
      const open = this.#c.openSession ?? Session.open;
      try {
        this.#session = await open(r.offer, (message) => this.#receive(message), { WebSocket: this.#c.WebSocket });
      } catch (e) {
        // Once, as the CLI's `take` fails: the relay no longer pairs with
        // the seller, whose offer is taken or withdrawn. Nothing was sent.
        this.#gone = `the offer is gone: ${e.message}`;
        await this.#c.store.delete(swapKey(r.swap_id));
        return false;
      }
      // The amount asked for, as the CLI's `take` asks: the seller fixes
      // the terms, which must be the ones the machine started on. Refused,
      // or unanswered, the offer is given up as one whose session would not
      // open: nothing of the swap was sent.
      const declined = await this.#request();
      if (declined !== null) {
        this.#gone = declined;
        this.#session.close();
        await this.#c.store.delete(swapKey(r.swap_id));
        return false;
      }
      r.taken = true;
      await this.#save();
      return true;
    });
    if (!taken) return;
    this.#since = this.#c.now();
    const pending = r.pending;
    r.pending = [];
    for (const action of pending) await this.#act(action);
  }

  /** Sends the request for the policy's amount at its price, and waits up
   * to `messageTimeout` for the seller's answer, the first message back:
   * why the buyer refuses it, or null. */
  async #request() {
    const { offer, policy } = this.#r;
    const { btc_amount, price } = policy;
    try {
      this.#session.send(JSON.stringify({ Request: { btc_amount, price } }));
    } catch (e) {
      return `the offer is gone: ${e.message}`;
    }
    const end = this.#c.now() + this.#c.messageTimeout;
    while (this.#inbox.length === 0) {
      if (this.#session.closed) return 'the offer is gone: the session ended';
      if (this.#c.now() > end) return 'the offer is gone: the seller sent no answer';
      await new Promise((resolve) => {
        this.#wake = resolve;
        setTimeout(resolve, Math.min(this.#c.poll, 100));
      });
      this.#wake = null;
    }
    const answer = JSON.parse(this.#inbox.shift()).Answer;
    if (answer === undefined) return 'refused: the seller sent no answer';
    return wasm.checkAnswer(JSON.stringify({ offer, policy, answer })) ?? null;
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
        await this.#checkNexus();
        await this.#wallet.nexus.submit(wasm.nexusSubmitBody(JSON.stringify(action.Submit)));
      } catch (e) {
        this.#warning = `nexus submit: ${e.message}`;
      }
    }
  }

  async #observeBitcoin() {
    const watch = call('watchBuyer', this.#r.state).bitcoin;
    if (!watch) return;
    await this.#checkBitcoin();
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
    await this.#checkNexus();
    const view = await nexusView(this.#wallet.nexus, watch);
    // The tip moved while the view was read: read again next round.
    if (view === null) return;
    this.#nexusDepth = view.watched?.[1] ?? null;
    await this.#apply({ Nexus: view });
  }

  /** Refuses a node on another Nexus, once per Buyer: a resumed swap's
   * first use of it, as `prepare` checks it before anything else. A swap
   * whose terms name another Nexus than the page's is refused first, as
   * the CLI's `resume` refuses one: the node is checked against the
   * page's. Throws into the round, as any failed read does. */
  async #checkNexus() {
    if (this.#nexusChecked) return;
    const genesis = call('buyerStatus', this.#r.state, null).terms?.nexus_genesis;
    const page = this.#c.nexusGenesis;
    if (genesis !== undefined && genesis !== page) {
      throw new Error(`refused: swap ${this.#r.swap_id} trades on the Nexus of genesis ${genesis}, not ${page}, the one nexusGenesis names`);
    }
    await checkNexus(this.#wallet.nexus, page);
    this.#nexusChecked = true;
  }

  /** Refuses an Esplora on another network than the page's, once per
   * Buyer: a resumed swap's first use of it, as `prepare` checks it before
   * anything else. Throws into the round, as any failed read does. */
  async #checkBitcoin() {
    if (this.#bitcoinChecked) return;
    await this.#wallet.esplora.checkNetwork(this.#c.network);
    this.#bitcoinChecked = true;
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
