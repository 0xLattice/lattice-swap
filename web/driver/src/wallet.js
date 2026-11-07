// The page's own Bitcoin wallet, as eigenwallet keeps an internal one: a
// key made in wasm and kept in the store, whose address the buyer deposits
// to. A swap funds its lock from the balance, its change and its refund
// come back here, and `withdraw` sends the balance to any address.
//
// Each chain is read from one backend, trusted for what it shows, as
// eigenwallet trusts its Electrum server and Monero node: an Esplora for
// Bitcoin, mempool.space's by default, and a Nexus node's public read port.
// A buyer that trusts neither sets its own.

import { call, wasm } from './wasm.js';
import { Esplora } from './esplora.js';
import { checkNexus, Nexus } from './views.js';
import { IndexedDBStore } from './store.js';

/** The default Esplora for each network: mempool.space's. Regtest has
 * none. */
export const ESPLORA = {
  bitcoin: 'https://mempool.space/api',
  testnet: 'https://mempool.space/testnet/api',
  signet: 'https://mempool.space/signet/api',
};

/** The CLI's own settings, where it has one. */
export const DEFAULTS = {
  /** Where the wallet key and each swap's record are kept, with `get`,
   * `put`, `add` (put if absent), `delete` and `keys`: an `IndexedDBStore`
   * unless given. */
  store: undefined,
  /** The page's `navigator.locks`, which keeps it the one page driving the
   * store; null where nothing else can drive it, as in Node. */
  locks: undefined,
  /** Called once if another tab holds the store: the page shows "open in
   * another tab", and goes on once that tab closes. */
  onWaiting: undefined,
  /** Called once this page holds the store's Web Lock, whether or not it
   * waited: `onWaiting`'s counterpart, when the page stops showing "open
   * in another tab". The Web Locks API marks the same moment by calling a
   * request's callback with the lock granted. Not called where `locks` is
   * null, with no lock to hold. */
  onAcquired: undefined,
  network: 'bitcoin',
  /** The Esplora API; by default `ESPLORA[network]`. */
  esplora: undefined,
  nexus: 'https://lattice-mainnet-read.fly.dev',
  nexusGenesis: 'bafyreiggtg4ezifboyekbf4gxst2jr3mpjqcxsbmopy7w6fp46g4ngpgxa',
  /** Between two rounds of reads, in ms. */
  poll: 10_000,
  /** How long the seller may stay quiet before anything is at stake, as
   * the native driver's `message_timeout`. */
  messageTimeout: 60_000,
  /** The oldest a Bitcoin tip may be, in seconds, for a view not to be
   * stale: the CLI's `--max-tip-age`. */
  maxTipAge: 90 * 60,
  fetch: undefined,
  WebSocket: undefined,
  /** Opens the session to the seller, as `Session.open`; tests stand a
   * seller in. */
  openSession: undefined,
  now: () => Date.now(),
};

/** The blocks a fee estimate aims to confirm in, as the CLI's. */
const FEE_TARGET = 6;
/** Bitcoin Core's default relay floor, in sat/vB. */
const MIN_RELAY = 1;

/** The record key of the wallet, and of swap `id`. */
const WALLET = 'wallet';
export const swapKey = (id) => `swap:${id}`;

/** A recovery file's format. */
const FORMAT = 'lattice-swap-wallet';

/** The Web Lock a page holds while it drives the store. */
const INSTANCE = 'lattice-swap';
const instances = new WeakMap();

/** Resolves once this page is the one driving the store, as eigenwallet
 * runs one instance (`tauri-plugin-single-instance`): the page holds the
 * exclusive Web Lock `lattice-swap` from then until it closes. If another
 * tab holds it, `onWaiting` is called and this page waits for that tab to
 * close; it reads the store only once it holds the lock. */
function single(locks = globalThis.navigator?.locks, onWaiting = undefined, onAcquired = undefined) {
  if (locks === null) return Promise.resolve();
  if (locks === undefined) throw new Error('refused: this browser has no Web Locks, to keep one tab on the swap');
  if (!instances.has(locks)) {
    const instance = new Promise((resolve, reject) => {
      const hold = () => {
        onAcquired?.();
        resolve();
        return new Promise(() => {});
      };
      locks
        .request(INSTANCE, { ifAvailable: true }, (lock) => {
          if (lock) return hold();
          onWaiting?.();
          locks.request(INSTANCE, hold).catch(reject);
        })
        .catch(reject);
    });
    instances.set(locks, instance);
    // A refusal is not kept, so the page can ask again, as Node's
    // `require` drops a module from its cache when loading it throws.
    instance.catch(() => instances.delete(locks));
  }
  return instances.get(locks);
}

/** The swap lock: one for the page, not one per `Wallet`, as eigenwallet
 * keeps one `SwapLock` per `Context` and Bitcoin Core's `loadwallet` refuses
 * a wallet already loaded. Two `Wallet`s of one store in a tab, from two
 * `open`s or an `open` and a `restore`, wait on the same lock; the page is
 * the one instance driving the store, so one lock for it is one per store. */
let swapLock = Promise.resolve();

/** Runs `act` once the swap lock is free, holding it until `act` settles:
 * {@link Wallet#exclusive}, which `restore` takes too. */
function exclusively(act) {
  const run = swapLock.then(act);
  swapLock = run.catch(() => {});
  return run;
}

/** Whether a swap's record has taken its offer and not ended: what
 * {@link Wallet#running} looks for, one swap at a time. */
export function isRunning(record) {
  return record.taken && !ended(record.state);
}

export class Wallet {
  /** Whether `config.store` holds a wallet, no key made: a page opens
   * one only when it does, or when the buyer starts, as
   * Bitcoin Core's `listwallets` names wallets without `createwallet`.
   * Read without the Web Lock, and safe so: the key is only ever added
   * where none is (`add`) and never written over or deleted, so another
   * tab can only have made it since, and `open` then reads that one. A
   * store made here, with none given, is closed once read.
   * @returns {Promise<boolean>} */
  static async exists(config) {
    const store = config.store ?? new IndexedDBStore();
    try {
      return (await store.get(WALLET)) !== null;
    } finally {
      if (!config.store) (await store.database).close();
    }
  }

  /** The wallet in `config.store`, made and saved first if there is none.
   * Resolves once this page holds the store (see `onAcquired`).
   * @returns {Promise<Wallet>} */
  static async open(config) {
    const c = { ...DEFAULTS, ...config };
    c.store ??= new IndexedDBStore();
    c.fetch ??= (...args) => globalThis.fetch(...args);
    c.WebSocket ??= globalThis.WebSocket;
    c.esplora ??= ESPLORA[c.network];
    if (!c.esplora) throw new Error(`no default Esplora for ${c.network}: give one`);
    await single(c.locks, c.onWaiting, c.onAcquired);
    let key = await c.store.get(WALLET);
    if (key === null) {
      // Written only where none is, and read back, as Bitcoin Core's
      // `createwallet` refuses to overwrite a wallet.
      await c.store.add(WALLET, call('newBitcoinKey', c.network));
      key = await c.store.get(WALLET);
    }
    return new Wallet(c, call('bitcoinKeyOf', key.wif, c.network));
  }

  constructor(config, key) {
    this.config = config;
    this.key = key;
    this.esplora = new Esplora(config.esplora, config.fetch);
    this.nexus = new Nexus(config.nexus, config.fetch);
  }

  /** Where the buyer deposits.
   * @returns {string} */
  get address() {
    return this.key.address;
  }

  /** Refuses backends a swap cannot rely on, as the CLI checks its nodes
   * before a swap: an Esplora on another network than `network`, and a
   * Nexus node that takes no transactions, follows another Nexus than
   * `nexusGenesis`, or keeps no state of past blocks. Its error, starting
   * `refused:`, says which, for a page to show where its backends are set.
   * @returns {Promise<void>} */
  async check() {
    await this.esplora.checkNetwork(this.config.network);
    await checkNexus(this.nexus, this.config.nexusGenesis);
  }

  /** The outputs the wallet holds: those in a block are spendable, as
   * Bitcoin Core spends none it received still unconfirmed.
   * @returns {Promise<{txid: string, vout: number, value: number}[]>} */
  async spendable() {
    const utxos = await this.esplora.utxos(this.address);
    return utxos.filter((utxo) => utxo.height !== null).map(({ txid, vout, value }) => ({ txid, vout, value }));
  }

  /** `{confirmed, unconfirmed}`, in sat: what the wallet can spend, and
   * what is on its way to it.
   * @returns {Promise<{confirmed: number, unconfirmed: number}>} */
  async balance() {
    const utxos = await this.esplora.utxos(this.address);
    const sum = (confirmed) =>
      utxos.filter((utxo) => (utxo.height !== null) === confirmed).reduce((sum, utxo) => sum + utxo.value, 0);
    return { confirmed: sum(true), unconfirmed: sum(false) };
  }

  /** The Esplora's estimate for the CLI's target, in whole sat/vB, never
   * below the relay floor, which is also the rate where it has none, as on
   * regtest: how Electrum and eigenwallet price their own spends.
   * @returns {Promise<number>} */
  async feeRate() {
    const estimate = await this.esplora.feeRate(FEE_TARGET);
    return Math.max(MIN_RELAY, Math.ceil(estimate ?? MIN_RELAY));
  }

  /** `{enough, need}`: whether the spendable balance funds a swap of
   * `btcAmount` sat at today's fee rate, and the balance a funding with
   * change needs, in sat: what a swap's `status().need` shows before it
   * takes its offer, and what a page shows for an amount before preparing
   * one. Only the amount counts: the lock is that output, and the offer's
   * swap fees are paid out of it.
   * @returns {Promise<{enough: boolean, need: number}>} */
  async need(btcAmount) {
    const utxos = await this.spendable();
    return call('walletNeed', { utxos, amount: btcAmount, fee_rate: await this.feeRate() });
  }

  /** The swap ids in the store.
   * @returns {Promise<string[]>} */
  async swaps() {
    return (await this.config.store.keys()).filter((key) => key.startsWith('swap:')).map((key) => key.slice(5));
  }

  /** The swap that has taken its offer and not ended, if any: eigenwallet
   * runs one swap at a time.
   * @returns {Promise<string | null>} */
  async running() {
    for (const id of await this.swaps()) {
      if (isRunning(await this.config.store.get(swapKey(id)))) return id;
    }
    return null;
  }

  /** Runs `act` with the wallet's outputs to itself, as eigenwallet's
   * `SwapLock` is held from a swap's start: a withdrawal, a swap prepared,
   * or one taking its offer, until it is saved as taken, each waits for
   * the one before. `act`'s answer, or its failure.
   * @template T
   * @param {() => T | Promise<T>} act
   * @returns {Promise<T>} */
  exclusive(act) {
    return exclusively(act);
  }

  /** Sends the whole spendable balance to `address`, less its fee: the
   * txid. Not while a swap runs, whose funding spends the same outputs.
   * @returns {Promise<string>} */
  withdraw(address) {
    return this.exclusive(async () => {
      const running = await this.running();
      if (running !== null) throw new Error(`refused: swap ${running} is running, and funds from this wallet`);
      const script = wasm.scriptOf(address, this.config.network);
      const utxos = await this.spendable();
      if (utxos.length === 0) throw new Error('refused: the wallet holds nothing spendable');
      const { tx, txid } = call('walletSweep', {
        wif: this.key.wif,
        utxos,
        script_pubkey: script,
        fee_rate: await this.feeRate(),
      });
      await this.esplora.broadcast(tx);
      return txid;
    });
  }

  /** The recovery file, `{name, file}`, as Boltz has its buyer download
   * one: the wallet key and every swap not yet ended, as each stands now.
   * {@link Wallet.restore} reads it.
   * @returns {Promise<{name: string, file: string}>} */
  async backup() {
    const swaps = [];
    for (const id of await this.swaps()) {
      const record = await this.config.store.get(swapKey(id));
      if (ended(record.state)) continue;
      const { version } = JSON.parse(call('backup', record.state).file);
      swaps.push({ ...record, version, state: JSON.parse(record.state) });
    }
    const file = { format: FORMAT, network: this.config.network, wallet: this.key.wif, swaps };
    return { name: `lattice-swap-${this.address}.json`, file: JSON.stringify(file) };
  }

  /** The wallet in a recovery `file` from {@link Wallet#backup}, put in
   * `config.store` with its swaps, but those the store holds already.
   * Refuses a store that holds another wallet, whose key it would lose,
   * and a file whose unfinished swap would run beside another the store
   * runs: one swap at a time, as eigenwallet's `SwapLock` refuses a second.
   * @returns {Promise<Wallet>} */
  static async restore(config, file) {
    const c = { ...DEFAULTS, ...config };
    c.store ??= new IndexedDBStore();
    const backup = JSON.parse(file);
    if (backup.format !== FORMAT) throw new Error('not a recovery file');
    if (backup.network !== c.network) throw new Error(`the file is for ${backup.network}, not ${c.network}`);
    const key = call('bitcoinKeyOf', backup.wallet, c.network);
    await single(c.locks, c.onWaiting, c.onAcquired);
    const held = await c.store.get(WALLET);
    if (held !== null && held.wif !== key.wif) throw new Error('refused: the store holds another wallet');
    const records = backup.swaps.map(({ version, state, ...record }) => {
      // The state version and side checked as the CLI's `resume` checks them.
      const restored = call('restore', JSON.stringify({ version, state }));
      if (restored.side !== 'buyer') throw new Error('not a buyer’s swap');
      return { ...record, state: JSON.stringify(restored.state) };
    });
    // Under the swap lock, as a swap taking its offer is: what runs is
    // read and added to at once.
    await exclusively(async () => {
      // A swap the store holds is as far on as the file's, or further;
      // one it holds untaken that the file holds taken is not, and is
      // refused, as another wallet's key is.
      const added = [];
      for (const record of records) {
        const held = await c.store.get(swapKey(record.swap_id));
        if (held === null) added.push(record);
        else if (!held.taken && record.taken) {
          throw new Error(`refused: the store holds swap ${record.swap_id} untaken, and the file holds it taken`);
        }
      }
      const ids = (await c.store.keys()).filter((id) => id.startsWith('swap:'));
      const runs = [];
      for (const id of ids) if (isRunning(await c.store.get(id))) runs.push(id.slice(5));
      for (const record of added) if (isRunning(record)) runs.push(record.swap_id);
      if (runs.length > 1) throw new Error(`refused: swaps ${runs.join(' and ')} would both run; one swap at a time`);
      // Never over another wallet, as `open` makes one.
      await c.store.add(WALLET, key);
      if ((await c.store.get(WALLET)).wif !== key.wif) throw new Error('refused: the store holds another wallet');
      for (const record of added) await c.store.put(swapKey(record.swap_id), record);
    });
    return Wallet.open(c);
  }
}

/** Whether a buyer's state has ended: `Punished` keeps its secrets, for
 * a resume to ask the seller for `s` again. */
export function ended(state) {
  return ['Done', 'Punished'].includes(Object.keys(JSON.parse(state))[0]);
}
