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
import { Nexus } from './views.js';
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
function single(locks = globalThis.navigator?.locks, onWaiting = undefined) {
  if (locks === null) return Promise.resolve();
  if (locks === undefined) throw new Error('refused: this browser has no Web Locks, to keep one tab on the swap');
  if (!instances.has(locks)) {
    const instance = new Promise((resolve, reject) => {
      const hold = () => {
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

export class Wallet {
  /** The wallet in `config.store`, made and saved first if there is none. */
  static async open(config) {
    const c = { ...DEFAULTS, ...config };
    c.store ??= new IndexedDBStore();
    c.fetch ??= (...args) => globalThis.fetch(...args);
    c.WebSocket ??= globalThis.WebSocket;
    c.esplora ??= ESPLORA[c.network];
    if (!c.esplora) throw new Error(`no default Esplora for ${c.network}: give one`);
    await single(c.locks, c.onWaiting);
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

  /** Where the buyer deposits. */
  get address() {
    return this.key.address;
  }

  /** The outputs the wallet holds: those in a block are spendable, as
   * Bitcoin Core spends none it received still unconfirmed. */
  async spendable() {
    const utxos = await this.esplora.utxos(this.address);
    return utxos.filter((utxo) => utxo.height !== null).map(({ txid, vout, value }) => ({ txid, vout, value }));
  }

  /** `{confirmed, unconfirmed}`, in sat: what the wallet can spend, and
   * what is on its way to it. */
  async balance() {
    const utxos = await this.esplora.utxos(this.address);
    const sum = (confirmed) =>
      utxos.filter((utxo) => (utxo.height !== null) === confirmed).reduce((sum, utxo) => sum + utxo.value, 0);
    return { confirmed: sum(true), unconfirmed: sum(false) };
  }

  /** The Esplora's estimate for the CLI's target, in whole sat/vB, never
   * below the relay floor, which is also the rate where it has none, as on
   * regtest: how Electrum and eigenwallet price their own spends. */
  async feeRate() {
    const estimate = await this.esplora.feeRate(FEE_TARGET);
    return Math.max(MIN_RELAY, Math.ceil(estimate ?? MIN_RELAY));
  }

  /** The swap ids in the store. */
  async swaps() {
    return (await this.config.store.keys()).filter((key) => key.startsWith('swap:')).map((key) => key.slice(5));
  }

  /** The swap that has taken its offer and not ended, if any: eigenwallet
   * runs one swap at a time. */
  async running() {
    for (const id of await this.swaps()) {
      const record = await this.config.store.get(swapKey(id));
      if (record.taken && !ended(record.state)) return id;
    }
    return null;
  }

  /** Runs `act` with the wallet's outputs to itself, as eigenwallet's
   * `SwapLock` is held from a swap's start: a withdrawal, a swap prepared,
   * or one taking its offer, until it is saved as taken, each waits for
   * the one before. */
  exclusive(act) {
    const run = swapLock.then(act);
    swapLock = run.catch(() => {});
    return run;
  }

  /** Sends the whole spendable balance to `address`, less its fee: the
   * txid. Not while a swap runs, whose funding spends the same outputs. */
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
   * {@link Wallet.restore} reads it. `states` stands a swap's state, by
   * id, in for the one the store holds: a buyer's, whose funding waits for
   * the file. */
  async backup(states = {}) {
    const swaps = [];
    for (const id of await this.swaps()) {
      const stored = await this.config.store.get(swapKey(id));
      const record = { ...stored, state: states[id] ?? stored.state };
      if (ended(record.state)) continue;
      const { version } = JSON.parse(call('backup', record.state).file);
      swaps.push({ ...record, version, state: JSON.parse(record.state) });
    }
    const file = { format: FORMAT, network: this.config.network, wallet: this.key.wif, swaps };
    return { name: `lattice-swap-${this.address}.json`, file: JSON.stringify(file) };
  }

  /** The wallet in a recovery `file` from {@link Wallet#backup}, put in
   * `config.store` with its swaps, but those the store holds already.
   * Refuses a store that holds another wallet, whose key it would lose. */
  static async restore(config, file) {
    const c = { ...DEFAULTS, ...config };
    c.store ??= new IndexedDBStore();
    const backup = JSON.parse(file);
    if (backup.format !== FORMAT) throw new Error('not a recovery file');
    if (backup.network !== c.network) throw new Error(`the file is for ${backup.network}, not ${c.network}`);
    const key = call('bitcoinKeyOf', backup.wallet, c.network);
    await single(c.locks, c.onWaiting);
    const held = await c.store.get(WALLET);
    if (held !== null && held.wif !== key.wif) throw new Error('refused: the store holds another wallet');
    const records = backup.swaps.map(({ version, state, ...record }) => {
      // The state version and side checked as the CLI's `resume` checks them.
      const restored = call('restore', JSON.stringify({ version, state }));
      if (restored.side !== 'buyer') throw new Error('not a buyer’s swap');
      return { ...record, state: JSON.stringify(restored.state) };
    });
    // Never over another wallet, as `open` makes one.
    await c.store.add(WALLET, key);
    if ((await c.store.get(WALLET)).wif !== key.wif) throw new Error('refused: the store holds another wallet');
    // A swap the store holds is as far on as the file's, or further.
    for (const record of records) {
      if ((await c.store.get(swapKey(record.swap_id))) === null) await c.store.put(swapKey(record.swap_id), record);
    }
    return Wallet.open(c);
  }
}

/** Whether a buyer's state has ended. */
export function ended(state) {
  return Object.keys(JSON.parse(state))[0] === 'Done';
}
