// The browser's buyer, run in Node by the CLI's end-to-end tests
// (crates/lattice-swap/tests/e2e.rs) against regtest, a Nexus node's
// public read port and a relay, as a page runs it: only the store differs,
// a directory of files standing in for IndexedDB.
//
//   node e2e-buyer.js take <config.json>     open the wallet, prepare the
//                                             offer, print what to deposit,
//                                             then run
//   node e2e-buyer.js restore <config.json>  restore the recovery file
//                                             into a fresh store, then run
//
// The config: {dir, esplora, nexus, genesis, offer, policy, nex_address}.
// What to deposit prints as one JSON line, `{"address", "need"}`; the end
// as `outcome: <outcome>`. The recovery file is written to `<dir>/backup`
// once, when `backupCovers` first says it covers the lock: when a page asks
// the buyer to download it, and never again, so a restore reads it as the
// buyer would have it, stale.

import { existsSync, mkdirSync, readFileSync, readdirSync, renameSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { Buyer, load, Wallet } from '../src/index.js';

/** One file per key, each replaced whole: what IndexedDB is to a page. */
class FileStore {
  constructor(dir) {
    this.dir = dir;
    mkdirSync(dir, { recursive: true });
  }

  async get(key) {
    try {
      return JSON.parse(readFileSync(join(this.dir, `${key}.json`), 'utf8'));
    } catch {
      return null;
    }
  }

  async put(key, value) {
    const path = join(this.dir, `${key}.json`);
    writeFileSync(`${path}.tmp`, JSON.stringify(value));
    renameSync(`${path}.tmp`, path);
  }

  async add(key, value) {
    if (!existsSync(join(this.dir, `${key}.json`))) await this.put(key, value);
  }

  async delete() {
    throw new Error('not needed here');
  }

  async keys() {
    return readdirSync(this.dir)
      .filter((name) => name.endsWith('.json'))
      .map((name) => name.slice(0, -5));
  }
}

const [mode, configPath] = process.argv.slice(2);
const c = JSON.parse(readFileSync(configPath, 'utf8'));
await load(readFileSync(new URL('../pkg/swap_wasm_bg.wasm', import.meta.url)));
const config = (dir) => ({
  store: new FileStore(dir),
  network: 'regtest',
  esplora: c.esplora,
  nexus: c.nexus,
  nexusGenesis: c.genesis,
  poll: 500,
  // One process, the only one on its store.
  locks: null,
});

let wallet;
let buyer;
if (mode === 'take') {
  wallet = await Wallet.open(config(c.dir));
  buyer = await Buyer.prepare(wallet, { offer: c.offer, policy: c.policy, nexAddress: c.nex_address });
} else {
  const file = readFileSync(join(c.dir, 'backup'), 'utf8');
  wallet = await Wallet.restore(config(join(c.dir, 'restored')), file);
  const [swapId] = await wallet.swaps();
  buyer = await Buyer.resume(wallet, swapId);
}
let told = mode !== 'take';
let backedUp = mode !== 'take';
buyer.addEventListener('status', async (event) => {
  const status = event.detail;
  console.error(JSON.stringify(status));
  if (!told && status.need !== null) {
    told = true;
    console.log(JSON.stringify({ address: status.wallet.address, need: status.need }));
  }
  if (!backedUp && status.backupCovers === 'lock') {
    backedUp = true;
    const { file } = await wallet.backup();
    writeFileSync(join(c.dir, 'backup.tmp'), file);
    renameSync(join(c.dir, 'backup.tmp'), join(c.dir, 'backup'));
  }
});
console.log(`outcome: ${await buyer.run()}`);
// A session may still be open: the swap is over.
process.exit(0);
