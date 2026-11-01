// The browser's buyer, run in Node by the CLI's end-to-end tests
// (crates/lattice-swap/tests/e2e.rs) against regtest, a Nexus node's
// public read port and a relay, as a page runs it: only the store differs,
// a directory of files standing in for IndexedDB.
//
//   node e2e-buyer.js take <config.json>    prepare, back up, print the
//                                            deposit, then run
//   node e2e-buyer.js resume <config.json>  run the swap in the store again
//
// The config: {dir, esplora: [url], nexus, genesis, offer, policy,
// refund_address, nex_address, swap_id (resume)}. The deposit prints as
// one JSON line, `{"address", "amount"}`; the end as `outcome: <step>`.

import { readFileSync, renameSync, writeFileSync, mkdirSync, readdirSync } from 'node:fs';
import { join } from 'node:path';
import { Buyer, load } from '../src/index.js';

/** One file per swap, each replaced whole: what IndexedDB is to a page. */
class FileStore {
  constructor(dir) {
    this.dir = dir;
    mkdirSync(dir, { recursive: true });
  }

  async load(swapId) {
    try {
      return JSON.parse(readFileSync(join(this.dir, `${swapId}.json`), 'utf8'));
    } catch {
      return null;
    }
  }

  async save(record) {
    const path = join(this.dir, `${record.swap_id}.json`);
    writeFileSync(`${path}.tmp`, JSON.stringify(record));
    renameSync(`${path}.tmp`, path);
  }

  async list() {
    return readdirSync(this.dir).filter((name) => name.endsWith('.json')).map((name) => name.slice(0, -5));
  }
}

const [mode, configPath] = process.argv.slice(2);
const c = JSON.parse(readFileSync(configPath, 'utf8'));
await load(readFileSync(new URL('../pkg/swap_wasm_bg.wasm', import.meta.url)));
const config = {
  store: new FileStore(c.dir),
  network: 'regtest',
  esplora: c.esplora,
  nexus: c.nexus,
  nexusGenesis: c.genesis,
  poll: 500,
};

let buyer;
if (mode === 'take') {
  buyer = await Buyer.prepare(config, {
    offer: c.offer,
    policy: c.policy,
    refundAddress: c.refund_address,
    nexAddress: c.nex_address,
  });
  const { file } = await buyer.backup();
  writeFileSync(join(c.dir, 'backup'), file);
  const { address, amount } = buyer.status().deposit;
  console.log(JSON.stringify({ swap_id: buyer.swapId, address, amount }));
} else {
  buyer = await Buyer.resume(config, c.swap_id);
}
buyer.addEventListener('status', (event) => console.error(JSON.stringify(event.detail)));
console.log(`outcome: ${await buyer.run()}`);
// A session may still be open: the swap is over.
process.exit(0);
