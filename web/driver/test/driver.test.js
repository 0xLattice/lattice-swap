import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import 'fake-indexeddb/auto';

import { Buyer, IndexedDBStore, MemoryStore } from '../src/index.js';
import { agreed, bitcoinView } from '../src/views.js';
import { call, wasm } from '../src/wasm.js';
import { Chain, esplora, kind, loadWasm, nexus, POLICY, relay, seller, testOffer, until } from './fakes.js';

before(loadWasm);

const servers = [];
after(() => servers.forEach((server) => server.close()));

/** A swap of the test offer through fakes: the two Esploras show `chain`
 * and `other` (the same chain unless given), the store is `store`. Every
 * send and broadcast is checked against what the store holds at that
 * moment; what it lacked is logged in `unsaved`. */
async function world({ other, store = new MemoryStore(), watchStatus, clock = { offset: 0 } } = {}) {
  const chain = new Chain();
  const unsaved = [];
  const w = { chain, store, unsaved, clock };
  const saved = () => store.load(w.buyer.swapId);
  // A broadcast the store does not know of is lost to a restart.
  const onPost = async (hex) => {
    const record = await saved();
    const state = kind(record.state);
    const known =
      (record.funding?.tx === hex && !['AwaitFunded', 'AwaitSellerSignatures', 'SendingSignatures'].includes(state)) ||
      record.child?.tx === hex ||
      record.deposit_refund?.tx === hex ||
      (state === 'Cancelling' && JSON.parse(wasm.watchRequest(record.state, 'regtest') ?? '{}').cancel === hex);
    if (!known) unsaved.push({ broadcast: hex.slice(0, 16), state: kind(record.state) });
  };
  const a = await esplora(chain, onPost);
  const b = await esplora(other ?? chain, onPost);
  const node = await nexus();
  const board = await relay(null, watchStatus);
  servers.push(a, b, node, board);
  board.listed.offer = testOffer(board.url);
  // The state each message must already be saved in when it goes out.
  const expect = { BuyerHello: 'AwaitSellerHello', LockProposal: 'AwaitSellerSignatures', BuyerSignatures: 'SendingSignatures' };
  w.seller = seller(board.listed.offer);
  const open = w.seller.open;
  w.seller.open = async (...args) => {
    const session = await open(...args);
    const send = session.send;
    session.send = (message) => {
      const name = Object.keys(JSON.parse(message))[0];
      w.pendingCheck = saved().then((record) => {
        if (!record.taken || kind(record.state) !== expect[name]) unsaved.push({ send: name, state: kind(record.state) });
      });
      send(message);
    };
    return session;
  };
  w.config = {
    store,
    network: 'regtest',
    esplora: [a.url, b.url],
    nexus: node.url,
    nexusGenesis: 'genesis',
    poll: 2,
    openSession: (...args) => w.seller.open(...args),
    now: () => Date.now() + clock.offset,
  };
  w.a = a;
  w.b = b;
  w.board = board;
  w.refundKey = call('newBitcoinKey', 'regtest');
  w.buyer = await Buyer.prepare(w.config, {
    offer: board.listed.offer,
    policy: POLICY,
    refundAddress: w.refundKey.address,
    nexAddress: call('newNexKey').address,
  });
  return w;
}

/** Pays `value` to the deposit address, confirmed, on `chains`. */
function deposit(w, value, chains = [w.chain]) {
  const { address } = w.buyer.status().deposit;
  for (const chain of chains) chain.utxos.set(address, [{ txid: 'aa'.repeat(32), vout: 0, value, height: chain.height }]);
}

function running(buyer) {
  const stop = new AbortController();
  const done = buyer.run(stop.signal);
  return { stop: () => (stop.abort(), done), done };
}

const pause = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

test('the deposit address is shown only once the backup is taken', async () => {
  const w = await world();
  assert.equal(w.buyer.status().step, 'backup');
  assert.equal(w.buyer.status().deposit, null);
  const { name, file } = await w.buyer.backup();
  assert.equal(name, `${w.buyer.swapId}.json`);
  assert.equal(JSON.parse(file).deposit, (await w.store.load(w.buyer.swapId)).deposit.wif);
  const status = w.buyer.status();
  assert.equal(status.step, 'deposit');
  assert.match(status.deposit.address, /^bcrt1q/);
  assert.ok(status.deposit.amount > 1_000_000, 'the quote covers the amount and its fees');
  assert.equal((await w.store.load(w.buyer.swapId)).backed_up, true);
});

test('a deposit only one source shows is waited for; once both do, the offer is taken', async () => {
  const other = new Chain();
  const w = await world({ other });
  await w.buyer.backup();
  deposit(w, w.buyer.status().deposit.amount, [w.chain]);
  const run = running(w.buyer);
  await pause(100);
  assert.equal(w.seller.log.length, 0, 'nothing taken on one source');
  assert.equal(w.buyer.status().step, 'deposit');
  assert.equal(w.buyer.status().deposit.confirmations, undefined, 'nothing shown that the sources disagree on');
  deposit(w, w.buyer.status().deposit.amount, [other]);
  await until(() => w.seller.log.length > 0);
  await run.stop();
});

test('a Bitcoin view is one only when both sources show it', async () => {
  const lookups = {
    lock: `${'bb'.repeat(32)}:0`,
    lock_spends: ['cc'.repeat(32), 'dd'.repeat(32)],
    cancel_spends: ['ee'.repeat(32), 'ff'.repeat(32)],
    cancel_output: `${'dd'.repeat(32)}:0`,
    t2: 20,
  };
  const [one, two] = [new Chain(), new Chain()];
  const a = await esplora(one);
  const b = await esplora(two);
  servers.push(a, b);
  const { Esplora } = await import('../src/esplora.js');
  const sources = [new Esplora(a.url), new Esplora(b.url)];
  const read = () => agreed(sources, (source) => bitcoinView(source, lookups));
  for (const chain of [one, two]) chain.txs.set('bb'.repeat(32), { hex: '00', height: 95 });
  assert.equal((await read()).view.funding, 6);
  // One source shows a block the other does not.
  two.mine();
  assert.equal(await read(), null);
  one.mine();
  assert.equal((await read()).view.funding, 7);
  // One shows the funding unconfirmed.
  two.txs.set('bb'.repeat(32), { hex: '00', height: null });
  assert.equal(await read(), null);
});

/** A world run to the funding's broadcast: `{w, run, record}`. */
async function funded(options) {
  const w = await world(options);
  await w.buyer.backup();
  w.chain.fees = { 6: 2 };
  deposit(w, w.buyer.status().deposit.amount);
  const run = running(w.buyer);
  await until(async () => {
    const record = await w.store.load(w.buyer.swapId);
    return record.child && w.a.posted.includes(record.child.tx);
  });
  await w.pendingCheck;
  return { w, run, record: await w.store.load(w.buyer.swapId) };
}

test('nothing is sent or broadcast before the state that asks for it is saved', async () => {
  const store = new IndexedDBStore('save-before-send');
  const { w, run, record } = await funded({ store });
  await run.stop();
  assert.deepEqual(w.seller.log.map((message) => Object.keys(message)[0]), ['BuyerHello', 'LockProposal', 'BuyerSignatures']);
  assert.ok(w.a.posted.includes(record.funding.tx) && w.b.posted.includes(record.funding.tx), 'the funding went to both');
  assert.ok(record.child.tx.includes(record.refund_script), 'the change goes back to the buyer');
  assert.deepEqual(w.unsaved, []);
  assert.equal(w.buyer.status().step, 'locking');
});

test('a deposit too small or far too large goes back, and no swap runs', async () => {
  for (const value of [() => 1_000_000, (quote) => 2 * quote + 1]) {
    const w = await world();
    await w.buyer.backup();
    deposit(w, value(w.buyer.status().deposit.amount));
    const run = running(w.buyer);
    await until(() => w.a.posted.length > 0).catch((e) => assert.fail(`${e.message}: ${JSON.stringify(w.buyer.status())}`));
    const record = await w.store.load(w.buyer.swapId);
    assert.equal(w.a.posted[0], record.deposit_refund.tx);
    assert.ok(record.deposit_refund.tx.includes(record.refund_script), 'back to the refund address');
    assert.equal(w.buyer.status().step, 'refunding');
    assert.equal(w.seller.log.length, 0, 'never taken');
    w.chain.txs.set(record.deposit_refund.txid, { hex: record.deposit_refund.tx, height: w.chain.height + 1 });
    w.chain.mine();
    assert.equal(await run.done, 'refunded');
    assert.deepEqual(w.unsaved, []);
  }
});

test('a deposit that fits takes the offer, but not one gone from the board', async () => {
  const w = await world();
  await w.buyer.backup();
  w.board.listed.offer = null;
  deposit(w, w.buyer.status().deposit.amount);
  const run = running(w.buyer);
  await until(() => w.a.posted.length > 0);
  assert.match((await w.store.load(w.buyer.swapId)).deposit_refund.why, /no longer listed/);
  assert.equal(w.seller.log.length, 0);
  await run.stop();
});

test('the refund goes to the watchtower once it cancels with the redeem unsigned, retried each minute', async () => {
  let answers = [503, 200];
  const clock = { offset: 0 };
  const { w, run, record } = await funded({ watchStatus: () => answers.shift() ?? 500, clock });
  // The funding confirms; the NEX lock never comes.
  const lock = call('watchBuyer', record.state).bitcoin.lock;
  w.chain.txs.set(lock.split(':')[0], { hex: record.funding.tx, height: w.chain.height + 1 });
  w.chain.mine();
  await pause(100);
  assert.equal(w.board.watches.length, 0, 'nothing to hand over while the swap may still go through');
  w.chain.mine(30);
  await until(() => w.board.watches.length === 1).catch((e) => assert.fail(`${e.message}: ${JSON.stringify(w.buyer.status())}`));
  const cancelling = await w.store.load(w.buyer.swapId);
  assert.equal(kind(cancelling.state), 'Cancelling');
  // What the CLI hands over: the buyer's signatures in it are made anew
  // each time, so the rest is compared.
  const posted = JSON.parse(w.board.watches[0].body);
  const expected = JSON.parse(wasm.watchRequest(cancelling.state, 'regtest'));
  assert.deepEqual(Object.keys(posted).sort(), ['cancel', 'depth', 'network', 'refund']);
  assert.equal(posted.network, 'regtest');
  assert.equal(posted.depth, expected.depth);
  assert.equal(posted.refund.slice(0, 80), expected.refund.slice(0, 80));
  await pause(100);
  assert.equal(w.board.watches.length, 1, 'no retry within the minute');
  clock.offset += 60_000;
  await until(() => w.board.watches.length === 2);
  await until(async () => (await w.store.load(w.buyer.swapId)).watch_posted);
  clock.offset += 120_000;
  await pause(100);
  assert.equal(w.board.watches.length, 2, 'taken: never handed over again');
  await run.stop();
});

test('a swap restores from its backup file, or its stored record, and carries on from the chains', async () => {
  const { w, run, record } = await funded();
  const { file } = await w.buyer.backup();
  await run.stop();

  const restored = await Buyer.restore({ ...w.config, store: new MemoryStore() }, { file, refundAddress: w.refundKey.address });
  const kept = await restored.backup();
  assert.equal(JSON.parse(kept.file).deposit, record.deposit.wif, 'the deposit key comes back');
  assert.deepEqual(JSON.parse(kept.file).state, JSON.parse(record.state));
  assert.equal(restored.status().step, 'locking');
  // Unconfirmed, the funding is broadcast again from the restored state.
  const before = w.a.posted.length;
  const again = running(restored);
  await until(() => w.a.posted.slice(before).includes(record.funding.tx));
  await again.stop();

  const store = new IndexedDBStore('restore');
  await store.save(record);
  const resumed = await Buyer.resume({ ...w.config, store }, record.swap_id);
  assert.equal(resumed.status().step, 'locking');
  assert.equal((await store.load(record.swap_id)).state, record.state);
});
