import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import 'fake-indexeddb/auto';

import { Buyer, IndexedDBStore, MemoryStore } from '../src/index.js';
import { agreed, bitcoinView } from '../src/views.js';
import { call, wasm } from '../src/wasm.js';
import { Chain, esplora, kind, loadWasm, nexus, parseTx, POLICY, relay, seller, testOffer, until } from './fakes.js';

before(loadWasm);

const servers = [];
after(() => servers.forEach((server) => server.close()));

/** A swap of the test offer through fakes: the two Esploras show `chain`
 * and `other` (the same chain unless given), as `w.sources` (each's `fees`
 * and `down`) say; the store is `store`. Every send and broadcast is
 * checked against what the store holds at that moment; what it lacked is
 * logged in `unsaved`. */
async function world({ other, store = new MemoryStore(), watchStatus, clock = { offset: 0 }, extra = {}, policy = POLICY } = {}) {
  const chain = new Chain();
  const unsaved = [];
  const sources = [{}, {}];
  const w = { chain, store, unsaved, clock, sources };
  const saved = () => store.load(w.buyer.swapId);
  // A broadcast the store does not know of is lost to a restart.
  const onPost = async (hex) => {
    const record = await saved();
    const state = kind(record.state);
    const spends = state === 'Cancelling' ? call('watchBuyer', record.state).bitcoin : null;
    const known =
      (record.funding?.tx === hex && !['AwaitFunded', 'AwaitSellerSignatures', 'SendingSignatures'].includes(state)) ||
      record.child?.tx === hex ||
      record.refund_child?.tx === hex ||
      record.deposit_refund?.tx === hex ||
      [spends?.lock_spends[1], spends?.cancel_spends[0]].includes(parseTx(hex).txid);
    if (!known) unsaved.push({ broadcast: hex.slice(0, 16), state: kind(record.state) });
  };
  const a = await esplora(chain, onPost, sources[0]);
  const b = await esplora(other ?? chain, onPost, sources[1]);
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
    locks: null,
    storage: null,
    ...extra,
  };
  w.a = a;
  w.b = b;
  w.board = board;
  w.refundKey = call('newBitcoinKey', 'regtest');
  w.buyer = await Buyer.prepare(w.config, {
    offer: board.listed.offer,
    policy,
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
  const record = await w.store.load(w.buyer.swapId);
  assert.deepEqual(JSON.parse(file).browser, { deposit: record.deposit.wif, relay: w.board.url, quote_rate: 10 });
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

  const restoredStore = new MemoryStore();
  const restored = await Buyer.restore({ ...w.config, store: restoredStore }, { file, refundAddress: w.refundKey.address });
  const kept = await restored.backup();
  assert.deepEqual(JSON.parse(kept.file).browser, JSON.parse(file).browser, 'the deposit key and relay come back');
  assert.deepEqual(JSON.parse(kept.file).state, JSON.parse(record.state));
  assert.equal(restored.status().step, 'locking');
  // Unconfirmed, the funding is broadcast again from the restored state,
  // and its change sent on by a child of its own.
  const before = w.a.posted.length;
  const again = running(restored);
  const sentOn = (tx) => parseTx(tx).inputs[0].txid === parseTx(record.funding.tx).txid;
  await until(() => w.a.posted.slice(before).includes(record.funding.tx) && w.a.posted.slice(before).some(sentOn));
  await again.stop();
  const child = parseTx(w.a.posted.slice(before).find(sentOn));
  assert.equal(child.outputs[0].script, record.refund_script);
  const rebuilt = await restoredStore.load(record.swap_id);
  assert.equal(rebuilt.funding.tx, record.funding.tx, 'the funding, from the state');
  assert.equal(parseTx(rebuilt.child.tx).txid, child.txid, 'its child, bumped as the funding’s');

  const store = new IndexedDBStore('restore');
  await store.save(record);
  const resumed = await Buyer.resume({ ...w.config, store }, record.swap_id);
  assert.equal(resumed.status().step, 'locking');
  assert.equal((await store.load(record.swap_id)).state, record.state);
});

test('an offer the policy refuses is refused before anything is saved', async () => {
  const store = new MemoryStore();
  await assert.rejects(world({ store, policy: { ...POLICY, nex_amount: POLICY.nex_amount + 1 } }), /^Error: refused: the offer/);
  assert.equal(store.saves.length, 0);
});

/** The fee `tx` paid, spending `value`. */
const paid = (tx, value) => value - parseTx(tx).outputs.reduce((sum, output) => sum + output.value, 0);

test('one source that answers high spends no more of the deposit in fees', async () => {
  // At 2 and 9000 sat/vB the offer's fee is below the higher's floor, so
  // the deposit goes back: at the lower rate. At 500 and 9000, at twice
  // the quote's 10 sat/vB.
  for (const [fees, rate] of [[[{ 6: 2 }, { 6: 9000 }], 2], [[{ 6: 500 }, { 6: 9000 }], 20]]) {
    const w = await world();
    await w.buyer.backup();
    const quote = w.buyer.status().deposit.amount;
    assert.equal(quote, 1_005_260);
    [w.sources[0].fees, w.sources[1].fees] = fees;
    deposit(w, quote);
    const run = running(w.buyer);
    await until(() => w.a.posted.length > 0);
    await run.stop();
    const refund = (await w.store.load(w.buyer.swapId)).deposit_refund;
    assert.match(refund.why, /refused: the offer/);
    const fee = paid(refund.tx, quote);
    assert.ok(fee >= rate * 100 && fee <= rate * 111, `${fee} sat at ${rate} sat/vB`);
    assert.equal(w.seller.log.length, 0);
  }
  // Both low, the funding and its child pay the lower.
  const w = await world();
  await w.buyer.backup();
  [w.sources[0].fees, w.sources[1].fees] = [{ 6: 3 }, { 6: 2 }];
  deposit(w, w.buyer.status().deposit.amount);
  const run = running(w.buyer);
  await until(async () => (await w.store.load(w.buyer.swapId)).child);
  await run.stop();
  const record = await w.store.load(w.buyer.swapId);
  assert.equal(record.fee_rate, 2);
  assert.equal(record.child.rate, 2);
});

test('an offer whose fee fell below the estimate while the deposit confirmed is not taken', async () => {
  const w = await world();
  await w.buyer.backup();
  deposit(w, w.buyer.status().deposit.amount);
  w.chain.fees = { 6: 1000 };
  const run = running(w.buyer);
  await until(() => w.a.posted.length > 0);
  await run.stop();
  const record = await w.store.load(w.buyer.swapId);
  assert.match(record.deposit_refund.why, /refused: the offer/);
  assert.equal(w.seller.log.length, 0, 'never taken');
  assert.ok(paid(record.deposit_refund.tx, record.quote) <= 20 * 111, 'within the quote’s headroom');
});

/** Mines the funding `record` holds, then `blocks` more. */
function confirmFunding(w, record, blocks) {
  const lock = call('watchBuyer', record.state).bitcoin.lock;
  w.chain.txs.set(lock.split(':')[0], { hex: record.funding.tx, height: w.chain.height + 1 });
  w.chain.mine(1 + blocks);
}

test('the page must stay open from the funding broadcast until a watchtower holds the refund', async () => {
  let answer = 503;
  const clock = { offset: 0 };
  const w = await world({ watchStatus: () => answer, clock });
  await w.buyer.backup();
  assert.equal(w.buyer.status().mustStayOpen, false, 'nothing at stake');
  w.chain.fees = { 6: 2 };
  deposit(w, w.buyer.status().deposit.amount);
  const run = running(w.buyer);
  await until(async () => (await w.store.load(w.buyer.swapId)).child);
  const status = w.buyer.status();
  assert.equal(status.step, 'locking');
  assert.equal(status.mustStayOpen, true, 'the funding is out: no one else cancels at t1');
  assert.equal(status.backupStale, true, 'the file lacks the seller’s signatures');
  await w.buyer.backup();
  assert.equal(w.buyer.status().backupStale, false);
  confirmFunding(w, await w.store.load(w.buyer.swapId), 30);
  await until(() => w.board.watches.length === 1);
  assert.equal(w.buyer.status().step, 'refunding');
  assert.equal(w.buyer.status().mustStayOpen, true, 'the watchtower refused it');
  answer = 200;
  clock.offset += 60_000;
  await until(async () => (await w.store.load(w.buyer.swapId)).watch_posted);
  await until(() => w.buyer.status().mustStayOpen === false);
  await run.stop();
});

test('with one source down for good, the buyer still cancels, refunds and sends the refund on', async () => {
  const { w, run, record } = await funded();
  w.sources[1].down = true;
  const lookups = call('watchBuyer', record.state).bitcoin;
  const sent = (txid) => w.a.posted.find((tx) => parseTx(tx).txid === txid);
  confirmFunding(w, record, 30);
  await until(() => sent(lookups.lock_spends[1])).catch((e) => assert.fail(`${e.message}: ${JSON.stringify(w.buyer.status())}`));
  w.chain.txs.set(lookups.lock_spends[1], { hex: sent(lookups.lock_spends[1]), height: w.chain.height + 1 });
  w.chain.mine();
  await until(() => sent(lookups.cancel_spends[0]));
  const refund = parseTx(sent(lookups.cancel_spends[0]));
  assert.equal(refund.outputs[0].script, record.deposit.script_pubkey, 'the refund pays the deposit key');
  await until(async () => (await w.store.load(w.buyer.swapId)).refund_child);
  const { refund_child: child } = await w.store.load(w.buyer.swapId);
  assert.ok(w.a.posted.includes(child.tx));
  assert.equal(parseTx(child.tx).inputs[0].txid, refund.txid);
  assert.equal(parseTx(child.tx).outputs[0].script, record.refund_script, 'sent on to the refund address');
  assert.equal(w.buyer.status().step, 'refunding');
  await run.stop();
  assert.deepEqual(w.unsaved, []);
});

test('a refund the watchtower broadcast is sent on from the deposit key once the buyer is back', async () => {
  const { w, run, record } = await funded();
  confirmFunding(w, record, 30);
  await until(async () => (await w.store.load(w.buyer.swapId)).watch_posted);
  await run.stop();
  // Away, the watchtower's cancel and refund confirm.
  const { cancel, refund } = JSON.parse(w.board.watches[0].body);
  const [c, r] = [parseTx(cancel), parseTx(refund)];
  w.chain.txs.set(c.txid, { hex: cancel, height: w.chain.height + 1 });
  w.chain.txs.set(r.txid, { hex: refund, height: w.chain.height + 1 });
  w.chain.utxos.set(record.deposit.address, [{ txid: r.txid, vout: 0, value: r.outputs[0].value, height: w.chain.height + 1 }]);
  w.chain.mine();

  const back = await Buyer.resume(w.config, record.swap_id);
  const again = running(back);
  await until(async () => (await w.store.load(record.swap_id)).deposit_refund);
  const forward = (await w.store.load(record.swap_id)).deposit_refund;
  assert.ok(w.a.posted.includes(forward.tx));
  assert.deepEqual(parseTx(forward.tx).inputs.map(({ txid, vout }) => `${txid}:${vout}`), [`${r.txid}:0`]);
  assert.equal(parseTx(forward.tx).outputs[0].script, record.refund_script);
  w.chain.txs.set(forward.txid, { hex: forward.tx, height: w.chain.height + 1 });
  w.chain.mine();
  assert.equal(await again.done, 'refunded');
});

test('one tab alone drives a swap, and the page learns whether its store is kept', async () => {
  const held = new Set();
  const locks = {
    async request(name, options, callback) {
      assert.equal(options.ifAvailable, true);
      if (held.has(name)) return callback(null);
      held.add(name);
      try {
        return await callback({ name });
      } finally {
        held.delete(name);
      }
    },
  };
  const w = await world({ extra: { locks, storage: { persist: async () => true } } });
  await w.buyer.backup();
  const first = running(w.buyer);
  await until(() => held.has(`lattice-swap:${w.buyer.swapId}`));
  const other = await Buyer.resume({ ...w.config, storage: { persist: async () => false } }, w.buyer.swapId);
  assert.equal(await other.run(), null);
  assert.equal(other.status().elsewhere, true);
  assert.equal(other.status().persisted, false);
  assert.equal(w.buyer.status().elsewhere, false);
  assert.equal(w.buyer.status().persisted, true);
  await first.stop();
  assert.equal(held.size, 0, 'released once it stops');
  const unknown = await Buyer.resume({ ...w.config, locks: null, storage: null }, w.buyer.swapId);
  assert.equal(unknown.status().persisted, null);
});
