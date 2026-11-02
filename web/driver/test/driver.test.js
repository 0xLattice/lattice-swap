import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import 'fake-indexeddb/auto';

import { Buyer, IndexedDBStore, MemoryStore, Wallet } from '../src/index.js';
import { call } from '../src/wasm.js';
import { Chain, esplora, kind, Locks, loadWasm, nexus, parseTx, POLICY, seller, testOffer, until } from './fakes.js';

before(loadWasm);

const servers = [];
after(() => servers.forEach((server) => server.close()));

/** The test offer's terms. */
const TERMS = JSON.parse(testOffer('http://relay.invalid')).terms;

/** The state's own transactions, as a restart from it would know them:
 * its funding, and once it cancels, cancel and refund. */
function known(state) {
  const value = JSON.parse(state);
  const locked = Object.values(value)[0]?.locked;
  const txids = [];
  if (kind(state) === 'Cancelling') {
    const lookups = call('watchBuyer', state).bitcoin;
    txids.push(lookups.lock_spends[1], lookups.cancel_spends[0]);
  }
  return { funding: locked?.funding ?? null, txids };
}

/** A wallet and a swap of the test offer through fakes, the store
 * `store`. Every send and broadcast is checked against what the store
 * holds at that moment; what it lacked is logged in `unsaved`. */
async function world({ store = new MemoryStore(), policy = POLICY, chain = new Chain(), extra = {} } = {}) {
  const unsaved = [];
  const w = { chain, store, unsaved };
  const saved = () => store.get(`swap:${TERMS.swap_id}`);
  // A broadcast the store does not know of is lost to a restart; a
  // withdrawal is the wallet's own, and needs nothing saved.
  const onPost = async (hex) => {
    if (w.withdrawing) return;
    const record = await saved();
    const { funding, txids } = known(record.state);
    if (funding !== hex && !txids.includes(parseTx(hex).txid)) unsaved.push({ broadcast: hex.slice(0, 16), state: kind(record.state) });
  };
  const a = await esplora(chain, onPost);
  const node = await nexus();
  servers.push(a, node);
  w.a = a;
  w.offer = testOffer('http://relay.invalid');
  // The state each message must already be saved in when it goes out.
  const expect = { BuyerHello: 'AwaitSellerHello', LockProposal: 'AwaitSellerSignatures', BuyerSignatures: 'SendingSignatures' };
  w.seller = seller(w.offer);
  const open = w.seller.open;
  w.seller.open = async (...args) => {
    const session = await open(...args);
    const send = session.send;
    session.send = (message) => {
      const name = Object.keys(JSON.parse(message))[0];
      w.checked = saved().then((record) => {
        if (!record.taken || kind(record.state) !== expect[name]) unsaved.push({ send: name, state: kind(record.state) });
      });
      send(message);
    };
    w.session = session;
    return session;
  };
  w.config = {
    store,
    network: 'regtest',
    esplora: a.url,
    nexus: node.url,
    nexusGenesis: 'genesis',
    poll: 2,
    locks: null,
    openSession: (...args) => w.seller.open(...args),
    ...extra,
  };
  w.wallet = await Wallet.open(w.config);
  w.nexAddress = call('newNexKey').address;
  w.buyer = await Buyer.prepare(w.wallet, { offer: w.offer, policy, nexAddress: w.nexAddress });
  return w;
}

/** Pays `value` to the wallet, in a block unless `confirmed` is false. */
function deposit(w, value, confirmed = true) {
  const utxo = { txid: 'aa'.repeat(32), vout: 0, value, height: confirmed ? w.chain.height : null };
  w.chain.utxos.set(w.wallet.address, [utxo]);
}

function running(buyer) {
  const stop = new AbortController();
  const done = buyer.run(stop.signal);
  return { stop: () => (stop.abort(), done), done };
}

const pause = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

/** A swap run until its funding is broadcast, the recovery file saved
 * when it asks. */
async function funded(options) {
  const w = await world(options);
  deposit(w, 1_100_000);
  const run = running(w.buyer);
  await until(() => w.buyer.status().step === 'save-backup');
  w.buyer.backupSaved();
  await until(() => w.a.posted.length > 0).catch((e) => assert.fail(`${e.message}: ${JSON.stringify(w.buyer.status())}`));
  const record = await w.store.get(`swap:${w.buyer.swapId}`);
  return { w, run, record, funding: known(record.state).funding };
}

/** `hex` in a block `depth` deep, the chain mined to there. */
function confirm(w, hex, depth = 1) {
  w.chain.txs.set(parseTx(hex).txid, { hex, height: w.chain.height + 1 });
  w.chain.mine(depth);
}

/** The broadcast whose txid is `txid`, once it comes. */
async function broadcast(w, txid) {
  await until(() => w.a.posted.some((tx) => parseTx(tx).txid === txid)).catch((e) =>
    assert.fail(`${e.message}: ${JSON.stringify(w.buyer.status())}`),
  );
  return w.a.posted.find((tx) => parseTx(tx).txid === txid);
}

test('the wallet is made once and kept, and the swap waits for it to be funded', async () => {
  const w = await world();
  const again = await Wallet.open(w.config);
  assert.equal(again.address, w.wallet.address, 'the same key');
  assert.match(w.wallet.address, /^bcrt1q/);
  // Unconfirmed, the deposit is on its way, not spendable.
  deposit(w, 1_100_000, false);
  const run = running(w.buyer);
  await until(() => w.buyer.status().wallet.unconfirmed === 1_100_000 && w.buyer.status().need !== null);
  const status = w.buyer.status();
  assert.equal(status.step, 'fund-wallet');
  assert.equal(status.backupCovers, 'wallet');
  assert.equal(status.wallet.confirmed, 0);
  assert.ok(status.need > TERMS.btc_amount && status.need < TERMS.btc_amount + 1_000, `${status.need}`);
  assert.equal(w.seller.log.length, 0, 'not taken');
  deposit(w, 1_100_000);
  await until(() => w.seller.log.length > 0);
  await run.stop();
});

test('nothing is sent or broadcast before the state that asks for it is saved', async () => {
  const store = new IndexedDBStore('save-before-send');
  const { w, run } = await funded({ store });
  await run.stop();
  await w.checked;
  assert.deepEqual(
    w.seller.log.map((message) => Object.keys(message)[0]),
    ['BuyerHello', 'LockProposal', 'BuyerSignatures'],
  );
  assert.deepEqual(w.unsaved, []);
  assert.equal(w.buyer.status().step, 'swapping');
});

test('the lock is funded from the wallet’s balance, its change back to the wallet', async () => {
  const { w, run, funding } = await funded();
  await run.stop();
  const tx = parseTx(funding);
  assert.equal(w.a.posted[0], funding);
  assert.deepEqual(tx.inputs.map((input) => `${input.txid}:${input.vout}`), [`${'aa'.repeat(32)}:0`]);
  assert.equal(tx.outputs[0].value, TERMS.btc_amount);
  assert.equal(tx.outputs[1].script, w.wallet.key.script_pubkey, 'the change, to the wallet');
  const fee = 1_100_000 - TERMS.btc_amount - tx.outputs[1].value;
  assert.ok(fee > 100 && fee < 300, `${fee} sat at 1 sat/vB, the relay floor, with no estimate`);
});

test('the funding pays the backend’s estimate, floored at the relay minimum', async () => {
  for (const [estimate, rate] of [[3.2, 4], [0.3, 1], [0, 1]]) {
    const chain = new Chain();
    // The offer's fee must clear the estimate for 6 blocks.
    chain.fees = { 6: estimate };
    const { run, funding } = await funded({ chain });
    await run.stop();
    const tx = parseTx(funding);
    const fee = 1_100_000 - tx.outputs.reduce((sum, output) => sum + output.value, 0);
    // One P2WPKH input, the lock and the change: about 154 vB.
    assert.ok(fee >= rate * 150 && fee <= rate * 160, `${estimate}: paid ${fee}`);
  }
});

test('an offer the policy refuses is refused before anything of the swap is saved', async () => {
  const store = new MemoryStore();
  await assert.rejects(world({ store, policy: { ...POLICY, nex_amount: POLICY.nex_amount + 1 } }), /^Error: refused: the offer/);
  assert.deepEqual(store.puts.map(([key]) => key), ['wallet']);
  // An offer whose fee is below the estimate is refused too, as the CLI's
  // `take` refuses it.
  const chain = new Chain();
  chain.fees = { 6: 50 };
  await assert.rejects(world({ chain }), /below the .* sat its node's fee rate asks/);
});

test('the refund lands in the wallet, and the deadlines show where it is', async () => {
  const { w, run, funding } = await funded();
  const lookups = call('watchBuyer', (await w.store.get(`swap:${w.buyer.swapId}`)).state).bitcoin;
  assert.deepEqual(w.buyer.status().deadlines, { cancel: null, refund: null, punish: null });
  // The funding is in block 101; the NEX lock never comes.
  confirm(w, funding);
  const lockHeight = w.chain.height;
  await until(() => w.buyer.status().confirmations.funding === 1);
  const { deadlines } = w.buyer.status();
  assert.equal(deadlines.cancel.height, lockHeight + TERMS.t1);
  assert.equal(deadlines.punish.height, lockHeight + TERMS.t1 + TERMS.t2, 'the earliest, before cancel');
  // The refund goes out once cancel is `btc_confirmations` deep (1 here):
  // in the block after.
  assert.deepEqual(deadlines.refund, { from: lockHeight + TERMS.t1 + 1, until: lockHeight + TERMS.t1 + TERMS.t2 });
  const eta = deadlines.cancel.eta - Date.now();
  assert.ok(Math.abs(eta - TERMS.t1 * 600_000) < 60_000, `${eta}`);
  assert.equal(w.buyer.status().mustStayOpen, false, 'the redeem is unsigned, and cancel not due');
  assert.equal(w.buyer.status().backupCovers, 'lock');

  // At t1 it cancels; once cancel is in a block, it refunds. From cancel
  // on, the page stays open until the refund confirms.
  w.chain.mine(TERMS.t1 - 1);
  const cancel = await broadcast(w, lookups.lock_spends[1]);
  assert.equal(w.buyer.status().step, 'refunding');
  assert.equal(w.buyer.status().mustStayOpen, true, 'cancel is due');
  // A block late, so the refund and the punish move from their earliest.
  w.chain.mine();
  confirm(w, cancel);
  const cancelHeight = w.chain.height;
  assert.equal(cancelHeight, lockHeight + TERMS.t1 + 1);
  await until(() => w.buyer.status().deadlines.punish?.height === cancelHeight + TERMS.t2);
  assert.deepEqual(w.buyer.status().deadlines.refund, { from: cancelHeight + 1, until: cancelHeight + TERMS.t2 });
  assert.equal(w.buyer.status().mustStayOpen, true);
  // Cancel must be `btc_confirmations` deep, the redeem signed or not.
  const state = JSON.parse((await w.store.get(`swap:${w.buyer.swapId}`)).state);
  const locked = state.Cancelling.locked;
  locked.setup.terms.btc_confirmations = 3;
  const view = { height: cancelHeight, funding: TERMS.t1 + 2, lock_spend: { tx: cancel, confirmations: 1 }, cancel_spend: null, stale: null };
  for (const redeem of [null, locked.refund]) {
    const deep = call('buyerStatus', JSON.stringify({ Cancelling: { locked, redeem } }), JSON.stringify(view));
    assert.equal(deep.deadlines.refund, cancelHeight + 3, `redeem ${redeem === null ? 'unsigned' : 'signed'}`);
  }
  const refund = parseTx(await broadcast(w, lookups.cancel_spends[0]));
  assert.equal(refund.outputs[0].script, w.wallet.key.script_pubkey, 'the refund pays the wallet');
  assert.equal(refund.outputs[0].value, TERMS.btc_amount - 2 * TERMS.btc_fee, 'cancel and refund pay their fixed fees');
  confirm(w, w.a.posted.find((tx) => parseTx(tx).txid === refund.txid));
  assert.equal(await run.done, 'refunded');
  assert.equal(w.buyer.status().step, 'refunded');
  assert.equal(w.buyer.status().mustStayOpen, false);
  assert.deepEqual(w.buyer.status().deadlines, { cancel: null, refund: null, punish: null });
  assert.deepEqual(w.unsaved, []);
});

test('the page must stay open only while the redeem is signed and unsettled', async () => {
  const status = (state) => call('buyerStatus', JSON.stringify(state), null).must_stay_open;
  const { w, run, record } = await funded();
  await run.stop();
  assert.equal(status(JSON.parse(record.state)), false, 'awaiting the NEX lock');
  const locked = JSON.parse(record.state).AwaitNexLock.locked;
  // An adaptor signature, as the redeem's is: the seller's refund one.
  const redeem = locked.refund;
  assert.equal(status({ AwaitRedeem: { locked, redeem } }), true);
  assert.equal(status({ Cancelling: { locked, redeem } }), true);
  assert.equal(status({ Cancelling: { locked, redeem: null } }), false);
  assert.equal(status({ Done: 'Swapped' }), false);
  assert.equal(w.buyer.status().mustStayOpen, false);
});

test('one swap runs at a time, and the wallet withdraws only when none does', async () => {
  const { w, run } = await funded();
  await run.stop();
  await assert.rejects(Buyer.prepare(w.wallet, { offer: w.offer, policy: POLICY, nexAddress: w.nexAddress }), /one swap at a time/);
  const to = call('newBitcoinKey', 'regtest');
  await assert.rejects(w.wallet.withdraw(to.address), /is running/);
});

test('a withdrawal sends the whole spendable balance to any address', async () => {
  const w = await world();
  w.chain.utxos.set(w.wallet.address, [
    { txid: 'aa'.repeat(32), vout: 0, value: 60_000, height: w.chain.height },
    { txid: 'bb'.repeat(32), vout: 1, value: 40_000, height: w.chain.height },
    { txid: 'cc'.repeat(32), vout: 2, value: 5_000, height: null },
  ]);
  const to = call('newBitcoinKey', 'regtest');
  w.withdrawing = true;
  const txid = await w.wallet.withdraw(to.address);
  const tx = parseTx(w.a.posted[0]);
  assert.equal(tx.txid, txid);
  assert.equal(tx.inputs.length, 2, 'the confirmed outputs only');
  assert.equal(tx.outputs.length, 1);
  assert.equal(tx.outputs[0].script, to.script_pubkey);
  assert.ok(tx.outputs[0].value > 100_000 - 300 && tx.outputs[0].value < 100_000, `${tx.outputs[0].value}`);
  await assert.rejects(w.wallet.withdraw('nonsense'), /./);
});

test('a wallet and its swap restore from the recovery file and carry on from the chains', async () => {
  const { w, run, record, funding } = await funded();
  await run.stop();
  const { name, file } = await w.wallet.backup();
  assert.equal(name, `lattice-swap-${w.wallet.address}.json`);

  const store = new MemoryStore();
  const wallet = await Wallet.restore({ ...w.config, store }, file);
  assert.equal(wallet.address, w.wallet.address, 'the wallet key comes back');
  assert.deepEqual(await wallet.swaps(), [record.swap_id]);
  const restored = await store.get(`swap:${record.swap_id}`);
  assert.equal(restored.state, record.state);
  const buyer = await Buyer.resume(wallet, record.swap_id);
  assert.equal(buyer.status().step, 'swapping');
  // Unconfirmed, the funding is broadcast again from the restored state.
  const before = w.a.posted.length;
  const again = running(buyer);
  await until(() => w.a.posted.slice(before).includes(funding));
  await again.stop();

  // A store with another wallet is refused, and one already holding the
  // swap keeps its own record.
  await assert.rejects(Wallet.restore({ ...w.config, store: new MemoryStore(), network: 'regtest' }, file.replace(/"network":"regtest"/, '"network":"signet"')), /for signet/);
  const other = new MemoryStore();
  await Wallet.open({ ...w.config, store: other });
  await assert.rejects(Wallet.restore({ ...w.config, store: other }, file), /another wallet/);
  const ahead = { ...restored, state: JSON.stringify({ Done: 'Swapped' }) };
  const holding = new MemoryStore();
  await holding.put(`swap:${record.swap_id}`, ahead);
  await Wallet.restore({ ...w.config, store: holding }, file);
  assert.deepEqual(await holding.get(`swap:${record.swap_id}`), ahead);
  assert.rejects(Wallet.restore(w.config, '{}'), /not a recovery file/);
});

test('a swap that never took its offer is dropped when another is prepared', async () => {
  const w = await world();
  const second = await Buyer.prepare(w.wallet, { offer: w.offer, policy: POLICY, nexAddress: w.nexAddress });
  assert.equal(second.swapId, w.buyer.swapId);
  assert.deepEqual(await w.wallet.swaps(), [w.buyer.swapId]);
  assert.equal((await w.store.get(`swap:${w.buyer.swapId}`)).taken, false);
});

test('a seller that goes quiet before the lock aborts the swap, the deposit kept', async () => {
  const clock = { offset: 0 };
  const w = await world({ extra: { now: () => Date.now() + clock.offset } });
  w.seller.open = async () => ({ closed: false, send() {}, close() {} });
  deposit(w, 1_100_000);
  const run = running(w.buyer);
  await until(async () => (await w.store.get(`swap:${w.buyer.swapId}`)).taken);
  clock.offset += 61_000;
  assert.equal(await run.done, 'aborted');
  assert.equal(w.buyer.status().step, 'done');
  assert.equal(w.a.posted.length, 0, 'nothing broadcast');
  assert.equal(w.buyer.status().wallet.confirmed, 1_100_000);
});

test('two opens of a fresh store end on one wallet key', async () => {
  const config = { network: 'regtest', esplora: 'http://esplora.invalid', locks: null };
  const tab = () => Wallet.open({ ...config, store: new IndexedDBStore('key-race') });
  const [a, b] = await Promise.all([tab(), tab()]);
  assert.equal(a.address, b.address);
  const store = new IndexedDBStore('key-race');
  assert.equal((await store.get('wallet')).wif, a.key.wif);
  // A key there is never written over, as `createwallet` refuses to.
  await store.add('wallet', call('newBitcoinKey', 'regtest'));
  assert.equal((await store.get('wallet')).wif, a.key.wif);
  assert.equal((await Wallet.open({ ...config, store })).address, a.address);
});

test('one tab drives the wallet; another waits, then takes over from the store', async () => {
  const locks = new Locks();
  const first = locks.tab();
  const w = await world({ store: new IndexedDBStore('two-tabs'), extra: { locks: first } });
  let waiting = false;
  const second = Wallet.open({ ...w.config, store: new IndexedDBStore('two-tabs'), locks: locks.tab(), onWaiting: () => (waiting = true) });
  await until(() => waiting);
  const opened = await Promise.race([second.then(() => 'opened'), pause(50).then(() => 'waiting')]);
  assert.equal(opened, 'waiting', 'not while the first tab is open');
  locks.close(first);
  const wallet = await second;
  assert.equal(wallet.address, w.wallet.address);
  assert.deepEqual(await wallet.swaps(), [w.buyer.swapId], 'the first tab’s swap, read from the store');
});

test('a withdrawal waits for an offer being taken, then refuses', async () => {
  const w = await world();
  let release;
  const gate = new Promise((resolve) => (release = resolve));
  const open = w.seller.open;
  let dialing = false;
  w.seller.open = async (...args) => {
    dialing = true;
    await gate;
    return open(...args);
  };
  deposit(w, 1_100_000);
  const run = running(w.buyer);
  await until(() => dialing);
  w.withdrawing = true;
  const withdrawal = w.wallet.withdraw(call('newBitcoinKey', 'regtest').address);
  await pause(20);
  release();
  await assert.rejects(withdrawal, /is running/);
  await run.stop();
  assert.equal(w.a.posted.length, 0, 'no sweep');
});

test('an offer whose session will not open is given up once, nothing sent', async () => {
  const w = await world();
  let opens = 0;
  w.seller.open = async () => {
    opens += 1;
    throw new Error('the session ended');
  };
  deposit(w, 1_100_000);
  const run = running(w.buyer);
  await until(() => w.buyer.status().step === 'offer-gone');
  assert.equal(await run.done, null);
  assert.equal(opens, 1);
  assert.match(w.buyer.status().warning, /^the offer is gone: the session ended$/);
  assert.equal(await w.store.get(`swap:${w.buyer.swapId}`), null, 'nothing kept of it');
  assert.equal(w.a.posted.length, 0);
});

test('a failed read of the wallet’s balance skips none of the swap’s views', async () => {
  const { w, run, funding } = await funded();
  w.chain.utxosDown = true;
  await until(() => /503/.test(w.buyer.status().warning ?? ''));
  confirm(w, funding);
  // The view still read, the balance read failing after it.
  await until(() => w.buyer.status().confirmations.funding === 1);
  await run.stop();
});

test('two Wallets of one store in a tab share the swap lock', async () => {
  for (const second of [(w) => Wallet.open(w.config), async (w) => Wallet.restore(w.config, (await w.wallet.backup()).file)]) {
    const w = await world();
    const other = await second(w);
    let release;
    const gate = new Promise((resolve) => (release = resolve));
    const open = w.seller.open;
    let dialing = false;
    w.seller.open = async (...args) => {
      dialing = true;
      await gate;
      return open(...args);
    };
    deposit(w, 1_100_000);
    const run = running(w.buyer);
    await until(() => dialing);
    w.withdrawing = true;
    const withdrawal = other.withdraw(call('newBitcoinKey', 'regtest').address);
    await pause(20);
    release();
    await assert.rejects(withdrawal, /is running/);
    await run.stop();
    assert.equal(w.a.posted.length, 0, 'no sweep');
  }
});

test('the funding waits for the recovery file, which covers the lock', async () => {
  const w = await world();
  deposit(w, 1_100_000);
  const run = running(w.buyer);
  await until(() => w.buyer.status().step === 'save-backup');
  assert.equal(w.buyer.status().backupCovers, 'lock');
  await pause(50);
  assert.equal(w.a.posted.length, 0, 'nothing broadcast before the file is saved');
  const { file } = await w.buyer.backup();
  const [swap] = JSON.parse(file).swaps;
  assert.equal(Object.keys(swap.state)[0], 'AwaitNexLock', 'the file restores to the state the funding goes out from');
  w.buyer.backupSaved();
  await until(() => w.a.posted.length > 0);
  assert.equal(w.a.posted[0], JSON.parse(file).swaps[0].state.AwaitNexLock.locked.funding);
  assert.equal(w.buyer.status().step, 'swapping');
  await run.stop();
  assert.deepEqual(w.unsaved, []);
});

test('a recovery file never saved lets the swap abort before funding, at the message timeout', async () => {
  let now = Date.now();
  const w = await world({ extra: { now: () => now } });
  deposit(w, 1_100_000);
  const run = running(w.buyer);
  await until(() => w.buyer.status().step === 'save-backup');
  now += 60_001;
  assert.equal(await run.done, 'aborted');
  assert.equal(w.a.posted.length, 0, 'never funded');
  assert.equal(await w.wallet.running(), null, 'the wallet is free again');
});

test('a refused Web Lock request is asked again', async () => {
  const locks = new Locks().tab();
  const request = locks.request;
  let refusals = 1;
  locks.request = (...args) => (refusals-- > 0 ? Promise.reject(new Error('SecurityError')) : request(...args));
  const config = { network: 'regtest', esplora: 'http://esplora.invalid', store: new MemoryStore(), locks };
  await assert.rejects(Wallet.open(config), /SecurityError/);
  assert.match((await Wallet.open(config)).address, /^bcrt1q/);
});

test('a swap dropped by a later prepare never takes its offer', async () => {
  const w = await world();
  const first = w.buyer;
  const second = await Buyer.prepare(w.wallet, { offer: w.offer, policy: POLICY, nexAddress: w.nexAddress });
  deposit(w, 1_100_000);
  const run = running(first);
  await until(() => first.status().step === 'offer-gone');
  assert.equal(await run.done, null);
  assert.match(first.status().warning, /dropped when another was prepared/);
  assert.equal(w.seller.log.length, 0, 'nothing sent');
  assert.equal((await w.store.get(`swap:${second.swapId}`)).taken, false, 'the second’s record kept');
});
