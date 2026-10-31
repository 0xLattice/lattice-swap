# The swap protocol

A seller has NEX and wants BTC; a buyer has BTC and wants NEX. They agree
on the terms off-band: the amounts, the fees, the timelocks `t1` and `t2`,
how many confirmations each chain needs, and a `margin` of Bitcoin blocks of
slack before a timelock.

## Keys

Each party makes fresh secrets for every swap: a Bitcoin key, and a key
share that exists on both curves, ed25519 for Nexus and secp256k1 for
Bitcoin, with a proof that the two halves are the same scalar. The NEX is
locked at the Nexus address of the joint key `(s + b)·G`, where `s` is the
seller's share and `b` the buyer's. Whoever learns both shares can spend
from it. Nexus needs nothing new: the lock is an ordinary transfer, and so
is the claim from it.

Never use one Nexus wallet seed on two networks, such as a testnet and
mainnet. A Lattice signature commits to the chain path, `Nexus`, but not to
the genesis block, so a transfer signed on one network is valid on any
other where its nonce is next. A testnet NEX lock replayed on mainnet pays
mainnet NEX to a lock address whose key the testnet counterparty holds.

Bitcoin carries every timelock. The buyer funds a Taproot output that only
the seller's and the buyer's Bitcoin keys can spend together. Four
transactions can move it, each with its txid fixed before any is signed:

- redeem pays the seller;
- cancel moves the BTC to the cancel output, once the lock is `t1` deep;
- refund pays the cancel output back to the buyer;
- punish pays the cancel output to the seller alone, once cancel is `t2`
  deep.

The buyer's signature on the redeem is an adaptor signature encrypted to
the seller's share. To publish the redeem, the seller decrypts it, which
reveals `s`. The seller's signature on the refund is encrypted to the
buyer's share, so publishing the refund reveals `b`. Either is revealed as
soon as its transaction is in the mempool.

## Messages

All messages travel on the ivy topic `lattice-swap/v1`. Each carries the
swap id.

1. B → S `BuyerHello`, then S → B `SellerHello`. Each sends its Bitcoin key,
   its public share with the cross-curve proof, and its payout scripts.
2. B → S `LockProposal`: the funding transaction without witnesses. Its txid
   is final, but the seller cannot broadcast it.
3. S → B `SellerSignatures`: the seller's cancel signature and its refund
   adaptor signature. B → S `BuyerSignatures`: the buyer's cancel
   signature. The buyer then broadcasts the funding transaction.
4. Once the lock is `btc_confirmations` deep, S transfers `nex_amount` to
   the lock address. Once that is mined, S sends `NexLocked` with its CID.
5. B checks the NEX lock on its own node and sends `RedeemSignature`, its
   redeem adaptor signature. The buyer checks that the transaction is on
   Nexus, credits the lock address at least `nex_amount`, and is
   `nex_confirmations` deep. It also checks that the lock address holds at
   least `nex_amount` and has never signed, and that its node is synced.
6. S redeems the BTC, which reveals `s`. B claims the NEX.

## When something goes wrong

- If S never redeems, B cancels after `t1` and refunds, which reveals `b`.
  S then claims its NEX back.
- If B never refunds, S punishes after `t2` and keeps the BTC.
- S stops starting to broadcast the redeem once the lock is `t1 - margin +
  1` deep, so a redeem it starts sending has `margin - 1` blocks to confirm
  before cancel can be broadcast. A redeem it has seen, in the mempool or a
  block, may have made `s` public, so S keeps broadcasting it until it is
  `btc_confirmations` deep, in place of cancel, and against a cancel still
  in the mempool. Only a cancel in a block stops it; a reorg that puts that
  cancel back in the mempool starts it again.
- Every deadline is read from the party's own Bitcoin node, so a node that
  stalled, or that the counterparty cut off from the network, would show
  the redeem window still open after cancel, and the buyer's deadlines
  still far. A party acts on a view only while its node has every block of
  the best header chain it knows and the tip's block time is at most
  `max_tip_age`, 90 minutes by default, behind the party's clock. Until
  then it does nothing and warns, again every minute. Feeding a node fresh
  blocks of a fork takes real proof of work.
- Before anything is at stake, a party whose counterparty goes quiet
  aborts.
- A seller that signed a NEX lock and then learned `b` keeps waiting while
  the lock address holds less than `nex_amount`, because the lock can still
  land until the seller's nonce passes it. The operator ends the wait by
  spending once from the seller's Nexus wallet at that nonce. Once that is
  mined, the lock can never land.
- A buyer whose node never shows its funding transaction rebroadcasts it and
  keeps its secrets, because only they can refund it if it confirms. The
  operator ends the wait by spending one of the funding's inputs elsewhere.
  The buyer never notices that spend: once it is `btc_confirmations` deep,
  the funding can no longer confirm, and the operator stops the process and
  discards the swap file.

Every timelock counts blocks after a confirmation, so every deadline is a
number of confirmations.

## Fees

Each Bitcoin swap transaction is version 3 (TRUC), has one output, and
pays a fee fixed at setup, `btc_fee`, but redeem, which pays two. The party
a spend pays raises its feerate by CPFP: a child that spends the payout,
sent with it as a package, and replaced by a higher-paying child to bump
again. Redeem and punish pay the seller and refund pays the buyer; nobody
else can spend those outputs, and TRUC lets an unconfirmed transaction have
only one small child, so nobody else can pin them.

- Cancel cannot be bumped: its output is the cancel output, which only both
  parties together, or the seller after `t2`, can spend. A stuck cancel
  only delays the swap, since `t2` counts from its confirmation. Its fee is
  fixed when both sign it, so choose `btc_fee` with headroom over today's
  rates; both sides refuse one below their node's estimate. Sending cancel
  and refund as a package is no fix: a refund broadcast while cancel is
  unconfirmed reveals `b` while the seller can still redeem.
- Refund has no timelock, so after `t1` the buyer could send cancel and
  refund as one package, paying two fees, against a redeem still pending.
  Redeem paying two fees keeps that package from replacing it.
- The buyer is safe as long as its refund confirms before `t2`. After
  that, the punish leaf takes the seller's signature alone, so the seller
  can spend the cancel output in a shape no refund can replace at any fee,
  and contesting a punish is best effort.

## State

Each party is a state machine that does no I/O. A driver feeds it what the
chains and the counterparty show. Before any action, the driver writes the
party's state to its swap file, tagged with a state version; a build reads
only its own version. The state holds the party's secrets for the
swap but never the seller's Nexus wallet key, so a party that restarts picks
up where it stopped.

## Outcomes

- `Swapped`: the buyer has the NEX, the seller the BTC.
- `Refunded`: the buyer has its BTC back, and the seller has its NEX if it
  locked any.
- `Punished`: the seller took the BTC through punish.
- `Drained`: this party learned the joint key, but the lock was already
  spent.
- `Aborted`: stopped before anything was at stake.
