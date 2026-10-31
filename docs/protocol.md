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

There is one Nexus: every lattice-node build pins its genesis block,
anchored in Bitcoin, and each party refuses a node whose root chain starts
from any other. A private or dev chain forked from that same genesis shares
its identity: a Lattice signature commits to the chain path, `Nexus`, and to
nothing that tells such a chain from mainnet, so a transfer signed on it is
valid on mainnet wherever its nonce is next. Never use a mainnet key on a
private or dev chain.

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
  before cancel can be broadcast. A redeem it has sent, or seen in the
  mempool or a block, may have made `s` public: S marks it sent in the
  state it saves before the broadcast, and keeps broadcasting it until it
  is `btc_confirmations` deep, in place of cancel, and against a cancel
  still in the mempool. Only a cancel in a block stops it; a reorg that
  puts that cancel back in the mempool starts it again, even with a refund
  pooled on that cancel: only a B racing the redeem sends one, and B holds
  `s` and may have taken the NEX already. Once due, S broadcasts cancel
  beside a redeem missing from its node: a redeem in the mempool refuses
  it, paying twice its fee, but one refused for another reason leaves S
  its path to punish. A refund gives S `b`, even in the mempool, and S
  claims the NEX. A claim that lands means S fights for the redeem no
  longer. Until then, while it holds a redeem sent or seen, S goes on
  watching Bitcoin: it fights for that redeem until the cancel is in a
  block, and goes on until the refund is `btc_confirmations` deep. A
  redeem never sent cannot have revealed `s`, and is abandoned once the
  window closes: no one else can empty the lock, and before `t2` a refund
  leaves only the claim at once.
- From `t2`, a refund not yet in a block missed it. Whatever its claim,
  pending, landed or drained, and whether or not it held a redeem, S
  broadcasts punish at every Bitcoin view while the cancel is `t2` deep and
  the cancel output is unspent or spent only by a refund in the mempool;
  its driver bumps punish as a package priced to replace that refund. The
  claim goes on beside it: recovering the BTC never waits on Nexus. S never
  broadcasts punish before `t2`, which consensus would refuse anyway, and
  never contests a refund in a block. Whichever spend gets
  `btc_confirmations` deep decides: a redeem ends the swap `Swapped`; a
  punish `Punished`, even with the claim landed, when S has both since the
  refund missed `t2`, and with the claim still pending S keeps its secrets
  and goes on claiming, ending `Punished` once the claim lands or the lock
  turns out drained or empty; a refund `Refunded` if the claim landed or
  nothing was locked, `Drained` if B emptied the lock with `s`, and
  otherwise leaves only the claim. A claim that lands, or finds nothing was
  locked, ends the swap `Refunded` at the next Bitcoin view that shows no
  punish can win: before `t2`, or against a refund in a block.
- Every deadline is read from the party's own Bitcoin node. A node that
  stalled, or that someone cut off from the network, shows fewer blocks
  than there are: every depth it reports is too low. That only delays
  cancel and punish, which consensus holds to their timelocks, and the
  refund, which waits on depth, so they and their bumps go on whatever the
  node shows. A node fed a fork reports that fork's depths instead;
  acting on them, even B's refund, needs a cancel on the fork, which takes
  fork blocks of full difficulty from where the node left the network
  until the lock is `t1` deep. The one thing a stale node
  makes unsafe is the redeem window, which such a node shows open after it
  closed: S starts a redeem, and locks the NEX, only on a view whose node
  has every block of the best header chain it knows and whose tip is at
  most `max_tip_age` old, 90 minutes by default. The tip's age counts from
  the earlier of its block time and when S's driver first saw it: a block
  time is the miner's to set, up to two hours ahead, but first sight is
  S's own. A redeem S has seen is sent again on any view. Once its views
  have been stale for a minute, the driver warns, and again every minute.
- So to keep S's node showing the window open, whoever cut it off must feed
  it a fork block of full difficulty at least every `max_tip_age`: about
  11% of the network's hashrate at 90 minutes, sustained over the redeem
  window. The protection is the connectivity of S's own node; for a large
  swap, run a well-connected one. S's driver does not also bound the
  window by its clock: the window is set in blocks, which come at no fixed
  rate, and a clock bound tight enough to matter would close it before the
  NEX lock could be deep enough for B, so most swaps would cancel.
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
- The buyer is safe as long as its refund confirms before `t2` and stays
  confirmed: a reorg reaching below the refund's block after `t2` puts it
  back in the mempool, where the seller contests it. The buyer refunds once
  cancel is in a block, or `btc_confirmations` deep once it has sent its
  redeem signature, leaving at least `t2 - btc_confirmations` blocks of
  margin. After `t2`, the punish leaf takes the seller's signature alone,
  so the seller can spend the cancel output in a shape no refund can
  replace at any fee, and contesting a punish is best effort.

The buyer funds the lock from its wallet at its node's estimate or else a
fallback rate, or the mempool's minimum if higher, and not capped by the
most a bump pays, so the lock relays when it is funded.

The NEX lock and the claim from it each pay `nex_fee`, below `nex_amount`;
the claim pays the claimant's node's relay floor if higher, out of
`nex_amount`. A fee one node pools is no proof the network relays it: a lock
no miner sees leaves the swap to refund at `t1`. Each side holds `nex_fee` to
its own floor, the higher of an operator setting and its node's relay floor,
and the seller offers, and the buyer takes, no fee below it.

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
- `Punished`: the seller took the BTC through punish. Its claim of the
  NEX, if it learned `b` from a refund that missed `t2`, may land too: a
  claim still pending is seen through before the swap ends.
- `Drained`: this party learned the joint key, but the lock was already
  spent.
- `Aborted`: stopped before anything was at stake.
