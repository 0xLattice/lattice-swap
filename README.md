# lattice-swap

Trustless atomic swaps between NEX (Nexus) and BTC.

The swap uses adaptor signatures. Bitcoin carries every timelock: a Taproot
2-of-2 lock with cancel, refund and punish paths. The Nexus side is two
ordinary transfers: the seller locks NEX at the address of a key split between
the two parties (`address(sG + bG)`), and whoever learns both shares claims it.
Each party's Bitcoin claim reveals exactly the share the other party needs, so
no Nexus consensus change is required.

## Crates

- `swap-core`: key setup: one secret per party on two curves, and the proof
  that ties them.
- `swap-bitcoin`: the Taproot lock, with cancel, refund and punish paths
  using adaptor signatures. Each swap transaction has one output; redeem,
  refund and punish pay a party, who alone can raise its fee by CPFP from
  that payout. Redeem pays two fees, so cancel and refund together cannot
  replace it. Cancel cannot be bumped. The buyer is safe only if its refund
  confirms before `t2`: after it, the seller can spend the cancel output
  through the punish leaf in a shape no refund can replace, and contesting
  it is best effort.
- `swap-nexus`: the joint key, `(s + b)·G`, and Ed25519 signing with it.
- `swap-nexus-tx`: Nexus transfers encoded and signed exactly as Lattice
  54.2.1 does, checked against Lattice's conformance vectors, and a small
  client for a lattice-node's RPC. Its node test is ignored by default; run
  it with `NEXUS_NODE_IMAGE` naming a lattice-node image and `-- --ignored`,
  where Docker can share the host's network.

- `swap`: the protocol: the messages, a state machine for each party, and
  drivers that run them against bitcoind, a lattice-node and an ivy session,
  saving each party's state so it survives a restart. A driver bumps the
  swap transactions that pay its party while they wait unconfirmed, from
  their payout, up to `max_fee_rate` and `max_fee_fraction` of the payout.
  Its end-to-end tests run whole swaps on regtest and a Nexus node; like the
  node test, they are ignored by default and need `NEXUS_NODE_IMAGE` and
  `-- --ignored`.
- `lattice-swap`: the command line tool that runs one side of a swap.

## Usage

Each party runs its own bitcoind with `-txindex` and a wallet, and its own
lattice-node. Before anything else, `offer`, `take` and `resume` check the
bitcoind: Bitcoin Core 28 or later, its txindex synced, not in initial block
download, on the chain `--btc-network` names, and `--btc-wallet` loaded with
private keys, so it can sign. The two agree on the terms off-tool. The seller, who has NEX,
makes an offer and waits for the buyer to dial:

```sh
lattice-swap offer --nex-key-file ~/.lattice-swap/nex.key \
  --btc-amount 50000000 --btc-fee 2000 --nex-amount 1000000 --nex-fee 10 \
  --listen 0.0.0.0:7400 --advertise 203.0.113.5:7400 \
  --btc-wallet sell --btc-cookie ~/.bitcoin/.cookie \
  --nexus-url http://127.0.0.1:8080 --nexus-cookie ~/lattice/.cookie > offer
```

The first line it prints is the offer: the terms, where the seller listens and
its key, and a session key for the buyer. The offer is a secret: whoever holds
it can take it, so write it where only you can read it (run `umask 077` first)
and hand it over on a private channel. The buyer, who has BTC, takes it:

```sh
lattice-swap take offer --nex-address <your Nexus address> \
  --btc-amount 50000000 --nex-amount 1000000 \
  --btc-wallet buy --btc-cookie ~/.bitcoin/.cookie \
  --nexus-url http://127.0.0.1:8080 --nexus-cookie ~/lattice/.cookie
```

Both then run until the swap ends and print its outcome. Each keeps its
state in `<swap id>.json` in `--dir`, which holds its secrets for the swap
but never the seller's Nexus wallet key: that comes from `--nex-key-file`,
which only its owner may read, or `LATTICE_SWAP_NEX_KEY`, never from an
argument. The seller gives `--advertise` when it listens on an unspecified
address such as `0.0.0.0`.

- `lattice-swap resume <swap file>` carries on after a restart, from the
  chains alone, with the same flags: the node flags, and `--max-fee-rate`,
  `--fallback-fee-rate` and `--max-fee-fraction`, which are not saved. A
  seller also needs its Nexus key until the NEX lock is signed; a key given
  later must still be the swap's. `refund` is the same command: a swap cancels
  and refunds by itself once its timelocks allow.
- `lattice-swap status <swap file>` prints the state and outcome, and asks no
  node.

Both, like the driver, refuse a swap file of another state version: finish
a swap with the build that started it.

The defaults are `t1` 288 and `t2` 144 Bitcoin blocks, 6 Bitcoin and 24 Nexus
confirmations, and a margin of 12. A Nexus block is about 6 Bitcoin blocks, so
the tool refuses any `t1` below `btc-confirmations + 6 × (nex-confirmations +
1) + margin`. A buyer refuses an offer on another `--btc-network`, or for
other amounts than its `--btc-amount` and `--nex-amount`, and prints the terms
before it dials. It also refuses one outside its bounds: `--max-btc-fee` 10000
sat, `--max-nex-fee` 1000, `--max-t1` 288, `--min-t2` 144,
`--min-btc-confirmations` 6, `--max-btc-confirmations` 12,
`--min-refund-window` 72, `--min-nex-confirmations` 24 and `--min-margin` 6 by
default. Either side refuses a `--btc-amount` below two `--btc-fee`, which
redeem pays, plus 546 sat, the highest dust limit of a wallet's payout. Once
the buyer has signed the redeem, it refunds only when cancel is
`btc-confirmations` deep, and the seller can punish once cancel is `t2` deep:
the refund window is `t2 - btc-confirmations` blocks. The buyer also refuses a
`--btc-fee` at which cancel or refund, the spends it relies on, pays less than
its bitcoind's conservative fee estimate for 6 blocks, or, where bitcoind has
no estimate, as on regtest, `--min-btc-fee-rate` sat/vB.

While a swap transaction that pays this side waits unconfirmed (redeem and
punish for the seller, refund for the buyer), `offer`, `take` and `resume`
bump it by CPFP from its payout, toward bitcoind's estimate. A bump pays
for at most `--max-fee-rate` sat/vB, 1000 by default, and at most
`--max-fee-fraction` of the payout, from 0 to 1, 1 by default: all of it
but dust. Where bitcoind has no estimate it aims at `--fallback-fee-rate`,
10 sat/vB by default. Cancel is never bumped.

`offer`, `take` and `resume` exit 0 only when the swap swapped: 3 when it
refunded, 4 punished, 5 drained, 6 aborted. 1 means an error stopped the
tool before the swap ended; if the swap file exists by then, it prints the
`resume` command to carry on with, given the same flags. A `take` run again
on an offer it took refuses, and prints the same command.
`docs/protocol.md` describes the protocol.

## License

MIT
