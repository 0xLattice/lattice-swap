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
- `swap-wasm`: the machines built for a browser, with JSON in and out: no
  I/O, which the page does. `swap` and `swap-nexus-tx` keep their native I/O
  behind the default `native` feature, so without it they build for
  `wasm32-unknown-unknown`, with a clang that has the WebAssembly target.
- `swap-relay`: a relay the parties can meet through: an offer board, a
  pipe between the two, and a watchtower for buyers' refunds.
- `lattice-swap`: the command line tool that runs one side of a swap.

## Install

Download the archive for your platform from
[Releases](https://github.com/0xLattice/lattice-swap/releases):
`lattice-swap-<version>-<target>.tar.gz` for `x86_64-unknown-linux-gnu`,
`aarch64-unknown-linux-gnu` or `aarch64-apple-darwin`. Check it against its
`.sha256` file or `SHA256SUMS`, then unpack it:

```sh
shasum -a 256 -c lattice-swap-<version>-<target>.tar.gz.sha256
tar -xzf lattice-swap-<version>-<target>.tar.gz
```

The Linux binaries link glibc dynamically and are built on Ubuntu 24.04, so
they need glibc 2.39 or later. Each archive carries a build provenance
attestation: `gh attestation verify <archive> --repo 0xLattice/lattice-swap`.

Or build from source with Rust 1.89 or later:

```sh
cargo build --release -p lattice-swap
```

The binary is `target/release/lattice-swap`.

## Usage

Each party runs its own bitcoind with `-txindex` and a wallet, and its own
lattice-node. Before anything else, `offer`, `take` and `resume` check the
bitcoind: Bitcoin Core 28 or later, its txindex synced, not in initial block
download, on the chain `--btc-network` names, and `--btc-wallet` loaded with
private keys and, if encrypted, unlocked; an unlock that times out mid-swap
stops its bumps. They also check that the lattice-node keeps past blocks and
the state after them (`--state all` and `--block-bodies all`, its defaults),
without which it cannot say how deep a transaction is. Before that, they
check which Nexus the lattice-node follows: the genesis block of its root
chain, as `GET /api/chain/info` names it, must be the one `--nexus-genesis`
names. By default that is mainnet's,
`bafyreiggtg4ezifboyekbf4gxst2jr3mpjqcxsbmopy7w6fp46g4ngpgxa`, anchored in
Bitcoin as the OP_RETURN of transaction
`7501f77602b581f605e6bc61c310b540e17324d3cc292c18985d8a3464d23236` in block
970053. A buyer on any other Nexus would accept a worthless NEX lock. The
offer's terms also name the seller's genesis, and the buyer refuses one
other than its own, but each side's protection is its own node's check. The
swap file keeps that genesis: `resume` refuses a `--nexus-genesis` naming
another. A private chain
forked from mainnet's genesis passes it: it shares mainnet's identity, so
trade only through a node that follows the public network, and never use a
mainnet key on a private or dev chain, where a transfer it signs is valid on
mainnet too. While a swap runs, a bitcoind that falls behind its headers,
or whose tip is over `--max-tip-age` minutes old, 90 by default, since its
block time or since the tool first saw it, may hide that
the redeem window closed: the seller starts no redeem and locks no NEX on it,
and the tool warns until it catches up. Every other spend and bump goes on.
The seller's protection against a node someone cut off is that node's own
connectivity: for a large swap, run a well-connected one. The two agree on the terms off-tool. The
seller, who has NEX, makes an offer and waits for the buyer to dial:

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
  `--fallback-fee-rate`, `--max-fee-fraction` and `--max-tip-age`, which are
  not saved. A
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
no estimate, as on regtest, `--min-btc-fee-rate` sat/vB. The seller refuses
to offer such a `--btc-fee` too: cancel, which it needs to reclaim its NEX,
pays it as signed and is never bumped, so leave headroom.

The NEX lock and the buyer's claim from it each pay `--nex-fee`, and
`--nex-amount` must exceed it. A fee one node pools may still be below what
the rest of the network relays: then no miner sees the lock, and the swap
waits until `t1` and refunds. So the seller refuses to offer, and the buyer
to take, a `--nex-fee` below `--min-nex-fee`, 1 by default, the default
relay floor, or their Nexus node's `minRelayFee` if higher. Raise
`--min-nex-fee` to the network's floor if it is higher.

While a swap transaction that pays this side waits unconfirmed (redeem and
punish for the seller, refund for the buyer), `offer`, `take` and `resume`
bump it by CPFP from its payout, toward bitcoind's estimate. A bump pays
for at most `--max-fee-rate` sat/vB, 1000 by default, and at most
`--max-fee-fraction` of the payout, from 0 to 1, 1 by default: all of it
but dust. Where bitcoind has no estimate it aims at `--fallback-fee-rate`,
10 sat/vB by default. Cancel is never bumped. The buyer's wallet funds the
lock at bitcoind's estimate, or else `--fallback-fee-rate`, never below the
node's mempool minimum, and not capped by `--max-fee-rate`; never at the
wallet's own estimate, which a freshly synced node lacks, and without
`-fallbackfee` funds nothing.

`offer`, `take` and `resume` exit 0 only when the swap swapped: 3 when it
refunded, 4 punished, 5 drained, 6 aborted. 1 means an error stopped the
tool before the swap ended; if the swap file exists by then, it prints the
`resume` command to carry on with, given the same flags. A `take` run again
on an offer it took refuses, and prints the same command. A swap file is run
by one process at a time: a second `resume` while one runs refuses.
`docs/protocol.md` describes the protocol.

## Swapping through a relay

A relay lets the seller post an offer without a reachable address, and
anyone find it. It holds no keys and no funds: the parties' session runs end
to end through it, encrypted, each side authenticating the other's key, and
the buyer checks the seller's signature over the offer's terms. A relay can
drop or delay what it carries, which ends a swap in a refund, but cannot
change it.

```sh
cargo build --release -p swap-relay
swap-relay --listen 0.0.0.0:7500 --network bitcoin --watches /var/lib/swap-relay
```

It serves `GET /offers`, the offers listed; `GET /sell` and
`GET /take/<swap id>`, the WebSockets a seller waits on and a buyer pairs
through; and `POST /watch`, the watchtower. An offer is listed while its
seller stays connected, until a buyer takes it. The watchtower reads Bitcoin
through an Esplora API, `--esplora`, mempool.space's for the network by
default (give one for regtest), every `--poll` seconds, 60 by default. Put
TLS in front of it for `https://`. Each bound says what it protects:
`--max-offers`, 10000 by default, the sellers held at once, listed or
swapping, each a connection and its offer in memory; `--max-watches`, 10000,
the watches held, each in memory and on disk, and two or three Esplora
requests a round; an offer at most 4 KiB, the board's memory; one WebSocket
message at most 64 KiB, which a pipe holds whole while passing it on; a
watch at most 16 KiB. A connection silent for 60 seconds, not even
answering the relay's pings, is closed, and its offer withdrawn.

The seller gives `--relay` instead of `--listen`; the offer it prints names
the relay, not an address. Anyone can list the relay's offers and take one,
so an offer on a relay is public:

```sh
lattice-swap offer --relay https://relay.example ... > offer
curl -s https://relay.example/offers
```

`take` on an offer that names a relay reaches the seller through it. The
buyer also hands the relay's watchtower its cancel and fully signed refund,
for it to broadcast the refund as soon as cancel is in a block if the buyer
is offline then: `--watchtower <url>` names another relay, `--no-watchtower` none, and
`resume --watchtower <url>` hands them over from a resumed swap. The refund
reveals the buyer's key share, with which a seller that can still redeem
takes both coins, so the buyer hands it over only once it has given up on
the swap at `t1` without signing the redeem, and broadcasts its cancel. The
watchtower takes a watch only once its cancel is on the network, so each
costs a real transaction, and only with a refund signed by both keys; the
buyer asks again every minute until it is taken. It does not cover a
buyer that signed the redeem: that buyer must itself be online to refund
between cancel and `t2`.

## License

MIT
