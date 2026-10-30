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
  using adaptor signatures.
- `swap-nexus`: the joint key, `(s + b)·G`, and Ed25519 signing with it.
- `swap-nexus-tx`: Nexus transfers encoded and signed exactly as Lattice
  54.2.1 does, checked against Lattice's conformance vectors, and a small
  client for a lattice-node's RPC. Its node test is ignored by default; run
  it with `NEXUS_NODE_IMAGE` naming a lattice-node image and `-- --ignored`,
  where Docker can share the host's network.

- `swap`: the protocol: the messages, a state machine for each party, and
  drivers that run them against bitcoind, a lattice-node and an ivy session,
  saving each party's state so it survives a restart. Its end-to-end tests
  run whole swaps on regtest and a Nexus node; like the node test, they are
  ignored by default and need `NEXUS_NODE_IMAGE` and `-- --ignored`.

## License

MIT
