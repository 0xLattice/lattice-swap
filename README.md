# lattice-swap

Trustless atomic swaps between NEX (Nexus) and BTC.

The swap uses adaptor signatures. Bitcoin carries every timelock: a Taproot
2-of-2 lock with cancel, refund and punish paths. The Nexus side is two
ordinary transfers: the seller locks NEX at the address of a key split between
the two parties (`address(sG + bG)`), and whoever learns both shares claims it.
Each party's Bitcoin claim reveals exactly the share the other party needs, so
no Nexus consensus change is required.

## Crates

- `swap-nexus`: the joint key, `(s + b)·G`, and Ed25519 signing with it.
- `swap-nexus-tx`: Nexus transfers encoded and signed exactly as Lattice
  54.2.1 does, checked against Lattice's conformance vectors, and a small
  client for a lattice-node's RPC. Its node test runs when
  `NEXUS_NODE_IMAGE` names a lattice-node image and Docker can share the
  host's network.

## License

MIT
