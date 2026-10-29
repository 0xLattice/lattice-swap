# lattice-swap

Trustless atomic swaps between NEX (Nexus) and BTC.

The swap uses adaptor signatures. Bitcoin carries every timelock: a Taproot
2-of-2 lock with cancel, refund and punish paths. The Nexus side is two
ordinary transfers: the seller locks NEX at the address of a key split between
the two parties (`address(sG + bG)`), and whoever learns both shares claims it.
Each party's Bitcoin claim reveals exactly the share the other party needs, so
no Nexus consensus change is required.

## License

MIT
