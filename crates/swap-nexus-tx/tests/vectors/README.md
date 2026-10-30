# Lattice conformance vectors

`encoding.json`, `addresses.json` and `signing.json` are copied unchanged from
[Lattice](https://github.com/0xLattice/Lattice) tag `54.2.1`, directory
`Vectors/` (vector `version` 1). That directory's README describes each file.

`boundaries.json` is generated here, by Lattice 54.2.1's own
`TransactionBody.toData()`, `HeaderImpl.rawCID` and
`TransactionSigning.preimage`: integer-head boundaries for the nonce and
deltas, two-component and UTF-8 chain paths, and 24 account actions.

Copyright (c) 2024-2026 The Lattice Authors, used under the MIT License.
