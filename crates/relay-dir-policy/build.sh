#!/bin/sh
# Builds the policy module so it names no machine.
#
# rustc keeps the path of every panic location in the module. The policy
# depends on Moniker's rules through git, which Cargo checks out under its
# home (~/.cargo), so a plain `cargo build` puts the builder's home
# directory, and with it their username, into the module, and the module is
# stored by every node that hosts the chain. Remapping Cargo's home to one
# fixed path keeps it out, and makes the module the same bytes wherever it is
# built: chain/relay_dir_policy.wasm is this build's output, and spec.json
# names it by CID.
set -eu
cd "$(dirname "$0")"
RUSTFLAGS="--remap-path-prefix=${CARGO_HOME:-$HOME/.cargo}=/Users/anonymous/.cargo" \
  cargo build --release --target wasm32-unknown-unknown "$@"
