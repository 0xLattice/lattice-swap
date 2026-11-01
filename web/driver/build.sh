#!/bin/sh
# Builds swap-wasm into pkg/ as the ES module `wasm-bindgen --target web`
# writes: a browser loads it by URL, Node from its bytes. secp256k1-sys
# needs a clang with the WebAssembly target (CC_wasm32_unknown_unknown).
set -eu
cd "$(dirname "$0")/../.."
cargo build --release -p swap-wasm --target wasm32-unknown-unknown
wasm-bindgen --target web --out-dir web/driver/pkg \
  target/wasm32-unknown-unknown/release/swap_wasm.wasm
