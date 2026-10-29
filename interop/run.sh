#!/bin/bash
# Checks Rust joint-key signatures with Lattice's consensus signature rules
# (Transaction.signaturesAreValid / signaturesMatchSigners), over N random
# key-share pairs. Exits nonzero on the first unexpected verdict.
set -euo pipefail
cd "$(dirname "$0")/.."
rounds="${1:-25}"
cargo build -q --example jointkey -p swap-nexus
(cd interop && swift build -q)
rust=target/debug/examples/jointkey
swift=interop/.build/debug/Interop
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

field() { sed -n "s/^$1=//p" <<<"$2"; }
verdict() { "$swift" verify "$@" | tail -1; }
expect() {
  if [[ "$2" != "$3" ]]; then echo "round $round: $1: got [$2], want [$3]" >&2; exit 1; fi
}

for round in $(seq 1 "$rounds"); do
  keys=$("$rust" keys); other=$("$rust" keys)
  a=$(field a "$keys"); b=$(field b "$keys"); A=$(field A "$keys"); Aa=$(field A_a "$keys")
  a2=$(field a "$other"); b2=$(field b "$other"); A2=$(field A "$other")
  "$swift" payload "$A" 0 > "$work/body0"
  "$swift" payload "$A" 1 > "$work/body1"
  joint=$("$rust" sign "$a" "$b" "$work/body0")

  expect "joint key spends the lock address" "$(verdict "$A" "$joint" "$A")" \
    "signaturesAreValid=true signaturesMatchSigners=true"
  expect "signature for another body" "$(verdict "$A" "$("$rust" sign "$a" "$b" "$work/body1")" "$A")" \
    "signaturesAreValid=false signaturesMatchSigners=true"
  expect "joint signature presented under one share's key" "$(verdict "$A" "$joint" "$Aa")" \
    "signaturesAreValid=false signaturesMatchSigners=false"
  expect "another joint key signs for this lock address" "$(verdict "$A" "$("$rust" sign "$a2" "$b2" "$work/body0")" "$A2")" \
    "signaturesAreValid=true signaturesMatchSigners=false"
done
echo "interop: $rounds rounds passed"
