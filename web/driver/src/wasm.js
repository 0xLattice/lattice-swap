// swap-wasm, built into ../pkg by build.sh: the machines and every rule a
// view is judged by. Everything crosses as JSON text; `call` takes and
// gives plain values.

import init, { initSync } from '../pkg/swap_wasm.js';
import * as wasm from '../pkg/swap_wasm.js';

/** Loads the module: in a browser from its URL beside this one, or from
 * `bytes` given, as Node does. */
export async function load(bytes) {
  if (bytes === undefined) await init();
  else initSync({ module: bytes });
}

/** `wasm[name]` on `input` as JSON (a string as it is, null or undefined
 * as none), its JSON answer parsed. Amounts
 * beyond 2^53 do not survive a JavaScript number: a driver refuses an
 * offer that holds one ({@link safe}), so none reaches a state. */
export function call(name, ...input) {
  const args = input.map((value) =>
    typeof value === 'string' || value === null || value === undefined ? value ?? undefined : JSON.stringify(value),
  );
  const answer = wasm[name](...args);
  return answer === undefined || answer === null ? null : JSON.parse(answer);
}

/** Whether every number in `value` is an integer JavaScript holds exactly. */
export function safe(value) {
  if (typeof value === 'number') return Number.isSafeInteger(value);
  if (value && typeof value === 'object') return Object.values(value).every(safe);
  return true;
}

export { wasm };
