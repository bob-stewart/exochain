// @exoeth/exochain-wasm — Lazy-init wrapper for ExoChain WASM bindings
// Usage: import { wasm, init } from '@exoeth/exochain-wasm';

import * as wasmModule from './wasm/exochain_wasm.js';

let initialized = false;

export async function init() {
  if (!initialized) {
    // wasm-bindgen nodejs target auto-initializes, but we track it
    initialized = true;
  }
  return wasmModule;
}

// Re-export all WASM functions for direct use
export const {
  wasm_hash_bytes,
  wasm_generate_keypair,
  wasm_compute_signature,
  wasm_verify_signature,
  wasm_reduce_combinator,
  wasm_create_decision,
  wasm_valid_transitions,
  wasm_check_quorum,
  wasm_enforce_tncs,
  wasm_create_genesis_decision,
  wasm_create_authenticated_record,
  wasm_detect_anomalies,
  wasm_evaluate_policy,
  wasm_verify_chain,
} = wasmModule;

export default wasmModule;
