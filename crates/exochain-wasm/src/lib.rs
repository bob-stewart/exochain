//! ExoChain WASM Bindings
//!
//! Provides a WebAssembly interface to the ExoChain governance engine,
//! exposing the full stack: cryptographic primitives, combinator graph
//! reduction, decision lifecycle, authority chain verification, consent
//! policy evaluation, legal records, escalation detection, and the
//! decision.forum TNC enforcer.
//!
//! All public functions accept JSON strings via `&str` and return
//! `Result<JsValue, JsError>` or `Result<String, JsError>` for
//! structured outputs.

use wasm_bindgen::prelude::*;

pub mod serde_bridge;

pub mod core_bindings;
pub mod combinator_bindings;
pub mod governance_bindings;
pub mod authority_bindings;
pub mod consent_bindings;
pub mod legal_bindings;
pub mod escalation_bindings;
pub mod decision_forum_bindings;

// Re-export all wasm_bindgen-annotated functions so they appear at the
// top level of the WASM module.
pub use core_bindings::*;
pub use combinator_bindings::*;
pub use governance_bindings::*;
pub use authority_bindings::*;
pub use consent_bindings::*;
pub use legal_bindings::*;
pub use escalation_bindings::*;
pub use decision_forum_bindings::*;
