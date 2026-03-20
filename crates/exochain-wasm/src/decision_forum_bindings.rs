//! WASM bindings for the decision.forum protocol layer.
//!
//! Exposes the TNC enforcer (all 10 Trust-Critical Non-Negotiable Controls)
//! and genesis decision creation from the `decision-forum` crate.

use crate::serde_bridge;
use decision_forum::decision_object::DecisionObject as ForumDecisionObject;
use decision_forum::tnc_enforcer::TNCEnforcer;
use serde::{Deserialize, Serialize};
use wasm_bindgen::prelude::*;

// ---------------------------------------------------------------------------
// Serde types
// ---------------------------------------------------------------------------

/// Input for TNC enforcement — a decision-forum DecisionObject serialized as JSON.
/// The decision-forum crate's DecisionObject derives Serialize/Deserialize,
/// so we can deserialize it directly.
#[derive(Deserialize)]
struct EnforceTncsInput {
    /// The decision object to validate.
    decision: ForumDecisionObject,
}

#[derive(Serialize)]
struct EnforceTncsOutput {
    /// Whether all 10 TNC controls passed.
    valid: bool,
    /// Error message if any TNC control failed.
    error: Option<String>,
}

#[derive(Serialize)]
struct GenesisDecisionOutput {
    /// The newly created decision object.
    decision: ForumDecisionObject,
}

// ---------------------------------------------------------------------------
// WASM exports
// ---------------------------------------------------------------------------

/// Enforce all 10 Trust-Critical Non-Negotiable Controls on a decision object.
///
/// This runs the full TNC enforcement suite from the decision-forum layer:
///   TNC-01: Authority chain integrity
///   TNC-02: Human gate for strategic/constitutional decisions
///   TNC-03: Audit trail continuity
///   TNC-04: Constitutional binding (sync constraints)
///   TNC-05: Delegation expiry enforcement
///   TNC-06: Conflict disclosure requirement
///   TNC-07: Quorum verification
///   TNC-08: Terminal immutability (merkle root + evidence)
///   TNC-09: AI agent ceiling enforcement
///   TNC-10: Ratification deadline enforcement
///
/// **Input:** JSON `{ "decision": { ... } }` where `decision` is a
///   decision-forum `DecisionObject`.
///
/// **Output:** JSON `{ "valid": true|false, "error": "..." }`
#[wasm_bindgen]
pub fn wasm_enforce_tncs(input_json: &str) -> Result<JsValue, JsError> {
    let input: EnforceTncsInput = serde_bridge::from_json_str(input_json)?;

    match TNCEnforcer::enforce_all(&input.decision) {
        Ok(()) => serde_bridge::to_js_value(&EnforceTncsOutput {
            valid: true,
            error: None,
        }),
        Err(msg) => serde_bridge::to_js_value(&EnforceTncsOutput {
            valid: false,
            error: Some(msg),
        }),
    }
}

/// Create a genesis decision object with sensible defaults.
///
/// Uses `DecisionObject::new(title)` from the decision-forum crate, which
/// initializes a decision in Draft status with a genesis authority chain,
/// audit sequence = 1, and a SHA-256 merkle root derived from the title.
///
/// **Input:** `title` — the human-readable title of the decision
///
/// **Output:** JSON-serialized decision-forum `DecisionObject`.
#[wasm_bindgen]
pub fn wasm_create_genesis_decision(title: &str) -> Result<JsValue, JsError> {
    let decision = ForumDecisionObject::new(title);
    serde_bridge::to_js_value(&GenesisDecisionOutput { decision })
}
