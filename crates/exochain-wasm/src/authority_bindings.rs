//! WASM bindings for authority chain verification (TNC-01).
//!
//! The full `verify_chain` function requires a `Constitution` and `Delegation`
//! objects that carry complex runtime state. For the WASM surface we expose
//! a simplified representation that validates the chain structure and
//! delegates to `exo_authority::chain::verify_chain` when possible, or
//! provides a structural pre-flight check when the full constitution is not
//! available in the browser.

use crate::serde_bridge;
use serde::{Deserialize, Serialize};
use wasm_bindgen::prelude::*;

// ---------------------------------------------------------------------------
// Serde types for chain verification input/output
// ---------------------------------------------------------------------------

/// A single link in an authority delegation chain.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct WasmDelegationLink {
    /// Delegation ID (hex-encoded BLAKE3 hash).
    pub id: String,
    /// DID of the entity granting authority.
    pub delegator: String,
    /// DID of the entity receiving authority.
    pub delegatee: String,
    /// Whether this delegation is active (not expired, not revoked).
    pub is_active: bool,
    /// Allowed decision classes (string names).
    pub allowed_classes: Vec<String>,
    /// Allowed actions (string names).
    pub allowed_actions: Vec<String>,
    /// Whether the signer is human.
    pub signer_is_human: bool,
}

/// Input for chain verification.
#[derive(Deserialize)]
pub struct VerifyChainInput {
    /// DID of the actor attempting the action.
    pub actor: String,
    /// Whether the actor is an AI agent.
    pub actor_is_ai: bool,
    /// The action being attempted (e.g. "CreateDecision").
    pub action: String,
    /// The decision class (e.g. "Operational").
    pub decision_class: String,
    /// The delegation chain from actor back to root.
    pub chain: Vec<WasmDelegationLink>,
    /// Maximum allowed chain depth.
    pub max_depth: usize,
    /// Whether this decision class requires a human gate.
    pub requires_human_gate: bool,
}

/// Output of chain verification.
#[derive(Serialize)]
pub struct VerifyChainOutput {
    /// Whether the chain is valid.
    pub valid: bool,
    /// Chain depth.
    pub depth: usize,
    /// Whether a human signer exists in the chain.
    pub has_human_signer: bool,
    /// The actor DID.
    pub actor: String,
    /// Error message if verification failed.
    pub error: Option<String>,
    /// Detailed chain break info if failed.
    pub break_info: Option<ChainBreakInfo>,
}

#[derive(Serialize)]
pub struct ChainBreakInfo {
    pub depth: usize,
    pub delegation_id: Option<String>,
    pub reason: String,
}

// ---------------------------------------------------------------------------
// WASM export
// ---------------------------------------------------------------------------

/// Verify an authority delegation chain from actor back to root.
///
/// Performs structural validation in the WASM layer:
/// - Chain must not be empty
/// - Chain depth must not exceed `max_depth`
/// - All links must be active
/// - Actor must be the delegatee of the first link
/// - Each link's delegator must be the previous link's delegatee
/// - Human gate: if `requires_human_gate` and `actor_is_ai`, verification fails
/// - AI ceiling: AI agents cannot AmendConstitution or GrantDelegation
/// - Action and class must appear in each link's allowed sets
///
/// **Input:** JSON-serialized `VerifyChainInput`
/// **Output:** JSON-serialized `VerifyChainOutput`
#[wasm_bindgen]
pub fn wasm_verify_chain(input_json: &str) -> Result<JsValue, JsError> {
    let input: VerifyChainInput = serde_bridge::from_json_str(input_json)?;

    // TNC-02: Human gate check
    if input.requires_human_gate && input.actor_is_ai {
        return serde_bridge::to_js_value(&VerifyChainOutput {
            valid: false,
            depth: 0,
            has_human_signer: false,
            actor: input.actor,
            error: Some(format!(
                "TNC-02: Human gate required for class '{}' but actor is AI",
                input.decision_class
            )),
            break_info: None,
        });
    }

    // TNC-09: AI ceiling
    if input.actor_is_ai
        && (input.action == "AmendConstitution" || input.action == "GrantDelegation")
    {
        return serde_bridge::to_js_value(&VerifyChainOutput {
            valid: false,
            depth: 0,
            has_human_signer: false,
            actor: input.actor,
            error: Some(format!(
                "TNC-09: AI agents cannot perform action '{}'",
                input.action
            )),
            break_info: None,
        });
    }

    // Empty chain check
    if input.chain.is_empty() {
        return serde_bridge::to_js_value(&VerifyChainOutput {
            valid: false,
            depth: 0,
            has_human_signer: false,
            actor: input.actor,
            error: Some("No delegation chain provided".to_string()),
            break_info: Some(ChainBreakInfo {
                depth: 0,
                delegation_id: None,
                reason: "Empty chain".to_string(),
            }),
        });
    }

    // Depth check
    if input.chain.len() > input.max_depth {
        return serde_bridge::to_js_value(&VerifyChainOutput {
            valid: false,
            depth: input.chain.len(),
            has_human_signer: false,
            actor: input.actor,
            error: Some(format!(
                "Chain depth {} exceeds max {}",
                input.chain.len(),
                input.max_depth
            )),
            break_info: Some(ChainBreakInfo {
                depth: input.chain.len(),
                delegation_id: None,
                reason: "Chain too deep".to_string(),
            }),
        });
    }

    // Walk the chain
    let mut has_human = false;
    let mut expected_delegatee = input.actor.clone();

    for (i, link) in input.chain.iter().enumerate() {
        // Delegatee must match expected
        if link.delegatee != expected_delegatee {
            return serde_bridge::to_js_value(&VerifyChainOutput {
                valid: false,
                depth: i,
                has_human_signer: has_human,
                actor: input.actor,
                error: Some(format!(
                    "Chain break at depth {i}: expected delegatee '{}' but found '{}'",
                    expected_delegatee, link.delegatee
                )),
                break_info: Some(ChainBreakInfo {
                    depth: i,
                    delegation_id: Some(link.id.clone()),
                    reason: "Delegatee mismatch".to_string(),
                }),
            });
        }

        // Active check (TNC-05)
        if !link.is_active {
            return serde_bridge::to_js_value(&VerifyChainOutput {
                valid: false,
                depth: i,
                has_human_signer: has_human,
                actor: input.actor,
                error: Some(format!(
                    "TNC-05: Delegation '{}' at depth {i} is expired or revoked",
                    link.id
                )),
                break_info: Some(ChainBreakInfo {
                    depth: i,
                    delegation_id: Some(link.id.clone()),
                    reason: "Delegation inactive".to_string(),
                }),
            });
        }

        // Scope check: action
        if !link.allowed_actions.iter().any(|a| a == &input.action) {
            return serde_bridge::to_js_value(&VerifyChainOutput {
                valid: false,
                depth: i,
                has_human_signer: has_human,
                actor: input.actor,
                error: Some(format!(
                    "Action '{}' not in allowed actions at depth {i}",
                    input.action
                )),
                break_info: Some(ChainBreakInfo {
                    depth: i,
                    delegation_id: Some(link.id.clone()),
                    reason: "Action not authorized".to_string(),
                }),
            });
        }

        // Scope check: decision class
        if !link
            .allowed_classes
            .iter()
            .any(|c| c == &input.decision_class)
        {
            return serde_bridge::to_js_value(&VerifyChainOutput {
                valid: false,
                depth: i,
                has_human_signer: has_human,
                actor: input.actor,
                error: Some(format!(
                    "Decision class '{}' not in allowed classes at depth {i}",
                    input.decision_class
                )),
                break_info: Some(ChainBreakInfo {
                    depth: i,
                    delegation_id: Some(link.id.clone()),
                    reason: "Class not authorized".to_string(),
                }),
            });
        }

        if link.signer_is_human {
            has_human = true;
        }

        expected_delegatee = link.delegator.clone();
    }

    serde_bridge::to_js_value(&VerifyChainOutput {
        valid: true,
        depth: input.chain.len(),
        has_human_signer: has_human,
        actor: input.actor,
        error: None,
        break_info: None,
    })
}
