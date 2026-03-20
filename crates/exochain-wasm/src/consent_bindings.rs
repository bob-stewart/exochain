//! WASM bindings for consent policy evaluation.
//!
//! Exposes the `exo_consent::policy::Policy` matching logic to JavaScript,
//! allowing browser-side consent checks. Supports both simple matching
//! (no group resolution) and group-aware matching (with a static group
//! resolver provided as JSON).

use crate::serde_bridge;
use exo_consent::policy::{AccessorSet, Effect, Policy, Condition, StaticGroupResolver};
use serde::{Deserialize, Serialize};
use wasm_bindgen::prelude::*;
use std::collections::HashMap;

// ---------------------------------------------------------------------------
// Serde types
// ---------------------------------------------------------------------------

/// JSON-friendly representation of a consent policy.
#[derive(Deserialize)]
struct WasmPolicy {
    id: String,
    description: String,
    effect: String,
    subjects: WasmAccessorSet,
    resources: Vec<String>,
    #[serde(default)]
    conditions: Vec<WasmCondition>,
}

#[derive(Deserialize)]
#[serde(tag = "type")]
enum WasmAccessorSet {
    Any,
    Specific { dids: Vec<String> },
    Group { group_id: String },
}

#[derive(Deserialize)]
struct WasmCondition {
    #[serde(rename = "type")]
    type_: String,
    value: String,
}

/// Input for policy evaluation.
#[derive(Deserialize)]
struct EvaluatePolicyInput {
    /// Policies to evaluate (first-match-wins).
    policies: Vec<WasmPolicy>,
    /// Subject DID requesting access.
    subject: String,
    /// Resource being accessed.
    resource: String,
    /// Optional group memberships: group_id -> list of member DIDs.
    #[serde(default)]
    groups: HashMap<String, Vec<String>>,
}

#[derive(Serialize)]
struct EvaluatePolicyOutput {
    /// "Allow", "Deny", or "NoMatch"
    decision: String,
    /// ID of the matching policy, if any.
    matched_policy_id: Option<String>,
    /// Description of the matching policy.
    matched_policy_description: Option<String>,
}

// ---------------------------------------------------------------------------
// Converters
// ---------------------------------------------------------------------------

fn convert_policy(wp: &WasmPolicy) -> Policy {
    let effect = match wp.effect.as_str() {
        "Allow" => Effect::Allow,
        _ => Effect::Deny,
    };
    let subjects = match &wp.subjects {
        WasmAccessorSet::Any => AccessorSet::Any,
        WasmAccessorSet::Specific { dids } => AccessorSet::Specific(dids.clone()),
        WasmAccessorSet::Group { group_id } => AccessorSet::Group(group_id.clone()),
    };
    let conditions: Vec<Condition> = wp
        .conditions
        .iter()
        .map(|c| Condition {
            type_: c.type_.clone(),
            value: c.value.clone(),
        })
        .collect();

    Policy {
        id: wp.id.clone(),
        description: wp.description.clone(),
        effect,
        subjects,
        resources: wp.resources.clone(),
        conditions,
    }
}

// ---------------------------------------------------------------------------
// WASM export
// ---------------------------------------------------------------------------

/// Evaluate a set of consent policies against a subject/resource pair.
///
/// Uses first-match-wins semantics: the first policy whose subject and
/// resource patterns match determines the outcome. If group memberships
/// are provided, group-based accessor sets are resolved.
///
/// **Input:** JSON-serialized `EvaluatePolicyInput` with fields:
///   - `policies`: array of policy objects
///   - `subject`: DID of the requesting entity
///   - `resource`: resource identifier
///   - `groups`: optional map of group_id -> member DID arrays
///
/// **Output:** JSON `{ "decision": "Allow"|"Deny"|"NoMatch",
///   "matched_policy_id": "...", "matched_policy_description": "..." }`
#[wasm_bindgen]
pub fn wasm_evaluate_policy(input_json: &str) -> Result<JsValue, JsError> {
    let input: EvaluatePolicyInput = serde_bridge::from_json_str(input_json)?;

    let policies: Vec<Policy> = input.policies.iter().map(convert_policy).collect();

    // Build group resolver if groups provided
    let has_groups = !input.groups.is_empty();
    let resolver = if has_groups {
        let mut r = StaticGroupResolver::new();
        for (group_id, members) in &input.groups {
            for member in members {
                r.add_member(group_id, member.clone());
            }
        }
        Some(r)
    } else {
        None
    };

    // First-match-wins evaluation
    for (i, policy) in policies.iter().enumerate() {
        let matches = if let Some(ref r) = resolver {
            policy.is_match_with_resolver(&input.subject, &input.resource, r)
        } else {
            policy.is_match(&input.subject, &input.resource)
        };

        if matches {
            let wp = &input.policies[i];
            let decision = match policy.effect {
                Effect::Allow => "Allow",
                Effect::Deny => "Deny",
            };
            return serde_bridge::to_js_value(&EvaluatePolicyOutput {
                decision: decision.to_string(),
                matched_policy_id: Some(wp.id.clone()),
                matched_policy_description: Some(wp.description.clone()),
            });
        }
    }

    // No policy matched
    serde_bridge::to_js_value(&EvaluatePolicyOutput {
        decision: "NoMatch".to_string(),
        matched_policy_id: None,
        matched_policy_description: None,
    })
}
