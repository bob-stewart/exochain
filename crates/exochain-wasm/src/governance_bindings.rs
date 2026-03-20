//! WASM bindings for the exo-governance decision lifecycle.
//!
//! Exposes decision creation, status advancement, vote casting, quorum
//! checking, valid transition queries, and terminal status checks.

use crate::serde_bridge;
use exo_core::crypto::Blake3Hash;
use exo_core::hlc::HybridLogicalClock;
use exo_governance::decision::{
    DecisionObject, DecisionStatus, QuorumSpec, Vote, VoteChoice,
};
use exo_governance::quorum::verify_quorum;
use exo_governance::types::*;
use serde::{Deserialize, Serialize};
use wasm_bindgen::prelude::*;

// ---------------------------------------------------------------------------
// Serde intermediate types
// ---------------------------------------------------------------------------

/// Minimal input for creating a new decision object.
#[derive(Deserialize)]
struct CreateDecisionInput {
    tenant_id: String,
    title: String,
    body: Option<Vec<u8>>,
    decision_class: String,
    constitution_hash: String,
    constitution_version: [u32; 3],
    author: String,
    eligible_voters: Vec<String>,
    minimum_participants: u32,
    approval_threshold_pct: u32,
}

/// Minimal input for advancing a decision.
#[derive(Deserialize)]
struct AdvanceDecisionInput {
    new_status: String,
    actor: String,
    reason: Option<String>,
    timestamp_ms: u64,
}

/// Minimal input for casting a vote.
#[derive(Deserialize)]
struct CastVoteInput {
    voter: String,
    choice: String,
    rationale: Option<String>,
    timestamp_ms: u64,
    is_ai: Option<bool>,
    delegation_id_hex: Option<String>,
    delegation_expires_at: Option<u64>,
}

/// Minimal input for quorum check.
#[derive(Deserialize)]
struct CheckQuorumInput {
    eligible_voters: Vec<String>,
    present_voters: Vec<String>,
    minimum_participants: u32,
}

#[derive(Serialize)]
struct QuorumResult {
    eligible_count: u32,
    present_count: u32,
    required_count: u32,
    is_met: bool,
    absent_members: Vec<String>,
}

#[derive(Serialize)]
struct TransitionResult {
    valid_transitions: Vec<String>,
}

#[derive(Serialize)]
struct TerminalResult {
    is_terminal: bool,
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn parse_status(s: &str) -> Result<DecisionStatus, JsError> {
    match s {
        "Created" => Ok(DecisionStatus::Created),
        "Deliberation" => Ok(DecisionStatus::Deliberation),
        "Voting" => Ok(DecisionStatus::Voting),
        "Approved" => Ok(DecisionStatus::Approved),
        "Rejected" => Ok(DecisionStatus::Rejected),
        "Void" => Ok(DecisionStatus::Void),
        "Contested" => Ok(DecisionStatus::Contested),
        "RatificationRequired" => Ok(DecisionStatus::RatificationRequired),
        "RatificationExpired" => Ok(DecisionStatus::RatificationExpired),
        "DegradedGovernance" => Ok(DecisionStatus::DegradedGovernance),
        other => Err(JsError::new(&format!("Unknown status: {other}"))),
    }
}

fn status_name(s: &DecisionStatus) -> &'static str {
    match s {
        DecisionStatus::Created => "Created",
        DecisionStatus::Deliberation => "Deliberation",
        DecisionStatus::Voting => "Voting",
        DecisionStatus::Approved => "Approved",
        DecisionStatus::Rejected => "Rejected",
        DecisionStatus::Void => "Void",
        DecisionStatus::Contested => "Contested",
        DecisionStatus::RatificationRequired => "RatificationRequired",
        DecisionStatus::RatificationExpired => "RatificationExpired",
        DecisionStatus::DegradedGovernance => "DegradedGovernance",
    }
}

fn parse_decision_class(s: &str) -> DecisionClass {
    match s {
        "Operational" => DecisionClass::Operational,
        "Strategic" => DecisionClass::Strategic,
        "Constitutional" => DecisionClass::Constitutional,
        "Emergency" => DecisionClass::Emergency,
        other => DecisionClass::Custom(other.to_string()),
    }
}

fn parse_vote_choice(s: &str) -> Result<VoteChoice, JsError> {
    match s {
        "Approve" => Ok(VoteChoice::Approve),
        "Reject" => Ok(VoteChoice::Reject),
        "Abstain" => Ok(VoteChoice::Abstain),
        other => Err(JsError::new(&format!("Unknown vote choice: {other}"))),
    }
}

fn hex_to_blake3(hex: &str) -> Result<Blake3Hash, JsError> {
    let bytes = hex::decode(hex)
        .map_err(|e| JsError::new(&format!("Invalid hex: {e}")))?;
    let arr: [u8; 32] = bytes
        .try_into()
        .map_err(|_| JsError::new("Hash must be 32 bytes"))?;
    Ok(Blake3Hash(arr))
}

/// Create a dummy governance signature for WASM-side operations.
/// In production, signatures are computed client-side and verified server-side.
fn placeholder_governance_sig(signer: &str, timestamp_ms: u64) -> GovernanceSignature {
    // Use a zeroed-out signature as placeholder; real signing happens in
    // core_bindings::wasm_compute_signature.
    GovernanceSignature {
        signer: signer.to_string(),
        signer_type: SignerType::Human,
        signature: ed25519_dalek::Signature::from_bytes(&[0u8; 64]),
        key_version: 1,
        timestamp: HybridLogicalClock {
            physical_ms: timestamp_ms,
            logical: 0,
        },
    }
}

// ---------------------------------------------------------------------------
// WASM exports
// ---------------------------------------------------------------------------

/// Create a new DecisionObject in the `Created` status.
///
/// **Input:** JSON with fields: `tenant_id`, `title`, `body?`, `decision_class`,
///   `constitution_hash` (hex), `constitution_version` ([major, minor, patch]),
///   `author`, `eligible_voters`, `minimum_participants`, `approval_threshold_pct`.
///
/// **Output:** JSON-serialized `DecisionObject`.
#[wasm_bindgen]
pub fn wasm_create_decision(input_json: &str) -> Result<JsValue, JsError> {
    let input: CreateDecisionInput = serde_bridge::from_json_str(input_json)?;
    let constitution_hash = hex_to_blake3(&input.constitution_hash)?;

    // Compute a content-addressed ID from the title + timestamp
    let id_bytes = exo_core::crypto::hash_bytes(
        format!("{}:{}:{}", input.tenant_id, input.title, input.author).as_bytes(),
    );

    let now = HybridLogicalClock {
        physical_ms: js_sys::Date::now() as u64,
        logical: 0,
    };

    let decision = DecisionObject {
        id: id_bytes,
        tenant_id: input.tenant_id,
        status: DecisionStatus::Created,
        title: input.title,
        body: input.body.unwrap_or_default(),
        decision_class: parse_decision_class(&input.decision_class),
        constitution_hash,
        constitution_version: SemVer::new(
            input.constitution_version[0],
            input.constitution_version[1],
            input.constitution_version[2],
        ),
        author: input.author,
        created_at: now,
        delegations_snapshot: vec![],
        evidence: vec![],
        conflicts_disclosed: vec![],
        votes: vec![],
        quorum_requirement: QuorumSpec {
            minimum_participants: input.minimum_participants,
            approval_threshold_pct: input.approval_threshold_pct,
            eligible_voters: input.eligible_voters,
        },
        parent_decisions: vec![],
        challenge_ids: vec![],
        signatures: vec![],
        transition_log: vec![],
        crosscheck_reports: vec![],
        clearance_certificates: vec![],
        anchor_receipts: vec![],
    };

    serde_bridge::to_js_value(&decision)
}

/// Advance a decision to a new lifecycle status.
///
/// **Inputs:**
/// - `decision_json`: JSON-serialized `DecisionObject`
/// - `advance_json`: JSON with `new_status`, `actor`, `reason?`, `timestamp_ms`
///
/// **Output:** JSON-serialized updated `DecisionObject`.
#[wasm_bindgen]
pub fn wasm_advance_decision(
    decision_json: &str,
    advance_json: &str,
) -> Result<JsValue, JsError> {
    let mut decision: DecisionObject = serde_bridge::from_json_str(decision_json)?;
    let input: AdvanceDecisionInput = serde_bridge::from_json_str(advance_json)?;

    let new_status = parse_status(&input.new_status)?;
    let sig = placeholder_governance_sig(&input.actor, input.timestamp_ms);
    let timestamp = HybridLogicalClock {
        physical_ms: input.timestamp_ms,
        logical: 0,
    };

    decision
        .advance(new_status, input.actor, input.reason, sig, timestamp)
        .map_err(|e| JsError::new(&format!("Advance failed: {e:?}")))?;

    serde_bridge::to_js_value(&decision)
}

/// Cast a vote on a decision that is in `Voting` status.
///
/// **Inputs:**
/// - `decision_json`: JSON-serialized `DecisionObject`
/// - `vote_json`: JSON with `voter`, `choice` (Approve|Reject|Abstain),
///   `rationale?`, `timestamp_ms`, `is_ai?`, `delegation_id_hex?`,
///   `delegation_expires_at?`
///
/// **Output:** JSON-serialized updated `DecisionObject`.
#[wasm_bindgen]
pub fn wasm_cast_vote(
    decision_json: &str,
    vote_json: &str,
) -> Result<JsValue, JsError> {
    let mut decision: DecisionObject = serde_bridge::from_json_str(decision_json)?;
    let input: CastVoteInput = serde_bridge::from_json_str(vote_json)?;

    let signer_type = if input.is_ai.unwrap_or(false) {
        let delegation_id = input
            .delegation_id_hex
            .as_deref()
            .map(hex_to_blake3)
            .transpose()?
            .unwrap_or(Blake3Hash([0u8; 32]));
        SignerType::AiAgent {
            delegation_id,
            expires_at: input.delegation_expires_at.unwrap_or(0),
        }
    } else {
        SignerType::Human
    };

    let vote = Vote {
        voter: input.voter,
        signer_type,
        choice: parse_vote_choice(&input.choice)?,
        rationale: input.rationale,
        signature: placeholder_governance_sig("vote-sig", input.timestamp_ms),
        timestamp: HybridLogicalClock {
            physical_ms: input.timestamp_ms,
            logical: 0,
        },
    };

    decision
        .cast_vote(vote)
        .map_err(|e| JsError::new(&format!("Vote failed: {e:?}")))?;

    serde_bridge::to_js_value(&decision)
}

/// Check whether quorum is met given eligible and present voter sets.
///
/// **Input:** JSON with `eligible_voters`, `present_voters`, `minimum_participants`
///
/// **Output:** JSON with `eligible_count`, `present_count`, `required_count`,
///   `is_met`, `absent_members`.
#[wasm_bindgen]
pub fn wasm_check_quorum(input_json: &str) -> Result<JsValue, JsError> {
    let input: CheckQuorumInput = serde_bridge::from_json_str(input_json)?;

    match verify_quorum(
        &input.eligible_voters,
        &input.present_voters,
        input.minimum_participants,
    ) {
        Ok(v) => {
            let result = QuorumResult {
                eligible_count: v.eligible_count,
                present_count: v.present_count,
                required_count: v.required_count,
                is_met: v.is_met,
                absent_members: v.absent_members,
            };
            serde_bridge::to_js_value(&result)
        }
        Err(_) => {
            // Quorum not met — still return structured data
            let present_count = input
                .present_voters
                .iter()
                .filter(|p| input.eligible_voters.contains(p))
                .count() as u32;
            let absent: Vec<String> = input
                .eligible_voters
                .iter()
                .filter(|e| !input.present_voters.contains(e))
                .cloned()
                .collect();
            let result = QuorumResult {
                eligible_count: input.eligible_voters.len() as u32,
                present_count,
                required_count: input.minimum_participants,
                is_met: false,
                absent_members: absent,
            };
            serde_bridge::to_js_value(&result)
        }
    }
}

/// Return the list of valid next statuses from a given status.
///
/// **Input:** status name string (e.g. `"Created"`, `"Voting"`)
/// **Output:** JSON `{ "valid_transitions": ["Deliberation", "Void"] }`
#[wasm_bindgen]
pub fn wasm_valid_transitions(status_str: &str) -> Result<JsValue, JsError> {
    let status = parse_status(status_str)?;
    let transitions: Vec<String> = status
        .valid_transitions()
        .iter()
        .map(|s| status_name(s).to_string())
        .collect();
    let result = TransitionResult {
        valid_transitions: transitions,
    };
    serde_bridge::to_js_value(&result)
}

/// Check whether a status is terminal (immutable).
///
/// **Input:** status name string
/// **Output:** JSON `{ "is_terminal": true|false }`
#[wasm_bindgen]
pub fn wasm_is_terminal(status_str: &str) -> Result<JsValue, JsError> {
    let status = parse_status(status_str)?;
    let result = TerminalResult {
        is_terminal: status.is_terminal(),
    };
    serde_bridge::to_js_value(&result)
}
