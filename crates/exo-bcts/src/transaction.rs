//! BCTS transaction types and lifecycle operations.
//!
//! Each transaction carries an [`EventEnvelope`] with the proposed action,
//! a correlation ID (SHA-256 of canonical content), and produces [`LedgerEvent`]s
//! recording every state transition with proof hashes.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::states::{can_transition, is_terminal, BctsState};

/// Event envelope — carries the proposed action through the pipeline
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EventEnvelope {
    pub id: String,
    pub correlation_id: String,
    pub actor_did: String,
    pub action: String,
    pub payload: serde_json::Value,
    pub timestamp: DateTime<Utc>,
    pub parent_ids: Vec<String>,
    pub signature: Option<String>,
    pub signer_type: SignerType,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SignerType {
    Human,
    Ai,
}

/// A ledger event recording a state transition
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LedgerEvent {
    pub id: String,
    pub transaction_id: String,
    pub from_state: BctsState,
    pub to_state: BctsState,
    pub actor_did: String,
    pub timestamp: DateTime<Utc>,
    pub evidence: Option<String>,
    pub proof_hash: String,
}

/// A BCTS transaction flowing through the pipeline
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BctsTransaction {
    pub id: String,
    pub state: BctsState,
    pub envelope: EventEnvelope,
    pub ledger: Vec<LedgerEvent>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub metadata: serde_json::Value,
}

/// Create a new transaction in Draft state
pub fn create_transaction(
    actor_did: &str,
    action: &str,
    payload: serde_json::Value,
    signer_type: SignerType,
    parent_ids: Vec<String>,
) -> BctsTransaction {
    let id = Uuid::new_v4().to_string();
    let now = Utc::now();

    let canonical = serde_json::json!({
        "actor_did": actor_did,
        "action": action,
        "payload": payload,
        "timestamp": now.to_rfc3339(),
        "parent_ids": parent_ids,
    });
    let correlation_id = hex::encode(Sha256::digest(canonical.to_string().as_bytes()));

    let envelope = EventEnvelope {
        id: Uuid::new_v4().to_string(),
        correlation_id,
        actor_did: actor_did.to_string(),
        action: action.to_string(),
        payload: payload.clone(),
        timestamp: now,
        parent_ids,
        signature: None,
        signer_type,
    };

    BctsTransaction {
        id,
        state: BctsState::Draft,
        envelope,
        ledger: Vec::new(),
        created_at: now,
        updated_at: now,
        metadata: serde_json::Value::Null,
    }
}

/// Transition a transaction to a new state
pub fn transition(
    tx: &BctsTransaction,
    to_state: BctsState,
    actor_did: &str,
    evidence: Option<&str>,
) -> Result<BctsTransaction, String> {
    if is_terminal(tx.state) {
        return Err(format!("transaction {} is in terminal state: {}", tx.id, tx.state));
    }
    if !can_transition(tx.state, to_state) {
        return Err(format!("invalid transition: {} -> {} for transaction {}", tx.state, to_state, tx.id));
    }

    let now = Utc::now();
    let proof_data = format!("{}|{}|{}|{}|{}", tx.id, tx.state, to_state, actor_did, now.to_rfc3339());
    let proof_hash = hex::encode(Sha256::digest(proof_data.as_bytes()));

    let event = LedgerEvent {
        id: Uuid::new_v4().to_string(),
        transaction_id: tx.id.clone(),
        from_state: tx.state,
        to_state,
        actor_did: actor_did.to_string(),
        timestamp: now,
        evidence: evidence.map(String::from),
        proof_hash,
    };

    let mut new_tx = tx.clone();
    new_tx.state = to_state;
    new_tx.ledger.push(event);
    new_tx.updated_at = now;
    Ok(new_tx)
}

/// Verify the entire ledger chain is consistent
pub fn verify_ledger(tx: &BctsTransaction) -> bool {
    let mut expected = BctsState::Draft;
    for event in &tx.ledger {
        if event.from_state != expected {
            return false;
        }
        if !can_transition(event.from_state, event.to_state) {
            return false;
        }
        expected = event.to_state;
    }
    expected == tx.state
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_create_in_draft() {
        let tx = create_transaction("did:user:1", "submit:screener", serde_json::json!({}), SignerType::Human, vec![]);
        assert_eq!(tx.state, BctsState::Draft);
        assert!(tx.ledger.is_empty());
    }

    #[test]
    fn test_valid_transition() {
        let tx = create_transaction("did:user:1", "submit", serde_json::json!({}), SignerType::Human, vec![]);
        let tx2 = transition(&tx, BctsState::Submitted, "did:user:1", None).unwrap();
        assert_eq!(tx2.state, BctsState::Submitted);
        assert_eq!(tx2.ledger.len(), 1);
    }

    #[test]
    fn test_invalid_transition() {
        let tx = create_transaction("did:user:1", "submit", serde_json::json!({}), SignerType::Human, vec![]);
        assert!(transition(&tx, BctsState::Closed, "did:user:1", None).is_err());
    }

    #[test]
    fn test_verify_ledger() {
        let tx = create_transaction("did:user:1", "submit", serde_json::json!({}), SignerType::Human, vec![]);
        let tx = transition(&tx, BctsState::Submitted, "did:user:1", None).unwrap();
        let tx = transition(&tx, BctsState::IdentityResolved, "did:user:1", None).unwrap();
        assert!(verify_ledger(&tx));
    }
}
