//! CustodyEvent — chain of responsibility tracking for decision.forum
//!
//! Per the decision.forum whitepaper: "who did what, when, optionally signed."
//! CustodyEvents form an append-only log of all actions taken on a DecisionRecord,
//! creating a complete chain of responsibility.
//!
//! Satisfies: GOV-005 (authority chain), TNC-03 (audit continuity), LEG-001 (business records)

use crate::types::*;
use exo_core::crypto::Blake3Hash;
use exo_core::hlc::HybridLogicalClock;
use serde::{Deserialize, Serialize};

/// Actions that produce CustodyEvents.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum CustodyAction {
    /// Record created.
    Create,
    /// Record edited (context, decision, or consequences modified).
    Edit,
    /// CrosscheckReport attached.
    AttachCrosscheck { report_id: String },
    /// Attestation: approval.
    Approve,
    /// Attestation: rejection.
    Reject,
    /// Attestation: abstention.
    Abstain,
    /// Veto exercised (if policy allows).
    Veto,
    /// Clearance certificate issued.
    IssueClearance { certificate_id: String },
    /// Record anchored to immutable store (EXOCHAIN).
    Anchor { receipt_id: String },
    /// Status advanced in lifecycle.
    AdvanceStatus { from: String, to: String },
    /// Record superseded by a new record.
    Supersede { successor_id: String },
    /// Record deprecated.
    Deprecate,
    /// Emergency action taken.
    EmergencyAction { reason: String },
    /// Challenge filed.
    Challenge { challenge_id: String },
    /// Comment or note added.
    Comment { content: String },
    /// Custom action.
    Custom { action: String, metadata: Option<String> },
}

/// Role of the actor performing the custody action.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum CustodyRole {
    /// Decision proposer/author.
    Proposer,
    /// Reviewer with attestation authority.
    Reviewer,
    /// Steward with elevated authority.
    Steward,
    /// Observer (read-only, but may comment).
    Observer,
    /// System/automated process.
    System,
    /// AI agent acting under delegation.
    AiAgent { delegation_id: Blake3Hash },
    /// Custom role.
    Custom(String),
}

/// A single custody event in the chain of responsibility.
///
/// Per whitepaper: CustodyEvents include actor_id, role, action, time,
/// and optionally a signature over the record hash.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CustodyEvent {
    /// Unique event identifier.
    pub id: String,
    /// Sequence number in the custody chain (monotonically increasing).
    pub sequence: u64,
    /// Hash of the DecisionRecord at time of this event.
    pub record_hash: Blake3Hash,
    /// Hash of the previous CustodyEvent (chain linkage).
    pub prev_event_hash: Option<Blake3Hash>,
    /// DID of the actor.
    pub actor_id: Did,
    /// Role of the actor.
    pub role: CustodyRole,
    /// The action performed.
    pub action: CustodyAction,
    /// Timestamp.
    pub timestamp: HybridLogicalClock,
    /// Optional detached signature over the record_hash (Ed25519).
    pub signature: Option<GovernanceSignature>,
    /// Hash of this event (computed over all fields except this one).
    pub event_hash: Blake3Hash,
}

/// An append-only chain of custody events for a single DecisionRecord.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CustodyChain {
    /// The DecisionRecord this chain belongs to.
    pub decision_id: Blake3Hash,
    /// Ordered custody events.
    pub events: Vec<CustodyEvent>,
    /// Current sequence counter.
    pub next_sequence: u64,
}

impl CustodyChain {
    /// Create a new empty custody chain for a decision.
    pub fn new(decision_id: Blake3Hash) -> Self {
        Self {
            decision_id,
            events: Vec::new(),
            next_sequence: 0,
        }
    }

    /// Append a custody event to the chain.
    pub fn append(
        &mut self,
        actor_id: Did,
        role: CustodyRole,
        action: CustodyAction,
        record_hash: Blake3Hash,
        timestamp: HybridLogicalClock,
        signature: Option<GovernanceSignature>,
    ) -> &CustodyEvent {
        let prev_event_hash = self.events.last().map(|e| e.event_hash);
        let sequence = self.next_sequence;

        // Compute event hash over canonical fields
        let event_hash = self.compute_event_hash(
            sequence,
            &record_hash,
            prev_event_hash.as_ref(),
            &actor_id,
            &action,
            &timestamp,
        );

        let event = CustodyEvent {
            id: format!("ce-{}-{}", self.decision_id.0[0], sequence),
            sequence,
            record_hash,
            prev_event_hash,
            actor_id,
            role,
            action,
            timestamp,
            signature,
            event_hash,
        };

        self.next_sequence += 1;
        self.events.push(event);
        self.events.last().unwrap()
    }

    /// Verify the integrity of the custody chain.
    /// Returns Ok(()) if all event hashes and chain links are valid.
    pub fn verify_integrity(&self) -> Result<(), CustodyChainError> {
        for (i, event) in self.events.iter().enumerate() {
            // Verify sequence
            if event.sequence != i as u64 {
                return Err(CustodyChainError::SequenceGap {
                    expected: i as u64,
                    actual: event.sequence,
                });
            }

            // Verify chain linkage
            if i == 0 {
                if event.prev_event_hash.is_some() {
                    return Err(CustodyChainError::InvalidGenesisLink);
                }
            } else {
                let expected_prev = self.events[i - 1].event_hash;
                match &event.prev_event_hash {
                    Some(prev) if *prev != expected_prev => {
                        return Err(CustodyChainError::BrokenLink {
                            sequence: event.sequence,
                            expected: expected_prev,
                            actual: *prev,
                        });
                    }
                    None => {
                        return Err(CustodyChainError::MissingLink {
                            sequence: event.sequence,
                        });
                    }
                    _ => {}
                }
            }

            // Verify event hash
            let recomputed = self.compute_event_hash(
                event.sequence,
                &event.record_hash,
                event.prev_event_hash.as_ref(),
                &event.actor_id,
                &event.action,
                &event.timestamp,
            );
            if recomputed != event.event_hash {
                return Err(CustodyChainError::HashMismatch {
                    sequence: event.sequence,
                    expected: recomputed,
                    actual: event.event_hash,
                });
            }
        }

        Ok(())
    }

    /// Number of events in the chain.
    pub fn len(&self) -> usize {
        self.events.len()
    }

    /// Whether the chain is empty.
    pub fn is_empty(&self) -> bool {
        self.events.is_empty()
    }

    /// Get the latest event.
    pub fn latest(&self) -> Option<&CustodyEvent> {
        self.events.last()
    }

    /// Get all events by a specific actor.
    pub fn events_by_actor(&self, actor: &str) -> Vec<&CustodyEvent> {
        self.events.iter().filter(|e| e.actor_id == actor).collect()
    }

    /// Get all attestation events (Approve, Reject, Abstain, Veto).
    pub fn attestations(&self) -> Vec<&CustodyEvent> {
        self.events
            .iter()
            .filter(|e| {
                matches!(
                    e.action,
                    CustodyAction::Approve
                        | CustodyAction::Reject
                        | CustodyAction::Abstain
                        | CustodyAction::Veto
                )
            })
            .collect()
    }

    fn compute_event_hash(
        &self,
        sequence: u64,
        record_hash: &Blake3Hash,
        prev_event_hash: Option<&Blake3Hash>,
        actor_id: &str,
        action: &CustodyAction,
        timestamp: &HybridLogicalClock,
    ) -> Blake3Hash {
        let mut hasher = blake3::Hasher::new();
        hasher.update(&sequence.to_le_bytes());
        hasher.update(&record_hash.0);
        if let Some(prev) = prev_event_hash {
            hasher.update(&prev.0);
        }
        hasher.update(actor_id.as_bytes());
        hasher.update(&serde_json::to_vec(action).unwrap_or_default());
        hasher.update(&timestamp.physical_ms.to_le_bytes());
        hasher.update(&timestamp.logical.to_le_bytes());

        let hash = hasher.finalize();
        Blake3Hash(*hash.as_bytes())
    }
}

/// Errors in custody chain verification.
#[derive(Debug, Clone)]
pub enum CustodyChainError {
    SequenceGap { expected: u64, actual: u64 },
    InvalidGenesisLink,
    BrokenLink { sequence: u64, expected: Blake3Hash, actual: Blake3Hash },
    MissingLink { sequence: u64 },
    HashMismatch { sequence: u64, expected: Blake3Hash, actual: Blake3Hash },
}

impl std::fmt::Display for CustodyChainError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::SequenceGap { expected, actual } => {
                write!(f, "Sequence gap: expected {}, got {}", expected, actual)
            }
            Self::InvalidGenesisLink => write!(f, "Genesis event should not have prev_event_hash"),
            Self::BrokenLink { sequence, .. } => {
                write!(f, "Broken chain link at sequence {}", sequence)
            }
            Self::MissingLink { sequence } => {
                write!(f, "Missing prev_event_hash at sequence {}", sequence)
            }
            Self::HashMismatch { sequence, .. } => {
                write!(f, "Event hash mismatch at sequence {}", sequence)
            }
        }
    }
}

impl std::error::Error for CustodyChainError {}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_hlc(ms: u64) -> HybridLogicalClock {
        HybridLogicalClock {
            physical_ms: ms,
            logical: 0,
        }
    }

    #[test]
    fn test_custody_chain_creation() {
        let chain = CustodyChain::new(Blake3Hash([1u8; 32]));
        assert!(chain.is_empty());
        assert_eq!(chain.len(), 0);
        assert!(chain.latest().is_none());
    }

    #[test]
    fn test_append_events() {
        let mut chain = CustodyChain::new(Blake3Hash([1u8; 32]));
        let record_hash = Blake3Hash([2u8; 32]);

        chain.append(
            "did:exo:alice".to_string(),
            CustodyRole::Proposer,
            CustodyAction::Create,
            record_hash,
            test_hlc(1000),
            None,
        );

        assert_eq!(chain.len(), 1);
        assert_eq!(chain.events[0].sequence, 0);
        assert!(chain.events[0].prev_event_hash.is_none());

        chain.append(
            "did:exo:bob".to_string(),
            CustodyRole::Reviewer,
            CustodyAction::Approve,
            record_hash,
            test_hlc(2000),
            None,
        );

        assert_eq!(chain.len(), 2);
        assert_eq!(chain.events[1].sequence, 1);
        assert_eq!(
            chain.events[1].prev_event_hash.unwrap(),
            chain.events[0].event_hash
        );
    }

    #[test]
    fn test_chain_integrity() {
        let mut chain = CustodyChain::new(Blake3Hash([1u8; 32]));
        let record_hash = Blake3Hash([2u8; 32]);

        chain.append(
            "did:exo:alice".to_string(),
            CustodyRole::Proposer,
            CustodyAction::Create,
            record_hash,
            test_hlc(1000),
            None,
        );
        chain.append(
            "did:exo:bob".to_string(),
            CustodyRole::Reviewer,
            CustodyAction::Approve,
            record_hash,
            test_hlc(2000),
            None,
        );
        chain.append(
            "did:exo:carol".to_string(),
            CustodyRole::Steward,
            CustodyAction::IssueClearance {
                certificate_id: "cert-1".to_string(),
            },
            record_hash,
            test_hlc(3000),
            None,
        );

        assert!(chain.verify_integrity().is_ok());
    }

    #[test]
    fn test_tampered_chain_detected() {
        let mut chain = CustodyChain::new(Blake3Hash([1u8; 32]));
        let record_hash = Blake3Hash([2u8; 32]);

        chain.append(
            "did:exo:alice".to_string(),
            CustodyRole::Proposer,
            CustodyAction::Create,
            record_hash,
            test_hlc(1000),
            None,
        );
        chain.append(
            "did:exo:bob".to_string(),
            CustodyRole::Reviewer,
            CustodyAction::Approve,
            record_hash,
            test_hlc(2000),
            None,
        );

        // Tamper with the first event's hash
        chain.events[0].event_hash = Blake3Hash([99u8; 32]);
        assert!(chain.verify_integrity().is_err());
    }

    #[test]
    fn test_events_by_actor() {
        let mut chain = CustodyChain::new(Blake3Hash([1u8; 32]));
        let record_hash = Blake3Hash([2u8; 32]);

        chain.append("did:exo:alice".to_string(), CustodyRole::Proposer, CustodyAction::Create, record_hash, test_hlc(1000), None);
        chain.append("did:exo:bob".to_string(), CustodyRole::Reviewer, CustodyAction::Approve, record_hash, test_hlc(2000), None);
        chain.append("did:exo:alice".to_string(), CustodyRole::Proposer, CustodyAction::Comment { content: "Updated rationale".to_string() }, record_hash, test_hlc(3000), None);

        let alice_events = chain.events_by_actor("did:exo:alice");
        assert_eq!(alice_events.len(), 2);
    }

    #[test]
    fn test_attestations() {
        let mut chain = CustodyChain::new(Blake3Hash([1u8; 32]));
        let record_hash = Blake3Hash([2u8; 32]);

        chain.append("did:exo:alice".to_string(), CustodyRole::Proposer, CustodyAction::Create, record_hash, test_hlc(1000), None);
        chain.append("did:exo:bob".to_string(), CustodyRole::Reviewer, CustodyAction::Approve, record_hash, test_hlc(2000), None);
        chain.append("did:exo:carol".to_string(), CustodyRole::Reviewer, CustodyAction::Reject, record_hash, test_hlc(3000), None);
        chain.append("did:exo:dave".to_string(), CustodyRole::Observer, CustodyAction::Comment { content: "I agree with Carol".to_string() }, record_hash, test_hlc(4000), None);

        let attestations = chain.attestations();
        assert_eq!(attestations.len(), 2); // Approve + Reject
    }
}
