//! Conflict Disclosure — blocks participation until disclosure complete.
//!
//! Satisfies: TNC-06, LEG-005, LEG-013

use crate::decision::ConflictDisclosure;
use crate::errors::GovernanceError;
use crate::types::*;
use exo_core::crypto::Blake3Hash;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Registry tracking known conflicts for participants.
#[derive(Clone, Debug, Default)]
pub struct ConflictRegistry {
    /// Map of DID -> list of known conflicts.
    known_conflicts: HashMap<Did, Vec<KnownConflict>>,
}

/// A known conflict registered for a participant.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct KnownConflict {
    pub participant: Did,
    pub nature: ConflictNature,
    pub related_entities: Vec<String>,
    pub registered_at: u64,
    /// Whether disclosure has been filed for a specific decision.
    pub disclosed_for_decisions: Vec<Blake3Hash>,
}

/// Conflict nature categories.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum ConflictNature {
    Financial,
    Personal,
    Organizational,
    Other(String),
}

/// Recusal status for a participant on a specific decision.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RecusalStatus {
    /// No known conflicts — cleared to participate.
    Cleared,
    /// Conflict exists, disclosure filed — may participate.
    DisclosedAndCleared,
    /// Conflict exists, no disclosure — BLOCKED from participation (TNC-06).
    Blocked,
    /// Voluntarily recused.
    Recused,
}

impl ConflictRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    /// Register a known conflict for a participant.
    pub fn register_conflict(&mut self, conflict: KnownConflict) {
        self.known_conflicts
            .entry(conflict.participant.clone())
            .or_default()
            .push(conflict);
    }

    /// Check if a participant has undisclosed conflicts for a decision (TNC-06).
    pub fn check_participation(
        &self,
        participant: &Did,
        decision_id: &Blake3Hash,
        disclosures: &[ConflictDisclosure],
    ) -> RecusalStatus {
        let conflicts = match self.known_conflicts.get(participant) {
            Some(c) => c,
            None => return RecusalStatus::Cleared,
        };

        // Check if there are any conflicts that haven't been disclosed for this decision
        let has_undisclosed = conflicts.iter().any(|c| {
            !c.disclosed_for_decisions.contains(decision_id)
                && !disclosures.iter().any(|d| d.discloser == *participant)
        });

        if has_undisclosed {
            RecusalStatus::Blocked
        } else {
            RecusalStatus::DisclosedAndCleared
        }
    }

    /// Enforce conflict disclosure requirement (TNC-06).
    /// Returns Err if participant has undisclosed conflicts.
    pub fn enforce_disclosure(
        &self,
        participant: &Did,
        decision_id: &Blake3Hash,
        disclosures: &[ConflictDisclosure],
    ) -> Result<(), GovernanceError> {
        match self.check_participation(participant, decision_id, disclosures) {
            RecusalStatus::Cleared | RecusalStatus::DisclosedAndCleared => Ok(()),
            RecusalStatus::Blocked => Err(GovernanceError::ConflictDisclosureRequired(
                participant.clone(),
            )),
            RecusalStatus::Recused => Ok(()), // Recused participants are excluded, not blocked
        }
    }

    /// Record that a disclosure was filed for a specific decision.
    pub fn record_disclosure(&mut self, participant: &Did, decision_id: Blake3Hash) {
        if let Some(conflicts) = self.known_conflicts.get_mut(participant) {
            for conflict in conflicts.iter_mut() {
                conflict.disclosed_for_decisions.push(decision_id);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::decision::ConflictNature as DecisionConflictNature;
    use exo_core::hlc::HybridLogicalClock;

    fn test_hlc() -> HybridLogicalClock {
        HybridLogicalClock {
            physical_ms: 1000,
            logical: 0,
        }
    }

    fn test_sig(signer: &str) -> GovernanceSignature {
        use ed25519_dalek::SigningKey;
        use rand::rngs::OsRng;
        let sk = SigningKey::generate(&mut OsRng);
        let dummy = Blake3Hash([0u8; 32]);
        let sig = exo_core::compute_signature(&sk, &dummy);
        GovernanceSignature {
            signer: signer.to_string(),
            signer_type: SignerType::Human,
            signature: sig,
            key_version: 1,
            timestamp: test_hlc(),
        }
    }

    #[test]
    fn test_tnc06_blocks_undisclosed_conflict() {
        let mut registry = ConflictRegistry::new();
        let decision_id = Blake3Hash([1u8; 32]);

        registry.register_conflict(KnownConflict {
            participant: "did:exo:alice".to_string(),
            nature: ConflictNature::Financial,
            related_entities: vec!["Acme Corp".to_string()],
            registered_at: 1000,
            disclosed_for_decisions: vec![],
        });

        // No disclosure filed — should be blocked
        let result = registry.enforce_disclosure(&"did:exo:alice".to_string(), &decision_id, &[]);
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            GovernanceError::ConflictDisclosureRequired(_)
        ));
    }

    #[test]
    fn test_tnc06_allows_after_disclosure() {
        let mut registry = ConflictRegistry::new();
        let decision_id = Blake3Hash([1u8; 32]);

        registry.register_conflict(KnownConflict {
            participant: "did:exo:alice".to_string(),
            nature: ConflictNature::Financial,
            related_entities: vec![],
            registered_at: 1000,
            disclosed_for_decisions: vec![],
        });

        // File disclosure
        let disclosure = ConflictDisclosure {
            discloser: "did:exo:alice".to_string(),
            description: "Financial interest in Acme Corp".to_string(),
            nature: DecisionConflictNature::Financial,
            timestamp: test_hlc(),
            signature: test_sig("did:exo:alice"),
        };

        let result =
            registry.enforce_disclosure(&"did:exo:alice".to_string(), &decision_id, &[disclosure]);
        assert!(result.is_ok());
    }

    #[test]
    fn test_no_conflicts_cleared() {
        let registry = ConflictRegistry::new();
        let decision_id = Blake3Hash([1u8; 32]);

        let status = registry.check_participation(&"did:exo:bob".to_string(), &decision_id, &[]);
        assert_eq!(status, RecusalStatus::Cleared);
    }
}
