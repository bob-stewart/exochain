//! Audit Trail — continuous tamper-evident hash chain.
//!
//! Satisfies: TNC-03, LEG-001, LEG-002, LEG-003

use crate::errors::GovernanceError;
use crate::types::*;
use exo_core::crypto::{hash_bytes, Blake3Hash};
use exo_core::hlc::HybridLogicalClock;
use serde::{Deserialize, Serialize};

/// A single entry in the audit hash chain.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AuditEntry {
    /// Monotonically increasing sequence number.
    pub sequence: u64,
    /// Hash of the previous entry (genesis has all-zero prev_hash).
    pub prev_hash: Blake3Hash,
    /// Hash of the event being recorded.
    pub event_hash: Blake3Hash,
    /// Type of governance event.
    pub event_type: AuditEventType,
    /// Actor who caused the event.
    pub actor: Did,
    /// Tenant context.
    pub tenant_id: TenantId,
    /// Timestamp.
    pub timestamp: HybridLogicalClock,
    /// Computed hash of this entry: H(sequence || prev_hash || event_hash || event_type || actor || timestamp).
    pub entry_hash: Blake3Hash,
}

/// Types of auditable governance events.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum AuditEventType {
    DecisionCreated,
    DecisionAdvanced,
    VoteCast,
    DelegationGranted,
    DelegationRevoked,
    DelegationExpired,
    ConstitutionAmended,
    ChallengeRaised,
    ChallengeResolved,
    EmergencyActionTaken,
    EmergencyActionRatified,
    ConflictDisclosed,
    AuthorityChainVerified,
    AuditSelfVerification,
}

/// The audit log — append-only hash chain.
#[derive(Clone, Debug, Default)]
pub struct AuditLog {
    entries: Vec<AuditEntry>,
}

impl AuditLog {
    pub fn new() -> Self {
        Self {
            entries: Vec::new(),
        }
    }

    /// Get the current chain length.
    pub fn len(&self) -> u64 {
        self.entries.len() as u64
    }

    /// Check if the audit log is empty.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Get the hash of the most recent entry (or all-zero for empty chain).
    pub fn head_hash(&self) -> Blake3Hash {
        self.entries
            .last()
            .map(|e| e.entry_hash)
            .unwrap_or(Blake3Hash([0u8; 32]))
    }

    /// Append a new event to the audit log.
    pub fn append(
        &mut self,
        event_hash: Blake3Hash,
        event_type: AuditEventType,
        actor: Did,
        tenant_id: TenantId,
        timestamp: HybridLogicalClock,
    ) -> AuditEntry {
        let sequence = self.len();
        let prev_hash = self.head_hash();

        let entry_hash = compute_entry_hash(
            sequence,
            &prev_hash,
            &event_hash,
            &event_type,
            &actor,
            &timestamp,
        );

        let entry = AuditEntry {
            sequence,
            prev_hash,
            event_hash,
            event_type,
            actor,
            tenant_id,
            timestamp,
            entry_hash,
        };

        self.entries.push(entry.clone());
        entry
    }

    /// Verify the entire hash chain integrity (TNC-03).
    /// Returns Ok(()) if the chain is intact, or an error at the first break.
    pub fn verify_integrity(&self) -> Result<(), GovernanceError> {
        let mut expected_prev = Blake3Hash([0u8; 32]);

        for entry in &self.entries {
            // Check prev_hash linkage
            if entry.prev_hash != expected_prev {
                return Err(GovernanceError::AuditChainBroken {
                    sequence: entry.sequence,
                    expected: expected_prev,
                    actual: entry.prev_hash,
                });
            }

            // Recompute entry hash
            let recomputed = compute_entry_hash(
                entry.sequence,
                &entry.prev_hash,
                &entry.event_hash,
                &entry.event_type,
                &entry.actor,
                &entry.timestamp,
            );

            if recomputed != entry.entry_hash {
                return Err(GovernanceError::AuditChainBroken {
                    sequence: entry.sequence,
                    expected: recomputed,
                    actual: entry.entry_hash,
                });
            }

            expected_prev = entry.entry_hash;
        }

        Ok(())
    }

    /// Get entries in a range.
    pub fn entries_range(&self, start: u64, end: u64) -> &[AuditEntry] {
        let start = start as usize;
        let end = (end as usize).min(self.entries.len());
        if start >= self.entries.len() {
            return &[];
        }
        &self.entries[start..end]
    }

    /// Get all entries.
    pub fn entries(&self) -> &[AuditEntry] {
        &self.entries
    }
}

/// Compute the hash of an audit entry.
fn compute_entry_hash(
    sequence: u64,
    prev_hash: &Blake3Hash,
    event_hash: &Blake3Hash,
    event_type: &AuditEventType,
    actor: &Did,
    timestamp: &HybridLogicalClock,
) -> Blake3Hash {
    let mut preimage = Vec::new();
    preimage.extend_from_slice(&sequence.to_le_bytes());
    preimage.extend_from_slice(&prev_hash.0);
    preimage.extend_from_slice(&event_hash.0);
    // Include event type discriminant
    let type_bytes = serde_cbor::to_vec(event_type).unwrap_or_default();
    preimage.extend_from_slice(&type_bytes);
    preimage.extend_from_slice(actor.as_bytes());
    preimage.extend_from_slice(&timestamp.physical_ms.to_le_bytes());
    preimage.extend_from_slice(&timestamp.logical.to_le_bytes());
    hash_bytes(&preimage)
}

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
    fn test_audit_log_append_and_verify() {
        let mut log = AuditLog::new();
        assert!(log.is_empty());

        log.append(
            Blake3Hash([1u8; 32]),
            AuditEventType::DecisionCreated,
            "did:exo:alice".to_string(),
            "tenant-1".to_string(),
            test_hlc(1000),
        );

        log.append(
            Blake3Hash([2u8; 32]),
            AuditEventType::DecisionAdvanced,
            "did:exo:alice".to_string(),
            "tenant-1".to_string(),
            test_hlc(2000),
        );

        log.append(
            Blake3Hash([3u8; 32]),
            AuditEventType::VoteCast,
            "did:exo:bob".to_string(),
            "tenant-1".to_string(),
            test_hlc(3000),
        );

        assert_eq!(log.len(), 3);
        assert!(log.verify_integrity().is_ok());
    }

    #[test]
    fn test_tnc03_tamper_detection() {
        let mut log = AuditLog::new();

        log.append(
            Blake3Hash([1u8; 32]),
            AuditEventType::DecisionCreated,
            "did:exo:alice".to_string(),
            "tenant-1".to_string(),
            test_hlc(1000),
        );

        log.append(
            Blake3Hash([2u8; 32]),
            AuditEventType::DecisionAdvanced,
            "did:exo:alice".to_string(),
            "tenant-1".to_string(),
            test_hlc(2000),
        );

        // Tamper with the first entry's event hash
        log.entries[0].event_hash = Blake3Hash([99u8; 32]);

        // Verification should detect the tamper
        let result = log.verify_integrity();
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            GovernanceError::AuditChainBroken { sequence: 0, .. }
        ));
    }

    #[test]
    fn test_chain_linkage() {
        let mut log = AuditLog::new();

        let e1 = log.append(
            Blake3Hash([1u8; 32]),
            AuditEventType::DecisionCreated,
            "did:exo:alice".to_string(),
            "tenant-1".to_string(),
            test_hlc(1000),
        );

        let e2 = log.append(
            Blake3Hash([2u8; 32]),
            AuditEventType::VoteCast,
            "did:exo:bob".to_string(),
            "tenant-1".to_string(),
            test_hlc(2000),
        );

        // First entry's prev_hash is all-zero (genesis)
        assert_eq!(e1.prev_hash, Blake3Hash([0u8; 32]));
        // Second entry's prev_hash is first entry's hash
        assert_eq!(e2.prev_hash, e1.entry_hash);
    }

    #[test]
    fn test_head_hash() {
        let mut log = AuditLog::new();
        assert_eq!(log.head_hash(), Blake3Hash([0u8; 32]));

        let e1 = log.append(
            Blake3Hash([1u8; 32]),
            AuditEventType::DecisionCreated,
            "did:exo:alice".to_string(),
            "tenant-1".to_string(),
            test_hlc(1000),
        );
        assert_eq!(log.head_hash(), e1.entry_hash);
    }

    #[test]
    fn test_entries_range() {
        let mut log = AuditLog::new();
        for i in 0..10 {
            log.append(
                Blake3Hash([i as u8; 32]),
                AuditEventType::DecisionCreated,
                "did:exo:alice".to_string(),
                "tenant-1".to_string(),
                test_hlc(1000 + i as u64),
            );
        }

        let range = log.entries_range(2, 5);
        assert_eq!(range.len(), 3);
        assert_eq!(range[0].sequence, 2);
        assert_eq!(range[2].sequence, 4);
    }
}
