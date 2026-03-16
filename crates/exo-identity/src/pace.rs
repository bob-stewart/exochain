//! PACE Enrollment Workflow.
//!
//! PACE = Provable -> Auditable -> Compliant -> Enforceable.
//!
//! A progressive identity enrollment system where users designate a minimum of
//! 4 PACE contacts (trustees) who each hold a Shamir share of the user's master
//! key. A threshold of 3-of-N shares is required for recovery.

use crate::shamir::{self, Share, ShamirError};
use std::collections::HashMap;

// ---------------------------------------------------------------------------
// Enums
// ---------------------------------------------------------------------------

/// The stages of PACE enrollment, progressing from left to right.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum PaceStage {
    Unenrolled,
    Provable,
    Auditable,
    Compliant,
    Enforceable,
}

impl PaceStage {
    /// Returns the next stage, if one exists.
    fn next(&self) -> Option<PaceStage> {
        match self {
            PaceStage::Unenrolled => Some(PaceStage::Provable),
            PaceStage::Provable => Some(PaceStage::Auditable),
            PaceStage::Auditable => Some(PaceStage::Compliant),
            PaceStage::Compliant => Some(PaceStage::Enforceable),
            PaceStage::Enforceable => None,
        }
    }
}

/// Relationship category for a PACE contact.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ContactRelationship {
    Family,
    Friend,
    Colleague,
    Legal,
    Institutional,
}

/// Types of auditable events in the PACE enrollment lifecycle.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PaceEventType {
    EnrollmentStarted,
    ContactAdded,
    ContactRemoved,
    ShareGenerated,
    ShareDistributed,
    ShareConfirmed,
    StageAdvanced,
    RecoveryInitiated,
    RecoveryCompleted,
}

// ---------------------------------------------------------------------------
// Structs
// ---------------------------------------------------------------------------

/// A PACE contact (trustee) who holds a Shamir share.
#[derive(Clone, Debug)]
pub struct PaceContact {
    pub contact_did: String,
    pub display_name: String,
    pub relationship: ContactRelationship,
    /// Assigned share index (1-based), set when shares are generated.
    pub share_index: u8,
    /// Whether the share has been distributed to this contact.
    pub share_distributed: bool,
    /// Whether the contact has confirmed receipt of their share.
    pub confirmed_receipt: bool,
    /// Timestamp (Unix ms) when this contact was added.
    pub added_at_ms: u64,
}

/// Configuration for the Shamir scheme used in this enrollment.
#[derive(Clone, Debug)]
pub struct ShamirConfig {
    /// Minimum shares needed for recovery.
    pub threshold: usize,
    /// Total shares to generate (one per contact).
    pub total_shares: usize,
}

/// An auditable event in the PACE enrollment lifecycle.
#[derive(Clone, Debug)]
pub struct PaceAuditEvent {
    pub timestamp_ms: u64,
    pub event_type: PaceEventType,
    pub description: String,
    pub actor_did: String,
}

/// Errors specific to PACE enrollment operations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PaceError {
    /// Cannot advance to the next stage; requirements not met.
    StageRequirementsNotMet(String),
    /// Contact not found by DID.
    ContactNotFound(String),
    /// Cannot modify contacts after shares have been generated.
    AlreadySharded,
    /// Duplicate contact DID.
    DuplicateContact(String),
    /// Already at the final stage.
    AlreadyAtFinalStage,
    /// Shamir operation failed.
    ShamirFailure(String),
    /// Minimum contact count not met.
    InsufficientContacts { need: usize, got: usize },
}

impl std::fmt::Display for PaceError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PaceError::StageRequirementsNotMet(msg) => {
                write!(f, "Stage requirements not met: {msg}")
            }
            PaceError::ContactNotFound(did) => write!(f, "Contact not found: {did}"),
            PaceError::AlreadySharded => write!(f, "Cannot modify contacts: shares already generated"),
            PaceError::DuplicateContact(did) => write!(f, "Duplicate contact: {did}"),
            PaceError::AlreadyAtFinalStage => write!(f, "Already at final stage (Enforceable)"),
            PaceError::ShamirFailure(msg) => write!(f, "Shamir error: {msg}"),
            PaceError::InsufficientContacts { need, got } => {
                write!(f, "Need at least {need} contacts, have {got}")
            }
        }
    }
}

impl std::error::Error for PaceError {}

impl From<ShamirError> for PaceError {
    fn from(e: ShamirError) -> Self {
        PaceError::ShamirFailure(e.to_string())
    }
}

/// The minimum number of PACE contacts required.
pub const MIN_PACE_CONTACTS: usize = 4;

/// The default recovery threshold (3-of-N).
pub const DEFAULT_THRESHOLD: usize = 3;

/// The full PACE enrollment state machine.
#[derive(Clone, Debug)]
pub struct PaceEnrollment {
    /// The DID of the user being enrolled.
    pub user_did: String,
    /// Current enrollment stage.
    pub current_stage: PaceStage,
    /// Designated PACE contacts (trustees).
    pub contacts: Vec<PaceContact>,
    /// Shamir scheme configuration.
    pub shamir_config: ShamirConfig,
    /// Whether Shamir shares have been generated.
    pub key_sharded: bool,
    /// Timestamp when enrollment was started.
    pub enrollment_started_ms: u64,
    /// Timestamps for each completed stage.
    pub stage_completed_ms: HashMap<PaceStage, u64>,
    /// Audit log of all enrollment events.
    pub audit_log: Vec<PaceAuditEvent>,
    /// Whether compliance attestation has been completed (gate for Compliant -> Enforceable).
    pub compliance_attested: bool,
    /// Generated shares (held transiently for distribution; cleared after all distributed).
    generated_shares: Vec<Share>,
}

impl PaceEnrollment {
    /// Create a new PACE enrollment for the given user DID.
    /// Starts at `Unenrolled` stage with default 3-of-N threshold.
    pub fn new(user_did: impl Into<String>, now_ms: u64) -> Self {
        let user_did = user_did.into();
        let mut enrollment = Self {
            user_did: user_did.clone(),
            current_stage: PaceStage::Unenrolled,
            contacts: Vec::new(),
            shamir_config: ShamirConfig {
                threshold: DEFAULT_THRESHOLD,
                total_shares: 0, // Updated when shares are generated.
            },
            key_sharded: false,
            enrollment_started_ms: now_ms,
            stage_completed_ms: HashMap::new(),
            audit_log: Vec::new(),
            compliance_attested: false,
            generated_shares: Vec::new(),
        };

        enrollment.log_event(
            now_ms,
            PaceEventType::EnrollmentStarted,
            "PACE enrollment initiated".to_string(),
            user_did,
        );

        enrollment
    }

    /// Add a PACE contact (trustee).
    pub fn add_contact(
        &mut self,
        contact_did: impl Into<String>,
        display_name: impl Into<String>,
        relationship: ContactRelationship,
        now_ms: u64,
    ) -> Result<(), PaceError> {
        if self.key_sharded {
            return Err(PaceError::AlreadySharded);
        }

        let contact_did = contact_did.into();

        // Check for duplicate.
        if self.contacts.iter().any(|c| c.contact_did == contact_did) {
            return Err(PaceError::DuplicateContact(contact_did));
        }

        let display_name = display_name.into();

        self.log_event(
            now_ms,
            PaceEventType::ContactAdded,
            format!("Contact added: {display_name} ({contact_did})"),
            self.user_did.clone(),
        );

        self.contacts.push(PaceContact {
            contact_did,
            display_name,
            relationship,
            share_index: 0, // Assigned when shares are generated.
            share_distributed: false,
            confirmed_receipt: false,
            added_at_ms: now_ms,
        });

        Ok(())
    }

    /// Remove a PACE contact by DID. Only allowed before shares are generated.
    pub fn remove_contact(
        &mut self,
        contact_did: &str,
        now_ms: u64,
    ) -> Result<(), PaceError> {
        if self.key_sharded {
            return Err(PaceError::AlreadySharded);
        }

        let idx = self
            .contacts
            .iter()
            .position(|c| c.contact_did == contact_did)
            .ok_or_else(|| PaceError::ContactNotFound(contact_did.to_string()))?;

        let removed = self.contacts.remove(idx);

        self.log_event(
            now_ms,
            PaceEventType::ContactRemoved,
            format!("Contact removed: {} ({})", removed.display_name, removed.contact_did),
            self.user_did.clone(),
        );

        Ok(())
    }

    /// Check whether the enrollment can advance to the next stage.
    pub fn can_advance(&self) -> Result<(), PaceError> {
        match self.current_stage {
            PaceStage::Unenrolled => {
                // Must have a DID (non-empty).
                if self.user_did.is_empty() {
                    return Err(PaceError::StageRequirementsNotMet(
                        "User DID is required".to_string(),
                    ));
                }
                Ok(())
            }
            PaceStage::Provable => {
                // Must have >= MIN_PACE_CONTACTS contacts.
                if self.contacts.len() < MIN_PACE_CONTACTS {
                    return Err(PaceError::InsufficientContacts {
                        need: MIN_PACE_CONTACTS,
                        got: self.contacts.len(),
                    });
                }
                Ok(())
            }
            PaceStage::Auditable => {
                // All shares must be distributed AND confirmed.
                if !self.key_sharded {
                    return Err(PaceError::StageRequirementsNotMet(
                        "Shares have not been generated".to_string(),
                    ));
                }
                for contact in &self.contacts {
                    if !contact.share_distributed {
                        return Err(PaceError::StageRequirementsNotMet(format!(
                            "Share not distributed to {}",
                            contact.contact_did
                        )));
                    }
                    if !contact.confirmed_receipt {
                        return Err(PaceError::StageRequirementsNotMet(format!(
                            "Share receipt not confirmed by {}",
                            contact.contact_did
                        )));
                    }
                }
                Ok(())
            }
            PaceStage::Compliant => {
                // Must have completed compliance attestation.
                if !self.compliance_attested {
                    return Err(PaceError::StageRequirementsNotMet(
                        "Compliance attestation not completed".to_string(),
                    ));
                }
                Ok(())
            }
            PaceStage::Enforceable => Err(PaceError::AlreadyAtFinalStage),
        }
    }

    /// Advance to the next PACE stage if all requirements are met.
    pub fn advance_stage(&mut self, now_ms: u64) -> Result<PaceStage, PaceError> {
        self.can_advance()?;

        let next = self
            .current_stage
            .next()
            .ok_or(PaceError::AlreadyAtFinalStage)?;

        self.stage_completed_ms
            .insert(self.current_stage.clone(), now_ms);
        self.current_stage = next.clone();

        self.log_event(
            now_ms,
            PaceEventType::StageAdvanced,
            format!("Advanced to stage: {next:?}"),
            self.user_did.clone(),
        );

        Ok(next)
    }

    /// Generate Shamir shares for all current contacts.
    ///
    /// Requires at least `MIN_PACE_CONTACTS` contacts. Uses a 3-of-N threshold
    /// where N = number of contacts.
    pub fn generate_shares(
        &mut self,
        master_secret: &[u8],
        now_ms: u64,
    ) -> Result<Vec<Share>, PaceError> {
        if self.contacts.len() < MIN_PACE_CONTACTS {
            return Err(PaceError::InsufficientContacts {
                need: MIN_PACE_CONTACTS,
                got: self.contacts.len(),
            });
        }

        let total = self.contacts.len();
        let threshold = DEFAULT_THRESHOLD;

        let shares = shamir::split_secret(master_secret, threshold, total)?;

        // Assign share indices to contacts.
        for (i, contact) in self.contacts.iter_mut().enumerate() {
            contact.share_index = shares[i].index;
        }

        self.shamir_config = ShamirConfig {
            threshold,
            total_shares: total,
        };
        self.key_sharded = true;
        self.generated_shares = shares.clone();

        self.log_event(
            now_ms,
            PaceEventType::ShareGenerated,
            format!("Generated {total} Shamir shares with threshold {threshold}"),
            self.user_did.clone(),
        );

        Ok(shares)
    }

    /// Mark a share as distributed to the given contact.
    pub fn mark_share_distributed(
        &mut self,
        contact_did: &str,
        now_ms: u64,
    ) -> Result<(), PaceError> {
        let contact = self
            .contacts
            .iter_mut()
            .find(|c| c.contact_did == contact_did)
            .ok_or_else(|| PaceError::ContactNotFound(contact_did.to_string()))?;

        contact.share_distributed = true;

        self.log_event(
            now_ms,
            PaceEventType::ShareDistributed,
            format!("Share distributed to {contact_did}"),
            self.user_did.clone(),
        );

        Ok(())
    }

    /// Confirm that a contact has received their share.
    pub fn confirm_share_receipt(
        &mut self,
        contact_did: &str,
        now_ms: u64,
    ) -> Result<(), PaceError> {
        let contact = self
            .contacts
            .iter_mut()
            .find(|c| c.contact_did == contact_did)
            .ok_or_else(|| PaceError::ContactNotFound(contact_did.to_string()))?;

        contact.confirmed_receipt = true;

        self.log_event(
            now_ms,
            PaceEventType::ShareConfirmed,
            format!("Share receipt confirmed by {contact_did}"),
            contact_did.to_string(),
        );

        Ok(())
    }

    /// Attempt key recovery using presented shares.
    pub fn initiate_recovery(
        &self,
        presenting_shares: &[Share],
        now_ms: u64,
    ) -> Result<(Vec<u8>, Vec<PaceAuditEvent>), PaceError> {
        let mut events = Vec::new();

        events.push(PaceAuditEvent {
            timestamp_ms: now_ms,
            event_type: PaceEventType::RecoveryInitiated,
            description: format!(
                "Recovery initiated with {} shares (threshold: {})",
                presenting_shares.len(),
                self.shamir_config.threshold
            ),
            actor_did: self.user_did.clone(),
        });

        let secret = shamir::reconstruct_secret(
            presenting_shares,
            self.shamir_config.threshold,
        )?;

        events.push(PaceAuditEvent {
            timestamp_ms: now_ms,
            event_type: PaceEventType::RecoveryCompleted,
            description: "Recovery completed successfully".to_string(),
            actor_did: self.user_did.clone(),
        });

        Ok((secret, events))
    }

    /// Set the compliance attestation flag.
    pub fn attest_compliance(&mut self, now_ms: u64) {
        self.compliance_attested = true;
        self.log_event(
            now_ms,
            PaceEventType::StageAdvanced,
            "Compliance attestation completed".to_string(),
            self.user_did.clone(),
        );
    }

    // -----------------------------------------------------------------------
    // Internal helpers
    // -----------------------------------------------------------------------

    fn log_event(
        &mut self,
        timestamp_ms: u64,
        event_type: PaceEventType,
        description: String,
        actor_did: String,
    ) {
        self.audit_log.push(PaceAuditEvent {
            timestamp_ms,
            event_type,
            description,
            actor_did,
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_enrollment() -> PaceEnrollment {
        PaceEnrollment::new("did:exo:user123", 1000)
    }

    fn add_default_contacts(enrollment: &mut PaceEnrollment) {
        let contacts = vec![
            ("did:exo:alice", "Alice", ContactRelationship::Family),
            ("did:exo:bob", "Bob", ContactRelationship::Friend),
            ("did:exo:carol", "Carol", ContactRelationship::Colleague),
            ("did:exo:dave", "Dave", ContactRelationship::Legal),
        ];
        for (did, name, rel) in contacts {
            enrollment.add_contact(did, name, rel, 2000).unwrap();
        }
    }

    #[test]
    fn test_new_enrollment_starts_unenrolled() {
        let e = make_enrollment();
        assert_eq!(e.current_stage, PaceStage::Unenrolled);
        assert_eq!(e.contacts.len(), 0);
        assert!(!e.key_sharded);
        assert_eq!(e.audit_log.len(), 1);
        assert_eq!(e.audit_log[0].event_type, PaceEventType::EnrollmentStarted);
    }

    #[test]
    fn test_advance_unenrolled_to_provable() {
        let mut e = make_enrollment();
        assert!(e.can_advance().is_ok());
        let next = e.advance_stage(1500).unwrap();
        assert_eq!(next, PaceStage::Provable);
        assert_eq!(e.current_stage, PaceStage::Provable);
    }

    #[test]
    fn test_provable_requires_contacts() {
        let mut e = make_enrollment();
        e.advance_stage(1500).unwrap(); // -> Provable

        // Should fail: no contacts
        assert!(matches!(
            e.can_advance(),
            Err(PaceError::InsufficientContacts { need: 4, got: 0 })
        ));

        // Add 3 contacts (still not enough)
        e.add_contact("did:exo:a", "A", ContactRelationship::Family, 2000).unwrap();
        e.add_contact("did:exo:b", "B", ContactRelationship::Friend, 2000).unwrap();
        e.add_contact("did:exo:c", "C", ContactRelationship::Colleague, 2000).unwrap();

        assert!(matches!(
            e.can_advance(),
            Err(PaceError::InsufficientContacts { need: 4, got: 3 })
        ));

        // Add 4th contact
        e.add_contact("did:exo:d", "D", ContactRelationship::Legal, 2000).unwrap();
        assert!(e.can_advance().is_ok());
    }

    #[test]
    fn test_add_contact_and_duplicate_rejection() {
        let mut e = make_enrollment();
        e.add_contact("did:exo:alice", "Alice", ContactRelationship::Family, 1000)
            .unwrap();
        let result = e.add_contact("did:exo:alice", "Alice Again", ContactRelationship::Friend, 1000);
        assert!(matches!(result, Err(PaceError::DuplicateContact(_))));
    }

    #[test]
    fn test_remove_contact_before_sharding() {
        let mut e = make_enrollment();
        e.add_contact("did:exo:alice", "Alice", ContactRelationship::Family, 1000)
            .unwrap();
        assert_eq!(e.contacts.len(), 1);

        e.remove_contact("did:exo:alice", 1500).unwrap();
        assert_eq!(e.contacts.len(), 0);
    }

    #[test]
    fn test_remove_contact_not_found() {
        let mut e = make_enrollment();
        let result = e.remove_contact("did:exo:nobody", 1000);
        assert!(matches!(result, Err(PaceError::ContactNotFound(_))));
    }

    #[test]
    fn test_cannot_modify_contacts_after_sharding() {
        let mut e = make_enrollment();
        e.advance_stage(1000).unwrap(); // -> Provable
        add_default_contacts(&mut e);
        e.advance_stage(2000).unwrap(); // -> Auditable

        // Generate shares
        e.generate_shares(b"master secret key!!", 3000).unwrap();

        // Cannot add or remove contacts now
        let result = e.add_contact("did:exo:eve", "Eve", ContactRelationship::Friend, 3500);
        assert!(matches!(result, Err(PaceError::AlreadySharded)));

        let result = e.remove_contact("did:exo:alice", 3500);
        assert!(matches!(result, Err(PaceError::AlreadySharded)));
    }

    #[test]
    fn test_generate_shares_assigns_indices() {
        let mut e = make_enrollment();
        e.advance_stage(1000).unwrap();
        add_default_contacts(&mut e);
        e.advance_stage(2000).unwrap();

        let shares = e.generate_shares(b"secret", 3000).unwrap();
        assert_eq!(shares.len(), 4);

        for (i, contact) in e.contacts.iter().enumerate() {
            assert_eq!(contact.share_index, (i + 1) as u8);
        }
        assert!(e.key_sharded);
    }

    #[test]
    fn test_generate_shares_needs_min_contacts() {
        let mut e = make_enrollment();
        let result = e.generate_shares(b"secret", 1000);
        assert!(matches!(
            result,
            Err(PaceError::InsufficientContacts { .. })
        ));
    }

    #[test]
    fn test_share_distribution_and_confirmation() {
        let mut e = make_enrollment();
        e.advance_stage(1000).unwrap();
        add_default_contacts(&mut e);
        e.advance_stage(2000).unwrap();
        e.generate_shares(b"the secret", 3000).unwrap();

        e.mark_share_distributed("did:exo:alice", 4000).unwrap();
        assert!(e.contacts[0].share_distributed);
        assert!(!e.contacts[0].confirmed_receipt);

        e.confirm_share_receipt("did:exo:alice", 4500).unwrap();
        assert!(e.contacts[0].confirmed_receipt);
    }

    #[test]
    fn test_auditable_to_compliant_requires_all_confirmed() {
        let mut e = make_enrollment();
        e.advance_stage(1000).unwrap(); // -> Provable
        add_default_contacts(&mut e);
        e.advance_stage(2000).unwrap(); // -> Auditable

        e.generate_shares(b"the secret", 3000).unwrap();

        // Not all distributed yet
        assert!(e.can_advance().is_err());

        // Distribute and confirm all
        let dids: Vec<String> = e.contacts.iter().map(|c| c.contact_did.clone()).collect();
        for did in &dids {
            e.mark_share_distributed(did, 4000).unwrap();
            e.confirm_share_receipt(did, 4500).unwrap();
        }

        assert!(e.can_advance().is_ok());
        let next = e.advance_stage(5000).unwrap();
        assert_eq!(next, PaceStage::Compliant);
    }

    #[test]
    fn test_compliant_to_enforceable_requires_attestation() {
        let mut e = make_enrollment();
        e.advance_stage(1000).unwrap(); // -> Provable
        add_default_contacts(&mut e);
        e.advance_stage(2000).unwrap(); // -> Auditable
        e.generate_shares(b"secret", 3000).unwrap();

        let dids: Vec<String> = e.contacts.iter().map(|c| c.contact_did.clone()).collect();
        for did in &dids {
            e.mark_share_distributed(did, 4000).unwrap();
            e.confirm_share_receipt(did, 4500).unwrap();
        }

        e.advance_stage(5000).unwrap(); // -> Compliant

        // Cannot advance without attestation
        assert!(matches!(
            e.can_advance(),
            Err(PaceError::StageRequirementsNotMet(_))
        ));

        e.attest_compliance(5500);
        assert!(e.can_advance().is_ok());

        let next = e.advance_stage(6000).unwrap();
        assert_eq!(next, PaceStage::Enforceable);
    }

    #[test]
    fn test_cannot_advance_past_enforceable() {
        let mut e = make_enrollment();
        e.advance_stage(1000).unwrap();
        add_default_contacts(&mut e);
        e.advance_stage(2000).unwrap();
        e.generate_shares(b"secret", 3000).unwrap();

        let dids: Vec<String> = e.contacts.iter().map(|c| c.contact_did.clone()).collect();
        for did in &dids {
            e.mark_share_distributed(did, 4000).unwrap();
            e.confirm_share_receipt(did, 4500).unwrap();
        }
        e.advance_stage(5000).unwrap();
        e.attest_compliance(5500);
        e.advance_stage(6000).unwrap(); // -> Enforceable

        assert!(matches!(
            e.advance_stage(7000),
            Err(PaceError::AlreadyAtFinalStage)
        ));
    }

    #[test]
    fn test_initiate_recovery() {
        let mut e = make_enrollment();
        e.advance_stage(1000).unwrap();
        add_default_contacts(&mut e);
        e.advance_stage(2000).unwrap();

        let secret = b"master key material";
        let shares = e.generate_shares(secret, 3000).unwrap();

        // Recover with 3 of 4 shares
        let (recovered, events) =
            e.initiate_recovery(&shares[..3], 10000).unwrap();
        assert_eq!(recovered, secret);
        assert_eq!(events.len(), 2);
        assert_eq!(events[0].event_type, PaceEventType::RecoveryInitiated);
        assert_eq!(events[1].event_type, PaceEventType::RecoveryCompleted);
    }

    #[test]
    fn test_recovery_fails_with_insufficient_shares() {
        let mut e = make_enrollment();
        e.advance_stage(1000).unwrap();
        add_default_contacts(&mut e);
        e.advance_stage(2000).unwrap();

        let shares = e.generate_shares(b"secret", 3000).unwrap();

        let result = e.initiate_recovery(&shares[..2], 10000);
        assert!(matches!(result, Err(PaceError::ShamirFailure(_))));
    }

    #[test]
    fn test_full_enrollment_flow() {
        let mut e = PaceEnrollment::new("did:exo:user1", 1000);
        assert_eq!(e.current_stage, PaceStage::Unenrolled);

        // Stage 1: Unenrolled -> Provable
        e.advance_stage(1100).unwrap();
        assert_eq!(e.current_stage, PaceStage::Provable);

        // Add contacts
        e.add_contact("did:exo:alice", "Alice", ContactRelationship::Family, 1200).unwrap();
        e.add_contact("did:exo:bob", "Bob", ContactRelationship::Friend, 1300).unwrap();
        e.add_contact("did:exo:carol", "Carol", ContactRelationship::Colleague, 1400).unwrap();
        e.add_contact("did:exo:dave", "Dave", ContactRelationship::Legal, 1500).unwrap();
        e.add_contact("did:exo:eve", "Eve", ContactRelationship::Institutional, 1600).unwrap();

        // Stage 2: Provable -> Auditable
        e.advance_stage(2000).unwrap();
        assert_eq!(e.current_stage, PaceStage::Auditable);

        // Generate shares (3-of-5)
        let secret = b"my master secret key for recovery";
        let shares = e.generate_shares(secret, 2500).unwrap();
        assert_eq!(shares.len(), 5);
        assert_eq!(e.shamir_config.threshold, 3);
        assert_eq!(e.shamir_config.total_shares, 5);

        // Distribute and confirm all shares
        let dids: Vec<String> = e.contacts.iter().map(|c| c.contact_did.clone()).collect();
        for did in &dids {
            e.mark_share_distributed(did, 3000).unwrap();
        }
        for did in &dids {
            e.confirm_share_receipt(did, 3500).unwrap();
        }

        // Stage 3: Auditable -> Compliant
        e.advance_stage(4000).unwrap();
        assert_eq!(e.current_stage, PaceStage::Compliant);

        // Compliance attestation
        e.attest_compliance(4500);

        // Stage 4: Compliant -> Enforceable
        e.advance_stage(5000).unwrap();
        assert_eq!(e.current_stage, PaceStage::Enforceable);

        // Verify recovery works with any 3-of-5
        let (recovered, _) = e.initiate_recovery(&shares[1..4], 6000).unwrap();
        assert_eq!(recovered, secret);

        // Verify audit log has meaningful entries
        assert!(e.audit_log.len() >= 5);
        assert_eq!(
            e.audit_log.first().unwrap().event_type,
            PaceEventType::EnrollmentStarted
        );

        // Verify stage completion timestamps
        assert!(e.stage_completed_ms.contains_key(&PaceStage::Unenrolled));
        assert!(e.stage_completed_ms.contains_key(&PaceStage::Provable));
        assert!(e.stage_completed_ms.contains_key(&PaceStage::Auditable));
        assert!(e.stage_completed_ms.contains_key(&PaceStage::Compliant));
    }

    #[test]
    fn test_audit_log_tracks_events() {
        let mut e = make_enrollment();
        assert_eq!(e.audit_log.len(), 1); // EnrollmentStarted

        e.add_contact("did:exo:alice", "Alice", ContactRelationship::Family, 1000)
            .unwrap();
        assert_eq!(e.audit_log.len(), 2); // + ContactAdded

        e.remove_contact("did:exo:alice", 1500).unwrap();
        assert_eq!(e.audit_log.len(), 3); // + ContactRemoved

        assert_eq!(e.audit_log[1].event_type, PaceEventType::ContactAdded);
        assert_eq!(e.audit_log[2].event_type, PaceEventType::ContactRemoved);
    }
}
