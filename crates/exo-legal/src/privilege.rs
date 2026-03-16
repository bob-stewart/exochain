//! Attorney-client privilege compartmentalization (LEG-009).
//!
//! Ensures privileged communications are cryptographically isolated
//! and access-controlled to prevent inadvertent waiver.

use chrono::{DateTime, Utc};
use exo_core::crypto::Blake3Hash;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Level of privilege protection.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
pub enum PrivilegeLevel {
    /// No privilege — public record.
    None = 0,
    /// Work product doctrine protection.
    WorkProduct = 1,
    /// Attorney-client privilege.
    AttorneyClient = 2,
    /// Joint defense / common interest privilege.
    JointDefense = 3,
}

/// A compartment for privileged communications.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PrivilegeCompartment {
    pub id: Uuid,
    pub tenant_id: String,
    pub level: PrivilegeLevel,
    pub purpose: String,
    pub authorized_viewers: Vec<String>,
    pub created_at: DateTime<Utc>,
    pub created_by: String,
    /// Content hash for integrity without exposing content.
    pub content_hash: Blake3Hash,
    /// Encrypted content — only decryptable by authorized viewers.
    pub encrypted_content: Vec<u8>,
    /// Whether this compartment has been reviewed for privilege log.
    pub logged_for_discovery: bool,
}

impl PrivilegeCompartment {
    /// Create a new privilege compartment.
    pub fn new(
        tenant_id: String,
        level: PrivilegeLevel,
        purpose: String,
        authorized_viewers: Vec<String>,
        created_by: String,
        content_hash: Blake3Hash,
        encrypted_content: Vec<u8>,
    ) -> Self {
        Self {
            id: Uuid::new_v4(),
            tenant_id,
            level,
            purpose,
            authorized_viewers,
            created_at: Utc::now(),
            created_by,
            content_hash,
            encrypted_content,
            logged_for_discovery: false,
        }
    }

    /// Check if a viewer is authorized to access this compartment.
    pub fn is_authorized(&self, viewer: &str) -> bool {
        self.authorized_viewers.iter().any(|v| v == viewer)
    }

    /// Mark this compartment as logged for privilege log in discovery.
    pub fn mark_logged(&mut self) {
        self.logged_for_discovery = true;
    }

    /// Generate a privilege log entry (without revealing content).
    pub fn privilege_log_entry(&self) -> PrivilegeLogEntry {
        PrivilegeLogEntry {
            compartment_id: self.id,
            level: self.level.clone(),
            purpose: self.purpose.clone(),
            created_at: self.created_at,
            created_by: self.created_by.clone(),
            content_hash: self.content_hash,
        }
    }
}

/// Privilege log entry for e-discovery — describes privileged material
/// without revealing its content.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PrivilegeLogEntry {
    pub compartment_id: Uuid,
    pub level: PrivilegeLevel,
    pub purpose: String,
    pub created_at: DateTime<Utc>,
    pub created_by: String,
    pub content_hash: Blake3Hash,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_privilege_compartment_access() {
        let compartment = PrivilegeCompartment::new(
            "tenant-1".into(),
            PrivilegeLevel::AttorneyClient,
            "Legal advice on merger".into(),
            vec!["did:exo:ceo".into(), "did:exo:counsel".into()],
            "did:exo:counsel".into(),
            Blake3Hash([1u8; 32]),
            vec![0u8; 64],
        );

        assert!(compartment.is_authorized("did:exo:ceo"));
        assert!(compartment.is_authorized("did:exo:counsel"));
        assert!(!compartment.is_authorized("did:exo:random"));
    }

    #[test]
    fn test_privilege_log_entry() {
        let compartment = PrivilegeCompartment::new(
            "tenant-1".into(),
            PrivilegeLevel::WorkProduct,
            "Litigation analysis".into(),
            vec!["did:exo:counsel".into()],
            "did:exo:counsel".into(),
            Blake3Hash([2u8; 32]),
            vec![0u8; 32],
        );

        let entry = compartment.privilege_log_entry();
        assert_eq!(entry.level, PrivilegeLevel::WorkProduct);
        assert_eq!(entry.purpose, "Litigation analysis");
    }

    #[test]
    fn test_privilege_level_ordering() {
        assert!(PrivilegeLevel::AttorneyClient > PrivilegeLevel::WorkProduct);
        assert!(PrivilegeLevel::WorkProduct > PrivilegeLevel::None);
        assert!(PrivilegeLevel::JointDefense > PrivilegeLevel::AttorneyClient);
    }
}
