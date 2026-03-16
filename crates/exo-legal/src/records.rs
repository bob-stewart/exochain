//! Self-authenticating business records (LEG-001, LEG-002, LEG-003).
//!
//! Implements FRE 803(6) compliant record authentication with BLAKE3
//! content hashing and third-party timestamp anchoring.

use chrono::{DateTime, Utc};
use exo_core::crypto::{hash_bytes, Blake3Hash};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Type of business record.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum RecordType {
    /// Decision record — captures the full decision object.
    Decision,
    /// Vote record — individual vote cast.
    Vote,
    /// Delegation record — authority delegation.
    Delegation,
    /// Constitutional amendment record.
    ConstitutionalAmendment,
    /// Audit trail segment.
    AuditSegment,
    /// Evidence attachment.
    Evidence,
    /// Meeting minutes or deliberation transcript.
    Deliberation,
    /// Custom record type.
    Custom(String),
}

/// A self-authenticating business record per FRE 803(6).
///
/// Each record is content-addressed, timestamped, and carries
/// a hash chain link for tamper evidence.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AuthenticatedRecord {
    /// Unique record identifier.
    pub id: Uuid,
    /// Type classification.
    pub record_type: RecordType,
    /// Tenant context.
    pub tenant_id: String,
    /// BLAKE3 hash of the record content.
    pub content_hash: Blake3Hash,
    /// Serialized record content (CBOR or JSON).
    pub content: Vec<u8>,
    /// Timestamp of record creation.
    pub created_at: DateTime<Utc>,
    /// Identity of the record custodian.
    pub custodian: String,
    /// Previous record hash in the chain (for continuity).
    pub prev_record_hash: Option<Blake3Hash>,
    /// Third-party timestamp anchor (e.g., RFC 3161 TSA response hash).
    pub timestamp_anchor: Option<TimestampAnchor>,
    /// Hash of this entire record for chain linkage.
    pub record_hash: Blake3Hash,
}

/// Third-party timestamp anchor for legal admissibility.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TimestampAnchor {
    /// Authority that issued the timestamp.
    pub authority: String,
    /// The anchored hash value.
    pub anchored_hash: Blake3Hash,
    /// When the anchor was issued.
    pub anchored_at: DateTime<Utc>,
    /// Raw anchor response (e.g., RFC 3161 token).
    pub anchor_token: Vec<u8>,
}

/// Record authentication service.
pub struct RecordAuthentication {
    chain_head: Option<Blake3Hash>,
}

impl RecordAuthentication {
    pub fn new() -> Self {
        Self { chain_head: None }
    }

    /// Create a new authenticated record from raw content.
    pub fn create_record(
        &mut self,
        record_type: RecordType,
        tenant_id: String,
        content: Vec<u8>,
        custodian: String,
    ) -> AuthenticatedRecord {
        let content_hash = hash_bytes(&content);
        let id = Uuid::new_v4();
        let created_at = Utc::now();
        let prev_record_hash = self.chain_head;

        let record_hash = self.compute_record_hash(
            &id,
            &content_hash,
            &created_at,
            &custodian,
            prev_record_hash.as_ref(),
        );

        self.chain_head = Some(record_hash);

        AuthenticatedRecord {
            id,
            record_type,
            tenant_id,
            content_hash,
            content,
            created_at,
            custodian,
            prev_record_hash,
            timestamp_anchor: None,
            record_hash,
        }
    }

    /// Verify the integrity of a record's content hash.
    pub fn verify_content(record: &AuthenticatedRecord) -> bool {
        let computed = hash_bytes(&record.content);
        computed == record.content_hash
    }

    /// Verify the chain linkage of a sequence of records.
    pub fn verify_chain(records: &[AuthenticatedRecord]) -> bool {
        for (i, record) in records.iter().enumerate() {
            if i == 0 {
                if record.prev_record_hash.is_some() {
                    return false;
                }
            } else if record.prev_record_hash != Some(records[i - 1].record_hash) {
                return false;
            }
            if !Self::verify_content(record) {
                return false;
            }
        }
        true
    }

    fn compute_record_hash(
        &self,
        id: &Uuid,
        content_hash: &Blake3Hash,
        created_at: &DateTime<Utc>,
        custodian: &str,
        prev_hash: Option<&Blake3Hash>,
    ) -> Blake3Hash {
        let mut preimage = Vec::new();
        preimage.extend_from_slice(id.as_bytes());
        preimage.extend_from_slice(&content_hash.0);
        preimage.extend_from_slice(created_at.to_rfc3339().as_bytes());
        preimage.extend_from_slice(custodian.as_bytes());
        if let Some(ph) = prev_hash {
            preimage.extend_from_slice(&ph.0);
        }
        hash_bytes(&preimage)
    }
}

impl Default for RecordAuthentication {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_create_and_verify_record() {
        let mut auth = RecordAuthentication::new();
        let record = auth.create_record(
            RecordType::Decision,
            "tenant-1".into(),
            b"decision content".to_vec(),
            "did:exo:custodian".into(),
        );

        assert!(RecordAuthentication::verify_content(&record));
        assert!(record.prev_record_hash.is_none());
    }

    #[test]
    fn test_record_chain() {
        let mut auth = RecordAuthentication::new();
        let r1 = auth.create_record(
            RecordType::Decision,
            "tenant-1".into(),
            b"first".to_vec(),
            "did:exo:alice".into(),
        );
        let r2 = auth.create_record(
            RecordType::Vote,
            "tenant-1".into(),
            b"second".to_vec(),
            "did:exo:alice".into(),
        );
        let r3 = auth.create_record(
            RecordType::Delegation,
            "tenant-1".into(),
            b"third".to_vec(),
            "did:exo:alice".into(),
        );

        assert!(r1.prev_record_hash.is_none());
        assert_eq!(r2.prev_record_hash, Some(r1.record_hash));
        assert_eq!(r3.prev_record_hash, Some(r2.record_hash));
        assert!(RecordAuthentication::verify_chain(&[r1, r2, r3]));
    }

    #[test]
    fn test_tampered_content_detected() {
        let mut auth = RecordAuthentication::new();
        let mut record = auth.create_record(
            RecordType::Decision,
            "tenant-1".into(),
            b"original".to_vec(),
            "did:exo:alice".into(),
        );
        record.content = b"tampered".to_vec();
        assert!(!RecordAuthentication::verify_content(&record));
    }
}
