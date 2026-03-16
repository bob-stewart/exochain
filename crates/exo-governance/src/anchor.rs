//! AnchorReceipt — immutable reference of record_hash in the EXOCHAIN custody spine
//!
//! Per the decision.forum whitepaper: "An AnchorReceipt MUST reference the record_hash."
//! Anchoring is pluggable: local simulation for MVP, EXOCHAIN provider for production.
//!
//! Satisfies: ARCH-001 (Merkle-DAG), TNC-03 (audit continuity), LEG-001 (business records)

use exo_core::crypto::Blake3Hash;
use exo_core::hlc::HybridLogicalClock;
use serde::{Deserialize, Serialize};

/// The anchoring provider used.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum AnchorProvider {
    /// EXOCHAIN DAG store — production provider.
    Exochain,
    /// Local file-based simulation — MVP/dev.
    LocalSimulation,
    /// Third-party timestamping service.
    TimestampService { service_name: String },
    /// External blockchain.
    ExternalChain { chain_name: String },
    /// Custom provider.
    Custom(String),
}

/// Verification status of an anchor.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum AnchorVerificationStatus {
    /// Anchor has been verified against the provider.
    Verified,
    /// Anchor exists but has not been verified yet.
    Unverified,
    /// Verification failed — integrity compromised.
    Failed { reason: String },
    /// Provider unavailable for verification.
    Unavailable,
}

/// An AnchorReceipt — immutable proof that a record_hash was anchored.
///
/// Per whitepaper:
/// - An AnchorReceipt MUST reference the record_hash.
/// - Anchor providers MUST return a verifiable receipt (txid or equivalent).
/// - Systems SHOULD treat anchoring as optional but recommended for high-stakes decisions.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AnchorReceipt {
    /// Unique receipt identifier.
    pub id: String,
    /// The DecisionRecord ID this anchor references.
    pub record_id: Blake3Hash,
    /// The record_hash at time of anchoring.
    pub record_hash: Blake3Hash,
    /// Provider used for anchoring.
    pub provider: AnchorProvider,
    /// Transaction ID or equivalent verifiable reference from the provider.
    pub txid: String,
    /// Block number or sequence in the anchor chain (if applicable).
    pub block_number: Option<u64>,
    /// Merkle inclusion proof from the provider (if applicable).
    pub inclusion_proof: Option<Vec<u8>>,
    /// Timestamp of anchoring.
    pub anchored_at: HybridLogicalClock,
    /// Last verification status.
    pub verification_status: AnchorVerificationStatus,
    /// Last verification timestamp.
    pub last_verified_at: Option<HybridLogicalClock>,
}

impl AnchorReceipt {
    /// Create a new anchor receipt from an EXOCHAIN anchoring.
    pub fn from_exochain(
        record_id: Blake3Hash,
        record_hash: Blake3Hash,
        txid: String,
        block_number: u64,
        inclusion_proof: Vec<u8>,
        timestamp: HybridLogicalClock,
    ) -> Self {
        Self {
            id: format!("anc-{}-{}", record_id.0[0], timestamp.physical_ms),
            record_id,
            record_hash,
            provider: AnchorProvider::Exochain,
            txid,
            block_number: Some(block_number),
            inclusion_proof: Some(inclusion_proof),
            anchored_at: timestamp,
            verification_status: AnchorVerificationStatus::Unverified,
            last_verified_at: None,
        }
    }

    /// Create a local simulation anchor (for MVP/dev).
    pub fn local_simulation(
        record_id: Blake3Hash,
        record_hash: Blake3Hash,
        timestamp: HybridLogicalClock,
    ) -> Self {
        // Compute a deterministic "txid" from the record hash
        let sim_txid = format!(
            "sim-{:02x}{:02x}{:02x}{:02x}",
            record_hash.0[0], record_hash.0[1], record_hash.0[2], record_hash.0[3]
        );

        Self {
            id: format!("anc-sim-{}", timestamp.physical_ms),
            record_id,
            record_hash,
            provider: AnchorProvider::LocalSimulation,
            txid: sim_txid,
            block_number: None,
            inclusion_proof: None,
            anchored_at: timestamp,
            verification_status: AnchorVerificationStatus::Verified,
            last_verified_at: Some(timestamp),
        }
    }

    /// Verify this receipt against its provider.
    /// In production, this would call the EXOCHAIN DAG store to verify inclusion.
    /// For MVP, local simulation always verifies successfully.
    pub fn verify(&mut self, timestamp: HybridLogicalClock) -> bool {
        match &self.provider {
            AnchorProvider::LocalSimulation => {
                self.verification_status = AnchorVerificationStatus::Verified;
                self.last_verified_at = Some(timestamp);
                true
            }
            AnchorProvider::Exochain => {
                // In production: call exo_dag::verify_integrity() with inclusion_proof
                // For now, mark as verified if we have an inclusion proof
                if self.inclusion_proof.is_some() {
                    self.verification_status = AnchorVerificationStatus::Verified;
                    self.last_verified_at = Some(timestamp);
                    true
                } else {
                    self.verification_status = AnchorVerificationStatus::Failed {
                        reason: "No inclusion proof available".to_string(),
                    };
                    self.last_verified_at = Some(timestamp);
                    false
                }
            }
            _ => {
                self.verification_status = AnchorVerificationStatus::Unavailable;
                self.last_verified_at = Some(timestamp);
                false
            }
        }
    }

    /// Whether this anchor is currently verified.
    pub fn is_verified(&self) -> bool {
        matches!(
            self.verification_status,
            AnchorVerificationStatus::Verified
        )
    }
}

/// Registry of anchored decisions for efficient lookup.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct AnchorRegistry {
    /// All anchor receipts indexed by record_id.
    pub receipts: Vec<AnchorReceipt>,
}

impl AnchorRegistry {
    pub fn new() -> Self {
        Self {
            receipts: Vec::new(),
        }
    }

    /// Register a new anchor receipt.
    pub fn register(&mut self, receipt: AnchorReceipt) {
        self.receipts.push(receipt);
    }

    /// Find all anchors for a specific decision record.
    pub fn find_by_record(&self, record_id: &Blake3Hash) -> Vec<&AnchorReceipt> {
        self.receipts
            .iter()
            .filter(|r| r.record_id == *record_id)
            .collect()
    }

    /// Find anchor by txid.
    pub fn find_by_txid(&self, txid: &str) -> Option<&AnchorReceipt> {
        self.receipts.iter().find(|r| r.txid == txid)
    }

    /// Get all verified anchors.
    pub fn verified(&self) -> Vec<&AnchorReceipt> {
        self.receipts.iter().filter(|r| r.is_verified()).collect()
    }

    /// Total number of anchors.
    pub fn len(&self) -> usize {
        self.receipts.len()
    }

    pub fn is_empty(&self) -> bool {
        self.receipts.is_empty()
    }
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
    fn test_local_simulation_anchor() {
        let record_id = Blake3Hash([1u8; 32]);
        let record_hash = Blake3Hash([2u8; 32]);
        let receipt = AnchorReceipt::local_simulation(record_id, record_hash, test_hlc(1000));

        assert!(receipt.is_verified());
        assert_eq!(receipt.provider, AnchorProvider::LocalSimulation);
        assert!(receipt.txid.starts_with("sim-"));
    }

    #[test]
    fn test_exochain_anchor() {
        let record_id = Blake3Hash([1u8; 32]);
        let record_hash = Blake3Hash([2u8; 32]);
        let receipt = AnchorReceipt::from_exochain(
            record_id,
            record_hash,
            "tx-abc123".to_string(),
            42,
            vec![0u8; 64],
            test_hlc(1000),
        );

        assert!(!receipt.is_verified()); // Unverified until verify() called
        assert_eq!(receipt.provider, AnchorProvider::Exochain);
        assert_eq!(receipt.block_number, Some(42));
    }

    #[test]
    fn test_verify_exochain_with_proof() {
        let mut receipt = AnchorReceipt::from_exochain(
            Blake3Hash([1u8; 32]),
            Blake3Hash([2u8; 32]),
            "tx-abc123".to_string(),
            42,
            vec![0u8; 64],
            test_hlc(1000),
        );

        assert!(receipt.verify(test_hlc(2000)));
        assert!(receipt.is_verified());
    }

    #[test]
    fn test_verify_exochain_without_proof() {
        let mut receipt = AnchorReceipt::from_exochain(
            Blake3Hash([1u8; 32]),
            Blake3Hash([2u8; 32]),
            "tx-abc123".to_string(),
            42,
            vec![0u8; 64],
            test_hlc(1000),
        );
        receipt.inclusion_proof = None;

        assert!(!receipt.verify(test_hlc(2000)));
        assert!(!receipt.is_verified());
    }

    #[test]
    fn test_anchor_registry() {
        let mut registry = AnchorRegistry::new();
        assert!(registry.is_empty());

        let record_id = Blake3Hash([1u8; 32]);
        let receipt1 = AnchorReceipt::local_simulation(
            record_id,
            Blake3Hash([2u8; 32]),
            test_hlc(1000),
        );
        let receipt2 = AnchorReceipt::local_simulation(
            Blake3Hash([3u8; 32]),
            Blake3Hash([4u8; 32]),
            test_hlc(2000),
        );

        registry.register(receipt1);
        registry.register(receipt2);

        assert_eq!(registry.len(), 2);
        assert_eq!(registry.find_by_record(&record_id).len(), 1);
        assert_eq!(registry.verified().len(), 2); // Both local sims are auto-verified
    }

    #[test]
    fn test_find_by_txid() {
        let mut registry = AnchorRegistry::new();
        let receipt = AnchorReceipt::from_exochain(
            Blake3Hash([1u8; 32]),
            Blake3Hash([2u8; 32]),
            "tx-unique-123".to_string(),
            42,
            vec![0u8; 64],
            test_hlc(1000),
        );

        registry.register(receipt);
        assert!(registry.find_by_txid("tx-unique-123").is_some());
        assert!(registry.find_by_txid("tx-nonexistent").is_none());
    }
}
