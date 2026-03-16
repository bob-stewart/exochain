//! TEE (Trusted Execution Environment) interfaces.
//!
//! Provides attestation verification for hardware-backed secure enclaves.
//! The MockGatekeeper implements a software-based attestation for development
//! and testing. Production deployments use SGX/SEV-SNP/TDX.

use exo_core::crypto::{hash_bytes, Blake3Hash};
use serde::{Deserialize, Serialize};

/// A TEE attestation report.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TeeAttestation {
    /// Platform type (SGX, SEV-SNP, TDX, Mock).
    pub platform: TeePlatform,
    /// Measurement of the enclave contents.
    pub measurement: Blake3Hash,
    /// Nonce for freshness.
    pub nonce: [u8; 32],
    /// Timestamp of attestation.
    pub attested_at: u64,
    /// Signature over the report.
    pub signature: Vec<u8>,
}

/// Supported TEE platforms.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum TeePlatform {
    /// Intel SGX.
    Sgx,
    /// AMD SEV-SNP.
    SevSnp,
    /// Intel TDX.
    Tdx,
    /// Software mock for development.
    Mock,
}

/// TEE attestation report for verification.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TeeReport {
    pub platform: TeePlatform,
    pub measurement: Blake3Hash,
    pub nonce: [u8; 32],
    pub attested_at: u64,
}

impl TeeReport {
    /// Verify that the measurement is non-zero (basic sanity check).
    pub fn verify(&self) -> bool {
        self.measurement.0 != [0u8; 32]
    }
}

/// Mock Gatekeeper for development — software-based attestation.
pub struct MockGatekeeper {
    secret: Vec<u8>,
}

impl MockGatekeeper {
    pub fn new(secret: &[u8]) -> Self {
        Self {
            secret: secret.to_vec(),
        }
    }

    /// Create a mock attestation for the given policy hashes.
    pub fn attest(&self, policy_hashes: &[Blake3Hash], nonce: [u8; 32], timestamp: u64) -> TeeAttestation {
        // Compute measurement as BLAKE3(policy_hashes concatenated)
        let mut data = Vec::new();
        data.extend_from_slice(b"EXOCHAIN-TEE-MOCK-v1:");
        for h in policy_hashes {
            data.extend_from_slice(&h.0);
        }
        let measurement = hash_bytes(&data);

        // Sign = BLAKE3(secret || measurement || nonce)
        let mut sig_data = Vec::new();
        sig_data.extend_from_slice(&self.secret);
        sig_data.extend_from_slice(&measurement.0);
        sig_data.extend_from_slice(&nonce);
        let sig_hash = hash_bytes(&sig_data);

        TeeAttestation {
            platform: TeePlatform::Mock,
            measurement,
            nonce,
            attested_at: timestamp,
            signature: sig_hash.0.to_vec(),
        }
    }

    /// Verify a mock attestation.
    pub fn verify_attestation(&self, att: &TeeAttestation) -> bool {
        // Recompute signature
        let mut sig_data = Vec::new();
        sig_data.extend_from_slice(&self.secret);
        sig_data.extend_from_slice(&att.measurement.0);
        sig_data.extend_from_slice(&att.nonce);
        let expected = hash_bytes(&sig_data);
        att.signature == expected.0.to_vec()
    }

    /// Generate an access token from an attestation.
    pub fn request_access(&self, att: &TeeAttestation) -> Option<String> {
        if self.verify_attestation(att) {
            let mut token_data = Vec::new();
            token_data.extend_from_slice(b"EXOCHAIN-ACCESS-v1:");
            token_data.extend_from_slice(&att.measurement.0);
            token_data.extend_from_slice(&att.attested_at.to_le_bytes());
            let token_hash = hash_bytes(&token_data);
            Some(hex::encode(token_hash.0))
        } else {
            None
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mock_attestation_roundtrip() {
        let gk = MockGatekeeper::new(b"test-secret");
        let hashes = vec![Blake3Hash([1u8; 32]), Blake3Hash([2u8; 32])];
        let att = gk.attest(&hashes, [0u8; 32], 1000);
        assert_eq!(att.platform, TeePlatform::Mock);
        assert!(gk.verify_attestation(&att));
    }

    #[test]
    fn test_tampered_attestation_rejected() {
        let gk = MockGatekeeper::new(b"test-secret");
        let hashes = vec![Blake3Hash([1u8; 32])];
        let mut att = gk.attest(&hashes, [0u8; 32], 1000);
        att.measurement = Blake3Hash([99u8; 32]); // tamper
        assert!(!gk.verify_attestation(&att));
    }

    #[test]
    fn test_wrong_secret_rejected() {
        let gk1 = MockGatekeeper::new(b"secret-1");
        let gk2 = MockGatekeeper::new(b"secret-2");
        let hashes = vec![Blake3Hash([1u8; 32])];
        let att = gk1.attest(&hashes, [0u8; 32], 1000);
        assert!(!gk2.verify_attestation(&att));
    }

    #[test]
    fn test_access_token_generation() {
        let gk = MockGatekeeper::new(b"test-secret");
        let hashes = vec![Blake3Hash([1u8; 32])];
        let att = gk.attest(&hashes, [0u8; 32], 1000);
        let token = gk.request_access(&att);
        assert!(token.is_some());
        assert_eq!(token.unwrap().len(), 64); // 32 bytes hex-encoded
    }

    #[test]
    fn test_access_denied_for_invalid_attestation() {
        let gk = MockGatekeeper::new(b"test-secret");
        let mut att = gk.attest(&[], [0u8; 32], 1000);
        att.signature = vec![0u8; 32]; // invalid
        assert!(gk.request_access(&att).is_none());
    }

    #[test]
    fn test_tee_report_verify() {
        let report = TeeReport {
            platform: TeePlatform::Mock,
            measurement: Blake3Hash([1u8; 32]),
            nonce: [0u8; 32],
            attested_at: 1000,
        };
        assert!(report.verify());

        let empty = TeeReport {
            platform: TeePlatform::Mock,
            measurement: Blake3Hash([0u8; 32]),
            nonce: [0u8; 32],
            attested_at: 1000,
        };
        assert!(!empty.verify());
    }
}
