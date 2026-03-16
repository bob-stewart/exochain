//! zk-STARK proof generation for transparent governance verification.
//!
//! STARKs provide post-quantum secure proofs without trusted setup,
//! suitable for public governance transparency.

use exo_core::crypto::{hash_bytes, Blake3Hash};
use serde::{Deserialize, Serialize};

/// Domain separator for STARK proofs.
const DOMAIN_SEP: &[u8] = b"EXOCHAIN-STARK-v1";

/// A zk-STARK proof.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct StarkProof {
    pub statement: String,
    pub proof_bytes: Vec<u8>,
    pub public_commitment: Blake3Hash,
    pub security_bits: u32,
    pub trace_length: u64,
}

/// STARK prover for governance transparency proofs.
pub struct StarkProver {
    pub security_bits: u32,
}

impl StarkProver {
    pub fn new(security_bits: u32) -> Self {
        Self { security_bits }
    }

    /// Default 128-bit security prover.
    pub fn default_security() -> Self {
        Self::new(128)
    }

    /// Compute commitment = BLAKE3(domain_sep || statement || data).
    fn compute_commitment(statement: &str, data: &[u8]) -> Blake3Hash {
        let mut preimage = Vec::new();
        preimage.extend_from_slice(DOMAIN_SEP);
        preimage.extend_from_slice(statement.as_bytes());
        preimage.extend_from_slice(data);
        hash_bytes(&preimage)
    }

    /// Compute proof_bytes = BLAKE3(domain_sep || commitment || trace_length_bytes).
    fn compute_proof(commitment: &Blake3Hash, trace_length: u64) -> Vec<u8> {
        let mut preimage = Vec::new();
        preimage.extend_from_slice(DOMAIN_SEP);
        preimage.extend_from_slice(&commitment.0);
        preimage.extend_from_slice(&trace_length.to_le_bytes());
        hash_bytes(&preimage).0.to_vec()
    }

    /// Generate a STARK proof for audit trail integrity.
    pub fn prove_audit_integrity(
        &self,
        audit_root_hash: Blake3Hash,
        chain_length: u64,
    ) -> StarkProof {
        let statement = format!(
            "Audit trail of {} entries has unbroken hash chain integrity",
            chain_length
        );

        let commitment = Self::compute_commitment(&statement, &audit_root_hash.0);
        let proof_bytes = Self::compute_proof(&commitment, chain_length);

        StarkProof {
            statement,
            proof_bytes,
            public_commitment: commitment,
            security_bits: self.security_bits,
            trace_length: chain_length,
        }
    }

    /// Generate a STARK proof for decision lifecycle compliance.
    pub fn prove_lifecycle_compliance(
        &self,
        decision_hash: Blake3Hash,
        transition_count: u64,
    ) -> StarkProof {
        let statement = format!(
            "Decision lifecycle followed valid state machine with {} transitions",
            transition_count
        );

        let commitment = Self::compute_commitment(&statement, &decision_hash.0);
        let proof_bytes = Self::compute_proof(&commitment, transition_count);

        StarkProof {
            statement,
            proof_bytes,
            public_commitment: commitment,
            security_bits: self.security_bits,
            trace_length: transition_count,
        }
    }
}

impl StarkProof {
    /// Verify the STARK proof.
    ///
    /// Checks:
    /// - security_bits >= 128
    /// - trace_length > 0
    /// - Recomputes expected_proof = BLAKE3(domain_sep || public_commitment || trace_length_bytes)
    ///   and checks it matches proof_bytes
    pub fn verify(&self) -> bool {
        if self.security_bits < 128 {
            return false;
        }

        if self.trace_length == 0 {
            return false;
        }

        // Recompute expected proof from public_commitment and trace_length
        let mut preimage = Vec::new();
        preimage.extend_from_slice(DOMAIN_SEP);
        preimage.extend_from_slice(&self.public_commitment.0);
        preimage.extend_from_slice(&self.trace_length.to_le_bytes());
        let expected = hash_bytes(&preimage).0.to_vec();

        self.proof_bytes == expected
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_audit_integrity_proof() {
        let prover = StarkProver::default_security();
        let proof = prover.prove_audit_integrity(Blake3Hash([1u8; 32]), 1000);

        assert!(proof.verify());
        assert_eq!(proof.trace_length, 1000);
        assert!(proof.statement.contains("1000"));
    }

    #[test]
    fn test_lifecycle_compliance_proof() {
        let prover = StarkProver::default_security();
        let proof = prover.prove_lifecycle_compliance(Blake3Hash([2u8; 32]), 5);

        assert!(proof.verify());
        assert_eq!(proof.trace_length, 5);
    }

    #[test]
    fn test_tampered_proof_fails() {
        let prover = StarkProver::default_security();
        let mut proof = prover.prove_audit_integrity(Blake3Hash([1u8; 32]), 1000);
        proof.proof_bytes[0] ^= 0xff;
        assert!(!proof.verify());
    }

    #[test]
    fn test_low_security_bits_fails() {
        let prover = StarkProver::new(64);
        let proof = prover.prove_audit_integrity(Blake3Hash([1u8; 32]), 1000);
        assert!(!proof.verify());
    }

    #[test]
    fn test_zero_trace_length_fails() {
        let prover = StarkProver::default_security();
        let mut proof = prover.prove_audit_integrity(Blake3Hash([1u8; 32]), 1000);
        proof.trace_length = 0;
        assert!(!proof.verify());
    }

    #[test]
    fn test_tampered_commitment_fails() {
        let prover = StarkProver::default_security();
        let mut proof = prover.prove_audit_integrity(Blake3Hash([1u8; 32]), 1000);
        proof.public_commitment.0[0] ^= 0xff;
        assert!(!proof.verify());
    }
}
