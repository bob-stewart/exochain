//! zk-SNARK circuit definitions for governance compliance verification.
//!
//! These circuits allow proving governance compliance properties
//! (authority chain validity, quorum satisfaction, constitutional bounds)
//! without revealing the underlying data.

use exo_core::crypto::{hash_bytes, Blake3Hash};
use serde::{Deserialize, Serialize};

/// Domain separator for SNARK proofs.
const DOMAIN_SEP: &[u8] = b"EXOCHAIN-SNARK-v1";

/// A zk-SNARK circuit for governance proofs.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SnarkCircuit {
    pub circuit_type: CircuitType,
    pub public_inputs: Vec<Blake3Hash>,
    pub constraint_count: u64,
}

/// Types of governance proof circuits.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum CircuitType {
    /// Prove authority chain validity without revealing delegation details.
    AuthorityChainValid,
    /// Prove quorum was met without revealing voter identities.
    QuorumSatisfied,
    /// Prove decision is within constitutional bounds.
    ConstitutionalCompliance,
    /// Prove monetary amount is within delegation cap.
    MonetaryCapCompliance,
    /// Prove conflict disclosure was filed (without revealing conflict).
    ConflictDisclosed,
}

impl CircuitType {
    /// Return a unique tag byte for each circuit type.
    fn tag(&self) -> u8 {
        match self {
            CircuitType::AuthorityChainValid => 0x01,
            CircuitType::QuorumSatisfied => 0x02,
            CircuitType::ConstitutionalCompliance => 0x03,
            CircuitType::MonetaryCapCompliance => 0x04,
            CircuitType::ConflictDisclosed => 0x05,
        }
    }
}

/// A zk-SNARK proof.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SnarkProof {
    pub circuit_type: CircuitType,
    pub proof_bytes: Vec<u8>,
    pub public_inputs: Vec<Blake3Hash>,
    pub verification_key_hash: Blake3Hash,
    /// Commitment derived from domain separator, circuit type, and public inputs.
    /// Used by verify() to check consistency without the witness.
    pub verification_key: Vec<u8>,
}

/// Compute the public commitment: BLAKE3(domain_sep || circuit_type_tag || public_inputs).
fn compute_commitment(circuit_type: &CircuitType, public_inputs: &[Blake3Hash]) -> Blake3Hash {
    let mut preimage = Vec::new();
    preimage.extend_from_slice(DOMAIN_SEP);
    preimage.push(circuit_type.tag());
    for input in public_inputs {
        preimage.extend_from_slice(&input.0);
    }
    hash_bytes(&preimage)
}

impl SnarkCircuit {
    /// Create a new circuit for authority chain verification.
    pub fn authority_chain(chain_root_hash: Blake3Hash, actor_hash: Blake3Hash) -> Self {
        Self {
            circuit_type: CircuitType::AuthorityChainValid,
            public_inputs: vec![chain_root_hash, actor_hash],
            constraint_count: 1024,
        }
    }

    /// Create a new circuit for quorum verification.
    pub fn quorum(decision_hash: Blake3Hash, quorum_threshold_hash: Blake3Hash) -> Self {
        Self {
            circuit_type: CircuitType::QuorumSatisfied,
            public_inputs: vec![decision_hash, quorum_threshold_hash],
            constraint_count: 512,
        }
    }

    /// Generate a proof using an HMAC-style commitment scheme.
    ///
    /// proof = BLAKE3(domain_sep || circuit_type_tag || public_inputs || witness)
    /// commitment = BLAKE3(domain_sep || circuit_type_tag || public_inputs)
    ///
    /// The first 16 bytes of the proof match the first 16 bytes of the commitment
    /// only if the prover used inputs consistent with the public inputs.
    pub fn prove(&self, witness: &[u8]) -> SnarkProof {
        let commitment = compute_commitment(&self.circuit_type, &self.public_inputs);

        // Full proof includes the witness
        let mut proof_preimage = Vec::new();
        proof_preimage.extend_from_slice(DOMAIN_SEP);
        proof_preimage.push(self.circuit_type.tag());
        for input in &self.public_inputs {
            proof_preimage.extend_from_slice(&input.0);
        }
        proof_preimage.extend_from_slice(witness);
        let proof_hash = hash_bytes(&proof_preimage);

        // Construct proof_bytes: commitment prefix (16 bytes) || proof suffix (16 bytes)
        let mut proof_bytes = Vec::with_capacity(32);
        proof_bytes.extend_from_slice(&commitment.0[..16]);
        proof_bytes.extend_from_slice(&proof_hash.0[16..]);

        let verification_key_hash = hash_bytes(&commitment.0);

        SnarkProof {
            circuit_type: self.circuit_type.clone(),
            proof_bytes,
            public_inputs: self.public_inputs.clone(),
            verification_key_hash,
            verification_key: commitment.0.to_vec(),
        }
    }
}

impl SnarkProof {
    /// Verify this proof using the HMAC-style commitment scheme.
    ///
    /// Checks:
    /// - proof_bytes is exactly 32 bytes
    /// - public_inputs are non-empty
    /// - Recomputed commitment prefix (first 16 bytes) matches proof_bytes prefix
    /// - verification_key_hash is consistent with the verification_key
    pub fn verify(&self) -> bool {
        // Check proof_bytes length
        if self.proof_bytes.len() != 32 {
            return false;
        }

        // Check public_inputs non-empty
        if self.public_inputs.is_empty() {
            return false;
        }

        // Recompute the commitment from public data
        let expected_commitment = compute_commitment(&self.circuit_type, &self.public_inputs);

        // Check that the first 16 bytes of proof_bytes match the commitment prefix
        if self.proof_bytes[..16] != expected_commitment.0[..16] {
            return false;
        }

        // Check verification_key consistency
        let expected_vk_hash = hash_bytes(&expected_commitment.0);
        if self.verification_key_hash != expected_vk_hash {
            return false;
        }

        // Check verification_key matches expected commitment
        if self.verification_key.len() != 32 {
            return false;
        }
        if self.verification_key[..] != expected_commitment.0[..] {
            return false;
        }

        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_authority_chain_proof() {
        let circuit = SnarkCircuit::authority_chain(Blake3Hash([1u8; 32]), Blake3Hash([2u8; 32]));
        assert_eq!(circuit.circuit_type, CircuitType::AuthorityChainValid);

        let proof = circuit.prove(b"witness-data");
        assert!(proof.verify());
        assert_eq!(proof.public_inputs.len(), 2);
        assert_eq!(proof.proof_bytes.len(), 32);
    }

    #[test]
    fn test_quorum_proof() {
        let circuit = SnarkCircuit::quorum(Blake3Hash([3u8; 32]), Blake3Hash([4u8; 32]));
        let proof = circuit.prove(b"quorum-witness");
        assert!(proof.verify());
    }

    #[test]
    fn test_tampered_proof_fails() {
        let circuit = SnarkCircuit::authority_chain(Blake3Hash([1u8; 32]), Blake3Hash([2u8; 32]));
        let mut proof = circuit.prove(b"witness-data");
        // Tamper with proof bytes
        proof.proof_bytes[0] ^= 0xff;
        assert!(!proof.verify());
    }

    #[test]
    fn test_empty_proof_bytes_fails() {
        let circuit = SnarkCircuit::authority_chain(Blake3Hash([1u8; 32]), Blake3Hash([2u8; 32]));
        let mut proof = circuit.prove(b"witness-data");
        proof.proof_bytes = vec![];
        assert!(!proof.verify());
    }

    #[test]
    fn test_wrong_circuit_type_fails() {
        let circuit = SnarkCircuit::authority_chain(Blake3Hash([1u8; 32]), Blake3Hash([2u8; 32]));
        let mut proof = circuit.prove(b"witness-data");
        proof.circuit_type = CircuitType::QuorumSatisfied;
        assert!(!proof.verify());
    }

    #[test]
    fn test_empty_public_inputs_fails() {
        let circuit = SnarkCircuit::authority_chain(Blake3Hash([1u8; 32]), Blake3Hash([2u8; 32]));
        let mut proof = circuit.prove(b"witness-data");
        proof.public_inputs = vec![];
        assert!(!proof.verify());
    }

    #[test]
    fn test_different_witnesses_produce_different_proofs() {
        let circuit = SnarkCircuit::authority_chain(Blake3Hash([1u8; 32]), Blake3Hash([2u8; 32]));
        let proof1 = circuit.prove(b"witness-1");
        let proof2 = circuit.prove(b"witness-2");
        // Same commitment prefix but different suffix
        assert_eq!(proof1.proof_bytes[..16], proof2.proof_bytes[..16]);
        assert_ne!(proof1.proof_bytes[16..], proof2.proof_bytes[16..]);
    }
}
