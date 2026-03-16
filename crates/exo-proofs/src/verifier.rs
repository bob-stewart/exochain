//! Unified proof verification interface.

use crate::snark::SnarkProof;
use crate::stark::StarkProof;
use crate::zkml::AiProvenanceProof;
use serde::{Deserialize, Serialize};

/// Proof type discriminator.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum ProofType {
    Snark,
    Stark,
    ZkMl,
}

/// Result of proof verification.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct VerificationResult {
    pub proof_type: ProofType,
    pub valid: bool,
    pub message: String,
}

/// Unified verifier that can verify any proof type.
pub struct UnifiedVerifier;

impl UnifiedVerifier {
    /// Verify a SNARK proof.
    pub fn verify_snark(proof: &SnarkProof) -> VerificationResult {
        let valid = proof.verify();
        VerificationResult {
            proof_type: ProofType::Snark,
            valid,
            message: if valid {
                format!("SNARK proof for {:?} verified", proof.circuit_type)
            } else {
                "SNARK proof verification failed".into()
            },
        }
    }

    /// Verify a STARK proof.
    pub fn verify_stark(proof: &StarkProof) -> VerificationResult {
        let valid = proof.verify();
        VerificationResult {
            proof_type: ProofType::Stark,
            valid,
            message: if valid {
                format!("STARK proof verified: {}", proof.statement)
            } else {
                "STARK proof verification failed".into()
            },
        }
    }

    /// Verify a zkML proof.
    pub fn verify_zkml(proof: &AiProvenanceProof) -> VerificationResult {
        let valid = proof.verify();
        VerificationResult {
            proof_type: ProofType::ZkMl,
            valid,
            message: if valid {
                format!(
                    "zkML proof verified: model {} with confidence {:.2}%",
                    proof.model_version,
                    proof.confidence_score * 100.0
                )
            } else {
                "zkML proof verification failed".into()
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::snark::SnarkCircuit;
    use crate::stark::StarkProver;
    use crate::zkml::ZkMlProver;
    use exo_core::crypto::Blake3Hash;

    #[test]
    fn test_unified_snark_verification() {
        let circuit = SnarkCircuit::authority_chain(Blake3Hash([1u8; 32]), Blake3Hash([2u8; 32]));
        let proof = circuit.prove(b"witness");
        let result = UnifiedVerifier::verify_snark(&proof);
        assert!(result.valid);
        assert_eq!(result.proof_type, ProofType::Snark);
    }

    #[test]
    fn test_unified_stark_verification() {
        let prover = StarkProver::default_security();
        let proof = prover.prove_audit_integrity(Blake3Hash([1u8; 32]), 500);
        let result = UnifiedVerifier::verify_stark(&proof);
        assert!(result.valid);
        assert_eq!(result.proof_type, ProofType::Stark);
    }

    #[test]
    fn test_unified_zkml_verification() {
        let proof = ZkMlProver::prove_recommendation(
            Blake3Hash([1u8; 32]),
            b"input",
            b"output",
            0.87,
            "model-v1".into(),
        );
        let result = UnifiedVerifier::verify_zkml(&proof);
        assert!(result.valid);
        assert_eq!(result.proof_type, ProofType::ZkMl);
        assert!(result.message.contains("87.00%"));
    }
}
