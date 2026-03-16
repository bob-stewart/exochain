use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use exo_core::{Blake3Hash, Did};
use serde::{Deserialize, Serialize};

/// Normative RiskAttestation (Spec 9.5)
/// A signed attestation from a Scoring Engine.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RiskAttestation {
    /// Subject being scored.
    pub subject: Did,

    /// Intended audience (verifier/vendor DID).
    pub audience: Did,

    /// Risk score 0-100 (higher = more trusted).
    pub score: u8,

    /// Confidence in the score (0-10000 basis points).
    pub confidence_bps: u16,

    /// Hash of factors contributing to the score.
    pub factors_hash: Blake3Hash,

    /// Hash of the adjudication request context.
    pub context_hash: Blake3Hash,

    /// Anti-replay nonce.
    pub nonce: u64,

    /// Issued timestamp (Unix ms).
    pub issued_at: u64,

    /// Expiration timestamp.
    pub expires_at: u64,

    /// Scoring Engine DID.
    pub issuer: Did,

    /// Signature.
    pub signature: Signature,
}

impl RiskAttestation {
    /// Create and sign a new RiskAttestation.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        subject: Did,
        audience: Did,
        score: u8,
        confidence_bps: u16,
        factors_hash: Blake3Hash,
        context_hash: Blake3Hash,
        nonce: u64,
        issued_at: u64,
        duration_ms: u64,
        issuer: Did,
        signing_key: &SigningKey,
    ) -> Self {
        let expires_at = issued_at + duration_ms;

        let mut attestation = Self {
            subject,
            audience,
            score,
            confidence_bps,
            factors_hash,
            context_hash,
            nonce,
            issued_at,
            expires_at,
            issuer,
            signature: Signature::from_bytes(&[0u8; 64]), // Placeholder
        };

        let preimage = attestation.compute_preimage();
        // We use a different domain separator logic or reuse the event one?
        // Spec 9.5 doesn't explicitly define a separate domain separator for RiskAttestation
        // but implies standard signing.
        // For distinctness, we should use a specific domain separator but currently reuse existing crypto util
        // which hardcodes EVENT separator.
        // TODO: Update crypto util to accept domain separator or add specific one here.
        // For MVP, using raw signature over preimage might be safer OR we accept the event separator
        // if we treat attestation as an event payload wrapper? No, it's a token.
        // Let's implement a specific sign method here if needed, or update crypto.
        // Update: `compute_signature` in exo-core uses "EXOCHAIN-EVENT-SIG-v1".
        // Use a local signer for now to capture the intent of Spec 9.5 validation (Audience check etc).

        // Actually, to avoid "Signature Forgery" threat, use a unique domain sep.
        // Just use raw ed25519 sign for now or extend crypto crate.
        // I will trust `signing_key.sign` but I need to be careful about what `compute_signature` does.
        // I'll stick to `signing_key.sign(&preimage)` raw for now to avoid EVENT collision.

        attestation.signature = signing_key.sign(&preimage);
        attestation
    }

    pub fn compute_preimage(&self) -> Vec<u8> {
        // Serialization for signing.
        // Should be canonical. Using generic CBOR for now.
        // Note: Field order matters for naive serialization.
        // Use a struct without signature for hashing to avoid circularity.
        // But for MVP, manual concatenation or partial struct is consistent.
        // Let's use a tuple for the preimage.
        let tuple = (
            &self.subject,
            &self.audience,
            self.score,
            self.confidence_bps,
            &self.factors_hash,
            &self.context_hash,
            self.nonce,
            self.issued_at,
            self.expires_at,
            &self.issuer,
        );
        serde_cbor::to_vec(&tuple).unwrap()
    }

    pub fn verify(
        &self,
        verification_key: &VerifyingKey,
    ) -> Result<(), ed25519_dalek::SignatureError> {
        let preimage = self.compute_preimage();
        verification_key.verify(&preimage, &self.signature)
    }

    pub fn is_expired(&self, current_time: u64) -> bool {
        current_time > self.expires_at
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use exo_core::hash_bytes;
    use rand::rngs::OsRng;

    #[test]
    fn test_risk_attestation_flow() {
        let mut csprng = OsRng;
        let signing_key = SigningKey::generate(&mut csprng);
        let verifying_key = signing_key.verifying_key();
        let issuer_did = "did:exo:issuer".to_string();
        let subject_did = "did:exo:subject".to_string();

        // Create attestation
        let att = RiskAttestation::new(
            subject_did,
            "did:exo:verifier".to_string(),
            85,
            9000,
            hash_bytes(b"factors"),
            hash_bytes(b"context"),
            12345,
            1000,
            300, // duration
            issuer_did,
            &signing_key,
        );

        // Verify
        assert!(att.verify(&verifying_key).is_ok());
        assert!(!att.is_expired(1200));
        assert!(att.is_expired(1301));
    }
}
