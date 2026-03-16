use crate::policy::Policy;
use exo_core::{hash_bytes, Blake3Hash, Did};
use serde::{Deserialize, Serialize};
use thiserror::Error;

#[derive(Error, Debug)]
pub enum GatekeeperError {
    #[error("Policy Denied")]
    PolicyDenied,
    #[error("Attestation Failed")]
    AttestationFailed,
    #[error("System Error: {0}")]
    System(String),
}

/// TEE Attestation Report (Mock).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TeeReport {
    pub measurement: Blake3Hash,
    pub signature: Vec<u8>,
}

impl TeeReport {
    /// Verify the TEE report: measurement must be non-zero and signature must be non-empty.
    pub fn verify(&self) -> bool {
        let zero = Blake3Hash([0u8; 32]);
        self.measurement != zero && !self.signature.is_empty()
    }
}

/// Gatekeeper Interface (Spec 12.2).
/// Enforces policy-based access to data keys.
pub trait Gatekeeper {
    /// Request access to a resource.
    fn request_access(
        &self,
        subject: &Did,
        resource_id: &str,
        context: &str, // Context for policy evaluation
    ) -> Result<AccessGrant, GatekeeperError>;

    /// Verify TEE integrity.
    fn attest(&self) -> Result<TeeReport, GatekeeperError>;
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AccessGrant {
    pub token: String,
    pub expires_at: u64,
}

/// Mock Gatekeeper for development.
pub struct MockGatekeeper {
    pub policies: Vec<Policy>,
}

impl Default for MockGatekeeper {
    fn default() -> Self {
        Self::new()
    }
}

impl MockGatekeeper {
    pub fn new() -> Self {
        Self {
            policies: Vec::new(),
        }
    }

    pub fn register_policy(&mut self, policy: Policy) {
        self.policies.push(policy);
    }
}

impl Gatekeeper for MockGatekeeper {
    fn request_access(
        &self,
        subject: &Did,
        resource_id: &str,
        _context: &str,
    ) -> Result<AccessGrant, GatekeeperError> {
        // Find matching policy
        let matching = self
            .policies
            .iter()
            .find(|p| p.is_match(subject, resource_id)); // Basic match

        match matching {
            Some(policy) => match policy.effect {
                crate::policy::Effect::Allow => {
                    // Generate token: BLAKE3(subject || resource || timestamp) hex-encoded
                    // Use a deterministic "timestamp" derived from subject+resource for testability
                    let mut token_preimage = Vec::new();
                    token_preimage.extend_from_slice(subject.as_bytes());
                    token_preimage.extend_from_slice(resource_id.as_bytes());
                    // Use a fixed timestamp marker for deterministic output
                    token_preimage.extend_from_slice(b"mock-timestamp");
                    let token_hash = hash_bytes(&token_preimage);
                    let token = token_hash
                        .0
                        .iter()
                        .map(|b| format!("{:02x}", b))
                        .collect::<String>();

                    Ok(AccessGrant {
                        token,
                        expires_at: 0,
                    })
                }
                crate::policy::Effect::Deny => Err(GatekeeperError::PolicyDenied),
            },
            None => Err(GatekeeperError::PolicyDenied), // Default deny
        }
    }

    fn attest(&self) -> Result<TeeReport, GatekeeperError> {
        // Compute measurement = BLAKE3(policy_hashes) based on registered policies
        let mut preimage = Vec::new();
        for policy in &self.policies {
            let policy_id_hash = hash_bytes(policy.id.as_bytes());
            preimage.extend_from_slice(&policy_id_hash.0);
        }

        // If no policies, use a sentinel so measurement is still non-zero
        if preimage.is_empty() {
            preimage.extend_from_slice(b"empty-policy-set");
        }

        let measurement = hash_bytes(&preimage);

        // Signature = hash of measurement
        let signature = hash_bytes(&measurement.0).0.to_vec();

        Ok(TeeReport {
            measurement,
            signature,
        })
    }
}
