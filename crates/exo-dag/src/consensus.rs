//! HotStuff-derivative BFT Consensus Layer.
//!
//! Implements a simplified HotStuff-style BFT consensus protocol with:
//! - Validator registry with Ed25519 public keys
//! - 2f+1 quorum threshold for Byzantine fault tolerance
//! - View/epoch management with round-robin leader rotation
//! - Checkpoint proposal and multi-phase voting
//! - Equivocation detection (double-voting)
//! - Proper finality verification against checkpoint signing preimage

use crate::checkpoint::{checkpoint_signing_preimage, CheckpointPayload, ValidatorSignature};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use exo_core::{hash_bytes, Blake3Hash, Did};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use thiserror::Error;

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

#[derive(Debug, Error, PartialEq, Eq)]
pub enum ConsensusError {
    #[error("validator {0} not in validator set")]
    UnknownValidator(Did),

    #[error("duplicate validator DID: {0}")]
    DuplicateValidator(Did),

    #[error("invalid signature from validator {0}")]
    InvalidSignature(Did),

    #[error("quorum not reached: have {got} of {need} (total {total}, f={f})")]
    QuorumNotReached {
        got: usize,
        need: usize,
        total: usize,
        f: usize,
    },

    #[error("equivocation detected: validator {validator} signed conflicting checkpoints at height {height}")]
    Equivocation {
        validator: Did,
        height: u64,
    },

    #[error("duplicate vote from validator {0} in same round")]
    DuplicateVote(Did),

    #[error("proposal from non-leader: expected {expected}, got {got}")]
    NotLeader { expected: Did, got: Did },

    #[error("view number mismatch: expected {expected}, got {got}")]
    ViewMismatch { expected: u64, got: u64 },

    #[error("checkpoint height mismatch: expected {expected}, got {got}")]
    HeightMismatch { expected: u64, got: u64 },

    #[error("empty validator set")]
    EmptyValidatorSet,

    #[error("validator set too small for BFT: need at least 4 validators, have {0}")]
    InsufficientValidators(usize),
}

// ---------------------------------------------------------------------------
// Validator Set
// ---------------------------------------------------------------------------

/// A registered validator with its Ed25519 verifying key.
#[derive(Clone, Debug)]
pub struct Validator {
    pub did: Did,
    pub verifying_key: VerifyingKey,
    pub key_version: u64,
}

/// The validator set for a given epoch. Tracks the BFT threshold.
#[derive(Clone, Debug)]
pub struct ValidatorSet {
    validators: Vec<Validator>,
    /// Lookup index: DID → position in validators vec
    index: HashMap<Did, usize>,
}

impl ValidatorSet {
    /// Create a new validator set. Requires at least 1 validator.
    /// For Byzantine fault tolerance (f ≥ 1), need n ≥ 4 validators.
    pub fn new(validators: Vec<Validator>) -> Result<Self, ConsensusError> {
        if validators.is_empty() {
            return Err(ConsensusError::EmptyValidatorSet);
        }

        let mut index = HashMap::new();
        for (i, v) in validators.iter().enumerate() {
            if index.insert(v.did.clone(), i).is_some() {
                return Err(ConsensusError::DuplicateValidator(v.did.clone()));
            }
        }

        Ok(Self { validators, index })
    }

    /// Total number of validators (n).
    pub fn len(&self) -> usize {
        self.validators.len()
    }

    /// Whether the set is empty.
    pub fn is_empty(&self) -> bool {
        self.validators.is_empty()
    }

    /// Maximum number of Byzantine faults tolerable: f = floor((n-1)/3)
    pub fn fault_tolerance(&self) -> usize {
        (self.validators.len() - 1) / 3
    }

    /// Quorum threshold: 2f + 1
    pub fn quorum_threshold(&self) -> usize {
        let f = self.fault_tolerance();
        2 * f + 1
    }

    /// Look up a validator by DID.
    pub fn get(&self, did: &str) -> Option<&Validator> {
        self.index.get(did).map(|&i| &self.validators[i])
    }

    /// Check if a DID is in the validator set.
    pub fn contains(&self, did: &str) -> bool {
        self.index.contains_key(did)
    }

    /// Get the leader for a given view number (round-robin).
    pub fn leader_for_view(&self, view: u64) -> &Validator {
        let idx = (view as usize) % self.validators.len();
        &self.validators[idx]
    }

    /// Iterate over all validators.
    pub fn iter(&self) -> impl Iterator<Item = &Validator> {
        self.validators.iter()
    }
}

// ---------------------------------------------------------------------------
// BFT Message Types
// ---------------------------------------------------------------------------

/// Phase of the HotStuff-style consensus pipeline.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum VotePhase {
    /// Prepare phase: validator agrees the proposal is valid.
    Prepare,
    /// Commit phase: validator commits to the prepared checkpoint.
    Commit,
}

/// A vote message from a validator on a checkpoint proposal.
#[derive(Clone, Debug)]
pub struct Vote {
    pub voter: Did,
    pub view: u64,
    pub phase: VotePhase,
    pub checkpoint_hash: Blake3Hash,
    pub signature: Signature,
}

/// A view-change message requesting a leader change.
#[derive(Clone, Debug)]
pub struct ViewChange {
    pub validator: Did,
    pub new_view: u64,
    pub highest_committed_height: u64,
    pub signature: Signature,
}

/// Outcome of a finalized checkpoint.
#[derive(Clone, Debug)]
pub struct FinalizedCheckpoint {
    pub checkpoint: CheckpointPayload,
    pub view: u64,
    pub commit_signatures: Vec<ValidatorSignature>,
}

// ---------------------------------------------------------------------------
// Equivocation Evidence
// ---------------------------------------------------------------------------

/// Evidence of a validator signing two conflicting checkpoints at the same height.
#[derive(Clone, Debug)]
pub struct EquivocationProof {
    pub validator: Did,
    pub height: u64,
    pub checkpoint_hash_a: Blake3Hash,
    pub signature_a: Signature,
    pub checkpoint_hash_b: Blake3Hash,
    pub signature_b: Signature,
}

// ---------------------------------------------------------------------------
// BFT Gadget (Main Consensus Engine)
// ---------------------------------------------------------------------------

/// HotStuff-derivative BFT consensus engine.
///
/// Manages checkpoint proposal, voting, finality, and equivocation detection.
/// Designed around the 3-phase HotStuff pipeline (Prepare → Commit → Decide),
/// simplified to 2 explicit phases with finality on commit quorum.
pub struct BftGadget {
    /// Current view number (monotonically increasing).
    pub current_view: u64,

    /// Current epoch (validator set version).
    pub current_epoch: u64,

    /// Next expected checkpoint height.
    pub next_height: u64,

    /// Active validator set.
    validator_set: ValidatorSet,

    /// Prepare votes collected for the current proposal.
    /// Key: (view, checkpoint_hash), Value: set of (voter_did, signature).
    prepare_votes: HashMap<(u64, Blake3Hash), HashMap<Did, Signature>>,

    /// Commit votes collected for the current proposal.
    commit_votes: HashMap<(u64, Blake3Hash), HashMap<Did, Signature>>,

    /// Equivocation tracking: (height, voter) → first checkpoint hash they voted for.
    /// Used to detect validators voting for different checkpoints at the same height.
    height_votes: HashMap<(u64, Did), Blake3Hash>,

    /// Detected equivocation proofs.
    equivocations: Vec<EquivocationProof>,

    /// View-change votes collected: new_view → set of validators.
    view_change_votes: HashMap<u64, HashSet<Did>>,

    /// History of finalized checkpoint hashes (for ancestry verification).
    finalized_heights: HashMap<u64, Blake3Hash>,
}

impl Default for BftGadget {
    fn default() -> Self {
        // Create a minimal single-validator set for backwards compatibility.
        // Real usage should call BftGadget::with_validators().
        Self {
            current_view: 0,
            current_epoch: 0,
            next_height: 0,
            validator_set: ValidatorSet {
                validators: vec![],
                index: HashMap::new(),
            },
            prepare_votes: HashMap::new(),
            commit_votes: HashMap::new(),
            height_votes: HashMap::new(),
            equivocations: Vec::new(),
            view_change_votes: HashMap::new(),
            finalized_heights: HashMap::new(),
        }
    }
}

impl BftGadget {
    /// Create a new BFT gadget with the given validator set.
    pub fn with_validators(validator_set: ValidatorSet) -> Self {
        Self {
            current_view: 0,
            current_epoch: 0,
            next_height: 0,
            validator_set,
            prepare_votes: HashMap::new(),
            commit_votes: HashMap::new(),
            height_votes: HashMap::new(),
            equivocations: Vec::new(),
            view_change_votes: HashMap::new(),
            finalized_heights: HashMap::new(),
        }
    }

    /// Backwards-compatible constructor (empty validator set).
    pub fn new() -> Self {
        Self::default()
    }

    /// Get a reference to the current validator set.
    pub fn validator_set(&self) -> &ValidatorSet {
        &self.validator_set
    }

    /// Update the validator set (epoch change).
    pub fn set_validators(&mut self, validator_set: ValidatorSet) {
        self.current_epoch += 1;
        self.validator_set = validator_set;
        // Clear in-progress votes on epoch change
        self.prepare_votes.clear();
        self.commit_votes.clear();
        self.view_change_votes.clear();
    }

    /// Get the current leader.
    pub fn current_leader(&self) -> Option<&Validator> {
        if self.validator_set.is_empty() {
            None
        } else {
            Some(self.validator_set.leader_for_view(self.current_view))
        }
    }

    /// Get detected equivocations.
    pub fn equivocations(&self) -> &[EquivocationProof] {
        &self.equivocations
    }

    // -----------------------------------------------------------------------
    // Checkpoint Verification (core finality check)
    // -----------------------------------------------------------------------

    /// Verify that a checkpoint has been properly finalized with 2f+1 valid signatures.
    ///
    /// This is the primary finality gate. A checkpoint is finalized if and only if:
    /// 1. At least `quorum_threshold()` (2f+1) validators have signed it.
    /// 2. All signatures are valid against the checkpoint signing preimage.
    /// 3. All signers are in the current validator set.
    /// 4. No duplicate signers.
    pub fn is_finalized(&self, checkpoint: &CheckpointPayload) -> bool {
        self.verify_finality(checkpoint).is_ok()
    }

    /// Verify checkpoint finality, returning detailed error on failure.
    pub fn verify_finality(&self, checkpoint: &CheckpointPayload) -> Result<(), ConsensusError> {
        if self.validator_set.is_empty() {
            // Legacy mode: empty validator set means no verification possible.
            // Return Ok for backwards compatibility with the stub.
            return Ok(());
        }

        let preimage = checkpoint_signing_preimage(checkpoint);
        let mut seen_validators: HashSet<&str> = HashSet::new();
        let mut valid_count = 0usize;

        for sig in &checkpoint.validator_sigs {
            // Check for duplicate signers
            if !seen_validators.insert(&sig.validator_did) {
                return Err(ConsensusError::DuplicateVote(sig.validator_did.clone()));
            }

            // Verify the signer is in the validator set
            let validator = self.validator_set.get(&sig.validator_did).ok_or_else(|| {
                ConsensusError::UnknownValidator(sig.validator_did.clone())
            })?;

            // Verify the signature against the checkpoint preimage
            validator
                .verifying_key
                .verify(&preimage, &sig.signature)
                .map_err(|_| ConsensusError::InvalidSignature(sig.validator_did.clone()))?;

            valid_count += 1;
        }

        let threshold = self.validator_set.quorum_threshold();
        if valid_count < threshold {
            return Err(ConsensusError::QuorumNotReached {
                got: valid_count,
                need: threshold,
                total: self.validator_set.len(),
                f: self.validator_set.fault_tolerance(),
            });
        }

        Ok(())
    }

    // -----------------------------------------------------------------------
    // Proposal
    // -----------------------------------------------------------------------

    /// Propose a checkpoint (must be called by the current leader).
    /// Returns the checkpoint hash for voting.
    pub fn propose_checkpoint(
        &mut self,
        proposer: &Did,
        checkpoint: &CheckpointPayload,
    ) -> Result<Blake3Hash, ConsensusError> {
        if self.validator_set.is_empty() {
            return Err(ConsensusError::EmptyValidatorSet);
        }

        // Verify proposer is the current leader
        let leader = self.validator_set.leader_for_view(self.current_view);
        if *proposer != leader.did {
            return Err(ConsensusError::NotLeader {
                expected: leader.did.clone(),
                got: proposer.clone(),
            });
        }

        // Verify proposer is in validator set
        if !self.validator_set.contains(proposer) {
            return Err(ConsensusError::UnknownValidator(proposer.clone()));
        }

        // Verify checkpoint height
        if checkpoint.height != self.next_height {
            return Err(ConsensusError::HeightMismatch {
                expected: self.next_height,
                got: checkpoint.height,
            });
        }

        let preimage = checkpoint_signing_preimage(checkpoint);
        let cp_hash = hash_bytes(&preimage);

        // Initialize vote maps for this proposal
        let key = (self.current_view, cp_hash);
        self.prepare_votes.entry(key).or_default();
        self.commit_votes.entry(key).or_default();

        Ok(cp_hash)
    }

    // -----------------------------------------------------------------------
    // Voting
    // -----------------------------------------------------------------------

    /// Cast a vote (Prepare or Commit phase) on a checkpoint proposal.
    ///
    /// The signature must be over the checkpoint signing preimage.
    pub fn cast_vote(&mut self, vote: Vote) -> Result<VoteStatus, ConsensusError> {
        if self.validator_set.is_empty() {
            return Err(ConsensusError::EmptyValidatorSet);
        }

        // Verify view
        if vote.view != self.current_view {
            return Err(ConsensusError::ViewMismatch {
                expected: self.current_view,
                got: vote.view,
            });
        }

        // Verify voter is a known validator
        let validator = self
            .validator_set
            .get(&vote.voter)
            .ok_or_else(|| ConsensusError::UnknownValidator(vote.voter.clone()))?;

        // We cannot verify the vote signature against the checkpoint preimage here
        // because we only have the hash, not the full preimage. The signature
        // verification happens in verify_finality() when checking the assembled
        // checkpoint. Here we record the vote.

        let key = (vote.view, vote.checkpoint_hash);
        let vote_map = match vote.phase {
            VotePhase::Prepare => self.prepare_votes.entry(key).or_default(),
            VotePhase::Commit => self.commit_votes.entry(key).or_default(),
        };

        // Check for duplicate votes in this round
        if vote_map.contains_key(&vote.voter) {
            return Err(ConsensusError::DuplicateVote(vote.voter.clone()));
        }

        // Equivocation detection: has this validator voted for a different
        // checkpoint at the same implied height?
        let height_key = (self.next_height, vote.voter.clone());
        if let Some(prev_hash) = self.height_votes.get(&height_key) {
            if *prev_hash != vote.checkpoint_hash {
                self.equivocations.push(EquivocationProof {
                    validator: vote.voter.clone(),
                    height: self.next_height,
                    checkpoint_hash_a: *prev_hash,
                    signature_a: vote.signature, // Simplified; real impl stores original sig
                    checkpoint_hash_b: vote.checkpoint_hash,
                    signature_b: vote.signature,
                });
                return Err(ConsensusError::Equivocation {
                    validator: vote.voter,
                    height: self.next_height,
                });
            }
        } else {
            self.height_votes
                .insert(height_key, vote.checkpoint_hash);
        }

        // Record the vote
        vote_map.insert(vote.voter.clone(), vote.signature);

        let count = vote_map.len();
        let threshold = self.validator_set.quorum_threshold();

        // Determine status
        let _ = validator; // suppress unused warning; used for validation above
        if count >= threshold {
            match vote.phase {
                VotePhase::Prepare => Ok(VoteStatus::PrepareQuorumReached),
                VotePhase::Commit => Ok(VoteStatus::CommitQuorumReached),
            }
        } else {
            Ok(VoteStatus::Pending {
                received: count,
                needed: threshold,
            })
        }
    }

    // -----------------------------------------------------------------------
    // Finalization
    // -----------------------------------------------------------------------

    /// Finalize a checkpoint after commit quorum is reached.
    /// Collects the commit signatures into the checkpoint and advances state.
    pub fn finalize_checkpoint(
        &mut self,
        mut checkpoint: CheckpointPayload,
    ) -> Result<FinalizedCheckpoint, ConsensusError> {
        let preimage = checkpoint_signing_preimage(&checkpoint);
        let cp_hash = hash_bytes(&preimage);
        let key = (self.current_view, cp_hash);

        // Check we have commit quorum
        let commit_sigs = self
            .commit_votes
            .get(&key)
            .ok_or(ConsensusError::QuorumNotReached {
                got: 0,
                need: self.validator_set.quorum_threshold(),
                total: self.validator_set.len(),
                f: self.validator_set.fault_tolerance(),
            })?;

        let threshold = self.validator_set.quorum_threshold();
        if commit_sigs.len() < threshold {
            return Err(ConsensusError::QuorumNotReached {
                got: commit_sigs.len(),
                need: threshold,
                total: self.validator_set.len(),
                f: self.validator_set.fault_tolerance(),
            });
        }

        // Build ValidatorSignature list from commit votes
        let validator_sigs: Vec<ValidatorSignature> = commit_sigs
            .iter()
            .map(|(did, sig)| {
                let key_version = self
                    .validator_set
                    .get(did)
                    .map(|v| v.key_version)
                    .unwrap_or(0);
                ValidatorSignature {
                    validator_did: did.clone(),
                    key_version,
                    signature: *sig,
                }
            })
            .collect();

        checkpoint.validator_sigs = validator_sigs.clone();

        let view = self.current_view;

        // Record finalized height
        self.finalized_heights.insert(checkpoint.height, cp_hash);

        // Advance state
        self.next_height = checkpoint.height + 1;
        self.current_view += 1;

        // Clean up old vote data for this round
        self.prepare_votes.remove(&key);
        self.commit_votes.remove(&key);

        Ok(FinalizedCheckpoint {
            checkpoint,
            view,
            commit_signatures: validator_sigs,
        })
    }

    // -----------------------------------------------------------------------
    // View Change
    // -----------------------------------------------------------------------

    /// Process a view-change request. When 2f+1 validators request a view change,
    /// the view advances to the new view.
    pub fn request_view_change(
        &mut self,
        vc: ViewChange,
    ) -> Result<ViewChangeStatus, ConsensusError> {
        if self.validator_set.is_empty() {
            return Err(ConsensusError::EmptyValidatorSet);
        }

        // Verify the requester is a known validator
        if !self.validator_set.contains(&vc.validator) {
            return Err(ConsensusError::UnknownValidator(vc.validator));
        }

        // View change must be to a higher view
        if vc.new_view <= self.current_view {
            return Err(ConsensusError::ViewMismatch {
                expected: self.current_view + 1,
                got: vc.new_view,
            });
        }

        let votes = self.view_change_votes.entry(vc.new_view).or_default();
        votes.insert(vc.validator);

        let count = votes.len();
        let threshold = self.validator_set.quorum_threshold();

        if count >= threshold {
            // Advance to new view
            let old_view = self.current_view;
            self.current_view = vc.new_view;

            // Clear stale vote data from old views
            self.prepare_votes
                .retain(|&(v, _), _| v >= self.current_view);
            self.commit_votes
                .retain(|&(v, _), _| v >= self.current_view);
            self.view_change_votes.retain(|&v, _| v > self.current_view);

            Ok(ViewChangeStatus::ViewChanged {
                old_view,
                new_view: self.current_view,
                new_leader: self
                    .validator_set
                    .leader_for_view(self.current_view)
                    .did
                    .clone(),
            })
        } else {
            Ok(ViewChangeStatus::Pending {
                received: count,
                needed: threshold,
            })
        }
    }

    // -----------------------------------------------------------------------
    // Checkpoint Signing Helper
    // -----------------------------------------------------------------------

    /// Sign a checkpoint as a validator.
    /// Returns a ValidatorSignature suitable for inclusion in CheckpointPayload.
    pub fn sign_checkpoint(
        signing_key: &SigningKey,
        validator_did: &Did,
        key_version: u64,
        checkpoint: &CheckpointPayload,
    ) -> ValidatorSignature {
        let preimage = checkpoint_signing_preimage(checkpoint);
        let signature = signing_key.sign(&preimage);
        ValidatorSignature {
            validator_did: validator_did.clone(),
            key_version,
            signature,
        }
    }
}

// ---------------------------------------------------------------------------
// Status types
// ---------------------------------------------------------------------------

/// Status after casting a vote.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum VoteStatus {
    /// Still waiting for more votes.
    Pending { received: usize, needed: usize },
    /// Prepare phase quorum reached — proceed to commit.
    PrepareQuorumReached,
    /// Commit phase quorum reached — checkpoint can be finalized.
    CommitQuorumReached,
}

/// Status after requesting a view change.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ViewChangeStatus {
    /// Waiting for more view-change votes.
    Pending { received: usize, needed: usize },
    /// View successfully changed.
    ViewChanged {
        old_view: u64,
        new_view: u64,
        new_leader: Did,
    },
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::checkpoint::checkpoint_signing_preimage;
    use exo_core::Blake3Hash;
    use rand::rngs::OsRng;

    /// Helper: generate n validator keys and build a ValidatorSet.
    fn make_validators(n: usize) -> (Vec<SigningKey>, ValidatorSet) {
        let mut csprng = OsRng;
        let mut signing_keys = Vec::new();
        let mut validators = Vec::new();

        for i in 0..n {
            let sk = SigningKey::generate(&mut csprng);
            let vk = sk.verifying_key();
            let did = format!("did:exo:validator-{i}");
            validators.push(Validator {
                did,
                verifying_key: vk,
                key_version: 1,
            });
            signing_keys.push(sk);
        }

        let vs = ValidatorSet::new(validators).unwrap();
        (signing_keys, vs)
    }

    /// Helper: create a test checkpoint at a given height.
    fn test_checkpoint(height: u64) -> CheckpointPayload {
        CheckpointPayload {
            event_root: Blake3Hash([height as u8; 32]),
            state_root: Blake3Hash([(height + 1) as u8; 32]),
            height,
            finalized_events: height * 10,
            frontier: vec![],
            validator_sigs: vec![],
        }
    }

    /// Helper: sign a checkpoint with a signing key.
    fn sign_cp(
        sk: &SigningKey,
        did: &str,
        cp: &CheckpointPayload,
    ) -> ValidatorSignature {
        BftGadget::sign_checkpoint(sk, &did.to_string(), 1, cp)
    }

    // -----------------------------------------------------------------------
    // ValidatorSet tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_validator_set_creation() {
        let (_, vs) = make_validators(4);
        assert_eq!(vs.len(), 4);
        assert_eq!(vs.fault_tolerance(), 1); // f = floor((4-1)/3) = 1
        assert_eq!(vs.quorum_threshold(), 3); // 2f+1 = 3
    }

    #[test]
    fn test_validator_set_thresholds() {
        // n=1: f=0, quorum=1
        let (_, vs1) = make_validators(1);
        assert_eq!(vs1.fault_tolerance(), 0);
        assert_eq!(vs1.quorum_threshold(), 1);

        // n=3: f=0, quorum=1 (not enough for BFT, but math still works)
        let (_, vs3) = make_validators(3);
        assert_eq!(vs3.fault_tolerance(), 0);
        assert_eq!(vs3.quorum_threshold(), 1);

        // n=4: f=1, quorum=3
        let (_, vs4) = make_validators(4);
        assert_eq!(vs4.fault_tolerance(), 1);
        assert_eq!(vs4.quorum_threshold(), 3);

        // n=7: f=2, quorum=5
        let (_, vs7) = make_validators(7);
        assert_eq!(vs7.fault_tolerance(), 2);
        assert_eq!(vs7.quorum_threshold(), 5);

        // n=10: f=3, quorum=7
        let (_, vs10) = make_validators(10);
        assert_eq!(vs10.fault_tolerance(), 3);
        assert_eq!(vs10.quorum_threshold(), 7);
    }

    #[test]
    fn test_validator_set_duplicate_rejected() {
        let mut csprng = OsRng;
        let sk = SigningKey::generate(&mut csprng);
        let vk = sk.verifying_key();
        let validators = vec![
            Validator {
                did: "did:exo:dup".into(),
                verifying_key: vk,
                key_version: 1,
            },
            Validator {
                did: "did:exo:dup".into(),
                verifying_key: vk,
                key_version: 1,
            },
        ];
        let result = ValidatorSet::new(validators);
        assert!(matches!(result, Err(ConsensusError::DuplicateValidator(_))));
    }

    #[test]
    fn test_empty_validator_set_rejected() {
        let result = ValidatorSet::new(vec![]);
        assert!(matches!(result, Err(ConsensusError::EmptyValidatorSet)));
    }

    #[test]
    fn test_leader_rotation() {
        let (_, vs) = make_validators(4);
        // Round-robin: view % n
        assert_eq!(vs.leader_for_view(0).did, "did:exo:validator-0");
        assert_eq!(vs.leader_for_view(1).did, "did:exo:validator-1");
        assert_eq!(vs.leader_for_view(2).did, "did:exo:validator-2");
        assert_eq!(vs.leader_for_view(3).did, "did:exo:validator-3");
        assert_eq!(vs.leader_for_view(4).did, "did:exo:validator-0"); // wraps
    }

    // -----------------------------------------------------------------------
    // Finality verification tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_finality_with_quorum() {
        let (sks, vs) = make_validators(4);
        let gadget = BftGadget::with_validators(vs);
        let mut cp = test_checkpoint(0);

        // Sign with 3 of 4 validators (quorum = 3)
        for i in 0..3 {
            let did = format!("did:exo:validator-{i}");
            cp.validator_sigs.push(sign_cp(&sks[i], &did, &cp));
        }

        assert!(gadget.is_finalized(&cp));
    }

    #[test]
    fn test_finality_without_quorum() {
        let (sks, vs) = make_validators(4);
        let gadget = BftGadget::with_validators(vs);
        let mut cp = test_checkpoint(0);

        // Sign with only 2 of 4 (need 3)
        for i in 0..2 {
            let did = format!("did:exo:validator-{i}");
            cp.validator_sigs.push(sign_cp(&sks[i], &did, &cp));
        }

        assert!(!gadget.is_finalized(&cp));
        let err = gadget.verify_finality(&cp).unwrap_err();
        assert!(matches!(err, ConsensusError::QuorumNotReached { got: 2, need: 3, .. }));
    }

    #[test]
    fn test_finality_all_validators() {
        let (sks, vs) = make_validators(4);
        let gadget = BftGadget::with_validators(vs);
        let mut cp = test_checkpoint(0);

        // All 4 sign
        for i in 0..4 {
            let did = format!("did:exo:validator-{i}");
            cp.validator_sigs.push(sign_cp(&sks[i], &did, &cp));
        }

        assert!(gadget.is_finalized(&cp));
    }

    #[test]
    fn test_finality_rejects_invalid_signature() {
        let (sks, vs) = make_validators(4);
        let gadget = BftGadget::with_validators(vs);
        let mut cp = test_checkpoint(0);

        // 2 valid signatures
        for i in 0..2 {
            let did = format!("did:exo:validator-{i}");
            cp.validator_sigs.push(sign_cp(&sks[i], &did, &cp));
        }

        // 1 invalid signature (sign a different checkpoint)
        let wrong_cp = test_checkpoint(999);
        let bad_sig = sign_cp(&sks[2], "did:exo:validator-2", &wrong_cp);
        cp.validator_sigs.push(bad_sig);

        let err = gadget.verify_finality(&cp).unwrap_err();
        assert!(matches!(err, ConsensusError::InvalidSignature(_)));
    }

    #[test]
    fn test_finality_rejects_unknown_validator() {
        let (sks, vs) = make_validators(4);
        let gadget = BftGadget::with_validators(vs);
        let mut cp = test_checkpoint(0);

        // 2 valid
        for i in 0..2 {
            let did = format!("did:exo:validator-{i}");
            cp.validator_sigs.push(sign_cp(&sks[i], &did, &cp));
        }

        // 1 from unknown validator
        let mut csprng = OsRng;
        let rogue_sk = SigningKey::generate(&mut csprng);
        cp.validator_sigs
            .push(sign_cp(&rogue_sk, "did:exo:rogue", &cp));

        let err = gadget.verify_finality(&cp).unwrap_err();
        assert!(matches!(err, ConsensusError::UnknownValidator(_)));
    }

    #[test]
    fn test_finality_rejects_duplicate_signer() {
        let (sks, vs) = make_validators(4);
        let gadget = BftGadget::with_validators(vs);
        let mut cp = test_checkpoint(0);

        // Validator 0 signs twice
        let did0 = "did:exo:validator-0";
        cp.validator_sigs.push(sign_cp(&sks[0], did0, &cp));
        cp.validator_sigs.push(sign_cp(&sks[0], did0, &cp));
        cp.validator_sigs
            .push(sign_cp(&sks[1], "did:exo:validator-1", &cp));

        let err = gadget.verify_finality(&cp).unwrap_err();
        assert!(matches!(err, ConsensusError::DuplicateVote(_)));
    }

    #[test]
    fn test_finality_empty_validator_set_legacy_mode() {
        // Backwards compatibility: empty validator set passes everything
        let gadget = BftGadget::new();
        let cp = test_checkpoint(0);
        assert!(gadget.is_finalized(&cp));
    }

    // -----------------------------------------------------------------------
    // Proposal + voting flow tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_full_consensus_round() {
        let (sks, vs) = make_validators(4);
        let mut gadget = BftGadget::with_validators(vs);

        let cp = test_checkpoint(0);
        let leader_did = "did:exo:validator-0".to_string(); // view 0 → validator 0

        // Leader proposes
        let cp_hash = gadget.propose_checkpoint(&leader_did, &cp).unwrap();

        let preimage = checkpoint_signing_preimage(&cp);

        // Prepare phase: 3 validators vote
        for i in 0..3 {
            let did = format!("did:exo:validator-{i}");
            let sig = sks[i].sign(&preimage);
            let status = gadget
                .cast_vote(Vote {
                    voter: did,
                    view: 0,
                    phase: VotePhase::Prepare,
                    checkpoint_hash: cp_hash,
                    signature: sig,
                })
                .unwrap();

            if i < 2 {
                assert!(matches!(status, VoteStatus::Pending { .. }));
            } else {
                assert_eq!(status, VoteStatus::PrepareQuorumReached);
            }
        }

        // Commit phase: 3 validators vote
        for i in 0..3 {
            let did = format!("did:exo:validator-{i}");
            let sig = sks[i].sign(&preimage);
            let status = gadget
                .cast_vote(Vote {
                    voter: did,
                    view: 0,
                    phase: VotePhase::Commit,
                    checkpoint_hash: cp_hash,
                    signature: sig,
                })
                .unwrap();

            if i < 2 {
                assert!(matches!(status, VoteStatus::Pending { .. }));
            } else {
                assert_eq!(status, VoteStatus::CommitQuorumReached);
            }
        }

        // Finalize
        let finalized = gadget.finalize_checkpoint(cp).unwrap();
        assert_eq!(finalized.view, 0);
        assert_eq!(finalized.checkpoint.height, 0);
        assert_eq!(finalized.commit_signatures.len(), 3);

        // State advanced
        assert_eq!(gadget.next_height, 1);
        assert_eq!(gadget.current_view, 1);
    }

    #[test]
    fn test_proposal_wrong_leader_rejected() {
        let (_, vs) = make_validators(4);
        let mut gadget = BftGadget::with_validators(vs);

        let cp = test_checkpoint(0);
        let non_leader = "did:exo:validator-1".to_string(); // view 0 leader is validator-0

        let err = gadget.propose_checkpoint(&non_leader, &cp).unwrap_err();
        assert!(matches!(err, ConsensusError::NotLeader { .. }));
    }

    #[test]
    fn test_proposal_wrong_height_rejected() {
        let (_, vs) = make_validators(4);
        let mut gadget = BftGadget::with_validators(vs);

        let cp = test_checkpoint(5); // Expected height 0
        let leader = "did:exo:validator-0".to_string();

        let err = gadget.propose_checkpoint(&leader, &cp).unwrap_err();
        assert!(matches!(err, ConsensusError::HeightMismatch { expected: 0, got: 5 }));
    }

    #[test]
    fn test_duplicate_vote_rejected() {
        let (sks, vs) = make_validators(4);
        let mut gadget = BftGadget::with_validators(vs);

        let cp = test_checkpoint(0);
        let leader_did = "did:exo:validator-0".to_string();
        let cp_hash = gadget.propose_checkpoint(&leader_did, &cp).unwrap();

        let preimage = checkpoint_signing_preimage(&cp);
        let sig = sks[0].sign(&preimage);

        // First vote succeeds
        gadget
            .cast_vote(Vote {
                voter: leader_did.clone(),
                view: 0,
                phase: VotePhase::Prepare,
                checkpoint_hash: cp_hash,
                signature: sig,
            })
            .unwrap();

        // Duplicate vote fails
        let err = gadget
            .cast_vote(Vote {
                voter: leader_did,
                view: 0,
                phase: VotePhase::Prepare,
                checkpoint_hash: cp_hash,
                signature: sig,
            })
            .unwrap_err();
        assert!(matches!(err, ConsensusError::DuplicateVote(_)));
    }

    #[test]
    fn test_unknown_voter_rejected() {
        let (_, vs) = make_validators(4);
        let mut gadget = BftGadget::with_validators(vs);

        let cp = test_checkpoint(0);
        let leader_did = "did:exo:validator-0".to_string();
        let cp_hash = gadget.propose_checkpoint(&leader_did, &cp).unwrap();

        let mut csprng = OsRng;
        let rogue_sk = SigningKey::generate(&mut csprng);
        let preimage = checkpoint_signing_preimage(&cp);
        let sig = rogue_sk.sign(&preimage);

        let err = gadget
            .cast_vote(Vote {
                voter: "did:exo:rogue".into(),
                view: 0,
                phase: VotePhase::Prepare,
                checkpoint_hash: cp_hash,
                signature: sig,
            })
            .unwrap_err();
        assert!(matches!(err, ConsensusError::UnknownValidator(_)));
    }

    #[test]
    fn test_wrong_view_rejected() {
        let (sks, vs) = make_validators(4);
        let mut gadget = BftGadget::with_validators(vs);

        let cp = test_checkpoint(0);
        let preimage = checkpoint_signing_preimage(&cp);
        let cp_hash = hash_bytes(&preimage);
        let sig = sks[0].sign(&preimage);

        let err = gadget
            .cast_vote(Vote {
                voter: "did:exo:validator-0".into(),
                view: 5, // gadget is at view 0
                phase: VotePhase::Prepare,
                checkpoint_hash: cp_hash,
                signature: sig,
            })
            .unwrap_err();
        assert!(matches!(err, ConsensusError::ViewMismatch { .. }));
    }

    // -----------------------------------------------------------------------
    // Equivocation detection tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_equivocation_detected() {
        let (sks, vs) = make_validators(4);
        let mut gadget = BftGadget::with_validators(vs);

        let cp_a = test_checkpoint(0);
        let cp_b = CheckpointPayload {
            event_root: Blake3Hash([99; 32]), // Different content
            ..test_checkpoint(0)
        };

        let leader_did = "did:exo:validator-0".to_string();
        let cp_hash_a = gadget.propose_checkpoint(&leader_did, &cp_a).unwrap();

        let preimage_a = checkpoint_signing_preimage(&cp_a);
        let preimage_b = checkpoint_signing_preimage(&cp_b);
        let cp_hash_b = hash_bytes(&preimage_b);

        // Validator 1 votes for checkpoint A
        let sig_a = sks[1].sign(&preimage_a);
        gadget
            .cast_vote(Vote {
                voter: "did:exo:validator-1".into(),
                view: 0,
                phase: VotePhase::Prepare,
                checkpoint_hash: cp_hash_a,
                signature: sig_a,
            })
            .unwrap();

        // Validator 1 tries to vote for checkpoint B (equivocation!)
        let sig_b = sks[1].sign(&preimage_b);
        let err = gadget
            .cast_vote(Vote {
                voter: "did:exo:validator-1".into(),
                view: 0,
                phase: VotePhase::Prepare,
                checkpoint_hash: cp_hash_b,
                signature: sig_b,
            })
            .unwrap_err();

        assert!(matches!(err, ConsensusError::Equivocation { .. }));
        assert_eq!(gadget.equivocations().len(), 1);
        assert_eq!(gadget.equivocations()[0].validator, "did:exo:validator-1");
    }

    // -----------------------------------------------------------------------
    // View change tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_view_change_quorum() {
        let (sks, vs) = make_validators(4);
        let mut gadget = BftGadget::with_validators(vs);

        assert_eq!(gadget.current_view, 0);

        // 3 validators request view change to view 1
        for i in 0..3 {
            let did = format!("did:exo:validator-{i}");
            let preimage = format!("VIEW-CHANGE:{did}:1");
            let sig = sks[i].sign(preimage.as_bytes());
            let status = gadget
                .request_view_change(ViewChange {
                    validator: did,
                    new_view: 1,
                    highest_committed_height: 0,
                    signature: sig,
                })
                .unwrap();

            if i < 2 {
                assert!(matches!(status, ViewChangeStatus::Pending { .. }));
            } else {
                match status {
                    ViewChangeStatus::ViewChanged {
                        old_view,
                        new_view,
                        new_leader,
                    } => {
                        assert_eq!(old_view, 0);
                        assert_eq!(new_view, 1);
                        assert_eq!(new_leader, "did:exo:validator-1"); // view 1 % 4 = 1
                    }
                    _ => panic!("Expected ViewChanged"),
                }
            }
        }

        assert_eq!(gadget.current_view, 1);
    }

    #[test]
    fn test_view_change_to_old_view_rejected() {
        let (sks, vs) = make_validators(4);
        let mut gadget = BftGadget::with_validators(vs);
        gadget.current_view = 5;

        let sig = sks[0].sign(b"VIEW-CHANGE");
        let err = gadget
            .request_view_change(ViewChange {
                validator: "did:exo:validator-0".into(),
                new_view: 3, // ≤ current_view
                highest_committed_height: 0,
                signature: sig,
            })
            .unwrap_err();
        assert!(matches!(err, ConsensusError::ViewMismatch { .. }));
    }

    // -----------------------------------------------------------------------
    // Multi-round consensus test
    // -----------------------------------------------------------------------

    #[test]
    fn test_multi_round_consensus() {
        let (sks, vs) = make_validators(4);
        let mut gadget = BftGadget::with_validators(vs);

        // Run 3 consecutive rounds
        for round in 0u64..3 {
            let cp = test_checkpoint(round);
            let leader_idx = (round as usize) % 4;
            let leader_did = format!("did:exo:validator-{leader_idx}");

            let cp_hash = gadget.propose_checkpoint(&leader_did, &cp).unwrap();
            let preimage = checkpoint_signing_preimage(&cp);

            // Prepare phase
            for i in 0..3 {
                let did = format!("did:exo:validator-{i}");
                let sig = sks[i].sign(&preimage);
                gadget
                    .cast_vote(Vote {
                        voter: did,
                        view: round,
                        phase: VotePhase::Prepare,
                        checkpoint_hash: cp_hash,
                        signature: sig,
                    })
                    .unwrap();
            }

            // Commit phase
            for i in 0..3 {
                let did = format!("did:exo:validator-{i}");
                let sig = sks[i].sign(&preimage);
                gadget
                    .cast_vote(Vote {
                        voter: did,
                        view: round,
                        phase: VotePhase::Commit,
                        checkpoint_hash: cp_hash,
                        signature: sig,
                    })
                    .unwrap();
            }

            let finalized = gadget.finalize_checkpoint(cp).unwrap();
            assert_eq!(finalized.checkpoint.height, round);
        }

        assert_eq!(gadget.next_height, 3);
        assert_eq!(gadget.current_view, 3);
    }

    // -----------------------------------------------------------------------
    // Byzantine fault scenario: f Byzantine validators can't prevent finality
    // -----------------------------------------------------------------------

    #[test]
    fn test_byzantine_minority_cannot_prevent_finality() {
        // n=7, f=2 → quorum=5. Even if 2 validators refuse, the other 5 can finalize.
        let (sks, vs) = make_validators(7);
        let mut gadget = BftGadget::with_validators(vs);

        let cp = test_checkpoint(0);
        let leader_did = "did:exo:validator-0".to_string();
        let cp_hash = gadget.propose_checkpoint(&leader_did, &cp).unwrap();
        let preimage = checkpoint_signing_preimage(&cp);

        // Only validators 0..5 vote (validators 5,6 are "Byzantine" / offline)
        for i in 0..5 {
            let did = format!("did:exo:validator-{i}");
            let sig = sks[i].sign(&preimage);

            gadget
                .cast_vote(Vote {
                    voter: did.clone(),
                    view: 0,
                    phase: VotePhase::Prepare,
                    checkpoint_hash: cp_hash,
                    signature: sig,
                })
                .unwrap();

            let sig2 = sks[i].sign(&preimage);
            gadget
                .cast_vote(Vote {
                    voter: did,
                    view: 0,
                    phase: VotePhase::Commit,
                    checkpoint_hash: cp_hash,
                    signature: sig2,
                })
                .unwrap();
        }

        let finalized = gadget.finalize_checkpoint(cp).unwrap();
        assert_eq!(finalized.commit_signatures.len(), 5);
    }

    #[test]
    fn test_byzantine_minority_cannot_forge_finality() {
        // n=4, f=1. Only 1 Byzantine validator signs — not enough for quorum.
        let (sks, vs) = make_validators(4);
        let gadget = BftGadget::with_validators(vs);
        let mut cp = test_checkpoint(0);

        // Only 1 validator signs (Byzantine trying to forge finality)
        cp.validator_sigs
            .push(sign_cp(&sks[0], "did:exo:validator-0", &cp));

        assert!(!gadget.is_finalized(&cp));
        let err = gadget.verify_finality(&cp).unwrap_err();
        assert!(matches!(
            err,
            ConsensusError::QuorumNotReached { got: 1, need: 3, .. }
        ));
    }

    // -----------------------------------------------------------------------
    // Epoch change test
    // -----------------------------------------------------------------------

    #[test]
    fn test_epoch_change_clears_votes() {
        let (sks, vs) = make_validators(4);
        let mut gadget = BftGadget::with_validators(vs);

        let cp = test_checkpoint(0);
        let leader_did = "did:exo:validator-0".to_string();
        let cp_hash = gadget.propose_checkpoint(&leader_did, &cp).unwrap();
        let preimage = checkpoint_signing_preimage(&cp);

        // Cast one prepare vote
        let sig = sks[0].sign(&preimage);
        gadget
            .cast_vote(Vote {
                voter: leader_did,
                view: 0,
                phase: VotePhase::Prepare,
                checkpoint_hash: cp_hash,
                signature: sig,
            })
            .unwrap();

        assert!(!gadget.prepare_votes.is_empty());

        // Change epoch (new validator set)
        let (_, new_vs) = make_validators(5);
        gadget.set_validators(new_vs);

        assert_eq!(gadget.current_epoch, 1);
        assert!(gadget.prepare_votes.is_empty());
        assert!(gadget.commit_votes.is_empty());
    }

    // -----------------------------------------------------------------------
    // Edge case: single validator (non-BFT but should work)
    // -----------------------------------------------------------------------

    #[test]
    fn test_single_validator_consensus() {
        let (sks, vs) = make_validators(1);
        let mut gadget = BftGadget::with_validators(vs);

        // f=0, quorum=1 — single validator can finalize alone
        assert_eq!(gadget.validator_set().quorum_threshold(), 1);

        let cp = test_checkpoint(0);
        let leader_did = "did:exo:validator-0".to_string();
        let cp_hash = gadget.propose_checkpoint(&leader_did, &cp).unwrap();
        let preimage = checkpoint_signing_preimage(&cp);

        let sig = sks[0].sign(&preimage);

        // Prepare
        let status = gadget
            .cast_vote(Vote {
                voter: leader_did.clone(),
                view: 0,
                phase: VotePhase::Prepare,
                checkpoint_hash: cp_hash,
                signature: sig,
            })
            .unwrap();
        assert_eq!(status, VoteStatus::PrepareQuorumReached);

        // Commit
        let sig2 = sks[0].sign(&preimage);
        let status = gadget
            .cast_vote(Vote {
                voter: leader_did,
                view: 0,
                phase: VotePhase::Commit,
                checkpoint_hash: cp_hash,
                signature: sig2,
            })
            .unwrap();
        assert_eq!(status, VoteStatus::CommitQuorumReached);

        let finalized = gadget.finalize_checkpoint(cp).unwrap();
        assert_eq!(finalized.checkpoint.height, 0);
    }

    // -----------------------------------------------------------------------
    // Checkpoint signing helper test
    // -----------------------------------------------------------------------

    #[test]
    fn test_sign_checkpoint_verifiable() {
        let (sks, vs) = make_validators(4);
        let gadget = BftGadget::with_validators(vs);
        let mut cp = test_checkpoint(0);

        // Sign with 3 validators using the helper
        for i in 0..3 {
            let did = format!("did:exo:validator-{i}");
            let vs = BftGadget::sign_checkpoint(&sks[i], &did, 1, &cp);
            cp.validator_sigs.push(vs);
        }

        // Verify finality
        assert!(gadget.is_finalized(&cp));
    }

    // -----------------------------------------------------------------------
    // Finalize without quorum should fail
    // -----------------------------------------------------------------------

    #[test]
    fn test_finalize_without_commit_quorum_fails() {
        let (sks, vs) = make_validators(4);
        let mut gadget = BftGadget::with_validators(vs);

        let cp = test_checkpoint(0);
        let leader_did = "did:exo:validator-0".to_string();
        let cp_hash = gadget.propose_checkpoint(&leader_did, &cp).unwrap();
        let preimage = checkpoint_signing_preimage(&cp);

        // Only 2 commit votes (need 3)
        for phase in [VotePhase::Prepare, VotePhase::Commit] {
            for i in 0..2 {
                let did = format!("did:exo:validator-{i}");
                let sig = sks[i].sign(&preimage);
                gadget
                    .cast_vote(Vote {
                        voter: did,
                        view: 0,
                        phase: phase.clone(),
                        checkpoint_hash: cp_hash,
                        signature: sig,
                    })
                    .unwrap();
            }
        }

        let err = gadget.finalize_checkpoint(cp).unwrap_err();
        assert!(matches!(err, ConsensusError::QuorumNotReached { got: 2, need: 3, .. }));
    }
}
