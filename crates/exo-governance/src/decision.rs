//! Decision Object — first-class sovereign object with lifecycle state machine.
//!
//! Satisfies: GOV-001, GOV-002, GOV-003, TNC-01, TNC-02, TNC-08

use crate::anchor::AnchorReceipt;
use crate::clearance::ClearanceCertificate;
use crate::crosscheck::CrosscheckReport;
use crate::errors::GovernanceError;
use crate::types::*;
use exo_core::crypto::Blake3Hash;
use exo_core::hlc::HybridLogicalClock;
use serde::{Deserialize, Serialize};

/// Decision lifecycle status.
/// Once a decision reaches a terminal status, it is immutable (TNC-08).
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum DecisionStatus {
    /// Initial creation — being drafted.
    Created,
    /// Open for discussion and deliberation.
    Deliberation,
    /// Voting period active (quorum verified before entry — TNC-07).
    Voting,
    /// Terminal: approved by sufficient votes.
    Approved,
    /// Terminal: rejected by vote outcome.
    Rejected,
    /// Terminal: voided (e.g., constitutional violation discovered post-hoc).
    Void,
    /// Non-terminal: under active contestation (pauses execution).
    Contested,
    /// Non-terminal: emergency action awaiting ratification (TNC-10).
    RatificationRequired,
    /// Terminal: ratification period expired without ratification.
    RatificationExpired,
    /// Non-terminal: degraded governance mode (GOV-010).
    DegradedGovernance,
}

impl DecisionStatus {
    /// Returns true if this is a terminal (immutable) status.
    pub fn is_terminal(&self) -> bool {
        matches!(
            self,
            DecisionStatus::Approved
                | DecisionStatus::Rejected
                | DecisionStatus::Void
                | DecisionStatus::RatificationExpired
        )
    }

    /// Returns the set of valid next statuses from this status.
    pub fn valid_transitions(&self) -> &[DecisionStatus] {
        match self {
            DecisionStatus::Created => &[DecisionStatus::Deliberation, DecisionStatus::Void],
            DecisionStatus::Deliberation => &[
                DecisionStatus::Voting,
                DecisionStatus::Void,
                DecisionStatus::Contested,
            ],
            DecisionStatus::Voting => &[
                DecisionStatus::Approved,
                DecisionStatus::Rejected,
                DecisionStatus::Void,
                DecisionStatus::Contested,
            ],
            DecisionStatus::Contested => &[DecisionStatus::Deliberation, DecisionStatus::Void],
            DecisionStatus::RatificationRequired => &[
                DecisionStatus::Approved,
                DecisionStatus::RatificationExpired,
                DecisionStatus::Void,
            ],
            DecisionStatus::DegradedGovernance => {
                &[DecisionStatus::Deliberation, DecisionStatus::Void]
            }
            // Terminal statuses have no transitions
            DecisionStatus::Approved
            | DecisionStatus::Rejected
            | DecisionStatus::Void
            | DecisionStatus::RatificationExpired => &[],
        }
    }

    /// Check whether transitioning to `next` is valid from this status.
    pub fn can_transition_to(&self, next: &DecisionStatus) -> bool {
        self.valid_transitions().contains(next)
    }
}

/// A vote cast on a decision.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Vote {
    pub voter: Did,
    pub signer_type: SignerType,
    pub choice: VoteChoice,
    pub rationale: Option<String>,
    pub signature: GovernanceSignature,
    pub timestamp: HybridLogicalClock,
}

/// Vote choices.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum VoteChoice {
    Approve,
    Reject,
    Abstain,
}

/// Quorum specification for a decision.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct QuorumSpec {
    /// Minimum number of eligible voters who must participate.
    pub minimum_participants: u32,
    /// Approval threshold as percentage (0-100).
    pub approval_threshold_pct: u32,
    /// Eligible voter DIDs.
    pub eligible_voters: Vec<Did>,
}

impl QuorumSpec {
    /// Check whether quorum is met given the current participant count (TNC-07).
    pub fn is_quorum_met(&self, participant_count: u32) -> bool {
        participant_count >= self.minimum_participants
    }

    /// Check whether the approval threshold is met given approve/total counts.
    pub fn is_approved(&self, approve_count: u32, total_count: u32) -> bool {
        if total_count == 0 {
            return false;
        }
        let pct = (approve_count as u64 * 100) / total_count as u64;
        pct >= self.approval_threshold_pct as u64
    }
}

/// The core Decision Object.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DecisionObject {
    /// Content-addressed unique identifier.
    pub id: Blake3Hash,
    /// Owning tenant.
    pub tenant_id: TenantId,
    /// Current lifecycle status.
    pub status: DecisionStatus,
    /// Human-readable title.
    pub title: String,
    /// CBOR-encoded decision body.
    pub body: Vec<u8>,
    /// Classification determining governance requirements.
    pub decision_class: DecisionClass,
    /// Hash of the constitution version binding this decision (GOV-002).
    pub constitution_hash: Blake3Hash,
    /// Semantic version of the bound constitution.
    pub constitution_version: SemVer,
    /// DID of the decision author.
    pub author: Did,
    /// Creation timestamp.
    pub created_at: HybridLogicalClock,
    /// Snapshot of delegation chain hashes at creation time.
    pub delegations_snapshot: Vec<Blake3Hash>,
    /// Evidence references for duty of care (LEG-004).
    pub evidence: Vec<EvidenceRef>,
    /// Conflict disclosures filed for this decision (TNC-06).
    pub conflicts_disclosed: Vec<ConflictDisclosure>,
    /// Votes cast.
    pub votes: Vec<Vote>,
    /// Quorum requirements.
    pub quorum_requirement: QuorumSpec,
    /// Parent decision hashes (DAG linkage).
    pub parent_decisions: Vec<Blake3Hash>,
    /// Challenge IDs linked to this decision.
    pub challenge_ids: Vec<Blake3Hash>,
    /// Governance signatures (multi-sig support).
    pub signatures: Vec<GovernanceSignature>,
    /// History of status transitions.
    pub transition_log: Vec<StatusTransition>,

    // --- decision.forum protocol extensions ---

    /// CrosscheckReports attached to this decision (plural intelligence).
    /// Produced by crosschecked.ai and attached as evidence of deliberation.
    pub crosscheck_reports: Vec<CrosscheckReport>,
    /// ClearanceCertificates issued for this decision (legitimacy proof).
    pub clearance_certificates: Vec<ClearanceCertificate>,
    /// AnchorReceipts proving immutable anchoring in EXOCHAIN.
    pub anchor_receipts: Vec<AnchorReceipt>,
}

/// Conflict disclosure filed by a participant (TNC-06).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ConflictDisclosure {
    pub discloser: Did,
    pub description: String,
    pub nature: ConflictNature,
    pub timestamp: HybridLogicalClock,
    pub signature: GovernanceSignature,
}

/// Nature of a disclosed conflict.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum ConflictNature {
    Financial,
    Personal,
    Organizational,
    Other(String),
}

/// Record of a status transition in the decision lifecycle.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct StatusTransition {
    pub from: DecisionStatus,
    pub to: DecisionStatus,
    pub timestamp: HybridLogicalClock,
    pub actor: Did,
    pub reason: Option<String>,
    pub signature: GovernanceSignature,
}

impl DecisionObject {
    /// Advance the decision to a new status with full validation.
    ///
    /// Enforces:
    /// - TNC-08: Immutability after terminal status
    /// - Valid state machine transitions
    pub fn advance(
        &mut self,
        new_status: DecisionStatus,
        actor: Did,
        reason: Option<String>,
        signature: GovernanceSignature,
        timestamp: HybridLogicalClock,
    ) -> Result<(), GovernanceError> {
        // TNC-08: Cannot modify terminal decisions
        if self.status.is_terminal() {
            return Err(GovernanceError::DecisionImmutable(self.id));
        }

        // Validate state machine transition
        if !self.status.can_transition_to(&new_status) {
            return Err(GovernanceError::InvalidTransition {
                from: format!("{:?}", self.status),
                to: format!("{:?}", new_status),
            });
        }

        // Record transition
        let transition = StatusTransition {
            from: self.status.clone(),
            to: new_status.clone(),
            timestamp,
            actor,
            reason,
            signature,
        };
        self.transition_log.push(transition);
        self.status = new_status;

        Ok(())
    }

    /// Cast a vote on this decision.
    ///
    /// Enforces:
    /// - Decision must be in Voting status
    /// - Voter must be in eligible voters list
    /// - TNC-02: AI agents cannot vote on HUMAN_GATE_REQUIRED classes
    /// - TNC-09: AI agent delegation ceiling
    /// - No duplicate votes
    pub fn cast_vote(&mut self, vote: Vote) -> Result<(), GovernanceError> {
        if self.status != DecisionStatus::Voting {
            return Err(GovernanceError::InvalidTransition {
                from: format!("{:?}", self.status),
                to: "CastVote".to_string(),
            });
        }

        // TNC-02 + TNC-09: AI agents cannot vote on human-gate-required classes
        if matches!(vote.signer_type, SignerType::AiAgent { .. })
            && self.decision_class.requires_human_gate()
        {
            return Err(GovernanceError::HumanGateViolation {
                class: self.decision_class.clone(),
                signer: vote.voter.clone(),
            });
        }

        // Check voter eligibility
        if !self
            .quorum_requirement
            .eligible_voters
            .contains(&vote.voter)
        {
            return Err(GovernanceError::AuthorityChainBroken {
                reason: format!("Voter {} not in eligible voters list", vote.voter),
            });
        }

        // Prevent duplicate votes
        if self.votes.iter().any(|v| v.voter == vote.voter) {
            return Err(GovernanceError::AuthorityChainBroken {
                reason: format!("Voter {} has already voted", vote.voter),
            });
        }

        self.votes.push(vote);
        Ok(())
    }

    /// File a challenge against this decision (GOV-008).
    ///
    /// Transitions the decision to Contested status, pausing execution.
    /// Returns error if the decision is in a terminal or already contested state.
    pub fn file_challenge(
        &mut self,
        challenge_id: Blake3Hash,
        actor: Did,
        signature: GovernanceSignature,
        timestamp: HybridLogicalClock,
    ) -> Result<(), GovernanceError> {
        if !self.status.can_transition_to(&DecisionStatus::Contested) {
            return Err(GovernanceError::InvalidTransition {
                from: format!("{:?}", self.status),
                to: "Contested".to_string(),
            });
        }

        self.challenge_ids.push(challenge_id);
        self.transition_log.push(StatusTransition {
            from: self.status.clone(),
            to: DecisionStatus::Contested,
            timestamp,
            actor,
            reason: Some("Challenge filed — execution paused".to_string()),
            signature,
        });
        self.status = DecisionStatus::Contested;
        Ok(())
    }

    /// Tally votes and determine outcome.
    /// Returns the appropriate terminal status based on quorum and approval threshold.
    pub fn tally(&self) -> Result<DecisionStatus, GovernanceError> {
        if self.status != DecisionStatus::Voting {
            return Err(GovernanceError::InvalidTransition {
                from: format!("{:?}", self.status),
                to: "Tally".to_string(),
            });
        }

        let total = self.votes.len() as u32;

        // TNC-07: Quorum check
        if !self.quorum_requirement.is_quorum_met(total) {
            return Err(GovernanceError::QuorumNotMet {
                required: self.quorum_requirement.minimum_participants,
                present: total,
            });
        }

        let approvals = self
            .votes
            .iter()
            .filter(|v| v.choice == VoteChoice::Approve)
            .count() as u32;

        if self.quorum_requirement.is_approved(approvals, total) {
            Ok(DecisionStatus::Approved)
        } else {
            Ok(DecisionStatus::Rejected)
        }
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

    fn test_signature(signer: &str) -> GovernanceSignature {
        use ed25519_dalek::SigningKey;
        use rand::rngs::OsRng;

        let signing_key = SigningKey::generate(&mut OsRng);
        let dummy_hash = Blake3Hash([0u8; 32]);
        let sig = exo_core::compute_signature(&signing_key, &dummy_hash);

        GovernanceSignature {
            signer: signer.to_string(),
            signer_type: SignerType::Human,
            signature: sig,
            key_version: 1,
            timestamp: test_hlc(1000),
        }
    }

    fn test_decision() -> DecisionObject {
        DecisionObject {
            id: Blake3Hash([1u8; 32]),
            tenant_id: "tenant-1".to_string(),
            status: DecisionStatus::Created,
            title: "Test Decision".to_string(),
            body: vec![],
            decision_class: DecisionClass::Operational,
            constitution_hash: Blake3Hash([2u8; 32]),
            constitution_version: SemVer::new(1, 0, 0),
            author: "did:exo:alice".to_string(),
            created_at: test_hlc(1000),
            delegations_snapshot: vec![],
            evidence: vec![],
            conflicts_disclosed: vec![],
            votes: vec![],
            quorum_requirement: QuorumSpec {
                minimum_participants: 2,
                approval_threshold_pct: 51,
                eligible_voters: vec![
                    "did:exo:alice".to_string(),
                    "did:exo:bob".to_string(),
                    "did:exo:carol".to_string(),
                ],
            },
            parent_decisions: vec![],
            challenge_ids: vec![],
            signatures: vec![],
            transition_log: vec![],
            crosscheck_reports: vec![],
            clearance_certificates: vec![],
            anchor_receipts: vec![],
        }
    }

    #[test]
    fn test_valid_lifecycle_transitions() {
        let mut d = test_decision();
        assert_eq!(d.status, DecisionStatus::Created);

        // Created -> Deliberation
        d.advance(
            DecisionStatus::Deliberation,
            "did:exo:alice".into(),
            None,
            test_signature("did:exo:alice"),
            test_hlc(2000),
        )
        .unwrap();
        assert_eq!(d.status, DecisionStatus::Deliberation);

        // Deliberation -> Voting
        d.advance(
            DecisionStatus::Voting,
            "did:exo:alice".into(),
            None,
            test_signature("did:exo:alice"),
            test_hlc(3000),
        )
        .unwrap();
        assert_eq!(d.status, DecisionStatus::Voting);
    }

    #[test]
    fn test_invalid_transition_rejected() {
        let mut d = test_decision();
        // Created -> Approved is not valid
        let result = d.advance(
            DecisionStatus::Approved,
            "did:exo:alice".into(),
            None,
            test_signature("did:exo:alice"),
            test_hlc(2000),
        );
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            GovernanceError::InvalidTransition { .. }
        ));
    }

    #[test]
    fn test_tnc08_terminal_immutability() {
        let mut d = test_decision();
        d.status = DecisionStatus::Approved;

        let result = d.advance(
            DecisionStatus::Deliberation,
            "did:exo:alice".into(),
            None,
            test_signature("did:exo:alice"),
            test_hlc(2000),
        );
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            GovernanceError::DecisionImmutable(_)
        ));
    }

    #[test]
    fn test_vote_casting_and_tally() {
        let mut d = test_decision();
        d.status = DecisionStatus::Voting;

        // Cast votes
        let vote1 = Vote {
            voter: "did:exo:alice".into(),
            signer_type: SignerType::Human,
            choice: VoteChoice::Approve,
            rationale: None,
            signature: test_signature("did:exo:alice"),
            timestamp: test_hlc(3000),
        };
        d.cast_vote(vote1).unwrap();

        let vote2 = Vote {
            voter: "did:exo:bob".into(),
            signer_type: SignerType::Human,
            choice: VoteChoice::Approve,
            rationale: None,
            signature: test_signature("did:exo:bob"),
            timestamp: test_hlc(3001),
        };
        d.cast_vote(vote2).unwrap();

        // Tally
        let result = d.tally().unwrap();
        assert_eq!(result, DecisionStatus::Approved);
    }

    #[test]
    fn test_tnc07_quorum_enforcement() {
        let mut d = test_decision();
        d.status = DecisionStatus::Voting;

        // Only one vote — quorum requires 2
        let vote = Vote {
            voter: "did:exo:alice".into(),
            signer_type: SignerType::Human,
            choice: VoteChoice::Approve,
            rationale: None,
            signature: test_signature("did:exo:alice"),
            timestamp: test_hlc(3000),
        };
        d.cast_vote(vote).unwrap();

        let result = d.tally();
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            GovernanceError::QuorumNotMet { .. }
        ));
    }

    #[test]
    fn test_duplicate_vote_rejected() {
        let mut d = test_decision();
        d.status = DecisionStatus::Voting;

        let vote = Vote {
            voter: "did:exo:alice".into(),
            signer_type: SignerType::Human,
            choice: VoteChoice::Approve,
            rationale: None,
            signature: test_signature("did:exo:alice"),
            timestamp: test_hlc(3000),
        };
        d.cast_vote(vote.clone()).unwrap();

        let dup = Vote {
            voter: "did:exo:alice".into(),
            signer_type: SignerType::Human,
            choice: VoteChoice::Reject,
            rationale: None,
            signature: test_signature("did:exo:alice"),
            timestamp: test_hlc(3001),
        };
        assert!(d.cast_vote(dup).is_err());
    }

    #[test]
    fn test_terminal_statuses() {
        assert!(DecisionStatus::Approved.is_terminal());
        assert!(DecisionStatus::Rejected.is_terminal());
        assert!(DecisionStatus::Void.is_terminal());
        assert!(DecisionStatus::RatificationExpired.is_terminal());
        assert!(!DecisionStatus::Created.is_terminal());
        assert!(!DecisionStatus::Contested.is_terminal());
        assert!(!DecisionStatus::RatificationRequired.is_terminal());
    }

    #[test]
    fn test_tnc02_ai_blocked_on_human_gate() {
        let mut d = test_decision();
        d.decision_class = DecisionClass::Strategic; // requires human gate
        d.status = DecisionStatus::Voting;

        let ai_vote = Vote {
            voter: "did:exo:alice".into(),
            signer_type: SignerType::AiAgent {
                delegation_id: Blake3Hash([99u8; 32]),
                expires_at: 9999999,
            },
            choice: VoteChoice::Approve,
            rationale: None,
            signature: test_signature("did:exo:alice"),
            timestamp: test_hlc(3000),
        };
        let result = d.cast_vote(ai_vote);
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            GovernanceError::HumanGateViolation { .. }
        ));
    }

    #[test]
    fn test_file_challenge_transitions_to_contested() {
        let mut d = test_decision();
        d.advance(
            DecisionStatus::Deliberation,
            "did:exo:alice".into(),
            None,
            test_signature("did:exo:alice"),
            test_hlc(2000),
        )
        .unwrap();

        d.file_challenge(
            Blake3Hash([50u8; 32]),
            "did:exo:bob".into(),
            test_signature("did:exo:bob"),
            test_hlc(3000),
        )
        .unwrap();

        assert_eq!(d.status, DecisionStatus::Contested);
        assert_eq!(d.challenge_ids.len(), 1);
        assert_eq!(d.transition_log.len(), 2); // Deliberation + Contested
    }

    #[test]
    fn test_cannot_challenge_terminal_decision() {
        let mut d = test_decision();
        d.status = DecisionStatus::Approved; // terminal

        let result = d.file_challenge(
            Blake3Hash([50u8; 32]),
            "did:exo:bob".into(),
            test_signature("did:exo:bob"),
            test_hlc(3000),
        );
        assert!(result.is_err());
    }

    #[test]
    fn test_transition_log_maintained() {
        let mut d = test_decision();
        assert!(d.transition_log.is_empty());

        d.advance(
            DecisionStatus::Deliberation,
            "did:exo:alice".into(),
            Some("Opening deliberation".into()),
            test_signature("did:exo:alice"),
            test_hlc(2000),
        )
        .unwrap();

        assert_eq!(d.transition_log.len(), 1);
        assert_eq!(d.transition_log[0].from, DecisionStatus::Created);
        assert_eq!(d.transition_log[0].to, DecisionStatus::Deliberation);
    }
}
