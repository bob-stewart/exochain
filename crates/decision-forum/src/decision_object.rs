use super::*;
use sha2::{Sha256, Digest};
use uuid::Uuid;

#[derive(Debug, Clone, PartialEq, PartialOrd, serde::Serialize, serde::Deserialize)]
pub enum DecisionClass {
    Routine,
    Operational,
    Strategic,
    Constitutional,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub enum SignerType {
    Human,
    AiAgent {
        delegation_id: String,
        ceiling_class: DecisionClass,
    },
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct DelegationRecord {
    pub delegator: String,
    pub delegate: String,
    pub scope: String,
    pub expires_at: chrono::DateTime<chrono::Utc>,
    pub allows_sub_delegation: bool,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ConflictDisclosure {
    pub discloser: String,
    pub description: String,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub enum VoteChoice {
    Approve,
    Reject,
    Abstain,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct Vote {
    pub voter_did: String,
    pub choice: VoteChoice,
    pub signer_type: SignerType,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct DecisionObject {
    pub id: String,
    pub title: String,
    pub constitution_hash: String,
    pub authority_chain: Vec<authority::AuthorityLink>,
    pub merkle_root: String,
    pub status: Status,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub evidence: Vec<Evidence>,
    pub decision_class: DecisionClass,
    pub signer_type: SignerType,
    pub delegation_chain: Vec<DelegationRecord>,
    pub conflicts_disclosed: Vec<ConflictDisclosure>,
    pub votes: Vec<Vote>,
    pub quorum_required: u32,
    pub quorum_threshold_pct: f64,
    pub audit_sequence: u64,
    pub prev_audit_hash: String,
    pub requires_ratification: bool,
    pub ratification_deadline: Option<chrono::DateTime<chrono::Utc>>,
    pub constitution_version: String,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub enum Status { Draft, Pending, Approved, Rejected, Contested, Void }

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct Evidence { pub hash: String, pub description: String }

impl DecisionObject {
    pub fn new(title: &str) -> Self {
        let id = Uuid::new_v4().to_string();
        let mut hasher = Sha256::new();
        hasher.update(title.as_bytes());
        let merkle_root = format!("{:x}", hasher.finalize());

        Self {
            id,
            title: title.to_string(),
            constitution_hash: "genesis-constitution-hash".to_string(),
            authority_chain: vec![authority::AuthorityLink {
                pubkey: "genesis-pubkey".to_string(),
                signature: "genesis-signature".to_string(),
            }],
            merkle_root,
            status: Status::Draft,
            created_at: chrono::Utc::now(),
            evidence: vec![],
            decision_class: DecisionClass::Routine,
            signer_type: SignerType::Human,
            delegation_chain: vec![],
            conflicts_disclosed: vec![],
            votes: vec![],
            quorum_required: 0,
            quorum_threshold_pct: 0.0,
            audit_sequence: 1,
            prev_audit_hash: "genesis-audit-hash".to_string(),
            requires_ratification: false,
            ratification_deadline: None,
            constitution_version: "1.0.0".to_string(),
        }
    }

    pub fn seal(&mut self) -> Result<(), String> {
        TNCEnforcer::enforce_all(self)?;
        self.status = Status::Approved;
        Ok(())
    }
}
