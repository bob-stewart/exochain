//! DGCL §144 safe-harbor automation (LEG-005, LEG-013).
//!
//! Automates conflict-of-interest disclosure workflows to achieve
//! Delaware General Corporation Law §144 safe-harbor protection.

use chrono::{DateTime, Utc};
use exo_core::crypto::Blake3Hash;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Status of a DGCL §144 safe-harbor workflow.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum SafeHarborStatus {
    /// Disclosure has been filed but not yet reviewed.
    DisclosureFiled,
    /// Board has been notified of the conflict.
    BoardNotified,
    /// Disinterested directors have approved despite conflict.
    DisinterestedApproval,
    /// Shareholders have ratified despite conflict.
    ShareholderRatification,
    /// Transaction deemed fair by independent evaluation.
    FairnessEstablished,
    /// Safe harbor achieved through one of the §144 paths.
    SafeHarborAchieved,
    /// Safe harbor denied — transaction voidable.
    SafeHarborDenied,
}

/// A DGCL §144 safe-harbor workflow instance.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DgclSafeHarbor {
    pub id: Uuid,
    pub decision_id: Blake3Hash,
    pub tenant_id: String,
    pub interested_party: String,
    pub conflict_description: String,
    pub material_facts: Vec<String>,
    pub status: SafeHarborStatus,
    pub disclosure_timestamp: DateTime<Utc>,
    pub disinterested_voters: Vec<String>,
    pub disinterested_approvals: Vec<String>,
    pub fairness_opinion: Option<FairnessOpinion>,
    pub resolution_timestamp: Option<DateTime<Utc>>,
}

/// Independent fairness opinion for §144(a)(3) path.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct FairnessOpinion {
    pub evaluator: String,
    pub opinion: String,
    pub is_fair: bool,
    pub issued_at: DateTime<Utc>,
    pub content_hash: Blake3Hash,
}

impl DgclSafeHarbor {
    /// Create a new safe-harbor workflow from a conflict disclosure.
    pub fn new(
        decision_id: Blake3Hash,
        tenant_id: String,
        interested_party: String,
        conflict_description: String,
        material_facts: Vec<String>,
    ) -> Self {
        Self {
            id: Uuid::new_v4(),
            decision_id,
            tenant_id,
            interested_party,
            conflict_description,
            material_facts,
            status: SafeHarborStatus::DisclosureFiled,
            disclosure_timestamp: Utc::now(),
            disinterested_voters: Vec::new(),
            disinterested_approvals: Vec::new(),
            fairness_opinion: None,
            resolution_timestamp: None,
        }
    }

    /// Notify the board of the conflict (§144(a)(1) first step).
    pub fn notify_board(&mut self) {
        if self.status == SafeHarborStatus::DisclosureFiled {
            self.status = SafeHarborStatus::BoardNotified;
        }
    }

    /// Record disinterested director approval (§144(a)(1) path).
    pub fn record_disinterested_approval(&mut self, approver: String) {
        if !self.disinterested_approvals.contains(&approver) && !self.is_interested_party(&approver)
        {
            self.disinterested_approvals.push(approver);
        }
    }

    /// Check if disinterested majority has approved (§144(a)(1) path).
    pub fn check_disinterested_approval(&mut self) -> bool {
        if self.disinterested_voters.is_empty() {
            return false;
        }
        let required = (self.disinterested_voters.len() / 2) + 1;
        if self.disinterested_approvals.len() >= required {
            self.status = SafeHarborStatus::DisinterestedApproval;
            self.achieve_safe_harbor();
            true
        } else {
            false
        }
    }

    /// Record a fairness opinion (§144(a)(3) path).
    pub fn record_fairness_opinion(&mut self, opinion: FairnessOpinion) {
        let is_fair = opinion.is_fair;
        self.fairness_opinion = Some(opinion);
        if is_fair {
            self.status = SafeHarborStatus::FairnessEstablished;
            self.achieve_safe_harbor();
        }
    }

    /// Check if safe harbor has been achieved through any path.
    pub fn is_safe_harbor_achieved(&self) -> bool {
        self.status == SafeHarborStatus::SafeHarborAchieved
    }

    fn is_interested_party(&self, party: &str) -> bool {
        self.interested_party == party
    }

    fn achieve_safe_harbor(&mut self) {
        self.status = SafeHarborStatus::SafeHarborAchieved;
        self.resolution_timestamp = Some(Utc::now());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_safe_harbor_disinterested_approval_path() {
        let mut sh = DgclSafeHarbor::new(
            Blake3Hash([1u8; 32]),
            "tenant-1".into(),
            "did:exo:ceo".into(),
            "CEO has financial interest in vendor".into(),
            vec!["CEO owns 10% of vendor".into()],
        );

        sh.disinterested_voters = vec![
            "did:exo:dir1".into(),
            "did:exo:dir2".into(),
            "did:exo:dir3".into(),
        ];

        sh.notify_board();
        assert_eq!(sh.status, SafeHarborStatus::BoardNotified);

        sh.record_disinterested_approval("did:exo:dir1".into());
        assert!(!sh.check_disinterested_approval());

        sh.record_disinterested_approval("did:exo:dir2".into());
        assert!(sh.check_disinterested_approval());
        assert!(sh.is_safe_harbor_achieved());
    }

    #[test]
    fn test_interested_party_cannot_approve() {
        let mut sh = DgclSafeHarbor::new(
            Blake3Hash([1u8; 32]),
            "tenant-1".into(),
            "did:exo:ceo".into(),
            "conflict".into(),
            vec![],
        );

        sh.record_disinterested_approval("did:exo:ceo".into());
        assert!(sh.disinterested_approvals.is_empty());
    }

    #[test]
    fn test_fairness_opinion_path() {
        let mut sh = DgclSafeHarbor::new(
            Blake3Hash([1u8; 32]),
            "tenant-1".into(),
            "did:exo:ceo".into(),
            "conflict".into(),
            vec![],
        );

        sh.record_fairness_opinion(FairnessOpinion {
            evaluator: "Independent Valuator LLC".into(),
            opinion: "Transaction is fair to shareholders".into(),
            is_fair: true,
            issued_at: Utc::now(),
            content_hash: Blake3Hash([99u8; 32]),
        });

        assert!(sh.is_safe_harbor_achieved());
    }
}
