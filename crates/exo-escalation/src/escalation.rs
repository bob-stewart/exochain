//! Escalation Policy Engine — defines escalation chains and actions for anomalies.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Escalation levels from automated to emergency.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum EscalationLevel {
    L1Automated,
    L2TeamLead,
    L3Governance,
    L4Constitutional,
    L5Emergency,
}

/// Actions that can be taken at each escalation level.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum EscalationAction {
    Notify(Vec<String>),
    AssignReviewer(String),
    CreateTriageItem,
    SuspendActor(String),
    TriggerVote,
    HaltSystem,
    Custom(String),
}

/// A single step in an escalation chain.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EscalationStep {
    pub level: EscalationLevel,
    pub actions: Vec<EscalationAction>,
    pub timeout_ms: u64,
    pub auto_escalate: bool,
}

/// A chain of escalation steps for a given anomaly type.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EscalationChain {
    pub levels: Vec<EscalationStep>,
}

/// Manages escalation policies mapped to anomaly types.
#[derive(Clone, Debug)]
pub struct EscalationPolicy {
    pub policies: HashMap<String, EscalationChain>,
}

impl EscalationPolicy {
    /// Creates a default policy with pre-built chains for known anomaly types.
    pub fn default_policy() -> Self {
        let mut policies = HashMap::new();

        // KernelTamper: L5_Emergency immediately -> HaltSystem + Notify all validators
        policies.insert(
            "KernelTamper".into(),
            EscalationChain {
                levels: vec![EscalationStep {
                    level: EscalationLevel::L5Emergency,
                    actions: vec![
                        EscalationAction::HaltSystem,
                        EscalationAction::Notify(vec!["all-validators".into()]),
                    ],
                    timeout_ms: 0,
                    auto_escalate: false,
                }],
            },
        );

        // HumanOverrideAttempt: L4_Constitutional -> TriggerVote + SuspendActor
        policies.insert(
            "HumanOverrideAttempt".into(),
            EscalationChain {
                levels: vec![EscalationStep {
                    level: EscalationLevel::L4Constitutional,
                    actions: vec![
                        EscalationAction::TriggerVote,
                        EscalationAction::SuspendActor("offending-actor".into()),
                    ],
                    timeout_ms: 86_400_000, // 24h
                    auto_escalate: true,
                }],
            },
        );

        // EquivocationAttempt: L3_Governance -> SuspendActor + CreateTriageItem
        policies.insert(
            "EquivocationAttempt".into(),
            EscalationChain {
                levels: vec![EscalationStep {
                    level: EscalationLevel::L3Governance,
                    actions: vec![
                        EscalationAction::SuspendActor("offending-actor".into()),
                        EscalationAction::CreateTriageItem,
                    ],
                    timeout_ms: 3_600_000, // 1h
                    auto_escalate: true,
                }],
            },
        );

        // AuditGap: L2_TeamLead -> AssignReviewer + CreateTriageItem
        policies.insert(
            "AuditGap".into(),
            EscalationChain {
                levels: vec![EscalationStep {
                    level: EscalationLevel::L2TeamLead,
                    actions: vec![
                        EscalationAction::AssignReviewer("audit-team".into()),
                        EscalationAction::CreateTriageItem,
                    ],
                    timeout_ms: 7_200_000, // 2h
                    auto_escalate: true,
                }],
            },
        );

        // Default for all other types: L1_Automated -> Notify + CreateTriageItem
        for key in &[
            "QuorumManipulation",
            "DelegationCascade",
            "AlignmentDrift",
            "ConsentExpiry",
            "UnauthorizedAccess",
            "SilentMutation",
            "RapidEmergencyActions",
            "TrustScoreAnomaly",
        ] {
            policies.insert(
                (*key).to_string(),
                EscalationChain {
                    levels: vec![EscalationStep {
                        level: EscalationLevel::L1Automated,
                        actions: vec![
                            EscalationAction::Notify(vec!["ops-team".into()]),
                            EscalationAction::CreateTriageItem,
                        ],
                        timeout_ms: 14_400_000, // 4h
                        auto_escalate: true,
                    }],
                },
            );
        }

        Self { policies }
    }

    /// Returns the escalation chain for a given anomaly type key.
    pub fn get_chain(&self, anomaly_type: &str) -> Option<&EscalationChain> {
        self.policies.get(anomaly_type)
    }

    /// Returns the actions for a given anomaly type and escalation level.
    pub fn get_actions(
        &self,
        anomaly_type: &str,
        level: &EscalationLevel,
    ) -> Vec<&EscalationAction> {
        self.policies
            .get(anomaly_type)
            .map(|chain| {
                chain
                    .levels
                    .iter()
                    .filter(|step| &step.level == level)
                    .flat_map(|step| step.actions.iter())
                    .collect()
            })
            .unwrap_or_default()
    }

    /// Checks whether auto-escalation should occur based on elapsed time.
    pub fn should_auto_escalate(
        &self,
        anomaly_type: &str,
        level: &EscalationLevel,
        elapsed_ms: u64,
    ) -> bool {
        self.policies
            .get(anomaly_type)
            .map(|chain| {
                chain.levels.iter().any(|step| {
                    &step.level == level
                        && step.auto_escalate
                        && step.timeout_ms > 0
                        && elapsed_ms >= step.timeout_ms
                })
            })
            .unwrap_or(false)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_policy_has_all_types() {
        let policy = EscalationPolicy::default_policy();
        assert!(policy.get_chain("KernelTamper").is_some());
        assert!(policy.get_chain("HumanOverrideAttempt").is_some());
        assert!(policy.get_chain("EquivocationAttempt").is_some());
        assert!(policy.get_chain("AuditGap").is_some());
        assert!(policy.get_chain("DelegationCascade").is_some());
        assert!(policy.get_chain("SilentMutation").is_some());
    }

    #[test]
    fn test_kernel_tamper_is_emergency() {
        let policy = EscalationPolicy::default_policy();
        let chain = policy.get_chain("KernelTamper").unwrap();
        assert_eq!(chain.levels[0].level, EscalationLevel::L5Emergency);
        assert!(chain.levels[0]
            .actions
            .contains(&EscalationAction::HaltSystem));
    }

    #[test]
    fn test_human_override_triggers_vote() {
        let policy = EscalationPolicy::default_policy();
        let chain = policy.get_chain("HumanOverrideAttempt").unwrap();
        assert_eq!(chain.levels[0].level, EscalationLevel::L4Constitutional);
        assert!(chain.levels[0]
            .actions
            .contains(&EscalationAction::TriggerVote));
    }

    #[test]
    fn test_equivocation_suspends_actor() {
        let policy = EscalationPolicy::default_policy();
        let actions = policy.get_actions("EquivocationAttempt", &EscalationLevel::L3Governance);
        assert!(actions
            .iter()
            .any(|a| matches!(a, EscalationAction::SuspendActor(_))));
    }

    #[test]
    fn test_audit_gap_assigns_reviewer() {
        let policy = EscalationPolicy::default_policy();
        let actions = policy.get_actions("AuditGap", &EscalationLevel::L2TeamLead);
        assert!(actions
            .iter()
            .any(|a| matches!(a, EscalationAction::AssignReviewer(_))));
    }

    #[test]
    fn test_default_type_is_l1_automated() {
        let policy = EscalationPolicy::default_policy();
        let chain = policy.get_chain("DelegationCascade").unwrap();
        assert_eq!(chain.levels[0].level, EscalationLevel::L1Automated);
    }

    #[test]
    fn test_should_auto_escalate_timeout() {
        let policy = EscalationPolicy::default_policy();
        // AuditGap has 2h timeout with auto_escalate
        assert!(!policy.should_auto_escalate(
            "AuditGap",
            &EscalationLevel::L2TeamLead,
            3_600_000
        ));
        assert!(policy.should_auto_escalate(
            "AuditGap",
            &EscalationLevel::L2TeamLead,
            7_200_000
        ));
    }

    #[test]
    fn test_should_not_auto_escalate_kernel_tamper() {
        let policy = EscalationPolicy::default_policy();
        // KernelTamper has timeout=0, auto_escalate=false
        assert!(!policy.should_auto_escalate(
            "KernelTamper",
            &EscalationLevel::L5Emergency,
            999_999_999
        ));
    }

    #[test]
    fn test_get_actions_nonexistent_type() {
        let policy = EscalationPolicy::default_policy();
        let actions = policy.get_actions("NonExistent", &EscalationLevel::L1Automated);
        assert!(actions.is_empty());
    }

    #[test]
    fn test_get_actions_wrong_level() {
        let policy = EscalationPolicy::default_policy();
        // KernelTamper is L5, asking for L1 should return nothing
        let actions = policy.get_actions("KernelTamper", &EscalationLevel::L1Automated);
        assert!(actions.is_empty());
    }
}
