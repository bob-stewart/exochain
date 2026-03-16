//! Quorum verification — ensures proper participation before decisions.
//!
//! Satisfies: TNC-07, GOV-010

use crate::errors::GovernanceError;
use crate::types::Did;
use serde::{Deserialize, Serialize};

/// Quorum verification result.
#[derive(Clone, Debug)]
pub struct QuorumVerification {
    pub eligible_count: u32,
    pub present_count: u32,
    pub required_count: u32,
    pub is_met: bool,
    pub absent_members: Vec<Did>,
}

/// Degraded governance configuration (GOV-010).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DegradedGovernanceConfig {
    /// Minimum fraction of eligible voters that must be reachable (0.0-1.0).
    pub minimum_reachable_fraction: f64,
    /// Whether degraded governance is enabled.
    pub enabled: bool,
    /// Maximum duration of degraded governance in hours.
    pub max_duration_hours: u32,
    /// Reduced quorum threshold during degraded mode (percentage).
    pub reduced_quorum_pct: u32,
}

impl Default for DegradedGovernanceConfig {
    fn default() -> Self {
        Self {
            minimum_reachable_fraction: 0.5,
            enabled: true,
            max_duration_hours: 24,
            reduced_quorum_pct: 50,
        }
    }
}

/// Verify quorum before vote initiation (TNC-07).
///
/// This MUST be called before a decision can enter Voting status.
pub fn verify_quorum(
    eligible_voters: &[Did],
    present_voters: &[Did],
    minimum_participants: u32,
) -> Result<QuorumVerification, GovernanceError> {
    let eligible_count = eligible_voters.len() as u32;
    let present_count = present_voters
        .iter()
        .filter(|p| eligible_voters.contains(p))
        .count() as u32;

    let absent_members: Vec<Did> = eligible_voters
        .iter()
        .filter(|e| !present_voters.contains(e))
        .cloned()
        .collect();

    let is_met = present_count >= minimum_participants;

    let verification = QuorumVerification {
        eligible_count,
        present_count,
        required_count: minimum_participants,
        is_met,
        absent_members,
    };

    if !is_met {
        return Err(GovernanceError::QuorumNotMet {
            required: minimum_participants,
            present: present_count,
        });
    }

    Ok(verification)
}

/// Check if degraded governance should be activated.
pub fn should_activate_degraded_governance(
    eligible_count: u32,
    reachable_count: u32,
    config: &DegradedGovernanceConfig,
) -> bool {
    if !config.enabled {
        return false;
    }
    let fraction = reachable_count as f64 / eligible_count as f64;
    fraction < 1.0 && fraction >= config.minimum_reachable_fraction
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tnc07_quorum_met() {
        let eligible = vec![
            "did:exo:a".to_string(),
            "did:exo:b".to_string(),
            "did:exo:c".to_string(),
        ];
        let present = vec!["did:exo:a".to_string(), "did:exo:b".to_string()];

        let result = verify_quorum(&eligible, &present, 2);
        assert!(result.is_ok());
        let v = result.unwrap();
        assert!(v.is_met);
        assert_eq!(v.present_count, 2);
        assert_eq!(v.absent_members, vec!["did:exo:c".to_string()]);
    }

    #[test]
    fn test_tnc07_quorum_not_met() {
        let eligible = vec![
            "did:exo:a".to_string(),
            "did:exo:b".to_string(),
            "did:exo:c".to_string(),
        ];
        let present = vec!["did:exo:a".to_string()];

        let result = verify_quorum(&eligible, &present, 2);
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            GovernanceError::QuorumNotMet {
                required: 2,
                present: 1
            }
        ));
    }

    #[test]
    fn test_ineligible_present_not_counted() {
        let eligible = vec!["did:exo:a".to_string(), "did:exo:b".to_string()];
        let present = vec![
            "did:exo:a".to_string(),
            "did:exo:intruder".to_string(), // not eligible
        ];

        let result = verify_quorum(&eligible, &present, 2);
        assert!(result.is_err()); // only 1 eligible present
    }

    #[test]
    fn test_degraded_governance_activation() {
        let config = DegradedGovernanceConfig::default();

        // 3 of 5 reachable — should activate degraded mode
        assert!(should_activate_degraded_governance(5, 3, &config));

        // All reachable — no degraded mode needed
        assert!(!should_activate_degraded_governance(5, 5, &config));

        // Too few reachable — below minimum fraction
        assert!(!should_activate_degraded_governance(10, 4, &config));
    }
}
