//! Adverse Event Detector — monitors event streams for anomalies and outliers.

use exo_core::crypto::{hash_bytes, Blake3Hash};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Severity levels for detected events.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum EventSeverity {
    Info,
    Warning,
    Elevated,
    Critical,
    Emergency,
}

/// Types of anomalies the detector can identify.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum AnomalyType {
    /// Voting patterns suggest coordination.
    QuorumManipulation,
    /// Rapid delegation chain growth.
    DelegationCascade,
    /// Holon alignment score degrading.
    AlignmentDrift,
    /// Consent grants approaching mass expiry.
    ConsentExpiry,
    /// Missing events in audit sequence.
    AuditGap,
    /// BFT double-voting detected.
    EquivocationAttempt,
    /// Access without valid consent.
    UnauthorizedAccess,
    /// State change without audit event (INV-006).
    SilentMutation,
    /// Attempt to remove human override (INV-007).
    HumanOverrideAttempt,
    /// CGR kernel/registry integrity violation (INV-008/009).
    KernelTamper,
    /// Too many emergency actions in period.
    RapidEmergencyActions,
    /// Abnormal trust score movement.
    TrustScoreAnomaly,
    /// User-defined anomaly type.
    Custom(String),
}

impl AnomalyType {
    /// Returns the canonical string key for this anomaly type.
    pub fn key(&self) -> String {
        match self {
            AnomalyType::QuorumManipulation => "QuorumManipulation".into(),
            AnomalyType::DelegationCascade => "DelegationCascade".into(),
            AnomalyType::AlignmentDrift => "AlignmentDrift".into(),
            AnomalyType::ConsentExpiry => "ConsentExpiry".into(),
            AnomalyType::AuditGap => "AuditGap".into(),
            AnomalyType::EquivocationAttempt => "EquivocationAttempt".into(),
            AnomalyType::UnauthorizedAccess => "UnauthorizedAccess".into(),
            AnomalyType::SilentMutation => "SilentMutation".into(),
            AnomalyType::HumanOverrideAttempt => "HumanOverrideAttempt".into(),
            AnomalyType::KernelTamper => "KernelTamper".into(),
            AnomalyType::RapidEmergencyActions => "RapidEmergencyActions".into(),
            AnomalyType::TrustScoreAnomaly => "TrustScoreAnomaly".into(),
            AnomalyType::Custom(s) => format!("Custom({})", s),
        }
    }
}

/// A rule that defines when an anomaly should be flagged.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DetectionRule {
    pub id: String,
    pub name: String,
    pub anomaly_type: AnomalyType,
    pub severity: EventSeverity,
    /// Number of occurrences to trigger.
    pub threshold: u32,
    /// Time window in milliseconds (0 = no window, any time).
    pub window_ms: u64,
    pub enabled: bool,
}

/// A detected adverse event.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AdverseEvent {
    pub id: Blake3Hash,
    pub anomaly_type: AnomalyType,
    pub severity: EventSeverity,
    pub source_event_id: Option<Blake3Hash>,
    pub actor_did: String,
    pub description: String,
    pub detected_at_ms: u64,
    pub evidence: Vec<String>,
    pub auto_escalate: bool,
}

/// Monitors governance event streams and flags anomalies.
#[derive(Clone, Debug)]
pub struct AdverseEventDetector {
    pub rules: Vec<DetectionRule>,
    /// actor DID -> list of timestamps, keyed by anomaly type key.
    pub event_history: HashMap<String, Vec<u64>>,
    pub detected_events: Vec<AdverseEvent>,
}

impl AdverseEventDetector {
    /// Creates a new detector with default rules pre-loaded.
    pub fn new() -> Self {
        let rules = vec![
            DetectionRule {
                id: "RULE-001".into(),
                name: "Equivocation Attempt".into(),
                anomaly_type: AnomalyType::EquivocationAttempt,
                severity: EventSeverity::Critical,
                threshold: 1,
                window_ms: 0,
                enabled: true,
            },
            DetectionRule {
                id: "RULE-002".into(),
                name: "Kernel Tamper".into(),
                anomaly_type: AnomalyType::KernelTamper,
                severity: EventSeverity::Emergency,
                threshold: 1,
                window_ms: 0,
                enabled: true,
            },
            DetectionRule {
                id: "RULE-003".into(),
                name: "Human Override Attempt".into(),
                anomaly_type: AnomalyType::HumanOverrideAttempt,
                severity: EventSeverity::Emergency,
                threshold: 1,
                window_ms: 0,
                enabled: true,
            },
            DetectionRule {
                id: "RULE-004".into(),
                name: "Silent Mutation".into(),
                anomaly_type: AnomalyType::SilentMutation,
                severity: EventSeverity::Elevated,
                threshold: 1,
                window_ms: 0,
                enabled: true,
            },
            DetectionRule {
                id: "RULE-005".into(),
                name: "Rapid Emergency Actions".into(),
                anomaly_type: AnomalyType::RapidEmergencyActions,
                severity: EventSeverity::Warning,
                threshold: 3,
                window_ms: 7_776_000_000, // 90 days
                enabled: true,
            },
            DetectionRule {
                id: "RULE-006".into(),
                name: "Delegation Cascade".into(),
                anomaly_type: AnomalyType::DelegationCascade,
                severity: EventSeverity::Warning,
                threshold: 10,
                window_ms: 3_600_000, // 1 hour
                enabled: true,
            },
            DetectionRule {
                id: "RULE-007".into(),
                name: "Alignment Drift".into(),
                anomaly_type: AnomalyType::AlignmentDrift,
                severity: EventSeverity::Elevated,
                threshold: 5,
                window_ms: 0,
                enabled: true,
            },
            DetectionRule {
                id: "RULE-008".into(),
                name: "Audit Gap".into(),
                anomaly_type: AnomalyType::AuditGap,
                severity: EventSeverity::Critical,
                threshold: 1,
                window_ms: 0,
                enabled: true,
            },
            DetectionRule {
                id: "RULE-009".into(),
                name: "Trust Score Anomaly".into(),
                anomaly_type: AnomalyType::TrustScoreAnomaly,
                severity: EventSeverity::Warning,
                threshold: 100,
                window_ms: 0,
                enabled: true,
            },
            DetectionRule {
                id: "RULE-010".into(),
                name: "Consent Expiry".into(),
                anomaly_type: AnomalyType::ConsentExpiry,
                severity: EventSeverity::Info,
                threshold: 10,
                window_ms: 0,
                enabled: true,
            },
        ];

        Self {
            rules,
            event_history: HashMap::new(),
            detected_events: Vec::new(),
        }
    }

    /// Evaluates an event against detection rules. Returns an `AdverseEvent` if threshold exceeded.
    pub fn evaluate_event(
        &mut self,
        actor: &str,
        anomaly_type: AnomalyType,
        timestamp_ms: u64,
    ) -> Option<AdverseEvent> {
        // Find matching enabled rule
        let rule = self
            .rules
            .iter()
            .find(|r| r.enabled && r.anomaly_type == anomaly_type)?;

        let severity = rule.severity.clone();
        let threshold = rule.threshold;
        let window_ms = rule.window_ms;
        let auto_escalate = severity >= EventSeverity::Critical;

        // Build history key from actor + anomaly type
        let history_key = format!("{}::{}", actor, anomaly_type.key());

        // Record the event
        self.event_history
            .entry(history_key.clone())
            .or_default()
            .push(timestamp_ms);

        // Count events in window
        let timestamps = self.event_history.get(&history_key).unwrap();
        let count = if window_ms == 0 {
            timestamps.len() as u32
        } else {
            let cutoff = timestamp_ms.saturating_sub(window_ms);
            timestamps.iter().filter(|&&t| t >= cutoff).count() as u32
        };

        if count >= threshold {
            let description = format!(
                "Detected {} for actor {} ({} occurrences)",
                anomaly_type.key(),
                actor,
                count
            );
            let id_input = format!("{}:{}:{}", actor, anomaly_type.key(), timestamp_ms);
            let id = hash_bytes(id_input.as_bytes());

            let event = AdverseEvent {
                id,
                anomaly_type,
                severity,
                source_event_id: None,
                actor_did: actor.to_string(),
                description,
                detected_at_ms: timestamp_ms,
                evidence: vec![format!("count={}, threshold={}", count, threshold)],
                auto_escalate,
            };

            self.detected_events.push(event.clone());
            Some(event)
        } else {
            None
        }
    }

    /// Returns true if the actor has exceeded the rate limit within the given window.
    pub fn check_rate_limit(
        &self,
        actor: &str,
        window_ms: u64,
        max_events: u32,
        timestamp_ms: u64,
    ) -> bool {
        let cutoff = timestamp_ms.saturating_sub(window_ms);
        let total: usize = self
            .event_history
            .iter()
            .filter(|(k, _)| k.starts_with(&format!("{}::", actor)))
            .map(|(_, ts)| ts.iter().filter(|&&t| t >= cutoff).count())
            .sum();
        total as u32 > max_events
    }

    /// Total number of detected adverse events.
    pub fn detected_count(&self) -> usize {
        self.detected_events.len()
    }

    /// Returns detected events matching the given severity.
    pub fn events_by_severity(&self, severity: EventSeverity) -> Vec<&AdverseEvent> {
        self.detected_events
            .iter()
            .filter(|e| e.severity == severity)
            .collect()
    }
}

impl Default for AdverseEventDetector {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_rules_loaded() {
        let det = AdverseEventDetector::new();
        assert_eq!(det.rules.len(), 10);
    }

    #[test]
    fn test_equivocation_attempt_threshold_1() {
        let mut det = AdverseEventDetector::new();
        let ev = det.evaluate_event("did:exo:alice", AnomalyType::EquivocationAttempt, 1000);
        assert!(ev.is_some());
        assert_eq!(ev.unwrap().severity, EventSeverity::Critical);
    }

    #[test]
    fn test_kernel_tamper_emergency() {
        let mut det = AdverseEventDetector::new();
        let ev = det.evaluate_event("did:exo:eve", AnomalyType::KernelTamper, 2000);
        assert!(ev.is_some());
        let ev = ev.unwrap();
        assert_eq!(ev.severity, EventSeverity::Emergency);
        assert!(ev.auto_escalate);
    }

    #[test]
    fn test_human_override_attempt() {
        let mut det = AdverseEventDetector::new();
        let ev = det.evaluate_event("did:exo:mallory", AnomalyType::HumanOverrideAttempt, 3000);
        assert!(ev.is_some());
        assert_eq!(ev.unwrap().severity, EventSeverity::Emergency);
    }

    #[test]
    fn test_silent_mutation_elevated() {
        let mut det = AdverseEventDetector::new();
        let ev = det.evaluate_event("did:exo:bob", AnomalyType::SilentMutation, 4000);
        assert!(ev.is_some());
        assert_eq!(ev.unwrap().severity, EventSeverity::Elevated);
    }

    #[test]
    fn test_delegation_cascade_below_threshold() {
        let mut det = AdverseEventDetector::new();
        for i in 0..9 {
            let ev = det.evaluate_event("did:exo:alice", AnomalyType::DelegationCascade, 1000 + i);
            assert!(ev.is_none(), "Should not trigger below threshold of 10");
        }
    }

    #[test]
    fn test_delegation_cascade_at_threshold() {
        let mut det = AdverseEventDetector::new();
        for i in 0..9 {
            det.evaluate_event("did:exo:alice", AnomalyType::DelegationCascade, 1000 + i);
        }
        let ev = det.evaluate_event("did:exo:alice", AnomalyType::DelegationCascade, 1009);
        assert!(ev.is_some());
        assert_eq!(ev.unwrap().severity, EventSeverity::Warning);
    }

    #[test]
    fn test_delegation_cascade_outside_window() {
        let mut det = AdverseEventDetector::new();
        // Events from long ago (outside 1-hour window)
        for i in 0..9 {
            det.evaluate_event("did:exo:alice", AnomalyType::DelegationCascade, i);
        }
        // New event far in the future — only 1 event in window
        let ev = det.evaluate_event(
            "did:exo:alice",
            AnomalyType::DelegationCascade,
            10_000_000,
        );
        assert!(ev.is_none());
    }

    #[test]
    fn test_rapid_emergency_actions_threshold_3() {
        let mut det = AdverseEventDetector::new();
        assert!(det
            .evaluate_event("did:exo:admin", AnomalyType::RapidEmergencyActions, 1000)
            .is_none());
        assert!(det
            .evaluate_event("did:exo:admin", AnomalyType::RapidEmergencyActions, 2000)
            .is_none());
        let ev = det.evaluate_event("did:exo:admin", AnomalyType::RapidEmergencyActions, 3000);
        assert!(ev.is_some());
    }

    #[test]
    fn test_audit_gap_critical() {
        let mut det = AdverseEventDetector::new();
        let ev = det.evaluate_event("did:exo:system", AnomalyType::AuditGap, 5000);
        assert!(ev.is_some());
        assert_eq!(ev.unwrap().severity, EventSeverity::Critical);
    }

    #[test]
    fn test_events_by_severity_filter() {
        let mut det = AdverseEventDetector::new();
        det.evaluate_event("did:exo:a", AnomalyType::KernelTamper, 1000);
        det.evaluate_event("did:exo:b", AnomalyType::AuditGap, 2000);
        det.evaluate_event("did:exo:c", AnomalyType::SilentMutation, 3000);

        assert_eq!(det.events_by_severity(EventSeverity::Emergency).len(), 1);
        assert_eq!(det.events_by_severity(EventSeverity::Critical).len(), 1);
        assert_eq!(det.events_by_severity(EventSeverity::Elevated).len(), 1);
        assert_eq!(det.events_by_severity(EventSeverity::Info).len(), 0);
    }

    #[test]
    fn test_detected_count() {
        let mut det = AdverseEventDetector::new();
        assert_eq!(det.detected_count(), 0);
        det.evaluate_event("did:exo:a", AnomalyType::EquivocationAttempt, 1000);
        det.evaluate_event("did:exo:b", AnomalyType::AuditGap, 2000);
        assert_eq!(det.detected_count(), 2);
    }

    #[test]
    fn test_check_rate_limit() {
        let mut det = AdverseEventDetector::new();
        det.evaluate_event("did:exo:alice", AnomalyType::EquivocationAttempt, 1000);
        det.evaluate_event("did:exo:alice", AnomalyType::AuditGap, 1500);
        det.evaluate_event("did:exo:alice", AnomalyType::SilentMutation, 2000);

        // 3 events in window, max=2 => exceeded
        assert!(det.check_rate_limit("did:exo:alice", 5000, 2, 3000));
        // max=5 => not exceeded
        assert!(!det.check_rate_limit("did:exo:alice", 5000, 5, 3000));
    }

    #[test]
    fn test_custom_anomaly_type() {
        let mut det = AdverseEventDetector::new();
        // Custom type has no matching rule, so should return None
        let ev = det.evaluate_event(
            "did:exo:test",
            AnomalyType::Custom("TestAnomaly".into()),
            1000,
        );
        assert!(ev.is_none());
    }

    #[test]
    fn test_consent_expiry_info_threshold_10() {
        let mut det = AdverseEventDetector::new();
        for i in 0..9 {
            assert!(det
                .evaluate_event("did:exo:sys", AnomalyType::ConsentExpiry, 1000 + i)
                .is_none());
        }
        let ev = det.evaluate_event("did:exo:sys", AnomalyType::ConsentExpiry, 1009);
        assert!(ev.is_some());
        assert_eq!(ev.unwrap().severity, EventSeverity::Info);
    }

    #[test]
    fn test_trust_score_anomaly() {
        let mut det = AdverseEventDetector::new();
        // Threshold is 100, need 100 events
        for i in 0..99 {
            assert!(det
                .evaluate_event("did:exo:node", AnomalyType::TrustScoreAnomaly, 1000 + i)
                .is_none());
        }
        let ev = det.evaluate_event("did:exo:node", AnomalyType::TrustScoreAnomaly, 1099);
        assert!(ev.is_some());
        assert_eq!(ev.unwrap().severity, EventSeverity::Warning);
    }

    #[test]
    fn test_adverse_event_has_blake3_id() {
        let mut det = AdverseEventDetector::new();
        let ev = det
            .evaluate_event("did:exo:x", AnomalyType::EquivocationAttempt, 999)
            .unwrap();
        // ID should be a blake3 hash, not all zeros
        assert_ne!(ev.id, Blake3Hash([0u8; 32]));
    }
}
