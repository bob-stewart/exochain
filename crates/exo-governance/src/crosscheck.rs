//! CrosscheckReport — plural intelligence artifact from crosschecked.ai
//!
//! Per the decision.forum whitepaper: "preserve plurality as structured artifact."
//! CrosscheckReports are produced by crosschecked.ai's multi-model consensus engine
//! and attached to DecisionRecords as evidence of plural deliberation.
//!
//! Satisfies: GOV-001 (plural governance), UX-004 (AI recommendation cards)

use crate::types::*;
use exo_core::crypto::Blake3Hash;
use exo_core::hlc::HybridLogicalClock;
use serde::{Deserialize, Serialize};

/// The method used for crosscheck deliberation.
/// Maps to crosschecked.ai operational modes.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum CrosscheckMethod {
    /// Single model, single pass (crosschecked.ai "QuickCheck")
    QuickCheck,
    /// Multi-model panel consensus (crosschecked.ai "Crosscheck")
    Crosscheck,
    /// Full panel with multi-round refinement (crosschecked.ai "Borg")
    Borg,
    /// Adversarial challenge mode (crosschecked.ai "Audit")
    Audit,
    /// Devil's advocate sub-process
    DevilsAdvocate,
    /// Red team adversarial analysis
    RedTeam,
    /// Structured jury deliberation
    Jury,
    /// Custom method
    Custom(String),
}

/// Provenance metadata for a synthetic opinion.
/// Per whitepaper: "Synthetic voices MUST NOT be presented as distinct humans."
/// Each opinion SHOULD carry provenance: agent_id, agent_kind, model.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct OpinionProvenance {
    /// Unique identifier for the agent/model instance.
    pub agent_id: String,
    /// Kind of agent (e.g., "llm", "human-reviewer", "rule-engine").
    pub agent_kind: AgentKind,
    /// Model identifier if applicable (e.g., "gpt-4o", "claude-3.5-sonnet").
    pub model: Option<String>,
    /// Provider (e.g., "openai", "anthropic", "google", "xai").
    pub provider: Option<String>,
}

/// Agent kind — distinguishes synthetic from human opinions.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum AgentKind {
    /// Large language model
    Llm,
    /// Human reviewer
    Human,
    /// Rule-based engine
    RuleEngine,
    /// Specialist agent (code analysis, risk scoring, etc.)
    Specialist(String),
}

/// A single opinion from one panelist in a crosscheck.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CrosscheckOpinion {
    /// Unique identifier for this opinion.
    pub id: String,
    /// Provenance — who/what produced this opinion.
    pub provenance: OpinionProvenance,
    /// The opinion content.
    pub content: String,
    /// Confidence score (0.0 to 1.0) if available.
    pub confidence: Option<f64>,
    /// Whether this opinion dissents from the synthesis.
    pub is_dissent: bool,
    /// Reasoning chain or rationale.
    pub rationale: Option<String>,
    /// Token count (for cost tracking).
    pub token_count: Option<u64>,
    /// Latency in milliseconds.
    pub latency_ms: Option<u64>,
}

/// The CrosscheckReport — a first-class decision.forum protocol object.
///
/// Produced by crosschecked.ai, attached to DecisionRecords as evidence
/// of plural intelligence deliberation. Preserves dissent as first-class data.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CrosscheckReport {
    /// Unique identifier for this report.
    pub id: String,
    /// Content hash for integrity verification (deterministic canonical hash).
    pub content_hash: Blake3Hash,
    /// The question or prompt that was crosschecked.
    pub query: String,
    /// All panelist opinions with provenance.
    pub opinions: Vec<CrosscheckOpinion>,
    /// Synthesized consensus output.
    pub synthesis: String,
    /// Synthesized confidence score (0.0 to 1.0).
    pub synthesis_confidence: Option<f64>,
    /// Dissenting opinions (preserved as first-class output — "Minority Report").
    pub dissent: Vec<String>,
    /// DIDs/IDs of dissenters.
    pub dissenters: Vec<String>,
    /// Method used for this crosscheck.
    pub method: CrosscheckMethod,
    /// Whether a Devil's Advocate challenge was run.
    pub devils_advocate_applied: bool,
    /// Devil's advocate critique if applied.
    pub devils_advocate_output: Option<String>,
    /// Total cost in credits (crosschecked.ai billing).
    pub total_credits: Option<f64>,
    /// Timestamp of report generation.
    pub created_at: HybridLogicalClock,
    /// DID of the user who initiated the crosscheck.
    pub initiated_by: Did,
    /// Reference to the DecisionRecord this report is attached to.
    pub decision_id: Option<Blake3Hash>,
    /// zkML proof of AI provenance (ARCH-002) — optional.
    pub zkml_proof: Option<Vec<u8>>,
}

impl CrosscheckReport {
    /// Compute the consensus agreement ratio (0.0 to 1.0).
    /// Higher values indicate stronger consensus.
    pub fn agreement_ratio(&self) -> f64 {
        if self.opinions.is_empty() {
            return 0.0;
        }
        let agreeing = self.opinions.iter().filter(|o| !o.is_dissent).count();
        agreeing as f64 / self.opinions.len() as f64
    }

    /// Returns true if consensus was unanimous (no dissent).
    pub fn is_unanimous(&self) -> bool {
        self.dissent.is_empty() && self.opinions.iter().all(|o| !o.is_dissent)
    }

    /// Returns the number of distinct models/agents that participated.
    pub fn panel_size(&self) -> usize {
        self.opinions.len()
    }

    /// Check whether this report meets a minimum panel size and agreement threshold.
    pub fn meets_threshold(&self, min_panel: usize, min_agreement: f64) -> bool {
        self.panel_size() >= min_panel && self.agreement_ratio() >= min_agreement
    }

    /// Extract all unique provider names from the panel.
    pub fn providers(&self) -> Vec<String> {
        let mut providers: Vec<String> = self
            .opinions
            .iter()
            .filter_map(|o| o.provenance.provider.clone())
            .collect();
        providers.sort();
        providers.dedup();
        providers
    }

    /// Verify that no synthetic opinions are presented without provenance.
    /// Per whitepaper: "Synthetic voices MUST NOT be presented as distinct humans."
    pub fn verify_provenance_compliance(&self) -> bool {
        self.opinions.iter().all(|o| {
            // LLM opinions must have model specified
            if o.provenance.agent_kind == AgentKind::Llm {
                o.provenance.model.is_some()
            } else {
                true
            }
        })
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

    fn test_opinion(id: &str, model: &str, provider: &str, is_dissent: bool) -> CrosscheckOpinion {
        CrosscheckOpinion {
            id: id.to_string(),
            provenance: OpinionProvenance {
                agent_id: format!("agent-{}", id),
                agent_kind: AgentKind::Llm,
                model: Some(model.to_string()),
                provider: Some(provider.to_string()),
            },
            content: format!("Opinion from {}", model),
            confidence: Some(0.85),
            is_dissent,
            rationale: Some("Reasoning here".to_string()),
            token_count: Some(150),
            latency_ms: Some(1200),
        }
    }

    fn test_report() -> CrosscheckReport {
        CrosscheckReport {
            id: "xck-001".to_string(),
            content_hash: Blake3Hash([1u8; 32]),
            query: "Should we approve the quarterly budget?".to_string(),
            opinions: vec![
                test_opinion("1", "gpt-4o", "openai", false),
                test_opinion("2", "claude-3.5-sonnet", "anthropic", false),
                test_opinion("3", "gemini-2.0-flash", "google", true),
            ],
            synthesis: "Majority recommends approval with conditions.".to_string(),
            synthesis_confidence: Some(0.78),
            dissent: vec!["Gemini raises concerns about Q3 projections.".to_string()],
            dissenters: vec!["agent-3".to_string()],
            method: CrosscheckMethod::Crosscheck,
            devils_advocate_applied: true,
            devils_advocate_output: Some("Consider downside scenario if revenue drops 15%.".to_string()),
            total_credits: Some(45.0),
            created_at: test_hlc(1000),
            initiated_by: "did:exo:alice".to_string(),
            decision_id: Some(Blake3Hash([2u8; 32])),
            zkml_proof: None,
        }
    }

    #[test]
    fn test_agreement_ratio() {
        let report = test_report();
        // 2 of 3 agree
        let ratio = report.agreement_ratio();
        assert!((ratio - 0.6667).abs() < 0.01);
    }

    #[test]
    fn test_unanimous() {
        let mut report = test_report();
        assert!(!report.is_unanimous());

        // Make all opinions agree
        for o in &mut report.opinions {
            o.is_dissent = false;
        }
        report.dissent.clear();
        assert!(report.is_unanimous());
    }

    #[test]
    fn test_panel_size() {
        let report = test_report();
        assert_eq!(report.panel_size(), 3);
    }

    #[test]
    fn test_meets_threshold() {
        let report = test_report();
        assert!(report.meets_threshold(2, 0.5));
        assert!(!report.meets_threshold(4, 0.5)); // panel too small
        assert!(!report.meets_threshold(2, 0.8)); // agreement too low
    }

    #[test]
    fn test_providers() {
        let report = test_report();
        let providers = report.providers();
        assert_eq!(providers, vec!["anthropic", "google", "openai"]);
    }

    #[test]
    fn test_provenance_compliance() {
        let report = test_report();
        assert!(report.verify_provenance_compliance());

        // Create a report with missing model provenance for LLM
        let mut bad_report = test_report();
        bad_report.opinions[0].provenance.model = None;
        assert!(!bad_report.verify_provenance_compliance());
    }

    #[test]
    fn test_empty_report() {
        let mut report = test_report();
        report.opinions.clear();
        assert_eq!(report.agreement_ratio(), 0.0);
        assert_eq!(report.panel_size(), 0);
    }
}
