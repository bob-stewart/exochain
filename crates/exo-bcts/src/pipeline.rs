//! 9-stage BCTS pipeline executor.
//!
//! Runs a transaction through the full governance pipeline from Draft to Closed.
//! Each stage invokes a validator callback — return `Ok(evidence)` to proceed
//! or `Err(reason)` to deny. Failed transactions transition to `Denied` with
//! cryptographic evidence of the violation.

use crate::states::BctsState;
use crate::transaction::{transition, BctsTransaction};

/// The 7 BCTS pipeline stages (mapped to all required state transitions)
pub const PIPELINE_STAGES: &[PipelineStage] = &[
    PipelineStage { name: "propose", from: BctsState::Draft, to: BctsState::Submitted },
    PipelineStage { name: "authenticate", from: BctsState::Submitted, to: BctsState::IdentityResolved },
    PipelineStage { name: "gate", from: BctsState::IdentityResolved, to: BctsState::ConsentValidated },
    PipelineStage { name: "deliberate", from: BctsState::ConsentValidated, to: BctsState::Deliberated },
    PipelineStage { name: "prove", from: BctsState::Deliberated, to: BctsState::Verified },
    PipelineStage { name: "govern", from: BctsState::Verified, to: BctsState::Governed },
    PipelineStage { name: "commit", from: BctsState::Governed, to: BctsState::Approved },
    PipelineStage { name: "anchor", from: BctsState::Approved, to: BctsState::Executed },
    PipelineStage { name: "audit", from: BctsState::Executed, to: BctsState::Recorded },
];

#[derive(Debug, Clone)]
pub struct PipelineStage {
    pub name: &'static str,
    pub from: BctsState,
    pub to: BctsState,
}

#[derive(Debug, Clone)]
pub struct StageResult {
    pub stage: String,
    pub success: bool,
    pub evidence: Option<String>,
    pub error: Option<String>,
}

#[derive(Debug, Clone)]
pub struct PipelineResult {
    pub transaction: BctsTransaction,
    pub stages: Vec<StageResult>,
    pub failed_at: Option<String>,
}

/// Run a transaction through the full 7-stage pipeline.
/// `validators` is called for each stage — return Ok(evidence) to pass, Err(reason) to deny.
pub fn run_pipeline<F>(
    tx: BctsTransaction,
    actor_did: &str,
    mut validator: F,
) -> PipelineResult
where
    F: FnMut(&str, &BctsTransaction) -> Result<String, String>,
{
    let mut current = tx;
    let mut stages = Vec::new();

    for stage in PIPELINE_STAGES {
        match validator(stage.name, &current) {
            Ok(evidence) => {
                stages.push(StageResult {
                    stage: stage.name.to_string(),
                    success: true,
                    evidence: Some(evidence.clone()),
                    error: None,
                });
                match transition(&current, stage.to, actor_did, Some(&evidence)) {
                    Ok(next) => current = next,
                    Err(e) => {
                        stages.last_mut().unwrap().success = false;
                        stages.last_mut().unwrap().error = Some(e.clone());
                        if let Ok(denied) = transition(&current, BctsState::Denied, actor_did, Some(&e)) {
                            current = denied;
                        }
                        return PipelineResult { transaction: current, stages, failed_at: Some(stage.name.to_string()) };
                    }
                }
            }
            Err(reason) => {
                stages.push(StageResult {
                    stage: stage.name.to_string(),
                    success: false,
                    evidence: None,
                    error: Some(reason.clone()),
                });
                if let Ok(denied) = transition(&current, BctsState::Denied, actor_did, Some(&reason)) {
                    current = denied;
                }
                return PipelineResult { transaction: current, stages, failed_at: Some(stage.name.to_string()) };
            }
        }
    }

    // Close the transaction
    if let Ok(closed) = transition(&current, BctsState::Closed, actor_did, Some("pipeline-complete")) {
        current = closed;
    }

    PipelineResult { transaction: current, stages, failed_at: None }
}

/// Pipeline stage descriptions for the onboarding UI
pub fn stage_description(name: &str) -> &'static str {
    match name {
        "propose" => "Create and submit the transaction envelope with action and payload",
        "authenticate" => "Verify actor identity via DID credential and Ed25519 signature",
        "gate" => "Validate active bailment consent boundaries",
        "deliberate" => "Governance deliberation — quorum reached, decision recorded",
        "prove" => "CGR kernel verifies all 9 constitutional invariants",
        "govern" => "Apply governance rules — compliance confirmed",
        "commit" => "Approved transaction receives cryptographic proof certificate",
        "anchor" => "Execute the state change and anchor to external trust sources",
        "audit" => "Record the transaction in the append-only audit ledger with HLC timestamp",
        _ => "Unknown pipeline stage",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::transaction::{create_transaction, SignerType};

    #[test]
    fn test_full_pipeline_success() {
        let tx = create_transaction("did:user:1", "submit:case", serde_json::json!({}), SignerType::Human, vec![]);
        let result = run_pipeline(tx, "did:user:1", |_stage, _tx| Ok("pass".to_string()));
        assert!(result.failed_at.is_none());
        assert_eq!(result.transaction.state, BctsState::Closed);
        assert_eq!(result.stages.len(), 9);
    }

    #[test]
    fn test_pipeline_denied_at_gate() {
        let tx = create_transaction("did:user:1", "submit:case", serde_json::json!({}), SignerType::Human, vec![]);
        let result = run_pipeline(tx, "did:user:1", |stage, _tx| {
            if stage == "gate" {
                Err("no active bailment".to_string())
            } else {
                Ok("pass".to_string())
            }
        });
        assert_eq!(result.failed_at.as_deref(), Some("gate"));
        assert_eq!(result.transaction.state, BctsState::Denied);
    }
}
