use clap::Subcommand;
use exo_bcts::{
    create_transaction, run_pipeline, verify_ledger,
    BctsState, SignerType, state_description, stage_description,
    PIPELINE_STAGES,
};

#[derive(Subcommand)]
pub enum BctsAction {
    /// Create a new BCTS transaction
    Create {
        /// Actor DID
        #[arg(long)]
        actor: String,
        /// Action name
        #[arg(long)]
        action: String,
    },
    /// Show BCTS pipeline stages
    Pipeline,
    /// Show all 14 transaction states with descriptions
    States,
    /// Run a demo transaction through the full 7-stage pipeline
    Demo {
        /// Actor DID
        #[arg(long, default_value = "did:demo:user")]
        actor: String,
    },
}

pub fn execute(action: BctsAction) -> Result<(), Box<dyn std::error::Error>> {
    match action {
        BctsAction::Create { actor, action: act } => {
            let tx = create_transaction(&actor, &act, serde_json::json!({}), SignerType::Human, vec![]);
            println!("BCTS Transaction created:");
            println!("  ID:             {}", tx.id);
            println!("  State:          {}", tx.state);
            println!("  Actor:          {}", tx.envelope.actor_did);
            println!("  Action:         {}", tx.envelope.action);
            println!("  Correlation ID: {}", tx.envelope.correlation_id);
            println!("  Created:        {}", tx.created_at);
            Ok(())
        }
        BctsAction::Pipeline => {
            println!("BCTS 7-Stage Pipeline:");
            println!("{:-<60}", "");
            for (i, stage) in PIPELINE_STAGES.iter().enumerate() {
                println!("  {}. {} ({} -> {})", i + 1, stage.name.to_uppercase(), stage.from, stage.to);
                println!("     {}", stage_description(stage.name));
                println!();
            }
            Ok(())
        }
        BctsAction::States => {
            println!("BCTS Transaction States (14):");
            println!("{:-<60}", "");
            let states = [
                BctsState::Draft, BctsState::Submitted, BctsState::IdentityResolved,
                BctsState::ConsentValidated, BctsState::Deliberated, BctsState::Verified,
                BctsState::Governed, BctsState::Approved, BctsState::Executed,
                BctsState::Recorded, BctsState::Closed, BctsState::Denied,
                BctsState::Escalated, BctsState::Remediated,
            ];
            for state in &states {
                println!("  {:<22} {}", state.to_string(), state_description(*state));
            }
            Ok(())
        }
        BctsAction::Demo { actor } => {
            println!("Running BCTS demo pipeline for {actor}...");
            println!("{:-<60}", "");

            let tx = create_transaction(&actor, "demo:submit-case", serde_json::json!({"demo": true}), SignerType::Human, vec![]);
            let result = run_pipeline(tx, &actor, |stage, _tx| {
                Ok(format!("{stage} validated"))
            });

            for stage_result in &result.stages {
                let icon = if stage_result.success { "✓" } else { "✗" };
                println!("  {icon} {:<15} {}", stage_result.stage, stage_result.evidence.as_deref().unwrap_or(""));
            }

            println!();
            println!("Final state: {}", result.transaction.state);
            println!("Ledger events: {}", result.transaction.ledger.len());
            println!("Chain valid: {}", verify_ledger(&result.transaction));

            if result.failed_at.is_some() {
                println!("Failed at: {}", result.failed_at.unwrap());
            }
            Ok(())
        }
    }
}
