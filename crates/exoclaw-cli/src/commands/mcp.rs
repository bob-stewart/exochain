use std::collections::BTreeMap;
use clap::Subcommand;
use exo_gatekeeper::{
    McpContext, McpEnforcementResult, SignerType, ALL_MCP_RULES, enforce,
};

#[derive(Subcommand)]
pub enum McpAction {
    /// Enforce MCP rules against an AI context
    Enforce {
        /// Actor DID
        #[arg(long)]
        actor: String,
        /// BCTS scope
        #[arg(long)]
        scope: Option<String>,
        /// Comma-separated capabilities
        #[arg(long, default_value = "")]
        capabilities: String,
    },
    /// Show all 6 MCP constitutional rules
    Rules,
    /// Show MCP audit trail format
    AuditInfo,
}

pub fn execute(action: McpAction) -> Result<(), Box<dyn std::error::Error>> {
    match action {
        McpAction::Enforce { actor, scope, capabilities } => {
            let caps: Vec<String> = capabilities
                .split(',')
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
                .collect();

            let mut meta = BTreeMap::new();
            meta.insert("model".to_string(), "exoclaw-cli".to_string());
            meta.insert("provider".to_string(), "exochain".to_string());
            meta.insert("action".to_string(), "cli-enforce".to_string());

            let context = McpContext {
                actor_did: actor.clone(),
                signer_type: SignerType::Ai,
                capabilities: caps,
                bcts_scope: scope,
                provenance_metadata: Some(meta),
                consent_bailment_ids: vec!["cli-session".to_string()],
                is_distinguished: true,
            };

            let results = enforce(&context, &ALL_MCP_RULES);
            println!("MCP Enforcement Results for {actor}:");
            println!("{:-<60}", "");

            for result in &results {
                match result {
                    McpEnforcementResult::Allowed { rule } => {
                        println!("  [PASS] {rule}");
                    }
                    McpEnforcementResult::Blocked { violation } => {
                        println!("  [FAIL] {}", violation.rule);
                        println!("         {}", violation.description);
                        println!("         severity: {:?}", violation.severity);
                    }
                    McpEnforcementResult::Escalated { rule, reason } => {
                        println!("  [ESCL] {rule}");
                        println!("         {reason}");
                    }
                }
            }

            let blocked = results.iter().any(|r| matches!(r, McpEnforcementResult::Blocked { .. }));
            println!();
            if blocked {
                println!("Result: BLOCKED — constitutional violation detected");
            } else {
                println!("Result: ALLOWED — all 6 MCP rules satisfied");
            }
            Ok(())
        }
        McpAction::Rules => {
            println!("EXOCHAIN MCP Constitutional Rules (6):");
            println!("{:-<60}", "");
            println!("  MCP-001  BCTS Scope");
            println!("           AI must operate within Bounded Computational Trust Scope");
            println!("  MCP-002  No Self-Escalation");
            println!("           AI cannot escalate its own capabilities");
            println!("  MCP-003  Provenance Required");
            println!("           All AI actions require metadata documenting origin");
            println!("  MCP-004  No Identity Forge");
            println!("           AI cannot forge identities or signatures (0x02 prefix)");
            println!("  MCP-005  Distinguishable");
            println!("           AI outputs must be marked as AI-generated");
            println!("  MCP-006  Consent Boundaries");
            println!("           AI must respect active bailment consent boundaries");
            Ok(())
        }
        McpAction::AuditInfo => {
            println!("MCP Audit Trail:");
            println!("  Format:    BLAKE3 hash-chained append-only log");
            println!("  Records:   id | timestamp | rule | actor_did | outcome | chain_hash");
            println!("  Outcomes:  Allowed | Blocked | Escalated");
            println!("  Integrity: Each record's chain_hash links to previous record");
            println!("  Residency: Optional data_residency_region for GDPR compliance");
            println!();
            println!("  Verification: exoclaw mcp audit-verify <log-file>");
            Ok(())
        }
    }
}
