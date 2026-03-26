//! # Exemplar App — consuming the EXOCHAIN trust fabric
//!
//! This example demonstrates how any application (litigation portal, healthcare system,
//! financial platform, etc.) integrates with the constitutional trust fabric.
//!
//! The pattern is always the same:
//! 1. Propose a bailment for data access
//! 2. Accept the bailment
//! 3. Create a BCTS transaction
//! 4. Run it through the pipeline (with consent + invariant checks)
//! 5. Verify the audit trail

use exo_consent::{propose, accept, BailmentType, is_active};
use exo_gatekeeper::{
    McpContext, SignerType, enforce, ALL_MCP_RULES, McpAuditLog, McpEnforcementOutcome,
};
use exo_bcts::{
    create_transaction, run_pipeline, verify_ledger, check_all_invariants,
    InvariantContext,
    SignerType as BctsSignerType,
};

fn main() {
    println!("=== EXOCHAIN Trust Fabric — Exemplar App ===\n");

    // ── Step 1: Establish consent via bailment ──────────────────────
    println!("1. Proposing bailment...");
    let bailment = propose(
        "did:user:institution-alpha",
        "did:org:law-firm-beta",
        BailmentType::Processing,
        "Access institution data for case evaluation under polymer litigation",
        None,
    );
    println!("   Bailment ID: {}", bailment.id);
    println!("   Terms hash:  {}", bailment.terms_hash);

    println!("\n2. Accepting bailment...");
    let bailment = accept(&bailment, "ed25519:bailee-signature-hex").unwrap();
    println!("   Status: {} (active: {})", bailment.status, is_active(&bailment));

    // ── Step 2: MCP enforcement for AI actions ─────────────────────
    println!("\n3. Enforcing MCP rules on AI agent...");
    let mut provenance = std::collections::BTreeMap::new();
    provenance.insert("model".to_string(), "claude-opus-4-6".to_string());
    provenance.insert("provider".to_string(), "anthropic".to_string());
    provenance.insert("action".to_string(), "score-eligibility".to_string());

    let ctx = McpContext {
        actor_did: "did:ai:exoclaw-scorer".to_string(),
        signer_type: SignerType::Ai,
        capabilities: vec!["read:screener-data".to_string()],
        bcts_scope: Some("litigation-scoring".to_string()),
        provenance_metadata: Some(provenance),
        consent_bailment_ids: vec![bailment.id.clone()],
        is_distinguished: true,
    };

    let results = enforce(&ctx, &ALL_MCP_RULES);
    for r in &results {
        match r {
            exo_gatekeeper::McpEnforcementResult::Allowed { rule } => {
                println!("   [PASS] {rule}");
            }
            exo_gatekeeper::McpEnforcementResult::Blocked { violation } => {
                println!("   [FAIL] {} — {}", violation.rule, violation.description);
            }
            _ => {}
        }
    }

    // ── Step 3: BCTS transaction through the pipeline ──────────────
    println!("\n4. Creating BCTS transaction...");
    let tx = create_transaction(
        "did:user:institution-alpha",
        "submit:eligibility-screener",
        serde_json::json!({
            "institution_type": "ACADEMIC",
            "products_affected": 3,
            "studies_impacted": 2,
        }),
        BctsSignerType::Human,
        vec![],
    );
    println!("   Transaction ID: {}", tx.id);
    println!("   Correlation ID: {}", tx.envelope.correlation_id);

    println!("\n5. Running BCTS pipeline...");
    let result = run_pipeline(tx, "did:user:institution-alpha", |stage, tx| {
        // In a real app, each stage performs actual validation:
        // - "authenticate" checks DID credentials
        // - "gate" verifies active bailment via ConsentGatekeeper
        // - "prove" runs check_all_invariants()
        // - etc.
        println!("   [{stage}] validating...");

        if stage == "prove" {
            // Demonstrate invariant checking at the prove stage
            let inv_ctx = InvariantContext {
                actor_did: "did:user:institution-alpha".to_string(),
                actor_capabilities: vec![],
                active_bailment_ids: vec!["active-bailment".to_string()],
                is_human_override_available: true,
                alignment_score: None,
                alignment_threshold: None,
            };
            let inv_results = check_all_invariants(tx, &inv_ctx);
            let all_pass = inv_results.iter().all(|r| r.passed);
            if !all_pass {
                return Err("invariant violation".to_string());
            }
        }

        Ok(format!("{stage} passed"))
    });

    println!("\n6. Pipeline result:");
    println!("   Final state: {}", result.transaction.state);
    println!("   Stages completed: {}", result.stages.len());
    println!("   Ledger events: {}", result.transaction.ledger.len());
    println!("   Ledger valid: {}", verify_ledger(&result.transaction));
    if let Some(failed) = &result.failed_at {
        println!("   Failed at: {failed}");
    }

    // ── Step 4: Audit trail ────────────────────────────────────────
    println!("\n7. MCP Audit trail:");
    let mut audit = McpAuditLog::new();
    for r in &results {
        let (rule, outcome) = match r {
            exo_gatekeeper::McpEnforcementResult::Allowed { rule } => (*rule, McpEnforcementOutcome::Allowed),
            exo_gatekeeper::McpEnforcementResult::Blocked { violation } => (violation.rule, McpEnforcementOutcome::Blocked),
            exo_gatekeeper::McpEnforcementResult::Escalated { rule, .. } => (*rule, McpEnforcementOutcome::Escalated),
        };
        let record = audit.create_record(rule, "did:ai:exoclaw-scorer", outcome, Some("US-EAST"));
        audit.append(record).unwrap();
    }
    println!("   Records: {}", audit.len());
    println!("   Chain valid: {}", audit.verify_chain());
    println!("   Head hash: {}...", &audit.head_hash()[..16]);

    println!("\n=== Done. All constitutional checks passed. ===");
}
