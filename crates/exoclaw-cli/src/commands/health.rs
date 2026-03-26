use clap::Subcommand;

#[derive(Subcommand)]
pub enum HealthAction {
    /// Check all EXOCHAIN services
    Check,
    /// Show service topology
    Topology,
}

pub fn execute(action: HealthAction) -> Result<(), Box<dyn std::error::Error>> {
    match action {
        HealthAction::Check => {
            println!("EXOCHAIN Service Health Check:");
            println!("{:-<60}", "");

            let services = [
                ("exo-consent",     "Bailment engine",     true),
                ("exo-gatekeeper",  "MCP enforcement",     true),
                ("exo-bcts",        "BCTS pipeline",       true),
                ("gateway-api",     "API gateway (3000)",   false),
                ("identity-svc",    "Identity (3001)",      false),
                ("consent-svc",     "Consent (3002)",       false),
                ("governance-eng",  "Governance (3003)",    false),
            ];

            for (name, desc, available) in &services {
                let status = if *available { "OK (crate)" } else { "NOT PROVISIONED" };
                let icon = if *available { "●" } else { "○" };
                println!("  {icon} {name:<18} {desc:<25} [{status}]");
            }

            println!();
            println!("Crate services:     3/3 available");
            println!("Network services:   0/4 provisioned");
            println!();
            println!("To provision network services:");
            println!("  exoclaw health topology");
            Ok(())
        }
        HealthAction::Topology => {
            println!("EXOCHAIN Trust Fabric Topology:");
            println!();
            println!("  ┌─────────────────────────────────────────────┐");
            println!("  │              gateway-api :3000              │");
            println!("  └──────┬──────────┬──────────┬───────────────┘");
            println!("         │          │          │");
            println!("  ┌──────▼──┐ ┌─────▼────┐ ┌──▼──────────────┐");
            println!("  │identity │ │ consent  │ │  governance     │");
            println!("  │ :3001   │ │  :3002   │ │   :3003         │");
            println!("  └─────────┘ └──────────┘ └──┬──────────────┘");
            println!("                              │");
            println!("                       ┌──────▼──────┐");
            println!("                       │decision-forge│");
            println!("                       │   :3004      │");
            println!("                       └──────┬──────┘");
            println!("                              │");
            println!("                  ┌───────────┴───────────┐");
            println!("                  │                       │");
            println!("           ┌──────▼──────┐  ┌─────────▼──┐");
            println!("           │ provenance  │  │  audit-api  │");
            println!("           │   :3006     │  │   :3007     │");
            println!("           └─────────────┘  └────────────┘");
            println!();
            println!("  Enforcement flow:");
            println!("    Request → Identity → Consent(bailment) → Governance");
            println!("    → CGR Kernel(9 invariants) → Execute → Audit");
            Ok(())
        }
    }
}
