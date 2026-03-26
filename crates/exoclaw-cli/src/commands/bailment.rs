use clap::Subcommand;
use exo_consent::{propose, accept, BailmentType};

#[derive(Subcommand)]
pub enum BailmentAction {
    /// Propose a new bailment contract
    Propose {
        /// Bailor DID (data subject)
        #[arg(long)]
        bailor: String,
        /// Bailee DID (receiving party)
        #[arg(long)]
        bailee: String,
        /// Bailment type: custody, processing, delegation, emergency
        #[arg(long, value_parser = parse_bailment_type)]
        r#type: BailmentType,
        /// Terms text (will be hashed)
        #[arg(long)]
        terms: String,
    },
    /// Accept a proposed bailment with signature
    Accept {
        /// Bailment ID
        #[arg(long)]
        id: String,
        /// Bailee signature
        #[arg(long)]
        signature: String,
    },
    /// Show all bailment types and lifecycle states
    Info,
}

fn parse_bailment_type(s: &str) -> Result<BailmentType, String> {
    match s.to_lowercase().as_str() {
        "custody" => Ok(BailmentType::Custody),
        "processing" => Ok(BailmentType::Processing),
        "delegation" => Ok(BailmentType::Delegation),
        "emergency" => Ok(BailmentType::Emergency),
        _ => Err(format!("unknown bailment type: {s}. Use: custody, processing, delegation, emergency")),
    }
}

pub fn execute(action: BailmentAction) -> Result<(), Box<dyn std::error::Error>> {
    match action {
        BailmentAction::Propose { bailor, bailee, r#type, terms } => {
            let bailment = propose(&bailor, &bailee, r#type, &terms, None);
            println!("Bailment proposed:");
            println!("  ID:          {}", bailment.id);
            println!("  Bailor:      {}", bailment.bailor_did);
            println!("  Bailee:      {}", bailment.bailee_did);
            println!("  Type:        {:?}", bailment.bailment_type);
            println!("  Terms hash:  {}", bailment.terms_hash);
            println!("  Status:      {}", bailment.status);
            println!("  Created:     {}", bailment.created_at);
            println!();
            println!("Next: exoclaw bailment accept --id {} --signature <sig>", bailment.id);
            Ok(())
        }
        BailmentAction::Accept { id: _, signature } => {
            // In a real system this would load from storage; demo creates a fresh one
            let demo = propose("did:demo:bailor", "did:demo:bailee", BailmentType::Processing, "demo terms", None);
            match accept(&demo, &signature) {
                Ok(active) => {
                    println!("Bailment accepted:");
                    println!("  ID:          {}", active.id);
                    println!("  Status:      {}", active.status);
                    println!("  Signature:   {}", active.bailee_signature.as_deref().unwrap_or(""));
                }
                Err(e) => {
                    eprintln!("Failed to accept bailment: {e}");
                }
            }
            Ok(())
        }
        BailmentAction::Info => {
            println!("EXOCHAIN Bailment Types:");
            println!("  custody     — Data held without processing rights");
            println!("  processing  — Data may be processed under defined terms");
            println!("  delegation  — Authority delegated to sub-bailees");
            println!("  emergency   — Time-limited access requiring justification");
            println!();
            println!("Bailment Lifecycle:");
            println!("  Proposed → Active → Suspended/Terminated/Expired");
            println!();
            println!("Constitutional Rule:");
            println!("  INV-003: Consent Precedes Access");
            println!("  No action may proceed without an active bailment.");
            Ok(())
        }
    }
}
