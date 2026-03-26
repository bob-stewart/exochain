pub mod bailment;
pub mod bcts;
pub mod health;
pub mod mcp;

use clap::{Parser, Subcommand};

/// exoclaw — EXOCHAIN constitutional trust fabric CLI
#[derive(Parser)]
#[command(name = "exoclaw", version, about = "EXOCHAIN constitutional trust fabric management")]
pub struct Cli {
    #[command(subcommand)]
    pub command: Command,
}

#[derive(Subcommand)]
pub enum Command {
    /// Manage bailment contracts (propose, accept, suspend, terminate, list)
    Bailment {
        #[command(subcommand)]
        action: bailment::BailmentAction,
    },
    /// MCP enforcement operations (enforce, audit, rules)
    Mcp {
        #[command(subcommand)]
        action: mcp::McpAction,
    },
    /// BCTS pipeline operations (create, transition, verify, run)
    Bcts {
        #[command(subcommand)]
        action: bcts::BctsAction,
    },
    /// Service health checks
    Health {
        #[command(subcommand)]
        action: health::HealthAction,
    },
}

pub fn execute(cli: Cli) -> Result<(), Box<dyn std::error::Error>> {
    match cli.command {
        Command::Bailment { action } => bailment::execute(action),
        Command::Mcp { action } => mcp::execute(action),
        Command::Bcts { action } => bcts::execute(action),
        Command::Health { action } => health::execute(action),
    }
}
