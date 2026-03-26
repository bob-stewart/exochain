//! # exoclaw
//!
//! CLI for the EXOCHAIN constitutional trust fabric.
//!
//! Provides commands for managing bailment contracts, MCP enforcement,
//! BCTS pipeline operations, and service health checks.
//!
//! ## Usage
//!
//! ```text
//! exoclaw bailment propose --bailor did:user:alice --bailee did:org:corp --type processing --terms "data access"
//! exoclaw bailment info
//! exoclaw mcp enforce --actor did:ai:agent --scope litigation
//! exoclaw mcp rules
//! exoclaw bcts demo
//! exoclaw bcts pipeline
//! exoclaw bcts states
//! exoclaw health check
//! exoclaw health topology
//! ```

mod commands;

use clap::Parser;
use commands::{Cli, execute};

fn main() {
    let cli = Cli::parse();
    if let Err(e) = execute(cli) {
        eprintln!("error: {e}");
        std::process::exit(1);
    }
}
