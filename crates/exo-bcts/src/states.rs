//! BCTS transaction state machine — 14 states with deterministic transitions.
//!
//! Terminal states ([`BctsState::Closed`], [`BctsState::Denied`]) are immutable —
//! no transition can ever modify them (except `Denied → Remediated` for resubmission).

use serde::{Deserialize, Serialize};

/// The 14 BCTS transaction states
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BctsState {
    Draft,
    Submitted,
    IdentityResolved,
    ConsentValidated,
    Deliberated,
    Verified,
    Governed,
    Approved,
    Executed,
    Recorded,
    Closed,
    Denied,
    Escalated,
    Remediated,
}

impl std::fmt::Display for BctsState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Draft => write!(f, "Draft"),
            Self::Submitted => write!(f, "Submitted"),
            Self::IdentityResolved => write!(f, "Identity Resolved"),
            Self::ConsentValidated => write!(f, "Consent Validated"),
            Self::Deliberated => write!(f, "Deliberated"),
            Self::Verified => write!(f, "Verified"),
            Self::Governed => write!(f, "Governed"),
            Self::Approved => write!(f, "Approved"),
            Self::Executed => write!(f, "Executed"),
            Self::Recorded => write!(f, "Recorded"),
            Self::Closed => write!(f, "Closed"),
            Self::Denied => write!(f, "Denied"),
            Self::Escalated => write!(f, "Escalated"),
            Self::Remediated => write!(f, "Remediated"),
        }
    }
}

/// Terminal states — no further transitions
pub const TERMINAL_STATES: &[BctsState] = &[BctsState::Closed, BctsState::Denied];

/// Valid state transitions
pub fn valid_transitions(from: BctsState) -> &'static [BctsState] {
    match from {
        BctsState::Draft => &[BctsState::Submitted],
        BctsState::Submitted => &[BctsState::IdentityResolved, BctsState::Denied],
        BctsState::IdentityResolved => &[BctsState::ConsentValidated, BctsState::Denied],
        BctsState::ConsentValidated => &[BctsState::Deliberated, BctsState::Denied, BctsState::Escalated],
        BctsState::Deliberated => &[BctsState::Verified, BctsState::Denied, BctsState::Escalated],
        BctsState::Verified => &[BctsState::Governed, BctsState::Denied],
        BctsState::Governed => &[BctsState::Approved, BctsState::Denied, BctsState::Escalated],
        BctsState::Approved => &[BctsState::Executed, BctsState::Denied],
        BctsState::Executed => &[BctsState::Recorded],
        BctsState::Recorded => &[BctsState::Closed],
        BctsState::Closed => &[],
        BctsState::Denied => &[BctsState::Remediated],
        BctsState::Escalated => &[BctsState::Deliberated, BctsState::Denied],
        BctsState::Remediated => &[BctsState::Submitted],
    }
}

pub fn can_transition(from: BctsState, to: BctsState) -> bool {
    valid_transitions(from).contains(&to)
}

pub fn is_terminal(state: BctsState) -> bool {
    TERMINAL_STATES.contains(&state)
}

/// Human-readable descriptions for onboarding UI
pub fn state_description(state: BctsState) -> &'static str {
    match state {
        BctsState::Draft => "Transaction created but not yet submitted for processing",
        BctsState::Submitted => "Transaction submitted and awaiting identity verification",
        BctsState::IdentityResolved => "Actor identity verified via DID/credential check",
        BctsState::ConsentValidated => "Active bailment confirmed — consent boundaries verified",
        BctsState::Deliberated => "Governance deliberation complete — quorum reached",
        BctsState::Verified => "Constitutional invariants verified by CGR kernel",
        BctsState::Governed => "Governance rules applied — compliance confirmed",
        BctsState::Approved => "Transaction approved for execution",
        BctsState::Executed => "Transaction executed — state change applied",
        BctsState::Recorded => "Transaction recorded in append-only audit ledger",
        BctsState::Closed => "Transaction finalized — immutable",
        BctsState::Denied => "Transaction denied — violation evidence recorded",
        BctsState::Escalated => "Transaction escalated for human review",
        BctsState::Remediated => "Denial remediated — resubmission permitted",
    }
}

/// Maps BCTS states to the 7 pipeline stages for visualization
pub fn pipeline_stage(state: BctsState) -> Option<&'static str> {
    match state {
        BctsState::Draft | BctsState::Submitted => Some("propose"),
        BctsState::IdentityResolved => Some("authenticate"),
        BctsState::ConsentValidated | BctsState::Deliberated => Some("gate"),
        BctsState::Verified | BctsState::Governed => Some("prove"),
        BctsState::Approved => Some("commit"),
        BctsState::Executed => Some("anchor"),
        BctsState::Recorded | BctsState::Closed => Some("audit"),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_valid_transitions() {
        assert!(can_transition(BctsState::Draft, BctsState::Submitted));
        assert!(!can_transition(BctsState::Draft, BctsState::Closed));
        assert!(!can_transition(BctsState::Closed, BctsState::Draft));
    }

    #[test]
    fn test_terminal_states() {
        assert!(is_terminal(BctsState::Closed));
        assert!(is_terminal(BctsState::Denied));
        assert!(!is_terminal(BctsState::Draft));
    }

    #[test]
    fn test_denied_can_remediate() {
        assert!(can_transition(BctsState::Denied, BctsState::Remediated));
        assert!(can_transition(BctsState::Remediated, BctsState::Submitted));
    }
}
