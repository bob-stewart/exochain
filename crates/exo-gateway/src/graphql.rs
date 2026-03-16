//! GraphQL schema for governance operations.
//!
//! Defines queries, mutations, and subscriptions for the decision.forum API.

use serde::{Deserialize, Serialize};

/// GraphQL query operations.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum GovQuery {
    /// Get a decision by ID.
    Decision { id: String },
    /// List decisions with optional filters.
    Decisions {
        tenant_id: String,
        status: Option<String>,
        limit: Option<u32>,
        offset: Option<u32>,
    },
    /// Get the authority chain for an actor.
    AuthorityChain { actor_did: String },
    /// Get the constitution for a tenant at a specific version.
    Constitution {
        tenant_id: String,
        version: Option<String>,
    },
    /// List delegations for an actor.
    Delegations { actor_did: String },
    /// Get audit trail for a decision.
    AuditTrail { decision_id: String },
    /// Verify a proof.
    VerifyProof { proof_id: String },
}

/// GraphQL mutation operations.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum GovMutation {
    /// Create a new decision.
    CreateDecision {
        tenant_id: String,
        title: String,
        body: String,
        decision_class: String,
    },
    /// Advance a decision to a new status.
    AdvanceDecision {
        decision_id: String,
        new_status: String,
        reason: Option<String>,
    },
    /// Cast a vote on a decision.
    CastVote {
        decision_id: String,
        choice: String,
        rationale: Option<String>,
    },
    /// Grant a delegation.
    GrantDelegation {
        delegatee_did: String,
        scope: String,
        expires_in_hours: u32,
    },
    /// Revoke a delegation.
    RevokeDelegation { delegation_id: String },
    /// Raise a challenge against a decision.
    RaiseChallenge {
        decision_id: String,
        grounds: String,
    },
    /// Take an emergency action.
    TakeEmergencyAction {
        decision_id: String,
        justification: String,
    },
    /// Disclose a conflict of interest.
    DiscloseConflict {
        decision_id: String,
        description: String,
        nature: String,
    },
    /// Amend the constitution.
    AmendConstitution {
        tenant_id: String,
        amendment: String,
    },
}

/// GraphQL subscription events.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum GovSubscription {
    /// Decision status updates.
    DecisionUpdated { decision_id: String },
    /// Delegation approaching expiry.
    DelegationExpiring { actor_did: String },
    /// Emergency action notifications.
    EmergencyAction { tenant_id: String },
}

/// GraphQL schema definition.
pub struct GovSchema;

impl GovSchema {
    /// Get the SDL (Schema Definition Language) for the governance API,
    /// including LiveSafe extensions.
    pub fn sdl() -> &'static str {
        r#"
type Query {
    decision(id: ID!): Decision
    decisions(tenantId: ID!, status: String, limit: Int, offset: Int): [Decision!]!
    authorityChain(actorDid: String!): AuthorityChain
    constitution(tenantId: ID!, version: String): Constitution
    delegations(actorDid: String!): [Delegation!]!
    auditTrail(decisionId: ID!): [AuditEntry!]!
    verifyProof(proofId: ID!): VerificationResult
}

type Mutation {
    createDecision(input: CreateDecisionInput!): Decision!
    advanceDecision(id: ID!, newStatus: String!, reason: String): Decision!
    castVote(decisionId: ID!, choice: VoteChoice!, rationale: String): Vote!
    grantDelegation(input: GrantDelegationInput!): Delegation!
    revokeDelegation(id: ID!): Delegation!
    raiseChallenge(decisionId: ID!, grounds: String!): Challenge!
    takeEmergencyAction(decisionId: ID!, justification: String!): EmergencyAction!
    discloseConflict(decisionId: ID!, description: String!, nature: String!): ConflictDisclosure!
    amendConstitution(tenantId: ID!, amendment: String!): Constitution!
}

type Subscription {
    decisionUpdated(decisionId: ID!): Decision!
    delegationExpiring(actorDid: String!): Delegation!
    emergencyAction(tenantId: ID!): EmergencyAction!
}

type Decision {
    id: ID!
    tenantId: ID!
    status: DecisionStatus!
    title: String!
    decisionClass: String!
    author: String!
    createdAt: DateTime!
    votes: [Vote!]!
    challenges: [Challenge!]!
}

enum DecisionStatus {
    CREATED
    DELIBERATION
    VOTING
    APPROVED
    REJECTED
    VOID
    CONTESTED
    RATIFICATION_REQUIRED
    RATIFICATION_EXPIRED
    DEGRADED_GOVERNANCE
}

enum VoteChoice {
    APPROVE
    REJECT
    ABSTAIN
}

type Vote {
    voter: String!
    choice: VoteChoice!
    rationale: String
    timestamp: DateTime!
}

type Delegation {
    id: ID!
    delegator: String!
    delegatee: String!
    expiresAt: DateTime!
    active: Boolean!
}

type Constitution {
    tenantId: ID!
    version: String!
    hash: String!
}

type Challenge {
    id: ID!
    grounds: String!
    status: String!
}

type EmergencyAction {
    id: ID!
    decisionId: ID!
    ratificationDeadline: DateTime!
}

type ConflictDisclosure {
    discloser: String!
    description: String!
    nature: String!
}

type AuthorityChain {
    actorDid: String!
    chainLength: Int!
    valid: Boolean!
}

type AuditEntry {
    sequence: Int!
    eventType: String!
    actor: String!
    timestamp: DateTime!
}

type VerificationResult {
    proofType: String!
    valid: Boolean!
    message: String!
}

input CreateDecisionInput {
    tenantId: ID!
    title: String!
    body: String!
    decisionClass: String!
}

input GrantDelegationInput {
    delegateeDid: String!
    scope: String!
    expiresInHours: Int!
}

scalar DateTime
"#
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_schema_sdl_not_empty() {
        let sdl = GovSchema::sdl();
        assert!(!sdl.is_empty());
        assert!(sdl.contains("type Query"));
        assert!(sdl.contains("type Mutation"));
        assert!(sdl.contains("type Subscription"));
        assert!(sdl.contains("createDecision"));
        assert!(sdl.contains("castVote"));
    }

    #[test]
    fn test_query_variants() {
        let q = GovQuery::Decision { id: "abc".into() };
        assert!(matches!(q, GovQuery::Decision { .. }));
    }

    #[test]
    fn test_mutation_variants() {
        let m = GovMutation::CreateDecision {
            tenant_id: "t1".into(),
            title: "Test".into(),
            body: "body".into(),
            decision_class: "Operational".into(),
        };
        assert!(matches!(m, GovMutation::CreateDecision { .. }));
    }
}
