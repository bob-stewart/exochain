//! decision.forum Protocol Completeness Card Generator — auto-generates kanban
//! cards from the protocol domain gap analysis.  Each card maps to a
//! decision.forum protocol primitive or workflow, driving the five core
//! protocol objects (DecisionRecord, CrosscheckReport, CustodyEvent,
//! ClearanceCertificate, AnchorReceipt) and their supporting governance
//! layers to 100%.

use crate::kanban::{CardTag, KanbanBoard, KanbanCard};
use crate::triage::TriagePriority;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Identifies each protocol domain in decision.forum.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ProtocolDomainId {
    // ── Core Protocol Objects ──
    CrosscheckReport,
    CustodyChain,
    ClearanceCertificate,
    AnchorReceipt,
    DecisionRecord,
    // ── Supporting Governance Layers ──
    ConstitutionalCorpus,
    AuthorityDelegation,
    IdentitySovereignty,
    ChallengeProtocol,
    EmergencyGovernance,
    AuditIntegrity,
    GatewayApi,
    ZkProofLayer,
    LegalCompliance,
}

// Keep the old name as an alias for backward compatibility with existing tests
// that may reference it indirectly through re-exports.
pub type SubsystemId = ProtocolDomainId;

impl ProtocolDomainId {
    /// Returns all protocol domain variants.
    pub fn all() -> Vec<ProtocolDomainId> {
        vec![
            ProtocolDomainId::CrosscheckReport,
            ProtocolDomainId::CustodyChain,
            ProtocolDomainId::ClearanceCertificate,
            ProtocolDomainId::AnchorReceipt,
            ProtocolDomainId::DecisionRecord,
            ProtocolDomainId::ConstitutionalCorpus,
            ProtocolDomainId::AuthorityDelegation,
            ProtocolDomainId::IdentitySovereignty,
            ProtocolDomainId::ChallengeProtocol,
            ProtocolDomainId::EmergencyGovernance,
            ProtocolDomainId::AuditIntegrity,
            ProtocolDomainId::GatewayApi,
            ProtocolDomainId::ZkProofLayer,
            ProtocolDomainId::LegalCompliance,
        ]
    }

    /// Returns a short kebab-case slug for card IDs.
    pub fn slug(&self) -> &'static str {
        match self {
            ProtocolDomainId::CrosscheckReport => "crosscheck-report",
            ProtocolDomainId::CustodyChain => "custody-chain",
            ProtocolDomainId::ClearanceCertificate => "clearance-certificate",
            ProtocolDomainId::AnchorReceipt => "anchor-receipt",
            ProtocolDomainId::DecisionRecord => "decision-record",
            ProtocolDomainId::ConstitutionalCorpus => "constitutional-corpus",
            ProtocolDomainId::AuthorityDelegation => "authority-delegation",
            ProtocolDomainId::IdentitySovereignty => "identity-sovereignty",
            ProtocolDomainId::ChallengeProtocol => "challenge-protocol",
            ProtocolDomainId::EmergencyGovernance => "emergency-governance",
            ProtocolDomainId::AuditIntegrity => "audit-integrity",
            ProtocolDomainId::GatewayApi => "gateway-api",
            ProtocolDomainId::ZkProofLayer => "zk-proof-layer",
            ProtocolDomainId::LegalCompliance => "legal-compliance",
        }
    }

    /// Returns the decision.forum protocol object this domain implements.
    pub fn protocol_object(&self) -> &'static str {
        match self {
            ProtocolDomainId::CrosscheckReport => "CrosscheckReport",
            ProtocolDomainId::CustodyChain => "CustodyEvent",
            ProtocolDomainId::ClearanceCertificate => "ClearanceCertificate",
            ProtocolDomainId::AnchorReceipt => "AnchorReceipt",
            ProtocolDomainId::DecisionRecord => "DecisionRecord",
            ProtocolDomainId::ConstitutionalCorpus => "Constitution",
            ProtocolDomainId::AuthorityDelegation => "Delegation",
            ProtocolDomainId::IdentitySovereignty => "PACE + DID",
            ProtocolDomainId::ChallengeProtocol => "ChallengeObject",
            ProtocolDomainId::EmergencyGovernance => "EmergencyAction",
            ProtocolDomainId::AuditIntegrity => "AuditLog",
            ProtocolDomainId::GatewayApi => "exo-gateway",
            ProtocolDomainId::ZkProofLayer => "exo-proofs",
            ProtocolDomainId::LegalCompliance => "exo-legal",
        }
    }

    /// Whether this domain is a core protocol object (vs supporting layer).
    pub fn is_core_object(&self) -> bool {
        matches!(
            self,
            ProtocolDomainId::CrosscheckReport
                | ProtocolDomainId::CustodyChain
                | ProtocolDomainId::ClearanceCertificate
                | ProtocolDomainId::AnchorReceipt
                | ProtocolDomainId::DecisionRecord
        )
    }
}

/// Effort estimate for a gap item.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum EffortEstimate {
    /// Less than 1 day.
    Small,
    /// 1-3 days.
    Medium,
    /// 3-7 days.
    Large,
    /// More than 1 week.
    Epic,
}

impl EffortEstimate {
    /// Returns a human-readable label.
    pub fn label(&self) -> &'static str {
        match self {
            EffortEstimate::Small => "small",
            EffortEstimate::Medium => "medium",
            EffortEstimate::Large => "large",
            EffortEstimate::Epic => "epic",
        }
    }
}

/// A specific gap preventing a protocol domain from reaching 100%.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct GapItem {
    pub id: String,
    pub title: String,
    pub description: String,
    pub effort_estimate: EffortEstimate,
    pub priority: TriagePriority,
    pub tags: Vec<String>,
    pub blocks_production: bool,
}

/// Assessment of a single protocol domain's completeness.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SubsystemAssessment {
    pub id: ProtocolDomainId,
    pub name: String,
    pub current_score: u8,
    pub target_score: u8,
    pub gaps: Vec<GapItem>,
    pub assessed_at_ms: u64,
}

// ---------------------------------------------------------------------------
// Helper builders
// ---------------------------------------------------------------------------

fn gap(
    id: &str,
    title: &str,
    desc: &str,
    effort: EffortEstimate,
    priority: TriagePriority,
    tags: &[&str],
    blocks: bool,
) -> GapItem {
    GapItem {
        id: id.to_string(),
        title: title.to_string(),
        description: desc.to_string(),
        effort_estimate: effort,
        priority,
        tags: tags.iter().map(|s| s.to_string()).collect(),
        blocks_production: blocks,
    }
}

fn assessment(
    id: ProtocolDomainId,
    name: &str,
    score: u8,
    gaps: Vec<GapItem>,
) -> SubsystemAssessment {
    SubsystemAssessment {
        id,
        name: name.to_string(),
        current_score: score,
        target_score: 100,
        gaps,
        assessed_at_ms: 0,
    }
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Creates the current protocol domain assessment based on the latest review.
/// Every domain maps to a decision.forum protocol primitive or workflow.
pub fn generate_platform_assessment() -> Vec<SubsystemAssessment> {
    vec![
        // ── Core Protocol Objects ──

        // CrosscheckReport — 55%
        assessment(
            ProtocolDomainId::CrosscheckReport,
            "CrosscheckReport",
            55,
            vec![
                gap("xck-1", "crosschecked.ai provider adapter",
                    "Build ProviderAdapter normalizing OpenAI/Anthropic/Google/xAI panel responses into CrosscheckOpinion structs",
                    EffortEstimate::Epic, TriagePriority::Immediate, &["crosscheck", "integration", "plural-intelligence"], true),
                gap("xck-2", "Panel orchestration engine",
                    "Multi-model panel assembly, round-robin deliberation, synthesis, and Minority Report preservation",
                    EffortEstimate::Epic, TriagePriority::Urgent, &["crosscheck", "orchestration"], true),
                gap("xck-3", "zkML proof generation for AI provenance",
                    "Generate ZK proofs for model opinion provenance without revealing weights",
                    EffortEstimate::Large, TriagePriority::Standard, &["crosscheck", "zkml", "provenance"], false),
                gap("xck-4", "Provenance compliance verification",
                    "Enforce: synthetic voices MUST NOT be presented as distinct humans",
                    EffortEstimate::Medium, TriagePriority::Urgent, &["crosscheck", "compliance"], false),
                gap("xck-5", "Devil's Advocate adversarial sub-process",
                    "Adversarial challenge mode probing consensus for weaknesses",
                    EffortEstimate::Large, TriagePriority::Standard, &["crosscheck", "adversarial"], false),
            ],
        ),
        // AnchorReceipt — 60%
        assessment(
            ProtocolDomainId::AnchorReceipt,
            "AnchorReceipt",
            60,
            vec![
                gap("anc-1", "EXOCHAIN anchor provider integration",
                    "Wire AnchorReceipt to exo-dag append_event + EventInclusionProof",
                    EffortEstimate::Large, TriagePriority::Immediate, &["anchor", "exochain", "dag"], true),
                gap("anc-2", "Anchor verification with Merkle proofs",
                    "Full inclusion proof verification against DAG MMR/SMT state",
                    EffortEstimate::Large, TriagePriority::Urgent, &["anchor", "merkle", "verification"], true),
                gap("anc-3", "Third-party timestamp anchoring",
                    "RFC 3161 compatible timestamp service provider",
                    EffortEstimate::Medium, TriagePriority::Standard, &["anchor", "timestamp", "rfc3161"], false),
                gap("anc-4", "Anchor verification UI badges",
                    "Tamper-evident badges: Verified/Unverified/Failed with explainers (UX-002)",
                    EffortEstimate::Medium, TriagePriority::Standard, &["anchor", "frontend", "badges"], false),
                gap("anc-5", "Periodic re-verification daemon",
                    "Background re-verification on schedule with integrity failure alerts",
                    EffortEstimate::Medium, TriagePriority::Deferred, &["anchor", "daemon", "integrity"], false),
            ],
        ),
        // ClearanceCertificate — 65%
        assessment(
            ProtocolDomainId::ClearanceCertificate,
            "ClearanceCertificate",
            65,
            vec![
                gap("cc-1", "Clearance policy engine integration",
                    "Wire ClearancePolicy evaluation into decision lifecycle; auto-issue certificates",
                    EffortEstimate::Large, TriagePriority::Immediate, &["clearance", "policy", "engine"], true),
                gap("cc-2", "Weighted clearance mode",
                    "Role-weighted voting (stewards 2x) per policy definition",
                    EffortEstimate::Medium, TriagePriority::Standard, &["clearance", "quorum", "weights"], false),
                gap("cc-3", "Clearance certificate portability",
                    "Export as standalone verifiable JSON documents",
                    EffortEstimate::Medium, TriagePriority::Standard, &["clearance", "portability", "export"], false),
                gap("cc-4", "Named approver enforcement",
                    "Block clearance until specific DIDs have attested",
                    EffortEstimate::Medium, TriagePriority::Urgent, &["clearance", "approvers", "enforcement"], false),
            ],
        ),
        // CustodyChain — 70%
        assessment(
            ProtocolDomainId::CustodyChain,
            "CustodyChain",
            70,
            vec![
                gap("cust-1", "Custody chain API endpoints",
                    "GraphQL mutations for CustodyEvent append + chain queries",
                    EffortEstimate::Large, TriagePriority::Urgent, &["custody", "api", "graphql"], true),
                gap("cust-2", "Signature verification for custody events",
                    "Verify Ed25519 detached signatures via DID-resolved public keys",
                    EffortEstimate::Medium, TriagePriority::Urgent, &["custody", "crypto", "signatures"], false),
                gap("cust-3", "Real-time custody chain subscriptions",
                    "GraphQL subscriptions for live CustodyEvent stream",
                    EffortEstimate::Large, TriagePriority::Standard, &["custody", "realtime", "subscriptions"], false),
                gap("cust-4", "Custody chain visualization UI",
                    "Timeline/graph view of chain of responsibility per DecisionRecord",
                    EffortEstimate::Medium, TriagePriority::Standard, &["custody", "frontend", "visualization"], false),
            ],
        ),
        // DecisionRecord — 85%
        assessment(
            ProtocolDomainId::DecisionRecord,
            "DecisionRecord",
            85,
            vec![
                gap("dr-1", "Canonical hashing for record_hash",
                    "Deterministic canonical serialization per whitepaper §Normative for stable record_hash",
                    EffortEstimate::Large, TriagePriority::Urgent, &["decision", "hashing", "canonical"], true),
                gap("dr-2", "Decision lineage (supersedes chain)",
                    "supersedes/superseded_by linkage for decision versioning",
                    EffortEstimate::Medium, TriagePriority::Standard, &["decision", "lineage", "versioning"], false),
                gap("dr-3", "Decision lifecycle tracker UI",
                    "Visual status timeline with state transitions, actors, timestamps (UX-010)",
                    EffortEstimate::Medium, TriagePriority::Standard, &["decision", "frontend", "lifecycle"], false),
            ],
        ),

        // ── Supporting Governance Layers ──

        // IdentitySovereignty — 70%
        assessment(
            ProtocolDomainId::IdentitySovereignty,
            "Identity Sovereignty",
            70,
            vec![
                gap("id-1", "Wire PACE wizard to Shamir backend",
                    "Connect frontend wizard to exo-identity::shamir::ShamirScheme",
                    EffortEstimate::Large, TriagePriority::Urgent, &["identity", "pace", "shamir", "integration"], true),
                gap("id-2", "PACE contact management API",
                    "Backend API for contact CRUD, share distribution tracking",
                    EffortEstimate::Medium, TriagePriority::Urgent, &["identity", "pace", "api"], false),
                gap("id-3", "Key rotation with share re-distribution",
                    "Master key rotation generating new shares for contacts",
                    EffortEstimate::Large, TriagePriority::Standard, &["identity", "pace", "rotation"], false),
                gap("id-4", "Trust score from governance participation",
                    "Compute scores from custody chain participation, attestation reliability",
                    EffortEstimate::Large, TriagePriority::Deferred, &["identity", "trust", "scoring"], false),
            ],
        ),
        // ConstitutionalCorpus — 75%
        assessment(
            ProtocolDomainId::ConstitutionalCorpus,
            "Constitutional Corpus",
            75,
            vec![
                gap("con-1", "Constraint expression evaluator",
                    "Runtime evaluation engine for ConstraintExpressions (TNC-04)",
                    EffortEstimate::Large, TriagePriority::Urgent, &["constitution", "constraints", "engine"], false),
                gap("con-2", "Constitutional amendment workflow",
                    "Full amendment lifecycle: proposal, deliberation, quorum vote, version bump",
                    EffortEstimate::Large, TriagePriority::Standard, &["constitution", "amendment", "workflow"], false),
                gap("con-3", "Conflict resolution hierarchy",
                    "Articles > Bylaws > Resolutions > Charters > Policies (GOV-006)",
                    EffortEstimate::Medium, TriagePriority::Standard, &["constitution", "precedence", "hierarchy"], false),
                gap("con-4", "Constitutional constraint warnings UI",
                    "Real-time inline warnings during decision creation (UX-003)",
                    EffortEstimate::Medium, TriagePriority::Standard, &["constitution", "frontend", "warnings"], false),
            ],
        ),
        // GatewayApi — 75%
        assessment(
            ProtocolDomainId::GatewayApi,
            "Gateway API",
            75,
            vec![
                gap("gw-1", "CrosscheckReport GraphQL mutations",
                    "createCrosscheck, attachCrosscheckToDecision with panel orchestration",
                    EffortEstimate::Large, TriagePriority::Urgent, &["gateway", "graphql", "crosscheck"], false),
                gap("gw-2", "ClearanceCertificate issuance endpoint",
                    "evaluateClearance mutation running ClearancePolicy against CustodyChain",
                    EffortEstimate::Large, TriagePriority::Urgent, &["gateway", "graphql", "clearance"], false),
                gap("gw-3", "AnchorReceipt mutation + verification query",
                    "anchorDecision mutation and verifyAnchor query",
                    EffortEstimate::Medium, TriagePriority::Standard, &["gateway", "graphql", "anchor"], false),
                gap("gw-4", "Real-time GraphQL subscriptions",
                    "decisionUpdated, custodyEventAppended, clearanceIssued, anchorVerified",
                    EffortEstimate::Large, TriagePriority::Standard, &["gateway", "subscriptions", "realtime"], false),
            ],
        ),
        // ChallengeProtocol — 80%
        assessment(
            ProtocolDomainId::ChallengeProtocol,
            "Challenge Protocol",
            80,
            vec![
                gap("ch-1", "Challenge resolution as new DecisionRecord",
                    "Create new DecisionRecord with immutable REVERSAL linkage",
                    EffortEstimate::Large, TriagePriority::Standard, &["challenge", "reversal", "lifecycle"], false),
                gap("ch-2", "Contestation pause enforcement",
                    "CONTESTED status pauses all execution across API and UI",
                    EffortEstimate::Medium, TriagePriority::Standard, &["challenge", "enforcement", "pause"], false),
                gap("ch-3", "Challenge filing UI",
                    "Interface for filing challenges with grounds, evidence, linked decision",
                    EffortEstimate::Medium, TriagePriority::Deferred, &["challenge", "frontend"], false),
            ],
        ),
        // EmergencyGovernance — 80%
        assessment(
            ProtocolDomainId::EmergencyGovernance,
            "Emergency Governance",
            80,
            vec![
                gap("em-1", "Auto-create RATIFICATION_REQUIRED follow-up",
                    "Emergency action auto-generates ratification DecisionRecord (TNC-10)",
                    EffortEstimate::Large, TriagePriority::Standard, &["emergency", "ratification", "auto-create"], false),
                gap("em-2", "Emergency frequency monitoring",
                    "Track frequency; mandatory review if >3 per quarter",
                    EffortEstimate::Medium, TriagePriority::Standard, &["emergency", "monitoring", "frequency"], false),
                gap("em-3", "Succession protocol activation",
                    "Pre-defined succession with automatic activation triggers (GOV-011)",
                    EffortEstimate::Large, TriagePriority::Deferred, &["emergency", "succession"], false),
            ],
        ),
        // LegalCompliance — 80%
        assessment(
            ProtocolDomainId::LegalCompliance,
            "Legal Compliance",
            80,
            vec![
                gap("lc-1", "Self-authenticating business records",
                    "FRE 803(6) compliant records with third-party timestamp anchoring (LEG-001/002/003)",
                    EffortEstimate::Large, TriagePriority::Standard, &["legal", "fre803", "records"], false),
                gap("lc-2", "DGCL §144 safe-harbor automation",
                    "Wire conflict disclosure to DGCL §144 requirements (LEG-005/013)",
                    EffortEstimate::Medium, TriagePriority::Standard, &["legal", "dgcl", "conflict"], false),
                gap("lc-3", "Attorney-client privilege compartmentalization",
                    "Protect privileged communications from e-discovery (LEG-009)",
                    EffortEstimate::Large, TriagePriority::Deferred, &["legal", "privilege", "compartment"], false),
            ],
        ),
        // AuditIntegrity — 85%
        assessment(
            ProtocolDomainId::AuditIntegrity,
            "Audit Integrity",
            85,
            vec![
                gap("aud-1", "Hourly self-verification",
                    "Schedule hourly audit hash chain verification with escalation on failure (TNC-03)",
                    EffortEstimate::Medium, TriagePriority::Standard, &["audit", "self-verify", "integrity"], false),
                gap("aud-2", "E-discovery export workflow",
                    "Legally compliant export packages with chain-of-custody docs (LEG-010)",
                    EffortEstimate::Large, TriagePriority::Standard, &["audit", "ediscovery", "legal"], false),
                gap("aud-3", "Fiduciary defense package generation",
                    "Auto-generate duty-of-care evidence packages (LEG-012)",
                    EffortEstimate::Large, TriagePriority::Deferred, &["audit", "fiduciary", "legal"], false),
            ],
        ),
        // AuthorityDelegation — 90%
        assessment(
            ProtocolDomainId::AuthorityDelegation,
            "Authority Delegation",
            90,
            vec![
                gap("del-1", "Delegation expiry enforcement daemon",
                    "Background auto-revocation of expired delegations (TNC-05)",
                    EffortEstimate::Medium, TriagePriority::Standard, &["delegation", "expiry", "daemon"], false),
                gap("del-2", "AI delegation ceiling visualization",
                    "UI showing AI agent authority boundaries and ceiling enforcement (TNC-09)",
                    EffortEstimate::Medium, TriagePriority::Standard, &["delegation", "ai-ceiling", "frontend"], false),
            ],
        ),
        // ZkProofLayer — 50%
        assessment(
            ProtocolDomainId::ZkProofLayer,
            "ZK Proof Layer",
            50,
            vec![
                gap("zk-1", "Real zk-SNARK circuit integration",
                    "Replace proof stubs with Circom/Halo2 for authority chain and quorum proofs",
                    EffortEstimate::Epic, TriagePriority::Urgent, &["zk", "snark", "circuits"], true),
                gap("zk-2", "zk-STARK transparent governance proofs",
                    "Transparent proofs that constitutional constraints satisfied without revealing content",
                    EffortEstimate::Epic, TriagePriority::Standard, &["zk", "stark", "transparency"], false),
                gap("zk-3", "zkML proof integration with CrosscheckReport",
                    "Wire zkml_proof field to real zkML proof generation",
                    EffortEstimate::Large, TriagePriority::Standard, &["zk", "zkml", "crosscheck"], false),
                gap("zk-4", "Unified proof verifier",
                    "Single interface for SNARK, STARK, and zkML with batch verification",
                    EffortEstimate::Large, TriagePriority::Standard, &["zk", "verifier", "unified"], false),
                gap("zk-5", "Proof generation benchmarks",
                    "Target <100ms verify, <2s generate under load",
                    EffortEstimate::Medium, TriagePriority::Deferred, &["zk", "perf", "benchmarks"], false),
            ],
        ),
    ]
}

/// Converts all gap items from assessments into [`KanbanCard`]s.
///
/// Card ID format: `df-{domain_slug}-{gap_index}` (1-based index).
pub fn generate_completeness_cards(assessments: &[SubsystemAssessment]) -> Vec<KanbanCard> {
    let mut cards = Vec::new();

    for assess in assessments {
        let slug = assess.id.slug();
        for (i, gap_item) in assess.gaps.iter().enumerate() {
            let card_id = format!("df-{}-{}", slug, i + 1);

            // Build tags: protocol object + domain name + gap-specific tags + "decision.forum"
            let mut tag_labels: Vec<String> =
                vec![assess.id.protocol_object().to_lowercase().replace(' ', "-")];
            tag_labels.push(assess.name.to_lowercase().replace([' ', '/'], "-"));
            tag_labels.extend(gap_item.tags.clone());
            tag_labels.push("decision.forum".to_string());

            let tags: Vec<CardTag> = tag_labels
                .into_iter()
                .map(|label| CardTag {
                    label,
                    color: if assess.id.is_core_object() {
                        "violet".to_string()
                    } else {
                        "blue".to_string()
                    },
                })
                .collect();

            let mut metadata = HashMap::new();
            metadata.insert("domain".to_string(), assess.name.clone());
            metadata.insert(
                "protocol_object".to_string(),
                assess.id.protocol_object().to_string(),
            );
            metadata.insert("effort".to_string(), gap_item.effort_estimate.label().to_string());
            metadata.insert(
                "blocks_production".to_string(),
                gap_item.blocks_production.to_string(),
            );
            metadata.insert("current_score".to_string(), assess.current_score.to_string());
            metadata.insert(
                "is_core_object".to_string(),
                assess.id.is_core_object().to_string(),
            );

            cards.push(KanbanCard {
                id: card_id,
                title: gap_item.title.clone(),
                description: gap_item.description.clone(),
                tags,
                assignee: None,
                priority: gap_item.priority.clone(),
                created_at_ms: assess.assessed_at_ms,
                updated_at_ms: assess.assessed_at_ms,
                linked_decision_id: None,
                linked_triage_id: None,
                metadata,
            });
        }
    }

    cards
}

/// Populates a [`KanbanBoard`] with completeness cards.
///
/// - Cards that block production or have Immediate/Urgent priority go to "triage".
/// - Everything else goes to "backlog".
pub fn populate_board(board: &mut KanbanBoard, cards: Vec<KanbanCard>) {
    for card in cards {
        let blocks = card
            .metadata
            .get("blocks_production")
            .map(|v| v == "true")
            .unwrap_or(false);

        let high_priority = matches!(
            card.priority,
            TriagePriority::Immediate | TriagePriority::Urgent
        );

        let column = if blocks || high_priority {
            "triage"
        } else {
            "backlog"
        };

        // Ignore WIP errors — completeness cards may overflow the triage WIP limit,
        // which is acceptable during bulk population.
        let _ = board.add_card(column, card);
    }
}

/// Returns a formatted summary of all protocol domain assessments.
pub fn completeness_summary(assessments: &[SubsystemAssessment]) -> String {
    let mut lines = Vec::new();
    lines.push("=== decision.forum Protocol Completeness Summary ===".to_string());
    lines.push(String::new());

    let total_score: u32 = assessments.iter().map(|a| a.current_score as u32).sum();
    let count = assessments.len() as u32;
    let avg = if count > 0 { total_score / count } else { 0 };

    lines.push(format!(
        "Overall: {}% average across {} protocol domains",
        avg, count
    ));
    lines.push(String::new());

    // Core objects first, then layers, sorted by score ascending within each group
    let mut core: Vec<&SubsystemAssessment> = assessments
        .iter()
        .filter(|a| a.id.is_core_object())
        .collect();
    core.sort_by_key(|a| a.current_score);

    let mut layers: Vec<&SubsystemAssessment> = assessments
        .iter()
        .filter(|a| !a.id.is_core_object())
        .collect();
    layers.sort_by_key(|a| a.current_score);

    lines.push("── Core Protocol Objects ──".to_string());
    for assess in &core {
        let bar_filled = assess.current_score as usize / 5;
        let bar_empty = 20 - bar_filled;
        let bar = format!(
            "[{}{}]",
            "#".repeat(bar_filled),
            "-".repeat(bar_empty),
        );
        lines.push(format!(
            "  {:.<30} {:>3}% {} ({} gaps) [{}]",
            assess.name,
            assess.current_score,
            bar,
            assess.gaps.len(),
            assess.id.protocol_object(),
        ));
    }

    lines.push(String::new());
    lines.push("── Governance Layers ──".to_string());
    for assess in &layers {
        let bar_filled = assess.current_score as usize / 5;
        let bar_empty = 20 - bar_filled;
        let bar = format!(
            "[{}{}]",
            "#".repeat(bar_filled),
            "-".repeat(bar_empty),
        );
        lines.push(format!(
            "  {:.<30} {:>3}% {} ({} gaps) [{}]",
            assess.name,
            assess.current_score,
            bar,
            assess.gaps.len(),
            assess.id.protocol_object(),
        ));
    }

    let total_gaps: usize = assessments.iter().map(|a| a.gaps.len()).sum();
    let blocking: usize = assessments
        .iter()
        .flat_map(|a| &a.gaps)
        .filter(|g| g.blocks_production)
        .count();

    lines.push(String::new());
    lines.push(format!("Total gaps: {}", total_gaps));
    lines.push(format!("Blocking production: {}", blocking));

    lines.join("\n")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_assessment_covers_all_domains() {
        let assessments = generate_platform_assessment();
        let ids: Vec<&ProtocolDomainId> = assessments.iter().map(|a| &a.id).collect();
        for did in ProtocolDomainId::all() {
            assert!(ids.contains(&&did), "Missing domain: {:?}", did);
        }
    }

    #[test]
    fn test_all_domain_ids_represented() {
        let all = ProtocolDomainId::all();
        assert_eq!(all.len(), 14, "Expected 14 protocol domain variants");
    }

    #[test]
    fn test_core_objects_identified() {
        assert!(ProtocolDomainId::CrosscheckReport.is_core_object());
        assert!(ProtocolDomainId::CustodyChain.is_core_object());
        assert!(ProtocolDomainId::ClearanceCertificate.is_core_object());
        assert!(ProtocolDomainId::AnchorReceipt.is_core_object());
        assert!(ProtocolDomainId::DecisionRecord.is_core_object());
        assert!(!ProtocolDomainId::GatewayApi.is_core_object());
        assert!(!ProtocolDomainId::ZkProofLayer.is_core_object());
    }

    #[test]
    fn test_assessment_scores() {
        let assessments = generate_platform_assessment();
        let find = |id: &ProtocolDomainId| -> &SubsystemAssessment {
            assessments.iter().find(|a| &a.id == id).unwrap()
        };
        assert_eq!(find(&ProtocolDomainId::ZkProofLayer).current_score, 50);
        assert_eq!(find(&ProtocolDomainId::CrosscheckReport).current_score, 55);
        assert_eq!(find(&ProtocolDomainId::AnchorReceipt).current_score, 60);
        assert_eq!(find(&ProtocolDomainId::ClearanceCertificate).current_score, 65);
        assert_eq!(find(&ProtocolDomainId::CustodyChain).current_score, 70);
        assert_eq!(find(&ProtocolDomainId::IdentitySovereignty).current_score, 70);
        assert_eq!(find(&ProtocolDomainId::ConstitutionalCorpus).current_score, 75);
        assert_eq!(find(&ProtocolDomainId::GatewayApi).current_score, 75);
        assert_eq!(find(&ProtocolDomainId::DecisionRecord).current_score, 85);
        assert_eq!(find(&ProtocolDomainId::AuthorityDelegation).current_score, 90);
    }

    #[test]
    fn test_generate_cards_from_assessment() {
        let assessments = generate_platform_assessment();
        let cards = generate_completeness_cards(&assessments);
        let total_gaps: usize = assessments.iter().map(|a| a.gaps.len()).sum();
        assert_eq!(cards.len(), total_gaps);
    }

    #[test]
    fn test_card_id_format_uses_df_prefix() {
        let assessments = generate_platform_assessment();
        let cards = generate_completeness_cards(&assessments);
        for card in &cards {
            assert!(
                card.id.starts_with("df-"),
                "Card ID '{}' should start with 'df-' (decision.forum)",
                card.id
            );
        }
        // Check specific cards exist
        assert!(cards.iter().any(|c| c.id == "df-crosscheck-report-1"));
        assert!(cards.iter().any(|c| c.id == "df-custody-chain-1"));
        assert!(cards.iter().any(|c| c.id == "df-anchor-receipt-1"));
        assert!(cards.iter().any(|c| c.id == "df-decision-record-1"));
    }

    #[test]
    fn test_card_tagging() {
        let assessments = generate_platform_assessment();
        let cards = generate_completeness_cards(&assessments);
        for card in &cards {
            let labels: Vec<&str> = card.tags.iter().map(|t| t.label.as_str()).collect();
            assert!(
                labels.contains(&"decision.forum"),
                "Card '{}' missing 'decision.forum' tag",
                card.id
            );
        }
    }

    #[test]
    fn test_core_object_cards_tagged_violet() {
        let assessments = generate_platform_assessment();
        let cards = generate_completeness_cards(&assessments);
        let xck_card = cards.iter().find(|c| c.id == "df-crosscheck-report-1").unwrap();
        assert!(xck_card.tags.iter().all(|t| t.color == "violet"));
    }

    #[test]
    fn test_card_metadata_has_protocol_object() {
        let assessments = generate_platform_assessment();
        let cards = generate_completeness_cards(&assessments);
        let card = cards.iter().find(|c| c.id == "df-crosscheck-report-1").unwrap();
        assert_eq!(card.metadata.get("protocol_object").unwrap(), "CrosscheckReport");
        assert_eq!(card.metadata.get("domain").unwrap(), "CrosscheckReport");
        assert_eq!(card.metadata.get("is_core_object").unwrap(), "true");
    }

    #[test]
    fn test_blocking_cards_go_to_triage() {
        let assessments = generate_platform_assessment();
        let cards = generate_completeness_cards(&assessments);
        let mut board = KanbanBoard::governance_default();
        populate_board(&mut board, cards);

        let triage_cards = board.cards_in_column("triage");
        // CrosscheckReport provider adapter is blocking + immediate
        assert!(
            triage_cards.iter().any(|c| c.id == "df-crosscheck-report-1"),
            "Blocking card should be in triage"
        );
    }

    #[test]
    fn test_non_blocking_go_to_backlog() {
        let assessments = generate_platform_assessment();
        let cards = generate_completeness_cards(&assessments);
        let mut board = KanbanBoard::governance_default();
        populate_board(&mut board, cards);

        let backlog_cards = board.cards_in_column("backlog");
        // Authority delegation daemon is Standard, non-blocking -> backlog
        assert!(
            backlog_cards.iter().any(|c| c.id == "df-authority-delegation-1"),
            "Non-blocking standard card should be in backlog"
        );
    }

    #[test]
    fn test_completeness_summary_format() {
        let assessments = generate_platform_assessment();
        let summary = completeness_summary(&assessments);
        assert!(summary.contains("decision.forum Protocol Completeness Summary"));
        assert!(summary.contains("protocol domains"));
        assert!(summary.contains("Core Protocol Objects"));
        assert!(summary.contains("Governance Layers"));
        assert!(summary.contains("Total gaps:"));
        assert!(summary.contains("Blocking production:"));
        assert!(summary.contains("CrosscheckReport"));
        assert!(summary.contains("AnchorReceipt"));
    }

    #[test]
    fn test_completeness_summary_gap_count() {
        let assessments = generate_platform_assessment();
        let total_gaps: usize = assessments.iter().map(|a| a.gaps.len()).sum();
        let summary = completeness_summary(&assessments);
        assert!(summary.contains(&format!("Total gaps: {}", total_gaps)));
    }

    #[test]
    fn test_gap_descriptions_not_empty() {
        let assessments = generate_platform_assessment();
        for a in &assessments {
            for gap_item in &a.gaps {
                assert!(!gap_item.description.is_empty(), "Gap '{}' has empty description", gap_item.title);
                assert_ne!(gap_item.description, gap_item.title, "Gap '{}' should have distinct description", gap_item.title);
            }
        }
    }

    #[test]
    fn test_target_score_always_100() {
        let assessments = generate_platform_assessment();
        for a in &assessments {
            assert_eq!(a.target_score, 100, "{} target should be 100", a.name);
        }
    }

    #[test]
    fn test_domain_slug_unique() {
        let all = ProtocolDomainId::all();
        let slugs: Vec<&str> = all.iter().map(|s| s.slug()).collect();
        let mut deduped = slugs.clone();
        deduped.sort();
        deduped.dedup();
        assert_eq!(slugs.len(), deduped.len(), "Slugs must be unique");
    }

    #[test]
    fn test_populate_board_total_cards() {
        let assessments = generate_platform_assessment();
        let cards = generate_completeness_cards(&assessments);
        let expected = cards.len();
        let mut board = KanbanBoard::governance_default();
        populate_board(&mut board, cards);
        assert!(board.total_cards() > 0);
        assert!(board.total_cards() <= expected);
    }
}
