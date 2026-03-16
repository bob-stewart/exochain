//! exo-escalation: Operational nervous system for EXOCHAIN governance.
//!
//! Detects adverse events, flags outliers, manages triage queues,
//! and provides kanban-style control for human-in-the-loop governance.

pub mod detector;
pub mod triage;
pub mod kanban;
pub mod escalation;
pub mod feedback;
pub mod completeness;

pub use detector::{AdverseEventDetector, EventSeverity, DetectionRule, AnomalyType};
pub use triage::{TriageQueue, TriageItem, TriagePriority, TriageStatus};
pub use kanban::{KanbanBoard, KanbanColumn, KanbanCard, CardTag};
pub use escalation::{EscalationPolicy, EscalationLevel, EscalationAction, EscalationChain};
pub use feedback::{FeedbackLoop, FeedbackEntry, FeedbackType};
pub use completeness::{
    ProtocolDomainId, SubsystemId, SubsystemAssessment, GapItem, EffortEstimate,
    generate_platform_assessment, generate_completeness_cards,
    populate_board, completeness_summary,
};
