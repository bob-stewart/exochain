//! Feedback Loop — collects and manages feedback for governance improvements.

use serde::{Deserialize, Serialize};

/// Types of feedback that can be submitted.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum FeedbackType {
    Question,
    Suggestion,
    BugReport,
    EscalationReview,
    PolicyProposal,
    ContextUpdate,
}

/// Status of a feedback entry.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum FeedbackStatus {
    Open,
    InReview,
    Accepted,
    Rejected,
    Implemented,
}

/// A single feedback entry.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct FeedbackEntry {
    pub id: String,
    pub feedback_type: FeedbackType,
    pub author_did: String,
    pub title: String,
    pub body: String,
    pub tags: Vec<String>,
    pub related_decision_id: Option<String>,
    pub related_triage_id: Option<String>,
    pub created_at_ms: u64,
    pub status: FeedbackStatus,
    pub rejection_reason: Option<String>,
}

/// Manages a collection of feedback entries.
#[derive(Clone, Debug, Default)]
pub struct FeedbackLoop {
    pub entries: Vec<FeedbackEntry>,
}

impl FeedbackLoop {
    /// Creates a new empty feedback loop.
    pub fn new() -> Self {
        Self {
            entries: Vec::new(),
        }
    }

    /// Adds a feedback entry.
    pub fn add(&mut self, entry: FeedbackEntry) {
        self.entries.push(entry);
    }

    /// Filter entries by type.
    pub fn by_type(&self, ft: FeedbackType) -> Vec<&FeedbackEntry> {
        self.entries
            .iter()
            .filter(|e| e.feedback_type == ft)
            .collect()
    }

    /// Filter entries by status.
    pub fn by_status(&self, status: FeedbackStatus) -> Vec<&FeedbackEntry> {
        self.entries.iter().filter(|e| e.status == status).collect()
    }

    /// Count of open entries.
    pub fn open_count(&self) -> usize {
        self.entries
            .iter()
            .filter(|e| e.status == FeedbackStatus::Open)
            .count()
    }

    /// Accept a feedback entry.
    pub fn accept(&mut self, id: &str) -> bool {
        if let Some(entry) = self.entries.iter_mut().find(|e| e.id == id) {
            entry.status = FeedbackStatus::Accepted;
            return true;
        }
        false
    }

    /// Reject a feedback entry with a reason.
    pub fn reject(&mut self, id: &str, reason: &str) -> bool {
        if let Some(entry) = self.entries.iter_mut().find(|e| e.id == id) {
            entry.status = FeedbackStatus::Rejected;
            entry.rejection_reason = Some(reason.to_string());
            return true;
        }
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_entry(id: &str, ft: FeedbackType) -> FeedbackEntry {
        FeedbackEntry {
            id: id.to_string(),
            feedback_type: ft,
            author_did: "did:exo:tester".into(),
            title: format!("Feedback {}", id),
            body: "Test feedback body".into(),
            tags: vec![],
            related_decision_id: None,
            related_triage_id: None,
            created_at_ms: 1000,
            status: FeedbackStatus::Open,
            rejection_reason: None,
        }
    }

    #[test]
    fn test_add_and_open_count() {
        let mut fl = FeedbackLoop::new();
        fl.add(make_entry("f1", FeedbackType::Question));
        fl.add(make_entry("f2", FeedbackType::Suggestion));
        assert_eq!(fl.open_count(), 2);
    }

    #[test]
    fn test_by_type() {
        let mut fl = FeedbackLoop::new();
        fl.add(make_entry("f1", FeedbackType::BugReport));
        fl.add(make_entry("f2", FeedbackType::Suggestion));
        fl.add(make_entry("f3", FeedbackType::BugReport));
        assert_eq!(fl.by_type(FeedbackType::BugReport).len(), 2);
        assert_eq!(fl.by_type(FeedbackType::Suggestion).len(), 1);
    }

    #[test]
    fn test_by_status() {
        let mut fl = FeedbackLoop::new();
        fl.add(make_entry("f1", FeedbackType::Question));
        fl.add(make_entry("f2", FeedbackType::Suggestion));
        fl.accept("f1");
        assert_eq!(fl.by_status(FeedbackStatus::Open).len(), 1);
        assert_eq!(fl.by_status(FeedbackStatus::Accepted).len(), 1);
    }

    #[test]
    fn test_accept() {
        let mut fl = FeedbackLoop::new();
        fl.add(make_entry("f1", FeedbackType::PolicyProposal));
        assert!(fl.accept("f1"));
        assert_eq!(fl.entries[0].status, FeedbackStatus::Accepted);
    }

    #[test]
    fn test_reject_with_reason() {
        let mut fl = FeedbackLoop::new();
        fl.add(make_entry("f1", FeedbackType::Question));
        assert!(fl.reject("f1", "Out of scope"));
        assert_eq!(fl.entries[0].status, FeedbackStatus::Rejected);
        assert_eq!(
            fl.entries[0].rejection_reason.as_deref(),
            Some("Out of scope")
        );
    }

    #[test]
    fn test_accept_nonexistent() {
        let mut fl = FeedbackLoop::new();
        assert!(!fl.accept("nope"));
    }

    #[test]
    fn test_reject_nonexistent() {
        let mut fl = FeedbackLoop::new();
        assert!(!fl.reject("nope", "reason"));
    }

    #[test]
    fn test_open_count_decreases_on_accept() {
        let mut fl = FeedbackLoop::new();
        fl.add(make_entry("f1", FeedbackType::Question));
        fl.add(make_entry("f2", FeedbackType::Suggestion));
        assert_eq!(fl.open_count(), 2);
        fl.accept("f1");
        assert_eq!(fl.open_count(), 1);
    }
}
