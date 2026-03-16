//! Triage Queue — prioritized queue for human review of flagged events.

use exo_core::crypto::Blake3Hash;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Priority levels for triage items, from highest to lowest.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum TriagePriority {
    Immediate,
    Urgent,
    Standard,
    Deferred,
    Backlog,
}

impl TriagePriority {
    /// Returns the next higher priority level, if one exists.
    pub fn bump(&self) -> Self {
        match self {
            TriagePriority::Backlog => TriagePriority::Deferred,
            TriagePriority::Deferred => TriagePriority::Standard,
            TriagePriority::Standard => TriagePriority::Urgent,
            TriagePriority::Urgent => TriagePriority::Immediate,
            TriagePriority::Immediate => TriagePriority::Immediate,
        }
    }
}

/// Status of a triage item.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum TriageStatus {
    New,
    Acknowledged,
    InProgress,
    Escalated,
    Resolved,
    Dismissed,
}

/// An item in the triage queue.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TriageItem {
    pub id: String,
    pub title: String,
    pub description: String,
    pub priority: TriagePriority,
    pub status: TriageStatus,
    pub source_event_id: Option<Blake3Hash>,
    pub assigned_to: Option<String>,
    pub tags: Vec<String>,
    pub created_at_ms: u64,
    pub updated_at_ms: u64,
    pub due_at_ms: Option<u64>,
    pub resolution_notes: Option<String>,
}

/// Summary statistics for the triage queue.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TriageStats {
    pub by_status: HashMap<String, usize>,
    pub by_priority: HashMap<String, usize>,
    pub total: usize,
}

/// A prioritized queue for human review of flagged events.
#[derive(Clone, Debug, Default)]
pub struct TriageQueue {
    pub items: Vec<TriageItem>,
}

impl TriageQueue {
    pub fn new() -> Self {
        Self { items: Vec::new() }
    }

    /// Adds an item, maintaining sort order by priority (highest first).
    pub fn add(&mut self, item: TriageItem) {
        let pos = self
            .items
            .iter()
            .position(|existing| existing.priority > item.priority)
            .unwrap_or(self.items.len());
        self.items.insert(pos, item);
    }

    /// Peek at the highest priority New item.
    pub fn next(&self) -> Option<&TriageItem> {
        self.items
            .iter()
            .find(|item| item.status == TriageStatus::New)
    }

    /// Transition a New item to Acknowledged.
    pub fn acknowledge(&mut self, id: &str) -> bool {
        if let Some(item) = self.items.iter_mut().find(|i| i.id == id) {
            if item.status == TriageStatus::New {
                item.status = TriageStatus::Acknowledged;
                return true;
            }
        }
        false
    }

    /// Assign an item to a person and set status to InProgress.
    pub fn assign(&mut self, id: &str, assignee: &str) -> bool {
        if let Some(item) = self.items.iter_mut().find(|i| i.id == id) {
            item.assigned_to = Some(assignee.to_string());
            item.status = TriageStatus::InProgress;
            return true;
        }
        false
    }

    /// Escalate an item: status -> Escalated, bump priority one level.
    pub fn escalate(&mut self, id: &str) -> bool {
        if let Some(item) = self.items.iter_mut().find(|i| i.id == id) {
            item.status = TriageStatus::Escalated;
            item.priority = item.priority.bump();
            return true;
        }
        false
    }

    /// Resolve an item with notes.
    pub fn resolve(&mut self, id: &str, notes: &str) -> bool {
        if let Some(item) = self.items.iter_mut().find(|i| i.id == id) {
            item.status = TriageStatus::Resolved;
            item.resolution_notes = Some(notes.to_string());
            return true;
        }
        false
    }

    /// Dismiss an item with a reason.
    pub fn dismiss(&mut self, id: &str, reason: &str) -> bool {
        if let Some(item) = self.items.iter_mut().find(|i| i.id == id) {
            item.status = TriageStatus::Dismissed;
            item.resolution_notes = Some(reason.to_string());
            return true;
        }
        false
    }

    /// Filter items by status.
    pub fn by_status(&self, status: TriageStatus) -> Vec<&TriageItem> {
        self.items.iter().filter(|i| i.status == status).collect()
    }

    /// Filter items by priority.
    pub fn by_priority(&self, priority: TriagePriority) -> Vec<&TriageItem> {
        self.items.iter().filter(|i| i.priority == priority).collect()
    }

    /// Filter items by assignee.
    pub fn by_assignee(&self, assignee: &str) -> Vec<&TriageItem> {
        self.items
            .iter()
            .filter(|i| i.assigned_to.as_deref() == Some(assignee))
            .collect()
    }

    /// Returns items that are past their due date.
    pub fn overdue(&self, now_ms: u64) -> Vec<&TriageItem> {
        self.items
            .iter()
            .filter(|i| {
                i.due_at_ms.is_some_and(|due| due < now_ms)
                    && i.status != TriageStatus::Resolved
                    && i.status != TriageStatus::Dismissed
            })
            .collect()
    }

    /// Number of items in the queue.
    pub fn len(&self) -> usize {
        self.items.len()
    }

    /// Whether the queue is empty.
    pub fn is_empty(&self) -> bool {
        self.items.is_empty()
    }

    /// Returns summary statistics.
    pub fn stats(&self) -> TriageStats {
        let mut by_status: HashMap<String, usize> = HashMap::new();
        let mut by_priority: HashMap<String, usize> = HashMap::new();

        for item in &self.items {
            *by_status.entry(format!("{:?}", item.status)).or_default() += 1;
            *by_priority
                .entry(format!("{:?}", item.priority))
                .or_default() += 1;
        }

        TriageStats {
            by_status,
            by_priority,
            total: self.items.len(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_item(id: &str, priority: TriagePriority) -> TriageItem {
        TriageItem {
            id: id.to_string(),
            title: format!("Item {}", id),
            description: "Test item".into(),
            priority,
            status: TriageStatus::New,
            source_event_id: None,
            assigned_to: None,
            tags: vec![],
            created_at_ms: 1000,
            updated_at_ms: 1000,
            due_at_ms: None,
            resolution_notes: None,
        }
    }

    #[test]
    fn test_add_and_len() {
        let mut q = TriageQueue::new();
        q.add(make_item("t1", TriagePriority::Standard));
        q.add(make_item("t2", TriagePriority::Urgent));
        assert_eq!(q.len(), 2);
    }

    #[test]
    fn test_priority_ordering() {
        let mut q = TriageQueue::new();
        q.add(make_item("low", TriagePriority::Backlog));
        q.add(make_item("high", TriagePriority::Immediate));
        q.add(make_item("mid", TriagePriority::Standard));
        // Highest priority first
        assert_eq!(q.items[0].id, "high");
    }

    #[test]
    fn test_next_returns_highest_new() {
        let mut q = TriageQueue::new();
        q.add(make_item("t1", TriagePriority::Immediate));
        q.add(make_item("t2", TriagePriority::Standard));
        let next = q.next().unwrap();
        assert_eq!(next.id, "t1");
    }

    #[test]
    fn test_acknowledge() {
        let mut q = TriageQueue::new();
        q.add(make_item("t1", TriagePriority::Standard));
        assert!(q.acknowledge("t1"));
        assert_eq!(q.items[0].status, TriageStatus::Acknowledged);
        // Can't acknowledge again
        assert!(!q.acknowledge("t1"));
    }

    #[test]
    fn test_assign() {
        let mut q = TriageQueue::new();
        q.add(make_item("t1", TriagePriority::Standard));
        assert!(q.assign("t1", "alice"));
        assert_eq!(q.items[0].assigned_to.as_deref(), Some("alice"));
        assert_eq!(q.items[0].status, TriageStatus::InProgress);
    }

    #[test]
    fn test_escalate_bumps_priority() {
        let mut q = TriageQueue::new();
        q.add(make_item("t1", TriagePriority::Standard));
        assert!(q.escalate("t1"));
        assert_eq!(q.items[0].status, TriageStatus::Escalated);
        assert_eq!(q.items[0].priority, TriagePriority::Urgent);
    }

    #[test]
    fn test_resolve_with_notes() {
        let mut q = TriageQueue::new();
        q.add(make_item("t1", TriagePriority::Standard));
        assert!(q.resolve("t1", "Fixed the issue"));
        assert_eq!(q.items[0].status, TriageStatus::Resolved);
        assert_eq!(
            q.items[0].resolution_notes.as_deref(),
            Some("Fixed the issue")
        );
    }

    #[test]
    fn test_dismiss() {
        let mut q = TriageQueue::new();
        q.add(make_item("t1", TriagePriority::Standard));
        assert!(q.dismiss("t1", "Not actionable"));
        assert_eq!(q.items[0].status, TriageStatus::Dismissed);
    }

    #[test]
    fn test_by_status() {
        let mut q = TriageQueue::new();
        q.add(make_item("t1", TriagePriority::Standard));
        q.add(make_item("t2", TriagePriority::Urgent));
        q.acknowledge("t1");
        assert_eq!(q.by_status(TriageStatus::New).len(), 1);
        assert_eq!(q.by_status(TriageStatus::Acknowledged).len(), 1);
    }

    #[test]
    fn test_overdue() {
        let mut q = TriageQueue::new();
        let mut item = make_item("t1", TriagePriority::Standard);
        item.due_at_ms = Some(500);
        q.add(item);
        assert_eq!(q.overdue(1000).len(), 1);
        assert_eq!(q.overdue(100).len(), 0);
    }

    #[test]
    fn test_stats() {
        let mut q = TriageQueue::new();
        q.add(make_item("t1", TriagePriority::Standard));
        q.add(make_item("t2", TriagePriority::Urgent));
        q.add(make_item("t3", TriagePriority::Standard));
        let stats = q.stats();
        assert_eq!(stats.total, 3);
        assert_eq!(stats.by_status.get("New"), Some(&3));
        assert_eq!(stats.by_priority.get("Standard"), Some(&2));
    }

    #[test]
    fn test_by_assignee() {
        let mut q = TriageQueue::new();
        q.add(make_item("t1", TriagePriority::Standard));
        q.add(make_item("t2", TriagePriority::Standard));
        q.assign("t1", "bob");
        assert_eq!(q.by_assignee("bob").len(), 1);
        assert_eq!(q.by_assignee("alice").len(), 0);
    }

    #[test]
    fn test_nonexistent_id_returns_false() {
        let mut q = TriageQueue::new();
        assert!(!q.acknowledge("nope"));
        assert!(!q.assign("nope", "x"));
        assert!(!q.escalate("nope"));
        assert!(!q.resolve("nope", "x"));
        assert!(!q.dismiss("nope", "x"));
    }
}
