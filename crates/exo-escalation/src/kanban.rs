//! Kanban Board — visual governance workflow management.

use crate::triage::TriagePriority;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// A tag that can be attached to a kanban card.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CardTag {
    pub label: String,
    pub color: String,
}

/// A card on the kanban board representing a work item.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct KanbanCard {
    pub id: String,
    pub title: String,
    pub description: String,
    pub tags: Vec<CardTag>,
    pub assignee: Option<String>,
    pub priority: TriagePriority,
    pub created_at_ms: u64,
    pub updated_at_ms: u64,
    pub linked_decision_id: Option<String>,
    pub linked_triage_id: Option<String>,
    pub metadata: HashMap<String, String>,
}

/// A column on the kanban board.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct KanbanColumn {
    pub id: String,
    pub title: String,
    pub position: u32,
    pub cards: Vec<KanbanCard>,
    pub wip_limit: Option<u32>,
}

/// A kanban board for governance workflow management.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct KanbanBoard {
    pub id: String,
    pub name: String,
    pub columns: Vec<KanbanColumn>,
    pub created_at_ms: u64,
}

impl KanbanBoard {
    /// Creates a default governance board with standard columns.
    pub fn governance_default() -> Self {
        let column_defs = vec![
            ("backlog", "Backlog", 0, None),
            ("triage", "Triage", 1, Some(10)),
            ("in-review", "In Review", 2, Some(5)),
            ("deliberation", "Deliberation", 3, Some(5)),
            ("voting", "Voting", 4, Some(3)),
            ("resolved", "Resolved", 5, None),
            ("archived", "Archived", 6, None),
        ];

        let columns = column_defs
            .into_iter()
            .map(|(id, title, pos, wip)| KanbanColumn {
                id: id.to_string(),
                title: title.to_string(),
                position: pos,
                cards: Vec::new(),
                wip_limit: wip,
            })
            .collect();

        Self {
            id: "gov-board-default".into(),
            name: "Governance Board".into(),
            columns,
            created_at_ms: 0,
        }
    }

    /// Adds a card to the specified column, respecting WIP limits.
    pub fn add_card(&mut self, column_id: &str, card: KanbanCard) -> Result<(), String> {
        let col = self
            .columns
            .iter_mut()
            .find(|c| c.id == column_id)
            .ok_or_else(|| format!("Column '{}' not found", column_id))?;

        if let Some(limit) = col.wip_limit {
            if col.cards.len() as u32 >= limit {
                return Err(format!(
                    "WIP limit ({}) reached for column '{}'",
                    limit, column_id
                ));
            }
        }

        col.cards.push(card);
        Ok(())
    }

    /// Moves a card between columns, respecting WIP limits on target.
    pub fn move_card(
        &mut self,
        card_id: &str,
        from_col: &str,
        to_col: &str,
    ) -> Result<(), String> {
        // Check target WIP limit first
        let to_column = self
            .columns
            .iter()
            .find(|c| c.id == to_col)
            .ok_or_else(|| format!("Target column '{}' not found", to_col))?;

        if let Some(limit) = to_column.wip_limit {
            if to_column.cards.len() as u32 >= limit {
                return Err(format!(
                    "WIP limit ({}) reached for column '{}'",
                    limit, to_col
                ));
            }
        }

        // Remove from source
        let from_column = self
            .columns
            .iter_mut()
            .find(|c| c.id == from_col)
            .ok_or_else(|| format!("Source column '{}' not found", from_col))?;

        let card_pos = from_column
            .cards
            .iter()
            .position(|c| c.id == card_id)
            .ok_or_else(|| format!("Card '{}' not found in column '{}'", card_id, from_col))?;

        let card = from_column.cards.remove(card_pos);

        // Add to target
        let to_column = self
            .columns
            .iter_mut()
            .find(|c| c.id == to_col)
            .unwrap();
        to_column.cards.push(card);

        Ok(())
    }

    /// Finds a card by ID across all columns.
    pub fn find_card(&self, card_id: &str) -> Option<(&KanbanColumn, &KanbanCard)> {
        for col in &self.columns {
            if let Some(card) = col.cards.iter().find(|c| c.id == card_id) {
                return Some((col, card));
            }
        }
        None
    }

    /// Number of columns on the board.
    pub fn column_count(&self) -> usize {
        self.columns.len()
    }

    /// Total cards across all columns.
    pub fn total_cards(&self) -> usize {
        self.columns.iter().map(|c| c.cards.len()).sum()
    }

    /// Cards in a specific column.
    pub fn cards_in_column(&self, column_id: &str) -> Vec<&KanbanCard> {
        self.columns
            .iter()
            .find(|c| c.id == column_id)
            .map(|c| c.cards.iter().collect())
            .unwrap_or_default()
    }

    /// Check if a column has reached its WIP limit.
    pub fn wip_exceeded(&self, column_id: &str) -> bool {
        self.columns
            .iter()
            .find(|c| c.id == column_id)
            .map(|c| {
                c.wip_limit
                    .is_some_and(|limit| c.cards.len() as u32 >= limit)
            })
            .unwrap_or(false)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_card(id: &str) -> KanbanCard {
        KanbanCard {
            id: id.to_string(),
            title: format!("Card {}", id),
            description: "Test card".into(),
            tags: vec![],
            assignee: None,
            priority: TriagePriority::Standard,
            created_at_ms: 1000,
            updated_at_ms: 1000,
            linked_decision_id: None,
            linked_triage_id: None,
            metadata: HashMap::new(),
        }
    }

    #[test]
    fn test_governance_default_columns() {
        let board = KanbanBoard::governance_default();
        assert_eq!(board.column_count(), 7);
        assert_eq!(board.columns[0].title, "Backlog");
        assert_eq!(board.columns[6].title, "Archived");
    }

    #[test]
    fn test_add_card() {
        let mut board = KanbanBoard::governance_default();
        board.add_card("backlog", make_card("c1")).unwrap();
        assert_eq!(board.total_cards(), 1);
    }

    #[test]
    fn test_add_card_invalid_column() {
        let mut board = KanbanBoard::governance_default();
        let result = board.add_card("nonexistent", make_card("c1"));
        assert!(result.is_err());
    }

    #[test]
    fn test_wip_limit_enforcement() {
        let mut board = KanbanBoard::governance_default();
        // "voting" has WIP limit of 3
        for i in 0..3 {
            board
                .add_card("voting", make_card(&format!("v{}", i)))
                .unwrap();
        }
        let result = board.add_card("voting", make_card("v3"));
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("WIP limit"));
    }

    #[test]
    fn test_move_card() {
        let mut board = KanbanBoard::governance_default();
        board.add_card("backlog", make_card("c1")).unwrap();
        board.move_card("c1", "backlog", "triage").unwrap();
        assert_eq!(board.cards_in_column("backlog").len(), 0);
        assert_eq!(board.cards_in_column("triage").len(), 1);
    }

    #[test]
    fn test_move_card_wip_blocked() {
        let mut board = KanbanBoard::governance_default();
        // Fill voting to WIP limit
        for i in 0..3 {
            board
                .add_card("voting", make_card(&format!("v{}", i)))
                .unwrap();
        }
        board.add_card("backlog", make_card("extra")).unwrap();
        let result = board.move_card("extra", "backlog", "voting");
        assert!(result.is_err());
    }

    #[test]
    fn test_find_card() {
        let mut board = KanbanBoard::governance_default();
        board.add_card("triage", make_card("c1")).unwrap();
        let (col, card) = board.find_card("c1").unwrap();
        assert_eq!(col.id, "triage");
        assert_eq!(card.id, "c1");
    }

    #[test]
    fn test_find_card_not_found() {
        let board = KanbanBoard::governance_default();
        assert!(board.find_card("nope").is_none());
    }

    #[test]
    fn test_total_cards() {
        let mut board = KanbanBoard::governance_default();
        board.add_card("backlog", make_card("c1")).unwrap();
        board.add_card("triage", make_card("c2")).unwrap();
        assert_eq!(board.total_cards(), 2);
    }

    #[test]
    fn test_wip_exceeded() {
        let mut board = KanbanBoard::governance_default();
        assert!(!board.wip_exceeded("voting"));
        for i in 0..3 {
            board
                .add_card("voting", make_card(&format!("v{}", i)))
                .unwrap();
        }
        assert!(board.wip_exceeded("voting"));
        // Backlog has no WIP limit
        assert!(!board.wip_exceeded("backlog"));
    }

    #[test]
    fn test_no_wip_limit_column_unlimited() {
        let mut board = KanbanBoard::governance_default();
        // Backlog has no WIP limit, add many cards
        for i in 0..50 {
            board
                .add_card("backlog", make_card(&format!("b{}", i)))
                .unwrap();
        }
        assert_eq!(board.cards_in_column("backlog").len(), 50);
    }

    #[test]
    fn test_move_card_nonexistent_source() {
        let mut board = KanbanBoard::governance_default();
        let result = board.move_card("c1", "nonexistent", "backlog");
        assert!(result.is_err());
    }
}
