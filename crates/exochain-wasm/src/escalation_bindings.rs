//! WASM bindings for the escalation subsystem: adverse event detection
//! and triage queue management.
//!
//! Exposes `AdverseEventDetector::evaluate_event` for anomaly flagging and
//! `TriageQueue` CRUD operations for human review workflows.

use crate::serde_bridge;
use exo_escalation::detector::{
    AdverseEventDetector, AnomalyType, EventSeverity,
};
use exo_escalation::triage::{
    TriageItem, TriagePriority, TriageQueue, TriageStatus,
};
use serde::{Deserialize, Serialize};
use wasm_bindgen::prelude::*;

// ---------------------------------------------------------------------------
// Serde types — detector
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
struct DetectAnomaliesInput {
    /// Events to evaluate: each has an actor, anomaly type, and timestamp.
    events: Vec<EventToEvaluate>,
}

#[derive(Deserialize)]
struct EventToEvaluate {
    actor: String,
    anomaly_type: String,
    timestamp_ms: u64,
}

#[derive(Serialize)]
struct DetectedAnomaly {
    anomaly_type: String,
    severity: String,
    actor: String,
    description: String,
    detected_at_ms: u64,
    auto_escalate: bool,
}

#[derive(Serialize)]
struct DetectAnomaliesOutput {
    anomalies: Vec<DetectedAnomaly>,
    total_evaluated: usize,
}

// ---------------------------------------------------------------------------
// Serde types — triage queue
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
struct CreateTriageQueueInput {
    /// Optional initial items.
    #[serde(default)]
    items: Vec<WasmTriageItem>,
}

#[derive(Serialize, Deserialize, Clone)]
struct WasmTriageItem {
    id: String,
    title: String,
    description: String,
    priority: String,
    #[serde(default = "default_status")]
    status: String,
    source_event_id: Option<String>,
    assigned_to: Option<String>,
    #[serde(default)]
    tags: Vec<String>,
    created_at_ms: u64,
    #[serde(default)]
    updated_at_ms: u64,
    due_at_ms: Option<u64>,
    resolution_notes: Option<String>,
}

fn default_status() -> String {
    "New".to_string()
}

#[derive(Serialize, Deserialize)]
struct TriageQueueOutput {
    items: Vec<WasmTriageItem>,
    total: usize,
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn parse_anomaly_type(s: &str) -> AnomalyType {
    match s {
        "QuorumManipulation" => AnomalyType::QuorumManipulation,
        "DelegationCascade" => AnomalyType::DelegationCascade,
        "AlignmentDrift" => AnomalyType::AlignmentDrift,
        "ConsentExpiry" => AnomalyType::ConsentExpiry,
        "AuditGap" => AnomalyType::AuditGap,
        "EquivocationAttempt" => AnomalyType::EquivocationAttempt,
        "UnauthorizedAccess" => AnomalyType::UnauthorizedAccess,
        "SilentMutation" => AnomalyType::SilentMutation,
        "HumanOverrideAttempt" => AnomalyType::HumanOverrideAttempt,
        "KernelTamper" => AnomalyType::KernelTamper,
        "RapidEmergencyActions" => AnomalyType::RapidEmergencyActions,
        "TrustScoreAnomaly" => AnomalyType::TrustScoreAnomaly,
        other => AnomalyType::Custom(other.to_string()),
    }
}

fn severity_name(s: &EventSeverity) -> &'static str {
    match s {
        EventSeverity::Info => "Info",
        EventSeverity::Warning => "Warning",
        EventSeverity::Elevated => "Elevated",
        EventSeverity::Critical => "Critical",
        EventSeverity::Emergency => "Emergency",
    }
}

fn parse_priority(s: &str) -> TriagePriority {
    match s {
        "Immediate" => TriagePriority::Immediate,
        "Urgent" => TriagePriority::Urgent,
        "Standard" => TriagePriority::Standard,
        "Deferred" => TriagePriority::Deferred,
        _ => TriagePriority::Backlog,
    }
}

fn priority_name(p: &TriagePriority) -> &'static str {
    match p {
        TriagePriority::Immediate => "Immediate",
        TriagePriority::Urgent => "Urgent",
        TriagePriority::Standard => "Standard",
        TriagePriority::Deferred => "Deferred",
        TriagePriority::Backlog => "Backlog",
    }
}

fn parse_triage_status(s: &str) -> TriageStatus {
    match s {
        "Acknowledged" => TriageStatus::Acknowledged,
        "InProgress" => TriageStatus::InProgress,
        "Escalated" => TriageStatus::Escalated,
        "Resolved" => TriageStatus::Resolved,
        "Dismissed" => TriageStatus::Dismissed,
        _ => TriageStatus::New,
    }
}

fn triage_status_name(s: &TriageStatus) -> &'static str {
    match s {
        TriageStatus::New => "New",
        TriageStatus::Acknowledged => "Acknowledged",
        TriageStatus::InProgress => "InProgress",
        TriageStatus::Escalated => "Escalated",
        TriageStatus::Resolved => "Resolved",
        TriageStatus::Dismissed => "Dismissed",
    }
}

fn wasm_item_to_triage_item(wi: &WasmTriageItem) -> TriageItem {
    TriageItem {
        id: wi.id.clone(),
        title: wi.title.clone(),
        description: wi.description.clone(),
        priority: parse_priority(&wi.priority),
        status: parse_triage_status(&wi.status),
        source_event_id: wi.source_event_id.as_ref().and_then(|h| {
            hex::decode(h).ok().and_then(|b| {
                let arr: [u8; 32] = b.try_into().ok()?;
                Some(exo_core::crypto::Blake3Hash(arr))
            })
        }),
        assigned_to: wi.assigned_to.clone(),
        tags: wi.tags.clone(),
        created_at_ms: wi.created_at_ms,
        updated_at_ms: wi.updated_at_ms,
        due_at_ms: wi.due_at_ms,
        resolution_notes: wi.resolution_notes.clone(),
    }
}

fn triage_item_to_wasm(ti: &TriageItem) -> WasmTriageItem {
    WasmTriageItem {
        id: ti.id.clone(),
        title: ti.title.clone(),
        description: ti.description.clone(),
        priority: priority_name(&ti.priority).to_string(),
        status: triage_status_name(&ti.status).to_string(),
        source_event_id: ti.source_event_id.map(|h| hex::encode(h.0)),
        assigned_to: ti.assigned_to.clone(),
        tags: ti.tags.clone(),
        created_at_ms: ti.created_at_ms,
        updated_at_ms: ti.updated_at_ms,
        due_at_ms: ti.due_at_ms,
        resolution_notes: ti.resolution_notes.clone(),
    }
}

// ---------------------------------------------------------------------------
// WASM exports — detection
// ---------------------------------------------------------------------------

/// Evaluate a batch of events against the default detection rules.
///
/// Creates a fresh `AdverseEventDetector` with the built-in rule set and
/// evaluates each event. Returns any anomalies that were triggered.
///
/// **Input:** JSON `{ "events": [{ "actor": "...", "anomaly_type": "...", "timestamp_ms": N }] }`
/// **Output:** JSON `{ "anomalies": [...], "total_evaluated": N }`
#[wasm_bindgen]
pub fn wasm_detect_anomalies(input_json: &str) -> Result<JsValue, JsError> {
    let input: DetectAnomaliesInput = serde_bridge::from_json_str(input_json)?;
    let mut detector = AdverseEventDetector::new();

    let mut anomalies = Vec::new();
    for evt in &input.events {
        let anomaly_type = parse_anomaly_type(&evt.anomaly_type);
        if let Some(adverse) = detector.evaluate_event(&evt.actor, anomaly_type, evt.timestamp_ms) {
            anomalies.push(DetectedAnomaly {
                anomaly_type: adverse.anomaly_type.key(),
                severity: severity_name(&adverse.severity).to_string(),
                actor: adverse.actor_did.clone(),
                description: adverse.description.clone(),
                detected_at_ms: adverse.detected_at_ms,
                auto_escalate: adverse.auto_escalate,
            });
        }
    }

    serde_bridge::to_js_value(&DetectAnomaliesOutput {
        total_evaluated: input.events.len(),
        anomalies,
    })
}

// ---------------------------------------------------------------------------
// WASM exports — triage queue
// ---------------------------------------------------------------------------

/// Create a new triage queue, optionally pre-populated with items.
///
/// **Input:** JSON `{ "items": [{ ... }] }` (items optional)
/// **Output:** JSON `{ "items": [...], "total": N }`
#[wasm_bindgen]
pub fn wasm_create_triage_queue(input_json: &str) -> Result<JsValue, JsError> {
    let input: CreateTriageQueueInput = serde_bridge::from_json_str(input_json)?;
    let mut queue = TriageQueue::new();

    for wi in &input.items {
        queue.add(wasm_item_to_triage_item(wi));
    }

    let output = TriageQueueOutput {
        total: queue.len(),
        items: queue.items.iter().map(triage_item_to_wasm).collect(),
    };
    serde_bridge::to_js_value(&output)
}

/// Add a single item to an existing triage queue.
///
/// **Inputs:**
/// - `queue_json`: JSON-serialized triage queue (from `wasm_create_triage_queue`)
/// - `item_json`: JSON-serialized triage item to add
///
/// **Output:** Updated triage queue JSON.
#[wasm_bindgen]
pub fn wasm_enqueue_triage_item(
    queue_json: &str,
    item_json: &str,
) -> Result<JsValue, JsError> {
    let existing: TriageQueueOutput = serde_bridge::from_json_str(queue_json)?;
    let new_item: WasmTriageItem = serde_bridge::from_json_str(item_json)?;

    let mut queue = TriageQueue::new();
    for wi in &existing.items {
        queue.add(wasm_item_to_triage_item(wi));
    }
    queue.add(wasm_item_to_triage_item(&new_item));

    let output = TriageQueueOutput {
        total: queue.len(),
        items: queue.items.iter().map(triage_item_to_wasm).collect(),
    };
    serde_bridge::to_js_value(&output)
}
