//! WASM bindings for the Combinator Graph Reduction (CGR) engine.
//!
//! This is the crown jewel of the WASM surface: it exposes the type-level
//! proof engine to JavaScript, allowing browser-side constitutional invariant
//! verification. CombinatorTerm and TypedValue do not derive Serialize/Deserialize
//! in the source crate, so we define serde-capable mirror types here and
//! convert between them.

use crate::serde_bridge;
use exo_gatekeeper::combinator::{
    CombinatorEngine, CombinatorTerm, ReductionContext, ReductionTrace, TypedValue,
};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use wasm_bindgen::prelude::*;

// ---------------------------------------------------------------------------
// Serde mirror types for CombinatorTerm / TypedValue
// ---------------------------------------------------------------------------

/// JSON-serializable mirror of `TypedValue`.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "type", content = "value")]
pub enum WasmTypedValue {
    Bool(bool),
    Nat(u64),
    Text(String),
    Did(String),
    Hash(String), // hex-encoded 32 bytes
    List(Vec<WasmTypedValue>),
    Unit,
}

impl WasmTypedValue {
    fn into_typed_value(self) -> Result<TypedValue, JsError> {
        match self {
            WasmTypedValue::Bool(b) => Ok(TypedValue::Bool(b)),
            WasmTypedValue::Nat(n) => Ok(TypedValue::Nat(n)),
            WasmTypedValue::Text(s) => Ok(TypedValue::Text(s)),
            WasmTypedValue::Did(d) => Ok(TypedValue::Did(d)),
            WasmTypedValue::Hash(h) => {
                let bytes = hex::decode(&h)
                    .map_err(|e| JsError::new(&format!("Invalid hash hex: {e}")))?;
                let arr: [u8; 32] = bytes
                    .try_into()
                    .map_err(|_| JsError::new("Hash must be 32 bytes"))?;
                Ok(TypedValue::Hash(arr))
            }
            WasmTypedValue::List(items) => {
                let converted: Result<Vec<TypedValue>, _> =
                    items.into_iter().map(|i| i.into_typed_value()).collect();
                Ok(TypedValue::List(converted?))
            }
            WasmTypedValue::Unit => Ok(TypedValue::Unit),
        }
    }

    fn from_typed_value(tv: &TypedValue) -> Self {
        match tv {
            TypedValue::Bool(b) => WasmTypedValue::Bool(*b),
            TypedValue::Nat(n) => WasmTypedValue::Nat(*n),
            TypedValue::Text(s) => WasmTypedValue::Text(s.clone()),
            TypedValue::Did(d) => WasmTypedValue::Did(d.clone()),
            TypedValue::Hash(h) => WasmTypedValue::Hash(hex::encode(h)),
            TypedValue::List(items) => {
                WasmTypedValue::List(items.iter().map(Self::from_typed_value).collect())
            }
            TypedValue::Unit => WasmTypedValue::Unit,
        }
    }
}

/// JSON-serializable mirror of `CombinatorTerm`.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "kind")]
pub enum WasmCombinatorTerm {
    S,
    K,
    I,
    B,
    C,
    Not,
    And,
    Or,
    Implies,
    ForAll { variable: String, domain: String },
    Exists { variable: String, domain: String },
    Equals,
    LessThan,
    GreaterThanOrEqual,
    Lookup { key: String },
    Literal { value: WasmTypedValue },
    App { f: Box<WasmCombinatorTerm>, x: Box<WasmCombinatorTerm> },
    Reduced { value: WasmTypedValue },
}

impl WasmCombinatorTerm {
    fn into_combinator_term(self) -> Result<CombinatorTerm, JsError> {
        match self {
            WasmCombinatorTerm::S => Ok(CombinatorTerm::S),
            WasmCombinatorTerm::K => Ok(CombinatorTerm::K),
            WasmCombinatorTerm::I => Ok(CombinatorTerm::I),
            WasmCombinatorTerm::B => Ok(CombinatorTerm::B),
            WasmCombinatorTerm::C => Ok(CombinatorTerm::C),
            WasmCombinatorTerm::Not => Ok(CombinatorTerm::Not),
            WasmCombinatorTerm::And => Ok(CombinatorTerm::And),
            WasmCombinatorTerm::Or => Ok(CombinatorTerm::Or),
            WasmCombinatorTerm::Implies => Ok(CombinatorTerm::Implies),
            WasmCombinatorTerm::ForAll { variable, domain } => {
                Ok(CombinatorTerm::ForAll { variable, domain })
            }
            WasmCombinatorTerm::Exists { variable, domain } => {
                Ok(CombinatorTerm::Exists { variable, domain })
            }
            WasmCombinatorTerm::Equals => Ok(CombinatorTerm::Equals),
            WasmCombinatorTerm::LessThan => Ok(CombinatorTerm::LessThan),
            WasmCombinatorTerm::GreaterThanOrEqual => Ok(CombinatorTerm::GreaterThanOrEqual),
            WasmCombinatorTerm::Lookup { key } => Ok(CombinatorTerm::Lookup { key }),
            WasmCombinatorTerm::Literal { value } => {
                Ok(CombinatorTerm::Literal(value.into_typed_value()?))
            }
            WasmCombinatorTerm::App { f, x } => {
                let f_term = f.into_combinator_term()?;
                let x_term = x.into_combinator_term()?;
                Ok(CombinatorTerm::App(Box::new(f_term), Box::new(x_term)))
            }
            WasmCombinatorTerm::Reduced { value } => {
                Ok(CombinatorTerm::Reduced(value.into_typed_value()?))
            }
        }
    }
}

/// JSON-serializable mirror of `ReductionContext`.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct WasmReductionContext {
    /// Named value bindings.
    #[serde(default)]
    pub bindings: HashMap<String, WasmTypedValue>,
    /// Finite domains for quantifier evaluation.
    #[serde(default)]
    pub domains: HashMap<String, Vec<WasmTypedValue>>,
}

impl WasmReductionContext {
    fn into_reduction_context(self) -> Result<ReductionContext, JsError> {
        let mut ctx = ReductionContext::new();
        for (k, v) in self.bindings {
            ctx.bind(k, v.into_typed_value()?);
        }
        for (name, vals) in self.domains {
            let converted: Result<Vec<TypedValue>, _> =
                vals.into_iter().map(|v| v.into_typed_value()).collect();
            ctx.set_domain(name, converted?);
        }
        Ok(ctx)
    }
}

// ---------------------------------------------------------------------------
// Serde output types
// ---------------------------------------------------------------------------

#[derive(Serialize)]
struct WasmReductionStep {
    step_number: u32,
    rule_applied: String,
    before: String,
    after: String,
}

#[derive(Serialize)]
struct WasmReductionTrace {
    invariant_id: String,
    steps: Vec<WasmReductionStep>,
    final_value: WasmTypedValue,
    total_reductions: u32,
}

fn trace_to_wasm(trace: &ReductionTrace) -> WasmReductionTrace {
    WasmReductionTrace {
        invariant_id: trace.invariant_id.clone(),
        steps: trace
            .steps
            .iter()
            .map(|s| WasmReductionStep {
                step_number: s.step_number,
                rule_applied: s.rule_applied.clone(),
                before: s.before.clone(),
                after: s.after.clone(),
            })
            .collect(),
        final_value: WasmTypedValue::from_typed_value(&trace.final_value),
        total_reductions: trace.total_reductions,
    }
}

// ---------------------------------------------------------------------------
// WASM export
// ---------------------------------------------------------------------------

/// Reduce a combinator term to normal form in the given context.
///
/// This is the primary entry point for browser-side constitutional invariant
/// verification. The reduction trace returned constitutes a type-level proof.
///
/// **Inputs:**
/// - `term_json`: JSON-serialized `WasmCombinatorTerm`
/// - `context_json`: JSON-serialized `WasmReductionContext`
/// - `invariant_id`: human-readable name for the invariant being checked
/// - `max_reductions`: maximum number of reduction steps before halting
///
/// **Output:** JSON-serialized `WasmReductionTrace` containing every step
///   of the reduction and the final value.
#[wasm_bindgen]
pub fn wasm_reduce_combinator(
    term_json: &str,
    context_json: &str,
    invariant_id: &str,
    max_reductions: u32,
) -> Result<JsValue, JsError> {
    let wasm_term: WasmCombinatorTerm = serde_bridge::from_json_str(term_json)?;
    let wasm_ctx: WasmReductionContext = serde_bridge::from_json_str(context_json)?;

    let term = wasm_term.into_combinator_term()?;
    let ctx = wasm_ctx.into_reduction_context()?;

    let engine = CombinatorEngine::new(max_reductions);
    let trace = engine.reduce(term, &ctx, invariant_id);

    let wasm_trace = trace_to_wasm(&trace);
    serde_bridge::to_js_value(&wasm_trace)
}
