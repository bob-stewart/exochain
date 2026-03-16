//! Combinator Graph Reduction — type-level proof engine.
//!
//! The CGR engine represents constitutional invariants as combinatory logic
//! expressions that can be mechanically reduced. Each invariant is encoded
//! as a combinator term, and the reduction process produces a type-level
//! proof that the term reduces to TRUE or FALSE.
//!
//! ## Combinator Basis
//!
//! We use a typed combinatory logic basis:
//! - S: (S f g x) → (f x (g x))  — composition with sharing
//! - K: (K x y) → x               — constant projection
//! - I: (I x) → x                 — identity
//! - B: (B f g x) → f (g x)      — function composition
//! - C: (C f x y) → f y x        — argument flip
//!
//! Plus domain-specific combinators for governance:
//! - NOT: logical negation
//! - AND: logical conjunction
//! - OR: logical disjunction
//! - IMPLIES: logical implication
//! - FORALL: universal quantification (over a finite set)
//! - EXISTS: existential quantification (over a finite set)
//! - EQUALS: equality test
//! - LESS_THAN: ordering test
//! - LOOKUP: context value lookup

use std::collections::HashMap;
use std::fmt;

// ---------------------------------------------------------------------------
// TypedValue — the value domain
// ---------------------------------------------------------------------------

/// Domain of values that combinator terms can reduce to.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum TypedValue {
    Bool(bool),
    Nat(u64),
    Text(String),
    Did(String),
    Hash([u8; 32]),
    List(Vec<TypedValue>),
    Unit,
}

impl fmt::Display for TypedValue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            TypedValue::Bool(b) => write!(f, "{b}"),
            TypedValue::Nat(n) => write!(f, "{n}"),
            TypedValue::Text(s) => write!(f, "\"{s}\""),
            TypedValue::Did(d) => write!(f, "did({d})"),
            TypedValue::Hash(h) => write!(f, "hash({})", hex::encode(&h[..4])),
            TypedValue::List(items) => {
                write!(f, "[")?;
                for (i, item) in items.iter().enumerate() {
                    if i > 0 {
                        write!(f, ", ")?;
                    }
                    write!(f, "{item}")?;
                }
                write!(f, "]")
            }
            TypedValue::Unit => write!(f, "()"),
        }
    }
}

// ---------------------------------------------------------------------------
// CombinatorTerm — the expression tree
// ---------------------------------------------------------------------------

/// An algebraic expression tree in typed combinatory logic.
///
/// Terms are reduced step-by-step until they reach normal form (typically a
/// `Reduced(TypedValue)`). The reduction trace serves as the type-level proof
/// that the invariant holds or is violated.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CombinatorTerm {
    // Primitive combinators
    /// S combinator: (S f g x) → (f x (g x))
    S,
    /// K combinator: (K x y) → x
    K,
    /// I combinator: (I x) → x
    I,
    /// B combinator: (B f g x) → f (g x)
    B,
    /// C combinator: (C f x y) → f y x
    C,

    // Logical combinators
    /// Logical negation
    Not,
    /// Logical conjunction
    And,
    /// Logical disjunction
    Or,
    /// Logical implication
    Implies,

    // Quantifiers (over finite context sets)
    /// Universal quantification over a named domain
    ForAll { variable: String, domain: String },
    /// Existential quantification over a named domain
    Exists { variable: String, domain: String },

    // Comparison
    /// Equality test
    Equals,
    /// Strict less-than
    LessThan,
    /// Greater-than-or-equal
    GreaterThanOrEqual,

    // Context operations
    /// Look up a value from the reduction context
    Lookup { key: String },
    /// A literal value
    Literal(TypedValue),

    // Application
    /// Function application: `App(f, x)` means `f x`
    App(Box<CombinatorTerm>, Box<CombinatorTerm>),

    // Reduction result
    /// A fully-reduced value
    Reduced(TypedValue),
}

impl CombinatorTerm {
    /// Convenience: build `App(f, x)`.
    pub fn app(f: CombinatorTerm, x: CombinatorTerm) -> Self {
        CombinatorTerm::App(Box::new(f), Box::new(x))
    }

    /// Convenience: build `App(App(f, x), y)`.
    pub fn app2(f: CombinatorTerm, x: CombinatorTerm, y: CombinatorTerm) -> Self {
        CombinatorTerm::app(CombinatorTerm::app(f, x), y)
    }

    /// Convenience: build `App(App(App(f, x), y), z)`.
    pub fn app3(
        f: CombinatorTerm,
        x: CombinatorTerm,
        y: CombinatorTerm,
        z: CombinatorTerm,
    ) -> Self {
        CombinatorTerm::app(CombinatorTerm::app2(f, x, y), z)
    }
}

// ---------------------------------------------------------------------------
// ReductionContext — runtime bindings
// ---------------------------------------------------------------------------

/// Runtime bindings for context-dependent reduction.
///
/// Provides named values (via `bind`) and finite domains for quantifiers.
#[derive(Clone, Debug, Default)]
pub struct ReductionContext {
    bindings: HashMap<String, TypedValue>,
    domains: HashMap<String, Vec<TypedValue>>,
}

impl ReductionContext {
    pub fn new() -> Self {
        Self::default()
    }

    /// Bind a key to a typed value.
    pub fn bind(&mut self, key: impl Into<String>, value: TypedValue) {
        self.bindings.insert(key.into(), value);
    }

    /// Look up a binding by key.
    pub fn lookup(&self, key: &str) -> Option<&TypedValue> {
        self.bindings.get(key)
    }

    /// Register a finite domain for quantifier evaluation.
    pub fn set_domain(&mut self, name: impl Into<String>, values: Vec<TypedValue>) {
        self.domains.insert(name.into(), values);
    }

    /// Get the values of a named domain.
    pub fn domain(&self, name: &str) -> &[TypedValue] {
        self.domains.get(name).map(|v| v.as_slice()).unwrap_or(&[])
    }
}

// ---------------------------------------------------------------------------
// ReductionTrace — step-by-step proof
// ---------------------------------------------------------------------------

/// A single reduction step in the proof trace.
#[derive(Clone, Debug)]
pub struct ReductionStep {
    pub step_number: u32,
    pub rule_applied: String,
    pub before: String,
    pub after: String,
}

/// Complete trace of reducing a combinator term to normal form.
///
/// This trace constitutes the type-level proof: it records every reduction
/// rule applied, allowing mechanical verification of the result.
#[derive(Clone, Debug)]
pub struct ReductionTrace {
    pub invariant_id: String,
    pub steps: Vec<ReductionStep>,
    pub final_value: TypedValue,
    pub total_reductions: u32,
}

// ---------------------------------------------------------------------------
// CombinatorEngine — the reducer
// ---------------------------------------------------------------------------

/// The combinator graph reduction engine.
///
/// Reduces combinator terms to normal form by repeatedly applying reduction
/// rules. A maximum reduction count prevents divergence.
pub struct CombinatorEngine {
    max_reductions: u32,
}

impl CombinatorEngine {
    /// Create a new engine with the given reduction step limit.
    pub fn new(max_reductions: u32) -> Self {
        Self { max_reductions }
    }

    /// Reduce a combinator term to normal form in the given context.
    ///
    /// Returns a `ReductionTrace` recording every step. If the term does not
    /// reach normal form within `max_reductions` steps, reduction halts and
    /// the final (possibly non-normal) term is returned as `TypedValue::Unit`.
    pub fn reduce(
        &self,
        term: CombinatorTerm,
        ctx: &ReductionContext,
        invariant_id: &str,
    ) -> ReductionTrace {
        let mut current = term;
        let mut steps = Vec::new();
        let mut count: u32 = 0;

        while count < self.max_reductions {
            if self.is_normal_form(&current) {
                break;
            }
            let before_str = self.pretty_print(&current);
            if let Some(next) = self.step(&current, ctx) {
                count += 1;
                let after_str = self.pretty_print(&next);
                steps.push(ReductionStep {
                    step_number: count,
                    rule_applied: self.last_rule_name(&current, &next),
                    before: before_str,
                    after: after_str,
                });
                current = next;
            } else {
                // No reduction rule applies — stuck term
                break;
            }
        }

        let final_value = match &current {
            CombinatorTerm::Reduced(v) => v.clone(),
            _ => TypedValue::Unit, // non-normal / stuck
        };

        ReductionTrace {
            invariant_id: invariant_id.to_string(),
            steps,
            final_value,
            total_reductions: count,
        }
    }

    /// Attempt a single reduction step. Returns `None` if no rule applies.
    fn step(&self, term: &CombinatorTerm, ctx: &ReductionContext) -> Option<CombinatorTerm> {
        match term {
            // ----- Lookup -----
            CombinatorTerm::Lookup { key } => {
                ctx.lookup(key).map(|v| CombinatorTerm::Reduced(v.clone()))
            }

            // ----- Literal → Reduced -----
            CombinatorTerm::Literal(v) => Some(CombinatorTerm::Reduced(v.clone())),

            // ----- Application rules -----
            CombinatorTerm::App(f, x) => self.step_app(f.as_ref(), x.as_ref(), ctx),

            _ => None,
        }
    }

    /// Reduction rules for application terms.
    fn step_app(
        &self,
        f: &CombinatorTerm,
        x: &CombinatorTerm,
        ctx: &ReductionContext,
    ) -> Option<CombinatorTerm> {
        match (f, x) {
            // I combinator: (I x) → x
            (CombinatorTerm::I, _) => Some(x.clone()),

            // NOT: (Not, Reduced(Bool(b))) → Reduced(Bool(!b))
            (CombinatorTerm::Not, CombinatorTerm::Reduced(TypedValue::Bool(b))) => {
                Some(CombinatorTerm::Reduced(TypedValue::Bool(!b)))
            }

            // Doubly-applied: ((inner_f inner_x) y) where y = x in caller
            (CombinatorTerm::App(inner_f, inner_x), _) => {
                self.step_app2(inner_f.as_ref(), inner_x.as_ref(), x, ctx)
            }

            // ForAll: reduce body for each value in domain, AND results
            (CombinatorTerm::ForAll { variable, domain }, body) => {
                self.step_forall(variable, domain, body, ctx)
            }

            // Exists: reduce body for each value in domain, OR results
            (CombinatorTerm::Exists { variable, domain }, body) => {
                self.step_exists(variable, domain, body, ctx)
            }

            // Try reducing subterms
            _ => {
                // Try reducing f first
                if let Some(f2) = self.step(f, ctx) {
                    return Some(CombinatorTerm::app(f2, x.clone()));
                }
                // Then try reducing x
                if let Some(x2) = self.step(x, ctx) {
                    return Some(CombinatorTerm::app(f.clone(), x2));
                }
                None
            }
        }
    }

    /// Reduction rules for doubly-applied terms: `((f x) y)`.
    fn step_app2(
        &self,
        f: &CombinatorTerm,
        x: &CombinatorTerm,
        y: &CombinatorTerm,
        ctx: &ReductionContext,
    ) -> Option<CombinatorTerm> {
        match (f, x, y) {
            // K combinator: ((K x) y) → x
            (CombinatorTerm::K, _, _) => Some(x.clone()),

            // AND: ((And a) b) → Reduced(Bool(a && b))
            (CombinatorTerm::And, CombinatorTerm::Reduced(TypedValue::Bool(a)), CombinatorTerm::Reduced(TypedValue::Bool(b))) => {
                Some(CombinatorTerm::Reduced(TypedValue::Bool(*a && *b)))
            }

            // OR: ((Or a) b) → Reduced(Bool(a || b))
            (CombinatorTerm::Or, CombinatorTerm::Reduced(TypedValue::Bool(a)), CombinatorTerm::Reduced(TypedValue::Bool(b))) => {
                Some(CombinatorTerm::Reduced(TypedValue::Bool(*a || *b)))
            }

            // IMPLIES: ((Implies a) b) → Reduced(Bool(!a || b))
            (CombinatorTerm::Implies, CombinatorTerm::Reduced(TypedValue::Bool(a)), CombinatorTerm::Reduced(TypedValue::Bool(b))) => {
                Some(CombinatorTerm::Reduced(TypedValue::Bool(!a || *b)))
            }

            // EQUALS: ((Equals a) b) → Reduced(Bool(a == b))
            (CombinatorTerm::Equals, CombinatorTerm::Reduced(a), CombinatorTerm::Reduced(b)) => {
                Some(CombinatorTerm::Reduced(TypedValue::Bool(a == b)))
            }

            // LESS_THAN: ((LessThan a) b) → Reduced(Bool(a < b))
            (CombinatorTerm::LessThan, CombinatorTerm::Reduced(TypedValue::Nat(a)), CombinatorTerm::Reduced(TypedValue::Nat(b))) => {
                Some(CombinatorTerm::Reduced(TypedValue::Bool(a < b)))
            }

            // GTE: ((GreaterThanOrEqual a) b) → Reduced(Bool(a >= b))
            (CombinatorTerm::GreaterThanOrEqual, CombinatorTerm::Reduced(TypedValue::Nat(a)), CombinatorTerm::Reduced(TypedValue::Nat(b))) => {
                Some(CombinatorTerm::Reduced(TypedValue::Bool(a >= b)))
            }

            // Triply-applied: (((ff fx) x) y) — for S, B, C
            (CombinatorTerm::App(ff, fx), _, _) => {
                self.step_app3(ff.as_ref(), fx.as_ref(), x, y, ctx)
            }

            // Try reducing subterms of the inner application
            _ => {
                // Try reducing the inner App(f, x) first
                let inner = CombinatorTerm::app(f.clone(), x.clone());
                if let Some(inner2) = self.step(&inner, ctx) {
                    return Some(CombinatorTerm::app(inner2, y.clone()));
                }
                // Try reducing y
                if let Some(y2) = self.step(y, ctx) {
                    return Some(CombinatorTerm::App(
                        Box::new(CombinatorTerm::app(f.clone(), x.clone())),
                        Box::new(y2),
                    ));
                }
                None
            }
        }
    }

    /// Reduction rules for triply-applied terms: `(((f x) y) z)`.
    fn step_app3(
        &self,
        f: &CombinatorTerm,
        x: &CombinatorTerm,
        y: &CombinatorTerm,
        z: &CombinatorTerm,
        ctx: &ReductionContext,
    ) -> Option<CombinatorTerm> {
        match (f, x, y, z) {
            // S combinator: (((S f) g) x) → ((f x) (g x))
            (CombinatorTerm::S, _, _, _) => {
                // x=f_arg, y=g_arg, z=the_x
                let fx = CombinatorTerm::app(x.clone(), z.clone());
                let gx = CombinatorTerm::app(y.clone(), z.clone());
                Some(CombinatorTerm::app(fx, gx))
            }

            // B combinator: (((B f) g) x) → (f (g x))
            (CombinatorTerm::B, _, _, _) => {
                let gx = CombinatorTerm::app(y.clone(), z.clone());
                Some(CombinatorTerm::app(x.clone(), gx))
            }

            // C combinator: (((C f) x) y) → ((f y) x)
            (CombinatorTerm::C, _, _, _) => {
                let fy = CombinatorTerm::app(x.clone(), z.clone());
                Some(CombinatorTerm::app(fy, y.clone()))
            }

            _ => {
                // Try reducing inner triple app
                let inner = CombinatorTerm::app(
                    CombinatorTerm::app(f.clone(), x.clone()),
                    y.clone(),
                );
                if let Some(inner2) = self.step(&inner, ctx) {
                    return Some(CombinatorTerm::app(inner2, z.clone()));
                }
                // Try reducing z
                if let Some(z2) = self.step(z, ctx) {
                    return Some(CombinatorTerm::app(
                        CombinatorTerm::app(
                            CombinatorTerm::app(f.clone(), x.clone()),
                            y.clone(),
                        ),
                        z2,
                    ));
                }
                None
            }
        }
    }

    /// ForAll: reduce body for each value in domain, AND all results.
    fn step_forall(
        &self,
        variable: &str,
        domain_name: &str,
        body: &CombinatorTerm,
        ctx: &ReductionContext,
    ) -> Option<CombinatorTerm> {
        let domain_values = ctx.domain(domain_name);
        if domain_values.is_empty() {
            // Vacuous truth
            return Some(CombinatorTerm::Reduced(TypedValue::Bool(true)));
        }

        let mut all_true = true;
        for val in domain_values {
            let mut local_ctx = ctx.clone();
            local_ctx.bind(variable, val.clone());
            let sub_engine = CombinatorEngine::new(self.max_reductions);
            let trace = sub_engine.reduce(body.clone(), &local_ctx, "");
            match trace.final_value {
                TypedValue::Bool(b) => {
                    if !b {
                        all_true = false;
                        break;
                    }
                }
                _ => {
                    all_true = false;
                    break;
                }
            }
        }
        Some(CombinatorTerm::Reduced(TypedValue::Bool(all_true)))
    }

    /// Exists: reduce body for each value in domain, OR all results.
    fn step_exists(
        &self,
        variable: &str,
        domain_name: &str,
        body: &CombinatorTerm,
        ctx: &ReductionContext,
    ) -> Option<CombinatorTerm> {
        let domain_values = ctx.domain(domain_name);
        if domain_values.is_empty() {
            // No witnesses exist
            return Some(CombinatorTerm::Reduced(TypedValue::Bool(false)));
        }

        let mut any_true = false;
        for val in domain_values {
            let mut local_ctx = ctx.clone();
            local_ctx.bind(variable, val.clone());
            let sub_engine = CombinatorEngine::new(self.max_reductions);
            let trace = sub_engine.reduce(body.clone(), &local_ctx, "");
            if let TypedValue::Bool(true) = trace.final_value {
                any_true = true;
                break;
            }
        }
        Some(CombinatorTerm::Reduced(TypedValue::Bool(any_true)))
    }

    /// Check if a term is in normal form (no more reductions possible).
    fn is_normal_form(&self, term: &CombinatorTerm) -> bool {
        matches!(term, CombinatorTerm::Reduced(_))
    }

    /// Pretty-print a combinator term.
    pub fn pretty_print(&self, term: &CombinatorTerm) -> String {
        pp_term(term)
    }

    /// Determine the rule name for a reduction step (best-effort).
    fn last_rule_name(&self, before: &CombinatorTerm, _after: &CombinatorTerm) -> String {
        match before {
            CombinatorTerm::Lookup { .. } => "LOOKUP".to_string(),
            CombinatorTerm::Literal(_) => "LITERAL".to_string(),
            CombinatorTerm::App(f, _) => match f.as_ref() {
                CombinatorTerm::I => "I-REDUCE".to_string(),
                CombinatorTerm::Not => "NOT-REDUCE".to_string(),
                CombinatorTerm::ForAll { .. } => "FORALL-REDUCE".to_string(),
                CombinatorTerm::Exists { .. } => "EXISTS-REDUCE".to_string(),
                CombinatorTerm::App(ff, _) => match ff.as_ref() {
                    CombinatorTerm::K => "K-REDUCE".to_string(),
                    CombinatorTerm::And => "AND-REDUCE".to_string(),
                    CombinatorTerm::Or => "OR-REDUCE".to_string(),
                    CombinatorTerm::Implies => "IMPLIES-REDUCE".to_string(),
                    CombinatorTerm::Equals => "EQUALS-REDUCE".to_string(),
                    CombinatorTerm::LessThan => "LT-REDUCE".to_string(),
                    CombinatorTerm::GreaterThanOrEqual => "GTE-REDUCE".to_string(),
                    CombinatorTerm::App(fff, _) => match fff.as_ref() {
                        CombinatorTerm::S => "S-REDUCE".to_string(),
                        CombinatorTerm::B => "B-REDUCE".to_string(),
                        CombinatorTerm::C => "C-REDUCE".to_string(),
                        _ => "STEP".to_string(),
                    },
                    _ => "STEP".to_string(),
                },
                _ => "STEP".to_string(),
            },
            _ => "STEP".to_string(),
        }
    }
}

/// Pretty-print a combinator term as a human-readable string.
fn pp_term(term: &CombinatorTerm) -> String {
    match term {
        CombinatorTerm::S => "S".to_string(),
        CombinatorTerm::K => "K".to_string(),
        CombinatorTerm::I => "I".to_string(),
        CombinatorTerm::B => "B".to_string(),
        CombinatorTerm::C => "C".to_string(),
        CombinatorTerm::Not => "NOT".to_string(),
        CombinatorTerm::And => "AND".to_string(),
        CombinatorTerm::Or => "OR".to_string(),
        CombinatorTerm::Implies => "IMPLIES".to_string(),
        CombinatorTerm::ForAll { variable, domain } => {
            format!("FORALL({variable} in {domain})")
        }
        CombinatorTerm::Exists { variable, domain } => {
            format!("EXISTS({variable} in {domain})")
        }
        CombinatorTerm::Equals => "EQUALS".to_string(),
        CombinatorTerm::LessThan => "LT".to_string(),
        CombinatorTerm::GreaterThanOrEqual => "GTE".to_string(),
        CombinatorTerm::Lookup { key } => format!("LOOKUP({key})"),
        CombinatorTerm::Literal(v) => format!("LIT({v})"),
        CombinatorTerm::App(f, x) => {
            format!("({} {})", pp_term(f), pp_term(x))
        }
        CombinatorTerm::Reduced(v) => format!("{v}"),
    }
}

// ---------------------------------------------------------------------------
// Invariant encodings
// ---------------------------------------------------------------------------

/// Encode a constitutional invariant as a combinator term.
///
/// The returned term, when reduced in a context containing the relevant
/// bindings, will produce `Reduced(Bool(true))` if the invariant holds
/// and `Reduced(Bool(false))` if it is violated.
pub fn encode_invariant(id: &str) -> Option<CombinatorTerm> {
    match id {
        // INV-002: NO_CAPABILITY_SELF_GRANT
        // author_did != target_did  ≡  NOT(EQUALS(LOOKUP(author_did), LOOKUP(target_did)))
        "INV-002" => {
            let author = CombinatorTerm::Lookup { key: "author_did".to_string() };
            let target = CombinatorTerm::Lookup { key: "target_did".to_string() };
            let eq = CombinatorTerm::app2(CombinatorTerm::Equals, author, target);
            Some(CombinatorTerm::app(CombinatorTerm::Not, eq))
        }

        // INV-005: ALIGNMENT_FLOOR
        // alignment_score >= min_alignment
        "INV-005" => {
            let score = CombinatorTerm::Lookup { key: "alignment_score".to_string() };
            let min = CombinatorTerm::Lookup { key: "min_alignment".to_string() };
            Some(CombinatorTerm::app2(CombinatorTerm::GreaterThanOrEqual, score, min))
        }

        // INV-006: AUDIT_COMPLETENESS
        // audit_event_planned must be true
        "INV-006" => {
            Some(CombinatorTerm::Lookup { key: "audit_event_planned".to_string() })
        }

        // INV-007: HUMAN_OVERRIDE_PRESERVED
        // NOT(removes_human_override)
        "INV-007" => {
            let removes = CombinatorTerm::Lookup { key: "removes_human_override".to_string() };
            Some(CombinatorTerm::app(CombinatorTerm::Not, removes))
        }

        _ => None,
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn engine() -> CombinatorEngine {
        CombinatorEngine::new(100)
    }

    fn empty_ctx() -> ReductionContext {
        ReductionContext::new()
    }

    // 1. S combinator: (S K K x) → x  (SKK is identity)
    #[test]
    fn test_s_combinator_skk_identity() {
        let e = engine();
        // (((S K) K) val)
        let val = CombinatorTerm::Reduced(TypedValue::Nat(42));
        let term = CombinatorTerm::app3(CombinatorTerm::S, CombinatorTerm::K, CombinatorTerm::K, val);
        let trace = e.reduce(term, &empty_ctx(), "test-skk");
        assert_eq!(trace.final_value, TypedValue::Nat(42));
    }

    // 2. K combinator: (K a b) → a
    #[test]
    fn test_k_combinator() {
        let e = engine();
        let a = CombinatorTerm::Reduced(TypedValue::Nat(1));
        let b = CombinatorTerm::Reduced(TypedValue::Nat(2));
        let term = CombinatorTerm::app2(CombinatorTerm::K, a, b);
        let trace = e.reduce(term, &empty_ctx(), "test-k");
        assert_eq!(trace.final_value, TypedValue::Nat(1));
    }

    // 3. I combinator: (I x) → x
    #[test]
    fn test_i_combinator() {
        let e = engine();
        let x = CombinatorTerm::Reduced(TypedValue::Text("hello".to_string()));
        let term = CombinatorTerm::app(CombinatorTerm::I, x);
        let trace = e.reduce(term, &empty_ctx(), "test-i");
        assert_eq!(trace.final_value, TypedValue::Text("hello".to_string()));
    }

    // 4. B combinator: (B f g x) → f (g x)
    #[test]
    fn test_b_combinator_composition() {
        let e = engine();
        // (B NOT NOT true) → NOT (NOT true) → NOT false → true
        let term = CombinatorTerm::app3(
            CombinatorTerm::B,
            CombinatorTerm::Not,
            CombinatorTerm::Not,
            CombinatorTerm::Reduced(TypedValue::Bool(true)),
        );
        let trace = e.reduce(term, &empty_ctx(), "test-b");
        assert_eq!(trace.final_value, TypedValue::Bool(true));
    }

    // 5. C combinator: (C f x y) → (f y x)
    #[test]
    fn test_c_combinator_flip() {
        let e = engine();
        // (C LT 10 5) → (LT 5 10) → true  (5 < 10)
        let term = CombinatorTerm::app3(
            CombinatorTerm::C,
            CombinatorTerm::LessThan,
            CombinatorTerm::Reduced(TypedValue::Nat(10)),
            CombinatorTerm::Reduced(TypedValue::Nat(5)),
        );
        let trace = e.reduce(term, &empty_ctx(), "test-c");
        assert_eq!(trace.final_value, TypedValue::Bool(true));
    }

    // 6. NOT reduction
    #[test]
    fn test_not_reduction() {
        let e = engine();
        let term = CombinatorTerm::app(
            CombinatorTerm::Not,
            CombinatorTerm::Reduced(TypedValue::Bool(true)),
        );
        let trace = e.reduce(term, &empty_ctx(), "test-not");
        assert_eq!(trace.final_value, TypedValue::Bool(false));
    }

    // 7. AND reduction (true/true, true/false, false/false)
    #[test]
    fn test_and_true_true() {
        let e = engine();
        let term = CombinatorTerm::app2(
            CombinatorTerm::And,
            CombinatorTerm::Reduced(TypedValue::Bool(true)),
            CombinatorTerm::Reduced(TypedValue::Bool(true)),
        );
        let trace = e.reduce(term, &empty_ctx(), "test-and-tt");
        assert_eq!(trace.final_value, TypedValue::Bool(true));
    }

    #[test]
    fn test_and_true_false() {
        let e = engine();
        let term = CombinatorTerm::app2(
            CombinatorTerm::And,
            CombinatorTerm::Reduced(TypedValue::Bool(true)),
            CombinatorTerm::Reduced(TypedValue::Bool(false)),
        );
        let trace = e.reduce(term, &empty_ctx(), "test-and-tf");
        assert_eq!(trace.final_value, TypedValue::Bool(false));
    }

    #[test]
    fn test_and_false_false() {
        let e = engine();
        let term = CombinatorTerm::app2(
            CombinatorTerm::And,
            CombinatorTerm::Reduced(TypedValue::Bool(false)),
            CombinatorTerm::Reduced(TypedValue::Bool(false)),
        );
        let trace = e.reduce(term, &empty_ctx(), "test-and-ff");
        assert_eq!(trace.final_value, TypedValue::Bool(false));
    }

    // 8. OR reduction
    #[test]
    fn test_or_reduction() {
        let e = engine();
        let term = CombinatorTerm::app2(
            CombinatorTerm::Or,
            CombinatorTerm::Reduced(TypedValue::Bool(false)),
            CombinatorTerm::Reduced(TypedValue::Bool(true)),
        );
        let trace = e.reduce(term, &empty_ctx(), "test-or");
        assert_eq!(trace.final_value, TypedValue::Bool(true));
    }

    // 9. IMPLIES reduction
    #[test]
    fn test_implies_reduction() {
        let e = engine();
        // true → false = false
        let term = CombinatorTerm::app2(
            CombinatorTerm::Implies,
            CombinatorTerm::Reduced(TypedValue::Bool(true)),
            CombinatorTerm::Reduced(TypedValue::Bool(false)),
        );
        let trace = e.reduce(term, &empty_ctx(), "test-implies");
        assert_eq!(trace.final_value, TypedValue::Bool(false));

        // false → false = true (vacuously)
        let term2 = CombinatorTerm::app2(
            CombinatorTerm::Implies,
            CombinatorTerm::Reduced(TypedValue::Bool(false)),
            CombinatorTerm::Reduced(TypedValue::Bool(false)),
        );
        let trace2 = e.reduce(term2, &empty_ctx(), "test-implies-2");
        assert_eq!(trace2.final_value, TypedValue::Bool(true));
    }

    // 10. Equals on matching values
    #[test]
    fn test_equals_matching() {
        let e = engine();
        let term = CombinatorTerm::app2(
            CombinatorTerm::Equals,
            CombinatorTerm::Reduced(TypedValue::Nat(7)),
            CombinatorTerm::Reduced(TypedValue::Nat(7)),
        );
        let trace = e.reduce(term, &empty_ctx(), "test-eq-match");
        assert_eq!(trace.final_value, TypedValue::Bool(true));
    }

    // 11. Equals on mismatched values
    #[test]
    fn test_equals_mismatched() {
        let e = engine();
        let term = CombinatorTerm::app2(
            CombinatorTerm::Equals,
            CombinatorTerm::Reduced(TypedValue::Nat(7)),
            CombinatorTerm::Reduced(TypedValue::Nat(8)),
        );
        let trace = e.reduce(term, &empty_ctx(), "test-eq-mismatch");
        assert_eq!(trace.final_value, TypedValue::Bool(false));
    }

    // 12. LessThan
    #[test]
    fn test_less_than() {
        let e = engine();
        let term = CombinatorTerm::app2(
            CombinatorTerm::LessThan,
            CombinatorTerm::Reduced(TypedValue::Nat(3)),
            CombinatorTerm::Reduced(TypedValue::Nat(5)),
        );
        let trace = e.reduce(term, &empty_ctx(), "test-lt");
        assert_eq!(trace.final_value, TypedValue::Bool(true));

        let term2 = CombinatorTerm::app2(
            CombinatorTerm::LessThan,
            CombinatorTerm::Reduced(TypedValue::Nat(5)),
            CombinatorTerm::Reduced(TypedValue::Nat(3)),
        );
        let trace2 = e.reduce(term2, &empty_ctx(), "test-lt-false");
        assert_eq!(trace2.final_value, TypedValue::Bool(false));
    }

    // 13. GreaterThanOrEqual
    #[test]
    fn test_greater_than_or_equal() {
        let e = engine();
        let term = CombinatorTerm::app2(
            CombinatorTerm::GreaterThanOrEqual,
            CombinatorTerm::Reduced(TypedValue::Nat(5)),
            CombinatorTerm::Reduced(TypedValue::Nat(5)),
        );
        let trace = e.reduce(term, &empty_ctx(), "test-gte");
        assert_eq!(trace.final_value, TypedValue::Bool(true));

        let term2 = CombinatorTerm::app2(
            CombinatorTerm::GreaterThanOrEqual,
            CombinatorTerm::Reduced(TypedValue::Nat(3)),
            CombinatorTerm::Reduced(TypedValue::Nat(5)),
        );
        let trace2 = e.reduce(term2, &empty_ctx(), "test-gte-false");
        assert_eq!(trace2.final_value, TypedValue::Bool(false));
    }

    // 14. Lookup from context
    #[test]
    fn test_lookup_from_context() {
        let e = engine();
        let mut ctx = ReductionContext::new();
        ctx.bind("score", TypedValue::Nat(99));
        let term = CombinatorTerm::Lookup { key: "score".to_string() };
        let trace = e.reduce(term, &ctx, "test-lookup");
        assert_eq!(trace.final_value, TypedValue::Nat(99));
    }

    // 15. Lookup missing key → stays unreduced (Unit)
    #[test]
    fn test_lookup_missing_key() {
        let e = engine();
        let term = CombinatorTerm::Lookup { key: "nonexistent".to_string() };
        let trace = e.reduce(term, &empty_ctx(), "test-lookup-miss");
        assert_eq!(trace.final_value, TypedValue::Unit);
    }

    // 16. ForAll over domain (all true)
    #[test]
    fn test_forall_all_true() {
        let e = engine();
        let mut ctx = ReductionContext::new();
        ctx.set_domain("scores", vec![
            TypedValue::Nat(50),
            TypedValue::Nat(60),
            TypedValue::Nat(70),
        ]);
        ctx.bind("threshold", TypedValue::Nat(40));
        // ForAll x in scores: x >= threshold
        let body = CombinatorTerm::app2(
            CombinatorTerm::GreaterThanOrEqual,
            CombinatorTerm::Lookup { key: "x".to_string() },
            CombinatorTerm::Lookup { key: "threshold".to_string() },
        );
        let term = CombinatorTerm::app(
            CombinatorTerm::ForAll { variable: "x".to_string(), domain: "scores".to_string() },
            body,
        );
        let trace = e.reduce(term, &ctx, "test-forall-true");
        assert_eq!(trace.final_value, TypedValue::Bool(true));
    }

    // 17. ForAll over domain (one false)
    #[test]
    fn test_forall_one_false() {
        let e = engine();
        let mut ctx = ReductionContext::new();
        ctx.set_domain("scores", vec![
            TypedValue::Nat(50),
            TypedValue::Nat(20), // below threshold
            TypedValue::Nat(70),
        ]);
        ctx.bind("threshold", TypedValue::Nat(40));
        let body = CombinatorTerm::app2(
            CombinatorTerm::GreaterThanOrEqual,
            CombinatorTerm::Lookup { key: "x".to_string() },
            CombinatorTerm::Lookup { key: "threshold".to_string() },
        );
        let term = CombinatorTerm::app(
            CombinatorTerm::ForAll { variable: "x".to_string(), domain: "scores".to_string() },
            body,
        );
        let trace = e.reduce(term, &ctx, "test-forall-false");
        assert_eq!(trace.final_value, TypedValue::Bool(false));
    }

    // 18. Exists over domain (at least one true)
    #[test]
    fn test_exists_one_true() {
        let e = engine();
        let mut ctx = ReductionContext::new();
        ctx.set_domain("values", vec![
            TypedValue::Nat(1),
            TypedValue::Nat(2),
            TypedValue::Nat(42),
        ]);
        // Exists x in values: x == 42
        let body = CombinatorTerm::app2(
            CombinatorTerm::Equals,
            CombinatorTerm::Lookup { key: "x".to_string() },
            CombinatorTerm::Reduced(TypedValue::Nat(42)),
        );
        let term = CombinatorTerm::app(
            CombinatorTerm::Exists { variable: "x".to_string(), domain: "values".to_string() },
            body,
        );
        let trace = e.reduce(term, &ctx, "test-exists-true");
        assert_eq!(trace.final_value, TypedValue::Bool(true));
    }

    // 19. Exists over domain (all false)
    #[test]
    fn test_exists_all_false() {
        let e = engine();
        let mut ctx = ReductionContext::new();
        ctx.set_domain("values", vec![
            TypedValue::Nat(1),
            TypedValue::Nat(2),
            TypedValue::Nat(3),
        ]);
        let body = CombinatorTerm::app2(
            CombinatorTerm::Equals,
            CombinatorTerm::Lookup { key: "x".to_string() },
            CombinatorTerm::Reduced(TypedValue::Nat(42)),
        );
        let term = CombinatorTerm::app(
            CombinatorTerm::Exists { variable: "x".to_string(), domain: "values".to_string() },
            body,
        );
        let trace = e.reduce(term, &ctx, "test-exists-false");
        assert_eq!(trace.final_value, TypedValue::Bool(false));
    }

    // 20. INV-002: author != target → TRUE
    #[test]
    fn test_inv002_different_dids() {
        let e = engine();
        let mut ctx = ReductionContext::new();
        ctx.bind("author_did", TypedValue::Did("did:exo:alice".to_string()));
        ctx.bind("target_did", TypedValue::Did("did:exo:bob".to_string()));
        let term = encode_invariant("INV-002").unwrap();
        let trace = e.reduce(term, &ctx, "INV-002");
        assert_eq!(trace.final_value, TypedValue::Bool(true));
    }

    // 21. INV-002: author == target → FALSE
    #[test]
    fn test_inv002_same_did() {
        let e = engine();
        let mut ctx = ReductionContext::new();
        ctx.bind("author_did", TypedValue::Did("did:exo:alice".to_string()));
        ctx.bind("target_did", TypedValue::Did("did:exo:alice".to_string()));
        let term = encode_invariant("INV-002").unwrap();
        let trace = e.reduce(term, &ctx, "INV-002");
        assert_eq!(trace.final_value, TypedValue::Bool(false));
    }

    // 22. INV-005: score above floor
    #[test]
    fn test_inv005_above_floor() {
        let e = engine();
        let mut ctx = ReductionContext::new();
        ctx.bind("alignment_score", TypedValue::Nat(50));
        ctx.bind("min_alignment", TypedValue::Nat(30));
        let term = encode_invariant("INV-005").unwrap();
        let trace = e.reduce(term, &ctx, "INV-005");
        assert_eq!(trace.final_value, TypedValue::Bool(true));
    }

    // 23. INV-005: score below floor
    #[test]
    fn test_inv005_below_floor() {
        let e = engine();
        let mut ctx = ReductionContext::new();
        ctx.bind("alignment_score", TypedValue::Nat(10));
        ctx.bind("min_alignment", TypedValue::Nat(30));
        let term = encode_invariant("INV-005").unwrap();
        let trace = e.reduce(term, &ctx, "INV-005");
        assert_eq!(trace.final_value, TypedValue::Bool(false));
    }

    // 24. INV-006: audit completeness
    #[test]
    fn test_inv006_audit_completeness() {
        let e = engine();
        let mut ctx = ReductionContext::new();
        ctx.bind("audit_event_planned", TypedValue::Bool(true));
        let term = encode_invariant("INV-006").unwrap();
        let trace = e.reduce(term, &ctx, "INV-006");
        assert_eq!(trace.final_value, TypedValue::Bool(true));

        let mut ctx_false = ReductionContext::new();
        ctx_false.bind("audit_event_planned", TypedValue::Bool(false));
        let term2 = encode_invariant("INV-006").unwrap();
        let trace2 = e.reduce(term2, &ctx_false, "INV-006");
        assert_eq!(trace2.final_value, TypedValue::Bool(false));
    }

    // 25. INV-007: human override check
    #[test]
    fn test_inv007_human_override() {
        let e = engine();
        let mut ctx = ReductionContext::new();
        ctx.bind("removes_human_override", TypedValue::Bool(false));
        let term = encode_invariant("INV-007").unwrap();
        let trace = e.reduce(term, &ctx, "INV-007");
        assert_eq!(trace.final_value, TypedValue::Bool(true));

        let mut ctx_remove = ReductionContext::new();
        ctx_remove.bind("removes_human_override", TypedValue::Bool(true));
        let term2 = encode_invariant("INV-007").unwrap();
        let trace2 = e.reduce(term2, &ctx_remove, "INV-007");
        assert_eq!(trace2.final_value, TypedValue::Bool(false));
    }

    // 26. Max reduction limit prevents infinite loops
    #[test]
    fn test_max_reduction_limit() {
        // S I I (S I I) is a classic non-terminating term: Omega combinator
        // But we limit reductions so it should halt.
        let e = CombinatorEngine::new(10);
        // Build a self-application that won't terminate: (S I I (S I I))
        let sii = CombinatorTerm::app2(CombinatorTerm::S, CombinatorTerm::I, CombinatorTerm::I);
        let omega = CombinatorTerm::app(sii.clone(), sii);
        let trace = e.reduce(omega, &empty_ctx(), "test-omega");
        // Should halt without producing a Bool value
        assert!(trace.total_reductions <= 10);
    }

    // 27. Reduction trace records all steps
    #[test]
    fn test_trace_records_steps() {
        let e = engine();
        let mut ctx = ReductionContext::new();
        ctx.bind("x", TypedValue::Bool(true));
        // NOT(LOOKUP(x)) → NOT(true) → false — should be 2 steps
        let term = CombinatorTerm::app(
            CombinatorTerm::Not,
            CombinatorTerm::Lookup { key: "x".to_string() },
        );
        let trace = e.reduce(term, &ctx, "test-trace");
        assert_eq!(trace.final_value, TypedValue::Bool(false));
        assert!(trace.steps.len() >= 2);
        assert_eq!(trace.total_reductions, trace.steps.len() as u32);
        // Verify step numbers are sequential
        for (i, step) in trace.steps.iter().enumerate() {
            assert_eq!(step.step_number, (i + 1) as u32);
        }
    }

    // 28. Pretty-print produces readable output
    #[test]
    fn test_pretty_print() {
        let e = engine();
        let term = CombinatorTerm::app2(
            CombinatorTerm::And,
            CombinatorTerm::Reduced(TypedValue::Bool(true)),
            CombinatorTerm::app(
                CombinatorTerm::Not,
                CombinatorTerm::Lookup { key: "flag".to_string() },
            ),
        );
        let pp = e.pretty_print(&term);
        assert!(pp.contains("AND"));
        assert!(pp.contains("NOT"));
        assert!(pp.contains("LOOKUP(flag)"));
        assert!(pp.contains("true"));
    }
}
