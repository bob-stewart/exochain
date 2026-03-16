use super::decision_object::DecisionClass;

/// Reference to the governing constitution and its governance parameters.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ConstitutionRef {
    pub hash: String,
    pub version: String,
    pub human_gate_classes: Vec<DecisionClass>,
    pub max_delegation_depth: u32,
    pub ai_ceiling_class: DecisionClass,
}

/// Returns a sensible default constitution for genesis / testing.
pub fn default_constitution() -> ConstitutionRef {
    ConstitutionRef {
        hash: "genesis-constitution-hash".to_string(),
        version: "1.0.0".to_string(),
        human_gate_classes: vec![DecisionClass::Strategic, DecisionClass::Constitutional],
        max_delegation_depth: 5,
        ai_ceiling_class: DecisionClass::Operational,
    }
}
