use exo_core::Did;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum Effect {
    Allow,
    Deny,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Policy {
    pub id: String,
    pub description: String,
    pub effect: Effect,
    pub subjects: AccessorSet,
    pub resources: Vec<String>, // Resource IDs or wildcards
    pub conditions: Vec<Condition>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum AccessorSet {
    Any,
    Specific(Vec<Did>),
    Group(String), // Group ID
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Condition {
    pub type_: String, // e.g., "MFA", "RiskScore", "TimeOfDay"
    pub value: String, // e.g., "true", ">80", "AM"
}

/// Trait for resolving group membership.
pub trait GroupResolver {
    fn is_member(&self, group_id: &str, did: &Did) -> bool;
}

/// A static group resolver backed by a HashMap.
pub struct StaticGroupResolver {
    pub groups: HashMap<String, Vec<Did>>,
}

impl StaticGroupResolver {
    pub fn new() -> Self {
        Self {
            groups: HashMap::new(),
        }
    }

    pub fn add_member(&mut self, group_id: &str, did: Did) {
        self.groups
            .entry(group_id.to_string())
            .or_default()
            .push(did);
    }
}

impl Default for StaticGroupResolver {
    fn default() -> Self {
        Self::new()
    }
}

impl GroupResolver for StaticGroupResolver {
    fn is_member(&self, group_id: &str, did: &Did) -> bool {
        self.groups
            .get(group_id)
            .map(|members| members.contains(did))
            .unwrap_or(false)
    }
}

impl Policy {
    /// Match without group resolution (backwards compatible -- Group always returns false).
    pub fn is_match(&self, sub: &Did, res: &str) -> bool {
        let subject_match = match &self.subjects {
            AccessorSet::Any => true,
            AccessorSet::Specific(dids) => dids.contains(sub),
            AccessorSet::Group(_) => false, // No resolver available
        };

        if !subject_match {
            return false;
        }

        // Resource match (exact or wildcard)
        if !self.resources.contains(&res.to_string()) && !self.resources.contains(&"*".to_string())
        {
            return false;
        }

        true
    }

    /// Match with group resolution support.
    pub fn is_match_with_resolver(
        &self,
        sub: &Did,
        res: &str,
        resolver: &dyn GroupResolver,
    ) -> bool {
        let subject_match = match &self.subjects {
            AccessorSet::Any => true,
            AccessorSet::Specific(dids) => dids.contains(sub),
            AccessorSet::Group(group_id) => resolver.is_member(group_id, sub),
        };

        if !subject_match {
            return false;
        }

        // Resource match (exact or wildcard)
        if !self.resources.contains(&res.to_string()) && !self.resources.contains(&"*".to_string())
        {
            return false;
        }

        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_policy(effect: Effect, subjects: AccessorSet, resources: Vec<&str>) -> Policy {
        Policy {
            id: "test-policy".into(),
            description: "test".into(),
            effect,
            subjects,
            resources: resources.into_iter().map(String::from).collect(),
            conditions: vec![],
        }
    }

    #[test]
    fn test_any_subject_matches() {
        let policy = make_policy(Effect::Allow, AccessorSet::Any, vec!["resource-1"]);
        assert!(policy.is_match(&"did:example:alice".into(), "resource-1"));
    }

    #[test]
    fn test_specific_subject_matches() {
        let did: Did = "did:example:alice".into();
        let policy = make_policy(Effect::Allow, AccessorSet::Specific(vec![did.clone()]), vec!["resource-1"]);
        assert!(policy.is_match(&did, "resource-1"));
    }

    #[test]
    fn test_specific_subject_no_match() {
        let policy = make_policy(
            Effect::Allow,
            AccessorSet::Specific(vec!["did:example:alice".into()]),
            vec!["resource-1"],
        );
        assert!(!policy.is_match(&"did:example:bob".into(), "resource-1"));
    }

    #[test]
    fn test_group_without_resolver_returns_false() {
        let policy = make_policy(
            Effect::Allow,
            AccessorSet::Group("admins".into()),
            vec!["resource-1"],
        );
        assert!(!policy.is_match(&"did:example:alice".into(), "resource-1"));
    }

    #[test]
    fn test_group_with_resolver_member() {
        let policy = make_policy(
            Effect::Allow,
            AccessorSet::Group("admins".into()),
            vec!["resource-1"],
        );

        let mut resolver = StaticGroupResolver::new();
        resolver.add_member("admins", "did:example:alice".into());

        assert!(policy.is_match_with_resolver(&"did:example:alice".into(), "resource-1", &resolver));
    }

    #[test]
    fn test_group_with_resolver_non_member() {
        let policy = make_policy(
            Effect::Allow,
            AccessorSet::Group("admins".into()),
            vec!["resource-1"],
        );

        let mut resolver = StaticGroupResolver::new();
        resolver.add_member("admins", "did:example:alice".into());

        assert!(!policy.is_match_with_resolver(&"did:example:bob".into(), "resource-1", &resolver));
    }

    #[test]
    fn test_group_with_resolver_unknown_group() {
        let policy = make_policy(
            Effect::Allow,
            AccessorSet::Group("unknown-group".into()),
            vec!["resource-1"],
        );

        let resolver = StaticGroupResolver::new();
        assert!(!policy.is_match_with_resolver(&"did:example:alice".into(), "resource-1", &resolver));
    }

    #[test]
    fn test_wildcard_resource() {
        let policy = make_policy(Effect::Allow, AccessorSet::Any, vec!["*"]);
        assert!(policy.is_match(&"did:example:alice".into(), "any-resource"));
    }

    #[test]
    fn test_resource_no_match() {
        let policy = make_policy(Effect::Allow, AccessorSet::Any, vec!["resource-1"]);
        assert!(!policy.is_match(&"did:example:alice".into(), "resource-2"));
    }
}
