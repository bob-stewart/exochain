use exo_core::{hash_bytes, Blake3Hash};
use std::collections::HashMap;

/// Domain separator for SMT leaf hashing.
const DOMAIN_SEP: &[u8] = b"EXOCHAIN-SMT-v1";

/// Proof of membership or non-membership in the SMT.
#[derive(Debug, Clone)]
pub struct SmtProof {
    /// Sibling hashes along the path from leaf to root.
    /// Each entry is (sibling_hash, is_left) where is_left indicates
    /// whether the sibling is on the left side.
    pub siblings: Vec<(Blake3Hash, bool)>,
}

/// Sparse Merkle Tree (Enhanced).
/// Used for State Root.
/// Key = Hash(Key), Value = Hash(Value).
#[derive(Default, Debug)]
pub struct Smt {
    pub leaves: HashMap<Blake3Hash, Blake3Hash>,
}

impl Smt {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn update(&mut self, key: Blake3Hash, value: Blake3Hash) {
        self.leaves.insert(key, value);
    }

    /// Get a value by key.
    pub fn get(&self, key: &Blake3Hash) -> Option<&Blake3Hash> {
        self.leaves.get(key)
    }

    /// Remove a key-value pair, returning the old value if present.
    pub fn remove(&mut self, key: &Blake3Hash) -> Option<Blake3Hash> {
        self.leaves.remove(key)
    }

    /// Return the number of entries in the tree.
    pub fn len(&self) -> usize {
        self.leaves.len()
    }

    /// Check if the tree is empty.
    pub fn is_empty(&self) -> bool {
        self.leaves.is_empty()
    }

    /// Check if the tree contains a key.
    pub fn contains_key(&self, key: &Blake3Hash) -> bool {
        self.leaves.contains_key(key)
    }

    /// Hash a leaf with domain separation: BLAKE3(DOMAIN_SEP || key || value)
    fn hash_leaf(key: &Blake3Hash, value: &Blake3Hash) -> Blake3Hash {
        let mut buf = Vec::with_capacity(DOMAIN_SEP.len() + 64);
        buf.extend_from_slice(DOMAIN_SEP);
        buf.extend_from_slice(&key.0);
        buf.extend_from_slice(&value.0);
        hash_bytes(&buf)
    }

    /// Hash two children: BLAKE3(left || right)
    fn hash_branch(left: &Blake3Hash, right: &Blake3Hash) -> Blake3Hash {
        let mut buf = Vec::with_capacity(64);
        buf.extend_from_slice(&left.0);
        buf.extend_from_slice(&right.0);
        hash_bytes(&buf)
    }

    /// Build the sorted keys and leaf hashes, returning (sorted_keys, leaf_hashes).
    fn build_leaves(&self) -> (Vec<Blake3Hash>, Vec<Blake3Hash>) {
        let mut sorted_keys: Vec<Blake3Hash> = self.leaves.keys().copied().collect();
        sorted_keys.sort();

        let leaf_hashes: Vec<Blake3Hash> = sorted_keys
            .iter()
            .map(|k| {
                let v = self.leaves.get(k).unwrap();
                Self::hash_leaf(k, v)
            })
            .collect();

        (sorted_keys, leaf_hashes)
    }

    /// Compute root by sorting keys and building a Merkle tree with domain separation.
    pub fn get_root(&self) -> Blake3Hash {
        if self.leaves.is_empty() {
            return Blake3Hash([0u8; 32]);
        }

        let (_, leaf_hashes) = self.build_leaves();
        Self::merkleize(&leaf_hashes)
    }

    /// Merkleize a list of hashes into a single root.
    fn merkleize(hashes: &[Blake3Hash]) -> Blake3Hash {
        if hashes.is_empty() {
            return Blake3Hash([0u8; 32]);
        }

        let mut current_level = hashes.to_vec();

        while current_level.len() > 1 {
            let mut next_level = Vec::new();
            for chunk in current_level.chunks(2) {
                if chunk.len() == 2 {
                    next_level.push(Self::hash_branch(&chunk[0], &chunk[1]));
                } else {
                    // Promote odd node
                    next_level.push(chunk[0]);
                }
            }
            current_level = next_level;
        }

        current_level[0]
    }

    /// Generate a membership or non-membership proof for a key.
    pub fn generate_proof(&self, key: &Blake3Hash) -> SmtProof {
        if self.leaves.is_empty() {
            return SmtProof {
                siblings: vec![],
            };
        }

        let (sorted_keys, leaf_hashes) = self.build_leaves();

        // Find the index of this key in sorted order
        let key_index = sorted_keys.iter().position(|k| k == key);

        // If the key is not present, we still produce a proof for the
        // position where it would be (non-membership proof).
        let target_index = match key_index {
            Some(idx) => idx,
            None => {
                // For non-membership, find the insertion point
                sorted_keys
                    .binary_search(key)
                    .unwrap_or_else(|pos| pos.min(sorted_keys.len().saturating_sub(1)))
            }
        };

        // Build the proof by collecting sibling hashes up the tree
        let mut siblings = Vec::new();
        let mut current_level = leaf_hashes;
        let mut idx = target_index;

        while current_level.len() > 1 {
            let sibling_idx = if idx % 2 == 0 { idx + 1 } else { idx - 1 };

            if sibling_idx < current_level.len() {
                // is_left: true if sibling is on the left (i.e., idx is odd)
                let is_left = idx % 2 == 1;
                siblings.push((current_level[sibling_idx], is_left));
            }
            // No sibling (odd node promoted) — no entry needed

            // Move up
            let mut next_level = Vec::new();
            for chunk in current_level.chunks(2) {
                if chunk.len() == 2 {
                    next_level.push(Self::hash_branch(&chunk[0], &chunk[1]));
                } else {
                    next_level.push(chunk[0]);
                }
            }
            current_level = next_level;
            idx /= 2;
        }

        SmtProof { siblings }
    }

    /// Verify a membership/non-membership proof.
    /// For membership: value is Some(v), for non-membership: value is None.
    pub fn verify_proof(
        root: &Blake3Hash,
        key: &Blake3Hash,
        value: Option<&Blake3Hash>,
        proof: &SmtProof,
    ) -> bool {
        // Compute the leaf hash
        let mut current = match value {
            Some(v) => Self::hash_leaf(key, v),
            None => {
                // For non-membership proofs, verification is more nuanced.
                // A simple approach: if value is None and there are no siblings,
                // the root should be the empty root.
                if proof.siblings.is_empty() {
                    return *root == Blake3Hash([0u8; 32]);
                }
                // Non-membership proofs in this simplified SMT are not fully
                // supported — return false for now unless it's an empty tree.
                return false;
            }
        };

        // Walk up the tree using siblings
        for (sibling, is_left) in &proof.siblings {
            if *is_left {
                current = Self::hash_branch(sibling, &current);
            } else {
                current = Self::hash_branch(&current, sibling);
            }
        }

        current == *root
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_hash(byte: u8) -> Blake3Hash {
        Blake3Hash([byte; 32])
    }

    #[test]
    fn test_empty_tree() {
        let smt = Smt::new();
        assert!(smt.is_empty());
        assert_eq!(smt.len(), 0);
        assert_eq!(smt.get_root(), Blake3Hash([0u8; 32]));
    }

    #[test]
    fn test_insert_and_get() {
        let mut smt = Smt::new();
        let key = make_hash(1);
        let val = make_hash(2);

        smt.update(key, val);
        assert_eq!(smt.get(&key), Some(&val));
        assert!(smt.contains_key(&key));
        assert_eq!(smt.len(), 1);
        assert!(!smt.is_empty());
    }

    #[test]
    fn test_remove() {
        let mut smt = Smt::new();
        let key = make_hash(1);
        let val = make_hash(2);

        smt.update(key, val);
        assert_eq!(smt.remove(&key), Some(val));
        assert!(smt.is_empty());
        assert!(!smt.contains_key(&key));
    }

    #[test]
    fn test_root_deterministic() {
        let mut smt1 = Smt::new();
        let mut smt2 = Smt::new();

        // Insert in different order, should get same root
        let k1 = make_hash(1);
        let v1 = make_hash(10);
        let k2 = make_hash(2);
        let v2 = make_hash(20);

        smt1.update(k1, v1);
        smt1.update(k2, v2);

        smt2.update(k2, v2);
        smt2.update(k1, v1);

        assert_eq!(smt1.get_root(), smt2.get_root());
    }

    #[test]
    fn test_root_changes_on_update() {
        let mut smt = Smt::new();
        let k1 = make_hash(1);
        let v1 = make_hash(10);

        smt.update(k1, v1);
        let root1 = smt.get_root();

        let v2 = make_hash(20);
        smt.update(k1, v2);
        let root2 = smt.get_root();

        assert_ne!(root1, root2);
    }

    #[test]
    fn test_domain_separation_in_root() {
        // Verify that the root uses domain separation by checking
        // it differs from a naive hash(k||v) approach
        let mut smt = Smt::new();
        let key = make_hash(1);
        let val = make_hash(2);
        smt.update(key, val);

        let root = smt.get_root();

        // Naive hash without domain sep
        let mut buf = Vec::with_capacity(64);
        buf.extend_from_slice(&key.0);
        buf.extend_from_slice(&val.0);
        let naive = hash_bytes(&buf);

        assert_ne!(root, naive, "Root should use domain separation");
    }

    #[test]
    fn test_membership_proof_single() {
        let mut smt = Smt::new();
        let key = make_hash(1);
        let val = make_hash(10);
        smt.update(key, val);

        let root = smt.get_root();
        let proof = smt.generate_proof(&key);

        assert!(Smt::verify_proof(&root, &key, Some(&val), &proof));
    }

    #[test]
    fn test_membership_proof_multiple() {
        let mut smt = Smt::new();
        let k1 = make_hash(1);
        let v1 = make_hash(10);
        let k2 = make_hash(2);
        let v2 = make_hash(20);
        let k3 = make_hash(3);
        let v3 = make_hash(30);

        smt.update(k1, v1);
        smt.update(k2, v2);
        smt.update(k3, v3);

        let root = smt.get_root();

        for (k, v) in &[(k1, v1), (k2, v2), (k3, v3)] {
            let proof = smt.generate_proof(k);
            assert!(
                Smt::verify_proof(&root, k, Some(v), &proof),
                "Proof verification failed for key {:?}",
                k
            );
        }
    }

    #[test]
    fn test_proof_fails_with_wrong_value() {
        let mut smt = Smt::new();
        let key = make_hash(1);
        let val = make_hash(10);
        let wrong_val = make_hash(99);

        smt.update(key, val);
        let root = smt.get_root();
        let proof = smt.generate_proof(&key);

        assert!(!Smt::verify_proof(&root, &key, Some(&wrong_val), &proof));
    }

    #[test]
    fn test_proof_fails_with_wrong_root() {
        let mut smt = Smt::new();
        let key = make_hash(1);
        let val = make_hash(10);

        smt.update(key, val);
        let proof = smt.generate_proof(&key);

        let wrong_root = make_hash(99);
        assert!(!Smt::verify_proof(&wrong_root, &key, Some(&val), &proof));
    }

    #[test]
    fn test_non_membership_empty_tree() {
        let smt = Smt::new();
        let key = make_hash(1);
        let root = smt.get_root();
        let proof = smt.generate_proof(&key);

        assert!(Smt::verify_proof(&root, &key, None, &proof));
    }

    #[test]
    fn test_membership_proof_even_count() {
        let mut smt = Smt::new();
        let k1 = make_hash(1);
        let v1 = make_hash(10);
        let k2 = make_hash(2);
        let v2 = make_hash(20);
        let k3 = make_hash(3);
        let v3 = make_hash(30);
        let k4 = make_hash(4);
        let v4 = make_hash(40);

        smt.update(k1, v1);
        smt.update(k2, v2);
        smt.update(k3, v3);
        smt.update(k4, v4);

        let root = smt.get_root();

        for (k, v) in &[(k1, v1), (k2, v2), (k3, v3), (k4, v4)] {
            let proof = smt.generate_proof(k);
            assert!(
                Smt::verify_proof(&root, k, Some(v), &proof),
                "Proof verification failed for key {:?}",
                k
            );
        }
    }
}
