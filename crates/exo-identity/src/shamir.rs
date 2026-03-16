//! Shamir's Secret Sharing over GF(256).
//!
//! Implements threshold secret sharing using polynomial interpolation in the
//! Galois Field GF(2^8). Each byte of the secret is split independently using
//! a random polynomial of degree `threshold - 1`. Reconstruction uses Lagrange
//! interpolation to recover the constant term (the secret byte) from any
//! `threshold`-sized subset of shares.

use exo_core::{hash_bytes, Blake3Hash};
use rand::Rng;
use thiserror::Error;

// ---------------------------------------------------------------------------
// GF(256) arithmetic using the AES/Rijndael irreducible polynomial x^8 + x^4 + x^3 + x + 1.
// ---------------------------------------------------------------------------

/// Multiplication in GF(256) using peasant multiplication (shift-and-add).
fn gf256_mul(mut a: u8, mut b: u8) -> u8 {
    let mut result: u8 = 0;
    while b > 0 {
        if b & 1 != 0 {
            result ^= a;
        }
        let hi = a & 0x80;
        a <<= 1;
        if hi != 0 {
            a ^= 0x1b; // x^8 + x^4 + x^3 + x + 1
        }
        b >>= 1;
    }
    result
}

/// Addition in GF(256) is XOR.
#[inline]
fn gf256_add(a: u8, b: u8) -> u8 {
    a ^ b
}

/// Multiplicative inverse in GF(256) via exponentiation: a^254 = a^(-1).
fn gf256_inv(a: u8) -> u8 {
    if a == 0 {
        return 0; // 0 has no inverse; caller must avoid
    }
    // a^(2^8 - 2) = a^254 by Fermat's little theorem in GF(2^8)
    let mut result = a;
    for _ in 0..6 {
        result = gf256_mul(result, result);
        result = gf256_mul(result, a);
    }
    // After loop: result = a^(2^7 - 1) * step -- let's just do explicit exponentiation
    // Actually recompute cleanly:
    // a^254 = ((a^2)^127) but simpler: repeated square-and-multiply
    gf256_pow(a, 254)
}

/// Exponentiation in GF(256) via square-and-multiply.
fn gf256_pow(base: u8, mut exp: u8) -> u8 {
    if exp == 0 {
        return 1;
    }
    let mut result: u8 = 1;
    let mut b = base;
    while exp > 0 {
        if exp & 1 != 0 {
            result = gf256_mul(result, b);
        }
        b = gf256_mul(b, b);
        exp >>= 1;
    }
    result
}

// ---------------------------------------------------------------------------
// Shamir types
// ---------------------------------------------------------------------------

/// Errors that can occur during Shamir secret sharing operations.
#[derive(Error, Debug, Clone, PartialEq, Eq)]
pub enum ShamirError {
    #[error("Insufficient shares: need {need}, got {got}")]
    InsufficientShares { need: usize, got: usize },

    #[error("Invalid share: integrity check failed for share index {0}")]
    InvalidShare(u8),

    #[error("Duplicate share index: {0}")]
    DuplicateIndex(u8),

    #[error("Threshold ({threshold}) exceeds total shares ({total})")]
    ThresholdExceedsShares { threshold: usize, total: usize },

    #[error("Threshold must be at least 1")]
    ZeroThreshold,
}

/// A single share produced by Shamir splitting.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Share {
    /// Share evaluation point (1..=N, never 0).
    pub index: u8,
    /// Share data: one byte per byte of original secret, evaluated at `index`.
    pub data: Vec<u8>,
    /// Blake3 hash over (index || data) for integrity verification.
    pub share_hash: Blake3Hash,
}

impl Share {
    /// Compute the integrity hash for this share.
    fn compute_hash(index: u8, data: &[u8]) -> Blake3Hash {
        let mut preimage = Vec::with_capacity(1 + data.len());
        preimage.push(index);
        preimage.extend_from_slice(data);
        hash_bytes(&preimage)
    }

    /// Verify the integrity of this share against its stored hash.
    pub fn verify_integrity(&self) -> bool {
        let expected = Self::compute_hash(self.index, &self.data);
        self.share_hash == expected
    }
}

/// Configuration for a Shamir secret sharing scheme.
#[derive(Clone, Debug)]
pub struct ShamirScheme {
    /// Minimum number of shares required for reconstruction.
    pub threshold: usize,
    /// Total number of shares to generate.
    pub total_shares: usize,
}

impl ShamirScheme {
    /// Create a new scheme with the given threshold and total share count.
    pub fn new(threshold: usize, total_shares: usize) -> Result<Self, ShamirError> {
        if threshold == 0 {
            return Err(ShamirError::ZeroThreshold);
        }
        if threshold > total_shares {
            return Err(ShamirError::ThresholdExceedsShares {
                threshold,
                total: total_shares,
            });
        }
        if total_shares > 255 {
            return Err(ShamirError::ThresholdExceedsShares {
                threshold,
                total: total_shares,
            });
        }
        Ok(Self {
            threshold,
            total_shares,
        })
    }
}

/// Split a secret into `total_shares` shares, any `threshold` of which can
/// reconstruct the original secret.
///
/// Each byte of the secret is independently encoded as the constant term of
/// a random polynomial of degree `threshold - 1` over GF(256). Shares are
/// evaluations of that polynomial at x = 1, 2, ..., total_shares.
pub fn split_secret(
    secret: &[u8],
    threshold: usize,
    total_shares: usize,
) -> Result<Vec<Share>, ShamirError> {
    let scheme = ShamirScheme::new(threshold, total_shares)?;
    let mut rng = rand::thread_rng();

    // Pre-allocate share data vectors.
    let mut share_data: Vec<Vec<u8>> = (0..scheme.total_shares)
        .map(|_| Vec::with_capacity(secret.len()))
        .collect();

    for &secret_byte in secret {
        // Build a random polynomial: coefficients[0] = secret_byte, rest random.
        let mut coeffs = vec![0u8; scheme.threshold];
        coeffs[0] = secret_byte;
        for coeff in coeffs.iter_mut().skip(1) {
            *coeff = rng.gen();
        }

        // Evaluate polynomial at x = 1, 2, ..., total_shares.
        for (i, share_vec) in share_data.iter_mut().enumerate() {
            let x = (i + 1) as u8;
            let y = eval_polynomial(&coeffs, x);
            share_vec.push(y);
        }
    }

    // Build Share structs with integrity hashes.
    let shares = share_data
        .into_iter()
        .enumerate()
        .map(|(i, data)| {
            let index = (i + 1) as u8;
            let share_hash = Share::compute_hash(index, &data);
            Share {
                index,
                data,
                share_hash,
            }
        })
        .collect();

    Ok(shares)
}

/// Reconstruct the secret from a set of shares using Lagrange interpolation.
///
/// Requires at least `threshold` shares. All shares must have consistent data
/// lengths and unique indices.
pub fn reconstruct_secret(shares: &[Share], threshold: usize) -> Result<Vec<u8>, ShamirError> {
    if threshold == 0 {
        return Err(ShamirError::ZeroThreshold);
    }
    if shares.len() < threshold {
        return Err(ShamirError::InsufficientShares {
            need: threshold,
            got: shares.len(),
        });
    }

    // Verify integrity of each share.
    for share in shares {
        if !share.verify_integrity() {
            return Err(ShamirError::InvalidShare(share.index));
        }
    }

    // Check for duplicate indices.
    let used = &shares[..threshold];
    for i in 0..used.len() {
        for j in (i + 1)..used.len() {
            if used[i].index == used[j].index {
                return Err(ShamirError::DuplicateIndex(used[i].index));
            }
        }
    }

    let secret_len = used[0].data.len();
    let mut secret = vec![0u8; secret_len];

    // Lagrange interpolation at x = 0 for each byte position.
    for (byte_idx, secret_byte) in secret.iter_mut().enumerate() {
        let mut value = 0u8;

        for (i, share_i) in used.iter().enumerate() {
            let x_i = share_i.index;
            let y_i = share_i.data[byte_idx];

            // Compute Lagrange basis polynomial L_i(0).
            let mut numerator = 1u8;
            let mut denominator = 1u8;

            for (j, share_j) in used.iter().enumerate() {
                if i == j {
                    continue;
                }
                let x_j = share_j.index;
                // L_i(0) = product over j!=i of (0 - x_j) / (x_i - x_j)
                numerator = gf256_mul(numerator, x_j); // 0 ^ x_j = x_j in GF(256)
                denominator = gf256_mul(denominator, gf256_add(x_i, x_j));
            }

            let basis = gf256_mul(numerator, gf256_inv(denominator));
            value = gf256_add(value, gf256_mul(y_i, basis));
        }

        *secret_byte = value;
    }

    Ok(secret)
}

/// Evaluate a polynomial at `x` in GF(256) using Horner's method.
fn eval_polynomial(coeffs: &[u8], x: u8) -> u8 {
    // coeffs[0] + coeffs[1]*x + coeffs[2]*x^2 + ...
    // Horner's: (...((c_n * x + c_{n-1}) * x + c_{n-2}) * x + ... ) * x + c_0
    let mut result = 0u8;
    for &coeff in coeffs.iter().rev() {
        result = gf256_add(gf256_mul(result, x), coeff);
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_gf256_basics() {
        // Additive identity
        assert_eq!(gf256_add(0, 0), 0);
        assert_eq!(gf256_add(42, 0), 42);
        // Self-inverse of addition
        assert_eq!(gf256_add(42, 42), 0);
        // Multiplicative identity
        assert_eq!(gf256_mul(42, 1), 42);
        assert_eq!(gf256_mul(1, 42), 42);
        // Multiply by zero
        assert_eq!(gf256_mul(42, 0), 0);
        // Inverse
        for a in 1..=255u8 {
            let inv = gf256_inv(a);
            assert_eq!(gf256_mul(a, inv), 1, "inverse failed for {a}");
        }
    }

    #[test]
    fn test_split_reconstruct_roundtrip() {
        let secret = b"hello, shamir!";
        let shares = split_secret(secret, 3, 5).unwrap();
        assert_eq!(shares.len(), 5);

        let recovered = reconstruct_secret(&shares[..3], 3).unwrap();
        assert_eq!(recovered, secret);
    }

    #[test]
    fn test_any_3_of_5_subset_works() {
        let secret = b"any subset should work";
        let shares = split_secret(secret, 3, 5).unwrap();

        // Try all C(5,3) = 10 subsets.
        let indices: Vec<Vec<usize>> = vec![
            vec![0, 1, 2],
            vec![0, 1, 3],
            vec![0, 1, 4],
            vec![0, 2, 3],
            vec![0, 2, 4],
            vec![0, 3, 4],
            vec![1, 2, 3],
            vec![1, 2, 4],
            vec![1, 3, 4],
            vec![2, 3, 4],
        ];

        for subset in &indices {
            let sub_shares: Vec<Share> = subset.iter().map(|&i| shares[i].clone()).collect();
            let recovered = reconstruct_secret(&sub_shares, 3).unwrap();
            assert_eq!(
                recovered, secret,
                "Failed with subset {:?}",
                subset
            );
        }
    }

    #[test]
    fn test_fails_with_insufficient_shares() {
        let secret = b"need three";
        let shares = split_secret(secret, 3, 5).unwrap();

        let result = reconstruct_secret(&shares[..2], 3);
        assert!(matches!(
            result,
            Err(ShamirError::InsufficientShares { need: 3, got: 2 })
        ));
    }

    #[test]
    fn test_integrity_hash_verification() {
        let secret = b"integrity check";
        let shares = split_secret(secret, 3, 5).unwrap();

        // Valid shares pass integrity check.
        for share in &shares {
            assert!(share.verify_integrity());
        }

        // Tampered share fails integrity check.
        let mut tampered = shares[0].clone();
        tampered.data[0] ^= 0xff;
        assert!(!tampered.verify_integrity());

        // Reconstruction rejects tampered share.
        let bad_shares = vec![tampered, shares[1].clone(), shares[2].clone()];
        let result = reconstruct_secret(&bad_shares, 3);
        assert!(matches!(result, Err(ShamirError::InvalidShare(_))));
    }

    #[test]
    fn test_different_secret_lengths() {
        // Empty secret
        let shares = split_secret(b"", 2, 3).unwrap();
        let recovered = reconstruct_secret(&shares[..2], 2).unwrap();
        assert_eq!(recovered, b"");

        // Single byte
        let shares = split_secret(&[42], 2, 3).unwrap();
        let recovered = reconstruct_secret(&shares[..2], 2).unwrap();
        assert_eq!(recovered, &[42]);

        // Large secret (256 bytes)
        let big_secret: Vec<u8> = (0..=255).collect();
        let shares = split_secret(&big_secret, 3, 5).unwrap();
        let recovered = reconstruct_secret(&shares[..3], 3).unwrap();
        assert_eq!(recovered, big_secret);
    }

    #[test]
    fn test_edge_case_threshold_equals_total() {
        let secret = b"all shares needed";
        let shares = split_secret(secret, 5, 5).unwrap();
        let recovered = reconstruct_secret(&shares, 5).unwrap();
        assert_eq!(recovered, secret);

        // 4 of 5 should give wrong result (or at least not guaranteed correct).
        // We don't test the output value, just that it *can* be called.
    }

    #[test]
    fn test_edge_case_threshold_one() {
        // With threshold 1, each share IS the secret.
        let secret = b"plain copy";
        let shares = split_secret(secret, 1, 5).unwrap();
        for share in &shares {
            assert_eq!(share.data, secret);
        }
        let recovered = reconstruct_secret(&shares[..1], 1).unwrap();
        assert_eq!(recovered, secret);
    }

    #[test]
    fn test_duplicate_index_rejected() {
        let secret = b"dup test";
        let shares = split_secret(secret, 3, 5).unwrap();

        let dup_shares = vec![shares[0].clone(), shares[0].clone(), shares[2].clone()];
        let result = reconstruct_secret(&dup_shares, 3);
        assert!(matches!(result, Err(ShamirError::DuplicateIndex(_))));
    }

    #[test]
    fn test_invalid_params() {
        assert!(matches!(
            split_secret(b"x", 0, 5),
            Err(ShamirError::ZeroThreshold)
        ));
        assert!(matches!(
            split_secret(b"x", 6, 5),
            Err(ShamirError::ThresholdExceedsShares { .. })
        ));
    }

    #[test]
    fn test_share_indices_start_at_one() {
        let shares = split_secret(b"idx", 2, 4).unwrap();
        let indices: Vec<u8> = shares.iter().map(|s| s.index).collect();
        assert_eq!(indices, vec![1, 2, 3, 4]);
    }
}
