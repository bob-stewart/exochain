//! WASM bindings for exo-core cryptographic primitives and event ID computation.
//!
//! Exposes BLAKE3 hashing, Ed25519 signing/verification, keypair generation,
//! and canonical event ID computation to JavaScript/TypeScript consumers.

use crate::serde_bridge;
use exo_core::crypto::{hash_bytes, compute_signature, verify_signature, Blake3Hash};
use exo_core::event::{compute_event_id, EventEnvelope};
use ed25519_dalek::{SigningKey, VerifyingKey, Signature};
use serde::{Deserialize, Serialize};
use wasm_bindgen::prelude::*;

// ---------------------------------------------------------------------------
// Intermediate serde types for key/signature transport
// ---------------------------------------------------------------------------

#[derive(Serialize, Deserialize)]
struct KeyPairResult {
    /// Hex-encoded 32-byte secret key seed.
    secret_key: String,
    /// Hex-encoded 32-byte public key.
    public_key: String,
}

#[derive(Serialize, Deserialize)]
struct SignatureResult {
    /// Hex-encoded 64-byte Ed25519 signature.
    signature: String,
}

#[derive(Serialize, Deserialize)]
struct VerifyResult {
    valid: bool,
}

#[derive(Serialize, Deserialize)]
struct HashResult {
    /// Hex-encoded 32-byte BLAKE3 hash.
    hash: String,
}

#[derive(Serialize, Deserialize)]
struct EventIdResult {
    /// Hex-encoded 32-byte event ID.
    event_id: String,
}

// ---------------------------------------------------------------------------
// WASM exports
// ---------------------------------------------------------------------------

/// Compute the BLAKE3 hash of the given hex-encoded byte string.
///
/// **Input:** hex-encoded bytes (string)
/// **Output:** JSON `{ "hash": "<hex>" }`
#[wasm_bindgen]
pub fn wasm_hash_bytes(hex_data: &str) -> Result<JsValue, JsError> {
    let data = hex::decode(hex_data)
        .map_err(|e| JsError::new(&format!("Invalid hex input: {e}")))?;
    let hash = hash_bytes(&data);
    let result = HashResult {
        hash: hex::encode(hash.0),
    };
    serde_bridge::to_js_value(&result)
}

/// Compute an Ed25519 signature over an event ID using domain-separated signing (Spec 9.1).
///
/// **Inputs:**
/// - `secret_key_hex`: hex-encoded 32-byte Ed25519 secret key seed
/// - `event_id_hex`: hex-encoded 32-byte event ID (BLAKE3 hash)
///
/// **Output:** JSON `{ "signature": "<hex>" }`
#[wasm_bindgen]
pub fn wasm_compute_signature(
    secret_key_hex: &str,
    event_id_hex: &str,
) -> Result<JsValue, JsError> {
    let sk_bytes = hex_to_32_bytes(secret_key_hex, "secret_key")?;
    let event_id_bytes = hex_to_32_bytes(event_id_hex, "event_id")?;

    let signing_key = SigningKey::from_bytes(&sk_bytes);
    let event_id = Blake3Hash(event_id_bytes);
    let sig = compute_signature(&signing_key, &event_id);

    let result = SignatureResult {
        signature: hex::encode(sig.to_bytes()),
    };
    serde_bridge::to_js_value(&result)
}

/// Verify an Ed25519 signature over an event ID using domain-separated verification (Spec 9.1).
///
/// **Inputs:**
/// - `public_key_hex`: hex-encoded 32-byte Ed25519 public key
/// - `event_id_hex`: hex-encoded 32-byte event ID (BLAKE3 hash)
/// - `signature_hex`: hex-encoded 64-byte Ed25519 signature
///
/// **Output:** JSON `{ "valid": true|false }`
#[wasm_bindgen]
pub fn wasm_verify_signature(
    public_key_hex: &str,
    event_id_hex: &str,
    signature_hex: &str,
) -> Result<JsValue, JsError> {
    let pk_bytes = hex_to_32_bytes(public_key_hex, "public_key")?;
    let event_id_bytes = hex_to_32_bytes(event_id_hex, "event_id")?;
    let sig_bytes = hex::decode(signature_hex)
        .map_err(|e| JsError::new(&format!("Invalid hex signature: {e}")))?;

    let public_key = VerifyingKey::from_bytes(&pk_bytes)
        .map_err(|e| JsError::new(&format!("Invalid public key: {e}")))?;
    let event_id = Blake3Hash(event_id_bytes);
    let signature = Signature::from_slice(&sig_bytes)
        .map_err(|e| JsError::new(&format!("Invalid signature bytes: {e}")))?;

    let valid = verify_signature(&public_key, &event_id, &signature).is_ok();
    let result = VerifyResult { valid };
    serde_bridge::to_js_value(&result)
}

/// Generate a new Ed25519 keypair suitable for ExoChain signing.
///
/// **Output:** JSON `{ "secret_key": "<hex>", "public_key": "<hex>" }`
#[wasm_bindgen]
pub fn wasm_generate_keypair() -> Result<JsValue, JsError> {
    let mut csprng = rand::rngs::OsRng;
    let signing_key = SigningKey::generate(&mut csprng);
    let public_key = signing_key.verifying_key();

    let result = KeyPairResult {
        secret_key: hex::encode(signing_key.to_bytes()),
        public_key: hex::encode(public_key.to_bytes()),
    };
    serde_bridge::to_js_value(&result)
}

/// Compute the canonical event ID for an EventEnvelope (CBOR-hash).
///
/// **Input:** JSON-serialized `EventEnvelope`
/// **Output:** JSON `{ "event_id": "<hex>" }`
#[wasm_bindgen]
pub fn wasm_compute_event_id(envelope_json: &str) -> Result<JsValue, JsError> {
    let envelope: EventEnvelope = serde_bridge::from_json_str(envelope_json)?;
    let event_id = compute_event_id(&envelope)
        .map_err(|e| JsError::new(&format!("CBOR encoding error: {e}")))?;
    let result = EventIdResult {
        event_id: hex::encode(event_id.0),
    };
    serde_bridge::to_js_value(&result)
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn hex_to_32_bytes(hex_str: &str, field_name: &str) -> Result<[u8; 32], JsError> {
    let bytes = hex::decode(hex_str)
        .map_err(|e| JsError::new(&format!("Invalid hex {field_name}: {e}")))?;
    let array: [u8; 32] = bytes
        .try_into()
        .map_err(|_| JsError::new(&format!("{field_name} must be exactly 32 bytes")))?;
    Ok(array)
}
