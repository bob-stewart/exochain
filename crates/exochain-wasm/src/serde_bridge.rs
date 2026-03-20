//! Serde bridge helpers for converting between JsValue and Rust types.
//!
//! Centralises the `serde_json` round-trip so that every binding module
//! can share the same conversion logic without duplicating error handling.

use serde::de::DeserializeOwned;
use serde::Serialize;
use wasm_bindgen::prelude::*;

/// Deserialize a JSON string into a Rust type, returning a `JsError` on failure.
pub fn from_json_str<T: DeserializeOwned>(json: &str) -> Result<T, JsError> {
    serde_json::from_str(json).map_err(|e| JsError::new(&format!("JSON parse error: {e}")))
}

/// Serialize a Rust value to a `JsValue` via `serde_json::Value` -> `serde_wasm_bindgen`.
pub fn to_js_value<T: Serialize>(value: &T) -> Result<JsValue, JsError> {
    serde_wasm_bindgen::to_value(value)
        .map_err(|e| JsError::new(&format!("Serialization error: {e}")))
}

/// Serialize a Rust value to a JSON string.
pub fn to_json_string<T: Serialize>(value: &T) -> Result<String, JsError> {
    serde_json::to_string(value).map_err(|e| JsError::new(&format!("JSON serialize error: {e}")))
}

/// Serialize a Rust value to a pretty-printed JSON string.
#[allow(unused)]
pub fn to_json_string_pretty<T: Serialize>(value: &T) -> Result<String, JsError> {
    serde_json::to_string_pretty(value)
        .map_err(|e| JsError::new(&format!("JSON serialize error: {e}")))
}
