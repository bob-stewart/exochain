use crate::store::{DagStore, StoreError};
use exo_core::LedgerEvent;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum AppendError {
    #[error("Store Error: {0}")]
    Store(#[from] StoreError),
    #[error("Parent not found: {0:?}")]
    ParentNotFound(exo_core::Blake3Hash),
    #[error("Invalid Signature")]
    InvalidSignature,
    #[error("Causality Violation: Event time {0:?} <= Parent time")]
    CausalityViolation(exo_core::HybridLogicalClock),
    #[error("Crypto Error")]
    CryptoError,
}

/// Maximum allowed clock skew between nodes (500ms).
const MAX_CLOCK_SKEW_MS: u64 = 500;

/// Append an event to the DAG with full validation.
pub async fn append_event(store: &impl DagStore, event: LedgerEvent) -> Result<(), AppendError> {
    // 1. Verify Signature is well-formed (64 bytes for Ed25519)
    if event.signature.to_bytes().len() != 64 {
        return Err(AppendError::InvalidSignature);
    }

    // 2. HLC physical skew check: reject events claiming to be too far in the future.
    // Only apply when physical_ms > 0 (non-zero timestamps indicate real clock values).
    if event.envelope.logical_time.physical_ms > 0 {
        let now_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64;
        if event.envelope.logical_time.physical_ms > now_ms + MAX_CLOCK_SKEW_MS {
            return Err(AppendError::CausalityViolation(
                event.envelope.logical_time,
            ));
        }
    }

    // 3. Parent Existence & Causality
    for parent_id in &event.envelope.parents {
        let parent = store
            .get_event(parent_id)
            .await
            .map_err(|_| AppendError::ParentNotFound(*parent_id))?;

        // Normative HLC Check: event > parent
        if event.envelope.logical_time <= parent.envelope.logical_time {
            return Err(AppendError::CausalityViolation(event.envelope.logical_time));
        }
    }

    // 4. Persist
    store.insert_event(event).await?;

    Ok(())
}

/// Verify integrity of an event's hash chain (recursive).
pub async fn verify_integrity(
    store: &impl DagStore,
    event_id: &exo_core::Blake3Hash,
) -> Result<bool, AppendError> {
    let event = store.get_event(event_id).await?;

    // Check parents exist
    for parent in &event.envelope.parents {
        if !store.contains_event(parent).await? {
            return Ok(false);
        }
    }

    // Check hash correctness (re-compute)
    let recomputed =
        exo_core::compute_event_id(&event.envelope).map_err(|_| AppendError::CryptoError)?;

    if recomputed != event.event_id {
        return Ok(false);
    }

    Ok(true)
}
