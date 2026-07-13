//! Shared validation limits for the Form wire contract.

use std::fmt;

/// Maximum characters in a dedicated wire identifier or ordinary string.
pub const WIRE_STRING_MAX_CHARS: usize = 4_096;
/// Maximum items in a top-level telemetry stream.
pub const WIRE_LIST_MAX_ITEMS: usize = 4_096;
/// Maximum items in nested metadata arrays.
pub const NESTED_LIST_MAX_ITEMS: usize = 256;
/// Maximum IOC matches attached to one trace event.
pub const THREAT_MATCH_MAX_ITEMS: usize = 64;

/// A locally detected violation of the Form wire contract.
///
/// Producers return this before writing an artifact so invalid telemetry never
/// becomes a remote 422/dead-letter surprise.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WireContractError {
    message: String,
}

impl WireContractError {
    pub(crate) fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }
}

impl fmt::Display for WireContractError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.message)
    }
}

impl std::error::Error for WireContractError {}

pub(crate) fn ensure_chars(field: &str, value: &str, max: usize) -> Result<(), WireContractError> {
    let actual = value.chars().count();
    if actual > max {
        return Err(WireContractError::new(format!(
            "{field} has {actual} characters; Form allows at most {max}"
        )));
    }
    Ok(())
}

pub(crate) fn ensure_items(
    field: &str,
    actual: usize,
    max: usize,
) -> Result<(), WireContractError> {
    if actual > max {
        return Err(WireContractError::new(format!(
            "{field} has {actual} items; Form allows at most {max}"
        )));
    }
    Ok(())
}
