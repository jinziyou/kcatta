//! Bounded identifiers shared by every Agent producer.

use std::fmt::Write as _;

use sha2::{Digest, Sha256};

/// Maximum number of Unicode scalar values accepted by Form's
/// `CorrelationIdentifier` contract.
pub const CORRELATION_IDENTIFIER_MAX_CHARS: usize = 256;

/// Maximum number of Unicode scalar values accepted by Form's ordinary
/// `StrictModel` string fields.
pub const WIRE_TEXT_MAX_CHARS: usize = 4_096;

const HASH_LABEL: &str = "~sha256:";
const SHA256_HEX_CHARS: usize = 64;

/// Return a deterministic Form-compatible correlation identifier.
///
/// Values at or below [`CORRELATION_IDENTIFIER_MAX_CHARS`] are returned
/// unchanged. Longer values retain a readable prefix and append the complete
/// SHA-256 digest of the original UTF-8 bytes. Counting and truncation operate
/// on Unicode scalar values, so the result is always valid UTF-8 and is at most
/// 256 characters as measured by the Pydantic/JSON Schema contract. The full
/// digest makes identifiers with the same retained prefix collision-resistant.
#[must_use]
pub fn bounded_correlation_id(value: &str) -> String {
    bounded_with_hash(value, CORRELATION_IDENTIFIER_MAX_CHARS)
}

/// Return a deterministic Form-compatible ordinary wire string.
///
/// This is intended for descriptive fields such as `evidence` and
/// `description`. Dedicated path and asset-id fields retain their own values
/// and are deliberately not routed through this helper.
#[must_use]
pub fn bounded_wire_text(value: &str) -> String {
    bounded_with_hash(value, WIRE_TEXT_MAX_CHARS)
}

fn bounded_with_hash(value: &str, max_chars: usize) -> String {
    if value.chars().count() <= max_chars {
        return value.to_owned();
    }

    let digest = Sha256::digest(value.as_bytes());
    let mut suffix = String::with_capacity(HASH_LABEL.len() + SHA256_HEX_CHARS);
    suffix.push_str(HASH_LABEL);
    for byte in digest {
        write!(&mut suffix, "{byte:02x}").expect("writing to a String cannot fail");
    }

    let prefix_chars = max_chars - suffix.chars().count();
    let mut bounded = value.chars().take(prefix_chars).collect::<String>();
    bounded.push_str(&suffix);
    debug_assert_eq!(bounded.chars().count(), max_chars);
    bounded
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn short_and_exact_limit_values_are_unchanged() {
        assert_eq!(bounded_correlation_id("host-one"), "host-one");

        let exact = "界".repeat(CORRELATION_IDENTIFIER_MAX_CHARS);
        assert_eq!(bounded_correlation_id(&exact), exact);
    }

    #[test]
    fn unicode_truncation_is_valid_and_respects_character_limit() {
        let long = format!("{}tail", "边界🙂".repeat(100));
        let bounded = bounded_correlation_id(&long);

        assert_eq!(bounded.chars().count(), CORRELATION_IDENTIFIER_MAX_CHARS);
        assert!(bounded.contains("~sha256:"));
        assert!(bounded.is_char_boundary(bounded.len()));
        assert_eq!(bounded, bounded_correlation_id(&long));
    }

    #[test]
    fn equal_prefixes_keep_distinct_full_value_hashes() {
        let prefix = "a".repeat(400);
        let left = bounded_correlation_id(&format!("{prefix}-left"));
        let right = bounded_correlation_id(&format!("{prefix}-right"));

        assert_ne!(left, right);
        assert_eq!(left.chars().count(), CORRELATION_IDENTIFIER_MAX_CHARS);
        assert_eq!(right.chars().count(), CORRELATION_IDENTIFIER_MAX_CHARS);
    }

    #[test]
    fn wire_text_uses_its_wider_unicode_safe_limit() {
        let exact = "证".repeat(WIRE_TEXT_MAX_CHARS);
        assert_eq!(bounded_wire_text(&exact), exact);

        let long = format!("{}-tail", "证据🙂".repeat(1_500));
        let bounded = bounded_wire_text(&long);
        assert_eq!(bounded.chars().count(), WIRE_TEXT_MAX_CHARS);
        assert!(bounded.contains("~sha256:"));
        assert_eq!(bounded, bounded_wire_text(&long));
    }
}
