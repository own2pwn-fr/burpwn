//! Small shared helpers.

use std::time::{SystemTime, UNIX_EPOCH};

/// Current unix time in milliseconds. The store treats timestamps as opaque
/// `i64`s, so millis-since-epoch is the proxy's chosen convention. Never panics
/// (a clock before the epoch yields 0).
pub fn now_millis() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}
