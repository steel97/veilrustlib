//! Small helpers shared across the faucet.
//!
//! Port of `ref/veil-faucet/lib/core/utility.dart`.

use std::time::{SystemTime, UNIX_EPOCH};

/// The current unix timestamp, in seconds.
///
/// Matches `getUnixTimestamp()`. A clock before the epoch yields 0 rather than
/// panicking, which keeps a misconfigured host from taking the bot down.
pub fn unix_timestamp() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|elapsed| elapsed.as_secs() as i64)
        .unwrap_or(0)
}

/// Format a wait in seconds as `H:MM:SS`.
///
/// Matches `toTimeString`, which rendered a Dart `Duration` and left-padded it to
/// eight characters. Negative and zero waits render as `0:00:00`, since a wait
/// that has already elapsed is not shown to users anyway.
pub fn format_wait(total_seconds: i64) -> String {
    let total = total_seconds.max(0);

    let hours = total / 3600;
    let minutes = (total % 3600) / 60;
    let seconds = total % 60;

    format!("{hours}:{minutes:02}:{seconds:02}")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_wait_is_formatted_as_hours_minutes_seconds() {
        assert_eq!(format_wait(0), "0:00:00");
        assert_eq!(format_wait(59), "0:00:59");
        assert_eq!(format_wait(60), "0:01:00");
        assert_eq!(format_wait(3599), "0:59:59");
        assert_eq!(format_wait(3600), "1:00:00");
        assert_eq!(format_wait(3661), "1:01:01");
        assert_eq!(format_wait(86_400), "24:00:00");
    }

    #[test]
    fn an_elapsed_wait_is_clamped_to_zero() {
        assert_eq!(format_wait(-1), "0:00:00");
        assert_eq!(format_wait(i64::MIN), "0:00:00");
    }

    #[test]
    fn the_timestamp_is_plausible() {
        // Sanity check only: the value must be a positive, present-day epoch
        // second, which catches a unit mix-up such as milliseconds.
        let now = unix_timestamp();

        assert!(now > 1_700_000_000, "timestamp looks too small: {now}");
        assert!(now < 4_000_000_000, "timestamp looks too large: {now}");
    }
}
