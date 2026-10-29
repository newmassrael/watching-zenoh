// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! Whether a span of ticks has passed, over a counter that wraps at 2^32.
//!
//! A deadline and a sampling period are the same question: have `timeout` ticks passed since
//! `last`? The supervisor asks it of a checkpoint and the resource sampler of its period
//! (`docs/observation-plane.md` M3 and M4), so it is written once, here.
//!
//! The difference of two readings is taken modulo 2^32, so a wrap of the counter between the two
//! readings is the ordinary case and not a special one. That comparison cannot tell a span of
//! `timeout` ticks from one of `timeout + 2^32`, so a timeout is at most [`MAX_TIMEOUT_TICKS`], half
//! the range: past that, a counter that went round looks like one that did not move, and the check
//! must be made at least once in every `2^32 - timeout` ticks to see a span at all.

/// The longest timeout a comparison can have: the difference of two readings is compared modulo
/// 2^32, so a timeout past half the range cannot be told from a counter that went round.
pub const MAX_TIMEOUT_TICKS: u32 = i32::MAX as u32;

/// Whether `timeout` ticks have passed from `last` to `now`, both readings of a counter that
/// wraps at 2^32.
pub const fn elapsed(now: u32, last: u32, timeout: u32) -> bool {
    now.wrapping_sub(last) >= timeout
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_span_is_a_difference_taken_modulo_the_counter() {
        assert!(!elapsed(100, 100, 5));
        assert!(!elapsed(104, 100, 5));
        assert!(elapsed(105, 100, 5));
        // The counter went round between the two readings: 10 ticks passed.
        assert!(elapsed(5, u32::MAX - 4, 10));
        assert!(!elapsed(4, u32::MAX - 4, 10));
    }

    #[test]
    fn the_longest_timeout_is_half_the_range() {
        assert_eq!(MAX_TIMEOUT_TICKS, 2_147_483_647);
        assert!(elapsed(MAX_TIMEOUT_TICKS, 0, MAX_TIMEOUT_TICKS));
        assert!(!elapsed(MAX_TIMEOUT_TICKS - 1, 0, MAX_TIMEOUT_TICKS));
    }
}
