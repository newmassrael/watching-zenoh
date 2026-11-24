// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! What a receiver's judge of one stream of frames is configured with: the
//! counter's width, the largest step and the longest silence, and what a counter
//! verdict does to the judge's state. A profile states them and is read once,
//! so they are plain data beside the profile's reader; the judge that applies
//! them to every frame is `wz-app-frame`'s (`e2e_judge`), which re-exports
//! these items at the paths they had there and states their meaning in full.

/// What a judge is configured with.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct JudgeConfig {
    /// Width of the counter field, 1 to 8 bytes.
    pub counter_bytes: usize,
    /// The largest step that is not an error.
    pub max_gap: u64,
    /// The longest silence that is not an error; [`JudgeConfig::NO_TIMEOUT`]
    /// for a stream whose silence is never an error.
    pub timeout_ms: u64,
}

impl JudgeConfig {
    /// The `timeout_ms` of a stream with no limit on its silence (see
    /// `wz_app_frame::e2e_judge`).
    pub const NO_TIMEOUT: u64 = 0;

    /// The longest silence that is not an error; `None` when the stream has no
    /// limit.
    #[inline]
    pub const fn timeout_limit(&self) -> Option<u64> {
        if self.timeout_ms == Self::NO_TIMEOUT {
            None
        } else {
            Some(self.timeout_ms)
        }
    }
}

/// What a judge's counter verdicts do to its state, as a profile states it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CounterRules {
    /// Whether a step above the largest gap moves the baseline and the instant
    /// of the last valid reception to the frame. A repetition never moves them.
    pub out_of_range_moves_baseline: bool,
}

impl Default for CounterRules {
    /// A step out of range moves the baseline, so one lost run does not condemn
    /// every frame after it.
    fn default() -> Self {
        Self {
            out_of_range_moves_baseline: true,
        }
    }
}
