// SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! Error type shared by the runtime-services-tier traits.

use core::fmt;

/// Failures the [`crate::Runtime`] and [`crate::TimeSource`] surfaces
/// can produce. Intentionally narrow — the trait skeleton round
/// (R251) only names the failure modes the existing tokio + embassy
/// reference impls actually surface; richer error info (e.g. an
/// underlying `JoinError` source) can be added behind the
/// `#[non_exhaustive]` shield without breaking external matchers.
///
/// `core::error::Error` impl is omitted in this round: it requires
/// MSRV 1.81 (Error trait was moved into `core` in that release),
/// while the workspace MSRV is 1.75. A `std::error::Error` impl
/// behind the `std` feature flag lands in R252+ when the AP-profile
/// integration round wires TokioRuntime.
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RuntimeError {
    /// The spawned task did not complete normally — it panicked, was
    /// cancelled before producing an `Output`, or otherwise failed
    /// to deliver a result through the `JoinHandle`. Mirror of
    /// `tokio::task::JoinError`'s "panicked or cancelled" union
    /// (tokio splits the two via [`JoinError::is_panic`] /
    /// `is_cancelled`; we collapse them at the trait boundary
    /// because MCU runtimes generally do not distinguish).
    ///
    /// [`JoinError::is_panic`]: https://docs.rs/tokio/latest/tokio/task/struct.JoinError.html#method.is_panic
    JoinFailed,
    /// The runtime is shutting down and refuses to accept new spawn
    /// requests or queue new sleeps. Used by impls that have an
    /// explicit shutdown signal (tokio runtime drop, embassy
    /// stop-the-world). Surfaces only on operations attempted
    /// after the shutdown begins.
    Shutdown,
}

impl fmt::Display for RuntimeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::JoinFailed => {
                f.write_str("RuntimeError: spawned task did not produce an output")
            }
            Self::Shutdown => {
                f.write_str("RuntimeError: runtime is shutting down; new work refused")
            }
        }
    }
}
