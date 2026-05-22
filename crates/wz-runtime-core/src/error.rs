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
/// `core::error::Error` impl is omitted: it requires MSRV 1.81
/// (Error trait was moved into `core` in that release), while the
/// workspace MSRV is 1.75. The `std::error::Error` impl below
/// (gated on the `std` feature flag, added in R256 retiring the
/// R252 carry) provides AP-profile `Box<dyn std::error::Error>`
/// composability via the `std::error::Error` trait that has been
/// in `std` since 1.0; the `core::error::Error` no_std parity
/// arrives when the workspace MSRV bumps to 1.81+.
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

/// R256 — `std::error::Error` impl behind the `std` feature so
/// AP-profile callers can wrap `RuntimeError` in
/// `Box<dyn std::error::Error>` / use it with `?` against other
/// `std::error::Error`-bound returns. The impl is fully default
/// (no custom `source` chain) because `RuntimeError` is a flat
/// enum without an underlying-cause field yet; a future round
/// that adds an inner cause (e.g. wrapping `tokio::task::JoinError`
/// in `JoinFailed`) extends `source` here.
///
/// Stays behind `feature = "std"` because `std::error::Error` is
/// not accessible from `no_std` targets; the `core::error::Error`
/// equivalent lives on stable Rust 1.81+ which the workspace MSRV
/// has not yet committed to. When the MSRV bumps, this impl
/// becomes default-on (no feature gate) and a `core::error::Error`
/// blanket impl replaces it.
#[cfg(feature = "std")]
impl std::error::Error for RuntimeError {}

#[cfg(all(test, feature = "std"))]
mod std_error_tests {
    use super::*;

    #[test]
    fn runtime_error_is_std_error_compatible_boxable() {
        // Pin the std::error::Error contract: RuntimeError must be
        // boxable into Box<dyn std::error::Error>. This is the
        // typical Rust idiom for "any error, no matter the type"
        // return slots that AP-profile callers use (CLI tools,
        // top-level main() returns, etc.).
        let err: Box<dyn std::error::Error> = Box::new(RuntimeError::JoinFailed);
        assert!(err.to_string().contains("did not produce an output"));
    }

    #[test]
    fn runtime_error_source_chain_is_empty_for_flat_variants() {
        // The current variants (JoinFailed, Shutdown) are flat: no
        // wrapped inner cause. `source()` therefore returns None.
        // A future round that wraps an inner JoinError can extend
        // this contract by overriding `source` on the impl.
        use std::error::Error;
        let err = RuntimeError::Shutdown;
        assert!(err.source().is_none());
    }
}
