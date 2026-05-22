// SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! Error type shared by the runtime-services-tier traits.

use core::fmt;

#[cfg(feature = "alloc")]
use alloc::boxed::Box;

/// Failures the [`crate::Runtime`] and [`crate::TimeSource`] surfaces
/// can produce.
///
/// `#[non_exhaustive]` so future rounds can extend the variant set
/// (e.g. a future `SleepTimeout` variant for time-source impls that
/// surface deadline misses) without breaking external matchers.
///
/// `core::error::Error` impl is omitted: it requires MSRV 1.81
/// (Error trait was moved into `core` in that release), while the
/// workspace MSRV is 1.75. The `std::error::Error` impl below
/// (gated on the `std` feature flag, added in R256 retiring the
/// R252 carry) provides AP-profile `Box<dyn std::error::Error>`
/// composability via the `std::error::Error` trait that has been
/// in `std` since 1.0; the `core::error::Error` no_std parity
/// arrives when the workspace MSRV bumps to 1.81+.
///
/// ## R266 — `JoinFailed` panic payload
///
/// Under `feature = "alloc"`, the `JoinFailed` variant carries an
/// optional `payload: Option<Box<dyn Any + Send + 'static>>` slot
/// extracted from `tokio::task::JoinError::into_panic()` (or any
/// future runtime impl's equivalent). AP-profile callers can
/// `downcast_ref::<String>()` / `downcast_ref::<&'static str>()`
/// (the two payload types `std::panic::catch_unwind` surfaces in
/// practice) to extract the panic message for logging or richer
/// error reporting. The [`Self::panic_payload`] accessor centralises
/// the borrow shape.
///
/// MCU profiles compiling without `alloc` keep `JoinFailed` as a
/// unit variant — there is no heap to box the payload onto, and
/// `core::any::Any`'s downcast requires `'static` which the
/// no-alloc no_std environment can satisfy only for `&'static`
/// references that the panic infrastructure does not currently
/// surface. The accessor `Self::panic_payload` returns `None`
/// trivially in that build.
///
/// `Clone` / `PartialEq` / `Eq` are derived only under
/// `cfg(not(feature = "alloc"))` because the alloc-mode payload
/// (`Box<dyn Any + Send>`) is neither `Clone` nor `PartialEq`. The
/// no-alloc build retains the simpler "compare error code by
/// variant" pattern; the alloc build expects callers to use
/// `matches!` against the variant shape (the payload is for
/// post-mortem inspection, not equality comparison).
#[non_exhaustive]
#[derive(Debug)]
#[cfg_attr(not(feature = "alloc"), derive(Clone, PartialEq, Eq))]
pub enum RuntimeError {
    /// The spawned task panicked before producing its `Output`.
    /// Distinct from [`Self::JoinCancelled`] which signals a
    /// deliberate shutdown / abort path. Mirror of
    /// `tokio::task::JoinError::is_panic()`.
    ///
    /// R257 — prior to this round the variant collapsed both
    /// panic and cancellation cases. zenoh-pico semantics
    /// distinguish "the code broke" from "we asked the task to
    /// stop"; that round split the variants so callers can
    /// react appropriately (panic = log + bail; cancellation =
    /// expected during shutdown). MCU runtimes that genuinely
    /// can't distinguish may surface `JoinFailed` for both
    /// failure modes without violating the trait contract — the
    /// variant pair lets richer impls (tokio, embassy with
    /// explicit cancel signal) be honest about what happened.
    ///
    /// R266 — under `feature = "alloc"` the variant carries an
    /// optional `payload` slot extracted from the runtime impl's
    /// native error type (e.g. `JoinError::into_panic()` in
    /// tokio). Use [`Self::panic_payload`] to access it as a
    /// `&dyn Any` for downcast.
    ///
    /// [`JoinError::is_panic`]: https://docs.rs/tokio/latest/tokio/task/struct.JoinError.html#method.is_panic
    #[cfg(feature = "alloc")]
    JoinFailed {
        /// Payload returned by the underlying runtime's panic
        /// extraction API (`JoinError::into_panic()` for tokio).
        /// `None` when the runtime impl could not capture it
        /// (e.g. embassy on MCU surfaces panics through a global
        /// hook rather than per-task), or when the panic
        /// produced no payload (rare; `std::panic` always
        /// surfaces something).
        payload: Option<Box<dyn core::any::Any + Send + 'static>>,
    },
    /// The spawned task panicked before producing its `Output`
    /// (no-alloc build). See the alloc-gated variant for the
    /// production shape with payload extraction.
    #[cfg(not(feature = "alloc"))]
    JoinFailed,
    /// The spawned task was cancelled before producing its
    /// `Output`. This is the deliberate-shutdown / abort case:
    /// either an explicit `abort()` call on the handle, or a
    /// runtime-level shutdown that aborts every outstanding
    /// task. Distinct from [`Self::JoinFailed`] (panic).
    /// Mirror of `tokio::task::JoinError::is_cancelled()`.
    JoinCancelled,
    /// The runtime is shutting down and refuses to accept new spawn
    /// requests or queue new sleeps. Used by impls that have an
    /// explicit shutdown signal (tokio runtime drop, embassy
    /// stop-the-world). Surfaces only on operations attempted
    /// after the shutdown begins.
    Shutdown,
}

impl RuntimeError {
    /// Construct a `JoinFailed` with no captured panic payload.
    /// Available in both alloc and no-alloc builds so callers can
    /// produce the variant without knowing whether the payload
    /// field exists (it's the textbook "smart constructor" shape
    /// for a feature-gated struct-like variant). Runtime impls
    /// that DO capture payloads call the alloc-gated
    /// [`Self::join_failed_with_payload`] instead.
    pub fn join_failed() -> Self {
        #[cfg(feature = "alloc")]
        {
            Self::JoinFailed { payload: None }
        }
        #[cfg(not(feature = "alloc"))]
        {
            Self::JoinFailed
        }
    }

    /// Construct a `JoinFailed` with a captured panic payload.
    /// Available only under `feature = "alloc"`; the MCU
    /// no-alloc path uses [`Self::join_failed`] which has no
    /// payload slot.
    ///
    /// Runtime impls call this from their per-task join-error
    /// translation. The tokio adapter passes
    /// `Some(join_error.into_panic())`; embassy / lwIP MCU impls
    /// that lack a per-task payload accessor will pass `None`
    /// (preserving the variant but signalling "no captured
    /// payload").
    #[cfg(feature = "alloc")]
    pub fn join_failed_with_payload(
        payload: Option<Box<dyn core::any::Any + Send + 'static>>,
    ) -> Self {
        Self::JoinFailed { payload }
    }

    /// Borrow the captured panic payload, if any. Returns `None`
    /// for variants other than `JoinFailed`, for `JoinFailed`
    /// variants without a payload (e.g. constructed via
    /// [`Self::join_failed`]), or under `cfg(not(feature =
    /// "alloc"))` where the slot does not exist.
    ///
    /// Callers downcast via `payload.downcast_ref::<T>()` to
    /// inspect the type-erased contents. The two payload types
    /// `std::panic::catch_unwind` produces in practice are
    /// `&'static str` (panic from a string-literal message) and
    /// `String` (panic from a formatted message); a textbook
    /// extraction tries both:
    ///
    /// ```ignore
    /// let msg: Option<&str> = err
    ///     .panic_payload()
    ///     .and_then(|p| p.downcast_ref::<String>().map(|s| s.as_str())
    ///         .or_else(|| p.downcast_ref::<&'static str>().copied()));
    /// ```
    pub fn panic_payload(&self) -> Option<&(dyn core::any::Any + Send + 'static)> {
        #[cfg(feature = "alloc")]
        {
            match self {
                Self::JoinFailed { payload: Some(p) } => Some(p.as_ref()),
                _ => None,
            }
        }
        #[cfg(not(feature = "alloc"))]
        {
            let _ = self;
            None
        }
    }
}

impl fmt::Display for RuntimeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            #[cfg(feature = "alloc")]
            Self::JoinFailed { payload } => {
                // Prefer a human-readable extract of the panic
                // payload when one of the two common types matches;
                // fall back to a fixed message otherwise. The
                // narrower message keeps the Display output stable
                // for log-grep callers that do not introspect the
                // payload directly.
                if let Some(p) = payload {
                    let extracted: Option<&str> = p
                        .downcast_ref::<alloc::string::String>()
                        .map(|s| s.as_str())
                        .or_else(|| p.downcast_ref::<&'static str>().copied());
                    if let Some(msg) = extracted {
                        return write!(f, "RuntimeError: spawned task panicked: {msg}");
                    }
                }
                f.write_str("RuntimeError: spawned task panicked")
            }
            #[cfg(not(feature = "alloc"))]
            Self::JoinFailed => f.write_str("RuntimeError: spawned task panicked"),
            Self::JoinCancelled => {
                f.write_str("RuntimeError: spawned task was cancelled before completion")
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
/// `std::error::Error`-bound returns. R266 — the default `source`
/// chain stays `None` because the panic payload is type-erased
/// `dyn Any`, not `dyn Error`; a downcast-aware caller fetches it
/// via [`RuntimeError::panic_payload`] and inspects the
/// concrete type explicitly. Wrapping the panic payload in a
/// `dyn Error` adapter is rejected as misleading — `Any` is the
/// honest type for catch-unwind output and callers should not be
/// led to expect a `source` chain that doesn't structurally
/// exist.
///
/// Stays behind `feature = "std"` because `std::error::Error` is
/// not accessible from `no_std` targets; the `core::error::Error`
/// equivalent lives on stable Rust 1.81+ which the workspace MSRV
/// has not yet committed to. When the MSRV bumps, this impl
/// becomes default-on (no feature gate) and a `core::error::Error`
/// blanket impl replaces it.
#[cfg(feature = "std")]
impl std::error::Error for RuntimeError {}

#[cfg(test)]
mod compile_time_assertions {
    use super::*;

    // R258 — pin RuntimeError trait bounds structurally so any
    // future regression on Send surfaces as a compile error
    // rather than a runtime puzzle.
    //
    // R266 — Sync / Clone / PartialEq / Eq pinning gated on
    // `cfg(not(feature = "alloc"))` because the alloc-mode
    // `JoinFailed` carries a `Box<dyn Any + Send>` payload that
    // is not Sync (dyn Any + Send lacks the Sync bound — the
    // tokio panic infrastructure produces Send-only payloads),
    // not Clone (Box<dyn Any> has no Clone impl — Any erases
    // the concrete type's Clone), and not PartialEq (downstream
    // of `Any`'s missing PartialEq impl). The no-alloc build
    // retains the full trait surface for MCU targets that need
    // to share / clone / compare errors without payload
    // introspection. Send is preserved in both builds because
    // `Result<T, RuntimeError>` must cross thread boundaries
    // (the Future Output of `Runtime::spawn` is move-only).
    fn _assert_send<T: Send>() {}
    #[cfg(not(feature = "alloc"))]
    fn _assert_sync<T: Sync>() {}
    #[cfg(not(feature = "alloc"))]
    fn _assert_clone<T: Clone>() {}
    #[cfg(not(feature = "alloc"))]
    fn _assert_eq<T: Eq>() {}

    #[allow(dead_code)]
    fn runtime_error_trait_bounds_compile() {
        _assert_send::<RuntimeError>();
        #[cfg(not(feature = "alloc"))]
        {
            _assert_sync::<RuntimeError>();
            _assert_clone::<RuntimeError>();
            _assert_eq::<RuntimeError>();
        }
    }
}

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
        let err: Box<dyn std::error::Error> = Box::new(RuntimeError::join_failed());
        // R257 — JoinFailed Display narrowed to "panicked"; the
        // generic "did not produce an output" wording moved to
        // the new JoinCancelled variant doc-comment.
        assert!(err.to_string().contains("panicked"));
    }

    #[test]
    fn runtime_error_source_chain_is_empty_for_flat_variants() {
        // R266 — `source()` is still None for every variant. The
        // panic payload is exposed via panic_payload(), not via
        // source() — see the std::error::Error impl doc-comment
        // for the rationale.
        use std::error::Error;
        let err = RuntimeError::Shutdown;
        assert!(err.source().is_none());
        let cancel = RuntimeError::JoinCancelled;
        assert!(cancel.source().is_none());
        let panic_no_payload = RuntimeError::join_failed();
        assert!(panic_no_payload.source().is_none());
    }

    #[test]
    fn runtime_error_panic_payload_accessor_returns_none_for_non_panic() {
        // R266 — panic_payload returns None for non-JoinFailed
        // variants and for JoinFailed with no payload.
        assert!(RuntimeError::Shutdown.panic_payload().is_none());
        assert!(RuntimeError::JoinCancelled.panic_payload().is_none());
        assert!(RuntimeError::join_failed().panic_payload().is_none());
    }

    #[test]
    fn runtime_error_panic_payload_downcast_string() {
        // R266 — payload downcast to String round-trips through
        // the alloc-gated join_failed_with_payload constructor.
        let err = RuntimeError::join_failed_with_payload(Some(Box::new(
            "boom".to_string(),
        )));
        let payload = err.panic_payload().expect("payload present");
        let msg: &String = payload
            .downcast_ref::<String>()
            .expect("payload downcast to String");
        assert_eq!(msg, "boom");
    }

    #[test]
    fn runtime_error_panic_payload_downcast_static_str() {
        // R266 — payload downcast to &'static str (the other
        // common panic type, from `panic!("literal")`).
        let err = RuntimeError::join_failed_with_payload(Some(Box::new(
            "literal panic",
        )));
        let payload = err.panic_payload().expect("payload present");
        let msg: &&'static str = payload
            .downcast_ref::<&'static str>()
            .expect("payload downcast to &str");
        assert_eq!(*msg, "literal panic");
    }

    #[test]
    fn runtime_error_display_extracts_string_payload() {
        // R266 — Display surfaces the String payload as a
        // human-readable suffix; the prefix "RuntimeError:
        // spawned task panicked" is preserved for log-grep
        // stability.
        let err = RuntimeError::join_failed_with_payload(Some(Box::new(
            "kaboom".to_string(),
        )));
        let formatted = err.to_string();
        assert!(formatted.contains("panicked"));
        assert!(formatted.contains("kaboom"));
    }

    #[test]
    fn runtime_error_display_extracts_static_str_payload() {
        let err = RuntimeError::join_failed_with_payload(Some(Box::new(
            "literal kaboom",
        )));
        let formatted = err.to_string();
        assert!(formatted.contains("panicked"));
        assert!(formatted.contains("literal kaboom"));
    }
}
