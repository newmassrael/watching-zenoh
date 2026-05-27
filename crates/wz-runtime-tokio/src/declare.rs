// SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! Application-layer remote-declaration registries — route decoded
//! `Declare(Decl*|Undecl*)` records to user-registered callbacks so
//! the application sees "the peer just declared a subscriber/
//! queryable/token" or "the peer just undeclared one".
//!
//! ## Scope and module shape
//!
//! Three sibling registries — one per zenoh-pico sub-type cluster:
//!
//! | Registry                       | Wire arms                    | zenoh-pico feature gate    |
//! |--------------------------------|------------------------------|----------------------------|
//! | [`RemoteSubscriberRegistry`]   | `DeclSubscriber` + `Undecl`  | `Z_FEATURE_SUBSCRIPTION`   |
//! | [`RemoteQueryableRegistry`]    | `DeclQueryable` + `Undecl`   | `Z_FEATURE_QUERYABLE`      |
//! | [`LivelinessRegistry`]         | `DeclToken` + `UndeclToken`  | `Z_FEATURE_LIVELINESS`     |
//!
//! Each registry lives in its own sub-module file
//! (`declare/subscriber.rs`, `declare/queryable.rs`,
//! `declare/liveliness.rs`); this parent module re-exports the public
//! types verbatim so consumers continue to write
//! `wz_runtime_tokio::declare::RemoteSubscriberRegistry` etc. across
//! the reorg. The split is purely organisational — behaviour is
//! preserved (R121k-reorg).
//!
//! ## Why a separate registry rather than absorbing into [`crate::pubsub::SubscriberRegistry`]
//!
//! - **Direction**: [`crate::pubsub::SubscriberRegistry`] holds the
//!   LOCAL subscribers — keyexpr callbacks the application registered
//!   so wz can fire them on inbound `Push`. The remote registries
//!   hold the PEER's declarations — informational signals that "a
//!   peer is now subscribing to this keyexpr", typically consumed by
//!   metrics, debug logging, or a future router/forwarding layer.
//!   Keeping them separate avoids conflating the "I subscribe to X"
//!   and "peer subscribes to X" surfaces.
//! - **Threading and ownership**: same `!Sync` contract as the
//!   pub/sub and query registries (caller wraps in
//!   `Arc<Mutex<…>>` for cross-task sharing). No interior mutability
//!   in the registries themselves — callback storage is straight
//!   `Vec<…>`.
//! - **MCU runtime compatibility**: `FnMut` callbacks, no `async fn`,
//!   no `Future` in the trait surface. The dispatch path stays
//!   suitable for the `(c11, bare_metal)` runtime crate target once
//!   that crate adopts the same registry shape.
//!
//! ## Callback contract
//!
//! `on_*_declared` callbacks receive the decoded codec record by
//! reference plus the resolved keyexpr literal (composition rule
//! mirrors [`crate::pubsub::SubscriberRegistry`]: `id == 0` → suffix
//! verbatim; `id != 0` → `table[id] + suffix`). If the inner keyexpr
//! references a mapping id the peer has not yet declared, the
//! dispatch skips the callback entirely rather than firing on a
//! partial keyexpr — recording the declaration without its resolved
//! form would be a half-truth and most consumers (metrics
//! aggregation, route tables, log lines) would mis-render or mis-key.
//!
//! `on_*_undeclared` callbacks receive the decoded codec record by
//! reference. The undeclare body carries only `id: u64` (no
//! keyexpr), so no resolution is needed — the peer identifies the
//! prior declaration by the same id it used in its earlier `Decl*`.

// R311di-13 — resolve_wireexpr moved to
// wz-session-core::wireexpr_resolve so MCU profiles can compose the
// remote-declaration registries without inheriting wz-runtime-tokio.
// Re-exported `pub(super)` to keep the sub-modules' import path
// (`super::resolve_wireexpr`) compiling unchanged.
pub(super) use wz_session_core::wireexpr_resolve::resolve_wireexpr;

// R310 — each registry sub-module gates on its corresponding
// application-layer feature (the wire-emit counterpart was gated at
// R309 inside session_glue). The liveliness pair was already gated at
// R302b; R310 extends the same mechanical shape to subscriber +
// queryable so a `--no-default-features --features declare-subscriber`
// build carries only the RemoteSubscriberRegistry path and elides the
// peer-queryable observer entirely.
#[cfg(feature = "liveliness-token")]
mod liveliness;
// R311q — `liveliness_subscriber` module is type-ungated: the
// LivelinessSubscriberRegistry struct + LivelinessSample +
// LivelinessSampleKind + LivelinessSampleCallback types are always
// defined so `observer.liveliness_subscribers` and the
// `Session::declare_liveliness_subscriber{_aliased}` Result-form
// signatures compile unconditionally. The wire-codec dispatch body
// inside the module uses `wz_codecs::declare::DeclareVariant`, which
// is always available because the wz-codecs dep hardcodes
// `codec-declare` (Cargo.toml dep features), independent of the
// wz-runtime-tokio `codec-declare` consumer-side gate.
mod liveliness_subscriber;
#[cfg(feature = "declare-queryable")]
mod queryable;
#[cfg(feature = "declare-subscriber")]
mod subscriber;

#[cfg(test)]
mod cross_tests;
#[cfg(test)]
mod test_helpers;

#[cfg(feature = "liveliness-token")]
pub use liveliness::{DeclTokenCallback, LivelinessRegistry, UndeclTokenCallback};
pub use liveliness_subscriber::{
    LivelinessSample, LivelinessSampleCallback, LivelinessSampleKind, LivelinessSubscriberRegistry,
};
#[cfg(feature = "declare-queryable")]
pub use queryable::{DeclQueryableCallback, RemoteQueryableRegistry, UndeclQueryableCallback};
#[cfg(feature = "declare-subscriber")]
pub use subscriber::{DeclSubscriberCallback, RemoteSubscriberRegistry, UndeclSubscriberCallback};

// resolve_wireexpr moved to wz-session-core at R311di-13;
// the pub(super) use re-export above keeps the import path
// `super::resolve_wireexpr` working for the 3 sub-module callers
// (subscriber / liveliness / liveliness_subscriber).
