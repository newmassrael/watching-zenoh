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

// R311dt — the four declare sub-modules (subscriber / queryable /
// liveliness / liveliness_subscriber) were pure re-export shells after
// R311do-dq moved every registry body into wz-session-core. This parent
// module now re-exports the registry types directly from
// `wz_session_core::declare::*`, collapsing the redundant double hop
// (declare.rs -> declare/X.rs shell -> wz_session_core) into a single
// hop and deleting the four shell files. The
// `wz_runtime_tokio::declare::*` consumer path is unchanged.
//
// The per-feature `#[cfg]` gate stays on each re-export so a
// `--no-default-features --features declare-subscriber` build re-exposes
// only the RemoteSubscriberRegistry surface and elides the
// peer-queryable / liveliness observers entirely — exactly the eliding
// behaviour the `#[cfg] mod X;` gate provided before (R310).

#[cfg(feature = "liveliness-token")]
pub use wz_session_core::declare::liveliness::{
    DeclTokenCallback, LivelinessRegistry, UndeclTokenCallback,
};
// R311q — the liveliness_subscriber surface is type-ungated: the
// LivelinessSubscriberRegistry + LivelinessSample + LivelinessSampleKind
// + LivelinessSampleCallback types are always re-exported so
// `observer.liveliness_subscribers` and the Result-form
// `Session::declare_liveliness_subscriber{_aliased}` signatures compile
// unconditionally.
pub use wz_session_core::declare::liveliness_subscriber::{
    LivelinessSample, LivelinessSampleCallback, LivelinessSampleKind, LivelinessSubscriberRegistry,
};
#[cfg(feature = "declare-queryable")]
pub use wz_session_core::declare::queryable::{
    DeclQueryableCallback, RemoteQueryableRegistry, UndeclQueryableCallback,
};
#[cfg(feature = "declare-subscriber")]
pub use wz_session_core::declare::subscriber::{
    DeclSubscriberCallback, RemoteSubscriberRegistry, UndeclSubscriberCallback,
};
