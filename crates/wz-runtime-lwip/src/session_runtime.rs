// SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! `impl SessionRuntime for LwipRuntime<C>` — the session-tier link-sink
//! binding for the MCU profile (Stage 4a precondition).
//!
//! [`wz_session_core::link::SessionRuntime`] extends
//! [`wz_runtime_core::Runtime`] with the per-profile *storage* of the
//! [`wz_session_core::link::BoxedLinkDriver`] write seam, so that
//! `SessionLinkActions<R: SessionRuntime, T>` can hold one `R::LinkSink`
//! field and reach the pure `&dyn BoxedLinkDriver` through
//! [`SessionRuntime::link_driver`] without a third generic. This module
//! supplies that binding for the lwIP MCU profile, mirroring the AP
//! binding in `wz_runtime_tokio::runtime_impl`.
//!
//! ## Why `Rc`, not `Arc`
//!
//! The AP profile binds `LinkSink = Arc<dyn BoxedLinkDriver + Send +
//! Sync>` because the multi-thread tokio runtime shares the driver
//! across worker threads. The lwIP MCU profile runs a single-task
//! synchronous drive loop (`session_drive`, landing in the follow-up)
//! that shares the same `udp_pcb` between the loop and the driver, so
//! the sink is never sent across threads. It therefore binds
//! `LinkSink = Rc<dyn BoxedLinkDriver>` — `!Send`, no atomic refcount
//! traffic on every clone. This is exactly the binding the pure
//! (no `Send + Sync` supertrait) `BoxedLinkDriver` trait was shaped to
//! allow: baking `Send + Sync` onto the trait would have forced an
//! `unsafe impl Send` on the `!Send` `LwipUdpSocket` driver; keeping it
//! pure lets this profile's `LinkSink` carry only the auto-traits its
//! single-task concurrency model actually needs (see the
//! [`wz_session_core::link::BoxedLinkDriver`] / [`SessionRuntime`] docs).
//!
//! `SessionLinkActions<LwipRuntime<C>, LwipTime<C>>` is consequently
//! `!Send`; that is correct, not a limitation — the bundle lives on the
//! drive loop's stack and is never spawned. `new_generic` wraps it in an
//! `alloc::sync::Arc` for shared read access within that one task; the
//! `Arc` is `!Send` here because its contents are, which the sync loop
//! never violates.

use alloc::rc::Rc;

use wz_session_core::link::{BoxedLinkDriver, SessionRuntime};

use crate::runtime_impl::LwipRuntime;
use crate::time::{ClockSource, LwipTime};

/// MCU-profile [`SessionRuntime`] binding. The link sink is a
/// `Rc<dyn BoxedLinkDriver>` shared by the single-task drive loop and
/// its synchronous `LwipUdpSocket` driver; `!Send` is the intended
/// shape (see module doc).
impl<C: ClockSource> SessionRuntime for LwipRuntime<C> {
    type LinkSink = Rc<dyn BoxedLinkDriver>;

    fn link_driver(sink: &Self::LinkSink) -> &dyn BoxedLinkDriver {
        // `&**sink` reborrows through `Rc<dyn BoxedLinkDriver>` to the
        // pure `&dyn BoxedLinkDriver` the action methods send through.
        // No auto-trait coercion is needed (the MCU sink carries none),
        // unlike the AP `&**sink` which also drops `+ Send + Sync`.
        &**sink
    }
}

// ───────────────────── compile-time preconditions ─────────────────────
//
// These live in the (non-test) lib body — NOT a `#[cfg(test)]` module —
// so the Layer G cross-compile of `wz-runtime-lwip --features
// session-unicast` type-checks them on every MCU target, proving the
// binding holds on bare metal and not merely on the host test build.

/// Stage 4a precondition: `SessionLinkActions<LwipRuntime<C>,
/// LwipTime<C>>` is well-formed — i.e. `LwipRuntime<C>: SessionRuntime`
/// and `LwipTime<C>: TimeSource` both hold, so the runtime-agnostic
/// session action bundle composes on the MCU profile. Naming the type in
/// a reference position forces the struct's declared bounds to be
/// satisfied at compile time. The sync drive loop consumer
/// (`session_drive`) that constructs and drives it lands in the
/// follow-up; this gate is the type-check that unblocks it.
#[allow(dead_code)]
fn _session_link_actions_composes_on_lwip<C: ClockSource>(
    _actions: &wz_session_core::session_actions::SessionLinkActions<LwipRuntime<C>, LwipTime<C>>,
) {
}

/// LinkSink fixity. Mirrors the AP-side
/// `tokio_session_runtime_link_sink_bounds_compile` regression assert,
/// but pins the *opposite* auto-trait shape: the MCU sink is `Clone`
/// (the shared-by-refcount contract every profile satisfies) and is
/// deliberately NOT asserted `Send + Sync` — re-binding it to an `Arc`
/// "to make it Send" would silently reintroduce atomic refcount traffic
/// the single-task profile does not need. A regression that re-adds a
/// `Send + Sync` supertrait onto `BoxedLinkDriver` (which would force an
/// `unsafe impl Send` on the `!Send` `LwipUdpSocket` driver) surfaces at
/// the driver impl, not here.
#[allow(dead_code)]
fn _lwip_session_runtime_link_sink_is_clone<C: ClockSource>() {
    fn _assert_clone<T: Clone>() {}
    _assert_clone::<<LwipRuntime<C> as SessionRuntime>::LinkSink>();
}
