// SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! `impl SessionRuntime for CoopRuntime<C>` — the session-tier link-sink
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
//! `SessionLinkActions<CoopRuntime<C>, CoopTime<C>>` is consequently
//! `!Send`; that is correct, not a limitation — the bundle lives on the
//! drive loop's stack and is never spawned. `new_generic` wraps it in the
//! profile [`SessionRuntime::ActionsHandle`] — `Rc` here (R311ja), not
//! `Arc` — for shared read access within that one task: the FSM action
//! binding and the drive loop read the same bundle, but never across
//! threads, so an atomic refcount would be pure waste *and* would wall the
//! session off ARMv6-M (`alloc::sync::Arc` needs `target_has_atomic =
//! "ptr"`, absent on Cortex-M0/M0+). The single-task `Rc` is exactly what
//! lets the MCU session stack — handshake + reassembly consumer — reach
//! ARMv6-M, the no-alloc M0 session reach the AP `Arc` blocked.

use alloc::rc::Rc;

use wz_runtime_core::TimeSource;
use wz_session_core::link::{BoxedLinkDriver, SessionRuntime};
use wz_session_core::session_actions::SessionLinkActions;

use crate::runtime_impl::CoopRuntime;
use crate::time::{ClockSource, CoopTime};

/// MCU-profile [`SessionRuntime`] binding. The link sink is a
/// `Rc<dyn BoxedLinkDriver>` shared by the single-task drive loop and
/// its synchronous `LwipUdpSocket` driver; `!Send` is the intended
/// shape (see module doc).
impl<C: ClockSource> SessionRuntime for CoopRuntime<C> {
    type LinkSink = Rc<dyn BoxedLinkDriver>;

    // R311y205 (transport-multilink IMPL-2b-i) — the MCU shareable pointer is
    // `Rc`, not `Arc`: the single-task sync drive loop shares the aggregation
    // core only within its own task, never across threads, so the refcount needs
    // no atomics — the same seam that unblocks the no-alloc M0+ session reach
    // (`alloc::sync::Arc` requires `target_has_atomic = "ptr"`, absent on
    // ARMv6-M; `Rc` lowers to plain loads / stores). The MCU profile is
    // rsa-AP-only and always N=1, so this is only ever a refcount-1 pointer here.
    type Shared<U> = Rc<U>;

    fn share<U>(value: U) -> Self::Shared<U> {
        Rc::new(value)
    }

    // R311ja — the MCU action handle is `Rc`, not `Arc`: the single-task
    // sync drive loop shares the bundle only with its own FSM binding, never
    // across threads, so the refcount needs no atomics. This is the seam
    // that unblocks the no-alloc M0+ session reach — `alloc::sync::Arc`
    // requires `target_has_atomic = "ptr"`, which ARMv6-M lacks; `Rc` lowers
    // to plain loads / stores and cross-compiles on every Phase W target.
    type ActionsHandle<T: TimeSource> = Rc<SessionLinkActions<Self, T>>;

    fn wrap_actions<T: TimeSource>(actions: SessionLinkActions<Self, T>) -> Self::ActionsHandle<T> {
        Rc::new(actions)
    }

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
// so the Layer G cross-compile of `wz-runtime-coop --features
// session-unicast` type-checks them on every MCU target, proving the
// binding holds on bare metal and not merely on the host test build.

/// Stage 4a precondition: `SessionLinkActions<CoopRuntime<C>,
/// CoopTime<C>>` is well-formed — i.e. `CoopRuntime<C>: SessionRuntime`
/// and `CoopTime<C>: TimeSource` both hold, so the runtime-agnostic
/// session action bundle composes on the MCU profile. Naming the type in
/// a reference position forces the struct's declared bounds to be
/// satisfied at compile time. The sync drive loop consumer
/// (`session_drive`) that constructs and drives it lands in the
/// follow-up; this gate is the type-check that unblocks it.
#[allow(dead_code)]
fn _session_link_actions_composes_on_lwip<C: ClockSource>(
    _actions: &wz_session_core::session_actions::SessionLinkActions<CoopRuntime<C>, CoopTime<C>>,
) {
}

/// R311y742 (N50) — install this session's OWN keyexpr id space into an
/// application registry, on the MCU profile.
///
/// The AP does this inside `Session::new` (R311y739) for the reason R236 moved
/// the zid install there: the fact is authoritative at construction, so making
/// the application ask for it only creates a way to forget. The MCU has no such
/// single owner — `run_session` takes the actions bundle and hands decoded
/// batches to an `on_event` closure, and the registry belongs to the
/// application — so this is the named place to do it, one line, at bring-up:
///
/// ```ignore
/// install_own_mapping_space(&mut observer.subscribers, &actions);
/// ```
///
/// Without it an MCU node that calls `send_declare_keyexpr` drops every Push
/// the peer names with that alias, because zenoh PREFERS the receiver's own
/// expr id and stamps it `Mapping::Receiver` (`dispatcher/resource.rs:625`).
/// That is the defect R311y739 closed on the AP side and R311y740 unwalled here.
///
/// ## Why this is gated to targets WITHOUT atomic pointers
///
/// R311y742 measured the shape and found a real limit, stated rather than
/// hidden. `CoopRuntime::ActionsHandle` is `Rc<SessionLinkActions<..>>` on
/// EVERY MCU target, but
/// [`SharedOwnMappingSpace`](wz_session_core::wireexpr_resolve::SharedOwnMappingSpace)
/// is keyed on `target_has_atomic = "ptr"` — so it is `Rc` on thumbv6m and
/// `Arc` on the other six (M3 / M4F / M7 / M23 / M33 / RISC-V IMAC). An `Rc`
/// cannot become an `Arc` to the same allocation, so on those six the coop
/// profile has no install path at all, and this function correctly does not
/// exist there rather than pretending to.
///
/// Closing that needs the alias keyed on the CONCURRENCY MODEL (does this build
/// share the registry across tasks?) instead of on the target's atomics, which
/// means a named feature rather than a `cfg` — a change that moves the declared
/// cargo-feature surface the A3 / A5 inventory gates count, so it is its own
/// round. Carry N52.
#[cfg(not(target_has_atomic = "ptr"))]
pub fn install_own_mapping_space<C, T, S>(
    registry: &mut wz_session_core::pubsub::SubscriberRegistry<S>,
    actions: &Rc<SessionLinkActions<CoopRuntime<C>, T>>,
) where
    // `'static` on both parameters is not incidental: `dyn OwnMappingSpace`
    // carries an implicit `+ 'static`, so the erased handle must outlive any
    // borrow the registry could hand out. Stated here rather than left to the
    // caller to discover from an E0310 at the call site.
    C: ClockSource + 'static,
    T: wz_runtime_core::TimeSource + 'static,
    S: wz_session_core::sink::SampleSink,
{
    registry.set_own_mapping_space(actions.clone());
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
    _assert_clone::<<CoopRuntime<C> as SessionRuntime>::LinkSink>();
}
