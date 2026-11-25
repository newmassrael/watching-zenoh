// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
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
//! profile [`SessionRuntime::ActionsHandle`] — a counted cell handle here
//! (`link_cells::CellRc`), not `Arc` — for shared read access
//! within that one task: the FSM action binding and the drive loop read the
//! same bundle, but never across threads, so an atomic refcount would be
//! pure waste *and* would wall the session off ARMv6-M (`alloc::sync::Arc`
//! needs `target_has_atomic = "ptr"`, absent on Cortex-M0/M0+). The single-task count is exactly what
//! lets the MCU session stack — handshake + reassembly consumer — reach
//! ARMv6-M, the no-alloc M0 session reach the AP `Arc` blocked.

use wz_runtime_core::TimeSource;
use wz_session_core::entropy::EntropySource;
#[cfg(not(feature = "session-slot"))]
use wz_session_core::entropy::EntropyUnavailable;
#[cfg(not(feature = "session-slot"))]
use wz_session_core::link::ShareValues;
use wz_session_core::link::{BoxedLinkDriver, SessionRuntime};
#[cfg(not(feature = "session-slot"))]
use wz_session_core::session_actions::SessionLinkActions;
#[cfg(feature = "session-slot")]
use wz_session_core::session_slot::{SlotClaim, SlotRef, SlotSink};

#[cfg(not(feature = "session-slot"))]
use crate::link_cells::{CellRc, CountKind, OneTask};
use crate::runtime_impl::CoopRuntime;
use crate::sync::LockKind;
use crate::time::{ClockSource, CoopTime};

/// What [`SessionRuntime::Shared`] is on the slot profile: a pointer that cannot
/// exist. It has no value, so the claims the seam makes of it (it clones, it reads
/// as the value behind it) hold of nothing and cost nothing.
#[cfg(feature = "session-slot")]
pub enum NoShared<U> {
    #[doc(hidden)]
    Never(core::convert::Infallible, core::marker::PhantomData<U>),
}

#[cfg(feature = "session-slot")]
impl<U> Clone for NoShared<U> {
    fn clone(&self) -> Self {
        match self {
            NoShared::Never(never, _) => match *never {},
        }
    }
}

#[cfg(feature = "session-slot")]
impl<U> core::ops::Deref for NoShared<U> {
    type Target = U;

    fn deref(&self) -> &U {
        match self {
            NoShared::Never(never, _) => match *never {},
        }
    }
}

/// MCU-profile [`SessionRuntime`] binding. The link sink is a
/// `Rc<dyn BoxedLinkDriver>` shared by the single-task drive loop and
/// its synchronous `LwipUdpSocket` driver; `!Send` is the intended
/// shape (see module doc).
// The slot profile has no pointer to share a value behind (its `Shared` has no value): the
// bundle owns its kernel and its link, so the profile shares nothing and does not implement this.
#[cfg(not(feature = "session-slot"))]
impl<C: ClockSource, D: BoxedLinkDriver + ?Sized + 'static, K: LockKind> ShareValues
    for CoopRuntime<C, D, K>
{
    fn share<U>(value: U) -> Self::Shared<U> {
        crate::link_cells::CellRc::on_heap(value)
    }
}

impl<C: ClockSource, D: BoxedLinkDriver + ?Sized + 'static, K: LockKind> SessionRuntime
    for CoopRuntime<C, D, K>
{
    // The driver is the runtime's own `D`: the trait object for the profile that picks its link at
    // run time (the default), the driver's own type where the build names it, which makes every
    // call the session makes through the link a direct one.
    type Driver = D;

    // The sink is a counted handle on the cell the link's driver lives in, lent from the session's
    // arena or, for a link no table lends one, on the heap (`crate::link_cells`), counted as the
    // lock kind counts what its session's holders share (`LockKind::Count`).
    #[cfg(not(feature = "session-slot"))]
    type LinkSink = crate::link_cells::CellRc<D, K::Count>;

    // Fixed-memory step S5 — under `session-slot` the sink is a reference to the
    // driver the session's own slot holds (`wz_session_core::session_slot`), not
    // an `Rc` of one: there is nothing to allocate and the slot is what frees it.
    #[cfg(feature = "session-slot")]
    type LinkSink = SlotSink<D>;

    // The shareable pointer is a cell handle, counted as an `Rc` is and not atomically: the
    // single-task drive loop shares the kernel and the link only within its own task, and
    // ARMv6-M has no atomic pointer. A cell handle, so an engine that reserved a table of cells
    // writes a link's halves in one of them (`CellRc::halves_in`), and the same type names halves
    // on the heap (`ShareValues::share`).
    #[cfg(not(feature = "session-slot"))]
    type Shared<U> = crate::link_cells::CellRc<U, K::Count>;

    // Fixed-memory step S9c -- the slot profile holds no shared pointer: the bundle
    // is one value in its slot, with its kernel and its link as its own fields
    // (`SessionLinkActions::hold_core` / `hold_link` have a slot form that never asks
    // the runtime to share), so there is no value of this type and a build that made
    // one would be asking the profile for an aggregation it has no form of.
    #[cfg(feature = "session-slot")]
    type Shared<U> = NoShared<U>;

    // R2708 (open-debt item 785) — the MCU profile owes its loop NOTHING each
    // iteration, and `()` says so at zero cost: no field, no branch, no future
    // in a profile that has no executor to run one. That is the whole reason
    // the kernel carries this as an associated type rather than as something it
    // could name itself.
    type IterationWork = ();

    // What the session's holders write without a lock, and what they reach one at a time, are the
    // lock kind's (`LockKind::Flag`, `Word`, `Local`): cells where one task holds them (no atomic
    // instruction, and none of 64 bits that an ARMv6-M or a Cortex-M7 lacks), atomics and a lock of
    // each value where several threads do.
    type Flag = K::Flag;
    type Word = K::Word;
    type Local<T>
        = K::Local<T>
    where
        T: Send + 'static;

    fn new_local<T>(value: T) -> Self::Local<T>
    where
        T: Send + 'static,
    {
        K::new_local(value)
    }

    fn with_local<T, U>(local: &Self::Local<T>, f: impl FnOnce(&mut T) -> U) -> U
    where
        T: Send + 'static,
    {
        K::with_local(local, f)
    }

    // R311ja — the MCU action handle is counted without atomics, not an `Arc`:
    // the single-task sync drive loop shares the bundle only with its own FSM
    // binding, never across threads (`alloc::sync::Arc` requires
    // `target_has_atomic = "ptr"`, which ARMv6-M lacks). It is a cell handle so
    // an engine that lent a table of cells places the bundle in one of them
    // (`CellRc::place`) and the same type names a bundle on the heap.
    #[cfg(not(feature = "session-slot"))]
    type ActionsHandle<T: TimeSource> =
        crate::link_cells::CellRc<SessionLinkActions<Self, T>, K::Count>;

    // Fixed-memory step S5 — under `session-slot` the handle is a counted
    // reference to the session in its slot, which the slot table hands out and
    // frees the slot with the last of.
    #[cfg(feature = "session-slot")]
    type ActionsHandle<T: TimeSource> = SlotRef<Self, T>;

    // The session's one entropy source, as each of its links' bindings holds it.
    #[cfg(not(feature = "session-slot"))]
    type EntropyDraw = SessionEntropy<K::Count>;
    #[cfg(feature = "session-slot")]
    type EntropyDraw = SessionEntropy;

    #[cfg(not(feature = "session-slot"))]
    fn wrap_actions<T: TimeSource>(actions: SessionLinkActions<Self, T>) -> Self::ActionsHandle<T> {
        crate::link_cells::CellRc::on_heap(actions)
    }

    fn link_driver(sink: &Self::LinkSink) -> &D {
        #[cfg(not(feature = "session-slot"))]
        {
            // The handle derefs to the driver the action methods send through: `dyn
            // BoxedLinkDriver` for the profile that picks its link at run time, the driver's own
            // type otherwise. No auto-trait coercion is needed (the MCU sink carries none),
            // unlike the AP `&**sink` which also drops `+ Send + Sync`.
            sink
        }
        #[cfg(feature = "session-slot")]
        {
            sink.driver()
        }
    }
}

/// The handle to a session, as this profile holds it: a counted handle on the bundle, or
/// under `session-slot` a counted reference to the slot that holds it. The type
/// the drive loop, the FSM's action binding and the application layer each take,
/// written once so the two spellings are one name. `K` is how the runtime locks what it lends the
/// session ([`LockKind`]).
pub type SessionHandle<C, D = dyn BoxedLinkDriver, K = crate::sync::Shared> =
    <CoopRuntime<C, D, K> as SessionRuntime>::ActionsHandle<CoopTime<C>>;

/// The session's runtime's entropy handle, as `CoopRuntime<C, D, K>` holds it
/// ([`SessionRuntime::EntropyDraw`]): what a pump of that runtime is built with.
pub type EntropyOf<C, D = dyn BoxedLinkDriver, K = crate::sync::Shared> =
    <CoopRuntime<C, D, K> as SessionRuntime>::EntropyDraw;

/// A session's entropy source as its handles reach it: a draw answers the source's, or no entropy
/// when the source cannot be drawn from now.
#[cfg(not(feature = "session-slot"))]
pub trait DrawsEntropy {
    /// Fill `buf` from the source.
    fn try_draw(&self, buf: &mut [u8]) -> Result<(), EntropyUnavailable>;
}

/// One task's handles reach the source one draw at a time; a draw that finds the source already
/// drawing (a source that drew again from inside its own draw) is refused as no entropy, the
/// fail-closed answer.
#[cfg(not(feature = "session-slot"))]
impl<S: EntropySource> DrawsEntropy for core::cell::RefCell<S> {
    fn try_draw(&self, buf: &mut [u8]) -> Result<(), EntropyUnavailable> {
        match self.try_borrow_mut() {
            Ok(mut source) => source.try_fill_bytes(buf),
            Err(_) => Err(EntropyUnavailable),
        }
    }
}

/// Handles on several threads reach the source through its lock: a draw waits for one under way
/// on another thread, since two links' handshakes on two threads each draw and neither may be
/// refused for the other's.
#[cfg(all(not(feature = "session-slot"), feature = "host-lock"))]
impl<S: EntropySource + Send> DrawsEntropy for crate::cs::HostMutex<S> {
    fn try_draw(&self, buf: &mut [u8]) -> Result<(), EntropyUnavailable> {
        self.with(|source| source.try_fill_bytes(buf))
    }
}

/// How the handles on a session's entropy source are counted ([`CountKind`]), and what the
/// source is held in for that count: one task's handles reach it through a `RefCell` and ask
/// nothing more of it, handles that cross threads reach it through a lock and need it `Send`.
#[cfg(not(feature = "session-slot"))]
pub trait EntropyCount: CountKind {
    /// The source as a handle of this count reaches it.
    type Held: ?Sized + DrawsEntropy + 'static;

    /// `source` on the heap, behind the first handle of this count.
    fn hold<S: EntropySource + Send + 'static>(source: S) -> CellRc<Self::Held, Self>;
}

#[cfg(not(feature = "session-slot"))]
impl EntropyCount for OneTask {
    type Held = dyn DrawsEntropy;

    fn hold<S: EntropySource + Send + 'static>(source: S) -> CellRc<dyn DrawsEntropy> {
        held_by_one_task(source)
    }
}

#[cfg(all(
    not(feature = "session-slot"),
    feature = "host-lock",
    target_has_atomic = "8"
))]
impl EntropyCount for crate::link_cells::Atomic {
    type Held = dyn DrawsEntropy + Send + Sync;

    fn hold<S: EntropySource + Send + 'static>(
        source: S,
    ) -> CellRc<dyn DrawsEntropy + Send + Sync, Self> {
        let held = CellRc::<_, Self>::on_heap(crate::cs::HostMutex::new(source));
        // SAFETY: the closure is the unsizing coercion of the pointer it is handed.
        unsafe {
            held.unsize(|value| -> core::ptr::NonNull<dyn DrawsEntropy + Send + Sync> { value })
        }
    }
}

/// `source` behind the first handle of one task's count: what a source that is not `Send` (a
/// board's) is held by.
#[cfg(not(feature = "session-slot"))]
fn held_by_one_task<S: EntropySource + 'static>(source: S) -> CellRc<dyn DrawsEntropy> {
    let held = CellRc::<_, OneTask>::on_heap(core::cell::RefCell::new(source));
    // SAFETY: the closure is the unsizing coercion of the pointer it is handed.
    unsafe { held.unsize(|value| -> core::ptr::NonNull<dyn DrawsEntropy> { value }) }
}

/// The session's one entropy source, as this profile's [`SessionRuntime::EntropyDraw`]: a counted
/// handle on it, cloned to each of the session's links, whose bindings draw every InitAck's cookie
/// nonce and challenges from it. The board supplies its source once, as a TYPE, and a link's
/// bundle keeps none. `N` counts the handles as the session's lock kind counts its own
/// (`LockKind::Count`): one task's need no atomics and take any source ([`Self::new`]); handles
/// that cross threads take a source that is `Send` ([`Self::held`]).
#[cfg(not(feature = "session-slot"))]
pub struct SessionEntropy<N: EntropyCount = OneTask>(CellRc<N::Held, N>);

// Not derived: a derive would ask `N: Clone` of a kind of count.
#[cfg(not(feature = "session-slot"))]
impl<N: EntropyCount> Clone for SessionEntropy<N> {
    fn clone(&self) -> Self {
        Self(self.0.clone())
    }
}

#[cfg(not(feature = "session-slot"))]
impl SessionEntropy {
    /// The handle on `source`, the session's one source, for a session of one task.
    pub fn new(source: impl EntropySource + 'static) -> Self {
        Self(held_by_one_task(source))
    }
}

#[cfg(not(feature = "session-slot"))]
impl<N: EntropyCount> SessionEntropy<N> {
    /// The handle on `source`, the session's one source, counted as `N` counts.
    pub fn held(source: impl EntropySource + Send + 'static) -> Self {
        Self(N::hold(source))
    }
}

#[cfg(not(feature = "session-slot"))]
impl<N: EntropyCount> EntropySource for SessionEntropy<N> {
    fn try_fill_bytes(&mut self, buf: &mut [u8]) -> Result<(), EntropyUnavailable> {
        self.0.try_draw(buf)
    }
}

/// See the counted form. Under `session-slot` the source lies in the session's slot, which hands
/// out its one exclusive reference when it is opened ([`new_session_in_slot`]); nothing is
/// allocated.
#[cfg(feature = "session-slot")]
pub type SessionEntropy = &'static mut dyn EntropySource;

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
/// follow-up; this gate is the type-check that unblocks it. Generic over the clock, so a named
/// function rather than a `const`; its leading `_` keeps it out of the dead-code lint.
fn _session_link_actions_composes_on_lwip<C: ClockSource>(
    _actions: &wz_session_core::session_actions::SessionLinkActions<CoopRuntime<C>, CoopTime<C>>,
) {
}

/// R311y819 — the MCU profile's SESSION-BUNDLE CONSTRUCTION SEAM, the exact
/// counterpart of the AP's `wz_runtime_tokio::session_glue::new_session_actions`.
///
/// The bundle is one link's and keeps no entropy: the per-handshake cookie nonce and
/// challenges are drawn at each InitAck by the session's handshake binding, from the
/// session's one source ([`SessionEntropy`]) the pump that builds its engine is handed.
/// Before that, a bundle holds no nonce (`cookie_nonce` is `None`, fail-closed).
#[cfg(all(feature = "session-unicast", not(feature = "session-slot")))]
pub fn new_session_actions<C>(
    driver: crate::link_cells::CellRc<dyn BoxedLinkDriver>,
    params: wz_session_core::session_init_params::SessionInitParams,
    clock: CoopTime<C>,
) -> SessionHandle<C>
where
    C: ClockSource,
{
    SessionLinkActions::<CoopRuntime<C>, CoopTime<C>>::new_generic(driver, params, clock)
}

/// Fixed-memory step S5 — `new_session_actions` for `session-slot`: the same
/// seam, with the session built in the slot the caller claimed
/// ([`SessionSlots::claim`](wz_session_core::session_slot::SessionSlots::claim)),
/// which already holds the link driver and the board's entropy source by value.
///
/// The slot's entropy source is handed back beside the handle, once: the session's one
/// source, which the pump that builds the session's engine hands its binding. Nothing is
/// allocated.
#[cfg(feature = "session-slot")]
pub fn new_session_in_slot<C, D, E>(
    claim: SlotClaim<CoopRuntime<C, D>, CoopTime<C>, D, E>,
    params: impl FnOnce() -> wz_session_core::session_init_params::SessionInitParams,
    clock: CoopTime<C>,
) -> (SlotRef<CoopRuntime<C, D>, CoopTime<C>>, SessionEntropy)
where
    C: ClockSource + 'static,
    D: BoxedLinkDriver + 'static,
    E: EntropySource + Send + 'static,
{
    let (actions, entropy) = claim.open(params, clock);
    let entropy: SessionEntropy = entropy;
    (actions, entropy)
}

/// LinkSink fixity. Mirrors the AP-side
/// link-sink bounds assert in `wz_runtime_tokio::runtime_impl`,
/// but pins the *opposite* auto-trait shape: the MCU sink is `Clone`
/// (the shared-by-refcount contract every profile satisfies) and is
/// deliberately NOT asserted `Send + Sync` — re-binding it to an `Arc`
/// "to make it Send" would silently reintroduce atomic refcount traffic
/// the single-task profile does not need. A regression that re-adds a
/// `Send + Sync` supertrait onto `BoxedLinkDriver` (which would force an
/// `unsafe impl Send` on the `!Send` `LwipUdpSocket` driver) surfaces at
/// the driver impl, not here. Generic over the clock, as the composition check above is.
fn _lwip_session_runtime_link_sink_is_clone<C: ClockSource>() {
    fn _assert_clone<T: Clone>() {}
    _assert_clone::<<CoopRuntime<C> as SessionRuntime>::LinkSink>();
}

#[cfg(all(test, feature = "session-unicast", not(feature = "session-slot")))]
mod cookie_nonce_draw_tests {
    use super::*;
    use alloc::vec;
    use wz_session_core::entropy::{EntropySource, EntropyUnavailable};
    // R2371 — the driver-outcome type is named only by this module's test
    // double, so the import lives HERE: at module level it is unused in the
    // non-test build, which `-D unused-imports` refuses.
    use wz_session_core::link::LinkSendOutcome;
    use wz_session_core::reliability::Reliability;
    use wz_session_core::session_init_params::SessionInitParams;
    use wz_session_core::signing_key::SigningKey;

    /// The seam needs a link sink, and nothing about the draw touches it.
    struct NullDriver;

    impl BoxedLinkDriver for NullDriver {
        fn send_blocking(&self, _bytes: &[u8], _reliability: Reliability) -> LinkSendOutcome {
            LinkSendOutcome::Sent
        }
        fn open_blocking(&self) {}
        fn close_blocking(&self) {}
    }

    /// A frozen clock, so the bundle composes without a board.
    #[derive(Clone, Copy)]
    struct StoppedClock;

    impl ClockSource for StoppedClock {
        fn now_us(&self) -> u64 {
            0
        }
    }

    /// A board-shaped source: distinct bytes on every call, which is the
    /// property a real TRNG has and the fixture constant does not.
    struct Counting(u8);

    impl EntropySource for Counting {
        fn try_fill_bytes(&mut self, buf: &mut [u8]) -> Result<(), EntropyUnavailable> {
            for slot in buf.iter_mut() {
                *slot = self.0;
                self.0 = self.0.wrapping_add(1);
            }
            Ok(())
        }
    }

    /// A board whose TRNG is not ready — the fail-closed half.
    struct Dry;

    impl EntropySource for Dry {
        fn try_fill_bytes(&mut self, _buf: &mut [u8]) -> Result<(), EntropyUnavailable> {
            Err(EntropyUnavailable)
        }
    }

    fn params() -> SessionInitParams {
        SessionInitParams {
            whatami: wz_session_core::WhatAmI::Peer,
            zid: [0x0A, 0x0B, 0x0C, 0x0D].into(),
            seq_num_res: wz_session_core::policy::SnResolution::Bits32,
            req_id_res: 2,
            batch_size: 1024,
            lease_ms: 10_000,
            keep_alive: wz_session_core::session_init_params::KeepAliveConf::PICO,
            initial_sn: 0,
            cookie: vec![0u8; 16],
            tx_queue: wz_session_core::session_init_params::TxQueueConf::of_snapshot(
                &wz_session_core::policy::SessionPolicy::defaults(),
                &wz_session_core::limits::SessionLimits::BUILD,
            ),
            link_rx: wz_session_core::session_init_params::LinkRxConf::default(),
            policy: wz_session_core::policy::SessionPolicy::defaults(),
            limits: wz_session_core::limits::SessionLimits::BUILD,
            cookie_signing_key: SigningKey::new(vec![7u8; 32])
                .expect(">=32-byte key")
                .into(),
            region: None,
        }
    }

    fn build() -> SessionHandle<StoppedClock> {
        let runtime = CoopRuntime::new(StoppedClock);
        let clock = CoopTime::new(&runtime);
        let driver = crate::link_cells::heap_sink(NullDriver);
        new_session_actions(driver, params(), clock)
    }

    /// The bundle is one link's and keeps no source, so it holds no nonce until a handshake's
    /// binding draws one from the session's source.
    #[test]
    fn a_bundle_holds_no_nonce_until_its_binding_draws_one() {
        let actions = build();
        assert_eq!(actions.cookie_nonce(), None, "no source, no nonce");
        assert!(actions.draw_cookie_nonce(&mut SessionEntropy::new(Counting(0))));
        assert!(actions.cookie_nonce().is_some());
    }

    /// R2763 — the acceptor re-draws per handshake: two draws on one bundle are two nonces.
    #[test]
    fn two_draws_on_one_bundle_take_two_nonces() {
        let actions = build();
        let mut entropy = SessionEntropy::new(Counting(0));
        assert!(
            actions.draw_cookie_nonce(&mut entropy),
            "a live source must draw"
        );
        let first = actions.cookie_nonce();
        assert!(actions.draw_cookie_nonce(&mut entropy));
        assert_ne!(
            first,
            actions.cookie_nonce(),
            "a second handshake on one bundle must not reuse the first's nonce",
        );
    }

    /// The handle draws the source's own bytes, in the port's byte order: a handle that hashed
    /// or truncated the draw would pass the assertions above.
    #[test]
    fn the_drawn_nonce_is_the_sources_own_value() {
        let mut probe = Counting(0);
        let expected = probe.try_next_u64().unwrap();
        let actions = build();
        assert!(actions.draw_cookie_nonce(&mut SessionEntropy::new(Counting(0))));
        assert_eq!(actions.cookie_nonce(), Some(expected));
    }

    /// One source serves every link of a session: two links' bindings hold handles on it and
    /// draw from its one stream, so their nonces are its consecutive values.
    #[test]
    fn the_links_of_a_session_draw_from_its_one_source() {
        let mut probe = Counting(0);
        let (first, second) = (probe.try_next_u64().unwrap(), probe.try_next_u64().unwrap());
        let session = SessionEntropy::new(Counting(0));
        let (a, b) = (build(), build());
        assert!(a.draw_cookie_nonce(&mut session.clone()));
        assert!(b.draw_cookie_nonce(&mut session.clone()));
        assert_eq!(
            (a.cookie_nonce(), b.cookie_nonce()),
            (Some(first), Some(second))
        );
    }

    /// Handles on a source counted across threads draw from it on any thread, all from its one
    /// stream: a draw on another thread and one here take its consecutive values.
    #[cfg(all(feature = "host-lock", target_has_atomic = "8"))]
    #[test]
    fn an_entropy_handle_counted_across_threads_draws_on_another_thread() {
        extern crate std;

        let mut probe = Counting(0);
        let (first, second) = (probe.try_next_u64().unwrap(), probe.try_next_u64().unwrap());
        let mut here = SessionEntropy::<crate::link_cells::Atomic>::held(Counting(0));
        let mut there = here.clone();
        let drawn = std::thread::spawn(move || there.try_next_u64().is_ok_and(|n| n == first))
            .join()
            .expect("the other thread drew");
        assert!(drawn, "the other thread's draw is the source's first value");
        assert_eq!(here.try_next_u64().ok(), Some(second));
    }

    #[test]
    fn a_dry_source_leaves_the_slot_fail_closed() {
        // Not "no binding" but "admit no OpenSyn". A fallback to a constant
        // here would be indistinguishable from a working binding.
        let actions = build();
        assert!(!actions.draw_cookie_nonce(&mut SessionEntropy::new(Dry)));
        assert_eq!(
            actions.cookie_nonce(),
            None,
            "an entropy failure must leave the acceptor refusing, never guessing",
        );
    }

    /// R2763 — a source that WORKED and then stops must not leave the previous handshake's
    /// nonce standing, because that is the binding the refresh exists to replace.
    #[test]
    fn a_source_that_dries_up_clears_the_nonce_it_had_drawn() {
        /// Live for the first draw, dry for every draw after it.
        struct DriesUp(bool);

        impl EntropySource for DriesUp {
            fn try_fill_bytes(&mut self, buf: &mut [u8]) -> Result<(), EntropyUnavailable> {
                if self.0 {
                    self.0 = false;
                    buf.fill(0x5A);
                    Ok(())
                } else {
                    Err(EntropyUnavailable)
                }
            }
        }

        let actions = build();
        let mut entropy = SessionEntropy::new(DriesUp(true));
        assert!(
            actions.draw_cookie_nonce(&mut entropy),
            "the first draw lands"
        );
        assert!(
            !actions.draw_cookie_nonce(&mut entropy),
            "the second draw must fail"
        );
        assert_eq!(
            actions.cookie_nonce(),
            None,
            "a failed refresh must CLEAR, never leave the previous handshake's \
             nonce in place for this one to re-mint",
        );
    }
}
