// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
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

/// R311y819 — the MCU profile's SESSION-BUNDLE CONSTRUCTION SEAM, the exact
/// counterpart of the AP's `wz_runtime_tokio::session_glue::new_session_actions`.
///
/// ## What it closes
///
/// R311y813 bound the acceptor's anti-amplification cookie to ONE handshake by
/// folding a per-bundle nonce into the cookie MAC, and drew that nonce at the
/// AP CONSTRUCTION seam rather than at each of the seven accept entry points —
/// its own argument being that a caller cannot forget what construction does.
/// The MCU profile had no such seam: it called
/// [`SessionLinkActions::new_generic`] directly, which leaves the slot at its
/// fail-closed `None`, and the one in-tree MCU deploy therefore installed a
/// CONSTANT. A board built from that shape answers every handshake of its
/// service life with one cookie per zid — the defect R311y813 closed on the AP
/// side, alive on the profile whose e2e is a fixture. This seam gives the MCU
/// the same "drawn at construction" property, so a board integrator supplies a
/// TYPE (an [`EntropySource`]) instead of remembering a call.
///
/// ## Why the source is a parameter
///
/// §2.5 (`intrinsics-runtime--symbol-surface/2-5-rng`, ratified Round 11) puts
/// RNG in the PLUGIN tier precisely because of implementation multiplicity —
/// HW TRNG, ADC + Yarrow, `getrandom`, `arc4random`. There is no source this
/// crate could name that is right for every board, so it takes one.
///
/// ## Fail-closed, and how you see it
///
/// An entropy failure leaves the slot at `None`, which is NOT "no cookie
/// binding" but "admit no OpenSyn": the acceptor mints no HMAC cookie and every
/// inbound OpenSyn is refused. That is deliberate — a fallback to an
/// unbound cookie would be indistinguishable from a working binding. The AP
/// seam reports the failure through `log::error!`; a no_std board has no such
/// channel, so the observable here is
/// [`SessionLinkActions::cookie_nonce`] returning `None`, and the bundle is
/// still returned because an INITIATOR-role bundle never reads the slot and
/// must not be denied a session over it.
#[cfg(feature = "session-unicast")]
pub fn new_session_actions<C, E>(
    driver: Rc<dyn BoxedLinkDriver>,
    params: wz_session_core::session_init_params::SessionInitParams,
    clock: CoopTime<C>,
    entropy: &mut E,
) -> Rc<SessionLinkActions<CoopRuntime<C>, CoopTime<C>>>
where
    C: ClockSource,
    E: wz_session_core::entropy::EntropySource + ?Sized,
{
    let actions =
        SessionLinkActions::<CoopRuntime<C>, CoopTime<C>>::new_generic(driver, params, clock);
    // The draw, and the whole point of the seam. `Err` is dropped rather than
    // surfaced: the slot's own `None` is the report (see the fail-closed note
    // above), and there is no no_std channel to log through.
    if let Ok(nonce) = entropy.try_next_u64() {
        actions.refresh_cookie_nonce(nonce);
    }
    actions
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

#[cfg(all(test, feature = "session-unicast"))]
mod cookie_nonce_draw_tests {
    use super::*;
    use alloc::vec;
    use wz_session_core::entropy::{EntropySource, EntropyUnavailable};
    use wz_session_core::reliability::Reliability;
    use wz_session_core::session_init_params::SessionInitParams;
    use wz_session_core::signing_key::SigningKey;

    /// The seam needs a link sink, and nothing about the draw touches it.
    struct NullDriver;

    impl BoxedLinkDriver for NullDriver {
        fn send_blocking(&self, _bytes: &[u8], _reliability: Reliability) {}
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
            version: 0x05,
            whatami: wz_session_core::WhatAmI::Peer,
            zid: vec![0x0A, 0x0B, 0x0C, 0x0D],
            seq_num_res: 2,
            req_id_res: 2,
            batch_size: 1024,
            lease_ms: 10_000,
            initial_sn: 0,
            cookie: vec![0u8; 16],
            cookie_signing_key: SigningKey::new(vec![7u8; 32]).expect(">=32-byte key"),
        }
    }

    fn build<E: EntropySource>(
        entropy: &mut E,
    ) -> Rc<SessionLinkActions<CoopRuntime<StoppedClock>, CoopTime<StoppedClock>>> {
        let runtime = CoopRuntime::new(StoppedClock);
        let clock = CoopTime::new(&runtime);
        let driver: Rc<dyn BoxedLinkDriver> = Rc::new(NullDriver);
        new_session_actions(driver, params(), clock, entropy)
    }

    #[test]
    fn the_mcu_seam_installs_a_cookie_nonce_at_construction() {
        // The headline. Before R311y819 the MCU profile called `new_generic`
        // directly, which leaves the slot at `None`, and every deploy had to
        // remember to install one itself.
        let mut src = Counting(0);
        let actions = build(&mut src);
        assert!(
            actions.cookie_nonce().is_some(),
            "the construction seam must draw the nonce, so a deploy cannot forget it",
        );
    }

    #[test]
    fn two_bundles_take_two_nonces() {
        // The replay property, and the one a constant defeats: a board built
        // from the pre-R311y819 MCU shape answered every handshake of its
        // service life with one cookie per zid.
        let mut src = Counting(0);
        let (a, b) = (build(&mut src), build(&mut src));
        assert_ne!(
            a.cookie_nonce(),
            b.cookie_nonce(),
            "two bundles off one source must not share a cookie nonce",
        );
    }

    #[test]
    fn the_drawn_nonce_is_the_sources_own_value() {
        // Binds the seam to the port's fixed byte order rather than to
        // "some value": a seam that hashed or truncated the draw would pass
        // both assertions above.
        let mut probe = Counting(0);
        let expected = probe.try_next_u64().unwrap();
        let mut src = Counting(0);
        assert_eq!(build(&mut src).cookie_nonce(), Some(expected));
    }

    #[test]
    fn a_dry_source_leaves_the_slot_fail_closed() {
        // Not "no binding" but "admit no OpenSyn". A fallback to a constant
        // here would be indistinguishable from a working binding, which is
        // exactly the state this round found the MCU profile in.
        let mut src = Dry;
        assert_eq!(
            build(&mut src).cookie_nonce(),
            None,
            "an entropy failure must leave the acceptor refusing, never guessing",
        );
    }
}
