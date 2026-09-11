// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

#![no_std]

//! wz-runtime-coop — Phase W MCU profile.
//!
//! This crate is the MCU sibling of [`wz-runtime-tokio`] for the §5.P
//! runtime-services-tier contract. The R311au scope (C) entry landed
//! the [`sync`] module (`critical_section::Mutex<RefCell<T>>` aliases)
//! under `#![no_std]` without `alloc`. R311av lands the `Runtime`
//! trait impl behind the `alloc` feature: a self-rolled cooperative
//! task pool ([`executor`]) + [`join_handle`] handle type + own
//! [`ClockSource`] / [`CoopTime`] in [`time`], satisfying the
//! `wz_runtime_core::Runtime` and `wz_runtime_core::TimeSource`
//! contracts so generic code over `R: Runtime, T: TimeSource`
//! composes against this profile identically to the AP one.
//!
//! ## Feature gate split
//!
//! - **Default (no features)**: `sync` only. The R311au cross-compile
//!   surface — every Phase W MCU target (`thumbv6m`, `thumbv7m`,
//!   `thumbv7em-hf`, `thumbv8m.{base,main}{,-hf}`, `riscv32imac`)
//!   builds the sync alias under `#![no_std]` with no allocator
//!   requirement. This is the Layer G.4 lane.
//! - **`alloc`**: adds the [`executor`] + [`join_handle`] +
//!   [`runtime_impl`] + [`time`] modules. The `wz-runtime-core` dep
//!   activates (with its own `alloc` feature) and the
//!   [`CoopRuntime`] + [`CoopJoinHandle`] + [`CoopTime`] surface
//!   becomes available. Layer G.4-alloc covers the cross-compile.
//!
//! ## Why this scope shape (R63 anti-stub honesty)
//!
//! Every item exported under the `alloc` feature is a real
//! implementation:
//!
//! - [`CoopRuntime::spawn`] heap-allocates a `Pin<Box<dyn Future +
//!   Send>>` wrapper that captures the user future + a JoinState
//!   handle, pushes it into the executor's task vector, and returns
//!   a real `CoopJoinHandle<T>` whose `poll` checks the shared
//!   `JoinState<T>` and registers a waker if the task has not yet
//!   completed.
//! - [`CoopRuntime::run_until_idle`] is a real polling loop: it
//!   atomic-swaps each task's `wake_flag` to false, polls every
//!   task that was ready, and re-stores Pending futures. Tasks that
//!   self-wake (e.g. `SleepFuture::poll` returning Pending +
//!   `cx.waker().wake_by_ref()`) become ready for the *next*
//!   `run_until_idle` call; this round does not busy-spin inside
//!   one call.
//! - [`CoopTime::now_monotonic_ms`] reads the user-supplied
//!   `ClockSource::now_us(&self)` and divides by 1000 against the
//!   per-instance epoch — no fake constant, no `unimplemented!()`.
//!
//! The R53/R58/R63 retrospect (NOP `CoopRuntime::spawn` doc-around-
//! the-hack pattern) is honoured by *only* shipping real code: a
//! reader who builds with `--features alloc` and calls
//! `runtime.spawn(future).await` receives that future's output,
//! not silently-discarded work.
//!
//! ## What R311av deliberately defers
//!
//! - **`embedded-time` ecosystem adapter**: own [`ClockSource`]
//!   trait only. `embedded-time` v0.13 has been stalled since 2024;
//!   the composable-framework north star prefers a self-contained
//!   trait + optional adapter feature in a future round over a
//!   maintenance-mode external dep.
//!
//! ## What R311bc closes
//!
//! - **Real timer queue**: [`timer::TimerQueue`] lands as a
//!   deadline-keyed `BinaryHeap<Reverse<TimerEntry>>`; sleep /
//!   timeout futures register `(deadline_us, Waker)` on first
//!   Pending poll instead of self-waking. [`CoopRuntime::new`]
//!   takes a [`ClockSource`] (breaking sig from R311av's
//!   `CoopRuntime::new()`); [`CoopRuntime::run_until_idle`] calls
//!   `timers.pop_expired(clock.now_us())` before polling the task
//!   pool so wake-on-deadline becomes the natural shape. The
//!   deploy main loop can now `wfi()`-sleep between IRQs because
//!   the executor pass is genuinely idle when no task is ready and
//!   no timer has elapsed; previously the self-wake busy-poll kept
//!   the executor active every cycle.
//!
//! ## What R311bd closes
//!
//! - **`CoopJoinHandle::abort()`**: AP/MCU parity with
//!   `wz_runtime_tokio::TokioJoinHandle::abort`. Each spawned task
//!   slot carries a `cancel_flag: Arc<AtomicBool>` shared with the
//!   returned `CoopJoinHandle`. `abort()` writes the flag (the
//!   next `run_until_idle` sweeps the cancelled slots and drops
//!   their futures) AND synchronously writes
//!   `Err(RuntimeError::JoinCancelled)` into the shared
//!   `JoinState` so an awaiting handle resolves immediately
//!   without needing the executor pass to land. Race against
//!   natural completion resolves by "first result wins" via the
//!   `JoinState::result.is_none()` guard on both write paths;
//!   idempotent under repeated abort calls.
//!
//! ## Layer G.4 / G.4-alloc cross-compile gate
//!
//! `scripts/run-ci.sh` Layer G exercises both lanes:
//!
//! - **G.4** (R311au): `cargo build -p wz-runtime-coop` (no
//!   features) on every Phase W target. Sync-only path; no
//!   wz-runtime-core dep pulled in. Covers all 7 targets including
//!   `thumbv6m-none-eabi` (Cortex-M0+ / ARMv6-M).
//! - **G.4-alloc** (R311av): `cargo build -p wz-runtime-coop
//!   --features alloc` on the 6-target subset that supports atomic
//!   pointer CAS. Pulls in wz-runtime-core (its own `alloc` feature
//!   on) and exercises the executor + Runtime impl modules.
//!
//! ## Why thumbv6m-none-eabi is excluded from G.4-alloc
//!
//! Cortex-M0+ (ARMv6-M) lacks LDREX/STREX instructions, so
//! `target_has_atomic = "ptr"` is false and `alloc::sync::Arc` is
//! gated out by the standard library. The executor's `Arc<
//! ExecutorState>` + `Arc<AtomicBool>` waker storage cannot be
//! satisfied by `core::alloc::sync` alone on this target.
//!
//! Adding a polyfill (`portable-atomic` / `atomic-polyfill` with
//! the `critical-section` feature) would close the gap by emulating
//! CAS via critical sections, but pulling such a dep into the MCU
//! profile's runtime crate is an architectural decision that
//! deserves its own round — the polyfill changes the cost model of
//! every atomic operation in the executor (every wake_flag access
//! becomes a `critical_section::with` IRQ-disable on M0+), and the
//! tradeoff against just compiling without alloc on M0+ deploys is
//! a deploy-time choice. R311az+ carries the polyfill decision; for
//! R311av the M0+ deploys stay on the no-alloc sync-only build.
//!
//! Both lanes SKIP if the matching rustup target is not installed
//! (the developer machine does not need cross-compile interest to
//! build the workspace).
//!
//! [`wz-runtime-tokio`]: ../wz_runtime_tokio/index.html
//! [`Runtime`]: wz_runtime_core::Runtime
//! [`ClockSource`]: time::ClockSource
//! [`CoopRuntime`]: runtime_impl::CoopRuntime
//! [`CoopJoinHandle`]: join_handle::CoopJoinHandle
//! [`CoopTime`]: time::CoopTime

#[cfg(feature = "alloc")]
extern crate alloc;

pub mod sync;

// R311bb — Arc + AtomicBool/U64 polyfill via portable-atomic{,-util}
// for thumbv6m (Cortex-M0+). Crate-private: call sites import via
// `crate::atomic::Arc` etc. so the polyfill swap stays a single-cfg
// rewrite rather than per-file conditional imports.
#[cfg(feature = "alloc")]
pub(crate) mod atomic;

#[cfg(feature = "alloc")]
pub mod executor;
#[cfg(feature = "alloc")]
pub mod join_handle;
// The `!Send` task pool. Separate from `executor` (the `Send` pool) because
// the two differ in exactly one bound and that bound is what makes the AP
// contract and the MCU session bundle incompatible — see the module doc.
#[cfg(feature = "alloc")]
pub mod local;
#[cfg(feature = "alloc")]
pub mod runtime_impl;
#[cfg(feature = "alloc")]
pub mod time;
#[cfg(feature = "alloc")]
pub mod timer;

#[cfg(feature = "alloc")]
pub use executor::yield_now;
#[cfg(feature = "alloc")]
pub use join_handle::CoopJoinHandle;
#[cfg(feature = "alloc")]
pub use local::{CoopLocalJoinHandle, CoopLocalSet};
#[cfg(feature = "alloc")]
pub use runtime_impl::CoopRuntime;
#[cfg(feature = "alloc")]
pub use time::{ClockSource, CoopTime};

// Stage 4a — session-tier `SessionRuntime` binding (the per-profile
// `BoxedLinkDriver` link-sink storage) for the MCU profile. Gated on
// `session-unicast` (which pulls wz-session-core + implies `alloc`, so
// `CoopRuntime` / `CoopTime` are present). The MCU mirror of the AP-side
// `impl SessionRuntime for TokioRuntime` in `wz_runtime_tokio`; lands the
// type-check that `SessionLinkActions<CoopRuntime<C>, CoopTime<C>>`
// composes before the sync drive-loop consumer (`session_drive`) wires it
// to live lwIP sockets.
#[cfg(feature = "session-unicast")]
pub mod session_runtime;

// R311ih — re-export the runtime-agnostic static-scouting synth so the
// MCU profile reaches it through its runtime crate, mirroring how the AP
// profile reaches wz-session-core items through wz-runtime-tokio. The
// synth is no-alloc-capable (bounded seam), so this is NOT alloc-gated —
// a no-alloc static-only MCU deploy gets the synthesis.
#[cfg(feature = "scouting-static")]
pub use wz_session_core::scout_static;

// R2572 — re-export the switchboard ingress so the MCU profile reaches §5.20
// through its runtime crate, the same facade -> runtime -> core route
// `scout_static` above takes. Without this the feature forward alone would
// close only half the atom's residual: `wz --features runtime-coop,switchboard`
// would activate the core gate, but an MCU consumer still could not NAME the
// port without depending on wz-session-core directly.
//
// The port is NOT alloc-gated, mirroring `scout_static`: `EventInjector` is
// unconditional in wz-session-core because the MCU generated static match
// (`out/mcu-noheap-probe/dispatch_switchboard.rs`) takes `&mut dyn
// EventInjector` and that dispatch is what a no-alloc deploy calls.
#[cfg(feature = "switchboard")]
pub use wz_session_core::switchboard::EventInjector;

// ⚠ `SwitchboardRegistry` / `SwitchboardEntry` are deliberately NOT re-exported
// here, and the reason was MEASURED rather than assumed. The first attempt wrote
// `#[cfg(all(feature = "switchboard", feature = "alloc"))]` over them and failed
// to compile: that `alloc` is THIS crate's feature (`wz-runtime-core/alloc` +
// portable-atomic), while the table is gated on wz-session-core's OWN `alloc`
// (`wz-session-core/src/switchboard.rs` @ `pub use alloc_impl::{SwitchboardEntry, SwitchboardRegistry};`),
// which this crate's `alloc` does not forward — two same-named features on
// opposite sides of one crate edge. The repair is NOT to add
// `wz-session-core/alloc` to the forward: that would impose alloc on the
// no-alloc profile this whole leg exists for.
//
// It is that the table does not belong on this edge. §5.20 splits the surface
// by profile — the AP DYNAMIC registry against the MCU GENERATED static match —
// and the MCU side reaches its dispatch through the port above. Re-exporting the
// AP table through the MCU runtime would advertise a surface this profile has no
// consumer for. An alloc-bearing MCU deploy that later wants the dynamic table
// should name it as its own feature forwarding `wz-session-core/alloc`, the way
// `session-unicast` already does, rather than have it ride in on `alloc`.

/// SCE-generated MCU reassembly buffer-pool config. The emit comes from
/// `sources/network/reassembly_pool_mcu.scxml` (an `sce:kind="buffer-pool"`
/// document, the SSOT). R311y22b: COMMITTED at
/// `out/wz-runtime-coop/reassembly_pool_mcu.rs` and `include!`-ed from there
/// (regenerated by the `xtask` codegen SSOT + the Layer B2 regen-diff gate, so
/// this crate has no build script); compiled only under the `reassembly`
/// feature via the `#[cfg]` on the wrapping module below.
///
/// R311in carry[3] — the MCU sibling of `wz-runtime-tokio`'s
/// `reassembly_pool_ap`. Exposes the spec-anchored pool constants the
/// MCU [`reassembly_rx`] seam consumes: `SLOT_COUNT` / `SLOT_SIZE` (the
/// dispatcher const generics) and `PER_PEER_QUOTA` /
/// `REASSEMBLY_TIMEOUT_MS` (the `ReassemblyConfig` knobs). NOT
/// alloc-gated — the no-alloc MCU reassembly profile consumes these. The
/// xtask strips the file-head `#![...]` inner attributes and the
/// trailing SCE-pool-API `generated_tests` module; the lint allows are
/// restored here as outer attributes on the wrapping module. SCE's §5.E
/// DMA slot-pool API in the emit is unused by the dispatcher (which owns
/// its own inline staging) and is dead code.
#[cfg(feature = "reassembly")]
#[allow(non_snake_case)]
#[allow(unused_imports)]
#[allow(dead_code)]
#[allow(unused_variables)]
#[allow(unused_mut)]
#[allow(clippy::all)]
pub mod reassembly_pool_mcu {
    include!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../out/wz-runtime-coop",
        "/reassembly_pool_mcu.rs"
    ));
}

// R311in carry[3] — the live MCU reassembly seam: binds the engine-free
// ReassemblyDispatcher to the MCU machine's pool policy (from the
// buffer-pool SSOT above) and re-exports the driving types. No-alloc;
// the MCU main loop owns the dispatcher and feeds it decoded fragments.
#[cfg(feature = "reassembly")]
pub mod reassembly_rx;

// R2572 — the §5.20 MCU reach witness. This does NOT re-test the switchboard
// (wz-session-core owns that); it pins the one thing the atom's residual was
// about: that the ingress port is nameable THROUGH THIS CRATE, so an MCU
// consumer reaching `wz::runtime_coop::EventInjector` needs no direct
// wz-session-core dependency. Deleting the `pub use` above makes this module
// fail to resolve, which is the intended coupling -- the claim IS reachability,
// so a name that cannot be written is exactly the failure to catch.
//
// No `alloc`: the impl below is a bare struct with integer counters, so the
// witness holds on the same no-heap profile deploy/mcu-noheap-probe builds.
#[cfg(all(test, feature = "switchboard"))]
mod switchboard_reach_tests {
    use super::EventInjector;

    #[derive(Default)]
    struct CountingInjector {
        signals: u32,
        values: u32,
    }

    impl EventInjector for CountingInjector {
        fn inject(&mut self, _event_name: &str, _event_data: &str) {
            self.signals += 1;
        }

        fn inject_value(&mut self, _event_name: &str, _payload: &[u8]) -> bool {
            self.values += 1;
            true
        }
    }

    #[test]
    fn the_ingress_port_is_nameable_through_the_mcu_runtime_crate() {
        let mut inj = CountingInjector::default();
        // Drive both arms through the port as the generated dispatch does:
        // signal rows call `inject`, value rows call `inject_value`.
        inj.inject("reset", "");
        assert!(inj.inject_value("temp_reading", &[0x01, 0x02]));
        assert_eq!((inj.signals, inj.values), (1, 1));
    }

    #[test]
    fn the_value_arm_defaults_to_refusing_when_an_injector_does_not_override() {
        // The port's `inject_value` default returns false, which is what keeps
        // a signal-only injector from claiming a value binding it has not got.
        // Pinned here because the MCU generated dispatch relies on the
        // DISTINCTION between the two arms, not merely on the port existing.
        struct SignalOnly;
        impl EventInjector for SignalOnly {
            fn inject(&mut self, _event_name: &str, _event_data: &str) {}
        }
        assert!(!SignalOnly.inject_value("temp_reading", &[0x01]));
    }
}
