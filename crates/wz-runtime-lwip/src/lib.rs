// SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

#![no_std]

//! wz-runtime-lwip — Phase W MCU profile.
//!
//! This crate is the MCU sibling of [`wz-runtime-tokio`] for the §5.P
//! runtime-services-tier contract. The R311au scope (C) entry landed
//! the [`sync`] module (`critical_section::Mutex<RefCell<T>>` aliases)
//! under `#![no_std]` without `alloc`. R311av lands the `Runtime`
//! trait impl behind the `alloc` feature: a self-rolled cooperative
//! task pool ([`executor`]) + [`join_handle`] handle type + own
//! [`ClockSource`] / [`LwipTime`] in [`time`], satisfying the
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
//!   [`LwipRuntime`] + [`LwipJoinHandle`] + [`LwipTime`] surface
//!   becomes available. Layer G.4-alloc covers the cross-compile.
//!
//! ## Why this scope shape (R63 anti-stub honesty)
//!
//! Every item exported under the `alloc` feature is a real
//! implementation:
//!
//! - [`LwipRuntime::spawn`] heap-allocates a `Pin<Box<dyn Future +
//!   Send>>` wrapper that captures the user future + a JoinState
//!   handle, pushes it into the executor's task vector, and returns
//!   a real `LwipJoinHandle<T>` whose `poll` checks the shared
//!   `JoinState<T>` and registers a waker if the task has not yet
//!   completed.
//! - [`LwipRuntime::run_until_idle`] is a real polling loop: it
//!   atomic-swaps each task's `wake_flag` to false, polls every
//!   task that was ready, and re-stores Pending futures. Tasks that
//!   self-wake (e.g. `SleepFuture::poll` returning Pending +
//!   `cx.waker().wake_by_ref()`) become ready for the *next*
//!   `run_until_idle` call; this round does not busy-spin inside
//!   one call.
//! - [`LwipTime::now_monotonic_ms`] reads the user-supplied
//!   `ClockSource::now_us(&self)` and divides by 1000 against the
//!   per-instance epoch — no fake constant, no `unimplemented!()`.
//!
//! The R53/R58/R63 retrospect (NOP `LwipRuntime::spawn` doc-around-
//! the-hack pattern) is honoured by *only* shipping real code: a
//! reader who builds with `--features alloc` and calls
//! `runtime.spawn(future).await` receives that future's output,
//! not silently-discarded work.
//!
//! ## What R311av deliberately defers (R311az+ carries)
//!
//! - **`LwipJoinHandle::abort()`**: not implemented this round. The
//!   handle exposes only the `Future` impl; cooperative cancellation
//!   is a R311az+ design (cancel-token plumbed through TaskSlot, or
//!   a separate `Cancellable` trait). The trait surface stays
//!   unchanged — `Runtime` does not require abort.
//! - **Real timer queue**: [`SleepFuture::poll`] uses the
//!   `cx.waker().wake_by_ref()` self-wake pattern. The future becomes
//!   ready for the next `run_until_idle` iteration unconditionally,
//!   so the deploy main loop drives time forward by repeating
//!   `runtime.run_until_idle()` between `lwip_poll()` + `wfi()`.
//!   A real timer queue (deadline-keyed wake list, no busy-wake
//!   round-trips) is R311az+.
//! - **`embedded-time` ecosystem adapter**: own [`ClockSource`]
//!   trait only. `embedded-time` v0.13 has been stalled since 2024;
//!   the composable-framework north star prefers a self-contained
//!   trait + optional adapter feature in a future round over a
//!   maintenance-mode external dep.
//!
//! ## Layer G.4 / G.4-alloc cross-compile gate
//!
//! `scripts/run-ci.sh` Layer G exercises both lanes:
//!
//! - **G.4** (R311au): `cargo build -p wz-runtime-lwip` (no
//!   features) on every Phase W target. Sync-only path; no
//!   wz-runtime-core dep pulled in. Covers all 7 targets including
//!   `thumbv6m-none-eabi` (Cortex-M0+ / ARMv6-M).
//! - **G.4-alloc** (R311av): `cargo build -p wz-runtime-lwip
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
//! [`LwipRuntime`]: runtime_impl::LwipRuntime
//! [`LwipJoinHandle`]: join_handle::LwipJoinHandle
//! [`LwipTime`]: time::LwipTime

#[cfg(feature = "alloc")]
extern crate alloc;

pub mod sync;

#[cfg(feature = "alloc")]
pub mod executor;
#[cfg(feature = "alloc")]
pub mod join_handle;
#[cfg(feature = "alloc")]
pub mod runtime_impl;
#[cfg(feature = "alloc")]
pub mod time;

#[cfg(feature = "alloc")]
pub use join_handle::LwipJoinHandle;
#[cfg(feature = "alloc")]
pub use runtime_impl::LwipRuntime;
#[cfg(feature = "alloc")]
pub use time::{ClockSource, LwipTime};
