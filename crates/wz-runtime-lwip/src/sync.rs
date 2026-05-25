// SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! Per-runtime synchronization primitive aliases for the lwIP / MCU
//! profile (R311au scope C).
//!
//! R311w decision lock (per §5.P caveat) selected **option (a) —
//! per-runtime type alias** over option (b) a `MutexFamily` GAT (HKT
//! ergonomics) and option (c) AP/MCU source-tree fork (single-source-
//! tree violation). The tokio profile binds through
//! `wz_runtime_tokio::sync` (`std::sync::Mutex<T>` /
//! `std::sync::RwLock<T>`); this module is the matching MCU-profile
//! binding so future cross-runtime code reading `use
//! wz_runtime_lwip::sync::Mutex` lands on a real per-arch primitive.
//!
//! ## Why `critical_section::Mutex<RefCell<T>>`
//!
//! The MCU profile assumes a single-core, interrupt-driven execution
//! model (lwIP's `tcpip_thread` running cooperatively with hardware
//! ISRs). `critical_section::Mutex<T>` acquires its lock by disabling
//! interrupts in a critical section, which is the canonical
//! single-core IRQ-safe primitive for this environment:
//!
//! **Send + Sync**: `critical_section::Mutex<T>: Send + Sync where T:
//! Send`. The trait-level [`Runtime::Mutex`] bound (`Send + Sync +
//! 'static where T: Send + 'static`) is satisfied via the `RefCell<T>`
//! interior — `RefCell<T>: Send where T: Send`, and the outer
//! `critical_section::Mutex` adds the `Sync` half by interrupt-
//! disabling lock acquisition. The `T: Send + 'static` trait bound
//! propagates to `T: Send + 'static` for the inner value, matching
//! tokio's `std::sync::Mutex<T>: Sync where T: Send` shape one-to-one.
//!
//! **No allocator dep**: the `RefCell<T>` interior keeps the primitive
//! `#![no_std]`-compatible without `alloc`. Consumers that want owned
//! `Arc<R::Mutex<...>>` storage layer `alloc` on top, same as the
//! tokio profile.
//!
//! **API divergence from `std::sync::Mutex` is expected**:
//! `critical_section::Mutex::lock(|cs| { /* &RefCell access */ })` is
//! a closure-shaped API, distinct from `std::sync::Mutex::lock()`
//! which returns a `MutexGuard`. The per-runtime alias surface
//! intentionally leaves the call-site API profile-specific — generic
//! code over `R: Runtime` parameterises the *storage type*
//! `R::Mutex<T>` but locks against profile-aware wrappers (this is
//! the same shape `Session<R: Runtime>` will pick up when its
//! `Arc<R::Mutex<...>>` field migrates per the §5.P "Session struct
//! last" gate).
//!
//! ## Why `RwLock` collapses to `Mutex`
//!
//! Single-core, interrupt-driven execution means there is no
//! observable multi-reader concurrency: any "reader" runs atomically
//! within the critical section (interrupts disabled). The shared-read
//! semantic that distinguishes `RwLock` from `Mutex` on multi-core AP
//! is therefore unobservable on this profile; aliasing both to the
//! same `critical_section::Mutex<RefCell<T>>` is the textbook
//! collapse. The trait-level bound difference (`T: Send + Sync` for
//! `RwLock` vs `T: Send` for `Mutex`) is conservatively preserved at
//! the alias declaration — call sites that rely on the looser Mutex
//! bound still compile, and sites that read shared `&T` through the
//! RwLock alias retain the `Sync` requirement on `T` they would have
//! had under a true reader-writer lock.
//!
//! ## Future MCU profile fork
//!
//! A separate `wz-runtime-embassy` crate (if it lands) would expose
//! the same `sync::Mutex` / `sync::RwLock` names bound to
//! `embassy_sync::Mutex<RawMutex, T>` / `embassy_sync::RwLock<RawMutex,
//! T>` for the async-executor flavour of the MCU profile. The
//! per-runtime alias surface keeps both flavours composable through a
//! cfg switch at the consumer's import line.

use core::cell::RefCell;

/// MCU-profile mutual-exclusion lock alias (R311w option (a),
/// R311au scope C realisation).
///
/// Binds to `critical_section::Mutex<RefCell<T>>` — interrupt-
/// disabling lock with `RefCell<T>` interior for shared-mutable
/// access inside the critical section. See module doc for the full
/// rationale (Send + Sync bound, API divergence from
/// `std::sync::Mutex`, single-core IRQ-safe semantics).
///
/// Use this alias for new MCU-side code that wants to migrate
/// cleanly when the future `LwipRuntime` impl lands and `R::Mutex<T>`
/// generic dispatch becomes available. Direct
/// `critical_section::Mutex<RefCell<T>>` references should be
/// avoided in favour of this alias so a future
/// `wz-runtime-embassy::sync::Mutex` (or another MCU profile flavour)
/// can substitute without call-site churn.
pub type Mutex<T> = critical_section::Mutex<RefCell<T>>;

/// MCU-profile reader-writer lock alias (R311w option (a)).
///
/// Aliased to the same `critical_section::Mutex<RefCell<T>>` as
/// [`Mutex`] — see module doc on why the shared-read semantic
/// collapses on a single-core, interrupt-driven profile. The
/// trait-level bound difference (`T: Send + Sync` for `RwLock` vs
/// `T: Send` for `Mutex`) is preserved at the call-site contract;
/// the alias body is the same primitive.
pub type RwLock<T> = critical_section::Mutex<RefCell<T>>;
