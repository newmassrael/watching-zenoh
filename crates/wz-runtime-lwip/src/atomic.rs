// SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! Atomic + Arc polyfill aliases for the lwIP / MCU profile (R311bb).
//!
//! ## Why this module exists
//!
//! Cortex-M0+ (`thumbv6m-none-eabi`, ARMv6-M architecture) lacks the
//! atomic pointer CAS instruction that backs `alloc::sync::Arc`; the
//! standard library exposes `alloc::sync::Arc` only when
//! `target_has_atomic = "ptr"`. On M0+ the type is *missing from
//! alloc entirely*, not just slow — code that names `alloc::sync::Arc`
//! fails to compile. The same gap applies to several `core::sync::
//! atomic::*` types: `AtomicU64` requires `target_has_atomic = "64"`,
//! and even `AtomicBool` requires `target_has_atomic = "8"` on
//! architectures without single-byte atomics.
//!
//! `portable-atomic` + `portable-atomic-util` close this gap by
//! providing software-emulated atomic primitives backed by
//! `critical_section::with(..)` (the same primitive the rest of the
//! crate uses for `sync::Mutex`). With `features = ["critical-
//! section"]` the polyfill calls into whatever critical-section impl
//! the deploy crate supplies, keeping the polyfill consistent with the
//! rest of the runtime's lock acquisition discipline (no extra
//! disable-IRQ mechanism layered on top).
//!
//! ## Conditional substitution shape
//!
//! Each alias picks the standard-library type when the target has the
//! required atomic operation natively, falling back to the polyfill
//! only where it is missing. The cfg predicates use `target_has_atomic
//! = "<width>"` which evaluates at compile time per-target:
//!
//! | alias       | native cfg                       | polyfill                     |
//! |-------------|----------------------------------|------------------------------|
//! | `Arc<T>`    | `target_has_atomic = "ptr"`      | `portable_atomic_util::Arc`  |
//! | `AtomicBool`| `target_has_atomic = "8"`        | `portable_atomic::AtomicBool`|
//! | `AtomicU64` | `target_has_atomic = "64"`       | `portable_atomic::AtomicU64` |
//!
//! M3 / M4F / M7 / M23 / M33 / M55 + RISC-V IMAC all have the required
//! atomics natively; only M0+ engages the polyfill. AP profiles
//! (x86_64-linux, etc.) are unaffected.
//!
//! ## Cost
//!
//! Native targets pay nothing: the cfg evaluates to the standard
//! `alloc::sync::Arc` / `core::sync::atomic::*` type at compile time,
//! and the polyfill crates ride along but their types are not
//! instantiated.
//!
//! M0+ pays the critical-section overhead per atomic operation (which
//! is the only correct lowering on that architecture — there is no
//! cheaper alternative). The Arc ref-count operations become
//! critical-section-bracketed reads/writes; on a single-core
//! interrupt-driven model this is the same cost as the rest of the
//! crate's Mutex acquisition path.
//!
//! ## Why `Ordering` is re-exported
//!
//! Both `core::sync::atomic::Ordering` and `portable_atomic::Ordering`
//! exist; they are not the same enum even though their variants
//! match. The polyfill's atomic methods take
//! `portable_atomic::Ordering`, the standard atomic methods take
//! `core::sync::atomic::Ordering`. To keep call sites unaware of which
//! variant is active, this module re-exports the matching `Ordering`
//! alongside each atomic alias. Native: `core::sync::atomic::Ordering`.
//! Polyfill: `portable_atomic::Ordering`. The two share the same
//! semantic vocabulary (`SeqCst`, `Relaxed`, `Acquire`, `Release`,
//! `AcqRel`) so call sites are textually identical either way.

#[cfg(target_has_atomic = "ptr")]
pub(crate) use alloc::sync::Arc;
#[cfg(not(target_has_atomic = "ptr"))]
pub(crate) use portable_atomic_util::Arc;

#[cfg(target_has_atomic = "8")]
pub(crate) use core::sync::atomic::AtomicBool;
#[cfg(not(target_has_atomic = "8"))]
pub(crate) use portable_atomic::AtomicBool;

// AtomicU64 is currently only referenced by the test ClockSource in
// runtime_impl.rs; flagging unused imports is a workspace lint
// (`-D warnings`), so the alias carries an allow attribute. Future
// production use (e.g. monotonic timer queue per R311bc) will drop
// the allow.
#[cfg_attr(not(test), allow(unused_imports))]
#[cfg(target_has_atomic = "64")]
pub(crate) use core::sync::atomic::AtomicU64;
#[cfg_attr(not(test), allow(unused_imports))]
#[cfg(not(target_has_atomic = "64"))]
pub(crate) use portable_atomic::AtomicU64;

// `Ordering` must come from the same crate as the atomic type that
// consumes it. The two `Ordering` enums (core's and portable-atomic's)
// are isomorphic but type-distinct — using the wrong one results in
// "expected portable_atomic::Ordering, found core::sync::atomic::
// Ordering" at the method call site.
#[cfg(target_has_atomic = "8")]
pub(crate) use core::sync::atomic::Ordering;
#[cfg(not(target_has_atomic = "8"))]
pub(crate) use portable_atomic::Ordering;
