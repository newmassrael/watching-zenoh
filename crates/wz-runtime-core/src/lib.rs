// SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! wz-runtime-core — Phase W entry, R251.
//!
//! Trait-only crate that declares the §5.P runtime-services-tier
//! contract: [`Runtime`] (async-task + JoinHandle), [`TimeSource`]
//! (monotonic clock + async sleep), [`Allocator`] (no_std-friendly heap
//! provider). The crate has zero behaviour — every item is a trait + a
//! supporting error type. Concrete impls (TokioRuntime for AP, future
//! LwipRuntime / EmbassyRuntime for MCU) live in their respective
//! runtime crates and are wired in subsequent rounds (R252+ migration
//! plan, see the R230 §5.P "Site retire migration path" entry).
//!
//! ## Why a separate crate
//!
//! - **Dual-target compile**: AP build pulls in tokio + std; MCU build
//!   stays `no_std` + uses lwIP / embassy. wz upper layers
//!   (`Session`, `SubscriberRegistry`, etc.) generic over `R: Runtime`
//!   keep one source tree.
//! - **R63 anti-stub discipline**: keeping the trait skeleton in its
//!   own crate prevents the "Phase W deferred NOP impl" doc-around-a-
//!   hack pattern that R63 retired. No impl lives here — only the
//!   contract — so there is no temptation to ship a `todo!()`-shaped
//!   placeholder that would silently pass compile.
//! - **Layer separation from §5.I intrinsics**: the §5.P spec is
//!   explicit that the OS-runtime tier and the CPU-intrinsics tier
//!   (§5.I `intrinsics-runtime--symbol-surface`) must stay distinct in
//!   code. Putting Runtime in this crate and HAL intrinsics in a
//!   different crate enforces the boundary structurally.
//!
//! ## What is NOT here (Phase W carry)
//!
//! - **Mutex / RwLock**: §5.P lists these alongside spawn but the
//!   generic-over-T shape is awkward without higher-kinded types.
//!   R252+ will pick between (a) a per-runtime `Mutex<T>` type alias
//!   re-exported from the runtime crate, (b) a `MutexFamily` GAT
//!   trait, or (c) leaving the existing `std::sync::Mutex` direct
//!   call sites on the AP-only path and providing a parallel
//!   `embassy_sync::Mutex` direct call site on the MCU path. Choice
//!   waits on actual MCU work shape.
//! - **TokioRuntime impl**: lives in `wz-runtime-tokio` from R252+.
//! - **LwipRuntime / EmbassyRuntime impl**: lives in `wz-runtime-lwip`
//!   (re-introduced when Phase W gets to lwIP integration work, see
//!   `crates/Cargo.toml` historical comment on the R63 removal).
//! - **wz upper-layer reparameterisation**: 111 std/tokio call sites
//!   (R230 §5.P inventory baseline) need to migrate to trait-mediated
//!   calls; this is the multi-round R252+ work, with `Session` last
//!   per "leaf crates first, Session struct last" §5.P guidance.

#![cfg_attr(not(feature = "std"), no_std)]
#![deny(missing_docs)]

#[cfg(feature = "alloc")]
extern crate alloc;

pub mod allocator;
pub mod error;
pub mod runtime;
pub mod time;

pub use allocator::Allocator;
pub use error::RuntimeError;
pub use runtime::Runtime;
pub use time::TimeSource;
