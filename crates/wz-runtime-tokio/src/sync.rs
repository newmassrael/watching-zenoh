// SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! Per-runtime synchronization primitive aliases.
//!
//! R311w decision lock: `Mutex<T>` and `RwLock<T>` are surfaced as
//! per-runtime **type aliases**, not as a `MutexFamily` GAT trait
//! (option (b), rejected on HKT ergonomics) and not as parallel
//! AP/MCU direct call sites (option (c), rejected on single-source-
//! tree violation). The tokio profile aliases land here; the eventual
//! `wz-runtime-embassy` crate will define the matching
//! `pub type Mutex<T> = embassy_sync::Mutex<RawMutex, T>` shape from
//! its own `sync` module.
//!
//! This round (R311y) introduces the aliases without changing any
//! call site. R311z+ rounds will migrate
//! `Session::observer: Arc<std::sync::Mutex<...>>` and the ap-demo
//! 16 sites to `wz_runtime_tokio::sync::Mutex` so the eventual
//! Session-last reparam (`Session<R: Runtime, T: TimeSource>`) sees
//! a uniform import surface.
//!
//! ## Why a separate module (not an inline re-export at crate root)
//!
//! Two reasons:
//!
//! 1. **Cross-runtime symmetry**: future `wz-runtime-embassy::sync`
//!    will expose the same `Mutex<T>` / `RwLock<T>` names. Keeping
//!    the alias in a dedicated `sync` submodule means migration code
//!    can switch `use wz_runtime_tokio::sync::Mutex` ↔ `use
//!    wz_runtime_embassy::sync::Mutex` cleanly via a cfg gate without
//!    fighting crate-root namespace collisions.
//! 2. **Discoverability**: a consumer reading the wz-runtime-tokio
//!    surface sees the §5.P-driven sync primitives grouped together
//!    rather than scattered as crate-root re-exports.

/// Per-runtime mutual-exclusion lock alias (R311w option (a)).
///
/// Tokio profile binds to `std::sync::Mutex<T>` — synchronous, poison-
/// on-panic, fair queueing not guaranteed. The MCU profile will
/// re-bind this name to `embassy_sync::Mutex<RawMutex, T>` in the
/// future `wz-runtime-embassy::sync` module.
///
/// Use this alias for new code in wz-runtime-tokio + downstream
/// crates that want their `Mutex<T>` use to migrate cleanly across
/// runtime profiles. Direct `std::sync::Mutex<T>` references inside
/// wz-runtime-tokio are progressively replaced by this alias in
/// R311z+ rounds; the §5.P "Session struct last" gate covers the
/// `Session::observer` field migration as the terminal step.
pub type Mutex<T> = std::sync::Mutex<T>;

/// Per-runtime reader-writer lock alias (R311w option (a)).
///
/// Tokio profile binds to `std::sync::RwLock<T>` — synchronous,
/// poison-on-panic. The MCU profile will re-bind this to
/// `embassy_sync::RwLock<RawMutex, T>` (or an equivalent if Embassy
/// surfaces a different RwLock shape) when `wz-runtime-embassy`
/// lands.
///
/// Same migration discipline as [`Mutex`]: introduced this round for
/// future call sites; existing `std::sync::RwLock<T>` references are
/// progressively replaced in R311z+ rounds.
pub type RwLock<T> = std::sync::RwLock<T>;
