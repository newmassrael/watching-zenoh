// SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
//
// wz — top-level facade for the watching-zenoh composable framework.
//
// R311a4 brings the facade from "claimed but unused" to "production
// consumer of itself" by re-exporting the wz-runtime-tokio + wz-runtime-
// core + sce-rust-runtime + sce-rust-lua public surfaces under stable
// `wz::` paths. The companion wz-ap-demo refactor in the same round
// drops its 6 direct sub-crate deps in favour of `wz = { features = …
// preset-ap-client … }`, making the facade the first user-visible
// composable-framework boundary backed by a real Linux + tokio binary.
//
// The re-export shape mirrors the long-term split point between runtime
// profiles. `wz::runtime_tokio` is the AP (Linux + tokio + std) entry;
// when wz-runtime-lwip lands as the MCU sibling the facade will gain a
// parallel `wz::runtime_lwip` namespace gated on `runtime-lwip`. Keeping
// the runtime namespace explicit (not glob-merged into `wz::session`,
// `wz::query`, etc.) preserves the option to evolve the two profiles'
// public APIs independently — an MCU-side `Session` may not be identical
// to the AP-side one even though both implement the wire spec.
//
// `wz::script` is the typed re-export bundle for the SCE script-action
// engine surface. Consumers writing AP binaries instantiate `Engine` +
// `LuaEngine` here without naming the vendor/sce sub-crates directly,
// which gives the facade ownership of the future R-script-encapsulation
// refactor (hiding SCE entirely behind preset-driven defaults) without
// breaking the wz public API at that time.

#![cfg_attr(not(any(test, feature = "runtime-tokio")), no_std)]

#[cfg(feature = "runtime-tokio")]
pub use wz_runtime_tokio as runtime_tokio;

#[cfg(feature = "runtime-tokio")]
pub use wz_runtime_core as runtime_core;

#[cfg(feature = "runtime-tokio")]
pub mod script {
    pub use sce_rust_lua::LuaEngine;
    pub use sce_rust_runtime::{Engine, IScriptEngine};
}
