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

// R311ax — runtime-tokio and runtime-lwip are mutually exclusive
// per-deploy. Cargo features are monotone-additive (unification
// across the dep graph cannot encode XOR), so the catalog policy
// is enforced at compile time here: a build that turns both
// features on fails with a clear directive rather than silently
// linking two incompatible runtime profiles.
//
// The check pattern is `#[cfg(all(feature = "A", feature = "B"))]`
// + `compile_error!`. Per-deploy this is the right gate: a real
// binary picks AP (tokio) or MCU (lwip), never both. A test build
// that wants to exercise both code paths must split into two
// build invocations.
#[cfg(all(feature = "runtime-tokio", feature = "runtime-lwip"))]
compile_error!(
    "wz: `runtime-tokio` and `runtime-lwip` are mutually exclusive — \
     enable exactly one per deploy. The AP profile uses runtime-tokio \
     (std + tokio); the MCU profile uses runtime-lwip (no_std + alloc \
     + critical_section + cooperative task pool)."
);

#[cfg(feature = "runtime-tokio")]
pub use wz_runtime_tokio as runtime_tokio;

// R311ax — runtime-lwip namespace lands. Symmetric shape with the
// AP-side `runtime_tokio` re-export so a generic consumer reading
// `wz::runtime_tokio::TokioRuntime` and `wz::runtime_lwip::LwipRuntime`
// sees the same surface depth regardless of profile.
#[cfg(feature = "runtime-lwip")]
pub use wz_runtime_lwip as runtime_lwip;

// R311az-3a / R311az-3b-ii — §5.C link tier re-export under the MCU
// profile. The `link_lwip` namespace is symmetric with `runtime_lwip`:
// consumers get `wz::link_lwip::LwipLink` + `wz::link_lwip::LwipUdpSocket`
// alongside `wz::runtime_lwip::LwipRuntime`. The `lwip_real_build` cfg
// (set by build.rs via the lwip-sys `DEP_LWIP_LWIP_REAL_BUILD` metadata)
// mirrors wz-link-lwip's own crate-level gate so the re-export is
// populated exactly when the underlying crate body is non-empty:
//   - host build:                     re-exported + body populated
//   - cross + WZ_LWIP_PORT set:       re-exported + body populated
//   - cross + WZ_LWIP_PORT unset:     not re-exported (body is empty)
// Replaces R311az-3a's `cfg(not(target_os = "none"))` gate so the
// preset-cortex-m4-default catalog truthfulness reaches FULL closure
// when WZ_LWIP_PORT is supplied by the deploy.
#[cfg(all(feature = "runtime-lwip", lwip_real_build))]
pub use wz_link_lwip as link_lwip;

// `runtime_core` re-export is needed by BOTH profiles (the trait
// crate authoring §5.P Runtime / TimeSource / Allocator). The
// cfg(any(..)) merges the two opt-in paths so consumers always
// reach the trait surface through `wz::runtime_core::*` no matter
// which concrete profile they picked.
#[cfg(any(feature = "runtime-tokio", feature = "runtime-lwip"))]
pub use wz_runtime_core as runtime_core;

#[cfg(feature = "runtime-tokio")]
pub mod script {
    pub use sce_rust_lua::LuaEngine;
    pub use sce_rust_runtime::{Engine, IScriptEngine};
}
