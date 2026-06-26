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
// when wz-runtime-coop lands as the MCU sibling the facade will gain a
// parallel `wz::runtime_coop` namespace gated on `runtime-coop`. Keeping
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

// R311ax — runtime-tokio and runtime-coop are mutually exclusive
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
#[cfg(all(feature = "runtime-tokio", feature = "runtime-coop"))]
compile_error!(
    "wz: `runtime-tokio` and `runtime-coop` are mutually exclusive — \
     enable exactly one per deploy. The AP profile uses runtime-tokio \
     (std + tokio); the MCU profile uses runtime-coop (no_std + alloc \
     + critical_section + cooperative task pool)."
);

#[cfg(feature = "runtime-tokio")]
pub use wz_runtime_tokio as runtime_tokio;

// R311ax — runtime-coop namespace lands. Symmetric shape with the
// AP-side `runtime_tokio` re-export so a generic consumer reading
// `wz::runtime_tokio::TokioRuntime` and `wz::runtime_coop::CoopRuntime`
// sees the same surface depth regardless of profile.
#[cfg(feature = "runtime-coop")]
pub use wz_runtime_coop as runtime_coop;

// R311y28 — platform-freertos: the FreeRTOS COOPERATIVE SINGLE-TASK profile
// re-export. This is the ONE platform-* feature that gates real code, and the
// reason is a target_os limitation: a bare-metal deploy and a FreeRTOS deploy
// are BOTH `target_os = "none"` on thumbv7m-none-eabi, so `target_os` (which
// routes platform-linux/macos/windows) CANNOT distinguish them. The RTOS is an
// opt-in chosen by the runtime+link adapter, so it is a genuine cfg(feature)
// knob — making platform-freertos an A3 ACTIVE atom (unlike platform-bare-metal,
// which the target-triple + no_std select with no toggle = FOUNDATIONAL).
//
// ON pulls wz-runtime-freertos under `wz::runtime_freertos`: FreertosClock
// (a ClockSource over xTaskGetTickCount), the heap_4 FreertosAllocator, and
// FreertosRuntime = CoopRuntime<FreertosClock> — the runtime axis stays
// orthogonal (the deploy composes this with `runtime-coop`, which supplies the
// reused wz-runtime-coop executor). The profile runs that executor inside ONE
// FreeRTOS task = zenoh-pico's Z_FEATURE_MULTI_THREAD=0 single-thread mode;
// native multi-task (xTaskCreate per read/lease thread, pico's default) is a
// deliberate re-openable FUTURE profile, not what this ships.
#[cfg(feature = "platform-freertos")]
pub use wz_runtime_freertos as runtime_freertos;

// R311az-3a / R311az-3b-ii — §5.C link tier re-export under the MCU
// profile. The `link_lwip` namespace is symmetric with `runtime_coop`:
// consumers get `wz::link_lwip::LwipLink` + `wz::link_lwip::LwipUdpSocket`
// alongside `wz::runtime_coop::CoopRuntime`. The `lwip_real_build` cfg
// (set by build.rs via the lwip-sys `DEP_LWIP_LWIP_REAL_BUILD` metadata)
// mirrors wz-link-lwip's own crate-level gate so the re-export is
// populated exactly when the underlying crate body is non-empty:
//   - host build:                     re-exported + body populated
//   - cross + WZ_LWIP_PORT set:       re-exported + body populated
//   - cross + WZ_LWIP_PORT unset:     not re-exported (body is empty)
// Replaces R311az-3a's `cfg(not(target_os = "none"))` gate so the
// preset-cortex-m4-default catalog truthfulness reaches FULL closure
// when WZ_LWIP_PORT is supplied by the deploy.
#[cfg(all(feature = "runtime-coop", lwip_real_build))]
pub use wz_link_lwip as link_lwip;

// Stage 4b — the MCU session shell re-export. `wz::session_lwip` binds the
// runtime + link tiers to the session SSOT: `run_session` (the synchronous
// MCU drive loop) + `LwipUdpDriver` (the BoxedLinkDriver adapter). Gated on
// the same `lwip_real_build` condition as `link_lwip` (the crate names
// LwipUdpSocket, present only in a real lwIP build), so the namespace is
// populated exactly when the underlying crate body is non-empty.
#[cfg(all(feature = "session-lwip", lwip_real_build))]
pub use wz_session_lwip as session_lwip;

// `runtime_core` re-export is needed by BOTH profiles (the trait
// crate authoring §5.P Runtime / TimeSource / Allocator). The
// cfg(any(..)) merges the two opt-in paths so consumers always
// reach the trait surface through `wz::runtime_core::*` no matter
// which concrete profile they picked.
#[cfg(any(feature = "runtime-tokio", feature = "runtime-coop"))]
pub use wz_runtime_core as runtime_core;

// R311il — the `wz::script` re-export (sce-rust-lua `LuaEngine` +
// `IScriptEngine`) was removed. With the session FSM engine-free, no wz
// statechart is Lua-bound, so the facade no longer forces a Lua VM into
// AP builds. The framework is now fully Lua-free (the script engine is
// neither used internally nor exposed); a consumer wanting a Lua engine
// adds `sce-rust-lua` to its own manifest directly.
