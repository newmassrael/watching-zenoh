// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! Whether `wz_session_core::link::SessionRuntime` declares `wrap_actions` in this build, as the
//! cfg `wz_wrap_actions` the MCU profile's binding (`src/session_runtime.rs`) reads.
//!
//! The session core takes the item away under its `session-slot`, which this crate's
//! `session-slot` turns on but another crate of the graph can turn on too: Cargo unifies the
//! session core's features across the graph, so a feature of this crate cannot say whether the
//! item is declared. The session core's build script says it (`links = "wz_session_core"`), and
//! Cargo hands what it says to this direct dependent as `DEP_WZ_SESSION_CORE_WRAP_ACTIONS`;
//! without the session core in the build the variable is absent and the cfg off.

const WRAP_ACTIONS: &str = "DEP_WZ_SESSION_CORE_WRAP_ACTIONS";

fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rustc-check-cfg=cfg(wz_wrap_actions)");
    println!("cargo:rerun-if-env-changed={WRAP_ACTIONS}");
    if std::env::var(WRAP_ACTIONS).is_ok_and(|declared| declared == "1") {
        println!("cargo:rustc-cfg=wz_wrap_actions");
    }
}
