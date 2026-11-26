// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! Which items of `wz_session_core::link::SessionRuntime` the session core of this build
//! declares, as the cfgs the AP profile's binding (`src/runtime_impl.rs`) and what it names read.
//!
//! The session core declares them on features of its own, and Cargo unifies those across the
//! graph: any crate in it (this crate's `transport-qos`, `adminspace-core` through the admin
//! crate, a consumer's own dependency line) can turn them on while this crate's
//! `transport-unicast` stays off. A feature of this crate therefore cannot say whether the
//! items are declared; the session core's build script says it (`links = "wz_session_core"`),
//! and Cargo hands what it says to this direct dependent as `DEP_WZ_SESSION_CORE_<KEY>`.

/// The session core's metadata variable for each fact, and the cfg this crate reads it as.
const FACTS: [(&str, &str); 2] = [
    // `SessionRuntime::EntropyDraw` and `SessionRuntime::ActionsHandle`.
    (
        "DEP_WZ_SESSION_CORE_UNICAST_RUNTIME_ITEMS",
        "wz_unicast_runtime_items",
    ),
    // `SessionRuntime::wrap_actions`.
    ("DEP_WZ_SESSION_CORE_WRAP_ACTIONS", "wz_wrap_actions"),
];

fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    for (var, cfg) in FACTS {
        println!("cargo:rustc-check-cfg=cfg({cfg})");
        println!("cargo:rerun-if-env-changed={var}");
        if std::env::var(var).is_ok_and(|declared| declared == "1") {
            println!("cargo:rustc-cfg={cfg}");
        }
    }
}
