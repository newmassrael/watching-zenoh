// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
//
// wz-mcu-session-acceptor build.rs — lwip_real_build cfg relay (Stage 5).
//
// Identical in shape to wz-link-lwip / wz-session-lwip build.rs. lwip-sys
// declares `links = "lwip"` and emits `cargo:lwip_real_build=<0|1>`; because
// lwip-sys is a DIRECT dependency of this crate, cargo re-exposes that
// metadata as `DEP_LWIP_LWIP_REAL_BUILD` here. We convert it into
// `cargo:rustc-cfg=lwip_real_build`, which the crate-level
// `#![cfg(lwip_real_build)]` gate in src/lib.rs uses to collapse the whole
// crate to an empty body when no real lwIP build is present:
//
//   - host build:                lwip_real_build set      -> real body
//   - cross + WZ_LWIP_PORT set:   lwip_real_build set      -> real body
//   - cross + WZ_LWIP_PORT unset: lwip_real_build NOT set  -> empty crate
//
// The build-mode SSOT lives in lwip-sys's build.rs; this crate only relays
// the bit (no codegen).

fn main() {
    println!("cargo:rustc-check-cfg=cfg(lwip_real_build)");
    println!("cargo:rerun-if-env-changed=DEP_LWIP_LWIP_REAL_BUILD");
    println!("cargo:rerun-if-changed=build.rs");

    let mode = std::env::var("DEP_LWIP_LWIP_REAL_BUILD").unwrap_or_default();
    if mode == "1" {
        println!("cargo:rustc-cfg=lwip_real_build");
    }
}
