// SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
//
// wz-link-lwip build.rs — R311az-3b-ii cfg propagation.
//
// lwip-sys's build.rs emits `cargo:lwip_real_build=<0|1>` metadata.
// Because lwip-sys declares `links = "lwip"`, this metadata is
// re-exposed to direct dependents (this crate) as
// `DEP_LWIP_LWIP_REAL_BUILD`. We convert that env var into
// `cargo:rustc-cfg=lwip_real_build`, which the crate-level cfg gate
// in src/lib.rs uses to gate the entire crate body. The result:
//
//   - host build:                     lwip_real_build set      → real body
//   - cross + WZ_LWIP_PORT set:       lwip_real_build set      → real body
//   - cross + WZ_LWIP_PORT unset:     lwip_real_build NOT set  → empty crate
//
// The single source of truth for the build mode lives in lwip-sys's
// build.rs; this crate just relays the bit to the cfg surface.

fn main() {
    println!("cargo:rustc-check-cfg=cfg(lwip_real_build)");

    let mode = std::env::var("DEP_LWIP_LWIP_REAL_BUILD").unwrap_or_default();
    if mode == "1" {
        println!("cargo:rustc-cfg=lwip_real_build");
    }

    println!("cargo:rerun-if-env-changed=DEP_LWIP_LWIP_REAL_BUILD");
}
