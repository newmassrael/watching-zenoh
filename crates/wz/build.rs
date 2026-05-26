// SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
//
// wz facade build.rs — R311az-3b-ii cfg propagation.
//
// The `runtime-lwip` feature pulls lwip-sys as a direct optional dep
// so `DEP_LWIP_LWIP_REAL_BUILD` (re-exposed by lwip-sys's `links =
// "lwip"` metadata) lands here. Mirror the same conversion logic that
// wz-link-lwip uses: when lwip-sys emits `=1`, the facade flips
// `lwip_real_build` on so `pub use wz_link_lwip as link_lwip;` is
// gated on the exact same condition as the wz-link-lwip body — no
// drift between "namespace re-exported" and "namespace populated".
//
// Without the `runtime-lwip` feature the env var is empty (no lwip-
// sys edge) and `lwip_real_build` stays off, which the link_lwip
// re-export's `cfg(feature = "runtime-lwip", lwip_real_build)` short-
// circuits via the feature half. So the cfg is harmless on AP-only
// builds; it costs a single `#[cfg]` check at type-resolution time.

fn main() {
    println!("cargo:rustc-check-cfg=cfg(lwip_real_build)");

    let mode = std::env::var("DEP_LWIP_LWIP_REAL_BUILD").unwrap_or_default();
    if mode == "1" {
        println!("cargo:rustc-cfg=lwip_real_build");
    }

    println!("cargo:rerun-if-env-changed=DEP_LWIP_LWIP_REAL_BUILD");
}
