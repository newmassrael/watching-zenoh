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
//
// R311ip — on the real-build path it ALSO codegens the MCU scout/session
// rx buffer-pool SSOTs into the SLOT_COUNT / SLOT_SIZE constants the
// `rx_sockets` typed socket aliases consume (the link-tier sibling of
// `wz-runtime-lwip/build.rs`'s reassembly_pool_mcu emit). Gated on the
// same `mode == "1"` bit as the crate body: the empty-crate build
// (cross without WZ_LWIP_PORT) neither sets the cfg nor needs the emit.

use std::path::PathBuf;

fn main() {
    println!("cargo:rustc-check-cfg=cfg(lwip_real_build)");
    println!("cargo:rerun-if-env-changed=DEP_LWIP_LWIP_REAL_BUILD");
    println!("cargo:rerun-if-changed=build.rs");

    let mode = std::env::var("DEP_LWIP_LWIP_REAL_BUILD").unwrap_or_default();
    if mode != "1" {
        // Empty crate (#![cfg(lwip_real_build)] collapses the body):
        // no cfg, no buffer-pool emit, no sce-codegen dependency.
        return;
    }
    println!("cargo:rustc-cfg=lwip_real_build");

    let out_dir = PathBuf::from(std::env::var("OUT_DIR").expect("OUT_DIR not set by cargo"));
    let manifest_dir = PathBuf::from(
        std::env::var("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR not set by cargo"),
    );
    let resource_dir = manifest_dir
        .join("../../sources/network")
        .canonicalize()
        .expect("canonicalize sources/network");
    println!("cargo:rerun-if-changed={}", resource_dir.display());

    let codegen = wz_codegen_build::Codegen::from_manifest(&manifest_dir);
    codegen.emit_buffer_pool("scout_rx_pool_mcu", &resource_dir, &out_dir);

    // Session-rx pool: select the default full-rate profile (16 x 1536) or
    // the slim nrf51-class profile (4 x 256) by the
    // `buffer-pool-session-rx-slim` feature. Only the selected variant is
    // codegen'd + compiled (lib.rs `pub mod` + rx_sockets consts cfg-match
    // this choice) — the kconfig "build only the selected config" model.
    if std::env::var_os("CARGO_FEATURE_BUFFER_POOL_SESSION_RX_SLIM").is_some() {
        codegen.emit_buffer_pool("session_rx_pool_mcu_minimal", &resource_dir, &out_dir);
    } else {
        codegen.emit_buffer_pool("session_rx_pool_mcu", &resource_dir, &out_dir);
    }
}
