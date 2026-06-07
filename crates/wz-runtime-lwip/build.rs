// SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! wz-runtime-lwip build.rs — codegens the MCU reassembly buffer-pool.
//!
//! R311in carry[3] — the MCU sibling of `wz-runtime-tokio/build.rs`. The
//! lwIP (MCU / bare-metal) host's reassembly slot-pool dims + runtime
//! knobs are sourced from `sources/network/reassembly_pool_mcu.scxml`
//! (an `sce:kind="buffer-pool"` document, the SSOT) and consumed by the
//! no-alloc `reassembly_rx` seam. The sce-codegen invocation + emit
//! post-processing live once in the shared `wz-codegen-build`
//! build-dependency. The build script runs on the HOST, so it invokes
//! the host sce-codegen binary regardless of the crate's MCU
//! cross-compile target.

use std::path::PathBuf;

fn main() {
    println!("cargo:rerun-if-changed=build.rs");

    // Elidable: a build without `reassembly` neither invokes sce-codegen
    // nor includes the emitted module (the wrapper in lib.rs is gated on
    // the same feature).
    if std::env::var("CARGO_FEATURE_REASSEMBLY").is_err() {
        return;
    }

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
    codegen.emit_buffer_pool("reassembly_pool_mcu", &resource_dir, &out_dir);
}
