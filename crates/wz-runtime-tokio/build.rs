// SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! wz-runtime-tokio build.rs — codegens the AP reassembly buffer-pool.
//!
//! R311in — the tokio (AP / Linux) host's reassembly slot-pool
//! dimensions + runtime knobs are sourced from
//! `sources/network/reassembly_pool_ap.scxml` (an `sce:kind="buffer-pool"`
//! document, the SSOT) rather than hand-transcribed into
//! `session_glue.rs`. SCE owns the buffer-pool schema + codegen; its
//! `sce-codegen` emits the spec-anchored `SLOT_COUNT` / `SLOT_SIZE` /
//! `MAX_FRAGMENTS_PER_MESSAGE` / `REASSEMBLY_TIMEOUT_MS` / `PER_PEER_QUOTA`
//! constants the host `ReassemblyDispatcher` consumes (see the scxml
//! header for the SSOT rationale).
//!
//! The AP profile owns its deploy policy here; the MCU profile mirrors
//! this with `wz-runtime-lwip/build.rs` codegen'ing `reassembly_pool_mcu`.
//! The sce-codegen invocation + emit post-processing live once in the
//! shared `wz-codegen-build` build-dependency.

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
    codegen.emit_buffer_pool("reassembly_pool_ap", &resource_dir, &out_dir);
}
