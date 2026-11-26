// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The build's conformance digest and the cfgs of its forms. The artifact a C program links, and
//! its SONAME, are `wz-capi-pico-lib`'s.

fn main() {
    // The conformance digest of this build, read from the configuration it was built with, which
    // `zext_conformance_digest` hands out (`src/conformance.rs`).
    wz_conformance_build::emit("pico");
    // The core alone, without the doors of the additional features, which a library of their own
    // carries (`wz-capi-pico-ext`): set by the build of that form on this crate's own compile
    // (`cargo rustc -- --cfg wz_additional_apart`), never by a feature, since it takes doors out.
    println!("cargo:rustc-check-cfg=cfg(wz_additional_apart)");
    // The objects a program holds that no session holds for it lie in the process pools
    // (`src/process_pool.rs`) in every library without the tokio engine, the form with no heap
    // after its first object, and in one with it that has the doors which reserve them
    // (`object-pool`). A library of the tokio engine without the doors keeps them on the heap, as
    // the engine's own sessions allocate.
    println!("cargo:rustc-check-cfg=cfg(wz_process_pools)");
    if std::env::var_os("CARGO_FEATURE_OBJECT_POOL").is_some()
        || std::env::var_os("CARGO_FEATURE_ENGINE_TOKIO").is_none()
    {
        println!("cargo:rustc-cfg=wz_process_pools");
    }
    refuse_discarded_unwind_tables_with_std();
}

/// The linker script that discards the unwind tables (`link/discard-unwind-tables.ld`, given by
/// `.cargo/capi-discard-unwind-tables.toml`).
const DISCARD_SCRIPT: &str = "discard-unwind-tables.ld";

/// A library with `std` (the tokio engine's) unwinds a panic through the tables the script
/// discards. Only the library without `std` (`os-host`), which never unwinds, may be linked with
/// the script.
fn refuse_discarded_unwind_tables_with_std() {
    println!("cargo:rerun-if-env-changed=CARGO_ENCODED_RUSTFLAGS");
    let discards = std::env::var("CARGO_ENCODED_RUSTFLAGS")
        .unwrap_or_default()
        .split('\x1f')
        .any(|flag| flag.contains(DISCARD_SCRIPT));
    if discards && std::env::var_os("CARGO_FEATURE_OS_HOST").is_none() {
        panic!(
            "this build links with {DISCARD_SCRIPT} (.cargo/capi-discard-unwind-tables.toml), which \
             discards the unwind tables, and is not the library without std (os-host): a build \
             with std unwinds a panic, so it keeps its tables"
        );
    }
}
