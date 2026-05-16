// SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
//
// wz-runtime-lwip build.rs — drives the SCE B6 link-kind C11
// emitter against `sources/links/*.scxml` and compiles the C11
// driver-stub translation unit together with the emitted wrapper.
//
// The build produces:
//   1. `$OUT_DIR/include/<stem>.h` — per-link generated wrapper
//      header (one `#include "sce/forge/link.h"` consumer per
//      `<scxml sce:kind="link">` in sources/links/).
//   2. `libwz_runtime_lwip_stub.a` — static archive containing the
//      `sce_forge_link_ops_t` vtable stubs plus per-link factory
//      functions (`<snake>_link_make_driver(...)`) declared by
//      `include/wz_runtime_lwip.h`.
//
// Compile order matters because the emitted wrapper header includes
// `sce/forge/link.h` from the SCE forge runtime tree; cc's `-I`
// arguments must point at both `$OUT_DIR/include/` (for the emit)
// and `vendor/sce/sce-forge-runtime/c/include/` (for the contract).

use sce_build::{
    compile_forge_with_imports, generator::Language, DocumentLabel, ForgeCompileOptions,
};
use std::path::{Path, PathBuf};

// Link SCXMLs to compile. R53 vertical slice covers the multicast
// scouting endpoint only; the session + tcp + serial siblings land
// once deploy.yaml driver bindings are stabilized (R55+).
const LINKS: &[&str] = &["lwip_udp_scout"];

fn main() {
    let out_dir = PathBuf::from(std::env::var("OUT_DIR").expect("OUT_DIR not set by cargo"));
    let manifest_dir = PathBuf::from(
        std::env::var("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR not set by cargo"),
    );

    let resource_dir = manifest_dir
        .join("../../sources/links")
        .canonicalize()
        .expect("canonicalize sources/links");

    let sce_forge_c_include = manifest_dir
        .join("../../vendor/sce/sce-forge-runtime/c/include")
        .canonicalize()
        .expect("canonicalize vendor/sce/sce-forge-runtime/c/include");

    let emit_include = out_dir.join("include");
    std::fs::create_dir_all(&emit_include).expect("create OUT_DIR/include");

    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-changed={}", resource_dir.display());
    println!("cargo:rerun-if-changed=src/sce_link_runtime_lwip.c");
    println!("cargo:rerun-if-changed=src/wz_runtime_lwip.h");

    let options = ForgeCompileOptions::default();

    for stem in LINKS {
        emit_one(stem, &resource_dir, &emit_include, &options);
    }

    cc::Build::new()
        .file(manifest_dir.join("src/sce_link_runtime_lwip.c"))
        .include(&emit_include)
        .include(&sce_forge_c_include)
        .include(manifest_dir.join("src"))
        .flag_if_supported("-std=c11")
        .flag_if_supported("-Wall")
        .flag_if_supported("-Wextra")
        .flag_if_supported("-Wpedantic")
        .compile("wz_runtime_lwip_stub");

    // Expose the include path so downstream FFI consumers (smoke
    // tests using cc) can resolve `sce/forge/link.h` against the
    // same forge runtime tree the stub was compiled against.
    println!("cargo:include={}", emit_include.display());
    println!("cargo:include={}", sce_forge_c_include.display());
}

fn emit_one(
    stem: &str,
    resource_dir: &Path,
    emit_include: &Path,
    options: &ForgeCompileOptions,
) {
    let scxml_path = resource_dir.join(format!("{stem}.scxml"));
    let content = std::fs::read_to_string(&scxml_path)
        .unwrap_or_else(|e| panic!("read {}: {e}", scxml_path.display()));

    let output = compile_forge_with_imports(
        &content,
        DocumentLabel::symmetric(stem),
        Language::C11,
        resource_dir,
        options,
    )
    .unwrap_or_else(|e| panic!("sce-build C11 codegen failed for {stem}: {e}"));

    for (filename, code) in output.files {
        let target = emit_include.join(&filename);
        std::fs::write(&target, &code)
            .unwrap_or_else(|e| panic!("write {}: {e}", target.display()));
    }
}
