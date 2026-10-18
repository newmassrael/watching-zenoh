// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
//
// mcu-link-noalloc-probe build.rs: places `memory.x` into OUT_DIR for
// cortex-m-rt's `link.x` and emits `-Tlink.x` (cwd-invariant), as the sibling
// deploy/mcu-* crates do. The mps2 family rides the 4 MB / 4 MB layout, the
// microbit (thumbv6m) the 256 KB / 16 KB one. The crate-root files are
// `memory-{mps2,microbit}.x`, never a bare `memory.x`, so the linker resolves
// `INCLUDE memory.x` against the OUT_DIR copy only.

use std::env;
use std::fs;
use std::path::PathBuf;

fn main() {
    let out_dir = PathBuf::from(env::var("OUT_DIR").expect("OUT_DIR set by cargo"));
    let target = env::var("TARGET").expect("TARGET set by cargo");
    let memory_x: &[u8] = if target == "thumbv6m-none-eabi" {
        include_bytes!("memory-microbit.x")
    } else {
        include_bytes!("memory-mps2.x")
    };
    fs::write(out_dir.join("memory.x"), memory_x).expect("write memory.x to OUT_DIR");
    println!("cargo:rustc-link-search={}", out_dir.display());
    println!("cargo:rustc-link-arg=-Tlink.x");
    println!("cargo:rerun-if-changed=memory-mps2.x");
    println!("cargo:rerun-if-changed=memory-microbit.x");
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-env-changed=TARGET");
    // lwip-sys's own build.rs reads WZ_LWIP_PORT; naming it here makes the
    // dependency explicit to cargo's cache.
    println!("cargo:rerun-if-env-changed=WZ_LWIP_PORT");
}
