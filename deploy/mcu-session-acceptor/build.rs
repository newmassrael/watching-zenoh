// SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
//
// mcu-session-acceptor build.rs — Stage 5.
//
// Places `memory.x` into OUT_DIR so cortex-m-rt's bundled `link.x` can
// `INCLUDE memory.x` during the final link, and emits `-Tlink.x` so the
// link script is found cwd-invariantly (a `cargo build --manifest-path
// deploy/mcu-session-acceptor/Cargo.toml` from the workspace root does not
// see this crate's `.cargo/config.toml`, which walks from CWD). Same shape
// as deploy/mcu-qemu-demo's build.rs minus the microbit branch — this bin
// is native-atomic only (M3/M4/M7), all on the mps2 4 MB / 4 MB layout.

use std::env;
use std::fs;
use std::path::PathBuf;

fn main() {
    let out_dir = PathBuf::from(env::var("OUT_DIR").expect("OUT_DIR set by cargo"));

    let memory_x: &[u8] = include_bytes!("memory-mps2.x");
    fs::write(out_dir.join("memory.x"), memory_x).expect("write memory.x to OUT_DIR");
    println!("cargo:rustc-link-search={}", out_dir.display());
    println!("cargo:rustc-link-arg=-Tlink.x");
    println!("cargo:rerun-if-changed=memory-mps2.x");
    println!("cargo:rerun-if-changed=build.rs");

    // Re-run if WZ_LWIP_PORT changes (lwip-sys's own build.rs reads it; this
    // makes the cross-real dependency explicit to cargo's incremental cache).
    println!("cargo:rerun-if-env-changed=WZ_LWIP_PORT");
}
