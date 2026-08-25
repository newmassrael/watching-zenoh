// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
//
// mcu-multicast-e2e build.rs — R311mi.
//
// Places `memory.x` into OUT_DIR so cortex-m-rt's bundled `link.x` can
// `INCLUDE memory.x` during the final link, and emits `-Tlink.x` so the link
// script is found cwd-invariantly (a `cargo build --manifest-path
// deploy/mcu-multicast-e2e/Cargo.toml` from the workspace root does not see
// this crate's `.cargo/config.toml`). Same shape as deploy/mcu-session-
// acceptor's build.rs, but with a SINGLE memory map: the multicast profile is
// mps2-class only (the 32 x 1536 multicast rx pool does not fit nrf51's 16 KB
// SRAM — see the Cargo.toml header), so every target this bin builds for rides
// the 4 MB / 4 MB ZBT-SSRAM layout and there is no microbit fork.

use std::env;
use std::fs;
use std::path::PathBuf;

fn main() {
    let out_dir = PathBuf::from(env::var("OUT_DIR").expect("OUT_DIR set by cargo"));

    // Single map: the mps2 family (M3/M4/M7) 4 MB / 4 MB ZBT-SSRAM layout. The
    // crate-root file is `memory-mps2.x` (never a bare `memory.x` at the crate
    // root) so rust-lld resolves `INCLUDE memory.x` only against the OUT_DIR
    // copy emitted below.
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
