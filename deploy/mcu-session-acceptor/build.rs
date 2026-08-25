// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
//
// mcu-session-acceptor build.rs — Stage 5.
//
// Places `memory.x` into OUT_DIR so cortex-m-rt's bundled `link.x` can
// `INCLUDE memory.x` during the final link, and emits `-Tlink.x` so the
// link script is found cwd-invariantly (a `cargo build --manifest-path
// deploy/mcu-session-acceptor/Cargo.toml` from the workspace root does not
// see this crate's `.cargo/config.toml`, which walks from CWD). Same shape
// as deploy/mcu-qemu-demo's build.rs: the mps2 family (M3/M4/M7) rides the
// 4 MB / 4 MB layout; the microbit (Cortex-M0, thumbv6m) rides the 256 KB /
// 16 KB nrf51 layout. R311ja lifted the session handle off alloc::sync::Arc
// so the stack cross-compiles on ARMv6-M; R311jb added the thumbv6m build-
// only Q.4 lane; R311jc makes the microbit lane a real BOOT by selecting the
// slim buffer-pool profile (buffer-pool-session-rx-slim, measured ~3.15 KB
// peak heap), which fits the nrf51 16 KB SRAM where the default ~32 KB pool
// could not.

use std::env;
use std::fs;
use std::path::PathBuf;

fn main() {
    let out_dir = PathBuf::from(env::var("OUT_DIR").expect("OUT_DIR set by cargo"));

    // Select the memory map by target triple: the mps2 family (M3/M4/M7;
    // thumbv7m / thumbv7em-none-eabihf) uses the 4 MB / 4 MB ZBT-SSRAM
    // layout; the microbit (Cortex-M0, thumbv6m, nrf51822) uses the
    // 256 KB / 16 KB layout. The thumbv6m build is the slim buffer-pool
    // profile, whose MEASURED ~3.15 KB peak heap + lwIP MEM_SIZE + stack fit
    // the 16 KB SRAM. Same per-target selection shape as deploy/mcu-qemu-
    // demo's build.rs. The crate-root files are `memory-{mps2,microbit}.x`
    // (never a bare `memory.x` at the crate root) so rust-lld resolves
    // `INCLUDE memory.x` only against the per-target OUT_DIR copy emitted
    // below, not a crate-root file that would shadow it.
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

    // Re-run if WZ_LWIP_PORT changes (lwip-sys's own build.rs reads it; this
    // makes the cross-real dependency explicit to cargo's incremental cache).
    println!("cargo:rerun-if-env-changed=WZ_LWIP_PORT");
}
