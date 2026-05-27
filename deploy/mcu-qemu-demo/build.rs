// SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
//
// mcu-qemu-demo build.rs — R311be.
//
// Places `memory.x` into OUT_DIR so cortex-m-rt's bundled `link.x`
// can `INCLUDE memory.x` during the final link. cortex-m-rt's
// own build.rs adds `OUT_DIR` to `rustc-link-search` if its
// `cortex-m-rt` rlib is being linked; our `cargo:rustc-link-search`
// directive here is symmetric defence-in-depth so a manual cargo
// invocation that disables build-script propagation still finds
// memory.x.

use std::env;
use std::fs;
use std::path::PathBuf;

fn main() {
    let out_dir = PathBuf::from(env::var("OUT_DIR").expect("OUT_DIR set by cargo"));

    // R311bm-m0: thumbv6m-none-eabi (Cortex-M0/M0+, e.g. QEMU
    // `microbit` / nrf51822) needs a 16 KB RAM + 256 KB FLASH
    // memory map instead of the mps2 family's 4 MB / 4 MB. Pick
    // the matching file by inspecting cargo's `TARGET` env var.
    //
    // The crate-root variant files are named `memory-mps2.x` and
    // `memory-microbit.x` — never `memory.x` at the crate root —
    // because rust-lld resolves `INCLUDE memory.x` in `link.x`
    // by checking the link script's source directory (which on
    // cortex-m-rt 0.7 paths back to this crate's manifest dir)
    // BEFORE walking `-L` search paths. A `memory.x` at the
    // crate root shadows the OUT_DIR copy and silently feeds
    // the wrong layout to the linker (verified empirically:
    // `_stack_start` stayed at the mps2 4 MB value even when
    // OUT_DIR contained the 16 KB microbit file). Renaming the
    // crate-root file forces the linker to resolve INCLUDE only
    // against the per-target OUT_DIR copy this build.rs emits.
    let target = env::var("TARGET").expect("TARGET set by cargo");
    let memory_x: &[u8] = if target == "thumbv6m-none-eabi" {
        include_bytes!("memory-microbit.x")
    } else {
        include_bytes!("memory-mps2.x")
    };
    fs::write(out_dir.join("memory.x"), memory_x).expect("write memory.x to OUT_DIR");
    println!("cargo:rustc-link-search={}", out_dir.display());
    // R311bf: pass `-Tlink.x` here in addition to the same flag
    // in `.cargo/config.toml`. Cargo's `.cargo/config.toml` lookup
    // walks from CWD, not from the manifest dir, so a `cargo build
    // --manifest-path deploy/mcu-qemu-demo/Cargo.toml` invoked
    // from the workspace root (e.g. scripts/run-ci.sh Layer Q.1)
    // does NOT see the per-crate config and silently produces an
    // empty ELF. Emitting the directive from build.rs makes the
    // link-arg cwd-invariant; the config.toml entry remains for
    // `cargo run` ergonomics inside the crate dir.
    println!("cargo:rustc-link-arg=-Tlink.x");
    println!("cargo:rerun-if-changed=memory-mps2.x");
    println!("cargo:rerun-if-changed=memory-microbit.x");
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-env-changed=TARGET");

    // Bridge to the lwip-sys + wz-link-lwip cross-real path:
    // re-run if WZ_LWIP_PORT changes so a port swap (different
    // lwipopts.h) triggers a rebuild. The actual env var is read
    // by lwip-sys's own build.rs; this directive just makes our
    // dependency on it explicit to cargo's incremental cache.
    println!("cargo:rerun-if-env-changed=WZ_LWIP_PORT");
}
