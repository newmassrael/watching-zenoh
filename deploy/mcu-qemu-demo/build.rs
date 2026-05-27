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
    let memory_x = include_bytes!("memory.x");
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
    println!("cargo:rerun-if-changed=memory.x");
    println!("cargo:rerun-if-changed=build.rs");

    // Bridge to the lwip-sys + wz-link-lwip cross-real path:
    // re-run if WZ_LWIP_PORT changes so a port swap (different
    // lwipopts.h) triggers a rebuild. The actual env var is read
    // by lwip-sys's own build.rs; this directive just makes our
    // dependency on it explicit to cargo's incremental cache.
    println!("cargo:rerun-if-env-changed=WZ_LWIP_PORT");
}
