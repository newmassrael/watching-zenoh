// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! Places the mps2 memory map where cortex-m-rt's `link.x` looks for it.
//! One map: this firmware is only built for the mps2 machines, which carry
//! the LAN9118 it drives.

use std::env;
use std::fs;
use std::path::PathBuf;

fn main() {
    let out_dir = PathBuf::from(env::var("OUT_DIR").expect("OUT_DIR set by cargo"));
    fs::write(out_dir.join("memory.x"), include_bytes!("memory-mps2.x"))
        .expect("write memory.x to OUT_DIR");
    println!("cargo:rustc-link-search={}", out_dir.display());
    println!("cargo:rustc-link-arg=-Tlink.x");
    println!("cargo:rerun-if-changed=memory-mps2.x");
    println!("cargo:rerun-if-changed=build.rs");
    // lwip-sys reads the port from here; a new port must rebuild the stack.
    println!("cargo:rerun-if-env-changed=WZ_LWIP_PORT");
}
