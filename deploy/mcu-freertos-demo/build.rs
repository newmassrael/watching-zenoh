// SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
//
// mcu-freertos-demo build.rs — stage memory-mps2.x into OUT_DIR for
// cortex-m-rt's link.x to INCLUDE, and apply the link-arg cwd-invariantly
// (mirrors deploy/mcu-qemu-demo). thumbv7m-none-eabi only (the FreeRTOS
// ARM_CM3 port is Cortex-M3-specific).

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
    println!("cargo:rerun-if-env-changed=WZ_FREERTOS_CONFIG");
    println!("cargo:rerun-if-env-changed=WZ_LWIP_PORT");
}
