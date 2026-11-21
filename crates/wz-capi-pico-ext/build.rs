// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The library's SONAME, and the core library it imports from where the link names it.
//!
//! On Windows the imports name the core's DLL themselves (`raw-dylib`, `src/core_view.rs`), and
//! nothing is needed here. Elsewhere the core is a cdylib of another crate, which cargo cannot name
//! as a dependency of this one, so the build that makes the two names the directory of the core it
//! built: `WZ_CAPI_PICO_CORE_DIR`, the directory holding `libwz_capi_pico.so` (`.dylib` on Apple
//! targets). This library then records the core as a library it needs, so the system loads the core
//! with it and refuses it over a core without the functions it imports.
//!
//! Without the variable the imports stay for the program's own link of both libraries to resolve,
//! which is how a workspace build compiles this crate: an ELF shared object may leave them, and an
//! Apple one is told to (`-undefined dynamic_lookup`).

fn main() {
    wz_cdylib_build::emit_soname("wz_capi_pico_ext");
    println!("cargo:rerun-if-env-changed=WZ_CAPI_PICO_CORE_DIR");
    // The target's, not this build script's host: a cross build reads the target's environment.
    if std::env::var("CARGO_CFG_WINDOWS").is_ok() {
        return;
    }
    let apple = std::env::var("CARGO_CFG_TARGET_VENDOR").as_deref() == Ok("apple");
    match std::env::var("WZ_CAPI_PICO_CORE_DIR") {
        Ok(dir) if !dir.is_empty() => {
            println!("cargo:rustc-link-search=native={dir}");
            println!("cargo:rustc-link-lib=dylib=wz_capi_pico");
        }
        _ if apple => println!("cargo:rustc-cdylib-link-arg=-Wl,-undefined,dynamic_lookup"),
        _ => {}
    }
}
