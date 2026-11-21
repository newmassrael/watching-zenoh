// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! R2103 (open-debt item 521) — this crate's `cdylib` gets a SONAME.
//!
//! The zenoh-pico drop-in half of the same claim `wz-capi-c` makes: a program
//! written for zenoh-pico links this artifact, and could not redistribute what
//! it linked. The reason and the platform rule live in `wz_cdylib_build`.

fn main() {
    wz_cdylib_build::emit_soname("wz_capi_pico");
    // The conformance digest of this build, read from the configuration it was built with, which
    // `wz_ext_conformance_digest` hands out (`src/conformance.rs`).
    wz_conformance_build::emit("pico");
    // The core alone, without the doors of the additional features, which a library of their own
    // carries (`wz-capi-pico-ext`): set by the build of that form on this crate's own compile
    // (`cargo rustc -- --cfg wz_additional_apart`), never by a feature, since it takes doors out.
    println!("cargo:rustc-check-cfg=cfg(wz_additional_apart)");
}
