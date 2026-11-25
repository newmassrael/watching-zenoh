// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The target this crate is built for, which the harness needs to find a C library built for the
//! host's own target (`--target`): cargo puts it under `<target dir>/<triple>/<profile>/`, and
//! only a build script is told the triple.

fn main() {
    let target = std::env::var("TARGET").expect("cargo sets TARGET for a build script");
    println!("cargo:rustc-env=WZ_INTEGRATION_TESTS_HOST_TARGET={target}");
    println!("cargo:rerun-if-changed=build.rs");
}
