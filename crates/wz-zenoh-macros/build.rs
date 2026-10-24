// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! Records the compiler's verbose version, which `rustc_version_release!` reads back: the release
//! and commit of the rustc that built the crate that uses the macro's host, which is this one.

use std::{env, ffi::OsString, fs, path::PathBuf, process::Command};

fn main() {
    let rustc = env::var_os("RUSTC").unwrap_or_else(|| OsString::from("rustc"));
    let output = Command::new(rustc)
        .arg("-v")
        .arg("-V")
        .output()
        .expect("Couldn't get rustc version");
    let out = PathBuf::from(env::var_os("OUT_DIR").expect("cargo sets OUT_DIR")).join("version.rs");
    fs::write(out, output.stdout).expect("Couldn't record the rustc version");
}
