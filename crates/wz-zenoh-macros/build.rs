//
// Copyright (c) 2023 ZettaScale Technology
//
// This program and the accompanying materials are made available under the
// terms of the Eclipse Public License 2.0 which is available at
// http://www.eclipse.org/legal/epl-2.0, or the Apache License, Version 2.0
// which is available at https://www.apache.org/licenses/LICENSE-2.0.
//
// SPDX-License-Identifier: EPL-2.0 OR Apache-2.0
//
// Contributors:
//   ZettaScale Zenoh Team, <zenoh@zettascale.tech>
//
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
// Modified by newmassrael in 2026 for watching-zenoh. Derived from zenoh-macros 1.10.2, file
// build.rs (https://github.com/eclipse-zenoh/zenoh, tag 1.10.2).

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
