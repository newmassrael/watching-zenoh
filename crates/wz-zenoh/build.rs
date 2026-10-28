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
// Modified by newmassrael in 2026 for watching-zenoh. Derived from zenoh 1.10.1, file
// src/lib.rs (https://github.com/eclipse-zenoh/zenoh, tag 1.10.1). Upstream composes `GIT_VERSION`
// there with the `git_version!` macro; this build script asks `git` the same question with the same
// arguments, so that the crate takes no macro dependency (docs/zenoh-api-on-the-engine.md, slice Z6c).

//! Records the version `zenoh::GIT_VERSION` names, as upstream's crate composes it: `v`, the
//! version of the crate, `-`, and the commit it was built from.
//!
//! Upstream asks `git` for the commit at compile time (`git_version!` with the arguments
//! `--always --dirty=-modified --abbrev=40 --exclude=*`, and `release` where there is none), and
//! so does this: the commit of 40 digits, followed by `-modified` when the tree has changes, or
//! `release` for a build with no history to ask, a crate unpacked from a registry.

use std::{env, path::Path, process::Command};

/// What `git describe` says of the tree around `dir`, or `None` where it cannot say.
fn describe(dir: &Path) -> Option<String> {
    let output = Command::new("git")
        .args([
            "describe",
            "--always",
            "--dirty=-modified",
            "--abbrev=40",
            "--exclude=*",
        ])
        .current_dir(dir)
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    let text = String::from_utf8(output.stdout).ok()?;
    let text = text.trim();
    (!text.is_empty()).then(|| text.to_owned())
}

fn main() {
    let manifest = env::var_os("CARGO_MANIFEST_DIR").expect("cargo sets CARGO_MANIFEST_DIR");
    let manifest = Path::new(&manifest);
    let commit = describe(manifest).unwrap_or_else(|| "release".to_owned());
    let version = env::var("CARGO_PKG_VERSION").expect("cargo sets CARGO_PKG_VERSION");
    println!("cargo:rustc-env=WZ_ZENOH_GIT_VERSION=v{version}-{commit}");

    // A build is of the commit that is checked out: it is made again when HEAD moves, which is
    // as precise as upstream's macro, that runs when the crate is compiled and not when a file
    // of the tree changes.
    println!("cargo:rerun-if-changed=build.rs");
    if let Ok(output) = Command::new("git")
        .args(["rev-parse", "--git-path", "HEAD"])
        .current_dir(manifest)
        .output()
    {
        if output.status.success() {
            if let Ok(path) = String::from_utf8(output.stdout) {
                let path = manifest.join(path.trim());
                if path.exists() {
                    println!("cargo:rerun-if-changed={}", path.display());
                }
            }
        }
    }
}
