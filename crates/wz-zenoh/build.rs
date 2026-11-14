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
// Modified by newmassrael in 2026 for watching-zenoh. Derived from zenoh 1.10.2, file
// src/lib.rs (https://github.com/eclipse-zenoh/zenoh, tag 1.10.2). Upstream composes `GIT_VERSION`
// there with the `git_version!` macro; this build script asks `git` the same question with the same
// arguments, so that the crate takes no macro dependency (docs/zenoh-api-on-the-engine.md, slice Z6c).

//! Records the version `zenoh::GIT_VERSION` names, as upstream's crate composes it: `v`, the
//! version of the crate, `-`, and the commit it was built from.
//!
//! Upstream asks `git` for the commit at compile time (`git_version!` with the arguments
//! `--always --dirty=-modified --abbrev=40 --exclude=*`, and `release` where there is none), and
//! so does this: the commit of 40 digits, followed by `-modified` when the tree has changes, or
//! `release` for a build with no history to ask, a crate unpacked from a registry.
//!
//! A build that has the source and not its history hands the commit in instead: `WZ_SOURCE_COMMIT`,
//! when it is set, is the answer `git` would have given, and `git` is then neither asked nor watched.
//! A hermetic build runs on a copy of the tree with no `.git` (`deploy/offline-build.json`), and
//! without this it would name itself `release` where a build of the same commit in a checkout names
//! the commit; with it, the two compose the same version. The value is held to what `git` can
//! answer, the commit of 40 lowercase digits with `-modified` or without, or `release`, so a value
//! that is not one fails the build rather than becoming the version a daemon reports.

use std::{env, path::Path, process::Command};

/// The variable a build with no history hands the commit in by.
const SOURCE_COMMIT: &str = "WZ_SOURCE_COMMIT";

/// Whether `text` is an answer `describe` can give: a commit of 40 lowercase digits, with
/// `-modified` or without, or `release`.
fn is_answer(text: &str) -> bool {
    let commit = text.strip_suffix("-modified").unwrap_or(text);
    text == "release"
        || (commit.len() == 40
            && commit
                .bytes()
                .all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')))
}

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
    let version = env::var("CARGO_PKG_VERSION").expect("cargo sets CARGO_PKG_VERSION");
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-env-changed={SOURCE_COMMIT}");

    if let Some(given) = env::var_os(SOURCE_COMMIT) {
        let given = given.into_string().unwrap_or_else(|raw| {
            panic!("{SOURCE_COMMIT} is not UTF-8 ({raw:?}); unset it to ask git")
        });
        assert!(
            is_answer(&given),
            "{SOURCE_COMMIT}={given:?} is not an answer of `git describe`: a commit of 40 lowercase \
             hex digits, with `-modified` or without, or `release`; unset it to ask git"
        );
        println!("cargo:rustc-env=WZ_ZENOH_GIT_VERSION=v{version}-{given}");
        return;
    }

    let commit = describe(manifest).unwrap_or_else(|| "release".to_owned());
    println!("cargo:rustc-env=WZ_ZENOH_GIT_VERSION=v{version}-{commit}");

    // A build is of the commit that is checked out: it is made again when HEAD moves, which is
    // as precise as upstream's macro, that runs when the crate is compiled and not when a file
    // of the tree changes.
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
