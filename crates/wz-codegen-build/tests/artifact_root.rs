// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The Rust reading of the artifact-root rule answers what the shell
//! (`scripts/lib/artifact-root.sh`) and Python (`scripts/lib/artifact_root.py`)
//! readings answer: unset leaves every product in the checkout, set mirrors the
//! tree path under the root, and a path outside the checkout is not moved.
//! `artifact_dir_in` takes the variable as an argument, so no test here
//! touches the process environment other tests share.

use std::ffi::OsStr;
use std::path::{Path, PathBuf};

use wz_codegen_build::{artifact_dir_in, checkout_root};

const CHECKOUT: &str = "/no/such/checkout";

#[test]
fn unset_or_empty_root_leaves_a_product_in_the_checkout() {
    let p = Path::new("/no/such/checkout/target/zenohd/zenohd");
    assert_eq!(artifact_dir_in(None, Path::new(CHECKOUT), p), p);
    assert_eq!(
        artifact_dir_in(Some(OsStr::new("")), Path::new(CHECKOUT), p),
        p
    );
}

#[test]
fn a_set_root_mirrors_the_tree_path() {
    let got = artifact_dir_in(
        Some(OsStr::new("/out")),
        Path::new(CHECKOUT),
        Path::new("/no/such/checkout/crates/../vendor/sce"),
    );
    assert_eq!(got, PathBuf::from("/out/vendor/sce"));
    let root_itself = artifact_dir_in(
        Some(OsStr::new("/out")),
        Path::new(CHECKOUT),
        Path::new(CHECKOUT),
    );
    assert_eq!(root_itself, PathBuf::from("/out"));
}

#[test]
fn a_path_outside_the_checkout_is_not_moved() {
    let p = Path::new("/elsewhere/sce");
    assert_eq!(
        artifact_dir_in(Some(OsStr::new("/out")), Path::new(CHECKOUT), p),
        p
    );
    // A sibling whose name only STARTS with the checkout's is outside it.
    let sibling = Path::new("/no/such/checkout-two/target");
    assert_eq!(
        artifact_dir_in(Some(OsStr::new("/out")), Path::new(CHECKOUT), sibling),
        sibling
    );
}

#[test]
fn the_checkout_is_the_one_this_crate_was_built_in() {
    let root = checkout_root();
    assert!(
        root.join("crates/wz-codegen-build/Cargo.toml").is_file(),
        "{} is not the checkout",
        root.display()
    );
    assert!(
        root.join("scripts/lib/artifact-root.sh").is_file(),
        "the shell reading of the rule is not beside {}",
        root.display()
    );
}
