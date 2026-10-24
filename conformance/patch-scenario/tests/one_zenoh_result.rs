// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! After the `[patch]`, upstream's `zenoh-keyexpr` and this package meet ONE `zenoh_result`.
//!
//! `zenoh-keyexpr` is upstream's. It rejects a key expression with an error of the `zenoh_result` it
//! was built against, and these tests ask for that error as the type this package names. See
//! `Cargo.toml` for why that is the probe, and `../patch-control` for the same graph without the
//! patch, where the answer is the opposite.

use zenoh_keyexpr::OwnedKeyExpr;
use zenoh_result::{ErrNo, NegativeI8, ZError};

/// `a//b` is not a key expression: the empty chunk is refused, with a `ZError` that carries a number.
fn refused() -> zenoh_result::Error {
    OwnedKeyExpr::try_from("a//b").expect_err("an empty chunk is not a key expression")
}

#[test]
fn an_upstream_crates_error_is_the_zerror_of_the_patched_crate() {
    let error = refused();
    assert!(
        error.downcast_ref::<ZError>().is_some(),
        "`{error}` is not this package's `ZError`: the graph holds two `zenoh_result`s"
    );
}

#[test]
fn the_patched_trait_reads_the_number_of_an_error_upstream_raised() {
    let error = refused();
    // Upstream raises it as `zerror!((kind) ..)` with the number of the kind of fault, `-4` for an
    // empty chunk. A graph of two `zenoh_result`s cannot downcast and answers the lowest number,
    // `NegativeI8::MIN`, so `-4` is a number that went through the patched `ZError` and `ErrNo`.
    assert_eq!(error.errno(), NegativeI8::new(-4));
    assert_eq!(
        error.downcast_ref::<ZError>().map(ErrNo::errno),
        Some(NegativeI8::new(-4))
    );
}

#[test]
fn the_display_of_an_error_upstream_raised_is_the_patched_crates() {
    let text = refused().to_string();
    // The patched `Display` names the place the error was raised: the file of upstream's crate.
    assert!(
        text.contains(" at ") && text.contains("borrowed.rs"),
        "no raise place in `{text}`"
    );
}
