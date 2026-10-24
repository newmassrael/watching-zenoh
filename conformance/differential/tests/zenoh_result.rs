// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! `zenoh-result`: upstream's crate (`up`) and wz's (`wz`) given the same input, outputs equal.
//!
//! A macro of this family stamps the file and line it is written at into the error, so a case is
//! written ONCE, through `both!`, which expands the macro under test for each crate on one line:
//! both stamps are then the same place and the texts can be compared whole.

use std::error::Error as _;

/// The macro under test, for `up` and for `wz`, written at one place.
macro_rules! both {
    ($($t:tt)*) => {
        (up::zerror!($($t)*), wz::zerror!($($t)*))
    };
}

/// An error of upstream's and of wz's, built the same way and shown the same way.
fn same(
    case: &str,
    up_err: &(impl std::fmt::Display + std::fmt::Debug),
    wz_err: &(impl std::fmt::Display + std::fmt::Debug),
) {
    assert_eq!(up_err.to_string(), wz_err.to_string(), "{case}: Display");
    assert_eq!(
        format!("{up_err:?}"),
        format!("{wz_err:?}"),
        "{case}: Debug"
    );
}

#[test]
fn every_form_of_zerror_says_the_same_text_and_carries_the_same_number() {
    let (u, w) = both!("a literal");
    same("literal", &u, &w);
    assert_eq!(up::ErrNo::errno(&u).get(), wz::ErrNo::errno(&w).get());
    assert_eq!(
        wz::ErrNo::errno(&w),
        wz::NegativeI8::MIN,
        "no number given is the lowest"
    );

    let (u, w) = both!("format {} and {:?}", 7, "x");
    same("format", &u, &w);

    let (u, w) = both!((-3) "with a number");
    same("number and literal", &u, &w);
    assert_eq!(wz::ErrNo::errno(&w).get(), -3);
    assert_eq!(up::ErrNo::errno(&u).get(), -3);

    let (u, w) = both!((-9) "number {} and format", 1);
    same("number and format", &u, &w);
    assert_eq!(wz::ErrNo::errno(&w).get(), -9);

    let (u, w) = both!(std::io::Error::other("an io error"));
    same("an expression", &u, &w);

    let (u, w) = both!((-7) std::io::Error::other("an io error"));
    same("number and expression", &u, &w);
    assert_eq!(wz::ErrNo::errno(&w).get(), -7);
}

#[test]
fn a_cause_is_part_of_the_text_and_of_the_source_chain() {
    let (u, w) = both!(std::io::Error::other("cause") => "outer {}", 1);
    same("cause", &u, &w);
    assert!(w.to_string().contains(" - Caused by cause"), "{w}");
    assert_eq!(
        u.source().map(|s| s.to_string()),
        w.source().map(|s| s.to_string())
    );

    let (u, w) = both!((-5) std::io::Error::other("cause") => "outer");
    same("number and cause", &u, &w);
    assert_eq!(wz::ErrNo::errno(&w).get(), -5);

    // `set_source` is the method behind the arm.
    let w = wz::zerror!("outer").set_source(wz::zerror!("inner"));
    assert!(w.to_string().contains(" - Caused by inner at "), "{w}");
    assert!(w.source().is_some());
}

#[test]
fn the_error_number_of_a_foreign_error_is_the_lowest_and_of_a_boxed_zerror_its_own() {
    let foreign: Box<dyn std::error::Error + Send + Sync> = Box::new(std::io::Error::other("io"));
    let up_foreign: Box<dyn std::error::Error + Send + Sync> =
        Box::new(std::io::Error::other("io"));
    assert_eq!(
        wz::ErrNo::errno(&*foreign).get(),
        up::ErrNo::errno(&*up_foreign).get()
    );
    assert_eq!(wz::ErrNo::errno(&*foreign), wz::NegativeI8::MIN);

    let boxed: wz::Error = Box::new(wz::zerror!((-11) "boxed"));
    assert_eq!(wz::ErrNo::errno(&*boxed).get(), -11);
    let up_boxed: up::Error = Box::new(up::zerror!((-11) "boxed"));
    assert_eq!(up::ErrNo::errno(&*up_boxed).get(), -11);

    let shm = wz::ShmError(wz::zerror!((-2) "shm"));
    let up_shm = up::ShmError(up::zerror!((-2) "shm"));
    assert_eq!(
        wz::ErrNo::errno(&shm).get(),
        up::ErrNo::errno(&up_shm).get()
    );
    assert_eq!(
        shm.to_string().split(" at ").next(),
        up_shm.to_string().split(" at ").next()
    );
}

#[test]
fn bail_returns_as_upstream_does() {
    fn up_fn(fail: bool) -> up::ZResult<u8> {
        if fail {
            up::bail!((-6) "bailed {}", 2)
        }
        Ok(1)
    }
    fn wz_fn(fail: bool) -> wz::ZResult<u8> {
        if fail {
            wz::bail!((-6) "bailed {}", 2)
        }
        Ok(1)
    }
    assert_eq!(wz_fn(false).unwrap(), up_fn(false).unwrap());
    let (u, w) = (up_fn(true).unwrap_err(), wz_fn(true).unwrap_err());
    // Different lines (`bail!` is written in two functions), the same text before the place.
    assert_eq!(
        u.to_string().split(" at ").next(),
        w.to_string().split(" at ").next()
    );
    assert_eq!(wz::ErrNo::errno(&*w).get(), -6);
}

#[test]
fn the_negative_number_refuses_what_upstream_refuses() {
    assert_eq!(wz::NegativeI8::new(-1).get(), up::NegativeI8::new(-1).get());
    assert_eq!(wz::NegativeI8::MIN.get(), up::NegativeI8::MIN.get());
    let up_refused = std::panic::catch_unwind(|| up::NegativeI8::new(0)).is_err();
    let wz_refused = std::panic::catch_unwind(|| wz::NegativeI8::new(0)).is_err();
    assert!(
        up_refused && wz_refused,
        "zero is not below zero: up {up_refused}, wz {wz_refused}"
    );
    assert!(std::panic::catch_unwind(|| wz::NegativeI8::new(i8::MAX)).is_err());
}

#[test]
fn the_branch_hints_return_their_argument() {
    for b in [true, false] {
        assert_eq!(wz::likely(b), up::likely(b));
        assert_eq!(wz::unlikely(b), up::unlikely(b));
    }
    const _: bool = wz::likely(true);
    wz::cold();
}
