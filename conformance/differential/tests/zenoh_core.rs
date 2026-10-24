// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! `zenoh-core`: upstream's crate (`up_core`) and wz's (`wz_core`) given the same input, outputs
//! equal. Each case is written once, in a macro that expands it for the crate named, so both crates
//! are run by the same source. The macros of the crate expand to `zenoh_result::zerror!` in their
//! caller, so each expansion sits in a module that names that crate's own `zenoh-result` as
//! `zenoh_result`.

use std::{
    future::{Future, IntoFuture},
    sync::{Arc, Mutex, RwLock},
    task::{Context, Poll, Wake, Waker},
};

/// Poll an already-ready future once, so what `into_future` of a closure gives can be seen without
/// a runtime of either crate.
fn ready<F: Future>(f: F) -> F::Output {
    struct Noop;
    impl Wake for Noop {
        fn wake(self: Arc<Self>) {}
    }
    let waker = Waker::from(Arc::new(Noop));
    let mut cx = Context::from_waker(&waker);
    match Box::pin(f).as_mut().poll(&mut cx) {
        Poll::Ready(v) => v,
        Poll::Pending => panic!("a ready future was pending"),
    }
}

macro_rules! cases {
    ($name:ident, $core:ident, $zr:ident) => {
        mod $name {
            use super::*;
            use $core::{Resolvable, ResolveClosure, ResolveFuture, Wait};
            use $zr as zenoh_result;

            pub fn closure() -> (i32, i32) {
                (
                    ResolveClosure::new(|| 6 * 7).wait(),
                    ready(ResolveClosure::new(|| 6 * 7).into_future()),
                )
            }

            pub fn future_wait() -> i32 {
                ResolveFuture::new(async { 40 + 2 }).wait()
            }

            pub fn future_into_future() -> i32 {
                ready(ResolveFuture::new(async { 5 }).into_future())
            }

            pub fn debug_text() -> (String, String) {
                (
                    format!("{:?}", ResolveClosure::new(|| ())),
                    format!("{:?}", ResolveFuture::new(async {})),
                )
            }

            pub fn resolve_bound() -> (i32, i32) {
                fn needs_resolve<R: $core::Resolve<i32>>(r: R) -> i32 {
                    r.wait()
                }
                fn to_is_i32<R: Resolvable<To = i32>>(_r: &R) {}
                to_is_i32(&ResolveClosure::new(|| 3));
                (
                    needs_resolve(ResolveClosure::new(|| 1)),
                    needs_resolve(ResolveFuture::new(async { 2 })),
                )
            }

            pub fn none_or() -> [bool; 4] {
                use $core::polyfill::OptionExt;
                [
                    None::<u8>.is_none_or(|_| false),
                    Some(1u8).is_none_or(|v| v == 1),
                    Some(1u8).is_none_or(|v| v == 2),
                    Some(0u8).is_none_or(|v| v > 0),
                ]
            }

            pub fn locks() -> (i32, i32, i32) {
                let m = Mutex::new(1);
                let rw = RwLock::new(2);
                let a = *$core::zlock!(m);
                let b = *$core::zread!(rw);
                *$core::zwrite!(rw) += 10;
                let after = *rw.read().unwrap();
                (a, b, after)
            }

            pub fn parse() -> (Result<u8, String>, Result<u8, String>, u8, u8) {
                let ok: Result<u8, String> =
                    $core::zparse!("7").map_err(|e: zenoh_result::ZError| e.to_string());
                let bad: Result<u8, String> =
                    $core::zparse!("x").map_err(|e: zenoh_result::ZError| {
                        // the raise place is this file's line, which differs by crate: keep the text before it
                        e.to_string().split(" at ").next().unwrap().to_string()
                    });
                let d1: u8 = $core::zparse_default!("9", 1);
                let d2: u8 = $core::zparse_default!("x", 1);
                (ok, bad, d1, d2)
            }

            pub fn feature_switch() -> &'static str {
                $core::zcondfeat!("a-feature-this-crate-lacks", "on", "off")
            }

            pub fn to_u64() -> u64 {
                #[allow(unused_imports)]
                use std::convert::TryFrom;
                $core::to_u64!(5i32)
            }

            pub fn implies() {
                $core::debug_assert_implies!(false, false);
                $core::debug_assert_implies!(true, true);
                $core::debug_assert_implies!(false, true);
            }

            $core::zconfigurable! {
                pub static ref A_DEFAULTED_CONSTANT: u32 = 11;
            }

            pub fn constant() -> u32 {
                *A_DEFAULTED_CONSTANT
            }

            pub async fn async_forms() -> (i32, i32, Option<u8>) {
                let m = tokio::sync::Mutex::new(3);
                let a = *$core::zasynclock!(m);
                let rw = tokio::sync::RwLock::new(4);
                let b = *$core::zasyncread!(rw);
                *$core::zasyncwrite!(rw) += 1;
                let (tx, mut rx) = tokio::sync::mpsc::channel::<u8>(1);
                $core::zasyncsend!(tx, 9u8);
                let got = rx.recv().await;
                let after = *rw.read().await;
                (a, b + after, got)
            }
        }
    };
}

// The modules are not named `up` and `wz`: those are the extern crates of `zenoh-result`, which each
// module renames `zenoh_result` for the macros.
cases!(c_up, up_core, up);
cases!(c_wz, wz_core, wz);

#[test]
fn the_resolve_types_behave_alike() {
    assert_eq!(c_up::closure(), c_wz::closure());
    assert_eq!(c_wz::closure(), (42, 42));
    assert_eq!(c_up::future_into_future(), c_wz::future_into_future());
    assert_eq!(c_wz::future_into_future(), 5);
    assert_eq!(c_up::debug_text(), c_wz::debug_text());
    assert_eq!(c_wz::debug_text().0, "ResolveClosure(\"..\")");
    assert_eq!(c_up::resolve_bound(), c_wz::resolve_bound());
    assert_eq!(c_wz::resolve_bound(), (1, 2));
    assert_eq!(c_up::none_or(), c_wz::none_or());
    assert_eq!(c_wz::none_or(), [true, true, false, false]);
}

#[test]
fn waiting_on_a_future_blocks_on_the_application_runtime_alike() {
    // `block_in_place` needs a multi-threaded runtime around it.
    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .unwrap();
    let got = rt.block_on(async {
        let up = tokio::spawn(async { c_up::future_wait() }).await.unwrap();
        let wz = tokio::spawn(async { c_wz::future_wait() }).await.unwrap();
        (up, wz)
    });
    assert_eq!(got, (42, 42));
}

#[test]
fn waiting_on_a_future_inside_a_current_thread_runtime_panics_in_both() {
    let rt = tokio::runtime::Builder::new_current_thread()
        .build()
        .unwrap();
    let refused = |f: fn() -> i32| {
        rt.block_on(async move { std::panic::catch_unwind(f) })
            .is_err()
    };
    assert!(refused(c_up::future_wait), "upstream waited");
    assert!(refused(c_wz::future_wait), "wz waited, upstream does not");
}

#[test]
fn the_macros_expand_to_the_same_behaviour() {
    assert_eq!(c_up::locks(), c_wz::locks());
    assert_eq!(c_wz::locks(), (1, 2, 12));
    assert_eq!(c_up::parse(), c_wz::parse());
    let (ok, bad, d1, d2) = c_wz::parse();
    assert_eq!(ok, Ok(7));
    assert!(bad
        .unwrap_err()
        .starts_with("Failed to read configuration: x is not a valid value"));
    assert_eq!((d1, d2), (9, 1));
    assert_eq!(c_up::feature_switch(), c_wz::feature_switch());
    assert_eq!(c_wz::feature_switch(), "off");
    assert_eq!(c_up::to_u64(), c_wz::to_u64());
    assert_eq!(c_wz::to_u64(), 5);
    c_up::implies();
    c_wz::implies();
    assert_eq!(c_up::constant(), c_wz::constant());
    assert_eq!(c_wz::constant(), 11);
}

#[test]
fn a_debug_assertion_of_an_implication_fails_alike() {
    for f in [
        || up_core::debug_assert_implies!(true, false),
        || wz_core::debug_assert_implies!(true, false),
    ] {
        assert_eq!(
            std::panic::catch_unwind(f).is_err(),
            cfg!(debug_assertions),
            "an implication that does not hold must panic where debug assertions are on"
        );
    }
}

#[tokio::test]
async fn the_async_macros_expand_to_the_same_behaviour() {
    assert_eq!(c_up::async_forms().await, c_wz::async_forms().await);
    assert_eq!(c_wz::async_forms().await, (3, 9, Some(9)));
}
