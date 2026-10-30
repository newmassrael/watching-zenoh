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
// Modified by newmassrael in 2026 for watching-zenoh. Derived from zenoh-keyexpr 1.10.2, file
// src/key_expr/tests.rs (https://github.com/eclipse-zenoh/zenoh, tag 1.10.2).

//! The language's own rules, one assertion each. The comparison with upstream's crate is
//! `conformance/differential`; these hold the crate to the definition where no upstream is linked.

use alloc::string::String;

use super::{canon::Canonize, *};

fn ke(s: &str) -> &keyexpr {
    keyexpr::new(s).unwrap()
}

#[test]
fn a_key_expression_is_a_list_of_nonempty_canon_chunks() {
    for ok in [
        "a", "a/b", "*", "**", "a/*/**", "a$*b", "@a/b", "a/**/b", "$*a", "a$*",
    ] {
        assert!(keyexpr::new(ok).is_ok(), "`{ok}`");
    }
    for bad in [
        "", "/a", "a/", "a//b", "a/**/**", "**/*", "a$*$*", "$*", "a#", "a?", "a$", "a*b", "**x",
    ] {
        assert!(keyexpr::new(bad).is_err(), "`{bad}`");
    }
}

#[test]
fn each_fault_has_its_number() {
    use zenoh_result::ErrNo;
    for (s, n) in [
        ("$*", -1),
        ("**/*", -2),
        ("**/**", -3),
        ("a//b", -4),
        ("a*", -5),
        ("a$*$*", -6),
        ("a#", -7),
        ("a$", -8),
    ] {
        let e = keyexpr::new(s).unwrap_err();
        assert_eq!(e.errno().get(), n, "`{s}`");
    }
}

#[test]
fn canonization_follows_the_three_rules() {
    let canon = |s: &str| {
        OwnedKeyExpr::autocanonize(String::from(s))
            .unwrap()
            .to_string()
    };
    assert_eq!(canon("hello/foo$*$*/bar"), "hello/foo$*/bar");
    assert_eq!(canon("hello/**/**/bye"), "hello/**/bye");
    assert_eq!(canon("hello/**/**"), "hello/**");
    assert_eq!(canon("hello/$*/bye"), "hello/*/bye");
    assert_eq!(canon("$*$*$*/hello/$*$*/bye/$*$*"), "*/hello/*/bye/*");
    assert_eq!(canon("hello/**/*"), "hello/*/**");
    assert_eq!(canon("a/**/*/**/*/b"), "a/*/*/**/b");
    // A run of three is folded whole.
    assert_eq!(canon("a$*$*$*"), "a$*");
}

#[test]
fn a_mutable_str_shrinks_and_zeroes_the_rest() {
    let mut s = String::from("$*$*$*/hello/$*$*/bye/$*$*");
    let mut view = s.as_mut_str();
    view.canonize();
    assert_eq!(view, "*/hello/*/bye/*");
    assert_eq!(s, "*/hello/*/bye/*\0\0\0\0\0\0\0\0\0\0\0");
}

#[test]
fn intersection_and_inclusion_follow_the_sets() {
    assert!(ke("a/*").intersects(ke("*/a")));
    assert!(!ke("a/**").intersects(ke("b/**")));
    assert!(ke("a/*/**").includes(ke("a/b/**")));
    assert!(!ke("a/b/**").includes(ke("a/*/**")));
    assert!(ke("a/**").includes(ke("a")));
    assert!(ke("a$*").intersects(ke("$*b")));
    assert!(ke("a$*b").includes(ke("a$*cb")));
}

/// A verbatim chunk is matched by itself only: no wildcard takes it.
#[test]
fn a_verbatim_chunk_is_matched_by_itself_only() {
    assert!(!ke("*").intersects(ke("@a")));
    assert!(!ke("**").intersects(ke("@a")));
    assert!(!ke("a/**").intersects(ke("a/@b")));
    assert!(ke("a/**/@b").intersects(ke("a/@b")));
    assert!(ke("@a").includes(ke("@a")));
    assert!(!ke("**").includes(ke("@a")));
    assert!(!ke("a$*").intersects(ke("@a")));
}

#[test]
#[cfg(feature = "unstable")]
fn the_relation_is_ordered_by_how_much_is_shared() {
    use SetIntersectionLevel::*;
    assert!(Disjoint < Intersects && Intersects < Includes && Includes < Equals);
    assert_eq!(ke("a/*").relation_to(ke("*/a")), Intersects);
    assert_eq!(ke("a/**").relation_to(ke("a/b")), Includes);
    assert_eq!(ke("a").relation_to(ke("a")), Equals);
    assert_eq!(ke("a").relation_to(ke("b")), Disjoint);
}

#[test]
#[cfg(feature = "internal")]
fn chunks_come_from_both_ends() {
    let mut chunks = ke("a/b/c").chunks();
    assert_eq!(chunks.next().unwrap().as_str(), "a");
    assert_eq!(chunks.next_back().unwrap().as_str(), "c");
    assert_eq!(chunks.peek().unwrap().as_str(), "b");
    assert_eq!(chunks.as_keyexpr().unwrap().as_str(), "b");
}

#[test]
fn join_and_div() {
    let w = OwnedKeyExpr::new("some/workspace").unwrap();
    assert_eq!(
        w.join("some/topic").unwrap().as_str(),
        "some/workspace/some/topic"
    );
    assert_eq!((&w / ke("x")).as_str(), "some/workspace/x");
    assert_eq!(ke("a/**") / ke("*"), OwnedKeyExpr::new("a/*/**").unwrap());
}

#[test]
fn the_nonwild_form_refuses_a_wildcard() {
    assert!(nonwild_keyexpr::new("a/b").is_ok());
    assert!(nonwild_keyexpr::new("a/*").is_err());
    assert!(nonwild_keyexpr::new("a$*").is_err());
    assert!(OwnedNonWildKeyExpr::try_from(String::from("a/**")).is_err());
}

#[cfg(feature = "std")]
#[test]
fn the_generator_makes_canon_key_expressions() {
    let mut rng = rand::rngs::mock::StepRng::new(1, 0x9e37_79b9_7f4a_7c15);
    for k in fuzzer::KeyExprFuzzer(&mut rng).take(500) {
        assert_eq!(
            OwnedKeyExpr::autocanonize(String::from(k.as_str())).unwrap(),
            k,
            "`{k}`"
        );
    }
}
