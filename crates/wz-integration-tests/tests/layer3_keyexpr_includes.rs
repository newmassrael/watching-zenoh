// SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! Layer 3 cross-impl differential — keyexpr INCLUSION (R311y262).
//!
//! `keyexpr-includes` is an ACTIVE atom (`#[cfg(feature = "keyexpr-includes")]` in
//! `wz-session-core/src/keyexpr_match.rs`) that had NO cross-impl witness. Its sibling
//! `keyexpr-intersect` has had one since R296/R297 (`layer3_keyexpr_intersect.rs`), and
//! the two are easy to conflate — which is precisely the risk:
//!
//! **INCLUDES is DIRECTIONAL where INTERSECTS is symmetric.** `a ∩ b` asks whether some
//! key matches both. `a ⊇ b` asks whether EVERY key `b` matches is also matched by `a`.
//! An implementation can agree with zenoh-pico on every intersects answer and still
//! disagree about which side subsumes the other — `*` intersects `**` in both
//! directions, but `**` includes `*` while `*` does NOT include `**`. Nothing in the
//! repo had ever checked that asymmetry against a foreign implementation.
//!
//! ## Why this test compiles the code the atom IS
//!
//! The y261 lesson: a differential that agrees with the foreign side on the WIRE can
//! still leave the atom's own cfg-gated code unexercised, and then the claim is worth
//! nothing. Here `wz_session_core::keyexpr_match::keyexpr_includes_patterns` is itself
//! `#[cfg(feature = "keyexpr-includes")]` (keyexpr_match.rs:567) — turn the feature off
//! and this test does not compile, let alone pass. The claim binds to the atom.
//!
//! ## The witness
//!
//! zenoh-pico's `_z_keyexpr_forward_includes` — the worker `_z_keyexpr_includes`
//! (session/keyexpr.h:65) dispatches into, emitted by the SAME
//! `keyexpr_match_template.h` macro instantiation that produces the intersects worker
//! already used by the sibling test (keyexpr.c:565-568). Real C, linked in-process, so
//! this runs in Layer C1 on every push with no external binary to provision.
//!
//! Scope note: calling the worker bypasses `_z_keyexpr_includes`'s `strncmp` identity
//! fast path (keyexpr.c:590-593), so for identical-string pairs the public predicate
//! would short-circuit `true` without entering the matcher. The worker returns `true`
//! for those too, so nothing is hidden — but the differential is against the worker, as
//! the sibling intersects test is.
//!
//! ## Scope — what is NOT claimed
//!
//! The corpus is the same bounded alphabet the intersects differential uses (`a`/`b`/`c`
//! chunks, `*` / `**` / `$*`), and it excludes `@`-verbatim chunks. So this is `partial`,
//! not exhaustive: it enumerates the wildcard-vs-wildcard subsumption cases, it does not
//! claim the relation is closed.

use std::os::raw::c_char;

/// zenoh-pico's includes-mode chunk-level matcher, called on the raw `(ptr, len)` view of
/// two keyexpr strings — the same shape the intersects differential uses.
fn zenoh_pico_includes(a: &str, b: &str) -> bool {
    // SAFETY: the pointers are derived from live `&str`s that outlive the call, and the
    // worker only READS them (it is a pure chunk scan; the `true` argument selects the
    // verbatim-aware path, matching what `_z_keyexpr_includes` itself passes).
    unsafe {
        let a_ptr = a.as_ptr() as *const c_char;
        let a_end = a_ptr.add(a.len());
        let b_ptr = b.as_ptr() as *const c_char;
        let b_end = b_ptr.add(b.len());
        zenoh_pico_sys::_z_keyexpr_forward_includes(a_ptr, a_end, b_ptr, b_end, true)
    }
}

/// wz-side inclusion, through the atom's OWN cfg-gated entry point.
fn wz_includes(a: &str, b: &str) -> bool {
    let a_chunks: Vec<&str> = a.split('/').collect();
    let b_chunks: Vec<&str> = b.split('/').collect();
    wz_session_core::keyexpr_match::keyexpr_includes_patterns(&a_chunks, &b_chunks)
}

/// Assert wz and zenoh-pico agree on `a ⊇ b` — and, because the relation is DIRECTIONAL,
/// on `b ⊇ a` as a separate question rather than a symmetry check.
#[track_caller]
fn assert_includes_agree(a: &str, b: &str) {
    let wz_ab = wz_includes(a, b);
    let pico_ab = zenoh_pico_includes(a, b);
    assert_eq!(
        wz_ab, pico_ab,
        "includes mismatch: `{a}` ⊇ `{b}` → wz={wz_ab}, pico={pico_ab}",
    );
    let wz_ba = wz_includes(b, a);
    let pico_ba = zenoh_pico_includes(b, a);
    assert_eq!(
        wz_ba, pico_ba,
        "includes mismatch (reverse direction): `{b}` ⊇ `{a}` → wz={wz_ba}, pico={pico_ba}",
    );
}

/// Literal-vs-literal: inclusion degenerates to equality, in both directions.
// wz-proves: keyexpr-includes codec-parity partial
// wz-proves: keyexpr-literal codec-parity partial
#[test]
fn keyexpr_includes_literal_pairs() {
    for (a, b) in [
        ("a", "a"),
        ("a", "b"),
        ("a/b", "a/b"),
        ("a/b", "a/c"),
        ("a/b", "a"),
        ("a/b/c", "a/b"),
    ] {
        assert_includes_agree(a, b);
    }
}

/// The single-chunk wildcard: `*` subsumes any one literal chunk but not a longer path,
/// and no literal subsumes `*`.
// wz-proves: keyexpr-includes codec-parity partial
// wz-proves: keyexpr-wildcard-single codec-parity partial
#[test]
fn keyexpr_includes_single_chunk_wildcard() {
    for (a, b) in [
        ("*", "a"),
        ("a", "*"),
        ("*", "*"),
        ("a/*", "a/b"),
        ("a/b", "a/*"),
        ("*/b", "a/b"),
        ("a/*", "a/b/c"),
        ("*", "a/b"),
    ] {
        assert_includes_agree(a, b);
    }
}

/// The double-chunk wildcard, where the ASYMMETRY actually bites: `**` includes `*`, but
/// `*` does NOT include `**`. Both keyexprs intersect each other in both directions, so
/// an intersects-only differential cannot distinguish an implementation that gets this
/// backwards.
// wz-proves: keyexpr-includes codec-parity partial
// wz-proves: keyexpr-wildcard-double codec-parity partial
#[test]
fn keyexpr_includes_double_star_asymmetry() {
    for (a, b) in [
        ("**", "*"),
        ("*", "**"),
        ("**", "a"),
        ("a", "**"),
        ("**", "a/b/c"),
        ("a/**", "a/b/c"),
        ("a/b/c", "a/**"),
        ("a/**", "a"),
        ("**", "**"),
        ("a/**/c", "a/b/c"),
        ("a/b/c", "a/**/c"),
    ] {
        assert_includes_agree(a, b);
    }
}

/// Intra-chunk `$*` DSL — including the ORDERED SUB-PART WALK, which is exactly where
/// includes and intersects diverge.
///
/// A left chunk of the bare form `a$*` (one run, empty trailing anchor) does not reach
/// it: pico short-circuits and so does wz. The divergence lives in
/// `_z_chunk_right_contains_all_stardsl_subchunks_of_left`
/// (keyexpr_match_template.h:142-158): for INTERSECTS, a right chunk that itself
/// contains `$*` short-circuits to true; for INCLUDES it must walk the left chunk's
/// sub-parts in order. `a$*c` vs `a$*b$*c` is the smallest canonical pair that lands
/// there, so it is in the corpus deliberately.
///
/// A lone `$*` chunk is NOT in the corpus: the canonizer rewrites it to `*` on both
/// sides (pico `Z_KEYEXPR_CANON_LONE_DOLLAR_STAR`, wz `ChunkShape::LoneDollarStar`), so
/// it is outside both matchers' stated "assume canonized chunks" precondition and no
/// production path can emit it.
// wz-proves: keyexpr-includes codec-parity partial
// wz-proves: keyexpr-dollar-star codec-parity partial
#[test]
fn keyexpr_includes_dollar_star() {
    for (a, b) in [
        ("a$*", "ab"),
        ("ab", "a$*"),
        ("a$*", "a"),
        ("a$*", "a$*"),
        ("*", "a$*"),
        ("a$*", "*"),
        ("a/b$*", "a/bc"),
        // the ordered sub-part walk (includes) vs the short-circuit (intersects)
        ("a$*c", "a$*b$*c"),
        ("a$*b$*c", "a$*c"),
        ("a$*b$*c", "abc"),
        ("a$*c$*b", "a$*b$*c"),
    ] {
        assert_includes_agree(a, b);
    }
}

/// The relation's own algebra: inclusion must IMPLY intersection, in BOTH implementations
/// — and the two must still agree with each other on the same pairs.
///
/// The agreement check is what makes this a differential at all. Asserting only
/// `wz_includes => wz_intersects` and `pico_includes => pico_intersects` would be two
/// independent self-consistency checks: a wz whose `includes` returned `false`
/// unconditionally satisfies its half vacuously, and the pico half tests the vendored C
/// library rather than wz. So `assert_includes_agree` runs on every pair here too, and
/// the implication is the ADDITIONAL property on top.
// wz-proves: keyexpr-includes codec-parity partial
#[test]
fn keyexpr_includes_implies_intersects_in_both_impls() {
    use wz_runtime_tokio::pubsub::keyexpr_intersect_patterns;

    for (a, b) in [
        ("**", "*"),
        ("a/*", "a/b"),
        ("a/**", "a/b/c"),
        ("*", "a"),
        ("a$*", "ab"),
        ("a", "b"),
        ("a/b", "a/c"),
        ("*", "**"),
    ] {
        // The differential first: wz and pico must give the SAME inclusion answer.
        assert_includes_agree(a, b);

        let a_chunks: Vec<&str> = a.split('/').collect();
        let b_chunks: Vec<&str> = b.split('/').collect();

        if wz_includes(a, b) {
            assert!(
                keyexpr_intersect_patterns(&a_chunks, &b_chunks),
                "wz: `{a}` ⊇ `{b}` but they do not intersect — the matchers disagree",
            );
        }
        if zenoh_pico_includes(a, b) {
            assert!(
                zenoh_pico_intersects_for_algebra(a, b),
                "pico: `{a}` ⊇ `{b}` but they do not intersect",
            );
        }
    }
}

/// The intersects worker, for the algebra cross-check above.
fn zenoh_pico_intersects_for_algebra(a: &str, b: &str) -> bool {
    // SAFETY: same read-only raw-slice contract as `zenoh_pico_includes`.
    unsafe {
        let a_ptr = a.as_ptr() as *const c_char;
        let a_end = a_ptr.add(a.len());
        let b_ptr = b.as_ptr() as *const c_char;
        let b_end = b_ptr.add(b.len());
        zenoh_pico_sys::_z_keyexpr_forward_intersects(a_ptr, a_end, b_ptr, b_end, true)
    }
}
