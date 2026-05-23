// SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! Layer 3 wire-interop fixture — keyexpr intersection matcher.
//!
//! This is the cross-validation gate for the R293 / R296 closure
//! claim that `wz_runtime_tokio::pubsub::keyexpr_intersect_patterns`
//! is functionally equivalent to zenoh-pico's intersects-mode
//! chunk-level matcher (`_z_keyexpr_forward_intersects` →
//! `_z_chunk_forward_intersects` → `chunk_special_intersects` →
//! `_z_chunk_right_contains_all_stardsl_subchunks_of_left`). R296
//! pinned the equivalence via algorithm analysis + 8 wz-side
//! verification tests; R297 closes the loop by calling **both**
//! implementations on the same input and asserting byte-equal
//! boolean output.
//!
//! Test shape per case:
//!
//!   1. Take a `(a, b)` keyexpr string pair from the corpus.
//!   2. wz path: split each on `/` into chunks, feed to
//!      `keyexpr_intersect_patterns`.
//!   3. pico path: pass the raw `(ptr, len)` slices directly to
//!      `_z_keyexpr_forward_intersects` (zenoh-pico's worker that
//!      `_z_keyexpr_intersects` dispatches into after extracting
//!      string data from the `_z_keyexpr_t` composite —
//!      side-stepping the composite construction since chunk-level
//!      semantics are what we care about).
//!   4. Assert the two boolean answers agree.
//!
//! Corpus shape: canonical zenoh keyexprs only (no leading or
//! trailing `/`, no `@` verbatim chunks since wz does not implement
//! that feature, no `$*$*` non-canonical runs). The fixture exercises
//! literal-vs-literal, single-side `*` / `**`, two-side `*` / `**`,
//! intra-chunk `$*` on one side, and intra-chunk `$*` on both sides
//! across multiple anchor-compatibility shapes.

use std::os::raw::c_char;

/// Invoke zenoh-pico's intersects-mode chunk-level matcher with the
/// raw `(ptr, len)` view of two keyexpr strings. Bypasses the
/// `_z_keyexpr_t` / `_z_string_t` composite construction by calling
/// the worker `_z_keyexpr_forward_intersects` directly (the same
/// function `_z_keyexpr_intersects` in `session/keyexpr.c:570`
/// dispatches into).
fn zenoh_pico_intersects(a: &str, b: &str) -> bool {
    unsafe {
        let a_ptr = a.as_ptr() as *const c_char;
        let a_end = a_ptr.add(a.len());
        let b_ptr = b.as_ptr() as *const c_char;
        let b_end = b_ptr.add(b.len());
        zenoh_pico_sys::_z_keyexpr_forward_intersects(a_ptr, a_end, b_ptr, b_end, true)
    }
}

/// wz-side intersection. Splits the keyexpr string on `/` and feeds
/// the resulting chunk slices into the R293 + R296 matcher.
fn wz_intersects(a: &str, b: &str) -> bool {
    let a_chunks: Vec<&str> = a.split('/').collect();
    let b_chunks: Vec<&str> = b.split('/').collect();
    wz_runtime_tokio::pubsub::keyexpr_intersect_patterns(&a_chunks, &b_chunks)
}

/// Assert that wz and zenoh-pico return the same intersect answer
/// for `(a, b)`. Symmetrically also checks `(b, a)` since the
/// intersects relation is symmetric.
#[track_caller]
fn assert_agree(a: &str, b: &str) {
    let wz_ab = wz_intersects(a, b);
    let pico_ab = zenoh_pico_intersects(a, b);
    assert_eq!(
        wz_ab, pico_ab,
        "intersect mismatch (forward): `{}` ∩ `{}` → wz={}, pico={}",
        a, b, wz_ab, pico_ab,
    );
    let wz_ba = wz_intersects(b, a);
    let pico_ba = zenoh_pico_intersects(b, a);
    assert_eq!(
        wz_ba, pico_ba,
        "intersect mismatch (reverse): `{}` ∩ `{}` → wz={}, pico={}",
        b, a, wz_ba, pico_ba,
    );
    assert_eq!(
        wz_ab, wz_ba,
        "wz asymmetry: `{}` ∩ `{}` = {} but `{}` ∩ `{}` = {}",
        a, b, wz_ab, b, a, wz_ba,
    );
    assert_eq!(
        pico_ab, pico_ba,
        "pico asymmetry: `{}` ∩ `{}` = {} but `{}` ∩ `{}` = {}",
        a, b, pico_ab, b, a, pico_ba,
    );
}

#[test]
fn keyexpr_intersect_literal_pairs() {
    // Identical keyexprs trivially intersect; distinct literals do
    // not. Exercises the canonical-chunk byte-equal path before any
    // wildcard machinery runs.
    assert_agree("home/temp", "home/temp");
    assert_agree("home/temp", "home/humidity");
    assert_agree("a/b/c", "a/b/c");
    assert_agree("a/b/c", "x/y/z");
    assert_agree("a/b/c", "a/b/c/d"); // different depth — no intersect
    assert_agree("a", "a");
    assert_agree("a", "b");
}

#[test]
fn keyexpr_intersect_single_chunk_wildcard() {
    // `*` matches any single chunk. Exercises the chunk-level
    // wildcard fast path on each side.
    assert_agree("home/*", "home/temp");
    assert_agree("home/*", "home/sensor");
    assert_agree("home/*", "office/temp"); // mismatch on chunk 0
    assert_agree("*/temp", "home/temp");
    assert_agree("*/temp", "home/humidity"); // mismatch on chunk 1
    assert_agree("*/*", "home/temp");
    assert_agree("*/*", "a/b/c"); // different depth
    assert_agree("home/*/temp", "home/sensor/temp");
    assert_agree("home/*/temp", "*/sensor/temp"); // both-sides single-chunk wild
}

#[test]
fn keyexpr_intersect_double_star() {
    // `**` matches zero-or-more chunks. Exercises the `**` backtrack
    // path on each side.
    assert_agree("home/**", "home/temp");
    assert_agree("home/**", "home/sensor/temp");
    assert_agree("home/**", "home");
    assert_agree("home/**", "office/temp"); // chunk 0 mismatch
    assert_agree("**/temp", "home/temp");
    assert_agree("**/temp", "home/sensor/temp");
    assert_agree("**/temp", "home/humidity"); // last chunk mismatch
    assert_agree("**", "any/depth/at/all");
    assert_agree("home/**/temp", "home/sensor/temp");
    assert_agree("home/**/temp", "home/temp"); // zero middle chunks
    assert_agree("home/**/temp", "home/a/b/temp");
    assert_agree("home/**", "office/**"); // both-sides ** with distinct lead literals
}

#[test]
fn keyexpr_intersect_single_side_dsl() {
    // Intra-chunk `$*` on one side only. Exercises the
    // `chunk_matches_with_dsl` path against a literal chunk on the
    // other side.
    assert_agree("home/pre$*post", "home/prefix_post");
    assert_agree("home/pre$*post", "home/wrongprefix_post"); // bad lead
    assert_agree("home/pre$*post", "home/prefix_wrongpost"); // bad trail
    assert_agree("a/$*X", "a/Y");
    assert_agree("a/$*X", "a/YX");
    assert_agree("a/X$*", "a/Y");
    assert_agree("a/X$*", "a/XY");
    assert_agree("a/$*A$*B$*", "a/XAB"); // middles in order
    assert_agree("a/$*A$*B$*", "a/BA"); // middles in reverse order — no fit
}

#[test]
fn keyexpr_intersect_two_side_dsl_anchor_pairs() {
    // R296 core claim — two-side `$*` reduces to lead/trail anchor
    // pair compatibility. zenoh-pico reaches the same answer via the
    // `right contains $*` over-approximation branch on line 156 of
    // `keyexpr_match_template.h`.
    assert_agree("pre$*", "$*post"); // shared literal "prepost"
    assert_agree("a$*b", "a$*b"); // identical DSL chunks
    assert_agree("A$*Z", "B$*Z"); // lead mismatch
    assert_agree("X$*A", "X$*B"); // trail mismatch
    assert_agree("A$*Z", "AB$*Z"); // lead prefix-compatible
    assert_agree("$*C", "$*BC"); // trail suffix-compatible
    assert_agree("$*A$*B$*", "$*B$*A$*"); // distinct middle orderings
    assert_agree("$*ABC$*", "$*XYZ$*"); // distinct middle alphabets
    assert_agree("AB$*A", "A$*BA"); // lead+trail combined extend
    assert_agree("AB$*Z", "AX$*Z"); // byte-overlap lead but diverge
}

#[test]
fn keyexpr_intersect_mixed_wildcards() {
    // Cross-products of `*`, `**`, and `$*` on different chunks of
    // the same keyexpr.
    assert_agree("home/*/temp", "home/sensor/temp");
    assert_agree("home/*/temp", "home/sensor/humidity");
    assert_agree("home/**/temp", "home/*/temp");
    assert_agree("home/**/temp$*", "home/sensor/tempA");
    assert_agree("**/pre$*post/**", "a/prefix_post/b/c");
    assert_agree("**/pre$*post/**", "a/wrong_post/b/c"); // bad anchor in middle chunk
    assert_agree("home/*/*", "home/a/b");
    assert_agree("home/*/*", "home/a/b/c"); // depth mismatch
    assert_agree("*/**", "a/b/c/d");
    assert_agree("**/*", "a/b/c/d");
}

#[test]
fn keyexpr_intersect_depth_edge_cases() {
    // Depth-mismatch + wildcard-absorb edge cases.
    assert_agree("a", "a/b"); // single-chunk vs two-chunk
    assert_agree("**", "single"); // ** absorbs single chunk
    assert_agree("a/**", "a"); // ** absorbs zero chunks
    assert_agree("a/**/b", "a/b"); // ** absorbs zero in middle
    assert_agree("**/a", "a"); // leading ** absorbs zero
    assert_agree("a/**", "a/b/c/d/e");
}

// ── R297b property fuzz layer ───────────────────────────────────
//
// Random canonical-keyexpr generator + property assertion that
// wz/zenoh-pico agree on every shrunken case. Extends R297's
// handcrafted ~63-case corpus with bounded random coverage; the
// generator is constructive (only produces canonical forms) so
// proptest does not need to filter, and shrinking lands on a
// minimal counter-example string pair if a divergence ever
// surfaces.
//
// Bounds chosen to maximise chunk-pattern collision probability
// while keeping the corpus interesting:
//   * alphabet = [a, b, c]               → high literal-overlap
//   * depth    = 1..=4 chunks            → spans R297's depth range
//   * per chunk: literal / `*` / `**` /
//     `$*`-DSL (1..=2 `$*` runs)         → covers every chunk
//                                           class the R296 matcher
//                                           routes through

use proptest::prelude::*;

/// Single character drawn from the bounded `[a, b, c]` alphabet.
/// The narrow alphabet maximises the chance that two random
/// keyexprs share a candidate literal, so the random corpus
/// exercises real intersect-true branches (not just trivial
/// "all-distinct" rejects).
fn alpha_char_strategy() -> impl Strategy<Value = char> {
    prop::sample::select(vec!['a', 'b', 'c'])
}

/// Bounded-length literal string `[a-c]{min..=max}`.
fn lit_strategy(min: usize, max: usize) -> impl Strategy<Value = String> {
    prop::collection::vec(alpha_char_strategy(), min..=max)
        .prop_map(|chars| chars.into_iter().collect())
}

/// `$*`-DSL chunk. Either a single `$*` run (lead `$*` trail —
/// lead / trail each 0..=2 chars) or two `$*` runs separated by a
/// mandatory non-empty middle (lead `$*` mid `$*` trail — mid
/// must be ≥1 char to keep `$*$*` non-canonical runs out of the
/// corpus). Caps the per-chunk `$*` count at 2 to keep the matcher
/// in its productive regime (the R296 analysis covers 1 and 2 `$*`
/// runs; deeper runs reduce to the same lead/trail anchor check
/// but blow up the alternating-interleaving proof state).
fn dsl_chunk_strategy() -> impl Strategy<Value = String> {
    prop_oneof![
        // n=1: lead $* trail
        (lit_strategy(0, 2), lit_strategy(0, 2))
            .prop_map(|(lead, trail)| format!("{}$*{}", lead, trail)),
        // n=2: lead $* mid $* trail (mid ≥1 char enforces canonical
        // form — adjacent `$*$*` is non-canonical and not in scope)
        (lit_strategy(0, 2), lit_strategy(1, 2), lit_strategy(0, 2))
            .prop_map(|(lead, mid, trail)| format!("{}$*{}$*{}", lead, mid, trail)),
    ]
}

/// One chunk of a keyexpr. Weights balance literal/wildcard mix
/// so each property iteration is likely to exercise at least one
/// non-trivial chunk class (literal weight 3 ≈ 3/8, `*` 1/8,
/// `**` 1/8, DSL 3/8).
fn chunk_strategy() -> impl Strategy<Value = String> {
    prop_oneof![
        3 => lit_strategy(1, 3),
        1 => Just("*".to_string()),
        1 => Just("**".to_string()),
        3 => dsl_chunk_strategy(),
    ]
}

/// Full canonical keyexpr. Joins 1..=4 chunks with `/`, then
/// dedupes consecutive `**` chunks (canonical form per zenoh-pico
/// — `**/**` reduces to `**`). The dedup is in-generator rather
/// than via `prop_filter` so shrinking always lands on a canonical
/// string instead of a rejected sample.
fn keyexpr_strategy() -> impl Strategy<Value = String> {
    prop::collection::vec(chunk_strategy(), 1..=4).prop_map(|chunks| {
        let mut canonical: Vec<String> = Vec::with_capacity(chunks.len());
        for c in chunks {
            if canonical
                .last()
                .is_some_and(|last| last == "**" && c == "**")
            {
                continue;
            }
            canonical.push(c);
        }
        canonical.join("/")
    })
}

proptest! {
    #![proptest_config(ProptestConfig {
        cases: 512,
        ..ProptestConfig::default()
    })]

    /// wz/zenoh-pico cross-validation under random canonical input.
    /// Asserts: forward agreement, reverse agreement, wz symmetry,
    /// pico symmetry. A shrunken counter-example would be a minimal
    /// `(a, b)` pair where the two implementations diverge — the
    /// R296 algorithm analysis predicts no such pair exists in the
    /// canonical input space, and R297 confirmed that for a
    /// handcrafted ~63-case corpus; this property closes the
    /// remaining gap by random fuzz over the canonical chunk-pattern
    /// generator.
    #[test]
    fn keyexpr_intersect_wz_pico_property(
        a in keyexpr_strategy(),
        b in keyexpr_strategy(),
    ) {
        let wz_ab = wz_intersects(&a, &b);
        let pico_ab = zenoh_pico_intersects(&a, &b);
        prop_assert_eq!(
            wz_ab, pico_ab,
            "wz/pico mismatch (forward): `{}` ∩ `{}` → wz={}, pico={}",
            &a, &b, wz_ab, pico_ab,
        );
        let wz_ba = wz_intersects(&b, &a);
        let pico_ba = zenoh_pico_intersects(&b, &a);
        prop_assert_eq!(
            wz_ba, pico_ba,
            "wz/pico mismatch (reverse): `{}` ∩ `{}` → wz={}, pico={}",
            &b, &a, wz_ba, pico_ba,
        );
        prop_assert_eq!(
            wz_ab, wz_ba,
            "wz asymmetry: `{}` ∩ `{}` = {} but `{}` ∩ `{}` = {}",
            &a, &b, wz_ab, &b, &a, wz_ba,
        );
        prop_assert_eq!(
            pico_ab, pico_ba,
            "pico asymmetry: `{}` ∩ `{}` = {} but `{}` ∩ `{}` = {}",
            &a, &b, pico_ab, &b, &a, pico_ba,
        );
    }
}
