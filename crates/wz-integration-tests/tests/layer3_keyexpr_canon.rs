// SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! Layer 3 wire-interop fixture — keyexpr canonicalization mirror.
//!
//! Cross-validation gate for the R221 claim that
//! `wz_runtime_tokio::keyexpr_canon::canonize_keyexpr` is functionally
//! equivalent to zenoh-pico's `_z_keyexpr_canonize`
//! (`vendor/zenoh-pico/src/session/keyexpr.c:313-433`). The wz module
//! doc-comment (`crates/wz-runtime-tokio/src/keyexpr_canon.rs:64-65`)
//! asserts the variant-name 1:1 mapping; this fixture closes the
//! empirical loop by calling **both** implementations on the same
//! input and asserting:
//!
//!   * success-side — the rewritten canonical strings are byte-equal
//!     **within the agreed subspace** (inputs that do not trigger
//!     any of the three known pico canon bugs documented below)
//!   * failure-side — single-violation inputs map to the same status
//!     code (`KeyexprCanonError` ↔ `zp_keyexpr_canon_status_t`)
//!   * divergence — three **wz/pico canon divergences** are surfaced
//!     and pinned by dedicated tests (`canon_known_pico_anomaly_*`)
//!     so a future round that upgrades pico or upstreams a fix
//!     trips the lock and forces a revisit
//!
//! ## Known wz/pico canon divergences (R299 findings)
//!
//! Both divergences live in pico's main-canonize rewrite loop, not in
//! the per-chunk validation pass (`__zp_canon_prefix`). The wz code is
//! the spec-correct reference; pico's outputs are surfaced as the
//! actual upstream behaviour for wire-interop honesty.
//!
//! 1. **`**` followed by `*`-shape chunk** — pico's `case 1: reader[0]
//!    == '*'` branch writes `*` unconditionally without consulting
//!    `in_big_wild`, then defers `in_big_wild` to the NEXT non-`*`
//!    chunk (which gets `**` re-emitted before its body). Wz drops
//!    the post-`**` `*` per the spec. Example: input `**/*` →
//!    wz=`**`, pico=`*/**`.
//!
//! 2. **Initial `$*` rewrite + any later chunk containing `*`** —
//!    pico's main-rewrite char-walk uses `c < end` instead of `c <
//!    chunk_end` so the per-chunk byte scan reads PAST the chunk
//!    boundary and flags a STARS_IN_CHUNK error from the next chunk's
//!    `*`. Wz processes chunks independently and accepts the input.
//!    Example: input `$*/a/*` → wz=Ok(`*/a/*`), pico=Err(-5).
//!
//! 3. **`**` + literal chunk + `*`** — pico's `__zp_canon_prefix`
//!    case-1 branch (length-1 chunk that is NOT `*` while
//!    `in_big_wild=true`) takes the `else { advance; continue; }`
//!    path which SKIPS the post-walk `in_big_wild = false` reset.
//!    A subsequent `*` chunk then re-enters case-1 with `in_big_wild`
//!    still true and returns `SINGLE_STAR_AFTER_DOUBLE_STAR` with
//!    `*len = (chunk_start_of_star - start) - 3` — a position that
//!    is NOT the start of a 2-byte chunk ending in `*` (it lands on
//!    the `/` between the literal and the `*`). Main canonize then
//!    fails the `chunk_end - reader == 2` precondition and triggers
//!    `assert(false)` at `keyexpr.c:340`, aborting the process via
//!    SIGABRT. Wz handles the same input cleanly.
//!    Example: input `**/c/*` → wz=Ok(`**/c/*`) (identity — the
//!    `**` only absorbs an IMMEDIATELY following `*`-shape chunk,
//!    not one separated by a literal), pico=SIGABRT.
//!
//! Both bugs #1/#2 produce wrong outputs (wire-interop divergence);
//! bug #3 ABORTS the process (denial-of-service risk if a wz peer
//! sends such a keyexpr to a pico client). All three are surfaced
//! here for production wire-interop visibility; the fix decision
//! (track pico's buggy output in wz, add an inbound normalization
//! shim, or upstream a patch to zenoh-pico) is deferred to a future
//! round.

use std::os::raw::c_char;

use proptest::prelude::*;
use wz_runtime_tokio::keyexpr_canon::{canonize_keyexpr, KeyexprCanonError};

/// Invoke zenoh-pico's `_z_keyexpr_canonize` against a writable copy
/// of `input`. Returns the canonical rewritten string on SUCCESS, or
/// the negative status code on a grammar violation.
///
/// The buffer is sized to `input.len()` because canon never grows the
/// output past the input length (singleify shrinks; lone-`$*` → `*`
/// shrinks by 1; drop-after-`**` shrinks by 3; verbatim passthrough
/// is same-length). The truncate-on-success step scopes the returned
/// string to the post-canonize byte range.
fn zenoh_pico_canonize(input: &str) -> Result<String, i32> {
    let mut buf: Vec<u8> = input.as_bytes().to_vec();
    let mut len: usize = buf.len();
    let status = unsafe {
        zenoh_pico_sys::_z_keyexpr_canonize(buf.as_mut_ptr() as *mut c_char, &mut len as *mut usize)
    };
    if status == 0 {
        buf.truncate(len);
        Ok(String::from_utf8(buf).expect("canonize output is valid UTF-8 when input is"))
    } else {
        Err(status as i32)
    }
}

/// Map wz `KeyexprCanonError` → pico `zp_keyexpr_canon_status_t`
/// numeric value, per the 1:1 mapping recorded in the wz module
/// doc-comment.
fn wz_error_to_pico_status(err: &KeyexprCanonError) -> i32 {
    match err {
        KeyexprCanonError::EmptyChunk => -4,
        KeyexprCanonError::StarsInChunk => -5,
        KeyexprCanonError::DollarAfterDollarOrStar => -6,
        KeyexprCanonError::ContainsSharpOrQmark => -7,
        KeyexprCanonError::ContainsUnboundDollar => -8,
    }
}

/// Assert wz and zenoh-pico agree on `input` — same canonical output
/// on success, same status code on failure. Use only for inputs that
/// do NOT trigger one of the documented pico canon bugs; divergent
/// inputs live in `canon_known_pico_anomaly_*`.
#[track_caller]
fn assert_agree(input: &str) {
    let wz_result = canonize_keyexpr(input);
    let pico_result = zenoh_pico_canonize(input);
    match (&wz_result, &pico_result) {
        (Ok(wz_out), Ok(pico_out)) => {
            assert_eq!(
                wz_out, pico_out,
                "canonize output mismatch: `{}` → wz=`{}`, pico=`{}`",
                input, wz_out, pico_out,
            );
        }
        (Err(wz_err), Err(pico_status)) => {
            let expected = wz_error_to_pico_status(wz_err);
            assert_eq!(
                expected, *pico_status,
                "canonize status mismatch: `{}` → wz={:?} (→ {}), pico={}",
                input, wz_err, expected, pico_status,
            );
        }
        (Ok(wz_out), Err(pico_status)) => {
            panic!(
                "canonize accept/reject divergence: `{}` → wz=Ok(`{}`), pico=Err({})",
                input, wz_out, pico_status,
            );
        }
        (Err(wz_err), Ok(pico_out)) => {
            panic!(
                "canonize accept/reject divergence: `{}` → wz=Err({:?}), pico=Ok(`{}`)",
                input, wz_err, pico_out,
            );
        }
    }
}

/// Capture both implementations' output without panicking on
/// mismatch, so the divergence-locking tests can assert against
/// the SPECIFIC byte-different outputs each side produces.
fn capture_both(input: &str) -> (Result<String, KeyexprCanonError>, Result<String, i32>) {
    (canonize_keyexpr(input), zenoh_pico_canonize(input))
}

// ── Handcrafted corpus — agreed subspace ───────────────────────

#[test]
fn canon_identity_on_already_canonical_input() {
    // No-op path: input survives byte-for-byte through both
    // implementations. Pure literals, single `*`, double `**` (alone
    // or at end), intra-chunk `$*` DSL chunks.
    assert_agree("home/temp");
    assert_agree("sensors/room1/temp");
    assert_agree("home/*/temp");
    assert_agree("home/**");
    assert_agree("**/temp");
    assert_agree("home/**/temp");
    assert_agree("home/$*foo$*");
    assert_agree("a");
    assert_agree("a/b/c/d/e");
}

#[test]
fn canon_singleify_collapses_dollar_star_runs_in_dsl_chunks() {
    // `$*$*` and longer runs collapse to a single `$*` in chunks
    // that ALSO carry literal anchors — these don't hit pico bug #2
    // because the rewrite chunk stays a Mixed DSL chunk (no `$*`-
    // alone lift, no later chunks with `*`).
    assert_agree("home/foo$*$*bar");
    assert_agree("home/$*$*foo");
    assert_agree("home/foo$*$*$*bar");
}

#[test]
fn canon_lone_dollar_star_alone() {
    // Lone `$*` chunk lifts to `*`. Standalone or as a trailing
    // chunk with no further chunks containing `*` — avoids pico
    // bug #2 (char-walk overrun).
    assert_agree("$*");
    assert_agree("a/$*");
    assert_agree("home/temp/$*");
    assert_agree("a/b/c/$*");
}

#[test]
fn canon_drops_double_star_after_double_star() {
    // `**/**` collapses to one `**`. Both sides handle this
    // consistently — the rewrite occurs before the post-`**`
    // walker, so bug #1's `in_big_wild` deferral path never fires
    // for `**` chunks themselves.
    assert_agree("home/**/**/temp");
    assert_agree("**/**");
    assert_agree("**/**/**");
    assert_agree("a/**/**/**/b");
}

#[test]
fn canon_rejects_invalid_grammar_single_violation() {
    // Each input has EXACTLY ONE grammar violation so wz's chunk-
    // walk and pico's byte-walk hit the same first error — pinning
    // the 1:1 KeyexprCanonError ↔ zp_keyexpr_canon_status_t map.
    // Multi-violation inputs (e.g. `$*/#bad/`) hit different first
    // errors and are not in scope for the status-code lock.
    assert_agree("home//temp"); // EmptyChunk
    assert_agree("home/foo#bar"); // ContainsSharpOrQmark
    assert_agree("home/foo?bar"); // ContainsSharpOrQmark
    assert_agree("home/foo$"); // ContainsUnboundDollar
    assert_agree("home/foo$bar"); // ContainsUnboundDollar
    assert_agree("home/foo*bar"); // StarsInChunk
    assert_agree("home/***"); // StarsInChunk
    assert_agree("home/$$"); // DollarAfterDollarOrStar
    assert_agree("home/foo$*$"); // DollarAfterDollarOrStar
}

// ── Known wz/pico canon divergences (pinned for visibility) ────

#[test]
fn canon_known_pico_anomaly_star_after_double_star() {
    // Pico bug #1: `**` followed by any `*`-shape chunk. Wz drops
    // the post-`**` chunk per spec; pico writes it then re-emits
    // `**` before the next non-`*` chunk. Pinning these specific
    // outputs locks the divergence — a future pico fix flips the
    // assertion and triggers a revisit of the wire-interop strategy.
    let cases: &[(&str, &str, &str)] = &[
        ("**/*", "**", "*/**"),
        ("home/**/*/temp", "home/**/temp", "home/*/**/temp"),
        ("**/$*/temp", "**/temp", "**/*/temp"),
        ("**/$*", "**", "**/*"),
        ("**/$*$*/temp", "**/temp", "**/*/temp"),
    ];
    for (input, wz_expected, pico_expected) in cases {
        let (wz, pico) = capture_both(input);
        assert_eq!(
            wz.as_deref(),
            Ok(*wz_expected),
            "wz canon shape changed for `{}`",
            input,
        );
        assert_eq!(
            pico.as_deref(),
            Ok(*pico_expected),
            "pico canon shape changed for `{}` (upstream may have fixed bug #1 — \
             revisit the R299 divergence carry)",
            input,
        );
    }
}

#[test]
fn canon_known_pico_anomaly_double_star_literal_star_aborts() {
    // Pico bug #3: `**` + literal + `*` triggers SIGABRT via
    // `assert(false)` at keyexpr.c:340 — `__zp_canon_prefix`'s
    // case-1 else-continue path skips the in_big_wild reset, so
    // a subsequent `*` returns SINGLE_STAR_AFTER_DOUBLE_STAR with
    // a `*len` value pointing at the `/` between the literal and
    // the `*` (not at a 2-byte `**` chunk as the main rewrite
    // requires).
    //
    // We CANNOT cross-validate this case at runtime — pico aborts
    // the entire process, which would also kill the test binary.
    // So we only verify wz's behaviour (identity on these inputs —
    // `**` only absorbs an IMMEDIATELY following `*`-shape chunk,
    // not one separated by a literal) and document the pico side
    // analytically. The proptest strategy filters this pattern out
    // (no `**` followed anywhere later by a `*`-shape chunk) so
    // random fuzz does not trip the assert and abort the binary.
    assert_eq!(canonize_keyexpr("**/c/*"), Ok("**/c/*".to_string()));
    assert_eq!(canonize_keyexpr("**/foo/*"), Ok("**/foo/*".to_string()));
    assert_eq!(
        canonize_keyexpr("**/abc/*/def"),
        Ok("**/abc/*/def".to_string()),
    );
    assert_eq!(canonize_keyexpr("**/a/b/*"), Ok("**/a/b/*".to_string()));
}

#[test]
fn canon_known_pico_anomaly_dsl_rewrite_chunk_walk_overrun() {
    // Pico bug #2: the main-canonize char-walk uses `c < end`
    // instead of `c < chunk_end`, so any `*` in a LATER chunk
    // trips STARS_IN_CHUNK on the FIRST post-rewrite chunk's
    // validation pass. Triggers when:
    //
    //   (a) canon_prefix returns a rewrite code (LONE_DOLLAR_STAR
    //       or one of the *_AFTER_DOUBLE_STAR variants — i.e. the
    //       input has a `$*` chunk OR `**` adjacency near the
    //       start), AND
    //   (b) a LATER chunk (after at least one non-`*` chunk that
    //       falls through case 1 / default to the char-walk)
    //       contains any `*`.
    //
    // Wz processes chunks independently and accepts. Pinning the
    // Err(-5) outputs locks the bug.
    let cases: &[(&str, &str, i32)] = &[
        ("$*/a/*", "*/a/*", -5),
        ("$*$*/a/*", "*/a/*", -5),
        ("$*/a/b/*", "*/a/b/*", -5),
    ];
    for (input, wz_expected, pico_expected_status) in cases {
        let (wz, pico) = capture_both(input);
        assert_eq!(
            wz.as_deref(),
            Ok(*wz_expected),
            "wz canon shape changed for `{}`",
            input,
        );
        assert_eq!(
            pico,
            Err(*pico_expected_status),
            "pico canon shape changed for `{}` (upstream may have fixed bug #2 — \
             revisit the R299 divergence carry)",
            input,
        );
    }
}

// ── R299b property fuzz layer ───────────────────────────────────
//
// Random canonical keyexpr generator + property assertion that
// wz/pico agree on byte-equal output. The strategy is constrained
// to the AGREED subspace:
//
//   * inputs are pre-canonical (avoid singleify and rewrite paths
//     that trigger pico bug #2 char-walk overrun)
//   * `**` chunks are never followed by `*`-shape chunks (avoid
//     pico bug #1 in_big_wild deferral)
//
// The handcrafted corpus above + the divergence-lock tests pin the
// behaviour outside this subspace; the property exists to surface
// any THIRD divergence that random fuzz turns up.

/// Single character drawn from the bounded `[a, b, c]` alphabet.
fn alpha_char_strategy() -> impl Strategy<Value = char> {
    prop::sample::select(vec!['a', 'b', 'c'])
}

/// Bounded-length literal string `[a-c]{min..=max}`.
fn lit_strategy(min: usize, max: usize) -> impl Strategy<Value = String> {
    prop::collection::vec(alpha_char_strategy(), min..=max)
        .prop_map(|chars| chars.into_iter().collect())
}

/// Pre-canonical `$*`-DSL chunk: chunks with a single `$*` run
/// flanked by literal anchors (lead OR trail must be non-empty so
/// the chunk is NOT a lone `$*` — that lifts to `*` and triggers
/// the rewrite path).
fn dsl_chunk_strategy() -> impl Strategy<Value = String> {
    prop_oneof![
        // lead $* trail — at least one of lead/trail non-empty
        (lit_strategy(1, 2), lit_strategy(0, 2))
            .prop_map(|(lead, trail)| format!("{}$*{}", lead, trail)),
        (lit_strategy(0, 2), lit_strategy(1, 2))
            .prop_map(|(lead, trail)| format!("{}$*{}", lead, trail)),
    ]
}

/// Per-chunk strategy: weighted union over literal / `*` / `**` /
/// flanked-DSL. NO `$*`-alone chunk (would lift to `*` and bump
/// canon_prefix into the rewrite path).
fn chunk_strategy() -> impl Strategy<Value = String> {
    prop_oneof![
        4 => lit_strategy(1, 3),
        1 => Just("*".to_string()),
        1 => Just("**".to_string()),
        3 => dsl_chunk_strategy(),
    ]
}

/// Full canonical keyexpr — 1..=4 chunks joined by `/`. Post-
/// process strips known pico-divergence patterns:
///
///   * any `**` chunk → drop ALL subsequent chunks whose first
///     byte is `*` or `$` (pico bug #1) OR `*`-shape after any
///     literal that follows the `**` (pico bug #3, which aborts
///     the process via SIGABRT)
///
/// Simplest safe constraint: once a `**` chunk appears, drop every
/// later chunk that is exactly `*` or starts with `$` or is `**`.
/// Literal-only tails are safe. Equivalent: keep `**` only as the
/// final chunk OR followed exclusively by Mixed/literal chunks.
fn keyexpr_strategy() -> impl Strategy<Value = String> {
    prop::collection::vec(chunk_strategy(), 1..=4).prop_map(|chunks| {
        let mut canonical: Vec<String> = Vec::with_capacity(chunks.len());
        let mut seen_double_star = false;
        for c in chunks {
            if seen_double_star {
                // After a `**` anywhere in the keyexpr, drop any
                // `*`-shape or `$*`-DSL chunk to avoid pico bugs
                // #1 and #3. Mixed literal chunks are safe.
                if c == "*" || c == "**" || c.starts_with('$') {
                    continue;
                }
            }
            if c == "**" {
                seen_double_star = true;
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

    /// wz/zenoh-pico canonize cross-validation under random
    /// canonical input. The generator pre-filters known pico
    /// divergences so within the AGREED subspace the two impls
    /// must return byte-equal output. A failure would mean a
    /// THIRD divergence class — the property is the gate for it.
    #[test]
    fn keyexpr_canon_wz_pico_property(input in keyexpr_strategy()) {
        let wz_result = canonize_keyexpr(&input);
        let pico_result = zenoh_pico_canonize(&input);
        match (&wz_result, &pico_result) {
            (Ok(wz_out), Ok(pico_out)) => {
                prop_assert_eq!(
                    wz_out, pico_out,
                    "canonize output mismatch: `{}` → wz=`{}`, pico=`{}`",
                    &input, wz_out, pico_out,
                );
            }
            (Err(wz_err), Err(pico_status)) => {
                let expected = wz_error_to_pico_status(wz_err);
                prop_assert_eq!(
                    expected, *pico_status,
                    "canonize status mismatch: `{}` → wz={:?} (→ {}), pico={}",
                    &input, wz_err, expected, pico_status,
                );
            }
            (Ok(wz_out), Err(pico_status)) => {
                prop_assert!(
                    false,
                    "canonize accept/reject divergence: `{}` → wz=Ok(`{}`), pico=Err({})",
                    &input, wz_out, pico_status,
                );
            }
            (Err(wz_err), Ok(pico_out)) => {
                prop_assert!(
                    false,
                    "canonize accept/reject divergence: `{}` → wz=Err({:?}), pico=Ok(`{}`)",
                    &input, wz_err, pico_out,
                );
            }
        }
    }
}
