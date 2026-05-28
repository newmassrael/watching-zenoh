// SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! R311dn / di-15-pre — keyexpr glob + intersection matchers, the
//! shared resolver underneath subscriber / queryable / liveliness
//! `has_matching` checks.
//!
//! Migrated verbatim from `wz-runtime-tokio::pubsub` so the future
//! `RemoteSubscriberRegistry` + `RemoteQueryableRegistry` extractions
//! (R311do / R311dp) can ship without dragging this helper cluster
//! across into either declare/ leaf module — the registries live on
//! top of the matcher, not alongside it. wz-runtime-tokio re-exports
//! the two public entry points from this module so existing callsite
//! paths (`crate::pubsub::keyexpr_pattern_matches` etc.) stay
//! unchanged at the wz-runtime-tokio seam.
//!
//! Algorithmic shape kept byte-for-byte against the pubsub.rs source
//! so the cumulative R220 / R293 / R296 behavioural ratchet remains
//! observable (the test cases stay in `wz-runtime-tokio::pubsub` for
//! now under the R311dn-tests carry; their identity-via-re-export
//! callsite checks the moved bodies).

use alloc::vec::Vec;

/// Match a `/`-separated zenoh keyexpr `target` (Push's suffix) against
/// a pattern split into chunks. Pattern chunks are:
///
/// * `**` — matches zero or more target chunks.
/// * `*`  — matches exactly one target chunk (any content).
/// * a chunk containing `$*` — intra-chunk substring wildcard
///   (R220). The chunk is split on `$*` into sub-parts; the leading
///   sub-part (if non-empty) must be a prefix of the target chunk,
///   the trailing sub-part (if non-empty) must be a suffix, and
///   each middle sub-part must appear in order in the remaining
///   slice without overlap. See [`chunk_matches_with_dsl`] for the
///   full algorithm.
/// * any other chunk — must compare byte-for-byte against the
///   corresponding target chunk.
///
/// Returns `true` when the target is covered by the pattern.
///
/// The matcher is implemented as a non-recursive two-cursor walk
/// over pattern + target with a single `**` backtrack frame, mirror-
/// ing standard glob-match algorithms. Worst-case complexity is
/// `O(|pattern| * |target|)` when the pattern contains a single
/// `**`; with multiple `**` the algorithm degrades only on
/// pathological inputs (the productive zenoh-style patterns
/// `home/**` / `sensors/*/temp` stay linear).
pub fn keyexpr_pattern_matches(pattern_chunks: &[&str], target: &str) -> bool {
    let target_chunks: Vec<&str> = target.split('/').collect();
    matches_chunks(pattern_chunks, &target_chunks)
}

fn matches_chunks(pattern: &[&str], target: &[&str]) -> bool {
    let mut pi = 0;
    let mut ti = 0;
    // Backtrack frame for the last `**` encountered. When a
    // subsequent literal mismatch occurs we rewind pattern to one-
    // past-`**` and advance target by one, letting `**` consume one
    // more chunk before re-attempting the suffix.
    let mut star_star_pi: Option<usize> = None;
    let mut star_star_ti: usize = 0;

    while ti < target.len() {
        if pi < pattern.len() {
            let pat = pattern[pi];
            if pat == "**" {
                star_star_pi = Some(pi);
                star_star_ti = ti;
                pi += 1;
                continue;
            }
            if pat == "*" || chunk_matches(pat, target[ti]) {
                pi += 1;
                ti += 1;
                continue;
            }
        }
        // Mismatch (literal differs, or pattern is exhausted while
        // target still has chunks). If we are inside a `**` frame,
        // backtrack by absorbing one more target chunk into `**`.
        if let Some(saved_pi) = star_star_pi {
            star_star_ti += 1;
            ti = star_star_ti;
            pi = saved_pi + 1;
        } else {
            return false;
        }
    }
    // Target exhausted. Pattern must be exhausted too, except for a
    // trailing `**` which matches zero chunks.
    while pi < pattern.len() && pattern[pi] == "**" {
        pi += 1;
    }
    pi == pattern.len()
}

/// Match one pattern chunk against one target chunk. Routes between
/// the DSL path ([`chunk_matches_with_dsl`]) and a byte-equal
/// fast-path based on whether the pattern chunk contains the `$*`
/// token. The `*` and `**` whole-chunk wildcards are handled by the
/// caller before reaching this function.
fn chunk_matches(pattern: &str, target: &str) -> bool {
    if pattern.contains("$*") {
        chunk_matches_with_dsl(pattern, target)
    } else {
        pattern == target
    }
}

/// Intra-chunk substring DSL matcher. The pattern chunk is split on
/// `$*` into sub-parts; each non-empty sub-part must appear in
/// `target` in order without overlap, anchored as follows:
///
/// * If the chunk starts with `$*` (leading sub-part is empty), the
///   first non-empty sub-part can appear at any byte offset.
///   Otherwise the first sub-part must align with target byte 0.
/// * Symmetric for the chunk end: a trailing `$*` lets the last
///   non-empty sub-part float; otherwise it must align with the
///   target's last byte.
/// * Middle sub-parts are located via leftmost-first substring
///   search, mirroring zenoh-pico's
///   `_z_chunk_right_contains_all_stardsl_subchunks_of_left`.
///
/// Empty middle sub-parts (which only arise from non-canonical
/// `$*$*` runs, since canonical zenoh collapses them) are treated
/// as no-ops so the matcher remains equivalent to the canonical
/// form `$*`.
fn chunk_matches_with_dsl(pattern: &str, target: &str) -> bool {
    let parts: Vec<&str> = pattern.split("$*").collect();
    debug_assert!(
        parts.len() >= 2,
        "chunk_matches_with_dsl invoked on a pattern without `$*` — caller routing bug",
    );

    let n = parts.len();
    let mut remaining = target;

    let leading = parts[0];
    if !leading.is_empty() {
        match remaining.strip_prefix(leading) {
            Some(rest) => remaining = rest,
            None => return false,
        }
    }

    for &part in &parts[1..n - 1] {
        if part.is_empty() {
            continue;
        }
        match remaining.find(part) {
            Some(pos) => remaining = &remaining[pos + part.len()..],
            None => return false,
        }
    }

    let trailing = parts[n - 1];
    if trailing.is_empty() {
        true
    } else {
        remaining.ends_with(trailing) && remaining.len() >= trailing.len()
    }
}

/// R293 — honest two-pattern keyexpr intersection. Returns `true`
/// iff there exists at least one literal `/`-separated keyexpr `t`
/// covered by *both* `a_chunks` and `b_chunks` under zenoh
/// wildcard semantics. Both inputs are pre-split chunk slices
/// (the contract matches [`keyexpr_pattern_matches`]'s pattern
/// argument); pass `&['/'.split() of the string]`.
///
/// Wildcard chunk types handled symmetrically on either side:
///
/// * `**` — zero or more literal chunks (the standard zenoh
///   `match_anywhere` glob).
/// * `*` — exactly one literal chunk (any content).
/// * `pre$*mid$*post` — intra-chunk DSL: leading anchor, ordered
///   middle substrings, trailing anchor. The `$*` token consumes
///   zero-or-more bytes within the chunk (R220 intra-chunk
///   semantics).
/// * any other chunk — must compare byte-for-byte against the
///   other side's corresponding chunk (or be reachable through
///   the other side's `*` / `**`).
///
/// Two-side `$*` semantics: when both chunks contain `$*`,
/// [`chunk_intersects`] returns the conjunction of two
/// char-by-char anchor checks — leading-prefix compatibility plus
/// trailing-suffix compatibility — which is mechanically
/// equivalent (under canonical wire input) to zenoh-pico's
/// `intersects`-mode chunk matcher (`_z_chunk_forward_intersects`
/// → `_z_chunk_forward_backward_intersects` →
/// `_z_chunk_special_intersects`). R296 closure: middle
/// `$*`-separated sub-parts on both sides always admit a common
/// literal because any two ordered sub-part sequences can be
/// realised in a single shared chunk literal via alternating
/// interleaving (each side independently floats its sub-parts
/// through its own `$*` runs), so the lead/trail anchor pair is
/// also the sufficient condition. zenoh-pico's chunk_special
/// `intersects` path takes the same over-approximation branch
/// (line 156 of `keyexpr_match_template.h`: right contains `$*`
/// ⇒ YES) for every two-sided `$*` input — both implementations
/// agree on the answer in this branch.
///
/// The matcher is implemented as a recursive descent with
/// `**`-backtracking on either side. Worst-case complexity is
/// `O(|a| * |b|)` when at most one `**` is present per side; with
/// multiple `**` on both sides the algorithm degrades on
/// pathological inputs (productive zenoh patterns like
/// `home/*/temp` vs `*/sensor/temp` stay linear).
///
/// Symmetry: `keyexpr_intersect_patterns(a, b) ==
/// keyexpr_intersect_patterns(b, a)` for every pair (the
/// recursive cases are written symmetrically; `$*`-both-sides
/// over-approx tests both order combinations).
pub fn keyexpr_intersect_patterns(a_chunks: &[&str], b_chunks: &[&str]) -> bool {
    intersect_chunks(a_chunks, b_chunks)
}

fn intersect_chunks(a: &[&str], b: &[&str]) -> bool {
    match (a.first(), b.first()) {
        (None, None) => true,
        (Some(&"**"), _) => {
            // ** on a-side consumes 0+ chunks from b-side. Try 0
            // consumed (advance a past **) first, then 1+ (advance
            // b by one, keep a's ** for further consumption).
            if intersect_chunks(&a[1..], b) {
                return true;
            }
            if b.is_empty() {
                return false;
            }
            intersect_chunks(a, &b[1..])
        }
        (_, Some(&"**")) => intersect_chunks(b, a),
        (None, _) | (_, None) => {
            // One side exhausted while the other still has chunks
            // (none of which can be `**` — that case is handled
            // above). Mismatch.
            false
        }
        (Some(ap), Some(bp)) => {
            if !chunk_intersects(ap, bp) {
                return false;
            }
            intersect_chunks(&a[1..], &b[1..])
        }
    }
}

/// Two-side chunk intersection. Routes between the literal /
/// `*` / `$*`-DSL cases on each side. Used by
/// [`intersect_chunks`] to decide whether two single chunks can
/// share at least one literal value.
fn chunk_intersects(a: &str, b: &str) -> bool {
    // `*` on either side matches any single chunk; both-sides `*`
    // trivially intersect.
    if a == "*" || b == "*" {
        return true;
    }
    let a_has_dsl = a.contains("$*");
    let b_has_dsl = b.contains("$*");
    match (a_has_dsl, b_has_dsl) {
        (false, false) => a == b,
        (true, false) => chunk_matches_with_dsl(a, b),
        (false, true) => chunk_matches_with_dsl(b, a),
        (true, true) => {
            // Two-side `$*`. Equivalent to zenoh-pico's
            // intersects-mode chunk matcher
            // (`_z_chunk_forward_intersects` → `forward_backward` →
            // `chunk_special_intersects`) for canonical inputs.
            //
            // The algorithm: each chunk decomposes on `$*` into a
            // leading anchor + ordered middle sub-parts + trailing
            // anchor. Two chunk patterns share at least one literal
            // iff their leading anchors are prefix-compatible (one
            // is a prefix of the other — the empty string is a
            // prefix of any string) AND their trailing anchors are
            // suffix-compatible.
            //
            // Middle sub-parts are unconstrained: any two ordered
            // sub-part sequences `[A1, A2, …, AN]` and `[B1, B2,
            // …, BM]` always admit a shared chunk literal where
            // both occur sequentially — e.g. the alternating
            // concatenation `A1 B1 A2 B2 …` (each side independently
            // floats its sub-parts through its own `$*` runs).
            // zenoh-pico's `chunk_special_intersects` confirms this
            // via the `right contains $*` over-approximation on
            // line 156 of `keyexpr_match_template.h`: every (true,
            // true) input lands in that branch and zenoh-pico
            // returns YES. So the lead/trail anchor pair is also a
            // necessary condition (failing it rejects both
            // matchers) and the sufficient condition (passing it
            // accepts both matchers). R293 originally labelled this
            // "over-approximation"; R296 closure: the algorithm is
            // exact for intersects mode in the two-side `$*` case.
            let a_parts: Vec<&str> = a.split("$*").collect();
            let b_parts: Vec<&str> = b.split("$*").collect();
            let a_lead = a_parts[0];
            let a_trail = a_parts[a_parts.len() - 1];
            let b_lead = b_parts[0];
            let b_trail = b_parts[b_parts.len() - 1];
            let lead_compat = a_lead.starts_with(b_lead) || b_lead.starts_with(a_lead);
            let trail_compat = a_trail.ends_with(b_trail) || b_trail.ends_with(a_trail);
            lead_compat && trail_compat
        }
    }
}
