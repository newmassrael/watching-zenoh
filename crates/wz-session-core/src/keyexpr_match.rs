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
//!
//! ## Per-capability cfg gating (R311jf)
//!
//! The keyexpr wildcard / DSL capabilities are atomic catalog features
//! (`§5.6`), no longer always-on. Three are user-excludable composition
//! toggles; their branches carry a `#[cfg(feature = …)]` so a profile
//! that omits them strips the code (a literal-only MCU client does not
//! pay for the `**` backtrack frame or the `$*` substring DSL):
//!
//! * `keyexpr-wildcard-single` — the whole-chunk `*` arm.
//! * `keyexpr-wildcard-double` — the multi-chunk `**` arm + backtrack.
//! * `keyexpr-dollar-star` — the intra-chunk `$*` substring DSL.
//!
//! When a toggle is off the corresponding pattern token loses its
//! special meaning and **degrades to a literal chunk compare** (no
//! panic, no compile error — a pattern `home/**` simply ceases to
//! wildcard-match and is treated as the literal chunk `**`). This is
//! the same compile-flag elision shape zenoh-pico uses.
//!
//! `keyexpr-literal` (exact byte compare) and `keyexpr-mapping` (wire
//! keyexpr-id resolution, see `wireexpr_resolve`) are FOUNDATIONAL —
//! every consumer needs them, so they ship always-on and are not gated
//! here. `keyexpr-intersect` ([`keyexpr_intersect_patterns`]) is also
//! foundational: the always-compiled subscriber / queryable registry
//! `has_matching` calls it unconditionally, so it cannot be excluded
//! without breaking pub/sub matching. Its *wildcard sub-branches* are
//! still gated by the three toggles above (intersect with wildcards off
//! degrades to literal-set intersection).
//!
//! `keyexpr-includes` ([`keyexpr_includes_patterns`]) is a real toggle:
//! the directional pattern⊇pattern predicate (zenoh-pico
//! `_z_keyexpr_includes`) ships only under its feature. It has no
//! internal consumer yet (exposed + tested + cross-compiled, awaiting a
//! routing/aggregation caller — the bottom-up framework pattern).

use crate::bounded::BoundedVec;

/// Maximum number of `/`-separated chunks a target keyexpr is split
/// into for the backtracking matcher. On the MCU no-heap profile this
/// is the hard declared bound (`BoundedVec`'s no-alloc backing); a
/// target deeper than this is conservatively treated as no-match (the
/// §2.1 bounded-declared-table philosophy — MCU keyexprs are
/// deploy-bounded). On the AP profile the `BoundedVec` `alloc` backing
/// grows past it, so AP behaviour is unbounded and identical to the
/// prior `Vec` form. Mirrors the `parse_error::MAX_EXT_CHAIN_DEPTH`
/// declared-bound precedent.
pub const MAX_KEYEXPR_CHUNKS: usize = 32;

/// Match a `/`-separated zenoh keyexpr `target` (Push's suffix) against
/// a pattern split into chunks. Pattern chunks are:
///
/// * `**` — matches zero or more target chunks
///   (`keyexpr-wildcard-double`).
/// * `*`  — matches exactly one target chunk (any content)
///   (`keyexpr-wildcard-single`).
/// * a chunk containing `$*` — intra-chunk substring wildcard
///   (R220, `keyexpr-dollar-star`). The chunk is split on `$*` into
///   sub-parts; the leading sub-part (if non-empty) must be a prefix
///   of the target chunk, the trailing sub-part (if non-empty) must
///   be a suffix, and each middle sub-part must appear in order in
///   the remaining slice without overlap. See
///   [`chunk_matches_with_dsl`] for the full algorithm.
/// * any other chunk — must compare byte-for-byte against the
///   corresponding target chunk (`keyexpr-literal`, foundational).
///
/// When a wildcard feature is disabled its token degrades to a literal
/// chunk compare (a `**` chunk only matches the literal target chunk
/// `**`).
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
    let mut target_chunks: BoundedVec<&str, MAX_KEYEXPR_CHUNKS> = BoundedVec::new();
    for chunk in target.split('/') {
        // No-alloc backing: a target deeper than the declared bound
        // cannot be represented, so it is conservatively no-match. The
        // alloc backing never takes this arm (push is infallible).
        if target_chunks.push(chunk).is_err() {
            return false;
        }
    }
    matches_chunks(pattern_chunks, &target_chunks)
}

fn matches_chunks(pattern: &[&str], target: &[&str]) -> bool {
    let mut pi = 0;
    let mut ti = 0;
    // Backtrack frame for the last `**` encountered. When a
    // subsequent literal mismatch occurs we rewind pattern to one-
    // past-`**` and advance target by one, letting `**` consume one
    // more chunk before re-attempting the suffix. Present only when
    // `keyexpr-wildcard-double` is enabled — without it there is no
    // `**` token to backtrack over.
    #[cfg(feature = "keyexpr-wildcard-double")]
    let mut star_star_pi: Option<usize> = None;
    #[cfg(feature = "keyexpr-wildcard-double")]
    let mut star_star_ti: usize = 0;

    while ti < target.len() {
        if pi < pattern.len() {
            let pat = pattern[pi];
            #[cfg(feature = "keyexpr-wildcard-double")]
            if pat == "**" {
                star_star_pi = Some(pi);
                star_star_ti = ti;
                pi += 1;
                continue;
            }
            #[cfg(feature = "keyexpr-wildcard-single")]
            if pat == "*" {
                pi += 1;
                ti += 1;
                continue;
            }
            if chunk_matches(pat, target[ti]) {
                pi += 1;
                ti += 1;
                continue;
            }
        }
        // Mismatch (literal differs, or pattern is exhausted while
        // target still has chunks). If we are inside a `**` frame,
        // backtrack by absorbing one more target chunk into `**`.
        #[cfg(feature = "keyexpr-wildcard-double")]
        if let Some(saved_pi) = star_star_pi {
            star_star_ti += 1;
            ti = star_star_ti;
            pi = saved_pi + 1;
            continue;
        }
        return false;
    }
    // Target exhausted. Pattern must be exhausted too, except for a
    // trailing `**` which matches zero chunks.
    #[cfg(feature = "keyexpr-wildcard-double")]
    while pi < pattern.len() && pattern[pi] == "**" {
        pi += 1;
    }
    pi == pattern.len()
}

/// Match one pattern chunk against one target chunk. Routes between
/// the DSL path ([`chunk_matches_with_dsl`]) and a byte-equal
/// fast-path based on whether the pattern chunk contains the `$*`
/// token. The `*` and `**` whole-chunk wildcards are handled by the
/// caller before reaching this function. With `keyexpr-dollar-star`
/// off the `$*` route is elided and every chunk takes the literal
/// byte-equal path.
fn chunk_matches(pattern: &str, target: &str) -> bool {
    #[cfg(feature = "keyexpr-dollar-star")]
    if pattern.contains("$*") {
        return chunk_matches_with_dsl(pattern, target);
    }
    pattern == target
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
#[cfg(feature = "keyexpr-dollar-star")]
fn chunk_matches_with_dsl(pattern: &str, target: &str) -> bool {
    debug_assert!(
        pattern.contains("$*"),
        "chunk_matches_with_dsl invoked on a pattern without `$*` — caller routing bug",
    );

    // Allocation-free `$*`-split walk: a peekable iterator replaces the
    // former `Vec<&str> = split("$*").collect()`. The first item is the
    // leading anchor, the last item (peek == None) is the trailing
    // anchor, and every item in between is an ordered middle sub-part.
    // Behaviour is byte-for-byte identical to the prior indexed form
    // (`parts[0]` / `parts[1..n-1]` / `parts[n-1]`). Since `pattern`
    // contains `$*`, `split` yields at least two items, so the loop
    // always reaches the trailing-anchor arm and the `unreachable!`
    // tail is never executed.
    let mut parts = pattern.split("$*").peekable();
    let mut remaining = target;

    let leading = parts.next().unwrap_or("");
    if !leading.is_empty() {
        match remaining.strip_prefix(leading) {
            Some(rest) => remaining = rest,
            None => return false,
        }
    }

    loop {
        let part = match parts.next() {
            Some(p) => p,
            None => unreachable!("`$*` guarantees >= 2 parts; trailing arm consumes the last"),
        };
        if parts.peek().is_none() {
            // Trailing anchor.
            return if part.is_empty() {
                true
            } else {
                remaining.ends_with(part) && remaining.len() >= part.len()
            };
        }
        // Middle sub-part.
        if part.is_empty() {
            continue;
        }
        match remaining.find(part) {
            Some(pos) => remaining = &remaining[pos + part.len()..],
            None => return false,
        }
    }
}

/// R293 — honest two-pattern keyexpr intersection. Returns `true`
/// iff there exists at least one literal `/`-separated keyexpr `t`
/// covered by *both* `a_chunks` and `b_chunks` under zenoh
/// wildcard semantics. Both inputs are pre-split chunk slices
/// (the contract matches [`keyexpr_pattern_matches`]'s pattern
/// argument); pass `&['/'.split() of the string]`.
///
/// FOUNDATIONAL (not behind a `keyexpr-intersect` cfg): the
/// always-compiled subscriber / queryable `has_matching` calls this
/// unconditionally. Its `**` / `*` / `$*` sub-branches are gated by
/// the three wildcard toggles, so intersect with wildcards off
/// degrades to literal-set intersection (chunk equality).
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

/// Whether the registered/declared keyexpr `candidate` intersects a published
/// target already split into `target_chunks` — the per-candidate membership test
/// every keyexpr SCAN shares. A scan splits the published target ONCE, then
/// calls this per candidate; the candidate is split here into a bounded chunk
/// buffer and consulted via [`keyexpr_intersect_patterns`]. Two scans route
/// through it: the local subscriber / queryable registry consult
/// (`crate::declare::declared_intersects`) and the routing layer's linkstate-peer
/// interest scan (`matching_peers` in wz-runtime-tokio).
///
/// The candidate is split into a bounded buffer exactly as
/// [`keyexpr_pattern_matches`] splits its target: on the no-alloc MCU profile a
/// candidate deeper than [`MAX_KEYEXPR_CHUNKS`] is conservatively no-match, while
/// the alloc (AP) backing grows past it — so AP matching is unbounded and
/// behaviour-identical to the prior `Vec` split (see [`MAX_KEYEXPR_CHUNKS`]). The
/// pre-split `target_chunks` are the caller's, mirroring how
/// [`keyexpr_pattern_matches`] takes a caller-pre-split pattern.
///
/// zenoh folds these candidates into a prefix RESOURCE TREE (`Resource`) for
/// sublinear matching; wz keeps the O(candidates) linear scan (correct, and a
/// realistic subscription set is small). This helper is the SINGLE seam a future
/// resource-tree would land behind — both scans already consult it, so the tree
/// is one reimplementation site rather than two.
pub fn keyexpr_intersects_target(candidate: &str, target_chunks: &[&str]) -> bool {
    let mut candidate_chunks: BoundedVec<&str, MAX_KEYEXPR_CHUNKS> = BoundedVec::new();
    for chunk in candidate.split('/') {
        // No-alloc backing: a candidate deeper than the declared bound cannot be
        // represented, so it is conservatively no-match (the alloc backing never
        // takes this arm). Same shape as keyexpr_pattern_matches' target split.
        if candidate_chunks.push(chunk).is_err() {
            return false;
        }
    }
    keyexpr_intersect_patterns(&candidate_chunks, target_chunks)
}

fn intersect_chunks(a: &[&str], b: &[&str]) -> bool {
    match (a.first(), b.first()) {
        (None, None) => true,
        #[cfg(feature = "keyexpr-wildcard-double")]
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
        #[cfg(feature = "keyexpr-wildcard-double")]
        (_, Some(&"**")) => intersect_chunks(b, a),
        (None, _) | (_, None) => {
            // One side exhausted while the other still has chunks
            // (none of which can be `**` — that case is handled
            // above when the feature is on; off, `**` is a literal
            // chunk and falls to the `(Some, Some)` arm). Mismatch.
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
/// share at least one literal value. With both wildcard toggles
/// off this reduces to chunk equality.
fn chunk_intersects(a: &str, b: &str) -> bool {
    // `*` on either side matches any single chunk; both-sides `*`
    // trivially intersect.
    #[cfg(feature = "keyexpr-wildcard-single")]
    if a == "*" || b == "*" {
        return true;
    }
    #[cfg(feature = "keyexpr-dollar-star")]
    {
        let a_has_dsl = a.contains("$*");
        let b_has_dsl = b.contains("$*");
        if a_has_dsl || b_has_dsl {
            return match (a_has_dsl, b_has_dsl) {
                (true, false) => chunk_matches_with_dsl(a, b),
                (false, true) => chunk_matches_with_dsl(b, a),
                (true, true) => {
                    // Two-side `$*`. Equivalent to zenoh-pico's
                    // intersects-mode chunk matcher
                    // (`_z_chunk_forward_intersects` → `forward_backward` →
                    // `chunk_special_intersects`) for canonical inputs.
                    //
                    // Each chunk decomposes on `$*` into a leading anchor +
                    // ordered middle sub-parts + trailing anchor. Two chunk
                    // patterns share at least one literal iff their leading
                    // anchors are prefix-compatible (one is a prefix of the
                    // other — the empty string is a prefix of any string)
                    // AND their trailing anchors are suffix-compatible.
                    // Middle sub-parts are unconstrained (R296 closure: the
                    // alternating concatenation realises any two ordered
                    // sub-part sequences in one shared literal). Only the
                    // leading and trailing anchors are needed.
                    let a_lead = a.split("$*").next().unwrap_or("");
                    let a_trail = a.rsplit("$*").next().unwrap_or("");
                    let b_lead = b.split("$*").next().unwrap_or("");
                    let b_trail = b.rsplit("$*").next().unwrap_or("");
                    let lead_compat = a_lead.starts_with(b_lead) || b_lead.starts_with(a_lead);
                    let trail_compat = a_trail.ends_with(b_trail) || b_trail.ends_with(a_trail);
                    lead_compat && trail_compat
                }
                // Unreachable under the `a_has_dsl || b_has_dsl` guard;
                // the literal-literal answer is chunk equality.
                (false, false) => a == b,
            };
        }
    }
    a == b
}

/// R311jf — directional keyexpr inclusion: returns `true` iff
/// `a_chunks` **includes** `b_chunks`, i.e. every literal
/// `/`-separated keyexpr covered by `b` is also covered by `a`
/// (`a ⊇ b`). Mirror of zenoh-pico `_z_keyexpr_includes`
/// (`left` includes `right`). Both inputs are pre-split chunk
/// slices, same contract as [`keyexpr_intersect_patterns`].
///
/// Unlike [`keyexpr_intersect_patterns`] this is **directional /
/// asymmetric**: `includes(a, b)` is generally not `includes(b, a)`.
/// The chunk rules (a = superset side, b = subset side):
///
/// * a `**` consumes zero or more b chunks (a can be wider).
/// * a b-side `**` with a non-`**` a-chunk ⇒ NO: a's finite
///   non-`**` chunk cannot cover b's arbitrarily-many chunks.
/// * a `*` covers any single b chunk (literal, `*`, or `$*`-DSL).
/// * a b-side `*` with a non-`*`/`**` a-chunk ⇒ NO: only `*`/`**`
///   cover every single-chunk value `*` can take.
/// * a-DSL vs b (literal or DSL): a's `$*` set must contain b's set,
///   computed by [`chunk_matches_with_dsl`] over b's raw chunk
///   string as the haystack (anchored prefix/suffix + ordered
///   middle search — exactly the inclusion predicate, verified
///   against the zenoh-pico template's includes branch).
/// * a-literal vs b-DSL ⇒ NO: a single literal cannot cover a DSL
///   set (which always denotes more than one string).
///
/// Gated behind `keyexpr-includes`: ships only when selected. No
/// internal consumer yet (exposed + tested, awaiting a routing /
/// aggregation caller — the bottom-up framework pattern).
#[cfg(feature = "keyexpr-includes")]
pub fn keyexpr_includes_patterns(a_chunks: &[&str], b_chunks: &[&str]) -> bool {
    includes_chunks(a_chunks, b_chunks)
}

#[cfg(feature = "keyexpr-includes")]
fn includes_chunks(a: &[&str], b: &[&str]) -> bool {
    match (a.first(), b.first()) {
        (None, None) => true,
        #[cfg(feature = "keyexpr-wildcard-double")]
        (Some(&"**"), _) => {
            // a's ** can cover 0+ of b's chunks. Try consuming 0
            // (advance a past **), then 1+ (advance b by one, keep
            // a's ** to cover more). a `**` also includes b `**`.
            if includes_chunks(&a[1..], b) {
                return true;
            }
            if b.is_empty() {
                return false;
            }
            includes_chunks(a, &b[1..])
        }
        #[cfg(feature = "keyexpr-wildcard-double")]
        (_, Some(&"**")) => {
            // b has `**` but a does not start with `**` (handled
            // above): a's single non-`**` chunk cannot cover b's
            // arbitrarily-many chunks. Asymmetric vs intersect.
            false
        }
        (None, _) | (_, None) => false,
        (Some(ap), Some(bp)) => {
            if !chunk_includes(ap, bp) {
                return false;
            }
            includes_chunks(&a[1..], &b[1..])
        }
    }
}

/// Single-chunk directional inclusion (`a ⊇ b`, neither chunk is
/// `**` — that is resolved at the [`includes_chunks`] recursion
/// level). With both wildcard toggles off this reduces to chunk
/// equality.
#[cfg(feature = "keyexpr-includes")]
fn chunk_includes(a: &str, b: &str) -> bool {
    #[cfg(feature = "keyexpr-wildcard-single")]
    {
        // a `*` covers any single chunk.
        if a == "*" {
            return true;
        }
        // b `*` (a is not `*`/`**`) cannot be covered by a finite
        // literal / DSL chunk.
        if b == "*" {
            return false;
        }
    }
    #[cfg(feature = "keyexpr-dollar-star")]
    {
        if a.contains("$*") {
            // a's DSL set ⊇ b (b literal or DSL): b's raw chunk
            // string is the haystack for a's anchored sub-part walk.
            return chunk_matches_with_dsl(a, b);
        }
        if b.contains("$*") {
            // a literal vs b DSL: a denotes one string, b denotes a
            // set of >1, so a cannot include b.
            return false;
        }
    }
    a == b
}

#[cfg(test)]
mod tests {
    use super::*;

    // Profile-agnostic behaviour guard. The exhaustive R220/R293/R296
    // ratchet cases live in the alloc-gated `pubsub.rs`; these run in
    // BOTH the alloc and the no-alloc build so the BoundedVec /
    // peekable rewrites are covered on the MCU profile too. Each
    // wildcard / DSL group is gated by its own feature so the literal-
    // only subset still has a passing, applicable test set.

    #[test]
    fn literal_matching() {
        assert!(keyexpr_pattern_matches(&["home", "temp"], "home/temp"));
        assert!(!keyexpr_pattern_matches(&["home", "temp"], "home/humid"));
        assert!(!keyexpr_pattern_matches(&["home", "temp"], "home/temp/x"));
    }

    #[test]
    fn intersects_target_literal() {
        // The shared keyexpr-scan membership test: a candidate (registered
        // keyexpr) against a pre-split published target.
        assert!(keyexpr_intersects_target("home/temp", &["home", "temp"]));
        assert!(!keyexpr_intersects_target("home/humid", &["home", "temp"]));
        assert!(!keyexpr_intersects_target("home", &["home", "temp"]));
    }

    #[cfg(feature = "keyexpr-wildcard-double")]
    #[test]
    fn intersects_target_wildcard() {
        // A `**` candidate covers a deeper concrete target (the wildcard scan B2
        // relies on); a disjoint-anchor candidate does not.
        assert!(keyexpr_intersects_target("home/**", &["home", "a", "b"]));
        assert!(!keyexpr_intersects_target("other/**", &["home", "a", "b"]));
    }

    #[cfg(feature = "keyexpr-wildcard-single")]
    #[test]
    fn single_wildcard() {
        assert!(keyexpr_pattern_matches(&["home", "*"], "home/temp"));
        assert!(!keyexpr_pattern_matches(&["home", "*"], "home/a/b"));
        assert!(keyexpr_pattern_matches(&["*", "temp"], "home/temp"));
    }

    // Off-semantics guard: with `keyexpr-wildcard-single` disabled the
    // `*` chunk loses its wildcard meaning and is a literal chunk.
    #[cfg(not(feature = "keyexpr-wildcard-single"))]
    #[test]
    fn single_wildcard_off_degrades_to_literal() {
        // `*` matches only the literal chunk `*`, not an arbitrary one.
        assert!(!keyexpr_pattern_matches(&["home", "*"], "home/temp"));
        assert!(keyexpr_pattern_matches(&["home", "*"], "home/*"));
    }

    #[cfg(feature = "keyexpr-wildcard-double")]
    #[test]
    fn double_wildcard() {
        assert!(keyexpr_pattern_matches(&["home", "**"], "home/a/b/c"));
        assert!(keyexpr_pattern_matches(&["home", "**"], "home"));
        assert!(keyexpr_pattern_matches(&["**", "temp"], "a/b/temp"));
    }

    // Off-semantics guard: with `keyexpr-wildcard-double` disabled the
    // `**` chunk is a literal chunk (matches only the literal `**`).
    #[cfg(not(feature = "keyexpr-wildcard-double"))]
    #[test]
    fn double_wildcard_off_degrades_to_literal() {
        assert!(!keyexpr_pattern_matches(&["home", "**"], "home/a/b/c"));
        assert!(keyexpr_pattern_matches(&["home", "**"], "home/**"));
    }

    #[cfg(feature = "keyexpr-dollar-star")]
    #[test]
    fn intra_chunk_dsl() {
        // peekable rewrite of chunk_matches_with_dsl
        assert!(keyexpr_pattern_matches(&["sensor$*"], "sensor42"));
        assert!(keyexpr_pattern_matches(&["$*temp"], "room_temp"));
        assert!(keyexpr_pattern_matches(&["a$*b$*c"], "axxbyyc"));
        assert!(!keyexpr_pattern_matches(&["a$*c"], "axxb"));
    }

    #[cfg(feature = "keyexpr-dollar-star")]
    #[test]
    fn intersection_two_sided_dsl() {
        // split/rsplit head-tail extraction of the (true,true) arm
        assert!(keyexpr_intersect_patterns(&["pre$*post"], &["pre$*post"]));
        assert!(keyexpr_intersect_patterns(&["a$*"], &["$*b"]));
        assert!(!keyexpr_intersect_patterns(&["x$*"], &["y$*"]));
    }

    // Intersect is foundational, so a literal-set intersection test runs
    // on every profile (wildcards on or off).
    #[test]
    fn intersection_literal() {
        assert!(keyexpr_intersect_patterns(
            &["home", "temp"],
            &["home", "temp"]
        ));
        assert!(!keyexpr_intersect_patterns(
            &["home", "temp"],
            &["home", "humid"]
        ));
    }

    #[cfg(all(feature = "keyexpr-includes", feature = "keyexpr-wildcard-double"))]
    #[test]
    fn includes_directional_double_wildcard() {
        // a ⊇ b: `home/**` includes any concrete `home/...`.
        assert!(keyexpr_includes_patterns(
            &["home", "**"],
            &["home", "a", "b"]
        ));
        // asymmetric: the reverse does NOT include.
        assert!(!keyexpr_includes_patterns(
            &["home", "a", "b"],
            &["home", "**"]
        ));
        // `**` includes `**`.
        assert!(keyexpr_includes_patterns(&["**"], &["**"]));
        // a non-`**` chunk cannot include a b-side `**`.
        assert!(!keyexpr_includes_patterns(&["home", "*"], &["home", "**"]));
    }

    #[cfg(all(feature = "keyexpr-includes", feature = "keyexpr-wildcard-single"))]
    #[test]
    fn includes_directional_single_wildcard() {
        // `*` includes any single chunk.
        assert!(keyexpr_includes_patterns(&["home", "*"], &["home", "temp"]));
        // a literal does NOT include `*`.
        assert!(!keyexpr_includes_patterns(
            &["home", "temp"],
            &["home", "*"]
        ));
        // `*` includes `*`.
        assert!(keyexpr_includes_patterns(&["*"], &["*"]));
    }

    #[cfg(all(feature = "keyexpr-includes", feature = "keyexpr-dollar-star"))]
    #[test]
    fn includes_directional_dsl() {
        // a's DSL set ⊇ a concrete literal it matches.
        assert!(keyexpr_includes_patterns(&["sensor$*"], &["sensor42"]));
        // a literal does NOT include a DSL set.
        assert!(!keyexpr_includes_patterns(&["sensor42"], &["sensor$*"]));
        // a's broader DSL ⊇ b's narrower DSL (a anchored prefix `x` is a
        // prefix of b's `x...` strings).
        assert!(keyexpr_includes_patterns(&["x$*"], &["x$*y"]));
        // anchoring: `x$*` does NOT include `zx$*` (b's strings start
        // with `z`, a requires the `x` prefix).
        assert!(!keyexpr_includes_patterns(&["x$*"], &["zx$*"]));
        // trailing anchor: `$*c` includes `x$*c`, not `x$*`.
        assert!(keyexpr_includes_patterns(&["$*c"], &["x$*c"]));
        assert!(!keyexpr_includes_patterns(&["$*c"], &["x$*"]));
    }

    #[cfg(feature = "keyexpr-includes")]
    #[test]
    fn includes_literal_equality() {
        assert!(keyexpr_includes_patterns(
            &["home", "temp"],
            &["home", "temp"]
        ));
        assert!(!keyexpr_includes_patterns(
            &["home", "temp"],
            &["home", "humid"]
        ));
    }

    // No-alloc backing only: a target deeper than MAX_KEYEXPR_CHUNKS is
    // conservatively no-match. On the alloc backing the BoundedVec grows
    // past the declared bound, so this assertion is gated off it. Uses
    // `**` so it requires the double-wildcard toggle.
    #[cfg(all(not(feature = "alloc"), feature = "keyexpr-wildcard-double"))]
    #[test]
    fn over_depth_target_is_conservative_no_match_no_alloc() {
        // MAX_KEYEXPR_CHUNKS + 1 chunks, all matched by `**`.
        let deep = {
            // build "0/1/2/.../N" without alloc: a fixed worst-case &str
            // is simplest — use a static over-depth literal.
            "a/a/a/a/a/a/a/a/a/a/a/a/a/a/a/a/a/a/a/a/a/a/a/a/a/a/a/a/a/a/a/a/a"
        };
        // 33 chunks > MAX_KEYEXPR_CHUNKS (32): cannot be represented on
        // the no-alloc backing, so `**` (which would otherwise match)
        // returns false.
        assert_eq!(deep.split('/').count(), MAX_KEYEXPR_CHUNKS + 1);
        assert!(!keyexpr_pattern_matches(&["**"], deep));
    }

    #[cfg(all(feature = "alloc", feature = "keyexpr-wildcard-double"))]
    #[test]
    fn over_depth_target_matches_on_alloc() {
        let deep = "a/a/a/a/a/a/a/a/a/a/a/a/a/a/a/a/a/a/a/a/a/a/a/a/a/a/a/a/a/a/a/a/a";
        assert_eq!(deep.split('/').count(), MAX_KEYEXPR_CHUNKS + 1);
        // AP backing grows past the declared bound -> `**` still matches.
        assert!(keyexpr_pattern_matches(&["**"], deep));
    }

    // The CANDIDATE-side bound (session-review coverage gap): keyexpr_intersects_target
    // splits the candidate into the same bounded buffer, so the no-alloc backing is
    // conservatively no-match past the bound while the alloc backing grows. Mirrors
    // the over_depth_target_* pair above. Literal 33-vs-33 so no wildcard toggle is
    // needed (an equal candidate isolates the bound, not the content, as the cause).
    #[cfg(not(feature = "alloc"))]
    #[test]
    fn intersects_target_candidate_over_depth_no_match_no_alloc() {
        let deep = "a/a/a/a/a/a/a/a/a/a/a/a/a/a/a/a/a/a/a/a/a/a/a/a/a/a/a/a/a/a/a/a/a";
        assert_eq!(deep.split('/').count(), MAX_KEYEXPR_CHUNKS + 1);
        let target: [&str; MAX_KEYEXPR_CHUNKS + 1] = ["a"; MAX_KEYEXPR_CHUNKS + 1];
        // candidate too deep for the no-alloc buffer -> no-match despite equal content.
        assert!(!keyexpr_intersects_target(deep, &target));
        // a within-bound equal candidate DOES match (the bound, not content, caused it).
        assert!(keyexpr_intersects_target("a/a/a", &["a", "a", "a"]));
    }

    #[cfg(feature = "alloc")]
    #[test]
    fn intersects_target_candidate_over_depth_matches_on_alloc() {
        let deep = "a/a/a/a/a/a/a/a/a/a/a/a/a/a/a/a/a/a/a/a/a/a/a/a/a/a/a/a/a/a/a/a/a";
        assert_eq!(deep.split('/').count(), MAX_KEYEXPR_CHUNKS + 1);
        let target: [&str; MAX_KEYEXPR_CHUNKS + 1] = ["a"; MAX_KEYEXPR_CHUNKS + 1];
        // AP backing grows past the bound -> the deep candidate still matches.
        assert!(keyexpr_intersects_target(deep, &target));
    }
}
