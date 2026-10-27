// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
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
//! `_z_keyexpr_includes`) ships only under its feature. Its awaited
//! `routing/aggregation caller` ARRIVED as [`keyexpr_includes_target`],
//! which delegates here and is called on every ACL / routing coverage
//! scan (`router_forward`, `linkstate_forward`,
//! `interceptor::low_pass`, `wz-access-control`). R311y301: this said
//! "no internal consumer yet" — the THIRD copy of that stale claim in
//! this file, alongside the [`keyexpr_includes_patterns`] doc, while
//! [`keyexpr_includes_target`]'s doc recorded the arrival. Three
//! hand-maintained copies of one fact, two of them stale: the reason
//! the impl axis belongs in a gated tag, not in prose.

use crate::bounded::BoundedVec;

/// Maximum number of `/`-separated chunks a target keyexpr is split
/// into for the backtracking matcher. On the MCU profiles this is the
/// hard declared bound (`BoundedVec`'s fixed backing: `alloc` off, or
/// `bounded-heapless` on); a target deeper than this is conservatively
/// treated as no-match (the §2.1 bounded-declared-table philosophy — MCU
/// keyexprs are deploy-bounded), so a peer's 33-chunk keyexpr is
/// delivered to no subscriber there. On the AP profile the growable
/// backing grows past it, so AP behaviour is unbounded and identical to
/// the prior `Vec` form. Mirrors the `parse_error::MAX_EXT_CHAIN_DEPTH`
/// declared-bound precedent.
pub const MAX_KEYEXPR_CHUNKS: usize = 32;

/// How many chunks of a keyexpr [`KeyChunks`] holds on the stack. Real keys are a handful of
/// chunks deep (`@/<zid>/peer/status/connect` is five), so a scan of one almost never leaves it.
const STACK_KEY_CHUNKS: usize = 16;

/// A keyexpr split on `/` into a view of its chunks, held on the stack when it has at most
/// `STACK_KEY_CHUNKS` of them.
///
/// Every scan in this crate splits the key it is asked about, and on the growable (AP and
/// heap-MCU) backing a [`BoundedVec`] of chunks is a `Vec` that grows as it is pushed to: a split
/// of a five-chunk key cost two or three allocations and as many frees, on every message and for
/// every queryable the message was tried against. A key deeper than the stack view is split into
/// the [`BoundedVec`] as before, so what it holds and what it refuses are exactly what they
/// were: on the fixed backing a key deeper than [`MAX_KEYEXPR_CHUNKS`] is not representable and
/// [`KeyChunks::split`] answers `None`, which every caller reads as no-match.
pub struct KeyChunks<'a> {
    inline: [&'a str; STACK_KEY_CHUNKS],
    len: usize,
    spilled: Option<BoundedVec<&'a str, MAX_KEYEXPR_CHUNKS>>,
}

impl<'a> KeyChunks<'a> {
    /// Split `text` on `/`. `None` when it has more chunks than the backing can represent.
    pub fn split(text: &'a str) -> Option<Self> {
        let mut chunks = Self::empty();
        if chunks.split_into(text) {
            Some(chunks)
        } else {
            None
        }
    }

    /// No chunks, to be filled by [`Self::split_into`].
    ///
    /// The buffer is over a hundred bytes, and a value RETURNED from a function is moved into
    /// the caller's slot, once for the buffer and once for the `Option` around it, whatever the
    /// function does inside: a query splits six keys, so a hot caller builds the buffer where it
    /// will use it with this and fills it with `split_into`, and `split` is for the rest.
    pub fn empty() -> Self {
        Self {
            // Not `[""; N]`: that array of fat pointers is built by copying a constant template
            // of the same size, a call to the copy function for every split.
            inline: core::array::from_fn(|_| ""),
            len: 0,
            spilled: None,
        }
    }

    /// Split `text` on `/` into `self`, which is overwritten. `false` when it has more chunks
    /// than the backing can represent, and `self` is then not to be read.
    pub fn split_into(&mut self, text: &'a str) -> bool {
        self.len = 0;
        self.spilled = None;
        self.fill_inline(text) || self.spill(text)
    }

    /// Write `text`'s chunks into the inline array. `false` when there are more than it holds,
    /// with the array full (`len == STACK_KEY_CHUNKS`) for [`Self::spill`] to start over.
    fn fill_inline(&mut self, text: &'a str) -> bool {
        // By a scan of the bytes, not `str::split('/')`: the searcher behind that has a fixed
        // cost per chunk that a key of a few short chunks never earns back (4 of these splits
        // were 12% of the instructions of an answered admin GET), and `/` is ASCII, so a byte
        // of it is always a character boundary of the text around it.
        let mut start = 0usize;
        let bytes = text.as_bytes();
        let mut at = 0usize;
        loop {
            let end_of_chunk = at == bytes.len();
            if end_of_chunk || bytes[at] == b'/' {
                if self.len == STACK_KEY_CHUNKS {
                    return false;
                }
                self.inline[self.len] = &text[start..at];
                self.len += 1;
                if end_of_chunk {
                    return true;
                }
                start = at + 1;
            }
            at += 1;
        }
    }

    /// The key deeper than the inline array: every chunk into the bounded vector. `false` when
    /// even that cannot hold them, which every caller reads as no-match.
    fn spill(&mut self, text: &'a str) -> bool {
        let mut spilled: BoundedVec<&'a str, MAX_KEYEXPR_CHUNKS> = BoundedVec::new();
        for chunk in text.split('/') {
            if spilled.push(chunk).is_err() {
                return false;
            }
        }
        self.spilled = Some(spilled);
        true
    }
}

impl<'a> core::ops::Deref for KeyChunks<'a> {
    type Target = [&'a str];

    fn deref(&self) -> &[&'a str] {
        match &self.spilled {
            Some(spilled) => spilled,
            None => &self.inline[..self.len],
        }
    }
}

/// Whether a published `target` (already split on `/`) is well-formed — i.e.
/// has no empty `/`-delimited chunk. A target with an empty chunk (a trailing
/// `home/`, leading `/home`, interior `home//temp`, or the empty key `""`) is
/// NON-CANONICAL and must match NOTHING; without this a stray `home/temp/`
/// splits to `["home","temp",""]` and the trailing `""` is absorbed by a `**`
/// subscription's backtrack — a spurious match (and forward / local delivery).
///
/// zenoh rejects such keys at the data route (`compute_data_route` bails on
/// `key_expr.ends_with('/')` then `OwnedKeyExpr::try_from`,
/// `linkstate_peer/pubsub.rs:948,957`). wz enforces it HERE, inside the two
/// matcher entry points ([`keyexpr_pattern_matches`] +
/// [`keyexpr_intersects_target`]), so "a malformed target matches nothing" is
/// an INVARIANT OF THE MATCHER — every consumer inherits it by construction:
/// the local subscriber / queryable `has_matching`
/// ([`crate::declare::declared_intersects`]), the routing data-route scans
/// (`matching_peers`, `RouteTable::route_targets`), and the switchboard. That is
/// the single-source-of-truth placement: a per-call-site `ends_with('/')` guard
/// (the prior shape) both DUPLICATED the rule and was INCOMPLETE — it missed
/// `home//temp`, `/home`, and `""`. The full canonical grammar lives in
/// [`crate::keyexpr_canon`]; the empty-chunk test is the structural subset a
/// concrete published target can realistically violate, checked here without the
/// per-candidate allocation a full `canonize_keyexpr` would cost on this scan
/// hot path.
fn target_chunks_well_formed(target_chunks: &[&str]) -> bool {
    !target_chunks.iter().any(|chunk| chunk.is_empty())
}

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
///   `chunk_matches_with_dsl` for the full algorithm.
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
    // No-alloc backing: a target deeper than the declared bound cannot be
    // represented, so it is conservatively no-match. The alloc backing
    // never takes this arm.
    let mut target_chunks = KeyChunks::empty();
    if !target_chunks.split_into(target) {
        return false;
    }
    // A malformed target (an empty chunk) matches nothing — see
    // `target_chunks_well_formed`.
    if !target_chunks_well_formed(&target_chunks) {
        return false;
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
            // R311y543 — `*` reaches every chunk EXCEPT a verbatim one. The
            // guard is here rather than only in `chunk_matches` so the refusal
            // falls through to the mismatch arm below: an enclosing `**` frame
            // must still get its chance to backtrack, and an early `return
            // false` would take that away.
            #[cfg(feature = "keyexpr-wildcard-single")]
            if pat == "*" && !is_verbatim_chunk(target[ti]) {
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
            // R311y543 — the chunk `**` is about to swallow is
            // `target[star_star_ti]`, BEFORE the increment. `**` does not cross
            // a verbatim chunk (zenoh `it_intersect`, classical.rs:88-93), so
            // when that chunk is one, the frame is spent and the match fails
            // here instead of absorbing it.
            if star_star_ti < target.len() && is_verbatim_chunk(target[star_star_ti]) {
                return false;
            }
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
    if pattern == target {
        return true;
    }
    // R311y543 — @verbatim. A chunk beginning with `@` is zenoh's ADMIN
    // namespace and no wildcard reaches into it; only a byte-equal chunk does,
    // which the fast path above already answered. See [`is_verbatim_chunk`].
    if is_verbatim_chunk(pattern) || is_verbatim_chunk(target) {
        return false;
    }
    #[cfg(feature = "keyexpr-dollar-star")]
    if pattern.contains("$*") {
        return chunk_matches_with_dsl(pattern, target);
    }
    false
}

/// zenoh's `MayHaveVerbatim::has_direct_verbatim`
/// (`commons/zenoh-keyexpr/src/key_expr/intersect/mod.rs`
/// @ `fn has_direct_verbatim`): a chunk that
/// begins with `@` is VERBATIM — it belongs to the admin namespace and is
/// reachable only by a byte-equal chunk, never by `*`, `**` or a `$*` DSL
/// chunk.
///
/// ## Why this landed at R311y543, and what it cost before
///
/// `keyexpr_prefix`'s module note recorded until this round that wz is
/// "uniformly @-blind" and that full @verbatim is "a re-openable stack-wide
/// atom". It was re-opened by a MEASUREMENT rather than by a review: upstream's
/// `z_advanced_sub.c` subscribing on `demo/capic/**` against a real zenoh-pico
/// advanced publisher received the 4 data samples AND 7 samples of zenoh's own
/// `@adv/pub/<zid>/<eid>/_` beacon traffic, where the real `libzenohc.so` on the
/// identical wire received the 4 and none of the 7. A plain `z_sub.c` shows the
/// same split, so this is the keyexpr rule and not an advanced-subscriber
/// filter — a user subscription was being handed the router's internal
/// namespace.
///
/// The rule is a chunk CLASS, not a wildcard behaviour, so it is unconditional
/// rather than feature-gated: with every wildcard toggle off, chunk equality
/// already gives the same answer, and with any of them on the guard is what
/// keeps `@` out of their reach.
pub(crate) const fn is_verbatim_chunk(chunk: &str) -> bool {
    matches!(chunk.as_bytes(), [b'@', ..])
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
/// `chunk_intersects` returns the conjunction of two
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

/// Whether `keyexpr` contains a wildcard chunk (`*`, `**`, or the `$*`
/// dollar-star) — the single wildcard-PRESENCE predicate, the companion of the
/// wildcard-MATCH predicates above. `*` (ASCII 0x2A) is the sole wildcard lead
/// byte and, being ASCII, cannot occur inside a multi-byte UTF-8 sequence
/// (continuation / lead bytes are all >= 0x80), so a raw byte scan is correct
/// on arbitrary UTF-8. This is the SSOT for "is this a wildcard update / query"
/// — callers must not re-open-code `.contains('*')` (the same scan
/// [`crate::keyexpr_prefix::NonWildKeyExpr::new`] rejects on, and zenoh
/// `is_wild`, `key_expr/borrowed.rs:133`). `const` so a static keyexpr literal
/// can be classified at compile time.
pub const fn is_wild(keyexpr: &str) -> bool {
    let bytes = keyexpr.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'*' {
            return true;
        }
        i += 1;
    }
    false
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
    // A malformed target (an empty chunk) matches nothing — see
    // `target_chunks_well_formed`. Guarded once here, ahead of the candidate
    // split, so every scan (`matching_peers`, `declared_intersects`) inherits it.
    if !target_chunks_well_formed(target_chunks) {
        return false;
    }
    // Two keys with no wildcard intersect exactly when they are the same text: every chunk is a
    // literal, and a literal chunk meets only itself. Most candidates a scan tries are such keys
    // against such a target, and the walk below would split each of them only to compare them
    // chunk by chunk, so the text is compared where it lies. A target with no chunks is not a
    // key a split yields; it goes the long way, which refuses it. Same text has the target's
    // depth, so the fixed backing's refusal of a key deeper than it holds is the target's length.
    if !target_chunks.is_empty()
        && !is_wild(candidate)
        && !target_chunks.iter().any(|chunk| is_wild(chunk))
    {
        return (!crate::bounded::ENFORCES_CAPACITY || target_chunks.len() <= MAX_KEYEXPR_CHUNKS)
            && chunks_spell(target_chunks, candidate);
    }
    // No-alloc backing: a candidate deeper than the declared bound cannot be
    // represented, so it is conservatively no-match (the alloc backing never
    // takes this arm). Same shape as keyexpr_pattern_matches' target split.
    let mut candidate_chunks = KeyChunks::empty();
    if !candidate_chunks.split_into(candidate) {
        return false;
    }
    keyexpr_intersect_patterns(&candidate_chunks, target_chunks)
}

/// Whether the keyexpr `candidate` intersects the keyexpr `target`, both as text: the question
/// [`keyexpr_intersects_target`] asks, for a caller that holds the target unsplit.
///
/// A target is split for the walk only when a wildcard makes the walk necessary. Two keys with no
/// wildcard intersect exactly when they are the same text, and then no chunk of either is
/// looked at: the target is only checked to be a key the walk would accept (no empty chunk, and
/// not deeper than the backing holds), which are the two refusals the walk makes before it
/// compares anything.
pub fn keyexpr_intersects_text(candidate: &str, target: &str) -> bool {
    // Same text first: a candidate of another length is told apart from the target at once, and
    // when they are the same text one look for a wildcard answers for both.
    let same = candidate == target;
    let wild = if same {
        has_star(candidate)
    } else {
        has_star(candidate) || has_star(target)
    };
    if !wild {
        return same && text_is_a_key(target);
    }
    // No-alloc backing: a target deeper than the declared bound cannot be represented, so it is
    // conservatively no-match (the alloc backing never takes this arm).
    let mut target_chunks = KeyChunks::empty();
    if !target_chunks.split_into(target) {
        return false;
    }
    keyexpr_intersects_target(candidate, &target_chunks)
}

/// [`is_wild`] for a caller that is not in a `const` context: the slice search reads a word at a
/// time, where the `const` loop reads a byte.
fn has_star(text: &str) -> bool {
    text.as_bytes().contains(&b'*')
}

/// Whether `text` splits into chunks the matchers accept: none empty (so not the empty text, not
/// a leading or trailing `/`, no `//`), and on the fixed backing no more than it holds.
fn text_is_a_key(text: &str) -> bool {
    KeyFacts::of(text).key
}

/// What is true of a key's text, read in one pass and kept: whether it holds a wildcard, and
/// whether it is a key the matchers accept ([`text_is_a_key`]'s rule).
///
/// A key that does not change between questions is asked about once. A queryable's pattern is
/// fixed from its declaration and a query's key is fixed from its decode, and every match
/// between the two used to scan both again (a wildcard search on each, then a validity pass on
/// a hit). The facts are the same answers, computed where the text is made.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct KeyFacts {
    wild: bool,
    key: bool,
}

impl KeyFacts {
    /// The facts of `text`.
    pub fn of(text: &str) -> Self {
        let bytes = text.as_bytes();
        let mut wild = false;
        let mut doubled = false;
        let mut slashes = 0usize;
        let mut previous = 0u8;
        for &byte in bytes {
            wild |= byte == b'*';
            if byte == b'/' {
                doubled |= previous == b'/';
                slashes += 1;
            }
            previous = byte;
        }
        let key = !bytes.is_empty()
            && bytes[0] != b'/'
            && bytes[bytes.len() - 1] != b'/'
            && !doubled
            && (!crate::bounded::ENFORCES_CAPACITY || slashes < MAX_KEYEXPR_CHUNKS);
        Self { wild, key }
    }

    /// Whether the key of these facts intersects ITSELF, which is what a reply keyed exactly as
    /// its query is asked: the answer [`keyexpr_intersects_text`] gives for the same text on both
    /// sides, with no scan unless a wildcard makes the walk necessary.
    pub fn intersects_itself(self, text: &str) -> bool {
        if self.wild {
            keyexpr_intersects_text(text, text)
        } else {
            self.key
        }
    }
}

/// [`keyexpr_intersects_text`] for two keys whose [`KeyFacts`] are already known: the same
/// answer, with no scan of either text unless a wildcard makes the walk necessary.
pub fn keyexpr_intersects_text_with(
    candidate: &str,
    candidate_facts: KeyFacts,
    target: &str,
    target_facts: KeyFacts,
) -> bool {
    if !(candidate_facts.wild || target_facts.wild) {
        return candidate == target && target_facts.key;
    }
    keyexpr_intersects_text(candidate, target)
}

/// Whether `chunks` joined by `/` is `text`, compared without building the join.
fn chunks_spell(chunks: &[&str], text: &str) -> bool {
    let mut rest = text.as_bytes();
    for (index, chunk) in chunks.iter().enumerate() {
        if index > 0 {
            match rest.split_first() {
                Some((&b'/', tail)) => rest = tail,
                _ => return false,
            }
        }
        match rest.strip_prefix(chunk.as_bytes()) {
            Some(tail) => rest = tail,
            None => return false,
        }
    }
    rest.is_empty()
}

/// [`keyexpr_intersects_target`] for a candidate that is already split: the same question, the
/// same refusal of a malformed target, for a caller that asks it of the same candidate many
/// times (every leg of an admin answer) and splits the candidate once.
pub fn keyexpr_intersects_chunks(candidate_chunks: &[&str], target_chunks: &[&str]) -> bool {
    if !target_chunks_well_formed(target_chunks) {
        return false;
    }
    keyexpr_intersect_patterns(candidate_chunks, target_chunks)
}

/// Whether the rule keyexpr `superset` INCLUDES a message target already split
/// into `target_chunks` — directional `superset ⊇ target`, the asymmetric twin
/// of [`keyexpr_intersects_target`]. The single per-rule membership test the
/// access-control ACL scan shares: a deny/allow scan splits the message keyexpr
/// ONCE, then calls this per configured rule keyexpr; the rule is split here
/// into a bounded chunk buffer and consulted via [`keyexpr_includes_patterns`].
///
/// This is the directional matcher zenoh's ACL uses — `policy_decision_point`
/// asks whether a configured rule keyexpr `R` INCLUDES the message keyexpr `K`
/// (`R ⊇ K`, `deny.nodes_including(key_expr)` /
/// `allow.nodes_including(key_expr)`), NOT whether they merely intersect. The
/// two diverge on real keyexprs (rule `home/*` does NOT include `home/**`, yet
/// they intersect), so an ACL must scan with THIS predicate, not
/// [`keyexpr_intersects_target`] (which is correct for pub/sub route matching,
/// where overlap — not coverage — is the question). This is the awaited
/// `routing / aggregation caller` the [`keyexpr_includes_patterns`] doc names.
///
/// A malformed message target (an empty chunk) is included by no rule — the
/// same `target_chunks_well_formed` guard [`keyexpr_intersects_target`] applies,
/// so a trailing-`/` target is denied under default-deny rather than silently
/// matching. The rule (`superset`) is split into the bounded buffer exactly as
/// the candidate is in [`keyexpr_intersects_target`]: a rule deeper than
/// [`MAX_KEYEXPR_CHUNKS`] is conservatively no-match on the no-alloc backing,
/// unbounded on the alloc (AP) one.
#[cfg(feature = "keyexpr-includes")]
pub fn keyexpr_includes_target(superset: &str, target_chunks: &[&str]) -> bool {
    // A malformed message target matches no rule — guarded once here, ahead of
    // the rule split, the directional mirror of `keyexpr_intersects_target`.
    if !target_chunks_well_formed(target_chunks) {
        return false;
    }
    // No-alloc backing: a rule deeper than the declared bound cannot be
    // represented, so it is conservatively no-match (the alloc backing never
    // takes this arm). Same shape as `keyexpr_intersects_target`.
    let mut superset_chunks = KeyChunks::empty();
    if !superset_chunks.split_into(superset) {
        return false;
    }
    keyexpr_includes_patterns(&superset_chunks, target_chunks)
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
            // R311y543 — `**` does not cross a verbatim chunk, so the
            // consume-one-more step is unavailable when b's next chunk is one.
            // Zero-consumption above is unaffected: `**` may still END before an
            // `@` chunk that the rest of `a` then matches byte-equally.
            match b.first() {
                None => false,
                Some(next) if is_verbatim_chunk(next) => false,
                Some(_) => intersect_chunks(a, &b[1..]),
            }
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
    // R311y543 — zenoh `chunk_intersect` (classical.rs:65-72) in its own order:
    // byte equality FIRST, then the verbatim refusal, then the wildcard rules.
    // The order is load-bearing — `@adv` vs `@adv` intersects, and every other
    // pairing involving an `@` chunk does not.
    if a == b {
        return true;
    }
    if is_verbatim_chunk(a) || is_verbatim_chunk(b) {
        return false;
    }
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
///   computed by `chunk_matches_with_dsl` over b's raw chunk
///   string as the haystack (anchored prefix/suffix + ordered
///   middle search — exactly the inclusion predicate, verified
///   against the zenoh-pico template's includes branch).
/// * a-literal vs b-DSL ⇒ NO: a single literal cannot cover a DSL
///   set (which always denotes more than one string).
///
/// Gated behind `keyexpr-includes`: ships only when selected. The
/// awaited `routing / aggregation caller` ARRIVED — this is the engine
/// behind [`keyexpr_includes_target`], which splits a rule into a
/// bounded chunk buffer and delegates here, and which is called on
/// every ACL / routing coverage scan (`router_forward`,
/// `linkstate_forward`, `interceptor::low_pass`, `wz-access-control`).
/// R311y301: this doc said "no internal consumer yet (exposed +
/// tested, awaiting a routing / aggregation caller)" while
/// [`keyexpr_includes_target`]'s own doc, ~140 lines up, already
/// recorded itself AS that caller — two docs contradicting inside one
/// file, and the Mnemosyne inventory mirrored the stale one.
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
            // R311y543 — same verbatim stop as `intersect_chunks`: a's `**`
            // cannot cover an `@` chunk of b's.
            match b.first() {
                None => false,
                Some(next) if is_verbatim_chunk(next) => false,
                Some(_) => includes_chunks(a, &b[1..]),
            }
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
    // R311y543 — verbatim first, in the same order the intersect side uses: an
    // `@` chunk is covered only by itself.
    if a == b {
        return true;
    }
    if is_verbatim_chunk(a) || is_verbatim_chunk(b) {
        return false;
    }
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

    /// The scan `text_is_a_key` was before the facts were read in one pass, kept here as the
    /// reference the facts are held to.
    fn text_is_a_key_by_the_old_scan(text: &str) -> bool {
        let bytes = text.as_bytes();
        if bytes.is_empty() || bytes[0] == b'/' || bytes[bytes.len() - 1] == b'/' {
            return false;
        }
        let mut slashes = 0usize;
        let mut previous = 0u8;
        for &byte in bytes {
            if byte == b'/' {
                if previous == b'/' {
                    return false;
                }
                slashes += 1;
            }
            previous = byte;
        }
        !crate::bounded::ENFORCES_CAPACITY || slashes < MAX_KEYEXPR_CHUNKS
    }

    const FACT_KEYS: [&str; 18] = [
        "",
        "/",
        "//",
        "a",
        "a/",
        "/a",
        "a//b",
        "a/b",
        "a/b/c",
        "a/*",
        "*",
        "**",
        "a/**",
        "a/*/c",
        "a$*",
        "demo/status/node-0001",
        "demo/config/node-0001",
        "@/zid/query",
    ];

    #[test]
    fn the_facts_of_a_key_are_what_the_separate_scans_say() {
        for key in FACT_KEYS {
            let facts = KeyFacts::of(key);
            assert_eq!(facts.wild, has_star(key), "wild of {key:?}");
            assert_eq!(
                facts.key,
                text_is_a_key_by_the_old_scan(key),
                "key of {key:?}"
            );
        }
        // A key as deep as the backing holds, and one past it.
        for depth in [
            MAX_KEYEXPR_CHUNKS - 1,
            MAX_KEYEXPR_CHUNKS,
            MAX_KEYEXPR_CHUNKS + 1,
        ] {
            let key = ["k"; MAX_KEYEXPR_CHUNKS + 1][..depth].join("/");
            assert_eq!(
                KeyFacts::of(&key).key,
                text_is_a_key_by_the_old_scan(&key),
                "depth {depth}"
            );
        }
    }

    #[test]
    fn a_key_intersects_itself_as_the_text_form_says() {
        for key in FACT_KEYS {
            assert_eq!(
                KeyFacts::of(key).intersects_itself(key),
                keyexpr_intersects_text(key, key),
                "{key:?}"
            );
        }
    }

    #[test]
    fn two_keys_with_their_facts_intersect_as_the_text_form_says() {
        for candidate in FACT_KEYS {
            for target in FACT_KEYS {
                assert_eq!(
                    keyexpr_intersects_text_with(
                        candidate,
                        KeyFacts::of(candidate),
                        target,
                        KeyFacts::of(target)
                    ),
                    keyexpr_intersects_text(candidate, target),
                    "{candidate:?} against {target:?}"
                );
            }
        }
    }

    /// The stack view holds exactly the chunks `str::split('/')` yields, at every depth around its
    /// own bound (it spills past `STACK_KEY_CHUNKS`) and the backing's (`MAX_KEYEXPR_CHUNKS`), and
    /// refuses exactly what the backing refuses: the matchers that use it answer as they did.
    #[test]
    fn key_chunks_are_the_split_at_every_depth_around_both_bounds() {
        for depth in [
            1usize,
            2,
            5,
            STACK_KEY_CHUNKS - 1,
            STACK_KEY_CHUNKS,
            STACK_KEY_CHUNKS + 1,
        ] {
            let key = ["k"; STACK_KEY_CHUNKS + 1][..depth].join("/");
            let view = KeyChunks::split(&key).expect("a key this shallow is representable");
            let want: [&str; STACK_KEY_CHUNKS + 1] = ["k"; STACK_KEY_CHUNKS + 1];
            assert_eq!(&*view, &want[..depth], "depth {depth}");
        }
        // Distinct chunks, so a reordering or a drop shows.
        let key = "a/bb/ccc/dddd/e/ff/ggg/hhhh/i/jj/kkk/llll/m/nn/ooo/pppp/q/rr";
        let view = KeyChunks::split(key).expect("eighteen chunks fit the backing");
        assert!(view.iter().copied().eq(key.split('/')));
        // The empty key is one empty chunk, as `split` has it, and the matchers' own
        // well-formedness guard is what refuses it.
        assert_eq!(&*KeyChunks::split("").expect("one chunk"), &[""][..]);
        // The bound of the backing: representable up to MAX_KEYEXPR_CHUNKS chunks on the fixed
        // one, and past it only where the backing grows.
        let at = "a/".repeat(MAX_KEYEXPR_CHUNKS - 1) + "a";
        assert_eq!(
            KeyChunks::split(&at).map(|v| v.len()),
            Some(MAX_KEYEXPR_CHUNKS)
        );
        let past = "a/".repeat(MAX_KEYEXPR_CHUNKS) + "a";
        let split = KeyChunks::split(&past);
        if crate::bounded::ENFORCES_CAPACITY {
            assert!(split.is_none());
        } else {
            assert_eq!(split.map(|v| v.len()), Some(MAX_KEYEXPR_CHUNKS + 1));
        }
    }

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
    fn is_wild_detects_every_wildcard_marker_and_no_false_positive() {
        assert!(is_wild("demo/**"));
        assert!(is_wild("demo/*"));
        assert!(is_wild("demo/*/x"));
        assert!(is_wild("demo/$*"), "the dollar-star also leads with '*'");
        assert!(!is_wild("demo/a"));
        assert!(!is_wild("demo/a/b"));
        assert!(!is_wild(""));
    }

    /// The candidate scan answers what the split-and-intersect walk answers, for every pair of a
    /// corpus that holds both kinds of key (with and without a wildcard), the malformed ones (an
    /// empty chunk, a leading or trailing `/`, the empty key) and keys that differ only by a
    /// prefix, a suffix or one chunk. The walk is the oracle: the shortcut for two keys with no
    /// wildcard must never answer differently.
    #[test]
    fn intersects_target_agrees_with_the_walk_over_a_corpus() {
        let corpus = [
            "",
            "a",
            "a/b",
            "a/b/",
            "/a/b",
            "a//b",
            "a/b/c",
            "ab/c",
            "a/bc",
            "a/b/c/d",
            "@/5a1c0ffee001/peer/status/connect",
            "@/5a1c0ffee001/peer/status/config",
            "@/5a1c0ffee001/peer/status",
            "@/5a1c0ffee001/peer/status/connect/x",
            "a/*",
            "*/b",
            "a/**",
            "**",
            "a/b$*",
            "$*",
            "a/$b",
            "a/b$",
            "a/*/c",
            "@/5a1c0ffee001/**",
        ];
        // The walk, spelled out: split both, refuse a malformed target, intersect the chunks.
        let walk = |candidate: &str, target: &str| {
            KeyChunks::split(target).is_some_and(|chunks| {
                target_chunks_well_formed(&chunks)
                    && KeyChunks::split(candidate)
                        .is_some_and(|split| keyexpr_intersect_patterns(&split, &chunks))
            })
        };
        // Fixed buffers, not `String` and `Vec`: the test has to run where there is no allocator
        // as well, because that is where the shortcut it guards was added.
        const DEEP_BYTES: usize = 2 * MAX_KEYEXPR_CHUNKS + 1;
        let deep_with = |last: &str| {
            let mut key: crate::bounded::BoundedString<DEEP_BYTES> =
                crate::bounded::BoundedString::new();
            for _ in 0..MAX_KEYEXPR_CHUNKS {
                key.push_str("a/").expect("the buffer holds every chunk");
            }
            key.push_str(last).expect("the buffer holds the last chunk");
            key
        };
        let deep = deep_with("a");
        let deep_other = deep_with("b");
        let mut keys: crate::bounded::BoundedVec<&str, 64> = crate::bounded::BoundedVec::new();
        for &key in &corpus {
            keys.push(key).expect("the corpus fits");
        }
        keys.push(deep.as_str()).expect("two deep keys fit");
        keys.push(deep_other.as_str()).expect("two deep keys fit");
        for &candidate in keys.iter() {
            for &target in keys.iter() {
                let want = walk(candidate, target);
                assert_eq!(
                    keyexpr_intersects_text(candidate, target),
                    want,
                    "text: candidate {candidate:?} against target {target:?}"
                );
                if let Some(chunks) = KeyChunks::split(target) {
                    assert_eq!(
                        keyexpr_intersects_target(candidate, &chunks),
                        want,
                        "chunks: candidate {candidate:?} against target {target:?}"
                    );
                }
            }
        }
        // No chunks at all is not a key the split yields; the walk refuses the empty candidate
        // against it, and so must the scan.
        assert_eq!(
            keyexpr_intersects_target("", &[]),
            keyexpr_intersect_patterns(&KeyChunks::split("").expect("one chunk"), &[])
        );
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

    /// R2662 (open-debt item 763) — THE OTHER DIRECTION: a CONCRETE candidate
    /// against a WILDCARD target, which is what an inbound wildcard PUT is.
    ///
    /// The two tests above both put the wildcard on the CANDIDATE side, because
    /// that is the shape a subscription scan has: a registered `home/**` against
    /// a concrete published key. The delivery planes have the mirror problem — a
    /// subscriber registered on a CONCRETE keyexpr, and a sample arriving under
    /// `demo/*` — and nothing pinned it, which is why item 763 named "build the
    /// control FIRST" as a precondition of the migration rather than part of it.
    ///
    /// ⛔ THE CONTRAST IS THE POINT, so both matchers are asserted on the SAME
    /// inputs. `keyexpr_pattern_matches` treats its target as a literal, so it
    /// compares the pattern chunk `a` against the character sequence `*` and
    /// answers NO; intersection answers YES. Upstream's subscriber rule is
    /// intersection, so the NO is the defect five delivery sites still carry.
    #[cfg(feature = "keyexpr-wildcard-single")]
    #[test]
    fn intersects_target_when_the_target_itself_is_the_wildcard() {
        // A concrete subscriber keyexpr, a wildcard-addressed sample.
        assert!(keyexpr_intersects_target("demo/a", &["demo", "*"]));
        assert!(keyexpr_intersects_target("demo/a/b", &["demo", "*", "b"]));
        // ... and the one-sided matcher, on the SAME pair, says no. This is not
        // a bug in it: it is a MATCH predicate, and `demo/*` is not a literal
        // key. It is the wrong predicate for a target that may be a pattern.
        assert!(!keyexpr_pattern_matches(&["demo", "a"], "demo/*"));

        // NEGATIVE CONTROLS — the widening must not swallow disjoint keys.
        assert!(!keyexpr_intersects_target("other/a", &["demo", "*"]));
        assert!(!keyexpr_intersects_target("demo/a/b", &["demo", "*"]));
    }

    #[cfg(all(
        feature = "keyexpr-includes",
        feature = "keyexpr-wildcard-double",
        feature = "keyexpr-wildcard-single"
    ))]
    #[test]
    fn includes_target_is_directional_not_intersection() {
        // The ACL membership test: a rule keyexpr (superset) against a pre-split
        // message target. A `**` rule INCLUDES a deeper concrete message; a
        // disjoint anchor does not.
        assert!(keyexpr_includes_target("admin/**", &["admin", "secret"]));
        assert!(keyexpr_includes_target("admin/**", &["admin", "a", "b"]));
        assert!(!keyexpr_includes_target("metrics/**", &["admin", "secret"]));
        // A literal rule includes only its exact key.
        assert!(keyexpr_includes_target("admin/cfg", &["admin", "cfg"]));
        assert!(!keyexpr_includes_target("admin/cfg", &["admin", "other"]));
        // The DIVERGENCE from intersection (the bug a naive `_intersects_target`
        // reuse would have shipped): rule `home/*` does NOT INCLUDE a `home/**`
        // target (a single-chunk wildcard cannot cover arbitrarily-many chunks),
        // yet the two patterns DO intersect. An ACL must scan with inclusion, so
        // a `deny home/*` rule must not spuriously match a `home/**` declaration.
        assert!(!keyexpr_includes_target("home/*", &["home", "**"]));
        assert!(keyexpr_intersects_target("home/*", &["home", "**"]));
        // A malformed target is included by no rule (default-deny safe).
        assert!(!keyexpr_includes_target("admin/**", &["admin", ""]));
    }

    #[cfg(feature = "keyexpr-wildcard-double")]
    #[test]
    fn a_malformed_target_with_an_empty_chunk_matches_nothing() {
        // zenoh compute_data_route parity (linkstate_peer/pubsub.rs:948,957): a
        // published key with an empty `/`-delimited chunk is non-canonical and
        // must match NOTHING. Without the matcher guard each splits to leave a
        // trailing/leading/interior "" chunk that a `**` subscription's backtrack
        // absorbs (a spurious match -> forward AND local delivery). Covers all
        // four empty-chunk forms the prior `ends_with('/')` guard missed (it
        // caught only the first), across BOTH matcher entry points.
        let cases: [(&str, &[&str]); 4] = [
            ("home/temp/", &["home", "temp", ""]),
            ("home//temp", &["home", "", "temp"]),
            ("/home/temp", &["", "home", "temp"]),
            ("", &[""]),
        ];
        for (raw, chunks) in cases {
            assert!(
                !keyexpr_pattern_matches(&["home", "**"], raw),
                "pattern `home/**` must not match malformed `{raw}`"
            );
            assert!(
                !keyexpr_pattern_matches(&["**"], raw),
                "pattern `**` must not match malformed `{raw}`"
            );
            assert!(
                !keyexpr_intersects_target("home/**", chunks),
                "candidate `home/**` must not intersect malformed `{raw}`"
            );
            assert!(
                !keyexpr_intersects_target("**", chunks),
                "candidate `**` must not intersect malformed `{raw}`"
            );
        }
        // Control: the well-formed key DOES match, so the rejection is the empty
        // chunk, not an over-broad guard.
        assert!(keyexpr_pattern_matches(&["home", "**"], "home/temp"));
        assert!(keyexpr_intersects_target("home/**", &["home", "temp"]));
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

    // Fixed backing only (`alloc` off, or `bounded-heapless`): a target
    // deeper than MAX_KEYEXPR_CHUNKS is conservatively no-match. On the
    // growable backing the BoundedVec grows past the declared bound, so
    // this assertion is gated off it. Uses `**` so it requires the
    // double-wildcard toggle.
    #[cfg(all(
        any(not(feature = "alloc"), feature = "bounded-heapless"),
        feature = "keyexpr-wildcard-double"
    ))]
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

    #[cfg(all(
        feature = "alloc",
        not(feature = "bounded-heapless"),
        feature = "keyexpr-wildcard-double"
    ))]
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
    #[cfg(any(not(feature = "alloc"), feature = "bounded-heapless"))]
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

    #[cfg(all(feature = "alloc", not(feature = "bounded-heapless")))]
    #[test]
    fn intersects_target_candidate_over_depth_matches_on_alloc() {
        let deep = "a/a/a/a/a/a/a/a/a/a/a/a/a/a/a/a/a/a/a/a/a/a/a/a/a/a/a/a/a/a/a/a/a";
        assert_eq!(deep.split('/').count(), MAX_KEYEXPR_CHUNKS + 1);
        let target: [&str; MAX_KEYEXPR_CHUNKS + 1] = ["a"; MAX_KEYEXPR_CHUNKS + 1];
        // AP backing grows past the bound -> the deep candidate still matches.
        assert!(keyexpr_intersects_target(deep, &target));
    }
}
