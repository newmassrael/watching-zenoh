// SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! R221 — zenoh keyexpr canonicalization mirror.
//!
//! Mirrors the structural canonicalization performed by zenoh-pico's
//! `_z_keyexpr_canonize` (`vendor/zenoh-pico/src/session/keyexpr.c`
//! lines 313-433) so wz-side subscriber and queryable pattern
//! registrations agree byte-for-byte with the canonical wire form
//! a peer's `Declare(DeclKexpr)` emits. The canonical form is also
//! the form the inbound dispatch path matches against, so non-
//! canonical local registrations would silently miss legitimately
//! matching peer pushes.
//!
//! ## Scope (structural-only)
//!
//! `_z_keyexpr_canonize` is a three-pass structural transform —
//! there is no lowercase folding, no Unicode normalization, no NFC.
//! The grammar it enforces is byte-level:
//!
//! 1. **Singleify**: runs of `$*$*$*...` collapse to one `$*`
//!    ([`collapse_dsl_runs`]).
//! 2. **Chunk-level canon**: per-chunk validation + rewriting:
//!    - lone `$*` chunk → `*` chunk
//!    - `*` after `**` → drop the `*` (the `**` already covers it)
//!    - `**` after `**` → drop the duplicate
//!    - `**$*` and similar mixed shapes are rejected by the per-
//!      char state machine ([`analyze_chunk`])
//! 3. **Per-char validation** rejects `#`, `?`, unbound `$`, bare
//!    `*` mid-chunk, `$$`, `$**`, and similar grammar violations.
//!
//! ## Why mirror this
//!
//! zenoh-pico canonicalizes both at `z_keyexpr_from_substr` time
//! (user-supplied registration string) and again at encode time
//! (before going on the wire). wz currently skips canonicalization
//! on local registrations, so a user passing `home/$*` to
//! `SubscriberRegistry::register` would store `["home", "$*"]` as
//! pattern chunks. The R220 chunk matcher handles `$*`-as-a-chunk
//! by treating it equivalently to `*`, so behavior is correct, but
//! the stored form drifts from what zenoh-pico would produce for
//! the same registration. R221 closes that drift.
//!
//! ## Non-breaking integration
//!
//! [`canonize_keyexpr`] returns `Result<String, KeyexprCanonError>`
//! so callers can decide whether to reject invalid patterns or
//! fall back to raw. The current registry call sites
//! ([`crate::pubsub::SubscriberRegistry::register`] and
//! [`crate::query::QueryableRegistry::register`]) wrap with
//! `canonize_keyexpr(...).unwrap_or_else(|_| pattern.to_string())`
//! — canon success replaces the stored chunks with the canonical
//! form, canon failure stores the raw pattern unchanged. Tightening
//! to `Result`-returning `register` is a future round (R222 cluster
//! API rewrite).

use core::fmt;

use crate::bounded::{BoundedString, BoundedVec};
use crate::caps::MAX_KEYEXPR_BYTES;
use crate::keyexpr_match::MAX_KEYEXPR_CHUNKS;

/// Errors produced by [`canonize_keyexpr`] when the input violates
/// the structural keyexpr grammar that zenoh-pico's
/// `_z_keyexpr_canonize` enforces.
///
/// The variant names mirror zenoh-pico's `zp_keyexpr_canon_status_t`
/// values (`Z_KEYEXPR_CANON_*`) so cross-referencing the C
/// implementation stays mechanical.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KeyexprCanonError {
    /// A `/`-delimited segment was empty (`home//temp`, leading
    /// `/`, or trailing `/`). zenoh-pico:
    /// `Z_KEYEXPR_CANON_EMPTY_CHUNK`.
    EmptyChunk,
    /// A chunk contained `#` or `?`, both of which are reserved
    /// outside the keyexpr grammar. zenoh-pico:
    /// `Z_KEYEXPR_CANON_CONTAINS_SHARP_OR_QMARK`.
    ContainsSharpOrQmark,
    /// Two consecutive `$` (e.g. `$$`) or `$` immediately after a
    /// completed `$*` (e.g. `$*$`) — the second `$` is unbound.
    /// zenoh-pico: `Z_KEYEXPR_CANON_DOLLAR_AFTER_DOLLAR_OR_STAR`.
    DollarAfterDollarOrStar,
    /// A bare `*` appeared mid-chunk (not as a single-chunk wild
    /// `*`, not as part of a super-wild `**`, not preceded by the
    /// `$` of `$*`). zenoh-pico: `Z_KEYEXPR_CANON_STARS_IN_CHUNK`.
    StarsInChunk,
    /// A `$` appeared without a following `*` (e.g. `foo$`,
    /// `foo$bar`). zenoh-pico:
    /// `Z_KEYEXPR_CANON_CONTAINS_UNBOUND_DOLLAR`.
    ContainsUnboundDollar,
    /// R311gb (Track 2) — the canonical form would exceed the
    /// no-alloc output buffer: more than [`MAX_KEYEXPR_BYTES`] bytes
    /// or more than [`MAX_KEYEXPR_CHUNKS`] `/`-separated chunks. This
    /// variant has **no zenoh-pico mirror** (it is a wz-side bounded-
    /// backing concern, not a grammar status); it is only ever
    /// returned on the no-alloc (MCU) backing — the `alloc` (AP)
    /// backing grows its buffer and never produces it. Fail-fast per
    /// the [`crate::bounded`] contract: no silent truncation.
    ExceedsCapacity,
}

impl fmt::Display for KeyexprCanonError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmptyChunk => f.write_str("keyexpr canon: empty `/`-delimited chunk"),
            Self::ContainsSharpOrQmark => {
                f.write_str("keyexpr canon: chunk contains reserved `#` or `?`")
            }
            Self::DollarAfterDollarOrStar => {
                f.write_str("keyexpr canon: `$` after `$` or completed `$*`")
            }
            Self::StarsInChunk => {
                f.write_str("keyexpr canon: bare `*` mid-chunk (must be `$*`, `*`, or `**`)")
            }
            Self::ContainsUnboundDollar => f.write_str("keyexpr canon: `$` not followed by `*`"),
            Self::ExceedsCapacity => f.write_str(
                "keyexpr canon: canonical form exceeds the deploy-declared capacity \
                 (MAX_KEYEXPR_BYTES / MAX_KEYEXPR_CHUNKS)",
            ),
        }
    }
}

impl core::error::Error for KeyexprCanonError {}

/// Internal classification of one chunk's structural shape after
/// per-character validation. Drives the chunk-level rewriting
/// decisions ("lone `$*` → `*`", "drop `*` after `**`", etc.).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ChunkShape {
    /// Exactly `*`. Matches one chunk (when not immediately after a
    /// super-wild).
    SingleStar,
    /// Exactly `**`. Super-wild — matches zero or more chunks.
    DoubleStar,
    /// Exactly `$*`. Canonicalizes to `*`.
    LoneDollarStar,
    /// Chunk contains literal bytes possibly interleaved with one
    /// or more `$*` DSL tokens. Stored verbatim after validation.
    Mixed,
}

/// Canonicalize a zenoh keyexpr.
///
/// Returns the canonical byte-equivalent form on success, or a
/// [`KeyexprCanonError`] if the input violates the structural
/// grammar.
///
/// The output is a fresh [`BoundedString`] even when the input was
/// already canonical — callers that want to skip re-storing on the
/// already-canonical hot path can wrap with an equality check
/// (`canonize_keyexpr(s)? == s`). The two-pass implementation uses one
/// intermediate [`BoundedString`] for the `$*` run-collapse step and
/// one [`BoundedVec`] of chunk slices for the chunk walk; since canon
/// only ever shrinks or preserves length (collapsing runs, dropping
/// redundant `*`/`**` chunks), the output is bounded by the input
/// size. On the no-alloc backing an input longer than
/// [`MAX_KEYEXPR_BYTES`] (or deeper than [`MAX_KEYEXPR_CHUNKS`])
/// surfaces as [`KeyexprCanonError::ExceedsCapacity`].
///
/// # Examples
///
/// ```
/// use wz_session_core::keyexpr_canon::canonize_keyexpr;
///
/// // Already-canonical input is returned unchanged.
/// assert_eq!(canonize_keyexpr("home/temp").unwrap(), "home/temp");
///
/// // Lone `$*` chunk canonicalizes to `*`.
/// assert_eq!(canonize_keyexpr("home/$*/temp").unwrap(), "home/*/temp");
///
/// // `$*$*$*` runs collapse to single `$*`.
/// assert_eq!(canonize_keyexpr("home/$*$*$*foo").unwrap(), "home/$*foo");
///
/// // `*` after `**` is absorbed.
/// assert_eq!(canonize_keyexpr("home/**/*/temp").unwrap(), "home/**/temp");
///
/// // Invalid grammar returns a typed error.
/// assert!(canonize_keyexpr("home/foo?bar").is_err());
/// ```
pub fn canonize_keyexpr(
    input: &str,
) -> Result<BoundedString<MAX_KEYEXPR_BYTES>, KeyexprCanonError> {
    let collapsed = collapse_dsl_runs(input)?;
    canonize_chunks(&collapsed)
}

/// Collapse runs of consecutive `$*` tokens into a single `$*`.
///
/// Mirrors zenoh-pico's `__zp_singleify(start, len, "$*")`
/// (`vendor/zenoh-pico/src/session/keyexpr.c` lines 220-259). The
/// transform is purely substring-level — it does not understand
/// chunk boundaries — so a chunk like `$*$*$*foo` collapses to
/// `$*foo` and `pre$*$*post` collapses to `pre$*post`. The
/// transform is idempotent; running it twice yields the same
/// result as once.
fn collapse_dsl_runs(input: &str) -> Result<BoundedString<MAX_KEYEXPR_BYTES>, KeyexprCanonError> {
    const DSL: &str = "$*";
    let mut out = BoundedString::new();
    let mut cursor = 0;
    while cursor < input.len() {
        let rest = &input[cursor..];
        if rest.starts_with(DSL) {
            out.push_str(DSL)
                .map_err(|_| KeyexprCanonError::ExceedsCapacity)?;
            cursor += DSL.len();
            while input[cursor..].starts_with(DSL) {
                cursor += DSL.len();
            }
        } else {
            let next_char = rest.chars().next().expect("non-empty remainder");
            out.push(next_char)
                .map_err(|_| KeyexprCanonError::ExceedsCapacity)?;
            cursor += next_char.len_utf8();
        }
    }
    Ok(out)
}

/// Walk `/`-separated chunks, validating each via
/// [`analyze_chunk`] and applying the chunk-level canon rules
/// (`$*` → `*`, drop `*` / `**` after `**`).
fn canonize_chunks(input: &str) -> Result<BoundedString<MAX_KEYEXPR_BYTES>, KeyexprCanonError> {
    let mut out_chunks: BoundedVec<&str, MAX_KEYEXPR_CHUNKS> = BoundedVec::new();
    let mut prev_was_double_star = false;

    for chunk in input.split('/') {
        let shape = analyze_chunk(chunk)?;
        let keep: Option<&str> = match shape {
            ChunkShape::SingleStar => {
                let k = (!prev_was_double_star).then_some("*");
                prev_was_double_star = false;
                k
            }
            ChunkShape::DoubleStar => {
                let k = (!prev_was_double_star).then_some("**");
                prev_was_double_star = true;
                k
            }
            ChunkShape::LoneDollarStar => {
                let k = (!prev_was_double_star).then_some("*");
                prev_was_double_star = false;
                k
            }
            ChunkShape::Mixed => {
                prev_was_double_star = false;
                Some(chunk)
            }
        };
        if let Some(c) = keep {
            out_chunks
                .push(c)
                .map_err(|_| KeyexprCanonError::ExceedsCapacity)?;
        }
    }

    // Join by '/' into a fresh bounded buffer (replaces `Vec::join`).
    let mut out = BoundedString::new();
    for (i, c) in out_chunks.iter().enumerate() {
        if i > 0 {
            out.push('/')
                .map_err(|_| KeyexprCanonError::ExceedsCapacity)?;
        }
        out.push_str(c)
            .map_err(|_| KeyexprCanonError::ExceedsCapacity)?;
    }
    Ok(out)
}

/// Per-chunk validation + shape classification.
///
/// Mirrors zenoh-pico's per-chunk state machine in
/// `__zp_canon_prefix` (`vendor/zenoh-pico/src/session/keyexpr.c`
/// lines 113-218). The state values match zenoh-pico's `in_dollar`
/// encoding (0 = normal, 1 = after `$`, 3 = after `$*`); the
/// non-contiguous 2-skip keeps the cross-reference mechanical
/// instead of having to mentally re-encode states.
fn analyze_chunk(chunk: &str) -> Result<ChunkShape, KeyexprCanonError> {
    if chunk.is_empty() {
        return Err(KeyexprCanonError::EmptyChunk);
    }
    match chunk {
        "*" => return Ok(ChunkShape::SingleStar),
        "**" => return Ok(ChunkShape::DoubleStar),
        "$*" => return Ok(ChunkShape::LoneDollarStar),
        _ => {}
    }
    let mut state: u8 = 0;
    for &b in chunk.as_bytes() {
        match b {
            b'#' | b'?' => return Err(KeyexprCanonError::ContainsSharpOrQmark),
            b'$' => {
                if state != 0 {
                    return Err(KeyexprCanonError::DollarAfterDollarOrStar);
                }
                state = 1;
            }
            b'*' => {
                if state != 1 {
                    return Err(KeyexprCanonError::StarsInChunk);
                }
                state = 3;
            }
            _ => {
                if state == 1 {
                    return Err(KeyexprCanonError::ContainsUnboundDollar);
                }
                state = 0;
            }
        }
    }
    if state == 1 {
        return Err(KeyexprCanonError::ContainsUnboundDollar);
    }
    Ok(ChunkShape::Mixed)
}

// ──────────────────────────────────────────────────────────────────
// R300 — outbound-side gate guarding zenoh-pico bug #3 (SIGABRT)
//
// R311gb (Track 2) — this whole section stays `alloc`-gated: it guards
// the outbound DECLARE *wire emit* path (consumed by the AP-only
// `session_glue` send-declare builders), which is AP-retention per the
// Track 2 borrow boundary. Only the inbound canon core above is
// no-alloc.
// ──────────────────────────────────────────────────────────────────

#[cfg(feature = "alloc")]
use alloc::string::{String, ToString};

/// Errors returned by [`check_outbound_keyexpr_pico_safe`] when an
/// outbound DECLARE-side keyexpr (after mapping-table reconstruction)
/// would either fail the structural canon or trip a known buggy
/// zenoh-pico canon path on the receive side.
///
/// ## Scope
///
/// This error type sits one layer above [`KeyexprCanonError`]:
///
/// * [`KeyexprCanonError`] is the faithful mirror of zenoh-pico's
///   `zp_keyexpr_canon_status_t` — "what does pico's canon reject".
/// * [`OutboundKeyexprError`] adds a wz-side defensive variant
///   ([`OutboundKeyexprError::PicoBugThreeFamily`]) that detects
///   keyexpr shapes pico's canon ACCEPTS structurally but then
///   CRASHES on at canonical rewrite time (R299 fixture documented
///   bug #3 — `vendor/zenoh-pico/src/session/keyexpr.c:340`
///   `assert(false)` SIGABRT).
///
/// The gate is NARROW (R300 scope): only the SIGABRT-prone shape
/// (`** chunk` + literal chunk(s) + `*`-shape chunk) is rejected.
/// The wire-interop-drift shapes (R299 bug #1 / bug #2 — wrong
/// output but no crash) remain allowed; rejecting those is the
/// architectural carry [R299 #3] that requires a separate decision
/// round.
///
/// ## Where the SIGABRT comes from
///
/// pico's `__zp_canon_prefix` case-1 branch (single-byte chunk that
/// is NOT `*` while `in_big_wild = true`) takes the
/// `else { advance; continue; }` path which SKIPS the post-walk
/// `in_big_wild = false` reset. A subsequent `*`-shape chunk then
/// re-enters case-1 with stale `in_big_wild` and returns
/// `SINGLE_STAR_AFTER_DOUBLE_STAR` with `*len` pointing at the `/`
/// between the literal and the `*`. Main canonize then fails the
/// `chunk_end - reader == 2` precondition and triggers
/// `assert(false)`, aborting the receiving process via SIGABRT.
///
/// Empirically (R299 fixture
/// `canon_known_pico_anomaly_double_star_literal_star_aborts`) the
/// trigger fires on multi-char literals as well (`**/foo/*`,
/// `**/abc/*/def`), not only the documented single-char case. The
/// gate consequently treats ANY non-`*`-shape chunk after `**` as a
/// bug-window opener.
#[cfg(feature = "alloc")]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OutboundKeyexprError {
    /// Input failed the structural keyexpr grammar (empty chunk,
    /// reserved character, unbound `$`, bare `*` mid-chunk, …). The
    /// inner [`KeyexprCanonError`] carries the specific
    /// pico-`zp_keyexpr_canon_status_t` mirror code.
    NotCanonical(KeyexprCanonError),
    /// Input would crash zenoh-pico's `_z_keyexpr_canonize` on the
    /// receive side via SIGABRT (R299 bug #3 family). The shape is
    /// `** chunk` followed by at least one non-`*`-shape chunk
    /// followed by a `*`-shape chunk (single `*`, `**`, or any
    /// `$*`-only run that canonizes to `*`).
    PicoBugThreeFamily {
        /// The full input keyexpr (post mapping-table
        /// reconstruction), preserved verbatim for diagnostics.
        keyexpr: String,
        /// The trailing `*`-shape chunk that closed the bug window.
        offending_chunk: String,
    },
}

#[cfg(feature = "alloc")]
impl fmt::Display for OutboundKeyexprError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotCanonical(inner) => {
                write!(f, "outbound keyexpr non-canonical: {inner}")
            }
            Self::PicoBugThreeFamily {
                keyexpr,
                offending_chunk,
            } => write!(
                f,
                "outbound keyexpr `{keyexpr}` would crash zenoh-pico via \
                 SIGABRT (R299 bug #3 — `**` chunk followed by literal \
                 then `*`-shape chunk `{offending_chunk}`)"
            ),
        }
    }
}

#[cfg(feature = "alloc")]
impl core::error::Error for OutboundKeyexprError {
    fn source(&self) -> Option<&(dyn core::error::Error + 'static)> {
        match self {
            Self::NotCanonical(inner) => Some(inner),
            Self::PicoBugThreeFamily { .. } => None,
        }
    }
}

/// Check whether an outbound DECLARE-side keyexpr is safe to send to
/// a zenoh-pico peer.
///
/// Returns `Ok(())` when the input is both structurally canonical
/// (per [`canonize_keyexpr`]) and outside the R299-documented
/// SIGABRT pattern family. Returns
/// [`OutboundKeyexprError::NotCanonical`] when the input violates
/// the keyexpr grammar, and
/// [`OutboundKeyexprError::PicoBugThreeFamily`] when the input would
/// trigger the receive-side `assert(false)` at
/// `vendor/zenoh-pico/src/session/keyexpr.c:340`.
///
/// The input is expected to be the FULL reconstructed keyexpr — the
/// caller (e.g. `crate::session_glue::SessionLinkActions` outbound
/// DECLARE paths) must resolve `(mapping_id, suffix)` to a literal
/// before invoking this check; otherwise a cross-boundary bug #3
/// pattern (prefix=`"**"` + suffix=`"/c/*"`) slips through.
///
/// # Examples
///
/// ```
/// use wz_session_core::keyexpr_canon::{
///     check_outbound_keyexpr_pico_safe, OutboundKeyexprError,
/// };
///
/// // Safe — no `**` chunk.
/// assert!(check_outbound_keyexpr_pico_safe("home/temp").is_ok());
///
/// // Safe — `**` directly followed by `*` (R299 bug #1, no crash;
/// // wire-interop drift deferred to architectural carry R299 #3).
/// assert!(check_outbound_keyexpr_pico_safe("**/*").is_ok());
///
/// // Reject — `**` + literal + `*` (R299 bug #3, SIGABRT on pico).
/// assert!(matches!(
///     check_outbound_keyexpr_pico_safe("**/c/*"),
///     Err(OutboundKeyexprError::PicoBugThreeFamily { .. }),
/// ));
/// ```
#[cfg(feature = "alloc")]
pub fn check_outbound_keyexpr_pico_safe(input: &str) -> Result<(), OutboundKeyexprError> {
    // Structural canon (empty chunks, reserved chars, unbound `$`,
    // bare `*` mid-chunk, …). We discard the canonized output and
    // only consume its pass/fail signal: the wire emit path uses the
    // raw suffix verbatim (R300 NARROW scope; pre-emit canonization
    // is the R299 carry #3 architectural decision).
    canonize_keyexpr(input).map_err(OutboundKeyexprError::NotCanonical)?;

    // Bug #3 family walk. State machine:
    // * seen_double_star — set true after any `**` chunk has been
    //   observed.
    // * seen_literal_after_double_star — set true after a non-`**`,
    //   non-`*`-shape chunk has been observed since the most recent
    //   `**` chunk. Reset on every fresh `**` chunk.
    // Reject fires when both flags are set and the current chunk is
    // `*`-shape. This is exactly the R299 bug #3 trigger condition
    // (`__zp_canon_prefix` case-1 stale `in_big_wild`).
    let mut seen_double_star = false;
    let mut seen_literal_after_double_star = false;
    for chunk in input.split('/') {
        let is_star_shape = chunk_canonizes_to_star_shape(chunk);
        if seen_double_star && seen_literal_after_double_star && is_star_shape {
            return Err(OutboundKeyexprError::PicoBugThreeFamily {
                keyexpr: input.to_string(),
                offending_chunk: chunk.to_string(),
            });
        }
        if chunk == "**" {
            seen_double_star = true;
            seen_literal_after_double_star = false;
        } else if seen_double_star && !is_star_shape {
            seen_literal_after_double_star = true;
        }
    }
    Ok(())
}

/// True iff the raw chunk's canonical form is `*` — i.e. an exact
/// `*` / `**` chunk, or a `$*`-run-only chunk that the singleify +
/// lone-`$*` lift in [`canonize_keyexpr`] collapses to `*`.
/// Mixed chunks (literal + `$*` + literal) canonize verbatim and do
/// not trigger pico's case-1 `in_big_wild` confusion, so they are
/// excluded.
///
/// Distinct from [`analyze_chunk`]'s `ChunkShape::LoneDollarStar`
/// because this helper walks the RAW (pre-singleify) chunk — the
/// caller of [`check_outbound_keyexpr_pico_safe`] does not run
/// `collapse_dsl_runs` first; doing so would have to handle chunk
/// boundary effects (`$*$*` straddling `/` is not a single chunk).
#[cfg(feature = "alloc")]
fn chunk_canonizes_to_star_shape(chunk: &str) -> bool {
    if chunk == "*" || chunk == "**" {
        return true;
    }
    if chunk.is_empty() {
        return false;
    }
    let mut rest = chunk;
    while let Some(after) = rest.strip_prefix("$*") {
        rest = after;
    }
    rest.is_empty()
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── Identity (already-canonical input passes through) ──

    #[test]
    fn canon_identity_on_pure_literal() {
        assert_eq!(canonize_keyexpr("home/temp").unwrap(), "home/temp");
        assert_eq!(
            canonize_keyexpr("sensors/room1/temp").unwrap(),
            "sensors/room1/temp"
        );
    }

    #[test]
    fn canon_identity_on_canonical_wildcards() {
        assert_eq!(canonize_keyexpr("home/*/temp").unwrap(), "home/*/temp");
        assert_eq!(canonize_keyexpr("home/**").unwrap(), "home/**");
        assert_eq!(canonize_keyexpr("**/temp").unwrap(), "**/temp");
        assert_eq!(canonize_keyexpr("home/**/temp").unwrap(), "home/**/temp");
        assert_eq!(canonize_keyexpr("home/$*foo$*").unwrap(), "home/$*foo$*");
    }

    // ── Singleify ($*$* run collapse) ──

    #[test]
    fn canon_singleify_collapses_dsl_runs() {
        assert_eq!(canonize_keyexpr("home/$*$*$*foo").unwrap(), "home/$*foo");
        assert_eq!(
            canonize_keyexpr("home/foo$*$*bar").unwrap(),
            "home/foo$*bar"
        );
        assert_eq!(canonize_keyexpr("home/$*$*").unwrap(), "home/*");
    }

    // ── Lone $* chunk → * chunk ──

    #[test]
    fn canon_lone_dollar_star_chunk_becomes_single_star() {
        assert_eq!(canonize_keyexpr("home/$*/temp").unwrap(), "home/*/temp");
        assert_eq!(canonize_keyexpr("$*").unwrap(), "*");
        assert_eq!(canonize_keyexpr("$*/temp").unwrap(), "*/temp");
    }

    // ── Star-after-double-star drop ──

    #[test]
    fn canon_drops_single_star_after_double_star() {
        assert_eq!(canonize_keyexpr("home/**/*/temp").unwrap(), "home/**/temp");
        assert_eq!(canonize_keyexpr("**/*").unwrap(), "**");
        assert_eq!(canonize_keyexpr("**/$*/temp").unwrap(), "**/temp");
    }

    #[test]
    fn canon_drops_double_star_after_double_star() {
        assert_eq!(canonize_keyexpr("home/**/**/temp").unwrap(), "home/**/temp");
        assert_eq!(canonize_keyexpr("**/**").unwrap(), "**");
        assert_eq!(canonize_keyexpr("**/**/**").unwrap(), "**");
    }

    // ── Mixed canon (singleify + chunk rules combined) ──

    #[test]
    fn canon_combines_singleify_and_chunk_rules() {
        assert_eq!(canonize_keyexpr("**/$*$*/temp").unwrap(), "**/temp");
        assert_eq!(
            canonize_keyexpr("home/$*$*/$*/temp").unwrap(),
            "home/*/*/temp"
        );
    }

    // ── Error: structural grammar violations ──

    #[test]
    fn canon_rejects_empty_chunk() {
        assert_eq!(
            canonize_keyexpr("home//temp"),
            Err(KeyexprCanonError::EmptyChunk)
        );
        assert_eq!(
            canonize_keyexpr("/home"),
            Err(KeyexprCanonError::EmptyChunk)
        );
        assert_eq!(
            canonize_keyexpr("home/"),
            Err(KeyexprCanonError::EmptyChunk)
        );
        assert_eq!(canonize_keyexpr(""), Err(KeyexprCanonError::EmptyChunk));
    }

    #[test]
    fn canon_rejects_sharp_or_qmark() {
        assert_eq!(
            canonize_keyexpr("home/foo#bar"),
            Err(KeyexprCanonError::ContainsSharpOrQmark)
        );
        assert_eq!(
            canonize_keyexpr("home/foo?bar"),
            Err(KeyexprCanonError::ContainsSharpOrQmark)
        );
    }

    #[test]
    fn canon_rejects_unbound_dollar() {
        assert_eq!(
            canonize_keyexpr("home/foo$"),
            Err(KeyexprCanonError::ContainsUnboundDollar)
        );
        assert_eq!(
            canonize_keyexpr("home/foo$bar"),
            Err(KeyexprCanonError::ContainsUnboundDollar)
        );
    }

    #[test]
    fn canon_rejects_bare_star_mid_chunk() {
        // `foo*bar` is invalid — `*` must be standalone or paired
        // with `$`.
        assert_eq!(
            canonize_keyexpr("home/foo*bar"),
            Err(KeyexprCanonError::StarsInChunk)
        );
        // `***` is invalid — the third star is unpaired.
        assert_eq!(
            canonize_keyexpr("home/***"),
            Err(KeyexprCanonError::StarsInChunk)
        );
    }

    #[test]
    fn canon_rejects_dollar_after_dollar_or_star() {
        // `$$` is two consecutive dollars; the second is unbound.
        assert_eq!(
            canonize_keyexpr("home/$$"),
            Err(KeyexprCanonError::DollarAfterDollarOrStar)
        );
        // `$*$` — after the completed `$*` (state=3) a new `$`
        // arrives while still in non-zero state.
        assert_eq!(
            canonize_keyexpr("home/foo$*$"),
            Err(KeyexprCanonError::DollarAfterDollarOrStar)
        );
    }

    // ── analyze_chunk shape classification (internal) ──

    #[test]
    fn analyze_chunk_classifies_canonical_shapes() {
        assert_eq!(analyze_chunk("*").unwrap(), ChunkShape::SingleStar);
        assert_eq!(analyze_chunk("**").unwrap(), ChunkShape::DoubleStar);
        assert_eq!(analyze_chunk("$*").unwrap(), ChunkShape::LoneDollarStar);
        assert_eq!(analyze_chunk("foo").unwrap(), ChunkShape::Mixed);
        assert_eq!(analyze_chunk("pre$*suf").unwrap(), ChunkShape::Mixed);
    }

    #[test]
    fn collapse_dsl_runs_idempotent_on_canonical_input() {
        let canonical = "home/foo$*bar";
        let once = collapse_dsl_runs(canonical).unwrap();
        assert_eq!(once, canonical);
        let twice = collapse_dsl_runs(once.as_str()).unwrap();
        assert_eq!(twice, canonical);
    }

    // ── R300 — check_outbound_keyexpr_pico_safe ────────────────

    #[cfg(feature = "alloc")]
    #[test]
    fn outbound_safe_for_canonical_literal_keyexpr() {
        assert!(check_outbound_keyexpr_pico_safe("home/temp").is_ok());
        assert!(check_outbound_keyexpr_pico_safe("a/b/c").is_ok());
        assert!(check_outbound_keyexpr_pico_safe("liveliness/devA").is_ok());
    }

    #[cfg(feature = "alloc")]
    #[test]
    fn outbound_safe_for_canonical_wildcard_keyexpr() {
        assert!(check_outbound_keyexpr_pico_safe("home/*/temp").is_ok());
        assert!(check_outbound_keyexpr_pico_safe("**/temp").is_ok());
        assert!(check_outbound_keyexpr_pico_safe("home/**").is_ok());
        assert!(check_outbound_keyexpr_pico_safe("home/**/temp").is_ok());
    }

    #[cfg(feature = "alloc")]
    #[test]
    fn outbound_safe_for_bug_one_family_immediate_star_after_double_star() {
        // R299 bug #1 patterns — pico canon produces wrong output
        // (`*/**` etc.) but does NOT SIGABRT. R300 NARROW scope
        // allows these; wire-interop drift is the R299 carry #3
        // architectural decision.
        assert!(check_outbound_keyexpr_pico_safe("**/*").is_ok());
        assert!(check_outbound_keyexpr_pico_safe("home/**/*/temp").is_ok());
        assert!(check_outbound_keyexpr_pico_safe("**/$*/temp").is_ok());
        assert!(check_outbound_keyexpr_pico_safe("**/$*").is_ok());
        assert!(check_outbound_keyexpr_pico_safe("**/**").is_ok());
    }

    #[cfg(feature = "alloc")]
    #[test]
    fn outbound_rejects_bug_three_family_double_star_literal_star() {
        // R299 bug #3 — `**` + literal chunk + `*`-shape chunk. Pico
        // SIGABRTs on receive canonize; R300 reject pre-emit.
        let cases = [
            ("**/c/*", "*"),
            ("**/foo/*", "*"),
            ("**/abc/*/def", "*"),
            ("**/a/b/*", "*"),
        ];
        for (input, expected_offending) in cases {
            match check_outbound_keyexpr_pico_safe(input) {
                Err(OutboundKeyexprError::PicoBugThreeFamily {
                    keyexpr,
                    offending_chunk,
                }) => {
                    assert_eq!(keyexpr, input, "keyexpr field mismatch for `{}`", input);
                    assert_eq!(
                        offending_chunk, expected_offending,
                        "offending_chunk mismatch for `{}`",
                        input,
                    );
                }
                other => panic!(
                    "expected PicoBugThreeFamily for `{}`, got {:?}",
                    input, other
                ),
            }
        }
    }

    #[cfg(feature = "alloc")]
    #[test]
    fn outbound_rejects_bug_three_family_with_dsl_or_double_star_trailing() {
        // Bug #3 also fires when the trailing star-shape chunk is
        // `**` or a `$*`-only chunk (canonizes to `*`). Same case-1
        // trigger on pico's side.
        assert!(matches!(
            check_outbound_keyexpr_pico_safe("**/c/**"),
            Err(OutboundKeyexprError::PicoBugThreeFamily { .. }),
        ));
        assert!(matches!(
            check_outbound_keyexpr_pico_safe("**/c/$*"),
            Err(OutboundKeyexprError::PicoBugThreeFamily { .. }),
        ));
        assert!(matches!(
            check_outbound_keyexpr_pico_safe("**/c/$*$*"),
            Err(OutboundKeyexprError::PicoBugThreeFamily { .. }),
        ));
    }

    #[cfg(feature = "alloc")]
    #[test]
    fn outbound_rejects_structurally_invalid_keyexpr() {
        // Grammar violations pass through to NotCanonical. The
        // inner KeyexprCanonError variant mirrors pico's
        // zp_keyexpr_canon_status_t.
        assert_eq!(
            check_outbound_keyexpr_pico_safe("home//temp"),
            Err(OutboundKeyexprError::NotCanonical(
                KeyexprCanonError::EmptyChunk,
            )),
        );
        assert_eq!(
            check_outbound_keyexpr_pico_safe("home/foo?bar"),
            Err(OutboundKeyexprError::NotCanonical(
                KeyexprCanonError::ContainsSharpOrQmark,
            )),
        );
        assert_eq!(
            check_outbound_keyexpr_pico_safe("home/foo$"),
            Err(OutboundKeyexprError::NotCanonical(
                KeyexprCanonError::ContainsUnboundDollar,
            )),
        );
    }

    #[cfg(feature = "alloc")]
    #[test]
    fn outbound_mixed_chunk_after_double_star_opens_bug_window() {
        // A Mixed chunk (literal + `$*` + literal) is NOT star-shape
        // so it functions as a literal in the bug #3 walk — it CAN
        // open the literal-after-`**` window but does not itself
        // trigger reject. Reject only fires on a SUBSEQUENT
        // star-shape chunk.
        assert!(check_outbound_keyexpr_pico_safe("**/foo$*bar").is_ok());
        assert!(check_outbound_keyexpr_pico_safe("**/foo$*bar/temp").is_ok());
        assert!(matches!(
            check_outbound_keyexpr_pico_safe("**/foo$*bar/*"),
            Err(OutboundKeyexprError::PicoBugThreeFamily { .. }),
        ));
    }

    #[cfg(feature = "alloc")]
    #[test]
    fn outbound_conservatively_rejects_double_star_after_literal_segment() {
        // R300 NARROW gate is CONSERVATIVE on the trailing star-
        // shape: any *-shape chunk (single `*`, `**`, or `$*`-only)
        // appearing after a `**` segment with at least one non-`*`-
        // shape chunk between, is rejected. R299 fixture empirically
        // pins SIGABRT only for trailing single `*` (trailing `**`
        // / `$*` cannot be cross-validated against pico without
        // SIGABRT-aborting the test binary), but the underlying
        // `in_big_wild` stale-state mechanism does not distinguish
        // the closer's exact star-shape. Conservative reject keeps
        // wz unconditionally safe on send; narrowing this false-
        // positive zone (semantically `**/a/**`-style inputs ARE
        // valid zenoh-keyexpr — "a appears somewhere") is a future
        // round, pending an empirical fork-based pico abort probe.
        assert!(matches!(
            check_outbound_keyexpr_pico_safe("**/a/**"),
            Err(OutboundKeyexprError::PicoBugThreeFamily { .. }),
        ));
        assert!(matches!(
            check_outbound_keyexpr_pico_safe("**/a/**/b"),
            Err(OutboundKeyexprError::PicoBugThreeFamily { .. }),
        ));
        assert!(matches!(
            check_outbound_keyexpr_pico_safe("**/a/**/b/*"),
            Err(OutboundKeyexprError::PicoBugThreeFamily { .. }),
        ));
    }

    #[cfg(feature = "alloc")]
    #[test]
    fn chunk_canonizes_to_star_shape_classification() {
        assert!(chunk_canonizes_to_star_shape("*"));
        assert!(chunk_canonizes_to_star_shape("**"));
        assert!(chunk_canonizes_to_star_shape("$*"));
        assert!(chunk_canonizes_to_star_shape("$*$*"));
        assert!(chunk_canonizes_to_star_shape("$*$*$*"));
        assert!(!chunk_canonizes_to_star_shape("foo"));
        assert!(!chunk_canonizes_to_star_shape("$*foo"));
        assert!(!chunk_canonizes_to_star_shape("foo$*"));
        assert!(!chunk_canonizes_to_star_shape("foo$*bar"));
        assert!(!chunk_canonizes_to_star_shape(""));
    }
}
