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

use std::fmt;

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
            Self::ContainsUnboundDollar => {
                f.write_str("keyexpr canon: `$` not followed by `*`")
            }
        }
    }
}

impl std::error::Error for KeyexprCanonError {}

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
/// The output is a fresh `String` even when the input was already
/// canonical — callers that want zero-allocation on the
/// already-canonical hot path can wrap with an equality check
/// (`canonize_keyexpr(s)? == s`). The two-pass implementation
/// allocates one intermediate `String` for the `$*` run-collapse
/// step and one `Vec<String>` for the chunk walk, both bounded
/// by the input size.
///
/// # Examples
///
/// ```
/// use wz_runtime_tokio::keyexpr_canon::canonize_keyexpr;
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
pub fn canonize_keyexpr(input: &str) -> Result<String, KeyexprCanonError> {
    let collapsed = collapse_dsl_runs(input);
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
fn collapse_dsl_runs(input: &str) -> String {
    const DSL: &str = "$*";
    let mut out = String::with_capacity(input.len());
    let mut cursor = 0;
    while cursor < input.len() {
        let rest = &input[cursor..];
        if rest.starts_with(DSL) {
            out.push_str(DSL);
            cursor += DSL.len();
            while input[cursor..].starts_with(DSL) {
                cursor += DSL.len();
            }
        } else {
            let next_char = rest.chars().next().expect("non-empty remainder");
            out.push(next_char);
            cursor += next_char.len_utf8();
        }
    }
    out
}

/// Walk `/`-separated chunks, validating each via
/// [`analyze_chunk`] and applying the chunk-level canon rules
/// (`$*` → `*`, drop `*` / `**` after `**`).
fn canonize_chunks(input: &str) -> Result<String, KeyexprCanonError> {
    let chunks: Vec<&str> = input.split('/').collect();
    let mut out_chunks: Vec<&str> = Vec::with_capacity(chunks.len());
    let mut prev_was_double_star = false;

    for chunk in chunks {
        let shape = analyze_chunk(chunk)?;
        match shape {
            ChunkShape::SingleStar => {
                if !prev_was_double_star {
                    out_chunks.push("*");
                }
                prev_was_double_star = false;
            }
            ChunkShape::DoubleStar => {
                if !prev_was_double_star {
                    out_chunks.push("**");
                    prev_was_double_star = true;
                }
            }
            ChunkShape::LoneDollarStar => {
                if !prev_was_double_star {
                    out_chunks.push("*");
                }
                prev_was_double_star = false;
            }
            ChunkShape::Mixed => {
                out_chunks.push(chunk);
                prev_was_double_star = false;
            }
        }
    }

    Ok(out_chunks.join("/"))
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

#[cfg(test)]
mod tests {
    use super::*;

    // ── Identity (already-canonical input passes through) ──

    #[test]
    fn canon_identity_on_pure_literal() {
        assert_eq!(canonize_keyexpr("home/temp").unwrap(), "home/temp");
        assert_eq!(canonize_keyexpr("sensors/room1/temp").unwrap(), "sensors/room1/temp");
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
        assert_eq!(canonize_keyexpr("home/foo$*$*bar").unwrap(), "home/foo$*bar");
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
        assert_eq!(canonize_keyexpr("home/$*$*/$*/temp").unwrap(), "home/*/*/temp");
    }

    // ── Error: structural grammar violations ──

    #[test]
    fn canon_rejects_empty_chunk() {
        assert_eq!(canonize_keyexpr("home//temp"), Err(KeyexprCanonError::EmptyChunk));
        assert_eq!(canonize_keyexpr("/home"), Err(KeyexprCanonError::EmptyChunk));
        assert_eq!(canonize_keyexpr("home/"), Err(KeyexprCanonError::EmptyChunk));
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
        assert_eq!(collapse_dsl_runs(canonical), canonical);
        let twice = collapse_dsl_runs(&collapse_dsl_runs(canonical));
        assert_eq!(twice, canonical);
    }
}
