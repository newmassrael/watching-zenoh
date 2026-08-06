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
//!    - a wild RUN is reordered: every `*` first, then at most one
//!      `**`. R311y564 replaced "`*` after `**` → drop the `*`"
//!      here, which was a different LANGUAGE rather than a different
//!      spelling — `a/**/b` matches `a/b` and `a/**/*/b` does not, so
//!      absorbing widened the keyexpr. Both references disagree with
//!      the old rule and agree with this one; measured, not read.
//!    - `**` after `**` → collapse into the run's single `**`
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
/// // A `*` after `**` is REORDERED, not absorbed — the two say
/// // different things (`a/**/b` matches `a/b`; `a/**/*/b` does not).
/// assert_eq!(canonize_keyexpr("home/**/*/temp").unwrap(), "home/*/**/temp");
///
/// // Invalid grammar returns a typed error.
/// assert!(canonize_keyexpr("home/foo?bar").is_err());
/// ```
pub fn canonize_keyexpr(
    input: &str,
) -> Result<BoundedString<MAX_KEYEXPR_BYTES>, KeyexprCanonError> {
    canonize_keyexpr_in(input, KeyexprDialect::Pico)
}

/// Which upstream's canonical form to produce.
///
/// # R311y564 — the two references genuinely DISAGREE, on one case
///
/// This enum exists because a measurement said so, not because a
/// design wanted a knob. The real `libzenohc.so` and the real
/// `libzenohpico.so` were handed the same thirteen inputs; they
/// agreed on eleven, and split on what a `$*`-spelled single wild
/// does INSIDE a wild run:
///
/// | input | zenoh-c | zenoh-pico |
/// |---|---|---|
/// | `**/$*/temp` | `*/**/temp` | `**/*/temp` |
/// | `**/*` | `*/**` | `*/**` |
///
/// So pico's reorder pass treats a `$*` chunk as an ordinary chunk
/// that ENDS the wild run and only later rewrites it to `*`, while
/// zenoh-c folds it into the run first. Neither is a wz choice to
/// make: a drop-in has to answer whatever the ABI it is standing in
/// for answers, and picking one would make the other ABI's
/// pure-function oracle red.
///
/// Everything else — including the reorder itself — is shared, which
/// is why this is a two-variant flag rather than two canonizers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyexprDialect {
    /// zenoh-pico's form. wz's own wire path uses it, because wz is
    /// pico-faithful everywhere else too.
    Pico,
    /// zenoh-c's form, for the `wz-capi-c` drop-in.
    ZenohC,
}

/// [`canonize_keyexpr`] in an explicit dialect.
pub fn canonize_keyexpr_in(
    input: &str,
    dialect: KeyexprDialect,
) -> Result<BoundedString<MAX_KEYEXPR_BYTES>, KeyexprCanonError> {
    let collapsed = collapse_dsl_runs(input)?;
    canonize_chunks(&collapsed, dialect)
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
/// (`$*` → `*`; a wild RUN is reordered to all its `*` first, then
/// at most one `**`).
///
/// # R311y564 — the run rule REPLACES an absorb rule that was wrong
///
/// This function used to drop any `*` that followed a `**`, and
/// said so: "`*` after `**` is absorbed". That is a different
/// LANGUAGE, not a different spelling. `a/**/b` matches `a/b`,
/// while `a/**/*/b` requires at least one chunk between them — so
/// absorbing the `*` widened every such keyexpr, silently, in both
/// C ABIs and on the wire.
///
/// The rule upstream actually applies is a REORDER: within a
/// maximal run of `*` / `**` chunks, every `*` is emitted first and
/// the `**`s collapse into one. The arity is preserved (`n` single
/// wilds stay `n`) and the super-wild ends up last, which is the
/// canonical form both references produce.
///
/// MEASURED on both, not read off either implementation: the real
/// `libzenohc.so` and the real `libzenohpico.so` were each handed
/// `home/**/*/temp` and each answered `home/*/**/temp`, where wz
/// answered `home/**/temp`. The two ABIs' pure-function oracles
/// now drive that comparison on every run.
fn canonize_chunks(
    input: &str,
    dialect: KeyexprDialect,
) -> Result<BoundedString<MAX_KEYEXPR_BYTES>, KeyexprCanonError> {
    let mut out_chunks: BoundedVec<&str, MAX_KEYEXPR_CHUNKS> = BoundedVec::new();
    // The wild run being accumulated: how many `*` chunks it has
    // contained so far, and whether any of them was a `**`.
    let mut run_single_stars: usize = 0;
    let mut run_has_double_star = false;

    // Emit the pending wild run in canonical order: every `*`, then
    // at most one `**`.
    fn flush_run(
        out: &mut BoundedVec<&str, MAX_KEYEXPR_CHUNKS>,
        singles: usize,
        has_double: bool,
    ) -> Result<(), KeyexprCanonError> {
        for _ in 0..singles {
            out.push("*")
                .map_err(|_| KeyexprCanonError::ExceedsCapacity)?;
        }
        if has_double {
            out.push("**")
                .map_err(|_| KeyexprCanonError::ExceedsCapacity)?;
        }
        Ok(())
    }

    for chunk in input.split('/') {
        let shape = analyze_chunk(chunk)?;
        // The ONE case the two dialects split on — see [`KeyexprDialect`].
        // pico ends the wild run at a `$*` chunk and emits `*` after
        // whatever the run held; zenoh-c folds it into the run.
        let folds_into_run = match shape {
            ChunkShape::SingleStar => true,
            ChunkShape::LoneDollarStar => dialect == KeyexprDialect::ZenohC,
            _ => false,
        };
        if folds_into_run {
            run_single_stars += 1;
            continue;
        }
        match shape {
            ChunkShape::DoubleStar => run_has_double_star = true,
            // A pico-dialect `$*`, or an ordinary literal chunk: flush
            // the pending run, then emit this chunk's canonical form.
            _ => {
                flush_run(&mut out_chunks, run_single_stars, run_has_double_star)?;
                run_single_stars = 0;
                run_has_double_star = false;
                let literal = if shape == ChunkShape::LoneDollarStar {
                    "*"
                } else {
                    chunk
                };
                out_chunks
                    .push(literal)
                    .map_err(|_| KeyexprCanonError::ExceedsCapacity)?;
            }
        }
    }
    // A keyexpr may END in a wild run, so the flush cannot live only
    // at the literal-chunk boundary.
    flush_run(&mut out_chunks, run_single_stars, run_has_double_star)?;

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
/// R311y544 — this paragraph used to say the trigger fires on
/// multi-char literals as well (`**/foo/*`, `**/abc/*/def`), citing
/// the R299 fixture `canon_known_pico_anomaly_double_star_literal_star_aborts`
/// as empirical. That fixture never called pico on them; it says in so
/// many words that it cannot, because an in-process abort would take
/// the test binary with it. A SUBPROCESS can, and does
/// (`layer3_keyexpr_canon::canon_pico_abort_family_is_single_byte_chunks_only_measured`):
/// a real `_z_keyexpr_canonize` canonizes both of those to themselves.
///
/// Only a chunk of length ONE holds the window open, because
/// `case 1:` (`keyexpr.c:130-138`) is the only branch that reaches the
/// reset-skipping `else { advance; continue; }`. Anything longer falls
/// through to the char-walk and runs `in_big_wild = false`
/// (`keyexpr.c:206`). The window must ALSO have at least one
/// intervening chunk: with the closer adjacent to the `**`, pico's
/// `pos - 3` offset addresses the `**` chunk correctly and the result
/// is bug #1 (wrong output) rather than an abort.
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

    // Bug #3 family walk — a direct model of pico's `__zp_canon_prefix`
    // chunk loop (`vendor/zenoh-pico/src/session/keyexpr.c:121-209`),
    // because that loop is what decides whether the abort fires.
    //
    // * big_wild_open — pico's `in_big_wild`. Set by a `**` chunk.
    // * intervening — whether at least one chunk has passed since that
    //   `**` while the window stayed open. It is what separates an
    //   ABORT from bug #1: pico's rewrite offset is
    //   `pos(closer) - 3`, which addresses the `**` chunk exactly when
    //   the closer is adjacent to it, and lands mid-keyexpr otherwise
    //   (`keyexpr.c:132` / `:147` vs the `chunk_end - reader == 2`
    //   precondition at `:330`).
    //
    // ONLY a chunk of length 1 keeps the window open. pico reaches the
    // reset-skipping `else { advance; continue; }` exclusively from
    // `case 1:` (`keyexpr.c:130-138`); every chunk of length >= 2 that
    // is not `**` falls through to the char-walk and runs
    // `in_big_wild = false` (`keyexpr.c:206`). R311y544 measured this
    // rather than reading it —
    // `layer3_keyexpr_canon::canon_pico_abort_family_is_single_byte_chunks_only_measured`
    // runs the real `_z_keyexpr_canonize` in a subprocess and pins the
    // outcome for each shape, including the `**/ab/*` vs `**/a/*`
    // boundary. It REFUTES this function's former claim that the
    // trigger "fires on multi-char literals as well"; `**/foo/*` and
    // `**/abc/*/def` canonize to themselves on a real pico.
    //
    // The closer must be an exact `*` or `**`. A `$*`-shape closer
    // takes pico's LONE_DOLLAR_STAR branch, whose offset addresses the
    // `$*` chunk itself, so it cannot trip the assert (measured:
    // `**/c/$*` returns `**/c/*`).
    // The walk TERMINATES at the first chunk for which pico's loop
    // leaves `Z_KEYEXPR_CANON_SUCCESS`, because that is where
    // `__zp_canon_prefix` returns. Past that point control is in the
    // rewrite loop (`keyexpr.c:342-422`), which carries no assert, so
    // nothing later in the keyexpr can abort.
    let mut big_wild_open = false;
    let mut intervening = false;
    for chunk in input.split('/') {
        let abort = |offending: &str| {
            Err(OutboundKeyexprError::PicoBugThreeFamily {
                keyexpr: input.to_string(),
                offending_chunk: offending.to_string(),
            })
        };
        if chunk == "**" {
            if big_wild_open {
                // DOUBLE_STAR_AFTER_DOUBLE_STAR — walk ends here.
                return if intervening { abort(chunk) } else { Ok(()) };
            }
            big_wild_open = true;
            intervening = false;
        } else if chunk == "*" {
            if big_wild_open {
                // SINGLE_STAR_AFTER_DOUBLE_STAR — walk ends here.
                return if intervening { abort(chunk) } else { Ok(()) };
            }
            // pico's `case 1:` else-branch: advance, no reset. The
            // window is already closed, so nothing to carry.
        } else if chunk_canonizes_to_star_shape(chunk) {
            // A `$*`-run chunk: LONE_DOLLAR_STAR, whose offset
            // addresses this chunk itself, so the rewrite precondition
            // holds and the walk ends without an assert.
            return Ok(());
        } else if chunk.len() == 1 {
            // pico's `case 1:` — advance without resetting the window.
            intervening = big_wild_open;
        } else {
            // Any longer chunk reaches the char-walk, which resets it.
            big_wild_open = false;
            intervening = false;
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

    // ── Wild-run reorder (R311y564) ──

    /// A `*` inside a wild run is REORDERED before the `**`, never
    /// dropped. Every expectation here was read off the real
    /// `libzenohpico.so` by a C probe, not derived from this
    /// implementation — the rule this replaced was self-consistent
    /// and wrong, so a hand-written expectation is what let it live.
    #[test]
    fn canon_reorders_a_single_star_ahead_of_a_double_star() {
        assert_eq!(
            canonize_keyexpr("home/**/*/temp").unwrap(),
            "home/*/**/temp"
        );
        assert_eq!(canonize_keyexpr("**/*").unwrap(), "*/**");
        assert_eq!(canonize_keyexpr("a/**/*/*/b").unwrap(), "a/*/*/**/b");
    }

    /// The ONE case the two references split on: pico ENDS the wild
    /// run at a `$*` chunk, so the `**` stays in front.
    #[test]
    fn the_pico_dialect_does_not_fold_a_dollar_star_into_the_run() {
        assert_eq!(canonize_keyexpr("**/$*/temp").unwrap(), "**/*/temp");
        assert_eq!(canonize_keyexpr("**/$*$*/temp").unwrap(), "**/*/temp");
    }

    /// …and zenoh-c folds it, so the `*` comes out in front.
    #[test]
    fn the_zenoh_c_dialect_folds_a_dollar_star_into_the_run() {
        assert_eq!(
            canonize_keyexpr_in("**/$*/temp", KeyexprDialect::ZenohC).unwrap(),
            "*/**/temp"
        );
        // Everything the two agree on stays agreed.
        assert_eq!(
            canonize_keyexpr_in("home/**/*/temp", KeyexprDialect::ZenohC).unwrap(),
            "home/*/**/temp"
        );
    }

    #[test]
    fn canon_collapses_a_double_star_run_into_one() {
        assert_eq!(canonize_keyexpr("home/**/**/temp").unwrap(), "home/**/temp");
        assert_eq!(canonize_keyexpr("**/**").unwrap(), "**");
        assert_eq!(canonize_keyexpr("**/**/**").unwrap(), "**");
    }

    // ── Mixed canon (singleify + chunk rules combined) ──

    #[test]
    fn canon_combines_singleify_and_chunk_rules() {
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
        // R299 bug #3 — `**` + SINGLE-BYTE chunk(s) + `*`-shape chunk.
        // Pico SIGABRTs on receive canonize; R300 rejects pre-emit.
        //
        // R311y544 removed `**/foo/*` and `**/abc/*/def` from this list.
        // They were here on the strength of the word "empirically" in
        // this module's doc, and the fixture it cited never called pico
        // on them. A subprocess probe does, and a real
        // `_z_keyexpr_canonize` canonizes both to themselves — a
        // multi-byte chunk reaches pico's char-walk, which resets
        // `in_big_wild`. They now live in
        // `outbound_allows_multi_byte_chunk_after_double_star` below.
        let cases = [("**/c/*", "*"), ("**/a/b/*", "*")];
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
        // Bug #3 also fires when the closer is `**` rather than `*` —
        // pico's DOUBLE_STAR_AFTER_DOUBLE_STAR takes the same rewrite
        // path with the same off-by-a-chunk offset.
        assert!(matches!(
            check_outbound_keyexpr_pico_safe("**/c/**"),
            Err(OutboundKeyexprError::PicoBugThreeFamily { .. }),
        ));
        // A `$*`-shape closer does NOT. R311y544 measured it: pico
        // takes the LONE_DOLLAR_STAR branch, whose offset addresses the
        // `$*` chunk itself, so the `chunk_end - reader == 2`
        // precondition holds and no assert fires — `**/c/$*` comes back
        // as `**/c/*`. Refusing it was a false positive.
        assert!(check_outbound_keyexpr_pico_safe("**/c/$*").is_ok());
        assert!(check_outbound_keyexpr_pico_safe("**/c/$*$*").is_ok());
    }

    #[cfg(feature = "alloc")]
    #[test]
    fn outbound_allows_multi_byte_chunk_after_double_star() {
        // R311y544 — the half of the gate that was wrong, and the
        // reason it mattered: `<base>/@adv/pub/**` for a `**`-tailed
        // base is exactly this shape, and refusing it disabled the
        // advanced subscriber's entire recovery plane for upstream's
        // own default keyexpr.
        //
        // Only pico's `case 1:` (chunk length 1) skips the
        // `in_big_wild = false` reset. Every chunk of length >= 2 that
        // is not `**` falls through to the char-walk and closes the
        // window. Measured, not read, by
        // `layer3_keyexpr_canon::canon_pico_abort_family_is_single_byte_chunks_only_measured`.
        assert!(check_outbound_keyexpr_pico_safe("**/foo/*").is_ok());
        assert!(check_outbound_keyexpr_pico_safe("**/abc/*/def").is_ok());
        // The boundary: two bytes is already enough.
        assert!(check_outbound_keyexpr_pico_safe("**/ab/*").is_ok());
        assert!(matches!(
            check_outbound_keyexpr_pico_safe("**/a/*"),
            Err(OutboundKeyexprError::PicoBugThreeFamily { .. }),
        ));
        // An opened window is CLOSED again by a later long chunk.
        assert!(check_outbound_keyexpr_pico_safe("**/a/foo/*").is_ok());
        // The three derived `@adv` channels for a `**`-tailed base.
        assert!(check_outbound_keyexpr_pico_safe("demo/example/**/@adv/pub/**").is_ok());
        assert!(check_outbound_keyexpr_pico_safe("demo/example/**/@adv/**").is_ok());
        assert!(
            check_outbound_keyexpr_pico_safe("demo/example/**/@adv/*/a0b1c2d3e4f5/1/**").is_ok()
        );
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
    fn outbound_mixed_chunk_after_double_star_closes_the_bug_window() {
        // A Mixed chunk (literal + `$*` + literal) is NOT star-shape,
        // and it is longer than one byte, so on pico it reaches the
        // char-walk and CLOSES the window rather than holding it open.
        // R311y544 renamed and corrected this test: it previously
        // asserted the opposite for `**/foo$*bar/*`, which a real pico
        // canonizes to itself.
        assert!(check_outbound_keyexpr_pico_safe("**/foo$*bar").is_ok());
        assert!(check_outbound_keyexpr_pico_safe("**/foo$*bar/temp").is_ok());
        assert!(check_outbound_keyexpr_pico_safe("**/foo$*bar/*").is_ok());
    }

    #[cfg(feature = "alloc")]
    #[test]
    fn outbound_conservatively_rejects_double_star_after_literal_segment() {
        // A `**` closer aborts as surely as a `*` one, so these stay
        // rejected — but they are now rejected on a MEASUREMENT rather
        // than on conservatism. This comment used to end "narrowing
        // this false-positive zone ... is a future round, pending an
        // empirical fork-based pico abort probe"; R311y544 built that
        // probe (`probe_pico_canon`, a subprocess rather than a fork)
        // and did the narrowing. What survives here is the part the
        // probe CONFIRMED: a single-byte chunk between the `**` and
        // the closer really does hold pico's window open.
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
