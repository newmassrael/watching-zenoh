// SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! SSOT for the transport-message extension CHAIN codec — the Z-flag-gated list
//! of `ExtEntry` records that trails an Init / Open / Close / KeepAlive / Frame
//! body, and (nested) the per-method sub-ext chain INSIDE the Z_EXT_AUTH ext.
//!
//! One encode / decode pair so the outbound establishment path
//! (`handshake_encode`), the inbound parser (`inbound`), and the extauth
//! dispatch (`auth_dispatch`, the auth ext's inner method chain) share one
//! definition of the Z-bit continuation loop rather than each re-deriving it.
//! Each function is gated on the union of its consumers' features so a subset
//! that needs only one half does not drag the other in (and never trips
//! dead-code under `-D warnings`).

use alloc::vec::Vec;
use wz_codecs::ext_entry::ExtEntryOwned;

/// R311y582 (A1) — did a Z-terminated chain end because the wire said so, or
/// because the decoder ran out of room?
///
/// This is the SSOT for that question, and it exists because the GENERATED
/// chain decode cannot answer it. For a chain whose termination strategy is
/// `entry-flag` (every zenoh network / payload message), SCE emits
///
/// ```text
/// for _ in 0..MAX { ...; let _continue = entry.z(); ...; if !_continue { break; } }
/// ```
///
/// over a `HeaplessVec<_, MAX>` — so the `TooManyElements` arm is unreachable
/// (the loop cannot push more than `MAX`), and the generator DROPS the
/// post-loop overflow check on the entry-flag path even though the SCXML
/// declares `on-overflow="reject"`. A chain of `MAX + 1` entries therefore
/// leaves the loop on the FOR bound with the last entry's Z bit still set,
/// and the next field is read from bytes that belong to the chain.
///
/// Measured, not inferred: a `Put` carrying five extensions decodes to `Ok`
/// with a payload of `[0x03, 0xAA, 0xBB]` where the wire held
/// `[0xAA, 0xBB, 0xCC]` (`crate::dissect` tests,
/// `a_chain_past_the_cap_is_refused_rather_than_misread`). A silent wrong
/// answer, not an error.
///
/// The fix belongs in the generator, and `vendor/sce` is read-only from this
/// workspace (`CLAUDE.md`, External references), so wz carries the check at
/// its own seams until the SSOT lands it. Keeping the RULE here — rather than
/// re-deriving "the last entry still says continue" at each seam — is what
/// stops the two copies from drifting apart.
///
/// Stated over the three facts rather than over a concrete container so the
/// hand-written walker (which never builds a `HeaplessVec`) and the generated
/// struct can both ask it.
///
/// Gated on the union of its CALLERS' features, not on this module's — the
/// R311y579 (G7) rule. `ext_chain` compiles for six different consumer
/// features and only the observer path calls this one, so the module's own
/// gate would leave it dead under `-D warnings` on every other combination.
#[cfg(any(feature = "dissect", feature = "codec-frame"))]
pub fn chain_saturated(decoded: usize, capacity: usize, last_says_continue: bool) -> bool {
    decoded == capacity && last_says_continue
}

/// The `max-depth` every entry-flag ext chain in the network and zenoh-payload
/// layers is generated with (`sources/codecs/*.scxml`).
///
/// R311y582 — this constant exists because the hand-written walker in
/// [`crate::dissect`] has to be told the bound the generated decode gets from
/// its container type, and it was told fourteen times, as the literal `4`. One
/// fact reachable by two paths always drifts (this workspace has paid for that
/// four times in one session before), and here the drift would be silent in the
/// worst way: a walker whose bound is LOWER than the codec's rejects wire the
/// codec accepts, and one whose bound is HIGHER walks into bytes the codec
/// never read.
///
/// It is not derived from the generated type because a const generic parameter
/// has no name to import. What closes the loop instead is
/// `the_generated_chain_capacities_match_the_constants` in [`crate::dissect`],
/// which asks each generated container for its own `capacity()` — so a
/// regenerated codec with a different depth reds a test rather than silently
/// disagreeing with the walker.
// Callers: the `dissect` walkers, and this crate's own chain-saturation
// tests under `codec-frame`. NOT `codec-frame` alone — an MCU build that
// parses batches and never dissects has no use for it, and R311y579 (G7)
// says a helper is gated on who CALLS it.
#[cfg(any(feature = "dissect", test))]
pub const NETWORK_EXT_CHAIN_DEPTH: usize = 8;

/// `Query`'s chain is generated with the fill-to-end strategy and its own,
/// larger depth. Separate constant rather than a second use of
/// [`NETWORK_EXT_CHAIN_DEPTH`]: the two are different numbers in the SCXML for
/// different reasons, and collapsing them would make a future divergence
/// invisible.
#[cfg(feature = "dissect")]
pub const QUERY_EXT_CHAIN_DEPTH: usize = 8;

/// R311y582 (A1) — refuse one generated chain that never terminated.
///
/// The generic over `N` is deliberate: the cap is read off the container's
/// own type rather than restated, so raising `max-depth` in the SCXML moves
/// this check with it and cannot leave a stale constant behind.
#[cfg(feature = "codec-frame")]
pub fn check_chain<const N: usize>(
    chain: Option<&sce_forge_runtime::heapless::Vec<wz_codecs::ext_entry::ExtEntry<'_>, N>>,
) -> Result<(), sce_forge_runtime::codec::CodecError> {
    if let Some(v) = chain {
        if chain_saturated(v.len(), N, v.last().is_some_and(|e| e.z())) {
            return Err(sce_forge_runtime::codec::CodecError::TlvChainOverflow);
        }
    }
    Ok(())
}

/// R311y582 (A1) — the PARTICIPANT-side half of the same defect.
///
/// The observer refuses in [`crate::dissect`]; this is the seam that keeps a
/// wz NODE from acting on a misread message. A network message carries a
/// chain of its own AND, for the three that nest a zenoh-payload body, a
/// second chain inside that body — and it is the INNER one that does the real
/// damage, because `MsgPut` reads its `payload_len` out of the byte that
/// follows its chain.
///
/// This module is the single place that knows WHERE the chains are. That is
/// the whole reason the per-message functions live here rather than inline at
/// the call site: when SCE honours `on-overflow="reject"` on the entry-flag
/// path, this section deletes in one edit instead of being hunted across the
/// dispatch.
#[cfg(all(feature = "codec-frame", feature = "codec-push"))]
pub fn check_push(
    m: &wz_codecs::push::Push<'_>,
) -> Result<(), sce_forge_runtime::codec::CodecError> {
    use wz_codecs::push::PushVariant;
    check_chain(m.extensions.as_ref())?;
    match &m.body {
        PushVariant::CodecZenohMsgPut(b) | PushVariant::Default { body: b, .. } => {
            check_chain(b.extensions.as_ref())
        }
        PushVariant::CodecZenohMsgDel(b) => check_chain(b.extensions.as_ref()),
    }
}

/// See [`check_push`]. `Query`'s own chain uses the fill-to-end strategy and
/// already rejects an overlong chain inside the generated decode; it is
/// checked here anyway so the arm list mirrors the variant list exactly and a
/// future strategy change cannot silently open a hole.
#[cfg(all(feature = "codec-frame", feature = "codec-request"))]
pub fn check_request(
    m: &wz_codecs::request::Request<'_>,
) -> Result<(), sce_forge_runtime::codec::CodecError> {
    use wz_codecs::request::RequestVariant;
    check_chain(m.extensions.as_ref())?;
    match &m.body {
        RequestVariant::CodecZenohMsgPut(b) => check_chain(b.extensions.as_ref()),
        RequestVariant::CodecZenohMsgDel(b) => check_chain(b.extensions.as_ref()),
        RequestVariant::CodecZenohQuery(b) | RequestVariant::Default { body: b, .. } => {
            check_chain(b.extensions.as_ref())
        }
    }
}

/// See [`check_push`].
#[cfg(all(feature = "codec-frame", feature = "codec-response"))]
pub fn check_response(
    m: &wz_codecs::response::Response<'_>,
) -> Result<(), sce_forge_runtime::codec::CodecError> {
    use wz_codecs::response::ResponseVariant;
    check_chain(m.extensions.as_ref())?;
    match &m.body {
        ResponseVariant::CodecZenohReply(b) | ResponseVariant::Default { body: b, .. } => {
            check_chain(b.extensions.as_ref())
        }
        ResponseVariant::CodecZenohErr(b) => check_chain(b.extensions.as_ref()),
    }
}

/// See [`check_push`]. FOUR of `Declare`'s nine sub-bodies carry a chain of
/// their own — `decl_queryable`, `undecl_subscriber`, `undecl_queryable`,
/// `undecl_token` — and the other five do not.
///
/// That split is why the arm list below is written out in full rather than
/// collapsed with a wildcard: the first census taken for R311y582 enumerated
/// the twelve messages whose names suggested a chain and MISSED all four of
/// these, because a `Declare` sub-body is not a message. A wildcard arm would
/// have hidden the same omission again, and would hide the next sub-body that
/// gains a chain. An exhaustive match makes codegen adding one a COMPILE
/// error here.
#[cfg(all(feature = "codec-frame", feature = "codec-declare"))]
pub fn check_declare(
    m: &wz_codecs::declare::Declare<'_>,
) -> Result<(), sce_forge_runtime::codec::CodecError> {
    use wz_codecs::declare::DeclareVariant;
    check_chain(m.extensions.as_ref())?;
    match &m.body {
        DeclareVariant::CodecZenohDeclQueryable(b) => check_chain(b.extensions.as_ref()),
        DeclareVariant::CodecZenohUndeclSubscriber(b) => check_chain(b.extensions.as_ref()),
        DeclareVariant::CodecZenohUndeclQueryable(b) => check_chain(b.extensions.as_ref()),
        DeclareVariant::CodecZenohUndeclToken(b) => check_chain(b.extensions.as_ref()),
        // The five that carry no chain of their own.
        DeclareVariant::CodecZenohDeclKexpr(_)
        | DeclareVariant::CodecZenohUndeclKexpr(_)
        | DeclareVariant::CodecZenohDeclSubscriber(_)
        | DeclareVariant::CodecZenohDeclToken(_)
        | DeclareVariant::CodecZenohDeclFinal(_)
        | DeclareVariant::Default { .. } => Ok(()),
    }
}

/// Encode an ext chain to bytes: each entry's `ExtEntry` encoding with the
/// chain-continuation Z bit (`0x80`) set on every entry but the last (Z clear =
/// terminator). An empty slice encodes to no bytes (the "no extensions" case).
/// The non-Z header bits (`ext_id`, `M`, `enc`) stay author-set; the helper
/// only patches the Z bit per chain position (`ExtEntry::encode` pushes the
/// header byte first).
#[cfg(any(
    feature = "codec-init-body",
    feature = "codec-open-body",
    feature = "session-extauth"
))]
pub(crate) fn encode_ext_chain(entries: &[ExtEntryOwned]) -> Vec<u8> {
    if entries.is_empty() {
        return Vec::new();
    }
    let mut buf = Vec::with_capacity(entries.len() * 4);
    let last = entries.len() - 1;
    for (i, entry) in entries.iter().enumerate() {
        let mut bytes = entry.as_borrowed().encode_to_vec();
        if i == last {
            bytes[0] &= !0x80;
        } else {
            bytes[0] |= 0x80;
        }
        buf.extend_from_slice(&bytes);
    }
    buf
}

/// Decode the Z-flag-gated ext chain into the lifetime-free owned mirror,
/// bounded by [`MAX_EXT_CHAIN_DEPTH`](crate::parse_error::MAX_EXT_CHAIN_DEPTH)
/// so a malformed peer cannot pin the decoder into an unbounded loop.
#[cfg(any(
    feature = "codec-init-body",
    feature = "codec-open-body",
    feature = "codec-close",
    feature = "codec-keep-alive",
    feature = "codec-frame",
    feature = "session-extauth"
))]
pub(crate) fn decode_ext_chain(
    cursor: &mut sce_forge_runtime::codec::SceCursor<'_>,
) -> Result<Vec<ExtEntryOwned>, crate::parse_error::InboundParseError> {
    use crate::parse_error::{InboundParseError, MAX_EXT_CHAIN_DEPTH};
    use wz_codecs::ext_entry::ExtEntry;

    let mut entries = Vec::new();
    for _ in 0..MAX_EXT_CHAIN_DEPTH {
        let entry = ExtEntry::decode(cursor).map_err(InboundParseError::Codec)?;
        let z = entry.z();
        // Deep-copy the borrowed decode view into the lifetime-free owned mirror
        // so the parsed chain can outlive the input buffer.
        entries.push(entry.try_into_owned().map_err(InboundParseError::Codec)?);
        if !z {
            return Ok(entries);
        }
    }
    Err(InboundParseError::ExtChainOverflow)
}
