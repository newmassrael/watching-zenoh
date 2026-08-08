// SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The JOIN datagram DECODE, gated on nothing but `codec-join`.
//!
//! R311y605 — hoisted out of [`crate::multicast_join`], which is gated on
//! `session-multicast` because its encode half needs `MulticastParams` and its
//! validate half needs the dispatcher's baseline. The decode half needs neither:
//! it is the generated `Join` codec plus two header-flag projections.
//!
//! The hoist exists because a SECOND consumer arrived that is not a multicast
//! participant. [`crate::inbound::parse_inbound`] is the transport-message
//! parser the PASSIVE observer reads a capture through, and it reported every
//! JOIN as `Unknown { mid: 0x07 }` — so an analyzer looking at zenoh's
//! multicast session group, where JOIN is how a peer announces its zid, lease
//! and initial sequence numbers, saw the announcement traffic as unnamed bytes.
//!
//! Copying the six lines into `parse_inbound` was the alternative, and the flag
//! projection is exactly the kind of thing that must not exist twice: the S bit
//! selects two OPTIONAL body fields and the T bit changes the lease's UNIT, and
//! R311y604 is the round that spent itself on a mis-read Mapping bit. One
//! decode, two callers.

use sce_forge_runtime::codec::{CodecError, SceCursor};
use wz_codecs::join::Join;
use wz_codecs::wire_const;

/// Decode the JOIN base body that follows `header`, returning it and how many
/// of `body`'s bytes it consumed.
///
/// The MID check is the CALLER's — [`decode_join`] is that check plus this, and
/// [`crate::inbound::parse_inbound`] has already matched the MID by the time it
/// gets here. Splitting it this way is what lets the parser propagate the real
/// [`CodecError`] instead of collapsing a truncated body and a
/// wrong-MID slice into one `None`: absence and failure are different verdicts
/// (the R311y597 C4 rule).
///
/// Both header-flag projections live HERE and nowhere else. `S`
/// ([`wire_const::FLAG_T_JOIN_S`], bit 6) gates the optional `sn_res` /
/// `batch_size` pair, and `T` ([`wire_const::FLAG_T_JOIN_T`], bit 5) changes
/// the lease's UNIT — adjacent bits with unrelated meanings, which is exactly
/// the shape R311y604 spent a round on.
pub fn decode_join_body(header: u8, body: &[u8]) -> Result<(Join<'_>, usize), CodecError> {
    // The `join` codec gates its optional sn_res / batch_size on `s & 0x01`,
    // so project the wire S flag (header bit 6, `FLAG_T_JOIN_S` = 0x40, per
    // zenoh-pico transport.h:61) to that bit. A minimal JOIN clears S so
    // `s` is 0, but project from the named flag (not a raw shift) so a
    // future richer JOIN decodes correctly — header bit 5 is the distinct
    // `_Z_FLAG_T_JOIN_T` lease-unit flag (handled below), NOT S, so a
    // `header >> 5` shift would read the wrong bit.
    let s = u8::from(header & wire_const::FLAG_T_JOIN_S != 0);
    let mut cursor = SceCursor::new(body);
    let mut join = Join::decode(&mut cursor, s)?;
    // R311kr — T flag = the lease VLE is in SECONDS; project back to the
    // milliseconds every wz consumer speaks (pico decode parity,
    // codec/transport.c:161-164: `_lease = _lease * 1000`). The default
    // pico beacon (lease 10000ms) arrives as T=1 + VLE 10, so skipping
    // this read it as 10ms. R311ku — the projection SSOT is
    // `crate::lease` (shared with the unicast OPEN decode boundary).
    join.lease = crate::lease::lease_from_wire(header & wire_const::FLAG_T_JOIN_T != 0, join.lease);
    Ok((join, body.len() - cursor.remaining()))
}

/// If `bytes` is a multicast JOIN datagram, decode its full body (a
/// borrowed view into `bytes`). Returns `None` for a non-JOIN MID or a
/// malformed body. The returned `lease` is ALWAYS milliseconds — the
/// `T` header flag's seconds form is projected back here (R311kr), so
/// consumers never see the wire unit. The caller validates the
/// announcement (§3.2 rejection rules —
/// [`validate_join`](crate::multicast_join::validate_join)) before
/// feeding it to
/// [`MulticastDispatcher::ingest_join`](crate::multicast_dispatch::MulticastDispatcher::ingest_join).
pub fn decode_join(bytes: &[u8]) -> Option<Join<'_>> {
    let header = *bytes.first()?;
    if header & 0x1f != wire_const::T_MID_JOIN {
        return None;
    }
    decode_join_body(header, &bytes[1..])
        .ok()
        .map(|(join, _)| join)
}

/// If `bytes` is a multicast JOIN datagram, decode it and return the
/// announcer's zid (a sub-slice borrow of `bytes`). Returns `None` for a
/// non-JOIN MID or a malformed body. Thin projection of [`decode_join`].
pub fn decode_join_zid(bytes: &[u8]) -> Option<&[u8]> {
    decode_join(bytes).map(|join| join.zid)
}
