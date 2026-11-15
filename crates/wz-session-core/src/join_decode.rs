// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The JOIN datagram DECODE, gated on nothing but `codec-join`.
//!
//! R311y605 — hoisted out of [`crate::multicast_join`], which is gated on
//! `session-multicast` because its encode half needs `MulticastParams` and its
//! validate half needs the dispatcher's baseline. The decode half needs neither:
//! it is the message's document (`sources/codecs/transport_join.scxml`) plus the
//! one projection of the lease's unit.
//!
//! The hoist exists because a SECOND consumer arrived that is not a multicast
//! participant. [`crate::inbound::parse_inbound`] is the transport-message
//! parser the PASSIVE observer reads a capture through, and it reported every
//! JOIN as `Unknown { mid: 0x07 }` — so an analyzer looking at zenoh's
//! multicast session group, where JOIN is how a peer announces its zid, lease
//! and initial sequence numbers, saw the announcement traffic as unnamed bytes.
//!
//! Every reader here starts from [`read_join`](crate::join_decode::read_join), which
//! reads the header, the body and the extension chain as the document does. The S bit selects two OPTIONAL
//! body fields and the T bit changes the lease's UNIT, adjacent bits with
//! unrelated meanings; the document reads the first and
//! [`decode_join`](crate::join_decode::decode_join) projects
//! the second, so neither is read twice, and where the body ends and the chain
//! starts is never computed outside the document.

use sce_forge_runtime::codec::SceCursor;
use wz_codecs::join::Join;
use wz_codecs::transport_join::TransportJoinView;
use wz_codecs::wire_const;

/// The JOIN at the front of `bytes` as its document reads it: the header, the
/// body (with the lease as the wire carries it) and the extension chain, and how
/// many of `bytes` they occupy.
///
/// `None` for another message id, a JOIN that does not decode, or a chain longer
/// than the bound a node reads of a transport chain
/// ([`MAX_EXT_CHAIN_DEPTH`](crate::parse_error::MAX_EXT_CHAIN_DEPTH)): the
/// document reads a chain of any length, and a node holds that many entries of
/// one, as the Join arm of [`crate::inbound::parse_inbound`] does.
pub fn read_join(bytes: &[u8]) -> Option<(TransportJoinView<'_>, usize)> {
    if bytes.first()? & 0x1f != wire_const::T_MID_JOIN {
        return None;
    }
    let mut cursor = SceCursor::new(bytes);
    let view = TransportJoinView::decode(&mut cursor).ok()?;
    let entries = view
        .extensions
        .as_ref()
        .map_or(0, |chain| chain.inner().len());
    (entries <= crate::parse_error::MAX_EXT_CHAIN_DEPTH)
        .then(|| (view, bytes.len() - cursor.remaining()))
}

/// How many bytes the JOIN at the front of `bytes` occupies: its header, its base
/// body and its extension chain, which the header's Z flag says is there.
///
/// What a walk over a batched datagram needs to reach the message behind a JOIN,
/// read by [`read_join`], so no second statement of where a JOIN ends exists.
/// `None` where [`read_join`] reads none.
pub fn join_message_len(bytes: &[u8]) -> Option<usize> {
    read_join(bytes).map(|(_, len)| len)
}

/// If `bytes` is a multicast JOIN datagram, its body (a borrowed view into
/// `bytes`), read by [`read_join`], so a JOIN whose extension chain does not
/// decode, or runs past the bound, is no JOIN here either. The returned `lease`
/// is ALWAYS milliseconds — the `T` header flag's seconds form is projected back
/// here (R311kr, pico decode parity, codec/transport.c:161-164:
/// `_lease = _lease * 1000`; the projection itself is [`crate::lease`], shared
/// with the unicast OPEN), so consumers never see the wire unit. The caller
/// validates the announcement (§3.2 rejection rules —
/// `crate::multicast_join::judge_join`) before feeding it to
/// [`MulticastDispatcher::ingest_join`](crate::multicast_dispatch::MulticastDispatcher::ingest_join).
pub fn decode_join(bytes: &[u8]) -> Option<Join<'_>> {
    let (view, _) = read_join(bytes)?;
    let in_seconds = view.t();
    let mut join = view.body;
    join.lease = crate::lease::lease_from_wire(in_seconds, join.lease);
    Some(join)
}

/// If `bytes` is a multicast JOIN datagram, decode it and return the
/// announcer's zid (a sub-slice borrow of `bytes`). Returns `None` where
/// [`decode_join`] does. Thin projection of [`decode_join`].
pub fn decode_join_zid(bytes: &[u8]) -> Option<&[u8]> {
    decode_join(bytes).map(|join| join.zid.into_inner())
}

/// The identity of the JOIN QoS extension: id `0x1`, mandatory, a ZBuf
/// (`commons/zenoh-protocol/src/transport/join.rs` @ `pub type QoS = zextzbuf!(0x1, true);`),
/// which is zenoh-pico's `_Z_MSG_EXT_ID_JOIN_QOS` (protocol/ext.h:46). Compared
/// against [`crate::ext_header::ext_eid`] of a received header, so a chained and
/// an unchained one are the same extension.
pub const JOIN_QOS_EXT_EID: u8 =
    crate::ext_header::ext_identity(0x1, true, crate::ext_header::EXT_ENC_ZBUF);

/// The next SNs a JOIN QoS extension states, one pair per priority, read off the
/// extension's ZBuf BODY (the bytes behind its header and length).
///
/// Upstream writes `Priority::NUM` pairs of VLE `(reliable, best_effort)` in
/// priority order (`commons/zenoh-codec/src/transport/join.rs` @
/// `for p in ext_qos.iter_mut() {`), and with the extension present the body's
/// own `next_sn` is not read: a receiver seeds every priority from the extension
/// (`io/zenoh-transport/src/multicast/transport.rs` @ `let next_sns = match join.ext_qos.as_ref() {`).
/// `None` when the body holds fewer than `Priority::NUM` pairs.
///
/// One reader for the multicast participant, which finds the body in the
/// datagram (`crate::multicast_join::decode_join_qos`), and for the passive
/// observer, which finds it in the decoded extension chain.
pub fn qos_next_sns(
    body: &[u8],
) -> Option<[crate::sn::MulticastRxPair; crate::qos::Priority::NUM]> {
    let mut inner = SceCursor::new(body);
    let mut pairs = [crate::sn::MulticastRxPair::default(); crate::qos::Priority::NUM];
    for p in pairs.iter_mut() {
        p.reliable = inner.read_vle_u64().ok()?;
        p.best_effort = inner.read_vle_u64().ok()?;
    }
    Some(pairs)
}
