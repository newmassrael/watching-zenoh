// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! Multicast JOIN datagram surface: encode (the periodic TX beacon),
//! decode (RX classify) and validate (the §3.2 rejection rules).
//!
//! R311kt — hoisted from `wz-runtime-tokio::multicast_glue` so both
//! runtime profiles share one JOIN wire SSOT: the three functions are
//! pure (codecs + [`MulticastParams`] + `TxSn` only — no socket, no
//! clock, no tokio), and the MCU `#![no_std]` multicast loop cannot
//! depend on the tokio crate. The exact multicast sibling of
//! [`crate::handshake_encode`] (the unicast INIT / OPEN / CLOSE encoders,
//! hoisted for the same reason). The tokio drive loop keeps the IO: it
//! calls [`encode_join`] on the beacon tick and [`decode_join`] /
//! [`judge_join`] in its RX classifier.
//!
//! Alloc note: [`encode_join`] returns an owned `Vec` and exists on the heap
//! profile only; [`encode_join_into`] writes the same datagram through a sink the
//! caller holds, and `MulticastParams` holds its zid as the session bytes of its
//! profile, so the rest of the module (the decode, the validation, the sink
//! encode) compiles with no allocator (fixed-memory step S9e).

#[cfg(feature = "alloc")]
use alloc::vec::Vec;

#[cfg(feature = "transport-qos")]
use sce_forge_runtime::codec::SliceSink;
#[cfg(feature = "alloc")]
use sce_forge_runtime::codec::VecSink;
use sce_forge_runtime::codec::{Bounded, CodecError, SceSink};
use wz_codecs::ext_entry::{ExtEntryParts, ExtEntryPartsBody};
use wz_codecs::ext_unit::ExtUnitParts;
use wz_codecs::ext_zbuf::ExtZbufParts;
use wz_codecs::ext_zint::ExtZintParts;
use wz_codecs::join::{Join, JoinParts, JoinS};
use wz_codecs::transport_join::{TransportJoinParts, TransportJoinWire};
use wz_codecs::whatami::WhatAmI;
use wz_codecs::wire_const;

use crate::multicast_dispatch::JoinBaseline;
use crate::multicast_params::{
    pack_res_cbyte, unpack_res_cbyte, GroupJoinRule, MulticastParams, PROTOCOL_DEFAULT_BATCH_SIZE,
    PROTOCOL_DEFAULT_RESOLUTION,
};
use crate::sn::MulticastTxConduits;

// R311y227 — the JOIN QoS-SN extension header byte: id `0x1` | M (mandatory,
// `0x10`) | ENC_ZBUF (`0x40`) = `0x51` — byte-identical to zenoh-pico
// `_Z_MSG_EXT_ID_JOIN_QOS` (protocol/ext.h:46) and zenoh's `join::ext::QoS::ID`.
// A qos JOIN carries this ZBUF ext (`[0x51][VLE(len)][Priority::NUM * 2 VLE SNs]`)
// after the base body. The QoS ext is emitted FIRST when a Patch ext follows it,
// matching pico's own order (transport.c @ `_Z_MSG_EXT_ID_JOIN_QOS` before
// `_Z_MSG_EXT_ID_JOIN_PATCH`); the chain-MORE bit (`0x80`) it then carries, and the
// header's `Z`, are the document's, from where the entry stands ([`join_chain`]).
const JOIN_QOS_EXT_HEADER: u8 = crate::join_decode::JOIN_QOS_EXT_EID;

/// The JOIN Patch extension header byte — id `0x7`, Z64/ZINT encoding, NOT
/// mandatory, built from the SAME named constants the Init half reads
/// ([`crate::extpatch::peer_patch`]) rather than a fourth literal spelling of
/// one wire fact.
///
/// Both references carry this extension ON A JOIN, and both negotiate it PER
/// PEER off the beacon (read at the 1.10.0 pin, not inherited):
/// `commons/zenoh-protocol/src/transport/join.rs`
/// @ `pub type Patch = zextz64!(0x7, false);`, declared inside `join::ext`
/// with the comment "use the same id as Init"; and zenoh-pico
/// `include/zenoh-pico/protocol/ext.h` @ `_Z_MSG_EXT_ID_JOIN_PATCH`, which
/// spells the identical byte as `(0x07 | _Z_MSG_EXT_ENC_ZINT)`.
const JOIN_PATCH_EXT_HEADER: u8 = crate::extpatch::PATCH_EXT_ID | crate::ext_header::EXT_ENC_Z64;

/// Frame a multicast JOIN datagram for `params`:
/// `[T_MID_JOIN][version][cbyte][zid][S: res-cbyte + batch][lease vle]`
/// `[next_sn_r vle][next_sn_be vle][extension chain]`, written by the message's
/// document (`sources/codecs/transport_join.scxml`) from the fields this states.
///
/// R311kq — the S-flag optionals (`sn_res` resolution cbyte +
/// `batch_size`) are present exactly when the config departs from the
/// protocol defaults ([`MulticastParams::join_advertises_caps`], zenoh-pico
/// `_z_t_msg_make_join` parity): an omitted optional is the wire statement
/// "I run the protocol defaults", so a non-default config MUST advertise
/// or every protocol-default peer would mis-read its caps. The `S` flag that
/// announces them is the document's, from whether the body holds them.
///
/// R311kr — a whole-second lease rides the wire in SECONDS under the
/// `T` header flag ([`wire_const::FLAG_T_JOIN_T`]), pico `make_join`
/// parity (`lease % 1000 == 0` sets T, definitions/transport.c:113-115;
/// the codec then divides, codec/transport.c:59-62). The pico default
/// lease 10000ms therefore arrives as T=1 + VLE 10 — an encoder that
/// never set T was fine on its own wire (T=0 = milliseconds) but the
/// decode side MUST honor T or it mis-reads every pico beacon 1000x.
///
/// A1c — the JOIN advertises the LIVE per-channel `next_sn` from `tx_sn`
/// (the §3.2 `init_rx_seq` contract: receivers seed their RX baseline one
/// before these, so the next data frame this node mints is admitted).
///
/// [`MulticastParams::zid`] is a zid by its type, so the write the cbyte's length
/// nibble needs always holds.
#[cfg(feature = "alloc")]
pub fn encode_join(params: &MulticastParams, tx_sn: &MulticastTxConduits) -> Vec<u8> {
    let mut dgram = Vec::with_capacity(JOIN_MAX_BYTES);
    encode_join_into(params, tx_sn, &mut VecSink::new(&mut dgram))
        .expect("a zid of 1 to 16 bytes, and a VecSink grows, so the JOIN is written");
    // A group that compresses (`transport/multicast/compression/enabled`) carries its beacon as
    // every other datagram, a batch with the `BatchHeader` in front: upstream's link writes the
    // JOIN through the same batch as any transport message. The sink forms below write the bare
    // JOIN; a build with no allocator does not compress.
    #[cfg(feature = "transport-compression")]
    if params.compression {
        return crate::compression::compress_batch(&dgram);
    }
    dgram
}

/// [`encode_join`] into a sink the caller holds: the same datagram, byte for
/// byte, written through the codec's own sink seam and with nothing built on a
/// heap, so a node with no allocator can beacon from an array on its stack or a
/// slot its link lends (fixed-memory step S9d; this is the "sink-based encode"
/// the module header names as the MCU follow-up).
///
/// [`encode_join`] is this over a `VecSink`, so the two cannot disagree about a
/// byte, and the byte-for-byte pins against zenoh-pico (`layer3_join`,
/// `layer3_join_qos`) hold for both. `MulticastTxConduits` and the params are read
/// exactly as the owned form reads them. `CodecError::BufferOverflow` is the
/// refusal of a sink too small for the datagram; an empty zid, which no cbyte
/// states, never reaches it, as [`MulticastParams::zid`] is a `SessionZid`.
/// Nothing is truncated and nothing falls back to a heap. [`JOIN_MAX_BYTES`] is a
/// bound that fits every datagram this function writes whatever the zid, QoS and
/// patch settings.
///
/// It writes the bare JOIN whatever [`MulticastParams::compression`] says: the batch a
/// compressing group beacons in is built by [`encode_join`], on a heap. A loop that holds no
/// allocator has no compressing group to join.
pub fn encode_join_into<S: SceSink>(
    params: &MulticastParams,
    tx_sn: &MulticastTxConduits,
    out: &mut S,
) -> Result<(), CodecError>
where
    CodecError: From<S::Error>,
{
    // R311ku — the unit projection SSOT (`crate::lease`) is shared with
    // the unicast OPEN encoder; both carry the same `_Z_FLAG_T_*_T` rule.
    let (lease_in_seconds, lease) = crate::lease::lease_to_wire(params.lease_ms);
    // A1c — the base `next_sn` is the DEFAULT (Data) conduit's LIVE SNs on a
    // non-qos beacon. R311y227 — a qos beacon writes the `{0, 0}` DECOY here
    // (zenoh `multicast/link.rs:487` sets `next_sn = PrioritySn::DEFAULT` when the
    // real per-priority SNs ride the `ext_qos`), so every qos decoder seeds from
    // the ext and IGNORES this base; a non-qos peer rejects the qos JOIN outright
    // (group-agreed), so the decoy is never consumed.
    let default_conduit = tx_sn.advertise_default();
    #[cfg(feature = "transport-qos")]
    let (base_r, base_be) = if params.is_qos {
        (0, 0)
    } else {
        (
            default_conduit.next_reliable,
            default_conduit.next_best_effort,
        )
    };
    #[cfg(not(feature = "transport-qos"))]
    let (base_r, base_be) = (
        default_conduit.next_reliable,
        default_conduit.next_best_effort,
    );
    let body = JoinParts {
        // The protocol's, not a parameter: see `MulticastParams`.
        version: wire_const::PROTOCOL_VERSION,
        // The role in the low two bits; the zid's length above them is the
        // document's, from the zid.
        cbyte: params.whatami.to_wire(),
        zid: crate::codec_owned::sent(params.zid.as_slice())?,
        s: if params.join_advertises_caps() {
            Some(JoinS {
                sn_res: pack_res_cbyte(params.seq_num_res, params.req_id_res),
                batch_size: params.batch_size,
            })
        } else {
            None
        },
        lease,
        next_sn_reliable: base_r,
        next_sn_best_effort: base_be,
    };
    // R2417 — this node's protocol PATCH level rides a JOIN transport extension
    // whenever it can emit the chain-boundary markers that level promises, which
    // on this transport is exactly `transport-fragmentation`: that feature is the
    // sole gate on `multicast_frame_or_fragments` re-framing an oversize frame at
    // all, and the chain it then builds carries the `0x2 First` marker on its
    // leading fragment (`frame_encode::FragmentChain`). Announcing a level whose
    // markers this build cannot emit would be worse than silence — a patch-1
    // receiver refuses a chain whose start marker never arrives ("First fragment
    // received without start marker"), so the announcement is gated on the emit
    // and not on the reassembly half.
    //
    // pico gates the same announcement on `Z_FEATURE_FRAGMENTATION`
    // (`src/protocol/definitions/transport.c` @ `_z_t_msg_make_join`, where
    // `has_patch` is `_patch != _Z_NO_PATCH` under that `#if`), and zenoh's
    // multicast beacon carries the level unconditionally --
    // `io/zenoh-transport/src/multicast/link.rs`
    // @ `ext_patch: PatchType::CURRENT`, a field of the `Join` its tx task
    // builds on every beacon interval.
    #[cfg(feature = "transport-fragmentation")]
    let patch =
        (crate::extpatch::CURRENT_PATCH != crate::extpatch::NO_PATCH).then_some(ExtZintParts {
            value: u64::from(crate::extpatch::CURRENT_PATCH),
        });
    #[cfg(not(feature = "transport-fragmentation"))]
    let patch: Option<ExtZintParts> = None;
    // R311y227 — the per-priority QoS-SN advertisement rides a JOIN transport
    // extension when this node offers qos on the group.
    #[cfg(feature = "transport-qos")]
    let mut sns = [0u8; QOS_EXT_BODY_BYTES];
    #[cfg(feature = "transport-qos")]
    let qos = if params.is_qos {
        Some(ExtZbufParts {
            value: crate::codec_owned::sent(qos_sns(&mut sns, &tx_sn.advertise_per_priority())?)?,
        })
    } else {
        None
    };
    #[cfg(not(feature = "transport-qos"))]
    let qos: Option<ExtZbufParts<'_>> = None;
    let (chain, entries) = join_chain(qos.as_ref(), patch.as_ref());
    // `S` follows from the body and `Z` from the chain, so a NON-qos beacon that
    // carries only the patch level still announces its chain (pico:
    // `if (next_sn._is_qos || has_patch) _Z_SET_FLAG(_Z_FLAG_T_Z)`). `T` is the
    // lease's unit, which no field carries, so it is stated here.
    let message = TransportJoinParts {
        header: if lease_in_seconds {
            wire_const::T_MID_JOIN | wire_const::FLAG_T_JOIN_T
        } else {
            wire_const::T_MID_JOIN
        },
        body: &body,
        extensions: Bounded::new(&chain[..entries]),
    };
    Ok(TransportJoinWire::encode_source(&message, out)?)
}

/// [`encode_join_into`] over a byte slice the caller holds: how many of `out`'s
/// bytes the datagram occupies. The beacon of a drive loop that keeps no heap, from
/// an array of [`JOIN_MAX_BYTES`] on its stack, where the loop does not name the
/// sink the codec writes through. `CodecError::BufferOverflow` when `out` is too
/// small.
pub fn encode_join_into_slice(
    params: &MulticastParams,
    tx_sn: &MulticastTxConduits,
    out: &mut [u8],
) -> Result<usize, CodecError> {
    let mut sink = sce_forge_runtime::codec::SliceSink::new(out);
    encode_join_into(params, tx_sn, &mut sink)?;
    Ok(sink.position())
}

/// A bound on one JOIN datagram [`encode_join_into`] writes, for a caller that
/// holds an array for it: the flags byte, the longest base body the codec writes
/// (`Join::MAX_ENCODED_BYTES`), the QoS extension (header, length and
/// `Priority::NUM * 2` SNs of at most nine VLE bytes each) and the Patch
/// extension (header and a one-byte level).
pub const JOIN_MAX_BYTES: usize = 1 + Join::MAX_ENCODED_BYTES + 2 + QOS_EXT_BODY_BYTES + 2;

/// The body of the JOIN QoS extension at its widest: `Priority::NUM * 2` SNs,
/// each a VLE of at most nine bytes.
const QOS_EXT_BODY_BYTES: usize = crate::qos::Priority::NUM * 2 * 9;

/// R311y227 — the body of the JOIN QoS-SN extension (the zenoh `join::ext::QoS` /
/// pico `_Z_MSG_EXT_ID_JOIN_QOS` ZBuf): the LIVE per-priority `next_sn` each
/// conduit will mint (`reliable` then `best_effort` per `Priority`, ascending), so
/// a receiver seeds its per-priority RX baseline one before each. Written into
/// `body` and returned as the bytes it took; the ZBuf's length in front of them is
/// the document's (`ext_zbuf.scxml`).
#[cfg(feature = "transport-qos")]
fn qos_sns<'b>(
    body: &'b mut [u8; QOS_EXT_BODY_BYTES],
    conduits: &[crate::sn::TxSn; crate::qos::Priority::NUM],
) -> Result<&'b [u8], CodecError> {
    let len = {
        let mut sns = SliceSink::new(&mut body[..]);
        for c in conduits.iter() {
            sns.write_vle_u64(c.next_reliable)?;
            sns.write_vle_u64(c.next_best_effort)?;
        }
        sns.position()
    };
    Ok(&body[..len])
}

/// The extensions a Join carries at most: the QoS SNs and the patch level.
const JOIN_EXT_ENTRIES: usize = 2;

/// What the slots of [`join_chain`]'s array that hold no entry hold; never written.
static NO_ENTRY_BODY: ExtUnitParts = ExtUnitParts {};

/// The chain a beacon carries and how many of the array's slots it fills, in
/// zenoh-pico's order (`src/protocol/codec/transport.c` @ `_Z_MSG_EXT_ID_JOIN_QOS`
/// before `_Z_MSG_EXT_ID_JOIN_PATCH`): the QoS SNs, then the patch level.
///
/// The chain-MORE bit of each entry is the document's, from where the entry
/// stands (pico's `_Z_MSG_EXT_ID_JOIN_QOS | _Z_MSG_EXT_MORE(has_patch)`), so each
/// header here is its extension's identity alone.
///
/// R2417 — the Patch entry, `[0x27][VLE(level)]`, is byte-identical to pico's
/// `_z_uint8_encode(_Z_MSG_EXT_ID_JOIN_PATCH)` + `_z_zint64_encode(_patch)` and to
/// zenoh's `zextz64!(0x7, false)` Z64 body. It is the TX half of the negotiation
/// `decode_join_patch` reads back: the level says "my fragment chains carry
/// `0x2 First` / `0x3 Drop`", which is why [`encode_join_into`] presents it on the
/// feature that makes those markers reach the wire rather than on the one that
/// reads them.
fn join_chain<'e>(
    qos: Option<&'e ExtZbufParts<'e>>,
    patch: Option<&'e ExtZintParts>,
) -> ([ExtEntryParts<'e>; JOIN_EXT_ENTRIES], usize) {
    let mut chain = [ExtEntryParts {
        header: 0,
        body: ExtEntryPartsBody::CodecZenohExtUnit(&NO_ENTRY_BODY),
    }; JOIN_EXT_ENTRIES];
    let mut entries = 0;
    if let Some(body) = qos {
        chain[entries] = ExtEntryParts {
            header: JOIN_QOS_EXT_HEADER,
            body: ExtEntryPartsBody::CodecZenohExtZbuf(body),
        };
        entries += 1;
    }
    if let Some(body) = patch {
        chain[entries] = ExtEntryParts {
            header: JOIN_PATCH_EXT_HEADER,
            body: ExtEntryPartsBody::CodecZenohExtZint(body),
        };
        entries += 1;
    }
    (chain, entries)
}

/// R2417 — the announcer's protocol PATCH level from a JOIN's extension chain,
/// or [`crate::extpatch::NO_PATCH`] when the beacon carries none (no `Z` header
/// flag, an unparseable chain, or a chain with no `0x7` entry).
///
/// ## Why this walks the whole chain rather than peeking one ext
///
/// The Patch ext has no fixed position: pico emits it after the QoS ext on a qos
/// beacon and as the ONLY ext on a non-qos one, and it sets the `Z` header flag
/// in both cases (`_z_t_msg_make_join`: `next_sn._is_qos || has_patch`). A reader
/// that assumed a position would therefore see a patch level from exactly one of
/// the two beacon shapes.
///
/// So the chain is the one the message's document reads
/// ([`crate::join_decode::read_join`], under the depth bound a node reads of a
/// transport chain), walked entry by entry where it lies and never owned, so a
/// build with no allocator reads it too; each entry is matched by
/// [`crate::extpatch::patch_of_entry`], the rule [`crate::extpatch::peer_patch`]
/// applies to an owned Init chain. The Init and Join halves of one wire fact are
/// read by one rule each way.
#[cfg(feature = "reassembly")]
pub fn decode_join_patch(bytes: &[u8]) -> u8 {
    let Some((join, _)) = crate::join_decode::read_join(bytes) else {
        return crate::extpatch::NO_PATCH;
    };
    crate::ext_view::walked(join.extensions.as_ref())
        .find_map(|entry| crate::extpatch::patch_of_entry(&entry))
        .unwrap_or(crate::extpatch::NO_PATCH)
}

/// R311y227 — the announcer's per-priority next-SN pairs from a JOIN's QoS-SN
/// extension, or `None` when the JOIN carries none (a non-qos beacon) or does
/// not read ([`crate::join_decode::read_join`]).
///
/// The extension is found in the chain the message's document reads by its
/// identity, wherever it stands, as upstream finds it
/// (`commons/zenoh-codec/src/transport/join.rs` @ `match iext::eid(ext) {`) and
/// as the passive observer finds it in the same chain owned; its body is read by
/// the one reader both use ([`crate::join_decode::qos_next_sns`]).
#[cfg(feature = "transport-qos")]
pub fn decode_join_qos(
    bytes: &[u8],
) -> Option<[crate::sn::MulticastRxPair; crate::qos::Priority::NUM]> {
    use crate::ext_view::ExtEntryView as _;
    let (join, _) = crate::join_decode::read_join(bytes)?;
    let qos = crate::ext_view::find_by_eid_in(
        crate::ext_view::walked(join.extensions.as_ref()),
        crate::join_decode::JOIN_QOS_EXT_EID,
    )?;
    crate::join_decode::qos_next_sns(qos.plain_zbuf()?)
}

/// The JOIN `dgram` holds with its extension chain taken away, written back by its
/// document, which clears `Z` for a chain that is not there: the beacon of a peer
/// that announces nothing, with this beacon's header and body.
#[cfg(test)]
pub(crate) fn join_without_chain(dgram: &[u8]) -> std::vec::Vec<u8> {
    let (join, _) = crate::join_decode::read_join(dgram).expect("a JOIN");
    let silent = wz_codecs::transport_join::TransportJoinView {
        extensions: None,
        ..join
    };
    let mut slot = [0u8; JOIN_MAX_BYTES];
    let len = TransportJoinWire::write_window(&silent, &mut slot).expect("a JOIN fits its bound");
    slot[..len].to_vec()
}

// R311y605 — the DECODE half now lives in [`crate::join_decode`], gated on
// `codec-join` alone, because the passive observer's `parse_inbound` is a second
// consumer and is not a multicast participant. Re-exported here so every
// existing `multicast_join::decode_join` caller is unchanged, and so this
// module still reads as the JOIN wire SSOT it is.
pub use crate::join_decode::{decode_join, decode_join_named, decode_join_zid};

/// §3.2 rejection rules for an inbound JOIN announcement, ahead of
/// [`MulticastDispatcher::ingest_join`](crate::multicast_dispatch::MulticastDispatcher::ingest_join)
/// (the dispatcher's documented contract: "the caller has already
/// validated the Join"). Mirrors zenoh-pico's checks — version
/// (`_z_multicast_handle_join_inner` proto-version guard) and the
/// seq-num / req-id resolution + batch-size compatibility from the same
/// pico incompatible-config guard (multicast has no negotiation, so
/// peers must already agree; R311ko batch, R311kq req-id).
///
/// R311kq — omitted-optional semantics are pico's decode semantics: an
/// absent `sn_res` / `batch_size` means the PROTOCOL defaults
/// ([`PROTOCOL_DEFAULT_RESOLUTION`] / [`PROTOCOL_DEFAULT_BATCH_SIZE`],
/// codec/transport.c:155-157), NOT this node's local config — a
/// non-default announcer advertises (S=1). The advertised resolution
/// cbyte packs `seq_num_res` (bits 0-1) + `req_id_res` (bits 2-3); the
/// codec carries it opaque, so it is decomposed here
/// ([`unpack_res_cbyte`]) — comparing the whole byte against the 2-bit
/// `seq_num_res` would refuse every compatible S=1 announcer.
/// Returns the admitted baselines (per-channel SN + the announcer's
/// advertised lease, both stored per peer by `ingest_join` — R311ks), or
/// the term the announcement does not share with this node when it must be
/// ignored (counted, not a peer-FSM transition). The lease is NOT validated — any
/// advertisement is accepted (pico parity; the Router caps the hold
/// window locally).
///
/// A Join of another protocol version is ignored, as both references do
/// (zenoh `io/zenoh-transport/src/multicast/rx.rs` @
/// `if join.version != self.manager.config.version {`, pico
/// `src/transport/multicast/rx.c` @ `if (msg->_version != Z_PROTO_VERSION) {`).
/// The version compared against is the protocol's own, which neither reference
/// lets a node configure.
///
/// The one judge of a Join, for both rules a node may follow ([`GroupJoinRule`]):
/// `peer_offers_qos` says whether the Join offers per-priority conduits, which
/// zenoh's rule refuses a node that offers none. What becomes of a KNOWN member
/// whose Join is refused is the rule's too, and is the caller's to carry out
/// (`dispatch_multicast_message`).
pub fn judge_join(
    join: &Join<'_>,
    params: &MulticastParams,
    peer_offers_qos: bool,
) -> Result<JoinBaseline, JoinMismatch> {
    if join.version != wz_codecs::wire_const::PROTOCOL_VERSION {
        return Err(JoinMismatch::Version);
    }
    let res_cbyte = join.s.map_or(
        pack_res_cbyte(PROTOCOL_DEFAULT_RESOLUTION, PROTOCOL_DEFAULT_RESOLUTION),
        |s| s.sn_res,
    );
    let (seq_num_res, req_id_res) = unpack_res_cbyte(res_cbyte);
    if seq_num_res != params.seq_num_res || req_id_res != params.req_id_res {
        return Err(JoinMismatch::Resolution);
    }
    if join.s.map_or(PROTOCOL_DEFAULT_BATCH_SIZE, |s| s.batch_size) != params.batch_size {
        return Err(JoinMismatch::BatchSize);
    }
    if params.join_rule == GroupJoinRule::Zenoh && peer_offers_qos && !params.is_qos {
        return Err(JoinMismatch::Qos);
    }
    Ok(JoinBaseline {
        sn_res: seq_num_res,
        next_sn_reliable: join.next_sn_reliable,
        next_sn_best_effort: join.next_sn_best_effort,
        // Always milliseconds here — decode_join projected the wire
        // T-flag seconds form back before this point (R311kr).
        lease_ms: join.lease,
        // The announcer's node role, for the member view and the on-group
        // Designated-Router election (§5.21 I3b). `from_wire` maps the 2-bit
        // JOIN whatami (Router=0b00); an unrecognized code yields `None`.
        whatami: WhatAmI::from_wire(join.whatami()),
    })
}

/// The term a refused Join does not share with the node that judged it ([`judge_join`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum JoinMismatch {
    /// Another protocol version.
    Version,
    /// Another sequence-number or request-id resolution.
    Resolution,
    /// Another batch size.
    BatchSize,
    /// Per-priority conduits offered to a node of zenoh's rule that offers none.
    Qos,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sn;
    use std::vec::Vec;
    use wz_codecs::whatami::WhatAmI;

    fn params(zid: &[u8]) -> MulticastParams {
        MulticastParams {
            whatami: WhatAmI::Peer,
            zid: crate::multicast_params::zid_vec(zid),
            lease_ms: 5_000,
            join_interval_ms: 1,
            seq_num_res: 0x02,
            req_id_res: 0x02,
            batch_size: 2_048,
            is_qos: false,
            compression: false,
            tx_queue: crate::session_init_params::TxQueueConf::of_policy(
                &crate::policy::SessionPolicy::defaults(),
            ),
            link_rx: crate::session_init_params::LinkRxConf::default(),
            join_rule: GroupJoinRule::Pico,
            max_sessions: None,
        }
    }

    /// The judge's verdict on a Join that offers no per-priority conduits, as the baseline it
    /// admits with.
    fn validate_join(join: &Join<'_>, params: &MulticastParams) -> Option<JoinBaseline> {
        judge_join(join, params, false).ok()
    }

    /// Both rules refuse a member whose batch size is not the node's own, and say why: zenoh's
    /// 8,192-byte multicast batch and zenoh-pico's 2,048 are not read by each other.
    #[test]
    fn a_join_of_another_batch_size_is_refused_by_either_rule() {
        let zid = [0x01, 0x02, 0x03, 0x04];
        let mut theirs = params(&zid);
        theirs.batch_size = 8_192;
        let bytes = encode_join(
            &theirs,
            &MulticastTxConduits::new(sn::mask_from_res(theirs.seq_num_res)),
        );
        let join = decode_join(&bytes).expect("a Join");
        for rule in [GroupJoinRule::Zenoh, GroupJoinRule::Pico] {
            let mut ours = params(&[0xAA]);
            ours.join_rule = rule;
            assert_eq!(
                judge_join(&join, &ours, false).err(),
                Some(JoinMismatch::BatchSize),
                "{rule:?}"
            );
            ours.batch_size = 8_192;
            assert!(
                judge_join(&join, &ours, false).is_ok(),
                "{rule:?}, same batch"
            );
        }
    }

    /// A Join that offers per-priority conduits, to a node that offers none: zenoh's rule refuses
    /// it, zenoh-pico's has no such rule and admits it, and a node that offers them admits it
    /// under either.
    #[test]
    fn a_qos_join_to_a_node_without_qos_is_refused_by_zenohs_rule_only() {
        let zid = [0x01, 0x02, 0x03, 0x04];
        let bytes = encode_join(
            &params(&zid),
            &MulticastTxConduits::new(sn::mask_from_res(0x02)),
        );
        let join = decode_join(&bytes).expect("a Join");
        let mut ours = params(&[0xAA]);
        ours.join_rule = GroupJoinRule::Zenoh;
        assert_eq!(
            judge_join(&join, &ours, true).err(),
            Some(JoinMismatch::Qos)
        );
        ours.is_qos = true;
        assert!(judge_join(&join, &ours, true).is_ok(), "a node with QoS");
        ours.is_qos = false;
        ours.join_rule = GroupJoinRule::Pico;
        assert!(judge_join(&join, &ours, true).is_ok(), "zenoh-pico's rule");
    }

    /// `encode_join_into` an array of the caller's own writes the datagram
    /// `encode_join` writes, byte for byte, across the settings that change its
    /// shape: the zid width, a protocol-default config (no S optionals) against a
    /// departing one, a whole-second lease (the `T` flag) against a millisecond one,
    /// and, where the build emits them, the QoS and Patch extensions with SNs that
    /// are one and several VLE bytes wide. A sink one byte short is REFUSED, never
    /// cut, and every datagram fits [`JOIN_MAX_BYTES`].
    #[test]
    fn encode_join_into_writes_the_datagram_encode_join_writes() {
        use sce_forge_runtime::codec::SliceSink;
        let mut compared = 0usize;
        let mut widest = 0usize;
        for zid_len in [1usize, 4, 16] {
            let zid = std::vec![0x5a; zid_len];
            for config in [protocol_default_params(&zid), params(&zid)] {
                for lease_ms in [10_000u64, 5_001] {
                    for is_qos in [false, true] {
                        let p = MulticastParams {
                            lease_ms,
                            is_qos,
                            ..config.clone()
                        };
                        for advance in [0usize, 1, 200] {
                            let mut tx = MulticastTxConduits::new(sn::mask_from_res(p.seq_num_res));
                            for _ in 0..advance {
                                for wire in 0..crate::qos::Priority::NUM as u8 {
                                    let priority = crate::qos::Priority::from_wire(wire);
                                    tx.mint(priority, true);
                                    tx.mint(priority, false);
                                }
                            }
                            let owned = encode_join(&p, &tx);
                            let mut slot = [0u8; JOIN_MAX_BYTES];
                            let mut sink = SliceSink::new(&mut slot);
                            encode_join_into(&p, &tx, &mut sink).expect("fits its bound");
                            let written = sink.position();
                            assert_eq!(
                                &slot[..written],
                                &owned[..],
                                "zid {zid_len} lease {lease_ms} qos {is_qos} advance {advance}"
                            );
                            // An oracle that is not this encoder: what the decoders
                            // read back out of the written datagram is what the
                            // params and the conduits said.
                            assert_eq!(decode_join_zid(&slot[..written]), Some(&zid[..]));
                            #[cfg(feature = "transport-qos")]
                            if is_qos {
                                let advertised = tx.advertise_per_priority();
                                let read = decode_join_qos(&slot[..written]).expect("a qos JOIN");
                                for (priority, (seen, said)) in
                                    read.iter().zip(advertised.iter()).enumerate()
                                {
                                    assert_eq!(
                                        (seen.reliable, seen.best_effort),
                                        (said.next_reliable, said.next_best_effort),
                                        "priority {priority}, advance {advance}"
                                    );
                                }
                            }
                            // The extension that FOLLOWS the QoS body is what shows a
                            // body length that is one off: it is read from where the
                            // length says the body ends.
                            #[cfg(all(
                                feature = "transport-fragmentation",
                                feature = "reassembly"
                            ))]
                            assert_eq!(
                                decode_join_patch(&slot[..written]),
                                crate::extpatch::CURRENT_PATCH,
                                "the patch level after the body is read back"
                            );
                            widest = widest.max(written);
                            // One byte short of the datagram is refused, not cut.
                            let mut short = std::vec![0u8; written - 1];
                            let mut sink = SliceSink::new(&mut short);
                            assert_eq!(
                                encode_join_into(&p, &tx, &mut sink),
                                Err(CodecError::BufferOverflow),
                                "a sink one byte short is refused"
                            );
                            compared += 1;
                        }
                    }
                }
            }
        }
        assert_eq!(compared, 3 * 2 * 2 * 2 * 3, "the matrix ran");
        assert!(
            widest <= JOIN_MAX_BYTES,
            "the bound fits the widest datagram written ({widest})"
        );
    }

    /// A compressing group's beacon is a batch of the one JOIN: the `BatchHeader` in front, and
    /// what it gives back is the datagram a plain group sends.
    #[cfg(feature = "transport-compression")]
    #[test]
    fn a_compressing_groups_beacon_is_the_plain_beacon_as_a_batch() {
        let plain = params(&[0xAA, 0xBB, 0xCC, 0xDD]);
        let squeezing = MulticastParams {
            compression: true,
            ..params(&[0xAA, 0xBB, 0xCC, 0xDD])
        };
        let tx = MulticastTxConduits::new(sn::mask_from_res(plain.seq_num_res));
        let bare = encode_join(&plain, &tx);
        let wrapped = encode_join(&squeezing, &tx);
        assert_eq!(wrapped, crate::compression::compress_batch(&bare));
        assert_eq!(
            crate::compression::decompress_batch(&wrapped, usize::from(squeezing.batch_size))
                .as_deref(),
            Some(&bare[..])
        );
    }

    /// A fresh announcer's JOIN datagram (both advertised next SNs = 0) —
    /// the wire-shape fixtures only need SOME valid beacon.
    fn join0(p: &MulticastParams) -> Vec<u8> {
        encode_join(
            p,
            &MulticastTxConduits::new(sn::mask_from_res(p.seq_num_res)),
        )
    }

    /// A params bundle at the PROTOCOL defaults (8192 / 0x02 / 0x02) —
    /// the only config whose JOIN is minimal (S=0) under the R311kq
    /// pico `make_join` parity.
    fn protocol_default_params(zid: &[u8]) -> MulticastParams {
        MulticastParams {
            batch_size: PROTOCOL_DEFAULT_BATCH_SIZE,
            ..params(zid)
        }
    }

    /// The beacon a fresh announcer sends, laid out byte by byte in the order
    /// both references write a Join (`commons/zenoh-codec/src/transport/join.rs`
    /// @ `impl<W> WCodec<&Join, &mut W> for Zenoh080`, zenoh-pico
    /// `_z_join_encode`): an oracle that is neither this encoder nor the
    /// document it writes through. The chain is the one this build emits: the
    /// QoS SNs where it offers per-priority conduits, then the patch level where
    /// it emits fragment chains with their markers.
    #[test]
    fn a_beacon_is_the_bytes_both_references_lay_out() {
        let qos = cfg!(feature = "transport-qos");
        let patch = cfg!(feature = "transport-fragmentation");
        let mut p = params(&[0x01, 0x02, 0x03, 0x04]);
        p.is_qos = qos;
        let tx = MulticastTxConduits::new(sn::mask_from_res(p.seq_num_res));
        let mut expected = std::vec![
            // mid 0x07; T, a lease of whole seconds; S, a batch size off the
            // protocol's; Z, when a chain follows
            0x07 | 0x20 | 0x40 | if qos || patch { 0x80 } else { 0x00 },
            0x09, // the protocol version
            0x31, // whatami peer, and the zid length less one in the high nibble
            0x01,
            0x02,
            0x03,
            0x04,
            0x0a, // the SN resolution 2, the request id resolution 2 above it
            0x00,
            0x08, // the batch size 2048, little endian
            0x05, // the lease, 5 s
            0x00, // next reliable SN; under QoS the decoy upstream writes
            0x00, // next best-effort SN, likewise
        ];
        if qos {
            // id 1, mandatory, a ZBuf, chained when the patch level follows; a
            // length of 16; eight priorities of two one-byte SNs, all 0
            expected.push(if patch { 0xd1 } else { 0x51 });
            expected.push(16);
            expected.extend_from_slice(&[0x00; 16]);
        }
        if patch {
            // id 7, a z64, not mandatory, the last entry; level 1
            expected.extend_from_slice(&[0x27, 0x01]);
        }
        assert_eq!(encode_join(&p, &tx), expected);
    }

    /// A zid the cbyte cannot state never reaches the encoder: the cbyte holds
    /// the zid's length less one, so an empty zid has none, and
    /// `MulticastParams::zid` is a `SessionZid`, which refuses one where the
    /// parameters are made. A one-byte zid, the shortest there is, is written.
    #[test]
    fn a_join_of_no_zid_is_refused_where_its_params_are_made() {
        assert_eq!(
            crate::session_zid::SessionZid::new(&[]),
            Err(crate::session_zid::ZidError::LengthOutOfRange { len: 0 })
        );
        let tx = MulticastTxConduits::new(sn::mask_from_res(0x02));
        let mut slot = [0u8; JOIN_MAX_BYTES];
        let written = encode_join_into_slice(&params(&[0x01]), &tx, &mut slot).expect("written");
        assert_eq!(decode_join_zid(&slot[..written]), Some(&[0x01u8][..]));
    }

    /// `encode_join` frames a JOIN whose MID is `T_MID_JOIN` and whose
    /// body round-trips back to the announcer zid through
    /// `decode_join_zid` (the fixture batch 2048 is non-default, so the
    /// header also carries S — masked out of the MID compare).
    #[test]
    fn encode_join_round_trips_zid() {
        let zid = [0xAA, 0xBB, 0xCC, 0xDD];
        let dgram = join0(&params(&zid));
        assert_eq!(dgram[0] & 0x1f, wire_const::T_MID_JOIN);
        assert_eq!(decode_join_zid(&dgram), Some(&zid[..]));
    }

    /// R311kq — a protocol-default config emits the minimal JOIN BODY (S=0,
    /// no optionals): omitted IS the honest advertisement of the
    /// protocol defaults (pico `make_join` sets S only off-default).
    /// The fixture's whole-second lease (5000ms) still rides the T flag
    /// (R311kr) — T is the lease UNIT, orthogonal to the S caps.
    ///
    /// R2417 — "minimal" is about the BODY optionals and no longer about the
    /// whole datagram: a `transport-fragmentation` build now announces its
    /// patch level in an extension, so the `Z` flag rides even at the protocol
    /// defaults (pico does the same — its `_z_t_msg_make_join` sets `Z` on
    /// `next_sn._is_qos || has_patch`, and `has_patch` is unconditional under
    /// `Z_FEATURE_FRAGMENTATION`). The mask below therefore admits Z, and the
    /// clause it protects — that S and the two optionals stay off — is
    /// unchanged and still asserted.
    #[test]
    fn encode_join_is_minimal_at_protocol_defaults() {
        let p = protocol_default_params(&[0x01, 0x02, 0x03, 0x04]);
        let dgram = join0(&p);
        assert_eq!(dgram[0] & wire_const::FLAG_T_JOIN_S, 0, "no S flag");
        assert_eq!(
            dgram[0]
                & !(wire_const::FLAG_T_JOIN_S | wire_const::FLAG_T_JOIN_T | wire_const::FLAG_T_Z),
            wire_const::T_MID_JOIN
        );
        let join = decode_join(&dgram).expect("JOIN decodes");
        assert_eq!(join.s, None);
        assert!(
            validate_join(&join, &p).is_some(),
            "protocol-default group admits the minimal JOIN"
        );
    }

    /// R311kq — a non-default config (batch 2048) advertises S=1 with
    /// the packed resolution cbyte (seq 0x02 | req 0x02 << 2 = 0x0A) +
    /// batch, and a same-config group admits it through the cbyte
    /// decomposition (the pre-R311kq whole-byte compare refused every
    /// compatible S=1 announcer).
    #[test]
    fn encode_join_advertises_non_default_caps() {
        let zid = [0x01, 0x02, 0x03, 0x04];
        let p = params(&zid);
        let dgram = join0(&p);
        assert_ne!(dgram[0] & wire_const::FLAG_T_JOIN_S, 0, "S flag set");
        let join = decode_join(&dgram).expect("JOIN decodes");
        assert_eq!(join.s.map(|s| s.sn_res), Some(0x0A), "seq 2 | req 2 << 2");
        assert_eq!(join.s.map(|s| s.batch_size), Some(2_048));
        assert!(
            validate_join(&join, &p).is_some(),
            "same-config group admits the advertised caps"
        );
    }

    // ── R2417: the JOIN's protocol PATCH level (id 0x7), the per-peer
    //    negotiation both references run off the beacon ──

    /// R2417 — the beacon ANNOUNCES this node's patch level, and it reads back
    /// as that level through the production decoder.
    ///
    /// Both halves matter and neither implies the other: the bytes pin the wire
    /// form against the two references (header `0x27` = id 7 | Z64, not
    /// mandatory; then a VLE level), and the round trip pins that
    /// [`decode_join_patch`] finds it where [`encode_join`] put it. A test that
    /// only round-tripped would pass on any self-consistent private spelling.
    #[test]
    #[cfg(all(feature = "transport-fragmentation", feature = "reassembly"))]
    fn a_beacon_announces_this_nodes_patch_level() {
        let p = protocol_default_params(&[0x01, 0x02, 0x03, 0x04]);
        let dgram = join0(&p);
        assert_ne!(
            dgram[0] & wire_const::FLAG_T_Z,
            0,
            "an announcing beacon sets Z: an extension chain follows"
        );
        assert_eq!(
            &dgram[dgram.len() - 2..],
            &[JOIN_PATCH_EXT_HEADER, crate::extpatch::CURRENT_PATCH],
            "the chain ends with [0x27][VLE(level)] and no chain-MORE bit -- \
             pico's `_z_uint8_encode(_Z_MSG_EXT_ID_JOIN_PATCH)` + \
             `_z_zint64_encode(_patch)`, and zenoh's `zextz64!(0x7, false)`"
        );
        assert_eq!(
            decode_join_patch(&dgram),
            crate::extpatch::CURRENT_PATCH,
            "the announced level reads back through the production decoder"
        );
    }

    /// R2417 — a qos beacon carries BOTH extensions, and each decoder reads its
    /// own off the same datagram.
    ///
    /// This is the case a positional reader gets wrong. The Patch ext is second
    /// here and FIRST on the non-qos beacon above, so a decoder that peeked at
    /// one offset would report a level from exactly one of the two shapes. The
    /// chain-MORE bit on the QoS header is what makes the walk reach the second
    /// entry at all, which is why it is asserted as a byte rather than inferred
    /// from the patch level being found.
    #[test]
    #[cfg(all(
        feature = "transport-qos",
        feature = "transport-fragmentation",
        feature = "reassembly"
    ))]
    fn a_qos_beacon_chains_the_patch_ext_behind_the_qos_ext() {
        let mut p = params(&[0x01, 0x02, 0x03, 0x04]);
        p.is_qos = true;
        let dgram = join0(&p);
        let (join, _) = crate::join_decode::read_join(&dgram).expect("a JOIN");
        let first = crate::ext_view::walked(join.extensions.as_ref())
            .next()
            .expect("a chain");
        assert_eq!(
            first.header,
            JOIN_QOS_EXT_HEADER | crate::ext_header::EXT_FLAG_Z,
            "the QoS ext chains to the Patch ext behind it -- pico's \
             `_Z_MSG_EXT_ID_JOIN_QOS | _Z_MSG_EXT_MORE(has_patch)`"
        );
        assert!(
            decode_join_qos(&dgram).is_some(),
            "the qos advertisement is still readable with the chain grown"
        );
        assert_eq!(
            decode_join_patch(&dgram),
            crate::extpatch::CURRENT_PATCH,
            "and so is the patch level BEHIND it"
        );
    }

    /// R2417 — a beacon that announces nothing reads as
    /// [`crate::extpatch::NO_PATCH`], which is the state the marker rules must
    /// stay off for.
    ///
    /// The fixture is the real beacon with its chain REMOVED and `Z` cleared —
    /// the wire a peer built without fragmentation support emits (pico with
    /// `Z_FEATURE_FRAGMENTATION == 0`: `has_patch` false, so no ext and no `Z`).
    /// Deriving it from the production encoder rather than hand-writing a
    /// datagram keeps the body shape honest; only the announcement is taken
    /// away.
    #[test]
    #[cfg(all(feature = "transport-fragmentation", feature = "reassembly"))]
    fn a_beacon_that_announces_nothing_reads_as_no_patch() {
        let p = protocol_default_params(&[0x01, 0x02, 0x03, 0x04]);
        let dgram = join0(&p);
        let silent = join_without_chain(&dgram);
        assert_eq!(silent[0] & wire_const::FLAG_T_Z, 0, "no chain, no Z");
        assert_eq!(
            decode_join_patch(&silent),
            crate::extpatch::NO_PATCH,
            "no chain means no announcement, not a default level"
        );
        // And the SAME truncation with `Z` still set is a chain that is not
        // there: a decoder that walked past the body would read body-adjacent
        // bytes as an ext header. It must refuse, not invent.
        let mut lying = silent;
        lying[0] |= wire_const::FLAG_T_Z;
        assert_eq!(
            decode_join_patch(&lying),
            crate::extpatch::NO_PATCH,
            "an unparseable chain is an absent announcement, never a level"
        );
    }

    /// Every reader of a received JOIN reads the chain its document reads, so a
    /// JOIN whose `Z` announces a chain that is not there, or whose last entry
    /// announces one more, is no JOIN to any of them, its body included; a
    /// terminated chain is read whatever its length, as upstream reads it to
    /// its end (`commons/zenoh-codec/src/transport/join.rs` @ `while has_ext {`).
    #[test]
    fn every_reader_refuses_a_join_whose_chain_does_not_read() {
        use crate::ext_header::EXT_FLAG_Z;
        use crate::join_decode::join_message_len;
        let silent = join_without_chain(&join0(&protocol_default_params(&[0x01, 0x02])));
        // The body, then `entries` unit extensions of id 0xf, chained, the last
        // one clearing `Z` when `terminated`.
        let with_units = |entries: usize, terminated: bool| {
            let mut bytes = silent.clone();
            bytes[0] |= wire_const::FLAG_T_Z;
            for i in 0..entries {
                bytes.push(if i + 1 < entries || !terminated {
                    0x0f | EXT_FLAG_Z
                } else {
                    0x0f
                });
            }
            bytes
        };
        for entries in [1, 8, 9, 40] {
            let read = with_units(entries, true);
            assert_eq!(
                join_message_len(&read),
                Some(read.len()),
                "{entries} entries"
            );
            assert_eq!(
                decode_join_zid(&read),
                Some(&[0x01u8, 0x02][..]),
                "{entries} entries"
            );
        }
        let unterminated = with_units(9, false);
        let not_there = with_units(0, true);
        for (refused, what) in [(&unterminated, "unterminated"), (&not_there, "not there")] {
            assert_eq!(join_message_len(refused), None, "{what}");
            assert!(decode_join(refused).is_none(), "{what}");
            #[cfg(feature = "transport-qos")]
            assert!(decode_join_qos(refused).is_none(), "{what}");
            #[cfg(feature = "reassembly")]
            assert_eq!(
                decode_join_patch(refused),
                crate::extpatch::NO_PATCH,
                "{what}"
            );
        }
    }

    /// The QoS SNs and the patch level are found by their extensions' identity
    /// wherever the chain holds them, as upstream finds them: the beacon's own
    /// chain behind an entry of another id reads as the beacon does.
    #[cfg(feature = "transport-qos")]
    #[test]
    fn a_joins_extensions_are_read_wherever_the_chain_holds_them() {
        use crate::qos::Priority;
        let mut p = params(&[0x01, 0x02, 0x03, 0x04]);
        p.is_qos = true;
        let mut tx = MulticastTxConduits::new(sn::mask_from_res(p.seq_num_res));
        for _ in 0..3 {
            tx.mint(Priority::Data, true);
        }
        let dgram = encode_join(&p, &tx);
        let silent = join_without_chain(&dgram);
        let mut behind = silent.clone();
        behind[0] |= wire_const::FLAG_T_Z;
        behind.push(0x0f | crate::ext_header::EXT_FLAG_Z);
        behind.extend_from_slice(&dgram[silent.len()..]);
        let read = decode_join_qos(&behind).expect("the QoS SNs, second in the chain");
        assert_eq!(Some(read), decode_join_qos(&dgram));
        assert_eq!(read[Priority::Data as usize].reliable, 3);
        #[cfg(all(feature = "transport-fragmentation", feature = "reassembly"))]
        assert_eq!(
            decode_join_patch(&behind),
            crate::extpatch::CURRENT_PATCH,
            "the patch level, third"
        );
    }

    /// R311kr — pico `make_join` lease-unit parity: a whole-second lease
    /// sets the T header flag and rides the wire in SECONDS (the pico
    /// default 10000ms beacon is T=1 + a one-byte VLE 10); `decode_join`
    /// projects it back so consumers always see milliseconds. The
    /// pre-R311kr decoder ignored T and read that beacon as 10ms.
    #[test]
    fn encode_join_whole_second_lease_rides_t_flag() {
        let mut p = protocol_default_params(&[0x01, 0x02, 0x03, 0x04]);
        p.lease_ms = 10_000;
        let dgram = join0(&p);
        assert_ne!(dgram[0] & wire_const::FLAG_T_JOIN_T, 0, "T flag set");
        // header(1) + version(1) + cbyte(1) + zid(4) -> lease VLE at 7;
        // 10 fits one VLE byte, so the raw wire value is visible here.
        assert_eq!(dgram[7], 10, "wire VLE carries seconds");
        let join = decode_join(&dgram).expect("JOIN decodes");
        assert_eq!(join.lease, 10_000, "lease projected back to ms");
    }

    /// R311kr — a sub-second-granularity lease cannot ride the seconds
    /// form: T stays clear and the lease VLE carries raw milliseconds
    /// (pico `make_join` sets T only when `lease % 1000 == 0`).
    #[test]
    fn encode_join_fractional_lease_stays_in_ms() {
        let mut p = protocol_default_params(&[0x01, 0x02, 0x03, 0x04]);
        p.lease_ms = 1_500;
        let dgram = join0(&p);
        assert_eq!(dgram[0] & wire_const::FLAG_T_JOIN_T, 0, "T flag clear");
        let join = decode_join(&dgram).expect("JOIN decodes");
        assert_eq!(join.lease, 1_500);
    }

    /// R311ks — the wire-advertised lease flows through `validate_join`
    /// into the admitted baseline (zenoh-pico `entry->_lease =
    /// msg->_lease`, multicast/rx.c:393), already projected to ms by
    /// `decode_join` (the 7s lease rides the T-flag seconds form).
    #[test]
    fn validate_join_passes_advertised_lease() {
        let mut p = protocol_default_params(&[0x01, 0x02, 0x03, 0x04]);
        p.lease_ms = 7_000;
        let dgram = join0(&p);
        let join = decode_join(&dgram).expect("JOIN decodes");
        let baseline = validate_join(&join, &p).expect("admitted");
        assert_eq!(baseline.lease_ms, 7_000);
    }

    /// R311kq — pico omitted-optional semantics: a minimal JOIN means
    /// the PROTOCOL defaults, so a non-default group (batch 2048) must
    /// refuse it (`_z_multicast_handle_join_inner` compares the decoded
    /// default 8192 against the local config).
    #[test]
    fn validate_join_rejects_minimal_join_in_non_default_group() {
        let zid = [0x01, 0x02, 0x03, 0x04];
        let minimal = join0(&protocol_default_params(&zid));
        let join = decode_join(&minimal).expect("JOIN decodes");
        assert!(
            validate_join(&join, &params(&zid)).is_none(),
            "omitted batch means 8192, not the local 2048"
        );
    }

    /// R311kq — the req-id bits of the resolution cbyte are checked too:
    /// seq matches (0x02) but req differs (0x01) -> refused (pico checks
    /// `_req_id_res != Z_REQ_RESOLUTION` in the same guard).
    #[test]
    fn validate_join_rejects_mismatched_req_id_res() {
        let p = params(&[0x01, 0x02, 0x03, 0x04]);
        let mut join = Join::new();
        join.version = wz_codecs::wire_const::PROTOCOL_VERSION;
        join.set_whatami(p.whatami.to_wire());
        join.set_zid_len_m1(3);
        join.zid = wz_codecs::Bounded::new(&[0x05u8, 0x06, 0x07, 0x08] as &[u8]).unwrap();
        join.s = Some(JoinS {
            sn_res: pack_res_cbyte(0x02, 0x01), // seq ok, req off
            batch_size: p.batch_size,
        });
        join.lease = p.lease_ms;
        assert!(validate_join(&join, &p).is_none(), "req-id mismatch");
    }

    /// A Join of another protocol version is refused whatever else it agrees
    /// on, and the same Join at the protocol's version is admitted: the pair
    /// is what shows the version is the term refused.
    #[test]
    fn validate_join_refuses_another_protocol_version() {
        let p = params(&[0x01, 0x02, 0x03, 0x04]);
        let zid = [0x05, 0x06, 0x07, 0x08];
        let join_of = |version: u8| {
            let mut join = Join::new();
            join.version = version;
            join.set_whatami(p.whatami.to_wire());
            join.set_zid_len_m1(3);
            join.zid = wz_codecs::Bounded::new(&zid[..]).unwrap();
            join.s = Some(JoinS {
                sn_res: pack_res_cbyte(p.seq_num_res, p.req_id_res),
                batch_size: p.batch_size,
            });
            join.lease = p.lease_ms;
            join
        };
        assert!(validate_join(&join_of(wz_codecs::wire_const::PROTOCOL_VERSION), &p).is_some());
        for version in [0x00, 0x05, 0x08, 0x0a] {
            assert!(
                validate_join(&join_of(version), &p).is_none(),
                "{version:#04x}"
            );
        }
    }

    /// `decode_join_zid` rejects a datagram whose MID is not `T_MID_JOIN`.
    #[test]
    fn decode_rejects_non_join_mid() {
        // A T_MID_KEEP_ALIVE (0x04) datagram, not a JOIN (the const is
        // ungated since R311kx, so the fixture can name it directly).
        let dgram = [wz_codecs::wire_const::T_MID_KEEP_ALIVE, 0x00];
        assert_eq!(decode_join_zid(&dgram), None);
        assert_eq!(decode_join_zid(&[]), None);
    }

    /// A JOIN whose zid is zero is no JOIN: it is refused where it is read, and the same
    /// JOIN naming a zid is read with that zid as the member's identity.
    #[test]
    fn a_join_naming_a_zero_zid_is_refused_where_it_is_read() {
        let p = params(&[0x01]);
        let named = encode_join(
            &p,
            &MulticastTxConduits::new(sn::mask_from_res(p.seq_num_res)),
        );
        let (_, zid) = decode_join_named(&named).expect("a Join naming a zid");
        assert_eq!(zid, [0x01]);
        // Header, version, cbyte, then the one byte of the zid.
        assert_eq!(
            named[3], 0x01,
            "the zid's byte is where the fixture writes it"
        );
        let mut zero = named.clone();
        zero[3] = 0x00;
        assert!(decode_join_named(&zero).is_none());
        assert!(decode_join(&zero).is_none());
        assert_eq!(decode_join_zid(&zero), None);
    }

    /// R311y227 — the qos JOIN round-trips its per-priority next-SN advertisement:
    /// `encode_join` sets the Z header flag + the `{0,0}` base decoy + the QoS ext
    /// (`0x51` ZBUF), and `decode_join_qos` recovers all `Priority::NUM` DISTINCT
    /// pairs exactly. A non-qos JOIN clears Z and carries no qos ext.
    #[cfg(feature = "transport-qos")]
    #[test]
    fn encode_join_qos_round_trips_per_priority_sns() {
        use crate::qos::Priority;
        let mut p = params(&[0x01, 0x02, 0x03, 0x04]);
        p.is_qos = true;
        let mut tx = MulticastTxConduits::new(sn::mask_from_res(p.seq_num_res));
        // Mint a DISTINCT number of reliable SNs per priority so the round-trip
        // proves each conduit's own advertisement (not a shared origin).
        for pri in [
            Priority::Control,
            Priority::RealTime,
            Priority::Data,
            Priority::Background,
        ] {
            for _ in 0..=(pri as usize) {
                tx.mint(pri, true);
            }
        }
        let expected = tx.advertise_per_priority();
        let dgram = encode_join(&p, &tx);
        assert_ne!(
            dgram[0] & wire_const::FLAG_T_Z,
            0,
            "a qos JOIN sets the Z (extensions-follow) header flag"
        );
        let base = decode_join(&dgram).expect("base body decodes");
        assert_eq!(
            (base.next_sn_reliable, base.next_sn_best_effort),
            (0, 0),
            "the base next_sn is the {{0,0}} decoy under qos"
        );
        let pairs = decode_join_qos(&dgram).expect("the qos ext decodes");
        for i in 0..Priority::NUM {
            assert_eq!(
                pairs[i].reliable, expected[i].next_reliable,
                "conduit {i} reliable SN round-trips"
            );
            assert_eq!(
                pairs[i].best_effort, expected[i].next_best_effort,
                "conduit {i} best-effort SN round-trips"
            );
        }
        // R311y894 — the DISSECTOR is a second reader of these same bytes, and
        // this is where the two are tied together. `dissect`'s own fixture for
        // the table is hand-laid VLEs; what makes that fixture honest is this
        // leg, which never lays a byte: the datagram is `encode_join`'s, and
        // the walked numbers are compared against `decode_join_qos`'s. A walker
        // that agreed with my reading of the layout and not with the producer
        // fails HERE and nowhere else.
        #[cfg(feature = "dissect")]
        {
            use crate::dissect::{dissect_transport_message, FieldValue};
            let walked =
                dissect_transport_message(&dgram, 0).expect("the walker rejected a produced JOIN");
            assert_eq!(
                walked.span.end,
                dgram.len(),
                "the walk must account for every byte the producer wrote"
            );
            let table = walked
                .find("extensions")
                .and_then(|e| e.find("qos"))
                .expect("the per-priority SN table must be walked, not shown as hex");
            let rows: Vec<_> = match &table.value {
                FieldValue::Nested(children) => children
                    .iter()
                    .filter(|c| c.name == "priority_sn")
                    .collect(),
                other => panic!("the qos body must be a group of rows, not {other:?}"),
            };
            assert_eq!(rows.len(), Priority::NUM, "one row per priority");
            for (i, row) in rows.iter().enumerate() {
                let uint = |name: &str| match row.find(name).map(|f| &f.value) {
                    Some(FieldValue::Uint(v)) => *v,
                    other => panic!("{name} of row {i} is not a uint: {other:?}"),
                };
                assert_eq!(
                    uint("next_sn_reliable"),
                    pairs[i].reliable,
                    "row {i} reliable SN agrees with decode_join_qos"
                );
                assert_eq!(
                    uint("next_sn_best_effort"),
                    pairs[i].best_effort,
                    "row {i} best-effort SN agrees with decode_join_qos"
                );
            }
        }

        // A non-qos JOIN carries no qos ext. R2417 — it no longer clears Z:
        // the `Z` flag says "an extension chain follows", and a non-qos beacon
        // still announces its patch level, so what distinguishes the two
        // beacons is the CHAIN CONTENT rather than the header bit. That is
        // exactly what `decode_join_qos` reads, and it is the assertion that
        // survived: a reader keyed on `Z` alone would have called this beacon
        // qos.
        let mut p2 = params(&[0x01, 0x02, 0x03, 0x04]);
        p2.is_qos = false;
        let dgram2 = encode_join(
            &p2,
            &MulticastTxConduits::new(sn::mask_from_res(p2.seq_num_res)),
        );
        assert!(
            decode_join_qos(&dgram2).is_none(),
            "a non-qos JOIN carries no qos ext"
        );
    }

    /// A richer JOIN with the S flag set (sn_res + batch_size present) still
    /// yields the announcer zid: the `s`-flag projection reads bit 6
    /// (`FLAG_T_JOIN_S`), so the optional fields stay aligned and the body
    /// decodes whole.
    #[test]
    fn decode_join_with_s_flag_extracts_zid() {
        let zid = [0x11, 0x22, 0x33];
        let mut join = Join::new();
        join.version = 0x09;
        join.set_whatami(WhatAmI::Peer.to_wire());
        join.set_zid_len_m1((zid.len() - 1) as u8);
        join.zid = wz_codecs::Bounded::new(&zid[..]).unwrap();
        // The group makes the encode write sn_res + batch_size.
        join.s = Some(JoinS {
            sn_res: 0x00,
            batch_size: 0xFFFF,
        });
        join.lease = 5_000;
        let body = join.encode_to_vec();
        let mut dgram = std::vec![wire_const::T_MID_JOIN | wire_const::FLAG_T_JOIN_S];
        dgram.extend_from_slice(&body);
        assert_eq!(decode_join_zid(&dgram), Some(&zid[..]));
    }

    /// Every Join written here is the Join its document
    /// (`sources/codecs/transport_join.scxml`) reads: the view reads the datagram
    /// whole and writes it back byte for byte, and the readers here read the same
    /// flags, body, lease (projected to milliseconds) and length out of it,
    /// across the settings that change its shape.
    #[cfg(feature = "alloc")]
    #[test]
    fn every_join_written_here_is_the_join_the_document_reads() {
        use wz_codecs::transport_join::TransportJoinView;
        let mut compared = 0usize;
        for zid_len in [1usize, 4, 16] {
            let zid = std::vec![0x5a; zid_len];
            for config in [protocol_default_params(&zid), params(&zid)] {
                for lease_ms in [10_000u64, 5_001] {
                    for is_qos in [false, true] {
                        let p = MulticastParams {
                            lease_ms,
                            is_qos,
                            ..config.clone()
                        };
                        let tx = MulticastTxConduits::new(sn::mask_from_res(p.seq_num_res));
                        let dgram = encode_join(&p, &tx);
                        let mut cursor = sce_forge_runtime::codec::SceCursor::new(&dgram);
                        let view = TransportJoinView::decode(&mut cursor).expect("decodes");
                        assert_eq!(cursor.remaining(), 0, "the view reads the Join whole");
                        assert_eq!(view.encode_to_vec(), dgram, "and writes it back");
                        assert_eq!(
                            crate::join_decode::join_message_len(&dgram),
                            Some(dgram.len())
                        );
                        let join = crate::join_decode::decode_join(&dgram).expect("decodes");
                        assert_eq!(join.zid.into_inner(), view.body.zid.into_inner());
                        assert_eq!(
                            join.lease,
                            crate::lease::lease_from_wire(
                                view.header & wire_const::FLAG_T_JOIN_T != 0,
                                view.body.lease
                            )
                        );
                        assert_eq!(join.next_sn_reliable, view.body.next_sn_reliable);
                        assert_eq!(join.next_sn_best_effort, view.body.next_sn_best_effort);
                        assert_eq!(join.s.is_some(), view.body.s.is_some());
                        compared += 1;
                    }
                }
            }
        }
        assert_eq!(compared, 3 * 2 * 2 * 2);
    }
}
