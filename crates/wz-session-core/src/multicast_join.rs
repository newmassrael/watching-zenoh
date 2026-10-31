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
//! [`validate_join`] in its RX classifier.
//!
//! Alloc note: [`encode_join`] returns an owned `Vec` and exists on the heap
//! profile only; [`encode_join_into`] writes the same datagram through a sink the
//! caller holds, and `MulticastParams` holds its zid as the session bytes of its
//! profile, so the rest of the module (the decode, the validation, the sink
//! encode) compiles with no allocator (fixed-memory step S9e).

#[cfg(feature = "alloc")]
use alloc::vec::Vec;

// R311y605 — the cursor is now `decode_join_qos`'s alone: the base-body decode
// that used to need it here moved to `crate::join_decode`. Gated, or the
// `transport-qos`-off subset build fails on an unused import under
// `-D warnings` (measured by `--features alloc,session-multicast,codec-join`).
#[cfg(feature = "transport-qos")]
use sce_forge_runtime::codec::SceCursor;
#[cfg(feature = "transport-qos")]
use sce_forge_runtime::codec::SliceSink;
#[cfg(feature = "alloc")]
use sce_forge_runtime::codec::VecSink;
use sce_forge_runtime::codec::{CodecError, SceSink};
use wz_codecs::join::Join;
use wz_codecs::whatami::WhatAmI;
use wz_codecs::wire_const;

use crate::multicast_dispatch::JoinBaseline;
use crate::multicast_params::{
    pack_res_cbyte, unpack_res_cbyte, MulticastParams, PROTOCOL_DEFAULT_BATCH_SIZE,
    PROTOCOL_DEFAULT_RESOLUTION,
};
use crate::sn::MulticastTxConduits;

// R311y227 — the JOIN QoS-SN extension header byte: id `0x1` | M (mandatory,
// `0x10`) | ENC_ZBUF (`0x40`) = `0x51` — byte-identical to zenoh-pico
// `_Z_MSG_EXT_ID_JOIN_QOS` (protocol/ext.h:46) and zenoh's `join::ext::QoS::ID`.
// A qos JOIN sets the transport-message `Z` header flag and appends this ZBUF ext
// (`[0x51][VLE(len)][Priority::NUM * 2 VLE SNs]`) after the base body. The QoS ext
// is emitted FIRST when a Patch ext follows it, matching pico's own order
// (transport.c @ `_Z_MSG_EXT_ID_JOIN_QOS` before `_Z_MSG_EXT_ID_JOIN_PATCH`), and
// carries the chain-MORE bit (`0x80`) exactly then — see [`write_join_qos_ext`].
#[cfg(feature = "transport-qos")]
const JOIN_QOS_EXT_HEADER: u8 = 0x51;
/// The ext-id mask (`_Z_EXT_FULL_ID_MASK`, ext.h:30) — strips the chain-MORE bit
/// so a chained (`0xD1`) and an un-chained (`0x51`) QoS ext compare equal.
#[cfg(feature = "transport-qos")]
const EXT_FULL_ID_MASK: u8 = 0x7F;

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
#[cfg(feature = "transport-fragmentation")]
const JOIN_PATCH_EXT_HEADER: u8 = crate::extpatch::PATCH_EXT_ID | crate::ext_header::EXT_ENC_Z64;

/// Frame a multicast JOIN datagram for `params`:
/// `[T_MID_JOIN][version][cbyte][zid][S: res-cbyte + batch][lease vle]`
/// `[next_sn_r vle][next_sn_be vle]`.
///
/// R311kq — the S-flag optionals (`sn_res` resolution cbyte +
/// `batch_size`) are present exactly when the config departs from the
/// protocol defaults ([`MulticastParams::join_advertises_caps`], zenoh-pico
/// `_z_t_msg_make_join` parity): an omitted optional is the wire statement
/// "I run the protocol defaults", so a non-default config MUST advertise
/// or every protocol-default peer would mis-read its caps. The body codec
/// omits the MID byte, so header + S flag are prepended here (mirror of
/// the tokio scouting glue's `scout_emit`).
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
#[cfg(feature = "alloc")]
pub fn encode_join(params: &MulticastParams, tx_sn: &MulticastTxConduits) -> Vec<u8> {
    let mut dgram = Vec::with_capacity(Join::MAX_ENCODED_BYTES + 1);
    encode_join_into(params, tx_sn, &mut VecSink::new(&mut dgram))
        .expect("VecSink is growable, so the JOIN never overflows it");
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
/// exactly as the owned form reads them. `CodecError::BufferOverflow` is the one
/// refusal, from a sink too small for the datagram; nothing is truncated and
/// nothing falls back to a heap. [`JOIN_MAX_BYTES`] is a bound that fits every
/// datagram this function writes whatever the zid, QoS and patch settings.
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
    let zid = &params.zid;
    let mut join = Join::new();
    // The protocol's, not a parameter: see `MulticastParams`.
    join.version = wz_codecs::wire_const::PROTOCOL_VERSION;
    join.set_whatami(params.whatami.to_wire());
    if !zid.is_empty() {
        join.set_zid_len_m1((zid.len() - 1) as u8);
        join.zid = zid.as_slice();
    }
    let advertises = params.join_advertises_caps();
    if advertises {
        join.sn_res = Some(pack_res_cbyte(params.seq_num_res, params.req_id_res));
        join.batch_size = Some(params.batch_size);
    }
    // R311ku — the unit projection SSOT (`crate::lease`) is shared with
    // the unicast OPEN encoder; both carry the same `_Z_FLAG_T_*_T` rule.
    let (lease_in_seconds, wire_lease) = crate::lease::lease_to_wire(params.lease_ms);
    join.lease = wire_lease;
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
    join.next_sn_reliable = base_r;
    join.next_sn_best_effort = base_be;
    let mut flags = if advertises {
        wire_const::FLAG_T_JOIN_S
    } else {
        0
    };
    if lease_in_seconds {
        flags |= wire_const::FLAG_T_JOIN_T;
    }
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
    let has_patch = crate::extpatch::CURRENT_PATCH != crate::extpatch::NO_PATCH;
    #[cfg(not(feature = "transport-fragmentation"))]
    let has_patch = false;
    // R311y227 — the per-priority QoS-SN advertisement rides a JOIN transport
    // extension, so the `Z` (extensions-follow) header bit is set when this node
    // offers qos on the group. R2417 — a Patch ext sets it too, so a NON-qos
    // beacon that carries only the patch level still announces its chain
    // (pico: `if (next_sn._is_qos || has_patch) _Z_SET_FLAG(_Z_FLAG_T_Z)`).
    #[cfg(feature = "transport-qos")]
    let emits_qos_ext = params.is_qos;
    #[cfg(not(feature = "transport-qos"))]
    let emits_qos_ext = false;
    if emits_qos_ext || has_patch {
        flags |= wire_const::FLAG_T_Z;
    }
    out.write_u8(flags | wire_const::T_MID_JOIN)?;
    join.encode(out, u8::from(advertises))?;
    #[cfg(feature = "transport-qos")]
    if emits_qos_ext {
        write_join_qos_ext(out, &tx_sn.advertise_per_priority(), has_patch)?;
    }
    #[cfg(feature = "transport-fragmentation")]
    if has_patch {
        write_join_patch_ext(out, crate::extpatch::CURRENT_PATCH)?;
    }
    Ok(())
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

/// R311y227 — append the JOIN QoS-SN extension: `[0x51][VLE(len)][NUM*2 VLE SNs]`
/// (the zenoh `join::ext::QoS` / pico `_Z_MSG_EXT_ID_JOIN_QOS` ZBUF). The body is
/// the LIVE per-priority `next_sn` each conduit will mint (`reliable` then
/// `best_effort` per `Priority`, ascending), so a receiver seeds its per-priority
/// RX baseline one before each. The ZBUF is VLE-length-prefixed
/// ([`crate::vle::write_zbuf`], the Zenoh080 ZBuf framing / pico
/// `_z_zsize_encode(len)`).
///
/// R2417 — `more` sets the chain-MORE bit ([`crate::ext_header::EXT_FLAG_Z`])
/// when a Patch ext follows this one, which is pico's own construction:
/// `_Z_MSG_EXT_ID_JOIN_QOS | _Z_MSG_EXT_MORE(has_patch)`
/// (`src/protocol/codec/transport.c`). It is a PARAMETER rather than a second
/// literal header constant because the bit is a property of this ext's POSITION
/// in the chain, not of its identity — the same reason
/// [`crate::ext_chain::encode_ext_chain`] patches it per position.
#[cfg(feature = "transport-qos")]
fn write_join_qos_ext<S: SceSink>(
    out: &mut S,
    conduits: &[crate::sn::TxSn; crate::qos::Priority::NUM],
    more: bool,
) -> Result<(), CodecError>
where
    CodecError: From<S::Error>,
{
    out.write_u8(if more {
        JOIN_QOS_EXT_HEADER | crate::ext_header::EXT_FLAG_Z
    } else {
        JOIN_QOS_EXT_HEADER
    })?;
    // The body is length-prefixed and its length is only known once its SNs are
    // written, so they are written into an array on the stack first: at the
    // widest, `Priority::NUM * 2` VLEs of nine bytes.
    let mut body = [0u8; QOS_EXT_BODY_BYTES];
    let mut sns = SliceSink::new(&mut body);
    for c in conduits.iter() {
        sns.write_vle_u64(c.next_reliable)?;
        sns.write_vle_u64(c.next_best_effort)?;
    }
    let len = sns.position();
    // A ZBuf: a VLE length, then that many bytes (`crate::vle::write_zbuf`'s framing).
    out.write_vle_u64(len as u64)?;
    Ok(out.write_bytes(&body[..len])?)
}

/// R2417 — append the JOIN Patch extension: `[0x27][VLE(level)]`, the LAST ext
/// in the chain (so no chain-MORE bit), byte-identical to pico's
/// `_z_uint8_encode(_Z_MSG_EXT_ID_JOIN_PATCH)` + `_z_zint64_encode(_patch)` and
/// to zenoh's `zextz64!(0x7, false)` Z64 body.
///
/// It is the TX half of the negotiation [`decode_join_patch`] reads back: the
/// level says "my fragment chains carry `0x2 First` / `0x3 Drop`", which is why
/// [`encode_join`] gates it on the feature that makes those markers reach the
/// wire rather than on the one that reads them.
#[cfg(feature = "transport-fragmentation")]
fn write_join_patch_ext<S: SceSink>(out: &mut S, level: u8) -> Result<(), CodecError>
where
    CodecError: From<S::Error>,
{
    out.write_u8(JOIN_PATCH_EXT_HEADER)?;
    Ok(out.write_vle_u64(u64::from(level))?)
}

/// R2417 — the announcer's protocol PATCH level from a JOIN's extension chain,
/// or [`crate::extpatch::NO_PATCH`] when the beacon carries none (no `Z` header
/// flag, an unparseable chain, or a chain with no `0x7` entry).
///
/// ## Why this walks the whole chain rather than peeking one ext
///
/// [`decode_join_qos`] reads only the LEADING ext, which is correct for its own
/// question because a qos beacon puts the QoS ext first. The Patch ext has no
/// such fixed position: pico emits it after the QoS ext on a qos beacon and as
/// the ONLY ext on a non-qos one, and it sets the `Z` header flag in both cases
/// (`_z_t_msg_make_join`: `next_sn._is_qos || has_patch`). A reader that
/// assumed a position would therefore see a patch level from exactly one of the
/// two beacon shapes.
///
/// So this reuses the SSOTs that already exist for the unicast half rather
/// than hand-rolling a third walker: the generated entry decoder for the Z-bit
/// continuation loop (depth-bounded by `MAX_EXT_CHAIN_DEPTH`, as the owned decode
/// is, so a malformed peer cannot pin the decoder) and
/// [`crate::extpatch::patch_of_entry`] for the id / encoding match and the level
/// projection, which [`crate::extpatch::peer_patch`] applies to an owned chain. The
/// chain is read entry by entry where it lies and never owned, so a build with no
/// allocator reads it too. The Init and Join halves of one wire fact are read by one
/// rule each way.
#[cfg(feature = "reassembly")]
pub fn decode_join_patch(bytes: &[u8]) -> u8 {
    let Some(&header) = bytes.first() else {
        return crate::extpatch::NO_PATCH;
    };
    if header & 0x1f != wire_const::T_MID_JOIN {
        return crate::extpatch::NO_PATCH;
    }
    if header & wire_const::FLAG_T_Z == 0 {
        return crate::extpatch::NO_PATCH; // no extension chain -> no patch level
    }
    // The base body's width comes from the SHARED decode, exactly as
    // `decode_join_qos` takes it (R311y605): the S-flag bit that selects two
    // optional body fields is read in ONE place.
    let Ok((_, consumed)) = crate::join_decode::decode_join_body(header, &bytes[1..]) else {
        return crate::extpatch::NO_PATCH;
    };
    let mut cursor = sce_forge_runtime::codec::SceCursor::new(&bytes[1 + consumed..]);
    // An unparseable chain, or one deeper than the bound the owned decode refuses,
    // announces nothing: it reads as the owned decode's `Err` read.
    let mut announced = None;
    for _ in 0..crate::parse_error::MAX_EXT_CHAIN_DEPTH {
        let Ok(entry) = wz_codecs::ext_entry::ExtEntry::decode(&mut cursor) else {
            return crate::extpatch::NO_PATCH;
        };
        if announced.is_none() {
            announced = crate::extpatch::patch_of_entry(&entry);
        }
        if !entry.z() {
            return announced.unwrap_or(crate::extpatch::NO_PATCH);
        }
    }
    crate::extpatch::NO_PATCH
}

/// R311y227 — decode the JOIN QoS-SN extension into the announcer's per-priority
/// next-SN pairs, or `None` when the JOIN is non-qos (no `Z` header flag, or the
/// first ext is not `JOIN_QOS_EXT_HEADER`). The base body is re-decoded to
/// position the cursor at the ext chain (cheap; the SCXML `Join` codec has no ext
/// awareness, so the trailer is hand-parsed here — the multicast twin of the
/// frame/fragment `ext_qos` hand-roll in `frame_encode`, mesh-path-B: no new
/// `sce:*`). Only the leading QoS ext is honoured (pico emits it before any Patch
/// ext, transport.c:71/90); a chained Patch ext after it is not needed here.
#[cfg(feature = "transport-qos")]
pub fn decode_join_qos(
    bytes: &[u8],
) -> Option<[crate::sn::MulticastRxPair; crate::qos::Priority::NUM]> {
    let header = *bytes.first()?;
    if header & 0x1f != wire_const::T_MID_JOIN {
        return None;
    }
    if header & wire_const::FLAG_T_Z == 0 {
        return None; // no extension chain -> non-qos JOIN
    }
    // R311y605 — the base body's width comes from the SHARED decode
    // ([`crate::join_decode::decode_join_body`]) rather than from a second
    // S-flag projection here. It used to re-decode with its own `s`, which
    // meant the bit that selects two optional body fields was read in two
    // places; the hoist that gave `parse_inbound` a JOIN arm made that three,
    // so it became one.
    let (_, consumed) = crate::join_decode::decode_join_body(header, &bytes[1..]).ok()?;
    let mut cursor = SceCursor::new(&bytes[1 + consumed..]);
    let ext_header = *cursor.peek_slice(1).ok()?.first()?;
    cursor.advance(1).ok()?;
    if ext_header & EXT_FULL_ID_MASK != JOIN_QOS_EXT_HEADER {
        return None; // leading ext is not the QoS-SN advertisement
    }
    // The ZBuf is a VLE length and that many bytes; its body is read where it lies
    // (`crate::vle::read_zbuf` copies it onto the heap, which a build with no
    // allocator does not have).
    let ext_len = usize::try_from(cursor.read_vle_u64().ok()?).ok()?;
    let ext_body = cursor.peek_slice(ext_len).ok()?;
    let mut inner = SceCursor::new(ext_body);
    let mut pairs = [crate::sn::MulticastRxPair::default(); crate::qos::Priority::NUM];
    for p in pairs.iter_mut() {
        p.reliable = inner.read_vle_u64().ok()?;
        p.best_effort = inner.read_vle_u64().ok()?;
    }
    Some(pairs)
}

// R311y605 — the DECODE half now lives in [`crate::join_decode`], gated on
// `codec-join` alone, because the passive observer's `parse_inbound` is a second
// consumer and is not a multicast participant. Re-exported here so every
// existing `multicast_join::decode_join` caller is unchanged, and so this
// module still reads as the JOIN wire SSOT it is.
pub use crate::join_decode::{decode_join, decode_join_zid};

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
/// `None` when the announcement must be ignored (a diagnostic event, not
/// a peer-FSM transition). The lease is NOT validated — any
/// advertisement is accepted (pico parity; the Router caps the hold
/// window locally).
///
/// A Join of another protocol version is ignored, as both references do
/// (zenoh `io/zenoh-transport/src/multicast/rx.rs` @
/// `if join.version != self.manager.config.version {`, pico
/// `src/transport/multicast/rx.c` @ `if (msg->_version != Z_PROTO_VERSION) {`).
/// The version compared against is the protocol's own, which neither reference
/// lets a node configure.
pub fn validate_join(join: &Join<'_>, params: &MulticastParams) -> Option<JoinBaseline> {
    if join.version != wz_codecs::wire_const::PROTOCOL_VERSION {
        return None;
    }
    let res_cbyte = join.sn_res.unwrap_or(pack_res_cbyte(
        PROTOCOL_DEFAULT_RESOLUTION,
        PROTOCOL_DEFAULT_RESOLUTION,
    ));
    let (seq_num_res, req_id_res) = unpack_res_cbyte(res_cbyte);
    if seq_num_res != params.seq_num_res || req_id_res != params.req_id_res {
        return None;
    }
    if join.batch_size.unwrap_or(PROTOCOL_DEFAULT_BATCH_SIZE) != params.batch_size {
        return None;
    }
    Some(JoinBaseline {
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
            tx_queue: crate::session_init_params::TxQueueConf::default(),
            link_rx: crate::session_init_params::LinkRxConf::default(),
        }
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
        assert_eq!(join.sn_res, None);
        assert_eq!(join.batch_size, None);
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
        assert_eq!(join.sn_res, Some(0x0A), "seq 2 | req 2 << 2");
        assert_eq!(join.batch_size, Some(2_048));
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
        let (_, consumed) =
            crate::join_decode::decode_join_body(dgram[0], &dgram[1..]).expect("body decodes");
        assert_eq!(
            dgram[1 + consumed],
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
        let (_, consumed) =
            crate::join_decode::decode_join_body(dgram[0], &dgram[1..]).expect("body decodes");
        let mut silent = dgram[..1 + consumed].to_vec();
        silent[0] &= !wire_const::FLAG_T_Z;
        assert_eq!(
            decode_join_patch(&silent),
            crate::extpatch::NO_PATCH,
            "no chain means no announcement, not a default level"
        );
        // And the SAME truncation with `Z` still set is a chain that is not
        // there: a decoder that walked past the body would read body-adjacent
        // bytes as an ext header. It must refuse, not invent.
        let mut lying = dgram[..1 + consumed].to_vec();
        lying[0] |= wire_const::FLAG_T_Z;
        assert_eq!(
            decode_join_patch(&lying),
            crate::extpatch::NO_PATCH,
            "an unparseable chain is an absent announcement, never a level"
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
        join.zid = &[0x05, 0x06, 0x07, 0x08];
        join.sn_res = Some(pack_res_cbyte(0x02, 0x01)); // seq ok, req off
        join.batch_size = Some(p.batch_size);
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
            join.zid = &zid;
            join.sn_res = Some(pack_res_cbyte(p.seq_num_res, p.req_id_res));
            join.batch_size = Some(p.batch_size);
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
        join.zid = &zid;
        join.sn_res = Some(0x00);
        join.batch_size = Some(0xFFFF);
        join.lease = 5_000;
        // s=1: sn_res + batch_size written
        let body = join.encode_to_vec(1).expect("a fixture join is encodable");
        let mut dgram = std::vec![wire_const::T_MID_JOIN | wire_const::FLAG_T_JOIN_S];
        dgram.extend_from_slice(&body);
        assert_eq!(decode_join_zid(&dgram), Some(&zid[..]));
    }
}
