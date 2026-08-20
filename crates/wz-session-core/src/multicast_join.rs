// SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! Multicast JOIN datagram surface: encode (the periodic TX beacon),
//! decode (RX classify) and validate (the §3.2 rejection rules).
//!
//! R311kt — hoisted from `wz-runtime-tokio::multicast_glue` so both
//! runtime profiles share one JOIN wire SSOT: the three functions are
//! pure (codecs + [`MulticastParams`] + [`TxSn`] only — no socket, no
//! clock, no tokio), and the MCU `#![no_std]` multicast loop cannot
//! depend on the tokio crate. The exact multicast sibling of
//! [`crate::handshake_encode`] (the unicast INIT / OPEN / CLOSE encoders,
//! hoisted for the same reason). The tokio drive loop keeps the IO: it
//! calls [`encode_join`] on the beacon tick and [`decode_join`] /
//! [`validate_join`] in its RX classifier.
//!
//! Alloc note: [`encode_join`] returns an owned `Vec` and
//! [`MulticastParams`] carries a `Vec` zid, so the module is alloc-gated
//! as a whole; a no-alloc MCU TX variant (sink-based encode, heapless
//! params) is a follow-up shaped by the MCU multicast loop itself.

use alloc::vec::Vec;

// R311y605 — the cursor is now `decode_join_qos`'s alone: the base-body decode
// that used to need it here moved to `crate::join_decode`. Gated, or the
// `transport-qos`-off subset build fails on an unused import under
// `-D warnings` (measured by `--features alloc,session-multicast,codec-join`).
#[cfg(feature = "transport-qos")]
use sce_forge_runtime::codec::SceCursor;
use wz_codecs::join::Join;
#[cfg(feature = "multicast-declarations")]
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
// (`[0x51][VLE(len)][Priority::NUM * 2 VLE SNs]`) after the base body. wz emits
// ONLY this JOIN ext, so it never carries the ext-chain MORE bit (`0x80`); a peer
// that chains a Patch ext after it (pico, when fragmentation is on) still decodes
// here because the QoS ext is emitted FIRST (transport.c:71 before :90).
#[cfg(feature = "transport-qos")]
const JOIN_QOS_EXT_HEADER: u8 = 0x51;
/// The ext-id mask (`_Z_EXT_FULL_ID_MASK`, ext.h:30) — strips the chain-MORE bit
/// so a chained (`0xD1`) and an un-chained (`0x51`) QoS ext compare equal.
#[cfg(feature = "transport-qos")]
const EXT_FULL_ID_MASK: u8 = 0x7F;

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
pub fn encode_join(params: &MulticastParams, tx_sn: &MulticastTxConduits) -> Vec<u8> {
    let zid = &params.zid;
    let mut join = Join::new();
    join.version = params.version;
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
    let body = join.encode_to_vec(u8::from(advertises));

    let mut dgram = Vec::with_capacity(1 + body.len());
    let mut flags = if advertises {
        wire_const::FLAG_T_JOIN_S
    } else {
        0
    };
    if lease_in_seconds {
        flags |= wire_const::FLAG_T_JOIN_T;
    }
    // R311y227 — the per-priority QoS-SN advertisement rides a JOIN transport
    // extension, so the `Z` (extensions-follow) header bit is set when this node
    // offers qos on the group.
    #[cfg(feature = "transport-qos")]
    if params.is_qos {
        flags |= wire_const::FLAG_T_Z;
    }
    dgram.push(flags | wire_const::T_MID_JOIN);
    dgram.extend_from_slice(&body);
    #[cfg(feature = "transport-qos")]
    if params.is_qos {
        write_join_qos_ext(&mut dgram, &tx_sn.advertise_per_priority());
    }
    dgram
}

/// R311y227 — append the JOIN QoS-SN extension: `[0x51][VLE(len)][NUM*2 VLE SNs]`
/// (the zenoh `join::ext::QoS` / pico `_Z_MSG_EXT_ID_JOIN_QOS` ZBUF). The body is
/// the LIVE per-priority `next_sn` each conduit will mint (`reliable` then
/// `best_effort` per `Priority`, ascending), so a receiver seeds its per-priority
/// RX baseline one before each. The header byte carries no chain-MORE bit (wz
/// emits only this JOIN ext); the ZBUF is VLE-length-prefixed
/// ([`crate::vle::write_zbuf`], the Zenoh080 ZBuf framing / pico
/// `_z_zsize_encode(len)`).
#[cfg(feature = "transport-qos")]
fn write_join_qos_ext(out: &mut Vec<u8>, conduits: &[crate::sn::TxSn; crate::qos::Priority::NUM]) {
    out.push(JOIN_QOS_EXT_HEADER);
    let mut body = Vec::new();
    for c in conduits.iter() {
        crate::vle::encode_vle_u64_into(&mut body, c.next_reliable);
        crate::vle::encode_vle_u64_into(&mut body, c.next_best_effort);
    }
    crate::vle::write_zbuf(out, &body);
}

/// R311y227 — decode the JOIN QoS-SN extension into the announcer's per-priority
/// next-SN pairs, or `None` when the JOIN is non-qos (no `Z` header flag, or the
/// first ext is not [`JOIN_QOS_EXT_HEADER`]). The base body is re-decoded to
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
    let ext_body = crate::vle::read_zbuf(&mut cursor)?;
    let mut inner = SceCursor::new(&ext_body);
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
pub fn validate_join(join: &Join<'_>, params: &MulticastParams) -> Option<JoinBaseline> {
    if join.version != params.version {
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
        // §5.21 router-multicast-faces (I3b) — the announcer's node role for the
        // on-group Designated-Router election. `from_wire` maps the 2-bit JOIN
        // whatami (Router=0b00); an unrecognized code yields `None`.
        #[cfg(feature = "multicast-declarations")]
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
            version: 0x09,
            whatami: WhatAmI::Peer,
            zid: zid.to_vec(),
            lease_ms: 5_000,
            join_interval_ms: 1,
            seq_num_res: 0x02,
            req_id_res: 0x02,
            batch_size: 2_048,
            is_qos: false,
        }
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

    /// R311kq — a protocol-default config emits the minimal JOIN (S=0,
    /// no optionals): omitted IS the honest advertisement of the
    /// protocol defaults (pico `make_join` sets S only off-default).
    /// The fixture's whole-second lease (5000ms) still rides the T flag
    /// (R311kr) — T is the lease UNIT, orthogonal to the S caps.
    #[test]
    fn encode_join_is_minimal_at_protocol_defaults() {
        let p = protocol_default_params(&[0x01, 0x02, 0x03, 0x04]);
        let dgram = join0(&p);
        assert_eq!(dgram[0] & wire_const::FLAG_T_JOIN_S, 0, "no S flag");
        assert_eq!(
            dgram[0] & !(wire_const::FLAG_T_JOIN_S | wire_const::FLAG_T_JOIN_T),
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
        join.version = p.version;
        join.set_whatami(p.whatami.to_wire());
        join.set_zid_len_m1(3);
        join.zid = &[0x05, 0x06, 0x07, 0x08];
        join.sn_res = Some(pack_res_cbyte(0x02, 0x01)); // seq ok, req off
        join.batch_size = Some(p.batch_size);
        join.lease = p.lease_ms;
        assert!(validate_join(&join, &p).is_none(), "req-id mismatch");
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

        // A non-qos JOIN clears Z and carries no qos ext.
        let mut p2 = params(&[0x01, 0x02, 0x03, 0x04]);
        p2.is_qos = false;
        let dgram2 = encode_join(
            &p2,
            &MulticastTxConduits::new(sn::mask_from_res(p2.seq_num_res)),
        );
        assert_eq!(
            dgram2[0] & wire_const::FLAG_T_Z,
            0,
            "a non-qos JOIN clears the Z header flag"
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
        let body = join.encode_to_vec(1); // s=1: sn_res + batch_size written
        let mut dgram = std::vec![wire_const::T_MID_JOIN | wire_const::FLAG_T_JOIN_S];
        dgram.extend_from_slice(&body);
        assert_eq!(decode_join_zid(&dgram), Some(&zid[..]));
    }
}
