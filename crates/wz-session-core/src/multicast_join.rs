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

use sce_forge_runtime::codec::SceCursor;
use wz_codecs::join::Join;
use wz_codecs::wire_const;

use crate::multicast_dispatch::JoinBaseline;
use crate::multicast_params::{
    pack_res_cbyte, unpack_res_cbyte, MulticastParams, PROTOCOL_DEFAULT_BATCH_SIZE,
    PROTOCOL_DEFAULT_RESOLUTION,
};
use crate::sn::TxSn;

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
pub fn encode_join(params: &MulticastParams, tx_sn: &TxSn) -> Vec<u8> {
    let zid = &params.zid;
    let mut join = Join::new();
    join.version = params.version;
    join.set_whatami(params.whatami);
    if !zid.is_empty() {
        join.set_zid_len_m1((zid.len() - 1) as u8);
        join.zid = zid.as_slice();
    }
    let advertises = params.join_advertises_caps();
    if advertises {
        join.sn_res = Some(pack_res_cbyte(params.seq_num_res, params.req_id_res));
        join.batch_size = Some(params.batch_size);
    }
    let lease_in_seconds = params.lease_ms % 1000 == 0;
    join.lease = if lease_in_seconds {
        params.lease_ms / 1000
    } else {
        params.lease_ms
    };
    join.next_sn_reliable = tx_sn.next_reliable;
    join.next_sn_best_effort = tx_sn.next_best_effort;
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
    dgram.push(flags | wire_const::T_MID_JOIN);
    dgram.extend_from_slice(&body);
    dgram
}

/// If `bytes` is a multicast JOIN datagram, decode its full body (a
/// borrowed view into `bytes`). Returns `None` for a non-JOIN MID or a
/// malformed body. The returned `lease` is ALWAYS milliseconds — the
/// `T` header flag's seconds form is projected back here (R311kr), so
/// consumers never see the wire unit. The caller validates the
/// announcement (§3.2 rejection rules — [`validate_join`]) before
/// feeding it to
/// [`MulticastDispatcher::ingest_join`](crate::multicast_dispatch::MulticastDispatcher::ingest_join).
pub fn decode_join(bytes: &[u8]) -> Option<Join<'_>> {
    let header = *bytes.first()?;
    if header & 0x1f != wire_const::T_MID_JOIN {
        return None;
    }
    // The `join` codec gates its optional sn_res / batch_size on `s & 0x01`,
    // so project the wire S flag (header bit 6, `FLAG_T_JOIN_S` = 0x40, per
    // zenoh-pico transport.h:61) to that bit. A minimal JOIN clears S so
    // `s` is 0, but project from the named flag (not a raw shift) so a
    // future richer JOIN decodes correctly — header bit 5 is the distinct
    // `_Z_FLAG_T_JOIN_T` lease-unit flag (handled below), NOT S, so a
    // `header >> 5` shift would read the wrong bit.
    let s = u8::from(header & wire_const::FLAG_T_JOIN_S != 0);
    let mut cursor = SceCursor::new(&bytes[1..]);
    let mut join = Join::decode(&mut cursor, s).ok()?;
    // R311kr — T flag = the lease VLE is in SECONDS; project back to the
    // milliseconds every wz consumer speaks (pico decode parity,
    // codec/transport.c:161-164: `_lease = _lease * 1000`). The default
    // pico beacon (lease 10000ms) arrives as T=1 + VLE 10, so skipping
    // this read it as 10ms. Saturating: pico multiplies unchecked, but a
    // hostile VLE near u64::MAX must not panic the RX loop.
    if header & wire_const::FLAG_T_JOIN_T != 0 {
        join.lease = join.lease.saturating_mul(1000);
    }
    Some(join)
}

/// If `bytes` is a multicast JOIN datagram, decode it and return the
/// announcer's zid (a sub-slice borrow of `bytes`). Returns `None` for a
/// non-JOIN MID or a malformed body. Thin projection of [`decode_join`].
pub fn decode_join_zid(bytes: &[u8]) -> Option<&[u8]> {
    decode_join(bytes).map(|join| join.zid)
}

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
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sn;
    use std::vec::Vec;

    fn params(zid: &[u8]) -> MulticastParams {
        MulticastParams {
            version: 0x09,
            whatami: 0x01, // PEER (wire form)
            zid: zid.to_vec(),
            lease_ms: 5_000,
            join_interval_ms: 1,
            seq_num_res: 0x02,
            req_id_res: 0x02,
            batch_size: 2_048,
        }
    }

    /// A fresh announcer's JOIN datagram (both advertised next SNs = 0) —
    /// the wire-shape fixtures only need SOME valid beacon.
    fn join0(p: &MulticastParams) -> Vec<u8> {
        encode_join(p, &TxSn::new(sn::mask_from_res(p.seq_num_res)))
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
        join.set_whatami(p.whatami);
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
        // A T_MID_KEEP_ALIVE (0x04) datagram, not a JOIN — literal so the
        // negative-path fixture doesn't pull the codec-keep-alive gate.
        let dgram = [0x04u8, 0x00];
        assert_eq!(decode_join_zid(&dgram), None);
        assert_eq!(decode_join_zid(&[]), None);
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
        join.set_whatami(0x01);
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
