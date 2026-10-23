// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! Outbound transport-handshake / close frame encoders.
//!
//! `encode_init` (InitSyn / InitAck), `encode_open` (OpenSyn / OpenAck)
//! and `encode_close` build the transport-message wire bytes for the
//! unicast session handshake and graceful close — each composes the
//! one-byte transport header (`flags | T_MID_*`) with the wz codec body
//! (`InitBody` / `OpenBody` / `Close`) and, for Init / Open, the
//! transport-message extension chain (`encode_ext_chain`). The codec
//! bodies are verified byte-identical to zenoh-pico's `_z_init_encode` /
//! `_z_open_encode` / `_z_close_encode` by the Layer 3 wire-interop
//! tests (`crates/wz-integration-tests/tests/layer3_{init_body,open_body,close}.rs`).
//!
//! Hoisted from `wz-runtime-tokio::session_glue` so both runtime profiles
//! share one outbound handshake encode SSOT — the MCU `#![no_std]`
//! profile cannot depend on the tokio crate. Pure (no runtime / no
//! tokio); owned `Vec` output makes it the alloc-profile encoder
//! (gated at the `lib.rs` module declaration). Semantically distinct
//! from `frame_encode` (which is the `T_MID_FRAME` data-plane envelope).

// Vec backs the heap wrappers of the codec-body encoders; `encode_keep_alive`
// (transport-keepalive) is a const header byte, so a keepalive-only
// subset must not carry the unused imports (CI denies warnings). `VecSink`
// is the heap `encode_close`'s alone: Init and Open are written through the
// buffer seam (`encode_init_into` / `encode_open_into`) whatever the buffer is.
#[cfg(all(
    feature = "alloc",
    any(
        feature = "codec-init-body",
        feature = "codec-open-body",
        feature = "codec-close"
    )
))]
use alloc::vec::Vec;

#[cfg(all(feature = "alloc", feature = "codec-close"))]
use sce_forge_runtime::codec::VecSink;
#[cfg(feature = "codec-init-body")]
use wz_codecs::whatami::WhatAmI;
use wz_codecs::wire_const;

#[cfg(any(feature = "codec-init-body", feature = "codec-open-body"))]
use crate::ext_chain::encode_ext_chain_into;
#[cfg(any(feature = "codec-init-body", feature = "codec-open-body"))]
use crate::session_init_params::SessionInitParams;
// The `_into` encoders write through the buffer seam, which every one of them
// reaches with `append_byte` and a sink over it. `TxBuf` is needed for the
// method call only when `EncodeBuf` is a concrete type (no lending); on a
// `dyn TxBuf` the methods resolve without the import.
#[cfg(any(
    feature = "codec-init-body",
    feature = "codec-open-body",
    feature = "codec-close"
))]
#[allow(unused_imports)]
use crate::tx_buf::{TxBuf, TxSink};
#[cfg(any(
    feature = "codec-init-body",
    feature = "codec-open-body",
    feature = "codec-close"
))]
use sce_forge_runtime::codec::CodecError;
#[cfg(any(feature = "codec-init-body", feature = "codec-open-body"))]
use wz_codecs::ext_entry::ExtEntryOwned;

#[cfg(feature = "codec-close")]
use wz_codecs::close::Close;
#[cfg(feature = "codec-init-body")]
use wz_codecs::init_body::InitBody;
#[cfg(feature = "codec-open-body")]
use wz_codecs::open_body::OpenBody;

/// Build the wire bytes for an Init frame (InitSyn if `is_ack==false`,
/// InitAck if `is_ack==true`). The codec body is the wz `InitBody`,
/// verified byte-identical to zenoh-pico's `_z_init_encode` by
/// `crates/wz-integration-tests/tests/layer3_init_body.rs`. The
/// transport-message header is one byte: `(flags) | T_MID_INIT`.
#[cfg(all(feature = "alloc", feature = "codec-init-body"))]
pub fn encode_init(
    params: &SessionInitParams,
    is_ack: bool,
    extensions: &[ExtEntryOwned],
    cookie_override: Option<&[u8]>,
) -> Result<Vec<u8>, CodecError> {
    encode_init_with_caps(
        params,
        InitCaps::of(params),
        is_ack,
        extensions,
        cookie_override,
    )
}

/// [`encode_init`] advertising `caps` rather than what `params` says as it
/// stands: the session's sender, whose advertisement is also capped by what
/// its link can receive (`SessionLinkActions::own_batch_advertisement`).
#[cfg(all(feature = "alloc", feature = "codec-init-body"))]
pub fn encode_init_with_caps(
    params: &SessionInitParams,
    caps: InitCaps,
    is_ack: bool,
    extensions: &[ExtEntryOwned],
    cookie_override: Option<&[u8]>,
) -> Result<Vec<u8>, CodecError> {
    // The worst case the codec bounds the body by, the header byte and the
    // chain's own entries (a coarse four bytes each, as the chain encoder
    // reserves): one allocation for the whole frame, as the body-then-chain
    // form it replaced made.
    let mut wire = Vec::with_capacity(1 + InitBody::MAX_ENCODED_BYTES + extensions.len() * 4);
    encode_init_into(&mut wire, params, caps, is_ack, extensions, cookie_override)?;
    Ok(wire)
}

/// The sizes an Init message advertises: the `sn_res` pair and the batch size.
///
/// Separate from [`SessionInitParams`] because the InitAck advertises the
/// SMALLER of this node's and the peer's (`InitAck.size <= InitSyn.size`, the
/// wire-spec invariant `SessionLinkActions::init_ack_params` enforces), and a
/// sender that had to clone the whole parameter bundle to say a different
/// number would copy a zid, a cookie and a signing key to do it. Naming the
/// three numbers lets the encoder read the bundle where it is.
#[cfg(feature = "codec-init-body")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InitCaps {
    /// `SessionInitParams::seq_num_res`: the frame sequence-number resolution.
    pub seq_num_res: u8,
    /// `SessionInitParams::req_id_res`: the request-id resolution.
    pub req_id_res: u8,
    /// The batch size on the wire, never the internal `0` = "unset" sentinel.
    pub batch_size: u16,
}

#[cfg(feature = "codec-init-body")]
impl InitCaps {
    /// What `params` advertises as it stands, as an InitSyn does.
    pub fn of(params: &SessionInitParams) -> Self {
        Self {
            seq_num_res: params.seq_num_res,
            req_id_res: params.req_id_res,
            // R311kj — the wire NEVER carries the internal 0 = "unset"
            // sentinel (a pico peer would adopt it and size a 0-byte TX
            // wbuf); the effective accessor is the advertisement SSOT.
            batch_size: params.effective_batch_size(),
        }
    }
}

/// [`encode_init`] into a buffer the caller chose: a heap `Vec` (what
/// [`encode_init`] passes) or the slot a link lent, so the frame is written once
/// where it will be sent and nothing is allocated to build it.
///
/// The body is the codec's BORROWED view over the parameters' own zid and the
/// cookie, not an owned copy of either, and the extension chain is written
/// straight after it (`ext_chain::encode_ext_chain_into`). A buffer
/// that cannot hold the frame refuses with `BufferOverflow` and keeps the bytes
/// it was given; the caller discards the buffer, or rolls back with
/// `TxBuf::truncate`.
///
/// `caps` is what the message advertises ([`InitCaps::of`] for an InitSyn, the
/// peer-capped value for an InitAck). The cookie rules are those of
/// [`encode_init`]'s: an InitSyn never carries one, an InitAck carries
/// `cookie_override` or, without one, the parameters' own.
#[cfg(feature = "codec-init-body")]
pub fn encode_init_into(
    buf: &mut crate::tx_buf::EncodeBuf<'_>,
    params: &SessionInitParams,
    caps: InitCaps,
    is_ack: bool,
    extensions: &[ExtEntryOwned],
    cookie_override: Option<&[u8]>,
) -> Result<(), CodecError> {
    let mut parent_flags = wire_const::FLAG_T_INIT_S;
    if is_ack {
        parent_flags |= wire_const::FLAG_T_INIT_A;
    }
    if !extensions.is_empty() {
        parent_flags |= wire_const::FLAG_T_Z;
    }

    // R86 — cookie carrier rules: InitSyn (is_ack=false) never
    // carries a cookie regardless of override. InitAck (is_ack=true)
    // uses cookie_override when supplied (production peer_zid binding
    // path from send_init_ack_with_cookie) and falls back to
    // params.cookie otherwise. cookie_override is silently ignored on
    // InitSyn because the wire-spec forbids the field there.
    let cookie: Option<&[u8]> = if is_ack {
        Some(cookie_override.unwrap_or(&params.cookie))
    } else {
        None
    };
    let body = InitBody {
        // The protocol's, not a parameter: see `SessionInitParams`.
        version: wire_const::PROTOCOL_VERSION,
        cbyte: init_cbyte(params.whatami, params.zid.len()),
        // zid is the protocol-bounded peer id (1..=16); init_cbyte
        // above already encodes its length.
        zid: &params.zid,
        sn_res: Some(pack_sn_res(caps.seq_num_res, caps.req_id_res)),
        batch_size: Some(caps.batch_size),
        cookie_len: cookie.map(|c| c.len() as u64),
        cookie,
    };

    buf.append_byte(parent_flags | wire_const::T_MID_INIT)?;
    let s = (parent_flags >> 6) & 1;
    let a = (parent_flags >> 5) & 1;
    body.encode(&mut TxSink::new(&mut *buf), s, a)?;
    encode_ext_chain_into(buf, extensions)
}

/// Build the wire bytes for an Open frame (OpenSyn / OpenAck). Body
/// is the wz `OpenBody`, verified byte-identical to zenoh-pico's
/// `_z_open_encode` by `tests/layer3_open_body.rs`.
///
/// `cookie_override` carries the OpenSyn echo path (RFC §5.M): when
/// the Initiator receives a peer InitAck via `handle_inbound`, the
/// captured cookie bytes are passed here so OpenSyn echoes them
/// verbatim. `None` falls back to `params.cookie` for tests that
/// drive OpenSyn directly without an inbound parse cycle. The
/// argument is ignored when `is_ack=true` (OpenAck carries no
/// cookie field per transport.c:300-302).
#[cfg(all(feature = "alloc", feature = "codec-open-body"))]
pub fn encode_open(
    params: &SessionInitParams,
    is_ack: bool,
    cookie_override: Option<&[u8]>,
    extensions: &[ExtEntryOwned],
) -> Result<Vec<u8>, CodecError> {
    let mut wire = Vec::with_capacity(1 + OpenBody::MAX_ENCODED_BYTES + extensions.len() * 4);
    encode_open_into(
        &mut wire,
        params,
        params.initial_sn,
        is_ack,
        cookie_override,
        extensions,
    )?;
    Ok(wire)
}

/// [`encode_open`] into a buffer the caller chose, with the Open body's
/// `initial_sn` named instead of read from `params`.
///
/// The ring origin is DERIVED at the Open seam (R311y816:
/// `SessionLinkActions::encode_open_with_role` computes it from the two zids and
/// the negotiated mask), and a sender that had to put it into a clone of the
/// parameter bundle to say so would copy the zid, the cookie and the signing key
/// for one number. Taking it as an argument leaves the bundle where it is. See
/// [`encode_init_into`] for the buffer contract.
#[cfg(feature = "codec-open-body")]
pub fn encode_open_into(
    buf: &mut crate::tx_buf::EncodeBuf<'_>,
    params: &SessionInitParams,
    initial_sn: u64,
    is_ack: bool,
    cookie_override: Option<&[u8]>,
    extensions: &[ExtEntryOwned],
) -> Result<(), CodecError> {
    // R311ku — the T flag is DERIVED, not configured: a whole-second
    // lease compacts to the seconds form, pico `_z_t_msg_make_open_syn`
    // / `_ack` parity (definitions/transport.c:196-214; the pre-ku
    // manual `lease_in_seconds` knob let wz send `T=0 + VLE 10000`
    // where pico always compacts to `T=1 + VLE 10`).
    let (lease_in_seconds, wire_lease) = crate::lease::lease_to_wire(params.lease_ms);
    let mut parent_flags = 0u8;
    if lease_in_seconds {
        parent_flags |= wire_const::FLAG_T_OPEN_T;
    }
    if is_ack {
        parent_flags |= wire_const::FLAG_T_OPEN_A;
    }
    if !extensions.is_empty() {
        parent_flags |= wire_const::FLAG_T_Z;
    }

    let cookie_bytes: &[u8] = if !is_ack {
        cookie_override.unwrap_or(&params.cookie)
    } else {
        &[]
    };
    let body = OpenBody {
        lease: wire_lease,
        initial_sn,
        cookie_len: if !is_ack {
            Some(cookie_bytes.len() as u64)
        } else {
            None
        },
        cookie: if !is_ack { Some(cookie_bytes) } else { None },
    };

    buf.append_byte(parent_flags | wire_const::T_MID_OPEN)?;
    let a = (parent_flags >> 5) & 1;
    body.encode(&mut TxSink::new(&mut *buf), a)?;
    encode_ext_chain_into(buf, extensions)
}

// R2 (R311ww) — the ext-chain serializer moved to the shared `crate::ext_chain`
// SSOT (consumed by inbound decode + the extauth dispatch's inner method chain
// too); imported above. Was an inline `fn` here.

/// Build the wire bytes for a Close frame. Body is the wz `Close`
/// (single reason byte), verified byte-identical to zenoh-pico's
/// `_z_close_encode` by `tests/layer3_close.rs`.
///
/// `session` selects the `_Z_FLAG_T_CLOSE_S` flag: `true` = graceful WHOLE-
/// SESSION close (S=1, the peer tears the logical transport down), the shape
/// every pre-multilink caller uses. `false` = LINK-ONLY close (S=0) — the
/// R311y205 transport-multilink case where one physical link of an aggregated
/// session is dropped (over the `max_links` limit, or a per-link teardown)
/// while the logical session survives on its other links. zenoh distinguishes
/// these with the same S flag (`close.rs`); pico's `_z_close_encode` carries it.
///
/// R311y839 — the last sentence here used to read "the
/// [`send_close_with_reason`](crate::session_actions::SessionLinkActions::send_close_with_reason)
/// wrapper passes `session = true`, so every existing call site is
/// byte-identical". It no longer does, and neither does the FSM's `Closing`
/// emit: both DERIVE the flag from the link set at emit time, because both tear
/// down ONE link and only the last one is the session. The receivers act on the
/// difference — zenoh branches `delete()` vs `del_link(link)`
/// (`io/zenoh-transport/src/unicast/universal/rx.rs:60-73`), which is why a
/// per-link teardown announcing S=1 made a peer drop links wz was still using.
///
/// # Why `#[inline(never)]`, which is the MEASURED half
///
/// R2450 — TO GIVE `codec-close` A NAME THE ELISION GATE CAN SEE BY
/// CONSTRUCTION, rather than by the optimizer's grace. R311y822 moved this
/// codec's truthfulness claim off its byte delta and onto a by-name witness
/// (`CODEC_ELISION_WITNESS[codec-close]` in
/// `scripts/measure-codec-footprint.sh`), because a delta between two 2.7MB
/// binaries tracks the CALLER's inline boundary at this magnitude rather than
/// the codec. But it pinned this name while the name merely HAPPENED to exist:
/// the per-symbol diff it recorded reads
/// `-86 wz_session_core::handshake_encode::encode_close (86 -> 0)`, so the
/// function was out-of-line that day and nothing held it there.
///
/// It did not stay. An 86-byte body reached from three call sites sits on the
/// inline knife edge, and a `wz-runtime-tokio` change touching neither this
/// file nor this feature pushed it across: hosted Layer F shard 1/4 has redded
/// `WITNESS MISSING codec-close` on every completed run since the
/// `15730672`..`249dc6d2` window (2026-09-05), which grew the runtime's spawn
/// and writer-queue paths. Reproduced locally at `64f5a737`, and the cause is
/// not ambiguous: the baseline symbol table holds 7455 names, both siblings
/// `encode_init` and `encode_open` are among them, and this one is absent — so
/// the codec is reachable and the table is readable, and inlining is the whole
/// of it.
///
/// The attribute is the repair R311y878 made for `decode_keep_alive` and
/// R311y802 made for `declare_envelope_extensions`, load-bearing for the
/// reason both record: out-of-line, the inlining decision cannot FLIP between
/// the baseline and the minus build, so the name the catalog's claim is
/// checked by exists in one and not in the other.
#[cfg(all(feature = "alloc", feature = "codec-close"))]
#[inline(never)]
pub fn encode_close(reason: u8, session: bool) -> Vec<u8> {
    let parent_flags = if session {
        wire_const::FLAG_T_CLOSE_S
    } else {
        0
    };
    let mut wire = Vec::with_capacity(1 + Close::MAX_ENCODED_BYTES);
    wire.push(parent_flags | wire_const::T_MID_CLOSE);
    let mut sink = VecSink::new(&mut wire);
    Close { reason }
        .encode(&mut sink)
        .expect("VecSink is infallible");
    wire
}

/// [`encode_close`] into a buffer the caller chose: the slot a link lent, so a
/// close is two bytes written where they will be sent and not a vector built to
/// be copied. The same two bytes (header with the S flag, then the reason); a
/// buffer with no room for them refuses with `BufferOverflow`.
///
/// Not `#[inline(never)]`: that attribute on [`encode_close`] gives the
/// codec-elision gate a by-name witness in the heap profile, and this form is
/// the lend-only profile's, which that gate does not build.
#[cfg(feature = "codec-close")]
pub fn encode_close_into(
    buf: &mut crate::tx_buf::EncodeBuf<'_>,
    reason: u8,
    session: bool,
) -> Result<(), CodecError> {
    let parent_flags = if session {
        wire_const::FLAG_T_CLOSE_S
    } else {
        0
    };
    buf.append_byte(parent_flags | wire_const::T_MID_CLOSE)?;
    Close { reason }.encode(&mut TxSink::new(buf))
}

/// R311y782 — the wire bytes a multicast group member puts on the group when
/// it LEAVES voluntarily. Reason GENERIC, S flag CLEAR (link-only).
///
/// Named here rather than left as two literals at each drive loop's stop arm
/// because both arguments are protocol decisions whose upstreams DISAGREE, and
/// a caller choosing them inline is a caller choosing them differently:
///
/// - zenoh sends `Close { reason: GENERIC, session: false }` — S=0 — from
///   `TransportMulticastInner::close`
///   (`io/zenoh-transport/src/multicast/transport.rs:204-229`; the reason comes
///   from its only two callers, `multicast/mod.rs:108` and
///   `multicast/manager.rs:185`, both `close::reason::GENERIC`).
/// - zenoh-pico's multicast close-send passes `link_only = false`, which SETS
///   the S flag (`_z_multicast_send_close`,
///   `src/transport/multicast/transport.c:164-175` ->
///   `_z_t_msg_make_close`, `src/protocol/definitions/transport.c:228-238`) —
///   the OPPOSITE bit.
///
/// wz follows zenoh, and the tie-break is REACHABILITY rather than taste:
/// pico's multicast close-send is dead code in the vendored tree. Its only
/// callers are `_z_send_close` and `_z_transport_close`
/// (`src/transport/transport.c:60-79`), and nothing in the library calls
/// either — so zenoh is the only upstream that actually puts a multicast Close
/// on the wire, and matching observed traffic beats matching an unreachable
/// declaration.
///
/// The bit is unobservable to both upstreams' receivers in any case, which is
/// why the divergence is survivable at all: zenoh's multicast RX destructures
/// `Close { reason, .. }` and discards `session`
/// (`io/zenoh-transport/src/multicast/rx.rs:310-313`), and pico's drops the
/// peer on the MID alone (`src/transport/multicast/rx.c:513-536`). wz's own
/// receiver reads neither field — [`crate::multicast_rx`] classifies on the
/// MID and hands `close_by_src` back to the loop. Recorded rather than
/// resolved by guesswork, so a later round that finds a receiver which DOES
/// read the flag knows exactly which choice to revisit.
///
/// Contrast [`encode_close`]'s `session = true` unicast callers: there the
/// whole logical session is torn down, and the S bit is the only thing
/// separating that from dropping one link of an aggregated session.
#[cfg(all(feature = "alloc", feature = "codec-close"))]
pub fn encode_multicast_close() -> Vec<u8> {
    encode_close(MULTICAST_CLOSE_REASON, MULTICAST_CLOSE_SESSION)
}

/// The reason a group member's voluntary departure carries: see
/// [`encode_multicast_close`] for why both constants are what they are.
#[cfg(feature = "codec-close")]
const MULTICAST_CLOSE_REASON: u8 = crate::close_reason::CloseReason::Generic as u8;

/// The scope of that Close: link-only, the S flag clear.
#[cfg(feature = "codec-close")]
const MULTICAST_CLOSE_SESSION: bool = false;

/// [`encode_multicast_close`] into a byte slice the caller holds: how many of `out`'s
/// bytes the datagram occupies (two). The departing Close of a drive loop that keeps
/// no heap, written into an array on its stack. The reason and the scope are
/// [`encode_multicast_close`]'s own constants, so the two cannot send different
/// departures; `CodecError::BufferOverflow` when `out` has no room for them.
#[cfg(feature = "codec-close")]
pub fn encode_multicast_close_into_slice(out: &mut [u8]) -> Result<usize, CodecError> {
    let (header, body) = out.split_first_mut().ok_or(CodecError::BufferOverflow)?;
    *header = wire_const::T_MID_CLOSE
        | if MULTICAST_CLOSE_SESSION {
            wire_const::FLAG_T_CLOSE_S
        } else {
            0
        };
    let mut sink = sce_forge_runtime::codec::SliceSink::new(body);
    Close {
        reason: MULTICAST_CLOSE_REASON,
    }
    .encode(&mut sink)?;
    Ok(1 + sink.position())
}

/// R311kx — wire bytes for a KeepAlive transport message: the bare
/// 1-byte header (MID 0x04, no flags) over a zero-byte body — zenoh-pico
/// `_z_keep_alive_encode` writes nothing and the header alone marks the
/// message on the wire (`_z_t_msg_make_keep_alive`; the empty-body codec
/// parity is pinned by `tests/layer3_keep_alive.rs`). Const array (no
/// alloc): the message has no variable part.
#[cfg(feature = "transport-keepalive")]
pub const fn encode_keep_alive() -> [u8; 1] {
    [wire_const::T_MID_KEEP_ALIVE]
}

/// Pack the `cbyte` field: the 2-bit whatami wire form (via
/// [`WhatAmI::to_wire`], the `_z_whatami_to_uint8` SSOT,
/// transport.c:31-37) in the low bits + `(zid_len - 1) << 4`
/// (transport.c:189-192) in the high nibble.
#[cfg(feature = "codec-init-body")]
fn init_cbyte(whatami: WhatAmI, zid_len: usize) -> u8 {
    debug_assert!(
        (1..=16).contains(&zid_len),
        "zid_len must be 1..=16 (wire constraint, transport.h)"
    );
    whatami.to_wire() | (((zid_len as u8 - 1) & 0x0F) << 4)
}

/// Pack `sn_res` per transport.c:196-197:
/// `(seq_num_res & 0x03) | ((req_id_res & 0x03) << 2)`.
#[cfg(feature = "codec-init-body")]
fn pack_sn_res(seq_num_res: u8, req_id_res: u8) -> u8 {
    (seq_num_res & 0x03) | ((req_id_res & 0x03) << 2)
}

#[cfg(all(test, feature = "codec-init-body"))]
mod tests {
    use super::{init_cbyte, pack_sn_res};
    use wz_codecs::whatami::WhatAmI;

    /// A minimal params bundle for the OPEN lease-unit fixtures.
    #[cfg(feature = "codec-open-body")]
    fn open_params(lease_ms: u64) -> crate::session_init_params::SessionInitParams {
        use alloc::vec;
        crate::session_init_params::SessionInitParams {
            whatami: WhatAmI::Peer,
            zid: crate::session_init_params::zid_bytes(&[0x01; 4]),
            seq_num_res: 0,
            req_id_res: 0,
            batch_size: 0,
            lease_ms,
            initial_sn: 0,
            cookie: crate::session_init_params::cookie_bytes(&[]),
            tx_queue: crate::session_init_params::TxQueueConf::default(),
            link_rx: crate::session_init_params::LinkRxConf::default(),
            cookie_signing_key: crate::signing_key::SigningKey::new(vec![0xAB; 32])
                .expect("32-byte test key"),
        }
    }

    /// R311ku — encode_open derives the `_Z_FLAG_T_OPEN_T` flag from the
    /// lease value itself (pico `_z_t_msg_make_open_syn/_ack` parity,
    /// definitions/transport.c:196-214): a whole-second lease compacts
    /// to the seconds form (10000ms -> T=1 + VLE 10), a fractional one
    /// stays raw ms with T clear. The pre-ku manual `lease_in_seconds`
    /// knob let wz emit the non-compact form pico never sends.
    #[cfg(feature = "codec-open-body")]
    #[test]
    fn encode_open_derives_t_flag_from_lease() {
        // OpenAck (no cookie field): [header][lease vle][initial_sn vle].
        let ack = super::encode_open(&open_params(10_000), true, None, &[]).expect("encodes");
        assert_ne!(ack[0] & wire_const::FLAG_T_OPEN_T, 0, "T derived");
        assert_eq!(ack[1], 10, "wire VLE carries seconds");
        let ack = super::encode_open(&open_params(1_500), true, None, &[]).expect("encodes");
        assert_eq!(ack[0] & wire_const::FLAG_T_OPEN_T, 0, "T clear");
    }

    /// R311ku — the RX boundary inverts the projection: an OpenAck
    /// carrying the compact seconds form parses back to `body.lease`
    /// in MILLISECONDS (`parse_inbound` applies `lease_from_wire`, the
    /// same boundary rule as `multicast_join::decode_join`) — no
    /// consumer ever sees the wire unit.
    #[cfg(feature = "codec-open-body")]
    #[test]
    fn parse_inbound_projects_open_lease_to_ms() {
        let ack = super::encode_open(&open_params(10_000), true, None, &[]).expect("encodes");
        match crate::inbound::parse_inbound(&ack) {
            Ok(crate::inbound::InboundFrame::Open { body, .. }) => {
                assert_eq!(body.lease, 10_000, "seconds form projected back to ms");
            }
            // InboundFrame intentionally derives no Debug (sce-codegen
            // bodies only derive Default) — a variant name suffices here.
            Ok(_) => panic!("expected Open, got another variant"),
            Err(e) => panic!("expected Open, got parse error {e:?}"),
        }
    }
    #[cfg(feature = "codec-open-body")]
    use wz_codecs::wire_const;

    /// init_cbyte must match zenoh-pico's transport.c:189-192
    /// packing exactly — Layer 3 byte-equiv depends on this.
    #[test]
    fn init_cbyte_packs_whatami_and_zid_len() {
        // Peer.to_wire() = 0x01, zid_len_m1 = 3 → cbyte = 0x01 | (3 << 4) = 0x31
        assert_eq!(init_cbyte(WhatAmI::Peer, 4), 0x31);
        // Router.to_wire() = 0x00, zid_len_m1 = 0 → cbyte = 0
        assert_eq!(init_cbyte(WhatAmI::Router, 1), 0x00);
        // Client.to_wire() = 0x02, zid_len_m1 = 15 → cbyte = 0x02 | (15 << 4) = 0xF2
        assert_eq!(init_cbyte(WhatAmI::Client, 16), 0xF2);
    }

    /// pack_sn_res must match transport.c:196-197 packing exactly.
    #[test]
    fn pack_sn_res_layout_matches_transport_h() {
        assert_eq!(pack_sn_res(0, 0), 0x00);
        assert_eq!(pack_sn_res(3, 0), 0x03);
        assert_eq!(pack_sn_res(0, 3), 0x0C);
        assert_eq!(pack_sn_res(3, 3), 0x0F);
        assert_eq!(pack_sn_res(2, 1), 0x06);
    }
}
