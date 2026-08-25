// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
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

// Vec / VecSink back the codec-body encoders only; `encode_keep_alive`
// (transport-keepalive) is a const header byte, so a keepalive-only
// subset must not carry the unused imports (CI denies warnings).
#[cfg(any(
    feature = "codec-init-body",
    feature = "codec-open-body",
    feature = "codec-close"
))]
use alloc::vec::Vec;

#[cfg(any(
    feature = "codec-init-body",
    feature = "codec-open-body",
    feature = "codec-close"
))]
use sce_forge_runtime::codec::VecSink;
#[cfg(feature = "codec-init-body")]
use wz_codecs::whatami::WhatAmI;
use wz_codecs::wire_const;

#[cfg(any(feature = "codec-init-body", feature = "codec-open-body"))]
use crate::ext_chain::encode_ext_chain;
#[cfg(any(feature = "codec-init-body", feature = "codec-open-body"))]
use crate::session_init_params::SessionInitParams;
#[cfg(any(feature = "codec-init-body", feature = "codec-open-body"))]
use sce_forge_runtime::codec::CodecError;
#[cfg(any(feature = "codec-init-body", feature = "codec-open-body"))]
use wz_codecs::ext_entry::ExtEntryOwned;

#[cfg(feature = "codec-close")]
use wz_codecs::close::Close;
#[cfg(feature = "codec-init-body")]
use wz_codecs::init_body::{InitBody, InitBodyOwned};
#[cfg(feature = "codec-open-body")]
use wz_codecs::open_body::{OpenBody, OpenBodyOwned};

/// Build the wire bytes for an Init frame (InitSyn if `is_ack==false`,
/// InitAck if `is_ack==true`). The codec body is the wz `InitBody`,
/// verified byte-identical to zenoh-pico's `_z_init_encode` by
/// `crates/wz-integration-tests/tests/layer3_init_body.rs`. The
/// transport-message header is one byte: `(flags) | T_MID_INIT`.
#[cfg(feature = "codec-init-body")]
pub fn encode_init(
    params: &SessionInitParams,
    is_ack: bool,
    extensions: &[ExtEntryOwned],
    cookie_override: Option<&[u8]>,
) -> Result<Vec<u8>, CodecError> {
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
    let cbyte = init_cbyte(params.whatami, params.zid.len());
    let cookie_bytes: Option<Vec<u8>> = if is_ack {
        Some(
            cookie_override
                .map(|c| c.to_vec())
                .unwrap_or_else(|| params.cookie.clone()),
        )
    } else {
        None
    };
    let body: InitBodyOwned = InitBodyOwned {
        version: params.version,
        cbyte,
        // zid is the protocol-bounded peer id (1..=16); init_cbyte
        // above already encodes its length, so the bounded copy is an
        // invariant leaf (`.expect`), mirroring request_build.rs.
        zid: crate::codec_owned::owned_bytes(&params.zid).expect("zid length asserted in 1..=16"),
        sn_res: Some(pack_sn_res(params.seq_num_res, params.req_id_res)),
        // R311kj — the wire NEVER carries the internal 0 = "unset"
        // sentinel (a pico peer would adopt it and size a 0-byte TX
        // wbuf); the effective accessor is the advertisement SSOT.
        batch_size: Some(params.effective_batch_size()),
        cookie_len: cookie_bytes.as_ref().map(|c| c.len() as u64),
        cookie: cookie_bytes
            .as_deref()
            .map(crate::codec_owned::owned_bytes)
            .transpose()?,
    };

    let ext_bytes = encode_ext_chain(extensions);
    let mut wire = Vec::with_capacity(1 + InitBody::MAX_ENCODED_BYTES + ext_bytes.len());
    wire.push(parent_flags | wire_const::T_MID_INIT);
    let s = (parent_flags >> 6) & 1;
    let a = (parent_flags >> 5) & 1;
    {
        let mut sink = VecSink::new(&mut wire);
        body.as_borrowed()
            .encode(&mut sink, s, a)
            .expect("VecSink is infallible");
    }
    wire.extend_from_slice(&ext_bytes);
    Ok(wire)
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
#[cfg(feature = "codec-open-body")]
pub fn encode_open(
    params: &SessionInitParams,
    is_ack: bool,
    cookie_override: Option<&[u8]>,
    extensions: &[ExtEntryOwned],
) -> Result<Vec<u8>, CodecError> {
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
    let body: OpenBodyOwned = OpenBodyOwned {
        lease: wire_lease,
        initial_sn: params.initial_sn,
        cookie_len: if !is_ack {
            Some(cookie_bytes.len() as u64)
        } else {
            None
        },
        cookie: if !is_ack {
            Some(crate::codec_owned::owned_bytes(cookie_bytes)?)
        } else {
            None
        },
    };

    let ext_bytes = encode_ext_chain(extensions);
    let mut wire = Vec::with_capacity(1 + OpenBody::MAX_ENCODED_BYTES + ext_bytes.len());
    wire.push(parent_flags | wire_const::T_MID_OPEN);
    let a = (parent_flags >> 5) & 1;
    {
        let mut sink = VecSink::new(&mut wire);
        body.as_borrowed()
            .encode(&mut sink, a)
            .expect("VecSink is infallible");
    }
    wire.extend_from_slice(&ext_bytes);
    Ok(wire)
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
#[cfg(feature = "codec-close")]
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
#[cfg(feature = "codec-close")]
pub fn encode_multicast_close() -> Vec<u8> {
    encode_close(
        crate::close_reason::CloseReason::Generic as u8,
        /*session=*/ false,
    )
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
        use alloc::vec::Vec;
        crate::session_init_params::SessionInitParams {
            version: 0x05,
            whatami: WhatAmI::Peer,
            zid: vec![0x01; 4],
            seq_num_res: 0,
            req_id_res: 0,
            batch_size: 0,
            lease_ms,
            initial_sn: 0,
            cookie: Vec::new(),
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
