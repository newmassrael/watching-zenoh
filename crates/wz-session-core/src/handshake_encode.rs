// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! Outbound transport-handshake / close frame encoders.
//!
//! `encode_init` (InitSyn / InitAck), `encode_open` (OpenSyn / OpenAck)
//! and `encode_close` build the transport-message wire bytes for the
//! unicast session handshake and graceful close. Each whole message (header,
//! body, extension chain) is written by its document
//! (`sources/codecs/transport_{init,open,close}.scxml`), handed the body and
//! the chain where the sender holds them; the header's derived flags are the
//! document's, not this file's. The codec
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
// (transport-keepalive) writes one byte into an array, so a keepalive-only
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
use crate::session_init_params::SessionInitParams;
// The `_into` encoders write through the buffer seam, which every one of them
// reaches with `append_byte` and a sink over it. `TxBuf` is needed for the
// method call only when `EncodeBuf` is a concrete type (no lending); on a
// `dyn TxBuf` the methods resolve without the import.
#[cfg(any(
    feature = "codec-init-body",
    feature = "codec-open-body",
    feature = "codec-close",
    feature = "transport-keepalive"
))]
use crate::transport_profile::ExtEntryOwned;
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

#[cfg(feature = "codec-close")]
use wz_codecs::close::{Close, CloseSource};
#[cfg(feature = "codec-init-body")]
use wz_codecs::init_body::{InitBody, InitBodyS, InitBodySource};
#[cfg(feature = "codec-open-body")]
use wz_codecs::open_body::{OpenBody, OpenBodySource};
#[cfg(feature = "codec-close")]
use wz_codecs::transport_close::{TransportCloseSource, TransportCloseWire};
#[cfg(feature = "codec-init-body")]
use wz_codecs::transport_init::{TransportInitSource, TransportInitWire};
#[cfg(feature = "transport-keepalive")]
use wz_codecs::transport_keep_alive::{TransportKeepAliveSource, TransportKeepAliveWire};
#[cfg(feature = "codec-open-body")]
use wz_codecs::transport_open::{TransportOpenSource, TransportOpenWire};

#[cfg(any(feature = "codec-init-body", feature = "codec-open-body"))]
use sce_forge_runtime::codec::Bounded;
#[cfg(any(
    feature = "codec-init-body",
    feature = "codec-open-body",
    feature = "codec-close",
    feature = "transport-keepalive"
))]
use sce_forge_runtime::codec::BoundedIter;
#[cfg(any(
    feature = "codec-init-body",
    feature = "codec-open-body",
    feature = "codec-close",
    feature = "transport-keepalive"
))]
use wz_codecs::ext_entry::ExtEntrySource;

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
    // No reservation up front: the body is built inside `encode_init_into`, and
    // the codec's largest frame is no bound worth reserving, since a cookie may
    // be as long as upstream's u16 length lets it be. The vector grows to the
    // frame; a handshake is a few of these per session.
    let mut wire = Vec::new();
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
/// The whole message is written by its document (`sources/codecs/transport_init.scxml`):
/// the body is the codec's BORROWED view over the parameters' own zid and the
/// cookie, not an owned copy of either, the extension chain is read where it is
/// held, and the header's A, S and Z flags are derived from what is presented. A
/// buffer that cannot hold the frame refuses with `BufferOverflow` and keeps the
/// bytes it was given; the caller discards the buffer, or rolls back with
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
    let message = init_message(params, caps, is_ack, extensions, cookie_override)?;
    TransportInitWire::encode_source(&message, &mut TxSink::new(&mut *buf))
}

/// The bytes [`encode_init_into`] writes for the same arguments, as the message's
/// document counts them. It is what a lent slot
/// for the message must hold, and it is exact, since an Init body has no size
/// constant that bounds it (its cookie's length is upstream's u16). A message
/// `init_message` refuses counts as zero: the encoder that follows refuses it
/// with the same error.
// Its one caller is `SessionLinkActions::send_init_lent`, so the gate carries
// `session_actions`' own (`storage-profile` and `session-unicast`).
#[cfg(all(
    feature = "tx-lend-only",
    feature = "storage-profile",
    feature = "session-unicast",
    feature = "codec-init-body",
    any(feature = "session-unicast-open", feature = "session-unicast-accept")
))]
pub(crate) fn init_frame_len(
    params: &SessionInitParams,
    caps: InitCaps,
    is_ack: bool,
    extensions: &[ExtEntryOwned],
    cookie_override: Option<&[u8]>,
) -> usize {
    match init_message(params, caps, is_ack, extensions, cookie_override) {
        Ok(message) => TransportInitWire::measure(&message).len(),
        Err(_) => 0,
    }
}

/// The extension chain of a transport message as its document is handed it: the
/// entries a sender holds, read where they are. No entry is no chain, so the
/// encode clears the header's Z flag; it sets each entry's own Z but the last's,
/// whatever the held header says.
#[cfg(any(feature = "codec-init-body", feature = "codec-open-body"))]
struct HeldChain<'e>(Option<Bounded<&'e [ExtEntryOwned], { usize::MAX }, 1>>);

#[cfg(any(feature = "codec-init-body", feature = "codec-open-body"))]
impl<'e> HeldChain<'e> {
    fn of(entries: &'e [ExtEntryOwned]) -> Self {
        Self(Bounded::new(entries))
    }

    fn entries(
        &self,
    ) -> Option<BoundedIter<core::slice::Iter<'e, ExtEntryOwned>, { usize::MAX }, 1>> {
        self.0.as_ref().map(|chain| chain.iter())
    }
}

/// An Init message as `transport_init` writes it: the body, and the chain where
/// it is held. The header presents the message id alone; A and S follow from the
/// body (a cookie, the size parameters) and Z from the chain.
#[cfg(feature = "codec-init-body")]
struct InitMessage<'p, 'e> {
    body: InitBody<'p>,
    extensions: HeldChain<'e>,
}

#[cfg(feature = "codec-init-body")]
impl TransportInitSource for InitMessage<'_, '_> {
    fn header(&self) -> u8 {
        wire_const::T_MID_INIT
    }

    fn body(&self) -> &impl InitBodySource {
        &self.body
    }

    fn extensions(
        &self,
    ) -> Option<BoundedIter<impl Iterator<Item = impl ExtEntrySource> + Clone, { usize::MAX }, 1>>
    {
        self.extensions.entries()
    }
}

/// The Init message [`encode_init_into`] writes and [`init_frame_len`] counts.
/// `LengthOutOfRange` for a zid outside the protocol's 1..=16 bytes or a cookie
/// past its `u16` length.
#[cfg(feature = "codec-init-body")]
fn init_message<'p, 'e>(
    params: &'p SessionInitParams,
    caps: InitCaps,
    is_ack: bool,
    extensions: &'e [ExtEntryOwned],
    cookie_override: Option<&'p [u8]>,
) -> Result<InitMessage<'p, 'e>, CodecError> {
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
    // A `SessionZid` is 1..=16 bytes, the lengths `init_cbyte` can pack.
    let zid = crate::codec_owned::sent(params.zid.as_slice())?;
    let body = InitBody {
        // The protocol's, not a parameter: see `SessionInitParams`.
        version: wire_const::PROTOCOL_VERSION,
        cbyte: init_cbyte(params.whatami, params.zid.len()),
        zid,
        s: Some(InitBodyS {
            sn_res: pack_sn_res(caps.seq_num_res, caps.req_id_res),
            batch_size: caps.batch_size,
        }),
        cookie_len: cookie.map(|c| c.len() as u64),
        cookie: cookie.map(crate::codec_owned::sent).transpose()?,
    };
    Ok(InitMessage {
        body,
        extensions: HeldChain::of(extensions),
    })
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
    // No reservation up front, for the reason `encode_init_with_caps` gives: an
    // Open body has no largest frame at all, its cookie length being a `usize`.
    let mut wire = Vec::new();
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
/// [`encode_init_into`] for the buffer contract; the whole message is written by
/// its document (`sources/codecs/transport_open.scxml`).
#[cfg(feature = "codec-open-body")]
pub fn encode_open_into(
    buf: &mut crate::tx_buf::EncodeBuf<'_>,
    params: &SessionInitParams,
    initial_sn: u64,
    is_ack: bool,
    cookie_override: Option<&[u8]>,
    extensions: &[ExtEntryOwned],
) -> Result<(), CodecError> {
    let message = open_message(params, initial_sn, is_ack, cookie_override, extensions)?;
    TransportOpenWire::encode_source(&message, &mut TxSink::new(&mut *buf))
}

/// What [`encode_open_into`] writes before the extension chain: the header byte,
/// whose Z flag says whether a chain follows (`has_ext`), and the body with the
/// cookie. The chain is written after it by `ext_chain::encode_ext_chain_into`.
///
/// The two halves are separate for the lend-only send, which holds the cookie and
/// the chain under two session mutexes and takes them one after the other: the
/// chain is written where it is staged, and not copied out of its slot to be
/// handed to an encoder that needs both at once.
///
/// The header byte is the one place this file still writes a transport header:
/// the document derives Z from the chain it is handed, and this half is handed
/// none. A, T and the message id are the document's own derivation of the body
/// ([`open_head_byte`]).
// Its callers: the lend-only Open send in `session_actions`, whose gate this
// carries, and the test that holds its two halves to the Open written whole.
#[cfg(any(
    all(
        feature = "tx-lend-only",
        feature = "session-unicast",
        feature = "codec-open-body",
        any(feature = "session-unicast-open", feature = "session-unicast-accept")
    ),
    all(test, feature = "codec-init-body", feature = "codec-open-body")
))]
pub(crate) fn encode_open_head_into(
    buf: &mut crate::tx_buf::EncodeBuf<'_>,
    params: &SessionInitParams,
    initial_sn: u64,
    is_ack: bool,
    cookie_override: Option<&[u8]>,
    has_ext: bool,
) -> Result<(), CodecError> {
    let message = open_message(params, initial_sn, is_ack, cookie_override, &[])?;
    buf.append_byte(open_head_byte(&message, has_ext))?;
    message.body.encode(&mut TxSink::new(&mut *buf))
}

/// The header byte of the head [`encode_open_head_into`] writes: what
/// `transport_open` would write for `message` with a chain when `has_ext`.
#[cfg(any(
    all(
        feature = "tx-lend-only",
        feature = "session-unicast",
        feature = "codec-open-body",
        any(feature = "session-unicast-open", feature = "session-unicast-accept")
    ),
    all(test, feature = "codec-init-body", feature = "codec-open-body")
))]
fn open_head_byte(message: &OpenMessage<'_, '_>, has_ext: bool) -> u8 {
    let mut header = TransportOpenSource::header(message);
    if wz_codecs::open_body::OpenBodyWire::input_a(&message.body) {
        header |= wire_const::FLAG_T_OPEN_A;
    }
    if has_ext {
        header |= wire_const::FLAG_T_Z;
    }
    header
}

/// The bytes [`encode_open_head_into`] writes for the same arguments, whether or
/// not a chain follows (its Z flag is a bit of the header, not a byte): exact,
/// since an Open body has no size constant (its cookie's length is a `u32`), and
/// zero for a message `open_message` refuses. With `ext_chain::ext_chain_len` of
/// the chain it is what a lent slot for the Open must hold, as `init_frame_len`
/// is for Init.
// Its callers are the lend-only Open sends in `session_actions`, so the gate
// carries that module's own (`storage-profile` and `session-unicast`).
#[cfg(all(
    feature = "tx-lend-only",
    feature = "storage-profile",
    feature = "session-unicast",
    feature = "codec-open-body",
    any(feature = "session-unicast-open", feature = "session-unicast-accept")
))]
pub(crate) fn open_head_len(
    params: &SessionInitParams,
    initial_sn: u64,
    is_ack: bool,
    cookie_override: Option<&[u8]>,
) -> usize {
    match open_message(params, initial_sn, is_ack, cookie_override, &[]) {
        Ok(message) => 1 + wz_codecs::open_body::OpenBodyWire::measure(&message.body).len(),
        Err(_) => 0,
    }
}

/// An Open message as `transport_open` writes it: the body, and the chain where
/// it is held. The header presents the message id and the lease unit (T); A
/// follows from the body (no cookie) and Z from the chain.
#[cfg(feature = "codec-open-body")]
struct OpenMessage<'p, 'e> {
    lease_in_seconds: bool,
    body: OpenBody<'p>,
    extensions: HeldChain<'e>,
}

#[cfg(feature = "codec-open-body")]
impl TransportOpenSource for OpenMessage<'_, '_> {
    fn header(&self) -> u8 {
        if self.lease_in_seconds {
            wire_const::T_MID_OPEN | wire_const::FLAG_T_OPEN_T
        } else {
            wire_const::T_MID_OPEN
        }
    }

    fn body(&self) -> &impl OpenBodySource {
        &self.body
    }

    fn extensions(
        &self,
    ) -> Option<BoundedIter<impl Iterator<Item = impl ExtEntrySource> + Clone, { usize::MAX }, 1>>
    {
        self.extensions.entries()
    }
}

/// The Open message [`encode_open_into`] writes, and whose head
/// `encode_open_head_into` writes and `open_head_len` counts.
/// `LengthOutOfRange` for a cookie past the protocol's `u32` length.
#[cfg(feature = "codec-open-body")]
fn open_message<'p, 'e>(
    params: &'p SessionInitParams,
    initial_sn: u64,
    is_ack: bool,
    cookie_override: Option<&'p [u8]>,
    extensions: &'e [ExtEntryOwned],
) -> Result<OpenMessage<'p, 'e>, CodecError> {
    // R311ku — the T flag is DERIVED, not configured: a whole-second
    // lease compacts to the seconds form, pico `_z_t_msg_make_open_syn`
    // / `_ack` parity (definitions/transport.c:196-214; the pre-ku
    // manual `lease_in_seconds` knob let wz send `T=0 + VLE 10000`
    // where pico always compacts to `T=1 + VLE 10`).
    let (lease_in_seconds, wire_lease) = crate::lease::lease_to_wire(params.lease_ms);

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
        cookie: if !is_ack {
            Some(crate::codec_owned::sent(cookie_bytes)?)
        } else {
            None
        },
    };
    Ok(OpenMessage {
        lease_in_seconds,
        body,
        extensions: HeldChain::of(extensions),
    })
}

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
    let mut wire = Vec::with_capacity(1 + Close::MAX_ENCODED_BYTES);
    TransportCloseWire::encode_source(
        &CloseMessage::new(reason, session),
        &mut VecSink::new(&mut wire),
    )
    .expect("VecSink is infallible");
    wire
}

/// A Close as `transport_close` writes it: the scope (S) on the header, the
/// reason as the body, and no chain, since a Close declares no extension of its
/// own; Z is derived from that.
#[cfg(feature = "codec-close")]
struct CloseMessage {
    session: bool,
    body: Close,
}

#[cfg(feature = "codec-close")]
impl CloseMessage {
    const fn new(reason: u8, session: bool) -> Self {
        Self {
            session,
            body: Close { reason },
        }
    }
}

#[cfg(feature = "codec-close")]
impl TransportCloseSource for CloseMessage {
    fn header(&self) -> u8 {
        if self.session {
            wire_const::T_MID_CLOSE | wire_const::FLAG_T_CLOSE_S
        } else {
            wire_const::T_MID_CLOSE
        }
    }

    fn body(&self) -> &impl CloseSource {
        &self.body
    }

    fn extensions(
        &self,
    ) -> Option<BoundedIter<impl Iterator<Item = impl ExtEntrySource> + Clone, { usize::MAX }, 1>>
    {
        None::<BoundedIter<core::slice::Iter<'static, ExtEntryOwned>, { usize::MAX }, 1>>
    }
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
    TransportCloseWire::encode_source(&CloseMessage::new(reason, session), &mut TxSink::new(buf))
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
    TransportCloseWire::write_window(
        &CloseMessage::new(MULTICAST_CLOSE_REASON, MULTICAST_CLOSE_SESSION),
        out,
    )
}

/// R311kx — wire bytes for a KeepAlive transport message: the bare
/// 1-byte header (MID 0x04, no flags) over a zero-byte body — zenoh-pico
/// `_z_keep_alive_encode` writes nothing and the header alone marks the
/// message on the wire (`_z_t_msg_make_keep_alive`; the empty-body codec
/// parity is pinned by `tests/layer3_keep_alive.rs`). An array (no alloc):
/// a KeepAlive this node sends carries no chain, so it is the one byte its
/// document (`sources/codecs/transport_keep_alive.scxml`) writes for it.
#[cfg(feature = "transport-keepalive")]
pub fn encode_keep_alive() -> [u8; 1] {
    let mut frame = [0u8; 1];
    TransportKeepAliveWire::write_window(&KeepAliveMessage, &mut frame)
        .expect("a KeepAlive with no chain is its one header byte");
    frame
}

/// A KeepAlive as `transport_keep_alive` writes it for this node: the message
/// id, and no chain, so Z is derived clear.
#[cfg(feature = "transport-keepalive")]
struct KeepAliveMessage;

#[cfg(feature = "transport-keepalive")]
impl TransportKeepAliveSource for KeepAliveMessage {
    fn header(&self) -> u8 {
        wire_const::T_MID_KEEP_ALIVE
    }

    fn extensions(
        &self,
    ) -> Option<BoundedIter<impl Iterator<Item = impl ExtEntrySource> + Clone, { usize::MAX }, 1>>
    {
        None::<BoundedIter<core::slice::Iter<'static, ExtEntryOwned>, { usize::MAX }, 1>>
    }
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
            keep_alive: crate::session_init_params::KeepAliveConf::default(),
            initial_sn: 0,
            cookie: crate::session_init_params::cookie_bytes(&[]),
            tx_queue: crate::session_init_params::TxQueueConf::of_policy(
                &crate::policy::SessionPolicy::defaults(),
            ),
            link_rx: crate::session_init_params::LinkRxConf::default(),
            cookie_signing_key: crate::signing_key::SigningKey::new(vec![0xAB; 32])
                .expect("32-byte test key"),
            policy: crate::policy::SessionPolicy::defaults(),
            limits: crate::limits::SessionLimits::BUILD,
        }
    }

    /// An Init's Z flag says exactly whether its extension chain was written, at every patch
    /// level the chain can carry, and an InitAck that answers a peer that announced no patch
    /// still writes the patch entry (at level 0) behind a set Z. zenoh-pico 1.10.2 lowers its
    /// InitAck's level to the peer's and keeps Z, then writes no entry for level 0
    /// (`src/transport/unicast/transport.c:239-241`), so a peer that announced no patch reads
    /// a Z with nothing behind it. Here the flag is derived from the chain the encoder is given,
    /// so the two cannot part.
    #[cfg(all(
        feature = "alloc",
        feature = "codec-init-body",
        feature = "codec-open-body"
    ))]
    #[test]
    fn an_init_sets_z_exactly_when_its_patch_entry_is_written() {
        use crate::extpatch::{encode_patch_ext_at, CURRENT_PATCH, NO_PATCH, PATCH_EXT_ID};
        let params = open_params(10_000);
        let entry_header = PATCH_EXT_ID | crate::ext_header::EXT_ENC_Z64;
        for is_ack in [false, true] {
            for level in [NO_PATCH, CURRENT_PATCH] {
                let chain = [encode_patch_ext_at(level)];
                let wire = super::encode_init(&params, is_ack, &chain, None).expect("encodes");
                assert_ne!(
                    wire[0] & wire_const::FLAG_T_Z,
                    0,
                    "is_ack={is_ack} level={level}: a written entry sets Z"
                );
                assert_eq!(
                    &wire[wire.len() - 2..],
                    &[entry_header, level],
                    "is_ack={is_ack} level={level}: the entry closes the message, last in its chain"
                );
            }
            let bare = super::encode_init(&params, is_ack, &[], None).expect("encodes");
            assert_eq!(
                bare[0] & wire_const::FLAG_T_Z,
                0,
                "is_ack={is_ack}: no chain, no Z"
            );
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

    /// The Open the lend-only send writes in two steps, the head and then the
    /// chain where it is staged, is the Open written whole: the Z flag follows the
    /// chain's presence, and the cookie and the chain land where the one encoder
    /// puts them. Where the lend-only sizer is built, it counts exactly the head.
    #[cfg(feature = "codec-open-body")]
    #[test]
    fn an_open_written_head_then_chain_is_the_open_written_whole() {
        let params = open_params(10_000);
        let entries = [
            crate::extpatch::encode_patch_ext(),
            crate::extpatch::encode_patch_ext_at(0),
        ];
        let echoed = [0x5Au8; 12];
        for is_ack in [false, true] {
            for chain in [&entries[..], &[][..]] {
                for cookie in [None, Some(&echoed[..])] {
                    let mut whole = alloc::vec::Vec::new();
                    super::encode_open_into(&mut whole, &params, 1234, is_ack, cookie, chain)
                        .expect("whole");
                    let mut split = alloc::vec::Vec::new();
                    super::encode_open_head_into(
                        &mut split,
                        &params,
                        1234,
                        is_ack,
                        cookie,
                        !chain.is_empty(),
                    )
                    .expect("head");
                    let head = split.len();
                    crate::ext_chain::encode_ext_chain_into(&mut split, chain).expect("chain");
                    assert_eq!(split, whole, "ack {is_ack}, {} ext(s)", chain.len());
                    assert_eq!(
                        whole[0] & wire_const::FLAG_T_Z != 0,
                        !chain.is_empty(),
                        "the Z flag says whether a chain follows"
                    );
                    #[cfg(all(
                        feature = "tx-lend-only",
                        feature = "storage-profile",
                        feature = "session-unicast",
                        any(feature = "session-unicast-open", feature = "session-unicast-accept")
                    ))]
                    assert_eq!(
                        super::open_head_len(&params, 1234, is_ack, cookie),
                        head,
                        "the sizer counts the head it writes"
                    );
                    #[cfg(not(all(
                        feature = "tx-lend-only",
                        feature = "storage-profile",
                        feature = "session-unicast",
                        any(feature = "session-unicast-open", feature = "session-unicast-accept")
                    )))]
                    let _ = head;
                }
            }
        }
    }

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

// Under the sender's own feature, which is the one place it is built without
// the receive arm of `codec-keep-alive`.
#[cfg(all(test, feature = "transport-keepalive"))]
mod keep_alive_tests {
    /// The KeepAlive a node sends is its message id alone: no flag, no chain,
    /// which upstream writes for a KeepAlive
    /// (`commons/zenoh-codec/src/transport/keepalive.rs` @
    /// `impl<W> WCodec<&KeepAlive, &mut W> for Zenoh080`).
    #[test]
    fn the_keep_alive_sent_is_its_message_id_alone() {
        assert_eq!(super::encode_keep_alive(), [0x04]);
    }
}
