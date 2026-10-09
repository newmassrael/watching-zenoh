// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! Transport messages composed from EXPLICIT fields, and the stream prefix a
//! link puts in front of them.
//!
//! # What this is for, and what it is not
//!
//! `handshake_encode` and `frame_encode` are the session's TX path. They take
//! what a LIVE session knows (`SessionInitParams`, the next sequence number, the
//! negotiated priority) and they decide, on its behalf, the things a session
//! decides: a batch size of `0` is the internal "unset" sentinel and is written
//! as the default, a cookie is the one the handshake minted, a lease is a number
//! of milliseconds that the wire may compact to seconds. That is right for a
//! node and wrong for a caller that has to say EVERY field, because a field the
//! encoder substitutes is a field the caller cannot set.
//!
//! This module is the other reading of the same wire. Each `compose_*` takes the
//! message's semantic fields as plain values and writes exactly those, and the
//! only things it decides are the ones the wire DERIVES from them: the header
//! flags that mean "this part is present" (`S`, `A`, `Z`, `R`, `M`), the lease
//! unit flag (`T`), every length (`cookie_len`, an extension's `value_len`,
//! the stream prefix) and the width of every VLE. It writes through the same
//! generated codecs the session TX path does (`InitBody`, `OpenBody`, `Close`,
//! `KeepAlive`, `Fragment`, `Frame`, `StreamEnvelope`) and through the same
//! helpers (`lease_to_wire`, `encode_ext_chain`, `build_fragment_wire`), so the
//! bytes are the bytes a conforming sender writes, and a field the caller sets
//! to a value no sender would choose is still written the way the format
//! writes it.
//!
//! It adds no scanning, no destination and no peer. A message out of handshake
//! order is not a mode: it is a different message the caller asked for.
//!
//! # What it deliberately does not do
//!
//! * It does not know a SESSION. Whether a sequence number is inside the ring a
//!   handshake agreed is the caller's question; `sn_ring_max` answers it for a
//!   resolution code, and the build door in `wz-capture` asks it.
//! * It does not write `Join` or `Oam`. Both are later work; the seam is the
//!   `compose_*` family, one function per message.
//! * It does not write an extension chain on `Close` or `KeepAlive`, which
//!   declare none upstream, nor a Frame/Fragment extension other than the QoS
//!   priority and the two Fragment markers.
//!
//! # Where the wire facts come from
//!
//! Read at the pinned upstream (zenoh 1.10.1):
//!
//! * INIT header, `A`/`S`/`Z`, `cbyte`, `sn_res`, `batch_size`, cookie:
//!   `commons/zenoh-protocol/src/transport/init.rs` @ `|zid_len|x|x|wai|`;
//! * OPEN header, `A`/`T`/`Z`, lease, initial_sn, cookie on the SYN only:
//!   `commons/zenoh-protocol/src/transport/open.rs` @ `pub struct OpenSyn {`;
//! * `R`, `M`, `Z`, `sn`, extensions, payload:
//!   `commons/zenoh-protocol/src/transport/frame.rs` @ `pub struct Frame {` and
//!   `commons/zenoh-protocol/src/transport/fragment.rs` @ `pub struct Fragment {`;
//! * `S`, and the reserved bits:
//!   `commons/zenoh-protocol/src/transport/close.rs` @ `pub struct Close {` and
//!   `commons/zenoh-protocol/src/transport/keepalive.rs` @ `pub struct KeepAlive;`;
//! * the stream prefixes, a 16-bit little-endian length for streamed links:
//!   `commons/zenoh-protocol/src/transport/mod.rs` @
//!   `16 bits (2 bytes) may be prepended to the serialized message`, and a
//!   32-bit one once the session is LowLatency:
//!   `io/zenoh-transport/src/unicast/lowlatency/link.rs` @
//!   `len = (buffer.len() - 4) as u32;`.

use alloc::vec::Vec;

use sce_forge_runtime::codec::{CodecError, SceSink, VecSink};
use wz_codecs::close::Close;
use wz_codecs::ext_entry::{ExtEntryOwned, ExtEntryOwnedVariant};
use wz_codecs::ext_unit::ExtUnit;
use wz_codecs::ext_zbuf::ExtZbufOwned;
use wz_codecs::ext_zint::ExtZint;
use wz_codecs::init_body::InitBody;
use wz_codecs::keep_alive::KeepAlive;
use wz_codecs::open_body::OpenBody;
use wz_codecs::stream_envelope::StreamEnvelope;
use wz_codecs::wire_const;

use crate::codec_owned::owned_bytes;
use crate::ext_chain::encode_ext_chain;
use crate::frame_encode::{build_fragment_wire, build_frame_wire};
use crate::lease::lease_to_wire;
use crate::parse_error::MAX_EXT_CHAIN_DEPTH;
use crate::qos::Priority;

/// Why a message could not be composed.
///
/// Each variant is a value that does not fit the field it was given for, named
/// by what it was given for: the build door turns it into a diagnostic that
/// carries the caller's own key, and nothing here truncates.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ComposeError {
    /// A zid of this many bytes. The wire stores `zid_len - 1` in four bits, so
    /// it holds 1 to 16.
    ZidLength(usize),
    /// A `whatami` code above 3. The wire holds two bits; 3 is the reserved
    /// value upstream names and refuses to read, and is writable here.
    WhatAmI(u8),
    /// A resolution code above 3: the wire holds two bits per resolution.
    ResolutionCode(u8),
    /// A QoS priority above 7: the transport `QoSType` keeps it in three bits
    /// (`commons/zenoh-protocol/src/transport/mod.rs` @
    /// `const P_MASK: u8 = 0b00000111;`).
    Priority(u8),
    /// An extension id above 15: the entry header keeps it in four bits.
    ExtensionId {
        /// Which entry of the chain.
        index: usize,
        /// The id it was given.
        id: u8,
    },
    /// More extensions than the reader's bound
    /// ([`MAX_EXT_CHAIN_DEPTH`]). The chain is encodable; it is refused
    /// because a reader that stops at the bound could not read it back, and the
    /// layout of the bytes is derived by reading them.
    ExtensionChain {
        /// How many entries were given.
        entries: usize,
    },
    /// A lease that does not divide into seconds, asked for in seconds: the
    /// wire value would be a rounded one, and nothing here rounds.
    LeaseNotWholeSeconds {
        /// The lease in milliseconds.
        lease_ms: u64,
    },
    /// An extension body this build cannot hold.
    ExtensionBody {
        /// Which entry of the chain.
        index: usize,
    },
    /// A body that does not fit the length prefix of the framing asked for.
    UnitTooLong {
        /// The body's length in bytes.
        len: usize,
        /// The largest length the prefix holds.
        max: u64,
    },
}

/// The largest sequence number the ring of a `sn_res` resolution code holds.
///
/// The repository's own answer (`sn::mask_from_res`, zenoh-pico
/// `_z_sn_max`), which is also upstream's: `RES_U8` is `u8::MAX >> 1`, one byte
/// when encoded, up to `RES_U64`, `u64::MAX >> 1`, nine bytes
/// (`io/zenoh-transport/src/common/seq_num.rs` @
/// `const RES_U64: TransportSn = (u64::MAX >> 1) as TransportSn;`). A code above
/// 3 answers with the widest ring, as `mask_from_res` does.
pub const fn sn_ring_max(code: u8) -> u64 {
    crate::sn::mask_from_res(code)
}

/// What the wire stores for `sn_res`: the frame/fragment resolution in bits
/// 0-1 and the request-id resolution in bits 2-3, the upper nibble reserved and
/// written zero (`commons/zenoh-protocol/src/transport/init.rs` @
/// `|x|x|x|x|rid|fsn|`).
const fn pack_sn_res(frame_sn_code: u8, request_id_code: u8) -> u8 {
    (frame_sn_code & 0x03) | ((request_id_code & 0x03) << 2)
}

/// The bits of `sn_res` that hold the frame/fragment resolution, read off the
/// packing above rather than written a second time.
pub const SN_RES_FRAME_MASK: u8 = pack_sn_res(0x03, 0);

/// The bits of `sn_res` that hold the request-id resolution.
pub const SN_RES_REQUEST_ID_MASK: u8 = pack_sn_res(0, 0x03);

/// The size parameters an INIT carries behind its `S` flag.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SizeParams {
    /// The frame/fragment sequence number resolution, 0 (8 bit) to 3 (64 bit).
    pub frame_sn_code: u8,
    /// The request id resolution, 0 to 3.
    pub request_id_code: u8,
    /// The batch size, written as given: `0` is a value here, not a sentinel.
    pub batch_size: u16,
}

/// One extension of an INIT or OPEN chain.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExtBody<'a> {
    /// No body (`ZExtUnit`).
    Unit,
    /// One VLE (`ZExtZ64`).
    Z64(u64),
    /// A length-prefixed byte string (`ZExtZBuf`).
    ZBuf(&'a [u8]),
}

/// An extension entry: its id, its mandatory bit and its body. The encoding
/// bits of the header follow from the body, and the chain bit from the
/// entry's place in the chain.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ExtSpec<'a> {
    /// The id, 0 to 15.
    pub id: u8,
    /// The `M` bit.
    pub mandatory: bool,
    /// The body.
    pub body: ExtBody<'a>,
}

/// The two INIT messages.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InitRole<'a> {
    /// The initiator's INIT: no cookie.
    Syn,
    /// The acceptor's answer, with the cookie it asks to have echoed.
    Ack {
        /// The cookie, written behind its VLE length.
        cookie: &'a [u8],
    },
}

/// An INIT message, field by field.
#[derive(Debug, Clone, Copy)]
pub struct InitSpec<'a> {
    /// Syn or Ack.
    pub role: InitRole<'a>,
    /// The protocol version byte.
    pub version: u8,
    /// The `whatami` code, 0 to 3.
    pub whatami: u8,
    /// The zid bytes in wire order, 1 to 16 of them.
    pub zid: &'a [u8],
    /// The size parameters, or `None` for an INIT whose `S` flag is clear.
    pub size: Option<SizeParams>,
    /// The extension chain, in wire order.
    pub extensions: &'a [ExtSpec<'a>],
}

/// The two OPEN messages.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OpenRole<'a> {
    /// The initiator's OPEN, echoing the acceptor's cookie.
    Syn {
        /// The cookie, written behind its VLE length.
        cookie: &'a [u8],
    },
    /// The acceptor's answer: no cookie.
    Ack,
}

/// An OPEN message, field by field.
#[derive(Debug, Clone, Copy)]
pub struct OpenSpec<'a> {
    /// Syn or Ack.
    pub role: OpenRole<'a>,
    /// The lease in milliseconds.
    pub lease_ms: u64,
    /// The unit the lease travels in. `None` lets the wire derive it
    /// ([`lease_to_wire`]: a whole number of seconds travels as seconds, the
    /// form every sender in this tree writes); a unit named here is written as
    /// named, which is how a lease of `10000` ms is sent as `10000` with `T`
    /// clear.
    pub lease_unit: Option<LeaseUnit>,
    /// The initial sequence number, as given.
    pub initial_sn: u64,
    /// The extension chain, in wire order.
    pub extensions: &'a [ExtSpec<'a>],
}

/// The unit an OPEN's lease travels in: the `T` flag.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LeaseUnit {
    /// `T` clear: the wire value is milliseconds.
    Milliseconds,
    /// `T` set: the wire value is seconds, so the lease must be a whole number
    /// of them.
    Seconds,
}

/// A FRAME, field by field.
#[derive(Debug, Clone, Copy)]
pub struct FrameSpec<'a> {
    /// The channel: `R` is set for the reliable one.
    pub reliable: bool,
    /// The sequence number, as given.
    pub sn: u64,
    /// The QoS priority 0 to 7, written as an `ext_qos` whenever it is given
    /// (including the default priority, which a session would leave out).
    pub priority: Option<u8>,
    /// The bytes behind the header, verbatim.
    pub payload: &'a [u8],
}

/// A FRAGMENT, field by field.
#[derive(Debug, Clone, Copy)]
pub struct FragmentSpec<'a> {
    /// The channel: `R` is set for the reliable one.
    pub reliable: bool,
    /// The `M` flag: more fragments follow.
    pub more: bool,
    /// The sequence number, as given.
    pub sn: u64,
    /// The QoS priority 0 to 7, written as an `ext_qos` whenever it is given.
    pub priority: Option<u8>,
    /// The `First` marker (extension id 2).
    pub first: bool,
    /// The `Drop` marker (extension id 3).
    pub drop_marker: bool,
    /// The fragment bytes, verbatim.
    pub payload: &'a [u8],
}

/// How a unit is framed for the link it goes on.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Framing {
    /// The body alone: one datagram is one unit (UDP, multicast).
    Datagram,
    /// A 16-bit little-endian length, then the body: a streamed link in its
    /// ordinary mode (TCP, TLS, WebSocket, QUIC stream).
    TcpStream,
    /// A 32-bit little-endian length, then the body: a streamed link whose
    /// session negotiated LowLatency.
    LowLatencyStream,
}

impl Framing {
    /// Every framing, in the order the vocabulary lists them.
    pub const ALL: [Framing; 3] = [
        Framing::Datagram,
        Framing::TcpStream,
        Framing::LowLatencyStream,
    ];

    /// The width of the length prefix in bytes: 0, 2 or 4.
    pub const fn prefix_bytes(self) -> usize {
        match self {
            Framing::Datagram => 0,
            Framing::TcpStream => 2,
            Framing::LowLatencyStream => 4,
        }
    }

    /// The largest body the prefix can announce.
    pub const fn max_body(self) -> u64 {
        match self {
            Framing::Datagram => u64::MAX,
            Framing::TcpStream => u16::MAX as u64,
            Framing::LowLatencyStream => u32::MAX as u64,
        }
    }

    /// The word for this framing.
    pub const fn name(self) -> &'static str {
        match self {
            Framing::Datagram => "datagram",
            Framing::TcpStream => "tcp_stream",
            Framing::LowLatencyStream => "lowlatency_stream",
        }
    }

    /// The framing a word names.
    pub fn named(word: &str) -> Option<Framing> {
        Framing::ALL.into_iter().find(|f| f.name() == word)
    }
}

/// The length of a VLE-encoded `value` in bytes, as the codec writes it.
///
/// Measured by writing it: the codec is the definition, and a second formula
/// would be a second opinion about where the 9-byte bucket starts.
pub fn vle_width(value: u64) -> usize {
    let mut scratch = [0u8; 16];
    let mut sink = sce_forge_runtime::codec::SliceSink::new(&mut scratch);
    sink.write_vle_u64(value).expect("16 bytes hold any VLE");
    sink.position()
}

/// The widest VLE the codec writes, in bytes.
pub const VLE_MAX_WIDTH: usize = 9;

/// The smallest and the largest value whose VLE is `width` bytes long, found by
/// asking [`vle_width`] and not by arithmetic; `None` for a width the codec
/// never writes.
///
/// [`vle_width`] never decreases as the value grows, so the largest value of a
/// width is found by bisection, and the smallest is one past the largest value
/// of the width before it.
pub fn vle_range(width: usize) -> Option<(u64, u64)> {
    if width == 0 || width > VLE_MAX_WIDTH {
        return None;
    }
    let largest = |w: usize| -> u64 {
        let (mut lo, mut hi) = (0u64, u64::MAX);
        while lo < hi {
            let mid = lo + (hi - lo) / 2 + (hi - lo) % 2;
            if vle_width(mid) <= w {
                lo = mid;
            } else {
                hi = mid - 1;
            }
        }
        lo
    };
    let min = if width == 1 {
        0
    } else {
        largest(width - 1) + 1
    };
    Some((min, largest(width)))
}

fn check_zid(zid: &[u8]) -> Result<(), ComposeError> {
    if (1..=16).contains(&zid.len()) {
        Ok(())
    } else {
        Err(ComposeError::ZidLength(zid.len()))
    }
}

fn check_priority(priority: Option<u8>) -> Result<Option<Priority>, ComposeError> {
    match priority {
        None => Ok(None),
        Some(p) if p <= 7 => Ok(Some(Priority::from_wire(p))),
        Some(p) => Err(ComposeError::Priority(p)),
    }
}

/// The wire `cbyte`: `whatami` in the low two bits, `zid_len - 1` in the high
/// nibble, the two bits between them reserved and written zero
/// (`commons/zenoh-protocol/src/transport/init.rs` @ `|zid_len|x|x|wai|`).
fn cbyte(whatami: u8, zid_len: usize) -> u8 {
    whatami | (((zid_len as u8) - 1) << 4)
}

fn chain_of(extensions: &[ExtSpec<'_>]) -> Result<Vec<u8>, ComposeError> {
    if extensions.len() > MAX_EXT_CHAIN_DEPTH {
        return Err(ComposeError::ExtensionChain {
            entries: extensions.len(),
        });
    }
    let mut entries: Vec<ExtEntryOwned> = Vec::with_capacity(extensions.len());
    for (index, ext) in extensions.iter().enumerate() {
        if ext.id > 0x0F {
            return Err(ComposeError::ExtensionId { index, id: ext.id });
        }
        let (enc, body) = match ext.body {
            ExtBody::Unit => (0u8, ExtEntryOwnedVariant::CodecZenohExtUnit(ExtUnit {})),
            ExtBody::Z64(value) => (
                1u8,
                ExtEntryOwnedVariant::CodecZenohExtZint(ExtZint { value }),
            ),
            ExtBody::ZBuf(bytes) => (
                2u8,
                ExtEntryOwnedVariant::CodecZenohExtZbuf(ExtZbufOwned {
                    value_len: bytes.len() as u64,
                    value: owned_bytes(bytes)
                        .map_err(|_: CodecError| ComposeError::ExtensionBody { index })?,
                }),
            ),
        };
        let mut header = ext.id | (enc << 5);
        if ext.mandatory {
            header |= 0x10;
        }
        entries.push(ExtEntryOwned { header, body });
    }
    Ok(encode_ext_chain(&entries))
}

/// Compose an INIT message.
///
/// The header's `S` is set iff `size` is present, `A` iff the role is Ack and
/// `Z` iff the chain is not empty; the cookie length is the cookie's.
pub fn compose_init(spec: &InitSpec<'_>) -> Result<Vec<u8>, ComposeError> {
    check_zid(spec.zid)?;
    if spec.whatami > 3 {
        return Err(ComposeError::WhatAmI(spec.whatami));
    }
    if let Some(size) = &spec.size {
        for code in [size.frame_sn_code, size.request_id_code] {
            if code > 3 {
                return Err(ComposeError::ResolutionCode(code));
            }
        }
    }
    let chain = chain_of(spec.extensions)?;
    let mut flags = 0u8;
    if spec.size.is_some() {
        flags |= wire_const::FLAG_T_INIT_S;
    }
    let cookie = match spec.role {
        InitRole::Syn => None,
        InitRole::Ack { cookie } => {
            flags |= wire_const::FLAG_T_INIT_A;
            Some(cookie)
        }
    };
    if !chain.is_empty() {
        flags |= wire_const::FLAG_T_Z;
    }
    let body = InitBody {
        version: spec.version,
        cbyte: cbyte(spec.whatami, spec.zid.len()),
        zid: spec.zid,
        sn_res: spec
            .size
            .map(|s| pack_sn_res(s.frame_sn_code, s.request_id_code)),
        batch_size: spec.size.map(|s| s.batch_size),
        cookie_len: cookie.map(|c| c.len() as u64),
        cookie,
    };
    let mut wire = Vec::with_capacity(1 + InitBody::MAX_ENCODED_BYTES + chain.len());
    wire.push(flags | wire_const::T_MID_INIT);
    {
        let mut sink = VecSink::new(&mut wire);
        body.encode(&mut sink, (flags >> 6) & 1, (flags >> 5) & 1)
            .expect("VecSink is infallible");
    }
    wire.extend_from_slice(&chain);
    Ok(wire)
}

/// Compose an OPEN message.
///
/// `T` follows from the lease ([`lease_to_wire`]: a whole number of seconds
/// travels as seconds) unless the caller names the unit, `A` from the role, `Z`
/// from the chain; the cookie travels on the Syn only, behind its length.
pub fn compose_open(spec: &OpenSpec<'_>) -> Result<Vec<u8>, ComposeError> {
    let chain = chain_of(spec.extensions)?;
    let (in_seconds, wire_lease) = match spec.lease_unit {
        None => lease_to_wire(spec.lease_ms),
        Some(LeaseUnit::Milliseconds) => (false, spec.lease_ms),
        Some(LeaseUnit::Seconds) if spec.lease_ms % 1000 == 0 => (true, spec.lease_ms / 1000),
        Some(LeaseUnit::Seconds) => {
            return Err(ComposeError::LeaseNotWholeSeconds {
                lease_ms: spec.lease_ms,
            })
        }
    };
    let mut flags = 0u8;
    if in_seconds {
        flags |= wire_const::FLAG_T_OPEN_T;
    }
    let cookie = match spec.role {
        OpenRole::Syn { cookie } => Some(cookie),
        OpenRole::Ack => {
            flags |= wire_const::FLAG_T_OPEN_A;
            None
        }
    };
    if !chain.is_empty() {
        flags |= wire_const::FLAG_T_Z;
    }
    let body = OpenBody {
        lease: wire_lease,
        initial_sn: spec.initial_sn,
        cookie_len: cookie.map(|c| c.len() as u64),
        cookie,
    };
    let mut wire = Vec::with_capacity(1 + OpenBody::MAX_ENCODED_BYTES + chain.len());
    wire.push(flags | wire_const::T_MID_OPEN);
    {
        let mut sink = VecSink::new(&mut wire);
        body.encode(&mut sink, (flags >> 5) & 1)
            .expect("VecSink is infallible");
    }
    wire.extend_from_slice(&chain);
    Ok(wire)
}

/// Compose a CLOSE message: `S` set for a whole-session close, clear for a
/// link-only one, then the reason byte as given.
pub fn compose_close(reason: u8, session: bool) -> Vec<u8> {
    let flags = if session {
        wire_const::FLAG_T_CLOSE_S
    } else {
        0
    };
    let mut wire = Vec::with_capacity(2);
    wire.push(flags | wire_const::T_MID_CLOSE);
    let mut sink = VecSink::new(&mut wire);
    Close { reason }
        .encode(&mut sink)
        .expect("VecSink is infallible");
    wire
}

/// Compose a KEEPALIVE message: the header byte and an empty body.
pub fn compose_keep_alive() -> Vec<u8> {
    let mut wire = Vec::with_capacity(1);
    wire.push(wire_const::T_MID_KEEP_ALIVE);
    let mut sink = VecSink::new(&mut wire);
    KeepAlive {}
        .encode(&mut sink)
        .expect("VecSink is infallible");
    wire
}

/// Compose a FRAME message.
pub fn compose_frame(spec: &FrameSpec<'_>) -> Result<Vec<u8>, ComposeError> {
    let priority = check_priority(spec.priority)?;
    Ok(build_frame_wire(
        spec.sn,
        spec.payload,
        spec.reliable,
        priority,
    ))
}

/// Compose a FRAGMENT message.
pub fn compose_fragment(spec: &FragmentSpec<'_>) -> Result<Vec<u8>, ComposeError> {
    let priority = check_priority(spec.priority)?;
    Ok(build_fragment_wire(
        spec.sn,
        spec.payload,
        spec.reliable,
        spec.more,
        spec.first,
        spec.drop_marker,
        priority,
    ))
}

/// Put `body` behind the length prefix `framing` calls for.
///
/// The 16-bit prefix is the `StreamEnvelope` codec the streamed links use. The
/// 32-bit one has no codec: the LowLatency link writes
/// `(buffer.len() - 4) as u32` little-endian into the first four bytes
/// (`io/zenoh-transport/src/unicast/lowlatency/link.rs` @
/// `len = (buffer.len() - 4) as u32;`), and
/// `wz-runtime-tokio`'s stream driver writes the same four bytes by hand.
pub fn frame_unit(framing: Framing, body: &[u8]) -> Result<Vec<u8>, ComposeError> {
    if body.len() as u64 > framing.max_body() {
        return Err(ComposeError::UnitTooLong {
            len: body.len(),
            max: framing.max_body(),
        });
    }
    Ok(match framing {
        Framing::Datagram => body.to_vec(),
        Framing::TcpStream => StreamEnvelope {
            payload_len: body.len() as u16,
            payload: body,
        }
        .encode_to_vec(),
        Framing::LowLatencyStream => {
            let mut wire = Vec::with_capacity(4 + body.len());
            wire.extend_from_slice(&(body.len() as u32).to_le_bytes());
            wire.extend_from_slice(body);
            wire
        }
    })
}

#[cfg(test)]
mod tests;
