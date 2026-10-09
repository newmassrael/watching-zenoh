// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! R311nt — transport-agnostic SERIAL-link framing, handshake, and
//! locator logic (the `Z_FEATURE_LINK_SERIAL` upper protocol).
//!
//! This is the link-level layer that sits between the byte-framing
//! codecs ([`wz_codecs::serial_envelope`] / [`wz_codecs::cobs_encode`]
//! / [`wz_codecs::cobs_decode`] / [`wz_codecs::crc32`], landed R311ns)
//! and the byte I/O transport. It mirrors zenoh-pico's
//! `src/link/transport/upper/serial_protocol.c` +
//! `src/protocol/codec/serial.c`, but holds NO I/O — it only transforms
//! bytes, so the SAME logic is reusable by both the AP (tty) and MCU
//! (UART HAL) link drivers. The current form takes `alloc` (owned `Vec`
//! frame buffers + a growable reader accumulator) — the AP staging,
//! matching `transport-fragmentation` / `session-reconnect`; a bounded
//! no-alloc variant for the heap-less MCU profile is a follow-up (it
//! needs a no-alloc `serial_envelope` encode, which the codec does not
//! expose yet — only `encode_to_vec`). The host tty backend
//! (`tokio-serial`) and the `LinkDriver` impl that drives this logic are
//! a separate concern (the runtime-tokio side), exactly as `TcpDriver` /
//! `UdpDriver` sit above the stream/datagram codecs.
//!
//! ## On-wire frame
//!
//! `_z_serial_msg_serialize` (vendor/zenoh-pico/src/protocol/codec/serial.c:28-68)
//! lays out the pre-COBS buffer
//!
//! ```text
//! [ header(1) | payload_len(2 LE) | payload(N) | crc32(4 LE) ]
//! ```
//!
//! (= N + 7 bytes; the `crc32` is `_z_crc32` of the payload only),
//! COBS-encodes it, then appends a single `0x00` end-of-packet (EOP)
//! delimiter. [`encode_frame`] reproduces that pipeline; [`decode_frame`]
//! is the inverse (`_z_serial_msg_deserialize`, serial.c:70-118): COBS
//! destuff, split the fields, and reject on a CRC mismatch.
//!
//! ## Header flags
//!
//! The header byte carries the link-handshake control flags
//! (`definitions/serial.h:53-55`); a steady-state data frame uses
//! `0x00` (no flag set) and the receiver ignores the header on the data
//! path (`_z_read_serial` discards it, serial_protocol.c:282-285).
//!
//! ## Handshake
//!
//! Serial has its OWN link-level handshake BEFORE the zenoh transport
//! INIT/OPEN. `_z_connect_serial` (serial_protocol.c:255-280) is the
//! initiator: it emits an INIT frame and waits for INIT|ACK, throttling
//! and retrying on RESET. [`SerialHandshake`] models both that
//! initiator and its responder dual (receive INIT, reply INIT|ACK) so a
//! wz peer can take either role over a point-to-point link.

use alloc::vec::Vec;

use sce_forge_runtime::codec::SceCursor;
use wz_codecs::cobs_decode::cobs_decode;
use wz_codecs::cobs_encode::cobs_encode;
use wz_codecs::crc32::crc32;
use wz_codecs::serial_envelope::SerialEnvelope;

// ─── size constants (serial_protocol.h:31-34) ───

/// Largest serial payload (zenoh transport message bytes) a single
/// frame carries — `_Z_SERIAL_MTU_SIZE`.
pub const SERIAL_MTU: usize = 1500;
/// Maximum pre-COBS frame size — `_Z_SERIAL_MFS_SIZE`
/// (MTU + 1 header + 2 len + 4 crc32 = 1507). MUST equal the generated
/// `wz_codecs::cobs_decode` bound (it returns `SceBytes<1507>`): a
/// destuffed frame cannot exceed it. No compile-time link to that `N`
/// exists (the codegen does not emit a companion const), so the value is
/// kept in sync by the pico header + the R311ns byte-parity tests.
pub const SERIAL_MFS: usize = SERIAL_MTU + 1 + 2 + 4;
/// Maximum on-the-wire (post-COBS, incl. EOP) buffer size —
/// `_Z_SERIAL_MAX_COBS_BUF_SIZE` (1516). Bounds the read accumulator.
/// MUST equal the generated `wz_codecs::cobs_encode` bound (it returns
/// `SceBytes<1516>`); same hand-sync caveat as [`SERIAL_MFS`].
pub const SERIAL_MAX_COBS_BUF: usize = 1516;

// ─── header flags (definitions/serial.h:53-55) ───
//
// Link-layer handshake flags, NOT zenoh transport/network wire bytes.
// They live here with the handshake FSM that consumes them, deliberately
// NOT in `wz_codecs::wire_const` (the codec wire-shape SSOT): the
// `serial_envelope` codec treats `header` as an opaque `u8`, and these
// flags belong to the serial link protocol that runs BELOW and BEFORE
// the zenoh transport. Co-locating them with their FSM is the correct
// separation — a future "consolidate to wire_const" pass would be wrong.

/// `_Z_FLAG_SERIAL_INIT` — connection-initiate flag.
pub const SERIAL_FLAG_INIT: u8 = 0x01;
/// `_Z_FLAG_SERIAL_ACK` — handshake-acknowledge flag.
pub const SERIAL_FLAG_ACK: u8 = 0x02;
/// `_Z_FLAG_SERIAL_RESET` — peer-not-ready / back-off flag.
pub const SERIAL_FLAG_RESET: u8 = 0x04;

/// The single `0x00` end-of-packet delimiter appended after the COBS
/// body (serial.c:64). COBS guarantees the stuffed body is `0x00`-free,
/// so this byte is an unambiguous frame boundary.
pub const SERIAL_EOP: u8 = 0x00;

// ─── frame encode / decode ───

/// A decoded serial frame: the control `header` byte and the recovered
/// `payload` (the bytes the peer passed to [`encode_frame`]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DecodedFrame {
    pub header: u8,
    pub payload: Vec<u8>,
}

/// Why a serial frame failed to encode or decode.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SerialFrameError {
    /// The payload exceeds [`SERIAL_MTU`] (encode) or the destuffed
    /// frame exceeds [`SERIAL_MFS`] (decode).
    TooLarge,
    /// The COBS stuff/destuff step overran its capacity bound.
    Cobs,
    /// The destuffed buffer is too short to hold header + len + crc32,
    /// or the carried length disagrees with the available bytes.
    Malformed,
    /// The carried CRC32 does not match the CRC32 of the payload —
    /// `_z_serial_msg_deserialize` discards such a frame (serial.c:114).
    CrcMismatch,
}

/// Assemble a serial on-wire frame: `[header|len|payload|crc32]` ->
/// COBS-encode -> append `0x00` EOP (mirror of `_z_serial_msg_serialize`,
/// serial.c:28-68). The returned bytes are exactly what the link writes
/// to the wire.
pub fn encode_frame(header: u8, payload: &[u8]) -> Result<Vec<u8>, SerialFrameError> {
    if payload.len() > SERIAL_MTU {
        return Err(SerialFrameError::TooLarge);
    }
    let env = SerialEnvelope {
        header,
        payload_len: payload.len() as u16,
        payload,
        crc32: crc32(payload),
    };
    let pre_cobs = env.encode_to_vec();
    let cobs = cobs_encode(&pre_cobs).map_err(|_| SerialFrameError::Cobs)?;
    let stuffed = cobs.as_slice();
    let mut out = Vec::with_capacity(stuffed.len() + 1);
    out.extend_from_slice(stuffed);
    out.push(SERIAL_EOP);
    Ok(out)
}

/// Decode one serial on-wire frame (mirror of `_z_serial_msg_deserialize`,
/// serial.c:70-118). `wire` is the COBS body with an optional trailing
/// `0x00` EOP (`cobs_decode` stops on the `0x00` code byte, so the EOP is
/// tolerated). Verifies the carried CRC32 against the payload and rejects
/// on mismatch.
///
/// Total over every byte string. A COBS code byte promises that many bytes
/// follow it, and line noise or a half-written frame can promise more than the
/// frame holds. The generated `cobs_decode` handles that exactly like pico's
/// `_z_cobs_decode` (it bounds every read by the input end, so a truncated
/// group ends decoding with the bytes so far), and the length and CRC checks
/// below then reject the shortened frame the way pico's
/// `_z_serial_msg_deserialize` does -- there is no separate check for it here,
/// so there is one truth about what a damaged frame is. The comparison with
/// the compiled pico codec is `wz_decode_frame_verdict_equals_pico_on_damaged_frames`
/// in `wz-integration-tests`.
pub fn decode_frame(wire: &[u8]) -> Result<DecodedFrame, SerialFrameError> {
    let destuffed = cobs_decode(wire).map_err(|_| SerialFrameError::Cobs)?;
    let frame = destuffed.as_slice();
    if frame.len() > SERIAL_MFS {
        return Err(SerialFrameError::TooLarge);
    }
    let mut cursor = SceCursor::new(frame);
    let env = SerialEnvelope::decode(&mut cursor).map_err(|_| SerialFrameError::Malformed)?;
    // pico rejects a frame whose destuffed length disagrees with the
    // declared field sizes (`expected_size != decoded_size`, serial.c:92).
    // The codec consumes exactly [header|len|payload(len)|crc32]; any
    // leftover bytes after that are trailing garbage -> malformed. (The
    // codec already guarantees `payload.len() == payload_len`, so the
    // only residual divergence from pico's check is surplus bytes.)
    if cursor.remaining() != 0 {
        return Err(SerialFrameError::Malformed);
    }
    if env.crc32 != crc32(env.payload) {
        return Err(SerialFrameError::CrcMismatch);
    }
    Ok(DecodedFrame {
        header: env.header,
        payload: env.payload.to_vec(),
    })
}

/// Streaming frame boundary detector — the wz analogue of
/// `_z_read_serial_internal`'s byte-by-byte read-until-`0x00` loop
/// (serial_protocol.c:145-177). The link driver pushes received bytes
/// one at a time (or in chunks via [`SerialFrameReader::feed`]); a
/// complete frame is yielded when the `0x00` EOP arrives.
#[derive(Debug, Default)]
pub struct SerialFrameReader {
    buf: Vec<u8>,
}

impl SerialFrameReader {
    /// A fresh reader with an empty accumulator.
    pub fn new() -> Self {
        Self { buf: Vec::new() }
    }

    /// Push one received byte. Returns `Ok(Some(frame))` when the byte
    /// is the `0x00` EOP and the accumulated frame decodes; `Ok(None)`
    /// while still mid-frame; `Err` on a framing error (CRC mismatch,
    /// malformed, or accumulator overrun). The accumulator is always
    /// cleared at a frame boundary, so the reader resynchronises on the
    /// next EOP regardless of the outcome.
    pub fn push(&mut self, byte: u8) -> Result<Option<DecodedFrame>, SerialFrameError> {
        if byte == SERIAL_EOP {
            let result = decode_frame(&self.buf);
            self.buf.clear();
            return result.map(Some);
        }
        if self.buf.len() >= SERIAL_MAX_COBS_BUF {
            // The COBS body did not terminate within the on-wire bound.
            // `buf` excludes the 0x00 EOP, so this caps the body at
            // SERIAL_MAX_COBS_BUF; pico's `rb` counts the EOP too, one
            // byte tighter — both reject well past any valid frame (max
            // on-wire ~1514). Desync: drop the partial accumulation.
            self.buf.clear();
            return Err(SerialFrameError::TooLarge);
        }
        self.buf.push(byte);
        Ok(None)
    }

    /// Push a chunk of received bytes, collecting every complete frame
    /// they contain. A framing error on any single frame is returned
    /// immediately (the reader has already resynchronised past it).
    pub fn feed(&mut self, bytes: &[u8]) -> Result<Vec<DecodedFrame>, SerialFrameError> {
        let mut frames = Vec::new();
        for &b in bytes {
            if let Some(frame) = self.push(b)? {
                frames.push(frame);
            }
        }
        Ok(frames)
    }
}

// ─── handshake ───

/// The INIT an accepting side must carry across a flush, found in the bytes the
/// device had received when the flush was taken (open-debt 795).
///
/// A flush exists to discard what an EARLIER peer left on the wire, but an
/// initiator writes its INIT once and re-sends only after a RESET, which a
/// responder never sends: an INIT discarded with the stale bytes is a link that
/// never comes up. So the flush is split by frame. The returned header is the last
/// complete frame the responder handshake would take as its opener
/// ([`SerialHandshake::on_header`] answering [`HandshakeStep::EmitAndConnect`]);
/// every other byte in `received` -- data frames, a frame that fails its CRC, the
/// unterminated tail of a frame cut in half -- is stale and is not reported.
///
/// ## Frames have no leading delimiter
///
/// A frame on the wire is `COBS(body) 0x00`: only its END is marked. pico reads up
/// to and including the first `0x00` and deserialises that whole span as one frame
/// (`_z_read_serial_internal`, serial_protocol.c:145-177), and z-serial 0.3.1, the
/// crate upstream zenoh links, does the same (`internal_read` reads to the sentinel
/// and then `deserialize_into`s the span). Neither resynchronises inside a span:
/// stale bytes that no `0x00` closed, followed by a frame, are ONE span whose CRC
/// fails, so the frame is dropped. [`SerialFrameReader`] keeps exactly that
/// behaviour for the steady state. It is the wrong answer only for an `INIT`,
/// which the peer writes once.
///
/// ## What this adds
///
/// For this flush alone, each span (the bytes between two `0x00`, or from the start
/// of `received`) is searched for the frame that ENDS at its `0x00` from every start
/// offset instead of only the first. An offset is accepted only when
///
/// 1. the bytes from it are a well-formed COBS block sequence that lands exactly on
///    the span end (one backward pass; the span's first offset is tried without
///    this filter, as the reader would have), and
/// 2. [`decode_frame`] accepts them (the decoder is total; the declared length and
///    the CRC32 must agree), and
/// 3. the header is one the responder handshake takes as an opener.
///
/// So stale bytes are mistaken for an `INIT` only by passing the length check, an
/// INIT-without-ACK header and a 32-bit CRC together: below 2^-32 per candidate
/// offset, and a span offers at most [`SERIAL_MAX_COBS_BUF`] candidates (a frame
/// cannot be longer). The wire is not changed and nothing is sent: this only finds
/// the `INIT` the peer already wrote.
///
/// Not recovered, by design: the unterminated tail of `received` (no `0x00` yet, so
/// its end is unknown and what arrives after the flush completes it), so an `INIT`
/// whose body reached the device but whose `0x00` has not is not kept; and an `INIT`
/// that the line corrupted (its CRC fails at every offset).
///
/// Work is `O(n * SERIAL_MAX_COBS_BUF)` at the very worst (every offset of every
/// span lands and every decode runs to the span end) and `O(n)` for ordinary stale
/// bytes, `n` being `received.len()`. The caller bounds `n`: the accept's flush
/// reads at most `SERIAL_FLUSH_LIMIT` (1 MiB) and fails by name past it.
pub fn pending_init_header(received: &[u8]) -> Option<u8> {
    let responder = SerialHandshake::responder();
    let mut init = None;
    let mut span_start = 0;
    for (eop_at, _) in received
        .iter()
        .enumerate()
        .filter(|&(_, &byte)| byte == SERIAL_EOP)
    {
        if let Some(header) = init_header_ending_at(&received[span_start..eop_at], &responder) {
            init = Some(header);
        }
        span_start = eop_at + 1;
    }
    init
}

/// The header of the first responder `INIT` whose frame ENDS at the end of `span`
/// (the bytes before one `0x00` EOP), trying every start offset a frame could have.
/// See [`pending_init_header`] for what is accepted and why.
fn init_header_ending_at(span: &[u8], responder: &SerialHandshake) -> Option<u8> {
    // No frame is longer than SERIAL_MAX_COBS_BUF, so earlier offsets cannot start one.
    let window_start = span.len().saturating_sub(SERIAL_MAX_COBS_BUF);
    let window = &span[window_start..];
    // `lands[i]`: the COBS blocks from `window[i]` end exactly at the window end.
    // A span holds no 0x00, so every code byte steps forward by at least one.
    let mut lands = alloc::vec![false; window.len() + 1];
    lands[window.len()] = true;
    for at in (0..window.len()).rev() {
        let next = at + usize::from(window[at]);
        lands[at] = next <= window.len() && lands[next];
    }
    (0..window.len())
        .filter(|&at| window_start + at == 0 || lands[at])
        .find_map(|at| {
            let frame = decode_frame(&window[at..]).ok()?;
            matches!(
                responder.on_header(frame.header),
                HandshakeStep::EmitAndConnect(_)
            )
            .then_some(frame.header)
        })
}

/// Which side of the point-to-point serial handshake a peer plays.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SerialRole {
    /// Sends INIT, waits for INIT|ACK (`_z_connect_serial`,
    /// serial_protocol.c:255-280).
    Initiator,
    /// Waits for INIT, replies INIT|ACK (the logical dual; in pico the
    /// responder is the remote peer, e.g. a zenoh router serial link).
    Responder,
}

/// The next action the handshake driver should take after feeding a
/// received header (or starting the handshake).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HandshakeStep {
    /// Write these on-wire bytes (the responder's INIT|ACK reply) and
    /// treat the link as established in the same step — after
    /// acknowledging the peer's INIT the responder has nothing further to
    /// exchange. The connected transition is explicit (not implied by a
    /// bare `Emit`), so the driver does not infer link state from role.
    EmitAndConnect(Vec<u8>),
    /// The link handshake completed; the transport layer may proceed.
    Connected,
    /// The peer sent RESET — back off (`SERIAL_CONNECT_THROTTLE_TIME_MS`
    /// in pico) and re-drive via [`SerialHandshake::open`].
    Throttle,
    /// An unexpected header arrived; abort the link
    /// (`_z_connect_serial` returns `_Z_ERR_TRANSPORT_RX_FAILED`).
    Failed,
}

/// Pure serial-link handshake state machine (no I/O). The driver calls
/// [`open`](SerialHandshake::open) to obtain the first frame to send (if
/// any), then feeds each received frame's header to
/// [`on_header`](SerialHandshake::on_header) and acts on the returned
/// [`HandshakeStep`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SerialHandshake {
    role: SerialRole,
}

impl SerialHandshake {
    /// Initiator-side handshake.
    pub fn initiator() -> Self {
        Self {
            role: SerialRole::Initiator,
        }
    }

    /// Responder-side handshake.
    pub fn responder() -> Self {
        Self {
            role: SerialRole::Responder,
        }
    }

    /// The role this handshake plays.
    pub fn role(&self) -> SerialRole {
        self.role
    }

    /// The opening frame to emit, if any. The initiator emits a bare
    /// INIT frame (`_z_connect_serial` line 257-259); the responder
    /// emits nothing until it observes the peer's INIT. Also the
    /// re-drive entry point after a [`HandshakeStep::Throttle`]. The
    /// `Option` expresses ONLY that role asymmetry — encoding an INIT of
    /// empty payload is infallible (well within MTU), so it is `.expect`-ed
    /// rather than folded into `None` (which would alias an impossible
    /// encode failure with "responder is silent").
    pub fn open(&self) -> Option<Vec<u8>> {
        match self.role {
            SerialRole::Initiator => Some(
                encode_frame(SERIAL_FLAG_INIT, &[])
                    .expect("INIT frame (empty payload) is always within MTU"),
            ),
            SerialRole::Responder => None,
        }
    }

    /// Feed a received frame's `header` byte and obtain the next step.
    ///
    /// - Initiator: INIT|ACK -> [`Connected`](HandshakeStep::Connected);
    ///   RESET -> [`Throttle`](HandshakeStep::Throttle); else
    ///   [`Failed`](HandshakeStep::Failed) (serial_protocol.c:266-276).
    /// - Responder: INIT (without ACK) ->
    ///   [`EmitAndConnect`](HandshakeStep::EmitAndConnect) carrying the
    ///   INIT|ACK reply (the connected transition is explicit); any other
    ///   header -> [`Failed`](HandshakeStep::Failed).
    pub fn on_header(&self, header: u8) -> HandshakeStep {
        match self.role {
            SerialRole::Initiator => {
                if has_flag(header, SERIAL_FLAG_INIT) && has_flag(header, SERIAL_FLAG_ACK) {
                    HandshakeStep::Connected
                } else if has_flag(header, SERIAL_FLAG_RESET) {
                    HandshakeStep::Throttle
                } else {
                    HandshakeStep::Failed
                }
            }
            SerialRole::Responder => {
                if has_flag(header, SERIAL_FLAG_INIT) && !has_flag(header, SERIAL_FLAG_ACK) {
                    // INIT|ACK of empty payload is infallible (within MTU),
                    // same as the initiator's INIT in `open`.
                    let ack = encode_frame(SERIAL_FLAG_INIT | SERIAL_FLAG_ACK, &[])
                        .expect("INIT|ACK frame (empty payload) is always within MTU");
                    HandshakeStep::EmitAndConnect(ack)
                } else {
                    HandshakeStep::Failed
                }
            }
        }
    }
}

#[inline]
fn has_flag(header: u8, flag: u8) -> bool {
    header & flag != 0
}

// R311ny — the serial LOCATOR leaf (SerialEndpoint / SerialTarget /
// SerialLocatorError / parse_serial_locator) moved to the ungated
// `crate::locator` module so `AnyLocator::Serial` is an always-present
// variant (eliminating the cross-crate match-exhaustiveness skew). Only
// the FRAMING + HANDSHAKE below stays behind `transport-link-serial`.

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    // ─── frame byte-parity ───

    #[test]
    fn encode_frame_data_matches_pico_pre_cobs_plus_eop() {
        // header 0x00, payload ABCDEF, crc32 0xFBA72077 LE.
        // Pre-COBS frame [00 03 00 AB CD EF 77 20 A7 FB] (serial_envelope
        // byte-parity test), COBS [01 02 03 08 AB CD EF 77 20 A7 FB],
        // + EOP 0x00.
        let wire = encode_frame(0x00, &[0xAB, 0xCD, 0xEF]).expect("encode");
        assert_eq!(
            wire,
            vec![0x01, 0x02, 0x03, 0x08, 0xAB, 0xCD, 0xEF, 0x77, 0x20, 0xA7, 0xFB, 0x00]
        );
    }

    #[test]
    fn encode_frame_init_matches_pico() {
        // INIT frame: header 0x01, empty payload, crc 0x00000000.
        // Pre-COBS [01 00 00 00 00 00 00], COBS [02 01 01 01 01 01 01 01],
        // + EOP.
        let wire = encode_frame(SERIAL_FLAG_INIT, &[]).expect("encode INIT");
        assert_eq!(
            wire,
            vec![0x02, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x00]
        );
    }

    #[test]
    fn encode_frame_init_ack_matches_pico() {
        // INIT|ACK frame: header 0x03, empty payload.
        // Pre-COBS [03 00 00 00 00 00 00], COBS [02 03 01 01 01 01 01 01],
        // + EOP.
        let wire = encode_frame(SERIAL_FLAG_INIT | SERIAL_FLAG_ACK, &[]).expect("encode ACK");
        assert_eq!(
            wire,
            vec![0x02, 0x03, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x00]
        );
    }

    #[test]
    fn decode_frame_inverts_encode() {
        for &(header, payload) in &[
            (0x00u8, &[0xAB, 0xCD, 0xEF][..]),
            (0x01u8, &[][..]),
            (0x00u8, &[0x00, 0x00, 0x11][..]),
            (0x00u8, &[0x42; 257][..]),
        ] {
            let wire = encode_frame(header, payload).expect("encode");
            let decoded = decode_frame(&wire).expect("decode");
            assert_eq!(decoded.header, header);
            assert_eq!(decoded.payload, payload);
        }
    }

    #[test]
    fn decode_frame_tolerates_missing_eop() {
        // cobs_decode stops on the 0x00 code byte, so a frame body
        // without the trailing EOP still decodes.
        let wire = encode_frame(0x00, &[0xAB, 0xCD, 0xEF]).expect("encode");
        let no_eop = &wire[..wire.len() - 1];
        let decoded = decode_frame(no_eop).expect("decode without EOP");
        assert_eq!(decoded.payload, vec![0xAB, 0xCD, 0xEF]);
    }

    #[test]
    fn decode_frame_rejects_crc_mismatch() {
        // Flip a payload byte inside the COBS body so the carried CRC no
        // longer matches; the envelope still decodes but the CRC check
        // fails (pico discards: serial.c:114).
        let mut wire = encode_frame(0x00, &[0xAB, 0xCD, 0xEF]).expect("encode");
        // byte index 4 is the first payload byte (0xAB) inside COBS.
        wire[4] ^= 0xFF;
        assert_eq!(decode_frame(&wire), Err(SerialFrameError::CrcMismatch));
    }

    #[test]
    fn decode_frame_rejects_trailing_bytes() {
        // pico rejects a destuffed frame longer than its declared fields
        // (`expected_size != decoded_size`, serial.c:92). Build a valid
        // frame's pre-COBS bytes, append one extra byte, re-COBS: the
        // envelope still decodes but the leftover byte must be rejected.
        let env = SerialEnvelope {
            header: 0x00,
            payload_len: 3,
            payload: &[0xAB, 0xCD, 0xEF],
            crc32: crc32(&[0xAB, 0xCD, 0xEF]),
        };
        let mut pre_cobs = env.encode_to_vec();
        pre_cobs.push(0x99); // trailing garbage after crc32
        let cobs = cobs_encode(&pre_cobs).expect("cobs");
        let mut wire = cobs.as_slice().to_vec();
        wire.push(SERIAL_EOP);
        assert_eq!(decode_frame(&wire), Err(SerialFrameError::Malformed));
    }

    #[test]
    fn encode_frame_rejects_oversize_payload() {
        let too_big = vec![0u8; SERIAL_MTU + 1];
        assert_eq!(
            encode_frame(0x00, &too_big),
            Err(SerialFrameError::TooLarge)
        );
    }

    #[test]
    fn encode_frame_accepts_mtu_payload() {
        let max = vec![0x55u8; SERIAL_MTU];
        let wire = encode_frame(0x00, &max).expect("MTU payload encodes");
        let decoded = decode_frame(&wire).expect("MTU payload decodes");
        assert_eq!(decoded.payload.len(), SERIAL_MTU);
    }

    // ─── streaming reader ───

    #[test]
    fn reader_yields_frame_at_eop() {
        let wire = encode_frame(0x00, &[0xAB, 0xCD, 0xEF]).expect("encode");
        let mut reader = SerialFrameReader::new();
        let mut got = None;
        for &b in &wire {
            if let Some(frame) = reader.push(b).expect("push") {
                got = Some(frame);
            }
        }
        let frame = got.expect("one frame at EOP");
        assert_eq!(frame.header, 0x00);
        assert_eq!(frame.payload, vec![0xAB, 0xCD, 0xEF]);
    }

    #[test]
    fn reader_feed_splits_multiple_frames() {
        let mut stream = encode_frame(0x00, &[0x11, 0x22]).expect("f1");
        stream.extend(encode_frame(0x00, &[0x00, 0x33]).expect("f2"));
        stream.extend(encode_frame(0x01, &[]).expect("f3"));

        let mut reader = SerialFrameReader::new();
        let frames = reader.feed(&stream).expect("feed");
        assert_eq!(frames.len(), 3);
        assert_eq!(frames[0].payload, vec![0x11, 0x22]);
        assert_eq!(frames[1].payload, vec![0x00, 0x33]);
        assert_eq!(frames[2].header, 0x01);
        assert_eq!(frames[2].payload, Vec::<u8>::new());
    }

    #[test]
    fn reader_propagates_crc_error_and_resyncs() {
        let mut bad = encode_frame(0x00, &[0xAB, 0xCD, 0xEF]).expect("encode");
        bad[4] ^= 0xFF;
        let good = encode_frame(0x00, &[0x11]).expect("encode");

        let mut reader = SerialFrameReader::new();
        assert_eq!(reader.feed(&bad), Err(SerialFrameError::CrcMismatch));
        // The reader cleared its accumulator at the bad EOP, so the next
        // well-formed frame still decodes.
        let frames = reader.feed(&good).expect("resync");
        assert_eq!(frames.len(), 1);
        assert_eq!(frames[0].payload, vec![0x11]);
    }

    /// A COBS code byte promises that many bytes follow it; line noise can promise
    /// more than the frame holds. The decoder is total (it ends the group at the
    /// input end like pico's), so the shortened frame reaches the length check and
    /// is rejected there: this is the byte string the open-debt 795 accept flush
    /// meets on a wire with a stale, mangled frame on it.
    #[test]
    fn a_cobs_block_that_overruns_the_frame_is_rejected_and_the_reader_resyncs() {
        let mut reader = SerialFrameReader::new();
        assert_eq!(
            reader.feed(b"\x11\x22\x33-mangled\x00"),
            Err(SerialFrameError::Malformed)
        );
        let good = encode_frame(0x00, &[0x11]).expect("encode");
        let frames = reader.feed(&good).expect("resync");
        assert_eq!(frames[0].payload, vec![0x11]);
    }

    /// Cutting a valid frame at any byte, with or without the EOP put back,
    /// never panics and is never accepted: the shortened frame fails the length
    /// or CRC check. (The same sweep against the real pico codec, and against
    /// overwritten code bytes, is in `wz-integration-tests`.)
    #[test]
    fn every_strict_prefix_of_a_frame_is_rejected_without_panicking() {
        for payload in [&[][..], &[0x00, 0x11, 0x00][..], &[0xAB; 600][..]] {
            let wire = encode_frame(0x00, payload).expect("encode");
            for cut in 0..wire.len() - 1 {
                assert!(decode_frame(&wire[..cut]).is_err(), "cut {cut}");
                let mut with_eop = wire[..cut].to_vec();
                with_eop.push(SERIAL_EOP);
                assert!(decode_frame(&with_eop).is_err(), "cut {cut} + EOP");
            }
        }
    }

    #[test]
    fn a_cobs_block_that_ends_exactly_at_the_frame_end_is_not_an_overrun() {
        // Code 0x03 promises two data bytes and there are exactly two.
        assert_eq!(
            decode_frame(&[0x03, 0xAA, 0xBB, 0x00]),
            Err(SerialFrameError::Malformed),
            "well-formed COBS, too short to be a frame: rejected by the envelope, \
             not by the COBS check"
        );
    }

    // ─── handshake ───

    #[test]
    fn initiator_opens_with_init_frame() {
        let hs = SerialHandshake::initiator();
        let init = hs.open().expect("initiator emits INIT");
        // INIT frame on the wire.
        assert_eq!(init, encode_frame(SERIAL_FLAG_INIT, &[]).unwrap());
        // And it decodes back to a bare INIT header.
        assert_eq!(decode_frame(&init).unwrap().header, SERIAL_FLAG_INIT);
    }

    #[test]
    fn responder_is_silent_until_init() {
        assert_eq!(SerialHandshake::responder().open(), None);
    }

    #[test]
    fn initiator_connects_on_init_ack() {
        let hs = SerialHandshake::initiator();
        assert_eq!(
            hs.on_header(SERIAL_FLAG_INIT | SERIAL_FLAG_ACK),
            HandshakeStep::Connected
        );
    }

    #[test]
    fn initiator_throttles_on_reset() {
        let hs = SerialHandshake::initiator();
        assert_eq!(hs.on_header(SERIAL_FLAG_RESET), HandshakeStep::Throttle);
    }

    #[test]
    fn initiator_fails_on_unexpected_header() {
        let hs = SerialHandshake::initiator();
        // A bare INIT (no ACK) is not a valid initiator response.
        assert_eq!(hs.on_header(SERIAL_FLAG_INIT), HandshakeStep::Failed);
    }

    #[test]
    fn responder_acks_init() {
        let hs = SerialHandshake::responder();
        match hs.on_header(SERIAL_FLAG_INIT) {
            HandshakeStep::EmitAndConnect(ack) => {
                assert_eq!(
                    ack,
                    encode_frame(SERIAL_FLAG_INIT | SERIAL_FLAG_ACK, &[]).unwrap()
                );
            }
            other => panic!("responder must emit INIT|ACK and connect, got {other:?}"),
        }
    }

    #[test]
    fn handshake_roles_drive_each_other() {
        // End-to-end over the frame codec: initiator INIT -> responder
        // decodes -> emits INIT|ACK -> initiator decodes -> Connected.
        let initiator = SerialHandshake::initiator();
        let responder = SerialHandshake::responder();

        let init_wire = initiator.open().expect("INIT");
        let init_hdr = decode_frame(&init_wire).expect("decode INIT").header;

        let ack_wire = match responder.on_header(init_hdr) {
            HandshakeStep::EmitAndConnect(bytes) => bytes,
            other => panic!("expected ACK emit + connect, got {other:?}"),
        };
        let ack_hdr = decode_frame(&ack_wire).expect("decode ACK").header;

        assert_eq!(initiator.on_header(ack_hdr), HandshakeStep::Connected);
    }

    // ─── pending_init_header (open-debt 795) ───

    fn init_wire() -> Vec<u8> {
        encode_frame(SERIAL_FLAG_INIT, &[]).unwrap()
    }

    #[test]
    fn a_wire_with_no_bytes_holds_no_init() {
        assert_eq!(pending_init_header(&[]), None);
    }

    #[test]
    fn a_lone_init_frame_is_kept() {
        assert_eq!(pending_init_header(&init_wire()), Some(SERIAL_FLAG_INIT));
    }

    #[test]
    fn frames_a_responder_would_not_take_as_its_opener_are_not_kept() {
        for header in [0x00, SERIAL_FLAG_INIT | SERIAL_FLAG_ACK, SERIAL_FLAG_RESET] {
            let wire = encode_frame(header, b"x").unwrap();
            assert_eq!(
                pending_init_header(&wire),
                None,
                "header {header:#04x} is stale to a responder"
            );
        }
    }

    #[test]
    fn stale_frames_before_and_after_an_init_are_dropped_and_the_init_is_kept() {
        let mut wire = encode_frame(0x00, b"left behind").unwrap();
        wire.extend_from_slice(b"\x11\x22\x33-mangled\x00");
        wire.extend_from_slice(&init_wire());
        wire.extend_from_slice(&encode_frame(0x00, b"after").unwrap());
        assert_eq!(pending_init_header(&wire), Some(SERIAL_FLAG_INIT));
    }

    #[test]
    fn an_init_cut_off_before_its_end_marker_is_not_a_frame_yet() {
        let wire = init_wire();
        assert_eq!(pending_init_header(&wire[..wire.len() - 1]), None);
    }

    /// Stale bytes that no EOP closed: truncated frame bodies of every length, runs
    /// that look like COBS codes, and one longer than any frame.
    fn stale_fragments() -> Vec<Vec<u8>> {
        let mut fragments = Vec::new();
        let body = encode_frame(0x00, b"a frame the dead peer was sending").unwrap();
        for cut in 1..body.len() - 1 {
            fragments.push(body[..cut].to_vec());
        }
        for len in 1..=64usize {
            fragments.push(alloc::vec![0x01; len]);
            fragments.push(alloc::vec![0xFF; len]);
            fragments.push((0..len).map(|i| (i % 254) as u8 + 1).collect());
        }
        fragments.push(alloc::vec![0x55; 3 * SERIAL_MAX_COBS_BUF + 7]);
        fragments
    }

    /// With no EOP between them a stale fragment and the INIT that follows are one
    /// span on the wire, and pico (and upstream) drop that span on its CRC. The
    /// accept's flush searches the span for the frame that ends at its EOP, so the
    /// INIT, which its peer wrote once, is not lost behind the fragment.
    #[test]
    fn an_unterminated_fragment_glued_to_an_init_does_not_hide_it() {
        for fragment in stale_fragments() {
            let mut wire = fragment.clone();
            wire.extend_from_slice(&init_wire());
            assert_eq!(
                pending_init_header(&wire),
                Some(SERIAL_FLAG_INIT),
                "fragment of {} byte(s) {:02X?}",
                fragment.len(),
                &fragment[..fragment.len().min(8)]
            );
        }
    }

    /// Fragment, data frame, fragment, INIT, fragment, INIT: the LAST INIT wins, as
    /// it did when only whole frames were looked at, and the stale data frame and
    /// the fragments around it are not reported.
    #[test]
    fn the_last_init_wins_among_fragments_and_data_frames() {
        let first = encode_frame(SERIAL_FLAG_INIT, &[]).unwrap();
        let second = encode_frame(SERIAL_FLAG_INIT | SERIAL_FLAG_RESET, &[]).unwrap();
        let data = encode_frame(0x00, b"stale data").unwrap();
        let fragment = b"\x07\x22\x33".to_vec();

        let mut wire = fragment.clone();
        wire.extend_from_slice(&data);
        wire.extend_from_slice(&fragment);
        wire.extend_from_slice(&first);
        wire.extend_from_slice(&fragment);
        wire.extend_from_slice(&second);
        assert_eq!(
            pending_init_header(&wire),
            Some(SERIAL_FLAG_INIT | SERIAL_FLAG_RESET)
        );

        // The same bytes with the two INITs swapped: the answer follows the order
        // on the wire, not the header value.
        let mut swapped = fragment.clone();
        swapped.extend_from_slice(&data);
        swapped.extend_from_slice(&fragment);
        swapped.extend_from_slice(&second);
        swapped.extend_from_slice(&fragment);
        swapped.extend_from_slice(&first);
        assert_eq!(pending_init_header(&swapped), Some(SERIAL_FLAG_INIT));

        // A fragment glued to a data frame, with nothing after it, holds no INIT.
        let mut stale = fragment;
        stale.extend_from_slice(&data);
        assert_eq!(pending_init_header(&stale), None);
    }

    /// Bytes that are no INIT keep nothing, however the search is aimed at them:
    /// every nonzero byte pair and triple-with-codes, runs of valid-looking codes,
    /// and frames a responder does not take as its opener, all closed by an EOP.
    #[test]
    fn garbage_holds_no_init() {
        for first in 1..=255u8 {
            for second in 1..=255u8 {
                assert_eq!(
                    pending_init_header(&[first, second, SERIAL_EOP]),
                    None,
                    "{first:02X} {second:02X}"
                );
            }
        }
        for fragment in stale_fragments() {
            let mut closed = fragment.clone();
            closed.push(SERIAL_EOP);
            assert_eq!(pending_init_header(&closed), None);
            let mut with_data = fragment;
            with_data.extend_from_slice(&encode_frame(0x00, b"x").unwrap());
            assert_eq!(pending_init_header(&with_data), None);
        }
        for header in [0x00, SERIAL_FLAG_INIT | SERIAL_FLAG_ACK, SERIAL_FLAG_RESET] {
            let mut wire = b"\x05\x11".to_vec();
            wire.extend_from_slice(&encode_frame(header, &[]).unwrap());
            assert_eq!(pending_init_header(&wire), None, "header {header:#04x}");
        }
    }

    /// The limits of the search, stated and held so nobody mistakes the recovery
    /// for a guarantee. An INIT whose body reached the device but whose EOP has not
    /// is the unterminated tail: its end is unknown, so it is not kept (what arrives
    /// after the flush completes it). An INIT the line corrupted fails its CRC at
    /// every offset, however it is placed.
    #[test]
    fn what_the_search_does_not_recover() {
        let init = init_wire();
        let mut cut = b"\x11\x22\x33".to_vec();
        cut.extend_from_slice(&init[..init.len() - 1]);
        assert_eq!(pending_init_header(&cut), None, "no EOP yet");

        // The control: the same frame, intact, is found behind the same fragment.
        let intact = encode_frame(SERIAL_FLAG_INIT, b"abc").unwrap();
        let mut found = b"\x11\x22\x33".to_vec();
        found.extend_from_slice(&intact);
        assert_eq!(pending_init_header(&found), Some(SERIAL_FLAG_INIT));

        let mut corrupt = intact.clone();
        let payload_at = corrupt.iter().position(|&b| b == b'a').expect("payload");
        corrupt[payload_at] ^= 0x01;
        let mut glued = b"\x11\x22\x33".to_vec();
        glued.extend_from_slice(&corrupt);
        assert_eq!(pending_init_header(&glued), None, "corrupted INIT");
        assert_eq!(pending_init_header(&corrupt), None, "corrupted INIT alone");
    }

    /// The search is bounded by the frame limit per span, not by the span: an INIT
    /// behind more stale bytes than a frame can hold is found, and many long spans
    /// of the most search-friendly bytes (every offset lands) stay cheap.
    #[test]
    fn the_search_is_bounded_by_the_frame_limit() {
        let mut wire = Vec::new();
        for _ in 0..8 {
            wire.extend_from_slice(&alloc::vec![0x01; SERIAL_MAX_COBS_BUF + 400]);
            wire.push(SERIAL_EOP);
        }
        wire.extend_from_slice(&alloc::vec![0x01; 10 * SERIAL_MAX_COBS_BUF]);
        wire.extend_from_slice(&init_wire());
        assert_eq!(pending_init_header(&wire), Some(SERIAL_FLAG_INIT));
    }

    // R311ny — serial-locator parse tests moved with their leaf to
    // `crate::locator` (the framing / handshake tests above stay here).
}
