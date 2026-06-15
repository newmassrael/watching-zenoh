// SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! R311nt — transport-agnostic SERIAL-link framing, handshake, and
//! locator logic (the `Z_FEATURE_LINK_SERIAL` upper protocol).
//!
//! This is the link-level layer that sits between the byte-framing
//! codecs ([`wz_codecs::serial_envelope`] / [`wz_codecs::cobs_encode`]
//! / [`wz_codecs::cobs_decode`] / [`wz_codecs::crc32`], landed R311ns)
//! and the byte I/O transport. It mirrors zenoh-pico's
//! `src/link/transport/upper/serial_protocol.c` +
//! `src/protocol/codec/serial.c`, but holds NO I/O: it transforms
//! bytes, so it compiles on both the AP (tty) and MCU (UART HAL)
//! profiles. The host tty backend (`tokio-serial`) and the
//! `LinkDriver` impl that drives this logic are a separate concern
//! (the runtime-tokio side), exactly as `TcpDriver` / `UdpDriver`
//! sit above the stream/datagram codecs.
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

use alloc::string::{String, ToString};
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
/// (MTU + 1 header + 2 len + 4 crc32 = 1507).
pub const SERIAL_MFS: usize = SERIAL_MTU + 1 + 2 + 4;
/// Maximum on-the-wire (post-COBS, incl. EOP) buffer size —
/// `_Z_SERIAL_MAX_COBS_BUF_SIZE` (1516). Bounds the read accumulator.
pub const SERIAL_MAX_COBS_BUF: usize = 1516;

// ─── header flags (definitions/serial.h:53-55) ───

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
pub fn decode_frame(wire: &[u8]) -> Result<DecodedFrame, SerialFrameError> {
    let destuffed = cobs_decode(wire).map_err(|_| SerialFrameError::Cobs)?;
    let frame = destuffed.as_slice();
    if frame.len() > SERIAL_MFS {
        return Err(SerialFrameError::TooLarge);
    }
    let mut cursor = SceCursor::new(frame);
    let env = SerialEnvelope::decode(&mut cursor).map_err(|_| SerialFrameError::Malformed)?;
    if env.payload_len as usize != env.payload.len() {
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
            // A frame that never terminates within the on-wire bound is a
            // desync; drop the partial accumulation and report the error.
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
    /// Write these on-wire bytes (an INIT or INIT|ACK frame).
    Emit(Vec<u8>),
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
    /// re-drive entry point after a [`HandshakeStep::Throttle`].
    pub fn open(&self) -> Option<Vec<u8>> {
        match self.role {
            // INIT frame: header=INIT, empty payload. Infallible (empty
            // payload is within bound), but surfaced as Option for the
            // role asymmetry, not for encode failure.
            SerialRole::Initiator => encode_frame(SERIAL_FLAG_INIT, &[]).ok(),
            SerialRole::Responder => None,
        }
    }

    /// Feed a received frame's `header` byte and obtain the next step.
    ///
    /// - Initiator: INIT|ACK -> [`Connected`](HandshakeStep::Connected);
    ///   RESET -> [`Throttle`](HandshakeStep::Throttle); else
    ///   [`Failed`](HandshakeStep::Failed) (serial_protocol.c:266-276).
    /// - Responder: INIT (without ACK) -> emit INIT|ACK and
    ///   [`Connected`](HandshakeStep::Connected) — modelled as a single
    ///   `Emit` step (the caller treats reaching it as connected); any
    ///   other header -> [`Failed`](HandshakeStep::Failed).
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
                    match encode_frame(SERIAL_FLAG_INIT | SERIAL_FLAG_ACK, &[]) {
                        Ok(ack) => HandshakeStep::Emit(ack),
                        Err(_) => HandshakeStep::Failed,
                    }
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

// ─── locator parsing ───

/// The connection target of a serial endpoint: a host device path
/// (`/dev/ttyUSB0`) or a GPIO TX/RX pin pair (MCU). Mirrors pico's
/// `_z_serial_endpoint_cfg_t` dev-vs-pins split (serial_protocol.c:79-131).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SerialTarget {
    /// A device path opened by the host tty backend.
    Device(String),
    /// A TX/RX GPIO pin pair (MCU UART HAL).
    Pins { tx: u32, rx: u32 },
}

/// A parsed `serial/...` locator: its connection target and baud rate.
/// The baud-rate *value* is carried verbatim (any `u32`); validating it
/// against a supported speed table is the tty backend's concern, not the
/// parser's (pico parses the `u32` here and validates at tty-open,
/// tty_posix.c:27-56).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SerialEndpoint {
    pub target: SerialTarget,
    pub baudrate: u32,
}

/// Why a `serial/...` locator string did not parse.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SerialLocatorError {
    /// The locator does not begin with the `serial/` scheme.
    NotSerialScheme,
    /// The address (between the scheme and the `#config`) is empty.
    EmptyAddress,
    /// The required `baudrate=<u32>` config key is absent.
    MissingBaudrate,
    /// A config value (the baud rate, or a pin) is not a valid `u32`.
    BadNumber(String),
}

const SERIAL_SCHEME: &str = "serial";
const SERIAL_BAUDRATE_KEY: &str = "baudrate";

/// Parse a zenoh serial locator into a [`SerialEndpoint`].
///
/// Accepted forms (mirror of `_z_serial_endpoint_parse`,
/// serial_protocol.c:79-131):
/// - device: `serial//dev/ttyUSB0#baudrate=115200`
/// - pins:   `serial/12.13#baudrate=115200`
///
/// The scheme is the substring before the first `/`; the remainder is
/// `<address>#<config>` (config optional in shape, but `baudrate` is
/// required). An address containing `.` is read as a `TX.RX` pin pair,
/// otherwise as a device path — the same `.`-heuristic pico uses
/// (serial_protocol.c:109).
pub fn parse_serial_locator(locator: &str) -> Result<SerialEndpoint, SerialLocatorError> {
    let (scheme, rest) = locator
        .split_once('/')
        .ok_or(SerialLocatorError::NotSerialScheme)?;
    if scheme != SERIAL_SCHEME {
        return Err(SerialLocatorError::NotSerialScheme);
    }

    let (address, config) = match rest.split_once('#') {
        Some((addr, cfg)) => (addr, cfg),
        None => (rest, ""),
    };
    if address.is_empty() {
        return Err(SerialLocatorError::EmptyAddress);
    }

    let baudrate = parse_baudrate(config)?;

    let target = match address.split_once('.') {
        Some((tx_str, rx_str)) => {
            let tx = parse_u32(tx_str)?;
            let rx = parse_u32(rx_str)?;
            SerialTarget::Pins { tx, rx }
        }
        None => SerialTarget::Device(address.to_string()),
    };

    Ok(SerialEndpoint { target, baudrate })
}

/// Extract the required `baudrate=<u32>` from the `#`-delimited config
/// tail (`key=value` pairs separated by `;`). Only `baudrate` is
/// recognised — pico's serial config map has exactly one key
/// (config/serial.h:29-52).
fn parse_baudrate(config: &str) -> Result<u32, SerialLocatorError> {
    for pair in config.split(';') {
        if let Some((key, value)) = pair.split_once('=') {
            if key == SERIAL_BAUDRATE_KEY {
                return parse_u32(value);
            }
        }
    }
    Err(SerialLocatorError::MissingBaudrate)
}

fn parse_u32(s: &str) -> Result<u32, SerialLocatorError> {
    s.parse::<u32>()
        .map_err(|_| SerialLocatorError::BadNumber(s.to_string()))
}

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
            HandshakeStep::Emit(ack) => {
                assert_eq!(
                    ack,
                    encode_frame(SERIAL_FLAG_INIT | SERIAL_FLAG_ACK, &[]).unwrap()
                );
            }
            other => panic!("responder must emit INIT|ACK, got {other:?}"),
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
            HandshakeStep::Emit(bytes) => bytes,
            other => panic!("expected ACK emit, got {other:?}"),
        };
        let ack_hdr = decode_frame(&ack_wire).expect("decode ACK").header;

        assert_eq!(initiator.on_header(ack_hdr), HandshakeStep::Connected);
    }

    // ─── locator parsing ───

    #[test]
    fn parses_device_locator() {
        let ep = parse_serial_locator("serial//dev/ttyUSB0#baudrate=115200").expect("device");
        assert_eq!(ep.target, SerialTarget::Device("/dev/ttyUSB0".to_string()));
        assert_eq!(ep.baudrate, 115200);
    }

    #[test]
    fn parses_pins_locator() {
        let ep = parse_serial_locator("serial/12.13#baudrate=9600").expect("pins");
        assert_eq!(ep.target, SerialTarget::Pins { tx: 12, rx: 13 });
        assert_eq!(ep.baudrate, 9600);
    }

    #[test]
    fn rejects_non_serial_scheme() {
        assert_eq!(
            parse_serial_locator("tcp/127.0.0.1:7447"),
            Err(SerialLocatorError::NotSerialScheme)
        );
    }

    #[test]
    fn rejects_missing_separator() {
        assert_eq!(
            parse_serial_locator("serial"),
            Err(SerialLocatorError::NotSerialScheme)
        );
    }

    #[test]
    fn rejects_empty_address() {
        assert_eq!(
            parse_serial_locator("serial/#baudrate=115200"),
            Err(SerialLocatorError::EmptyAddress)
        );
    }

    #[test]
    fn rejects_missing_baudrate() {
        assert_eq!(
            parse_serial_locator("serial//dev/ttyUSB0"),
            Err(SerialLocatorError::MissingBaudrate)
        );
    }

    #[test]
    fn rejects_bad_baudrate() {
        assert_eq!(
            parse_serial_locator("serial//dev/ttyUSB0#baudrate=fast"),
            Err(SerialLocatorError::BadNumber("fast".to_string()))
        );
    }
}
