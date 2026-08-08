// SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! R311y602 — RFC6455 deframing, so a zenoh session carried over `ws/...`
//! is dissected instead of quietly producing nothing.
//!
//! ## Why this is the hole that mattered
//!
//! Every other gap in this crate announces itself. An unhandled link type, an
//! IPv4 fragment, a non-IP packet — each becomes a typed
//! [`SkipReason`](crate::link::SkipReason) attached to the packet it came
//! from, so a dissection with a hole says where the hole is. WebSocket was the
//! exception, and not by design: a `ws/...` zenoh link is ordinary TCP, so the
//! packets decapsulate perfectly, reassemble perfectly, and hand
//! `wz_session_core::passive` a byte stream that begins `GET / HTTP/1.1` and
//! continues in RFC6455 frames. Nothing refuses it. The stream simply never
//! decodes, and the analyzer reports a capture with no zenoh messages in it —
//! which is indistinguishable from a capture that genuinely had none.
//!
//! It is not a rare configuration either: zenoh's `transport_ws` is in its
//! DEFAULT feature set (`zenoh/Cargo.toml:45`) and the link is native
//! `tokio-tungstenite`, not a browser-only path.
//!
//! ## The framing contract, measured rather than assumed
//!
//! zenoh's ws link reports `is_streamed() = false`
//! (`io/zenoh-links/zenoh-link-ws/src/unicast.rs:225`) and its `write` hands
//! the whole buffer to one `Message::Binary` (`:143`), with `recv` taking one
//! Binary back and rejecting Text / Ping / Pong outright (`:102`). So the
//! WebSocket MESSAGE boundary is the framing, exactly as a UDP datagram
//! boundary is — no length prefix — which is why a deframed message goes to
//! the crate's DATAGRAM ingestion and not through the stream assembler's
//! prefixed path.
//!
//! ⚠ **One deliberate limit, named because it is a real edge and not an
//! oversight.** A non-streamed zenoh link receives a whole BATCH per write,
//! and a batch may hold more than one transport message; this crate's decode
//! seam (`parse_inbound`) reports no consumed length, so every ingestion in
//! this crate — TCP prefixed unit, UDP datagram, raweth frame, and now a ws
//! message — reads exactly ONE transport message per unit. Adding ws on that
//! same contract is consistent with the tree; changing the contract is a
//! separate round and needs a decode entry that reports consumption.
//!
//! ## What is skipped, and counted
//!
//! Control frames (Close / Ping / Pong) and Text frames carry no zenoh, so
//! they are dropped — but [`WsDeframer::skipped_frames`] counts them, because
//! this module exists to end a silent hole and must not open a smaller one.

use alloc::vec::Vec;

/// A continuation of the previous frame's message.
const OP_CONTINUATION: u8 = 0x0;
/// UTF-8 text. zenoh never sends it and its own `recv` treats one as an error.
const OP_TEXT: u8 = 0x1;
/// The one zenoh uses: a whole batch per frame.
const OP_BINARY: u8 = 0x2;
const OP_CLOSE: u8 = 0x8;
const OP_PING: u8 = 0x9;
const OP_PONG: u8 = 0xA;

/// Largest single frame payload, and largest reassembled message, this
/// deframer will buffer.
///
/// zenoh's own batch ceiling is 65535 (a `u16` length), so 16 MiB is far above
/// anything real. It exists because the length field is 64 bits wide and read
/// from a capture: a corrupt or mis-detected stream can claim an allocation
/// nothing bounds, and refusing is the only safe answer to a number that
/// cannot be true.
pub const MAX_WS_PAYLOAD: usize = 1 << 24;

/// Largest HTTP preamble tolerated before the flow is judged not to be
/// WebSocket after all. Real upgrade handshakes are a few hundred bytes.
const MAX_PREAMBLE: usize = 64 * 1024;

/// The two literals a WebSocket-carrying direction can open with: the client's
/// request line and the server's status line. Either alone is enough, which is
/// what lets a ONE-SIDED capture still be recognised — only the server's
/// direction is the normal result of a SPAN port on the wrong side, and
/// refusing to classify it would put this crate's worst failure mode straight
/// back.
const OPENINGS: [&[u8]; 2] = [b"GET ", b"HTTP"];

/// What a direction's opening bytes say about whether it carries WebSocket.
///
/// Three answers and not two, and the third is the one that matters: a caller
/// that must choose between `Yes` and `No` on too few bytes will either stall a
/// short first message forever or misclassify one.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UpgradeVerdict {
    /// An HTTP upgrade handshake.
    Yes,
    /// Not one — and settled, however few bytes there are.
    No,
    /// Still consistent with an opening, and shorter than it. Wait.
    NeedMore,
}

/// Does this direction's opening look like the HTTP half of a WebSocket
/// upgrade?
///
/// Answers `No` the moment the bytes DIVERGE from both openings rather than
/// waiting for a fixed width, and that is not an optimisation. A framed
/// KeepAlive is three bytes (`[1, 0, 0x0F]`), so a detector that demanded four
/// before deciding would hold a flow whose entire first message is shorter than
/// its threshold — forever, with no error. That defect was written, and the
/// negative test below is what caught it.
///
/// A zenoh stream link cannot be mistaken for an opening: its first two bytes
/// are a little-endian length prefix, so `GET ` would be a 17991-byte first
/// message and `HTTP` a 21576-byte one. Both are legal numbers, so the
/// discrimination is not on legality but on these being the literal opening of
/// the other protocol.
pub fn http_upgrade_verdict(prefix: &[u8]) -> UpgradeVerdict {
    let mut need_more = false;
    for opening in OPENINGS {
        if prefix.len() >= opening.len() {
            if &prefix[..opening.len()] == opening {
                return UpgradeVerdict::Yes;
            }
        } else if opening.starts_with(prefix) {
            need_more = true;
        }
    }
    if need_more {
        UpgradeVerdict::NeedMore
    } else {
        UpgradeVerdict::No
    }
}

/// One direction of a WebSocket-carried byte stream, turned into the zenoh
/// batches it holds.
///
/// Fed the same reassembled bytes the stream path would receive, and drained
/// with [`next_message`](Self::next_message) until it says no. Each message
/// comes back with the ABSOLUTE stream offset its first frame started at, so
/// `FlowDissection::packet_for` still resolves a decoded message to the packet
/// that carried it — the attribution this whole crate exists for survives the
/// extra framing layer.
#[derive(Debug, Default)]
pub struct WsDeframer {
    /// Bytes not yet consumed. `buf[0]` sits at stream offset `base`.
    buf: Vec<u8>,
    /// Absolute stream offset of `buf[0]`.
    base: usize,
    /// Has the HTTP upgrade preamble been stepped over?
    preamble_done: bool,
    /// Payload of the message being assembled across continuation frames.
    partial: Vec<u8>,
    /// Stream offset of the FIRST frame of `partial`, or `None` when no
    /// message is in progress.
    partial_offset: Option<usize>,
    /// Set once the byte stream stops making sense as RFC6455. Terminal: a
    /// deframer that has lost the frame boundary cannot find it again, and
    /// guessing would manufacture messages that were never sent.
    desynchronised: bool,
    /// Frames dropped because their opcode carries no zenoh.
    skipped_frames: usize,
}

impl WsDeframer {
    /// A fresh deframer positioned at stream offset 0.
    pub fn new() -> Self {
        Self::default()
    }

    /// Append newly-reassembled bytes for this direction.
    pub fn push(&mut self, bytes: &[u8]) {
        self.buf.extend_from_slice(bytes);
    }

    /// Has this direction stopped making sense as RFC6455?
    ///
    /// Reported rather than silent for the same reason
    /// [`SkipReason`](crate::link::SkipReason) is: a consumer that sees no
    /// messages needs to know whether the wire was empty or the reader gave
    /// up.
    pub fn desynchronised(&self) -> bool {
        self.desynchronised
    }

    /// Frames dropped because they were Close / Ping / Pong / Text.
    pub fn skipped_frames(&self) -> usize {
        self.skipped_frames
    }

    /// The next complete zenoh-carrying message, with the stream offset its
    /// first frame began at.
    pub fn next_message(&mut self) -> Option<(usize, Vec<u8>)> {
        if self.desynchronised {
            return None;
        }
        if !self.preamble_done && !self.step_over_preamble() {
            return None;
        }
        loop {
            let frame_start = self.base;
            let frame = match self.take_frame() {
                Frame::Need => return None,
                Frame::Bad => {
                    self.desynchronised = true;
                    return None;
                }
                Frame::Got(f) => f,
            };
            match frame.opcode {
                OP_CLOSE | OP_PING | OP_PONG | OP_TEXT => {
                    // Control frames may be interleaved INSIDE a fragmented
                    // message (RFC6455 §5.4), so dropping one must not touch
                    // `partial` — clearing it here would truncate the message
                    // being assembled around it.
                    self.skipped_frames += 1;
                }
                OP_BINARY => {
                    if self.partial_offset.is_some() {
                        // A new message starting while one is unfinished means
                        // the frame boundary is not where this reader thinks.
                        self.desynchronised = true;
                        return None;
                    }
                    self.partial = frame.payload;
                    self.partial_offset = Some(frame_start);
                    if frame.fin {
                        return self.take_partial();
                    }
                }
                OP_CONTINUATION => {
                    if self.partial_offset.is_none() {
                        self.desynchronised = true;
                        return None;
                    }
                    if self.partial.len() + frame.payload.len() > MAX_WS_PAYLOAD {
                        self.desynchronised = true;
                        return None;
                    }
                    self.partial.extend_from_slice(&frame.payload);
                    if frame.fin {
                        return self.take_partial();
                    }
                }
                _ => {
                    // A reserved opcode means this is not the protocol we
                    // think it is; guessing past it would invent messages.
                    self.desynchronised = true;
                    return None;
                }
            }
        }
    }

    /// Hand back the assembled message and reset the accumulator.
    fn take_partial(&mut self) -> Option<(usize, Vec<u8>)> {
        let offset = self.partial_offset.take()?;
        Some((offset, core::mem::take(&mut self.partial)))
    }

    /// Consume the HTTP upgrade handshake. `false` means "not yet all here".
    fn step_over_preamble(&mut self) -> bool {
        const END: &[u8] = b"\r\n\r\n";
        if let Some(at) = find(&self.buf, END) {
            let cut = at + END.len();
            self.buf.drain(..cut);
            self.base += cut;
            self.preamble_done = true;
            return true;
        }
        if self.buf.len() > MAX_PREAMBLE {
            // Detected as WebSocket on four bytes and then never terminated:
            // whatever this stream is, it is not an upgrade handshake.
            self.desynchronised = true;
        }
        false
    }

    /// Parse and consume ONE frame off the front of the buffer.
    fn take_frame(&mut self) -> Frame {
        if self.buf.len() < 2 {
            return Frame::Need;
        }
        let b0 = self.buf[0];
        let b1 = self.buf[1];
        let fin = (b0 & 0x80) != 0;
        // RSV1..3 are extension bits. zenoh negotiates no extension, so a set
        // bit means the payload is transformed in a way this reader cannot
        // undo — and a compressed payload handed on as if it were plain would
        // decode into confident nonsense.
        if (b0 & 0x70) != 0 {
            return Frame::Bad;
        }
        let opcode = b0 & 0x0F;
        let masked = (b1 & 0x80) != 0;
        let len7 = (b1 & 0x7F) as usize;

        let mut cursor = 2usize;
        let payload_len = match len7 {
            126 => {
                if self.buf.len() < cursor + 2 {
                    return Frame::Need;
                }
                let n = u16::from_be_bytes([self.buf[cursor], self.buf[cursor + 1]]) as usize;
                cursor += 2;
                n
            }
            127 => {
                if self.buf.len() < cursor + 8 {
                    return Frame::Need;
                }
                let mut raw = [0u8; 8];
                raw.copy_from_slice(&self.buf[cursor..cursor + 8]);
                cursor += 8;
                let n = u64::from_be_bytes(raw);
                // On a 32-bit target the cast would wrap; refusing above the
                // cap first makes the conversion total.
                if n > MAX_WS_PAYLOAD as u64 {
                    return Frame::Bad;
                }
                n as usize
            }
            n => n,
        };
        if payload_len > MAX_WS_PAYLOAD {
            return Frame::Bad;
        }
        let mut key = [0u8; 4];
        if masked {
            if self.buf.len() < cursor + 4 {
                return Frame::Need;
            }
            key.copy_from_slice(&self.buf[cursor..cursor + 4]);
            cursor += 4;
        }
        let total = cursor + payload_len;
        if self.buf.len() < total {
            return Frame::Need;
        }
        let mut payload = self.buf[cursor..total].to_vec();
        if masked {
            // Client-to-server frames are masked by RFC6455 §5.3, so the
            // dialer's whole half of a zenoh session arrives XORed. Skipping
            // this would leave that direction decoding into noise while the
            // acceptor's direction read fine — a half-working dissection,
            // which is worse than none.
            for (i, byte) in payload.iter_mut().enumerate() {
                *byte ^= key[i & 3];
            }
        }
        self.buf.drain(..total);
        self.base += total;
        Frame::Got(ParsedFrame {
            fin,
            opcode,
            payload,
        })
    }
}

/// One parsed RFC6455 frame.
struct ParsedFrame {
    fin: bool,
    opcode: u8,
    payload: Vec<u8>,
}

/// What [`WsDeframer::take_frame`] found.
enum Frame {
    /// A whole frame.
    Got(ParsedFrame),
    /// Not all here yet — wait for more bytes.
    Need,
    /// This is not RFC6455.
    Bad,
}

/// First index of `needle` in `haystack`. `no_std` and no dependencies, so the
/// naive scan is written out; the inputs are one HTTP preamble.
fn find(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || haystack.len() < needle.len() {
        return None;
    }
    (0..=haystack.len() - needle.len()).find(|&i| &haystack[i..i + needle.len()] == needle)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build one RFC6455 frame the way a real endpoint would.
    fn frame(fin: bool, opcode: u8, payload: &[u8], mask: Option<[u8; 4]>) -> Vec<u8> {
        let mut out = Vec::new();
        out.push(if fin { 0x80 | opcode } else { opcode });
        let masked_bit = if mask.is_some() { 0x80u8 } else { 0 };
        match payload.len() {
            n if n < 126 => out.push(masked_bit | n as u8),
            n if n <= u16::MAX as usize => {
                out.push(masked_bit | 126);
                out.extend_from_slice(&(n as u16).to_be_bytes());
            }
            n => {
                out.push(masked_bit | 127);
                out.extend_from_slice(&(n as u64).to_be_bytes());
            }
        }
        match mask {
            Some(key) => {
                out.extend_from_slice(&key);
                for (i, b) in payload.iter().enumerate() {
                    out.push(b ^ key[i & 3]);
                }
            }
            None => out.extend_from_slice(payload),
        }
        out
    }

    const UPGRADE: &[u8] = b"GET / HTTP/1.1\r\nHost: h\r\nUpgrade: websocket\r\n\r\n";

    #[test]
    fn the_detector_answers_for_both_halves_of_the_handshake() {
        assert_eq!(http_upgrade_verdict(b"GET / HTTP/1.1"), UpgradeVerdict::Yes);
        assert_eq!(
            http_upgrade_verdict(b"HTTP/1.1 101 Switching Protocols"),
            UpgradeVerdict::Yes
        );
    }

    /// THE ONE THAT CAUGHT A REAL STALL. A framed KeepAlive is three bytes, so
    /// a verdict that waited for four would hold such a flow forever — no
    /// messages, no error, which is the exact failure this module exists to
    /// end, reintroduced one layer up. Divergence must settle it at byte one.
    #[test]
    fn a_short_zenoh_opening_is_settled_without_waiting_for_four_bytes() {
        assert_eq!(http_upgrade_verdict(&[1, 0, 0x0F]), UpgradeVerdict::No);
        assert_eq!(http_upgrade_verdict(&[1]), UpgradeVerdict::No);
        assert_eq!(http_upgrade_verdict(&[0x0F]), UpgradeVerdict::No);
    }

    /// The other half of the same rule: bytes that are still consistent with an
    /// opening must NOT be decided early, or a one-byte-at-a-time arrival would
    /// classify a real handshake as a plain stream on its first `G`.
    #[test]
    fn a_prefix_of_an_opening_waits() {
        assert_eq!(http_upgrade_verdict(b"G"), UpgradeVerdict::NeedMore);
        assert_eq!(http_upgrade_verdict(b"GE"), UpgradeVerdict::NeedMore);
        assert_eq!(http_upgrade_verdict(b"H"), UpgradeVerdict::NeedMore);
        assert_eq!(http_upgrade_verdict(b"HTT"), UpgradeVerdict::NeedMore);
        // ...but a byte that leaves both openings is settled at once.
        assert_eq!(http_upgrade_verdict(b"GX"), UpgradeVerdict::No);
    }

    #[test]
    fn a_masked_binary_frame_comes_back_unmasked() {
        let mut d = WsDeframer::new();
        d.push(UPGRADE);
        d.push(&frame(
            true,
            OP_BINARY,
            b"zenoh",
            Some([0xAA, 0xBB, 0xCC, 0xDD]),
        ));
        let (offset, msg) = d.next_message().expect("one message");
        assert_eq!(&msg[..], b"zenoh");
        assert_eq!(
            offset,
            UPGRADE.len(),
            "the offset is where the FRAME started, past the preamble"
        );
        assert!(d.next_message().is_none());
        assert!(!d.desynchronised());
    }

    /// THE ONE THAT MATTERS for a real capture: the dialer's whole half of a
    /// zenoh session is masked, so an unmasking bug leaves exactly one
    /// direction decoding into noise.
    #[test]
    fn masked_and_unmasked_halves_yield_the_same_bytes() {
        let payload = b"\x0f-the-same-bytes";
        let mut client = WsDeframer::new();
        client.push(UPGRADE);
        client.push(&frame(true, OP_BINARY, payload, Some([1, 2, 3, 4])));
        let mut server = WsDeframer::new();
        server.push(b"HTTP/1.1 101 Switching Protocols\r\n\r\n");
        server.push(&frame(true, OP_BINARY, payload, None));
        assert_eq!(
            client.next_message().expect("client message").1,
            server.next_message().expect("server message").1
        );
    }

    #[test]
    fn a_fragmented_message_reassembles_and_keeps_its_first_offset() {
        let mut d = WsDeframer::new();
        d.push(UPGRADE);
        let start = UPGRADE.len();
        d.push(&frame(false, OP_BINARY, b"ze", None));
        // A Ping interleaved between fragments is legal (RFC6455 §5.4) and
        // must not truncate the message being assembled.
        d.push(&frame(true, OP_PING, b"", None));
        d.push(&frame(true, OP_CONTINUATION, b"noh", None));
        let (offset, msg) = d.next_message().expect("the reassembled message");
        assert_eq!(&msg[..], b"zenoh");
        assert_eq!(offset, start, "attributed to the FIRST fragment");
        assert_eq!(d.skipped_frames(), 1, "the Ping is counted, not hidden");
    }

    #[test]
    fn a_16_bit_extended_length_is_read() {
        let payload = alloc::vec![0x5Au8; 300];
        let mut d = WsDeframer::new();
        d.push(UPGRADE);
        d.push(&frame(true, OP_BINARY, &payload, None));
        assert_eq!(d.next_message().expect("300-byte message").1.len(), 300);
    }

    #[test]
    fn a_frame_arriving_in_pieces_waits_instead_of_guessing() {
        let bytes = frame(true, OP_BINARY, b"zenoh", None);
        let mut d = WsDeframer::new();
        d.push(UPGRADE);
        for byte in &bytes[..bytes.len() - 1] {
            d.push(&[*byte]);
            assert!(d.next_message().is_none(), "incomplete frame must wait");
        }
        d.push(&bytes[bytes.len() - 1..]);
        assert_eq!(&d.next_message().expect("now complete").1[..], b"zenoh");
        assert!(!d.desynchronised());
    }

    #[test]
    fn an_impossible_length_desynchronises_rather_than_allocating() {
        let mut d = WsDeframer::new();
        d.push(UPGRADE);
        // 127 => a 64-bit length, here u64::MAX.
        d.push(&[0x82, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF]);
        assert!(d.next_message().is_none());
        assert!(
            d.desynchronised(),
            "a length nothing could satisfy must stop the reader, not size a Vec"
        );
    }

    #[test]
    fn a_reserved_bit_stops_the_reader() {
        let mut d = WsDeframer::new();
        d.push(UPGRADE);
        // RSV1 set: a negotiated extension transformed the payload.
        d.push(&[0xC2, 0x02, 0x00, 0x00]);
        assert!(d.next_message().is_none());
        assert!(d.desynchronised());
    }

    #[test]
    fn a_continuation_without_a_start_is_not_invented_into_a_message() {
        let mut d = WsDeframer::new();
        d.push(UPGRADE);
        d.push(&frame(true, OP_CONTINUATION, b"orphan", None));
        assert!(d.next_message().is_none());
        assert!(d.desynchronised());
    }
}
