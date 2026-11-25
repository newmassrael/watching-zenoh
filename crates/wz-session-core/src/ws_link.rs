// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The RFC 6455 pieces a WebSocket link is made of, with no heap: the opening handshake's
//! request and response, the `Sec-WebSocket-Accept` value (SHA-1 and base64), the frame header,
//! the mask, and the generator a client draws its mask keys from.
//!
//! zenoh's WebSocket link writes each batch as one BINARY message
//! (`io/zenoh-links/zenoh-link-ws/src/unicast.rs` @ `let msg = buffer.into();`) after the
//! upgrade its WebSocket library runs (@ `tokio_tungstenite::connect_async(dst_url.as_str())`,
//! a request to `ws://<address>`, path `/`). What is read here is what that library writes, and
//! what is written here is what it reads.
//!
//! SHA-1 serves the accept value alone, a check that the server read the upgrade and not a
//! secret, so a small hash run once per handshake is all it needs. The mask keys are another
//! matter: RFC 6455 section 5.3 asks that each be unpredictable, so they come from ChaCha20 keyed
//! once from the platform's entropy ([`MaskKeys`]), never from a counter.

use core::fmt;
use core::net::SocketAddr;

use crate::text_out::TextOut;

/// The GUID RFC 6455 section 1.3 appends to the client's key before hashing it.
const ACCEPT_GUID: &[u8] = b"258EAFA5-E914-47DA-95CA-C5AB0DC85B11";

/// The length of a client's `Sec-WebSocket-Key`: sixteen bytes in base64.
pub const KEY_LEN: usize = 24;

/// The length of a `Sec-WebSocket-Accept` value: a SHA-1 digest in base64.
pub const ACCEPT_LEN: usize = 28;

/// The longest frame header: two bytes, a 64-bit length and a mask key.
pub const MAX_HEAD_LEN: usize = 14;

/// The longest payload of a control frame (RFC 6455 section 5.5).
pub const MAX_CONTROL_PAYLOAD: usize = 125;

/// A frame that continues a fragmented message.
pub const OP_CONTINUATION: u8 = 0x0;
/// A frame of a text message.
pub const OP_TEXT: u8 = 0x1;
/// A frame of a binary message, the kind a batch rides in.
pub const OP_BINARY: u8 = 0x2;
/// A Close frame.
pub const OP_CLOSE: u8 = 0x8;
/// A Ping frame.
pub const OP_PING: u8 = 0x9;
/// A Pong frame.
pub const OP_PONG: u8 = 0xA;

/// The status a Close frame carries when the endpoint ends the link of its own will.
pub const CLOSE_NORMAL: u16 = 1000;

/// The SHA-1 digest of the concatenation of `parts` (RFC 3174).
pub fn sha1(parts: &[&[u8]]) -> [u8; 20] {
    let mut hash = Sha1::new();
    for part in parts {
        for &byte in *part {
            hash.push(byte);
            hash.len = hash.len.wrapping_add(1);
        }
    }
    hash.finish()
}

/// SHA-1 over bytes pushed one at a time: the input is a handshake key, so the byte loop costs
/// nothing that matters and keeps the code small.
struct Sha1 {
    state: [u32; 5],
    block: [u8; 64],
    filled: usize,
    /// The bytes of the message, without the padding.
    len: u64,
}

impl Sha1 {
    fn new() -> Self {
        Self {
            state: [
                0x6745_2301,
                0xEFCD_AB89,
                0x98BA_DCFE,
                0x1032_5476,
                0xC3D2_E1F0,
            ],
            block: [0; 64],
            filled: 0,
            len: 0,
        }
    }

    fn push(&mut self, byte: u8) {
        // `filled` is below 64 between pushes: a full block is compressed and emptied at once.
        if let Some(slot) = self.block.get_mut(self.filled) {
            *slot = byte;
        }
        self.filled = self.filled.wrapping_add(1);
        if self.filled == 64 {
            sha1_compress(&mut self.state, &self.block);
            self.filled = 0;
        }
    }

    fn finish(mut self) -> [u8; 20] {
        let bits = self.len.wrapping_mul(8);
        self.push(0x80);
        while self.filled != 56 {
            self.push(0);
        }
        for byte in bits.to_be_bytes() {
            self.push(byte);
        }
        let mut digest = [0u8; 20];
        for (out, word) in digest.chunks_exact_mut(4).zip(self.state) {
            out.copy_from_slice(&word.to_be_bytes());
        }
        digest
    }
}

/// One block of SHA-1, the eighty rounds in one loop over a sixteen-word window of the schedule:
/// the window starts at the round's word and is slid by one each round, the schedule's next word
/// appended (RFC 3174 section 6.1), so every word is read at a fixed place.
fn sha1_compress(state: &mut [u32; 5], block: &[u8; 64]) {
    let mut w = [0u32; 16];
    for (word, bytes) in w.iter_mut().zip(block.chunks_exact(4)) {
        let mut be = [0u8; 4];
        be.copy_from_slice(bytes);
        *word = u32::from_be_bytes(be);
    }
    let [mut a, mut b, mut c, mut d, mut e] = *state;
    for t in 0..80usize {
        let word = w[0];
        let next = (w[13] ^ w[8] ^ w[2] ^ word).rotate_left(1);
        w.copy_within(1.., 0);
        w[15] = next;
        let (f, k) = match t / 20 {
            0 => ((b & c) | (!b & d), 0x5A82_7999),
            1 => (b ^ c ^ d, 0x6ED9_EBA1),
            2 => ((b & c) | (b & d) | (c & d), 0x8F1B_BCDC),
            _ => (b ^ c ^ d, 0xCA62_C1D6),
        };
        let next = a
            .rotate_left(5)
            .wrapping_add(f)
            .wrapping_add(e)
            .wrapping_add(k)
            .wrapping_add(word);
        e = d;
        d = c;
        c = b.rotate_left(30);
        b = a;
        a = next;
    }
    for (word, add) in state.iter_mut().zip([a, b, c, d, e]) {
        *word = word.wrapping_add(add);
    }
}

/// The base64 alphabet of RFC 4648 section 4.
const BASE64: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/// Write `input` in padded base64 into `out`: how many bytes were written, or `None` when `out`
/// is too short for them.
pub fn base64_encode(input: &[u8], out: &mut [u8]) -> Option<usize> {
    let mut written = 0usize;
    for chunk in input.chunks(3) {
        let word = chunk
            .iter()
            .zip([16u32, 8, 0])
            .fold(0u32, |word, (&byte, shift)| {
                word | (u32::from(byte) << shift)
            });
        let end = written.checked_add(4)?;
        let quad = out.get_mut(written..end)?;
        // A chunk of n bytes fills n + 1 sextets; the rest of the quad is padding.
        for (i, (slot, shift)) in quad.iter_mut().zip([18u32, 12, 6, 0]).enumerate() {
            *slot = match BASE64.get(((word >> shift) & 63) as usize) {
                Some(&sextet) if i <= chunk.len() => sextet,
                _ => b'=',
            };
        }
        written = end;
    }
    Some(written)
}

/// The `Sec-WebSocket-Accept` value a server answers the client key `key` with: the base64 of
/// the SHA-1 of the key and RFC 6455's GUID.
pub fn accept_value(key: &[u8]) -> [u8; ACCEPT_LEN] {
    let mut accept = [0u8; ACCEPT_LEN];
    let _ = base64_encode(&sha1(&[key, ACCEPT_GUID]), &mut accept);
    accept
}

/// A client's `Sec-WebSocket-Key`: sixteen bytes the client drew, in base64.
pub fn client_key(nonce: &[u8; 16]) -> [u8; KEY_LEN] {
    let mut key = [0u8; KEY_LEN];
    let _ = base64_encode(nonce, &mut key);
    key
}

/// Text written into a byte slice, which records whether it ran out of room.
struct SliceText<'a> {
    out: &'a mut [u8],
    len: usize,
    overflowed: bool,
}

impl fmt::Write for SliceText<'_> {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        let end = self.len.saturating_add(s.len());
        match self.out.get_mut(self.len..end) {
            Some(room) => {
                room.copy_from_slice(s.as_bytes());
                self.len = end;
                Ok(())
            }
            None => {
                self.overflowed = true;
                Err(fmt::Error)
            }
        }
    }
}

impl TextOut for SliceText<'_> {}

impl SliceText<'_> {
    fn push_bytes(&mut self, bytes: &[u8]) {
        // Only the base64 a caller hands over is written this way, and it is ASCII.
        let _ = fmt::Write::write_str(self, core::str::from_utf8(bytes).unwrap_or("\u{fffd}"));
    }

    fn written(self) -> Option<usize> {
        (!self.overflowed).then_some(self.len)
    }
}

/// Write the opening request a client sends to the server at `host`, with its key `key`, into
/// `out`: the request zenoh's WebSocket library writes for `ws://<host>` (path `/`, HTTP/1.1,
/// version 13). How many bytes it took, or `None` when `out` is too short.
pub fn write_request(out: &mut [u8], host: SocketAddr, key: &[u8; KEY_LEN]) -> Option<usize> {
    let mut text = SliceText {
        out,
        len: 0,
        overflowed: false,
    };
    text.push_str("GET / HTTP/1.1\r\nHost: ");
    text.push_socket_addr(host);
    text.push_str("\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Key: ");
    text.push_bytes(key);
    text.push_str("\r\n\r\n");
    text.written()
}

/// Write the answer a server gives a request it upgrades, with the accept value `accept`, into
/// `out`. How many bytes it took, or `None` when `out` is too short.
pub fn write_response(out: &mut [u8], accept: &[u8; ACCEPT_LEN]) -> Option<usize> {
    let mut text = SliceText {
        out,
        len: 0,
        overflowed: false,
    };
    text.push_str("HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Accept: ");
    text.push_bytes(accept);
    text.push_str("\r\n\r\n");
    text.written()
}

/// What the bytes read so far say of an opening handshake.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UpgradeRead {
    /// The head has not ended yet: read more.
    Partial,
    /// The head ended after `head_len` bytes and upgrades the connection; what follows them is
    /// the first frame's.
    Upgraded {
        /// The bytes of the head, its blank line included.
        head_len: usize,
    },
    /// The head ended and does not upgrade the connection as RFC 6455 asks.
    Refused,
}

/// What the bytes read so far say of a client's opening request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RequestRead {
    /// The head has not ended yet: read more.
    Partial,
    /// The head ended after `head_len` bytes and asks for an upgrade the server answers with
    /// `accept`.
    Upgrade {
        /// The bytes of the head, its blank line included.
        head_len: usize,
        /// The `Sec-WebSocket-Accept` value of the answer.
        accept: [u8; ACCEPT_LEN],
    },
    /// The head ended and is no upgrade request a server of RFC 6455 version 13 takes.
    Refused,
}

/// The bytes of an HTTP head at the front of `held`, its blank line included, if it has ended.
fn head_len(held: &[u8]) -> Option<usize> {
    held.windows(4)
        .position(|w| w == b"\r\n\r\n")
        .and_then(|at| at.checked_add(4))
}

/// The facts of a head's header fields that an upgrade turns on.
#[derive(Default)]
struct Fields<'a> {
    upgrade_websocket: bool,
    connection_upgrade: bool,
    version_13: bool,
    key: Option<&'a [u8]>,
    accept: Option<&'a [u8]>,
    /// An extension or a subprotocol was named, which this end offered none of.
    unasked: bool,
}

/// `bytes` without the spaces and tabs around it.
fn trim(mut bytes: &[u8]) -> &[u8] {
    while let [b' ' | b'\t', rest @ ..] = bytes {
        bytes = rest;
    }
    while let [rest @ .., b' ' | b'\t'] = bytes {
        bytes = rest;
    }
    bytes
}

/// Read the header fields of the lines after a head's first, up to its blank line.
fn fields(lines: &[u8]) -> Fields<'_> {
    let mut fields = Fields::default();
    for line in lines.split(|&b| b == b'\n') {
        let line = line.strip_suffix(b"\r").unwrap_or(line);
        let Some(colon) = line.iter().position(|&b| b == b':') else {
            continue;
        };
        let (name, value) = line.split_at(colon);
        let value = trim(value.get(1..).unwrap_or_default());
        if name.eq_ignore_ascii_case(b"upgrade") {
            fields.upgrade_websocket = value.eq_ignore_ascii_case(b"websocket");
        } else if name.eq_ignore_ascii_case(b"connection") {
            fields.connection_upgrade |= value
                .split(|&b| b == b',')
                .any(|token| trim(token).eq_ignore_ascii_case(b"upgrade"));
        } else if name.eq_ignore_ascii_case(b"sec-websocket-version") {
            fields.version_13 = value == b"13";
        } else if name.eq_ignore_ascii_case(b"sec-websocket-key") {
            fields.key = Some(value);
        } else if name.eq_ignore_ascii_case(b"sec-websocket-accept") {
            fields.accept = Some(value);
        } else if name.eq_ignore_ascii_case(b"sec-websocket-extensions")
            || name.eq_ignore_ascii_case(b"sec-websocket-protocol")
        {
            fields.unasked |= !value.is_empty();
        }
    }
    fields
}

/// Read the server's answer to the request a client sent with `key` (RFC 6455 section 4.1): a
/// `101` status, `Upgrade: websocket`, a `Connection` that names `upgrade`, and the accept
/// value of the key. An extension or a subprotocol the client did not offer fails it, as the
/// section asks.
pub fn read_response(held: &[u8], key: &[u8; KEY_LEN]) -> UpgradeRead {
    let Some(head_len) = head_len(held) else {
        return UpgradeRead::Partial;
    };
    let head = held.get(..head_len).unwrap_or_default();
    let status_end = head.iter().position(|&b| b == b'\n').unwrap_or(head.len());
    let (status, rest) = head.split_at(status_end);
    let status = status.strip_suffix(b"\r").unwrap_or(status);
    let switching = status
        .strip_prefix(b"HTTP/1.1 101")
        .is_some_and(|after| after.is_empty() || after.first() == Some(&b' '));
    let fields = fields(rest);
    let upgraded = switching
        && fields.upgrade_websocket
        && fields.connection_upgrade
        && !fields.unasked
        && fields.accept == Some(accept_value(key).as_slice());
    if upgraded {
        UpgradeRead::Upgraded { head_len }
    } else {
        UpgradeRead::Refused
    }
}

/// Read a client's opening request (RFC 6455 section 4.2.1): `GET` over HTTP/1.1,
/// `Upgrade: websocket`, a `Connection` that names `upgrade`, version 13 and a key of sixteen
/// bytes in base64. The path is not read: zenoh's listener takes any.
pub fn read_request(held: &[u8]) -> RequestRead {
    let Some(head_len) = head_len(held) else {
        return RequestRead::Partial;
    };
    let head = held.get(..head_len).unwrap_or_default();
    let line_end = head.iter().position(|&b| b == b'\n').unwrap_or(head.len());
    let (line, rest) = head.split_at(line_end);
    let line = line.strip_suffix(b"\r").unwrap_or(line);
    let get = line.starts_with(b"GET ") && line.ends_with(b" HTTP/1.1");
    let fields = fields(rest);
    let key = fields
        .key
        .filter(|key| key.len() == KEY_LEN && key.ends_with(b"=="));
    match key {
        Some(key)
            if get
                && fields.upgrade_websocket
                && fields.connection_upgrade
                && fields.version_13 =>
        {
            RequestRead::Upgrade {
                head_len,
                accept: accept_value(key),
            }
        }
        _ => RequestRead::Refused,
    }
}

/// The header of one frame, as read off the wire.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FrameHead {
    /// Whether the frame ends its message.
    pub fin: bool,
    /// What the frame is ([`OP_BINARY`], [`OP_PING`], ...).
    pub opcode: u8,
    /// The key the payload is masked with, when it is.
    pub mask: Option<[u8; 4]>,
    /// The bytes of the header.
    pub head_len: usize,
    /// The bytes of the payload behind it.
    pub payload_len: u64,
}

/// What the bytes read so far say of the frame at their front.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HeadRead {
    /// The header has not all arrived.
    Partial,
    /// The header, whole.
    Frame(FrameHead),
    /// No frame RFC 6455 allows without an extension: a reserved bit or opcode, a control frame
    /// that is fragmented or longer than 125 bytes, a length with its top bit set.
    Refused,
}

/// Read the frame header at the front of `held` (RFC 6455 section 5.2).
pub fn read_head(held: &[u8]) -> HeadRead {
    let (Some(&first), Some(&second)) = (held.first(), held.get(1)) else {
        return HeadRead::Partial;
    };
    let fin = first & 0x80 != 0;
    let opcode = first & 0x0F;
    let control = opcode & 0x08 != 0;
    let known = matches!(
        opcode,
        OP_CONTINUATION | OP_TEXT | OP_BINARY | OP_CLOSE | OP_PING | OP_PONG
    );
    let short = u64::from(second & 0x7F);
    if first & 0x70 != 0 || !known || (control && (!fin || short > 125)) {
        return HeadRead::Refused;
    }
    // Where the length ends, and where a mask key after it ends.
    let (len_end, masked_end) = match short {
        126 => (4, 8),
        127 => (10, 14),
        _ => (2, 6),
    };
    let Some(extended) = held.get(2..len_end) else {
        return HeadRead::Partial;
    };
    let payload_len = if extended.is_empty() {
        short
    } else {
        extended
            .iter()
            .fold(0u64, |len, &byte| (len << 8) | u64::from(byte))
    };
    if payload_len >> 63 != 0 {
        return HeadRead::Refused;
    }
    let (mask, head_len) = if second & 0x80 != 0 {
        let Some(key) = held
            .get(len_end..masked_end)
            .and_then(|key| <[u8; 4]>::try_from(key).ok())
        else {
            return HeadRead::Partial;
        };
        (Some(key), masked_end)
    } else {
        (None, len_end)
    };
    HeadRead::Frame(FrameHead {
        fin,
        opcode,
        mask,
        head_len,
        payload_len,
    })
}

/// Write the header of a whole (`FIN`) frame of `opcode` carrying `payload_len` bytes, masked
/// with `mask` when one is given, at the front of `out`: how many bytes it took. The length takes
/// the shortest of its three forms, as RFC 6455 section 5.2 asks.
pub fn write_head(
    out: &mut [u8; MAX_HEAD_LEN],
    opcode: u8,
    payload_len: usize,
    mask: Option<[u8; 4]>,
) -> usize {
    let masked = u8::from(mask.is_some()) << 7;
    out[0] = 0x80 | (opcode & 0x0F);
    let len = payload_len as u64;
    // Where the length ends, and where a mask key after it ends.
    let (len_end, masked_end) = match len {
        0..=125 => {
            out[1] = masked | len as u8;
            (2, 6)
        }
        126..=0xFFFF => {
            out[1] = masked | 126;
            out[2..4].copy_from_slice(&(len as u16).to_be_bytes());
            (4, 8)
        }
        _ => {
            out[1] = masked | 127;
            out[2..10].copy_from_slice(&len.to_be_bytes());
            (10, 14)
        }
    };
    match (mask, out.get_mut(len_end..masked_end)) {
        (Some(key), Some(room)) => {
            room.copy_from_slice(&key);
            masked_end
        }
        _ => len_end,
    }
}

/// Mask or unmask `payload` in place with `key` (RFC 6455 section 5.3): the same operation.
pub fn apply_mask(payload: &mut [u8], key: [u8; 4]) {
    for (byte, key_byte) in payload.iter_mut().zip(key.iter().cycle()) {
        *byte ^= key_byte;
    }
}

/// The source of a client's mask keys: ChaCha20 (RFC 8439 section 2.3) keyed once from the
/// platform's entropy, sixteen keys out of each block. RFC 6455 section 5.3 asks that a key be
/// one an observer of the earlier ones cannot foretell, which a counter or a linear generator is
/// not and a stream cipher's output is.
pub struct MaskKeys {
    key: [u32; 8],
    nonce: [u32; 2],
    counter: u64,
    block: [u8; 64],
    /// How many bytes of `block` were handed out.
    used: usize,
}

/// The bytes of entropy [`MaskKeys::seeded`] takes: a key and a nonce.
pub const MASK_SEED_LEN: usize = 40;

impl MaskKeys {
    /// The generator keyed by `seed`, its first 32 bytes the key and the rest the nonce.
    pub fn seeded(seed: &[u8; MASK_SEED_LEN]) -> Self {
        let mut words = [0u32; MASK_SEED_LEN / 4];
        for (word, bytes) in words.iter_mut().zip(seed.chunks_exact(4)) {
            let mut le = [0u8; 4];
            le.copy_from_slice(bytes);
            *word = u32::from_le_bytes(le);
        }
        let mut key = [0u32; 8];
        key.copy_from_slice(&words[..8]);
        Self {
            key,
            nonce: [words[8], words[9]],
            counter: 0,
            block: [0; 64],
            used: 64,
        }
    }

    /// The next mask key.
    pub fn next_key(&mut self) -> [u8; 4] {
        if let Some(&key) = self
            .block
            .get(self.used..)
            .and_then(|rest| rest.first_chunk::<4>())
        {
            // At most 64: a block's keys are handed out four bytes at a time.
            self.used = self.used.saturating_add(4);
            return key;
        }
        self.block = chacha20_block(
            &self.key,
            [
                self.counter as u32,
                (self.counter >> 32) as u32,
                self.nonce[0],
                self.nonce[1],
            ],
        );
        self.counter = self.counter.wrapping_add(1);
        self.used = 4;
        let [a, b, c, d, ..] = self.block;
        [a, b, c, d]
    }
}

/// One ChaCha20 block (RFC 8439 section 2.3) of `key` and the last four words of the state:
/// the block counter and the nonce, in the order of the state.
fn chacha20_block(key: &[u32; 8], tail: [u32; 4]) -> [u8; 64] {
    let mut input = [0u32; 16];
    input[..4].copy_from_slice(&[0x6170_7865, 0x3320_646E, 0x7962_2D32, 0x6B20_6574]);
    input[4..12].copy_from_slice(key);
    input[12..].copy_from_slice(&tail);
    let mut x = input;
    for _ in 0..10 {
        let [x0, x1, x2, x3, x4, x5, x6, x7, x8, x9, x10, x11, x12, x13, x14, x15] = &mut x;
        quarter_round(x0, x4, x8, x12);
        quarter_round(x1, x5, x9, x13);
        quarter_round(x2, x6, x10, x14);
        quarter_round(x3, x7, x11, x15);
        quarter_round(x0, x5, x10, x15);
        quarter_round(x1, x6, x11, x12);
        quarter_round(x2, x7, x8, x13);
        quarter_round(x3, x4, x9, x14);
    }
    let mut out = [0u8; 64];
    for ((bytes, word), start) in out.chunks_exact_mut(4).zip(x).zip(input) {
        bytes.copy_from_slice(&word.wrapping_add(start).to_le_bytes());
    }
    out
}

/// The ChaCha quarter round on four words of the state.
fn quarter_round(a: &mut u32, b: &mut u32, c: &mut u32, d: &mut u32) {
    *a = a.wrapping_add(*b);
    *d = (*d ^ *a).rotate_left(16);
    *c = c.wrapping_add(*d);
    *b = (*b ^ *c).rotate_left(12);
    *a = a.wrapping_add(*b);
    *d = (*d ^ *a).rotate_left(8);
    *c = c.wrapping_add(*d);
    *b = (*b ^ *c).rotate_left(7);
}

#[cfg(test)]
mod tests;
