// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The session's link over a WebSocket: the stream link
//! ([`StreamDriver`](crate::stream_link::StreamDriver)) over a TCP connection,
//! each batch one BINARY message of RFC 6455 as zenoh's WebSocket link writes it
//! (`io/zenoh-links/zenoh-link-ws/src/unicast.rs` @ `let msg = buffer.into();`), its frames read
//! and written by `WsFraming` with the session core's pieces (`wz_session_core::ws_link`).
//!
//! A message is read whole into the link's receive buffer: the frames of a fragmented one are
//! joined where they lie, and a masked one is unmasked there, so a batch is lent from the buffer
//! as a TCP link lends one. A Ping is answered with a Pong, as RFC 6455 section 5.5.2 asks; zenoh's
//! link ends instead (@ `Message::Ping(_) => bail!(`), which `docs/upstream-parity.md` records. A
//! Text message ends the link as it ends zenoh's (@ `Message::Text(_) => bail!(`), and so does a
//! Close, after the link answers it with its own.

use core::cell::{Cell, RefCell};

use wz_session_core::entropy::EntropyUnavailable;
use wz_session_core::link::{LinkEnds, LinkKind};
use wz_session_core::ws_link::{
    apply_mask, read_head, write_head, HeadRead, MaskKeys, CLOSE_NORMAL, MAX_CONTROL_PAYLOAD,
    MAX_HEAD_LEN, OP_BINARY, OP_CLOSE, OP_CONTINUATION, OP_PING, OP_PONG,
};

use crate::stream_link::{Front, StreamEnds, StreamFraming, StreamSocket};

/// What a stack's `ws/` links draw on besides their connections, on either profile: the clock an
/// opening handshake is timed on and the entropy of a client's key and mask keys. A value the
/// stack holds.
pub trait WsSource {
    /// The platform's monotonic clock, in microseconds: what a handshake is timed on.
    fn now_us(&self) -> u64;

    /// Fill `out` with entropy: a client's key and the seed of its mask keys.
    fn fill_entropy(&self, out: &mut [u8]) -> Result<(), EntropyUnavailable>;
}

/// The largest batch a message carries: zenoh's WebSocket MTU
/// (`io/zenoh-links/zenoh-link-ws/src/lib.rs` @ `const WS_MAX_MTU: BatchSize = BatchSize::MAX;`).
const WS_MTU: usize = u16::MAX as usize;

/// The room in front of a batch: a header with a 16-bit length and a mask key.
const WS_HEADROOM: usize = 8;

/// A frame the framing writes of its own, a Pong or a Close: a header and at most a control
/// frame's payload.
struct Control {
    bytes: [u8; MAX_HEAD_LEN + MAX_CONTROL_PAYLOAD],
    /// The bytes of the frame.
    len: usize,
    /// How many of them the stream took.
    from: usize,
}

/// The header a frame of a batch is written behind.
pub struct WsPrefix {
    bytes: [u8; MAX_HEAD_LEN],
    len: usize,
}

impl AsRef<[u8]> for WsPrefix {
    fn as_ref(&self) -> &[u8] {
        self.bytes.get(..self.len).unwrap_or_default()
    }
}

/// RFC 6455's framing of a stream, for one end of one link. A client masks every frame it writes
/// with a key from its [`MaskKeys`] and takes only unmasked frames; a server the other way round
/// (RFC 6455 section 5.1), and a frame masked the wrong way ends the link.
pub struct WsFraming {
    /// The client's mask keys; `None` on a server.
    keys: Option<RefCell<MaskKeys>>,
    /// The batch the last receive lent, which the link kept to lend again: its bytes were
    /// unmasked and joined already, so it is answered as it was.
    kept: Cell<Option<Front>>,
    /// A Pong or a Close the link owes the peer.
    control: RefCell<Control>,
}

impl WsFraming {
    fn with_keys(keys: Option<MaskKeys>) -> Self {
        Self {
            keys: keys.map(RefCell::new),
            kept: Cell::new(None),
            control: RefCell::new(Control {
                bytes: [0; MAX_HEAD_LEN + MAX_CONTROL_PAYLOAD],
                len: 0,
                from: 0,
            }),
        }
    }

    /// The framing of the end that opened the connection, masking with keys from `keys`.
    pub fn client(keys: MaskKeys) -> Self {
        Self::with_keys(Some(keys))
    }

    /// The framing of the end that accepted the connection.
    pub fn server() -> Self {
        Self::with_keys(None)
    }

    /// The key the next frame this end writes is masked with: a client's next key, none on a
    /// server.
    fn next_mask(&self) -> Option<[u8; 4]> {
        self.keys.as_ref().map(|keys| keys.borrow_mut().next_key())
    }

    /// Owe the peer a control frame of `opcode` carrying `payload`, in place of one not yet begun
    /// on the stream: RFC 6455 section 5.5.3 lets an end answer only the latest of several Pings.
    /// One the stream has taken part of is finished first, and this one is not owed.
    fn answer(&self, opcode: u8, payload: &[u8]) {
        let mut control = self.control.borrow_mut();
        if control.from > 0 && control.from < control.len {
            return;
        }
        let payload = payload.get(..MAX_CONTROL_PAYLOAD).unwrap_or(payload);
        let mask = self.next_mask();
        let mut head = [0u8; MAX_HEAD_LEN];
        let head_len = write_head(&mut head, opcode, payload.len(), mask);
        let end = head_len + payload.len();
        let Control { bytes, len, from } = &mut *control;
        if let (Some(to), Some(written)) = (bytes.get_mut(..head_len), head.get(..head_len)) {
            to.copy_from_slice(written);
        }
        if let Some(body) = bytes.get_mut(head_len..end) {
            body.copy_from_slice(payload);
            if let Some(key) = mask {
                apply_mask(body, key);
            }
        }
        *len = end;
        *from = 0;
    }

    /// Answer the control frame of `opcode` the peer sent with `payload`: a Ping with a Pong of
    /// the same payload, a Close with a Close of the status it named (RFC 6455 section 5.5.1).
    /// `true` when it was a Close.
    fn on_control(&self, opcode: u8, payload: &[u8]) -> bool {
        match opcode {
            OP_PING => {
                self.answer(OP_PONG, payload);
                false
            }
            OP_CLOSE => {
                self.answer(OP_CLOSE, payload.get(..2).unwrap_or_default());
                true
            }
            _ => false,
        }
    }

    /// Unmask the frames `..end` of `held` that make one message and join their payloads behind
    /// its first header, answering a control frame that came between them: the batch, or
    /// [`Front::Closed`] when a Close was among them.
    fn join(&self, held: &mut [u8], end: usize) -> Front {
        let mut read = 0usize;
        let mut first_head = None;
        let mut write = 0usize;
        while read < end {
            let HeadRead::Frame(head) = read_head(held.get(read..end).unwrap_or_default()) else {
                return Front::Closed;
            };
            let start = read + head.head_len;
            let stop = start + head.payload_len as usize;
            if let (Some(key), Some(payload)) = (head.mask, held.get_mut(start..stop)) {
                apply_mask(payload, key);
            }
            if head.opcode & 0x08 != 0 {
                if self.on_control(head.opcode, held.get(start..stop).unwrap_or_default()) {
                    return Front::Closed;
                }
            } else {
                let at = *first_head.get_or_insert(start);
                write = write.max(at);
                held.copy_within(start..stop, write);
                write += stop - start;
            }
            read = stop;
        }
        let at = first_head.unwrap_or(end);
        Front::Batch {
            at,
            len: write.saturating_sub(at),
            used: end,
        }
    }
}

/// What a receive that found no whole message makes of it: more to read, unless the buffer is
/// full already, when the message can never fit.
fn partial(held: &[u8], capacity: usize) -> Front {
    if held.len() >= capacity {
        Front::TooLong
    } else {
        Front::Partial
    }
}

impl StreamFraming for WsFraming {
    const HEADROOM: usize = WS_HEADROOM;
    const LENGTH_PREFIXED: bool = false;
    type Prefix = WsPrefix;

    fn front(&self, held: &mut [u8], capacity: usize, consume: bool) -> Front {
        if let Some(kept) = self.kept.get() {
            return kept;
        }
        // Read the frames of the message at the front, and of a control frame alone, without
        // changing a byte: until all of them are in, nothing is unmasked.
        let mut at = 0usize;
        let mut started = false;
        let mut payload = 0usize;
        let mut first_head = 0usize;
        loop {
            let head = match read_head(held.get(at..).unwrap_or_default()) {
                HeadRead::Partial => return partial(held, capacity),
                HeadRead::Refused => return Front::Closed,
                HeadRead::Frame(head) => head,
            };
            if head.mask.is_some() == self.keys.is_some() {
                return Front::Closed;
            }
            let Ok(len) = usize::try_from(head.payload_len) else {
                return Front::TooLong;
            };
            let end = at.saturating_add(head.head_len).saturating_add(len);
            if end > capacity {
                return Front::TooLong;
            }
            if end > held.len() {
                return partial(held, capacity);
            }
            match (head.opcode, started) {
                (OP_PING | OP_PONG | OP_CLOSE, false) => {
                    if !consume {
                        return if head.opcode == OP_CLOSE {
                            Front::Closed
                        } else {
                            Front::Skip(end)
                        };
                    }
                    let body = held.get_mut(at + head.head_len..end).unwrap_or_default();
                    if let Some(key) = head.mask {
                        apply_mask(body, key);
                    }
                    return if self.on_control(head.opcode, body) {
                        Front::Closed
                    } else {
                        Front::Skip(end)
                    };
                }
                (OP_PING | OP_PONG | OP_CLOSE, true) => {}
                (OP_BINARY, false) => {
                    started = true;
                    first_head = head.head_len;
                    payload = len;
                    if head.fin {
                        at = end;
                        break;
                    }
                }
                (OP_CONTINUATION, true) => {
                    payload = payload.saturating_add(len);
                    if head.fin {
                        at = end;
                        break;
                    }
                }
                // A Text message ends the link, as it ends zenoh's; a continuation with no
                // message begun, or a message begun inside another, is no stream RFC 6455 allows.
                _ => return Front::Closed,
            }
            at = end;
        }
        if !consume {
            return Front::Batch {
                at: first_head,
                len: payload,
                used: at,
            };
        }
        let front = self.join(held, at);
        if matches!(front, Front::Batch { .. }) {
            self.kept.set(Some(front));
        }
        front
    }

    fn passed(&self) {
        self.kept.set(None);
    }

    fn prefix(&self, len: usize) -> Option<(WsPrefix, Option<[u8; 4]>)> {
        if len > WS_MTU {
            return None;
        }
        let mask = self.next_mask();
        let mut bytes = [0u8; MAX_HEAD_LEN];
        let len = write_head(&mut bytes, OP_BINARY, len, mask);
        Some((WsPrefix { bytes, len }, mask))
    }

    // A WebSocket's ends are those of the TCP connection it runs over, under its own scheme.
    fn link_ends(ends: StreamEnds<'_>) -> LinkEnds<'_> {
        match ends.ip() {
            Some((local, peer)) => LinkEnds::ip(LinkKind::Ws, local, peer),
            None => ends.link_ends(),
        }
    }

    #[cfg(feature = "alloc")]
    fn subject(_ends: StreamEnds<'_>) -> &'static wz_session_core::link::LinkSubject {
        use wz_session_core::link::LinkSubject;
        static WS: LinkSubject = LinkSubject {
            kind: Some(LinkKind::Ws),
            ..LinkSubject::UNKNOWN
        };
        &WS
    }

    fn mtu(slot_len: usize) -> usize {
        slot_len.saturating_sub(WS_HEADROOM).min(WS_MTU)
    }

    fn rx_capacity(rx_len: usize) -> usize {
        rx_len.saturating_sub(MAX_HEAD_LEN)
    }

    fn owes_control(&self) -> bool {
        let control = self.control.borrow();
        control.from < control.len
    }

    fn write_control<S: StreamSocket>(&self, socket: &S) -> Result<bool, S::Error> {
        let mut control = self.control.borrow_mut();
        while control.from < control.len {
            let rest = control
                .bytes
                .get(control.from..control.len)
                .unwrap_or_default();
            let taken = socket.write(rest)?;
            if taken == 0 {
                return Ok(false);
            }
            control.from = control.from.saturating_add(taken);
        }
        control.len = 0;
        control.from = 0;
        Ok(true)
    }

    // zenoh's link closes the WebSocket with a Close frame before the connection ends
    // (`io/zenoh-links/zenoh-link-ws/src/unicast.rs` @ `guard.close().await`).
    fn closing(&self) {
        self.answer(OP_CLOSE, &CLOSE_NORMAL.to_be_bytes());
    }
}

// Every build with this module has one profile or the other (`runtime` asks for one), and each
// profile's links open with these steps.
mod handshake;

#[cfg(all(feature = "alloc", not(feature = "session-slot")))]
mod links;
#[cfg(all(feature = "alloc", not(feature = "session-slot")))]
pub use links::{WsDial, WsLinks, WsLinksDial, WsOpen, WS_RX_CAPACITY};

#[cfg(feature = "session-slot")]
mod slot;
#[cfg(feature = "session-slot")]
pub use slot::{WsAcceptor, WsStack};

#[cfg(all(test, not(feature = "session-slot")))]
mod tests;
