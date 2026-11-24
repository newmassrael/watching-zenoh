// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

extern crate std;

use core::ffi::c_int;
use core::net::SocketAddr;
use std::collections::VecDeque;
use std::rc::Rc;
use std::vec::Vec;

use wz_session_core::link::{BoxedLinkDriver, LinkEndsText, LostCause};
use wz_session_core::reliability::Reliability;
use wz_session_core::ws_link::MASK_SEED_LEN;

use super::*;
use crate::link_storage::{HeapTx, RxStore, TxStore};
use crate::session_drive::SessionDatagramLink;
use crate::stream_link::StreamDriver;

/// What the peer sent, in the pieces the stream cuts it into, and what the link wrote.
#[derive(Default)]
struct Wire {
    pieces: RefCell<VecDeque<Vec<u8>>>,
    writes: RefCell<Vec<Vec<u8>>>,
}

impl Wire {
    fn written(&self) -> Vec<u8> {
        self.writes.borrow().concat()
    }
}

struct Pipe(Rc<Wire>);

impl StreamSocket for Pipe {
    type Error = core::convert::Infallible;

    type Link<B: RxStore + 'static, X: TxStore + 'static>
        = StreamDriver<Self, B, X>
    where
        Self: 'static;

    fn local(&self) -> SocketAddr {
        SocketAddr::from(([10, 0, 0, 2], 40_000))
    }

    fn peer(&self) -> SocketAddr {
        SocketAddr::from(([10, 0, 0, 1], 7447))
    }

    fn write(&self, bytes: &[u8]) -> Result<usize, Self::Error> {
        self.0.writes.borrow_mut().push(bytes.to_vec());
        Ok(bytes.len())
    }

    fn wait_readable(&self, _timeout_ms: c_int) {}

    fn try_read(&self, buf: &mut [u8]) -> Result<Option<usize>, Self::Error> {
        let mut pieces = self.0.pieces.borrow_mut();
        let Some(piece) = pieces.front_mut() else {
            return Ok(None);
        };
        let n = piece.len().min(buf.len());
        buf[..n].copy_from_slice(&piece[..n]);
        piece.drain(..n);
        if piece.is_empty() {
            pieces.pop_front();
        }
        Ok(Some(n))
    }

    fn shutdown(&self) {}
}

type Link = StreamDriver<Pipe, Vec<u8>, HeapTx, WsFraming>;

fn open(framing: WsFraming) -> (Link, Rc<Wire>) {
    let wire = Rc::new(Wire::default());
    let link = StreamDriver::framed(
        Pipe(wire.clone()),
        std::vec![0u8; 512],
        0,
        HeapTx::for_link(0, 300, 0),
        framing,
    );
    (link, wire)
}

/// A frame of `opcode` with `payload` (shorter than 126 bytes), masked with `key` when given,
/// as a peer writes one.
fn frame(fin: bool, opcode: u8, payload: &[u8], key: Option<[u8; 4]>) -> Vec<u8> {
    let mut out = std::vec![(u8::from(fin) << 7) | opcode];
    let len = u8::try_from(payload.len()).expect("a short payload");
    match key {
        Some(key) => {
            out.push(0x80 | len);
            out.extend_from_slice(&key);
            let mut body = payload.to_vec();
            apply_mask(&mut body, key);
            out.extend_from_slice(&body);
        }
        None => {
            out.push(len);
            out.extend_from_slice(payload);
        }
    }
    out
}

fn received(link: &Link) -> Option<Vec<u8>> {
    let mut got = None;
    link.recv_with(&mut |bytes| got = Some(bytes.to_vec()));
    got
}

const KEY: [u8; 4] = [0x37, 0xfa, 0x21, 0x3d];

/// A server lends the batch a client's masked BINARY message carries, unmasked, even when the
/// stream cuts the message anywhere, and writes nothing back. Turned red by a mask not taken off,
/// or a header read as part of the batch.
#[test]
fn a_server_lends_the_batch_of_a_masked_message() {
    let (link, wire) = open(WsFraming::server());
    let message = frame(true, OP_BINARY, b"batch", Some(KEY));
    let (head, tail) = message.split_at(3);
    wire.pieces.borrow_mut().push_back(head.to_vec());
    assert_eq!(received(&link), None, "half a header");
    wire.pieces.borrow_mut().push_back(tail.to_vec());
    assert_eq!(received(&link).as_deref(), Some(&b"batch"[..]));
    assert_eq!(received(&link), None);
    assert!(wire.written().is_empty());
    assert_eq!(link.lost(), None);
}

/// The frames of a fragmented message are joined into one batch where they lie, a Ping between
/// them answered with a Pong of its payload, which the link writes as soon as it writes again.
/// Turned red by a join that leaves a header inside the batch, or a Ping left unanswered.
#[test]
fn a_fragmented_message_is_one_batch_and_a_ping_is_answered() {
    let (link, wire) = open(WsFraming::server());
    let mut bytes = frame(false, OP_BINARY, b"ab", Some(KEY));
    bytes.extend(frame(true, OP_PING, b"hi", Some([9, 8, 7, 6])));
    bytes.extend(frame(false, OP_CONTINUATION, b"cd", Some([1, 2, 3, 4])));
    bytes.extend(frame(true, OP_CONTINUATION, b"e", Some(KEY)));
    wire.pieces.borrow_mut().push_back(bytes);
    assert_eq!(received(&link).as_deref(), Some(&b"abcde"[..]));
    assert!(link.owes_write(), "the Pong is owed");
    link.service();
    assert_eq!(wire.written(), [0x8A, 0x02, b'h', b'i']);
    assert!(!link.owes_write());
}

/// A batch the session keeps is lent again as it was: its bytes were unmasked once, and the second
/// receive does not unmask them again. Turned red by a framing that reads a kept batch afresh.
#[test]
fn a_kept_batch_is_lent_again_unchanged() {
    let (link, wire) = open(WsFraming::server());
    let mut bytes = frame(true, OP_BINARY, b"kept", Some(KEY));
    bytes.extend(frame(true, OP_BINARY, b"next", Some(KEY)));
    wire.pieces.borrow_mut().push_back(bytes);
    let mut first = Vec::new();
    link.recv_with(&mut |bytes| {
        first = bytes.to_vec();
        link.keep();
    });
    assert_eq!(first, b"kept");
    assert!(link.holds_input());
    assert_eq!(received(&link).as_deref(), Some(&b"kept"[..]));
    assert_eq!(received(&link).as_deref(), Some(&b"next"[..]));
}

/// A client masks every frame it writes with the next key of its ChaCha20 stream, the first
/// key the keystream's first four bytes (RFC 8439 appendix A.1, an all-zero key), and a server
/// writes its frames unmasked, a batch of 126 bytes or more behind a 16-bit length. Turned red by
/// a frame sent unmasked from a client, or two frames masked with one key.
#[test]
fn a_client_masks_each_frame_with_a_fresh_key_and_a_server_does_not() {
    let (client, wire) = open(WsFraming::client(MaskKeys::seeded(&[0; MASK_SEED_LEN])));
    assert_eq!(
        client.send_blocking(&[1, 2, 3], Reliability::Reliable),
        wz_session_core::link::LinkSendOutcome::Sent
    );
    let first = [0x76, 0xb8, 0xe0, 0xad];
    let mut masked = std::vec![1u8, 2, 3];
    apply_mask(&mut masked, first);
    let mut expected = std::vec![0x82, 0x83];
    expected.extend_from_slice(&first);
    expected.extend_from_slice(&masked);
    assert_eq!(wire.written(), expected);
    wire.writes.borrow_mut().clear();
    client.send_blocking(&[1, 2, 3], Reliability::Reliable);
    let second = wire.written();
    assert_eq!(second.get(..2), Some(&[0x82, 0x83][..]));
    assert_ne!(second.get(2..6), Some(&first[..]), "a fresh key");

    let (server, wire) = open(WsFraming::server());
    let batch = [7u8; 200];
    server.send_blocking(&batch, Reliability::Reliable);
    let written = wire.written();
    assert_eq!(written.get(..4), Some(&[0x82, 126, 0, 200][..]));
    assert_eq!(written.get(4..), Some(&batch[..]));
}

/// What the link reports of itself: a WebSocket's ends, no length in the batch, a batch bounded
/// by the slot less the header room and by zenoh's WebSocket MTU. Turned red by a link that
/// names itself `tcp/` or asks the session for a length.
#[test]
fn the_link_names_itself_a_websocket_and_frames_no_length() {
    let (link, _wire) = open(WsFraming::server());
    assert!(!link.batch_length_prefixed());
    assert_eq!(link.link_mtu(), 300 - 8);
    assert_eq!(link.link_rx_capacity(), 512 - MAX_HEAD_LEN);
    let ends = link.link_endpoints().expect("both ends");
    assert_eq!(ends.dst.as_str(), "ws/10.0.0.1:7447");
    assert_eq!(ends.src.as_str(), "ws/10.0.0.2:40000");
    assert_eq!(WsFraming::mtu(100_000), WS_MTU);
}

/// The link ends on what zenoh's link ends on, and on what RFC 6455 tells an end to fail: a Close
/// (answered with a Close of the status it named first), a Text message, a frame masked the wrong
/// way for its end, a reserved opcode. Turned red by a link that reads on past any of them.
#[test]
fn the_link_ends_on_a_close_a_text_message_or_a_frame_masked_the_wrong_way() {
    let (link, wire) = open(WsFraming::server());
    wire.pieces
        .borrow_mut()
        .push_back(frame(true, OP_CLOSE, &[0x03, 0xE9], Some(KEY)));
    assert_eq!(received(&link), None);
    assert_eq!(link.lost(), Some(LostCause::PeerClosed));
    assert_eq!(wire.written(), [0x88, 0x02, 0x03, 0xE9]);

    for bytes in [
        frame(true, wz_session_core::ws_link::OP_TEXT, b"x", Some(KEY)),
        frame(true, OP_BINARY, b"unmasked", None),
        frame(true, 0x3, b"", Some(KEY)),
    ] {
        let (link, wire) = open(WsFraming::server());
        wire.pieces.borrow_mut().push_back(bytes);
        assert_eq!(received(&link), None);
        assert_eq!(link.lost(), Some(LostCause::PeerClosed));
    }

    let (client, wire) = open(WsFraming::client(MaskKeys::seeded(&[0; MASK_SEED_LEN])));
    wire.pieces
        .borrow_mut()
        .push_back(frame(true, OP_BINARY, b"masked", Some(KEY)));
    assert_eq!(received(&client), None);
    assert_eq!(client.lost(), Some(LostCause::PeerClosed));
}

/// A link that closes writes a Close of status 1000 behind what it owed, as zenoh's link closes
/// its WebSocket. Turned red by a close that ends the connection with no Close frame.
#[test]
fn a_closing_link_writes_a_close_frame() {
    let (link, wire) = open(WsFraming::server());
    link.close_blocking();
    assert_eq!(wire.written(), [0x88, 0x02, 0x03, 0xE8]);
}
