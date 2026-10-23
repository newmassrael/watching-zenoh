// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! R311ob — WebSocket-over-TCP session-open transport pipeline.
//!
//! The DATAGRAM-flow sibling of [`crate::udp_pipeline`], not of TCP/TLS. A
//! WebSocket link rides a TCP connection, but zenoh-pico classes it as
//! `Z_LINK_CAP_FLOW_DATAGRAM` (`src/link/unicast/ws.c`,
//! `_z_new_link_ws`): the transport adds NO length prefix
//! (`__unsafe_z_prepare_wbuf` reserves the 2-byte prefix only for
//! `FLOW_STREAM`, `src/transport/common/tx.c:347`), because each zenoh batch
//! rides ONE WebSocket BINARY message whose frame boundary delimits it —
//! exactly the UDP model. So this module reuses NEITHER [`crate::stream_link`]
//! (StreamEnvelope framing) NOR a custom byte codec (contrast serial's COBS);
//! the WebSocket protocol layer ([`tokio_tungstenite`], RFC6455) provides the
//! message framing, and the drivers mirror [`crate::udp_pipeline`]'s
//! one-message-is-one-frame shape.
//!
//! ## Pieces
//!
//! (Every link below is a full path: this inner doc also sits beside the outer
//! doc `lib.rs` puts on the module, so a short name resolves at the crate root
//! and finds nothing.)
//!
//! - [`dial_ws`](crate::ws_pipeline::dial_ws) — TCP-connect to the locator's
//!   addr, then run the WebSocket client handshake
//!   ([`tokio_tungstenite::client_async`]) to a connected
//!   [`WsLink`](crate::ws_pipeline::WsLink). Unlike TLS, no cert config is
//!   needed, so a `ws/...` locator dials directly through `dial_locator` (like
//!   `udp`).
//! - [`accept_ws`](crate::ws_pipeline::accept_ws) — the server handshake
//!   ([`tokio_tungstenite::accept_async`]) over an already-accepted
//!   [`TcpStream`].
//! - [`wire_ws_stream`](crate::ws_pipeline::wire_ws_stream) — splits the TCP
//!   connection under the handshaked link into its read half, which tungstenite
//!   keeps reading, and its write half, which the
//!   [`ws_writer_task`](crate::ws_pipeline::ws_writer_task) owns.
//! - [`WsReadDriver`](crate::ws_pipeline::WsReadDriver) — reads one
//!   `Message::Binary` as one [`RxFrame`]
//!   (control / text frames are skipped). The MTU is the unbounded stream
//!   default (pico's `_z_get_link_mtu_ws` = 65535), so the write driver
//!   overrides nothing.
//! - [`WsWriteDriver`](crate::ws_pipeline::WsWriteDriver) — FRAMES each
//!   outbound message itself (R3264): the
//!   RFC 6455 header in front of the payload and, on a client, the payload
//!   masked, in the buffer the message already lies in (under
//!   `runtime-zero-copy`, a slot of the link's transmit pool). tungstenite
//!   formats every message it sends into a write buffer of its own
//!   (`Frame::format_into_buf` copies the payload in), which is an intermediate
//!   copy ARCHITECTURE section 9.1 rules out; so the data messages do not go
//!   through it, and its header encoder (`FrameHeader::format`) is used for
//!   the bytes.
//! - [`ws_writer_task`](crate::ws_pipeline::ws_writer_task) — writes each
//!   queued frame as it lies, and the control frames tungstenite answers with
//!   (a Pong, a Close reply), which reach it through the same queue's control
//!   lane.

use std::io;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use futures_util::StreamExt;
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::net::tcp::{OwnedReadHalf, OwnedWriteHalf};
use tokio::net::TcpStream;
use tokio_tungstenite::tungstenite::protocol::frame::coding::{Control, Data, OpCode};
use tokio_tungstenite::tungstenite::protocol::frame::FrameHeader;
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::{accept_async, client_async, WebSocketStream};

use crate::link_interfaces::ip_link_subject;
use crate::writer_queue::{OutboundQueue, OutboundTx, WriterHandle};
use crate::{LinkDriver, LinkEvent, LostCause, Reliability, RxFrame, TxFrame};
use bytes::Bytes;
use wz_session_core::link::BoxedLinkDriver;
use wz_session_core::link::{LinkDropCause, LinkSendOutcome};
use wz_session_core::link::{LinkKind, LinkSubject};
use wz_session_core::link::{RxBytes, RxStorage};
use wz_session_core::qos::Priority;

/// R3264 — which end of the connection a link is. RFC 6455 section 5.3: a
/// client masks every frame it sends, with a fresh unpredictable key, and a
/// server masks none.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WsEnd {
    /// The end that dialed and sent the upgrade request.
    Client,
    /// The end that accepted it.
    Server,
}

impl WsEnd {
    /// The room a message needs in front of its payload for the largest header
    /// it can take: two bytes, a 16-bit extended length (a message is at most
    /// 65535 bytes, so never the 64-bit one), and a client's key.
    pub const fn headroom(self) -> usize {
        match self {
            Self::Client => 2 + 2 + 4,
            Self::Server => 2 + 2,
        }
    }

    /// The key a frame of this end is masked with: a fresh random one for a
    /// client, none for a server.
    fn mask(self) -> Option<[u8; 4]> {
        match self {
            Self::Client => Some(rand::random()),
            Self::Server => None,
        }
    }
}

/// R3264 — the header of one binary message (one FIN frame) of `len` bytes.
fn binary_header(mask: Option<[u8; 4]>) -> FrameHeader {
    FrameHeader {
        is_final: true,
        rsv1: false,
        rsv2: false,
        rsv3: false,
        opcode: OpCode::Data(Data::Binary),
        mask,
    }
}

/// R3264 — frame, IN PLACE, the message of `len` bytes that lies at
/// `buf[at..at + len]`: its header is written so that it ends at `at`, and the
/// payload is masked with `mask` if there is one. Answers where the frame
/// starts; `buf[start..at + len]` is then the frame as it goes on the wire.
/// `at` must leave room for the header, which [`WsEnd::headroom`] does.
pub fn frame_in_place(buf: &mut [u8], at: usize, len: usize, mask: Option<[u8; 4]>) -> usize {
    let header = binary_header(mask);
    let start = at - header.len(len as u64);
    let mut room = &mut buf[start..at];
    header
        .format(len as u64, &mut room)
        .expect("the header fits the room measured for it");
    debug_assert!(room.is_empty(), "the header filled its room exactly");
    if let Some(key) = mask {
        apply_mask(&mut buf[at..at + len], key);
    }
    start
}

/// RFC 6455 section 5.3: octet `i` of the payload is XORed with octet `i % 4`
/// of the key.
fn apply_mask(payload: &mut [u8], key: [u8; 4]) {
    for (i, byte) in payload.iter_mut().enumerate() {
        *byte ^= key[i & 3];
    }
}

/// R3264 — the message `payload` as a frame in a vector of its own, for a queue
/// with no pool: the header and the (masked) payload.
fn frame_vec(payload: &[u8], mask: Option<[u8; 4]>) -> Vec<u8> {
    let header = binary_header(mask);
    let mut frame = Vec::with_capacity(header.len(payload.len() as u64) + payload.len());
    header
        .format(payload.len() as u64, &mut frame)
        .expect("a vector takes the header");
    let at = frame.len();
    frame.extend_from_slice(payload);
    if let Some(key) = mask {
        apply_mask(&mut frame[at..], key);
    }
    frame
}

/// R3264 — the closing frame the writer sends when the link's queue finishes:
/// a Close with no body, masked by a client.
fn close_frame(end: WsEnd) -> Vec<u8> {
    let header = FrameHeader {
        opcode: OpCode::Control(Control::Close),
        mask: end.mask(),
        ..FrameHeader::default()
    };
    let mut frame = Vec::with_capacity(header.len(0));
    header
        .format(0, &mut frame)
        .expect("a vector takes the header");
    frame
}

/// R3264 — the byte stream tungstenite runs over. Whole during the handshake;
/// once [`wire_ws_stream`] has split the connection, tungstenite keeps the read
/// half, and what it writes from then on (the Pong that answers a Ping, the
/// Close that answers a Close: whole frames, masked as its end requires) is
/// queued on the link's CONTROL lane, so the one writer of the connection puts
/// it between data frames and never inside one.
pub struct WsIo {
    read: WsRead,
    control: Option<OutboundTx>,
}

enum WsRead {
    Whole(TcpStream),
    Half(OwnedReadHalf),
    /// Only while [`WsIo::split_off`] swaps one for the other.
    Taken,
}

impl WsIo {
    fn new(tcp: TcpStream) -> Self {
        Self {
            read: WsRead::Whole(tcp),
            control: None,
        }
    }

    /// Ask the connection a question while it is whole. The socket is lent to
    /// `ask` and never returned: this connection was tuned where it was dialled
    /// or accepted, so an accessor that handed the `TcpStream` out would be a
    /// second producer of one, which the per-link tuning seam gate
    /// (`tcp_tuning_seam_gate.py`) rightly reads as an untuned socket.
    fn ask_whole<R>(&self, ask: impl FnOnce(&TcpStream) -> R) -> R {
        match &self.read {
            WsRead::Whole(tcp) => ask(tcp),
            _ => unreachable!("a link is read as whole only before it is wired"),
        }
    }

    /// The local address of the connection, while it is whole.
    fn local_addr(&self) -> io::Result<SocketAddr> {
        self.ask_whole(TcpStream::local_addr)
    }

    /// The peer address of the connection, while it is whole.
    fn peer_addr(&self) -> io::Result<SocketAddr> {
        self.ask_whole(TcpStream::peer_addr)
    }

    /// `TCP_NODELAY` as the connection holds it, while it is whole.
    fn nodelay(&self) -> io::Result<bool> {
        self.ask_whole(TcpStream::nodelay)
    }

    /// Keep the read half, route later writes to `control`, and hand back the
    /// write half for the writer task.
    fn split_off(&mut self, control: OutboundTx) -> OwnedWriteHalf {
        let WsRead::Whole(tcp) = std::mem::replace(&mut self.read, WsRead::Taken) else {
            unreachable!("a link is wired once");
        };
        let (read, write) = tcp.into_split();
        self.read = WsRead::Half(read);
        self.control = Some(control);
        write
    }
}

impl AsyncRead for WsIo {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        match &mut self.get_mut().read {
            WsRead::Whole(tcp) => Pin::new(tcp).poll_read(cx, buf),
            WsRead::Half(read) => Pin::new(read).poll_read(cx, buf),
            WsRead::Taken => unreachable!("the read half is put back at once"),
        }
    }
}

impl AsyncWrite for WsIo {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        if let Some(control) = this.control.as_ref() {
            // tungstenite hands over whole frames: its write buffer holds
            // nothing else, and this takes all of it.
            return Poll::Ready(match control.send(Priority::Control, buf.to_vec()) {
                Ok(()) => Ok(buf.len()),
                Err(_) => Err(io::ErrorKind::BrokenPipe.into()),
            });
        }
        match &mut this.read {
            WsRead::Whole(tcp) => Pin::new(tcp).poll_write(cx, buf),
            _ => unreachable!("a split link writes through its control lane"),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match &mut self.get_mut().read {
            WsRead::Whole(tcp) => Pin::new(tcp).poll_flush(cx),
            _ => Poll::Ready(Ok(())),
        }
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match &mut self.get_mut().read {
            WsRead::Whole(tcp) => Pin::new(tcp).poll_shutdown(cx),
            // The writer task owns the write half and ends it.
            _ => Poll::Ready(Ok(())),
        }
    }
}

/// R3264 — a connected, handshaked WebSocket link, not yet wired: the protocol
/// stream over the whole connection, and which end of it this is.
pub struct WsLink {
    ws: WebSocketStream<WsIo>,
    end: WsEnd,
}

impl WsLink {
    /// `TCP_NODELAY` as the TCP connection under the link holds it, read back
    /// off the socket itself. The socket is not handed out: it was tuned where
    /// it was dialled or accepted, and a witness reads the option, not the
    /// stream.
    pub fn tcp_nodelay(&self) -> io::Result<bool> {
        self.ws.get_ref().nodelay()
    }

    /// Which end of the connection this is.
    pub fn end(&self) -> WsEnd {
        self.end
    }
}

/// Dial a WebSocket-over-TCP connection — TCP-connect to `addr`, then run the
/// RFC6455 client handshake ([`client_async`]) over it, returning the
/// connected [`WsLink`] ready for [`wire_ws_stream`]. The request URI
/// is `ws://{addr}/` (the `Host` header matches the dialed addr; wz<->wz uses
/// the root path). No cert config is involved, so — unlike TLS — a `ws/...`
/// session dials through the generic `dial_locator`, not a bespoke seam.
pub async fn dial_ws(
    addr: SocketAddr,
    link_socket: &crate::link_socket::LinkSocket<'_>,
) -> io::Result<WsLink> {
    // R311y236 — the TCP under a WS dial honours the locator `#iface=` bind via
    // the shared connect primitive (SO_BINDTODEVICE before connect). R2590 — a
    // ws `LinkSocket` carries no `bind` or `dscp`, because upstream's ws link
    // reads neither.
    let tcp = crate::iface_bind::connect_tcp_bound(addr, link_socket).await?;
    let url = format!("ws://{addr}/");
    let (ws, _resp) = client_async(url.as_str(), WsIo::new(tcp))
        .await
        .map_err(io::Error::other)?;
    Ok(WsLink {
        ws,
        end: WsEnd::Client,
    })
}

/// Accept side — run the RFC6455 server handshake ([`accept_async`]) over an
/// already-accepted [`TcpStream`]. The acceptor's caller owns the
/// `TcpListener::accept`; this is the WS analogue of handing
/// `accept_and_open_session` a `DialedLink::Tcp`.
pub async fn accept_ws(tcp: TcpStream) -> io::Result<WsLink> {
    let ws = accept_async(WsIo::new(tcp))
        .await
        .map_err(io::Error::other)?;
    Ok(WsLink {
        ws,
        end: WsEnd::Server,
    })
}

/// Split a handshaked [`WsLink`] into the cooperating drivers the
/// session FSM consumes: an inbound [`WsReadDriver`] (`&mut LinkDriver` for the
/// poll loop), an outbound `Arc<`[`WsWriteDriver`]`>` (`BoxedLinkDriver` for
/// `send_blocking`), and the [`ws_writer_task`] join handle. The handle is
/// awaited during teardown so a tail frame the FSM enqueued during its final
/// transition still reaches the peer before the socket closes.
pub fn wire_ws_stream(link: WsLink) -> (WsReadDriver, Arc<WsWriteDriver>, WriterHandle) {
    let WsLink { mut ws, end } = link;
    // R311y453 — the §5.16 subject, off the TCP socket the WebSocket wraps,
    // read BEFORE the split takes ownership of the halves.
    let wire = ws.get_ref();
    let subject = ip_link_subject(LinkKind::Ws, wire.local_addr().ok());
    // R311y473 — the adminspace `{src,dst}` pair, off the same wrapped TCP socket
    // and in the same before-the-split window.
    let endpoints = crate::link_interfaces::ip_link_endpoints(
        LinkKind::Ws,
        wire.local_addr().ok(),
        wire.peer_addr().ok(),
    );
    let (tx, rx) = crate::writer_queue::datagram_outbound_channel();
    let write = ws.get_mut().split_off(tx.clone());
    let inbound = WsReadDriver::new(ws);
    let writer_handle = WriterHandle::spawn(rx, move |queue| ws_writer_task(write, end, queue));
    let outbound = Arc::new(WsWriteDriver::new(tx, end, subject, endpoints));
    (inbound, outbound, writer_handle)
}

/// R3264 — a received binary message, which tungstenite 0.26 and later hands
/// over as refcounted `Bytes`, as the frame's lent storage: the frame (and every
/// sample taken from it) is a range of the library's own buffer, as a QUIC
/// datagram's is (`quic_datagram_pipeline::frame_of_datagram`). The one `Arc`
/// the storage needs replaces the vector 0.24 handed over.
struct WsMessage(Bytes);

impl RxStorage for WsMessage {
    fn as_slice(&self) -> &[u8] {
        &self.0
    }
}

fn frame_of_message(bytes: Bytes) -> RxFrame {
    let len = bytes.len();
    let storage: Arc<dyn RxStorage> = Arc::new(WsMessage(bytes));
    RxFrame::new(RxBytes::shared(storage, 0..len).expect("a message is a range of itself"))
}

/// Inbound read side of the split WebSocket — owns the read half and impls
/// [`LinkDriver`] with `poll_event` receiving one `Message::Binary` as one
/// [`RxFrame`] (no envelope strip — the WS message boundary is the frame
/// boundary, like a UDP datagram). The send/open/close methods mirror
/// [`crate::udp_pipeline::UdpReadDriver`]: open is a no-op (already
/// handshaked), close is a no-op (the writer task sends the WS Close), and
/// send fails loud (outbound goes via [`WsWriteDriver`]).
pub struct WsReadDriver {
    /// `Box`ed: the protocol stream carries tungstenite's own buffers, a few
    /// hundred bytes that would make every `InboundLink` that large (clippy
    /// `large_enum_variant`), as the dialed link's variant is boxed.
    read: Box<WebSocketStream<WsIo>>,
}

impl WsReadDriver {
    fn new(read: WebSocketStream<WsIo>) -> Self {
        Self {
            read: Box::new(read),
        }
    }
}

impl LinkDriver for WsReadDriver {
    async fn open(&mut self) -> io::Result<()> {
        // Already connected + handshaked; open is a no-op on this shape.
        Ok(())
    }

    async fn send(&mut self, _frame: &TxFrame<'_>, _reliability: Reliability) -> io::Result<()> {
        // The read side never sends — outbound goes via WsWriteDriver.
        Err(io::Error::new(
            io::ErrorKind::NotConnected,
            "WsReadDriver does not send; outbound goes via WsWriteDriver",
        ))
    }

    async fn close(&mut self) -> io::Result<()> {
        // The WS Close frame rides the writer task (sent when its queue
        // finishes); the read half just stops being polled.
        Ok(())
    }

    async fn poll_event(&mut self) -> LinkEvent {
        // One WS BINARY message = one wire frame (datagram flow, no
        // length-prefix reassembly). Control / text frames are not zenoh
        // payload, so skip them and keep reading (tungstenite auto-queues a
        // Pong for any Ping surfaced here). A Close frame or stream end is the
        // peer closing; a transport error is an OS-level loss.
        loop {
            match self.read.next().await {
                Some(Ok(Message::Binary(bytes))) => return LinkEvent::Rx(frame_of_message(bytes)),
                Some(Ok(Message::Close(_))) | None => {
                    return LinkEvent::Lost {
                        cause: LostCause::PeerClosed,
                    }
                }
                Some(Ok(_)) => continue,
                Some(Err(_)) => {
                    return LinkEvent::Lost {
                        cause: LostCause::OsError,
                    }
                }
            }
        }
    }
}

/// Outbound write side — holds an `OutboundTx` (R2919: priority lanes) whose
/// receiver is owned by the [`ws_writer_task`]. Impls [`BoxedLinkDriver`] with
/// a NON-blocking enqueue, the same sync-from-async decoupling
/// [`crate::udp_pipeline::UdpWriteDriver`] uses: the sync script-action
/// handlers fire from inside a future the same runtime drives, where a nested
/// `block_on` would trip the reentrancy check. The channel crosses that
/// boundary cleanly. No `link_mtu` override — pico's `_z_get_link_mtu_ws` is
/// the unbounded 65535 default a stream link inherits.
pub struct WsWriteDriver {
    tx: crate::writer_queue::OutboundTx,
    /// R3264 — which end this is: whether each frame is masked.
    end: WsEnd,
    /// R311y453 — the §5.16 link-derived subject, resolved once at open.
    subject: LinkSubject,
    /// R311y473 — this link's `{src,dst}` locator pair for the adminspace.
    endpoints: Option<wz_session_core::link::LinkEndpoints>,
    /// R3240 — the slots of the link's transmit pool lent to the session, under
    /// `runtime-zero-copy`.
    #[cfg(feature = "runtime-zero-copy")]
    lent: crate::writer_queue::LendTable,
}

/// The largest websocket message a write half sends: zenoh's batch ceiling.
const WS_MAX_FRAME: usize = u16::MAX as usize;

impl WsWriteDriver {
    /// A write half for `end` over `tx` (built by
    /// [`crate::writer_queue::datagram_outbound_channel`]): what it queues is
    /// each message FRAMED, header and (masked) payload, as the writer writes it.
    pub fn new(
        tx: crate::writer_queue::OutboundTx,
        end: WsEnd,
        subject: LinkSubject,
        endpoints: Option<wz_session_core::link::LinkEndpoints>,
    ) -> Self {
        Self {
            tx,
            end,
            subject,
            endpoints,
            #[cfg(feature = "runtime-zero-copy")]
            lent: Default::default(),
        }
    }

    /// R3264 — the message of `len` bytes the lend holds behind this end's
    /// headroom, framed in place and queued: the slot is the wire frame.
    #[cfg(feature = "runtime-zero-copy")]
    fn commit_framed(&self, lend: crate::writer_queue::TxLend, len: usize) -> LinkSendOutcome {
        let at = self.end.headroom();
        // SAFETY: the lend is this write half's alone until it is committed or
        // given back, and `capacity` bytes from `base` lie in its slot.
        let slot = unsafe { std::slice::from_raw_parts_mut(lend.base(), lend.capacity()) };
        let start = frame_in_place(slot, at, len, self.end.mask());
        match self.tx.commit_from(lend, start, at - start + len) {
            Ok(()) => LinkSendOutcome::Sent,
            Err(e) => {
                log::warn!("wz-runtime-tokio: outbound ws channel closed; dropping frame ({e})");
                LinkSendOutcome::Dropped(LinkDropCause::WriterGone)
            }
        }
    }
}

impl BoxedLinkDriver for WsWriteDriver {
    // R311y453 — the §5.16 subject resolved at open. A field read, not a syscall.
    fn link_subject(&self) -> Option<&LinkSubject> {
        Some(&self.subject)
    }

    // R311y473 — the adminspace `{src,dst}` pair resolved at open.
    fn link_endpoints(&self) -> Option<&wz_session_core::link::LinkEndpoints> {
        self.endpoints.as_ref()
    }

    // The writer queue stamps the end of every write; see the stream driver.
    fn reports_wire_writes(&self) -> bool {
        true
    }

    fn ms_since_wire_write(&self) -> Option<u64> {
        self.tx.ms_since_wire_write()
    }

    fn send_blocking(&self, bytes: &[u8], reliability: Reliability) -> LinkSendOutcome {
        self.send_prioritized(bytes, reliability, wz_session_core::qos::Priority::DEFAULT)
    }

    fn wait_for_room(
        &self,
        priority: wz_session_core::qos::Priority,
        wait: wz_session_core::link::RoomWait,
    ) -> wz_session_core::link::RoomAnswer {
        self.tx.link_room(priority, wait)
    }

    fn shape_tx_queue(&self, shape: wz_session_core::link::TxQueueShape) {
        self.tx.reshape(shape)
    }

    // R2952 — the block-first slot lives on this link's outbound queue.
    fn block_first_acquire(&self, priority: wz_session_core::qos::Priority, wait_us: u64) -> bool {
        self.tx.block_first_acquire(priority, wait_us)
    }

    fn block_first_release(&self, priority: wz_session_core::qos::Priority) {
        self.tx.block_first_release(priority)
    }

    fn send_prioritized(
        &self,
        bytes: &[u8],
        _reliability: Reliability,
        priority: wz_session_core::qos::Priority,
    ) -> LinkSendOutcome {
        if bytes.len() > WS_MAX_FRAME {
            // Oversize: drop with a warn. zenoh's batch ceiling is 65535
            // (u16), so a larger frame is a wz-side encoder bug — loud.
            log::warn!(
                "wz-runtime-tokio: outbound ws frame {} bytes > 65535; dropping",
                bytes.len()
            );
            return LinkSendOutcome::Dropped(LinkDropCause::Oversize);
        }
        // R3264 — a pooled queue takes the message by COPYING it into a slot,
        // behind the room for its header (one copy, which a byte door cannot
        // avoid, and no allocation); the frame is then made in the slot.
        #[cfg(feature = "runtime-zero-copy")]
        if self.tx.is_pooled() {
            let at = self.end.headroom();
            let Some(lend) = self.tx.lend(priority, at + bytes.len()) else {
                log::warn!("wz-runtime-tokio: outbound ws channel closed; dropping frame");
                return LinkSendOutcome::Dropped(LinkDropCause::WriterGone);
            };
            // SAFETY: as in `commit_framed`; `at + bytes.len()` bytes were lent.
            unsafe {
                std::ptr::copy_nonoverlapping(bytes.as_ptr(), lend.base().add(at), bytes.len())
            };
            return self.commit_framed(lend, bytes.len());
        }
        if let Err(e) = self.tx.send(priority, frame_vec(bytes, self.end.mask())) {
            log::warn!("wz-runtime-tokio: outbound ws channel closed; dropping frame ({e})");
            return LinkSendOutcome::Dropped(LinkDropCause::WriterGone);
        }
        LinkSendOutcome::Sent
    }

    // R3240 — lend the session a slot of the link's transmit pool to encode one
    // message into. R3264 — behind the room for its header: the frame is then
    // made around the message in the slot (`commit_framed`), and the writer
    // writes the slot as it lies.
    #[cfg(feature = "runtime-zero-copy")]
    fn tx_slot_acquire(
        &self,
        want: usize,
        priority: wz_session_core::qos::Priority,
    ) -> Option<wz_session_core::link::TxSlotGrant> {
        self.lent
            .acquire_with_headroom(&self.tx, want, WS_MAX_FRAME, self.end.headroom(), priority)
    }

    #[cfg(feature = "runtime-zero-copy")]
    fn tx_slot_storage(&self, slot: wz_session_core::link::TxSlot) -> (*mut u8, usize) {
        self.lent.storage(slot)
    }

    #[cfg(feature = "runtime-zero-copy")]
    fn tx_slot_send(
        &self,
        slot: wz_session_core::link::TxSlot,
        start: usize,
        len: usize,
        _reliability: Reliability,
        _priority: wz_session_core::qos::Priority,
    ) -> LinkSendOutcome {
        let lend = self.lent.take(slot);
        if len > WS_MAX_FRAME || start != self.end.headroom() {
            self.tx.abort_lend(lend);
            return LinkSendOutcome::Dropped(LinkDropCause::Oversize);
        }
        self.commit_framed(lend, len)
    }

    #[cfg(feature = "runtime-zero-copy")]
    fn tx_slot_abort(&self, slot: wz_session_core::link::TxSlot) {
        self.lent.abort(&self.tx, slot)
    }

    fn open_blocking(&self) {
        // The WS handshake already ran (dial_ws / accept_ws); open is a no-op.
    }

    fn close_blocking(&self) {
        // The writer task sends the WS Close frame when every sender clone
        // drops (the owning scope releases the Arc) — the textbook
        // receiver-drop channel idiom, mirroring UdpWriteDriver::close_blocking.
    }
}

/// Async writer task. Owns the connection's write half and drains the outbound
/// queue one frame at a time, writing each as it lies: a data frame the
/// [`WsWriteDriver`] framed (header and masked payload, under
/// `runtime-zero-copy` in a slot of the link's transmit pool), or a control
/// frame tungstenite answered with on the control lane. Exits when the queue
/// is SEALED and drained, when every sender has dropped, or when a write fails
/// / stalls past [`WRITER_STALL_MS`](crate::writer_queue::WRITER_STALL_MS) on a
/// sealed queue (logged + bail) — see [`crate::writer_queue`] for why the seal,
/// and not sender liveness alone, is the teardown signal. The first two send a
/// Close frame so the peer observes a clean WebSocket close.
pub async fn ws_writer_task(mut write: OwnedWriteHalf, end: WsEnd, mut queue: OutboundQueue) {
    // R3264 — no copy at this seam: the frame goes to the socket from the
    // memory it was built in, started as the write begins and home through the
    // completion edge once it has returned (`recycle_wire`, or the drop on
    // every other way out).
    while let Some(mut frame) = queue.next_wire().await {
        frame.begin_write();
        match queue.guarded(write.write_all(&frame)).await {
            Some(Ok(())) => queue.recycle_wire(frame),
            Some(Err(e)) => {
                log::warn!("wz-runtime-tokio: ws_writer_task send failed: {e}; closing");
                return;
            }
            None => {
                log::warn!(
                    "wz-runtime-tokio: ws_writer_task stalled past {} ms draining a sealed \
                     queue; closing with frames undelivered",
                    crate::writer_queue::WRITER_STALL_MS
                );
                return;
            }
        }
    }
    // Queue finished -> send a WS Close frame so the peer sees a clean close.
    let _ = write.write_all(&close_frame(end)).await;
    let _ = write.flush().await;
}
