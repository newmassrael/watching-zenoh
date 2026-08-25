// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! R311ez — canonical datagram session-open transport pipeline (UDP).
//!
//! The datagram sibling of [`crate::link_pipeline`] (TCP). The session FSM
//! needs the link in the same two shapes a stream does — an async
//! `&mut LinkDriver` for the inbound poll loop and a sync
//! `Arc<dyn BoxedLinkDriver>` for the `send_blocking` fired from Lua
//! script-action handlers — but a UDP socket is NOT split into owned
//! read/write halves the way [`tokio::net::TcpStream::into_split`] gives.
//! Instead the one `UdpSocket` is shared via `Arc`: `tokio::net::UdpSocket`
//! takes `&self` for both `recv_from` and `send_to`, so a clone backs the
//! inbound [`UdpReadDriver`] while the [`udp_writer_task`] holds another and
//! drains the outbound channel. This is the structural difference the
//! R311es dial-constructor round flagged: "uniform driver consumption shape
//! is contingent on the read/write-split decision — TCP session-open splits
//! the stream, UDP shares one socket — so the shape is fixed at the
//! orchestration round, not the dial constructor".
//!
//! ## Pieces
//!
//! - [`dial_udp`] — the raw-dial primitive: bind an ephemeral local socket
//!   whose address family mirrors `peer` (a v4-bound socket cannot reach a
//!   v6 peer) and `connect` it to that peer (R311y474), returning it unwrapped
//!   so the caller chooses its consumption shape. The session-open path wires
//!   it via [`wire_udp_socket`]; [`crate::UdpDriver::connect`] repeats the same
//!   BIND in the unified single-driver shape but does NOT connect, so the two
//!   seams diverge — see [`dial_udp`].
//! - [`wire_udp_socket`] — shares the bound socket into the cooperating
//!   `(UdpReadDriver, Arc<UdpWriteDriver>, writer-task handle)` triple.
//! - [`UdpReadDriver`] — impls [`LinkDriver`] with `poll_event` receiving one
//!   datagram, from either the link's own `Arc<UdpSocket>` (dial/scout) or the
//!   accept demux's per-src channel (see below). No framing prefix — UDP
//!   preserves message boundaries, so one datagram is exactly one wire
//!   message (contrast the TCP [`crate::poll_framed`] / `StreamEnvelope`
//!   length-prefix reassembly).
//! - [`UdpWriteDriver`] — holds the channel sender; impls
//!   [`BoxedLinkDriver`] with a non-blocking enqueue, mirroring
//!   [`crate::link_pipeline::TcpWriteDriver`] so the sync-action /
//!   async-runtime boundary is decoupled the same way.
//! - [`udp_writer_task`] — holds the shared socket + peer; drains the
//!   channel and writes each payload as one datagram (no envelope encode).
//!
//! ## Multi-peer accept demux (R311y382)
//!
//! A `udp/..` ACCEPTOR has ONE bound socket but may serve N peers. UDP has no
//! `accept()` yielding a per-peer socket, so [`bind_udp_demux`] spawns a single
//! pump task ([`udp_demux_task`]) that is the SOLE `recv_from` owner of the
//! listener socket and routes each datagram to its SOURCE's face channel:
//!
//! - a datagram from a KNOWN src is forwarded to that src's bounded channel;
//! - a datagram from a NEW src opens a channel (its first datagram queued) and
//!   emits a [`NewUdpFace`] on the listener's new-face channel, which
//!   [`crate::session_open::BoundListener::accept_raw`] awaits.
//!
//! Each accepted face reads ONLY its own src's datagrams ([`wire_udp_demuxed`]
//! feeds [`UdpReadDriver`] from the channel, not a shared `recv_from`) — this
//! retires the R311y381 F1 CROSS-TALK (a second peer's datagram no longer lands
//! in the first face) and F2 PERPETUAL-THROTTLE (a second src is a real second
//! face, not the single-shot `Err` the mesh loop throttled on). The zenoh
//! `LinkManagerUnicastUdp` (`io/zenoh-links/zenoh-link-udp/src/unicast.rs`
//! `accept_read_task`) mirror; wz keys on `src` only where zenoh keys on
//! `(src,dst)` + `IP_PKTINFO` — equivalent for a concrete-IP `--listen
//! udp/HOST:P`, weaker only for a wildcard `0.0.0.0` bind (see
//! [`crate::session_open::BoundListener`] `Udp`).
//!
//! The pump must OUTLIVE the `BoundListener` on the one-shot `accept_bound`
//! path (which drops the listener before the accepted session is driven), so it
//! is kept alive by an `Arc<`[`UdpDemuxPump`]`>` shared between the listener and
//! every accepted face's read driver; it aborts only when the last holder
//! drops. A plain [`TokioJoinHandle`] does NOT abort on drop
//! (`runtime_impl.rs:209`), so the abort is explicit — the same RAII idiom as
//! the (private) `group.rs` `AbortOnDrop`.

use std::collections::HashMap;
use std::io;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use tokio::net::UdpSocket;
use tokio::sync::mpsc;

use wz_runtime_core::Runtime;

use crate::runtime_impl::{TokioJoinHandle, TokioRuntime};
use crate::writer_queue::{OutboundQueue, WriterHandle};
// R311mk — import `BoxedLinkDriver` from its SSOT home (the shared
// `wz_session_core::link` tier) rather than via the `crate::session_glue`
// re-export hop. The link pipeline is transport-agnostic (a multicast deploy
// binds a UDP multicast socket too), so it must not depend on the
// `transport-unicast`-gated `session_glue`.
use crate::link_interfaces::{ip_link_endpoints, ip_link_subject};
use crate::{LinkDriver, LinkEvent, LostCause, Reliability, RxFrame, TxFrame};
use wz_session_core::link::BoxedLinkDriver;
use wz_session_core::link::{InterceptorLink, LinkEndpoints, LinkSubject};

/// Maximum UDP payload (65535 IP datagram - 20 IPv4 header - 8 UDP header).
/// A larger frame is a wz-side encoder bug; the driver drops it loud rather
/// than handing `send_to` a buffer the kernel will reject. This is the OS
/// datagram ceiling, NOT the fragmentation budget — see [`UDP_LINK_MTU`].
const MAX_UDP_PAYLOAD: usize = 65507;

/// The UDP link MTU — the per-datagram frame budget the transport fragments
/// to, the wz analogue of zenoh-pico's `zl->_mtu` for a UDP link. pico's
/// `_z_get_link_mtu_udp_unicast` returns this exact `1450`
/// (`src/link/unicast/udp.c:97`; the multicast sibling `udp.c:106` matches,
/// though that path uses its own TX seam, not this driver), a payload that
/// fits inside one standard 1500-byte Ethernet frame so a zenoh fragment
/// never triggers kernel IP-layer fragmentation — best-effort UDP loses a
/// whole datagram if any one IP fragment drops, so the zenoh transport caps
/// the frame here rather than hand the kernel a 64 KB datagram to shred.
///
/// [`UdpWriteDriver::link_mtu`] reports this; `negotiated_batch_mtu` mins it
/// against the negotiated batch (`min(link mtu, batch)`, the wbuf size pico
/// computes at `transport/unicast/transport.c:47`), so a >1450 message
/// fragments into emittable datagrams. It binds BELOW the unbounded stream
/// `DEFAULT_LINK_MTU` (65535) the default would otherwise inherit — the same
/// way serial's `SERIAL_MTU` (1500) does — and below [`MAX_UDP_PAYLOAD`], so
/// frames reaching [`UdpWriteDriver::send_blocking`] are pre-fragmented well
/// under the drop guard, leaving that guard a pure defensive backstop.
///
/// `pub` so the link-MTU-driven fragmentation e2e (`tests/udp_frag_e2e`) can
/// assert `negotiated_batch_mtu() == UDP_LINK_MTU` against the named constant
/// rather than a magic `1450`, the same way serial's e2e pins `SERIAL_MTU`.
pub const UDP_LINK_MTU: usize = 1450;

/// Bind AND `connect` an outbound UDP socket targeting `peer` — the raw-dial
/// primitive for the datagram transport. Returns the socket unwrapped so the
/// caller can choose its consumption shape; the session-open path shares it via
/// [`wire_udp_socket`]. The local bind address family mirrors `peer` (a v4-bound
/// socket cannot reach a v6 peer); the ephemeral port (`:0`) lets the kernel
/// assign — the peer learns this Initiator port from the first datagram's
/// source address.
///
/// R311y474 — the `connect` is part of the contract, not an implementation
/// detail: it is what makes `local_addr` report the concrete egress address
/// rather than the wildcard the bind leaves, and it filters inbound datagrams to
/// this one peer. See the body for the upstream citation and the consequences.
/// [`crate::UdpDriver::connect`] performs the SAME bind but NOT the connect — it
/// is a separate unified-driver seam, so the two paths diverge here.
/// R311y524 — dial a UDP peer named by a DNS `host:port`, returning the
/// connected socket AND the address it resolved to (the caller needs the
/// concrete peer for `DialedLink::Udp`).
///
/// The named sibling of [`dial_udp`], and pico parity rather than a
/// convenience: pico resolves a UDP endpoint through
/// `getaddrinfo(s_address, s_port, ..)` with `SOCK_DGRAM` / `IPPROTO_UDP`
/// (`src/link/transport/udp/udp_posix.c:32-40`), so a `udp/hostname:port`
/// locator is an ordinary endpoint there. wz rejected it with a typed
/// `Unsupported` until this existed.
///
/// Walks the resolved addresses in order and keeps the first that dials,
/// mirroring [`crate::link_pipeline::dial_tcp_host`]'s walk and
/// `getaddrinfo`'s own ordered list. A UDP "dial" is a bind + `connect`, so a
/// failure here is a local socket error rather than a peer refusal — the walk
/// still matters, because the family of the resolved address decides the bind.
pub async fn dial_udp_host(host: &str, iface: Option<&str>) -> io::Result<(UdpSocket, SocketAddr)> {
    let mut last_err: Option<io::Error> = None;
    for addr in tokio::net::lookup_host(host).await? {
        match dial_udp(addr, iface).await {
            Ok(socket) => return Ok((socket, addr)),
            Err(e) => last_err = Some(e),
        }
    }
    Err(last_err.unwrap_or_else(|| {
        io::Error::new(
            io::ErrorKind::AddrNotAvailable,
            format!("no addresses resolved for {host}"),
        )
    }))
}

pub async fn dial_udp(peer: SocketAddr, iface: Option<&str>) -> io::Result<UdpSocket> {
    let bind_addr: SocketAddr = match peer {
        SocketAddr::V4(_) => (Ipv4Addr::UNSPECIFIED, 0).into(),
        SocketAddr::V6(_) => (Ipv6Addr::UNSPECIFIED, 0).into(),
    };
    let socket = UdpSocket::bind(bind_addr).await?;
    // R311y236 — honour the locator `#iface=` bind (SO_BINDTODEVICE). Unlike TCP
    // (where the device must precede connect), a UDP socket sets it after bind
    // and before the first send — both steer egress routing. Linux/Android only;
    // a warn-no-op off-platform (the shared `bind_socket_to_device` stub).
    if let Some(iface) = iface {
        crate::iface_bind::bind_socket_to_device(&socket, iface)?;
    }
    // R311y474 — CONNECT the dial socket to its peer, as zenoh does
    // (`zenoh-link-udp/src/unicast.rs:311`, immediately after its identical
    // UNSPECIFIED:0 bind). Two consequences, and the second is why this is not
    // cosmetic:
    //
    // 1. The kernel resolves the ROUTE, so `local_addr` stops reporting the
    //    wildcard `0.0.0.0:<port>` the bind left and starts reporting the concrete
    //    address this link actually egresses from — which is what upstream's
    //    `src_addr` is (`unicast.rs:317`), and the only form the adminspace can
    //    publish as a DIALABLE locator.
    // 2. The socket receives ONLY this peer's datagrams. For a unicast dial face
    //    that is the correct filter and upstream's; it also means an off-path
    //    sender can no longer inject into an established dial link.
    //
    // Scoped to the DIAL path deliberately: the acceptor's socket is shared across
    // faces and must stay unconnected (see `bind_udp`), and the multicast /
    // scouting sockets have their own binds and never route through here.
    socket.connect(peer).await?;
    Ok(socket)
}

/// Bind a UDP socket on `listen` for the ACCEPTOR side — the datagram twin of
/// [`dial_udp`]'s ephemeral bind, but on a KNOWN address:port an Initiator can
/// target. Returns the bound socket unwrapped; [`bind_udp_demux`] wraps it in the
/// multi-peer [`UdpDemux`] (spawning the [`udp_demux_task`] pump that learns each
/// peer from its first datagram's source). `#iface=` is honoured the same as
/// [`dial_udp`] (SO_BINDTODEVICE, Linux/Android; a warn-no-op off-platform).
pub async fn bind_udp(listen: SocketAddr, iface: Option<&str>) -> io::Result<UdpSocket> {
    let socket = UdpSocket::bind(listen).await?;
    if let Some(iface) = iface {
        crate::iface_bind::bind_socket_to_device(&socket, iface)?;
    }
    Ok(socket)
}

/// The bounded per-face inbound channel depth for the accept demux. The pump
/// `try_send`s each datagram to its face's channel; a FULL channel drops the
/// datagram (best-effort, exactly the kernel UDP receive buffer's behaviour when
/// the consumer falls behind — the demux moves that drop from the kernel buffer
/// to this bounded userspace queue rather than growing unbounded). Sized to
/// absorb scheduling jitter between the single pump and a face's read driver
/// (the 4-datagram handshake never fills it; bulk best-effort traffic that would
/// overrun it is dropped, not queued without bound).
const UDP_DEMUX_FACE_CHANNEL_CAP: usize = 256;

/// Backoff after a demux `recv_from` error before re-arming the receive — zenoh's
/// `UDP_ACCEPT_THROTTLE_TIME` (`io/zenoh-links/zenoh-link-udp/src/unicast.rs`).
/// A transient error (e.g. an ICMP port-unreachable surfacing as ECONNREFUSED on
/// the unconnected listener socket) must not tear down the live faces, so the pump
/// throttles-and-continues rather than returning; the sleep both yields and bounds
/// a (pathological, socket-still-owned) persistent error to a slow loop, not a
/// full-CPU hot-spin.
const UDP_DEMUX_RECV_ERROR_THROTTLE_MS: u64 = 100;

/// RAII guard that aborts the demux pump task when the LAST holder drops. The
/// pump must outlive the [`crate::session_open::BoundListener`] on the one-shot
/// `accept_bound` path (which consumes-and-drops the listener before the
/// accepted session is driven), so this guard is shared `Arc`-wise between the
/// listener ([`UdpDemux`]) and every accepted face's [`UdpReadDriver`]; the pump
/// aborts (releasing its `Arc<UdpSocket>`) only when both are gone. A plain
/// [`TokioJoinHandle`] does NOT abort on drop (`runtime_impl.rs:209`), so the
/// abort is explicit — the same idiom as the (private) `group.rs` `AbortOnDrop`.
pub(crate) struct UdpDemuxPump(TokioJoinHandle<()>);

impl Drop for UdpDemuxPump {
    fn drop(&mut self) {
        self.0.abort();
    }
}

/// A newly-observed unicast peer on a demux listener: the datagram SOURCE the
/// pump learned + the bounded inbound channel carrying ONLY this src's datagrams
/// (its first datagram — typically the InitSyn — is already queued). Emitted on
/// the listener's new-face channel;
/// [`crate::session_open::BoundListener::accept_raw`] awaits it and wires it into
/// an accepted face via [`wire_udp_demuxed`].
pub struct NewUdpFace {
    /// The datagram source — a REAL IP peer (contrast the unix/vsock/unixpipe
    /// families' anonymous accept), so a udp accept is `AcceptedPeer::Ip`.
    pub peer: SocketAddr,
    /// This src's demultiplexed inbound datagrams (first one pre-queued).
    pub inbound_rx: mpsc::Receiver<Vec<u8>>,
}

/// The multi-peer datagram listener a `udp/..` acceptor binds to — replaces the
/// R311y381 single-shot `Option<UdpSocket>`. One bound socket is shared: the
/// pump task ([`udp_demux_task`], the sole `recv_from` owner) routes each
/// datagram to its src's face channel, and [`Self::recv_new_face`] awaits a NEW
/// src. Retires reviewer-C's F1 (cross-talk — each face reads only its own src)
/// and F2 (perpetual-throttle — a second src is a real second face, not an Err).
pub struct UdpDemux {
    new_face_rx: mpsc::UnboundedReceiver<NewUdpFace>,
    /// The listener socket, shared with the pump (`recv_from`) and cloned into
    /// each accepted face's writer task (`send_to(peer)`).
    send_socket: Arc<UdpSocket>,
    /// The bound listen address, cached at bind (the pump owns the socket, so
    /// the listener cannot read `local_addr` off it) — always available, unlike
    /// the single-shot model whose `local_addr` broke after the socket was taken.
    local_addr: SocketAddr,
    /// The shared pump keep-alive; cloned into every accepted face so the pump
    /// outlives the listener on the one-shot path (see [`UdpDemuxPump`]).
    pump: Arc<UdpDemuxPump>,
}

impl UdpDemux {
    /// The cached bound listen address (always `Ok` — the pump owns the socket).
    pub fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }

    /// Await the NEXT new-src face, or `None` when the pump has ended (a
    /// `recv_from` error killed the listener socket). The caller
    /// ([`crate::session_open::BoundListener::accept_raw`]) maps `None` to a
    /// PARK (never an `Err`), so a dead pump does not resurrect the F2 throttle.
    pub async fn recv_new_face(&mut self) -> Option<NewUdpFace> {
        self.new_face_rx.recv().await
    }

    /// Assemble the wire inputs for a face accepted from this listener: the src's
    /// inbound channel + a `send_socket` clone (egress `send_to(peer)`) + a pump
    /// keep-alive clone (so the pump outlives the listener while this face reads).
    pub fn wire_inputs(&self, inbound_rx: mpsc::Receiver<Vec<u8>>) -> UdpAcceptedInputs {
        UdpAcceptedInputs {
            inbound_rx,
            send_socket: self.send_socket.clone(),
            pump: self.pump.clone(),
        }
    }
}

/// The per-face wire inputs an accepted demux face carries through
/// `AcceptedLink`/`DialedLink` into [`wire_udp_demuxed`]: the src's inbound
/// channel, a shared `send_socket` clone, and the pump keep-alive. An OPAQUE
/// bundle — its fields are private (only [`UdpDemux::wire_inputs`] builds it and
/// only [`wire_udp_demuxed`] consumes it), so the accept path threads one value
/// through the `pub` `AcceptedLink`/`DialedLink` variants without exposing the
/// crate-private [`UdpDemuxPump`] guard type.
pub struct UdpAcceptedInputs {
    /// This src's demultiplexed inbound datagrams (from [`NewUdpFace`]).
    inbound_rx: mpsc::Receiver<Vec<u8>>,
    /// The shared listener socket (egress `send_to(peer)`).
    send_socket: Arc<UdpSocket>,
    /// The shared pump keep-alive — keeps the demux pump alive while this face
    /// reads, even after the listener is dropped (the one-shot path).
    pump: Arc<UdpDemuxPump>,
}

/// Bind a UDP demux LISTENER on `listen` and spawn its [`udp_demux_task`] pump —
/// the multi-peer datagram acceptor the scheme-keyed accept seam
/// ([`crate::session_open::bind_locator`]) wraps in `BoundListener::Udp`.
/// `#iface=` is honoured via [`bind_udp`]. The pump starts pumping at bind (like
/// zenoh's `accept_read_task`), buffering faces/datagrams until `accept_raw`
/// drains them.
pub async fn bind_udp_demux(listen: SocketAddr, iface: Option<&str>) -> io::Result<UdpDemux> {
    let socket = bind_udp(listen, iface).await?;
    let local_addr = socket.local_addr()?;
    let socket = Arc::new(socket);
    let (new_face_tx, new_face_rx) = mpsc::unbounded_channel::<NewUdpFace>();
    let handle = TokioRuntime.spawn(udp_demux_task(socket.clone(), new_face_tx));
    Ok(UdpDemux {
        new_face_rx,
        send_socket: socket,
        local_addr,
        pump: Arc::new(UdpDemuxPump(handle)),
    })
}

/// The demux pump: the sole `recv_from` owner of the listener socket, routing
/// each inbound datagram to its SOURCE's face channel. A KNOWN src's datagram is
/// `try_send`ed (FULL -> drop = best-effort; CLOSED -> the face is gone, reap the
/// entry); a NEW src opens a bounded channel (first datagram queued) and emits a
/// [`NewUdpFace`], keeping the src only if a listener is still there to accept it.
///
/// NEITHER error path returns: the pump's ONLY termination is the [`UdpDemuxPump`]
/// RAII abort (fired when the last listener/face holder drops). A `return` here
/// would drop the stack `faces` map and CLOSE every live face's channel — and on
/// the one-shot `accept_bound` path the listener is dropped while an accepted face
/// lives on via the shared pump guard, so a single stray datagram (a spoofable new
/// src) would otherwise tear down that established session. So a `recv_from` error
/// throttles-and-continues ([`UDP_DEMUX_RECV_ERROR_THROTTLE_MS`], zenoh's
/// `UDP_ACCEPT_THROTTLE_TIME` parity) and a new src arriving after the listener is
/// gone is simply not accepted (its channel dropped) while the already-accepted
/// faces keep being served. The zenoh `accept_read_task`
/// (`io/zenoh-links/zenoh-link-udp/src/unicast.rs:518`) mirror.
async fn udp_demux_task(socket: Arc<UdpSocket>, new_face_tx: mpsc::UnboundedSender<NewUdpFace>) {
    use tokio::sync::mpsc::error::TrySendError;
    let mut faces: HashMap<SocketAddr, mpsc::Sender<Vec<u8>>> = HashMap::new();
    let mut buf = vec![0u8; MAX_UDP_PAYLOAD];
    loop {
        let (n, src) = match socket.recv_from(&mut buf).await {
            Ok(pair) => pair,
            // Throttle-and-CONTINUE, never return: a transient recv error must not
            // close the live faces' channels (see the fn doc). The sleep bounds a
            // pathological persistent error to a slow loop, not a hot-spin.
            Err(e) => {
                log::warn!("wz-runtime-tokio: udp_demux_task recv_from error: {e}; throttling");
                tokio::time::sleep(Duration::from_millis(UDP_DEMUX_RECV_ERROR_THROTTLE_MS)).await;
                continue;
            }
        };
        let payload = buf[..n].to_vec();
        if let Some(tx) = faces.get(&src) {
            match tx.try_send(payload) {
                Ok(()) => {}
                // Best-effort: the face consumer is behind, drop the datagram
                // exactly as the kernel UDP receive buffer would on overflow.
                Err(TrySendError::Full(_)) => {}
                // The face was torn down (its read driver dropped the receiver);
                // reap the entry so a later datagram from the same src opens a
                // fresh face (a reconnect). NB: this triggering datagram is itself
                // dropped — a same-src reconnect's first (InitSyn) datagram is lost
                // and self-heals on FSM retransmit (the udp best-effort contract).
                Err(TrySendError::Closed(_)) => {
                    faces.remove(&src);
                }
            }
        } else {
            let (tx, rx) = mpsc::channel(UDP_DEMUX_FACE_CHANNEL_CAP);
            // The first datagram always fits (the channel is empty), so the
            // InitSyn is never lost — it is queued for the face's first `recv`.
            let _ = tx.try_send(payload);
            // Keep the src ONLY if the listener accepted the new-face handoff. If
            // its receiver is gone (the one-shot path dropped the listener after
            // accepting), this src can never be accepted: drop its channel and keep
            // serving the already-accepted faces. Crucially do NOT return — the
            // still-live faces ride the shared pump guard, and a return would close
            // their channels (a stray-datagram teardown of an established session).
            if new_face_tx
                .send(NewUdpFace {
                    peer: src,
                    inbound_rx: rx,
                })
                .is_ok()
            {
                faces.insert(src, tx);
            }
        }
    }
}

/// Share a bound [`UdpSocket`] into the cooperating drivers the session FSM
/// consumes: an inbound [`UdpReadDriver`] (`&mut LinkDriver` for the poll
/// loop), an outbound `Arc<`[`UdpWriteDriver`]`>` (`BoxedLinkDriver` for
/// `send_blocking`), and the [`udp_writer_task`] join handle.
///
/// Unlike [`crate::link_pipeline::wire_tcp_stream`], there is no owned
/// half-split: the single socket is wrapped in an `Arc` whose clones back
/// both directions (tokio's `UdpSocket` is `&self` for send and recv, so
/// concurrent send/recv on clones is sound). `peer` is the unicast target
/// every outbound datagram is addressed to. The handle is awaited during
/// teardown so a tail frame the FSM enqueued during its final transition
/// still reaches the peer before the socket drops.
pub fn wire_udp_socket(
    socket: UdpSocket,
    peer: SocketAddr,
) -> (UdpReadDriver, Arc<UdpWriteDriver>, WriterHandle) {
    let socket = Arc::new(socket);
    // R311y453 — the §5.16 subject, off the socket this face owns.
    let subject = ip_link_subject(InterceptorLink::Udp, socket.local_addr().ok());
    // R311y474 — the adminspace `{src,dst}` pair. `peer` is the unicast target
    // every outbound datagram is addressed to, so the DST is known exactly; the
    // SRC is this face's own socket. Both ends known means no `None` arm here
    // beyond a failed `local_addr` syscall.
    let endpoints = ip_link_endpoints(InterceptorLink::Udp, socket.local_addr().ok(), Some(peer));
    let inbound = UdpReadDriver::from_socket(socket.clone());
    let (tx, rx) = mpsc::unbounded_channel::<Vec<u8>>();
    let writer_handle = WriterHandle::spawn(rx, |queue| udp_writer_task(socket, peer, queue));
    let outbound = Arc::new(UdpWriteDriver::new(tx, subject, endpoints));
    (inbound, outbound, writer_handle)
}

/// Wire an ACCEPTED demux face into the cooperating drivers — the accept-side
/// twin of [`wire_udp_socket`]. Unlike the dial path (which owns its socket),
/// the face's RX is the demux pump's per-src channel (`inputs.inbound_rx`, only
/// this `peer`'s datagrams — F1 cross-talk retired) and its TX is a `send_to` on
/// the SHARED listener socket (`inputs.send_socket`, addressed to `peer`). The
/// pump keep-alive (`inputs.pump`) rides into the read driver so the pump lives
/// as long as this face reads, even after the listener drops (the one-shot
/// `accept_bound` path). The outbound + writer-task half is identical to
/// [`wire_udp_socket`]'s.
pub fn wire_udp_demuxed(
    inputs: UdpAcceptedInputs,
    peer: SocketAddr,
) -> (UdpReadDriver, Arc<UdpWriteDriver>, WriterHandle) {
    let UdpAcceptedInputs {
        inbound_rx,
        send_socket,
        pump,
    } = inputs;
    // R311y453 — the §5.16 subject: an accept-demux face shares the listener's
    // send socket, so the local address is that socket's.
    let subject = ip_link_subject(InterceptorLink::Udp, send_socket.local_addr().ok());
    // R311y474 — the adminspace `{src,dst}` pair. The SRC is the SHARED listener
    // socket's address (every demux face reports the same one, which is the truth:
    // they are one socket), and the DST is this face's own demultiplexed peer.
    let endpoints = ip_link_endpoints(
        InterceptorLink::Udp,
        send_socket.local_addr().ok(),
        Some(peer),
    );
    let inbound = UdpReadDriver::from_demux(inbound_rx, peer, pump);
    let (tx, rx) = mpsc::unbounded_channel::<Vec<u8>>();
    let writer_handle = WriterHandle::spawn(rx, |queue| udp_writer_task(send_socket, peer, queue));
    let outbound = Arc::new(UdpWriteDriver::new(tx, subject, endpoints));
    (inbound, outbound, writer_handle)
}

/// The RX source of a [`UdpReadDriver`] — the dial/scout path reads directly
/// from its own (unconnected) socket via `recv_from`; the accept-demux path
/// reads ONLY its src's datagrams from the pump's bounded channel. Keeping the
/// choice INSIDE `UdpReadDriver` (not a second `InboundLink` variant) means the
/// wire split is one type either way.
enum UdpRxSource {
    /// Dial/scout: this link owns the socket and `recv_from`s it (one peer;
    /// `recv_from` accepts any source, but a dialer only ever talks to its one
    /// target — the F1 cross-talk concern is the ACCEPT side, fixed by `Demux`).
    Socket(Arc<UdpSocket>),
    /// Accept-demux: this face's datagrams arrive on the pump's bounded channel,
    /// already demultiplexed to this `peer` (no cross-talk — F1 retired). `_pump`
    /// keeps the shared demux pump alive as long as this face reads (so the pump
    /// outlives the listener on the one-shot `accept_bound` path).
    Demux {
        rx: mpsc::Receiver<Vec<u8>>,
        peer: SocketAddr,
        _pump: Arc<UdpDemuxPump>,
    },
}

/// Inbound read side of a UDP link — impls [`LinkDriver`] with `poll_event`
/// receiving one datagram as one [`RxFrame`]. The RX comes from either the
/// link's own socket (dial/scout, [`Self::from_socket`]) or the accept demux's
/// per-src channel ([`Self::from_demux`]) — see [`UdpRxSource`]. The
/// send/open/close methods mirror [`crate::link_pipeline::TcpReadDriver`]: open
/// is a no-op (already bound/wired), close is a no-op (UDP has no teardown
/// handshake), and send fails loud (the FSM's outbound path is the sibling
/// [`UdpWriteDriver`]).
pub struct UdpReadDriver {
    source: UdpRxSource,
}

impl UdpReadDriver {
    /// The dial/scout read driver: `recv_from` this link's own socket.
    fn from_socket(socket: Arc<UdpSocket>) -> Self {
        Self {
            source: UdpRxSource::Socket(socket),
        }
    }

    /// The accept-demux read driver: read this src's datagrams from the pump's
    /// bounded channel, tagging each with the fixed `peer`. Holds a pump
    /// keep-alive clone so the demux pump lives as long as this face.
    fn from_demux(rx: mpsc::Receiver<Vec<u8>>, peer: SocketAddr, pump: Arc<UdpDemuxPump>) -> Self {
        Self {
            source: UdpRxSource::Demux {
                rx,
                peer,
                _pump: pump,
            },
        }
    }
}

impl LinkDriver for UdpReadDriver {
    async fn open(&mut self) -> io::Result<()> {
        // The socket is already bound (from a live UdpSocket); open is
        // unconditionally Ok, mirroring UdpDriver::from_socket.
        Ok(())
    }

    async fn send(&mut self, _frame: &TxFrame<'_>, _reliability: Reliability) -> io::Result<()> {
        // The read side never sends — outbound goes via UdpWriteDriver.
        // Surface NotConnected so an accidental call fails loud rather
        // than silently dropping the datagram.
        Err(io::Error::new(
            io::ErrorKind::NotConnected,
            "UdpReadDriver does not send; outbound goes via UdpWriteDriver",
        ))
    }

    async fn close(&mut self) -> io::Result<()> {
        // UDP has no kernel-level close handshake; dropping the Arc clones
        // releases the FD. No explicit shutdown needed.
        Ok(())
    }

    async fn poll_event(&mut self) -> LinkEvent {
        // One datagram = one wire message (UDP preserves boundaries, so no
        // length-prefix reassembly).
        match &mut self.source {
            // Dial/scout: read directly off the socket (single datagram cap =
            // MAX_UDP_PAYLOAD). The src is the datagram sender.
            UdpRxSource::Socket(socket) => {
                let mut buf = vec![0u8; MAX_UDP_PAYLOAD];
                match socket.recv_from(&mut buf).await {
                    Ok((n, src)) => {
                        buf.truncate(n);
                        LinkEvent::Rx(RxFrame::with_src(buf, src))
                    }
                    Err(_) => LinkEvent::Lost {
                        cause: LostCause::OsError,
                    },
                }
            }
            // Accept-demux: the pump already demultiplexed this src's datagrams
            // to `rx` and tagged the face with `peer`. A closed channel means the
            // pump ended (the listener socket died), reported as `Lost` — the
            // datagram-side mirror of a stream read hitting EOF.
            UdpRxSource::Demux { rx, peer, .. } => match rx.recv().await {
                Some(bytes) => LinkEvent::Rx(RxFrame::with_src(bytes, *peer)),
                None => LinkEvent::Lost {
                    cause: LostCause::OsError,
                },
            },
        }
    }
}

/// Outbound write side — holds an `mpsc::UnboundedSender<Vec<u8>>` whose
/// receiver is owned by the [`udp_writer_task`]. Impls [`BoxedLinkDriver`]
/// with a NON-blocking enqueue, the same sync-from-async decoupling
/// [`crate::link_pipeline::TcpWriteDriver`] uses: the sync Lua
/// script-action handlers fire from inside a future the same runtime drives,
/// where a nested `block_on` would trip the reentrancy check. The channel
/// crosses that boundary cleanly.
pub struct UdpWriteDriver {
    tx: mpsc::UnboundedSender<Vec<u8>>,
    /// R311y453 — the §5.16 link-derived subject, resolved once at open.
    subject: LinkSubject,
    /// R311y474 — the adminspace `{src,dst}` locator pair, resolved once at open.
    endpoints: Option<LinkEndpoints>,
}

impl UdpWriteDriver {
    fn new(
        tx: mpsc::UnboundedSender<Vec<u8>>,
        subject: LinkSubject,
        endpoints: Option<LinkEndpoints>,
    ) -> Self {
        Self {
            tx,
            subject,
            endpoints,
        }
    }
}

impl BoxedLinkDriver for UdpWriteDriver {
    // R311y453 — the §5.16 subject resolved at open. A field read, not a syscall.
    fn link_subject(&self) -> Option<&LinkSubject> {
        Some(&self.subject)
    }

    // R311y474 — the adminspace `{src,dst}` pair resolved at open. A field read.
    fn link_endpoints(&self) -> Option<&LinkEndpoints> {
        self.endpoints.as_ref()
    }

    fn send_blocking(&self, bytes: &[u8], _reliability: Reliability) {
        // UDP link layer is best-effort by definition; the Reliability hint
        // is the session FSM's concern. The transport TX path now caps its
        // fragment budget to THIS link's MTU ([`Self::link_mtu`] feeds
        // `SessionLinkActions::negotiated_batch_mtu`, which mins it against
        // the negotiated batch), so a well-formed session fragments an
        // oversize message to <= UDP_LINK_MTU datagrams before reaching this
        // seam. The MAX_UDP_PAYLOAD guard stays as a loud defensive backstop:
        // a caller that bypassed the negotiated budget drops here rather than
        // hand `send_to` a datagram the kernel will reject.
        if bytes.len() > MAX_UDP_PAYLOAD {
            log::warn!(
                "wz-runtime-tokio: outbound datagram {} bytes > {MAX_UDP_PAYLOAD}; dropping",
                bytes.len()
            );
            return;
        }
        if let Err(e) = self.tx.send(bytes.to_vec()) {
            log::warn!("wz-runtime-tokio: outbound channel closed; dropping datagram ({e})");
        }
    }

    fn open_blocking(&self) {
        // The socket is already bound; open is a no-op on this shape.
    }

    fn close_blocking(&self) {
        // The writer task exits when every sender clone drops (after the
        // owning scope releases the Arc). Letting the receiver-drop signal
        // terminate the task is the textbook channel idiom (mirrors
        // TcpWriteDriver::close_blocking).
    }

    fn link_mtu(&self) -> usize {
        // The UDP link's per-datagram frame budget — zenoh-pico's
        // `_z_get_link_mtu_udp_unicast` returns this same `1450`
        // (`src/link/unicast/udp.c:97`). The transport reads it through
        // `negotiated_batch_mtu` to bound its TX fragment budget
        // (`min(link mtu, negotiated batch)`, transport/unicast/transport.c:47),
        // so a >1450 message splits into datagrams that each fit one Ethernet
        // frame instead of relying on kernel IP fragmentation. TCP inherits
        // the unbounded `DEFAULT_LINK_MTU`; serial caps at SERIAL_MTU (1500).
        UDP_LINK_MTU
    }
}

/// Async writer task. Holds the shared `Arc<UdpSocket>` + the unicast `peer`
/// and drains the outbound channel one frame at a time, writing each payload
/// as one datagram via `send_to`. No envelope encode — UDP datagram
/// boundaries are the framing (contrast [`crate::link_pipeline::writer_task`],
/// which length-prefixes each payload through `StreamEnvelope`). Exits when
/// the queue is SEALED and drained, when every [`UdpWriteDriver`] clone has
/// dropped, or when a `send_to` fails / stalls past
/// [`WRITER_STALL_MS`](crate::writer_queue::WRITER_STALL_MS) on a sealed queue
/// (logged + bail) — see [`crate::writer_queue`] for why the seal, and not
/// sender liveness alone, is the teardown signal. UDP has no write-half
/// shutdown, so the task just returns.
pub async fn udp_writer_task(socket: Arc<UdpSocket>, peer: SocketAddr, mut queue: OutboundQueue) {
    // R311y474 — a DIAL socket is `connect`ed to its one peer, so it emits with
    // `send`; the shared LISTENER socket serves N peers and must address each
    // datagram, so it emits with `send_to`. Reading the socket's own connectedness
    // (rather than taking a flag) means the two wire paths cannot disagree with the
    // socket they were handed: `peer_addr` succeeds exactly when `connect` ran.
    //
    // Not merely stylistic. `sendto(2)` on a CONNECTED socket is permitted on Linux
    // but returns EISCONN on macOS/BSD, so an unconditional `send_to` would make
    // every udp dial fail on a platform §5.20 carries as an atom.
    let connected = socket.peer_addr().is_ok();
    while let Some(payload) = queue.next().await {
        let send = async {
            if connected {
                socket.send(&payload).await
            } else {
                socket.send_to(&payload, peer).await
            }
        };
        match queue.guarded(send).await {
            Some(Ok(_)) => {}
            Some(Err(e)) => {
                log::warn!("wz-runtime-tokio: udp_writer_task send failed: {e}; closing");
                return;
            }
            None => {
                log::warn!(
                    "wz-runtime-tokio: udp_writer_task stalled past {} ms draining a sealed \
                     queue; closing with frames undelivered",
                    crate::writer_queue::WRITER_STALL_MS
                );
                return;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `dial_udp` binds an ephemeral local socket whose family mirrors the
    /// peer; the bound local addr is a concrete v4 ephemeral port.
    #[tokio::test]
    async fn dial_udp_binds_ephemeral_v4() {
        let peer: SocketAddr = "127.0.0.1:9".parse().expect("peer addr");
        let socket = dial_udp(peer, None).await.expect("bind ephemeral");
        let local = socket.local_addr().expect("local addr");
        assert!(local.is_ipv4(), "v4 peer -> v4 bind");
        assert_ne!(local.port(), 0, "kernel assigned a concrete port");
    }

    /// Oversize datagrams are dropped by `send_blocking` rather than enqueued;
    /// the channel stays usable afterwards.
    #[tokio::test]
    async fn write_driver_drops_oversize_datagram() {
        let (tx, mut rx) = mpsc::unbounded_channel::<Vec<u8>>();
        let driver = UdpWriteDriver::new(tx, LinkSubject::UNKNOWN, None);
        driver.send_blocking(&vec![0u8; MAX_UDP_PAYLOAD + 1], Reliability::BestEffort);
        driver.send_blocking(b"ok", Reliability::BestEffort);
        // Only the in-range datagram reached the channel.
        assert_eq!(rx.recv().await.as_deref(), Some(b"ok".as_slice()));
    }

    /// The UDP write driver reports the UDP link MTU (not the unbounded
    /// `DEFAULT_LINK_MTU` a stream link inherits), so the transport's
    /// `negotiated_batch_mtu` mins its TX fragment budget down to a datagram
    /// that fits one Ethernet frame — matching zenoh-pico's
    /// `_z_get_link_mtu_udp_unicast` (1450). This is the link-side half of
    /// the >MTU fragmentation wiring; the transport-agnostic split +
    /// reassembly is proved end-to-end by `layer3_reassembly_tx` (TCP) /
    /// `serial_pty_e2e`.
    #[test]
    fn udp_write_driver_reports_udp_link_mtu() {
        // Static invariants: the UDP cap must bind BELOW the unbounded stream
        // default (else the `negotiated_batch_mtu` min term is inert and UDP
        // never fragments) AND below the `MAX_UDP_PAYLOAD` drop guard (so
        // frames arrive pre-fragmented and the guard is a pure backstop).
        // Const assertions so a constant regression fails the build.
        const _: () = assert!(UDP_LINK_MTU < wz_session_core::link::DEFAULT_LINK_MTU);
        const _: () = assert!(UDP_LINK_MTU < MAX_UDP_PAYLOAD);

        let (tx, _rx) = mpsc::unbounded_channel::<Vec<u8>>();
        let driver = UdpWriteDriver::new(tx, LinkSubject::UNKNOWN, None);
        assert_eq!(driver.link_mtu(), UDP_LINK_MTU);
    }

    /// Two wired sockets exchange a raw datagram end to end: the writer task
    /// addresses `peer`, the read driver receives it as one `RxFrame` with no
    /// envelope strip (datagram boundary == message boundary).
    #[tokio::test]
    async fn wired_sockets_round_trip_one_datagram() {
        let a = UdpSocket::bind("127.0.0.1:0").await.expect("bind a");
        let b = UdpSocket::bind("127.0.0.1:0").await.expect("bind b");
        let a_addr = a.local_addr().expect("a addr");
        let b_addr = b.local_addr().expect("b addr");

        let (_a_in, a_out, a_writer) = wire_udp_socket(a, b_addr);
        let (mut b_in, _b_out, _b_writer) = wire_udp_socket(b, a_addr);

        a_out.send_blocking(b"hello-datagram", Reliability::BestEffort);
        match b_in.poll_event().await {
            LinkEvent::Rx(frame) => assert_eq!(frame.bytes, b"hello-datagram"),
            other => panic!("expected Rx, got {other:?}"),
        }
        drop(a_out);
        let _ = a_writer.into_join().await;
    }

    /// R311y382 — the F1 DISCRIMINATOR: the demux keys faces by SOURCE, so two
    /// senders to one listener yield two DISTINCT face channels and each face
    /// receives ONLY its own src's datagrams (no cross-talk). Under the
    /// pre-demux shared-`recv_from` model (the single-shot `wire_udp_socket`
    /// path), both faces would read the same socket and sender-2's datagram
    /// would land in face-1 — so this asserts exactly what the demux fixes.
    /// RED-witnessed by wiring the faces through `wire_udp_socket` (shared
    /// recv_from) instead of the demux channel (the cross-talk foil).
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn udp_demux_isolates_two_peers_by_src() {
        let listen: SocketAddr = "127.0.0.1:0".parse().expect("listen addr");
        let mut demux = bind_udp_demux(listen, None).await.expect("bind demux");
        let addr = demux.local_addr();

        let s1 = UdpSocket::bind("127.0.0.1:0").await.expect("bind s1");
        let s2 = UdpSocket::bind("127.0.0.1:0").await.expect("bind s2");
        let s1_addr = s1.local_addr().expect("s1 addr");
        let s2_addr = s2.local_addr().expect("s2 addr");
        assert_ne!(s1_addr, s2_addr, "two distinct source ports");

        // First src -> first face (its first datagram queued on the channel).
        s1.send_to(b"from-s1-a", addr).await.expect("s1 send a");
        let face1 = demux.recv_new_face().await.expect("face1");
        assert_eq!(face1.peer, s1_addr, "face1 keyed on s1's source");

        // Second src -> a SECOND face (the F2 mechanism at the pipeline level:
        // not an Err, a real second face).
        s2.send_to(b"from-s2-a", addr).await.expect("s2 send a");
        let face2 = demux.recv_new_face().await.expect("face2");
        assert_eq!(face2.peer, s2_addr, "face2 keyed on s2's source");

        // A follow-up datagram from each src.
        s1.send_to(b"from-s1-b", addr).await.expect("s1 send b");
        s2.send_to(b"from-s2-b", addr).await.expect("s2 send b");

        let mut f1 = face1.inbound_rx;
        let mut f2 = face2.inbound_rx;
        // face1 sees ONLY s1's datagrams, in order (the queued first + the
        // follow-up) — never s2's (the cross-talk the demux kills).
        assert_eq!(f1.recv().await.as_deref(), Some(b"from-s1-a".as_slice()));
        assert_eq!(f1.recv().await.as_deref(), Some(b"from-s1-b".as_slice()));
        // face2 sees ONLY s2's datagrams.
        assert_eq!(f2.recv().await.as_deref(), Some(b"from-s2-a".as_slice()));
        assert_eq!(f2.recv().await.as_deref(), Some(b"from-s2-b".as_slice()));
    }

    /// R311y382 — a face whose read side is DROPPED is REAPED from the pump's
    /// face map on its next datagram (best-effort, no dead-sender retention),
    /// and a subsequent datagram from the SAME src opens a FRESH face (a
    /// reconnect). Guards the `TrySendError::Closed` reap arm of the pump.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn udp_demux_reaps_a_dropped_face_and_reaccepts_the_src() {
        let listen: SocketAddr = "127.0.0.1:0".parse().expect("listen addr");
        let mut demux = bind_udp_demux(listen, None).await.expect("bind demux");
        let addr = demux.local_addr();

        let s1 = UdpSocket::bind("127.0.0.1:0").await.expect("bind s1");
        let s1_addr = s1.local_addr().expect("s1 addr");

        s1.send_to(b"hello-1", addr).await.expect("s1 send 1");
        let face1 = demux.recv_new_face().await.expect("face1");
        assert_eq!(face1.peer, s1_addr);
        // Drop the face's receiver — the read side is gone.
        drop(face1);

        // The next datagram to the dead face hits TrySendError::Closed -> the
        // pump reaps the entry, then the one AFTER it opens a fresh face for the
        // same src. Send two so the reap and the re-accept are distinct events.
        s1.send_to(b"reap-trigger", addr)
            .await
            .expect("s1 reap send");
        s1.send_to(b"hello-2", addr).await.expect("s1 send 2");
        let face1b = demux.recv_new_face().await.expect("re-accepted face");
        assert_eq!(face1b.peer, s1_addr, "same src re-accepted as a fresh face");
    }
}
