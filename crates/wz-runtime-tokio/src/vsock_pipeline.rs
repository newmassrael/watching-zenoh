// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! R311xj — AF_VSOCK (VM<->host / VM<->VM) session-open transport pipeline.
//!
//! The vsock sibling of [`crate::link_pipeline`] (TCP) / [`crate::unixsock_pipeline`].
//! A vsock connection IS a reliable byte stream — `is_streamed() = true`,
//! `is_reliable() = true`, MTU `BatchSize::MAX` (zenoh's `VSOCK_DEFAULT_MTU`,
//! `io/zenoh-links/zenoh-link-vsock/src/{lib,unicast}.rs`) — so it reuses the
//! transport-neutral byte-stream machinery in [`crate::stream_link`] UNCHANGED:
//! the [`StreamReadDriver`] StreamEnvelope framing `LinkDriver` impl, the
//! [`StreamWriteDriver`] channel, and the
//! [`writer_task`](crate::stream_link::writer_task).
//!
//! Unlike TCP / unixsock (whose `into_split` yields owned halves), a
//! [`tokio_vsock::VsockStream`] has no owned-half split, so this module splits
//! it with [`tokio::io::split`] — exactly the shape [`crate::tls_pipeline`]
//! uses for its un-owned `TlsStream`. Otherwise the StreamEnvelope wire is the
//! SAME shared code: vsock is "TCP addressed by `(cid, port)` instead of
//! `ip:port`", with no filesystem artifact (UNLIKE unixsock — no socket file,
//! no lock-file lifecycle; `VsockListener::bind` is clean like `TcpListener`).
//!
//! ## Linux-only
//!
//! AF_VSOCK is a Linux socket family, so this whole module is
//! `#[cfg(all(feature = "transport-link-vsock", target_os = "linux"))]` (the
//! same platform gate zenoh-link-vsock carries) and pulls the Linux-only,
//! optional [`tokio_vsock`] dep. The `vsock/<CID>:<PORT>` LOCATOR parse is
//! platform-independent and lives ungated in
//! [`wz_session_core::locator`] — only this dial/accept BACKEND is gated. Off
//! Linux (or with the feature off) a `vsock/...` locator dials to a typed
//! `Unsupported` in [`crate::session_open::dial_locator`], like serial/udp.
//!
//! [`dial_vsock`] is the PRIMITIVE [`crate::session_open::dial_locator`] builds
//! on; [`wire_vsock_stream`] produces the
//! [`crate::session_open::DialedLink::Vsock`] split.

use std::io;
use std::sync::Arc;

use tokio::io::{split, ReadHalf};
use tokio::sync::mpsc;
use tokio_vsock::{VsockAddr, VsockListener, VsockStream};

use crate::link_interfaces::{addressless_link_endpoints, addressless_link_subject};
use crate::stream_link::{writer_task, StreamReadDriver, StreamWriteDriver};
use crate::writer_queue::WriterHandle;
use wz_session_core::link::InterceptorLink;

/// R2751 — vsock's read half, which REMEMBERS ITS DESCRIPTOR.
///
/// A `tokio::io::ReadHalf<VsockStream>` cannot answer "do my bytes have a raw
/// fd": it keeps the stream behind a shared lock and publishes no accessor. The
/// socket HAS one — `VsockStream: AsRawFd` — so the descriptor is unreachable
/// through the half, not absent. This type is the half that reaches it: the fd
/// is read off the stream BEFORE [`tokio::io::split`] consumes it, and carried
/// beside the half that keeps it open.
///
/// Upstream's vsock link answers `Ok` for exactly this reason — it keeps the
/// socket itself and reads `as_raw_fd()` off it
/// (`io/zenoh-links/zenoh-link-vsock/src/unicast.rs` @ `fn get_fd`). Before this
/// type, wz's answer was `None`, and the whole of `runtime-tokio-uring`'s
/// remaining divergence from upstream was that one wrong answer.
///
/// LIFETIME, which is what makes carrying a raw fd sound here rather than a
/// dangling-pointer waiting to happen: [`tokio::io::split`] gives both halves an
/// `Arc` on the stream, so the socket — and its descriptor — lives exactly as
/// long as this half does. That is the same contract
/// [`crate::uring_reactor::UringReactor::attach`] documents ("the caller's
/// reader half keeps it open"), upheld the same way TCP upholds it: the driver
/// owns the half and the ring body together.
pub struct VsockReadHalf {
    inner: ReadHalf<VsockStream>,
    fd: std::os::fd::RawFd,
}

impl tokio::io::AsyncRead for VsockReadHalf {
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<io::Result<()>> {
        std::pin::Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

/// vsock's answer: `Some`, from the descriptor captured before the split.
impl crate::link_ring_fd::RingReadable for VsockReadHalf {
    #[cfg(all(feature = "runtime-tokio-uring", feature = "transport-link-tcp"))]
    fn ring_fd(&self) -> Option<std::os::fd::RawFd> {
        // Upstream refuses a negative fd rather than trusting the accessor
        // (`fd if fd < 0 => bail!("FD unavailable")`); the same guard is kept.
        (self.fd >= 0).then_some(self.fd)
    }
}

/// Inbound read driver of a split [`VsockStream`] — the vsock instantiation of
/// the shared [`StreamReadDriver`]. The framing / [`crate::LinkDriver`] impl
/// lives once in [`crate::stream_link`] (a vsock link frames identically to TCP
/// — same StreamEnvelope, same `poll_framed`); this alias pins the stream half
/// to [`VsockReadHalf`].
///
/// ⚠ R2751 — THE REASON THIS MODULE USED TO GIVE FOR RIDING `ReadHalf` WAS
/// FALSE, and it is corrected rather than quietly dropped: it said "no
/// owned-half split exists". `tokio_vsock` 0.5.0 HAS `VsockStream::into_split`.
/// The CHOICE still stands, because that crate's own `OwnedReadHalf` holds the
/// stream behind a `tokio::sync::Mutex` and so yields a descriptor no more
/// readily than `tokio::io::split` does — but the choice now rests on what was
/// measured instead of on a capability that exists.
pub type VsockReadDriver = StreamReadDriver<VsockReadHalf>;

/// Dial an outbound AF_VSOCK connection to `(cid, port)` — the raw-dial
/// primitive the mode-agnostic `dial_locator(AnyLocator::Vsock)` dispatcher
/// (R311xj) routes a parsed [`wz_session_core::locator::VsockEndpoint`] to.
/// Returns the connected [`VsockStream`] unwrapped so the caller chooses its
/// consumption shape ([`wire_vsock_stream`] for the session-open split).
///
/// No per-link tuning: a vsock socket has no Nagle / TCP options (the TCP
/// path's `configure_tcp_stream` has no vsock analogue) — mirroring zenoh's
/// `VsockStream::connect` with no extra socket setup (`unicast.rs`, `new_link`).
pub async fn dial_vsock(cid: u32, port: u32) -> io::Result<VsockStream> {
    VsockStream::connect(VsockAddr::new(cid, port)).await
}

/// Bind an AF_VSOCK listener at `(cid, port)` — the accept-side "listen half"
/// symmetric to dial's [`dial_vsock`], so a caller (the e2e harness, a future
/// acceptor) observes the bound listener BEFORE the blocking accept, race-free,
/// the same split [`crate::link_pipeline::bind_tcp`] established.
///
/// UNLIKE [`crate::unixsock_pipeline::bind_unixsock`], there is NO stale-file
/// cleanup: vsock leaves no filesystem artifact (`VsockListener::bind` is clean
/// like `TcpListener::bind`, zenoh `new_listener`). Binding `port =
/// VMADDR_PORT_ANY` lets the kernel assign an ephemeral port, readable via
/// `listener.local_addr()` (the race-free port-learn the dial side then targets).
pub fn bind_vsock(cid: u32, port: u32) -> io::Result<VsockListener> {
    VsockListener::bind(VsockAddr::new(cid, port))
}

/// Accept ONE inbound connection from a mutably-borrowed [`VsockListener`],
/// returning the accepted [`VsockStream`] — the vsock mirror of
/// [`crate::link_pipeline::accept_tcp_on`]. Takes `&mut` (NOT `&` like the TCP /
/// unixsock acceptors): `tokio_vsock::VsockListener::accept` is `&mut self`,
/// not `&self`, so the borrow follows the upstream API. A multi-peer acceptor
/// still loops over the one listener it owns (exclusive `&mut` across accepts).
/// The peer [`VsockAddr`] is discarded (no routing identity worth threading
/// here; the session learns the peer zid from the handshake, as for every
/// transport). No per-link tuning.
pub async fn accept_vsock_on(listener: &mut VsockListener) -> io::Result<VsockStream> {
    let (stream, _peer) = listener.accept().await?;
    Ok(stream)
}

/// Split a connected [`VsockStream`] into the cooperating drivers the session
/// FSM consumes: an inbound [`VsockReadDriver`] (`&mut LinkDriver` for the poll
/// loop), an outbound `Arc<`[`StreamWriteDriver`]`>` (`BoxedLinkDriver` for
/// `send_blocking`), and the [`writer_task`](crate::stream_link::writer_task)
/// join handle. Mirrors [`crate::tls_pipeline::wire_tls_stream`] — a vsock
/// stream is split with [`tokio::io::split`] (no owned-half split) but
/// otherwise the StreamEnvelope framing + write driver are the SAME shared
/// [`crate::stream_link`] code.
pub fn wire_vsock_stream(
    stream: VsockStream,
) -> (VsockReadDriver, Arc<StreamWriteDriver>, WriterHandle) {
    // R311y473 — the adminspace `{src,dst}` pair, rendered in wz's OWN vsock
    // locator form `vsock/<CID>:<PORT>` (module doc) so an admin client reads back
    // a string it could dial, not a Debug rendering of the address struct.
    let endpoints = match (stream.local_addr().ok(), stream.peer_addr().ok()) {
        (Some(local), Some(peer)) => Some(addressless_link_endpoints(
            InterceptorLink::Vsock,
            &format!("{}:{}", local.cid(), local.port()),
            &format!("{}:{}", peer.cid(), peer.port()),
        )),
        _ => None,
    };
    // R2751 — the descriptor is read BEFORE the split, because that is the last
    // moment the stream is reachable: `split` consumes it into an `Arc` neither
    // half publishes. See `VsockReadHalf` for why it is sound to carry.
    let fd = {
        use std::os::fd::AsRawFd;
        stream.as_raw_fd()
    };
    let (reader, writer) = split(stream);
    let inbound = StreamReadDriver::new(
        VsockReadHalf { inner: reader, fd },
        Arc::new(std::sync::atomic::AtomicBool::new(false)),
    );
    let (tx, rx) = mpsc::unbounded_channel::<Vec<u8>>();
    let writer_handle = WriterHandle::spawn(rx, |queue| writer_task(writer, queue));
    // transport-lowlatency is a TCP-path negotiation; other stream links keep the
    // universal u16 prefix (an always-false flag on the write driver).
    let outbound = Arc::new(StreamWriteDriver::new(
        tx,
        Arc::new(std::sync::atomic::AtomicBool::new(false)),
        // R2548 — the pseudo-interface upstream names for this link, as a
        // LITERAL rather than as `InterceptorLink::Vsock`'s scheme string: the
        // two happen to coincide, and deriving one from the other would assert
        // a coupling upstream does not have (its sibling addressless links name
        // no interface at all).
        // `io/zenoh-links/zenoh-link-vsock/src/unicast.rs` @ `vec!["vsock".to_string()]`.
        // Without it an ACL narrowed by
        // `interfaces` -- the spelling a zenoh-authored config uses to target a
        // vsock link -- matches nothing here.
        addressless_link_subject(InterceptorLink::Vsock, vec!["vsock".to_string()]),
        endpoints,
    ));
    (inbound, outbound, writer_handle)
}

#[cfg(test)]
mod tests {
    use super::*;
    use wz_session_core::locator::{VMADDR_CID_LOCAL, VMADDR_PORT_ANY};

    /// `bind_vsock` + `accept_vsock_on` + `dial_vsock` complete a loopback
    /// connection over `VMADDR_CID_LOCAL` — the vsock mirror of the unixsock /
    /// TCP round-trip.
    ///
    /// `#[ignore]`: AF_VSOCK loopback needs the `vsock_loopback` kernel module
    /// (`VMADDR_CID_LOCAL`), which is absent in the default dev/CI sandbox
    /// (no `/dev/vsock`). This runs on a vsock-capable host via
    /// `cargo test --features transport-link-vsock -- --ignored` — the same
    /// environment-gated shape the Layer Z cross-impl tests use. The data path
    /// it would exercise (StreamEnvelope over the split stream) is already
    /// proven by the TCP / TLS / unixsock lanes; this asserts the
    /// vsock-specific bind/accept/dial wiring on a host that supports it.
    #[tokio::test]
    #[ignore = "needs AF_VSOCK loopback (vsock_loopback kernel module); run with --ignored on a vsock-capable host"]
    async fn bind_accept_dial_round_trip_on_cid_local() {
        let mut listener =
            bind_vsock(VMADDR_CID_LOCAL, VMADDR_PORT_ANY).expect("bind vsock loopback listener");
        let port = listener.local_addr().expect("bound local addr").port();
        let client = tokio::spawn(async move { dial_vsock(VMADDR_CID_LOCAL, port).await });
        let _server = accept_vsock_on(&mut listener)
            .await
            .expect("accept one peer");
        let _client_stream = client.await.expect("client task").expect("client connect");
    }

    /// R2751 — a WIRED vsock link can name its descriptor, so the ring can read
    /// it. Upstream's vsock answers `Ok` and wz's answered `None`; this is the
    /// assertion that they now agree.
    ///
    /// The fd is asserted to be the SOCKET's, not merely non-negative: a
    /// capture that read the wrong thing (the listener, a stale dup) would pass
    /// a `>= 0` check and fail this one. `dial_vsock`'s own stream is the
    /// ground truth, taken before `wire_vsock_stream` consumes it.
    ///
    /// ⚠ `#[ignore]` FOR THE SAME REASON AS ITS TWO SIBLINGS ABOVE, and the
    /// consequence is stated rather than glossed: AF_VSOCK loopback needs the
    /// `vsock_loopback` module, so NO lane in the default sandbox runs this and
    /// this round's vsock claim is NOT witnessed by an executing test here. It
    /// runs on a vsock-capable host (`--ignored`, Layer C1ab). What guards the
    /// claim in the meantime is a COMPILE-TIME fact rather than this test:
    /// R2751 deleted the blanket `impl<T> RingReadable for ReadHalf<T>`, so
    /// vsock's half has no answer unless one is written for it, and reverting
    /// [`VsockReadHalf`] fails the build instead of silently answering `None`
    /// again — which is exactly how the gap arose.
    #[cfg(all(feature = "runtime-tokio-uring", feature = "transport-link-tcp"))]
    #[tokio::test]
    #[ignore = "needs AF_VSOCK loopback (vsock_loopback kernel module); run with --ignored on a vsock-capable host"]
    async fn a_wired_vsock_half_names_its_descriptor() {
        use std::os::fd::AsRawFd;

        let mut listener =
            bind_vsock(VMADDR_CID_LOCAL, VMADDR_PORT_ANY).expect("bind vsock loopback listener");
        let port = listener.local_addr().expect("bound local addr").port();
        let client = tokio::spawn(async move { dial_vsock(VMADDR_CID_LOCAL, port).await });
        let server = accept_vsock_on(&mut listener)
            .await
            .expect("accept one peer");
        let _client_stream = client.await.expect("client task").expect("client connect");

        let expected = server.as_raw_fd();
        let (inbound, _outbound, _writer) = wire_vsock_stream(server);
        assert_eq!(
            inbound.reader_ring_fd(),
            Some(expected),
            "a vsock half must hand the ring the socket's own descriptor"
        );
    }

    /// R2548 — a WIRED vsock link names the pseudo-interface upstream names.
    ///
    /// `io/zenoh-links/zenoh-link-vsock/src/unicast.rs` @ `vec!["vsock".to_string()]`
    /// is the only one of upstream's four ADDRESSLESS links that names an
    /// interface at
    /// all (serial reports tty device names; unixsock and unixpipe each report
    /// none and say "not supported"). wz used to report a definite-empty set for
    /// all four, which is true of the wire and wrong about upstream: an ACL
    /// narrowed by `interfaces` — the spelling a zenoh-authored config uses to
    /// target a vsock link — matched nothing here while matching there.
    ///
    /// The expectation is a LITERAL, not `InterceptorLink::Vsock`'s scheme
    /// string: comparing the emitted name against the constant the producer
    /// reads would hold for every value it could take, which is the tautology
    /// R2470 had to repair on the attachment ext's Del id.
    ///
    /// `#[ignore]` for the same reason as its sibling above — it needs a real
    /// AF_VSOCK pair — and run by Layer C1ab wherever `/dev/vsock` exists.
    #[tokio::test]
    #[ignore = "needs AF_VSOCK loopback (vsock_loopback kernel module); run with --ignored on a vsock-capable host"]
    async fn wired_link_subject_names_the_vsock_pseudo_interface() {
        use wz_session_core::link::BoxedLinkDriver;

        let mut listener =
            bind_vsock(VMADDR_CID_LOCAL, VMADDR_PORT_ANY).expect("bind vsock loopback listener");
        let port = listener.local_addr().expect("bound local addr").port();
        let client = tokio::spawn(async move { dial_vsock(VMADDR_CID_LOCAL, port).await });
        let server = accept_vsock_on(&mut listener)
            .await
            .expect("accept one peer");
        let _client_stream = client.await.expect("client task").expect("client connect");

        let (_inbound, outbound, _writer) = wire_vsock_stream(server);
        let subject = outbound
            .link_subject()
            .expect("the vsock pipeline states a §5.16 subject");
        assert_eq!(subject.protocol, Some(InterceptorLink::Vsock));
        assert_eq!(
            subject.interfaces.as_deref(),
            Some(&["vsock".to_string()][..]),
            "a vsock link must name the `vsock` pseudo-interface; an empty set \
             leaves an `interfaces`-narrowed rule silently not governing it",
        );
    }
}
