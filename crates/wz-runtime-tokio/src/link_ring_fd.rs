// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! R2750 — THE QUESTION EVERY STREAM READ HALF MUST ANSWER.
//!
//! ## Why this trait exists rather than a match on a scheme
//!
//! `crate::uring_reactor` built a second read body and could not be reached:
//! its own module doc records the gap as "the read half would have to answer
//! 'do my bytes have a raw fd' the way upstream makes every link answer
//! `get_fd`". This is that question, asked of the half rather than of the link,
//! because the half is where the answer lives — after a split it is the reader
//! that still holds (or no longer holds) the descriptor.
//!
//! Upstream's shape, read rather than invented:
//! `io/zenoh-link-commons/src/unicast.rs` @ `fn get_fd(&self) -> ZResult<RawFd>;`
//! is a REQUIRED method on `LinkUnicastTrait` — no default body — so a new link
//! cannot compile without stating its answer, and ten links state one. It is
//! itself gated (`#[cfg(all(feature = "uring", target_os = "linux"))]`), and
//! each implementor repeats that gate over its own method. [`RingReadable`]
//! mirrors that method-for-method: the trait is unconditional so the bound on
//! [`crate::stream_link::StreamReadDriver`] can be spelled once, and the METHOD
//! carries the gate, so off the ring build the question is not asked at all.
//!
//! ## `Option`, not a `Result`
//!
//! Upstream's negative arm carries a message (`bail!("Not supported")`), and
//! upstream's only caller is `link.link.get_fd().is_ok()` — the message is
//! never read. A predicate whose negative arm informs nobody is an `Option`,
//! and the REASON for each `None` belongs where a reader will meet it, which is
//! the doc comment on the impl.
//!
//! ## What answers what, against upstream's own link
//!
//! | reader half | here | upstream's link | framing |
//! |---|---|---|---|
//! | `tokio::net::tcp::OwnedReadHalf` | `Some` | tcp `Ok` | stream |
//! | `tokio::net::unix::OwnedReadHalf` | `Some` | unixsock_stream `Ok` | stream |
//! | [`crate::unixpipe_pipeline::FifoReadEnd`] | `Some` | unixpipe `Ok` | stream |
//! | [`crate::vsock_pipeline::VsockReadHalf`] | `Some` | vsock `Ok` | stream |
//! | `tokio::net::UdpSocket`, connected (a dialed udp link) | `Some` | udp `Connected` `Ok` | datagram |
//! | `tokio::net::UdpSocket`, unconnected | `None` | udp `Unconnected` `bail!` | — |
//! | `quinn::RecvStream` | `None` | quic `bail!` | — |
//! | `ReadHalf<TlsStream<TcpStream>>` | `None` | tls `bail!` | — |
//!
//! The framing column is which body `crate::uring_reactor` cuts the link's
//! completions with: length-prefixed frames through its window for a stream,
//! one frame per completion for a datagram (that module's "Two framings"). An
//! accepted udp face has no row: it reads the listener's shared socket through
//! the accept demux and never holds a socket of its own to answer for, which
//! is the case upstream's unconnected arm refuses.
//!
//! Every row agrees with upstream. ⚠ R2751 CORRECTED THE VSOCK ROW, and the
//! correction is kept visible because the reasoning that produced the wrong one
//! is the reusable part: this table used to read
//! `tokio::io::ReadHalf<T> (tls, vsock) | None`, justified as "the fd is
//! unreachable by construction, a property of the SPLIT and not of vsock". The
//! premise was true and the conclusion was still wrong — a vsock socket HAS a
//! descriptor, and answering for it from a rule written over `ReadHalf<T>` is
//! what hid that. See the note above the tls impl.
//!
//! ## UDP, and why it is a row with its own framing
//!
//! Upstream's udp unicast link answers `Ok` for its connected variant and
//! refuses the unconnected one (`io/zenoh-links/zenoh-link-udp/src/unicast.rs`
//! @ `fn get_fd`), and dispatches a link whose `is_streamed` is false to a body
//! that hands each completion up whole (`setup_read`, where a stream gets
//! `setup_fragmented_read`). This table once left udp out on the argument that
//! the ring body reads LENGTH-PREFIXED bytes through
//! [`crate::link_rx_window::RxWindow`] and a datagram has none, and that
//! reaching udp needed upstream's multishot, provided-buffer receive. The first
//! half was right and is why the datagram row has its own framing; the second
//! was not: what a datagram needs is that one completion is one frame, which a
//! fixed read of a datagram socket already gives, and the multishot shape is
//! what upstream's always-armed push model needs, not what a datagram needs
//! (`crate::uring_reactor`'s "Why not upstream's multishot receive").
//!
//! The answer is the SOCKET'S, as the stream rows' are the half's: a udp link's
//! read driver holds the socket itself, since a datagram socket is not split.
//! It is `Some` only for a connected socket, which is upstream's line and for
//! the same reason: an unconnected socket receives from every peer, and only
//! the demultiplexing by source that a read through the ring would bypass
//! decides which link a datagram belongs to.

#[cfg(all(
    feature = "runtime-tokio-uring",
    feature = "transport-link-tcp",
    target_os = "linux"
))]
use std::os::fd::AsRawFd;
#[cfg(all(
    feature = "runtime-tokio-uring",
    feature = "transport-link-tcp",
    target_os = "linux"
))]
use std::os::fd::RawFd;

/// Can the kernel read this half's bytes into a registered buffer, and through
/// which descriptor?
///
/// The method is REQUIRED — deliberately no default body, which is the whole
/// mechanism. `crate::stream_link::StreamReadDriver` bounds its reader
/// parameter on this trait, so a new stream link reaches the tree only by
/// stating its answer, exactly as upstream's `get_fd` makes a new
/// `LinkUnicastTrait` implementor state one. A default of `None` would let a
/// half that DOES have a descriptor be silently left off the ring, which is the
/// failure this trait exists to make impossible.
pub trait RingReadable {
    /// The descriptor a ring may submit reads against, or `None` when this half
    /// has none to give.
    ///
    /// The fd is BORROWED for as long as the half is alive — the caller must
    /// not close it, and anything holding it must not outlive the half. That is
    /// the contract `crate::uring_reactor::UringReactor::attach` documents, and
    /// it is upheld the same way: the driver owns the half and the ring body
    /// together.
    #[cfg(all(
        feature = "runtime-tokio-uring",
        feature = "transport-link-tcp",
        target_os = "linux"
    ))]
    fn ring_fd(&self) -> Option<RawFd>;
}

/// TCP's owned read half — `Some`, read through `AsRef<TcpStream>`.
///
/// `into_split` hands both halves an `Arc<TcpStream>` and tokio exposes it as
/// `AsRef`, so the descriptor survives the split. Upstream's tcp answers `Ok`
/// from the same socket for the same reason.
impl RingReadable for tokio::net::tcp::OwnedReadHalf {
    #[cfg(all(
        feature = "runtime-tokio-uring",
        feature = "transport-link-tcp",
        target_os = "linux"
    ))]
    fn ring_fd(&self) -> Option<RawFd> {
        // Upstream refuses a negative fd rather than trusting the accessor
        // (`fd if fd < 0 => bail!("FD unavailable")`), and the same guard is
        // kept here: a closed socket can still be asked.
        let fd = self.as_ref().as_raw_fd();
        (fd >= 0).then_some(fd)
    }
}

/// ⛔ R2751 — THERE IS NO BLANKET `impl<T> RingReadable for ReadHalf<T>` HERE
/// ANY MORE, and its removal is the point rather than a tidy-up.
///
/// R2750 wrote one, reasoning that `tokio::io::ReadHalf` publishes no accessor
/// so the answer is `None` whatever `T` is. That reasoning is true about
/// `ReadHalf` and FALSE as an answer about the LINK: it made the blanket a
/// default body in everything but name — the very thing [`RingReadable`]'s own
/// doc says must not exist, three paragraphs up — and vsock is the proof. A
/// vsock socket HAS a descriptor (`tokio_vsock::VsockStream: AsRawFd`); it was
/// reported as having none because this impl answered on its behalf, and the
/// atom's parity gap with upstream's vsock link followed from that and not from
/// anything about vsock.
///
/// A half that cannot reach its descriptor is free to say so — `None` is a real
/// answer. What it may not do is have that said FOR it by a rule written over a
/// type constructor, because the next `ReadHalf<T>` link is then answered before
/// anyone looks at it. Each instantiation states its own answer below.
///
/// TLS — `None`, and not merely because `ReadHalf` hides the socket: reading the
/// raw descriptor would take the bytes BENEATH the TLS record layer, which is
/// ciphertext and not this link's frames. Upstream reaches the same answer for
/// the same reason (`io/zenoh-links/zenoh-link-tls/src/unicast.rs` @ `fn get_fd`
/// is `bail!("Correct FD unavailable for TLS extension")`). So this one would be
/// `None` even if the accessor existed, which is exactly why it is written out.
#[cfg(feature = "transport-link-tls")]
impl RingReadable for tokio::io::ReadHalf<tokio_rustls::TlsStream<tokio::net::TcpStream>> {
    #[cfg(all(
        feature = "runtime-tokio-uring",
        feature = "transport-link-tcp",
        target_os = "linux"
    ))]
    fn ring_fd(&self) -> Option<RawFd> {
        None
    }
}

/// A UDP socket — `Some` when it is CONNECTED, `None` when it is not.
///
/// Connected is asked of the socket (`peer_addr`), not assumed from the path
/// that built it: a dialed udp link connects its socket, and a socket handed
/// to the same read driver unconnected (a scouting socket, a test that wires
/// two bound sockets) receives from any peer and must stay off the ring.
/// Upstream's guard on the descriptor is kept beside it, as on the tcp row.
#[cfg(feature = "transport-link-udp")]
impl RingReadable for tokio::net::UdpSocket {
    #[cfg(all(
        feature = "runtime-tokio-uring",
        feature = "transport-link-tcp",
        target_os = "linux"
    ))]
    fn ring_fd(&self) -> Option<RawFd> {
        if self.peer_addr().is_err() {
            return None;
        }
        let fd = self.as_raw_fd();
        (fd >= 0).then_some(fd)
    }
}

/// An in-memory duplex pipe — `None`. It is not a socket and has no descriptor;
/// the tests that frame over one exercise the framed body, which is what they
/// are testing.
impl RingReadable for tokio::io::DuplexStream {
    #[cfg(all(
        feature = "runtime-tokio-uring",
        feature = "transport-link-tcp",
        target_os = "linux"
    ))]
    fn ring_fd(&self) -> Option<RawFd> {
        None
    }
}

#[cfg(all(
    test,
    feature = "transport-link-udp",
    feature = "runtime-tokio-uring",
    target_os = "linux"
))]
mod tests {
    use super::*;

    /// The udp row: a connected socket names its descriptor, the same socket
    /// before it is connected names none. CONTROL: drop the `peer_addr`
    /// question and the unconnected leg reds with the descriptor.
    #[tokio::test]
    async fn a_udp_socket_names_its_descriptor_only_once_connected() {
        let peer = tokio::net::UdpSocket::bind("127.0.0.1:0")
            .await
            .expect("bind");
        let socket = tokio::net::UdpSocket::bind("127.0.0.1:0")
            .await
            .expect("bind");
        assert_eq!(
            socket.ring_fd(),
            None,
            "an unconnected socket receives from every peer"
        );
        socket
            .connect(peer.local_addr().expect("address"))
            .await
            .expect("connect");
        assert_eq!(socket.ring_fd(), Some(socket.as_raw_fd()));
    }
}
