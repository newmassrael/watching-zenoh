// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
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
//! ## What answers what, and where it diverges from upstream
//!
//! | reader half | here | upstream's link |
//! |---|---|---|
//! | `tokio::net::tcp::OwnedReadHalf` | `Some` | tcp `Ok` |
//! | `tokio::net::unix::OwnedReadHalf` | `Some` | unixsock_stream `Ok` |
//! | [`crate::unixpipe_pipeline::FifoReadEnd`] | `Some` | unixpipe `Ok` |
//! | `quinn::RecvStream` | `None` | quic `bail!` |
//! | `tokio::io::ReadHalf<T>` (tls, vsock) | `None` | tls `bail!`, vsock `Ok` |
//!
//! ⚠ ONE ROW DIVERGES AND IT IS DECLARED HERE RATHER THAN FOUND LATER: vsock.
//! Upstream answers `Ok` for it because its link owns the socket and reads
//! through a `UnsafeCell`, so a split never hides the descriptor. wz splits
//! vsock with `tokio::io::split`, whose [`tokio::io::ReadHalf`] holds the
//! stream behind a shared mutex and exposes no accessor at all — the fd is not
//! withheld by policy here, it is unreachable by construction. That is a
//! property of the SPLIT, not of vsock, which is why the impl is written over
//! `ReadHalf<T>` for every `T` rather than over the two instantiations that
//! exist today: a future stream link that splits the same way inherits the same
//! true answer instead of a stale one. Making vsock answer `Some` is a change
//! to how vsock is split, and belongs to whatever round wants vsock on the ring.

#[cfg(all(feature = "runtime-tokio-uring", feature = "transport-link-tcp"))]
use std::os::fd::AsRawFd;
#[cfg(all(feature = "runtime-tokio-uring", feature = "transport-link-tcp"))]
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
    #[cfg(all(feature = "runtime-tokio-uring", feature = "transport-link-tcp"))]
    fn ring_fd(&self) -> Option<RawFd>;
}

/// TCP's owned read half — `Some`, read through `AsRef<TcpStream>`.
///
/// `into_split` hands both halves an `Arc<TcpStream>` and tokio exposes it as
/// `AsRef`, so the descriptor survives the split. Upstream's tcp answers `Ok`
/// from the same socket for the same reason.
impl RingReadable for tokio::net::tcp::OwnedReadHalf {
    #[cfg(all(feature = "runtime-tokio-uring", feature = "transport-link-tcp"))]
    fn ring_fd(&self) -> Option<RawFd> {
        // Upstream refuses a negative fd rather than trusting the accessor
        // (`fd if fd < 0 => bail!("FD unavailable")`), and the same guard is
        // kept here: a closed socket can still be asked.
        let fd = self.as_ref().as_raw_fd();
        (fd >= 0).then_some(fd)
    }
}

/// Anything split with [`tokio::io::split`] — `None`, by construction.
///
/// [`tokio::io::ReadHalf`] keeps the stream behind a shared lock and publishes
/// no accessor, so there is no descriptor to hand out whatever `T` is. Written
/// over every `T` on purpose: see this module's divergence note. tls and vsock
/// are today's instantiations.
impl<T> RingReadable for tokio::io::ReadHalf<T> {
    #[cfg(all(feature = "runtime-tokio-uring", feature = "transport-link-tcp"))]
    fn ring_fd(&self) -> Option<RawFd> {
        None
    }
}

/// An in-memory duplex pipe — `None`. It is not a socket and has no descriptor;
/// the tests that frame over one exercise the framed body, which is what they
/// are testing.
impl RingReadable for tokio::io::DuplexStream {
    #[cfg(all(feature = "runtime-tokio-uring", feature = "transport-link-tcp"))]
    fn ring_fd(&self) -> Option<RawFd> {
        None
    }
}
