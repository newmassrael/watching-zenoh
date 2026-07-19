// SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! R311y10 — Unix named-pipe (FIFO) session-open transport pipeline (Linux).
//!
//! The FIFO sibling of [`crate::unixsock_pipeline`] (AF_UNIX stream). zenoh's
//! `zenoh-link-unixpipe` carries a zenoh batch over a PAIR of named FIFOs (one
//! per direction) — a same-host link kind distinct from the AF_UNIX `unixsock`
//! socket. Where zenoh hand-rolls the FIFO I/O over the `unix_named_pipe` crate
//! + a manual `AsyncFd` loop + a multi-client Invitation handshake, wz uses
//! tokio's NATIVE named-pipe support ([`tokio::net::unix::pipe`]): a
//! [`Sender`](tokio::net::unix::pipe::Sender) is `AsyncWrite` and a
//! [`Receiver`](tokio::net::unix::pipe::Receiver) is `AsyncRead`, so the FIFO
//! link reuses the transport-neutral StreamEnvelope drivers in
//! [`crate::stream_link`] UNCHANGED (a FIFO is a reliable byte stream —
//! `is_streamed`, MTU `BatchSize::MAX`), exactly like the AF_UNIX stream. No
//! `unix_named_pipe` crate, no `advisory-lock`, no `AsyncFd` dance — only a
//! one-call `libc::mkfifo` to create the rendezvous nodes.
//!
//! ## Two FIFOs, the narrow single-connection seam
//!
//! A FIFO is UNIDIRECTIONAL, so a bidirectional link needs a PAIR:
//! - `{path}_uplink`   — the dialer WRITES, the acceptor READS.
//! - `{path}_downlink` — the acceptor WRITES, the dialer READS.
//!
//! [`bind_unixpipe`] `mkfifo`s both; [`dial_unixpipe`] / [`accept_unixpipe_on`]
//! open their `(receiver, sender)` ends. Like [`crate::unixsock_pipeline`]'s
//! narrow seam, this is a SINGLE-connection dial/accept — the per-connection
//! dedicated-pipe rendezvous zenoh's multi-client `UnicastPipeListener`
//! performs is out of this seam's scope (a future acceptor LinkManager, the
//! same extension point the other non-tcp transports document).
//!
//! ## Linux-only (the `read_write` rendezvous)
//!
//! `pipe::OpenOptions::open_sender` fails with `ENXIO` if no reader has the FIFO
//! open yet — an open-ordering race. tokio's `read_write(true)` (open the sender
//! O_RDWR so it is its own reader) liquidates the race, but that knob is
//! `target_os = "linux"`-gated in tokio. So this backend is Linux-only (the
//! `transport-link-unixpipe` mod is gated `all(feature, target_os = "linux")`),
//! consistent with the [`crate::vsock_pipeline`] Linux-only precedent and the
//! LAYER-1 = Linux-host scope; a macOS FIFO port is a track-2 follow-up. A
//! datagram sent before the peer opens its receiver is BUFFERED in the FIFO
//! (kernel pipe buffer), not dropped, so the open order is race-free.

use std::ffi::CString;
use std::io;
use std::sync::Arc;

use tokio::net::unix::pipe::{OpenOptions, Receiver, Sender};
use tokio::sync::mpsc;

use wz_runtime_core::Runtime;

use crate::runtime_impl::{TokioJoinHandle, TokioRuntime};
use crate::stream_link::{writer_task, StreamReadDriver, StreamWriteDriver};

/// The dialer-writes / acceptor-reads FIFO suffix (zenoh `_uplink` parity).
const UPLINK_SUFFIX: &str = "_uplink";
/// The acceptor-writes / dialer-reads FIFO suffix (zenoh `_downlink` parity).
const DOWNLINK_SUFFIX: &str = "_downlink";

/// Inbound read driver of a unixpipe link — the FIFO instantiation of the
/// shared [`StreamReadDriver`] over a tokio [`Receiver`](tokio::net::unix::pipe::Receiver)
/// (`AsyncRead`). The framing / [`crate::LinkDriver`] impl lives once in
/// [`crate::stream_link`] (a FIFO frames identically to a TCP stream — same
/// StreamEnvelope, same `poll_framed`); this alias pins the read half to the
/// FIFO receiver. [`crate::unixsock_pipeline::UnixsockReadDriver`] is the
/// AF_UNIX sibling over `UnixStream::into_split`'s owned read half.
pub type UnixpipeReadDriver = StreamReadDriver<Receiver>;

/// A connected unixpipe link: the `(receiver, sender)` FIFO-pair ends. Produced
/// by [`dial_unixpipe`] / [`accept_unixpipe_on`] and consumed by
/// [`wire_unixpipe_stream`]. Unlike a `UnixStream` (one fd split into halves),
/// the read + write halves are SEPARATE FIFOs from the start, so there is no
/// `into_split`.
pub struct UnixpipeLink {
    /// The inbound FIFO end (`AsyncRead`).
    pub receiver: Receiver,
    /// The outbound FIFO end (`AsyncWrite`).
    pub sender: Sender,
}

/// The resolved uplink/downlink FIFO paths a [`bind_unixpipe`] created — the
/// acceptor opens its ends through [`accept_unixpipe_on`].
pub struct UnixpipePaths {
    /// dialer->acceptor FIFO (`{path}_uplink`).
    pub uplink: String,
    /// acceptor->dialer FIFO (`{path}_downlink`).
    pub downlink: String,
}

fn suffixed(path: &str, suffix: &str) -> String {
    let mut s = String::with_capacity(path.len() + suffix.len());
    s.push_str(path);
    s.push_str(suffix);
    s
}

/// `mkfifo` a FIFO at `path` with mode 0o600, unlinking a stale one first (a
/// previous bind that did not clean up makes `mkfifo` fail with `EEXIST`). The
/// unixpipe analogue of [`crate::unixsock_pipeline::bind_unixsock`]'s stale-
/// socket unlink; the narrow single-owner seam unlinks unconditionally (a
/// `NotFound` is the normal first-bind case and is not an error).
///
/// R311y13 disclosure: mode 0o600 (owner-only) is a deliberate hardening over
/// zenoh's default 0o777 (world-rwx) for this same-host IPC node; wz does NOT
/// model zenoh's configurable `file_mask` locator parameter
/// (zenoh-link-unixpipe `unix/mod.rs` `FILE_ACCESS_MASK`). A tighter, fixed
/// default — a security improvement, not a regression, but a narrowing of
/// zenoh's surface recorded here for the superset-not-mirror ledger.
fn make_fifo(path: &str) -> io::Result<()> {
    match std::fs::remove_file(path) {
        Ok(()) => {}
        Err(e) if e.kind() == io::ErrorKind::NotFound => {}
        Err(e) => return Err(e),
    }
    let c_path = CString::new(path).map_err(|_| {
        io::Error::new(io::ErrorKind::InvalidInput, "fifo path has an interior NUL")
    })?;
    // SAFETY: `c_path` is a valid NUL-terminated C string live for the call;
    // `mkfifo` only reads through the pointer. 0o600 = owner read+write.
    let rc = unsafe { libc::mkfifo(c_path.as_ptr(), 0o600 as libc::mode_t) };
    if rc != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// Open the outbound FIFO `path` as a [`Sender`](tokio::net::unix::pipe::Sender)
/// in read-write mode so the open never blocks / `ENXIO`s on a not-yet-present
/// reader (the Linux `read_write` rendezvous, see the module doc).
fn open_sender_rw(path: &str) -> io::Result<Sender> {
    OpenOptions::new().read_write(true).open_sender(path)
}

/// `mkfifo` the uplink + downlink FIFO PAIR for a listening `path` — the
/// bind-side setup symmetric to the dial, so a caller (the e2e harness, a future
/// acceptor) creates the rendezvous BEFORE the dialer opens it, race-free. The
/// two FIFOs are `{path}_uplink` (dialer->acceptor) and `{path}_downlink`
/// (acceptor->dialer). The unixpipe mirror of
/// [`crate::unixsock_pipeline::bind_unixsock`] (which binds a `UnixListener`):
/// here there is no listener object — the FIFOs ARE the rendezvous — so this
/// returns the resolved [`UnixpipePaths`] the acceptor opens.
pub fn bind_unixpipe(path: &str) -> io::Result<UnixpipePaths> {
    let uplink = suffixed(path, UPLINK_SUFFIX);
    let downlink = suffixed(path, DOWNLINK_SUFFIX);
    make_fifo(&uplink)?;
    make_fifo(&downlink)?;
    Ok(UnixpipePaths { uplink, downlink })
}

/// Accept the unixpipe peer on a *bound* FIFO pair — open the acceptor's ends:
/// the inbound RECEIVER on the uplink (the dialer writes) + the outbound SENDER
/// on the downlink (the acceptor writes). The unixpipe mirror of
/// [`crate::unixsock_pipeline::accept_unixsock_on`]. Must run within a tokio
/// runtime (the FIFO ends register with the IO driver). Returns the connected
/// [`UnixpipeLink`]; no dial-time handshake, ready for the uniform split.
pub fn accept_unixpipe_on(paths: &UnixpipePaths) -> io::Result<UnixpipeLink> {
    let receiver = OpenOptions::new().open_receiver(&paths.uplink)?;
    let sender = open_sender_rw(&paths.downlink)?;
    Ok(UnixpipeLink { receiver, sender })
}

/// Dial the unixpipe link at `path` — open the dialer's ends: the inbound
/// RECEIVER on the downlink (the acceptor writes) + the outbound SENDER on the
/// uplink (the dialer writes). The narrow-seam dial primitive
/// [`crate::session_open::dial_locator`] routes a parsed `unixpipe/...` path to.
/// Must run within a tokio runtime. Returns the connected [`UnixpipeLink`].
///
/// No dial-time handshake (a FIFO open is the rendezvous), so the byte stream is
/// ready for the uniform StreamEnvelope split immediately — like tcp/unixsock.
/// The peer's [`bind_unixpipe`] must have created the FIFOs first (an `ENOENT`
/// surfaces if not), the bind/accept split every wz link seam takes.
pub fn dial_unixpipe(path: &str) -> io::Result<UnixpipeLink> {
    let uplink = suffixed(path, UPLINK_SUFFIX);
    let downlink = suffixed(path, DOWNLINK_SUFFIX);
    let receiver = OpenOptions::new().open_receiver(&downlink)?;
    let sender = open_sender_rw(&uplink)?;
    Ok(UnixpipeLink { receiver, sender })
}

/// Wire a connected [`UnixpipeLink`] into the cooperating drivers the session
/// FSM consumes: an inbound [`UnixpipeReadDriver`], an outbound
/// `Arc<`[`StreamWriteDriver`]`>`, and the [`writer_task`] join handle. The FIFO
/// read + write halves are ALREADY separate (a [`Receiver`](tokio::net::unix::pipe::Receiver)
/// / [`Sender`](tokio::net::unix::pipe::Sender), not a `UnixStream::into_split`),
/// so this is the unixsock wiring minus the split. StreamEnvelope framing + the
/// write driver are the SAME shared [`crate::stream_link`] code as TCP/unixsock.
pub fn wire_unixpipe_stream(
    link: UnixpipeLink,
) -> (
    UnixpipeReadDriver,
    Arc<StreamWriteDriver>,
    TokioJoinHandle<()>,
) {
    let UnixpipeLink { receiver, sender } = link;
    let inbound = StreamReadDriver::new(
        receiver,
        Arc::new(std::sync::atomic::AtomicBool::new(false)),
    );
    let (tx, rx) = mpsc::unbounded_channel::<Vec<u8>>();
    let writer_handle = TokioRuntime.spawn(writer_task(sender, rx));
    // transport-lowlatency is a TCP-path negotiation; other stream links keep the
    // universal u16 prefix (an always-false flag on the write driver).
    let outbound = Arc::new(StreamWriteDriver::new(
        tx,
        Arc::new(std::sync::atomic::AtomicBool::new(false)),
    ));
    (inbound, outbound, writer_handle)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::FileTypeExt;
    use std::sync::atomic::{AtomicU32, Ordering};

    use crate::{LinkDriver, LinkEvent, Reliability};
    use wz_session_core::link::BoxedLinkDriver;

    /// A unique FIFO base path under the system temp dir, unique across parallel
    /// tests via the pid + a per-process counter (no external tempfile dep).
    fn unique_pipe_base() -> String {
        static COUNTER: AtomicU32 = AtomicU32::new(0);
        let n = COUNTER.fetch_add(1, Ordering::Relaxed);
        std::env::temp_dir()
            .join(format!("wz-unixpipe-{}-{n}", std::process::id()))
            .to_string_lossy()
            .into_owned()
    }

    fn cleanup(paths: &UnixpipePaths) {
        let _ = std::fs::remove_file(&paths.uplink);
        let _ = std::fs::remove_file(&paths.downlink);
    }

    /// `bind_unixpipe` mkfifos BOTH ends of the pair, and they are genuine FIFOs
    /// (not regular files), replacing a stale node if present.
    #[test]
    fn bind_creates_fifo_pair() {
        let base = unique_pipe_base();
        let paths = bind_unixpipe(&base).expect("bind creates the fifo pair");
        for p in [&paths.uplink, &paths.downlink] {
            let ft = std::fs::metadata(p).expect("fifo exists").file_type();
            assert!(ft.is_fifo(), "{p} is a FIFO");
        }
        // A second bind over the stale nodes succeeds (unlinks first).
        let paths2 = bind_unixpipe(&base).expect("re-bind unlinks the stale fifos");
        cleanup(&paths2);
    }

    /// A wired dialer->acceptor FIFO pair carries one StreamEnvelope-framed
    /// frame end to end: the dialer's outbound `send_blocking` length-prefixes
    /// the payload through the shared writer task, the acceptor's inbound
    /// `poll_event` strips the envelope and yields the original bytes — the raw
    /// transport proof beneath the full session e2e.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn wired_pair_round_trips_a_frame() {
        let base = unique_pipe_base();
        let paths = bind_unixpipe(&base).expect("bind");
        // Open is non-blocking / O_RDWR, so dial + accept need no ordering.
        let dialer = dial_unixpipe(&base).expect("dial");
        let acceptor = accept_unixpipe_on(&paths).expect("accept");

        let (_d_in, d_out, _d_writer) = wire_unixpipe_stream(dialer);
        let (mut a_in, _a_out, _a_writer) = wire_unixpipe_stream(acceptor);

        d_out.send_blocking(b"unixpipe-hello", Reliability::Reliable);
        match a_in.poll_event().await {
            LinkEvent::Rx(frame) => assert_eq!(frame.bytes, b"unixpipe-hello"),
            other => panic!("expected Rx, got {other:?}"),
        }
        drop(d_out);
        cleanup(&paths);
    }
}
