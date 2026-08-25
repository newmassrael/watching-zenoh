// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! R311xi — Unix-domain-stream session-open transport pipeline.
//!
//! The local-IPC sibling of [`crate::link_pipeline`] (TCP). A unix-domain
//! socket IS a byte stream — `is_streamed() = true`, `is_reliable() = true`,
//! MTU 65535 (zenoh's `UNIXSOCKSTREAM_DEFAULT_MTU = BatchSize::MAX`,
//! `io/zenoh-links/zenoh-link-unixsock_stream/src/{lib,unicast}.rs`) — so it
//! reuses the transport-neutral byte-stream machinery in
//! [`crate::stream_link`] UNCHANGED: the [`StreamReadDriver`] StreamEnvelope
//! framing `LinkDriver` impl, the [`StreamWriteDriver`] channel, and the
//! [`writer_task`](crate::stream_link::writer_task). A `UnixStream` splits with
//! [`tokio::net::UnixStream::into_split`] (OWNED halves, like `TcpStream`, NOT
//! the `tokio::io::split` that TLS needs for its un-owned `TlsStream`), so this
//! module is the TCP pipeline with `UnixStream`/`UnixListener` swapped for
//! `TcpStream`/`TcpListener` and the IP `SocketAddr` swapped for a filesystem
//! path — no new codec, no new dep (tokio's `net` feature carries the unix
//! socket types on Unix).
//!
//! ## What this module does NOT carry (the wz dial/accept seam shape)
//!
//! zenoh's `unixsock_stream` LinkManager wraps the listener in a `nix`-`flock`
//! lock-file lifecycle (`{path}.lock`) to detect + unlink STALE socket files
//! across processes safely against a still-live peer (`new_listener` /
//! `del_listener`, `unicast.rs`). wz's transport seam is deliberately narrower
//! — a dial / accept primitive over an already-CONNECTED stream, with the
//! LISTEN owned by the application / acceptor (the same shape TCP/TLS/WS take:
//! [`crate::link_pipeline`] has no listener registry and sets no
//! `SO_REUSEADDR` policy in its dial primitive). So the socket-file LIFECYCLE
//! is a listen-side concern of the caller; [`bind_unixsock`] performs only the
//! minimal stale-file unlink a fresh single-owner bind needs, and the
//! cross-process `flock` arbitration zenoh's multi-listener LinkManager
//! performs is out of this seam's scope — it would land alongside a unixsock
//! ACCEPTOR LinkManager if one is ever needed (the same "not-yet-wired
//! acceptor" extension point the other non-tcp transports document in
//! [`crate::session_open::bind_locator`]).
//!
//! [`dial_unixsock`] is the PRIMITIVE [`crate::session_open::dial_locator`]
//! builds on for a `unixsock-stream/...` locator; [`wire_unixsock_stream`]
//! produces the [`crate::session_open::DialedLink::Unixsock`] split for
//! `initiate_and_open_session` / `accept_and_open_session`.

use std::io;
use std::sync::Arc;

use tokio::net::unix::OwnedReadHalf;
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::mpsc;

use crate::link_interfaces::{addressless_link_endpoints, addressless_link_subject};
use crate::stream_link::{writer_task, StreamReadDriver, StreamWriteDriver};
use crate::writer_queue::WriterHandle;
use wz_session_core::link::InterceptorLink;

/// Inbound read driver of a split [`UnixStream`] — the unixsock instantiation
/// of the shared [`StreamReadDriver`]. The framing / [`crate::LinkDriver`]
/// impl lives once in [`crate::stream_link`] (a unix stream frames identically
/// to TCP — same StreamEnvelope, same `poll_framed`); this alias just pins the
/// stream half to the `UnixStream::into_split` owned read half.
/// [`crate::link_pipeline::TcpReadDriver`] is the TCP sibling over
/// `tokio::net::tcp::OwnedReadHalf`.
pub type UnixsockReadDriver = StreamReadDriver<OwnedReadHalf>;

/// Dial an outbound unix-domain-socket connection to `path` — the raw-dial
/// primitive the mode-agnostic `dial_locator(AnyLocator::Unixsock)` dispatcher
/// (R311xi) routes a parsed socket path to. Returns the connected [`UnixStream`]
/// unwrapped so the caller chooses its consumption shape ([`wire_unixsock_stream`]
/// for the session-open split).
///
/// No per-link tuning: a unix socket has no Nagle / TCP socket options, so the
/// TCP path's `configure_tcp_stream` (`TCP_NODELAY`) has no unixsock analogue —
/// mirroring zenoh's `UnixStream::connect` with no extra socket setup
/// (`unicast.rs`, `new_link`). Connect-timeout / retry tuning is the caller's
/// concern (compose a `tokio::time::timeout`), exactly as for [`dial_unixsock`]'s
/// TCP sibling.
pub async fn dial_unixsock(path: &str) -> io::Result<UnixStream> {
    UnixStream::connect(path).await
}

/// Bind a unix-domain listener at `path` — the accept-side "listen half"
/// symmetric to dial's [`dial_unixsock`], so a caller (the e2e harness, a
/// future acceptor) observes the bound listener BEFORE the blocking accept,
/// race-free, the same split [`crate::link_pipeline::bind_tcp`] established.
///
/// A STALE socket file (a previous bind that did not clean up) makes a fresh
/// `UnixListener::bind` fail with `EADDRINUSE`, so a stale file is unlinked
/// first. zenoh performs this under a cross-process `flock` to stay safe
/// against a LIVE peer still bound to the path; wz's narrower single-owner
/// listen seam unlinks unconditionally (a `NotFound` is the normal first-bind
/// case and is not an error), leaving the cross-process arbitration to a future
/// acceptor LinkManager (see the module doc). The unlink is the listen-side
/// counterpart of the socket-file lifecycle the caller owns.
pub async fn bind_unixsock(path: &str) -> io::Result<UnixListener> {
    match std::fs::remove_file(path) {
        Ok(()) => {}
        Err(e) if e.kind() == io::ErrorKind::NotFound => {}
        Err(e) => return Err(e),
    }
    UnixListener::bind(path)
}

/// Accept ONE inbound connection from a *borrowed* [`UnixListener`], returning
/// the accepted [`UnixStream`] — the unixsock mirror of
/// [`crate::link_pipeline::accept_tcp_on`]. Borrowing (not consuming) the
/// listener is what lets a multi-peer acceptor call this in a loop. The peer
/// address is discarded: an accepted unix-socket peer is anonymous (zenoh
/// assigns it a fresh UUID rather than a meaningful name, `unicast.rs`
/// `accept_task`), so it carries no routing information worth threading here.
/// No per-link tuning (no unixsock analogue of `configure_tcp_stream`).
pub async fn accept_unixsock_on(listener: &UnixListener) -> io::Result<UnixStream> {
    let (stream, _peer) = listener.accept().await?;
    Ok(stream)
}

/// Split a connected [`UnixStream`] into the cooperating drivers the session
/// FSM consumes: an inbound [`UnixsockReadDriver`] (`&mut LinkDriver` for the
/// poll loop), an outbound `Arc<`[`StreamWriteDriver`]`>` (`BoxedLinkDriver`
/// for `send_blocking`), and the [`writer_task`](crate::stream_link::writer_task)
/// join handle. Byte-for-byte the same shape as
/// [`crate::link_pipeline::wire_tcp_stream`] — a unix stream owns its split
/// halves (`into_split`) exactly like a `TcpStream`, and the StreamEnvelope
/// framing + write driver are the SAME shared [`crate::stream_link`] code.
pub fn wire_unixsock_stream(
    stream: UnixStream,
) -> (UnixsockReadDriver, Arc<StreamWriteDriver>, WriterHandle) {
    // R311y473 — the adminspace `{src,dst}` pair. A unix stream is addressed by a
    // PATH, and only a BOUND end has one: an accepted server-side peer, and the
    // client end of any connection, are `unnamed`. Both ends are required (the
    // helper's contract), so a pair with an unnamed end resolves to `None` and the
    // admin host renders the link with blank ends rather than inventing a path.
    let endpoints = match (
        stream
            .local_addr()
            .ok()
            .and_then(|a| a.as_pathname().map(|p| p.to_string_lossy().into_owned())),
        stream
            .peer_addr()
            .ok()
            .and_then(|a| a.as_pathname().map(|p| p.to_string_lossy().into_owned())),
    ) {
        (Some(local), Some(peer)) => Some(addressless_link_endpoints(
            InterceptorLink::UnixsockStream,
            &local,
            &peer,
        )),
        _ => None,
    };
    let (reader, writer) = stream.into_split();
    let inbound =
        StreamReadDriver::new(reader, Arc::new(std::sync::atomic::AtomicBool::new(false)));
    let (tx, rx) = mpsc::unbounded_channel::<Vec<u8>>();
    let writer_handle = WriterHandle::spawn(rx, |queue| writer_task(writer, queue));
    // transport-lowlatency is a TCP-path negotiation; other stream links keep the
    // universal u16 prefix (an always-false flag on the write driver).
    let outbound = Arc::new(StreamWriteDriver::new(
        tx,
        Arc::new(std::sync::atomic::AtomicBool::new(false)),
        addressless_link_subject(InterceptorLink::UnixsockStream),
        endpoints,
    ));
    (inbound, outbound, writer_handle)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU32, Ordering};

    /// A unique unix-socket path under the system temp dir. Unix-socket paths
    /// have a ~108-byte kernel limit, so `temp_dir()` (`/tmp` on Linux) keeps
    /// it short; the pid + per-process counter make it unique across parallel
    /// tests without an external tempfile dep.
    fn unique_sock_path() -> std::path::PathBuf {
        static COUNTER: AtomicU32 = AtomicU32::new(0);
        let n = COUNTER.fetch_add(1, Ordering::Relaxed);
        std::env::temp_dir().join(format!("wz-unixsock-{}-{n}.sock", std::process::id()))
    }

    /// `dial_unixsock` surfaces a connect error rather than panicking when no
    /// socket exists at the path (the unixsock mirror of `dial_tcp`'s
    /// closed-port unit).
    #[tokio::test]
    async fn dial_unixsock_surfaces_connect_error() {
        let path = unique_sock_path();
        assert!(
            dial_unixsock(path.to_str().unwrap()).await.is_err(),
            "dial to a nonexistent socket path errors"
        );
    }

    /// `bind_unixsock` + `accept_unixsock_on` + `dial_unixsock` complete a
    /// loopback connection: the test binds a temp path, dials it, and accepts
    /// one peer — the unixsock mirror of `bind_tcp_then_accept_tcp_round_trip`.
    #[tokio::test]
    async fn bind_accept_dial_round_trip() {
        let path = unique_sock_path();
        let path_s = path.to_str().unwrap().to_string();
        let listener = bind_unixsock(&path_s).await.expect("bind loopback socket");
        let dial_path = path_s.clone();
        let client = tokio::spawn(async move { dial_unixsock(&dial_path).await });
        let server = accept_unixsock_on(&listener)
            .await
            .expect("accept one peer");
        let client_stream = client.await.expect("client task").expect("client connect");
        assert!(
            client_stream.peer_addr().is_ok(),
            "client stream is connected"
        );
        assert!(server.local_addr().is_ok(), "server stream is connected");
        let _ = std::fs::remove_file(&path_s);
    }

    /// `bind_unixsock` replaces a STALE socket file: a second bind at the same
    /// path (after the first listener drops, leaving the socket file behind)
    /// succeeds because the stale file is unlinked first. Without the unlink,
    /// `UnixListener::bind` would fail with `EADDRINUSE` — so this is a
    /// non-vacuous guard on the stale-file logic.
    #[tokio::test]
    async fn bind_unixsock_replaces_stale_socket_file() {
        let path = unique_sock_path();
        let path_s = path.to_str().unwrap().to_string();
        let first = bind_unixsock(&path_s).await.expect("first bind");
        drop(first); // leaves the socket file on disk (no unlink-on-drop)
        assert!(
            std::path::Path::new(&path_s).exists(),
            "a dropped listener leaves a stale socket file"
        );
        let _second = bind_unixsock(&path_s)
            .await
            .expect("second bind unlinks the stale file and rebinds");
        let _ = std::fs::remove_file(&path_s);
    }
}
