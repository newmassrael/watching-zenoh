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
//! ## The socket-file lifecycle (`flock` arbitration + teardown)
//!
//! A unix-domain socket has no `SO_REUSEADDR`: a leftover socket FILE makes a
//! fresh `bind(2)` fail with `EADDRINUSE`, so a stale file must be unlinked —
//! and an unlink cannot, by itself, tell a CRASHED predecessor's leftover from
//! a socket a LIVE peer is still accepting on. zenoh answers that with a
//! separate lock file: `new_listener` opens `{path}.lock`, takes an exclusive
//! non-blocking `flock`, and only then unlinks the socket and binds
//! (`io/zenoh-links/zenoh-link-unixsock_stream/src/unicast.rs` @ `async fn new_listener`).
//! A live listener holds the lock, so a second bind FAILS instead of pulling
//! the socket out from under it; a crashed one held it only until its fd
//! closed, so its leftovers are correctly reclaimed.
//! [`UnixsockListener`](crate::unixsock_pipeline::UnixsockListener) is
//! that discipline, over the same `libc::flock` wz already uses for the
//! unixpipe rendezvous (`crate::unixpipe_pipeline`) and the SHM auth segment.
//!
//! [`UnixsockListener::close`](crate::unixsock_pipeline::UnixsockListener::close)
//! is the `del_listener` counterpart (zenoh
//! `unicast.rs`, `del_listener`): release the lock, close the fd, unlink the
//! socket file. [`Drop`] runs the same teardown best-effort, so a listener that
//! is dropped on an early return or a panic does not leak a socket file — the
//! Rust-shaped strengthening of an explicit-`del_listener`-only lifecycle.
//!
//! ### One measured divergence: wz KEEPS the lock file
//!
//! zenoh's `del_listener` also `remove_file`s `{path}.lock`. That unlink
//! REOPENS the window the lock exists to close, because `flock` is bound to an
//! open file DESCRIPTION, not to a path: a process that opened the lock file
//! before the unlink keeps locking the now-unlinked inode, while the next
//! arrival's `O_CREAT` makes a DIFFERENT inode at the same path and locks that
//! one — two "holders", one path, and the second is free to unlink a live
//! socket. wz therefore retains the (zero-byte, `0600`) lock file as a stable
//! rendezvous inode. The cost is one leftover empty file per bound path; the
//! test `zenohs_lock_file_unlink_reopens_the_stale_window` runs BOTH orders
//! over the same helper and shows upstream's admitting a second holder where
//! wz's refuses. Retaining the file is invisible to upstream: zenoh opens the
//! lock file `O_CREAT`, so an existing unlocked one is the ordinary case.
//!
//! [`dial_unixsock`] is the PRIMITIVE [`crate::session_open::dial_locator`]
//! builds on for a `unixsock-stream/...` locator; [`wire_unixsock_stream`]
//! produces the [`crate::session_open::DialedLink::Unixsock`] split for
//! `initiate_and_open_session` / `accept_and_open_session`.

use std::io;
use std::os::fd::{AsRawFd, RawFd};
use std::path::{Path, PathBuf};
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

/// The suffix zenoh appends to a unix-socket path to name its lock file
/// (`unicast.rs`, `new_listener`: `format!("{path}.lock")`). Named once so the
/// bind side, the teardown side and the cross-impl harness that clears a
/// crashed zenohd's leftovers all spell it the same way.
pub const UNIXSOCK_LOCK_SUFFIX: &str = ".lock";

/// The lock-file path for a unix-socket path — `{path}.lock`, zenoh's spelling.
pub fn unixsock_lock_path(path: &str) -> PathBuf {
    PathBuf::from(format!("{path}{UNIXSOCK_LOCK_SUFFIX}"))
}

/// Try to take an EXCLUSIVE advisory lock on `fd` without blocking. `Ok(())` =
/// nobody else holds it; `Err(AddrInUse)` = a live holder does. Raw
/// [`libc::flock`], the same BSD lock zenoh's `nix::fcntl::flock` call makes
/// and the same one [`crate::unixpipe_pipeline`]'s rendezvous uses, so the
/// arbitration is cross-IMPLEMENTATION and not merely cross-wz.
///
/// `EWOULDBLOCK` is remapped to [`io::ErrorKind::AddrInUse`] because that is
/// what the contention MEANS to a listen caller: the address (here, the socket
/// path) is taken. Every other errno is surfaced unchanged.
fn try_lock_exclusive(fd: RawFd) -> io::Result<()> {
    // SAFETY: `fd` is a valid open fd owned by a live `File` for the call.
    let rc = unsafe { libc::flock(fd, libc::LOCK_EX | libc::LOCK_NB) };
    if rc != 0 {
        let err = io::Error::last_os_error();
        if err.raw_os_error() == Some(libc::EWOULDBLOCK) {
            return Err(io::Error::new(
                io::ErrorKind::AddrInUse,
                "another listener holds the unixsock path lock",
            ));
        }
        return Err(err);
    }
    Ok(())
}

/// A bound unix-domain listener that OWNS its socket-file lifecycle: the
/// `{path}.lock` fd whose exclusive `flock` makes this
/// process the path's single live listener, and the unlink of the socket file
/// on teardown. zenoh's `ListenerUnixSocketStream` carries the same pair (the
/// listener plus its `lock_fd`) for the same reason; the difference is that
/// upstream's registry drops it only through `del_listener`, whereas this is
/// an owning value whose [`Drop`] runs the teardown as well — see
/// [`Self::close`].
///
/// Construct with [`bind_unixsock`]; accept with [`accept_unixsock_on`].
#[derive(Debug)]
pub struct UnixsockListener {
    listener: UnixListener,
    /// The bound socket path, kept so teardown can unlink exactly what this
    /// listener created (rather than re-deriving it from `local_addr`, which an
    /// unnamed socket does not answer).
    path: PathBuf,
    /// The open `{path}.lock` file. Holding it open IS holding the lock —
    /// `flock` releases when the last fd for the open file description closes —
    /// so this field is load-bearing, not bookkeeping.
    lock: Option<std::fs::File>,
}

impl UnixsockListener {
    /// The bound socket path.
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// The underlying tokio listener, for callers that need `local_addr` or
    /// their own accept shape.
    pub fn listener(&self) -> &UnixListener {
        &self.listener
    }

    /// The bound socket address (delegates to [`UnixListener::local_addr`]).
    pub fn local_addr(&self) -> io::Result<tokio::net::unix::SocketAddr> {
        self.listener.local_addr()
    }

    /// Tear the listener down — zenoh's `del_listener` (`unicast.rs`): release
    /// the advisory lock, close the lock fd, and unlink the socket file, in
    /// that order, so no window exists in which the socket file is bindable
    /// while this listener still holds it.
    ///
    /// Unlike upstream this does NOT unlink `{path}.lock`; see the module doc
    /// for the interleaving that unlink reopens. Errors from the socket unlink
    /// are returned (a `NotFound` is not an error — a caller may have removed
    /// it), so a caller that cares can observe a teardown failure; [`Drop`]
    /// runs the same steps and discards them.
    pub fn close(mut self) -> io::Result<()> {
        self.teardown()
    }

    /// The teardown body shared by [`Self::close`] and [`Drop`]. Idempotent:
    /// the lock is taken by `Option::take`, so a second call is a no-op unlink.
    fn teardown(&mut self) -> io::Result<()> {
        if let Some(lock) = self.lock.take() {
            // SAFETY: `lock` is a live `File` for the duration of the call.
            // The unlock is explicit rather than left to the close, so the
            // ordering above is the one zenoh's `del_listener` performs.
            unsafe { libc::flock(lock.as_raw_fd(), libc::LOCK_UN) };
            drop(lock);
        }
        match std::fs::remove_file(&self.path) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(e),
        }
    }
}

impl Drop for UnixsockListener {
    fn drop(&mut self) {
        let _ = self.teardown();
    }
}

/// Bind a unix-domain listener at `path` — the accept-side "listen half"
/// symmetric to dial's [`dial_unixsock`], so a caller (the e2e harness, the
/// `bind_locator` acceptor seam) observes the bound listener BEFORE the
/// blocking accept, race-free, the same split [`crate::link_pipeline::bind_tcp`]
/// established.
///
/// The order is zenoh's `new_listener` (`unicast.rs`), step for step:
///
/// 1. open `{path}.lock` (`O_CREAT`, mode `0600` — upstream's
///    `S_IRUSR | S_IWUSR`);
/// 2. take an exclusive non-blocking `flock`. A LIVE
///    listener on this path holds it, so this fails with
///    [`io::ErrorKind::AddrInUse`] instead of destroying its socket. A crashed
///    one released it when its fd closed, so its leftovers are reclaimed;
/// 3. only now unlink the socket file (a `NotFound` is the ordinary first-bind
///    case, not an error);
/// 4. `UnixListener::bind`.
///
/// wz opens the lock file `O_RDWR` where upstream opens it `O_RDONLY`: std's
/// `OpenOptions` rejects `create` without write access, and `flock` is
/// indifferent to the access mode — the MODE BITS, which are what another
/// process sees, are upstream's.
///
/// Returns a [`UnixsockListener`], which owns the lock and unlinks the socket
/// on [`UnixsockListener::close`] or drop.
pub async fn bind_unixsock(path: &str) -> io::Result<UnixsockListener> {
    use std::os::unix::fs::OpenOptionsExt;

    let lock_path = unixsock_lock_path(path);
    let lock = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .mode(0o600)
        .open(&lock_path)?;
    try_lock_exclusive(lock.as_raw_fd())?;

    match std::fs::remove_file(path) {
        Ok(()) => {}
        Err(e) if e.kind() == io::ErrorKind::NotFound => {}
        Err(e) => return Err(e),
    }
    let listener = UnixListener::bind(path)?;
    Ok(UnixsockListener {
        listener,
        path: PathBuf::from(path),
        lock: Some(lock),
    })
}

/// Accept ONE inbound connection from a *borrowed* [`UnixsockListener`],
/// returning the accepted [`UnixStream`] — the unixsock mirror of
/// [`crate::link_pipeline::accept_tcp_on`]. Borrowing (not consuming) the
/// listener is what lets a multi-peer acceptor call this in a loop. The peer
/// address is discarded: an accepted unix-socket peer is anonymous (zenoh
/// assigns it a fresh UUID rather than a meaningful name, `unicast.rs`
/// `accept_task`), so it carries no routing information worth threading here.
/// No per-link tuning (no unixsock analogue of `configure_tcp_stream`).
pub async fn accept_unixsock_on(listener: &UnixsockListener) -> io::Result<UnixStream> {
    let (stream, _peer) = listener.listener.accept().await?;
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
        drop(listener); // unlinks the socket file
        let _ = std::fs::remove_file(unixsock_lock_path(&path_s));
    }

    /// `bind_unixsock` replaces a STALE socket file — one left by a listener
    /// that is NO LONGER LIVE. The stale file is made the way a crash makes it:
    /// a raw `UnixListener::bind` (not `bind_unixsock`, which would take the
    /// lock and clean up after itself) that is then dropped, leaving the socket
    /// file with nobody holding the path lock. Without the unlink,
    /// `UnixListener::bind` would fail with `EADDRINUSE` — so this is a
    /// non-vacuous guard on the stale-file logic, and it is now specifically a
    /// guard that the flock gate does not BLOCK the legitimate reclaim.
    #[tokio::test]
    async fn bind_unixsock_replaces_stale_socket_file() {
        let path = unique_sock_path();
        let path_s = path.to_str().unwrap().to_string();
        let crashed = UnixListener::bind(&path_s).expect("raw bind, the crashed predecessor");
        drop(crashed); // leaves the socket file on disk, holding no path lock
        assert!(
            std::path::Path::new(&path_s).exists(),
            "a dropped raw listener leaves a stale socket file"
        );
        let second = bind_unixsock(&path_s)
            .await
            .expect("second bind unlinks the stale file and rebinds");
        second.close().expect("teardown");
        let _ = std::fs::remove_file(unixsock_lock_path(&path_s));
    }

    /// The residual this module closes: a bind at a path a LIVE listener holds
    /// must FAIL, and must leave that listener's socket intact and dialable.
    ///
    /// The discriminator is the second half. Refusing to bind is cheap to get
    /// right by accident (a bind can fail for many reasons); what the lock buys
    /// is that the refused bind did NOT unlink the live socket on its way out,
    /// which is exactly what the pre-lock `remove_file`-then-bind order did.
    #[tokio::test]
    async fn a_live_listener_keeps_its_socket_against_a_second_bind() {
        let path = unique_sock_path();
        let path_s = path.to_str().unwrap().to_string();
        let live = bind_unixsock(&path_s).await.expect("first bind");

        let err = bind_unixsock(&path_s)
            .await
            .expect_err("a second bind on a live path is refused");
        assert_eq!(
            err.kind(),
            io::ErrorKind::AddrInUse,
            "the refusal names the contention: {err}"
        );

        // The live listener still owns a working socket: dial it and accept.
        let dial_path = path_s.clone();
        let client = tokio::spawn(async move { dial_unixsock(&dial_path).await });
        let server = accept_unixsock_on(&live)
            .await
            .expect("the live listener still accepts");
        let client_stream = client.await.expect("client task").expect("client connect");
        assert!(client_stream.peer_addr().is_ok(), "client is connected");
        assert!(server.local_addr().is_ok(), "server side is connected");
        live.close().expect("teardown");
        let _ = std::fs::remove_file(unixsock_lock_path(&path_s));
    }

    /// `close` is the `del_listener` counterpart: it unlinks the socket file and
    /// releases the path lock, so a FRESH bind afterwards succeeds. Drop runs
    /// the same teardown — asserted here on the same helper so the two paths
    /// cannot drift.
    #[tokio::test]
    async fn close_and_drop_both_release_the_path() {
        for closed_explicitly in [true, false] {
            let path = unique_sock_path();
            let path_s = path.to_str().unwrap().to_string();
            let listener = bind_unixsock(&path_s).await.expect("bind");
            assert!(
                std::path::Path::new(&path_s).exists(),
                "the bind created the socket file"
            );
            if closed_explicitly {
                listener.close().expect("explicit close");
            } else {
                drop(listener);
            }
            assert!(
                !std::path::Path::new(&path_s).exists(),
                "teardown unlinked the socket file (explicit = {closed_explicitly})"
            );
            // The measured divergence, asserted where it lives: the lock file
            // SURVIVES the teardown. Unlinking it is what reopens the window
            // `zenohs_lock_file_unlink_reopens_the_stale_window` measures.
            assert!(
                unixsock_lock_path(&path_s).exists(),
                "teardown keeps {{path}}.lock as the stable rendezvous inode \
                 (explicit = {closed_explicitly})"
            );
            let again = bind_unixsock(&path_s)
                .await
                .expect("the path is free again after teardown");
            again.close().expect("teardown");
            let _ = std::fs::remove_file(unixsock_lock_path(&path_s));
        }
    }

    /// The MEASURED reason wz keeps `{path}.lock` where zenoh's `del_listener`
    /// unlinks it: the unlink reopens the very window the lock exists to close.
    ///
    /// Both orders run here over the same two helpers, so this is a control
    /// group rather than a claim. `holders` counts how many "listeners" hold an
    /// exclusive lock on the path at once, under the interleaving that upstream
    /// admits: a late arrival opens the lock file, the incumbent tears down,
    /// the late arrival's lock then succeeds — and a THIRD arrival, opening
    /// `O_CREAT` after the unlink, gets a different inode and succeeds too.
    /// With the lock file retained the third arrival lands on the SAME inode and
    /// is refused.
    #[test]
    fn zenohs_lock_file_unlink_reopens_the_stale_window() {
        use std::fs::OpenOptions;
        use std::os::unix::fs::OpenOptionsExt;

        fn open_lock(p: &Path) -> std::fs::File {
            OpenOptions::new()
                .read(true)
                .write(true)
                .create(true)
                .truncate(false)
                .mode(0o600)
                .open(p)
                .expect("open lock file")
        }

        // `unlink_the_lock_file` = upstream's `del_listener` order; false = wz's.
        fn holders_after_a_handover(lock_path: &Path, unlink_the_lock_file: bool) -> usize {
            let _ = std::fs::remove_file(lock_path);
            let incumbent = open_lock(lock_path);
            try_lock_exclusive(incumbent.as_raw_fd()).expect("incumbent takes the lock");

            // A late arrival opens the lock file BEFORE the incumbent leaves.
            let late = open_lock(lock_path);

            // The incumbent tears down.
            // SAFETY: `incumbent` is a live `File` for the call.
            unsafe { libc::flock(incumbent.as_raw_fd(), libc::LOCK_UN) };
            drop(incumbent);
            if unlink_the_lock_file {
                let _ = std::fs::remove_file(lock_path);
            }

            let mut holders = 0;
            if try_lock_exclusive(late.as_raw_fd()).is_ok() {
                holders += 1;
            }
            // A third arrival that opens the path only now.
            let fresh = open_lock(lock_path);
            if try_lock_exclusive(fresh.as_raw_fd()).is_ok() {
                holders += 1;
            }
            let _ = std::fs::remove_file(lock_path);
            holders
        }

        let dir = std::env::temp_dir();
        let pid = std::process::id();
        let upstream_order = dir.join(format!("wz-unixsock-lockwin-up-{pid}.lock"));
        let wz_order = dir.join(format!("wz-unixsock-lockwin-wz-{pid}.lock"));

        assert_eq!(
            holders_after_a_handover(&upstream_order, true),
            2,
            "unlinking the lock file lets TWO listeners hold the same path"
        );
        assert_eq!(
            holders_after_a_handover(&wz_order, false),
            1,
            "retaining the lock file keeps the path single-holder"
        );
    }

    /// Read this crate's `*_pipeline.rs` sources as `(module name, text)`. The
    /// directory comes from `CARGO_MANIFEST_DIR`, so the derivation travels
    /// with the crate instead of assuming a repo root or a cwd (`file!()` is
    /// workspace-relative while a test's cwd is the package, which is exactly
    /// the mismatch this avoids).
    fn pipeline_modules() -> Vec<(String, String)> {
        let src_dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
        let mut out = Vec::new();
        for entry in std::fs::read_dir(&src_dir).expect("read the crate's src/") {
            let path = entry.expect("dir entry").path();
            let name = match path.file_name().and_then(|n| n.to_str()) {
                Some(n) if n.ends_with("_pipeline.rs") => n.to_string(),
                _ => continue,
            };
            out.push((
                name,
                std::fs::read_to_string(&path).expect("read a pipeline module"),
            ));
        }
        out
    }

    /// Every TOP-LEVEL free function in `text`, as `(qualifiers, name, body)`.
    ///
    /// "Top-level" is decided structurally: the `fn` keyword must sit on a line
    /// whose prefix starts at column 0 and holds nothing but item qualifiers
    /// (`pub`, `async`, `unsafe`, …). That one rule excludes doc comments (`///`
    /// prefix), string literals (`"` prefix) and every nested / `impl` / test-
    /// module function (indented prefix) without a comment parser. A body runs
    /// to the next column-0 `}`, which is where a top-level function ends.
    fn top_level_functions(text: &str) -> Vec<(String, String, String)> {
        let mut out = Vec::new();
        for (idx, _) in text.match_indices("fn ") {
            let line_start = text[..idx].rfind('\n').map(|p| p + 1).unwrap_or(0);
            let prefix = &text[line_start..idx];
            let qualifiers_only = prefix
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '(' || c == ')' || c == ' ');
            if !qualifiers_only || prefix.starts_with(' ') {
                continue;
            }
            let rest = &text[idx + 3..];
            let sig_end = match rest.find(['(', '<', ' ', '\n']) {
                Some(e) => e,
                None => continue,
            };
            if !rest[..sig_end]
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '_')
                || sig_end == 0
            {
                continue;
            }
            let end = rest.find("\n}\n").map(|e| e + 2).unwrap_or(rest.len());
            out.push((
                prefix.to_string(),
                rest[..sig_end].to_string(),
                rest[..end].to_string(),
            ));
        }
        out
    }

    /// Population guard for the class this round paid off, derived TWICE from
    /// the source so neither half is a list written here.
    ///
    /// The class: a listen seam addressed by a FILESYSTEM PATH cannot unlink a
    /// leftover artifact safely on the unlink alone — a crashed predecessor and
    /// a LIVE peer leave the same file — so it must first take an advisory lock
    /// nobody else can be holding. unixsock is where this was NOTICED; it is
    /// not the population. `bind_unixpipe` is in the same class and was already
    /// arbitrated, which is why the derivation must find it too.
    ///
    /// Derivation 1 — the advisory-lock helpers: functions in this crate's
    /// `*_pipeline.rs` whose bodies actually call `libc::flock` with `LOCK_EX`.
    /// Taking the NAMES from the code rather than typing them is what stops the
    /// needle from outliving the call.
    ///
    /// Derivation 2 — the seams: `pub async fn bind_*(path: &str)` in the same
    /// modules, i.e. a bind addressed by a path rather than by an IP socket, a
    /// vsock `(cid, port)` or a quinn endpoint.
    ///
    /// Either population being EMPTY fails: a guard whose subject vanished must
    /// not report green.
    #[test]
    fn every_path_addressed_bind_seam_takes_an_advisory_lock() {
        let modules = pipeline_modules();
        assert!(
            !modules.is_empty(),
            "derived NO *_pipeline.rs modules — the source walk broke"
        );

        let mut lock_helpers: Vec<String> = Vec::new();
        for (_, text) in &modules {
            for (_, name, body) in top_level_functions(text) {
                if body.contains("libc::flock") && body.contains("LOCK_EX") {
                    lock_helpers.push(name);
                }
            }
        }
        lock_helpers.sort();
        lock_helpers.dedup();
        assert!(
            !lock_helpers.is_empty(),
            "derived NO advisory-lock helper: nothing in this crate's pipelines \
             calls libc::flock with LOCK_EX any more, so the guard below would \
             be checking for a needle that cannot exist"
        );

        let mut seams: Vec<String> = Vec::new();
        for (module, text) in &modules {
            for (qualifiers, name, body) in top_level_functions(text) {
                // A path-ADDRESSED public listen seam: `pub async fn bind_*` whose
                // first parameter is a filesystem path (not a `SocketAddr`, a vsock
                // `(cid, port)` or a quinn endpoint).
                if qualifiers != "pub async " || !name.starts_with("bind_") {
                    continue;
                }
                if !body[name.len()..].starts_with("(path: &str") {
                    continue;
                }
                let seam = format!("{module}::{name}");
                assert!(
                    lock_helpers.iter().any(|h| body.contains(h.as_str())),
                    "{seam} is addressed by a filesystem path but calls none of the \
                     advisory-lock helpers {lock_helpers:?}: its unlink cannot tell a \
                     crashed predecessor from a LIVE peer"
                );
                seams.push(seam);
            }
        }
        seams.sort();
        seams.dedup();
        assert!(
            !seams.is_empty(),
            "derived an EMPTY population of path-addressed bind seams — the \
             derivation broke, which must fail rather than report green"
        );
    }
}
