// SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! R311y10 / R311y392 — Unix named-pipe (FIFO) session-open transport pipeline
//! (Linux), the MULTI-CLIENT, zenoh-wire-compatible acceptor.
//!
//! The FIFO sibling of [`crate::unixsock_pipeline`] (AF_UNIX stream). zenoh's
//! `zenoh-link-unixpipe` carries a zenoh batch over a PAIR of named FIFOs (one
//! per direction) — a same-host link kind distinct from the AF_UNIX `unixsock`
//! socket. The batch framing reuses the transport-neutral StreamEnvelope drivers
//! in [`crate::stream_link`] UNCHANGED (a FIFO is a reliable byte stream —
//! `is_streamed`, MTU `BatchSize::MAX`), exactly like the AF_UNIX stream and TCP.
//! wz uses tokio's NATIVE named-pipe support ([`tokio::net::unix::pipe`]) for the
//! byte I/O (a [`Sender`] is `AsyncWrite`, a [`Receiver`] is `AsyncRead`), NOT
//! zenoh's hand-rolled `AsyncFd<File>` + `unix_named_pipe` crate loop.
//!
//! ## Multi-client rendezvous (zenoh `UnicastPipeListener` wire-compatible)
//!
//! A single listener serves N distinct clients, exactly like zenoh's
//! `UnicastPipeListener`, and is WIRE-COMPATIBLE with it (a zenohd built with
//! `transport_unixpipe` interoperates). For a listen base path `P`:
//! - `P_uplink` is the shared REQUEST channel: clients WRITE 8-byte invitations,
//!   the listener READS them.
//! - Each accepted client gets a DEDICATED FIFO pair keyed by a random `u32`
//!   suffix (DECIMAL string): `P_uplink{suffix}` (client->listener) and
//!   `P_downlink{suffix}` (listener->client).
//!
//! An invitation is `[0xDE,0xAD,0xBE,0xEF]` ++ `suffix.to_ne_bytes()` (8 bytes,
//! NATIVE-endian u32 — same-host IPC, both processes share endianness; DO NOT
//! "fix" the endianness or interop with a zenoh peer breaks). The 3-way
//! handshake: client sends the invitation on the request channel; the listener
//! opens the dedicated pair and CONFIRMs the suffix on `P_downlink{suffix}`; the
//! client CONFIRMs back on `P_uplink{suffix}`. Both sides then hold the dedicated
//! pair and the byte stream is ready for the uniform StreamEnvelope split.
//!
//! ## flock is load-bearing (rendezvous + reservation + single-listener)
//!
//! zenoh's writer-open (`PipeW::new`) try-locks `flock(LOCK_EX)` on the FIFO and
//! `bail!("no listener")` if the lock is FREE — so a reader end a peer will write
//! to MUST hold an exclusive advisory lock for its whole life, or the peer aborts
//! the connection. wz mirrors this with raw [`libc::flock`] (== the `advisory_lock`
//! crate zenoh uses; same OFD-based BSD lock, cross-compatible):
//! - the listener holds `LOCK_EX` on the base request reader (`P_uplink`) — this
//!   also enforces ONE listener per path (a 2nd bind's try-lock fails) and is what
//!   a dialer probes to detect a live listener.
//! - the listener holds `LOCK_EX` on each dedicated `P_uplink{suffix}` reader.
//! - the client holds `LOCK_EX` on each dedicated `P_downlink{suffix}` reader.
//! flock is also the SUFFIX-COLLISION detector: a second dialer that draws the
//! same suffix fails to acquire the dedicated reader lock and retries (NOT
//! mkfifo-EEXIST, which is a harmless reuse — the node is created no-unlink).
//!
//! ## FIFO node cleanup — each side unlinks the node it READS
//!
//! zenoh's `PipeR::Drop` unlinks its node; a tokio [`Receiver`] does not, so wz
//! wraps every read end in a [`FifoReadEnd`] whose `Drop` unlinks its node (and,
//! via closing the fd, releases the flock). The listener unlinks each
//! `P_uplink{suffix}`, the client each `P_downlink{suffix}`, and the base
//! `P_uplink` is unlinked when the [`UnixpipeAcceptor`] drops. The listener never
//! creates `P_downlink` (only the dedicated `P_downlink{suffix}`), matching zenoh.
//!
//! ## Linux-only (the `read_write` rendezvous)
//!
//! tokio's `read_write(true)` (open a FIFO end O_RDWR so a sender never `ENXIO`s
//! on a not-yet-present reader, and a base reader never EOFs across client churn)
//! is `target_os = "linux"`-gated in tokio. So this backend is Linux-only (the
//! `transport-link-unixpipe` mod is gated `all(feature, target_os = "linux")`),
//! consistent with [`crate::vsock_pipeline`] and the LAYER-1 = Linux-host scope.

use std::ffi::CString;
use std::io;
use std::os::unix::io::{AsRawFd, RawFd};
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWriteExt, ReadBuf};
use tokio::net::unix::pipe::{OpenOptions, Receiver, Sender};
use tokio::sync::mpsc;

use wz_runtime_core::Runtime;

use crate::link_interfaces::addressless_link_subject;
use crate::runtime_impl::{TokioJoinHandle, TokioRuntime};
use crate::stream_link::{writer_task, StreamReadDriver, StreamWriteDriver};
use wz_session_core::link::InterceptorLink;

/// The dialer-writes / acceptor-reads FIFO suffix (zenoh `_uplink` parity).
const UPLINK_SUFFIX: &str = "_uplink";
/// The acceptor-writes / dialer-reads FIFO suffix (zenoh `_downlink` parity).
const DOWNLINK_SUFFIX: &str = "_downlink";
/// The 4-byte invitation magic (zenoh `PIPE_INVITATION`, unicast.rs:55).
const PIPE_INVITATION: [u8; 4] = [0xDE, 0xAD, 0xBE, 0xEF];
/// The full 8-byte invitation length (magic ++ native-endian u32 suffix).
const INVITATION_LEN: usize = 8;
/// Max attempts to draw a collision-free dedicated-pipe suffix (zenoh
/// `LINUX_PIPE_DEDICATE_TRIES`, unicast.rs:53).
const DEDICATE_TRIES: usize = 100;
/// Per-invitation handshake timeout — bounds a peer that sends a valid invitation
/// then STALLS (a crash between invitation-send and dedicated-uplink-open, or a
/// hostile peer) so it cannot hold a dedicated pipe pair — or wedge the acceptor —
/// forever. Matches zenoh's `transport.unicast.accept_timeout` default (10000ms);
/// zenoh's `UnicastPipeListener` loop has NO such bound (serial + unbounded), so the
/// timeout wrapper in [`unixpipe_acceptor_task`] is a SUPERSET hardening.
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);

// ---------------------------------------------------------------------------
// FIFO node names (DECIMAL suffix — zenoh `get_dedicated_pipe_names`).
// ---------------------------------------------------------------------------

fn suffixed(path: &str, suffix: &str) -> String {
    let mut s = String::with_capacity(path.len() + suffix.len());
    s.push_str(path);
    s.push_str(suffix);
    s
}

/// The base `(uplink, downlink)` request-channel names for a listen base `P`.
fn base_channels(base: &str) -> (String, String) {
    (
        suffixed(base, UPLINK_SUFFIX),
        suffixed(base, DOWNLINK_SUFFIX),
    )
}

/// The dedicated `(uplink{suffix}, downlink{suffix})` names for a connection —
/// the suffix is the DECIMAL string of the u32 (zenoh `suffix.to_string()`,
/// unicast.rs:345); a hex / zero-padded form would silently mismatch a zenoh
/// peer's node names.
fn dedicated_channels(base: &str, suffix: u32) -> (String, String) {
    let (uplink, downlink) = base_channels(base);
    (format!("{uplink}{suffix}"), format!("{downlink}{suffix}"))
}

// ---------------------------------------------------------------------------
// FIFO node create (NO-UNLINK, EEXIST-tolerant) + unlink.
// ---------------------------------------------------------------------------

/// `mkfifo` a FIFO at `path` with mode 0o600, TOLERATING a pre-existing node
/// (`EEXIST` => `Ok`). Unlike the old `make_fifo`, this does NOT unlink first —
/// unlink-then-create would clobber a concurrent dialer's flock-reserved node
/// (flock is invisible to `unlink`), defeating the suffix-collision detector. The
/// real reservation is the exclusive flock the caller then acquires on the
/// opened reader; `EEXIST` here is a harmless reuse.
///
/// R311y13 disclosure: mode 0o600 (owner-only) is a deliberate hardening over
/// zenoh's default 0o777 for this same-host IPC node; wz does NOT model zenoh's
/// configurable `file_mask` locator parameter. Cross-impl interop therefore needs
/// zenohd and wz to run as the SAME uid (a different uid + 0o600 would `EACCES`).
fn create_fifo_tolerant(path: &str) -> io::Result<()> {
    let c_path = CString::new(path).map_err(|_| {
        io::Error::new(io::ErrorKind::InvalidInput, "fifo path has an interior NUL")
    })?;
    // SAFETY: `c_path` is a valid NUL-terminated C string live for the call;
    // `mkfifo` only reads through the pointer. 0o600 = owner read+write.
    let rc = unsafe { libc::mkfifo(c_path.as_ptr(), 0o600 as libc::mode_t) };
    if rc != 0 {
        let err = io::Error::last_os_error();
        if err.raw_os_error() == Some(libc::EEXIST) {
            return Ok(());
        }
        return Err(err);
    }
    Ok(())
}

/// Best-effort unlink of a FIFO node (a `NotFound` is not an error — the peer may
/// have unlinked it already, or a re-bind cleaned it up).
fn unlink_node(path: &str) {
    match std::fs::remove_file(path) {
        Ok(()) => {}
        Err(e) if e.kind() == io::ErrorKind::NotFound => {}
        Err(e) => log::debug!("wz unixpipe: unlink {path} failed: {e}"),
    }
}

// ---------------------------------------------------------------------------
// Advisory lock (flock == zenoh's advisory_lock crate).
// ---------------------------------------------------------------------------

/// Try to acquire an EXCLUSIVE advisory lock on `fd` without blocking. `Ok(())`
/// = the lock was acquired (nobody else holds it); `Err(WouldBlock)` = someone
/// holds it. Raw [`libc::flock`], the same OFD-based BSD lock zenoh's
/// `advisory_lock` crate uses (cross-compatible). The lock releases only when the
/// fd closes, so callers keep the owning [`Receiver`]/[`Sender`] alive to hold it.
fn try_flock_ex(fd: RawFd) -> io::Result<()> {
    // SAFETY: `fd` is a valid open fd owned by a live pipe end for the call.
    let rc = unsafe { libc::flock(fd, libc::LOCK_EX | libc::LOCK_NB) };
    if rc != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Invitation encode / send / receive (8-byte magic ++ native-endian u32).
// ---------------------------------------------------------------------------

fn encode_invitation(suffix: u32) -> [u8; INVITATION_LEN] {
    let mut msg = [0u8; INVITATION_LEN];
    msg[..4].copy_from_slice(&PIPE_INVITATION);
    msg[4..].copy_from_slice(&suffix.to_ne_bytes());
    msg
}

/// Write an 8-byte invitation carrying `suffix` (zenoh `Invitation::send`).
async fn send_invitation<W: tokio::io::AsyncWrite + Unpin>(
    w: &mut W,
    suffix: u32,
) -> io::Result<()> {
    w.write_all(&encode_invitation(suffix)).await
}

/// Read an 8-byte invitation, verify the magic, and return its suffix (zenoh
/// `Invitation::receive`). A magic mismatch is a protocol error.
async fn recv_invitation<R: AsyncRead + Unpin>(r: &mut R) -> io::Result<u32> {
    let mut msg = [0u8; INVITATION_LEN];
    r.read_exact(&mut msg).await?;
    if msg[..4] != PIPE_INVITATION {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "unexpected unixpipe invitation magic",
        ));
    }
    let mut suffix_bytes = [0u8; 4];
    suffix_bytes.copy_from_slice(&msg[4..]);
    Ok(u32::from_ne_bytes(suffix_bytes))
}

/// Read an invitation and assert it carries `expected` (zenoh `Invitation::expect`).
async fn expect_invitation<R: AsyncRead + Unpin>(r: &mut R, expected: u32) -> io::Result<()> {
    let got = recv_invitation(r).await?;
    if got != expected {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("unixpipe suffix mismatch: expected {expected}, got {got}"),
        ));
    }
    Ok(())
}

/// Open the outbound FIFO `path` as a [`Sender`] in read-write mode so the open
/// never blocks / `ENXIO`s on a not-yet-present reader (the Linux `read_write`
/// rendezvous). Used for the dedicated write ends AFTER the handshake ordering has
/// guaranteed the peer's reader is present.
fn open_sender_rw(path: &str) -> io::Result<Sender> {
    OpenOptions::new().read_write(true).open_sender(path)
}

// ---------------------------------------------------------------------------
// FifoReadEnd — a tokio Receiver that unlinks its FIFO node on drop (zenoh
// PipeR::Drop parity) and holds its flock (released when the fd closes on drop).
// ---------------------------------------------------------------------------

/// The inbound half of a unixpipe link: a tokio [`Receiver`] paired with the FIFO
/// node it reads. `Drop` unlinks that node (a tokio `Receiver` does not, unlike
/// zenoh's `PipeR`) and — by closing the fd — releases the exclusive flock the
/// read end holds. Implements [`AsyncRead`] by delegating to the receiver, so it
/// drops straight into the shared [`StreamReadDriver`].
pub struct FifoReadEnd {
    receiver: Receiver,
    /// The FIFO node to unlink on drop (`None` = do not unlink, e.g. a borrowed
    /// end; today always `Some`).
    node: Option<String>,
}

impl FifoReadEnd {
    fn new(receiver: Receiver, node: String) -> Self {
        Self {
            receiver,
            node: Some(node),
        }
    }
}

impl AsyncRead for FifoReadEnd {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        // `Receiver` is `Unpin`, so `FifoReadEnd` is `Unpin`; project by ref.
        let this = self.get_mut();
        Pin::new(&mut this.receiver).poll_read(cx, buf)
    }
}

impl Drop for FifoReadEnd {
    fn drop(&mut self) {
        // Unlink the read node BEFORE the receiver's fd closes — safe: an open fd
        // keeps the inode alive, so bytes in flight are unaffected; the node just
        // vanishes from the filesystem (exactly zenoh's `PipeR::Drop` behavior).
        if let Some(node) = self.node.take() {
            unlink_node(&node);
        }
    }
}

/// Inbound read driver of a unixpipe link — the FIFO instantiation of the shared
/// [`StreamReadDriver`] over a [`FifoReadEnd`] (`AsyncRead`). The framing /
/// [`crate::LinkDriver`] impl lives once in [`crate::stream_link`] (a FIFO frames
/// identically to a TCP stream); this alias pins the read half to the FIFO end.
pub type UnixpipeReadDriver = StreamReadDriver<FifoReadEnd>;

/// A connected unixpipe link: the inbound [`FifoReadEnd`] + the outbound
/// [`Sender`]. Produced by [`dial_unixpipe`] (client) or the acceptor task
/// (listener) and consumed by [`wire_unixpipe_stream`]. The read + write halves
/// are SEPARATE FIFOs (a dedicated pair), so there is no `into_split`.
pub struct UnixpipeLink {
    /// The inbound FIFO end (unlinks its node + releases its flock on drop).
    pub read: FifoReadEnd,
    /// The outbound FIFO end (`AsyncWrite`).
    pub sender: Sender,
}

// ---------------------------------------------------------------------------
// Dial (client) — the invitation protocol (zenoh `UnicastPipeClient::connect_to`).
// ---------------------------------------------------------------------------

/// Draw a collision-free dedicated-pipe suffix and reserve it: create + flock the
/// client's `P_downlink{suffix}` reader (KEPT as the client's read end) and
/// transiently reserve `P_uplink{suffix}` (created + flock-checked, then dropped +
/// unlinked — the listener re-creates + opens it, zenoh's `create_pipe` parity).
/// A flock failure on either reader means another dialer holds that suffix ->
/// retry a new one (up to [`DEDICATE_TRIES`]). Returns `(suffix, downlink reader)`.
fn dedicate(base: &str) -> io::Result<(u32, FifoReadEnd)> {
    for _ in 0..DEDICATE_TRIES {
        let suffix: u32 = rand::random();
        let (uplink, downlink) = dedicated_channels(base, suffix);

        // Reserve the downlink (the client's read end): create no-unlink, open,
        // and try to flock. A held lock means a concurrent dialer has this suffix.
        if create_fifo_tolerant(&downlink).is_err() {
            continue;
        }
        let dl = match OpenOptions::new().open_receiver(&downlink) {
            Ok(r) => r,
            Err(_) => {
                unlink_node(&downlink);
                continue;
            }
        };
        if try_flock_ex(dl.as_raw_fd()).is_err() {
            // Taken by another dialer — drop (releasing our failed attempt) + retry.
            drop(dl);
            continue;
        }

        // Reserve the uplink transiently (zenoh creates it then drops+unlinks it,
        // so the listener re-creates + opens it): confirm the suffix's uplink name
        // is also free, then release + unlink it.
        if create_fifo_tolerant(&uplink).is_err() {
            drop(dl);
            unlink_node(&downlink);
            continue;
        }
        let ul = match OpenOptions::new().open_receiver(&uplink) {
            Ok(r) => r,
            Err(_) => {
                drop(dl);
                unlink_node(&downlink);
                unlink_node(&uplink);
                continue;
            }
        };
        if try_flock_ex(ul.as_raw_fd()).is_err() {
            drop(ul);
            drop(dl);
            unlink_node(&downlink);
            continue;
        }
        // Uplink is free; release our transient reservation (drop closes the fd ->
        // releases the flock) and unlink the node — the listener re-creates it.
        drop(ul);
        unlink_node(&uplink);

        return Ok((suffix, FifoReadEnd::new(dl, downlink)));
    }
    Err(io::Error::new(
        io::ErrorKind::AddrInUse,
        "unable to dedicate a collision-free unixpipe suffix",
    ))
}

/// Dial the unixpipe listener at base `path` — the client half of the invitation
/// protocol ([`crate::session_open::dial_locator`] routes a parsed `unixpipe/...`
/// path here). Detects a live listener (an absent one surfaces `ConnectionRefused`
/// via `ENXIO` / a free base flock), reserves a dedicated pair, and completes the
/// 3-way handshake, returning the connected [`UnixpipeLink`]. Must run within a
/// tokio runtime.
pub async fn dial_unixpipe(path: &str) -> io::Result<UnixpipeLink> {
    let (base_uplink, _base_downlink) = base_channels(path);

    // 1. Open the base request channel for write. Two "no listener" shapes both map
    //    to `ConnectionRefused`: the base FIFO node does not exist yet (`ENOENT` —
    //    nobody has bound), or it exists but has no reader (`ENXIO` — a
    //    O_WRONLY|O_NONBLOCK FIFO open with no reader). If the open succeeds, probe
    //    the flock: acquiring it means the listener's reader is absent (a live
    //    listener would hold the lock) -> also no listener.
    let mut base_sender = match OpenOptions::new().open_sender(&base_uplink) {
        Ok(s) => s,
        Err(e) if matches!(e.raw_os_error(), Some(libc::ENXIO) | Some(libc::ENOENT)) => {
            return Err(io::Error::new(
                io::ErrorKind::ConnectionRefused,
                format!("no unixpipe listener at {path}"),
            ));
        }
        Err(e) => return Err(e),
    };
    if try_flock_ex(base_sender.as_raw_fd()).is_ok() {
        // We acquired the lock => no listener holds it. Drop releases it.
        return Err(io::Error::new(
            io::ErrorKind::ConnectionRefused,
            format!("no unixpipe listener at {path}"),
        ));
    }

    // 2. Reserve a dedicated pair (client's downlink reader kept + flock'd).
    let (suffix, mut read) = dedicate(path)?;
    let (uplink, _downlink) = dedicated_channels(path, suffix);

    // 3. Invite the listener over the request channel.
    send_invitation(&mut base_sender, suffix).await?;

    // 4. Await the listener's confirm on our dedicated downlink reader.
    expect_invitation(&mut read, suffix).await?;

    // 5. Open the dedicated uplink for write (the listener has re-created its node
    //    + opened its reader by now — it did so before confirming in step 4).
    let mut ul_sender = open_sender_rw(&uplink)?;

    // 6. Confirm back over the dedicated uplink. (base_sender drops here.)
    send_invitation(&mut ul_sender, suffix).await?;

    Ok(UnixpipeLink {
        read,
        sender: ul_sender,
    })
}

// ---------------------------------------------------------------------------
// Accept (listener) — the acceptor task + its handle (zenoh
// `UnicastPipeListener` / `handle_incoming_connections`).
// ---------------------------------------------------------------------------

/// Complete the handshake for ONE invitation whose `suffix` was already read off
/// the base request channel: re-create + open + flock the dedicated
/// `P_uplink{suffix}` reader (the client unlinked its transient reservation), open
/// `P_downlink{suffix}` as sender, and run the 3-way suffix confirm. Returns the
/// connected listener-side [`UnixpipeLink`] (reads `P_uplink{suffix}`, writes
/// `P_downlink{suffix}`). Driven by [`unixpipe_acceptor_task`] under a
/// [`HANDSHAKE_TIMEOUT`] wrapper (NOT in `accept_raw`'s cancel-prone `select!`), so
/// a peer that stalls mid-handshake is bounded to the timeout rather than wedging
/// the acceptor forever.
async fn finish_handshake(base: &str, suffix: u32) -> io::Result<UnixpipeLink> {
    let (uplink, downlink) = dedicated_channels(base, suffix);

    // The client unlinked its transient `P_uplink{suffix}` reservation; re-create
    // it (EEXIST-tolerant) and open + flock it as our read end. The flock is what
    // a zenoh CLIENT's `PipeW::new(uplink)` probes.
    create_fifo_tolerant(&uplink)?;
    let ul_reader = OpenOptions::new().open_receiver(&uplink)?;
    try_flock_ex(ul_reader.as_raw_fd()).map_err(|e| {
        io::Error::new(
            io::ErrorKind::AddrInUse,
            format!("dedicated uplink {uplink} already locked: {e}"),
        )
    })?;
    let mut read = FifoReadEnd::new(ul_reader, uplink);

    // Open the dedicated downlink for write (the client created + flock'd its
    // reader during `dedicate`). O_RDWR open avoids the ENXIO race.
    let mut dl_sender = open_sender_rw(&downlink)?;

    // 3-way: confirm on the downlink, then expect the client's confirm on the
    // uplink. Ordering guarantees the client's uplink reader is present before it
    // writes (it writes only after our downlink confirm), so no drain loss.
    send_invitation(&mut dl_sender, suffix).await?;
    expect_invitation(&mut read, suffix).await?;

    Ok(UnixpipeLink {
        read,
        sender: dl_sender,
    })
}

/// RAII guard that aborts the acceptor task when the [`UnixpipeAcceptor`] drops. A
/// plain [`TokioJoinHandle`] does NOT abort on drop, so the abort is explicit —
/// the same idiom as the udp demux [`crate::udp_pipeline::UdpDemuxPump`] / the
/// private `group.rs` `AbortOnDrop`. Aborting drops the task's owned base reader,
/// releasing its flock (the lock releases on fd close, not synchronously with the
/// abort — a rapid re-bind on the SAME base path should use a fresh path).
pub(crate) struct UnixpipeAcceptorPump(TokioJoinHandle<()>);

impl Drop for UnixpipeAcceptorPump {
    fn drop(&mut self) {
        self.0.abort();
    }
}

/// A bound multi-client unixpipe LISTENER — the `unixpipe/..` acceptor
/// [`crate::session_open::bind_locator`] wraps in `BoundListener::Unixpipe`. Owns
/// the shared request channel (base `P_uplink`, flock'd for the single-listener
/// invariant) and the acceptor task that runs each client's 3-way handshake and
/// feeds the completed links over an unbounded channel;
/// [`Self::recv_new_link`] awaits the next one (cancel-safe). The udp demux
/// [`crate::udp_pipeline::UdpDemux`] analogue for a streamed, per-peer transport.
pub struct UnixpipeAcceptor {
    new_link_rx: mpsc::UnboundedReceiver<UnixpipeLink>,
    /// The bound listen base path (for the "listening on {addr}" log line).
    base: String,
    /// The base request FIFO node, unlinked on drop (a tokio `Receiver` does not).
    base_uplink_path: String,
    _pump: UnixpipeAcceptorPump,
}

impl UnixpipeAcceptor {
    /// The bound listen base path — the non-IP "address" of this listener (the
    /// FIFO rendezvous base), rendered by `BoundListener::local_addr_display`.
    pub fn base_path(&self) -> &str {
        &self.base
    }

    /// Await the NEXT accepted client link, or `None` when the acceptor task has
    /// ended. `mpsc::Receiver::recv` is cancel-safe, so
    /// `BoundListener::accept_raw` can drive this inside the mesh loop's `select!`;
    /// the caller maps `None` to a PARK (never an `Err` that would re-arm the
    /// reject throttle), the udp demux precedent.
    pub async fn recv_new_link(&mut self) -> Option<UnixpipeLink> {
        self.new_link_rx.recv().await
    }
}

impl Drop for UnixpipeAcceptor {
    fn drop(&mut self) {
        // The `_pump` field's Drop aborts the task (releasing the base reader fd +
        // its flock); unlink the base request node here (the task's tokio Receiver
        // does not, unlike zenoh's `PipeR::Drop`). Safe with the task's fd still
        // open — the node just leaves the filesystem.
        unlink_node(&self.base_uplink_path);
    }
}

/// The acceptor task: the sole reader of the base request channel. It reads each
/// invitation SERIALLY (there is one base reader) and then completes that
/// connection's handshake in a DETACHED per-invitation sub-task bounded by
/// [`HANDSHAKE_TIMEOUT`], feeding each completed link over the new-link channel.
///
/// Each handshake is bounded by [`HANDSHAKE_TIMEOUT`] — a SUPERSET hardening over
/// zenoh's serial `UnicastPipeListener` loop: a peer that sends a valid invitation
/// and then STALLS (crash, or hostile) blocks the acceptor for at most that timeout,
/// after which the acceptor logs, drops the half-open handshake (releasing its
/// dedicated FIFOs + flock via `Drop`), and reads the next invitation. zenoh's loop
/// is serial with NO timeout, so one such peer wedges it INDEFINITELY. Acceptance is
/// still serial (one base reader), so a stalled peer delays other clients by up to
/// the timeout, not forever — a bounded, honest limitation, not the unbounded wedge
/// zenoh has. A malformed invitation (bad magic) errors on the read and is logged;
/// the loop keeps reading (the base reader is O_RDWR, so it never EOFs on client
/// churn). The only loop termination is the [`UnixpipeAcceptorPump`] abort (when the
/// listener drops) or the receiver closing (`tx.send` errors — its link's
/// `FifoReadEnd::Drop` then cleans the dedicated nodes).
async fn unixpipe_acceptor_task(
    mut base_reader: Receiver,
    base: String,
    tx: mpsc::UnboundedSender<UnixpipeLink>,
) {
    loop {
        let suffix = match recv_invitation(&mut base_reader).await {
            Ok(suffix) => suffix,
            Err(e) => {
                log::warn!("wz unixpipe accept: bad invitation: {e}");
                continue;
            }
        };
        match tokio::time::timeout(HANDSHAKE_TIMEOUT, finish_handshake(&base, suffix)).await {
            Ok(Ok(link)) => {
                if tx.send(link).is_err() {
                    // The `UnixpipeAcceptor` (BoundListener) was dropped — stop.
                    break;
                }
            }
            Ok(Err(e)) => log::warn!("wz unixpipe accept: handshake failed: {e}"),
            Err(_elapsed) => {
                log::warn!("wz unixpipe accept: handshake for suffix {suffix} timed out")
            }
        }
    }
}

/// Bind a multi-client unixpipe LISTENER on base `path`: create + O_RDWR-open +
/// exclusively-flock the base request channel (`P_uplink`), then spawn the
/// acceptor task. The flock enforces ONE listener per path (a second bind fails
/// `AddrInUse`) and is what dialers probe for listener-detection. The base reader
/// is O_RDWR so it never EOFs as clients open/close the request channel. Async
/// (like [`crate::udp_pipeline::bind_udp_demux`]) — it spawns a task.
///
/// The listener creates ONLY `P_uplink` (the request channel); the per-connection
/// `P_uplink{suffix}` / `P_downlink{suffix}` nodes are created during each
/// handshake. `P_downlink` (base) is never created (zenoh parity).
pub async fn bind_unixpipe(path: &str) -> io::Result<UnixpipeAcceptor> {
    let (base_uplink, _base_downlink) = base_channels(path);

    create_fifo_tolerant(&base_uplink)?;
    // O_RDWR so the base reader is its own writer -> never EOFs across client churn.
    let base_reader = OpenOptions::new()
        .read_write(true)
        .open_receiver(&base_uplink)?;
    // Single-listener invariant + the listener-detection lock a dialer probes.
    try_flock_ex(base_reader.as_raw_fd()).map_err(|_| {
        io::Error::new(
            io::ErrorKind::AddrInUse,
            format!("another unixpipe listener already owns {base_uplink}"),
        )
    })?;

    let (tx, rx) = mpsc::unbounded_channel::<UnixpipeLink>();
    let handle = TokioRuntime.spawn(unixpipe_acceptor_task(base_reader, path.to_string(), tx));

    Ok(UnixpipeAcceptor {
        new_link_rx: rx,
        base: path.to_string(),
        base_uplink_path: base_uplink,
        _pump: UnixpipeAcceptorPump(handle),
    })
}

/// Wire a connected [`UnixpipeLink`] into the cooperating drivers the session FSM
/// consumes: an inbound [`UnixpipeReadDriver`], an outbound
/// `Arc<`[`StreamWriteDriver`]`>`, and the [`writer_task`] join handle. The FIFO
/// read + write halves are ALREADY separate, so this is the unixsock wiring minus
/// the split. StreamEnvelope framing + the write driver are the SAME shared
/// [`crate::stream_link`] code as TCP/unixsock.
pub fn wire_unixpipe_stream(
    link: UnixpipeLink,
) -> (
    UnixpipeReadDriver,
    Arc<StreamWriteDriver>,
    TokioJoinHandle<()>,
) {
    let UnixpipeLink { read, sender } = link;
    let inbound = StreamReadDriver::new(read, Arc::new(std::sync::atomic::AtomicBool::new(false)));
    let (tx, rx) = mpsc::unbounded_channel::<Vec<u8>>();
    let writer_handle = TokioRuntime.spawn(writer_task(sender, rx));
    // transport-lowlatency is a TCP-path negotiation; other stream links keep the
    // universal u16 prefix (an always-false flag on the write driver).
    let outbound = Arc::new(StreamWriteDriver::new(
        tx,
        Arc::new(std::sync::atomic::AtomicBool::new(false)),
        addressless_link_subject(InterceptorLink::Unixpipe),
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

    /// `bind_unixpipe` mkfifos the base request channel (`P_uplink`) as a genuine
    /// FIFO, and does NOT create the base `P_downlink` (zenoh parity).
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn bind_creates_only_the_request_channel() {
        let base = unique_pipe_base();
        let acc = bind_unixpipe(&base)
            .await
            .expect("bind the request channel");
        let (uplink, downlink) = base_channels(&base);
        let ft = std::fs::metadata(&uplink)
            .expect("request fifo exists")
            .file_type();
        assert!(ft.is_fifo(), "{uplink} is a FIFO");
        assert!(
            std::fs::metadata(&downlink).is_err(),
            "base downlink must NOT be created (zenoh parity)"
        );
        drop(acc);
    }

    /// A second listener on the same base path is rejected (`AddrInUse`) — the
    /// single-listener flock invariant.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn second_listener_on_the_same_path_is_rejected() {
        let base = unique_pipe_base();
        let acc = bind_unixpipe(&base).await.expect("first listener binds");
        // `UnixpipeAcceptor` is not `Debug`, so match rather than `expect_err`.
        match bind_unixpipe(&base).await {
            Ok(_) => panic!("second listener on the same path must fail"),
            Err(e) => assert_eq!(e.kind(), io::ErrorKind::AddrInUse),
        }
        drop(acc);
    }

    /// Dialing a base path with no listener is refused (not a hang).
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn dial_with_no_listener_is_refused() {
        let base = unique_pipe_base();
        // `UnixpipeLink` is not `Debug`, so match rather than `expect_err`.
        match dial_unixpipe(&base).await {
            Ok(_) => panic!("dial with no listener must be refused"),
            Err(e) => assert_eq!(e.kind(), io::ErrorKind::ConnectionRefused),
        }
    }

    /// TWO dialers against ONE bound listener each complete the invitation
    /// handshake, get a DISTINCT dedicated pair, and round-trip a frame — the
    /// multi-client discriminator (the old single-connection acceptor held one).
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn two_dialers_get_distinct_dedicated_pairs() {
        let base = unique_pipe_base();
        let mut acc = bind_unixpipe(&base).await.expect("bind");

        // Dial twice concurrently; accept both from the one listener.
        let d1 = tokio::spawn({
            let base = base.clone();
            async move { dial_unixpipe(&base).await }
        });
        let d2 = tokio::spawn({
            let base = base.clone();
            async move { dial_unixpipe(&base).await }
        });

        let a1 = acc.recv_new_link().await.expect("accept client 1");
        let a2 = acc.recv_new_link().await.expect("accept client 2");
        let c1 = d1.await.unwrap().expect("dial 1");
        let c2 = d2.await.unwrap().expect("dial 2");

        // Each dialer's link carries the SAME payload end to end on its own pair.
        for (dialer, acceptor, payload) in [
            (c1, a1, b"unixpipe-client-1".as_slice()),
            (c2, a2, b"unixpipe-client-2".as_slice()),
        ] {
            let (_d_in, d_out, _d_writer) = wire_unixpipe_stream(dialer);
            let (mut a_in, _a_out, _a_writer) = wire_unixpipe_stream(acceptor);
            d_out.send_blocking(payload, Reliability::Reliable);
            match a_in.poll_event().await {
                LinkEvent::Rx(frame) => assert_eq!(frame.bytes, payload),
                other => panic!("expected Rx, got {other:?}"),
            }
            drop(d_out);
        }
        drop(acc);
    }
}
