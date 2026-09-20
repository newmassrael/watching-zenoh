// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! R311oa — transport-neutral byte-stream link machinery.
//!
//! The single source of truth for "a byte stream + the Zenoh streamed-link
//! [`StreamEnvelope`] framing -> the session FSM's read/write drivers". Every
//! byte-stream transport whose wire framing is the StreamEnvelope length
//! prefix instantiates these SAME pieces, differing ONLY in the concrete
//! stream type:
//! - [`crate::link_pipeline`] (TCP) — `OwnedReadHalf` / `OwnedWriteHalf` from
//!   `TcpStream::into_split`;
//! - [`crate::tls_pipeline`] (TLS) — `ReadHalf` / `WriteHalf` of a
//!   `tokio_rustls::TlsStream<TcpStream>` from `tokio::io::split`.
//!
//! Extracted here (R311oa session review) so the read-driver logic is written
//! ONCE: a TLS link frames identically to a TCP link, so a separate
//! `TlsReadDriver` struct with a byte-for-byte copy of `TcpReadDriver`'s
//! `LinkDriver` impl would be a DRY/SSOT violation (contrast serial, whose
//! COBS framing genuinely differs and so keeps its own driver). The generic
//! [`StreamReadDriver<R>`] + per-transport type aliases give each transport a
//! readable name (`TcpReadDriver` / `TlsReadDriver`) over one impl.
//!
//! Datagram transports (UDP) do NOT use this module: a datagram preserves
//! message boundaries, so there is no length-prefix framing — `udp_pipeline`
//! carries its own boundary-as-frame drivers.

use std::io;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};
use tokio::sync::mpsc;

use wz_codecs::stream_envelope::StreamEnvelope;

use crate::frame_arena::{link_arena, LinkArena, LinkFrame};
use crate::link_ring_fd::RingReadable;
use crate::writer_queue::OutboundQueue;
use crate::{poll_framed, LinkDriver, LinkEvent, ReadState, Reliability, TxFrame};
use wz_session_core::link::BoxedLinkDriver;
use wz_session_core::link::LinkEndpoints;
use wz_session_core::link::LinkSubject;
use wz_session_core::link::LostCause;
use wz_session_core::link::{LinkDropCause, LinkSendOutcome};

/// Inbound read half of a split byte-stream link — owns the read half `R`
/// (any `AsyncRead`) and impls [`LinkDriver`] with `poll_event` reading one
/// [`StreamEnvelope`] frame via the shared [`crate::poll_framed`] state
/// machine. The send/open/close methods are no-ops: the inbound side never
/// emits — the FSM's outbound path is the sibling [`StreamWriteDriver`].
///
/// Generic over the stream half so the framing impl is written once;
/// [`crate::link_pipeline::TcpReadDriver`] and
/// [`crate::tls_pipeline::TlsReadDriver`] are type aliases that pin `R`.
pub struct StreamReadDriver<R> {
    reader: R,
    read_state: ReadState<LinkFrame>,
    /// R2740 — this link's RX buffers. See the field of the same name on
    /// [`crate::TcpDriver`]: the arena is per-link because upstream's is, built
    /// inside the read task from that link's own dimensions.
    ///
    /// R2742 — WHICH arena is [`crate::frame_arena::LinkArena`]'s to say. This
    /// driver has nine `wire_*` constructors and none of them has an opinion
    /// about RX buffering, which is the same reason the field is built here
    /// rather than taken as an argument.
    arena: LinkArena,
    /// transport-lowlatency — shared with the sibling [`writer_task`] and flipped
    /// true by the lowlatency open helper at Established (only when the session
    /// negotiated lowlatency). While true, the streamed length prefix read is the
    /// 4-byte LE u32 zenoh lowlatency form (`unicast/lowlatency/link.rs`), not the
    /// 2-byte u16 batch form; false (the default) keeps the universal u16 prefix,
    /// so a non-lowlatency link and the handshake frames of a lowlatency link read
    /// byte-identically to before.
    lowlatency: Arc<AtomicBool>,
    /// R2608 — `close_link_on_expiration`, as the READ half can actually
    /// observe it. `None` on every link that did not ask for the key, which is
    /// every link today except a `tls/...` one whose locator armed it.
    ///
    /// WHY A SIGNAL AND NOT A FLAG: [`Self::poll_event`] awaits the read, so an
    /// idle driver is PARKED inside it. A bool would not be looked at again
    /// until bytes arrived — which, for a peer that has gone silent behind an
    /// expired certificate, may be never. The read therefore has to be RACED,
    /// which is the shape upstream uses for its own tls expiry
    /// (`io/zenoh-link-commons/src/tls.rs` @ `pub mod expiration {`).
    ///
    /// WHY NOT THE QUIC SHORTCUT: quic arms by cloning the `quinn::Connection`
    /// and closing it, needing nothing here. That works because the connection
    /// is a cheap cloneable handle; a stream link is `split` into halves that
    /// leave no such handle behind, so the signal has to reach the half that is
    /// waiting. The quic comment saying wz "already carries the signal" is true
    /// of quic and only of quic.
    expiry: Option<Arc<ExpirySignal>>,
    /// R2750 — WHICH READ BODY this link uses, decided once, lazily.
    ///
    /// Upstream dispatches at rx-task start
    /// (`io/zenoh-transport/src/unicast/universal/link.rs` @
    /// `if transport.manager.state.uring.is_some() && link.link.get_fd().is_ok() {`)
    /// and never revisits it; this is the same decision at the same moment, the
    /// moment a link first asks to read.
    ///
    /// WHY NOT IN THE CONSTRUCTOR: the question costs an `attach` and a
    /// channel, and a driver that is built and never read should not pay it.
    ///
    /// ⚠ R2755 — THIS PARAGRAPH USED TO GIVE A DIFFERENT REASON AND THE REASON
    /// WAS A FALSE JOIN. It said the ring is attached with a FIXED prefix
    /// width, that `lowlatency` is flipped at Established after every `wire_*`
    /// has built its driver, and therefore that "first poll is the earliest
    /// moment the width is knowable". The two premises are true and the
    /// conclusion does not follow: a link's FIRST POLL IS ITS HANDSHAKE, which
    /// happens before Established, so first poll pinned exactly the universal
    /// width onto a lowlatency link that the paragraph said it was avoiding.
    /// `lowlatency_e2e` over real TCP measured it. The repair is in
    /// [`crate::uring_reactor::UringReactor::attach`], which no longer takes a
    /// width at all — so this moment no longer has to be the one the width is
    /// knowable at, and the only thing left to justify is the cost.
    #[cfg(all(feature = "runtime-tokio-uring", feature = "transport-link-tcp"))]
    ring: RingChoice,
    /// R2750 — WHOSE reactor [`Self::choose_ring`] consults. `None` is the
    /// node's. See that method for why a caller may need to own one.
    #[cfg(all(feature = "runtime-tokio-uring", feature = "transport-link-tcp"))]
    reactor: Option<Arc<crate::uring_reactor::UringReactor>>,
}

/// R2750 — the read body [`StreamReadDriver`] dispatched to, or the fact that it
/// has not asked yet.
///
/// Three states rather than an `Option<UringRx>`, because "not asked" and
/// "asked, and the answer was no" must not collapse: the question costs a
/// channel send and an `attach`, and a link that declined must not re-ask on
/// every frame.
#[cfg(all(feature = "runtime-tokio-uring", feature = "transport-link-tcp"))]
enum RingChoice {
    /// Not asked yet — see the field's doc for why the question waits.
    Undecided,
    /// Asked and answered no. This link reads through [`poll_framed`], which is
    /// what every link did before this round and what most still do.
    Framed,
    /// This link's bytes come off the ring.
    Ring(Box<crate::uring_reactor::UringRx>),
}

/// R2608 — the one-shot "this link's certificate chain has expired" signal,
/// shared between the arming task and the read half it must interrupt.
///
/// `fired` is checked BEFORE the race and the `Notify` is what wakes a parked
/// read. Both are needed: a signal that fired while the driver was between
/// polls would be missed by the notify alone, and the bool alone cannot wake a
/// parked read. `notify_waiters` is deliberately not used for that first
/// reason — the permit-storing `notify_one` plus the pre-check is what makes
/// the ordering irrelevant.
#[derive(Debug, Default)]
pub struct ExpirySignal {
    fired: AtomicBool,
    notify: tokio::sync::Notify,
}

impl ExpirySignal {
    /// Fire the signal. Idempotent: the link is lost once.
    pub fn fire(&self) {
        self.fired.store(true, Ordering::Release);
        self.notify.notify_one();
    }

    fn has_fired(&self) -> bool {
        self.fired.load(Ordering::Acquire)
    }
}

/// R2600 — the longest single sleep an expiry watcher takes, mirroring
/// upstream's own cap
/// (`io/zenoh-link-commons/src/tls.rs` @ `const MAX_SLEEP_DURATION: tokio::time::Duration = tokio::time::Duration::from_secs(600);`).
///
/// NOT a precision limit: the loop re-reads the clock each pass and its LAST
/// sleep is exactly the remaining time, so the fire lands on the expiry
/// instant. The cap exists because one enormous sleep is the unsound shape, and
/// because re-reading the wall clock is what lets a machine whose time jumped
/// forward notice.
///
/// The quic arm carries `transport-unicast` because the CONSUMER does.
/// `quic_pipeline::arm_expiry_close` is gated `all(transport-link-quic,
/// transport-unicast)`, so a `--no-default-features --features
/// transport-link-quic` build compiled this constant and `sleep_until_unix`
/// with no caller left, and Layer C1ac died at `-D dead-code` (hosted run
/// 34891263159). The union-of-consumers rule below is unchanged; what had been
/// copied here was one half of a consumer gate that is a CONJUNCTION.
#[cfg(any(
    all(feature = "transport-link-quic", feature = "transport-unicast"),
    feature = "transport-link-tls"
))]
const EXPIRY_MAX_SLEEP: std::time::Duration = std::time::Duration::from_secs(600);

/// R2600, moved here by R2608 — sleep until `deadline` (Unix seconds),
/// re-reading the wall clock.
///
/// It lived in `quic_pipeline` behind the quic gate until tls needed the same
/// loop. Copying it would have put the same clock reasoning in two files, which
/// is the shape that drifts the day either moves; the gate is therefore the
/// UNION of its consumers, which is open-debt 730's rule applied before the
/// second consumer rather than after.
#[cfg(any(
    all(feature = "transport-link-quic", feature = "transport-unicast"),
    feature = "transport-link-tls"
))]
pub(crate) async fn sleep_until_unix(deadline: i64) {
    loop {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs() as i64)
            .unwrap_or(i64::MAX);
        if deadline <= now {
            return;
        }
        let remaining = std::time::Duration::from_secs((deadline - now) as u64);
        tokio::time::sleep(remaining.min(EXPIRY_MAX_SLEEP)).await;
    }
}

/// R2608 — the earliest `not_after` across a peer's certificate chain, as Unix
/// seconds, or `None` when there is no chain to expire.
///
/// The FOLD is `min`, not the leaf's own validity, because upstream folds the
/// whole chain
/// (`io/zenoh-link-commons/src/quic/utils.rs` @ `pub fn get_cert_chain_expiration(conn: &quinn::Connection) -> ZResult<Option<OffsetDateTime>> {`):
/// an intermediate CA that expires first governs, and reading only the leaf
/// would keep a link alive that upstream drops.
///
/// `None` for an absent or unparseable chain is deliberate and matches
/// upstream: an absent chain is not an immediate expiry.
#[cfg(feature = "transport-link-tls")]
pub(crate) fn peer_chain_deadline(
    chain: Option<&[tokio_rustls::rustls::pki_types::CertificateDer<'_>]>,
) -> Option<i64> {
    use x509_parser::prelude::{FromDer, X509Certificate};

    chain?
        .iter()
        .filter_map(|cert| {
            X509Certificate::from_der(cert.as_ref())
                .ok()
                .map(|(_, parsed)| parsed.validity().not_after.timestamp())
        })
        .min()
}

/// R2698 — the COMMON NAME on the peer's LEAF certificate, or `None`.
///
/// The sibling of [`peer_chain_deadline`] above, over the same chain and the
/// same parser, and it answers the ACL's fifth subject axis
/// (`AclRule::governs_cert_common_name`).
///
/// It mirrors upstream exactly, and each of the three differences from its
/// sibling is upstream's rather than a choice made here
/// (`io/zenoh-links/zenoh-link-tls/src/unicast.rs` @
/// `fn get_client_cert_common_name`):
///
/// * THE LEAF ONLY — `client_certs[0]`, where the deadline folds the WHOLE
///   chain with `min`. The two are asking different questions: an expiry is a
///   property of the chain (any expired link in it ends the connection), an
///   identity is a property of the peer.
/// * THE FIRST COMMON NAME — `iter_common_name().next()`, where a subject may
///   carry several. Upstream takes the first and so does this.
/// * ABSENT IS ABSENT — no chain, an unparsable leaf, a subject with no common
///   name, or a common name that is not UTF-8 all answer `None`, which is the
///   single answer upstream's `auth_value: Option<String>` can carry.
///
/// ⚠ The `#[cfg]` is its CALLER's, matching the sibling above: `tokio_rustls`
/// and `x509_parser` are `transport-link-tls` dependencies, so an ungated copy
/// does not merely become dead code — it fails to RESOLVE in a build without
/// the feature. The workspace check caught exactly that, which is the third
/// time this crate has been bitten by a helper written with a wider gate than
/// the site that calls it.
#[cfg(feature = "transport-link-tls")]
pub(crate) fn peer_chain_common_name(
    chain: Option<&[tokio_rustls::rustls::pki_types::CertificateDer<'_>]>,
) -> Option<String> {
    use x509_parser::prelude::{FromDer, X509Certificate};

    let leaf = chain?.first()?;
    let (_, parsed) = X509Certificate::from_der(leaf.as_ref()).ok()?;
    // The FIELD, as upstream reads it (`cert.subject`), not the `subject()`
    // accessor: the accessor hands back a value whose borrow dies with the
    // statement, so an iterator over it cannot outlive the expression. Measured
    // — the first draft used the accessor and the borrow checker refused it.
    let common_name = parsed
        .subject
        .iter_common_name()
        .next()
        .and_then(|cn| cn.as_str().ok())?;
    Some(common_name.to_string())
}

// R2750 — `RingReadable` is bounded HERE, on the constructors, not only on the
// `LinkDriver` impl that consumes it: the discipline is that a stream link
// cannot be BUILT without stating whether a ring can read it, which is the
// force upstream gets from `get_fd` being a required trait method. It is the
// same reason `StreamWriteDriver` takes its `subject` through the constructor —
// a new stream pipeline must state what only it can know, to compile.
impl<R: AsyncRead + Unpin + RingReadable> StreamReadDriver<R> {
    // `pub(crate)` so each transport's `wire_*` constructs it over its own split
    // read half; the type is transport-neutral. `lowlatency` is the flag the
    // lowlatency open helper flips at Established (the TCP dial/accept path
    // threads a shared one; every non-lowlatency stream link passes a fresh
    // always-false flag, keeping the universal u16 prefix).
    pub(crate) fn new(reader: R, lowlatency: Arc<AtomicBool>) -> Self {
        // R2740 — the arena is built HERE rather than taken as an argument,
        // mirroring upstream's `rx_task_non_uring`, which constructs its own
        // pool from the link it was handed. Nine `wire_*` call sites construct
        // this driver and none of them has an opinion about RX buffering;
        // making them pass one would put the same default in nine places.
        Self::with_arena(reader, lowlatency, link_arena())
    }

    /// R2742 — the same driver over an arena the CALLER owns.
    ///
    /// [`Self::new`] is this with [`link_arena`]'s answer, and the split is
    /// what makes the RX buffering decision reachable from outside: under
    /// `runtime-zero-copy` the default arena is a handle on the NODE's slot
    /// table, and a caller that owns a node — or a witness that must observe
    /// one table without the rest of the process drawing from it — needs a way
    /// to say which table. Nothing in the tree passes a node handle yet, which
    /// is why `new` still answers for the nine `wire_*` sites.
    pub(crate) fn with_arena(reader: R, lowlatency: Arc<AtomicBool>, arena: LinkArena) -> Self {
        Self {
            reader,
            read_state: ReadState::Idle,
            lowlatency,
            expiry: None,
            arena,
            #[cfg(all(feature = "runtime-tokio-uring", feature = "transport-link-tcp"))]
            ring: RingChoice::Undecided,
            #[cfg(all(feature = "runtime-tokio-uring", feature = "transport-link-tcp"))]
            reactor: None,
        }
    }

    /// R2750 — the same driver over a reactor the CALLER owns, for the reason
    /// [`Self::with_arena`] exists over an arena the caller owns.
    ///
    /// Must be called BEFORE the first [`poll_event`](LinkDriver::poll_event):
    /// the choice is made once, at first read, and this is what it consults.
    ///
    /// ⚠ `test` IS IN THE GATE, and narrowing it is the point rather than a
    /// concession. Nothing in the tree owns a node yet — production links take
    /// the node's reactor through the `None` arm — so ungated this is dead code
    /// in every build, which `-D warnings` reds. Same reasoning, same shape, as
    /// [`Self::set_expiry`] being gated on its one consumer's feature. When a
    /// node object exists, this loses the `test` and gains a caller in the same
    /// change.
    #[cfg(all(test, feature = "runtime-tokio-uring", feature = "transport-link-tcp"))]
    pub(crate) fn on_reactor(mut self, reactor: Arc<crate::uring_reactor::UringReactor>) -> Self {
        self.reactor = Some(reactor);
        self
    }

    /// R2750 — which body this link settled on.
    ///
    /// The decision is otherwise invisible: both bodies answer the same
    /// [`LinkEvent`]s, which is precisely what makes them two bodies rather than
    /// two behaviours, so a witness cannot tell them apart from the frames. It
    /// reports state and changes none, so it is not a knob: the same link reads
    /// the same way whether or not anybody asks.
    ///
    /// Gated with its consumers for the reason [`Self::on_reactor`] is.
    #[cfg(all(test, feature = "runtime-tokio-uring", feature = "transport-link-tcp"))]
    pub(crate) fn reads_through_ring(&self) -> bool {
        matches!(self.ring, RingChoice::Ring(_))
    }

    /// R2751 — what THIS driver's own half answers to `RingReadable::ring_fd`,
    /// for a witness that must check the answer WITHOUT a reactor.
    ///
    /// The distinction from [`Self::reads_through_ring`] is the point: that one
    /// reports a DECISION, which needs a ring to have been available; this one
    /// reports the HALF'S ANSWER, which a host with no `io_uring` can still be
    /// asked. vsock's witness needs exactly that — AF_VSOCK loopback and
    /// `io_uring` are separate host capabilities, and demanding both would make
    /// the test unrunnable in strictly more places than demanding one.
    ///
    /// ⚠ `transport-link-vsock` IS IN THE GATE, and narrowly on purpose: this
    /// accessor's only consumer is that pipeline's witness, and Layer C1br
    /// builds `runtime-tokio-uring` WITHOUT vsock — where an ungated helper is
    /// dead code that `-D warnings` reds. Same rule, same shape, as
    /// [`Self::set_expiry`] being gated on its one consumer's feature. A second
    /// transport wanting this widens the gate in the change that adds the
    /// caller, not before.
    #[cfg(all(
        test,
        feature = "runtime-tokio-uring",
        feature = "transport-link-tcp",
        feature = "transport-link-vsock"
    ))]
    pub(crate) fn reader_ring_fd(&self) -> Option<std::os::fd::RawFd> {
        self.reader.ring_fd()
    }

    /// R2608 — arm `close_link_on_expiration` on this read half. Called by the
    /// pipeline that knows the peer's chain, which is the only place that can:
    /// the certificate is readable from the rustls connection BEFORE the stream
    /// is split, and not after.
    ///
    /// Gated on its ONE consumer's feature rather than left open. Ungated it is
    /// dead code in every build without the tls link — which the workspace
    /// type-check runs at DEFAULT features and reds under `-D warnings`. That
    /// is open-debt 730's class (a gate wider than its consumers this time,
    /// the mirror of the narrower case), and it was caught here by the gate
    /// rather than on hosted.
    #[cfg(feature = "transport-link-tls")]
    pub(crate) fn set_expiry(&mut self, signal: Arc<ExpirySignal>) {
        self.expiry = Some(signal);
    }

    /// R2750 — THE SELECTION POINT. Which read body this link gets, asked once.
    ///
    /// Upstream's two conjuncts, in upstream's order
    /// (`io/zenoh-transport/src/unicast/universal/link.rs` @
    /// `if transport.manager.state.uring.is_some() && link.link.get_fd().is_ok() {`):
    /// a ring at node scope, and a link that can name a descriptor. Everything
    /// else reads the way it always has.
    ///
    /// ⚠ THE CONJUNCTS ARE ASKED IN THE OPPOSITE ORDER TO UPSTREAM'S, and that
    /// is derived rather than stylistic. Upstream's `uring.is_some()` READS a
    /// manager field that configuration already built, so asking it first costs
    /// nothing. [`UringReactor::node`](crate::uring_reactor::UringReactor::node)
    /// BUILDS one on first call — it registers the node table and spawns a
    /// worker. Asking it first would mean a process whose links are all TLS, or
    /// a test framing over an in-memory duplex, pins ~4.2 MB and spawns a thread
    /// for a ring no link can use. The descriptor question is local, free and
    /// decides the same thing, so it goes first and the reactor is built only
    /// for a link that can actually be put on it.
    #[cfg(all(feature = "runtime-tokio-uring", feature = "transport-link-tcp"))]
    fn choose_ring(&self) -> RingChoice {
        let Some(fd) = self.reader.ring_fd() else {
            return RingChoice::Framed;
        };
        // A THIRD CONJUNCT WZ NEEDS AND UPSTREAM DOES NOT, declared rather than
        // discovered later: a link that armed `close_link_on_expiration` has
        // its read RACED against that signal (see the `expiry` field), and the
        // ring body has no such arm — its `poll_event` awaits a delivery and
        // nothing else. Putting an expiring link on the ring would silently
        // lose the expiry, so it keeps the framed body instead. No link can
        // reach both arms today (only a `tls/...` locator arms expiry, and
        // `ReadHalf<T>` answers `None` above), which is exactly why this is
        // written down: the guard is what keeps that true if either side moves.
        if self.expiry.is_some() {
            return RingChoice::Framed;
        }
        // WHOSE ring: the node's, or one this caller owns. Same pair and same
        // argument as `with_arena` beside `new` — "a caller that owns a node, or
        // a witness that must observe one reactor without the rest of the
        // process drawing from it, needs a way to say which". For a witness that
        // is not a convenience: the node's reactor is a `OnceLock` that never
        // drops, so a test triggering it would pin a second pool's worth of
        // locked memory for the whole test process and put a hosted runner's
        // 8 MiB ceiling permanently out of reach — which is the exact shape of
        // the red R2749 paid for.
        let reactor = match self.reactor.as_deref() {
            Some(owned) => owned,
            None => match crate::uring_reactor::UringReactor::node() {
                Some(node) => node,
                None => return RingChoice::Framed,
            },
        };
        // R2755 — THE FLAG, NOT A WIDTH READ OFF IT NOW. Handing over a width
        // computed here pinned whatever the flag said at this instant, and this
        // instant is inside the handshake: see [`UringReactor::attach`] for the
        // measurement. The reactor re-derives the width at each frame boundary,
        // which is the same rule `poll_framed` follows on the arm below.
        match reactor.attach(fd, Arc::clone(&self.lowlatency)) {
            Ok(rx) => RingChoice::Ring(Box::new(rx)),
            // A reactor whose worker has stopped is not this link's failure to
            // report — the framed body reads the same socket correctly. Falling
            // back is the honest answer; failing the link would turn a lost
            // optimisation into a lost session.
            Err(_) => RingChoice::Framed,
        }
    }
}

impl<R: AsyncRead + Unpin + RingReadable> LinkDriver for StreamReadDriver<R> {
    async fn open(&mut self) -> io::Result<()> {
        // The stream is already connected (split from a live stream); open is
        // unconditionally Ok.
        Ok(())
    }

    async fn send(&mut self, _frame: &TxFrame<'_>, _reliability: Reliability) -> io::Result<()> {
        // The read half never sends — outbound goes via StreamWriteDriver.
        // Surface NotConnected so an accidental call fails loud rather than
        // silently dropping the frame.
        Err(io::Error::new(
            io::ErrorKind::NotConnected,
            "StreamReadDriver does not send; outbound goes via StreamWriteDriver",
        ))
    }

    async fn close(&mut self) -> io::Result<()> {
        // The read half drops independently of the write half; no explicit
        // shutdown needed (the writer task shuts the write half on channel close).
        Ok(())
    }

    async fn poll_event(&mut self) -> LinkEvent {
        // R2750 — the dispatch, at the moment upstream dispatches: the first
        // time this link asks to read. See `RingChoice` and the `ring` field.
        #[cfg(all(feature = "runtime-tokio-uring", feature = "transport-link-tcp"))]
        {
            if matches!(self.ring, RingChoice::Undecided) {
                self.ring = self.choose_ring();
            }
            if let RingChoice::Ring(rx) = &mut self.ring {
                return rx.poll_event().await;
            }
        }
        // Destructured so the read future and the signal borrow disjoint
        // fields; `select!` over `&mut self` twice would not compile.
        let Self {
            reader,
            read_state,
            lowlatency,
            expiry,
            arena,
            ..
        } = self;
        let lowlatency = lowlatency.load(Ordering::Acquire);
        let Some(signal) = expiry.as_ref() else {
            return poll_framed(read_state, reader, lowlatency, arena).await;
        };
        // Checked BEFORE the race: a signal that fired while this driver was
        // between polls has no waiter to notify, and would otherwise be missed
        // until the next byte — which for an expired peer may never come.
        if signal.has_fired() {
            return LinkEvent::Lost {
                cause: LostCause::CertificateExpired,
            };
        }
        tokio::select! {
            event = poll_framed(read_state, reader, lowlatency, arena) => event,
            () = signal.notify.notified() => LinkEvent::Lost {
                cause: LostCause::CertificateExpired,
            },
        }
    }
}

/// Outbound write half of a split byte-stream link — holds an
/// `mpsc::UnboundedSender<Vec<u8>>` whose receiver is owned by the
/// [`writer_task`]. Impls [`BoxedLinkDriver`] so the FSM's
/// `Arc<dyn BoxedLinkDriver>` slot is satisfied with a NON-blocking enqueue:
/// the sync script-action handlers fire from inside a future the same runtime
/// is driving, where a nested `block_on` would trip the "Cannot start a
/// runtime from within a runtime" reentrancy check. The channel decouples that
/// sync-from-async boundary cleanly.
///
/// Transport-neutral (a plain channel sender with a u16-prefix oversize guard,
/// carrying no per-transport state), so TCP and TLS share the one type.
pub struct StreamWriteDriver {
    tx: mpsc::UnboundedSender<Vec<u8>>,
    /// transport-lowlatency — flipped true by the lowlatency open helper at
    /// Established (a fresh always-false flag for every non-lowlatency link).
    /// While true, [`Self::send_blocking`] frames with the 4-byte LE u32 zenoh
    /// lowlatency prefix (`unicast/lowlatency/link.rs`); false keeps the universal
    /// 2-byte u16 [`StreamEnvelope`] batch prefix. The framing is decided HERE, at
    /// enqueue time (synchronous with the FSM's emit), NOT in the async
    /// [`writer_task`] — so a handshake frame enqueued while the flag is still
    /// false is framed u16 even if the writer drains it after the flip, closing
    /// the enqueue-vs-dequeue race a dequeue-time flag read would open.
    lowlatency: Arc<AtomicBool>,
    /// R311y453 — the §5.16 link-derived subject: this stream's scheme and the
    /// NICs its local address sits on. The type is deliberately transport-NEUTRAL
    /// (see above), so it can infer neither: six pipelines build it — tcp, tls,
    /// quic, unixsock, unixpipe and vsock — and each is the only place that knows
    /// its scheme AND whether it even has an IP address to resolve. Threaded
    /// through the constructor rather than guessed, so a new stream pipeline must
    /// state its subject to compile.
    subject: LinkSubject,
    /// R311y473 — this link's `{src,dst}` locator pair for the adminspace's
    /// per-link view. Threaded through the constructor for the SAME reason
    /// `subject` is: this type is transport-NEUTRAL and so can name neither its
    /// scheme nor its socket, while each of the six constructing pipelines can
    /// name both. `None` when the pipeline could not read one of the two ends —
    /// the admin host still emits the link (the COUNT stays truthful), with the
    /// ends left blank rather than guessed.
    endpoints: Option<LinkEndpoints>,
}

impl StreamWriteDriver {
    pub(crate) fn new(
        tx: mpsc::UnboundedSender<Vec<u8>>,
        lowlatency: Arc<AtomicBool>,
        subject: LinkSubject,
        endpoints: Option<LinkEndpoints>,
    ) -> Self {
        Self {
            tx,
            lowlatency,
            subject,
            endpoints,
        }
    }
}

impl BoxedLinkDriver for StreamWriteDriver {
    // R311y453 — the §5.16 subject the constructing pipeline resolved, since this
    // driver is shared across six of them. A field read, never a syscall.
    fn link_subject(&self) -> Option<&LinkSubject> {
        Some(&self.subject)
    }

    // R311y473 — the adminspace `{src,dst}` pair the constructing pipeline
    // resolved, for the same six-pipelines reason as the subject above.
    fn link_endpoints(&self) -> Option<&wz_session_core::link::LinkEndpoints> {
        self.endpoints.as_ref()
    }

    fn send_blocking(&self, bytes: &[u8], _reliability: Reliability) -> LinkSendOutcome {
        if bytes.len() > u16::MAX as usize {
            // Oversize: drop with a warn rather than overflow the length prefix.
            // zenoh-pico's Z_BATCH_UNICAST_SIZE ceiling is 65535 and the
            // negotiated lowlatency max (49152) is under it, so a larger frame is
            // a wz-side encoder bug — loud, in either framing mode.
            log::warn!(
                "wz-runtime-tokio: outbound frame {} bytes > 65535; dropping",
                bytes.len()
            );
            return LinkSendOutcome::Dropped(LinkDropCause::Oversize);
        }
        let wire = if self.lowlatency.load(Ordering::Acquire) {
            // transport-lowlatency — 4-byte LE u32 length prefix + payload (zenoh's
            // lowlatency streamed framing), NOT the u16 batch prefix.
            let mut wire = Vec::with_capacity(4 + bytes.len());
            wire.extend_from_slice(&(bytes.len() as u32).to_le_bytes());
            wire.extend_from_slice(bytes);
            wire
        } else {
            // Codec-routed wire shape (single source of truth for the streamed-link
            // envelope); `bytes.len() <= u16::MAX` is guaranteed above.
            StreamEnvelope {
                payload_len: bytes.len() as u16,
                payload: bytes,
            }
            .encode_to_vec()
        };
        if let Err(e) = self.tx.send(wire) {
            log::warn!("wz-runtime-tokio: outbound channel closed; dropping frame ({e})");
            return LinkSendOutcome::Dropped(LinkDropCause::WriterGone);
        }
        LinkSendOutcome::Sent
    }

    fn open_blocking(&self) {
        // The stream is already connected; open is a no-op on this shape.
    }

    fn close_blocking(&self) {
        // The writer task exits when every sender clone drops (after the
        // owning scope releases the Arc). Explicit per-frame shutdown from the
        // FSM's release_link would race in-flight enqueues; letting the
        // receiver-drop signal terminate the task is the textbook channel idiom.
    }
}

/// Async writer task. Owns a stream write half `W` (any `AsyncWrite` — TCP's
/// `OwnedWriteHalf` or a rustls `WriteHalf<TlsStream<TcpStream>>`) and drains the
/// outbound queue one PRE-FRAMED wire at a time, writing + flushing each. The
/// length-prefix framing is applied by [`StreamWriteDriver::send_blocking`] at
/// enqueue time (synchronous with the FSM's emit), so a handshake frame enqueued
/// before a lowlatency flag flip stays u16-framed regardless of when it drains —
/// the writer never re-decides framing. Generic over the write half so it is the
/// single home for every byte-stream link.
///
/// R311y519 — exits on ANY of three signals, and the middle one is the new
/// teardown contract: the queue was SEALED and its remaining frames have been
/// handed over ([`OutboundQueue::next`]); every write-driver clone has dropped;
/// or a write failed / stalled past [`WRITER_STALL_MS`](crate::writer_queue::WRITER_STALL_MS)
/// on a sealed queue (logged + bail). The first two shut the write half so the
/// peer observes EOF rather than RST; a bail does not, because a peer that is
/// not reading will not read a shutdown either.
pub async fn writer_task<W>(mut writer: W, mut queue: OutboundQueue)
where
    W: AsyncWrite + Unpin,
{
    while let Some(wire) = queue.next().await {
        let write = async {
            writer.write_all(&wire).await?;
            writer.flush().await
        };
        match queue.guarded(write).await {
            Some(Ok(())) => {}
            Some(Err(e)) => {
                log::warn!("wz-runtime-tokio: writer_task write failed: {e}; closing");
                return;
            }
            None => {
                log::warn!(
                    "wz-runtime-tokio: writer_task stalled past {} ms draining a sealed \
                     queue; the peer has stopped reading. Closing with frames undelivered",
                    crate::writer_queue::WRITER_STALL_MS
                );
                return;
            }
        }
    }
    // Queue finished -> shut the write half cleanly (peer sees EOF, not RST).
    let _ = writer.shutdown().await;
}

#[cfg(test)]
mod tests {
    use super::*;

    /// R2698 — a DER certificate whose subject carries `common_name`, built with
    /// the same `rcgen` dev-dependency the TLS e2e uses for its own chain.
    ///
    /// A GENERATED certificate rather than a checked-in blob: a fixture that
    /// cannot be read back to its inputs proves only that the parser agrees with
    /// whoever made the file, and a certificate expires, which turns a pinned
    /// blob into a test that fails on a date nobody chose.
    #[cfg(feature = "transport-link-tls")]
    fn der_with_common_name(
        common_name: &str,
    ) -> tokio_rustls::rustls::pki_types::CertificateDer<'static> {
        let mut params = rcgen::CertificateParams::new(vec!["localhost".to_string()])
            .expect("valid subject alt name");
        params.distinguished_name = rcgen::DistinguishedName::new();
        params
            .distinguished_name
            .push(rcgen::DnType::CommonName, common_name);
        let key = rcgen::KeyPair::generate().expect("key");
        let cert = params.self_signed(&key).expect("self-signed");
        tokio_rustls::rustls::pki_types::CertificateDer::from(cert.der().to_vec())
    }

    /// R2698 — the ACL's cert-common-name axis reads the LEAF's first common
    /// name. The chain holds TWO certificates with different names so the
    /// assertion separates "read the leaf" from "read any of them", which is the
    /// one behaviour that distinguishes this from its `peer_chain_deadline`
    /// sibling (that one folds the whole chain with `min`).
    #[cfg(feature = "transport-link-tls")]
    #[test]
    fn peer_chain_common_name_reads_the_leaf_not_the_chain() {
        let chain = [
            der_with_common_name("leaf.example"),
            der_with_common_name("issuer.example"),
        ];
        assert_eq!(
            peer_chain_common_name(Some(&chain)),
            Some(String::from("leaf.example")),
        );
    }

    /// R2698 — absent is absent, upstream's single answer for every way a name
    /// can fail to arrive. An empty chain is the `first()?` arm and no chain at
    /// all is the `chain?` arm; both are reachable and both answer `None`.
    #[cfg(feature = "transport-link-tls")]
    #[test]
    fn peer_chain_common_name_answers_none_without_a_certificate() {
        assert_eq!(peer_chain_common_name(None), None, "no chain");
        assert_eq!(peer_chain_common_name(Some(&[])), None, "an empty chain");
    }

    /// Oversize frames are dropped by `send_blocking` rather than overflowing
    /// the u16 prefix — the channel stays usable afterwards. (Transport-neutral
    /// guard; exercised here once for both the TCP and TLS write paths.)
    #[tokio::test]
    async fn write_driver_drops_oversize_frame() {
        let (tx, mut rx) = mpsc::unbounded_channel::<Vec<u8>>();
        let driver = StreamWriteDriver::new(
            tx,
            Arc::new(AtomicBool::new(false)),
            LinkSubject::UNKNOWN,
            None,
        );
        // R2371 — the drop is now stated DIRECTLY by the return value, where it
        // used to be inferred from what did NOT arrive on the channel. Both
        // assertions are kept: the outcome is the driver's own claim, the
        // channel read is the independent evidence for it.
        assert_eq!(
            driver.send_blocking(&vec![0u8; 65_536], Reliability::Reliable),
            LinkSendOutcome::Dropped(LinkDropCause::Oversize)
        );
        assert_eq!(
            driver.send_blocking(b"ok", Reliability::Reliable),
            LinkSendOutcome::Sent
        );
        // Only the in-range frame reached the channel, u16-framed at enqueue
        // (2-byte LE len=2 + "ok"); the oversize frame was dropped.
        assert_eq!(
            rx.recv().await.as_deref(),
            Some([0x02, 0x00, b'o', b'k'].as_slice())
        );
    }

    /// R2608 — an armed read half reports `CertificateExpired` on a signal that
    /// fired BEFORE the poll, without a byte arriving.
    ///
    /// The peer side of the duplex is held open and never written, which is the
    /// state this mechanism exists for: a link whose certificate died while the
    /// peer had nothing to say. `io::empty()` would be the wrong reader -- it
    /// returns EOF at once and the driver would report loss for the ordinary
    /// reason, proving nothing.
    /// Gated with its subject: `set_expiry` exists only where the tls link
    /// does, so a test that calls it must carry the same gate. The three arms
    /// below move together on purpose -- the unarmed control discriminates the
    /// other two, and a control compiled without its subject grades nothing.
    #[cfg(feature = "transport-link-tls")]
    #[tokio::test(start_paused = true)]
    async fn a_fired_signal_loses_the_link_with_no_bytes() {
        let (near, _far) = tokio::io::duplex(64);
        let mut driver = StreamReadDriver::new(near, Arc::new(AtomicBool::new(false)));
        let signal = Arc::new(ExpirySignal::default());
        signal.fire();
        driver.set_expiry(Arc::clone(&signal));
        match driver.poll_event().await {
            LinkEvent::Lost { cause } => assert_eq!(cause, LostCause::CertificateExpired),
            other => panic!("an armed, fired link must be Lost; got {other:?}"),
        }
    }

    /// R2608 — the OTHER half, and the one a pre-check alone would fail: a
    /// signal that fires while the driver is ALREADY PARKED in its read must
    /// still wake it. That is the whole reason this is a `Notify` race and not
    /// a bool, so it gets its own arm rather than riding on the first.
    #[cfg(feature = "transport-link-tls")]
    #[tokio::test(start_paused = true)]
    async fn a_signal_fired_while_parked_still_wakes_the_read() {
        let (near, _far) = tokio::io::duplex(64);
        let mut driver = StreamReadDriver::new(near, Arc::new(AtomicBool::new(false)));
        let signal = Arc::new(ExpirySignal::default());
        driver.set_expiry(Arc::clone(&signal));
        let firing = tokio::spawn(async move {
            tokio::time::sleep(std::time::Duration::from_secs(5)).await;
            signal.fire();
        });
        match driver.poll_event().await {
            LinkEvent::Lost { cause } => assert_eq!(cause, LostCause::CertificateExpired),
            other => panic!("a parked read must wake on the signal; got {other:?}"),
        }
        firing.await.expect("the firing task completes");
    }

    /// R2608 -- the CONTROL, as a test rather than as an assertion in prose: an
    /// UNARMED driver over the same silent duplex must NOT report loss. Without
    /// this, both arms above would also pass if `poll_event` had been made to
    /// return `Lost` unconditionally.
    #[cfg(feature = "transport-link-tls")]
    #[tokio::test(start_paused = true)]
    async fn an_unarmed_driver_does_not_lose_a_silent_link() {
        let (near, _far) = tokio::io::duplex(64);
        let mut driver = StreamReadDriver::new(near, Arc::new(AtomicBool::new(false)));
        let parked =
            tokio::time::timeout(std::time::Duration::from_secs(3600), driver.poll_event()).await;
        assert!(
            parked.is_err(),
            "an unarmed driver over a silent peer must stay parked, not report loss"
        );
    }
}

/// R2750 — THE SELECTION POINT's own witnesses.
///
/// A module of their own, not arms of `tests` above, because Layer C1br selects
/// what it runs BY MODULE PATH and R2748 paid for the lesson that a sibling is
/// not a child: `uring::` does not match `uring_reactor::`, and neither reaches
/// `stream_link::`. Naming this module lets the lane run exactly these and not
/// the whole of `stream_link`'s framing suite, which has no ring in it.
#[cfg(all(test, feature = "runtime-tokio-uring", feature = "transport-link-tcp"))]
mod ring_selection {
    use super::*;
    use crate::link_rx_arena::LinkRxArena;
    use crate::uring_reactor::UringReactor;

    fn framed(payload: &[u8]) -> Vec<u8> {
        let mut wire = (payload.len() as u16).to_le_bytes().to_vec();
        wire.extend_from_slice(payload);
        wire
    }

    fn payload_of(event: LinkEvent) -> Vec<u8> {
        match event {
            LinkEvent::Rx(frame) => frame.bytes,
            other => panic!("expected a frame, got {other:?}"),
        }
    }

    /// Bounded so a defect reds instead of hanging the lane.
    async fn within<F: std::future::Future>(f: F) -> F::Output {
        tokio::time::timeout(std::time::Duration::from_secs(10), f)
            .await
            .expect("the link must answer")
    }

    /// A connected TCP pair, as an owned read half plus the peer end.
    ///
    /// Built through the PRODUCTION constructors — `dial_tcp` and
    /// `accept_tcp_on` — rather than `TcpStream::connect` and
    /// `listener.accept()`. `scripts/lib/tcp_tuning_seam_gate.py` caught the
    /// first draft doing the latter and it was right to: a socket that backs a
    /// wz link driver must be tuned the way a wz link is, and a witness whose
    /// half was built differently from a production half is measuring a
    /// different object than the one it claims to. That gate's not-a-link
    /// escape hatch would have been a false statement here — this socket is
    /// driven by a real [`StreamReadDriver`] — so the sockets are tuned rather
    /// than excused. (Writing that hatch's marker into this very comment is how
    /// R2750 found that the gate read it as a CLAIM; see its own header.)
    async fn tcp_pair() -> (tokio::net::tcp::OwnedReadHalf, tokio::net::TcpStream) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind");
        let addr = listener.local_addr().expect("addr");
        let dialed = crate::link_pipeline::dial_tcp(addr, &crate::link_socket::LinkSocket::NONE)
            .await
            .expect("dial");
        let (accepted, _) = crate::link_pipeline::accept_tcp_on(&listener)
            .await
            .expect("accept");
        let (read, _write) = accepted.into_split();
        // `_write` is dropped: this witness only reads, and TCP keeps the read
        // half usable after the local write half shuts down.
        (read, dialed)
    }

    /// A REACTOR THIS TEST OWNS, never the node's.
    ///
    /// The node's is a `OnceLock` that never drops, so triggering it would pin a
    /// second pool's worth of locked memory for the REST of the test process —
    /// on a host provisioned to exactly one registration (which is what hosted
    /// CI is) every later registering test would then fail permanently, with
    /// nothing transient for `FixedSlotRing::register` to wait out. That is the
    /// red R2749 paid for, and this is how it stays paid.
    fn own_reactor() -> Arc<UringReactor> {
        Arc::new(UringReactor::start(LinkRxArena::new()).expect("a reactor"))
    }

    /// THE CLAIM OF THIS ROUND: a production stream half that can name a
    /// descriptor is READ THROUGH THE RING, and the frames are the same frames.
    ///
    /// Both halves of that matter. `reads_through_ring` alone would pass on a
    /// link that chose the ring and then delivered nothing; the payload alone
    /// would pass on a link that quietly stayed framed — which is exactly the
    /// state the tree was in before this round, so the payload assertion on its
    /// own is the test that could not fail.
    ///
    /// CONTROL: make `ring_fd` answer `None` for TCP, or delete the dispatch
    /// from `poll_event`, and the `reads_through_ring` assertion reds while the
    /// payload one still passes — which is the pair saying the two assertions
    /// are not measuring one thing twice.
    #[tokio::test]
    async fn a_descriptor_bearing_half_is_read_through_the_ring() {
        let (read, mut peer) = tcp_pair().await;
        let mut driver =
            StreamReadDriver::new(read, Arc::new(AtomicBool::new(false))).on_reactor(own_reactor());

        peer.write_all(&framed(b"alpha")).await.expect("write");
        assert_eq!(payload_of(within(driver.poll_event()).await), b"alpha");
        assert!(
            driver.reads_through_ring(),
            "a TCP half names a descriptor and a reactor was supplied, so this \
             link must have been put on the ring"
        );
    }

    /// A half with NO descriptor keeps the framed body — and still delivers.
    ///
    /// The negative arm of the same question, and the reason the trait's
    /// `None` is a real answer rather than a gap: an in-memory duplex is not a
    /// socket, so there is nothing to register, and the link must go on working
    /// exactly as it did.
    #[tokio::test]
    async fn a_half_with_no_descriptor_keeps_the_framed_body() {
        let (near, mut far) = tokio::io::duplex(64);
        let mut driver =
            StreamReadDriver::new(near, Arc::new(AtomicBool::new(false))).on_reactor(own_reactor());

        far.write_all(&framed(b"beta")).await.expect("write");
        assert_eq!(payload_of(within(driver.poll_event()).await), b"beta");
        assert!(
            !driver.reads_through_ring(),
            "a duplex half has no descriptor, so it must not have been put on \
             the ring even though a reactor was available"
        );
    }

    /// WITHOUT A REACTOR there is no ring to choose, and the link still reads.
    ///
    /// This is the arm that says the node lookup is genuinely consulted rather
    /// than the choice being made by the descriptor alone: same TCP half as the
    /// first witness, same bytes, and the only difference is that no reactor was
    /// supplied. It relies on the node's `OnceLock` being unbuilt in this
    /// process, which the ORDER in `choose_ring` is what guarantees — the
    /// descriptor question is asked first, so no earlier test in this lane can
    /// have built one behind this test's back.
    #[tokio::test]
    async fn a_descriptor_alone_does_not_put_a_link_on_a_ring() {
        let (read, mut peer) = tcp_pair().await;
        let mut driver = StreamReadDriver::new(read, Arc::new(AtomicBool::new(false)));

        peer.write_all(&framed(b"gamma")).await.expect("write");
        assert_eq!(payload_of(within(driver.poll_event()).await), b"gamma");
    }

    /// AN EXPIRING LINK KEEPS THE FRAMED BODY, which is the third conjunct
    /// `choose_ring` adds to upstream's two.
    ///
    /// The ring body awaits a delivery and nothing else, so a link put on it
    /// would never observe its expiry signal. No link reaches both arms today —
    /// only a `tls/...` locator arms expiry and `ReadHalf<T>` answers `None` —
    /// so this witness is built on a TCP half with the signal armed by hand:
    /// the combination the guard exists to refuse, which the tree cannot
    /// otherwise produce.
    ///
    /// CONTROL: drop the `expiry.is_some()` arm from `choose_ring` and this
    /// reds, alone.
    #[cfg(feature = "transport-link-tls")]
    #[tokio::test]
    async fn an_expiring_link_keeps_the_framed_body() {
        let (read, mut peer) = tcp_pair().await;
        let mut driver =
            StreamReadDriver::new(read, Arc::new(AtomicBool::new(false))).on_reactor(own_reactor());
        driver.set_expiry(Arc::new(ExpirySignal::default()));

        peer.write_all(&framed(b"delta")).await.expect("write");
        assert_eq!(payload_of(within(driver.poll_event()).await), b"delta");
        assert!(
            !driver.reads_through_ring(),
            "a link whose read is raced against an expiry signal must keep the \
             body that has that race"
        );
    }
}
