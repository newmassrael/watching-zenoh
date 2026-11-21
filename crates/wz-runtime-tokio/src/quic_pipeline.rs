// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! R311xk — QUIC session-open transport pipeline.
//!
//! The QUIC sibling of [`crate::tls_pipeline`]. zenoh-link-quic carries a zenoh
//! batch over a bidirectional QUIC stream (`max_concurrent_bidi_streams = 1`),
//! and, when the connection negotiates a multistream protocol, carries each
//! priority above Control on a unidirectional stream of its own, every stream
//! with the SAME StreamEnvelope length-prefix framing as TCP/TLS
//! (`is_streamed() = true`, MTU `BatchSize::MAX`,
//! `io/zenoh-links/zenoh-link-quic/src/unicast.rs` @ `fn is_streamed`). The
//! protocols a link offers follow its locator's `multistream` and `mixed_rel`
//! keys ([`crate::quic_config::alpn_offer`]). So the read/write
//! drivers in [`crate::stream_link`] are reused UNCHANGED: a
//! [`quinn::RecvStream`] is `AsyncRead`, a [`quinn::SendStream`] is
//! `AsyncWrite`, and they are ALREADY a split pair (`open_bi`/`accept_bi`
//! return both) — so unlike TCP (`into_split`) / TLS (`tokio::io::split`) this
//! module needs no split call at all.
//!
//! ## The datagram companion of a mixed-reliability link
//!
//! A connection that negotiated `zenoh-mr` or `zenoh-ms-mr` carries its
//! best-effort batches on the connection's datagrams, one batch to a datagram
//! with no length in front, and its reliable batches on its streams, as
//! upstream's QUIC link pairs itself with a datagram link over the same
//! connection (`io/zenoh-link-commons/src/quic/unicast.rs` @
//! `PROTOCOL_MIXED_REL | PROTOCOL_MULTI_STREAM_MIXED_REL => true,`). The session
//! already keeps a frame to one reliability class and hands it over with that
//! class, so the class is what routes it: [`QuicWriteDriver`] puts a
//! best-effort frame on a datagram and every other on the streams' queue, and
//! the read driver reads the datagrams beside the streams. No second queue
//! orders the datagrams: quinn takes one without waiting, and the session's
//! conduits already hand frames over in priority order. A best-effort frame is
//! never held back by the streams' room, and the session keeps the companion
//! alive by its own last write and keepalive, since the peer leases it on its
//! own (`BoxedLinkDriver::carries_apart`).
//!
//! ## QUIC endpoint lifecycle (the wz keep-alive wrinkle)
//!
//! Unlike a TCP/unixsock/vsock socket (where the stream owns the OS fd), a QUIC
//! [`quinn::SendStream`]/[`RecvStream`] references its [`quinn::Connection`],
//! which references the [`quinn::Endpoint`]'s background driver (the UDP socket
//! pump). Dropping the `Endpoint` or `Connection` while the link is live would
//! tear the link down. Both are cheap `Clone` handles (Arc inside), so
//! [`QuicReadDriver`] holds a clone of each as a keep-alive for the link's
//! lifetime (the session-long inbound side). This is the QUIC analogue of WS's
//! bespoke `WsReadDriver` struct — a transport-specific read driver wrapping the
//! shared [`StreamReadDriver`] plus the resources the link must outlive.
//!
//! ## Certs ride the dial seam (not the locator), like TLS
//!
//! QUIC mandates TLS 1.3; its rustls config (TLS-1.3-only + the ALPN offer) is
//! built by [`crate::quic_config`]. The dial needs cert material a `quic/...`
//! locator cannot carry, so — exactly like TLS (R311oc) — it is threaded via
//! [`crate::session_open::DialConfig`]`.quic`; a `quic/...` locator with no such
//! config dials to a typed `Unsupported`.

use std::io;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Instant;

use bytes::Bytes;
use futures_util::stream::{SelectAll, Stream};
use futures_util::{FutureExt, StreamExt};
use quinn::crypto::rustls::{QuicClientConfig, QuicServerConfig};
use quinn::{
    ClientConfig as QuinnClientConfig, Connection, Endpoint, Incoming, RecvStream,
    SendDatagramError, SendStream, ServerConfig as QuinnServerConfig, TransportConfig,
};
use tokio::io::AsyncWriteExt;
use tokio_rustls::rustls::{
    ClientConfig as RustlsClientConfig, ServerConfig as RustlsServerConfig,
};

use crate::frame_arena::{link_arena, link_arena_settler, LinkArena};
use crate::link_interfaces::ip_link_subject;
use crate::link_socket::LinkSocket;
use crate::quic_config::{alpn_offer, client_offering, server_offering};
use crate::stream_link::{write_wire, writer_task, StreamReadDriver, StreamWriteDriver};
use crate::writer_queue::{OutboundQueue, WriterHandle};
use crate::{LinkDriver, LinkEvent, LostCause, Reliability, RxBytes, RxFrame, RxStorage, TxFrame};
use wz_session_core::link::{
    BoxedLinkDriver, LinkDropCause, LinkEndpoints, LinkKind, LinkRoom, LinkSendOutcome,
    LinkSubject, RoomAnswer, RoomPermit, RoomWait, TxQueueShape, TxSlot, TxSlotGrant,
};
use wz_session_core::locator::{QuicAlpn, QuicStreamChoice, QuicStreams};
use wz_session_core::qos::Priority;

/// R2600 — the EARLIEST `not_after` in the peer's certificate chain, as Unix
/// seconds, or `None` when the peer presented no chain.
///
/// ⚠ THE FOLD IS THE POINT, and it is the one line easy to drop when porting
/// this: upstream takes the MINIMUM over the whole chain, not the leaf's value
/// (`io/zenoh-link-commons/src/quic/utils.rs` @ `pub fn get_cert_chain_expiration(conn: &quinn::Connection) -> ZResult<Option<OffsetDateTime>> {`).
/// A chain whose intermediate CA expires before its leaf must die with the
/// intermediate; reading the leaf alone would keep a link upstream drops.
///
/// Unix SECONDS rather than upstream's `OffsetDateTime`, because
/// `ASN1Time::timestamp` already yields them and `std::time` compares them —
/// the same instant in a representation that costs wz no extra declared crate.
///
/// A certificate that fails to parse is SKIPPED rather than fataled: rustls
/// validated this chain during the handshake, so a parse failure here is this
/// reader disagreeing with rustls, not a bad peer. Skipping keeps the earliest
/// of what IS readable, which can only close a link earlier than the truth,
/// never later — the safe direction for a key whose whole purpose is to stop
/// trusting an expired identity.
/// R2602 — also gated on `transport-unicast`: the whole expiry seam is reached
/// only from `session_open`, which is `all(transport-link-tcp, transport-unicast)`,
/// and `transport-link-quic` implies tcp but NOT unicast. Layer C1ac builds
/// exactly that combination with `-D warnings`, where these are dead code.
#[cfg(all(feature = "transport-link-quic", feature = "transport-unicast"))]
pub(crate) fn peer_chain_expiry(connection: &Connection) -> Option<i64> {
    use x509_parser::prelude::{FromDer, X509Certificate};

    let identity = connection.peer_identity()?;
    let chain = identity
        .downcast::<Vec<tokio_rustls::rustls::pki_types::CertificateDer>>()
        .ok()?;
    chain
        .iter()
        .filter_map(|cert| {
            X509Certificate::from_der(cert.as_ref())
                .ok()
                .map(|(_, parsed)| parsed.validity().not_after.timestamp())
        })
        .min()
}

/// R2698 — the COMMON NAME on the peer's LEAF certificate over QUIC, or `None`.
///
/// The sibling of [`peer_chain_expiry`] above: same `peer_identity` downcast,
/// same parser, and the leaf-versus-whole-chain split its TLS twin
/// (`crate::stream_link::peer_chain_common_name`) explains — an expiry is a
/// property of the chain, an identity is a property of the peer. Upstream keeps
/// the same pair for the same reason
/// (`io/zenoh-link-commons/src/quic/utils.rs` @ `pub fn get_cert_common_name`).
///
/// ⚠ ITS `#[cfg]` IS ITS CALLER'S, not its sibling's, and the difference is
/// load-bearing. [`peer_chain_expiry`] carries
/// `all(transport-link-quic, transport-unicast)` because `session_open` is
/// where it is used; this one is called from [`wire_quic_stream`] below, which
/// the module gate alone reaches. Copying the wider gate would make it dead
/// code in a `transport-link-quic`-only build, which `-D warnings` fails and
/// neither the default nor the all-features leg would have shown.
pub(crate) fn peer_chain_common_name(connection: &Connection) -> Option<String> {
    use x509_parser::prelude::{FromDer, X509Certificate};

    let identity = connection.peer_identity()?;
    let chain = identity
        .downcast::<Vec<tokio_rustls::rustls::pki_types::CertificateDer>>()
        .ok()?;
    let leaf = chain.first()?;
    let (_, parsed) = X509Certificate::from_der(leaf.as_ref()).ok()?;
    // The FIELD rather than the `subject()` accessor, for the borrow reason its
    // TLS twin records.
    let common_name = parsed
        .subject
        .iter_common_name()
        .next()
        .and_then(|cn| cn.as_str().ok())?;
    Some(common_name.to_string())
}

/// The zid the public key of the peer's LEAF certificate names, or `None` —
/// [`peer_chain_common_name`]'s sibling over the same downcast, and its TLS
/// twin's (`crate::stream_link::peer_chain_credential_zid`) over a QUIC
/// connection. Gated by its caller, as that sibling is.
pub(crate) fn peer_chain_credential_zid(
    connection: &Connection,
) -> Option<[u8; wz_session_core::credential_identity::CREDENTIAL_ZID_BYTES]> {
    use x509_parser::prelude::{FromDer, X509Certificate};

    let identity = connection.peer_identity()?;
    let chain = identity
        .downcast::<Vec<tokio_rustls::rustls::pki_types::CertificateDer>>()
        .ok()?;
    let leaf = chain.first()?;
    let (_, parsed) = X509Certificate::from_der(leaf.as_ref()).ok()?;
    Some(wz_session_core::credential_identity::zid_from_spki_der(
        parsed.tbs_certificate.subject_pki.raw,
    ))
}

// R2608 — the cap moved with the loop it bounds, to
// `crate::stream_link::EXPIRY_MAX_SLEEP`. A constant separated from its only
// reader is the shape that goes stale unnoticed, so it travelled rather than
// being left behind pointing at nothing.

/// R2608 — the loop moved to [`crate::stream_link::sleep_until_unix`] when tls
/// became its second consumer. Re-exported under the old name so this module's
/// call site reads unchanged, and so the clock reasoning lives in ONE file.
#[cfg(all(feature = "transport-link-quic", feature = "transport-unicast"))]
use crate::stream_link::sleep_until_unix;

/// R2600 — arm `close_link_on_expiration` for one QUIC link.
///
/// Takes a CLONE of the `quinn::Connection`, which is a cheap Arc handle, so
/// this needs none of upstream's `LinkWithCertExpiration` trait, `Weak` and
/// `CancellationToken` machinery — wz's structure already carries the signal.
/// Closing the connection makes the peer's `RecvStream` read fail, which
/// `poll_framed` turns into a `LinkEvent::Lost`, which is what the session FSM
/// already consumes.
///
/// ⚠ MEASURED, and named because it is a real divergence: quinn maps a closed
/// connection to `io::ErrorKind::NotConnected`
/// (`quinn-0.11.11/src/recv_stream.rs` @ `ConnectionLost(_) | ClosedStream => io::ErrorKind::NotConnected,`),
/// so the link is lost with `LostCause::OsError` rather than a cause naming
/// expiry. The link DOES die, which is the behaviour the key promises; the
/// cause is coarser than upstream's dedicated `expire()` path.
///
/// The subsystem is `Net` — network-tier background upkeep, which is what a
/// per-link clock watcher is. Upstream puts its own on `Acceptor`, but wz's
/// `Acceptor` is specifically the listen/accept loops and this task belongs to
/// neither that nor the caller's path.
#[cfg(all(feature = "transport-link-quic", feature = "transport-unicast"))]
pub(crate) fn arm_expiry_close(connection: &Connection) {
    let Some(deadline) = peer_chain_expiry(connection) else {
        // No chain, nothing to expire. Upstream answers `None` here too rather
        // than treating an absent chain as an immediate expiry.
        return;
    };
    let conn = connection.clone();
    crate::runtime_pool::WzRuntime::Net.spawn(async move {
        sleep_until_unix(deadline).await;
        conn.close(0u32.into(), b"certificate chain expired");
    });
}

/// A dialed / accepted QUIC link: the endpoint + connection (kept alive for the
/// link) and the single bidirectional stream's split halves. Produced by
/// [`dial_quic`] (client) / [`accept_quic_on`] (server) and consumed by
/// [`wire_quic_stream`].
pub struct QuicLink {
    /// The QUIC endpoint (UDP socket + driver). A `Clone` handle; kept alive
    /// because the connection's driver lives on it.
    pub endpoint: Endpoint,
    /// The QUIC connection. A `Clone` handle; kept alive because the streams
    /// reference it.
    pub connection: Connection,
    /// The outbound half of the bidirectional stream (`AsyncWrite`): the link's
    /// one stream, or its Control stream on a multistream link.
    pub send: SendStream,
    /// The inbound half of the bidirectional stream (`AsyncRead`).
    pub recv: RecvStream,
    /// The streams this end opened for the priorities above Control, when the
    /// connection negotiated a multistream protocol; `None` on a single-stream
    /// link. The peer's own come in as it writes on them, so they are the read
    /// driver's to accept.
    pub priority_send: Option<PrioritySendStreams>,
    /// Whether the connection negotiated a mixed-reliability protocol, so its
    /// best-effort batches ride its datagrams (see the module doc).
    pub mixed_reliability: bool,
}

/// The largest best-effort batch a mixed-reliability link puts in a datagram.
/// Fixed rather than read off the path: both ends must size the batches the
/// same way whatever their own path MTU discovery has found, and upstream's
/// companion takes this many bytes, its datagram link's
/// `const MIXED_RELIABILITY_MTU: BatchSize = 1_150;` (QUIC's 1200-byte UDP
/// payload floor less the packet's header, tag and datagram frame).
pub const MIXED_RELIABILITY_MTU: usize = 1_150;

/// A received datagram as frame storage: quinn hands it over as a refcounted
/// `Bytes`, so the frame can be that buffer instead of a copy.
struct Datagram(Bytes);

impl RxStorage for Datagram {
    fn as_slice(&self) -> &[u8] {
        &self.0
    }
}

/// A received datagram as a frame: the refcounted buffer quinn already gave
/// it, handed up whole rather than copied out. The datagram link and the
/// datagram companion of a mixed-reliability link read through this one.
pub(crate) fn frame_of_datagram(bytes: Bytes) -> RxFrame {
    let len = bytes.len();
    let storage: Arc<dyn RxStorage> = Arc::new(Datagram(bytes));
    RxFrame::new(RxBytes::shared(storage, 0..len).expect("a datagram is a range of itself"))
}

/// The unidirectional streams of a multistream link that carry the priorities
/// above Control, `RealTime` first: upstream's `UniStreams`. Built only by
/// opening them on a connection that negotiated a multistream protocol.
pub struct PrioritySendStreams(Vec<SendStream>);

/// One stream per priority above Control; Control rides the bidirectional one.
const PRIORITY_STREAMS: usize = Priority::NUM - 1;

/// The application streams a QUIC connection allows its peer to open, set on
/// both ends as upstream's `configure_max_concurrent_streams` sets them
/// (`io/zenoh-link-commons/src/quic/utils.rs` @
/// `pub(crate) fn configure_max_concurrent_streams(`).
#[derive(Clone, Copy, Debug)]
pub(crate) enum StreamAllowance {
    /// The datagram link: no stream of either kind.
    #[cfg(feature = "transport-link-quic-datagram")]
    Datagrams,
    /// A streamed link: the one bidirectional stream, and a unidirectional
    /// stream per priority above Control unless the keys say `multistream=0`
    /// (`io/zenoh-link-commons/src/quic/unicast.rs` @
    /// `fn max_concurrent_uni_streams(&self) -> quinn::VarInt {`).
    Streamed(QuicStreams),
}

impl StreamAllowance {
    fn apply(self, transport: &mut TransportConfig) {
        let (bidi, uni) = match self {
            #[cfg(feature = "transport-link-quic-datagram")]
            StreamAllowance::Datagrams => (0u8, 0u8),
            StreamAllowance::Streamed(streams) => {
                let uni = match streams.multistream {
                    QuicStreamChoice::Disabled => 0,
                    QuicStreamChoice::Enabled | QuicStreamChoice::Auto => PRIORITY_STREAMS as u8,
                };
                (1u8, uni)
            }
        };
        transport.max_concurrent_bidi_streams(bidi.into());
        transport.max_concurrent_uni_streams(uni.into());
    }
}

/// The protocol `connection` negotiated by ALPN. Every wz endpoint offers a
/// non-empty list, so a connection that completed its handshake negotiated one
/// of them, which quinn guarantees to report; anything else is answered as an
/// error rather than assumed.
pub(crate) fn negotiated_protocol(connection: &Connection) -> io::Result<QuicAlpn> {
    let data = connection
        .handshake_data()
        .ok_or_else(|| io_other("the QUIC connection has no handshake data"))?;
    let data = data
        .downcast::<quinn::crypto::rustls::HandshakeData>()
        .map_err(|_| io_other("the QUIC handshake data is not a TLS handshake's"))?;
    data.protocol
        .as_deref()
        .and_then(QuicAlpn::from_token)
        .ok_or_else(|| io_other("the QUIC connection negotiated no zenoh protocol"))
}

/// Open this end's priority streams when `connection` negotiated a multistream
/// protocol: upstream's `UniStreams::try_open`. quinn numbers the streams one
/// end opens in the order it opens them, and the peer accepts them in that
/// order, so opening them in priority order is what maps a stream to its
/// priority without a byte on the wire saying so.
///
/// Each is opened without waiting, as upstream opens them: the peer allowed one
/// per priority when it offered the protocol (`StreamAllowance`), so a stream
/// that is not there at once never will be.
fn open_priority_streams(
    connection: &Connection,
    protocol: QuicAlpn,
) -> io::Result<Option<PrioritySendStreams>> {
    if !protocol.is_multistream() {
        return Ok(None);
    }
    let mut streams = Vec::with_capacity(PRIORITY_STREAMS);
    for priority in 1..Priority::NUM {
        let stream = connection
            .open_uni()
            .now_or_never()
            .ok_or_else(|| {
                io_other("the QUIC peer allows fewer streams than there are priorities")
            })?
            .map_err(io_other)?;
        // QUIC sends a stream of a HIGHER priority value first, and zenoh's
        // most urgent priority is its LOWEST number, so the sign is flipped
        // (`io/zenoh-link-commons/src/quic/unicast.rs` @ `open.set_priority(-(prio as i32))?;`).
        stream.set_priority(-(priority as i32)).map_err(io_other)?;
        streams.push(stream);
    }
    Ok(Some(PrioritySendStreams(streams)))
}

/// Inbound read driver of a QUIC link — the shared [`StreamReadDriver`] over a
/// [`quinn::RecvStream`], PLUS the keep-alive [`Endpoint`] + [`Connection`] the
/// link must outlive (see the module doc). Delegates the [`LinkDriver`] surface
/// to the inner stream driver; the framing / StreamEnvelope logic lives once in
/// [`crate::stream_link`]. The QUIC analogue of [`crate::ws_pipeline`]'s bespoke
/// `WsReadDriver`.
/// R2750 — QUIC's inbound half answers [`crate::link_ring_fd::RingReadable`]
/// with `None`.
///
/// A [`RecvStream`] is one stream MULTIPLEXED over a connection that quinn
/// drives on a UDP socket it owns; there is no descriptor whose bytes are this
/// stream's, so the question has no affirmative answer here rather than one
/// being withheld. Upstream reaches the same answer and says so in the same
/// terms — `io/zenoh-links/zenoh-link-quic/src/unicast.rs` @ `fn get_fd` is
/// `//TODO: expose FD for quinn??? bail!("Not supported")`.
impl crate::link_ring_fd::RingReadable for RecvStream {
    #[cfg(all(
        feature = "runtime-tokio-uring",
        feature = "transport-link-tcp",
        target_os = "linux"
    ))]
    fn ring_fd(&self) -> Option<std::os::fd::RawFd> {
        None
    }
}

pub struct QuicReadDriver {
    inner: QuicReader,
    // Keep-alive: dropping either before the link closes would tear it down
    // (the RecvStream/SendStream reference the connection; the connection
    // references the endpoint driver). Both are cheap Arc-backed handles.
    _endpoint: Endpoint,
    _connection: Connection,
}

/// What a QUIC link reads: its one stream, or every source of a link that has
/// more than one (a stream per priority, the datagram companion, or both).
enum QuicReader {
    Single(StreamReadDriver<RecvStream>),
    Sources(ConnectionReader),
}

impl LinkDriver for QuicReadDriver {
    async fn open(&mut self) -> io::Result<()> {
        match &mut self.inner {
            QuicReader::Single(reader) => reader.open().await,
            // The connection is live, as a single stream's is.
            QuicReader::Sources(_) => Ok(()),
        }
    }

    async fn send(&mut self, frame: &TxFrame<'_>, reliability: Reliability) -> io::Result<()> {
        match &mut self.inner {
            QuicReader::Single(reader) => reader.send(frame, reliability).await,
            QuicReader::Sources(_) => Err(io::Error::new(
                io::ErrorKind::NotConnected,
                "QuicReadDriver does not send; outbound goes via QuicWriteDriver",
            )),
        }
    }

    async fn close(&mut self) -> io::Result<()> {
        match &mut self.inner {
            QuicReader::Single(reader) => reader.close().await,
            QuicReader::Sources(_) => Ok(()),
        }
    }

    async fn poll_event(&mut self) -> LinkEvent {
        match &mut self.inner {
            QuicReader::Single(reader) => reader.poll_event().await,
            QuicReader::Sources(reader) => reader.poll_event().await,
        }
    }
}

/// What one source of a link's frames yields: a frame or a loss read off a
/// stream or a datagram, or a stream the peer opened.
enum Arrival {
    Event(LinkEvent),
    Opened(RecvStream),
}

/// One source of [`Arrival`]s, boxed once when it joins the reader.
type Arrivals = Pin<Box<dyn Stream<Item = Arrival> + Send>>;

/// The read side of a link with more than one source: the bidirectional
/// stream, each stream the peer opens for a priority on a multistream link, and
/// the connection's datagrams on a mixed-reliability one, read as one driver.
/// Upstream reads each priority's stream in a task of its own and ends the link
/// when any of them ends (`io/zenoh-transport/src/unicast/universal/link.rs` @
/// `let (res, _, _) = select_all((Priority::MAX as u8..=Priority::MIN as u8).map(|prio| {`),
/// and reads its datagram companion in the RX task of a link of its own, whose
/// end ends the pair; here they are polled together by the one driver the
/// session already polls, so a frame is handed up on the thread that reads it
/// and nothing is spawned.
///
/// A frame carries its own priority and reliability, so which source it came
/// from is not handed up: the sources separate them on the wire, where a lost
/// packet of one no longer holds up the others.
struct ConnectionReader {
    arrivals: SelectAll<Arrivals>,
    /// The link's one receive pool, which every stream reads into.
    arena: LinkArena,
    /// The loss of the first source that ended, which is the link's.
    lost: Option<LostCause>,
}

impl ConnectionReader {
    /// A reader of the bidirectional stream `control`, and, on `connection`,
    /// the peer's priority streams when `priority_streams` and its datagrams
    /// when `datagrams`.
    fn new(
        control: RecvStream,
        connection: &Connection,
        arena: LinkArena,
        priority_streams: bool,
        datagrams: bool,
    ) -> Self {
        let mut arrivals = SelectAll::new();
        arrivals.push(read_stream(control, arena.clone()));
        if priority_streams {
            arrivals.push(accept_priority_streams(connection.clone()));
        }
        if datagrams {
            arrivals.push(read_datagrams(connection.clone()));
        }
        Self {
            arrivals,
            arena,
            lost: None,
        }
    }

    async fn poll_event(&mut self) -> LinkEvent {
        loop {
            if let Some(cause) = self.lost {
                return LinkEvent::Lost { cause };
            }
            match self.arrivals.next().await {
                Some(Arrival::Event(LinkEvent::Lost { cause })) => {
                    // The link is lost with any of its sources; the rest are
                    // dropped, and their connection with them once the driver goes.
                    self.lost = Some(cause);
                    self.arrivals.clear();
                }
                Some(Arrival::Event(event)) => return event,
                Some(Arrival::Opened(recv)) => {
                    self.arrivals.push(read_stream(recv, self.arena.clone()));
                }
                // Unreachable while the bidirectional stream is read, which
                // ends only with a loss; answered as the peer gone rather than
                // a wait for nothing.
                None => self.lost = Some(LostCause::PeerClosed),
            }
        }
    }
}

/// The frames of one stream, read by the stream link's framing.
fn read_stream(recv: RecvStream, arena: LinkArena) -> Arrivals {
    // A QUIC link keeps the universal u16 prefix: lowlatency is a TCP-path
    // negotiation, so the flag is a fresh always-false one.
    let reader = StreamReadDriver::with_arena(recv, Arc::new(AtomicBool::new(false)), arena);
    Box::pin(futures_util::stream::unfold(
        reader,
        |mut reader| async move {
            let event = reader.poll_event().await;
            Some((Arrival::Event(event), reader))
        },
    ))
}

/// The streams the peer opens for its priorities, as it opens them: upstream's
/// `RecvStream::acceptor_task`, which stops once there is one per priority. A
/// connection that ends stops it too; that loss reaches the session through
/// the bidirectional stream, so the acceptor ends without an event of its own.
fn accept_priority_streams(connection: Connection) -> Arrivals {
    Box::pin(futures_util::stream::unfold(
        (connection, 0usize),
        |(connection, accepted)| async move {
            if accepted == PRIORITY_STREAMS {
                return None;
            }
            let recv = connection.accept_uni().await.ok()?;
            Some((Arrival::Opened(recv), (connection, accepted + 1)))
        },
    ))
}

/// The best-effort batches the peer puts on the connection's datagrams, one
/// batch to a datagram, as upstream's companion link reads them
/// (`read_datagram`, no length in front). A connection that ends ends this
/// source with the link's loss, as the end of the companion ends upstream's
/// pair, and the reader stops at the first loss of any source.
fn read_datagrams(connection: Connection) -> Arrivals {
    Box::pin(futures_util::stream::unfold(
        connection,
        |connection| async move {
            let event = match connection.read_datagram().await {
                Ok(bytes) => LinkEvent::Rx(frame_of_datagram(bytes)),
                // The connection ended: the cause a stream reader gives the
                // same end, quinn's `NotConnected`.
                Err(_) => LinkEvent::Lost {
                    cause: LostCause::OsError,
                },
            };
            Some((Arrival::Event(event), connection))
        },
    ))
}

/// The writer of a multistream link: the one queue's takes, each written on the
/// stream of its lane ([`OutboundQueue::next_wire_by_lane`]), so the existing
/// priority lanes feed the streams and no second scheduler decides the order.
/// `streams` holds the bidirectional stream first and then one per priority, so
/// a priority's wire byte is its stream's index.
///
/// Ends as [`writer_task`] does, and finishes every stream when the queue is.
async fn priority_writer_task(mut streams: Vec<SendStream>, mut queue: OutboundQueue) {
    while let Some((priority, wire)) = queue.next_wire_by_lane().await {
        let stream = &mut streams[priority.wire_byte() as usize];
        if !write_wire(stream, &mut queue, wire).await {
            return;
        }
    }
    for stream in &mut streams {
        let _ = stream.shutdown().await;
    }
}

/// The datagram half of a mixed-reliability link: the connection's datagrams,
/// one best-effort batch to each, written from the sending thread as upstream's
/// companion link writes them (a copy of the batch handed to `send_datagram`).
/// quinn queues a datagram without waiting and drops the oldest it holds when
/// its buffer is full, which is all a best-effort batch is promised, so there
/// is no room to wait for and no writer task.
struct DatagramCompanion {
    connection: Connection,
    /// The instant `last_send_ns` counts from.
    epoch: Instant,
    /// Nanoseconds from `epoch` to the last datagram quinn took, `NEVER_SENT`
    /// before the first: when this half last spoke.
    last_send_ns: AtomicU64,
}

/// `DatagramCompanion::last_send_ns` before the first datagram.
const NEVER_SENT: u64 = u64::MAX;

impl DatagramCompanion {
    fn new(connection: Connection) -> Self {
        Self {
            connection,
            epoch: Instant::now(),
            last_send_ns: AtomicU64::new(NEVER_SENT),
        }
    }

    fn now_ns(&self) -> u64 {
        self.epoch.elapsed().as_nanos() as u64
    }

    /// Put `batch` on one datagram.
    fn send(&self, batch: &[u8]) -> LinkSendOutcome {
        if batch.len() > MIXED_RELIABILITY_MTU {
            // The session sizes a best-effort batch to this half
            // (`QuicWriteDriver::link_mtu_for`), so a longer one bypassed it.
            log::warn!(
                "wz-runtime-tokio: best-effort batch {} bytes > the datagram companion's {}; \
                 dropping",
                batch.len(),
                MIXED_RELIABILITY_MTU
            );
            return LinkSendOutcome::Dropped(LinkDropCause::Oversize);
        }
        match self.connection.send_datagram(Bytes::copy_from_slice(batch)) {
            Ok(()) => {
                self.last_send_ns.store(self.now_ns(), Ordering::Relaxed);
                LinkSendOutcome::Sent
            }
            // The path takes less than the fixed size at the moment: this batch
            // is lost, and the half goes on.
            Err(SendDatagramError::TooLarge) => LinkSendOutcome::Dropped(LinkDropCause::Oversize),
            // The connection is gone, or a peer that negotiated the companion
            // takes no datagrams: no later batch can leave by this half either,
            // and upstream ends the pair on its companion's write error alike.
            Err(e) => {
                log::warn!("wz-runtime-tokio: quic datagram companion send failed: {e}");
                LinkSendOutcome::Dropped(LinkDropCause::WriterGone)
            }
        }
    }

    /// Milliseconds since quinn last took a datagram of this half, `None` before
    /// the first.
    fn ms_since_send(&self) -> Option<u64> {
        let last = self.last_send_ns.load(Ordering::Relaxed);
        (last != NEVER_SENT).then(|| self.now_ns().saturating_sub(last) / 1_000_000)
    }
}

/// The write half of a QUIC stream link: the stream link's write half over the
/// link's queue, and, on a link that negotiated a mixed-reliability protocol,
/// the datagram companion its best-effort frames leave by. Every frame of
/// another class, every transport message and every frame of a link without
/// the companion goes to the streams exactly as the stream link sends it.
pub struct QuicWriteDriver {
    streams: StreamWriteDriver,
    datagrams: Option<DatagramCompanion>,
}

impl QuicWriteDriver {
    /// The companion a frame of `class` leaves by: `None` for the streams.
    fn companion_for(&self, class: Reliability) -> Option<&DatagramCompanion> {
        match class {
            Reliability::BestEffort => self.datagrams.as_ref(),
            Reliability::Reliable => None,
        }
    }
}

impl BoxedLinkDriver for QuicWriteDriver {
    fn link_subject(&self) -> Option<&LinkSubject> {
        self.streams.link_subject()
    }

    fn link_endpoints(&self) -> Option<&LinkEndpoints> {
        self.streams.link_endpoints()
    }

    fn link_mtu(&self) -> usize {
        self.streams.link_mtu()
    }

    fn link_mtu_for(&self, class: Reliability) -> usize {
        match self.companion_for(class) {
            Some(_) => MIXED_RELIABILITY_MTU,
            None => self.streams.link_mtu_for(class),
        }
    }

    fn link_rx_capacity(&self) -> usize {
        self.streams.link_rx_capacity()
    }

    fn batch_length_prefixed(&self) -> bool {
        self.streams.batch_length_prefixed()
    }

    // A datagram is its own boundary: a best-effort batch on the companion has
    // no length in front.
    fn batch_length_prefixed_for(&self, class: Reliability) -> bool {
        match self.companion_for(class) {
            Some(_) => false,
            None => self.streams.batch_length_prefixed_for(class),
        }
    }

    fn reports_wire_writes(&self) -> bool {
        self.streams.reports_wire_writes()
    }

    fn ms_since_wire_write(&self) -> Option<u64> {
        self.streams.ms_since_wire_write()
    }

    // The companion is a line the peer leases on its own, so the session keeps it
    // alive by its own last write.
    fn carries_apart(&self, class: Reliability) -> bool {
        self.companion_for(class).is_some()
    }

    fn ms_since_wire_write_for(&self, class: Reliability) -> Option<u64> {
        match self.companion_for(class) {
            Some(companion) => companion.ms_since_send(),
            None => self.streams.ms_since_wire_write(),
        }
    }

    // The class names the line: the companion's keepalive is sent with the
    // best-effort class and goes on a datagram alone, every other urgent message
    // on the streams.
    fn send_urgent(&self, bytes: &[u8], reliability: Reliability) -> LinkSendOutcome {
        match self.companion_for(reliability) {
            Some(companion) => companion.send(bytes),
            None => self.streams.send_urgent(bytes, reliability),
        }
    }

    fn send_blocking(&self, bytes: &[u8], reliability: Reliability) -> LinkSendOutcome {
        self.send_prioritized(bytes, reliability, Priority::DEFAULT)
    }

    fn send_prioritized(
        &self,
        bytes: &[u8],
        reliability: Reliability,
        priority: Priority,
    ) -> LinkSendOutcome {
        match self.companion_for(reliability) {
            Some(companion) => companion.send(bytes),
            None => self.streams.send_prioritized(bytes, reliability, priority),
        }
    }

    fn wait_for_room(&self, priority: Priority, wait: RoomWait) -> RoomAnswer {
        self.streams.wait_for_room(priority, wait)
    }

    fn try_reserve_room(&self, priority: Priority) -> Option<RoomPermit> {
        self.streams.try_reserve_room(priority)
    }

    fn block_first_acquire(&self, priority: Priority, wait_us: u64) -> bool {
        self.streams.block_first_acquire(priority, wait_us)
    }

    fn block_first_release(&self, priority: Priority) {
        self.streams.block_first_release(priority)
    }

    // A best-effort frame on the companion never waits for the streams' room:
    // quinn takes a datagram without waiting, so the companion's queue, which
    // upstream keeps as a pipeline of its own beside its main link's, is never
    // full.
    fn wait_for_room_for(
        &self,
        class: Reliability,
        priority: Priority,
        wait: RoomWait,
    ) -> RoomAnswer {
        match self.companion_for(class) {
            Some(_) => RoomAnswer::at_once(LinkRoom::Free),
            None => self.streams.wait_for_room(priority, wait),
        }
    }

    fn try_reserve_room_for(&self, class: Reliability, priority: Priority) -> Option<RoomPermit> {
        match self.companion_for(class) {
            Some(_) => Some(RoomPermit::trivial()),
            None => self.streams.try_reserve_room(priority),
        }
    }

    // Upstream's block-first waiters are per link, and the companion's push never
    // waits, so its slot is always free.
    fn block_first_acquire_for(
        &self,
        class: Reliability,
        priority: Priority,
        wait_us: u64,
    ) -> bool {
        match self.companion_for(class) {
            Some(_) => true,
            None => self.streams.block_first_acquire(priority, wait_us),
        }
    }

    fn block_first_release_for(&self, class: Reliability, priority: Priority) {
        if self.companion_for(class).is_none() {
            self.streams.block_first_release(priority)
        }
    }

    fn shape_tx_queue(&self, shape: TxQueueShape) {
        self.streams.shape_tx_queue(shape)
    }

    fn set_idle_flush(
        &self,
        hook: Arc<dyn Fn() -> wz_session_core::link::IdleFlush + Send + Sync>,
    ) -> bool {
        self.streams.set_idle_flush(hook)
    }

    fn watch_room(&self, waker: Option<Arc<dyn Fn() + Send + Sync>>) {
        self.streams.watch_room(waker)
    }

    fn tx_staged(&self) {
        self.streams.tx_staged()
    }

    fn tx_fence(&self) {
        self.streams.tx_fence()
    }

    fn tx_slot_acquire(&self, want: usize, priority: Priority) -> Option<TxSlotGrant> {
        self.streams.tx_slot_acquire(want, priority)
    }

    fn tx_slot_storage(&self, slot: TxSlot) -> (*mut u8, usize) {
        self.streams.tx_slot_storage(slot)
    }

    fn tx_slot_send(
        &self,
        slot: TxSlot,
        start: usize,
        len: usize,
        reliability: Reliability,
        priority: Priority,
    ) -> LinkSendOutcome {
        let Some(companion) = self.companion_for(reliability) else {
            return self
                .streams
                .tx_slot_send(slot, start, len, reliability, priority);
        };
        // A best-effort frame the session encoded into a buffer the streams
        // lent leaves on a datagram: quinn takes a copy, as it does of every
        // batch of this half, and the buffer goes back to the streams unsent.
        let (base, capacity) = self.streams.tx_slot_storage(slot);
        debug_assert!(start + len <= capacity);
        // SAFETY: the session wrote `[start, start + len)` of the slot it was
        // lent and hands it over here (`TxLease::send`), within the capacity
        // `tx_slot_storage` reported; the slot is no one else's until the abort
        // below returns it.
        let frame = unsafe { std::slice::from_raw_parts(base.add(start), len) };
        let outcome = companion.send(frame);
        self.streams.tx_slot_abort(slot);
        outcome
    }

    fn tx_slot_abort(&self, slot: TxSlot) {
        self.streams.tx_slot_abort(slot)
    }

    fn open_blocking(&self) {
        self.streams.open_blocking()
    }

    fn close_blocking(&self) {
        self.streams.close_blocking()
    }
}

/// Map a quinn / rustls error into the `io::Result` the pipeline surface speaks.
/// `pub(crate)` so the datagram sibling [`crate::quic_datagram_pipeline`] reuses
/// the one error-mapping SSOT (R311y8) rather than re-deriving it.
pub(crate) fn io_other<E>(err: E) -> io::Error
where
    E: Into<Box<dyn std::error::Error + Send + Sync>>,
{
    io::Error::other(err)
}

/// R2798 — a rustls client config as quinn's crypto: the SECURE arm of the
/// choice upstream makes where it hands quinn its crypto
/// (`io/zenoh-link-commons/src/quic/unicast.rs` @ `Arc::new(PlainTextClientConfig::new(quic_config.into()))`,
/// the `else` of `if is_secure`). The plaintext arm is
/// `crate::quic_plaintext`, and both reach `connect_quic_client` through the
/// same parameter, which is why that function takes quinn's trait object rather
/// than a rustls config: a rustls config can only ever be the encrypted arm.
pub(crate) fn tls_client_crypto(
    client_config: Arc<RustlsClientConfig>,
) -> io::Result<Arc<dyn quinn::crypto::ClientConfig>> {
    Ok(Arc::new(
        QuicClientConfig::try_from(client_config).map_err(io_other)?,
    ))
}

/// R2798 — the server twin of [`tls_client_crypto`].
pub(crate) fn tls_server_crypto(
    server_config: Arc<RustlsServerConfig>,
) -> io::Result<Arc<dyn quinn::crypto::ServerConfig>> {
    Ok(Arc::new(
        QuicServerConfig::try_from(server_config).map_err(io_other)?,
    ))
}

/// Build a client [`Endpoint`] bound to a local socket (the locator's `#bind=`,
/// else an ephemeral one of `addr`'s family), install the QUIC `crypto` —
/// the TLS-1.3 rustls config via [`tls_client_crypto`], or
/// R2798's plaintext session — and connect
/// to `addr` (SNI = `server_name`) — the shared QUIC client-handshake SSOT for
/// BOTH the stream backend ([`dial_quic`]) and the datagram backend
/// ([`crate::quic_datagram_pipeline::dial_quic_datagram`]). Returns the endpoint
/// (the caller keeps it alive — its driver pumps the connection) + the
/// established [`Connection`], BEFORE any stream is opened; the caller chooses
/// `open_bi` (stream) vs riding datagrams. Mirrors zenoh's `new_link` client half.
///
/// R2590 — the socket is always built here and handed to quinn, which is what
/// upstream does whether or not any option is set
/// (`io/zenoh-link-commons/src/quic/socket.rs`
/// @ `pub async fn new_link(&self, dst_addr: &SocketAddr) -> ZResult<UdpSocket> {`).
/// Before R2590 an option-less dial took quinn's `Endpoint::client` instead,
/// and only a device-bound dial reached `Endpoint::new`; with `bind` and
/// `dscp` joining `iface` there would have been more pre-built sockets than
/// convenience ones, and two paths where upstream has one.
pub(crate) async fn connect_quic_client(
    addr: SocketAddr,
    crypto: Arc<dyn quinn::crypto::ClientConfig>,
    server_name: &str,
    link_socket: &LinkSocket<'_>,
    allowance: StreamAllowance,
) -> io::Result<(Endpoint, Connection)> {
    let local = link_socket.dial_local_addr(addr);
    let sock = tokio::net::UdpSocket::bind(local).await?;
    link_socket.configure(&sock, local)?;
    let mut endpoint = Endpoint::new(
        quinn::EndpointConfig::default(),
        None,
        sock.into_std()?,
        Arc::new(quinn::TokioRuntime),
    )?;
    let mut quinn_client = QuinnClientConfig::new(crypto);
    // R2598 — the dial half of the locator's quinn transport keys. Before this
    // round the dial set NO `TransportConfig` at all, so no locator config key
    // could reach quinn's transport on this side however it was spelled: the
    // gap was a missing seam, not a missing branch.
    let mut transport = TransportConfig::default();
    // The streams the server may open, set on this end too, as upstream's
    // client builder sets them.
    allowance.apply(&mut transport);
    link_socket.apply_quic_transport(&mut transport);
    quinn_client.transport_config(Arc::new(transport));
    endpoint.set_default_client_config(quinn_client);
    let connection = endpoint
        .connect(addr, server_name)
        .map_err(io_other)?
        .await
        .map_err(io_other)?;
    Ok((endpoint, connection))
}

/// Build a server [`Endpoint`] at `addr` presenting the QUIC `crypto` — the
/// TLS-1.3 rustls config via [`tls_server_crypto`], or R2798's plaintext
/// session — allowing the application streams `allowance` names — the shared
/// QUIC server-endpoint SSOT for BOTH the stream backend ([`bind_quic`]: the
/// bidirectional stream, and a stream per priority unless `multistream=0`) and
/// the datagram backend ([`crate::quic_datagram_pipeline::bind_quic_datagram`]:
/// none). The QUIC handshake rides crypto frames, not application streams, so
/// it completes regardless of the limit. Mirrors zenoh's `new_listener`
/// stream-limit setup.
///
/// R311y454 — `iface` is the LISTEN-side `#iface=<name>` honor, closing the
/// residual that only the dial half bound its socket to the named NIC. quinn's
/// convenience `Endpoint::server` owns the UDP socket it binds and exposes no
/// bind-device hook, so a device-bound listener needs the socket built FIRST:
/// bind, `SO_BINDTODEVICE`, then hand it to `Endpoint::new`. This is the exact
/// mirror of the dial-side `connect_quic_client` arm, and of zenoh's own
/// listener, which binds a UDP socket, calls `set_bind_to_device_udp_socket`, and
/// passes it to `Endpoint::new_with_abstract_socket`
/// (`io/zenoh-link-commons/src/quic/unicast.rs` @
/// `new_with_abstract_socket`); `Endpoint::new` IS that call plus
/// `wrap_udp_socket`.
///
/// R2590 — the socket is pre-built for EVERY listener now, not only a
/// device-bound one: `#dscp=` needs the same pre-bind hook, and upstream builds
/// it the same way whatever the options (`io/zenoh-link-commons/src/quic/socket.rs`
/// @ `pub async fn new_listener(&self, addr: &SocketAddr) -> ZResult<UdpSocket> {`).
/// That is also why this became `async`: the socket is bound through tokio, as
/// upstream's is, so the options are set with the setters tokio offers.
///
/// The socket MUST reach quinn. Building it, setting the device on it and then
/// dropping it would leave a listener that passes every "binding to `lo` works"
/// and "an absent device gives ENODEV" test while honouring nothing — the syscall
/// ran, on a socket quinn never used. That failure mode is what the delivery-based
/// A/B in `tests/quic_e2e.rs` exists to catch.
///
/// Deliberate divergence, named because it is a divergence and not a port: wz
/// hardcodes `quinn::TokioRuntime` where zenoh asks `quinn::default_runtime()`.
/// wz-runtime-tokio IS the tokio runtime crate, so there is no other answer to
/// give, and the dial half already hardcodes it. It stays fully qualified: wz
/// has its OWN `TokioRuntime` (the `wz_runtime_core::Runtime` impl), and two
/// unrelated types sharing one name is exactly the collision a bare name would
/// re-open.
pub(crate) async fn quic_server_endpoint(
    addr: SocketAddr,
    crypto: Arc<dyn quinn::crypto::ServerConfig>,
    allowance: StreamAllowance,
    link_socket: &LinkSocket<'_>,
) -> io::Result<Endpoint> {
    let mut sc = QuinnServerConfig::with_crypto(crypto);
    let mut transport = TransportConfig::default();
    allowance.apply(&mut transport);
    // R2598 — the listen half of the locator's quinn transport keys. Upstream
    // configures the MTU on BOTH builders
    // (`io/zenoh-link-commons/src/quic/unicast.rs` @ `.configure_mtu(&QuicMtuConfig::try_from(&epconf)?)`,
    // once in the server path and once in the client path), and each side's
    // value governs what THAT side may send, so neither is redundant.
    link_socket.apply_quic_transport(&mut transport);
    sc.transport_config(Arc::new(transport));
    let sock = tokio::net::UdpSocket::bind(addr).await?;
    link_socket.configure(&sock, addr)?;
    Endpoint::new(
        quinn::EndpointConfig::default(),
        Some(sc),
        sock.into_std()?,
        Arc::new(quinn::TokioRuntime),
    )
}

/// Accept one inbound QUIC connection from a *borrowed* server [`Endpoint`] and
/// complete its handshake — the accept-handshake SSOT for the DATAGRAM backend
/// ([`crate::quic_datagram_pipeline::accept_quic_datagram_on`]). Composes the
/// fast [`accept_quic_incoming`] arrival with the crypto handshake
/// (`incoming.await`); returns the established [`Connection`] BEFORE any stream is
/// accepted, since the datagram path rides datagrams rather than `accept_bi`-ing a
/// stream. Datagram-only (`transport-link-quic-datagram`): the STREAM backend went
/// through the split [`accept_quic_incoming`] / [`complete_quic_accept`] halves at
/// R311y404 (so the crypto defers off the accept loop) and no longer routes here.
#[cfg(feature = "transport-link-quic-datagram")]
pub(crate) async fn accept_quic_connection(endpoint: &Endpoint) -> io::Result<Connection> {
    let incoming = accept_quic_incoming(endpoint).await?;
    incoming.await.map_err(io_other)
}

/// Dial a QUIC connection to `addr` (SNI `server_name`, TLS-1.3
/// `client_config` from [`crate::quic_config`]) offering the default stream
/// keys' protocols, and open its streams. Returns a [`QuicLink`] ready for
/// [`wire_quic_stream`]. The primitive
/// [`crate::session_open::dial_locator`] calls for a `quic/...` locator carrying
/// [`crate::session_open::DialConfig`]`.quic`. Mirrors zenoh's `new_link`: the
/// shared `connect_quic_client` handshake, then `open_bi`.
pub async fn dial_quic(
    addr: SocketAddr,
    client_config: Arc<RustlsClientConfig>,
    server_name: &str,
    link_socket: &LinkSocket<'_>,
) -> io::Result<QuicLink> {
    dial_quic_with_streams(
        addr,
        client_config,
        server_name,
        link_socket,
        QuicStreams::DEFAULT,
    )
    .await
}

/// [`dial_quic`] for a locator whose stream keys are `streams`: the dial offers
/// their protocols ([`crate::quic_config::alpn_offer`]) in place of the ones
/// `client_config` carries, and the link it yields has a stream per priority
/// when the server chose a multistream protocol.
pub async fn dial_quic_with_streams(
    addr: SocketAddr,
    client_config: Arc<RustlsClientConfig>,
    server_name: &str,
    link_socket: &LinkSocket<'_>,
    streams: QuicStreams,
) -> io::Result<QuicLink> {
    open_quic_stream(
        addr,
        tls_client_crypto(client_offering(client_config, alpn_offer(streams)))?,
        server_name,
        link_socket,
        streams,
    )
    .await
}

/// R2798 — the crypto-agnostic body of [`dial_quic`]: the shared
/// `connect_quic_client` handshake, then `open_bi`, then the priority streams
/// when a multistream protocol was negotiated. Split out so the reliable UDP
/// variant, which is this same stream link under a plaintext session, dials
/// through it instead of repeating it. `crypto` already offers `streams`'
/// protocols; `streams` sets the streams the server may open.
pub(crate) async fn open_quic_stream(
    addr: SocketAddr,
    crypto: Arc<dyn quinn::crypto::ClientConfig>,
    server_name: &str,
    link_socket: &LinkSocket<'_>,
    streams: QuicStreams,
) -> io::Result<QuicLink> {
    let (endpoint, connection) = connect_quic_client(
        addr,
        crypto,
        server_name,
        link_socket,
        StreamAllowance::Streamed(streams),
    )
    .await?;
    // The initiator opens the bidirectional stream; the responder
    // `accept_bi`s it (zenoh: open_bi on dial, accept_bi on listen).
    let (send, recv) = connection.open_bi().await.map_err(io_other)?;
    let protocol = negotiated_protocol(&connection)?;
    let priority_send = open_priority_streams(&connection, protocol)?;
    Ok(QuicLink {
        endpoint,
        connection,
        send,
        recv,
        priority_send,
        mixed_reliability: protocol.is_mixed_rel(),
    })
}

/// Bind a QUIC server [`Endpoint`] at `addr` presenting `server_config` — the
/// accept-side "listen half" symmetric to [`dial_quic`], with the default stream
/// keys ([`bind_quic_with_streams`] takes a locator's). Allows the one
/// bidirectional stream and a stream per priority, mirroring zenoh's
/// `new_listener`. The caller owns the returned `Endpoint` and loops
/// [`accept_quic_on`] over it.
///
/// R311y454 — `iface` is the `#iface=<name>` LISTEN-side bind, the parameter
/// shape the sibling acceptors already use (`bind_tcp`,
/// [`crate::udp_pipeline::bind_udp_demux`]). R2590 — `async` since the listener
/// socket is bound through tokio (see the crate-private `quic_server_endpoint`).
pub async fn bind_quic(
    addr: SocketAddr,
    server_config: Arc<RustlsServerConfig>,
    link_socket: &LinkSocket<'_>,
) -> io::Result<Endpoint> {
    bind_quic_with_streams(addr, server_config, link_socket, QuicStreams::DEFAULT).await
}

/// [`bind_quic`] for a listener whose stream keys are `streams`: it offers their
/// protocols in place of the ones `server_config` carries, and allows a stream
/// per priority unless they say `multistream=0`.
pub async fn bind_quic_with_streams(
    addr: SocketAddr,
    server_config: Arc<RustlsServerConfig>,
    link_socket: &LinkSocket<'_>,
    streams: QuicStreams,
) -> io::Result<Endpoint> {
    quic_server_endpoint(
        addr,
        tls_server_crypto(server_offering(server_config, alpn_offer(streams)))?,
        StreamAllowance::Streamed(streams),
        link_socket,
    )
    .await
}

/// Accept the ARRIVAL of one inbound QUIC connection attempt from a *borrowed*
/// server [`Endpoint`] WITHOUT completing its crypto handshake — the fast,
/// non-blocking HALF of the accept the multi-peer
/// [`accept_loop`](crate::accept_loop) runs in its `select!` arm. Returns the
/// pending [`Incoming`], whose [`Incoming::remote_address`] already names the peer
/// (before the handshake); the caller drives the crypto to completion LATER via
/// [`complete_quic_accept`], off the accept path. This is the QUIC analogue of the
/// cheap TCP `accept` that precedes the DEFERRED tls SERVER handshake — a stalled
/// peer handshake never blocks accepting the next peer, which is what makes the
/// quic acceptor mesh-capable (R311y404). `None` (endpoint closed) maps to an
/// `io` error, matching `accept_quic_connection`.
pub async fn accept_quic_incoming(endpoint: &Endpoint) -> io::Result<Incoming> {
    endpoint
        .accept()
        .await
        .ok_or_else(|| io_other("quic endpoint closed before a peer connected"))
}

/// Complete an [`accept_quic_incoming`] arrival: drive the QUIC crypto handshake
/// to an established [`Connection`] (`incoming.await`), then accept the peer's
/// single bidirectional stream (`accept_bi`) — the DEFERRED, potentially-slow HALF
/// of the accept, run in the spawned per-face open future (never the accept loop's
/// `select!` arm), the tls-server-handshake analogue. Yields the SAME [`QuicLink`]
/// the inline [`accept_quic_on`] produces; `endpoint` is the keep-alive clone
/// (`Incoming` holds an internal `EndpointRef`, but the public [`QuicLink`]
/// contract carries an [`Endpoint`] handle so the link outlives the listener).
/// `accept_bi` resolves once the peer (the initiator) opens + writes the stream —
/// which the wz handshake does immediately (its InitSyn is the first wire byte).
pub async fn complete_quic_accept(incoming: Incoming, endpoint: Endpoint) -> io::Result<QuicLink> {
    let connection = incoming.await.map_err(io_other)?;
    let (send, recv) = connection.accept_bi().await.map_err(io_other)?;
    // Each end opens its own priority streams, as upstream's acceptor does.
    let protocol = negotiated_protocol(&connection)?;
    let priority_send = open_priority_streams(&connection, protocol)?;
    Ok(QuicLink {
        endpoint,
        connection,
        send,
        recv,
        priority_send,
        mixed_reliability: protocol.is_mixed_rel(),
    })
}

/// Accept ONE inbound QUIC connection from a *borrowed* server [`Endpoint`],
/// complete its handshake, and accept the peer's single bidirectional stream — the
/// QUIC mirror of [`crate::link_pipeline::accept_tcp_on`], INLINE (crypto + stream
/// back to back). Composes the [`accept_quic_incoming`] arrival with the deferred
/// [`complete_quic_accept`], so the split-half primitives stay the one SSOT. Since
/// R311y404 BOTH the one-shot `crate::session_open::accept_bound` AND the
/// multi-peer accept loop go through the two halves directly (accept_raw's arrival +
/// handshake's completion, so the crypto defers off the accept path); the only
/// remaining caller of this inline entry is the wz<->wz `quic_e2e` test, which wants
/// the crypto + stream back-to-back in one call. Returns a [`QuicLink`] (the
/// endpoint is cloned in as the keep-alive).
pub async fn accept_quic_on(endpoint: &Endpoint) -> io::Result<QuicLink> {
    let incoming = accept_quic_incoming(endpoint).await?;
    complete_quic_accept(incoming, endpoint.clone()).await
}

/// Wire a [`QuicLink`] into the cooperating drivers the session FSM consumes: an
/// inbound [`QuicReadDriver`] (`&mut LinkDriver` for the poll loop), an outbound
/// `Arc<`[`QuicWriteDriver`]`>` (`BoxedLinkDriver` for `send_blocking`; the
/// [`StreamWriteDriver`] of the streams, and the datagram companion of a
/// mixed-reliability link), and the [`writer_task`] join handle. The
/// `SendStream`/`RecvStream` are already a split pair (no `into_split` /
/// `tokio::io::split`); the endpoint + connection ride into the read driver as
/// the link keep-alive (module doc). StreamEnvelope framing + write driver are
/// the SAME shared [`crate::stream_link`] code as TCP/TLS. `rx_buffer_size` is
/// the session's `transport/link/rx/buffer_size`: the read storage the link
/// pools.
pub fn wire_quic_stream(
    link: QuicLink,
    rx_buffer_size: usize,
) -> (QuicReadDriver, Arc<QuicWriteDriver>, WriterHandle) {
    // R311y453 — the §5.16 subject: quinn reports the endpoint's bound address.
    // R2698 — with the peer's certificate common name, the ACL's fifth subject
    // axis. Unlike the TLS twin there is no split to race here: `connection`
    // outlives the wiring, so this is placed beside the subject for symmetry
    // rather than out of necessity.
    let subject = ip_link_subject(LinkKind::Quic, link.endpoint.local_addr().ok())
        .with_cert_common_name(peer_chain_common_name(&link.connection))
        .with_cert_credential_zid(peer_chain_credential_zid(&link.connection));
    // R311y473 — the adminspace `{src,dst}` pair: the endpoint's bound address is
    // this end, quinn's `Connection::remote_address` the peer's.
    let endpoints = crate::link_interfaces::ip_link_endpoints(
        LinkKind::Quic,
        link.endpoint.local_addr().ok(),
        Some(link.connection.remote_address()),
    );
    wire_stream_over_quic(link, subject, endpoints, rx_buffer_size)
}

/// R2810 — the part of [`wire_quic_stream`] that does not depend on WHICH link
/// the QUIC stream is: the StreamEnvelope drivers over the link's streams, the
/// datagram companion when the connection negotiated a mixed-reliability
/// protocol, and the endpoint and connection riding along as the keep-alive.
///
/// Split out because upstream's reliable UDP link IS this link under another
/// name, and the name is exactly what the caller must supply: its subject
/// (what a rule and the adminspace see it as) and its `{src,dst}` pair. Letting
/// it borrow `quic`'s would have filed a `udp` link under `quic` for every ACL
/// rule, which is the defect open-debt 814 separated the two axes to end.
pub(crate) fn wire_stream_over_quic(
    link: QuicLink,
    subject: wz_session_core::link::LinkSubject,
    endpoints: Option<wz_session_core::link::LinkEndpoints>,
    rx_buffer_size: usize,
) -> (QuicReadDriver, Arc<QuicWriteDriver>, WriterHandle) {
    let QuicLink {
        endpoint,
        connection,
        send,
        recv,
        priority_send,
        mixed_reliability,
    } = link;
    let (tx, rx) = crate::stream_link::stream_outbound_channel();
    let arena = link_arena(rx_buffer_size);
    // The streams of the link read into one pool, which the write half settles with the
    // link's negotiated batch at Established.
    let rx_settler = link_arena_settler(&arena);
    let has_priority_streams = priority_send.is_some();
    // transport-lowlatency is a TCP-path negotiation; QUIC keeps the universal
    // u16 prefix (an always-false flag on the drivers).
    let writer_handle = match priority_send {
        None => WriterHandle::spawn(rx, |queue| writer_task(send, queue)),
        // A lane per stream: the queue's lanes become the link's streams, and
        // the handshake, queued before the session's shape, stays on the
        // bidirectional stream where the peer reads it.
        Some(PrioritySendStreams(priority_streams)) => {
            let mut streams = Vec::with_capacity(Priority::NUM);
            streams.push(send);
            streams.extend(priority_streams);
            WriterHandle::spawn(rx.with_stream_lanes(), |queue| {
                priority_writer_task(streams, queue)
            })
        }
    };
    let reader = if has_priority_streams || mixed_reliability {
        QuicReader::Sources(ConnectionReader::new(
            recv,
            &connection,
            arena,
            has_priority_streams,
            mixed_reliability,
        ))
    } else {
        QuicReader::Single(StreamReadDriver::with_arena(
            recv,
            Arc::new(AtomicBool::new(false)),
            arena,
        ))
    };
    let outbound = Arc::new(QuicWriteDriver {
        streams: StreamWriteDriver::new(tx, Arc::new(AtomicBool::new(false)), subject, endpoints)
            .settling_rx(rx_settler),
        datagrams: mixed_reliability.then(|| DatagramCompanion::new(connection.clone())),
    });
    let inbound = QuicReadDriver {
        inner: reader,
        _endpoint: endpoint,
        _connection: connection,
    };
    (inbound, outbound, writer_handle)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// R2971 — A RECEIVED DATAGRAM IS QUINN'S BUFFER, not a copy of it.
    ///
    /// An address is a sound witness here where it is not for a freed buffer:
    /// the `Bytes` is alive inside the frame for the whole assertion, so no
    /// allocation can have reused its storage. Under a `to_vec` the frame's
    /// bytes would be a second allocation and the addresses would differ.
    #[test]
    fn a_received_datagram_is_the_buffer_quinn_gave_it() {
        let datagram = Bytes::from(b"one datagram, one frame".to_vec());
        let at = datagram.as_ptr();
        let frame = frame_of_datagram(datagram);
        assert_eq!(frame.bytes, b"one datagram, one frame");
        assert!(frame.bytes.is_shared());
        assert_eq!(
            frame.bytes.as_ptr(),
            at,
            "the frame IS the datagram's storage"
        );
    }
}
