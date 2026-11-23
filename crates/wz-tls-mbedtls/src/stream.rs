// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The channel as a stream over a stream: [`TlsStream`] is a [`StreamSocket`] over another one,
//! [`TlsDial`] the [`StreamDial`] that connects the stream under it and completes the handshake
//! before the link sees a byte, and [`TlsListener`] the [`StreamListen`] that takes a connection
//! and completes the handshake as the accepting end. A dial begun without waiting
//! ([`StreamDial::dial_started`]) runs the same handshake one step for each ask of
//! [`StreamSocket::connected`], so whoever holds the session while it asks never waits on the
//! peer's records. The stream link's framing, loss handling and lent-slot send
//! (`wz_runtime_coop::stream_link`) stay written once: they run over this stream as over a plain
//! connection.
//!
//! Who the peer is depends on the policy the dial or the listener was made with:
//!
//! - [`TlsDial::new`], pinned: each end proves the key its self-signed certificate carries and
//!   the stream names the peer by the zid of that key (decision D1), which the session reports
//!   as verified when it is the zid the peer states
//!   ([`StreamSocket::peer_credential_zid`], read by `peer_identity_verified`).
//! - [`TlsDial::chain`], chain: the peer's certificate chain verifies against roots
//!   ([`ChainTrust`]), as a zenoh router's and a zenoh-pico `tls/` link's does. The peer's zid
//!   is not derived from its key (a router's is its own), so the stream offers no credential zid
//!   and the session takes the zid the peer states; the chain was the proof.

use core::cell::{Cell, RefCell};
use core::ffi::{c_int, CStr};
use core::fmt::Write as _;
use core::net::{IpAddr, SocketAddr};

use wz_runtime_coop::session_drive::{LinkOpenError, LinkProto};
use wz_runtime_coop::stream_link::{StreamDial, StreamListen, StreamSocket};
use wz_runtime_coop::ClockSource;

use crate::channel::{Identity, Io, Role, Session, Step, TlsError, Transport, Trust, Want, Zid};

/// The stream under a session, as the session's transport: a write blocks until the stream took
/// it (as [`StreamSocket::send_parts`] does), a read never blocks.
struct Lower<S: StreamSocket> {
    socket: S,
    /// The stream's last failure, for the caller of the call that met it.
    error: Cell<Option<S::Error>>,
}

impl<S: StreamSocket> Transport for Lower<S> {
    fn send(&self, buf: &[u8]) -> Io {
        match self.socket.send_parts(&[buf]) {
            Ok(()) => Io::Done(buf.len()),
            Err(e) => {
                self.error.set(Some(e));
                Io::Failed
            }
        }
    }

    fn recv(&self, buf: &mut [u8]) -> Io {
        match self.socket.try_read(buf) {
            Ok(Some(n)) => Io::Done(n),
            Ok(None) => Io::WouldBlock,
            Err(e) => {
                self.error.set(Some(e));
                Io::Failed
            }
        }
    }
}

/// Why a [`TlsStream`] call failed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TlsStreamError<E> {
    /// The stream under the channel failed, for this reason.
    Transport(E),
    /// The channel failed.
    Tls(TlsError),
}

/// A secure channel over the connected stream `S`, its handshake done: the bytes the link
/// writes leave as TLS records and the bytes it reads arrive from them, and the peer is the
/// holder of the key whose zid [`TlsStream::peer_zid`] names.
pub struct TlsStream<S: StreamSocket + 'static> {
    lower: Lower<S>,
    session: RefCell<Session<'static, Lower<S>>>,
    /// The zid of the key the peer's certificate carries: always there for a pinned stream, and
    /// for a chain stream whenever the peer presented a certificate (a server that asked for no
    /// client certificate has none to name).
    peer_zid: Option<Zid>,
    /// Whether that zid is the peer's credential (pinned), or only the key's name (chain).
    pinned: bool,
    /// How far a stream begun without waiting is in its opening; `Open` for one handed out whole.
    opening: Opening,
}

/// Where a [`TlsStream`] is in its opening.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Opening {
    /// The stream under the channel is still connecting.
    Connecting,
    /// Connected; the handshake has not finished.
    Handshaking,
    /// The handshake is done and the peer is known.
    Open,
}

impl<S: StreamSocket + 'static> TlsStream<S> {
    /// The zid of the key the peer proved in the handshake (decision D1).
    pub fn peer_zid(&self) -> Option<Zid> {
        self.peer_zid
    }

    /// The negotiated cipher suite.
    pub fn suite(&self) -> Option<&'static str> {
        let session = self.session.try_borrow().ok()?;
        session.suite().and_then(|name| name.to_str().ok())
    }

    /// The failure the stream under the channel reported, as this stream's error.
    fn transport_error(&self, e: TlsError) -> TlsStreamError<S::Error> {
        match (e, self.lower.error.take()) {
            (TlsError::Transport, Some(cause)) => TlsStreamError::Transport(cause),
            (other, _) => TlsStreamError::Tls(other),
        }
    }
}

/// A call made while the session was already borrowed: a re-entrant use the single loop never
/// makes, reported rather than allowed.
const REENTERED: TlsError = TlsError::State;

impl<S: StreamSocket + 'static> StreamSocket for TlsStream<S> {
    type Error = TlsStreamError<S::Error>;

    type Link<
        B: wz_runtime_coop::link_storage::RxStore + 'static,
        X: wz_runtime_coop::link_storage::TxStore + 'static,
    >
        = wz_runtime_coop::stream_link::StreamDriver<Self, B, X>
    where
        Self: 'static;

    const PROTO: LinkProto = LinkProto::Tls;

    fn local(&self) -> SocketAddr {
        self.lower.socket.local()
    }

    fn peer(&self) -> SocketAddr {
        self.lower.socket.peer()
    }

    fn send_parts(&self, parts: &[&[u8]]) -> Result<(), Self::Error> {
        let mut session = self
            .session
            .try_borrow_mut()
            .map_err(|_| TlsStreamError::Tls(REENTERED))?;
        for part in parts {
            let mut rest = *part;
            while !rest.is_empty() {
                match session.write(&self.lower, rest) {
                    Ok(Step::Done(n)) => rest = &rest[n..],
                    // The stream under takes every byte before it returns, so the session
                    // only waits on itself here: call again.
                    Ok(Step::Wait(_)) => {}
                    Err(e) => return Err(self.transport_error(e)),
                }
            }
        }
        Ok(())
    }

    fn wait_readable(&self, timeout_ms: c_int) {
        let held = self
            .session
            .try_borrow()
            .map(|session| session.pending())
            .unwrap_or(false);
        if !held {
            self.lower.socket.wait_readable(timeout_ms);
        }
    }

    // The channel's records leave through the stream under it, which takes every byte before it
    // returns: that stream's room is the channel's.
    fn wait_writable(&self, timeout_us: u64) -> bool {
        self.lower.socket.wait_writable(timeout_us)
    }

    fn wait_writable_timed(&self, timeout_us: u64) -> (bool, u64) {
        self.lower.socket.wait_writable_timed(timeout_us)
    }

    // The same room, waited on from another thread: the stream's own wait, handed out.
    wz_runtime_coop::with_heap_link_seams! {
        fn room_wait(&self) -> Option<wz_runtime_coop::session_drive::WaitOn> {
            self.lower.socket.room_wait()
        }

        #[cfg(all(feature = "alloc", not(feature = "session-slot")))]
        fn writability(
            &self,
        ) -> Option<alloc::boxed::Box<dyn wz_runtime_coop::session_drive::LinkWritability>> {
            self.lower.socket.writability()
        }
    }

    /// A stream begun without waiting connects the stream under it, then runs one step of its
    /// handshake for each ask: a step that waits for the peer's records (or for room) answers
    /// `Ok(false)` and is taken up again at the next ask. The stream keeps no deadline of its
    /// own; whoever asks gives the dial up (the engine at its open deadline), and dropping the
    /// stream ends the connection.
    fn connected(&mut self) -> Result<bool, Self::Error> {
        if self.opening == Opening::Connecting {
            match self.lower.socket.connected() {
                Ok(false) => return Ok(false),
                Ok(true) => self.opening = Opening::Handshaking,
                Err(e) => return Err(TlsStreamError::Transport(e)),
            }
        }
        if self.opening == Opening::Handshaking {
            match self.session.get_mut().handshake(&self.lower) {
                Ok(Step::Done(())) => {}
                Ok(Step::Wait(_)) => return Ok(false),
                Err(e) => return Err(self.transport_error(e)),
            }
            match peer_of(self.session.get_mut(), self.pinned) {
                Ok(peer_zid) => {
                    self.peer_zid = peer_zid;
                    self.opening = Opening::Open;
                }
                // Done, but the peer is not who the policy needs.
                Err(e) => {
                    self.lower.socket.shutdown();
                    return Err(TlsStreamError::Tls(e));
                }
            }
        }
        Ok(true)
    }

    fn try_read(&self, buf: &mut [u8]) -> Result<Option<usize>, Self::Error> {
        let mut session = self
            .session
            .try_borrow_mut()
            .map_err(|_| TlsStreamError::Tls(REENTERED))?;
        match session.read(&self.lower, buf) {
            Ok(Step::Done(n)) => Ok(Some(n)),
            // A record that carried no data (a ticket the peer sent, a record not yet whole).
            Ok(Step::Wait(_)) => Ok(None),
            Err(e) => Err(self.transport_error(e)),
        }
    }

    fn shutdown(&self) {
        if let Ok(mut session) = self.session.try_borrow_mut() {
            session.close_notify(&self.lower);
        }
        self.lower.socket.shutdown();
    }

    fn peer_credential_zid(&self) -> Option<Zid> {
        // A pinned stream's key names the peer, so the session can report the peer's zid as
        // verified against it. A chain stream's peer is vouched for by an authority, and its zid
        // is whatever it states.
        self.peer_zid.filter(|_| self.pinned)
    }
}

/// How long a dial waits for the peer's handshake records: `waits` waits of `wait_ms` each,
/// after which the peer is taken as not answering and the dial is refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HandshakeBudget {
    /// One wait on the stream, in milliseconds.
    pub wait_ms: c_int,
    /// How many waits the handshake may spend with nothing to read.
    pub waits: u32,
}

impl HandshakeBudget {
    /// Ten seconds in waits of 100 ms: zenoh's own link open timeout, and well past a software
    /// P-256 handshake on the kit (about 1.5 s per role, Round 3495).
    pub const DEFAULT: Self = Self {
        wait_ms: 100,
        waits: 100,
    };
}

/// What a chain-verified channel presents and verifies against. A pico `tls/` link is made of
/// exactly these (`Z_CONFIG_TLS_ROOT_CA_CERTIFICATE_*`, `ENABLE_MTLS`, `VERIFY_NAME_ON_CONNECT`,
/// the certificate and key of the end).
#[derive(Clone, Copy)]
pub struct ChainTrust {
    /// The certificate chain and key this end presents: always by a listener, by a dialer only
    /// under mutual TLS.
    pub identity: Option<&'static Identity>,
    /// The roots the peer's chain verifies against: always by a dialer, by a listener only under
    /// mutual TLS.
    pub roots: Option<&'static Trust>,
    /// Mutual TLS: the dialer presents `identity` and the listener requires the dialer's chain to
    /// verify against `roots`.
    pub mutual: bool,
    /// Whether a dialer checks the server's name. The name a stream dial has is the address it
    /// connects to, so the certificate must cover that address as an IP address (a SAN), as zenoh
    /// does for a locator that is an address; pico leaves the check off by default.
    pub verify_name: bool,
}

/// How a dial or a listener answers "who is the peer".
#[derive(Clone, Copy)]
enum Policy {
    Pinned(&'static Identity),
    Chain(ChainTrust),
}

impl Policy {
    /// A session of `role`, for a dial of `addr` when it is the client.
    fn open<S: Transport>(
        &self,
        role: Role,
        addr: Option<IpAddr>,
    ) -> Result<Session<'static, S>, TlsError> {
        match *self {
            Policy::Pinned(identity) => Session::open(role, identity),
            Policy::Chain(chain) => {
                // A mutual policy missing a half is a configuration error, not a plain TLS end:
                // silently dropping the client certificate would be a quiet downgrade.
                if chain.mutual && (chain.identity.is_none() || chain.roots.is_none()) {
                    return Err(TlsError::NoTrust);
                }
                match role {
                    Role::Client => {
                        let own = chain.identity.filter(|_| chain.mutual);
                        let name = addr.filter(|_| chain.verify_name).map(AddressText::of);
                        Session::open_chain(
                            role,
                            own,
                            chain.roots,
                            name.as_ref().map(AddressText::as_c_str),
                        )
                    }
                    Role::Server => Session::open_chain(
                        role,
                        chain.identity,
                        chain.roots.filter(|_| chain.mutual),
                        None,
                    ),
                }
            }
        }
    }

    fn pinned(&self) -> bool {
        matches!(self, Policy::Pinned(_))
    }
}

/// An address as the text a certificate's IP SAN is matched against, in a buffer of its own
/// (nothing here allocates): dotted decimal for IPv4, RFC 5952 for IPv6, which mbedtls reads back
/// into the address it compares with the SAN's bytes. The scope of a link-local end is not part
/// of the name a certificate can carry, so it is not written.
struct AddressText {
    text: [u8; ADDRESS_TEXT_BYTES],
    len: usize,
}

/// The longest address text and its NUL: an IPv6 address with an IPv4 tail
/// (`ffff:ffff:ffff:ffff:ffff:ffff:255.255.255.255`) is 45 bytes, `INET6_ADDRSTRLEN` with the
/// NUL.
const ADDRESS_TEXT_BYTES: usize = 46;

impl AddressText {
    fn of(addr: IpAddr) -> Self {
        let mut text = Self {
            text: [0; ADDRESS_TEXT_BYTES],
            len: 0,
        };
        // The longest text is shorter than the buffer, and the last byte stays the NUL.
        let _ = write!(text, "{addr}");
        text
    }

    fn as_c_str(&self) -> &CStr {
        CStr::from_bytes_with_nul(&self.text[..=self.len]).unwrap_or(c"")
    }
}

impl core::fmt::Write for AddressText {
    fn write_str(&mut self, s: &str) -> core::fmt::Result {
        let end = self.len + s.len();
        if end >= self.text.len() {
            return Err(core::fmt::Error);
        }
        self.text[self.len..end].copy_from_slice(s.as_bytes());
        self.len = end;
        Ok(())
    }
}

/// How a listener times one inbound handshake: the time now, on the clock the deadline is kept
/// on, and how long a handshake may take on that clock. The accept never blocks on the network
/// (the node's loop is what waits), so a handshake that is waiting for its peer is looked at
/// again on the next accept and ends by this deadline, not by a count of waits.
///
/// The clock is the one the listener's sessions run on, so that a program that moves its
/// session's time itself (paused, or faster than the wall) moves this deadline with it:
/// [`AcceptBudget`] reads a clock an image supplies as a function, [`ClockedAccept`] reads the
/// clock source a session of the cooperative runtime is driven by.
pub trait AcceptTimer: Clone {
    /// The time now, in milliseconds of a monotonic clock.
    fn now_ms(&self) -> u64;

    /// The time one inbound handshake may take, in milliseconds of that clock.
    fn timeout_ms(&self) -> u64;
}

/// How long a listener lets one inbound handshake take before it drops the connection, on a
/// clock the deploy supplies as a function: an image whose sessions run on the platform's own
/// monotonic clock.
#[derive(Clone, Copy)]
pub struct AcceptBudget {
    /// A monotonic clock, in milliseconds.
    pub clock: fn() -> u64,
    /// The time one inbound handshake may take, in milliseconds.
    pub timeout_ms: u64,
}

impl AcceptTimer for AcceptBudget {
    fn now_ms(&self) -> u64 {
        (self.clock)()
    }

    fn timeout_ms(&self) -> u64 {
        self.timeout_ms
    }
}

/// How long a listener lets one inbound handshake take, on the clock source its sessions are
/// driven by: the same clock their lease, keepalive and handshake deadlines read, whether the
/// host's or one a program moves.
#[derive(Clone, Copy)]
pub struct ClockedAccept<C> {
    /// The sessions' clock source.
    pub clock: C,
    /// The time one inbound handshake may take, in milliseconds of that clock.
    pub timeout_ms: u64,
}

impl<C: ClockSource + Clone> AcceptTimer for ClockedAccept<C> {
    fn now_ms(&self) -> u64 {
        self.clock.now_us() / 1_000
    }

    fn timeout_ms(&self) -> u64 {
        self.timeout_ms
    }
}

/// The dial of a secure channel: the stream `D` connects, then a TLS 1.3 handshake under the
/// policy the dial was made with. The link sees the stream only once the peer is known by it.
/// The same value listens (`StreamDial::listen`, which a build without `alloc` or with
/// `session-slot` does not have, and [`TlsDial::listener`]) once it has an [`AcceptTimer`]
/// (`A`), an [`AcceptBudget`] unless it was given another.
#[derive(Clone, Copy)]
pub struct TlsDial<D, A = AcceptBudget> {
    inner: D,
    policy: Policy,
    budget: HandshakeBudget,
    accept: Option<A>,
}

impl<D> TlsDial<D> {
    /// The pinned channel over the streams `inner` connects, presenting `identity`.
    pub const fn new(inner: D, identity: &'static Identity) -> Self {
        Self {
            inner,
            policy: Policy::Pinned(identity),
            budget: HandshakeBudget::DEFAULT,
            accept: None,
        }
    }

    /// The chain-verified channel over the streams `inner` connects.
    pub const fn chain(inner: D, trust: ChainTrust) -> Self {
        Self {
            inner,
            policy: Policy::Chain(trust),
            budget: HandshakeBudget::DEFAULT,
            accept: None,
        }
    }
}

impl<D, A> TlsDial<D, A> {
    /// The dial with another handshake budget.
    #[must_use]
    pub const fn with_budget(mut self, budget: HandshakeBudget) -> Self {
        self.budget = budget;
        self
    }

    /// The dial that can also listen, dropping an inbound handshake that outlasts `accept`.
    #[must_use]
    pub fn with_accept<B: AcceptTimer>(self, accept: B) -> TlsDial<D, B> {
        TlsDial {
            inner: self.inner,
            policy: self.policy,
            budget: self.budget,
            accept: Some(accept),
        }
    }
}

impl<D, A: AcceptTimer> TlsDial<D, A> {
    /// The listener over the one `inner` a platform opened, under this dial's policy. A dial
    /// with no [`AcceptTimer`] does not listen: [`LinkOpenError::Unsupported`].
    pub fn listener<L: StreamListen>(&self, inner: L) -> Result<TlsListener<L, A>, LinkOpenError>
    where
        L::Stream: 'static,
    {
        let accept = self.accept.clone().ok_or(LinkOpenError::Unsupported)?;
        Ok(TlsListener {
            inner,
            policy: self.policy,
            accept,
            pending: RefCell::new(None),
            dropped: Cell::new(0),
            last_drop: Cell::new(None),
        })
    }
}

/// A channel failure as a stack's dial states it: an arena with no room is worth a later try as
/// a full table is; a policy that cannot make a session is permanent; anything else is the
/// other end not taking the link.
fn open_error(e: TlsError) -> LinkOpenError {
    match e {
        TlsError::OutOfMemory => LinkOpenError::Exhausted,
        TlsError::NoTrust => LinkOpenError::Unsupported,
        _ => LinkOpenError::Refused,
    }
}

/// The zid a finished handshake names the peer by, when the policy needs one: a `pinned` one
/// (`Policy::pinned`) always does.
fn peer_of<T: Transport>(
    session: &Session<'static, T>,
    pinned: bool,
) -> Result<Option<Zid>, TlsError> {
    if pinned {
        // A pinned peer is known by its key: a handshake that gave none is no handshake.
        session.peer_zid().map(Some)
    } else {
        // A chain peer was verified by its chain; the key is only named when it presented one.
        Ok(session.peer_zid().ok())
    }
}

/// A finished handshake as a stream.
fn established<S: StreamSocket + 'static>(
    lower: Lower<S>,
    session: Session<'static, Lower<S>>,
    peer_zid: Option<Zid>,
    policy: &Policy,
) -> TlsStream<S> {
    TlsStream {
        lower,
        session: RefCell::new(session),
        peer_zid,
        pinned: policy.pinned(),
        opening: Opening::Open,
    }
}

impl<D: StreamDial, A: AcceptTimer + 'static> StreamDial for TlsDial<D, A>
where
    D::Stream: 'static,
{
    type Stream = TlsStream<D::Stream>;

    // The channel connects over the dial it wraps, so it reaches the families that dial does.
    const IPV6: bool = D::IPV6;

    fn dial(&self, to: SocketAddr) -> Result<Self::Stream, LinkOpenError> {
        // The policy first: one that cannot make a session never connects.
        let mut session = self
            .policy
            .open::<Lower<D::Stream>>(Role::Client, Some(to.ip()))
            .map_err(open_error)?;
        let lower = Lower {
            socket: self.inner.dial(to)?,
            error: Cell::new(None),
        };
        let mut idle = 0;
        loop {
            match session.handshake(&lower).map_err(open_error)? {
                Step::Done(()) => break,
                Step::Wait(Want::Write) => {}
                Step::Wait(Want::Read) => {
                    if idle == self.budget.waits {
                        lower.socket.shutdown();
                        return Err(LinkOpenError::Refused);
                    }
                    idle += 1;
                    lower.socket.wait_readable(self.budget.wait_ms);
                }
            }
        }
        match peer_of(&session, self.policy.pinned()) {
            Ok(peer_zid) => Ok(established(lower, session, peer_zid, &self.policy)),
            Err(e) => {
                lower.socket.shutdown();
                Err(open_error(e))
            }
        }
    }

    /// The session is made under the policy and the connection under it begun without waiting
    /// (the wrapped dial's `dial_started`); the stream is returned at once and completes its
    /// handshake as it is asked ([`StreamSocket::connected`]). The [`HandshakeBudget`] bounds
    /// the waiting [`Self::dial`] only: a begun dial is given up by whoever asks it.
    fn dial_started(&self, to: SocketAddr) -> Result<Self::Stream, LinkOpenError> {
        let session = self
            .policy
            .open::<Lower<D::Stream>>(Role::Client, Some(to.ip()))
            .map_err(open_error)?;
        let lower = Lower {
            socket: self.inner.dial_started(to)?,
            error: Cell::new(None),
        };
        Ok(TlsStream {
            lower,
            session: RefCell::new(session),
            peer_zid: None,
            pinned: self.policy.pinned(),
            opening: Opening::Connecting,
        })
    }

    // The trait declares the method where the runtime has its heap link layer
    // (`with_heap_link_seams!`), and this crate's own form of it is the typed `listen_counted`.
    wz_runtime_coop::with_heap_link_seams! {
        #[cfg(all(feature = "alloc", not(feature = "session-slot")))]
        fn listen(
            &self,
            at: SocketAddr,
        ) -> Result<alloc::boxed::Box<dyn StreamListen<Stream = Self::Stream>>, LinkOpenError> {
            Ok(alloc::boxed::Box::new(self.listen_counted(at)?))
        }
    }
}

/// The listener [`TlsDial::listen_counted`] hands out: a secure listener over the dial's own
/// listener, kept boxed as the trait's `listen` keeps it, and typed so its counts can be read.
#[cfg(all(feature = "alloc", not(feature = "session-slot")))]
pub type CountedTlsListener<S, A> = TlsListener<alloc::boxed::Box<dyn StreamListen<Stream = S>>, A>;

#[cfg(all(feature = "alloc", not(feature = "session-slot")))]
impl<D: StreamDial, A: AcceptTimer + 'static> TlsDial<D, A>
where
    D::Stream: 'static,
{
    /// [`StreamDial::listen`] with the listener left typed, so its [`TlsListener::dropped`] and
    /// [`TlsListener::last_drop`] can be read by the program that holds it (the boxed form of
    /// `listen` hides them).
    pub fn listen_counted(
        &self,
        at: SocketAddr,
    ) -> Result<CountedTlsListener<D::Stream, A>, LinkOpenError> {
        // Checked before the port is bound, so a dial that cannot accept does not take the port.
        if self.accept.is_none() {
            return Err(LinkOpenError::Unsupported);
        }
        let inner = self.inner.listen(at)?;
        self.listener(inner)
    }
}

/// An inbound connection whose handshake is not done.
struct Pending<S: StreamSocket + 'static> {
    lower: Lower<S>,
    session: Session<'static, Lower<S>>,
    /// The listener's clock when the connection was taken.
    since_ms: u64,
}

/// The listening end of a secure channel over the listener `L`: a connection `L` takes is not
/// handed on until its handshake is done, so the link above sees only streams whose peer the
/// policy accepted.
///
/// One handshake runs at a time, and each [`StreamListen::accept`] advances it without blocking
/// on the network: a connection arriving behind it waits in `L`'s own queue, the arena holds one
/// inbound session and not a table of them, and a peer that stalls is dropped by the
/// [`AcceptTimer`]. A handshake that fails (a peer that is not trusted, a plain TCP client, a
/// reset) is dropped and is not the listener's failure, but it is counted: [`Self::dropped`] and
/// [`Self::last_drop`] are how a program sees that the arena or the key store had no room for a
/// handshake, which the caller of `accept` otherwise sees only as nothing to accept.
pub struct TlsListener<L: StreamListen, A = AcceptBudget>
where
    L::Stream: 'static,
{
    inner: L,
    policy: Policy,
    accept: A,
    pending: RefCell<Option<Pending<L::Stream>>>,
    dropped: Cell<u32>,
    last_drop: Cell<Option<TlsError>>,
}

impl<L: StreamListen, A> TlsListener<L, A>
where
    L::Stream: 'static,
{
    /// End the inbound connection and look for the next.
    fn drop_pending(&self, pending: Pending<L::Stream>, why: Option<TlsError>) {
        pending.lower.socket.shutdown();
        self.dropped.set(self.dropped.get().saturating_add(1));
        self.last_drop.set(why);
    }

    /// How many inbound connections this listener took and ended without a stream: a handshake
    /// that failed, a peer the policy did not accept, a peer that stalled past the
    /// [`AcceptTimer`]. Saturates at `u32::MAX`.
    pub fn dropped(&self) -> u32 {
        self.dropped.get()
    }

    /// The channel's error for the latest drop, `None` when that drop had none (a stall past the
    /// budget) or when there has been none. An arena or a key store with no room is
    /// [`TlsError::OutOfMemory`] (measured, `tests/arena_exhaustion.rs` and
    /// `tests/key_store_exhaustion.rs`). Mbed TLS itself reports a full key store as its generic
    /// handshake failure, so the channel asks the store when a handshake fails that way.
    pub fn last_drop(&self) -> Option<TlsError> {
        self.last_drop.get()
    }
}

impl<L: StreamListen, A: AcceptTimer> StreamListen for TlsListener<L, A>
where
    L::Stream: 'static,
{
    type Stream = TlsStream<L::Stream>;

    fn local(&self) -> SocketAddr {
        self.inner.local()
    }

    fn accept(&self) -> Result<Option<Self::Stream>, LinkOpenError> {
        let mut slot = self
            .pending
            .try_borrow_mut()
            .map_err(|_| LinkOpenError::Unsupported)?;
        if slot.is_none() {
            let Some(socket) = self.inner.accept()? else {
                return Ok(None);
            };
            let lower = Lower {
                socket,
                error: Cell::new(None),
            };
            match self.policy.open::<Lower<L::Stream>>(Role::Server, None) {
                Ok(session) => {
                    *slot = Some(Pending {
                        lower,
                        session,
                        since_ms: self.accept.now_ms(),
                    });
                }
                Err(e) => {
                    // Taken off the port and not served: the peer sees the close. The caller is
                    // told by the error, and the drop is counted as any other is.
                    lower.socket.shutdown();
                    self.dropped.set(self.dropped.get().saturating_add(1));
                    self.last_drop.set(Some(e));
                    return Err(open_error(e));
                }
            }
        }
        let Some(mut pending) = slot.take() else {
            return Ok(None);
        };
        loop {
            match pending.session.handshake(&pending.lower) {
                Ok(Step::Done(())) => {
                    return match peer_of(&pending.session, self.policy.pinned()) {
                        Ok(peer_zid) => Ok(Some(established(
                            pending.lower,
                            pending.session,
                            peer_zid,
                            &self.policy,
                        ))),
                        // Done, but the peer is not who the policy needs.
                        Err(e) => {
                            self.drop_pending(pending, Some(e));
                            Ok(None)
                        }
                    };
                }
                Ok(Step::Wait(Want::Write)) => {}
                Ok(Step::Wait(Want::Read)) => {
                    let waited = self.accept.now_ms().saturating_sub(pending.since_ms);
                    if waited > self.accept.timeout_ms() {
                        self.drop_pending(pending, None);
                    } else {
                        *slot = Some(pending);
                    }
                    return Ok(None);
                }
                Err(e) => {
                    self.drop_pending(pending, Some(e));
                    return Ok(None);
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::net::{Ipv4Addr, Ipv6Addr};

    /// The name a dial checks a certificate's IP SAN against is the address's own text on either
    /// family, NUL terminated, and the longest of each fits the buffer whole.
    #[test]
    fn the_name_a_dial_checks_is_the_address_text_on_either_family() {
        for (ip, text) in [
            (IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), "10.0.0.1"),
            (IpAddr::V4(Ipv4Addr::BROADCAST), "255.255.255.255"),
            (IpAddr::V6(Ipv6Addr::LOCALHOST), "::1"),
            (
                IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1)),
                "2001:db8::1",
            ),
            (
                IpAddr::V6(Ipv6Addr::new(0, 0, 0, 0, 0, 0xffff, 0xffff, 0xffff)),
                "::ffff:255.255.255.255",
            ),
            (
                IpAddr::V6(Ipv6Addr::new(
                    0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff,
                )),
                "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff",
            ),
        ] {
            let name = AddressText::of(ip);
            assert_eq!(name.as_c_str().to_str(), Ok(text), "{ip}");
        }
    }

    /// A clock source that stands at the microsecond it was made with.
    #[derive(Clone, Copy)]
    struct At(u64);

    impl ClockSource for At {
        fn now_us(&self) -> u64 {
            self.0
        }
    }

    /// A listener's deadline reads the clock its timer was given: an image's function as it
    /// answers, and a session's clock source in whole milliseconds of its microseconds, so a
    /// handshake is timed on the clock the session runs on and on no other.
    #[test]
    fn an_accept_timer_reads_the_clock_it_was_given() {
        fn seven() -> u64 {
            7
        }
        let budget = AcceptBudget {
            clock: seven,
            timeout_ms: 30,
        };
        assert_eq!(budget.now_ms(), 7);
        assert_eq!(AcceptTimer::timeout_ms(&budget), 30);

        let clocked = ClockedAccept {
            clock: At(2_500_999),
            timeout_ms: 40,
        };
        assert_eq!(
            clocked.now_ms(),
            2_500,
            "microseconds read as whole milliseconds"
        );
        assert_eq!(AcceptTimer::timeout_ms(&clocked), 40);
        let later = ClockedAccept {
            clock: At(2_541_000),
            ..clocked
        };
        assert_eq!(
            later.now_ms() - clocked.now_ms(),
            41,
            "the time waited is the session clock's"
        );
    }
}
