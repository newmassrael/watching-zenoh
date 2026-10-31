// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The channel as a stream over a stream: [`TlsStream`] is a [`StreamSocket`] over another one,
//! [`TlsDial`] the [`StreamDial`] that connects the stream under it and completes the handshake
//! before the link sees a byte, and [`TlsListener`] the [`StreamListen`] that takes a connection
//! and completes the handshake as the accepting end. The stream link's framing, loss handling
//! and lent-slot send (`wz_runtime_coop::stream_link`) stay written once: they run over this
//! stream as over a plain connection.
//!
//! Who the peer is depends on the policy the dial or the listener was made with:
//!
//! - [`TlsDial::new`], pinned: each end proves the key its self-signed certificate carries and
//!   the stream names the peer by the zid of that key (decision D1), which the session checks
//!   against the zid the peer states ([`StreamSocket::peer_credential_zid`]).
//! - [`TlsDial::chain`], chain: the peer's certificate chain verifies against roots
//!   ([`ChainTrust`]), as a zenoh router's and a zenoh-pico `tls/` link's does. The peer's zid
//!   is not derived from its key (a router's is its own), so the stream offers no credential zid
//!   and the session takes the zid the peer states; the chain was the proof.

use core::cell::{Cell, RefCell};
use core::ffi::{c_int, CStr};
use core::fmt::Write as _;

use wz_runtime_coop::session_drive::{LinkOpenError, LinkProto};
use wz_runtime_coop::stream_link::{StreamDial, StreamListen, StreamSocket};

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

    const PROTO: LinkProto = LinkProto::Tls;

    fn local(&self) -> ([u8; 4], u16) {
        self.lower.socket.local()
    }

    fn peer(&self) -> ([u8; 4], u16) {
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
        // A pinned stream's key names the peer, so the session holds the peer to it. A chain
        // stream's peer is vouched for by an authority, and its zid is whatever it states.
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
        addr: Option<[u8; 4]>,
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
                        let name = addr.filter(|_| chain.verify_name).map(DottedQuad::of);
                        Session::open_chain(
                            role,
                            own,
                            chain.roots,
                            name.as_ref().map(DottedQuad::as_c_str),
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

/// An IPv4 address as the text a certificate's IP SAN is matched against, in a buffer of its own
/// (nothing here allocates).
struct DottedQuad {
    text: [u8; 16],
    len: usize,
}

impl DottedQuad {
    fn of(addr: [u8; 4]) -> Self {
        let mut quad = Self {
            text: [0; 16],
            len: 0,
        };
        // 15 bytes is the longest address, and the last byte stays the NUL.
        let _ = write!(quad, "{}.{}.{}.{}", addr[0], addr[1], addr[2], addr[3]);
        quad
    }

    fn as_c_str(&self) -> &CStr {
        CStr::from_bytes_with_nul(&self.text[..=self.len]).unwrap_or(c"")
    }
}

impl core::fmt::Write for DottedQuad {
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

/// How long a listener lets one inbound handshake take before it drops the connection, on a
/// clock the deploy supplies. The accept never blocks on the network (the node's loop is what
/// waits), so a handshake that is waiting for its peer is looked at again on the next accept and
/// ends by this deadline, not by a count of waits.
#[derive(Clone, Copy)]
pub struct AcceptBudget {
    /// A monotonic clock, in milliseconds.
    pub clock: fn() -> u64,
    /// The time one inbound handshake may take, in milliseconds.
    pub timeout_ms: u64,
}

/// The dial of a secure channel: the stream `D` connects, then a TLS 1.3 handshake under the
/// policy the dial was made with. The link sees the stream only once the peer is known by it.
/// The same value listens ([`StreamDial::listen`], [`TlsDial::listener`]) once it has an
/// [`AcceptBudget`].
#[derive(Clone, Copy)]
pub struct TlsDial<D> {
    inner: D,
    policy: Policy,
    budget: HandshakeBudget,
    accept: Option<AcceptBudget>,
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

    /// The dial with another handshake budget.
    #[must_use]
    pub const fn with_budget(mut self, budget: HandshakeBudget) -> Self {
        self.budget = budget;
        self
    }

    /// The dial that can also listen, dropping an inbound handshake that outlasts `accept`.
    #[must_use]
    pub const fn with_accept(mut self, accept: AcceptBudget) -> Self {
        self.accept = Some(accept);
        self
    }

    /// The listener over the one `inner` a platform opened, under this dial's policy. A dial
    /// with no [`AcceptBudget`] does not listen: [`LinkOpenError::Unsupported`].
    pub fn listener<L: StreamListen>(&self, inner: L) -> Result<TlsListener<L>, LinkOpenError>
    where
        L::Stream: 'static,
    {
        let accept = self.accept.ok_or(LinkOpenError::Unsupported)?;
        Ok(TlsListener {
            inner,
            policy: self.policy,
            accept,
            pending: RefCell::new(None),
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

/// The zid a finished handshake names the peer by, when the policy needs one.
fn peer_of<T: Transport>(
    session: &Session<'static, T>,
    policy: &Policy,
) -> Result<Option<Zid>, TlsError> {
    match policy {
        // A pinned peer is known by its key: a handshake that gave none is no handshake.
        Policy::Pinned(_) => session.peer_zid().map(Some),
        // A chain peer was verified by its chain; the key is only named when it presented one.
        Policy::Chain(_) => Ok(session.peer_zid().ok()),
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
    }
}

impl<D: StreamDial> StreamDial for TlsDial<D>
where
    D::Stream: 'static,
{
    type Stream = TlsStream<D::Stream>;

    fn dial(&self, addr: [u8; 4], port: u16) -> Result<Self::Stream, LinkOpenError> {
        // The policy first: one that cannot make a session never connects.
        let mut session = self
            .policy
            .open::<Lower<D::Stream>>(Role::Client, Some(addr))
            .map_err(open_error)?;
        let lower = Lower {
            socket: self.inner.dial(addr, port)?,
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
        match peer_of(&session, &self.policy) {
            Ok(peer_zid) => Ok(established(lower, session, peer_zid, &self.policy)),
            Err(e) => {
                lower.socket.shutdown();
                Err(open_error(e))
            }
        }
    }

    #[cfg(all(feature = "alloc", not(feature = "session-slot")))]
    fn listen(
        &self,
        addr: [u8; 4],
        port: u16,
    ) -> Result<alloc::boxed::Box<dyn StreamListen<Stream = Self::Stream>>, LinkOpenError> {
        // Checked before the port is bound, so a dial that cannot accept does not take the port.
        self.accept.ok_or(LinkOpenError::Unsupported)?;
        let inner = self.inner.listen(addr, port)?;
        Ok(alloc::boxed::Box::new(self.listener(inner)?))
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
/// [`AcceptBudget`]. A handshake that fails (a peer that is not trusted, a plain TCP client, a
/// reset) is dropped and is not the listener's failure.
pub struct TlsListener<L: StreamListen>
where
    L::Stream: 'static,
{
    inner: L,
    policy: Policy,
    accept: AcceptBudget,
    pending: RefCell<Option<Pending<L::Stream>>>,
}

impl<L: StreamListen> TlsListener<L>
where
    L::Stream: 'static,
{
    /// End the inbound connection and look for the next.
    fn drop_pending(pending: Pending<L::Stream>) {
        pending.lower.socket.shutdown();
    }
}

impl<L: StreamListen> StreamListen for TlsListener<L>
where
    L::Stream: 'static,
{
    type Stream = TlsStream<L::Stream>;

    fn local(&self) -> ([u8; 4], u16) {
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
                        since_ms: (self.accept.clock)(),
                    });
                }
                Err(e) => {
                    // Taken off the port and not served: the peer sees the close.
                    lower.socket.shutdown();
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
                    return match peer_of(&pending.session, &self.policy) {
                        Ok(peer_zid) => Ok(Some(established(
                            pending.lower,
                            pending.session,
                            peer_zid,
                            &self.policy,
                        ))),
                        // Done, but the peer is not who the policy needs.
                        Err(_) => {
                            Self::drop_pending(pending);
                            Ok(None)
                        }
                    };
                }
                Ok(Step::Wait(Want::Write)) => {}
                Ok(Step::Wait(Want::Read)) => {
                    let waited = (self.accept.clock)().saturating_sub(pending.since_ms);
                    if waited > self.accept.timeout_ms {
                        Self::drop_pending(pending);
                    } else {
                        *slot = Some(pending);
                    }
                    return Ok(None);
                }
                Err(_) => {
                    Self::drop_pending(pending);
                    return Ok(None);
                }
            }
        }
    }
}
