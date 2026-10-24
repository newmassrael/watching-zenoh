// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The channel as a stream over a stream: [`TlsStream`] is a [`StreamSocket`] over another one,
//! and [`TlsDial`] the [`StreamDial`] that connects the stream under it and completes the
//! handshake before the link sees a byte. The stream link's framing, loss handling and lent-slot
//! send (`wz_runtime_coop::stream_link`) stay written once: they run over this stream as over
//! a plain connection.

use core::cell::{Cell, RefCell};
use core::ffi::c_int;

use wz_runtime_coop::session_drive::{LinkOpenError, LinkProto};
use wz_runtime_coop::stream_link::{StreamDial, StreamSocket};

use crate::channel::{Identity, Io, Role, Session, Step, TlsError, Transport, Want, Zid};

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
    peer_zid: Zid,
}

impl<S: StreamSocket + 'static> TlsStream<S> {
    /// The zid of the key the peer proved in the handshake (decision D1), for the session to
    /// pin against the zid the peer states.
    pub fn peer_zid(&self) -> Zid {
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

/// The dial of a secure channel: the stream `D` connects, then a TLS 1.3 handshake presenting
/// `identity`. The link sees the stream only once both ends proved their keys.
#[derive(Clone, Copy)]
pub struct TlsDial<D> {
    inner: D,
    identity: &'static Identity,
    budget: HandshakeBudget,
}

impl<D> TlsDial<D> {
    /// The channel over the streams `inner` connects, presenting `identity`.
    pub const fn new(inner: D, identity: &'static Identity) -> Self {
        Self {
            inner,
            identity,
            budget: HandshakeBudget::DEFAULT,
        }
    }

    /// The dial with another handshake budget.
    #[must_use]
    pub const fn with_budget(mut self, budget: HandshakeBudget) -> Self {
        self.budget = budget;
        self
    }
}

/// A channel failure as a stack's dial states it: an arena with no room is worth a later try as
/// a full table is; anything else is the other end not taking the link.
fn open_error(e: TlsError) -> LinkOpenError {
    match e {
        TlsError::OutOfMemory => LinkOpenError::Exhausted,
        _ => LinkOpenError::Refused,
    }
}

impl<D: StreamDial> StreamDial for TlsDial<D>
where
    D::Stream: 'static,
{
    type Stream = TlsStream<D::Stream>;

    fn dial(&self, addr: [u8; 4], port: u16) -> Result<Self::Stream, LinkOpenError> {
        let lower = Lower {
            socket: self.inner.dial(addr, port)?,
            error: Cell::new(None),
        };
        let mut session = Session::open(Role::Client, self.identity).map_err(open_error)?;
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
        let peer_zid = session.peer_zid().map_err(open_error)?;
        Ok(TlsStream {
            lower,
            session: RefCell::new(session),
            peer_zid,
        })
    }
}
