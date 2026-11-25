// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The WebSocket links of the slot profile: [`WsStack`], the stack of the session host whose
//! `ws/` dials open the stack's own plain streams and frame them with `WsFraming`, and
//! [`WsAcceptor`], which answers the opening requests of the connections a listener takes. A link
//! is the [`IpDriver`] the stack's other links are, so a session slot holds one type for every
//! protocol and the session host runs it unchanged. Nothing here touches a heap: a link's buffers
//! are claimed from the image's byte tables, as a `tcp/` link's are, and the opening handshake
//! runs in them.
//!
//! A dial waits out its handshake, as a `tls/` dial of the same stack does, held to
//! ten seconds on the stack's clock. An acceptor answers as many requests at once as its table
//! has rows, each row reserved when the connection is taken; while every row holds one, the
//! listener is not asked for the next connection, which stays queued on the port as upstream's
//! does when its one handshake runs (`io/zenoh-links/zenoh-link-ws/src/unicast.rs` @
//! `let stream = match accept_async(`).

use core::ffi::c_int;
use core::marker::PhantomData;
use core::mem::MaybeUninit;
use core::net::SocketAddr;

use wz_session_core::byte_cells::{ByteBuf, ByteSource};
use wz_session_core::session_slot::SlotDriver;

use super::handshake::{answer_request, client_keys, read_answer, send_request, OPEN_WAIT_US};
use super::{WsFraming, WsSource};
use crate::ip_stack::{named, opens_ipv6, IpDriver, IpStack};
use crate::session_drive::{Accept, Bind, DriverPump, LinkOpenError, Locator, SlotStack};
use crate::stream_link::{StreamDial, StreamDriver, StreamListen, StreamSocket};
use crate::udp_link::{DatagramSocket, SERVICE_WAIT_MS};

/// An [`IpStack`] whose `ws/` links run over the plain streams of its own dial, timed and keyed by
/// `source`: made by [`IpStack::with_ws`]. Every other locator is the stack's own.
pub struct WsStack<U, D, L, W> {
    ip: IpStack<U, D, L>,
    source: W,
}

// Not derived: a derive would ask `U: Clone`, and the stack holds no socket.
impl<U, D: Copy, L: Copy, W: Copy> Clone for WsStack<U, D, L, W> {
    fn clone(&self) -> Self {
        *self
    }
}

impl<U, D: Copy, L: Copy, W: Copy> Copy for WsStack<U, D, L, W> {}

impl<U, D, L> IpStack<U, D, L>
where
    U: DatagramSocket + 'static,
    D: StreamDial,
    D::Stream: 'static,
    L: StreamDial,
    L::Stream: 'static,
{
    /// The same stack with `ws/` links over its plain streams, whose handshakes are timed on
    /// `source`'s clock and whose clients draw their keys from its entropy.
    pub fn with_ws<W: WsSource>(self, source: W) -> WsStack<U, D, L, W> {
        WsStack { ip: self, source }
    }
}

impl<U, D, L, W> WsStack<U, D, L, W>
where
    U: DatagramSocket + 'static,
    D: StreamDial,
    D::Stream: 'static,
    L: StreamDial,
    L::Stream: 'static,
    W: WsSource,
{
    /// The stack the `ws/` links stand beside: what a `tcp/` or `tls/` acceptor is made from.
    pub fn ip(&self) -> &IpStack<U, D, L> {
        &self.ip
    }

    /// The link of a dial to `to`, written into `out`, the place the driver is kept: `out` is
    /// written exactly when `Ok` is answered. A `ws/` locator connects, writes the opening request
    /// and waits for the server's answer; any other is the stack's (`IpStack::bind_initiator_in`).
    /// A protocol the stack's dial does not carry, or an IPv6 end it cannot reach, is
    /// [`LinkOpenError::Unsupported`] before any buffer is claimed; a table with no buffer free is
    /// [`LinkOpenError::Exhausted`]; a server that does not take the connection, refuses the
    /// upgrade or has not answered within ten seconds is [`LinkOpenError::Refused`]. Whatever
    /// was claimed before a refusal goes back with it.
    pub fn bind_initiator_in(
        &self,
        to: Locator,
        out: &mut MaybeUninit<IpDriver<U, D::Stream, L::Stream>>,
    ) -> Result<(), LinkOpenError> {
        match to.as_ws() {
            Some(ws) => self.dial_ws_in(ws.at, out),
            None => self.ip.bind_initiator_in(to, out),
        }
    }

    /// The `ws/` dial of [`Self::bind_initiator_in`].
    fn dial_ws_in(
        &self,
        at: SocketAddr,
        out: &mut MaybeUninit<IpDriver<U, D::Stream, L::Stream>>,
    ) -> Result<(), LinkOpenError> {
        if !D::CARRIED || (at.is_ipv6() && !D::IPV6) {
            return Err(LinkOpenError::Unsupported);
        }
        let (key, keys) = client_keys(&self.source)?;
        let (mut rx, tx) = self.ip.claim()?;
        let stream = named(self.ip.dial.dial(at)?)?;
        send_request(&stream, at, &key)?;
        let deadline = self.source.now_us().saturating_add(OPEN_WAIT_US);
        let mut filled = 0usize;
        let held = loop {
            if let Some(read) = read_answer(&stream, &mut rx, &mut filled, &key) {
                break read?;
            }
            let now = self.source.now_us();
            if now >= deadline {
                return Err(LinkOpenError::Refused);
            }
            stream.wait_readable(wait_ms(deadline.saturating_sub(now)));
        };
        out.write(IpDriver::Ws(StreamDriver::framed(
            stream,
            rx,
            held,
            tx,
            WsFraming::client(keys),
        )));
        Ok(())
    }

    /// The acceptor of the `ws/` connections `listener` takes, answering up to `H` opening
    /// requests at once, whose links claim their buffers from the tables of this stack.
    pub fn acceptor<A, const H: usize>(&self, listener: A) -> WsAcceptor<A, U, L::Stream, W, H>
    where
        A: StreamListen<Stream = D::Stream>,
        W: Clone,
    {
        WsAcceptor {
            listener,
            rx: self.ip.rx,
            tx: self.ip.tx,
            source: self.source.clone(),
            rows: [const { None }; H],
            refused: 0,
            stack: PhantomData,
        }
    }
}

/// How long a wait of a dial's handshake for the server's answer lasts, in milliseconds, with
/// `remaining_us` left before its deadline: at most a service turn's, so the clock is read again.
fn wait_ms(remaining_us: u64) -> c_int {
    let ms = remaining_us
        .div_ceil(1_000)
        .min(u64::try_from(SERVICE_WAIT_MS).unwrap_or(u64::MAX));
    c_int::try_from(ms).unwrap_or(c_int::MAX)
}

impl<U, D, L, W> Bind<IpDriver<U, D::Stream, L::Stream>> for WsStack<U, D, L, W>
where
    U: DatagramSocket + 'static,
    D: StreamDial,
    D::Stream: 'static,
    L: StreamDial,
    L::Stream: 'static,
    W: WsSource,
{
    const IPV6: bool = opens_ipv6::<U, D, L>();

    fn bind(&mut self, to: Locator) -> Result<IpDriver<U, D::Stream, L::Stream>, LinkOpenError> {
        let mut out = MaybeUninit::uninit();
        self.bind_initiator_in(to, &mut out)?;
        // SAFETY: `bind_initiator_in` answered `Ok`, so it wrote `out`.
        Ok(unsafe { out.assume_init() })
    }

    fn bind_in(
        &mut self,
        to: Locator,
        out: &mut MaybeUninit<IpDriver<U, D::Stream, L::Stream>>,
    ) -> Result<(), LinkOpenError> {
        self.bind_initiator_in(to, out)
    }
}

impl<U, D, L, W> SlotStack for WsStack<U, D, L, W>
where
    U: DatagramSocket + 'static,
    D: StreamDial + 'static,
    D::Stream: 'static,
    L: StreamDial + 'static,
    L::Stream: 'static,
    W: WsSource + 'static,
{
    type Driver = IpDriver<U, D::Stream, L::Stream>;
    type Pump = DriverPump<IpDriver<U, D::Stream, L::Stream>>;
    type Lane = ();

    fn pump(
        &self,
        driver: SlotDriver<IpDriver<U, D::Stream, L::Stream>>,
        _lane: Option<()>,
    ) -> Self::Pump {
        DriverPump(driver)
    }
}

/// A connection taken off the port whose opening request is not yet answered, in a row of a
/// [`WsAcceptor`]'s table with the buffers of the link it becomes.
struct Handshake<P> {
    stream: P,
    rx: ByteBuf,
    tx: ByteBuf,
    /// The bytes of the request read so far.
    filled: usize,
    /// When the connection was taken, on the stack's clock.
    since_us: u64,
}

/// The accepting end of a `ws/` port of a [`WsStack`]: the listener, and a table of `H` rows,
/// each a connection whose opening request is still to be answered. Made by
/// [`WsStack::acceptor`]; it yields the same [`IpDriver`] a `ws/` dial does, the server's end of
/// the link.
pub struct WsAcceptor<A: StreamListen, U, L, W, const H: usize> {
    listener: A,
    rx: &'static dyn ByteSource,
    tx: &'static dyn ByteSource,
    source: W,
    rows: [Option<Handshake<A::Stream>>; H],
    refused: u32,
    stack: PhantomData<fn() -> (U, L)>,
}

impl<A: StreamListen, U, L, W, const H: usize> WsAcceptor<A, U, L, W, H> {
    /// Connections taken off the port and closed at once because the tables had no buffer left
    /// for a link: the node was full.
    pub const fn refused(&self) -> u32 {
        self.refused
    }

    /// The address and port the listener is bound to.
    pub fn local(&self) -> SocketAddr {
        self.listener.local()
    }

    /// The rows of the table that hold a connection whose request is still to be answered.
    pub fn handshaking(&self) -> usize {
        self.rows.iter().filter(|row| row.is_some()).count()
    }
}

impl<A, U, L, W, const H: usize> WsAcceptor<A, U, L, W, H>
where
    A: StreamListen,
    W: WsSource,
{
    /// Take the connection waiting on the port into a free row, with its link's buffers. A table
    /// with no row free leaves it queued on the port; one taken when the tables have no buffer for
    /// it is closed at once and counted, so its peer sees the close and not a handshake that never
    /// ends.
    fn take_next(&mut self) -> Result<(), LinkOpenError> {
        let Some(row) = self.rows.iter_mut().find(|row| row.is_none()) else {
            return Ok(());
        };
        let Some(stream) = self.listener.accept()? else {
            return Ok(());
        };
        let stream = named(stream)?;
        let (Some(rx), Some(tx)) = (self.rx.claim(), self.tx.claim()) else {
            self.refused = self.refused.saturating_add(1);
            return Err(LinkOpenError::Exhausted);
        };
        *row = Some(Handshake {
            stream,
            rx,
            tx,
            filled: 0,
            since_us: self.source.now_us(),
        });
        Ok(())
    }
}

impl<A, U, L, W, const H: usize> Accept<IpDriver<U, A::Stream, L>> for WsAcceptor<A, U, L, W, H>
where
    A: StreamListen,
    A::Stream: 'static,
    U: DatagramSocket + 'static,
    L: StreamSocket + 'static,
    W: WsSource,
{
    /// The server's end of the first link whose request is answered, `Ok(None)` while none is. A
    /// handshake that failed or ran past ten seconds is let go, its connection closed and its
    /// buffers back in the tables, and its row free for the next connection.
    fn accept(&mut self) -> Result<Option<IpDriver<U, A::Stream, L>>, LinkOpenError> {
        self.take_next()?;
        let now = self.source.now_us();
        for row in &mut self.rows {
            let Some(shake) = row.as_mut() else {
                continue;
            };
            let since_us = shake.since_us;
            match answer_request(&shake.stream, &mut shake.rx, &mut shake.filled) {
                None if now.saturating_sub(since_us) < OPEN_WAIT_US => {}
                None | Some(Err(_)) => *row = None,
                Some(Ok(held)) => {
                    let Some(Handshake { stream, rx, tx, .. }) = row.take() else {
                        continue;
                    };
                    return Ok(Some(IpDriver::Ws(StreamDriver::framed(
                        stream,
                        rx,
                        held,
                        tx,
                        WsFraming::server(),
                    ))));
                }
            }
        }
        Ok(None)
    }
}

#[cfg(test)]
mod tests;
