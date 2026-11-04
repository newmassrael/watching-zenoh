// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The link tier's TCP stream (`tcp` feature): one connection of lwIP's raw TCP API as a byte
//! stream a cooperative loop can write to and read from without blocking.
//!
//! [`LwipTcpSocket`] is the stream counterpart of [`LwipUdpSocket`](crate::LwipUdpSocket) and
//! keeps its conventions: the socket's state is address-stable storage lwIP's callbacks write into
//! (a heap box, or with `static-link-storage` a cell of a `static` pool the image declares),
//! written in place field by field because it holds the receive buffer, and every callback runs on
//! the one thread that drives lwIP, so the state is never borrowed while it is written.
//!
//! ## The receive buffer is the window
//!
//! A byte is acknowledged to the peer, and the receive window reopened, when the application
//! READS it ([`LwipTcpSocket::try_read`]) and not when lwIP delivers it. The buffer is therefore
//! the flow control: the peer can have in flight to this socket no more than the window lwIP
//! advertises, so a buffer at least that large always has room for what arrives, and nothing is
//! refused or held in a pbuf. [`LwipTcpSocket::connect`] refuses a buffer smaller than the port's
//! window ([`TcpError::RxBelowWindow`]) rather than letting a segment find it full later.
//!
//! ## What is written is whole or the connection ends
//!
//! [`send_parts`](LwipTcpSocket::send_parts) queues all of its parts or none: the send buffer is
//! checked first, and a short one is [`TcpError::WouldBlock`] with nothing written. A part that
//! lwIP then fails to queue (its segment pool ran out between two parts) would leave half a frame
//! in a stream, which cannot be taken back; the connection is aborted and the call says
//! [`TcpError::Write`].

use core::ffi::c_void;
use core::marker::PhantomPinned;
use core::pin::Pin;
use core::ptr;

#[cfg(not(feature = "static-link-storage"))]
use alloc::boxed::Box;

use lwip_sys::{
    err_enum_t_ERR_MEM, err_enum_t_ERR_OK, err_t, ip_addr_t, pbuf, pbuf_copy_partial, pbuf_free,
    tcp_abort, tcp_arg, tcp_close, tcp_connect, tcp_err, tcp_new, tcp_output, tcp_pcb, tcp_recv,
    tcp_recved, tcp_write, wz_lwip_tcp_sndbuf, wz_lwip_tcp_window,
};

use crate::LwipLink;

/// `TCP_WRITE_FLAG_COPY`: lwIP copies the bytes, so the caller's slice need not outlive the call.
const WRITE_COPY: u8 = 1;

/// Why a TCP call failed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TcpError {
    /// `tcp_new` returned NULL: `MEMP_NUM_TCP_PCB` is exhausted.
    PcbExhausted,
    /// `static-link-storage`: every cell of the pool the socket is made in is taken, counted by
    /// the pool; nothing is allocated instead.
    SlotsExhausted,
    /// `tcp_connect` refused the request with this lwIP error.
    ConnectFailed(i8),
    /// The receive buffer is smaller than the receive window the port advertises, so a segment
    /// could arrive that it cannot hold.
    RxBelowWindow {
        /// The buffer's size in bytes.
        rx: u32,
        /// The port's receive window in bytes.
        window: u32,
    },
    /// The send buffer has less room than the write needs; nothing was written. Poll lwIP and
    /// try again.
    WouldBlock,
    /// The connection is not open: it is still connecting, or has ended.
    NotOpen,
    /// The connection failed with this lwIP error (reset, aborted, timed out).
    Failed(i8),
    /// A write that was started could not be finished and the connection was aborted, so no half
    /// of a frame is left in the stream. The lwIP error that stopped it.
    Write(i8),
}

/// Where a connection is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TcpState {
    /// The SYN is out; the handshake has not completed.
    Connecting,
    /// Established: bytes can be written and read.
    Open,
    /// The peer sent its FIN. What it sent before is still to be read; nothing more will come.
    PeerClosed,
    /// The connection ended with this lwIP error and its control block is gone.
    Failed(i8),
}

/// A connection's state, written by lwIP's callbacks and read by the socket.
struct TcpInner<const RX: usize> {
    /// Null once lwIP has freed the control block (an error) or the socket closed it.
    pcb: *mut tcp_pcb,
    state: TcpState,
    /// The oldest unread byte of `rx`, and how many are held.
    head: usize,
    held: usize,
    rx: [u8; RX],
    _pin: PhantomPinned,
}

impl<const RX: usize> TcpInner<RX> {
    /// Write a connection's state, before its control block exists, at `at`, field by field: the
    /// receive buffer is in it, and a value of that size is not one to build on a stack.
    ///
    /// # Safety
    ///
    /// `at` must be aligned and valid for a write of `Self`; what it held is not dropped.
    #[inline(never)]
    unsafe fn init_in_place(at: *mut Self) {
        use core::ptr::{addr_of_mut, write};
        // SAFETY: the caller's; each field is written once through a pointer to it.
        unsafe {
            write(addr_of_mut!((*at).pcb), ptr::null_mut());
            write(addr_of_mut!((*at).state), TcpState::Connecting);
            write(addr_of_mut!((*at).head), 0);
            write(addr_of_mut!((*at).held), 0);
            write(addr_of_mut!((*at)._pin), PhantomPinned);
            // The receive buffer is left as the allocation had it: only `held` bytes of it are
            // ever read, and each of those was written first.
        }
    }

    /// Append `len` bytes of the chain `p` to the buffer.
    ///
    /// # Safety
    ///
    /// `p` is a valid chain of at least `len` bytes, and `len <= RX - held`.
    unsafe fn push_chain(&mut self, p: *mut pbuf, len: usize) {
        let tail = (self.head + self.held) % RX;
        let first = len.min(RX - tail);
        // SAFETY: the caller's; both copies land inside `rx`.
        unsafe {
            pbuf_copy_partial(p, self.rx.as_mut_ptr().add(tail).cast(), first as u16, 0);
            if first < len {
                pbuf_copy_partial(
                    p,
                    self.rx.as_mut_ptr().cast(),
                    (len - first) as u16,
                    first as u16,
                );
            }
        }
        self.held += len;
    }

    /// Take up to `out.len()` held bytes, oldest first.
    fn pop_into(&mut self, out: &mut [u8]) -> usize {
        let n = out.len().min(self.held);
        let first = n.min(RX - self.head);
        out[..first].copy_from_slice(&self.rx[self.head..self.head + first]);
        out[first..n].copy_from_slice(&self.rx[..n - first]);
        self.head = (self.head + n) % RX;
        self.held -= n;
        n
    }
}

/// Where a connection's state lives: a heap box by default, and with `static-link-storage` a cell
/// of the static pool the socket was made in. Either way it is pinned, because lwIP holds its
/// address as every callback's argument.
#[cfg(not(feature = "static-link-storage"))]
type InnerBox<const RX: usize> = Box<TcpInner<RX>>;
#[cfg(feature = "static-link-storage")]
type InnerBox<const RX: usize> = crate::static_slots::Slot<TcpInner<RX>>;

/// `static-link-storage`: the static storage for `S` connections of one buffer size, declared by
/// the image that owns the capacity decision:
///
/// ```text
/// static STREAMS: TcpSocketPool<4096, 2> = TcpSocketPool::new();
/// let socket = LwipTcpSocket::connect_in(&link, [192, 168, 0, 1], 7447, &STREAMS)?;
/// ```
///
/// A socket that drops gives its cell back; a connect that finds every cell taken is
/// [`TcpError::SlotsExhausted`], counted in [`refusals`](Self::refusals).
#[cfg(feature = "static-link-storage")]
pub struct TcpSocketPool<const RX: usize, const S: usize>(
    crate::static_slots::SlotPool<TcpInner<RX>, S>,
);

#[cfg(feature = "static-link-storage")]
impl<const RX: usize, const S: usize> TcpSocketPool<RX, S> {
    /// An empty pool, for a `static`.
    pub const fn new() -> Self {
        Self(crate::static_slots::SlotPool::new())
    }

    /// How many connections the pool holds at once.
    pub const fn capacity(&self) -> usize {
        S
    }

    /// How many are made now.
    pub fn in_use(&self) -> usize {
        self.0.in_use()
    }

    /// How many connects found every cell taken, since boot.
    pub fn refusals(&self) -> u32 {
        self.0.refusals()
    }
}

#[cfg(feature = "static-link-storage")]
impl<const RX: usize, const S: usize> Default for TcpSocketPool<RX, S> {
    fn default() -> Self {
        Self::new()
    }
}

/// One TCP connection over lwIP's raw API, with a receive buffer of `RX` bytes.
pub struct LwipTcpSocket<const RX: usize> {
    inner: Pin<InnerBox<RX>>,
}

unsafe extern "C" fn connected_thunk<const RX: usize>(
    arg: *mut c_void,
    _pcb: *mut tcp_pcb,
    _err: err_t,
) -> err_t {
    // SAFETY: `arg` is the `*mut TcpInner<RX>` handed to `tcp_arg`; the state is pinned and the
    // NO_SYS single-thread model means nothing else borrows it while a callback runs.
    let inner = unsafe { &mut *arg.cast::<TcpInner<RX>>() };
    inner.state = TcpState::Open;
    err_enum_t_ERR_OK as err_t
}

unsafe extern "C" fn recv_thunk<const RX: usize>(
    arg: *mut c_void,
    _pcb: *mut tcp_pcb,
    p: *mut pbuf,
    _err: err_t,
) -> err_t {
    // SAFETY: as `connected_thunk`.
    let inner = unsafe { &mut *arg.cast::<TcpInner<RX>>() };
    if p.is_null() {
        // The peer's FIN. The control block stays: the socket closes it.
        if inner.state == TcpState::Open {
            inner.state = TcpState::PeerClosed;
        }
        return err_enum_t_ERR_OK as err_t;
    }
    // SAFETY: lwIP gives a valid chain.
    let len = usize::from(unsafe { (*p).tot_len });
    if len > RX - inner.held {
        // Cannot happen with a buffer at least the window (`connect` checks); if it does, lwIP
        // keeps the chain and offers it again, and nothing is lost.
        return err_enum_t_ERR_MEM as err_t;
    }
    // SAFETY: the chain has `len` bytes and they fit.
    unsafe {
        inner.push_chain(p, len);
        pbuf_free(p);
    }
    err_enum_t_ERR_OK as err_t
}

unsafe extern "C" fn err_thunk<const RX: usize>(arg: *mut c_void, err: err_t) {
    // SAFETY: as `connected_thunk`; lwIP has already freed the control block.
    let inner = unsafe { &mut *arg.cast::<TcpInner<RX>>() };
    inner.pcb = ptr::null_mut();
    inner.state = TcpState::Failed(err);
}

impl<const RX: usize> LwipTcpSocket<RX> {
    /// Start a connection to `addr:port`. The handshake completes as lwIP is polled: watch
    /// [`state`](Self::state) for [`TcpState::Open`].
    ///
    /// # Errors
    ///
    /// [`TcpError::RxBelowWindow`] when `RX` is less than the port's receive window,
    /// [`TcpError::PcbExhausted`], and [`TcpError::ConnectFailed`].
    #[cfg(not(feature = "static-link-storage"))]
    pub fn connect(link: &LwipLink, addr: [u8; 4], port: u16) -> Result<Self, TcpError> {
        Self::check_window()?;
        let layout = core::alloc::Layout::new::<TcpInner<RX>>();
        // SAFETY: the layout is not zero-sized; `init_in_place` writes every field but the
        // receive buffer (read only after it is written), and an allocation from the global
        // allocator with this layout is what `Box::from_raw` takes back.
        let inner = unsafe {
            let at = alloc::alloc::alloc(layout).cast::<TcpInner<RX>>();
            if at.is_null() {
                alloc::alloc::handle_alloc_error(layout);
            }
            TcpInner::init_in_place(at);
            Box::into_pin(Box::from_raw(at))
        };
        Self::attach(link, inner, addr, port)
    }

    /// `static-link-storage`: [`connect`](Self::connect) over a cell of `pool`.
    ///
    /// # Errors
    ///
    /// As `connect`, and [`TcpError::SlotsExhausted`] when every cell is taken.
    #[cfg(feature = "static-link-storage")]
    pub fn connect_in<const S: usize>(
        link: &LwipLink,
        addr: [u8; 4],
        port: u16,
        pool: &'static TcpSocketPool<RX, S>,
    ) -> Result<Self, TcpError> {
        Self::check_window()?;
        // SAFETY: `init_in_place` writes every field the state is read through.
        let slot = unsafe { pool.0.claim_in_place(|at| TcpInner::init_in_place(at)) }
            .ok_or(TcpError::SlotsExhausted)?;
        // SAFETY: a slot's value stays in its cell of a `static` until the slot drops.
        Self::attach(link, unsafe { Pin::new_unchecked(slot) }, addr, port)
    }

    fn check_window() -> Result<(), TcpError> {
        // SAFETY: reads a constant the shim owns.
        let window = unsafe { wz_lwip_tcp_window() };
        if (RX as u64) < u64::from(window) {
            return Err(TcpError::RxBelowWindow {
                rx: u32::try_from(RX).unwrap_or(u32::MAX),
                window,
            });
        }
        Ok(())
    }

    /// Create the control block, hand lwIP the pinned state as every callback's argument, and
    /// start the connect. The order that keeps a callback from outliving its argument is written
    /// once, here.
    fn attach(
        _link: &LwipLink,
        mut inner: Pin<InnerBox<RX>>,
        addr: [u8; 4],
        port: u16,
    ) -> Result<Self, TcpError> {
        // SAFETY: `tcp_new` is a no-argument allocator of a control block.
        let pcb = unsafe { tcp_new() };
        if pcb.is_null() {
            return Err(TcpError::PcbExhausted);
        }
        // SAFETY: the state is pinned; only plain fields are written, and the callbacks that may
        // write it are registered after its address is taken.
        let state = unsafe { Pin::get_unchecked_mut(inner.as_mut()) };
        state.pcb = pcb;
        let arg = (state as *mut TcpInner<RX>).cast::<c_void>();
        let ip = ip_addr_t {
            addr: u32::from_le_bytes(addr),
        };
        // SAFETY: `pcb` is valid, `arg` outlives the registration (the drop clears it first),
        // and `ip` lives across the call.
        let connect = unsafe {
            tcp_arg(pcb, arg);
            tcp_recv(pcb, Some(recv_thunk::<RX>));
            tcp_err(pcb, Some(err_thunk::<RX>));
            tcp_connect(pcb, &ip, port, Some(connected_thunk::<RX>))
        };
        if connect as core::ffi::c_int != err_enum_t_ERR_OK as core::ffi::c_int {
            // SAFETY: nothing is in flight; the block was just made. Callbacks cleared first.
            unsafe {
                tcp_arg(pcb, ptr::null_mut());
                tcp_recv(pcb, None);
                tcp_err(pcb, None);
                tcp_abort(pcb);
            }
            return Err(TcpError::ConnectFailed(connect));
        }
        Ok(Self { inner })
    }

    fn state_mut(&mut self) -> &mut TcpInner<RX> {
        // SAFETY: only plain fields are written through it, none of which moves the state.
        unsafe { Pin::get_unchecked_mut(self.inner.as_mut()) }
    }

    /// Where the connection is.
    pub fn state(&self) -> TcpState {
        self.inner.state
    }

    /// How many received bytes are waiting to be read.
    pub fn readable(&self) -> usize {
        self.inner.held
    }

    /// The local port of the connection: the one the stack picked at the connect. Zero once the
    /// control block is gone (the connection failed or was shut down).
    pub fn local_port(&self) -> u16 {
        let pcb = self.inner.pcb;
        if pcb.is_null() {
            return 0;
        }
        // SAFETY: `pcb` is the live control block of this connection.
        unsafe { lwip_sys::wz_lwip_tcp_local_port(pcb) }
    }

    /// Queue every part, in order, for sending, or none of them.
    ///
    /// # Errors
    ///
    /// [`TcpError::NotOpen`] unless the connection is [`TcpState::Open`] or
    /// [`TcpState::PeerClosed`] (a half-closed stream can still be written),
    /// [`TcpError::WouldBlock`] when the send buffer cannot take them all, and
    /// [`TcpError::Write`] when lwIP failed part-way and the connection was aborted.
    pub fn send_parts(&mut self, parts: &[&[u8]]) -> Result<(), TcpError> {
        let state = self.state_mut();
        match state.state {
            TcpState::Open | TcpState::PeerClosed => {}
            TcpState::Failed(err) => return Err(TcpError::Failed(err)),
            TcpState::Connecting => return Err(TcpError::NotOpen),
        }
        let pcb = state.pcb;
        if pcb.is_null() {
            return Err(TcpError::NotOpen);
        }
        let total: usize = parts.iter().map(|part| part.len()).sum();
        // SAFETY: `pcb` is the live control block of an open connection.
        let room = unsafe { wz_lwip_tcp_sndbuf(pcb) } as usize;
        if total > room {
            return Err(TcpError::WouldBlock);
        }
        for part in parts.iter().filter(|part| !part.is_empty()) {
            let Ok(len) = u16::try_from(part.len()) else {
                // A part lwIP's length cannot name: nothing of this call is yet written if it
                // is the first, and a stream frame never is this large.
                return Err(TcpError::WouldBlock);
            };
            // SAFETY: `pcb` is live; the bytes are copied (`WRITE_COPY`).
            let err = unsafe { tcp_write(pcb, part.as_ptr().cast(), len, WRITE_COPY) };
            if err as core::ffi::c_int != err_enum_t_ERR_OK as core::ffi::c_int {
                self.abort();
                return Err(TcpError::Write(err));
            }
        }
        // SAFETY: `pcb` is live.
        let err = unsafe { tcp_output(pcb) };
        if err as core::ffi::c_int != err_enum_t_ERR_OK as core::ffi::c_int {
            // The data is queued and lwIP sends it from its timers; only the push failed.
            return Ok(());
        }
        Ok(())
    }

    /// Read what is queued into `buf` without blocking: `Ok(Some(n))` for `n` bytes,
    /// `Ok(Some(0))` once the peer has closed and everything it sent has been read, `Ok(None)`
    /// when nothing is queued yet.
    ///
    /// Reading is what reopens the receive window ([module](self)).
    ///
    /// # Errors
    ///
    /// [`TcpError::Failed`] when the connection ended with an error, after what arrived before
    /// it has been read; [`TcpError::NotOpen`] while it is still connecting.
    pub fn try_read(&mut self, buf: &mut [u8]) -> Result<Option<usize>, TcpError> {
        let state = self.state_mut();
        if state.held == 0 {
            return match state.state {
                TcpState::Connecting => Err(TcpError::NotOpen),
                TcpState::Open => Ok(None),
                TcpState::PeerClosed => Ok(Some(0)),
                TcpState::Failed(err) => Err(TcpError::Failed(err)),
            };
        }
        let n = state.pop_into(buf);
        let pcb = state.pcb;
        if n > 0 && !pcb.is_null() {
            // SAFETY: `pcb` is live; the window reopens by the bytes taken out of the buffer.
            unsafe { tcp_recved(pcb, n as u16) };
        }
        Ok(Some(n))
    }

    /// End the connection in both directions. A close lwIP cannot make now (no memory for the
    /// FIN) aborts it instead, which the peer reads as a reset. Safe to call twice.
    pub fn shutdown(&mut self) {
        let state = self.state_mut();
        let pcb = state.pcb;
        if pcb.is_null() {
            return;
        }
        state.pcb = ptr::null_mut();
        if !matches!(state.state, TcpState::Failed(_)) {
            state.state = TcpState::PeerClosed;
        }
        // SAFETY: `pcb` is live; the callbacks are cleared before the close so none runs into
        // this state afterwards.
        unsafe {
            tcp_arg(pcb, ptr::null_mut());
            tcp_recv(pcb, None);
            tcp_err(pcb, None);
            if tcp_close(pcb) as core::ffi::c_int != err_enum_t_ERR_OK as core::ffi::c_int {
                tcp_abort(pcb);
            }
        }
    }

    fn abort(&mut self) {
        let state = self.state_mut();
        let pcb = state.pcb;
        if pcb.is_null() {
            return;
        }
        state.pcb = ptr::null_mut();
        state.state = TcpState::Failed(-13);
        // SAFETY: `pcb` is live; callbacks cleared first, as in `shutdown`.
        unsafe {
            tcp_arg(pcb, ptr::null_mut());
            tcp_recv(pcb, None);
            tcp_err(pcb, None);
            tcp_abort(pcb);
        }
    }
}

impl<const RX: usize> Drop for LwipTcpSocket<RX> {
    fn drop(&mut self) {
        self.shutdown();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::lwip_test_link;
    use lwip_sys::{tcp_accept, tcp_bind, tcp_listen_with_backlog};

    /// 4096 is above the window of the host port (`TCP_WND` is four segments of 536).
    const RX: usize = 4096;

    /// An echo server on `port`: whatever arrives is written back, and `bye` ends the
    /// connection from the server's side. Raw API, as a peer on the same stack.
    fn echo_server(port: u16) {
        unsafe extern "C" fn accept(_: *mut c_void, new: *mut tcp_pcb, _: err_t) -> err_t {
            // SAFETY: a freshly accepted control block.
            unsafe { tcp_recv(new, Some(echo)) };
            0
        }
        unsafe extern "C" fn echo(
            _: *mut c_void,
            pcb: *mut tcp_pcb,
            p: *mut pbuf,
            _: err_t,
        ) -> err_t {
            // SAFETY: lwIP's callback contract: `pcb` live, `p` a chain or null.
            unsafe {
                if p.is_null() {
                    tcp_close(pcb);
                    return 0;
                }
                let len = (*p).tot_len;
                // A chain is at most the window, 2144 bytes on the host port.
                let mut bytes = [0u8; 4096];
                pbuf_copy_partial(p, bytes.as_mut_ptr().cast(), len, 0);
                tcp_recved(pcb, len);
                pbuf_free(p);
                if &bytes[..usize::from(len)] == b"bye" {
                    tcp_close(pcb);
                    return 0;
                }
                tcp_write(pcb, bytes.as_ptr().cast(), len, WRITE_COPY);
                tcp_output(pcb);
            }
            0
        }
        // SAFETY: a listener for the life of the process, on the one thread that drives lwIP.
        unsafe {
            let pcb = tcp_new();
            assert_eq!(tcp_bind(pcb, ptr::null(), port), 0);
            let listener = tcp_listen_with_backlog(pcb, 2);
            assert!(!listener.is_null());
            tcp_accept(listener, Some(accept));
        }
    }

    fn pump(link: &LwipLink) {
        link.poll_loopback();
        link.check_timeouts();
    }

    fn until(link: &LwipLink, mut done: impl FnMut() -> bool) {
        for _ in 0..4_000 {
            pump(link);
            if done() {
                return;
            }
        }
        panic!("lwIP was polled 4000 times and the condition did not come");
    }

    // One echo server per port, made once: a listener cannot be removed, and the tests run in
    // one process under the lwIP gate.
    fn server(port: u16) {
        use std::sync::Mutex;
        static MADE: Mutex<std::vec::Vec<u16>> = Mutex::new(std::vec::Vec::new());
        let mut made = MADE.lock().unwrap_or_else(|p| p.into_inner());
        if !made.contains(&port) {
            echo_server(port);
            made.push(port);
        }
    }

    #[test]
    fn a_connection_carries_a_frame_in_two_parts_and_reads_it_back() {
        let (_gate, link) = lwip_test_link();
        server(47_201);
        let mut socket = LwipTcpSocket::<RX>::connect(&link, [127, 0, 0, 1], 47_201).unwrap();
        assert_eq!(socket.state(), TcpState::Connecting);
        assert_eq!(socket.try_read(&mut [0; 8]), Err(TcpError::NotOpen));
        until(&link, || socket.state() == TcpState::Open);
        assert_eq!(socket.try_read(&mut [0; 8]), Ok(None), "nothing yet");

        socket.send_parts(&[b"he", b"llo"]).unwrap();
        until(&link, || socket.readable() == 5);
        let mut got = [0u8; 8];
        assert_eq!(socket.try_read(&mut got), Ok(Some(5)));
        assert_eq!(&got[..5], b"hello");
    }

    /// More bytes pass through than the buffer holds, so the ring wraps; and a read smaller than
    /// what is queued leaves the rest for the next.
    #[test]
    fn the_receive_buffer_wraps_and_a_short_read_leaves_the_rest() {
        let (_gate, link) = lwip_test_link();
        server(47_202);
        let mut socket = LwipTcpSocket::<RX>::connect(&link, [127, 0, 0, 1], 47_202).unwrap();
        until(&link, || socket.state() == TcpState::Open);

        // In lockstep: a chunk goes out and is read back before the next, so the echo server's
        // send buffer is never what limits the test, and every wait is bounded (`until`).
        let mut sent = 0usize;
        let mut read = std::vec::Vec::new();
        let total = 3 * RX;
        let mut chunk = [0u8; 700];
        while sent < total {
            let n = (total - sent).min(700);
            for (i, byte) in chunk[..n].iter_mut().enumerate() {
                *byte = ((sent + i) % 251) as u8;
            }
            socket.send_parts(&[&chunk[..n]]).unwrap();
            sent += n;
            let want = sent;
            let mut out = [0u8; 333];
            until(&link, || {
                match socket.try_read(&mut out) {
                    Ok(Some(n)) => read.extend_from_slice(&out[..n]),
                    Ok(None) => {}
                    Err(other) => panic!("{other:?}"),
                }
                read.len() >= want
            });
        }
        let expected: std::vec::Vec<u8> = (0..total).map(|i| (i % 251) as u8).collect();
        assert_eq!(
            read, expected,
            "every byte came back in order across the wrap"
        );
    }

    #[test]
    fn a_peer_that_closes_is_read_as_the_end_after_what_it_sent() {
        let (_gate, link) = lwip_test_link();
        server(47_203);
        let mut socket = LwipTcpSocket::<RX>::connect(&link, [127, 0, 0, 1], 47_203).unwrap();
        until(&link, || socket.state() == TcpState::Open);
        socket.send_parts(&[b"bye"]).unwrap();
        until(&link, || socket.state() == TcpState::PeerClosed);
        assert_eq!(
            socket.try_read(&mut [0; 8]),
            Ok(Some(0)),
            "the end, nothing before it"
        );
    }

    #[test]
    fn a_connect_to_a_port_nobody_listens_on_fails_with_the_error() {
        let (_gate, link) = lwip_test_link();
        let mut socket = LwipTcpSocket::<RX>::connect(&link, [127, 0, 0, 1], 47_299).unwrap();
        until(&link, || matches!(socket.state(), TcpState::Failed(_)));
        assert!(matches!(
            socket.try_read(&mut [0; 8]),
            Err(TcpError::Failed(_))
        ));
        assert!(matches!(
            socket.send_parts(&[b"x"]),
            Err(TcpError::Failed(_))
        ));
    }

    #[test]
    fn a_buffer_below_the_window_is_refused_before_anything_is_made() {
        let (_gate, link) = lwip_test_link();
        let refused = LwipTcpSocket::<512>::connect(&link, [127, 0, 0, 1], 47_201);
        assert!(matches!(
            refused,
            Err(TcpError::RxBelowWindow { rx: 512, window }) if window > 512
        ));
    }

    #[test]
    fn a_write_larger_than_the_send_buffer_writes_nothing() {
        let (_gate, link) = lwip_test_link();
        server(47_204);
        let mut socket = LwipTcpSocket::<RX>::connect(&link, [127, 0, 0, 1], 47_204).unwrap();
        until(&link, || socket.state() == TcpState::Open);
        let big = [7u8; 60_000];
        assert_eq!(
            socket.send_parts(&[&big[..30_000], &big[..30_000]]),
            Err(TcpError::WouldBlock)
        );
        // Nothing was queued, so the echo has nothing to say.
        for _ in 0..200 {
            pump(&link);
        }
        assert_eq!(socket.readable(), 0);
    }
}
