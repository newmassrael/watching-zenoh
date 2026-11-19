// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! Links over a transport the program supplies, on this runtime.
//!
//! A program with a network stack of its own gives a session an [`AppPort`]: the `open`, `send`
//! and `close` the session calls. The program in turn calls [`AppTransport::received`],
//! [`AppTransport::event`] and [`AppTransport::accepted`] from its own thread when its stack has
//! something to say. Both sides meet in the transport's
//! [`AppLinkTable`](wz_session_core::app_link_table::AppLinkTable), which this module keeps behind
//! a `std::sync::Mutex`.
//!
//! # Locks and calls
//!
//! The table's lock is held for one table method at a time and for nothing else: no call into the
//! program (`open`, `send`, `close`) and no wake is made while it is held. A program call that
//! comes back into the transport (a `close` that reports the link closed, a `send` that hands
//! bytes to another link) therefore finds the lock free. A call of the program's never waits on
//! the session: it copies its bytes into the table, collects the tasks to wake, and wakes them
//! after the lock is dropped.
//!
//! # Streams
//!
//! A stream link is an [`AsyncRead`] and an [`AsyncWrite`] over its handle ([`AppStream`]), so
//! the session frames it exactly as it frames a socket: the same length envelope, the same read
//! driver and the same writer task (`crate::stream_link`). A partial send is a short write the
//! writer resumes from its offset; a would-block parks the writer until the program says the link
//! is writable.

use std::future::poll_fn;
use std::io;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};
use std::task::{Context, Poll};

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use wz_session_core::app_link_table::{
    AcceptRead, AppLinkKind, AppLinkTable, Effects, InboundRefusal, LinkHandle, OpenProgress,
    ProgramEvent, ProgramOpen, ProgramSend, SendGate, SendStep, StreamRead,
};
use wz_session_core::link::LinkKind;

use crate::link_interfaces::{addressless_link_endpoints, addressless_link_subject};
use crate::stream_link::{writer_task, StreamReadDriver, StreamWriteDriver};
use crate::writer_queue::WriterHandle;

/// The program's side of a transport: what the session calls. Each call is made with no lock of
/// the transport held, from a thread of the session's.
pub trait AppPort: Send + Sync {
    /// Open `link`, a link of `kind`, for `locator`.
    fn open(&self, link: LinkHandle, kind: AppLinkKind, locator: &str) -> ProgramOpen;
    /// Send `bytes` on `link`.
    fn send(&self, link: LinkHandle, bytes: &[u8]) -> ProgramSend;
    /// Close `link`. The program reports nothing more of it after this returns.
    fn close(&self, link: LinkHandle);
}

/// A transport the program supplies: its port and the table of its links.
pub struct AppTransport {
    table: Mutex<AppLinkTable>,
    port: Box<dyn AppPort>,
}

impl AppTransport {
    /// A transport over `port`, with no link.
    pub fn new(port: Box<dyn AppPort>) -> Arc<Self> {
        Arc::new(Self {
            table: Mutex::new(AppLinkTable::new()),
            port,
        })
    }

    /// The table, for one method. A panic while it was held left it as the method left it, which
    /// every method keeps consistent, so a poisoned lock is taken as it is.
    fn table(&self) -> MutexGuard<'_, AppLinkTable> {
        self.table
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    /// Do what a table method asked for, with the lock dropped: the program's close of each link
    /// named, then the wakes.
    fn perform(&self, effects: Effects) {
        let Effects { close, wake } = effects;
        for link in close {
            self.port.close(link);
            let done = self.table().close_done(link);
            self.perform(done);
        }
        for waker in wake {
            waker.wake();
        }
    }

    /// How many links the transport holds.
    pub fn link_count(&self) -> usize {
        self.table().len()
    }

    /// The program hands in `bytes` that arrived on `link`, and the locator a datagram came from.
    /// The bytes are copied before this returns.
    pub fn received(
        &self,
        link: LinkHandle,
        bytes: &[u8],
        source: Option<&str>,
    ) -> Result<(), InboundRefusal> {
        let effects = self.table().received(link, bytes, source)?;
        self.perform(effects);
        Ok(())
    }

    /// The program says `event` happened to `link`.
    pub fn event(&self, link: LinkHandle, event: ProgramEvent) -> Result<(), InboundRefusal> {
        let effects = self.table().event(link, event)?;
        self.perform(effects);
        Ok(())
    }

    /// The program accepted a stream on `listener`, whose remote end it names `remote`: the
    /// handle of the new link, which it uses for the stream from here on.
    pub fn accepted(
        &self,
        listener: LinkHandle,
        remote: &str,
    ) -> Result<LinkHandle, InboundRefusal> {
        let (link, effects) = self.table().accepted(listener, remote)?;
        self.perform(effects);
        Ok(link)
    }

    /// Open a link of `kind` for `locator` and wait until the program says it is up. The link is
    /// released (and closed on the program) when the returned guard drops, or when this future is
    /// dropped before it completes.
    async fn open_link(
        self: &Arc<Self>,
        kind: AppLinkKind,
        locator: &str,
    ) -> io::Result<Arc<AppLinkGuard>> {
        let handle = self.table().reserve(kind);
        let guard = Arc::new(AppLinkGuard::new(Arc::clone(self), handle));
        let answer = self.port.open(handle, kind, locator);
        let effects = self.table().opened(handle, answer);
        self.perform(effects);
        poll_fn(|cx| {
            let progress = self.table().poll_open(handle, Some(cx.waker()));
            match progress {
                OpenProgress::Opening => Poll::Pending,
                OpenProgress::Open => Poll::Ready(Ok(())),
                OpenProgress::Closed => Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::ConnectionRefused,
                    format!("the program's transport did not open {locator}"),
                ))),
            }
        })
        .await?;
        Ok(guard)
    }

    /// Dial a stream for `locator` (a `tcp/` locator) over the program's stack.
    pub async fn dial_stream(self: &Arc<Self>, locator: &str) -> io::Result<AppStream> {
        let guard = self.open_link(AppLinkKind::StreamDial, locator).await?;
        Ok(AppStream {
            guard,
            local: None,
            remote: Some(locator_address(locator).to_owned()),
        })
    }

    /// Listen for streams on `locator` (a `tcp/` locator) over the program's stack.
    pub async fn listen_stream(self: &Arc<Self>, locator: &str) -> io::Result<AppListener> {
        let guard = self.open_link(AppLinkKind::StreamListen, locator).await?;
        Ok(AppListener {
            guard,
            address: locator_address(locator).to_owned(),
        })
    }
}

/// The address part of a locator: what follows its scheme, without its metadata.
fn locator_address(locator: &str) -> &str {
    let address = locator
        .split_once('#')
        .map_or(locator, |(address, _)| address);
    let address = address
        .split_once('?')
        .map_or(address, |(address, _)| address);
    address
        .split_once('/')
        .map_or(address, |(_, address)| address)
}

/// One link the session holds, released when the last of its halves goes.
pub struct AppLinkGuard {
    transport: Arc<AppTransport>,
    handle: LinkHandle,
    released: AtomicBool,
}

impl AppLinkGuard {
    fn new(transport: Arc<AppTransport>, handle: LinkHandle) -> Self {
        Self {
            transport,
            handle,
            released: AtomicBool::new(false),
        }
    }

    /// The link's handle in its transport.
    pub fn handle(&self) -> LinkHandle {
        self.handle
    }

    /// Let the link go: the program's close runs for a link that is not closed. Once.
    fn release(&self) {
        if !self.released.swap(true, Ordering::SeqCst) {
            let effects = self.transport.table().release(self.handle);
            self.transport.perform(effects);
        }
    }
}

impl Drop for AppLinkGuard {
    fn drop(&mut self) {
        self.release();
    }
}

/// A stream link over the program's stack, before the session splits it.
pub struct AppStream {
    guard: Arc<AppLinkGuard>,
    /// The address of this end, when the program named it (the listener's, for an accepted one).
    local: Option<String>,
    /// The address of the remote end: the dialled one, or the one the program named at accept.
    remote: Option<String>,
}

impl AppStream {
    /// The link's handle in its transport.
    pub fn handle(&self) -> LinkHandle {
        self.guard.handle
    }

    /// The address of this end, when known.
    pub fn local_address(&self) -> Option<&str> {
        self.local.as_deref()
    }

    /// The address of the remote end, when known.
    pub fn remote_address(&self) -> Option<&str> {
        self.remote.as_deref()
    }

    /// The read and write halves, which share the link: it is released when both are gone, or
    /// when the write half is shut down.
    pub fn into_split(self) -> (AppStreamRead, AppStreamWrite) {
        (
            AppStreamRead {
                guard: Arc::clone(&self.guard),
            },
            AppStreamWrite { guard: self.guard },
        )
    }
}

/// The read half of an [`AppStream`].
pub struct AppStreamRead {
    guard: Arc<AppLinkGuard>,
}

impl AsyncRead for AppStreamRead {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let handle = self.guard.handle;
        let read = self.guard.transport.table().read_stream(
            handle,
            buf.initialize_unfilled(),
            Some(cx.waker()),
        );
        match read {
            StreamRead::Bytes(n) => {
                buf.advance(n);
                Poll::Ready(Ok(()))
            }
            StreamRead::Empty => Poll::Pending,
            // A read of nothing is the end of the stream, as a socket's is.
            StreamRead::End => Poll::Ready(Ok(())),
        }
    }
}

/// `None`: the program's stack is not a descriptor the kernel can read into.
impl crate::link_ring_fd::RingReadable for AppStreamRead {
    #[cfg(all(
        feature = "runtime-tokio-uring",
        feature = "transport-link-tcp",
        target_os = "linux"
    ))]
    fn ring_fd(&self) -> Option<std::os::fd::RawFd> {
        None
    }
}

/// The write half of an [`AppStream`].
pub struct AppStreamWrite {
    guard: Arc<AppLinkGuard>,
}

impl AsyncWrite for AppStreamWrite {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }
        let transport = &self.guard.transport;
        let handle = self.guard.handle;
        loop {
            let gate = transport.table().begin_send(handle, Some(cx.waker()));
            let ticket = match gate {
                SendGate::Go(ticket) => ticket,
                // The waker was kept: the link wakes this writer when it opens or is writable.
                SendGate::Opening | SendGate::Blocked => return Poll::Pending,
                // One writer per link; another task's send is out, so look again soon.
                SendGate::Busy => {
                    cx.waker().wake_by_ref();
                    return Poll::Pending;
                }
                SendGate::Closed => return Poll::Ready(Err(closed())),
            };
            let answer = transport.port.send(handle, buf);
            let (step, effects) = transport.table().send_answered(ticket, buf.len(), answer);
            transport.perform(effects);
            match step {
                // A writable came between the would-block and its answer: send again now.
                SendStep::Retry => {}
                SendStep::Wrote(n) => return Poll::Ready(Ok(n)),
                SendStep::Blocked => return Poll::Pending,
                SendStep::Closed => return Poll::Ready(Err(closed())),
                SendStep::Failed => {
                    return Poll::Ready(Err(io::Error::other(
                        "the program's transport failed a send",
                    )))
                }
            }
        }
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        // Every byte a write answered is the program's already.
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        // The program's transport has no half-close: the session ends its writing only when it
        // ends the link.
        self.guard.release();
        Poll::Ready(Ok(()))
    }
}

fn closed() -> io::Error {
    io::Error::new(
        io::ErrorKind::BrokenPipe,
        "the program's transport closed the link",
    )
}

/// The read driver of a stream over the program's stack: the shared stream reader over its read
/// half.
pub type AppReadDriver = StreamReadDriver<AppStreamRead>;

/// Split a stream over the program's stack into the drivers the session consumes, as
/// `crate::link_pipeline::wire_tcp_stream` splits a socket: the read driver, the write driver
/// (`BoxedLinkDriver`) and the writer task's handle. The framing and the write driver are the
/// shared `crate::stream_link` code, so the length envelope runs over the program's byte stream
/// exactly as over a socket. `rx_buffer_size` is the session's `transport/link/rx/buffer_size`.
pub fn wire_app_stream(
    stream: AppStream,
    rx_buffer_size: usize,
) -> (AppReadDriver, Arc<StreamWriteDriver>, WriterHandle) {
    // The adminspace `{src,dst}` pair, when the program named both ends (an accepted stream);
    // a dialled one has no local address this side knows.
    let endpoints = match (stream.local_address(), stream.remote_address()) {
        (Some(local), Some(remote)) => {
            Some(addressless_link_endpoints(LinkKind::Tcp, local, remote))
        }
        _ => None,
    };
    let (reader, writer) = stream.into_split();
    let inbound = StreamReadDriver::new(reader, Arc::new(AtomicBool::new(false)), rx_buffer_size);
    let (tx, rx) = crate::stream_link::stream_outbound_channel();
    let writer_handle = WriterHandle::spawn(rx, |queue| writer_task(writer, queue));
    let outbound = Arc::new(
        StreamWriteDriver::new(
            tx,
            Arc::new(AtomicBool::new(false)),
            // No interface of the system carries it: the program's stack does.
            addressless_link_subject(LinkKind::Tcp, Vec::new()),
            endpoints,
        )
        .settling_rx(inbound.rx_settler()),
    );
    (inbound, outbound, writer_handle)
}

/// A stream listener over the program's stack.
pub struct AppListener {
    guard: Arc<AppLinkGuard>,
    address: String,
}

impl AppListener {
    /// The address the listener was opened for.
    pub fn address(&self) -> &str {
        &self.address
    }

    /// The next stream the program accepts, and the locator it named for the remote end.
    /// Cancel-safe: a stream is taken only by a call that returns it.
    pub async fn accept(&self) -> io::Result<(AppStream, String)> {
        let transport = &self.guard.transport;
        let listener = self.guard.handle;
        let (handle, remote) = poll_fn(|cx| {
            let next = transport.table().next_accepted(listener, Some(cx.waker()));
            match next {
                AcceptRead::Accepted(handle, remote) => Poll::Ready(Ok((handle, remote))),
                AcceptRead::Empty => Poll::Pending,
                AcceptRead::End => Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::ConnectionAborted,
                    "the program's transport closed the listener",
                ))),
            }
        })
        .await?;
        let stream = AppStream {
            guard: Arc::new(AppLinkGuard::new(Arc::clone(transport), handle)),
            local: Some(self.address.clone()),
            remote: Some(locator_address(&remote).to_owned()),
        };
        Ok((stream, remote))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    /// A port that records what the session asked and answers from a script.
    #[derive(Default)]
    struct Script {
        opens: Mutex<Vec<(LinkHandle, AppLinkKind, String)>>,
        sent: Mutex<Vec<u8>>,
        closes: Mutex<Vec<LinkHandle>>,
        open_answer: Mutex<Option<ProgramOpen>>,
        /// The next send answers, in order; an empty script takes everything.
        send_answers: Mutex<Vec<ProgramSend>>,
    }

    struct ScriptPort(Arc<Script>);

    impl AppPort for ScriptPort {
        fn open(&self, link: LinkHandle, kind: AppLinkKind, locator: &str) -> ProgramOpen {
            self.0
                .opens
                .lock()
                .unwrap()
                .push((link, kind, locator.to_owned()));
            self.0
                .open_answer
                .lock()
                .unwrap()
                .unwrap_or(ProgramOpen::Up)
        }

        fn send(&self, _link: LinkHandle, bytes: &[u8]) -> ProgramSend {
            let mut answers = self.0.send_answers.lock().unwrap();
            let answer = if answers.is_empty() {
                ProgramSend::Wrote(bytes.len())
            } else {
                answers.remove(0)
            };
            if let ProgramSend::Wrote(n) = answer {
                self.0
                    .sent
                    .lock()
                    .unwrap()
                    .extend_from_slice(&bytes[..n.min(bytes.len())]);
            }
            answer
        }

        fn close(&self, link: LinkHandle) {
            self.0.closes.lock().unwrap().push(link);
        }
    }

    fn transport() -> (Arc<Script>, Arc<AppTransport>) {
        let script = Arc::new(Script::default());
        let transport = AppTransport::new(Box::new(ScriptPort(Arc::clone(&script))));
        (script, transport)
    }

    #[test]
    fn the_address_of_a_locator_drops_its_scheme_and_metadata() {
        assert_eq!(locator_address("tcp/192.0.2.5:7447"), "192.0.2.5:7447");
        assert_eq!(
            locator_address("tcp/192.0.2.5:7447#iface=lan7"),
            "192.0.2.5:7447"
        );
        assert_eq!(
            locator_address("tcp/192.0.2.5:7447?prio=1"),
            "192.0.2.5:7447"
        );
    }

    #[tokio::test]
    async fn a_dialled_stream_writes_through_the_port_and_reads_what_the_program_hands_in() {
        let (script, transport) = transport();
        let stream = transport
            .dial_stream("tcp/192.0.2.5:7447")
            .await
            .expect("the port answers up");
        let handle = stream.handle();
        assert_eq!(
            script.opens.lock().unwrap().as_slice(),
            [(
                handle,
                AppLinkKind::StreamDial,
                "tcp/192.0.2.5:7447".to_owned()
            )]
        );
        let (mut read, mut write) = stream.into_split();
        write.write_all(b"frame").await.expect("written");
        assert_eq!(script.sent.lock().unwrap().as_slice(), b"frame");
        transport.received(handle, b"reply", None).expect("open");
        let mut buf = [0u8; 5];
        read.read_exact(&mut buf).await.expect("read");
        assert_eq!(&buf, b"reply");
    }

    #[tokio::test]
    async fn a_partial_send_and_a_would_block_still_deliver_every_byte_in_order() {
        let (script, transport) = transport();
        *script.send_answers.lock().unwrap() = vec![ProgramSend::Wrote(2), ProgramSend::WouldBlock];
        let stream = transport.dial_stream("tcp/192.0.2.5:7447").await.unwrap();
        let handle = stream.handle();
        let (_read, mut write) = stream.into_split();
        let writer = tokio::spawn(async move { write.write_all(b"abcdef").await });
        // The writer parks on the would-block until the program says writable.
        for _ in 0..100 {
            if script.send_answers.lock().unwrap().is_empty() {
                break;
            }
            tokio::task::yield_now().await;
        }
        tokio::task::yield_now().await;
        assert_eq!(script.sent.lock().unwrap().as_slice(), b"ab");
        transport
            .event(handle, ProgramEvent::Writable)
            .expect("the link is open");
        writer.await.unwrap().expect("the rest is written");
        assert_eq!(script.sent.lock().unwrap().as_slice(), b"abcdef");
    }

    #[tokio::test]
    async fn a_refused_open_is_an_error_and_leaves_no_link() {
        let (script, transport) = transport();
        *script.open_answer.lock().unwrap() = Some(ProgramOpen::Refused);
        let error = transport
            .dial_stream("tcp/192.0.2.5:7447")
            .await
            .err()
            .expect("refused");
        assert_eq!(error.kind(), io::ErrorKind::ConnectionRefused);
        assert_eq!(transport.link_count(), 0);
        assert!(
            script.closes.lock().unwrap().is_empty(),
            "a link the program refused is not closed on it again"
        );
    }

    #[tokio::test]
    async fn dropping_both_halves_closes_the_link_on_the_program() {
        let (script, transport) = transport();
        let stream = transport.dial_stream("tcp/192.0.2.5:7447").await.unwrap();
        let handle = stream.handle();
        let (read, write) = stream.into_split();
        drop(read);
        assert!(
            script.closes.lock().unwrap().is_empty(),
            "the write half holds it"
        );
        drop(write);
        assert_eq!(script.closes.lock().unwrap().as_slice(), [handle]);
        assert_eq!(transport.link_count(), 0);
        assert_eq!(
            transport.received(handle, b"late", None),
            Err(InboundRefusal::NoSuchLink)
        );
    }

    #[tokio::test]
    async fn a_program_close_ends_the_read_and_fails_the_write() {
        let (_script, transport) = transport();
        let stream = transport.dial_stream("tcp/192.0.2.5:7447").await.unwrap();
        let handle = stream.handle();
        let (mut read, mut write) = stream.into_split();
        transport.received(handle, b"x", None).unwrap();
        transport.event(handle, ProgramEvent::Closed).unwrap();
        let mut rest = Vec::new();
        read.read_to_end(&mut rest).await.expect("ends");
        assert_eq!(rest, b"x", "what came before the close is read");
        let error = write.write_all(b"y").await.err().expect("closed");
        assert_eq!(error.kind(), io::ErrorKind::BrokenPipe);
    }

    #[tokio::test]
    async fn a_listener_hands_out_the_streams_the_program_accepts() {
        let (_script, transport) = transport();
        let listener = transport
            .listen_stream("tcp/192.0.2.5:7447")
            .await
            .expect("listening");
        assert_eq!(listener.address(), "192.0.2.5:7447");
        let listener_handle = listener.guard.handle();
        let accepted = transport
            .accepted(listener_handle, "tcp/198.51.100.3:50000")
            .expect("a listener accepts");
        let (stream, remote) = listener.accept().await.expect("one waits");
        assert_eq!(stream.handle(), accepted);
        assert_eq!(remote, "tcp/198.51.100.3:50000");
        assert_eq!(stream.remote_address(), Some("198.51.100.3:50000"));
        assert_eq!(stream.local_address(), Some("192.0.2.5:7447"));
    }

    #[tokio::test]
    async fn an_open_the_program_finishes_later_completes_on_connected() {
        let (script, transport) = transport();
        *script.open_answer.lock().unwrap() = Some(ProgramOpen::Pending);
        let dial = {
            let transport = Arc::clone(&transport);
            tokio::spawn(async move { transport.dial_stream("tcp/192.0.2.5:7447").await })
        };
        let handle = loop {
            if let Some((handle, ..)) = script.opens.lock().unwrap().first().cloned() {
                break handle;
            }
            tokio::task::yield_now().await;
        };
        transport.event(handle, ProgramEvent::Connected).unwrap();
        let stream = dial.await.unwrap().expect("up");
        assert_eq!(stream.handle(), handle);
    }
}
