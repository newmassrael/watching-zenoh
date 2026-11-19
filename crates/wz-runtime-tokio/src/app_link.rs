// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! Links over a transport the program supplies, on this runtime.
//!
//! The transport is the engine-neutral [`AppTransport`] of `wz-session-core`: the program's calls
//! and the table of its links behind the lock the ABI gave it. This module is what the tokio
//! engine makes of it: streams the shared stream pipeline frames, datagram links the datagram
//! writer queue feeds, and group links the multicast glue drives.
//!
//! # Streams
//!
//! A stream link is an [`AsyncRead`] and an [`AsyncWrite`] over its handle ([`AppStream`]), so
//! the session frames it exactly as it frames a socket: the same length envelope, the same read
//! driver and the same writer task (`crate::stream_link`). A partial send is a short write the
//! writer resumes from its offset; a would-block parks the writer until the program says the link
//! is writable. Nothing is copied on the way out.
//!
//! # Datagrams and groups
//!
//! A datagram is one batch: the program takes it whole or not at all, so a send it answers with
//! fewer bytes than it was given fails the link. A would-block parks the writer as on a stream.
//! What arrives is read whole, with the source the program named for it: a group's members are
//! told apart by it, so a group's datagrams must name one.

use std::future::poll_fn;
use std::io;
#[cfg(any(feature = "transport-link-udp", feature = "transport-multicast"))]
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use wz_session_core::app_link_table::{
    AcceptRead, AppLinkKind, AppLinkTable, LinkHandle, OpenProgress, SendGate, SendStep, StreamRead,
};
#[cfg(any(feature = "transport-link-udp", feature = "transport-multicast"))]
use wz_session_core::app_link_table::{DatagramRead, Received};
pub use wz_session_core::app_transport::{AppPort, AppTransport, TableLock};
use wz_session_core::link::LinkKind;

use crate::link_interfaces::{addressless_link_endpoints, addressless_link_subject};
use crate::stream_link::{writer_task, StreamReadDriver, StreamWriteDriver};
use crate::writer_queue::WriterHandle;

/// The host's lock for a transport's table: a `std::sync::Mutex`, taken as it is when a panic left
/// it poisoned (every table method leaves the table consistent).
pub struct HostTableLock(Mutex<AppLinkTable>);

impl HostTableLock {
    /// `table`, behind the host's lock.
    pub fn new(table: AppLinkTable) -> Self {
        Self(Mutex::new(table))
    }
}

impl TableLock for HostTableLock {
    fn lock_with(&self, f: &mut dyn FnMut(&mut AppLinkTable)) {
        f(&mut self
            .0
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner()));
    }
}

/// A transport over `port`, under the host's lock, whose links queue at most the build's
/// `APP_LINK_QUEUE_BYTES`.
pub fn host_transport(port: Box<dyn AppPort>) -> Arc<AppTransport> {
    Arc::new(AppTransport::new(
        Box::new(HostTableLock::new(AppLinkTable::new())),
        port,
    ))
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

/// The socket address a locator names, when it names a numeric one.
#[cfg(any(feature = "transport-link-udp", feature = "transport-multicast"))]
fn locator_socket(locator: &str) -> Option<SocketAddr> {
    locator_address(locator).parse().ok()
}

/// Open a link of `kind` for `locator` and wait until the program says it is up. The link is
/// released (and closed on the program) when the returned guard drops, or when this future is
/// dropped before it completes.
async fn open_link(
    transport: &Arc<AppTransport>,
    kind: AppLinkKind,
    locator: &str,
) -> io::Result<Arc<AppLinkGuard>> {
    let handle = transport.begin_open(kind, locator);
    let guard = Arc::new(AppLinkGuard::new(Arc::clone(transport), handle));
    poll_fn(|cx| {
        let progress = transport.with(|table| table.poll_open(handle, Some(cx.waker())));
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
pub async fn dial_stream(transport: &Arc<AppTransport>, locator: &str) -> io::Result<AppStream> {
    let guard = open_link(transport, AppLinkKind::StreamDial, locator).await?;
    Ok(AppStream {
        guard,
        local: None,
        remote: Some(locator_address(locator).to_owned()),
    })
}

/// Listen for streams on `locator` (a `tcp/` locator) over the program's stack.
pub async fn listen_stream(
    transport: &Arc<AppTransport>,
    locator: &str,
) -> io::Result<AppListener> {
    let guard = open_link(transport, AppLinkKind::StreamListen, locator).await?;
    Ok(AppListener {
        guard,
        address: locator_address(locator).to_owned(),
    })
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
            self.transport.release(self.handle);
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
        let transport = &self.guard.transport;
        let unfilled = buf.initialize_unfilled();
        let (read, drained) = transport.with(|table| {
            let read = table.read_stream(handle, unfilled, Some(cx.waker()));
            (read, table.take_drained())
        });
        transport.perform(drained);
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

/// One send of `bytes` on `guard`'s link as far as the program takes it now: `Ready` with what it
/// took, or `Pending` with the waker kept for the link's next writable.
fn poll_send(guard: &AppLinkGuard, cx: &mut Context<'_>, bytes: &[u8]) -> Poll<io::Result<usize>> {
    let transport = &guard.transport;
    let handle = guard.handle;
    loop {
        let gate = transport.with(|table| table.begin_send(handle, Some(cx.waker())));
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
        let answer = transport.port().send(handle, bytes);
        let (step, effects) =
            transport.with(|table| table.send_answered(ticket, bytes.len(), answer));
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
        poll_send(&self.guard, cx, buf)
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
        let (guard, remote) = self.accept_link().await?;
        let stream = AppStream {
            guard,
            local: Some(self.address.clone()),
            remote: Some(locator_address(&remote).to_owned()),
        };
        Ok((stream, remote))
    }

    /// The datagrams of the next source the program accepts on a datagram listener, as a datagram
    /// link to it. Cancel-safe as [`Self::accept`] is.
    #[cfg(feature = "transport-link-udp")]
    pub async fn accept_datagram(&self) -> io::Result<(AppDatagram, String)> {
        let (guard, remote) = self.accept_link().await?;
        let link = AppDatagram {
            guard,
            locator: remote.clone(),
        };
        Ok((link, remote))
    }

    /// The next link the program accepts on the listener, and the locator it named for it.
    async fn accept_link(&self) -> io::Result<(Arc<AppLinkGuard>, String)> {
        let transport = &self.guard.transport;
        let listener = self.guard.handle;
        let (handle, remote) = poll_fn(|cx| {
            let next = transport.with(|table| table.next_accepted(listener, Some(cx.waker())));
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
        Ok((
            Arc::new(AppLinkGuard::new(Arc::clone(transport), handle)),
            remote,
        ))
    }
}

/// Listen for datagrams on `locator` (a `udp/` locator naming no interface) over the program's
/// stack: the program accepts each source that sends to it as a link of its own.
#[cfg(feature = "transport-link-udp")]
pub async fn listen_datagram(
    transport: &Arc<AppTransport>,
    locator: &str,
) -> io::Result<AppListener> {
    let guard = open_link(transport, AppLinkKind::DatagramListen, locator).await?;
    Ok(AppListener {
        guard,
        address: locator_address(locator).to_owned(),
    })
}

/// The next datagram of `guard`'s link: `Ready(Some)` with it, `Ready(None)` at its end, or
/// `Pending` with the waker kept.
#[cfg(any(feature = "transport-link-udp", feature = "transport-multicast"))]
fn poll_datagram(guard: &AppLinkGuard, cx: &mut Context<'_>) -> Poll<Option<Received>> {
    let transport = &guard.transport;
    let handle = guard.handle;
    let (read, drained) = transport.with(|table| {
        let read = table.read_datagram(handle, Some(cx.waker()));
        (read, table.take_drained())
    });
    transport.perform(drained);
    match read {
        DatagramRead::Datagram(datagram) => Poll::Ready(Some(datagram)),
        DatagramRead::Empty => Poll::Pending,
        DatagramRead::End => Poll::Ready(None),
    }
}

/// Send one datagram whole on `guard`'s link, waiting while the program would block. A program
/// that takes fewer bytes than the datagram has cut it, which fails the link.
#[cfg(any(feature = "transport-link-udp", feature = "transport-multicast"))]
async fn send_datagram(guard: &AppLinkGuard, datagram: &[u8]) -> io::Result<()> {
    let taken = poll_fn(|cx| poll_send(guard, cx, datagram)).await?;
    if taken == datagram.len() {
        Ok(())
    } else {
        Err(io::Error::other(
            "the program's transport took part of a datagram",
        ))
    }
}

/// A unicast datagram link over the program's stack (a `udp/` connect locator).
#[cfg(feature = "transport-link-udp")]
pub struct AppDatagram {
    guard: Arc<AppLinkGuard>,
    /// The locator the link was dialled to.
    locator: String,
}

/// Open a datagram link to `locator` (a `udp/` locator) over the program's stack.
#[cfg(feature = "transport-link-udp")]
pub async fn dial_datagram(
    transport: &Arc<AppTransport>,
    locator: &str,
) -> io::Result<AppDatagram> {
    let guard = open_link(transport, AppLinkKind::Datagram, locator).await?;
    Ok(AppDatagram {
        guard,
        locator: locator.to_owned(),
    })
}

/// The read driver of a datagram link over the program's stack: each datagram one batch, from
/// the peer it was dialled to.
#[cfg(feature = "transport-link-udp")]
pub struct AppDatagramReadDriver {
    guard: Arc<AppLinkGuard>,
    /// What the session keys the peer by: the dialled address, or nothing numeric.
    peer: SocketAddr,
    /// Tripped by the writer when a send fails: the link is lost then, as a socket's is.
    write_fault: crate::udp_pipeline::DatagramWriteWatch,
}

#[cfg(feature = "transport-link-udp")]
impl crate::LinkDriver for AppDatagramReadDriver {
    async fn open(&mut self) -> io::Result<()> {
        Ok(())
    }

    async fn send(
        &mut self,
        _frame: &crate::TxFrame<'_>,
        _reliability: crate::Reliability,
    ) -> io::Result<()> {
        Err(io::Error::new(
            io::ErrorKind::NotConnected,
            "the read side of a datagram link does not send; its write driver does",
        ))
    }

    async fn close(&mut self) -> io::Result<()> {
        self.guard.release();
        Ok(())
    }

    async fn poll_event(&mut self) -> crate::LinkEvent {
        let guard = Arc::clone(&self.guard);
        let peer = self.peer;
        tokio::select! {
            biased;
            () = self.write_fault.tripped() => crate::LinkEvent::Lost {
                cause: crate::LostCause::OsError,
            },
            datagram = poll_fn(|cx| poll_datagram(&guard, cx)) => match datagram {
                Some(datagram) => crate::LinkEvent::Rx(crate::RxFrame::with_src(datagram.bytes, peer)),
                None => crate::LinkEvent::Lost {
                    cause: crate::LostCause::PeerClosed,
                },
            },
        }
    }
}

/// Write what the session queues on a datagram link through the program, one datagram per batch,
/// until the queue ends or a send fails, which trips `fault`.
#[cfg(feature = "transport-link-udp")]
async fn app_datagram_writer(
    guard: Arc<AppLinkGuard>,
    mut queue: crate::writer_queue::OutboundQueue,
    fault: crate::udp_pipeline::DatagramWriteFault,
) {
    while let Some(mut payload) = queue.next_wire().await {
        payload.begin_write();
        match queue.guarded(send_datagram(&guard, &payload)).await {
            Some(Ok(())) => queue.recycle_wire(payload),
            Some(Err(error)) => {
                fault.trip(&error);
                return;
            }
            None => return,
        }
    }
}

/// Wire a datagram link over the program's stack into the drivers the session consumes, as
/// `crate::udp_pipeline::wire_udp_socket` wires a socket: the read driver, the shared datagram
/// write driver over the writer queue, and the handle of the writer task that sends through the
/// program.
#[cfg(feature = "transport-link-udp")]
pub fn wire_app_datagram(
    link: AppDatagram,
) -> (
    AppDatagramReadDriver,
    Arc<crate::udp_pipeline::UdpWriteDriver>,
    WriterHandle,
) {
    let AppDatagram { guard, locator } = link;
    let (fault, watch) = crate::udp_pipeline::DatagramWriteFault::channel();
    let peer = locator_socket(&locator).unwrap_or(SocketAddr::from(([0, 0, 0, 0], 0)));
    let inbound = AppDatagramReadDriver {
        guard: Arc::clone(&guard),
        peer,
        write_fault: watch,
    };
    let (tx, rx) = crate::writer_queue::datagram_outbound_channel();
    let writer_handle = WriterHandle::spawn(rx, |queue| app_datagram_writer(guard, queue, fault));
    let outbound = Arc::new(crate::udp_pipeline::UdpWriteDriver::new(
        tx,
        // No interface of the system carries it: the program's stack does.
        addressless_link_subject(LinkKind::Udp, Vec::new()),
        None,
    ));
    (inbound, outbound, writer_handle)
}

/// A multicast group joined over the program's stack (a `udp/` listen locator with `#iface=`):
/// the group link the multicast glue drives. Leaving the group is closing the link, which the
/// program hears as `close`.
#[cfg(feature = "transport-multicast")]
pub struct AppGroupDriver {
    guard: Arc<AppLinkGuard>,
    /// The group's locator, without its metadata: what both ends of the link are labelled by,
    /// since the address this node's datagrams leave from is the program's to know.
    group: String,
}

/// Join the group `locator` names over the program's stack.
#[cfg(feature = "transport-multicast")]
pub async fn join_group(
    transport: &Arc<AppTransport>,
    locator: &str,
) -> io::Result<AppGroupDriver> {
    let guard = open_link(transport, AppLinkKind::Group, locator).await?;
    Ok(AppGroupDriver {
        guard,
        group: format!("udp/{}", locator_address(locator)),
    })
}

#[cfg(feature = "transport-multicast")]
impl crate::LinkDriver for AppGroupDriver {
    async fn open(&mut self) -> io::Result<()> {
        Ok(())
    }

    async fn send(
        &mut self,
        _frame: &crate::TxFrame<'_>,
        _reliability: crate::Reliability,
    ) -> io::Result<()> {
        // The group is written through its send half, which the transmit task owns.
        Err(io::Error::new(
            io::ErrorKind::NotConnected,
            "a group link sends through its datagram sender",
        ))
    }

    async fn close(&mut self) -> io::Result<()> {
        self.guard.release();
        Ok(())
    }

    async fn poll_event(&mut self) -> crate::LinkEvent {
        let guard = Arc::clone(&self.guard);
        loop {
            match poll_fn(|cx| poll_datagram(&guard, cx)).await {
                // A member is told apart by the source the program named (the table refuses a
                // group's datagram that names none); one whose source is not an address the
                // session can key is dropped, as a socket drops one it cannot read.
                Some(Received {
                    bytes,
                    source: Some(source),
                }) => match locator_socket(&source) {
                    Some(src) => return crate::LinkEvent::Rx(crate::RxFrame::with_src(bytes, src)),
                    None => continue,
                },
                Some(_) => continue,
                None => {
                    return crate::LinkEvent::Lost {
                        cause: crate::LostCause::PeerClosed,
                    }
                }
            }
        }
    }
}

#[cfg(feature = "transport-multicast")]
impl crate::multicast_glue::MulticastLinkDriver for AppGroupDriver {
    type Sender = AppGroupSender;

    fn datagram_sender(&self) -> io::Result<AppGroupSender> {
        Ok(AppGroupSender {
            guard: Arc::clone(&self.guard),
        })
    }

    fn group_locators(&self) -> io::Result<(String, String)> {
        Ok((self.group.clone(), self.group.clone()))
    }
}

/// The send half of an [`AppGroupDriver`], which the transmit task owns.
#[cfg(feature = "transport-multicast")]
pub struct AppGroupSender {
    guard: Arc<AppLinkGuard>,
}

#[cfg(feature = "transport-multicast")]
impl crate::multicast_glue::MulticastDatagramSender for AppGroupSender {
    fn send(&self, datagram: &[u8]) -> impl core::future::Future<Output = io::Result<()>> + Send {
        let guard = Arc::clone(&self.guard);
        let datagram = datagram.to_vec();
        async move { send_datagram(&guard, &datagram).await }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use wz_session_core::app_link_table::{InboundRefusal, ProgramEvent, ProgramOpen, ProgramSend};

    /// A port that records what the session asked and answers from a script.
    #[derive(Default)]
    struct Script {
        opens: Mutex<Vec<(LinkHandle, AppLinkKind, String)>>,
        sent: Mutex<Vec<u8>>,
        datagrams: Mutex<Vec<Vec<u8>>>,
        closes: Mutex<Vec<LinkHandle>>,
        drained: Mutex<Vec<LinkHandle>>,
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
                let n = n.min(bytes.len());
                self.0.sent.lock().unwrap().extend_from_slice(&bytes[..n]);
                self.0.datagrams.lock().unwrap().push(bytes[..n].to_vec());
            }
            answer
        }

        fn close(&self, link: LinkHandle) {
            self.0.closes.lock().unwrap().push(link);
        }

        fn drained(&self, link: LinkHandle) {
            self.0.drained.lock().unwrap().push(link);
        }
    }

    fn transport_bounded(bound: usize) -> (Arc<Script>, Arc<AppTransport>) {
        let script = Arc::new(Script::default());
        let transport = Arc::new(AppTransport::new(
            Box::new(HostTableLock::new(AppLinkTable::with_queue_bound(bound))),
            Box::new(ScriptPort(Arc::clone(&script))),
        ));
        (script, transport)
    }

    fn transport() -> (Arc<Script>, Arc<AppTransport>) {
        transport_bounded(1 << 16)
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

    #[cfg(any(feature = "transport-link-udp", feature = "transport-multicast"))]
    #[test]
    fn a_locator_names_a_socket_address_only_when_it_is_numeric() {
        assert_eq!(
            locator_socket("udp/192.0.2.5:7447"),
            Some(SocketAddr::from(([192, 0, 2, 5], 7447)))
        );
        assert_eq!(locator_socket("udp/a-name:7447"), None);
    }

    #[tokio::test]
    async fn a_dialled_stream_writes_through_the_port_and_reads_what_the_program_hands_in() {
        let (script, transport) = transport();
        let stream = dial_stream(&transport, "tcp/192.0.2.5:7447")
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
        let stream = dial_stream(&transport, "tcp/192.0.2.5:7447").await.unwrap();
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
        let error = dial_stream(&transport, "tcp/192.0.2.5:7447")
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
        let stream = dial_stream(&transport, "tcp/192.0.2.5:7447").await.unwrap();
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
        let stream = dial_stream(&transport, "tcp/192.0.2.5:7447").await.unwrap();
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
        let listener = listen_stream(&transport, "tcp/192.0.2.5:7447")
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
            tokio::spawn(async move { dial_stream(&transport, "tcp/192.0.2.5:7447").await })
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

    #[tokio::test]
    async fn a_full_stream_tells_the_program_when_the_session_has_read_it_down() {
        let (script, transport) = transport_bounded(4);
        let stream = dial_stream(&transport, "tcp/192.0.2.5:7447").await.unwrap();
        let handle = stream.handle();
        let (mut read, _write) = stream.into_split();
        transport.received(handle, b"abcd", None).unwrap();
        assert_eq!(
            transport.received(handle, b"e", None),
            Err(InboundRefusal::Full)
        );
        let mut buf = [0u8; 4];
        read.read_exact(&mut buf).await.unwrap();
        assert_eq!(script.drained.lock().unwrap().as_slice(), [handle]);
        transport
            .received(handle, b"e", None)
            .expect("the retry is taken");
    }

    #[cfg(feature = "transport-link-udp")]
    #[tokio::test]
    async fn a_datagram_link_sends_each_batch_whole_and_reads_each_datagram_with_its_peer() {
        use crate::LinkDriver as _;
        let (script, transport) = transport();
        let link = dial_datagram(&transport, "udp/192.0.2.6:7447")
            .await
            .unwrap();
        let handle = link.guard.handle();
        let (mut inbound, outbound, _writer) = wire_app_datagram(link);
        use wz_session_core::link::BoxedLinkDriver as _;
        let _ = outbound.send_blocking(b"batch-one", crate::Reliability::BestEffort);
        for _ in 0..200 {
            if !script.datagrams.lock().unwrap().is_empty() {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(5)).await;
        }
        assert_eq!(
            script.datagrams.lock().unwrap().as_slice(),
            [b"batch-one".to_vec()]
        );
        transport
            .received(handle, b"in", Some("udp/192.0.2.6:7447"))
            .unwrap();
        match inbound.poll_event().await {
            crate::LinkEvent::Rx(_) => {}
            other => panic!("a datagram is one Rx, not {other:?}"),
        }
    }

    #[cfg(feature = "transport-link-udp")]
    #[tokio::test]
    async fn a_datagram_the_program_cuts_fails_the_send() {
        let (script, transport) = transport();
        *script.send_answers.lock().unwrap() = vec![ProgramSend::Wrote(3)];
        let link = dial_datagram(&transport, "udp/192.0.2.6:7447")
            .await
            .unwrap();
        let error = send_datagram(&link.guard, b"abcdef")
            .await
            .err()
            .expect("cut");
        assert_eq!(error.kind(), io::ErrorKind::Other);
    }

    #[cfg(feature = "transport-multicast")]
    #[tokio::test]
    async fn a_group_link_keys_each_member_by_the_source_the_program_named() {
        use crate::multicast_glue::MulticastLinkDriver as _;
        use crate::LinkDriver as _;
        let (script, transport) = transport();
        let mut group = join_group(&transport, "udp/239.7.7.7:7447#iface=lan7")
            .await
            .unwrap();
        let handle = group.guard.handle();
        assert_eq!(
            script.opens.lock().unwrap()[0].1,
            AppLinkKind::Group,
            "the program is asked to join"
        );
        assert_eq!(
            group.group_locators().unwrap(),
            (
                "udp/239.7.7.7:7447".to_owned(),
                "udp/239.7.7.7:7447".to_owned()
            )
        );
        // A datagram with no source is refused; one whose source is no address is dropped; one
        // with a source is read with it.
        assert_eq!(
            transport.received(handle, b"anon", None),
            Err(InboundRefusal::NoSource)
        );
        transport
            .received(handle, b"named", Some("udp/a-name:7447"))
            .unwrap();
        transport
            .received(handle, b"member", Some("udp/198.51.100.20:7447"))
            .unwrap();
        match group.poll_event().await {
            crate::LinkEvent::Rx(_) => {}
            other => panic!("the sourced datagram is read, not {other:?}"),
        }
        assert_eq!(transport.with(|table| table.queued_bytes(handle)), 0);
        // Leaving the group is closing the link on the program.
        group.close().await.unwrap();
        assert_eq!(script.closes.lock().unwrap().as_slice(), [handle]);
    }
}
