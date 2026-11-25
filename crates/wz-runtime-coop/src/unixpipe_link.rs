// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The session's link over a pair of named FIFOs on this host (`unixpipe/`), as zenoh's unixpipe
//! link makes one, and the stack that opens it beside the links of another.
//!
//! A platform supplies a [`FifoOpen`]: it creates, opens, locks and removes the FIFOs, and draws
//! the suffix that names a link's pair. The rest is here, written once. A listener on the base
//! path `P` reads invitations on `P_uplink`; a dial reserves a pair `P_downlink<s>` and
//! `P_uplink<s>` under a random `u32` `s`, writes the invitation (`DE AD BE EF` and `s` in the
//! host's byte order), and the two confirm `s` on the pair, the listener first
//! (`io/zenoh-links/zenoh-link-unixpipe/src/unix/unicast.rs` @ `static PIPE_INVITATION: &[u8] = &[0xDE, 0xAD, 0xBE, 0xEF];`).
//! Each end then reads the FIFO it holds the lock of and writes the other, and the batches cross
//! it as over any stream, behind their length (`is_streamed`), through the stream link
//! ([`StreamDriver`](crate::stream_link::StreamDriver)) over a [`PipeStream`].
//!
//! Both handshakes step without waiting: a dial is asked again until it is made
//! ([`SessionLinks::begin_initiator`]), and a listener takes one invitation at a time, as
//! upstream's does, and gives up on one its dialer does not confirm within
//! [`HANDSHAKE_TIMEOUT_US`], which upstream's listener has no bound for.

use alloc::boxed::Box;
use alloc::format;
use alloc::string::String;
use core::cell::RefCell;
use core::ffi::c_int;
use core::fmt::Debug;

use wz_session_core::byte_cells::LentByteCells;
use wz_session_core::group_locator::GroupLocator;

use crate::group_transport::GroupTransport;
use crate::ip_stack::{heap_link, HeapLink};
use crate::link_cells::{CellRc, CountKind, OneTask};
use crate::link_storage::{heap_link_buffers, LinkTables, RxBuffer, RxStore, TxBuffer, TxStore};
use crate::session_drive::{
    LinkListener, LinkOpenError, Locator, OpenedLink, PendingDial, SessionDatagramLink,
    SessionLinks, UnixpipeLocator, WaitOn,
};
use crate::stream_link::{
    link_over, stream_ends_fit, StreamDriver, StreamEnds, StreamSocket, STREAM_RX_CAPACITY,
};

/// The mode a link's FIFOs are created with when its locator names none: owner only.
///
/// Upstream's default is `0o777` (`io/zenoh-links/zenoh-link-unixpipe/src/unix/mod.rs` @
/// `pub const FILE_ACCESS_MASK_DEFAULT: u32 = 0o777;`), which lets any account of the host
/// write frames into another's session; wz's tokio engine declines it for that reason and makes
/// the permissive mode one a locator writes (`file_mask=511`), and this engine reads a locator
/// as that one does (`docs/upstream-parity.md`).
pub const UNIXPIPE_DEFAULT_FILE_MASK: u32 = 0o600;

/// The longest a listener waits for the dialer of an invitation to confirm it, in microseconds:
/// wz's tokio listener's bound, the default of zenoh's `transport/unicast/accept_timeout`.
pub const HANDSHAKE_TIMEOUT_US: u64 = 10_000_000;

/// The longest a dial that must be waited out waits, in microseconds: the connect timeout of a
/// zenoh-pico session, which a waiting serial dial is held to as well.
const OPEN_WAIT_US: u64 = 10_000_000;

/// How many suffixes a dial draws before it gives up finding a free pair
/// (`io/zenoh-links/zenoh-link-unixpipe/src/unix/unicast.rs` @ `const LINUX_PIPE_DEDICATE_TRIES: usize = 100;`).
const DEDICATE_TRIES: usize = 100;

/// What every invitation and confirmation opens with.
const PIPE_INVITATION: [u8; 4] = [0xDE, 0xAD, 0xBE, 0xEF];

/// An invitation: the magic and a suffix.
const INVITATION_LEN: usize = 8;

/// One open FIFO end: a platform's descriptor. Only the one thread that drives the link touches
/// it. A read end the platform created and locked removes its node when it is let go, as
/// upstream's does (`io/zenoh-links/zenoh-link-unixpipe/src/unix/unicast.rs` @ `let _ = unlink(self.path.as_str());`).
pub trait Fifo: Sized {
    /// Why a call failed, as the platform reports it. `Copy`, because a link keeps the last
    /// failure for the deploy to report.
    type Error: Copy + Debug;

    /// Write `bytes` as far as the FIFO takes them now, without waiting: how many it took, `0`
    /// when it has no room.
    fn write(&self, bytes: &[u8]) -> Result<usize, Self::Error>;

    /// Read what is queued into `buf` without blocking: `Ok(Some(n))` for `n` bytes,
    /// `Ok(Some(0))` when no writer holds the FIFO open (the end of the stream, once the peer's
    /// writer has), `Ok(None)` when nothing is queued.
    fn try_read(&self, buf: &mut [u8]) -> Result<Option<usize>, Self::Error>;

    /// Block until bytes are queued or `timeout_ms` has passed, and return at once when some
    /// already are.
    fn wait_readable(&self, timeout_ms: c_int);

    /// Wait up to `timeout_us` microseconds for the FIFO to take more bytes: whether it will,
    /// and how long the wait took, as [`StreamSocket::wait_writable`] answers.
    fn wait_writable(&self, timeout_us: u64) -> (bool, u64) {
        let _ = timeout_us;
        (true, 0)
    }

    /// What a thread other than the link's waits on for this FIFO's input; `None` when the
    /// platform gives none.
    fn input_wait(&self) -> Option<WaitOn> {
        None
    }

    /// What a thread other than the link's waits on for room on this FIFO; `None` when the
    /// platform gives none.
    fn room_wait(&self) -> Option<WaitOn> {
        None
    }
}

/// How a stack opens the FIFOs its `unixpipe/` links run over: a value the stack holds.
pub trait FifoOpen {
    /// The FIFO end this platform opens.
    type Fifo: Fifo;

    /// The FIFO at `path`, created with `mode` when there is none (one that is there is kept,
    /// with its mode), open for reading without waiting for a writer and locked for this end
    /// alone, as upstream opens every FIFO it reads
    /// (`io/zenoh-links/zenoh-link-unixpipe/src/unix/unicast.rs` @ `AdvisoryFileLock::try_lock(&read, FileLockMode::Exclusive)?;`).
    /// [`LinkOpenError::AddressInUse`] when another end holds the lock, which the node then
    /// keeps; [`LinkOpenError::Refused`] when it cannot be made or opened.
    fn reader(&self, path: &str, mode: u32) -> Result<Self::Fifo, LinkOpenError>;

    /// The request FIFO of a listener at `path`, created with `mode` when there is none, open for
    /// reading and locked as [`Self::reader`] opens one, and read as one that never ends: dials
    /// come and go on it, and one that let it go is no end of the listener.
    /// [`LinkOpenError::AddressInUse`] when another listener holds it.
    fn listen(&self, path: &str, mode: u32) -> Result<Self::Fifo, LinkOpenError>;

    /// The request FIFO of a listener at `path`, open for writing: [`LinkOpenError::Refused`]
    /// when no listener reads it, a node there is none of or one whose lock nobody holds
    /// (`io/zenoh-links/zenoh-link-unixpipe/src/unix/unicast.rs` @ `bail!("no listener...")`).
    fn request(&self, path: &str) -> Result<Self::Fifo, LinkOpenError>;

    /// The FIFO at `path` its peer reads, open for writing without waiting for a reader.
    fn writer(&self, path: &str) -> Result<Self::Fifo, LinkOpenError>;

    /// A suffix for a dial to name its pair by, drawn at random.
    fn suffix(&self) -> u32;

    /// The platform's monotonic clock, in microseconds: what a handshake is timed on.
    fn now_us(&self) -> u64;
}

/// A link's two FIFOs as one stream: it reads the one it holds the lock of and writes the other,
/// and names them its two ends, as upstream names a unixpipe link's (`src` the FIFO an end reads,
/// `dst` the one it writes).
pub struct PipeStream<F: Fifo> {
    read: F,
    write: F,
    read_node: String,
    write_node: String,
}

impl<F: Fifo> StreamSocket for PipeStream<F> {
    type Error = F::Error;

    type Link<B: RxStore + 'static, X: TxStore + 'static>
        = StreamDriver<Self, B, X>
    where
        Self: 'static;

    const WRITES_NOW: bool = true;

    fn ends(&self) -> StreamEnds<'_> {
        StreamEnds::Unixpipe {
            local: &self.read_node,
            peer: &self.write_node,
        }
    }

    fn write(&self, bytes: &[u8]) -> Result<usize, F::Error> {
        self.write.write(bytes)
    }

    fn wait_readable(&self, timeout_ms: c_int) {
        self.read.wait_readable(timeout_ms);
    }

    fn wait_writable(&self, timeout_us: u64) -> (bool, u64) {
        self.write.wait_writable(timeout_us)
    }

    fn try_read(&self, buf: &mut [u8]) -> Result<Option<usize>, F::Error> {
        self.read.try_read(buf)
    }

    // Upstream's close of the link does nothing (`io/zenoh-links/zenoh-link-unixpipe/src/unix/unicast.rs` @
    // `tracing::trace!("Closing Unix Pipe link: {}", self);`): the FIFOs close when the link is let
    // go, and the peer reads the end of its stream then.
    fn shutdown(&self) {}

    fn input_wait(&self) -> Option<WaitOn> {
        self.read.input_wait()
    }

    fn room_wait(&self) -> Option<WaitOn> {
        self.write.room_wait()
    }
}

/// The request FIFO of a listener on `base`, the dedicated FIFO a dialer writes, and the one a
/// listener writes, of the pair `suffix` names
/// (`io/zenoh-links/zenoh-link-unixpipe/src/unix/unicast.rs` @ `fn get_dedicated_pipe_names(`).
fn request_path(base: &str) -> String {
    format!("{base}_uplink")
}

fn uplink_path(base: &str, suffix: u32) -> String {
    format!("{base}_uplink{suffix}")
}

fn downlink_path(base: &str, suffix: u32) -> String {
    format!("{base}_downlink{suffix}")
}

/// The invitation, or the confirmation, of the pair `suffix` names.
fn invitation(suffix: u32) -> [u8; INVITATION_LEN] {
    let mut bytes = [0u8; INVITATION_LEN];
    let (magic, rest) = bytes.split_at_mut(PIPE_INVITATION.len());
    magic.copy_from_slice(&PIPE_INVITATION);
    rest.copy_from_slice(&suffix.to_ne_bytes());
    bytes
}

/// Write the invitation of `suffix` whole into `fifo`: `Ok(true)` once written, `Ok(false)`
/// when the FIFO has no room yet. Eight bytes are fewer than any FIFO writes at once, so it takes
/// all of them or none. A failed write is [`LinkOpenError::Refused`].
fn send_invitation<F: Fifo>(fifo: &F, suffix: u32) -> Result<bool, LinkOpenError> {
    match fifo.write(&invitation(suffix)) {
        Ok(0) => Ok(false),
        Ok(INVITATION_LEN) => Ok(true),
        Ok(_) | Err(_) => Err(LinkOpenError::Refused),
    }
}

/// An invitation being read: its bytes so far.
#[derive(Default)]
struct Reading {
    held: [u8; INVITATION_LEN],
    filled: usize,
}

/// What a read of an invitation found.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Read {
    /// Not all eight bytes yet.
    Partial,
    /// An invitation of this suffix.
    Suffix(u32),
    /// Eight bytes that open with no invitation's magic.
    NotAnInvitation,
}

impl Reading {
    /// Read what `fifo` holds of the invitation. A FIFO no writer holds yet reads as nothing
    /// queued, as upstream reads it (`io/zenoh-links/zenoh-link-unixpipe/src/unix/unicast.rs` @
    /// `Ok(0) => Err(ErrorKind::WouldBlock.into()),`): a handshake reads its peer's FIFO before
    /// the peer has opened it. A failed read is [`LinkOpenError::Refused`].
    fn read<F: Fifo>(&mut self, fifo: &F) -> Result<Read, LinkOpenError> {
        while self.filled < INVITATION_LEN {
            let room = self.held.get_mut(self.filled..).unwrap_or_default();
            match fifo.try_read(room) {
                Ok(Some(0) | None) => return Ok(Read::Partial),
                Ok(Some(n)) => self.filled = self.filled.saturating_add(n).min(INVITATION_LEN),
                Err(_) => return Err(LinkOpenError::Refused),
            }
        }
        self.filled = 0;
        let (magic, suffix) = self.held.split_at(PIPE_INVITATION.len());
        Ok(match <[u8; 4]>::try_from(suffix) {
            Ok(suffix) if magic == PIPE_INVITATION => Read::Suffix(u32::from_ne_bytes(suffix)),
            _ => Read::NotAnInvitation,
        })
    }
}

/// The link over a pair of FIFOs, as a stack of the heap profile holds it.
type PipeDriver<F, B> = StreamDriver<PipeStream<F>, RxBuffer<B>, TxBuffer<B>>;

/// What every unixpipe link of a [`UnixpipeLinks`] is given besides its FIFOs: the session's
/// tables and cells when it lent them, the slots its frames are encoded into, and whether its
/// owner waits.
struct PipeShape<N: CountKind> {
    lent: Option<LinkTables<N::Flag>>,
    cells: Option<LentByteCells<N::Flag>>,
    owner_waits: bool,
    tx_slots: usize,
    tx_capacity: usize,
}

// Not derived: a derive would ask `N: Clone` and `N: Default` of a kind of count.
impl<N: CountKind> Clone for PipeShape<N> {
    fn clone(&self) -> Self {
        *self
    }
}

impl<N: CountKind> Copy for PipeShape<N> {}

impl<N: CountKind> Default for PipeShape<N> {
    fn default() -> Self {
        Self {
            lent: None,
            cells: None,
            owner_waits: false,
            tx_slots: 0,
            tx_capacity: 0,
        }
    }
}

impl<N: CountKind> PipeShape<N> {
    /// The stream link over `pipe`, its handshake made: buffers claimed as every link's of the
    /// stack are, refused when the rows of the build do not name both its FIFOs, made in a cell
    /// when the stack was lent some.
    fn link<F: Fifo + 'static>(
        &self,
        pipe: PipeStream<F>,
    ) -> Result<OpenedLink<HeapLink<N>, N>, LinkOpenError> {
        let (rx, tx) = heap_link_buffers(
            self.lent.as_ref(),
            STREAM_RX_CAPACITY,
            self.tx_slots,
            self.tx_capacity,
        )?;
        heap_link::<_, N>(self.cells.as_ref(), stream_ends_fit(&pipe))?.open(|place| {
            let link = place.write(link_over(pipe, rx, tx));
            if self.owner_waits {
                link.wait_by_owner();
            }
            link
        })
    }
}

/// Where a dial stands.
enum DialStep<F> {
    /// The invitation is written once the request FIFO has room.
    Inviting,
    /// The invitation is written; the listener's confirmation is read off the downlink.
    Confirming(Reading),
    /// The listener confirmed; the dialer's confirmation is written on the uplink once it has
    /// room.
    Answering(F),
}

/// A `unixpipe/` dial under way ([`SessionLinks::begin_initiator`]): the pair reserved, and
/// each step of the handshake taken when it can be.
pub struct UnixpipeDial<O: FifoOpen, N: CountKind = OneTask> {
    opener: O,
    shape: PipeShape<N>,
    base: UnixpipeLocator,
    suffix: u32,
    request: Option<O::Fifo>,
    downlink: Option<O::Fifo>,
    step: Option<DialStep<O::Fifo>>,
}

impl<O: FifoOpen, N: CountKind> UnixpipeDial<O, N>
where
    O::Fifo: 'static,
{
    /// The dial of the listener `at` names: its request FIFO opened, a pair reserved under a
    /// suffix no other dial holds, and the invitation written when the FIFO takes it
    /// (`io/zenoh-links/zenoh-link-unixpipe/src/unix/unicast.rs` @ `async fn connect_to(endpoint: EndPoint)`).
    /// No listener is [`LinkOpenError::Refused`]; no free pair in [`DEDICATE_TRIES`] draws is
    /// [`LinkOpenError::Exhausted`].
    fn begin(opener: O, shape: PipeShape<N>, at: UnixpipeLocator) -> Result<Self, LinkOpenError> {
        let base = at.path.as_str();
        let mode = at.file_mask.unwrap_or(UNIXPIPE_DEFAULT_FILE_MASK);
        let request = opener.request(&request_path(base))?;
        let (suffix, downlink) = dedicate(&opener, base, mode)?;
        Ok(Self {
            opener,
            shape,
            base: at,
            suffix,
            request: Some(request),
            downlink: Some(downlink),
            step: Some(DialStep::Inviting),
        })
    }

    /// One step of the handshake: the link once both confirmed, a refusal once a FIFO failed or
    /// the listener confirmed another pair, `None` while it waits for the peer or for room.
    fn step_once(&mut self) -> Option<Result<OpenedLink<HeapLink<N>, N>, LinkOpenError>> {
        loop {
            let (next, advanced) = match self.step.take()? {
                DialStep::Inviting => match send_invitation(self.request.as_ref()?, self.suffix) {
                    Ok(true) => (DialStep::Confirming(Reading::default()), true),
                    Ok(false) => (DialStep::Inviting, false),
                    Err(refused) => return Some(Err(refused)),
                },
                DialStep::Confirming(mut reading) => match reading.read(self.downlink.as_ref()?) {
                    Ok(Read::Suffix(suffix)) if suffix == self.suffix => {
                        let uplink = uplink_path(self.base.path.as_str(), self.suffix);
                        match self.opener.writer(&uplink) {
                            Ok(uplink) => (DialStep::Answering(uplink), true),
                            Err(refused) => return Some(Err(refused)),
                        }
                    }
                    Ok(Read::Partial) => (DialStep::Confirming(reading), false),
                    Ok(Read::Suffix(_) | Read::NotAnInvitation) => {
                        return Some(Err(LinkOpenError::Refused))
                    }
                    Err(refused) => return Some(Err(refused)),
                },
                DialStep::Answering(uplink) => match send_invitation(&uplink, self.suffix) {
                    Ok(true) => {
                        self.request = None;
                        let base = self.base.path.as_str();
                        let pipe = PipeStream {
                            read: self.downlink.take()?,
                            write: uplink,
                            read_node: downlink_path(base, self.suffix),
                            write_node: uplink_path(base, self.suffix),
                        };
                        return Some(self.shape.link(pipe));
                    }
                    Ok(false) => (DialStep::Answering(uplink), false),
                    Err(refused) => return Some(Err(refused)),
                },
            };
            self.step = Some(next);
            if !advanced {
                return None;
            }
        }
    }

    /// The dial, waited out: asked again each time the downlink has something to read, until the
    /// listener confirms or [`OPEN_WAIT_US`] has passed on the opener's clock, which refuses it as
    /// an open worth trying later.
    fn wait(mut self) -> Result<OpenedLink<HeapLink<N>, N>, LinkOpenError> {
        let deadline = self.opener.now_us().saturating_add(OPEN_WAIT_US);
        loop {
            if let Some(made) = self.step_once() {
                return made;
            }
            let now = self.opener.now_us();
            if now >= deadline {
                return Err(LinkOpenError::Refused);
            }
            // A step that waits for room, not for the listener, is asked again within a few
            // milliseconds: the downlink's input does not tell it.
            let wait_ms = deadline.saturating_sub(now).div_ceil(1_000).min(10);
            let downlink = self.downlink.as_ref().ok_or(LinkOpenError::Refused)?;
            downlink.wait_readable(c_int::try_from(wait_ms).unwrap_or(c_int::MAX));
        }
    }
}

impl<O: FifoOpen, N: CountKind> PendingDial<HeapLink<N>, N> for UnixpipeDial<O, N>
where
    O::Fifo: 'static,
{
    fn poll(&mut self) -> Option<Result<OpenedLink<HeapLink<N>, N>, LinkOpenError>> {
        self.step_once()
    }
}

/// A pair for a dial on `base`: a suffix drawn until both its FIFOs are free, the downlink kept
/// open and locked as the dial's read end and the uplink created, found free and let go (its
/// listener makes it again), as upstream's dial does
/// (`io/zenoh-links/zenoh-link-unixpipe/src/unix/unicast.rs` @ `async fn dedicate_pipe(`).
fn dedicate<O: FifoOpen>(
    opener: &O,
    base: &str,
    mode: u32,
) -> Result<(u32, O::Fifo), LinkOpenError> {
    for _ in 0..DEDICATE_TRIES {
        let suffix = opener.suffix();
        let Ok(downlink) = opener.reader(&downlink_path(base, suffix), mode) else {
            continue;
        };
        if opener.reader(&uplink_path(base, suffix), mode).is_ok() {
            return Ok((suffix, downlink));
        }
    }
    Err(LinkOpenError::Exhausted)
}

/// An invitation a listener took, being answered: its pair open, the confirmation written, the
/// dialer's read back off the uplink until [`HANDSHAKE_TIMEOUT_US`] has passed.
struct Answering<F> {
    suffix: u32,
    uplink: F,
    downlink: F,
    reading: Reading,
    since_us: u64,
}

/// The accepting end of a `unixpipe/` path: it holds the request FIFO `<path>_uplink`, locked, so
/// one listener holds a path, and takes the invitations written there one at a time, each into a
/// link of its own (`io/zenoh-links/zenoh-link-unixpipe/src/unix/unicast.rs` @
/// `async fn handle_incoming_connections(`).
struct UnixpipeListener<O: FifoOpen, N: CountKind> {
    opener: O,
    at: UnixpipeLocator,
    shape: PipeShape<N>,
    request: O::Fifo,
    invitation: RefCell<Reading>,
    answering: RefCell<Option<Answering<O::Fifo>>>,
}

impl<O: FifoOpen, N: CountKind> UnixpipeListener<O, N>
where
    O::Fifo: 'static,
{
    /// Open the pair of an invitation of `suffix` and write its confirmation: the uplink made
    /// again and locked as this end's read end, the dialer's downlink opened to write. `None` when
    /// a FIFO cannot be had, and the invitation is dropped.
    fn answer(&self, suffix: u32) -> Option<Answering<O::Fifo>> {
        let base = self.at.path.as_str();
        let mode = self.at.file_mask.unwrap_or(UNIXPIPE_DEFAULT_FILE_MASK);
        let uplink = self.opener.reader(&uplink_path(base, suffix), mode).ok()?;
        let downlink = self.opener.writer(&downlink_path(base, suffix)).ok()?;
        match send_invitation(&downlink, suffix) {
            Ok(true) => Some(Answering {
                suffix,
                uplink,
                downlink,
                reading: Reading::default(),
                since_us: self.opener.now_us(),
            }),
            // A downlink with no room for eight bytes is no dialer's that waits for them.
            Ok(false) | Err(_) => None,
        }
    }

    /// One step of the invitation being answered: the link once the dialer confirmed it, `None`
    /// while it has not; one it confirmed with another suffix, or did not confirm in time, or
    /// whose FIFO failed, is dropped, its FIFOs with it. A link the session's tables have no
    /// buffers or cell left for is [`LinkOpenError::Exhausted`], and its FIFOs are let go.
    fn step_answer(&self) -> Result<Option<OpenedLink<HeapLink<N>, N>>, LinkOpenError> {
        let mut slot = self.answering.borrow_mut();
        let Some(answering) = slot.as_mut() else {
            return Ok(None);
        };
        match answering.reading.read(&answering.uplink) {
            Ok(Read::Suffix(suffix)) if suffix == answering.suffix => {
                let Some(Answering {
                    suffix,
                    uplink,
                    downlink,
                    ..
                }) = slot.take()
                else {
                    return Ok(None);
                };
                let base = self.at.path.as_str();
                let pipe = PipeStream {
                    read: uplink,
                    write: downlink,
                    read_node: uplink_path(base, suffix),
                    write_node: downlink_path(base, suffix),
                };
                self.shape.link(pipe).map(Some)
            }
            Ok(Read::Partial)
                if self.opener.now_us().saturating_sub(answering.since_us)
                    < HANDSHAKE_TIMEOUT_US =>
            {
                Ok(None)
            }
            _ => {
                slot.take();
                Ok(None)
            }
        }
    }
}

impl<O: FifoOpen, N: CountKind> LinkListener<HeapLink<N>, N> for UnixpipeListener<O, N>
where
    O::Fifo: 'static,
{
    fn local(&self) -> Locator {
        Locator::Unixpipe(self.at)
    }

    fn accept(&self) -> Result<Option<OpenedLink<HeapLink<N>, N>>, LinkOpenError> {
        loop {
            if self.answering.borrow().is_some() {
                return self.step_answer();
            }
            // Eight bytes that are no invitation were one writer's alone, so the next eight are a
            // new question; a request FIFO that fails answers the same way every time, and ends the
            // listener.
            let read = self
                .invitation
                .borrow_mut()
                .read(&self.request)
                .map_err(|_| LinkOpenError::Unsupported)?;
            match read {
                Read::Partial => return Ok(None),
                Read::NotAnInvitation => continue,
                Read::Suffix(suffix) => *self.answering.borrow_mut() = self.answer(suffix),
            }
        }
    }

    fn input_wait(&self) -> Option<WaitOn> {
        match self.answering.borrow().as_ref() {
            Some(answering) => answering.uplink.input_wait(),
            None => self.request.input_wait(),
        }
    }
}

/// A dial of [`UnixpipeLinks`]: the stack's, or a unixpipe one.
// Held by value in its face's link, as `ip_stack::IpDial` is: a link being made is not boxed.
#[allow(clippy::large_enum_variant)]
pub enum UnixpipeLinksDial<D, O: FifoOpen, N: CountKind = OneTask> {
    /// A dial of the stack the unixpipe links stand beside.
    Links(D),
    /// A `unixpipe/` dial.
    Unixpipe(UnixpipeDial<O, N>),
}

impl<D: PendingDial<HeapLink<N>, N>, O: FifoOpen, N: CountKind> PendingDial<HeapLink<N>, N>
    for UnixpipeLinksDial<D, O, N>
where
    O::Fifo: 'static,
{
    fn poll(&mut self) -> Option<Result<OpenedLink<HeapLink<N>, N>, LinkOpenError>> {
        match self {
            Self::Links(dial) => dial.poll(),
            Self::Unixpipe(dial) => dial.poll(),
        }
    }
}

/// A link made at once is the stack's: a unixpipe link is made by its handshake.
impl<D: From<OpenedLink<HeapLink<N>, N>>, O: FifoOpen, N: CountKind>
    From<OpenedLink<HeapLink<N>, N>> for UnixpipeLinksDial<D, O, N>
{
    fn from(opened: OpenedLink<HeapLink<N>, N>) -> Self {
        Self::Links(D::from(opened))
    }
}

/// The links of the stack `S` and unixpipe links beside them, over the FIFOs `O` opens: a
/// `unixpipe/` locator is dialled and listened on here, any other is the stack's. Unixpipe links
/// take their buffers and cells from what the session lends the stack, and are placed and waited
/// on as the stack's links of the heap profile are ([`HeapLink`]). `N` is how the sessions they
/// serve count the handles on a link, as `S`'s sessions do.
pub struct UnixpipeLinks<S, O, N: CountKind = OneTask> {
    links: S,
    opener: O,
    shape: PipeShape<N>,
}

impl<S, O: FifoOpen> UnixpipeLinks<S, O> {
    /// The links of `links`, and unixpipe links over the FIFOs `opener` opens.
    pub fn new(links: S, opener: O) -> Self {
        Self {
            links,
            opener,
            shape: PipeShape::default(),
        }
    }
}

impl<S, O: FifoOpen, N: CountKind> UnixpipeLinks<S, O, N> {
    /// The same links, for sessions that count the handles on a link as `M` does, over `links`,
    /// the stack's links counted so: asked before a session is opened over them, which is when it
    /// lends them its cells.
    pub fn counted_by<M: CountKind, T>(self, links: T) -> UnixpipeLinks<T, O, M> {
        debug_assert!(
            self.shape.cells.is_none() && self.shape.lent.is_none(),
            "cells and buffers are lent after the links are made"
        );
        UnixpipeLinks {
            links,
            opener: self.opener,
            shape: PipeShape {
                lent: None,
                cells: None,
                owner_waits: self.shape.owner_waits,
                tx_slots: self.shape.tx_slots,
                tx_capacity: self.shape.tx_capacity,
            },
        }
    }

    /// Unixpipe links whose owner waits for their input, as the stack's links that are told so.
    #[must_use]
    pub fn waited_by_owner(mut self) -> Self {
        self.shape.owner_waits = true;
        self
    }

    /// Unixpipe links that lend the session `slots` buffers of `bytes` each to encode its frames
    /// into.
    #[must_use]
    pub fn with_tx_buffers(mut self, slots: usize, bytes: usize) -> Self {
        self.shape.tx_slots = slots;
        self.shape.tx_capacity = bytes;
        self
    }
}

impl<S, O, N: CountKind> SessionLinks<N> for UnixpipeLinks<S, O, N>
where
    S: SessionLinks<N, Pump = HeapLink<N>>,
    O: FifoOpen + Clone + 'static,
    O::Fifo: 'static,
{
    type Pump = HeapLink<N>;

    type Dial = UnixpipeLinksDial<S::Dial, O, N>;

    const IPV6: bool = S::IPV6;

    // A name is resolved by the network the stack's IP links are opened on.
    const RESOLVES: bool = S::RESOLVES;

    fn resolve(&self, host: &str, port: u16, found: &mut [core::net::SocketAddr]) -> usize {
        self.links.resolve(host, port, found)
    }

    type Waits = S::Waits;

    fn waits(&self) -> S::Waits {
        self.links.waits()
    }

    fn open_acceptor(&self, port: u16) -> Result<OpenedLink<HeapLink<N>, N>, LinkOpenError> {
        self.links.open_acceptor(port)
    }

    // A unixpipe link is made by its handshake, which waits for the listener: a caller that opens
    // and does not ask again is held until the listener confirms, as a waiting open is.
    fn open_initiator(&self, to: Locator) -> Result<OpenedLink<HeapLink<N>, N>, LinkOpenError> {
        match to.as_unixpipe() {
            Some(at) => UnixpipeDial::begin(self.opener.clone(), self.shape, at)?.wait(),
            None => self.links.open_initiator(to),
        }
    }

    fn lend_buffers(&mut self, tables: LinkTables<N::Flag>) {
        self.shape.lent = Some(tables);
        self.links.lend_buffers(tables);
    }

    // A stack that places its links on the heap has the unixpipe links placed there too.
    fn link_cell_bytes(&self) -> usize {
        match self.links.link_cell_bytes() {
            0 => 0,
            links => links.max(CellRc::<PipeDriver<O::Fifo, N::Flag>>::cell_bytes()),
        }
    }

    fn lend_cells(&mut self, cells: LentByteCells<N::Flag>) {
        self.shape.cells = Some(cells);
        self.links.lend_cells(cells);
    }

    #[cfg(feature = "udp-listen")]
    fn lend_port_rows(
        &mut self,
        rows: crate::udp_link::PortRows<wz_session_core::bounded::Lent, N::Flag>,
    ) -> Result<(), usize> {
        self.links.lend_port_rows(rows)
    }

    fn begin_initiator(&self, to: Locator) -> Result<Self::Dial, LinkOpenError> {
        match to.as_unixpipe() {
            Some(at) => UnixpipeDial::begin(self.opener.clone(), self.shape, at)
                .map(UnixpipeLinksDial::Unixpipe),
            None => self.links.begin_initiator(to).map(UnixpipeLinksDial::Links),
        }
    }

    fn open_listener(
        &self,
        at: Locator,
    ) -> Result<Box<dyn LinkListener<HeapLink<N>, N>>, LinkOpenError> {
        let Some(at) = at.as_unixpipe() else {
            return self.links.open_listener(at);
        };
        let mode = at.file_mask.unwrap_or(UNIXPIPE_DEFAULT_FILE_MASK);
        let request = self.opener.listen(&request_path(at.path.as_str()), mode)?;
        Ok(Box::new(UnixpipeListener {
            opener: self.opener.clone(),
            at,
            shape: self.shape,
            request,
            invitation: RefCell::new(Reading::default()),
            answering: RefCell::new(None),
        }))
    }

    fn open_group(
        &self,
        endpoint: &str,
        group: &GroupLocator,
    ) -> Result<Box<dyn GroupTransport>, LinkOpenError> {
        self.links.open_group(endpoint, group)
    }

    fn share_pump(pump: HeapLink<N>) -> Option<CellRc<dyn SessionDatagramLink, N>> {
        S::share_pump(pump)
    }
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use alloc::collections::{BTreeMap, BTreeSet, VecDeque};
    use alloc::rc::Rc;
    use alloc::vec::Vec;
    use core::cell::Cell;
    use core::net::{Ipv4Addr, SocketAddr};

    use wz_session_core::link::{LinkEndsText, LinkSendOutcome};
    use wz_session_core::reliability::Reliability;

    use crate::session_drive::{Dialled, NoWaits, UnixpipePath};

    /// The bytes written into a FIFO and not read yet.
    type Queue = Rc<RefCell<VecDeque<u8>>>;

    /// The host's FIFOs, as the test keeps them: each node's bytes, the mode each read end asked
    /// its node made with, the nodes a read end holds the lock of, the suffixes the dials draw,
    /// and the clock.
    #[derive(Default)]
    struct Host {
        nodes: RefCell<BTreeMap<String, Queue>>,
        modes: RefCell<BTreeMap<String, u32>>,
        locked: RefCell<BTreeSet<String>>,
        suffixes: RefCell<VecDeque<u32>>,
        now_us: Cell<u64>,
    }

    #[derive(Clone, Default)]
    struct TestOpen(Rc<Host>);

    /// A FIFO end of the test; a read end holds its node's lock and removes the node when let go.
    struct TestFifo {
        queue: Queue,
        reads: Option<(String, Rc<Host>)>,
    }

    impl Drop for TestFifo {
        fn drop(&mut self) {
            if let Some((path, host)) = self.reads.take() {
                host.locked.borrow_mut().remove(&path);
                host.nodes.borrow_mut().remove(&path);
            }
        }
    }

    impl Fifo for TestFifo {
        type Error = ();

        fn write(&self, bytes: &[u8]) -> Result<usize, ()> {
            self.queue.borrow_mut().extend(bytes.iter().copied());
            Ok(bytes.len())
        }

        fn try_read(&self, buf: &mut [u8]) -> Result<Option<usize>, ()> {
            let mut queue = self.queue.borrow_mut();
            if queue.is_empty() {
                return Ok(None);
            }
            let read = buf.len().min(queue.len());
            for (slot, byte) in buf.iter_mut().zip(queue.drain(..read)) {
                *slot = byte;
            }
            Ok(Some(read))
        }

        fn wait_readable(&self, _timeout_ms: c_int) {}
    }

    impl FifoOpen for TestOpen {
        type Fifo = TestFifo;

        fn reader(&self, path: &str, mode: u32) -> Result<TestFifo, LinkOpenError> {
            if !self.0.locked.borrow_mut().insert(String::from(path)) {
                return Err(LinkOpenError::AddressInUse);
            }
            self.0.modes.borrow_mut().insert(String::from(path), mode);
            let queue = Rc::clone(
                self.0
                    .nodes
                    .borrow_mut()
                    .entry(String::from(path))
                    .or_default(),
            );
            Ok(TestFifo {
                queue,
                reads: Some((String::from(path), Rc::clone(&self.0))),
            })
        }

        fn listen(&self, path: &str, mode: u32) -> Result<TestFifo, LinkOpenError> {
            self.reader(path, mode)
        }

        fn request(&self, path: &str) -> Result<TestFifo, LinkOpenError> {
            if !self.0.locked.borrow().contains(path) {
                return Err(LinkOpenError::Refused);
            }
            self.writer(path)
        }

        fn writer(&self, path: &str) -> Result<TestFifo, LinkOpenError> {
            let queue = Rc::clone(
                self.0
                    .nodes
                    .borrow()
                    .get(path)
                    .ok_or(LinkOpenError::Refused)?,
            );
            Ok(TestFifo { queue, reads: None })
        }

        fn suffix(&self) -> u32 {
            self.0.suffixes.borrow_mut().pop_front().unwrap_or(7)
        }

        fn now_us(&self) -> u64 {
            self.0.now_us.get()
        }
    }

    impl TestOpen {
        /// The bytes queued on `path`, taken.
        fn take(&self, path: &str) -> Vec<u8> {
            self.0
                .nodes
                .borrow()
                .get(path)
                .map(|queue| queue.borrow_mut().drain(..).collect())
                .unwrap_or_default()
        }

        /// Queue `bytes` on `path`, as a peer's write.
        fn put(&self, path: &str, bytes: &[u8]) {
            if let Some(queue) = self.0.nodes.borrow().get(path) {
                queue.borrow_mut().extend(bytes.iter().copied());
            }
        }
    }

    /// A stack with no link of its own, which counts the dials it was asked for.
    #[derive(Default)]
    struct NoLinks {
        dials: Cell<usize>,
    }

    impl SessionLinks for NoLinks {
        type Pump = HeapLink;
        type Dial = Dialled<HeapLink>;
        type Waits = NoWaits;

        fn waits(&self) -> NoWaits {
            NoWaits
        }

        fn open_acceptor(&self, _port: u16) -> Result<OpenedLink<HeapLink>, LinkOpenError> {
            Err(LinkOpenError::Unsupported)
        }

        fn open_initiator(&self, _to: Locator) -> Result<OpenedLink<HeapLink>, LinkOpenError> {
            self.dials.set(self.dials.get() + 1);
            Err(LinkOpenError::Unsupported)
        }
    }

    fn pipe(path: &str) -> Locator {
        Locator::Unixpipe(UnixpipeLocator {
            path: UnixpipePath::new(path).expect("a path a row holds"),
            file_mask: None,
        })
    }

    fn links(open: &TestOpen) -> UnixpipeLinks<NoLinks, TestOpen> {
        UnixpipeLinks::new(NoLinks::default(), open.clone())
    }

    /// The text a link reports as the end it writes to.
    fn dst(link: &OpenedLink<HeapLink>) -> Option<String> {
        link.sink
            .link_endpoints()
            .map(|ends| String::from(ends.dst.as_str()))
    }

    /// A dial and a listener on one path make a link over the dial's pair: the dial invites on
    /// the request FIFO, the listener confirms on the downlink, the dial on the uplink, and each
    /// end then writes the FIFO the other reads. Turned red by a handshake that writes either
    /// confirmation to the wrong FIFO, or ends named the wrong way round.
    #[test]
    fn a_dial_and_a_listener_make_a_link_over_the_dials_pair() {
        let open = TestOpen::default();
        let links = links(&open);
        let listener = links.open_listener(pipe("/tmp/p")).expect("a listener");
        assert_eq!(listener.local(), pipe("/tmp/p"));
        let mut dial = links.begin_initiator(pipe("/tmp/p")).expect("a dial");
        assert!(dial.poll().is_none(), "the listener has not confirmed");
        let accepted = listener.accept().expect("a sound listener");
        assert!(accepted.is_none(), "the dial has not confirmed");
        let dialled = match dial.poll() {
            Some(Ok(link)) => link,
            _ => panic!("the listener's confirmation makes the dial's link"),
        };
        let accepted = listener
            .accept()
            .expect("a sound listener")
            .expect("the dial's confirmation makes the listener's link");
        assert_eq!(dst(&dialled).as_deref(), Some("unixpipe//tmp/p_uplink7"));
        assert_eq!(dst(&accepted).as_deref(), Some("unixpipe//tmp/p_downlink7"));
        assert_eq!(
            dialled.sink.send_blocking(b"abc", Reliability::Reliable),
            LinkSendOutcome::Sent
        );
        let mut got = Vec::new();
        assert!(accepted
            .pump
            .recv_with(&mut |batch| got.extend_from_slice(batch)));
        assert_eq!(got, b"abc");
    }

    /// A path no listener holds is refused, and so is a second listener on a held one. Turned red
    /// by a dial that opens a request FIFO nobody reads, or a listener that shares a path.
    #[test]
    fn no_listener_refuses_a_dial_and_one_listener_holds_a_path() {
        let open = TestOpen::default();
        let links = links(&open);
        assert!(matches!(
            links.begin_initiator(pipe("/tmp/p")),
            Err(LinkOpenError::Refused)
        ));
        let _first = links.open_listener(pipe("/tmp/p")).expect("a listener");
        assert!(matches!(
            links.open_listener(pipe("/tmp/p")),
            Err(LinkOpenError::AddressInUse)
        ));
    }

    /// A listener that confirms a pair other than the dial's refuses the dial. Turned red by a dial
    /// that takes any confirmation.
    #[test]
    fn a_dial_confirmed_for_another_pair_is_refused() {
        let open = TestOpen::default();
        let _listening = open
            .reader("/tmp/p_uplink", 0o600)
            .expect("the request FIFO");
        let mut dial = links(&open)
            .begin_initiator(pipe("/tmp/p"))
            .expect("a dial");
        assert!(dial.poll().is_none());
        assert_eq!(open.take("/tmp/p_uplink"), invitation(7));
        open.put("/tmp/p_downlink7", &invitation(8));
        assert!(matches!(dial.poll(), Some(Err(LinkOpenError::Refused))));
    }

    /// Eight bytes on the request FIFO that are no invitation are passed over and the next
    /// invitation answered; one its dialer does not confirm within the bound is dropped and its
    /// uplink let go. Turned red by a listener that stops at a bad invitation, or waits for a
    /// confirmation without end.
    #[test]
    fn a_listener_passes_over_junk_and_drops_an_unconfirmed_invitation() {
        let open = TestOpen::default();
        let listener = links(&open)
            .open_listener(pipe("/tmp/p"))
            .expect("a listener");
        let _downlink = open
            .reader("/tmp/p_downlink9", 0o600)
            .expect("the dialer's read end");
        open.put("/tmp/p_uplink", b"junkjunk");
        open.put("/tmp/p_uplink", &invitation(9));
        assert!(listener.accept().expect("a sound listener").is_none());
        assert_eq!(open.take("/tmp/p_downlink9"), invitation(9), "confirmed");
        assert!(open.0.locked.borrow().contains("/tmp/p_uplink9"));
        open.0.now_us.set(HANDSHAKE_TIMEOUT_US);
        assert!(listener.accept().expect("a sound listener").is_none());
        assert!(
            !open.0.locked.borrow().contains("/tmp/p_uplink9"),
            "the unconfirmed pair is let go"
        );
    }

    /// Every FIFO of a link, the listener's request FIFO and both of a dial's pair, is made owner
    /// only when the locator states no mode, and with the mode a locator states. Turned red by a
    /// default wider than the owner's (upstream's `0o777`), or by a mode the listener or the dial
    /// does not hand down.
    #[test]
    fn a_link_makes_its_fifos_owner_only_unless_its_locator_states_a_mode() {
        for (file_mask, mode) in [(None, 0o600), (Some(0o666), 0o666)] {
            let open = TestOpen::default();
            let links = links(&open);
            let at = Locator::Unixpipe(UnixpipeLocator {
                path: UnixpipePath::new("/tmp/p").expect("a path a row holds"),
                file_mask,
            });
            let listener = links.open_listener(at).expect("a listener");
            let mut dial = links.begin_initiator(at).expect("a dial");
            assert!(dial.poll().is_none(), "the listener has not confirmed");
            assert!(listener.accept().expect("a sound listener").is_none());
            for node in ["/tmp/p_uplink", "/tmp/p_downlink7", "/tmp/p_uplink7"] {
                assert_eq!(open.0.modes.borrow().get(node), Some(&mode), "{node}");
            }
        }
    }

    /// A locator of another kind is the stack's to dial and listen on. Turned red by a combinator
    /// that takes every locator.
    #[test]
    fn a_locator_of_another_kind_is_the_stacks() {
        let open = TestOpen::default();
        let links = links(&open);
        let udp = Locator::udp(SocketAddr::from((Ipv4Addr::LOCALHOST, 7447)));
        assert!(links.begin_initiator(udp).is_err());
        assert_eq!(links.links.dials.get(), 1);
        assert!(links.open_listener(udp).is_err());
    }
}
