// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The session's link over a serial line, its handshake, and the stack that opens it beside the
//! links of another.
//!
//! [`SerialDriver`] is the session's outbound [`BoxedLinkDriver`] and the drive loop's
//! [`SessionDatagramLink`] over one line: each batch is one frame of zenoh's serial framing
//! (`wz_session_core::serial_link`), read out of the bytes the line delivers and written whole
//! before the next. A line has its own handshake before the session's: a dial writes `INIT` and
//! waits for `INIT|ACK` ([`SerialDial`]), and a listener answers the `INIT` it reads. Both run in
//! the driver of the link they make, over the buffers that link reads and writes with, so a link
//! is handed to its session the moment the handshake ends and nothing read before is lost.
//!
//! [`SerialLinks`] puts these beside the links of any stack of the heap profile: a `serial/`
//! locator is dialled and listened on here, every other is the stack's, so a build without
//! serial links carries none of this.
//!
//! The locator's keys are read as upstream reads them. `tout` is how long a dial waits after the
//! peer's `RESET` before it writes `INIT` again
//! (`io/zenoh-links/zenoh-link-serial/src/unicast.rs` @ `port.connect(Some(Duration::from_micros(tout))).await?;`).
//! `release_on_close` is what a listener does with its line once the link over it ends: let it
//! go and open it again for the next peer, or keep it open for the next peer
//! (`io/zenoh-links/zenoh-link-serial/src/unicast.rs` @ `if release_on_close {`); a dialled link
//! lets its line go with it either way, as upstream's dialled link does when it is dropped.

use alloc::boxed::Box;
use core::cell::{Cell, RefCell};
use core::ffi::c_int;
use core::mem::ManuallyDrop;
use core::ops::Deref;

use wz_session_core::byte_cells::LentByteCells;
use wz_session_core::group_locator::GroupLocator;
use wz_session_core::link::{
    BoxedLinkDriver, LinkDropCause, LinkEnds, LinkKind, LinkRoom, LinkSendOutcome, LinkSubject,
    LostCause, RoomAnswer, RoomWait, RxFrame, TxSlot, TxSlotGrant,
};
use wz_session_core::qos::Priority;
use wz_session_core::reliability::Reliability;
use wz_session_core::serial_link::{
    encode_frame_stuffing, next_frame_in, pending_init_header, DestuffBuffer, HandshakeStep,
    SerialHandshake, StuffBuffer, SERIAL_EOP, SERIAL_FLAG_ACK, SERIAL_FLAG_INIT,
    SERIAL_MAX_COBS_BUF, SERIAL_MTU,
};

use super::{SerialDevice, SerialOpen};
use crate::group_transport::GroupTransport;
use crate::ip_stack::HeapLink;
use crate::link_cells::{CellRc, CountKind, OneTask};
use crate::link_storage::{
    heap_link_buffers, LinkTables, RxBuffer, RxStore, TxBuffer, TxLender, TxStore,
};
use crate::session_drive::{
    LinkListener, LinkOpenError, Locator, OpenedLink, PendingDial, SerialLine, SerialLocator,
    SessionDatagramLink, SessionLinks, WaitOn,
};
use crate::udp_link::SERVICE_WAIT_MS;

/// The header of a frame that carries a batch: no flag set. The receiver reads no header on the
/// data path, as zenoh-pico's does not.
const DATA_HEADER: u8 = 0;

/// How long a service turn waits for room to write, in microseconds.
const SERVICE_WAIT_US: u64 = SERVICE_WAIT_MS as u64 * 1_000;

/// The longest a dial that waits for its handshake waits, in microseconds: the connect timeout of
/// a zenoh-pico session, which a waiting open of a program's transport is held to as well
/// (`OPEN_WAIT_MS` in `crate::app_link`).
const OPEN_WAIT_US: u64 = 10_000_000;

/// The largest batch whose frame a buffer of `capacity` bytes holds whole: the frame adds a
/// header, a length and a CRC (seven bytes), COBS one code byte and one more for every 254 bytes
/// it stuffs, and the EOP; never more than the serial MTU.
const fn payload_bound(capacity: usize) -> usize {
    let bound = capacity.saturating_sub((capacity / 254).saturating_add(9));
    if bound < SERIAL_MTU {
        bound
    } else {
        SERIAL_MTU
    }
}

/// The session's link over one serial line `D`, its receive buffer in `B` and its outbound frames
/// built in `T`: the heap profile's buffers, claimed from the session's tables when it lent some.
///
/// The receive buffer gathers what the line delivers until a frame's end marker is in it; the
/// frame is then destuffed and checked into a buffer of the link's own and its batch handed to
/// the session from there. A frame the line damaged is dropped and the reading goes on, as
/// zenoh-pico drops a frame whose CRC fails. Each frame the session hands over is stuffed into the
/// link's wire buffer and written from it; what the line does not take at once is owed and
/// written by the next step, and the wire buffer takes no other frame until it is.
pub struct SerialDriver<
    D: SerialDevice,
    B: RxStore = RxBuffer,
    T: TxStore = TxBuffer,
    M: CountKind = OneTask,
> {
    line: LineLease<D, M>,
    at: SerialLocator,
    rx: RefCell<B>,
    /// The largest batch the receive buffer holds the frame of.
    rx_bound: usize,
    /// How many bytes at the front of the receive buffer were read and are not yet a frame.
    filled: Cell<usize>,
    /// Whether a whole frame lies in those bytes, which the next receive reads without the line.
    ready: Cell<bool>,
    destuffed: RefCell<DestuffBuffer>,
    stuffed: RefCell<StuffBuffer>,
    wire: RefCell<[u8; SERIAL_MAX_COBS_BUF]>,
    /// The bytes of the wire buffer still to write: from, end.
    owed: Cell<(usize, usize)>,
    tx: TxLender<T>,
    lost: Cell<Option<LostCause>>,
    /// The last failure the line reported, kept for the deploy to report.
    error: Cell<Option<D::Error>>,
    /// The frames the copying receive let go of for want of heap room, until the loop takes them.
    rx_drops: crate::link_storage::RxDrops,
    owner_waits: bool,
    /// When a dial writes its `INIT` again, after the peer's `RESET`.
    resend_at_us: Cell<Option<u64>>,
}

impl<D: SerialDevice, B: RxStore, T: TxStore, M: CountKind> SerialDriver<D, B, T, M> {
    /// The link over `line`, which `at` named, receiving into `rx` and building its frames in
    /// `tx`. Its handshake is its maker's to run: a link handed to a session has made it.
    pub fn over(line: LineLease<D, M>, at: SerialLocator, mut rx: B, tx: T) -> Self {
        let rx_bound = payload_bound(rx.capacity());
        Self {
            line,
            at,
            rx: RefCell::new(rx),
            rx_bound,
            filled: Cell::new(0),
            ready: Cell::new(false),
            destuffed: RefCell::new(DestuffBuffer::new()),
            stuffed: RefCell::new(StuffBuffer::new()),
            wire: RefCell::new([0; SERIAL_MAX_COBS_BUF]),
            owed: Cell::new((0, 0)),
            tx: TxLender::new(tx),
            lost: Cell::new(None),
            error: Cell::new(None),
            rx_drops: crate::link_storage::RxDrops::new(),
            owner_waits: false,
            resend_at_us: Cell::new(None),
        }
    }

    /// The link, waited on by its owner when its line can be ([`SessionDatagramLink::input_wait`]),
    /// set where the link lies.
    pub fn wait_by_owner(&mut self) {
        self.owner_waits = self.line.input_wait().is_some();
    }

    /// The most recent failure the line reported, if it has failed.
    pub fn error(&self) -> Option<D::Error> {
        self.error.get()
    }

    /// The link is gone, for `cause`; the first cause is the one kept.
    fn end(&self, cause: LostCause) {
        if self.lost.get().is_none() {
            self.lost.set(Some(cause));
        }
    }

    /// The line failed with `error`: the link ends, and nothing it owed is written.
    fn fail(&self, error: D::Error) {
        self.error.set(Some(error));
        self.end(LostCause::OsError);
        self.owed.set((0, 0));
    }

    fn owes(&self) -> bool {
        let (from, end) = self.owed.get();
        from < end
    }

    /// Write what the link owes the line, without waiting: `true` once nothing is owed (or the
    /// link has ended), `false` when the line took less than all of it.
    fn write_owed(&self) -> bool {
        loop {
            let (from, end) = self.owed.get();
            if from >= end {
                return true;
            }
            if self.lost.get().is_some() {
                self.owed.set((0, 0));
                return true;
            }
            let wrote = {
                let wire = self.wire.borrow();
                self.line.write(wire.get(from..end).unwrap_or_default())
            };
            match wrote {
                Ok(0) => return false,
                Ok(taken) => self.owed.set((from.saturating_add(taken).min(end), end)),
                Err(error) => {
                    self.fail(error);
                    return true;
                }
            }
        }
    }

    /// Frame `payload` behind `header` and write it, as far as the line takes it now. A link
    /// still owing the frame before has no wire buffer for it, and refuses it as having no slot.
    fn send_frame(&self, header: u8, payload: &[u8]) -> LinkSendOutcome {
        if !self.write_owed() {
            return LinkSendOutcome::Dropped(LinkDropCause::NoTxSlot);
        }
        if self.lost.get().is_some() {
            return LinkSendOutcome::Dropped(LinkDropCause::WriterGone);
        }
        let encoded = {
            let mut wire = self.wire.borrow_mut();
            encode_frame_stuffing(
                header,
                payload,
                &mut wire[..],
                &mut self.stuffed.borrow_mut(),
            )
        };
        let Ok(len) = encoded else {
            return LinkSendOutcome::Dropped(LinkDropCause::Oversize);
        };
        self.owed.set((0, len));
        self.write_owed();
        if self.lost.get().is_some() {
            LinkSendOutcome::Dropped(LinkDropCause::WriterGone)
        } else {
            LinkSendOutcome::Sent
        }
    }

    /// Hand the next whole frame's header and payload to `f`, reading the line until there is one
    /// or nothing more is queued; `false` when there is none. The payload is lent from the link's
    /// destuffing buffer for the call.
    fn next_frame(&self, f: &mut dyn FnMut(u8, &[u8])) -> bool {
        if self.lost.get().is_some() {
            return false;
        }
        let mut rx = self.rx.borrow_mut();
        // A link of a pool that holds no buffer and finds none free reads nothing: what its peer
        // sent waits on the line.
        let Some(bytes) = rx.bytes() else {
            return false;
        };
        let mut filled = self.filled.get().min(bytes.len());
        let mut destuffed = self.destuffed.borrow_mut();
        let handed = loop {
            match next_frame_in(bytes, &mut filled, &mut destuffed) {
                Some(Ok((header, payload))) => {
                    f(header, payload);
                    break true;
                }
                Some(Err(_)) => continue,
                None => {}
            }
            let room = bytes.get_mut(filled..).unwrap_or_default();
            if room.is_empty() {
                break false;
            }
            match self.line.try_read(room) {
                Ok(Some(0)) => {
                    self.end(LostCause::PeerClosed);
                    break false;
                }
                Ok(Some(n)) => filled = filled.saturating_add(n),
                Ok(None) => break false,
                Err(error) => {
                    self.error.set(Some(error));
                    self.end(LostCause::OsError);
                    break false;
                }
            }
        };
        self.ready.set(
            bytes
                .get(..filled)
                .unwrap_or_default()
                .contains(&SERIAL_EOP),
        );
        self.filled.set(filled);
        // Nothing of the link's own is left in a pooled buffer: it goes back for any link to read
        // into.
        if B::POOLED && filled == 0 {
            rx.idle();
        }
        handed
    }

    /// Hand the next batch to `f`: a frame's payload, its header unread; a frame with none is
    /// passed over.
    fn receive(&self, f: &mut dyn FnMut(&[u8])) -> bool {
        loop {
            let mut empty = false;
            let handed = self.next_frame(&mut |_header, payload| {
                if payload.is_empty() {
                    empty = true;
                } else {
                    f(payload);
                }
            });
            if !handed || !empty {
                return handed;
            }
        }
    }

    /// One step of a dial's handshake at `now_us` on the opener's clock: the peer's `INIT|ACK`
    /// makes the link, its `RESET` has the `INIT` written again once the locator's `tout` has
    /// passed, and any other answer, or a line that ends, refuses the dial; `None` while it waits.
    fn dial_step(&self, now_us: u64) -> Option<Result<(), LinkOpenError>> {
        self.write_owed();
        if let Some(at) = self.resend_at_us.get() {
            if now_us < at {
                return None;
            }
            self.resend_at_us.set(None);
            // A line that failed the write ends the dial; one still writing the last INIT has it
            // answered as the next.
            let resent = self.send_frame(SERIAL_FLAG_INIT, &[]);
            if resent == LinkSendOutcome::Dropped(LinkDropCause::WriterGone) {
                return Some(Err(LinkOpenError::Refused));
            }
        }
        let initiator = SerialHandshake::initiator();
        let mut answer = None;
        if !self.next_frame(&mut |header, _payload| answer = Some(initiator.on_header(header))) {
            return self.lost.get().map(|_| Err(LinkOpenError::Refused));
        }
        match answer? {
            HandshakeStep::Connected => Some(Ok(())),
            HandshakeStep::Throttle => {
                let tout_us = self.at.options.timeout_us;
                self.resend_at_us.set(Some(now_us.saturating_add(tout_us)));
                None
            }
            HandshakeStep::Failed | HandshakeStep::EmitAndConnect(_) => {
                Some(Err(LinkOpenError::Refused))
            }
        }
    }

    /// One step of a listener's handshake: read what the line holds and answer the last `INIT` an
    /// end marker closed with `INIT|ACK`, `true` once answered. Every other frame, and the
    /// bytes before them, are stale: a peer that dials writes nothing but its `INIT` until it is
    /// answered. The `INIT` is searched for behind stale bytes the line left in front of it
    /// (`pending_init_header`), because the peer writes it once. A line that fails or hangs up
    /// is [`LinkOpenError::Refused`].
    fn accept_step(&self) -> Result<bool, LinkOpenError> {
        let init = {
            let mut rx = self.rx.borrow_mut();
            let Some(bytes) = rx.bytes() else {
                return Ok(false);
            };
            let mut filled = self.filled.get().min(bytes.len());
            loop {
                let room = bytes.get_mut(filled..).unwrap_or_default();
                if room.is_empty() {
                    break;
                }
                match self.line.try_read(room) {
                    Ok(Some(0)) => return Err(LinkOpenError::Refused),
                    Ok(Some(n)) => filled = filled.saturating_add(n),
                    Ok(None) => break,
                    Err(error) => {
                        self.error.set(Some(error));
                        return Err(LinkOpenError::Refused);
                    }
                }
            }
            let held = bytes.get(..filled).unwrap_or_default();
            let init = pending_init_header(held);
            // What an end marker closed has been searched; the tail after the last one may be the
            // start of a frame, unless it fills the buffer and so can be none.
            let spent = match held.iter().rposition(|&byte| byte == SERIAL_EOP) {
                _ if init.is_some() => filled,
                Some(eop) => eop.saturating_add(1),
                None if filled == bytes.len() => filled,
                None => 0,
            };
            bytes.copy_within(spent..filled, 0);
            self.filled.set(filled.saturating_sub(spent));
            init
        };
        if init.is_none() {
            return Ok(false);
        }
        match self.send_frame(SERIAL_FLAG_INIT | SERIAL_FLAG_ACK, &[]) {
            LinkSendOutcome::Sent => Ok(true),
            _ => Err(LinkOpenError::Refused),
        }
    }
}

impl<D: SerialDevice + 'static, B: RxStore + 'static, T: TxStore + 'static, M: CountKind>
    BoxedLinkDriver for SerialDriver<D, B, T, M>
{
    fn send_blocking(&self, bytes: &[u8], _reliability: Reliability) -> LinkSendOutcome {
        self.send_frame(DATA_HEADER, bytes)
    }

    // A link that owes the line nothing has room: the frame is tried, and what the line does not
    // take is owed, which makes the next frame wait here for the line to take it.
    fn wait_for_room(&self, _priority: Priority, wait: RoomWait) -> RoomAnswer {
        if self.write_owed() {
            return if self.tx.claimable() {
                RoomAnswer::at_once(LinkRoom::Free)
            } else {
                RoomAnswer::at_once(LinkRoom::Congested)
            };
        }
        let (room, waited_us) = self.line.wait_writable(wait.wait_us());
        let room = if room && self.write_owed() {
            LinkRoom::Free
        } else {
            LinkRoom::Congested
        };
        RoomAnswer { room, waited_us }
    }

    // A slot is lent only while the wire buffer is free for the frame the session encodes into it.
    fn tx_slot_acquire(&self, _want: usize, _priority: Priority) -> Option<TxSlotGrant> {
        if !self.write_owed() {
            return None;
        }
        self.tx.acquire(0)
    }

    fn tx_slot_storage(&self, slot: TxSlot) -> (*mut u8, usize) {
        self.tx.storage(slot)
    }

    // The batch is stuffed out of its slot into the wire buffer at once, so the slot goes back
    // here.
    fn tx_slot_send(
        &self,
        slot: TxSlot,
        start: usize,
        len: usize,
        _reliability: Reliability,
        _priority: Priority,
    ) -> LinkSendOutcome {
        match self.tx.take(slot, start, len) {
            Some(batch) => self.send_frame(DATA_HEADER, batch),
            None => LinkSendOutcome::Dropped(LinkDropCause::Oversize),
        }
    }

    fn tx_slot_abort(&self, slot: TxSlot) {
        self.tx.release(slot);
    }

    #[cfg(feature = "session-unicast-accept")]
    fn tx_slot_spare(&self) -> bool {
        self.tx.spare()
    }

    #[cfg(feature = "session-unicast-accept")]
    fn tx_slot_claimable(&self) -> bool {
        self.tx.claimable()
    }

    fn open_blocking(&self) {}

    // The session's Close frame has been handed over; what is owed of it is tried once more. The
    // line itself goes with the link, or stays with the listener that keeps it.
    fn close_blocking(&self) {
        self.write_owed();
        self.end(LostCause::PeerClosed);
        self.owed.set((0, 0));
    }

    // A device's path names both ends, as upstream names a dialled serial link's; a pin pair has
    // no name a locator row holds.
    fn link_ends(&self) -> Option<LinkEnds<'_>> {
        match &self.at.line {
            SerialLine::Device(path) => Some(LinkEnds::named(
                LinkKind::Serial,
                path.as_str(),
                path.as_str(),
            )),
            SerialLine::Pins { .. } => None,
        }
    }

    fn link_subject(&self) -> Option<&LinkSubject> {
        static SERIAL: LinkSubject = LinkSubject {
            kind: Some(LinkKind::Serial),
            ..LinkSubject::UNKNOWN
        };
        Some(&SERIAL)
    }

    fn link_mtu(&self) -> usize {
        if self.tx.lends() {
            self.tx.slot_len().min(SERIAL_MTU)
        } else {
            SERIAL_MTU
        }
    }

    fn link_rx_capacity(&self) -> usize {
        self.rx_bound
    }
}

impl<D: SerialDevice + 'static, B: RxStore + 'static, T: TxStore + 'static, M: CountKind>
    SessionDatagramLink for SerialDriver<D, B, T, M>
{
    fn service(&self) {
        if self.owes() {
            self.write_owed();
        }
        if self.lost.get().is_none() && !self.ready.get() && !self.owner_waits {
            if !self.owes() {
                self.line.wait_readable(SERVICE_WAIT_MS);
            } else if self.line.wait_writable(SERVICE_WAIT_US).0 {
                self.write_owed();
            }
        }
    }

    fn try_recv(&self) -> Option<RxFrame> {
        crate::link_storage::copied_receive(self, &self.rx_drops)
    }

    fn take_rx_dropped(&self) -> usize {
        self.rx_drops.take()
    }

    fn recv_with(&self, f: &mut dyn FnMut(&[u8])) -> bool {
        self.receive(f)
    }

    // A batch is lent from the link's destuffing buffer, which a receive alone writes
    // (`Self::next_frame`, for a batch and for a dial's answer), never a service, which waits on
    // the line and writes what is owed: what a receive lent lies there until the link is next
    // asked to receive. A session whose round reads its records where they lie needs this; a link
    // that answered the provided `false` would have every sample with a payload refused there.
    fn lends_until_next_receive(&self) -> bool {
        true
    }

    fn lost(&self) -> Option<LostCause> {
        self.lost.get()
    }

    fn holds_input(&self) -> bool {
        self.ready.get()
    }

    #[cfg(feature = "session-unicast-accept")]
    fn waits_for_buffer(&self) -> bool {
        self.rx.try_borrow().is_ok_and(|rx| rx.starved())
    }

    fn owes_write(&self) -> bool {
        self.owes()
    }

    #[cfg(feature = "session-unicast-accept")]
    fn write_owed_now(&self) {
        if self.owes() {
            self.write_owed();
        }
    }

    fn input_wait(&self) -> Option<WaitOn> {
        if self.owner_waits {
            self.line.input_wait()
        } else {
            None
        }
    }

    fn room_wait(&self) -> Option<WaitOn> {
        self.line.room_wait()
    }
}

/// A serial link of a stack whose sessions count its handles as `N` does: its buffers are of
/// tables flagged as `N` flags the cells it is placed in.
type SerialDriverOf<D, N> = SerialDriver<
    D,
    RxBuffer<<N as CountKind>::Flag>,
    TxBuffer<<N as CountKind>::Flag>,
    <N as CountKind>::Shared,
>;

/// The handle a stack's sessions hold a serial link by: on the cell it is made in, counted as they
/// count their handles.
type SerialCellOf<D, N> = CellRc<SerialDriverOf<D, N>, N>;

/// What a listener keeps of its line between the links over it: the line, while the listener
/// keeps it open and no link holds it, and whether a link holds it now. The line has one owner at
/// a time: this home, or the one link over it ([`LineLease`]), which gives it back as it ends.
struct LineHome<D> {
    kept: Option<D>,
    out: bool,
    keep: bool,
}

impl<D> LineHome<D> {
    /// The home of a listener's line, holding none yet: `keep` when the listener keeps its line
    /// open between links, as a locator that does not release it on close asks.
    fn new(keep: bool) -> Self {
        Self {
            kept: None,
            out: false,
            keep,
        }
    }

    /// The line the listener kept, for a link to take, when no link holds the line now: `None`
    /// while one does, `Some(None)` when the line is to be opened.
    fn free(&mut self) -> Option<Option<D>> {
        if self.out {
            None
        } else {
            Some(self.kept.take())
        }
    }

    /// `line` back from the link that held it: kept for the next link when the listener keeps
    /// its line, and answered to be closed otherwise.
    fn back(&mut self, line: D) -> Option<D> {
        self.out = false;
        if self.keep {
            self.kept = Some(line);
            None
        } else {
            Some(line)
        }
    }
}

/// The handle a listener and the link over its line share the line's home by. The link is held
/// with its face and the listener with the session, which several threads may hold apart, so it
/// is counted as what links share ([`CountKind::Shared`]).
type HomeOf<D, M> = CellRc<<M as CountKind>::Local<LineHome<D>>, M>;

/// A serial line, owned by the one link over it for as long as the link lives: a line a listener
/// opened goes back to the listener's home as the link ends, which tells the listener the line is
/// free, and a dialled line is closed with its link. No handle on the line is shared, so the link
/// holding it is moved with its face whole.
pub struct LineLease<D, M: CountKind = OneTask> {
    line: ManuallyDrop<D>,
    home: Option<HomeOf<D, M>>,
}

impl<D, M: CountKind> LineLease<D, M> {
    /// `line`, owned by a dialled link alone and closed with it.
    pub fn owned(line: D) -> Self {
        Self {
            line: ManuallyDrop::new(line),
            home: None,
        }
    }

    /// `line`, taken from `home` (kept there, or opened for it) by the link made over it, and
    /// given back as that link ends.
    fn homed(line: D, home: HomeOf<D, M>) -> Self {
        M::with_local::<LineHome<D>, ()>(&home, |home| home.out = true);
        Self {
            line: ManuallyDrop::new(line),
            home: Some(home),
        }
    }
}

impl<D, M: CountKind> Deref for LineLease<D, M> {
    type Target = D;

    fn deref(&self) -> &D {
        &self.line
    }
}

impl<D, M: CountKind> Drop for LineLease<D, M> {
    fn drop(&mut self) {
        // SAFETY: `drop` runs once, and nothing reads the line after it is taken here.
        let line = unsafe { ManuallyDrop::take(&mut self.line) };
        if let Some(home) = self.home.take() {
            // A line the home does not keep is closed here, out of the home's hold.
            let closed = M::with_local::<LineHome<D>, Option<D>>(&home, |home| home.back(line));
            drop(closed);
        }
    }
}

/// What every serial link of a [`SerialLinks`] is given besides its line: the session's tables
/// and cells when it lent them, the slots its frames are encoded into, and whether its owner
/// waits.
struct SerialShape<N: CountKind> {
    lent: Option<LinkTables<N::Flag>>,
    cells: Option<LentByteCells<N::Flag>>,
    owner_waits: bool,
    tx_slots: usize,
    tx_capacity: usize,
}

// Not derived: a derive would ask `N: Clone` and `N: Default` of a kind of count.
impl<N: CountKind> Clone for SerialShape<N> {
    fn clone(&self) -> Self {
        *self
    }
}

impl<N: CountKind> Copy for SerialShape<N> {}

impl<N: CountKind> Default for SerialShape<N> {
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

impl<N: CountKind> SerialShape<N> {
    /// The link over `line`, which `at` named, made in a cell before its handshake: its receive
    /// buffer holds the largest frame, and its buffers and cell are claimed as every link's of the
    /// stack are, [`LinkOpenError::Exhausted`] when the session's have none left.
    fn link<D: SerialDevice + 'static>(
        &self,
        line: LineLease<D, N::Shared>,
        at: SerialLocator,
    ) -> Result<SerialCellOf<D, N>, LinkOpenError> {
        let (rx, tx) = heap_link_buffers(
            self.lent.as_ref(),
            SERIAL_MAX_COBS_BUF,
            self.tx_slots,
            self.tx_capacity,
        )?;
        let owner_waits = self.owner_waits;
        CellRc::<_, N>::claim_of(self.cells.as_ref())
            .ok_or(LinkOpenError::Exhausted)?
            .made(|place| {
                let link = place.write(SerialDriver::over(line, at, rx, tx));
                if owner_waits {
                    link.wait_by_owner();
                }
                link
            })
            .ok_or(LinkOpenError::Exhausted)
    }
}

/// A `serial/` dial under way ([`SessionLinks::begin_initiator`]): its line open, its `INIT`
/// written, and the peer's answer asked for at each poll, timed on the opener's clock.
pub struct SerialDial<O: SerialOpen, N: CountKind = OneTask> {
    link: Option<SerialCellOf<O::Device, N>>,
    opener: O,
}

impl<O: SerialOpen, N: CountKind> PendingDial<HeapLink<N>, N> for SerialDial<O, N>
where
    O::Device: 'static,
{
    fn poll(&mut self) -> Option<Result<OpenedLink<HeapLink<N>, N>, LinkOpenError>> {
        let answer = self.link.as_ref()?.dial_step(self.opener.now_us())?;
        let link = self.link.take()?;
        Some(answer.map(|()| OpenedLink::behind_tables(link)))
    }
}

impl<O: SerialOpen, N: CountKind> SerialDial<O, N>
where
    O::Device: 'static,
{
    /// The dial, waited out: asked again each time the line has something to read or the
    /// `INIT` is due again, until the peer answers or [`OPEN_WAIT_US`] has passed on the
    /// opener's clock, which refuses it as an open worth trying later.
    fn wait(mut self) -> Result<OpenedLink<HeapLink<N>, N>, LinkOpenError> {
        let deadline = self.opener.now_us().saturating_add(OPEN_WAIT_US);
        loop {
            if let Some(made) = self.poll() {
                return made;
            }
            let now = self.opener.now_us();
            let link = self.link.as_ref().ok_or(LinkOpenError::Refused)?;
            if now >= deadline {
                return Err(LinkOpenError::Refused);
            }
            let until = link.resend_at_us.get().unwrap_or(deadline).min(deadline);
            let wait_ms = until.saturating_sub(now).div_ceil(1_000);
            link.line
                .wait_readable(c_int::try_from(wait_ms).unwrap_or(c_int::MAX));
        }
    }
}

/// A dial of [`SerialLinks`]: the stack's, or a serial one.
pub enum SerialLinksDial<D, O: SerialOpen, N: CountKind = OneTask> {
    /// A dial of the stack the serial links stand beside.
    Links(D),
    /// A `serial/` dial.
    Serial(SerialDial<O, N>),
}

impl<D: PendingDial<HeapLink<N>, N>, O: SerialOpen, N: CountKind> PendingDial<HeapLink<N>, N>
    for SerialLinksDial<D, O, N>
where
    O::Device: 'static,
{
    fn poll(&mut self) -> Option<Result<OpenedLink<HeapLink<N>, N>, LinkOpenError>> {
        match self {
            Self::Links(dial) => dial.poll(),
            Self::Serial(dial) => dial.poll(),
        }
    }
}

/// A link made at once is the stack's: a serial link is made by its handshake.
impl<D: From<OpenedLink<HeapLink<N>, N>>, O: SerialOpen, N: CountKind>
    From<OpenedLink<HeapLink<N>, N>> for SerialLinksDial<D, O, N>
{
    fn from(opened: OpenedLink<HeapLink<N>, N>) -> Self {
        Self::Links(D::from(opened))
    }
}

/// The accepting end of a serial line: one link at a time, since a line is point-to-point. The
/// line is opened when the listener is made, as zenoh-pico's listen opens its device, so a peer's
/// `INIT` written once the listen returns is not cleared by a later open; the next accept waits
/// for the link over it to end, as upstream's waits while its link is connected
/// (`io/zenoh-links/zenoh-link-serial/src/unicast.rs` @ `while is_connected.load(Ordering::Acquire) {`).
/// A link made waits on the line for the peer's `INIT` (`waiting`) and is handed over once it
/// is answered.
struct SerialListener<O: SerialOpen, N: CountKind> {
    opener: O,
    at: SerialLocator,
    shape: SerialShape<N>,
    waiting: RefCell<Option<SerialCellOf<O::Device, N>>>,
    /// Where the line is kept between links when the locator does not release it on close, and
    /// whether a link holds it now ([`LineLease`]).
    home: HomeOf<O::Device, N::Shared>,
}

impl<O: SerialOpen, N: CountKind> SerialListener<O, N>
where
    O::Device: 'static,
{
    /// Take the line for the next link and wait on it for the peer's `INIT` (`waiting`): the
    /// line kept between links, or the line opened now. `false`, with nothing taken, while a link
    /// still holds the line. Only this listener lends the line, so a line found free stays free
    /// until the lease below takes it.
    fn wait_on_line(&self) -> Result<bool, LinkOpenError> {
        let free = <N::Shared as CountKind>::with_local::<LineHome<O::Device>, _>(
            &self.home,
            LineHome::free,
        );
        let Some(kept) = free else {
            return Ok(false);
        };
        let line = match kept {
            Some(line) => line,
            None => self.opener.open(&self.at)?,
        };
        let line = LineLease::homed(line, self.home.clone());
        let link = self.shape.link(line, self.at)?;
        *self.waiting.borrow_mut() = Some(link);
        Ok(true)
    }
}

impl<O: SerialOpen, N: CountKind> LinkListener<HeapLink<N>, N> for SerialListener<O, N>
where
    O::Device: 'static,
{
    fn local(&self) -> Locator {
        Locator::Serial(self.at)
    }

    fn accept(&self) -> Result<Option<OpenedLink<HeapLink<N>, N>>, LinkOpenError> {
        if self.waiting.borrow().is_none() && !self.wait_on_line()? {
            return Ok(None);
        }
        let step = match self.waiting.borrow().as_ref() {
            Some(link) => link.accept_step(),
            None => return Ok(None),
        };
        match step {
            Ok(false) => Ok(None),
            Ok(true) => Ok(self
                .waiting
                .borrow_mut()
                .take()
                .map(OpenedLink::behind_tables)),
            // A line that failed is let go, kept or not, and opened again by the next call.
            Err(_) => {
                self.waiting.borrow_mut().take();
                let failed = <N::Shared as CountKind>::with_local::<LineHome<O::Device>, _>(
                    &self.home,
                    |home| home.kept.take(),
                );
                drop(failed);
                Ok(None)
            }
        }
    }

    fn input_wait(&self) -> Option<WaitOn> {
        self.waiting
            .borrow()
            .as_ref()
            .and_then(|link| link.line.input_wait())
    }
}

/// The links of the stack `S` and serial links beside them, over the lines `O` opens: a
/// `serial/` locator is dialled and listened on here, any other is the stack's. Serial links take
/// their buffers and cells from what the session lends the stack, and are placed and waited on as
/// the stack's links of the heap profile are ([`HeapLink`]). `N` is how the sessions they serve
/// count the handles on a link, as `S`'s sessions do.
pub struct SerialLinks<S, O, N: CountKind = OneTask> {
    links: S,
    opener: O,
    shape: SerialShape<N>,
}

impl<S, O: SerialOpen> SerialLinks<S, O> {
    /// The links of `links`, and serial links over the lines `opener` opens.
    pub fn new(links: S, opener: O) -> Self {
        Self {
            links,
            opener,
            shape: SerialShape::default(),
        }
    }
}

impl<S, O: SerialOpen, N: CountKind> SerialLinks<S, O, N> {
    /// The same links, for sessions that count the handles on a link as `M` does, over `links`,
    /// the stack's links counted so: asked before a session is opened over them, which is when it
    /// lends them its cells.
    pub fn counted_by<M: CountKind, T>(self, links: T) -> SerialLinks<T, O, M> {
        debug_assert!(
            self.shape.cells.is_none() && self.shape.lent.is_none(),
            "cells and buffers are lent after the links are made"
        );
        SerialLinks {
            links,
            opener: self.opener,
            shape: SerialShape {
                lent: None,
                cells: None,
                owner_waits: self.shape.owner_waits,
                tx_slots: self.shape.tx_slots,
                tx_capacity: self.shape.tx_capacity,
            },
        }
    }

    /// Serial links whose owner waits for their input, as the stack's links that are told so.
    #[must_use]
    pub fn waited_by_owner(mut self) -> Self {
        self.shape.owner_waits = true;
        self
    }

    /// A dial of the line `at` names: the line opened and what it holds thrown away before the
    /// `INIT`, as upstream clears its port before it connects; the link is made then, so the
    /// peer's answer is read into its buffer.
    fn dial_serial(&self, at: SerialLocator) -> Result<SerialDial<O, N>, LinkOpenError>
    where
        O: Clone,
        O::Device: 'static,
    {
        let line = LineLease::owned(self.opener.open(&at)?);
        line.discard_queued().map_err(|_| LinkOpenError::Refused)?;
        let link = self.shape.link(line, at)?;
        if link.send_frame(SERIAL_FLAG_INIT, &[]) != LinkSendOutcome::Sent {
            return Err(LinkOpenError::Refused);
        }
        Ok(SerialDial {
            link: Some(link),
            opener: self.opener.clone(),
        })
    }

    /// Serial links that lend the session `slots` buffers of `bytes` each to encode its frames
    /// into; by default a slot holds the largest frame's batch.
    #[must_use]
    pub fn with_tx_buffers(mut self, slots: usize, bytes: usize) -> Self {
        self.shape.tx_slots = slots;
        self.shape.tx_capacity = bytes;
        self
    }
}

impl<S, O, N: CountKind> SessionLinks<N> for SerialLinks<S, O, N>
where
    S: SessionLinks<N, Pump = HeapLink<N>>,
    O: SerialOpen + Clone + 'static,
    O::Device: 'static,
{
    type Pump = HeapLink<N>;

    type Dial = SerialLinksDial<S::Dial, O, N>;

    const IPV6: bool = S::IPV6;

    // A name is resolved by the network the stack's IP links are opened on.
    const RESOLVES: bool = S::RESOLVES;

    fn resolve(
        &self,
        name: &crate::locator_text::NamedHost<'_>,
        found: &mut [core::net::SocketAddr],
    ) -> usize {
        self.links.resolve(name, found)
    }

    type Waits = S::Waits;

    fn waits(&self) -> S::Waits {
        self.links.waits()
    }

    fn open_acceptor(&self, port: u16) -> Result<OpenedLink<HeapLink<N>, N>, LinkOpenError> {
        self.links.open_acceptor(port)
    }

    // A serial link is made by its handshake, which waits for the peer: a caller that opens and
    // does not ask again (a node's dialer over an endpoint its config names) is held until the
    // peer answers, as a waiting open is (`SerialDial::wait`).
    fn open_initiator(&self, to: Locator) -> Result<OpenedLink<HeapLink<N>, N>, LinkOpenError> {
        match to.as_serial() {
            Some(at) => self.dial_serial(at)?.wait(),
            None => self.links.open_initiator(to),
        }
    }

    fn lend_buffers(&mut self, tables: LinkTables<N::Flag>) {
        self.shape.lent = Some(tables);
        self.links.lend_buffers(tables);
    }

    // A stack that places its links on the heap has the serial links placed there too.
    const LINK_CELL_BYTES: usize = match S::LINK_CELL_BYTES {
        0 => 0,
        links => crate::link_cells::larger_cell(
            links,
            CellRc::<SerialDriverOf<O::Device, N>>::cell_bytes(),
        ),
    };

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
        match to.as_serial() {
            Some(at) => self.dial_serial(at).map(SerialLinksDial::Serial),
            None => self.links.begin_initiator(to).map(SerialLinksDial::Links),
        }
    }

    fn open_listener(
        &self,
        at: Locator,
    ) -> Result<Box<dyn LinkListener<HeapLink<N>, N>>, LinkOpenError> {
        let Some(at) = at.as_serial() else {
            return self.links.open_listener(at);
        };
        let listener = SerialListener {
            opener: self.opener.clone(),
            at,
            shape: self.shape,
            waiting: RefCell::new(None),
            // A heap with no room for the home refuses the listener, as a stack with no line
            // left does.
            home: CellRc::try_on_heap(<N::Shared as CountKind>::new_local(LineHome::new(
                !at.options.release_on_close,
            )))
            .ok_or(LinkOpenError::Exhausted)?,
        };
        // The line is open, and cleared once, before the listen is answered: a peer that dials
        // as soon as the listen returns writes its `INIT` into a line already held, which a
        // later open would clear. A line that does not open refuses the listen, as zenoh-pico's
        // listen of a device does
        // (`vendor/zenoh-pico/src/link/transport/serial/tty_posix.c` @ `static z_result_t _z_posix_tty_listen_from_dev(`).
        listener.wait_on_line()?;
        Ok(Box::new(listener))
    }

    fn open_group(
        &self,
        endpoint: &str,
        group: &GroupLocator,
    ) -> Result<Box<dyn GroupTransport>, LinkOpenError> {
        self.links.open_group(endpoint, group)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::collections::VecDeque;
    use alloc::rc::Rc;
    use alloc::vec::Vec;
    use core::net::{Ipv4Addr, SocketAddr};

    use wz_session_core::locator_grammar::SerialOptions;
    use wz_session_core::serial_link::{encode_frame, SERIAL_FLAG_RESET};

    use crate::session_drive::{Dialled, NoWaits, SerialPath};

    /// One direction of a line: the bytes written into it and not read yet.
    type Queue = Rc<RefCell<VecDeque<u8>>>;

    /// A line of the test: what the link reads (the peer's writes), what it wrote, how many more
    /// bytes the line takes, and whether it hung up. A wait on it lets the test's clock run for
    /// the wait, and delivers what the peer writes meanwhile (`later`).
    struct TestLine {
        inbox: Queue,
        outbox: Queue,
        later: Queue,
        room: Rc<Cell<usize>>,
        hung: Rc<Cell<bool>>,
        now_us: Rc<Cell<u64>>,
    }

    impl SerialDevice for TestLine {
        type Error = ();

        fn write(&self, bytes: &[u8]) -> Result<usize, ()> {
            let taken = bytes.len().min(self.room.get());
            self.room.set(self.room.get().saturating_sub(taken));
            self.outbox.borrow_mut().extend(bytes.iter().take(taken));
            Ok(taken)
        }

        fn wait_readable(&self, timeout_ms: c_int) {
            let waited_us = u64::try_from(timeout_ms).unwrap_or(0).saturating_mul(1_000);
            self.now_us.set(self.now_us.get().saturating_add(waited_us));
            let mut later = self.later.borrow_mut();
            self.inbox.borrow_mut().extend(later.drain(..));
        }

        fn try_read(&self, buf: &mut [u8]) -> Result<Option<usize>, ()> {
            if self.hung.get() {
                return Ok(Some(0));
            }
            let mut inbox = self.inbox.borrow_mut();
            if inbox.is_empty() {
                return Ok(None);
            }
            let read = buf.len().min(inbox.len());
            for (slot, byte) in buf.iter_mut().zip(inbox.drain(..read)) {
                *slot = byte;
            }
            Ok(Some(read))
        }

        fn discard_queued(&self) -> Result<(), ()> {
            self.inbox.borrow_mut().clear();
            Ok(())
        }
    }

    /// The opener of the test: every line it opens is the one line, whose far end the test is.
    #[derive(Clone, Default)]
    struct TestOpen {
        inbox: Queue,
        outbox: Queue,
        later: Queue,
        room: Rc<Cell<usize>>,
        hung: Rc<Cell<bool>>,
        opens: Rc<Cell<usize>>,
        now_us: Rc<Cell<u64>>,
    }

    impl TestOpen {
        fn new() -> Self {
            let open = Self::default();
            open.room.set(usize::MAX);
            open
        }

        /// The peer writes the frame of `payload` behind `header`.
        fn peer_sends(&self, header: u8, payload: &[u8]) {
            self.inbox.borrow_mut().extend(frame(header, payload));
        }

        /// What the links wrote since the last look.
        fn written(&self) -> Vec<u8> {
            self.outbox.borrow_mut().drain(..).collect()
        }
    }

    impl SerialOpen for TestOpen {
        type Device = TestLine;

        // An open clears what the line held, as the host's opener does and as zenoh-pico's open of a
        // device does (`tcflush(fd, TCIOFLUSH)`).
        fn open(&self, _at: &SerialLocator) -> Result<TestLine, LinkOpenError> {
            self.opens.set(self.opens.get() + 1);
            self.inbox.borrow_mut().clear();
            Ok(TestLine {
                inbox: Rc::clone(&self.inbox),
                outbox: Rc::clone(&self.outbox),
                later: Rc::clone(&self.later),
                room: Rc::clone(&self.room),
                hung: Rc::clone(&self.hung),
                now_us: Rc::clone(&self.now_us),
            })
        }

        fn now_us(&self) -> u64 {
            self.now_us.get()
        }
    }

    /// The frame of `payload` behind `header`, as the session core writes it.
    fn frame(header: u8, payload: &[u8]) -> Vec<u8> {
        encode_frame(header, payload).expect("a frame of at most the serial MTU")
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

    fn links(open: &TestOpen) -> SerialLinks<NoLinks, TestOpen> {
        SerialLinks::new(NoLinks::default(), open.clone())
    }

    fn serial(timeout_us: u64, release_on_close: bool) -> Locator {
        Locator::Serial(SerialLocator {
            line: SerialLine::Device(SerialPath::new("/dev/ttyTEST0").expect("a path a row holds")),
            baudrate: 115_200,
            options: SerialOptions {
                exclusive: true,
                timeout_us,
                release_on_close,
            },
        })
    }

    /// A link dialled over the test's line, its handshake made.
    fn made(open: &TestOpen) -> OpenedLink<HeapLink> {
        let mut dial = links(open)
            .begin_initiator(serial(50_000, true))
            .expect("a dial");
        open.written();
        open.peer_sends(SERIAL_FLAG_INIT | SERIAL_FLAG_ACK, &[]);
        match dial.poll() {
            Some(Ok(link)) => link,
            _ => panic!("the peer's INIT|ACK makes the link"),
        }
    }

    #[test]
    fn a_dial_writes_its_init_and_is_made_by_the_peers_init_ack() {
        let open = TestOpen::new();
        let mut dial = links(&open)
            .begin_initiator(serial(50_000, true))
            .expect("a dial");
        assert_eq!(open.opens.get(), 1);
        assert_eq!(open.written(), frame(SERIAL_FLAG_INIT, &[]));
        assert!(dial.poll().is_none(), "no answer yet");
        open.peer_sends(SERIAL_FLAG_INIT | SERIAL_FLAG_ACK, &[]);
        assert!(matches!(dial.poll(), Some(Ok(_))));
    }

    #[test]
    fn a_reset_holds_the_next_init_back_for_the_locators_tout() {
        let open = TestOpen::new();
        open.now_us.set(10_000);
        let mut dial = links(&open)
            .begin_initiator(serial(2_000, true))
            .expect("a dial");
        open.written();
        open.peer_sends(SERIAL_FLAG_RESET, &[]);
        assert!(dial.poll().is_none(), "a reset is waited out");
        open.now_us.set(11_999);
        assert!(dial.poll().is_none());
        assert!(
            open.written().is_empty(),
            "no INIT before the tout has passed"
        );
        open.now_us.set(12_000);
        assert!(dial.poll().is_none());
        assert_eq!(open.written(), frame(SERIAL_FLAG_INIT, &[]));
        open.peer_sends(SERIAL_FLAG_INIT | SERIAL_FLAG_ACK, &[]);
        assert!(matches!(dial.poll(), Some(Ok(_))));
    }

    #[test]
    fn a_dial_answered_by_anything_else_is_refused() {
        let open = TestOpen::new();
        let mut dial = links(&open)
            .begin_initiator(serial(50_000, true))
            .expect("a dial");
        open.peer_sends(DATA_HEADER, b"x");
        assert!(matches!(dial.poll(), Some(Err(LinkOpenError::Refused))));
    }

    #[test]
    fn a_link_frames_each_batch_and_hands_over_each_whole_frame_it_reads() {
        let open = TestOpen::new();
        let link = made(&open);
        assert_eq!(
            link.sink.send_blocking(b"abc", Reliability::Reliable),
            LinkSendOutcome::Sent
        );
        assert_eq!(open.written(), frame(DATA_HEADER, b"abc"));
        // Bytes the line damaged, a frame of no batch, then a batch.
        open.inbox
            .borrow_mut()
            .extend([0x05, 0x11, 0x22, SERIAL_EOP]);
        open.peer_sends(DATA_HEADER, &[]);
        open.peer_sends(DATA_HEADER, b"xyz");
        let mut got = Vec::new();
        assert!(link
            .pump
            .recv_with(&mut |batch| got.extend_from_slice(batch)));
        assert_eq!(got, b"xyz");
        assert!(!link.pump.recv_with(&mut |_| {}), "nothing more");
    }

    /// The batch a receive lends lies where it was lent, unwritten, until the link is next asked
    /// to receive: a service in between, with the peer's next frame waiting on the line, leaves it
    /// as it was. What a session's round relies on to read a sample where it lies. Turned red by a
    /// link that answers the provided `false`, or by a service that reads the line into the
    /// destuffing buffer.
    #[test]
    fn a_lent_batch_lies_where_it_was_lent_until_the_next_receive() {
        let open = TestOpen::new();
        let link = made(&open);
        assert!(link.pump.lends_until_next_receive());
        open.peer_sends(DATA_HEADER, b"xyz");
        let mut lent: Option<(*const u8, usize)> = None;
        assert!(link
            .pump
            .recv_with(&mut |batch| lent = Some((batch.as_ptr(), batch.len()))));
        let (at, len) = lent.expect("a batch");
        open.peer_sends(DATA_HEADER, b"uvw");
        link.pump.service();
        // SAFETY: the bytes lie in the link's destuffing buffer, which the link holds and which
        // nothing writes until the next receive below; this read is before it.
        let still = unsafe { core::slice::from_raw_parts(at, len) };
        assert_eq!(still, b"xyz", "a service leaves the lent batch as it was");
        let mut next = Vec::new();
        assert!(link
            .pump
            .recv_with(&mut |batch| next.extend_from_slice(batch)));
        assert_eq!(next, b"uvw");
    }

    #[test]
    fn a_frame_the_line_takes_in_part_is_owed_and_finished_by_the_next_step() {
        let open = TestOpen::new();
        let link = made(&open);
        open.room.set(3);
        assert_eq!(
            link.sink.send_blocking(b"abcdef", Reliability::Reliable),
            LinkSendOutcome::Sent
        );
        assert!(link.pump.owes_write(), "the rest is owed");
        assert_eq!(
            link.sink.send_blocking(b"next", Reliability::Reliable),
            LinkSendOutcome::Dropped(LinkDropCause::NoTxSlot),
            "the wire buffer holds the frame still owed"
        );
        open.room.set(usize::MAX);
        link.pump.service();
        assert!(!link.pump.owes_write());
        assert_eq!(open.written(), frame(DATA_HEADER, b"abcdef"));
    }

    #[test]
    fn a_line_that_hangs_up_ends_the_link() {
        let open = TestOpen::new();
        let link = made(&open);
        open.hung.set(true);
        assert!(!link.pump.recv_with(&mut |_| {}));
        assert!(matches!(link.pump.lost(), Some(LostCause::PeerClosed)));
    }

    #[test]
    fn a_listener_that_releases_its_line_opens_it_for_each_link() {
        let open = TestOpen::new();
        let listener = links(&open)
            .open_listener(serial(50_000, true))
            .expect("a listener");
        assert!(matches!(listener.local(), Locator::Serial(_)));
        assert_eq!(
            open.opens.get(),
            1,
            "the line is opened when the listener is made"
        );
        assert!(listener.accept().expect("an open line").is_none());
        assert_eq!(open.opens.get(), 1);
        // The peer's INIT, behind bytes the line held before it.
        open.inbox.borrow_mut().extend([0x11, 0x22]);
        open.peer_sends(SERIAL_FLAG_INIT, &[]);
        let link = listener
            .accept()
            .expect("an open line")
            .expect("the INIT answered");
        assert_eq!(
            open.written(),
            frame(SERIAL_FLAG_INIT | SERIAL_FLAG_ACK, &[])
        );
        assert!(
            listener.accept().expect("an open line").is_none(),
            "one link at a time"
        );
        assert_eq!(open.opens.get(), 1);
        drop(link);
        assert!(listener.accept().expect("an open line").is_none());
        assert_eq!(
            open.opens.get(),
            2,
            "the line opened again for the next link"
        );
    }

    /// A peer that dials as soon as the listen returns has its `INIT` answered: the line was open
    /// before the peer wrote, and the first accept reads what it wrote. Turned red by a listener
    /// that opens its line at the first accept, whose open clears the `INIT` already on it.
    #[test]
    fn a_peer_that_dials_as_the_listen_returns_is_answered() {
        let open = TestOpen::new();
        let listener = links(&open)
            .open_listener(serial(50_000, true))
            .expect("a listener");
        open.peer_sends(SERIAL_FLAG_INIT, &[]);
        assert!(
            listener.accept().expect("an open line").is_some(),
            "the INIT written once the listen returned is answered"
        );
        assert_eq!(
            open.written(),
            frame(SERIAL_FLAG_INIT | SERIAL_FLAG_ACK, &[])
        );
    }

    #[test]
    fn a_listener_that_keeps_its_line_takes_the_next_peer_on_it() {
        let open = TestOpen::new();
        let listener = links(&open)
            .open_listener(serial(50_000, false))
            .expect("a listener");
        open.peer_sends(SERIAL_FLAG_INIT, &[]);
        let link = listener
            .accept()
            .expect("an open line")
            .expect("the INIT answered");
        assert!(listener.accept().expect("an open line").is_none());
        drop(link);
        open.written();
        open.peer_sends(SERIAL_FLAG_INIT, &[]);
        assert!(listener.accept().expect("an open line").is_some());
        assert_eq!(open.opens.get(), 1, "the line kept, not opened again");
    }

    /// A line that counts its closes.
    struct Closes(Rc<Cell<usize>>);

    impl Drop for Closes {
        fn drop(&mut self) {
            self.0.set(self.0.get().saturating_add(1));
        }
    }

    /// A line a listener lent is free again once the link over it ends: kept in the listener's
    /// home for the next link where the listener keeps its line, closed with the link otherwise.
    /// A dialled line is closed with its link. Turned red by a line still lent after its link
    /// ended, a kept line closed, or a released line kept.
    #[test]
    fn a_lent_line_goes_home_as_its_link_ends() {
        let closed = Rc::new(Cell::new(0));
        for keep in [true, false] {
            let home: HomeOf<Closes, OneTask> =
                CellRc::try_on_heap(OneTask::new_local(LineHome::new(keep)))
                    .expect("the heap has room");
            let before = closed.get();
            let lease = LineLease::homed(Closes(closed.clone()), home.clone());
            let lent = OneTask::with_local::<LineHome<Closes>, _>(&home, |home| home.free());
            assert!(lent.is_none(), "a link holds the line");
            drop(lease);
            assert_eq!(
                closed.get(),
                before + usize::from(!keep),
                "closed with its link unless kept"
            );
            let free = OneTask::with_local::<LineHome<Closes>, _>(&home, |home| {
                home.free().map(|kept| kept.is_some())
            });
            assert_eq!(
                free,
                Some(keep),
                "free, and kept when the listener keeps it"
            );
        }
        let before = closed.get();
        drop(LineLease::<Closes>::owned(Closes(closed.clone())));
        assert_eq!(
            closed.get(),
            before + 1,
            "a dialled line closes with its link"
        );
    }

    #[test]
    fn a_serial_locator_is_dialled_here_and_any_other_by_the_stack() {
        let open = TestOpen::new();
        let links = links(&open);
        let udp = Locator::udp(SocketAddr::from((Ipv4Addr::LOCALHOST, 7447)));
        assert!(links.begin_initiator(udp).is_err());
        assert_eq!(links.links.dials.get(), 1);
        assert!(links.open_listener(udp).is_err());
    }

    #[test]
    fn a_dial_that_waits_is_made_once_the_peer_answers_on_the_line() {
        let open = TestOpen::new();
        open.later
            .borrow_mut()
            .extend(frame(SERIAL_FLAG_INIT | SERIAL_FLAG_ACK, &[]));
        let link = links(&open)
            .open_initiator(serial(50_000, true))
            .expect("the peer's INIT|ACK makes the link");
        assert_eq!(open.written(), frame(SERIAL_FLAG_INIT, &[]));
        assert_eq!(
            link.sink.send_blocking(b"abc", Reliability::Reliable),
            LinkSendOutcome::Sent
        );
    }

    #[test]
    fn a_dial_that_waits_is_refused_once_the_open_wait_has_passed() {
        let open = TestOpen::new();
        open.now_us.set(5);
        assert!(matches!(
            links(&open).open_initiator(serial(50_000, true)),
            Err(LinkOpenError::Refused)
        ));
        assert!(open.now_us.get() >= 5 + OPEN_WAIT_US);
        assert_eq!(open.opens.get(), 1);
    }

    #[test]
    fn a_batch_bound_leaves_room_for_the_frame_around_it() {
        assert_eq!(payload_bound(SERIAL_MAX_COBS_BUF), SERIAL_MTU);
        let bound = payload_bound(512);
        assert_eq!(bound, 501);
        assert!(frame(DATA_HEADER, &[0x55; 501]).len() <= 512);
    }
}
