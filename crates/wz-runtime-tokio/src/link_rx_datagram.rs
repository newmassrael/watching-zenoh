// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! R3255 — ARCHITECTURE section 9.2 on the AP DATAGRAM receive: a UDP datagram
//! is received INTO a slot of the node's receive pool and handed to the session
//! as that slot.
//!
//! ## What this replaces
//!
//! The three UDP read paths each brought their own buffer: the dial read half
//! and the `UdpDriver` read (multicast group links, the scouting socket) zeroed
//! a fresh 65507-byte vector for every datagram, and the accept demux pump read
//! into a buffer of its own and copied each datagram out of it. Under
//! `runtime-zero-copy` all three receive through [`DatagramRxPool`], and the
//! frame the session decodes, and every sample it keeps, IS the slot.
//!
//! ## Two size classes, chosen by what the socket says is next
//!
//! A slot that holds any UDP datagram (65507 bytes over IPv4) is the node's
//! link-RX table, `session_rx_pool_ap`, which the stream read halves fill too.
//! Holding a 64-byte sample in a 64 KiB slot would let a few dozen kept samples
//! exhaust the table the node's stream links read into, so a datagram no larger
//! than the sessions send (`UDP_LINK_MTU`, 1450) takes a slot of the small class,
//! `session_rx_pool_ap_small` (1472 bytes), as the transmit side's two classes do.
//!
//! The class has to be chosen BEFORE the read, because a datagram read into a
//! slot too small for it is truncated and its tail is gone. The reader asks the
//! socket how long its next datagram is, which costs one non-blocking syscall
//! per datagram, and is what each host answers exactly or from above:
//!
//! | host | the question | its answer |
//! |---|---|---|
//! | Linux | `ioctl(FIONREAD)` | the next datagram's length (`udp(7)`) |
//! | macOS and the other Apple hosts | `getsockopt(SO_NREAD)` | the first datagram's length |
//! | Windows | `ioctlsocket(FIONREAD)` | the first datagram's length, or the bytes pending |
//! | other unix | `ioctl(FIONREAD)` | the bytes pending, at least the next datagram |
//!
//! An answer from above only sends a small datagram to the large class. An
//! answer from below would truncate, and the class catches it: it admits only a
//! datagram STRICTLY shorter than a slot, so a read that fills the whole slot is
//! a truncation by construction, refused and counted (Windows reports it as
//! `WSAEMSGSIZE`, the same refusal). The alternatives were measured and set
//! aside: reading every datagram into a large slot costs no query but holds 64
//! KiB per kept sample in the table the stream links share; reading into a
//! small slot first and peeking for truncation costs the same second syscall
//! and differs per host in how a peek reports it; a vectored read into a small
//! slot followed by a large one costs no query but copies the head of every
//! large datagram to make it contiguous, which is the copy this module exists to
//! remove. On this host a FIONREAD costs about what the `recvfrom` beside it
//! costs (both near 0.6 us from a Python loop on loopback, loop overhead
//! included).
//!
//! ## A dry pool refuses, and counts
//!
//! A datagram neither class has a slot for is read into nothing (a zero-length
//! receive discards a datagram on every host) and counted as refused: it is
//! never received into an allocation. That is the bounded receive path the
//! demux's own channel already is, and the `RxSlots` contract (`None` from a
//! reserve is back-pressure; the caller drops the datagram and counts it).
//!
//! ## The lifecycle, by the emit's own edges
//!
//! | what happens to the slot | edge of the generated pool |
//! |---|---|
//! | the read is about to be issued into it | `link_arm_rx`, then `dma_start_rx` |
//! | the read returned the datagram | `rx_complete` (to cpu-ref, shared read-only) |
//! | the read did not (no datagram after all, an error, a truncation) | `rx_complete`, then `pool_return` |
//! | the last range of the frame, or of a sample kept from it, drops | `pool_return` (cpu-ref to free) |
//!
//! The ranges are counted by the pool, per slot ([`RxSlotHome`]), so a frame
//! handed up and every range taken of it cost no allocation, where an `Arc` of a
//! storage would cost one per datagram.

use std::io;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicPtr, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, OnceLock};

use tokio::net::UdpSocket;
use wz_session_core::link::{RxBytes, RxSlotHome};

use crate::link_rx_pool::NodeTable;

// THE DIMENSIONS THE CLASSES EXIST FOR, enforced at COMPILE time.
//
// The small class takes a datagram only when it is strictly shorter than a
// slot (the last byte is the truncation witness), so a slot must exceed the
// datagram the sessions send. The large class must hold the largest UDP payload
// there is, and a byte more for the same witness.
const _: () = assert!(
    crate::session_rx_pool_ap_small::SLOT_SIZE > crate::udp_pipeline::UDP_LINK_MTU,
    "the small receive class must hold the steady-state datagram and its witness byte"
);
const _: () = assert!(
    crate::session_rx_pool_ap::SLOT_SIZE > crate::udp_pipeline::MAX_UDP_PAYLOAD,
    "the large receive class must hold the largest UDP datagram and its witness byte"
);
// One accept face's full channel, the frame its read half is handing up and the
// datagram the pump is receiving (`session_rx_pool_ap_small.scxml`).
const _: () = assert!(
    crate::session_rx_pool_ap_small::SLOT_COUNT
        >= crate::udp_pipeline::UDP_DEMUX_FACE_CHANNEL_CAP + 2,
    "the small receive class must hold one accept face's channel and its two frames in flight"
);

/// A slot's place in the generated lifecycle, one enum for both classes (the
/// emits each declare their own).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RxSlotState {
    Free,
    CpuMut,
    DmaArmedTx,
    DmaBusyTx,
    DmaArmedRx,
    DmaBusyRx,
    CpuRef,
}

/// One generated `sce:kind="buffer-pool"` table, as the datagram receive walks
/// it: the emit's receive edges under names of their own (an inherent method of
/// the same name would win the call and these would recurse).
pub trait RxTable: Send + 'static {
    /// The handle the emit gives for a slot the CPU shares (`Slot<CpuRef>`).
    type Ref: Send;
    const SLOT_SIZE: usize;
    const SLOT_COUNT: usize;
    /// Free to dma-armed-rx (`link_arm_rx`), the address published
    /// (`dma_armed_rx_ptr`), then dma-busy-rx (`dma_start_rx`): the slot's index
    /// and first byte.
    ///
    /// # Safety
    /// The caller is about to issue the read into the returned address, and
    /// nothing else reads or writes the slot until [`Self::complete_rx`].
    unsafe fn arm_and_start_rx(&mut self) -> Option<(usize, *mut u8)>;
    /// Dma-busy-rx to cpu-ref (`rx_complete`).
    ///
    /// # Safety
    /// The read issued into slot `idx` has returned.
    unsafe fn complete_rx(&mut self, idx: usize) -> Option<Self::Ref>;
    /// Cpu-ref to free (`pool_return`).
    fn return_ref(&mut self, slot: Self::Ref);
    fn free_slots(&self) -> usize;
    fn state_of(&self, idx: usize) -> Option<RxSlotState>;
    /// The slot whose first byte is `ptr`, by the emit's own answer.
    fn slot_at(&self, ptr: *const u8) -> Option<usize>;
}

macro_rules! impl_rx_table {
    ($module:ident, $table:ident) => {
        const _: () = assert!(
            crate::$module::SlotState::Free as u8 == 0,
            "a pool of zeroes is a pool of free slots only while free is the state 0"
        );
        impl RxTable for crate::$module::$table {
            type Ref = crate::$module::Slot<crate::$module::CpuRef>;
            const SLOT_SIZE: usize = crate::$module::SLOT_SIZE;
            const SLOT_COUNT: usize = crate::$module::SLOT_COUNT;
            unsafe fn arm_and_start_rx(&mut self) -> Option<(usize, *mut u8)> {
                let armed = self.link_arm_rx()?;
                let idx = armed.idx();
                let base = armed.dma_armed_rx_ptr(self);
                // SAFETY: the caller's contract: the "peripheral" on this row is
                // the read the caller issues into `base` next, so handing the
                // address over IS the start, as `link_rx_arena` says of its own.
                unsafe { armed.dma_start_rx(self) };
                Some((idx, base))
            }
            unsafe fn complete_rx(&mut self, idx: usize) -> Option<Self::Ref> {
                // SAFETY: the caller's contract.
                unsafe { self.rx_complete(idx) }
            }
            fn return_ref(&mut self, slot: Self::Ref) {
                slot.pool_return(self)
            }
            fn free_slots(&self) -> usize {
                self.free_count()
            }
            fn state_of(&self, idx: usize) -> Option<RxSlotState> {
                use crate::$module::SlotState as S;
                self.slot_state(idx).map(|state| match state {
                    S::Free => RxSlotState::Free,
                    S::CpuMut => RxSlotState::CpuMut,
                    S::DmaArmedTx => RxSlotState::DmaArmedTx,
                    S::DmaBusyTx => RxSlotState::DmaBusyTx,
                    S::DmaArmedRx => RxSlotState::DmaArmedRx,
                    S::DmaBusyRx => RxSlotState::DmaBusyRx,
                    S::CpuRef => RxSlotState::CpuRef,
                })
            }
            fn slot_at(&self, ptr: *const u8) -> Option<usize> {
                self.slot_index_of_ptr(ptr)
            }
        }
    };
}

impl_rx_table!(session_rx_pool_ap, SessionRxPoolAp);
impl_rx_table!(session_rx_pool_ap_small, SessionRxPoolApSmall);

/// Table `T`, allocated ZEROED and owned through a box, so no temporary of its
/// size is ever put on the stack (`link_rx_pool::heap_pool` gives the full
/// argument; the zero pattern is a table of free slots, asserted per table).
fn zeroed_table<T: RxTable>() -> Box<T> {
    // SAFETY: `alloc_zeroed` returns a block of `Layout::new::<T>()`, sized and
    // aligned for it, and the all-zero pattern is a valid generated table (its
    // storage is bytes and its states read free), so the block holds an
    // initialised value before `from_raw` owns it.
    let table = unsafe {
        let layout = core::alloc::Layout::new::<T>();
        let raw = std::alloc::alloc_zeroed(layout) as *mut T;
        if raw.is_null() {
            std::alloc::handle_alloc_error(layout);
        }
        Box::from_raw(raw)
    };
    debug_assert_eq!(
        table.free_slots(),
        T::SLOT_COUNT,
        "the zero pattern is no longer the pool's initial state"
    );
    table
}

/// What one size class has done since it was built. Each slot armed is counted
/// once in `armed`, and then once in exactly one of `completed` (the datagram is
/// in it and handed up), `abandoned` (the read did not land a datagram, and the
/// slot went home through the completion edge) or `faults` (the emit refused
/// the completion edge, which a correct walk never meets). Each completed slot
/// is counted once more in `returned` when its last range drops.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct RxClassStats {
    pub armed: u64,
    pub completed: u64,
    pub abandoned: u64,
    pub returned: u64,
    pub faults: u64,
    /// Releases of a slot no range held: a defect of a caller of the lease,
    /// refused rather than wrapped below zero.
    pub stray_releases: u64,
}

#[derive(Default)]
struct ClassCounters {
    armed: AtomicU64,
    completed: AtomicU64,
    abandoned: AtomicU64,
    returned: AtomicU64,
    faults: AtomicU64,
    stray_releases: AtomicU64,
}

/// One size class over generated table `T`: the table, the emit's handle for
/// every slot a frame holds, and the count of the ranges reading each slot.
pub struct RxClass<T: RxTable> {
    table: Arc<NodeTable<T>>,
    /// The emit's cpu-ref handle of each slot a frame holds, by index.
    held: Mutex<Vec<Option<T::Ref>>>,
    /// The ranges reading each slot; the last release sends it home.
    refs: Box<[AtomicUsize]>,
    /// Each slot's first byte, published when it is armed.
    bases: Box<[AtomicPtr<u8>]>,
    counters: ClassCounters,
}

impl<T: RxTable> RxClass<T> {
    fn over(table: Arc<NodeTable<T>>) -> Self {
        Self {
            table,
            held: Mutex::new((0..T::SLOT_COUNT).map(|_| None).collect()),
            refs: (0..T::SLOT_COUNT).map(|_| AtomicUsize::new(0)).collect(),
            bases: (0..T::SLOT_COUNT)
                .map(|_| AtomicPtr::new(std::ptr::null_mut()))
                .collect(),
            counters: ClassCounters::default(),
        }
    }

    fn private() -> Self {
        Self::over(Arc::new(NodeTable {
            slots: Mutex::new(zeroed_table::<T>()),
        }))
    }

    /// A free slot armed and started for a read: its index and first byte.
    fn arm(&self) -> Option<(usize, *mut u8)> {
        let mut table = self.table.slots.lock().ok()?;
        // SAFETY: the caller issues the read into the slot next and is the only
        // holder of its address until `complete` or `abandon`.
        let (idx, base) = unsafe { table.arm_and_start_rx() }?;
        self.bases[idx].store(base, Ordering::Release);
        self.counters.armed.fetch_add(1, Ordering::Relaxed);
        Some((idx, base))
    }

    /// The read into slot `idx` returned a datagram: cpu-ref, one range.
    fn complete(&self, idx: usize) -> bool {
        let Ok(mut table) = self.table.slots.lock() else {
            self.counters.faults.fetch_add(1, Ordering::Relaxed);
            return false;
        };
        // SAFETY: the read issued into this slot has returned.
        let Some(shared) = (unsafe { table.complete_rx(idx) }) else {
            self.counters.faults.fetch_add(1, Ordering::Relaxed);
            return false;
        };
        match self.held.lock() {
            Ok(mut held) => held[idx] = Some(shared),
            Err(_) => {
                // A poisoned book cannot record the handle, so the slot goes home
                // now rather than being lent with no way back.
                table.return_ref(shared);
                self.counters.faults.fetch_add(1, Ordering::Relaxed);
                return false;
            }
        }
        self.refs[idx].store(1, Ordering::Release);
        self.counters.completed.fetch_add(1, Ordering::Relaxed);
        true
    }

    /// The read into slot `idx` landed no datagram: home through the completion
    /// edge, the only edge out of dma-busy-rx.
    fn abandon(&self, idx: usize) {
        let Ok(mut table) = self.table.slots.lock() else {
            return;
        };
        // SAFETY: the read issued into this slot has returned.
        match unsafe { table.complete_rx(idx) } {
            Some(shared) => {
                table.return_ref(shared);
                self.counters.abandoned.fetch_add(1, Ordering::Relaxed);
            }
            None => {
                self.counters.faults.fetch_add(1, Ordering::Relaxed);
            }
        }
    }

    /// The last range of slot `idx` dropped: cpu-ref to free.
    fn go_home(&self, idx: usize) {
        let Ok(mut table) = self.table.slots.lock() else {
            return;
        };
        let shared = match self.held.lock() {
            Ok(mut held) => held[idx].take(),
            Err(_) => None,
        };
        match shared {
            Some(shared) => {
                table.return_ref(shared);
                self.counters.returned.fetch_add(1, Ordering::Relaxed);
            }
            None => {
                self.counters.stray_releases.fetch_add(1, Ordering::Relaxed);
            }
        }
    }

    fn stats(&self) -> RxClassStats {
        let c = &self.counters;
        RxClassStats {
            armed: c.armed.load(Ordering::Relaxed),
            completed: c.completed.load(Ordering::Relaxed),
            abandoned: c.abandoned.load(Ordering::Relaxed),
            returned: c.returned.load(Ordering::Relaxed),
            faults: c.faults.load(Ordering::Relaxed),
            stray_releases: c.stray_releases.load(Ordering::Relaxed),
        }
    }

    /// Slots a frame of this class holds now.
    fn live(&self) -> usize {
        self.refs
            .iter()
            .filter(|r| r.load(Ordering::Acquire) > 0)
            .count()
    }

    fn free_slots(&self) -> usize {
        self.table.slots.lock().map_or(0, |t| t.free_slots())
    }

    fn slot_state(&self, idx: usize) -> Option<RxSlotState> {
        self.table.slots.lock().ok().and_then(|t| t.state_of(idx))
    }

    fn slot_at(&self, ptr: *const u8) -> Option<usize> {
        self.table.slots.lock().ok().and_then(|t| t.slot_at(ptr))
    }
}

/// A frame of this class is a range of one of its slots, read where it lies.
impl<T: RxTable> RxSlotHome for RxClass<T> {
    fn slot_bytes(&self, slot: usize) -> &[u8] {
        let base = self.bases[slot].load(Ordering::Acquire);
        // SAFETY: `base` is the first byte of slot `slot`, published when it was
        // armed, valid for `SLOT_SIZE` bytes because the table is boxed and this
        // class keeps it alive. A range of the slot exists (its count is above
        // zero), so the slot is in cpu-ref: nothing writes it until the last
        // range drops and it goes home.
        unsafe { std::slice::from_raw_parts(base, T::SLOT_SIZE) }
    }

    fn retain(&self, slot: usize) {
        self.refs[slot].fetch_add(1, Ordering::Relaxed);
    }

    fn release(&self, slot: usize) {
        match self.refs[slot]
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |n| n.checked_sub(1))
        {
            Ok(1) => self.go_home(slot),
            Ok(_) => {}
            Err(_) => {
                self.counters.stray_releases.fetch_add(1, Ordering::Relaxed);
            }
        }
    }
}

/// Which class a slot belongs to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RxClassId {
    /// `session_rx_pool_ap_small`.
    Small,
    /// `session_rx_pool_ap`, the node's link-RX table.
    Large,
}

/// Why a datagram was not handed up.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Refusal {
    /// No class had a slot for it.
    Dry,
    /// The read filled the whole slot: the length the socket gave was short.
    Truncated,
    /// The emit refused a lifecycle edge (a defect, counted per class).
    Fault,
}

/// One datagram read off a socket.
#[derive(Debug)]
pub enum DatagramRead {
    /// The datagram, as a range of the slot it was received into.
    Frame { bytes: RxBytes, src: SocketAddr },
    /// The datagram was consumed and not handed up, counted by cause.
    Refused {
        src: Option<SocketAddr>,
        cause: Refusal,
    },
}

type Small = crate::session_rx_pool_ap_small::SessionRxPoolApSmall;
type Large = crate::session_rx_pool_ap::SessionRxPoolAp;

/// The node's datagram receive pool: the small class and the large one (the
/// node's link-RX table), and the datagrams refused for want of a slot.
pub struct DatagramRxPool {
    small: Arc<RxClass<Small>>,
    large: Arc<RxClass<Large>>,
    refused: AtomicU64,
    truncated: AtomicU64,
}

impl DatagramRxPool {
    /// THE NODE's pool, built on the first datagram a UDP link receives: a
    /// small class of its own and the node's link-RX table as the large one.
    pub fn node() -> &'static DatagramRxPool {
        static NODE: OnceLock<DatagramRxPool> = OnceLock::new();
        NODE.get_or_init(|| Self {
            small: Arc::new(RxClass::private()),
            large: Arc::new(RxClass::over(crate::link_rx_pool::node_table())),
            refused: AtomicU64::new(0),
            truncated: AtomicU64::new(0),
        })
    }

    /// A PRIVATE pool with tables of its own, for a caller that owns its node
    /// (the seam a node object plugs into, as `LinkRxArena::new` is), and what
    /// lets a test exhaust a pool without starving the process's links.
    pub fn new() -> Self {
        Self {
            small: Arc::new(RxClass::private()),
            large: Arc::new(RxClass::private()),
            refused: AtomicU64::new(0),
            truncated: AtomicU64::new(0),
        }
    }

    /// Receive the next datagram on `socket` into a slot.
    ///
    /// Cancel-safe: nothing is held across the one `await`, which is the wait
    /// for the socket to be readable; the length query, the arming and the read
    /// that follow it run without yielding.
    pub async fn recv_from(&self, socket: &UdpSocket) -> io::Result<DatagramRead> {
        loop {
            socket.readable().await?;
            match self.try_recv_from(socket) {
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => continue,
                other => return other,
            }
        }
    }

    /// One attempt: `WouldBlock` when no datagram was waiting after all.
    pub fn try_recv_from(&self, socket: &UdpSocket) -> io::Result<DatagramRead> {
        let small =
            pending_datagram_len(socket).is_ok_and(|len| len < <Small as RxTable>::SLOT_SIZE);
        if small {
            if let Some(read) = self.receive_into(&self.small, socket) {
                return read;
            }
        }
        if let Some(read) = self.receive_into(&self.large, socket) {
            return read;
        }
        // Neither class has a slot: read the datagram into nothing, which
        // discards it on every host, and count it.
        let src = match socket.try_recv_from(&mut []) {
            Ok((_, src)) => Some(src),
            Err(e) if is_truncation(&e) => None,
            Err(e) => return Err(e),
        };
        self.refused.fetch_add(1, Ordering::Relaxed);
        Ok(DatagramRead::Refused {
            src,
            cause: Refusal::Dry,
        })
    }

    /// Read the next datagram into a slot of `class`; `None` when the class has
    /// no free slot.
    fn receive_into<T: RxTable>(
        &self,
        class: &Arc<RxClass<T>>,
        socket: &UdpSocket,
    ) -> Option<io::Result<DatagramRead>> {
        let (idx, base) = class.arm()?;
        // SAFETY: `base` is the first byte of a slot armed for this read and
        // valid for `SLOT_SIZE` bytes; nothing else holds its address.
        let buf = unsafe { std::slice::from_raw_parts_mut(base, T::SLOT_SIZE) };
        let read = match socket.try_recv_from(buf) {
            Ok((n, src)) if n < T::SLOT_SIZE => {
                if !class.complete(idx) {
                    return Some(Ok(DatagramRead::Refused {
                        src: Some(src),
                        cause: Refusal::Fault,
                    }));
                }
                let home: Arc<dyn RxSlotHome> = class.clone();
                match RxBytes::leased(home, idx, 0..n) {
                    Some(bytes) => Ok(DatagramRead::Frame { bytes, src }),
                    None => Ok(DatagramRead::Refused {
                        src: Some(src),
                        cause: Refusal::Fault,
                    }),
                }
            }
            Ok((_, src)) => {
                class.abandon(idx);
                self.truncated.fetch_add(1, Ordering::Relaxed);
                Ok(DatagramRead::Refused {
                    src: Some(src),
                    cause: Refusal::Truncated,
                })
            }
            Err(e) if is_truncation(&e) => {
                class.abandon(idx);
                self.truncated.fetch_add(1, Ordering::Relaxed);
                Ok(DatagramRead::Refused {
                    src: None,
                    cause: Refusal::Truncated,
                })
            }
            Err(e) => {
                class.abandon(idx);
                Err(e)
            }
        };
        Some(read)
    }

    /// Datagrams refused because neither class had a slot.
    pub fn refused(&self) -> u64 {
        self.refused.load(Ordering::Relaxed)
    }

    /// Datagrams refused because the read filled a whole slot.
    pub fn truncated(&self) -> u64 {
        self.truncated.load(Ordering::Relaxed)
    }

    /// Class `class`'s counters.
    pub fn stats(&self, class: RxClassId) -> RxClassStats {
        match class {
            RxClassId::Small => self.small.stats(),
            RxClassId::Large => self.large.stats(),
        }
    }

    /// Slots of class `class` a frame holds now.
    pub fn live(&self, class: RxClassId) -> usize {
        match class {
            RxClassId::Small => self.small.live(),
            RxClassId::Large => self.large.live(),
        }
    }

    /// Free slots of class `class`'s table, by the emit's own count (the large
    /// table of the node pool is shared with the stream read halves).
    pub fn free_slots(&self, class: RxClassId) -> usize {
        match class {
            RxClassId::Small => self.small.free_slots(),
            RxClassId::Large => self.large.free_slots(),
        }
    }

    /// Slots in class `class`'s table.
    pub fn capacity(&self, class: RxClassId) -> usize {
        match class {
            RxClassId::Small => <Small as RxTable>::SLOT_COUNT,
            RxClassId::Large => <Large as RxTable>::SLOT_COUNT,
        }
    }

    /// The lifecycle state the emit records for slot `idx` of class `class`.
    pub fn slot_state(&self, class: RxClassId, idx: usize) -> Option<RxSlotState> {
        match class {
            RxClassId::Small => self.small.slot_state(idx),
            RxClassId::Large => self.large.slot_state(idx),
        }
    }

    /// Which slot of which class has its first byte at `ptr`, by the emits' own
    /// answer: the witness that a frame IS a slot and not a copy of one.
    pub fn slot_of(&self, ptr: *const u8) -> Option<(RxClassId, usize)> {
        self.small
            .slot_at(ptr)
            .map(|idx| (RxClassId::Small, idx))
            .or_else(|| self.large.slot_at(ptr).map(|idx| (RxClassId::Large, idx)))
    }
}

impl Default for DatagramRxPool {
    fn default() -> Self {
        Self::new()
    }
}

/// The read a UDP link that owns its socket runs (the dial read half, and the
/// `UdpDriver` a multicast group link or the scouting socket reads through):
/// the next datagram, received into the node's pool, as the frame the session
/// is handed. A datagram the pool refused was consumed and counted there, and
/// the read goes on to the next one.
pub async fn recv_frame(socket: &UdpSocket) -> io::Result<wz_session_core::link::RxFrame> {
    loop {
        match DatagramRxPool::node().recv_from(socket).await? {
            DatagramRead::Frame { bytes, src } => {
                return Ok(wz_session_core::link::RxFrame::with_src(bytes, src))
            }
            DatagramRead::Refused { .. } => continue,
        }
    }
}

/// The length of the next datagram waiting on `socket`, as the host answers it
/// (see the module docs for what each host's answer means).
#[cfg(all(unix, not(target_vendor = "apple")))]
fn pending_datagram_len(socket: &UdpSocket) -> io::Result<usize> {
    use std::os::fd::AsRawFd;
    let mut len: libc::c_int = 0;
    // SAFETY: FIONREAD writes one `int` through the pointer, which is a live
    // local of that type; the descriptor is the socket's own.
    let rc = unsafe { libc::ioctl(socket.as_raw_fd(), libc::FIONREAD, &mut len) };
    if rc < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(usize::try_from(len).unwrap_or(0))
}

#[cfg(target_vendor = "apple")]
fn pending_datagram_len(socket: &UdpSocket) -> io::Result<usize> {
    use std::os::fd::AsRawFd;
    let mut len: libc::c_int = 0;
    let mut size = std::mem::size_of::<libc::c_int>() as libc::socklen_t;
    // SAFETY: SO_NREAD writes one `int` and its size through the two pointers,
    // which are live locals of those types; the descriptor is the socket's own.
    let rc = unsafe {
        libc::getsockopt(
            socket.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_NREAD,
            (&mut len as *mut libc::c_int).cast(),
            &mut size,
        )
    };
    if rc < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(usize::try_from(len).unwrap_or(0))
}

#[cfg(windows)]
fn pending_datagram_len(socket: &UdpSocket) -> io::Result<usize> {
    use std::os::windows::io::AsRawSocket;
    use windows_sys::Win32::Networking::WinSock::{ioctlsocket, FIONREAD, SOCKET};
    let mut len: u32 = 0;
    // SAFETY: FIONREAD writes one `u_long` through the pointer, which is a live
    // local of that type; the socket is the one this value wraps.
    let rc = unsafe { ioctlsocket(socket.as_raw_socket() as SOCKET, FIONREAD, &mut len) };
    if rc != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(len as usize)
}

#[cfg(not(any(unix, windows)))]
fn pending_datagram_len(_socket: &UdpSocket) -> io::Result<usize> {
    Err(io::Error::from(io::ErrorKind::Unsupported))
}

/// Whether a receive error says the datagram was larger than the buffer, which
/// discards it: Windows reports that as `WSAEMSGSIZE`, where the unix hosts
/// return the truncated length.
#[cfg(windows)]
fn is_truncation(e: &io::Error) -> bool {
    e.raw_os_error() == Some(windows_sys::Win32::Networking::WinSock::WSAEMSGSIZE)
}

#[cfg(not(windows))]
fn is_truncation(_e: &io::Error) -> bool {
    false
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::UdpSocket as PeerSocket;

    // Every test builds a PRIVATE pool (`DatagramRxPool::new`), never the node's,
    // so exhausting a class here cannot starve whatever else the process reads.

    async fn pair() -> (PeerSocket, UdpSocket) {
        let peer = PeerSocket::bind("127.0.0.1:0").expect("peer");
        let socket = UdpSocket::bind("127.0.0.1:0").await.expect("bind");
        (peer, socket)
    }

    async fn frame(pool: &DatagramRxPool, socket: &UdpSocket) -> (RxBytes, SocketAddr) {
        match pool.recv_from(socket).await.expect("read") {
            DatagramRead::Frame { bytes, src } => (bytes, src),
            refused => panic!("expected a frame, got {refused:?}"),
        }
    }

    /// The accounting identity of a class, against the emit's own freelist.
    fn balanced(pool: &DatagramRxPool, class: RxClassId) {
        let s = pool.stats(class);
        let live = pool.live(class) as u64;
        assert_eq!(
            s.armed,
            s.completed + s.abandoned + s.faults,
            "{class:?}: {s:?}"
        );
        assert_eq!(s.completed, s.returned + live, "{class:?}: {s:?}");
        assert_eq!(s.faults, 0, "{class:?}");
        assert_eq!(s.stray_releases, 0, "{class:?}");
        assert_eq!(
            pool.free_slots(class) as u64,
            pool.capacity(class) as u64 - live,
            "{class:?}: the emit's freelist is every slot no frame holds"
        );
    }

    /// THE WITNESS: the datagram the session is handed IS a slot of the pool,
    /// by the emit's own answer for the address, shared read-only while any
    /// range of it lives, and home when the last one drops.
    ///
    /// An address and not the bytes: a copy has the same bytes.
    #[tokio::test]
    async fn a_datagram_is_its_slot_until_its_last_range_drops() {
        let pool = DatagramRxPool::new();
        let (peer, socket) = pair().await;
        peer.send_to(b"in the slot", socket.local_addr().unwrap())
            .unwrap();
        let (bytes, src) = frame(&pool, &socket).await;
        assert_eq!(src, peer.local_addr().unwrap());
        assert_eq!(&bytes[..], b"in the slot");
        assert!(bytes.is_leased());
        let (class, idx) = pool
            .slot_of(bytes.as_ptr())
            .expect("the frame's bytes ARE a slot, by the pool's own answer");
        assert_eq!(class, RxClassId::Small);
        assert_eq!(pool.slot_state(class, idx), Some(RxSlotState::CpuRef));
        assert_eq!(pool.free_slots(class), pool.capacity(class) - 1);

        let kept = bytes.subslice(3..7).expect("inside");
        drop(bytes);
        assert_eq!(
            pool.slot_state(class, idx),
            Some(RxSlotState::CpuRef),
            "a range kept from the frame keeps the slot out"
        );
        assert_eq!(&kept[..], b"the ");
        drop(kept);
        assert_eq!(pool.slot_state(class, idx), Some(RxSlotState::Free));
        assert_eq!(pool.free_slots(class), pool.capacity(class));
        balanced(&pool, RxClassId::Small);
    }

    /// The class is chosen by the length the socket says is next: strictly
    /// shorter than a small slot is small, anything else large.
    #[tokio::test]
    async fn the_class_is_the_smallest_whose_slot_exceeds_the_datagram() {
        let pool = DatagramRxPool::new();
        let (peer, socket) = pair().await;
        let to = socket.local_addr().unwrap();
        let small = <Small as RxTable>::SLOT_SIZE;
        for (len, expected) in [
            (0usize, RxClassId::Small),
            (1450, RxClassId::Small),
            (small - 1, RxClassId::Small),
            (small, RxClassId::Large),
            (65_507, RxClassId::Large),
        ] {
            let payload: Vec<u8> = (0..len).map(|i| i as u8).collect();
            peer.send_to(&payload, to).unwrap();
            let (bytes, _) = frame(&pool, &socket).await;
            assert_eq!(&bytes[..], &payload[..]);
            let held = if len == 0 {
                // An empty range has no first byte to ask about; the class is
                // read off the counters instead.
                None
            } else {
                Some(pool.slot_of(bytes.as_ptr()).expect("a slot").0)
            };
            if let Some(class) = held {
                assert_eq!(class, expected, "a datagram of {len} bytes");
            }
            assert_eq!(pool.live(expected), 1, "a datagram of {len} bytes");
        }
        balanced(&pool, RxClassId::Small);
        balanced(&pool, RxClassId::Large);
        assert_eq!(pool.truncated(), 0);
    }

    /// A small datagram takes the large class while the small one is out.
    #[tokio::test]
    async fn a_small_datagram_takes_the_large_class_when_the_small_one_is_out() {
        let pool = DatagramRxPool::new();
        let (peer, socket) = pair().await;
        let armed: Vec<usize> = (0..pool.capacity(RxClassId::Small))
            .map(|_| pool.small.arm().expect("a free slot").0)
            .collect();
        peer.send_to(b"small", socket.local_addr().unwrap())
            .unwrap();
        let (bytes, _) = frame(&pool, &socket).await;
        assert_eq!(
            pool.slot_of(bytes.as_ptr()).map(|s| s.0),
            Some(RxClassId::Large)
        );
        drop(bytes);
        for idx in armed {
            pool.small.abandon(idx);
        }
        balanced(&pool, RxClassId::Small);
        balanced(&pool, RxClassId::Large);
    }

    /// A DRY POOL REFUSES, COUNTS, AND CONSUMES: the datagram no class had a
    /// slot for is read into nothing and counted, and the next one, once a slot
    /// is free again, is received (so the refused one did not stay queued).
    #[tokio::test]
    async fn a_dry_pool_refuses_counts_and_consumes_the_datagram() {
        let pool = DatagramRxPool::new();
        let (peer, socket) = pair().await;
        let to = socket.local_addr().unwrap();
        let small: Vec<usize> = (0..pool.capacity(RxClassId::Small))
            .map(|_| pool.small.arm().expect("a free slot").0)
            .collect();
        let large: Vec<usize> = (0..pool.capacity(RxClassId::Large))
            .map(|_| pool.large.arm().expect("a free slot").0)
            .collect();
        peer.send_to(b"refused", to).unwrap();
        match pool.recv_from(&socket).await.expect("read") {
            DatagramRead::Refused { src, cause } => {
                assert_eq!(cause, Refusal::Dry);
                assert_eq!(src, Some(peer.local_addr().unwrap()));
            }
            frame => panic!("a dry pool hands nothing up, got {frame:?}"),
        }
        assert_eq!(pool.refused(), 1);
        for idx in small {
            pool.small.abandon(idx);
        }
        for idx in large {
            pool.large.abandon(idx);
        }
        peer.send_to(b"received", to).unwrap();
        let (bytes, _) = frame(&pool, &socket).await;
        assert_eq!(&bytes[..], b"received", "the refused datagram was consumed");
        drop(bytes);
        assert_eq!(pool.refused(), 1);
        balanced(&pool, RxClassId::Small);
        balanced(&pool, RxClassId::Large);
    }

    /// A read that fills its whole slot is a truncation, refused and counted,
    /// and the slot goes home: what the class does when the length it was told
    /// was short, driven here by reading a long datagram into a small slot.
    #[tokio::test]
    async fn a_read_that_fills_its_slot_is_a_counted_truncation() {
        let pool = DatagramRxPool::new();
        let (peer, socket) = pair().await;
        peer.send_to(&[7u8; 2000], socket.local_addr().unwrap())
            .unwrap();
        socket.readable().await.unwrap();
        let read = pool
            .receive_into(&pool.small, &socket)
            .expect("a free slot")
            .expect("the read");
        assert!(matches!(
            read,
            DatagramRead::Refused {
                cause: Refusal::Truncated,
                ..
            }
        ));
        assert_eq!(pool.truncated(), 1);
        assert_eq!(pool.stats(RxClassId::Small).abandoned, 1);
        balanced(&pool, RxClassId::Small);
    }
}
