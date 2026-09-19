// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! R2742 — the link-RX pool as `crate::poll_framed`'s destination.
//!
//! ## The structure that existed and had nobody to serve
//!
//! ⚠ THE LINKS BELOW ARE SPELLED IN FULL, and that is forced rather than
//! verbose. This module is declared in `lib.rs` with a `///` comment of its
//! own, so rustdoc MERGES that with this `//!` block and resolves the result in
//! the OUTER scope — `wz_runtime_tokio`, where neither this module's own items
//! nor its `use` imports are in scope. `frame_arena` records the same finding
//! beside its own `FrameArena` link; R2742 repeated it anyway and C1bz counted
//! four unresolved links for it (522 against a budget of 518).
//!
//! R2739 emitted `session_rx_pool_ap` and gave it the
//! [`RxSlots`](wz_runtime_core::rx_slots::RxSlots) seam; R2740
//! made the framing read take its destination from a
//! [`FrameArena`](crate::frame_arena::FrameArena) instead of manufacturing a
//! `Vec`. Between them sat nothing: the only two arenas were the allocator
//! ([`HeapArena`](crate::frame_arena::HeapArena)) and a free list of boxes
//! ([`RecyclingArena`](crate::frame_arena::RecyclingArena)), so a production
//! link's bytes still landed somewhere the pool had never heard of, and the
//! pool's own slot table had zero consumers. This module is the third impl,
//! and it is the one that makes ARCHITECTURE §9.2's single-frame RX
//! pool-routed: the socket read writes INTO a slot of the node's table and the
//! frame is read back out of that same slot.
//!
//! ## Upstream's shape, read rather than invented
//!
//! The pinned zenoh hands its uring reader's registered buffers out as an
//! OWNED handle over borrowed storage:
//!
//! ```text
//! pub struct RxBuffer {
//!     data: &'static mut [u8],
//!     buf_id: u16,
//!     arena: Arc<ReservableArenaInner>,
//! }
//! impl Drop for RxBuffer { fn drop(&mut self) { self.arena.recycle_batch(self.buf_id); } }
//! ```
//! (`commons/zenoh-uring/src/linux/api/reader/rx_buffer.rs`
//! @ `pub struct RxBuffer {`), whose `data`
//! comes from `BatchArena::index_mut_unchecked`, an `unsafe fn` returning
//! `&'static mut [u8]` sliced out of the pinned arena
//! (`commons/zenoh-uring/src/linux/batch_arena.rs`
//! @ `unsafe fn index_mut_unchecked(`).
//! [`LinkRxFrame`](crate::link_rx_arena::LinkRxFrame) is that shape with wz's nouns: a
//! raw pointer into one slot, the slot's own handle, and the table to give it
//! back to. It is NOT a borrow, for the same reason
//! [`RecycledBuf`](crate::frame_arena::RecycledBuf) is not one — a lifetime
//! would tie every frame to a borrow of the arena, and `crate::poll_framed`
//! holds its frame across an `await` in a `ReadState` its driver owns beside
//! the arena.
//!
//! ## Why the table is the NODE's and not the link's
//!
//! `RecyclingArena` is per link because upstream's non-uring pool is per link,
//! built inside `rx_task_non_uring` from that link's own mtu — and at the
//! pinned defaults it is ONE buffer. This table is the other kind: it is
//! declared once per NODE (`deploy/ap_mcu_pair.yaml` @ `session_rx_pool`), it
//! is `SLOT_COUNT` x `SLOT_SIZE` = about 4.2 MiB, and giving each link its own
//! would multiply that by the link count to buy nothing — a link's read half
//! holds at most one frame at a time, which is why sixty-four slots serve
//! sixty-four links rather than one.
//!
//! So [`LinkRxArena::node`](crate::link_rx_arena::LinkRxArena::node) is a
//! handle on one process-wide table and
//! [`LinkRxArena::new`](crate::link_rx_arena::LinkRxArena::new) builds a
//! private one. The second is not a test
//! affordance: it is the constructor a later round threads from a node object
//! once one exists to thread from, and having it means that round changes a
//! call site rather than this type. Today no such object is reachable from the
//! nine `wire_*` sites that build a read half — R2740 measured that and took
//! the same answer for the same reason.

use std::sync::{Arc, Mutex};

use wz_runtime_core::rx_slots::RxSlots;

use crate::frame_arena::FrameArena;
use crate::link_rx_pool::heap_pool;
use crate::session_rx_pool_ap::{CpuMut, SessionRxPoolAp, Slot, SLOT_SIZE};

/// One link-RX slot table, plus the lock that serialises reserve and release.
///
/// A `Mutex` and not a lock-free freelist: the table's operations are a
/// freelist scan and a state store, they happen once per FRAME rather than
/// once per byte, and the population sharing them is a node's links. Upstream
/// reaches for an atomic queue because its arena serves a submission ring's
/// completion path; this one serves a handful of `tokio` tasks.
struct NodeTable {
    slots: Mutex<Box<SessionRxPoolAp>>,
}

/// A handle on a link-RX slot table, cheap to clone and shared by every link
/// that reads through it.
#[derive(Clone)]
pub struct LinkRxArena {
    table: Arc<NodeTable>,
}

impl LinkRxArena {
    /// A handle on THE NODE's table, built on first use.
    ///
    /// Lazily, so a process that never opens a byte-stream link never pays the
    /// 4.2 MiB: the pool is a receive resource and a node with no links
    /// receives nothing.
    pub fn node() -> Self {
        static TABLE: std::sync::OnceLock<Arc<NodeTable>> = std::sync::OnceLock::new();
        Self {
            table: TABLE
                .get_or_init(|| {
                    Arc::new(NodeTable {
                        slots: Mutex::new(heap_pool()),
                    })
                })
                .clone(),
        }
    }

    /// A PRIVATE table, for a caller that owns its own node.
    ///
    /// See the module docs: this is the seam a node object plugs into, and it
    /// is what lets a test observe exhaustion without starving whatever else
    /// the process is receiving.
    pub fn new() -> Self {
        Self {
            table: Arc::new(NodeTable {
                slots: Mutex::new(heap_pool()),
            }),
        }
    }

    /// Slots currently on this table's freelist.
    ///
    /// The accounting the seam exists for: a frame that is dropped without its
    /// slot going home shows up here and nowhere else until the table runs dry
    /// somewhere unrelated.
    pub fn free_slots(&self) -> usize {
        match self.table.slots.lock() {
            Ok(slots) => slots.free_count(),
            Err(_) => 0,
        }
    }

    /// Which slot of THIS table an address names, if any.
    ///
    /// The pool's own answer (`SessionRxPoolAp::slot_index_of_ptr`) rather
    /// than arithmetic performed here, which is what makes it usable as a
    /// witness: a test that computed the expected address itself would agree
    /// with a copy that happened to be at the address the test computed.
    pub fn slot_of(&self, addr: *const u8) -> Option<usize> {
        self.table
            .slots
            .lock()
            .ok()
            .and_then(|slots| slots.slot_index_of_ptr(addr))
    }

    /// Lifecycle state the emit records for `idx`, for tests that adjudicate
    /// against the generated FSM instead of against this module's bookkeeping.
    pub fn slot_state(&self, idx: usize) -> Option<crate::session_rx_pool_ap::SlotState> {
        self.table
            .slots
            .lock()
            .ok()
            .and_then(|slots| slots.slot_state(idx))
    }
}

impl Default for LinkRxArena {
    fn default() -> Self {
        Self::new()
    }
}

impl FrameArena for LinkRxArena {
    type Buf = LinkRxFrame;

    fn take(&mut self, want: usize) -> LinkRxFrame {
        // ONE arm for two causes, both of which are "this table has no slot for
        // this frame": the freelist is empty, or the frame is wider than a slot.
        // The second cannot happen through `crate::poll_framed` -- the const
        // assertion in `crate::link_rx_pool` fails the BUILD unless a slot holds
        // prefix + `u16::MAX` -- but `FrameArena::take` promises storage for
        // `want`, not for `MAX_FRAME`, and folding the two keeps the arm
        // reachable instead of documenting a branch nobody can take.
        if want > SLOT_SIZE {
            return LinkRxFrame::spilled(want);
        }
        let Ok(mut guard) = self.table.slots.lock() else {
            return LinkRxFrame::spilled(want);
        };
        let slots: &mut SessionRxPoolAp = &mut guard;
        let Some(mut held) = slots.reserve() else {
            // Upstream's dry-pool arm is `pool.try_take().unwrap_or_else(||
            // pool.alloc())`, so falling back to the allocator is its shape
            // rather than an optimism here. `RxSlots::reserve` documents `None`
            // as back-pressure, but a link cannot apply back-pressure to a peer
            // whose bytes are already in the socket, so the frame costs an
            // allocation and the steady state keeps its slots.
            return LinkRxFrame::spilled(want);
        };
        // The borrow of `slots` and `held` ends with this statement, which is
        // what lets the handle move into the frame on the next one. Same
        // manoeuvre as `crate::uring`'s registration, which collects every
        // slot's address without holding N mutable borrows.
        let data = slots.buf(&mut held).as_mut_ptr();
        LinkRxFrame {
            len: want,
            storage: Storage::Slot {
                data,
                held: Some(held),
                home: Arc::clone(&self.table),
            },
        }
    }
}

/// One frame's storage, owned, that returns its slot to the table on drop.
pub struct LinkRxFrame {
    /// The FRAME's width. A slot is always `SLOT_SIZE` wide and a frame is
    /// whatever its prefix named, and `crate::poll_framed` reads completion off
    /// `as_ref().len()` -- so this, not the slot, is what the accessors show.
    len: usize,
    storage: Storage,
}

enum Storage {
    /// A slot of a live table.
    Slot {
        /// First byte of the slot, valid for `SLOT_SIZE` bytes.
        ///
        /// Stable because `heap_pool` puts the table in a `Box` and `home`
        /// keeps that box alive; exclusive because `reserve` handed this slot
        /// out and nothing else can hold it until `release` takes it back.
        data: *mut u8,
        /// `Option` only so [`Drop`] can move the handle out; `Some` for the
        /// whole observable life of the value.
        held: Option<Slot<CpuMut>>,
        home: Arc<NodeTable>,
    },
    /// No slot was available, so this frame is an allocation that goes nowhere.
    Spilled(Vec<u8>),
}

// SAFETY: the only reason this is not automatic is the raw pointer, and it
// names memory this value alone may touch -- `reserve` granted the slot
// exclusively and no other `LinkRxFrame`, and no accessor on the table, can
// reach those bytes until `Drop` returns the handle. The `Arc<NodeTable>` keeps
// the boxed storage alive and at its address for at least as long as the
// pointer, so moving the value between threads moves an exclusive, live
// reference and nothing else. `Sync` is deliberately NOT claimed: sharing `&`
// would say two threads may read the slot at once, which this type has no
// caller for.
unsafe impl Send for LinkRxFrame {}

impl LinkRxFrame {
    fn spilled(len: usize) -> Self {
        Self {
            len,
            storage: Storage::Spilled(vec![0u8; len]),
        }
    }

    /// Whether this frame's bytes live in a pool slot rather than in an
    /// allocation of its own.
    ///
    /// Exposed because the difference is the whole claim of this module and a
    /// caller that cannot ask it cannot report it — `crate::poll_framed`
    /// behaves identically either way, which is the seam working and also what
    /// makes the distinction invisible without this.
    pub fn is_pooled(&self) -> bool {
        matches!(self.storage, Storage::Slot { .. })
    }
}

impl AsRef<[u8]> for LinkRxFrame {
    fn as_ref(&self) -> &[u8] {
        match &self.storage {
            // SAFETY: see the `Send` impl -- `data` is the first byte of a slot
            // this value holds exclusively, `len <= SLOT_SIZE` is checked in
            // `take`, and `home` keeps the storage alive and unmoved.
            Storage::Slot { data, .. } => unsafe { std::slice::from_raw_parts(*data, self.len) },
            Storage::Spilled(bytes) => bytes,
        }
    }
}

impl AsMut<[u8]> for LinkRxFrame {
    fn as_mut(&mut self) -> &mut [u8] {
        let len = self.len;
        match &mut self.storage {
            // SAFETY: as above, and `&mut self` is what makes the exclusive
            // reference this hands out sound rather than merely unique.
            Storage::Slot { data, .. } => unsafe { std::slice::from_raw_parts_mut(*data, len) },
            Storage::Spilled(bytes) => bytes,
        }
    }
}

impl Drop for LinkRxFrame {
    fn drop(&mut self) {
        let Storage::Slot { held, home, .. } = &mut self.storage else {
            return;
        };
        let Some(held) = held.take() else {
            return;
        };
        // A poisoned lock forfeits this slot, and that is the honest arm rather
        // than an `unwrap`: the only code that holds this lock does freelist
        // bookkeeping and cannot panic, so poisoning means a thread died
        // somewhere this destructor cannot repair. Forfeiting costs one of
        // SLOT_COUNT slots; panicking in a destructor costs the process.
        if let Ok(mut guard) = home.slots.lock() {
            let slots: &mut SessionRxPoolAp = &mut guard;
            slots.release(held);
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::AtomicBool;
    use std::time::Duration;

    use tokio::io::AsyncWriteExt;

    use super::{LinkRxArena, LinkRxFrame};
    use crate::frame_arena::{FrameArena, HeapArena};
    use crate::session_rx_pool_ap::{SlotState, SLOT_COUNT};
    use crate::stream_link::StreamReadDriver;
    use crate::{poll_framed, LinkDriver, LinkEvent, ReadState};

    // Every test here builds a PRIVATE table (`LinkRxArena::new`) rather than
    // the node's, and that is not fastidiousness: `node()` is one table for the
    // whole process, libtest runs these threads in parallel, and a test that
    // asserted on the node table's free count would be measuring whatever else
    // the suite was receiving at the time.
    //
    // The two MID-READ tests drive a `tokio::io::duplex` rather than a `&[u8]`,
    // and that is load-bearing: a slice reader answers `Ok(0)` once it is
    // exhausted, which the `Payload` arm reads as a truncated frame -- it
    // returns `Lost { PeerClosed }` and resets to `Idle`, dropping the very
    // buffer the assertion is about. A duplex whose peer is still alive PARKS
    // instead, which is the state a link mid-frame is actually in. MEASURED:
    // the first draft used a slice and the frame was gone before the assert.

    /// THE SELECTION IS THE PRODUCTION ONE, and rustc is what says so.
    ///
    /// `StreamReadDriver::new` and `TcpDriver::from_stream` both build their
    /// arena from `frame_arena::link_arena()`, whose type is
    /// `frame_arena::LinkArena`. This signature compiles only while that alias
    /// IS this module's arena in a `runtime-zero-copy` build, which is the one
    /// step between "the arena fills slots" (the tests below) and "a production
    /// link fills slots". A comment saying it would be a claim; a signature
    /// saying it is a binding.
    #[allow(dead_code)]
    fn the_selected_link_arena_is_this_table(
        selected: crate::frame_arena::LinkArena,
    ) -> LinkRxArena {
        selected
    }

    /// One universal-prefix frame on the wire.
    fn framed(payload: &[u8]) -> Vec<u8> {
        let mut wire = (payload.len() as u16).to_le_bytes().to_vec();
        wire.extend_from_slice(payload);
        wire
    }

    /// THE WITNESS: the bytes a framing read lands are IN a table slot.
    ///
    /// ⚠ The address is the POOL's answer, not this test's arithmetic —
    /// `SessionRxPoolAp::slot_index_of_ptr` is what adjudicates, so a frame
    /// that merely happened to sit where the test predicted cannot pass. And
    /// it has to be an address: asserting on the bytes, or on the length,
    /// passes just as well when the arena hands out a copy, which is exactly
    /// what the two arenas this one joins do.
    ///
    /// The frame is observed MID-READ because that is the only moment it
    /// exists: `poll_framed` reads a completed frame in place and drops the
    /// buffer as it resets, so a test that waited for `LinkEvent::Rx` would be
    /// holding the copy `RxFrame` owns and the slot would already be home.
    #[tokio::test]
    async fn a_framing_read_fills_a_slot_of_the_table_it_was_given() {
        let mut arena = LinkRxArena::new();
        let mut st: ReadState<LinkRxFrame> = ReadState::Idle;

        // A prefix that promises eight bytes, followed by three of them: the
        // loop sizes its frame off the prefix and then parks awaiting the rest.
        let (mut peer, mut src) = tokio::io::duplex(64);
        peer.write_all(&[8u8, 0, 0xA1, 0xA2, 0xA3])
            .await
            .expect("duplex write");
        let _ = tokio::time::timeout(
            Duration::from_millis(100),
            poll_framed(&mut st, &mut src, false, &mut arena),
        )
        .await;

        let ReadState::Payload { frame, offset, .. } = &st else {
            panic!("the read parks mid-frame holding its buffer");
        };
        assert_eq!(*offset, 5, "prefix plus the three payload bytes that came");
        assert!(
            frame.is_pooled(),
            "the arena served this frame from the table"
        );

        let idx = arena
            .slot_of(frame.as_ref().as_ptr())
            .expect("the frame's bytes ARE a slot of this table, by the pool's own answer");
        assert_eq!(
            arena.slot_state(idx),
            Some(SlotState::CpuMut),
            "the emit's lifecycle records the slot as checked out for CPU writing"
        );
        assert_eq!(
            arena.free_slots(),
            SLOT_COUNT - 1,
            "a slot being filled is gone from the freelist"
        );
        assert_eq!(
            &frame.as_ref()[2..5],
            &[0xA1, 0xA2, 0xA3],
            "and the bytes the socket delivered are in it"
        );
    }

    /// The slot goes home when the frame is done, which is what keeps a link
    /// that reads forever from draining the table.
    #[tokio::test]
    async fn a_completed_frame_returns_its_slot() {
        let mut arena = LinkRxArena::new();
        let mut st: ReadState<LinkRxFrame> = ReadState::Idle;
        let wire = framed(b"pool-routed");
        let mut src = &wire[..];

        let event = poll_framed(&mut st, &mut src, false, &mut arena).await;
        let LinkEvent::Rx(rx) = event else {
            panic!("a complete frame is an Rx");
        };
        assert_eq!(&rx.bytes[..], b"pool-routed");
        assert_eq!(
            arena.free_slots(),
            SLOT_COUNT,
            "the frame is done, so its slot is back on the freelist"
        );
    }

    /// The two arenas reassemble the same bytes — the property that lets this
    /// one be selected without reading every consumer.
    ///
    /// A control in its own right: it is green when the seam is a pure
    /// extension and red the moment the pooled arm changes what the loop
    /// SEES, as opposed to where the bytes live.
    #[tokio::test]
    async fn the_pooled_arena_delivers_what_the_heap_arena_delivers() {
        let wire = framed(b"the same bytes either way");

        let mut heap_state: ReadState<Vec<u8>> = ReadState::Idle;
        let mut heap_src = &wire[..];
        let heap = poll_framed(&mut heap_state, &mut heap_src, false, &mut HeapArena).await;

        let mut pooled_arena = LinkRxArena::new();
        let mut pooled_state: ReadState<LinkRxFrame> = ReadState::Idle;
        let mut pooled_src = &wire[..];
        let pooled =
            poll_framed(&mut pooled_state, &mut pooled_src, false, &mut pooled_arena).await;

        let (LinkEvent::Rx(heap), LinkEvent::Rx(pooled)) = (heap, pooled) else {
            panic!("both arenas complete the frame");
        };
        assert_eq!(heap.bytes, pooled.bytes);
    }

    /// An exhausted table SERVES the frame rather than refusing it.
    ///
    /// `RxSlots::reserve` documents `None` as back-pressure, and this is the
    /// one caller that cannot apply any: the peer's bytes are already in the
    /// socket. Upstream reaches the same arm from the other side —
    /// `pool.try_take().unwrap_or_else(|| pool.alloc())`.
    #[test]
    fn an_exhausted_table_spills_instead_of_refusing() {
        let mut arena = LinkRxArena::new();
        let held: Vec<LinkRxFrame> = (0..SLOT_COUNT).map(|_| arena.take(16)).collect();
        assert_eq!(arena.free_slots(), 0);
        assert!(held.iter().all(|f| f.is_pooled()));

        let mut spilled = arena.take(16);
        assert!(!spilled.is_pooled(), "the table had nothing left to give");
        assert!(
            arena.slot_of(spilled.as_ref().as_ptr()).is_none(),
            "and the spilled frame is not at any slot's address"
        );
        spilled.as_mut()[0] = 0x7E;
        assert_eq!(spilled.as_ref()[0], 0x7E, "it is still a usable frame");

        drop(spilled);
        assert_eq!(
            arena.free_slots(),
            0,
            "a spilled frame owns no slot, so dropping it returns none"
        );
        drop(held);
        assert_eq!(arena.free_slots(), SLOT_COUNT);
    }

    /// THE WIRING WITNESS: a PRODUCTION read half — the type every `wire_*`
    /// site builds — draws its frames from the table.
    ///
    /// The test above proves the arena puts bytes in a slot; this one proves
    /// the driver is the thing asking. Between them sits the claim
    /// `runtime-zero-copy`'s residual makes, and neither half states it alone.
    #[tokio::test]
    async fn a_production_read_half_draws_its_frames_from_the_table() {
        let arena = LinkRxArena::new();
        let (mut peer, link) = tokio::io::duplex(64);
        let mut driver = StreamReadDriver::with_arena(
            link,
            std::sync::Arc::new(AtomicBool::new(false)),
            arena.clone(),
        );

        // Same shape as the address witness: a prefix promising more than the
        // peer sends, so the driver parks holding the frame.
        peer.write_all(&[8u8, 0, 0xB1]).await.expect("duplex write");
        let _ = tokio::time::timeout(Duration::from_millis(100), driver.poll_event()).await;

        assert_eq!(
            arena.free_slots(),
            SLOT_COUNT - 1,
            "the read half's in-flight frame is a slot of the table it was given"
        );

        drop(driver);
        assert_eq!(
            arena.free_slots(),
            SLOT_COUNT,
            "and the slot goes home when the driver does"
        );
    }
}
