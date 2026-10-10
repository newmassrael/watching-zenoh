// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! ARCHITECTURE section 9.1 on the AP stream links and the serial link: the
//! TRANSMIT POOL a link's outbound frames live in, and the generated lifecycle
//! that governs each slot. (The serial link writes its COBS frames into the same
//! slots, back to back; a COBS frame ends at its `0x00`, so the run is the wire.)
//!
//! ## What this replaces
//!
//! The stream write half used to lend the session an owned vector and hand the
//! filled vector to its writer task by ownership; the writer gave each written
//! vector back to a spare list of at most four buffers of at most 16 KiB. So a
//! steady state of small frames allocated nothing, and a burst past the fourth
//! buffer, or any frame past 16 KiB, allocated a vector per frame, and the
//! generated pool's transmit lifecycle (`sources/network/session_tx_pool_ap.scxml`)
//! governed none of it. Under `runtime-zero-copy` a stream link's writer queue
//! owns one instance of that pool and every outbound byte lies in one of its
//! slots, from the lend to the end of the write.
//!
//! | what happens to the slot | edge of the generated pool |
//! |---|---|
//! | a lane needs room for a frame and has none | `pool_acquire_for_encode` (free to cpu-mut) |
//! | frames are encoded into it (a lend) or copied in (the byte door) | none: the slot stays cpu-mut while its lane may still append to it |
//! | the writer takes it off its lane | `link_arm_tx` (cpu-mut to dma-armed-tx) |
//! | the writer begins the write | `dma_start_tx` (to dma-busy-tx) |
//! | the write ended, written or failed | `tx_complete` (dma-busy-tx to free) |
//! | taken but never started (the writer stopped first) | `un_arm_tx` then `pool_return` |
//! | never taken (the queue was dropped, or a lend was given back empty) | `pool_return` (cpu-mut to free) |
//!
//! On this row of ARCHITECTURE section 9.5 the bus master is the kernel's copy out
//! of the slot into the socket, which the writer task's `write_all` issues, so
//! "start" and "complete" bracket that call; the edge actions are the no-op the
//! epoll row names. A failed write has ended too (nothing reads the slot after
//! the call returns), which is why it takes the completion edge and not the
//! un-arm one: the generated lifecycle has no other edge out of dma-busy-tx.
//!
//! ## Why a frame is never too large for a slot
//!
//! The slot size is the largest frame a stream link can be handed, prefix
//! included (the const assertion below fails the build otherwise), so a frame
//! larger than a slot does not exist and there is no fallback to write down. A
//! slot holds frames back to back, appended while it is its lane's newest and
//! the writer has not taken it, which is what keeps sixteen slots enough for the
//! byte bound the queue's lanes already apply (the derivation is in the scxml).
//!
//! ## The accounting
//!
//! [`TxPoolStats`] counts each edge as it is
//! taken, and the pool's own `free_count` and `slot_state` are what the tests
//! adjudicate against, never this module's bookkeeping alone.

use crate::session_tx_pool_ap::{CpuMut, SessionTxPoolAp, Slot, SlotState, SLOT_COUNT, SLOT_SIZE};

/// The largest frame a stream write half can hand its writer: the 4-byte
/// lowlatency prefix and a `u16::MAX` payload.
pub const MAX_STREAM_FRAME: usize = 4 + u16::MAX as usize;

// THE DIMENSION THIS POOL EXISTS FOR, enforced at COMPILE time, as
// `link_rx_pool` enforces it for the receive table: a slot that could not hold
// the largest frame would turn that frame back into a heap vector.
const _: () = assert!(
    SLOT_SIZE >= MAX_STREAM_FRAME,
    "a stream transmit slot must hold prefix + u16::MAX payload"
);

/// What a link's transmit pool has done since it was built. Each slot acquired
/// is counted once in `acquired`, and then once in exactly one of `returned`
/// (never armed), `completed` (its write ended) or `unarmed` (armed, never
/// started) when it goes home.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct TxPoolStats {
    /// Slots taken off the freelist for a lane.
    pub acquired: u64,
    /// Frames encoded into a slot by a lend and committed.
    pub lent: u64,
    /// Frames copied into a slot by the byte door.
    pub copied: u64,
    /// Slots the writer took off a lane (cpu-mut to dma-armed-tx).
    pub armed: u64,
    /// Writes the writer began from a slot (to dma-busy-tx).
    pub started: u64,
    /// Writes that ended, written or failed (dma-busy-tx to free).
    pub completed: u64,
    /// Of those, the writes that failed or were abandoned mid-write.
    pub failed: u64,
    /// Slots armed and never started, un-armed and returned.
    pub unarmed: u64,
    /// Slots returned without being armed: a lend given back empty, or a lane
    /// dropped with its queue.
    pub returned: u64,
}

/// One link's transmit pool: the generated slot table and its counters.
pub struct TxPool {
    slots: Box<SessionTxPoolAp>,
    stats: TxPoolStats,
}

impl TxPool {
    /// A pool of free slots, built without a stack temporary.
    pub fn new() -> Self {
        Self {
            slots: heap_pool(),
            stats: TxPoolStats::default(),
        }
    }

    /// Slots on the freelist now, by the pool's own count.
    pub fn free_count(&self) -> usize {
        self.slots.free_count()
    }

    /// The lifecycle state the emit records for `idx`.
    pub fn slot_state(&self, idx: usize) -> Option<SlotState> {
        self.slots.slot_state(idx)
    }

    /// What this pool has done.
    pub fn stats(&self) -> TxPoolStats {
        self.stats
    }

    /// A free slot for a lane to write frames into, or `None` when every slot is
    /// out. Free to cpu-mut.
    pub fn acquire(&mut self) -> Option<Slot<CpuMut>> {
        let slot = self.slots.pool_acquire_for_encode()?;
        self.stats.acquired += 1;
        Some(slot)
    }

    /// The first byte of a slot the caller holds for writing.
    ///
    /// Stable for the life of the pool: the table is boxed and the box does not
    /// move, so the address stays valid after the borrow this takes has ended,
    /// for as long as the caller keeps the handle.
    pub fn base_of(&mut self, slot: &mut Slot<CpuMut>) -> *mut u8 {
        slot.write(&mut self.slots).as_mut_ptr()
    }

    /// Count a frame encoded into a slot by a lend.
    pub fn note_lent(&mut self) {
        self.stats.lent += 1;
    }

    /// Count a frame copied into a slot by the byte door.
    pub fn note_copied(&mut self) {
        self.stats.copied += 1;
    }

    /// Give back a slot that was never armed. Cpu-mut to free.
    pub fn give_back(&mut self, slot: Slot<CpuMut>) {
        slot.pool_return(&mut self.slots);
        self.stats.returned += 1;
    }

    /// The writer takes `slot` off its lane: no sender may write it again.
    /// Cpu-mut to dma-armed-tx. Returns the slot's index and its first byte, by
    /// the pool's own answer for an armed slot.
    pub fn arm(&mut self, slot: Slot<CpuMut>) -> (usize, *const u8) {
        let idx = slot.idx();
        slot.link_arm_tx(&mut self.slots);
        self.stats.armed += 1;
        let base = self
            .slots
            .dma_armed_tx_ptr(idx)
            .expect("a slot just armed is in dma-armed-tx");
        (idx, base)
    }

    /// The writer begins writing armed slot `idx`. Dma-armed-tx to dma-busy-tx.
    ///
    /// `false` when the slot is not armed, which is a defect of the caller: the
    /// generated edge refuses it and so does this.
    pub fn start(&mut self, idx: usize) -> bool {
        // SAFETY: the "peripheral" on this row is the writer's own write of the
        // slot's bytes, which the caller is about to begin; the pool refuses a
        // slot that is not armed, so no other slot moves.
        let started = unsafe { self.slots.dma_start_tx(idx) };
        if started {
            self.stats.started += 1;
        }
        started
    }

    /// The write of busy slot `idx` has ended, `written` or not. Dma-busy-tx to
    /// free. `false` when the slot is not busy (a second completion, or a slot
    /// never started), which the generated edge refuses.
    pub fn complete(&mut self, idx: usize, written: bool) -> bool {
        // SAFETY: the write the slot was started for has returned, so nothing
        // reads the slot any more; the pool refuses a slot that is not busy.
        let done = unsafe { self.slots.tx_complete(idx) };
        if done {
            self.stats.completed += 1;
            if !written {
                self.stats.failed += 1;
            }
        }
        done
    }

    /// Armed slot `idx` will never be started: un-arm it and give it back.
    /// Dma-armed-tx to cpu-mut to free. `false` when it was not armed.
    pub fn unarm(&mut self, idx: usize) -> bool {
        // SAFETY: the slot was armed and its write never began, so nothing reads
        // it; the pool refuses a slot that is not armed.
        match unsafe { self.slots.un_arm_tx(idx) } {
            Some(slot) => {
                slot.pool_return(&mut self.slots);
                self.stats.unarmed += 1;
                true
            }
            None => false,
        }
    }
}

impl Default for TxPool {
    fn default() -> Self {
        Self::new()
    }
}

/// The pool, allocated ZEROED and owned through a box, so no temporary of its
/// ~1 MiB is ever put on the stack. `link_rx_pool::heap_pool` gives the full
/// argument; the zero pattern is the pool's initial state because every byte of
/// a slot is a plain byte and `SlotState::Free` is the state 0.
fn heap_pool() -> Box<SessionTxPoolAp> {
    const _: () = assert!(
        SlotState::Free as u8 == 0,
        "a pool of zeroes is a pool of free slots only while free is the state 0"
    );
    // SAFETY: `alloc_zeroed` returns a block of `Layout::new::<T>()`, sized and
    // aligned for it, and the all-zero pattern is a valid `SessionTxPoolAp` (see
    // above), so the block holds an initialised value before `from_raw` owns it.
    let pool = unsafe {
        let layout = core::alloc::Layout::new::<SessionTxPoolAp>();
        let raw = std::alloc::alloc_zeroed(layout) as *mut SessionTxPoolAp;
        if raw.is_null() {
            std::alloc::handle_alloc_error(layout);
        }
        Box::from_raw(raw)
    };
    debug_assert_eq!(
        pool.free_count(),
        SLOT_COUNT,
        "the zero pattern is no longer the pool's initial state"
    );
    pool
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The largest stream frame is writable end to end in one slot, which is
    /// what makes the const assertion a live property rather than arithmetic.
    #[test]
    fn the_largest_stream_frame_fits_one_slot() {
        let mut pool = TxPool::new();
        let mut slot = pool.acquire().expect("a fresh pool has slots");
        let base = pool.base_of(&mut slot);
        // SAFETY: `base` is the first byte of a slot of SLOT_SIZE bytes this test
        // holds for writing, and MAX_STREAM_FRAME <= SLOT_SIZE.
        unsafe { base.add(MAX_STREAM_FRAME - 1).write(0xAB) };
        pool.give_back(slot);
        assert_eq!(pool.free_count(), SLOT_COUNT);
    }

    /// The writer's walk, read off the pool's own states: acquired, armed,
    /// started, complete, and free again.
    #[test]
    fn a_written_slot_walks_the_transmit_arms_and_goes_home() {
        let mut pool = TxPool::new();
        let slot = pool.acquire().expect("free");
        let idx = slot.idx();
        assert_eq!(pool.slot_state(idx), Some(SlotState::CpuMut));
        let (armed, base) = pool.arm(slot);
        assert_eq!(armed, idx);
        assert!(!base.is_null());
        assert_eq!(pool.slot_state(idx), Some(SlotState::DmaArmedTx));
        assert!(pool.start(idx));
        assert_eq!(pool.slot_state(idx), Some(SlotState::DmaBusyTx));
        assert!(pool.complete(idx, true));
        assert_eq!(pool.slot_state(idx), Some(SlotState::Free));
        assert_eq!(pool.free_count(), SLOT_COUNT);
        let stats = pool.stats();
        assert_eq!(
            (stats.acquired, stats.armed, stats.started, stats.completed),
            (1, 1, 1, 1)
        );
    }

    /// A second completion is refused by the generated edge, so a writer that
    /// completed twice cannot free a slot a later frame is being written into.
    #[test]
    fn a_second_completion_is_refused() {
        let mut pool = TxPool::new();
        let slot = pool.acquire().expect("free");
        let (idx, _) = pool.arm(slot);
        assert!(pool.start(idx));
        assert!(pool.complete(idx, true));
        let next = pool.acquire().expect("free");
        assert_eq!(next.idx(), idx, "the freed slot is the next one taken");
        assert!(
            !pool.complete(idx, true),
            "completing again must not free the slot the next frame holds"
        );
        assert_eq!(pool.slot_state(idx), Some(SlotState::CpuMut));
        pool.give_back(next);
    }

    /// A write cannot start from a slot that was never armed: skipping the arm
    /// is refused, and the slot stays the sender's.
    #[test]
    fn a_start_without_an_arm_is_refused() {
        let mut pool = TxPool::new();
        let slot = pool.acquire().expect("free");
        let idx = slot.idx();
        assert!(!pool.start(idx), "cpu-mut has no edge to dma-busy-tx");
        assert_eq!(pool.slot_state(idx), Some(SlotState::CpuMut));
        pool.give_back(slot);
        assert_eq!(pool.free_count(), SLOT_COUNT);
    }

    /// An armed slot whose write never began goes home through un-arm, and only
    /// an armed one does.
    #[test]
    fn an_armed_slot_never_started_is_unarmed_and_returned() {
        let mut pool = TxPool::new();
        let slot = pool.acquire().expect("free");
        let (idx, _) = pool.arm(slot);
        assert!(pool.unarm(idx));
        assert_eq!(pool.slot_state(idx), Some(SlotState::Free));
        assert!(!pool.unarm(idx), "a free slot is not armed");
        assert_eq!(pool.stats().unarmed, 1);
    }

    /// A fresh pool is all free by the emit's own count, and the zero pattern
    /// it was built from is the free state of every slot.
    #[test]
    fn a_fresh_pool_is_all_free() {
        let pool = TxPool::new();
        assert_eq!(pool.free_count(), SLOT_COUNT);
        for idx in 0..SLOT_COUNT {
            assert_eq!(pool.slot_state(idx), Some(SlotState::Free));
        }
    }

    /// Exhaustion is a refusal, not an error and not an allocation: past
    /// SLOT_COUNT the pool answers `None`, and a slot given back is taken again.
    #[test]
    fn an_exhausted_pool_refuses_and_recovers() {
        let mut pool = TxPool::new();
        let mut held = Vec::new();
        for _ in 0..SLOT_COUNT {
            held.push(pool.acquire().expect("within SLOT_COUNT"));
        }
        assert!(pool.acquire().is_none());
        pool.give_back(held.pop().expect("held"));
        held.push(pool.acquire().expect("one came back"));
        for slot in held {
            pool.give_back(slot);
        }
        assert_eq!(pool.free_count(), SLOT_COUNT);
    }
}

/// The pool as the pooled writer queue walks it: what a sender, the writer and
/// teardown each do to a slot, read off the pool's own count and states.
///
/// In this module rather than `writer_queue`'s so the lane that runs the pool's
/// tests by module path (`--lib link_tx_`) runs these too.
#[cfg(test)]
mod queue {
    use std::time::Duration;

    use tokio::io::AsyncWriteExt;
    use wz_session_core::link::RoomWait;
    use wz_session_core::qos::Priority;

    use crate::session_tx_pool_ap::{SlotState, SLOT_COUNT, SLOT_SIZE};
    use crate::writer_queue::{
        outbound_channel_pooled, OutboundTx, PooledSendError, Room, WriterHandle,
    };

    const P: Priority = Priority::DEFAULT;

    fn free(tx: &OutboundTx) -> usize {
        tx.tx_pool_stats().expect("a pooled queue").1
    }

    /// Frames copied in while the writer is not looking pack into ONE slot, and
    /// the writer is handed them as one run of bytes: the concatenation, which on
    /// a byte stream is the wire.
    #[test]
    fn frames_queued_together_share_one_slot_and_leave_as_one_run() {
        let (tx, mut rx) = outbound_channel_pooled();
        tx.send_framed(P, &[1, 0], b"a").expect("queued");
        tx.send_framed(P, &[2, 0], b"bc").expect("queued");
        tx.send_framed(P, &[3, 0], b"def").expect("queued");
        assert_eq!(tx.tx_pool_stats().expect("pooled").0.acquired, 1);
        let (_, wire) = rx.try_recv_wire_tagged().expect("one run");
        assert!(wire.is_pooled());
        assert_eq!(wire, [1, 0, b'a', 2, 0, b'b', b'c', 3, 0, b'd', b'e', b'f']);
        assert!(rx.try_recv_wire_tagged().is_none(), "and nothing else");
        drop(wire);
        assert_eq!(free(&tx), SLOT_COUNT);
    }

    /// The writer's walk on the pool's own states: a taken slot is ARMED, a
    /// started one BUSY, and a written one FREE again; every slot comes home.
    #[test]
    fn a_taken_slot_is_armed_then_busy_then_free() {
        let (tx, mut rx) = outbound_channel_pooled();
        tx.send_framed(P, &[1, 0], b"x").expect("queued");
        let (_, mut wire) = rx.try_recv_wire_tagged().expect("taken");
        let idx = wire.slot_index().expect("a slot");
        assert_eq!(tx.tx_slot_state(idx), Some(SlotState::DmaArmedTx));
        wire.begin_write();
        assert_eq!(tx.tx_slot_state(idx), Some(SlotState::DmaBusyTx));
        drop(wire);
        assert_eq!(tx.tx_slot_state(idx), Some(SlotState::Free));
        let (stats, free_now) = tx.tx_pool_stats().expect("pooled");
        assert_eq!(free_now, SLOT_COUNT);
        assert_eq!(
            (stats.acquired, stats.armed, stats.started, stats.completed),
            (1, 1, 1, 1)
        );
    }

    /// A slot taken and never started (the writer stopped before writing it)
    /// goes home through un-arm, not through the completion edge.
    #[test]
    fn a_slot_taken_and_never_started_is_unarmed() {
        let (tx, mut rx) = outbound_channel_pooled();
        tx.send_framed(P, &[1, 0], b"x").expect("queued");
        let (_, wire) = rx.try_recv_wire_tagged().expect("taken");
        drop(wire);
        let (stats, free_now) = tx.tx_pool_stats().expect("pooled");
        assert_eq!(
            (stats.unarmed, stats.completed, free_now),
            (1, 0, SLOT_COUNT)
        );
    }

    /// Through the real writer task: written slots come home through the
    /// completion edge counted as written, and the peer reads the frames.
    #[cfg(feature = "transport-link-tcp")]
    #[tokio::test]
    async fn the_writer_task_completes_every_slot_it_writes() {
        use tokio::io::AsyncReadExt;
        let (tx, rx) = outbound_channel_pooled();
        let (near, mut far) = tokio::io::duplex(1 << 16);
        let writer = WriterHandle::spawn_on(tokio::runtime::Handle::current(), rx, |queue| {
            crate::stream_link::writer_task(near, queue)
        });
        for round in 0..5u8 {
            tx.send_framed(P, &[1, 0], &[round]).expect("queued");
            let mut got = [0u8; 3];
            far.read_exact(&mut got).await.expect("the frame");
            assert_eq!(got, [1, 0, round]);
        }
        writer.drain().await;
        let mut tail = Vec::new();
        far.read_to_end(&mut tail).await.expect("eof");
        assert!(tail.is_empty());
        // Every slot the writer took, it started and completed as written.
        let (stats, free_now) = tx.tx_pool_stats().expect("pooled");
        assert_eq!(free_now, SLOT_COUNT);
        assert_eq!(stats.armed, stats.started);
        assert_eq!(stats.started, stats.completed);
        assert_eq!(stats.failed, 0);
        assert!(stats.completed >= 1);
    }

    /// A write that FAILS has ended too: its slot goes home through the
    /// completion edge, counted as failed, and nothing is left out.
    #[cfg(feature = "transport-link-tcp")]
    #[tokio::test]
    async fn a_failed_write_returns_its_slot() {
        struct Broken;
        impl tokio::io::AsyncWrite for Broken {
            fn poll_write(
                self: std::pin::Pin<&mut Self>,
                _cx: &mut std::task::Context<'_>,
                _buf: &[u8],
            ) -> std::task::Poll<std::io::Result<usize>> {
                std::task::Poll::Ready(Err(std::io::ErrorKind::BrokenPipe.into()))
            }
            fn poll_flush(
                self: std::pin::Pin<&mut Self>,
                _cx: &mut std::task::Context<'_>,
            ) -> std::task::Poll<std::io::Result<()>> {
                std::task::Poll::Ready(Ok(()))
            }
            fn poll_shutdown(
                self: std::pin::Pin<&mut Self>,
                _cx: &mut std::task::Context<'_>,
            ) -> std::task::Poll<std::io::Result<()>> {
                std::task::Poll::Ready(Ok(()))
            }
        }
        let (tx, rx) = outbound_channel_pooled();
        tx.send_framed(P, &[1, 0], b"x").expect("queued");
        let writer = WriterHandle::spawn_on(tokio::runtime::Handle::current(), rx, |queue| {
            crate::stream_link::writer_task(Broken, queue)
        });
        writer
            .into_join()
            .await
            .expect("the writer ends on the error");
        let (stats, free_now) = tx.tx_pool_stats().expect("pooled");
        assert_eq!(
            (stats.started, stats.completed, stats.failed, free_now),
            (1, 1, 1, SLOT_COUNT)
        );
        // And a frame sent after the writer has gone is refused, holding nothing.
        assert_eq!(
            tx.send_framed(P, &[1, 0], b"y"),
            Err(PooledSendError::Closed)
        );
        assert_eq!(free(&tx), SLOT_COUNT);
    }

    /// A CLOSING connection returns its slots: when the receiving half is
    /// dropped with frames still queued, nothing will write them, and every slot
    /// they held is free at once, though a sender still holds the queue.
    #[test]
    fn dropping_the_receiver_returns_every_queued_slot() {
        let (tx, rx) = outbound_channel_pooled();
        let big = vec![0x5Au8; SLOT_SIZE / 2 + 1];
        for _ in 0..3 {
            tx.send_framed(P, &[], &big).expect("queued");
        }
        assert_eq!(free(&tx), SLOT_COUNT - 3, "three frames that do not pack");
        drop(rx);
        let (stats, free_now) = tx.tx_pool_stats().expect("pooled");
        assert_eq!((stats.returned, free_now), (3, SLOT_COUNT));
    }

    /// A lend in progress when the receiver goes keeps its slot until the lend is
    /// settled, and then the slot goes home whatever the lend says.
    #[test]
    fn a_lend_open_when_the_receiver_goes_is_returned_when_settled() {
        let (tx, rx) = outbound_channel_pooled();
        let lend = tx.lend(P, 16).expect("lent");
        drop(rx);
        assert_eq!(free(&tx), SLOT_COUNT - 1, "the lend's slot is still lent");
        assert_eq!(tx.commit(lend, 4), Err(PooledSendError::Closed));
        assert_eq!(free(&tx), SLOT_COUNT);
    }

    /// A lend into a slot that already holds frames keeps the writer off that
    /// slot until it is committed, and the committed frame follows the earlier
    /// ones in the same run.
    #[test]
    fn a_lend_behind_queued_frames_holds_the_writer_until_committed() {
        let (tx, mut rx) = outbound_channel_pooled();
        tx.send_framed(P, &[1, 0], b"a").expect("queued");
        let lend = tx.lend(P, 8).expect("lent behind it");
        assert!(
            rx.try_recv_wire_tagged().is_none(),
            "the slot is being written by the lend"
        );
        // SAFETY: the lend is this test's, and 3 <= its capacity.
        unsafe { std::ptr::copy_nonoverlapping([1u8, 0, b'b'].as_ptr(), lend.base(), 3) };
        tx.commit(lend, 3).expect("committed");
        let (_, wire) = rx.try_recv_wire_tagged().expect("now taken");
        assert_eq!(wire, [1, 0, b'a', 1, 0, b'b']);
        assert_eq!(tx.tx_pool_stats().expect("pooled").0.acquired, 1);
    }

    /// A lend into a FRESH slot holds no frame yet, so frames queued after it
    /// leave first; the lent frame leaves when it is committed.
    #[test]
    fn an_empty_lend_does_not_hold_back_the_frames_behind_it() {
        let (tx, mut rx) = outbound_channel_pooled();
        let lend = tx.lend(P, 8).expect("lent");
        tx.send_framed(P, &[1, 0], b"z")
            .expect("queued after the lend");
        let (_, first) = rx.try_recv_wire_tagged().expect("the byte frame");
        assert_eq!(first, [1, 0, b'z']);
        // SAFETY: the lend is this test's, and 3 <= its capacity.
        unsafe { std::ptr::copy_nonoverlapping([1u8, 0, b'y'].as_ptr(), lend.base(), 3) };
        tx.commit(lend, 3).expect("committed");
        let (_, second) = rx.try_recv_wire_tagged().expect("the lent frame");
        assert_eq!(second, [1, 0, b'y']);
    }

    /// A lend given back holds no frame: its slot goes home.
    #[test]
    fn an_aborted_lend_returns_its_slot() {
        let (tx, mut rx) = outbound_channel_pooled();
        let lend = tx.lend(P, 8).expect("lent");
        assert_eq!(free(&tx), SLOT_COUNT - 1);
        tx.abort_lend(lend);
        assert_eq!(free(&tx), SLOT_COUNT);
        assert!(rx.try_recv_wire_tagged().is_none(), "and nothing is queued");
    }

    /// A DRY pool is congestion: room is refused while every slot is out, and
    /// given again when one comes home. The byte bound is far from full, so the
    /// answer is the pool's.
    #[test]
    fn a_dry_pool_is_no_room_until_a_slot_comes_home() {
        let (tx, _rx) = outbound_channel_pooled();
        let lends: Vec<_> = (0..SLOT_COUNT)
            .map(|_| tx.lend(P, SLOT_SIZE).expect("a whole slot each"))
            .collect();
        assert_eq!(free(&tx), 0);
        let now = RoomWait::Block { wait_us: 0 };
        assert_eq!(tx.wait_for_room(P, now), Room::Congested);
        let mut lends = lends.into_iter();
        tx.abort_lend(lends.next().expect("one"));
        assert_eq!(tx.wait_for_room(P, now), Room::Free);
        for lend in lends {
            tx.abort_lend(lend);
        }
        assert_eq!(free(&tx), SLOT_COUNT);
    }

    /// Past the pool a frame does not allocate and is not lost: the byte door
    /// WAITS for the writer to free a slot, and is released by it; and a sender
    /// waiting when the queue closes is told so.
    #[test]
    fn a_sender_past_the_pool_waits_for_the_writer_and_is_released_by_close() {
        let (tx, mut rx) = outbound_channel_pooled();
        let big = vec![0xA5u8; SLOT_SIZE / 2 + 1];
        for _ in 0..SLOT_COUNT {
            tx.send_framed(P, &[], &big).expect("queued");
        }
        assert_eq!(free(&tx), 0);
        // The waiter reports through a channel read with a deadline, so a slot
        // that never comes home reds this test instead of hanging the lane.
        let spawn_waiter = |big: Vec<u8>| {
            let tx = tx.clone();
            let (done, outcome) = std::sync::mpsc::channel();
            std::thread::spawn(move || {
                let _ = done.send(tx.send_framed(P, &[], &big));
            });
            outcome
        };
        let bound = Duration::from_secs(10);
        let outcome = spawn_waiter(big.clone());
        assert!(
            outcome.recv_timeout(Duration::from_millis(30)).is_err(),
            "no slot: the sender waits"
        );
        let (_, wire) = rx.try_recv_wire_tagged().expect("the writer takes one");
        drop(wire);
        assert_eq!(
            outcome
                .recv_timeout(bound)
                .expect("released by the slot coming home"),
            Ok(())
        );

        let outcome = spawn_waiter(big);
        assert!(outcome.recv_timeout(Duration::from_millis(30)).is_err());
        rx.close();
        assert_eq!(
            outcome.recv_timeout(bound).expect("released by the close"),
            Err(PooledSendError::Closed)
        );
    }

    /// No stream frame is too large for a slot, and the queue refuses the one
    /// that would be rather than spilling it to the heap.
    #[test]
    fn the_largest_stream_frame_is_queued_and_a_larger_one_refused() {
        let (tx, mut rx) = outbound_channel_pooled();
        let payload = vec![7u8; u16::MAX as usize];
        tx.send_framed(P, &[0xFF, 0xFF, 0, 0], &payload)
            .expect("fits one slot");
        let (_, wire) = rx.try_recv_wire_tagged().expect("taken");
        assert_eq!(wire.len(), super::MAX_STREAM_FRAME);
        assert_eq!(
            tx.send_framed(P, &[], &vec![0u8; SLOT_SIZE + 1]),
            Err(PooledSendError::TooLarge)
        );
    }

    /// A frame the link encodes in place takes the bytes it wrote and no more,
    /// so the next frame packs behind it; an encoder that fails queues nothing
    /// and gives back the slot it was handed.
    #[test]
    fn a_link_encoded_frame_takes_what_it_wrote_and_a_failed_one_nothing() {
        let (tx, mut rx) = outbound_channel_pooled();
        tx.send_encoded(P, 1516, |dst| {
            dst[..3].copy_from_slice(b"abc");
            Some(3)
        })
        .expect("queued");
        tx.send_framed(P, &[], b"de").expect("packed behind it");
        assert_eq!(
            tx.send_encoded(P, 1516, |_| None),
            Err(PooledSendError::Unencodable)
        );
        let (_, wire) = rx.try_recv_wire_tagged().expect("one run");
        assert_eq!(wire, *b"abcde");
        drop(wire);
        assert_eq!(free(&tx), SLOT_COUNT);
        // A failing encoder handed a FRESH slot gives it back.
        assert_eq!(
            tx.send_encoded(P, 1516, |_| None),
            Err(PooledSendError::Unencodable)
        );
        assert_eq!(free(&tx), SLOT_COUNT);
        assert!(rx.try_recv_wire_tagged().is_none());
    }

    /// A heap queue is untouched by all of this: it lends nothing from a pool and
    /// reports no pool.
    #[tokio::test]
    async fn a_heap_queue_has_no_pool() {
        let (tx, mut rx) = crate::writer_queue::outbound_channel();
        assert!(!tx.is_pooled());
        assert!(tx.tx_pool_stats().is_none());
        assert!(tx.lend(P, 8).is_none());
        tx.send(P, vec![1, 2]).expect("queued");
        let wire = rx.recv_wire().await.expect("a frame");
        assert!(!wire.is_pooled());
        let mut sink = Vec::new();
        sink.write_all(&wire).await.expect("write");
        assert_eq!(sink, [1, 2]);
    }
}
