// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
#![cfg(feature = "codec-push")]

//! ARCHITECTURE section 9.1 on the session's own send path: a link that lends a
//! slot is handed the frame IN that slot, and a link that does not (or cannot)
//! is handed the same frame on the heap.
//!
//! The session is the production `SessionLinkActions`; the link is a fake that
//! records which of its two doors a frame came through (`tx_slot_send` for a
//! lent slot, `send_prioritized` for bytes) and keeps count of every slot it
//! lent against every slot that came back. What is pinned:
//!
//! * the lent frame is byte-for-byte the frame the heap path writes, so a link
//!   that opts in changes where the codec writes and nothing on the wire;
//! * the lend is the DEFAULT-OFF seam it claims to be: a link that lends
//!   nothing, or has no free slot, or whose slot is too small, gets the heap
//!   frame, never an error and never a lost frame;
//! * a frame past the MTU is fragmented from the heap, and the slot it had
//!   already been lent is given back;
//! * no path leaks a slot.

use std::cell::UnsafeCell;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use wz_runtime_tokio::runtime_impl::TokioTime;
use wz_runtime_tokio::session_glue::new_session_actions;
use wz_runtime_tokio_test_support::fixture_session_init_params;
use wz_session_core::link::{BoxedLinkDriver, LinkSendOutcome, TxSlot, TxSlotGrant};
use wz_session_core::qos::Priority;
use wz_session_core::reliability::Reliability;

/// One slot's memory. Shared between the fake link and the session's lease, one
/// party at a time: the link lends it and does not touch it until the slot is
/// sent or aborted, which is the contract `tx_slot_storage` states.
struct SlotMem(UnsafeCell<Box<[u8]>>);

// SAFETY: see the type's doc; the fake link upholds the same exclusivity a real
// one must, and the tests are single-threaded around each send.
unsafe impl Sync for SlotMem {}
unsafe impl Send for SlotMem {}

/// A link with a small pool of slots it may or may not lend.
struct LendingLink {
    /// `false` leaves every slot method at its default: the link of every
    /// driver that has not opted in.
    lends: bool,
    headroom: usize,
    slots: Vec<SlotMem>,
    taken: Mutex<Vec<bool>>,
    /// Frames that arrived as bytes, through `send_prioritized`.
    heap: Mutex<Vec<Vec<u8>>>,
    /// Frames that arrived as a lent slot: the bytes after the headroom.
    lent: Mutex<Vec<Vec<u8>>>,
    /// Every frame in arrival order, whichever door it came through (`true`
    /// for the slot door), so an order across the two doors can be read.
    doors: Mutex<Vec<(bool, Vec<u8>)>>,
    grants: AtomicUsize,
    aborts: AtomicUsize,
}

impl LendingLink {
    fn new(lends: bool, n_slots: usize, slot_len: usize, headroom: usize) -> Arc<Self> {
        Arc::new(Self {
            lends,
            headroom,
            slots: (0..n_slots)
                .map(|_| SlotMem(UnsafeCell::new(vec![0u8; slot_len].into_boxed_slice())))
                .collect(),
            taken: Mutex::new(vec![false; n_slots]),
            heap: Mutex::new(Vec::new()),
            lent: Mutex::new(Vec::new()),
            doors: Mutex::new(Vec::new()),
            grants: AtomicUsize::new(0),
            aborts: AtomicUsize::new(0),
        })
    }

    fn free(&self) -> usize {
        self.taken
            .lock()
            .expect("taken")
            .iter()
            .filter(|t| !**t)
            .count()
    }
    fn heap(&self) -> Vec<Vec<u8>> {
        self.heap.lock().expect("heap").clone()
    }
    fn lent(&self) -> Vec<Vec<u8>> {
        self.lent.lock().expect("lent").clone()
    }
    fn aborts(&self) -> usize {
        self.aborts.load(Ordering::SeqCst)
    }
    #[cfg(feature = "transport-batching")]
    fn doors(&self) -> Vec<(bool, Vec<u8>)> {
        self.doors.lock().expect("doors").clone()
    }
    /// The slot lifecycle balances and every slot is back: each slot granted
    /// was sent or aborted exactly once (`granted - aborted - sent` is what is
    /// still out, and that is what the pool misses), and nothing is still out.
    #[track_caller]
    fn assert_every_slot_home(&self) {
        let granted = self.grants.load(Ordering::SeqCst);
        let out = granted - self.aborts() - self.lent().len();
        assert_eq!(
            out,
            self.slots.len() - self.free(),
            "the lifecycle balances"
        );
        assert_eq!(out, 0, "and no slot is still lent");
    }
}

impl BoxedLinkDriver for LendingLink {
    fn send_blocking(&self, bytes: &[u8], _reliability: Reliability) -> LinkSendOutcome {
        self.heap.lock().expect("heap").push(bytes.to_vec());
        self.doors
            .lock()
            .expect("doors")
            .push((false, bytes.to_vec()));
        LinkSendOutcome::Sent
    }
    fn open_blocking(&self) {}
    fn close_blocking(&self) {}

    fn tx_slot_acquire(&self, _want: usize, _priority: Priority) -> Option<TxSlotGrant> {
        // `want` is a hint (the codec's worst case, far past any ordinary frame):
        // this link has one slot size and lends it whatever is asked, so a frame
        // that does not fit is found out by the encode, as it is on a real link.
        if !self.lends {
            return None;
        }
        let mut taken = self.taken.lock().expect("taken");
        let idx = taken.iter().position(|t| !*t)?;
        taken[idx] = true;
        self.grants.fetch_add(1, Ordering::SeqCst);
        Some(TxSlotGrant {
            slot: TxSlot(idx as u32),
            headroom: self.headroom,
        })
    }

    fn tx_slot_storage(&self, slot: TxSlot) -> (*mut u8, usize) {
        let mem = &self.slots[slot.0 as usize];
        // SAFETY: the slot was granted and neither sent nor aborted, so no one
        // else is touching it; the pointer and length are of the boxed slice.
        unsafe {
            let bytes = &mut *mem.0.get();
            (bytes.as_mut_ptr(), bytes.len())
        }
    }

    fn tx_slot_send(
        &self,
        slot: TxSlot,
        start: usize,
        len: usize,
        _reliability: Reliability,
        _priority: Priority,
    ) -> LinkSendOutcome {
        let idx = slot.0 as usize;
        // SAFETY: the session handed the slot over, so this is its only reader.
        let frame = unsafe { (&*self.slots[idx].0.get())[start..start + len].to_vec() };
        self.doors
            .lock()
            .expect("doors")
            .push((true, frame.clone()));
        self.lent.lock().expect("lent").push(frame);
        // The link has "written" the slot and returns it to its pool.
        self.taken.lock().expect("taken")[idx] = false;
        LinkSendOutcome::Sent
    }

    fn tx_slot_abort(&self, slot: TxSlot) {
        self.aborts.fetch_add(1, Ordering::SeqCst);
        self.taken.lock().expect("taken")[slot.0 as usize] = false;
    }
}

const SLOT_LEN: usize = 256;
const HEADROOM: usize = 4;

/// The frame the heap path writes for `payload`: the control every lent frame
/// is compared with.
fn heap_frame(payload: &[u8]) -> Vec<u8> {
    let link = LendingLink::new(false, 0, 0, 0);
    let actions = new_session_actions(link.clone(), params_with_sn_7(None), TokioTime::new());
    actions
        .send_push_literal("home/lent", payload, true)
        .expect("push");
    let mut frames = link.heap();
    assert_eq!(frames.len(), 1, "one push is one frame");
    frames.remove(0)
}

fn params_with_sn_7(batch: Option<u16>) -> wz_session_core::session_init_params::SessionInitParams {
    let mut params = fixture_session_init_params();
    params.initial_sn = 7;
    if let Some(batch) = batch {
        params.batch_size = batch;
    }
    params
}

#[test]
fn a_push_over_a_lending_link_is_written_into_its_slot_and_not_copied() {
    let link = LendingLink::new(true, 2, SLOT_LEN, HEADROOM);
    let actions = new_session_actions(link.clone(), params_with_sn_7(None), TokioTime::new());
    actions
        .send_push_literal("home/lent", b"payload", true)
        .expect("push");
    assert_eq!(link.lent().len(), 1, "the frame went through the slot door");
    assert!(
        link.heap().is_empty(),
        "and no byte copy of it went through the other"
    );
    assert_eq!(link.aborts(), 0, "a sent slot is not also given back");
    assert_eq!(link.free(), 2, "the link returned the slot it was handed");
}

#[test]
fn the_lent_frame_is_byte_for_byte_the_frame_the_heap_path_writes() {
    for payload in [&b"x"[..], &b"payload"[..], &[0xA5u8; 100][..]] {
        let link = LendingLink::new(true, 1, SLOT_LEN, HEADROOM);
        let actions = new_session_actions(link.clone(), params_with_sn_7(None), TokioTime::new());
        actions
            .send_push_literal("home/lent", payload, true)
            .expect("push");
        assert_eq!(
            link.lent(),
            vec![heap_frame(payload)],
            "payload of {} bytes",
            payload.len()
        );
    }
}

#[test]
fn a_link_that_lends_nothing_is_handed_the_same_frame_on_the_heap() {
    let link = LendingLink::new(false, 1, SLOT_LEN, HEADROOM);
    let actions = new_session_actions(link.clone(), params_with_sn_7(None), TokioTime::new());
    actions
        .send_push_literal("home/lent", b"payload", true)
        .expect("push");
    assert!(link.lent().is_empty());
    assert_eq!(link.heap(), vec![heap_frame(b"payload")]);
    assert_eq!(link.aborts(), 0, "nothing was lent, so nothing came back");
}

#[test]
fn a_link_with_no_free_slot_gets_the_frame_on_the_heap_and_loses_nothing() {
    let link = LendingLink::new(true, 0, SLOT_LEN, HEADROOM);
    let actions = new_session_actions(link.clone(), params_with_sn_7(None), TokioTime::new());
    actions
        .send_push_literal("home/lent", b"payload", true)
        .expect("a dry pool is a fallback, not an error");
    assert!(link.lent().is_empty());
    assert_eq!(link.heap(), vec![heap_frame(b"payload")]);
}

#[test]
fn a_frame_that_overflows_its_slot_goes_on_the_heap_and_the_slot_comes_back() {
    // The link grants a 24-byte slot whatever it is asked: the push's frame does
    // not fit what is left after the headroom, and the encode finds that out.
    let link = LendingLink::new(true, 1, 24, HEADROOM);
    let actions = new_session_actions(link.clone(), params_with_sn_7(None), TokioTime::new());
    let payload = [0x3Cu8; 80];
    actions
        .send_push_literal("home/lent", &payload, true)
        .expect("push");
    assert!(link.lent().is_empty(), "nothing fitted the slot");
    assert_eq!(link.heap(), vec![heap_frame(&payload)]);
    assert_eq!(link.aborts(), 1, "the lent slot was given back unsent");
    assert_eq!(link.free(), 1, "and it is free to be lent again");
    link.assert_every_slot_home();
}

/// The SAME session sends a small frame through the slot and, when the link has
/// no slot left to lend, the next one on the heap, with consecutive SNs: the
/// fallback does not skip or repeat a sequence number.
#[test]
fn the_fallback_keeps_the_sequence_numbers_gapless() {
    let link = LendingLink::new(true, 1, SLOT_LEN, HEADROOM);
    let actions = new_session_actions(link.clone(), params_with_sn_7(None), TokioTime::new());
    actions
        .send_push_literal("home/lent", b"one", true)
        .expect("first");
    // Hold the only slot so the second push finds the pool dry.
    link.taken.lock().expect("taken")[0] = true;
    actions
        .send_push_literal("home/lent", b"two", true)
        .expect("second");
    link.taken.lock().expect("taken")[0] = false;
    actions
        .send_push_literal("home/lent", b"three", true)
        .expect("third");

    let lent = link.lent();
    let heap = link.heap();
    assert_eq!((lent.len(), heap.len()), (2, 1));
    // Frame byte 1 is `VLE(sn)`: 7, 8, 9 in send order.
    assert_eq!(lent[0][1], 7);
    assert_eq!(heap[0][1], 8);
    assert_eq!(lent[1][1], 9);
}

// transport-lowlatency: the bare network message with no Frame wrapper, no SN and
// no fragmentation. The lend is the same one with nothing in front of the payload
// but the link's own framing.

/// A session that has negotiated lowlatency with its peer, over `link`.
#[cfg(feature = "transport-lowlatency")]
fn lowlatency_session(
    link: Arc<LendingLink>,
) -> Arc<
    wz_session_core::session_actions::SessionLinkActions<
        wz_runtime_tokio::runtime_impl::TokioRuntime,
        TokioTime,
    >,
> {
    let actions = new_session_actions(link, params_with_sn_7(None), TokioTime::new());
    assert!(
        actions.set_lowlatency_offer(true),
        "lowlatency offer applies"
    );
    actions.negotiate_lowlatency_against_peer(true);
    assert!(actions.is_lowlatency(), "both sides offered it");
    actions
}

/// The bare message the heap path writes for `payload` under lowlatency.
#[cfg(feature = "transport-lowlatency")]
fn heap_bare_message(payload: &[u8]) -> Vec<u8> {
    let link = LendingLink::new(false, 0, 0, 0);
    let actions = lowlatency_session(link.clone());
    actions
        .send_push_literal("home/lent", payload, true)
        .expect("push");
    let mut frames = link.heap();
    assert_eq!(frames.len(), 1, "one push is one message");
    frames.remove(0)
}

#[cfg(feature = "transport-lowlatency")]
#[test]
fn a_lowlatency_push_is_written_into_the_lent_slot_as_the_bare_message() {
    for payload in [&b"x"[..], &b"payload"[..], &[0xA5u8; 100][..]] {
        let link = LendingLink::new(true, 1, SLOT_LEN, HEADROOM);
        let actions = lowlatency_session(link.clone());
        actions
            .send_push_literal("home/lent", payload, true)
            .expect("push");
        assert_eq!(
            link.lent(),
            vec![heap_bare_message(payload)],
            "payload of {} bytes",
            payload.len()
        );
        assert!(link.heap().is_empty(), "no byte copy of it");
        assert_eq!(link.aborts(), 0);
        assert_eq!(link.free(), 1);
    }
}

#[cfg(feature = "transport-lowlatency")]
#[test]
fn a_lowlatency_message_that_overflows_its_slot_goes_on_the_heap_and_the_slot_returns() {
    let link = LendingLink::new(true, 1, 12, HEADROOM);
    let actions = lowlatency_session(link.clone());
    let payload = [0x3Cu8; 80];
    actions
        .send_push_literal("home/lent", &payload, true)
        .expect("push");
    assert!(link.lent().is_empty());
    assert_eq!(link.heap(), vec![heap_bare_message(&payload)]);
    assert_eq!(link.aborts(), 1);
    assert_eq!(link.free(), 1);
}

#[cfg(feature = "transport-lowlatency")]
#[test]
fn a_lowlatency_link_that_lends_nothing_gets_the_heap_message() {
    let link = LendingLink::new(false, 1, SLOT_LEN, HEADROOM);
    let actions = lowlatency_session(link.clone());
    actions
        .send_push_literal("home/lent", b"payload", true)
        .expect("push");
    assert!(link.lent().is_empty());
    assert_eq!(link.heap(), vec![heap_bare_message(b"payload")]);
    assert_eq!(link.aborts(), 0);
}

// The reconnect swap seam. A session that reconnects sends through a
// `SwappableLink`; if the seam did not forward the lend, every reconnecting
// session would silently take the heap while its link offered a slot.

use wz_runtime_tokio::runtime_impl::TokioRuntime;
use wz_session_core::reconnect::{LocalSwappableLink, SwappableLink};
use wz_session_core::tx_buf::TxBuf;
use wz_session_core::tx_lease::TxLease;

type Sink = Arc<dyn BoxedLinkDriver + Send + Sync>;

#[test]
fn a_lender_behind_the_swap_seam_still_lends() {
    let link = LendingLink::new(true, 1, SLOT_LEN, HEADROOM);
    let seam: Sink = Arc::new(SwappableLink::<TokioRuntime>::new(link.clone()));
    let actions = new_session_actions(seam, params_with_sn_7(None), TokioTime::new());
    actions
        .send_push_literal("home/lent", b"payload", true)
        .expect("push");
    assert_eq!(link.lent(), vec![heap_frame(b"payload")]);
    assert!(link.heap().is_empty(), "no byte copy behind the seam");
    assert_eq!(link.free(), 1);
}

#[test]
fn a_lender_behind_the_single_task_seam_still_lends() {
    // `!Sync` by design, so it cannot be a session's sink on this profile; the
    // lease is driven on it directly, which is exactly what the MCU session does.
    let link = LendingLink::new(true, 1, SLOT_LEN, HEADROOM);
    let seam = LocalSwappableLink::<TokioRuntime>::new(link.clone());
    let mut lease = TxLease::acquire(&seam, 64, Priority::DEFAULT).expect("lent through the seam");
    assert_eq!(
        lease.capacity(),
        SLOT_LEN - HEADROOM,
        "the grant's headroom survives"
    );
    lease.append(b"frame").expect("fits");
    assert_eq!(
        lease.send(Reliability::Reliable, Priority::DEFAULT),
        LinkSendOutcome::Sent
    );
    assert_eq!(link.lent(), vec![b"frame".to_vec()]);
    assert!(link.heap().is_empty());
}

/// A swap while a frame is being encoded: the slot belongs to the link that
/// lent it, so the frame is sent THERE (and refused by its closed queue in real
/// life), and the new link is neither handed a number it never gave nor asked to
/// send a frame it has no buffer for.
#[test]
fn a_swap_mid_encode_sends_the_frame_to_the_link_that_lent_the_slot() {
    let old = LendingLink::new(true, 1, SLOT_LEN, HEADROOM);
    let new = LendingLink::new(true, 1, SLOT_LEN, HEADROOM);
    let seam = SwappableLink::<TokioRuntime>::new(old.clone());
    let mut lease = TxLease::acquire(&seam, 64, Priority::DEFAULT).expect("old link lends");
    lease.append(b"in flight").expect("fits");
    seam.swap(new.clone());
    assert_eq!(
        lease.send(Reliability::Reliable, Priority::DEFAULT),
        LinkSendOutcome::Sent
    );
    assert_eq!(old.lent(), vec![b"in flight".to_vec()]);
    assert!(new.lent().is_empty() && new.heap().is_empty());
    assert_eq!((old.free(), new.free()), (1, 1), "nothing is left lent");
}

#[test]
fn a_swap_mid_encode_aborts_on_the_link_that_lent_the_slot() {
    let old = LendingLink::new(true, 1, SLOT_LEN, HEADROOM);
    let new = LendingLink::new(true, 1, SLOT_LEN, HEADROOM);
    let seam = SwappableLink::<TokioRuntime>::new(old.clone());
    let lease = TxLease::acquire(&seam, 64, Priority::DEFAULT).expect("old link lends");
    seam.swap(new.clone());
    drop(lease);
    assert_eq!((old.aborts(), new.aborts()), (1, 0));
    assert_eq!((old.free(), new.free()), (1, 1));
}

/// The same for the single-task seam, and with the old link's number reused by
/// the new link for another frame in the meantime: the two frames stay apart.
#[test]
fn the_single_task_seam_keeps_two_links_slot_numbers_apart() {
    let old = LendingLink::new(true, 1, SLOT_LEN, HEADROOM);
    let new = LendingLink::new(true, 1, SLOT_LEN, HEADROOM);
    let seam = LocalSwappableLink::<TokioRuntime>::new(old.clone());
    let mut first = TxLease::acquire(&seam, 64, Priority::DEFAULT).expect("old lends");
    first.append(b"from old").expect("fits");
    let _ = seam.swap(new.clone());
    let mut second = TxLease::acquire(&seam, 64, Priority::DEFAULT).expect("new lends");
    second.append(b"from new").expect("fits");
    // Both links number their only slot 0; the seam must not confuse them.
    assert_eq!(
        second.send(Reliability::Reliable, Priority::DEFAULT),
        LinkSendOutcome::Sent
    );
    assert_eq!(
        first.send(Reliability::Reliable, Priority::DEFAULT),
        LinkSendOutcome::Sent
    );
    assert_eq!(old.lent(), vec![b"from old".to_vec()]);
    assert_eq!(new.lent(), vec![b"from new".to_vec()]);
}

#[test]
fn a_swap_to_a_link_that_lends_nothing_takes_the_heap_afterwards() {
    let old = LendingLink::new(true, 1, SLOT_LEN, HEADROOM);
    let plain = LendingLink::new(false, 0, 0, 0);
    let seam = Arc::new(SwappableLink::<TokioRuntime>::new(old.clone()));
    let actions = new_session_actions(seam.clone(), params_with_sn_7(None), TokioTime::new());
    actions
        .send_push_literal("home/lent", b"one", true)
        .expect("first");
    seam.swap(plain.clone());
    actions
        .send_push_literal("home/lent", b"two", true)
        .expect("second");
    assert_eq!(old.lent().len(), 1);
    assert_eq!(plain.heap().len(), 1, "the new link's frame came as bytes");
    assert!(plain.lent().is_empty());
}

#[cfg(feature = "transport-fragmentation")]
#[test]
fn a_frame_past_the_mtu_is_fragmented_from_the_heap_and_its_slot_comes_back() {
    // A 64-byte batch budget: a 300-byte push cannot be one frame.
    let link = LendingLink::new(true, 1, 1024, HEADROOM);
    let actions = new_session_actions(link.clone(), params_with_sn_7(Some(64)), TokioTime::new());
    actions
        .send_push_literal("home/lent", &[0x5Au8; 300], true)
        .expect("push");
    assert!(
        link.lent().is_empty(),
        "a fragment chain is built from bytes, not from the slot"
    );
    assert!(
        link.heap().len() >= 4,
        "300 bytes over a 64-byte budget is a chain: {}",
        link.heap().len()
    );
    assert_eq!(
        link.aborts(),
        1,
        "the slot lent for the whole frame came back"
    );
    assert_eq!(link.free(), 1);
}

// The batching window. Its frame stays open across the calls that fill it, so
// the stage buffer IS a slot the link lends, held from the frame's first message
// to its flush: each message is encoded straight into it and the flush hands the
// slot over. Every test runs the same window over a link that lends nothing (the
// heap stage, the control) and compares the wire, frame by frame.

/// The batch budget the windows below negotiate (the session's own batch size;
/// no peer has answered, so it is the whole budget).
#[cfg(feature = "transport-batching")]
const BUDGET: u16 = 200;
/// A slot that holds a whole batch after the headroom.
#[cfg(feature = "transport-batching")]
const BATCH_SLOT: usize = BUDGET as usize + HEADROOM;

#[cfg(feature = "transport-batching")]
type Actions = Arc<wz_session_core::session_actions::SessionLinkActions<TokioRuntime, TokioTime>>;

#[cfg(feature = "transport-batching")]
fn batching_session(link: Sink) -> Actions {
    new_session_actions(link, params_with_sn_7(Some(BUDGET)), TokioTime::new())
}

/// Open a window, push each payload, and close it.
#[cfg(feature = "transport-batching")]
fn run_window(actions: &Actions, payloads: &[&[u8]]) {
    actions.batch_start().expect("batch_start");
    for payload in payloads {
        actions
            .send_push_literal("home/batch", payload, true)
            .expect("push");
    }
    actions.batch_stop().expect("batch_stop");
}

/// The frames the heap stage puts on the wire for the same window.
#[cfg(feature = "transport-batching")]
fn heap_window(payloads: &[&[u8]]) -> Vec<Vec<u8>> {
    let link = LendingLink::new(false, 0, 0, 0);
    run_window(&batching_session(link.clone()), payloads);
    link.heap()
}

/// THE CLAIM: a window of messages leaves as ONE lent slot, the frame the heap
/// stage builds byte for byte, and the flush copies nothing. The bytes copied at
/// flush are what crosses the byte door, `send_prioritized`, which copies a
/// frame out of the session's buffer into the link's: the batch size for the
/// heap stage, zero here.
#[cfg(feature = "transport-batching")]
#[test]
fn a_window_leaves_as_one_lent_slot_and_its_flush_copies_nothing() {
    let payloads: [&[u8]; 5] = [b"one", b"two", b"three", b"four", b"five"];
    let control = heap_window(&payloads);
    assert_eq!(
        control.len(),
        1,
        "CONTROL: the heap stage coalesced the window"
    );
    let copied_by_heap_stage: usize = control.iter().map(Vec::len).sum();
    assert!(copied_by_heap_stage > 0);

    let link = LendingLink::new(true, 2, BATCH_SLOT, HEADROOM);
    let actions = batching_session(link.clone());
    run_window(&actions, &payloads);
    assert_eq!(link.lent(), control, "the slot is the heap stage's frame");
    let copied_at_flush: usize = link.heap().iter().map(Vec::len).sum();
    assert_eq!(copied_at_flush, 0, "nothing crossed the byte door");
    assert_eq!(
        link.grants.load(Ordering::SeqCst),
        1,
        "one slot for the whole window, not one per message"
    );
    assert_eq!(
        actions.batch_lend_counts(),
        wz_session_core::session_actions::BatchLendCounts {
            slot_frames: 1,
            ..Default::default()
        }
    );
    link.assert_every_slot_home();
}

/// A message that does not fit what the slot has left closes the batch: the
/// slot leaves as the frame and the message opens the next one. Nothing is lost
/// or reordered, and the boundaries are the heap stage's, because a slot is
/// only used when it holds the whole budget.
#[cfg(feature = "transport-batching")]
#[test]
fn a_message_past_the_slot_closes_the_batch_and_opens_the_next() {
    let payloads: Vec<Vec<u8>> = (0..12u8).map(|i| vec![i; 30]).collect();
    let payloads: Vec<&[u8]> = payloads.iter().map(Vec::as_slice).collect();
    let control = heap_window(&payloads);
    assert!(
        control.len() >= 3,
        "CONTROL: the window spans frames: {}",
        control.len()
    );

    let link = LendingLink::new(true, 1, BATCH_SLOT, HEADROOM);
    let actions = batching_session(link.clone());
    run_window(&actions, &payloads);
    assert_eq!(link.lent(), control, "same frames, same order, same bytes");
    assert!(link.heap().is_empty());
    assert_eq!(
        actions.batch_lend_counts().slot_frames as usize,
        control.len(),
        "each frame in a slot of its own, one at a time"
    );
    link.assert_every_slot_home();
}

/// Messages appended to a frame keep their sequence: the frame is a slot, the
/// next frame is the next SN, with the window's messages in between.
#[cfg(feature = "transport-batching")]
#[test]
fn consecutive_windows_number_their_frames_without_a_gap() {
    let link = LendingLink::new(true, 1, BATCH_SLOT, HEADROOM);
    let actions = batching_session(link.clone());
    run_window(&actions, &[b"a", b"b"]);
    run_window(&actions, &[b"c"]);
    let lent = link.lent();
    assert_eq!(lent.len(), 2);
    // Frame byte 1 is `VLE(sn)`: one SN per frame, not per message.
    assert_eq!((lent[0][1], lent[1][1]), (7, 8));
    link.assert_every_slot_home();
}

/// A message past the batch budget in the middle of a window: the open frame
/// leaves as its slot WITHOUT the message (its partial encode rolled back), the
/// slot lent for the message alone goes back, and the message takes the
/// oversize path from bytes. The wire, across both doors, is the heap stage's.
#[cfg(feature = "transport-batching")]
#[test]
fn a_message_past_the_budget_mid_window_leaves_no_frame_half_built() {
    let big = [0x77u8; 300];
    let payloads: [&[u8]; 3] = [b"before", &big, b"after"];
    let control = heap_window(&payloads);

    let link = LendingLink::new(true, 1, BATCH_SLOT, HEADROOM);
    let actions = batching_session(link.clone());
    run_window(&actions, &payloads);
    let wire: Vec<Vec<u8>> = link.doors().into_iter().map(|(_, bytes)| bytes).collect();
    assert_eq!(wire, control, "the same frames in the same order");
    let lent_doors: Vec<bool> = link.doors().into_iter().map(|(lent, _)| lent).collect();
    assert_eq!(
        (lent_doors.first(), lent_doors.last()),
        (Some(&true), Some(&true)),
        "the two small frames left as slots"
    );
    assert!(
        link.aborts() >= 1,
        "the slot lent for the oversize message came back"
    );
    link.assert_every_slot_home();
}

/// A link with no slot free: the window is staged on the heap as it always was,
/// with the same bytes, and the fallback is counted, not silent.
#[cfg(feature = "transport-batching")]
#[test]
fn a_dry_pool_stages_the_window_on_the_heap_and_counts_it() {
    let payloads: [&[u8]; 3] = [b"x", b"y", b"z"];
    let control = heap_window(&payloads);

    let link = LendingLink::new(true, 0, BATCH_SLOT, HEADROOM);
    let actions = batching_session(link.clone());
    run_window(&actions, &payloads);
    assert_eq!(link.heap(), control);
    assert!(link.lent().is_empty());
    assert_eq!(
        actions.batch_lend_counts(),
        wz_session_core::session_actions::BatchLendCounts {
            heap_no_slot: 1,
            ..Default::default()
        }
    );

    // A link that lends nothing at all is the same fallback, counted the same.
    let plain = LendingLink::new(false, 0, 0, 0);
    let actions = batching_session(plain.clone());
    run_window(&actions, &payloads);
    assert_eq!(actions.batch_lend_counts().heap_no_slot, 1);
}

/// A slot that cannot hold the whole budget is refused: a frame built in it
/// would close earlier than the heap frame and change the wire. Counted.
#[cfg(feature = "transport-batching")]
#[test]
fn a_slot_short_of_the_budget_is_given_back_and_the_window_staged_on_the_heap() {
    let payloads: [&[u8]; 2] = [b"short", b"slot"];
    let control = heap_window(&payloads);

    let link = LendingLink::new(true, 1, BATCH_SLOT - 1, HEADROOM);
    let actions = batching_session(link.clone());
    run_window(&actions, &payloads);
    assert_eq!(link.heap(), control);
    assert!(link.lent().is_empty());
    assert_eq!(link.aborts(), 1, "the short slot went back unused");
    assert_eq!(actions.batch_lend_counts().heap_short_slot, 1);
    link.assert_every_slot_home();
}

/// A swap of the session's link in the middle of a window: the open frame is in
/// the OLD link's slot, so it leaves there, and the new link is asked for
/// nothing it did not lend.
#[cfg(feature = "transport-batching")]
#[test]
fn a_swap_mid_window_sends_the_open_frame_on_the_link_that_lent_its_slot() {
    let payloads: [&[u8]; 2] = [b"in", b"flight"];
    let control = heap_window(&payloads);

    let old = LendingLink::new(true, 1, BATCH_SLOT, HEADROOM);
    let new = LendingLink::new(true, 1, BATCH_SLOT, HEADROOM);
    let seam = Arc::new(SwappableLink::<TokioRuntime>::new(old.clone()));
    let actions = batching_session(seam.clone());
    actions.batch_start().expect("batch_start");
    for payload in payloads {
        actions
            .send_push_literal("home/batch", payload, true)
            .expect("push");
    }
    seam.swap(new.clone());
    actions.batch_stop().expect("batch_stop");
    assert_eq!(old.lent(), control);
    assert!(new.lent().is_empty() && new.heap().is_empty());
    old.assert_every_slot_home();
    new.assert_every_slot_home();
}

/// A reopen in the middle of a window discards the open frame, as it discards a
/// heap frame (the sequence numbers start over): the slot goes back to the link
/// that lent it, and nothing half built reaches the wire.
#[cfg(all(feature = "transport-batching", feature = "session-reconnect"))]
#[test]
fn a_reopen_mid_window_gives_the_open_frames_slot_back() {
    let old = LendingLink::new(true, 1, BATCH_SLOT, HEADROOM);
    let new = LendingLink::new(true, 1, BATCH_SLOT, HEADROOM);
    let seam = Arc::new(SwappableLink::<TokioRuntime>::new(old.clone()));
    let actions = batching_session(seam.clone());
    actions.batch_start().expect("batch_start");
    actions
        .send_push_literal("home/batch", b"discarded", true)
        .expect("push");
    assert_eq!(old.free(), 0, "CONTROL: the open frame holds the slot");
    // The supervisor's order: reset first, then swap in the re-dialled link.
    actions.reset_for_reopen();
    seam.swap(new.clone());
    actions.batch_stop().expect("batch_stop");
    assert_eq!(old.aborts(), 1, "the slot went back to its lender");
    assert!(
        old.doors().is_empty() && new.doors().is_empty(),
        "nothing was sent"
    );
    old.assert_every_slot_home();
    new.assert_every_slot_home();
}

/// A close in the middle of a window drains the open frame first, as its slot,
/// and only then sends the close: data batched before the close is not lost
/// behind it.
#[cfg(all(feature = "transport-batching", feature = "codec-close"))]
#[test]
fn a_close_mid_window_sends_the_open_slot_before_the_close() {
    let link = LendingLink::new(true, 1, BATCH_SLOT, HEADROOM);
    let actions = batching_session(link.clone());
    actions.batch_start().expect("batch_start");
    actions
        .send_push_literal("home/batch", b"last words", true)
        .expect("push");
    actions.send_close_with_reason(wz_session_core::close_reason::CloseReason::Generic);
    let doors: Vec<bool> = link.doors().into_iter().map(|(lent, _)| lent).collect();
    assert_eq!(
        doors,
        vec![true, false],
        "the slot, then the close as bytes"
    );
    link.assert_every_slot_home();
}

/// A session dropped with a window open gives the slot back: the link holding
/// the record returns it as it goes, and nothing is sent.
#[cfg(feature = "transport-batching")]
#[test]
fn a_session_dropped_mid_window_gives_the_slot_back() {
    let link = LendingLink::new(true, 1, BATCH_SLOT, HEADROOM);
    let actions = batching_session(link.clone());
    actions.batch_start().expect("batch_start");
    actions
        .send_push_literal("home/batch", b"never flushed", true)
        .expect("push");
    assert_eq!(link.free(), 0, "CONTROL: the open frame holds the slot");
    drop(actions);
    assert_eq!(link.aborts(), 1);
    assert!(link.doors().is_empty(), "nothing half built was sent");
    link.assert_every_slot_home();
}
