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
}

impl BoxedLinkDriver for LendingLink {
    fn send_blocking(&self, bytes: &[u8], _reliability: Reliability) -> LinkSendOutcome {
        self.heap.lock().expect("heap").push(bytes.to_vec());
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
