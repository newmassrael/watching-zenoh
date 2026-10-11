// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! ARCHITECTURE section 9.3 on the AP reassembly, counted by the allocator and
//! read by address: under `runtime-zero-copy` a reassembled message is
//! delivered FROM the reassembly pool slot its fragments were staged into, so
//! the payload the application is handed lies in that slot, and completing a
//! chain costs no allocation beyond what decoding the same batch from a frame
//! the link lent costs. The slot goes home once the last range of it is
//! dropped.
//!
//! The completion is driven through the production caller,
//! `wz_session_core::drive::report_outcome_reassembling`, over the production
//! Router type (`TokioReassembly`, the pooled arena under this feature).
//! Host-test level.
#![cfg(all(
    feature = "runtime-zero-copy",
    feature = "codec-push",
    feature = "transport-unicast"
))]

use std::alloc::{GlobalAlloc, Layout, System};
use std::cell::Cell;
use std::sync::{Arc, Mutex};

use wz_runtime_tokio::reassembly::TokioReassembly;
use wz_runtime_tokio::runtime_impl::{TokioRuntime, TokioTime};
use wz_runtime_tokio::session_glue::new_session_actions;
use wz_runtime_tokio_test_support::fixture_session_init_params;
use wz_session_core::drive::report_outcome_reassembling;
use wz_session_core::driver_loop::{DriverLoopOutcome, IterationEvent};
use wz_session_core::link::{BoxedLinkDriver, LinkSendOutcome, RxBytes};
use wz_session_core::network_message::NetworkMessage;
use wz_session_core::qos::Priority;
use wz_session_core::reassembly_dispatch::ReassemblyConfig;
use wz_session_core::reliability::Reliability;

/// Counts the allocations made BY THE CURRENT THREAD: everything a test drives
/// here runs on its own thread, so libtest's threads (which start, report and
/// join tests) cannot move a count the way a process-wide counter let them.
struct CountingAllocator;

thread_local! {
    static ALLOCATIONS: Cell<usize> = const { Cell::new(0) };
}

// SAFETY: every call forwards to `System` unchanged; the only addition is a
// bump of a thread-local cell without a destructor, which neither allocates
// nor unwinds.
unsafe impl GlobalAlloc for CountingAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        ALLOCATIONS.with(|n| n.set(n.get() + 1));
        // SAFETY: same contract as the caller's.
        unsafe { System.alloc(layout) }
    }

    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        ALLOCATIONS.with(|n| n.set(n.get() + 1));
        // SAFETY: same contract as the caller's.
        unsafe { System.alloc_zeroed(layout) }
    }

    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        ALLOCATIONS.with(|n| n.set(n.get() + 1));
        // SAFETY: same contract as the caller's.
        unsafe { System.realloc(ptr, layout, new_size) }
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        // SAFETY: same contract as the caller's.
        unsafe { System.dealloc(ptr, layout) }
    }
}

#[global_allocator]
static GLOBAL: CountingAllocator = CountingAllocator;

/// One test at a time in this binary, as it was when the counter was
/// process-wide; the counter is per thread now, so this no longer protects a
/// count.
static SERIAL: Mutex<()> = Mutex::new(());

/// Take [`SERIAL`]; a test that failed while holding it says nothing about the
/// next one, so a poisoned lock is taken all the same.
fn one_at_a_time() -> std::sync::MutexGuard<'static, ()> {
    SERIAL
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

fn allocations() -> usize {
    ALLOCATIONS.with(Cell::get)
}

type Actions = Arc<wz_session_core::session_actions::SessionLinkActions<TokioRuntime, TokioTime>>;

/// A link that records the frames it is handed, as bytes.
struct Recorder(Mutex<Vec<Vec<u8>>>);

impl BoxedLinkDriver for Recorder {
    fn send_blocking(&self, bytes: &[u8], _reliability: Reliability) -> LinkSendOutcome {
        self.0.lock().expect("frames").push(bytes.to_vec());
        LinkSendOutcome::Sent
    }
    fn open_blocking(&self) {}
    fn close_blocking(&self) {}
}

const KEY: &str = "home/reassembled";
static PAYLOAD: [u8; 3000] = [0xA7; 3000];

/// The batch a whole Frame carries for one Put of [`PAYLOAD`], as the session's
/// own heap path encodes it: the frame after its header byte and `VLE(sn)`.
fn batch() -> Vec<u8> {
    let link = Arc::new(Recorder(Mutex::new(Vec::new())));
    let mut params = fixture_session_init_params();
    params.initial_sn = 7;
    params.batch_size = u16::MAX;
    let actions = new_session_actions(link.clone(), params, TokioTime::new());
    actions
        .send_push_literal(KEY, &PAYLOAD, true)
        .expect("the push is sent");
    let frames = link.0.lock().expect("frames");
    assert_eq!(frames.len(), 1, "one push is one frame");
    // Header byte, then `VLE(7)`, one byte.
    frames[0][2..].to_vec()
}

/// The batch cut into three Fragment outcomes, as the dispatch reports them.
fn fragments(batch: &[u8], base_sn: u64) -> Vec<DriverLoopOutcome> {
    let third = batch.len().div_ceil(3);
    batch
        .chunks(third)
        .enumerate()
        .map(|(i, chunk)| DriverLoopOutcome::Fragment {
            reliable: true,
            sn: base_sn + i as u64,
            more: (i + 1) * third < batch.len(),
            payload: chunk.to_vec(),
            has_ext: false,
            extensions: Vec::new(),
            priority: Priority::DEFAULT,
            markers: wz_session_core::extfragment::FragmentMarkers::NONE,
        })
        .collect()
}

/// The inline payload of the one Push a batch carries.
fn put_payload(messages: &[NetworkMessage]) -> &[u8] {
    let [NetworkMessage::Push(push)] = messages else {
        panic!("the batch is one Push");
    };
    let wz_session_core::wire::PushOwnedVariant::CodecZenohMsgPut(put) = &push.body else {
        panic!("a literal push carries a Put");
    };
    wz_session_core::put_payload::inline_bytes(put).expect("an inline Put")
}

/// Whether `bytes` lie in a slot of the Router's own pool.
fn in_a_pool_slot(reasm: &TokioReassembly, bytes: &[u8]) -> bool {
    reasm.staging().slot_of(bytes.as_ptr()).is_some()
}

struct Completion {
    /// Allocations made by the call that completed the chain.
    allocations: usize,
    /// The delivered payload lay in a slot of the Router's pool.
    in_slot: bool,
    /// The delivered payload was the one sent.
    intact: bool,
}

/// Drive one chain through the production caller and measure its completion.
fn complete_one_chain(
    reasm: &mut TokioReassembly,
    actions: &Actions,
    chain: &[DriverLoopOutcome],
) -> Completion {
    let (last, head) = chain.split_last().expect("a chain");
    let mut ignore = |_: IterationEvent<'_>| {};
    for fragment in head {
        report_outcome_reassembling(fragment, reasm, actions, 0, &mut ignore);
    }
    let mut seen: Option<(usize, usize, bool)> = None;
    let before = allocations();
    {
        let mut sink = |event: IterationEvent<'_>| {
            if let IterationEvent::Poll(DriverLoopOutcome::FramePayload { messages, .. }) = event {
                let payload = put_payload(messages);
                seen = Some((payload.as_ptr() as usize, payload.len(), payload == PAYLOAD));
            }
        };
        report_outcome_reassembling(last, reasm, actions, 0, &mut sink);
    }
    let allocations = allocations() - before;
    let (ptr, len, intact) = seen.expect("the chain completed into a FramePayload");
    // SAFETY: read only as an address, never dereferenced.
    let in_slot = in_a_pool_slot(reasm, unsafe {
        std::slice::from_raw_parts(ptr as *const u8, len)
    });
    Completion {
        allocations,
        in_slot,
        intact,
    }
}

/// Allocations of decoding `batch` from a buffer that is already lent: what a
/// whole Frame the link lent costs its decode, the baseline the completion is
/// held to.
fn decode_from_a_lent_frame(batch: &[u8]) -> usize {
    let lent = RxBytes::lend(batch.to_vec());
    let before = allocations();
    let messages = wz_session_core::network_message::parse_frame_payload_in(&lent)
        .map_err(wz_session_core::parse_error::InboundParseError::Codec)
        .and_then(wz_session_core::network_message::refuse_unknown_mandatory_ext)
        .expect("the batch decodes");
    let outcome = DriverLoopOutcome::FramePayload {
        reliable: true,
        sn: 0,
        messages,
        has_ext: false,
        extensions: Vec::new(),
        priority: Priority::DEFAULT,
    };
    let spent = allocations() - before;
    drop(outcome);
    spent
}

fn session() -> Actions {
    let link = Arc::new(Recorder(Mutex::new(Vec::new())));
    let actions = new_session_actions(link, fixture_session_init_params(), TokioTime::new());
    *actions.inbound_peer_zid.lock().expect("zid") = Some(vec![0x0A; 4]);
    actions
}

/// Allocations the ROUTER makes completing the same chain with nothing done
/// with the bytes: the chain FSM's own work (its events and its release), which
/// is not the cost of the bytes and is subtracted out. Measured on a Router of
/// the same type, after a warm-up chain, over the borrowed ingest whose
/// delivery does nothing.
fn router_completion_cost(batch: &[u8]) -> usize {
    let mut reasm = TokioReassembly::new(ReassemblyConfig::new(8, 5_000));
    let mut measured = 0;
    for base in [10u64, 20] {
        for fragment in fragments(batch, base) {
            let DriverLoopOutcome::Fragment {
                sn, more, payload, ..
            } = &fragment
            else {
                unreachable!("fragments() builds Fragment outcomes");
            };
            let before = allocations();
            reasm.ingest(
                wz_session_core::reassembly_dispatch::Fragment {
                    peer_key: &[0x0A; 4],
                    reliable: true,
                    sn: *sn,
                    more: u8::from(*more),
                    payload,
                    priority: Priority::DEFAULT,
                    markers: wz_session_core::extfragment::FragmentMarkers::NONE,
                },
                wz_session_core::sn::mask_from_res(0x02),
                0,
                |_| {},
            );
            if !*more {
                measured = allocations() - before;
            }
        }
    }
    measured
}

/// THE CLAIM: the reassembled payload is delivered from the pool slot it was
/// staged into, and completing the chain allocates nothing for its bytes: the
/// completion costs the Router's own work plus what decoding the same batch
/// from a frame the link lent costs, and not one allocation more. The heap form
/// copied the chain into a vector and wrapped that in a shared buffer, two
/// allocations and a copy of the whole message.
#[test]
fn a_reassembled_message_is_delivered_from_its_pool_slot_with_no_copy() {
    let _one = one_at_a_time();
    let batch = batch();
    let actions = session();
    let mut reasm = TokioReassembly::new(ReassemblyConfig::new(8, 5_000));
    // Warm-up: whatever a first chain sets up once (the slot's shared view
    // among it) is not the steady state.
    complete_one_chain(&mut reasm, &actions, &fragments(&batch, 10));
    let done = complete_one_chain(&mut reasm, &actions, &fragments(&batch, 20));
    let router = router_completion_cost(&batch);
    let decode = decode_from_a_lent_frame(&batch);
    assert!(done.intact, "the delivered payload is the one sent");
    assert!(
        done.in_slot,
        "the delivered payload lies in the reassembly pool slot, not in a copy \
         (completion allocated {}, the Router's own work {router}, a lent frame's decode {decode})",
        done.allocations
    );
    assert_eq!(
        done.allocations,
        router + decode,
        "completing the chain allocated {} for its bytes",
        done.allocations.saturating_sub(router + decode)
    );
}

/// The lifecycle through the production caller: the slot a delivered message
/// lives in is out of the pool while the application keeps the message, and
/// goes home once it is dropped.
#[test]
fn the_slot_stays_out_while_the_delivered_message_is_kept_and_goes_home_after() {
    let _one = one_at_a_time();
    let batch = batch();
    let actions = session();
    let mut reasm = TokioReassembly::new(ReassemblyConfig::new(8, 5_000));
    let chain = fragments(&batch, 10);
    let (last, head) = chain.split_last().expect("a chain");
    let mut ignore = |_: IterationEvent<'_>| {};
    for fragment in head {
        report_outcome_reassembling(fragment, &mut reasm, &actions, 0, &mut ignore);
    }
    // What the application keeps: the delivered Put's payload, a range of the
    // reassembled chain.
    let mut kept = None;
    let mut keep = |event: IterationEvent<'_>| {
        if let IterationEvent::Poll(DriverLoopOutcome::FramePayload { messages, .. }) = event {
            let [NetworkMessage::Push(push)] = messages.as_slice() else {
                panic!("the batch is one Push");
            };
            let wz_session_core::wire::PushOwnedVariant::CodecZenohMsgPut(put) = &push.body else {
                panic!("a literal push carries a Put");
            };
            kept = put.payload.clone();
        }
    };
    report_outcome_reassembling(last, &mut reasm, &actions, 0, &mut keep);
    let kept = kept.expect("the chain completed");
    assert_eq!(&kept[..], &PAYLOAD[..]);
    assert!(in_a_pool_slot(&reasm, &kept));
    let slots = wz_runtime_tokio::reassembly_pool_ap::SLOT_COUNT;
    assert_eq!(reasm.staging().lent_out(), 1);
    assert_eq!(
        reasm.staging_available(),
        slots - 1,
        "the kept message holds its slot"
    );
    drop(kept);
    assert_eq!(
        reasm.staging_available(),
        slots,
        "dropped: the slot is available"
    );
    assert_eq!(reasm.active_chains(), 0);
    // The next chain start takes the slot home through the pool first.
    let _ = complete_one_chain(&mut reasm, &actions, &fragments(&batch, 20));
    assert_eq!(
        (reasm.staging().free_count(), reasm.staging().lent_out()),
        (slots - 1, 1),
        "the first slot went home through the pool; the second chain's is lent"
    );
}
