// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! A session of the per-session slot profile, the one the MCU client node runs: its tables
//! in `static`s the image declares, its pump in a cell, and the session shell's slot application
//! layer (`wz_session_mcu::app_layer::dispatch_slot`) on its events. It dials, a far end answers
//! its handshake, and every unit the fuzzer writes reaches it afterwards as a datagram from that
//! peer, read where the link holds it (the receive in place and its lent record walk) and
//! rejoined in the cell's own reassembly table.
//!
//! Input: one byte of arguments, then the units (`wz_fuzz_ingress_common::units`).
//!
//! | byte | argument |
//! |------|----------|
//! | 0    | the milliseconds the clock moves between two units |
//!
//! Held beside not crashing:
//!
//! - the handshake the harness answers opens the session, so every input reaches an established
//!   session (a failure here is the harness's, and every input shows it);
//! - the session allocates nothing from its handshake to its last datagram: the profile is the
//!   one an image with no allocator runs;
//! - once the input is read and the session let go, its slot and its pump cell are free again.
//!
//! The runtime is a `static` cell that starts once, so it and its clock live from one input to
//! the next; each input claims, and gives back, the one session slot and pump cell.

#![no_main]

use std::cell::{Cell, UnsafeCell};
use std::rc::Rc;

use libfuzzer_sys::fuzz_target;
use wz_fuzz_ingress_common::{
    advance_ms, handshake_replies, now_us, units, CountingAlloc, Window, BATCH,
};
use wz_runtime_coop::session_drive::{
    PumpSlots, SessionDatagramLink, SessionDriveConfig, SessionRole,
};
use wz_runtime_coop::session_runtime::new_session_in_slot;
use wz_runtime_coop::{ClockSource, CoopRuntime, CoopTime, RuntimeCell};
use wz_session_core::entropy::{EntropySource, EntropyUnavailable};
use wz_session_core::limits::SessionLimits;
use wz_session_core::link::{BoxedLinkDriver, LinkSendOutcome, TxSlot, TxSlotGrant};
use wz_session_core::policy::SessionPolicy;
use wz_session_core::qos::Priority;
use wz_session_core::reliability::Reliability;
use wz_session_core::session_init_params::{
    cookie_bytes, zid_bytes, KeepAliveConf, LinkRxConf, SessionInitParams, TxQueueConf,
};
use wz_session_core::session_slot::SessionSlots;
use wz_session_core::session_timeouts::SessionTimeouts;
use wz_session_core::signing_key::SigningKey;
use wz_session_core::slot_observer::{DefaultSinks, ObserverCell, Requesters};
use wz_session_core::WhatAmI;
use wz_session_mcu::app_layer::{dispatch_slot, NoReplies, SlotApp};

#[global_allocator]
static ALLOC: CountingAlloc = CountingAlloc;

/// How many steps the handshake is given, the steps each unit is given beyond its own, and the
/// steps the session is given once the last unit is in (see the heap profile's target).
const HANDSHAKE_STEPS: usize = 8;
const STEPS_PER_UNIT: usize = 8;
const TAIL_STEPS: usize = 256;

/// The bytes of the one outbound slot the link lends: a batch.
const TX_SLOT_BYTES: usize = BATCH as usize;

type Runtime = CoopRuntime<Clock, Nowhere>;

/// The image's tables: one session, its pump cell, the runtime's task and timer cells, and the
/// application layer's observer.
static RUNTIME: RuntimeCell<Clock, 4, 512, 4> = RuntimeCell::new();
static SESSIONS: SessionSlots<Runtime, CoopTime<Clock>, Nowhere, Counting, 1> = SessionSlots::new();
static PUMPS: PumpSlots<Clock, Rc<Feed>, 1, Nowhere> = PumpSlots::new();
static APP: SlotApp = SlotApp::new();

std::thread_local! {
    /// The runtime, started once, by the one thread libFuzzer runs the inputs on.
    static STARTED: Runtime = RUNTIME
        .start::<Nowhere>(Clock)
        .expect("the runtime cell is started once");
}

/// The time the harness moves (`wz_fuzz_ingress_common::now_us`), never set back: the runtime
/// outlives each input.
#[derive(Clone, Copy)]
struct Clock;

impl ClockSource for Clock {
    fn now_us(&self) -> u64 {
        now_us()
    }
}

/// A board's entropy, made deterministic so an input is one path.
struct Counting(u8);

impl EntropySource for Counting {
    fn try_fill_bytes(&mut self, buf: &mut [u8]) -> Result<(), EntropyUnavailable> {
        for slot in buf.iter_mut() {
            self.0 = self.0.wrapping_add(1);
            *slot = self.0;
        }
        Ok(())
    }
}

/// The link's outbound half, moved into the session's slot: it lends the session one outbound
/// slot to encode a frame into, as a lend-only session needs of its link, and what is sent goes
/// nowhere.
struct Nowhere {
    slot: UnsafeCell<[u8; TX_SLOT_BYTES]>,
    lent: Cell<bool>,
}

impl Nowhere {
    fn new() -> Self {
        Self {
            slot: UnsafeCell::new([0; TX_SLOT_BYTES]),
            lent: Cell::new(false),
        }
    }
}

impl BoxedLinkDriver for Nowhere {
    fn send_blocking(&self, _bytes: &[u8], _reliability: Reliability) -> LinkSendOutcome {
        LinkSendOutcome::Sent
    }

    fn open_blocking(&self) {}

    fn close_blocking(&self) {}

    fn tx_slot_acquire(&self, _want: usize, _priority: Priority) -> Option<TxSlotGrant> {
        if self.lent.replace(true) {
            return None;
        }
        Some(TxSlotGrant {
            slot: TxSlot(0),
            headroom: 0,
        })
    }

    fn tx_slot_storage(&self, _slot: TxSlot) -> (*mut u8, usize) {
        (self.slot.get().cast::<u8>(), TX_SLOT_BYTES)
    }

    fn tx_slot_send(
        &self,
        _slot: TxSlot,
        _start: usize,
        _len: usize,
        _reliability: Reliability,
        _priority: Priority,
    ) -> LinkSendOutcome {
        self.lent.set(false);
        LinkSendOutcome::Sent
    }

    fn tx_slot_abort(&self, _slot: TxSlot) {
        self.lent.set(false);
    }
}

/// The link's inbound half: the far end's replies and the fuzzer's units, laid out before the
/// session runs, and lent one at a time, where they lie, as the harness lets each go.
struct Feed {
    bytes: Vec<u8>,
    bounds: Vec<(usize, usize)>,
    next: Cell<usize>,
    released: Cell<usize>,
}

impl Feed {
    fn new<'a>(datagrams: impl IntoIterator<Item = &'a [u8]>) -> Self {
        let mut bytes = Vec::new();
        let mut bounds = Vec::new();
        for datagram in datagrams {
            let at = bytes.len();
            bytes.extend_from_slice(datagram);
            bounds.push((at, bytes.len()));
        }
        Self {
            bytes,
            bounds,
            next: Cell::new(0),
            released: Cell::new(0),
        }
    }

    /// Let the next datagram go; `false` once every one has been.
    fn release(&self) -> bool {
        let released = self.released.get();
        if released == self.bounds.len() {
            return false;
        }
        self.released.set(released + 1);
        true
    }
}

impl SessionDatagramLink for Feed {
    fn service(&self) {}

    fn recv_with(&self, f: &mut dyn FnMut(&[u8])) -> bool {
        let next = self.next.get();
        if next >= self.released.get() {
            return false;
        }
        self.next.set(next + 1);
        let (start, end) = self.bounds[next];
        f(&self.bytes[start..end]);
        true
    }
}

fn params() -> SessionInitParams {
    SessionInitParams {
        whatami: WhatAmI::Peer,
        zid: zid_bytes(&[0xb0; 4]),
        seq_num_res: 2,
        req_id_res: 2,
        batch_size: BATCH,
        lease_ms: 10_000,
        keep_alive: KeepAliveConf::PICO,
        initial_sn: 0,
        cookie: cookie_bytes(&[]),
        tx_queue: TxQueueConf::of_snapshot(&SessionPolicy::defaults(), &SessionLimits::BUILD),
        link_rx: LinkRxConf::default(),
        policy: SessionPolicy::defaults(),
        limits: SessionLimits::BUILD,
        cookie_signing_key: SigningKey::from_slice(&[7u8; 32]).expect("a key of 32 bytes"),
    }
}

/// The application layer's observer, installed in its `static` by the first input.
fn observer() -> &'static ObserverCell<DefaultSinks> {
    if let Some(cell) = APP.get() {
        return cell;
    }
    match APP.install_with(|_| ()) {
        Ok((cell, ())) => cell,
        Err(_) => unreachable!("no observer was installed, so this install is the first"),
    }
}

fuzz_target!(|data: &[u8]| {
    let (pace, stream) = match data.split_first() {
        Some((pace, stream)) => (u64::from(*pace), stream),
        None => (0, data),
    };
    let replies = handshake_replies();
    let feed = Rc::new(Feed::new(
        replies.iter().map(Vec::as_slice).chain(units(stream)),
    ));
    let runtime = STARTED.with(Runtime::clone);
    let Ok(claim) = SESSIONS.claim(Nowhere::new(), Counting(0)) else {
        panic!("the session slot is free when an input begins");
    };
    let actions = new_session_in_slot(claim, params, CoopTime::new(&runtime));
    let config = SessionDriveConfig {
        timeouts: SessionTimeouts::from_build(),
        role: SessionRole::Initiator,
        max_iters: None,
    };
    let Ok(mut pump) = PUMPS.claim(
        runtime.clone(),
        feed.clone(),
        actions.clone(),
        CoopTime::new(&runtime),
        config,
    ) else {
        panic!("the pump cell is free when an input begins");
    };
    let mut on_event = dispatch_slot(
        observer(),
        actions.clone(),
        Requesters::<NoReplies, NoReplies>::new(),
    );

    let window = Window::open();
    for _ in replies.iter() {
        feed.release();
    }
    for _ in 0..HANDSHAKE_STEPS {
        if actions.is_established() || pump.step(&mut on_event).is_some() {
            break;
        }
    }
    assert!(
        actions.is_established(),
        "the far end's handshake opens the session: the harness is wrong when it does not"
    );
    'units: while feed.release() {
        advance_ms(pace);
        for _ in 0..=STEPS_PER_UNIT {
            if pump.step(&mut on_event).is_some() {
                break 'units;
            }
        }
    }
    for _ in 0..TAIL_STEPS {
        if pump.step(&mut on_event).is_some() {
            break;
        }
    }
    assert_eq!(
        window.allocations(),
        0,
        "a session of the slot profile allocated while it read its peer"
    );

    drop(on_event);
    drop(pump);
    drop(actions);
    assert_eq!(SESSIONS.in_use(), 0, "a session let go gives its slot back");
    assert_eq!(PUMPS.in_use(), 0, "a pump let go gives its cell back");
});
