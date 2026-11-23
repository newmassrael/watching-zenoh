// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! A unicast session of the session shell's heap profile, driven by the cooperative runtime's
//! pump, as an MCU image with an allocator drives it: it dials, a far end answers its handshake,
//! and every unit the fuzzer writes reaches it afterwards as a datagram from that peer, through
//! the copying receive (`try_recv`, the owned and lent record walks of `dispatch_link_event`)
//! and the reassembly of fragments, into an application layer with a subscriber and a queryable
//! on every key.
//!
//! Input: one byte of arguments, then the units (`wz_fuzz_ingress_common::units`).
//!
//! | byte | argument |
//! |------|----------|
//! | 0    | the milliseconds the clock moves between two units, so the lease and the reassembly deadlines can fall due |
//!
//! Held beside not crashing:
//!
//! - the handshake the harness answers opens the session, so every input reaches an established
//!   session (a failure here is the harness's, and every input shows it);
//! - every event the session reports, each refusal among them, renders through its `Debug`;
//! - the live heap grows by less than `GROWTH_LIMIT` while the session reads the input.

#![no_main]

use std::cell::RefCell;
use std::collections::VecDeque;
use std::fmt::Write as _;
use std::rc::Rc;

use libfuzzer_sys::fuzz_target;
use wz_fuzz_ingress_common::{
    advance_ms, handshake_replies, now_us, reset_clock, units, CountingAlloc, Discard, Window,
    BATCH, GROWTH_LIMIT,
};
use wz_runtime_coop::session_drive::{
    SessionDatagramLink, SessionDriveConfig, SessionPump, SessionRole,
};
use wz_runtime_coop::session_runtime::new_session_actions;
use wz_runtime_coop::{ClockSource, CoopRuntime, CoopTime};
use wz_session_core::driver_loop::IterationEvent;
use wz_session_core::entropy::{EntropySource, EntropyUnavailable};
use wz_session_core::limits::SessionLimits;
use wz_session_core::link::{BoxedLinkDriver, LinkSendOutcome, RxFrame};
use wz_session_core::observer::ApplicationLayerObserver;
use wz_session_core::policy::SessionPolicy;
use wz_session_core::reliability::Reliability;
use wz_session_core::session_init_params::{
    KeepAliveConf, LinkRxConf, SessionInitParams, TxQueueConf,
};
use wz_session_core::session_timeouts::SessionTimeouts;
use wz_session_core::signing_key::SigningKey;
use wz_session_core::WhatAmI;

#[global_allocator]
static ALLOC: CountingAlloc = CountingAlloc;

/// How many steps the handshake is given: the InitSyn leaves when the pump is made, and each of
/// the two replies takes a step.
const HANDSHAKE_STEPS: usize = 8;
/// The steps each unit is given beyond its own: a unit that is a batch of several messages has
/// the rest dispatched a message a step.
const STEPS_PER_UNIT: usize = 8;
/// The steps the session is given once the last unit is in, for what it parked.
const TAIL_STEPS: usize = 256;

/// The time the harness moves (`wz_fuzz_ingress_common::now_us`).
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

/// The link's outbound half: what the session sends is taken and goes nowhere.
struct Nowhere;

impl BoxedLinkDriver for Nowhere {
    fn send_blocking(&self, _bytes: &[u8], _reliability: Reliability) -> LinkSendOutcome {
        LinkSendOutcome::Sent
    }

    fn open_blocking(&self) {}

    fn close_blocking(&self) {}
}

/// The link's inbound half: the datagrams the harness queued, the peer's and no one else's.
#[derive(Default)]
struct Feed(RefCell<VecDeque<Vec<u8>>>);

impl Feed {
    fn push(&self, datagram: Vec<u8>) {
        self.0.borrow_mut().push_back(datagram);
    }
}

impl SessionDatagramLink for Feed {
    fn service(&self) {}

    fn try_recv(&self) -> Option<RxFrame> {
        self.0.borrow_mut().pop_front().map(RxFrame::new)
    }
}

fn params() -> SessionInitParams {
    SessionInitParams {
        whatami: WhatAmI::Peer,
        zid: [0x0A, 0x0B, 0x0C, 0x0D].into(),
        seq_num_res: 2,
        req_id_res: 2,
        batch_size: BATCH,
        lease_ms: 10_000,
        keep_alive: KeepAliveConf::PICO,
        initial_sn: 0,
        cookie: vec![0u8; 16],
        tx_queue: TxQueueConf::of_snapshot(&SessionPolicy::defaults(), &SessionLimits::BUILD),
        link_rx: LinkRxConf::default(),
        policy: SessionPolicy::defaults(),
        limits: SessionLimits::BUILD,
        cookie_signing_key: SigningKey::new(vec![7u8; 32]).expect("a key of 32 bytes"),
    }
}

fuzz_target!(|data: &[u8]| {
    let (pace, stream) = match data.split_first() {
        Some((pace, stream)) => (u64::from(*pace), stream),
        None => (0, data),
    };
    reset_clock();
    let runtime = CoopRuntime::new(Clock);
    let clock = CoopTime::new(&runtime);
    let sink: Rc<dyn BoxedLinkDriver> = Rc::new(Nowhere);
    let actions = new_session_actions(sink, params(), clock.clone(), Counting(0));
    let feed = Rc::new(Feed::default());
    let config = SessionDriveConfig {
        timeouts: SessionTimeouts::from_build(),
        role: SessionRole::Initiator,
        max_iters: None,
    };
    let mut pump = SessionPump::new(runtime, feed.clone(), actions.clone(), clock, config);
    let mut observer = ApplicationLayerObserver::new();
    let _ = observer.subscribe("**", |_| {});
    let _ = observer.with_app(|app_half| app_half.queryables.register("**", |_, _| {}));
    let mut on_event = |event: IterationEvent<'_, '_>| {
        let _ = write!(Discard, "{event:?}");
        observer.set_unanswerable_final(actions.params.policy.query_unanswerable_final());
        observer.dispatch(event, &*actions);
    };

    for reply in handshake_replies() {
        feed.push(reply);
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

    let window = Window::open();
    'units: for unit in units(stream) {
        feed.push(unit.to_vec());
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
    assert!(
        window.peak_growth() < GROWTH_LIMIT,
        "the session's heap grew by {} bytes reading {} bytes",
        window.peak_growth(),
        stream.len()
    );
});
