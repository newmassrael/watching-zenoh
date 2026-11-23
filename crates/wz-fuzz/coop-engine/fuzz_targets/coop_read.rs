// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The cooperative engine behind the C ABI (`wz-capi-coop`), opened over a link the harness
//! holds and read as a C program reads it (`SessionDrive::read`, zenoh-pico's `zp_read`): a far
//! end answers its dial's handshake, a subscriber and a queryable are declared on every key, and
//! every unit the fuzzer writes reaches the engine afterwards as a datagram from that peer. The
//! engine's read steps its session over the receive in place, the delivery lane that hands
//! samples to the subscriber's callback, and the queryable's answers.
//!
//! Input: one byte of arguments, then the units (`wz_fuzz_ingress_common::units`).
//!
//! | byte | argument |
//! |------|----------|
//! | 0    | the milliseconds the clock moves between two units |
//!
//! Held beside not crashing:
//!
//! - the handshake the harness answers opens the engine to the far end, so every input reaches
//!   an open session (a failure here is the harness's, and every input shows it);
//! - every sample handed to the subscriber names a key;
//! - the live heap grows by less than `GROWTH_LIMIT` while the engine reads the input.

#![no_main]

use std::cell::RefCell;
use std::collections::VecDeque;
use std::rc::Rc;
use std::sync::Arc;

use libfuzzer_sys::fuzz_target;
use wz_capi_coop::arena::{admitted_faces, admitted_handshakes};
use wz_capi_coop::{CoopConfig, CoopEngine};
use wz_capi_port::{
    QueryCallback, QueryHolder, SessionDrive, SessionEngine, SubscriberSink, WireKey,
};
use wz_fuzz_ingress_common::{
    advance_ms, handshake_replies, now_us, reset_clock, units, CountingAlloc, Window, BATCH,
    GROWTH_LIMIT,
};
use wz_runtime_coop::session_drive::{
    LinkOpenError, Locator, OpenedLink, SessionDatagramLink, SessionLinks,
};
use wz_runtime_coop::ClockSource;
use wz_session_core::entropy::{EntropySource, EntropyUnavailable};
use wz_session_core::limits::SessionLimits;
use wz_session_core::link::{BoxedLinkDriver, LinkSendOutcome, RxFrame};
use wz_session_core::locality::Locality;
use wz_session_core::policy::{SessionPolicy, SnResolution};
use wz_session_core::query_sink::{QueryView, ReplyOut};
use wz_session_core::reliability::Reliability;
use wz_session_core::session_init_params::{KeepAliveConf, LinkRxConf, TxQueueConf};
use wz_session_core::session_timeouts::SessionTimeouts;
use wz_session_core::sink::SampleView;
use wz_session_core::WhatAmI;

#[global_allocator]
static ALLOC: CountingAlloc = CountingAlloc;

/// The reads the engine is given once the last unit is in, for what it holds back.
const TAIL_READS: usize = 4;

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

/// The datagrams the far end has sent and the engine not yet read.
type Queue = Rc<RefCell<VecDeque<Vec<u8>>>>;

/// The network the engine opens its links on: every dial reaches the one far end, whose
/// datagrams are the harness's queue; nothing listens.
struct Links(Queue);

impl SessionLinks for Links {
    type Pump = Feed;

    fn open_acceptor(&self, _port: u16) -> Result<OpenedLink<Feed>, LinkOpenError> {
        Err(LinkOpenError::Unsupported)
    }

    fn open_initiator(&self, _to: Locator) -> Result<OpenedLink<Feed>, LinkOpenError> {
        Ok(OpenedLink {
            sink: Rc::new(Nowhere),
            pump: Feed(self.0.clone()),
        })
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

/// The link's inbound half: the far end's datagrams, in order.
struct Feed(Queue);

impl SessionDatagramLink for Feed {
    fn service(&self) {}

    fn try_recv(&self) -> Option<RxFrame> {
        self.0.borrow_mut().pop_front().map(RxFrame::new)
    }
}

/// A client that dials the far end and waits for nothing: no listener, no redial, no idle wait,
/// so a read returns as soon as its link has nothing more.
fn config() -> CoopConfig {
    CoopConfig {
        endpoints: vec!["udp/127.0.0.1:7447".to_owned()],
        whatami: WhatAmI::Client,
        zid: Some(vec![0xb1; 4]),
        batch_size: BATCH,
        lease_ms: 10_000,
        keep_alive: KeepAliveConf::PICO,
        sn_resolution: SnResolution::default(),
        link_rx: LinkRxConf::default(),
        tx_queue: TxQueueConf::pico_of_snapshot(
            &SessionPolicy::defaults(),
            &SessionLimits::defaults(),
        ),
        timeouts: SessionTimeouts::spec_defaults(),
        open_timeout_ms: 5_000,
        redial_ms: None,
        idle_wait_ms: 0,
        listen: Vec::new(),
        accept_pending: admitted_handshakes(&SessionLimits::defaults())
            .expect("the build admits its own value"),
        max_faces: admitted_faces(&SessionLimits::defaults())
            .expect("the build admits its own value"),
        groups: Vec::new(),
        clock_moves: None,
        limits: SessionLimits::defaults(),
    }
}

fuzz_target!(|data: &[u8]| {
    let (pace, stream) = match data.split_first() {
        Some((pace, stream)) => (u64::from(*pace), stream),
        None => (0, data),
    };
    reset_clock();
    let queue: Queue = Rc::default();
    queue.borrow_mut().extend(handshake_replies());
    let Ok(engine) = CoopEngine::open(Links(queue.clone()), Clock, Counting(0), config()) else {
        panic!("the far end's handshake opens the engine: the harness is wrong when it does not");
    };
    assert!(
        !engine.peer_identities().is_empty(),
        "the open engine holds the far end as its peer"
    );
    let _ = engine.declare_subscriber_on_wire(
        "**".to_owned(),
        WireKey::literal(),
        Locality::Any,
        None,
        SubscriberSink::shared(|sample: &dyn SampleView| {
            assert!(!sample.keyexpr().is_empty(), "a sample names its key");
        }),
    );
    let _ = engine.declare_queryable_on_wire(
        "**".to_owned(),
        WireKey::literal(),
        false,
        Locality::Any,
        None,
        Arc::new(|_holder: Arc<dyn QueryHolder>| {
            Box::new(|_query: &dyn QueryView, _out: &mut dyn ReplyOut| {}) as QueryCallback
        }),
    );

    let window = Window::open();
    for unit in units(stream) {
        queue.borrow_mut().push_back(unit.to_vec());
        advance_ms(pace);
        if SessionDrive::read(&*engine, false).is_err() {
            break;
        }
    }
    for _ in 0..TAIL_READS {
        if SessionDrive::read(&*engine, false).is_err() {
            break;
        }
    }
    assert!(
        window.peak_growth() < GROWTH_LIMIT,
        "the engine's heap grew by {} bytes reading {} bytes",
        window.peak_growth(),
        stream.len()
    );
});
