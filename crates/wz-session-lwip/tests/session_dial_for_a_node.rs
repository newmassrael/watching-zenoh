// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! Decision D4 of `docs/session-lifecycle-intent.md` on the fixed-memory host: a dial made for
//! a node closes at an InitAck from another one.
//!
//! The host dials a far end on the lwIP loopback. The far end answers the `InitSyn` with an
//! InitAck from `FIXTURE_LISTENER_ZID` and reads the next datagram the dialler sends. A dial
//! made for another zid sends a Close carrying INVALID, upstream's reason, and never an
//! OpenSyn. A dial made for the zid the InitAck carries sends its OpenSyn. The same far end
//! gives the two answers, so the refusal can only be the zid's.
//!
//! It runs on the node's real profile, as `session_dial_exhaustion` does: `session-slot` for
//! the session tables and `static-link-storage` for the sockets.

use std::rc::Rc;

use wz_codecs::wire_const::{T_MID_CLOSE, T_MID_OPEN};
use wz_link_lwip::rx_sockets::{SessionRxPool, SessionRxSocket};
use wz_link_lwip::LwipLink;
use wz_runtime_coop::session_drive::{IpEndpoint, PumpSlots, SessionDriveConfig, SessionRole};
use wz_runtime_coop::{ClockSource, CoopLocalSet, CoopTime, RuntimeCell};
use wz_session_core::close_reason::CloseReason;
use wz_session_core::datagram_peer::is_init_syn;
use wz_session_core::session_init_params::{cookie_bytes, zid_bytes, SessionInitParams};
use wz_session_core::session_slot::SessionSlots;
use wz_session_core::session_timeouts::SessionTimeouts;
use wz_session_core::signing_key::SigningKey;
use wz_session_core::WhatAmI;
use wz_session_lwip::driver::LwipUdpDriver;
use wz_session_lwip::session_host::{DialTarget, OpenedSession, SessionHost};
use wz_session_lwip::{LwipLinks, LwipSessionLink};
use wz_session_wire_fixtures::{craft_initack_wire_with_caps, FIXTURE_LISTENER_ZID};

/// A clock that never moves: no deadline fires, so the dialler sends nothing the far end did
/// not ask for.
#[derive(Clone, Default)]
struct Frozen;
impl ClockSource for Frozen {
    fn now_us(&self) -> u64 {
        0
    }
}

/// A deterministic stand-in for a board's TRNG.
struct Counting(u8);
impl wz_session_core::entropy::EntropySource for Counting {
    fn try_fill_bytes(
        &mut self,
        buf: &mut [u8],
    ) -> Result<(), wz_session_core::entropy::EntropyUnavailable> {
        for b in buf {
            self.0 = self.0.wrapping_add(1);
            *b = self.0;
        }
        Ok(())
    }
}

type LinkRc = Rc<LwipLink>;
type Slots = SessionSlots<
    wz_runtime_coop::CoopRuntime<Frozen, LwipUdpDriver>,
    CoopTime<Frozen>,
    LwipUdpDriver,
    Counting,
    1,
>;
type Pumps = PumpSlots<Frozen, LwipSessionLink<LinkRc>, 1, LwipUdpDriver>;

/// The dialler's sequence-number and request-id resolutions (2 and 2) and batch size: the
/// InitAck answers them unchanged, so nothing but its zid can refuse it.
const SN_RES_BYTE: u8 = 2 | (2 << 2);
const BATCH: u16 = 1024;

fn params() -> SessionInitParams {
    SessionInitParams {
        whatami: WhatAmI::Peer,
        zid: zid_bytes(&[0xb0; 4]),
        seq_num_res: 2,
        req_id_res: 2,
        batch_size: BATCH,
        lease_ms: 10_000,
        keep_alive: wz_session_core::session_init_params::KeepAliveConf::PICO,
        initial_sn: 0,
        cookie: cookie_bytes(&[]),
        tx_queue: wz_session_core::session_init_params::TxQueueConf::default(),
        link_rx: wz_session_core::session_init_params::LinkRxConf::default(),
        cookie_signing_key: SigningKey::from_slice(&[7u8; 32]).expect("key"),
    }
}

/// Dial the far end for `expected`, answer its `InitSyn` with an InitAck from
/// `FIXTURE_LISTENER_ZID`, and return the next datagram the dialler sent.
fn next_datagram_after_the_init_ack(
    expected: [u8; 16],
    sink_port: u16,
    cell: &'static RuntimeCell<Frozen, 4, 256, 4>,
    sessions: &'static Slots,
    pumps: &'static Pumps,
    sockets: &'static SessionRxPool<1>,
) -> Vec<u8> {
    let (_serial, link) = wz_link_lwip::lwip_test_link();
    let link: LinkRc = Rc::new(link);
    let runtime = cell
        .start::<LwipUdpDriver>(Frozen)
        .expect("the runtime starts once");
    let local = CoopLocalSet::new(&runtime);
    let host: SessionHost<Frozen, LinkRc, Counting, 1, 1> =
        SessionHost::new(CoopLocalSet::new(&runtime), sessions, pumps, link.clone());
    let links = LwipLinks::new(link.clone(), sockets);
    let mut sink: SessionRxSocket =
        wz_link_lwip::test_bind::session_rx(&link, sink_port).expect("bind the far end");

    let _opened: OpenedSession<Frozen, LwipUdpDriver> = host
        .dial(
            &links,
            DialTarget::node(
                IpEndpoint {
                    addr: [127, 0, 0, 1],
                    port: sink_port,
                },
                expected,
            ),
            Counting(0xb0),
            params(),
            SessionDriveConfig {
                timeouts: SessionTimeouts::spec_defaults(),
                role: SessionRole::Initiator,
                max_iters: None,
            },
            |_| |_: wz_session_core::driver_loop::IterationEvent<'_>| {},
        )
        .expect("the host has a socket, a slot, a pump cell and a task cell");

    let turn = |sink: &mut SessionRxSocket| {
        local.run_until_idle();
        link.poll_loopback();
        link.check_timeouts();
        sink.try_recv()
    };
    let init_syn = (0..8)
        .find_map(|_| turn(&mut sink))
        .expect("the dial sent its InitSyn");
    assert!(
        is_init_syn(init_syn.data.as_slice()),
        "the first datagram is the InitSyn"
    );
    let init_ack = craft_initack_wire_with_caps(&[0xC0, 0x01], SN_RES_BYTE, BATCH);
    sink.send_to(init_syn.src_addr, init_syn.src_port, &init_ack)
        .expect("the far end answers");
    let next = (0..8)
        .find_map(|_| turn(&mut sink))
        .expect("the dialler sent a datagram after the InitAck");
    next.data.as_slice().to_vec()
}

#[test]
fn a_dial_the_fixed_memory_host_makes_for_another_node_closes_invalid_at_the_init_ack() {
    static RUNTIME: RuntimeCell<Frozen, 4, 256, 4> = RuntimeCell::new();
    static SESSIONS: Slots = SessionSlots::new();
    static PUMPS: Pumps = PumpSlots::new();
    static SOCKETS: SessionRxPool<1> = SessionRxPool::new();
    let mut another = [0u8; 16];
    another[..4].copy_from_slice(&[0xB0, 0xB1, 0xB2, 0xB3]);
    let next =
        next_datagram_after_the_init_ack(another, 7821, &RUNTIME, &SESSIONS, &PUMPS, &SOCKETS);
    assert_eq!(
        next.first().map(|h| h & 0x1f),
        Some(T_MID_CLOSE),
        "the datagram after the InitAck is a Close, not an OpenSyn: {next:02x?}"
    );
    assert_eq!(
        next.get(1).copied(),
        Some(CloseReason::Invalid as u8),
        "and it carries INVALID: {next:02x?}"
    );
}

#[test]
fn a_dial_the_fixed_memory_host_makes_for_the_node_that_answers_goes_on_to_the_open() {
    static RUNTIME: RuntimeCell<Frozen, 4, 256, 4> = RuntimeCell::new();
    static SESSIONS: Slots = SessionSlots::new();
    static PUMPS: Pumps = PumpSlots::new();
    static SOCKETS: SessionRxPool<1> = SessionRxPool::new();
    let mut the_node = [0u8; 16];
    the_node[..FIXTURE_LISTENER_ZID.len()].copy_from_slice(&FIXTURE_LISTENER_ZID);
    let next =
        next_datagram_after_the_init_ack(the_node, 7822, &RUNTIME, &SESSIONS, &PUMPS, &SOCKETS);
    assert_eq!(
        next.first().map(|h| h & 0x1f),
        Some(T_MID_OPEN),
        "the datagram after the InitAck is the OpenSyn: {next:02x?}"
    );
}
