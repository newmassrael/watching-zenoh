// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! ARCHITECTURE section 9.1 on the MCU profile -- which frames of a session leave
//! from a transmit pool slot, counted over a real session and not over one send.
//!
//! A session puts frames on its link through two doors of the link driver. A
//! data frame (`dispatch_network_message`'s immediate and lowlatency paths) is
//! encoded into a slot the link lends (`tx_slot_*`); everything else is encoded
//! elsewhere and handed over as bytes (`send_blocking`): the handshake (InitSyn,
//! InitAck, OpenSyn, OpenAck), the keep-alive and the close (`send_wire_this_link`),
//! a flushed batch, a fragment. On the T2G kit the second door sent each frame from
//! a pbuf of lwIP's heap, which the MAC cannot read in place, so every keep-alive of
//! an idle session was copied into the MAC's ring while the pool sat free (the
//! console read `in place 20, copied 13` growing to `copied 37` over about 65
//! seconds, with only keep-alives on the wire).
//!
//! The witness: an acceptor and an initiator over the real lwIP loopback, a pool
//! installed before either sends, and the pool's own count of slots lent set
//! against the sessions' own count of what they emitted. A frame that left from
//! lwIP's heap is a frame the pool never lent, so the two disagree by exactly the
//! frames that took the heap.

use alloc::rc::Rc;
use alloc::vec;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use wz_link_lwip::tx_pool::{self, TxPoolStats, TxPoolStorage};
use wz_runtime_coop::session_drive::{
    spawn_session, OpenedLink, SessionDriveConfig, SessionLinks, SessionRole, UdpPeer,
};
use wz_runtime_coop::session_runtime::new_session_actions;
use wz_runtime_coop::{ClockSource, CoopLocalSet, CoopRuntime, CoopTime};
use wz_session_core::action_trace::ActionTrace;
use wz_session_core::session_actions::SessionLinkActions;
use wz_session_core::session_init_params::SessionInitParams;
use wz_session_core::session_timeouts::SessionTimeouts;

use crate::links::LwipLinks;

/// A clock the test moves; both sessions read the one runtime clock.
#[derive(Clone, Default)]
struct StepClock(Arc<AtomicU64>);
impl StepClock {
    fn advance_ms(&self, ms: u64) {
        self.0.fetch_add(ms * 1000, Ordering::SeqCst);
    }
}
impl ClockSource for StepClock {
    fn now_us(&self) -> u64 {
        self.0.load(Ordering::SeqCst)
    }
}

/// A deterministic stand-in for a board's TRNG (the acceptor mints a cookie).
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

/// The lease the keep-alive cadence is derived from.
const LEASE_MS: u64 = 10_000;

fn params(zid: u8) -> SessionInitParams {
    SessionInitParams {
        version: 0x09,
        whatami: wz_session_core::WhatAmI::Peer,
        zid: vec![zid; 4],
        seq_num_res: 2,
        req_id_res: 2,
        batch_size: 1024,
        lease_ms: LEASE_MS,
        initial_sn: 0,
        cookie: vec![],
        tx_queue: wz_session_core::session_init_params::TxQueueConf::default(),
        cookie_signing_key: wz_session_core::signing_key::SigningKey::new(vec![7u8; 32])
            .expect("key"),
    }
}

/// The pool for the length of the test, taken away at its end even if the test
/// fails, so no other test in the process lends from it.
struct InstalledPool;
impl InstalledPool {
    fn install() -> Self {
        let storage: &'static mut TxPoolStorage =
            alloc::boxed::Box::leak(alloc::boxed::Box::new(TxPoolStorage::uninit()));
        tx_pool::install(storage);
        Self
    }
    fn stats(&self) -> TxPoolStats {
        tx_pool::stats().expect("installed")
    }
}
impl Drop for InstalledPool {
    fn drop(&mut self) {
        tx_pool::uninstall();
    }
}

/// The handshake frames a session's trace says it emitted.
fn handshake_emits(t: &ActionTrace) -> u32 {
    t.send_init_syn + t.send_open_syn + t.send_init_ack_with_cookie + t.send_open_ack
}

/// THE COUNT: every frame two sessions put on the wire, from the first InitSyn
/// through several keep-alive intervals, left from a slot of the pool. Over the
/// loopback no MAC reads a slot, so each lent slot is also counted `unarmed`
/// when lwIP lets go of it; a slot that went home any other way, or is still out,
/// is a frame the lifecycle lost.
#[test]
fn every_frame_of_an_established_session_leaves_from_a_pool_slot() {
    let (_serial, link) = wz_link_lwip::lwip_test_link();
    let links = LwipLinks::new(Rc::new(link));
    let clock = StepClock::default();
    let runtime = CoopRuntime::new(clock.clone());
    let local = CoopLocalSet::new(&runtime);
    let pool = InstalledPool::install();

    let OpenedLink { sink, pump } = links.open_acceptor(7561).expect("bind acceptor");
    let acceptor = new_session_actions(sink, params(0xa1), CoopTime::new(&runtime), Counting(1));
    let _acceptor_task = spawn_session(
        &local,
        pump,
        acceptor.clone(),
        CoopTime::new(&runtime),
        SessionDriveConfig {
            timeouts: SessionTimeouts::spec_defaults(),
            role: SessionRole::Acceptor,
            max_iters: None,
        },
        |_| {},
    );
    let OpenedLink { sink, pump } = links
        .open_initiator(UdpPeer {
            addr: [127, 0, 0, 1],
            port: 7561,
        })
        .expect("open initiator");
    let initiator = SessionLinkActions::<CoopRuntime<StepClock>, CoopTime<StepClock>>::new_generic(
        sink,
        params(0xb1),
        CoopTime::new(&runtime),
    );
    let initiator_task = spawn_session(
        &local,
        pump,
        initiator.clone(),
        CoopTime::new(&runtime),
        SessionDriveConfig {
            timeouts: SessionTimeouts::spec_defaults(),
            role: SessionRole::Initiator,
            max_iters: None,
        },
        |_| {},
    );

    for _ in 0..64 {
        if initiator.is_established() && acceptor.is_established() {
            break;
        }
        local.run_until_idle();
    }
    std::assert!(
        initiator.is_established() && acceptor.is_established(),
        "the handshake completed"
    );
    let handshake =
        handshake_emits(&initiator.trace_snapshot()) + handshake_emits(&acceptor.trace_snapshot());
    std::assert_eq!(handshake, 4, "InitSyn, InitAck, OpenSyn, OpenAck");
    let after_handshake = pool.stats();
    std::assert_eq!(
        after_handshake.lent,
        handshake,
        "each handshake frame left from a slot: {after_handshake:?}"
    );

    // Idle, established: the only frames now are keep-alives, on each side's own
    // cadence, for several lease fractions.
    for _ in 0..12 {
        clock.advance_ms(LEASE_MS / 8);
        for _ in 0..8 {
            local.run_until_idle();
        }
    }
    std::assert!(
        !initiator_task.is_finished(),
        "the session stayed up\ninitiator: {:?}\nacceptor: {:?}",
        initiator.trace_snapshot(),
        acceptor.trace_snapshot()
    );
    let keep_alives =
        initiator.trace_snapshot().send_keep_alive + acceptor.trace_snapshot().send_keep_alive;
    std::assert!(
        keep_alives >= 4,
        "CONTROL: the interval carried keep-alives on both sides ({keep_alives})"
    );
    let s = pool.stats();
    std::assert_eq!(
        s.lent - after_handshake.lent,
        keep_alives,
        "each keep-alive left from a slot: {s:?}"
    );
    std::assert_eq!(
        (s.unarmed, s.abandoned, s.started, s.completed),
        (s.lent, 0, 0, 0),
        "over the loopback every slot went home un-armed, none lost"
    );
    std::assert_eq!(
        s.free as usize,
        wz_link_lwip::session_tx_pool_mcu::SLOT_COUNT,
        "and none is still out"
    );
    drop(pool);
}
