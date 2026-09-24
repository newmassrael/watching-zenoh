// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! R2838 (§5.23) — a wz MCU node on QEMU `mps2-an385` Ethernet that a zenoh
//! host reconfigures through the node's admin space.
//!
//! Boot: heap, SysTick clock, lwIP, the LAN9118 under an Ethernet netif at
//! QEMU user networking's guest address, then an `AdminNode` listening on
//! udp/10.0.2.15:7447. The main loop runs the task set, moves received
//! frames into lwIP, pumps lwIP's timers (ARP among them) and ticks the node.
//!
//! What a host sees: the node answers the admin GET under its zid
//! (`@/<zid>/peer/**`), and a PUT on `@/<zid>/peer/config/connect/endpoints`
//! makes it dial the endpoints named. The host decides whether that worked;
//! the firmware reports what it sees over semihosting and runs until QEMU is
//! stopped.

#![no_std]
#![no_main]

extern crate alloc;

use alloc::rc::Rc;
use alloc::string::String;
use alloc::vec;
use alloc::vec::Vec;
use core::mem::MaybeUninit;

use cortex_m_rt::{entry, exception};
use cortex_m_semihosting::{debug, hprintln};
use embedded_alloc::LlffHeap as Heap;
use panic_semihosting as _;
use wz::link_lwip::ethernet::{EthernetIf, Ipv4Config};
use wz::link_lwip::lan9118::{Lan9118, MPS2_BASE};
use wz::link_lwip::LwipLink;
use wz::runtime_coop::session_runtime::new_session_actions;
use wz::runtime_coop::{ClockSource, CoopLocalSet, CoopRuntime, CoopTime};
use wz::session_lwip::admin_host::ConnectControl;
use wz::session_lwip::admin_node::AdminNode;
use wz::session_lwip::admin_status::{NodeIdentity, NodeStatus};
use wz_mcu_clock::SystickClock;
use wz_session_core::entropy::{EntropySource, EntropyUnavailable};
use wz_session_core::session_init_params::SessionInitParams;
use wz_session_core::session_timeouts::SessionTimeouts;
use wz_session_core::signing_key::SigningKey;
use wz_session_core::zid_hex::zid_to_zenoh_hex;
use wz_session_core::WhatAmI;

const HEAP_SIZE: usize = 1024 * 256;

#[global_allocator]
static HEAP: Heap = Heap::empty();

/// QEMU's mps2 SysTick reference clock: 25 MHz.
const CYCLES_PER_US: u64 = 25;
static GLOBAL_CLOCK: SystickClock<{ CYCLES_PER_US }> = SystickClock::new();

#[exception]
fn SysTick() {
    GLOBAL_CLOCK.on_tick();
}

#[derive(Clone, Copy, Default)]
struct SystickClockRef;
impl ClockSource for SystickClockRef {
    fn now_us(&self) -> u64 {
        GLOBAL_CLOCK.now_us()
    }
}

/// lwIP's NO_SYS millisecond clock (ARP and the other lwIP timers).
#[unsafe(no_mangle)]
pub extern "C" fn sys_now() -> u32 {
    (GLOBAL_CLOCK.now_us() / 1000) as u32
}

/// The node's zid: "wzMCU" and a serial.
const ZID: [u8; 8] = [0x77, 0x7a, 0x4d, 0x43, 0x55, 0x00, 0x00, 0x01];
const ADDRESS: [u8; 4] = [10, 0, 2, 15];
const LISTEN_PORT: u16 = 7447;

/// Writes are PERMITTED on this node: upstream's default is to refuse, and
/// the node opts in, because being reconfigured is what it is for.
static CONTROL: ConnectControl = ConnectControl::new(true);
static STATUS: NodeStatus = NodeStatus::new(true);

/// NOT a TRNG. QEMU's mps2 machines have none, so the acceptor's cookie
/// nonces come from a xorshift stream seeded from the SysTick clock at each
/// construction. Enough to make each handshake's cookie distinct in the
/// lane; a board with a TRNG hands that in here instead.
struct ClockSeededXorshift(u64);

impl ClockSeededXorshift {
    fn seeded() -> Self {
        Self(GLOBAL_CLOCK.now_us() ^ 0x9e37_79b9_7f4a_7c15)
    }
}

impl EntropySource for ClockSeededXorshift {
    fn try_fill_bytes(&mut self, buf: &mut [u8]) -> Result<(), EntropyUnavailable> {
        for byte in buf {
            self.0 ^= self.0 << 13;
            self.0 ^= self.0 >> 7;
            self.0 ^= self.0 << 17;
            *byte = self.0 as u8;
        }
        Ok(())
    }
}

/// zenoh 1.x's handshake shape, with a batch the MCU's 1536-byte receive
/// slot holds whole.
fn params(signing_key: &[u8]) -> SessionInitParams {
    SessionInitParams {
        version: 0x09,
        whatami: WhatAmI::Peer,
        zid: ZID.to_vec(),
        seq_num_res: 2,
        req_id_res: 2,
        batch_size: 1500,
        lease_ms: 10_000,
        initial_sn: 0,
        cookie: Vec::new(),
        cookie_signing_key: SigningKey::new(signing_key.to_vec()).expect("32-byte key"),
    }
}

fn init_heap() {
    static mut HEAP_MEM: [MaybeUninit<u8>; HEAP_SIZE] = [MaybeUninit::uninit(); HEAP_SIZE];
    // SAFETY: `HEAP_MEM` is touched only here, as the entry point's first
    // action; nothing else can hold a reference to it.
    unsafe {
        let ptr = core::ptr::addr_of_mut!(HEAP_MEM) as usize;
        HEAP.init(ptr, HEAP_SIZE);
    }
}

fn fail(what: &str) -> ! {
    hprintln!("admin-node FAIL: {}", what);
    debug::exit(debug::EXIT_FAILURE);
    #[allow(clippy::empty_loop)]
    loop {}
}

#[entry]
fn main() -> ! {
    init_heap();
    GLOBAL_CLOCK.init();

    let link = Rc::new(LwipLink::init());
    // SAFETY: MPS2_BASE is the LAN9118 on every mps2 machine but an500, and
    // nothing else in this firmware drives it.
    let mut nic = unsafe { Lan9118::new(MPS2_BASE) };
    if let Err(e) = nic.init() {
        hprintln!("admin-node: LAN9118 {:?}", e);
        fail("no Ethernet controller");
    }
    let mut ethernet = match EthernetIf::add(
        &link,
        nic,
        Ipv4Config {
            address: ADDRESS,
            netmask: [255, 255, 255, 0],
            gateway: [10, 0, 2, 2],
        },
    ) {
        Ok(ethernet) => ethernet,
        Err(_) => fail("lwIP refused the Ethernet interface"),
    };

    let mut key = [0u8; 32];
    let _ = ClockSeededXorshift::seeded().try_fill_bytes(&mut key);

    let runtime = CoopRuntime::new(SystickClockRef);
    let local = CoopLocalSet::new(&runtime);
    let zid_hex = zid_to_zenoh_hex(&ZID);
    let accept_runtime = runtime.clone();
    let mut node = AdminNode::new(
        &local,
        link.clone(),
        &CONTROL,
        &STATUS,
        NodeIdentity {
            zid_hex: zid_hex.clone(),
            whatami: "peer",
            version: String::from("wz-mcu-admin-node"),
            locators: vec![String::from("udp/10.0.2.15:7447")],
        },
        LISTEN_PORT,
        SessionTimeouts::spec_defaults(),
        move || params(&key),
        move |sink| {
            new_session_actions(
                sink,
                params(&key),
                CoopTime::new(&accept_runtime),
                ClockSeededXorshift::seeded(),
            )
        },
    );
    hprintln!("admin-node: listening on udp/10.0.2.15:7447 as {}", zid_hex);

    let mut reported = 0;
    let mut generation = None;
    loop {
        local.run_until_idle();
        ethernet.poll();
        link.check_timeouts();
        node.tick(GLOBAL_CLOCK.now_us() / 1000);

        let (written, endpoints) = CONTROL.endpoints();
        if generation != Some(written) {
            generation = Some(written);
            hprintln!("admin-node: connect/endpoints = {:?}", endpoints);
        }
        let sessions = STATUS.sessions();
        if sessions.len() != reported {
            reported = sessions.len();
            for s in &sessions {
                hprintln!(
                    "admin-node: session with {} ({:?})",
                    s.peer_zid_hex,
                    s.whatami
                );
            }
            hprintln!("admin-node: {} session(s)", reported);
        }
    }
}
