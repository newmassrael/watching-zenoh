// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! zephyr-admin-node (Rust staticlib) — a wz node on a Zephyr board that a zenoh
//! host reconfigures through the node's admin space.
//!
//! The node is `wz_session_mcu::admin_node::AdminNode`: it listens for a
//! session, answers upstream's admin GET under its zid (`@/<zid>/peer/**`), and a
//! PUT on `@/<zid>/peer/config/connect/endpoints` makes it dial the endpoints
//! named. It is the node the QEMU lwIP firmware (deploy/mcu-admin-node) is; what
//! this firmware changes is the stack under it, which the BOARD chooses, so that a
//! lab can drive one on whatever it has on the bench.
//!
//! What a board contributes is a [`NodeNet`]: its links (`SessionLinks`), the
//! address it advertises, the id it claims, and whatever work its stack needs
//! each pass. [`net_zephyr`] is Zephyr's own sockets, for a board whose
//! Ethernet Zephyr drives. Nothing in the node's assembly or its loop names a
//! board, an address, an id, a clock rate or a random source: each is read from
//! the board (devicetree, Kconfig, its interface, its entropy device).
//!
//! The Zephyr C `main()` (src/main.c) calls [`wz_app_main`], which returns only
//! when the node could not start: a running node never does.
#![no_std]

extern crate alloc;

use alloc::format;
use alloc::rc::Rc;
use alloc::string::String;
use alloc::vec::Vec;

use wz::runtime_coop::session_drive::SessionLinks;
use wz::runtime_coop::session_runtime::new_session_actions;
use wz::runtime_coop::{ClockSource, CoopLocalSet, CoopRuntime, CoopTime};
use wz::runtime_zephyr::glue::{log, log_line, yield_ms};
use wz::runtime_zephyr::{ZephyrClock, ZephyrEntropy};
use wz_session_core::entropy::EntropySource;
use wz_session_core::session_init_params::SessionInitParams;
use wz_session_core::session_timeouts::SessionTimeouts;
use wz_session_core::signing_key::SigningKey;
use wz_session_core::zid_hex::zid_to_zenoh_hex;
use wz_session_core::WhatAmI;
use wz_session_mcu::admin_host::ConnectControl;
use wz_session_mcu::admin_node::AdminNode;
use wz_session_mcu::admin_status::{NodeIdentity, NodeStatus};

#[cfg(feature = "mac-cyt4bf")]
mod mac_cyt4bf;
#[cfg(feature = "net-lwip-mac")]
mod net_lwip;
#[cfg(feature = "net-zephyr-sockets")]
mod net_zephyr;
#[cfg(feature = "spi-probe")]
mod spi_cyt4bf;
// The allocator over the kernel heap (`CONFIG_HEAP_MEM_POOL_SIZE` in prj.conf),
// the critical section over the kernel IRQ lock and the panic handler.
wz::runtime_zephyr::zephyr_image!();

/// The board's `CONFIG_SYS_CLOCK_TICKS_PER_SEC`, as this build was configured:
/// the `ZephyrClock` timebase.
const TICK_HZ: u32 = wz::runtime_zephyr::tick_hz_from_build!();

/// The port the node listens on: zenoh's default.
const LISTEN_PORT: u16 = 7447;

/// The largest batch the node's sessions negotiate. Its receive buffers are this
/// big plus the slack a link adds, so a board with a small heap pays for what a
/// session can carry, not for the largest datagram UDP allows.
const BATCH_SIZE: u16 = 1500;

/// Writes are PERMITTED on this node: upstream's default is to refuse, and the
/// node opts in, because being reconfigured is what it is for.
static CONTROL: ConnectControl = ConnectControl::new(true);
static STATUS: NodeStatus = NodeStatus::new(true);

/// What a board's network stack gives the node, beyond the links themselves.
pub trait NodeNet {
    /// The links the node opens: one that accepts, one per endpoint it dials.
    type Links: SessionLinks + 'static;

    /// The node's links.
    fn links(&self) -> Rc<Self::Links>;

    /// The IPv4 addresses the node advertises as its locators, as its interfaces
    /// hold them: one per link. The accepting socket is bound on every interface, so
    /// a host reaches the node on whichever of them it shares a network with, and the
    /// node tells it all of them.
    fn addresses(&self) -> Vec<[u8; 4]>;

    /// The node's zenoh id: 1 to 16 bytes, unique per board on a network.
    fn zid(&self) -> Vec<u8>;

    /// One pass of the stack's own work. A stack that runs on its own threads
    /// (Zephyr's) has none; one polled from this thread (lwIP) moves its input
    /// and timers here.
    fn pump(&mut self) {}
}

/// zenoh 1.x's handshake shape, with a batch the MCU's receive slot holds whole.
fn params(zid: &[u8], signing_key: &[u8]) -> SessionInitParams {
    SessionInitParams {
        version: 0x09,
        whatami: WhatAmI::Peer,
        zid: zid.to_vec(),
        seq_num_res: 2,
        req_id_res: 2,
        batch_size: BATCH_SIZE,
        lease_ms: 10_000,
        initial_sn: 0,
        cookie: Vec::new(),
        tx_queue: wz_session_core::session_init_params::TxQueueConf::default(),
        cookie_signing_key: SigningKey::new(signing_key.to_vec()).expect("32-byte key"),
    }
}

fn locator(address: [u8; 4]) -> String {
    let [a, b, c, d] = address;
    format!("udp/{a}.{b}.{c}.{d}:{LISTEN_PORT}")
}

/// Assemble the node over `net` and run it. Returns only when it cannot start;
/// the value is the reason, as a nonzero code the C `main()` prints.
fn run<N: NodeNet>(mut net: N) -> i32 {
    // The cookie-signing key is a secret, so it comes from the board's entropy
    // source and a board that cannot supply it stops the node: a predictable key
    // is worse than no node.
    let mut key = [0u8; 32];
    if ZephyrEntropy.try_fill_bytes(&mut key).is_err() {
        log(c"wz: FAIL - the board's entropy source could not fill the signing key");
        return 2;
    }

    let clock = ZephyrClock::<TICK_HZ>;
    let runtime = CoopRuntime::new(clock);
    let local = CoopLocalSet::new(&runtime);
    let zid = net.zid();
    let zid_hex = zid_to_zenoh_hex(&zid);
    let locators: Vec<String> = net.addresses().into_iter().map(locator).collect();
    let accept_runtime = runtime.clone();
    let (dial_zid, accept_zid) = (zid.clone(), zid.clone());
    let mut node = AdminNode::new(
        &local,
        net.links(),
        &CONTROL,
        &STATUS,
        NodeIdentity {
            zid_hex: zid_hex.clone(),
            whatami: "peer",
            version: String::from("wz-zephyr-admin-node"),
            locators: locators.clone(),
        },
        LISTEN_PORT,
        SessionTimeouts::spec_defaults(),
        move || params(&dial_zid, &key),
        move |sink| {
            new_session_actions(
                sink,
                params(&accept_zid, &key),
                CoopTime::new(&accept_runtime),
                ZephyrEntropy,
            )
        },
    );
    // The line a lane (or a person at the console) waits for: who the node claims
    // to be and where it is, one locator per link.
    log_line(format!(
        "ZEPHYR-WZ-ADMIN READY {} {}",
        zid_hex,
        locators.join(" ")
    ));

    let mut reported = 0;
    let mut generation = None;
    loop {
        local.run_until_idle();
        net.pump();
        node.tick(clock.now_us() / 1000);

        let (written, endpoints) = CONTROL.endpoints();
        if generation != Some(written) {
            generation = Some(written);
            log_line(format!(
                "zephyr-admin-node: connect/endpoints = {endpoints:?}"
            ));
        }
        let sessions = STATUS.sessions();
        if sessions.len() != reported {
            reported = sessions.len();
            for s in &sessions {
                log_line(format!(
                    "zephyr-admin-node: session with {} ({:?})",
                    s.peer_zid_hex, s.whatami
                ));
            }
            log_line(format!("zephyr-admin-node: {reported} session(s)"));
        }
        // The net stack's own threads, and the tick, need this thread's CPU.
        yield_ms(1);
    }
}

#[cfg(not(any(feature = "net-zephyr-sockets", feature = "net-lwip-mac")))]
compile_error!(
    "no network backend: CMakeLists.txt turns on exactly one `net-*` feature from the \
     board's CONFIG_WZ_NET_BACKEND_*"
);

#[cfg(all(feature = "net-zephyr-sockets", feature = "net-lwip-mac"))]
compile_error!(
    "two network backends: a node runs over one stack, and CMakeLists.txt turns on exactly \
     one `net-*` feature"
);

#[cfg(all(feature = "net-lwip-mac", not(feature = "mac-cyt4bf")))]
compile_error!(
    "the lwIP backend needs a MAC: CMakeLists.txt turns on the `mac-*` feature of CONFIG_WZ_MAC_*"
);

#[cfg(all(feature = "spi-probe", not(feature = "mac-cyt4bf")))]
compile_error!("the SPI probe is the CYT4BF kit's: it needs the `mac-cyt4bf` feature's board");

/// Read the TC6 identity registers of whatever is plugged into the kit's MikroBUS
/// socket and log them. Read-only: two control reads, `OA_ID` (the interface
/// version) and `OA_PHYID` (the PHY's vendor, model and revision), which every TC6
/// device has at the same addresses, so this works on a chip nothing here knows.
///
/// What a lab does with it: plug the expansion board in, flash this, and read the
/// two lines. A device that answers gives its identity; one that does not gives
/// the way it did not (a read of all zeros or all ones is a bus nobody drives, a
/// header echo that does not match is a device that is not speaking the interface).
/// Either is a fact about the board that no document had to supply.
///
/// SPI mode 0 and eight-bit elements are how Zephyr's own TC6 chip driver opens its
/// device (it passes only the word size, so no clock polarity or phase flag), and
/// the rate is `CONFIG_WZ_SPI_PROBE_HZ`, which is a probe's, kept well under any
/// TC6 chip's limit: this reads an identity and moves no frame.
#[cfg(feature = "spi-probe")]
fn probe_tc6() {
    use wz::runtime_zephyr::u32_from_build;
    use wz_oa_tc6::proto::std_reg;
    use wz_oa_tc6::{ChunkSize, Tc6};
    use wz_spi_scb::SpiMode;

    const PROBE_HZ: u32 = u32_from_build!("WZ_SPI_PROBE_HZ");

    let (spi, rate) = match spi_cyt4bf::open(SpiMode::Mode0, PROBE_HZ) {
        Ok(opened) => opened,
        Err(why) => {
            log(why);
            return;
        }
    };
    log_line(format!(
        "wz: spi probe: SCB3, mode 0, {} Hz (divider {}, oversample {})",
        rate.achieved_hz, rate.divider, rate.oversample
    ));
    let mut tc6 = Tc6::new(spi, ChunkSize::B64);
    for (name, reg) in [("OA_ID", std_reg::ID), ("OA_PHYID", std_reg::PHYID)] {
        match tc6.reg_read(reg) {
            Ok(value) => log_line(format!("wz: spi probe: {name} = {value:#010x}")),
            Err(why) => log_line(format!("wz: spi probe: {name} not read: {why:?}")),
        }
    }
}

/// Bring the board's network up and run the node over it.
#[cfg(feature = "net-zephyr-sockets")]
fn start() -> i32 {
    match net_zephyr::ZephyrNet::bring_up() {
        Ok(net) => run(net),
        Err(why) => {
            log(why);
            1
        }
    }
}

/// The lwIP backend over the CYT4BF's ETH0. Every board value comes from the
/// environment the board's build sets (Kconfig): the addresses, the MAC address,
/// the reference clock and how long to wait for a link.
#[cfg(all(feature = "net-lwip-mac", feature = "mac-cyt4bf"))]
fn start() -> i32 {
    use net_lwip::{Addressing, LwipMacNet};
    use wz::runtime_zephyr::{ipv4_from_build, parse_mac, random_station_address, u32_from_build};
    use wz_eth_mac_cyt4bf::RefClock;

    // The address this build was given for this board, when it was given one
    // (CONFIG_WZ_MAC_SOURCE_EXPLICIT). A build that was not draws one at every
    // start: there is no value it falls back to, because one every build shares is
    // one two boards on a network would both answer to.
    const GIVEN_MAC: Option<[u8; 6]> = match option_env!("WZ_MAC_ADDRESS") {
        Some(text) => Some(parse_mac(text)),
        None => None,
    };
    const ADDRESSING: Addressing = Addressing {
        address: ipv4_from_build!("WZ_STATIC_IPV4"),
        netmask: ipv4_from_build!("WZ_STATIC_NETMASK"),
        gateway: ipv4_from_build!("WZ_STATIC_GATEWAY"),
    };
    // 0 says the PHY supplies the reference clock; anything else is the divider of
    // the internal PLL the MAC supplies it from.
    const REF_CLOCK_DIVIDER: u32 = u32_from_build!("WZ_REF_CLOCK_DIVIDER");
    const LINK_WAIT_MS: u32 = u32_from_build!("WZ_LINK_WAIT_MS");

    let ref_clock = match REF_CLOCK_DIVIDER {
        0 => RefClock::External,
        divider => RefClock::InternalPll {
            divider: divider.min(u16::MAX as u32) as u16,
        },
    };
    let station = match GIVEN_MAC {
        Some(given) => given,
        None => match random_station_address(&mut ZephyrEntropy) {
            Ok(drawn) => drawn,
            Err(_) => {
                log(c"wz: FAIL - the board's entropy source could not make a station address");
                return 1;
            }
        },
    };
    log_line(format!(
        "wz: station address {:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x} ({})",
        station[0],
        station[1],
        station[2],
        station[3],
        station[4],
        station[5],
        if GIVEN_MAC.is_some() {
            "given"
        } else {
            "drawn at this boot"
        }
    ));
    // What is on the MikroBUS socket, read before the network is started: a probe
    // that logs and returns, which is why it needs no link and no clock.
    #[cfg(feature = "spi-probe")]
    probe_tc6();
    let mac = match mac_cyt4bf::open(station, ref_clock, LINK_WAIT_MS) {
        Ok(mac) => mac,
        Err(why) => {
            log(why);
            return 1;
        }
    };
    let mut net = LwipMacNet::start();
    if let Err(why) = net.add_port(mac, ADDRESSING) {
        log(why);
        return 1;
    }
    run(net)
}

/// Entry point the Zephyr C `main()` calls. Returns nonzero only when the node
/// could not start; a running node never returns.
#[no_mangle]
pub extern "C" fn wz_app_main() -> i32 {
    start()
}
