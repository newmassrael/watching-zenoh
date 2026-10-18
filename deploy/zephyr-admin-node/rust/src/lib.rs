// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
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

// S9e -- the heap profile's: the growable node, the Zephyr sockets' stack and the console
// lines built on the heap. A build of the fixed-memory profile with the defaults off links
// no `alloc` crate, and declares no allocator (`zephyr_image_no_heap!` below).
#[cfg(feature = "heap")]
extern crate alloc;

// The growable node's imports (S9c: the `fixed-memory` profile runs `fixed_node`'s
// instead, over statics, and the heap node does not exist in it).
#[cfg(not(feature = "fixed-memory"))]
use alloc::format;
#[cfg(not(feature = "fixed-memory"))]
use alloc::rc::Rc;
#[cfg(not(feature = "fixed-memory"))]
use alloc::string::String;
#[cfg(not(feature = "fixed-memory"))]
use alloc::vec::Vec;

#[cfg(not(feature = "fixed-memory"))]
use wz::runtime_coop::session_drive::SessionLinks;
#[cfg(not(feature = "fixed-memory"))]
use wz::runtime_coop::session_runtime::new_session_actions;
#[cfg(any(not(feature = "fixed-memory"), feature = "mac-cyt4bf"))]
use wz::runtime_coop::ClockSource;
#[cfg(not(feature = "fixed-memory"))]
use wz::runtime_coop::{CoopLocalSet, CoopRuntime, CoopTime};
use wz::runtime_zephyr::core_clock::{assess_core_clock, CoreClockOutcome};
use wz::runtime_zephyr::glue::{core_clock_hz, log, log_args};
#[cfg(not(feature = "fixed-memory"))]
use wz::runtime_zephyr::glue::{log_line, stack_usage, yield_us};
#[cfg(not(feature = "fixed-memory"))]
use wz::runtime_zephyr::stack::StackWatch;
#[cfg(any(not(feature = "fixed-memory"), feature = "mac-cyt4bf"))]
use wz::runtime_zephyr::ZephyrClock;
use wz::runtime_zephyr::ZephyrEntropy;
#[cfg(not(feature = "fixed-memory"))]
use wz_session_core::entropy::EntropySource;
#[cfg(not(feature = "fixed-memory"))]
use wz_session_core::session_init_params::SessionInitParams;
#[cfg(not(feature = "fixed-memory"))]
use wz_session_core::session_timeouts::SessionTimeouts;
#[cfg(not(feature = "fixed-memory"))]
use wz_session_core::signing_key::SigningKey;
#[cfg(not(feature = "fixed-memory"))]
use wz_session_core::zid_hex::zid_to_zenoh_hex;
#[cfg(not(feature = "fixed-memory"))]
use wz_session_core::WhatAmI;
#[cfg(not(feature = "fixed-memory"))]
use wz_session_mcu::admin_host::ConnectControl;
#[cfg(not(feature = "fixed-memory"))]
use wz_session_mcu::admin_node::AdminNode;
#[cfg(not(feature = "fixed-memory"))]
use wz_session_mcu::admin_status::{NodeIdentity, NodeStatus};

#[cfg(feature = "fixed-memory")]
mod fixed_node;
#[cfg(feature = "mac-cyt4bf")]
mod mac_cyt4bf;
#[cfg(feature = "t1s-lan865x")]
mod mac_lan865x;
#[cfg(feature = "net-lwip-mac")]
mod net_lwip;
#[cfg(feature = "net-zephyr-sockets")]
mod net_zephyr;
#[cfg(any(feature = "spi-probe", feature = "t1s-lan865x"))]
mod spi_cyt4bf;
// The allocator over the kernel heap (`CONFIG_HEAP_MEM_POOL_SIZE` in prj.conf),
// the critical section over the kernel IRQ lock and the panic handler.
#[cfg(feature = "heap")]
wz::runtime_zephyr::zephyr_image!();
// The same without the allocator: a build that allocates anywhere in its graph does not
// link, which is what the no-allocator link gate takes as its proof.
#[cfg(not(feature = "heap"))]
wz::runtime_zephyr::zephyr_image_no_heap!();

/// How often the node reads its stack's high-water mark. The read walks the whole
/// stack, so it is made a few times a second and not on every pass of the loop;
/// the mark persists, so a peak between two reads is not lost.
const STACK_CHECK_MS: u64 = 250;

/// The board's `CONFIG_SYS_CLOCK_TICKS_PER_SEC`, as this build was configured:
/// the `ZephyrClock` timebase.
const TICK_HZ: u32 = wz::runtime_zephyr::tick_hz_from_build!();

/// What an idle pass of the loop sleeps: one kernel tick, and no more than a
/// millisecond. The kernel rounds a sleep up to its tick, so a board that ticks at
/// 10 kHz is given its 100 microseconds and a board that ticks at 100 Hz is asked for
/// the millisecond it has always been asked for (and gets its tick, as before).
const IDLE_SLEEP_US: i32 = {
    let tick_us = 1_000_000 / TICK_HZ;
    if tick_us > 1_000 {
        1_000
    } else {
        tick_us as i32
    }
};

/// How many passes in a row may skip the sleep because the one before took a frame
/// in: a stream of frames cannot keep this thread from ever giving the CPU away.
const BUSY_PASSES_MAX: u32 = 64;

/// The core clock this image was built for: the board's
/// `CONFIG_SYS_CLOCK_HW_CYCLES_PER_SEC`, from which the kernel derives every tick and
/// every busy wait, as the board's build handed it to cargo. Whether the core really
/// runs at it is checked at boot (`check_core_clock`).
const IMAGE_CORE_CLOCK_HZ: u32 = wz::runtime_zephyr::u32_from_build!("WZ_CORE_CLOCK_HZ");

/// Milliseconds since boot by the kernel's own tick count. Stage lines carry it so
/// that a bench can set it against a wall clock, which is the one check of the
/// board's time base that needs no instrument.
#[cfg(feature = "mac-cyt4bf")]
fn uptime_ms() -> u64 {
    ZephyrClock::<TICK_HZ>.now_us() / 1000
}

/// The port the node listens on: zenoh's default.
const LISTEN_PORT: u16 = 7447;

/// The largest IP packet one Ethernet frame carries: the MTU of every interface
/// this node runs on (Zephyr's Ethernet interfaces, and the lwIP netif, whose
/// shim sets `mtu = 1500`).
const ETHERNET_MTU: usize = 1500;
/// The IPv4 header with no options, which is what lwIP and a host's stack send.
const IPV4_HEADER: usize = 20;
/// The UDP header.
const UDP_HEADER: usize = 8;

/// The largest batch the node's sessions negotiate: 1500 - 20 - 8 = 1472, the
/// largest UDP payload one Ethernet frame carries whole. A router takes the
/// smaller of its batch and the node's, so no datagram of the node's sessions
/// needs IP fragmentation, in either direction: lwIP copies a datagram it
/// reassembles (the receive pool's HW.35), and a fragment is not a frame whose
/// UDP checksum the transmit pool's HW.30 can check. A batch of 1500, as this
/// was, let a full batch cross the link in two fragments. Its receive buffers
/// are this big plus the slack a link adds, so a board with a small heap pays for
/// what a session can carry, not for the largest datagram UDP allows.
const BATCH_SIZE: u16 = (ETHERNET_MTU - IPV4_HEADER - UDP_HEADER) as u16;

/// Writes are PERMITTED on this node: upstream's default is to refuse, and the
/// node opts in, because being reconfigured is what it is for.
#[cfg(not(feature = "fixed-memory"))]
static CONTROL: ConnectControl = ConnectControl::new(true);
#[cfg(not(feature = "fixed-memory"))]
static STATUS: NodeStatus = NodeStatus::new(true);

/// What a board's network stack gives the node, beyond the links themselves.
#[cfg(not(feature = "fixed-memory"))]
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
    /// and timers here. True when a frame came in, so the node has work the next pass
    /// should not wait for; a stack with no pass of its own answers false and the loop
    /// gives the CPU away every time, as it always did.
    fn pump(&mut self) -> bool {
        false
    }
}

/// zenoh 1.x's handshake shape, with a batch the MCU's receive slot holds whole.
#[cfg(not(feature = "fixed-memory"))]
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

#[cfg(not(feature = "fixed-memory"))]
fn locator(address: [u8; 4]) -> String {
    let [a, b, c, d] = address;
    format!("udp/{a}.{b}.{c}.{d}:{LISTEN_PORT}")
}

/// Assemble the node over `net` and run it. Returns only when it cannot start;
/// the value is the reason, as a nonzero code the C `main()` prints.
#[cfg(not(feature = "fixed-memory"))]
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
    let node = AdminNode::new(
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
    // A node whose observer refused its admin keys would run without its admin
    // space: stop instead, with the reason.
    let mut node = match node {
        Ok(node) => node,
        Err(_) => {
            log(c"wz: FAIL - the node's observer refused its admin queryable or config subscriber");
            return 3;
        }
    };
    // The line a lane (or a person at the console) waits for: who the node claims
    // to be and where it is, one locator per link.
    log_line(format!(
        "ZEPHYR-WZ-ADMIN READY {} {}",
        zid_hex,
        locators.join(" ")
    ));

    let mut reported = 0;
    let mut generation = None;
    // The node is the stack's only tenant, so its own reading of it is the one that
    // counts: a line when the peak grows, which a lane reads the last of.
    let mut stack = StackWatch::new();
    let mut next_stack_check_ms = 0u64;
    let mut busy_passes = 0u32;
    loop {
        local.run_until_idle();
        let worked = net.pump();
        let now_ms = clock.now_us() / 1000;
        node.tick(now_ms);
        if now_ms >= next_stack_check_ms {
            next_stack_check_ms = now_ms + STACK_CHECK_MS;
            if let Some(line) = stack.observe(stack_usage()) {
                log_line(line);
            }
        }

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
        // The net stack's own threads, and the tick, need this thread's CPU. A pass that
        // took a frame in has work the next pass does at once (the session reads it and
        // answers), so it does not wait first, for at most BUSY_PASSES_MAX in a row.
        if worked && busy_passes < BUSY_PASSES_MAX {
            busy_passes += 1;
        } else {
            busy_passes = 0;
            yield_us(IDLE_SLEEP_US);
        }
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

#[cfg(not(any(feature = "heap", feature = "fixed-memory")))]
compile_error!(
    "no memory profile: `heap` (the growable node over the kernel heap, the default) or \
     `fixed-memory` (the slot profile's node over statics, with the defaults off)"
);

#[cfg(all(feature = "fixed-memory", not(feature = "net-lwip-mac")))]
compile_error!(
    "the fixed-memory node is the lwIP one: its sessions are opened by the slot profile's \
     session host, which owns the tables of one stack, and Zephyr's sockets have none yet"
);

#[cfg(all(feature = "net-lwip-mac", not(feature = "mac-cyt4bf")))]
compile_error!(
    "the lwIP backend needs a MAC: CMakeLists.txt turns on the `mac-*` feature of CONFIG_WZ_MAC_*"
);

#[cfg(all(feature = "spi-probe", not(feature = "mac-cyt4bf")))]
compile_error!("the SPI probe is the CYT4BF kit's: it needs the `mac-cyt4bf` feature's board");

#[cfg(all(feature = "t1s-lan865x", not(feature = "mac-cyt4bf")))]
compile_error!(
    "the 10BASE-T1S interface is the CYT4BF kit's: it needs the `mac-cyt4bf` feature's board"
);

#[cfg(all(feature = "spi-probe", feature = "t1s-lan865x"))]
compile_error!(
    "the SPI probe and the 10BASE-T1S interface both open SCB3: a build has one of them"
);

/// Read the identity registers of whatever is plugged into the kit's MikroBUS
/// socket and log them. Read-only: three control reads. `OA_ID` (the interface
/// version) and `OA_PHYID` (the PHY's vendor, model and revision) are the standard
/// registers every TC6 device has at the same addresses, so those two work on a
/// chip nothing here knows.
///
/// The third, `DEVID`, is the LAN8650/1's own and means nothing on another chip
/// (the line says only what was read). It is there because `OA_PHYID` cannot do
/// the job it appears to: on the LAN8650/1 it reflects the integrated PHY's
/// clause 22 ID, so it names neither the product nor its silicon revision (the
/// errata, item s1). The register that does is `DEVID`, memory map selector 10,
/// address 0x0094: `MODEL` in bits 19:4 (0x8650 is the LAN8650, 0x8651 the
/// LAN8651) and `REV` in bits 3:0 (1 is product revision B0, 2 is B1).
///
/// What a lab does with it: plug the expansion board in, flash this, and read the
/// lines. A device that answers gives its identity; one that does not gives the way
/// it did not (a read of all zeros or all ones is a bus nobody drives, a header
/// echo that does not match is a device that is not speaking the interface).
/// Either is a fact about the board that no document had to supply.
///
/// SPI mode 0 and eight-bit elements are how Zephyr's own TC6 chip driver opens its
/// device (it passes only the word size, so no clock polarity or phase flag), and
/// the rate is `CONFIG_WZ_SPI_PROBE_HZ`, which is a probe's, kept well under any
/// TC6 chip's limit: this reads an identity and moves no frame.
#[cfg(feature = "spi-probe")]
fn probe_tc6() {
    use wz::runtime_zephyr::u32_from_build;
    use wz_oa_tc6::proto::{std_reg, Reg};
    use wz_oa_tc6::{ChunkSize, Tc6};
    use wz_spi_scb::SpiMode;

    const PROBE_HZ: u32 = u32_from_build!("WZ_SPI_PROBE_HZ");
    /// `DEVID` of the LAN8650/1 (data sheet DS60001734, register description
    /// "Device Identification"; errata DS80001075 item s1 names the address and
    /// the memory map selector).
    const LAN865X_DEVID: Reg = Reg::new(10, 0x0094);

    let (spi, rate) = match spi_cyt4bf::open(SpiMode::Mode0, PROBE_HZ) {
        Ok(opened) => opened,
        Err(why) => {
            log(why);
            return;
        }
    };
    log_args(format_args!(
        "wz: spi probe: SCB3, mode 0, {} Hz (divider {}, oversample {})",
        rate.achieved_hz, rate.divider, rate.oversample
    ));
    let mut tc6 = Tc6::new(spi, ChunkSize::B64);
    for (name, reg) in [("OA_ID", std_reg::ID), ("OA_PHYID", std_reg::PHYID)] {
        match tc6.reg_read(reg) {
            Ok(value) => log_args(format_args!("wz: spi probe: {name} = {value:#010x}")),
            Err(why) => log_args(format_args!("wz: spi probe: {name} not read: {why:?}")),
        }
    }
    match tc6.reg_read(LAN865X_DEVID) {
        Ok(value) => log_args(format_args!(
            "wz: spi probe: DEVID = {value:#010x} (MODEL {:#06x}, REV {})",
            (value >> 4) & 0xFFFF,
            value & 0xF
        )),
        Err(why) => log_args(format_args!("wz: spi probe: DEVID not read: {why:?}")),
    }
    log_args(format_args!(
        "wz: spi probe: done (kernel uptime {} ms)",
        uptime_ms()
    ));
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

/// The address the build gave the onboard port's MAC, when it was given one
/// (CONFIG_WZ_MAC_SOURCE_EXPLICIT). A build that was not draws one at every
/// start: there is no value it falls back to, because one every build shares is
/// one two boards on a network would both answer to.
#[cfg(all(feature = "net-lwip-mac", feature = "mac-cyt4bf"))]
const GIVEN_MAC: Option<[u8; 6]> = match option_env!("WZ_MAC_ADDRESS") {
    Some(text) => Some(wz::runtime_zephyr::parse_mac(text)),
    None => None,
};

/// The onboard port's addresses, from the board's Kconfig.
#[cfg(all(feature = "net-lwip-mac", feature = "mac-cyt4bf"))]
const ADDRESSING: net_lwip::Addressing = net_lwip::Addressing {
    address: wz::runtime_zephyr::ipv4_from_build!("WZ_STATIC_IPV4"),
    netmask: wz::runtime_zephyr::ipv4_from_build!("WZ_STATIC_NETMASK"),
    gateway: wz::runtime_zephyr::ipv4_from_build!("WZ_STATIC_GATEWAY"),
};

/// The 10BASE-T1S interface as a second port of the node: its station address
/// (given by the build or drawn, and never the onboard port's), its chip, and its
/// addresses from the board's Kconfig.
///
/// The two interfaces must not sit on one network, and when both addresses are given
/// they must differ; a build that breaks either does not compile, so the node never
/// runs with an interface the stack cannot tell from the other.
#[cfg(all(
    feature = "net-lwip-mac",
    feature = "mac-cyt4bf",
    feature = "t1s-lan865x"
))]
fn add_t1s(
    net: &mut net_lwip::LwipMacNet,
    onboard_station: [u8; 6],
) -> Result<(), &'static core::ffi::CStr> {
    use net_lwip::Addressing;
    use wz::runtime_zephyr::{
        ipv4_from_build, ipv4_networks_overlap, mac_addresses_equal, parse_mac,
        random_station_address,
    };

    const GIVEN_T1S_MAC: Option<[u8; 6]> = match option_env!("WZ_T1S_MAC_ADDRESS") {
        Some(text) => Some(parse_mac(text)),
        None => None,
    };
    const T1S_ADDRESSING: Addressing = Addressing {
        address: ipv4_from_build!("WZ_T1S_IPV4"),
        netmask: ipv4_from_build!("WZ_T1S_NETMASK"),
        gateway: ipv4_from_build!("WZ_T1S_GATEWAY"),
    };
    const _: () = assert!(
        !ipv4_networks_overlap(
            ADDRESSING.address,
            ADDRESSING.netmask,
            T1S_ADDRESSING.address,
            T1S_ADDRESSING.netmask
        ),
        "the 10BASE-T1S interface is on the onboard port's network: CONFIG_WZ_T1S_IPV4 and \
         CONFIG_WZ_STATIC_IPV4 must be on different networks"
    );
    const _: () = {
        if let (Some(onboard), Some(t1s)) = (GIVEN_MAC, GIVEN_T1S_MAC) {
            assert!(
                !mac_addresses_equal(onboard, t1s),
                "the 10BASE-T1S interface has the onboard port's station address"
            );
        }
    };

    let station = match GIVEN_T1S_MAC {
        Some(given) => given,
        None => random_station_address(&mut ZephyrEntropy).map_err(|_| {
            c"wz: FAIL - the board's entropy source could not make the 10BASE-T1S station address"
        })?,
    };
    if mac_addresses_equal(station, onboard_station) {
        // Two draws of 46 bits agreeing: not a thing to run on, and not one to retry
        // until it is hidden.
        return Err(c"wz: FAIL - the 10BASE-T1S station address is the onboard port's");
    }
    log_args(format_args!(
        "wz: 10BASE-T1S station address {:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x} ({})",
        station[0],
        station[1],
        station[2],
        station[3],
        station[4],
        station[5],
        if GIVEN_T1S_MAC.is_some() {
            "given"
        } else {
            "drawn at this boot"
        }
    ));
    let mac = mac_lan865x::open(station)?;
    net.add_port(mac, T1S_ADDRESSING)
}

/// The lwIP backend over the CYT4BF's ETH0. Every board value comes from the
/// environment the board's build sets (Kconfig): the addresses, the MAC address,
/// the reference clock and how long to wait for a link.
#[cfg(all(feature = "net-lwip-mac", feature = "mac-cyt4bf"))]
fn start() -> i32 {
    use net_lwip::LwipMacNet;
    use wz::runtime_zephyr::{random_station_address, u32_from_build};
    use wz_eth_mac_cyt4bf::RefClock;

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
    log_args(format_args!(
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
    // The second interface goes in after the onboard one: the node's id is the first
    // port's station address, and the default route belongs to the first port with a
    // gateway, so the order is what keeps both from moving when this one is added.
    #[cfg(feature = "t1s-lan865x")]
    if let Err(why) = add_t1s(&mut net, station) {
        log(why);
        return 1;
    }
    #[cfg(not(feature = "fixed-memory"))]
    return run(net);
    // S9c -- the same node over the statics of `fixed_node`.
    #[cfg(feature = "fixed-memory")]
    fixed_node::run(net)
}

/// What `wz_app_main` returns when the core does not run at the clock the image
/// was built for.
const CORE_CLOCK_MISMATCH: i32 = 3;

/// Does the core run at the clock the image assumes? Logs what it found, and returns
/// the code to stop with when it does not.
///
/// This is the first thing the node does, before anything that waits: a core that
/// runs at 8 MHz where 350 MHz was assumed (a CM0+ image that started the M7 without
/// bringing the clock tree up) makes every wait last tens of times what it was asked
/// to, and the node then prints nothing for minutes. A board that cannot read its
/// clock says nothing here, so the console of an emulated board is unchanged.
fn check_core_clock() -> Option<i32> {
    // The CYT4BF's hook reads clock registers, so a reading of nothing is news there;
    // elsewhere it is the ordinary answer.
    let board_reads_clock = cfg!(feature = "mac-cyt4bf");
    match assess_core_clock(core_clock_hz(), IMAGE_CORE_CLOCK_HZ, board_reads_clock) {
        CoreClockOutcome::Silent => None,
        CoreClockOutcome::Report(line) => {
            log_args(format_args!("{line}"));
            None
        }
        CoreClockOutcome::Stop(line) => {
            log_args(format_args!("{line}"));
            Some(CORE_CLOCK_MISMATCH)
        }
    }
}

/// Entry point the Zephyr C `main()` calls. Returns nonzero only when the node
/// could not start; a running node never returns.
#[no_mangle]
pub extern "C" fn wz_app_main() -> i32 {
    if let Some(stop) = check_core_clock() {
        return stop;
    }
    start()
}
