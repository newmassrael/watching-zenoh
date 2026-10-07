// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The admin node over lwIP, polled from this thread, on Ethernet MACs a wz crate
//! drives.
//!
//! For a board whose Ethernet controller Zephyr has no driver for. Zephyr is the
//! kernel (threads, clock, heap, console) and nothing of its network stack is
//! built; lwIP runs `NO_SYS`, each MAC is a `wz_runtime_core::EthernetMac`, and the
//! node's loop is what moves frames and timers. The addresses are the board's
//! Kconfig, read at compile time from the environment the board's build sets: no
//! Zephyr interface exists to ask, and no address is typed into this file.
//!
//! One image may carry TWO links (the lwIP shim's interface table holds two): an
//! on-board RMII and a 10BASE-T1S MAC-PHY on SPI are the pair the T2G board is
//! meant to run together. Each is a port; the accepting socket is bound on every
//! interface, the locators advertised are all of them, and the one default route
//! belongs to the first port with a gateway.

use alloc::boxed::Box;
use alloc::rc::Rc;
use alloc::vec::Vec;
use core::ffi::CStr;

use wz::link_lwip::ethernet::{EthernetIf, Ipv4Config};
use wz::link_lwip::LwipLink;
use wz::runtime_coop::ClockSource;
use wz::runtime_core::EthernetMac;
use wz::runtime_zephyr::ZephyrClock;
use wz::session_lwip::LwipLinks;

use crate::{NodeNet, TICK_HZ};

/// A MAC the board brings up: the frames it carries, and the housekeeping its link
/// needs between them (a PHY's negotiation is not a frame).
pub trait BoardMac: EthernetMac + 'static {
    /// Called every pass of the node's loop with a millisecond clock; a MAC rate
    /// limits itself.
    fn service(&mut self, now_ms: u64);
}

/// lwIP's `NO_SYS` clock, in milliseconds: ARP, the IGMP report timers and every
/// other lwIP timer run off it.
#[no_mangle]
pub extern "C" fn sys_now() -> u32 {
    (ZephyrClock::<TICK_HZ>.now_us() / 1000) as u32
}

/// The addresses of one interface, from the board's configuration.
#[derive(Clone, Copy)]
pub struct Addressing {
    pub address: [u8; 4],
    pub netmask: [u8; 4],
    pub gateway: [u8; 4],
}

/// One interface of the node, with the MAC's type erased: the node's loop does the
/// same two things to each, whatever chip is under it.
trait Port {
    fn poll(&mut self);
    fn service(&mut self, now_ms: u64);
}

struct MacPort<M: BoardMac>(EthernetIf<M>);

impl<M: BoardMac> Port for MacPort<M> {
    fn poll(&mut self) {
        self.0.poll();
    }

    fn service(&mut self, now_ms: u64) {
        self.0.with_mac(|mac| mac.service(now_ms));
    }
}

pub struct LwipMacNet {
    link: Rc<LwipLink>,
    ports: Vec<Box<dyn Port>>,
    links: Rc<LwipLinks>,
    addresses: Vec<[u8; 4]>,
    zid: Vec<u8>,
}

impl LwipMacNet {
    /// Start lwIP with no interface yet: add the board's ports with
    /// [`add_port`](Self::add_port).
    pub fn start() -> Self {
        let link = Rc::new(LwipLink::init());
        let links = Rc::new(LwipLinks::new(link.clone()));
        Self {
            link,
            ports: Vec::new(),
            links,
            addresses: Vec::new(),
            zid: Vec::new(),
        }
    }

    /// Put `mac` under lwIP as an Ethernet interface with the given addresses.
    ///
    /// The node's zenoh id is the FIRST port's MAC address: unique per NIC, the
    /// same on every boot, and the same whichever link a host reached the node on.
    pub fn add_port<M: BoardMac>(
        &mut self,
        mac: M,
        addressing: Addressing,
    ) -> Result<(), &'static CStr> {
        if self.ports.is_empty() {
            self.zid = mac.mac_address().to_vec();
        }
        let ethernet = EthernetIf::add(
            &self.link,
            mac,
            Ipv4Config {
                address: addressing.address,
                netmask: addressing.netmask,
                gateway: addressing.gateway,
            },
        )
        .map_err(|_| c"wz: FAIL - lwIP refused an Ethernet interface")?;
        self.addresses.push(addressing.address);
        self.ports.push(Box::new(MacPort(ethernet)));
        Ok(())
    }
}

impl NodeNet for LwipMacNet {
    type Links = LwipLinks;

    fn links(&self) -> Rc<LwipLinks> {
        self.links.clone()
    }

    fn addresses(&self) -> Vec<[u8; 4]> {
        self.addresses.clone()
    }

    fn zid(&self) -> Vec<u8> {
        self.zid.clone()
    }

    fn pump(&mut self) {
        // Frames in on every port, then lwIP's timers, then each MAC's own
        // housekeeping: the order the QEMU firmware's loop has, with the link
        // service added.
        for port in &mut self.ports {
            port.poll();
        }
        self.link.check_timeouts();
        let now_ms = ZephyrClock::<TICK_HZ>.now_us() / 1000;
        for port in &mut self.ports {
            port.service(now_ms);
        }
    }
}
