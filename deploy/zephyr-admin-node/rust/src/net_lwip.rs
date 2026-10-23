// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
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

//!
//! # The two forms
//!
//! By default the node's stack is built on the kernel heap: `Rc` handles, a `Vec` of
//! `Box<dyn Port>`, `Vec`s of addresses. With `fixed-memory` (fixed-memory step S9c) it is
//! built in storage this file declares: the interface of each MAC in a cell of a static
//! pool, the ports in a table of two, the sockets in a static pool, the addresses and the
//! zid in arrays. The second form is what `fixed_node` runs over; it has the same
//! `start` / `add_port` the board's bring-up calls, and a port the table has no cell for
//! is refused by name.

#[cfg(not(storage_fixed))]
use alloc::boxed::Box;
#[cfg(not(storage_fixed))]
use alloc::rc::Rc;
#[cfg(not(storage_fixed))]
use alloc::vec::Vec;
use core::ffi::CStr;

#[cfg(storage_fixed)]
use wz::link_lwip::ethernet::EthernetPool;
use wz::link_lwip::ethernet::{EthernetIf, Ipv4Config};
#[cfg(storage_fixed)]
use wz::link_lwip::rx_sockets::SessionRxPool;
use wz::link_lwip::LwipLink;
use wz::runtime_coop::ClockSource;
use wz::runtime_core::EthernetMac;
use wz::runtime_zephyr::ZephyrClock;
#[cfg(not(storage_fixed))]
use wz::session_lwip::LwipLinks;
#[cfg(storage_fixed)]
use wz_session_core::bounded::BoundedVec;

#[cfg(not(storage_fixed))]
use crate::NodeNet;
use crate::TICK_HZ;

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
#[cfg(not(storage_fixed))]
trait Port {
    /// Frames in; how many frames lwIP took.
    fn poll(&mut self) -> usize;
    fn service(&mut self, now_ms: u64);
}

#[cfg(not(storage_fixed))]
struct MacPort<M: BoardMac>(EthernetIf<M>);

#[cfg(not(storage_fixed))]
impl<M: BoardMac> Port for MacPort<M> {
    fn poll(&mut self) -> usize {
        self.0.poll()
    }

    fn service(&mut self, now_ms: u64) {
        self.0.with_mac(|mac| mac.service(now_ms));
    }
}

#[cfg(not(storage_fixed))]
pub struct LwipMacNet {
    link: Rc<LwipLink>,
    ports: Vec<Box<dyn Port>>,
    links: Rc<LwipLinks>,
    addresses: Vec<[u8; 4]>,
    zid: Vec<u8>,
}

#[cfg(not(storage_fixed))]
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

#[cfg(not(storage_fixed))]
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

    fn pump(&mut self) -> bool {
        // Frames in on every port, then lwIP's timers, then each MAC's own
        // housekeeping: the order the QEMU firmware's loop has, with the link
        // service added.
        let mut taken = 0;
        for port in &mut self.ports {
            taken += port.poll();
        }
        self.link.check_timeouts();
        let now_ms = ZephyrClock::<TICK_HZ>.now_us() / 1000;
        for port in &mut self.ports {
            port.service(now_ms);
        }
        taken > 0
    }
}

// ─────────────────────────── the fixed-memory form ───────────────────────────

/// Interfaces the node holds at most: the lwIP shim's interface table holds two (the
/// on-board RMII and the 10BASE-T1S MAC-PHY).
#[cfg(storage_fixed)]
pub const MAX_PORTS: usize = 2;

/// One interface of the node, per MAC type this build can carry. A closed set in place
/// of a `Box<dyn Port>`: the node's loop does the same two things to each, and an enum
/// holds the interface where it is, with no allocation to type-erase it.
#[cfg(storage_fixed)]
pub(crate) enum PortCell {
    Onboard(EthernetIf<crate::mac_cyt4bf::T2gMac>),
    #[cfg(feature = "t1s-lan865x")]
    T1s(EthernetIf<crate::mac_lan865x::T1sMac>),
}

#[cfg(storage_fixed)]
impl PortCell {
    fn poll(&mut self) -> usize {
        match self {
            PortCell::Onboard(eth) => eth.poll(),
            #[cfg(feature = "t1s-lan865x")]
            PortCell::T1s(eth) => eth.poll(),
        }
    }

    fn service(&mut self, now_ms: u64) {
        match self {
            PortCell::Onboard(eth) => eth.with_mac(|mac| mac.service(now_ms)),
            #[cfg(feature = "t1s-lan865x")]
            PortCell::T1s(eth) => eth.with_mac(|mac| mac.service(now_ms)),
        }
    }
}

/// A MAC the fixed-memory node can bring up: where its interface lives, and the cell of
/// [`PortCell`] it is carried in. Implemented here for the chips this build has.
#[cfg(storage_fixed)]
pub trait PortStorage: BoardMac + Sized {
    /// The static cell the MAC's interface is added in (see
    /// `wz::link_lwip::ethernet::EthernetPool`).
    fn pool() -> &'static EthernetPool<Self, 1>;

    /// The interface, as a port of the node.
    fn cell(interface: EthernetIf<Self>) -> PortCell;
}

#[cfg(storage_fixed)]
static ONBOARD_POOL: EthernetPool<crate::mac_cyt4bf::T2gMac, 1> = EthernetPool::new();

#[cfg(storage_fixed)]
impl PortStorage for crate::mac_cyt4bf::T2gMac {
    fn pool() -> &'static EthernetPool<Self, 1> {
        &ONBOARD_POOL
    }

    fn cell(interface: EthernetIf<Self>) -> PortCell {
        PortCell::Onboard(interface)
    }
}

#[cfg(all(storage_fixed, feature = "t1s-lan865x"))]
static T1S_POOL: EthernetPool<crate::mac_lan865x::T1sMac, 1> = EthernetPool::new();

#[cfg(all(storage_fixed, feature = "t1s-lan865x"))]
impl PortStorage for crate::mac_lan865x::T1sMac {
    fn pool() -> &'static EthernetPool<Self, 1> {
        &T1S_POOL
    }

    fn cell(interface: EthernetIf<Self>) -> PortCell {
        PortCell::T1s(interface)
    }
}

/// The session sockets of the node: one for the listener and one per session it dials.
/// The cell count is `fixed_node::SOCKETS`, which sizes it.
#[cfg(storage_fixed)]
pub static SOCKETS: SessionRxPool<{ crate::fixed_node::SOCKETS }> = SessionRxPool::new();

/// The node's stack in storage declared here (`fixed-memory`): `start` and `add_port`
/// are the heap form's, so the board's bring-up does not change, and the rest is what
/// `fixed_node` reads.
#[cfg(storage_fixed)]
pub struct LwipMacNet {
    link: &'static LwipLink,
    ports: BoundedVec<PortCell, MAX_PORTS>,
    addresses: BoundedVec<[u8; 4], MAX_PORTS>,
    zid: [u8; 6],
}

#[cfg(storage_fixed)]
impl LwipMacNet {
    /// Start lwIP with no interface yet: add the board's ports with
    /// [`add_port`](Self::add_port).
    pub fn start() -> Self {
        Self {
            link: LwipLink::init_static(),
            ports: BoundedVec::new(),
            addresses: BoundedVec::new(),
            zid: [0; 6],
        }
    }

    /// Put `mac` under lwIP as an Ethernet interface with the given addresses, in the
    /// static cell of its type.
    ///
    /// The node's zenoh id is the FIRST port's MAC address: unique per NIC, the same on
    /// every boot, and the same whichever link a host reached the node on.
    pub fn add_port<M: PortStorage>(
        &mut self,
        mac: M,
        addressing: Addressing,
    ) -> Result<(), &'static CStr> {
        if self.ports.len() == MAX_PORTS {
            return Err(c"wz: FAIL - the node has no cell for another interface");
        }
        let first = self.ports.is_empty().then(|| mac.mac_address());
        let ethernet = EthernetIf::add_in(
            self.link,
            mac,
            Ipv4Config {
                address: addressing.address,
                netmask: addressing.netmask,
                gateway: addressing.gateway,
            },
            M::pool(),
        )
        .map_err(|_| c"wz: FAIL - lwIP refused an Ethernet interface")?;
        // The capacity was checked above, so neither push can be refused.
        let _ = self.addresses.push(addressing.address);
        let _ = self.ports.push(M::cell(ethernet));
        if let Some(address) = first {
            self.zid = address;
        }
        Ok(())
    }

    /// The stack's witness, which the links and the loop's timer pass need.
    pub fn link(&self) -> &'static LwipLink {
        self.link
    }

    /// The IPv4 addresses the node advertises as its locators: one per port.
    pub fn addresses(&self) -> &[[u8; 4]] {
        &self.addresses
    }

    /// The node's zenoh id: the first port's station address.
    pub fn zid(&self) -> [u8; 6] {
        self.zid
    }

    /// One pass of the stack's own work: frames in on every port, then lwIP's timers,
    /// then each MAC's own housekeeping, in the heap form's order. Whether a frame came
    /// in, which is the pass that has work for the node's loop to do next.
    pub fn pump(&mut self) -> bool {
        let mut taken = 0;
        for port in self.ports.iter_mut() {
            taken += port.poll();
        }
        self.link.check_timeouts();
        let now_ms = ZephyrClock::<TICK_HZ>.now_us() / 1000;
        for port in self.ports.iter_mut() {
            port.service(now_ms);
        }
        taken > 0
    }
}
