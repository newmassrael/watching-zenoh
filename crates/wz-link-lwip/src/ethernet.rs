// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! R2835 — an Ethernet netif whose MAC is a Rust driver.
//!
//! Until now every lwIP stack in this tree ran over the loopback netif alone,
//! which is enough to exercise a session inside one process and not enough to
//! talk to anything outside it. This is the other half: a real Ethernet
//! interface, IPv4 over ARP, with the chip behind
//! [`crate::ethernet::EthernetMac`].
//!
//! The split follows lwIP's own `ethernetif` template. The netif — its flags,
//! `etharp_output`, `ethernet_input`, pbuf handling — is lwIP's and is built
//! in C (`lwip-sys/shim.c`, `wz_ethif_add` / `wz_ethif_input`), since those
//! are struct fields and macros the Rust bindings cannot reliably reach. The
//! MAC is a driver: it sends one whole frame, and it hands whole frames in.
//!
//! Receive is POLLED: [`crate::ethernet::EthernetIf::poll`] moves every frame the MAC holds
//! into lwIP. A firmware calls it each time round its main loop, beside the
//! link's timer pump, which is also what drives ARP's timers.

use alloc::boxed::Box;
use core::cell::RefCell;
use core::ffi::c_void;
use core::ptr::NonNull;

use lwip_sys::{netif, wz_ethif_add, wz_ethif_input};

use crate::LwipLink;

/// The longest frame the netif sends or accepts, without the FCS: a 14-byte
/// header and a 1500-byte MTU. The same bound `shim.c` holds its transmit
/// buffer to.
pub const FRAME_MAX: usize = 1514;

/// An Ethernet MAC: the part of a NIC driver lwIP needs.
pub trait EthernetMac {
    /// The station address this MAC answers to.
    fn mac_address(&self) -> [u8; 6];

    /// Put one whole frame (header and payload, no FCS) on the wire. `false`
    /// when it could not be sent; lwIP counts it as an interface error.
    fn transmit(&mut self, frame: &[u8]) -> bool;

    /// Take the next received frame (no FCS) into `buf` and return its
    /// length, or `None` when nothing is waiting. A frame longer than `buf`
    /// is dropped whole rather than truncated.
    fn receive(&mut self, buf: &mut [u8]) -> Option<usize>;
}

/// Why an interface could not be added.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EthernetIfError {
    /// lwIP refused the interface, or this build's interface table
    /// (`WZ_ETHIF_MAX` in `shim.c`) is full.
    Refused,
}

/// An IPv4 address, mask and gateway, as dotted quads.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Ipv4Config {
    /// This interface's address.
    pub address: [u8; 4],
    /// Its network mask.
    pub netmask: [u8; 4],
    /// The default gateway; `[0, 0, 0, 0]` for none.
    pub gateway: [u8; 4],
}

/// The MAC, shared between the transmit callback lwIP calls and the receive
/// poll this module makes. Never borrowed across the call into lwIP, so a
/// transmit that lwIP makes WHILE handling a received frame (an ARP reply)
/// finds it free.
struct Shared<M> {
    mac: RefCell<M>,
}

/// An Ethernet interface added to lwIP. Lives as long as the firmware:
/// lwIP keeps pointers to it, so it is never removed.
pub struct EthernetIf<M: EthernetMac + 'static> {
    netif: NonNull<netif>,
    shared: &'static Shared<M>,
    rx: Box<[u8; FRAME_MAX]>,
}

unsafe extern "C" fn transmit_trampoline<M: EthernetMac>(
    ctx: *mut c_void,
    frame: *const u8,
    len: u16,
) -> i32 {
    // SAFETY: `ctx` is the `&'static Shared<M>` `EthernetIf::add` registered
    // with this very monomorphisation, and lwIP passes a frame of `len` bytes
    // it owns for the duration of the call.
    let shared = unsafe { &*(ctx as *const Shared<M>) };
    let frame = unsafe { core::slice::from_raw_parts(frame, usize::from(len)) };
    match shared.mac.try_borrow_mut() {
        Ok(mut mac) => i32::from(mac.transmit(frame)),
        // Re-entered from inside the MAC's own call: refuse rather than alias.
        Err(_) => 0,
    }
}

impl<M: EthernetMac + 'static> EthernetIf<M> {
    /// Add `mac` to lwIP as an Ethernet interface with `ip`, bring it and
    /// its carrier up, and make it the default route.
    ///
    /// Takes the link as the witness that lwIP is initialised. The MAC is
    /// moved into storage that lives for the rest of the program, because
    /// lwIP holds the pointer to it.
    pub fn add(_link: &LwipLink, mac: M, ip: Ipv4Config) -> Result<Self, EthernetIfError> {
        let hwaddr = mac.mac_address();
        let shared: &'static Shared<M> = Box::leak(Box::new(Shared {
            mac: RefCell::new(mac),
        }));
        // SAFETY: `hwaddr` outlives the call (the netif copies it); the
        // callback and its context are valid for the program's lifetime.
        let raw = unsafe {
            wz_ethif_add(
                hwaddr.as_ptr(),
                crate::ipv4_addr_from_octets(ip.address),
                crate::ipv4_addr_from_octets(ip.netmask),
                crate::ipv4_addr_from_octets(ip.gateway),
                Some(transmit_trampoline::<M>),
                shared as *const Shared<M> as *mut c_void,
            )
        };
        let netif = NonNull::new(raw).ok_or(EthernetIfError::Refused)?;
        Ok(Self {
            netif,
            shared,
            rx: Box::new([0u8; FRAME_MAX]),
        })
    }

    /// Move every frame the MAC holds into lwIP. Returns how many were
    /// taken; a frame lwIP could not buffer is dropped, as a NIC would.
    pub fn poll(&mut self) -> usize {
        let mut taken = 0;
        loop {
            let len = match self.shared.mac.borrow_mut().receive(&mut self.rx[..]) {
                Some(len) => len,
                None => return taken,
            };
            // The MAC borrow has ended: lwIP may transmit while it handles
            // this frame.
            // SAFETY: the netif is lwIP's for the program's lifetime, and
            // `len <= FRAME_MAX` holds by `receive`'s contract.
            let accepted =
                unsafe { wz_ethif_input(self.netif.as_ptr(), self.rx.as_ptr(), len as u16) };
            if accepted != 0 {
                taken += 1;
            }
        }
    }

    /// Run `f` on the MAC, e.g. to read a driver's counters.
    pub fn with_mac<R>(&self, f: impl FnOnce(&mut M) -> R) -> R {
        f(&mut self.shared.mac.borrow_mut())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::collections::VecDeque;
    use alloc::rc::Rc;
    use alloc::vec::Vec;

    use crate::rx_sockets::bind_session_rx;

    /// The node's end of a cable; the test holds the other end and plays
    /// the far host at the frame level.
    struct CableEnd {
        address: [u8; 6],
        outbox: Rc<RefCell<VecDeque<Vec<u8>>>>,
        inbox: Rc<RefCell<VecDeque<Vec<u8>>>>,
    }

    const NODE_MAC: [u8; 6] = [0x02, 0, 0, 0, 0, 0x0a];
    const FAR_MAC: [u8; 6] = [0x02, 0, 0, 0, 0, 0x0b];
    const NODE_IP: [u8; 4] = [10, 9, 0, 1];
    const FAR_IP: [u8; 4] = [10, 9, 0, 2];

    fn ipv4_checksum(header: &[u8]) -> u16 {
        let mut sum: u32 = header
            .chunks(2)
            .map(|w| u32::from(u16::from_be_bytes([w[0], w[1]])))
            .sum();
        while sum > 0xffff {
            sum = (sum & 0xffff) + (sum >> 16);
        }
        !(sum as u16)
    }

    /// The far host's ARP reply: `FAR_IP` is at `FAR_MAC`.
    fn arp_reply() -> Vec<u8> {
        let mut f = Vec::new();
        f.extend_from_slice(&NODE_MAC);
        f.extend_from_slice(&FAR_MAC);
        f.extend_from_slice(&[0x08, 0x06, 0x00, 0x01, 0x08, 0x00, 6, 4, 0x00, 0x02]);
        f.extend_from_slice(&FAR_MAC);
        f.extend_from_slice(&FAR_IP);
        f.extend_from_slice(&NODE_MAC);
        f.extend_from_slice(&NODE_IP);
        f
    }

    /// A UDP datagram from the far host, `FAR_IP:src` to `NODE_IP:dst`,
    /// with no UDP checksum (zero, which IPv4 allows).
    fn udp_frame(src: u16, dst: u16, payload: &[u8]) -> Vec<u8> {
        let udp_len = 8 + payload.len() as u16;
        let total = 20 + udp_len;
        let mut ip = Vec::new();
        ip.extend_from_slice(&[0x45, 0x00]);
        ip.extend_from_slice(&total.to_be_bytes());
        ip.extend_from_slice(&[0, 0, 0, 0, 64, 17, 0, 0]);
        ip.extend_from_slice(&FAR_IP);
        ip.extend_from_slice(&NODE_IP);
        let sum = ipv4_checksum(&ip);
        ip[10..12].copy_from_slice(&sum.to_be_bytes());
        let mut f = Vec::new();
        f.extend_from_slice(&NODE_MAC);
        f.extend_from_slice(&FAR_MAC);
        f.extend_from_slice(&[0x08, 0x00]);
        f.extend_from_slice(&ip);
        f.extend_from_slice(&src.to_be_bytes());
        f.extend_from_slice(&dst.to_be_bytes());
        f.extend_from_slice(&udp_len.to_be_bytes());
        f.extend_from_slice(&[0, 0]);
        f.extend_from_slice(payload);
        f
    }

    /// The UDP destination port and payload of an IPv4/UDP frame, if it is one.
    fn udp_of(frame: &[u8]) -> Option<(u16, &[u8])> {
        if frame.get(12..14)? != [0x08, 0x00] || *frame.get(23)? != 17 {
            return None;
        }
        let udp = 14 + usize::from(frame[14] & 0x0f) * 4;
        let dst = u16::from_be_bytes([frame[udp + 2], frame[udp + 3]]);
        let len = usize::from(u16::from_be_bytes([frame[udp + 4], frame[udp + 5]]));
        Some((dst, frame.get(udp + 8..udp + len)?))
    }

    impl EthernetMac for CableEnd {
        fn mac_address(&self) -> [u8; 6] {
            self.address
        }
        fn transmit(&mut self, frame: &[u8]) -> bool {
            self.outbox.borrow_mut().push_back(frame.to_vec());
            true
        }
        fn receive(&mut self, buf: &mut [u8]) -> Option<usize> {
            let frame = self.inbox.borrow_mut().pop_front()?;
            buf[..frame.len()].copy_from_slice(&frame);
            Some(frame.len())
        }
    }

    /// A datagram leaves through the interface only once ARP has resolved
    /// the far host, as an Ethernet/IPv4/UDP frame addressed to the MAC the
    /// reply named; and a frame the far host sends in reaches the socket
    /// bound on the node. The far host is the test, at the frame level, so
    /// the interface is judged by exactly what crosses the cable.
    #[test]
    fn a_datagram_crosses_the_cable_both_ways_after_arp() {
        let (_serial, link) = crate::lwip_test_link();
        let out = Rc::new(RefCell::new(VecDeque::new()));
        let inbox = Rc::new(RefCell::new(VecDeque::new()));
        let mut node = EthernetIf::add(
            &link,
            CableEnd {
                address: NODE_MAC,
                outbox: out.clone(),
                inbox: inbox.clone(),
            },
            Ipv4Config {
                address: NODE_IP,
                netmask: [255, 255, 255, 0],
                gateway: [0, 0, 0, 0],
            },
        )
        .expect("interface");
        let mut socket = bind_session_rx(&link, 7602).expect("bind");

        // Out: the send asks who has FAR_IP before anything else.
        out.borrow_mut().clear();
        socket
            .send_to(crate::ipv4_addr_from_octets(FAR_IP), 7601, b"out")
            .expect("send");
        let request = out.borrow_mut().pop_front().expect("an ARP request left");
        std::assert_eq!(&request[0..6], &[0xff; 6], "broadcast");
        std::assert_eq!(&request[12..14], &[0x08, 0x06], "ARP");
        std::assert_eq!(&request[20..22], &[0x00, 0x01], "a request");
        std::assert_eq!(&request[38..42], &FAR_IP, "for the far host");
        std::assert!(
            out.borrow().iter().all(|f| udp_of(f).is_none()),
            "CONTROL: no datagram before the reply"
        );

        inbox.borrow_mut().push_back(arp_reply());
        std::assert_eq!(node.poll(), 1, "the reply was taken");
        let sent = out
            .borrow_mut()
            .pop_front()
            .expect("the queued datagram left");
        std::assert_eq!(&sent[0..6], &FAR_MAC, "to the MAC the reply named");
        std::assert_eq!(udp_of(&sent), Some((7601, &b"out"[..])));

        // In: a datagram from the far host reaches the bound socket.
        std::assert!(socket.try_recv().is_none(), "CONTROL: nothing in yet");
        inbox.borrow_mut().push_back(udp_frame(7601, 7602, b"in"));
        node.poll();
        let got = socket.try_recv().expect("the datagram came in");
        std::assert_eq!(got.data.as_slice(), b"in");
    }
}
