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
use core::cell::{Cell, RefCell};
use core::ffi::c_void;
use core::ptr::NonNull;

use lwip_sys::{
    netif, wz_ethif_add, wz_ethif_held_count, wz_ethif_input, wz_ethif_input_loan,
    wz_ethif_is_default, wz_ethif_rx_held_count, wz_ethif_seg, wz_ethif_set_gather,
    wz_ethif_set_rx_release, wz_ethif_tx_done,
};
use wz_runtime_core::{TxGather, TxSegment};

use crate::LwipLink;

/// The most pieces one frame is handed to the MAC in, which is the shim's
/// `WZ_ETHIF_SEG_MAX`: a chain with more is sent through the flat copy.
const SEG_MAX: usize = 8;
/// The most frames the MAC may hold in place at once, the shim's
/// `WZ_ETHIF_HELD_MAX`.
const HELD_MAX: usize = 8;
/// The most received frames lwIP may hold lent at once, the shim's
/// `WZ_ETHIF_RX_HELD_MAX`.
const RX_HELD_MAX: usize = 8;

/// The MAC seam and the frame bound, which moved to the dependency-free trait
/// tier so that a chip's driver can implement the seam without depending on
/// this crate (which builds lwIP's C sources). Re-exported here so the path a
/// firmware already names, `ethernet::EthernetMac`, stays one.
///
/// `FRAME_MAX` is the bound `shim.c` holds its transmit buffer to.
pub use wz_runtime_core::eth_mac::{EthernetMac, FRAME_MAX};

/// How many received frames lwIP has taken since boot, across every interface:
/// `(lent in place, copied in)`. A frame is lent when its MAC lends it and the
/// shim can wrap it ([`EthernetIf::poll`]); it is copied when its MAC does not
/// lend, or the shim's table of lent frames was full, which is the explicit
/// fallback a bench sets beside the frames read in place.
pub fn rx_frames_taken() -> (u32, u32) {
    // SAFETY: reads two counters the shim owns.
    unsafe {
        (
            lwip_sys::wz_ethif_rx_loaned_total(),
            lwip_sys::wz_ethif_rx_copied_total(),
        )
    }
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
    ///
    /// This is also what decides the DEFAULT ROUTE, which a node with more than
    /// one interface must not leave to the order they were added in: the first
    /// interface added with a gateway becomes the default route and a later one
    /// never moves it, and an interface with none is on-link only and is never
    /// the default route.
    pub gateway: [u8; 4],
}

/// The MAC, shared between the transmit callback lwIP calls and the receive
/// poll this module makes. Never borrowed across the call into lwIP, so a
/// transmit that lwIP makes WHILE handling a received frame (an ARP reply)
/// finds it free.
struct Shared<M> {
    mac: RefCell<M>,
    /// Lent receive buffers lwIP finished with at a moment the MAC was borrowed
    /// (a pbuf freed from inside a MAC call), to be given back by the next
    /// [`EthernetIf::poll`]. At most [`RX_HELD_MAX`] are ever lent.
    deferred_rx: [Cell<u32>; RX_HELD_MAX],
    deferred_rx_len: Cell<usize>,
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

/// ARCHITECTURE section 9.1 -- lwIP's pbuf chain, handed to the MAC piece by
/// piece instead of joined into one buffer first. The answer tells lwIP's shim
/// whether the pieces are free again (`1`, sent from a copy), still being read
/// (`2`, the shim keeps the chain until [`EthernetIf::reap_tx`] reports
/// `cookie`), or refused (`0`).
unsafe extern "C" fn gather_trampoline<M: EthernetMac>(
    ctx: *mut c_void,
    segs: *const wz_ethif_seg,
    n: u16,
    cookie: u32,
) -> i32 {
    // SAFETY: as `transmit_trampoline`; `segs` is `n <= SEG_MAX` pieces lwIP owns
    // for the duration of the call, and until the MAC reports `cookie` if it
    // queues them (the shim holds a reference on the chain).
    let shared = unsafe { &*(ctx as *const Shared<M>) };
    let n = usize::from(n).min(SEG_MAX);
    let mut pieces = [TxSegment {
        ptr: core::ptr::null(),
        len: 0,
    }; SEG_MAX];
    for (piece, seg) in pieces
        .iter_mut()
        .zip(unsafe { core::slice::from_raw_parts(segs, n) })
    {
        *piece = TxSegment {
            ptr: seg.ptr,
            len: usize::from(seg.len),
        };
    }
    match shared.mac.try_borrow_mut() {
        // SAFETY: lwIP's chain stays readable and unchanged until `tx_done`.
        Ok(mut mac) => match unsafe { mac.transmit_gather(&pieces[..n], cookie) } {
            TxGather::Refused => 0,
            TxGather::Copied => 1,
            TxGather::Queued => {
                // A frame read in place out of a transmit pool slot: the slot is
                // the bus master's now.
                #[cfg(feature = "tx-pool")]
                crate::tx_pool::on_queued(&pieces[..n]);
                2
            }
        },
        Err(_) => 0,
    }
}

/// ARCHITECTURE section 9.2 -- lwIP no longer reads a received frame the MAC
/// lent, so the buffer is the MAC's again. Called from inside lwIP, possibly while
/// the MAC is borrowed (a pbuf freed from within a MAC call), in which case the
/// return is parked for the next poll rather than aliased.
unsafe extern "C" fn rx_release_trampoline<M: EthernetMac>(ctx: *mut c_void, cookie: u32) {
    // SAFETY: `ctx` is the `&'static Shared<M>` `EthernetIf::add` registered.
    let shared = unsafe { &*(ctx as *const Shared<M>) };
    match shared.mac.try_borrow_mut() {
        Ok(mut mac) => mac.return_rx(cookie),
        Err(_) => {
            let at = shared.deferred_rx_len.get();
            // The shim lends at most `RX_HELD_MAX`, so the parking place cannot
            // overflow; a cookie past it would be a shim defect, kept loud.
            debug_assert!(at < RX_HELD_MAX, "more parked returns than frames lent");
            if at < RX_HELD_MAX {
                shared.deferred_rx[at].set(cookie);
                shared.deferred_rx_len.set(at + 1);
            }
        }
    }
}

impl<M: EthernetMac + 'static> EthernetIf<M> {
    /// Add `mac` to lwIP as an Ethernet interface with `ip`, and bring it and
    /// its carrier up. It becomes the default route only if it has a gateway
    /// and nothing else holds the route (see [`Ipv4Config::gateway`]).
    ///
    /// A node may add as many interfaces as the shim's table holds, two in the
    /// default build, which is what a board with an onboard Ethernet and a
    /// 10BASE-T1S MAC-PHY needs. A socket bound on `0.0.0.0` hears every one of
    /// them, and a send leaves by the interface whose network holds the
    /// destination.
    ///
    /// Takes the link as the witness that lwIP is initialised. The MAC is
    /// moved into storage that lives for the rest of the program, because
    /// lwIP holds the pointer to it.
    pub fn add(_link: &LwipLink, mac: M, ip: Ipv4Config) -> Result<Self, EthernetIfError> {
        let hwaddr = mac.mac_address();
        let shared: &'static Shared<M> = Box::leak(Box::new(Shared {
            mac: RefCell::new(mac),
            deferred_rx: [const { Cell::new(0) }; RX_HELD_MAX],
            deferred_rx_len: Cell::new(0),
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
        if shared.mac.borrow().gathers_in_place() {
            // SAFETY: the netif is lwIP's for the program's lifetime, and the
            // callback is the monomorphisation matching the registered context.
            unsafe { wz_ethif_set_gather(netif.as_ptr(), Some(gather_trampoline::<M>)) };
        }
        if shared.mac.borrow().loans_rx() {
            // SAFETY: as above, for the release callback.
            unsafe { wz_ethif_set_rx_release(netif.as_ptr(), Some(rx_release_trampoline::<M>)) };
        }
        Ok(Self {
            netif,
            shared,
            rx: Box::new([0u8; FRAME_MAX]),
        })
    }

    /// Give lwIP back every chain the MAC has finished reading in place, and
    /// return how many. [`poll`](Self::poll) does this first, so a firmware that
    /// polls each time round its loop never needs to call it; it is public for one
    /// that drains transmit completions on their own schedule.
    ///
    /// A MAC that reads a frame in place keeps the pbuf chain alive, through the
    /// reference the shim took, until this reports it, so a firmware that never
    /// polls runs out of held chains and falls back to the copying path.
    pub fn reap_tx(&self) -> usize {
        let mut cookies = [0u32; HELD_MAX];
        let mut count = 0;
        // The MAC borrow ends before lwIP is touched.
        self.shared.mac.borrow_mut().reap_tx(&mut |cookie| {
            if count < HELD_MAX {
                cookies[count] = cookie;
                count += 1;
            }
        });
        for &cookie in &cookies[..count] {
            // SAFETY: a cookie the MAC reports is one the shim handed it; a stale
            // or foreign one names no held chain and is ignored there.
            unsafe { wz_ethif_tx_done(cookie) };
        }
        count
    }

    /// How many pbuf chains lwIP is holding for a MAC to finish reading, across
    /// every interface. Zero when nothing is in flight.
    pub fn held_tx(&self) -> usize {
        // SAFETY: reads a counter the shim owns.
        unsafe { wz_ethif_held_count() as usize }
    }

    /// Give the MAC back the received buffers lwIP finished with while the MAC
    /// was borrowed, which the release callback could not hand back at once.
    fn return_deferred_rx(&self) {
        while self.shared.deferred_rx_len.get() > 0 {
            let at = self.shared.deferred_rx_len.get() - 1;
            self.shared.deferred_rx_len.set(at);
            let cookie = self.shared.deferred_rx[at].get();
            self.shared.mac.borrow_mut().return_rx(cookie);
        }
    }

    /// How many received frames lwIP is reading in place right now, lent by a MAC
    /// and not yet released. Zero when nothing is lent.
    pub fn held_rx(&self) -> usize {
        // SAFETY: reads a counter the shim owns.
        unsafe { wz_ethif_rx_held_count() as usize }
    }

    /// Move every frame the MAC holds into lwIP. Returns how many were
    /// taken; a frame lwIP could not buffer is dropped, as a NIC would.
    ///
    /// A MAC that lends its received frames ([`EthernetMac::loans_rx`]) has them
    /// read in place: lwIP is handed a pbuf that points into the MAC's own buffer,
    /// and the buffer goes back to the MAC when lwIP frees the pbuf. Otherwise,
    /// and for the one frame in a burst that finds the shim's table of lent frames
    /// full, the frame is copied in.
    pub fn poll(&mut self) -> usize {
        self.reap_tx();
        self.return_deferred_rx();
        let lends = self.shared.mac.borrow().loans_rx();
        let mut taken = 0;
        loop {
            if lends {
                let loan = self.shared.mac.borrow_mut().receive_loan();
                let Some(loan) = loan else {
                    return taken;
                };
                // The MAC borrow has ended: lwIP may transmit while it handles
                // this frame, and may free the pbuf (which returns the buffer).
                // SAFETY: the netif is lwIP's for the program's lifetime, and the
                // loan stays readable until `return_rx`, which the shim causes
                // only once lwIP no longer reads it.
                let outcome = unsafe {
                    wz_ethif_input_loan(self.netif.as_ptr(), loan.ptr, loan.len as u16, loan.cookie)
                };
                match outcome {
                    1 => taken += 1,
                    // lwIP refused it and the shim freed the pbuf, which gave the
                    // buffer back: a drop, as on a NIC.
                    0 => {}
                    // The shim could not wrap it: copy it in, then give it back.
                    _ => {
                        // SAFETY: as above; `wz_ethif_input` copies before it returns.
                        let accepted = unsafe {
                            wz_ethif_input(self.netif.as_ptr(), loan.ptr, loan.len as u16)
                        };
                        self.shared.mac.borrow_mut().return_rx(loan.cookie);
                        if accepted != 0 {
                            taken += 1;
                        }
                    }
                }
                continue;
            }
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

    /// Whether this interface is lwIP's default route, which is where a send
    /// to a destination on no interface's network goes.
    pub fn is_default_route(&self) -> bool {
        // SAFETY: the netif is lwIP's for the program's lifetime.
        unsafe { wz_ethif_is_default(self.netif.as_ptr()) != 0 }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::collections::VecDeque;
    use alloc::rc::Rc;
    use alloc::vec::Vec;

    use crate::rx_sockets::bind_session_rx;
    use wz_runtime_core::RxLoan;

    /// The buffers a loaning MAC double has lent and not yet had returned, by
    /// cookie.
    type LentBuffers = Rc<RefCell<Vec<(u32, Vec<u8>)>>>;

    /// The node's end of a cable; the test holds the other end and plays
    /// the far host at the frame level.
    struct CableEnd {
        address: [u8; 6],
        outbox: Rc<RefCell<VecDeque<Vec<u8>>>>,
        inbox: Rc<RefCell<VecDeque<Vec<u8>>>>,
    }

    /// One cable's two ends: the node's interface and the far host on it.
    #[derive(Clone, Copy)]
    struct Net {
        node_mac: [u8; 6],
        node_ip: [u8; 4],
        far_mac: [u8; 6],
        far_ip: [u8; 4],
    }

    /// The first network, which the single-interface test uses.
    const NET_A: Net = Net {
        node_mac: [0x02, 0, 0, 0, 0, 0x0a],
        node_ip: [10, 9, 0, 1],
        far_mac: [0x02, 0, 0, 0, 0, 0x0b],
        far_ip: [10, 9, 0, 2],
    };
    /// A second, on another subnet and with other MACs: what a node with two
    /// links (an onboard Ethernet and a 10BASE-T1S MAC-PHY, say) is attached to.
    const NET_B: Net = Net {
        node_mac: [0x02, 0, 0, 0, 0, 0x1a],
        node_ip: [10, 9, 1, 1],
        far_mac: [0x02, 0, 0, 0, 0, 0x1b],
        far_ip: [10, 9, 1, 2],
    };

    const NODE_MAC: [u8; 6] = NET_A.node_mac;
    const FAR_MAC: [u8; 6] = NET_A.far_mac;
    const NODE_IP: [u8; 4] = NET_A.node_ip;
    const FAR_IP: [u8; 4] = NET_A.far_ip;

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

    /// The far host's ARP reply on `net`: its address is at its MAC.
    fn arp_reply_on(net: Net) -> Vec<u8> {
        let mut f = Vec::new();
        f.extend_from_slice(&net.node_mac);
        f.extend_from_slice(&net.far_mac);
        f.extend_from_slice(&[0x08, 0x06, 0x00, 0x01, 0x08, 0x00, 6, 4, 0x00, 0x02]);
        f.extend_from_slice(&net.far_mac);
        f.extend_from_slice(&net.far_ip);
        f.extend_from_slice(&net.node_mac);
        f.extend_from_slice(&net.node_ip);
        f
    }

    /// The far host's ARP reply: `FAR_IP` is at `FAR_MAC`.
    fn arp_reply() -> Vec<u8> {
        arp_reply_on(NET_A)
    }

    /// A UDP datagram from the far host on `net`, `far_ip:src` to
    /// `node_ip:dst`, with no UDP checksum (zero, which IPv4 allows).
    fn udp_frame_on(net: Net, src: u16, dst: u16, payload: &[u8]) -> Vec<u8> {
        let udp_len = 8 + payload.len() as u16;
        let total = 20 + udp_len;
        let mut ip = Vec::new();
        ip.extend_from_slice(&[0x45, 0x00]);
        ip.extend_from_slice(&total.to_be_bytes());
        ip.extend_from_slice(&[0, 0, 0, 0, 64, 17, 0, 0]);
        ip.extend_from_slice(&net.far_ip);
        ip.extend_from_slice(&net.node_ip);
        let sum = ipv4_checksum(&ip);
        ip[10..12].copy_from_slice(&sum.to_be_bytes());
        let mut f = Vec::new();
        f.extend_from_slice(&net.node_mac);
        f.extend_from_slice(&net.far_mac);
        f.extend_from_slice(&[0x08, 0x00]);
        f.extend_from_slice(&ip);
        f.extend_from_slice(&src.to_be_bytes());
        f.extend_from_slice(&dst.to_be_bytes());
        f.extend_from_slice(&udp_len.to_be_bytes());
        f.extend_from_slice(&[0, 0]);
        f.extend_from_slice(payload);
        f
    }

    /// A UDP datagram from the far host: `FAR_IP:src` to `NODE_IP:dst`.
    fn udp_frame(src: u16, dst: u16, payload: &[u8]) -> Vec<u8> {
        udp_frame_on(NET_A, src, dst, payload)
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

    type Cable = Rc<RefCell<VecDeque<Vec<u8>>>>;

    /// An interface on `net` with `gateway`, and the test's two ends of its
    /// cable: what the node sent, and what the far host sends in.
    fn node_on(
        link: &LwipLink,
        net: Net,
        gateway: [u8; 4],
    ) -> (EthernetIf<CableEnd>, Cable, Cable) {
        let out: Cable = Rc::new(RefCell::new(VecDeque::new()));
        let inbox: Cable = Rc::new(RefCell::new(VecDeque::new()));
        let iface = EthernetIf::add(
            link,
            CableEnd {
                address: net.node_mac,
                outbox: out.clone(),
                inbox: inbox.clone(),
            },
            Ipv4Config {
                address: net.node_ip,
                netmask: [255, 255, 255, 0],
                gateway,
            },
        )
        .expect("interface");
        (iface, out, inbox)
    }

    /// THE FIRST INTERFACE WITH A GATEWAY IS THE DEFAULT ROUTE, AND A LATER ONE
    /// NEVER TAKES IT.
    ///
    /// Every interface used to become the default route as it was added, which is
    /// harmless with one and with two lets the second take the route from the
    /// first: whichever was added last won, whatever gateways they had. A node
    /// with an onboard Ethernet and a second link has exactly that order to get
    /// wrong, and "the route moved because of the order of two calls" is not a
    /// thing a firmware can see.
    #[test]
    fn the_first_interface_with_a_gateway_is_the_default_route_and_no_later_one_takes_it() {
        let (_serial, link) = crate::lwip_test_link();
        let (first, _, _) = node_on(&link, NET_A, [10, 9, 0, 254]);
        let (second, _, _) = node_on(&link, NET_B, [10, 9, 1, 254]);
        std::assert!(
            first.is_default_route(),
            "the first with a gateway holds it"
        );
        std::assert!(
            !second.is_default_route(),
            "the second did not take it, with a gateway of its own"
        );
    }

    /// An interface with no gateway is on-link only: it is never the default
    /// route, and it does not stop a later interface that has a gateway from
    /// being it.
    #[test]
    fn an_interface_without_a_gateway_is_never_the_default_route() {
        let (_serial, link) = crate::lwip_test_link();
        let (on_link, _, _) = node_on(&link, NET_A, [0, 0, 0, 0]);
        std::assert!(!on_link.is_default_route(), "no gateway, no default route");
        let (routed, _, _) = node_on(&link, NET_B, [10, 9, 1, 254]);
        std::assert!(
            routed.is_default_route(),
            "the route nothing held goes to the interface that has a gateway"
        );
        std::assert!(!on_link.is_default_route());
    }

    /// TWO INTERFACES EACH CARRY THEIR OWN NETWORK'S TRAFFIC, AND ONE SOCKET
    /// HEARS BOTH.
    ///
    /// The node a board with two links is: a datagram for the far host on one
    /// network asks that cable and no other, and a frame arriving on either
    /// cable reaches the one socket bound on `0.0.0.0`. Judged at the frame
    /// level on both cables, so an interface that sent the datagram out of the
    /// wrong cable is seen on the wrong cable.
    #[test]
    fn two_interfaces_carry_their_own_networks_and_one_socket_hears_both() {
        let (_serial, link) = crate::lwip_test_link();
        let (mut a, out_a, in_a) = node_on(&link, NET_A, [0, 0, 0, 0]);
        let (mut b, out_b, in_b) = node_on(&link, NET_B, [0, 0, 0, 0]);
        let mut socket = bind_session_rx(&link, 7612).expect("bind");
        out_a.borrow_mut().clear();
        out_b.borrow_mut().clear();

        // Out to the second network: its cable asks, the first stays quiet.
        socket
            .send_to(crate::ipv4_addr_from_octets(NET_B.far_ip), 7611, b"to-b")
            .expect("send");
        std::assert!(
            out_a.borrow().is_empty(),
            "nothing for network B on cable A"
        );
        let request = out_b.borrow_mut().pop_front().expect("ARP on cable B");
        std::assert_eq!(&request[12..14], &[0x08, 0x06], "ARP");
        std::assert_eq!(&request[38..42], &NET_B.far_ip, "for B's far host");
        in_b.borrow_mut().push_back(arp_reply_on(NET_B));
        std::assert_eq!(b.poll(), 1);
        let sent = out_b
            .borrow_mut()
            .pop_front()
            .expect("the datagram left on B");
        std::assert_eq!(&sent[0..6], &NET_B.far_mac, "to the MAC B's reply named");
        std::assert_eq!(udp_of(&sent), Some((7611, &b"to-b"[..])));
        std::assert!(out_a.borrow().is_empty(), "and cable A still heard nothing");

        // Out to the first network: now it is A's cable that asks.
        socket
            .send_to(crate::ipv4_addr_from_octets(NET_A.far_ip), 7611, b"to-a")
            .expect("send");
        let request = out_a.borrow_mut().pop_front().expect("ARP on cable A");
        std::assert_eq!(&request[38..42], &NET_A.far_ip, "for A's far host");
        std::assert!(
            out_b.borrow().is_empty(),
            "nothing for network A on cable B"
        );
        in_a.borrow_mut().push_back(arp_reply_on(NET_A));
        std::assert_eq!(a.poll(), 1);
        let sent = out_a
            .borrow_mut()
            .pop_front()
            .expect("the datagram left on A");
        std::assert_eq!(udp_of(&sent), Some((7611, &b"to-a"[..])));

        // In: a datagram on either cable reaches the one socket.
        std::assert!(socket.try_recv().is_none(), "CONTROL: nothing in yet");
        in_a.borrow_mut()
            .push_back(udp_frame_on(NET_A, 7611, 7612, b"via-a"));
        a.poll();
        std::assert_eq!(socket.try_recv().expect("via A").data.as_slice(), b"via-a");
        in_b.borrow_mut()
            .push_back(udp_frame_on(NET_B, 7611, 7612, b"via-b"));
        b.poll();
        std::assert_eq!(socket.try_recv().expect("via B").data.as_slice(), b"via-b");
    }

    // ---- ARCHITECTURE section 9.1: the MAC reads lwIP's pbuf chain in place -----

    /// One frame the MAC was handed in pieces.
    struct Gathered {
        cookie: u32,
        /// `(address, length)` of each piece, as lwIP presented them.
        pieces: Vec<(usize, usize)>,
        /// The pieces joined, read at the moment they were handed over.
        joined: Vec<u8>,
    }

    /// A MAC that reads frames in place and answers a fixed outcome: it records
    /// which door each frame came through, and reports a cookie done only when the
    /// test releases it.
    struct GatherEnd {
        address: [u8; 6],
        inbox: Cable,
        /// Frames that came through the copying door.
        flat: Cable,
        gathered: Rc<RefCell<Vec<Gathered>>>,
        outcome: TxGather,
        released: Rc<RefCell<Vec<u32>>>,
    }

    impl EthernetMac for GatherEnd {
        fn mac_address(&self) -> [u8; 6] {
            self.address
        }
        fn transmit(&mut self, frame: &[u8]) -> bool {
            self.flat.borrow_mut().push_back(frame.to_vec());
            true
        }
        fn receive(&mut self, buf: &mut [u8]) -> Option<usize> {
            let frame = self.inbox.borrow_mut().pop_front()?;
            buf[..frame.len()].copy_from_slice(&frame);
            Some(frame.len())
        }
        fn gathers_in_place(&self) -> bool {
            true
        }
        unsafe fn transmit_gather(&mut self, segments: &[TxSegment], cookie: u32) -> TxGather {
            let mut joined = Vec::new();
            for s in segments {
                // SAFETY: lwIP hands pieces it keeps readable for this call.
                joined.extend_from_slice(unsafe { core::slice::from_raw_parts(s.ptr, s.len) });
            }
            self.gathered.borrow_mut().push(Gathered {
                cookie,
                pieces: segments.iter().map(|s| (s.ptr as usize, s.len)).collect(),
                joined,
            });
            self.outcome
        }
        fn reap_tx(&mut self, done: &mut dyn FnMut(u32)) {
            for cookie in self.released.borrow_mut().drain(..) {
                done(cookie);
            }
        }
    }

    struct GatherRig {
        node: EthernetIf<GatherEnd>,
        inbox: Cable,
        flat: Cable,
        gathered: Rc<RefCell<Vec<Gathered>>>,
        released: Rc<RefCell<Vec<u32>>>,
    }

    fn gather_node(link: &LwipLink, outcome: TxGather) -> GatherRig {
        let inbox: Cable = Rc::new(RefCell::new(VecDeque::new()));
        let flat: Cable = Rc::new(RefCell::new(VecDeque::new()));
        let gathered = Rc::new(RefCell::new(Vec::new()));
        let released = Rc::new(RefCell::new(Vec::new()));
        let node = EthernetIf::add(
            link,
            GatherEnd {
                address: NODE_MAC,
                inbox: inbox.clone(),
                flat: flat.clone(),
                gathered: gathered.clone(),
                outcome,
                released: released.clone(),
            },
            Ipv4Config {
                address: NODE_IP,
                netmask: [255, 255, 255, 0],
                gateway: [0, 0, 0, 0],
            },
        )
        .expect("interface");
        // lwIP announces a new interface (a gratuitous ARP) from inside the call
        // that adds it, before the gathering door is installed, so that one frame
        // went through the copying door. What the tests look at is what follows.
        flat.borrow_mut().clear();
        GatherRig {
            node,
            inbox,
            flat,
            gathered,
            released,
        }
    }

    /// Resolve the far host's address, so a datagram sent afterwards leaves at
    /// once: an ARP request goes out for the first send, and the reply answers it.
    fn resolve_far_host<S: FnMut(&mut GatherRig)>(rig: &mut GatherRig, mut after_reply: S) {
        rig.inbox.borrow_mut().push_back(arp_reply());
        rig.node.poll();
        after_reply(rig);
    }

    /// A frame lwIP sends is handed to the MAC in place, through the gathering
    /// door and not the copying one, and lwIP keeps the chain alive until the MAC
    /// reports it: held while in flight, given back when reaped.
    #[test]
    fn a_frame_is_handed_over_in_place_and_held_until_the_mac_reports_it() {
        let (_serial, link) = crate::lwip_test_link();
        let mut rig = gather_node(&link, TxGather::Queued);
        let socket = bind_session_rx(&link, 7602).expect("bind");
        socket
            .send_to(crate::ipv4_addr_from_octets(FAR_IP), 7601, b"first")
            .expect("send");
        resolve_far_host(&mut rig, |_| {});

        std::assert!(
            rig.flat.borrow().is_empty(),
            "nothing took the copying door"
        );
        let gathered = rig.gathered.borrow();
        let datagram = gathered
            .iter()
            .find(|g| udp_of(&g.joined).is_some())
            .expect("the datagram reached the gathering door");
        std::assert_eq!(udp_of(&datagram.joined), Some((7601, &b"first"[..])));
        // The caller has long since freed its own pbuf, so the memory is readable
        // now only because the shim holds a reference, and it is unchanged: the
        // MAC would read the same bytes it was handed.
        let mut reread = Vec::new();
        for (ptr, len) in &datagram.pieces {
            // SAFETY: the shim holds the chain, so the bytes are readable.
            reread
                .extend_from_slice(unsafe { core::slice::from_raw_parts(*ptr as *const u8, *len) });
        }
        std::assert_eq!(reread, datagram.joined, "unchanged since the handover");
        for g in gathered.iter() {
            // SAFETY: reads a counter the shim owns.
            std::assert_eq!(
                unsafe { lwip_sys::wz_ethif_held_refs(g.cookie) },
                1,
                "the shim's reference is the only one keeping the chain alive"
            );
        }
        std::assert_eq!(
            rig.node.held_tx(),
            gathered.len(),
            "every queued frame is held, the ARP request and the datagram"
        );
        let cookies: Vec<u32> = gathered.iter().map(|g| g.cookie).collect();
        drop(gathered);

        rig.released.borrow_mut().extend(cookies.iter().copied());
        std::assert_eq!(rig.node.reap_tx(), cookies.len());
        std::assert_eq!(rig.node.held_tx(), 0, "lwIP has its chains back");
        let _ = socket;
    }

    /// A MAC that answers COPIED has finished with the pieces on the spot, so
    /// nothing is held.
    #[test]
    fn a_frame_the_mac_copied_is_not_held() {
        let (_serial, link) = crate::lwip_test_link();
        let mut rig = gather_node(&link, TxGather::Copied);
        let socket = bind_session_rx(&link, 7602).expect("bind");
        socket
            .send_to(crate::ipv4_addr_from_octets(FAR_IP), 7601, b"copied")
            .expect("send");
        resolve_far_host(&mut rig, |_| {});
        std::assert!(!rig.gathered.borrow().is_empty());
        std::assert_eq!(rig.node.held_tx(), 0);
    }

    /// A refused frame is an error to lwIP and holds nothing.
    #[test]
    fn a_frame_the_mac_refused_is_not_held() {
        let (_serial, link) = crate::lwip_test_link();
        let mut rig = gather_node(&link, TxGather::Refused);
        let socket = bind_session_rx(&link, 7602).expect("bind");
        let _ = socket.send_to(crate::ipv4_addr_from_octets(FAR_IP), 7601, b"refused");
        resolve_far_host(&mut rig, |_| {});
        let again = socket.send_to(crate::ipv4_addr_from_octets(FAR_IP), 7601, b"refused");
        std::assert!(again.is_err(), "lwIP reports the refusal");
        std::assert_eq!(rig.node.held_tx(), 0);
    }

    /// When the table of held chains is full the frame goes through the copying
    /// door, which is always correct: a MAC that is slow to report loses speed
    /// and never a frame.
    #[test]
    fn a_full_table_of_held_chains_falls_back_to_the_copying_door() {
        let (_serial, link) = crate::lwip_test_link();
        let mut rig = gather_node(&link, TxGather::Queued);
        let socket = bind_session_rx(&link, 7602).expect("bind");
        socket
            .send_to(crate::ipv4_addr_from_octets(FAR_IP), 7601, b"prime")
            .expect("send");
        resolve_far_host(&mut rig, |_| {});
        let mut sent = 0;
        while rig.node.held_tx() < HELD_MAX {
            socket
                .send_to(crate::ipv4_addr_from_octets(FAR_IP), 7601, b"fill")
                .expect("send");
            sent += 1;
            std::assert!(sent < 4 * HELD_MAX, "the table never filled");
        }
        std::assert!(rig.flat.borrow().is_empty(), "nothing copied yet");

        socket
            .send_to(crate::ipv4_addr_from_octets(FAR_IP), 7601, b"overflow")
            .expect("send");
        let flat = rig.flat.borrow();
        std::assert_eq!(flat.len(), 1, "the ninth frame took the copying door");
        std::assert_eq!(udp_of(&flat[0]), Some((7601, &b"overflow"[..])));
        std::assert_eq!(rig.node.held_tx(), HELD_MAX, "and holds nothing more");
    }

    /// A payload lwIP does not own (a ROM pbuf) reaches the MAC as its OWN piece,
    /// at its own address: the chain is [headers][payload], and the payload is read
    /// where the caller left it, never copied.
    #[test]
    fn a_payload_pbuf_the_caller_owns_is_handed_over_at_its_own_address() {
        use lwip_sys::{
            pbuf_alloc, pbuf_free, pbuf_layer_PBUF_TRANSPORT, pbuf_type_PBUF_ROM, udp_new,
            udp_remove, udp_sendto,
        };

        let (_serial, link) = crate::lwip_test_link();
        let mut rig = gather_node(&link, TxGather::Queued);
        let socket = bind_session_rx(&link, 7602).expect("bind");
        // Resolve the far host first, so the ROM datagram is not parked in ARP's
        // queue (which would copy it).
        socket
            .send_to(crate::ipv4_addr_from_octets(FAR_IP), 7601, b"prime")
            .expect("send");
        resolve_far_host(&mut rig, |_| {});
        let before = rig.gathered.borrow().len();

        static PAYLOAD: [u8; 24] = *b"rom-payload-in-place-ok!";
        // SAFETY: a fresh pcb and ROM pbuf, both released below; PAYLOAD is
        // 'static, so the pointer lwIP holds stays valid.
        unsafe {
            let pcb = udp_new();
            std::assert!(!pcb.is_null());
            let p = pbuf_alloc(
                pbuf_layer_PBUF_TRANSPORT,
                PAYLOAD.len() as u16,
                pbuf_type_PBUF_ROM,
            );
            std::assert!(!p.is_null());
            (*p).payload = PAYLOAD.as_ptr() as *mut c_void;
            let dst = lwip_sys::ip_addr_t {
                addr: crate::ipv4_addr_from_octets(FAR_IP),
            };
            let err = udp_sendto(pcb, p, &dst, 7601);
            std::assert_eq!(err as core::ffi::c_int, lwip_sys::err_enum_t_ERR_OK);
            pbuf_free(p);
            udp_remove(pcb);
        }

        let gathered = rig.gathered.borrow();
        let frame = gathered
            .get(before)
            .expect("the ROM datagram was handed over");
        std::assert_eq!(
            frame.pieces.len(),
            2,
            "headers in one piece, the payload in another"
        );
        std::assert_eq!(
            frame.pieces[1],
            (PAYLOAD.as_ptr() as usize, PAYLOAD.len()),
            "the payload piece IS the caller's memory"
        );
        std::assert_eq!(udp_of(&frame.joined), Some((7601, &PAYLOAD[..])));
        std::assert!(rig.node.held_tx() >= 1, "held while the MAC reads it");
    }

    // ---- ARCHITECTURE section 9.1: a frame sent from a transmit pool slot --------

    /// Lend a pool slot through the socket, write `bytes` into it, and send it to
    /// the far host. Returns the address the bytes were written at.
    #[cfg(feature = "tx-pool")]
    fn send_from_slot(socket: &mut crate::rx_sockets::SessionRxSocket, bytes: &[u8]) -> usize {
        let payload = socket.alloc_tx_payload(bytes.len()).expect("a lend");
        let (at, capacity) = payload.storage();
        std::assert!(capacity >= bytes.len());
        std::assert_eq!(
            crate::tx_pool::slot_of(at).map(|(_, state)| state),
            Some(crate::tx_pool::SlotState::CpuMut),
            "the lend is a slot of the pool, the CPU's while it is written"
        );
        // SAFETY: the lent payload has `capacity >= bytes.len()` writable bytes.
        unsafe { core::ptr::copy_nonoverlapping(bytes.as_ptr(), at, bytes.len()) };
        socket
            .send_tx_payload(
                payload,
                bytes.len(),
                crate::ipv4_addr_from_octets(FAR_IP),
                7601,
            )
            .expect("send");
        at as usize
    }

    /// THE POINT OF THE POOL: the frame a MAC is handed to read in place lies
    /// inside the slot the session wrote it into, headers and all, and the slot's
    /// generated lifecycle follows it. The pool records it as the bus master's
    /// while the MAC holds it, and free only once the MAC has reported it done.
    /// Judged by address and by the pool's own state, which a copy cannot fake.
    #[cfg(feature = "tx-pool")]
    #[test]
    fn a_frame_from_a_pool_slot_is_read_by_the_mac_inside_that_slot() {
        use crate::tx_pool::{slot_of, stats, SlotState, TestPool};

        let (_serial, link) = crate::lwip_test_link();
        let mut rig = gather_node(&link, TxGather::Queued);
        let mut socket = bind_session_rx(&link, 7602).expect("bind");
        // Resolve the far host first, from lwIP's heap, so the slot's frame leaves at
        // once rather than waiting in ARP's queue.
        socket
            .send_to(crate::ipv4_addr_from_octets(FAR_IP), 7601, b"prime")
            .expect("send");
        resolve_far_host(&mut rig, |_| {});
        let pool = TestPool::install();
        let before = rig.gathered.borrow().len();

        let written = send_from_slot(&mut socket, b"encoded once, into the slot");

        let gathered = rig.gathered.borrow();
        let frame = gathered.get(before).expect("the datagram reached the MAC");
        std::assert_eq!(
            udp_of(&frame.joined),
            Some((7601, &b"encoded once, into the slot"[..]))
        );
        std::assert_eq!(frame.pieces.len(), 1, "headers and payload are one piece");
        let (start, len) = frame.pieces[0];
        let (idx, state) = slot_of(start as *const u8).expect("the piece lies in a slot");
        std::assert_eq!(
            slot_of((start + len - 1) as *const u8).map(|(i, _)| i),
            Some(idx),
            "the whole frame lies in that one slot"
        );
        std::assert_eq!(
            slot_of(written as *const u8).map(|(i, _)| i),
            Some(idx),
            "the slot the session wrote into"
        );
        std::assert_eq!(state, SlotState::DmaBusyTx, "the bus master's while queued");
        let cookie = frame.cookie;
        drop(gathered);
        let s = stats().expect("installed");
        std::assert_eq!((s.lent, s.started, s.completed, s.unarmed), (1, 1, 0, 0));

        rig.released.borrow_mut().push(cookie);
        rig.node.reap_tx();
        std::assert_eq!(slot_of(start as *const u8), Some((idx, SlotState::Free)));
        let s = stats().expect("installed");
        std::assert_eq!((s.completed, s.unarmed), (1, 0));
        std::assert_eq!(s.free as usize, crate::session_tx_pool_mcu::SLOT_COUNT);
        drop(pool);
    }

    /// A datagram handed over as BYTES (`send_to`, the send every frame takes that
    /// the session did not encode into a lent slot: the keep-alive, the close, the
    /// handshake, a flushed batch, a fragment) leaves from a pool slot too, and the
    /// MAC reads it in place. Before, it went out of a pbuf of lwIP's heap, which
    /// the MAC cannot read in place and copied into its ring: on the kit every
    /// keep-alive of an idle session was a copy while the pool sat free.
    #[cfg(feature = "tx-pool")]
    #[test]
    fn a_datagram_sent_as_bytes_leaves_from_a_pool_slot_read_in_place() {
        use crate::tx_pool::{slot_of, stats, SlotState, TestPool};

        let (_serial, link) = crate::lwip_test_link();
        let mut rig = gather_node(&link, TxGather::Queued);
        let socket = bind_session_rx(&link, 7602).expect("bind");
        socket
            .send_to(crate::ipv4_addr_from_octets(FAR_IP), 7601, b"prime")
            .expect("send");
        resolve_far_host(&mut rig, |_| {});
        let pool = TestPool::install();
        let before = rig.gathered.borrow().len();

        socket
            .send_to(crate::ipv4_addr_from_octets(FAR_IP), 7601, &[0x04])
            .expect("send");

        let gathered = rig.gathered.borrow();
        let frame = gathered.get(before).expect("the datagram reached the MAC");
        std::assert_eq!(udp_of(&frame.joined), Some((7601, &[0x04u8][..])));
        std::assert_eq!(frame.pieces.len(), 1, "headers and payload are one piece");
        let (start, len) = frame.pieces[0];
        let (idx, state) = slot_of(start as *const u8).expect("the piece lies in a slot");
        std::assert_eq!(
            slot_of((start + len - 1) as *const u8).map(|(i, _)| i),
            Some(idx),
            "the whole frame lies in that one slot"
        );
        std::assert_eq!(state, SlotState::DmaBusyTx, "the bus master's while queued");
        let cookie = frame.cookie;
        drop(gathered);
        let s = stats().expect("installed");
        std::assert_eq!((s.lent, s.started, s.completed, s.unarmed), (1, 1, 0, 0));

        rig.released.borrow_mut().push(cookie);
        rig.node.reap_tx();
        let s = stats().expect("installed");
        std::assert_eq!((s.completed, s.unarmed), (1, 0));
        std::assert_eq!(s.free as usize, crate::session_tx_pool_mcu::SLOT_COUNT);
        std::assert!(
            rig.flat.borrow().is_empty(),
            "nothing took the copying door"
        );
        drop(pool);
    }

    /// A datagram larger than a slot carries is not cut to fit one: it leaves from
    /// lwIP's heap whole, as it did before there was a pool, and takes no slot.
    #[cfg(feature = "tx-pool")]
    #[test]
    fn a_datagram_past_a_slot_leaves_whole_from_lwips_heap() {
        use crate::tx_pool::{stats, TestPool};

        let (_serial, link) = crate::lwip_test_link();
        let mut rig = gather_node(&link, TxGather::Queued);
        // A socket wider than a slot whatever the session socket's build-time
        // width is (the slim profile's is narrower than a slot).
        let socket = crate::LwipUdpSocket::<2048, 4>::bind(&link, 7602).expect("bind");
        socket
            .send_to(crate::ipv4_addr_from_octets(FAR_IP), 7601, b"prime")
            .expect("send");
        resolve_far_host(&mut rig, |_| {});
        let pool = TestPool::install();
        let before = rig.gathered.borrow().len();
        let past = crate::tx_pool::capacity() + 1;
        let big: Vec<u8> = (0..past).map(|i| i as u8).collect();
        socket
            .send_to(crate::ipv4_addr_from_octets(FAR_IP), 7601, &big)
            .expect("send");
        let s = stats().expect("installed");
        std::assert_eq!(s.lent, 0, "a datagram no slot holds takes none");
        let gathered = rig.gathered.borrow();
        let frame = gathered.get(before).expect("the datagram reached the MAC");
        std::assert_eq!(
            udp_of(&frame.joined),
            Some((7601, &big[..])),
            "whole, not cut to a slot"
        );
        drop(gathered);
        drop(pool);
    }

    /// A frame the MAC sent from a COPY never had its slot read by the bus master:
    /// the slot is un-armed and back on the freelist as soon as lwIP lets go, and
    /// the pool counts it as such and not as a transfer.
    #[cfg(feature = "tx-pool")]
    #[test]
    fn a_frame_the_mac_copied_returns_its_slot_without_a_transfer() {
        use crate::tx_pool::{slot_of, stats, SlotState, TestPool};

        let (_serial, link) = crate::lwip_test_link();
        let mut rig = gather_node(&link, TxGather::Copied);
        let mut socket = bind_session_rx(&link, 7602).expect("bind");
        socket
            .send_to(crate::ipv4_addr_from_octets(FAR_IP), 7601, b"prime")
            .expect("send");
        resolve_far_host(&mut rig, |_| {});
        let pool = TestPool::install();

        let written = send_from_slot(&mut socket, b"copied by the mac");

        std::assert_eq!(
            slot_of(written as *const u8).map(|(_, state)| state),
            Some(SlotState::Free)
        );
        let s = stats().expect("installed");
        std::assert_eq!((s.lent, s.started, s.completed, s.unarmed), (1, 0, 0, 1));
        std::assert_eq!(s.free as usize, crate::session_tx_pool_mcu::SLOT_COUNT);
        drop(pool);
    }

    /// A frame sent before the far host's address is known waits in ARP's queue,
    /// which keeps the slot's pbuf: the slot stays armed and is not the bus
    /// master's until the reply lets the frame reach the MAC, and goes home when
    /// the MAC reports it.
    #[cfg(feature = "tx-pool")]
    #[test]
    fn a_frame_parked_for_an_address_keeps_its_slot_armed_until_it_reaches_the_mac() {
        use crate::tx_pool::{slot_of, stats, SlotState, TestPool};

        let (_serial, link) = crate::lwip_test_link();
        let mut rig = gather_node(&link, TxGather::Queued);
        let mut socket = bind_session_rx(&link, 7602).expect("bind");
        let pool = TestPool::install();

        let written = send_from_slot(&mut socket, b"waits for the address") as *const u8;
        std::assert_eq!(
            slot_of(written).map(|(_, state)| state),
            Some(SlotState::DmaArmedTx),
            "parked: sent by the session, not yet read by a bus master"
        );
        resolve_far_host(&mut rig, |_| {});
        std::assert_eq!(
            slot_of(written).map(|(_, state)| state),
            Some(SlotState::DmaBusyTx)
        );
        let cookies: Vec<u32> = rig.gathered.borrow().iter().map(|g| g.cookie).collect();
        rig.released.borrow_mut().extend(cookies);
        rig.node.reap_tx();
        std::assert_eq!(
            slot_of(written).map(|(_, state)| state),
            Some(SlotState::Free)
        );
        let s = stats().expect("installed");
        std::assert_eq!((s.lent, s.started, s.completed, s.unarmed), (1, 1, 1, 0));
        drop(pool);
    }

    // ---- ARCHITECTURE section 9.2: lwIP reads a received frame in place ----------

    /// A MAC that lends the frames it receives out of storage of its own, and
    /// records which buffers came back.
    struct LoanEnd {
        address: [u8; 6],
        /// Frames the far side has sent, waiting to be lent.
        inbox: Rc<RefCell<VecDeque<Vec<u8>>>>,
        /// The lent buffers, by cookie, until they are returned.
        lent: LentBuffers,
        returned: Rc<RefCell<Vec<u32>>>,
        out: Cable,
        next: u32,
    }

    impl EthernetMac for LoanEnd {
        fn mac_address(&self) -> [u8; 6] {
            self.address
        }
        fn transmit(&mut self, frame: &[u8]) -> bool {
            self.out.borrow_mut().push_back(frame.to_vec());
            true
        }
        /// The copying door finds nothing: a frame reaching lwIP in these tests
        /// came through the loan or did not come.
        fn receive(&mut self, _buf: &mut [u8]) -> Option<usize> {
            None
        }
        fn loans_rx(&self) -> bool {
            true
        }
        fn receive_loan(&mut self) -> Option<RxLoan> {
            let frame = self.inbox.borrow_mut().pop_front()?;
            let cookie = self.next;
            self.next += 1;
            let (ptr, len) = (frame.as_ptr(), frame.len());
            self.lent.borrow_mut().push((cookie, frame));
            Some(RxLoan { ptr, len, cookie })
        }
        fn return_rx(&mut self, cookie: u32) {
            self.lent.borrow_mut().retain(|(c, _)| *c != cookie);
            self.returned.borrow_mut().push(cookie);
        }
    }

    struct LoanRig {
        node: EthernetIf<LoanEnd>,
        inbox: Rc<RefCell<VecDeque<Vec<u8>>>>,
        lent: LentBuffers,
        returned: Rc<RefCell<Vec<u32>>>,
        out: Cable,
    }

    fn loan_node(link: &LwipLink) -> LoanRig {
        let inbox = Rc::new(RefCell::new(VecDeque::new()));
        let lent = Rc::new(RefCell::new(Vec::new()));
        let returned = Rc::new(RefCell::new(Vec::new()));
        let out: Cable = Rc::new(RefCell::new(VecDeque::new()));
        let node = EthernetIf::add(
            link,
            LoanEnd {
                address: NODE_MAC,
                inbox: inbox.clone(),
                lent: lent.clone(),
                returned: returned.clone(),
                out: out.clone(),
                next: 0,
            },
            Ipv4Config {
                address: NODE_IP,
                netmask: [255, 255, 255, 0],
                gateway: [0, 0, 0, 0],
            },
        )
        .expect("interface");
        LoanRig {
            node,
            inbox,
            lent,
            returned,
            out,
        }
    }

    /// How many frames the shim has wrapped in a custom pbuf so far, process-wide:
    /// the witness that a frame went in place and was not copied in.
    fn loaned_total() -> u32 {
        // SAFETY: reads a counter the shim owns.
        unsafe { lwip_sys::wz_ethif_rx_loaned_total() }
    }

    /// The point of the seam: a datagram that arrives as a lent frame reaches the
    /// bound socket intact, was wrapped in place and not copied in, and the buffer
    /// goes back to the MAC exactly once, when lwIP is done with it.
    #[test]
    fn a_received_datagram_is_read_in_place_and_its_buffer_goes_back_once() {
        let (_serial, link) = crate::lwip_test_link();
        let mut rig = loan_node(&link);
        let mut socket = bind_session_rx(&link, 7602).expect("bind");
        let before = loaned_total();

        rig.inbox
            .borrow_mut()
            .push_back(udp_frame(7601, 7602, b"read in place"));
        std::assert_eq!(rig.node.poll(), 1, "lwIP took the frame");

        let got = socket.try_recv().expect("the datagram came in");
        std::assert_eq!(got.data.as_slice(), b"read in place");
        std::assert_eq!(loaned_total(), before + 1, "it went in place, not by copy");
        std::assert_eq!(
            *rig.returned.borrow(),
            std::vec![0u32],
            "the buffer went back, once"
        );
        std::assert!(rig.lent.borrow().is_empty());
        std::assert_eq!(rig.node.held_rx(), 0, "and lwIP holds nothing");
    }

    /// ARP is read in place too: the far host's reply, lent, resolves the address,
    /// and the queued datagram leaves.
    #[test]
    fn an_arp_reply_read_in_place_resolves_the_address() {
        let (_serial, link) = crate::lwip_test_link();
        let mut rig = loan_node(&link);
        let socket = bind_session_rx(&link, 7602).expect("bind");
        rig.out.borrow_mut().clear();
        socket
            .send_to(crate::ipv4_addr_from_octets(FAR_IP), 7601, b"after arp")
            .expect("send");

        rig.inbox.borrow_mut().push_back(arp_reply());
        std::assert_eq!(rig.node.poll(), 1);

        let sent = rig
            .out
            .borrow_mut()
            .iter()
            .find_map(|f| udp_of(f).map(|(port, body)| (port, body.to_vec())))
            .expect("the datagram left once ARP resolved");
        std::assert_eq!(sent, (7601, b"after arp".to_vec()));
        std::assert_eq!(rig.returned.borrow().len(), 1, "the reply's buffer is back");
    }

    /// A buffer is lent for as long as lwIP reads it, which may be long after the
    /// input call returned: the first fragment of a datagram is parked in lwIP's
    /// reassembly queue, and its buffer stays out of the MAC's hands until the rest
    /// arrives and the datagram is delivered.
    #[test]
    fn a_fragment_lwip_parks_keeps_its_buffer_lent_until_reassembly_is_done() {
        let (_serial, link) = crate::lwip_test_link();
        let mut rig = loan_node(&link);
        let mut socket = bind_session_rx(&link, 7602).expect("bind");

        // One UDP datagram, cut in two on an 8-byte boundary: the UDP header and
        // eight payload bytes in the first fragment, the rest in the second.
        let payload = b"0123456789abcdefghij";
        let mut udp = std::vec::Vec::new();
        udp.extend_from_slice(&7601u16.to_be_bytes());
        udp.extend_from_slice(&7602u16.to_be_bytes());
        udp.extend_from_slice(&(8 + payload.len() as u16).to_be_bytes());
        udp.extend_from_slice(&[0, 0]);
        udp.extend_from_slice(payload);
        let (first, rest) = udp.split_at(16);

        let fragment = |offset8: u16, more: bool, body: &[u8]| {
            let mut ip = std::vec::Vec::new();
            ip.extend_from_slice(&[0x45, 0x00]);
            ip.extend_from_slice(&(20 + body.len() as u16).to_be_bytes());
            ip.extend_from_slice(&0x4242u16.to_be_bytes());
            let flags = (if more { 0x2000u16 } else { 0 }) | offset8;
            ip.extend_from_slice(&flags.to_be_bytes());
            ip.extend_from_slice(&[64, 17, 0, 0]);
            ip.extend_from_slice(&FAR_IP);
            ip.extend_from_slice(&NODE_IP);
            let sum = ipv4_checksum(&ip);
            ip[10..12].copy_from_slice(&sum.to_be_bytes());
            let mut f = std::vec::Vec::new();
            f.extend_from_slice(&NODE_MAC);
            f.extend_from_slice(&FAR_MAC);
            f.extend_from_slice(&[0x08, 0x00]);
            f.extend_from_slice(&ip);
            f.extend_from_slice(body);
            f
        };

        rig.inbox.borrow_mut().push_back(fragment(0, true, first));
        rig.node.poll();
        std::assert!(
            socket.try_recv().is_none(),
            "CONTROL: half a datagram is none"
        );
        std::assert!(
            rig.returned.borrow().is_empty(),
            "lwIP is still holding the first fragment, so its buffer is still lent"
        );
        std::assert_eq!(rig.node.held_rx(), 1);
        std::assert_eq!(rig.lent.borrow().len(), 1);

        rig.inbox.borrow_mut().push_back(fragment(2, false, rest));
        rig.node.poll();
        let got = socket.try_recv().expect("the datagram reassembled");
        std::assert_eq!(got.data.as_slice(), payload);
        std::assert_eq!(rig.node.held_rx(), 0);
        let mut back = rig.returned.borrow().clone();
        back.sort_unstable();
        std::assert_eq!(
            back,
            std::vec![0u32, 1],
            "both buffers went back, once each"
        );
    }

    // ---- ARCHITECTURE section 9.2: wire to slot to pbuf to socket, no copy ------

    use crate::mac_rx_pool::{EthRxRing, SlotState};
    use wz_runtime_core::MacRxPool;

    /// The installed generated receive pool, shared by the MAC double and the test,
    /// which reads the pool's own slot states.
    type SharedRing = Rc<RefCell<&'static mut EthRxRing>>;

    /// A MAC whose received frames are slots of the GENERATED receive pool, walked
    /// the way a descriptor-ring MAC walks them: a slot is armed and started, the
    /// "controller" writes the frame through the address the pool published and
    /// nothing else, the completion hands the slot to the CPU, and the frame is lent
    /// with the slot's index as its cookie; a return releases the slot.
    struct PoolEnd {
        address: [u8; 6],
        inbox: Cable,
        ring: SharedRing,
        returned: Rc<RefCell<Vec<u32>>>,
    }

    impl EthernetMac for PoolEnd {
        fn mac_address(&self) -> [u8; 6] {
            self.address
        }
        fn transmit(&mut self, _frame: &[u8]) -> bool {
            true
        }
        fn receive(&mut self, _buf: &mut [u8]) -> Option<usize> {
            None
        }
        fn loans_rx(&self) -> bool {
            true
        }
        fn receive_loan(&mut self) -> Option<RxLoan> {
            let frame = self.inbox.borrow_mut().pop_front()?;
            let mut ring = self.ring.borrow_mut();
            let (idx, addr) = ring.arm_rx().expect("a free slot");
            // SAFETY: the test is the bus master; the slot is armed for it.
            std::assert!(unsafe { ring.start_rx(idx) });
            // SAFETY: `addr` is the slot's first byte, in the bus master's hands,
            // and a frame is shorter than a slot.
            unsafe { core::ptr::copy_nonoverlapping(frame.as_ptr(), addr, frame.len()) };
            // SAFETY: the write above is the completion.
            let ptr = unsafe { ring.complete_rx(idx) }.expect("in flight");
            Some(RxLoan {
                ptr,
                len: frame.len(),
                cookie: idx as u32,
            })
        }
        fn return_rx(&mut self, cookie: u32) {
            std::assert!(
                self.ring.borrow_mut().release_rx(cookie as usize),
                "a lent slot"
            );
            self.returned.borrow_mut().push(cookie);
        }
    }

    struct PoolRig {
        node: EthernetIf<PoolEnd>,
        inbox: Cable,
        ring: SharedRing,
        returned: Rc<RefCell<Vec<u32>>>,
    }

    fn pool_node(link: &LwipLink) -> PoolRig {
        let storage: &'static mut crate::mac_rx_pool::RxPoolStorage =
            Box::leak(Box::new(crate::mac_rx_pool::RxPoolStorage::uninit()));
        let ring: SharedRing = Rc::new(RefCell::new(crate::mac_rx_pool::install(storage)));
        let inbox: Cable = Rc::new(RefCell::new(VecDeque::new()));
        let returned = Rc::new(RefCell::new(Vec::new()));
        let node = EthernetIf::add(
            link,
            PoolEnd {
                address: NODE_MAC,
                inbox: inbox.clone(),
                ring: ring.clone(),
                returned: returned.clone(),
            },
            Ipv4Config {
                address: NODE_IP,
                netmask: [255, 255, 255, 0],
                gateway: [0, 0, 0, 0],
            },
        )
        .expect("interface");
        PoolRig {
            node,
            inbox,
            ring,
            returned,
        }
    }

    impl PoolRig {
        /// The pool slot `ptr` lies in and its state, by the pool's own answer.
        fn slot_of(&self, ptr: *const u8) -> Option<(usize, SlotState)> {
            let ring = self.ring.borrow();
            let (start, len) = ring.span();
            let offset = (ptr as usize).checked_sub(start as usize)?;
            if offset >= len {
                return None;
            }
            let idx = offset / ring.slot_size();
            Some((idx, ring.pool().slot_state(idx)?))
        }

        fn free(&self) -> usize {
            self.ring.borrow().free_count()
        }
    }

    /// THE POINT: a datagram that arrives in a pool slot reaches a socket that holds
    /// lent frames WITHOUT A COPY. The bytes a reader is lent are inside the slot the
    /// controller wrote, 42 bytes in (Ethernet, IPv4 and UDP headers), the slot is the
    /// CPU's to read for as long as the socket holds it, and it is free once the
    /// reader gives the datagram back. Judged by address and by the pool's own state,
    /// which a copy cannot fake.
    #[test]
    fn a_datagram_a_socket_holds_is_read_in_the_pool_slot_the_controller_wrote() {
        let (_serial, link) = crate::lwip_test_link();
        let mut rig = pool_node(&link);
        let mut socket = bind_session_rx(&link, 7602).expect("bind");
        socket.hold_lent_rx(true);
        let (in_place, copied) = crate::rx_hold::counts();
        let taken = rx_frames_taken();

        rig.inbox
            .borrow_mut()
            .push_back(udp_frame(7601, 7602, b"read where it was written"));
        std::assert_eq!(rig.node.poll(), 1, "lwIP took the frame");

        let view = socket.peek_recv().expect("the datagram came in");
        std::assert_eq!(view.data, b"read where it was written");
        let (idx, state) = rig
            .slot_of(view.data.as_ptr())
            .expect("the bytes are a slot's");
        std::assert_eq!(state, SlotState::CpuRef, "the CPU's to read, while held");
        let slot_start = rig.ring.borrow().span().0 as usize + idx * 1536;
        std::assert_eq!(
            view.data.as_ptr() as usize - slot_start,
            14 + 20 + 8,
            "the payload, behind the headers, where the controller wrote the frame"
        );
        std::assert!(rig.returned.borrow().is_empty(), "the slot is still lent");
        std::assert_eq!(rig.node.held_rx(), 1);
        std::assert_eq!(
            rx_frames_taken(),
            (taken.0 + 1, taken.1),
            "lent, not copied in"
        );

        std::assert!(socket.consume_recv());
        std::assert_eq!(*rig.returned.borrow(), std::vec![idx as u32], "back once");
        std::assert_eq!(
            rig.slot_of(slot_start as *const u8),
            Some((idx, SlotState::Free))
        );
        std::assert_eq!(rig.free(), crate::eth_rx_pool_mcu::SLOT_COUNT);
        std::assert_eq!(rig.node.held_rx(), 0);
        std::assert_eq!(crate::rx_hold::counts(), (in_place + 1, copied));
    }

    /// CONTROL: a socket that does not hold copies the datagram in its callback, and
    /// the slot is free before a reader ever looks. The bytes the reader sees are
    /// not in the pool.
    #[test]
    fn a_socket_that_does_not_hold_copies_and_frees_the_slot_at_once() {
        let (_serial, link) = crate::lwip_test_link();
        let mut rig = pool_node(&link);
        let mut socket = bind_session_rx(&link, 7602).expect("bind");
        rig.inbox
            .borrow_mut()
            .push_back(udp_frame(7601, 7602, b"copied by the callback"));
        rig.node.poll();
        std::assert_eq!(rig.returned.borrow().len(), 1, "returned inside the poll");
        std::assert_eq!(rig.free(), crate::eth_rx_pool_mcu::SLOT_COUNT);
        let view = socket.peek_recv().expect("came in");
        std::assert_eq!(view.data, b"copied by the callback");
        std::assert!(rig.slot_of(view.data.as_ptr()).is_none(), "a copy");
        std::assert!(socket.consume_recv());
    }

    /// A datagram lwIP reassembles from two fragments arrives as a chain of two
    /// pbufs, which is no one piece to read in place: it takes the explicit copy,
    /// is counted as copied, and both slots go home when lwIP lets go of the chain.
    #[test]
    fn a_reassembled_datagram_is_copied_and_both_slots_go_home() {
        let (_serial, link) = crate::lwip_test_link();
        let mut rig = pool_node(&link);
        let mut socket = bind_session_rx(&link, 7602).expect("bind");
        socket.hold_lent_rx(true);
        let (in_place, copied) = crate::rx_hold::counts();

        let payload = b"0123456789abcdefghij";
        let mut udp = std::vec::Vec::new();
        udp.extend_from_slice(&7601u16.to_be_bytes());
        udp.extend_from_slice(&7602u16.to_be_bytes());
        udp.extend_from_slice(&(8 + payload.len() as u16).to_be_bytes());
        udp.extend_from_slice(&[0, 0]);
        udp.extend_from_slice(payload);
        let (first, rest) = udp.split_at(16);
        let fragment = |offset8: u16, more: bool, body: &[u8]| {
            let mut ip = std::vec::Vec::new();
            ip.extend_from_slice(&[0x45, 0x00]);
            ip.extend_from_slice(&(20 + body.len() as u16).to_be_bytes());
            ip.extend_from_slice(&0x4343u16.to_be_bytes());
            let flags = (if more { 0x2000u16 } else { 0 }) | offset8;
            ip.extend_from_slice(&flags.to_be_bytes());
            ip.extend_from_slice(&[64, 17, 0, 0]);
            ip.extend_from_slice(&FAR_IP);
            ip.extend_from_slice(&NODE_IP);
            let sum = ipv4_checksum(&ip);
            ip[10..12].copy_from_slice(&sum.to_be_bytes());
            let mut f = std::vec::Vec::new();
            f.extend_from_slice(&NODE_MAC);
            f.extend_from_slice(&FAR_MAC);
            f.extend_from_slice(&[0x08, 0x00]);
            f.extend_from_slice(&ip);
            f.extend_from_slice(body);
            f
        };
        rig.inbox.borrow_mut().push_back(fragment(0, true, first));
        rig.node.poll();
        rig.inbox.borrow_mut().push_back(fragment(2, false, rest));
        rig.node.poll();

        let view = socket.peek_recv().expect("reassembled");
        std::assert_eq!(view.data, payload);
        std::assert!(rig.slot_of(view.data.as_ptr()).is_none(), "a copy");
        std::assert_eq!(rig.returned.borrow().len(), 2, "both slots home");
        std::assert_eq!(rig.free(), crate::eth_rx_pool_mcu::SLOT_COUNT);
        std::assert!(socket.consume_recv());
        std::assert_eq!(crate::rx_hold::counts(), (in_place, copied + 1));
    }

    /// The shim lends at most `RX_HELD_MAX` frames at once, so a socket that holds
    /// that many leaves the next frame to the copying input: it is copied in, the
    /// MAC's slot goes home at once, and the frame reaches the socket all the same.
    /// Nothing is dropped, and nothing reaches for memory but the pool and lwIP's.
    #[test]
    fn past_the_shims_bound_a_held_socket_falls_back_to_the_copy() {
        let (_serial, link) = crate::lwip_test_link();
        let mut rig = pool_node(&link);
        let mut socket = bind_session_rx(&link, 7602).expect("bind");
        socket.hold_lent_rx(true);
        let taken = rx_frames_taken();
        for i in 0..RX_HELD_MAX as u8 {
            rig.inbox
                .borrow_mut()
                .push_back(udp_frame(7601, 7602, &[i; 4]));
            rig.node.poll();
        }
        std::assert_eq!(rig.node.held_rx(), RX_HELD_MAX);
        std::assert!(rig.returned.borrow().is_empty());
        rig.inbox
            .borrow_mut()
            .push_back(udp_frame(7601, 7602, b"ninth"));
        rig.node.poll();
        std::assert_eq!(
            rx_frames_taken(),
            (taken.0 + RX_HELD_MAX as u32, taken.1 + 1),
            "eight lent, the ninth copied in"
        );
        std::assert_eq!(rig.returned.borrow().len(), 1, "the ninth's slot went home");
        for i in 0..RX_HELD_MAX as u8 {
            let view = socket.peek_recv().expect("held");
            std::assert_eq!(view.data, &[i; 4]);
            std::assert!(rig.slot_of(view.data.as_ptr()).is_some(), "in its slot");
            std::assert!(socket.consume_recv());
        }
        let ninth = socket.try_recv().expect("the ninth");
        std::assert_eq!(ninth.data.as_slice(), b"ninth");
        std::assert_eq!(rig.free(), crate::eth_rx_pool_mcu::SLOT_COUNT);
    }

    /// An owned receive of a held frame copies it then and gives the slot back, and
    /// a socket dropped with frames still held gives theirs back too.
    #[test]
    fn an_owned_receive_or_a_dropped_socket_gives_held_slots_back() {
        let (_serial, link) = crate::lwip_test_link();
        let mut rig = pool_node(&link);
        let mut socket = bind_session_rx(&link, 7602).expect("bind");
        socket.hold_lent_rx(true);
        for payload in [&b"owned"[..], b"dropped-1", b"dropped-2"] {
            rig.inbox
                .borrow_mut()
                .push_back(udp_frame(7601, 7602, payload));
            rig.node.poll();
        }
        std::assert_eq!(rig.free(), crate::eth_rx_pool_mcu::SLOT_COUNT - 3);
        let owned = socket.try_recv().expect("held");
        std::assert_eq!(owned.data.as_slice(), b"owned");
        std::assert_eq!(rig.returned.borrow().len(), 1);
        drop(socket);
        std::assert_eq!(rig.returned.borrow().len(), 3, "the drop gave two back");
        std::assert_eq!(rig.free(), crate::eth_rx_pool_mcu::SLOT_COUNT);
        std::assert_eq!(rig.node.held_rx(), 0);
    }
}
