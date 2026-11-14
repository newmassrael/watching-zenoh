// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! `ZephyrLinks` — Zephyr's side of the session shell's `SessionLinks` seam.
//!
//! The shell (`wz-session-mcu`) opens two kinds of link and names no stack: one
//! that accepts on a port, one that dials an address. This is what each is on
//! Zephyr's BSD sockets: a socket bound on the node's own address and the given
//! port for an acceptor, on a port the stack chooses for an initiator, wrapped in
//! the [`ZephyrUdpDriver`] that is both the session's outbound sink and the link
//! the drive loop pumps.
//!
//! The local address is the node's, as its interface holds it. It is a
//! parameter, never a constant here: the node advertises it as its locator, a
//! dialled link names it as its source, and on a board it comes from DHCP,
//! autoconfiguration or Kconfig through [`board_ip`](crate::net::board_ip), of the
//! family the image's Kconfig chose.

use alloc::rc::Rc;
use core::net::{IpAddr, SocketAddr};

use wz_runtime_coop::session_drive::{LinkOpenError, LinkProto, Locator, OpenedLink, SessionLinks};
use wz_runtime_coop::udp_link::{bind_refused, dial_bind};

use crate::net::{HeapTx, ZephyrUdpDriver, ZephyrUdpSocket, UDP_RX_CAPACITY};
use crate::stream::{ZephyrTcpDial, ZephyrTcpSocket};

/// Zephyr's sockets as the session shell's links on the heap profile, `udp/` and `tcp/` alike:
/// `wz_runtime_coop::ip_stack`'s `IpLinks` at [`ZephyrUdpSocket`] and [`ZephyrTcpDial`], made
/// with `ZephyrIpLinks::new(local, ZephyrTcpDial)`. A dial opens the link of the protocol its
/// locator names, a `tcp/` listener takes connections off its port, and each link allocates its
/// buffers when it opens. The twin of `wz-runtime-posix`'s `PosixLinks`, and what a program with an
/// allocator on Zephyr (the pico C ABI over the cooperative engine) gives the session shell;
/// [`ZephyrLinks`] is the datagram-only form the heap images that predate it were written against.
pub type ZephyrIpLinks = wz_runtime_coop::ip_stack::IpLinks<ZephyrUdpSocket, ZephyrTcpDial>;

/// The driver [`ZephyrIpLinks`] opens: a datagram or a stream link, as the dial named.
pub type ZephyrHeapDriver =
    wz_runtime_coop::ip_stack::HeapIpDriver<ZephyrUdpSocket, ZephyrTcpSocket>;

/// The links of a node whose network stack is Zephyr's own.
pub struct ZephyrLinks {
    local: IpAddr,
    rx_capacity: usize,
    tx_slots: usize,
    tx_capacity: usize,
}

impl ZephyrLinks {
    /// Links bound on the node's own address `local`, each with a receive
    /// buffer that holds the largest UDP datagram and no buffer of its own to
    /// encode frames into (the session builds each in a buffer it allocates).
    pub fn new(local: impl Into<IpAddr>) -> Self {
        Self {
            local: local.into(),
            rx_capacity: UDP_RX_CAPACITY,
            tx_slots: 0,
            tx_capacity: 0,
        }
    }

    /// Links that lend the session `slots` buffers of `bytes` each to encode its frames into,
    /// allocated once with the link: a frame then costs no allocation, and the link states the
    /// largest frame it carries (these `bytes`) and the largest batch it receives (its receive
    /// buffer). `bytes` is the batch the sessions negotiate; a session that batches holds one slot
    /// open while it encodes the next message into another, so it needs two.
    pub fn with_tx_buffers(mut self, slots: usize, bytes: usize) -> Self {
        self.tx_slots = slots;
        self.tx_capacity = bytes;
        self
    }

    /// Links whose receive buffers hold `bytes` each. A node runs one accepting
    /// link and one per dialled endpoint at once, so a board with a small heap
    /// sizes this to the batch its sessions negotiate instead of paying 64 KiB a
    /// link.
    pub fn with_rx_capacity(mut self, bytes: usize) -> Self {
        self.rx_capacity = bytes;
        self
    }

    /// The address the links are bound on, as a node advertises it.
    pub fn local(&self) -> IpAddr {
        self.local
    }
}

impl SessionLinks for ZephyrLinks {
    type Pump = Rc<ZephyrUdpDriver>;

    fn open_acceptor(&self, port: u16) -> Result<OpenedLink<Self::Pump>, LinkOpenError> {
        // The peer is whoever opens a session first; the driver is bound by its InitSyn.
        let socket = ZephyrUdpSocket::bind(SocketAddr::new(self.local, port))
            .map_err(bind_refused::<ZephyrUdpSocket>)?;
        let driver = Rc::new(ZephyrUdpDriver::acceptor_with_buffers(
            socket,
            self.rx_capacity,
            HeapTx::new(self.tx_slots, self.tx_capacity),
        ));
        Ok(OpenedLink {
            sink: driver.clone(),
            pump: driver,
        })
    }

    fn open_initiator(&self, to: Locator) -> Result<OpenedLink<Self::Pump>, LinkOpenError> {
        // These links are Zephyr's datagram sockets alone, so a `tcp/` dial is not this stack's;
        // `ZephyrIpLinks` carries both.
        if to.proto != LinkProto::Udp {
            return Err(LinkOpenError::Unsupported);
        }
        // Port 0 has the stack choose a free one, one per initiator session.
        let socket = ZephyrUdpSocket::bind(dial_bind(self.local, to.at))
            .map_err(bind_refused::<ZephyrUdpSocket>)?;
        let driver = Rc::new(ZephyrUdpDriver::initiator_with_buffers(
            socket,
            to.at,
            self.rx_capacity,
            HeapTx::new(self.tx_slots, self.tx_capacity),
        ));
        Ok(OpenedLink {
            sink: driver.clone(),
            pump: driver,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use wz_runtime_coop::session_drive::SessionLinks;

    /// What the session shell holds of a stack: its links, and the driver each link pumps.
    fn shell_links<L: SessionLinks<Pump = Rc<ZephyrHeapDriver>>>(_: &L) {}

    /// Zephyr's two sockets meet every bound the heap profile's stack asks of a platform's, so the
    /// session shell takes them as it takes the host's: the stack is made without opening a
    /// socket, and its driver is the datagram-or-stream one.
    #[test]
    fn zephyrs_sockets_are_the_shells_links_on_the_heap_profile() {
        let links = ZephyrIpLinks::new(IpAddr::V4(core::net::Ipv4Addr::UNSPECIFIED), ZephyrTcpDial)
            .waited_by_owner()
            .with_tx_buffers(2, 2048);
        shell_links(&links);
    }
}
