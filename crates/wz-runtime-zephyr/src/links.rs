// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
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
//! dialled link names it as its source, and on a board it comes from DHCP or
//! Kconfig through [`board_ipv4`](crate::net::board_ipv4).

use alloc::rc::Rc;

use wz_runtime_coop::session_drive::{LinkOpenError, OpenedLink, SessionLinks, UdpPeer};

use crate::net::{ZephyrUdpDriver, ZephyrUdpSocket, UDP_RX_CAPACITY};

/// The links of a node whose network stack is Zephyr's own.
pub struct ZephyrLinks {
    local: [u8; 4],
    rx_capacity: usize,
}

impl ZephyrLinks {
    /// Links bound on the node's own address `local`, each with a receive
    /// buffer that holds the largest UDP datagram.
    pub fn new(local: [u8; 4]) -> Self {
        Self {
            local,
            rx_capacity: UDP_RX_CAPACITY,
        }
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
    pub fn local(&self) -> [u8; 4] {
        self.local
    }
}

impl SessionLinks for ZephyrLinks {
    type Pump = Rc<ZephyrUdpDriver>;

    fn open_acceptor(&self, port: u16) -> Result<OpenedLink<Self::Pump>, LinkOpenError> {
        // The peer is whoever speaks first; the driver learns it on receive.
        let socket =
            ZephyrUdpSocket::bind(self.local, port).map_err(|_| LinkOpenError::Exhausted)?;
        let driver = Rc::new(ZephyrUdpDriver::acceptor_with_capacity(
            socket,
            self.rx_capacity,
        ));
        Ok(OpenedLink {
            sink: driver.clone(),
            pump: driver,
        })
    }

    fn open_initiator(&self, peer: UdpPeer) -> Result<OpenedLink<Self::Pump>, LinkOpenError> {
        // Port 0 has the stack choose a free one, one per initiator session.
        let socket = ZephyrUdpSocket::bind(self.local, 0).map_err(|_| LinkOpenError::Exhausted)?;
        let driver = Rc::new(ZephyrUdpDriver::initiator_with_capacity(
            socket,
            (peer.addr, peer.port),
            self.rx_capacity,
        ));
        Ok(OpenedLink {
            sink: driver.clone(),
            pump: driver,
        })
    }
}
