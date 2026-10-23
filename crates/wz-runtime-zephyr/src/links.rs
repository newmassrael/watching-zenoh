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
//! dialled link names it as its source, and on a board it comes from DHCP or
//! Kconfig through [`board_ipv4`](crate::net::board_ipv4).

use alloc::rc::Rc;

use wz_runtime_coop::session_drive::{LinkOpenError, LinkProto, Locator, OpenedLink, SessionLinks};

use crate::net::{HeapTx, ZephyrUdpDriver, ZephyrUdpSocket, UDP_RX_CAPACITY};

/// The links of a node whose network stack is Zephyr's own.
pub struct ZephyrLinks {
    local: [u8; 4],
    rx_capacity: usize,
    tx_slots: usize,
    tx_capacity: usize,
}

impl ZephyrLinks {
    /// Links bound on the node's own address `local`, each with a receive
    /// buffer that holds the largest UDP datagram and no buffer of its own to
    /// encode frames into (the session builds each in a buffer it allocates).
    pub fn new(local: [u8; 4]) -> Self {
        Self {
            local,
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
    pub fn local(&self) -> [u8; 4] {
        self.local
    }
}

impl SessionLinks for ZephyrLinks {
    type Pump = Rc<ZephyrUdpDriver>;

    fn open_acceptor(&self, port: u16) -> Result<OpenedLink<Self::Pump>, LinkOpenError> {
        // The peer is whoever opens a session first; the driver is bound by its InitSyn.
        let socket =
            ZephyrUdpSocket::bind(self.local, port).map_err(|_| LinkOpenError::Exhausted)?;
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
        // These links are Zephyr's datagram sockets; no stream socket of Zephyr's is written
        // over `wz_runtime_coop::stream_link` yet, so a `tcp/` dial is not this stack's.
        if to.proto != LinkProto::Udp {
            return Err(LinkOpenError::Unsupported);
        }
        // Port 0 has the stack choose a free one, one per initiator session.
        let socket = ZephyrUdpSocket::bind(self.local, 0).map_err(|_| LinkOpenError::Exhausted)?;
        let driver = Rc::new(ZephyrUdpDriver::initiator_with_buffers(
            socket,
            (to.at.addr, to.at.port),
            self.rx_capacity,
            HeapTx::new(self.tx_slots, self.tx_capacity),
        ));
        Ok(OpenedLink {
            sink: driver.clone(),
            pump: driver,
        })
    }
}
