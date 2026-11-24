// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The admin node over Zephyr's own network stack and BSD sockets.
//!
//! For a board whose Ethernet (or Wi-Fi, or modem) Zephyr drives. The interface,
//! its address and its link-layer identity are Zephyr's: DHCP or Kconfig gave the
//! address, the driver gave the MAC. This module reads them and does nothing
//! else; the sockets are `wz_runtime_zephyr::ZephyrLinks`.

use alloc::rc::Rc;
use alloc::vec::Vec;
use core::ffi::CStr;
use core::net::IpAddr;

use wz::runtime_zephyr::net::{await_board_ip, board_zid};
use wz::runtime_zephyr::ZephyrLinks;

use crate::{NodeNet, BATCH_SIZE};

/// How long the node waits for the board to have an address: a DHCP lease on a
/// slow link takes seconds, and a board with no link or no server never gets one.
const ADDRESS_WAIT_MS: u32 = 30_000;

/// Extra bytes a link's receive buffer holds beyond one batch, so a datagram that
/// carries a batch and a transport header is not truncated.
const RX_SLACK: usize = 64;

pub struct ZephyrNet {
    links: Rc<ZephyrLinks>,
    address: IpAddr,
    zid: Vec<u8>,
}

impl ZephyrNet {
    /// Wait for the board's interface to hold an address of the family the image chose
    /// (`CONFIG_WZ_NODE_IPV4` or `CONFIG_WZ_NODE_IPV6`) and read the identity from it. The error
    /// is what the console says when it does not.
    pub fn bring_up() -> Result<Self, &'static CStr> {
        let Some(address) = await_board_ip(ADDRESS_WAIT_MS) else {
            return Err(c"wz: FAIL - the board's interface never got an address of its family");
        };
        let Some(zid) = board_zid() else {
            return Err(c"wz: FAIL - the board gave no identity to derive a zenoh id from");
        };
        let links = ZephyrLinks::new(address).with_rx_capacity(BATCH_SIZE as usize + RX_SLACK);
        // Each link lends its session the buffers it needs, allocated once and one batch long: the
        // client node's sessions encode their frames into them (`wz/transport-tx-lend`), and a
        // link sends a frame of bytes from one of them. Two, because a session that batches holds
        // one open while another frame leaves; a link holds more where its session needs more.
        let links = links.with_tx_buffers(2, BATCH_SIZE as usize);
        Ok(Self {
            links: Rc::new(links),
            address,
            zid,
        })
    }
}

impl NodeNet for ZephyrNet {
    type Links = ZephyrLinks;

    fn links(&self) -> Rc<ZephyrLinks> {
        self.links.clone()
    }

    fn addresses(&self) -> Vec<IpAddr> {
        alloc::vec![self.address]
    }

    fn zid(&self) -> Vec<u8> {
        self.zid.clone()
    }

    fn idle_sleep_us(&self) -> i32 {
        // The session's pass waits on its socket for up to a millisecond (`ZephyrUdpDriver::
        // service`), which is what gives the net stack's threads the CPU; a sleep after it only
        // delays the next frame.
        0
    }
}
