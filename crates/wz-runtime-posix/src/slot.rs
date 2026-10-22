// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The host's sockets as a stack of the slot profile's session host.
//!
//! [`PosixStack`] is `wz_runtime_coop::udp_link`'s `UdpStack` at
//! [`PosixUdpSocket`](crate::net::PosixUdpSocket), and [`PosixUdpDriver`] is the driver it opens
//! in the session's slot. The driver claims its receive buffer and the buffer its frames are
//! encoded into from two tables the image declares, so a dial moves a few words and no bytes.
//!
//! Present only under `session-slot`: a build with a heap has the heap forms of the cooperative
//! runtime, and the session host this stack is given is the slot profile's.

use crate::net::PosixUdpSocket;

/// The host's sockets as a stack of the slot profile's session host. The image states how long
/// its link may sleep when the session has nothing due ([`PosixStack::with_idle_wait_ms`]) when
/// the session is the only thing its loop waits on.
pub type PosixStack = wz_runtime_coop::udp_link::UdpStack<PosixUdpSocket>;

/// The driver a [`PosixStack`] opens: the session's link in its slot, with both buffers claimed
/// from the image's tables.
pub type PosixUdpDriver = wz_runtime_coop::udp_link::FixedUdpDriver<PosixUdpSocket>;
