// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The host's sockets as a stack of the slot profile's session host.
//!
//! [`PosixStack`] is `wz_runtime_coop::ip_stack`'s `IpStack` at [`PosixUdpSocket`] and
//! [`PosixTcpDial`]: a dial to `udp/...` opens the datagram link, a dial to `tcp/...` the stream
//! link over a [`PosixTcpSocket`], and [`PosixDriver`] is either, in the session's slot. Each
//! claims its receive buffer and the buffer its frames are encoded into from two tables the image
//! declares, so a dial moves a few words and no bytes.
//!
//! Present only under `session-slot`: a build with a heap has the heap forms of the cooperative
//! runtime, and the session host this stack is given is the slot profile's.

use crate::net::PosixUdpSocket;
use crate::stream::{PosixTcpDial, PosixTcpSocket};

/// The host's sockets as a stack of the slot profile's session host, made with
/// `PosixStack::new(local, rx, tx, PosixTcpDial)`. The image states how long its datagram links
/// may sleep when the session has nothing due ([`PosixStack::with_idle_wait_ms`]) when the
/// session is the only thing its loop waits on.
pub type PosixStack = wz_runtime_coop::ip_stack::IpStack<PosixUdpSocket, PosixTcpDial>;

/// The driver a [`PosixStack`] opens: the session's link in its slot, a datagram or a stream
/// link as the dial named, with both buffers claimed from the image's tables.
pub type PosixDriver = wz_runtime_coop::ip_stack::IpDriver<PosixUdpSocket, PosixTcpSocket>;
