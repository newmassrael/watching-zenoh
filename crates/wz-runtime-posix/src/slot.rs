// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The host's sockets as a stack of the slot profile's session host.
//!
//! On a POSIX host, `PosixStack` is `wz_runtime_coop::ip_stack`'s `IpStack` at `PosixUdpSocket`
//! and `PosixTcpDial`: a dial to `udp/...` opens the datagram link, a dial to `tcp/...` the
//! stream link over a `PosixTcpSocket`, and `PosixDriver` is either, in the session's slot. On
//! Windows, `WindowsStack` and `WindowsDriver` are the same over Winsock's sockets. Each link
//! claims its receive buffer and the buffer its frames are encoded into from two tables the program
//! declares, so a dial moves a few words and no bytes.
//!
//! Present only under `session-slot`: a build with a heap has the heap forms of the cooperative
//! runtime, and the session host this stack is given is the slot profile's.

#[cfg(unix)]
use crate::net::PosixUdpSocket;
#[cfg(unix)]
use crate::stream::{PosixTcpDial, PosixTcpSocket};
#[cfg(windows)]
use crate::windows::net::WindowsUdpSocket;
#[cfg(windows)]
use crate::windows::stream::{WindowsTcpDial, WindowsTcpSocket};

/// The host's sockets as a stack of the slot profile's session host, made with
/// `PosixStack::new(local, rx, tx, PosixTcpDial)`. The image states how long its datagram links
/// may sleep when the session has nothing due (`PosixStack::with_idle_wait_ms`) when the
/// session is the only thing its loop waits on.
#[cfg(unix)]
pub type PosixStack = wz_runtime_coop::ip_stack::IpStack<PosixUdpSocket, PosixTcpDial>;

/// The driver a [`PosixStack`] opens: the session's link in its slot, a datagram or a stream
/// link as the dial named, with both buffers claimed from the image's tables.
#[cfg(unix)]
pub type PosixDriver = wz_runtime_coop::ip_stack::IpDriver<PosixUdpSocket, PosixTcpSocket>;

/// Winsock's sockets as a stack of the slot profile's session host, made with
/// `WindowsStack::new(local, rx, tx, WindowsTcpDial)`.
#[cfg(windows)]
pub type WindowsStack = wz_runtime_coop::ip_stack::IpStack<WindowsUdpSocket, WindowsTcpDial>;

/// The driver a [`WindowsStack`] opens: the session's link in its slot, a datagram or a stream
/// link as the dial named, with both buffers claimed from the program's tables.
#[cfg(windows)]
pub type WindowsDriver = wz_runtime_coop::ip_stack::IpDriver<WindowsUdpSocket, WindowsTcpSocket>;

#[cfg(all(test, windows))]
mod tests {
    use super::*;
    use core::net::{IpAddr, Ipv4Addr, SocketAddr};
    use wz_runtime_coop::session_drive::{Bind, LinkOpenError, Locator, SlotStack};
    use wz_runtime_coop::stream_link::StreamListen;
    use wz_session_core::byte_cells::ByteCells;

    use crate::windows::stream::WindowsTcpListener;

    const LOOPBACK: IpAddr = IpAddr::V4(Ipv4Addr::LOCALHOST);

    static RX: ByteCells<66, 1> = ByteCells::new();
    static TX: ByteCells<34, 1> = ByteCells::new();

    /// Holds only for a stack of the slot profile whose sessions hold [`WindowsDriver`].
    fn holds_windows_drivers<T: SlotStack<Driver = WindowsDriver>>(_stack: &T) {}

    #[test]
    fn a_dial_opens_the_link_its_protocol_names_in_a_cell_of_the_programs_tables() {
        let mut stack = WindowsStack::new(LOOPBACK, &RX, &TX, WindowsTcpDial);
        holds_windows_drivers(&stack);
        let listener = WindowsTcpListener::bind(SocketAddr::new(LOOPBACK, 0)).expect("a listener");
        let at = listener.local();
        let tcp = stack
            .bind(Locator::tcp(at))
            .expect("a stream link to the listener");
        assert!(matches!(tcp, WindowsDriver::Tcp(_)));
        assert!(
            matches!(stack.bind(Locator::udp(at)), Err(LinkOpenError::Exhausted)),
            "the one cell of each table is held by the stream link"
        );
        drop(tcp);
        let udp = stack
            .bind(Locator::udp(at))
            .expect("the cells came back with the stream link");
        assert!(matches!(udp, WindowsDriver::Udp(_)));
    }
}
