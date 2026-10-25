// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! What a hosted operating system tells a node about its own network, for every runtime that
//! holds a socket.
//!
//! The interface facts ([`link_interfaces`]): which interfaces exist and carry an address, which
//! can carry multicast, which index an address selects, which names a Windows adapter answers
//! to. Read live at each call, and "could not determine" is told apart from "none".
//!
//! The multicast sockets ([`multicast`]): the policy under them (which interface an `#iface=`
//! names, what an unpinned link joins and sends on, whether a refused membership ends the bind,
//! the loopback and the hop limit) built into a bound `socket2::Socket` that a runtime adopts.
//!
//! Nothing here names a runtime, an executor or a socket type of one.

pub mod link_interfaces;
pub mod multicast;
