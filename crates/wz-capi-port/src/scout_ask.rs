// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! What a C ABI asks of a scouting window: the one value its door hands each engine's window.

use core::net::IpAddr;

use wz_session_core::session_zid::SessionZid;

/// One scout as the ABI asks it: the multicast group and port the Scout is sent to, the kinds of
/// node it asks for, the zid it names as the asker (`None` for none), and how long the window
/// stays open.
#[derive(Clone, Copy)]
pub struct ScoutAsk {
    /// The multicast group the Scout is sent to.
    pub group: IpAddr,
    /// The port on that group.
    pub port: u16,
    /// The kinds of node asked for, as the Scout's `what` bits.
    pub what: u8,
    /// The asker the Scout names, `None` for none.
    pub zid: Option<SessionZid>,
    /// How long the window stays open, in milliseconds.
    pub budget_ms: u64,
}
