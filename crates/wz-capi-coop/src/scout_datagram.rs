// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! Active scouting over one datagram socket of the stack the engine runs on, with no `std`.
//!
//! zenoh-pico scouts by opening a UDP unicast link to the scouting group and reading the Hellos
//! that answer off it (`vendor/zenoh-pico/src/session/scout.c` @
//! `_z_scout_add_link(scout, locator, NULL)`). Where its platform has an interface iterator (a
//! POSIX host, lwIP) it opens one such link per interface; where it has none, Zephyr's sockets
//! among them, it opens the one: a socket the stack binds on first send
//! (`vendor/zenoh-pico/src/link/transport/udp/udp_zephyr.c` @ `_z_udp_zephyr_open`), the Scout
//! written to the group from it, and the responders' unicast Hellos read back on it. That is this
//! window: the session's rules (`wz_session_core::scouting_host`) pumped over any
//! [`DatagramSocket`], so an image scouts on the socket type its links already use. The host's
//! window with a socket for each interface is `scout`.
//!
//! The group is an IPv4 address, as a datagram socket of the stacks is; a window asked of any other
//! has no socket and finds nothing, as a window nobody answers does.

use core::ffi::c_int;

use wz_runtime_coop::udp_link::DatagramSocket;
use wz_runtime_coop::{ClockSource, CoopRuntime};
use wz_session_core::scouting_host::{
    deliver_in_upstream_order, ScoutParams, ScoutWindow, ScoutedHello,
};

use crate::prelude::*;

/// How long one wait for a Hello lasts before the window reads its clock again: a few
/// milliseconds, so the window answers a Hello at once and ends close to its budget without
/// spinning, as the host's window sleeps between reads.
const READ_WAIT_MS: c_int = 2;

/// Scout `group:port` for `budget_ms` over a socket of `U`, reading each datagram into a buffer of
/// `rx_capacity` bytes (zenoh-pico reads a scout into one of its multicast batch size), and hand
/// each peer that answered to `on_hello` in the order upstream delivers them (after the window,
/// last responder first). The number delivered; a socket that cannot be opened is a window nobody
/// answers, `0`.
#[allow(clippy::too_many_arguments)]
pub fn run_scout<U, C>(
    clock: &C,
    group: [u8; 4],
    port: u16,
    what: u8,
    zid: Vec<u8>,
    budget_ms: u64,
    rx_capacity: usize,
    on_hello: impl FnMut(&ScoutedHello),
) -> usize
where
    U: DatagramSocket,
    C: ClockSource + Clone + 'static,
{
    let params = ScoutParams {
        what,
        zid,
        timeout_ms: budget_ms,
        exit_on_first: false,
    };
    let hellos = window::<U, C>(clock, group, port, params, rx_capacity);
    deliver_in_upstream_order(&hellos, on_hello)
}

/// Scout for `budget_ms` and answer the FIRST node that replies, or `None` when none does in the
/// window: zenoh-pico's open-time lookup, which `_z_open` runs when its config names no locator.
pub fn scout_first<U, C>(
    clock: &C,
    group: [u8; 4],
    port: u16,
    what: u8,
    zid: Vec<u8>,
    budget_ms: u64,
    rx_capacity: usize,
) -> Option<ScoutedHello>
where
    U: DatagramSocket,
    C: ClockSource + Clone + 'static,
{
    let params = ScoutParams {
        what,
        zid,
        timeout_ms: budget_ms,
        exit_on_first: true,
    };
    window::<U, C>(clock, group, port, params, rx_capacity)
        .into_iter()
        .next()
}

/// One window: the Scout sent once, every datagram that arrives read until the machine resolves,
/// and the Hellos collected. A read that fails ends the window with what it has, as a lost member
/// does in the host's window.
fn window<U, C>(
    clock: &C,
    group: [u8; 4],
    port: u16,
    params: ScoutParams,
    rx_capacity: usize,
) -> Vec<ScoutedHello>
where
    U: DatagramSocket,
    C: ClockSource + Clone + 'static,
{
    let mut window = ScoutWindow::<CoopRuntime<C>>::new(params);
    let actions = window.actions().clone();
    let Ok(socket) = U::bind([0; 4], 0) else {
        return actions.scouted_hellos();
    };
    let sent = window
        .open()
        .is_some_and(|scout| socket.send_to(group, port, &scout).is_ok());
    // The start is read rounded UP to the millisecond, as the host's window reads it, so the
    // window stays open for at least its budget.
    window.sent(clock.now_us().div_ceil(1000), sent);
    let mut buffer = vec![0u8; rx_capacity.max(1)];
    while !window.resolved() {
        socket.wait_readable(READ_WAIT_MS);
        let mut lost = false;
        while !window.resolved() {
            match socket.try_recv(&mut buffer) {
                Ok(Some((len, _addr, _port))) => window.datagram(&buffer[..len]),
                Ok(None) => break,
                Err(_) => {
                    lost = true;
                    break;
                }
            }
        }
        window.tick(clock.now_us() / 1000);
        if lost {
            break;
        }
    }
    actions.scouted_hellos()
}
