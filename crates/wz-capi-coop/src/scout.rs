// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! Active multicast scouting on the host's own sockets, with no executor.
//!
//! A scouting window needs no session: one Scout is asked of the group, the Hellos that answer are
//! collected for a budget, and the window ends. The rules of it are the session's
//! (`wz_session_core::scouting_host`: what a Scout says, which datagrams are answers and which are
//! named and dropped, when it is over) and the sockets are the host's
//! (`wz_runtime_posix::scouting`: an ask socket pinned to each interface that can carry multicast,
//! and the group socket, over either host's sockets). What this module adds is the blocking host
//! that pumps the one with the other: it opens the sockets, sends the Scout, reads what arrives
//! and reads the clock, on the calling thread, which is what a C program that calls `z_scout`
//! expects, and what zenoh-pico's own `__z_scout_loop` does. It needs no `std`: a host library
//! built without it scouts as the one with it does.

#[cfg(all(test, feature = "std", unix))]
use alloc::sync::Arc;
use core::ffi::c_int;
use core::net::IpAddr;

use wz_runtime_coop::{ClockSource, CoopRuntime};
use wz_runtime_posix::group::MulticastSocket;
use wz_runtime_posix::scouting::ScoutMembers;
#[cfg(all(test, feature = "std", unix))]
use wz_session_core::scouting_host::ScoutingActions;
use wz_session_core::scouting_host::{
    deliver_rows_in_upstream_order, HelloRow, HelloTable, ScoutWindow, ScoutWindowPlace,
};
use wz_session_core::session_zid::SessionZid;

use crate::prelude::*;

pub use wz_session_core::scouting_host::{
    parse_multicast_locator, ScoutParams, ScoutedHello, MULTICAST_LOCATOR_DEFAULT,
    SCOUTING_TIMEOUT_DEFAULT_MS, SCOUTING_WHAT_DEFAULT,
};

/// How long a window waits for a datagram when none has arrived, before it reads its clock again:
/// a few milliseconds, so the window ends close to its budget without spinning, and a Hello that
/// arrives ends the wait at once.
const IDLE_WAIT_MS: c_int = 2;

/// The interface addresses a window asks by: the first IPv4 address of every interface that is up
/// and can carry multicast (the host's own reading; none when it cannot be read, which is a window
/// on the group socket alone).
fn interface_addresses() -> Vec<IpAddr> {
    wz_runtime_posix::interfaces::multicast_interface_addresses().unwrap_or_default()
}

/// One scouting window over `members`: send the Scout, read until the machine resolves, and answer
/// what was collected.
///
/// `clock` is the host's: the window's budget is measured against it. A window with no member, or
/// whose Scout could not leave by any, ends at once (the machine returns to `Idle` on a failed
/// send), as a window nobody answers does.
#[cfg(all(test, feature = "std", unix))]
fn run_window<S: MulticastSocket, C: ClockSource + Clone + 'static>(
    clock: &C,
    members: ScoutMembers<S>,
    params: ScoutParams,
) -> Arc<ScoutingActions<CoopRuntime<C>>> {
    // Built in this frame's place and pumped from it: the machine is made in a frame that has
    // returned before the first datagram is read.
    let mut place = ScoutWindowPlace::<CoopRuntime<C>>::empty();
    let window = place.build(params);
    let actions = Arc::clone(
        window
            .shared_actions()
            .expect("a window built over its params shares its state"),
    );
    // The most a single datagram can carry over UDP.
    let mut buffer = vec![0u8; 65_507];
    pump(clock, members, window, &mut buffer);
    actions
}

/// [`run_window`] recording its Hellos in `table` and reading each datagram into `buffer`, both
/// the host's where it keeps the scout's state, which the window clears and holds only until it
/// returns. Its own state lies in this frame's place: the window makes no allocation.
fn run_window_over<S: MulticastSocket, C: ClockSource + Clone + 'static>(
    clock: &C,
    members: ScoutMembers<S>,
    params: ScoutParams,
    table: &mut HelloTable,
    buffer: &mut [u8],
) {
    let mut place = ScoutWindowPlace::<CoopRuntime<C>>::empty();
    // SAFETY: `table` outlives the place, which this frame drops before it returns, nothing else
    // reaches it while the window is pumped, and the window is pumped where the place holds it.
    let window = unsafe { place.build_over(params, table) };
    pump(clock, members, window, buffer);
}

/// Pump `window` over `members` until it resolves, reading each datagram into `buffer`: a
/// datagram longer than it is read cut short, and is no Hello the window takes.
fn pump<S: MulticastSocket, C: ClockSource + Clone + 'static>(
    clock: &C,
    mut members: ScoutMembers<S>,
    window: &mut ScoutWindow<CoopRuntime<C>>,
    buffer: &mut [u8],
) {
    if members.is_empty() {
        return;
    }
    let sent = window.open().is_some_and(|scout| members.send(&scout));
    // The budget is the least time the window stays open, so the start is read rounded UP to the
    // millisecond and each tick rounded down: a start read rounded down closed the window up to a
    // millisecond inside its budget (measured, 299.917 ms of a 300 ms one).
    let now_ms = |clock: &C| clock.now_us() / 1000;
    window.sent(clock.now_us().div_ceil(1000), sent);
    while !window.resolved() {
        let any = members.drain(buffer, |datagram| window.datagram(datagram));
        window.tick(now_ms(clock));
        if window.resolved() || members.is_empty() {
            break;
        }
        if !any {
            members.wait(IDLE_WAIT_MS);
        }
    }
}

/// Scout `group:port` for `budget_ms` over the host's sockets `S`, recording the peers that
/// answered in `table`, and lend each to `on_hello` as the table holds it, in the order upstream
/// delivers them (after the window, last responder first), as both C ABIs' `z_scout` does. The
/// number delivered. `table` and `buffer`, which each datagram is read into, are the caller's,
/// where it keeps the scout's state: zenoh-pico reads a scout into a buffer of its multicast
/// batch.
///
/// A socket that cannot be bound is a smaller window, and no window at all is a window nobody
/// answers: `0`, not an error, as both C ABIs report success and simply find nothing.
///
/// `zid` is the asker the Scout names, `None` for none; a configured zid that is not one is the
/// ABI's to refuse before it scouts.
#[allow(clippy::too_many_arguments)]
pub fn run_scout<S: MulticastSocket, C: ClockSource + Clone + 'static>(
    clock: &C,
    group: IpAddr,
    port: u16,
    what: u8,
    zid: Option<SessionZid>,
    budget_ms: u64,
    table: &mut HelloTable,
    buffer: &mut [u8],
    on_hello: impl FnMut(&HelloRow),
) -> usize {
    window_hellos::<S, C>(
        clock, group, port, what, zid, budget_ms, false, table, buffer,
    );
    deliver_rows_in_upstream_order(table, on_hello)
}

/// Scout for `budget_ms` and answer the FIRST node that replies, or `None` when none does in the
/// window: zenoh-pico's open-time lookup, which `_z_open` runs when its config names no locator
/// (`vendor/zenoh-pico/src/net/session.c` @
/// `_z_hello_slist_t *hellos = _z_scout_inner(what, *zid, &mcast_locator, timeout, true);`). The
/// `true` is `exit_on_first`: the window ends at the first Hello. `table` is where the window
/// records it and `buffer` what it reads into, as [`run_scout`]'s.
#[allow(clippy::too_many_arguments)]
pub fn scout_first<S: MulticastSocket, C: ClockSource + Clone + 'static>(
    clock: &C,
    group: IpAddr,
    port: u16,
    what: u8,
    zid: Option<SessionZid>,
    budget_ms: u64,
    table: &mut HelloTable,
    buffer: &mut [u8],
) -> Option<ScoutedHello> {
    window_hellos::<S, C>(
        clock, group, port, what, zid, budget_ms, true, table, buffer,
    );
    table.first().map(HelloRow::to_hello)
}

#[allow(clippy::too_many_arguments)]
fn window_hellos<S: MulticastSocket, C: ClockSource + Clone + 'static>(
    clock: &C,
    group: IpAddr,
    port: u16,
    what: u8,
    zid: Option<SessionZid>,
    budget_ms: u64,
    exit_on_first: bool,
    table: &mut HelloTable,
    buffer: &mut [u8],
) {
    let members = ScoutMembers::<S>::open(group, port, &interface_addresses());
    let params = ScoutParams {
        what,
        zid,
        // The caller's whole budget IS the window: upstream hands its `timeout` straight to
        // `__z_scout_loop`'s `while elapsed < period`.
        timeout_ms: budget_ms,
        exit_on_first,
    };
    run_window_over(clock, members, params, table, buffer);
}

// The tests run responders on threads of `std`.
#[cfg(all(test, feature = "std", unix))]
mod tests;
