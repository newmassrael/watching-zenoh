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

use alloc::sync::Arc;
use core::ffi::c_int;
use core::net::IpAddr;

use wz_runtime_coop::{ClockSource, CoopRuntime};
use wz_runtime_posix::group::MulticastSocket;
use wz_runtime_posix::scouting::ScoutMembers;
use wz_session_core::scouting_host::{deliver_in_upstream_order, ScoutWindow, ScoutingActions};
use wz_session_core::session_zid::SessionZid;

use crate::prelude::*;

pub use wz_session_core::scouting_host::{
    parse_multicast_locator, ScoutParams, ScoutedHello, MULTICAST_LOCATOR_DEFAULT,
    SCOUTING_TIMEOUT_DEFAULT_MS, SCOUTING_WHAT_DEFAULT,
};

/// The most a single datagram can carry over UDP, which sizes the read buffer.
const MAX_DATAGRAM: usize = 65507;

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
fn run_window<S: MulticastSocket, C: ClockSource + Clone + 'static>(
    clock: &C,
    mut members: ScoutMembers<S>,
    params: ScoutParams,
) -> Arc<ScoutingActions<CoopRuntime<C>>> {
    let mut window = ScoutWindow::<CoopRuntime<C>>::new(params);
    let actions = window.actions().clone();
    if members.is_empty() {
        return actions;
    }
    let sent = window.open().is_some_and(|scout| members.send(&scout));
    // The budget is the least time the window stays open, so the start is read rounded UP to the
    // millisecond and each tick rounded down: a start read rounded down closed the window up to a
    // millisecond inside its budget (measured, 299.917 ms of a 300 ms one).
    let now_ms = |clock: &C| clock.now_us() / 1000;
    window.sent(clock.now_us().div_ceil(1000), sent);
    let mut buffer = vec![0u8; MAX_DATAGRAM];
    while !window.resolved() {
        let any = members.drain(&mut buffer, |datagram| window.datagram(datagram));
        window.tick(now_ms(clock));
        if window.resolved() || members.is_empty() {
            break;
        }
        if !any {
            members.wait(IDLE_WAIT_MS);
        }
    }
    actions
}

/// Scout `group:port` for `budget_ms` over the host's sockets `S` and hand each peer that answered
/// to `on_hello`, in the order upstream delivers them (after the window, last responder first), as
/// both C ABIs' `z_scout` does. The number delivered.
///
/// A socket that cannot be bound is a smaller window, and no window at all is a window nobody
/// answers: `0`, not an error, as both C ABIs report success and simply find nothing.
///
/// `zid` is the asker the Scout names, `None` for none; a configured zid that is not one is the
/// ABI's to refuse before it scouts.
pub fn run_scout<S: MulticastSocket, C: ClockSource + Clone + 'static>(
    clock: &C,
    group: IpAddr,
    port: u16,
    what: u8,
    zid: Option<SessionZid>,
    budget_ms: u64,
    on_hello: impl FnMut(&ScoutedHello),
) -> usize {
    let hellos = window_hellos::<S, C>(clock, group, port, what, zid, budget_ms, false);
    deliver_in_upstream_order(&hellos, on_hello)
}

/// Scout for `budget_ms` and answer the FIRST node that replies, or `None` when none does in the
/// window: zenoh-pico's open-time lookup, which `_z_open` runs when its config names no locator
/// (`vendor/zenoh-pico/src/net/session.c` @
/// `_z_hello_slist_t *hellos = _z_scout_inner(what, *zid, &mcast_locator, timeout, true);`). The
/// `true` is `exit_on_first`: the window ends at the first Hello.
pub fn scout_first<S: MulticastSocket, C: ClockSource + Clone + 'static>(
    clock: &C,
    group: IpAddr,
    port: u16,
    what: u8,
    zid: Option<SessionZid>,
    budget_ms: u64,
) -> Option<ScoutedHello> {
    window_hellos::<S, C>(clock, group, port, what, zid, budget_ms, true)
        .into_iter()
        .next()
}

fn window_hellos<S: MulticastSocket, C: ClockSource + Clone + 'static>(
    clock: &C,
    group: IpAddr,
    port: u16,
    what: u8,
    zid: Option<SessionZid>,
    budget_ms: u64,
    exit_on_first: bool,
) -> Vec<ScoutedHello> {
    let members = ScoutMembers::<S>::open(group, port, &interface_addresses());
    let params = ScoutParams {
        what,
        zid,
        // The caller's whole budget IS the window: upstream hands its `timeout` straight to
        // `__z_scout_loop`'s `while elapsed < period`.
        timeout_ms: budget_ms,
        exit_on_first,
    };
    run_window(clock, members, params).scouted_hellos()
}

// The tests run responders on threads of `std`.
#[cfg(all(test, feature = "std", unix))]
mod tests;
