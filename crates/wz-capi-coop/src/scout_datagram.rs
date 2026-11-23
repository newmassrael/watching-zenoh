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
//! The socket is of the group's family, as zenoh-pico's is of the family its scouting locator
//! resolved to: it is bound to the unspecified address of that family, on a port the stack picks,
//! so an IPv6 group (`udp/[ff02::1]:7446`) is asked from an IPv6 socket. A stack without the
//! family has no socket to give, and its window is one nobody answers.

use core::ffi::c_int;
use core::net::SocketAddr;

use wz_runtime_coop::udp_link::{unspecified_like, DatagramSocket};
use wz_runtime_coop::{ClockSource, CoopRuntime};
use wz_session_core::scouting_host::{
    deliver_rows_in_upstream_order, HelloRow, HelloTable, ScoutParams, ScoutWindowPlace,
    ScoutedHello,
};
use wz_session_core::session_zid::SessionZid;

/// How long one wait for a Hello lasts before the window reads its clock again: a few
/// milliseconds, so the window answers a Hello at once and ends close to its budget without
/// spinning, as the host's window sleeps between reads.
const READ_WAIT_MS: c_int = 2;

/// Scout `group` for `budget_ms` over a socket of `U`, reading each datagram into `buffer`
/// (zenoh-pico reads a scout into one of its multicast batch size), record each peer that answered
/// in `table`, both the caller's, where it keeps the scout's state, and lend each to `on_hello` as
/// the table holds it, in the order upstream delivers them (after the window, last responder
/// first). The number delivered; a socket that cannot be opened is a window nobody answers, `0`.
///
/// `zid` is the asker the Scout names, `None` for none; a configured zid that is not one is the
/// ABI's to refuse before it scouts.
#[allow(clippy::too_many_arguments)]
pub fn run_scout<U, C>(
    clock: &C,
    group: SocketAddr,
    what: u8,
    zid: Option<SessionZid>,
    budget_ms: u64,
    table: &mut HelloTable,
    buffer: &mut [u8],
    on_hello: impl FnMut(&HelloRow),
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
    window::<U, C>(clock, group, params, table, buffer);
    deliver_rows_in_upstream_order(table, on_hello)
}

/// Scout `group` for `budget_ms` and answer the FIRST node that replies, or `None` when none does
/// in the window: zenoh-pico's open-time lookup, which `_z_open` runs when its config names no
/// locator. `table` is where the window records it and `buffer` what it reads into, as
/// [`run_scout`]'s.
pub fn scout_first<U, C>(
    clock: &C,
    group: SocketAddr,
    what: u8,
    zid: Option<SessionZid>,
    budget_ms: u64,
    table: &mut HelloTable,
    buffer: &mut [u8],
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
    window::<U, C>(clock, group, params, table, buffer);
    table.first().map(HelloRow::to_hello)
}

/// What the window's socket is bound to: the unspecified address of the group's family, on a port
/// the stack picks, so the stack chooses the interface and the source as it does for the first
/// send of zenoh-pico's unbound socket.
fn scout_bind(group: SocketAddr) -> SocketAddr {
    SocketAddr::new(unspecified_like(group.ip()), 0)
}

/// One window: the Scout sent once, every datagram that arrives read into `buffer` until the
/// machine resolves, and the Hellos recorded in `table`. A read that fails ends the window with
/// what it has, as a lost member does in the host's window. Its own state lies in this frame's
/// place: the window makes no allocation.
fn window<U, C>(
    clock: &C,
    group: SocketAddr,
    params: ScoutParams,
    table: &mut HelloTable,
    buffer: &mut [u8],
) where
    U: DatagramSocket,
    C: ClockSource + Clone + 'static,
{
    // Built in this frame's place and pumped from it: the machine is made in a frame that has
    // returned before the first datagram is read.
    let mut place = ScoutWindowPlace::<CoopRuntime<C>>::empty();
    // SAFETY: `table` outlives the place, which this frame drops before it returns, nothing else
    // reaches it while the window is pumped, and the window is pumped where the place holds it.
    let window = unsafe { place.build_over(params, table) };
    let Ok(socket) = U::bind(scout_bind(group)) else {
        return;
    };
    let sent = window
        .open()
        .is_some_and(|scout| socket.send_to(group, &scout).is_ok());
    // The start is read rounded UP to the millisecond, as the host's window reads it, so the
    // window stays open for at least its budget.
    window.sent(clock.now_us().div_ceil(1000), sent);
    while !window.resolved() {
        socket.wait_readable(READ_WAIT_MS);
        let mut lost = false;
        while !window.resolved() {
            match socket.try_recv(buffer) {
                Ok(Some((len, _from))) => window.datagram(&buffer[..len]),
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
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::net::{Ipv4Addr, Ipv6Addr};

    /// A window built in its place is the window built by value: it opens to the same Scout, stays
    /// open until its budget passes and then ends alike, and its actions go when the place goes.
    /// Turned red by a place that writes another window, or drops its window otherwise than once.
    #[test]
    fn a_window_built_in_its_place_is_the_window_built_by_value() {
        use alloc::sync::Arc;
        use wz_runtime_posix::PosixClock;
        use wz_session_core::scouting_host::{ScoutOutcome, ScoutWindow};

        let params = ScoutParams {
            what: 0x03,
            zid: None,
            timeout_ms: 100,
            exit_on_first: false,
        };
        let mut by_value = ScoutWindow::<CoopRuntime<PosixClock>>::new(params.clone());
        let mut place = ScoutWindowPlace::<CoopRuntime<PosixClock>>::empty();
        let in_place = place.build(params);
        let scout = in_place.open();
        assert!(scout.is_some(), "a window opens with a Scout");
        assert_eq!(scout, by_value.open(), "the same Scout either way");
        in_place.sent(0, true);
        by_value.sent(0, true);
        in_place.tick(99);
        by_value.tick(99);
        assert!(
            !in_place.resolved() && !by_value.resolved(),
            "CONTROL: open inside its budget"
        );
        in_place.tick(100);
        by_value.tick(100);
        assert!(in_place.resolved() && by_value.resolved());
        assert_eq!(in_place.outcome(), ScoutOutcome::TimedOut);
        assert_eq!(by_value.outcome(), ScoutOutcome::TimedOut);
        let actions = Arc::clone(
            in_place
                .shared_actions()
                .expect("a window built over its params shares its state"),
        );
        let held = Arc::strong_count(&actions);
        drop(place);
        assert!(
            Arc::strong_count(&actions) < held,
            "the window, and the actions its machine held, went with its place"
        );
    }

    /// The window's socket is of the group's family, unbound to any one address of it, and on a
    /// port the stack picks.
    #[test]
    fn the_window_binds_the_unspecified_address_of_the_groups_family() {
        assert_eq!(
            scout_bind(SocketAddr::from(([224, 0, 0, 224], 7446))),
            SocketAddr::from((Ipv4Addr::UNSPECIFIED, 0))
        );
        assert_eq!(
            scout_bind(SocketAddr::from((
                Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, 1),
                7446
            ))),
            SocketAddr::from((Ipv6Addr::UNSPECIFIED, 0))
        );
    }
}
