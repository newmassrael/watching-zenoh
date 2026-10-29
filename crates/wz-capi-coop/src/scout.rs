// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! Active multicast scouting on the host's own sockets, with no executor.
//!
//! A scouting window needs no session: one Scout is asked of the group, the Hellos that answer are
//! collected for a budget, and the window ends. The rules of it are the session's
//! (`wz_session_core::scouting_host`: what a Scout says, which datagrams are answers and which are
//! named and dropped, when it is over) and the sockets are `wz_host_net`'s (the plan under a
//! multicast socket, written once for every runtime). What this module adds is the blocking host
//! that pumps the one with the other: it opens the sockets, sends the Scout, reads what arrives
//! and reads the clock, on the calling thread, which is what a C program that calls `z_scout`
//! expects, and what zenoh-pico's own `__z_scout_loop` does.
//!
//! ## The sockets, as the tokio window opens them
//!
//! The group socket (joined, bound on the group port) is an extra RECEIVE member and not a
//! condition of the window: neither reference binds one to scout. Upstream's `scout` receives on
//! its per-interface sockets alone, and zenoh-pico opens a link per interface when the config
//! names none (`vendor/zenoh-pico/src/session/scout.c` @
//! `_z_udp_unicast_interface_iterator_next(&iter)`). So the Scout leaves by an ASK socket pinned
//! to each interface that can carry multicast, and the Hello comes back to the socket the Scout
//! left from, because both references' responders reply unicast to the asker. A window whose
//! group socket cannot be bound goes on with the ask sockets, and is empty only when there is
//! nothing to ask or listen with. A build or host that cannot enumerate the interfaces offers
//! nothing, and the group socket asks alone, as a floor.
//!
//! A scout is sent when AT LEAST ONE ask socket sent it (pico's rule, `scout.c` @
//! `return sent ? _Z_RES_OK : _Z_ERR_TRANSPORT_TX_FAILED;`): a node with one dead interface
//! among four must still discover.

use std::io;
use std::net::{IpAddr, SocketAddr, UdpSocket};
use std::sync::Arc;
use std::time::Duration;

use wz_host_net::multicast::{bind_joined, bind_sender, Bound, RxBind, SocketConfig};
use wz_runtime_coop::{ClockSource, CoopRuntime};
use wz_session_core::scouting_host::{deliver_in_upstream_order, ScoutWindow, ScoutingActions};

pub use wz_session_core::scouting_host::{
    parse_multicast_locator, ScoutParams, ScoutedHello, MULTICAST_LOCATOR_DEFAULT,
    SCOUTING_TIMEOUT_DEFAULT_MS, SCOUTING_WHAT_DEFAULT,
};

/// The most a single datagram can carry over UDP, which sizes the read buffer.
const MAX_DATAGRAM: usize = 65507;

/// How long a window sleeps when nothing arrived, so the loop answers a Hello within a few
/// milliseconds without spinning. Shorter than the tokio window's 50 ms timer cadence, which is
/// a timer and not that window's read latency.
const IDLE_SLEEP: Duration = Duration::from_millis(2);

/// One socket of a window: where it reads, where the Scout goes from it, and whether it asks.
struct Member {
    socket: UdpSocket,
    /// Where the Scout is written from this member: the group, or in a test the responder.
    peer: SocketAddr,
    asks: bool,
}

/// The sockets a window holds. A member that errors on a read is dropped, as a link that is lost
/// is, and the window goes on with the rest: one interface going down must not end a window the
/// others can still answer on.
struct Members {
    members: Vec<Member>,
    /// Where the next read starts, so one continuously ready socket cannot starve the others (a
    /// group socket is one anybody can send to).
    cursor: usize,
}

impl Members {
    /// Open the group socket and one ask socket for each address in `locals`, the way the tokio
    /// window does ([`Self::from_parts`] says what is kept when they fail).
    fn open(group: IpAddr, port: u16, locals: &[IpAddr]) -> Self {
        // `Group`, not the family wildcard: a scouting socket reads on the group address itself
        // where a socket may be bound to one, as upstream's does (R3126).
        let group_member = bind_joined(group, port, &SocketConfig::default(), RxBind::Group)
            .ok()
            .and_then(|bound| member(bound, false));
        let mut asking = Vec::new();
        for local in locals {
            // `#iface=` takes an address literal as well as a name, so an enumerated address
            // needs no lookup to become a pin.
            let pinned = local.to_string();
            let cfg = SocketConfig {
                iface: Some(&pinned),
                ..SocketConfig::default()
            };
            // A refusal is the address's alone: it is left out and the others stand.
            if let Some(ask) = bind_sender(group, port, &cfg, false)
                .ok()
                .and_then(|bound| member(bound, true))
            {
                asking.push(ask);
            }
        }
        Self::from_parts(group_member, asking)
    }

    /// Compose the group member with the ask members. With no ask member the group socket asks,
    /// which is the floor a host whose enumeration fails still scouts on; with neither, there is
    /// no window.
    fn from_parts(group: Option<Member>, ask: Vec<Member>) -> Self {
        let fell_back_to_group = ask.is_empty();
        let mut members = Vec::with_capacity(ask.len() + 1);
        if let Some(mut group) = group {
            group.asks = fell_back_to_group;
            members.push(group);
        }
        members.extend(ask);
        log::debug!(
            "scout: asking on {} socket(s); fell back to the group socket: {fell_back_to_group}",
            members.iter().filter(|m| m.asks).count()
        );
        Self { members, cursor: 0 }
    }

    fn is_empty(&self) -> bool {
        self.members.is_empty()
    }

    /// Write `scout` from every ask member: whether at least one sent.
    fn send(&self, scout: &[u8]) -> bool {
        let mut sent = false;
        for member in self.members.iter().filter(|m| m.asks) {
            match member.socket.send_to(scout, member.peer) {
                Ok(_) => sent = true,
                Err(error) => {
                    log::debug!("scout: a Scout did not leave by {}: {error}", member.peer)
                }
            }
        }
        sent
    }

    /// Read every datagram that is waiting, handing each to `on_datagram`, and say whether any
    /// was. A read that fails for any reason but "nothing waits" drops its member.
    fn drain(&mut self, buffer: &mut [u8], mut on_datagram: impl FnMut(&[u8])) -> bool {
        let mut any = false;
        let mut gone = Vec::new();
        let count = self.members.len();
        for step in 0..count {
            let at = (self.cursor + step) % count;
            loop {
                match self.members[at].socket.recv_from(buffer) {
                    Ok((n, _from)) => {
                        any = true;
                        on_datagram(&buffer[..n]);
                    }
                    Err(error) if error.kind() == io::ErrorKind::WouldBlock => break,
                    Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
                    Err(error) => {
                        log::debug!("scout: a member was lost: {error}");
                        gone.push(at);
                        break;
                    }
                }
            }
        }
        if count > 0 {
            self.cursor = (self.cursor + 1) % count;
        }
        gone.sort_unstable();
        for at in gone.into_iter().rev() {
            self.members.remove(at);
        }
        any
    }
}

/// Make `bound` a window member. The builder hands it over non-blocking, which the poll loop
/// needs; it is set again here so a member built from another source cannot block the window.
fn member(bound: Bound, asks: bool) -> Option<Member> {
    bound.socket.set_nonblocking(true).ok()?;
    Some(Member {
        socket: bound.socket.into(),
        peer: bound.peer,
        asks,
    })
}

/// The interface addresses a window asks by: the first IPv4 address of every interface that is up
/// and can carry multicast (the host's own reading; `None` when it cannot be read, which is a
/// window on the group socket alone).
fn interface_addresses() -> Vec<IpAddr> {
    wz_host_net::link_interfaces::multicast_interface_addresses().unwrap_or_default()
}

/// One scouting window over `members`: send the Scout, read until the machine resolves, and answer
/// what was collected.
///
/// `clock` is the host's: the window's budget is measured against it. A window with no member, or
/// whose Scout could not leave by any, ends at once (the machine returns to `Idle` on a failed
/// send), as a window nobody answers does.
fn run_window<C: ClockSource + Clone + 'static>(
    clock: &C,
    mut members: Members,
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
            std::thread::sleep(IDLE_SLEEP);
        }
    }
    actions
}

/// Scout `group:port` for `budget_ms` and hand each peer that answered to `on_hello`, in the order
/// upstream delivers them (after the window, last responder first), as both C ABIs' `z_scout`
/// does. The number delivered.
///
/// A socket that cannot be bound is a smaller window, and no window at all is a window nobody
/// answers: `0`, not an error, as both C ABIs report success and simply find nothing.
pub fn run_scout<C: ClockSource + Clone + 'static>(
    clock: &C,
    group: IpAddr,
    port: u16,
    what: u8,
    zid: Vec<u8>,
    budget_ms: u64,
    on_hello: impl FnMut(&ScoutedHello),
) -> usize {
    let hellos = window_hellos(clock, group, port, what, zid, budget_ms, false);
    deliver_in_upstream_order(&hellos, on_hello)
}

/// Scout for `budget_ms` and answer the FIRST node that replies, or `None` when none does in the
/// window: zenoh-pico's open-time lookup, which `_z_open` runs when its config names no locator
/// (`vendor/zenoh-pico/src/net/session.c` @
/// `_z_hello_slist_t *hellos = _z_scout_inner(what, *zid, &mcast_locator, timeout, true);`). The
/// `true` is `exit_on_first`: the window ends at the first Hello.
pub fn scout_first<C: ClockSource + Clone + 'static>(
    clock: &C,
    group: IpAddr,
    port: u16,
    what: u8,
    zid: Vec<u8>,
    budget_ms: u64,
) -> Option<ScoutedHello> {
    window_hellos(clock, group, port, what, zid, budget_ms, true)
        .into_iter()
        .next()
}

fn window_hellos<C: ClockSource + Clone + 'static>(
    clock: &C,
    group: IpAddr,
    port: u16,
    what: u8,
    zid: Vec<u8>,
    budget_ms: u64,
    exit_on_first: bool,
) -> Vec<ScoutedHello> {
    let members = Members::open(group, port, &interface_addresses());
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

#[cfg(test)]
mod tests;
