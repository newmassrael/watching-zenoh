// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! R2611 — the ASK side of active scouting, over EVERY multicast-capable
//! interface rather than whichever one the kernel's default route picks.
//!
//! # The gap this closes
//!
//! Both references ask on every interface, and each does it with a socket per
//! interface:
//!
//! * zenoh builds one unicast socket per enumerated interface and sends the
//!   Scout on each — `zenoh/src/net/runtime/orchestrator.rs` @
//!   `let sockets: Vec<ScoutSocket> = ifaces`, whose members come from
//!   `bind_ucast_port` (family wildcard, port 0, egress pinned with
//!   `set_multicast_if_v4`). An interface that refuses is FILTERED OUT rather
//!   than fatal; all of them refusing is fatal.
//! * zenoh-pico opens a scout link per interface when the endpoint config names
//!   none — `vendor/zenoh-pico/src/session/scout.c` @
//!   `_z_udp_unicast_interface_iterator_next(&iter)` — and sends on all of them,
//!   succeeding when AT LEAST ONE sent (the same file's `bool sent`).
//!
//! wz bound ONE multicast socket, whose egress is the kernel's default route and
//! whose membership `INADDR_ANY` places on one interface. On a multi-homed host
//! a peer on any other interface never saw the Scout. wz's own two halves
//! disagreed about it: the RESPONDER has bound one reply socket per address
//! since R2219 ([`crate::scouting_responder::bind_reply_sockets`]).
//!
//! # Why the addresses are a PARAMETER and not a call to the enumerator
//!
//! The same reason the responder half takes `locals`: enumeration needs
//! `getifaddrs`, which lives behind `link-interfaces` (it owns the `libc`
//! dependency), and `scouting-active` does not pull it. Forcing it would put
//! libc in every scouting build for a capability an embedded profile cannot use
//! — the shape the kconfig footprint invariant exists to refuse.
//!
//! It also makes the population INJECTABLE, which is what lets this module be
//! graded on a host with one NIC. A test whose population is "this machine's
//! interfaces" reports green by emptiness on exactly the runner CI uses.
//!
//! # What this module does NOT change
//!
//! The group-joined socket stays in the set as a RECEIVE member. Dropping it
//! would lose a Hello sent to the GROUP rather than unicast to the asker —
//! neither reference's responder sends one ([`UdpDriver::send_datagram_to`]
//! records why upstream replies unicast), but wz sees one today, and a round
//! that widened the ask must not narrow the listen. It does not ASK, because a
//! second Scout out the default route would make one responder answer twice and
//! a survey count one peer as two.

use std::io;
use std::net::IpAddr;
use std::pin::Pin;
use std::task::Poll;

use wz_session_core::link::{LinkEvent, LostCause, TxFrame};
use wz_session_core::reliability::Reliability;

use crate::{LinkDriver, McastSocketConfig, UdpDriver};

/// Every multicast-capable interface's address, or `None` when this build
/// cannot ask.
///
/// `None` and `Some(vec![])` are DIFFERENT and the distinction is R2219's:
/// "the resolution could not run" versus "it ran and nothing qualified".
/// Reporting the first as an empty set would let [`ScoutFanOut`] describe a
/// host as single-homed on the strength of a feature flag.
///
/// # Why it takes TWO features, measured
///
/// `link-interfaces` is the one that ENUMERATES (it owns the `getifaddrs`
/// dependency). `locator-iface` is the one that PINS: without it the `#iface=`
/// honour is not compiled and its selector warns and returns "unpinned"
/// instead. MEASURED while writing this module — with `locator-iface` off, two
/// ask sockets pinned to two different addresses both bind and both egress by
/// the kernel's default route.
///
/// A fan-out built on an unpinned pin is not a wider ask, it is the SAME ask
/// sent N times: no interface gains reach, and every responder that hears it
/// answers N times, so a survey counts one peer as N. That is worse than the
/// single socket it replaces, which is why this reports `None` rather than
/// offering addresses a build cannot honour.
pub fn scout_interface_addresses() -> Option<Vec<IpAddr>> {
    #[cfg(all(feature = "link-interfaces", feature = "locator-iface"))]
    {
        crate::link_interfaces::multicast_interface_addresses()
    }
    #[cfg(not(all(feature = "link-interfaces", feature = "locator-iface")))]
    {
        None
    }
}

/// Bind one ask socket per address in `locals`, and say which addresses
/// refused.
///
/// The refusals are RETURNED for the reason
/// [`crate::scouting_responder::bind_reply_sockets`] returns its own: an
/// address can be enumerated and be ungrabbable a moment later, and a helper
/// that quietly handed back the shorter list would turn a multi-homed node into
/// a single-homed one with nothing said.
///
/// Each socket is `bind_multicast_tx` — the family wildcard on port 0 with
/// egress pinned to the address and the hop limit applied, which is what
/// zenoh's `bind_ucast_port` is. The Hello comes back to the socket the Scout
/// left from, because both references' responders reply unicast to the asker.
///
/// ⚠ WHAT THE REFUSAL LIST DOES NOT CATCH, measured rather than assumed. A
/// same-family address this host does not hold BINDS: the kernel accepts
/// `IP_MULTICAST_IF` for 203.0.113.1 here and only fails, if at all, at send
/// time. So `refused` names the addresses that could not be set up, not the
/// interfaces that cannot carry a datagram, and a reader must not take an empty
/// list as "every ask socket works". Upstream is in the same position — its own
/// per-interface filter is the `ok()` of this same setsockopt — and the send
/// rule is what absorbs it: [`ScoutFanOut`] succeeds when at least one socket
/// sent.
pub async fn bind_scout_sockets(
    group: IpAddr,
    port: u16,
    locals: &[IpAddr],
    ttl: Option<u32>,
) -> (Vec<UdpDriver>, Vec<(IpAddr, io::Error)>) {
    let mut bound = Vec::new();
    let mut refused = Vec::new();
    for local in locals {
        // `#iface=` takes an address literal as well as a name (upstream's own
        // first arm), so an enumerated address needs no lookup to become a pin.
        let pinned = local.to_string();
        let cfg = McastSocketConfig {
            iface: Some(&pinned),
            ttl,
            extra_joins: &[],
        };
        match UdpDriver::bind_multicast_tx(group, port, cfg).await {
            Ok(driver) => bound.push(driver),
            Err(error) => refused.push((*local, error)),
        }
    }
    (bound, refused)
}

/// What shape a [`ScoutFanOut`] actually took, as a value.
///
/// Returned rather than logged because a silent fallback is indistinguishable
/// from a fan-out that worked: a caller — and a test — must be able to ask how
/// many interfaces the Scout left by, not infer it.
#[derive(Debug)]
pub struct FanOutShape {
    /// How many sockets the Scout is sent on.
    pub asked_on: usize,
    /// Addresses that were offered and could not be bound.
    pub refused: Vec<(IpAddr, io::Error)>,
    /// The group socket is asking because nothing else could — the pre-R2611
    /// behaviour, kept as a floor so a host whose enumeration fails still
    /// scouts. NAMED because a fallback nobody can see is the shape this tree
    /// keeps paying for.
    pub fell_back_to_group: bool,
}

/// One member of the set: a driver, and whether the Scout goes out of it.
struct Member {
    driver: UdpDriver,
    asks: bool,
}

/// A [`LinkDriver`] over several sockets: the Scout leaves by every ask member,
/// and a datagram arriving at ANY member is the window's.
///
/// It is a `LinkDriver` and not a new seam because
/// [`crate::scouting_glue::drive_scouting_until_resolved`] is generic over the
/// driver, so the whole fan-out is an addition with no change to the loop that
/// consumes it.
pub struct ScoutFanOut {
    members: Vec<Member>,
    /// Where the next poll starts. A fixed start would let one continuously
    /// ready socket starve the others, and the group a scouting window listens
    /// on is one anybody can send to.
    cursor: usize,
}

impl ScoutFanOut {
    /// Compose the group socket with the ask sockets.
    ///
    /// `group` is the socket the window already had — joined, looping back, and
    /// bound on the group port. It receives; it asks only when there is nothing
    /// else to ask with.
    pub fn over(
        group: UdpDriver,
        ask: Vec<UdpDriver>,
        refused: Vec<(IpAddr, io::Error)>,
    ) -> (Self, FanOutShape) {
        let fell_back_to_group = ask.is_empty();
        let mut members = Vec::with_capacity(ask.len() + 1);
        members.push(Member {
            driver: group,
            asks: fell_back_to_group,
        });
        for driver in ask {
            members.push(Member { driver, asks: true });
        }
        let asked_on = members.iter().filter(|m| m.asks).count();
        // Reported HERE, at the one place that knows it, rather than by each
        // caller: a consumer without a logger (the C-ABI crate is one) would
        // otherwise drop the observation, and then "the survey found nothing"
        // and "the Scout left by one interface of four" read the same from
        // outside.
        log::debug!(
            "scout fan-out: asking on {asked_on} socket(s); fell back to the group \
             socket: {fell_back_to_group}; {} address(es) refused",
            refused.len()
        );
        (
            Self { members, cursor: 0 },
            FanOutShape {
                asked_on,
                refused,
                fell_back_to_group,
            },
        )
    }

    /// How many members the set holds, ask and receive alike.
    pub fn members(&self) -> usize {
        self.members.len()
    }
}

impl LinkDriver for ScoutFanOut {
    async fn open(&mut self) -> io::Result<()> {
        for member in &mut self.members {
            member.driver.open().await?;
        }
        Ok(())
    }

    /// Send on every ask member; succeed when AT LEAST ONE did.
    ///
    /// That is pico's rule verbatim (`vendor/zenoh-pico/src/session/scout.c` @
    /// `return sent ? _Z_RES_OK : _Z_ERR_TRANSPORT_TX_FAILED;`) and zenoh's in
    /// its own vocabulary, which logs a per-interface failure and carries on.
    /// A node with one dead NIC among four must still discover.
    async fn send(&mut self, frame: &TxFrame<'_>, reliability: Reliability) -> io::Result<()> {
        let mut sent = false;
        let mut last: Option<io::Error> = None;
        for member in &mut self.members {
            if !member.asks {
                continue;
            }
            match member.driver.send(frame, reliability).await {
                Ok(()) => sent = true,
                Err(error) => last = Some(error),
            }
        }
        if sent {
            return Ok(());
        }
        Err(last.unwrap_or_else(|| {
            io::Error::new(
                io::ErrorKind::NotConnected,
                "scout fan-out has no socket to ask with",
            )
        }))
    }

    async fn close(&mut self) -> io::Result<()> {
        for member in &mut self.members {
            member.driver.close().await?;
        }
        Ok(())
    }

    /// Poll every member, starting one past the last winner.
    ///
    /// A member reporting `Lost` is REMOVED and the poll continues: one
    /// interface going down must not end a window the other three can still
    /// answer on — the same class of defect R2610 fixed one layer up, where a
    /// single datagram ended a window. `Lost` is the set's verdict only when
    /// the set empties.
    ///
    /// The per-member futures are rebuilt on every call rather than held across
    /// them, which is sound because [`UdpDriver::poll_event`] is one `recv_from`
    /// on a fresh buffer: it carries no partial state, so dropping it — which
    /// the drive loop's `select!` does on every tick — loses nothing.
    /// `futures_util::select_all` would express this in one line and is
    /// deliberately not used: that dependency is optional in this crate and
    /// activated by exactly two other features, so reaching for it here would
    /// put it in every scouting build.
    async fn poll_event(&mut self) -> LinkEvent {
        loop {
            if self.members.is_empty() {
                return LinkEvent::Lost {
                    cause: LostCause::PeerClosed,
                };
            }
            let start = self.cursor % self.members.len();
            let (index, event) = {
                let mut pending: Vec<
                    Pin<Box<dyn core::future::Future<Output = LinkEvent> + Send>>,
                > = self
                    .members
                    .iter_mut()
                    .map(|m| {
                        Box::pin(m.driver.poll_event())
                            as Pin<Box<dyn core::future::Future<Output = LinkEvent> + Send>>
                    })
                    .collect();
                let count = pending.len();
                core::future::poll_fn(move |cx| {
                    for step in 0..count {
                        let index = (start + step) % count;
                        if let Poll::Ready(event) = pending[index].as_mut().poll(cx) {
                            return Poll::Ready((index, event));
                        }
                    }
                    Poll::Pending
                })
                .await
            };
            self.cursor = index + 1;
            match event {
                LinkEvent::Lost { .. } => {
                    self.members.remove(index);
                }
                other => return other,
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::net::Ipv4Addr;

    /// The group every scouting socket in this tree uses.
    const GROUP: IpAddr = IpAddr::V4(Ipv4Addr::new(224, 0, 0, 224));

    /// An address of the OTHER family from the group above.
    ///
    /// This is the refusal that is real and deterministic: the `#iface=`
    /// selector refuses a v6 literal for a v4 group BY FAMILY (R2584 made that
    /// a named fault rather than a "not found"), in process, with no network.
    ///
    /// ⚠ It is NOT the first thing tried. TEST-NET-3 (203.0.113.1, an address
    /// this host does not hold) was, and it BOUND — the kernel accepts
    /// `IP_MULTICAST_IF` for an address it does not have. That measurement is
    /// recorded on [`bind_scout_sockets`], because it bounds what the refusal
    /// list can mean.
    ///
    /// Gated with its ONE consumer rather than left ungated: a constant whose
    /// `cfg` is wider than the arm that reads it is an unused item under
    /// `-D warnings`, which is open-debt 730's class arriving in a test module.
    #[cfg(feature = "locator-iface")]
    const OTHER_FAMILY: IpAddr = IpAddr::V6(std::net::Ipv6Addr::LOCALHOST);

    /// A stand-in for the window's group socket: the same constructor, with no
    /// interface pinned and no membership installed.
    ///
    /// Not the real `bind_multicast`: that JOINS, and a join is what makes the
    /// scouting e2e legs environment-dependent enough to be `#[ignore]`d into
    /// Layer M. These arms assert how the SET is composed, which the join does
    /// not enter into; delivery is the Layer M leg's subject.
    async fn stand_in_group_socket() -> UdpDriver {
        UdpDriver::bind_multicast_tx(GROUP, 7446, McastSocketConfig::default())
            .await
            .expect("stand-in group socket")
    }

    /// R2611 — the ask set is one socket per address, and the shape SAYS so.
    ///
    /// The population is injected rather than enumerated: this host has four
    /// multicast-capable interfaces and a CI runner has one, so a test that
    /// asked the machine would grade a different number in each place and pass
    /// by emptiness where it matters.
    #[tokio::test]
    async fn every_offered_address_becomes_one_ask_socket() {
        let locals = vec![
            IpAddr::V4(Ipv4Addr::LOCALHOST),
            IpAddr::V4(Ipv4Addr::LOCALHOST),
        ];
        let (ask, refused) = bind_scout_sockets(GROUP, 7446, &locals, None).await;
        assert!(refused.is_empty(), "loopback must bind: {refused:?}");
        assert_eq!(ask.len(), 2, "one ask socket per offered address");

        let (fan, shape) = ScoutFanOut::over(stand_in_group_socket().await, ask, refused);
        assert_eq!(shape.asked_on, 2, "the Scout leaves by both");
        assert!(
            !shape.fell_back_to_group,
            "with ask sockets the group socket must not ask — a second Scout out \
             the default route makes one responder answer twice"
        );
        assert_eq!(
            fan.members(),
            3,
            "the group socket stays in the set as a receive member"
        );
    }

    /// R2611 — an address that cannot be a pin is REFUSED, by name, and the
    /// others still bind.
    ///
    /// Upstream filters a failing interface out rather than failing the scout
    /// (`zenoh/src/net/runtime/orchestrator.rs` @ `let sockets: Vec<ScoutSocket> = ifaces`
    /// collects through `filter_map(.. .ok())`), and this is the arm that says
    /// wz does too — while still naming what it lost, which upstream's `ok()`
    /// discards.
    ///
    /// ⚠ NEEDS `locator-iface`, and is the reason this module's lane names that
    /// feature. Without it the pin is not compiled: the selector warns and
    /// returns unpinned, so NOTHING is refused and the arm would assert a rule
    /// the build does not have. It cannot go missing silently — the lane's
    /// count guard pins the number of tests that run there, so a build that
    /// dropped the feature runs one fewer and reds.
    #[cfg(feature = "locator-iface")]
    #[tokio::test]
    async fn an_address_that_cannot_be_a_pin_is_refused_by_name() {
        let locals = vec![IpAddr::V4(Ipv4Addr::LOCALHOST), OTHER_FAMILY];
        let (ask, refused) = bind_scout_sockets(GROUP, 7446, &locals, None).await;
        assert_eq!(ask.len(), 1, "the address that can pin still binds");
        assert_eq!(refused.len(), 1, "and the one that cannot is reported");
        assert_eq!(refused[0].0, OTHER_FAMILY, "named, not counted");
    }

    /// R2611 — with nothing to ask with, the group socket asks: the pre-round
    /// behaviour as a FLOOR, and the shape says it happened.
    ///
    /// This is the arm that keeps a build without `link-interfaces`, or a host
    /// whose enumeration fails, scouting at all. A fan-out that silently sent
    /// nothing would be a worse defect than the one this round is closing.
    #[tokio::test]
    async fn with_no_ask_socket_the_group_socket_asks_and_says_so() {
        let (fan, shape) = ScoutFanOut::over(stand_in_group_socket().await, Vec::new(), Vec::new());
        assert!(shape.fell_back_to_group);
        assert_eq!(shape.asked_on, 1);
        assert_eq!(fan.members(), 1);
    }

    /// R2611 — each ask socket's egress is PINNED TO ITS OWN ADDRESS, read back
    /// from the kernel rather than from the call that set it.
    ///
    /// This is the arm that makes the fan-out a fan-out. Composition says there
    /// are N sockets; only the readback says they LEAVE BY N INTERFACES, and a
    /// `set_multicast_if_v4` that returned `Ok` is not evidence of what the
    /// kernel kept — measured in this very module, where an address this host
    /// does not hold was accepted by that call.
    ///
    /// It grades on a host with ONE interface, which is the point: delivery
    /// needs a second NIC to discriminate and the pin does not. The control is
    /// the unpinned socket beside it — same constructor, no `#iface=`, and the
    /// kernel reports the wildcard.
    #[cfg(feature = "locator-iface")]
    #[tokio::test]
    async fn each_ask_socket_leaves_by_the_interface_it_was_given() {
        let local = IpAddr::V4(Ipv4Addr::LOCALHOST);
        let (ask, refused) = bind_scout_sockets(GROUP, 7446, &[local], None).await;
        assert!(refused.is_empty(), "loopback must bind: {refused:?}");
        assert_eq!(ask.len(), 1);
        assert_eq!(
            ask[0].multicast_egress_v4().expect("read back the pin"),
            Ipv4Addr::LOCALHOST,
            "the kernel must hold the address the fan-out asked for"
        );

        // CONTROL: the same constructor with nothing pinned. Without this the
        // arm above would pass on a build where `#iface=` did nothing, because
        // the readback would still equal whatever the default happened to be.
        let unpinned = stand_in_group_socket().await;
        assert_eq!(
            unpinned
                .multicast_egress_v4()
                .expect("read back the default"),
            Ipv4Addr::UNSPECIFIED,
            "an unpinned socket must read as the kernel's default, or the arm \
             above is not measuring the pin"
        );
    }

    /// R2611 — an empty offer is not a fan-out, and the shape must not read as
    /// one.
    ///
    /// The anti-vacuity arm: `asked_on` is the number a caller would quote, so
    /// a zero-interface host must report the fallback rather than a fan-out of
    /// one that happens to be the same socket.
    #[tokio::test]
    async fn an_empty_offer_binds_nothing() {
        let (ask, refused) = bind_scout_sockets(GROUP, 7446, &[], None).await;
        assert!(ask.is_empty(), "nothing offered, nothing bound");
        assert!(refused.is_empty(), "and nothing to refuse");
    }
}
