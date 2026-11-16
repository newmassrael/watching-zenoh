// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The links a node that aggregates links (`max_links` above one) opens to a peer a discovery
//! plane found.
//!
//! Upstream dials a discovered peer at each locator it advertised, in order, and passes over a
//! locator when the session to the peer already has a link with the same priority range and the
//! same reliability
//! (`zenoh/src/net/runtime/orchestrator.rs` @ `already connected to this peer for this PriorityRange-Reliability pair`).
//! A peer that advertises one locator, or several of one kind and band, is given one link; a peer
//! that advertises a locator per band, or a reliable one beside a best-effort one, is given a link
//! for each. It does so only for a peer it holds no session to: a peer found again while it is
//! held is not dialed
//! (`zenoh/src/net/runtime/orchestrator.rs` @ `Already connected scouted peer`).
//!
//! The plan is made once, from the locators the node knows for the peer when it is found, and its
//! links are dialed together rather than one after another: the plan never holds two locators of
//! one pair, so no link of it waits on another to know whether it is needed. It stops at
//! `max_links`, as the session refuses a link past it on this side
//! ([`join_link`](crate::multilink::join_link)) and the peer on its own, which counts the links it
//! accepts
//! (`io/zenoh-transport/src/unicast/universal/transport.rs` @ `max num of links reached`).

use wz_session_core::link::LinkKind;
use wz_session_core::locator::{AnyLocator, Proto};
use wz_session_core::qos::Priority;

use crate::session_open::{mesh_dial_plan, plan_endpoint, MeshDialTarget};

/// What upstream tells two links to one peer apart by: the priority range the endpoint declares
/// and whether its link kind delivers reliably.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct LinkPair {
    /// The bounds of the endpoint's `prio=` as wire bytes, `None` when it declares none or one
    /// that does not read as a range: upstream keeps the parse's `ok()`, so an unreadable value
    /// is the same pair as no value.
    priorities: Option<(u8, u8)>,
    /// Whether the endpoint's link kind delivers reliably.
    reliable: bool,
}

/// The links to dial to a peer a discovery plane found: `first`, the dial the loop decided on,
/// then each of `candidates` whose pair no link before it has, in their order, `max_links` at
/// most. Every link is made for the node `first` is made for. A candidate the loop cannot dial
/// without a resolver, or that does not parse, is passed over as the loop's own choice of `first`
/// passes it over.
pub(super) fn discovered_peer_links(
    first: MeshDialTarget,
    candidates: &[String],
    max_links: usize,
) -> Vec<MeshDialTarget> {
    let expected_zid = first.expected_zid;
    let mut pairs = vec![link_pair(&first.locator)];
    let mut links = vec![first];
    for candidate in candidates {
        if links.len() >= max_links {
            break;
        }
        let Some(target) = plan_endpoint(candidate)
            .ok()
            .and_then(|locator| mesh_dial_plan(locator).ok())
        else {
            continue;
        };
        let pair = link_pair(&target.locator);
        if pairs.contains(&pair) {
            continue;
        }
        pairs.push(pair);
        links.push(MeshDialTarget {
            expected_zid,
            ..target
        });
    }
    links
}

/// The pair of the link `locator` would open.
fn link_pair(locator: &AnyLocator) -> LinkPair {
    LinkPair {
        priorities: locator
            .qos_metadata()
            .and_then(|metadata| metadata.priorities.as_deref())
            .and_then(priority_range),
        reliable: link_kind(locator).is_reliable(),
    }
}

/// A `prio=` value read as upstream reads it
/// (`commons/zenoh-protocol/src/core/mod.rs` @ `impl FromStr for PriorityRange {`): one
/// priority, or two joined by `-`, each a priority's wire byte. Bounds are kept in the order
/// written, as upstream's range is built from them.
fn priority_range(written: &str) -> Option<(u8, u8)> {
    let mut bounds = written.split('-');
    let start = priority_byte(bounds.next()?)?;
    let end = match bounds.next() {
        Some(end) => priority_byte(end)?,
        None => start,
    };
    if bounds.next().is_some() {
        return None;
    }
    Some((start, end))
}

/// One bound of a `prio=` value: a wire byte that names a priority.
fn priority_byte(written: &str) -> Option<u8> {
    written
        .parse::<u8>()
        .ok()
        .filter(|byte| usize::from(*byte) < Priority::NUM)
}

/// The kind of link `locator` opens. Wildcard-free, so a shape or a scheme added to the locator
/// has to say which kind it is, and so whether it is reliable.
fn link_kind(locator: &AnyLocator) -> LinkKind {
    match locator {
        AnyLocator::Ip(parsed) => proto_kind(parsed.proto),
        AnyLocator::Named { proto, .. } => proto_kind(*proto),
        AnyLocator::Serial(_) => LinkKind::Serial,
        AnyLocator::Unixsock(_) => LinkKind::UnixsockStream,
        AnyLocator::Unixpipe(_) => LinkKind::Unixpipe,
        AnyLocator::Vsock(_) => LinkKind::Vsock,
    }
}

/// The kind of link an IP-family scheme opens, once the parse has read `rel=` into the scheme
/// where it picks the kind (`udp` and `quic`).
fn proto_kind(proto: Proto) -> LinkKind {
    match proto {
        Proto::Tcp => LinkKind::Tcp,
        Proto::Udp => LinkKind::Udp,
        Proto::Tls => LinkKind::Tls,
        Proto::Ws => LinkKind::Ws,
        Proto::Quic => LinkKind::Quic,
        Proto::QuicDatagram => LinkKind::QuicDatagram,
        Proto::UdpReliable => LinkKind::UdpReliable,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The dial the loop decides on for `locator`, made for the node `zid` names.
    fn first(locator: &str, zid: [u8; 16]) -> MeshDialTarget {
        mesh_dial_plan(plan_endpoint(locator).expect("parses"))
            .expect("dialable")
            .for_node(zid)
    }

    fn locators(links: &[MeshDialTarget]) -> Vec<String> {
        links.iter().map(|link| link.key.to_string()).collect()
    }

    fn strings(locators: &[&str]) -> Vec<String> {
        locators.iter().map(|locator| locator.to_string()).collect()
    }

    const ZID: [u8; 16] = [0xAA; 16];

    #[test]
    fn a_peer_with_one_locator_is_given_one_link() {
        let candidates = strings(&["tcp/127.0.0.1:7447"]);
        let links = discovered_peer_links(first("tcp/127.0.0.1:7447", ZID), &candidates, 4);
        assert_eq!(locators(&links), ["127.0.0.1:7447"]);
    }

    #[test]
    fn locators_of_one_pair_give_one_link_whatever_their_address() {
        let candidates = strings(&[
            "tcp/127.0.0.1:7447",
            "tcp/127.0.0.2:7447",
            "tls/127.0.0.3:7447",
            "ws/127.0.0.4:7447",
        ]);
        let links = discovered_peer_links(first("tcp/127.0.0.1:7447", ZID), &candidates, 4);
        assert_eq!(
            locators(&links),
            ["127.0.0.1:7447"],
            "tcp, tls and ws are all reliable and none declares a band"
        );
    }

    #[test]
    fn each_band_a_peer_declares_is_given_a_link_made_for_the_peer() {
        let candidates = strings(&[
            "tcp/127.0.0.1:7447?prio=0-3",
            "tcp/127.0.0.1:7448?prio=4-7",
            "tcp/127.0.0.1:7449?prio=0-3",
        ]);
        let links =
            discovered_peer_links(first("tcp/127.0.0.1:7447?prio=0-3", ZID), &candidates, 4);
        assert_eq!(locators(&links), ["127.0.0.1:7447", "127.0.0.1:7448"]);
        assert!(
            links.iter().all(|link| link.expected_zid == Some(ZID)),
            "every link is made for the node the first one is"
        );
    }

    #[test]
    fn a_best_effort_locator_beside_a_reliable_one_is_given_a_link() {
        let candidates = strings(&[
            "tcp/127.0.0.1:7447",
            "udp/127.0.0.1:7447",
            "udp/127.0.0.1:7450?rel=1",
        ]);
        let links = discovered_peer_links(first("tcp/127.0.0.1:7447", ZID), &candidates, 4);
        assert_eq!(
            locators(&links),
            ["127.0.0.1:7447", "127.0.0.1:7447"],
            "the datagram udp link is a second pair; the reliable udp link is tcp's pair"
        );
        assert!(matches!(
            &links[1].locator,
            AnyLocator::Ip(parsed) if parsed.proto == Proto::Udp
        ));
    }

    #[test]
    fn the_plan_stops_at_max_links() {
        let candidates = strings(&[
            "tcp/127.0.0.1:7447?prio=0",
            "tcp/127.0.0.1:7448?prio=1",
            "tcp/127.0.0.1:7449?prio=2",
        ]);
        let two = discovered_peer_links(first("tcp/127.0.0.1:7447?prio=0", ZID), &candidates, 2);
        assert_eq!(locators(&two), ["127.0.0.1:7447", "127.0.0.1:7448"]);
        let one = discovered_peer_links(first("tcp/127.0.0.1:7447?prio=0", ZID), &candidates, 1);
        assert_eq!(locators(&one), ["127.0.0.1:7447"]);
    }

    #[test]
    fn a_candidate_the_loop_cannot_dial_is_passed_over() {
        let candidates = strings(&[
            "tcp/example.org:7447?prio=4-7",
            "nonsense",
            "tcp/127.0.0.1:7448?prio=4-7",
        ]);
        let links = discovered_peer_links(first("tcp/127.0.0.1:7447", ZID), &candidates, 4);
        assert_eq!(locators(&links), ["127.0.0.1:7447", "127.0.0.1:7448"]);
    }

    #[test]
    fn a_band_is_read_as_upstream_reads_it() {
        assert_eq!(priority_range("3"), Some((3, 3)));
        assert_eq!(priority_range("1-4"), Some((1, 4)));
        assert_eq!(priority_range("5-2"), Some((5, 2)), "kept as written");
        assert_eq!(priority_range("8"), None, "not a priority");
        assert_eq!(priority_range("1-4-6"), None);
        assert_eq!(priority_range("1-"), None);
        assert_eq!(priority_range(""), None);
        // A single priority and the range of that one priority are one pair.
        let candidates = strings(&["tcp/127.0.0.1:7448?prio=3-3"]);
        let links = discovered_peer_links(first("tcp/127.0.0.1:7447?prio=3", ZID), &candidates, 4);
        assert_eq!(locators(&links), ["127.0.0.1:7447"]);
        // An unreadable band is no band.
        let candidates = strings(&["tcp/127.0.0.1:7448?prio=9"]);
        let links = discovered_peer_links(first("tcp/127.0.0.1:7447", ZID), &candidates, 4);
        assert_eq!(locators(&links), ["127.0.0.1:7447"]);
    }

    #[test]
    fn every_shape_is_given_its_link_kinds_reliability() {
        let reliable = |locator: &str| link_pair(&plan_endpoint(locator).expect("parses")).reliable;
        assert!(
            reliable("tcp/127.0.0.1:7447?rel=0"),
            "tcp is reliable whatever rel says"
        );
        assert!(reliable("quic/127.0.0.1:7447"));
        assert!(!reliable("quic/127.0.0.1:7447?rel=0"));
        assert!(!reliable("udp/127.0.0.1:7447"));
        assert!(reliable("udp/127.0.0.1:7447?rel=1"));
        assert!(reliable("unixsock-stream//tmp/wz-peer.sock"));
        assert!(!reliable("serial//dev/ttyUSB0#baudrate=115200"));
    }
}
