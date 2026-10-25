use super::*;

use std::net::{Ipv4Addr, Ipv6Addr};

/// A group and port nothing else on this host is expected to use, so two cases in one test
/// binary do not collide on the membership.
const GROUP: Ipv4Addr = Ipv4Addr::new(239, 255, 91, 32);

fn plan(iface: Option<Ipv4Addr>) -> Plan {
    Plan::V4 {
        group: GROUP,
        iface,
        joins: Vec::new(),
    }
}

fn v4(a: u8, b: u8, c: u8, d: u8) -> IpAddr {
    IpAddr::V4(Ipv4Addr::new(a, b, c, d))
}

/// R3335 -- the choice, proved over a several-interface list on a host that has one: the
/// loopback address and an IPv6 address that precede it are skipped, the FIRST non-loopback IPv4
/// address wins (not the last, not the lowest), and a host with no such address stays on the
/// wildcard.
#[test]
fn an_unpinned_link_takes_the_first_non_loopback_ipv4_interface() {
    let list = vec![
        v4(127, 0, 0, 1),
        IpAddr::V6("fe80::1".parse().unwrap()),
        v4(198, 51, 100, 7),
        v4(192, 0, 2, 5),
    ];
    match plan(None).with_link_default_iface(Some(list)) {
        Plan::V4 { iface, .. } => {
            assert_eq!(iface, Some(Ipv4Addr::new(198, 51, 100, 7)))
        }
        Plan::V6 { .. } => panic!("a v4 plan stays v4"),
    }
    for none in [None, Some(Vec::new()), Some(vec![v4(127, 0, 0, 1)])] {
        match plan(None).with_link_default_iface(none) {
            Plan::V4 { iface, .. } => {
                assert_eq!(iface, None, "nothing to choose: the wildcard, as upstream")
            }
            Plan::V6 { .. } => panic!("a v4 plan stays v4"),
        }
    }
}

/// An `#iface=` the plan already resolved is never overridden, and an IPv6 plan is not touched
/// (upstream joins a v6 group on index 0 whatever the address is).
#[test]
fn a_pinned_or_ipv6_plan_keeps_what_it_resolved() {
    let pinned = Ipv4Addr::new(203, 0, 113, 9);
    match plan(Some(pinned)).with_link_default_iface(Some(vec![v4(192, 0, 2, 5)])) {
        Plan::V4 { iface, .. } => assert_eq!(iface, Some(pinned)),
        Plan::V6 { .. } => panic!("a v4 plan stays v4"),
    }
    let six = Plan::V6 {
        group: "ff02::1".parse::<Ipv6Addr>().unwrap(),
        iface: None,
        joins: Vec::new(),
    };
    match six.with_link_default_iface(Some(vec![v4(192, 0, 2, 5)])) {
        Plan::V6 { iface, .. } => assert_eq!(iface, None),
        Plan::V4 { .. } => panic!("a v6 plan stays v6"),
    }
}

/// A multicast datagram's reach is its TTL, and the OS default is 1 — one subnet. zenoh exposes
/// the knob as the locator config key `ttl`, set on the sending socket
/// (`io/zenoh-links/zenoh-link-udp/src/multicast.rs` @ `ucast_sock.set_multicast_ttl_v4(ttl)`);
/// without it no deployment could reach past its own subnet by any route. Read back from the
/// kernel, in both arms.
#[test]
fn a_joined_socket_leaves_the_local_subnet_only_when_asked() {
    let default = bind_joined(
        IpAddr::V4(GROUP),
        0,
        &SocketConfig::default(),
        RxBind::Wildcard,
    )
    .expect("bind the group");
    assert_eq!(
        default.socket.multicast_ttl_v4().expect("read ttl"),
        1,
        "the default is the single-subnet one, which is why the knob has to exist"
    );
    assert_eq!(
        default.peer.ip(),
        IpAddr::V4(GROUP),
        "datagrams go to the group"
    );

    let asked = bind_joined(
        IpAddr::V4(GROUP),
        0,
        &SocketConfig {
            ttl: Some(8),
            ..Default::default()
        },
        RxBind::Wildcard,
    )
    .expect("bind the group with a ttl");
    assert_eq!(
        asked.socket.multicast_ttl_v4().expect("read ttl"),
        8,
        "a requested ttl must reach the socket, or the config key is decoration"
    );
}

/// The send-only half carries the hop limit too: zenoh sets the TTL on its `ucast_sock`, the
/// SENDING socket, so a hop limit that only reached the bidirectional constructor would leave the
/// one path that exists to send unbounded by it.
#[test]
fn the_send_only_half_carries_the_hop_limit_too() {
    let sender = bind_sender(
        IpAddr::V4(GROUP),
        7446,
        &SocketConfig {
            ttl: Some(5),
            ..Default::default()
        },
        false,
    )
    .expect("bind a sender");
    assert_eq!(sender.socket.multicast_ttl_v4().expect("read ttl"), 5);
}

/// A scouting socket reads on the group address itself, where a socket may be bound to one (unix),
/// and a multicast link on the wildcard.
#[test]
#[cfg(unix)]
fn a_scouting_socket_binds_the_group_and_a_link_the_wildcard() {
    let scouting = bind_joined(
        IpAddr::V4(GROUP),
        0,
        &SocketConfig::default(),
        RxBind::Group,
    )
    .expect("bind the group as a scout does");
    let local = scouting
        .socket
        .local_addr()
        .expect("addr")
        .as_socket()
        .expect("an IP socket");
    assert_eq!(local.ip(), IpAddr::V4(GROUP));

    let link = bind_joined(
        IpAddr::V4(GROUP),
        0,
        &SocketConfig::default(),
        RxBind::Wildcard,
    )
    .expect("bind the group as a link does");
    let local = link
        .socket
        .local_addr()
        .expect("addr")
        .as_socket()
        .expect("an IP socket");
    assert!(
        local.ip().is_unspecified(),
        "a link binds the wildcard: {local}"
    );
}

/// On the wire: a link socket with no `#iface=` leaves by the interface the choice names, read
/// back from the kernel -- the egress half. The expectation is derived the way the product
/// derives it, from the live list, so a host whose first interface is anything at all passes only
/// when the socket really took it. A sender that is not a link is left to the kernel.
#[test]
#[cfg(target_os = "linux")]
fn an_unpinned_link_leaves_by_the_chosen_interface_and_a_scout_does_not() {
    let expected = crate::link_interfaces::unicast_addresses_of_multicast_interfaces()
        .and_then(|ips| {
            ips.into_iter().find_map(|ip| match ip {
                IpAddr::V4(a) if !a.is_loopback() => Some(a),
                _ => None,
            })
        })
        .unwrap_or(Ipv4Addr::UNSPECIFIED);

    let joined = bind_joined(
        IpAddr::V4(GROUP),
        0,
        &SocketConfig::default(),
        RxBind::Wildcard,
    )
    .expect("bind the link's receiving half");
    assert_eq!(
        joined
            .socket
            .multicast_if_v4()
            .expect("read IP_MULTICAST_IF"),
        expected
    );

    let link = bind_sender(IpAddr::V4(GROUP), 0, &SocketConfig::default(), true)
        .expect("bind the link's send half");
    assert_eq!(
        link.socket.multicast_if_v4().expect("read IP_MULTICAST_IF"),
        expected
    );

    let scout_like = bind_sender(IpAddr::V4(GROUP), 0, &SocketConfig::default(), false)
        .expect("bind a plain sender");
    assert_eq!(
        scout_like
            .socket
            .multicast_if_v4()
            .expect("read IP_MULTICAST_IF"),
        Ipv4Addr::UNSPECIFIED,
        "a sender that is not a link is left to the kernel"
    );
}

/// A scouting socket goes on past an IPv4 membership the kernel refuses, as upstream's does, and a
/// multicast link does not.
///
/// The refusal is made by asking for more memberships than one socket may hold: Linux refuses the
/// ones past `net.ipv4.igmp_max_memberships` (20 by default) with `ENOBUFS`. It is a refusal of
/// the same call a host with no default route meets with `ENODEV` when the join is made on
/// `INADDR_ANY`. Before the skip a scout and a responder on such a host failed their whole bind,
/// and the real pico and zenoh found routers where wz found none.
///
/// Linux only, because the limit is: macOS grows a socket's membership table to 4095, so the
/// premise would not be made there. The count is read from the host's own sysctl, so a tuned host
/// is crowded past its limit too.
#[test]
#[cfg(target_os = "linux")]
fn a_scouting_socket_goes_on_past_a_membership_the_kernel_refuses() {
    let limit: usize = std::fs::read_to_string("/proc/sys/net/ipv4/igmp_max_memberships")
        .expect("the host's IPv4 membership limit")
        .trim()
        .parse()
        .expect("the limit is a number");
    // The group itself and one more than the limit: past it by two.
    let first = u32::from(Ipv4Addr::new(239, 1, 0, 1));
    let extra: Vec<String> = (0..=limit)
        .map(|n| Ipv4Addr::from(first + n as u32).to_string())
        .collect();
    let crowded = SocketConfig {
        extra_joins: &extra,
        ..Default::default()
    };
    assert!(
        bind_joined(IpAddr::V4(GROUP), 0, &crowded, RxBind::Wildcard).is_err(),
        "the premise: the kernel refuses a membership past its limit, and a multicast LINK keeps \
         that refusal"
    );
    bind_joined(IpAddr::V4(GROUP), 0, &crowded, RxBind::Group)
        .expect("a scouting socket binds and joins what it can, as upstream's does");
}

/// A `#join=` of the wrong family is refused before any membership is installed.
#[test]
fn a_join_of_the_wrong_family_is_refused() {
    let joins = vec!["ff02::7".to_owned()];
    let err = bind_joined(
        IpAddr::V4(GROUP),
        0,
        &SocketConfig {
            extra_joins: &joins,
            ..Default::default()
        },
        RxBind::Wildcard,
    )
    .expect_err("an IPv6 group in an IPv4 locator is a config error");
    assert_eq!(err.kind(), io::ErrorKind::InvalidInput, "{err}");
}
