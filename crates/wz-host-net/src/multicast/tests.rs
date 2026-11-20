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

/// A plan names an interface only when the locator resolved to one, in either family. This is
/// what the `multicast-link-requires-iface` rule reads, so a key the build cannot honour (which
/// resolves to none) is an unchosen interface like a missing key.
#[test]
fn a_plan_has_a_chosen_interface_only_when_one_was_resolved() {
    assert!(!plan(None).interface_is_chosen());
    assert!(plan(Some(Ipv4Addr::new(203, 0, 113, 9))).interface_is_chosen());
    let six = |iface| Plan::V6 {
        group: "ff02::1".parse::<Ipv6Addr>().unwrap(),
        iface,
        joins: Vec::new(),
    };
    assert!(!six(None).interface_is_chosen());
    assert!(six(Some(2)).interface_is_chosen());
}

/// The rule, at both values of the policy and both ways a plan can be: it refuses only an
/// unchosen interface with the policy on, and what it refuses is invalid input.
#[test]
fn the_rule_refuses_an_unchosen_interface_only_when_the_policy_is_on() {
    let on = SocketConfig {
        link_requires_iface: true,
        ..Default::default()
    };
    let off = SocketConfig::default();
    assert!(
        !off.link_requires_iface,
        "upstream's behaviour is the default"
    );
    let err = plan(None)
        .require_chosen_interface(&on)
        .expect_err("a link with no interface is refused when the policy asks");
    assert_eq!(err.kind(), io::ErrorKind::InvalidInput, "{err}");
    plan(Some(Ipv4Addr::new(203, 0, 113, 9)))
        .require_chosen_interface(&on)
        .expect("a chosen interface is never refused");
    plan(None)
        .require_chosen_interface(&off)
        .expect("with the policy off an unpinned link is upstream's");
}

/// On the sockets: with the policy on a link's two halves are refused when the locator chose no
/// interface, scouting sockets are not links and are not refused, and with the policy off the same
/// link opens as it always did. A link that chose an interface opens in both arms, so the refusal
/// is the missing choice and not the policy refusing every link.
#[test]
fn a_link_with_no_interface_is_refused_when_the_policy_asks_and_scouting_is_not() {
    let on = SocketConfig {
        link_requires_iface: true,
        ..Default::default()
    };
    let group = IpAddr::V4(GROUP);

    let err = bind_joined(group, 0, &on, RxBind::Wildcard)
        .expect_err("the receiving half of a link with no interface is refused");
    assert_eq!(err.kind(), io::ErrorKind::InvalidInput, "{err}");
    let err = bind_sender(group, 0, &on, true)
        .expect_err("the send half of a link with no interface is refused");
    assert_eq!(err.kind(), io::ErrorKind::InvalidInput, "{err}");

    bind_joined(group, 0, &on, RxBind::Group).expect("a scouting socket is not a link");
    bind_sender(group, 0, &on, false).expect("a plain sender is not a link");

    bind_joined(group, 0, &SocketConfig::default(), RxBind::Wildcard)
        .expect("with the policy off the link opens on upstream's interface");
    bind_sender(group, 0, &SocketConfig::default(), true)
        .expect("with the policy off the send half opens on upstream's interface");
}

/// The other half of the refusal: a link whose locator chose an interface opens with the policy
/// on. The interface is an address of the host's own, read live, so the case runs wherever the
/// host has a non-loopback IPv4 address that can carry multicast.
#[test]
#[cfg(all(target_os = "linux", feature = "locator-iface"))]
fn a_link_that_chose_an_interface_opens_with_the_policy_on() {
    let Some(own) =
        crate::link_interfaces::unicast_addresses_of_multicast_interfaces().and_then(|ips| {
            ips.into_iter().find_map(|ip| match ip {
                IpAddr::V4(a) if !a.is_loopback() => Some(a),
                _ => None,
            })
        })
    else {
        eprintln!(
            "no non-loopback IPv4 interface on this host: the chosen-interface case is not run"
        );
        return;
    };
    let named = own.to_string();
    let on = SocketConfig {
        iface: Some(&named),
        link_requires_iface: true,
        ..Default::default()
    };
    let joined = bind_joined(IpAddr::V4(GROUP), 0, &on, RxBind::Wildcard)
        .expect("a link that named its interface is not refused");
    assert_eq!(
        joined
            .socket
            .multicast_if_v4()
            .expect("read IP_MULTICAST_IF"),
        own
    );
    let sender = bind_sender(IpAddr::V4(GROUP), 0, &on, true)
        .expect("the send half of a link that named its interface is not refused");
    assert_eq!(
        sender
            .socket
            .multicast_if_v4()
            .expect("read IP_MULTICAST_IF"),
        own
    );
}

/// A link's `#bind=` address chooses its egress as well as its source, as upstream's `ucast_sock`
/// sets `IP_MULTICAST_IF` to the local address it binds
/// (`io/zenoh-links/zenoh-link-udp/src/multicast.rs` @ `.set_multicast_if_v4(addr)`); the link
/// used to leave by the first interface address whatever `#bind=` named. Read back from the
/// kernel. Linux only, whose `IP_MULTICAST_IF` takes the loopback address.
#[test]
#[cfg(target_os = "linux")]
fn a_link_bound_by_bind_leaves_by_the_address_it_binds() {
    let cfg = SocketConfig {
        bind: Some("127.0.0.1:0"),
        ..Default::default()
    };
    let link = bind_sender(IpAddr::V4(GROUP), 0, &cfg, true).expect("bind the link's send half");
    assert_eq!(
        link.socket.multicast_if_v4().expect("read IP_MULTICAST_IF"),
        Ipv4Addr::LOCALHOST
    );
    let bound = link
        .socket
        .local_addr()
        .expect("the bound address")
        .as_socket()
        .expect("an inet address");
    assert_eq!(bound.ip(), IpAddr::V4(Ipv4Addr::LOCALHOST));

    // CONTROL: a sender that is not a link keeps `#iface=` or the kernel's choice, whatever it
    // binds.
    let plain = bind_sender(IpAddr::V4(GROUP), 0, &cfg, false).expect("bind a plain sender");
    assert_eq!(
        plain
            .socket
            .multicast_if_v4()
            .expect("read IP_MULTICAST_IF"),
        Ipv4Addr::UNSPECIFIED
    );
}

/// A link's IPv6 egress is the interface of the address its sending socket binds, as upstream's
/// `ucast_sock` takes it (`io/zenoh-links/zenoh-link-udp/src/multicast.rs` @
/// `match zenoh_util::net::get_index_of_interface(local_addr.ip())`), told case by case over a
/// lookup that stands in for the host's interface table.
#[test]
fn a_link_leaves_by_the_interface_its_ipv6_address_is_on() {
    use crate::link_interfaces::IfaceResolveError;
    use std::net::SocketAddrV6;

    let global: Ipv6Addr = "2001:db8::7".parse().unwrap();
    let at = |ip: Ipv6Addr, scope: u32| SocketAddrV6::new(ip, 0, 0, scope);
    let unasked = |_: IpAddr| -> Result<Vec<u32>, IfaceResolveError> {
        panic!("the address names its egress without a lookup")
    };

    // A link-local address carries its interface as its scope.
    assert_eq!(
        link_egress_index_v6(at("fe80::1".parse().unwrap(), 3), unasked).unwrap(),
        Some(3)
    );
    // The wildcard names no interface, so the egress stays as it was.
    assert_eq!(
        link_egress_index_v6(at(Ipv6Addr::UNSPECIFIED, 0), unasked).unwrap(),
        None
    );
    // The first carrier, as upstream answers with the first interface of its table.
    assert_eq!(
        link_egress_index_v6(at(global, 0), |ip| {
            assert_eq!(ip, IpAddr::V6(global));
            Ok(vec![5, 7])
        })
        .unwrap(),
        Some(5)
    );
    // An address no interface carries refuses the link, as upstream's lookup does.
    let err = link_egress_index_v6(at(global, 0), |_| Ok(Vec::new()))
        .expect_err("an address no interface carries");
    assert_eq!(err.kind(), io::ErrorKind::AddrNotAvailable);
    // A table that cannot be read keeps the egress as it was rather than refusing the link.
    assert_eq!(
        link_egress_index_v6(at(global, 0), |_| Err(IfaceResolveError::Undetermined)).unwrap(),
        None
    );
    // Any other failure of the lookup refuses it.
    assert!(link_egress_index_v6(at(global, 0), |_| Err(IfaceResolveError::NotFound)).is_err());
}

/// `#dscp=` marks a socket in the option of the group's family, with the value as written: the
/// kernel reads back what was set, on an IPv4 socket as `IP_TOS` and on an IPv6 one as
/// `IPV6_TCLASS` (the IPv6 half only where the host opens an IPv6 socket at all).
#[cfg(target_os = "linux")]
#[test]
fn a_traffic_class_is_set_in_the_option_of_the_groups_family() {
    let v4 = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP)).expect("an IPv4 socket");
    mark_traffic_class(&v4, &SocketAddr::from((GROUP, 7447)), 0x28).expect("IP_TOS is set");
    assert_eq!(v4.tos_v4().expect("IP_TOS reads back"), 0x28);
    if let Ok(v6) = Socket::new(Domain::IPV6, Type::DGRAM, Some(Protocol::UDP)) {
        let group = SocketAddr::from((Ipv6Addr::new(0xff05, 0, 0, 0, 0, 0, 0x7a, 0x7703), 7447));
        mark_traffic_class(&v6, &group, 0x28).expect("IPV6_TCLASS is set");
        assert_eq!(v6.tclass_v6().expect("IPV6_TCLASS reads back"), 0x28);
    }
}

/// A datagram socket whose send buffer has room is writable at once: the wait answers `true`
/// long before the time it was given is up.
#[test]
fn a_socket_with_room_is_writable_at_once() {
    let socket = std::net::UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).expect("a socket");
    let started = std::time::Instant::now();
    assert!(wait_writable(&socket, 5_000_000), "a socket with room");
    assert!(
        started.elapsed() < std::time::Duration::from_secs(2),
        "the wait took {:?}",
        started.elapsed()
    );
}

/// A wait for input over two sockets is waited out while neither has a datagram, and returns long
/// before its time once one of them has.
#[cfg(any(unix, windows))]
#[test]
fn a_wait_for_input_returns_once_any_socket_has_a_datagram() {
    use std::time::{Duration, Instant};
    let quiet = std::net::UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).expect("a socket");
    let reader = std::net::UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).expect("a socket");
    let handles = [
        raw_handle(&quiet).expect("a handle"),
        raw_handle(&reader).expect("a handle"),
    ];
    let started = Instant::now();
    wait_readable(&handles, 50);
    assert!(
        started.elapsed() >= Duration::from_millis(40),
        "nothing to read: the wait took {:?}",
        started.elapsed()
    );

    quiet
        .send_to(b"datagram", reader.local_addr().expect("its address"))
        .expect("sent");
    let started = Instant::now();
    wait_readable(&handles, 5_000);
    assert!(
        started.elapsed() < Duration::from_secs(2),
        "a datagram queued: the wait took {:?}",
        started.elapsed()
    );
}
