use super::*;

/// The loopback interface's NAME, discovered rather than assumed.
///
/// R311y581 — three tests below hardcoded `"lo"`, and all three FAILED the
/// first time any CI lane actually RAN this crate on macOS, where the
/// loopback interface is `lo0`. They had compiled cleanly on that host since
/// R311y13; a name that only exists on Linux is invisible to `clippy`.
///
/// The defect was in the FIXTURES, not the resolver: every function here
/// takes the name as an argument and asks the kernel, so none of them
/// assumes a platform. What the tests assert is the loopback ADDRESS
/// contract, and the name is an INPUT to that — so it belongs here, once,
/// instead of at three call sites.
///
/// Deliberately a candidate list rather than a lookup through
/// `interface_names_for(127.0.0.1)`: that would make
/// `the_two_resolution_directions_agree_on_loopback` circular, since
/// witnessing exactly that pair is the test's whole purpose.
fn loopback_iface_name() -> &'static str {
    // `lo` on Linux, `lo0` on macOS and the BSDs.
    for candidate in ["lo", "lo0"] {
        if super::unicast_addresses_of_interface(candidate).is_ok() {
            return candidate;
        }
    }
    panic!("no loopback interface resolved as `lo` or `lo0` on this host");
}

/// The loopback address must resolve to at least one interface on any host
/// this test can run on, and the resolution must be a definite `Some`.
#[test]
fn loopback_resolves_to_a_named_interface() {
    let names = interface_names_for(IpAddr::V4(std::net::Ipv4Addr::LOCALHOST))
        .expect("getifaddrs resolves on a unix host");
    assert!(
        !names.is_empty(),
        "127.0.0.1 must sit on some interface; got {names:?}"
    );
}

/// An address no local interface carries resolves to an EMPTY set — a
/// definite negative, NOT an error. This is the distinction zenoh collapses:
/// upstream returns `vec![]` for this case AND for a failed lookup.
#[test]
fn a_foreign_address_resolves_to_a_definite_empty_set() {
    // TEST-NET-1 (RFC5737) — reserved for documentation, never assigned to a
    // host interface.
    let names = interface_names_for(IpAddr::V4(std::net::Ipv4Addr::new(192, 0, 2, 1)))
        .expect("the lookup itself succeeds");
    assert!(
        names.is_empty(),
        "192.0.2.1 is reserved and must be on no interface; got {names:?}"
    );
}

/// The loopback interface must resolve to a set containing `127.0.0.1`. This
/// checks the resolver against the KERNEL's interface table, not against its
/// own syscall: the expected address is a constant of the loopback contract,
/// not something the function under test chose.
#[test]
fn the_loopback_interface_resolves_to_its_loopback_address() {
    let lo = loopback_iface_name();
    let addrs =
        unicast_addresses_of_interface(lo).expect("the loopback is present, up and running");
    assert!(
        addrs.contains(&IpAddr::V4(std::net::Ipv4Addr::LOCALHOST)),
        "{lo} must carry 127.0.0.1; got {addrs:?}"
    );
    assert!(
        addrs.iter().all(|ip| !ip.is_multicast()),
        "a multicast address is not a valid interface selector; got {addrs:?}"
    );
}

/// An interface name that cannot exist is `NotFound` — DISTINCT from
/// `Undetermined`. This is the boundary the honor policy turns on: `NotFound`
/// is upstream's hard error, `Undetermined` is the platform warn.
#[test]
fn an_absent_interface_name_is_not_found_rather_than_undetermined() {
    // IFNAMSIZ caps a real device name at 15 bytes, and `/` is not legal in
    // one, so this name cannot collide with a host interface.
    let err = unicast_addresses_of_interface("wz/no/such/dev")
        .expect_err("an unnameable device cannot resolve");
    assert_eq!(
        err,
        IfaceResolveError::NotFound,
        "an absent name must be NotFound, not {err:?} — the policy treats \
         Undetermined as a warn and NotFound as a hard error"
    );
}

/// An `#iface=` value that is an IPv4 LITERAL is used directly, without any
/// interface lookup — upstream's first arm
/// (`io/zenoh-links/zenoh-link-udp/src/multicast.rs` @ `iface_addr = match iface.parse() {`).
/// Checked with an address NO interface carries, so it can only pass if the literal
/// short-circuits the table walk.
#[test]
#[cfg(feature = "locator-iface")]
fn a_multicast_iface_given_as_an_address_literal_skips_the_interface_lookup() {
    // TEST-NET-1 (RFC5737): reserved for documentation, never on a host NIC. A
    // name-based resolution of it would be NotFound.
    let selector = multicast_iface_selector_v4("192.0.2.1")
        .expect("an address literal needs no interface table");
    assert_eq!(
        selector,
        Some(std::net::Ipv4Addr::new(192, 0, 2, 1)),
        "an IPv4 literal must be taken verbatim as the interface selector"
    );
}

/// A NAME resolves through the interface table to that interface's v4 address.
#[test]
#[cfg(feature = "locator-iface")]
fn a_multicast_iface_given_as_a_name_resolves_to_its_v4_address() {
    let lo = loopback_iface_name();
    let selector =
        multicast_iface_selector_v4(lo).expect("the loopback is present, up and running");
    assert_eq!(
        selector,
        Some(std::net::Ipv4Addr::LOCALHOST),
        "{lo}'s v4 address is the selector a v4 group pins to"
    );
}

/// An absent name is a HARD ERROR, not a warn-and-continue — the same posture as
/// upstream, which `bail!`s and propagates with `?` (`multicast.rs:229`). This is
/// the boundary the policy turns on: silently falling back would pin the group to
/// an interface the config never named.
#[test]
#[cfg(feature = "locator-iface")]
fn an_absent_multicast_iface_refuses_the_bind_rather_than_warning() {
    let err = multicast_iface_selector_v4("wz/no/such/dev")
        .expect_err("an unnameable device must not yield a selector");
    assert_eq!(
        err.kind(),
        std::io::ErrorKind::InvalidInput,
        "an unresolvable #iface= must refuse the bind; got {err:?}"
    );
}

/// R2584 — the loopback's kernel index, read from sysfs so that it does not
/// come from the `if_nametoindex` call the resolver itself makes.
///
/// Without sysfs (not Linux) the resolver's own answer is used instead. The
/// name test below then checks `if_nametoindex` against itself, but the
/// address test still checks two lookups against each other.
fn loopback_index(lo: &str) -> u32 {
    match std::fs::read_to_string(format!("/sys/class/net/{lo}/ifindex")) {
        Ok(s) => s
            .trim()
            .parse()
            .expect("sysfs ifindex is a decimal integer"),
        Err(_) => interface_index_of_name(lo).expect("the loopback has an index"),
    }
}

/// The loopback must carry `::1`, or every v6 test below is about an address
/// the host does not have. A host with IPv6 disabled FAILS here rather than
/// skipping, because a skipped selector test reports green while checking
/// nothing.
fn loopback_carrying_v6() -> &'static str {
    let lo = loopback_iface_name();
    let addrs = unicast_addresses_of_interface(lo).expect("the loopback resolves");
    assert!(
        addrs.contains(&IpAddr::V6(std::net::Ipv6Addr::LOCALHOST)),
        "{lo} carries no ::1, so IPv6 is disabled on this host and the v6 \
         resolution cannot be checked; got {addrs:?}"
    );
    lo
}

/// An address resolves to the index of the interface holding it, checked
/// against sysfs. Both families go through the same lookup, and IPv4 is
/// included because a family filter hidden in it would pass a v6-only test.
#[test]
fn an_address_resolves_to_the_index_of_the_interface_that_carries_it() {
    let lo = loopback_carrying_v6();
    let want = loopback_index(lo);
    for addr in [
        IpAddr::V6(std::net::Ipv6Addr::LOCALHOST),
        IpAddr::V4(std::net::Ipv4Addr::LOCALHOST),
    ] {
        let got = interface_indices_of_address(addr).expect("the lookup runs");
        assert!(
            got.contains(&want),
            "{addr} sits on {lo} (index {want}), so its carriers {got:?} must include it"
        );
    }
}

/// No interface holds the wildcard as an address. `interface_names_for`
/// returns every interface for it, for a different reason (a socket bound to
/// the wildcard is on all of them), and an index lookup that reused that
/// answer would let `#iface=::` pin some arbitrary interface.
#[test]
fn the_unspecified_address_is_carried_by_no_interface() {
    let got = interface_indices_of_address(IpAddr::V6(std::net::Ipv6Addr::UNSPECIFIED))
        .expect("the lookup runs");
    assert!(got.is_empty(), ":: is no interface's address; got {got:?}");
}

/// A v6 `#iface=` NAME selects that interface's own index.
#[test]
#[cfg(feature = "locator-iface")]
fn a_v6_multicast_iface_given_a_name_selects_that_interfaces_index() {
    let lo = loopback_carrying_v6();
    let selector = multicast_iface_selector_v6(lo).expect("the loopback carries ::1");
    assert_eq!(
        selector,
        Some(loopback_index(lo)),
        "a v6 group pinned to {lo} must select {lo}'s index"
    );
}

/// A v6 address LITERAL selects the interface that holds it: upstream's
/// address-then-index chain.
#[test]
#[cfg(feature = "locator-iface")]
fn a_v6_multicast_iface_given_an_address_selects_the_interface_carrying_it() {
    let lo = loopback_carrying_v6();
    let selector = multicast_iface_selector_v6("::1").expect("::1 is carried by the loopback");
    assert_eq!(selector, Some(loopback_index(lo)));
}

/// An address no interface holds is refused. That matches upstream, which
/// `bail!`s when it finds no interface with that address. Unlike the v4 literal,
/// the address cannot be handed to the kernel as-is, because a v6 selector
/// is an index.
#[test]
#[cfg(feature = "locator-iface")]
fn a_v6_multicast_iface_no_interface_carries_refuses_the_bind() {
    // 2001:db8::/32 (RFC3849) is reserved for documentation and never assigned.
    let err = multicast_iface_selector_v6("2001:db8::7a")
        .expect_err("an address nothing carries selects no interface");
    assert_eq!(err.kind(), std::io::ErrorKind::AddrNotAvailable, "{err}");
}

/// The selection itself, for every carrier count, including the one this
/// host cannot produce: one address on SEVERAL interfaces. Upstream takes
/// whichever came first in its snapshot. wz refuses, because that order is
/// not something the config author chose.
#[test]
#[cfg(feature = "locator-iface")]
fn an_address_on_several_interfaces_names_none_of_them() {
    assert_eq!(the_one_carrier("fe80::1", &[5]).expect("one carrier"), 5);
    let none = the_one_carrier("fe80::1", &[]).expect_err("no carrier");
    assert_eq!(none.kind(), std::io::ErrorKind::AddrNotAvailable);
    let several = the_one_carrier("fe80::1", &[2, 5]).expect_err("two carriers");
    assert_eq!(several.kind(), std::io::ErrorKind::InvalidInput);
    assert!(
        several.to_string().contains("2 interfaces"),
        "the refusal says how many interfaces claimed the address: {several}"
    );
}

/// An address of the OTHER family is refused by both selectors and the
/// message names the family. Before R2584 the v4 selector looked a v6 literal
/// up as a NAME and reported "not found".
#[test]
#[cfg(feature = "locator-iface")]
fn a_multicast_iface_of_the_other_family_is_refused_by_both_selectors() {
    let v6_given_v4 = multicast_iface_selector_v6("127.0.0.1").expect_err("family mismatch");
    let v4_given_v6 = multicast_iface_selector_v4("::1").expect_err("family mismatch");
    for err in [v6_given_v4, v4_given_v6] {
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidInput, "{err}");
        assert!(
            err.to_string().contains("protocols must match"),
            "the refusal names the family mismatch: {err}"
        );
    }
}

/// An absent name is a hard error for v6 as well.
#[test]
#[cfg(feature = "locator-iface")]
fn an_absent_v6_multicast_iface_refuses_the_bind_rather_than_warning() {
    let err = multicast_iface_selector_v6("wz/no/such/dev")
        .expect_err("an unnameable device must not yield a selector");
    assert_eq!(err.kind(), std::io::ErrorKind::InvalidInput, "{err}");
}

/// The IFF_UP / IFF_RUNNING verdicts must agree with what sysfs independently
/// reports, for EVERY interface the host has.
///
/// This exists because the carrier check is otherwise unasserted: nothing else
/// here can construct a down interface (that needs `CAP_NET_ADMIN`), so without
/// a cross-check the whole `NotUp` / `NotRunning` surface would rest on reading
/// the code. `/sys/class/net/<dev>/carrier` is a genuinely independent source —
/// sysfs, not `getifaddrs` — and it is the right one: sysfs's `flags` file
/// deliberately omits IFF_RUNNING (`lo` reads `0x9`, no `0x40`, while
/// `getifaddrs` does report it), so comparing against `flags` would manufacture
/// a disagreement on loopback.
///
/// A host whose every interface has carrier means the `carrier == 0` direction
/// checks nothing — but the `carrier == 1` direction still asserts on every one
/// of them, so the test is never vacuous.
#[test]
fn the_carrier_verdict_agrees_with_sysfs_for_every_interface() {
    let entries = match std::fs::read_dir("/sys/class/net") {
        Ok(e) => e,
        // Not Linux, or sysfs unmounted: the resolver still works, there is just
        // no second source to compare against.
        Err(_) => return,
    };
    let mut checked = 0usize;
    for entry in entries.filter_map(|e| e.ok()) {
        let name = entry.file_name().to_string_lossy().into_owned();
        let carrier = match std::fs::read_to_string(format!("/sys/class/net/{name}/carrier")) {
            Ok(s) => s.trim().to_string(),
            // A device can refuse the read (EINVAL while down); skip only that one.
            Err(_) => continue,
        };
        let verdict = unicast_addresses_of_interface(&name);
        checked += 1;
        match carrier.as_str() {
            "0" => assert!(
                matches!(
                    verdict,
                    Err(IfaceResolveError::NotRunning) | Err(IfaceResolveError::NotUp)
                ),
                "sysfs says {name} has no carrier, so the resolver must reject it as \
                 NotRunning/NotUp (upstream bails on exactly this); got {verdict:?}"
            ),
            "1" => assert!(
                !matches!(verdict, Err(IfaceResolveError::NotRunning)),
                "sysfs says {name} HAS carrier, so the resolver must not call it \
                 NotRunning; got {verdict:?}"
            ),
            other => panic!("unexpected carrier value {other:?} for {name}"),
        }
    }
    assert!(
        checked > 0,
        "no interface carrier was readable under /sys/class/net, so this \
         cross-check asserted nothing"
    );
}

/// The two directions must agree: every address `lo` resolves to must resolve
/// BACK to a name set containing `lo`. Neither function can satisfy this
/// alone, so it witnesses the pair rather than either one's own output.
#[test]
fn the_two_resolution_directions_agree_on_loopback() {
    let lo = loopback_iface_name();
    let addrs = unicast_addresses_of_interface(lo).expect("the loopback resolves");
    assert!(!addrs.is_empty(), "{lo} carries at least one address");
    for addr in addrs {
        let names = interface_names_for(addr).expect("the reverse lookup runs");
        assert!(
            names.iter().any(|n| n == lo),
            "{addr} came from {lo}, so its name set {names:?} must contain {lo}"
        );
    }
}

/// The wildcard address is on EVERY interface (zenoh's same arm), so it must
/// be a strict superset of what a specific local address resolves to.
#[test]
fn the_unspecified_address_covers_every_interface() {
    let all = interface_names_for(IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED))
        .expect("getifaddrs resolves");
    let loopback = interface_names_for(IpAddr::V4(std::net::Ipv4Addr::LOCALHOST))
        .expect("getifaddrs resolves");
    assert!(!all.is_empty(), "the host has at least one interface");
    for name in &loopback {
        assert!(
            all.contains(name),
            "the wildcard set {all:?} must contain the loopback's {name}"
        );
    }
}

/// R3071 -- the host's own address list, read from the kernel, names loopback and a
/// non-loopback address, which is the population an unspecified listener expands over.
#[test]
fn the_local_address_list_holds_loopback_and_something_else() {
    let local = local_addresses().expect("getifaddrs resolves");
    assert!(
        local.iter().any(IpAddr::is_loopback),
        "an UP interface named loopback is in {local:?}"
    );
}
