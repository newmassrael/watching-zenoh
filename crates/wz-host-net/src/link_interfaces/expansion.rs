use super::*;

fn ip(text: &str) -> IpAddr {
    text.parse().expect("an address")
}

fn host() -> Vec<IpAddr> {
    // The order `getifaddrs` gave on the measured host: the IPv4 ones first, then IPv6.
    [
        "127.0.0.1",
        "172.30.1.74",
        "100.75.93.118",
        "::1",
        "fe80::44be:2469:54d9:9a33",
        "fe80::a583:492f:8016:3c7e",
        "fd7a:115c:a1e0::db37:5d7a",
    ]
    .iter()
    .map(|text| ip(text))
    .collect()
}

fn texts(list: Vec<SocketAddr>) -> Vec<String> {
    list.iter().map(ToString::to_string).collect()
}

#[test]
fn a_v6_wildcard_lists_global_then_public_then_link_local_then_private() {
    let bound: SocketAddr = "[::]:36561".parse().unwrap();
    assert_eq!(
        texts(expand_unspecified(bound, &host(), true)),
        [
            "[fd7a:115c:a1e0::db37:5d7a]:36561",
            "100.75.93.118:36561",
            "[fe80::44be:2469:54d9:9a33]:36561",
            "[fe80::a583:492f:8016:3c7e]:36561",
            "172.30.1.74:36561",
        ]
    );
}

/// An asker on this host is owed the loopback addresses too: `::1` is a global-scope IPv6
/// address and so comes first of the IPv6 ones, and `127.0.0.1` is not private so it follows
/// the other public IPv4 address.
#[test]
fn a_loopback_asker_is_also_offered_loopback() {
    let bound: SocketAddr = "[::]:1".parse().unwrap();
    let with = texts(expand_unspecified(bound, &host(), false));
    assert_eq!(with.len(), 7, "every address of the host: {with:?}");
    assert_eq!(with[0], "[::1]:1");
    assert!(with.contains(&"127.0.0.1:1".to_string()));
}

#[test]
fn a_v4_wildcard_lists_only_ipv4_in_the_hosts_order() {
    let bound: SocketAddr = "0.0.0.0:17922".parse().unwrap();
    assert_eq!(
        texts(expand_unspecified(bound, &host(), true)),
        ["172.30.1.74:17922", "100.75.93.118:17922"]
    );
    assert_eq!(
        texts(expand_unspecified(bound, &host(), false)),
        [
            "127.0.0.1:17922",
            "172.30.1.74:17922",
            "100.75.93.118:17922"
        ]
    );
}

/// An address that is not unspecified stands for itself, and loopback in it is the node's
/// own choice and is not filtered.
#[test]
fn a_specific_bind_stands_for_itself() {
    let bound: SocketAddr = "127.0.0.1:17921".parse().unwrap();
    assert_eq!(expand_unspecified(bound, &host(), true), vec![bound]);
}

/// An IPv4 link-local, multicast or broadcast address is not offered through a `[::]` bind.
#[test]
fn a_v6_wildcard_does_not_offer_an_unusable_ipv4_address() {
    let local: Vec<IpAddr> = ["169.254.3.4", "224.0.0.1", "255.255.255.255", "10.1.2.3"]
        .iter()
        .map(|text| ip(text))
        .collect();
    let bound: SocketAddr = "[::]:5".parse().unwrap();
    assert_eq!(
        texts(expand_unspecified(bound, &local, true)),
        ["10.1.2.3:5"]
    );
}
