use super::{
    adapter_first_ipv4_named, adapter_indices_of, adapter_local_addresses, adapter_names_for,
    AdapterRow,
};
use std::net::IpAddr;

fn ip(text: &str) -> IpAddr {
    text.parse().expect("an address")
}

fn row(guid: &str, friendly: &str, description: &str, index: u32, addrs: &[&str]) -> AdapterRow {
    AdapterRow {
        adapter_name: guid.to_owned(),
        friendly_name: friendly.to_owned(),
        description: description.to_owned(),
        ipv6_if_index: index,
        unicast: addrs.iter().map(|a| ip(a)).collect(),
    }
}

/// A loopback adapter, an Ethernet one with an IPv6 address ahead of two IPv4 ones, and one
/// with no address at all.
fn table() -> Vec<AdapterRow> {
    vec![
        row(
            "{LO}",
            "Loopback Pseudo-Interface 1",
            "Software Loopback Interface 1",
            1,
            &["::1", "127.0.0.1"],
        ),
        row(
            "{ETH}",
            "Ethernet",
            "Intel(R) Ethernet",
            12,
            &["fe80::5", "10.0.0.5", "10.0.0.6"],
        ),
        row("{DOWN}", "Wi-Fi", "Intel(R) Wi-Fi", 14, &[]),
    ]
}

/// Every adapter's every address, whether or not the adapter is up: the Windows reading never
/// asks, and the adapter with no address contributes none. A name restricts it to the one
/// adapter whose `AdapterName` is that text, and only that field is compared.
#[test]
fn the_local_addresses_are_every_adapters_unfiltered() {
    assert_eq!(
        adapter_local_addresses(&table(), None),
        vec![
            ip("::1"),
            ip("127.0.0.1"),
            ip("fe80::5"),
            ip("10.0.0.5"),
            ip("10.0.0.6")
        ]
    );
    assert_eq!(
        adapter_local_addresses(&table(), Some("{ETH}")),
        vec![ip("fe80::5"), ip("10.0.0.5"), ip("10.0.0.6")]
    );
    assert!(adapter_local_addresses(&table(), Some("Ethernet")).is_empty());
}

/// A name finds an adapter by any of its three names, and the adapter answers with its FIRST
/// IPv4 address, past an IPv6 one ahead of it and short of the IPv4 one after it.
#[test]
fn a_name_finds_the_first_ipv4_of_the_adapter_by_any_of_its_three_names() {
    for name in ["{ETH}", "Ethernet", "Intel(R) Ethernet"] {
        assert_eq!(
            adapter_first_ipv4_named(&table(), name),
            Some(ip("10.0.0.5")),
            "`{name}` names the Ethernet adapter"
        );
    }
    assert_eq!(
        adapter_first_ipv4_named(&table(), "{LO}"),
        Some(ip("127.0.0.1"))
    );
}

/// An adapter that holds no IPv4 address, and a name nothing holds, find nothing; and an
/// address spelled as a name is that address, which is the second rule of upstream's loop.
#[test]
fn a_name_with_nothing_to_answer_finds_nothing_and_an_address_text_is_itself() {
    assert_eq!(adapter_first_ipv4_named(&table(), "Wi-Fi"), None);
    assert_eq!(adapter_first_ipv4_named(&table(), "nope"), None);
    assert_eq!(
        adapter_first_ipv4_named(&table(), "10.0.0.6"),
        Some(ip("10.0.0.6"))
    );
}

/// The index an address selects is its adapter's `Ipv6IfIndex`, for an IPv4 address as for an
/// IPv6 one, and an address no adapter holds selects none.
#[test]
fn an_address_selects_the_ipv6_index_of_its_adapter() {
    assert_eq!(adapter_indices_of(&table(), ip("10.0.0.5")), vec![12]);
    assert_eq!(adapter_indices_of(&table(), ip("::1")), vec![1]);
    assert!(adapter_indices_of(&table(), ip("192.0.2.1")).is_empty());
}

/// An address names the adapters that carry it, by `AdapterName`; the unspecified address names
/// every adapter, one with no address included.
#[test]
fn an_address_names_the_adapters_that_carry_it() {
    assert_eq!(
        adapter_names_for(&table(), ip("10.0.0.6")),
        vec!["{ETH}".to_owned()]
    );
    assert_eq!(
        adapter_names_for(&table(), ip("::1")),
        vec!["{LO}".to_owned()]
    );
    assert!(adapter_names_for(&table(), ip("192.0.2.1")).is_empty());
    assert_eq!(
        adapter_names_for(&table(), ip("0.0.0.0")),
        vec!["{LO}".to_owned(), "{ETH}".to_owned(), "{DOWN}".to_owned()]
    );
}
