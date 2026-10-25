use super::{first_ipv4_among, scouting_interface_addresses};
use std::net::IpAddr;

fn ip(text: &str) -> IpAddr {
    text.parse().expect("an address")
}

/// The lookup a host would give: names to the first IPv4 of the interface of that name.
fn host(name: &str) -> Option<IpAddr> {
    match name {
        "eth0" => Some(ip("10.0.0.5")),
        "wlan0" => Some(ip("192.168.1.9")),
        _ => None,
    }
}

/// An interface that holds several addresses is answered by its first IPv4, whatever comes
/// before it and whatever follows.
#[test]
fn the_first_ipv4_of_an_interface_answers_for_all_of_it() {
    let table = [ip("fe80::1"), ip("10.0.0.5"), ip("10.0.0.6"), ip("fd00::2")];
    assert_eq!(first_ipv4_among(&table), Some(ip("10.0.0.5")));
    assert_eq!(first_ipv4_among(&[ip("fe80::1"), ip("fd00::2")]), None);
    assert_eq!(first_ipv4_among(&[]), None);
}

/// Commas split the text, each part is trimmed, and a literal is itself in either family.
#[test]
fn a_list_is_split_on_commas_and_trimmed() {
    assert_eq!(
        scouting_interface_addresses(" eth0 , 192.0.2.7 ,fd7a::1", host),
        vec![ip("10.0.0.5"), ip("192.0.2.7"), ip("fd7a::1")]
    );
    assert_eq!(
        scouting_interface_addresses("wlan0,eth0", host),
        vec![ip("192.168.1.9"), ip("10.0.0.5")],
        "the order of the text is the order of the addresses"
    );
}

/// A part that finds nothing is left out and the others stand: a name that matches no
/// interface, an interface that holds no IPv4 address, an empty part.
#[test]
fn a_part_that_finds_nothing_is_left_out() {
    assert_eq!(
        scouting_interface_addresses("nope,eth0,,v6only", host),
        vec![ip("10.0.0.5")]
    );
    assert!(scouting_interface_addresses("nope", host).is_empty());
    assert!(scouting_interface_addresses("", host).is_empty());
}

/// A literal is taken before any name is looked up: a lookup that would answer for it is
/// never asked, so an address a host does not hold is still what the text says.
#[test]
fn a_literal_is_taken_before_a_name_is_looked_up() {
    let asked = std::cell::RefCell::new(Vec::new());
    let lookup = |name: &str| {
        asked.borrow_mut().push(name.to_owned());
        None
    };
    assert_eq!(
        scouting_interface_addresses("192.0.2.7,wlan0", lookup),
        vec![ip("192.0.2.7")]
    );
    assert_eq!(*asked.borrow(), vec!["wlan0".to_owned()]);
}
