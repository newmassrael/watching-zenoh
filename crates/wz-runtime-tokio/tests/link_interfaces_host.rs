// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The HOST facet of the interface table: what `link_interfaces` answers when it is
//! asked the machine it runs on, and not a table made for the question.
//!
//! The unit tests of the module tell the Windows questions on adapter tables built
//! in the test (`adapter_table_reading`), which proves the reading of a table and
//! says nothing about the call that fetches one. The unix hosts fetch it with
//! `getifaddrs`, a Windows host with `GetAdaptersAddresses`, and the two differ in
//! what they list, how they name an adapter and what they call its index, so the
//! call is the part a table made for the test cannot witness. This is that witness:
//! it asks the host about the one address every host carries, loopback, and requires
//! the four answers to agree with each other.
//!
//! Loopback is the subject because it is the one adapter a hosted runner of any
//! system has, and the one whose first IPv4 address is known without reading the
//! table. What it does NOT prove is any other adapter: a runner's real interfaces
//! are whatever the provider attached that day.
//!
//! Opt-in (`#[ignore]`), run by the platform leg with `--ignored` on each host, like
//! the other host facets: whether a host can be read is an environment fact, and the
//! lane that runs it says so.

#![cfg(feature = "link-interfaces")]

use std::net::{IpAddr, Ipv4Addr};

use wz_runtime_tokio::link_interfaces::{
    first_ipv4_of_interface_named, interface_indices_of_address, interface_names_for,
    local_addresses,
};

const LOOPBACK: IpAddr = IpAddr::V4(Ipv4Addr::LOCALHOST);

/// The host's own table lists loopback, names the adapter that carries it, gives that
/// adapter an index, and the adapter's name finds loopback again as its first IPv4
/// address. Each answer is read from the host, and the last one is the first three
/// agreeing with one another.
#[test]
#[ignore = "reads this host's own interface table"]
fn the_host_table_names_the_adapter_that_carries_loopback() {
    let addresses = local_addresses().expect("the host's interface table could be read");
    assert!(
        addresses.contains(&LOOPBACK),
        "the host lists no loopback address among {addresses:?}"
    );

    let names = interface_names_for(LOOPBACK).expect("the carriers of loopback could be named");
    assert!(!names.is_empty(), "no adapter carries loopback");

    let indices = interface_indices_of_address(LOOPBACK)
        .expect("the index of the loopback carrier could be read");
    assert!(!indices.is_empty(), "no index for the loopback carrier");

    let found = names
        .iter()
        .find_map(|name| first_ipv4_of_interface_named(name));
    assert_eq!(
        found,
        Some(LOOPBACK),
        "no carrier of loopback ({names:?}) answers its own name with loopback"
    );
}
