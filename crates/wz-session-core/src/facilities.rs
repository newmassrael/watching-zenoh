// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! What an open asks of the operating system: the configuration-aware half of the device
//! requirement (docs/target-build-contract.md T9), for every ABI, engine and executable.
//!
//! A manifest's `requires` and `may_require` bound every run of a BUILD. A configuration narrows
//! them: a node told to dial `tcp/192.0.2.1:7447` and nothing else needs a TCP socket and no name
//! resolution, one told to dial `tcp/router.lan:7447` needs both. Each reader of a configuration
//! (the zenoh-c open plan, the pico C ABI, the demo's sessions document) reads it into
//! [`OpenFacts`], the same reading its open acts on, and [`device_requires`] answers from it, so
//! the answer cannot read a configuration differently from the open.
//!
//! The two sets keep the manifest's meanings. `requires` is what the open cannot go on without:
//! the engine's threads and entropy, each file the run reads and cannot go on without, each
//! endpoint the open fails without (a listener or a group whose bind fails the open, the facilities
//! EVERY dial target needs when a failed dial fails it, since one success suffices), and the group
//! scouting of an open that has no other way to a node. `may_require` is everything else a run of
//! the configuration may ask for. `requires` is a lower bound as the manifest's is: an
//! intersection over the dial targets is below "at least one" and below "all of them" alike.
//!
//! An endpoint of a scheme no facility names (serial, vsock) makes `may_require` UNKNOWN (`None`)
//! with the reason in `unknown`, never a guess.
//!
//! [`FACILITIES`] is the vocabulary of `scripts/lib/wz_config.py` (`OS_FACILITIES`), and
//! [`ENGINE`] its `[os] always`; `wz_config.py --check` holds both to the declaration.

use alloc::collections::BTreeSet;
use alloc::format;
use alloc::string::{String, ToString};
use alloc::vec::Vec;

use crate::locator::{parse_any_locator, AnyLocator, Proto};

/// The facility vocabulary, in `OS_FACILITIES`' order.
pub const FACILITIES: [&str; 11] = [
    "threads",
    "sockets-tcp",
    "sockets-udp",
    "multicast",
    "raw-ethernet",
    "unix-sockets",
    "filesystem",
    "entropy",
    "wall-clock",
    "interface-list",
    "name-resolution",
];

/// What the engine itself asks of every run, whatever the configuration: its threads and the
/// entropy every handshake draws (the `[os] always` of `deploy/wz-config.toml`).
pub const ENGINE: [&str; 2] = ["threads", "entropy"];

/// How an open uses multicast scouting.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Scouting {
    /// It does not scout.
    Off,
    /// It scouts beside the endpoints it was told of, or answers others' scouts.
    Beside,
    /// It has no other way to a node: a scout that finds nobody fails the open.
    OnlyWay,
}

/// What an open does, as each reader reads it from its configuration.
#[derive(Clone, Debug)]
pub struct OpenFacts<'a> {
    /// The endpoints dialled.
    pub connect: &'a [String],
    /// Whether a dial that reaches none of them fails the open.
    pub dial_must_succeed: bool,
    /// The unicast endpoints bound.
    pub listen: &'a [String],
    /// The multicast groups joined.
    pub groups: Vec<&'a str>,
    /// Whether an endpoint or group that cannot be bound fails the open.
    pub bind_must_succeed: bool,
    /// How the open scouts.
    pub scouting: Scouting,
    /// Whether the run reads a file it cannot go on without: certificate or credential material
    /// named by path, or the configuration document itself.
    pub reads_files: bool,
    /// Whether the run reads the calendar time besides its links: a session that stamps what it
    /// publishes, a program that stamps its log lines.
    pub reads_calendar: bool,
}

/// One configuration's device requirement, in the manifest's terms.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DeviceRequires {
    /// What every run of the configuration asks for and cannot go on without, sorted.
    pub requires: Vec<&'static str>,
    /// The rest of what a run may ask for, sorted, or `None` when part of it has no name.
    pub may_require: Option<Vec<&'static str>>,
    /// Why `may_require` is unknown, one reason per endpoint; empty when it is known.
    pub unknown: Vec<String>,
}

impl DeviceRequires {
    /// The requirement of a run that is all of `parts`, each of which must run (the sessions of
    /// one program, each a part the program reports failed without): what any part cannot go on
    /// without, and the rest any part may ask for; unknown when any part's is.
    pub fn all_of(parts: &[DeviceRequires]) -> DeviceRequires {
        let mut requires: BTreeSet<&'static str> = ENGINE.into_iter().collect();
        let mut may: BTreeSet<&'static str> = BTreeSet::new();
        let mut unknown: Vec<String> = Vec::new();
        for part in parts {
            requires.extend(part.requires.iter().copied());
            may.extend(part.may_require.iter().flatten().copied());
            unknown.extend(part.unknown.iter().cloned());
        }
        may.retain(|facility| !requires.contains(facility));
        let known = parts.iter().all(|part| part.may_require.is_some());
        DeviceRequires {
            requires: requires.into_iter().collect(),
            may_require: known.then(|| may.into_iter().collect()),
            unknown,
        }
    }

    /// The requirement as one JSON object with the manifest's keys and `unknown`.
    pub fn to_json(&self) -> String {
        let list = |items: &[&str]| {
            let quoted: Vec<String> = items.iter().map(|item| format!("\"{item}\"")).collect();
            format!("[{}]", quoted.join(", "))
        };
        let may = self
            .may_require
            .as_ref()
            .map_or_else(|| "null".to_string(), |may| list(may));
        let unknown: Vec<String> = self
            .unknown
            .iter()
            .map(|reason| json_string(reason))
            .collect();
        format!(
            "{{\"requires\": {}, \"may_require\": {may}, \"unknown\": [{}]}}",
            list(&self.requires),
            unknown.join(", ")
        )
    }
}

fn json_string(text: &str) -> String {
    let mut out = String::from("\"");
    for c in text.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

/// What one endpoint asks for: `strict`, without which its link cannot be made, and `loose`, which
/// its link may ask for and goes on without.
#[derive(Default)]
struct EndpointNeeds {
    strict: BTreeSet<&'static str>,
    loose: BTreeSet<&'static str>,
}

/// The socket an IP link of `proto` opens, and what its link may ask besides.
fn ip_link(proto: Proto) -> EndpointNeeds {
    let mut needs = EndpointNeeds::default();
    needs.strict.insert(match proto {
        Proto::Tcp | Proto::Tls | Proto::Ws => "sockets-tcp",
        Proto::Udp | Proto::Quic | Proto::QuicDatagram | Proto::UdpReliable => "sockets-udp",
    });
    // Every IP link reads the interfaces its local address sits on, for the access-control
    // subject, and goes on with an indeterminate set when it cannot. An `#iface=` asks nothing
    // stricter: a unicast link hands the name to the kernel (`SO_BINDTODEVICE`) and lists nothing,
    // and a group looks a named interface up in the listing but, when the listing cannot be made,
    // joins on the kernel's default interface and goes on (`wz-host-net`'s
    // `multicast_iface_selector_v4` and `_v6`).
    needs.loose.insert("interface-list");
    // The certificate-bearing links check a peer certificate's validity against the calendar.
    if matches!(proto, Proto::Tls | Proto::Quic | Proto::QuicDatagram) {
        needs.loose.insert("wall-clock");
    }
    needs
}

/// pico's raw Ethernet transport (`reth/<interface>...`): a link-layer socket on the interface the
/// locator names, looked up by that name.
const RAW_ETHERNET_SCHEME: &str = "reth/";

/// What dialling or binding `endpoint` asks for, or why that has no name.
fn endpoint_needs(endpoint: &str) -> Result<EndpointNeeds, String> {
    if endpoint.starts_with(RAW_ETHERNET_SCHEME) {
        return Ok(EndpointNeeds {
            strict: BTreeSet::from(["raw-ethernet", "interface-list"]),
            loose: BTreeSet::new(),
        });
    }
    match parse_any_locator(endpoint) {
        Ok(AnyLocator::Ip(parsed)) => Ok(ip_link(parsed.proto)),
        Ok(AnyLocator::Named { proto, .. }) => {
            // A host rather than an address goes through the resolver before any socket.
            let mut needs = ip_link(proto);
            needs.strict.insert("name-resolution");
            Ok(needs)
        }
        Ok(AnyLocator::Unixsock(_)) => Ok(EndpointNeeds {
            strict: BTreeSet::from(["unix-sockets"]),
            loose: BTreeSet::new(),
        }),
        // A pipe link is a pair of named pipes made and opened by their paths.
        Ok(AnyLocator::Unixpipe(_)) => Ok(EndpointNeeds {
            strict: BTreeSet::from(["filesystem"]),
            loose: BTreeSet::new(),
        }),
        Ok(AnyLocator::Serial(_)) => Err(format!(
            "{endpoint}: a serial device is a request no facility of the vocabulary names"
        )),
        Ok(AnyLocator::Vsock(_)) => Err(format!(
            "{endpoint}: a vsock socket is a request no facility of the vocabulary names"
        )),
        Err(error) => Err(format!(
            "{endpoint}: not a locator this build reads ({error:?})"
        )),
    }
}

/// What joining the group `endpoint` asks for: a UDP socket that has joined an IP multicast group,
/// or for pico's raw Ethernet group the link-layer socket alone.
fn group_needs(endpoint: &str) -> Result<EndpointNeeds, String> {
    let mut needs = endpoint_needs(endpoint)?;
    if !endpoint.starts_with(RAW_ETHERNET_SCHEME) {
        needs.strict.insert("multicast");
    }
    Ok(needs)
}

/// What a run of an open of `facts` asks of the operating system. See the module documentation.
pub fn device_requires(facts: &OpenFacts<'_>) -> DeviceRequires {
    let mut requires: BTreeSet<&'static str> = ENGINE.into_iter().collect();
    let mut may: BTreeSet<&'static str> = BTreeSet::new();
    let mut unknown: Vec<String> = Vec::new();

    if facts.reads_files {
        requires.insert("filesystem");
    }

    // Every listener and every group is bound by the open; one that cannot be bound fails it when
    // the open says so.
    let bound = facts
        .listen
        .iter()
        .map(|endpoint| endpoint_needs(endpoint))
        .chain(facts.groups.iter().map(|group| group_needs(group)));
    for needs in bound {
        match needs {
            Ok(needs) => {
                if facts.bind_must_succeed {
                    requires.extend(needs.strict);
                } else {
                    may.extend(needs.strict);
                }
                may.extend(needs.loose);
            }
            Err(reason) => unknown.push(reason),
        }
    }

    // One dial target that answers is enough, so what the open cannot go on without is what every
    // target needs.
    let mut common: Option<BTreeSet<&'static str>> = None;
    for endpoint in facts.connect {
        let strict = match endpoint_needs(endpoint) {
            Ok(needs) => {
                may.extend(needs.loose);
                needs.strict
            }
            Err(reason) => {
                unknown.push(reason);
                BTreeSet::new()
            }
        };
        may.extend(strict.iter().copied());
        common = Some(match common {
            None => strict,
            Some(common) => common.intersection(&strict).copied().collect(),
        });
    }
    if facts.dial_must_succeed {
        requires.extend(common.unwrap_or_default());
    }

    if facts.scouting != Scouting::Off {
        for facility in ["sockets-udp", "multicast"] {
            if facts.scouting == Scouting::OnlyWay {
                requires.insert(facility);
            } else {
                may.insert(facility);
            }
        }
        // The interface scouting goes out on, and the links to what it finds, whose schemes are
        // the found node's and not the configuration's.
        may.extend(["interface-list", "sockets-tcp", "sockets-udp"]);
    }

    // A stamp read from an unset clock is a wrong stamp and not a stopped node.
    if facts.reads_calendar {
        may.insert("wall-clock");
    }

    may.retain(|facility| !requires.contains(facility));
    DeviceRequires {
        requires: requires.into_iter().collect(),
        may_require: unknown.is_empty().then(|| may.into_iter().collect()),
        unknown,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::borrow::ToOwned;
    use alloc::vec;

    fn facts<'a>(connect: &'a [String], listen: &'a [String]) -> OpenFacts<'a> {
        OpenFacts {
            connect,
            dial_must_succeed: true,
            listen,
            groups: Vec::new(),
            bind_must_succeed: true,
            scouting: Scouting::Off,
            reads_files: false,
            reads_calendar: false,
        }
    }

    fn owned(items: &[&str]) -> Vec<String> {
        items.iter().map(|item| (*item).to_owned()).collect()
    }

    #[test]
    fn a_group_requires_its_socket_and_the_membership() {
        let none = owned(&[]);
        let mut open = facts(&none, &none);
        open.groups = vec!["udp/224.0.0.224:7447"];
        let got = device_requires(&open);
        assert_eq!(
            got.requires,
            ["entropy", "multicast", "sockets-udp", "threads"]
        );
    }

    #[test]
    fn a_raw_ethernet_group_requires_the_link_layer_socket_and_no_ip_membership() {
        let none = owned(&[]);
        let mut open = facts(&none, &none);
        open.groups = vec!["reth/eth0#ethtype=72e1"];
        let got = device_requires(&open);
        assert_eq!(
            got.requires,
            ["entropy", "interface-list", "raw-ethernet", "threads"]
        );
        assert_eq!(got.may_require, Some(vec![]));
    }

    #[test]
    fn a_file_read_requires_the_file_system() {
        let connect = owned(&["tcp/192.0.2.1:7447"]);
        let none = owned(&[]);
        let mut open = facts(&connect, &none);
        open.reads_files = true;
        assert!(device_requires(&open).requires.contains(&"filesystem"));
    }

    #[test]
    fn scouting_beside_a_target_is_only_may() {
        let connect = owned(&["tcp/192.0.2.1:7447"]);
        let none = owned(&[]);
        let mut open = facts(&connect, &none);
        open.scouting = Scouting::Beside;
        let got = device_requires(&open);
        assert_eq!(got.requires, ["entropy", "sockets-tcp", "threads"]);
        assert_eq!(
            got.may_require,
            Some(vec!["interface-list", "multicast", "sockets-udp"])
        );
    }

    #[test]
    fn a_vsock_endpoint_leaves_the_bound_unknown() {
        let connect = owned(&["vsock/1:7447"]);
        let none = owned(&[]);
        let got = device_requires(&facts(&connect, &none));
        assert_eq!(got.may_require, None);
        assert!(got.unknown[0].contains("vsock"), "{got:?}");
    }

    #[test]
    fn a_run_of_several_opens_requires_what_any_of_them_requires() {
        let tcp = owned(&["tcp/192.0.2.1:7447"]);
        let udp = owned(&["udp/192.0.2.1:7447"]);
        let none = owned(&[]);
        let got = DeviceRequires::all_of(&[
            device_requires(&facts(&tcp, &none)),
            device_requires(&facts(&udp, &none)),
        ]);
        assert_eq!(
            got.requires,
            ["entropy", "sockets-tcp", "sockets-udp", "threads"]
        );
        assert_eq!(got.may_require, Some(vec!["interface-list"]));
        let vsock = owned(&["vsock/1:7447"]);
        let unknown = DeviceRequires::all_of(&[
            device_requires(&facts(&tcp, &none)),
            device_requires(&facts(&vsock, &none)),
        ]);
        assert_eq!(unknown.may_require, None);
        assert_eq!(unknown.unknown.len(), 1);
    }
}
