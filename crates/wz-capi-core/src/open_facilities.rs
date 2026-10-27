// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! What an open asks of the operating system, read from the plan it runs: the configuration-aware
//! half of the device requirement (docs/target-build-contract.md T9).
//!
//! A manifest's `requires` and `may_require` bound every run of a BUILD. A configuration narrows
//! them: a node told to dial `tcp/192.0.2.1:7447` and nothing else needs a TCP socket and no name
//! resolution, one told to dial `tcp/router.lan:7447` needs both. [`OpenPlan::device_requires`]
//! answers for one configuration, from the [`OpenPlan`] the open itself runs on, so the answer
//! cannot read a document differently from the open that consumes it.
//!
//! The two sets keep the manifest's meanings. `requires` is what the open cannot go on without:
//! the engine's threads and entropy, each file the plan read (an unreadable one is refused), each
//! endpoint the open fails without (a listener under `listen/exit_on_failure`, the facilities
//! EVERY dial target needs under `connect/exit_on_failure`, since one success suffices), and the
//! group scouting of a client that has nothing else to dial. `may_require` is everything else a run
//! of the configuration may ask for. `requires` is a lower bound as the manifest's is: an
//! intersection over the dial targets is below "at least one" and below "all of them" alike.
//!
//! An endpoint of a scheme no facility names (serial, vsock) makes `may_require` UNKNOWN (`None`)
//! with the reason in `unknown`, never a guess.
//!
//! [`FACILITIES`] is the vocabulary of `scripts/lib/wz_config.py` (`OS_FACILITIES`), which
//! `wz_config.py --check` holds this list to.

use std::collections::BTreeSet;

use wz_runtime_tokio::locator::{parse_any_locator, AnyLocator, LinkSocketOptions, Proto};
#[cfg(feature = "scout")]
use wz_runtime_tokio::session_glue::WhatAmI;

use crate::open_plan::OpenPlan;

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

/// What the engine itself asks of every run, whatever the configuration: its tokio runtime's
/// threads and the entropy every handshake draws (the `[os] always` of `deploy/wz-config.toml`).
const ENGINE: [&str; 2] = ["threads", "entropy"];

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
    /// The requirement as one JSON object with the manifest's keys and `unknown`.
    pub fn to_json(&self) -> String {
        let list = |items: &[&str]| {
            let quoted: Vec<String> = items.iter().map(|item| format!("\"{item}\"")).collect();
            format!("[{}]", quoted.join(", "))
        };
        let may = self
            .may_require
            .as_ref()
            .map_or_else(|| "null".to_owned(), |may| list(may));
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
fn ip_link(proto: Proto, socket: Option<&LinkSocketOptions>) -> EndpointNeeds {
    let mut needs = EndpointNeeds::default();
    needs.strict.insert(match proto {
        Proto::Tcp | Proto::Tls | Proto::Ws => "sockets-tcp",
        Proto::Udp | Proto::Quic | Proto::QuicDatagram | Proto::UdpReliable => "sockets-udp",
    });
    // `#iface=` names the interface the socket is bound to, looked up by name: no interface, no
    // link.
    if socket.is_some_and(|options| options.iface.is_some()) {
        needs.strict.insert("interface-list");
    }
    // Every IP link reads the interfaces its local address sits on, for the access-control
    // subject, and goes on with an indeterminate set when it cannot.
    needs.loose.insert("interface-list");
    // The certificate-bearing links check a peer certificate's validity against the calendar.
    if matches!(proto, Proto::Tls | Proto::Quic | Proto::QuicDatagram) {
        needs.loose.insert("wall-clock");
    }
    needs
}

/// What dialling or binding `endpoint` asks for, or why that has no name.
fn endpoint_needs(endpoint: &str) -> Result<EndpointNeeds, String> {
    match parse_any_locator(endpoint) {
        Ok(AnyLocator::Ip(parsed)) => Ok(ip_link(parsed.proto, parsed.socket.as_deref())),
        Ok(AnyLocator::Named { proto, socket, .. }) => {
            // A host rather than an address goes through the resolver before any socket.
            let mut needs = ip_link(proto, socket.as_deref());
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

/// What joining the multicast group `endpoint` asks for: a UDP socket that has joined it.
fn group_needs(endpoint: &str) -> Result<EndpointNeeds, String> {
    let mut needs = endpoint_needs(endpoint)?;
    needs.strict.insert("multicast");
    Ok(needs)
}

impl OpenPlan {
    /// What a run of this plan asks of the operating system. See the module documentation.
    pub fn device_requires(&self) -> DeviceRequires {
        let mut requires: BTreeSet<&'static str> = ENGINE.into_iter().collect();
        let mut may: BTreeSet<&'static str> = BTreeSet::new();
        let mut unknown: Vec<String> = Vec::new();

        if !self.read_files.is_empty() {
            requires.insert("filesystem");
        }

        // Every listener and every group is bound by the open; under `exit_on_failure` one that
        // cannot be bound fails it.
        let binds_or_fails = self.listen_phase.policy.exit_on_failure;
        let bound = self
            .listen
            .iter()
            .map(|endpoint| endpoint_needs(endpoint))
            .chain(self.groups.iter().map(|group| group_needs(&group.endpoint)));
        for needs in bound {
            match needs {
                Ok(needs) => {
                    if binds_or_fails {
                        requires.extend(needs.strict);
                    } else {
                        may.extend(needs.strict);
                    }
                    may.extend(needs.loose);
                }
                Err(reason) => unknown.push(reason),
            }
        }

        // One dial target that answers is enough, so what the open cannot go on without is what
        // every target needs.
        let mut common: Option<BTreeSet<&'static str>> = None;
        for endpoint in &self.connect {
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
        if self.dial.policy.exit_on_failure {
            requires.extend(common.unwrap_or_default());
        }

        #[cfg(feature = "scout")]
        if self.scouting.as_ref().is_some_and(|plan| plan.scouts()) {
            // A client with no endpoint to dial finds its node by scouting or fails its open; any
            // other node scouts beside what it was told.
            let only_way = self.role == WhatAmI::Client && self.connect.is_empty();
            for facility in ["sockets-udp", "multicast"] {
                if only_way {
                    requires.insert(facility);
                } else {
                    may.insert(facility);
                }
            }
            // The interface scouting goes out on, and the links to what it finds, whose schemes
            // are the found node's and not the configuration's.
            may.extend(["interface-list", "sockets-tcp", "sockets-udp"]);
        }

        // A clock stamps every sample this role publishes; a stamp read from an unset clock is a
        // wrong stamp and not a stopped node.
        if self.timestamping.get(self.role) {
            may.insert("wall-clock");
        }

        may.retain(|facility| !requires.contains(facility));
        DeviceRequires {
            requires: requires.into_iter().collect(),
            may_require: unknown.is_empty().then(|| may.into_iter().collect()),
            unknown,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::open_plan::{OpenPlan, StatedEndpoints};
    use wz_runtime_tokio::session_glue::WhatAmI;

    fn plan(role: WhatAmI, connect: &[&str], listen: &[&str], document: &str) -> OpenPlan {
        let stated = StatedEndpoints {
            connect: connect.iter().map(|s| (*s).to_owned()).collect(),
            listen: listen.iter().map(|s| (*s).to_owned()).collect(),
        };
        let mode = role.to_str();
        let document = format!("{{ mode: \"{mode}\", {document} }}");
        match OpenPlan::resolve(role, stated, Some(&document)) {
            Ok(plan) => plan,
            Err(refusal) => panic!("the plan was refused: {refusal:?}"),
        }
    }

    const NO_SCOUT: &str = "scouting: { multicast: { enabled: false } }";

    #[test]
    fn a_client_dialling_one_address_requires_its_socket_and_no_resolver() {
        let got = plan(WhatAmI::Client, &["tcp/192.0.2.1:7447"], &[], NO_SCOUT).device_requires();
        assert_eq!(got.requires, ["entropy", "sockets-tcp", "threads"]);
        assert_eq!(got.may_require, Some(vec!["interface-list"]));
        assert!(got.unknown.is_empty());
    }

    #[test]
    fn a_host_name_requires_the_resolver_when_it_is_the_only_target() {
        let got =
            plan(WhatAmI::Client, &["tcp/router.example:7447"], &[], NO_SCOUT).device_requires();
        assert_eq!(
            got.requires,
            ["entropy", "name-resolution", "sockets-tcp", "threads"]
        );
    }

    #[test]
    fn of_two_targets_only_what_both_need_is_required() {
        let got = plan(
            WhatAmI::Client,
            &["tcp/router.example:7447", "udp/192.0.2.1:7447"],
            &[],
            NO_SCOUT,
        )
        .device_requires();
        assert_eq!(got.requires, ["entropy", "threads"]);
        assert_eq!(
            got.may_require,
            Some(vec![
                "interface-list",
                "name-resolution",
                "sockets-tcp",
                "sockets-udp"
            ])
        );
    }

    #[test]
    fn a_dial_that_may_fail_requires_nothing_of_its_targets() {
        let got = plan(
            WhatAmI::Client,
            &["tcp/192.0.2.1:7447"],
            &[],
            "scouting: { multicast: { enabled: false } }, connect: { exit_on_failure: false }",
        )
        .device_requires();
        assert_eq!(got.requires, ["entropy", "threads"]);
        assert_eq!(got.may_require, Some(vec!["interface-list", "sockets-tcp"]));
    }

    #[test]
    fn a_listener_that_must_bind_requires_its_socket() {
        let got = plan(WhatAmI::Peer, &[], &["tcp/127.0.0.1:7447"], NO_SCOUT).device_requires();
        assert!(got.requires.contains(&"sockets-tcp"), "{got:?}");
    }

    #[test]
    fn an_interface_named_by_the_endpoint_is_required_with_it() {
        let got = plan(
            WhatAmI::Client,
            &["tcp/192.0.2.1:7447#iface=eth0"],
            &[],
            NO_SCOUT,
        )
        .device_requires();
        assert!(got.requires.contains(&"interface-list"), "{got:?}");
    }

    #[test]
    fn a_client_that_can_only_scout_requires_the_group() {
        let got = plan(
            WhatAmI::Client,
            &[],
            &[],
            "scouting: { multicast: { enabled: true } }",
        )
        .device_requires();
        if cfg!(feature = "scout") {
            assert!(
                got.requires.contains(&"multicast") && got.requires.contains(&"sockets-udp"),
                "{got:?}"
            );
        }
    }

    #[test]
    fn a_unix_socket_requires_the_socket_and_no_ip_facility() {
        let got = plan(
            WhatAmI::Client,
            &["unixsock-stream//tmp/wz.sock"],
            &[],
            NO_SCOUT,
        )
        .device_requires();
        assert_eq!(got.requires, ["entropy", "threads", "unix-sockets"]);
        assert_eq!(got.may_require, Some(vec![]));
    }

    #[test]
    fn a_scheme_no_facility_names_leaves_the_bound_unknown() {
        let got = plan(
            WhatAmI::Client,
            &["tcp/192.0.2.1:7447", "serial//dev/ttyUSB0#baudrate=115200"],
            &[],
            NO_SCOUT,
        )
        .device_requires();
        assert_eq!(got.may_require, None);
        assert_eq!(got.unknown.len(), 1, "{got:?}");
        assert!(got.unknown[0].contains("serial"), "{got:?}");
        assert_eq!(got.requires, ["entropy", "threads"]);
    }

    #[test]
    fn the_json_has_the_manifest_keys() {
        let got = DeviceRequires {
            requires: vec!["entropy"],
            may_require: None,
            unknown: vec!["a \"b\"".to_owned()],
        };
        assert_eq!(
            got.to_json(),
            "{\"requires\": [\"entropy\"], \"may_require\": null, \"unknown\": [\"a \\\"b\\\"\"]}"
        );
    }
}
