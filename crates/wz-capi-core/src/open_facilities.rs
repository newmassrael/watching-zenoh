// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! What an open of an [`OpenPlan`] asks of the operating system: the plan read as the
//! [`OpenFacts`] of `wz_session_core::facilities`, which answers for every reader of a
//! configuration (docs/target-build-contract.md T9).
//!
//! The reading is the plan the open itself runs on, so the answer cannot read a document
//! differently from the open that consumes it: a listener fails the open under
//! `listen/exit_on_failure`, a dial that reaches no target fails it under
//! `connect/exit_on_failure`, a client with no endpoint to dial has only its scouting, and the
//! certificate and credential files the plan read are files the open cannot go on without.

use wz_runtime_tokio::facilities::{device_requires, OpenFacts, Scouting};
pub use wz_runtime_tokio::facilities::{DeviceRequires, FACILITIES};
#[cfg(feature = "scout")]
use wz_runtime_tokio::session_glue::WhatAmI;

use crate::open_plan::OpenPlan;

impl OpenPlan {
    /// What a run of this plan asks of the operating system. See the module documentation.
    pub fn device_requires(&self) -> DeviceRequires {
        #[cfg(feature = "scout")]
        let scouting = match self.scouting.as_ref().is_some_and(|plan| plan.scouts()) {
            false => Scouting::Off,
            true if self.role == WhatAmI::Client && self.connect.is_empty() => Scouting::OnlyWay,
            true => Scouting::Beside,
        };
        #[cfg(not(feature = "scout"))]
        let scouting = Scouting::Off;
        device_requires(&OpenFacts {
            connect: &self.connect,
            dial_must_succeed: self.dial.policy.exit_on_failure,
            listen: &self.listen,
            groups: self
                .groups
                .iter()
                .map(|group| group.endpoint.as_str())
                .collect(),
            bind_must_succeed: self.listen_phase.policy.exit_on_failure,
            scouting,
            reads_files: !self.read_files.is_empty(),
            reads_calendar: self.timestamping.get(self.role),
        })
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
    fn an_interface_named_by_the_endpoint_lists_nothing_it_cannot_go_without() {
        let got = plan(
            WhatAmI::Client,
            &["tcp/192.0.2.1:7447#iface=eth0"],
            &[],
            NO_SCOUT,
        )
        .device_requires();
        assert_eq!(got.requires, ["entropy", "sockets-tcp", "threads"]);
        assert_eq!(got.may_require, Some(vec!["interface-list"]));
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
