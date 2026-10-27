// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! `--device-requires <file>`: what a `--sessions` run of a document asks of the
//! operating system (docs/target-build-contract.md T9), one JSON object with the
//! manifest's keys.
//!
//! Each session is read into the `OpenFacts` of `wz::runtime_tokio::facilities`
//! as [`crate::sessions_run`] opens it. A dialling session tries its endpoints
//! once, in order, and fails when none opens. A listening session fails when its
//! endpoint cannot be bound, a group session when its first join fails, and a
//! session that answers Scouts when its scouting group cannot be joined, so that
//! group is one more group the session joins. A failed session is the run's
//! failure (status 1), so the run is all of its sessions
//! ([`DeviceRequires::all_of`]). The process itself reads the document and stamps
//! its log lines with the calendar time.

use wz::runtime_tokio::facilities::{device_requires, DeviceRequires, OpenFacts, Scouting};

use crate::sessions::{SessionLink, SessionSpec, SessionsPlan};

/// What a `--sessions` run of `plan` asks of the operating system.
pub(crate) fn device_requires_of(plan: &SessionsPlan) -> DeviceRequires {
    let process = device_requires(&OpenFacts {
        connect: &[],
        dial_must_succeed: true,
        listen: &[],
        groups: Vec::new(),
        bind_must_succeed: true,
        scouting: Scouting::Off,
        reads_files: true,
        reads_calendar: true,
    });
    let mut parts: Vec<DeviceRequires> = plan.sessions.iter().map(session_requires).collect();
    parts.push(process);
    DeviceRequires::all_of(&parts)
}

/// What one session of the run asks for.
fn session_requires(spec: &SessionSpec) -> DeviceRequires {
    let (connect, listen, mut groups): (&[String], &[String], Vec<String>) = match &spec.link {
        SessionLink::Connect { endpoints } => (endpoints.as_slice(), &[], Vec::new()),
        SessionLink::Listen { endpoint, .. } => (&[], std::slice::from_ref(endpoint), Vec::new()),
        SessionLink::Group { endpoint, .. } => (&[], &[], vec![endpoint.clone()]),
    };
    groups.extend(responder_group(spec));
    device_requires(&OpenFacts {
        connect,
        dial_must_succeed: true,
        listen,
        groups: groups.iter().map(String::as_str).collect(),
        bind_must_succeed: true,
        scouting: Scouting::Off,
        reads_files: false,
        reads_calendar: false,
    })
}

/// The scouting group a session answers Scouts on, as a group endpoint: the
/// responder binds and joins it with the same socket policy a group session's
/// `#iface=` selects.
#[cfg(feature = "scouting-responder")]
fn responder_group(spec: &SessionSpec) -> Option<String> {
    let socket = spec.scouting.as_ref()?;
    let (group, port) =
        socket.group_and_port(crate::runner::SCOUT_GROUP, crate::runner::SCOUT_PORT);
    Some(match socket.interface.as_deref() {
        Some(interface) => format!("udp/{group}:{port}#iface={interface}"),
        None => format!("udp/{group}:{port}"),
    })
}

/// A build without the responder refuses a session's `scouting` key
/// (`BuildCapabilities::scouting_responder`), so no session here answers Scouts.
#[cfg(not(feature = "scouting-responder"))]
fn responder_group(_spec: &SessionSpec) -> Option<String> {
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sessions::read_sessions_document;

    fn requires_of(document: &str) -> DeviceRequires {
        match read_sessions_document(document) {
            Ok(plan) => device_requires_of(&plan),
            Err(refusals) => panic!("the document was refused: {refusals:?}"),
        }
    }

    #[test]
    fn a_dialling_session_requires_what_every_target_needs_and_the_document() {
        let got = requires_of(
            r#"{ sessions: [ { name: "a", mode: "client", transport: "unicast",
                 connect: { endpoints: ["tcp/192.0.2.1:7447", "tcp/router.example:7447"] } } ] }"#,
        );
        assert_eq!(
            got.requires,
            ["entropy", "filesystem", "sockets-tcp", "threads"]
        );
        assert_eq!(
            got.may_require,
            Some(vec!["interface-list", "name-resolution", "wall-clock"])
        );
    }

    #[test]
    fn every_session_is_required_by_the_run() {
        let got = requires_of(
            r#"{ sessions: [
                 { name: "in", mode: "peer", transport: "unicast",
                   listen: { endpoints: ["tcp/127.0.0.1:0"] } },
                 { name: "group", mode: "peer", transport: "multicast",
                   group: { endpoint: "udp/224.0.0.224:7446#iface=lo" } } ] }"#,
        );
        assert_eq!(
            got.requires,
            [
                "entropy",
                "filesystem",
                "interface-list",
                "multicast",
                "sockets-tcp",
                "sockets-udp",
                "threads"
            ]
        );
        assert_eq!(got.may_require, Some(vec!["wall-clock"]));
    }

    #[cfg(feature = "scouting-responder")]
    #[test]
    fn a_session_that_answers_scouts_requires_its_scouting_group() {
        let got = requires_of(
            r#"{ sessions: [ { name: "a", mode: "peer", transport: "unicast",
                 listen: { endpoints: ["unixsock-stream//tmp/wz.sock"] },
                 scouting: { multicast: { listen: true, interface: "eth0" } } } ] }"#,
        );
        assert_eq!(
            got.requires,
            [
                "entropy",
                "filesystem",
                "interface-list",
                "multicast",
                "sockets-udp",
                "threads",
                "unix-sockets"
            ]
        );
    }
}
