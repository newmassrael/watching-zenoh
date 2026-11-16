// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! Open-debt item 902 -- a group session in a `wz-ap-demo` PROCESS rides out the removal of the
//! interface it is joined on, and the interface coming back, the way a hot-unplugged device is
//! unplugged and plugged in again.
//!
//! The pieces have their own witnesses: `wz_datagram_carrier_loss_netns` shows a group link is
//! lost at its next failed write once its interface is gone, and the paused-time tests of
//! `serve_group` show the re-join schedule over an in-memory bus. Nothing showed the whole
//! sequence in one process over a real device: the link lost, a re-join REFUSED while the
//! interface is absent, the re-join taken once it is back, and a member admitted over the
//! re-joined link.
//!
//! # The sequence, each step asserted in order on the subject's own lines
//!
//! 1. `READY peer multicast joined` -- the subject joined on the veth host end (`#iface=` its
//!    address).
//! 2. `peer arrived b2b2` -- a member in the namespace is admitted, so the link carried a group
//!    before anything was removed.
//! 3. The host end is removed. `link lost (` -- the next write failed and the session reported
//!    it rather than ending.
//! 4. `re-join failed (` -- the first re-join is refused while the interface is absent. Without
//!    this step a re-join that silently bound the default interface would pass the steps after.
//! 5. The pair is re-attached (`NetnsPair::reattach`). `rejoined ` -- the retry binds the
//!    interface that is back.
//! 6. `peer arrived c3c3` -- a member started only now, so its arrival can have come over
//!    nothing but the re-joined link.
//!
//! The subject never prints `ended (`: a group session re-joins rather than ending.

use std::fs::File;
use std::io::{BufRead, BufReader};
use std::net::Ipv4Addr;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::mpsc::{self, Receiver, RecvTimeoutError};
use std::time::{Duration, Instant};

use wz_integration_tests::common::{
    assert_demo_binary_newer_than_sources, graceful_terminate, read_captured, wz_ap_demo_binary,
    ChildGuard, NetnsPair,
};

/// An organization-local group no other lane, test or zenoh default binds.
const GROUP: Ipv4Addr = Ipv4Addr::new(239, 255, 73, 61);
/// A port no other multicast lane binds.
const PORT: u16 = 17493;
const HOST_CIDR: &str = "10.251.21.1/30";
const PEER_CIDR: &str = "10.251.21.2/30";
const HOST_ADDR: &str = "10.251.21.1";
const PEER_ADDR: &str = "10.251.21.2";
/// Each step's bound. The slowest is the re-join after the re-attach: the schedule is
/// 1000 ms, then 2000 ms, then 4000 ms, so the retry that sees the interface back comes
/// within 7 s of the loss.
const STEP_WITHIN: Duration = Duration::from_secs(20);
/// Every line the subject prints for its one session starts with this.
const SUBJECT: &str = "wz-ap-demo session group: ";

/// A `--sessions` document of one group session joined on the interface holding `iface_addr`.
fn group_document(dir: &Path, file: &str, zid: &str, iface_addr: &str) -> PathBuf {
    let doc = dir.join(file);
    std::fs::write(
        &doc,
        format!(
            r#"{{
                sessions: [
                    {{ name: "group", mode: "peer", transport: "multicast", zid: "{zid}",
                       group: {{ endpoint: "udp/{GROUP}:{PORT}#iface={iface_addr}",
                                 join_interval_ms: 100, lease_ms: 2000 }} }},
                ],
            }}"#
        ),
    )
    .expect("the document is written");
    doc
}

/// A member of the group, running in the namespace on its end of the pair. Its output goes to
/// `log` for the failure message.
fn spawn_member(ns: &NetnsPair, demo: &Path, doc: &Path, log: &File) -> Child {
    ns.command(demo)
        .arg("--sessions")
        .arg(doc)
        .stdout(Stdio::null())
        .stderr(Stdio::from(log.try_clone().expect("dup the member log")))
        .spawn()
        .expect("spawn a group member inside the namespace")
}

/// The subject's lines, read on a thread, and the members' logs for a failure message.
struct Witness {
    rx: Receiver<String>,
    seen: Vec<String>,
    member_logs: Vec<File>,
}

impl Witness {
    /// The index of the first subject line at or after `from` that carries `needle`, waiting up
    /// to [`STEP_WITHIN`] for it. Indices are what the order of the steps is asserted on.
    fn expect(&mut self, from: usize, needle: &str) -> usize {
        let wanted = format!("{SUBJECT}{needle}");
        if let Some(at) = self.seen[from..].iter().position(|l| l.contains(&wanted)) {
            return from + at;
        }
        let until = Instant::now() + STEP_WITHIN;
        loop {
            match self
                .rx
                .recv_timeout(until.saturating_duration_since(Instant::now()))
            {
                Ok(line) => {
                    let hit = line.contains(&wanted);
                    self.seen.push(line);
                    if hit {
                        return self.seen.len() - 1;
                    }
                }
                Err(RecvTimeoutError::Timeout) => {
                    panic!("the subject never printed {wanted:?}\n{}", self.report())
                }
                Err(RecvTimeoutError::Disconnected) => {
                    panic!("the subject exited before {wanted:?}\n{}", self.report())
                }
            }
        }
    }

    fn report(&mut self) -> String {
        let mut text = format!("--- subject stderr ---\n{}", self.seen.join("\n"));
        for (n, log) in self.member_logs.iter_mut().enumerate() {
            text.push_str(&format!(
                "\n--- member {n} stderr ---\n{}",
                read_captured(log)
            ));
        }
        text
    }
}

// The subject and both members are wz: the claim is the re-join sequence of wz's own group
// session over a real device, which no foreign program can be asked to perform.
// wz-proves: none -- wz group session re-join over a removed and re-attached device, wz members only
#[test]
#[ignore = "needs a network namespace and wz-ap-demo with transport-multicast + locator-iface; Layer M runs via --ignored after probing for one"]
fn in_a_netns_a_group_session_rejoins_a_reattached_interface_and_admits_a_new_member() {
    let demo = wz_ap_demo_binary();
    assert_demo_binary_newer_than_sources(&demo);
    let ns = NetnsPair::up("grprejoin", HOST_CIDR, PEER_CIDR);
    let dir = tempfile::tempdir().expect("a directory for the documents");
    let subject_doc = group_document(dir.path(), "subject.json5", "a1a1", HOST_ADDR);
    let first_doc = group_document(dir.path(), "first.json5", "b2b2", PEER_ADDR);
    let second_doc = group_document(dir.path(), "second.json5", "c3c3", PEER_ADDR);

    let mut subject = ChildGuard::wrap(
        "wz-ap-demo group session on the veth host end",
        Command::new(&demo)
            .arg("--sessions")
            .arg(&subject_doc)
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .spawn()
            .expect("the subject demo runs"),
    );
    let stderr = subject.child_mut().stderr.take().expect("stderr was piped");
    let (tx, rx) = mpsc::channel();
    std::thread::spawn(move || {
        for line in BufReader::new(stderr).lines().map_while(Result::ok) {
            if tx.send(line).is_err() {
                return;
            }
        }
    });
    let mut witness = Witness {
        rx,
        seen: Vec::new(),
        member_logs: vec![
            tempfile::tempfile().expect("first member log"),
            tempfile::tempfile().expect("second member log"),
        ],
    };

    let ready = witness.expect(0, "READY peer multicast joined");
    let mut members = vec![spawn_member(
        &ns,
        &demo,
        &first_doc,
        &witness.member_logs[0],
    )];
    let first_arrived = witness.expect(ready + 1, "peer arrived b2b2");

    ns.detach();
    let lost = witness.expect(first_arrived + 1, "link lost (");
    let refused = witness.expect(lost + 1, "re-join failed (");

    ns.reattach();
    let rejoined = witness.expect(refused + 1, "rejoined ");
    members.push(spawn_member(
        &ns,
        &demo,
        &second_doc,
        &witness.member_logs[1],
    ));
    witness.expect(rejoined + 1, "peer arrived c3c3");

    let ended = format!("{SUBJECT}ended (");
    assert!(
        !witness.seen.iter().any(|l| l.contains(&ended)),
        "a group session re-joins a lost link rather than ending\n{}",
        witness.report()
    );

    graceful_terminate(subject.child_mut(), Duration::from_secs(5));
    ns.kill_inside();
    for member in &mut members {
        let _ = member.wait();
    }
}
