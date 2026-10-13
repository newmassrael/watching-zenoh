// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! A `--config` file ALONE hosts the storage it declares and binds the endpoint it
//! names.
//!
//! `wz-ap-demo` hosts a storage in exactly one run-mode, `--storage-host`, and
//! until now a file could not select it: `mode` picks `--peer`, `--router-hat` or
//! `--connect`, so a document whose `plugins` section declared a storage started a
//! peer that hosted nothing and reported the section "read but not applied", and a
//! query for the storage got no reply. Typing `--storage-host` beside the file
//! hosted the storage but made the file's `listen/endpoints` yield to the command
//! line. A peer-mode document that declares a storage now selects the host and
//! gives it its one listen endpoint.
//!
//! What the unit tests of the expansion cannot show, and this does: that the run
//! the file selects really binds the file's port, that its storage really serves
//! (a value put on the first session is read back by a LATER session), and that
//! the node's own report says the two keys were applied.
//!
//! Both clients are `wz-ap-demo` too, so this is wz against wz; the pico client
//! the same startup is read with is `wz_storage_host_plugins_section_pico`, in
//! the same lane.
//!
//! The first accepted session applies the section (a storage is declared on a
//! session), and the storage it starts captures what that session carries, so the
//! PUBLISHER is the first session here. The host serves its sessions in turn,
//! which is why the reader comes after the publisher has gone.

use std::io::Write as _;
use std::process::{Command, Stdio};
use std::time::Duration;

use wz_integration_tests::bounded::BoundedChild as _;
use wz_integration_tests::common::{
    assert_demo_binary_newer_than_sources, read_captured, wait_for_substring, wz_ap_demo_binary,
    ChildGuard, PortReservation,
};

/// How long the publisher holds its put after the session opens: the demo
/// otherwise sends the instant it is Established, which can precede the host
/// applying the section it was started on.
const PUBLISH_HOLD_MS: &str = "1500";

// Both ends are wz's own binary, so this file claims no foreign proof; the
// foreign twin of this claim is
// wz_storage_host_plugins_section_from_a_config_file_serves_via_pico, which
// reads the same startup with a stock pico client and still passes `--storage-host`.
#[test]
#[ignore = "binary-dep e2e (wz-ap-demo --features adminspace-config-hotreload,zenoh-config); Layer E6h runs via --ignored"]
fn wz_storage_host_from_a_config_file_alone_hosts_its_storage_and_applies_its_listen_endpoint() {
    let demo = wz_ap_demo_binary();
    assert_demo_binary_newer_than_sources(&demo);
    let port_res = PortReservation::pick();
    let port = port_res.port();
    let addr = format!("127.0.0.1:{port}");

    // An operator's file, as a zenohd would be given it: a peer that listens on
    // one endpoint and declares one storage. No run-mode flag anywhere.
    let mut file = tempfile::Builder::new()
        .suffix(".json5")
        .tempfile()
        .expect("config tempfile");
    write!(
        file,
        r#"{{ mode: "peer",
              listen: {{ endpoints: ["tcp/{addr}"] }},
              plugins: {{ storage_manager: {{ storages: {{
                boot: {{ key_expr: "boot/**", volume: "memory" }} }} }} }} }}"#
    )
    .expect("write config");
    file.flush().expect("flush config");

    let h_stderr = tempfile::tempfile().expect("tempfile for the host's stderr");
    let h_writer = h_stderr.try_clone().expect("dup the host's stderr handle");
    let mut h_reader = h_stderr;
    let mut host = ChildGuard::wrap(
        "wz-ap-demo --config <file> (nothing else)",
        Command::new(&demo)
            .arg("--config")
            .arg(file.path())
            .env("RUST_LOG", "info")
            .stdout(Stdio::null())
            .stderr(Stdio::from(h_writer))
            .spawn()
            .expect("spawn wz-ap-demo on a config file"),
    );
    let ready = match wait_for_substring(
        &mut h_reader,
        "adminspace config GET at ",
        Duration::from_secs(10),
    ) {
        Ok(captured) => captured,
        Err(captured) => {
            let _ = host.child_mut().kill();
            let _ = host.child_mut().wait_bounded();
            panic!(
                "the file alone never started a storage host within 10s (is the demo built \
                 with --features adminspace-config-hotreload,zenoh-config?)\n--- host ---\n{captured}"
            );
        }
    };
    drop(port_res);

    // The endpoint came out of the file and nowhere else: the host says it is
    // listening on THIS port.
    assert!(
        ready.contains(&format!("storage-host: listening on {addr}")),
        "the host is not listening where the file said\n--- host ---\n{ready}"
    );
    // And the node's own account agrees: the two keys were applied, and the
    // storage section is no longer in the not-applied list.
    let applied = ready
        .lines()
        .find(|l| l.contains("APPLIED [") && !l.contains("NOT APPLIED"))
        .unwrap_or_else(|| panic!("no APPLIED line in the host's report\n--- host ---\n{ready}"));
    for key in ["\"plugins\"", "\"listen/endpoints\"", "\"mode\""] {
        assert!(
            applied.contains(key),
            "{key} is not reported applied\n{applied}"
        );
    }
    for line in ready.lines().filter(|l| l.contains("READ BUT NOT APPLIED")) {
        assert!(
            !line.contains("plugins"),
            "plugins is still reported unapplied\n{line}"
        );
    }

    // The first session is the publisher's: the section is applied on it, and the
    // storage it starts captures the put that session carries.
    let mut publisher = ChildGuard::wrap(
        "wz-ap-demo publisher",
        Command::new(&demo)
            .args(["--connect", &addr])
            .args(["--publish", "boot/a", "--value", "stored-at-boot"])
            .args(["--publish-after-ms", PUBLISH_HOLD_MS])
            .env("RUST_LOG", "info")
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn the publisher"),
    );
    if let Err(captured) = wait_for_substring(
        &mut h_reader,
        "plugins config key plugins written from --plugins — storage_manager plugin running",
        Duration::from_secs(15),
    ) {
        let _ = host.child_mut().kill();
        let _ = host.child_mut().wait_bounded();
        panic!("the host never applied the file's storage section\n--- host ---\n{captured}");
    }
    // Let the held put leave and the session end before the reader dials: the
    // host serves its sessions in turn.
    std::thread::sleep(Duration::from_millis(3500));
    let _ = publisher.child_mut().kill();
    let _ = publisher.child_mut().wait_bounded();

    // A LATER session reads the stored value back after the publisher is gone.
    // Bounded convergence on an observable (the reply), never a fixed wait.
    let mut last = String::new();
    let mut read_back = false;
    for _ in 0..5 {
        let r_stderr = tempfile::tempfile().expect("tempfile for the reader's stderr");
        let r_writer = r_stderr
            .try_clone()
            .expect("dup the reader's stderr handle");
        let mut r_reader = r_stderr;
        let mut reader = ChildGuard::wrap(
            "wz-ap-demo reader",
            Command::new(&demo)
                .args(["--connect", &addr])
                .args(["--query", "boot/a", "--on-query-reply-log"])
                .env("RUST_LOG", "info")
                .stdout(Stdio::null())
                .stderr(Stdio::from(r_writer))
                .spawn()
                .expect("spawn the reader"),
        );
        let reply = wait_for_substring(&mut r_reader, "REPLY RECEIVED", Duration::from_secs(8));
        let _ = reader.child_mut().kill();
        let _ = reader.child_mut().wait_bounded();
        last = match reply {
            Ok(captured) | Err(captured) => captured,
        };
        if last.contains("REPLY RECEIVED") && last.contains("stored-at-boot") {
            read_back = true;
            break;
        }
    }
    let host_log = read_captured(&mut h_reader);
    let _ = host.child_mut().kill();
    let _ = host.child_mut().wait_bounded();
    assert!(
        read_back,
        "the storage the file declared did not serve the value the first session put\n\
         --- reader ---\n{last}\n--- host ---\n{host_log}"
    );
}
