// SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! R311fg — facade-subset behavioural e2e: pubsub-only.
//!
//! The sibling test `wz_publisher_to_zsub.rs` drives the FULL
//! preset-ap-client `wz-ap-demo` binary against zenoh-pico's z_sub.
//! This one drives `wz-e2e-pubsub` — a binary whose facade dependency
//! pins EXACTLY the pubsub-only coherent subset (no query / declare /
//! liveliness). It proves the pub/sub data plane interoperates on the
//! wire with a foreign implementation when compiled in isolation, the
//! behavioural counterpart of the C4b `pubsub-only` BUILD subset.
//!
//! Mechanically identical flow to `wz_publisher_to_zsub.rs`: an
//! acceptor emits a literal-keyexpr Put burst to a z_sub client
//! subscriber; only the binary under test differs. See that file's
//! module doc for the per-step rationale (port reservation,
//! line-buffered z_sub stdout, two-stage substring wait,
//! captured-output-on-failure).

use std::process::{Command, Stdio};
use std::time::Duration;

use wz_integration_tests::common::{
    read_captured, wait_for_substring, wz_e2e_pubsub_binary, zenoh_pico_cli_binary, ChildGuard,
    PortReservation, Z_SUB_INIT_TIMEOUT,
};

#[test]
#[ignore = "binary-dep e2e (wz-e2e-pubsub + zenoh-pico CLI); Layer E2 runs via --ignored"]
fn wz_e2e_pubsub_round_trip_against_zenoh_pico_z_sub() {
    let bin = wz_e2e_pubsub_binary();
    let z_sub = zenoh_pico_cli_binary("z_sub");
    let port_res = PortReservation::pick();
    let port = port_res.port();
    let listen_addr = format!("127.0.0.1:{port}");
    let endpoint = format!("tcp/{listen_addr}");
    let publish_key = "demo/test";
    let sub_key = "demo/**";
    let publish_value = "hello-from-wz-subset";

    // ── wz-e2e-pubsub (acceptor + publisher) ─────────────────
    let bin_stderr = tempfile::tempfile().expect("tempfile for binary stderr");
    let bin_stderr_writer = bin_stderr.try_clone().expect("dup binary stderr handle");
    let mut bin_stderr_reader = bin_stderr;

    let mut bin_child = ChildGuard::wrap(
        "wz-e2e-pubsub (--listen --publish)",
        Command::new(&bin)
            .arg("--listen")
            .arg(&listen_addr)
            .arg("--publish")
            .arg(publish_key)
            .arg("--value")
            .arg(publish_value)
            .env("RUST_LOG", "info")
            .stdout(Stdio::null())
            .stderr(Stdio::from(bin_stderr_writer))
            .spawn()
            .expect("spawn wz-e2e-pubsub"),
    );

    let bound = wait_for_substring(
        &mut bin_stderr_reader,
        "listening on",
        Duration::from_secs(5),
    );
    if let Err(captured) = &bound {
        let _ = bin_child.child_mut().kill();
        let _ = bin_child.child_mut().wait();
        panic!(
            "wz-e2e-pubsub did not log 'listening on' within 5s\n\
             --- captured stderr ---\n{captured}"
        );
    }
    drop(port_res);

    // ── z_sub (client + subscriber) ──────────────────────────
    let z_sub_stdout = tempfile::tempfile().expect("tempfile for z_sub stdout");
    let z_sub_stdout_writer = z_sub_stdout.try_clone().expect("dup z_sub stdout handle");
    let mut z_sub_stdout_reader = z_sub_stdout;

    let mut z_sub_child = ChildGuard::wrap(
        "z_sub client (zenoh-pico)",
        Command::new("stdbuf")
            .args(["-oL", "-eL"])
            .arg(&z_sub)
            .args(["-k", sub_key, "-e", &endpoint, "-m", "client"])
            .stdout(Stdio::from(z_sub_stdout_writer))
            .stderr(Stdio::inherit())
            .spawn()
            .expect("spawn z_sub via stdbuf"),
    );

    let session_opening = wait_for_substring(
        &mut z_sub_stdout_reader,
        "Opening session",
        Z_SUB_INIT_TIMEOUT,
    );
    let received_substr = ">> [Subscriber] Received";
    let received = wait_for_substring(
        &mut z_sub_stdout_reader,
        received_substr,
        Duration::from_secs(10),
    );

    let _ = z_sub_child.child_mut().kill();
    let _ = z_sub_child.child_mut().wait();
    let _ = bin_child.child_mut().kill();
    let _ = bin_child.child_mut().wait();

    let bin_captured = read_captured(&mut bin_stderr_reader);
    let z_sub_captured = read_captured(&mut z_sub_stdout_reader);
    eprintln!("--- captured wz-e2e-pubsub stderr ---\n{bin_captured}");
    eprintln!("--- captured z_sub stdout ---\n{z_sub_captured}");

    if let Err(c) = &session_opening {
        panic!(
            "z_sub did not log 'Opening session' within 10s — z_sub binary failed to \
             initialize. Captured z_sub stdout:\n{c}\n\
             --- captured wz-e2e-pubsub stderr ---\n{bin_captured}"
        );
    }

    let received_text = match received {
        Ok(c) => c,
        Err(c) => panic!(
            "z_sub did not log '{received_substr}' within 10s — wz-e2e-pubsub Push did not \
             reach z_sub's subscriber callback.\n\
             --- captured z_sub stdout at deadline ---\n{c}\n\
             --- captured wz-e2e-pubsub stderr at deadline ---\n{bin_captured}"
        ),
    };

    assert!(
        received_text.contains(publish_key),
        "z_sub captured the 'Received' line but the publish keyexpr '{publish_key}' is missing.\n\
         --- captured z_sub stdout ---\n{received_text}"
    );
    assert!(
        received_text.contains(publish_value),
        "z_sub captured the 'Received' line but the publish value '{publish_value}' is missing.\n\
         --- captured z_sub stdout ---\n{received_text}"
    );
}
