// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! `timestamping/drop_future_timestamp` read from a `--config` FILE: the same
//! relay topology `wz_router_hlc_stamp_to_pico_zsub.rs` drives with the
//! `--drop-future-timestamp` flag, with the key stated in a stock zenoh
//! document instead.
//!
//! ## What this adds over the flag-level legs
//!
//! The flag legs prove the router's drop arm from a typed word on argv. The step
//! from a document to that word is `expand_stock_zenoh_config`, covered by unit
//! tests that compare argv text and never start a node. A file whose key
//! expanded to the wrong flag, or to none, would keep every one of those green.
//! These legs spawn the shipped binary on the file and read a FOREIGN
//! subscriber's stdout, so the whole path from document to wire is inside the
//! assertion.
//!
//! ## Why the controls are attributable
//!
//! Every leg runs ONE topology (`--router-hat` typed on argv, a foreign-linked
//! oracle publishing a Put 10 s ahead of the router's clock, a pico subscriber)
//! and varies only the document. The controls pass a file too -- one that names
//! `timestamping` without the drop key, and one that states the key as
//! `false` -- so the file-reading path is exercised in every leg and only the
//! key's value differs. A router that ignored the file would deliver in all
//! three and fail the DROP leg alone.
//!
//! Requires: wz-ap-demo built with `--features router-hat-router,time-hlc,zenoh-config`,
//! the zenoh-pico CLI and the `oracles/future-stamp` binary. The test fns carry
//! the `wz_router_hat_` prefix so the default Layer E sweep's `--skip wz_router`
//! excludes them from the arbitrary-feature binary run.
//!
//! The foreign decoder only witnesses the router's decision; the document ->
//! flag step is wz's own, so these legs claim no atom and say so. The flag-level
//! file carries the proof rows for the wire behaviour.

use std::io::Write;
use std::process::{Command, Stdio};
use std::time::Duration;

use wz_integration_tests::common::{
    assert_demo_binary_newer_than_sources, graceful_terminate, read_captured,
    spawn_on_ephemeral_port, spawn_subscribed_zsub, wait_for_substring, wz_ap_demo_binary,
    wz_zenoh_oracle_binary, zenoh_pico_cli_binary, ChildGuard,
};

const TIMESTAMP_WITNESS: &str = "with timestamp:";
const RECEIVED_WITNESS: &str = ">> [Subscriber] Received";
const PUBLISH_KEY: &str = "demo/hlc";
const SUB_KEY: &str = "demo/**";
const PUBLISH_VALUE: &str = "bare-put-stamped-by-wz-router";

/// Far enough past uhlc's 500 ms drift bound that the router is on the
/// rejected-timestamp arm, which is the only arm the drop knob reaches.
const FUTURE_OFFSET_MS: i64 = 10_000;

/// The document: names `timestamping` and not the drop key.
const DOC_WITHOUT_THE_KEY: &str = "{ timestamping: { enabled: true } }";
/// The document: states the key at upstream's shipped default.
const DOC_DROP_FALSE: &str = "{ timestamping: { drop_future_timestamp: false } }";
/// The document: states the key as the drop arm.
const DOC_DROP_TRUE: &str = "{ timestamping: { drop_future_timestamp: true } }";

struct RelayOutcome {
    pico_stdout: String,
    router_stderr: String,
    saw_sample: bool,
    publisher_stdout: String,
}

/// Drive publisher -> `--router-hat --config <file>` -> pico subscriber once.
fn relay_a_future_stamped_put_with_document(document: &str) -> RelayOutcome {
    let demo = wz_ap_demo_binary();
    assert_demo_binary_newer_than_sources(&demo);
    let z_sub = zenoh_pico_cli_binary("z_sub_attachment");

    let mut file = tempfile::Builder::new()
        .suffix(".json5")
        .tempfile()
        .expect("config tempfile");
    file.write_all(document.as_bytes()).expect("write config");
    file.flush().expect("flush config");
    let config_path = file.path().to_str().expect("utf-8 config path").to_string();

    let router_argv: Vec<&str> = vec![
        "--router-hat",
        "127.0.0.1:0",
        "--config",
        config_path.as_str(),
    ];
    let router_stderr = tempfile::tempfile().expect("tempfile for router stderr");
    let (mut r_guard, mut r_reader, port) = spawn_on_ephemeral_port(
        &demo,
        &router_argv,
        "router-hat: listening on 127.0.0.1:",
        "router-hat",
        router_stderr,
    );
    let endpoint = format!("tcp/127.0.0.1:{port}");

    let (mut z_sub_child, mut z_sub_reader) =
        spawn_subscribed_zsub(&z_sub, SUB_KEY, &endpoint, "the wz router-hat", || {
            tempfile::tempfile().expect("tempfile for z_sub_attachment stdout")
        });

    wait_for_substring(
        &mut r_reader,
        "router-hat: learned a client sub",
        Duration::from_secs(10),
    )
    .unwrap_or_else(|c| {
        let _ = z_sub_child.child_mut().kill();
        let _ = z_sub_child.child_mut().wait();
        let _ = r_guard.child_mut().kill();
        let _ = r_guard.child_mut().wait();
        panic!(
            "router-hat never logged it learned the pico client subscription within \
             10s\n--- router-hat stderr ---\n{c}"
        )
    });

    let pub_stderr = tempfile::tempfile().expect("tempfile for publisher output");
    let pub_writer = pub_stderr.try_clone().expect("dup publisher output handle");
    let mut pub_reader = pub_stderr;
    let mut pub_child = ChildGuard::wrap(
        format!("wz-oracle-future-stamp (offset_ms={FUTURE_OFFSET_MS} -> wz router-hat)"),
        Command::new("stdbuf")
            .args(["-oL", "-eL"])
            .arg(wz_zenoh_oracle_binary("future-stamp"))
            .args([
                "--endpoint",
                &endpoint,
                "--key",
                PUBLISH_KEY,
                "--value",
                PUBLISH_VALUE,
                "--offset-ms",
                &FUTURE_OFFSET_MS.to_string(),
            ])
            .stdout(Stdio::from(
                pub_writer.try_clone().expect("dup oracle stdout handle"),
            ))
            .stderr(Stdio::from(pub_writer))
            .spawn()
            .expect("spawn wz-oracle-future-stamp via stdbuf"),
    );

    let received = wait_for_substring(&mut z_sub_reader, RECEIVED_WITNESS, Duration::from_secs(15));

    let _ = pub_child.child_mut().kill();
    let _ = pub_child.child_mut().wait();
    let _ = z_sub_child.child_mut().kill();
    let _ = z_sub_child.child_mut().wait();
    graceful_terminate(r_guard.child_mut(), Duration::from_secs(5));

    let router_stderr = read_captured(&mut r_reader);
    let pub_captured = read_captured(&mut pub_reader);
    let pico_stdout = read_captured(&mut z_sub_reader);
    eprintln!("--- router-hat stderr ---\n{router_stderr}");
    eprintln!("--- oracle publisher output ---\n{pub_captured}");
    eprintln!("--- pico z_sub_attachment stdout ---\n{pico_stdout}");

    RelayOutcome {
        saw_sample: received.is_ok(),
        pico_stdout,
        router_stderr,
        publisher_stdout: pub_captured,
    }
}

/// First run of decimal digits after `needle`, as a u64.
fn parse_ntp64(haystack: &str, needle: &str) -> Option<u64> {
    let tail = haystack.split(needle).nth(1)?;
    let digits: String = tail
        .chars()
        .skip_while(|c| c.is_whitespace())
        .take_while(|c| c.is_ascii_digit())
        .collect();
    digits.parse().ok()
}

/// A control must have delivered the Put re-stamped to a time behind the
/// rejected one: that is the arm a document that does not drop must reach.
fn assert_delivered_and_restamped(outcome: &RelayOutcome, document: &str) {
    assert!(
        outcome.saw_sample,
        "pico z_sub_attachment never logged '{RECEIVED_WITNESS}' within 15s on a router \
         given the document {document} -- that document does not ask for a drop, and the \
         same topology re-stamps and delivers, so the control is void\n--- pico stdout \
         ---\n{}\n--- publisher ---\n{}\n--- router-hat stderr ---\n{}",
        outcome.pico_stdout, outcome.publisher_stdout, outcome.router_stderr
    );
    let sent = parse_ntp64(
        &outcome.publisher_stdout,
        "future-stamp: sending timestamp ntp64=",
    )
    .unwrap_or_else(|| {
        panic!(
            "the oracle never printed the timestamp it sent\n--- publisher ---\n{}",
            outcome.publisher_stdout
        )
    });
    assert!(
        outcome.pico_stdout.contains(TIMESTAMP_WITNESS),
        "the delivered Put carried no timestamp\n--- pico stdout ---\n{}",
        outcome.pico_stdout
    );
    let received = parse_ntp64(&outcome.pico_stdout, TIMESTAMP_WITNESS).unwrap_or_else(|| {
        panic!(
            "pico printed no parsable '{TIMESTAMP_WITNESS}' value\n--- pico stdout ---\n{}",
            outcome.pico_stdout
        )
    });
    assert!(
        received < sent,
        "a timestamp 10s ahead is beyond uhlc's drift bound, so the router re-stamps it \
         with its own now; pico received {received}, not behind the {sent} the oracle \
         sent\n--- publisher ---\n{}\n--- pico stdout ---\n{}",
        outcome.publisher_stdout,
        outcome.pico_stdout
    );
}

/// The DROP arm, from a document: `timestamping: { drop_future_timestamp: true }`
/// in a `--config` file makes the router deliver NOTHING for a Put whose
/// timestamp uhlc rejects.
///
/// Its controls are the two legs below, on the same topology with a document
/// that does not state the drop.
// wz-proves: none -- the DOCUMENT -> flag half of a flag-level proof that lives in
// wz_router_hlc_stamp_to_pico_zsub.rs; the foreign subscriber only reads the router's
// decision, so no atom is witnessed beyond what that file already claims.
#[test]
#[ignore = "binary-dep e2e (wz-ap-demo --features router-hat-router,time-hlc,zenoh-config + oracles/future-stamp + zenoh-pico z_sub_attachment); Layer E8t runs via --ignored"]
fn wz_router_hat_given_a_config_file_that_drops_future_timestamps_delivers_nothing() {
    let outcome = relay_a_future_stamped_put_with_document(DOC_DROP_TRUE);

    assert!(
        outcome
            .router_stderr
            .contains("\"--drop-future-timestamp\""),
        "the router's own report of the expansion does not name \
         `--drop-future-timestamp`, so the file never reached the flag and the silence \
         below would not be about the key\n--- router-hat stderr ---\n{}",
        outcome.router_stderr
    );
    assert!(
        !outcome.saw_sample,
        "a router whose --config file says `drop_future_timestamp: true` DELIVERED a Put \
         whose timestamp is 10s ahead; the sibling legs show the same Put arriving \
         re-stamped when the document does not state the key, so the topology works and \
         the file's key did not take effect\n--- pico stdout ---\n{}\n--- publisher \
         ---\n{}\n--- router-hat stderr ---\n{}",
        outcome.pico_stdout, outcome.publisher_stdout, outcome.router_stderr
    );
    assert!(
        outcome.publisher_stdout.contains("future-stamp: put done"),
        "the oracle never completed its Put, so nothing was offered to the router and \
         its silence proves nothing\n--- publisher ---\n{}",
        outcome.publisher_stdout
    );
}

/// CONTROL, key absent: a `--config` file that names `timestamping` and not the
/// drop key leaves the router on the REPLACE arm.
// wz-proves: none -- the key-absent control of the drop leg above; it asserts the
// router's existing re-stamp arm, which the flag-level file already witnesses.
#[test]
#[ignore = "binary-dep e2e (wz-ap-demo --features router-hat-router,time-hlc,zenoh-config + oracles/future-stamp + zenoh-pico z_sub_attachment); Layer E8t runs via --ignored"]
fn wz_router_hat_given_a_config_file_without_the_drop_key_restamps_a_future_timestamp() {
    let outcome = relay_a_future_stamped_put_with_document(DOC_WITHOUT_THE_KEY);
    assert_delivered_and_restamped(&outcome, DOC_WITHOUT_THE_KEY);
}

/// CONTROL, key stated as `false`: upstream's shipped default is the behaviour
/// the node already has, so the file must not change the outcome either.
// wz-proves: none -- the stated-default control of the drop leg above; it asserts the
// router's existing re-stamp arm, which the flag-level file already witnesses.
#[test]
#[ignore = "binary-dep e2e (wz-ap-demo --features router-hat-router,time-hlc,zenoh-config + oracles/future-stamp + zenoh-pico z_sub_attachment); Layer E8t runs via --ignored"]
fn wz_router_hat_given_a_config_file_stating_drop_false_restamps_a_future_timestamp() {
    let outcome = relay_a_future_stamped_put_with_document(DOC_DROP_FALSE);
    assert_delivered_and_restamped(&outcome, DOC_DROP_FALSE);
}
