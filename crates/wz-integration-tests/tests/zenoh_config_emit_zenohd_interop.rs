// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! R311y579 (G8) — the emitted config, judged by a REAL zenohd 1.5.0.
//!
//! [`wz_runtime_tokio::zenoh_config`] renders a stock-zenoh JSON5 config and
//! validates a topology before anything is started. Both halves are claims
//! ABOUT ZENOH, and neither can be settled inside wz: a unit test proves the
//! emitter produced the string the emitter meant to produce, which is
//! self-consistency and nothing more. What matters is whether zenoh reads it
//! the way wz intended.
//!
//! Two legs, and the second is what keeps the first honest:
//!
//! 1. [`zenohd_reports_back_every_value_the_emitted_config_carried`] — zenohd
//!    is started on an emitted config and NOTHING else, and its own
//!    `Initial conf:` line (the config AFTER zenoh's parser has resolved it)
//!    must carry every value wz emitted. This is the discriminating form: a
//!    key emitted at the WRONG path is not a parse error in zenoh, it is
//!    silently ignored, and the resolved line then shows zenoh's DEFAULT
//!    where wz's value should be. Asserting the values (rather than "zenohd
//!    started") is what separates "wz emitted valid JSON" from "wz emitted
//!    the config it meant".
//! 2. [`zenohd_refuses_every_config_the_validator_rejects`] — for each defect
//!    the validator reports, the same zenohd handed that config REFUSES TO
//!    RUN. Without this leg the validator's rules would be wz's opinion about
//!    zenoh; with it they are zenoh's own behaviour, measured. Both cases were
//!    established by running zenohd before the rules were written, not
//!    afterwards: the protocol case exits with "Unicast not supported for
//!    <proto> protocol" and the qos/lowlatency case with "'qos' and
//!    'lowlatency' options are incompatible".
//!
//! `#[ignore]` (binary-dep e2e): needs `target/zenohd/zenohd` (set
//! `WZ_ZENOHD_BIN` or run `scripts/build-zenohd.sh`). Run via Layer Z /
//! `--ignored`.

use std::fs::File;
use std::io::Write;
use std::process::{Command, Stdio};
use std::time::Duration;

use tempfile::NamedTempFile;

use wz_codecs::whatami::WhatAmI;
use wz_integration_tests::common::{
    read_captured, wait_for_exit, wait_for_substring, wait_for_tcp_accept_alive, zenohd_binary,
    ChildGuard, PortReservation, ZENOHD_TCP_ACCEPT_BUDGET,
};
use wz_runtime_tokio::zenoh_config::{
    validate_topology, ConfigDefect, TopologyDefect, ZenohNodeConfig,
};

/// zenohd prints its resolved config on this line before doing anything else.
const RESOLVED_CONF_MARKER: &str = "Initial conf:";

/// How long to wait for zenohd to either print its resolved config or exit.
const STARTUP_BUDGET: Duration = Duration::from_secs(30);

/// Write `json5` to a tempfile zenohd can read. The handle is returned because
/// dropping it deletes the file out from under the process.
///
/// The `.json5` SUFFIX is load-bearing, not cosmetic: zenoh dispatches its
/// config parser on the file EXTENSION and panics on a file without one
/// ("Configuration files must have an extension (.json, .json5 and .yaml
/// supported)", commons/zenoh-config/src/lib.rs:1286). An extensionless
/// tempfile is rejected before a single byte of the config is read, which is
/// how this harness first failed.
fn staged_config(json5: &str) -> NamedTempFile {
    let mut file = tempfile::Builder::new()
        .suffix(".json5")
        .tempfile()
        .expect("config tempfile");
    file.write_all(json5.as_bytes()).expect("write config");
    file.flush().expect("flush config");
    file
}

/// Spawn zenohd on `config_path` and NOTHING else — no `-l`, no `--cfg`, no
/// `--no-multicast-scouting`. The config file is the sole input, which is the
/// whole claim under test; a CLI flag alongside it would leave open which of
/// the two zenohd actually obeyed. Only `--rest-http-port none` is passed,
/// because the REST plugin binds a fixed default port and two concurrent
/// zenohds would collide on it for reasons unrelated to the config.
fn spawn_on_config(label: &'static str, config_path: &std::path::Path) -> (ChildGuard, File) {
    // BOTH streams land in ONE capture file: zenohd prints the resolved config
    // on stdout and its refusal on stderr, and a test that has to know which
    // stream a line came from would be asserting on zenohd's logging layout
    // rather than on its config handling.
    let capture = tempfile::tempfile().expect("tempfile for zenohd output");
    let out = capture.try_clone().expect("dup zenohd stdout handle");
    let err = capture.try_clone().expect("dup zenohd stderr handle");
    let mut command = Command::new(zenohd_binary());
    command
        .arg("-c")
        .arg(config_path)
        .arg("--rest-http-port")
        .arg("none")
        .stdout(Stdio::from(out))
        .stderr(Stdio::from(err));
    (
        ChildGuard::wrap(label, command.spawn().expect("spawn zenohd")),
        capture,
    )
}

// wz-proves: none -- and the reason is a REGISTRATION gap, not an absence of
// proof. zenohd genuinely adjudicates wz here: it parses a config wz emitted and
// echoes back the values it resolved, which is exactly the foreign-witness shape
// this corpus tracks. What it cannot claim is an ATOM, because `zenoh-config-emit`
// is not in the inventory (A4-1 would reject the name), and REGISTERING it is not
// a side-effect this test may take: an atom joins `built(N)` and moves the A3/A4
// denominators that other gates pin, so it belongs to its own round with its own
// F=/P=/C= reason. Recorded rather than papered over: the day that entry lands,
// this line becomes `zenoh-config-emit wz->zenohd`.
#[test]
#[ignore = "binary-dep e2e: needs target/zenohd/zenohd (scripts/build-zenohd.sh)"]
fn zenohd_reports_back_every_value_the_emitted_config_carried() {
    let listen = PortReservation::pick();
    let port = listen.port();
    let endpoint = format!("tcp/127.0.0.1:{port}");

    // Every value here is deliberately NOT zenoh's default, so the resolved
    // line cannot agree with wz by accident. batch_size 4096 vs 65535, lease
    // 8000 vs 10000, max_links 3 vs 1, qos off vs on, compression on vs off,
    // multicast scouting off vs on, adminspace write on vs off.
    let mut config = ZenohNodeConfig::default()
        .listening_on(&endpoint)
        .with_multicast_scouting(false)
        .with_adminspace(true, true);
    config.mode = wz_codecs::whatami::WhatAmI::Router;
    config.batch_size = 4096;
    config.lease_ms = 8000;
    config.max_links = 3;
    config.qos = false;
    config.compression = true;
    config.timestamping = true;
    // R311y844 — the ten keys that round promoted, set here so the EMIT half of
    // the shared key table is adjudicated by the same zenohd that adjudicates
    // the read half. Without these rows `to_json5` could grow a branch nothing
    // upstream ever parses, which is the drift the one-table design exists to
    // prevent. Each value is away from zenoh's own resolved default (measured:
    // five resolve to null, multicast qos to false, shared memory to true).
    config.id = Some(String::from("a1b2c3d4"));
    config.namespace = Some(String::from("demo/ns"));
    config.queries_default_timeout_ms = Some(11_000);
    config.interests_timeout_ms = Some(9_000);
    config.scouting_timeout_ms = Some(2_500);
    config.multicast_qos = true;
    config.shared_memory = false;
    config.tls_root_ca = Some(String::from("/etc/wz/ca.pem"));
    config.tls_listen_certificate = Some(String::from("/etc/wz/server.pem"));
    config.tls_listen_private_key = Some(String::from("/etc/wz/server.key"));

    assert!(
        config.validate().is_empty(),
        "the fixture config is not one the validator accepts: {:?}",
        config.validate()
    );

    let json5 = config.to_json5();
    let file = staged_config(&json5);
    // The port reservation must be released before zenohd binds it.
    drop(listen);
    let (mut guard, mut capture) = spawn_on_config("zenohd (emitted config)", file.path());

    let captured = wait_for_substring(&mut capture, RESOLVED_CONF_MARKER, STARTUP_BUDGET)
        .unwrap_or_else(|e| panic!("zenohd never printed its resolved config: {e}\n{json5}"));

    // Each of these is a key wz emitted. A wrong PATH would leave zenoh's
    // default here instead, which is why the assertion is on the value and not
    // on the key's presence.
    for expected in [
        r#""mode":"router""#,
        r#""batch_size":4096"#,
        r#""lease":8000"#,
        r#""max_links":3"#,
        r#""lowlatency":false"#,
        r#""compression":{"enabled":true}"#,
        r#""adminspace":{"enabled":true,"permissions":{"read":true,"write":true}}"#,
        r#""timestamping":{"drop_future_timestamp":null,"enabled":true}"#,
        // R311y844 — the promoted ten, read back out of the same resolved line.
        r#""id":"a1b2c3d4""#,
        r#""namespace":"demo/ns""#,
        r#""queries_default_timeout":11000"#,
        r#""interests":{"timeout":9000}"#,
        r#""root_ca_certificate":"/etc/wz/ca.pem""#,
        r#""listen_certificate":"/etc/wz/server.pem""#,
        r#""listen_private_key":"/etc/wz/server.key""#,
        r#""shared_memory":{"enabled":false"#,
    ] {
        assert!(
            captured.contains(expected),
            "zenohd's resolved config does not carry {expected}\nemitted:\n{json5}\nresolved:\n{captured}"
        );
    }
    // qos and multicast-scouting appear more than once in the resolved tree
    // (unicast vs multicast; scouting vs gossip), so they are asserted against
    // the enclosing key rather than on their own.
    assert!(
        captured.contains(r#""unicast":{"accept_pending":100,"accept_timeout":10000,"compression":{"enabled":true},"lowlatency":false,"max_links":3,"max_sessions":1000,"open_timeout":10000,"qos":{"enabled":false}}"#),
        "the unicast transport block does not carry wz's values\nresolved:\n{captured}"
    );
    assert!(
        captured.contains(&format!(r#""endpoints":["{endpoint}"]"#)),
        "the listen endpoint wz emitted is not in zenohd's resolved config\nresolved:\n{captured}"
    );

    // Parsed is not applied: the endpoint must actually be bound.
    if let Err(e) = wait_for_tcp_accept_alive(guard.child_mut(), port, ZENOHD_TCP_ACCEPT_BUDGET) {
        panic!("zenohd resolved the config but never listened on {endpoint}: {e}");
    }
}

// wz-proves: none -- same registration gap as the leg above, and one more reason
// besides: this leg's subject is wz's VALIDATOR, whose judgment zenohd confirms by
// refusing to run. That is a claim about a wz-side predicate agreeing with a
// foreign program's startup behaviour, which no atom in the inventory names.
#[test]
#[ignore = "binary-dep e2e: needs target/zenohd/zenohd (scripts/build-zenohd.sh)"]
fn zenohd_refuses_every_config_the_validator_rejects() {
    // A POSITIVE CONTROL first: the same shape with the defect removed must
    // start. Without it, "zenohd exited" would be evidence about the harness
    // (a bad path, a missing binary) rather than about the defect.
    let control_port = PortReservation::pick();
    let control_endpoint = format!("tcp/127.0.0.1:{}", control_port.port());
    let control = ZenohNodeConfig::default()
        .listening_on(&control_endpoint)
        .with_multicast_scouting(false);
    assert!(control.validate().is_empty());
    let control_file = staged_config(&control.to_json5());
    let port = control_port.port();
    drop(control_port);
    let (mut control_guard, _control_capture) =
        spawn_on_config("zenohd (control)", control_file.path());
    if let Err(e) =
        wait_for_tcp_accept_alive(control_guard.child_mut(), port, ZENOHD_TCP_ACCEPT_BUDGET)
    {
        panic!("the positive control never came up, so this test can prove nothing: {e}");
    }
    drop(control_guard);

    // (label, the config, the defect the validator must report)
    let mut unknown_protocol = ZenohNodeConfig::default().with_multicast_scouting(false);
    unknown_protocol.listen = vec![String::from("carrier-pigeon/127.0.0.1:1")];
    let unknown_expected = ConfigDefect::UnknownProtocol {
        endpoint: String::from("carrier-pigeon/127.0.0.1:1"),
        protocol: String::from("carrier-pigeon"),
    };

    let qos_port = PortReservation::pick();
    let mut qos_lowlatency = ZenohNodeConfig::default()
        .listening_on(format!("tcp/127.0.0.1:{}", qos_port.port()))
        .with_multicast_scouting(false);
    qos_lowlatency.lowlatency = true;
    qos_lowlatency.qos = true;
    drop(qos_port);

    for (label, config, expected) in [
        ("unknown protocol", unknown_protocol, unknown_expected),
        (
            "qos + lowlatency",
            qos_lowlatency,
            ConfigDefect::QosWithLowlatency,
        ),
    ] {
        let defects = config.validate();
        assert!(
            defects.contains(&expected),
            "{label}: the validator did not report {expected:?}, only {defects:?}"
        );

        let json5 = config.to_json5();
        let file = staged_config(&json5);
        let (mut guard, mut capture) = spawn_on_config("zenohd (rejected config)", file.path());
        let status = wait_for_exit(guard.child_mut(), STARTUP_BUDGET).unwrap_or_else(|e| {
            panic!("{label}: zenohd kept running on a config wz calls invalid: {e}\n{json5}")
        });
        // The exit is the observable; the message is read back so the test
        // cannot pass on an unrelated crash.
        let captured = read_captured(&mut capture);
        assert!(
            captured.contains("Exiting")
                || captured.contains("incompatible")
                || captured.contains("not supported"),
            "{label}: zenohd exited ({status:?}) but not for the reason wz predicted\n{captured}"
        );
    }
}

// wz-proves: none -- the same registration gap as the legs above. The subject
// is wz's TOPOLOGY validator, and the claim is that a real zenohd refuses each
// set it rejects, which no atom in the inventory names.
//
/// R2127 (open-debt item 497) — A FOREIGN WITNESS FOR EACH TOPOLOGY VERDICT.
///
/// # What item 497 measured, and the half of it that was wrong
///
/// R2071 read upstream's `connect_peers_single_link` and found that on the
/// retry path it calls `peer_connector_retry` and returns `Ok(())` — so a node
/// with nowhere to attach retries for ever and never exits. It concluded that
/// all three topology verdicts had only a timeout NEGATIVE as their
/// observable, and that a foreign witness would need a non-default
/// `connect/retry/timeout_ms = 0` fixture to force an exit.
///
/// That is right about the branch and wrong about which nodes take it, because
/// the timeouts deciding it are MODE-DEPENDENT. Read this round at the pinned
/// rev, in `commons/zenoh-config/src/defaults.rs`:
///
///   * `connect::timeout_ms` is `{ router: -1, peer: -1, client: 0 }`, and
///     `ms_to_duration` maps a negative to `Duration::MAX` and `0` to zero. So
///     `get_global_connect_timeout()` is ZERO for a client, a client takes the
///     `is_zero()` branch, and its failed dial falls through the loop to
///     `Err`. A CLIENT already exits; the router and the peer are what retry
///     for ever.
///   * `connect::exit_on_failure` is `{ router: false, peer: false, client: true }`.
///   * `listen::timeout_ms` is `Unique(0)` and `listen::exit_on_failure` is
///     `Unique(true)` — every mode. A listen collision already exits.
///
/// So two of the three verdicts had a foreign witness at stock config all
/// along, and the third needs only a client. The non-default fixture item 497
/// proposed is not used here, and that matters beyond tidiness: a witness that
/// had to bend the config would be evidence about the bent config rather than
/// about a deployment anyone runs.
///
/// # Which node exits is the content of the test
///
///   * `ListenEndpointCollision` — the SECOND binder. The first holds the
///     address, so the set's defect is observable only once one of them is up.
///   * `DanglingConnectTarget` — the dialling client, in a set that has a
///     listener elsewhere so the verdict is this one and not `NoNodeAccepts`.
///   * `NoNodeAccepts` — the only node there is, refused with `No peer
///     specified and multicast scouting deactivated!` before any dial happens.
#[test]
#[ignore = "binary-dep e2e: needs target/zenohd/zenohd (scripts/build-zenohd.sh)"]
fn zenohd_refuses_every_topology_the_validator_rejects() {
    // THE POSITIVE CONTROL, and for a topology it has to be a real PAIR: a
    // peer that listens and a client that dials it. Without it, "the client
    // exited" below would be as well explained by "a client always exits".
    let control_port = PortReservation::pick();
    let control_endpoint = format!("tcp/127.0.0.1:{}", control_port.port());
    let listener = ZenohNodeConfig::default()
        .listening_on(&control_endpoint)
        .with_multicast_scouting(false);
    let mut dialer = ZenohNodeConfig::default()
        .connecting_to(&control_endpoint)
        .with_multicast_scouting(false);
    dialer.mode = WhatAmI::Client;
    assert!(
        validate_topology(&[listener.clone(), dialer.clone()]).is_empty(),
        "the control topology must be one the validator accepts, or it controls nothing"
    );
    let control_bind = control_port.port();
    drop(control_port);
    let listener_file = staged_config(&listener.to_json5());
    let (mut listener_guard, _listener_capture) =
        spawn_on_config("zenohd (control listener)", listener_file.path());
    if let Err(e) = wait_for_tcp_accept_alive(
        listener_guard.child_mut(),
        control_bind,
        ZENOHD_TCP_ACCEPT_BUDGET,
    ) {
        panic!("the control listener never came up, so this test can prove nothing: {e}");
    }
    let dialer_file = staged_config(&dialer.to_json5());
    let (mut dialer_guard, mut dialer_capture) =
        spawn_on_config("zenohd (control dialer)", dialer_file.path());
    if wait_for_exit(dialer_guard.child_mut(), STARTUP_BUDGET).is_ok() {
        panic!(
            "the control CLIENT exited against a listener that WAS up, so an exit \
             below would say nothing about the defect\n{}",
            read_captured(&mut dialer_capture)
        );
    }
    drop(dialer_guard);
    drop(listener_guard);

    // (a) ListenEndpointCollision — two nodes claiming one address.
    let taken = PortReservation::pick();
    let shared = format!("tcp/127.0.0.1:{}", taken.port());
    let first = ZenohNodeConfig::default()
        .listening_on(&shared)
        .with_multicast_scouting(false);
    let second = ZenohNodeConfig::default()
        .listening_on(&shared)
        .with_multicast_scouting(false);
    let shared_bind = taken.port();
    drop(taken);

    // (b) DanglingConnectTarget — a client dialling an endpoint nobody in the
    // set listens on, with a listener elsewhere so the verdict is this one
    // rather than `NoNodeAccepts`.
    let dead = PortReservation::pick();
    let dead_endpoint = format!("tcp/127.0.0.1:{}", dead.port());
    drop(dead);
    let elsewhere = PortReservation::pick();
    let elsewhere_endpoint = format!("tcp/127.0.0.1:{}", elsewhere.port());
    drop(elsewhere);
    let mut stranded = ZenohNodeConfig::default()
        .connecting_to(&dead_endpoint)
        .with_multicast_scouting(false);
    stranded.mode = WhatAmI::Client;
    let bystander = ZenohNodeConfig::default()
        .listening_on(&elsewhere_endpoint)
        .with_multicast_scouting(false);

    // (c) NoNodeAccepts — a set that is all clients.
    let mut alone = ZenohNodeConfig::default().with_multicast_scouting(false);
    alone.mode = WhatAmI::Client;

    let collision = TopologyDefect::ListenEndpointCollision {
        endpoint: shared.clone(),
        nodes: vec![String::from("0"), String::from("1")],
    };
    let dangling = TopologyDefect::DanglingConnectTarget {
        node: String::from("0"),
        endpoint: dead_endpoint.clone(),
    };

    for (label, nodes, expected, refused) in [
        (
            "listen collision",
            vec![first, second.clone()],
            collision,
            second,
        ),
        (
            "dangling connect target",
            vec![stranded.clone(), bystander],
            dangling,
            stranded,
        ),
        (
            "no node accepts",
            vec![alone.clone()],
            TopologyDefect::NoNodeAccepts,
            alone,
        ),
    ] {
        let defects = validate_topology(&nodes);
        assert!(
            defects.contains(&expected),
            "{label}: the validator did not report {expected:?}, only {defects:?}"
        );

        // The collision arm needs its FIRST binder up, because the defect is
        // that two nodes want one address and the second is refused by the
        // first holding it. Held for the whole arm.
        let held = if label == "listen collision" {
            let file = staged_config(&nodes[0].to_json5());
            let (mut guard, _capture) = spawn_on_config("zenohd (first binder)", file.path());
            if let Err(e) =
                wait_for_tcp_accept_alive(guard.child_mut(), shared_bind, ZENOHD_TCP_ACCEPT_BUDGET)
            {
                panic!("{label}: the first binder never took the address: {e}");
            }
            Some((guard, file))
        } else {
            None
        };

        let json5 = refused.to_json5();
        let file = staged_config(&json5);
        let (mut guard, mut capture) = spawn_on_config("zenohd (rejected topology)", file.path());
        let status = wait_for_exit(guard.child_mut(), STARTUP_BUDGET).unwrap_or_else(|e| {
            panic!("{label}: zenohd kept running in a topology wz calls invalid: {e}\n{json5}")
        });
        // The exit is the observable; the message is read back so an arm
        // cannot pass on an unrelated crash -- a bad path or a missing binary
        // exits too.
        let captured = read_captured(&mut capture);
        assert!(
            captured.contains("Exiting")
                || captured.contains("Unable to")
                || captured.contains("No peer specified"),
            "{label}: zenohd exited ({status:?}) but not for the reason wz predicted\n{captured}"
        );
        drop(held);
    }
}
