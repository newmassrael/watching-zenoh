// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The three TLS material keys, read from `--config` files, shown to matter.
//!
//! `transport/link/tls/root_ca_certificate`, `listen_certificate` and
//! `listen_private_key` expand to `--tls-ca`, `--tls-cert` and `--tls-key`, and
//! the expansion unit tests say so. What they cannot say is that a node given
//! only a file handshakes TLS with another node given only a file, and that
//! removing one key from one of the files stops it. This file says both, wz
//! against wz, so it needs no zenohd: the two nodes are the same binary and the
//! only thing between them is a loopback socket.
//!
//! The acceptor is `mode: "peer"` with a `tls/` listen endpoint and the
//! certificate and key paths; the dialer is `mode: "client"` with the matching
//! `tls/` connect endpoint and the root CA path. Neither command line carries a
//! role or a certificate flag, so every bit of TLS material a node holds comes
//! out of its file. The endpoints are numeric on purpose: a numeric `tls/` dial
//! verifies the peer against the name `localhost`, which the generated
//! certificate is valid for, so one self-signed certificate is both the
//! acceptor's chain and the dialer's root.
//!
//! Each key is shown to matter by a leg that leaves it out (or breaks its
//! value) beside a leg that has it, against the same running acceptor, so a
//! failure cannot be a dead acceptor or a wrong port:
//!
//! - no `root_ca_certificate`: the dial has no trust store and refuses before a
//!   byte is sent;
//! - a `root_ca_certificate` naming a certificate the acceptor does not
//!   present: the key is read and used, and the handshake is refused;
//! - no `listen_certificate` and `listen_private_key`: the `tls/` endpoint
//!   cannot be served, so the node gives up its listen phase and exits.
//!
//! The expansion of these keys is withheld unless the endpoint is a `tls/` one
//! (the CA file is opened eagerly, so a `tcp/` node carrying a CA path would
//! otherwise fail to start); every endpoint here is `tls/`.
//!
//! Requires a `wz-ap-demo` built with `--features tls,routing-peer,zenoh-config`:
//! `tls` for the rustls links, `routing-peer` for the `mode: "peer"` run-mode a
//! file selects for a listening document, `zenoh-config` for `--config`. The
//! function names carry the `wz_peer` token so the default Layer E sweep, whose
//! binary has none of the three, does not run them.

use std::fs::File;
use std::path::Path;
use std::process::{Command, Stdio};
use std::time::Duration;

use wz_integration_tests::bounded::BoundedChild as _;
use wz_integration_tests::common::{
    assert_demo_binary_newer_than_sources, read_captured, spawn_on_ephemeral_port,
    wait_for_substring, wz_ap_demo_binary, ChildGuard,
};
use wz_runtime_tokio_test_support::localhost_cert_key_pem;

/// The acceptor's listen line; `spawn_on_ephemeral_port` reads the bound port
/// off the digits that follow it.
const PEER_LISTEN_MARKER: &str = "peer: listening on 127.0.0.1:";

/// The line a dialer logs when a candidate endpoint could not be opened.
const DIAL_REFUSED: &str = "unable to connect to";

/// The text of the refusal a dial gives when it holds no trust store at all.
const NO_TRUST_STORE: &str = "tls dial requires DialConfig.tls";

/// How long any one node gets to reach the line a leg waits for.
const BUDGET: Duration = Duration::from_secs(10);

/// A throwaway directory holding the acceptor's certificate and key and every
/// config file a leg writes; removed on drop, so a failing leg leaves nothing.
struct Material {
    dir: tempfile::TempDir,
    cert: String,
    key: String,
}

impl Material {
    fn new() -> Self {
        let dir = tempfile::tempdir().expect("tempdir for the tls material");
        let (cert_pem, key_pem) = localhost_cert_key_pem();
        let cert = write_file(dir.path(), "server.cert.pem", &cert_pem);
        let key = write_file(dir.path(), "server.key.pem", &key_pem);
        Self { dir, cert, key }
    }

    /// A second self-signed certificate for the same name, which the acceptor
    /// does not present and so cannot be a root for its chain.
    fn foreign_cert(&self) -> String {
        let (cert_pem, _key_pem) = localhost_cert_key_pem();
        write_file(self.dir.path(), "foreign.cert.pem", &cert_pem)
    }

    fn config(&self, name: &str, document: &str) -> String {
        write_file(self.dir.path(), name, document)
    }
}

fn write_file(dir: &Path, name: &str, body: &str) -> String {
    let path = dir.join(name);
    std::fs::write(&path, body).unwrap_or_else(|e| panic!("write {}: {e}", path.display()));
    path.display().to_string()
}

/// The acceptor's document: a listening peer with a `tls/` endpoint, and the
/// paths of `material`'s certificate and key when one is given.
fn acceptor_document(material: Option<&Material>) -> String {
    let tls = match material {
        Some(Material { cert, key, .. }) => format!(
            r#", transport: {{ link: {{ tls: {{
                   listen_certificate: "{cert}", listen_private_key: "{key}" }} }} }}"#
        ),
        None => String::new(),
    };
    format!(r#"{{ mode: "peer", listen: {{ endpoints: ["tls/127.0.0.1:0"] }}{tls} }}"#)
}

/// The dialer's document: a client with one `tls/` endpoint, and the root CA
/// when `root_ca` names one.
fn dialer_document(port: u16, root_ca: Option<&str>) -> String {
    let tls = match root_ca {
        Some(path) => {
            format!(r#", transport: {{ link: {{ tls: {{ root_ca_certificate: "{path}" }} }} }}"#)
        }
        None => String::new(),
    };
    format!(r#"{{ mode: "client", connect: {{ endpoints: ["tls/127.0.0.1:{port}"] }}{tls} }}"#)
}

/// Start a node on `--config <file>` and nothing else, its stderr captured.
fn spawn_on_config(demo: &Path, label: &str, config: &str) -> (ChildGuard, File) {
    let capture = tempfile::tempfile().expect("tempfile for a node's stderr");
    let writer = capture.try_clone().expect("dup a node's stderr handle");
    let child = Command::new(demo)
        .arg("--config")
        .arg(config)
        .env("RUST_LOG", "info")
        .stdout(Stdio::null())
        .stderr(Stdio::from(writer))
        .spawn()
        .unwrap_or_else(|e| panic!("spawn {label}: {e}"));
    (ChildGuard::wrap(label, child), capture)
}

/// Start the acceptor on `config` and read back the port it bound.
fn start_acceptor(demo: &Path, config: &str) -> (ChildGuard, File, u16) {
    let stderr = tempfile::tempfile().expect("tempfile for the acceptor's stderr");
    spawn_on_ephemeral_port(
        demo,
        &["--config", config],
        PEER_LISTEN_MARKER,
        "wz tls acceptor from a config file",
        stderr,
    )
}

/// Run one dialer on `config` until its stderr shows `needle` or the budget is
/// spent, then stop it. Returns whether the line appeared and everything the
/// dialer wrote.
fn dial_until(demo: &Path, label: &str, config: &str, needle: &str) -> (bool, String) {
    let (mut dialer, mut log) = spawn_on_config(demo, label, config);
    let seen = wait_for_substring(&mut log, needle, BUDGET);
    let _ = dialer.child_mut().kill();
    let _ = dialer.child_mut().wait();
    let text = read_captured(&mut log);
    eprintln!("--- {label} stderr ---\n{text}");
    (seen.is_ok(), text)
}

/// Both nodes from files alone, with every key present: the dialer verifies the
/// acceptor's certificate against the root its file names and the session
/// opens over a TLS link.
#[test]
#[ignore = "binary-dep e2e (wz-ap-demo --features tls,routing-peer,zenoh-config); Layer Z runs via --ignored"]
fn wz_peer_tls_keys_in_two_config_files_establish_a_tls_session() {
    let demo = wz_ap_demo_binary();
    assert_demo_binary_newer_than_sources(&demo);
    let material = Material::new();

    let acceptor_config = material.config("acceptor.json5", &acceptor_document(Some(&material)));
    let (_acceptor, mut acceptor_log, port) = start_acceptor(&demo, &acceptor_config);

    let dialer_config =
        material.config("dialer.json5", &dialer_document(port, Some(&material.cert)));
    let (established, dialer_text) = dial_until(
        &demo,
        "wz tls dialer from a config file",
        &dialer_config,
        "session Established",
    );
    let acceptor_text = read_captured(&mut acceptor_log);
    eprintln!("--- wz tls acceptor stderr ---\n{acceptor_text}");

    assert!(
        established,
        "the dialer never logged 'session Established' within {BUDGET:?}; the certificate \
         and key from the acceptor's file and the root from the dialer's file did not \
         produce a TLS session\n--- dialer stderr ---\n{dialer_text}\n\
         --- acceptor stderr ---\n{acceptor_text}"
    );
    assert!(
        dialer_text.contains("over tls transport"),
        "the session opened, but not over a tls link\n--- dialer stderr ---\n{dialer_text}"
    );
    // The expansion line names the flags each file produced, so a run that
    // established by some other route (a tcp fallback, a default trust store)
    // cannot satisfy this leg.
    assert!(
        dialer_text.contains("\"--tls-ca\""),
        "the dialer's file did not expand root_ca_certificate to --tls-ca\n{dialer_text}"
    );
    assert!(
        acceptor_text.contains("\"--tls-cert\"") && acceptor_text.contains("\"--tls-key\""),
        "the acceptor's file did not expand listen_certificate and listen_private_key to \
         --tls-cert and --tls-key\n{acceptor_text}"
    );
}

/// Without `root_ca_certificate` the dialer has no trust store and does not
/// establish; with it, against the same acceptor, it does.
#[test]
#[ignore = "binary-dep e2e (wz-ap-demo --features tls,routing-peer,zenoh-config); Layer Z runs via --ignored"]
fn wz_peer_tls_dialer_without_root_ca_certificate_key_does_not_establish() {
    let demo = wz_ap_demo_binary();
    assert_demo_binary_newer_than_sources(&demo);
    let material = Material::new();

    let acceptor_config = material.config("acceptor.json5", &acceptor_document(Some(&material)));
    let (_acceptor, _acceptor_log, port) = start_acceptor(&demo, &acceptor_config);

    let bare_config = material.config("dialer-bare.json5", &dialer_document(port, None));
    let (refused, bare_text) = dial_until(
        &demo,
        "wz tls dialer without root_ca_certificate",
        &bare_config,
        DIAL_REFUSED,
    );
    assert!(
        refused,
        "the dialer without root_ca_certificate neither connected nor reported a refusal \
         within {BUDGET:?}\n--- dialer stderr ---\n{bare_text}"
    );
    assert!(
        bare_text.contains(NO_TRUST_STORE),
        "the dial failed, but not for want of a trust store\n--- dialer stderr ---\n{bare_text}"
    );
    assert!(
        !bare_text.contains("session Established"),
        "a dialer holding no root_ca_certificate established a TLS session\n{bare_text}"
    );

    // The same acceptor, the same endpoint, the key restored.
    let keyed_config = material.config(
        "dialer-keyed.json5",
        &dialer_document(port, Some(&material.cert)),
    );
    let (established, keyed_text) = dial_until(
        &demo,
        "wz tls dialer with root_ca_certificate",
        &keyed_config,
        "session Established",
    );
    assert!(
        established,
        "restoring root_ca_certificate did not produce a session against the same acceptor \
         within {BUDGET:?}, so the refusal above says nothing about the key\n\
         --- dialer stderr ---\n{keyed_text}"
    );
}

/// A `root_ca_certificate` that names a certificate the acceptor does not
/// present is read and used, and the handshake is refused: the key's VALUE
/// decides the outcome, not only its presence.
#[test]
#[ignore = "binary-dep e2e (wz-ap-demo --features tls,routing-peer,zenoh-config); Layer Z runs via --ignored"]
fn wz_peer_tls_dialer_with_a_foreign_root_ca_certificate_is_refused() {
    let demo = wz_ap_demo_binary();
    assert_demo_binary_newer_than_sources(&demo);
    let material = Material::new();

    let acceptor_config = material.config("acceptor.json5", &acceptor_document(Some(&material)));
    let (_acceptor, _acceptor_log, port) = start_acceptor(&demo, &acceptor_config);

    let foreign = material.foreign_cert();
    let wrong_config = material.config(
        "dialer-foreign.json5",
        &dialer_document(port, Some(&foreign)),
    );
    let (refused, wrong_text) = dial_until(
        &demo,
        "wz tls dialer trusting a foreign root",
        &wrong_config,
        DIAL_REFUSED,
    );
    assert!(
        refused,
        "the dialer trusting a foreign root neither connected nor reported a refusal \
         within {BUDGET:?}\n--- dialer stderr ---\n{wrong_text}"
    );
    assert!(
        !wrong_text.contains(NO_TRUST_STORE),
        "the foreign root was never loaded: the dial failed for want of a trust store\n\
         --- dialer stderr ---\n{wrong_text}"
    );
    assert!(
        !wrong_text.contains("session Established"),
        "a dialer trusting a root the acceptor does not chain to established a TLS \
         session\n{wrong_text}"
    );

    let right_config = material.config(
        "dialer-right.json5",
        &dialer_document(port, Some(&material.cert)),
    );
    let (established, right_text) = dial_until(
        &demo,
        "wz tls dialer trusting the acceptor's root",
        &right_config,
        "session Established",
    );
    assert!(
        established,
        "naming the acceptor's own certificate as the root did not produce a session against \
         the same acceptor within {BUDGET:?}, so the refusal above says nothing about the \
         key's value\n--- dialer stderr ---\n{right_text}"
    );
}

/// Without `listen_certificate` and `listen_private_key` a `tls/` endpoint
/// cannot be served: the node gives up its listen phase and exits without
/// binding. The same document with the two keys listens.
#[test]
#[ignore = "binary-dep e2e (wz-ap-demo --features tls,routing-peer,zenoh-config); Layer Z runs via --ignored"]
fn wz_peer_tls_acceptor_without_listen_certificate_and_key_does_not_listen() {
    let demo = wz_ap_demo_binary();
    assert_demo_binary_newer_than_sources(&demo);
    let material = Material::new();

    let bare_config = material.config("acceptor-bare.json5", &acceptor_document(None));
    let (mut bare, mut bare_log) =
        spawn_on_config(&demo, "wz tls acceptor without a certificate", &bare_config);
    let status = bare
        .child_mut()
        .wait_within(BUDGET)
        .expect("poll the acceptor that has no certificate");
    let bare_text = read_captured(&mut bare_log);
    eprintln!("--- wz tls acceptor without a certificate stderr ---\n{bare_text}");
    assert!(
        !status.success(),
        "an acceptor with a tls endpoint and no certificate exited successfully\n{bare_text}"
    );
    assert!(
        !bare_text.contains("listening on") && !bare_text.contains("BOUND LISTEN ENDPOINT"),
        "an acceptor with a tls endpoint and no certificate reported a bound listener\n{bare_text}"
    );
    assert!(
        bare_text.contains("listen phase gave up"),
        "the acceptor exited, but not by giving up its listen phase\n{bare_text}"
    );

    // The same document with the two keys binds.
    let keyed_config = material.config("acceptor-keyed.json5", &acceptor_document(Some(&material)));
    let (_keyed, keyed_log, port) = start_acceptor(&demo, &keyed_config);
    drop(keyed_log);
    assert_ne!(
        port, 0,
        "the acceptor given listen_certificate and listen_private_key bound no port"
    );
}
