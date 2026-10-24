// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The fixed-memory profile's secure channel against the reference router: step 1b's witness
//! (decision D9 of `docs/session-lifecycle-intent.md`), a fixed-memory image and a router each
//! verifying the other.
//!
//! The image is `deploy/host-slot-node` built with `tls`: the kit's session code as a Linux
//! process with no allocator, dialling `tls/` through `wz-tls-mbedtls`. It generates its identity
//! at start and prints its certificate as PEM, as a device would for its operator. The router is
//! zenohd 1.10.1 with mutual TLS on, pinning that certificate as its `root_ca_certificate`, which
//! is how a zenoh router admits a device; its own certificate is self-signed over a P-256 key.
//!
//! Three runs, each the control of another:
//!
//! - the router's zid is the one its key names: the session is established and the image reads
//!   the router as VERIFIED (its claimed zid is the zid of the key it proved);
//! - the router's zid is any other: the session is established over the same channel, and the
//!   image reads the router as NOT verified, so the first verdict is the key binding and not the
//!   channel alone;
//! - the router pins another device's certificate: no session is established, so the first two
//!   are the router verifying the image and not a router that admits anyone.
//!
//! Requires the image (`WZ_HOST_SLOT_NODE_TLS`, built by Layer Z) and the reference zenohd.
//! Runs on the `--ignored` lane; the file's `zenohd` token keeps Layer E's sweep off it.

use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::time::Duration;

use wz_integration_tests::common::{
    graceful_terminate, read_captured, wait_for_substring, zenohd_binary, ChildGuard,
};
use wz_runtime_tokio_test_support::{free_port, key_named_identity, KeyNamedIdentity};
use wz_session_core::credential_identity::zid_from_spki_der;

/// What the image prints once its session is up, with the verdict on the router.
const ESTABLISHED: &str = "host-slot-node: session established, peer ";
const VERIFIED: &str = "host-slot-node: session established, peer verified";
const NOT_VERIFIED: &str = "host-slot-node: session established, peer not verified";

/// How long a run may take to establish: the image redials on the connect manager's schedule
/// while the router comes up, and each handshake is a few milliseconds on a host.
const ESTABLISH_BUDGET: Duration = Duration::from_secs(30);
/// How long a refused run is watched for a session that must not come.
const REFUSAL_WINDOW: Duration = Duration::from_secs(10);

/// The image built with `tls`, as Layer Z names it.
fn node_binary() -> PathBuf {
    let path = PathBuf::from(std::env::var("WZ_HOST_SLOT_NODE_TLS").expect(
        "WZ_HOST_SLOT_NODE_TLS names deploy/host-slot-node built with `--features tls` \
         (Layer Z builds it)",
    ));
    assert!(path.is_file(), "no image at {}", path.display());
    path
}

/// Files a run writes, removed however the run ends.
struct TempFiles(Vec<PathBuf>);

impl Drop for TempFiles {
    fn drop(&mut self) {
        for path in &self.0 {
            let _ = std::fs::remove_file(path);
        }
    }
}

/// A zenoh id as zenoh's configuration spells one: lowercase hex of the id's bytes read as a
/// little-endian integer (`uhlc` 0.8.2 `src/id.rs` @ `write!(f, "{:x}", u128::from_le_bytes(self.0))`).
fn config_id(zid: &[u8; 16]) -> String {
    format!("{:x}", u128::from_le_bytes(*zid))
}

/// The PEM block the image printed, once it has printed all of it.
fn printed_certificate(captured: &str) -> Option<String> {
    let begin = captured.find("-----BEGIN CERTIFICATE-----")?;
    let end = captured[begin..].find("-----END CERTIFICATE-----")? + begin;
    let end = end + "-----END CERTIFICATE-----".len();
    Some(format!("{}\n", &captured[begin..end]))
}

/// How a run ended, as the image saw it.
struct Outcome {
    image: String,
    router: String,
}

/// Which certificate the router pins.
enum Pin {
    /// The image's own.
    TheImage,
    /// Another device's.
    Stranger,
}

/// Which zid the router claims.
enum RouterId {
    /// The one its key names.
    OfItsKey,
    /// One no key names.
    Unbound,
}

/// Run the image against a router configured by `pin` and `id`, until `needle` appears in the
/// image's output or `budget` runs out.
fn run(
    pin: Pin,
    id: RouterId,
    needle: &str,
    budget: Duration,
) -> (Result<String, String>, Outcome) {
    let node = node_binary();
    let port = free_port();
    let base = std::env::temp_dir().join(format!("wz-fixed-tls-{}-{port}", std::process::id()));
    let path = |suffix: &str| PathBuf::from(format!("{}.{suffix}", base.display()));
    let (device_pem, router_cert, router_key, config) = (
        path("device.pem"),
        path("router.pem"),
        path("router.key"),
        path("zenohd.json5"),
    );
    let _cleanup = TempFiles(vec![
        device_pem.clone(),
        router_cert.clone(),
        router_key.clone(),
        config.clone(),
    ]);

    // The image first: it makes its identity, prints its certificate and dials a router that is
    // not up yet, which it keeps redialling.
    let mut image_out = tempfile::tempfile().expect("a capture for the image");
    let mut image = ChildGuard::wrap(
        "host-slot-node (tls)",
        Command::new(&node)
            .arg(format!("tls/127.0.0.1:{port}"))
            .stdout(Stdio::from(image_out.try_clone().expect("dup capture")))
            .stderr(Stdio::from(image_out.try_clone().expect("dup capture")))
            .spawn()
            .expect("spawn the image"),
    );
    let printed = wait_for_substring(
        &mut image_out,
        "-----END CERTIFICATE-----",
        Duration::from_secs(10),
    )
    .unwrap_or_else(|c| panic!("the image printed no certificate\n--- image ---\n{c}"));
    let device = printed_certificate(&printed).expect("a whole PEM block");

    // The router, as its operator configures it for this device.
    let router: KeyNamedIdentity = key_named_identity();
    let pinned = match pin {
        Pin::TheImage => device,
        Pin::Stranger => key_named_identity().cert_pem,
    };
    let zid = match id {
        RouterId::OfItsKey => zid_from_spki_der(&router.spki_der),
        // Any id but the key's: the key's with its first byte moved.
        RouterId::Unbound => {
            let mut zid = zid_from_spki_der(&router.spki_der);
            zid[0] ^= 0x5a;
            zid
        }
    };
    std::fs::write(&device_pem, pinned).expect("write the pinned certificate");
    std::fs::write(&router_cert, &router.cert_pem).expect("write the router certificate");
    std::fs::write(&router_key, &router.key_pem).expect("write the router key");
    std::fs::write(
        &config,
        format!(
            "{{ id: {id:?}, mode: \"router\", transport: {{ link: {{ tls: {{ \
             listen_certificate: {cert:?}, listen_private_key: {key:?}, \
             root_ca_certificate: {root:?}, enable_mtls: true }} }} }} }}",
            id = config_id(&zid),
            cert = router_cert.display().to_string(),
            key = router_key.display().to_string(),
            root = device_pem.display().to_string(),
        ),
    )
    .expect("write the router configuration");

    let mut router_out = tempfile::tempfile().expect("a capture for the router");
    let mut zenohd = ChildGuard::wrap(
        "zenohd (reference router, mutual tls)",
        Command::new(zenohd_binary())
            .arg("--config")
            .arg(&config)
            .arg("-l")
            .arg(format!("tls/127.0.0.1:{port}"))
            .arg("--no-multicast-scouting")
            .arg("--rest-http-port")
            .arg("none")
            .stdout(Stdio::from(router_out.try_clone().expect("dup capture")))
            .stderr(Stdio::from(router_out.try_clone().expect("dup capture")))
            .spawn()
            .expect("spawn zenohd"),
    );

    let seen = wait_for_substring(&mut image_out, needle, budget);
    graceful_terminate(image.child_mut(), Duration::from_secs(5));
    graceful_terminate(zenohd.child_mut(), Duration::from_secs(5));
    let outcome = Outcome {
        image: read_captured(&mut image_out),
        router: read_captured(&mut router_out),
    };
    (seen, outcome)
}

fn report(outcome: &Outcome) -> String {
    format!(
        "--- image ---\n{}\n--- zenohd ---\n{}",
        outcome.image, outcome.router
    )
}

// wz-proves: none -- the fixed-memory profile's channel (D9, wz-tls-mbedtls) has no catalog atom: transport-link-tls is the tokio link's feature and is not in this image, and session-close-ingress's verbs are not on this path
#[test]
#[ignore = "binary-dep e2e (the tls build of deploy/host-slot-node, which Layer Z makes, + zenohd); runs via --ignored"]
fn zenohd_and_a_fixed_memory_image_each_verify_the_other_over_mutual_tls() {
    let (seen, outcome) = run(
        Pin::TheImage,
        RouterId::OfItsKey,
        ESTABLISHED,
        ESTABLISH_BUDGET,
    );
    seen.unwrap_or_else(|_| {
        panic!(
            "no session within {ESTABLISH_BUDGET:?}: zenohd did not admit the image it pins\n{}",
            report(&outcome)
        )
    });
    assert!(
        outcome.image.contains(VERIFIED),
        "the session is up but the image does not read the router as the holder of the key \
         its zid names\n{}",
        report(&outcome)
    );
}

// wz-proves: none -- the control of the leg above, for the same reason: no catalog atom names the fixed-memory profile's channel
#[test]
#[ignore = "binary-dep e2e (the tls build of deploy/host-slot-node, which Layer Z makes, + zenohd); runs via --ignored"]
fn zenohd_claiming_a_zid_its_key_does_not_name_is_not_verified() {
    let (seen, outcome) = run(
        Pin::TheImage,
        RouterId::Unbound,
        ESTABLISHED,
        ESTABLISH_BUDGET,
    );
    seen.unwrap_or_else(|_| {
        panic!(
            "no session within {ESTABLISH_BUDGET:?}, so this control says nothing\n{}",
            report(&outcome)
        )
    });
    assert!(
        outcome.image.contains(NOT_VERIFIED),
        "a router claiming a zid its key does not name was read as verified\n{}",
        report(&outcome)
    );
}

// wz-proves: none -- the control of the first leg, for the same reason: no catalog atom names the fixed-memory profile's channel
#[test]
#[ignore = "binary-dep e2e (the tls build of deploy/host-slot-node, which Layer Z makes, + zenohd); runs via --ignored"]
fn zenohd_pinning_another_device_admits_no_session() {
    let (seen, outcome) = run(
        Pin::Stranger,
        RouterId::OfItsKey,
        ESTABLISHED,
        REFUSAL_WINDOW,
    );
    assert!(
        seen.is_err(),
        "a router pinning another device's certificate admitted the image\n{}",
        report(&outcome)
    );
    assert!(
        outcome.image.contains("HOST-WZ-CLIENT READY"),
        "the image never came up, so the refusal says nothing\n{}",
        report(&outcome)
    );
}
