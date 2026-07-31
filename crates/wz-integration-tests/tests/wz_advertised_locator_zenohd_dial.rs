// SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! A real zenohd dials the locator **wz itself chose to advertise** — not one
//! this test composed. The foreign witness for R311y470's advertise-path fix.
//!
//! ## Why the existing unixsock leg is not this witness
//!
//! `wz_unixsock_acceptor_zenohd_interop.rs` already proves a zenohd can dial a
//! wz AF_UNIX acceptor, and it is a good proof of the LINK. It cannot be a proof
//! of the ADVERTISE path, because it writes `unixsock-stream/<path>` twice —
//! once into wz's `--listen` and once into zenohd's `-e` — so the two sides
//! agree with each other by construction and wz's own choice of advertised
//! string is never consulted. That is exactly how R311y470's defect survived:
//! wz advertised `unixsock/<path>`, a scheme neither zenoh (whose prefix is
//! `unixsock-stream`) nor wz's OWN parser accepts, and every interop test in the
//! corpus hand-composed its way around it.
//!
//! ## What this test does differently
//!
//! wz runs as a linkstate PEER, so it takes the advertise path
//! (`run_peer` -> `BoundListener::advertised_locator` -> `set_self_locators` ->
//! `LinkstateForwarder` -> the neighbour graph). It logs its choice, and this
//! test READS that line and hands the string, verbatim, to zenohd's `-e`.
//! Nothing here knows what a unixsock locator looks like:
//!
//! ```text
//!   wz --peer unixsock-stream/<path>   ->  logs ADVERTISED SELF LOCATOR <S>
//!   zenohd -e <S>                      ->  dials it
//!   wz                                 ->  "face 0 UP (… unixsock peer …)"
//! ```
//!
//! The readiness needle is `face N UP`, not the `session Established` the
//! client-mode legs use: `--peer` is a MESH mode and holds per-peer FACES.
//!
//! So the assertion is a genuine cross-impl one: whatever wz decides to publish
//! as its dial hint must be a string a foreign zenoh stack can actually connect
//! to. Under the pre-R311y470 rendering `<S>` is `unixsock/<path>` and zenohd
//! never reaches wz, so the run reds — verified by damage, not assumed.
//!
//! The `--listen` side deliberately keeps its explicit `unixsock-stream/` form:
//! that is wz PARSING a foreign-facing locator, an independent axis this test
//! does not conflate with the advertise one.
//!
//! ## Why unixsock and not quic-datagram
//!
//! Both schemes were corrected in R311y470, but only one is cheap to witness:
//! zenoh's default features carry `transport_unixsock-stream` (the existing
//! acceptor leg dials stock zenohd), while a quic-datagram witness needs cert
//! threading on both ends AND a zenohd variant build. The quic-datagram arm of
//! the fix therefore stays unwitnessed and is carried as such — its unit proof
//! (`advertised_quic_datagram_locator_uses_zenoh_quic_scheme_and_rel_metadata`)
//! pins the string and the wz-side round-trip, not a foreign dial.

use std::path::Path;
use std::process::{Command, Stdio};
use std::time::Duration;

use wz_integration_tests::common::{
    spawn_zenohd_dialer_on_ephemeral_tcp, wait_for_substring, wz_ap_demo_binary, zenohd_binary,
    ChildGuard,
};

/// The needle `run_peer` emits for each advertised dial locator.
const ADVERTISED_NEEDLE: &str = "ADVERTISED SELF LOCATOR ";

// The direction follows the corpus convention — who DIALS. zenohd dials wz, as in
// the `*_acceptor_zenohd_interop` legs, so this is `zenohd->wz` even though the
// thing under test is a string wz emitted.
// wz-proves: locator-unixsock zenohd->wz
#[test]
#[ignore = "binary-dep e2e: needs zenohd (stock) + wz-ap-demo[+unixsock]; runs via --ignored"]
fn zenohd_dials_the_locator_wz_advertised_for_its_unixsock_peer() {
    let demo = wz_ap_demo_binary();
    let sock_path = std::env::temp_dir()
        .join(format!("wz-adv-loc-zenohd-{}.sock", std::process::id()))
        .to_string_lossy()
        .into_owned();
    let _ = std::fs::remove_file(&sock_path);

    // wz as a linkstate PEER on a unixsock listen — the mode that runs the
    // advertise path. The `--listen` form here is the explicit foreign-facing
    // one; what this test is about is the string wz DERIVES from it below.
    let wz_stderr = tempfile::tempfile().expect("tempfile for wz peer stderr");
    let wz_writer = wz_stderr.try_clone().expect("dup wz stderr handle");
    let mut wz_reader = wz_stderr;
    let mut wz = ChildGuard::wrap(
        "wz-ap-demo (--peer unixsock-stream)",
        Command::new(&demo)
            .arg("--peer")
            .arg(format!("unixsock-stream/{sock_path}"))
            .arg("--zid")
            .arg("70730001")
            .env("RUST_LOG", "info")
            .stdout(Stdio::null())
            .stderr(Stdio::from(wz_writer))
            .spawn()
            .expect("spawn wz-ap-demo --peer unixsock-stream"),
    );

    // THE POINT OF THE TEST: read wz's own advertised locator rather than
    // composing one. `bind_unixsock` binds synchronously before the advertise, so
    // the needle also witnesses the socket file being present.
    let advertised_line =
        wait_for_substring(&mut wz_reader, ADVERTISED_NEEDLE, Duration::from_secs(10));
    // `wait_for_substring` returns the captured buffer from the needle onward, not
    // one line, so cut at the first newline before trimming — otherwise the
    // "locator" carries every subsequent log line with it.
    let advertised = advertised_line.as_ref().ok().and_then(|captured| {
        captured
            .split_once(ADVERTISED_NEEDLE)
            .map(|(_, rest)| rest.lines().next().unwrap_or("").trim().to_string())
            .filter(|s| !s.is_empty())
    });
    let bound = advertised.is_some() && Path::new(&sock_path).exists();

    // Hand it, VERBATIM, to a real zenohd. Nothing rewrites or repairs it: if wz
    // advertised a scheme zenoh has no prefix for, this dial cannot land.
    let zenohd = advertised.as_deref().filter(|_| bound).map(|locator| {
        spawn_zenohd_dialer_on_ephemeral_tcp(
            &zenohd_binary(),
            "zenohd (dials wz's advertised locator)",
            Some(locator),
            &[],
            None,
        )
    });

    // `--peer` is a MESH mode: it holds per-peer FACES and logs "face N UP", not the
    // single-session "session Established" the client-mode legs wait on. Waiting on
    // the wrong needle here would time out against a link that had actually come up.
    let established = zenohd
        .as_ref()
        .map(|_| wait_for_substring(&mut wz_reader, "face 0 UP", Duration::from_secs(20)));

    if let Some((mut guard, _port)) = zenohd {
        let _ = guard.child_mut().kill();
        let _ = guard.child_mut().wait();
    }
    let _ = wz.child_mut().kill();
    let _ = wz.child_mut().wait();
    let _ = std::fs::remove_file(&sock_path);

    assert!(
        advertised_line.is_ok(),
        "wz-ap-demo --peer never logged an advertised self locator; without it the \
         advertise path is unobservable and this witness cannot exist"
    );
    let advertised = advertised.expect("the needle carries the locator");
    // Pinned so a REGRESSION to a log-word scheme is named here too, not only in
    // the unit test: zenoh's prefix is `unixsock-stream` and so is wz's own.
    assert_eq!(
        advertised,
        format!("unixsock-stream/{sock_path}"),
        "wz must advertise zenoh's UNIXSOCKSTREAM_LOCATOR_PREFIX, not the `unixsock` log word"
    );
    assert!(
        bound,
        "the wz peer advertised but its AF_UNIX socket file is absent — nothing to dial"
    );
    let face = match &established {
        Some(Ok(captured)) => captured.clone(),
        _ => panic!(
            "a real zenohd did not bring a face up by dialing the locator wz advertised \
             ({advertised}); the advertised string is not foreign-dialable"
        ),
    };
    // The face must be the UNIXSOCK one, so a stray face from some other transport
    // cannot pass this off as a successful unixsock dial.
    assert!(
        face.contains("unixsock peer"),
        "face 0 came up on a transport other than unixsock; the log line was: {face}"
    );
}
