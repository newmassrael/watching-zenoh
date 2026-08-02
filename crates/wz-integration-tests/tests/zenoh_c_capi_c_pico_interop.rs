// SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! R311y500 — §5.27 `api-compat-c` against a REAL FOREIGN PEER.
//!
//! ## What the sibling file could not do, and why this one exists
//!
//! `zenoh_c_examples_on_wz_capi_dropin.rs` compiles upstream's `z_put.c` against
//! upstream's header, links it to wz's cdylib, and checks it against the real
//! `libzenohc.so` as a reference arm. That is a strong differential and it is
//! still the right place for the layout gate — but it carries NO cross-impl proof
//! annotation at all, and its own doc says why: **neither leg puts a foreign
//! implementation on the wire.** The C program links wz's library and the
//! observer is a wz node, so every byte on that link was produced and consumed by
//! wz. Layer A4 refused a claim there twice, correctly, and `api-compat-c` sat in
//! the UNPROVEN list.
//!
//! That file names the leg that would earn the axis as "upstream's `z_sub.c`
//! running on the REAL `libzenohc.so`, subscribing to a wz publisher", and defers
//! it for needing the closure and channel families. That framing looked past a
//! foreign counterparty this tree already provisions: **zenoh-pico**. A4 scores a
//! foreign IMPLEMENTATION opposite wz, not a specific one, and the sibling atom
//! `api-compat-pico` is proven this exact way. A real pico CLI is a perfectly
//! good counterparty for a zenoh-c-ABI program — better, in one respect, than a
//! second zenoh-c would be: pico shares no code with either side, so an
//! agreement between them is agreement on the WIRE rather than on a library.
//!
//! ## The two legs are a pair, and the second is the load-bearing one
//!
//! - LEG 1 (`pico->wz`): upstream's `z_sub.c` on wz's cdylib LISTENS; the real
//!   pico `z_put` dials in and publishes. Foreign bytes on the INBOUND path,
//!   rendered by upstream's own `data_handler` through wz's `z_sample_keyexpr` /
//!   `z_sample_payload` / `z_sample_kind` / `z_bytes_to_string`. The witness is
//!   the drop-in's stdout — upstream's program text, wz's runtime underneath.
//! - LEG 2 (`wz->pico`): upstream's `z_put.c` on wz's cdylib dials a real pico
//!   `z_sub`, and the FOREIGN process is what reports the sample. Here both the
//!   decoding and the verdict come from outside wz, which leg 1 cannot claim.
//!
//! Leg 1 alone would be a wz assertion about wz's own output; leg 2 alone would
//! exercise none of the new accessors. Neither is the claim.
//!
//! ## The claim is `partial`, and the residual is MEASURED
//!
//! Three of upstream's 22 compilable examples link against this cdylib
//! (`z_put`, `z_sub`, `z_sub_shm`). Layer C1cc prints that ratio every run via
//! `scripts/lib/capi_c_coverage.py`, so the gap between "this atom is proven" and
//! "this ABI is complete" stays a number rather than an impression.
//!
//! ## The oracle is machine-local
//!
//! zenoh-c's headers and its example clone are not in this repo, and neither are
//! the pico CLIs. Absence is reported LOUDLY and the leg returns, because a
//! silent skip is a green test that proved nothing; the LANE decides whether that
//! is acceptable.

use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::Duration;

use wz_integration_tests::common::{
    compile_zenoh_c_example, graceful_terminate, read_captured, spawn_zenohd, wait_for_substring,
    wait_for_tcp_accept_alive, wz_capi_c_cdylib, zenoh_c_oracle, zenoh_pico_cli_binary, ChildGuard,
    PortReservation,
};

/// How long a listener gets to bind and accept.
///
/// The barrier is the liveness-aware `wait_for_tcp_accept_alive`, not a bare
/// connect: a bare connect proves only that SOMETHING accepts on that port, so a
/// child that lost the ephemeral-port race and exited passes it against whatever
/// won, and the failure resurfaces later as an unrelated symptom.
const LISTEN_TIMEOUT: Duration = Duration::from_secs(10);
/// How long the exchange gets to reach the observing side's stdout.
const EXCHANGE_TIMEOUT: Duration = Duration::from_secs(20);

/// The oracle, or `None` with a LOUD note naming what to do about it.
fn oracle_or_note() -> Option<(PathBuf, PathBuf, PathBuf)> {
    match zenoh_c_oracle() {
        Some(o) => Some(o),
        None => {
            eprintln!(
                "skip: the zenoh-c ORACLE is absent. This leg needs zenoh-c's headers \
                 (default prefix ~/.local, override WZ_ZENOH_C_PREFIX) AND a clone of \
                 its examples (default ~/zenoh-c-ref/examples, override \
                 WZ_ZENOH_C_EXAMPLES: `git clone --depth 1 --branch 1.5.0 \
                 https://github.com/eclipse-zenoh/zenoh-c ~/zenoh-c-ref`). Layer C1cc \
                 with WZ_C1CC_REQUIRE=1 fails instead of skipping."
            );
            None
        }
    }
}

/// Compile an upstream zenoh-c example against WZ's cdylib, failing with the
/// compiler's own diagnostics when it does not link.
///
/// A link failure IS the drop-in claim being false, so it is surfaced verbatim:
/// the undefined-reference list names exactly which `z_*` exports wz is missing,
/// which is the actionable form of "not a drop-in yet".
fn dropin_binary(example: &str, dir: &Path, include: &Path, examples: &Path) -> (PathBuf, PathBuf) {
    let lib = wz_capi_c_cdylib();
    let libdir = lib.parent().expect("cdylib has a parent").to_path_buf();
    let exe = compile_zenoh_c_example(example, dir, include, examples, &libdir, "wz_capi_c")
        .unwrap_or_else(|diag| {
            panic!(
                "§5.27 api-compat-c: upstream {example}.c does NOT link against wz's \
                 C-ABI cdylib, so wz is not a binary drop-in for it.\n{diag}"
            )
        });
    (exe, libdir)
}

/// LEG 1 (`pico->wz`) — upstream's `z_sub.c`, running on WZ's C ABI, receives a
/// sample published by the REAL zenoh-pico `z_put` binary.
///
/// The drop-in LISTENS and the foreign publisher dials in, which is what puts the
/// foreign bytes on the INBOUND path: the payload text is chosen by real pico,
/// crosses a real TCP link, and is rendered by upstream's own `data_handler`.
/// A wz sample accessor that mis-framed the payload, resolved the keyexpr wrongly
/// or reported the wrong kind could not print the line this asserts.
///
/// Upstream's `z_sub.c` has no self-terminating sample count — it loops on
/// `z_sleep_s` until killed — so its stdout is LINE-BUFFERED through `stdbuf` and
/// read while it runs. Waiting for an exit that only a signal produces would
/// leave every failure mode with a byte-identical empty capture.
// wz-proves: api-compat-c pico->wz partial
#[test]
#[ignore = "compiles an upstream zenoh-c example with cc and spawns the real \
            zenoh-pico z_put CLI; needs the machine-local zenoh-c oracle; \
            run-ci Layer C1cc drives it"]
fn upstream_z_sub_on_wz_capi_c_receives_from_a_real_pico_zput() {
    let Some((include, _libdir_ref, examples)) = oracle_or_note() else {
        return;
    };
    let dir = tempfile::tempdir().expect("tempdir for the compiled drop-in");
    let (dropin, libdir) = dropin_binary("z_sub", dir.path(), &include, &examples);
    let z_put = zenoh_pico_cli_binary("z_put");

    let reservation = PortReservation::pick();
    let port = reservation.port();
    let endpoint = format!("tcp/127.0.0.1:{port}");
    let payload = "PAYLOAD-FROM-REAL-PICO-ZPUT";
    let key = "demo/capic/leg1";

    let mut sub_out = tempfile::tempfile().expect("subscriber stdout capture");
    let writer = sub_out.try_clone().expect("dup subscriber stdout handle");
    let mut sub = ChildGuard::wrap(
        "upstream z_sub.c on wz-capi-c",
        Command::new("stdbuf")
            .args(["-oL", "-eL"])
            .arg(&dropin)
            .args(["-l", &endpoint, "-m", "peer", "-k", "demo/capic/**"])
            .env("LD_LIBRARY_PATH", &libdir)
            .stdout(Stdio::from(writer))
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn the compiled z_sub drop-in"),
    );

    if let Err(why) = wait_for_tcp_accept_alive(sub.child_mut(), port, LISTEN_TIMEOUT) {
        panic!(
            "upstream z_sub.c on wz's C ABI never accepted on {endpoint} — {why}; \
             capture so far:\n{}",
            read_captured(&mut sub_out)
        );
    }
    drop(reservation);

    // Captured even though the exit status is asserted: a zero exit says the
    // process ran, not that it published. The capture is what the panic below
    // reads to tell "the publisher never got there" from "it published and wz
    // dropped it".
    let mut put_out = tempfile::tempfile().expect("foreign z_put stdout capture");
    let put_writer = put_out.try_clone().expect("dup foreign z_put handle");
    let put = Command::new("stdbuf")
        .args(["-oL", "-eL"])
        .arg(&z_put)
        .args(["-e", &endpoint, "-m", "client", "-k", key, "-v", payload])
        .stdout(Stdio::from(put_writer))
        .stderr(Stdio::null())
        .status()
        .expect("run the real zenoh-pico z_put");
    assert!(
        put.success(),
        "real zenoh-pico z_put exited {put:?}\n--- its stdout ---\n{}",
        read_captured(&mut put_out)
    );

    let captured =
        wait_for_substring(&mut sub_out, payload, EXCHANGE_TIMEOUT).unwrap_or_else(|captured| {
            let driver = read_captured(&mut put_out);
            panic!(
                "upstream z_sub.c running on wz's zenoh-c ABI never reported the payload \
                 published by the REAL zenoh-pico z_put.\nexpected substring: {payload}\n\
                 the foreign publisher reached its put: {}\n\
                 --- z_sub.c (on wz) stdout ---\n{captured}\n\
                 --- REAL pico z_put (driver) stdout ---\n{driver}",
                driver.contains("Putting Data"),
            )
        });

    // Upstream's handler prints `>> [Subscriber] Received <KIND> ('<key>': '<payload>')`.
    // The KEY and the KIND are asserted beside the payload because they come from
    // three DIFFERENT wz exports and only the payload is covered by the line above:
    // a keyexpr wz resolved wrongly would still carry the right bytes, and a kind
    // wz mapped wrongly would print DELETE for a put.
    assert!(
        captured.contains(key),
        "the payload arrived but not on the key the foreign publisher used ({key}); \
         wz's `z_sample_keyexpr` / inbound keyexpr resolution disagrees.\n\
         --- stdout ---\n{captured}"
    );
    assert!(
        captured.contains("Received PUT"),
        "the sample arrived but wz's `z_sample_kind` did not report it as a PUT, so \
         upstream's `kind_to_str` printed something else.\n--- stdout ---\n{captured}"
    );

    graceful_terminate(sub.child_mut(), Duration::from_secs(5));
}

/// LEG 2 (`wz->pico`) — upstream's `z_put.c`, running on WZ's C ABI, reaches the
/// REAL zenoh-pico `z_sub` binary, and the FOREIGN process is what reports it.
///
/// This is the stronger of the two legs and the reason the pair exists. The
/// witness line is read from the real pico subscriber's own stdout, so the
/// assertion is made by a foreign implementation about bytes it decoded itself —
/// not by a wz test inspecting a value wz produced. Leg 1 can only be observed
/// through the drop-in's own output (upstream's program text, but wz's runtime
/// underneath); here the decoding and the verdict both come from outside.
// wz-proves: api-compat-c wz->pico partial
#[test]
#[ignore = "compiles an upstream zenoh-c example with cc and spawns the real \
            zenoh-pico z_sub CLI; needs the machine-local zenoh-c oracle; \
            run-ci Layer C1cc drives it"]
fn upstream_z_put_on_wz_capi_c_reaches_a_real_pico_zsub() {
    let Some((include, _libdir_ref, examples)) = oracle_or_note() else {
        return;
    };
    let dir = tempfile::tempdir().expect("tempdir for the compiled drop-in");
    let (dropin, libdir) = dropin_binary("z_put", dir.path(), &include, &examples);
    let z_sub = zenoh_pico_cli_binary("z_sub");

    let reservation = PortReservation::pick();
    let port = reservation.port();
    let endpoint = format!("tcp/127.0.0.1:{port}");
    let payload = "PAYLOAD-FROM-UPSTREAM-ZPUT-ON-WZ";
    let key = "demo/example/leg2";

    let mut sub_out = tempfile::tempfile().expect("foreign subscriber stdout capture");
    let writer = sub_out.try_clone().expect("dup foreign subscriber handle");
    let mut sub = ChildGuard::wrap(
        "real zenoh-pico z_sub",
        Command::new("stdbuf")
            .args(["-oL", "-eL"])
            .arg(&z_sub)
            .args(["-l", &endpoint, "-m", "peer", "-k", "demo/example/**"])
            .stdout(Stdio::from(writer))
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn the real zenoh-pico z_sub"),
    );

    if let Err(why) = wait_for_tcp_accept_alive(sub.child_mut(), port, LISTEN_TIMEOUT) {
        panic!(
            "the real zenoh-pico z_sub never accepted on {endpoint} — {why}; capture \
             so far:\n{}",
            read_captured(&mut sub_out)
        );
    }
    drop(reservation);

    let put = Command::new("stdbuf")
        .args(["-oL", "-eL"])
        .arg(&dropin)
        .args(["-e", &endpoint, "-m", "client", "-k", key, "-p", payload])
        .env("LD_LIBRARY_PATH", &libdir)
        .output()
        .expect("run upstream z_put.c on wz's C ABI");
    assert!(
        put.status.success(),
        "upstream z_put.c on wz's zenoh-c ABI exited {:?}\n--- stdout ---\n{}\n\
         --- stderr ---\n{}",
        put.status.code(),
        String::from_utf8_lossy(&put.stdout),
        String::from_utf8_lossy(&put.stderr),
    );

    let captured =
        wait_for_substring(&mut sub_out, payload, EXCHANGE_TIMEOUT).unwrap_or_else(|captured| {
            panic!(
                "the REAL zenoh-pico z_sub never reported the payload published by \
                 upstream's z_put.c running on wz's zenoh-c ABI.\n\
                 expected substring: {payload}\n\
                 --- REAL pico z_sub stdout ---\n{captured}\n\
                 --- z_put.c (on wz) stdout ---\n{}",
                String::from_utf8_lossy(&put.stdout),
            )
        });
    assert!(
        captured.contains(key),
        "the foreign subscriber decoded the payload but on a different key than the \
         one wz published ({key}), so wz's outbound keyexpr does not survive the \
         wire.\n--- REAL pico z_sub stdout ---\n{captured}"
    );

    graceful_terminate(sub.child_mut(), Duration::from_secs(5));
}

/// LEG 3 (`wz->pico`) — upstream's `z_delete.c`, running on WZ's C ABI, produces
/// a wire message a REAL zenoh-pico decodes and delivers on the addressed key.
///
/// ## What this leg does NOT prove, stated before what it does
///
/// It does not witness the sample KIND. The intended assertion was that the
/// foreign subscriber prints DELETE where `z_put` prints PUT — and that was
/// written, run, and refuted: the vendored pico `z_sub` prints
/// `Received ('<key>': '<payload>')` and nothing else. A scan of every
/// subscriber example in `vendor/zenoh-pico/examples` (unix, zephyr, windows,
/// freertos, threadx) found no CLI that renders the kind at all, so an
/// empty-payload PUT and a DEL are the SAME two lines at this observer. The
/// foreign CLI hides the property, which is a limit of the oracle rather than of
/// wz, and naming it is cheaper than a leg that reads as proving it.
///
/// The kind MAPPING is covered elsewhere and differently: leg 1 asserts
/// `Received PUT` through upstream's own `kind_to_str`, and R311y500 measured
/// that mapping `SampleKind::Put` to `Z_SAMPLE_KIND_DELETE` reddens leg 1 while
/// leaving legs 2 and 3 green.
///
/// ## What it does prove
///
/// That `z_delete` puts a well-formed Del BODY on the wire. zenoh's Del is a
/// different push body from a Put (`_z_n_msg_make_push_del` carries no payload
/// field), so a foreign decoder that accepts it and delivers a sample on the key
/// has parsed a body wz encoded — a malformed one is dropped in pico's codec and
/// produces no line at all.
///
/// The ordering is OWNED, not slept on: the delete is sent only after the put's
/// line has been observed, and the barrier for the delete
/// (`'<key>': ''`) is a substring the put's line cannot contain, because
/// `wait_for_substring` re-reads the capture from offset 0 and would otherwise
/// answer "has this EVER appeared".
// wz-proves: api-compat-c wz->pico partial
#[test]
#[ignore = "compiles two upstream zenoh-c examples with cc and spawns the real \
            zenoh-pico z_sub CLI; needs the machine-local zenoh-c oracle; \
            run-ci Layer C1cc drives it"]
fn upstream_z_delete_on_wz_capi_c_is_decoded_by_a_real_pico_zsub() {
    let Some((include, _libdir_ref, examples)) = oracle_or_note() else {
        return;
    };
    let dir = tempfile::tempdir().expect("tempdir for the compiled drop-ins");
    let (put_dropin, libdir) = dropin_binary("z_put", dir.path(), &include, &examples);
    let (del_dropin, _) = dropin_binary("z_delete", dir.path(), &include, &examples);
    let z_sub = zenoh_pico_cli_binary("z_sub");

    let reservation = PortReservation::pick();
    let port = reservation.port();
    let endpoint = format!("tcp/127.0.0.1:{port}");
    let payload = "PAYLOAD-BEFORE-THE-DELETE";
    let key = "demo/example/leg3";
    // The delete's line, and it is unique BY CONSTRUCTION: the put above carries
    // a non-empty payload, so only a payload-less sample on this key renders it.
    let deleted_line = format!("'{key}': ''");

    let mut sub_out = tempfile::tempfile().expect("foreign subscriber stdout capture");
    let writer = sub_out.try_clone().expect("dup foreign subscriber handle");
    let mut sub = ChildGuard::wrap(
        "real zenoh-pico z_sub",
        Command::new("stdbuf")
            .args(["-oL", "-eL"])
            .arg(&z_sub)
            .args(["-l", &endpoint, "-m", "peer", "-k", "demo/example/**"])
            .stdout(Stdio::from(writer))
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn the real zenoh-pico z_sub"),
    );

    if let Err(why) = wait_for_tcp_accept_alive(sub.child_mut(), port, LISTEN_TIMEOUT) {
        panic!(
            "the real zenoh-pico z_sub never accepted on {endpoint} — {why}; capture \
             so far:\n{}",
            read_captured(&mut sub_out)
        );
    }
    drop(reservation);

    let put = Command::new("stdbuf")
        .args(["-oL", "-eL"])
        .arg(&put_dropin)
        .args(["-e", &endpoint, "-m", "client", "-k", key, "-p", payload])
        .env("LD_LIBRARY_PATH", &libdir)
        .output()
        .expect("run upstream z_put.c on wz's C ABI");
    assert!(
        put.status.success(),
        "upstream z_put.c on wz's zenoh-c ABI exited {:?}\n--- stderr ---\n{}",
        put.status.code(),
        String::from_utf8_lossy(&put.stderr),
    );

    // The PUT half lands BEFORE the delete is sent — this is the calibration the
    // leg rests on. It establishes that the link carries samples at all, so a
    // missing delete line below is a statement about `z_delete` and not about the
    // session.
    let after_put =
        wait_for_substring(&mut sub_out, payload, EXCHANGE_TIMEOUT).unwrap_or_else(|captured| {
            panic!(
                "the REAL zenoh-pico z_sub never reported the PUT that precedes the \
                 delete, so the calibration this leg rests on was never \
                 established.\n--- REAL pico z_sub stdout ---\n{captured}"
            )
        });
    assert!(
        !after_put.contains(&deleted_line),
        "a payload-less line for {key} appeared BEFORE z_delete ran, so the barrier \
         below would not be evidence of the delete.\n--- stdout ---\n{after_put}"
    );

    let del = Command::new("stdbuf")
        .args(["-oL", "-eL"])
        .arg(&del_dropin)
        .args(["-e", &endpoint, "-m", "client", "-k", key])
        .env("LD_LIBRARY_PATH", &libdir)
        .output()
        .expect("run upstream z_delete.c on wz's C ABI");
    assert!(
        del.status.success(),
        "upstream z_delete.c on wz's zenoh-c ABI exited {:?}\n--- stderr ---\n{}",
        del.status.code(),
        String::from_utf8_lossy(&del.stderr),
    );

    wait_for_substring(&mut sub_out, &deleted_line, EXCHANGE_TIMEOUT).unwrap_or_else(|captured| {
        panic!(
            "the REAL zenoh-pico z_sub never delivered a sample for the key \
             upstream's z_delete.c removed ({key}) — wz's Del body did not survive \
             a foreign decoder, and the foreign decoder is what says so.\n\
             --- REAL pico z_sub stdout ---\n{captured}\n\
             --- z_delete.c (on wz) stdout ---\n{}",
            String::from_utf8_lossy(&del.stdout),
        )
    });

    graceful_terminate(sub.child_mut(), Duration::from_secs(5));
}

/// LEG 4 (`pico->wz`) — upstream's `z_sub.c` on WZ's C ABI renders an ATTACHMENT
/// that a real zenoh-pico publisher attached, carried by a real zenohd.
///
/// ## Why this leg has a router in it when the other three do not
///
/// `z_sample_attachment`'s PRESENT arm needs a foreign publisher that attaches,
/// and the only pico example that does is `z_pub_attachment` — which publishes
/// through a DECLARED PUBLISHER. In the client-to-listening-peer topology legs
/// 1-3 use, that path delivers nothing: not to wz, and not to a real pico either.
///
/// The first reading of that was "a wz ingress defect", and the second was "a
/// pico topology property, so not wz's problem". BOTH were wrong, and the second
/// was wrong in the more dangerous direction: matching pico's behaviour is not
/// the same as being correct, wz aims at a superset rather than a mirror, and
/// two implementations can miss the same observable for unrelated reasons. What
/// settled it was putting a REAL zenohd in the middle and measuring all four
/// arms: pico `z_pub` reaches a pico subscriber through zenohd (3 of 3) and
/// through wz's own `--router-hat` (3 of 3), so the declared-publisher path works
/// and wz forwards it exactly as the reference router does. The earlier failures
/// were the ABSENT ROUTER, which is a fact about the harness and about neither
/// implementation.
///
/// So this leg uses the topology the feature is actually defined in, and gains
/// something the others lack: TWO foreign implementations on the path — pico
/// encodes the attachment, zenohd routes it, and only the rendering is wz's.
///
/// ## What is asserted
///
/// pico's attachment is a `ze_serializer` map, so its bytes are not a chosen
/// string; the field NAMES it serializes (`source`, `index`) survive as literal
/// text and are what upstream's handler prints inside its `(...)` suffix. The
/// negative half is free and load-bearing: legs 1-3 publish with no attachment
/// and their captures carry no `(` suffix at all, so a wz that answered non-NULL
/// unconditionally would redden them.
// wz-proves: api-compat-c pico->wz partial
#[test]
#[ignore = "compiles an upstream zenoh-c example with cc and spawns BOTH the real \
            zenoh-pico z_pub_attachment CLI and a real zenohd; needs the \
            machine-local zenoh-c oracle; run-ci Layer C1cd drives it"]
fn upstream_z_sub_on_wz_capi_c_renders_a_pico_attachment_through_zenohd() {
    let Some((include, _libdir_ref, examples)) = oracle_or_note() else {
        return;
    };
    let dir = tempfile::tempdir().expect("tempdir for the compiled drop-in");
    let (dropin, libdir) = dropin_binary("z_sub", dir.path(), &include, &examples);
    let z_pub_attachment = zenoh_pico_cli_binary("z_pub_attachment");

    let reservation = PortReservation::pick();
    let port = reservation.port();
    let endpoint = format!("tcp/127.0.0.1:{port}");
    let key = "demo/capic/leg4";

    let mut router = spawn_zenohd(port, || {
        tempfile::tempfile().expect("zenohd handshake probe stderr")
    });
    drop(reservation);

    let mut sub_out = tempfile::tempfile().expect("subscriber stdout capture");
    let writer = sub_out.try_clone().expect("dup subscriber stdout handle");
    let mut sub = ChildGuard::wrap(
        "upstream z_sub.c on wz-capi-c",
        Command::new("stdbuf")
            .args(["-oL", "-eL"])
            .arg(&dropin)
            .args(["-e", &endpoint, "-m", "client", "-k", "demo/capic/**"])
            .env("LD_LIBRARY_PATH", &libdir)
            .stdout(Stdio::from(writer))
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn the compiled z_sub drop-in"),
    );

    // The drop-in DIALS, so there is no port of its own to probe. Its own
    // "Declaring Subscriber" line is the barrier, and it is printed after
    // `z_open` returns — so it establishes the session is up, not merely that the
    // process started.
    if let Err(captured) = wait_for_substring(
        &mut sub_out,
        "Declaring Subscriber",
        Duration::from_secs(15),
    ) {
        panic!(
            "upstream z_sub.c on wz's C ABI never reached its declare against \
             zenohd at {endpoint}\n--- capture ---\n{captured}"
        );
    }

    let mut pub_out = tempfile::tempfile().expect("foreign publisher stdout capture");
    let pub_writer = pub_out.try_clone().expect("dup foreign publisher handle");
    let publisher = Command::new("stdbuf")
        .args(["-oL", "-eL"])
        .arg(&z_pub_attachment)
        .args([
            "-e",
            &endpoint,
            "-m",
            "client",
            "-k",
            key,
            "-v",
            "HELLO-ATT",
            "-n",
            "3",
        ])
        .stdout(Stdio::from(pub_writer))
        .stderr(Stdio::null())
        .status()
        .expect("run the real zenoh-pico z_pub_attachment");
    assert!(
        publisher.success(),
        "real zenoh-pico z_pub_attachment exited {publisher:?}\n--- its stdout ---\n{}",
        read_captured(&mut pub_out)
    );

    let captured =
        wait_for_substring(&mut sub_out, key, EXCHANGE_TIMEOUT).unwrap_or_else(|captured| {
            panic!(
                "upstream z_sub.c on wz's zenoh-c ABI never reported the sample the \
                 REAL pico z_pub_attachment published through a REAL zenohd.\n\
                 --- z_sub.c (on wz) stdout ---\n{captured}\n\
                 --- REAL pico publisher stdout ---\n{}",
                read_captured(&mut pub_out)
            )
        });

    // Upstream prints the attachment only when `z_sample_attachment` is non-NULL,
    // so the parenthesised suffix existing at all is the PRESENT arm firing.
    // `source` and `index` are pico's own serializer field names — text wz never
    // chose and could not produce without carrying the foreign bytes through.
    for token in ["source", "index"] {
        assert!(
            captured.contains(token),
            "the sample arrived but wz did not surface the attachment pico attached: \
             upstream's handler prints it only when z_sample_attachment is non-NULL, \
             and {token:?} is a field name pico's serializer wrote.\n\
             --- z_sub.c (on wz) stdout ---\n{captured}"
        );
    }

    graceful_terminate(sub.child_mut(), Duration::from_secs(5));
    let _ = router.child_mut().kill();
}
