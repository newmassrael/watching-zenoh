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

/// LEG 5 (`wz->pico`, DECLARED PUBLISHER) — upstream's `z_pub.c`, running on WZ's
/// C ABI, reaches the REAL zenoh-pico `z_sub`, and its MATCHING LISTENER is told
/// about that foreign subscriber.
///
/// ## Why this leg and not another symbol count
///
/// `z_pub.c` was blocked on nine exports and every one of them can be present and
/// wrong in a way `nm` cannot see. It is the first program on this ABI that
/// exercises FOUR planes at once, and each has a failure mode a link check passes:
///
///   * the PUBLISHER plane (`z_declare_publisher` / `z_publisher_put`) — a
///     declared publisher that dropped its keyexpr, or published on the session's
///     rather than its own, still links;
///   * the PUBLISHER OPTIONS struct — it is TRANSPARENT and stack-allocated, and
///     `z_publisher_put_options_default` writes through a pointer to it. A wrong
///     SIZE corrupts the caller's frame rather than failing anything, which is why
///     the sibling footprint gate measures it against the installed header;
///   * the ENCODING family — `z_encoding_clone(&encoding, z_encoding_text_plain())`
///     then `z_move(encoding)` into the options. A constant whose pointer was not
///     `'static`, or a clone that produced a gravestone, faults here;
///   * the MATCHING plane, which is the half no other leg reaches at all.
///
/// ## The matching verdict is caused by the FOREIGN process
///
/// wz holds N sessions where zenoh-c holds one, so the registry AGGREGATES the
/// per-face verdicts and reports the session's. This leg makes a real zenoh-pico
/// subscriber the cause of the flip: the drop-in prints "Publisher has matching
/// subscribers." only after a foreign `z_sub` has declared a subscription that
/// intersects, over a real TCP link. Nothing wz produced is on either side of that
/// implication.
///
/// Both barriers are read from a process that did not compute them: the payload
/// from the real pico's stdout, the matching line from upstream's own handler
/// text.
// wz-proves: api-compat-c wz->pico partial
#[test]
#[ignore = "compiles an upstream zenoh-c example with cc and spawns the real \
            zenoh-pico z_sub CLI; needs the machine-local zenoh-c oracle; \
            run-ci Layer C1cc drives it"]
fn upstream_z_pub_on_wz_capi_c_reaches_a_real_pico_zsub_and_sees_it_match() {
    let Some((include, _libdir_ref, examples)) = oracle_or_note() else {
        return;
    };
    let dir = tempfile::tempdir().expect("tempdir for the compiled drop-in");
    let (dropin, libdir) = dropin_binary("z_pub", dir.path(), &include, &examples);
    let z_sub = zenoh_pico_cli_binary("z_sub");

    let reservation = PortReservation::pick();
    let port = reservation.port();
    let endpoint = format!("tcp/127.0.0.1:{port}");
    let payload = "PAYLOAD-FROM-UPSTREAM-ZPUB-ON-WZ";
    let key = "demo/example/leg5";

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

    // `z_pub.c` never exits on its own — it publishes once a second until killed —
    // so its stdout is line-buffered and read WHILE it runs, the same shape LEG 1
    // uses for `z_sub.c`.
    let mut pub_out = tempfile::tempfile().expect("drop-in stdout capture");
    let pub_writer = pub_out.try_clone().expect("dup drop-in stdout handle");
    let mut publisher = ChildGuard::wrap(
        "upstream z_pub.c on wz",
        Command::new("stdbuf")
            .args(["-oL", "-eL"])
            .arg(&dropin)
            .args([
                "-e",
                &endpoint,
                "-m",
                "client",
                "-k",
                key,
                "-p",
                payload,
                "--add-matching-listener",
            ])
            .env("LD_LIBRARY_PATH", &libdir)
            .stdout(Stdio::from(pub_writer.try_clone().expect("dup")))
            .stderr(Stdio::from(pub_writer))
            .spawn()
            .expect("run upstream z_pub.c on wz's C ABI"),
    );

    let captured =
        wait_for_substring(&mut sub_out, payload, EXCHANGE_TIMEOUT).unwrap_or_else(|captured| {
            panic!(
                "the REAL zenoh-pico z_sub never reported the payload published by \
                 upstream's z_pub.c through a DECLARED PUBLISHER on wz's zenoh-c \
                 ABI.\nexpected substring: {payload}\n\
                 --- REAL pico z_sub stdout ---\n{captured}\n\
                 --- z_pub.c (on wz) stdout+stderr ---\n{}",
                read_captured(&mut pub_out),
            )
        });
    assert!(
        captured.contains(key),
        "the foreign subscriber decoded the payload but on a different key than the \
         publisher was declared on ({key}), so the DECLARED publisher is not \
         publishing on its own keyexpr.\n--- REAL pico z_sub stdout ---\n{captured}"
    );

    // The matching half. Asserted AFTER the payload so the failure separates: a
    // publish that never arrived reds the barrier above, and a publish that
    // arrived while the listener stayed silent reds only this one.
    let matched = wait_for_substring(
        &mut pub_out,
        "Publisher has matching subscribers.",
        EXCHANGE_TIMEOUT,
    )
    .unwrap_or_else(|captured| {
        panic!(
            "a REAL zenoh-pico subscriber is connected and receiving, but wz never \
             told upstream's matching listener about it, so the aggregated matching \
             verdict never flipped.\n--- z_pub.c (on wz) stdout+stderr ---\n{captured}"
        )
    });
    assert!(
        !matched.contains("NO MORE matching subscribers"),
        "the matching listener reported the subscriber GONE while it is still \
         connected and receiving — the aggregation is inverted or a per-face \
         teardown is leaking through as the session verdict.\n\
         --- z_pub.c (on wz) stdout+stderr ---\n{matched}"
    );

    graceful_terminate(publisher.child_mut(), Duration::from_secs(5));
    graceful_terminate(sub.child_mut(), Duration::from_secs(5));
}

/// LEG 6 (`wz->pico`, LIVELINESS DECLARE) — upstream's `z_liveliness.c`, running
/// on WZ's C ABI, is seen ALIVE by the REAL zenoh-pico `z_sub_liveliness`.
///
/// ## What this leg does NOT prove, stated before what it does
///
/// It does not witness the RETRACTION, and the reason was MEASURED rather than
/// assumed. The first draft asserted that killing the token holder makes the
/// foreign subscriber print "Dropped token"; it red, and the oracle calibration
/// that followed shows the reference cannot do it either. A real zenoh-pico
/// `z_liveliness` against a real zenoh-pico `z_sub_liveliness`, in this same
/// listening-peer topology, produces "New alive token" and then NOTHING when the
/// holder is SIGTERM'd — the token holder has no signal handler, so the process
/// dies before any teardown runs, and the observing pico does not synthesize a
/// deletion from the link death.
///
/// That is a property of the OBSERVER and of the signal, not of wz — but "the
/// reference fails too" is not a defence, so the retraction is not silently
/// dropped: it is proved in the direction where wz IS the observer, by
/// [`upstream_z_sub_liveliness_on_wz_capi_c_sees_a_real_pico_token_come_and_go`].
///
/// ## What it does prove
///
/// That wz's `z_liveliness_declare_token` puts a DeclToken on the wire that a
/// foreign implementation decodes and resolves to the right keyexpr — and that it
/// survives the DECLARE-BEFORE-PEER ordering, since `z_liveliness.c` declares and
/// then sleeps, so the SSOT replay onto the face is what carries it.
// wz-proves: api-compat-c wz->pico partial
#[test]
#[ignore = "compiles an upstream zenoh-c example with cc and spawns the real \
            zenoh-pico z_sub_liveliness CLI; needs the machine-local zenoh-c \
            oracle; run-ci Layer C1cc drives it"]
fn upstream_z_liveliness_on_wz_capi_c_is_seen_alive_by_real_pico() {
    let Some((include, _libdir_ref, examples)) = oracle_or_note() else {
        return;
    };
    let dir = tempfile::tempdir().expect("tempdir for the compiled drop-in");
    let (dropin, libdir) = dropin_binary("z_liveliness", dir.path(), &include, &examples);
    let z_sub_liveliness = zenoh_pico_cli_binary("z_sub_liveliness");

    let reservation = PortReservation::pick();
    let port = reservation.port();
    let endpoint = format!("tcp/127.0.0.1:{port}");
    let key = "demo/liveliness/leg6";

    let mut watcher_out = tempfile::tempfile().expect("foreign watcher stdout capture");
    let writer = watcher_out.try_clone().expect("dup foreign watcher handle");
    let mut watcher = ChildGuard::wrap(
        "real zenoh-pico z_sub_liveliness",
        Command::new("stdbuf")
            .args(["-oL", "-eL"])
            .arg(&z_sub_liveliness)
            .args(["-l", &endpoint, "-m", "peer", "-k", "demo/liveliness/**"])
            .stdout(Stdio::from(writer))
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn the real zenoh-pico z_sub_liveliness"),
    );
    if let Err(why) = wait_for_tcp_accept_alive(watcher.child_mut(), port, LISTEN_TIMEOUT) {
        panic!(
            "the real zenoh-pico z_sub_liveliness never accepted on {endpoint} — \
             {why}; capture so far:\n{}",
            read_captured(&mut watcher_out)
        );
    }
    drop(reservation);

    let mut token_out = tempfile::tempfile().expect("drop-in stdout capture");
    let token_writer = token_out.try_clone().expect("dup drop-in stdout handle");
    let mut token = ChildGuard::wrap(
        "upstream z_liveliness.c on wz",
        Command::new("stdbuf")
            .args(["-oL", "-eL"])
            .arg(&dropin)
            .args(["-e", &endpoint, "-m", "client", "-k", key])
            .env("LD_LIBRARY_PATH", &libdir)
            .stdout(Stdio::from(token_writer.try_clone().expect("dup")))
            .stderr(Stdio::from(token_writer))
            .spawn()
            .expect("run upstream z_liveliness.c on wz's C ABI"),
    );

    let alive = format!(">> [LivelinessSubscriber] New alive token ('{key}')");
    wait_for_substring(&mut watcher_out, &alive, EXCHANGE_TIMEOUT).unwrap_or_else(|captured| {
        panic!(
            "the REAL zenoh-pico z_sub_liveliness never saw the token upstream's \
             z_liveliness.c declared on wz's zenoh-c ABI.\nexpected: {alive}\n\
             --- REAL pico z_sub_liveliness stdout ---\n{captured}\n\
             --- z_liveliness.c (on wz) stdout+stderr ---\n{}",
            read_captured(&mut token_out),
        )
    });

    graceful_terminate(token.child_mut(), Duration::from_secs(5));
    graceful_terminate(watcher.child_mut(), Duration::from_secs(5));
}

/// LEG 7 (`pico->wz`, LIVELINESS RETRACTION) — upstream's `z_sub_liveliness.c`,
/// running on WZ's C ABI, sees a REAL zenoh-pico token come AND go.
///
/// ## This is the leg LEG 6 cannot be
///
/// The retraction edge needs wz to be the OBSERVER, because the token holder that
/// dies cannot report its own death: it is SIGTERM'd with no handler, so nothing
/// runs in that process. What must happen instead is on the observing side — the
/// face dies, and the session has to synthesize the DELETE for every token that
/// face had declared, or a C application is left believing the resource is alive
/// forever.
///
/// That synthesis is `face_down`'s liveliness flush plus its deferred-fire drain
/// (`wz_capi_core::faces`), shared with the zenoh-pico ABI. The drain is the
/// load-bearing half: the registry slot holds a DEFERRED-FIRE staging sink, so a
/// flush alone stages Deletes that nothing delivers — it measures as one slot
/// fired and reaches the application as silence.
///
/// The calibration behind LEG 6 is what makes this leg's verdict meaningful: two
/// real picos in the mirrored arrangement print NOTHING on the holder's death, so
/// a "Dropped token" line here is wz doing something the reference does not, not
/// wz echoing it.
// wz-proves: api-compat-c pico->wz partial
#[test]
#[ignore = "compiles an upstream zenoh-c example with cc and spawns the real \
            zenoh-pico z_liveliness CLI; needs the machine-local zenoh-c oracle; \
            run-ci Layer C1cc drives it"]
fn upstream_z_sub_liveliness_on_wz_capi_c_sees_a_real_pico_token_come_and_go() {
    let Some((include, _libdir_ref, examples)) = oracle_or_note() else {
        return;
    };
    let dir = tempfile::tempdir().expect("tempdir for the compiled drop-in");
    let (dropin, libdir) = dropin_binary("z_sub_liveliness", dir.path(), &include, &examples);
    let z_liveliness = zenoh_pico_cli_binary("z_liveliness");

    let reservation = PortReservation::pick();
    let port = reservation.port();
    let endpoint = format!("tcp/127.0.0.1:{port}");
    let key = "demo/liveliness/leg7";

    // The DROP-IN listens and the foreign token holder dials in, so the face whose
    // death must be noticed is one wz accepted.
    let mut watcher_out = tempfile::tempfile().expect("drop-in stdout capture");
    let writer = watcher_out.try_clone().expect("dup drop-in stdout handle");
    let mut watcher = ChildGuard::wrap(
        "upstream z_sub_liveliness.c on wz",
        Command::new("stdbuf")
            .args(["-oL", "-eL"])
            .arg(&dropin)
            .args(["-l", &endpoint, "-m", "peer", "-k", "demo/liveliness/**"])
            .env("LD_LIBRARY_PATH", &libdir)
            .stdout(Stdio::from(writer.try_clone().expect("dup")))
            .stderr(Stdio::from(writer))
            .spawn()
            .expect("run upstream z_sub_liveliness.c on wz's C ABI"),
    );
    if let Err(why) = wait_for_tcp_accept_alive(watcher.child_mut(), port, LISTEN_TIMEOUT) {
        panic!(
            "upstream z_sub_liveliness.c on wz never accepted on {endpoint} — {why}; \
             capture so far:\n{}",
            read_captured(&mut watcher_out)
        );
    }
    drop(reservation);

    let mut token_out = tempfile::tempfile().expect("foreign token stdout capture");
    let token_writer = token_out.try_clone().expect("dup foreign token handle");
    let mut token = ChildGuard::wrap(
        "real zenoh-pico z_liveliness",
        Command::new("stdbuf")
            .args(["-oL", "-eL"])
            .arg(&z_liveliness)
            .args(["-e", &endpoint, "-m", "client", "-k", key])
            .stdout(Stdio::from(token_writer))
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn the real zenoh-pico z_liveliness"),
    );

    let alive = format!(">> [LivelinessSubscriber] New alive token ('{key}')");
    wait_for_substring(&mut watcher_out, &alive, EXCHANGE_TIMEOUT).unwrap_or_else(|captured| {
        panic!(
            "upstream z_sub_liveliness.c on wz never reported the token a REAL \
             zenoh-pico declared.\nexpected: {alive}\n\
             --- z_sub_liveliness.c (on wz) stdout+stderr ---\n{captured}\n\
             --- REAL pico z_liveliness stdout ---\n{}",
            read_captured(&mut token_out),
        )
    });

    // Kill the FOREIGN holder. Nothing in that process reports the retraction —
    // the observing side has to produce it.
    graceful_terminate(token.child_mut(), Duration::from_secs(5));

    let dropped = format!(">> [LivelinessSubscriber] Dropped token ('{key}')");
    wait_for_substring(&mut watcher_out, &dropped, EXCHANGE_TIMEOUT).unwrap_or_else(|captured| {
        panic!(
            "the REAL zenoh-pico token holder died and wz never told upstream's \
             liveliness callback, so a C application is left believing the resource \
             is still alive. The face-death flush or its deferred-fire drain did not \
             reach the C ABI.\nexpected: {dropped}\n\
             --- z_sub_liveliness.c (on wz) stdout+stderr ---\n{captured}"
        )
    });

    graceful_terminate(watcher.child_mut(), Duration::from_secs(5));
}

// --- R311y539: the QUERY, CHANNEL, SYNC and SERIALIZATION planes ------------
//
// The six legs below exist because `api-compat-c` went from 11 of 22 upstream
// examples linking to 22 of 22, and A LINK IS NOT A PASS. Each drives one of the
// planes that moved the number, against a counterparty outside wz.

/// LEG 8 (`pico->wz`, QUERY INBOUND) — upstream's `z_queryable.c`, running on
/// WZ's C ABI, answers a query issued by the REAL zenoh-pico `z_get`.
///
/// The verdict is the FOREIGN process's: it is the real pico that decodes wz's
/// reply and prints the payload, so a queryable that received the query and then
/// framed its reply wrongly — wrong keyexpr, wrong rid correlation, a
/// `ResponseFinal` before the data — could not produce this line. The inbound
/// half is proved at the same time by the drop-in's own stdout, which prints the
/// selector real pico sent.
// wz-proves: api-compat-c pico->wz partial
#[test]
#[ignore = "compiles an upstream zenoh-c example with cc and spawns the real \
            zenoh-pico z_get CLI; needs the machine-local zenoh-c oracle; \
            run-ci Layer C1cc drives it"]
fn upstream_z_queryable_on_wz_capi_c_answers_a_real_pico_zget() {
    let Some((include, _libdir_ref, examples)) = oracle_or_note() else {
        return;
    };
    let dir = tempfile::tempdir().expect("tempdir for the compiled drop-in");
    let (dropin, libdir) = dropin_binary("z_queryable", dir.path(), &include, &examples);
    let z_get = zenoh_pico_cli_binary("z_get");

    let reservation = PortReservation::pick();
    let port = reservation.port();
    let endpoint = format!("tcp/127.0.0.1:{port}");
    let key = "demo/example/leg8";
    let value = "REPLY-FROM-UPSTREAM-ZQUERYABLE-ON-WZ";

    // The QUERYABLE listens and the foreign querier dials in: that puts the
    // foreign query on the INBOUND path and makes the foreign process the one
    // that renders the reply.
    let mut qbl_out = tempfile::tempfile().expect("drop-in stdout capture");
    let qbl_writer = qbl_out.try_clone().expect("dup drop-in stdout handle");
    let mut queryable = ChildGuard::wrap(
        "upstream z_queryable.c on wz",
        Command::new("stdbuf")
            .args(["-oL", "-eL"])
            .arg(&dropin)
            .args(["-l", &endpoint, "-m", "peer", "-k", key, "-p", value])
            .env("LD_LIBRARY_PATH", &libdir)
            .stdout(Stdio::from(qbl_writer.try_clone().expect("dup")))
            .stderr(Stdio::from(qbl_writer))
            .spawn()
            .expect("run upstream z_queryable.c on wz's C ABI"),
    );
    if let Err(why) = wait_for_tcp_accept_alive(queryable.child_mut(), port, LISTEN_TIMEOUT) {
        panic!(
            "upstream z_queryable.c on wz never accepted on {endpoint} — {why}; \
             capture so far:\n{}",
            read_captured(&mut qbl_out)
        );
    }
    drop(reservation);

    let mut get_out = tempfile::tempfile().expect("foreign querier stdout capture");
    let get_writer = get_out.try_clone().expect("dup foreign querier handle");
    let mut querier = ChildGuard::wrap(
        "real zenoh-pico z_get",
        Command::new("stdbuf")
            .args(["-oL", "-eL"])
            .arg(&z_get)
            .args(["-e", &endpoint, "-m", "client", "-k", key])
            .stdout(Stdio::from(get_writer))
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn the real zenoh-pico z_get"),
    );

    let captured =
        wait_for_substring(&mut get_out, value, EXCHANGE_TIMEOUT).unwrap_or_else(|captured| {
            panic!(
                "the REAL zenoh-pico z_get never reported a reply from upstream's \
                 z_queryable.c on wz's zenoh-c ABI.\nexpected substring: {value}\n\
                 --- REAL pico z_get stdout ---\n{captured}\n\
                 --- z_queryable.c (on wz) stdout+stderr ---\n{}",
                read_captured(&mut qbl_out),
            )
        });
    assert!(
        captured.contains(key),
        "the foreign querier decoded a reply but under a different key than the \
         queryable replied on ({key}), so the reply keyexpr is not surviving the \
         wire.\n--- REAL pico z_get stdout ---\n{captured}"
    );
    // The INBOUND half, asserted separately so the two failures do not merge: a
    // query that never arrived reds here, a reply that never came back reds
    // above.
    let inbound = read_captured(&mut qbl_out);
    assert!(
        inbound.contains("Received Query") && inbound.contains(key),
        "upstream's z_queryable.c never printed the query a REAL pico sent, so the \
         inbound query accessors did not resolve it.\n\
         --- z_queryable.c (on wz) stdout+stderr ---\n{inbound}"
    );

    graceful_terminate(querier.child_mut(), Duration::from_secs(5));
    graceful_terminate(queryable.child_mut(), Duration::from_secs(5));
}

/// LEG 9 (`wz->pico`, QUERY OUTBOUND) — upstream's `z_get.c`, running on WZ's C
/// ABI, queries a REAL zenoh-pico `z_queryable` and renders its reply.
///
/// The mirror of LEG 8, and it exercises the half LEG 8 cannot: the FIFO reply
/// channel is not involved here (`z_get.c` uses a plain closure), but the
/// outbound Query, the rid correlation and the `reply ⊆ query` RECEIVE gate all
/// are — and the payload it prints was chosen and encoded by a foreign process.
// wz-proves: api-compat-c wz->pico partial
#[test]
#[ignore = "compiles an upstream zenoh-c example with cc and spawns the real \
            zenoh-pico z_queryable CLI; needs the machine-local zenoh-c oracle; \
            run-ci Layer C1cc drives it"]
fn upstream_z_get_on_wz_capi_c_is_answered_by_a_real_pico_queryable() {
    let Some((include, _libdir_ref, examples)) = oracle_or_note() else {
        return;
    };
    let dir = tempfile::tempdir().expect("tempdir for the compiled drop-in");
    let (dropin, libdir) = dropin_binary("z_get", dir.path(), &include, &examples);
    let z_queryable = zenoh_pico_cli_binary("z_queryable");

    let reservation = PortReservation::pick();
    let port = reservation.port();
    let endpoint = format!("tcp/127.0.0.1:{port}");
    let key = "demo/example/leg9";
    let value = "REPLY-FROM-REAL-PICO-QUERYABLE";

    let mut qbl_out = tempfile::tempfile().expect("foreign queryable stdout capture");
    let qbl_writer = qbl_out.try_clone().expect("dup foreign queryable handle");
    let mut queryable = ChildGuard::wrap(
        "real zenoh-pico z_queryable",
        Command::new("stdbuf")
            .args(["-oL", "-eL"])
            .arg(&z_queryable)
            .args(["-l", &endpoint, "-m", "peer", "-k", key, "-v", value])
            .stdout(Stdio::from(qbl_writer))
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn the real zenoh-pico z_queryable"),
    );
    if let Err(why) = wait_for_tcp_accept_alive(queryable.child_mut(), port, LISTEN_TIMEOUT) {
        panic!(
            "the real zenoh-pico z_queryable never accepted on {endpoint} — {why}; \
             capture so far:\n{}",
            read_captured(&mut qbl_out)
        );
    }
    drop(reservation);

    // `z_get.c` runs ONCE and exits, so its output is read after it finishes
    // rather than watched while it runs.
    let mut get_out = tempfile::tempfile().expect("drop-in stdout capture");
    let get_writer = get_out.try_clone().expect("dup drop-in stdout handle");
    let mut getter = ChildGuard::wrap(
        "upstream z_get.c on wz",
        Command::new("stdbuf")
            .args(["-oL", "-eL"])
            .arg(&dropin)
            .args(["-e", &endpoint, "-m", "client", "-s", key])
            .env("LD_LIBRARY_PATH", &libdir)
            .stdout(Stdio::from(get_writer.try_clone().expect("dup")))
            .stderr(Stdio::from(get_writer))
            .spawn()
            .expect("run upstream z_get.c on wz's C ABI"),
    );

    let captured =
        wait_for_substring(&mut get_out, value, EXCHANGE_TIMEOUT).unwrap_or_else(|captured| {
            panic!(
                "upstream's z_get.c on wz's zenoh-c ABI never rendered a reply from a \
                 REAL zenoh-pico queryable.\nexpected substring: {value}\n\
                 --- z_get.c (on wz) stdout+stderr ---\n{captured}\n\
                 --- REAL pico z_queryable stdout ---\n{}",
                read_captured(&mut qbl_out),
            )
        });
    assert!(
        captured.contains(key),
        "the drop-in rendered the foreign payload but under a different key, so the \
         reply's keyexpr did not survive the receive path.\n\
         --- z_get.c (on wz) stdout+stderr ---\n{captured}"
    );

    graceful_terminate(getter.child_mut(), Duration::from_secs(5));
    graceful_terminate(queryable.child_mut(), Duration::from_secs(5));
}

/// LEG 10 (`pico->wz`, ESCAPED QUERY) — upstream's
/// `z_queryable_with_channels.c`, running on WZ's C ABI, answers a REAL pico
/// `z_get` from its OWN thread, through a FIFO query channel.
///
/// ## Why this is a different claim from LEG 8
///
/// LEG 8's queryable replies INSIDE the dispatch callback, so the reply is
/// flushed by the same drive-thread job that delivered the query. This one does
/// not: the query is copied out of the callback, queued, and answered from
/// `main` after the callback has long returned. Two things have to hold that LEG
/// 8 never exercises — the escaped query must still know which face and which
/// request id to answer, and the `ResponseFinal` must be WITHHELD until the C
/// side drops it.
///
/// The second is the one with teeth: a `ResponseFinal` emitted when the callback
/// returned would reach the querier BEFORE the reply, and a querier that has seen
/// the final stops listening. So a broken hold does not produce a late reply, it
/// produces NO reply — which is exactly what this leg's barrier catches.
// wz-proves: api-compat-c pico->wz partial
#[test]
#[ignore = "compiles an upstream zenoh-c example with cc and spawns the real \
            zenoh-pico z_get CLI; needs the machine-local zenoh-c oracle; \
            run-ci Layer C1cc drives it"]
fn upstream_z_queryable_with_channels_on_wz_capi_c_answers_from_its_own_thread() {
    let Some((include, _libdir_ref, examples)) = oracle_or_note() else {
        return;
    };
    let dir = tempfile::tempdir().expect("tempdir for the compiled drop-in");
    let (dropin, libdir) =
        dropin_binary("z_queryable_with_channels", dir.path(), &include, &examples);
    let z_get = zenoh_pico_cli_binary("z_get");

    let reservation = PortReservation::pick();
    let port = reservation.port();
    let endpoint = format!("tcp/127.0.0.1:{port}");
    let key = "demo/example/leg10";
    let value = "REPLY-FROM-A-CHANNEL-QUERYABLE-ON-WZ";

    let mut qbl_out = tempfile::tempfile().expect("drop-in stdout capture");
    let qbl_writer = qbl_out.try_clone().expect("dup drop-in stdout handle");
    let mut queryable = ChildGuard::wrap(
        "upstream z_queryable_with_channels.c on wz",
        Command::new("stdbuf")
            .args(["-oL", "-eL"])
            .arg(&dropin)
            .args(["-l", &endpoint, "-m", "peer", "-k", key, "-p", value])
            .env("LD_LIBRARY_PATH", &libdir)
            .stdout(Stdio::from(qbl_writer.try_clone().expect("dup")))
            .stderr(Stdio::from(qbl_writer))
            .spawn()
            .expect("run upstream z_queryable_with_channels.c on wz's C ABI"),
    );
    if let Err(why) = wait_for_tcp_accept_alive(queryable.child_mut(), port, LISTEN_TIMEOUT) {
        panic!(
            "the channel queryable on wz never accepted on {endpoint} — {why}; \
             capture so far:\n{}",
            read_captured(&mut qbl_out)
        );
    }
    drop(reservation);

    let mut get_out = tempfile::tempfile().expect("foreign querier stdout capture");
    let get_writer = get_out.try_clone().expect("dup foreign querier handle");
    let mut querier = ChildGuard::wrap(
        "real zenoh-pico z_get",
        Command::new("stdbuf")
            .args(["-oL", "-eL"])
            .arg(&z_get)
            .args(["-e", &endpoint, "-m", "client", "-k", key])
            .stdout(Stdio::from(get_writer))
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn the real zenoh-pico z_get"),
    );

    let captured =
        wait_for_substring(&mut get_out, value, EXCHANGE_TIMEOUT).unwrap_or_else(|captured| {
            panic!(
                "the REAL zenoh-pico z_get never reported a reply from a query the \
                 drop-in answered OFF the dispatch thread. Either the escaped query \
                 lost its face/rid, or the ResponseFinal went out when the callback \
                 returned — in which case the querier stopped listening before the \
                 reply arrived.\nexpected substring: {value}\n\
                 --- REAL pico z_get stdout ---\n{captured}\n\
                 --- channel queryable (on wz) stdout+stderr ---\n{}",
                read_captured(&mut qbl_out),
            )
        });
    assert!(
        captured.contains(key),
        "the foreign querier decoded a reply under the wrong key.\n\
         --- REAL pico z_get stdout ---\n{captured}"
    );

    graceful_terminate(querier.child_mut(), Duration::from_secs(5));
    graceful_terminate(queryable.child_mut(), Duration::from_secs(5));
}

/// LEG 11 (`pico->wz`, RING CHANNEL + OWNED SAMPLE) — upstream's `z_pull.c`,
/// running on WZ's C ABI, pulls a sample published by the REAL zenoh-pico
/// `z_put` out of a ring channel.
///
/// The plane under test is the one nothing else drives: a sample ESCAPES its
/// callback into a ring buffer, is handed back as a `z_owned_sample_t` on the
/// application thread, and is read there through `z_sample_loan`. A sample whose
/// cached loaned views were copied rather than re-bound would print garbage or
/// crash here, because the callback frame they pointed into is long gone.
///
/// `z_pull.c` polls on `getchar`, so the newline this feeds it IS the pull.
// wz-proves: api-compat-c pico->wz partial
#[test]
#[ignore = "compiles an upstream zenoh-c example with cc and spawns the real \
            zenoh-pico z_put CLI; needs the machine-local zenoh-c oracle; \
            run-ci Layer C1cc drives it"]
fn upstream_z_pull_on_wz_capi_c_pulls_a_real_pico_sample_out_of_a_ring() {
    use std::io::Write;

    let Some((include, _libdir_ref, examples)) = oracle_or_note() else {
        return;
    };
    let dir = tempfile::tempdir().expect("tempdir for the compiled drop-in");
    let (dropin, libdir) = dropin_binary("z_pull", dir.path(), &include, &examples);
    let z_put = zenoh_pico_cli_binary("z_put");

    let reservation = PortReservation::pick();
    let port = reservation.port();
    let endpoint = format!("tcp/127.0.0.1:{port}");
    let key = "demo/example/leg11";
    let payload = "PAYLOAD-PULLED-OUT-OF-A-RING-ON-WZ";

    let mut pull_out = tempfile::tempfile().expect("drop-in stdout capture");
    let pull_writer = pull_out.try_clone().expect("dup drop-in stdout handle");
    let mut puller = ChildGuard::wrap(
        "upstream z_pull.c on wz",
        Command::new("stdbuf")
            .args(["-oL", "-eL"])
            .arg(&dropin)
            .args(["-l", &endpoint, "-m", "peer", "-k", "demo/example/**"])
            .env("LD_LIBRARY_PATH", &libdir)
            .stdin(Stdio::piped())
            .stdout(Stdio::from(pull_writer.try_clone().expect("dup")))
            .stderr(Stdio::from(pull_writer))
            .spawn()
            .expect("run upstream z_pull.c on wz's C ABI"),
    );
    if let Err(why) = wait_for_tcp_accept_alive(puller.child_mut(), port, LISTEN_TIMEOUT) {
        panic!(
            "upstream z_pull.c on wz never accepted on {endpoint} — {why}; capture so \
             far:\n{}",
            read_captured(&mut pull_out)
        );
    }
    drop(reservation);

    let mut put_out = tempfile::tempfile().expect("foreign publisher stdout capture");
    let put_writer = put_out.try_clone().expect("dup foreign publisher handle");
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
        "the real zenoh-pico z_put failed: {put}\n{}",
        read_captured(&mut put_out)
    );

    // Feed newlines until the sample surfaces: each one is a `getchar` that
    // makes the program `z_try_recv` the ring. A single newline would race the
    // sample's arrival, and a sleep-then-one-newline would only move the race —
    // so the pull is REPEATED until the barrier or the timeout, which is what
    // makes the leg a wait rather than a guess.
    let mut stdin = puller
        .child_mut()
        .stdin
        .take()
        .expect("z_pull.c was spawned with a piped stdin");
    let deadline = std::time::Instant::now() + EXCHANGE_TIMEOUT;
    let captured = loop {
        let _ = stdin.write_all(b"\n");
        let _ = stdin.flush();
        if let Ok(text) = wait_for_substring(&mut pull_out, payload, Duration::from_millis(300)) {
            break text;
        }
        if std::time::Instant::now() >= deadline {
            panic!(
                "upstream z_pull.c on wz never pulled the sample a REAL zenoh-pico \
                 z_put published out of its ring channel.\nexpected substring: \
                 {payload}\n--- z_pull.c (on wz) stdout+stderr ---\n{}\n\
                 --- REAL pico z_put stdout ---\n{}",
                read_captured(&mut pull_out),
                read_captured(&mut put_out),
            );
        }
    };
    assert!(
        captured.contains(key),
        "the drop-in pulled a sample but rendered the wrong keyexpr, so the OWNED \
         sample's cached views are not pointing at its own fields.\n\
         --- z_pull.c (on wz) stdout+stderr ---\n{captured}"
    );

    graceful_terminate(puller.child_mut(), Duration::from_secs(5));
}

/// LEG 12 (SERIALIZATION, TWICE-AND-DIFF) — upstream's `z_bytes.c`, compiled
/// ONCE and linked BOTH ways, must produce the SAME stdout and both must exit 0.
///
/// ## Why this shape rather than a wz-side round trip
///
/// `z_bytes.c` is self-asserting: it carries `#undef NDEBUG` and asserts every
/// round trip, so running it on wz already proves the serializer and the
/// deserializer agree WITH EACH OTHER. That is exactly the proof a
/// permutation-invariant round trip gives, and it is not the claim — an
/// implementation that wrote every integer as a VLE would pass it and be
/// unreadable by a real peer.
///
/// So the same program is linked against the REAL `libzenohc.so` too and the two
/// stdouts are diffed. The slice-iterator section is what makes that diff sharp:
/// it prints one line per slice, so a payload built from three
/// `z_bytes_writer_append` calls prints three lines upstream and would print ONE
/// from an implementation that flattened the arrangement — while every assert in
/// the file still passed.
// wz-proves: none -- there is no WIRE here and no foreign counterparty process.
// Both arms run in-process against a library; the leg is a differential between
// two IMPLEMENTATIONS of the same header, not an exchange between two peers, so
// it witnesses no cross-impl transport direction. It is still the sharpest check
// this repo has on the SERIALIZATION FORMAT, which no wire leg exercises: the
// query and pubsub legs carry opaque payloads that neither end interprets.
#[test]
#[ignore = "compiles an upstream zenoh-c example with cc and links it against \
            BOTH wz's cdylib and the real libzenohc.so; needs the machine-local \
            zenoh-c oracle; run-ci Layer C1cc drives it"]
fn upstream_z_bytes_on_wz_capi_c_prints_identically_to_real_libzenohc() {
    let Some((include, libdir_ref, examples)) = oracle_or_note() else {
        return;
    };
    let dir = tempfile::tempdir().expect("tempdir for the compiled programs");
    let (on_wz, wz_libdir) = dropin_binary("z_bytes", dir.path(), &include, &examples);
    let ref_dir = dir.path().join("reference");
    std::fs::create_dir_all(&ref_dir).expect("reference build dir");
    let on_ref = compile_zenoh_c_example(
        "z_bytes",
        &ref_dir,
        &include,
        &examples,
        &libdir_ref,
        "zenohc",
    )
    .unwrap_or_else(|diag| {
        panic!("upstream z_bytes.c does not link against the REAL libzenohc.so\n{diag}")
    });

    let run = |exe: &Path, libdir: &Path| -> (bool, String) {
        let out = Command::new(exe)
            .env("LD_LIBRARY_PATH", libdir)
            .output()
            .unwrap_or_else(|why| panic!("spawn {}: {why}", exe.display()));
        (
            out.status.success(),
            String::from_utf8_lossy(&out.stdout).into_owned(),
        )
    };
    let (wz_ok, wz_stdout) = run(&on_wz, &wz_libdir);
    let (ref_ok, ref_stdout) = run(&on_ref, &libdir_ref);

    assert!(
        ref_ok,
        "the REFERENCE arm failed, so this machine's oracle cannot serve as one \
         here — the comparison below would be meaningless.\n{ref_stdout}"
    );
    assert!(
        wz_ok,
        "upstream's z_bytes.c ABORTED on wz's C ABI. The file asserts every \
         serialization round trip with NDEBUG undefined, so a non-zero exit is a \
         round trip that did not hold.\n--- stdout on wz ---\n{wz_stdout}"
    );
    assert_eq!(
        wz_stdout, ref_stdout,
        "upstream's z_bytes.c prints DIFFERENT output on wz's C ABI than on the \
         real libzenohc.so. Both arms' asserts passed, so this is a difference the \
         round trips cannot see — the slice-iterator section is the likely one: a \
         payload built from three appends must iterate as THREE slices, not one.\n\
         --- stdout on wz ---\n{wz_stdout}\n--- stdout on real libzenohc ---\n{ref_stdout}"
    );
    assert!(
        wz_stdout.contains("slice len: 3"),
        "neither arm printed a slice line, so the diff above compared two empty \
         outputs and proved nothing about the slice arrangement.\n{wz_stdout}"
    );
}

/// LEG 13 (`wz->pico`, MUTEX + CONDVAR) — upstream's `z_ping.c`, running on WZ's
/// C ABI, completes its round trips against the REAL zenoh-pico `z_pong`.
///
/// The plane under test is [`wz_capi_c::sync`](../../wz-capi-c/src/sync.rs): the
/// program publishes on `ping`, then BLOCKS on a condvar that its own subscriber
/// callback signals when `pong` comes back. A condvar whose signal could be lost
/// between the mutex release and the wait would hang here rather than fail —
/// which is why the leg's failure message says so, and why the binary is given a
/// bounded run rather than being waited on forever.
// wz-proves: api-compat-c wz->pico partial
#[test]
#[ignore = "compiles an upstream zenoh-c example with cc and spawns the real \
            zenoh-pico z_pong CLI; needs the machine-local zenoh-c oracle; \
            run-ci Layer C1cc drives it"]
fn upstream_z_ping_on_wz_capi_c_round_trips_against_a_real_pico_pong() {
    let Some((include, _libdir_ref, examples)) = oracle_or_note() else {
        return;
    };
    let dir = tempfile::tempdir().expect("tempdir for the compiled drop-in");
    let (dropin, libdir) = dropin_binary("z_ping", dir.path(), &include, &examples);
    let z_pong = zenoh_pico_cli_binary("z_pong");

    let reservation = PortReservation::pick();
    let port = reservation.port();
    let endpoint = format!("tcp/127.0.0.1:{port}");

    let mut pong_out = tempfile::tempfile().expect("foreign pong stdout capture");
    let pong_writer = pong_out.try_clone().expect("dup foreign pong handle");
    let mut pong = ChildGuard::wrap(
        "real zenoh-pico z_pong",
        Command::new("stdbuf")
            .args(["-oL", "-eL"])
            .arg(&z_pong)
            .args(["-l", &endpoint, "-m", "peer"])
            .stdout(Stdio::from(pong_writer))
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn the real zenoh-pico z_pong"),
    );
    if let Err(why) = wait_for_tcp_accept_alive(pong.child_mut(), port, LISTEN_TIMEOUT) {
        panic!(
            "the real zenoh-pico z_pong never accepted on {endpoint} — {why}; capture \
             so far:\n{}",
            read_captured(&mut pong_out)
        );
    }
    drop(reservation);

    let mut ping_out = tempfile::tempfile().expect("drop-in stdout capture");
    let ping_writer = ping_out.try_clone().expect("dup drop-in stdout handle");
    let mut ping = ChildGuard::wrap(
        "upstream z_ping.c on wz",
        Command::new("stdbuf")
            .args(["-oL", "-eL"])
            .arg(&dropin)
            // The payload size is a POSITIONAL argument, not a flag; `-n` is the
            // number of pings and `-w` the warmup. The warmup is shortened from
            // its one-second default so the leg's own timeout is not mostly
            // spent inside it.
            .args([
                "-e", &endpoint, "-m", "client", "-n", "4", "-w", "300", "64",
            ])
            .env("LD_LIBRARY_PATH", &libdir)
            .stdout(Stdio::from(ping_writer.try_clone().expect("dup")))
            .stderr(Stdio::from(ping_writer))
            .spawn()
            .expect("run upstream z_ping.c on wz's C ABI"),
    );

    // `z_ping.c` prints one `<size> bytes: seq=<n> ...` line per completed round
    // trip. Waiting for seq=3 rather than seq=0 is deliberate: the FIRST wait can
    // be satisfied by a signal that happened to arrive late, while the fourth
    // requires the condvar to work every time.
    let captured =
        wait_for_substring(&mut ping_out, "seq=3", EXCHANGE_TIMEOUT).unwrap_or_else(|captured| {
            panic!(
                "upstream z_ping.c on wz's C ABI did not complete four round trips \
                 against a REAL zenoh-pico z_pong. A LOST condvar signal shows up \
                 here as a HANG, not as a wrong number — the program is blocked in \
                 z_condvar_wait with the pong already delivered.\n\
                 --- z_ping.c (on wz) stdout+stderr ---\n{captured}\n\
                 --- REAL pico z_pong stdout ---\n{}",
                read_captured(&mut pong_out),
            )
        });
    assert!(
        captured.contains("seq=0"),
        "the fourth round trip completed but the first was never reported, so the \
         output is not the per-round-trip sequence this leg reads it as.\n{captured}"
    );

    graceful_terminate(ping.child_mut(), Duration::from_secs(5));
    graceful_terminate(pong.child_mut(), Duration::from_secs(5));
}

/// LEG 14 (`wz->pico`, PUT-OPTIONS ENCODING) — upstream's `z_pub.c`, running on
/// WZ's C ABI, puts a `text/plain` encoding on the wire and the REAL zenoh-pico
/// `z_sub_attachment` prints it back.
///
/// ## What was wrong, and why LEG 5 could not see it
///
/// `z_pub.c` sets `options.encoding = z_move(z_encoding_text_plain())` on EVERY
/// put — it is not behind a flag. Until R311y545 wz accepted that field and
/// dropped it, so the program was correct about the API and wrong about the
/// wire, and `wz-capi-c/src/encoding.rs` said so in its own module doc. LEG 5
/// runs the same binary against a real pico and passes either way, because the
/// stock `z_sub` prints the payload and not the encoding.
///
/// The observer is what makes this a different question. `z_sub_attachment`
/// prints `with encoding: <label>` from `z_encoding_to_string(z_sample_encoding(
/// sample))` — its own stock line, no build-time patch involved — and a dropped
/// encoding decodes as pico's default `zenoh/bytes`. So the two outcomes are
/// distinct strings produced by a foreign implementation, not by anything wz
/// computed.
///
/// ## Why `text/plain` discriminates
///
/// The label is the zenoh wire id 4, which wz packs as `4 << 1 = 8` through the
/// ABI-neutral table in `wz-capi-core::encoding_ids` — the same table
/// `wz-capi-pico` pins against the real `libzenohpico.so`. A wz that emitted the
/// wrong id would print some OTHER label here rather than nothing, and a wz that
/// emitted no encoding at all prints `zenoh/bytes`. Both failure modes are
/// visible, which is why the assertion is on the exact line rather than on the
/// absence of the default.
// wz-proves: api-compat-c wz->pico partial
#[test]
#[ignore = "compiles an upstream zenoh-c example with cc and spawns the real \
            zenoh-pico z_sub_attachment CLI; needs the machine-local zenoh-c \
            oracle; run-ci Layer C1cc drives it"]
fn upstream_z_pub_on_wz_capi_c_carries_its_put_encoding_to_a_real_pico() {
    let Some((include, _libdir_ref, examples)) = oracle_or_note() else {
        return;
    };
    let dir = tempfile::tempdir().expect("tempdir for the compiled drop-in");
    let (dropin, libdir) = dropin_binary("z_pub", dir.path(), &include, &examples);
    let z_sub = zenoh_pico_cli_binary("z_sub_attachment");

    let reservation = PortReservation::pick();
    let port = reservation.port();
    let endpoint = format!("tcp/127.0.0.1:{port}");
    let payload = "PAYLOAD-FROM-UPSTREAM-ZPUB-WITH-ENCODING";
    let key = "demo/example/leg14";

    let mut sub_out = tempfile::tempfile().expect("foreign subscriber stdout capture");
    let writer = sub_out.try_clone().expect("dup foreign subscriber handle");
    let mut sub = ChildGuard::wrap(
        "real zenoh-pico z_sub_attachment",
        Command::new("stdbuf")
            .args(["-oL", "-eL"])
            .arg(&z_sub)
            .args(["-l", &endpoint, "-m", "peer", "-k", "demo/example/**"])
            .stdout(Stdio::from(writer))
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn the real zenoh-pico z_sub_attachment"),
    );
    if let Err(why) = wait_for_tcp_accept_alive(sub.child_mut(), port, LISTEN_TIMEOUT) {
        panic!(
            "the real zenoh-pico z_sub_attachment never accepted on {endpoint} — {why}; \
             capture so far:\n{}",
            read_captured(&mut sub_out)
        );
    }
    drop(reservation);

    let mut pub_out = tempfile::tempfile().expect("drop-in stdout capture");
    let pub_writer = pub_out.try_clone().expect("dup drop-in stdout handle");
    let mut publisher = ChildGuard::wrap(
        "upstream z_pub.c on wz",
        Command::new("stdbuf")
            .args(["-oL", "-eL"])
            .arg(&dropin)
            .args(["-e", &endpoint, "-m", "client", "-k", key, "-p", payload])
            .env("LD_LIBRARY_PATH", &libdir)
            .stdout(Stdio::from(pub_writer.try_clone().expect("dup")))
            .stderr(Stdio::from(pub_writer))
            .spawn()
            .expect("run upstream z_pub.c on wz's C ABI"),
    );

    // The payload barrier FIRST, so the two failures separate: a sample that
    // never arrived reds here, and a sample that arrived with the encoding
    // stripped reds only on the line below.
    let captured =
        wait_for_substring(&mut sub_out, payload, EXCHANGE_TIMEOUT).unwrap_or_else(|captured| {
            panic!(
                "the REAL zenoh-pico z_sub_attachment never reported the payload \
                 published by upstream's z_pub.c on wz's zenoh-c ABI.\n\
                 expected substring: {payload}\n\
                 --- REAL pico z_sub_attachment stdout ---\n{captured}\n\
                 --- z_pub.c (on wz) stdout+stderr ---\n{}",
                read_captured(&mut pub_out),
            )
        });
    let encoding_witness = "with encoding: text/plain";
    let captured = if captured.contains(encoding_witness) {
        captured
    } else {
        wait_for_substring(&mut sub_out, encoding_witness, EXCHANGE_TIMEOUT).unwrap_or_else(
            |captured| {
                panic!(
                    "a REAL zenoh-pico decoded the sample but NOT the encoding \
                     upstream's z_pub.c set on it. `z_pub.c` assigns \
                     `options.encoding = z_move(z_encoding_text_plain())` on every put, \
                     so wz accepted the field and dropped it — the sample arrived with \
                     pico's default, which prints `with encoding: zenoh/bytes`.\n\
                     expected substring: {encoding_witness}\n\
                     --- REAL pico z_sub_attachment stdout ---\n{captured}\n\
                     --- z_pub.c (on wz) stdout+stderr ---\n{}",
                    read_captured(&mut pub_out),
                )
            },
        )
    };
    assert!(
        captured.contains(key),
        "the foreign subscriber decoded the sample but on a different key than the \
         publisher was declared on ({key}).\n\
         --- REAL pico z_sub_attachment stdout ---\n{captured}"
    );

    graceful_terminate(publisher.child_mut(), Duration::from_secs(5));
    graceful_terminate(sub.child_mut(), Duration::from_secs(5));
}

/// LEG 15 (`wz->pico`, PUBLISHER-OPTIONS QoS) — upstream's `z_pub_thr.c`, running
/// on WZ's C ABI, puts its DECLARE-TIME priority, congestion control and express
/// bits on the wire, and the REAL zenoh-pico `z_sub_attachment` decodes all three.
///
/// ## The struct this leg exists for
///
/// `z_pub_thr.c` is the only upstream example that populates
/// `z_publisher_options_t`, and it populates exactly the three fields that reach
/// the wire:
///
/// ```c
/// options.congestion_control = Z_CONGESTION_CONTROL_BLOCK;
/// options.priority = args.priority;   // -p
/// options.is_express = args.express;  // --express
/// ```
///
/// Until R311y545 `z_declare_publisher` took `_options` and ignored it, so all
/// three were dropped. They ride ONE packed QoS byte (priority in the low 3
/// bits, `nodrop` at bit 3, express at bit 4), which is why one leg witnessing
/// all three is honest rather than three legs each witnessing a third: the byte
/// is one compile unit (`pubsub-qos`) and one wire extension.
///
/// ## Why these three values discriminate
///
/// pico's default sample QoS is `_Z_N_QOS_DEFAULT._val = 5` — priority `Data`
/// (5), congestion DROP (0), express false (0). This leg asks for
/// `Z_PRIORITY_REAL_TIME` (1) and `--express`, and `z_pub_thr.c` hard-codes
/// BLOCK. A wz that dropped the struct prints `1`/`0`/`0` on the wire's default
/// path — i.e. `with priority: 5`, `with congestion: 0`, `with express: 0` — so
/// every one of the three assertions separates "propagated" from "dropped".
///
/// Note the enum inversion this leg is downstream of: zenoh-c's
/// `Z_CONGESTION_CONTROL_BLOCK` is **0** and pico's `z_sample_congestion_control`
/// returns **1** for the same meaning. The C side says 0, the observing pico says
/// 1, and both are right — which is precisely the mapping R311y545 had wrong.
///
/// ## The publisher is a THROUGHPUT loop, and that is handled rather than hoped
///
/// `z_pub_thr.c` publishes in a tight `while (1)`, so it is spawned LAST, its
/// payload is the smallest useful size, and it is terminated the moment the
/// witness lands. The subscriber's stdout is a temp file rather than a pipe for
/// the same reason: a full pipe buffer would block the writer instead of the
/// test.
// wz-proves: api-compat-c wz->pico partial
#[test]
#[ignore = "compiles an upstream zenoh-c example with cc and spawns the real \
            zenoh-pico z_sub_attachment CLI; needs the machine-local zenoh-c \
            oracle; run-ci Layer C1cc drives it"]
fn upstream_z_pub_thr_on_wz_capi_c_carries_its_publisher_qos_to_a_real_pico() {
    let Some((include, _libdir_ref, examples)) = oracle_or_note() else {
        return;
    };
    let dir = tempfile::tempdir().expect("tempdir for the compiled drop-in");
    let (dropin, libdir) = dropin_binary("z_pub_thr", dir.path(), &include, &examples);
    let z_sub = zenoh_pico_cli_binary("z_sub_attachment");

    let reservation = PortReservation::pick();
    let port = reservation.port();
    let endpoint = format!("tcp/127.0.0.1:{port}");
    // `z_pub_thr.c` hard-codes its keyexpr; the subscriber has to meet it there.
    let key = "test/thr";

    let mut sub_out = tempfile::tempfile().expect("foreign subscriber stdout capture");
    let writer = sub_out.try_clone().expect("dup foreign subscriber handle");
    let mut sub = ChildGuard::wrap(
        "real zenoh-pico z_sub_attachment",
        Command::new("stdbuf")
            .args(["-oL", "-eL"])
            .arg(&z_sub)
            .args(["-l", &endpoint, "-m", "peer", "-k", key])
            .stdout(Stdio::from(writer))
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn the real zenoh-pico z_sub_attachment"),
    );
    if let Err(why) = wait_for_tcp_accept_alive(sub.child_mut(), port, LISTEN_TIMEOUT) {
        panic!(
            "the real zenoh-pico z_sub_attachment never accepted on {endpoint} — {why}; \
             capture so far:\n{}",
            read_captured(&mut sub_out)
        );
    }
    drop(reservation);

    let mut pub_out = tempfile::tempfile().expect("drop-in stdout capture");
    let pub_writer = pub_out.try_clone().expect("dup drop-in stdout handle");
    let mut publisher = ChildGuard::wrap(
        "upstream z_pub_thr.c on wz",
        Command::new("stdbuf")
            .args(["-oL", "-eL"])
            .arg(&dropin)
            .args(["-e", &endpoint, "-m", "client", "-p", "1", "--express", "8"])
            .env("LD_LIBRARY_PATH", &libdir)
            .stdout(Stdio::from(pub_writer.try_clone().expect("dup")))
            .stderr(Stdio::from(pub_writer))
            .spawn()
            .expect("run upstream z_pub_thr.c on wz's C ABI"),
    );

    // Each of the three is waited for on its own line, in the order a failure
    // would be most informative: arrival first, then the three sub-fields.
    let mut captured =
        wait_for_substring(&mut sub_out, ">> [Subscriber] Received", EXCHANGE_TIMEOUT)
            .unwrap_or_else(|captured| {
                graceful_terminate(publisher.child_mut(), Duration::from_secs(2));
                panic!(
                    "the REAL zenoh-pico z_sub_attachment never received anything from \
                 upstream's z_pub_thr.c on wz's zenoh-c ABI.\n\
                 --- REAL pico z_sub_attachment stdout ---\n{captured}\n\
                 --- z_pub_thr.c (on wz) stdout+stderr ---\n{}",
                    read_captured(&mut pub_out),
                )
            });
    for (witness, dropped) in [
        ("with priority: 1", "with priority: 5"),
        ("with congestion: 1", "with congestion: 0"),
        ("with express: 1", "with express: 0"),
    ] {
        if !captured.contains(witness) {
            captured = wait_for_substring(&mut sub_out, witness, EXCHANGE_TIMEOUT).unwrap_or_else(
                |captured| {
                    graceful_terminate(publisher.child_mut(), Duration::from_secs(2));
                    panic!(
                        "a REAL zenoh-pico received the samples but NOT the QoS \
                         `z_pub_thr.c` set on its DECLARED PUBLISHER. All three \
                         sub-fields ride one packed byte, so a dropped \
                         `z_publisher_options_t` prints pico's defaults instead.\n\
                         expected substring: {witness}   (dropped would print: {dropped})\n\
                         --- REAL pico z_sub_attachment stdout (tail) ---\n{}\n\
                         --- z_pub_thr.c (on wz) stdout+stderr ---\n{}",
                        captured
                            .chars()
                            .rev()
                            .take(4000)
                            .collect::<String>()
                            .chars()
                            .rev()
                            .collect::<String>(),
                        read_captured(&mut pub_out),
                    )
                },
            );
        }
    }

    graceful_terminate(publisher.child_mut(), Duration::from_secs(5));
    graceful_terminate(sub.child_mut(), Duration::from_secs(5));
}

/// LEG 16 (`wz->pico`, REPLY-OPTIONS ENCODING) — a queryable on WZ's C ABI sets
/// `z_query_reply_options_t::encoding`, and the REAL zenoh-pico
/// `z_get_attachment` prints the label it decoded off the reply.
///
/// ## Why this leg is a DIFFERENTIAL and the sibling legs are not
///
/// Every other `wz->pico` leg in this file drives an UPSTREAM example, because
/// a wz-authored program calls only what wz exports and that bias is exactly
/// what the corpus rule exists to remove. No upstream example sets a reply
/// encoding — `z_queryable.c` takes `z_query_reply_options_default` and touches
/// nothing — so an upstream driver cannot reach this field at all.
///
/// The answer is not to write a wz-authored program and trust it: it is to
/// compile ONE wz-authored source TWICE, against wz's cdylib and against the
/// real `libzenohc.so`, put a real zenoh-pico on the far side of BOTH, and
/// compare what the FOREIGN process printed. Anything wz-flavoured about the
/// driver appears identically on both arms and cancels; what survives the
/// subtraction is a disagreement between the two implementations, adjudicated
/// by a third. That is the same argument the option-defaults differential
/// makes, with a foreign observer added.
///
/// ## What was wrong
///
/// `wz-capi-c`'s `z_query_reply` took the options struct, TOOK its attachment,
/// and dropped its encoding on the floor — `flush_one` passed a literal `None`
/// into `ReplyOut::reply_keyed_attached`'s encoding slot. That slot has carried
/// a real value since the storage per-version reply landed, so the wire path
/// was there the whole time and nothing fed it. A queryable that set
/// `text/plain` answered with `zenoh/bytes`.
///
/// pico's `z_get_attachment.c` prints `with encoding: <label>` per reply from
/// its own stock handler — no build-time patch involved — so the two outcomes
/// are distinct strings produced by a foreign implementation.
// wz-proves: api-compat-c wz->pico partial
#[test]
#[ignore = "compiles a C driver against wz's cdylib AND the real libzenohc.so \
            and spawns the real zenoh-pico z_get_attachment CLI; needs the \
            machine-local zenoh-c oracle; run-ci Layer C1cc drives it"]
fn a_wz_capi_c_queryable_reply_encoding_reaches_a_real_pico_as_it_does_on_libzenohc() {
    let Some((include, libdir_ref, examples)) = oracle_or_note() else {
        return;
    };
    let dir = tempfile::tempdir().expect("tempdir for the compiled drivers");
    let src_dir = dir.path().join("src");
    std::fs::create_dir_all(&src_dir).expect("driver source dir");
    // Upstream's own `parse_args.h` is copied beside the driver so the driver
    // can use the SAME argument and config handling every example in the corpus
    // uses — the endpoint / mode plumbing is then upstream's, not this test's.
    std::fs::copy(examples.join("parse_args.h"), src_dir.join("parse_args.h"))
        .expect("upstream parse_args.h is part of the examples clone");
    std::fs::write(
        src_dir.join("wz_reply_encoding.c"),
        r#"#include <stdio.h>
#include <string.h>

#include "parse_args.h"
#include "zenoh.h"

static const char *REPLY_VALUE = "REPLY-CARRYING-AN-ENCODING";

void query_handler(z_loaned_query_t *query, void *context) {
    z_query_reply_options_t options;
    z_query_reply_options_default(&options);
    // The field this driver exists for. Everything else is defaults.
    z_owned_encoding_t encoding;
    z_encoding_clone(&encoding, z_encoding_text_plain());
    options.encoding = z_move(encoding);

    z_owned_bytes_t reply_payload;
    z_bytes_copy_from_str(&reply_payload, REPLY_VALUE);
    z_view_keyexpr_t reply_keyexpr;
    z_view_keyexpr_from_str(&reply_keyexpr, (const char *)context);
    printf(">> [Queryable ] Responding with text/plain\n");
    fflush(stdout);
    z_query_reply(query, z_loan(reply_keyexpr), z_move(reply_payload), &options);
}

int main(int argc, char **argv) {
    zc_init_log_from_env_or("error");
    z_owned_config_t config;
    z_config_default(&config);
    parse_zenoh_common_args(argc, argv, &config);
    // The keyexpr is the LAST argument, so no option-table plumbing is needed
    // beyond upstream's own.
    const char *keyexpr = argv[argc - 1];

    z_owned_session_t s;
    if (z_open(&s, z_move(config), NULL) < 0) {
        printf("Unable to open session!\n");
        return -1;
    }

    z_owned_closure_query_t callback;
    z_closure(&callback, query_handler, NULL, (void *)keyexpr);
    z_owned_queryable_t qable;
    z_view_keyexpr_t ke;
    z_view_keyexpr_from_str(&ke, keyexpr);
    if (z_declare_queryable(z_loan(s), &qable, z_loan(ke), z_move(callback), NULL) < 0) {
        printf("Unable to create queryable.\n");
        return -1;
    }
    printf("Queryable declared on '%s'\n", keyexpr);
    fflush(stdout);
    while (1) {
        z_sleep_s(1);
    }
    z_drop(z_move(qable));
    z_drop(z_move(s));
    return 0;
}
"#,
    )
    .expect("write the driver source");

    let lib = wz_capi_c_cdylib();
    let wz_libdir = lib.parent().expect("cdylib has a parent").to_path_buf();
    let on_wz = compile_zenoh_c_example(
        "wz_reply_encoding",
        dir.path(),
        &include,
        &src_dir,
        &wz_libdir,
        "wz_capi_c",
    )
    .unwrap_or_else(|diag| {
        panic!("the reply-encoding driver does NOT link against wz's C-ABI cdylib.\n{diag}")
    });
    let ref_dir = dir.path().join("reference");
    std::fs::create_dir_all(&ref_dir).expect("reference build dir");
    let on_ref = compile_zenoh_c_example(
        "wz_reply_encoding",
        &ref_dir,
        &include,
        &src_dir,
        &libdir_ref,
        "zenohc",
    )
    .unwrap_or_else(|diag| {
        panic!("the reply-encoding driver does not link against the REAL libzenohc.so\n{diag}")
    });

    // One arm: queryable listens, a real pico z_get_attachment dials in and
    // reports what it decoded. A FRESH port per arm — a shared one makes the
    // second arm's result depend on the first, which the sibling dropin file
    // paid for once already.
    let z_get = zenoh_pico_cli_binary("z_get_attachment");
    let run_arm = |driver: &Path, libdir: &Path, arm: &str| -> String {
        let key = "demo/capic/leg16";
        let reservation = PortReservation::pick();
        let port = reservation.port();
        let endpoint = format!("tcp/127.0.0.1:{port}");

        let mut qbl_out = tempfile::tempfile().expect("queryable stdout capture");
        let writer = qbl_out.try_clone().expect("dup queryable handle");
        let mut qbl = ChildGuard::wrap(
            format!("reply-encoding queryable ({arm})"),
            Command::new("stdbuf")
                .args(["-oL", "-eL"])
                .arg(driver)
                .args(["-l", &endpoint, "-m", "peer", key])
                .env("LD_LIBRARY_PATH", libdir)
                .stdout(Stdio::from(writer))
                .stderr(Stdio::null())
                .spawn()
                .unwrap_or_else(|why| panic!("spawn the {arm} queryable: {why}")),
        );
        if let Err(why) = wait_for_tcp_accept_alive(qbl.child_mut(), port, LISTEN_TIMEOUT) {
            panic!(
                "the {arm} queryable never accepted on {endpoint} — {why}; capture so \
                 far:\n{}",
                read_captured(&mut qbl_out)
            );
        }
        drop(reservation);
        // The port accepting is NOT the queryable being declared, and pico's
        // z_get is one-shot: it sends its query as soon as it is open and takes
        // the final notification as its answer. The first draft waited only on
        // the port and the REFERENCE arm came back with an empty reply set,
        // which is the fixture racing the declaration rather than either
        // library dropping anything. The driver prints its own declaration, so
        // the barrier is that line.
        if let Err(captured) =
            wait_for_substring(&mut qbl_out, "Queryable declared on", LISTEN_TIMEOUT)
        {
            panic!(
                "the {arm} queryable never reported its declaration within \
                 {LISTEN_TIMEOUT:?}.\n--- {arm} queryable stdout ---\n{captured}"
            );
        }

        let mut get_out = tempfile::tempfile().expect("foreign querier stdout capture");
        let get_writer = get_out.try_clone().expect("dup foreign querier handle");
        let mut get = ChildGuard::wrap(
            format!("real zenoh-pico z_get_attachment ({arm})"),
            Command::new("stdbuf")
                .args(["-oL", "-eL"])
                .arg(&z_get)
                .args(["-k", key, "-e", &endpoint, "-m", "client"])
                .stdout(Stdio::from(get_writer))
                .stderr(Stdio::null())
                .spawn()
                .expect("spawn the real zenoh-pico z_get_attachment"),
        );
        let captured = wait_for_substring(&mut get_out, "with encoding:", EXCHANGE_TIMEOUT)
            .unwrap_or_else(|captured| {
                panic!(
                    "the REAL zenoh-pico z_get_attachment never printed an encoding line \
                     for the {arm} queryable's reply.\n\
                     --- REAL pico z_get_attachment stdout ---\n{captured}\n\
                     --- {arm} queryable stdout ---\n{}",
                    read_captured(&mut qbl_out)
                )
            });
        graceful_terminate(get.child_mut(), Duration::from_secs(5));
        graceful_terminate(qbl.child_mut(), Duration::from_secs(5));
        // Only the encoding lines, so the comparison below is not sensitive to
        // reply ordering or to anything else the two libraries may narrate.
        captured
            .lines()
            .filter(|l| l.contains("with encoding:"))
            .map(|l| l.trim().to_owned())
            .collect::<Vec<_>>()
            .join("\n")
    };

    let ref_lines = run_arm(&on_ref, &libdir_ref, "REFERENCE libzenohc");
    let wz_lines = run_arm(&on_wz, &wz_libdir, "wz cdylib");

    // The reference arm establishes what the answer IS, before wz is compared
    // to it — a differential between two arms that both dropped the field would
    // be EQUAL and prove nothing.
    assert!(
        ref_lines.contains("with encoding: text/plain"),
        "the REFERENCE arm did not carry the reply encoding either, so this \
         machine's oracle cannot serve as one here and the comparison below \
         would be vacuous.\n--- pico saw (reference) ---\n{ref_lines}"
    );
    assert_eq!(
        wz_lines, ref_lines,
        "a REAL zenoh-pico decoded a DIFFERENT reply encoding from wz's C ABI \
         than from the real libzenohc.so, driven by the SAME C source. \
         `z_query_reply_options_t::encoding` is the only field this driver sets; \
         wz dropping it makes pico print the default `zenoh/bytes`.\n\
         --- pico saw (wz) ---\n{wz_lines}\n--- pico saw (reference) ---\n{ref_lines}"
    );
}

/// LEG 17 (`wz->pico`, QUERY-VALUE ENCODING) — a `z_get` on WZ's C ABI sets
/// `z_get_options_t::encoding`, and the REAL zenoh-pico `z_queryable` prints the
/// label it decoded off the query.
///
/// ## This leg exists to RETIRE a non-claim, not to add coverage
///
/// R311y547 wired `z_get_options_t::encoding` onto the Query value ext and could
/// only prove it at the seam, recording in so many words that "no zenoh-pico
/// example renders the encoding of a query it received". That was true of the
/// STOCK example and it is not a property of pico: `z_query_encoding` is
/// declared UNCONDITIONALLY in `api/primitives.h`, and the stock handler simply
/// prints keyexpr, parameters and value. R311y548 adds the print to this repo's
/// existing build-time patch on `z_queryable.c` — the same move R311y240 made
/// for the sample QoS getters — and the seam-only proof becomes a foreign one.
///
/// The lesson is worth more than the leg: "no example prints it" is a statement
/// about a program, and this tree already owns a mechanism for changing that.
/// A non-claim resting on a stock example's output is worth re-testing against
/// the ACCESSOR list before it is carried.
///
/// ## Shape
///
/// A differential with a foreign adjudicator, exactly as
/// [`a_wz_capi_c_queryable_reply_encoding_reaches_a_real_pico_as_it_does_on_libzenohc`]
/// — no upstream example sets a query encoding (`z_get.c` sets only target,
/// timeout and payload), so one wz-authored source is compiled twice and a real
/// pico queryable adjudicates both arms.
// wz-proves: api-compat-c wz->pico partial
#[test]
#[ignore = "compiles a C driver against wz's cdylib AND the real libzenohc.so \
            and spawns the real zenoh-pico z_queryable CLI; needs the \
            machine-local zenoh-c oracle; run-ci Layer C1cc drives it"]
fn a_wz_capi_c_get_encoding_reaches_a_real_pico_queryable_as_it_does_on_libzenohc() {
    let Some((include, libdir_ref, examples)) = oracle_or_note() else {
        return;
    };
    let dir = tempfile::tempdir().expect("tempdir for the compiled drivers");
    let src_dir = dir.path().join("src");
    std::fs::create_dir_all(&src_dir).expect("driver source dir");
    std::fs::copy(examples.join("parse_args.h"), src_dir.join("parse_args.h"))
        .expect("upstream parse_args.h is part of the examples clone");
    std::fs::write(
        src_dir.join("wz_get_encoding.c"),
        r#"#include <stdio.h>
#include <string.h>

#include "parse_args.h"
#include "zenoh.h"

void reply_handler(z_loaned_reply_t *reply, void *ctx) {
    (void)reply;
    (void)ctx;
    printf(">> [Get] reply\n");
    fflush(stdout);
}

void drop_handler(void *ctx) { (void)ctx; }

int main(int argc, char **argv) {
    zc_init_log_from_env_or("error");
    z_owned_config_t config;
    z_config_default(&config);
    parse_zenoh_common_args(argc, argv, &config);
    const char *keyexpr = argv[argc - 1];

    z_owned_session_t s;
    if (z_open(&s, z_move(config), NULL) < 0) {
        printf("Unable to open session!\n");
        return -1;
    }

    z_get_options_t opts;
    z_get_options_default(&opts);
    // The field this driver exists for. A payload rides along because a value
    // ext carries the (encoding, payload) PAIR — an encoding with no payload
    // would be a shape neither library is being asked about here.
    z_owned_bytes_t payload;
    z_bytes_copy_from_str(&payload, "QUERY-VALUE-FROM-THE-C-ABI");
    opts.payload = z_move(payload);
    z_owned_encoding_t encoding;
    z_encoding_clone(&encoding, z_encoding_text_plain());
    opts.encoding = z_move(encoding);

    z_owned_closure_reply_t callback;
    z_closure(&callback, reply_handler, drop_handler, NULL);
    z_view_keyexpr_t ke;
    z_view_keyexpr_from_str(&ke, keyexpr);
    printf("Sending Query '%s'\n", keyexpr);
    fflush(stdout);
    if (z_get(z_loan(s), z_loan(ke), "", z_move(callback), &opts) < 0) {
        printf("Unable to send query.\n");
        return -1;
    }
    z_sleep_s(3);
    z_drop(z_move(s));
    return 0;
}
"#,
    )
    .expect("write the driver source");

    let lib = wz_capi_c_cdylib();
    let wz_libdir = lib.parent().expect("cdylib has a parent").to_path_buf();
    let on_wz = compile_zenoh_c_example(
        "wz_get_encoding",
        dir.path(),
        &include,
        &src_dir,
        &wz_libdir,
        "wz_capi_c",
    )
    .unwrap_or_else(|diag| {
        panic!("the get-encoding driver does NOT link against wz's C-ABI cdylib.\n{diag}")
    });
    let ref_dir = dir.path().join("reference");
    std::fs::create_dir_all(&ref_dir).expect("reference build dir");
    let on_ref = compile_zenoh_c_example(
        "wz_get_encoding",
        &ref_dir,
        &include,
        &src_dir,
        &libdir_ref,
        "zenohc",
    )
    .unwrap_or_else(|diag| {
        panic!("the get-encoding driver does not link against the REAL libzenohc.so\n{diag}")
    });

    let z_queryable = zenoh_pico_cli_binary("z_queryable");
    let run_arm = |driver: &Path, libdir: &Path, arm: &str| -> String {
        let key = "demo/capic/leg17";
        let reservation = PortReservation::pick();
        let port = reservation.port();
        let endpoint = format!("tcp/127.0.0.1:{port}");

        // The FOREIGN side listens and the drop-in dials in, so the query's
        // bytes are the ones crossing a real TCP link into a foreign decoder.
        let mut qbl_out = tempfile::tempfile().expect("foreign queryable stdout capture");
        let writer = qbl_out.try_clone().expect("dup foreign queryable handle");
        let mut qbl = ChildGuard::wrap(
            format!("real zenoh-pico z_queryable ({arm})"),
            Command::new("stdbuf")
                .args(["-oL", "-eL"])
                .arg(&z_queryable)
                .args(["-k", key, "-l", &endpoint, "-m", "peer"])
                .stdout(Stdio::from(writer))
                .stderr(Stdio::null())
                .spawn()
                .expect("spawn the real zenoh-pico z_queryable"),
        );
        if let Err(why) = wait_for_tcp_accept_alive(qbl.child_mut(), port, LISTEN_TIMEOUT) {
            panic!(
                "the real zenoh-pico z_queryable never accepted on {endpoint} — {why}; \
                 capture so far:\n{}",
                read_captured(&mut qbl_out)
            );
        }
        drop(reservation);

        let mut get_out = tempfile::tempfile().expect("driver stdout capture");
        let get_writer = get_out.try_clone().expect("dup driver handle");
        let mut get = ChildGuard::wrap(
            format!("get-encoding driver ({arm})"),
            Command::new("stdbuf")
                .args(["-oL", "-eL"])
                .arg(driver)
                .args(["-e", &endpoint, "-m", "client", key])
                .env("LD_LIBRARY_PATH", libdir)
                .stdout(Stdio::from(get_writer))
                .stderr(Stdio::null())
                .spawn()
                .unwrap_or_else(|why| panic!("spawn the {arm} driver: {why}")),
        );
        let captured = wait_for_substring(&mut qbl_out, "with query encoding:", EXCHANGE_TIMEOUT)
            .unwrap_or_else(|captured| {
                panic!(
                    "the REAL zenoh-pico z_queryable never printed a query-encoding line \
                     for the {arm} driver's get. The line comes from this repo's \
                     build-time patch on z_queryable.c (R311y548) — if it is absent \
                     entirely, the pico CLIs predate that patch and need rebuilding with \
                     scripts/build-zenoh-pico-cli.sh.\n\
                     --- REAL pico z_queryable stdout ---\n{captured}\n\
                     --- {arm} driver stdout ---\n{}",
                    read_captured(&mut get_out)
                )
            });
        graceful_terminate(get.child_mut(), Duration::from_secs(5));
        graceful_terminate(qbl.child_mut(), Duration::from_secs(5));
        captured
            .lines()
            .filter(|l| l.contains("with query encoding:"))
            .map(|l| l.trim().to_owned())
            .collect::<Vec<_>>()
            .join("\n")
    };

    let ref_lines = run_arm(&on_ref, &libdir_ref, "REFERENCE libzenohc");
    let wz_lines = run_arm(&on_wz, &wz_libdir, "wz cdylib");

    assert!(
        ref_lines.contains("with query encoding: text/plain"),
        "the REFERENCE arm did not carry the query encoding either, so this \
         machine's oracle cannot serve as one here and the comparison below \
         would be vacuous.\n--- pico saw (reference) ---\n{ref_lines}"
    );
    assert_eq!(
        wz_lines, ref_lines,
        "a REAL zenoh-pico decoded a DIFFERENT query encoding from wz's C ABI \
         than from the real libzenohc.so, driven by the SAME C source. \
         `z_get_options_t::encoding` is the only field this driver sets beyond \
         the payload it must ride with; wz dropping it makes pico print the \
         default `zenoh/bytes`.\n\
         --- pico saw (wz) ---\n{wz_lines}\n--- pico saw (reference) ---\n{ref_lines}"
    );
}
