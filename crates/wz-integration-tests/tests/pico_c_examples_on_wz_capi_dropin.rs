// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! §5.27 `api-compat-pico` — the BINARY DROP-IN claim, witnessed by upstream's
//! own C programs against upstream's own running binaries.
//!
//! ## What the atom claims, and why nothing here could witness it before
//!
//! `wz-capi-pico` exists so that "a zenoh-pico C program can link the wz cdylib
//! as a binary drop-in" (`crates/wz-capi-pico/Cargo.toml`). Every gate the atom
//! had until this round was a Rust `#[test]` calling the exported `extern "C"`
//! symbols from inside the same workspace — which checks that wz agrees with
//! wz. The inventory recorded the hole plainly: *"no C compiler consumes it —
//! there is no cc dependency and no C lane"*. A C ABI whose only consumer is
//! Rust is not an ABI, it is a naming convention.
//!
//! Every leg below therefore hands the checking to artifacts wz does not own:
//!
//!   * the PROGRAM is `vendor/zenoh-pico/examples/unix/c11/<name>.c`, unmodified;
//!   * the HEADERS are zenoh-pico's own — its types, its struct SIZES, and the
//!     `_Generic` `z_loan`/`z_move`/`z_drop` dispatch in `api/macros.h`, taken
//!     together with the CMake-GENERATED `config.h` that fixes the `Z_FEATURE_*`
//!     set (see `common::zenoh_pico_include_dirs`);
//!   * the COUNTERPARTY on the wire is a real `zenoh_pico_cli_binary`.
//!
//! Only the library answering the `z_*` calls is wz's. So the C compiler, the
//! linker, and a foreign peer do the adjudicating, and none of them can be
//! talked round by a wz-authored assertion.
//!
//! ## Why upstream's own examples are the right corpus, and not a hand-written one
//!
//! A wz-authored C program would be written against the exports wz happens to
//! have, which is precisely the bias that let the atom sit at "BUILT" while its
//! headline claim was unwitnessed. Upstream's examples were written with no
//! knowledge of wz, so what they call is what a pico program actually calls —
//! including the getters wz had never been forced to get right. That is not
//! hypothetical: measuring all 32 upstream examples at this pin, exactly ONE
//! (`z_sub.c`) linked against wz's cdylib with its real body compiled, and
//! bringing `z_queryable.c` to the same state exposed a crash-level divergence
//! in `z_query_payload` (see `crates/wz-capi-pico/src/query.rs`).
//!
//! **A link is not a pass, and the difference is measurable.** Six examples
//! once linked while calling nothing at all — `z_advanced_pub`,
//! `z_advanced_sub`, `z_pub_st`, `z_pub_tls`, `z_sub_st`, `z_sub_tls` compiled
//! to a `#else` stub `main` because the CMake-generated feature set disagreed
//! with what they demand. `nm -u <obj> | grep z_open` separates a stub from a
//! real body, which is why this file names its examples explicitly instead of
//! sweeping a glob: a glob would have counted six vacuous passes.
//!
//! **Census at R311y534: 32 of 32 upstream examples LINK, and 32 of 32 are
//! DRIVEN.** The stub set is EMPTY — the six that were stubs were not short of
//! wz exports, they were short of the CMake flags their `#if` demanded, and each
//! flag was turned on once someone re-read the exclusion instead of the count:
//! `Z_FEATURE_ADVANCED_{PUBLICATION,SUBSCRIPTION}` for the advanced pair, a
//! second `Z_FEATURE_MULTI_THREAD=0` header arm for the `_st` pair, and
//! `Z_FEATURE_LINK_TLS` plus a pinned Mbed TLS for the `_tls` pair. The
//! configuration gate at the end of this file is what keeps that set empty: it
//! runs each program and reds if any of them takes its stub branch again.
//!
//! Not every DRIVEN program is a leg SUBJECT. `z_ping`, `z_get_lat`,
//! `z_pub_thr`, `z_get_attachment` and the foreign `z_sub_tls` / `z_pub_tls`
//! appear as this file's own counterparties as well, which is a different role:
//! a subject is compiled against wz's cdylib, a counterparty is upstream's own
//! binary.
//!
//! ## Leg 3 needs a discriminator the other two do not
//!
//! `z_put.c` DECLARES its keyexpr and then publishes on the declared value, so
//! the property under test is that the publish goes out ALIASED — the wire
//! carrying a numeric id the peer resolves through the mapping table our
//! `DeclareKeyExpr` built. A literal Push would reach the same subscriber and
//! print the same line, so the OUTCOME cannot tell the two apart and the leg
//! would pass just as happily against a build that ignored the declaration
//! entirely.
//!
//! What separates them is a damage, and it is recorded here because the test
//! body cannot express it: suppressing only the DECLARE
//! (`SharedSession::declare_keyexpr`'s per-face `send_declare_keyexpr`) while
//! leaving the aliased publish in place makes the peer drop the Push for an id
//! it never registered, and this leg reds. Against a literal-publishing build
//! that same damage changes nothing. That asymmetry is what makes the green
//! here mean "aliased", and it was run.
//!
//! ## Scope, stated as a limit rather than implied
//!
//! Every claim is `partial`, and deliberately: the atom covers 184 of pico's
//! 726 declared functions, and six programs are six programs. What is proven is
//! that the drop-in is REAL for the paths those programs exercise — inbound
//! samples, queryable replies, a declared-keyexpr publish, a full
//! publish/background-subscribe round trip, and both directions of the presence
//! plane including the DEPARTURE half — compiled and linked the way a pico user
//! would.

use std::process::{Command, Stdio};
use std::time::Duration;

use wz_integration_tests::common::{
    compile_pico_example_against_wz_capi, compile_pico_example_against_wz_capi_with_includes,
    graceful_terminate, project_root, read_captured,
    spawn_zenohd_multicast_scouting_on_any_interface, wait_for_capture_alive, wait_for_exit,
    wait_for_substring, wait_for_tcp_accept_alive, zenoh_pico_cli_binary, zenoh_pico_include_dirs,
    zenoh_pico_include_dirs_single_threaded, zenoh_pico_library_dir, zenohd_binary, ChildGuard,
    PortReservation,
};

/// How long a compiled drop-in gets to bind its listener. Generous relative to
/// the sub-100 ms observed path: the gate is a TCP connect, so a slow bind
/// costs only latency here, never a false PASS.
///
/// R311y490 — "never a false PASS" was TRUE OF A SLOW BIND AND FALSE OF A LOST
/// ONE, and every barrier below now uses the liveness-aware
/// `wait_for_tcp_accept_alive` because of it. A bare TCP connect proves only
/// that SOMETHING accepts on that port. If our child lost the ephemeral-port
/// race and exited, the connect can succeed against whatever won — the barrier
/// passes, and the failure resurfaces further down as a foreign process
/// exiting -1, which is exactly the shape this suite's leg 3 showed once under a
/// full sweep with no diagnosis attached. The alive-aware variant `Err`s the
/// instant the child we spawned exits, naming its `ExitStatus`, so a lost race
/// reads as a lost race at the point it happens. See `PortReservation` in
/// `wz_integration_tests::common` for the race itself and its cross-process fix.
const LISTEN_TIMEOUT: Duration = Duration::from_secs(10);
/// How long a leg's exchange gets to complete, ending in the observed process
/// EXITING.
///
/// Exit is load-bearing, not incidental. Every witness here is read from a C
/// program's `printf` output captured to a file, where libc is block-buffered —
/// so the bytes are only guaranteed on the file after the process flushes at
/// exit. Each leg is therefore driven by a self-terminating invocation (`-n 1`
/// for a subscriber, a one-shot `z_get`, `-n 5` for the ping loop) and asserts
/// on the capture AFTER the wait, rather than polling a partially-flushed
/// buffer.
///
/// R311y482 — THE ABOVE IS TRUE OF THE PASS PATH AND WAS WRONG AS AN EXEMPTION.
/// R311y480's own ledger recorded a scan for pico spawns lacking `stdbuf` and
/// cleared this file as a "deliberate exit-flush design". That reasoning holds
/// only while the test SUCCEEDS. When it fails, the self-terminating invocation
/// has by definition NOT reached its exit count, so libc never flushes and the
/// capture handed to the panic message is **0 bytes** — measured, and measured
/// again after a kill, which loses the buffer outright. Every failure mode in a
/// leg therefore produced a byte-identical empty capture, and one Layer E run did
/// fail here with a panic message asserting a mode the capture could not
/// distinguish from any other.
///
/// So every C-program spawn in this file is now wrapped in `stdbuf -oL -eL`
/// (measured: 148 bytes mid-run against 0 without). The exit-driven reads above
/// are UNCHANGED and still correct — line buffering only adds the partial
/// evidence a failing run needs, and costs a passing run nothing. The rule this
/// encodes: a harness that reads a foreign process's stdout must line-buffer it,
/// because "it flushes on exit" is a statement about the path where you do not
/// need the output.
const EXCHANGE_TIMEOUT: Duration = Duration::from_secs(20);

/// Compile an upstream example against wz's cdylib, failing the test with the
/// compiler's own diagnostics when it does not link.
///
/// A link failure IS the drop-in claim being false, so it is surfaced verbatim:
/// the undefined-reference list names exactly which `z_*` exports wz is missing,
/// which is the actionable form of "not a drop-in yet".
fn dropin_binary(example: &str, dir: &std::path::Path) -> std::path::PathBuf {
    match compile_pico_example_against_wz_capi(example, dir) {
        Ok(exe) => exe,
        Err(diag) => panic!(
            "§5.27 api-compat-pico: upstream {example}.c does NOT link against wz's \
             C-ABI cdylib, so wz is not a binary drop-in for it.\n{diag}"
        ),
    }
}

/// [`dropin_binary`] compiled against the SINGLE-THREADED pico header arm.
///
/// `z_pub_st.c` / `z_sub_st.c` guard their whole `main` on
/// `Z_FEATURE_MULTI_THREAD == 0`, so the primary header set compiles them to a
/// one-`printf` stub. Only the `-I` differs; the library is the same wz cdylib,
/// which is a MEASURED claim rather than a convenience — see
/// `zenoh_pico_include_dirs_single_threaded`.
fn dropin_binary_single_threaded(example: &str, dir: &std::path::Path) -> std::path::PathBuf {
    let includes = zenoh_pico_include_dirs_single_threaded();
    match compile_pico_example_against_wz_capi_with_includes(example, dir, &includes) {
        Ok(exe) => exe,
        Err(diag) => panic!(
            "§5.27 api-compat-pico: upstream {example}.c does NOT link against wz's \
             C-ABI cdylib under the SINGLE-THREADED header arm, so wz is not a \
             binary drop-in for it.\n{diag}"
        ),
    }
}

/// How long a bounded foreign / drop-in invocation gets to EXIT.
///
/// The legs below drive programs that wait on their counterparty — `z_ping` and
/// `z_get_lat` block until their round-trip count completes, `z_get_liveliness`
/// until its snapshot terminates — so a plain `Command::status()` on any of
/// them is an UNBOUNDED wait. Measured the hard way: one suite run sat on a
/// hung snapshot for 25 minutes with no output, because a `status()` that never
/// returns produces neither a failure nor a diagnostic. Every such call is now
/// spawned and bounded.
const EXIT_TIMEOUT: Duration = Duration::from_secs(30);

/// Wait for a spawned child to exit within [`EXIT_TIMEOUT`], killing it and
/// failing with its capture if it does not.
///
/// Returns the exit status so the caller still asserts on it: a bounded wait
/// replaces "hangs forever" with "fails and says why", not with "passes".
fn bounded_exit(
    label: &str,
    mut child: std::process::Child,
    capture: &mut std::fs::File,
) -> std::process::ExitStatus {
    match wait_for_exit(&mut child, EXIT_TIMEOUT) {
        Ok(status) => status,
        Err(why) => {
            let captured = read_captured(capture);
            let _ = child.kill();
            let _ = child.wait();
            panic!(
                "{label} did not exit within {EXIT_TIMEOUT:?} — {why}. It waits on \
                 its counterparty, so this is the shape of a reply that never came.\n\
                 --- its captured output ---\n{captured}"
            );
        }
    }
}

/// LEG 1 (`pico->wz`) — upstream's `z_sub.c`, running on wz, receives a sample
/// published by the REAL zenoh-pico `z_put` binary.
///
/// The subscriber is the drop-in and it LISTENS; the foreign publisher dials in.
/// That direction is chosen because it puts the foreign bytes on the inbound
/// path: the payload text is produced by real pico, crosses a real TCP link, and
/// is rendered by upstream's own `data_handler` through wz's `z_sample_payload` /
/// `z_bytes_to_string`. A wz-side sample accessor that mis-framed the payload
/// could not print the string the foreign publisher chose.
// wz-proves: api-compat-pico pico->wz partial
#[test]
#[ignore = "spawns the real zenoh-pico z_put CLI and a cc-compiled binary; \
            run by run-ci Layer E"]
fn pico_zsub_source_on_wz_capi_receives_from_real_pico_zput() {
    let dir = tempfile::tempdir().expect("tempdir for the compiled drop-in");
    let dropin = dropin_binary("z_sub", dir.path());
    let z_put = zenoh_pico_cli_binary("z_put");

    let reservation = PortReservation::pick();
    let port = reservation.port();
    let endpoint = format!("tcp/127.0.0.1:{port}");
    let payload = "PAYLOAD-FROM-REAL-PICO-ZPUT";
    let key = "demo/dropin/leg1";

    let mut sub_out = tempfile::tempfile().expect("subscriber stdout capture");
    let writer = sub_out.try_clone().expect("dup subscriber stdout handle");
    // `-n 1`: exit after the first sample, which is what flushes libc's block
    // buffer onto the capture file (see EXCHANGE_TIMEOUT).
    let mut sub = ChildGuard::wrap(
        "z_sub.c on wz-capi-pico",
        Command::new("stdbuf")
            .args(["-oL", "-eL"])
            .arg(&dropin)
            .args([
                "-l",
                &endpoint,
                "-m",
                "peer",
                "-k",
                "demo/dropin/**",
                "-n",
                "1",
            ])
            .stdout(Stdio::from(writer))
            .stderr(Stdio::from(sub_out.try_clone().expect("dup stderr handle")))
            .spawn()
            .expect("spawn the compiled z_sub drop-in"),
    );

    if let Err(why) = wait_for_tcp_accept_alive(sub.child_mut(), port, LISTEN_TIMEOUT) {
        panic!(
            "the z_sub.c drop-in never accepted on {endpoint} — {why}; capture so far:\n{}",
            read_captured(&mut sub_out)
        );
    }
    drop(reservation);

    // R311y482 — captured even though the exit status is asserted below. A zero
    // exit says the process ran, not that it published: pico's z_put prints
    // `Putting Data ('<ke>': '<v>')...` and can still exit 0 on a session it never
    // established. The capture is what the panic further down reads.
    let mut put_out = tempfile::tempfile().expect("foreign z_put stdout capture");
    let put_writer = put_out.try_clone().expect("dup foreign z_put handle");
    let put = Command::new("stdbuf")
        .args(["-oL", "-eL"])
        .arg(&z_put)
        .args(["-e", &endpoint, "-m", "client", "-k", key, "-v", payload])
        .stdout(Stdio::from(put_writer))
        .stderr(Stdio::from(put_out.try_clone().expect("dup stderr handle")))
        .status()
        .expect("run the real zenoh-pico z_put");
    assert!(
        put.success(),
        "real zenoh-pico z_put exited {put:?}\n--- its stdout+stderr ---\n{}",
        read_captured(&mut put_out)
    );

    // The subscriber self-terminates on its first sample; wait for that exit so
    // the capture is complete, then assert.
    let captured =
        wait_for_substring(&mut sub_out, payload, EXCHANGE_TIMEOUT).unwrap_or_else(|captured| {
            let driver = read_captured(&mut put_out);
            panic!(
                "upstream z_sub.c running on wz's C-ABI never reported the payload \
                 published by the REAL zenoh-pico z_put.\nexpected substring: {payload}\n\
                 the foreign publisher reached its put: {}\n\
                 --- z_sub.c (on wz) stdout ---\n{captured}\n\
                 --- REAL pico z_put (driver) stdout ---\n{driver}",
                driver.contains("Putting Data"),
            )
        });
    // Upstream's handler prints `>> [Subscriber] Received ('<key>': '<payload>')`,
    // so pinning the KEY as well as the payload is what distinguishes "the
    // sample arrived intact" from "some sample arrived": a keyexpr wz resolved
    // wrongly would still carry the right bytes.
    assert!(
        captured.contains(key),
        "the payload arrived but not on the key the foreign publisher used \
         ({key}); wz's inbound keyexpr resolution disagrees.\n--- stdout+stderr ---\n{captured}"
    );

    graceful_terminate(sub.child_mut(), Duration::from_secs(5));
}

/// LEG 2 (`wz->pico`) — upstream's `z_queryable.c`, running on wz, answers a
/// query from the REAL zenoh-pico `z_get` binary, and the FOREIGN process is
/// what reports the reply.
///
/// This is the stronger of the two legs and the reason the pair exists. The
/// witness line is read from `z_get`'s own stdout, so the assertion is made by
/// the foreign implementation about bytes it decoded itself — not by a wz test
/// inspecting a value wz produced. Leg 1 can only be observed through the
/// drop-in's own output (upstream's program text, but wz's runtime underneath);
/// here both the question and the verdict come from outside.
///
/// It is also the leg that exposed a real defect. Upstream's handler calls
/// `z_bytes_to_string(z_query_payload(query), &payload_string)` UNCONDITIONALLY
/// and only then tests the length, so wz's original "null for a payload-less
/// query" contract left a stack-allocated owned string uninitialized and the
/// next line loaned it — the example aborted the moment a real `z_get` reached
/// it. pico's own getter is an unconditional address-of
/// (`vendor/zenoh-pico/src/api/api.c:476`).
// wz-proves: api-compat-pico wz->pico partial
#[test]
#[ignore = "spawns the real zenoh-pico z_get CLI and a cc-compiled binary; \
            run by run-ci Layer E"]
fn pico_zqueryable_source_on_wz_capi_answers_real_pico_zget() {
    let dir = tempfile::tempdir().expect("tempdir for the compiled drop-in");
    let dropin = dropin_binary("z_queryable", dir.path());
    let z_get = zenoh_pico_cli_binary("z_get");

    let reservation = PortReservation::pick();
    let port = reservation.port();
    let endpoint = format!("tcp/127.0.0.1:{port}");
    let reply = "REPLY-FROM-PICO-QUERYABLE-ON-WZ";
    let selector = "demo/dropin/leg2";

    let mut qable_out = tempfile::tempfile().expect("queryable stdout capture");
    let writer = qable_out.try_clone().expect("dup queryable stdout handle");
    let mut qable = ChildGuard::wrap(
        "z_queryable.c on wz-capi-pico",
        Command::new("stdbuf")
            .args(["-oL", "-eL"])
            .arg(&dropin)
            // `-n 1`: serve exactly one query and exit. Needed for the handler
            // assertion below — upstream increments its counter AFTER
            // `z_query_reply`, so the reply is on the wire before the process
            // leaves the loop, and the exit is what flushes its block-buffered
            // stdout onto the capture. Without it the handler's own line is
            // still sitting in libc when the assertion reads the file, and a
            // leg that genuinely worked fails on an unflushed buffer.
            .args([
                "-l",
                &endpoint,
                "-m",
                "peer",
                "-k",
                "demo/dropin/**",
                "-v",
                reply,
                "-n",
                "1",
            ])
            .stdout(Stdio::from(writer))
            .stderr(Stdio::from(
                qable_out.try_clone().expect("dup stderr handle"),
            ))
            .spawn()
            .expect("spawn the compiled z_queryable drop-in"),
    );

    if let Err(why) = wait_for_tcp_accept_alive(qable.child_mut(), port, LISTEN_TIMEOUT) {
        panic!(
            "the z_queryable.c drop-in never accepted on {endpoint} — {why}; capture so far:\n{}",
            read_captured(&mut qable_out)
        );
    }
    drop(reservation);

    // A one-shot `z_get`: it prints its replies and the final notification, then
    // exits — which is what flushes its capture.
    let mut get_out = tempfile::tempfile().expect("z_get stdout capture");
    let get_writer = get_out.try_clone().expect("dup z_get stdout handle");
    let get = Command::new("stdbuf")
        .args(["-oL", "-eL"])
        .arg(&z_get)
        .args(["-e", &endpoint, "-m", "client", "-k", selector])
        .stdout(Stdio::from(get_writer))
        .stderr(Stdio::from(get_out.try_clone().expect("dup stderr handle")))
        .status()
        .expect("run the real zenoh-pico z_get");
    assert!(get.success(), "real zenoh-pico z_get exited {get:?}");

    let foreign = read_captured(&mut get_out);
    // Ordering note: the reply assertion comes FIRST and is the verdict. The
    // "final notification" line below prints even when no reply arrived, so
    // asserting it first would let a silent drop-in pass a leg that reads as
    // green — the whole point is that the foreign querier saw DATA.
    assert!(
        foreign.contains(reply),
        "the REAL zenoh-pico z_get never decoded the reply that upstream's \
         z_queryable.c produced while running on wz's C-ABI.\n\
         expected substring: {reply}\n--- REAL pico z_get stdout ---\n{foreign}\n\
         --- z_queryable.c (on wz) stdout ---\n{}",
        read_captured(&mut qable_out)
    );
    assert!(
        foreign.contains(selector),
        "the reply reached the foreign querier on the wrong key (expected \
         {selector}).\n--- REAL pico z_get stdout ---\n{foreign}"
    );
    // The handler itself must have run: without this, a reply fabricated
    // anywhere else on wz's side would satisfy the two assertions above. Read
    // after the `-n 1` exit, which is what makes the line observable at all.
    wait_for_substring(
        &mut qable_out,
        "[Queryable handler] Received Query",
        EXCHANGE_TIMEOUT,
    )
    .unwrap_or_else(|local| {
        panic!(
            "the foreign querier got its reply but upstream's own query handler \
             never ran, so the reply did not come from the drop-in.\n\
             --- z_queryable.c (on wz) stdout ---\n{local}"
        )
    });

    graceful_terminate(qable.child_mut(), Duration::from_secs(5));
}

/// LEG 3 (`wz->pico`) — upstream's `z_put.c`, running on wz, DECLARES its
/// keyexpr and the resulting aliased publish is received by a real zenoh-pico
/// `z_sub`.
///
/// This is the leg the keyexpr-declaration family exists for. Upstream's
/// program calls `z_declare_keyexpr`, publishes on the OWNED keyexpr that
/// returns, and then `z_undeclare_keyexpr`s it — so a build that exported those
/// symbols as stubs, or that quietly published the literal instead, would be
/// caught only by the damage described in the module docs, not by this
/// assertion. The assertion's job is the other half: that the peer RESOLVES
/// what wz sent, on the right key.
///
/// Direction and roles follow upstream's own design rather than this file's
/// convenience: `z_put.c` is a one-shot DIALER, so the real pico `z_sub`
/// listens and the drop-in connects to it. That also puts the foreign process
/// on the reporting side, as in leg 2.
// wz-proves: api-compat-pico wz->pico partial
// wz-proves: declare-keyexpr wz->pico partial
#[test]
#[ignore = "spawns the real zenoh-pico z_sub CLI and a cc-compiled binary; \
            run by run-ci Layer E"]
fn pico_zput_source_on_wz_capi_declares_and_reaches_real_pico_zsub() {
    let dir = tempfile::tempdir().expect("tempdir for the compiled drop-in");
    let dropin = dropin_binary("z_put", dir.path());
    let z_sub = zenoh_pico_cli_binary("z_sub");

    let reservation = PortReservation::pick();
    let port = reservation.port();
    let endpoint = format!("tcp/127.0.0.1:{port}");
    let payload = "ALIASED-PUT-FROM-PICO-SOURCE-ON-WZ";
    let key = "demo/dropin/leg3";

    // The FOREIGN process listens here, and `-n 1` makes it exit on the first
    // sample so its block-buffered stdout is flushed before we read it.
    let mut sub_out = tempfile::tempfile().expect("z_sub stdout capture");
    let writer = sub_out.try_clone().expect("dup z_sub stdout handle");
    let mut sub = ChildGuard::wrap(
        "real zenoh-pico z_sub",
        Command::new("stdbuf")
            .args(["-oL", "-eL"])
            .arg(&z_sub)
            .args([
                "-l",
                &endpoint,
                "-m",
                "peer",
                "-k",
                "demo/dropin/**",
                "-n",
                "1",
            ])
            .stdout(Stdio::from(writer))
            .stderr(Stdio::from(sub_out.try_clone().expect("dup stderr handle")))
            .spawn()
            .expect("spawn the real zenoh-pico z_sub"),
    );

    if let Err(why) = wait_for_tcp_accept_alive(sub.child_mut(), port, LISTEN_TIMEOUT) {
        panic!(
            "the real zenoh-pico z_sub never accepted on {endpoint} — {why}; capture so far:\n{}",
            read_captured(&mut sub_out)
        );
    }
    drop(reservation);

    // R311y482 — the wz-side DRIVER's stdout is captured. This leg is the one that
    // fails most often under file-parallel runs, and with the driver silent the
    // panic below could only report that pico received nothing — it could not say
    // whether wz's z_put.c ever declared and published. Upstream prints
    // `Declaring key expression '<ke>'...` and `Putting Data ('<ke>': '<v>')...`,
    // which is precisely the missing half.
    let mut put_out = tempfile::tempfile().expect("z_put drop-in stdout capture");
    let put_writer = put_out.try_clone().expect("dup z_put drop-in handle");
    // R311y489 — stderr rides the SAME capture as stdout instead of being
    // discarded. The assertion below names three functions any of which could have
    // returned the -1, and with `Stdio::null()` here it could never say which:
    // upstream prints the distinguishing line ("Unable to open session!" vs the
    // keyexpr complaints) on the stream that was being thrown away. This leg's own
    // comment above already records that it "fails most often under file-parallel
    // runs", and it duly failed once in a full local sweep on 2026-08-01 while
    // passing 18/18 in isolation — with no diagnosis captured, which is the whole
    // reason the cause is still open. The next occurrence will carry one.
    let put_err = put_out
        .try_clone()
        .expect("dup z_put drop-in stderr handle");
    let put = Command::new("stdbuf")
        .args(["-oL", "-eL"])
        .arg(&dropin)
        .args(["-e", &endpoint, "-m", "client", "-k", key, "-v", payload])
        .stdout(Stdio::from(put_writer))
        .stderr(Stdio::from(put_err))
        .status()
        .expect("run the compiled z_put drop-in");
    // A non-zero exit is itself a finding: upstream returns -1 when
    // `z_declare_keyexpr` fails, so this catches a declaration that never
    // happened before the subscriber assertion can mask it as a lost sample.
    assert!(
        put.success(),
        "upstream z_put.c on wz's C-ABI exited {put:?} — it returns -1 when \
         z_open, z_view_keyexpr_from_str or z_declare_keyexpr fails\n\
         --- z_put drop-in (stdout+stderr) ---\n{}\n--- z_sub ---\n{}",
        read_captured(&mut put_out),
        read_captured(&mut sub_out)
    );

    let foreign =
        wait_for_substring(&mut sub_out, payload, EXCHANGE_TIMEOUT).unwrap_or_else(|captured| {
            // R311y482 — BOTH sides, and the driver's line is what names the leg.
            // `Putting Data` present means wz declared + published and the sample
            // did not arrive; absent means wz never got that far, so the subscriber
            // side is not implicated at all.
            let driver = read_captured(&mut put_out);
            panic!(
                "the REAL zenoh-pico z_sub never received the declared-keyexpr put \
                 that upstream's z_put.c issued while running on wz's C-ABI.\n\
                 expected substring: {payload}\n\
                 wz-side driver reached its put: {}\n\
                 --- REAL pico z_sub stdout ---\n{captured}\n\
                 --- z_put.c-on-wz (driver) stdout ---\n{driver}",
                driver.contains("Putting Data"),
            )
        });
    // The KEY is the part the alias has to reconstruct. wz sends a numeric id
    // plus no suffix; the peer prints whatever ITS mapping table resolved that
    // id to. So a declaration that registered the wrong literal shows up here
    // as the wrong key, not as a missing sample.
    assert!(
        foreign.contains(key),
        "the sample reached the foreign subscriber on the wrong key (expected \
         {key}), so the peer's mapping table resolved the alias to something \
         else.\n--- REAL pico z_sub stdout ---\n{foreign}"
    );

    graceful_terminate(sub.child_mut(), Duration::from_secs(5));
}

/// LEG 4 (round trip) — upstream's `z_ping.c`, running on wz, measures real
/// round-trip latencies against the REAL zenoh-pico `z_pong` binary.
///
/// This is the widest leg in the file, and it is the one that could not have
/// been faked. Every printed line requires a COMPLETE circuit: wz publishes the
/// ping, a foreign process receives it and republishes to `test/pong`, wz's
/// background subscriber delivers the echo, and upstream's own callback bumps
/// the atomic its `load_loop` is spinning on. Publish, subscribe and the
/// platform clock all have to be right at once, and the loop has no timeout of
/// its own — it simply never returns if any of them is wrong.
///
/// That is also why the child is waited on with a BUDGET rather than
/// `Command::status()`: a broken echo path pins a core forever, and a hung lane
/// tells CI less than a red one.
// wz-proves: api-compat-pico wz->pico partial
// wz-proves: api-compat-pico pico->wz partial
#[test]
#[ignore = "spawns the real zenoh-pico z_pong CLI and a cc-compiled binary; \
            run by run-ci Layer E"]
fn pico_zping_source_on_wz_capi_round_trips_through_real_pico_zpong() {
    let dir = tempfile::tempdir().expect("tempdir for the compiled drop-in");
    let dropin = dropin_binary("z_ping", dir.path());
    let z_pong = zenoh_pico_cli_binary("z_pong");

    let reservation = PortReservation::pick();
    let port = reservation.port();
    let endpoint = format!("tcp/127.0.0.1:{port}");
    const PINGS: usize = 5;

    // The FOREIGN echo listens; the drop-in dials in. `z_pong` runs until killed,
    // so its own output is not the WITNESS — the drop-in's is.
    //
    // R311y482 — it is captured anyway, because "not the witness" is not the same
    // as "not evidence". When the drop-in reports fewer than PINGS round trips, the
    // question is whether the echo ever saw a ping at all, and z_pong prints one
    // line per sample it re-publishes. Discarding that made a failure here
    // undiagnosable in exactly the way this round's other legs were.
    let mut pong_out = tempfile::tempfile().expect("z_pong stdout capture");
    let pong_writer = pong_out.try_clone().expect("dup z_pong stdout handle");
    let mut pong = ChildGuard::wrap(
        "real zenoh-pico z_pong",
        Command::new("stdbuf")
            .args(["-oL", "-eL"])
            .arg(&z_pong)
            .args(["-l", &endpoint, "-m", "peer"])
            .stdout(Stdio::from(pong_writer))
            .stderr(Stdio::from(
                pong_out.try_clone().expect("dup stderr handle"),
            ))
            .spawn()
            .expect("spawn the real zenoh-pico z_pong"),
    );
    if let Err(why) = wait_for_tcp_accept_alive(pong.child_mut(), port, LISTEN_TIMEOUT) {
        panic!("the real zenoh-pico z_pong never accepted on {endpoint} — {why}");
    }
    drop(reservation);

    let mut ping_out = tempfile::tempfile().expect("z_ping stdout capture");
    let writer = ping_out.try_clone().expect("dup z_ping stdout handle");
    let mut ping = ChildGuard::wrap(
        "z_ping.c on wz-capi-pico",
        Command::new("stdbuf")
            .args(["-oL", "-eL"])
            .arg(&dropin)
            .args([
                "-e",
                &endpoint,
                "-m",
                "client",
                "-n",
                &PINGS.to_string(),
                "-s",
                "64",
                "-w",
                "500",
            ])
            .stdout(Stdio::from(writer))
            .stderr(Stdio::from(
                ping_out.try_clone().expect("dup stderr handle"),
            ))
            .spawn()
            .expect("spawn the compiled z_ping drop-in"),
    );

    let status = wait_for_exit(ping.child_mut(), EXCHANGE_TIMEOUT).unwrap_or_else(|why| {
        graceful_terminate(ping.child_mut(), Duration::from_secs(5));
        // R311y482 — the echo's own capture, which is what splits the two causes
        // this message names. z_pong prints a line per re-published sample, so its
        // presence means the publish leg worked and the drop-in's background
        // SUBSCRIBER is the broken half; its absence means the publish never
        // arrived and the subscriber is not implicated.
        let echo = read_captured(&mut pong_out);
        panic!(
            "upstream z_ping.c on wz's C-ABI never finished its {PINGS} round trips \
             against the REAL zenoh-pico z_pong ({why}). Its load_loop spins on an \
             atomic the echo callback bumps, so this is what a broken publish OR a \
             broken background subscriber looks like.\n\
             the foreign echo saw traffic: {}\n\
             --- REAL pico z_pong stdout ---\n{echo}",
            !echo.trim().is_empty(),
        )
    });
    assert!(status.success(), "z_ping.c on wz exited {status:?}");

    // Upstream prints one bare integer per completed round trip, and nothing
    // else on the success path. Counting parsed integers is therefore an exact
    // count of circuits closed — a partial echo path yields fewer lines rather
    // than wrong ones.
    let captured = read_captured(&mut ping_out);
    let samples: Vec<u64> = captured
        .lines()
        .filter_map(|l| l.trim().parse::<u64>().ok())
        .collect();
    assert_eq!(
        samples.len(),
        PINGS,
        "expected {PINGS} round-trip measurements from upstream z_ping.c on wz, got \
         {}.\n--- z_ping.c (on wz) stdout ---\n{captured}",
        samples.len()
    );

    graceful_terminate(pong.child_mut(), Duration::from_secs(5));
}

/// The `-t` seconds upstream's `z_liveliness.c` holds its token before dropping
/// it. Short, because the DROP is the half under test and the leg waits for it.
const TOKEN_HOLD_SECS: &str = "3";

/// LEG 5 (`wz->pico`) — upstream's `z_liveliness.c`, running on wz, is seen
/// ALIVE and then DROPPED by a real zenoh-pico `z_sub_liveliness`.
///
/// Both halves are asserted, and the second is the one worth having. pico's
/// `z_liveliness_token_drop` retracts through `_z_liveliness_token_clear`
/// (`vendor/zenoh-pico/src/api/liveliness.c:35-43`), and upstream's program
/// never calls the explicit undeclare — it just lets the token go out of scope.
/// A wz drop that only freed memory would still produce the ALIVE line, so an
/// alive-only assertion would pass against a build in which nothing ever
/// reports a peer's departure. The foreign subscriber printing "Dropped" is
/// what rules that out, and it prints it because a real UndeclToken arrived.
// wz-proves: api-compat-pico wz->pico partial
// wz-proves: liveliness-token wz->pico partial
#[test]
#[ignore = "spawns the real zenoh-pico z_sub_liveliness CLI and a cc-compiled \
            binary; run by run-ci Layer E"]
fn pico_zliveliness_source_on_wz_capi_is_seen_alive_then_dropped_by_real_pico() {
    let dir = tempfile::tempdir().expect("tempdir for the compiled drop-in");
    let dropin = dropin_binary("z_liveliness", dir.path());
    let z_sub_liveliness = zenoh_pico_cli_binary("z_sub_liveliness");

    let reservation = PortReservation::pick();
    let port = reservation.port();
    let endpoint = format!("tcp/127.0.0.1:{port}");
    let key = "dropin/leg5/token";

    // `-n 2` — exit after ALIVE + DROPPED.
    //
    // R311y482 — line-buffered via `stdbuf`, which this spawn used to omit. The
    // omission was not cosmetic: it made this test's FAILURE undiagnosable, and
    // that is measured, not argued. With stdout redirected to a file and no
    // `stdbuf`, pico's libc buffers block-wise and two short lines never fill 4 KB,
    // so the capture stays at **0 bytes** until the process EXITS — and it exits
    // only on the SECOND event. A run that saw the ALIVE and not the drop therefore
    // produced a capture byte-identical to a run that saw nothing at all, and
    // killing the child loses the buffer outright (measured: 0 bytes before the
    // kill, 0 bytes after). One Layer E run did fail here, its panic named exactly
    // the mode the capture could not distinguish, and the round that hit it could
    // not tell the two apart. With `-oL` the ALIVE line lands the moment it is
    // printed (measured: 148 bytes mid-run against 0 without), so the next failure
    // separates "the token was never seen alive" from "it was seen and never
    // retracted".
    //
    // The sibling `spawn_subscribed_zsub` / `spawn_answering_zqueryable` helpers
    // have always spawned pico under `stdbuf -oL -eL` for this reason; this file
    // spawns pico directly and had drifted from that convention.
    let mut sub_out = tempfile::tempfile().expect("z_sub_liveliness stdout capture");
    let writer = sub_out.try_clone().expect("dup capture handle");
    let mut sub = ChildGuard::wrap(
        "real zenoh-pico z_sub_liveliness",
        Command::new("stdbuf")
            .args(["-oL", "-eL"])
            .arg(&z_sub_liveliness)
            .args([
                "-l",
                &endpoint,
                "-m",
                "peer",
                "-k",
                "dropin/leg5/**",
                "-n",
                "2",
            ])
            .stdout(Stdio::from(writer))
            .stderr(Stdio::from(sub_out.try_clone().expect("dup stderr handle")))
            .spawn()
            .expect("spawn the real zenoh-pico z_sub_liveliness"),
    );
    if let Err(why) = wait_for_tcp_accept_alive(sub.child_mut(), port, LISTEN_TIMEOUT) {
        panic!("the real zenoh-pico z_sub_liveliness never accepted on {endpoint} — {why}");
    }
    drop(reservation);

    // R311y482 — the TOKEN HOLDER's own output is CAPTURED, not discarded. It used
    // to go to `Stdio::null()`, which threw away the only evidence that decides
    // this leg's failure: upstream's `z_liveliness.c` prints `Undeclaring liveliness
    // token...` immediately BEFORE `z_drop(z_move(token))`, so its presence
    // separates "wz never reached the retraction" from "wz retracted and the frame
    // did not reach the peer". With both sides discarded, a failing run said only
    // that pico had not printed `Dropped token` — which is the observation, not a
    // diagnosis. `stdbuf` for the same reason as the subscriber: this is a C program
    // writing to a file.
    let mut holder_out = tempfile::tempfile().expect("token-holder stdout capture");
    let holder_writer = holder_out.try_clone().expect("dup token-holder handle");
    let token = Command::new("stdbuf")
        .args(["-oL", "-eL"])
        .arg(&dropin)
        .args([
            "-e",
            &endpoint,
            "-m",
            "client",
            "-k",
            key,
            "-t",
            TOKEN_HOLD_SECS,
        ])
        .stdout(Stdio::from(holder_writer))
        .stderr(Stdio::from(
            holder_out.try_clone().expect("dup stderr handle"),
        ))
        .status()
        .expect("run the compiled z_liveliness drop-in");
    assert!(token.success(), "z_liveliness.c on wz exited {token:?}");

    let foreign = wait_for_substring(&mut sub_out, "Dropped token", EXCHANGE_TIMEOUT)
        .unwrap_or_else(|captured| {
            // R311y482 — the message states what the capture can SHOW and names both
            // modes, instead of asserting one of them. Its previous wording said a
            // failure here "produces the ALIVE line and nothing else", which was a
            // claim about a state the harness could not observe: without `stdbuf`
            // the capture was empty in BOTH modes (see the spawn site). With line
            // buffering the ALIVE line is now present or absent on its own, so the
            // reader is pointed at that distinction rather than told the answer.
            let saw_alive = captured.contains("New alive token");
            let holder = read_captured(&mut holder_out);
            let holder_undeclared = holder.contains("Undeclaring liveliness token");
            panic!(
                "the REAL zenoh-pico subscriber never printed 'Dropped token'.\n\
                 subscriber saw the ALIVE line: {saw_alive}\n\
                 token holder reached its undeclare: {holder_undeclared}\n\
                 Read those two together -- they name the leg, which a single \
                 missing line cannot:\n\
                 * alive=true, undeclare=true  -> wz RETRACTED and the UndeclToken \
                 did not reach the foreign peer. That is the defect this leg exists \
                 to catch (a drop that frees the local value without emitting).\n\
                 * alive=true, undeclare=false -> the holder never got as far as the \
                 drop, so the retraction path is NOT implicated; look at its hold/exit.\n\
                 * alive=false                 -> the token was never seen alive at \
                 all, so the failure is upstream of the drop (session open / declare).\n\
                 --- REAL pico z_sub_liveliness stdout ---\n{captured}\n\
                 --- z_liveliness.c-on-wz (token holder) stdout ---\n{holder}"
            )
        });
    assert!(
        foreign.contains("New alive token") && foreign.contains(key),
        "the foreign subscriber saw a drop but not the matching alive declaration \
         on {key}.\n--- REAL pico z_sub_liveliness stdout ---\n{foreign}"
    );

    graceful_terminate(sub.child_mut(), Duration::from_secs(5));
}

/// LEG 6 (`pico->wz`) — upstream's `z_sub_liveliness.c`, running on wz, sees a
/// real zenoh-pico token appear and then go away.
///
/// The inbound mirror of leg 5, and it covers what leg 5 cannot: the DECODE of a
/// foreign peer's `DeclToken` / `UndeclToken` into the PUT / DELETE sample kinds
/// upstream's handler switches on. A wz build that delivered both events with
/// the same kind would print "New alive token" twice and fail here while leg 5
/// stayed green.
// wz-proves: api-compat-pico pico->wz partial
// wz-proves: liveliness-subscriber pico->wz partial
#[test]
#[ignore = "spawns the real zenoh-pico z_liveliness CLI and a cc-compiled \
            binary; run by run-ci Layer E"]
fn pico_zsubliveliness_source_on_wz_capi_sees_real_pico_token_come_and_go() {
    let dir = tempfile::tempdir().expect("tempdir for the compiled drop-in");
    let dropin = dropin_binary("z_sub_liveliness", dir.path());
    let z_liveliness = zenoh_pico_cli_binary("z_liveliness");

    let reservation = PortReservation::pick();
    let port = reservation.port();
    let endpoint = format!("tcp/127.0.0.1:{port}");
    let key = "dropin/leg6/token";

    let mut sub_out = tempfile::tempfile().expect("drop-in stdout capture");
    let writer = sub_out.try_clone().expect("dup capture handle");
    let mut sub = ChildGuard::wrap(
        "z_sub_liveliness.c on wz-capi-pico",
        Command::new("stdbuf")
            .args(["-oL", "-eL"])
            .arg(&dropin)
            .args([
                "-l",
                &endpoint,
                "-m",
                "peer",
                "-k",
                "dropin/leg6/**",
                "-n",
                "2",
            ])
            .stdout(Stdio::from(writer))
            .stderr(Stdio::from(sub_out.try_clone().expect("dup stderr handle")))
            .spawn()
            .expect("spawn the compiled z_sub_liveliness drop-in"),
    );
    if let Err(why) = wait_for_tcp_accept_alive(sub.child_mut(), port, LISTEN_TIMEOUT) {
        panic!(
            "the z_sub_liveliness.c drop-in never accepted on {endpoint} — {why}; capture so far:\n{}",
            read_captured(&mut sub_out)
        );
    }
    drop(reservation);

    // R311y482 — captured for the reason leg 5's twin states: this leg is the MIRROR
    // (foreign holder, wz observer), so the holder's `Undeclaring liveliness
    // token...` line is what separates "the foreign side never retracted" from "it
    // retracted and wz's observer did not surface it". Without it the two are the
    // same missing line, and the two point at opposite code.
    let mut holder_out = tempfile::tempfile().expect("foreign z_liveliness stdout capture");
    let holder_writer = holder_out
        .try_clone()
        .expect("dup foreign z_liveliness handle");
    let token = Command::new("stdbuf")
        .args(["-oL", "-eL"])
        .arg(&z_liveliness)
        .args([
            "-e",
            &endpoint,
            "-m",
            "client",
            "-k",
            key,
            "-t",
            TOKEN_HOLD_SECS,
        ])
        .stdout(Stdio::from(holder_writer))
        .stderr(Stdio::from(
            holder_out.try_clone().expect("dup stderr handle"),
        ))
        .status()
        .expect("run the real zenoh-pico z_liveliness");
    assert!(
        token.success(),
        "real zenoh-pico z_liveliness exited {token:?}\n--- its stdout+stderr ---\n{}",
        read_captured(&mut holder_out)
    );

    let local = wait_for_substring(&mut sub_out, "Dropped token", EXCHANGE_TIMEOUT).unwrap_or_else(
        |captured| {
            let holder = read_captured(&mut holder_out);
            panic!(
                "upstream z_sub_liveliness.c on wz never reported the REAL pico \
                 token going away.\n\
                 the FOREIGN holder reached its undeclare: {}\n\
                 If TRUE, pico retracted and wz did not deliver the UndeclToken as a \
                 DELETE-kind sample -- the defect this leg names. If FALSE, the \
                 foreign holder never retracted, so wz's delivery path is not \
                 implicated.\n\
                 --- z_sub_liveliness.c (on wz) stdout ---\n{captured}\n\
                 --- REAL pico z_liveliness (holder) stdout ---\n{holder}",
                holder.contains("Undeclaring liveliness token"),
            )
        },
    );
    assert!(
        local.contains("New alive token") && local.contains(key),
        "the drop-in saw a drop but not the matching alive declaration on {key}.\n\
         --- z_sub_liveliness.c (on wz) stdout ---\n{local}"
    );

    graceful_terminate(sub.child_mut(), Duration::from_secs(5));
}

/// LEG 7 (`wz->pico`) — upstream's `z_get.c`, running on wz, queries a REAL
/// zenoh-pico `z_queryable` and decodes its reply.
///
/// This is the QUERIER direction of leg 2, and it is a distinct claim rather
/// than its mirror: leg 2 proves wz can ANSWER a foreign query, this proves wz
/// can ASK one and render a foreign answer. The payload asserted on
/// (`Queryable from Pico!`) is upstream's own default reply string, produced by
/// the foreign process — a wz-side fabrication could not choose it.
///
/// The program links at all only because of the `z_mutex_*` / `z_condvar_*`
/// family: measured against the 32 upstream examples, those ten symbols were
/// `z_get.c`'s COMPLETE missing set. They carry no zenoh semantics, which is
/// exactly why their absence was easy to miss and why it kept the canonical
/// querier from being a drop-in. What makes them load-bearing HERE is that
/// upstream's `z_get.c` blocks on the condvar until its reply closure signals:
/// a `z_condvar_wait` that returned immediately would race the reply and this
/// leg would flake, and one that never woke would hang it. Neither is possible
/// against a real pthread pair, which is what the module's sync unit tests pin.
// wz-proves: api-compat-pico wz->pico partial
#[test]
#[ignore = "spawns the real zenoh-pico z_queryable CLI and a cc-compiled \
            binary; run by run-ci Layer E"]
fn pico_zget_source_on_wz_capi_queries_real_pico_zqueryable() {
    let dir = tempfile::tempdir().expect("tempdir for the compiled drop-in");
    let dropin = dropin_binary("z_get", dir.path());
    let z_queryable = zenoh_pico_cli_binary("z_queryable");

    let reservation = PortReservation::pick();
    let port = reservation.port();
    let endpoint = format!("tcp/127.0.0.1:{port}");
    // Upstream's z_get.c hard-codes its selector default and takes `-k`; the
    // real pico queryable must cover it. Both sides are upstream text, so the
    // key is the only thing this test chooses.
    let selector = "demo/dropin/leg7";

    // The FOREIGN queryable listens; the drop-in dials in. That direction puts
    // the reply bytes on wz's INBOUND path, where a mis-framed reply payload
    // could not print the string pico chose.
    let mut qbl_out = tempfile::tempfile().expect("queryable stdout capture");
    let qbl_writer = qbl_out.try_clone().expect("dup queryable stdout handle");
    let mut qbl = ChildGuard::wrap(
        "real zenoh-pico z_queryable",
        Command::new("stdbuf")
            .args(["-oL", "-eL"])
            .arg(&z_queryable)
            .args(["-l", &endpoint, "-m", "peer", "-k", "demo/dropin/**"])
            .stdout(Stdio::from(qbl_writer))
            .stderr(Stdio::from(qbl_out.try_clone().expect("dup stderr handle")))
            .spawn()
            .expect("spawn the real zenoh-pico z_queryable"),
    );

    if let Err(why) = wait_for_tcp_accept_alive(qbl.child_mut(), port, LISTEN_TIMEOUT) {
        panic!(
            "the REAL pico z_queryable never accepted on {endpoint} — {why}; \
             capture so far:\n{}",
            read_captured(&mut qbl_out)
        );
    }
    drop(reservation);

    // `z_get.c` is a one-shot: it waits on its condvar for the final
    // notification, then exits — which is what flushes its capture.
    let mut get_out = tempfile::tempfile().expect("z_get stdout capture");
    let get_writer = get_out.try_clone().expect("dup z_get stdout handle");
    let get = Command::new("stdbuf")
        .args(["-oL", "-eL"])
        .arg(&dropin)
        .args(["-e", &endpoint, "-m", "client", "-k", selector])
        .stdout(Stdio::from(get_writer))
        .stderr(Stdio::from(get_out.try_clone().expect("dup stderr handle")))
        .status()
        .expect("run upstream z_get.c on wz's C ABI");
    assert!(
        get.success(),
        "upstream z_get.c on wz's C ABI exited {get:?}\n--- its stdout+stderr ---\n{}",
        read_captured(&mut get_out)
    );

    let local = read_captured(&mut get_out);
    // The REPLY is the verdict and is asserted FIRST. "Received query final
    // notification" prints even when no reply arrived, so asserting the final
    // first would let a silent path pass as green.
    assert!(
        local.contains("Queryable from Pico!"),
        "upstream z_get.c on wz never decoded the REAL pico queryable's reply \
         payload.\n--- z_get.c (on wz) stdout ---\n{local}\n\
         --- REAL pico z_queryable stdout ---\n{}",
        read_captured(&mut qbl_out)
    );
    assert!(
        local.contains(selector),
        "the reply arrived on the wrong key (expected {selector}).\n\
         --- z_get.c (on wz) stdout ---\n{local}"
    );
    assert!(
        local.contains("Received query final notification"),
        "the reply arrived but the query never finalised, so wz's condvar wake \
         did not come from the FINAL.\n--- z_get.c (on wz) stdout ---\n{local}"
    );

    graceful_terminate(qbl.child_mut(), Duration::from_secs(5));
}

/// LEG 8 (`pico->wz`) — upstream's `z_pub.c -a`, running on wz, is told by wz's
/// MATCHING plane when a REAL zenoh-pico `z_sub` appears and when it goes away.
///
/// Both edges are driven by the foreign process, which is what makes this a
/// cross-impl proof rather than a wz-internal one: the `true` edge is caused by
/// real pico's `DeclSubscriber` and the `false` edge by real pico EXITING
/// (`-n 2`, so it undeclares after two samples). wz is only the reporter.
///
/// ## Why this leg exists at the C level at all
///
/// `z_pub.c` is upstream's canonical publisher, and it was missing exactly two
/// exports — `z_closure_matching_status_move` and
/// `z_publisher_declare_background_matching_listener`. Both live in the `-a`
/// arm, which the program links unconditionally and calls only under the flag,
/// so the whole canonical publisher failed to link over an optional feature.
///
/// ## What separates this from a leg that would pass on a lie
///
/// A build that reported `matching = true` unconditionally would print the
/// first line and never the second, so the NO-MORE assertion is the
/// discriminator and it is deliberately not merely a `contains`: it is
/// asserted to arrive AFTER the first, in order, because the aggregate is
/// flip-only and a fixed `false` would print the second line and never the
/// first.
///
/// The delivery window cross-checks the verdict window independently: the
/// foreign subscriber's own capture must show it received samples, and the
/// samples it received are the ones published between the two edges. A matching
/// verdict that had nothing to do with the real subscriber set could satisfy
/// the two edges and would not line up with the payloads pico printed.
// wz-proves: api-compat-pico pico->wz partial
// wz-proves: session-matching pico->wz partial
#[test]
#[ignore = "spawns the real zenoh-pico z_sub CLI and a cc-compiled binary; \
            run by run-ci Layer E"]
fn pico_zpub_source_on_wz_capi_is_told_about_a_real_pico_zsub_arriving_and_leaving() {
    let dir = tempfile::tempdir().expect("tempdir for the compiled drop-in");
    let dropin = dropin_binary("z_pub", dir.path());
    let z_sub = zenoh_pico_cli_binary("z_sub");

    let reservation = PortReservation::pick();
    let port = reservation.port();
    let endpoint = format!("tcp/127.0.0.1:{port}");
    let key = "demo/dropin/leg8";

    // The drop-in LISTENS so the foreign subscriber's declaration arrives on an
    // accepted face — the direction that exercises wz's remote-subscriber
    // registry, which is what the matching verdict is read from.
    //
    // `-n` is generous relative to the ~4 s exchange: the publisher must still
    // be alive after the subscriber has come AND gone, since the `false` edge
    // is only observable in the publisher's own output.
    let mut pub_out = tempfile::tempfile().expect("publisher stdout capture");
    let pub_writer = pub_out.try_clone().expect("dup publisher stdout handle");
    let mut publisher = ChildGuard::wrap(
        "z_pub.c -a on wz-capi-pico",
        Command::new("stdbuf")
            .args(["-oL", "-eL"])
            .arg(&dropin)
            .args(["-l", &endpoint, "-m", "peer", "-k", key, "-a", "-n", "60"])
            .stdout(Stdio::from(pub_writer))
            .stderr(Stdio::from(pub_out.try_clone().expect("dup stderr handle")))
            .spawn()
            .expect("spawn the compiled z_pub drop-in"),
    );

    if let Err(why) = wait_for_tcp_accept_alive(publisher.child_mut(), port, LISTEN_TIMEOUT) {
        panic!(
            "the z_pub.c drop-in never accepted on {endpoint} — {why}; capture \
             so far:\n{}",
            read_captured(&mut pub_out)
        );
    }
    drop(reservation);

    // A self-terminating foreign subscriber: `-n 2` exits after two samples,
    // and that EXIT is the `false` edge's cause. Its own capture is read for
    // the delivery cross-check.
    let mut sub_out = tempfile::tempfile().expect("subscriber stdout capture");
    let sub_writer = sub_out.try_clone().expect("dup subscriber stdout handle");
    let sub = Command::new("stdbuf")
        .args(["-oL", "-eL"])
        .arg(&z_sub)
        .args([
            "-e",
            &endpoint,
            "-m",
            "client",
            "-k",
            "demo/dropin/**",
            "-n",
            "2",
        ])
        .stdout(Stdio::from(sub_writer))
        .stderr(Stdio::from(sub_out.try_clone().expect("dup stderr handle")))
        .status()
        .expect("run the real zenoh-pico z_sub");
    assert!(
        sub.success(),
        "real zenoh-pico z_sub exited {sub:?}\n--- its stdout+stderr ---\n{}",
        read_captured(&mut sub_out)
    );

    // Edge 1: the foreign subscriber's declaration reached wz's matching plane.
    let after_arrival = wait_for_substring(
        &mut pub_out,
        "Publisher has matching subscribers.",
        EXCHANGE_TIMEOUT,
    )
    .unwrap_or_else(|captured| {
        panic!(
            "upstream z_pub.c -a on wz was never told that a REAL pico \
             subscriber matched.\n--- z_pub.c (on wz) stdout ---\n{captured}\n\
             --- REAL pico z_sub stdout ---\n{}",
            read_captured(&mut sub_out)
        )
    });

    // Edge 2: the foreign subscriber going away. This is the discriminator — a
    // build that answered `true` unconditionally passes edge 1 and cannot pass
    // this one.
    let both = wait_for_substring(
        &mut pub_out,
        "Publisher has NO MORE matching subscribers.",
        EXCHANGE_TIMEOUT,
    )
    .unwrap_or_else(|captured| {
        panic!(
            "the arriving edge fired but the DEPARTING one never did, so wz \
             reports matching without retracting it.\n\
             --- z_pub.c (on wz) stdout ---\n{captured}"
        )
    });

    // ORDER, not just presence: the aggregate is flip-only, so a build stuck on
    // `false` would print the NO-MORE line and never the first, and one stuck
    // on `true` the reverse. Requiring arrival to be observable BEFORE
    // departure is what excludes both.
    let arrival_at = both
        .find("Publisher has matching subscribers.")
        .expect("edge 1 is in the capture that contains edge 2");
    let departure_at = both
        .find("Publisher has NO MORE matching subscribers.")
        .expect("edge 2 was just matched");
    assert!(
        arrival_at < departure_at,
        "the two edges arrived out of order (arrival at {arrival_at}, \
         departure at {departure_at}), so the verdict is not tracking the \
         foreign subscriber's lifetime.\n--- z_pub.c (on wz) stdout ---\n{both}"
    );
    assert!(
        after_arrival.len() <= both.len(),
        "capture shrank between reads, which means the harness is not \
         accumulating the child's output"
    );

    // Independent cross-check: the foreign subscriber actually RECEIVED data,
    // so the window the two edges bracket is the window in which delivery
    // happened. A verdict unrelated to the real subscriber set could satisfy
    // both edges and would not line up with this.
    let foreign = read_captured(&mut sub_out);
    assert!(
        foreign.contains(key),
        "the matching edges fired but the REAL pico subscriber never received \
         anything on {key}, so the verdict was not about a live subscription.\n\
         --- REAL pico z_sub stdout ---\n{foreign}"
    );

    graceful_terminate(publisher.child_mut(), Duration::from_secs(5));
}

/// LEG 9 (`wz->foreign ROUTER`) — upstream's `z_info.c`, running on wz, reports
/// the zid of a REAL `zenohd` under **Routers IDs**, and that zid is the one
/// zenohd printed about itself.
///
/// ## Why this leg is worth more than the symbol count suggests
///
/// `z_info.c` cost five exports to link (`z_info_zid`, `z_info_routers_zid`,
/// `z_info_peers_zid`, `z_id_to_string`, `z_closure_zid_move`), and every one of
/// them could be present and WRONG in a way no link check sees:
///
///   * the id could render big-endian — plausible from the source, and
///     disagreeing with every id a pico program prints;
///   * the peers/routers split could be inverted, or collapsed into one bucket;
///   * the enumeration could report the session's OWN id back, or a zero id.
///
/// None of those is a wz-authored assertion here. The VALUE is chosen by
/// zenohd, which prints its own `ZID:` line at startup, and the leg asserts that
/// upstream's program — compiled against pico's headers, linked against wz —
/// prints that same 32-character string. Nothing in wz gets to pick either side
/// of that comparison.
///
/// The BUCKET is the discriminator, and it needs LEG 10 to be one: a build that
/// reported every peer as a router passes this leg and fails that one, and a
/// build that reported none as routers fails this one. Neither leg alone
/// separates the split; the pair does.
// wz-proves: api-compat-pico wz->zenohd partial
#[test]
#[ignore = "spawns the real zenohd router and a cc-compiled binary; \
            run by run-ci Layer E"]
fn pico_zinfo_source_on_wz_capi_reports_a_real_zenohd_as_a_router() {
    let dir = tempfile::tempdir().expect("tempdir for the compiled drop-in");
    let dropin = dropin_binary("z_info", dir.path());
    let zenohd = zenohd_binary();

    let reservation = PortReservation::pick();
    let port = reservation.port();
    let endpoint = format!("tcp/127.0.0.1:{port}");

    let mut router_out = tempfile::tempfile().expect("zenohd stdout capture");
    let router_writer = router_out.try_clone().expect("dup zenohd stdout handle");
    let mut router = ChildGuard::wrap(
        "zenohd",
        Command::new("stdbuf")
            .args(["-oL", "-eL"])
            .arg(&zenohd)
            .args(["--no-multicast-scouting", "-l", &endpoint])
            .env("RUST_LOG", "info")
            .stdout(Stdio::from(router_writer.try_clone().expect("dup")))
            .stderr(Stdio::from(router_writer))
            .spawn()
            .expect("spawn zenohd"),
    );
    if let Err(why) = wait_for_tcp_accept_alive(router.child_mut(), port, LISTEN_TIMEOUT) {
        panic!(
            "zenohd never accepted on {endpoint} — {why}; capture so far:\n{}",
            read_captured(&mut router_out)
        );
    }
    drop(reservation);

    // The ORACLE value: zenohd naming itself. Read from its own log, so the
    // expected string is produced by the foreign process, never by wz.
    let router_log = wait_for_substring(&mut router_out, "ZID:", EXCHANGE_TIMEOUT)
        .unwrap_or_else(|captured| panic!("zenohd never printed its ZID:\n{captured}"));
    let expected_zid = canonical_zid_32(&logged_zid(&router_log));

    let mut info_out = tempfile::tempfile().expect("z_info stdout capture");
    let info_writer = info_out.try_clone().expect("dup z_info stdout handle");
    let info = Command::new("stdbuf")
        .args(["-oL", "-eL"])
        .arg(&dropin)
        .args(["-e", &endpoint, "-m", "client"])
        .stdout(Stdio::from(info_writer))
        .stderr(Stdio::from(
            info_out.try_clone().expect("dup stderr handle"),
        ))
        .status()
        .expect("run the compiled z_info drop-in");
    assert!(info.success(), "z_info.c on wz exited {info:?}");
    let printed = read_captured(&mut info_out);

    let (routers, peers) = split_info_sections(&printed);
    assert!(
        routers.contains(&expected_zid),
        "upstream z_info.c on wz did not report the REAL zenohd's own zid \
         ({expected_zid}) under Routers IDs.\n--- z_info (on wz) stdout ---\n{printed}"
    );
    assert!(
        !peers.contains(&expected_zid),
        "the router's zid was reported under Peers IDs as well, so the \
         whatami split is not being made.\n--- z_info (on wz) stdout ---\n{printed}"
    );
    // Non-vacuity: the session's OWN id must not be what got enumerated.
    let own = printed
        .split("Own ID:")
        .nth(1)
        .and_then(|tail| tail.split_whitespace().next())
        .expect("z_info prints its own id first")
        .to_owned();
    assert_ne!(
        own, expected_zid,
        "z_info reported its own zid as the router's, so the enumeration is \
         not reading the peer set"
    );

    graceful_terminate(router.child_mut(), Duration::from_secs(5));
}

/// LEG 9z (`wz->zenohd`, SHORT ZID) — LEG 9 again with zenohd's zid PINNED to a
/// value whose leading nibble is zero.
///
/// ## Why this leg exists
///
/// LEG 9 red once, on nothing wz did: zenohd came up with the zid
/// `9c3a1e13dd2689ece0c232e62887fbc` and the leg asserted its oracle was 32
/// characters. It is 31. `uhlc::ID` renders through `{:x}` over a `u128`
/// (`uhlc-0.8.2/src/id.rs:281`), so a leading zero nibble is trimmed, and 1
/// random zid in 16 is short — the leg was a 6% flake from the day it was
/// written, and the failure it produced named neither cause nor consequence.
///
/// The number was not the defect. The defect was that the two SIDES of this
/// comparison render the same 16 bytes at different widths, and nothing said so.
/// `canonical_zid_32` now says it; this leg makes the short case DETERMINISTIC
/// rather than leaving it to a 1-in-16 draw, which is the only way a rendering
/// rule stays covered.
///
/// ## What is pinned, and what is still the oracle's to choose
///
/// Only the VALUE is pinned, through zenohd's own `-i`. Both RENDERINGS remain
/// foreign-authored: zenohd prints the trimmed 31-character form into its log,
/// and upstream's `z_info.c` — compiled against pico's headers — prints whatever
/// wz's `z_id_to_string` produces. The leg asserts the padded 32-character form
/// appears under `Routers IDs`, i.e. that wz pads where zenoh trims, which is
/// pico's contract and not a wz preference.
///
/// The trimmed-log assertion is the DAMAGE PROBE, and it is what keeps this leg
/// honest: if a future zenoh stopped trimming, the pin would silently stop
/// exercising the short case and this leg would still pass on padding alone.
/// Asserting the log is 31 characters fails loudly instead.
///
/// zenoh REFUSES a configured zid with a literal leading `0` ("Leading 0s are
/// not valid", `commons/zenoh-protocol/src/core/mod.rs:180`), so the pin is
/// written as the 31-character canonical string — which is exactly the point:
/// the trimmed form IS zenoh's canonical spelling of a value the C side spells
/// with 32.
// wz-proves: api-compat-pico wz->zenohd partial
#[test]
#[ignore = "spawns the real zenohd router and a cc-compiled binary; \
            run by run-ci Layer E"]
fn pico_zinfo_source_on_wz_capi_pads_a_short_zenohd_zid_to_32() {
    /// 31 hex characters: the canonical spelling of a 16-byte zid whose
    /// most-significant nibble is zero.
    const PINNED_ZID_31: &str = "123456789abcdef0123456789abcdef";
    let padded = format!("0{PINNED_ZID_31}");

    let dir = tempfile::tempdir().expect("tempdir for the compiled drop-in");
    let dropin = dropin_binary("z_info", dir.path());
    let zenohd = zenohd_binary();

    let reservation = PortReservation::pick();
    let port = reservation.port();
    let endpoint = format!("tcp/127.0.0.1:{port}");

    let mut router_out = tempfile::tempfile().expect("zenohd stdout capture");
    let router_writer = router_out.try_clone().expect("dup zenohd stdout handle");
    let mut router = ChildGuard::wrap(
        "zenohd",
        Command::new("stdbuf")
            .args(["-oL", "-eL"])
            .arg(&zenohd)
            .args([
                "--no-multicast-scouting",
                "-l",
                &endpoint,
                "-i",
                PINNED_ZID_31,
            ])
            .env("RUST_LOG", "info")
            .stdout(Stdio::from(router_writer.try_clone().expect("dup")))
            .stderr(Stdio::from(router_writer))
            .spawn()
            .expect("spawn zenohd"),
    );
    if let Err(why) = wait_for_tcp_accept_alive(router.child_mut(), port, LISTEN_TIMEOUT) {
        panic!(
            "zenohd never accepted on {endpoint} — {why}; capture so far:\n{}",
            read_captured(&mut router_out)
        );
    }
    drop(reservation);

    let router_log = wait_for_substring(&mut router_out, "ZID:", EXCHANGE_TIMEOUT)
        .unwrap_or_else(|captured| panic!("zenohd never printed its ZID:\n{captured}"));
    let logged = logged_zid(&router_log);
    // DAMAGE PROBE on the pin: zenoh must still be TRIMMING, or this leg is no
    // longer driving the short case it exists for.
    assert_eq!(
        logged, PINNED_ZID_31,
        "zenohd did not log the pinned zid in its trimmed 31-character form, so \
         this leg is no longer exercising the short-oracle case.\n\
         --- zenohd log ---\n{router_log}"
    );
    assert_eq!(canonical_zid_32(&logged), padded);

    let mut info_out = tempfile::tempfile().expect("z_info stdout capture");
    let info_writer = info_out.try_clone().expect("dup z_info stdout handle");
    let info = Command::new("stdbuf")
        .args(["-oL", "-eL"])
        .arg(&dropin)
        .args(["-e", &endpoint, "-m", "client"])
        .stdout(Stdio::from(info_writer))
        .stderr(Stdio::from(
            info_out.try_clone().expect("dup stderr handle"),
        ))
        .status()
        .expect("run the compiled z_info drop-in");
    assert!(info.success(), "z_info.c on wz exited {info:?}");
    let printed = read_captured(&mut info_out);

    let (routers, _peers) = split_info_sections(&printed);
    let listed: Vec<&str> = routers.split_whitespace().collect();
    assert_eq!(
        listed,
        vec![padded.as_str()],
        "upstream z_info.c on wz did not render the pinned zid ZERO-PADDED to 32 \
         characters under Routers IDs. pico prints two hex digits per byte with \
         no trimming (vendor/zenoh-pico/src/utils/uuid.c:38-41), so the leading \
         zero must survive.\n--- z_info (on wz) stdout ---\n{printed}"
    );

    graceful_terminate(router.child_mut(), Duration::from_secs(5));
}

/// LEG 10 (`wz->foreign PEER`) — the same program against a REAL zenoh-pico peer
/// reports it under **Peers IDs** instead.
///
/// This is LEG 9's other half. A build that put every connected face in one
/// bucket satisfies exactly one of the two, whichever bucket it chose, so the
/// pair is what pins the `whatami` split. See LEG 9 for why neither is
/// sufficient alone.
// wz-proves: api-compat-pico wz->pico partial
#[test]
#[ignore = "spawns the real zenoh-pico z_sub CLI and a cc-compiled binary; \
            run by run-ci Layer E"]
fn pico_zinfo_source_on_wz_capi_reports_a_real_pico_peer_as_a_peer() {
    let dir = tempfile::tempdir().expect("tempdir for the compiled drop-in");
    let dropin = dropin_binary("z_info", dir.path());
    let z_sub = zenoh_pico_cli_binary("z_sub");

    let reservation = PortReservation::pick();
    let port = reservation.port();
    let endpoint = format!("tcp/127.0.0.1:{port}");

    let mut peer_out = tempfile::tempfile().expect("pico z_sub stdout capture");
    let peer_writer = peer_out.try_clone().expect("dup pico stdout handle");
    let mut peer = ChildGuard::wrap(
        "real zenoh-pico z_sub (listening peer)",
        Command::new("stdbuf")
            .args(["-oL", "-eL"])
            .arg(&z_sub)
            .args(["-l", &endpoint, "-m", "peer", "-k", "demo/dropin/**"])
            .stdout(Stdio::from(peer_writer))
            .stderr(Stdio::from(
                peer_out.try_clone().expect("dup stderr handle"),
            ))
            .spawn()
            .expect("spawn the real zenoh-pico z_sub as a listener"),
    );
    if let Err(why) = wait_for_tcp_accept_alive(peer.child_mut(), port, LISTEN_TIMEOUT) {
        panic!(
            "the real pico z_sub never accepted on {endpoint} — {why}; capture \
             so far:\n{}",
            read_captured(&mut peer_out)
        );
    }
    drop(reservation);

    let mut info_out = tempfile::tempfile().expect("z_info stdout capture");
    let info_writer = info_out.try_clone().expect("dup z_info stdout handle");
    let info = Command::new("stdbuf")
        .args(["-oL", "-eL"])
        .arg(&dropin)
        .args(["-e", &endpoint, "-m", "client"])
        .stdout(Stdio::from(info_writer))
        .stderr(Stdio::from(
            info_out.try_clone().expect("dup stderr handle"),
        ))
        .status()
        .expect("run the compiled z_info drop-in");
    assert!(info.success(), "z_info.c on wz exited {info:?}");
    let printed = read_captured(&mut info_out);

    let (routers, peers) = split_info_sections(&printed);
    let listed: Vec<&str> = peers.split_whitespace().collect();
    assert_eq!(
        listed.len(),
        1,
        "exactly one foreign peer is connected, so exactly one zid must be \
         listed under Peers IDs.\n--- z_info (on wz) stdout ---\n{printed}"
    );
    assert_eq!(
        listed[0].len(),
        32,
        "a zid renders as 32 hex characters.\n--- z_info (on wz) stdout ---\n{printed}"
    );
    assert!(
        routers.split_whitespace().next().is_none(),
        "a pico PEER was reported under Routers IDs -- the whatami split is \
         inverted or collapsed.\n--- z_info (on wz) stdout ---\n{printed}"
    );

    graceful_terminate(peer.child_mut(), Duration::from_secs(5));
}

/// Split `z_info.c`'s output into its `Routers IDs:` and `Peers IDs:` sections.
///
/// The program prints the two as consecutive labelled blocks, so the split is on
/// the labels themselves rather than on line offsets — a leg that counted lines
/// would break the moment upstream added a field.
fn split_info_sections(printed: &str) -> (String, String) {
    let after_routers = printed.split("Routers IDs:").nth(1).unwrap_or("");
    let mut halves = after_routers.split("Peers IDs:");
    let routers = halves.next().unwrap_or("").to_owned();
    // Everything after `Peers IDs:` up to the next label, if any. With
    // Z_FEATURE_CONNECTIVITY off there is no next label, so this is the tail.
    let peers = halves
        .next()
        .unwrap_or("")
        .split("Connected")
        .next()
        .unwrap_or("")
        .to_owned();
    (routers, peers)
}

/// The zid a Rust zenoh node printed about itself, lifted out of its log line.
fn logged_zid(router_log: &str) -> String {
    router_log
        .split("ZID:")
        .nth(1)
        .and_then(|tail| tail.split_whitespace().next())
        .map(|s| s.trim().to_ascii_lowercase())
        .expect("a zenoh node's ZID line carries a value")
}

/// Widen a zid as a RUST zenoh node renders it to the form a C program prints.
///
/// The two renderings of one 16-byte value do NOT have the same width, and this
/// leg used to assert they did. `zenohd` logs its zid through `uhlc::ID`'s
/// `Display`, which is `write!(f, "{:x}", u128::from_le_bytes(self.0))`
/// (`uhlc-0.8.2/src/id.rs:281`) — a `u128` hex format, so every LEADING ZERO
/// NIBBLE is trimmed. One random zid in 16 therefore logs as 31 characters, one
/// in 256 as 30, and so on. The C side never trims: pico's `_z_id_to_string`
/// hands all 16 bytes to `_z_string_convert_bytes_le`
/// (`vendor/zenoh-pico/src/utils/uuid.c:38-41`), which emits two hex digits per
/// byte unconditionally, and wz's `z_id_to_string` matches that
/// (`crates/wz-capi-pico/src/zid.rs:318-326`).
///
/// So the comparison has to be made on a canonical form. Left-padding to 32 is
/// that form because it is the one the C program prints, which keeps the
/// assertions below EXACT-WIDTH matches. The alternative — comparing on the
/// log's literal text — degrades to a suffix match the moment the oracle is
/// short, and a suffix match is a weaker claim than this leg is making.
///
/// The guard that replaces the old `== 32` states what upstream actually
/// guarantees: a zid renders as 1..=32 lowercase hex characters. `LEG 9z` drives
/// the short case deterministically rather than waiting 16 runs for it.
fn canonical_zid_32(logged: &str) -> String {
    assert!(
        !logged.is_empty()
            && logged.len() <= 32
            && logged
                .bytes()
                .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase()),
        "a zenoh node's self-reported zid must be 1..=32 lowercase hex \
         characters, got {logged:?} ({} chars)",
        logged.len(),
    );
    format!("{logged:0>32}")
}

/// LEG 11 (`wz->pico`, THROUGHPUT) — upstream's `z_pub_thr.c`, running on wz
/// with its `zp_batch_start` / `zp_batch_stop` window, delivers to a REAL
/// zenoh-pico subscriber.
///
/// ## What this proves that the other publish legs do not
///
/// LEG 3 and LEG 8 publish a handful of samples. This one drives the batching
/// path: `z_pub_thr.c` opens a TX batch window, publishes in a tight loop, and
/// closes it. Three things only this leg exercises:
///
///   * `zp_batch_start` / `zp_batch_stop` reaching every face rather than
///     erroring or silently no-op'ing;
///   * `_z_zint_len`, which the program calls to SIZE its payload — a wrong
///     answer changes the message size the benchmark chooses, and the program
///     links it directly even though it is an internal symbol;
///   * sustained delivery, where a batching bug that coalesced frames
///     incorrectly would surface as the foreign subscriber decoding garbage or
///     stalling, not as a wrong first sample.
///
/// The foreign subscriber is self-terminating (`-n`), so its EXIT is the
/// witness: it exits only once it has decoded that many well-formed samples
/// from wz's batched frames, and a coalescing bug leaves it waiting.
// wz-proves: api-compat-pico wz->pico partial
#[test]
#[ignore = "spawns the real zenoh-pico z_sub CLI and a cc-compiled binary; \
            run by run-ci Layer E"]
fn pico_zpubthr_source_on_wz_capi_batches_to_a_real_pico_zsub() {
    let dir = tempfile::tempdir().expect("tempdir for the compiled drop-in");
    let dropin = dropin_binary("z_pub_thr", dir.path());
    let z_sub = zenoh_pico_cli_binary("z_sub");

    let reservation = PortReservation::pick();
    let port = reservation.port();
    let endpoint = format!("tcp/127.0.0.1:{port}");
    let key = "demo/dropin/thr";

    let mut sub_out = tempfile::tempfile().expect("subscriber stdout capture");
    let sub_writer = sub_out.try_clone().expect("dup subscriber stdout handle");
    let mut sub = ChildGuard::wrap(
        "real zenoh-pico z_sub (listening peer)",
        Command::new("stdbuf")
            .args(["-oL", "-eL"])
            .arg(&z_sub)
            .args(["-l", &endpoint, "-m", "peer", "-k", key, "-n", "50"])
            .stdout(Stdio::from(sub_writer))
            .stderr(Stdio::from(sub_out.try_clone().expect("dup stderr handle")))
            .spawn()
            .expect("spawn the real zenoh-pico z_sub as a listener"),
    );
    if let Err(why) = wait_for_tcp_accept_alive(sub.child_mut(), port, LISTEN_TIMEOUT) {
        panic!(
            "the real pico z_sub never accepted on {endpoint} — {why}; capture \
             so far:\n{}",
            read_captured(&mut sub_out)
        );
    }
    drop(reservation);

    // The benchmark never terminates on its own; it is killed once the foreign
    // subscriber has had its fill, which is the actual assertion.
    let mut pub_out = tempfile::tempfile().expect("publisher stdout capture");
    let pub_writer = pub_out.try_clone().expect("dup publisher stdout handle");
    let mut publisher = ChildGuard::wrap(
        "z_pub_thr.c on wz-capi-pico",
        Command::new("stdbuf")
            .args(["-oL", "-eL"])
            .arg(&dropin)
            .args(["-e", &endpoint, "-m", "client", "-k", key, "-s", "64"])
            .stdout(Stdio::from(pub_writer))
            .stderr(Stdio::from(pub_out.try_clone().expect("dup stderr handle")))
            .spawn()
            .expect("spawn the compiled z_pub_thr drop-in"),
    );

    let status = wait_for_exit(sub.child_mut(), EXCHANGE_TIMEOUT).unwrap_or_else(|why| {
        panic!(
            "the REAL pico subscriber never decoded its 50 samples from wz's \
             BATCHED frames, so the zp_batch_* window is not producing \
             well-formed output ({why}).\n--- pico z_sub stdout ---\n{}\n\
             --- z_pub_thr (on wz) stdout ---\n{}",
            read_captured(&mut sub_out),
            read_captured(&mut pub_out)
        )
    });
    assert!(
        status.success(),
        "the real pico subscriber exited {status:?}\n--- its stdout+stderr ---\n{}",
        read_captured(&mut sub_out)
    );
    let foreign = read_captured(&mut sub_out);
    assert!(
        foreign.contains(key),
        "the subscriber exited but never named {key}, so the samples it \
         counted were not wz's.\n--- pico z_sub stdout ---\n{foreign}"
    );

    graceful_terminate(publisher.child_mut(), Duration::from_secs(5));
}

/// LEG 12 (`wz->pico`, QUERIER) — upstream's `z_get_lat.c`, running on wz,
/// round-trips through a REAL zenoh-pico queryable.
///
/// ## Why this program and not a hand-written querier exercise
///
/// `z_get_lat.c` is the canonical querier client, and it uses the family the way
/// a real program does rather than the way a test author would: it declares ONCE
/// and gets many times, passes `NULL` options and `NULL` parameters (so the
/// defaults are the thing under test), and — decisively — it BLOCKS on each
/// reply before issuing the next. Its `load_loop` spins until the reply counter
/// increments, so a querier that issued nothing, issued to the wrong keyexpr, or
/// dropped the reply does not fail an assertion; it hangs, and the leg times out.
///
/// That makes the program's own EXIT the witness. Its keyexpr is hard-coded
/// `"lat"`, so the foreign counterparty is a real pico `z_queryable` on that
/// key, and the leg additionally reads that queryable's own log — a program that
/// somehow satisfied its reply counter without the foreign process seeing a
/// query would fail the cross-check.
///
/// The printed body is `ping_nb` microsecond figures, one per round trip, so the
/// line count is the round-trip count: five requested, five printed, five
/// answered by a process wz does not own.
// wz-proves: api-compat-pico wz->pico partial
#[test]
#[ignore = "spawns the real zenoh-pico z_queryable CLI and a cc-compiled \
            binary; run by run-ci Layer E"]
fn pico_zgetlat_source_on_wz_capi_round_trips_through_real_pico_zqueryable() {
    let dir = tempfile::tempdir().expect("tempdir for the compiled drop-in");
    let dropin = dropin_binary("z_get_lat", dir.path());
    let z_queryable = zenoh_pico_cli_binary("z_queryable");

    let reservation = PortReservation::pick();
    let port = reservation.port();
    let endpoint = format!("tcp/127.0.0.1:{port}");
    // Hard-coded in the upstream program; the foreign queryable must match it.
    let key = "lat";
    let rounds = 5usize;

    let mut qable_out = tempfile::tempfile().expect("queryable stdout capture");
    let qable_writer = qable_out.try_clone().expect("dup queryable stdout handle");
    let mut qable = ChildGuard::wrap(
        "real zenoh-pico z_queryable (listening peer)",
        Command::new("stdbuf")
            .args(["-oL", "-eL"])
            .arg(&z_queryable)
            .args(["-l", &endpoint, "-m", "peer", "-k", key])
            .stdout(Stdio::from(qable_writer))
            .stderr(Stdio::from(
                qable_out.try_clone().expect("dup stderr handle"),
            ))
            .spawn()
            .expect("spawn the real zenoh-pico z_queryable as a listener"),
    );
    if let Err(why) = wait_for_tcp_accept_alive(qable.child_mut(), port, LISTEN_TIMEOUT) {
        panic!(
            "the real pico z_queryable never accepted on {endpoint} — {why}; \
             capture so far:\n{}",
            read_captured(&mut qable_out)
        );
    }
    drop(reservation);

    let mut lat_out = tempfile::tempfile().expect("z_get_lat stdout capture");
    let lat_writer = lat_out.try_clone().expect("dup z_get_lat stdout handle");
    let lat = Command::new("stdbuf")
        .args(["-oL", "-eL"])
        .arg(&dropin)
        .args([
            "-e",
            &endpoint,
            "-m",
            "client",
            "-n",
            &rounds.to_string(),
            "-w",
            "200",
        ])
        .stdout(Stdio::from(lat_writer))
        .stderr(Stdio::from(lat_out.try_clone().expect("dup stderr handle")))
        .status()
        .expect("run the compiled z_get_lat drop-in");
    let printed = read_captured(&mut lat_out);
    assert!(
        lat.success(),
        "z_get_lat.c on wz exited {lat:?} — a querier that never delivered a \
         reply BLOCKS in its load_loop, so a non-zero exit or a timeout here \
         means the querier plane did not round-trip.\n--- its stdout+stderr ---\n\
         {printed}\n--- REAL pico z_queryable stdout ---\n{}",
        read_captured(&mut qable_out)
    );

    // The body is one microsecond figure per completed round trip.
    let measurements: Vec<&str> = printed
        .lines()
        .filter(|line| !line.trim().is_empty() && line.trim().parse::<u64>().is_ok())
        .collect();
    assert_eq!(
        measurements.len(),
        rounds,
        "z_get_lat printed {} measurements, expected {rounds} — each line is \
         one COMPLETED round trip through the foreign queryable.\n\
         --- z_get_lat (on wz) stdout ---\n{printed}",
        measurements.len()
    );
    assert!(
        !printed.contains("Tx failed"),
        "z_querier_get reported a transmit failure.\n--- stdout+stderr ---\n{printed}"
    );

    // Cross-check against the counterparty: the foreign process must have SEEN
    // the queries. Without this, a build whose reply counter advanced for some
    // other reason would satisfy every assertion above.
    let foreign = wait_for_substring(
        &mut qable_out,
        "[Queryable handler] Received Query",
        EXCHANGE_TIMEOUT,
    )
    .unwrap_or_else(|captured| {
        panic!(
            "z_get_lat completed its round trips but the REAL pico queryable \
             never logged a query, so the replies did not come from it.\n\
             --- REAL pico z_queryable stdout ---\n{captured}"
        )
    });
    assert!(
        foreign.contains(key),
        "the foreign queryable logged queries but not on {key}.\n\
         --- REAL pico z_queryable stdout ---\n{foreign}"
    );

    graceful_terminate(qable.child_mut(), Duration::from_secs(5));
}

/// LEG 13 (`wz->pico`, ATTACHMENT PLANE) — upstream's `z_pub_attachment.c`,
/// running on wz, is decoded IN FULL by a REAL zenoh-pico `z_sub_attachment`:
/// the encoding string, the timestamp, and the serialized key/value attachment.
///
/// ## This leg is the only thing that can pin the encoding ID
///
/// `wz-capi-pico/src/encoding.rs` maps `"zenoh/string;utf8"` to a numeric id
/// through a 53-entry table, and the id is what goes on the wire. The
/// `libzenohpico.so` oracle test cannot check that mapping — `from_str` and
/// `to_string` read the SAME table, so a round trip is invariant under any
/// permutation of it, demonstrated by a damage probe that swapped two entries
/// and stayed green. Here a FOREIGN decoder prints the string it recovered from
/// wz's bytes, so a wrong id shows up as a wrong name.
///
/// The attachment does the same job for the serialization format: the kv pairs
/// are written by wz's `ze_serializer_*` and read back by pico's OWN
/// `ze_deserializer_*`, so the `<vle len><bytes>` framing is adjudicated by
/// upstream's parser rather than by wz's.
///
/// ## What this caught, which a link check could not
///
/// `z_pub_attachment.c` linked and RAN before any of this worked: it printed its
/// own "Putting Data" lines while the real pico subscriber reported
/// `encoding: zenoh/bytes` with no attachment and no timestamp, because
/// `z_publisher_put` took its options as `*const c_void` and dropped all three.
/// A link is not a pass, and that is what the difference looked like.
// wz-proves: api-compat-pico wz->pico partial
#[test]
#[ignore = "spawns the real zenoh-pico z_sub_attachment CLI and a cc-compiled \
            binary; run by run-ci Layer E"]
fn pico_zpubattachment_source_on_wz_capi_is_fully_decoded_by_real_pico() {
    let dir = tempfile::tempdir().expect("tempdir for the compiled drop-in");
    let dropin = dropin_binary("z_pub_attachment", dir.path());
    let z_sub_attachment = zenoh_pico_cli_binary("z_sub_attachment");

    let reservation = PortReservation::pick();
    let port = reservation.port();
    let endpoint = format!("tcp/127.0.0.1:{port}");

    let mut sub_out = tempfile::tempfile().expect("subscriber stdout capture");
    let sub_writer = sub_out.try_clone().expect("dup subscriber stdout handle");
    let mut sub = ChildGuard::wrap(
        "real zenoh-pico z_sub_attachment (listening peer)",
        Command::new("stdbuf")
            .args(["-oL", "-eL"])
            .arg(&z_sub_attachment)
            .args(["-l", &endpoint, "-m", "peer", "-k", "demo/**", "-n", "2"])
            .stdout(Stdio::from(sub_writer))
            .stderr(Stdio::from(sub_out.try_clone().expect("dup stderr handle")))
            .spawn()
            .expect("spawn the real zenoh-pico z_sub_attachment as a listener"),
    );
    if let Err(why) = wait_for_tcp_accept_alive(sub.child_mut(), port, LISTEN_TIMEOUT) {
        panic!(
            "the real pico z_sub_attachment never accepted on {endpoint} — \
             {why}; capture so far:\n{}",
            read_captured(&mut sub_out)
        );
    }
    drop(reservation);

    // R311y606 — captured, not discarded. A process whose exit status is
    // ASSERTED must leave its reason behind: these legs failed twice in one
    // Layer E measurement with nothing to read but the exit code.
    let mut pub_out = tempfile::tempfile().expect("z_pub_attachment capture");
    let publisher = Command::new("stdbuf")
        .args(["-oL", "-eL"])
        .arg(&dropin)
        .args(["-e", &endpoint, "-m", "client", "-n", "2"])
        .stdout(Stdio::from(pub_out.try_clone().expect("dup stdout handle")))
        .stderr(Stdio::from(pub_out.try_clone().expect("dup stderr handle")))
        .status()
        .expect("run the compiled z_pub_attachment drop-in");
    assert!(
        publisher.success(),
        "z_pub_attachment.c on wz exited {publisher:?}\n--- its stdout+stderr ---\n{}",
        read_captured(&mut pub_out)
    );

    let status = wait_for_exit(sub.child_mut(), EXCHANGE_TIMEOUT).unwrap_or_else(|why| {
        panic!(
            "the REAL pico subscriber never received its two samples ({why}).\n\
             --- pico z_sub_attachment stdout ---\n{}",
            read_captured(&mut sub_out)
        )
    });
    assert!(
        status.success(),
        "the real pico subscriber exited {status:?}\n--- its stdout+stderr ---\n{}",
        read_captured(&mut sub_out)
    );
    let foreign = read_captured(&mut sub_out);

    // The ENCODING, named by the foreign decoder. `zenoh/string` is table id 1
    // and `;utf8` is its schema, so this one line pins both halves of the
    // packed wire word.
    assert!(
        foreign.contains("with encoding: zenoh/string;utf8"),
        "the REAL pico subscriber did not decode the encoding wz sent — a wrong \
         table id renders as a different name here.\n\
         --- pico z_sub_attachment stdout ---\n{foreign}"
    );
    // The ATTACHMENT, deserialized by pico's own `ze_deserializer_*`. The kv
    // content is chosen by the upstream program, not by this test.
    assert!(
        foreign.contains("with attachment:"),
        "no attachment reached the foreign subscriber.\n\
         --- pico z_sub_attachment stdout ---\n{foreign}"
    );
    assert!(
        foreign.contains("source, C"),
        "the attachment arrived but its serialized key/value pairs did not \
         deserialize through pico's own reader — the `<vle len><bytes>` framing \
         disagrees.\n--- pico z_sub_attachment stdout ---\n{foreign}"
    );
    // The TIMESTAMP, which the program stamps from the session and which the
    // subscriber prints only when present.
    assert!(
        foreign.contains("with timestamp:"),
        "no timestamp reached the foreign subscriber.\n\
         --- pico z_sub_attachment stdout ---\n{foreign}"
    );
}

/// LEG 14 (`pico->wz`) — upstream's `z_sub.c` on wz, subscribing to a
/// **WILDCARD**, receives from the REAL zenoh-pico `z_pub` binary: a DECLARED
/// publisher, not a `z_put`.
///
/// The distinction is the whole leg, and until R311y530 nothing covered it.
/// Every other `pico->wz` leg in this file drives `z_put`, which carries no
/// write filter and therefore cannot observe the publisher path at all.
/// `z_declare_publisher` arms `_z_write_filter_create` (`net/filtering.c`) and
/// pico then drops every put LOCALLY until its interest is answered — so a
/// session that ignores a subscriber Interest passes LEG 1 and silently blocks
/// every pico app built on `z_declare_publisher`.
///
/// MEASURED, and the numbers are why this leg exists in this shape: without
/// wz's interest response it fails 12 of 12 runs; with it, 8 of 8. R311y529
/// carried the symptom ("a real pico DECLARED publisher delivers NOTHING to a
/// wz C-ABI session") without the mechanism.
///
/// It is also a lesson about GREEN. An early R311y530 run of this same leg
/// passed repeatedly against an unfixed tree, and that green nearly retracted a
/// true carry: a publisher whose filter fails to ARM writes freely, so "it
/// worked" and "the mechanism is present" are different claims. The rate had to
/// be measured over repeats before either direction could be believed — a
/// single green run here proves nothing at all.
///
/// The keyexpr is a WILDCARD on purpose and it is the discriminating half:
/// `zzz/**` against the same publisher delivers ZERO (measured), so the
/// assertion is not vacuous, and an EXACT keyexpr passes WITHOUT the interest
/// response (wz's unsolicited `DeclSubscriber` for the literal key satisfies
/// the peer either way) and would therefore prove nothing.
///
/// What this leg does NOT discriminate, stated rather than implied: the reply's
/// KEYEXPR. Damage-probed — answering with the subscription's own `demo/**`
/// instead of the interest's keyexpr still passes 4 of 4. The measured
/// discriminator is the interest-stamped reply EXISTING. The aggregate-keyexpr
/// choice in `SubscriberRegistry::respond_to_subscriber_interest_borrowed` is
/// upstream parity (`session/interest.c:274-276` associates an AGGREGATE
/// interest's replies by `_z_keyexpr_equals`), not something this test pins.
// wz-proves: api-compat-pico pico->wz partial
#[test]
#[ignore = "spawns the real zenoh-pico z_pub CLI and a cc-compiled binary; \
            run by run-ci Layer E"]
fn pico_zsub_source_on_wz_capi_receives_from_a_real_pico_declared_publisher() {
    let dir = tempfile::tempdir().expect("tempdir for the compiled drop-in");
    let dropin = dropin_binary("z_sub", dir.path());
    let z_pub = zenoh_pico_cli_binary("z_pub");

    let reservation = PortReservation::pick();
    let port = reservation.port();
    let endpoint = format!("tcp/127.0.0.1:{port}");
    // The publisher's literal key. The subscriber below deliberately does NOT
    // name it — see the doc comment.
    let key = "demo/declared/leg14";

    let mut sub_out = tempfile::tempfile().expect("subscriber stdout capture");
    let writer = sub_out.try_clone().expect("dup subscriber stdout handle");
    let mut sub = ChildGuard::wrap(
        "z_sub.c on wz-capi-pico (wildcard)",
        Command::new("stdbuf")
            .args(["-oL", "-eL"])
            .arg(&dropin)
            .args([
                "-l", &endpoint, "-m", "peer",
                // WILDCARD, load-bearing: an exact keyexpr passes without the
                // interest-response and would make this leg vacuous.
                "-k", "demo/**", "-n", "1",
            ])
            .stdout(Stdio::from(writer))
            .stderr(Stdio::from(sub_out.try_clone().expect("dup stderr handle")))
            .spawn()
            .expect("spawn the compiled z_sub drop-in"),
    );

    if let Err(why) = wait_for_tcp_accept_alive(sub.child_mut(), port, LISTEN_TIMEOUT) {
        panic!(
            "the z_sub.c drop-in never accepted on {endpoint} — {why}; capture so far:\n{}",
            read_captured(&mut sub_out)
        );
    }
    drop(reservation);

    // The REAL pico publisher. `-n 4` rather than 1: the first put can race the
    // declaration exchange, and a publisher that is only ever going to send once
    // would turn a timing question into a delivery question.
    let mut pub_out = tempfile::tempfile().expect("foreign z_pub stdout capture");
    let pub_writer = pub_out.try_clone().expect("dup foreign z_pub handle");
    let published = Command::new("stdbuf")
        .args(["-oL", "-eL"])
        .arg(&z_pub)
        .args(["-e", &endpoint, "-m", "client", "-k", key, "-n", "4"])
        .stdout(Stdio::from(pub_writer))
        .stderr(Stdio::from(pub_out.try_clone().expect("dup stderr handle")))
        .status()
        .expect("run the real zenoh-pico z_pub");
    assert!(
        published.success(),
        "real zenoh-pico z_pub exited {published:?}\n--- its stdout+stderr ---\n{}",
        read_captured(&mut pub_out)
    );

    let captured =
        wait_for_substring(&mut sub_out, key, EXCHANGE_TIMEOUT).unwrap_or_else(|captured| {
            let driver = read_captured(&mut pub_out);
            panic!(
                "upstream z_sub.c on wz's C-ABI, subscribed to `demo/**`, never received \
                 anything from the REAL zenoh-pico z_pub — a DECLARED publisher.\n\
                 The publisher reached its put loop: {}\n\
                 If it did, pico's write filter never opened, so wz's \
                 `Declare(DeclSubscriber)` for `demo/**` either did not reach the \
                 publisher or did not match its subscriber Interest.\n\
                 --- z_sub.c (on wz) stdout ---\n{captured}\n\
                 --- REAL pico z_pub (driver) stdout ---\n{driver}",
                driver.contains("Putting Data"),
            )
        });
    assert!(
        captured.contains("Pub from Pico"),
        "a sample arrived on the key but not the payload the foreign DECLARED \
         publisher sends.\n--- stdout+stderr ---\n{captured}"
    );

    graceful_terminate(sub.child_mut(), Duration::from_secs(5));
}

/// Compile an upstream example against the REAL `libzenohpico.so` — the ORACLE
/// twin of [`dropin_binary`].
///
/// The two differ in exactly one flag (`-lzenohpico` vs `-lwz_capi_pico`);
/// everything else — upstream's program text, upstream's headers, the same
/// compiler — is shared. That is what makes a diff of their OUTPUT a statement
/// about the two libraries and nothing else.
fn oracle_binary(example: &str, dir: &std::path::Path) -> std::path::PathBuf {
    let root = project_root();
    let src = root
        .join("vendor/zenoh-pico/examples/unix/c11")
        .join(format!("{example}.c"));
    // R311y536 — through the REGISTERED resolver, not a local `join`. Layer A4
    // reads a file's foreign class off the resolver functions it names, so a
    // hand-built path makes the reference arm invisible to the audit even
    // though it links real pico. `zenoh_pico_library_dir` carries the same
    // hard-prereq assert this used to inline.
    let libdir = zenoh_pico_library_dir();
    let exe = dir.join(format!("{example}_oracle"));
    let cc = std::env::var("CC").unwrap_or_else(|_| "cc".to_string());
    let mut cmd = Command::new(&cc);
    cmd.arg(&src).arg("-DZENOH_LINUX");
    for inc in &zenoh_pico_include_dirs() {
        cmd.arg(format!("-I{}", inc.display()));
    }
    cmd.arg("-o")
        .arg(&exe)
        .arg(format!("-L{}", libdir.display()))
        .arg("-lzenohpico")
        .arg(format!("-Wl,-rpath,{}", libdir.display()));
    let out = cmd.output().expect("spawn the C compiler for the oracle");
    assert!(
        out.status.success(),
        "the ORACLE build failed for {example}.c against the real zenoh-pico:\n{}",
        String::from_utf8_lossy(&out.stderr)
    );
    exe
}

/// The `Hello { ... }` line `z_scout.c` prints for the peer listening on
/// `port`, or `None`. Selecting by the PORT rather than by line index is what
/// makes this robust to another zenoh process answering the same host-wide
/// multicast group: an extra peer adds a line, it does not move this one.
///
/// R2230 (open-debt item 579) — the needle was `tcp/127.0.0.1:{port}` and is now
/// `:{port}` inside any `tcp/` locator. The pinned 1.10.0 answers a NON-loopback
/// scouter with `get_locators_noloopback()`, so the reply carries the router's
/// real-interface addresses and never the loopback literal; see
/// `spawn_zenohd_multicast_scouting_on_any_interface` for the measurement. The
/// PORT is what the discrimination rested on all along — it is the value the
/// kernel chose and neither scout was told — and pinning the address as well was
/// pinning the one part of the locator this leg does not care about.
fn hello_line_for_port(printed: &str, port: u16) -> Option<&str> {
    hello_lines_for_port(printed, port).next()
}

/// Every such line, for the callers that assert HOW MANY there are.
///
/// R2230 (open-debt item 579) — extracted because the predicate had been written
/// out a third and fourth time, inline, in the two occurrence counters. When the
/// pin move invalidated the locator's address those copies did not move with
/// `hello_line_for_port`, and the counters went to zero while the finder
/// succeeded — one predicate reading two different ways about the same output.
/// Counting and finding are now the same question asked twice.
fn hello_lines_for_port(printed: &str, port: u16) -> impl Iterator<Item = &str> {
    let needle = format!(":{port}");
    printed
        .lines()
        .filter(move |l| l.starts_with("Hello {") && l.contains("tcp/") && l.contains(&needle))
}

/// LEG 15 (`wz vs pico`, ORACLE) — upstream's `z_scout.c`, compiled twice
/// against the SAME headers and linked once to wz's cdylib and once to the REAL
/// `libzenohpico.so`, discovers the SAME zenohd and prints the SAME line.
///
/// R311y530 built the scouting plane (`z_scout`, `z_hello_*`, `z_string_array_*`,
/// `z_whatami_to_view_string`, `zp_hello_locators`, `z_closure_hello_move`) and
/// this is what says it is right rather than merely linked — the y529 lesson,
/// where `z_pub_attachment.c` linked, RAN, and silently dropped three fields.
///
/// Every field in the compared line is chosen by a foreign process:
///
/// - the **zid** is zenohd's, and its BYTE ORDER is the assertion that a
///   substring check would miss. `fprintzid` walks `id[i]` ascending, so the
///   rendered string is the reverse of the id zenohd prints in its own log; a
///   wz that stored the wire bytes reversed would print a plausible 32-hex
///   string that differs from the oracle's in every byte.
/// - the **whatami** is `"Router"`, which pins the bitmask INDEX (slot 1 of
///   upstream's map, not an ordinal list — slot 3 is `Router|Peer`).
/// - the **locator** carries an EPHEMERAL port the kernel chose and this test
///   never gave to either scout, so no build that merely parsed a flag can
///   print it.
///
/// It also pins ONE LINE PER PEER, which the line comparison does not imply.
/// When this leg was written wz drove discovery in repeated CYCLES — the
/// scouting FSM left `AwaitingHello` on the first Hello, so a single window
/// could report one peer — and a live responder answered every cycle, which is
/// why delivery had to be keyed on the zid. The FSM carries pico's
/// `exit_on_first == false` survey arm now (`src/session/scout.c:121-123`), so
/// wz emits ONE Scout for the whole budget and this count is upstream's own
/// arithmetic rather than a de-duplication of wz's own re-asking.
///
/// The name carries `zenohd` deliberately: Layer E's sweep skips that token
/// because it provisions no router, so this leg is registered by exact name in
/// Layer Z, which does. Renaming to dodge the token would make Layer E red on
/// every machine without zenohd.
// R311y536 — `wz-vs-pico` was never a KIND. The grammar admits
// codec-parity / pico->wz / wz->pico / wz->zenoh-ext / wz->zenohd /
// zenoh-ext->wz / zenohd->wz, so Layer A4 rejected this line as malformed and
// then, because a rejected claim leaves the test declaring nothing, counted the
// test a second time under A4-4. One bad token, two findings, and the lane red
// on every hosted run.
//
// `wz->zenohd` is what this leg actually is and is the same kind its sibling at
// the z_info leg already uses: wz's C ABI emits the Scout and a REAL zenohd
// answers it. The pico-compiled twin is the RENDERING oracle, not the
// counterparty — it scouts the same router independently and its stdout is the
// thing wz's is diffed against. `partial`, not `full`, because this file's
// header states that every claim here is partial deliberately (the atom covers
// a fraction of pico's declared functions), and one `full` among them was that
// discipline being contradicted in passing.
// wz-proves: api-compat-pico wz->zenohd partial
#[test]
#[ignore = "spawns a real zenohd and two cc-compiled binaries; run by run-ci Layer Z"]
fn pico_zscout_source_on_wz_capi_matches_the_real_pico_against_a_zenohd() {
    let dir = tempfile::tempdir().expect("tempdir for the compiled binaries");
    let dropin = dropin_binary("z_scout", dir.path());
    let oracle = oracle_binary("z_scout", dir.path());

    // A zenohd with its DEFAULT multicast scouting responder; the spawn gates
    // on zenohd's own scout-listener line, so the group socket is bound and
    // joined before either scout emits (nothing retransmits a lost Scout).
    // R2230 (open-debt item 579) — listening on EVERY interface, not loopback.
    // The pinned 1.10.0 answers a non-loopback scouter with
    // `get_locators_noloopback()`, so a loopback-only router replies with an
    // EMPTY locator list and the comparison below has nothing to compare. The
    // helper's own doc carries the measurement.
    let (mut zenohd, port) =
        spawn_zenohd_multicast_scouting_on_any_interface("zenohd (multicast-scouting router)");

    // The ORACLE first, so a failure to provision multicast at all reads as the
    // REAL library finding nothing — never as a wz defect.
    let oracle_out = Command::new("stdbuf")
        .args(["-oL", "-eL"])
        .arg(&oracle)
        .output()
        .expect("run upstream z_scout linked to the REAL zenoh-pico");
    let oracle_printed = String::from_utf8_lossy(&oracle_out.stdout).into_owned();

    let wz_out = Command::new("stdbuf")
        .args(["-oL", "-eL"])
        .arg(&dropin)
        .output()
        .expect("run upstream z_scout linked to wz's C-ABI cdylib");
    let wz_printed = String::from_utf8_lossy(&wz_out.stdout).into_owned();

    let _ = zenohd.child_mut().kill();
    let _ = zenohd.child_mut().wait();

    let oracle_line = hello_line_for_port(&oracle_printed, port).unwrap_or_else(|| {
        panic!(
            "the REAL zenoh-pico z_scout did not discover the zenohd on port \
             {port} — multicast scouting is not working on this host, \
             so the comparison below would be vacuous.\n\
             --- oracle stdout ---\n{oracle_printed}"
        )
    });
    let wz_line = hello_line_for_port(&wz_printed, port).unwrap_or_else(|| {
        panic!(
            "upstream z_scout.c on wz's C-ABI did not discover the zenohd the REAL \
             zenoh-pico found on the same group.\n\
             --- oracle stdout (found it) ---\n{oracle_printed}\n\
             --- z_scout.c on wz stdout ---\n{wz_printed}"
        )
    });

    assert_eq!(
        wz_line, oracle_line,
        "upstream z_scout.c printed a DIFFERENT line on wz than on the real \
         zenoh-pico for the same zenohd. The zid rendering (byte order), the \
         whatami map index, or the locator projection disagrees.\n\
         --- z_scout.c on wz stdout ---\n{wz_printed}\n\
         --- oracle stdout ---\n{oracle_printed}"
    );
    // Not implied by the line comparison: the oracle prints ONE line per peer,
    // and a wz that re-reported the peer every cycle would still match on the
    // first line while flooding the callback.
    let wz_hits = hello_lines_for_port(&wz_printed, port).count();
    assert_eq!(
        wz_hits, 1,
        "wz reported the same peer {wz_hits} times; the real zenoh-pico reports it \
         once per scout.\n--- z_scout.c on wz stdout ---\n{wz_printed}"
    );
    // The closure's `drop` is the program's own completion signal, and it must
    // run AFTER the callbacks — a scout that emitted it early would reorder
    // upstream's output.
    assert!(
        wz_printed.trim_end().ends_with("Dropping scout results."),
        "z_scout.c on wz did not end with the closure-drop line, so the closure \
         `drop` did not run last (or did not run).\n\
         --- z_scout.c on wz stdout ---\n{wz_printed}"
    );
}

/// LEG 15b (`wz->zenohd`, ORACLE) — upstream's `z_scout.c` on wz's C ABI
/// reports BOTH routers answering one multicast group, exactly as the real
/// zenoh-pico does.
///
/// LEG 15 has ONE responder, and that is the whole reason this leg exists: a
/// single answer is reported identically by a survey and by a first-answer
/// lookup, so LEG 15 cannot see the difference. Measured, not assumed — forcing
/// `ScoutParams::exit_on_first` back to `true` in `wz-capi-pico`'s `run_scout`
/// leaves LEG 15 GREEN. Two responders is the smallest topology in which
/// pico's `exit_on_first == false` arm (`src/session/scout.c:121-123`, which
/// `_z_scout` passes at `src/net/primitives.c:81`) is observable from outside
/// wz at all.
///
/// The ORACLE runs first and must find both, for the same reason LEG 15 orders
/// it first: a host that cannot carry two multicast responders must read as an
/// environment fact, never as a wz defect.
///
/// Each router's line is selected by its OWN kernel-assigned tcp port, which
/// this test never gives to either scout — it reaches them only through that
/// router's Hello. So "wz found two peers" cannot be satisfied by printing one
/// peer twice, and "wz found the right two" cannot be satisfied by a build that
/// merely parsed a flag.
// wz-proves: api-compat-pico wz->zenohd partial
// wz-proves: scouting-active wz->zenohd partial
#[test]
#[ignore = "spawns two real zenohd routers and two cc-compiled binaries; run by run-ci Layer Z"]
fn pico_zscout_source_on_wz_capi_reports_every_zenohd_on_the_group() {
    let dir = tempfile::tempdir().expect("tempdir for the compiled binaries");
    let dropin = dropin_binary("z_scout", dir.path());
    let oracle = oracle_binary("z_scout", dir.path());

    // R2230 (open-debt item 579) — both on EVERY interface, for the reason the
    // single-router leg above states: a loopback-only router's Hello carries no
    // locator on the pinned 1.10.0, and this leg needs TWO distinguishable ones.
    let (mut router_a, port_a) =
        spawn_zenohd_multicast_scouting_on_any_interface("zenohd A (multicast-scouting router)");
    let (mut router_b, port_b) =
        spawn_zenohd_multicast_scouting_on_any_interface("zenohd B (multicast-scouting router)");
    assert_ne!(port_a, port_b, "the two routers must be distinguishable");

    let oracle_out = Command::new("stdbuf")
        .args(["-oL", "-eL"])
        .arg(&oracle)
        .output()
        .expect("run upstream z_scout linked to the REAL zenoh-pico");
    let oracle_printed = String::from_utf8_lossy(&oracle_out.stdout).into_owned();

    let wz_out = Command::new("stdbuf")
        .args(["-oL", "-eL"])
        .arg(&dropin)
        .output()
        .expect("run upstream z_scout linked to wz's C-ABI cdylib");
    let wz_printed = String::from_utf8_lossy(&wz_out.stdout).into_owned();

    let _ = router_a.child_mut().kill();
    let _ = router_a.child_mut().wait();
    let _ = router_b.child_mut().kill();
    let _ = router_b.child_mut().wait();

    for port in [port_a, port_b] {
        if hello_line_for_port(&oracle_printed, port).is_none() {
            panic!(
                "the REAL zenoh-pico z_scout did not report the zenohd on \
                 port {port}, so this host cannot carry two multicast \
                 responders and the comparison below would be vacuous.\n\
                 --- oracle stdout ---\n{oracle_printed}"
            );
        }
    }

    for port in [port_a, port_b] {
        let oracle_line = hello_line_for_port(&oracle_printed, port).expect("checked above");
        let wz_line = hello_line_for_port(&wz_printed, port).unwrap_or_else(|| {
            panic!(
                "upstream z_scout.c on wz's C-ABI reported only some of the routers \
                 the REAL zenoh-pico found on the same group — the router on port \
                 {port} is missing, which is what a scout that stops at the FIRST \
                 answer looks like from outside.\n\
                 --- oracle stdout (found it) ---\n{oracle_printed}\n\
                 --- z_scout.c on wz stdout ---\n{wz_printed}"
            )
        });
        assert_eq!(
            wz_line, oracle_line,
            "upstream z_scout.c printed a DIFFERENT line on wz than on the real \
             zenoh-pico for the zenohd on port {port}.\n\
             --- z_scout.c on wz stdout ---\n{wz_printed}\n\
             --- oracle stdout ---\n{oracle_printed}"
        );
        let hits = hello_lines_for_port(&wz_printed, port).count();
        assert_eq!(
            hits, 1,
            "wz reported the router on port {port} {hits} times; one Scout \
             draws one answer per peer.\n--- z_scout.c on wz stdout ---\n{wz_printed}"
        );
    }
}

/// LEG 16 (`pico->wz`) — upstream's `z_sub_channel.c`, running on wz, receives
/// a sample published by the REAL zenoh-pico `z_put` through a FIFO CHANNEL.
///
/// The channel is the point, not the delivery. `z_sub_channel.c` never
/// registers a callback that prints: it hands `z_fifo_channel_sample_new` a
/// closure, and its main loop BLOCKS in `z_recv` on the application thread.
/// Everything between those two is code the C compiler emitted from
/// `api/handlers.h` into this program's own object file, calling straight
/// through to wz's `_z_rc_*` / `_z_fifo_mt_*` / owned-sample exports. So a
/// printed line here means: the closure pushed a heap-allocated
/// `z_owned_sample_t` into wz's queue from the drive thread, the main thread's
/// blocking pull woke and moved it out, and the accessors read it AFTER the
/// dispatch that produced it had returned.
///
/// The last clause is what no earlier leg covered. Every other subscriber leg
/// reads its sample inside the callback, where wz's marshal is still borrowed
/// and alive; this one reads it from a different thread at an arbitrary later
/// time, which only works because `z_sample_take_from_loaned` produced an
/// INDEPENDENT owned copy.
// wz-proves: api-compat-pico pico->wz partial
#[test]
#[ignore = "spawns the real zenoh-pico z_put CLI and a cc-compiled binary; \
            run by run-ci Layer E"]
fn pico_zsubchannel_source_on_wz_capi_receives_through_a_fifo_channel() {
    let dir = tempfile::tempdir().expect("tempdir for the compiled drop-in");
    let dropin = dropin_binary("z_sub_channel", dir.path());
    let z_put = zenoh_pico_cli_binary("z_put");

    let reservation = PortReservation::pick();
    let port = reservation.port();
    let endpoint = format!("tcp/127.0.0.1:{port}");
    let payload = "PAYLOAD-THROUGH-THE-FIFO-CHANNEL";
    let key = "demo/dropin/leg16";

    let mut sub_out = tempfile::tempfile().expect("subscriber stdout capture");
    let writer = sub_out.try_clone().expect("dup subscriber stdout handle");
    // No `-n` on this example: it loops on `z_recv` until killed, so the
    // capture is read mid-run and `stdbuf -oL` is what makes that possible.
    let mut sub = ChildGuard::wrap(
        "z_sub_channel.c on wz-capi-pico",
        Command::new("stdbuf")
            .args(["-oL", "-eL"])
            .arg(&dropin)
            .args(["-l", &endpoint, "-m", "peer", "-k", "demo/dropin/**"])
            .stdout(Stdio::from(writer))
            .stderr(Stdio::from(sub_out.try_clone().expect("dup stderr handle")))
            .spawn()
            .expect("spawn the compiled z_sub_channel drop-in"),
    );

    if let Err(why) = wait_for_tcp_accept_alive(sub.child_mut(), port, LISTEN_TIMEOUT) {
        panic!(
            "the z_sub_channel.c drop-in never accepted on {endpoint} — {why}; \
             capture so far:\n{}",
            read_captured(&mut sub_out)
        );
    }
    drop(reservation);

    let mut put_out = tempfile::tempfile().expect("foreign z_put stdout capture");
    let put_writer = put_out.try_clone().expect("dup foreign z_put handle");
    let put = Command::new("stdbuf")
        .args(["-oL", "-eL"])
        .arg(&z_put)
        .args(["-e", &endpoint, "-m", "client", "-k", key, "-v", payload])
        .stdout(Stdio::from(put_writer))
        .stderr(Stdio::from(put_out.try_clone().expect("dup stderr handle")))
        .status()
        .expect("run the real zenoh-pico z_put");
    assert!(
        put.success(),
        "real zenoh-pico z_put exited {put:?}\n--- its stdout+stderr ---\n{}",
        read_captured(&mut put_out)
    );

    let captured =
        wait_for_substring(&mut sub_out, payload, EXCHANGE_TIMEOUT).unwrap_or_else(|captured| {
            let driver = read_captured(&mut put_out);
            panic!(
                "upstream z_sub_channel.c on wz's C-ABI never pulled the sample the \
                 REAL zenoh-pico z_put published. Either the channel closure never \
                 pushed (the `_z_fifo_mt_push` / owned-sample path), or the blocking \
                 `z_recv` never woke.\nexpected substring: {payload}\n\
                 the foreign publisher reached its put: {}\n\
                 --- z_sub_channel.c (on wz) stdout ---\n{captured}\n\
                 --- REAL pico z_put (driver) stdout ---\n{driver}",
                driver.contains("Putting Data"),
            )
        });
    assert!(
        captured.contains(key),
        "the payload came through the channel but not on the key the foreign \
         publisher used ({key}).\n--- stdout+stderr ---\n{captured}"
    );

    graceful_terminate(sub.child_mut(), Duration::from_secs(5));
}

/// LEG 17 (`wz->pico`) — upstream's `z_queryable_channel.c`, running on wz,
/// answers a query from the REAL zenoh-pico `z_get`, and the FOREIGN process is
/// what reports the reply.
///
/// This is the strongest of the channel legs and the one the whole deferred
/// mechanism exists for. `z_queryable_channel.c` does NOT reply from its
/// callback: the channel closure escapes the query with
/// `z_query_take_from_loaned` and the MAIN thread replies to it after
/// `z_recv` returns — arbitrarily long after the dispatch that delivered it.
///
/// wz's ordinary rule is that a dispatched request owes exactly one
/// `ResponseFinal`, staged contiguously with the handler jobs. Under that rule
/// this program would be silently useless: the Final would go out while the
/// query was still sitting in the ring, the querier would close its pending
/// entry, and every later reply would be discarded by the FOREIGN side with no
/// error anywhere. The verdict here is read from `z_get`'s own stdout, so it is
/// the foreign implementation asserting that the late reply arrived and was
/// still correlated.
///
/// The discriminator is therefore the LATENESS, and it is structural rather
/// than timed: there is no arrangement of this program in which the reply
/// precedes the callback's return.
// wz-proves: api-compat-pico wz->pico partial
#[test]
#[ignore = "spawns the real zenoh-pico z_get CLI and a cc-compiled binary; \
            run by run-ci Layer E"]
fn pico_zqueryablechannel_source_on_wz_capi_answers_real_pico_zget_after_the_dispatch() {
    let dir = tempfile::tempdir().expect("tempdir for the compiled drop-in");
    let dropin = dropin_binary("z_queryable_channel", dir.path());
    let z_get = zenoh_pico_cli_binary("z_get");

    let reservation = PortReservation::pick();
    let port = reservation.port();
    let endpoint = format!("tcp/127.0.0.1:{port}");
    let key = "demo/dropin/leg17";
    let value = "REPLY-FROM-A-CHANNEL-QUERYABLE";

    let mut qbl_out = tempfile::tempfile().expect("queryable stdout capture");
    let writer = qbl_out.try_clone().expect("dup queryable stdout handle");
    let mut qbl = ChildGuard::wrap(
        "z_queryable_channel.c on wz-capi-pico",
        Command::new("stdbuf")
            .args(["-oL", "-eL"])
            .arg(&dropin)
            .args(["-l", &endpoint, "-m", "peer", "-k", key, "-v", value])
            .stdout(Stdio::from(writer))
            .stderr(Stdio::from(qbl_out.try_clone().expect("dup stderr handle")))
            .spawn()
            .expect("spawn the compiled z_queryable_channel drop-in"),
    );

    if let Err(why) = wait_for_tcp_accept_alive(qbl.child_mut(), port, LISTEN_TIMEOUT) {
        panic!(
            "the z_queryable_channel.c drop-in never accepted on {endpoint} — {why}; \
             capture so far:\n{}",
            read_captured(&mut qbl_out)
        );
    }
    drop(reservation);

    let mut get_out = tempfile::tempfile().expect("foreign z_get stdout capture");
    let get_writer = get_out.try_clone().expect("dup foreign z_get handle");
    let get = Command::new("stdbuf")
        .args(["-oL", "-eL"])
        .arg(&z_get)
        .args(["-e", &endpoint, "-m", "client", "-k", key])
        .stdout(Stdio::from(get_writer))
        .stderr(Stdio::from(get_out.try_clone().expect("dup stderr handle")))
        .status()
        .expect("run the real zenoh-pico z_get");
    assert!(
        get.success(),
        "real zenoh-pico z_get exited {get:?}\n--- its stdout+stderr ---\n{}",
        read_captured(&mut get_out)
    );

    // The verdict comes from the FOREIGN process: it decoded the reply itself.
    let foreign = read_captured(&mut get_out);
    let responder = read_captured(&mut qbl_out);
    assert!(
        foreign.contains(value),
        "the REAL zenoh-pico z_get never reported the reply that upstream's \
         z_queryable_channel.c produced ON wz. The reply is issued from the \
         application thread AFTER the dispatch returned, so a ResponseFinal \
         emitted at dispatch time would close the querier before it arrived — \
         which is exactly this shape.\nexpected substring: {value}\n\
         the responder saw the query: {}\n\
         --- REAL pico z_get stdout ---\n{foreign}\n\
         --- z_queryable_channel.c (on wz) stdout ---\n{responder}",
        responder.contains("Received Query"),
    );
    // Not implied by the line above: the responder must have gone through the
    // CHANNEL, which is what its own handler line reports.
    assert!(
        responder.contains("[Queryable handler] Received Query"),
        "the reply arrived but the drop-in never printed its channel-handler \
         line, so the query did not travel through `z_recv`.\n--- stdout+stderr ---\n{responder}"
    );

    graceful_terminate(qbl.child_mut(), Duration::from_secs(5));
}

/// LEG 18 (`self-contained`) — upstream's `z_bytes.c` prints the SAME thing on
/// wz's C-ABI as it does on the real zenoh-pico.
///
/// `z_bytes.c` opens no session: it is a pure serialization exercise, which is
/// what makes the twice-compiled equality available here without any network at
/// all. One source, one set of headers, two libraries, and the two stdouts must
/// match byte for byte.
///
/// That equality pins more than the slice iterator this round added. It pins
/// every arithmetic serializer's byte order, the string and slice round trips,
/// the iterator's slice COUNT and its per-slice bytes, and the writer/reader
/// framing — all of it asserted by upstream's own program against upstream's
/// own library, with wz having no say in what "correct" means.
// wz-proves: api-compat-pico wz->pico partial
#[test]
#[ignore = "compiles upstream z_bytes.c twice (wz + the real libzenohpico); \
            run by run-ci Layer E"]
fn pico_zbytes_source_on_wz_capi_prints_what_the_real_pico_prints() {
    let dir = tempfile::tempdir().expect("tempdir for the compiled binaries");
    let dropin = dropin_binary("z_bytes", dir.path());
    let oracle = oracle_binary("z_bytes", dir.path());

    // The ORACLE first, so a broken oracle build reads as a broken oracle
    // rather than as a wz defect.
    let oracle_out = Command::new("stdbuf")
        .args(["-oL", "-eL"])
        .arg(&oracle)
        .output()
        .expect("run upstream z_bytes linked to the REAL zenoh-pico");
    assert!(
        oracle_out.status.success(),
        "upstream z_bytes.c on the REAL zenoh-pico exited {:?}\n--- stdout+stderr ---\n{}\
         \n--- stderr ---\n{}",
        oracle_out.status,
        String::from_utf8_lossy(&oracle_out.stdout),
        String::from_utf8_lossy(&oracle_out.stderr),
    );
    let oracle_printed = String::from_utf8_lossy(&oracle_out.stdout).into_owned();
    assert!(
        oracle_printed.contains("slice len:"),
        "the oracle run did not reach the slice-iterator section, so the \
         comparison below would not cover it.\n--- oracle stdout ---\n{oracle_printed}"
    );

    let wz_out = Command::new("stdbuf")
        .args(["-oL", "-eL"])
        .arg(&dropin)
        .output()
        .expect("run upstream z_bytes linked to wz's C-ABI cdylib");
    let wz_printed = String::from_utf8_lossy(&wz_out.stdout).into_owned();
    assert!(
        wz_out.status.success(),
        "upstream z_bytes.c on wz's C-ABI exited {:?} — it asserts its own \
         round trips, so a non-zero status is one of those assertions failing.\n\
         --- z_bytes.c on wz stdout ---\n{wz_printed}\n--- stderr ---\n{}",
        wz_out.status,
        String::from_utf8_lossy(&wz_out.stderr),
    );

    assert_eq!(
        wz_printed, oracle_printed,
        "upstream z_bytes.c printed DIFFERENT output on wz than on the real \
         zenoh-pico. One source, one set of headers, two libraries.\n\
         --- z_bytes.c on wz stdout ---\n{wz_printed}\n\
         --- oracle stdout ---\n{oracle_printed}"
    );
}

/// LEG 19 (`pico->wz`) — upstream's `z_advanced_sub.c`, running on wz, receives
/// samples from the REAL zenoh-pico's own `z_advanced_pub.c`.
///
/// Both programs are upstream's; only the library under the subscriber differs.
/// The publisher is the REAL zenoh-pico (compiled against `libzenohpico.so`),
/// so the `@adv` sequencing, the cache queryable it declares, and the liveliness
/// token it announces are all produced by upstream's implementation — wz has no
/// say in the wire it must understand.
///
/// A plain `z_sub` would also receive these samples, so what makes this the
/// ADVANCED leg is the second assertion: `z_advanced_sub.c` declares a
/// liveliness subscriber on `<ke>/@adv/pub/**` through
/// `ze_advanced_subscriber_detect_publishers` and prints a line when the
/// foreign publisher's `@adv` token appears. That line can only be produced by
/// a real publisher-detection token on the derived keyexpr — an advanced
/// subscriber that ignored the `@adv` namespace would still print the samples.
// wz-proves: api-compat-pico pico->wz partial
#[test]
#[ignore = "compiles upstream z_advanced_pub.c against the real libzenohpico \
            and z_advanced_sub.c against wz; run by run-ci Layer E"]
fn pico_zadvancedsub_source_on_wz_capi_receives_from_the_real_pico_advanced_pub() {
    let dir = tempfile::tempdir().expect("tempdir for the compiled binaries");
    let dropin = dropin_binary("z_advanced_sub", dir.path());
    let oracle_pub = oracle_binary("z_advanced_pub", dir.path());

    let reservation = PortReservation::pick();
    let port = reservation.port();
    let endpoint = format!("tcp/127.0.0.1:{port}");
    let key = "demo/dropin/leg19";
    let value = "ADV-FROM-REAL-PICO";

    let mut sub_out = tempfile::tempfile().expect("advanced subscriber stdout capture");
    let writer = sub_out.try_clone().expect("dup subscriber stdout handle");
    let mut sub = ChildGuard::wrap(
        "z_advanced_sub.c on wz-capi-pico",
        Command::new("stdbuf")
            .args(["-oL", "-eL"])
            .arg(&dropin)
            .args(["-l", &endpoint, "-m", "peer", "-k", key])
            .stdout(Stdio::from(writer))
            .stderr(Stdio::from(sub_out.try_clone().expect("dup stderr handle")))
            .spawn()
            .expect("spawn the compiled z_advanced_sub drop-in"),
    );

    if let Err(why) = wait_for_tcp_accept_alive(sub.child_mut(), port, LISTEN_TIMEOUT) {
        panic!(
            "the z_advanced_sub.c drop-in never accepted on {endpoint} — {why}; \
             capture so far:\n{}",
            read_captured(&mut sub_out)
        );
    }
    drop(reservation);

    let mut pub_out = tempfile::tempfile().expect("foreign advanced publisher capture");
    let pub_writer = pub_out.try_clone().expect("dup foreign publisher handle");
    let mut publisher = ChildGuard::wrap(
        "z_advanced_pub.c on the REAL zenoh-pico",
        Command::new("stdbuf")
            .args(["-oL", "-eL"])
            .arg(&oracle_pub)
            .args(["-e", &endpoint, "-m", "client", "-k", key, "-v", value])
            .stdout(Stdio::from(pub_writer))
            .stderr(Stdio::from(pub_out.try_clone().expect("dup stderr handle")))
            .spawn()
            .expect("spawn the REAL zenoh-pico z_advanced_pub"),
    );

    let captured =
        wait_for_substring(&mut sub_out, value, EXCHANGE_TIMEOUT).unwrap_or_else(|captured| {
            let driver = read_captured(&mut pub_out);
            panic!(
                "upstream z_advanced_sub.c on wz's C-ABI never reported a sample from \
                 the REAL zenoh-pico's own z_advanced_pub.\nexpected substring: {value}\n\
                 the foreign publisher reached its put: {}\n\
                 --- z_advanced_sub.c (on wz) stdout ---\n{captured}\n\
                 --- REAL pico z_advanced_pub (driver) stdout ---\n{driver}",
                driver.contains("Putting Data"),
            )
        });
    // The ADVANCED half: publisher detection. Only an `@adv/pub/**` liveliness
    // token from the foreign publisher can produce this line, and a subscriber
    // that ignored the `@adv` namespace would still have printed the sample
    // above.
    let detected = wait_for_substring(
        &mut sub_out,
        "[Liveliness Subscriber] New alive token",
        EXCHANGE_TIMEOUT,
    )
    .unwrap_or_else(|captured| {
        panic!(
            "samples arrived but the drop-in never detected the foreign advanced \
             publisher through its `@adv/pub/**` liveliness token, so \
             `ze_advanced_subscriber_detect_publishers` did not reach the derived \
             keyexpr.\n--- z_advanced_sub.c (on wz) stdout ---\n{captured}"
        )
    });
    assert!(
        detected.contains(key),
        "the publisher-detection line does not carry the subscribed key ({key}), \
         so the derived `@adv` keyexpr is not the one the publisher announced \
         under.\n--- stdout+stderr ---\n{detected}"
    );
    assert!(
        captured.contains(key),
        "the sample arrived but not on the key the foreign advanced publisher \
         used ({key}).\n--- stdout+stderr ---\n{captured}"
    );

    graceful_terminate(publisher.child_mut(), Duration::from_secs(5));
    graceful_terminate(sub.child_mut(), Duration::from_secs(5));
}

/// LEG 20 (`pico->wz`) — upstream's `z_pull.c`, running on wz, keeps the
/// NEWEST samples when its RING channel overflows, and drops the oldest.
///
/// This is the only leg that can see the ring's full policy, and it is the
/// reason it exists. Every other channel leg pulls fewer samples than the
/// channel holds, so a ring that kept the OLDEST — or that silently behaved
/// like a fifo and blocked its producer — would pass all of them. `z_pull.c`
/// is the upstream program that overflows on purpose: it sets a ring size,
/// sleeps between drains, and prints what it got.
///
/// Four samples into a ring of TWO, drained once. The witness is asymmetric on
/// purpose: the newest two must be PRESENT and the oldest two ABSENT, because
/// "3 and 4 arrived" alone is satisfied by a ring of four, and "1 is missing"
/// alone is satisfied by a ring that dropped everything.
///
/// The window is a barrier, not a sleep: the drop-in prints its
/// `Nothing to pull... sleep for N ms` line BEFORE the publishers start, so all
/// four puts land inside one 10-second drain interval that has only just begun.
/// Each `z_put` is a synchronous process whose exit is awaited, so the four are
/// ordered by construction rather than by timing.
// wz-proves: api-compat-pico pico->wz partial
#[test]
#[ignore = "spawns the real zenoh-pico z_put CLI and a cc-compiled binary; \
            run by run-ci Layer E"]
fn pico_zpull_source_on_wz_capi_keeps_the_newest_when_the_ring_overflows() {
    let dir = tempfile::tempdir().expect("tempdir for the compiled drop-in");
    let dropin = dropin_binary("z_pull", dir.path());
    let z_put = zenoh_pico_cli_binary("z_put");

    let reservation = PortReservation::pick();
    let port = reservation.port();
    let endpoint = format!("tcp/127.0.0.1:{port}");
    let key = "demo/dropin/leg20";

    let mut sub_out = tempfile::tempfile().expect("z_pull stdout capture");
    let writer = sub_out.try_clone().expect("dup z_pull stdout handle");
    let mut sub = ChildGuard::wrap(
        "z_pull.c on wz-capi-pico",
        Command::new("stdbuf")
            .args(["-oL", "-eL"])
            .arg(&dropin)
            .args([
                "-l",
                &endpoint,
                "-m",
                "peer",
                "-k",
                "demo/dropin/**",
                // Ring capacity TWO and a ten-second drain interval: the four
                // puts below must all land inside one window, and the window
                // starts when the barrier line appears.
                "-s",
                "2",
                "-i",
                "10000",
            ])
            .stdout(Stdio::from(writer))
            .stderr(Stdio::from(sub_out.try_clone().expect("dup stderr handle")))
            .spawn()
            .expect("spawn the compiled z_pull drop-in"),
    );

    if let Err(why) = wait_for_tcp_accept_alive(sub.child_mut(), port, LISTEN_TIMEOUT) {
        panic!(
            "the z_pull.c drop-in never accepted on {endpoint} — {why}; capture so far:\n{}",
            read_captured(&mut sub_out)
        );
    }
    drop(reservation);

    // THE BARRIER. Without it the first drain could fire between two puts, the
    // oldest would be reported, and the leg would red for a timing reason
    // rather than a policy one.
    if wait_for_substring(&mut sub_out, "Nothing to pull", EXCHANGE_TIMEOUT).is_err() {
        panic!(
            "the z_pull.c drop-in never reached its first empty drain, so the \
             publish window below would not be bounded.\n--- stdout+stderr ---\n{}",
            read_captured(&mut sub_out)
        );
    }

    for idx in 1..=4 {
        let payload = format!("EVICT-{idx}");
        // R311y606 — see the note on z_pub_attachment above: an asserted exit
        // status with a discarded stderr is an unanswerable failure.
        let mut put_out = tempfile::tempfile().expect("z_put capture");
        let put = Command::new("stdbuf")
            .args(["-oL", "-eL"])
            .arg(&z_put)
            .args(["-e", &endpoint, "-m", "client", "-k", key, "-v", &payload])
            .stdout(Stdio::from(put_out.try_clone().expect("dup stdout handle")))
            .stderr(Stdio::from(put_out.try_clone().expect("dup stderr handle")))
            .status()
            .expect("run the real zenoh-pico z_put");
        assert!(
            put.success(),
            "real zenoh-pico z_put #{idx} exited {put:?}\n--- its stdout+stderr ---\n{}",
            read_captured(&mut put_out)
        );
    }

    // The drain fires at the end of the interval; allow for it plus slack.
    let captured = wait_for_substring(&mut sub_out, "EVICT-4", Duration::from_secs(30))
        .unwrap_or_else(|captured| {
            panic!(
                "upstream z_pull.c on wz's C-ABI never pulled the NEWEST sample out \
                 of its ring channel.\n--- z_pull.c (on wz) stdout ---\n{captured}"
            )
        });
    assert!(
        captured.contains("EVICT-3"),
        "the ring kept only ONE of its two slots — capacity is not being honoured.\n\
         --- stdout+stderr ---\n{captured}"
    );
    assert!(
        !captured.contains("EVICT-1") && !captured.contains("EVICT-2"),
        "the ring reported a sample it should have EVICTED. A ring of two that \
         received four must drop the two OLDEST; this one kept them, so its \
         overflow policy is a fifo's (or its capacity is wrong).\n\
         --- z_pull.c (on wz) stdout ---\n{captured}"
    );

    graceful_terminate(sub.child_mut(), Duration::from_secs(5));
}

/// LEG 21 (`wz->pico`) — upstream's `z_advanced_pub.c`, running on wz, is
/// received by the REAL zenoh-pico's own `z_advanced_sub.c`.
///
/// The mirror of LEG 19, and the half that leaves wz nothing to grade itself
/// on: the sequence numbers, the `@adv` cache queryable and the `@adv`
/// liveliness token are all produced by wz here, and it is upstream's own
/// subscriber on the real library that has to make sense of them.
// wz-proves: api-compat-pico wz->pico partial
#[test]
#[ignore = "spawns the real zenoh-pico z_advanced_sub CLI and a cc-compiled \
            binary; run by run-ci Layer E"]
fn pico_zadvancedpub_source_on_wz_capi_reaches_the_real_pico_advanced_sub() {
    let dir = tempfile::tempdir().expect("tempdir for the compiled drop-in");
    let dropin = dropin_binary("z_advanced_pub", dir.path());
    let z_advanced_sub = zenoh_pico_cli_binary("z_advanced_sub");

    let reservation = PortReservation::pick();
    let port = reservation.port();
    let endpoint = format!("tcp/127.0.0.1:{port}");
    let key = "demo/dropin/leg21";
    let value = "ADV-FROM-WZ";

    // The FOREIGN process listens; the drop-in dials in.
    let mut sub_out = tempfile::tempfile().expect("foreign advanced sub capture");
    let writer = sub_out.try_clone().expect("dup foreign sub handle");
    let mut sub = ChildGuard::wrap(
        "real zenoh-pico z_advanced_sub",
        Command::new("stdbuf")
            .args(["-oL", "-eL"])
            .arg(&z_advanced_sub)
            .args(["-l", &endpoint, "-m", "peer", "-k", key])
            .stdout(Stdio::from(writer))
            .stderr(Stdio::from(sub_out.try_clone().expect("dup stderr handle")))
            .spawn()
            .expect("spawn the real zenoh-pico z_advanced_sub"),
    );

    if let Err(why) = wait_for_tcp_accept_alive(sub.child_mut(), port, LISTEN_TIMEOUT) {
        panic!(
            "the real zenoh-pico z_advanced_sub never accepted on {endpoint} — {why}; \
             capture so far:\n{}",
            read_captured(&mut sub_out)
        );
    }
    drop(reservation);

    let mut pub_out = tempfile::tempfile().expect("advanced pub drop-in capture");
    let pub_writer = pub_out.try_clone().expect("dup pub drop-in handle");
    let pub_err = pub_out.try_clone().expect("dup pub drop-in stderr handle");
    let mut publisher = ChildGuard::wrap(
        "z_advanced_pub.c on wz-capi-pico",
        Command::new("stdbuf")
            .args(["-oL", "-eL"])
            .arg(&dropin)
            .args(["-e", &endpoint, "-m", "client", "-k", key, "-v", value])
            .stdout(Stdio::from(pub_writer))
            .stderr(Stdio::from(pub_err))
            .spawn()
            .expect("spawn the compiled z_advanced_pub drop-in"),
    );

    let foreign =
        wait_for_substring(&mut sub_out, value, EXCHANGE_TIMEOUT).unwrap_or_else(|captured| {
            let driver = read_captured(&mut pub_out);
            panic!(
                "the REAL zenoh-pico z_advanced_sub never reported a sample from \
                 upstream's z_advanced_pub.c running ON wz.\nexpected substring: {value}\n\
                 the drop-in reached its put: {}\n\
                 --- REAL pico z_advanced_sub stdout ---\n{captured}\n\
                 --- z_advanced_pub.c (on wz) stdout+stderr ---\n{driver}",
                driver.contains("Putting Data"),
            )
        });
    assert!(
        foreign.contains(key),
        "the foreign advanced subscriber received the value on a different key \
         than {key}.\n--- stdout+stderr ---\n{foreign}"
    );

    graceful_terminate(publisher.child_mut(), Duration::from_secs(5));
    graceful_terminate(sub.child_mut(), Duration::from_secs(5));
}

/// LEG 22 (`wz->pico`) — upstream's `z_querier.c`, running on wz, gets a reply
/// from the REAL zenoh-pico `z_queryable`.
///
/// A querier is a get with its keyexpr and options bound once and reused, so
/// this exercises the `z_querier_*` family end to end rather than through the
/// `z_get` path its options share.
// wz-proves: api-compat-pico wz->pico partial
#[test]
#[ignore = "spawns the real zenoh-pico z_queryable CLI and a cc-compiled \
            binary; run by run-ci Layer E"]
fn pico_zquerier_source_on_wz_capi_gets_a_reply_from_real_pico_zqueryable() {
    let dir = tempfile::tempdir().expect("tempdir for the compiled drop-in");
    let dropin = dropin_binary("z_querier", dir.path());
    let z_queryable = zenoh_pico_cli_binary("z_queryable");

    let reservation = PortReservation::pick();
    let port = reservation.port();
    let endpoint = format!("tcp/127.0.0.1:{port}");
    let key = "demo/dropin/leg22";
    let value = "REPLY-TO-A-WZ-QUERIER";

    let mut qbl_out = tempfile::tempfile().expect("foreign queryable capture");
    let writer = qbl_out.try_clone().expect("dup foreign queryable handle");
    let mut qbl = ChildGuard::wrap(
        "real zenoh-pico z_queryable",
        Command::new("stdbuf")
            .args(["-oL", "-eL"])
            .arg(&z_queryable)
            .args(["-l", &endpoint, "-m", "peer", "-k", key, "-v", value])
            .stdout(Stdio::from(writer))
            .stderr(Stdio::from(qbl_out.try_clone().expect("dup stderr handle")))
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

    let mut get_out = tempfile::tempfile().expect("querier drop-in capture");
    let get_writer = get_out.try_clone().expect("dup querier drop-in handle");
    let get_err = get_out.try_clone().expect("dup querier stderr handle");
    // `-n 1`: one query, then exit — which is what flushes the capture.
    let get = Command::new("stdbuf")
        .args(["-oL", "-eL"])
        .arg(&dropin)
        .args(["-e", &endpoint, "-m", "client", "-s", key, "-n", "1"])
        .stdout(Stdio::from(get_writer))
        .stderr(Stdio::from(get_err))
        .spawn()
        .expect("spawn the compiled z_querier drop-in");
    let get = bounded_exit("z_querier.c on wz", get, &mut get_out);
    let captured = read_captured(&mut get_out);
    assert!(
        get.success(),
        "upstream z_querier.c on wz's C-ABI exited {get:?}\n--- its stdout+stderr ---\n{captured}"
    );
    assert!(
        captured.contains(value),
        "upstream z_querier.c on wz's C-ABI never reported the reply the REAL \
         zenoh-pico z_queryable sent.\nexpected substring: {value}\n\
         --- z_querier.c (on wz) stdout+stderr ---\n{captured}\n\
         --- REAL pico z_queryable stdout ---\n{}",
        read_captured(&mut qbl_out)
    );

    graceful_terminate(qbl.child_mut(), Duration::from_secs(5));
}

/// LEG 23 (`wz->pico`) — upstream's `z_get_channel.c`, running on wz, receives
/// the REAL zenoh-pico `z_queryable`'s reply through a FIFO CHANNEL.
///
/// The reply-side twin of LEG 16: the replies are pushed into a channel by the
/// session's read task and pulled by the application thread, so the owned
/// REPLY family (248 B) is what carries them out of the callback.
// wz-proves: api-compat-pico wz->pico partial
#[test]
#[ignore = "spawns the real zenoh-pico z_queryable CLI and a cc-compiled \
            binary; run by run-ci Layer E"]
fn pico_zgetchannel_source_on_wz_capi_receives_replies_through_a_channel() {
    let dir = tempfile::tempdir().expect("tempdir for the compiled drop-in");
    let dropin = dropin_binary("z_get_channel", dir.path());
    let z_queryable = zenoh_pico_cli_binary("z_queryable");

    let reservation = PortReservation::pick();
    let port = reservation.port();
    let endpoint = format!("tcp/127.0.0.1:{port}");
    let key = "demo/dropin/leg23";
    let value = "REPLY-INTO-A-CHANNEL";

    let mut qbl_out = tempfile::tempfile().expect("foreign queryable capture");
    let writer = qbl_out.try_clone().expect("dup foreign queryable handle");
    let mut qbl = ChildGuard::wrap(
        "real zenoh-pico z_queryable",
        Command::new("stdbuf")
            .args(["-oL", "-eL"])
            .arg(&z_queryable)
            .args(["-l", &endpoint, "-m", "peer", "-k", key, "-v", value])
            .stdout(Stdio::from(writer))
            .stderr(Stdio::from(qbl_out.try_clone().expect("dup stderr handle")))
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

    let mut get_out = tempfile::tempfile().expect("get_channel drop-in capture");
    let get_writer = get_out.try_clone().expect("dup get_channel handle");
    let get_err = get_out.try_clone().expect("dup get_channel stderr handle");
    let get = Command::new("stdbuf")
        .args(["-oL", "-eL"])
        .arg(&dropin)
        .args(["-e", &endpoint, "-m", "client", "-k", key])
        .stdout(Stdio::from(get_writer))
        .stderr(Stdio::from(get_err))
        .spawn()
        .expect("spawn the compiled z_get_channel drop-in");
    let get = bounded_exit("z_get_channel.c on wz", get, &mut get_out);
    let captured = read_captured(&mut get_out);
    assert!(
        get.success(),
        "upstream z_get_channel.c on wz's C-ABI exited {get:?}\n\
         --- its stdout+stderr ---\n{captured}"
    );
    assert!(
        captured.contains(value),
        "upstream z_get_channel.c on wz's C-ABI never pulled the reply the REAL \
         zenoh-pico z_queryable sent. Either the reply closure never pushed into \
         the channel, or the blocking recv never woke.\nexpected substring: {value}\n\
         --- z_get_channel.c (on wz) stdout+stderr ---\n{captured}\n\
         --- REAL pico z_queryable stdout ---\n{}",
        read_captured(&mut qbl_out)
    );

    graceful_terminate(qbl.child_mut(), Duration::from_secs(5));
}

/// LEG 24 (`pico->wz`) — upstream's `z_get_liveliness.c`, running on wz,
/// discovers a liveliness token declared by the REAL zenoh-pico `z_liveliness`,
/// with a real zenohd routing between them.
///
/// The one-shot snapshot half of the presence plane, and the leg that gives
/// `z_liveliness_get` a foreign witness: the token is declared by upstream's
/// own binary, and the reply stream that carries it back is wz's CURRENT
/// Interest, not a query.
///
/// ## Why a router, and why the name changed (R311y533)
///
/// This leg was FLAKY, and finding out why produced two results worth more than
/// the leg. It used to wire the pico token holder and the drop-in DIRECTLY —
/// the holder listening as a peer, the drop-in dialling as a client — and it
/// passed about one run in three, failing either with an empty snapshot or by
/// hanging for the full budget.
///
/// The first result came from calibrating the ORACLE before blaming wz: the
/// REAL zenoh-pico `z_get_liveliness` against the REAL zenoh-pico
/// `z_liveliness`, line-buffered, in that same direct topology reports ZERO
/// alive tokens and hangs — 6 runs of 6. Put a zenohd between them and the same
/// foreign pair answers immediately. So the topology this leg used is one the
/// reference implementation does not serve at all, and wz's one-in-three was
/// wz being MORE permissive than pico, not less. A leg whose premise the oracle
/// cannot satisfy is not measuring the subject.
///
/// The second result is a real wz defect the flakiness exposed, and it is fixed
/// rather than routed around: the hang was `Session::liveliness_get` arming a
/// deadline no host under the C ABI ever swept. See
/// `Session::sweep_expired_liveliness_gets`. The router topology removes the
/// FLAKE; the sweep removes the HANG, and either one alone would have left the
/// other in place.
///
/// The rename is lane REGISTRATION, not evasion: Layer E's sweep carries
/// `--skip zenohd`, so a leg that now needs a router must carry that token and
/// be registered in Layer Z — the lane that provisions zenohd — exactly as the
/// two other zenohd-bearing legs in this file are.
// wz-proves: api-compat-pico pico->wz partial
#[test]
#[ignore = "spawns zenohd, the real zenoh-pico z_liveliness CLI and a \
            cc-compiled binary; run by run-ci Layer Z"]
fn pico_zgetliveliness_source_on_wz_capi_sees_a_real_pico_token_through_zenohd() {
    let dir = tempfile::tempdir().expect("tempdir for the compiled drop-in");
    let dropin = dropin_binary("z_get_liveliness", dir.path());
    let z_liveliness = zenoh_pico_cli_binary("z_liveliness");
    let zenohd = zenohd_binary();

    let reservation = PortReservation::pick();
    let port = reservation.port();
    let endpoint = format!("tcp/127.0.0.1:{port}");
    let key = "demo/dropin/leg24";

    let mut router_out = tempfile::tempfile().expect("zenohd stdout capture");
    let router_writer = router_out.try_clone().expect("dup zenohd stdout handle");
    let mut router = ChildGuard::wrap(
        "zenohd",
        Command::new("stdbuf")
            .args(["-oL", "-eL"])
            .arg(&zenohd)
            .args(["--no-multicast-scouting", "-l", &endpoint])
            .env("RUST_LOG", "info")
            .stdout(Stdio::from(router_writer.try_clone().expect("dup")))
            .stderr(Stdio::from(router_writer))
            .spawn()
            .expect("spawn zenohd"),
    );
    if let Err(why) = wait_for_tcp_accept_alive(router.child_mut(), port, LISTEN_TIMEOUT) {
        panic!(
            "zenohd never accepted on {endpoint} — {why}; capture so far:\n{}",
            read_captured(&mut router_out)
        );
    }
    drop(reservation);

    let mut tok_out = tempfile::tempfile().expect("foreign token capture");
    let writer = tok_out.try_clone().expect("dup foreign token handle");
    let mut token = ChildGuard::wrap(
        "real zenoh-pico z_liveliness",
        Command::new("stdbuf")
            .args(["-oL", "-eL"])
            .arg(&z_liveliness)
            .args(["-e", &endpoint, "-m", "client", "-k", key])
            .stdout(Stdio::from(writer))
            .stderr(Stdio::from(tok_out.try_clone().expect("dup stderr handle")))
            .spawn()
            .expect("spawn the real zenoh-pico z_liveliness"),
    );

    // The barrier is upstream's own POST-DECLARATION line, not the TCP accept
    // and not a sleep. `z_liveliness.c:58-65` declares the token AFTER `z_open`
    // returns, so any barrier that fires at connect time races the declaration,
    // and losing that race yields a correct EMPTY snapshot rather than a wz
    // failure. Measured at HEAD with the connect as the only barrier: 1 pass
    // in 3.
    if let Err(captured) = wait_for_substring(
        &mut tok_out,
        "Press CTRL-C to undeclare liveliness token",
        EXCHANGE_TIMEOUT,
    ) {
        panic!(
            "the real zenoh-pico z_liveliness never reported its token declared \
             on {key}, so there was nothing for the drop-in to find.\n\
             --- REAL pico z_liveliness stdout ---\n{captured}"
        );
    }

    let mut get_out = tempfile::tempfile().expect("get_liveliness drop-in capture");
    let get_writer = get_out.try_clone().expect("dup get_liveliness handle");
    let get_err = get_out
        .try_clone()
        .expect("dup get_liveliness stderr handle");
    let get = Command::new("stdbuf")
        .args(["-oL", "-eL"])
        .arg(&dropin)
        .args(["-e", &endpoint, "-m", "client", "-k", key])
        .stdout(Stdio::from(get_writer))
        .stderr(Stdio::from(get_err))
        .spawn()
        .expect("spawn the compiled z_get_liveliness drop-in");
    let get = bounded_exit("z_get_liveliness.c on wz", get, &mut get_out);
    let captured = read_captured(&mut get_out);
    assert!(
        get.success(),
        "upstream z_get_liveliness.c on wz's C-ABI exited {get:?}\n\
         --- its stdout+stderr ---\n{captured}"
    );
    assert!(
        captured.contains("Alive token") && captured.contains(key),
        "upstream z_get_liveliness.c on wz's C-ABI did not report the token the \
         REAL zenoh-pico z_liveliness declared on {key}.\n\
         --- z_get_liveliness.c (on wz) stdout+stderr ---\n{captured}\n\
         --- REAL pico z_liveliness stdout ---\n{}\n--- zenohd ---\n{}",
        read_captured(&mut tok_out),
        read_captured(&mut router_out),
    );

    graceful_terminate(token.child_mut(), Duration::from_secs(5));
    graceful_terminate(router.child_mut(), Duration::from_secs(5));
}

/// LEG 25 (`wz->pico`) — upstream's `z_get_attachment.c`, running on wz, reads
/// back the ATTACHMENT the REAL zenoh-pico `z_queryable_attachment` put on its
/// reply.
///
/// The querier half of the attachment plane. The attachment is a serialized
/// key/value map built by upstream's own serializer on the foreign side and
/// walked by upstream's own deserializer on wz, so the framing is asserted by
/// two pieces of upstream code with wz only carrying the bytes.
// wz-proves: api-compat-pico wz->pico partial
#[test]
#[ignore = "spawns the real zenoh-pico z_queryable_attachment CLI and a \
            cc-compiled binary; run by run-ci Layer E"]
fn pico_zgetattachment_source_on_wz_capi_reads_a_real_pico_reply_attachment() {
    let dir = tempfile::tempdir().expect("tempdir for the compiled drop-in");
    let dropin = dropin_binary("z_get_attachment", dir.path());
    let z_queryable_attachment = zenoh_pico_cli_binary("z_queryable_attachment");

    let reservation = PortReservation::pick();
    let port = reservation.port();
    let endpoint = format!("tcp/127.0.0.1:{port}");
    let key = "demo/dropin/leg25";
    let value = "ATTACHED-REPLY-FROM-REAL-PICO";

    let mut qbl_out = tempfile::tempfile().expect("foreign queryable capture");
    let writer = qbl_out.try_clone().expect("dup foreign queryable handle");
    let mut qbl = ChildGuard::wrap(
        "real zenoh-pico z_queryable_attachment",
        Command::new("stdbuf")
            .args(["-oL", "-eL"])
            .arg(&z_queryable_attachment)
            .args(["-l", &endpoint, "-m", "peer", "-k", key, "-v", value])
            .stdout(Stdio::from(writer))
            .stderr(Stdio::from(qbl_out.try_clone().expect("dup stderr handle")))
            .spawn()
            .expect("spawn the real zenoh-pico z_queryable_attachment"),
    );

    if let Err(why) = wait_for_tcp_accept_alive(qbl.child_mut(), port, LISTEN_TIMEOUT) {
        panic!(
            "the real zenoh-pico z_queryable_attachment never accepted on {endpoint} \
             — {why}; capture so far:\n{}",
            read_captured(&mut qbl_out)
        );
    }
    drop(reservation);

    let mut get_out = tempfile::tempfile().expect("get_attachment drop-in capture");
    let get_writer = get_out.try_clone().expect("dup get_attachment handle");
    let get_err = get_out
        .try_clone()
        .expect("dup get_attachment stderr handle");
    let get = Command::new("stdbuf")
        .args(["-oL", "-eL"])
        .arg(&dropin)
        .args(["-e", &endpoint, "-m", "client", "-k", key])
        .stdout(Stdio::from(get_writer))
        .stderr(Stdio::from(get_err))
        .spawn()
        .expect("spawn the compiled z_get_attachment drop-in");
    let get = bounded_exit("z_get_attachment.c on wz", get, &mut get_out);
    let captured = read_captured(&mut get_out);
    assert!(
        get.success(),
        "upstream z_get_attachment.c on wz's C-ABI exited {get:?}\n\
         --- its stdout+stderr ---\n{captured}"
    );
    assert!(
        captured.contains(value),
        "upstream z_get_attachment.c on wz's C-ABI never reported the reply.\n\
         expected substring: {value}\n--- stdout+stderr ---\n{captured}\n\
         --- REAL pico z_queryable_attachment stdout ---\n{}",
        read_captured(&mut qbl_out)
    );
    // The ATTACHMENT is the point: a reply that arrived with its attachment
    // dropped would satisfy the assertion above and fail this one.
    assert!(
        captured.contains("with attachment"),
        "the reply arrived but carried NO attachment, so the attachment ext was \
         lost on the way in.\n--- z_get_attachment.c (on wz) stdout+stderr ---\n{captured}"
    );

    graceful_terminate(qbl.child_mut(), Duration::from_secs(5));
}

/// LEG 26 (`wz->pico`) — upstream's `z_queryable_attachment.c`, running on wz,
/// answers the REAL zenoh-pico `z_get_attachment`, and the FOREIGN process
/// reports both the reply and its attachment.
///
/// The responder half of LEG 25, and the stronger direction: the verdict comes
/// from upstream's own deserializer running on upstream's own library.
// wz-proves: api-compat-pico wz->pico partial
#[test]
#[ignore = "spawns the real zenoh-pico z_get_attachment CLI and a cc-compiled \
            binary; run by run-ci Layer E"]
fn pico_zqueryableattachment_source_on_wz_capi_is_read_by_real_pico_zgetattachment() {
    let dir = tempfile::tempdir().expect("tempdir for the compiled drop-in");
    let dropin = dropin_binary("z_queryable_attachment", dir.path());
    let z_get_attachment = zenoh_pico_cli_binary("z_get_attachment");

    let reservation = PortReservation::pick();
    let port = reservation.port();
    let endpoint = format!("tcp/127.0.0.1:{port}");
    let key = "demo/dropin/leg26";
    let value = "ATTACHED-REPLY-FROM-WZ";

    let mut qbl_out = tempfile::tempfile().expect("queryable drop-in capture");
    let writer = qbl_out.try_clone().expect("dup queryable drop-in handle");
    let err = qbl_out.try_clone().expect("dup queryable stderr handle");
    let mut qbl = ChildGuard::wrap(
        "z_queryable_attachment.c on wz-capi-pico",
        Command::new("stdbuf")
            .args(["-oL", "-eL"])
            .arg(&dropin)
            .args(["-l", &endpoint, "-m", "peer", "-k", key, "-v", value])
            .stdout(Stdio::from(writer))
            .stderr(Stdio::from(err))
            .spawn()
            .expect("spawn the compiled z_queryable_attachment drop-in"),
    );

    if let Err(why) = wait_for_tcp_accept_alive(qbl.child_mut(), port, LISTEN_TIMEOUT) {
        panic!(
            "the z_queryable_attachment.c drop-in never accepted on {endpoint} — \
             {why}; capture so far:\n{}",
            read_captured(&mut qbl_out)
        );
    }
    drop(reservation);

    let mut get_out = tempfile::tempfile().expect("foreign z_get_attachment capture");
    let get_writer = get_out.try_clone().expect("dup foreign get handle");
    let get = Command::new("stdbuf")
        .args(["-oL", "-eL"])
        .arg(&z_get_attachment)
        .args(["-e", &endpoint, "-m", "client", "-k", key])
        .stdout(Stdio::from(get_writer))
        .stderr(Stdio::from(get_out.try_clone().expect("dup stderr handle")))
        .spawn()
        .expect("spawn the real zenoh-pico z_get_attachment");
    let get = bounded_exit("real pico z_get_attachment", get, &mut get_out);
    let foreign = read_captured(&mut get_out);
    let responder = read_captured(&mut qbl_out);
    assert!(
        get.success(),
        "real zenoh-pico z_get_attachment exited {get:?}\n--- its stdout+stderr ---\n{foreign}"
    );
    assert!(
        foreign.contains(value),
        "the REAL zenoh-pico z_get_attachment never reported the reply upstream's \
         z_queryable_attachment.c produced ON wz.\nexpected substring: {value}\n\
         --- REAL pico z_get_attachment stdout ---\n{foreign}\n\
         --- z_queryable_attachment.c (on wz) stdout+stderr ---\n{responder}"
    );
    assert!(
        foreign.contains("with attachment"),
        "the foreign querier got the reply but no attachment on it, so wz dropped \
         the outbound attachment ext.\n--- REAL pico stdout ---\n{foreign}"
    );
    // The INBOUND half: upstream's queryable prints the attachment the querier
    // sent, so a wz that dropped it on the way IN would still pass above.
    assert!(
        responder.contains("with attachment"),
        "the drop-in answered but never reported the querier's OWN attachment, so \
         the inbound attachment ext was lost.\n--- z_queryable_attachment.c (on wz) \
         stdout+stderr ---\n{responder}"
    );

    graceful_terminate(qbl.child_mut(), Duration::from_secs(5));
}

/// LEG 27 (`wz->pico`) — upstream's `z_queryable_lat.c`, running on wz, answers
/// the REAL zenoh-pico `z_get_lat`, and the FOREIGN process prints the
/// round-trip times.
///
/// The latency pair is the only place a REPLY travels the full request/response
/// path under back-to-back load rather than once: `z_get_lat` issues its
/// queries through a QUERIER and waits for each reply before sending the next,
/// so a single dropped or mis-correlated response stalls it to a timeout
/// instead of merely skewing a number.
// wz-proves: api-compat-pico wz->pico partial
#[test]
#[ignore = "spawns the real zenoh-pico z_get_lat CLI and a cc-compiled binary; \
            run by run-ci Layer E"]
fn pico_zqueryablelat_source_on_wz_capi_answers_real_pico_zgetlat() {
    let dir = tempfile::tempdir().expect("tempdir for the compiled drop-in");
    let dropin = dropin_binary("z_queryable_lat", dir.path());
    let z_get_lat = zenoh_pico_cli_binary("z_get_lat");

    let reservation = PortReservation::pick();
    let port = reservation.port();
    let endpoint = format!("tcp/127.0.0.1:{port}");

    // Both sides default to the `lat` keyexpr, so neither is passed one.
    let mut qbl_out = tempfile::tempfile().expect("queryable_lat drop-in capture");
    let writer = qbl_out.try_clone().expect("dup queryable_lat handle");
    let err = qbl_out
        .try_clone()
        .expect("dup queryable_lat stderr handle");
    let mut qbl = ChildGuard::wrap(
        "z_queryable_lat.c on wz-capi-pico",
        Command::new("stdbuf")
            .args(["-oL", "-eL"])
            .arg(&dropin)
            .args(["-l", &endpoint, "-m", "peer"])
            .stdout(Stdio::from(writer))
            .stderr(Stdio::from(err))
            .spawn()
            .expect("spawn the compiled z_queryable_lat drop-in"),
    );

    if let Err(why) = wait_for_tcp_accept_alive(qbl.child_mut(), port, LISTEN_TIMEOUT) {
        panic!(
            "the z_queryable_lat.c drop-in never accepted on {endpoint} — {why}; \
             capture so far:\n{}",
            read_captured(&mut qbl_out)
        );
    }
    drop(reservation);

    let mut lat_out = tempfile::tempfile().expect("foreign z_get_lat capture");
    let lat_writer = lat_out.try_clone().expect("dup foreign get_lat handle");
    // `-n 5` round trips after a short warmup; each prints one line.
    let lat = Command::new("stdbuf")
        .args(["-oL", "-eL"])
        .arg(&z_get_lat)
        .args(["-e", &endpoint, "-m", "client", "-n", "5", "-w", "500"])
        .stdout(Stdio::from(lat_writer))
        .stderr(Stdio::from(lat_out.try_clone().expect("dup stderr handle")))
        .spawn()
        .expect("spawn the real zenoh-pico z_get_lat");
    let lat = bounded_exit("real pico z_get_lat", lat, &mut lat_out);
    let foreign = read_captured(&mut lat_out);
    let responder = read_captured(&mut qbl_out);
    assert!(
        lat.success(),
        "real zenoh-pico z_get_lat exited {lat:?} — a queryable that never replied \
         stalls it.\n--- its stdout+stderr ---\n{foreign}\n\
         --- z_queryable_lat.c (on wz) stdout+stderr ---\n{responder}"
    );
    // One line per completed round trip. Fewer than the five asked for means a
    // reply was lost or mis-correlated.
    let round_trips = foreign
        .lines()
        .filter(|line| line.trim().parse::<u64>().is_ok())
        .count();
    assert_eq!(
        round_trips, 5,
        "the REAL zenoh-pico z_get_lat completed {round_trips} of 5 round trips \
         against upstream's z_queryable_lat.c running ON wz.\n\
         --- REAL pico z_get_lat stdout ---\n{foreign}\n\
         --- z_queryable_lat.c (on wz) stdout+stderr ---\n{responder}"
    );

    graceful_terminate(qbl.child_mut(), Duration::from_secs(5));
}

/// LEG 28 (`pico->wz`) — upstream's `z_sub_attachment.c`, running on wz, reads
/// the attachment, encoding and timestamp the REAL zenoh-pico
/// `z_pub_attachment` sent.
///
/// The subscriber-side attachment leg. Its twin (`z_pub_attachment` on wz,
/// decoded by a real pico subscriber) is LEG 13 and is what caught wz silently
/// dropping all three on the way OUT; this is the inbound direction of the same
/// three fields.
// wz-proves: api-compat-pico pico->wz partial
#[test]
#[ignore = "spawns the real zenoh-pico z_pub_attachment CLI and a cc-compiled \
            binary; run by run-ci Layer E"]
fn pico_zsubattachment_source_on_wz_capi_decodes_a_real_pico_attachment() {
    let dir = tempfile::tempdir().expect("tempdir for the compiled drop-in");
    let dropin = dropin_binary("z_sub_attachment", dir.path());
    let z_pub_attachment = zenoh_pico_cli_binary("z_pub_attachment");

    let reservation = PortReservation::pick();
    let port = reservation.port();
    let endpoint = format!("tcp/127.0.0.1:{port}");
    let key = "demo/dropin/leg28";

    let mut sub_out = tempfile::tempfile().expect("sub_attachment drop-in capture");
    let writer = sub_out.try_clone().expect("dup sub_attachment handle");
    let err = sub_out
        .try_clone()
        .expect("dup sub_attachment stderr handle");
    let mut sub = ChildGuard::wrap(
        "z_sub_attachment.c on wz-capi-pico",
        Command::new("stdbuf")
            .args(["-oL", "-eL"])
            .arg(&dropin)
            .args(["-l", &endpoint, "-m", "peer", "-k", key])
            .stdout(Stdio::from(writer))
            .stderr(Stdio::from(err))
            .spawn()
            .expect("spawn the compiled z_sub_attachment drop-in"),
    );

    if let Err(why) = wait_for_tcp_accept_alive(sub.child_mut(), port, LISTEN_TIMEOUT) {
        panic!(
            "the z_sub_attachment.c drop-in never accepted on {endpoint} — {why}; \
             capture so far:\n{}",
            read_captured(&mut sub_out)
        );
    }
    drop(reservation);

    let mut pub_out = tempfile::tempfile().expect("foreign z_pub_attachment capture");
    let pub_writer = pub_out.try_clone().expect("dup foreign publisher handle");
    let mut publisher = ChildGuard::wrap(
        "real zenoh-pico z_pub_attachment",
        Command::new("stdbuf")
            .args(["-oL", "-eL"])
            .arg(&z_pub_attachment)
            .args(["-e", &endpoint, "-m", "client", "-k", key])
            .stdout(Stdio::from(pub_writer))
            .stderr(Stdio::from(pub_out.try_clone().expect("dup stderr handle")))
            .spawn()
            .expect("spawn the real zenoh-pico z_pub_attachment"),
    );

    let captured = wait_for_substring(&mut sub_out, "with attachment", EXCHANGE_TIMEOUT)
        .unwrap_or_else(|captured| {
            let driver = read_captured(&mut pub_out);
            panic!(
                "upstream z_sub_attachment.c on wz's C-ABI never reported an \
                 attachment on a sample from the REAL zenoh-pico z_pub_attachment.\n\
                 the foreign publisher reached its put: {}\n\
                 --- z_sub_attachment.c (on wz) stdout+stderr ---\n{captured}\n\
                 --- REAL pico z_pub_attachment stdout ---\n{driver}",
                driver.contains("Putting Data"),
            )
        });
    // Encoding rides the same sample and is a separate ext; upstream prints it
    // on its own line, so a build that carried the attachment and dropped the
    // encoding would pass the wait above.
    assert!(
        captured.contains("with encoding"),
        "the attachment arrived but the ENCODING did not, so that ext was lost \
         inbound.\n--- z_sub_attachment.c (on wz) stdout+stderr ---\n{captured}"
    );

    graceful_terminate(publisher.child_mut(), Duration::from_secs(5));
    graceful_terminate(sub.child_mut(), Duration::from_secs(5));
}

/// LEG 31 (`pico->wz`) — upstream's `z_sub_thr.c`, running on wz, measures the
/// rate of samples from the REAL zenoh-pico `z_pub_thr` under BATCHED load.
///
/// NAMING: "measures", not "counts". Layer E's sweep carries `--skip capi_c`
/// (it excludes the zenoh-c ABI family, whose artifact a later lane rebuilds),
/// and `..._on_wz_capi_counts_...` contains that token as a substring — so the
/// first spelling of this test registered and was SILENTLY filtered out, which
/// the lane reported only as "28 passed; 3 filtered out" against a 31-test
/// file. Read the lane LOG, not its verdict.
///
/// The throughput pair is the only leg that puts many small samples on the wire
/// back to back, which is what exercises the transport's batching seam rather
/// than its single-message path: `z_pub_thr` publishes in a tight loop, so the
/// peer's frames carry several messages each. A receiver that decoded only the
/// first message of a batch would still pass every single-sample leg here and
/// would report a throughput of roughly one message per frame.
// wz-proves: api-compat-pico pico->wz partial
#[test]
#[ignore = "spawns the real zenoh-pico z_pub_thr CLI and a cc-compiled binary; \
            run by run-ci Layer E"]
fn pico_zsubthr_source_on_wz_capi_measures_a_real_pico_batched_stream() {
    let dir = tempfile::tempdir().expect("tempdir for the compiled drop-in");
    let dropin = dropin_binary("z_sub_thr", dir.path());
    let z_pub_thr = zenoh_pico_cli_binary("z_pub_thr");

    let reservation = PortReservation::pick();
    let port = reservation.port();
    let endpoint = format!("tcp/127.0.0.1:{port}");

    // Both sides default to the `thr` keyexpr.
    let mut sub_out = tempfile::tempfile().expect("sub_thr drop-in capture");
    let writer = sub_out.try_clone().expect("dup sub_thr handle");
    let err = sub_out.try_clone().expect("dup sub_thr stderr handle");
    let mut sub = ChildGuard::wrap(
        "z_sub_thr.c on wz-capi-pico",
        Command::new("stdbuf")
            .args(["-oL", "-eL"])
            .arg(&dropin)
            .args(["-l", &endpoint, "-m", "peer"])
            .stdout(Stdio::from(writer))
            .stderr(Stdio::from(err))
            .spawn()
            .expect("spawn the compiled z_sub_thr drop-in"),
    );

    if let Err(why) = wait_for_tcp_accept_alive(sub.child_mut(), port, LISTEN_TIMEOUT) {
        panic!(
            "the z_sub_thr.c drop-in never accepted on {endpoint} — {why}; \
             capture so far:\n{}",
            read_captured(&mut sub_out)
        );
    }
    drop(reservation);

    let mut pub_out = tempfile::tempfile().expect("foreign z_pub_thr capture");
    let pub_writer = pub_out.try_clone().expect("dup foreign publisher handle");
    let mut publisher = ChildGuard::wrap(
        "real zenoh-pico z_pub_thr",
        Command::new("stdbuf")
            .args(["-oL", "-eL"])
            .arg(&z_pub_thr)
            .args(["-e", &endpoint, "-m", "client"])
            .stdout(Stdio::from(pub_writer))
            .stderr(Stdio::from(pub_out.try_clone().expect("dup stderr handle")))
            .spawn()
            .expect("spawn the real zenoh-pico z_pub_thr"),
    );

    // Upstream prints one messages-per-second figure per elapsed period.
    let captured = wait_for_capture_alive(
        sub.child_mut(),
        &mut sub_out,
        EXCHANGE_TIMEOUT,
        "a non-zero message rate",
        |text: &str| {
            text.lines()
                .any(|line| line.trim().parse::<f64>().map(|v| v > 0.0).unwrap_or(false))
                .then(|| text.to_owned())
        },
    )
    .unwrap_or_else(|captured| {
        let driver = read_captured(&mut pub_out);
        panic!(
            "upstream z_sub_thr.c on wz's C-ABI never reported a NON-ZERO message \
             rate for the REAL zenoh-pico z_pub_thr's stream.\n\
             --- z_sub_thr.c (on wz) stdout+stderr ---\n{captured}\n\
             --- REAL pico z_pub_thr stdout ---\n{driver}"
        )
    });
    let best = captured
        .lines()
        .filter_map(|line| line.trim().parse::<f64>().ok())
        .fold(0.0f64, f64::max);
    // A receiver that decoded one message per frame would land near the frame
    // rate, orders of magnitude below this. The bound is deliberately loose:
    // this leg asserts BATCHING happened, not how fast the host is.
    assert!(
        best > 1000.0,
        "the best observed rate was {best:.3} msg/s, which is the shape of a \
         receiver decoding roughly one message per FRAME rather than draining the \
         batch.\n--- z_sub_thr.c (on wz) stdout+stderr ---\n{captured}"
    );

    graceful_terminate(publisher.child_mut(), Duration::from_secs(5));
    graceful_terminate(sub.child_mut(), Duration::from_secs(5));
}

/// LEG 33 (`pico->wz`, SINGLE-THREADED arm) — upstream's `z_sub_st.c`, compiled
/// against a `Z_FEATURE_MULTI_THREAD == 0` header set and running on wz,
/// receives a sample published by the REAL zenoh-pico `z_put`.
///
/// This leg and its sibling below are what turned the single-threaded pair from
/// an EXCLUSION into a witness, and the exclusion's stated reason was measured
/// wrong. It read: a `zp_spin_once` build "would need `Z_FEATURE_MULTI_THREAD ==
/// 0` in the header set, which is a different pico build", and a different build
/// "would need a second cdylib arm to link against". The first half is true and
/// cheap — CMake writes `config.h` at CONFIGURE time, so the arm costs one extra
/// `cmake -B` and no compile. The second half is false, and the measurement is
/// in `scripts/build-zenoh-pico-cli.sh`: across the two configs the ONLY public
/// owned types whose size moves are `z_owned_mutex_t` (40 -> 8) and
/// `z_owned_condvar_t` (48 -> 8). Session, publisher, subscriber, bytes, sample,
/// closure and handler are byte-identical, and neither example names a mutex or
/// a condvar. One cdylib serves both arms.
///
/// What the arm DOES need is one export wz did not have: `zp_spin_once`. Under
/// `Z_FEATURE_MULTI_THREAD == 0` pico has no executor thread, so the application
/// advances the session by hand — every loop iteration here sleeps 50 ms and
/// calls it. The link failure was the measurement: both ST examples were missing
/// exactly that one symbol and nothing else.
///
/// The counterparty is the ORDINARY multi-threaded `z_put` binary, deliberately.
/// `Z_FEATURE_MULTI_THREAD` is a host threading model, not a wire feature, so a
/// single-threaded program and a multi-threaded one are the same peer on the
/// socket. Using the installed oracle also keeps the foreign side identical to
/// every other `pico->wz` leg in this file.
// wz-proves: api-compat-pico pico->wz partial
#[test]
#[ignore = "spawns the real zenoh-pico z_put CLI and a cc-compiled binary; \
            run by run-ci Layer E"]
fn pico_zsubst_source_on_wz_capi_receives_from_real_pico_zput() {
    let dir = tempfile::tempdir().expect("tempdir for the compiled drop-in");
    let dropin = dropin_binary_single_threaded("z_sub_st", dir.path());
    let z_put = zenoh_pico_cli_binary("z_put");

    let reservation = PortReservation::pick();
    let port = reservation.port();
    let endpoint = format!("tcp/127.0.0.1:{port}");
    let payload = "PAYLOAD-INTO-SINGLE-THREADED-DROPIN";
    let key = "demo/dropin/leg33";

    let mut sub_out = tempfile::tempfile().expect("subscriber stdout capture");
    let writer = sub_out.try_clone().expect("dup subscriber stdout handle");
    let sub_err = sub_out.try_clone().expect("dup subscriber stderr handle");
    let mut sub = ChildGuard::wrap(
        "z_sub_st.c on wz-capi-pico",
        Command::new("stdbuf")
            .args(["-oL", "-eL"])
            .arg(&dropin)
            .args([
                "-l",
                &endpoint,
                "-m",
                "peer",
                "-k",
                "demo/dropin/**",
                "-n",
                "1",
            ])
            .stdout(Stdio::from(writer))
            .stderr(Stdio::from(sub_err))
            .spawn()
            .expect("spawn the compiled z_sub_st drop-in"),
    );

    if let Err(why) = wait_for_tcp_accept_alive(sub.child_mut(), port, LISTEN_TIMEOUT) {
        panic!(
            "the z_sub_st.c drop-in never accepted on {endpoint} — {why}; capture so far:\n{}",
            read_captured(&mut sub_out)
        );
    }
    drop(reservation);

    let mut put_out = tempfile::tempfile().expect("foreign z_put stdout capture");
    let put_writer = put_out.try_clone().expect("dup foreign z_put handle");
    let put = Command::new("stdbuf")
        .args(["-oL", "-eL"])
        .arg(&z_put)
        .args(["-e", &endpoint, "-m", "client", "-k", key, "-v", payload])
        .stdout(Stdio::from(put_writer))
        .stderr(Stdio::from(put_out.try_clone().expect("dup stderr handle")))
        .status()
        .expect("run the real zenoh-pico z_put");
    assert!(
        put.success(),
        "real zenoh-pico z_put exited {put:?}\n--- its stdout+stderr ---\n{}",
        read_captured(&mut put_out)
    );

    let captured =
        wait_for_substring(&mut sub_out, payload, EXCHANGE_TIMEOUT).unwrap_or_else(|captured| {
            let driver = read_captured(&mut put_out);
            panic!(
                "upstream z_sub_st.c running on wz's C-ABI never reported the payload \
                 published by the REAL zenoh-pico z_put.\nexpected substring: {payload}\n\
                 the foreign publisher reached its put: {}\n\
                 --- z_sub_st.c (on wz) stdout+stderr ---\n{captured}\n\
                 --- REAL pico z_put (driver) stdout ---\n{driver}",
                driver.contains("Putting Data"),
            )
        });
    // The stub `#else` branch prints this and exits -2. Asserting its ABSENCE is
    // what keeps the leg from being satisfied by a program with no body: the
    // payload assertion above already implies it, but only as long as the two
    // never appear together, and a partially-flushed capture is exactly where
    // that assumption would break quietly.
    assert!(
        !captured.contains("ERROR: Zenoh pico"),
        "z_sub_st.c compiled to its feature-gated STUB branch, so this leg drove \
         no wz code. The single-threaded header arm is not in effect.\n\
         --- stdout+stderr ---\n{captured}"
    );
    assert!(
        captured.contains(key),
        "the payload arrived but not on the key the foreign publisher used \
         ({key}); wz's inbound keyexpr resolution disagrees.\n--- stdout+stderr ---\n{captured}"
    );

    graceful_terminate(sub.child_mut(), Duration::from_secs(5));
}

/// LEG 34 (`wz->pico`, SINGLE-THREADED arm) — upstream's `z_pub_st.c`, compiled
/// against a `Z_FEATURE_MULTI_THREAD == 0` header set and running on wz,
/// publishes a sample the REAL zenoh-pico `z_sub` receives and reports.
///
/// The sibling of LEG 33 in the other direction, and the stronger of the two:
/// the witness line is read from the FOREIGN process's own stdout, so the
/// verdict comes from upstream's decoder rather than from a drop-in printing
/// what wz handed it.
///
/// The drop-in DIALS and the foreign subscriber listens, which is what lets this
/// leg publish exactly ONCE. `z_pub_st.c` puts on a 1-second timer, and `z_open`
/// does not return until the session is established, so by the time the first
/// (and with `-n 1`, only) put happens the foreign peer has been listening with
/// its subscription declared since before the dial. The ordering is the
/// fixture's, not a retry's.
// wz-proves: api-compat-pico wz->pico partial
#[test]
#[ignore = "spawns the real zenoh-pico z_sub CLI and a cc-compiled binary; \
            run by run-ci Layer E"]
fn pico_zpubst_source_on_wz_capi_reaches_real_pico_zsub() {
    let dir = tempfile::tempdir().expect("tempdir for the compiled drop-in");
    let dropin = dropin_binary_single_threaded("z_pub_st", dir.path());
    let z_sub = zenoh_pico_cli_binary("z_sub");

    let reservation = PortReservation::pick();
    let port = reservation.port();
    let endpoint = format!("tcp/127.0.0.1:{port}");
    let payload = "SINGLE-THREADED-DROPIN-PUBLISHES";
    let key = "demo/dropin/leg34";

    let mut sub_out = tempfile::tempfile().expect("z_sub stdout capture");
    let writer = sub_out.try_clone().expect("dup z_sub stdout handle");
    let mut sub = ChildGuard::wrap(
        "real zenoh-pico z_sub",
        Command::new("stdbuf")
            .args(["-oL", "-eL"])
            .arg(&z_sub)
            .args([
                "-l",
                &endpoint,
                "-m",
                "peer",
                "-k",
                "demo/dropin/**",
                "-n",
                "1",
            ])
            .stdout(Stdio::from(writer))
            .stderr(Stdio::from(sub_out.try_clone().expect("dup stderr handle")))
            .spawn()
            .expect("spawn the real zenoh-pico z_sub"),
    );

    if let Err(why) = wait_for_tcp_accept_alive(sub.child_mut(), port, LISTEN_TIMEOUT) {
        panic!(
            "the real zenoh-pico z_sub never accepted on {endpoint} — {why}; capture so far:\n{}",
            read_captured(&mut sub_out)
        );
    }
    drop(reservation);

    let mut pub_out = tempfile::tempfile().expect("z_pub_st drop-in stdout capture");
    let pub_writer = pub_out.try_clone().expect("dup z_pub_st stdout handle");
    let pub_err = pub_out.try_clone().expect("dup z_pub_st stderr handle");
    // Spawned and BOUNDED rather than `status()`ed: upstream's loop only leaves
    // when it has issued its `-n` puts, so a session that never came up would
    // otherwise wait here forever with nothing said.
    let publisher = Command::new("stdbuf")
        .args(["-oL", "-eL"])
        .arg(&dropin)
        .args([
            "-e", &endpoint, "-m", "client", "-k", key, "-v", payload, "-n", "1",
        ])
        .stdout(Stdio::from(pub_writer))
        .stderr(Stdio::from(pub_err))
        .spawn()
        .expect("spawn the compiled z_pub_st drop-in");
    let status = bounded_exit("z_pub_st.c on wz-capi-pico", publisher, &mut pub_out);
    assert!(
        status.success(),
        "upstream z_pub_st.c on wz's C-ABI exited {status:?} — it returns -1 when \
         z_open, z_view_keyexpr_from_str or z_declare_publisher fails, and -2 from \
         the feature-gated stub branch\n--- its stdout+stderr ---\n{}",
        read_captured(&mut pub_out)
    );

    let foreign =
        wait_for_substring(&mut sub_out, payload, EXCHANGE_TIMEOUT).unwrap_or_else(|captured| {
            let driver = read_captured(&mut pub_out);
            panic!(
                "the REAL zenoh-pico z_sub never received the put that upstream's \
                 z_pub_st.c issued while running on wz's C-ABI.\n\
                 expected substring: {payload}\n\
                 wz-side driver reached its put: {}\n\
                 --- REAL pico z_sub stdout ---\n{captured}\n\
                 --- z_pub_st.c-on-wz (driver) stdout+stderr ---\n{driver}",
                driver.contains("Putting Data"),
            )
        });
    assert!(
        foreign.contains(key),
        "the sample reached the foreign subscriber on the wrong key (expected \
         {key}).\n--- REAL pico z_sub stdout ---\n{foreign}"
    );

    graceful_terminate(sub.child_mut(), Duration::from_secs(5));
}

/// The keyexpr / payload / topology the two TLS legs share, plus the reason the
/// PUBLISHER is the listener in both.
///
/// R311y534 — the direction was CALIBRATED against the reference before either
/// leg was written, and the first arrangement tried was wrong. With the
/// SUBSCRIBER listening (`-l tls/...`) and a `client` publisher dialing in, the
/// real zenoh-pico `z_pub_tls` reaches a real zenoh-pico `z_sub_tls` with ZERO
/// samples — and the identical arrangement over plain TCP with `z_pub`/`z_sub`
/// is also zero. Reversed, both pairs deliver. So it is not TLS and it is not
/// wz: a DECLARED publisher (which every `z_*_pub*` example is) dialing OUT as a
/// client never has its write filter armed by the peer it dialed, and pico drops
/// the put before the wire. Writing the legs the other way round would have
/// produced two red tests and a hunt through wz's TLS code for a defect that was
/// never there.
///
/// Both legs therefore run: publisher LISTENS as a peer, subscriber DIALS as a
/// client. That also puts the wz side on the interesting half of each leg —
/// LEG 35's wz is the TLS ACCEPTOR, LEG 36's wz is the TLS DIALER, so the pair
/// covers both halves of the handshake rather than one twice.
const TLS_KEY: &str = "demo/dropin/tls";
const TLS_KEY_FILTER: &str = "demo/dropin/**";

/// LEG 35 (`wz->pico`) — upstream's `z_pub_tls.c`, running on wz, ACCEPTS a real
/// zenoh-pico `z_sub_tls` over TLS and publishes a sample the foreign process
/// decodes and reports.
///
/// This is the leg that makes wz's C ABI a TLS acceptor. Everything the
/// handshake needs is supplied by upstream's own program: the server cert and
/// private key are base64 PEM blobs compiled into `z_pub_tls.c` and inserted
/// under `Z_CONFIG_TLS_LISTEN_{CERTIFICATE,PRIVATE_KEY}_BASE64_KEY`, and wz has
/// to resolve those keys, build a rustls `ServerConfig` from them, and bind a
/// `tls/` listener that presents it. Before R311y534 wz read only the PATH forms
/// of those two keys and fed them exclusively to the QUIC acceptor, so this
/// program's config produced a cert-free `tls/` bind and a typed `Unsupported`.
///
/// The verdict is FOREIGN and it is not merely a payload match: real zenoh-pico
/// (over mbedtls) completed a TLS handshake against wz (over rustls), decrypted
/// the record layer, and parsed a zenoh frame out of it. A wz that presented a
/// wrong cert, a wrong chain, or spoke the zenoh framing in the clear could not
/// reach that line.
// wz-proves: api-compat-pico wz->pico partial
#[test]
#[ignore = "spawns the real zenoh-pico z_sub_tls CLI and a cc-compiled binary; \
            run by run-ci Layer E"]
fn pico_zpubtls_source_on_wz_capi_serves_real_pico_zsubtls_over_tls() {
    let dir = tempfile::tempdir().expect("tempdir for the compiled drop-in");
    let dropin = dropin_binary("z_pub_tls", dir.path());
    let z_sub_tls = zenoh_pico_cli_binary("z_sub_tls");

    let reservation = PortReservation::pick();
    let port = reservation.port();
    let endpoint = format!("tls/127.0.0.1:{port}");
    let payload = "TLS-FROM-DROPIN-PUBLISHER";

    let mut pub_out = tempfile::tempfile().expect("z_pub_tls drop-in stdout capture");
    let writer = pub_out.try_clone().expect("dup z_pub_tls stdout handle");
    let pub_err = pub_out.try_clone().expect("dup z_pub_tls stderr handle");
    // `-n 60`: upstream puts on a one-second timer, so the count is a WINDOW,
    // not an expectation. The subscriber leaves on its first sample and this
    // publisher is terminated right after; a small count would make the leg a
    // race between the dialer's handshake and the publisher's exit.
    let mut publisher = ChildGuard::wrap(
        "z_pub_tls.c on wz-capi-pico",
        Command::new("stdbuf")
            .args(["-oL", "-eL"])
            .arg(&dropin)
            .args([
                "-l", &endpoint, "-m", "peer", "-k", TLS_KEY, "-v", payload, "-n", "60",
            ])
            .stdout(Stdio::from(writer))
            .stderr(Stdio::from(pub_err))
            .spawn()
            .expect("spawn the compiled z_pub_tls drop-in"),
    );

    if let Err(why) = wait_for_tcp_accept_alive(publisher.child_mut(), port, LISTEN_TIMEOUT) {
        panic!(
            "the z_pub_tls.c drop-in never accepted on {endpoint} — {why}. Its \
             z_open must resolve the inline base64 listen cert + key and bind a \
             TLS listener that presents them; capture so far:\n{}",
            read_captured(&mut pub_out)
        );
    }
    drop(reservation);

    let mut sub_out = tempfile::tempfile().expect("foreign z_sub_tls stdout capture");
    let sub_writer = sub_out.try_clone().expect("dup foreign z_sub_tls handle");
    let sub_err = sub_out
        .try_clone()
        .expect("dup foreign z_sub_tls stderr handle");
    let subscriber = Command::new("stdbuf")
        .args(["-oL", "-eL"])
        .arg(&z_sub_tls)
        .args([
            "-e",
            &endpoint,
            "-m",
            "client",
            "-k",
            TLS_KEY_FILTER,
            "-n",
            "1",
        ])
        .stdout(Stdio::from(sub_writer))
        .stderr(Stdio::from(sub_err))
        .spawn()
        .expect("spawn the real zenoh-pico z_sub_tls");
    let status = bounded_exit("real zenoh-pico z_sub_tls", subscriber, &mut sub_out);

    let foreign = read_captured(&mut sub_out);
    assert!(
        status.success(),
        "the REAL zenoh-pico z_sub_tls exited {status:?} dialing wz's TLS \
         listener — it returns -1 when z_open fails, which is what a rejected or \
         absent TLS handshake looks like from the foreign side.\n\
         --- REAL pico z_sub_tls stdout+stderr ---\n{foreign}\n\
         --- z_pub_tls.c (on wz) stdout+stderr ---\n{}",
        read_captured(&mut pub_out)
    );
    assert!(
        foreign.contains(payload),
        "the REAL zenoh-pico z_sub_tls opened a TLS session against wz but never \
         reported the sample upstream's z_pub_tls.c published while running on \
         wz's C-ABI.\nexpected substring: {payload}\n\
         --- REAL pico z_sub_tls stdout+stderr ---\n{foreign}\n\
         --- z_pub_tls.c (on wz) stdout+stderr ---\n{}",
        read_captured(&mut pub_out)
    );
    // The KEY as well as the payload, for the same reason as LEG 1: a keyexpr wz
    // resolved wrongly would still carry the right bytes.
    assert!(
        foreign.contains(TLS_KEY),
        "the payload crossed TLS but not on the key the drop-in published \
         ({TLS_KEY}).\n--- REAL pico z_sub_tls stdout ---\n{foreign}"
    );

    graceful_terminate(publisher.child_mut(), Duration::from_secs(5));
}

/// LEG 36 (`pico->wz`) — upstream's `z_sub_tls.c`, running on wz, DIALS a real
/// zenoh-pico `z_pub_tls` over TLS and reports the sample the foreign publisher
/// encrypted.
///
/// The mirror of LEG 35, and the half that exercises wz as the TLS CLIENT: here
/// the foreign process owns the cert and wz has to verify it. The program hands
/// wz a root CA under `Z_CONFIG_TLS_ROOT_CA_CERTIFICATE_BASE64_KEY` and a
/// `Z_CONFIG_TLS_VERIFY_NAME_ON_CONNECT_KEY` of `"false"`, and BOTH matter: the
/// bundled cert names `localhost` while the example dials `tls/127.0.0.1:<port>`,
/// so a wz that ignored the verify-name key and hard-coded SAN checking would
/// fail this handshake on a cert the reference accepts. Chain-to-root is still
/// enforced — only the name match is dropped — so this is not a leg that passes
/// on an unverified connection.
///
/// The witness is the drop-in's own stdout, which is weaker than LEG 35's
/// foreign verdict; the pair is what makes the claim, since LEG 35's foreign
/// process cannot say anything about wz's dial path and this one can.
// wz-proves: api-compat-pico pico->wz partial
#[test]
#[ignore = "spawns the real zenoh-pico z_pub_tls CLI and a cc-compiled binary; \
            run by run-ci Layer E"]
fn pico_zsubtls_source_on_wz_capi_dials_real_pico_zpubtls_over_tls() {
    let dir = tempfile::tempdir().expect("tempdir for the compiled drop-in");
    let dropin = dropin_binary("z_sub_tls", dir.path());
    let z_pub_tls = zenoh_pico_cli_binary("z_pub_tls");

    let reservation = PortReservation::pick();
    let port = reservation.port();
    let endpoint = format!("tls/127.0.0.1:{port}");
    let payload = "TLS-FROM-REAL-PICO-PUBLISHER";

    let mut pub_out = tempfile::tempfile().expect("foreign z_pub_tls stdout capture");
    let writer = pub_out.try_clone().expect("dup foreign z_pub_tls handle");
    let pub_err = pub_out
        .try_clone()
        .expect("dup foreign z_pub_tls stderr handle");
    let mut publisher = ChildGuard::wrap(
        "real zenoh-pico z_pub_tls",
        Command::new("stdbuf")
            .args(["-oL", "-eL"])
            .arg(&z_pub_tls)
            .args([
                "-l", &endpoint, "-m", "peer", "-k", TLS_KEY, "-v", payload, "-n", "60",
            ])
            .stdout(Stdio::from(writer))
            .stderr(Stdio::from(pub_err))
            .spawn()
            .expect("spawn the real zenoh-pico z_pub_tls"),
    );

    if let Err(why) = wait_for_tcp_accept_alive(publisher.child_mut(), port, LISTEN_TIMEOUT) {
        panic!(
            "the real zenoh-pico z_pub_tls never accepted on {endpoint} — {why}; \
             capture so far:\n{}",
            read_captured(&mut pub_out)
        );
    }
    drop(reservation);

    let mut sub_out = tempfile::tempfile().expect("z_sub_tls drop-in stdout capture");
    let sub_writer = sub_out.try_clone().expect("dup z_sub_tls stdout handle");
    let sub_err = sub_out.try_clone().expect("dup z_sub_tls stderr handle");
    let subscriber = Command::new("stdbuf")
        .args(["-oL", "-eL"])
        .arg(&dropin)
        .args([
            "-e",
            &endpoint,
            "-m",
            "client",
            "-k",
            TLS_KEY_FILTER,
            "-n",
            "1",
        ])
        .stdout(Stdio::from(sub_writer))
        .stderr(Stdio::from(sub_err))
        .spawn()
        .expect("spawn the compiled z_sub_tls drop-in");
    let status = bounded_exit("z_sub_tls.c on wz-capi-pico", subscriber, &mut sub_out);

    let captured = read_captured(&mut sub_out);
    assert!(
        status.success(),
        "upstream z_sub_tls.c on wz's C-ABI exited {status:?} — it returns -1 when \
         z_open fails, which is what a TLS dial with no trust material, a rejected \
         chain, or an unsupported `tls/` scheme looks like from inside.\n\
         --- z_sub_tls.c (on wz) stdout+stderr ---\n{captured}\n\
         --- REAL pico z_pub_tls stdout+stderr ---\n{}",
        read_captured(&mut pub_out)
    );
    assert!(
        captured.contains(payload),
        "upstream z_sub_tls.c running on wz's C-ABI never reported the sample the \
         REAL zenoh-pico z_pub_tls encrypted onto the TLS link it dialed.\n\
         expected substring: {payload}\n\
         the foreign publisher reached its put: {}\n\
         --- z_sub_tls.c (on wz) stdout+stderr ---\n{captured}\n\
         --- REAL pico z_pub_tls stdout+stderr ---\n{}",
        read_captured(&mut pub_out).contains("Putting Data"),
        read_captured(&mut pub_out),
    );
    assert!(
        captured.contains(TLS_KEY),
        "the payload arrived over TLS but not on the key the foreign publisher \
         used ({TLS_KEY}); wz's inbound keyexpr resolution disagrees.\n\
         --- z_sub_tls.c (on wz) stdout ---\n{captured}"
    );

    graceful_terminate(publisher.child_mut(), Duration::from_secs(5));
}

/// LEG 32 (`pico->wz`) — upstream's `z_pong.c`, running on wz, echoes for the
/// REAL zenoh-pico `z_ping`, which reports the round trips it completed.
///
/// This program was carried as an EXCLUSION for two rounds under the heading
/// "links, has a body, and still cannot be driven", and the exclusion's
/// reasoning is worth keeping because the observation was right and the
/// conclusion was wrong. Its callback never calls the API:
///
/// ```c
/// void callback(z_loaned_sample_t* sample, void* context) {
///     const z_loaned_publisher_t* pub = z_loan(*(z_owned_publisher_t*)context);
///     z_owned_bytes_t payload = {._val = sample->payload};
///     z_publisher_put(pub, z_move(payload), NULL);
/// }
/// ```
///
/// `sample->payload` reads a FIELD of pico's concrete `_z_sample_t`, and
/// `{._val = ...}` writes a field of pico's concrete `z_owned_bytes_t`. Against
/// a marshal with no such layout the read returned whatever sat at offset 48,
/// and the measurement was unambiguous: the real `z_ping` completed ZERO round
/// trips and hung.
///
/// The exclusion then said supporting it "means reproducing `_z_bytes_t`'s
/// refcounted arc-slice representation ... a different ABI commitment from the
/// handle model this crate is built on". That is the half that was wrong, and
/// the correction is the interesting part. Two things were needed and neither is
/// an allocator:
///
/// 1. `SampleMarshal` reproduces pico's `_z_sample_t` layout PREFIX — 48 inert
///    bytes where the keyexpr lives, then a 32-byte payload slot — so the field
///    read lands on something wz put there. Offsets measured from upstream's
///    headers and pinned by a `const _` assertion in `wz-capi-pico::pubsub`.
/// 2. That slot is a BORROW, tagged as such. The by-value copy plus `z_move`
///    really would be a double free over a `Box` handle, which is what the
///    exclusion saw. But pico does not solve that with refcounting either — its
///    `_z_svec_t` carries an `_aliased` flag and its clear() skips the free when
///    the flag is set. wz now carries the same flag in the handle's padding
///    slot, and `take_moved_bytes` copies instead of reclaiming when it is set.
///
/// So the shape of the correction is: an exclusion whose OBSERVATION was
/// measured and whose CONSEQUENCE was assumed. The observation cost nothing to
/// re-verify; the consequence went unchecked for two rounds and turned out to
/// name a harder problem than the one that was actually there.
// wz-proves: api-compat-pico pico->wz partial
#[test]
#[ignore = "spawns the real zenoh-pico z_ping CLI and a cc-compiled binary; \
            run by run-ci Layer E"]
fn pico_zpong_source_on_wz_capi_echoes_for_the_real_pico_zping() {
    let dir = tempfile::tempdir().expect("tempdir for the compiled drop-in");
    let dropin = dropin_binary("z_pong", dir.path());
    let z_ping = zenoh_pico_cli_binary("z_ping");

    let reservation = PortReservation::pick();
    let port = reservation.port();
    let endpoint = format!("tcp/127.0.0.1:{port}");
    const PINGS: usize = 5;

    // The drop-in LISTENS and the foreign pinger dials, which is what puts the
    // verdict outside wz: every number `z_ping` prints requires a complete
    // circuit through this echo.
    //
    // `stdin` is a live PIPE, not inherited and not `null`. Upstream's loop is
    // `while (getchar() != 'q')`, so on a closed stdin `getchar` returns EOF
    // immediately and the program becomes a busy spin that steals the core the
    // echo needs. Holding the write end open blocks it in `read` instead, and
    // dropping the handle at the end of the test is what lets it leave.
    let mut pong_out = tempfile::tempfile().expect("z_pong drop-in stdout capture");
    let pong_writer = pong_out.try_clone().expect("dup z_pong stdout handle");
    let pong_err = pong_out.try_clone().expect("dup z_pong stderr handle");
    let mut pong = ChildGuard::wrap(
        "z_pong.c on wz-capi-pico",
        Command::new("stdbuf")
            .args(["-oL", "-eL"])
            .arg(&dropin)
            .args(["-l", &endpoint, "-m", "peer"])
            .stdin(Stdio::piped())
            .stdout(Stdio::from(pong_writer))
            .stderr(Stdio::from(pong_err))
            .spawn()
            .expect("spawn the compiled z_pong drop-in"),
    );
    if let Err(why) = wait_for_tcp_accept_alive(pong.child_mut(), port, LISTEN_TIMEOUT) {
        panic!(
            "the z_pong.c drop-in never accepted on {endpoint} — {why}; capture so far:\n{}",
            read_captured(&mut pong_out)
        );
    }
    drop(reservation);

    let mut ping_out = tempfile::tempfile().expect("foreign z_ping stdout capture");
    let writer = ping_out.try_clone().expect("dup foreign z_ping handle");
    let ping = Command::new("stdbuf")
        .args(["-oL", "-eL"])
        .arg(&z_ping)
        .args([
            "-e",
            &endpoint,
            "-m",
            "client",
            "-n",
            &PINGS.to_string(),
            "-s",
            "64",
            "-w",
            "500",
        ])
        .stdout(Stdio::from(writer))
        .stderr(Stdio::from(
            ping_out.try_clone().expect("dup stderr handle"),
        ))
        .spawn()
        .expect("spawn the real zenoh-pico z_ping");
    let status = bounded_exit("real zenoh-pico z_ping", ping, &mut ping_out);
    assert!(
        status.success(),
        "the REAL zenoh-pico z_ping exited {status:?} against the z_pong.c drop-in\n\
         --- z_ping stdout ---\n{}\n--- z_pong.c-on-wz stdout+stderr ---\n{}",
        read_captured(&mut ping_out),
        read_captured(&mut pong_out),
    );

    // z_ping prints one bare integer per COMPLETED round trip and nothing else on
    // the success path, so parsed integers count circuits closed. A payload that
    // arrived empty, on the wrong key, or not at all yields fewer lines — the
    // pinger's `load_loop` never returns for a ping it did not get back.
    let captured = read_captured(&mut ping_out);
    let samples: Vec<u64> = captured
        .lines()
        .filter_map(|l| l.trim().parse::<u64>().ok())
        .collect();
    assert_eq!(
        samples.len(),
        PINGS,
        "the REAL zenoh-pico z_ping completed {} of {PINGS} round trips through \
         upstream's z_pong.c running on wz's C-ABI.\n\
         --- REAL pico z_ping stdout ---\n{captured}\n\
         --- z_pong.c-on-wz stdout+stderr ---\n{}",
        samples.len(),
        read_captured(&mut pong_out),
    );

    graceful_terminate(pong.child_mut(), Duration::from_secs(5));
}

/// CONFIGURATION GATE — the exclusion list is EMPTY, and this is what holds it
/// there.
///
/// It has been inverted twice, and the shape of both inversions is the point.
/// It once named FOUR programs with no body to drive. `z_pub_st.c` /
/// `z_sub_st.c` left at LEGS 33/34 when their exclusion was re-read: it was
/// right that they compiled to a one-`printf` stub and wrong that fixing it
/// needed "a different pico build" AND "a second cdylib arm" — the second CMake
/// arm costs no compile, and the second cdylib was measured unnecessary.
///
/// `z_pub_tls.c` / `z_sub_tls.c` left at LEGS 35/36 the same way. Their
/// exclusion's OBSERVATION was exact — `Z_FEATURE_LINK_TLS` on makes `link.h`
/// pull `tls_stream.h` which `#include`s `mbedtls/*.h`, and this box had the
/// runtime `.so` without the headers. Its CONSEQUENCE, "a provisioning
/// prerequisite" left for whoever came next, was the half that went unexamined
/// for two rounds, and it hid a SECOND fact that no amount of installing the
/// distro package would have fixed: Ubuntu's `libmbedtls-dev` ships no
/// pkg-config metadata at all, and pico resolves Mbed TLS exclusively through
/// `pkg_search_module(MBEDTLS REQUIRED ...)` (`vendor/zenoh-pico/CMakeLists.txt
/// :479`). So the real prerequisite was a pinned Mbed TLS with its own `.pc`
/// (`scripts/install-mbedtls.sh`), and the flag then cost one line.
///
/// What that flag does NOT cost was measured before it was set: across
/// `Z_FEATURE_LINK_TLS` 0 and 1, every `z_owned_*` / `z_loaned_*` / `z_view_*` /
/// `z_moved_*` / `z_*_options_t` type the vendored headers declare — 86 of them
/// — has identical size and alignment. That is why TLS rides the PRIMARY header
/// arm rather than a fourth configure, and why one cdylib still serves all 36
/// legs.
///
/// So the gate now asserts the configuration each set of legs DEPENDS on, from
/// the side that makes a silent regression loud:
///
/// - primary arm `Z_FEATURE_LINK_TLS 1` — LEGS 35/36 drive real TLS bodies
///   through it; a 0 would turn both into stub runs that pass on a `printf`.
/// - ST arm `Z_FEATURE_MULTI_THREAD 0` — the same for LEGS 33/34.
/// - and the programs themselves must NOT take a feature-gated stub branch,
///   which is the direct observation rather than an inference from the header.
/// # R311y571 — this witnesses NO atom, and used to claim one
///
/// It read `api-compat-pico pico->wz partial`, and nothing in it reaches a
/// foreign implementation: it parses the CMake-generated `config.h` and runs
/// upstream's examples linked against WZ's cdylib. Every answer comes from wz.
/// The claim survived because A4 asked what the FILE reaches, and this file
/// spawns a real pico CLI in its other 36 legs — so a self-witnessing test sat
/// inside a foreign-classed file and counted as foreign proof. A4-8 is the
/// invariant that now asks per TEST.
///
/// What it actually is: the POSITIVE CONTROL for those 36 legs. If the header
/// arms were mis-configured every one of them would run a stub `main` and pass
/// on a `printf`. That is worth gating and is not a parity claim.
// wz-proves: none -- positive control for this file's 36 drop-in legs (asserts the header arms and that no program took a feature-gated stub branch); reaches no foreign implementation
#[test]
#[ignore = "reads the CMake-generated pico config and runs the drop-in binaries; \
            run by run-ci Layer E"]
fn pico_dropin_header_arms_give_every_example_a_real_body() {
    let dir = tempfile::tempdir().expect("tempdir for the compiled drop-ins");
    // The generated config is the SSOT for what these programs compiled to —
    // not the CMakeLists default, which R311y466 recorded as the trap.
    let generated = zenoh_pico_include_dirs()[0].join("zenoh-pico/config.h");
    let config = std::fs::read_to_string(&generated)
        .unwrap_or_else(|e| panic!("cannot read {}: {e}", generated.display()));
    assert!(
        config.contains("#define Z_FEATURE_LINK_TLS 1"),
        "the primary zenoh-pico header arm does NOT have Z_FEATURE_LINK_TLS 1, so \
         z_pub_tls.c / z_sub_tls.c compile to their `#else` stub main and LEGS \
         35/36 are driving a printf. Check that scripts/install-mbedtls.sh \
         provisioned the pinned Mbed TLS (pico's CMake resolves it through \
         pkg-config and hard-fails the configure without a .pc).\n--- {} ---\n{}",
        generated.display(),
        config
            .lines()
            .filter(|l| l.contains("Z_FEATURE_LINK_TLS"))
            .collect::<Vec<_>>()
            .join("\n"),
    );

    // The SINGLE-THREADED arm is asserted from the opposite side: it must be 0,
    // because LEGS 33/34 compile against it and a 1 there would silently turn
    // both of them into stub runs. The two checks together say that each of the
    // two header trees is the one its consumers believe it is.
    let generated_st = zenoh_pico_include_dirs_single_threaded()[0].join("zenoh-pico/config.h");
    let config_st = std::fs::read_to_string(&generated_st)
        .unwrap_or_else(|e| panic!("cannot read {}: {e}", generated_st.display()));
    assert!(
        config_st.contains("#define Z_FEATURE_MULTI_THREAD 0"),
        "the SINGLE-THREADED header arm does not have Z_FEATURE_MULTI_THREAD 0, \
         so LEGS 33/34 are driving stub mains.\n--- {} ---\n{}",
        generated_st.display(),
        config_st
            .lines()
            .filter(|l| l.contains("Z_FEATURE_MULTI_THREAD"))
            .collect::<Vec<_>>()
            .join("\n"),
    );

    // Run them. A stub main prints `ERROR: Zenoh pico was compiled without ...`
    // and exits -2, so its ABSENCE is the direct evidence that the `#if` arm
    // under test is the real one. Argument-free is deliberate: every one of these
    // fails its `z_open` (no connect, no listen) and that is fine — the branch is
    // chosen at COMPILE time, long before the session, so the stub marker is
    // present or absent regardless of what the run does next.
    //
    // The ST pair is checked through the ST header arm and the TLS pair through
    // the primary one, because that is how their legs compile them; checking
    // either through the other arm would assert the wrong tree.
    for example in ["z_pub_tls", "z_sub_tls"] {
        assert_not_a_stub_main(example, &dropin_binary(example, dir.path()));
    }
    for example in ["z_pub_st", "z_sub_st"] {
        assert_not_a_stub_main(example, &dropin_binary_single_threaded(example, dir.path()));
    }
}

/// Assert a compiled drop-in did NOT take an upstream example's feature-gated
/// `#else` stub branch.
fn assert_not_a_stub_main(example: &str, exe: &std::path::Path) {
    let out = Command::new("stdbuf")
        .args(["-oL", "-eL"])
        .arg(exe)
        .output()
        .unwrap_or_else(|e| panic!("run {example} on wz: {e}"));
    let printed = String::from_utf8_lossy(&out.stdout);
    assert!(
        !printed.contains("ERROR: Zenoh pico"),
        "{example} on wz took its feature-gated STUB branch, so the leg that \
         drives it is exercising a printf and no wz code at all.\n\
         --- stdout+stderr ---\n{printed}\n--- stderr ---\n{}",
        String::from_utf8_lossy(&out.stderr),
    );
}
