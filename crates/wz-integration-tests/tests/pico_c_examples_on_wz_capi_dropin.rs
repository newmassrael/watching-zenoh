// SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
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
//! link while calling nothing at all — `z_advanced_pub`, `z_advanced_sub`,
//! `z_pub_st`, `z_pub_tls`, `z_sub_st`, `z_sub_tls` compile to a `#else` stub
//! `main` because the CMake-generated feature set disagrees with what they
//! demand (`z_pub_st` and `z_sub_st` want `Z_FEATURE_MULTI_THREAD == 0`, and
//! the generated config has it at 1). `nm -u <obj> | grep z_open` separates
//! them from a real body. That is why this file names its examples explicitly
//! instead of sweeping a glob: a glob would have counted six vacuous passes.
//!
//! Census at this round, measured that way: NINE examples link with a real
//! body — `z_liveliness`, `z_ping`, `z_pong`, `z_put`, `z_queryable`,
//! `z_queryable_lat`, `z_sub`, `z_sub_liveliness`, `z_sub_thr` — 6 link as
//! stubs, 15 are still short of exports, and 2 are both. SIX of the nine are
//! legs below; `z_pong` is used as this file's own foreign counterparty rather
//! than as a subject, and `z_queryable_lat` / `z_sub_thr` link but are not yet
//! driven, which is recorded here rather than rounded up into the leg count.
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
    compile_pico_example_against_wz_capi, graceful_terminate, project_root, read_captured,
    spawn_zenohd_multicast_scouting_on_ephemeral_tcp, wait_for_capture_alive, wait_for_exit,
    wait_for_substring, wait_for_tcp_accept_alive, zenoh_pico_cli_binary, zenoh_pico_include_dirs,
    zenohd_binary, ChildGuard, PortReservation,
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
            .stderr(Stdio::null())
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
        .stderr(Stdio::null())
        .status()
        .expect("run the real zenoh-pico z_put");
    assert!(
        put.success(),
        "real zenoh-pico z_put exited {put:?}\n--- its stdout ---\n{}",
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
         ({key}); wz's inbound keyexpr resolution disagrees.\n--- stdout ---\n{captured}"
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
            .stderr(Stdio::null())
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
        .stderr(Stdio::null())
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
            .stderr(Stdio::null())
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
            .stderr(Stdio::null())
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
            .stderr(Stdio::null())
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
            .stderr(Stdio::null())
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
        .stderr(Stdio::null())
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
            .stderr(Stdio::null())
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
        .stderr(Stdio::null())
        .status()
        .expect("run the real zenoh-pico z_liveliness");
    assert!(
        token.success(),
        "real zenoh-pico z_liveliness exited {token:?}\n--- its stdout ---\n{}",
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
            .stderr(Stdio::null())
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
        .stderr(Stdio::null())
        .status()
        .expect("run upstream z_get.c on wz's C ABI");
    assert!(
        get.success(),
        "upstream z_get.c on wz's C ABI exited {get:?}\n--- its stdout ---\n{}",
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
            .stderr(Stdio::null())
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
        .stderr(Stdio::null())
        .status()
        .expect("run the real zenoh-pico z_sub");
    assert!(
        sub.success(),
        "real zenoh-pico z_sub exited {sub:?}\n--- its stdout ---\n{}",
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
    let expected_zid = router_log
        .split("ZID:")
        .nth(1)
        .and_then(|tail| tail.split_whitespace().next())
        .map(|s| s.trim().to_ascii_lowercase())
        .expect("zenohd's ZID line carries a value");
    assert_eq!(
        expected_zid.len(),
        32,
        "zenohd's self-reported zid is not 32 hex characters: {expected_zid:?}"
    );

    let mut info_out = tempfile::tempfile().expect("z_info stdout capture");
    let info_writer = info_out.try_clone().expect("dup z_info stdout handle");
    let info = Command::new("stdbuf")
        .args(["-oL", "-eL"])
        .arg(&dropin)
        .args(["-e", &endpoint, "-m", "client"])
        .stdout(Stdio::from(info_writer))
        .stderr(Stdio::null())
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
            .stderr(Stdio::null())
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
        .stderr(Stdio::null())
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
            .stderr(Stdio::null())
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
            .stderr(Stdio::null())
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
        "the real pico subscriber exited {status:?}\n--- its stdout ---\n{}",
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
            .stderr(Stdio::null())
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
        .stderr(Stdio::null())
        .status()
        .expect("run the compiled z_get_lat drop-in");
    let printed = read_captured(&mut lat_out);
    assert!(
        lat.success(),
        "z_get_lat.c on wz exited {lat:?} — a querier that never delivered a \
         reply BLOCKS in its load_loop, so a non-zero exit or a timeout here \
         means the querier plane did not round-trip.\n--- its stdout ---\n\
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
        "z_querier_get reported a transmit failure.\n--- stdout ---\n{printed}"
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
            .stderr(Stdio::null())
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

    let publisher = Command::new("stdbuf")
        .args(["-oL", "-eL"])
        .arg(&dropin)
        .args(["-e", &endpoint, "-m", "client", "-n", "2"])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .expect("run the compiled z_pub_attachment drop-in");
    assert!(
        publisher.success(),
        "z_pub_attachment.c on wz exited {publisher:?}"
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
        "the real pico subscriber exited {status:?}\n--- its stdout ---\n{}",
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
            .stderr(Stdio::null())
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
        .stderr(Stdio::null())
        .status()
        .expect("run the real zenoh-pico z_pub");
    assert!(
        published.success(),
        "real zenoh-pico z_pub exited {published:?}\n--- its stdout ---\n{}",
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
         publisher sends.\n--- stdout ---\n{captured}"
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
    let libdir = root.join("target/zenoh-pico-build/lib");
    assert!(
        libdir.join("libzenohpico.so").is_file(),
        "the REAL zenoh-pico shared library is missing at {}; run \
         scripts/build-zenoh-pico-cli.sh first (it is the CMake build product \
         this oracle compares against)",
        libdir.display()
    );
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
fn hello_line_for_port(printed: &str, port: u16) -> Option<&str> {
    let needle = format!("tcp/127.0.0.1:{port}");
    printed
        .lines()
        .find(|l| l.starts_with("Hello {") && l.contains(&needle))
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
/// It also pins the DEDUPE. wz drives discovery in cycles and a live responder
/// answers every cycle, so a cursor over the recorded hellos reports one peer
/// once per cycle; the oracle prints exactly one line, and so must wz.
///
/// The name carries `zenohd` deliberately: Layer E's sweep skips that token
/// because it provisions no router, so this leg is registered by exact name in
/// Layer Z, which does. Renaming to dodge the token would make Layer E red on
/// every machine without zenohd.
// wz-proves: api-compat-pico wz-vs-pico full
#[test]
#[ignore = "spawns a real zenohd and two cc-compiled binaries; run by run-ci Layer Z"]
fn pico_zscout_source_on_wz_capi_matches_the_real_pico_against_a_zenohd() {
    let dir = tempfile::tempdir().expect("tempdir for the compiled binaries");
    let dropin = dropin_binary("z_scout", dir.path());
    let oracle = oracle_binary("z_scout", dir.path());

    // A zenohd with its DEFAULT multicast scouting responder; the spawn gates
    // on zenohd's own scout-listener line, so the group socket is bound and
    // joined before either scout emits (nothing retransmits a lost Scout).
    let (mut zenohd, port) =
        spawn_zenohd_multicast_scouting_on_ephemeral_tcp("zenohd (multicast-scouting router)");

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
            "the REAL zenoh-pico z_scout did not discover the zenohd on \
             tcp/127.0.0.1:{port} — multicast scouting is not working on this host, \
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
    let wz_hits = wz_printed
        .lines()
        .filter(|l| l.starts_with("Hello {") && l.contains(&format!("tcp/127.0.0.1:{port}")))
        .count();
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
            .stderr(Stdio::null())
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
         publisher used ({key}).\n--- stdout ---\n{captured}"
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
            .stderr(Stdio::null())
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
        .stderr(Stdio::null())
        .status()
        .expect("run the real zenoh-pico z_get");
    assert!(
        get.success(),
        "real zenoh-pico z_get exited {get:?}\n--- its stdout ---\n{}",
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
         line, so the query did not travel through `z_recv`.\n--- stdout ---\n{responder}"
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
        "upstream z_bytes.c on the REAL zenoh-pico exited {:?}\n--- stdout ---\n{}\
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
            .stderr(Stdio::null())
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
            .stderr(Stdio::null())
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
         under.\n--- stdout ---\n{detected}"
    );
    assert!(
        captured.contains(key),
        "the sample arrived but not on the key the foreign advanced publisher \
         used ({key}).\n--- stdout ---\n{captured}"
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
            .stderr(Stdio::null())
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
             publish window below would not be bounded.\n--- stdout ---\n{}",
            read_captured(&mut sub_out)
        );
    }

    for idx in 1..=4 {
        let payload = format!("EVICT-{idx}");
        let put = Command::new("stdbuf")
            .args(["-oL", "-eL"])
            .arg(&z_put)
            .args(["-e", &endpoint, "-m", "client", "-k", key, "-v", &payload])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .expect("run the real zenoh-pico z_put");
        assert!(put.success(), "real zenoh-pico z_put #{idx} exited {put:?}");
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
         --- stdout ---\n{captured}"
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
            .stderr(Stdio::null())
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
         than {key}.\n--- stdout ---\n{foreign}"
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
/// discovers a liveliness token declared by the REAL zenoh-pico `z_liveliness`.
///
/// The one-shot snapshot half of the presence plane, and the leg that gives
/// `z_liveliness_get` a foreign witness: the token is declared by upstream's
/// own binary, and the reply stream that carries it back is wz's CURRENT
/// Interest, not a query.
// wz-proves: api-compat-pico pico->wz partial
#[test]
#[ignore = "spawns the real zenoh-pico z_liveliness CLI and a cc-compiled \
            binary; run by run-ci Layer E"]
fn pico_zgetliveliness_source_on_wz_capi_sees_a_real_pico_token() {
    let dir = tempfile::tempdir().expect("tempdir for the compiled drop-in");
    let dropin = dropin_binary("z_get_liveliness", dir.path());
    let z_liveliness = zenoh_pico_cli_binary("z_liveliness");

    let reservation = PortReservation::pick();
    let port = reservation.port();
    let endpoint = format!("tcp/127.0.0.1:{port}");
    let key = "demo/dropin/leg24";

    let mut tok_out = tempfile::tempfile().expect("foreign token capture");
    let writer = tok_out.try_clone().expect("dup foreign token handle");
    let mut token = ChildGuard::wrap(
        "real zenoh-pico z_liveliness",
        Command::new("stdbuf")
            .args(["-oL", "-eL"])
            .arg(&z_liveliness)
            .args(["-l", &endpoint, "-m", "peer", "-k", key])
            .stdout(Stdio::from(writer))
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn the real zenoh-pico z_liveliness"),
    );

    if let Err(why) = wait_for_tcp_accept_alive(token.child_mut(), port, LISTEN_TIMEOUT) {
        panic!(
            "the real zenoh-pico z_liveliness never accepted on {endpoint} — {why}; \
             capture so far:\n{}",
            read_captured(&mut tok_out)
        );
    }
    drop(reservation);

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
         --- REAL pico z_liveliness stdout ---\n{}",
        read_captured(&mut tok_out)
    );

    graceful_terminate(token.child_mut(), Duration::from_secs(5));
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
            .stderr(Stdio::null())
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
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn the real zenoh-pico z_get_attachment");
    let get = bounded_exit("real pico z_get_attachment", get, &mut get_out);
    let foreign = read_captured(&mut get_out);
    let responder = read_captured(&mut qbl_out);
    assert!(
        get.success(),
        "real zenoh-pico z_get_attachment exited {get:?}\n--- its stdout ---\n{foreign}"
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
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn the real zenoh-pico z_get_lat");
    let lat = bounded_exit("real pico z_get_lat", lat, &mut lat_out);
    let foreign = read_captured(&mut lat_out);
    let responder = read_captured(&mut qbl_out);
    assert!(
        lat.success(),
        "real zenoh-pico z_get_lat exited {lat:?} — a queryable that never replied \
         stalls it.\n--- its stdout ---\n{foreign}\n\
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
            .stderr(Stdio::null())
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
            .stderr(Stdio::null())
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

/// LEG 32 (`ABI-model gate`) — `z_pong.c` is the one program of the 32 that
/// cannot be driven, and the reason is not a missing export or a feature flag.
///
/// Its callback does not use the API at all:
///
/// ```c
/// void callback(z_loaned_sample_t* sample, void* context) {
///     const z_loaned_publisher_t* pub = z_loan(*(z_owned_publisher_t*)context);
///     z_owned_bytes_t payload = {._val = sample->payload};
///     z_publisher_put(pub, z_move(payload), NULL);
/// }
/// ```
///
/// `sample->payload` reads a FIELD of pico's concrete `_z_sample_t` at pico's
/// offset, and `{._val = ...}` writes a field of pico's concrete
/// `z_owned_bytes_t`. Neither goes through `z_sample_payload` or any exported
/// function. This crate's drop-in contract is the exported SYMBOLS plus the
/// owned-struct SIZES — a loaned sample is an opaque handle, deliberately (see
/// [`crate`]'s sibling accessors) — so a program that dereferences pico's
/// internal layout is reading wz's marshal as if it were `_z_sample_t`.
///
/// Reproducing the layout would not be enough either, and that is worth stating
/// because it is the part that looks close: the C code COPIES the payload
/// struct by value and then `z_move`s it into `z_publisher_put`, which consumes
/// it. wz's bytes handle is a `Box`, so a by-value copy that is later consumed
/// is a double free. pico survives it because `_z_bytes_t` is a refcounted
/// arc-slice vector; matching that means reimplementing pico's internal slice
/// allocator, not widening a struct.
///
/// Measured, not assumed: the real `z_ping` against this program on wz
/// completes ZERO of its round trips and then sits until killed. The reverse
/// direction IS driven and passes — `z_ping.c` on wz against the real `z_pong`
/// is the leg above, and `z_ping.c` touches no internals.
///
/// So this gate asserts the REASON, and fires if upstream ever rewrites the
/// callback in terms of the API — at which point the real leg becomes writable
/// and should replace this one.
// wz-proves: api-compat-pico pico->wz partial
#[test]
#[ignore = "reads upstream z_pong.c; run by run-ci Layer E"]
fn pico_zpong_dereferences_pico_internals_and_so_cannot_be_driven() {
    let src = project_root().join("vendor/zenoh-pico/examples/unix/c11/z_pong.c");
    let text = std::fs::read_to_string(&src)
        .unwrap_or_else(|e| panic!("cannot read {}: {e}", src.display()));
    // Both halves of the bypass, asserted separately so a partial rewrite is
    // not read as the whole one.
    assert!(
        text.contains("sample->payload"),
        "upstream z_pong.c no longer reads `sample->payload` directly. If its \
         callback now uses `z_sample_payload`, this program is drivable on wz \
         and this gate must be replaced by a real leg (a wz z_pong echoing the \
         REAL zenoh-pico z_ping).\n--- {} ---\n{text}",
        src.display()
    );
    assert!(
        text.contains("._val = sample->payload"),
        "upstream z_pong.c no longer builds its `z_owned_bytes_t` by writing \
         pico's internal `_val` field. See this gate's doc: the by-value copy \
         plus `z_move` is the half that makes a layout match insufficient.\n\
         --- {} ---\n{text}",
        src.display()
    );
}

/// LEG 31 (`configuration gate`) — FOUR of the 32 have NO body to drive at
/// this pin, and this leg exists to say which, and to fire when that stops
/// being true.
///
/// `z_pub_tls.c`, `z_sub_tls.c`, `z_pub_st.c` and `z_sub_st.c` are the
/// remainder without a driven leg, and the reason is not a missing wz export.
/// Each guards its whole `main` on a `Z_FEATURE_*` combination the pinned
/// CMake-generated config does not have — TLS wants `Z_FEATURE_LINK_TLS == 1`
/// (the config has 0) and the single-threaded pair wants
/// `Z_FEATURE_MULTI_THREAD == 0` (the config has 1) — so all four compile to a
/// `#else` branch whose entire body is one `printf`. Measured two independent
/// ways: by running each binary (it prints its `ERROR: Zenoh pico ...` line and
/// exits without reaching `z_open`) and by reading the `#if` at the top of each
/// source. A leg that drove them would exercise zero wz code, which is the
/// definition of a vacuous proof.
///
/// The single-threaded pair is worth naming separately, because it is the one
/// place a reader might expect wz to have a gap and it does not: wz's session
/// SELF-DRIVES, so `zp_start_read_task` and friends are documented no-ops here.
/// A `zp_spin_once` build would need `Z_FEATURE_MULTI_THREAD == 0` in the
/// header set, which is a different pico build, not a different wz export.
///
/// So this asserts the CONFIGURATION instead, and it is written to be
/// self-retracting: the moment the pinned pico build turns TLS on, the header
/// check below reds and whoever moved the pin is told to write the two real
/// legs. That is the point — an exclusion that names its own re-open trigger
/// costs one test and cannot quietly outlive its reason.
///
/// Note what the fix is NOT. Rebuilding pico with TLS on is not a local change:
/// the `Z_FEATURE_*` set decides several owned struct SIZES, and wz's cdylib is
/// built for the CURRENT set. A second, TLS-enabled header tree would need a
/// second cdylib arm to link against, which is the same hazard run-ci's Layer
/// C1cc already manages for the zenoh-c ABI.
// wz-proves: api-compat-pico pico->wz partial
#[test]
#[ignore = "reads the CMake-generated pico config and runs two stub binaries; \
            run by run-ci Layer E"]
fn pico_zfeature_gated_examples_are_stub_mains_at_this_pin_and_say_so() {
    let dir = tempfile::tempdir().expect("tempdir for the compiled drop-ins");
    // The generated config is the SSOT for what these programs compiled to —
    // not the CMakeLists default, which R311y466 recorded as the trap.
    let generated = zenoh_pico_include_dirs()[0].join("zenoh-pico/config.h");
    let config = std::fs::read_to_string(&generated)
        .unwrap_or_else(|e| panic!("cannot read {}: {e}", generated.display()));
    for (feature, expected) in [
        ("Z_FEATURE_LINK_TLS", "#define Z_FEATURE_LINK_TLS 0"),
        ("Z_FEATURE_MULTI_THREAD", "#define Z_FEATURE_MULTI_THREAD 1"),
    ] {
        assert!(
            config.contains(expected),
            "the pinned zenoh-pico build's {feature} changed, so the examples \
             guarded on it now have a real body and this leg must be replaced by \
             DRIVEN legs for them. See this test's doc for why the cdylib arm \
             matters.\n--- {} ---\n{}",
            generated.display(),
            config
                .lines()
                .filter(|l| l.contains("Z_FEATURE_LINK_TLS")
                    || l.contains("Z_FEATURE_MULTI_THREAD"))
                .collect::<Vec<_>>()
                .join("\n"),
        );
    }

    for example in ["z_pub_tls", "z_sub_tls", "z_pub_st", "z_sub_st"] {
        let exe = dropin_binary(example, dir.path());
        let out = Command::new("stdbuf")
            .args(["-oL", "-eL"])
            .arg(&exe)
            .output()
            .unwrap_or_else(|e| panic!("run {example} on wz: {e}"));
        let printed = String::from_utf8_lossy(&out.stdout);
        assert!(
            printed.contains("ERROR: Zenoh pico"),
            "{example} on wz did NOT take its feature-gated stub branch, so it \
             has a body after all and owes a driven leg.\n--- stdout ---\n{printed}\
             \n--- stderr ---\n{}",
            String::from_utf8_lossy(&out.stderr),
        );
    }
}
