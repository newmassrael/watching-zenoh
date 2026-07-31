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
//! Both legs below therefore hand the checking to artifacts wz does not own:
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
//! At this round the real-body linkers are `z_sub`, `z_queryable` and `z_put`
//! — the three legs below — with 21 examples still short of exports and 2 more
//! that are stubs AND short.
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
//! All three claims are `partial`, and deliberately: the atom covers 150 of
//! pico's 726 declared functions, and three programs are three programs. What
//! is proven is that the drop-in is REAL for the paths those programs exercise
//! — inbound samples, queryable replies, and a declared-keyexpr publish —
//! compiled and linked the way a pico user would.

use std::process::{Command, Stdio};
use std::time::Duration;

use wz_integration_tests::common::{
    compile_pico_example_against_wz_capi, graceful_terminate, read_captured, wait_for_substring,
    wait_for_tcp_accept, zenoh_pico_cli_binary, ChildGuard, PortReservation,
};

/// How long a compiled drop-in gets to bind its listener. Generous relative to
/// the sub-100 ms observed path: the gate is a TCP connect, so a slow bind
/// costs only latency here, never a false PASS.
const LISTEN_TIMEOUT: Duration = Duration::from_secs(10);
/// How long the foreign CLI gets to complete its exchange and EXIT.
///
/// Exit is load-bearing, not incidental. Both witnesses are read from a C
/// program's `printf` output captured to a file, where libc is block-buffered —
/// so the bytes are only guaranteed on the file after the process flushes at
/// exit. Every leg below is therefore driven by a self-terminating invocation
/// (`-n 1` for the subscriber, a one-shot `z_get`) and asserts on the capture
/// AFTER the wait, rather than polling a partially-flushed buffer.
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
        Command::new(&dropin)
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

    assert!(
        wait_for_tcp_accept(port, LISTEN_TIMEOUT),
        "the z_sub.c drop-in never accepted on {endpoint}; capture so far:\n{}",
        read_captured(&mut sub_out)
    );
    drop(reservation);

    let put = Command::new(&z_put)
        .args(["-e", &endpoint, "-m", "client", "-k", key, "-v", payload])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .expect("run the real zenoh-pico z_put");
    assert!(put.success(), "real zenoh-pico z_put exited {put:?}");

    // The subscriber self-terminates on its first sample; wait for that exit so
    // the capture is complete, then assert.
    let captured =
        wait_for_substring(&mut sub_out, payload, EXCHANGE_TIMEOUT).unwrap_or_else(|captured| {
            panic!(
                "upstream z_sub.c running on wz's C-ABI never reported the payload \
                 published by the REAL zenoh-pico z_put.\nexpected substring: {payload}\n\
                 --- z_sub.c (on wz) stdout ---\n{captured}"
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
        Command::new(&dropin)
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

    assert!(
        wait_for_tcp_accept(port, LISTEN_TIMEOUT),
        "the z_queryable.c drop-in never accepted on {endpoint}; capture so far:\n{}",
        read_captured(&mut qable_out)
    );
    drop(reservation);

    // A one-shot `z_get`: it prints its replies and the final notification, then
    // exits — which is what flushes its capture.
    let mut get_out = tempfile::tempfile().expect("z_get stdout capture");
    let get_writer = get_out.try_clone().expect("dup z_get stdout handle");
    let get = Command::new(&z_get)
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
        Command::new(&z_sub)
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

    assert!(
        wait_for_tcp_accept(port, LISTEN_TIMEOUT),
        "the real zenoh-pico z_sub never accepted on {endpoint}; capture so far:\n{}",
        read_captured(&mut sub_out)
    );
    drop(reservation);

    let put = Command::new(&dropin)
        .args(["-e", &endpoint, "-m", "client", "-k", key, "-v", payload])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .expect("run the compiled z_put drop-in");
    // A non-zero exit is itself a finding: upstream returns -1 when
    // `z_declare_keyexpr` fails, so this catches a declaration that never
    // happened before the subscriber assertion can mask it as a lost sample.
    assert!(
        put.success(),
        "upstream z_put.c on wz's C-ABI exited {put:?} — it returns -1 when \
         z_open, z_view_keyexpr_from_str or z_declare_keyexpr fails"
    );

    let foreign =
        wait_for_substring(&mut sub_out, payload, EXCHANGE_TIMEOUT).unwrap_or_else(|captured| {
            panic!(
                "the REAL zenoh-pico z_sub never received the declared-keyexpr put \
                 that upstream's z_put.c issued while running on wz's C-ABI.\n\
                 expected substring: {payload}\n--- REAL pico z_sub stdout ---\n{captured}"
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
