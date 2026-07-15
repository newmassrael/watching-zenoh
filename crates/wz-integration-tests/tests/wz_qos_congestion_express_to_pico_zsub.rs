// SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! R311y242 — FOREIGN-INTEROP Put CONGESTION + EXPRESS: a watching-zenoh
//! publisher emits a `Put` carrying a non-default qos byte (congestion
//! `Block` + `express` set), and a real zenoh-pico `z_sub_attachment` CLI
//! decodes it and prints `with congestion: 1` + `with express: 1`.
//!
//! ## The gap this closes (the named R311y240 follow-up)
//!
//! The Push outer QoS ext packs three sub-fields into ONE byte: priority
//! (low 3 bits) + congestion-control (bit 3, `nodrop`) + express (bit 4).
//! R311y240 (`wz_priority_to_pico_zsub`) proved the PRIORITY sub-field
//! wz->pico via pico's `z_sample_priority`, but left congestion + express
//! unproven. That round's scope note deferred them with the claim
//! "congestion has no per-sample getter; express is a batching-only
//! effect" — a claim that is FALSE on direct read of the vendor pin:
//! `zenoh-pico/include/zenoh-pico/api/primitives.h` declares BOTH
//! `z_sample_congestion_control` (line ~2255) and `z_sample_express`
//! (line ~2266), and `src/api/api.c` implements them as
//! `_z_n_qos_get_congestion_control(sample->qos)` /
//! `_z_n_qos_get_express(sample->qos)` — reading the SAME `sample->qos`
//! byte that y240 already proved is wire-populated. So both sub-fields
//! ARE foreign-observable; this test closes the remaining two.
//!
//! ## Scope — R311y312: the WHOLE qos byte, i.e. the whole `pubsub-qos` atom
//!
//! wz emits the whole packed byte in one ext (`build_push_outer_extensions`
//! writes `q.raw` — no sub-field masking), so all three sub-fields ride the
//! wire together. This test needs NO send-path change; it only sets the bits
//! and reads them back through pico's public getters.
//!
//! R311y312 widened the scope from "congestion + express" to all three, and
//! this file's proof claims below moved from the three per-field atoms onto
//! `pubsub-qos`. Two reasons, both structural:
//!
//! 1. R311y307 MERGED the three former per-field features into the single
//!    `pubsub-qos` atom, because one byte behind one gate is one compile unit.
//!    The three survive only as elidable cargo ALIASES with zero cfg sites of
//!    their own, so a proof claimed against them binds to no gated code. (This
//!    doc used to say the ext was "gated on `any(pubsub-priority /
//!    pubsub-congestion-control / pubsub-express)`" — that was the pre-y307
//!    union the merge dissolved, left stale here.)
//! 2. Partial claims never aggregate (`full = set(proven_full)`;
//!    `partial = proven_partial - full`), so splitting the byte's proof across
//!    two tests capped `pubsub-qos` at `partial` permanently. Asserting all
//!    three sub-fields in ONE test is what makes the claim FULL — and it is
//!    honest exactly because they share one byte: witnessing that byte
//!    round-trip through pico IS witnessing the atom.
//!
//! Note the honest limit, unchanged: this witnesses the express BIT's foreign
//! decode, NOT express's batching-flush SEMANTICS (a sender-side tx behaviour
//! with no receiver-observable proxy) — that effect is the independent
//! `transport-batching` axis.
//!
//! ## Why `Block`(1) + `express`(1) and not the default
//!
//! pico's default sample qos is `_Z_N_QOS_DEFAULT._val = 5`
//! (`src/protocol/definitions/network.c` 22) = priority `Data`(5), congestion
//! `DROP`(0), express `false`(0). `z_sample_congestion_control` returns
//! `Z_CONGESTION_CONTROL_BLOCK = 1` / `Z_CONGESTION_CONTROL_DROP = 0`
//! (`api/constants.h`), and `z_sample_express` returns the bit-4 boolean. If
//! wz DROPPED the qos byte on the wire, pico would decode the default and
//! print `with congestion: 0` + `with express: 0`. wz's
//! `build_push_outer_extensions` SUPPRESSES the ext when the byte equals
//! `QosLevel::DEFAULT` (0x05); `QosLevel::from_parts(Data, Block, true)` packs
//! to 0x1D (`5 | 1<<3 | 1<<4`), which is != DEFAULT, so the ext IS emitted and
//! pico decodes congestion `1` + express `1`. So `with congestion: 1` +
//! `with express: 1` genuinely discriminate "propagated" from "dropped"
//! (which prints the default `0`/`0`) — the same discriminating shape as the
//! y240 priority witness (`RealTime`(1) vs the default `5`).
//!
//! ## The witness
//!
//! `scripts/build-zenoh-pico-cli.sh` build-time-patches `z_sub_attachment.c`
//! to print `with priority:` / `with congestion:` / `with express:` (the same
//! in-place patch y240 introduced, extended to all three getters; documented
//! in THIRD_PARTY.md, reverted on exit by the shared trap). The qos byte is
//! set via `PublishOptions::with_qos(QosLevel::from_parts(..))`, the typed
//! packer that already exists — no new publish API is needed (congestion +
//! express carry no transport-conduit-band role, unlike priority, so they
//! need no `with_priority`-style single-source setter).
//!
//! ## Harness shape
//!
//! Mirrors `wz_priority_to_pico_zsub.rs` (in-test wz acceptor +
//! `Session::publish` over the accepted session, `select!` drive-vs-scenario,
//! pico CLI dial-in with accept-retry + a subscriber-declared readiness gate +
//! a 150 ms republish cadence). The only deltas: the `with_qos` publish and
//! the `with congestion: 1` + `with express: 1` assertions.

use std::process::{Command, Stdio};
use std::sync::Arc;
use std::time::{Duration, Instant};

use tokio::net::TcpListener;

use wz_integration_tests::common::{read_captured, zenoh_pico_cli_binary, ChildGuard};
use wz_runtime_tokio::observer::ApplicationLayerObserver;
use wz_runtime_tokio::runtime_impl::TokioTime;
use wz_runtime_tokio::session::{PublishOptions, TokioSession};
use wz_runtime_tokio::session_glue::drive_session_until_terminal;
use wz_runtime_tokio::session_open::{accept_and_open_session, DialedLink, DEFAULT_OPEN_TICK_MS};
use wz_runtime_tokio::sync::Mutex;
use wz_runtime_tokio_test_support::fixture_session_init_params;
use wz_session_core::qos::{CongestionControl, Priority};
use wz_session_core::sample::QosLevel;
use wz_session_core::session_timeouts::SessionTimeouts;

const ITER_CAP: usize = 4096;
const PUBLISH_KEYEXPR: &str = "demo/qos";
const SUB_KEYEXPR: &str = "demo/**";
const PAYLOAD: &str = "qos-metadata-hello-from-wz";

// wz-proves: pubsub-qos wz->pico
// wz-proves: pubsub-put wz->pico
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "binary-dep e2e (zenoh-pico CLI z_sub_attachment); Layer E runs via --ignored"]
async fn wz_put_congestion_express_decoded_by_pico_zsub_attachment() {
    let z_sub = zenoh_pico_cli_binary("z_sub_attachment");

    // wz acceptor binds first so pico's client dial lands in the listen
    // backlog and `accept()` resolves it.
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind wz acceptor");
    let addr = listener.local_addr().expect("local_addr");
    let endpoint = format!("tcp/{addr}");

    // Accept + handshake WITH RETRY (same rationale as wz_priority_to_pico_zsub):
    // pico's one-shot open transient must be a retry, not a red build. The
    // common case succeeds on attempt 1.
    const OPEN_ATTEMPTS: usize = 6;
    let established = {
        let mut acc = None;
        for attempt in 1..=OPEN_ATTEMPTS {
            let z_sub_stdout = tempfile::tempfile().expect("tempfile for z_sub stdout");
            let z_sub_stdout_writer = z_sub_stdout.try_clone().expect("dup z_sub stdout handle");
            let z_sub_stdout_reader = z_sub_stdout;
            let mut z_sub_child = ChildGuard::wrap(
                "z_sub_attachment client (zenoh-pico)",
                Command::new("stdbuf")
                    .args(["-oL", "-eL"])
                    .arg(&z_sub)
                    .args(["-k", SUB_KEYEXPR, "-e", &endpoint, "-m", "client"])
                    .stdout(Stdio::from(z_sub_stdout_writer))
                    .stderr(Stdio::inherit())
                    .spawn()
                    .expect("spawn z_sub_attachment via stdbuf"),
            );
            let accepted = tokio::time::timeout(Duration::from_secs(8), listener.accept()).await;
            let stream = match accepted {
                Ok(Ok((stream, _peer))) => stream,
                _ => {
                    let _ = z_sub_child.child_mut().kill();
                    let _ = z_sub_child.child_mut().wait();
                    eprintln!(
                        "attempt {attempt}/{OPEN_ATTEMPTS}: pico did not connect within 8s; retrying"
                    );
                    continue;
                }
            };
            // Default (non-fragmenting) batch: a small Put stays one frame; the
            // proof is the decoded qos byte, not fragmentation.
            let params = fixture_session_init_params();
            match accept_and_open_session(
                DialedLink::Tcp(stream),
                params,
                TokioTime::new(),
                Some(ITER_CAP),
                DEFAULT_OPEN_TICK_MS,
            )
            .await
            {
                Ok(opened) => {
                    acc = Some((opened, z_sub_child, z_sub_stdout_reader));
                    break;
                }
                Err(e) => {
                    let _ = z_sub_child.child_mut().kill();
                    let _ = z_sub_child.child_mut().wait();
                    eprintln!(
                        "attempt {attempt}/{OPEN_ATTEMPTS}: wz<->pico handshake failed ({e:?}); retrying"
                    );
                    continue;
                }
            }
        }
        acc.expect(
            "wz acceptor reached Established against a pico z_sub_attachment client within OPEN_ATTEMPTS",
        )
    };
    let (mut opened, mut z_sub_child, mut z_sub_stdout_reader) = established;

    // Publisher over the accepted session's actions (Arc-shared); the drive
    // loop below borrows `&opened.actions`, the publisher holds an independent
    // Arc clone.
    let publisher = TokioSession::new(
        opened.actions.clone(),
        Arc::new(Mutex::new(ApplicationLayerObserver::new())),
        Arc::new(opened.clock),
    );

    let timeouts = SessionTimeouts::spec_defaults();
    let mut observer = ApplicationLayerObserver::new();
    let drive = drive_session_until_terminal(
        &mut opened.inbound,
        &opened.actions,
        &mut opened.engine,
        None,
        &opened.clock,
        &timeouts,
        |event| observer.dispatch_event(event),
    );

    let received_witness = ">> [Subscriber] Received";
    // congestion `Block` = 1, express = 1; a dropped qos byte would print the
    // default `0`/`0`, so the exact lines discriminate propagated from dropped.
    let congestion_witness = "with congestion: 1";
    let express_witness = "with express: 1";
    let subscribed_witness = "Declaring Subscriber on";
    // R311y312 — priority is now `RealTime` (1) and asserted here too, so this
    // ONE test witnesses ALL THREE sub-fields of the single qos byte.
    //
    // It used to pin `Data` (5) deliberately, "so the qos byte's discrimination
    // is on the congestion + express bits alone; the priority sub-field is
    // R311y240's witness, not this test's". That division of labour mapped onto
    // three per-field ATOMS. R311y307 merged them: the byte is ONE atom
    // (`pubsub-qos`) because it is ONE gate. A per-field split of the proof no
    // longer maps onto anything in the catalog, and it capped the merged atom at
    // `partial` forever -- partial claims never aggregate (`full =
    // set(proven_full)`, `partial = proven_partial - full`), so N partials never
    // promote to a proof of the whole byte. Asserting all three here is what
    // makes the claim FULL, and it is honest precisely because one byte carries
    // all three: witnessing 0x01|0x08|0x10 round-trip through pico IS witnessing
    // the atom.
    //
    // `RealTime`(1) is the discriminating choice, for the reason
    // wz_priority_to_pico_zsub.rs states: `Data`(5) is pico's own default, so it
    // would print 5 whether or not propagation works -- a tautology. wz's
    // `Priority::wire_byte()` is 1:1 with pico's `z_priority_t`, so a propagated
    // RealTime prints 1 and a dropped byte prints the default 5.
    let priority_witness = "with priority: 1";
    let qos = QosLevel::from_parts(Priority::RealTime, CongestionControl::Block, true);
    let scenario = async {
        // Gate the delivery budget on pico's subscriber-declared witness
        // before publishing (no-flaky; pico open latency does not eat the
        // delivery deadline). The drive loop keeps the session alive.
        let ready_deadline = Instant::now() + Duration::from_secs(10);
        loop {
            let captured = read_captured(&mut z_sub_stdout_reader);
            if captured.contains(subscribed_witness) {
                break;
            }
            if Instant::now() >= ready_deadline {
                return Err(format!(
                    "pico z_sub_attachment did not declare its subscriber within 10s.\n\
                     --- captured stdout ---\n{captured}"
                ));
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        // Republish the Block+express Put on a 150 ms cadence until pico prints
        // the payload AND both `with congestion: 1` and `with express: 1`
        // (idempotent, byte-identical — one landing after the subscription is
        // installed suffices; not flaky-masking retry).
        let deadline = Instant::now() + Duration::from_secs(12);
        loop {
            publisher
                .publish(
                    PUBLISH_KEYEXPR,
                    PAYLOAD.as_bytes(),
                    PublishOptions::put().with_qos(qos),
                )
                .expect("qos-metadata publish builds and routes through the send seam");
            tokio::time::sleep(Duration::from_millis(150)).await;
            let captured = read_captured(&mut z_sub_stdout_reader);
            if captured.contains(received_witness)
                && captured.contains(PAYLOAD)
                && captured.contains(priority_witness)
                && captured.contains(congestion_witness)
                && captured.contains(express_witness)
            {
                return Ok(());
            }
            if Instant::now() >= deadline {
                return Err(format!(
                    "pico z_sub_attachment did not decode wz's RealTime+Block+express Put \
                     within 12s.\n\
                     Expected '{received_witness}' + payload '{PAYLOAD}' + \
                     '{priority_witness}' + '{congestion_witness}' + '{express_witness}' \
                     (a dropped qos byte would print the defaults 'with priority: 5' + \
                     'with congestion: 0' + 'with express: 0').\n\
                     --- captured stdout ---\n{captured}"
                ));
            }
        }
    };

    let result = tokio::select! {
        _ = drive => panic!(
            "wz drive loop reached a terminal state before pico decoded the qos-metadata Put"
        ),
        r = scenario => r,
    };

    let _ = z_sub_child.child_mut().kill();
    let _ = z_sub_child.child_mut().wait();

    if let Err(msg) = result {
        panic!("wz->pico Put-congestion/express interop FAILED.\n{msg}");
    }
}
