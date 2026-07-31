// SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! AP-FULL <-> real zenoh-pico ADVANCED-PUBSUB interop (R311y488).
//!
//! ## The claim this file retires
//!
//! "zenoh-pico has no advanced-pubsub plane whatsoever."
//!
//! That sentence is in `wz_advanced_pubsub_zenoh_ext_interop.rs`'s module doc,
//! and a second copy is the reason `scripts/lib/crossimpl_corpus.py`'s
//! `KIND_CLASS` maps the advanced plane to `zenoh-ext` alone. It is FALSE. The
//! vendored tree ships `examples/unix/c11/z_advanced_pub.c` and
//! `z_advanced_sub.c`, and `CMakeLists.txt:319/321` carry
//! `Z_FEATURE_ADVANCED_PUBLICATION` / `_SUBSCRIPTION`.
//!
//! What was true is narrower and was never measured: those knobs DEFAULT TO 0,
//! `scripts/build-zenoh-pico-cli.sh` did not set them, and each example's
//! `#else` arm is a stub `main` that prints "ERROR: Zenoh pico was compiled
//! without ..." and exits -2. So every advanced example in this tree WAS a stub
//! — a build fact, read as a zenoh-pico fact, for as long as the claim stood.
//! The build script now sets both to `1` (not `ON`; see its own comment on why
//! that difference is silent) and ASSERTS the generated `config.h` agrees.
//!
//! ## Why this file needed a PRESET change to exist
//!
//! `wz/preset-ap-full` omitted the whole `ext-pubsub-*` family, and
//! `wz-ap-demo`'s mirror key held back `advanced` / `group` BECAUSE the library
//! preset omitted their atoms. So the AP-full binary compiled no advanced plane:
//! `--advanced-publish` logged INERT and declared no cache. Measured before the
//! change, from the demo's own first line:
//!
//! ```text
//! wz-ap-demo: BUILD FEATURES = [locator-iface query-attachment quic ... ws]
//! ```
//!
//! — no `advanced`. Every leg below asserts that word IS present, which is this
//! file's build discriminator: on the pre-y488 preset they fail at that
//! assertion with the feature list in the message, rather than timing out on a
//! marker and reading like a wire defect. That is the R311y481 trap
//! (`target/debug/wz-ap-demo` is ONE path many feature sets are written over)
//! closed by construction rather than by remembering.
//!
//! ## THE ORDERING TRAP that shaped both legs
//!
//! The first draft was a two-process fixture: an AP-full `--listen` node with
//! `--advanced-publish`, then a pico `z_advanced_sub`. It PASSED, and it proved
//! nothing about history, because the demo's advanced burst is triggered by a
//! session reaching Established — not by startup. MEASURED directly: with
//! `--listen ... --advanced-publish --advanced-publish-count 5` and no peer, the
//! process logs ZERO `ADVANCED PUT` lines at T+3s; the moment a pico client
//! attaches, all seven advanced lines appear. So in that topology every sample
//! necessarily POST-dates pico's session, and a live delivery is
//! indistinguishable from a cache recovery. The passing run was consistent with
//! both.
//!
//! What caught it was the fixture asserting its own precondition
//! (`ADVANCED BURST COMPLETE` read before pico is spawned) instead of arranging
//! it by sleep and trusting the arrangement. Both legs therefore put the cache
//! holder behind a `--peer` HUB and attach the asking side as a second client,
//! which is the only topology where "the cache was full before the asker
//! existed" is a fact the fixture can hold.
//!
//! ## The two legs
//!
//! 1. **wz ANSWERS a real pico** (hub + wz `--advanced-publish` client + pico
//!    `z_advanced_sub`). wz's cache is full and serving before the pico process
//!    starts, so pico's startup `@adv` history GET is the only path its samples
//!    could arrive by.
//! 2. **wz ASKS a real pico** (hub + pico `z_advanced_pub` + wz
//!    `--advanced-subscribe` client). Same direction as leg 1 of the zenoh-ext
//!    file, but the foreign cache is zenoh-pico's — a different implementation
//!    of the same replier contract.
//!
//! Both cross the AP-full PEER between two of its clients, so they also witness
//! that the composed peer routes the `@adv` QUERY plane and not only pushes — a
//! peer that forwards pushes but not queries reds them while leaving E9's
//! two-pico push leg green.
//!
//! ## WHICH code this binds to — established by damage, not by reading
//!
//! Four damages were run against these legs. Recorded because two of the four
//! refuted what was expected of them:
//!
//! * `KE_ADV_PREFIX` `@adv` -> `@advX` (`wz-runtime-tokio/src/advanced_ke.rs`)
//!   reds BOTH legs. This is the wire discriminator: the `@adv` namespace is
//!   what wz's cache queryable is declared under and what pico's
//!   `_Z_KEYEXPR_ADV_PREFIX` addresses, and no leg here can pass while the two
//!   disagree.
//! * `advanced` removed from `wz-ap-demo`'s `preset-ap-full` reds both in ~0.15s
//!   at `assert_advanced_was_built`, naming the feature list — the BUILD
//!   discriminator, and the reason that assertion runs before any wire wait.
//! * `ANYKE_PARAM` `_anyke` -> `_anykeX` reds leg 2 ONLY. So leg 2 additionally
//!   binds to wz's `_anyke` emission being honoured by pico's responder guard —
//!   the same guard zenoh applies (`zenoh/src/api/queryable.rs:278-287`), now
//!   measured to exist in zenoh-pico too. Leg 1 stayed GREEN, which says
//!   something about wz worth carrying rather than asserting: wz's own replier
//!   does NOT enforce the intersect guard, so it answers pico's history GET
//!   whether or not it recognises the token pico sent. That is a permissiveness,
//!   not an interop failure, and calling it a defect needs its own round.
//! * `PARAM_LIST_SEPARATOR` `;` -> `&` reds NOTHING here, and the reason is a
//!   caveat for the next author: neither leg passes `--history-max` /
//!   `--history-max-age`, so its selector carries ONE parameter and a list
//!   separator never appears in it. The zenoh-ext file's separator witness needs
//!   a TWO-parameter selector for exactly this reason; do not read these legs as
//!   covering it.
//!
//! ## What is deliberately NOT claimed
//!
//! `--advanced-recovery` is ARMED in leg 2 and pico's last-sample-miss beacons
//! do arrive, but no gap is INDUCED, so the retransmit repair path never runs.
//! The recovery claim is therefore `partial` and
//! `ext-pubsub-sample-miss-detection` is not claimed at all. A relay fault
//! (`RelayFault::DropFirstAcceptorToDialer`) is what would promote either, and
//! it is a separate round: leg 2 already has three processes and the drop would
//! have to be aimed at one specific `@adv` reply.
//!
//! PUBLISHER DETECTION is also absent, and it was WRITTEN and then REMOVED —
//! which is the more useful record. pico's
//! `ze_advanced_subscriber_detect_publishers` subscribes wz's `@adv/pub`
//! liveliness token, and a real pico WAS observed reporting
//! `New alive token ('demo/example/adv/@adv/pub/<zid>/0/_')` against the
//! `--listen` topology, repeatedly. It is not shipped because the fixture cannot
//! own the ORDERING it needs: `z_liveliness_subscriber_options_default` sets
//! `history = false` (`vendor/zenoh-pico/src/api/liveliness.c:73`), so pico only
//! sees a token declared AFTER its liveliness subscriber is installed, while
//! wz's token is declared the instant the session reaches Established — a race
//! with no marker between the two halves. The `ANYKE_PARAM` damage above is what
//! exposed it: that leg went red while still receiving all five samples live,
//! i.e. the damage moved the timing rather than the token, and a leg a wz-side
//! constant can flip by moving timing is a leg that reds on a loaded CI host.
//! Shipping it would have been a flake with a green history. What it needs is a
//! demo surface that declares the advanced publisher on a trigger the fixture
//! can sequence against, not a longer sleep.

use std::fs::File;
use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::time::Duration;

use wz_integration_tests::common::{
    graceful_terminate, read_captured, spawn_on_ephemeral_port, wait_for_capture_alive,
    wait_for_substring, wz_ap_demo_binary, zenoh_pico_cli_binary, ChildGuard,
};

/// How long a foreign exchange gets. Generous because the lane runs under
/// full-run-ci process pressure, and every wait returns the instant its marker
/// appears — a wide ceiling costs a green run nothing.
const EXCHANGE_TIMEOUT: Duration = Duration::from_secs(30);

/// How many samples the cache side emits before the asking side joins. Five is
/// the same depth the zenoh-ext history leg uses, and it is above one for a
/// reason: a single sample cannot distinguish "the cache replied" from "the last
/// sample happened to be re-pushed".
const BURST: usize = 5;

/// The cache depth BOTH cache holders are configured with, wz's `--cache-max`
/// and pico's `-i`. Strictly deeper than [`BURST`], so eviction can never be
/// what a missing sample means.
///
/// Neither side's default is taken, and wz's is why: with `--cache-max` omitted
/// the AP-full publisher logs `cache_max=None` and a real pico advanced
/// subscriber recovered exactly ONE sample — the last. That is a defensible
/// default and a useless fixture, and reading the recovery of 1 as "the cache
/// answered" would have been true but far weaker than this file claims.
const CACHE_DEPTH: usize = 20;

/// The `advanced` demo key must be in the binary under test. Asserted from the
/// demo's own `BUILD FEATURES = [...]` line rather than from the cargo
/// invocation, because the invocation is in a shell script one directory away
/// and the binary sits at a path other feature sets also write to.
fn assert_advanced_was_built(captured: &str, role: &str) {
    let line = captured
        .lines()
        .find(|l| l.contains("BUILD FEATURES = ["))
        .unwrap_or_else(|| {
            panic!(
                "the wz-ap-demo ({role}) never printed its BUILD FEATURES line, so \
                 which feature set this binary carries is unknown and no assertion \
                 below means anything\n--- captured ---\n{captured}"
            )
        });
    assert!(
        line.contains(" advanced ") || line.contains("[advanced "),
        "the wz-ap-demo ({role}) was built WITHOUT the `advanced` feature, so its \
         advanced plane is compiled out and `--advanced-publish` / \
         `--advanced-subscribe` are INERT. Build it with \
         `--no-default-features --features preset-ap-full` from a tree that carries \
         the R311y488 preset change.\n{line}"
    );
}

/// Spawn zenoh-pico's `z_advanced_sub` as a CLIENT of `endpoint`, returned once
/// it has opened its session AND declared the advanced subscriber.
///
/// `stdbuf -oL -eL` is not optional: pico's CLI block-buffers a non-TTY stdout,
/// so without it the `Received` lines sit in libc's buffer until exit and the
/// leg reads as a delivery failure. stderr rides the SAME capture as stdout
/// rather than being discarded — a foreign binary that dies has its diagnosis on
/// stderr, and `Stdio::null` there makes every failure mode look identical.
fn spawn_declared_advanced_sub(
    z_advanced_sub: &Path,
    keyexpr: &str,
    endpoint: &str,
    mk_capture: impl Fn() -> File,
) -> (ChildGuard, File) {
    let out = mk_capture();
    let out_writer = out.try_clone().expect("dup z_advanced_sub stdout handle");
    let err_writer = out.try_clone().expect("dup z_advanced_sub stderr handle");
    let mut reader = out;
    let mut child = ChildGuard::wrap(
        "z_advanced_sub client (zenoh-pico)",
        Command::new("stdbuf")
            .args(["-oL", "-eL"])
            .arg(z_advanced_sub)
            .args(["-k", keyexpr, "-e", endpoint, "-m", "client"])
            .stdout(Stdio::from(out_writer))
            .stderr(Stdio::from(err_writer))
            .spawn()
            .expect("spawn zenoh-pico z_advanced_sub"),
    );
    let declared = wait_for_capture_alive(
        child.child_mut(),
        &mut reader,
        EXCHANGE_TIMEOUT,
        "the pico advanced subscriber's declare marker",
        |cap| {
            cap.contains("Declaring AdvancedSubscriber on")
                .then_some(())
        },
    );
    if let Err(diagnosis) = declared {
        panic!(
            "the real zenoh-pico z_advanced_sub never declared. If the capture says \
             'compiled without Z_FEATURE_ADVANCED_SUBSCRIPTION' the CLI is the \
             vendor-default STUB main and the fix is \
             `bash scripts/build-zenoh-pico-cli.sh` on a tree carrying the R311y488 \
             cmake flags.\n{diagnosis}"
        );
    }
    (child, reader)
}

/// Spawn zenoh-pico's `z_advanced_pub` as a CLIENT of `endpoint`, returned once
/// it has published sample `BURST - 1` — i.e. once its cache demonstrably holds
/// the whole burst the wz subscriber will later ask for.
fn spawn_caching_advanced_pub(
    z_advanced_pub: &Path,
    keyexpr: &str,
    value: &str,
    endpoint: &str,
    mk_capture: impl Fn() -> File,
) -> (ChildGuard, File) {
    let out = mk_capture();
    let out_writer = out.try_clone().expect("dup z_advanced_pub stdout handle");
    let err_writer = out.try_clone().expect("dup z_advanced_pub stderr handle");
    let mut reader = out;
    let depth = CACHE_DEPTH.to_string();
    let mut child = ChildGuard::wrap(
        "z_advanced_pub client (zenoh-pico)",
        Command::new("stdbuf")
            .args(["-oL", "-eL"])
            .arg(z_advanced_pub)
            .args([
                "-k", keyexpr, "-v", value, "-e", endpoint, "-m", "client", "-i", &depth,
            ])
            .stdout(Stdio::from(out_writer))
            .stderr(Stdio::from(err_writer))
            .spawn()
            .expect("spawn zenoh-pico z_advanced_pub"),
    );
    let last = format!("[{:4}] {value}", BURST - 1);
    let filled = wait_for_capture_alive(
        child.child_mut(),
        &mut reader,
        EXCHANGE_TIMEOUT,
        "the pico advanced publisher's whole burst",
        |cap| cap.contains(&last).then_some(()),
    );
    if let Err(diagnosis) = filled {
        panic!(
            "the real zenoh-pico z_advanced_pub never reached sample {}. If the \
             capture says 'compiled without Z_FEATURE_ADVANCED_PUBLICATION' the CLI \
             is the vendor-default STUB main and the fix is \
             `bash scripts/build-zenoh-pico-cli.sh` on a tree carrying the R311y488 \
             cmake flags.\n{diagnosis}",
            BURST - 1
        );
    }
    (child, reader)
}

/// Spawn the AP-full binary as a `--connect` CLIENT of the hub with `extra`
/// flags, capturing stderr. `RUST_LOG=info` because every marker this file waits
/// on is an INFO line.
fn spawn_demo_client(
    demo: &Path,
    port: u16,
    extra: &[&str],
    label: &'static str,
    capture: File,
) -> (ChildGuard, File) {
    let writer = capture.try_clone().expect("dup wz-ap-demo stderr handle");
    let reader = capture;
    let child = ChildGuard::wrap(
        label,
        Command::new(demo)
            .arg("--connect")
            .arg(format!("127.0.0.1:{port}"))
            .args(extra)
            .env("RUST_LOG", "info")
            .stdout(Stdio::null())
            .stderr(Stdio::from(writer))
            .spawn()
            .unwrap_or_else(|e| panic!("spawn {label}: {e}")),
    );
    (child, reader)
}

/// Reap a child without waiting for a graceful exit. Used for the foreign CLIs
/// and for demo clients that run until killed.
fn kill_now(child: &mut Child) {
    let _ = child.kill();
    let _ = child.wait();
}

/// LEG 1 — a real zenoh-pico AdvancedSubscriber recovers the AP-full cache.
///
/// The ordering is the whole leg, and it is asserted rather than arranged: the
/// wz publisher's own `ADVANCED BURST COMPLETE` marker is read BEFORE the pico
/// process is spawned, so pico's session cannot have existed when any of the
/// five samples was published. Every sample it then reports came out of wz's
/// cache in reply to pico's startup `@adv` history GET — routed to that cache by
/// the AP-full peer, since the two are separate clients of it.
// wz-proves: ext-pubsub-advanced-publisher wz->pico
// wz-proves: ext-pubsub-advanced-cache wz->pico
// wz-proves: ext-pubsub-advanced-history wz->pico
// wz-proves: routing-peer wz->pico partial
#[test]
#[ignore = "binary-dep e2e (wz-ap-demo --features preset-ap-full + zenoh-pico z_advanced_sub); Layer E11 runs via --ignored"]
fn apfull_cache_history_recovered_by_a_real_pico_advanced_subscriber() {
    let demo = wz_ap_demo_binary();
    let z_advanced_sub = zenoh_pico_cli_binary("z_advanced_sub");
    let keyexpr = "demo/example/adv";
    let value = "APFULL-CACHE-TO-PICO";

    let hub_stderr = tempfile::tempfile().expect("tempfile for AP-full hub stderr");
    let (mut hub_guard, mut hub_reader, port) = spawn_on_ephemeral_port(
        &demo,
        &["--peer", "127.0.0.1:0"],
        "peer: listening on 127.0.0.1:",
        "wz-ap-demo (preset-ap-full, --peer hub)",
        hub_stderr,
    );
    let endpoint = format!("tcp/127.0.0.1:{port}");

    // The build discriminator, BEFORE any wire assertion: an AP-full binary from a
    // pre-y488 preset fails here naming its own feature list, instead of timing out
    // on a marker that never comes.
    assert_advanced_was_built(&read_captured(&mut hub_reader), "peer hub");

    let (mut pub_guard, mut pub_reader) = spawn_demo_client(
        &demo,
        port,
        &[
            "--advanced-publish",
            keyexpr,
            "--value",
            value,
            "--advanced-publish-count",
            &BURST.to_string(),
            "--cache-max",
            &CACHE_DEPTH.to_string(),
        ],
        "wz-ap-demo (preset-ap-full, --advanced-publish)",
        tempfile::tempfile().expect("tempfile for wz advanced publisher stderr"),
    );

    // The precondition the leg rests on, OWNED rather than assumed.
    let served = match wait_for_capture_alive(
        pub_guard.child_mut(),
        &mut pub_reader,
        EXCHANGE_TIMEOUT,
        "the wz advanced publisher's whole burst",
        |cap| {
            cap.contains("ADVANCED BURST COMPLETE")
                .then(|| cap.to_string())
        },
    ) {
        Ok(c) => c,
        Err(diagnosis) => {
            let hub = read_captured(&mut hub_reader);
            panic!(
                "the AP-full publisher never logged 'ADVANCED BURST COMPLETE', so no \
                 cache was serving and the leg's ordering precondition does not \
                 hold\n{diagnosis}\n--- hub stderr ---\n{hub}"
            );
        }
    };
    assert!(
        served.contains("DECLARED ADVANCED PUBLISHER"),
        "the burst completed without a DECLARED ADVANCED PUBLISHER line — the Puts \
         went out on the plain publisher, so there is no cache behind them\n\
         --- wz publisher stderr ---\n{served}"
    );
    assert!(
        served.contains(&format!("cache_max=Some({CACHE_DEPTH})")),
        "`--cache-max {CACHE_DEPTH}` did not take. With the default depth the cache \
         answers with the LAST sample only (measured: 1 of {BURST}), so the \
         per-index assertions below would fail for a configuration reason rather \
         than an interop one\n--- wz publisher stderr ---\n{served}"
    );

    let (mut sub_child, mut sub_reader) =
        spawn_declared_advanced_sub(&z_advanced_sub, "demo/example/**", &endpoint, || {
            tempfile::tempfile().expect("tempfile for z_advanced_sub capture")
        });

    // Wait on the LAST index, then assert every one — waiting on the last is what
    // makes the per-index asserts a check rather than a race.
    let last_marker = format!("Received PUT ('{keyexpr}': '[{:4}] {value}')", BURST - 1);
    let recovered =
        wait_for_substring(&mut sub_reader, &last_marker, EXCHANGE_TIMEOUT).map(|c| c.to_string());

    kill_now(sub_child.child_mut());
    kill_now(pub_guard.child_mut());
    graceful_terminate(hub_guard.child_mut(), Duration::from_secs(5));

    let pico_out = match recovered {
        Ok(c) => c,
        Err(c) => panic!(
            "the real zenoh-pico AdvancedSubscriber never recovered sample {} from \
             the AP-full cache. Its startup history GET is the only path these \
             samples could arrive by — every one was published before this process \
             existed.\n--- z_advanced_sub capture ---\n{c}\n\
             --- wz publisher stderr ---\n{}\n--- hub stderr ---\n{}",
            BURST - 1,
            read_captured(&mut pub_reader),
            read_captured(&mut hub_reader)
        ),
    };

    assert!(
        !pico_out.contains("compiled without Z_FEATURE_ADVANCED_SUBSCRIPTION"),
        "the z_advanced_sub binary is the vendor-default STUB main, so nothing above \
         witnessed anything\n--- z_advanced_sub capture ---\n{pico_out}"
    );
    for i in 0..BURST {
        let marker = format!("Received PUT ('{keyexpr}': '[{i:4}] {value}')");
        assert!(
            pico_out.contains(&marker),
            "sample {i} of the pre-published burst is missing from the real pico's \
             recovery — a cache that answers a history GET partially is a different \
             defect from one that does not answer at all\n\
             --- z_advanced_sub capture ---\n{pico_out}"
        );
    }
}

/// LEG 2 — the AP-full AdvancedSubscriber recovers a real zenoh-pico cache.
///
/// Same recovery direction as the zenoh-ext file's leg 1, different replier
/// implementation. Three processes: the AP-full `--peer` hub, a pico
/// `z_advanced_pub` client holding the cache, and a wz `--advanced-subscribe`
/// client. The peer is not scenery — the history GET and its replies have to
/// cross it.
// wz-proves: ext-pubsub-advanced-subscriber pico->wz
// wz-proves: ext-pubsub-advanced-history pico->wz
// wz-proves: ext-pubsub-advanced-recovery pico->wz partial
// wz-proves: routing-peer pico->wz partial
#[test]
#[ignore = "binary-dep e2e (wz-ap-demo --features preset-ap-full + zenoh-pico z_advanced_pub); Layer E11 runs via --ignored"]
fn apfull_advanced_subscriber_recovers_history_from_a_real_pico_cache() {
    let demo = wz_ap_demo_binary();
    let z_advanced_pub = zenoh_pico_cli_binary("z_advanced_pub");
    let keyexpr = "demo/example/picoadv";
    let value = "PICO-CACHE-TO-APFULL";

    let hub_stderr = tempfile::tempfile().expect("tempfile for AP-full hub stderr");
    let (mut hub_guard, mut hub_reader, port) = spawn_on_ephemeral_port(
        &demo,
        &["--peer", "127.0.0.1:0"],
        "peer: listening on 127.0.0.1:",
        "wz-ap-demo (preset-ap-full, --peer hub)",
        hub_stderr,
    );
    let endpoint = format!("tcp/127.0.0.1:{port}");
    assert_advanced_was_built(&read_captured(&mut hub_reader), "peer hub");

    // The pico cache first, and FILLED: the helper returns only after sample
    // BURST-1 has been put, so every sample the wz subscriber later reports
    // predates its own session.
    let (mut pub_child, mut pub_reader) =
        spawn_caching_advanced_pub(&z_advanced_pub, keyexpr, value, &endpoint, || {
            tempfile::tempfile().expect("tempfile for z_advanced_pub capture")
        });

    let (mut sub_guard, mut sub_reader) = spawn_demo_client(
        &demo,
        port,
        &[
            "--advanced-subscribe",
            "demo/example/**",
            "--advanced-recovery",
        ],
        "wz-ap-demo (preset-ap-full, --advanced-subscribe)",
        tempfile::tempfile().expect("tempfile for wz advanced subscriber stderr"),
    );

    let last_marker = format!("payload='[{:4}] {value}'", BURST - 1);
    let recovered =
        wait_for_substring(&mut sub_reader, &last_marker, EXCHANGE_TIMEOUT).map(|c| c.to_string());

    kill_now(sub_guard.child_mut());
    kill_now(pub_child.child_mut());
    graceful_terminate(hub_guard.child_mut(), Duration::from_secs(5));

    let sub_log = match recovered {
        Ok(c) => c,
        Err(c) => panic!(
            "the AP-full AdvancedSubscriber never recovered sample {} from the real \
             zenoh-pico cache. All {BURST} samples were published before this \
             subscriber's session existed, so its startup `@adv` history GET — \
             routed by the AP-full peer to pico's cache queryable — is the only path \
             they could arrive by.\n--- wz subscriber stderr ---\n{c}\n\
             --- z_advanced_pub capture ---\n{}\n--- hub stderr ---\n{}",
            BURST - 1,
            read_captured(&mut pub_reader),
            read_captured(&mut hub_reader)
        ),
    };

    assert!(
        sub_log.contains("DECLARED ADVANCED SUBSCRIBER"),
        "no DECLARED ADVANCED SUBSCRIBER line — the samples, if any, arrived on a \
         plain subscriber and no history GET was ever emitted\n\
         --- wz subscriber stderr ---\n{sub_log}"
    );
    assert!(
        sub_log.contains("recovery=true"),
        "the subscriber declared with recovery=false, so `--advanced-recovery` did \
         not take and the partial recovery claim on this leg is unfounded\n\
         --- wz subscriber stderr ---\n{sub_log}"
    );
    for i in 0..BURST {
        let marker = format!("payload='[{i:4}] {value}'");
        assert!(
            sub_log.contains(&marker),
            "sample {i} of pico's pre-filled cache is missing from wz's recovery — a \
             partial answer to the history GET is a different defect from no \
             answer\n--- wz subscriber stderr ---\n{sub_log}"
        );
    }
    let pico_out = read_captured(&mut pub_reader);
    assert!(
        !pico_out.contains("compiled without Z_FEATURE_ADVANCED_PUBLICATION"),
        "the z_advanced_pub binary is the vendor-default STUB main, so nothing above \
         witnessed anything\n--- z_advanced_pub capture ---\n{pico_out}"
    );
}
