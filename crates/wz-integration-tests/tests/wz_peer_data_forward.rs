// SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! R311ri / R311rs — c3c e2e: linkstate-peer SUBSCRIPTION-FILTERED mesh data
//! forwarding over a 3-peer LINE.
//!
//! Topology (all the `--features routing-peer` binary, ephemeral ports read
//! back from each peer's listen log):
//!   - peer C: `--peer 127.0.0.1:0 --subscribe demo/mesh` — the FAR SUBSCRIBER
//!     (2 hops from the publisher), declaring interest in the keyexpr.
//!   - peer B: `--peer 127.0.0.1:0 --connect <C>` — dials C (the transit hop;
//!     NOT a subscriber, it only relays toward C).
//!   - peer A: `--peer 127.0.0.1:0 --connect <B> --publish demo/mesh` — dials B
//!     AND originates data into the mesh.
//!
//! So the linkstate edges are A<->B and B<->C (a line A-B-C). C's subscription
//! floods C -> B -> A, so A LEARNS that C is interested in `demo/mesh`. Only
//! then does A's subscription-filtered route (c3c-3 atom4) forward the Put:
//! `directions_toward` the interested C picks A's child B, and B re-forwards to
//! ITS child C (re-stamping the routing-context NodeId). C therefore RECEIVES
//! data it has no direct link to the publisher for — the end-to-end proof that
//! the FULL c3c-3 chain works over real TCP: declare_subscription (c3c-3 atom3)
//! propagates interest A-ward, and the filtered data route (atom4) then delivers
//! C-ward. Without C's subscription the publisher's any-interest gate would
//! forward nothing.
//!
//! A second test (c3c-3 debt A1) is the RETRACTION counterpart over the same
//! line: C subscribes, confirms the round-trip, then `--unsubscribe-after-data`
//! flips it to flooding a sourced `UndeclareSubscriber` C -> B -> A, and the
//! publisher witnesses its learned interest being WITHDRAWN (a positive
//! transition, not a flaky non-receipt) — the end-to-end proof of the
//! subscription-lifecycle retraction path.
//!
//! Both line tests declare interest exactly ONCE (c3c-3 debt A2): the
//! subscription reaches the LATER-joining publisher via the tree-change
//! re-advertise (`re_advertise_subscriptions`, zenoh `pubsub_tree_change`) on
//! each topology recompute, not a per-tick re-declare — so these e2es also
//! exercise that convergence path end-to-end.
//!
//! A third test (c3c-3 debt C1) is the SELECTIVITY counterpart over a BRANCHING
//! topology — a hub peer B with three leaves: publisher A, subscriber C, and a
//! NON-subscriber D (`A - B - {C subscribes, D does not}`). A's published data
//! must reach C (the subscriber, two hops) but NOT D: when A's Put reaches the
//! hub B, B's `directions_toward` filter routes it only toward the interested
//! subtree (the C branch), pruning the D branch in the SAME synchronous fan-out
//! — so D is excluded by the subscription filter, not by timing. The witness is
//! NEVER a flaky wait-for-absence: the test gates on C RECEIVING (the positive
//! proof the data actually flowed through B), then asserts D's DETERMINISTIC
//! shutdown state — D learned the mesh topology (so its non-receipt is genuine
//! pruning, not isolation) yet its data-push count is exactly zero. This is the
//! end-to-end proof that the data route prunes an unsubscribed branch rather
//! than broadcasting along the whole tree.
//!
//! Requires the binary built with `--features routing-peer` (the `--peer` /
//! `--publish` / `--subscribe` / `--unsubscribe-after-data` args are opt-in
//! behind it; `--connect` takes a comma-separated dial list in peer mode, so the
//! hub B dials both leaves). run-ci's Layer E6 builds it so all three tests ride
//! the same `--ignored` lane as the other binary-dep e2es.

use std::fs::File;
use std::process::{Command, Stdio};
use std::time::Duration;

use wz_integration_tests::common::{
    graceful_terminate, read_captured, wait_for_substring, wz_ap_demo_binary, ChildGuard,
};

/// Parse the bound port from a peer's `listening on 127.0.0.1:<port>` log line
/// — the ephemeral-port read-back that lets the next peer dial this one without
/// a reserved-port allocation.
fn listen_port(captured: &str) -> u16 {
    let marker = "listening on 127.0.0.1:";
    let rest = captured
        .split(marker)
        .nth(1)
        .unwrap_or_else(|| panic!("no '{marker}' in:\n{captured}"));
    rest.chars()
        .take_while(char::is_ascii_digit)
        .collect::<String>()
        .parse()
        .unwrap_or_else(|e| panic!("unparseable port after '{marker}': {e}\n{captured}"))
}

/// Spawn a `--peer` demo on an ephemeral port and wait until it binds, then read
/// the bound port back from its listen log. Returns the guard, its stderr
/// reader, and the port.
fn spawn_peer(label: &str, args: &[&str]) -> (ChildGuard, File, u16) {
    let stderr = tempfile::tempfile().expect("tempfile for peer stderr");
    let writer = stderr.try_clone().expect("dup peer stderr handle");
    let mut reader = stderr;
    let mut guard = ChildGuard::wrap(
        label.to_string(),
        Command::new(wz_ap_demo_binary())
            .args(args)
            .env("RUST_LOG", "info")
            .stdout(Stdio::null())
            .stderr(Stdio::from(writer))
            .spawn()
            .unwrap_or_else(|e| panic!("spawn {label}: {e}")),
    );
    let captured = wait_for_substring(
        &mut reader,
        "peer: listening on 127.0.0.1:",
        Duration::from_secs(5),
    )
    .unwrap_or_else(|c| {
        let _ = guard.child_mut().kill();
        let _ = guard.child_mut().wait();
        panic!(
            "{label} did not bind within 5s (is the binary built with \
                     --features routing-peer?)\n--- {label} stderr ---\n{c}"
        );
    });
    let port = listen_port(&captured);
    (guard, reader, port)
}

#[test]
#[ignore = "binary-dep e2e (wz-ap-demo --features routing-peer); Layer E runs via --ignored"]
fn wz_peer_mesh_forwards_subscribed_data_two_hops() {
    // C (far SUBSCRIBER) binds first so B can dial it; then B binds so A can
    // dial it. C declares interest in demo/mesh, which floods C -> B -> A.
    let (mut c_guard, mut c_reader, p_c) = spawn_peer(
        "peer-C",
        &["--peer", "127.0.0.1:0", "--subscribe", "demo/mesh"],
    );
    let addr_c = format!("127.0.0.1:{p_c}");
    let (mut b_guard, mut b_reader, p_b) =
        spawn_peer("peer-B", &["--peer", "127.0.0.1:0", "--connect", &addr_c]);
    let addr_b = format!("127.0.0.1:{p_b}");
    let (mut a_guard, mut a_reader, _p_a) = spawn_peer(
        "peer-A",
        &[
            "--peer",
            "127.0.0.1:0",
            "--connect",
            &addr_b,
            "--publish",
            "demo/mesh",
        ],
    );

    // The FAR SUBSCRIBER C must RECEIVE A's published data — but only because
    // its subscription flooded A-ward and A's filtered route then forwarded
    // A -> B -> C (B re-stamping the routing-context NodeId for C). C has NO
    // direct link to A, so receiving this proves the full subscription-gated
    // multi-hop chain (declare propagate + filtered data route) over the wire.
    let c_data = wait_for_substring(&mut c_reader, "received mesh data", Duration::from_secs(15));

    // Graceful-shutdown all three, then read their captured logs.
    graceful_terminate(a_guard.child_mut(), Duration::from_secs(5));
    graceful_terminate(b_guard.child_mut(), Duration::from_secs(5));
    graceful_terminate(c_guard.child_mut(), Duration::from_secs(5));
    let a_captured = read_captured(&mut a_reader);
    let b_captured = read_captured(&mut b_reader);
    let c_captured = read_captured(&mut c_reader);
    eprintln!("--- peer-A stderr ---\n{a_captured}");
    eprintln!("--- peer-B stderr ---\n{b_captured}");
    eprintln!("--- peer-C stderr ---\n{c_captured}");

    // Diagnostics printed; now assert.
    c_data.unwrap_or_else(|c| {
        panic!(
            "peer-C (2 hops from the publisher) never logged 'received mesh data' within \
             15s — A's published data did not flood through B to C (multi-hop forward \
             did not reach the far peer)\n--- peer-C stderr ---\n{c}"
        )
    });
    // The publisher A must have LEARNED C's subscription — the declaration
    // flooded C -> B -> A — before its any-interest gate would forward anything.
    // This is the subscription half of the chain: without it, the filtered data
    // route never fires (so C's reception above is genuinely subscription-gated,
    // not a leftover broadcast).
    assert!(
        a_captured.contains("publisher learned subscriber interest"),
        "peer-A never learned C's subscription — the declaration did not flood \
         A-ward, so the subscription-filtered route could not enable the \
         publish\n--- peer-A stderr ---\n{a_captured}"
    );
    // The transit hop B must ALSO have received the data (it is what forwarded
    // it onward to C) — distinguishing a true two-hop relay from a fluke. B is
    // read AFTER shutdown, so this matches B's DETERMINISTIC shutdown-summary
    // witness (gated on data_seen > 0), not the in-run app-tick log B might be
    // SIGTERM'd before firing (R311rj — the prior in-run-only assertion was
    // flaky under load).
    assert!(
        b_captured.contains("received mesh data"),
        "peer-B (the transit hop) must have received and forwarded A's data\n\
         --- peer-B stderr ---\n{b_captured}"
    );
}

#[test]
#[ignore = "binary-dep e2e (wz-ap-demo --features routing-peer); Layer E runs via --ignored"]
fn wz_peer_mesh_wildcard_subscription_attracts_a_concrete_publish() {
    // c3c-3 B2 — the wildcard-matching counterpart of the two-hop forward test.
    // The far subscriber C declares `demo/**` (a PATTERN), the publisher A
    // publishes the CONCRETE `demo/mesh`. With exact-match-only this would never
    // route; B2's keyexpr intersection means A's `interested("demo/mesh")` now
    // matches C's `demo/**`, so the subscription-gated route fires and C receives
    // — proving the wildcard match end-to-end over real TCP (the pattern keyexpr
    // survives the DeclareSubscriber wire, floods A-ward, and the data route
    // intersects it against the concrete publish).
    let (mut c_guard, mut c_reader, p_c) = spawn_peer(
        "peer-C",
        &["--peer", "127.0.0.1:0", "--subscribe", "demo/**"],
    );
    let addr_c = format!("127.0.0.1:{p_c}");
    let (mut b_guard, mut b_reader, p_b) =
        spawn_peer("peer-B", &["--peer", "127.0.0.1:0", "--connect", &addr_c]);
    let addr_b = format!("127.0.0.1:{p_b}");
    let (mut a_guard, mut a_reader, _p_a) = spawn_peer(
        "peer-A",
        &[
            "--peer",
            "127.0.0.1:0",
            "--connect",
            &addr_b,
            "--publish",
            "demo/mesh",
        ],
    );

    let c_data = wait_for_substring(&mut c_reader, "received mesh data", Duration::from_secs(15));

    graceful_terminate(a_guard.child_mut(), Duration::from_secs(5));
    graceful_terminate(b_guard.child_mut(), Duration::from_secs(5));
    graceful_terminate(c_guard.child_mut(), Duration::from_secs(5));
    let a_captured = read_captured(&mut a_reader);
    let b_captured = read_captured(&mut b_reader);
    let c_captured = read_captured(&mut c_reader);
    eprintln!("--- peer-A stderr ---\n{a_captured}");
    eprintln!("--- peer-B stderr ---\n{b_captured}");
    eprintln!("--- peer-C stderr ---\n{c_captured}");

    c_data.unwrap_or_else(|c| {
        panic!(
            "peer-C (subscribed to the PATTERN demo/**) never received the concrete \
             demo/mesh publish within 15s — the wildcard subscription did not attract \
             the data (B2 keyexpr intersection)\n--- peer-C stderr ---\n{c}"
        )
    });
    assert!(
        a_captured.contains("publisher learned subscriber interest"),
        "peer-A never learned C's demo/** subscription, so the intersection route \
         could not enable the publish\n--- peer-A stderr ---\n{a_captured}"
    );
}

#[test]
#[ignore = "binary-dep e2e (wz-ap-demo --features routing-peer); Layer E runs via --ignored"]
fn wz_peer_mesh_withdraws_subscription_two_hops() {
    // c3c-3 debt A1 — the RETRACTION counterpart of the forward test. The same
    // line A-B-C, but C RETRACTS its interest once it has confirmed the
    // round-trip (received data): `--unsubscribe-after-data` flips C from
    // declaring to undeclaring. The sourced UndeclareSubscriber floods C -> B ->
    // A (re-stamping the routing-context NodeId at each hop), so A's LEARNED
    // interest is withdrawn.
    //
    // The witness is a POSITIVE state transition at the publisher — interest
    // learned, then withdrawn — never a flaky non-receipt assertion. Because C
    // only retracts AFTER it has received data, observing the withdrawal at A
    // proves the whole lifecycle ran over real TCP: subscribe propagate, the
    // data round-trip (C's self-coordinating trigger), and undeclare propagate.
    let (mut c_guard, mut c_reader, p_c) = spawn_peer(
        "peer-C",
        &[
            "--peer",
            "127.0.0.1:0",
            "--subscribe",
            "demo/mesh",
            "--unsubscribe-after-data",
        ],
    );
    let addr_c = format!("127.0.0.1:{p_c}");
    let (mut b_guard, mut b_reader, p_b) =
        spawn_peer("peer-B", &["--peer", "127.0.0.1:0", "--connect", &addr_c]);
    let addr_b = format!("127.0.0.1:{p_b}");
    let (mut a_guard, mut a_reader, _p_a) = spawn_peer(
        "peer-A",
        &[
            "--peer",
            "127.0.0.1:0",
            "--connect",
            &addr_b,
            "--publish",
            "demo/mesh",
        ],
    );

    // Terminal witness: the publisher first LEARNS C's interest, then — after C
    // confirms data and retracts — sees that interest WITHDRAWN. The demo emits
    // this string BOTH in-run (per app-tick) AND deterministically at its shutdown
    // summary (state-derived: announced_interest ever true AND the interest set now
    // empty, runner.rs:1607). The PASS/FAIL gate is the DETERMINISTIC post-shutdown
    // capture asserted below — NOT this wait, which is only a NON-FATAL propagation
    // SYNC: it lets the whole lifecycle run (subscribe propagate, data round-trip,
    // undeclare propagate) before we snapshot A's terminal state. Gating on the
    // in-run app-tick log flaked a CORRECT run (R311y22e) because under a rare host-
    // starvation tail A's app-tick emit can race past 20s while the interest state
    // is correctly empty; the SIGTERM-driven shutdown summary emits the SAME string
    // from state regardless of app-tick timing. This mirrors the data/topology
    // witnesses (R311rj/R311sg) which already assert on the deterministic shutdown
    // capture rather than the racy in-run log — closing the lone hold-out here.
    let _withdrawn_sync = wait_for_substring(
        &mut a_reader,
        "publisher subscriber interest withdrawn",
        Duration::from_secs(20),
    );

    graceful_terminate(a_guard.child_mut(), Duration::from_secs(5));
    graceful_terminate(b_guard.child_mut(), Duration::from_secs(5));
    graceful_terminate(c_guard.child_mut(), Duration::from_secs(5));
    let a_captured = read_captured(&mut a_reader);
    let b_captured = read_captured(&mut b_reader);
    let c_captured = read_captured(&mut c_reader);
    eprintln!("--- peer-A stderr ---\n{a_captured}");
    eprintln!("--- peer-B stderr ---\n{b_captured}");
    eprintln!("--- peer-C stderr ---\n{c_captured}");

    // PRIMARY witness (deterministic): peer-A's interest in demo/mesh went from
    // learned to EMPTY, proving C's UndeclareSubscriber flooded C -> B -> A. Read
    // from the post-shutdown capture, so it is satisfied by EITHER the in-run app-
    // tick log OR the state-derived shutdown summary (runner.rs:1607) — A is
    // terminated FIRST (B and C still up), so an empty interest set can only mean
    // the undeclare propagated, never a face-down side effect.
    assert!(
        a_captured.contains("publisher subscriber interest withdrawn"),
        "peer-A's interest in demo/mesh never went empty — C's UndeclareSubscriber \
         did not flood C -> B -> A to retract the learned interest\n\
         --- peer-A stderr ---\n{a_captured}"
    );
    // Order + both-present: the publisher must have LEARNED the interest before
    // it could be WITHDRAWN — the retraction is meaningful only against an
    // established interest. The demo logs withdrawn ONLY after learned, so this
    // asserts the lifecycle, not a spurious empty.
    let learned_at = a_captured
        .find("publisher learned subscriber interest")
        .unwrap_or_else(|| {
            panic!(
                "peer-A withdrew without first learning C's interest\n\
                 --- peer-A stderr ---\n{a_captured}"
            )
        });
    let withdrawn_at = a_captured
        .find("publisher subscriber interest withdrawn")
        .expect("withdrawn substring present (asserted above)");
    assert!(
        learned_at < withdrawn_at,
        "publisher must LEARN interest before WITHDRAWING it\n\
         --- peer-A stderr ---\n{a_captured}"
    );
    // C must have RECEIVED data — the trigger that made it retract. Anchors that
    // the withdrawal followed a real established round-trip, not a peer that
    // never subscribed in the first place.
    assert!(
        c_captured.contains("received mesh data"),
        "peer-C never received data, so its --unsubscribe-after-data trigger never \
         fired\n--- peer-C stderr ---\n{c_captured}"
    );
}

#[test]
#[ignore = "binary-dep e2e (wz-ap-demo --features routing-peer); Layer E runs via --ignored"]
fn wz_peer_mesh_prunes_the_unsubscribed_branch_four_peers() {
    // c3c-3 debt C1 — the SELECTIVITY proof over a BRANCHING topology. The hub
    // peer B holds three leaves:
    //   - peer D: `--peer 127.0.0.1:0` — a hold-only mesh member that NEVER
    //     subscribes (no `--subscribe`). It participates in topology flooding so
    //     it is a converged graph node, but it declares no interest.
    //   - peer C: `--peer 127.0.0.1:0 --subscribe demo/mesh` — the SUBSCRIBER,
    //     two hops from the publisher.
    //   - peer B: `--peer 127.0.0.1:0 --connect <C>,<D>` — the HUB. In peer mode
    //     `--connect` takes a comma-separated dial list, so B dials BOTH leaves
    //     and holds a face to each (plus the inbound face from A below).
    //   - peer A: `--peer 127.0.0.1:0 --connect <B> --publish demo/mesh` — dials
    //     the hub and originates data.
    //
    // Linkstate edges: A<->B, B<->C, B<->D (a star centred on B). C's
    // subscription floods C -> B -> A, so A learns C is interested. When A's
    // any-interest gate then forwards the Put, A's filtered route picks its child
    // B; at B, `directions_toward` the interested set {C} routes the Put toward
    // C's subtree ONLY. D is one of B's tree children too, but it is NOT in the
    // interested set, so the SAME synchronous fan-out at B that forwards to C
    // SKIPS D — pruned by the subscription filter, not by any timing window.
    //
    // The far SUBSCRIBER C and the NON-subscriber D both bind first (so the hub
    // can dial them), then the hub B, then the publisher A.
    let (mut d_guard, mut d_reader, p_d) = spawn_peer("peer-D", &["--peer", "127.0.0.1:0"]);
    let addr_d = format!("127.0.0.1:{p_d}");
    let (mut c_guard, mut c_reader, p_c) = spawn_peer(
        "peer-C",
        &["--peer", "127.0.0.1:0", "--subscribe", "demo/mesh"],
    );
    let addr_c = format!("127.0.0.1:{p_c}");
    // The hub dials BOTH leaves via the comma-separated peer-mode dial list.
    let dial_list = format!("{addr_c},{addr_d}");
    let (mut b_guard, mut b_reader, p_b) = spawn_peer(
        "peer-B",
        &["--peer", "127.0.0.1:0", "--connect", &dial_list],
    );
    let addr_b = format!("127.0.0.1:{p_b}");
    let (mut a_guard, mut a_reader, _p_a) = spawn_peer(
        "peer-A",
        &[
            "--peer",
            "127.0.0.1:0",
            "--connect",
            &addr_b,
            "--publish",
            "demo/mesh",
        ],
    );

    // POSITIVE sync: the far SUBSCRIBER C must RECEIVE A's published data
    // (A -> B -> C). Waiting on this is the proof the whole chain ran — interest
    // propagated A-ward AND the filtered data route delivered C-ward — and it is
    // also the gate that makes D's non-receipt below a DETERMINISTIC terminal
    // state rather than a flaky wait-for-absence: once C has the data, B has
    // already run the single fan-out that either includes or excludes each of its
    // tree children, so D's state is settled.
    let c_data = wait_for_substring(&mut c_reader, "received mesh data", Duration::from_secs(15));

    graceful_terminate(a_guard.child_mut(), Duration::from_secs(5));
    graceful_terminate(b_guard.child_mut(), Duration::from_secs(5));
    graceful_terminate(c_guard.child_mut(), Duration::from_secs(5));
    graceful_terminate(d_guard.child_mut(), Duration::from_secs(5));
    let a_captured = read_captured(&mut a_reader);
    let b_captured = read_captured(&mut b_reader);
    let c_captured = read_captured(&mut c_reader);
    let d_captured = read_captured(&mut d_reader);
    eprintln!("--- peer-A stderr ---\n{a_captured}");
    eprintln!("--- peer-B stderr ---\n{b_captured}");
    eprintln!("--- peer-C stderr ---\n{c_captured}");
    eprintln!("--- peer-D stderr ---\n{d_captured}");

    // Diagnostics printed; now assert.
    c_data.unwrap_or_else(|c| {
        panic!(
            "peer-C (the subscriber, 2 hops from the publisher) never logged 'received \
             mesh data' within 15s — A's data did not reach the subscribed branch\n\
             --- peer-C stderr ---\n{c}"
        )
    });
    // The publisher A must have LEARNED C's subscription before its any-interest
    // gate would forward anything — the subscription half of the chain.
    assert!(
        a_captured.contains("publisher learned subscriber interest"),
        "peer-A never learned C's subscription — the declaration did not flood \
         A-ward, so the subscription-filtered route could not enable the \
         publish\n--- peer-A stderr ---\n{a_captured}"
    );
    // The hub B must have received and forwarded the data (it is what relayed it
    // to C) — read AFTER shutdown via B's DETERMINISTIC data-reception witness
    // (R311rj), not the in-run app-tick log that SIGTERM may have pre-empted.
    assert!(
        b_captured.contains("received mesh data"),
        "peer-B (the hub) must have received and forwarded A's data toward the \
         subscribed branch\n--- peer-B stderr ---\n{b_captured}"
    );

    // The crux: D is a FULLY-CONVERGED mesh member, so its non-receipt is genuine
    // SUBSCRIPTION PRUNING, not isolation. "learned mesh topology" alone only
    // proves D ingested >= 1 link-state; the stronger anchor is that D's graph
    // holds all FOUR peers (A, B, C, D) — which means the hub B genuinely holds D
    // as a routable tree child at fan-out time, so D's exclusion is the filter's
    // doing, not a missing B<->D edge (R311sg — the prior weaker anchor could pass
    // for the wrong reason if B never formed the B<->D edge).
    assert!(
        d_captured.contains("learned mesh topology"),
        "peer-D never converged into the mesh, so its non-receipt would not prove \
         the filter pruned it (it could just be isolated)\n--- peer-D stderr ---\n{d_captured}"
    );
    assert!(
        d_captured.contains("4 node(s) in topology graph"),
        "peer-D's graph does not hold all 4 peers — it is not a fully-converged \
         member, so its non-receipt could be topological (no B<->D edge) rather \
         than the subscription filter pruning it\n--- peer-D stderr ---\n{d_captured}"
    );
    // The NON-subscriber D received NOTHING. Asserted DETERMINISTICALLY, never as
    // a flaky wait-for-absence: the shutdown summary unconditionally reports the
    // data-push count ("0 data push(es) received" here, state-derived from
    // `data_seen == 0`), and the "received mesh data" witness fires ONLY when the
    // count is > 0 — so its ABSENCE in D's log is a positive statement of zero
    // receipt, anchored to the post-shutdown terminal state we reach only after C
    // confirmed the data flowed. This is the selectivity: B's `directions_toward`
    // filter forwarded to the interested C branch and pruned the uninterested D
    // branch in one fan-out.
    assert!(
        d_captured.contains("0 data push(es) received"),
        "peer-D's shutdown summary did not report zero data pushes — the data route \
         leaked onto the UNSUBSCRIBED branch (the filter did not prune D)\n\
         --- peer-D stderr ---\n{d_captured}"
    );
    assert!(
        !d_captured.contains("received mesh data"),
        "peer-D (which never subscribed) received mesh data — the subscription \
         filter failed to prune the unsubscribed branch at the hub\n\
         --- peer-D stderr ---\n{d_captured}"
    );
}
