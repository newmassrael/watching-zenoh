// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! R311y509 — the linkstate PEER's liveliness-TOKEN plane, witnessed by real
//! zenoh-pico processes on BOTH ends.
//!
//! ## What this closes, and why the tree already contained the proof it was missing
//!
//! `wz_router_hat_liveliness_history_pico_interop.rs` says it outright: a `--peer`
//! node "has NO client-token plane at all — its only two mentions of one are
//! comments pointing AT the router's", so R311y461 moved its proof to a
//! `--router-hat` node. That was an accurate reading of the code and the right
//! call for that round. It was also a hole: a foreign liveliness GET through a wz
//! PEER always read empty, because the peer's inbound Declare dispatch had no
//! token arm (a client `DeclToken` fell through to the subscriber catch-all, whose
//! body match rejects it and returns) and `respond_to_interest` answered only the
//! `su()` and `qu()` planes. zenoh's own `linkstate_peer` hat answers it
//! (`hat/linkstate_peer/token.rs:659` `declare_token_interest`, folding
//! `linkstatepeer_tokens` at `:672` beside the client leaves).
//!
//! R311y509 built both tiers on the peer. This file is the foreign witness, and it
//! is deliberately the SAME shape as the router-hat file above so the two are
//! comparable: pico holds the token, pico asks, wz is the only thing in between.
//!
//! ## Two legs, because there are two tiers and they fail independently
//!
//! - [`wz_peer_replays_a_co_attached_pico_token`] — the CLIENT-LEAF tier. One wz
//!   peer, pico A holding a token on it, pico B asking the same peer. This is the
//!   exact topology the router-hat file records a `--peer` node as unable to serve.
//! - [`wz_peer_replays_a_pico_token_held_across_the_mesh`] — the MESH tier. TWO wz
//!   peers linked by `--connect`, pico A holding its token on peer B, pico C asking
//!   peer A. Nothing in the client-leaf tier can answer this: A's `client_tokens`
//!   is empty, so the reply can only come from the mesh table the token was flooded
//!   into. This is the tier whose absence made liveliness peer-local.
//!
//! Unit damage already separates the two tiers (disabling the mesh ingest reds only
//! the mesh-sourced unit test), so the split here is not decoration — each leg
//! fails to a different half of the plane.
//!
//! ## The negative arm is what makes either leg a claim
//!
//! `New alive token` is what pico logs for ANY token, so a lone green cannot
//! separate "the pre-existing token was replayed" from "some token arrived". Each
//! leg's positive arm passes `-h` to `z_sub_liveliness` and its twin omits it. That
//! flag is exactly the CURRENT bit on the wire (`history ? (CURRENT|FUTURE) :
//! FUTURE`, `vendor/zenoh-pico/src/net/liveliness.c:196-205`) and wz gates the
//! replay on that same bit (`interest.c()`), so the pair says the replay is caused
//! by the CURRENT-dump path and not by the token merely existing. The positive arm
//! is also the twin's non-vacuity control: the same binary demonstrably receives.
//!
//! ## Ordering is OWNED, never slept
//!
//! Every arm gates pico B/C's spawn on pico A's OWN declaration banner, which
//! `z_liveliness` prints only after `z_liveliness_declare_token` returns
//! (`examples/unix/c11/z_liveliness.c`). So the token provably pre-exists the
//! asking session, and "the token was late" cannot masquerade as "the plane
//! answered". The mesh leg additionally gates on peer A logging its face to peer B,
//! so the flood has a path before the token is declared.
//!
//! ## Build variant
//!
//! Plain `--features routing-peer`. The peer token plane is UNGATED — it is part of
//! what a routing peer IS, like `client_subs` beside it — so unlike the router-hat
//! file this lane needs no `routing-token-tables`, and a build that omits it does
//! NOT make these legs pass vacuously.

use std::fs::File;
use std::process::{Command, Stdio};
use std::time::Duration;

use wz_integration_tests::common::{
    graceful_terminate, listen_port, read_captured, wait_for_substring, wz_ap_demo_binary,
    zenoh_pico_cli_binary, ChildGuard,
};

/// The literal pico A declares, and the exact string a replay must carry. The
/// asking side's filter is a WILDCARD, so a sample naming THIS token is a real
/// intersect against a real declaration and never an echo of the request.
const PICO_TOKEN: &str = "group1/pico-peer-token";
const SUB_FILTER: &str = "group1/**";

/// How long a positive arm waits for the replay.
const SAMPLE_TIMEOUT: Duration = Duration::from_secs(15);

/// How long a twin waits before concluding the replay never came. ANCHORED to the
/// positive arm's bound rather than picked: half of it, so the twin cannot pass
/// merely by being asked sooner than its sibling was.
const NO_SAMPLE_WINDOW: Duration = Duration::from_secs(8);

/// Spawn a `--peer` demo on an ephemeral port, optionally dialing `connect`, and
/// read the bound port back out of its own listen log.
fn spawn_peer(label: &str, connect: Option<&str>) -> (ChildGuard, File, u16) {
    let stderr = tempfile::tempfile().expect("tempfile for peer stderr");
    let writer = stderr.try_clone().expect("dup peer stderr handle");
    let mut reader = stderr;
    let mut cmd = Command::new(wz_ap_demo_binary());
    cmd.args(["--peer", "127.0.0.1:0", "--subscribe", "**"]);
    if let Some(target) = connect {
        cmd.args(["--connect", target]);
    }
    let mut guard = ChildGuard::wrap(
        format!("liveliness-token peer {label}"),
        cmd.env("RUST_LOG", "info")
            .stdout(Stdio::null())
            .stderr(Stdio::from(writer))
            .spawn()
            .expect("spawn wz-ap-demo --peer"),
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
            "wz-ap-demo did not bind a peer listener within 5s (is the binary built \
             with --features routing-peer?)\n--- peer {label} stderr ---\n{c}"
        );
    });
    let port = listen_port(&captured);
    (guard, reader, port)
}

/// Spawn `z_liveliness` and BLOCK until it has actually declared the token. The
/// return is the guard plus its stdout reader; the caller owns teardown.
fn spawn_token_holder(endpoint: &str) -> (ChildGuard, File) {
    let stdout = tempfile::tempfile().expect("tempfile for z_liveliness stdout");
    let writer = stdout.try_clone().expect("dup z_liveliness handle");
    let mut reader = stdout;
    let mut holder = ChildGuard::wrap(
        "z_liveliness token holder (zenoh-pico)".to_string(),
        Command::new("stdbuf")
            .args(["-oL", "-eL"])
            .arg(zenoh_pico_cli_binary("z_liveliness"))
            .args(["-k", PICO_TOKEN, "-t", "30", "-e", endpoint, "-m", "client"])
            .stdout(Stdio::from(writer))
            .stderr(Stdio::inherit())
            .spawn()
            .expect("spawn z_liveliness via stdbuf"),
    );
    if let Err(captured) = wait_for_substring(
        &mut reader,
        "Press CTRL-C to undeclare liveliness token",
        Duration::from_secs(10),
    ) {
        let _ = holder.child_mut().kill();
        let _ = holder.child_mut().wait();
        panic!(
            "z_liveliness never declared '{PICO_TOKEN}' within 10s. A positive arm \
             would have nothing to replay and a twin would pass on an empty world.\n\
             --- z_liveliness stdout ---\n{captured}"
        );
    }
    (holder, reader)
}

/// Spawn the ASKING side. `history` is the one bit that differs between an arm and
/// its twin.
fn spawn_asker(endpoint: &str, history: bool) -> (ChildGuard, File) {
    let stdout = tempfile::tempfile().expect("tempfile for z_sub_liveliness stdout");
    let writer = stdout.try_clone().expect("dup z_sub_liveliness handle");
    let reader = stdout;
    let mut cmd = Command::new("stdbuf");
    cmd.args(["-oL", "-eL"])
        .arg(zenoh_pico_cli_binary("z_sub_liveliness"))
        .args(["-k", SUB_FILTER, "-e", endpoint, "-m", "client", "-n", "1"]);
    if history {
        cmd.arg("-h");
    }
    let guard = ChildGuard::wrap(
        "z_sub_liveliness asker (zenoh-pico)".to_string(),
        cmd.stdout(Stdio::from(writer))
            .stderr(Stdio::inherit())
            .spawn()
            .expect("spawn z_sub_liveliness via stdbuf"),
    );
    (guard, reader)
}

/// Wait for the replay (positive arm) or for the bound to elapse (twin), then read
/// whatever the asker actually printed.
fn collect_asker_output(reader: &mut File, history: bool) -> (bool, String) {
    let expected = format!("New alive token ('{PICO_TOKEN}')");
    if history {
        match wait_for_substring(reader, &expected, SAMPLE_TIMEOUT) {
            Ok(seen) => {
                let rest = read_captured(reader);
                (true, format!("{seen}{rest}"))
            }
            Err(captured) => (false, captured),
        }
    } else {
        // The twin cannot "wait for nothing": it sleeps its bound, then reads
        // whatever landed. Anything present is a real replay and a real failure.
        std::thread::sleep(NO_SAMPLE_WINDOW);
        let captured = read_captured(reader);
        let seen = captured.contains(&expected);
        (seen, captured)
    }
}

/// The CLIENT-LEAF tier: pico A's token and pico B's request land on the SAME wz
/// peer, so the reply comes from that peer's `client_tokens`.
fn run_client_leaf_arm(history: bool) -> String {
    let (mut peer, mut peer_reader, port) = spawn_peer("P", None);
    let endpoint = format!("tcp/127.0.0.1:{port}");

    let (mut holder, mut holder_reader) = spawn_token_holder(&endpoint);
    let (mut asker, mut asker_reader) = spawn_asker(&endpoint, history);
    let (seen, asker_captured) = collect_asker_output(&mut asker_reader, history);

    let holder_captured = read_captured(&mut holder_reader);
    let _ = asker.child_mut().kill();
    let _ = asker.child_mut().wait();
    let _ = holder.child_mut().kill();
    let _ = holder.child_mut().wait();
    graceful_terminate(peer.child_mut(), Duration::from_secs(5));
    let peer_captured = read_captured(&mut peer_reader);

    if history && !seen {
        panic!(
            "history=true, and a co-attached pico's PRE-EXISTING token was not \
             replayed by the wz peer. Expected 'New alive token' naming \
             '{PICO_TOKEN}' — the holder had declared it before the asker was \
             spawned (gated on the holder's own banner), so neither the token nor \
             the session can explain this.\n\
             --- z_sub_liveliness stdout ---\n{asker_captured}\n\
             --- z_liveliness stdout ---\n{holder_captured}\n\
             --- peer stderr ---\n{peer_captured}"
        );
    }
    asker_captured
}

/// The MESH tier: pico A's token lands on peer B, pico C asks peer A. A's
/// `client_tokens` is EMPTY for this keyexpr, so a reply can only come from the
/// mesh table B's flood populated.
fn run_mesh_arm(history: bool) -> String {
    let (mut peer_b, mut b_reader, b_port) = spawn_peer("B", None);
    // pico endpoints carry the `tcp/` scheme; wz's `--connect` takes a bare
    // socket address. Two spellings of one address, kept apart deliberately -- the
    // first draft passed the pico form to --connect and the peer refused to bind.
    let b_dial = format!("127.0.0.1:{b_port}");
    let b_endpoint = format!("tcp/{b_dial}");
    let (mut peer_a, mut a_reader, a_port) = spawn_peer("A", Some(&b_dial));
    let a_endpoint = format!("tcp/127.0.0.1:{a_port}");

    // The mesh edge must EXIST before the token is declared, or the flood has no
    // path and the leg would be measuring a race rather than the plane.
    if let Err(captured) = wait_for_substring(&mut a_reader, "face 0 UP", Duration::from_secs(10)) {
        let _ = peer_a.child_mut().kill();
        let _ = peer_b.child_mut().kill();
        panic!(
            "peer A never held a face to peer B within 10s; there is no mesh for a \
             token to cross.\n--- peer A stderr ---\n{captured}"
        );
    }

    // The token is declared on B, and the asker attaches to A.
    let (mut holder, mut holder_reader) = spawn_token_holder(&b_endpoint);
    let (mut asker, mut asker_reader) = spawn_asker(&a_endpoint, history);
    let (seen, asker_captured) = collect_asker_output(&mut asker_reader, history);

    let holder_captured = read_captured(&mut holder_reader);
    let _ = asker.child_mut().kill();
    let _ = asker.child_mut().wait();
    let _ = holder.child_mut().kill();
    let _ = holder.child_mut().wait();
    graceful_terminate(peer_a.child_mut(), Duration::from_secs(5));
    graceful_terminate(peer_b.child_mut(), Duration::from_secs(5));
    let a_captured = read_captured(&mut a_reader);
    let b_captured = read_captured(&mut b_reader);

    if history && !seen {
        panic!(
            "history=true, and a token held by a pico on the OTHER peer was not \
             replayed. Expected 'New alive token' naming '{PICO_TOKEN}'. Peer A's \
             client_tokens cannot hold it, so this is the mesh tier: either the \
             flood never carried the token or the CURRENT dump never folded it.\n\
             --- z_sub_liveliness stdout ---\n{asker_captured}\n\
             --- z_liveliness stdout ---\n{holder_captured}\n\
             --- peer A stderr ---\n{a_captured}\n\
             --- peer B stderr ---\n{b_captured}"
        );
    }
    asker_captured
}

// wz-proves: routing-token-tables pico->wz
#[test]
#[ignore = "binary-dep e2e (wz-ap-demo --features routing-peer + zenoh-pico z_liveliness/z_sub_liveliness); Layer E6 runs via --ignored"]
fn wz_peer_replays_a_co_attached_pico_token() {
    run_client_leaf_arm(true);
}

// wz-proves: none -- the twin that makes the arm above a claim rather than an
// observation. It shares every process and differs only in the `-h` flag, so its
// silence isolates the CURRENT bit; it witnesses no atom of its own.
#[test]
#[ignore = "binary-dep e2e (wz-ap-demo --features routing-peer + zenoh-pico z_liveliness/z_sub_liveliness); Layer E6 runs via --ignored"]
fn wz_peer_without_history_replays_no_co_attached_token() {
    let captured = run_client_leaf_arm(false);
    assert!(
        !captured.contains("New alive token"),
        "a FUTURE-only subscriber must not be replayed a pre-existing token; the \
         CURRENT bit is the whole difference from its twin\n\
         --- z_sub_liveliness stdout ---\n{captured}"
    );
}

// wz-proves: routing-token-tables pico->wz
#[test]
#[ignore = "binary-dep e2e (wz-ap-demo --features routing-peer + zenoh-pico z_liveliness/z_sub_liveliness); Layer E6 runs via --ignored"]
fn wz_peer_replays_a_pico_token_held_across_the_mesh() {
    run_mesh_arm(true);
}

// wz-proves: none -- the mesh leg's twin, same role as the client-leaf twin above.
#[test]
#[ignore = "binary-dep e2e (wz-ap-demo --features routing-peer + zenoh-pico z_liveliness/z_sub_liveliness); Layer E6 runs via --ignored"]
fn wz_peer_without_history_replays_no_mesh_token() {
    let captured = run_mesh_arm(false);
    assert!(
        !captured.contains("New alive token"),
        "a FUTURE-only subscriber must not be replayed a token that pre-existed it, \
         mesh-sourced or not\n--- z_sub_liveliness stdout ---\n{captured}"
    );
}
