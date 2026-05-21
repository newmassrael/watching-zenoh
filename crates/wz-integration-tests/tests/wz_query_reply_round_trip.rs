// SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! R121j-6-e2e — wz↔wz z_get-side Query/Reply round-trip
//! integration test.
//!
//! Pairs two wz-ap-demo instances across a TCP loopback so the
//! z_get-side ReplyRegistry landed in R121j-6-registry (reply.rs:
//! pending rid table + per-rid on_reply / on_final callbacks +
//! Final-driven auto-unregister) and the wz-ap-demo CLI plumbing
//! landed in R121j-6-e2e (`--on-query-reply-log` /
//! `--on-query-final-log` + observer fan-out) round-trip end-to-end
//! on a real socket.
//!
//! Test flow:
//!   1. Pick a free TCP port.
//!   2. Spawn `wz-ap-demo --listen <addr> --queryable demo/** --reply
//!      <text>` as the acceptor + queryable.
//!   3. Wait up to 5s for the acceptor's stderr to contain
//!      "listening on" — bind succeeded.
//!   4. Spawn `wz-ap-demo --connect <addr> --query demo/test
//!      --on-query-reply-log --on-query-final-log` as the initiator +
//!      query emitter + reply consumer.
//!   5. Wait up to 5s for the initiator's stderr to contain
//!      "connected to" — dial succeeded.
//!   6. Wait up to 10s for the initiator's stderr to contain
//!      "REPLY RECEIVED" — the full 4-way handshake completed AND
//!      the inbound Response(Reply) reached the ReplyRegistry
//!      through the production poll loop (drive_session_until_terminal
//!      → observer → reply_registry.dispatch_iteration_event) and the
//!      registered on_reply callback fired with the matched rid +
//!      resolved keyexpr literal.
//!   7. Wait up to 10s for "FINAL RECEIVED" — the matching
//!      ResponseFinal traversed the same path, the on_final callback
//!      fired, and the pending entry was auto-unregistered.
//!   8. Belt-and-suspenders assertions on the rid + keyexpr literal +
//!      reply payload so a regression on any of the three localises
//!      here. The reply text is configured via `--reply` on the
//!      acceptor side; assertion uses the exact same value to keep
//!      the test independent of any default-payload drift.
//!   9. SIGTERM both children + surface captured stderr on any
//!      failed assertion.
//!
//! Differs from wz_queryable_round_trip.rs in that this test
//! asserts on the INITIATOR side (z_get consumes the reply chain)
//! whereas the sister test asserts on the ACCEPTOR side (queryable
//! produces the reply chain). Together they pin both halves of the
//! Q/R wire round-trip in production-shape code (TCP → stream
//! envelope → Frame → parse_frame_payload → NetworkMessage::Response
//! / ResponseFinal → ReplyRegistry → callback).

use std::io::{Read, Seek, SeekFrom};
use std::net::TcpListener;
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

fn project_root() -> PathBuf {
    let manifest_dir =
        std::env::var("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR set by cargo");
    PathBuf::from(manifest_dir)
        .parent()
        .and_then(|p| p.parent())
        .map(|p| p.to_path_buf())
        .expect("project root resolves from CARGO_MANIFEST_DIR")
}

fn wz_ap_demo_binary() -> PathBuf {
    let crates_dir = project_root().join("crates");
    let candidates = [
        crates_dir.join("target/debug/wz-ap-demo"),
        crates_dir.join("target/release/wz-ap-demo"),
    ];
    for c in &candidates {
        if c.is_file() {
            return c.clone();
        }
    }
    panic!(
        "wz-ap-demo binary not found in {:?}; run `cargo build -p wz-ap-demo` first",
        candidates
    );
}

fn pick_free_port() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind 127.0.0.1:0");
    let port = listener.local_addr().expect("local_addr").port();
    drop(listener);
    port
}

fn read_captured(file: &mut std::fs::File) -> String {
    file.seek(SeekFrom::Start(0)).expect("seek to start");
    let mut s = String::new();
    file.read_to_string(&mut s).expect("read captured output");
    s
}

fn wait_for_substring(
    file: &mut std::fs::File,
    needle: &str,
    timeout: Duration,
) -> Result<String, String> {
    let deadline = Instant::now() + timeout;
    loop {
        let captured = read_captured(file);
        if captured.contains(needle) {
            return Ok(captured);
        }
        if Instant::now() >= deadline {
            return Err(captured);
        }
        thread::sleep(Duration::from_millis(50));
    }
}

#[test]
fn wz_initiator_consumes_reply_chain_from_wz_queryable() {
    let demo = wz_ap_demo_binary();
    let port = pick_free_port();
    let addr = format!("127.0.0.1:{port}");
    let queryable_pattern = "demo/**";
    let reply_text = "value-from-queryable";
    let query_keyexpr = "demo/test";

    // ── wz acceptor (queryable side) ────────────────────────────
    let acceptor_stderr = tempfile::tempfile().expect("tempfile for acceptor stderr");
    let acceptor_stderr_writer =
        acceptor_stderr.try_clone().expect("dup acceptor stderr handle");
    let mut acceptor_stderr_reader = acceptor_stderr;

    let mut acceptor_child = Command::new(&demo)
        .arg("--listen")
        .arg(&addr)
        .arg("--queryable")
        .arg(queryable_pattern)
        .arg("--reply")
        .arg(reply_text)
        .env("RUST_LOG", "info")
        .stdout(Stdio::null())
        .stderr(Stdio::from(acceptor_stderr_writer))
        .spawn()
        .expect("spawn wz-ap-demo --listen --queryable");

    let bound = wait_for_substring(
        &mut acceptor_stderr_reader,
        "listening on",
        Duration::from_secs(5),
    );
    if let Err(captured) = &bound {
        let _ = acceptor_child.kill();
        let _ = acceptor_child.wait();
        panic!(
            "wz-ap-demo --listen --queryable did not log 'listening on' within 5s\n\
             --- captured acceptor stderr ---\n{captured}"
        );
    }

    // ── wz initiator (z_get side: --query + --on-query-*-log) ───
    let initiator_stderr = tempfile::tempfile().expect("tempfile for initiator stderr");
    let initiator_stderr_writer =
        initiator_stderr.try_clone().expect("dup initiator stderr handle");
    let mut initiator_stderr_reader = initiator_stderr;

    let mut initiator_child = Command::new(&demo)
        .arg("--connect")
        .arg(&addr)
        .arg("--query")
        .arg(query_keyexpr)
        .arg("--on-query-reply-log")
        .arg("--on-query-final-log")
        .env("RUST_LOG", "info")
        .stdout(Stdio::null())
        .stderr(Stdio::from(initiator_stderr_writer))
        .spawn()
        .expect("spawn wz-ap-demo --connect --query --on-query-*-log");

    let dialed = wait_for_substring(
        &mut initiator_stderr_reader,
        "connected to",
        Duration::from_secs(5),
    );
    let reply_recv = wait_for_substring(
        &mut initiator_stderr_reader,
        "REPLY RECEIVED",
        Duration::from_secs(10),
    );
    let final_recv = wait_for_substring(
        &mut initiator_stderr_reader,
        "FINAL RECEIVED",
        Duration::from_secs(10),
    );

    let _ = initiator_child.kill();
    let _ = initiator_child.wait();
    let _ = acceptor_child.kill();
    let _ = acceptor_child.wait();

    let acceptor_captured = read_captured(&mut acceptor_stderr_reader);
    let initiator_captured = read_captured(&mut initiator_stderr_reader);
    eprintln!("--- captured wz acceptor stderr ---\n{acceptor_captured}");
    eprintln!("--- captured wz initiator stderr ---\n{initiator_captured}");

    if let Err(c) = &dialed {
        panic!(
            "wz-ap-demo --connect did not log 'connected to' within 5s — initiator \
             TCP dial against {addr} failed.\n\
             --- captured initiator stderr ---\n{c}\n\
             --- captured acceptor stderr ---\n{acceptor_captured}"
        );
    }

    let reply_text_captured = match reply_recv {
        Ok(c) => c,
        Err(c) => panic!(
            "wz initiator did not log 'REPLY RECEIVED' within 10s — z_get-side \
             Reply consumption regressed somewhere between Response(Reply) emit \
             (acceptor side) and ReplyRegistry dispatch (initiator side).\n\
             --- captured initiator stderr at deadline ---\n{c}\n\
             --- captured acceptor stderr at deadline ---\n{acceptor_captured}"
        ),
    };
    let final_text_captured = match final_recv {
        Ok(c) => c,
        Err(c) => panic!(
            "wz initiator did not log 'FINAL RECEIVED' within 10s — the \
             ResponseFinal terminator either never arrived or the on_final \
             callback did not fire.\n\
             --- captured initiator stderr at deadline ---\n{c}\n\
             --- captured acceptor stderr at deadline ---\n{acceptor_captured}"
        ),
    };

    // The initiator's on_reply callback logs:
    //   "REPLY RECEIVED rid=1 keyexpr='demo/test' body=Put payload=\"value-from-queryable\""
    // Three substring assertions so a regression on any of (rid echo,
    // resolved keyexpr literal, configured reply payload, body arm)
    // localises here.
    assert!(
        reply_text_captured.contains("rid=1"),
        "REPLY RECEIVED line lacks 'rid=1' — initiator's query_task hard-codes \
         QUERY_RID=1 and the inbound Response.request_id must echo the outbound \
         Request.rid verbatim.\n\
         --- initiator stderr ---\n{reply_text_captured}"
    );
    assert!(
        reply_text_captured.contains(&format!("keyexpr='{query_keyexpr}'")),
        "REPLY RECEIVED line lacks keyexpr='{query_keyexpr}' — the queryable \
         responder builds the Reply keyexpr in literal form (mapping_id=0 + \
         suffix=Some(literal)) so the initiator's resolve_wireexpr should yield \
         the exact same literal.\n\
         --- initiator stderr ---\n{reply_text_captured}"
    );
    assert!(
        reply_text_captured.contains(&format!("payload=\"{reply_text}\"")),
        "REPLY RECEIVED line lacks payload={reply_text:?} — the queryable's \
         configured reply payload is not surfacing through MsgPut.payload + \
         InboundReplyBody::Put.\n\
         --- initiator stderr ---\n{reply_text_captured}"
    );
    assert!(
        reply_text_captured.contains("body=Put"),
        "REPLY RECEIVED line lacks 'body=Put' — the Reply inner-body arm should \
         be MsgPut for a non-Del / non-Err responder.send_reply() call.\n\
         --- initiator stderr ---\n{reply_text_captured}"
    );

    assert!(
        final_text_captured.contains("FINAL RECEIVED rid=1"),
        "FINAL RECEIVED line lacks 'rid=1' — the on_final callback should \
         receive the same rid the registry was bound to.\n\
         --- initiator stderr ---\n{final_text_captured}"
    );

    // Acceptor-side belt-and-suspenders: the queryable callback's
    // QUERYABLE FIRED line must also be present in the acceptor capture
    // (proves the OUTBOUND path on the responder side actually ran).
    // This is a regression backstop against accidentally claiming a
    // green test when the acceptor returned no reply but the initiator
    // happened to log something else.
    assert!(
        acceptor_captured.contains("QUERYABLE FIRED"),
        "wz acceptor stderr lacks 'QUERYABLE FIRED' — the queryable callback \
         never ran, which would mean the initiator's REPLY RECEIVED matched on \
         stale state or a reply not produced by this run.\n\
         --- acceptor stderr ---\n{acceptor_captured}"
    );
}
