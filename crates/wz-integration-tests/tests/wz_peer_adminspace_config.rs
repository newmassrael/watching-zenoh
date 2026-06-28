// SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! R311y45 (§5.23 Phase 2b) — a ROUTING PEER answers its OWN adminspace
//! `config` GET over the wire, reading its forwarder-bound `WzConfig`.
//!
//! This is the §5.23 combined-node payoff: ONE `WzConfig` instance both drives
//! the routing peer's forwarder (interceptor install) AND answers the admin
//! config GET — the runtime composition the R311y42 review found missing.
//!
//! Scope of the proof: this asserts config-GET-over-the-wire WORKS and (by
//! construction) the single shared instance serves both surfaces. The served
//! JSON carries the handshake-fixed read-at-open fields (batch/lease/whatami)
//! AND, R311y49, the LIVE ACL deny-list (acl_deny) — here empty, since A has no
//! startup ACL, but its presence proves the GET-observable interceptor view
//! crosses the wire. The runtime FLIP ([] -> populated after a config-write) is
//! proven by the data-plane e2e wz_peer_adminspace_config_write + the unit
//! wzconfig_to_admin_json_reflects_a_reconfigure.
//!
//! Test flow (reuses the query-reply e2e harness, `wz_query_reply_round_trip`):
//!   1. Spawn peer A: `wz-ap-demo --peer <addr> --config-queryable`. A hosts a
//!      forwarder-local admin queryable on `@/<A_zid>/peer/**` (R311y44
//!      self-dispatch + R311y45 admin handler reading the shared WzConfig).
//!   2. Wait for A's `adminspace config GET at <key>` log; scrape the exact
//!      config keyexpr (so B need not derive A's port-derived zid).
//!   3. Spawn client B: `--connect <addr> --query <key> --on-query-reply-log`.
//!      B's z_get routes to A; A's forward_request finds no remote queryable
//!      (the admin key is self-unique), self-dispatches to the admin handler,
//!      which replies the read-at-open `WzConfig` JSON; the reply unwinds to B.
//!   4. Assert B logs `REPLY RECEIVED` carrying the config keyexpr + the typed
//!      config JSON (`"whatami":"peer"` + `"batch_size":65535`).

use std::process::{Command, Stdio};
use std::time::Duration;

use wz_integration_tests::common::{
    read_captured, wait_for_substring, wz_ap_demo_binary, ChildGuard, PortReservation,
};

#[test]
#[ignore = "binary-dep e2e (wz-ap-demo bin); Layer E runs via --ignored"]
fn wz_peer_admin_config_get_over_the_wire() {
    let demo = wz_ap_demo_binary();
    let port_res = PortReservation::pick();
    let addr = format!("127.0.0.1:{}", port_res.port());

    // ── peer A (routing peer hosting its adminspace) ────────────────
    let a_stderr = tempfile::tempfile().expect("tempfile for peer A stderr");
    let a_writer = a_stderr.try_clone().expect("dup peer A stderr handle");
    let mut a_reader = a_stderr;

    let mut a_child = ChildGuard::wrap(
        "wz-ap-demo peer A (--peer --config-queryable)",
        Command::new(&demo)
            .arg("--peer")
            .arg(&addr)
            .arg("--config-queryable")
            .env("RUST_LOG", "info")
            .stdout(Stdio::null())
            .stderr(Stdio::from(a_writer))
            .spawn()
            .expect("spawn wz-ap-demo --peer --config-queryable"),
    );

    // A logs `adminspace config GET at @/<zid>/peer/config` once it has bound and
    // registered the forwarder-hosted admin — scrape the exact key for B's query.
    let a_ready = wait_for_substring(
        &mut a_reader,
        "adminspace config GET at ",
        Duration::from_secs(5),
    );
    let a_captured = match a_ready {
        Ok(c) => c,
        Err(c) => {
            let _ = a_child.child_mut().kill();
            let _ = a_child.child_mut().wait();
            panic!(
                "peer A did not log 'adminspace config GET at' within 5s — the \
                 --config-queryable admin host did not register.\n\
                 --- captured peer A stderr ---\n{c}"
            );
        }
    };
    let config_key = a_captured
        .lines()
        .find_map(|l| {
            l.split_once("adminspace config GET at ")
                .map(|(_, rest)| rest.trim().to_string())
        })
        .expect("peer A logged the admin config keyexpr");
    assert!(
        config_key.starts_with("@/") && config_key.ends_with("/peer/config"),
        "scraped admin config key has the expected @/<zid>/peer/config shape: {config_key}"
    );
    // A bound + registered; release the port-alloc mutex.
    drop(port_res);

    // ── client B (z_get the admin config over the wire) ─────────────
    let b_stderr = tempfile::tempfile().expect("tempfile for client B stderr");
    let b_writer = b_stderr.try_clone().expect("dup client B stderr handle");
    let mut b_reader = b_stderr;

    let mut b_child = ChildGuard::wrap(
        "wz-ap-demo client B (--connect --query --on-query-reply-log)",
        Command::new(&demo)
            .arg("--connect")
            .arg(&addr)
            .arg("--query")
            .arg(&config_key)
            .arg("--on-query-reply-log")
            .env("RUST_LOG", "info")
            .stdout(Stdio::null())
            .stderr(Stdio::from(b_writer))
            .spawn()
            .expect("spawn wz-ap-demo --connect --query --on-query-reply-log"),
    );

    let dialed = wait_for_substring(&mut b_reader, "connected to", Duration::from_secs(5));
    let reply_recv = wait_for_substring(&mut b_reader, "REPLY RECEIVED", Duration::from_secs(10));

    let _ = b_child.child_mut().kill();
    let _ = b_child.child_mut().wait();
    let _ = a_child.child_mut().kill();
    let _ = a_child.child_mut().wait();

    let a_final = read_captured(&mut a_reader);
    let b_final = read_captured(&mut b_reader);
    eprintln!("--- captured peer A stderr ---\n{a_final}");
    eprintln!("--- captured client B stderr ---\n{b_final}");

    if let Err(c) = &dialed {
        panic!(
            "client B did not log 'connected to' within 5s — TCP dial against {addr} \
             (peer A) failed.\n--- B stderr ---\n{c}\n--- A stderr ---\n{a_final}"
        );
    }

    let reply = match reply_recv {
        Ok(c) => c,
        Err(c) => panic!(
            "client B did not log 'REPLY RECEIVED' within 10s — the routing peer's \
             forwarder-hosted admin config GET did not answer over the wire.\n\
             --- B stderr at deadline ---\n{c}\n--- A stderr ---\n{a_final}"
        ),
    };

    // The reply is keyed to the config sub-key (the handler replies under
    // config_key via reply_keyed_encoded, R311y45) and carries the typed
    // read-at-open WzConfig JSON read from A's LIVE shared instance.
    assert!(
        reply.contains(&format!("keyexpr='{config_key}'")),
        "REPLY RECEIVED lacks keyexpr='{config_key}' — the admin reply must be keyed \
         to the config sub-key.\n--- B stderr ---\n{reply}"
    );
    assert!(
        reply.contains("body=Put"),
        "REPLY RECEIVED lacks 'body=Put' — the admin reply should be a Put-form \
         Reply carrying the config JSON.\n--- B stderr ---\n{reply}"
    );
    // The demo's reply log debug-escapes the JSON payload, so the served config
    // appears with backslash-escaped quotes (e.g. \"whatami\":\"peer\").
    assert!(
        reply.contains(r#"\"whatami\":\"peer\""#),
        "REPLY RECEIVED lacks the typed config field whatami=peer — the \
         forwarder-hosted admin did not serve A's WzConfig.\n--- B stderr ---\n{reply}"
    );
    assert!(
        reply.contains(r#"\"batch_size\":65535"#),
        "REPLY RECEIVED lacks batch_size=65535 — the read-at-open mirror (the \
         0-sentinel resolves to the effective 65535) is not in the served config.\n\
         --- B stderr ---\n{reply}"
    );
    // R311y49/y50 — the served JSON now carries the LIVE ACL view: `acl_default`
    // (the base verdict) + `acl_deny` (the denied-keyexpr list). A has no startup
    // --acl-deny, so it is the open baseline ("allow" + []); the PRESENCE of both
    // proves the GET-observable interceptor view crosses the wire (a runtime
    // config-write flips acl_deny [] -> populated — proven by the unit flip + the
    // 3-process GET-flip e2e in wz_peer_adminspace_config_write).
    assert!(
        reply.contains(r#"\"acl_default\":\"allow\""#),
        "REPLY RECEIVED lacks acl_default=allow — the GET-observable ACL base verdict \
         (R311y50) is not in the served config.\n--- B stderr ---\n{reply}"
    );
    assert!(
        reply.contains(r#"\"acl_deny\":[]"#),
        "REPLY RECEIVED lacks the acl_deny array — the GET-observable interceptor \
         view (R311y49) is not in the served config.\n--- B stderr ---\n{reply}"
    );
}
