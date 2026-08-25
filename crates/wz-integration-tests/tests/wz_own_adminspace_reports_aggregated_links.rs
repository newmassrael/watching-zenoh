// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! wz's OWN adminspace reports a multilink session's aggregated links (R311y473).
//!
//! R311y472 proved `transport-multilink` across the wire by asking ZENOH how many
//! links it had bound to wz's session, because wz's own adminspace could not be
//! asked: the `sessions[]` array was hard-coded empty at both admin hosts, and
//! `to_admin_json` rendered neither `max_links` nor the aggregated link set. That
//! was the atom's named S5 residual, and R311y472's carry recorded it as the next
//! thing this atom needs — *"That is code, not a test."*
//!
//! This leg is the read side of the code that closed it. Same topology as y472 (a
//! `--max-links 2` wz peer dialing ONE zenohd twice), but the question is put to
//! WZ's adminspace instead of zenoh's.
//!
//! ## What makes this a measurement and not a restatement
//!
//! Asking wz to report its own link count is, on its face, exactly the wz-side
//! bookkeeping y472 refused to trust. Two things keep it honest:
//!
//!   1. The CALIBRATION TWIN. The same wz argv runs against a STOCK zenohd, whose
//!      `max_links` defaults to 1 and which therefore REFUSES the second dial. wz's
//!      own adminspace must then report ONE link. So the number wz renders tracks
//!      the ROUTER's budget — a foreign process's configuration — and cannot be a
//!      wz-side constant, a hard-coded 2, or an echo of `--max-links`.
//!   2. The SESSION COUNT, asserted alongside the link count, so a rendering that
//!      split the aggregate into two single-link sessions could never pass as an
//!      aggregated one. A naive count of link objects in the document cannot tell
//!      those apart, which is why y472 built a structural parser — and this leg
//!      reuses that same parser, pointed at wz.
//!
//! Reusing `parse_zenoh_admin_sessions` is itself an assertion. It was written
//! against zenohd's `@/<zid>/router` body; that it reads wz's `@/<zid>/peer` body
//! unchanged is the claim that wz's `local_data` rendering is the shape a zenoh
//! admin client expects, not merely a shape wz can read back.
//!
//! ## Assertion order
//!
//! The link count is asserted BEFORE wz's aggregation log line, for the reason
//! y472 recorded after measuring it: under a wire damage the peer correctly
//! DECLINES to claim aggregation, so a leading log-line assertion fires first and
//! the verdict is never evaluated — decorative under the whole damage space. The
//! log line rides in the failure message instead, and gets its own assertion after
//! the verdict, where it catches the reverse disagreement.
//!
//! Opt-in (run-ci Layer Z): zenohd is an external binary. Serialized with the
//! other zenohd legs (`--test-threads=1`).

use std::process::{Command, Stdio};
use std::time::Duration;

use wz_integration_tests::common::{
    demo_log_filter, line_with, parse_zenoh_admin_sessions, spawn_on_ephemeral_port,
    spawn_zenohd_multilink_on_ephemeral_tcp, spawn_zenohd_on_ephemeral_tcp, wait_for_substring,
    wz_ap_demo_binary, ChildGuard, ZenohSession,
};

/// The wz peer's PINNED routing zid, as passed to `--zid`. Shared with the y472
/// leg's value so the two read the same node.
const WZ_PEER_ZID_ARG: &str = "70730002";

/// The needle the wz peer emits once it has joined a second physical link onto an
/// existing session. NOT the verdict here — see the module doc on ordering.
const WZ_AGGREGATED_NEEDLE: &str = "link AGGREGATED to zid";

/// Distinct pinned zids for the two back-to-back admin queriers. See
/// [`query_wz_admin`] for why sharing the demo's stock zid does not work here.
const ROOT_QUERIER_ZID: &str = "0ad10001";
const CONFIG_QUERIER_ZID: &str = "0ad10002";

/// The line the `--config-queryable` host logs once its admin queryable is bound,
/// carrying the node's own config keyexpr. Scraped rather than derived, so the
/// leg never has to reproduce wz's zid-hex rendering by hand.
const ADMIN_KEY_NEEDLE: &str = "adminspace config GET at ";

/// GET `key` off a live wz node with a second wz process and return the reply body
/// it sent, unescaped.
///
/// The querier is a separate process for the same reason y472's was: a value read
/// out of the aggregating node's own memory would prove nothing about what that
/// node PUBLISHES. It connects as a plain client, so it shows up in the reply as
/// its own `whatami:"client"` session and cannot be confused with the router.
///
/// `zid` is a PARAMETER, not the demo default, and this leg does not work without
/// that. It makes two GETs back to back, and the wz peer's face table is zid-keyed:
/// with both queriers on the stock `01020304` the second one connects while the
/// first's face is still held under that key, and its transport is torn down before
/// it can emit — measured, as `TransportUnavailable` from the querier's query task.
/// Run by hand with seconds between them they both succeed, which is exactly what
/// makes this the kind of race a fast test finds and a manual check does not.
///
/// The name carries no test-family token by accident: Layer C0's scanner binds a
/// test attribute on a preceding line to the next `fn`, so helpers here are named
/// so a red names the helper.
fn query_wz_admin(port: u16, key: &str, zid: &str) -> String {
    const REPLY_NEEDLE: &str = "REPLY RECEIVED";
    let demo = wz_ap_demo_binary();
    let stderr = tempfile::tempfile().expect("tempfile for wz admin querier stderr");
    let writer = stderr
        .try_clone()
        .expect("dup wz admin querier stderr handle");
    let mut reader = stderr;
    let mut querier = ChildGuard::wrap(
        "wz-ap-demo (wz adminspace querier)",
        Command::new(&demo)
            .arg("--connect")
            .arg(format!("127.0.0.1:{port}"))
            .arg("--query")
            .arg(key)
            .arg("--zid")
            .arg(zid)
            .arg("--on-query-reply-log")
            .env("RUST_LOG", demo_log_filter())
            .stdout(Stdio::null())
            .stderr(Stdio::from(writer))
            .spawn()
            .expect("spawn wz-ap-demo adminspace querier"),
    );
    let captured = wait_for_substring(&mut reader, REPLY_NEEDLE, Duration::from_secs(20));
    let _ = querier.child_mut().kill();
    let _ = querier.child_mut().wait();
    let captured = captured
        .unwrap_or_else(|e| panic!("the wz peer never answered the admin GET on {key}: {e}"));
    let line = line_with(&captured, REPLY_NEEDLE)
        .unwrap_or_else(|| panic!("no {REPLY_NEEDLE} line in the querier capture:\n{captured}"));
    // The payload is Debug-formatted into the log line, so its quotes arrive
    // escaped; nothing else in an admin body is escaped.
    line.replace("\\\"", "\"")
}

/// What one run of the shared fixture observed.
struct AdminObservation {
    /// wz's OWN `sessions[]`, parsed with the parser built for zenoh's.
    sessions: Vec<ZenohSession>,
    /// wz's OWN `config` body — where `max_links` became GET-observable.
    config: String,
    /// wz's aggregation log line, if it claimed one.
    aggregated: Option<String>,
}

/// Run the SHARED fixture against a zenohd on `port`: a `--max-links 2` wz peer
/// that dials it twice and hosts its own adminspace, then wz's account of the
/// result. The proof and its twin differ only in which zenohd the port belongs to,
/// so the twin is a twin by construction rather than by two copies kept in step.
fn observe_wz_admin_against(port: u16) -> AdminObservation {
    let demo = wz_ap_demo_binary();
    let target = format!("127.0.0.1:{port}");
    let stderr = tempfile::tempfile().expect("tempfile for wz peer stderr");
    let (mut peer, mut reader, peer_port) = spawn_on_ephemeral_port(
        &demo,
        &[
            "--peer",
            "127.0.0.1:0",
            // The same target LISTED TWICE opens two physical links to one zid;
            // `--max-links 2` is what lets the second be a JOIN, not a new session.
            "--connect",
            &format!("{target},{target}"),
            "--max-links",
            "2",
            "--zid",
            WZ_PEER_ZID_ARG,
            // The whole point of this leg: the node must HOST its own adminspace.
            "--config-queryable",
        ],
        "peer: listening on 127.0.0.1:",
        "wz peer (--max-links 2, --config-queryable)",
        stderr,
    );

    // Barrier 1: the admin queryable is bound, and the log carries its exact key.
    let admin_key = wait_for_substring(&mut reader, ADMIN_KEY_NEEDLE, Duration::from_secs(20))
        .ok()
        .and_then(|c| line_with(&c, ADMIN_KEY_NEEDLE))
        .and_then(|l| {
            l.split(ADMIN_KEY_NEEDLE)
                .nth(1)
                .map(|k| k.trim().to_string())
        });

    // Barrier 2: a link to THIS router is up. The needle names the peer ADDRESS,
    // not a face INDEX — the two dials race, so either can be the survivor.
    let face_needle = format!(" UP (peer {target}");
    let face_up = wait_for_substring(&mut reader, &face_needle, Duration::from_secs(20));

    // wz's own aggregation claim, captured but NOT asserted here: the caller
    // decides what it means, and in the twin its ABSENCE is what is expected.
    let aggregated = wait_for_substring(&mut reader, WZ_AGGREGATED_NEEDLE, Duration::from_secs(10))
        .ok()
        .and_then(|c| line_with(&c, WZ_AGGREGATED_NEEDLE));

    let observed = match (&face_up, &admin_key) {
        (Ok(_), Some(config_key)) => {
            // The root key (`local_data`, carrying `sessions[]`) is the config key
            // without its trailing leaf; a GET on the bare root fires local_data
            // ONLY, since config is one chunk deeper.
            let root_key = config_key
                .strip_suffix("/config")
                .unwrap_or_else(|| {
                    panic!("scraped admin key is not a .../config key: {config_key}")
                })
                .to_string();
            let sessions =
                parse_zenoh_admin_sessions(&query_wz_admin(peer_port, &root_key, ROOT_QUERIER_ZID));
            let config = query_wz_admin(peer_port, config_key, CONFIG_QUERIER_ZID);
            Some((sessions, config))
        }
        _ => None,
    };

    let _ = peer.child_mut().kill();
    let _ = peer.child_mut().wait();

    // Carry the peer's own capture into the diagnosis: a bare "no face" red is
    // ambiguous between a refused dial, a mis-parsed flag and a dead router.
    if let Err(captured) = &face_up {
        panic!(
            "the wz peer never brought a face up against zenohd on 127.0.0.1:{port}\n\
             --- captured wz peer stderr ---\n{captured}"
        );
    }
    let admin_key = admin_key.expect(
        "the wz peer never logged its adminspace key — --config-queryable did not register, \
         so there was no wz admin surface to ask",
    );
    let (sessions, config) = observed
        .unwrap_or_else(|| panic!("no admin observation despite a live face and key {admin_key}"));
    AdminObservation {
        sessions,
        config,
        aggregated,
    }
}

/// Select the ONE session wz reports for the ROUTER it dialed.
///
/// The querier processes connect as clients and appear as their own
/// `whatami:"client"` entries, so the router selection is unambiguous. Asserting
/// that exactly one such entry exists is the load-bearing half: a router that
/// REFUSED the aggregation leaves wz holding TWO single-link router sessions, and
/// that is the state this leg has to be able to tell from the aggregated one.
fn the_router_session(sessions: &[ZenohSession]) -> &ZenohSession {
    let routers: Vec<&ZenohSession> = sessions.iter().filter(|s| s.whatami == "router").collect();
    assert_eq!(
        routers.len(),
        1,
        "expected wz to report exactly ONE whatami=router session; {} of them is what a \
         REFUSED aggregation looks like (two separate single-link transports to the same \
         router). Full reply: {sessions:?}",
        routers.len()
    );
    routers[0]
}

/// LEG 1 — the proof. Against a `max_links:2` zenohd dialed twice, WZ's OWN
/// adminspace reports ONE router session carrying TWO links, and its config body
/// reports the aggregation budget that produced it.
// wz dials zenohd (twice), so the direction is `wz->zenohd` by the corpus
// convention of who DIALS.
// wz-proves: adminspace-core wz->zenohd
#[test]
#[ignore = "binary-dep e2e: needs zenohd + wz-ap-demo[+routing-peer,transport-multilink,adminspace-core]; runs via --ignored"]
fn wz_adminspace_reports_two_links_on_one_zenohd_session() {
    let (zenohd, port) = spawn_zenohd_multilink_on_ephemeral_tcp(2, || {
        tempfile::tempfile().expect("tempfile for zenohd readiness probe stderr")
    });
    let observed = observe_wz_admin_against(port);
    let mut zenohd = zenohd;
    let _ = zenohd.child_mut().kill();
    let _ = zenohd.child_mut().wait();

    // THE VERDICT, asserted FIRST — see the module doc on ordering. Before
    // R311y473 this array was hard-coded empty, so this assertion read 0 links on
    // a session that did not exist in the report at all.
    let session = the_router_session(&observed.sessions);
    assert_eq!(
        session.links, 2,
        "wz's own adminspace reports {} link(s) on its router session, not 2 — the \
         aggregated link set is not reaching local_data.\n\
         wz's own JOIN line was: {:?}\n\
         full reply: {:?}",
        session.links, observed.aggregated, observed.sessions
    );

    // The config half of the same residual: the budget is now readable over the
    // wire, not only off a startup log line.
    assert!(
        observed.config.contains(r#""max_links":2"#),
        "wz's admin config body does not report the --max-links 2 budget that produced \
         the aggregation above: {}",
        observed.config
    );

    // The reverse disagreement, which the count alone cannot catch: the admin view
    // says two links while the node never registered the join.
    let aggregated = observed.aggregated.expect(
        "wz's adminspace reports TWO links on one session, but the peer never logged a \
         multilink JOIN — the admin view and the session table disagree",
    );
    assert!(
        aggregated.contains("live links now 2"),
        "wz logged a JOIN that did not reach 2 live links while its admin view reports 2: \
         {aggregated}"
    );
}

/// LEG 2 — the twin. The SAME wz argv against a STOCK zenohd, whose `max_links`
/// defaults to 1: wz's own adminspace must report ONE link. This is what makes leg
/// 1 a discriminator rather than wz agreeing with itself — the count it renders
/// follows a FOREIGN process's configuration.
// wz-proves: none -- the CALIBRATION twin of the leg above. An aggregation that
// correctly does not happen witnesses no atom's cross-impl behaviour; its job is to
// show that the sibling's rendered count tracks the router's budget.
#[test]
#[ignore = "binary-dep e2e: needs zenohd + wz-ap-demo[+routing-peer,transport-multilink,adminspace-core]; runs via --ignored"]
fn wz_adminspace_reports_one_link_against_a_stock_zenohd() {
    let (zenohd, port) = spawn_zenohd_on_ephemeral_tcp(|| {
        tempfile::tempfile().expect("tempfile for zenohd readiness probe stderr")
    });
    let observed = observe_wz_admin_against(port);
    let mut zenohd = zenohd;
    let _ = zenohd.child_mut().kill();
    let _ = zenohd.child_mut().wait();

    let session = the_router_session(&observed.sessions);
    assert_eq!(
        session.links, 1,
        "wz's own adminspace reports {} link(s) against a STOCK zenohd (max_links=1), which \
         must refuse the second dial. If this is not 1, leg 1's count is not tracking the \
         router's budget and is therefore not a discriminator. Full reply: {:?}",
        session.links, observed.sessions
    );
    assert_eq!(
        observed.aggregated, None,
        "wz reported a multilink JOIN against a router whose max_links is 1; either the stock \
         default moved or wz aggregated without the router's consent"
    );
    // The budget is what wz OFFERED, and it is reported whether or not the router
    // granted it — so this key is not a proxy for "aggregation happened", and the
    // link count above is doing the discriminating on its own.
    assert!(
        observed.config.contains(r#""max_links":2"#),
        "wz's admin config must report the OFFERED budget even when the router refused it: {}",
        observed.config
    );
}
