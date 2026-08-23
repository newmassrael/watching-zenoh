// SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! R311y902 (open-debt item 396) — the AUTH chain walkers, against bytes two
//! stock zenoh processes actually wrote.
//!
//! ## The gap, and why it stayed open after R311y897
//!
//! R311y896 gave the `0x3` auth extension a walker: its body is not a value
//! but a CHAIN of method sub-extensions, and `walk_auth_body` reads it.
//! R311y897 then read the method bodies one level in — `walk_auth_usrpwd_body`
//! and `walk_pubkey_challenge_body`, the latter shared by three carriers
//! because zenoh `.transmute()`s the same bytes onto `0x4`. Every one of those
//! was judged by exactly two things: this tree's own `AuthDispatch::mux`, and
//! upstream source a person had read. Those are not two witnesses — they are
//! two things that can be wrong together, and item 396 said so.
//!
//! ## The bridge existed; the traffic was the wrong half
//!
//! Item 396 recorded that the traffic was already here —
//! `usrpwd_zenohd_interop.rs` runs a real zenohd through this exchange — and
//! that only the bridge was missing. R311y900 built that bridge for item 406
//! (`FlowDissection::message_bytes`, plus a tap leg on Layer Ewirez), so this
//! round should have been a copy of that witness one axis over.
//!
//! It was not, and the reason is worth writing down: in those tests **wz
//! dials**, and the usrpwd body that carries `{user, hmac}` is written by the
//! DIALER. Pointing the dissector at that capture would have graded wz's
//! encoder against wz's decoder — the self-witness this whole axis exists to
//! escape, and the exact mistake item 395's own caveat made when it called
//! pubkey's producer foreign because it lived in `wz-runtime-tokio`.
//!
//! So the foreign half had to be the CLIENT. A stock `zenoh_z_get` carries
//! `transport/auth/usrpwd/{user,password}` (`DEFAULT_CONFIG.json5:737-742`),
//! which makes it a usrpwd initiator, and it dials through the tap into a
//! stock zenohd holding the matching dictionary:
//!
//! ```text
//!   zenoh_z_get --cfg .../user,password ──► [tap] ──► zenohd --cfg .../dictionary_file
//!        (stock zenoh client, INITIATOR)              (stock router, ACCEPTOR)
//! ```
//!
//! No wz process is on that wire. wz appears only as the reader of the
//! synthesised pcap, which is the right shape for grading a DECODER.
//!
//! ## What each half contributes, and why both are needed
//!
//! The usrpwd handshake is not symmetric, and the two directions exercise
//! DIFFERENT walkers:
//!
//! | direction | message | the auth chain carries |
//! |---|---|---|
//! | client -> zenohd | `Init`(syn) | the method OFFER — a sub-ext with no body |
//! | zenohd -> client | `Init`(ack) | the CHALLENGE, a Z64 nonce (`SCALAR_Z64_BODIES` declares it scalar) |
//! | client -> zenohd | `Open`(syn) | `{user, hmac}` — the ZBuf body `walk_auth_usrpwd_body` reads |
//!
//! A capture of only one direction would leave `walk_auth_usrpwd_body` unfed
//! or the chain walker ungraded on the acceptor's shape.
//!
//! ## The assertion order R311y900 paid for
//!
//! That round's first run FAILED on its SET assertion: the file claimed four
//! extension bodies and the wire held six. The lesson it recorded is the order
//! — a foreign witness must say what the capture CONTAINS, as a two-sided set,
//! before it says what any reading of it should be. [`WITNESSED`] is that
//! statement here and it is asserted first.
//!
//! ## What is held against what
//!
//! `user` is asserted against the username this test spawned the client with:
//! a config value is not a constant this tree could have copied wrong, so a
//! walker that mis-framed the two ZBufs — swapping `user` and `hmac`, or
//! reading the length as part of the value — passes every self-witness in the
//! workspace and reds here.
//!
//! ## R2046 (open-debt item 419) — the other two rows, by value
//!
//! For three rounds `user` was the ONLY value this file held against anything.
//! The item recorded what that left open, and the dump printed it plainly:
//!
//! ```text
//!   A Init/usrpwd enc=Some(1) read=[]                        <- the challenge
//!   B Open/usrpwd ... hmac=<32 byte(s)>                      <- the answer
//! ```
//!
//! The acceptor's Z64 CHALLENGE showed NO reading at all — not because the
//! dissector dropped it (a scalar body's value is exactly what it should
//! report) but because this harness folded `value` away as envelope for every
//! row alike. And the `hmac` was asserted only as "non-empty ZBuf of its own",
//! which is framing, not identity: any other 32-byte span satisfied it.
//!
//! Both are closed the same way, and with material that was already in the
//! capture. The nonce is now surfaced ([`Body::value`]) and used as the KEY to
//! recompute the digest over the password this test chose, upstream's algorithm
//! reproduced in [`usrpwd_hmac`]. See
//! [`assert_the_hmac_is_the_password_keyed_by_the_challenge`] — it is the whole
//! usrpwd calculation bound to foreign bytes, where before only a username was.

use std::io::Write as _;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use hmac::{Hmac, Mac};
use sha3::Sha3_256;
use tempfile::NamedTempFile;
use wz_capture::Dissection;
use wz_integration_tests::common::{
    read_captured, wait_for_tcp_accept_alive, zenoh_core_example_binary, zenohd_binary, ChildGuard,
    PortReservation, ZENOHD_TCP_ACCEPT_BUDGET,
};
use wz_integration_tests::ext_bodies::{
    assert_no_entry_borrows_a_descendants_value, assert_witnessed_set, bodies_of, dump, Body,
    Depth, Reading, ENC_UNIT, ENC_Z64, ENC_ZBUF,
};
use wz_integration_tests::wire_tap::{synthesise_pcap, tap_proxy, Recording, Side};
use wz_session_core::passive::Direction;

/// The synthesised endpoint ports. NOT the real ones, and named because they
/// DECIDE which half `Direction::A` is — `FlowKey` orders endpoints by
/// `(addr, port)` and both are 127.0.0.1. The mapping is derived and asserted
/// below rather than written down, which is the correction R311y761 had to
/// make after a round reported wz's own frames as a router's.
const DIALER_PORT: u16 = 40_000;
const LISTENER_PORT: u16 = 7447;

/// The credentials. `USER` is what the `user` field is asserted against, so it
/// is deliberately not a value that could appear by accident in a handshake.
const USER: &str = "wz-foreign-witness-user";
const PASSWORD: &str = "wz-foreign-witness-pass";

/// `z_get -o`, and the wall clock allowed on top. The query itself is
/// scaffolding — nothing answers it — because the subject is the HANDSHAKE,
/// which completes before any query is sent.
const GET_TIMEOUT_MS: &str = "1500";
const GET_WALL_CLOCK: Duration = Duration::from_secs(20);

/// The extension bodies this capture is asserted to carry, by `ext_name`.
///
/// A SET rather than a count (R311y897's anti-vacuity shape), compared BOTH
/// ways, and asserted BEFORE any claim about a reading — the order R311y900's
/// first run paid for. A body that vanishes leaves an assertion below about
/// nothing; a body that APPEARS is a foreign reading going unjudged.
///
/// Every body, not only the auth ones: narrowing the list would let a capture
/// that had quietly stopped carrying everything else still satisfy it.
/// MEASURED, not guessed: the first run of this witness claimed three and the
/// wire held five. `patch` and `timeout` are as foreign as the auth rows and
/// are judged by their own witnesses elsewhere; listing them here is what
/// stops this file from passing on a capture that had quietly lost them.
const WITNESSED: &[&str] = &["auth", "patch", "qos", "timeout", "usrpwd"];

// R2048 — `Reading`, `Body`, the ENVELOPE / MESSAGE_NAMES tables and the
// ENC_* constants moved to `wz_integration_tests::ext_bodies`. Three witnesses
// read a capture this way and the copies had already diverged: R2046's
// direct-child lookup landed here and nowhere else. The doc that used to sit on
// each item is on the shared item now.

// R2048 — `fold_readings` / `own_child` / `collect` / `bodies_of` / `dump` /
// `assert_witnessed_set` moved to `wz_integration_tests::ext_bodies`. The fold
// this file needs is `Depth::Deep`, which is why that enum exists: the Z64
// witness beside it wants one level and the two answers are about different
// subjects, not about taste.

/// ONE extension id, THREE encodings, and a different reading for each.
///
/// This is the fact the capture turned out to carry and the reason it grades
/// the dispatch rather than only a walker. `usrpwd` occupies a single id
/// inside the auth chain, and stock zenoh puts three different bodies there
/// across one handshake:
///
/// | half | message | encoding | what it means |
/// |---|---|---|---|
/// | initiator | `Init` | UNIT | "I offer usrpwd" — no body at all |
/// | acceptor | `Init` | Z64 | the CHALLENGE nonce, declared scalar in `SCALAR_Z64_BODIES` |
/// | initiator | `Open` | ZBuf | `{user, hmac}`, the body `walk_auth_usrpwd_body` reads |
///
/// `zbuf_body_walker` is keyed on the carrier AND the name, and `walk_ext_entry`
/// selects on the encoding bits before either is asked — so a build that keyed
/// on the name alone would try to read the UNIT offer as a `{user, hmac}` pair
/// and mis-frame the whole chain. Nothing in this tree emits all three: the wz
/// producer emits the initiator's two, and the acceptor's Z64 challenge is
/// zenohd's. That is precisely what item 396 said was missing.
fn assert_one_id_three_encodings(bodies: &[Body], acceptor: Direction, initiator: Direction) {
    let want: [(Direction, &str, u64, &str); 3] = [
        (
            initiator,
            "Init",
            ENC_UNIT,
            "the method OFFER carries no body",
        ),
        (acceptor, "Init", ENC_Z64, "the CHALLENGE is one VLE nonce"),
        (initiator, "Open", ENC_ZBUF, "the response is {user, hmac}"),
    ];
    let mut covered: Vec<u64> = Vec::new();
    for (side, carrier, enc, why) in want {
        let hit = bodies
            .iter()
            .filter(|b| b.direction == side && b.carrier == carrier && b.name == "usrpwd")
            .find(|b| b.encoding == Some(enc));
        assert!(
            hit.is_some(),
            "no `usrpwd` entry on {side:?}'s {carrier} with encoding {enc} \
             ({why}). One id carries three encodings across this handshake and \
             the dispatch must select on all of them:\n{}",
            dump(bodies)
        );
        covered.push(enc);
    }
    // ANTI-VACUITY as a SET: three DISTINCT encodings, so a capture in which
    // one shape stood in for another cannot satisfy this by count.
    covered.sort_unstable();
    covered.dedup();
    assert_eq!(
        covered,
        [ENC_UNIT, ENC_Z64, ENC_ZBUF],
        "the three encodings must be distinct, not three sightings of one",
    );
}

// R2048 — `assert_no_entry_borrows_a_descendants_value` moved to
// `wz_integration_tests::ext_bodies` with the rest of the harness. It was
// written here in R2046 because a mutation SURVIVED this file; it belongs
// beside the lookup it guards, where the other two witnesses get it too.

/// Upstream's usrpwd digest, recomputed here rather than borrowed.
///
/// `zenoh_crypto::hmac::sign` is `Hmac::<Sha3_256>` over `data` keyed by `key`
/// (`commons/zenoh-crypto/src/hmac.rs:19-23`), and usrpwd calls it with
/// `key = state.nonce.to_le_bytes()` and `data = password`
/// (`.../establishment/ext/auth/usrpwd.rs:325-327` on the initiator,
/// `:420-423` on the acceptor, which recomputes and compares). Written from
/// that algorithm and not from `wz_session_core::extauth_usrpwd`'s private
/// twin on purpose: a digest borrowed from the tree under test could agree
/// with it while both disagreed with the wire.
fn usrpwd_hmac(nonce: u64, password: &[u8]) -> Vec<u8> {
    let mut mac = <Hmac<Sha3_256> as Mac>::new_from_slice(&nonce.to_le_bytes())
        .expect("HMAC accepts a key of any length");
    mac.update(password);
    mac.finalize().into_bytes().to_vec()
}

/// THE DIGEST, BY VALUE — the acceptor's challenge and the initiator's answer
/// held against each other.
///
/// R2046, open-debt item 419. Until this round the `hmac` was asserted only as
/// "a non-empty ZBuf of its own", which is a claim about FRAMING: a walker that
/// pointed at some other 32-byte span — the tail of the digest, an adjacent
/// field, the challenge echoed back — satisfied it. Only `user` was held
/// against a value, and `user` is the FIRST of the two records, so nothing in
/// the file constrained where the second one started beyond its length prefix.
///
/// Everything needed to close that was already in the capture. The challenge
/// nonce is the acceptor's Z64 body; the password is a value this test chose;
/// the algorithm is upstream's and is reproduced in [`usrpwd_hmac`]. Recomputing
/// it binds the WHOLE usrpwd calculation to foreign bytes:
///
/// | what is asserted | what a mis-read would do |
/// |---|---|
/// | the challenge row has a value at all | a scalar body reported as `read=[]` |
/// | that value keys the observed digest | a nonce read at the wrong width / offset |
/// | the digest equals HMAC(nonce, password) | an `hmac` span off by any amount |
///
/// ⚠ This is NOT producer parity, and saying so matters: `usrpwd_zenohd_interop.rs`
/// already proves wz COMPUTES this digest correctly, because a wrong one fails
/// the handshake. What is bound here is that the DISSECTOR names the right
/// bytes — which no amount of successful authentication can show.
fn assert_the_hmac_is_the_password_keyed_by_the_challenge(
    bodies: &[Body],
    acceptor: Direction,
    initiator: Direction,
) {
    // ── THE CHALLENGE, FROM THE ACCEPTOR'S HALF ───────────────────────────
    let challenge = bodies
        .iter()
        .filter(|b| b.direction == acceptor && b.carrier == "Init" && b.name == "usrpwd")
        .find(|b| b.encoding == Some(ENC_Z64))
        .unwrap_or_else(|| {
            panic!(
                "no Z64 `usrpwd` body on the acceptor's Init, so this handshake \
                 carried no challenge to key a digest with:\n{}",
                dump(bodies)
            )
        });
    let Some(Reading::Number(nonce)) = challenge.value else {
        panic!(
            "the acceptor's usrpwd CHALLENGE reached this witness with no value \
             of its own. A scalar Z64 body's value IS its reading, so a row that \
             reports none is one nothing in this file can assert against: {}",
            challenge.describe()
        )
    };

    // ── THE ANSWER, FROM THE INITIATOR'S HALF ─────────────────────────────
    let answered = bodies
        .iter()
        .filter(|b| b.direction == initiator && b.carrier == "Open" && b.name == "usrpwd")
        .find(|b| b.reading("hmac").is_some())
        .unwrap_or_else(|| {
            panic!(
                "no walked `usrpwd` body on the initiator's Open carries an \
                 `hmac`:\n{}",
                dump(bodies)
            )
        });
    let Some(Reading::Bytes(observed)) = answered.reading("hmac") else {
        panic!(
            "the `hmac` reading is not raw bytes: {}",
            answered.describe()
        )
    };

    let expected = usrpwd_hmac(nonce, PASSWORD.as_bytes());
    assert_eq!(
        observed,
        &expected,
        "the 32 bytes this build points at as `hmac` are not \
         HMAC-SHA3-256(nonce_le, password) for the challenge the acceptor sent \
         ({nonce}) and the password this test spawned the client with. Either \
         the challenge or the digest is being read from the wrong span.\n  \
         challenge: {}\n  answer:    {}",
        challenge.describe(),
        answered.describe(),
    );

    // ── ANTI-VACUITY: THE EQUALITY MUST DEPEND ON BOTH INPUTS ─────────────
    // A digest that ignored its key would satisfy the assertion above while
    // proving nothing about the challenge, and one that ignored its message
    // would prove nothing about the password. Both directions are checked so
    // that "the nonce was read correctly" is a thing this test can fail on.
    assert_ne!(
        usrpwd_hmac(nonce ^ 1, PASSWORD.as_bytes()),
        expected,
        "the digest does not depend on its key, so the assertion above says \
         nothing about the challenge nonce",
    );
    assert_ne!(
        usrpwd_hmac(nonce, b"not-the-password-this-test-chose"),
        expected,
        "the digest does not depend on its message, so the assertion above \
         says nothing about the password",
    );
}

/// Spawn a zenohd whose transport REQUIRES usrpwd: a dictionary holding
/// `USER:PASSWORD`. Per zenoh's `usrpwd.rs` a configured dictionary makes auth
/// mandatory, so a client without the ext is refused at InitSyn — which is
/// what makes the captured chain a REQUIRED exchange rather than an optional
/// one. The tempfile is returned because dropping it deletes the file zenohd
/// reads.
fn spawn_usrpwd_zenohd(port: u16) -> (ChildGuard, NamedTempFile) {
    let mut dict = NamedTempFile::new().expect("usrpwd dictionary tempfile");
    writeln!(dict, "{USER}:{PASSWORD}").expect("write usrpwd dictionary entry");
    dict.flush().expect("flush usrpwd dictionary");
    let dict_path = dict.path().to_path_buf();

    let mut command = Command::new(zenohd_binary());
    command
        .arg("-l")
        .arg(format!("tcp/127.0.0.1:{port}"))
        .arg("--no-multicast-scouting")
        .arg("--rest-http-port")
        .arg("none")
        // `--cfg KEY:VALUE` takes JSON5, so the path is a quoted string.
        .arg("--cfg")
        .arg(format!(
            "transport/auth/usrpwd/dictionary_file:\"{}\"",
            dict_path.display()
        ))
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    let mut guard = ChildGuard::wrap(
        "zenohd (usrpwd acceptor, behind the tap)",
        command.spawn().expect("spawn zenohd with usrpwd auth"),
    );
    if let Err(e) = wait_for_tcp_accept_alive(guard.child_mut(), port, ZENOHD_TCP_ACCEPT_BUDGET) {
        panic!("zenohd (usrpwd): {e}");
    }
    (guard, dict)
}

/// Run a stock `z_get` as a usrpwd INITIATOR through `endpoint`, to
/// completion, and return its output.
///
/// The query is scaffolding: nothing answers it, and the handshake this test
/// reads is complete before the query is sent.
fn run_usrpwd_zget(z_get: &std::path::Path, endpoint: &str) -> String {
    let out = tempfile::tempfile().expect("tempfile for z_get stdout");
    let out_writer = out.try_clone().expect("dup z_get stdout handle");
    let mut out_reader = out;
    let mut cmd = Command::new("stdbuf");
    cmd.args(["-oL", "-eL"]).arg(z_get).args([
        "-s",
        "demo/auth-witness/**",
        "-o",
        GET_TIMEOUT_MS,
        "-m",
        "client",
        "-e",
        endpoint,
        "--no-multicast-scouting",
        "--cfg",
    ]);
    cmd.arg(format!("transport/auth/usrpwd/user:\"{USER}\""));
    cmd.arg("--cfg");
    cmd.arg(format!("transport/auth/usrpwd/password:\"{PASSWORD}\""));
    let mut child = ChildGuard::wrap(
        "z_get (stock zenoh, usrpwd initiator)",
        cmd.stderr(Stdio::from(
            out_writer.try_clone().expect("dup stderr handle"),
        ))
        .stdout(Stdio::from(out_writer))
        .spawn()
        .expect("spawn z_get via stdbuf"),
    );
    let deadline = Instant::now() + GET_WALL_CLOCK;
    loop {
        match child.child_mut().try_wait().expect("try_wait on z_get") {
            Some(_) => break,
            None if Instant::now() >= deadline => {
                panic!(
                    "stock z_get did not finish within {GET_WALL_CLOCK:?}; captured:\n{}",
                    read_captured(&mut out_reader)
                );
            }
            None => std::thread::sleep(Duration::from_millis(50)),
        }
    }
    read_captured(&mut out_reader)
}

/// Wait until BOTH directions have carried bytes. Polls the RECORDING rather
/// than a log line, so the marker is the same artefact the assertions read.
fn wait_for_both_directions(recording: &Recording, budget: Duration) -> bool {
    let deadline = Instant::now() + budget;
    loop {
        {
            let segments = recording.lock().expect("recording lock");
            let dialer = segments.iter().any(|(s, _)| *s == Side::FromDialer);
            let listener = segments.iter().any(|(s, _)| *s == Side::FromListener);
            if dialer && listener {
                return true;
            }
        }
        if Instant::now() >= deadline {
            return false;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
}

/// THE WITNESS: the auth chain and its method body, fed bytes stock zenoh
/// wrote on both halves.
///
/// The `zenohd` in the name is LOAD-BEARING: Layer C0's skip-token rule reads
/// the FUNCTION name, because that is what libtest's `--skip` matches, and a
/// test Layer E's default sweep does not skip is a test Layer E RUNS against
/// whatever binaries that lane happens to have built.
// wz-proves: session-extauth zenohd->wz partial
// wz-proves: access-extauth-usrpwd zenoh->wz partial
#[test]
#[ignore = "binary-dep e2e (zenohd + zenoh z_get, usrpwd); Layer Ewirez runs via --ignored"]
fn the_auth_chain_walkers_read_what_a_stock_zenohd_usrpwd_handshake_wrote() {
    let z_get = zenoh_core_example_binary("z_get");

    let reservation = PortReservation::pick();
    let zenohd_port = reservation.port();
    let (mut zenohd, _dict) = spawn_usrpwd_zenohd(zenohd_port);

    let (proxy_port, recording) = tap_proxy(zenohd_port);

    let get_out = run_usrpwd_zget(&z_get, &format!("tcp/127.0.0.1:{proxy_port}"));

    let both = wait_for_both_directions(&recording, Duration::from_secs(5));
    std::thread::sleep(Duration::from_millis(200));
    let _ = zenohd.child_mut().kill();
    let _ = zenohd.child_mut().wait();
    std::thread::sleep(Duration::from_millis(200));

    assert!(
        both,
        "the tap never saw both directions, so no stock usrpwd handshake \
         reached it. z_get said:\n{get_out}"
    );

    let segments = recording.lock().expect("recording lock").clone();

    // ── ANTI-VACUITY FIRST ────────────────────────────────────────────────
    assert!(
        !segments.is_empty(),
        "the tap recorded NOTHING -- an empty capture satisfies every field \
         assertion below. z_get said:\n{get_out}"
    );
    let from_client: usize = segments
        .iter()
        .filter(|(s, _)| *s == Side::FromDialer)
        .map(|(_, b)| b.len())
        .sum();
    let from_zenohd: usize = segments
        .iter()
        .filter(|(s, _)| *s == Side::FromListener)
        .map(|(_, b)| b.len())
        .sum();
    assert!(
        from_client > 0 && from_zenohd > 0,
        "a one-way recording is not a handshake: {from_client} byte(s) from \
         the client, {from_zenohd} from zenohd"
    );

    let pcap = synthesise_pcap(&segments, DIALER_PORT, LISTENER_PORT);
    let dissection = Dissection::from_pcap(&pcap).expect("the synthesised pcap parses");
    let flows = dissection.flows();
    assert_eq!(flows.len(), 1, "one relayed connection is one flow");
    let flow = &flows[0];

    // WHICH HALF IS WHICH, DERIVED. `low` is the lesser endpoint by
    // `(addr, port)` and zenohd is the listener, so A is the acceptor's half.
    assert_eq!(
        (flow.flow.low.port, flow.flow.high.port),
        (u32::from(LISTENER_PORT), u32::from(DIALER_PORT)),
        "the synthesised ports decide which half is Direction::A, so this test \
         pins them: zenohd (the listener) is the LOW endpoint here"
    );
    let (acceptor_side, initiator_side) = (Direction::A, Direction::B);

    let bodies = bodies_of(flow, Depth::Deep);
    eprintln!(
        "extension bodies a stock zenoh usrpwd handshake put on this wire:\n{}",
        dump(&bodies)
    );

    // ── THE CLAIM ABOUT THE CAPTURE, BEFORE ANY CLAIM ABOUT A READING ─────
    // R311y900's lesson, in the order it was paid for.
    assert_witnessed_set(
        &bodies,
        WITNESSED,
        "a stock zenoh usrpwd handshake put on this wire",
    );

    // ── NO ROW IS CREDITED WITH A DESCENDANT'S NUMBER ─────────────────────
    // Before any reading is judged, because a row that borrowed a value from
    // below it makes every assertion under it a claim about the wrong entry.
    assert_no_entry_borrows_a_descendants_value(&bodies);

    // ── THE CHAIN WAS WALKED, ON BOTH HALVES ──────────────────────────────
    // `auth` is an ext whose body is a CHAIN, not a value. A build that left
    // it opaque would still produce an `auth` row, so the assertion is that it
    // has readings under it rather than that it exists.
    for (side, who) in [(acceptor_side, "zenohd"), (initiator_side, "the client")] {
        let auth: Vec<&Body> = bodies
            .iter()
            .filter(|b| b.direction == side && b.name == "auth")
            .collect();
        assert!(
            !auth.is_empty(),
            "no `auth` extension on {who}'s half; a usrpwd handshake cannot \
             have completed without one:\n{}",
            dump(&bodies)
        );
        assert!(
            auth.iter().any(|b| !b.read.is_empty()),
            "{who}'s `auth` extension was reported with NO readings, so the \
             chain was left opaque rather than walked: {:?}",
            auth.iter().map(|b| b.describe()).collect::<Vec<_>>()
        );
    }

    // ── ONE ID, THREE ENCODINGS ───────────────────────────────────────────
    assert_one_id_three_encodings(&bodies, acceptor_side, initiator_side);

    // ── THE METHOD BODY, AGAINST THE USERNAME THE CLIENT WAS SPAWNED WITH ─
    // The sharpest binding available: a config value this test chose, which no
    // constant in this tree could have been copied wrong from. A walker that
    // swapped `user` and `hmac`, or that read a ZBuf length as part of its
    // value, passes every self-witness in the workspace and reds here.
    let usrpwd: Vec<&Body> = bodies
        .iter()
        .filter(|b| b.direction == initiator_side && b.name == "usrpwd")
        .collect();
    assert!(
        !usrpwd.is_empty(),
        "the stock client authenticated with usrpwd and no `usrpwd` method \
         body reached the dissector on its half:\n{}",
        dump(&bodies)
    );
    let named = usrpwd
        .iter()
        .find(|b| b.reading("user").is_some())
        .unwrap_or_else(|| {
            panic!(
                "no `usrpwd` body carried a `user` field, so the method body \
                 was not walked into its ZBufs: {:?}",
                usrpwd.iter().map(|b| b.describe()).collect::<Vec<_>>()
            )
        });
    assert_eq!(
        named.reading("user"),
        Some(&Reading::Bytes(USER.as_bytes().to_vec())),
        "the `user` a stock zenoh client put on the wire is not the one it was \
         spawned with: {}",
        named.describe()
    );
    // FRAMING first: the second ZBuf exists, is its own record, and is not
    // empty. That separates "two records were read" from "one record was read
    // and the rest swallowed", and it is the assertion that still holds if the
    // capture ever stops carrying a challenge to key the digest with.
    match named.reading("hmac") {
        Some(Reading::Bytes(h)) if !h.is_empty() => {}
        other => panic!(
            "the `usrpwd` body's second ZBuf is not a non-empty `hmac`: \
             {other:?} in {}",
            named.describe()
        ),
    }

    // ── AND THEN BY VALUE ─────────────────────────────────────────────────
    // R2046 (item 419). The framing check above is a claim about lengths; this
    // one recomputes the digest from the challenge the acceptor actually sent
    // and the password the client was actually given, so the two ZBufs are
    // pinned to where they start rather than to how long they are.
    assert_the_hmac_is_the_password_keyed_by_the_challenge(&bodies, acceptor_side, initiator_side);
}
