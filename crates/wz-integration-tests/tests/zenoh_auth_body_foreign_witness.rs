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
//! `user` is asserted against the username this test spawned the client with.
//! That is the sharpest binding available: a config value is not a constant
//! this tree could have copied wrong, so a walker that mis-framed the two
//! ZBufs — swapping `user` and `hmac`, or reading the length as part of the
//! value — passes every self-witness in the workspace and reds here.

use std::io::Write as _;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use tempfile::NamedTempFile;
use wz_capture::Dissection;
use wz_integration_tests::common::{
    read_captured, wait_for_tcp_accept_alive, zenoh_core_example_binary, zenohd_binary, ChildGuard,
    PortReservation, ZENOHD_TCP_ACCEPT_BUDGET,
};
use wz_integration_tests::wire_tap::{synthesise_pcap, tap_proxy, Recording, Side};
use wz_session_core::dissect::{Field, FieldValue};
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

/// The `encoding` bits of an extension entry, as `walk_ext_entry` reports
/// them: a UNIT body has none, a Z64 body is one VLE, a ZBuf body is a length
/// and that many bytes.
///
/// Named here because this capture's sharpest fact is about them — see
/// [`assert_one_id_three_encodings`].
const ENC_UNIT: u64 = 0;
const ENC_Z64: u64 = 1;
const ENC_ZBUF: u64 = 2;

/// The message groups a walked tree names, so an extension is attributed to
/// the message that CARRIED it rather than to the transport envelope.
const MESSAGE_NAMES: &[&str] = &[
    "Init",
    "Open",
    "Close",
    "KeepAlive",
    "Frame",
    "Fragment",
    "Oam",
    "Push",
    "Request",
    "Response",
    "ResponseFinal",
    "Interest",
    "Declare",
];

/// The fields `walk_ext_entry` pushes for EVERY entry whatever the body — the
/// envelope, not a reading of it.
const ENVELOPE: &[&str] = &[
    "header",
    "ext_id",
    "m",
    "encoding",
    "z",
    "ext_name",
    "value",
    "value_len",
];

/// One reading a walker produced.
#[derive(Debug, Clone, PartialEq)]
enum Reading {
    Label(String),
    Flag(bool),
    Number(u64),
    /// Raw bytes — how `user` and `hmac` come back.
    Bytes(Vec<u8>),
    Text(String),
    /// A walked sub-structure and its child count. An auth body IS one, so
    /// this is what tells "the chain was walked" from "the chain was left
    /// opaque".
    Group(usize),
}

impl core::fmt::Display for Reading {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Reading::Label(v) => write!(f, "{v}"),
            Reading::Flag(v) => write!(f, "{v}"),
            Reading::Number(v) => write!(f, "{v}"),
            // Rendered as text when it is text, because `user` is and a
            // failure message naming it in hex would be unreadable.
            Reading::Bytes(v) => match core::str::from_utf8(v) {
                Ok(s) if s.chars().all(|c| !c.is_control()) => write!(f, "{s:?}"),
                _ => write!(f, "<{} byte(s)>", v.len()),
            },
            Reading::Text(v) => write!(f, "{v:?}"),
            Reading::Group(n) => write!(f, "<{n} field(s)>"),
        }
    }
}

impl Reading {
    fn of(field: &Field) -> Option<Reading> {
        match &field.value {
            FieldValue::Label(v) => Some(Reading::Label(v.to_string())),
            FieldValue::Flag(v) => Some(Reading::Flag(*v)),
            FieldValue::Bits(v) | FieldValue::Uint(v) => Some(Reading::Number(*v)),
            FieldValue::Bytes(v) => Some(Reading::Bytes(v.clone())),
            FieldValue::Text(v) => Some(Reading::Text(v.to_string())),
            FieldValue::Nested(children) => Some(Reading::Group(children.len())),
            FieldValue::Opaque => None,
        }
    }
}

/// One extension body the capture carried, flattened for assertion.
#[derive(Debug, Clone)]
struct Body {
    direction: Direction,
    /// The message that carried it — the innermost [`MESSAGE_NAMES`] group.
    carrier: String,
    /// `ext_name`: which row of `wz_session_core::ext_name`'s table this is.
    name: String,
    /// The entry's `encoding` bits. Kept OUT of [`Self::read`] because it is
    /// envelope rather than a reading — but kept, because on this wire one id
    /// carries three of them and that is the fact worth asserting.
    encoding: Option<u64>,
    /// Every reading under this entry, at ANY depth below the envelope.
    ///
    /// Depth matters here in a way it did not for the Z64 rows: an auth method
    /// body is a group, and the fields worth asserting (`user`, `hmac`) are its
    /// CHILDREN. A one-level fold would report `usrpwd=<4 field(s)>` and have
    /// nothing to hold against a username.
    read: Vec<(String, Reading)>,
}

impl Body {
    fn reading(&self, name: &str) -> Option<&Reading> {
        self.read.iter().find(|(n, _)| n == name).map(|(_, v)| v)
    }

    fn describe(&self) -> String {
        let read = self
            .read
            .iter()
            .map(|(n, v)| format!("{n}={v}"))
            .collect::<Vec<_>>()
            .join(", ");
        format!(
            "{:?} {}/{} enc={:?} read=[{read}]",
            self.direction, self.carrier, self.name, self.encoding
        )
    }
}

/// Fold every reading under `field`, at any depth, skipping the envelope and
/// skipping NESTED ext entries (which become rows of their own).
fn fold_readings(field: &Field, out: &mut Vec<(String, Reading)>) {
    if let FieldValue::Nested(children) = &field.value {
        for child in children {
            if ENVELOPE.contains(&child.name.as_ref()) {
                continue;
            }
            // A nested `ext` is a sub-extension: `collect` gives it its own
            // row, so folding it here too would report it twice.
            if child.name == "ext" || child.name == "extensions" {
                continue;
            }
            if let Some(r) = Reading::of(child) {
                out.push((child.name.to_string(), r));
            }
            fold_readings(child, out);
        }
    }
}

/// Collect every `ext` entry under `field`, attributing each to the innermost
/// enclosing message group.
fn collect(field: &Field, direction: Direction, carrier: &str, out: &mut Vec<Body>) {
    let carrier = if MESSAGE_NAMES.contains(&field.name.as_ref()) {
        field.name.as_ref()
    } else {
        carrier
    };
    if field.name == "ext" {
        if let Some(FieldValue::Label(name)) = field.find("ext_name").map(|f| &f.value) {
            let mut read = Vec::new();
            fold_readings(field, &mut read);
            out.push(Body {
                direction,
                carrier: carrier.to_string(),
                name: name.to_string(),
                encoding: match field.find("encoding").map(|f| &f.value) {
                    Some(FieldValue::Bits(v)) | Some(FieldValue::Uint(v)) => Some(*v),
                    _ => None,
                },
                read,
            });
        }
    }
    if let FieldValue::Nested(children) = &field.value {
        for child in children {
            collect(child, direction, carrier, out);
        }
    }
}

/// Walk every message of `flow` and collect its extension bodies.
fn bodies_of(flow: &wz_capture::FlowDissection) -> Vec<Body> {
    let mut out = Vec::new();
    for frame in flow.frames.iter() {
        let Ok(bytes) = flow.message_bytes(frame) else {
            continue;
        };
        let Ok(walked) = wz_session_core::dissect::dissect_transport_message(bytes, 0) else {
            continue;
        };
        collect(&walked, frame.direction, "?", &mut out);
    }
    out
}

fn dump(bodies: &[Body]) -> String {
    bodies
        .iter()
        .map(|b| format!("  {}", b.describe()))
        .collect::<Vec<_>>()
        .join("\n")
}

/// Hold this file's claim about what the capture carries against what it
/// actually carried — both ways, and before any reading is judged.
fn assert_witnessed_set(bodies: &[Body]) {
    let mut seen: Vec<&str> = bodies.iter().map(|b| b.name.as_str()).collect();
    seen.sort_unstable();
    seen.dedup();
    assert_eq!(
        seen,
        WITNESSED,
        "the extension bodies a stock zenoh usrpwd handshake put on this wire \
         are not the set this file asserts. A difference either way means an \
         assertion below is about nothing, or a foreign reading is going \
         unjudged. Whole capture:\n{}",
        dump(bodies)
    );
}

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

    let bodies = bodies_of(flow);
    eprintln!(
        "extension bodies a stock zenoh usrpwd handshake put on this wire:\n{}",
        dump(&bodies)
    );

    // ── THE CLAIM ABOUT THE CAPTURE, BEFORE ANY CLAIM ABOUT A READING ─────
    // R311y900's lesson, in the order it was paid for.
    assert_witnessed_set(&bodies);

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
    // The hmac is NOT asserted by value -- it is a keyed digest and this test
    // holds no key. What IS asserted is that it was framed as its own ZBuf and
    // is not empty, which is what separates "two records were read" from "one
    // record was read and the rest swallowed".
    match named.reading("hmac") {
        Some(Reading::Bytes(h)) if !h.is_empty() => {}
        other => panic!(
            "the `usrpwd` body's second ZBuf is not a non-empty `hmac`: \
             {other:?} in {}",
            named.describe()
        ),
    }
}
