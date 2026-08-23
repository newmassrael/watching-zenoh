// SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! R311y900 (open-debt item 406) — the Z64 EXTENSION BODY walkers, against
//! bytes two stock zenoh processes actually wrote.
//!
//! ## The gap, stated as the register stated it
//!
//! R311y898 gave `walk_ext_entry`'s `ExtZint` arm its first walkers and
//! R311y899 added three more, so six extension bodies stopped rendering as a
//! bare number: `qos`, `target`, `queryable_info`, `node_id`, `patch`,
//! `budget`. Every one of them was judged by exactly two things — a PRODUCER
//! in this tree (`crate::qos`, `crate::query_mode`, `crate::queryable_info`)
//! and upstream source a person had read. Neither is a foreign witness. A
//! walker written from a misread of `network/request.rs` and a producer
//! written from the same misread agree with each other perfectly, and a test
//! holding the two together reports that agreement as correctness.
//!
//! The register filed this as the FOURTH instance of one axis — 390 (the ZBuf
//! bodies), 396 (the auth chain), then this — and said in as many words what
//! was missing: *not the traffic, the bridge*. The traffic has been in this
//! crate since R311y841.
//!
//! ## Both halves foreign, which the two older witnesses could not manage
//!
//! `zenohd_wire_dissection.rs` and `pico_wire_dissection.rs` tap a session
//! between wz and a foreign peer, so one half of every capture is wz's own
//! encoder. Here NO wz process is on the wire at all:
//!
//! ```text
//!   zenoh_z_queryable --complete ──► [tap] ──► zenohd ◄── zenoh_z_get --target
//!        (stock zenoh client)                 (stock router)   (off the tap)
//! ```
//!
//! Every byte the tap records was written by stock zenoh 1.5.0 — a client's
//! `Declare` on one half, a router's forwarded `Request` on the other — and wz
//! appears only as the reader of the synthesised pcap. That is the strongest
//! shape this harness can take, and it is available here because the question
//! is about a DECODER: a decoder needs no seat at the table.
//!
//! ## What each assertion is held against, and why it is not this tree
//!
//! | body | the foreign fact it is checked against |
//! |---|---|
//! | `queryable_info` | the `--complete` FLAG the queryable was spawned with |
//! | `target` | the `--target ALL_COMPLETE` FLAG the querier was spawned with |
//! | `qos` on a `Declare` | `QoSType::DECLARE` = `(Control, Block, !express)`, `zenoh-protocol/src/network/mod.rs:410-411` |
//! | `qos` on a `Request` | `QoSType::REQUEST` = `(Data, Block, !express)`, the same table at 413-414 |
//! | `patch` on an `Init` | `PatchType::CURRENT` = 1, `zenoh-protocol/src/transport/mod.rs:322` |
//!
//! The first two are the sharpest, because a CLI switch is not a constant this
//! tree could have copied wrong: a reader that mixed up `All` and
//! `AllComplete` passes every self-witness in the workspace and reds here.
//!
//! The `patch` row is the odd one and is deliberately kept: `read_patch_z64`
//! is SILENT on a value a receiver acts on as written (R311y899's rule — the
//! presence of `read_as` is a finding), so the only thing a conforming
//! capture can witness about it is that silence. Asserting it is what stops
//! the narrowing arm from firing on values it must not fire on, which is the
//! half of that walker a hand-written fixture is least likely to cover.
//!
//! ## What this does NOT witness, and it is filed rather than glossed
//!
//! `node_id` and `budget` are reached by no byte in this capture, and both
//! absences are upstream's own encoder rule rather than a gap in the fixture:
//! `NodeIdType::DEFAULT` is `0` and a client face routes at node 0, so
//! `zenoh-codec/src/network/declare.rs:126` never writes the extension;
//! `ext_budget` is `None` unless a querier calls `.limit(n)`, and `z_get` has
//! no flag for it. This test asserts neither. [`WITNESSED`] is the set it DOES
//! assert and it is held against the capture in both directions, so a future
//! fixture that starts carrying one of the two cannot leave it unjudged.
//!
//! ## What the first run FOUND, which no wz-authored fixture could have
//!
//! Open-debt item 412. A `Frame` carries a MANDATORY Z64 `qos`, and this
//! capture holds one at value `0` — read here as
//! `priority=Control, congestion=Drop, express=false`. Upstream's frame
//! receiver consumes `ext_qos.priority()` and NOTHING else
//! (`io/zenoh-transport/src/unicast/universal/rx.rs:85`, and the `Fragment`
//! arm at 135 is the same), so the congestion and express bits of a frame are
//! decoded by no one. Reporting them is R311y899's own failure one carrier
//! over — a value shown as a reading that no receiver acts on — and it was
//! invisible from inside this tree because wz's frame encoder writes the same
//! zeros a stock one does. It is FILED rather than fixed here: the fix is a
//! per-carrier reading and this round's subject is the bridge.
//!
//! ## Falsification, measured
//!
//! Damage probes, each run alone and each red for its own reason — see the
//! round entry. The one that matters most is the last, because its subject is
//! a SILENCE: `narrowed_z64` made to emit `read_as` unconditionally reds on
//! the `patch` leg and on nothing else.

use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use wz_capture::Dissection;
use wz_integration_tests::common::{
    read_captured, wait_for_tcp_accept_alive, zenoh_core_example_binary, zenohd_binary, ChildGuard,
    PortReservation, ZENOHD_TCP_ACCEPT_BUDGET,
};
use wz_integration_tests::wire_tap::{synthesise_pcap, tap_proxy, Recording, Side};
use wz_session_core::dissect::{Field, FieldValue};
use wz_session_core::passive::Direction;

/// The synthesised endpoint ports, on `zenohd_wire_dissection.rs`'s rule: they
/// are NOT the real ones, and they are named because they DECIDE which half
/// `Direction::A` is — `FlowKey` orders its endpoints by `(addr, port)` and
/// both addresses are 127.0.0.1. The mapping is derived and asserted below
/// rather than written down, which is the correction R311y761 had to make
/// after a round reported wz's own frames as a router's.
const DIALER_PORT: u16 = 40_000;
const LISTENER_PORT: u16 = 7447;

/// The keyexpr the queryable declares and the query names INSIDE it. Distinct
/// from every other Layer E keyexpr so parallel runs never cross-match.
const QABL_KEY: &str = "demo/ext-body/**";
const QUERY_KEY: &str = "demo/ext-body/x";

/// zenoh `z_queryable`'s ready marker.
const QABL_READY: &str = "Declaring Queryable on";

/// The querier's per-reply marker — the signal that the whole chain (client →
/// router → tapped queryable → back) completed, so the recording holds a
/// forwarded `Request` and not only a handshake.
const GET_RECEIVED: &str = ">> Received (";

/// `z_get -o`, in milliseconds, and the wall clock the harness allows on top.
/// MEASURED rather than chosen, on `wz_router_query_target_zenoh_interop.rs`'s
/// rule: at upstream's 10s default an expired query and an answered one exit
/// alike, so a generous deadline reads both as success.
const GET_TIMEOUT_MS: &str = "3000";
const GET_WALL_CLOCK: Duration = Duration::from_secs(15);

/// The extension bodies this capture is asserted to carry, by `ext_name`.
///
/// A SET rather than a count, which is R311y897's anti-vacuity shape: a count
/// weakens silently the moment one row stops appearing and another starts.
/// This list is also the falsification target for the module doc's claim about
/// `node_id` and `budget` — [`assert_witnessed_set`] holds it against what the
/// capture actually held, so a fixture that gains a body reds until the claim
/// is rewritten and the new body judged.
///
/// EVERY body, not only the Z64 ones this file is about: `responder_id` is a
/// ZBuf body R311y890 walked and `timeout` is a Z64 row declared SCALAR, and
/// both belong here for the reason the set exists at all. A list narrowed to
/// the rows under test would be satisfied by a capture that had quietly
/// stopped carrying everything else, which is the vacuity this shape refuses.
/// The first run of this witness listed four and the wire held six — the two
/// extra were found by this assertion and not by reading the fixture.
const WITNESSED: &[&str] = &[
    "patch",
    "qos",
    "queryable_info",
    "responder_id",
    "target",
    "timeout",
];

/// The message groups a walked tree names, so an extension can be attributed
/// to the message that CARRIED it rather than to the transport envelope it
/// arrived in.
///
/// Needed because `dissect_transport_message` returns one tree per transport
/// message and a `Frame` descends into its whole record batch: without this,
/// every `qos` inside a frame would be attributed to `Frame` and the two
/// per-message constants below could not be told apart.
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
///
/// Excluded from [`Body::read`] so that an empty `read` means "this body got
/// no walker output", which is the exact claim the `patch` leg rests on.
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
///
/// [`Group`](Reading::Group) exists so that "the body was walked into a
/// subtree" and "the body got no walker at all" are DIFFERENT entries rather
/// than two ways of contributing nothing. Without it the `patch` leg's
/// `read.is_empty()` would also be satisfied by a ZBuf body walked into a
/// nested group, and that leg's whole subject is an emptiness.
#[derive(Debug, Clone, PartialEq)]
enum Reading {
    /// A name this build resolved from the bits (`"Block"`, `"AllComplete"`).
    Label(String),
    /// A single bit (`express`, `complete`, `absent_to_receiver`).
    Flag(bool),
    /// A number (`distance`, `read_as`, `undefined_bits`).
    Number(u64),
    /// A walked sub-structure, with how many children it has. Only a ZBuf body
    /// produces one; every Z64 walker in this build emits flat fields.
    Group(usize),
}

impl core::fmt::Display for Reading {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Reading::Label(v) => write!(f, "{v}"),
            Reading::Flag(v) => write!(f, "{v}"),
            Reading::Number(v) => write!(f, "{v}"),
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
            FieldValue::Nested(children) => Some(Reading::Group(children.len())),
            _ => None,
        }
    }
}

/// One extension body the capture carried, flattened for assertion.
#[derive(Debug, Clone)]
struct Body {
    /// Which half wrote it.
    direction: Direction,
    /// The message that carried it — the innermost [`MESSAGE_NAMES`] group the
    /// entry sits under.
    carrier: String,
    /// `ext_name`: which row of `wz_session_core::ext_name`'s table this is.
    name: String,
    /// The packed value as it stood on the wire, before any narrowing. `None`
    /// for a `ExtUnit` entry, which has no body byte at all — `Init`'s `qos`
    /// is one, and telling it apart from the Z64 `qos` is why this is an
    /// `Option` rather than a defaulted zero.
    value: Option<u64>,
    /// Everything the walker made of it, in tree order, minus [`ENVELOPE`].
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
            "{:?} {}/{} value={:?} read=[{read}]",
            self.direction, self.carrier, self.name, self.value
        )
    }
}

/// Collect every `ext` entry under `field`, attributing each to the innermost
/// enclosing message group.
///
/// Depth-first and INCLUDING nested chains (an auth body is itself a chain of
/// ext entries), because a body's carrier is decided by where it sits. The
/// name is read from the entry's own `ext_name` child, which `walk_ext_entry`
/// pushes ahead of the body — so [`Field::find`]'s first match is this
/// entry's name and never an inner one's.
fn collect(field: &Field, direction: Direction, carrier: &str, out: &mut Vec<Body>) {
    let carrier = if MESSAGE_NAMES.contains(&field.name.as_ref()) {
        field.name.as_ref()
    } else {
        carrier
    };
    if field.name == "ext" {
        if let Some(FieldValue::Label(name)) = field.find("ext_name").map(|f| &f.value) {
            let read = match &field.value {
                FieldValue::Nested(children) => children
                    .iter()
                    .filter(|c| !ENVELOPE.contains(&c.name.as_ref()))
                    .filter_map(|c| Reading::of(c).map(|r| (c.name.to_string(), r)))
                    .collect(),
                _ => Vec::new(),
            };
            out.push(Body {
                direction,
                carrier: carrier.to_string(),
                name: name.to_string(),
                // R2048 — this entry's OWN `value`, not `Field::find`'s.
                //
                // The paragraph above argues that a recursive search is safe
                // here, and it is RIGHT about `ext_name`: `walk_ext_entry`
                // pushes that ahead of the body, so the direct child wins. The
                // argument does not carry to `value`, which a WALKED ZBuf body
                // does not push at all — the walked group replaces it — so a
                // recursive search descends into the body and hands back a
                // SUB-EXTENSION's number. R2046 found that in the auth witness,
                // where an `auth` chain reported its first method's nonce as its
                // own; nothing in this capture has a nested chain today, which
                // is why it never showed here. `ext_bodies::own_child` is the
                // shared form of this fix.
                value: match wz_integration_tests::ext_bodies::own_child(field, "value")
                    .map(|f| &f.value)
                {
                    Some(FieldValue::Uint(v)) | Some(FieldValue::Bits(v)) => Some(*v),
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
///
/// A message whose bytes cannot be sliced or whose walk fails is SKIPPED here
/// rather than reported, because this file's subject is the extension layer
/// and the two witnesses beside it already refuse a capture with an unparsed
/// message on either half. [`assert_witnessed_set`] is what stops a silent
/// skip from emptying the capture: a walk that failed everywhere yields an
/// empty set and reds there.
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

/// Every body, one per line, for a failure message.
fn dump(bodies: &[Body]) -> String {
    bodies
        .iter()
        .map(|b| format!("  {}", b.describe()))
        .collect::<Vec<_>>()
        .join("\n")
}

/// Hold the module doc's claim about what this capture carries against what it
/// actually carried.
///
/// The claim is TWO-SIDED, which is why this is a set comparison and not a
/// containment check: a body that vanishes leaves an assertion below asserting
/// nothing, and a body that APPEARS (a `node_id`, once a fixture puts a second
/// router behind the tap) is a foreign reading going unjudged while the module
/// doc says it is unreachable. Both are findings about this file.
fn assert_witnessed_set(bodies: &[Body]) {
    let mut seen: Vec<&str> = bodies.iter().map(|b| b.name.as_str()).collect();
    seen.sort_unstable();
    seen.dedup();
    assert_eq!(
        seen,
        WITNESSED,
        "the extension bodies a stock zenoh pair put on this wire are not the \
         set this file asserts. WITNESSED is the module doc's claim, including \
         its statement that `node_id` and `budget` are unreachable here -- a \
         difference either way means an assertion below is about nothing, or a \
         foreign reading is going unjudged. Whole capture:\n{}",
        dump(bodies)
    );
}

/// Spawn a stock `zenoh_z_queryable` as a CLIENT of `endpoint` and return once
/// it has declared.
///
/// Retries on a transient open failure, on the sibling file's rule: a session
/// that fails to open is a flake, not a finding. `stdbuf -oL` because the
/// marker is read from a file while the process is still alive.
fn spawn_declared_queryable(
    z_queryable: &std::path::Path,
    endpoint: &str,
) -> (ChildGuard, std::fs::File) {
    const ATTEMPTS: usize = 6;
    for attempt in 1..=ATTEMPTS {
        let out = tempfile::tempfile().expect("tempfile for z_queryable stdout");
        let out_writer = out.try_clone().expect("dup z_queryable stdout handle");
        let mut out_reader = out;
        let mut cmd = Command::new("stdbuf");
        cmd.args(["-oL", "-eL"]).arg(z_queryable).args([
            "-k",
            QABL_KEY,
            "-p",
            "answer-from-a-stock-zenoh-queryable",
            "-m",
            "client",
            "-e",
            endpoint,
            "--no-multicast-scouting",
            // THE FLAG THE `queryable_info` ASSERTION IS HELD AGAINST. Without
            // it `QueryableInfoType` equals its default and
            // `zenoh-codec/src/network/declare.rs:118` omits the extension
            // entirely, so the walker would never be reached and the assertion
            // would be about an absence.
            "--complete",
        ]);
        let mut child = ChildGuard::wrap(
            "z_queryable (stock zenoh, through the tap)",
            cmd.stderr(Stdio::from(
                out_writer.try_clone().expect("dup stderr handle"),
            ))
            .stdout(Stdio::from(out_writer))
            .spawn()
            .expect("spawn z_queryable via stdbuf"),
        );
        let deadline = Instant::now() + Duration::from_secs(10);
        loop {
            if read_captured(&mut out_reader).contains(QABL_READY) {
                return (child, out_reader);
            }
            if Instant::now() >= deadline {
                break;
            }
            std::thread::sleep(Duration::from_millis(50));
        }
        let _ = child.child_mut().kill();
        let _ = child.child_mut().wait();
        eprintln!("z_queryable open attempt {attempt}/{ATTEMPTS} did not declare; retrying");
    }
    panic!("stock zenoh z_queryable failed to declare through the tap after {ATTEMPTS} attempts");
}

/// Run one stock `z_get` to completion, straight at the router, and return its
/// stdout.
fn run_zget(z_get: &std::path::Path, endpoint: &str) -> String {
    let out = tempfile::tempfile().expect("tempfile for z_get stdout");
    let out_writer = out.try_clone().expect("dup z_get stdout handle");
    let mut out_reader = out;
    let mut cmd = Command::new("stdbuf");
    cmd.args(["-oL", "-eL"]).arg(z_get).args([
        "-s",
        QUERY_KEY,
        "-o",
        GET_TIMEOUT_MS,
        "-m",
        "client",
        "-e",
        endpoint,
        "--no-multicast-scouting",
        // THE FLAG THE `target` ASSERTION IS HELD AGAINST. Upstream's default
        // is `BEST_MATCHING`, which `zenoh-codec/src/network/request.rs:96`
        // omits, so a plain `z_get` puts no `target` extension on the wire.
        "-t",
        "ALL_COMPLETE",
    ]);
    let mut child = ChildGuard::wrap(
        "z_get (stock zenoh, off the tap)",
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
                    "stock z_get did not finish within {GET_WALL_CLOCK:?}; captured so far:\n{}",
                    read_captured(&mut out_reader)
                );
            }
            None => std::thread::sleep(Duration::from_millis(50)),
        }
    }
    read_captured(&mut out_reader)
}

/// Wait until BOTH directions have carried bytes — the earliest point a
/// handshake can have completed. Polls the RECORDING rather than a log line,
/// so the marker is the same artefact the assertions read.
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

/// Assert that at least one body matching `(carrier, name)` reads exactly
/// `want`, and say what the candidates read when none does.
///
/// EXISTENCE rather than universality: a capture holds several `Declare`s and
/// only some are the queryable's, so a for-all would be a claim about the
/// router's whole declaration set rather than about the walker.
fn assert_some_reads(bodies: &[Body], carrier: &str, name: &str, want: &[(&str, Reading)]) {
    let candidates: Vec<&Body> = bodies
        .iter()
        .filter(|b| b.carrier == carrier && b.name == name)
        .collect();
    assert!(
        !candidates.is_empty(),
        "no `{name}` extension on any `{carrier}` in this capture, so the \
         reading asserted for it is about nothing:\n{}",
        dump(bodies)
    );
    let hit = candidates
        .iter()
        .any(|b| want.iter().all(|(k, v)| b.reading(k) == Some(v)));
    assert!(
        hit,
        "no `{carrier}`'s `{name}` was read as {want:?}. The expected reading \
         comes from a FOREIGN fact (a CLI flag, or an upstream constant this \
         tree does not own), so a mismatch is a defect in the walker rather \
         than in the fixture. Candidates:\n{}",
        candidates
            .iter()
            .map(|b| format!("  {}", b.describe()))
            .collect::<Vec<_>>()
            .join("\n")
    );
}

/// THE WITNESS: the Z64 body walkers, fed bytes stock zenoh wrote.
///
/// The `zenohd` in the name is LOAD-BEARING and not description: Layer C0's
/// skip-token rule reads the FUNCTION name, because that is what libtest's
/// `--skip` matches, and a test Layer E's default sweep does not skip is a
/// test Layer E RUNS — against whatever binaries that lane happens to have
/// built. This one spawns zenohd, so it carries zenohd's token.
// wz-proves: codec-declare zenoh->wz partial
// wz-proves: codec-request zenohd->wz partial
#[test]
#[ignore = "binary-dep e2e (zenohd + zenoh z_queryable/z_get); Layer Ewirez runs via --ignored"]
fn the_z64_body_walkers_read_what_a_stock_zenohd_and_queryable_wrote() {
    let z_queryable = zenoh_core_example_binary("z_queryable");
    let z_get = zenoh_core_example_binary("z_get");

    let reservation = PortReservation::pick();
    let zenohd_port = reservation.port();
    let mut zenohd = ChildGuard::wrap(
        "zenohd (routing between a tapped queryable and an untapped querier)",
        Command::new(zenohd_binary())
            .arg("-l")
            .arg(format!("tcp/127.0.0.1:{zenohd_port}"))
            .arg("--no-multicast-scouting")
            .arg("--rest-http-port")
            .arg("none")
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn zenohd"),
    );
    if let Err(e) =
        wait_for_tcp_accept_alive(zenohd.child_mut(), zenohd_port, ZENOHD_TCP_ACCEPT_BUDGET)
    {
        panic!("zenohd never accepted: {e}");
    }

    let (proxy_port, recording) = tap_proxy(zenohd_port);

    // THE OBSERVED FACE: a stock zenoh queryable, through the tap. Its
    // `Declare` carries `queryable_info`; the router's forwarded `Request`
    // carries `target`. Both halves of this connection are stock zenoh's own
    // bytes and neither is wz's.
    let (mut queryable, mut qabl_reader) =
        spawn_declared_queryable(&z_queryable, &format!("tcp/127.0.0.1:{proxy_port}"));
    assert!(
        wait_for_both_directions(&recording, Duration::from_secs(15)),
        "the tap never saw both directions, so no stock session reached it. \
         z_queryable said:\n{}",
        read_captured(&mut qabl_reader)
    );

    // THE UNOBSERVED FACE: the querier, straight at zenohd. Nothing it writes
    // is recorded; whatever reaches the tap because of it was written by the
    // ROUTER, which is what makes the `target` reading foreign twice over --
    // the flag was a stock client's and the bytes are a stock router's.
    let get_out = run_zget(&z_get, &format!("tcp/127.0.0.1:{zenohd_port}"));
    let qabl_out = read_captured(&mut qabl_reader);
    assert!(
        get_out.contains(GET_RECEIVED),
        "the stock querier got no reply, so the router never forwarded the \
         query through the tap and this capture holds a handshake only.\n\
         --- z_get ---\n{get_out}\n--- z_queryable ---\n{qabl_out}"
    );

    std::thread::sleep(Duration::from_millis(300));
    let _ = queryable.child_mut().kill();
    let _ = queryable.child_mut().wait();
    let _ = zenohd.child_mut().kill();
    let _ = zenohd.child_mut().wait();
    std::thread::sleep(Duration::from_millis(200));

    let segments = recording.lock().expect("recording lock").clone();

    // ── ANTI-VACUITY FIRST ────────────────────────────────────────────────
    assert!(
        !segments.is_empty(),
        "the tap recorded NOTHING -- an empty capture satisfies every field \
         assertion below.\n--- z_queryable ---\n{qabl_out}"
    );
    let from_qabl: usize = segments
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
        from_qabl > 0 && from_zenohd > 0,
        "a one-way recording is not a session: {from_qabl} byte(s) from the \
         queryable, {from_zenohd} from zenohd"
    );

    let pcap = synthesise_pcap(&segments, DIALER_PORT, LISTENER_PORT);
    let dissection = Dissection::from_pcap(&pcap).expect("the synthesised pcap parses");
    let flows = dissection.flows();
    assert_eq!(flows.len(), 1, "one relayed connection is one flow");
    let flow = &flows[0];

    // WHICH HALF IS WHICH, DERIVED. `low` is the lesser endpoint by
    // `(addr, port)` and zenohd is the listener, so A is the router's half.
    assert_eq!(
        (flow.flow.low.port, flow.flow.high.port),
        (u32::from(LISTENER_PORT), u32::from(DIALER_PORT)),
        "the synthesised ports decide which half is Direction::A, so this test \
         pins them: zenohd (the listener) is the LOW endpoint here"
    );
    let (router_side, client_side) = (Direction::A, Direction::B);

    let bodies = bodies_of(flow);
    eprintln!(
        "extension bodies a stock zenoh pair put on this wire:\n{}",
        dump(&bodies)
    );

    // ── THE CLAIM ABOUT THE CAPTURE, BEFORE ANY CLAIM ABOUT A READING ─────
    assert_witnessed_set(&bodies);

    let half = |d: Direction| -> Vec<Body> {
        bodies
            .iter()
            .filter(|b| b.direction == d)
            .cloned()
            .collect()
    };
    let from_client = half(client_side);
    let from_router = half(router_side);
    assert!(
        !from_client.is_empty() && !from_router.is_empty(),
        "both halves must carry extensions: client={} router={}",
        from_client.len(),
        from_router.len()
    );

    // ── `queryable_info`, against the `--complete` FLAG ────────────────────
    // Nothing else in this fixture can produce that bit, so a reader that took
    // `complete` from the wrong bit of the low byte reds here while passing
    // every self-witness this workspace holds.
    assert_some_reads(
        &from_client,
        "Declare",
        "queryable_info",
        &[("complete", Reading::Flag(true))],
    );

    // ── `target`, against the `--target ALL_COMPLETE` FLAG ─────────────────
    // On the ROUTER's half: this is the query the stock client asked, as the
    // stock router re-encoded it onto the queryable's face.
    assert_some_reads(
        &from_router,
        "Request",
        "target",
        &[("target", Reading::Label("AllComplete".into()))],
    );

    // ── `qos`, against upstream's own per-message constants ────────────────
    // Two rows, and they are each other's control: a walker that ignored the
    // priority bits would satisfy one of them by accident and never both, and
    // a walker that read D_FLAG as `Drop` would satisfy neither.
    assert_some_reads(
        &from_client,
        "Declare",
        "qos",
        &[
            ("priority", Reading::Label("Control".into())),
            ("congestion", Reading::Label("Block".into())),
            ("express", Reading::Flag(false)),
        ],
    );
    assert_some_reads(
        &from_router,
        "Request",
        "qos",
        &[
            ("priority", Reading::Label("Data".into())),
            ("congestion", Reading::Label("Block".into())),
            ("express", Reading::Flag(false)),
        ],
    );

    // ── `timeout`, against the `-o` FLAG ──────────────────────────────────
    // Not a walked row -- `SCALAR_Z64_BODIES` declares it, correctly, as
    // milliseconds that ARE the answer -- and asserted anyway, because every
    // walker above reads its value out of the same VLE this does. A `value`
    // decoded a byte wide of the truth would feed all six of them, and this is
    // the only row in the capture whose exact number a foreign CLI flag names.
    let timeouts: Vec<&Body> = from_router
        .iter()
        .filter(|b| b.carrier == "Request" && b.name == "timeout")
        .collect();
    assert!(
        !timeouts.is_empty(),
        "the router forwarded no `Request` carrying a `timeout` extension, so \
         the value leg below is about nothing:\n{}",
        dump(&bodies)
    );
    for timeout in &timeouts {
        assert_eq!(
            timeout.value,
            Some(
                GET_TIMEOUT_MS
                    .parse::<u64>()
                    .expect("GET_TIMEOUT_MS parses")
            ),
            "the querier was spawned `-o {GET_TIMEOUT_MS}` and the router \
             forwarded a different number: {}",
            timeout.describe()
        );
        assert!(
            timeout.read.is_empty(),
            "`timeout` is a DECLARED SCALAR row (`SCALAR_Z64_BODIES`) and \
             something gave it sub-fields: {}",
            timeout.describe()
        );
    }

    // ── `patch`, whose subject is a SILENCE ───────────────────────────────
    // `PatchType::CURRENT` is 1 and upstream narrows the field with
    // `ext.value as u8`, so 1 is a value a receiver acts on AS WRITTEN and
    // `read_patch_z64` must emit nothing at all. R311y899 made the presence of
    // `read_as` a FINDING; this is the leg that says the finding does not fire
    // on a conforming capture, and it is the half of that walker no
    // hand-written fixture in this tree covers.
    let patches: Vec<&Body> = bodies.iter().filter(|b| b.name == "patch").collect();
    assert!(
        !patches.is_empty(),
        "neither stock peer announced a protocol patch, so the narrowed-row \
         control leg is about nothing:\n{}",
        dump(&bodies)
    );
    for patch in &patches {
        assert_eq!(
            patch.value,
            Some(1),
            "a stock zenoh 1.5.0 peer announces `PatchType::CURRENT` = 1 \
             (zenoh-protocol/src/transport/mod.rs:322): {}",
            patch.describe()
        );
        assert!(
            patch.read.is_empty(),
            "`read_patch_z64` spoke about a value a receiver acts on AS \
             WRITTEN. R311y899's rule is that these fields are a FINDING -- \
             `read_as` / `undefined_bits` / `absent_to_receiver` mean the wire \
             said something no peer will act on -- so emitting them for a \
             conforming `patch` would report every stock handshake as a \
             narrowing: {}",
            patch.describe()
        );
    }
}
