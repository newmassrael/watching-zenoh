// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! wz <-> zenoh-ext GROUP-MEMBERSHIP cross-impl interop (R311y445).
//!
//! `ext-pubsub-group-membership` was built in R311y97 and graded PARTIAL in
//! R311y441, but until this file it had NO foreign witness: every test of it was
//! wz<->wz, where the same encoder sits on both ends of the claim. That is the
//! arrangement R311y441 showed cannot see a dialect defect — a wz pair agrees on
//! a wire spelling no zenoh peer reads, because the spelling is wrong in the same
//! way twice.
//!
//! ## Why the oracle is `z_view_size` and not `z_member`
//!
//! Both are zenoh-ext group examples, and only one is usable. `z_member` builds
//! `Config::default()` with no `CommonArgs`, so it cannot be pointed at a zenohd
//! with `-e` and would depend on multicast scouting. `z_view_size` takes the full
//! `CommonArgs` AND — the load-bearing part — prints its own VERDICT:
//! `wait_for_view_size` yields either
//!
//! ```text
//! Established view size of N with members:
//!  - <id>
//! ```
//!
//! or `Failed to establish view size of N`. So the pass/fail judgement is made by
//! the FOREIGN implementation and merely read here, rather than being inferred
//! from wz's own logs. Provisioned by `scripts/build-zenohd.sh` alongside the
//! advanced-pubsub oracles.
//!
//! ## What the legs prove
//!
//! 1. **PROOF (keep-alive + queryable).** wz joins FIRST, so the oracle arrives
//!    to a member it never heard announce itself. wz's periodic `KeepAlive`
//!    reveals the id; upstream does not know it, so it GETs the per-member
//!    keyexpr (`zenoh-ext/src/group.rs`
//!    @ `Received Keep Alive from unknown member`, the ONLY client-side get in its
//!    group protocol) and wz's queryable answers with the `Member` record. Both
//!    encoders are load-bearing here — damaging either reds this leg.
//! 2. **CONTROL.** The same fixture with wz joining a DIFFERENT group. wz is
//!    still running, still connected, still publishing group traffic — only the
//!    group id differs, and the oracle now fails to reach size 2. That is what
//!    separates "upstream decoded our membership" from "upstream counted a peer
//!    that happened to be there": a process-absence control could not.
//!
//!    Its reach is narrower than that wording alone suggests. R311y445-review
//!    measured it: making only the EVENT keyexpr group-blind leaves all three
//!    legs green, so a wz that leaked group events into another group's
//!    namespace would not be caught here. It reds when both keyexprs go blind.
//! 3. **PROOF (Join broadcast).** The oracle joins FIRST into an empty group, so
//!    the queryable path of leg 1 is closed by construction and wz's `Join`
//!    announcement is the only way in. Isolated with a 60s lease so wz's first
//!    keep-alive (lease * 0.75 = 45s) lands long after the leg ends — measured at
//!    exactly +45.0s against a 0.2s leg.
//!
//! ## R2622 — the three legs where wz is the OBSERVER
//!
//! Legs 1-3 all grade wz's ENCODERS: the observable is upstream's verdict, and
//! what it says is that a real zenoh-ext `Group` could read what wz wrote. The
//! other direction was unwitnessed, and the two residuals this atom carried into
//! R2622 both live there — the election rule and the lease-expiry sweep are
//! things wz COMPUTES from a foreign member's record, so no amount of upstream
//! reading wz can reach them.
//!
//! 4. **PROOF (leader election, foreign wins).** A zenoh-ext member whose id
//!    sorts above wz's joins, and wz must hand it the leadership.
//! 5. **PROOF (leader election, local wins) + leg 4's ANTI-VACUITY ARM.** Same
//!    fixture, an id that sorts below wz's, and the answer must flip. Either arm
//!    alone passes for a wz that always answers the same way.
//! 6. **PROOF (lease-expiry eviction).** A zenoh-ext member joins, exits, and wz
//!    must drop it on the lease THAT MEMBER advertised. wz advertises 60s against
//!    the oracle's 3s, so the eviction window is itself the control.
//!
//! The third residual this atom carried, `Leave`, is NOT here, and that is a
//! finding rather than an omission: neither implementation ever SENDS one.
//! `GroupNetEvent::Leave` has a decode arm on both sides and no construction site
//! on either, so a leg driving an undeclare could only be built by giving wz an
//! emitter upstream does not have. Eviction by lease is how a member leaves a
//! view in both implementations, which is leg 6.
//!
//! Every test fn carries the `zenoh_ext` token, per the naming obligation
//! R311y443 recorded: run-ci's Layer E catch-all skips by that substring and runs
//! a demo built without these features, where `--group-join` is INERT.
//!
//! Opt-in (`#[ignore]`, run-ci Layer Z): zenohd and the zenoh-ext example are
//! external binaries, and wz-ap-demo must be built `--features group` (without it
//! the demo logs INERT and joins nothing, which the legs assert against).

use std::fs::File;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use wz_integration_tests::common::{
    spawn_zenohd_on_ephemeral_tcp, wait_for_substring, wz_ap_demo_binary, zenoh_ext_example_binary,
    ChildGuard,
};

/// How long a leg waits for a marker line before declaring the fixture dead.
const MARKER_TIMEOUT: Duration = Duration::from_secs(20);

/// The group both sides join in the proof leg.
const GROUP: &str = "zgroup";

/// wz's member id — the literal the oracle must print in its view listing.
const WZ_MEMBER: &str = "wz-member";

/// The oracle's own member id, so the listing is unambiguous about which line is
/// wz's and which is upstream's own.
const ORACLE_MEMBER: &str = "oracle";

/// R2622 — an oracle id that sorts ABOVE [`WZ_MEMBER`], for the leg where the
/// elected leader must be the FOREIGN member.
///
/// The election rule is `max` by id, byte-compared, on both sides (`zenoh-ext/
/// src/group.rs` @ `pub async fn leader(&self) -> Member {`, which folds the view
/// with `leader.id().as_str().cmp(m.id().as_str()) == Ordering::Less`). `'z'`
/// (0x7a) is above `'w'` (0x77), so this id wins against `wz-member` and the id
/// below loses to it. Both are asserted in the leg itself rather than trusted
/// here, because a constant that silently stopped satisfying its own ordering
/// would turn the pair into two copies of the same arm.
const ORACLE_MEMBER_ABOVE_WZ: &str = "zz-oracle";

/// R2622 — an oracle id that sorts BELOW [`WZ_MEMBER`], for the leg where the
/// elected leader must be the LOCAL member. See [`ORACLE_MEMBER_ABOVE_WZ`].
const ORACLE_MEMBER_BELOW_WZ: &str = "aa-oracle";

/// R2622 — the view size the OBSERVING legs ask the oracle for, and it is
/// deliberately unreachable.
///
/// Those legs read wz's log, not the oracle's verdict, and what they need from
/// the oracle is that it JOINS (so wz decodes its record) and then EXITS (so its
/// keep-alives stop). Asking for a size that can never be met makes the exit
/// happen on the timeout, at a moment the fixture picks, instead of at whatever
/// moment wz's beacon happens to complete the oracle's view. Two members exist,
/// so three is out of reach by construction.
const UNREACHABLE_VIEW_SIZE: usize = 3;

/// R2622 — how long the observing legs let the oracle run before it gives up and
/// exits. Short on purpose: it is the START of the eviction clock, not a budget.
const OBSERVER_ORACLE_TIMEOUT_SECS: u64 = 3;

/// R2622 — how long wz is given to evict the departed oracle, and this bound is
/// the lease-expiry leg's CONTROL rather than a comfort margin.
///
/// The leg makes wz advertise [`JOIN_ISOLATION_LEASE_SECS`] (60s) while the
/// oracle advertises 3s, which upstream's example hardcodes:
/// `zenoh-ext/examples/examples/z_view_size.rs` @ `.lease(Duration::from_secs(3))`.
/// An eviction can
/// therefore only land inside this window if wz timed it on the lease the FOREIGN
/// member advertised -- the one that crossed the wire inside upstream's bincode
/// `Member`. A wz that fell back to its own advertised lease, or to
/// `DEFAULT_LEASE` (18s), lands outside it and the leg reds. Budget: the oracle
/// beacons at 3 * 0.75 = 2.25s and exits at 3s, so the last refresh wz sees is at
/// 2.25s and the deadline it computes is 5.25s, swept within 1s by the watchdog.
/// The two fallbacks land at 2.25 + 18 = 20.25s and 2.25 + 60 = 62.25s, so both
/// sit outside this window while the correct answer sits at roughly half of it.
const EVICTION_DEADLINE: Duration = Duration::from_secs(12);

/// The member lease for the legs that need wz's keep-alive beacon running.
///
/// THIS IS A LATENCY BUDGET, NOT AN EVICTION SETTING, and the first version of
/// this comment said the opposite ("matched to the oracle's 3s so wz refreshes
/// before it evicts a member"). Upstream evicts a member on the lease THAT
/// MEMBER ADVERTISED, not on its own (`zenoh-ext/src/group.rs`
/// @ `Instant::now().add(m.lease)` -- every site that computes an eviction
/// deadline takes `m.lease` from the received record), which is exactly why leg
/// 3 can advertise 60s with no ill effect. Matching the oracle's own 3s is
/// therefore irrelevant to eviction.
///
/// What it actually sets is the beacon period, `lease * refresh_ratio` (0.75) =
/// 2.25s — and that beacon is leg 1's DISCOVERY TRIGGER, so this value is what
/// decides whether leg 1 finishes inside [`VIEW_TIMEOUT_SECS`]. Measured margin:
/// 8 - 2.25 = 5.75s. R311y445-review measured the cliff too: at ~9s this leg goes
/// flaky, at 11s it fails permanently. Do not raise it to match
/// [`JOIN_ISOLATION_LEASE_SECS`] "for consistency" — that silently reds leg 1 and
/// leaves the control green for the wrong reason.
const LEASE_SECS: u64 = 3;

/// The member lease for the leg that must ISOLATE the `Join` broadcast.
///
/// This is the mechanism that makes that isolation possible, and it was found by
/// measurement after a first draft failed. Upstream does NOT need `Join` to learn
/// a member: on a KeepAlive from an id it does not know it fires an
/// unknown-member GET (`zenoh-ext/src/group.rs` @ `let qres = format!`) and
/// recovers the record
/// from the member's own queryable. So with a short lease, damaging `Join` proves
/// nothing — the KeepAlive path silently repairs it, which is exactly what the
/// first version of the broadcast leg measured (all three legs stayed green under
/// a damaged Join variant).
///
/// wz emits keep-alives every `lease * refresh_ratio` (0.75), so a 60s lease puts
/// the first one ~45s out — far past this leg's runtime. Within the leg, `Join`
/// is the only event wz emits, and the isolation is by CONSTRUCTION rather than
/// by hoping the timing works out.
const JOIN_ISOLATION_LEASE_SECS: u64 = 60;

/// How long the oracle waits for its view to reach the expected size.
///
/// MUST stay comfortably below [`MARKER_TIMEOUT`], and the margin is the whole
/// reason this is not simply 20s. The CONTROL leg's observable is the oracle's
/// NEGATIVE verdict, which it only prints after this timeout expires — so a
/// marker wait equal to it is a race the fixture loses, reporting "printed
/// neither verdict" for a fixture that was working correctly. Measured: the
/// first draft used 20s for both and the control failed exactly that way.
const VIEW_TIMEOUT_SECS: u64 = 8;

fn tempfile() -> std::fs::File {
    tempfile::tempfile().expect("tempfile for captured child output")
}

/// Spawn a wz demo that joins `group`, and return once it has JOINED.
///
/// Waiting for the join marker is what makes a later oracle failure attributable:
/// without it, "the oracle never saw wz" and "wz never joined" are the same
/// observation.
///
/// R2622 — the open READER comes back with the child, because three of this
/// file's legs read wz's log only up to the join line and two read it afterwards.
/// Returning the handle rather than adding a second spawn function keeps ONE
/// derivation of how a wz group member is started: a second one would drift, and
/// the legs that observe wz would then be observing a differently-configured
/// member than the legs wz is observed by.
fn spawn_wz_group_member(port: u16, group: &str, lease_secs: u64) -> (ChildGuard, File, String) {
    let demo = wz_ap_demo_binary();
    let stderr = tempfile();
    let writer = stderr.try_clone().expect("dup wz-ap-demo stderr");
    let mut reader = stderr;
    let child = ChildGuard::wrap(
        "wz-ap-demo (--group-join)",
        Command::new(&demo)
            .arg("--connect")
            .arg(format!("127.0.0.1:{port}"))
            .arg("--group-join")
            .arg(group)
            .arg("--group-member-id")
            .arg(WZ_MEMBER)
            .arg("--group-lease-secs")
            .arg(lease_secs.to_string())
            .env("RUST_LOG", "info")
            .stdout(Stdio::null())
            .stderr(Stdio::from(writer))
            .spawn()
            .expect("spawn wz-ap-demo group member"),
    );
    let captured = wait_for_substring(&mut reader, "JOINED GROUP", MARKER_TIMEOUT).unwrap_or_else(
        |snapshot| {
            panic!(
                "wz-ap-demo never joined the group. If this says INERT, the demo was \
                 built without `--features group`.\n--- captured ---\n{snapshot}"
            )
        },
    );
    assert!(
        !captured.contains("is INERT"),
        "wz-ap-demo reports --group-join INERT; build it with `--features \
         group`.\n--- captured ---\n{captured}"
    );
    // The join line echoes the group it actually joined, so a fixture that meant
    // to vary the group and did not is caught here rather than downstream, where
    // it would read as the control leg passing.
    assert!(
        captured.contains(&format!("group='{group}'")),
        "wz-ap-demo joined a different group than {group:?}\n--- captured ---\n{captured}"
    );
    (child, reader, captured)
}

/// Run upstream's `z_view_size` against `port` and return everything it printed.
fn run_zenoh_ext_view_size(port: u16, group: &str, size: usize) -> String {
    let (child, mut reader) =
        spawn_zenoh_ext_view_size(port, group, size, ORACLE_MEMBER, VIEW_TIMEOUT_SECS);
    let verdict = wait_view_verdict(&mut reader);
    drop(child);
    verdict
}

/// Spawn `z_view_size` WITHOUT waiting for its verdict.
///
/// Split out because the ORDER of the two peers decides which wz code path the
/// leg exercises, and one of the two orders needs the oracle running first:
///
///   * oracle LAST — it joins into an already-populated group, so it learns wz
///     through the per-member QUERYABLE its own view query hits;
///   * oracle FIRST — its view query finds nothing, so the only way wz can enter
///     its view is the `Join` BROADCAST wz emits on joining.
///
/// Those are different encoders on wz's side, and a leg that does not control the
/// order silently proves whichever one happened to run.
///
/// R2622 — `id` and `timeout_secs` became parameters because the legs where wz is
/// the OBSERVER vary exactly those two. The member id is the whole variable of
/// the leader-election pair (it is what the election compares), and the timeout
/// is what decides when the oracle EXITS, which is the event the lease-expiry leg
/// is waiting on.
fn spawn_zenoh_ext_view_size(
    port: u16,
    group: &str,
    size: usize,
    id: &str,
    timeout_secs: u64,
) -> (ChildGuard, File) {
    let bin = zenoh_ext_example_binary("z_view_size");
    let output = tempfile();
    let writer = output.try_clone().expect("dup z_view_size stdout");
    let reader = output;
    let child = ChildGuard::wrap(
        "z_view_size (zenoh-ext oracle)",
        Command::new(&bin)
            .arg("--mode")
            .arg("client")
            .arg("-e")
            .arg(format!("tcp/127.0.0.1:{port}"))
            .arg("--no-multicast-scouting")
            .arg("--group")
            .arg(group)
            .arg("--size")
            .arg(size.to_string())
            .arg("--timeout")
            .arg(timeout_secs.to_string())
            .arg("--id")
            .arg(id)
            .env("RUST_LOG", "error")
            .stderr(Stdio::from(writer.try_clone().expect("dup stderr handle")))
            .stdout(Stdio::from(writer))
            .spawn()
            .expect("spawn z_view_size"),
    );
    // BARRIER, not decoration — but a WEAKER one than the first version claimed.
    // The example prints this line after `Group::join` returns, and that
    // guarantees its own Join has gone out (`zenoh-ext/src/group.rs`
    // @ `let is_auto_liveliness` awaits
    // the put) but NOT that its event subscriber exists: `join` only
    // `spawn_abortable`s `net_event_handler` (`:400`), and the
    // `declare_subscriber` runs inside that task (`:248-251`). The residual race
    // is small in practice — wz still has to fork, dial zenohd and join — and
    // R311y445-review measured leg 3 green 3/3 including under 3x CPU
    // oversubscription. The broadcast leg spawns wz next, and wz
    // announces itself ONCE; without this wait that announcement can precede the
    // oracle's subscriber and be missed, which reads downstream as "wz's Join was
    // not decoded" when nothing was ever listening. Measured: the first draft had
    // no barrier here and the broadcast leg failed for exactly that reason.
    let mut reader = reader;
    wait_for_substring(&mut reader, "waiting for", MARKER_TIMEOUT).unwrap_or_else(|snapshot| {
        panic!(
            "z_view_size never reported that it had joined and started waiting\n\
             --- z_view_size ---\n{snapshot}"
        )
    });
    (child, reader)
}

/// Block until the oracle prints one of its two verdicts.
///
/// The example prints exactly one and then exits, so this is a real barrier
/// rather than a sleep. Note that "waiting for N members" does NOT contain the
/// needle, deliberately: only the decision does.
fn wait_view_verdict(reader: &mut std::fs::File) -> String {
    wait_for_substring(reader, "view size of", MARKER_TIMEOUT).unwrap_or_else(|snapshot| {
        panic!(
            "z_view_size printed neither verdict within {MARKER_TIMEOUT:?}; the \
             oracle never reached its decision\n--- z_view_size ---\n{snapshot}"
        )
    })
}

/// Leg 1 — the PROOF for wz's KEEP-ALIVE plus its per-member QUERYABLE. wz joins
/// first, so by the time the oracle arrives wz is already a member it has never
/// heard announce itself; wz's periodic keep-alive is what reveals it, and wz's
/// queryable then serves the `Member` record on the bincode wire.
///
/// ## This leg's trigger has been misattributed TWICE, so it is spelled out
///
/// The first version claimed the `Join` broadcast — refuted by damage (Join
/// variant 0 -> 7 leaves this leg green; `Join` is not on its path once wz is
/// already in the group). R311y445 then replaced that with "the oracle's own view
/// query", which does not exist: `Group::join` issues NO query
/// (`zenoh-ext/src/group.rs` @ `// announce the member:` declares a publisher,
/// puts its Join and
/// spawns four tasks), and the only client-side `z.get()` in the whole of
/// upstream's group protocol is at `group.rs:307`, inside the KeepAlive handler's
/// unknown-member arm (`group.rs:279-307`).
///
/// The real chain, confirmed by R311y445-review's damage matrix: wz emits a
/// `KeepAlive` (`group_membership.rs:258-261`, variant index 2) every
/// `lease * refresh_ratio`; the oracle does not know that member id, so it GETs
/// `zenoh/ext/net/group/<gid>/<mid>`; wz's per-member queryable answers with
/// `push_member` (`group_membership.rs:222`). BOTH encoders are on this leg:
/// damaging the KeepAlive variant (2 -> 8) reds it ALONE, and damaging
/// `push_member` reds it too. The timing corroborates — this leg costs ~2.36s,
/// which is the 2.25s beacon period, while leg 3 (no beacon needed) costs 0.2s.
// wz-proves: ext-pubsub-group-membership wz->zenoh-ext
#[test]
#[ignore = "external binaries: zenohd + zenoh-ext z_view_size; run-ci Layer Z"]
fn zenoh_ext_group_view_recovers_the_wz_member_after_its_keepalive() {
    let (_zenohd, port) = spawn_zenohd_on_ephemeral_tcp(tempfile);
    let (_wz, _wz_out, wz_log) = spawn_wz_group_member(port, GROUP, LEASE_SECS);
    let view = run_zenoh_ext_view_size(port, GROUP, 2);
    let ctx = format!("--- z_view_size ---\n{view}\n--- wz ---\n{wz_log}");

    assert!(
        view.contains("Established view size of 2"),
        "a real zenoh-ext group peer never reached a view of 2 with wz in the \
         group. wz DID join (asserted above), so either its KeepAlive was not \
         decoded or its per-member queryable did not answer the resulting GET — \
         those two encoders are this leg's path, NOT Join\n{ctx}"
    );
    // The size alone would be satisfied by any second member; the ID is what
    // makes this a statement about wz's member record surviving the round trip.
    assert!(
        view.contains(&format!(" - {WZ_MEMBER}")),
        "the oracle established a view of 2 but did not name {WZ_MEMBER:?} in it, \
         so the second member is not the one under test\n{ctx}"
    );
}

/// Leg 2 — the CONTROL. Same fixture, wz joins a DIFFERENT group, and the oracle
/// cannot reach a view of 2.
///
/// The variable is the group id ALONE: wz is still running, still connected to
/// the same zenohd, and still emitting the same Join / KeepAlive traffic on the
/// group namespace. So this rules out the reading that upstream simply counted a
/// peer that happened to be present — the thing a "wz not started" control could
/// never rule out.
// wz-proves: none -- the CONTROL for the group-membership leg.
#[test]
#[ignore = "external binaries: zenohd + zenoh-ext z_view_size; run-ci Layer Z"]
fn zenoh_ext_group_view_excludes_a_wz_member_of_another_group() {
    let (_zenohd, port) = spawn_zenohd_on_ephemeral_tcp(tempfile);
    let (_wz, _wz_out, wz_log) = spawn_wz_group_member(port, "other-group", LEASE_SECS);
    let view = run_zenoh_ext_view_size(port, GROUP, 2);
    let ctx = format!("--- z_view_size ---\n{view}\n--- wz ---\n{wz_log}");

    assert!(
        view.contains("Failed to establish view size of 2"),
        "the oracle reached a view of 2 while wz was in a DIFFERENT group, so the \
         proof leg's positive result is not attributable to group membership — \
         either the group id is not on the wire or it is not being matched\n{ctx}"
    );
    assert!(
        !view.contains(&format!(" - {WZ_MEMBER}")),
        "the oracle listed {WZ_MEMBER:?} in a group wz never joined\n{ctx}"
    );
}

/// Leg 3 — the PROOF for wz's `Join` BROADCAST, the half leg 1 cannot reach.
///
/// The oracle joins FIRST here, and that ordering is the whole leg. Its own view
/// query goes out into an empty group, so the per-member queryable path leg 1
/// exercises is closed by construction: the only way wz can enter this view is
/// the `GroupNetEvent::Join` wz publishes on `zenoh/ext/net/group/<gid>/evt` when
/// it joins, decoded by a real zenoh-ext `Group`.
///
/// Bound to the atom's own wire artifact rather than to a flag, per the standard
/// R311y443-review set: changing the Join variant index in `encode_net_event`
/// (`group_membership.rs:251`, 0 -> 7) reds THIS leg and leaves legs 1 and 2
/// green — which is exactly how the false claim in leg 1's first version was
/// found.
// wz-proves: ext-pubsub-group-membership wz->zenoh-ext
#[test]
#[ignore = "external binaries: zenohd + zenoh-ext z_view_size; run-ci Layer Z"]
fn zenoh_ext_group_view_learns_the_wz_member_from_its_join_broadcast() {
    let (_zenohd, port) = spawn_zenohd_on_ephemeral_tcp(tempfile);
    // ORACLE FIRST. It is already waiting, with an empty view, before wz exists.
    let (_oracle, mut oracle_out) =
        spawn_zenoh_ext_view_size(port, GROUP, 2, ORACLE_MEMBER, VIEW_TIMEOUT_SECS);
    let (_wz, _wz_out, wz_log) = spawn_wz_group_member(port, GROUP, JOIN_ISOLATION_LEASE_SECS);
    let view = wait_view_verdict(&mut oracle_out);
    let ctx = format!("--- z_view_size ---\n{view}\n--- wz ---\n{wz_log}");

    assert!(
        view.contains("Established view size of 2"),
        "the oracle was already in the group with an empty view when wz joined, \
         so wz's Join broadcast was the only path into that view — and it never \
         arrived or was not decoded\n{ctx}"
    );
    assert!(
        view.contains(&format!(" - {WZ_MEMBER}")),
        "the oracle reached a view of 2 without naming {WZ_MEMBER:?}\n{ctx}"
    );
}

/// R2622 — what [`wz_observes_foreign_member`] hands back.
///
/// A struct rather than a tuple because THREE of its five fields exist only to
/// be held: dropping any of the guards kills the process the leg is still
/// reading from, and a tuple invites a caller to bind the ones it reads and
/// discard the rest. The wz guard is the sharp one — `-D warnings` caught the
/// first draft doing exactly that, which would have killed wz before any leg
/// observed anything.
struct Observed {
    _zenohd: ChildGuard,
    _wz: ChildGuard,
    _oracle: ChildGuard,
    /// wz's still-open log, positioned to be read for events AFTER the join.
    wz_out: File,
    /// Everything wz had logged when the foreign member entered its view.
    seen: String,
}

/// R2622 — the fixture for the legs where wz is the OBSERVER, returning once wz
/// has logged the foreign member into its own view.
///
/// Legs 1-3 all read the ORACLE's verdict, which makes them statements about
/// wz's ENCODERS. The two residuals this fixture serves — the election rule and
/// the lease-expiry sweep — are statements about wz's DECODERS and about what it
/// computes from them, so the observable has to be wz's log and the foreign
/// member has to be the thing wz reports on.
///
/// Order and leases are both load-bearing, and neither is free choice:
///
///   * **wz FIRST.** Upstream's `Group::join` broadcasts its `Join` and only then
///     spawns the task that declares its subscriber (`zenoh-ext/src/group.rs`
///     @ `async fn net_event_handler(z: Arc<Session>, state: Arc<GroupState>) {`),
///     which is the same race leg 3 documents in the other direction. Here wz is
///     the listener, so wz must be joined and subscribed before the oracle
///     announces itself, or the announcement lands on nobody.
///   * **wz advertises 60s.** wz is not being observed in these legs, so it needs
///     no beacon of its own, and a long lease makes wz's own lease unusable as an
///     eviction clock — see [`EVICTION_DEADLINE`].
///   * **the oracle is asked for an unreachable view size.** It then exits on its
///     own timeout at a moment the fixture chose, rather than the moment its view
///     happened to fill. See [`UNREACHABLE_VIEW_SIZE`].
fn wz_observes_foreign_member(oracle_id: &str) -> Observed {
    let (zenohd, port) = spawn_zenohd_on_ephemeral_tcp(tempfile);
    let (wz, mut wz_out, join_log) = spawn_wz_group_member(port, GROUP, JOIN_ISOLATION_LEASE_SECS);
    let (oracle, _oracle_out) = spawn_zenoh_ext_view_size(
        port,
        GROUP,
        UNREACHABLE_VIEW_SIZE,
        oracle_id,
        OBSERVER_ORACLE_TIMEOUT_SECS,
    );
    // The barrier: wz has DECODED upstream's `Member` record and folded it into
    // its view. Everything downstream is about what wz computed from it, so a
    // failure here is attributable to the decode rather than to the election or
    // the sweep.
    let seen = wait_for_substring(
        &mut wz_out,
        &format!("GROUP VIEW event=Join mid='{oracle_id}' size=2"),
        MARKER_TIMEOUT,
    )
    .unwrap_or_else(|snapshot| {
        panic!(
            "wz never folded the foreign member {oracle_id:?} into its view. wz DID \
             join (asserted above) and the oracle DID start waiting (asserted in \
             its spawn), so upstream's `Join` either never arrived or wz did not \
             decode it\n--- wz ---\n{snapshot}\n--- wz join ---\n{join_log}"
        )
    });
    Observed {
        _zenohd: zenohd,
        _wz: wz,
        _oracle: oracle,
        wz_out,
        seen,
    }
}

/// Leg 4 — the PROOF for LEADER ELECTION ACROSS IMPLEMENTATIONS, foreign-wins arm.
///
/// The elected leader here is a member wz has never been configured with: its id
/// reached wz only inside upstream's bincode `Member`, and wz must then rank it
/// above its own. That is the part no wz<->wz test can reach — a wz pair agrees
/// on an ordering even if the ordering is upstream's reversed.
///
/// The rule is `max` by id on both sides: `zenoh-ext/src/group.rs`
/// @ `pub async fn leader(&self) -> Member {` folds the view keeping the greater
/// id, and `crates/wz-runtime-tokio/src/group.rs`
/// @ `pub fn leader(&self) -> Member {` does the same over the same view. Note
/// what is NOT claimed: upstream never PUBLISHES a leader (its
/// `GroupEvent::NewLeader` has no construction site anywhere in the protocol, and
/// wz mirrors that omission), so there is no foreign leader announcement to agree
/// with. The election is a pull over the view, and this leg grades wz's fold
/// against a view containing a real foreign member.
///
/// Paired with leg 5, which is the same fixture with the ordering reversed. Alone
/// either arm passes for a wz that always answers the same way.
// wz-proves: ext-pubsub-group-membership zenoh-ext->wz
#[test]
#[ignore = "external binaries: zenohd + zenoh-ext z_view_size; run-ci Layer Z"]
fn wz_group_elects_the_zenoh_ext_member_whose_id_sorts_above_its_own() {
    assert!(
        ORACLE_MEMBER_ABOVE_WZ > WZ_MEMBER,
        "this leg's premise is that {ORACLE_MEMBER_ABOVE_WZ:?} sorts above \
         {WZ_MEMBER:?}; with the constants as they stand it does not, so the leg \
         would grade the opposite of what it claims"
    );
    let observed = wz_observes_foreign_member(ORACLE_MEMBER_ABOVE_WZ);
    let seen = observed.seen;

    assert!(
        seen.contains(&format!(
            "event=Join mid='{ORACLE_MEMBER_ABOVE_WZ}' size=2 \
             leader='{ORACLE_MEMBER_ABOVE_WZ}'"
        )),
        "wz reached a view of 2 with the foreign member in it but did not elect \
         {ORACLE_MEMBER_ABOVE_WZ:?}, whose id sorts above wz's own — so wz's \
         election does not agree with zenoh-ext's over a shared view\n--- wz ---\n{seen}"
    );
}

/// Leg 5 — the PROOF for LEADER ELECTION ACROSS IMPLEMENTATIONS, local-wins arm,
/// and leg 4's anti-vacuity control.
///
/// Identical fixture, one variable: the foreign member's id now sorts BELOW wz's,
/// so the correct answer flips to wz itself.
///
/// MEASURED, and not what the first draft of this comment claimed. Reversing the
/// comparison in `crates/wz-runtime-tokio/src/group.rs`
/// @ `if leader.id() < m.id() {` reds BOTH arms, not one: with the fold keeping
/// the smaller id, leg 4 elects wz where the oracle should win and leg 5 elects
/// the oracle where wz should. Legs 1-3 stay green, so the damage is localised.
/// What the PAIR buys is therefore not reversal-detection -- either arm alone
/// catches that -- but the CONSTANT answer: a wz that always named the local
/// member, or always the foreign one, passes whichever single arm agrees with it.
/// Only two arms whose correct answers differ can tell an election from a habit.
// wz-proves: ext-pubsub-group-membership zenoh-ext->wz
#[test]
#[ignore = "external binaries: zenohd + zenoh-ext z_view_size; run-ci Layer Z"]
fn wz_group_keeps_the_leadership_over_a_zenoh_ext_member_that_sorts_below_it() {
    assert!(
        ORACLE_MEMBER_BELOW_WZ < WZ_MEMBER,
        "this leg's premise is that {ORACLE_MEMBER_BELOW_WZ:?} sorts below \
         {WZ_MEMBER:?}; with the constants as they stand it does not, so the leg \
         would grade the opposite of what it claims"
    );
    let observed = wz_observes_foreign_member(ORACLE_MEMBER_BELOW_WZ);
    let seen = observed.seen;

    assert!(
        seen.contains(&format!(
            "event=Join mid='{ORACLE_MEMBER_BELOW_WZ}' size=2 leader='{WZ_MEMBER}'"
        )),
        "wz saw a foreign member whose id sorts BELOW its own and handed it the \
         leadership anyway, so wz's election is not comparing ids in zenoh-ext's \
         direction\n--- wz ---\n{seen}"
    );
}

/// Leg 6 — the PROOF for the LEASE-EXPIRY EVICTION PATH against a real zenoh-ext
/// member.
///
/// Neither implementation announces its departure: `GroupNetEvent::Leave` has a
/// decode arm on both sides and NO construction site on either
/// (`zenoh-ext/src/group.rs` @ `enum GroupNetEvent {` declares it; nothing in the
/// crate serialises one). Eviction by lease is therefore the ONLY way a group
/// member ever leaves a view, in either implementation, which is what makes this
/// leg the one that matters rather than a completeness exercise.
///
/// What crosses the wire here is a `Duration` inside upstream's bincode `Member`,
/// and wz's eviction deadline is computed from it —
/// `crates/wz-runtime-tokio/src/group.rs`
/// @ `let alive_till = now_ms.saturating_add(member.lease.as_millis() as u64);`,
/// mirroring `zenoh-ext/src/group.rs` @ `let alive_till = Instant::now().add(je.member.lease);`.
/// The control is built into [`EVICTION_DEADLINE`] rather than bolted on: wz
/// advertises 60s and the oracle 3s, so an eviction inside the window can only
/// have been timed on the foreign value.
// wz-proves: ext-pubsub-group-membership zenoh-ext->wz
#[test]
#[ignore = "external binaries: zenohd + zenoh-ext z_view_size; run-ci Layer Z"]
fn wz_group_evicts_a_departed_zenoh_ext_member_on_the_lease_it_advertised() {
    let mut observed = wz_observes_foreign_member(ORACLE_MEMBER);
    // Timed from the moment wz HAS the member, not from the spawn: the oracle's
    // own start-up is not part of the lease, and folding it in would make the
    // window a measurement of process launch cost.
    let joined_at = Instant::now();

    let expired = wait_for_substring(
        &mut observed.wz_out,
        &format!("event=LeaseExpired mid='{ORACLE_MEMBER}' size=1"),
        EVICTION_DEADLINE,
    )
    .unwrap_or_else(|snapshot| {
        panic!(
            "wz still held the departed zenoh-ext member after {EVICTION_DEADLINE:?}. \
             The oracle exits on its own {OBSERVER_ORACLE_TIMEOUT_SECS}s timeout and \
             advertised a 3s lease, so an eviction timed on the FOREIGN lease is due \
             at ~5.25s; wz advertised {JOIN_ISOLATION_LEASE_SECS}s, so this is the \
             shape of wz timing the sweep on its own lease (or on DEFAULT_LEASE) \
             instead of the decoded one\n--- wz ---\n{snapshot}\n--- wz at join ---\n{}",
            observed.seen
        )
    });
    let elapsed = joined_at.elapsed();

    // Not a second spelling of the wait above: the wait proves an eviction landed
    // in the window, this proves it was not ALREADY there when the window opened.
    // A wz that evicted the member the instant it learned it would satisfy the
    // wait and is a different defect entirely.
    assert!(
        elapsed >= Duration::from_secs(1),
        "wz evicted the foreign member {elapsed:?} after folding it in, which is \
         shorter than any lease either side advertises — the sweep is not waiting \
         for a lease at all\n--- wz ---\n{expired}"
    );
}
