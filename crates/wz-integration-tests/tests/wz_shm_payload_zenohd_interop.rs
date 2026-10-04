// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! `transport-shm` -- the PAYLOAD, in both directions, against upstream's own SHM
//! publisher and subscriber.
//!
//! ## What was unmeasured
//!
//! `wz_shm_establishment_zenohd_interop` proves the two sides AGREE on shared
//! memory (`shm negotiated = true`, challenge-response both ways). Nothing ever
//! put a payload through that agreement with a zenoh process on the other end:
//! the atom's reason said so ("no CROSS-IMPL payload witness yet"), and the only
//! SHM round trip in the tree was wz's writer read back by wz's reader, which is
//! a self-witness of exactly the kind the establishment tests were written to
//! escape.
//!
//! `zenohd` cannot fill the gap: it relays an SHM buffer and never makes or reads
//! one. Upstream ships the two programs that do, `z_pub_shm` and `z_sub_shm`
//! (`examples/examples/`), and `ZENOHD_SHM=1 scripts/build-zenohd.sh` builds them
//! beside the shared-memory `zenohd`. `z_sub_shm` prints the kind of buffer each
//! sample arrived in -- `[SHM (IMMUT)]` or `[RAW]` -- which is the discriminator
//! this file relies on: a payload delivered raw proves nothing about shared
//! memory, and a delivered payload is the only thing a lenient reader would check.
//!
//! ## The legs
//!
//! ```text
//!   zenoh z_pub_shm --connect--> [ wz acceptor, PosixShmResolver ]   (leg 1, control)
//!   [ wz dialer, publish_shm ] --connect--> zenoh z_sub_shm --listen (leg 2, 3)
//! ```
//!
//! Leg 1 reads what zenoh wrote: upstream's provider allocates in a POOL, names a
//! header slot in ITS metadata segment, and the four-varint descriptor names that
//! slot. Its CONTROL is the same publisher against a wz acceptor that does not
//! offer SHM: zenoh then sends the payload raw, so that arm passing while leg 1
//! fails is the evidence that the failure is about shared memory and not about the
//! topology, the declarations or the harness.
//!
//! Legs 2 and 3 are wz's writer read by zenoh's reader, which validates the
//! header before it maps anything (`commons/zenoh-shm/src/reader.rs` @
//! `pub fn read_shmbuf(`). Leg 3 is the lifecycle arm: the publisher lets go of
//! its payload the moment `publish_shm` returns, which is what every real
//! publisher does, and the receiver reads some time later. Until R3038 that arm
//! FAILED (open-debt item 823 (6): wz's provider unlinked the segment when its
//! owner dropped) and was a PIN of the defect; the provider now holds a chunk by
//! the reference count upstream uses, and the leg is the positive twin of leg 2.
//!
//! Both directions also read the reference count itself off the OTHER side's
//! header. Leg 1 reads zenoh's metadata segment after wz has read each sample and
//! asserts every chunk was given back; legs 2 and 3 assert that the chunk comes
//! home to wz's provider after zenoh's subscriber lets go, a decrement made by
//! zenoh's own `Drop for ShmBufInner`.
//!
//! ## The wz node is the ordinary one
//!
//! Both sides of the wz process are a [`TokioSession`] made by its ordinary
//! constructor, opened by the library entry points a host calls, and driven by
//! `dispatch_iteration_event`. Nothing is installed by hand except a COUNTING
//! resolver in leg 1, whose job is to show that a sample went through shared
//! memory rather than merely arrived. The session params are the zenoh interop
//! profile, not the wz-to-wz fixture: a strict zenoh refuses the fixture's
//! version and batch size at InitSyn.
//!
//! Requires `ZENOHD_SHM=1 scripts/build-zenohd.sh`. SKIPs where the oracle is
//! absent, like the establishment test: hosted CI does not provision a source
//! build for it.

use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex as StdMutex};
use std::time::Duration;

use tokio::net::TcpListener;
use wz_integration_tests::common::{
    read_captured, wait_for_substring, zenoh_shm_example_binary, ChildGuard, PortReservation,
};
use wz_runtime_tokio::observer::ApplicationLayerObserver;
use wz_runtime_tokio::runtime_impl::TokioTime;
use wz_runtime_tokio::session::{PublishOptions, SubscribeOptions, TokioSession};
use wz_runtime_tokio::session_glue::{drive_session_until_terminal, WhatAmI};
use wz_runtime_tokio::session_open::{
    accept_and_open_session, accept_and_open_session_with_shm, connect_and_open_session_with_shm,
    DialConfig, DialedLink, DEFAULT_OPEN_TICK_MS,
};
use wz_runtime_tokio::shm_provider::{
    is_invalidated, reference_state, ChunkHold, PosixShmResolver, ReferenceState, ShmBackedPayload,
};
use wz_runtime_tokio::sync::Mutex;
use wz_runtime_tokio_test_support::zenoh_interop_session_init_params;
use wz_session_core::extshm::{ShmDescriptor, ShmResolver};
use wz_session_core::locator::parse_any_locator;
use wz_session_core::session_timeouts::SessionTimeouts;

const ITER_CAP: usize = 4096;

/// What `z_pub_shm` appends to its `[idx] ` prefix by default.
const ZENOH_PAYLOAD: &str = "Pub from Rust SHM!";

/// What `z_sub_shm` prints for a sample that arrived through shared memory, as
/// opposed to `[RAW]`: the front of either of its two SHM labels.
///
/// The example labels a shared-memory buffer `SHM (MUT)` when it can convert it
/// to a mutable one and `SHM (IMMUT)` when it cannot, and that is a question
/// about the REFERENCE COUNT, not about shared memory
/// (`examples/examples/z_sub_shm.rs` @ `Ok(_shm_mut) => "SHM (MUT)",`). A buffer
/// a zenoh publisher is still holding is shared and reads `IMMUT`; a buffer
/// whose only holder is the receiver reads `MUT`, and wz's payload is the second
/// kind. Asking for `IMMUT` here was a guess made before any wz payload could
/// be observed, and it measured the publisher's bookkeeping. The discriminator
/// is `SHM` against `RAW`.
const ZENOH_SAW_SHM: &str = "[SHM (";

/// A resolver that counts what the registry asked it to resolve, so a leg can
/// tell a payload that crossed as SHM from one that merely arrived.
struct CountingResolver {
    inner: PosixShmResolver,
    resolved: Arc<AtomicUsize>,
    refused: Arc<AtomicUsize>,
    /// Every descriptor the registry asked about, so a leg can read the OTHER
    /// side's bookkeeping for each chunk afterwards.
    seen: Arc<StdMutex<Vec<ShmDescriptor>>>,
}

impl ShmResolver for CountingResolver {
    fn resolve(&self, descriptor: &ShmDescriptor) -> Option<Vec<u8>> {
        self.seen.lock().expect("seen").push(*descriptor);
        let bytes = self.inner.resolve(descriptor);
        let counter = if bytes.is_some() {
            &self.resolved
        } else {
            &self.refused
        };
        counter.fetch_add(1, Ordering::SeqCst);
        bytes
    }
}

/// How the resolver of a zenoh-to-wz run treats the descriptors it is shown.
#[derive(Clone, Copy, PartialEq, Eq)]
enum RunMode {
    /// Resolve every descriptor: link it, read it and let go.
    Resolving,
    /// HOLD the first chunk (link it and keep the hold) and link-and-release every
    /// other one at once, so that zenoh's OWN watchdog validator can be watched
    /// deciding between a chunk wz still holds and chunks wz has let go of.
    WatchdogProbe,
}

/// The resolver of [`RunMode::WatchdogProbe`]: the first descriptor is linked and
/// the hold kept; every other one is linked and let go at once, which confirms it
/// a single time and gives its reference back, and is refused.
struct HoldingResolver {
    held: Arc<StdMutex<Option<ChunkHold>>>,
    seen: Arc<StdMutex<Vec<ShmDescriptor>>>,
}

impl ShmResolver for HoldingResolver {
    fn resolve(&self, descriptor: &ShmDescriptor) -> Option<Vec<u8>> {
        let mut seen = self.seen.lock().expect("seen");
        seen.push(*descriptor);
        let first = seen.len() == 1;
        drop(seen);
        let hold = ChunkHold::link(descriptor)?;
        if !first {
            // Dropped here: confirmed once, released, and nothing confirms it again.
            return None;
        }
        let bytes = hold.read();
        *self.held.lock().expect("held") = Some(hold);
        bytes
    }
}

/// What zenoh's own validator did with the chunks of a [`RunMode::WatchdogProbe`]
/// run, read off the headers in zenoh's metadata segment.
struct WatchdogOutcome {
    /// Whether the chunk wz held stayed un-invalidated for the whole hold.
    held_stayed_valid: bool,
    /// How many chunks wz linked and let go of at once.
    released: usize,
    /// Of those, the ones zenoh's validator had NOT invalidated by the end of the
    /// wait, each with what its header says: whether it is invalidated and what its
    /// reference count is. A chunk nobody holds and nobody confirms is invalidated
    /// within a window or two.
    released_still_valid: Vec<(ShmDescriptor, Option<bool>, Option<ReferenceState>)>,
}

/// THE WATCHDOG, read off ZENOH'S validator. wz linked the first chunk and holds
/// it; every other one it linked and let go of at once. zenoh's validator clears
/// each chunk's bit every 100 ms and invalidates one that nobody confirmed in the
/// window, so if wz confirms the bit zenoh's validator reads, the held chunk stays
/// valid for as long as it is held (six windows here) and the released ones, which
/// nobody confirms any more, do not. A wz that confirmed a DIFFERENT bit would see
/// its held chunk invalidated.
///
/// It runs inside the scenario, so wz keeps driving its session, and so keeps
/// acknowledging what zenoh sends, while zenoh's validator is watched.
///
/// `None` when fewer than two descriptors were seen, so there is no control.
async fn probe_watchdog(seen: &StdMutex<Vec<ShmDescriptor>>) -> Option<WatchdogOutcome> {
    let descriptors = seen.lock().expect("seen").clone();
    if descriptors.len() < 2 {
        return None;
    }
    let held_descriptor = descriptors[0];
    let mut held_stayed_valid = true;
    for _ in 0..12 {
        if is_invalidated(&held_descriptor) != Some(false) {
            held_stayed_valid = false;
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    let released = descriptors[1..].to_vec();
    let mut still_valid = released.clone();
    for _ in 0..60 {
        still_valid.retain(|d| is_invalidated(d) != Some(true));
        if still_valid.is_empty() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    Some(WatchdogOutcome {
        held_stayed_valid,
        released: released.len(),
        released_still_valid: still_valid
            .iter()
            .map(|d| (*d, is_invalidated(d), reference_state(d)))
            .collect(),
    })
}

/// Start an upstream SHM example with the flags every leg shares, its output
/// going to one capture file. `RUST_LOG` is raised so a failing leg can show what
/// zenoh itself said about the buffer it refused.
fn spawn_zenoh(
    binary: &std::path::Path,
    name: &str,
    args: &[String],
) -> (ChildGuard, std::fs::File) {
    let log = tempfile::tempfile().expect("capture");
    let child = Command::new(binary)
        .args(args)
        .args(["--no-multicast-scouting", "--enable-shm"])
        .env(
            "RUST_LOG",
            "zenoh=info,zenoh_shm=debug,zenoh_transport=debug",
        )
        .stdout(Stdio::from(log.try_clone().expect("dup")))
        .stderr(Stdio::from(log.try_clone().expect("dup")))
        .spawn()
        .unwrap_or_else(|e| panic!("spawn {name}: {e}"));
    (ChildGuard::wrap(name.to_string(), child), log)
}

/// What one run of a zenoh publisher against a wz subscriber saw.
struct ZenohToWz {
    /// Whether the wz session negotiated SHM with the publisher.
    negotiated: bool,
    /// The payload of every sample the wz subscriber was handed.
    received: Vec<Vec<u8>>,
    /// Descriptors the resolver turned into bytes.
    resolved: usize,
    /// Descriptors the resolver refused.
    refused: usize,
    /// Of the chunks zenoh's provider handed over, how many were still holding
    /// the reference zenoh took for wz once the wz side had read them, after a
    /// wait for the publisher's own release to land. A wz that never gives a
    /// reference back leaves every one of them at one, in a header zenoh owns.
    unreleased: Vec<(ShmDescriptor, Option<ReferenceState>)>,
    /// Of the chunks zenoh's provider handed over, those its OWN watchdog
    /// validator had not invalidated once the wz side had read them and, by the
    /// handoff counters, acknowledged them. zenoh's sender keeps a hard reference
    /// to every buffer it sends, and that reference keeps the buffer's watchdog bit
    /// confirmed, until the receiver lowers the sender's handoff counter; a wz that
    /// never does leaves every chunk confirmed for as long as the publisher runs
    /// (MEASURED: counter at 3 after three puts and still 3 seconds later, every
    /// chunk confirmed and not invalidated), where a chunk its receiver
    /// acknowledged is invalidated within about 200 ms. Read off zenoh's own header.
    uninvalidated: Vec<(ShmDescriptor, Option<bool>)>,
    /// What zenoh's validator did, in [`RunMode::WatchdogProbe`] only.
    watchdog: Option<WatchdogOutcome>,
    /// Everything the publisher printed.
    zenoh_log: String,
}

/// Run `z_pub_shm` against a wz acceptor with a subscriber declared, until three
/// samples arrived or the budget ran out. `offer_shm` says whether the wz side
/// offers shared memory at establishment; when it does not, zenoh must send the
/// payload raw, which is this helper's own control.
async fn zenoh_publishes_to_wz(offer_shm: bool) -> Option<ZenohToWz> {
    zenoh_publishes_to_wz_in(offer_shm, RunMode::Resolving).await
}

/// [`zenoh_publishes_to_wz`] with the resolver's behaviour chosen: see [`RunMode`].
async fn zenoh_publishes_to_wz_in(offer_shm: bool, mode: RunMode) -> Option<ZenohToWz> {
    let Some(z_pub) = zenoh_shm_example_binary("z_pub_shm") else {
        eprintln!(
            "SKIP: no z_pub_shm at target/zenohd-shm (run `ZENOHD_SHM=1 scripts/build-zenohd.sh`)"
        );
        return None;
    };
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let port = listener.local_addr().expect("local addr").port();
    let (_guard, mut zenoh_log) = spawn_zenoh(
        &z_pub,
        "z_pub_shm",
        &[
            "-m".into(),
            "peer".into(),
            "-e".into(),
            format!("tcp/127.0.0.1:{port}"),
        ],
    );

    // A deadline, because a z_pub_shm that never dials (it died, or was built
    // without the feature) must fail this leg rather than park the job.
    let (stream, _) = tokio::time::timeout(Duration::from_secs(20), listener.accept())
        .await
        .unwrap_or_else(|_| {
            panic!(
                "z_pub_shm never dialled the wz acceptor:\n{}",
                read_captured(&mut zenoh_log)
            )
        })
        .expect("accept");
    let params = zenoh_interop_session_init_params(WhatAmI::Peer, vec![0x0d, 0x0a, 0x10, 0x02]);
    let opened = if offer_shm {
        accept_and_open_session_with_shm(
            DialedLink::Tcp(stream),
            params,
            TokioTime::new(),
            Some(ITER_CAP),
            DEFAULT_OPEN_TICK_MS,
        )
        .await
    } else {
        accept_and_open_session(
            DialedLink::Tcp(stream),
            params,
            TokioTime::new(),
            Some(ITER_CAP),
            DEFAULT_OPEN_TICK_MS,
        )
        .await
    };
    let mut opened = opened.unwrap_or_else(|e| {
        panic!(
            "the wz acceptor did not reach Established (offering SHM: {offer_shm}): {e:?}\n{}",
            read_captured(&mut zenoh_log)
        )
    });
    let negotiated = opened.actions.is_shm();

    let session = TokioSession::new(
        opened.actions.clone(),
        Arc::new(Mutex::new(ApplicationLayerObserver::new())),
        Arc::new(opened.clock),
    );
    let resolved = Arc::new(AtomicUsize::new(0));
    let refused = Arc::new(AtomicUsize::new(0));
    let seen: Arc<StdMutex<Vec<ShmDescriptor>>> = Arc::default();
    let held: Arc<StdMutex<Option<ChunkHold>>> = Arc::default();
    match mode {
        RunMode::Resolving => session.set_shm_resolver(Box::new(CountingResolver {
            inner: PosixShmResolver,
            resolved: resolved.clone(),
            refused: refused.clone(),
            seen: seen.clone(),
        })),
        RunMode::WatchdogProbe => session.set_shm_resolver(Box::new(HoldingResolver {
            held: held.clone(),
            seen: seen.clone(),
        })),
    }
    let received: Arc<StdMutex<Vec<Vec<u8>>>> = Arc::default();
    let sink = received.clone();
    // The routed declaration: a zenoh publisher sends nothing to a peer that has
    // not told it there is a subscriber.
    let _subscriber = session.declare_subscriber(
        "demo/example/**",
        SubscribeOptions::default(),
        move |sample| {
            sink.lock()
                .expect("received")
                .push(sample.payload().to_vec());
        },
    );

    let timeouts = SessionTimeouts::spec_defaults();
    let drive = drive_session_until_terminal(
        &mut opened.inbound,
        &opened.actions,
        &mut opened.engine,
        None,
        &opened.clock,
        &timeouts,
        |event| session.dispatch_iteration_event(event),
    );

    let probe = received.clone();
    let probe_seen = seen.clone();
    let scenario = async move {
        for _ in 0..400 {
            // Resolving: three samples DELIVERED. Probing: three descriptors SEEN,
            // since all but the first are refused and so deliver nothing.
            let enough = match mode {
                RunMode::Resolving => probe.lock().expect("received").len() >= 3,
                RunMode::WatchdogProbe => probe_seen.lock().expect("seen").len() >= 3,
            };
            if enough {
                return match mode {
                    RunMode::WatchdogProbe => probe_watchdog(&probe_seen).await,
                    RunMode::Resolving => None,
                };
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        None
    };
    let mut drive_log = zenoh_log.try_clone().expect("dup");
    let watchdog = tokio::select! {
        _ = drive => panic!(
            "the wz drive loop ended before the scenario did:\n{}",
            read_captured(&mut drive_log)
        ),
        outcome = scenario => outcome,
    };

    let received = received.lock().expect("received").clone();
    // Read the publisher's own headers while its process still lives. A chunk is
    // given back when its count reads zero or its slot has been reclaimed (the
    // publisher's provider collects when it allocates). The publisher's OWN
    // reference to a buffer it just sent goes when it drops that buffer, a moment
    // after the put returns, so the read waits for that rather than racing it.
    let descriptors = seen.lock().expect("seen").clone();
    let given_back = |state: &Option<ReferenceState>| {
        matches!(
            state,
            Some(ReferenceState::Held(0) | ReferenceState::Reclaimed)
        )
    };
    let mut unreleased: Vec<(ShmDescriptor, Option<ReferenceState>)> = Vec::new();
    let mut uninvalidated: Vec<(ShmDescriptor, Option<bool>)> = Vec::new();
    // Only the resolving mode releases and acknowledges what it is shown with the
    // hold dropped: the probe holds the first chunk on purpose, and reads zenoh's
    // validator inside the scenario instead.
    if mode == RunMode::Resolving {
        for _ in 0..60 {
            unreleased = descriptors
                .iter()
                .map(|d| (*d, reference_state(d)))
                .filter(|(_, state)| !given_back(state))
                .collect();
            // `None` is a slot the publisher's provider has since reclaimed, which
            // is further along than invalidated; only a header still reading
            // "valid" is a chunk zenoh is still holding confirmed.
            uninvalidated = descriptors
                .iter()
                .map(|d| (*d, is_invalidated(d)))
                .filter(|(_, state)| *state == Some(false))
                .collect();
            if unreleased.is_empty() && uninvalidated.is_empty() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    }
    // The hold ends here, which gives back the reference zenoh took for it.
    drop(held);
    Some(ZenohToWz {
        negotiated,
        received,
        resolved: resolved.load(Ordering::SeqCst),
        refused: refused.load(Ordering::SeqCst),
        unreleased,
        uninvalidated,
        watchdog,
        zenoh_log: read_captured(&mut zenoh_log),
    })
}

/// Control for leg 1 -- the same publisher and the same subscriber against a wz
/// acceptor that does not offer shared memory. zenoh sends the payload RAW, so
/// the samples must arrive without the resolver being asked anything. If this
/// arm fails, leg 1's failure is the harness and says nothing about SHM.
// wz-proves: none -- the raw control for leg 1: wz offers no shared memory, so a delivery proves the topology and not the layout
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "binary-dep e2e (ZENOHD_SHM=1 build-zenohd.sh: z_pub_shm); Layer Z runs via --ignored"]
async fn zenohd_publisher_reaches_a_wz_subscriber_raw_when_shm_is_not_offered() {
    let Some(run) = zenoh_publishes_to_wz(false).await else {
        return;
    };
    assert!(
        !run.negotiated,
        "a wz acceptor that offered nothing negotiated SHM"
    );
    assert!(
        run.received.len() >= 3,
        "{} sample(s) arrived from a zenoh publisher that had no SHM to use, so the topology or \
         the declarations are wrong and leg 1 cannot be read:\n{}",
        run.received.len(),
        run.zenoh_log
    );
    for payload in &run.received {
        let text = String::from_utf8_lossy(payload);
        assert!(
            text.ends_with(ZENOH_PAYLOAD),
            "a raw sample is not the bytes z_pub_shm wrote: {text:?}"
        );
    }
    assert_eq!(
        run.resolved + run.refused,
        0,
        "the resolver was asked about a payload that arrived raw"
    );
}

/// Leg 1 -- a zenoh SHM publisher dials a wz acceptor that offers shared memory;
/// every sample must reach the wz subscriber byte-exact AND by way of the
/// resolver.
// wz-proves: transport-shm zenoh->wz
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "binary-dep e2e (ZENOHD_SHM=1 build-zenohd.sh: z_pub_shm); Layer Z runs via --ignored"]
async fn zenohd_shm_publisher_payload_reaches_a_wz_subscriber_through_shared_memory() {
    let Some(run) = zenoh_publishes_to_wz(true).await else {
        return;
    };
    assert!(
        run.negotiated,
        "the session did not negotiate SHM, so zenoh sent the payload RAW and this leg measured \
         nothing about shared memory:\n{}",
        run.zenoh_log
    );
    assert!(
        run.received.len() >= 3,
        "{} sample(s) arrived from z_pub_shm, fewer than three ({} resolved, {} refused):\n{}",
        run.received.len(),
        run.resolved,
        run.refused,
        run.zenoh_log
    );
    for payload in &run.received {
        let text = String::from_utf8_lossy(payload);
        assert!(
            text.ends_with(ZENOH_PAYLOAD),
            "a sample is not the bytes z_pub_shm wrote: {text:?}"
        );
    }
    assert_eq!(
        run.refused, 0,
        "the resolver refused descriptors zenoh's provider wrote:\n{}",
        run.zenoh_log
    );
    assert!(
        run.resolved >= run.received.len(),
        "{} samples arrived but only {} went through the resolver, so some arrived RAW and did not \
         exercise shared memory",
        run.received.len(),
        run.resolved
    );
    // THE LIFECYCLE, read off the OTHER side's bookkeeping: zenoh's sender took
    // one reference per serialization for its receiver and its provider reclaims
    // a chunk only when the count reads zero, so a receiver that reads and never
    // lets go drains the publisher's pool one buffer per sample. The headers read
    // here are zenoh's, in a segment zenoh made; a wz that asked itself whether it
    // had released would be grading wz with wz.
    assert!(
        run.unreleased.is_empty(),
        "{} chunk(s) zenoh's provider handed over still hold the reference zenoh took for wz after \
         wz read them: {:?}\n{}",
        run.unreleased.len(),
        run.unreleased,
        run.zenoh_log
    );
    // THE HANDOFF, read off zenoh's own validator. zenoh's sender keeps a hard
    // reference to each buffer it sends, which keeps the buffer's watchdog bit
    // confirmed, until the receiver lowers the sender's handoff counter for it
    // (`io/zenoh-transport/src/unicast/establishment/ext/shm/handoff.rs` @
    // `pub fn on_rx(&self, priority: Priority) {`). A wz that reads every chunk and
    // releases its reference but never lowers the counter passes the check above and
    // leaves every chunk confirmed, and never invalidated, for as long as the
    // publisher runs: MEASURED before the handoff was built, the counter read 3
    // after three puts and still 3 seconds later. A chunk wz acknowledged is
    // invalidated by zenoh's validator within about 200 ms, as it is between two
    // zenoh programs.
    assert!(
        run.uninvalidated.is_empty(),
        "{} chunk(s) zenoh's provider handed over were still confirmed and not invalidated after wz \
         read and released them, so zenoh is still holding them for an acknowledgement wz never \
         gave: {:?}\n{}",
        run.uninvalidated.len(),
        run.uninvalidated,
        run.zenoh_log
    );
}

/// Leg 5 -- THE WATCHDOG, against zenoh's own validator. A zenoh SHM publisher
/// lets go of each buffer it sends once its receiver has acknowledged it, so from
/// then on only a RECEIVER's confirmation keeps a chunk valid, and zenoh's provider
/// invalidates a chunk nobody confirmed for a whole 100 ms window
/// (`commons/zenoh-shm/src/watchdog/validator.rs` @
/// `WatchdogValidator::new(Duration::from_millis(100));`).
///
/// wz links the FIRST chunk it is sent and holds it for six windows, and links
/// every other one and lets go of it at once. Both facts are read off zenoh's own
/// header, in a segment zenoh made: the held chunk must stay valid for the whole
/// hold, which is only true if the bit wz confirms is the bit zenoh's validator
/// clears, and every chunk wz released must be invalidated, which is the CONTROL:
/// it shows zenoh's validator is running and invalidates a chunk nobody confirms,
/// so the held chunk's survival is the confirmation and not a validator that
/// never acted.
///
/// THIS LEG WAS BUILT TWICE. The first time it could not be kept: its control
/// failed in three designs, because zenoh's publisher held every chunk it sent wz
/// confirmed for as long as it ran, whatever wz did with the chunk, and an
/// invalidation that never happens makes a held chunk's survival vacuous. The
/// cause was the handoff counters wz never lowered, found by freezing upstream's
/// own subscriber so that it could not acknowledge (the counter climbed to five
/// and every chunk stayed confirmed for five seconds, then all six were
/// invalidated within 400 ms of it being thawed). With the acknowledgement built
/// the control works, and this is the leg.
// wz-proves: transport-shm zenoh->wz
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "binary-dep e2e (ZENOHD_SHM=1 build-zenohd.sh: z_pub_shm); Layer Z runs via --ignored"]
async fn zenohd_shm_publisher_chunk_wz_holds_stays_valid_while_one_wz_released_is_invalidated() {
    let Some(run) = zenoh_publishes_to_wz_in(true, RunMode::WatchdogProbe).await else {
        return;
    };
    assert!(
        run.negotiated,
        "the session did not negotiate SHM, so zenoh sent the payload RAW and this leg measured \
         nothing about the watchdog:\n{}",
        run.zenoh_log
    );
    let outcome = run
        .watchdog
        .as_ref()
        .unwrap_or_else(|| panic!("fewer than two descriptors arrived:\n{}", run.zenoh_log));
    assert!(
        outcome.released >= 1,
        "no chunk was released, so there is no control:\n{}",
        run.zenoh_log
    );
    assert!(
        outcome.released_still_valid.is_empty(),
        "zenoh's validator did not invalidate {} of {} chunk(s) wz released and acknowledged ({:?}), \
         so it is not acting and the held chunk's survival proves nothing:\n{}",
        outcome.released_still_valid.len(),
        outcome.released,
        outcome.released_still_valid,
        run.zenoh_log
    );
    assert!(
        outcome.held_stayed_valid,
        "zenoh's validator invalidated the chunk wz was HOLDING, so the bit wz confirms is not the \
         bit zenoh's validator reads:\n{}",
        run.zenoh_log
    );
}

/// What a wz publisher does with its payload after `publish_shm` returns.
#[derive(Clone, Copy, Debug)]
enum Owner {
    /// Keeps it alive for the whole leg, the lifecycle the API documents today.
    HoldsIt,
    /// Lets go the moment `publish_shm` returns, as a real publisher does.
    LetsGoAtOnce,
}

/// What one run of a wz publisher against `z_sub_shm` showed.
struct WzToZenoh {
    /// Everything the zenoh subscriber printed.
    printed: String,
    /// Whether the chunk came home to wz's provider: the owner let go, zenoh's
    /// receiver let go of the reference wz's descriptor carried, the count read
    /// zero and the next allocation collected it. Read off wz's own header, but the
    /// DECREMENT it depends on was made by zenoh's `Drop for ShmBufInner` in a
    /// process wz does not control, which is what makes it a foreign witness of the
    /// reference count rather than wz reading its own writes.
    chunk_came_home: bool,
}

/// Dial `z_sub_shm` with SHM offered, publish one payload through `publish_shm`
/// and return what the zenoh subscriber printed and whether the chunk came home.
async fn wz_publishes_to_zenoh_subscriber(owner: Owner, key: &str, text: &str) -> WzToZenoh {
    let z_sub = zenoh_shm_example_binary("z_sub_shm").expect("checked by the caller");
    let port = PortReservation::pick();
    let (_guard, mut zenoh_log) = spawn_zenoh(
        &z_sub,
        "z_sub_shm",
        &[
            "-m".into(),
            "peer".into(),
            "-l".into(),
            format!("tcp/127.0.0.1:{}", port.port()),
            "-k".into(),
            "demo/example/**".into(),
        ],
    );
    wait_for_substring(
        &mut zenoh_log,
        "Press CTRL-C to quit",
        Duration::from_secs(20),
    )
    .unwrap_or_else(|e| panic!("z_sub_shm never became ready: {e}"));
    let listen_port = port.port();
    drop(port);

    let locator = parse_any_locator(&format!("tcp/127.0.0.1:{listen_port}")).expect("locator");
    let mut opened = connect_and_open_session_with_shm(
        locator,
        zenoh_interop_session_init_params(WhatAmI::Peer, vec![0x0b, 0x0a, 0x10, 0x01]),
        &DialConfig::default(),
        TokioTime::new(),
        Some(ITER_CAP),
        DEFAULT_OPEN_TICK_MS,
    )
    .await
    .unwrap_or_else(|e| {
        panic!(
            "the wz dialer did not reach Established with SHM offered: {e:?}\n{}",
            read_captured(&mut zenoh_log)
        )
    });
    assert!(
        opened.actions.is_shm(),
        "the session did not negotiate SHM, so publish_shm would send the bytes inline and \
         this leg would measure nothing about shared memory:\n{}",
        read_captured(&mut zenoh_log)
    );

    let session = TokioSession::new(
        opened.actions.clone(),
        Arc::new(Mutex::new(ApplicationLayerObserver::new())),
        Arc::new(opened.clock),
    );
    let timeouts = SessionTimeouts::spec_defaults();
    let drive = drive_session_until_terminal(
        &mut opened.inbound,
        &opened.actions,
        &mut opened.engine,
        None,
        &opened.clock,
        &timeouts,
        |event| session.dispatch_iteration_event(event),
    );

    let key = key.to_string();
    let bytes = text.as_bytes().to_vec();
    let probe_log = zenoh_log.try_clone().expect("dup");
    let mut drive_log = zenoh_log.try_clone().expect("dup");
    let scenario = async {
        // Let the session settle, then publish through shared memory.
        tokio::time::sleep(Duration::from_millis(500)).await;
        let mut payload = ShmBackedPayload::alloc(bytes.len()).expect("alloc a payload");
        payload.write(&bytes);
        let descriptor = payload.descriptor();
        session
            .publish_shm(&key, &payload, PublishOptions::put())
            .expect("publish_shm");
        // The arm that lets go drops it HERE, before the subscriber has had any
        // time to read; a binding left in scope would keep it until the block ends.
        let held = match owner {
            Owner::HoldsIt => Some(payload),
            Owner::LetsGoAtOnce => {
                drop(payload);
                None
            }
        };
        let mut probe_log = probe_log;
        for _ in 0..200 {
            if read_captured(&mut probe_log).contains("Received") {
                break;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        drop(held);
        // zenoh's subscriber drops the sample after printing it, which gives back
        // the reference this descriptor carried. Every holder gone, the chunk is
        // collected by the next allocation, so allocate (and let go) until it is
        // or the wait ends.
        let mut came_home = false;
        for _ in 0..60 {
            let _collect = ShmBackedPayload::alloc(1);
            if reference_state(&descriptor) == Some(ReferenceState::Reclaimed) {
                came_home = true;
                break;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        came_home
    };
    let chunk_came_home = tokio::select! {
        outcome = drive => panic!(
            "the wz drive loop ended before the scenario did ({outcome:?}):\n{}",
            read_captured(&mut drive_log)
        ),
        came_home = scenario => came_home,
    };
    WzToZenoh {
        printed: read_captured(&mut zenoh_log),
        chunk_came_home,
    }
}

/// Leg 2 -- wz publishes a payload it keeps alive; zenoh's reader must map it and
/// `z_sub_shm` must say it arrived through shared memory.
// wz-proves: transport-shm wz->zenoh
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "binary-dep e2e (ZENOHD_SHM=1 build-zenohd.sh: z_sub_shm); Layer Z runs via --ignored"]
async fn wz_shm_payload_held_by_its_owner_reaches_a_zenohd_shm_subscriber() {
    if zenoh_shm_example_binary("z_sub_shm").is_none() {
        eprintln!(
            "SKIP: no z_sub_shm at target/zenohd-shm (run `ZENOHD_SHM=1 scripts/build-zenohd.sh`)"
        );
        return;
    }
    let text = "held-payload-from-wz";
    let run = wz_publishes_to_zenoh_subscriber(Owner::HoldsIt, "demo/example/wz-held", text).await;
    assert!(
        run.printed.contains(&format!(
            "('demo/example/wz-held': '{text}') {ZENOH_SAW_SHM}"
        )),
        "z_sub_shm did not report wz's payload as a shared-memory buffer:\n{}",
        run.printed
    );
    assert!(
        run.chunk_came_home,
        "the chunk never came home to wz's provider after the owner and zenoh's subscriber had both \
         let go, so zenoh's release of the reference wz's descriptor carried was not observed:\n{}",
        run.printed
    );
}

/// Leg 3 -- the same, for a publisher that lets go at once, which is what a real
/// publisher does: the payload is dropped the moment `publish_shm` returns, and
/// zenoh's reader gets to it afterwards.
///
/// THE LIFECYCLE ARM, AND IT WAS A PIN UNTIL R3038. Until then wz's provider
/// unlinked the data segment the moment its owner dropped, so the reader found
/// nothing and `z_sub_shm` logged `Error receiving SHM buffer: Unable to open
/// POSIX shm segment: OS error 2` (open-debt item 823 (6)). This test asserted
/// that signature, so it passed while the defect stood and went red the day the
/// provider held by count. It holds by count now: serializing the descriptor
/// takes a reference for the receiver, as upstream's does
/// (`commons/zenoh-codec/src/core/zbuf.rs` @ `unsafe { shmb.inc_ref_count() };`),
/// the owner's drop gives back only its own, and the chunk is collected when the
/// count reads zero. This is the positive twin of leg 2 the pin said it would
/// become, with the same claim.
///
/// It also asserts the end of the protocol, off wz's own header: after zenoh's
/// subscriber has printed the sample and let go of the buffer, the reference its
/// descriptor carried is back and the chunk is collected. That decrement is made
/// by zenoh's `Drop for ShmBufInner` in a process wz does not control.
// wz-proves: transport-shm wz->zenoh
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "binary-dep e2e (ZENOHD_SHM=1 build-zenohd.sh: z_sub_shm); Layer Z runs via --ignored"]
async fn wz_shm_payload_its_owner_let_go_of_at_once_is_still_readable_by_a_zenohd_shm_subscriber() {
    if zenoh_shm_example_binary("z_sub_shm").is_none() {
        eprintln!(
            "SKIP: no z_sub_shm at target/zenohd-shm (run `ZENOHD_SHM=1 scripts/build-zenohd.sh`)"
        );
        return;
    }
    let text = "released-payload-from-wz";
    let run =
        wz_publishes_to_zenoh_subscriber(Owner::LetsGoAtOnce, "demo/example/wz-released", text)
            .await;
    assert!(
        !run.printed.contains("Error receiving SHM buffer"),
        "zenoh's reader refused a buffer its wz owner had let go of, which is the lifecycle defect \
         (the provider unlinked its segment when the owner dropped):\n{}",
        run.printed
    );
    assert!(
        run.printed.contains(&format!(
            "('demo/example/wz-released': '{text}') {ZENOH_SAW_SHM}"
        )),
        "z_sub_shm did not report a payload its wz owner let go of at once as a shared-memory \
         buffer:\n{}",
        run.printed
    );
    assert!(
        run.chunk_came_home,
        "the chunk never came home to wz's provider after zenoh's subscriber had let go, so zenoh's \
         release of the reference wz's descriptor carried was not observed:\n{}",
        run.printed
    );
}
