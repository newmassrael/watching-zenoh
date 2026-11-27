// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The action bundle built over a runtime of this crate's own, so the parts of it a non-default
//! feature compiles in are read here and not only through a runtime crate's tests: the action
//! counters (`action-trace`), the egress admission of the replies a session sends
//! (`reply-egress-gate`), and what a peer's handshake records with the accepting role
//! (`session-unicast-accept`) and without it.
//!
//! The runtime holds its state behind std locks and spawns nothing; the link counts what the
//! session hands it and writes nowhere; the clock never moves. Nothing here opens a session, so
//! what a test reads is what one call into the bundle did.

use alloc::boxed::Box;
use alloc::sync::Arc;
use alloc::vec;
use core::future::Future;
use core::pin::Pin;
use core::sync::atomic::{AtomicUsize, Ordering};
use core::task::{Context, Poll};

use wz_codecs::whatami::WhatAmI;
use wz_runtime_core::{Runtime, RuntimeError, TimeSource, TimeoutElapsed};

use super::SessionLinkActions;
use crate::link::{BoxedLinkDriver, HeapRefused, LinkSendOutcome, SessionRuntime, ShareValues};
use crate::reliability::Reliability;
use crate::session_init_params::{
    cookie_bytes, KeepAliveConf, LinkRxConf, SessionInitParams, TxQueueConf,
};

/// A runtime whose locks are std's and that runs no task: the bundle's tests call it from the
/// test's own thread and spawn nothing.
struct PlainRuntime;

impl Runtime for PlainRuntime {
    type JoinHandle<T>
        = core::future::Pending<Result<T, RuntimeError>>
    where
        T: Send + 'static;
    type Mutex<T>
        = std::sync::Mutex<T>
    where
        T: Send + 'static;
    type RwLock<T>
        = std::sync::RwLock<T>
    where
        T: Send + Sync + 'static;

    fn spawn<F>(&self, _fut: F) -> Self::JoinHandle<F::Output>
    where
        F: Future + Send + 'static,
        F::Output: Send + 'static,
    {
        unreachable!("the action bundle's tests spawn no task")
    }

    fn with_mutex_mut<T, U>(mutex: &Self::Mutex<T>, f: impl FnOnce(&mut T) -> U) -> U
    where
        T: Send + 'static,
    {
        HOLDS.with(|holds| holds.set(holds.get().wrapping_add(1)));
        // A test that panicked under the lock leaves its value as the panic left it, as the
        // runtimes' own locks do.
        f(&mut *mutex
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner))
    }

    fn new_mutex<T>(value: T) -> Self::Mutex<T>
    where
        T: Send + 'static,
    {
        std::sync::Mutex::new(value)
    }

    fn new_rwlock<T>(value: T) -> Self::RwLock<T>
    where
        T: Send + Sync + 'static,
    {
        std::sync::RwLock::new(value)
    }
}

std::thread_local! {
    /// The holds of a lock this thread has taken through the test runtime. A test runs on a
    /// thread of its own, so it reads only its own.
    static HOLDS: core::cell::Cell<usize> = const { core::cell::Cell::new(0) };
}

/// How many holds of the bundle's locks `f` takes, whichever lock each one is.
fn holds_in(f: impl FnOnce()) -> usize {
    let before = HOLDS.with(core::cell::Cell::get);
    f();
    HOLDS.with(core::cell::Cell::get).wrapping_sub(before)
}

/// The test runtime's entropy: none, so a handshake these tests drive mints no cookie (the
/// fail-closed draw).
pub(super) struct NoEntropy;

impl crate::entropy::EntropySource for NoEntropy {
    fn try_fill_bytes(
        &mut self,
        _buf: &mut [u8],
    ) -> Result<(), crate::entropy::EntropyUnavailable> {
        Err(crate::entropy::EntropyUnavailable)
    }
}

std::thread_local! {
    /// How many of this thread's next pointers the runtime makes before it refuses the rest, as a
    /// heap with that much room would; `None` makes every one.
    static ROOM: core::cell::Cell<Option<usize>> = const { core::cell::Cell::new(None) };
}

/// One pointer made, or the heap's refusal when `ROOM` has run out.
fn take_room() -> Result<(), HeapRefused> {
    ROOM.with(|room| match room.get() {
        None => Ok(()),
        Some(0) => Err(HeapRefused),
        Some(left) => {
            room.set(Some(left - 1));
            Ok(())
        }
    })
}

/// `f`'s answer with room for `pointers` pointers.
fn with_room<A>(pointers: usize, f: impl FnOnce() -> A) -> A {
    ROOM.with(|room| room.set(Some(pointers)));
    let answer = f();
    ROOM.with(|room| room.set(None));
    answer
}

impl ShareValues for PlainRuntime {
    fn share<U>(value: U) -> Result<Self::Shared<U>, HeapRefused> {
        take_room()?;
        Ok(Arc::new(value))
    }
}

impl SessionRuntime for PlainRuntime {
    type LinkSink = Arc<dyn BoxedLinkDriver + Send + Sync>;
    type Driver = dyn BoxedLinkDriver;
    type Shared<U> = Arc<U>;
    type IterationWork = ();
    type EntropyDraw = NoEntropy;
    type Flag = core::sync::atomic::AtomicBool;
    type Word = core::sync::atomic::AtomicU64;
    type Local<T>
        = std::sync::Mutex<T>
    where
        T: Send + 'static;

    fn new_local<T>(value: T) -> Self::Local<T>
    where
        T: Send + 'static,
    {
        Self::new_mutex(value)
    }

    // Counted as a hold of a lock, as the threaded runtimes' local is one.
    fn with_local<T, U>(
        local: &Self::Local<T>,
        f: impl FnOnce(&mut T) -> U,
    ) -> Result<U, crate::link::LocalHeld>
    where
        T: Send + 'static,
    {
        Ok(Self::with_mutex_mut(local, f))
    }

    type ActionsHandle<T: TimeSource> = Arc<SessionLinkActions<Self, T>>;

    fn wrap_actions<T: TimeSource>(
        actions: SessionLinkActions<Self, T>,
    ) -> Result<Self::ActionsHandle<T>, HeapRefused> {
        take_room()?;
        Ok(Arc::new(actions))
    }

    fn link_driver(sink: &Self::LinkSink) -> &Self::Driver {
        &**sink
    }
}

/// A clock that stays at zero, so no deadline the bundle reads ever passes.
struct StillClock;

/// [`TimeSource::timeout`] on a clock that never moves: the budget never runs out, so the
/// outcome is the future's own.
struct NeverExpires<F: Future>(Pin<Box<F>>);

impl<F: Future> Future for NeverExpires<F> {
    type Output = Result<F::Output, TimeoutElapsed>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        self.0.as_mut().poll(cx).map(Ok)
    }
}

impl TimeSource for StillClock {
    fn now_monotonic_ms(&self) -> u64 {
        0
    }

    fn sleep(&self, _ms: u64) -> impl Future<Output = ()> + Send + '_ {
        core::future::ready(())
    }

    fn timeout<F>(
        &self,
        _ms: u64,
        fut: F,
    ) -> impl Future<Output = Result<F::Output, TimeoutElapsed>> + Send + '_
    where
        F: Future + Send + 'static,
        F::Output: Send,
    {
        NeverExpires(Box::pin(fut))
    }
}

/// A link that takes every write and counts what the session asked of it.
#[derive(Default)]
struct CountingLink {
    /// How many times the session opened the link.
    opened: AtomicUsize,
    /// How many writes the session handed the link.
    written: AtomicUsize,
}

impl BoxedLinkDriver for CountingLink {
    fn send_blocking(&self, _bytes: &[u8], _reliability: Reliability) -> LinkSendOutcome {
        self.written.fetch_add(1, Ordering::SeqCst);
        LinkSendOutcome::Sent
    }

    fn open_blocking(&self) {
        self.opened.fetch_add(1, Ordering::SeqCst);
    }

    fn close_blocking(&self) {}
}

fn params() -> SessionInitParams {
    SessionInitParams {
        whatami: WhatAmI::Peer,
        zid: crate::session_zid::SessionZid::from_array([0x51; 4]),
        seq_num_res: crate::policy::SnResolution::Bits32,
        req_id_res: 2,
        batch_size: 1024,
        lease_ms: 10_000,
        keep_alive: KeepAliveConf::default(),
        initial_sn: 0,
        cookie: cookie_bytes([]),
        tx_queue: TxQueueConf::of_snapshot(
            &crate::policy::SessionPolicy::defaults(),
            &crate::limits::SessionLimits::BUILD,
        ),
        link_rx: LinkRxConf::default(),
        cookie_signing_key: crate::signing_key::SigningKey::new(vec![0xAB; 32])
            .expect("32-byte test key")
            .into(),
        policy: crate::policy::SessionPolicy::defaults(),
        limits: crate::limits::SessionLimits::BUILD,
        region: None,
    }
}

/// A new session's action bundle over a [`CountingLink`], and the link, for the test to read.
fn bundle() -> (
    Arc<SessionLinkActions<PlainRuntime, StillClock>>,
    Arc<CountingLink>,
) {
    let link = Arc::new(CountingLink::default());
    let sink: Arc<dyn BoxedLinkDriver + Send + Sync> = link.clone();
    let actions =
        SessionLinkActions::<PlainRuntime, StillClock>::new_generic(sink, params(), StillClock)
            .expect("the heap has room");
    (actions, link)
}

/// A bundle the heap has no room for is refused, whichever of its three pointers (the link's
/// half, the kernel's half, the handle) is the one refused, and what it was handed is let go of.
/// Turned red by `new_generic` answering a bundle past a refused half, or by `build` keeping
/// the sink past the refusal.
#[test]
fn a_bundle_the_heap_has_no_room_for_is_refused() {
    let link = Arc::new(CountingLink::default());
    for room in 0..3 {
        let sink: Arc<dyn BoxedLinkDriver + Send + Sync> = link.clone();
        let made = with_room(room, || {
            SessionLinkActions::<PlainRuntime, StillClock>::new_generic(sink, params(), StillClock)
        });
        assert!(
            matches!(made, Err(HeapRefused)),
            "room for {room} pointers of three is a refused bundle"
        );
        assert_eq!(
            Arc::strong_count(&link),
            1,
            "the refused bundle lets the sink go"
        );
    }
    let sink: Arc<dyn BoxedLinkDriver + Send + Sync> = link.clone();
    let made = with_room(3, || {
        SessionLinkActions::<PlainRuntime, StillClock>::new_generic(sink, params(), StillClock)
    });
    assert!(made.is_ok(), "room for all three pointers is the bundle");
}

/// A datagram the link let go of before the session read it is charged to the session's receive
/// drops, once for each, and to nothing it sends. Turned red by `drive::note_rx_dropped`
/// charging no counter, or the transmit side's.
#[cfg(feature = "transport-stats")]
#[test]
fn a_datagram_dropped_before_the_session_read_it_is_a_receive_drop() {
    let (actions, _link) = bundle();
    crate::drive::note_rx_dropped(&actions, 2);
    crate::drive::note_rx_dropped(&actions, 1);
    let report = actions.stats_report();
    assert_eq!(report.rx.n_dropped, 3, "each dropped datagram is counted");
    assert_eq!(report.tx.n_dropped, 0, "nothing sent was dropped");
}

/// [`bundle`] with its link established ([`SessionLinkActions::enter_established`]): the
/// bundle a data or reply send is made on, since the data-send gate opens only there. A test of
/// what a send does is made on this one; a test of the gate itself starts from [`bundle`].
/// Compiled with the sends its tests make: a plain put, a gated reply, a staged reply, a counted
/// get.
#[cfg(any(
    all(feature = "codec-push", not(feature = "tx-lend-only")),
    all(feature = "reply-egress-gate", feature = "codec-response"),
    all(feature = "codec-response", not(feature = "tx-lend-only")),
    all(
        feature = "transport-stats",
        feature = "codec-request",
        feature = "storage-profile",
        not(feature = "tx-lend-only")
    )
))]
fn established_bundle() -> (
    Arc<SessionLinkActions<PlainRuntime, StillClock>>,
    Arc<CountingLink>,
) {
    let (actions, link) = bundle();
    actions.enter_established();
    (actions, link)
}

/// What `send` adds to the transmit counters of a new established session
/// ([`established_bundle`]): its network messages, and the messages and the payload bytes it
/// counts as `message` in `space`. The CONTROL is the link handed a write.
#[cfg(all(
    feature = "transport-stats",
    not(feature = "tx-lend-only"),
    any(
        all(feature = "codec-request", feature = "storage-profile"),
        feature = "codec-response"
    )
))]
fn counted_as(
    message: crate::stats::StatMessage,
    space: crate::stats::StatSpace,
    send: impl FnOnce(&SessionLinkActions<PlainRuntime, StillClock>),
) -> (usize, usize, usize) {
    use crate::stats::{DirectionReport, StatMedium};
    let (actions, link) = established_bundle();
    let before = actions.stats_report().tx;
    send(&actions);
    assert_ne!(
        link.written.load(Ordering::SeqCst),
        0,
        "CONTROL: the send reached the link"
    );
    let after = actions.stats_report().tx;
    let payload = |report: &DirectionReport| report.payload_of(message, space);
    (
        after.n_msgs_on(StatMedium::Net) - before.n_msgs_on(StatMedium::Net),
        payload(&after).msgs - payload(&before).msgs,
        payload(&after).pl_bytes - payload(&before).pl_bytes,
    )
}

/// The halves a holder writes where it keeps them are the halves the bundle is made of: the link's
/// half holds the sink handed and the kernel the parameters. A holder that refuses has its refusal
/// answered and lets go of what it was handed, the sink's handle with it. Turned red by a bundle
/// that holds halves other than the ones written, or by parts kept past a refusal.
#[test]
fn the_halves_a_holder_writes_make_the_bundle() {
    use core::mem::MaybeUninit;

    use super::{LinkState, SessionCore};

    let link = Arc::new(CountingLink::default());
    let sink: Arc<dyn BoxedLinkDriver + Send + Sync> = link.clone();
    let built = SessionLinkActions::<PlainRuntime, StillClock>::build_held(
        sink,
        params(),
        StillClock,
        |halves| {
            let mut link_half = MaybeUninit::<LinkState<PlainRuntime>>::uninit();
            let mut kernel = MaybeUninit::<SessionCore<PlainRuntime, StillClock>>::uninit();
            // SAFETY: two uninitialised places of the halves' types, apart; `write` leaves each
            // whole.
            let (link_half, kernel) = unsafe {
                halves.write(link_half.as_mut_ptr(), kernel.as_mut_ptr());
                (link_half.assume_init(), kernel.assume_init())
            };
            Ok::<_, &str>((Arc::new(link_half), Arc::new(kernel)))
        },
    );
    let Ok(actions) = built else {
        panic!("a holder that keeps the halves is answered with the bundle");
    };
    assert_eq!(
        Arc::strong_count(&link),
        2,
        "the link's half holds the sink"
    );
    assert_eq!(
        (actions.core.params.batch_size, actions.core.params.lease_ms),
        (1024, 10_000),
        "the kernel holds the parameters"
    );
    drop(actions);
    assert_eq!(Arc::strong_count(&link), 1);

    let sink: Arc<dyn BoxedLinkDriver + Send + Sync> = link.clone();
    let refused = SessionLinkActions::<PlainRuntime, StillClock>::build_held(
        sink,
        params(),
        StillClock,
        |halves| {
            drop(halves);
            Err::<
                (
                    Arc<LinkState<PlainRuntime>>,
                    Arc<SessionCore<PlainRuntime, StillClock>>,
                ),
                _,
            >("no place")
        },
    );
    assert!(matches!(refused, Err("no place")));
    assert_eq!(
        Arc::strong_count(&link),
        1,
        "the refused parts let the sink go"
    );
}

#[cfg(feature = "action-trace")]
mod action_trace {
    use alloc::sync::Arc;
    use core::sync::atomic::Ordering;

    use super::{bundle, NoEntropy, PlainRuntime, StillClock};
    use crate::close_reason::CloseReason;
    use crate::session_actions::SessionActionsBinding;
    use crate::session_fsm_unicast::SessionFsmUnicastActions;

    /// Each action the machine runs counts itself once, on its own counter, and the snapshot
    /// reads the counts; an action that did not run reads zero.
    #[test]
    fn each_action_that_runs_is_counted_once_on_its_own_counter() {
        let (actions, link) = bundle();
        let before = actions.trace_snapshot();
        assert_eq!(
            (
                before.link_driver_open,
                before.free_pool_slots,
                before.set_close_reason_count,
                before.enable_rx_tx_regions,
            ),
            (0, 0, 0, 0),
            "a new session has run no action"
        );

        let mut binding =
            SessionActionsBinding::<PlainRuntime, StillClock>::new(Arc::clone(&actions), NoEntropy);
        binding.link_driver_open();
        binding.free_pool_slots();
        binding.free_pool_slots();
        binding.set_close_reason_generic();

        let after = actions.trace_snapshot();
        assert_eq!(after.link_driver_open, 1, "one open, one count");
        assert_eq!(
            link.opened.load(Ordering::SeqCst),
            1,
            "CONTROL: the open the count records reached the link"
        );
        assert_eq!(after.free_pool_slots, 2, "two runs, two counts");
        assert_eq!(after.set_close_reason_count, 1);
        assert_eq!(
            actions.close_reason(),
            Some(CloseReason::Generic),
            "CONTROL: the reason the action staged is its effect, apart from its count"
        );
        assert_eq!(
            (
                after.enable_rx_tx_regions,
                after.release_link,
                after.send_init_syn,
            ),
            (0, 0, 0),
            "an action that did not run is not counted"
        );
    }

    /// A snapshot is a copy taken under the lock: it keeps the counts it was taken with while
    /// the session goes on counting, and a later snapshot reads the counts of then.
    #[test]
    fn a_snapshot_keeps_the_counts_it_was_taken_with() {
        let (actions, _link) = bundle();
        let mut binding =
            SessionActionsBinding::<PlainRuntime, StillClock>::new(Arc::clone(&actions), NoEntropy);
        binding.enable_rx_tx_regions();
        let first = actions.trace_snapshot();
        binding.enable_rx_tx_regions();
        assert_eq!(
            first.enable_rx_tx_regions, 1,
            "the earlier snapshot does not move"
        );
        assert_eq!(
            actions.trace_snapshot().enable_rx_tx_regions,
            2,
            "a later snapshot reads the count of then"
        );
    }
}

#[cfg(all(feature = "reply-egress-gate", feature = "codec-response"))]
mod reply_egress_gate {
    use alloc::boxed::Box;
    use alloc::sync::Arc;
    use core::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

    use super::{bundle, established_bundle};
    use crate::network_message::MessageRef;
    use crate::response_build::build_response_reply;
    use crate::session_actions::ReplyEgressGate;
    use crate::wire::ResponseOwned;

    /// A gate that admits a reply when the test says so, and counts what it was asked.
    struct Gate {
        asked: Arc<AtomicUsize>,
        admits: Arc<AtomicBool>,
    }

    impl Gate {
        fn new(admits: bool) -> Self {
            Self {
                asked: Arc::new(AtomicUsize::new(0)),
                admits: Arc::new(AtomicBool::new(admits)),
            }
        }

        /// The gate a session installs, answering from this one's switch: a `Response` is
        /// admitted while the switch is on, and nothing else is.
        fn installed(&self) -> ReplyEgressGate {
            let asked = Arc::clone(&self.asked);
            let admits = Arc::clone(&self.admits);
            Box::new(move |reply: MessageRef<'_>| {
                asked.fetch_add(1, Ordering::SeqCst);
                matches!(reply, MessageRef::Response(_)) && admits.load(Ordering::SeqCst)
            })
        }

        fn asked(&self) -> usize {
            self.asked.load(Ordering::SeqCst)
        }

        fn admit(&self, admits: bool) {
            self.admits.store(admits, Ordering::SeqCst);
        }
    }

    fn reply() -> ResponseOwned {
        build_response_reply(
            5,
            crate::wire_key::WireKey::literal("demo/asked").expect("a literal key"),
            b"answer",
        )
        .expect("a reply")
    }

    /// A reply the installed gate denies is consumed and never reaches the link; one it admits
    /// is written; with the gate taken away a reply is written without the gate being asked.
    #[test]
    fn a_reply_the_gate_denies_is_not_written_and_one_it_admits_is() {
        let (actions, link) = established_bundle();
        let gate = Gate::new(false);
        actions.set_egress_reply_gate(Some(gate.installed()));

        assert_eq!(
            actions.try_send_response(reply()),
            Ok(()),
            "a denied reply is consumed, not refused"
        );
        assert_eq!(gate.asked(), 1, "the gate was asked of the reply");
        assert_eq!(
            link.written.load(Ordering::SeqCst),
            0,
            "a denied reply never reaches the link"
        );

        gate.admit(true);
        assert_eq!(actions.try_send_response(reply()), Ok(()));
        assert_eq!(gate.asked(), 2, "the gate was asked of the second reply");
        let written = link.written.load(Ordering::SeqCst);
        assert_ne!(written, 0, "an admitted reply is written to the link");

        actions.set_egress_reply_gate(None);
        assert_eq!(actions.try_send_response(reply()), Ok(()));
        assert_eq!(gate.asked(), 2, "a gate taken away is asked nothing");
        assert!(
            link.written.load(Ordering::SeqCst) > written,
            "with no gate the reply is written"
        );
    }

    /// The verdict alone: every reply is admitted while no gate is installed, and once one is,
    /// a reply is handed back exactly when the gate admits it.
    #[test]
    fn the_verdict_admits_a_reply_exactly_when_the_installed_gate_does() {
        let (actions, link) = bundle();
        let gate = Gate::new(false);
        assert!(
            actions.reply_egress_verdict(reply()).is_some(),
            "no gate installed: the reply is admitted"
        );

        actions.set_egress_reply_gate(Some(gate.installed()));
        assert!(
            actions.reply_egress_verdict(reply()).is_none(),
            "the gate denies it"
        );
        gate.admit(true);
        assert!(
            actions.reply_egress_verdict(reply()).is_some(),
            "the gate admits it"
        );
        assert_eq!(gate.asked(), 2, "asked once per verdict while installed");
        assert_eq!(
            link.written.load(Ordering::SeqCst),
            0,
            "CONTROL: a verdict sends nothing"
        );
    }
}

/// What the bundle records of a peer's InitSyn and OpenSyn. Those facts are the acceptor's: a
/// build with the accepting role takes them as each message is read, and a build without it
/// takes none, so what an initiator took off the InitAck stands.
#[cfg(any(feature = "codec-init-body", feature = "codec-open-body"))]
mod handshake_records {
    use alloc::vec;

    use super::bundle;

    const ACCEPTS: bool = cfg!(feature = "session-unicast-accept");

    /// The InitSyn's zid where the cookie binds it and where the routing reads it, its role,
    /// and its caps where the InitAck answers them.
    #[cfg(feature = "codec-init-body")]
    #[test]
    fn a_peer_init_syn_is_recorded_only_with_the_accepting_role() {
        use wz_codecs::wire_const::{FLAG_T_INIT_S, PROTOCOL_VERSION, T_MID_INIT};
        const ZID: [u8; 4] = [0xB0, 0xB1, 0xB2, 0xB3];
        let (actions, _link) = bundle();
        // Role peer (wire 1) and a 4-byte zid, then the size block: SN resolution, batch size.
        let init_syn = vec![
            FLAG_T_INIT_S | T_MID_INIT,
            PROTOCOL_VERSION,
            0x31,
            ZID[0],
            ZID[1],
            ZID[2],
            ZID[3],
            0x00,
            0x00,
            0x00,
        ];
        actions
            .handle_inbound(&init_syn)
            .expect("the InitSyn decodes in either build");
        let routed = actions.fact_remote_peer_zid(|slot| *slot);
        let bound = actions.fact_inbound_peer_zid(|slot| *slot);
        let caps = actions.fact_inbound_peer_init_caps(|slot| slot.is_some());
        let expected = ACCEPTS.then_some(&ZID[..]);
        assert_eq!(routed.as_deref(), expected, "the zid the routing reads");
        assert_eq!(bound.as_deref(), expected, "the zid the cookie binds");
        assert_eq!(
            actions.peer_whatami_wire(),
            ACCEPTS.then_some(1),
            "the role"
        );
        assert_eq!(caps, ACCEPTS, "the caps the InitAck answers");
    }

    /// The zid an InitAck's read made is the one the session records, and facts that name no zid
    /// record none over the one recorded before. Turned red by a read that hands no zid on, or by
    /// a record that keeps a zid other than the facts'.
    #[cfg(all(
        feature = "codec-init-body",
        feature = "alloc",
        feature = "codec-frame",
        feature = "session-unicast"
    ))]
    #[test]
    fn an_init_ack_records_the_zid_its_read_made() {
        use crate::inbound::{read_control, ControlFacts, InitFacts};
        use wz_codecs::wire_const::{FLAG_T_INIT_A, PROTOCOL_VERSION, T_MID_INIT};
        const ZID: [u8; 2] = [0xAA, 0xBB];
        let (actions, _link) = bundle();
        // A 2-byte zid (its length less one in the high nibble), then a 3-byte cookie.
        let wire = [
            T_MID_INIT | FLAG_T_INIT_A,
            PROTOCOL_VERSION,
            0x12,
            ZID[0],
            ZID[1],
            0x03,
            0x01,
            0x02,
            0x03,
        ];
        let (read, _) = read_control(&wire).expect("an InitAck");
        let facts = *read.facts();
        actions.observe_control(&facts);
        assert_eq!(
            actions.fact_remote_peer_zid(|slot| *slot).as_deref(),
            Some(&ZID[..]),
            "the zid the read made"
        );
        let ControlFacts::Init(init) = facts else {
            panic!("an Init: {facts:?}");
        };
        actions.observe_control(&ControlFacts::Init(InitFacts { zid: None, ..init }));
        assert_eq!(
            actions.fact_remote_peer_zid(|slot| *slot),
            None,
            "facts that name no zid record none"
        );
    }

    /// The OpenSyn's echoed cookie, which the admission checks. Its lease is taken by neither
    /// build as it is read: only an admitted OpenSyn gives one.
    #[cfg(feature = "codec-open-body")]
    #[test]
    fn a_peer_open_syn_cookie_is_kept_only_with_the_accepting_role() {
        use wz_codecs::wire_const::T_MID_OPEN;
        let (actions, _link) = bundle();
        // A lease of 5 ms, initial SN 0, and a 4-byte cookie.
        let open_syn = vec![T_MID_OPEN, 0x05, 0x00, 0x04, 0xDE, 0xAD, 0xBE, 0xEF];
        actions
            .handle_inbound(&open_syn)
            .expect("the OpenSyn decodes in either build");
        let kept = actions.fact_inbound_opensyn_cookie(|slot| slot.is_some());
        assert_eq!(kept, ACCEPTS, "the echoed cookie");
        assert!(
            actions.fact_peer_open_lease_ms(|slot| slot.is_none()),
            "no lease is taken from an OpenSyn that was only read"
        );
    }
}

/// The heap path's handshake senders hand the link the message their encoder answers: one write
/// each for the opener's InitSyn and OpenSyn. A message the encoder refused is not sent; the
/// fields of these four leave no input that reaches it, which is why this reads the sent arm.
#[cfg(all(
    feature = "codec-init-body",
    feature = "codec-open-body",
    feature = "session-unicast-open",
    not(feature = "tx-lend-only")
))]
#[test]
fn the_heap_paths_opening_handshake_reaches_the_link() {
    use crate::session_fsm_unicast::SessionFsmUnicastActions;
    let (actions, link) = bundle();
    let mut binding = super::SessionActionsBinding::<PlainRuntime, StillClock>::new(
        Arc::clone(&actions),
        NoEntropy,
    );
    binding.link_driver_open();
    binding.send_init_syn();
    assert_eq!(link.written.load(Ordering::SeqCst), 1, "the InitSyn");
    binding.send_open_syn();
    assert_eq!(link.written.load(Ordering::SeqCst), 2, "and the OpenSyn");
}

/// The lend-only handshake senders write each message once, into a slot asked for by the bound
/// every handshake message fits and not by the message's own length, which nothing measures
/// before the write; the link is handed the bytes written. A slot shorter than the message
/// refuses it, counted, and nothing reaches the link.
#[cfg(all(
    feature = "tx-lend-only",
    feature = "codec-init-body",
    feature = "codec-open-body",
    feature = "session-unicast-open"
))]
mod lent_handshake {
    use alloc::sync::Arc;
    use alloc::vec::Vec;
    use std::sync::Mutex;

    use super::{params, NoEntropy, PlainRuntime, StillClock};
    use crate::handshake_encode::HANDSHAKE_LEND_WANT;
    use crate::link::{BoxedLinkDriver, LinkSendOutcome, TxSlot, TxSlotGrant};
    use crate::qos::Priority;
    use crate::reliability::Reliability;
    use crate::session_actions::{SessionActionsBinding, SessionLinkActions};
    use crate::session_fsm_unicast::SessionFsmUnicastActions;
    use crate::session_init_params::SessionInitParams;

    /// A link that lends one slot of a fixed width, whatever it is asked for, and records each
    /// ask and each send.
    struct LendingLink {
        slot: Mutex<Vec<u8>>,
        asked: Mutex<Vec<usize>>,
        sent: Mutex<Vec<Vec<u8>>>,
    }

    impl LendingLink {
        fn of_width(width: usize) -> Arc<Self> {
            Arc::new(Self {
                slot: Mutex::new(alloc::vec![0; width]),
                asked: Mutex::new(Vec::new()),
                sent: Mutex::new(Vec::new()),
            })
        }
    }

    impl BoxedLinkDriver for LendingLink {
        fn send_blocking(&self, _bytes: &[u8], _reliability: Reliability) -> LinkSendOutcome {
            LinkSendOutcome::Sent
        }

        fn open_blocking(&self) {}

        fn close_blocking(&self) {}

        fn tx_slot_acquire(&self, want: usize, _priority: Priority) -> Option<TxSlotGrant> {
            self.asked.lock().expect("the asks").push(want);
            Some(TxSlotGrant {
                slot: TxSlot(0),
                headroom: 0,
            })
        }

        fn tx_slot_storage(&self, _slot: TxSlot) -> (*mut u8, usize) {
            let mut slot = self.slot.lock().expect("the slot");
            (slot.as_mut_ptr(), slot.len())
        }

        fn tx_slot_send(
            &self,
            _slot: TxSlot,
            start: usize,
            len: usize,
            _reliability: Reliability,
            _priority: Priority,
        ) -> LinkSendOutcome {
            let written = self.slot.lock().expect("the slot")[start..start + len].to_vec();
            self.sent.lock().expect("the sends").push(written);
            LinkSendOutcome::Sent
        }

        fn tx_slot_abort(&self, _slot: TxSlot) {}
    }

    /// A new session's action bundle over `link`, and the binding the machine drives it through.
    fn opener(
        link: &Arc<LendingLink>,
    ) -> (
        Arc<SessionLinkActions<PlainRuntime, StillClock>>,
        SessionActionsBinding<PlainRuntime, StillClock>,
    ) {
        opener_of(link, params())
    }

    /// [`opener`] over the parameters `params`.
    fn opener_of(
        link: &Arc<LendingLink>,
        params: SessionInitParams,
    ) -> (
        Arc<SessionLinkActions<PlainRuntime, StillClock>>,
        SessionActionsBinding<PlainRuntime, StillClock>,
    ) {
        let sink: Arc<dyn BoxedLinkDriver + Send + Sync> = link.clone();
        let actions =
            SessionLinkActions::<PlainRuntime, StillClock>::new_generic(sink, params, StillClock)
                .expect("the heap has room");
        let binding =
            SessionActionsBinding::<PlainRuntime, StillClock>::new(Arc::clone(&actions), NoEntropy);
        (actions, binding)
    }

    #[test]
    fn each_opening_message_asks_the_bound_and_sends_what_it_wrote() {
        let link = LendingLink::of_width(512);
        let (actions, mut binding) = opener(&link);
        binding.link_driver_open();
        binding.send_init_syn();
        binding.send_open_syn();
        assert_eq!(
            *link.asked.lock().expect("the asks"),
            [HANDSHAKE_LEND_WANT, HANDSHAKE_LEND_WANT],
            "each message asks for the bound, not for a length measured before the write"
        );
        let sent = link.sent.lock().expect("the sends");
        assert_eq!(sent.len(), 2, "the InitSyn and the OpenSyn");
        assert_eq!(sent[0][0] & 0x1F, wz_codecs::wire_const::T_MID_INIT);
        assert_eq!(sent[1][0] & 0x1F, wz_codecs::wire_const::T_MID_OPEN);
        assert_eq!(actions.tx_refusals().no_slot, 0, "nothing was refused");
    }

    #[test]
    fn a_slot_shorter_than_the_init_syn_refuses_it_and_sends_nothing() {
        let link = LendingLink::of_width(4);
        let (actions, mut binding) = opener(&link);
        binding.link_driver_open();
        binding.send_init_syn();
        assert_eq!(*link.asked.lock().expect("the asks"), [HANDSHAKE_LEND_WANT]);
        assert!(link.sent.lock().expect("the sends").is_empty());
        assert_eq!(actions.tx_refusals().no_slot, 1, "the refusal is counted");
    }

    /// A lend-only Open stages the bound the session decided where it writes the Open, so the
    /// peer reads it off the OpenSyn, and an OpenSyn sent once the decision went to none carries
    /// none. Turned red by a lend-only Open that leaves the bound unstaged, which no other step of
    /// a lend-only session stages.
    #[cfg(all(
        feature = "alloc",
        feature = "codec-frame",
        feature = "session-unicast"
    ))]
    #[test]
    fn a_lent_open_syn_carries_the_bound_the_session_decided() {
        use crate::extbound::Bound;
        use crate::inbound::{read_control, ExtChainRead};
        let link = LendingLink::of_width(512);
        let (actions, mut binding) = opener(&link);
        binding.link_driver_open();
        actions.fact_local_remote_bound(|slot| *slot = Some(Bound::South));
        binding.send_open_syn();
        actions.fact_local_remote_bound(|slot| *slot = None);
        binding.send_open_syn();
        let sent = link.sent.lock().expect("the sends");
        assert_eq!(sent.len(), 2, "both OpenSyns were sent");
        let bound_of = |bytes: &[u8]| {
            let (read, _) = read_control(bytes).expect("an Open the reader reads");
            read.chain().remote_bound().ok()
        };
        assert_eq!(
            bound_of(sent[0].as_slice()),
            Some(Some(Bound::South)),
            "the bound the session decided"
        );
        assert_eq!(
            bound_of(sent[1].as_slice()),
            Some(None),
            "a bound decided away is taken off the chain"
        );
    }

    /// The InitSyn and the OpenSyn a lend-only opener sends are the bytes the heap encoders write
    /// for its chains: the patch level on the InitSyn, and on the OpenSyn the bound the session
    /// decided. A build that stages no handshake extension writes both from its parameters
    /// (`encode_init_patch_into`, `encode_open_bound_into`) and one that stages writes them from
    /// its chains, and each lend-only leg runs this. Turned red by either writer putting another
    /// entry, header or value on the wire, or leaving the bound off.
    #[test]
    fn a_lent_opening_handshake_writes_the_bytes_of_its_chains() {
        use crate::extbound::{encode_remote_bound_ext, Bound};
        use crate::handshake_encode::{encode_init_with_caps, encode_open, InitCaps};
        let link = LendingLink::of_width(512);
        let (actions, mut binding) = opener(&link);
        binding.link_driver_open();
        binding.send_init_syn();
        actions.fact_local_remote_bound(|slot| *slot = Some(Bound::South));
        binding.send_open_syn();
        let sent = link.sent.lock().expect("the sends");
        assert_eq!(sent.len(), 2, "the InitSyn and the OpenSyn");
        let params = params();
        // The InitSyn advertises the batch its link can receive, as the session's sender does.
        let caps = InitCaps {
            batch_size: actions.own_batch_advertisement(),
            ..InitCaps::of(&params)
        };
        let patch = [crate::extpatch::encode_patch_ext()];
        let init_syn = encode_init_with_caps(&params, caps, false, patch.as_slice().into(), None)
            .expect("the InitSyn the heap encoder writes");
        assert_eq!(
            sent[0], init_syn,
            "the InitSyn carries the patch level alone"
        );
        let bound = [encode_remote_bound_ext(Bound::South)];
        let open_syn =
            encode_open(&params, false, None, &bound).expect("the OpenSyn the heap encoder writes");
        assert_eq!(sent[1], open_syn, "the OpenSyn carries the bound alone");
    }

    /// Every lend-only control message is written by one writer, which holds the initiator's
    /// OpenSyn as it went out, and nothing of the InitSyn before it, for a replay that sends those
    /// very bytes again. A build whose domain of `handshake-stray-message` leaves the replay out
    /// holds nothing. Turned red by a writer that holds by a role other than the message's own
    /// (`write_control`'s `answer`), or that holds from where the message does not start.
    #[test]
    fn a_lent_open_syn_is_sent_again_as_written_and_the_init_syn_is_not_held() {
        use crate::policy::HandshakeStrayMessage;
        let mut replaying = params();
        let replays = replaying
            .policy
            .select_handshake_stray_message(HandshakeStrayMessage::IgnoreAndReplay)
            .is_ok();
        let link = LendingLink::of_width(512);
        let (actions, mut binding) = opener_of(&link, replaying);
        binding.link_driver_open();
        binding.send_init_syn();
        assert_eq!(actions.held_answer_len(), 0, "an InitSyn is never held");
        assert!(
            !actions.resend_held_answer(),
            "and so nothing is sent again"
        );
        binding.send_open_syn();
        let sent = link.sent.lock().expect("the sends").clone();
        assert_eq!(sent.len(), 2, "the InitSyn and the OpenSyn");
        if !replays {
            assert_eq!(actions.held_answer_len(), 0, "no hold without the replay");
            assert!(!actions.resend_held_answer());
            return;
        }
        assert_eq!(
            actions.held_answer_len(),
            sent[1].len(),
            "the OpenSyn, whole"
        );
        assert!(
            actions.resend_held_answer(),
            "the held OpenSyn is sent again"
        );
        let again = link.sent.lock().expect("the sends");
        assert_eq!(again.len(), 3);
        assert_eq!(again[2], sent[1], "as the very bytes that went out");
    }

    /// The lend-only Close goes through the same writer as the handshake: its header and
    /// reason in a lent slot, and a slot too short for it refused and counted, with nothing
    /// sent. Turned red by a Close written without its reason, or sent from a short slot.
    #[cfg(feature = "codec-close")]
    #[test]
    fn a_lent_close_carries_its_reason_and_a_short_slot_refuses_it() {
        let link = LendingLink::of_width(512);
        let (actions, _binding) = opener(&link);
        assert!(actions.send_close_lent(0x02).is_ok());
        {
            let sent = link.sent.lock().expect("the sends");
            assert_eq!(sent.len(), 1);
            assert_eq!(sent[0][0] & 0x1F, wz_codecs::wire_const::T_MID_CLOSE);
            assert_eq!(&sent[0][1..], &[0x02], "the reason, and nothing after it");
        }
        assert_eq!(actions.tx_refusals().no_slot, 0);

        let short = LendingLink::of_width(1);
        let (actions, _binding) = opener(&short);
        assert_eq!(
            actions.send_close_lent(0x02),
            Err(crate::link::LinkDropCause::NoTxSlot)
        );
        assert!(short.sent.lock().expect("the sends").is_empty());
        assert_eq!(actions.tx_refusals().no_slot, 1, "the refusal is counted");
    }
}

/// Under `tx-lend-only` a frame the link lends no slot for is refused before a byte of it is
/// written, and takes no sequence number: the next frame of the conduit carries the one it would
/// have, so the reliable channel has no gap no frame fills. Turned red by an SN taken before the
/// slot is lent (`write_n_msg` minting before its room is asked or its slot lent), whose next
/// frame carries SN 1.
#[cfg(all(feature = "tx-lend-only", feature = "codec-push", feature = "alloc"))]
mod lent_frame_refusal {
    use alloc::sync::Arc;
    use alloc::vec::Vec;
    use core::sync::atomic::{AtomicBool, Ordering};
    use std::sync::Mutex;

    use super::{params, PlainRuntime, StillClock};
    use crate::link::{
        BoxedLinkDriver, LinkDropCause, LinkRoom, LinkSendOutcome, RoomAnswer, RoomWait, TxSlot,
        TxSlotGrant,
    };
    use crate::qos::Priority;
    use crate::reliability::Reliability;
    use crate::send_wire_error::SendWireError;
    use crate::session_actions::SessionLinkActions;

    /// A link of one slot that lends it only while `lends` says so, has no room while `full`
    /// says so, and keeps each frame sent.
    struct DryLink {
        lends: AtomicBool,
        full: AtomicBool,
        slot: Mutex<Vec<u8>>,
        sent: Mutex<Vec<Vec<u8>>>,
        asked: Mutex<Vec<usize>>,
    }

    impl DryLink {
        fn of_width(width: usize, lends: bool) -> Arc<Self> {
            Arc::new(Self {
                lends: AtomicBool::new(lends),
                full: AtomicBool::new(false),
                slot: Mutex::new(alloc::vec![0; width]),
                sent: Mutex::new(Vec::new()),
                asked: Mutex::new(Vec::new()),
            })
        }
    }

    impl BoxedLinkDriver for DryLink {
        fn send_blocking(&self, _bytes: &[u8], _reliability: Reliability) -> LinkSendOutcome {
            LinkSendOutcome::Sent
        }

        fn open_blocking(&self) {}

        fn close_blocking(&self) {}

        fn wait_for_room_for(
            &self,
            _class: Reliability,
            _priority: Priority,
            _wait: RoomWait,
        ) -> RoomAnswer {
            RoomAnswer::at_once(if self.full.load(Ordering::SeqCst) {
                LinkRoom::Congested
            } else {
                LinkRoom::Free
            })
        }

        fn tx_slot_acquire(&self, want: usize, _priority: Priority) -> Option<TxSlotGrant> {
            self.asked.lock().expect("the asks").push(want);
            self.lends.load(Ordering::SeqCst).then_some(TxSlotGrant {
                slot: TxSlot(0),
                headroom: 0,
            })
        }

        fn tx_slot_storage(&self, _slot: TxSlot) -> (*mut u8, usize) {
            let mut slot = self.slot.lock().expect("the slot");
            (slot.as_mut_ptr(), slot.len())
        }

        fn tx_slot_send(
            &self,
            _slot: TxSlot,
            start: usize,
            len: usize,
            _reliability: Reliability,
            _priority: Priority,
        ) -> LinkSendOutcome {
            let written = self.slot.lock().expect("the slot")[start..start + len].to_vec();
            self.sent.lock().expect("the sends").push(written);
            LinkSendOutcome::Sent
        }

        fn tx_slot_abort(&self, _slot: TxSlot) {}
    }

    /// A reliable plain put on `actions`.
    fn put(
        actions: &SessionLinkActions<PlainRuntime, StillClock>,
    ) -> Option<Result<(), SendWireError>> {
        let key = crate::named_key::NamedKey::literal("home/gap").expect("a key");
        actions.send_plain_put_qos(
            key,
            b"v",
            None,
            super::super::SendAs {
                reliable: true,
                express: false,
                priority: Priority::DEFAULT,
            },
        )
    }

    #[test]
    fn a_frame_refused_for_want_of_a_slot_gives_its_sequence_number_back() {
        let link = DryLink::of_width(512, false);
        let sink: Arc<dyn BoxedLinkDriver + Send + Sync> = link.clone();
        let actions =
            SessionLinkActions::<PlainRuntime, StillClock>::new_generic(sink, params(), StillClock)
                .expect("the heap has room");
        actions.enter_established();
        assert_eq!(
            put(&actions),
            Some(Err(SendWireError::LinkRefused(LinkDropCause::NoTxSlot)))
        );
        assert_eq!(actions.tx_refusals().no_slot, 1, "the refusal is counted");
        link.lends.store(true, Ordering::SeqCst);
        assert_eq!(put(&actions), Some(Ok(())));
        let sent = link.sent.lock().expect("the sends");
        assert_eq!(sent.len(), 1, "only the second put reached the link");
        // A frame's second byte is its SN, one byte while it is below 128; `params` starts at 0.
        assert_eq!(
            sent[0][1], 0,
            "the second frame carries the SN the refused one gave back"
        );
    }

    /// The one frame a fresh session sends for `put`.
    fn one_frame(
        put: &dyn Fn(
            &SessionLinkActions<PlainRuntime, StillClock>,
        ) -> Option<Result<(), SendWireError>>,
    ) -> Vec<u8> {
        let link = DryLink::of_width(512, true);
        let sink: Arc<dyn BoxedLinkDriver + Send + Sync> = link.clone();
        let actions =
            SessionLinkActions::<PlainRuntime, StillClock>::new_generic(sink, params(), StillClock)
                .expect("the heap has room");
        actions.enter_established();
        assert_eq!(put(&actions), Some(Ok(())));
        let mut sent = link.sent.lock().expect("the sends");
        assert_eq!(sent.len(), 1, "one frame");
        sent.remove(0)
    }

    /// A put written from the head its publisher's plain way made leaves as the frame its parts
    /// make, for a QoS byte that rides and the one that does not, and its parts' writer does not
    /// run; a head that does not name the key (another declaration) is not written, so the frame
    /// is still the key's own, written from its parts. Turned red by a head written for a key it
    /// does not name, by a head whose bytes differ from the writer's, or by a head the send is
    /// handed and does not write.
    #[cfg(feature = "storage-profile")]
    #[test]
    fn a_put_written_from_its_head_is_the_frame_its_parts_make() {
        let send = super::super::SendAs {
            reliable: true,
            express: false,
            priority: Priority::DEFAULT,
        };
        let id = crate::wire_key::MappedId::new(7).expect("not zero");
        let key = crate::named_key::NamedKey::under(
            "home/head",
            crate::named_key::Prefix::of(id, "home/head"),
        )
        .expect("a key under its declaration");
        let runs = || crate::lent_push::WRITER_RUNS.with(core::cell::Cell::get);
        for qos in [
            crate::sample::QosLevel::DEFAULT,
            crate::sample::QosLevel::from_raw(0x1a),
        ] {
            let meta = crate::metadata::PushMetadata {
                qos: Some(qos),
                ..Default::default()
            };
            let with_head = |head| super::super::PushParts {
                kind: crate::sample::SampleKind::Put,
                value: b"v",
                meta: &meta,
                head,
            };
            let parts =
                one_frame(&|actions| actions.send_plain_put_qos(key, b"v", Some(qos), send));
            let own = crate::lent_push::PutHead::new(7, qos).expect("a declared id");
            assert!(with_head(Some(own)).takes_head(key), "qos {:#04x}", qos.raw);
            let before = runs();
            assert_eq!(
                one_frame(&|actions| actions.send_push_qos(key, with_head(Some(own)), send)),
                parts,
                "the head of the key, qos {:#04x}",
                qos.raw
            );
            assert_eq!(runs(), before, "the head is written, not the parts");
            let other = crate::lent_push::PutHead::new(8, qos).expect("a declared id");
            assert!(
                !with_head(Some(other)).takes_head(key),
                "qos {:#04x}",
                qos.raw
            );
            let before = runs();
            assert_eq!(
                one_frame(&|actions| actions.send_push_qos(key, with_head(Some(other)), send)),
                parts,
                "the head of another declaration is not written, qos {:#04x}",
                qos.raw
            );
            assert!(runs() > before, "the parts are written in its place");
        }
    }

    /// A head whose QoS byte is not the put's is not written: the put leaves with its own QoS, as
    /// its parts make it. Turned red by a send that writes the head of the key whatever QoS the
    /// put carries.
    #[cfg(feature = "pubsub-qos")]
    #[test]
    fn a_head_of_another_qos_is_not_written() {
        let send = super::super::SendAs {
            reliable: true,
            express: false,
            priority: Priority::DEFAULT,
        };
        let id = crate::wire_key::MappedId::new(7).expect("not zero");
        let key = crate::named_key::NamedKey::under(
            "home/head",
            crate::named_key::Prefix::of(id, "home/head"),
        )
        .expect("a key under its declaration");
        let qos = crate::sample::QosLevel::from_raw(0x1a);
        let meta = crate::metadata::PushMetadata {
            qos: Some(qos),
            ..Default::default()
        };
        let default_head = crate::lent_push::PutHead::new(7, crate::sample::QosLevel::DEFAULT)
            .expect("a declared id");
        let push = super::super::PushParts {
            kind: crate::sample::SampleKind::Put,
            value: b"v",
            meta: &meta,
            head: Some(default_head),
        };
        assert!(!push.takes_head(key), "the head carries the default QoS");
        assert_eq!(
            one_frame(&|actions| actions.send_push_qos(key, push, send)),
            one_frame(&|actions| actions.send_plain_put_qos(key, b"v", Some(qos), send)),
            "the put carries its own QoS"
        );
    }

    /// A Del handed its publisher's head is written as a Del from its parts, not as the Put the
    /// head begins. Turned red by a send that takes the head for a Push that is no plain Put. The
    /// network counters leave a publication to the owned send, which this link does not take.
    #[cfg(not(feature = "transport-stats"))]
    #[test]
    fn a_del_is_not_written_from_a_puts_head() {
        let send = super::super::SendAs {
            reliable: true,
            express: false,
            priority: Priority::DEFAULT,
        };
        let id = crate::wire_key::MappedId::new(7).expect("not zero");
        let key = crate::named_key::NamedKey::under(
            "home/head",
            crate::named_key::Prefix::of(id, "home/head"),
        )
        .expect("a key under its declaration");
        let none = crate::metadata::PushMetadata::default();
        let head = crate::lent_push::PutHead::new(7, crate::sample::QosLevel::DEFAULT)
            .expect("a declared id");
        let push = |kind| super::super::PushParts {
            kind,
            value: b"",
            meta: &none,
            head: Some(head),
        };
        let del = push(crate::sample::SampleKind::Del);
        assert!(!del.takes_head(key), "a Del is no plain Put");
        assert!(push(crate::sample::SampleKind::Put).takes_head(key));
        assert_ne!(
            one_frame(&|actions| actions.send_push_qos(key, del, send)),
            one_frame(&|actions| actions.send_push_qos(
                key,
                push(crate::sample::SampleKind::Put),
                send
            )),
            "the Del is not the Put its head begins"
        );
    }

    /// A frame sent whole asks its link for the whole batch budget, as a window does: nothing
    /// measures the message before it is written into the slot. Turned red by a send that asks
    /// for a size it counted first (`write_n_msg` asking for anything but `emit.mtu`).
    #[test]
    fn a_frame_sent_whole_asks_for_the_batch_budget() {
        let link = DryLink::of_width(512, true);
        let sink: Arc<dyn BoxedLinkDriver + Send + Sync> = link.clone();
        let actions =
            SessionLinkActions::<PlainRuntime, StillClock>::new_generic(sink, params(), StillClock)
                .expect("the heap has room");
        actions.enter_established();
        assert_eq!(put(&actions), Some(Ok(())));
        let (budget, _) = actions
            .negotiated_tx_limits_for(Reliability::Reliable)
            .expect("the limits are settled at establishment");
        assert_eq!(
            *link.asked.lock().expect("the asks"),
            [budget],
            "one ask, for the budget"
        );
    }

    /// A put its link has no room for is dropped before its frame asks for a slot or takes an SN:
    /// nothing reaches the link, and the next frame carries the SN the dropped one left untaken.
    /// Turned red by `write_n_msg` lending its frame before it asks for room
    /// (`congested_within` after `lease_on`), whose dropped put asks for a slot and takes SN 0,
    /// or by the room not asked at all, whose put is sent while the link is full.
    #[test]
    fn a_put_its_link_has_no_room_for_asks_no_slot_and_takes_no_sequence_number() {
        let link = DryLink::of_width(512, true);
        link.full.store(true, Ordering::SeqCst);
        let sink: Arc<dyn BoxedLinkDriver + Send + Sync> = link.clone();
        let actions =
            SessionLinkActions::<PlainRuntime, StillClock>::new_generic(sink, params(), StillClock)
                .expect("the heap has room");
        actions.enter_established();
        assert_eq!(
            put(&actions),
            Some(Ok(())),
            "a droppable put the link has no room for is dropped, not refused"
        );
        assert!(
            link.asked.lock().expect("the asks").is_empty(),
            "no slot was asked for"
        );
        assert!(
            link.sent.lock().expect("the sends").is_empty(),
            "nothing reached the link"
        );
        link.full.store(false, Ordering::SeqCst);
        assert_eq!(put(&actions), Some(Ok(())));
        let sent = link.sent.lock().expect("the sends");
        assert_eq!(sent.len(), 1, "only the second put reached the link");
        assert_eq!(
            sent[0][1], 0,
            "the second frame carries the SN the dropped one left untaken"
        );
    }

    /// Without fragmentation a put past the batch budget is refused as oversize, and the SN its
    /// frame was written with is given back: the next frame of the conduit carries it. Turned red
    /// by the `unmint` of `write_n_msg`'s `FrameLend::PastMtu` arm taken out, whose next frame
    /// carries SN 1.
    #[cfg(not(feature = "transport-fragmentation"))]
    #[test]
    fn a_put_past_the_budget_without_fragmentation_gives_its_sequence_number_back() {
        let link = DryLink::of_width(4096, true);
        let sink: Arc<dyn BoxedLinkDriver + Send + Sync> = link.clone();
        let actions =
            SessionLinkActions::<PlainRuntime, StillClock>::new_generic(sink, params(), StillClock)
                .expect("the heap has room");
        actions.enter_established();
        let (budget, _) = actions
            .negotiated_tx_limits_for(Reliability::Reliable)
            .expect("the limits are settled at establishment");
        let key = crate::named_key::NamedKey::literal("home/gap").expect("a key");
        let past = alloc::vec![0x5a; budget + 1];
        assert_eq!(
            actions.send_plain_put_qos(
                key,
                &past,
                None,
                super::super::SendAs {
                    reliable: true,
                    express: false,
                    priority: Priority::DEFAULT,
                },
            ),
            Some(Err(SendWireError::LinkRefused(LinkDropCause::Oversize)))
        );
        assert_eq!(put(&actions), Some(Ok(())));
        let sent = link.sent.lock().expect("the sends");
        assert_eq!(sent.len(), 1, "only the second put reached the link");
        assert_eq!(
            sent[0][1], 0,
            "the second frame carries the SN the refused one gave back"
        );
    }

    /// A slot lent short of the frame took the SN the frame was written with, and gives it back
    /// with the refusal: the next frame of the conduit carries it. Turned red by the
    /// `unmint` of `write_n_msg`'s `FrameLend::Heap` arm taken out, whose next frame
    /// carries SN 1.
    #[test]
    fn a_frame_refused_in_a_short_slot_gives_its_sequence_number_back() {
        let link = DryLink::of_width(4, true);
        let sink: Arc<dyn BoxedLinkDriver + Send + Sync> = link.clone();
        let actions =
            SessionLinkActions::<PlainRuntime, StillClock>::new_generic(sink, params(), StillClock)
                .expect("the heap has room");
        actions.enter_established();
        assert_eq!(
            put(&actions),
            Some(Err(SendWireError::LinkRefused(LinkDropCause::NoTxSlot)))
        );
        assert_eq!(actions.tx_refusals().no_slot, 1, "the refusal is counted");
        *link.slot.lock().expect("the slot") = alloc::vec![0; 512];
        assert_eq!(put(&actions), Some(Ok(())));
        let sent = link.sent.lock().expect("the sends");
        assert_eq!(sent.len(), 1, "only the second put reached the link");
        assert_eq!(
            sent[0][1], 0,
            "the second frame carries the SN the refused one gave back"
        );
    }
}

/// A chain of fragments its link cuts, in a build without the fragment credit and its stop
/// fragment (`tx-fragment-credit`): nothing more of the chain leaves, as zenoh-pico's chain ends at
/// the fragment whose write failed, and the next frame of the conduit carries the sequence number
/// of the fragment that did not leave, so the reliable ring has no gap.
#[cfg(all(
    feature = "tx-lend-only",
    feature = "codec-push",
    feature = "alloc",
    feature = "transport-fragmentation",
    not(feature = "tx-fragment-credit")
))]
mod chain_cut_without_a_stop_fragment {
    use alloc::sync::Arc;
    use alloc::vec::Vec;
    use core::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Mutex;

    use super::{params, PlainRuntime, StillClock};
    use crate::link::{
        BoxedLinkDriver, LinkDropCause, LinkRoom, LinkSendOutcome, RoomAnswer, RoomWait, TxSlot,
        TxSlotGrant,
    };
    use crate::qos::Priority;
    use crate::reliability::Reliability;
    use crate::send_wire_error::SendWireError;
    use crate::session_actions::SessionLinkActions;

    /// A link that has room while it holds fewer than `room_until` frames, lends its one slot
    /// while it holds fewer than `lend_until`, and keeps each frame sent.
    struct CuttingLink {
        room_until: AtomicUsize,
        lend_until: AtomicUsize,
        slot: Mutex<Vec<u8>>,
        sent: Mutex<Vec<Vec<u8>>>,
    }

    impl CuttingLink {
        fn new(room_until: usize, lend_until: usize) -> Arc<Self> {
            Arc::new(Self {
                room_until: AtomicUsize::new(room_until),
                lend_until: AtomicUsize::new(lend_until),
                slot: Mutex::new(alloc::vec![0; 8192]),
                sent: Mutex::new(Vec::new()),
            })
        }

        /// How many frames the link holds.
        fn held(&self) -> usize {
            self.sent.lock().expect("the sends").len()
        }

        /// Room and a slot for every frame from now on.
        fn free(&self) {
            self.room_until.store(usize::MAX, Ordering::SeqCst);
            self.lend_until.store(usize::MAX, Ordering::SeqCst);
        }
    }

    impl BoxedLinkDriver for CuttingLink {
        fn send_blocking(&self, _bytes: &[u8], _reliability: Reliability) -> LinkSendOutcome {
            LinkSendOutcome::Sent
        }

        fn open_blocking(&self) {}

        fn close_blocking(&self) {}

        fn wait_for_room_for(
            &self,
            _class: Reliability,
            _priority: Priority,
            _wait: RoomWait,
        ) -> RoomAnswer {
            RoomAnswer::at_once(if self.held() < self.room_until.load(Ordering::SeqCst) {
                LinkRoom::Free
            } else {
                LinkRoom::Congested
            })
        }

        fn tx_slot_acquire(&self, _want: usize, _priority: Priority) -> Option<TxSlotGrant> {
            (self.held() < self.lend_until.load(Ordering::SeqCst)).then_some(TxSlotGrant {
                slot: TxSlot(0),
                headroom: 0,
            })
        }

        fn tx_slot_storage(&self, _slot: TxSlot) -> (*mut u8, usize) {
            let mut slot = self.slot.lock().expect("the slot");
            (slot.as_mut_ptr(), slot.len())
        }

        fn tx_slot_send(
            &self,
            _slot: TxSlot,
            start: usize,
            len: usize,
            _reliability: Reliability,
            _priority: Priority,
        ) -> LinkSendOutcome {
            let written = self.slot.lock().expect("the slot")[start..start + len].to_vec();
            self.sent.lock().expect("the sends").push(written);
            LinkSendOutcome::Sent
        }

        fn tx_slot_abort(&self, _slot: TxSlot) {}
    }

    /// An established session over `link`.
    fn session(link: &Arc<CuttingLink>) -> Arc<SessionLinkActions<PlainRuntime, StillClock>> {
        let sink: Arc<dyn BoxedLinkDriver + Send + Sync> = link.clone();
        let actions =
            SessionLinkActions::<PlainRuntime, StillClock>::new_generic(sink, params(), StillClock)
                .expect("the heap has room");
        actions.enter_established();
        actions
    }

    /// A reliable plain put of `len` bytes on `actions`.
    fn put(
        actions: &SessionLinkActions<PlainRuntime, StillClock>,
        len: usize,
    ) -> Option<Result<(), SendWireError>> {
        let key = crate::named_key::NamedKey::literal("home/chain").expect("a key");
        actions.send_plain_put_qos(
            key,
            &alloc::vec![0x5a; len],
            None,
            super::super::SendAs {
                reliable: true,
                express: false,
                priority: Priority::DEFAULT,
            },
        )
    }

    /// A payload two batches long, which leaves as a chain of fragments.
    fn chain_len(actions: &SessionLinkActions<PlainRuntime, StillClock>) -> usize {
        let (budget, _) = actions
            .negotiated_tx_limits_for(Reliability::Reliable)
            .expect("the limits are settled at establishment");
        budget.saturating_mul(2)
    }

    /// A chain whose link has no room after its first fragment ends there: the put is the
    /// congestion drop a droppable message is, nothing follows the first fragment, and the next
    /// frame carries the sequence number the second fragment would have had. Turned red by a stop
    /// fragment written in this build (a frame between the two), or by the cut fragment's number
    /// spent (the next frame on SN 2).
    #[test]
    fn a_chain_cut_for_room_ends_where_it_was_cut() {
        let link = CuttingLink::new(1, usize::MAX);
        let actions = session(&link);
        let long = chain_len(&actions);
        assert_eq!(
            put(&actions, long),
            Some(Ok(())),
            "a droppable chain cut for room is dropped, not refused"
        );
        assert_eq!(link.held(), 1, "only the first fragment left");
        link.free();
        assert_eq!(put(&actions, 1), Some(Ok(())));
        let sent = link.sent.lock().expect("the sends");
        assert_eq!(
            sent.len(),
            2,
            "the next put follows the first fragment with nothing between"
        );
        // The second byte of a frame or a fragment is its SN while it is below 128.
        assert_eq!(sent[0][1], 0, "the first fragment carries SN 0");
        assert_eq!(
            sent[1][1], 1,
            "the next frame carries the cut fragment's SN"
        );
    }

    /// A chain whose link lends no slot for its second fragment ends there: the put is refused
    /// for want of a slot, nothing follows the first fragment, and the number the second fragment
    /// took is given back, so the next frame carries it. Turned red by the `unmint` of a chain
    /// cut without its stop fragment taken out (the next frame on SN 2), or by a stop fragment
    /// written in this build.
    #[test]
    fn a_chain_cut_for_want_of_a_slot_gives_the_cut_fragments_number_back() {
        let link = CuttingLink::new(usize::MAX, 1);
        let actions = session(&link);
        let long = chain_len(&actions);
        assert_eq!(
            put(&actions, long),
            Some(Err(SendWireError::LinkRefused(LinkDropCause::NoTxSlot)))
        );
        assert_eq!(link.held(), 1, "only the first fragment left");
        link.free();
        assert_eq!(put(&actions, 1), Some(Ok(())));
        let sent = link.sent.lock().expect("the sends");
        assert_eq!(
            sent.len(),
            2,
            "the next put follows the first fragment with nothing between"
        );
        assert_eq!(sent[0][1], 0, "the first fragment carries SN 0");
        assert_eq!(
            sent[1][1], 1,
            "the next frame carries the cut fragment's SN"
        );
    }
}

/// A session the `tx-expiry-keeps-session` policy keeps through an expiry, in a build without
/// the run of expiries (`tx-expiry-run`).
#[cfg(all(not(feature = "tx-expiry-run"), feature = "policy-selection"))]
mod expiry_without_a_run {
    use alloc::sync::Arc;

    use super::{params, CountingLink, PlainRuntime, StillClock};
    use crate::limit_binding::Quota;
    use crate::link::BoxedLinkDriver;
    use crate::policy::TxExpiryKeepsSession;
    use crate::session_actions::SessionLinkActions;
    use crate::session_init_params::TxQueueConf;
    use crate::tx_deadline::TxExpiry;

    /// A kept expiry never closes the session, however many come in a row and whatever count
    /// the snapshot holds: a send that finds no room fails and the session stays, as zenoh-pico's
    /// failed send leaves its session, until the lease decides. Turned red by
    /// `settle_blocking_expiry` ordering a close on a kept expiry in this build.
    #[test]
    fn a_kept_expiry_never_closes_the_session() {
        let mut params = params();
        params
            .policy
            .select_tx_expiry_keeps_session(TxExpiryKeepsSession::On)
            .expect("the policy's domain holds on");
        params
            .limits
            .select_tx_expiry_close_after(Quota::at_most(2))
            .expect("the limit's domain holds two");
        params.tx_queue = TxQueueConf::of_snapshot(&params.policy, &params.limits);
        let sink: Arc<dyn BoxedLinkDriver + Send + Sync> = Arc::new(CountingLink::default());
        let actions =
            SessionLinkActions::<PlainRuntime, StillClock>::new_generic(sink, params, StillClock)
                .expect("the heap has room");
        for expiry in 0..8 {
            assert_eq!(
                actions.settle_blocking_expiry(),
                TxExpiry::Kept,
                "expiry {expiry}"
            );
            assert!(
                !actions.congestion_close_ordered(),
                "expiry {expiry} ordered no close"
            );
        }
    }
}

/// A control message the link has no slot for, because the batch a data conduit holds open has
/// its one slot, sends that batch first and then takes the slot it gave back: the control message
/// does not overtake data the session staged before it. The session machine's Close is that case,
/// since it does not drain the window first (the application's close does). Turned red by a
/// control send that asks the link once and no more (`send_control_lent` over
/// `TxLease::acquire` again), which is refused and sends nothing.
#[cfg(all(
    feature = "tx-lend-only",
    feature = "transport-batching",
    feature = "transport-qos",
    feature = "codec-push",
    feature = "codec-close",
    feature = "alloc"
))]
mod lent_control_order {
    use alloc::sync::Arc;
    use alloc::vec::Vec;
    use core::sync::atomic::{AtomicBool, Ordering};
    use std::sync::Mutex;

    use super::{params, PlainRuntime, StillClock};
    use crate::link::{BoxedLinkDriver, LinkSendOutcome, TxSlot, TxSlotGrant};
    use crate::qos::Priority;
    use crate::reliability::Reliability;
    use crate::session_actions::SessionLinkActions;

    /// A link of one slot, lent to one holder at a time, that keeps each message sent.
    struct OneSlotLink {
        lent: AtomicBool,
        slot: Mutex<Vec<u8>>,
        sent: Mutex<Vec<Vec<u8>>>,
    }

    impl BoxedLinkDriver for OneSlotLink {
        fn send_blocking(&self, _bytes: &[u8], _reliability: Reliability) -> LinkSendOutcome {
            LinkSendOutcome::Sent
        }

        fn open_blocking(&self) {}

        fn close_blocking(&self) {}

        fn tx_slot_acquire(&self, _want: usize, _priority: Priority) -> Option<TxSlotGrant> {
            if self.lent.swap(true, Ordering::SeqCst) {
                return None;
            }
            Some(TxSlotGrant {
                slot: TxSlot(0),
                headroom: 0,
            })
        }

        fn tx_slot_storage(&self, _slot: TxSlot) -> (*mut u8, usize) {
            let mut slot = self.slot.lock().expect("the slot");
            (slot.as_mut_ptr(), slot.len())
        }

        fn tx_slot_send(
            &self,
            _slot: TxSlot,
            start: usize,
            len: usize,
            _reliability: Reliability,
            _priority: Priority,
        ) -> LinkSendOutcome {
            let written = self.slot.lock().expect("the slot")[start..start + len].to_vec();
            self.sent.lock().expect("the sends").push(written);
            self.lent.store(false, Ordering::SeqCst);
            LinkSendOutcome::Sent
        }

        fn tx_slot_abort(&self, _slot: TxSlot) {
            self.lent.store(false, Ordering::SeqCst);
        }
    }

    #[test]
    fn a_close_with_no_slot_free_sends_the_open_data_batch_before_it() {
        let link = Arc::new(OneSlotLink {
            lent: AtomicBool::new(false),
            slot: Mutex::new(alloc::vec![0; 2048]),
            sent: Mutex::new(Vec::new()),
        });
        let sink: Arc<dyn BoxedLinkDriver + Send + Sync> = link.clone();
        let actions =
            SessionLinkActions::<PlainRuntime, StillClock>::new_generic(sink, params(), StillClock)
                .expect("the heap has room");
        actions.enter_established();
        assert_eq!(actions.batch_start(), Ok(()));
        let key = crate::named_key::NamedKey::literal("home/order").expect("a key");
        let put = actions.send_plain_put_qos(
            key,
            b"v",
            None,
            super::super::SendAs {
                reliable: true,
                express: false,
                priority: Priority::DEFAULT,
            },
        );
        assert_eq!(put, Some(Ok(())));
        assert!(
            link.sent.lock().expect("the sends").is_empty(),
            "CONTROL: the put waits in the window's slot"
        );
        assert!(
            link.lent.load(Ordering::SeqCst),
            "CONTROL: which is the link's one slot, out"
        );

        assert_eq!(actions.send_close_lent(0x02), Ok(()));
        let sent = link.sent.lock().expect("the sends");
        assert_eq!(sent.len(), 2, "the batch, then the Close");
        assert_eq!(
            sent[0][0] & 0x1F,
            wz_codecs::wire_const::T_MID_FRAME,
            "the data first"
        );
        assert_eq!(
            sent[1][0] & 0x1F,
            wz_codecs::wire_const::T_MID_CLOSE,
            "the Close behind it"
        );
        assert_eq!(actions.tx_refusals().no_slot, 0, "nothing was refused");
    }
}

/// Under `tx-lend-only` a window's messages are written into the frame their conduit holds open
/// in a lent slot: messages of one reliability share the frame, one of the other reliability sends
/// it and opens the next, and one the frame has no room left for sends it once and is written whole
/// into the next.
#[cfg(all(
    feature = "tx-lend-only",
    feature = "transport-batching",
    feature = "codec-push",
    feature = "alloc"
))]
mod lent_window {
    use alloc::sync::Arc;
    use alloc::vec::Vec;
    use core::sync::atomic::{AtomicBool, Ordering};
    use std::sync::Mutex;

    use super::{params, PlainRuntime, StillClock};
    use crate::link::{BoxedLinkDriver, LinkSendOutcome, TxSlot, TxSlotGrant};
    use crate::qos::Priority;
    use crate::reliability::Reliability;
    use crate::send_wire_error::SendWireError;
    use crate::session_actions::SessionLinkActions;

    /// A link of one slot wider than the batch, lent to one holder at a time, that keeps each
    /// frame sent.
    struct OneSlotLink {
        lent: AtomicBool,
        slot: Mutex<Vec<u8>>,
        sent: Mutex<Vec<Vec<u8>>>,
    }

    impl BoxedLinkDriver for OneSlotLink {
        fn send_blocking(&self, _bytes: &[u8], _reliability: Reliability) -> LinkSendOutcome {
            LinkSendOutcome::Sent
        }

        fn open_blocking(&self) {}

        fn close_blocking(&self) {}

        fn tx_slot_acquire(&self, _want: usize, _priority: Priority) -> Option<TxSlotGrant> {
            if self.lent.swap(true, Ordering::SeqCst) {
                return None;
            }
            Some(TxSlotGrant {
                slot: TxSlot(0),
                headroom: 0,
            })
        }

        fn tx_slot_storage(&self, _slot: TxSlot) -> (*mut u8, usize) {
            let mut slot = self.slot.lock().expect("the slot");
            (slot.as_mut_ptr(), slot.len())
        }

        fn tx_slot_send(
            &self,
            _slot: TxSlot,
            start: usize,
            len: usize,
            _reliability: Reliability,
            _priority: Priority,
        ) -> LinkSendOutcome {
            let written = self.slot.lock().expect("the slot")[start..start + len].to_vec();
            self.sent.lock().expect("the sends").push(written);
            self.lent.store(false, Ordering::SeqCst);
            LinkSendOutcome::Sent
        }

        fn tx_slot_abort(&self, _slot: TxSlot) {
            self.lent.store(false, Ordering::SeqCst);
        }
    }

    /// An established session over a fresh [`OneSlotLink`] with its window open, and the link.
    fn windowed() -> (
        Arc<SessionLinkActions<PlainRuntime, StillClock>>,
        Arc<OneSlotLink>,
    ) {
        let link = Arc::new(OneSlotLink {
            lent: AtomicBool::new(false),
            slot: Mutex::new(alloc::vec![0; 2048]),
            sent: Mutex::new(Vec::new()),
        });
        let sink: Arc<dyn BoxedLinkDriver + Send + Sync> = link.clone();
        let actions =
            SessionLinkActions::<PlainRuntime, StillClock>::new_generic(sink, params(), StillClock)
                .expect("the heap has room");
        actions.enter_established();
        assert_eq!(actions.batch_start(), Ok(()));
        (actions, link)
    }

    /// A plain put of `value` on `actions`, reliable or best effort.
    fn put(
        actions: &SessionLinkActions<PlainRuntime, StillClock>,
        value: &[u8],
        reliable: bool,
    ) -> Option<Result<(), SendWireError>> {
        let key = crate::named_key::NamedKey::literal("home/window").expect("a key");
        actions.send_plain_put_qos(
            key,
            value,
            None,
            super::super::SendAs {
                reliable,
                express: false,
                priority: Priority::DEFAULT,
            },
        )
    }

    /// Two reliable puts share the window's frame, and a best-effort put sends that frame and
    /// opens one of its own. Turned red by `write_n_msg` not comparing the open frame's
    /// reliability (its `open_channel == reliability` taken as true), whose best-effort put rides the reliable frame, or by a window's opening that
    /// does not keep its frame open (`write_n_msg` sending the slot it should keep), whose first
    /// put leaves alone.
    #[test]
    fn puts_of_one_reliability_share_a_frame_and_the_other_opens_its_own() {
        let (actions, link) = windowed();
        assert_eq!(put(&actions, b"v", true), Some(Ok(())));
        assert_eq!(put(&actions, b"v", true), Some(Ok(())));
        assert!(
            link.sent.lock().expect("the sends").is_empty(),
            "both wait in the window's frame"
        );
        assert_eq!(put(&actions, b"v", false), Some(Ok(())));
        assert_eq!(
            link.sent.lock().expect("the sends").len(),
            1,
            "the reliable frame left when the best-effort put came"
        );
        assert_eq!(actions.batch_flush(), Ok(()));
        // A frame of one reliable put, for its length.
        assert_eq!(put(&actions, b"v", true), Some(Ok(())));
        assert_eq!(actions.batch_flush(), Ok(()));
        let sent = link.sent.lock().expect("the sends");
        assert_eq!(
            sent.len(),
            3,
            "the two frames of the window, then the one of a put"
        );
        assert_eq!(
            crate::frame_encode::frame_wire_reliability(&sent[0]),
            Reliability::Reliable
        );
        assert_eq!(
            crate::frame_encode::frame_wire_reliability(&sent[1]),
            Reliability::BestEffort
        );
        // A frame is its header byte, its SN (one byte below 128) and its messages.
        assert_eq!(
            sent[0].len() - 2,
            2 * (sent[2].len() - 2),
            "the window's reliable frame holds two puts"
        );
    }

    /// A put the window's frame has no room left for sends that frame once and is written whole
    /// into the next. Turned red by an append that answers a put it did not write as written
    /// (`write_n_msg` keeping the frame after its encoder was refused), whose second put is
    /// lost, or by an overflow that does not send the open frame, whose second put finds no slot.
    #[test]
    fn a_put_the_open_frame_has_no_room_for_sends_it_once_and_opens_the_next() {
        let (actions, link) = windowed();
        let (budget, _) = actions
            .negotiated_tx_limits_for(Reliability::Reliable)
            .expect("the limits are settled at establishment");
        // One such put fits a frame and two do not.
        let value = alloc::vec![0x5a; budget * 3 / 5];
        assert_eq!(put(&actions, &value, true), Some(Ok(())));
        assert!(
            link.sent.lock().expect("the sends").is_empty(),
            "the first put waits in the window"
        );
        assert_eq!(put(&actions, &value, true), Some(Ok(())));
        assert_eq!(
            link.sent.lock().expect("the sends").len(),
            1,
            "the full frame left once"
        );
        assert_eq!(actions.batch_flush(), Ok(()));
        let sent = link.sent.lock().expect("the sends");
        assert_eq!(sent.len(), 2, "a frame for each put");
        assert_eq!(sent[0].len(), sent[1].len(), "each holds one whole put");
        assert!(sent[0].len() <= budget, "within the budget");
        assert_eq!(
            (sent[0][1], sent[1][1]),
            (0, 1),
            "the frames take SNs 0 and 1"
        );
        assert_eq!(actions.tx_refusals().no_slot, 0, "nothing was refused");
    }
}

#[cfg(all(
    not(feature = "tx-lend-only"),
    feature = "transport-batching",
    feature = "transport-tx-lend",
    feature = "codec-push",
    feature = "alloc"
))]
mod heap_window {
    use alloc::sync::Arc;
    use alloc::vec::Vec;
    use core::sync::atomic::{AtomicBool, Ordering};
    use std::sync::Mutex;

    use super::{params, PlainRuntime, StillClock};
    use crate::link::{BoxedLinkDriver, LinkSendOutcome, TxSlot, TxSlotGrant};
    use crate::qos::Priority;
    use crate::reliability::Reliability;
    use crate::send_wire_error::SendWireError;
    use crate::session_actions::SessionLinkActions;

    /// A link that lends one slot far shorter than the batch, and keeps each frame written to it
    /// from the heap and each slot it was handed.
    struct ShortSlotLink {
        lent: AtomicBool,
        slot: Mutex<Vec<u8>>,
        written: Mutex<Vec<Vec<u8>>>,
        slots_sent: Mutex<usize>,
    }

    impl BoxedLinkDriver for ShortSlotLink {
        fn send_blocking(&self, bytes: &[u8], _reliability: Reliability) -> LinkSendOutcome {
            self.written
                .lock()
                .expect("the writes")
                .push(bytes.to_vec());
            LinkSendOutcome::Sent
        }

        fn open_blocking(&self) {}

        fn close_blocking(&self) {}

        fn tx_slot_acquire(&self, _want: usize, _priority: Priority) -> Option<TxSlotGrant> {
            if self.lent.swap(true, Ordering::SeqCst) {
                return None;
            }
            Some(TxSlotGrant {
                slot: TxSlot(0),
                headroom: 0,
            })
        }

        fn tx_slot_storage(&self, _slot: TxSlot) -> (*mut u8, usize) {
            let mut slot = self.slot.lock().expect("the slot");
            (slot.as_mut_ptr(), slot.len())
        }

        fn tx_slot_send(
            &self,
            _slot: TxSlot,
            _start: usize,
            _len: usize,
            _reliability: Reliability,
            _priority: Priority,
        ) -> LinkSendOutcome {
            *self.slots_sent.lock().expect("the slot sends") += 1;
            self.lent.store(false, Ordering::SeqCst);
            LinkSendOutcome::Sent
        }

        fn tx_slot_abort(&self, _slot: TxSlot) {
            self.lent.store(false, Ordering::SeqCst);
        }
    }

    /// A plain put of `value` on `actions`, reliable or best effort.
    fn put(
        actions: &SessionLinkActions<PlainRuntime, StillClock>,
        value: &[u8],
        reliable: bool,
    ) -> Option<Result<(), SendWireError>> {
        let key = crate::named_key::NamedKey::literal("home/heap").expect("a key");
        actions.send_plain_put_qos(
            key,
            value,
            None,
            super::super::SendAs {
                reliable,
                express: false,
                priority: Priority::DEFAULT,
            },
        )
    }

    /// A window's frame the link lends no whole-batch slot for is staged on the heap, counted as
    /// a short slot, and the next put of its reliability joins it there without a slot asked; a
    /// best-effort put sends it once and opens its own. Turned red by `write_n_msg`'s heap arm not
    /// comparing the open frame's R flag (the best-effort put joins the reliable frame and
    /// nothing is written before the flush), by that arm skipped (the second put opens a frame of
    /// its own and the first leaves alone), or by the short slot counted as no slot (its
    /// `heap_why = HeapStage::ShortSlot` taken out).
    #[test]
    fn a_window_frame_no_whole_slot_holds_is_staged_and_joined_on_the_heap() {
        let link = Arc::new(ShortSlotLink {
            lent: AtomicBool::new(false),
            slot: Mutex::new(alloc::vec![0; 16]),
            written: Mutex::new(Vec::new()),
            slots_sent: Mutex::new(0),
        });
        let sink: Arc<dyn BoxedLinkDriver + Send + Sync> = link.clone();
        let actions =
            SessionLinkActions::<PlainRuntime, StillClock>::new_generic(sink, params(), StillClock)
                .expect("the heap has room");
        actions.enter_established();
        assert_eq!(actions.batch_start(), Ok(()));
        assert_eq!(put(&actions, b"v", true), Some(Ok(())));
        assert_eq!(put(&actions, b"v", true), Some(Ok(())));
        assert!(
            link.written.lock().expect("the writes").is_empty(),
            "both wait in the window's heap frame"
        );
        let counts = actions.batch_lend_counts();
        assert_eq!(
            (
                counts.heap_short_slot,
                counts.heap_no_slot,
                counts.slot_frames
            ),
            (1, 0, 0),
            "one frame opened, on the heap, for a short slot"
        );
        assert_eq!(put(&actions, b"v", false), Some(Ok(())));
        assert_eq!(
            link.written.lock().expect("the writes").len(),
            1,
            "the reliable frame left when the best-effort put came"
        );
        assert_eq!(actions.batch_flush(), Ok(()));
        let written = link.written.lock().expect("the writes");
        assert_eq!(written.len(), 2, "the two frames of the window");
        assert_eq!(
            crate::frame_encode::frame_wire_reliability(&written[0]),
            Reliability::Reliable
        );
        assert_eq!(
            crate::frame_encode::frame_wire_reliability(&written[1]),
            Reliability::BestEffort
        );
        drop(written);
        // A frame of one reliable put, for its length.
        assert_eq!(put(&actions, b"v", true), Some(Ok(())));
        assert_eq!(actions.batch_flush(), Ok(()));
        let written = link.written.lock().expect("the writes");
        assert_eq!(written.len(), 3, "and the frame of one put");
        assert_eq!(
            written[1].len(),
            written[2].len(),
            "a frame of one put is as long whatever its reliability"
        );
        assert!(
            written[0].len() > written[2].len(),
            "the window's reliable frame holds more than one put"
        );
        assert_eq!(
            *link.slots_sent.lock().expect("the slot sends"),
            0,
            "no slot was sent"
        );
        assert!(
            !link.lent.load(Ordering::SeqCst),
            "every short slot went back"
        );
        assert_eq!(actions.batch_lend_counts().heap_short_slot, 3);
    }
}

/// A plain put whose key is past its protocol bound is refused with the codec's error on the heap
/// path, and nothing reaches the link: the vector refuses no write, but the body refuses its
/// message, and the send answers that as a value.
#[cfg(all(feature = "codec-push", not(feature = "tx-lend-only")))]
#[test]
fn a_plain_put_past_its_key_bound_is_refused_and_not_sent() {
    let (actions, link) = established_bundle();
    let long = "k".repeat(usize::from(u16::MAX) + 1);
    let key = crate::named_key::NamedKey::literal(&long).expect("a key");
    let sent = actions.send_plain_put_qos(
        key,
        b"v",
        None,
        super::SendAs {
            reliable: true,
            express: false,
            priority: crate::qos::Priority::DEFAULT,
        },
    );
    assert_eq!(
        sent,
        Some(Err(crate::send_wire_error::SendWireError::Codec(
            sce_forge_runtime::codec::CodecError::LengthOutOfRange
        )))
    );
    assert_eq!(
        link.written.load(Ordering::SeqCst),
        0,
        "nothing was written"
    );
}

/// A staged reply leaves through the writer of its parts in a session that reads no owned reply (no
/// policy or namespace is installed here), whether the build counts its transports or not: one the
/// writer takes is written, and one it refuses is skipped with nothing built. The responder
/// identity of no bytes is the case the owned builder asserts against, so a refused reply that fell
/// back to the owned record would panic here.
///
/// Turned red by a `send_reply_parts` that sends a reply the writer refuses as an owned one.
#[cfg(all(feature = "codec-response", not(feature = "tx-lend-only")))]
mod staged_replies {
    use core::sync::atomic::Ordering;

    use super::established_bundle;
    use crate::reply_stage::{PartsBody, PartsKind, ReplyParts};
    use crate::response_sink::ResponseSink as _;
    use crate::sample::QosLevel;

    fn staged<'a>(keyexpr: &'a str, responder: Option<(&'a [u8], u32)>) -> ReplyParts<'a> {
        ReplyParts {
            rid: 5,
            keyexpr,
            responder,
            qos: QosLevel::DEFAULT,
            #[cfg(feature = "pubsub-ts-stack")]
            ts_stack: None,
            kind: PartsKind::Reply {
                body: PartsBody::Put(b"answer"),
                encoding: None,
                timestamp: None,
                attachment: None,
                source_info: None,
            },
        }
    }

    #[test]
    fn a_staged_reply_the_writer_refuses_is_skipped_and_one_it_takes_is_written() {
        let (actions, link) = established_bundle();
        actions.send_reply_parts(staged("demo/asked", Some((&[], 1))));
        actions.send_reply_parts(staged("", None));
        assert_eq!(
            link.written.load(Ordering::SeqCst),
            0,
            "nothing of a refused reply reaches the link"
        );
        actions.send_reply_parts(staged("demo/asked", Some((&[1, 2, 3, 4], 5))));
        assert_ne!(
            link.written.load(Ordering::SeqCst),
            0,
            "CONTROL: a reply the writer takes is written"
        );
    }

    /// A staged reply written from its parts is counted once, as the owned reply of the same parts
    /// is counted by a session that sends that record: one network message, one reply in the space
    /// of the key it is stamped with, by its payload.
    ///
    /// Turned red by a `send_reply_parts` that hands its dispatch no class
    /// (`NetworkStatsClass::unread` there), or by a class of the parts that reads another space or
    /// another payload than the owned reply's (`network_message::reply_parts_stats_class`).
    #[cfg(feature = "transport-stats")]
    #[test]
    fn a_staged_reply_is_counted_once_as_its_owned_reply_is() {
        use super::counted_as;
        use crate::stats::{StatMessage, StatSpace};
        for (keyexpr, space) in [
            ("demo/asked", StatSpace::User),
            ("@/demo/asked", StatSpace::Admin),
        ] {
            let parts = staged(keyexpr, Some((&[1, 2, 3, 4], 5)));
            let lent = counted_as(StatMessage::Reply, space, |actions| {
                actions.send_reply_parts(parts);
            });
            let owned = counted_as(StatMessage::Reply, space, |actions| {
                let response = crate::query::QueryReply::from_parts(&parts)
                    .into_response()
                    .expect("the owned reply");
                actions.send_response(response);
            });
            assert_eq!(lent, owned, "{keyexpr}: counted as its owned reply is");
            assert_eq!(
                lent,
                (1, 1, b"answer".len()),
                "{keyexpr}: one reply in its key's space, by its payload"
            );
        }
    }
}

/// A get written from its parts is counted once, as the owned `Request` of the same parts is
/// counted by a session that sends that message: one network message, one query in the space of
/// its key, by the payload of its value and its attachment as far as the build writes them.
///
/// Turned red by a `send_get_parts` that hands its dispatch no class (`NetworkStatsClass::unread`
/// there), or by a get class that reads a declared key's space from another table than the owned
/// send resolves it through (`SessionLinkActions::with_outbound_mapping`).
#[cfg(all(
    feature = "transport-stats",
    feature = "codec-request",
    feature = "storage-profile",
    not(feature = "tx-lend-only")
))]
mod counted_gets {
    use super::{counted_as, PlainRuntime, StillClock};
    use crate::query_parts::{GetParts, QueryParts};
    use crate::reply_stage::EncodingParts;
    use crate::session_actions::SessionLinkActions;
    use crate::stats::{StatMessage, StatSpace};
    use crate::wire_key::WireKey;

    /// What `parts` adds to the counters of a session that sends them as they are and of one that
    /// sends their owned `Request`, each prepared by `prepare` first.
    fn both_ways(
        parts: GetParts<'_>,
        space: StatSpace,
        prepare: impl Fn(&SessionLinkActions<PlainRuntime, StillClock>),
    ) -> [(usize, usize, usize); 2] {
        let lent = counted_as(StatMessage::Query, space, |actions| {
            prepare(actions);
            assert_eq!(actions.send_get_parts(parts), Ok(()), "{parts:?}");
        });
        let owned = counted_as(StatMessage::Query, space, |actions| {
            prepare(actions);
            let request = parts.owned_request().expect("the owned request");
            assert_eq!(actions.dispatch_request(request, true), Ok(()), "{parts:?}");
        });
        [lent, owned]
    }

    #[test]
    fn a_get_sent_from_its_parts_is_counted_once_as_its_owned_request_is() {
        let query = QueryParts {
            value: Some((
                EncodingParts {
                    packed_id: 0,
                    schema: None,
                },
                b"payload".as_slice(),
            )),
            attachment: b"attached",
            ..QueryParts::PLAIN
        };
        // The value and the attachment count where the build writes them.
        let value = if cfg!(feature = "query-value") {
            "payload".len()
        } else {
            0
        };
        let attachment = if cfg!(feature = "query-attachment") {
            "attached".len()
        } else {
            0
        };
        for (key, space) in [
            (WireKey::literal("demo/asked"), StatSpace::User),
            (WireKey::literal("@/demo/asked"), StatSpace::Admin),
        ] {
            let parts = GetParts {
                rid: 3,
                key: key.expect("a literal"),
                query,
            };
            let [lent, owned] = both_ways(parts, space, |_| {});
            assert_eq!(lent, owned, "{parts:?}: counted as its owned Request is");
            assert_eq!(
                lent,
                (1, 1, value + attachment),
                "{parts:?}: one query in its key's space, by its payload"
            );
        }
    }

    /// A get whose key is named by a declaration of the session's own is counted in the space of
    /// the declared key, read where the declaration lies, as the owned send resolves it. A build
    /// whose session keeps its declarations off the link (`session-keeps-keyexprs`) resolves
    /// neither, and counts both in the user space.
    #[cfg(feature = "declare-keyexpr")]
    #[test]
    fn a_get_named_by_a_declaration_is_counted_in_the_declared_keys_space() {
        let parts = GetParts {
            rid: 3,
            key: WireKey::from_parts(5, Some("/asked")).expect("an id and a suffix"),
            query: QueryParts::PLAIN,
        };
        let space = if cfg!(feature = "session-keeps-keyexprs") {
            StatSpace::User
        } else {
            StatSpace::Admin
        };
        let [lent, owned] = both_ways(parts, space, |actions| {
            actions.with_facts(|facts| facts.own_keyexprs.sent_declaration(5, "@/demo"));
        });
        assert_eq!(lent, owned, "counted as its owned Request is");
        assert_eq!(lent, (1, 1, 0), "one query in the declared key's space");
    }
}

/// The session's facts are one row under one lock: what a door writes is what the whole row reads,
/// and a reopen empties the handshake's part of it and keeps what is not the handshake's.
mod facts_lock {
    use super::bundle;
    // The tests that count holds read an admitted Open (`codec-open-body`).
    #[cfg(feature = "codec-open-body")]
    use super::holds_in;

    #[test]
    fn a_fact_written_through_its_door_is_read_in_the_one_row() {
        let (actions, _link) = bundle();
        actions.fact_peer_whatami(|slot| *slot = Some(2));
        actions.fact_cookie_nonce(|slot| *slot = Some(7));
        let (whatami, nonce) =
            actions.with_facts(|facts| (facts.handshake.peer_whatami, facts.cookie_nonce));
        assert_eq!(whatami, Some(2), "the handshake's row");
        assert_eq!(nonce, Some(7), "the session's row");
    }

    #[cfg(feature = "session-reconnect")]
    #[test]
    fn a_reopen_empties_the_handshake_row_and_keeps_the_cookie_nonce() {
        let (actions, _link) = bundle();
        actions.fact_inbound_peer_zid(|slot| *slot = Some([0x0A; 4].into()));
        actions.fact_cookie_nonce(|slot| *slot = Some(7));
        actions.reset_for_reopen();
        let (zid, nonce) =
            actions.with_facts(|facts| (facts.handshake.inbound_peer_zid, facts.cookie_nonce));
        assert_eq!(zid, None, "a handshake fact is the transport's, and goes");
        assert_eq!(
            nonce,
            Some(7),
            "the nonce survives to be drawn over at the next InitAck"
        );
    }

    /// Every fact the closed transport's handshake took is cleared in the reopen's one hold,
    /// and the reopened link takes no data send, and holds no send limits, until it is
    /// established again.
    #[cfg(feature = "session-reconnect")]
    #[test]
    fn a_reopen_clears_every_handshake_fact_and_closes_the_data_send_gate() {
        let (actions, _link) = bundle();
        actions.fact_awaiting_open_ack(|slot| *slot = true);
        actions.fact_remote_peer_zid(|slot| *slot = Some([0x0B; 4].into()));
        actions.fact_peer_whatami(|slot| *slot = Some(1));
        actions.set_peer_init_caps(Some(crate::peer_init_caps::PeerInitCaps {
            seq_num_res: 2,
            req_id_res: 2,
            batch_size: 1024,
        }));
        actions.enter_established();
        assert!(actions.link.transport_available.is_open(), "established");
        #[cfg(feature = "codec-push")]
        assert!(
            actions.negotiated_tx_limits().is_some(),
            "the send limits are settled at establishment"
        );
        actions.reset_for_reopen();
        let (awaiting, zid, whatami, caps) = actions.with_facts(|facts| {
            (
                facts.handshake.awaiting_open_ack,
                facts.handshake.remote_peer_zid,
                facts.handshake.peer_whatami,
                facts.handshake.inbound_peer_init_caps,
            )
        });
        assert!(!awaiting, "no OpenAck is awaited before the next OpenSyn");
        assert_eq!(zid, None, "the routing zid is the closed transport's");
        assert_eq!(whatami, None, "the role is the closed transport's");
        assert_eq!(caps, None, "the capabilities are the closed transport's");
        assert!(
            !actions.link.transport_available.is_open(),
            "the reopened link waits for its establishment"
        );
        #[cfg(feature = "codec-push")]
        assert_eq!(
            actions.negotiated_tx_limits(),
            None,
            "the send limits are the closed transport's"
        );
    }

    /// A data send is refused until the link is established; once it is, the send leaves with
    /// the limits settled from the capabilities the handshake wrote, which a write after
    /// establishment does not move until the link is established again. Turned red by a gate
    /// open at construction, or by limits read from the capabilities at each send.
    #[cfg(all(feature = "codec-push", not(feature = "tx-lend-only")))]
    #[test]
    fn data_leaves_only_an_established_link_with_the_limits_it_was_established_with() {
        use crate::peer_init_caps::PeerInitCaps;
        use crate::send_wire_error::SendWireError;
        let caps = |batch_size| PeerInitCaps {
            seq_num_res: 2,
            req_id_res: 2,
            batch_size,
        };
        let (actions, link) = bundle();
        assert_eq!(
            actions.send_push_literal("a/b", b"x", true),
            Err(SendWireError::TransportUnavailable),
            "a send before establishment is refused"
        );
        assert_eq!(
            link.written.load(core::sync::atomic::Ordering::SeqCst),
            0,
            "and reaches no link"
        );
        assert_eq!(
            actions.negotiated_tx_limits(),
            None,
            "no limits are settled yet"
        );

        actions.set_peer_init_caps(Some(caps(512)));
        actions.enter_established();
        let settled = actions.negotiated_tx_limits();
        assert_eq!(
            settled,
            Some((
                actions.negotiated_batch_mtu() - actions.batch_envelope_bytes(),
                actions.negotiated_sn_mask()
            )),
            "settled from the capabilities the handshake wrote"
        );
        assert_eq!(actions.send_push_literal("a/b", b"x", true), Ok(()));

        actions.set_peer_init_caps(Some(caps(256)));
        assert_eq!(
            actions.negotiated_tx_limits(),
            settled,
            "a write after establishment waits for the next establishment"
        );
        actions.enter_established();
        assert_eq!(
            actions.negotiated_tx_limits().map(|(budget, _)| budget),
            Some(actions.negotiated_batch_mtu() - actions.batch_envelope_bytes()),
            "established again, the limits are the new capabilities'"
        );
        assert_ne!(actions.negotiated_tx_limits(), settled);
    }

    /// A link no handshake runs over takes a data send once it is opened without one, with the
    /// limits the session's own advertisement sets, and is not established. Turned red by a door
    /// that leaves the gate shut (the send refused), settles no limits (`None`), or stamps the
    /// establishment.
    #[cfg(all(feature = "codec-push", not(feature = "tx-lend-only")))]
    #[test]
    fn a_link_opened_without_a_handshake_sends_with_its_own_limits_unestablished() {
        let (actions, _link) = bundle();
        actions.open_without_handshake();
        let limits = actions
            .negotiated_tx_limits()
            .expect("opening without a handshake settles the limits");
        assert_eq!(
            limits,
            (
                actions.negotiated_batch_mtu() - actions.batch_envelope_bytes(),
                actions.negotiated_sn_mask()
            ),
            "settled from the session's own advertisement"
        );
        assert_ne!(limits.0, 0, "a frame has room");
        assert_eq!(actions.send_push_literal("a/b", b"x", true), Ok(()));
        assert!(!actions.is_established(), "no handshake ran");
    }

    /// An awaited OpenAck is admitted, ends the wait and takes the peer's lease and bound in one
    /// hold. Turned red by an admission that asks whether one is awaited, or writes the bound, in
    /// a hold of its own.
    #[cfg(feature = "codec-open-body")]
    #[test]
    fn an_admitted_open_ack_ends_the_wait_and_takes_the_lease() {
        use crate::extbound::{encode_remote_bound_ext, peer_remote_bound, Bound};
        use crate::session_actions::OpenAckAdmission;
        let (actions, _link) = bundle();
        actions.fact_awaiting_open_ack(|slot| *slot = true);
        let bound = peer_remote_bound(&[encode_remote_bound_ext(Bound::South)]);
        let mut admitted = None;
        let holds = holds_in(|| admitted = Some(actions.admit_open_ack(5, 10, bound)));
        assert_eq!(admitted, Some(OpenAckAdmission::Taken));
        assert_eq!(
            holds, 1,
            "the OpenAck is judged and taken in one hold of the facts"
        );
        let (awaiting, lease, bound) = actions.with_facts(|facts| {
            (
                facts.handshake.awaiting_open_ack,
                actions.fact_peer_open_lease_ms(|slot| *slot),
                facts.handshake.peer_remote_bound,
            )
        });
        assert!(!awaiting, "the one awaited OpenAck has been taken");
        assert_eq!(lease, Some(5), "the lease the OpenAck advertised");
        assert_eq!(bound, Some(Bound::South), "the bound the OpenAck announced");
    }

    /// An OpenAck no one awaits is dropped and takes nothing, whatever it carries: the wait, the
    /// lease and the bound stay as they were.
    #[cfg(feature = "codec-open-body")]
    #[test]
    fn an_open_ack_no_one_awaits_takes_nothing() {
        use crate::extbound::{encode_remote_bound_ext, peer_remote_bound, Bound};
        use crate::session_actions::OpenAckAdmission;
        let (actions, _link) = bundle();
        let bound = peer_remote_bound(&[encode_remote_bound_ext(Bound::South)]);
        assert_eq!(
            actions.admit_open_ack(5, 10, bound),
            OpenAckAdmission::NotAwaited
        );
        let (awaiting, lease, bound) = actions.with_facts(|facts| {
            (
                facts.handshake.awaiting_open_ack,
                actions.fact_peer_open_lease_ms(|slot| *slot),
                facts.handshake.peer_remote_bound,
            )
        });
        assert!(!awaiting, "nothing was awaited, and nothing is now");
        assert_eq!(lease, None, "an OpenAck not awaited adopts no lease");
        assert_eq!(bound, None, "an OpenAck not awaited writes no bound");
    }

    /// An awaited OpenAck whose remote bound is present and invalid refuses the handshake and
    /// takes nothing: it is still awaited, and neither its lease nor a bound is written.
    #[cfg(feature = "codec-open-body")]
    #[test]
    fn an_awaited_open_ack_with_an_invalid_bound_takes_nothing() {
        use crate::extbound::{peer_remote_bound, InvalidBound, REMOTE_BOUND_EXT_HEADER};
        use crate::session_actions::OpenAckAdmission;
        use crate::transport_profile::{ExtEntryOwned, ExtEntryOwnedVariant};
        let (actions, _link) = bundle();
        actions.fact_awaiting_open_ack(|slot| *slot = true);
        let invalid = [ExtEntryOwned {
            header: REMOTE_BOUND_EXT_HEADER,
            body: ExtEntryOwnedVariant::CodecZenohExtZint(wz_codecs::ext_zint::ExtZint {
                value: 2,
            }),
        }];
        let bound = peer_remote_bound(&invalid);
        assert_eq!(bound, Err(InvalidBound(2)), "a bound of 2 is neither bound");
        assert_eq!(
            actions.admit_open_ack(5, 10, bound),
            OpenAckAdmission::BoundRefused
        );
        let (awaiting, lease, bound) = actions.with_facts(|facts| {
            (
                facts.handshake.awaiting_open_ack,
                actions.fact_peer_open_lease_ms(|slot| *slot),
                facts.handshake.peer_remote_bound,
            )
        });
        assert!(awaiting, "a refused OpenAck ends no wait");
        assert_eq!(lease, None, "a refused OpenAck adopts no lease");
        assert_eq!(bound, None, "a refused bound is not written");
    }

    /// The chain-boundary markers are read off the negotiated patch level: none before an Init
    /// set one, and the level that has them once it is negotiated.
    #[test]
    fn the_fragment_markers_follow_the_negotiated_patch() {
        let (actions, _link) = bundle();
        assert!(
            !actions.fragmentation_markers_negotiated(),
            "no level negotiated reads as no markers"
        );
        actions.fact_negotiated_patch(|slot| *slot = Some(crate::extpatch::NO_PATCH));
        assert!(
            !actions.with_facts(|facts| facts.handshake.fragmentation_markers()),
            "a peer at no patch level marks no chain"
        );
        actions.fact_negotiated_patch(|slot| *slot = Some(u8::MAX));
        assert!(
            actions.with_facts(|facts| facts.handshake.fragmentation_markers()),
            "a level past the markers' marks its chains"
        );
        assert!(actions.fragmentation_markers_negotiated());
    }

    /// The Open's origin is derived from the ring and the peer's zid read in one hold of the facts,
    /// and is none before the peer's zid is known.
    #[cfg(all(feature = "alloc", feature = "codec-open-body"))]
    #[test]
    fn the_open_origin_reads_the_ring_and_the_zid_in_one_hold() {
        let (actions, _link) = bundle();
        assert_eq!(actions.open_initial_sn(), None, "no peer zid, no origin");
        let peer = [0x0C; 4];
        actions.fact_remote_peer_zid(|slot| *slot = Some(peer.into()));
        let mut origin = None;
        let holds = holds_in(|| origin = actions.open_initial_sn());
        assert_eq!(holds, 1, "the ring and the zid are read in one hold");
        let mask = actions.negotiated_sn_mask();
        assert_eq!(
            origin,
            Some(crate::initial_sn::derive_initial_sn(
                &actions.params.zid,
                &peer,
                mask
            ))
        );
    }

    /// An admitted OpenSyn spends the nonce that admitted it and takes the peer's lease.
    #[cfg(all(feature = "codec-open-body", feature = "session-unicast-accept"))]
    #[test]
    fn an_admitted_open_syn_spends_the_nonce_and_takes_the_lease() {
        let (actions, _link) = bundle();
        actions.fact_cookie_nonce(|slot| *slot = Some(7));
        actions.admit_open_syn(5, 10);
        let (nonce, lease) = (
            actions.fact_cookie_nonce(|slot| *slot),
            actions.fact_peer_open_lease_ms(|slot| *slot),
        );
        assert_eq!(nonce, None, "a spent nonce admits no replay");
        assert_eq!(lease, Some(5), "the lease the OpenSyn advertised");
    }

    /// An Init whose region does not read is refused before its patch is taken; one whose region
    /// reads writes the region and caps the patch at the peer's level.
    #[cfg(all(
        feature = "codec-init-body",
        any(
            feature = "alloc",
            all(feature = "codec-frame", feature = "session-slot")
        )
    ))]
    #[test]
    fn an_init_whose_region_does_not_read_takes_no_patch() {
        let (actions, _link) = bundle();
        let earlier = crate::extregion::RegionName::new("south").expect("a valid region name");
        actions.fact_peer_region(|slot| *slot = Some(earlier));
        assert!(
            !actions.admit_init_region_and_patch(Err(crate::extregion::RegionNameError::Empty), 0),
            "a region that does not read refuses the Init"
        );
        assert_eq!(
            actions.fact_negotiated_patch(|slot| *slot),
            None,
            "a refused Init merges no patch"
        );
        assert!(
            actions.fact_peer_region(|slot| slot.is_some()),
            "a refused Init writes no region"
        );
        assert!(
            actions.admit_init_region_and_patch(Ok(None), 0),
            "a peer that announces no region is admitted"
        );
        let (region_none, patch) = actions.with_facts(|facts| {
            (
                facts.handshake.peer_region.is_none(),
                facts.handshake.negotiated_patch,
            )
        });
        assert!(
            region_none,
            "the region is what the admitted Init announced"
        );
        assert_eq!(patch, Some(0), "the patch is capped at the peer's level");
    }
}

/// The send budget is the least of the session's own advertisement, the link's bound and the
/// batch the peer advertised, and a peer not heard from bounds nothing.
mod batch_budget {
    use super::bundle;
    use crate::peer_init_caps::PeerInitCaps;

    fn caps(batch_size: u16) -> Option<PeerInitCaps> {
        Some(PeerInitCaps {
            seq_num_res: 2,
            req_id_res: 2,
            batch_size,
        })
    }

    /// Turned red by a peer not heard from read as a bound of zero, or by a peer's bound left
    /// out of the least.
    #[test]
    fn the_budget_is_the_least_bound_and_an_unheard_peer_bounds_nothing() {
        let (actions, _link) = bundle();
        let unheard = actions.negotiated_batch_mtu();
        assert_ne!(unheard, 0, "a peer not heard from bounds nothing");
        assert!(unheard <= usize::from(actions.own_batch_advertisement()));
        actions.set_peer_init_caps(caps(u16::MAX));
        assert_eq!(
            actions.negotiated_batch_mtu(),
            unheard,
            "a peer above both bounds moves nothing"
        );
        let below = u16::try_from(unheard - 1).expect("the own bound is a u16");
        actions.set_peer_init_caps(caps(below));
        assert_eq!(
            actions.negotiated_batch_mtu(),
            usize::from(below),
            "a peer below both bounds is the budget"
        );
    }
}

/// A link's time stamps are words of their own, read under no lock: what a door writes is what the
/// row reads, the deadlines read the stamps they compare only while their duty is armed, a tick
/// ends once, and a reopen clears all three.
mod link_stamps {
    use super::{bundle, holds_in};
    use crate::session_actions::LinkStamps;

    /// Turned red by a door that writes another stamp than it names, or by a read of the row
    /// that takes a lock.
    #[test]
    fn a_stamp_written_through_its_door_is_read_in_the_row_under_no_lock() {
        let (actions, _link) = bundle();
        actions.link.fact_established_at(|slot| *slot = Some(1));
        actions.link.fact_last_inbound_at(|slot| *slot = Some(2));
        actions.link.fact_keepalive_tick_at(|slot| *slot = Some(3));
        let mut stamps = LinkStamps::default();
        let holds = holds_in(|| stamps = actions.link.stamps());
        assert_eq!(holds, 0, "the row is read under no lock");
        assert_eq!(
            stamps,
            LinkStamps {
                established_at: Some(1),
                last_inbound_at: Some(2),
                keepalive_tick_at: Some(3),
            }
        );
    }

    /// The lease deadline counts from the later of the establishment and the last receipt, and
    /// reads them under no lock; the one hold is the peer's lease. Turned red by a deadline that
    /// takes a lock to read a stamp.
    #[test]
    fn the_lease_deadline_reads_its_two_stamps_under_no_lock() {
        let (actions, _link) = bundle();
        actions
            .link
            .lease_armed
            .store(true, core::sync::atomic::Ordering::SeqCst);
        actions.link.fact_established_at(|slot| *slot = Some(100));
        actions.link.fact_last_inbound_at(|slot| *slot = Some(250));
        let lease = actions.adopted_lease_ms();
        let mut deadline = None;
        let holds = holds_in(|| deadline = crate::drive::lease_wake_deadline(&*actions));
        assert_eq!(
            deadline,
            Some(250 + 1 + lease),
            "the later stamp is the baseline, counted from the end of its millisecond"
        );
        assert_eq!(
            holds, 0,
            "the stamps and the peer's lease are read under no lock"
        );
    }

    /// A receipt stamped anywhere in the millisecond its reading names has the lease expire no
    /// sooner than a whole lease after the latest instant of that millisecond, and at most a
    /// millisecond after it. Turned red by a deadline counted from the stamp itself, which
    /// expires up to a millisecond before the lease has passed.
    #[test]
    fn the_lease_never_expires_before_it_has_passed_since_the_receipt() {
        let (actions, _link) = bundle();
        actions
            .link
            .lease_armed
            .store(true, core::sync::atomic::Ordering::SeqCst);
        let stamp_ms: u64 = 4_000;
        actions
            .link
            .fact_last_inbound_at(|slot| *slot = Some(stamp_ms));
        let lease = actions.adopted_lease_ms();
        let deadline = crate::drive::lease_wake_deadline(&*actions).expect("a lease deadline");
        // In microseconds: the latest instant the stamp can stand for, and the earliest a reading
        // of the deadline can be made at.
        let latest_receipt_us = stamp_ms * 1_000 + 999;
        assert!(
            deadline * 1_000 >= latest_receipt_us + lease * 1_000,
            "the lease expires at {deadline}, before {lease} ms have passed since a receipt late \
             in the millisecond {stamp_ms}"
        );
        assert_eq!(deadline, stamp_ms + 1 + lease, "and no later than it must");
    }

    /// The watch of the peer's initial declarations counts from the establishment stamp the lease
    /// read, so a running watch adds no hold of the stamps. Turned red by a watch that reads the
    /// stamps again.
    #[cfg(feature = "alloc")]
    #[test]
    fn the_declaration_watch_reads_the_stamps_the_lease_read() {
        let (actions, _link) = bundle();
        actions
            .link
            .lease_armed
            .store(true, core::sync::atomic::Ordering::SeqCst);
        actions.link.fact_established_at(|slot| *slot = Some(100));
        // A first event noted: the watch runs from the establishment.
        actions
            .peer_declaration_progress_ms
            .store(0, core::sync::atomic::Ordering::Release);
        let expiry = 100 + 1 + actions.adopted_lease_ms();
        let watch = actions.declaration_watch_deadline();
        let mut deadline = None;
        let holds = holds_in(|| deadline = crate::drive::lease_wake_deadline(&*actions));
        assert_eq!(
            deadline,
            Some(watch.map_or(expiry, |watch| watch.min(expiry))),
            "the earlier of the expiry and the watch"
        );
        assert_eq!(
            holds, 0,
            "the stamps and the peer's lease are read under no lock"
        );
    }

    /// A due lease is judged by the deadlines its wake was read from: the stamps and the peer's
    /// lease are read once, and the expiry is what the driver is told. Turned red by timers that
    /// read the deadlines again to judge them, or that judge a lease before it is due.
    #[test]
    fn a_due_lease_is_judged_by_the_deadlines_its_wake_read() {
        use crate::driver_loop::IterationEvent;
        use crate::lease::LeaseCheckOutcome;
        use crate::session_timeouts::SessionTimeouts;
        use crate::transport_timers::TransportTimers;

        let (actions, _link) = bundle();
        let mut engine = crate::drive::new_session_engine::<super::PlainRuntime, super::StillClock>(
            &actions,
            super::NoEntropy,
        );
        engine.initialize().unwrap_or_else(|never| match never {});
        actions
            .link
            .lease_armed
            .store(true, core::sync::atomic::Ordering::SeqCst);
        actions.link.fact_established_at(|slot| *slot = Some(100));
        let expiry = 100 + 1 + actions.adopted_lease_ms();
        let mut timers = TransportTimers::new(SessionTimeouts::spec_defaults());
        let mut outcomes = alloc::vec::Vec::new();
        let mut sink = |event: IterationEvent<'_, '_>| {
            if let IterationEvent::Lease(outcome) = event {
                outcomes.push(outcome);
            }
        };
        timers.fire_due(&mut engine, &*actions, expiry - 1, &mut sink);
        let holds = holds_in(|| timers.fire_due(&mut engine, &*actions, expiry, &mut sink));
        assert_eq!(
            outcomes,
            [LeaseCheckOutcome::Expired],
            "nothing before the expiry, the expiry at it"
        );
        assert_eq!(
            holds, 0,
            "the stamps and the peer's lease are read under no lock"
        );
    }

    /// The bundle the timers are handed, and the machine over it.
    type Actions = super::SessionLinkActions<super::PlainRuntime, super::StillClock>;
    type Machine = crate::drive::SessionEngine<super::PlainRuntime, super::StillClock>;

    /// The session's machine over `actions`, entered in its initial state.
    fn machine(actions: &alloc::sync::Arc<Actions>) -> Machine {
        let mut engine = crate::drive::new_session_engine::<super::PlainRuntime, super::StillClock>(
            actions,
            super::NoEntropy,
        );
        engine.initialize().unwrap_or_else(|never| match never {});
        engine
    }

    /// The lease's checks a step of `timers` at `now_ms` raises.
    fn lease_checks(
        timers: &mut crate::transport_timers::TransportTimers,
        engine: &mut Machine,
        actions: &Actions,
        now_ms: u64,
    ) -> alloc::vec::Vec<crate::lease::LeaseCheckOutcome> {
        use crate::driver_loop::IterationEvent;
        let mut seen = alloc::vec::Vec::new();
        let mut sink = |event: IterationEvent<'_, '_>| {
            if let IterationEvent::Lease(outcome) = event {
                seen.push(outcome);
            }
        };
        timers.fire_due(engine, actions, now_ms, &mut sink);
        seen
    }

    /// Timers that read the deadlines keep them: a step before the first of them falls due reads
    /// no stamp and no lease. The stamps and the peer's lease are words, read under no lock, so
    /// what a step reads is told by what it judges: the lease is cut short after the first step
    /// through its door, which counts no move, and a step that read it again would judge the
    /// earlier expiry. Turned red by timers that read the deadlines at every step.
    #[test]
    fn a_step_before_the_deadlines_fall_due_reads_none_of_them() {
        use crate::lease::LeaseCheckOutcome;
        use crate::session_timeouts::SessionTimeouts;
        use crate::transport_timers::TransportTimers;

        let (actions, _link) = bundle();
        let mut engine = machine(&actions);
        actions
            .link
            .lease_armed
            .store(true, core::sync::atomic::Ordering::SeqCst);
        actions.link.fact_established_at(|slot| *slot = Some(100));
        assert!(
            101 < 100 + 1 + actions.adopted_lease_ms(),
            "CONTROL: 101 is before the expiry"
        );
        let mut timers = TransportTimers::new(SessionTimeouts::spec_defaults());
        assert!(
            lease_checks(&mut timers, &mut engine, &actions, 100).is_empty(),
            "CONTROL: nothing is due at the establishment"
        );
        let moved = actions.link.deadlines_moved();
        actions.fact_peer_open_lease_ms(|slot| *slot = Some(0));
        assert_eq!(
            actions.link.deadlines_moved(),
            moved,
            "CONTROL: the lease's door counts no move"
        );
        assert!(
            lease_checks(&mut timers, &mut engine, &actions, 101).is_empty(),
            "a step before the expiry it holds reads nothing and judges nothing"
        );
        let mut fresh = TransportTimers::new(SessionTimeouts::spec_defaults());
        assert_eq!(
            lease_checks(&mut fresh, &mut engine, &actions, 101),
            [LeaseCheckOutcome::Expired],
            "CONTROL: a step that reads the lease at 101 judges it expired"
        );
    }

    /// A receipt moves the lease's deadline later with one store and no count: the timers find the
    /// later deadline when the one they held comes, and judge the lease at the later one. Turned
    /// red by timers that judge the deadline they held without reading it again.
    #[test]
    fn a_receipt_moves_the_lease_later_and_the_timers_find_it_when_the_old_deadline_comes() {
        use crate::lease::LeaseCheckOutcome;
        use crate::session_timeouts::SessionTimeouts;
        use crate::transport_timers::TransportTimers;

        let (actions, _link) = bundle();
        let mut engine = machine(&actions);
        actions
            .link
            .lease_armed
            .store(true, core::sync::atomic::Ordering::SeqCst);
        actions.link.fact_established_at(|slot| *slot = Some(100));
        let lease = actions.adopted_lease_ms();
        let mut timers = TransportTimers::new(SessionTimeouts::spec_defaults());
        let mut step = |now_ms| lease_checks(&mut timers, &mut engine, &actions, now_ms);
        assert!(step(100).is_empty());
        let moved = actions.link.deadlines_moved();
        actions.link.note_received_at(250);
        assert_eq!(
            actions.link.deadlines_moved(),
            moved,
            "a receipt counts no move"
        );
        assert!(
            step(100 + 1 + lease).is_empty(),
            "the deadline held comes, and the lease read again runs on"
        );
        assert!(step(250 + lease).is_empty());
        assert_eq!(
            step(250 + 1 + lease),
            [LeaseCheckOutcome::Expired],
            "the lease ends a window after the end of the receipt's millisecond"
        );
    }

    /// A stamp changed through its door may bring a deadline earlier, so the timers read the
    /// deadlines again at the next step; a door only read counts nothing. Turned red by a door that
    /// counts no move when it changes its stamp (the earlier expiry missed), or one that counts a
    /// read.
    #[test]
    fn a_stamp_changed_through_its_door_has_the_timers_read_again() {
        use crate::lease::LeaseCheckOutcome;
        use crate::session_timeouts::SessionTimeouts;
        use crate::transport_timers::TransportTimers;

        let (actions, _link) = bundle();
        let mut engine = machine(&actions);
        actions
            .link
            .lease_armed
            .store(true, core::sync::atomic::Ordering::SeqCst);
        actions.link.fact_established_at(|slot| *slot = Some(900));
        let lease = actions.adopted_lease_ms();
        let mut timers = TransportTimers::new(SessionTimeouts::spec_defaults());
        let mut step = |now_ms| lease_checks(&mut timers, &mut engine, &actions, now_ms);
        assert!(step(900).is_empty());
        let moved = actions.link.deadlines_moved();
        let _ = actions.link.fact_established_at(|slot| *slot);
        assert_eq!(
            actions.link.deadlines_moved(),
            moved,
            "a door only read counts nothing"
        );
        actions.link.fact_established_at(|slot| *slot = Some(10));
        assert_ne!(
            actions.link.deadlines_moved(),
            moved,
            "a door written counts"
        );
        assert_eq!(
            step(10 + 1 + lease),
            [LeaseCheckOutcome::Expired],
            "the earlier expiry is judged at its time"
        );
    }

    /// A duty armed after the timers read the deadlines without it is read at the next step, though
    /// it was armed by a store that counts nothing. Turned red by timers that compare the count
    /// alone.
    #[test]
    fn a_duty_armed_after_a_read_has_the_timers_read_again() {
        use crate::lease::LeaseCheckOutcome;
        use crate::session_timeouts::SessionTimeouts;
        use crate::transport_timers::TransportTimers;

        let (actions, _link) = bundle();
        let mut engine = machine(&actions);
        actions.link.fact_established_at(|slot| *slot = Some(100));
        let lease = actions.adopted_lease_ms();
        let mut timers = TransportTimers::new(SessionTimeouts::spec_defaults());
        let mut step = |now_ms| lease_checks(&mut timers, &mut engine, &actions, now_ms);
        assert!(
            step(100).is_empty(),
            "CONTROL: no lease while the monitor is not running"
        );
        actions
            .link
            .lease_armed
            .store(true, core::sync::atomic::Ordering::SeqCst);
        assert_eq!(step(100 + 1 + lease), [LeaseCheckOutcome::Expired]);
    }

    /// The due a step is told is the one the timers hold, read again only where what it was read
    /// under changed: a stamp changed through its door is answered at once; a receipt, which
    /// moves the lease only later, leaves the held deadline answered, early and never late, until
    /// the check at it reads the later one; and after that check a lease cut short through its
    /// door, which counts no move, leaves the due the check read. The CONTROL is timers that read
    /// the lease now: they answer the earlier wake. Turned red by a wait that keeps its deadline
    /// across a door's move (the earlier expiry missed), by one that reads the stamps at every
    /// call (the receipt's expiry answered before the check), or by a due that reads the stamps
    /// and the clock at every step between checks.
    #[test]
    fn a_step_is_told_the_due_the_timers_hold() {
        use crate::session_timeouts::SessionTimeouts;
        use crate::transport_timers::TransportTimers;

        let (actions, _link) = bundle();
        let mut engine = machine(&actions);
        actions
            .link
            .lease_armed
            .store(true, core::sync::atomic::Ordering::SeqCst);
        actions.link.fact_established_at(|slot| *slot = Some(900));
        let lease = actions.adopted_lease_ms();
        assert!(900 < 10 + 1 + lease, "CONTROL: 900 is before either expiry");
        let mut timers = TransportTimers::new(SessionTimeouts::spec_defaults());
        assert_eq!(
            timers.next_due_ms(&engine, &*actions, 900),
            Some(900 + 1 + lease),
            "the expiry read"
        );
        actions.link.fact_established_at(|slot| *slot = Some(10));
        assert_eq!(
            timers.next_due_ms(&engine, &*actions, 900),
            Some(10 + 1 + lease),
            "a door's move is read at once"
        );
        actions.link.note_received_at(950);
        assert_eq!(
            timers.next_due_ms(&engine, &*actions, 901),
            Some(10 + 1 + lease),
            "a receipt leaves the held expiry"
        );
        assert!(
            lease_checks(&mut timers, &mut engine, &actions, 10 + 1 + lease).is_empty(),
            "the check at it reads the later one and judges nothing"
        );
        let held = Some(950 + 1 + lease);
        assert_eq!(
            timers.next_due_ms(&engine, &*actions, 10 + 1 + lease),
            held,
            "and the wait answers the later one"
        );
        actions.fact_peer_open_lease_ms(|slot| *slot = Some(0));
        let now = crate::drive::lease_wake_deadline(&*actions);
        assert_ne!(now, held, "CONTROL: the lease cut short wakes earlier");
        assert_eq!(
            timers.next_due_ms(&engine, &*actions, 10 + 1 + lease),
            held,
            "the step was told a due read anew"
        );
        let mut fresh = TransportTimers::new(SessionTimeouts::spec_defaults());
        assert_eq!(
            fresh.next_due_ms(&engine, &*actions, 10 + 1 + lease),
            now,
            "CONTROL: timers that read the lease now answer its earlier wake"
        );
    }

    /// A duty armed after a check is in the next step's due, though the store that armed it counts
    /// no move: the due a step is told is never later than the duty's own. The CONTROL is the due
    /// before the duty is armed: none. Turned red by a due that keeps what the last check read
    /// after a duty was armed.
    #[test]
    fn a_duty_armed_after_a_check_is_in_the_next_steps_due() {
        use crate::session_timeouts::SessionTimeouts;
        use crate::transport_timers::TransportTimers;

        let (actions, _link) = bundle();
        let mut engine = machine(&actions);
        actions.link.fact_established_at(|slot| *slot = Some(100));
        let mut timers = TransportTimers::new(SessionTimeouts::spec_defaults());
        assert!(lease_checks(&mut timers, &mut engine, &actions, 100).is_empty());
        assert_eq!(
            timers.next_due_ms(&engine, &*actions, 100),
            None,
            "CONTROL: nothing is armed"
        );
        actions
            .link
            .lease_armed
            .store(true, core::sync::atomic::Ordering::SeqCst);
        let wake = crate::drive::lease_wake_deadline(&*actions);
        assert!(wake.is_some(), "CONTROL: the armed lease has a wake");
        assert_eq!(
            timers.next_due_ms(&engine, &*actions, 100),
            wake,
            "the step kept the due read before the duty was armed"
        );
    }

    /// The first event of the peer's declarations begins their watch, which gives the lease a
    /// deadline it did not have, and counts a move; a later one moves the watch only later and
    /// counts nothing. Turned red by a first event that counts no move, or a later one that does.
    #[test]
    fn the_first_event_of_the_peers_declarations_counts_a_move() {
        use crate::driver_loop::IterationEvent;
        let (actions, _link) = bundle();
        let before = actions.link.deadlines_moved();
        actions.note_declaration_progress(IterationEvent::AppWake);
        let begun = actions.link.deadlines_moved();
        assert_ne!(begun, before, "the watch begun");
        actions.note_declaration_progress(IterationEvent::AppWake);
        assert_eq!(
            actions.link.deadlines_moved(),
            begun,
            "a later event moves the watch only later"
        );
    }

    /// The keepalive deadline counts from the later of the establishment and the tick's start, and
    /// reads them under no lock. Turned red by a deadline that takes a lock to read a stamp.
    #[cfg(feature = "transport-keepalive")]
    #[test]
    fn the_keepalive_deadline_reads_its_two_stamps_under_no_lock() {
        let (actions, _link) = bundle();
        actions
            .link
            .keepalive_armed
            .store(true, core::sync::atomic::Ordering::SeqCst);
        actions.link.fact_established_at(|slot| *slot = Some(300));
        actions
            .link
            .fact_keepalive_tick_at(|slot| *slot = Some(200));
        let interval = actions.keepalive_interval_ms();
        let mut deadline = None;
        let holds = holds_in(|| deadline = crate::drive::keepalive_wake_deadline(&*actions));
        assert_eq!(
            deadline,
            Some(300 + interval),
            "the later stamp is the baseline"
        );
        assert_eq!(
            holds, 0,
            "the stamps and the peer's lease are read under no lock"
        );
    }

    /// Every stamp is the closed transport's: a reopen clears the three, and lowers the lease
    /// duty that reads them. Turned red by a reopen that leaves one of them standing.
    #[cfg(feature = "session-reconnect")]
    #[test]
    fn a_reopen_clears_every_stamp() {
        let (actions, _link) = bundle();
        actions.link.fact_established_at(|slot| *slot = Some(1));
        actions.link.fact_last_inbound_at(|slot| *slot = Some(2));
        actions.link.fact_keepalive_tick_at(|slot| *slot = Some(3));
        actions
            .link
            .lease_armed
            .store(true, core::sync::atomic::Ordering::SeqCst);
        actions.reset_for_reopen();
        assert_eq!(actions.link.stamps(), LinkStamps::default());
        assert_eq!(
            actions.link.stamps_while(&actions.link.lease_armed),
            None,
            "the duty is lowered with them"
        );
    }

    /// A duty reads the stamps only while it is armed: lowered, it is answered with nothing,
    /// whatever the stamps hold. Turned red by a read that does not ask the duty's flag.
    #[test]
    fn a_duty_reads_the_stamps_only_while_it_is_armed() {
        let (actions, _link) = bundle();
        actions.link.fact_established_at(|slot| *slot = Some(7));
        let armed = &actions.link.lease_armed;
        armed.store(false, core::sync::atomic::Ordering::SeqCst);
        assert_eq!(actions.link.stamps_while(armed), None, "a lowered duty");
        armed.store(true, core::sync::atomic::Ordering::SeqCst);
        assert_eq!(
            actions
                .link
                .stamps_while(armed)
                .map(|row| row.established_at),
            Some(Some(7)),
            "an armed one reads the row"
        );
    }

    /// No stamp reads as none: the word that means none is never what a stamp is written as, so
    /// the latest instant reads as one below it, and a door that writes nothing leaves the stamp.
    /// Turned red by a stamp of the latest instant read back as none.
    #[test]
    fn the_latest_instant_is_still_a_stamp() {
        let (actions, _link) = bundle();
        actions
            .link
            .fact_last_inbound_at(|slot| *slot = Some(u64::MAX));
        assert_eq!(
            actions.link.fact_last_inbound_at(|slot| *slot),
            Some(u64::MAX - 1)
        );
        actions.link.fact_last_inbound_at(|slot| *slot = Some(4));
        assert_eq!(actions.link.fact_last_inbound_at(|slot| *slot), Some(4));
        actions.link.fact_last_inbound_at(|slot| *slot = None);
        assert_eq!(actions.link.fact_last_inbound_at(|slot| *slot), None);
    }

    /// A keepalive tick ends once: the judge that read it ends it, and a second judge that read the
    /// same tick finds it ended and writes nothing. Turned red by an end that does not compare the
    /// tick it read.
    #[cfg(feature = "transport-keepalive")]
    #[test]
    fn a_keepalive_tick_ends_once() {
        let (actions, _link) = bundle();
        actions.link.fact_keepalive_tick_at(|slot| *slot = Some(10));
        assert!(
            actions.link.end_keepalive_tick(Some(10), 20),
            "the first judge"
        );
        assert!(
            !actions.link.end_keepalive_tick(Some(10), 30),
            "the second finds it ended"
        );
        assert_eq!(actions.link.stamps().keepalive_tick_at, Some(20));
        assert!(
            actions.link.end_keepalive_tick(Some(20), 40),
            "the tick running now ends"
        );
        assert!(
            !actions.link.end_keepalive_tick(None, 50),
            "a tick read as not yet begun does not end one that runs"
        );
        assert_eq!(actions.link.stamps().keepalive_tick_at, Some(40));
    }

    /// An established bundle whose keepalive worker runs, as the machine's `Established` entry
    /// leaves it, and the session's keepalive interval. The still clock stands at 0, the
    /// establishment with it, so the first tick ends at the interval.
    #[cfg(feature = "transport-keepalive")]
    fn keeping_alive() -> (
        alloc::sync::Arc<super::SessionLinkActions<super::PlainRuntime, super::StillClock>>,
        alloc::sync::Arc<super::CountingLink>,
        u64,
    ) {
        let (actions, link) = bundle();
        actions.enter_established();
        actions.link.arm_keepalive();
        let interval = actions.keepalive_interval_ms();
        (actions, link, interval)
    }

    /// A tick the line was silent in ends in one keepalive, at its end and not before, and that
    /// keepalive is no speech in the next tick, which ends in one too: an idle line sends one per
    /// interval. Turned red by a judge that leaves its own keepalive's mark standing (no second
    /// keepalive), or by one that sends before the tick ends.
    #[cfg(feature = "transport-keepalive")]
    #[test]
    fn an_idle_tick_ends_in_one_keepalive_and_so_does_the_next() {
        use crate::lease::KeepAliveCheckOutcome as K;
        let (actions, link, interval) = keeping_alive();
        let written = || link.written.load(core::sync::atomic::Ordering::SeqCst);
        let check = |now_ms| crate::drive::check_keepalive_deadline(&*actions, now_ms);
        let before = written();
        assert_eq!(check(interval - 1), K::WithinInterval, "the tick runs");
        assert_eq!(written(), before, "nothing before the tick ends");
        assert_eq!(check(interval), K::Emitted, "the first tick was silent");
        assert_eq!(written(), before + 1, "one keepalive for it");
        assert_eq!(
            actions.link.stamps().keepalive_tick_at,
            Some(interval),
            "the next tick starts at the check"
        );
        assert_eq!(
            check(2 * interval - 1),
            K::WithinInterval,
            "the next tick runs"
        );
        assert_eq!(
            check(2 * interval),
            K::Emitted,
            "the keepalive was no speech in the next tick"
        );
        assert_eq!(written(), before + 2, "one keepalive for each silent tick");
    }

    /// A frame holds back the keepalive of its own tick and of no other: the next tick, silent,
    /// ends in one, so a line that spoke once just after a tick began is silent for two intervals
    /// at most, which is inside the lease. The frame takes no stamp, so it reads no clock and no
    /// lock of the stamps. Turned red by a frame that does not mark its tick (a keepalive at the
    /// first end), by a mark that outlives the tick (none at the second), or by a frame that
    /// writes the tick's stamp.
    #[cfg(all(
        feature = "transport-keepalive",
        feature = "codec-push",
        not(feature = "tx-lend-only")
    ))]
    #[test]
    fn a_frame_holds_back_the_keepalive_of_its_tick_alone() {
        use crate::lease::KeepAliveCheckOutcome as K;
        let (actions, link, interval) = keeping_alive();
        let key = crate::named_key::NamedKey::literal("home/tick").expect("a key");
        let put = actions.send_plain_put_qos(
            key,
            b"v",
            None,
            super::super::SendAs {
                reliable: true,
                express: false,
                priority: crate::qos::Priority::DEFAULT,
            },
        );
        assert_eq!(put, Some(Ok(())), "CONTROL: the put left");
        assert_eq!(
            actions.link.stamps().keepalive_tick_at,
            None,
            "a frame writes no stamp"
        );
        let written = || link.written.load(core::sync::atomic::Ordering::SeqCst);
        let check = |now_ms| crate::drive::check_keepalive_deadline(&*actions, now_ms);
        let before = written();
        assert_eq!(
            check(interval),
            K::WithinInterval,
            "the line spoke in the first tick"
        );
        assert_eq!(written(), before, "no keepalive for that tick");
        assert_eq!(
            check(2 * interval),
            K::Emitted,
            "the second tick was silent"
        );
        assert_eq!(written(), before + 1, "one keepalive for it");
        assert!(
            2 * interval < actions.adopted_lease_ms(),
            "two silent intervals are inside the lease"
        );
    }

    /// The keep-alive's checks a step of `timers` at `now_ms` raises.
    #[cfg(feature = "transport-keepalive")]
    fn keepalive_checks(
        timers: &mut crate::transport_timers::TransportTimers,
        engine: &mut Machine,
        actions: &Actions,
        now_ms: u64,
    ) -> alloc::vec::Vec<crate::lease::KeepAliveCheckOutcome> {
        use crate::driver_loop::IterationEvent;
        let mut seen = alloc::vec::Vec::new();
        let mut sink = |event: IterationEvent<'_, '_>| {
            if let IterationEvent::KeepAlive(outcome) = event {
                seen.push(outcome);
            }
        };
        timers.fire_due(engine, actions, now_ms, &mut sink);
        seen
    }

    /// The timers send the keepalive at the end of each tick they read, and read the next tick
    /// after the judge that ended one. Turned red by timers that keep the deadline they held after
    /// judging it (no second keepalive), or that send before the tick ends.
    #[cfg(feature = "transport-keepalive")]
    #[test]
    fn the_timers_send_a_keepalive_at_the_end_of_every_silent_tick() {
        use crate::lease::KeepAliveCheckOutcome as K;
        use crate::session_timeouts::SessionTimeouts;
        use crate::transport_timers::TransportTimers;

        let (actions, _link, interval) = keeping_alive();
        let mut engine = machine(&actions);
        let mut timers = TransportTimers::new(SessionTimeouts::spec_defaults());
        let mut step = |now_ms| keepalive_checks(&mut timers, &mut engine, &actions, now_ms);
        assert!(step(0).is_empty(), "the first tick runs");
        assert!(step(interval - 1).is_empty(), "nothing before it ends");
        assert_eq!(step(interval), [K::Emitted], "the first tick was silent");
        assert!(step(interval + 1).is_empty(), "the next tick runs");
        assert_eq!(step(2 * interval), [K::Emitted], "and the next");
    }

    /// Two judges that read the same deadlines (the tokio pacer beside the drive loop) end the
    /// tick once and send one keepalive for it. Turned red by a judge that ends a tick another
    /// has already ended.
    #[cfg(feature = "transport-keepalive")]
    #[test]
    fn a_tick_ends_once_whoever_judges_it() {
        use crate::lease::KeepAliveCheckOutcome as K;
        let (actions, link, interval) = keeping_alive();
        let read = crate::drive::keepalive_deadlines(&*actions).expect("the worker runs");
        let before = link.written.load(core::sync::atomic::Ordering::SeqCst);
        assert_eq!(
            crate::drive::judge_keepalive(&*actions, interval, read),
            K::Emitted
        );
        assert_eq!(
            crate::drive::judge_keepalive(&*actions, interval, read),
            K::WithinInterval,
            "the second judge finds the tick ended"
        );
        assert_eq!(
            link.written.load(core::sync::atomic::Ordering::SeqCst),
            before + 1,
            "one keepalive for the tick"
        );
    }

    /// What the link sent before its keepalive worker started, the handshake, is no speech in the
    /// worker's first tick, which ends in a keepalive when the line says nothing after. Turned red
    /// by a worker that starts with the mark an earlier frame left.
    #[cfg(feature = "transport-keepalive")]
    #[test]
    fn what_the_link_sent_before_its_worker_is_no_speech_in_the_first_tick() {
        use crate::lease::KeepAliveCheckOutcome as K;
        let (actions, _link) = bundle();
        actions.enter_established();
        actions.send_keep_alive();
        assert!(
            actions
                .link
                .spoke
                .load(core::sync::atomic::Ordering::Relaxed),
            "CONTROL: a frame on a link that writes inline marks the line"
        );
        actions.link.arm_keepalive();
        let interval = actions.keepalive_interval_ms();
        assert_eq!(
            crate::drive::check_keepalive_deadline(&*actions, interval),
            K::Emitted
        );
    }
}

/// The inbound SN gates, kept in words of the runtime's: a frame is judged with no hold of a lock,
/// on the ring the peer's capabilities give.
mod rx_sn_gate {
    use alloc::vec::Vec;

    use super::{bundle, holds_in};
    use crate::peer_init_caps::PeerInitCaps;
    use crate::qos::Priority;
    use crate::sn::RxAdmit;

    /// The peer's capabilities with the sequence-number resolution `seq_num_res`.
    fn caps(seq_num_res: u8) -> Option<PeerInitCaps> {
        Some(PeerInitCaps {
            seq_num_res,
            req_id_res: 2,
            batch_size: 1024,
        })
    }

    /// Every frame of a walk is judged under no lock: the first taken as the baseline, the next
    /// one accepted, its duplicate stale, a skip a gap; and the best-effort channel, a baseline of
    /// its own, takes the first frame it sees though the reliable one has passed it. Turned red by
    /// a judgement that takes a lock to read the baseline or the ring, or by channels that share
    /// one baseline.
    #[test]
    fn a_frame_is_judged_under_no_lock() {
        let (actions, _link) = bundle();
        let mut verdicts = Vec::new();
        let holds = holds_in(|| {
            for sn in [5, 6, 6, 9] {
                verdicts.push(actions.admit_rx_frame_sn_judged(Priority::DEFAULT, true, sn));
            }
            verdicts.push(actions.admit_rx_frame_sn_judged(Priority::DEFAULT, false, 5));
        });
        assert_eq!(
            verdicts,
            [
                RxAdmit::Accept,
                RxAdmit::Accept,
                RxAdmit::Stale,
                RxAdmit::Gap { missing: 2 },
                RxAdmit::Accept
            ]
        );
        assert_eq!(
            holds, 0,
            "the baseline and the ring are words, read under no lock"
        );
    }

    /// The gate judges on the ring the peer's capabilities give, followed as they are written:
    /// a jump of 64 is stale on the seven-bit ring a peer names and a gap on the session's own
    /// once the capabilities are withdrawn. Turned red by a ring the gate reads once, or one a
    /// write of the capabilities does not move.
    #[test]
    fn the_gate_judges_on_the_ring_the_peers_capabilities_give() {
        let (actions, _link) = bundle();
        actions.set_peer_init_caps(caps(0x00));
        assert_eq!(
            actions.admit_rx_frame_sn_judged(Priority::DEFAULT, true, 0),
            RxAdmit::Accept
        );
        assert_eq!(
            actions.admit_rx_frame_sn_judged(Priority::DEFAULT, true, 64),
            RxAdmit::Stale,
            "past half the seven-bit ring"
        );
        actions.set_peer_init_caps(None);
        assert_eq!(
            actions.admit_rx_frame_sn_judged(Priority::DEFAULT, true, 64),
            RxAdmit::Gap { missing: 63 },
            "within half the session's own 28-bit ring"
        );
    }

    /// An admitted OpenAck seeds every channel one before the peer's initial SN, on the ring the
    /// peer's capabilities give. Turned red by a seed on another ring or of one channel.
    #[cfg(feature = "codec-open-body")]
    #[test]
    fn an_admitted_open_ack_seeds_the_gate_on_the_peers_ring() {
        use crate::session_actions::OpenAckAdmission;
        use crate::sn::{mask_from_res, RxConduits};
        let (actions, _link) = bundle();
        actions.set_peer_init_caps(caps(0x00));
        actions.fact_awaiting_open_ack(|slot| *slot = true);
        assert_eq!(
            actions.admit_open_ack(5, 0, Ok(None)),
            OpenAckAdmission::Taken
        );
        let mut expected = RxConduits::default();
        expected.seed(mask_from_res(0x00), 0);
        assert_eq!(
            actions.rx_sn(),
            expected,
            "one before 0 on the seven-bit ring is 127"
        );
        assert_eq!(
            actions.admit_rx_frame_sn_judged(Priority::DEFAULT, false, 0),
            RxAdmit::Accept,
            "the first frame at the initial SN passes"
        );
    }

    /// A reopen clears every channel and puts the gate back on the session's own ring, with the
    /// capabilities it clears. Turned red by a reopen that leaves a baseline or the peer's ring.
    #[cfg(feature = "session-reconnect")]
    #[test]
    fn a_reopen_clears_the_gate_and_its_ring() {
        use crate::sn::RxConduits;

        let (actions, _link) = bundle();
        actions.set_peer_init_caps(caps(0x00));
        assert_eq!(
            actions.admit_rx_frame_sn_judged(Priority::DEFAULT, true, 0),
            RxAdmit::Accept
        );
        actions.reset_for_reopen();
        assert_eq!(actions.rx_sn(), RxConduits::default(), "no baseline left");
        assert_eq!(
            actions.admit_rx_frame_sn_judged(Priority::DEFAULT, true, 0),
            RxAdmit::Accept
        );
        assert_eq!(
            actions.admit_rx_frame_sn_judged(Priority::DEFAULT, true, 64),
            RxAdmit::Gap { missing: 63 },
            "judged on the session's own ring again"
        );
    }
}

/// The one value of a one-face session's transport, over a real session's machine and actions: what
/// it raises before input is read, the order it hands a datagram and the time to the session, and
/// when it is next due.
mod unicast_transport {
    use alloc::sync::Arc;
    use alloc::vec::Vec;
    use core::mem::MaybeUninit;

    use super::{bundle, NoEntropy, PlainRuntime, StillClock};
    use crate::drive::{new_session_engine, SessionEngine};
    use crate::driver_loop::IterationEvent;
    use crate::link_life::{LinkInput, LinkTimes};
    use crate::session_actions::SessionLinkActions;
    use crate::session_timeouts::SessionTimeouts;
    use crate::unicast_transport::{MadeLink, UnicastTransport};

    const TIMES: LinkTimes = LinkTimes {
        open_timeout_ms: 1_000,
        redial_ms: Some(500),
        dial_look_ms: 10,
        accept_timeout_ms: 1_000,
    };

    /// The session's machine over `actions`, entered in its initial state and given no role.
    fn engine(
        actions: &Arc<SessionLinkActions<PlainRuntime, StillClock>>,
    ) -> SessionEngine<PlainRuntime, StillClock> {
        let mut engine = new_session_engine::<PlainRuntime, StillClock>(actions, NoEntropy);
        engine.initialize().unwrap_or_else(|never| match never {});
        engine
    }

    /// The application layer's deadline that came due is raised once by the time handed to the
    /// transport, and spent: the time handed again raises nothing. Turned red by an `on_time` that
    /// leaves the deadline out, or raises it without spending it.
    #[test]
    fn the_time_raises_the_application_layers_deadline_once() {
        let (actions, _link) = bundle();
        let mut engine = engine(&actions);
        let mut place = MaybeUninit::<UnicastTransport<()>>::uninit();
        let transport = UnicastTransport::init_in(
            &mut place,
            TIMES,
            1,
            SessionTimeouts::from_build(),
            |slot| slot.write(()),
        )
        .expect("built");
        actions.set_app_wake_deadline_ms(Some(0));
        let mut wakes = 0usize;
        let mut count = |event: IterationEvent<'_, '_>| {
            if matches!(event, IterationEvent::AppWake) {
                wakes += 1;
            }
        };
        transport.on_time(&mut engine, &*actions, 0, &mut count);
        transport.on_time(&mut engine, &*actions, 0, &mut count);
        assert_eq!(wakes, 1, "the deadline is raised once");
        assert_eq!(actions.app_wake_deadline_ms(), None, "and spent");
    }

    /// The transport is due at the first of what its link and its session have due: the session's
    /// application deadline while the link waits on nothing, and the link's look at once when a
    /// dial it asked for is owed. Turned red by a due instant that leaves the link's wake out.
    #[test]
    fn the_transport_is_due_at_the_first_of_its_links_and_its_sessions() {
        let (actions, _link) = bundle();
        let engine = engine(&actions);
        let mut place = MaybeUninit::<UnicastTransport<()>>::uninit();
        let transport = UnicastTransport::init_in(
            &mut place,
            TIMES,
            1,
            SessionTimeouts::from_build(),
            |slot| slot.write(()),
        )
        .expect("built");
        actions.set_app_wake_deadline_ms(Some(9));
        assert!(
            transport
                .due_ms(&engine, &*actions, 0)
                .is_some_and(|due_ms| due_ms <= 9),
            "an idle link leaves the session's deadline to bound the look"
        );
        assert_eq!(transport.input(LinkInput::Open, 0).dial(), Some(0));
        assert_eq!(
            transport.due_ms(&engine, &*actions, 0),
            Some(0),
            "a dial owed a report is looked at now"
        );
    }

    /// A datagram handed to the transport is read after the application layer's deadline is raised,
    /// and the receive counts the path it took. Turned red by an `on_datagram` that reads the
    /// datagram first, leaves the deadline out, or dispatches past the receive's count.
    #[cfg(feature = "rx-in-place")]
    #[test]
    fn a_datagram_is_read_after_the_application_layers_deadline_and_counted() {
        use crate::unicast_rx::RxPathCounts;

        let (actions, _link) = bundle();
        let mut engine = engine(&actions);
        let mut place = MaybeUninit::<UnicastTransport<()>>::uninit();
        let transport = UnicastTransport::init_in(
            &mut place,
            TIMES,
            1,
            SessionTimeouts::from_build(),
            |slot| slot.write(()),
        )
        .expect("built");
        actions.set_app_wake_deadline_ms(Some(0));
        let mut wakes: Vec<bool> = Vec::new();
        let path = transport.on_datagram(
            &[wz_codecs::wire_const::T_MID_KEEP_ALIVE],
            &mut engine,
            &*actions,
            0,
            &mut |event: IterationEvent<'_, '_>| {
                wakes.push(matches!(event, IterationEvent::AppWake));
            },
        );
        assert_eq!(wakes.first(), Some(&true), "the deadline is raised first");
        assert_eq!(wakes.iter().filter(|wake| **wake).count(), 1, "and once");
        let mut counted = RxPathCounts::default();
        counted.count(path);
        assert_eq!(
            transport.rx().path_counts(),
            counted,
            "the receive counted the one datagram on the path it took"
        );
    }

    /// A `Frame` read where its datagram lies stamps the link's last receipt with the time of the
    /// turn of input that read it, not with a reading of the session's clock, which stands at 0
    /// here. Turned red by an admitted head that reads the clock for its stamp again.
    #[cfg(feature = "rx-in-place")]
    #[test]
    fn a_frame_read_in_place_stamps_its_receipt_at_the_time_of_its_turn() {
        use crate::drive::DatagramPath;
        use wz_codecs::wire_const::{FLAG_T_FRAME_R, T_MID_FRAME};

        let (actions, _link) = bundle();
        let mut engine = engine(&actions);
        let mut place = MaybeUninit::<UnicastTransport<()>>::uninit();
        let transport = UnicastTransport::init_in(
            &mut place,
            TIMES,
            1,
            SessionTimeouts::from_build(),
            |slot| slot.write(()),
        )
        .expect("built");
        assert_eq!(actions.link.fact_last_inbound_at(|slot| *slot), None);
        // A reliable `Frame` at SN 1 that carries no record.
        let frame = [T_MID_FRAME | FLAG_T_FRAME_R, 0x01];
        let path = transport.on_datagram(
            &frame,
            &mut engine,
            &*actions,
            7_000,
            &mut |_: IterationEvent<'_, '_>| {},
        );
        assert_eq!(path, DatagramPath::InPlace, "the Frame is read in place");
        assert_eq!(
            actions.link.fact_last_inbound_at(|slot| *slot),
            Some(7_000),
            "the receipt is stamped at the turn's time"
        );
    }

    /// A datagram its link keeps is read on from where the last turn stopped, which the receive
    /// notes beside its record: two KeepAlives in one datagram are read over two lends of the same
    /// bytes, one a lend, and the turn between says the link is to keep it. A kept datagram read
    /// to its end has nothing left, and finding so takes no lock. Turned red by a receive that
    /// reads a kept datagram from its start again, that does not say the link is to keep it, or
    /// that notes where it stopped under a lock. A build that decodes no KeepAlive takes one for a
    /// framing error and keeps no datagram, so the test needs the codec.
    #[cfg(all(
        feature = "rx-in-place",
        feature = "alloc",
        feature = "codec-keep-alive"
    ))]
    #[test]
    fn a_kept_datagram_is_read_on_from_where_its_receive_noted_it_stopped() {
        use super::holds_in;
        use crate::driver_loop::EventSink;

        /// A host whose link keeps its datagram and that takes one message a lend.
        #[derive(Default)]
        struct OneALend {
            events: usize,
        }

        impl EventSink for OneALend {
            fn event(&mut self, _event: IterationEvent<'_, '_>) {
                self.events += 1;
            }

            fn takes_another(&mut self) -> bool {
                false
            }

            fn holds_datagram(&self) -> bool {
                true
            }
        }

        let (actions, _link) = bundle();
        let mut engine = engine(&actions);
        let mut place = MaybeUninit::<UnicastTransport<(), MadeLink>>::uninit();
        let transport =
            UnicastTransport::init_made_in(&mut place, SessionTimeouts::from_build(), |slot| {
                slot.write(())
            })
            .expect("built");
        let keep_alive = wz_codecs::wire_const::T_MID_KEEP_ALIVE;
        let datagram = [keep_alive, keep_alive];
        let mut host = OneALend::default();

        let mut first = transport.input_at(0);
        first.datagram(&datagram, &mut engine, &*actions, &mut host);
        assert_eq!(
            host.events, 1,
            "the first message, and no other in this lend"
        );
        assert!(first.resumes_datagram(), "the link is to keep the datagram");

        let mut second = transport.input_at(0);
        second.datagram(&datagram, &mut engine, &*actions, &mut host);
        assert_eq!(
            host.events, 2,
            "the second message, read on from where the first lend stopped"
        );
        assert!(!second.resumes_datagram(), "read to its end");

        let mut third = transport.input_at(0);
        let holds = holds_in(|| {
            third.datagram(&[], &mut engine, &*actions, &mut host);
        });
        assert_eq!(
            host.events, 2,
            "a kept datagram with nothing left reads nothing"
        );
        assert!(!third.resumes_datagram());
        assert_eq!(
            holds, 0,
            "where the receive stands is its own, under no lock"
        );
    }

    /// A transport over a link handed to it made is due when its session is, and a life that
    /// asks for a look moves only the transport that holds it. Turned red by a made link that adds
    /// a wake of its own, or a due instant that reads another transport's life.
    #[test]
    fn a_transport_over_a_made_link_is_due_when_its_session_is() {
        let (actions, _link) = bundle();
        let engine = engine(&actions);
        let mut made_place = MaybeUninit::<UnicastTransport<(), MadeLink>>::uninit();
        let made = UnicastTransport::init_made_in(
            &mut made_place,
            SessionTimeouts::from_build(),
            |slot| slot.write(()),
        )
        .expect("built");
        let mut place = MaybeUninit::<UnicastTransport<()>>::uninit();
        let dialling = UnicastTransport::init_in(
            &mut place,
            TIMES,
            1,
            SessionTimeouts::from_build(),
            |slot| slot.write(()),
        )
        .expect("built");
        actions.set_app_wake_deadline_ms(Some(9));
        assert_eq!(
            made.due_ms(&engine, &*actions, 0),
            dialling.due_ms(&engine, &*actions, 0),
            "an idle life adds nothing to the session's own"
        );
        assert_eq!(dialling.input(LinkInput::Open, 0).dial(), Some(0));
        assert_eq!(dialling.due_ms(&engine, &*actions, 0), Some(0));
        assert!(
            made.due_ms(&engine, &*actions, 0)
                .is_some_and(|due_ms| due_ms <= 9),
            "the session's deadline still bounds the made link's transport"
        );
    }

    /// A turn that raises nothing first leaves the application layer's deadline for the time its
    /// owner hands apart, and a turn begun raises it. Turned red by an `input_at` that raises.
    #[test]
    fn a_turn_that_raises_nothing_leaves_the_deadline_for_the_time() {
        let (actions, _link) = bundle();
        let mut engine = engine(&actions);
        let mut place = MaybeUninit::<UnicastTransport<(), MadeLink>>::uninit();
        let transport =
            UnicastTransport::init_made_in(&mut place, SessionTimeouts::from_build(), |slot| {
                slot.write(())
            })
            .expect("built");
        actions.set_app_wake_deadline_ms(Some(0));
        {
            let turn = transport.input_at(0);
            assert!(turn.ready(), "a Router of its own takes input");
        }
        assert_eq!(actions.app_wake_deadline_ms(), Some(0), "left for the time");
        let mut wakes = 0usize;
        let mut count = |event: IterationEvent<'_, '_>| {
            if matches!(event, IterationEvent::AppWake) {
                wakes += 1;
            }
        };
        transport
            .begin_input(&*actions, 0, &mut count)
            .end(&mut engine, &*actions, &mut count);
        assert_eq!(wakes, 1, "a turn begun raises it");
        assert_eq!(actions.app_wake_deadline_ms(), None);
    }

    /// A link that is gone is told to the session's machine and reported to the owner as the
    /// link's loss, with its cause. Turned red by a `lose` that reports another outcome or does
    /// not reach the machine.
    #[test]
    fn a_lost_link_is_told_to_the_machine_and_reported_with_its_cause() {
        use crate::driver_loop::DriverLoopOutcome;
        use crate::link::LostCause;

        let (actions, _link) = bundle();
        let mut engine = engine(&actions);
        let mut place = MaybeUninit::<UnicastTransport<(), MadeLink>>::uninit();
        let transport =
            UnicastTransport::init_made_in(&mut place, SessionTimeouts::from_build(), |slot| {
                slot.write(())
            })
            .expect("built");
        let mut lost = Vec::new();
        let mut seen = |event: IterationEvent<'_, '_>| {
            if let IterationEvent::Poll(DriverLoopOutcome::LinkLost(cause)) = event {
                lost.push(matches!(cause, LostCause::PeerClosed));
            }
        };
        let turn = transport.begin_input(&*actions, 0, &mut seen);
        turn.lose(&mut engine, LostCause::PeerClosed, &mut seen);
        assert_eq!(lost, [true], "one loss, with the peer's close as its cause");
    }
}
