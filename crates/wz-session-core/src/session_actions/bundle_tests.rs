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
use crate::link::{BoxedLinkDriver, LinkSendOutcome, SessionRuntime, ShareValues};
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

impl ShareValues for PlainRuntime {
    fn share<U>(value: U) -> Self::Shared<U> {
        Arc::new(value)
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
    fn with_local<T, U>(local: &Self::Local<T>, f: impl FnOnce(&mut T) -> U) -> U
    where
        T: Send + 'static,
    {
        Self::with_mutex_mut(local, f)
    }

    type ActionsHandle<T: TimeSource> = Arc<SessionLinkActions<Self, T>>;

    fn wrap_actions<T: TimeSource>(actions: SessionLinkActions<Self, T>) -> Self::ActionsHandle<T> {
        Arc::new(actions)
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
        SessionLinkActions::<PlainRuntime, StillClock>::new_generic(sink, params(), StillClock);
    (actions, link)
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

    use super::bundle;
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
        let (actions, link) = bundle();
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
            SessionLinkActions::<PlainRuntime, StillClock>::new_generic(sink, params, StillClock);
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
/// slot is lent (`open_frame_lent` minting in its admission again), whose next frame carries SN 1.
#[cfg(all(feature = "tx-lend-only", feature = "codec-push", feature = "alloc"))]
mod lent_frame_refusal {
    use alloc::sync::Arc;
    use alloc::vec::Vec;
    use core::sync::atomic::{AtomicBool, Ordering};
    use std::sync::Mutex;

    use super::{params, PlainRuntime, StillClock};
    use crate::link::{BoxedLinkDriver, LinkDropCause, LinkSendOutcome, TxSlot, TxSlotGrant};
    use crate::qos::Priority;
    use crate::reliability::Reliability;
    use crate::send_wire_error::SendWireError;
    use crate::session_actions::SessionLinkActions;

    /// A link of one slot that lends it only while `lends` says so, and keeps each frame sent.
    struct DryLink {
        lends: AtomicBool,
        slot: Mutex<Vec<u8>>,
        sent: Mutex<Vec<Vec<u8>>>,
        asked: Mutex<Vec<usize>>,
    }

    impl DryLink {
        fn of_width(width: usize, lends: bool) -> Arc<Self> {
            Arc::new(Self {
                lends: AtomicBool::new(lends),
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
            SessionLinkActions::<PlainRuntime, StillClock>::new_generic(sink, params(), StillClock);
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

    /// A frame sent whole asks its link for the whole batch budget, as a window does: nothing
    /// measures the message before it is written into the slot. Turned red by a send that asks
    /// for a size it counted first (`open_frame_lent` asking for anything but `emit.mtu`).
    #[test]
    fn a_frame_sent_whole_asks_for_the_batch_budget() {
        let link = DryLink::of_width(512, true);
        let sink: Arc<dyn BoxedLinkDriver + Send + Sync> = link.clone();
        let actions =
            SessionLinkActions::<PlainRuntime, StillClock>::new_generic(sink, params(), StillClock);
        assert_eq!(put(&actions), Some(Ok(())));
        let (budget, _) = actions.negotiated_tx_limits_for(Reliability::Reliable);
        assert_eq!(
            *link.asked.lock().expect("the asks"),
            [budget],
            "one ask, for the budget"
        );
    }

    /// A slot lent short of the frame took the SN the frame was written with, and gives it back
    /// with the refusal: the next frame of the conduit carries it. Turned red by the
    /// `unmint` of `open_frame_lent`'s `FrameLend::Heap` arm taken out, whose next frame
    /// carries SN 1.
    #[test]
    fn a_frame_refused_in_a_short_slot_gives_its_sequence_number_back() {
        let link = DryLink::of_width(4, true);
        let sink: Arc<dyn BoxedLinkDriver + Send + Sync> = link.clone();
        let actions =
            SessionLinkActions::<PlainRuntime, StillClock>::new_generic(sink, params(), StillClock);
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
            SessionLinkActions::<PlainRuntime, StillClock>::new_generic(sink, params(), StillClock);
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

/// A plain put whose key is past its protocol bound is refused with the codec's error on the heap
/// path, and nothing reaches the link: the vector refuses no write, but the body refuses its
/// message, and the send answers that as a value.
#[cfg(all(feature = "codec-push", not(feature = "tx-lend-only")))]
#[test]
fn a_plain_put_past_its_key_bound_is_refused_and_not_sent() {
    let (actions, link) = bundle();
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

/// A staged reply leaves through the writer of its parts in a build that reads no owned reply (no
/// statistics; no policy or namespace is installed here): one the writer takes is written, and one
/// it refuses is skipped with nothing built. The responder identity of no bytes is the case the
/// owned builder asserts against, so a refused reply that fell back to the owned record would panic
/// here.
///
/// Turned red by a `send_reply_parts` that sends a reply the writer refuses as an owned one.
#[cfg(all(
    feature = "codec-response",
    not(feature = "transport-stats"),
    not(feature = "tx-lend-only")
))]
mod staged_replies {
    use core::sync::atomic::Ordering;

    use super::bundle;
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
        let (actions, link) = bundle();
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
}

/// The session's facts are one row under one lock: what a door writes is what the whole row reads,
/// and a reopen empties the handshake's part of it and keeps what is not the handshake's.
mod facts_lock {
    use super::{bundle, holds_in};

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
    /// and the reopened link takes no data send until it is established again.
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
            (0, 0),
            "no limits are settled yet"
        );

        actions.set_peer_init_caps(Some(caps(512)));
        actions.enter_established();
        let settled = actions.negotiated_tx_limits();
        assert_eq!(
            settled,
            (
                actions.negotiated_batch_mtu() - actions.batch_envelope_bytes(),
                actions.negotiated_sn_mask()
            ),
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
            actions.negotiated_tx_limits().0,
            actions.negotiated_batch_mtu() - actions.batch_envelope_bytes(),
            "established again, the limits are the new capabilities'"
        );
        assert_ne!(actions.negotiated_tx_limits(), settled);
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
                facts.handshake.peer_open_lease_ms,
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
                facts.handshake.peer_open_lease_ms,
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
                facts.handshake.peer_open_lease_ms,
                facts.handshake.peer_remote_bound,
            )
        });
        assert!(awaiting, "a refused OpenAck ends no wait");
        assert_eq!(lease, None, "a refused OpenAck adopts no lease");
        assert_eq!(bound, None, "a refused bound is not written");
    }

    /// The RX SN gate reads the ring the peer's capabilities give and moves the conduit's
    /// baseline in one hold of the facts. Turned red by a gate that reads the capabilities in a
    /// hold of their own.
    #[test]
    fn the_rx_sn_gate_judges_in_one_hold_of_the_facts() {
        use crate::qos::Priority;
        use crate::sn::RxAdmit;
        let (actions, _link) = bundle();
        let mut first = None;
        let holds = holds_in(|| {
            first = Some(actions.admit_rx_frame_sn_judged(Priority::DEFAULT, true, 5));
        });
        assert_eq!(
            first,
            Some(RxAdmit::Accept),
            "a channel's first frame is taken"
        );
        assert_eq!(holds, 1, "the gate takes the facts once");
        assert_eq!(
            actions.admit_rx_frame_sn_judged(Priority::DEFAULT, true, 5),
            RxAdmit::Stale,
            "a duplicate is dropped"
        );
        assert_eq!(
            actions.admit_rx_frame_sn_judged(Priority::DEFAULT, true, 7),
            RxAdmit::Gap { missing: 1 },
            "a forward jump is taken and reports the frame it skipped"
        );
        assert_eq!(
            actions.admit_rx_frame_sn_judged(Priority::DEFAULT, false, 5),
            RxAdmit::Accept,
            "the best-effort channel keeps a baseline of its own"
        );
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

    /// An admitted OpenSyn spends the nonce that admitted it and takes the peer's lease in one
    /// hold.
    #[cfg(all(feature = "codec-open-body", feature = "session-unicast-accept"))]
    #[test]
    fn an_admitted_open_syn_spends_the_nonce_and_takes_the_lease() {
        let (actions, _link) = bundle();
        actions.fact_cookie_nonce(|slot| *slot = Some(7));
        actions.admit_open_syn(5, 10);
        let (nonce, lease) =
            actions.with_facts(|facts| (facts.cookie_nonce, facts.handshake.peer_open_lease_ms));
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

/// A link's time stamps are one row under one lock: what a door writes is what the row reads, the
/// deadlines read the two stamps they compare in one hold, and a reopen clears all three.
mod link_stamps {
    use super::{bundle, holds_in};
    use crate::session_actions::LinkStamps;

    /// Turned red by a door that writes another stamp than it names, or by a read of the row
    /// that holds the lock once per stamp.
    #[test]
    fn a_stamp_written_through_its_door_is_read_in_the_one_row() {
        let (actions, _link) = bundle();
        actions.link.fact_established_at(|slot| *slot = Some(1));
        actions.link.fact_last_inbound_at(|slot| *slot = Some(2));
        actions.link.fact_last_outbound_at(|slot| *slot = Some(3));
        let mut stamps = LinkStamps::default();
        let holds = holds_in(|| stamps = actions.link.stamps());
        assert_eq!(holds, 1, "the row is read in one hold");
        assert_eq!(
            stamps,
            LinkStamps {
                established_at: Some(1),
                last_inbound_at: Some(2),
                last_outbound_at: Some(3),
            }
        );
    }

    /// The lease deadline counts from the later of the establishment and the last receipt, and
    /// reads the two in one hold; the other hold is the peer's lease. Turned red by a deadline
    /// that reads each stamp in a hold of its own.
    #[test]
    fn the_lease_deadline_reads_its_two_stamps_in_one_hold() {
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
            Some(250 + lease),
            "the later stamp is the baseline"
        );
        assert_eq!(
            holds, 2,
            "the stamps in one hold, the peer's lease in another"
        );
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
        let expiry = 100 + actions.adopted_lease_ms();
        let watch = actions.declaration_watch_deadline();
        let mut deadline = None;
        let holds = holds_in(|| deadline = crate::drive::lease_wake_deadline(&*actions));
        assert_eq!(
            deadline,
            Some(watch.map_or(expiry, |watch| watch.min(expiry))),
            "the earlier of the expiry and the watch"
        );
        assert_eq!(
            holds, 2,
            "the stamps in one hold, the peer's lease in another"
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
        let expiry = 100 + actions.adopted_lease_ms();
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
            holds, 2,
            "the stamps in one hold, the peer's lease in another"
        );
    }

    /// The keepalive deadline counts from the later of the establishment and the last emit, and
    /// reads the two in one hold. Turned red by a deadline that reads each stamp in a hold of its
    /// own.
    #[cfg(feature = "transport-keepalive")]
    #[test]
    fn the_keepalive_deadline_reads_its_two_stamps_in_one_hold() {
        let (actions, _link) = bundle();
        actions
            .link
            .keepalive_armed
            .store(true, core::sync::atomic::Ordering::SeqCst);
        actions.link.fact_established_at(|slot| *slot = Some(300));
        actions.link.fact_last_outbound_at(|slot| *slot = Some(200));
        let interval = actions.keepalive_interval_ms();
        let mut deadline = None;
        let holds = holds_in(|| deadline = crate::drive::keepalive_wake_deadline(&*actions));
        assert_eq!(
            deadline,
            Some(300 + interval),
            "the later stamp is the baseline"
        );
        assert_eq!(
            holds, 2,
            "the stamps in one hold, the peer's lease in another"
        );
    }

    /// Every stamp is the closed transport's: a reopen clears the three in one hold of the row.
    /// Turned red by a reopen that leaves one of them standing.
    #[cfg(feature = "session-reconnect")]
    #[test]
    fn a_reopen_clears_every_stamp() {
        let (actions, _link) = bundle();
        actions.link.with_stamps(|stamps| {
            *stamps = LinkStamps {
                established_at: Some(1),
                last_inbound_at: Some(2),
                last_outbound_at: Some(3),
            }
        });
        actions.reset_for_reopen();
        assert_eq!(actions.link.stamps(), LinkStamps::default());
    }
}
