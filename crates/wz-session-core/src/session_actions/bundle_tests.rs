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
        seq_num_res: 2,
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
            .expect("32-byte test key"),
        policy: crate::policy::SessionPolicy::defaults(),
        limits: crate::limits::SessionLimits::BUILD,
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

    use wz_runtime_core::Runtime;

    use super::{bundle, PlainRuntime};

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
        let routed = PlainRuntime::with_mutex_mut(&actions.remote_peer_zid, |slot| *slot);
        let bound = PlainRuntime::with_mutex_mut(&actions.inbound_peer_zid, |slot| *slot);
        let caps =
            PlainRuntime::with_mutex_mut(&actions.inbound_peer_init_caps, |slot| slot.is_some());
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
        let kept =
            PlainRuntime::with_mutex_mut(&actions.inbound_opensyn_cookie, |slot| slot.is_some());
        assert_eq!(kept, ACCEPTS, "the echoed cookie");
        assert!(
            PlainRuntime::with_mutex_mut(&actions.peer_open_lease_ms, |slot| slot.is_none()),
            "no lease is taken from an OpenSyn that was only read"
        );
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
    let sent =
        actions.send_plain_put_qos(key, b"v", None, true, false, crate::qos::Priority::DEFAULT);
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
