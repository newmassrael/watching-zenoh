// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! R2827 — the MCU session with its application layer attached.
//!
//! `wz_runtime_coop::session_drive` decodes every inbound frame and hands the
//! batch to its caller's `on_event`, and stops there. Until this module nothing
//! in the MCU stack took it further in production: the only caller counted
//! frames, and the application-layer dispatch (`ApplicationLayerObserver`, the
//! one the AP runs) was reached on the MCU only from tests. A Push therefore had
//! no subscriber to land on and a query no queryable to answer it, however the
//! firmware was written.
//!
//! `crate::app_layer::dispatch_to` is that missing step, as an `on_event` value
//! both session drivers take (`wz_runtime_coop::session_drive::run_session` and
//! `wz_runtime_coop::session_drive::spawn_session`): every iteration's event goes
//! to the observer, and whatever the observer staged — replies and their finals,
//! declare replies — goes out through the SAME session's action bundle, which
//! is what the AP's `observer.dispatch(event, &actions)` does.
//!
//! The observer is shared (`Rc<RefCell<..>>`), because the firmware registers
//! its subscribers and queryables on it while the session runs, and a spawned
//! session must own its share. `!Send` is fine: the MCU session runs on a
//! local set, which is the reason the bundle is `Rc` in the first place.

// S9e -- the observer these dispatch to registers heap-boxed sinks, so everything
// that names it is the heap profile's; what a build with no allocator keeps is the
// event seam ([`SessionEvents`]) and the reply sink that discards ([`NoReplies`]),
// which an image's own dispatcher is written against.
#[cfg(feature = "alloc")]
use core::cell::RefCell;

#[cfg(feature = "alloc")]
use core::ops::Deref;

#[cfg(any(feature = "alloc", feature = "session-slot"))]
use wz_runtime_coop::{ClockSource, CoopRuntime, CoopTime};
use wz_session_core::driver_loop::IterationEvent;
#[cfg(feature = "alloc")]
use wz_session_core::observer::ApplicationLayerObserver;
#[cfg(feature = "session-slot")]
use wz_session_core::reply_sink::{ReplySink, ReplyView};
#[cfg(feature = "alloc")]
use wz_session_core::session_actions::SessionLinkActions;
#[cfg(feature = "session-slot")]
use wz_session_core::session_slot::SlotRef;
#[cfg(feature = "session-slot")]
use wz_session_core::slot_observer::{
    AlreadyInitialised, DefaultSinks, ObserverCell, ObserverSinks, Requesters, SlotObserverOf,
};

/// The `on_event` that dispatches each iteration to `observer` and drains its
/// staged output through `actions`, the session's own send path.
///
/// Pass the same `actions` the session is driven with: a reply drained
/// through a different bundle would go out on a different session.
///
/// `actions` is the session handle of the profile: an `Rc` of the bundle, or under
/// `session-slot` a counted reference to the slot that holds it. It is taken as
/// anything that derefs to the bundle, which is what lets the clock type `C` be
/// read off the handle at the call site (a handle named through the runtime's
/// associated type would leave `C` to be spelled out).
///
/// `observer` is anything that derefs to the shared observer cell (an
/// `Rc<RefCell<ApplicationLayerObserver>>`, the form every caller has), and is named
/// by what it derefs to and not by `Rc`, so that this crate links no `alloc` of its
/// own under `session-slot`. That observer holds a session's peer-written tables
/// beside the application's, in the growable form; the slot profile's own form is
/// `dispatch_slot` over a process-wide `SlotObserver` and the session's tables in its
/// slot.
#[cfg(feature = "alloc")]
pub fn dispatch_to<C, H, O>(observer: O, actions: H) -> impl FnMut(IterationEvent<'_>) + 'static
where
    C: ClockSource + 'static,
    H: Deref<Target = SessionLinkActions<CoopRuntime<C>, CoopTime<C>>> + 'static,
    O: Deref<Target = RefCell<ApplicationLayerObserver>> + 'static,
{
    move |event| observer.borrow_mut().dispatch(event, &*actions)
}

/// A reply sink for a session that asks nothing: a pending query of its own never
/// exists, so nothing is ever delivered to it. The closed, allocation-free type a
/// node that only ANSWERS (the admin node) gives `Requesters`, where the heap profile
/// would box a closure per query.
#[cfg(feature = "session-slot")]
#[derive(Debug, Default, Clone, Copy)]
pub struct NoReplies;

#[cfg(feature = "session-slot")]
impl ReplySink for NoReplies {
    fn on_reply(&mut self, _reply: &dyn ReplyView) {}

    fn on_final(&mut self, _rid: u64) {}
}

/// What the application registered on the slot profile, in a place the sessions'
/// `on_event`s all reach: the process-wide `SlotObserver`, installed once at
/// startup into a `static`.
///
/// `SlotObserver::new` is not `const` (its registries are built, not zeroed), so the
/// `static` is an empty cell and the image builds the observer IN it and registers on
/// it, once, before the first session runs:
///
/// ```ignore
/// static APP: SlotApp = SlotApp::new();
/// let (observer, registered) = APP
///     .install_with(|observer| observer.subscribers.register_sink(..))
///     .ok()
///     .expect("installed once");
/// ```
///
/// In place, and not by value: the observer is about 16 KB, and an install that takes it
/// as an argument holds it again in every call that hands it on (four copies, 69 KB of
/// the Zephyr node's main frame, on a 32 KB stack).
///
/// Like every table of the profile it is `Sync` by the profile's rule: one
/// cooperative task on one core drives every session and so reaches the observer, and
/// never two at once.
#[cfg(feature = "session-slot")]
pub struct SlotApp<K: ObserverSinks = DefaultSinks> {
    observer: ObserverCell<K>,
}

// SAFETY: the profile's rule, stated on the type. The observer is reached by the one
// cooperative task that drives the node's sessions and, at startup, by the image
// before any session runs, never from an interrupt and never by two at once.
#[cfg(feature = "session-slot")]
unsafe impl<K: ObserverSinks> Sync for SlotApp<K> {}

#[cfg(feature = "session-slot")]
impl<K: ObserverSinks> SlotApp<K> {
    /// An application with no observer yet, for a `static`.
    pub const fn new() -> Self {
        Self {
            observer: ObserverCell::new(),
        }
    }

    /// Build the observer in the application, once, and hand it to `register`, which
    /// registers the image's sinks on it. Returns the cell the sessions dispatch to and
    /// what `register` returned. A second install leaves the observer as it was.
    ///
    /// # Errors
    ///
    /// [`AlreadyInitialised`] if an observer was installed before.
    pub fn install_with<R>(
        &'static self,
        register: impl FnOnce(&mut SlotObserverOf<K>) -> R,
    ) -> Result<(&'static ObserverCell<K>, R), AlreadyInitialised>
    where
        K: 'static,
    {
        let registered = self.observer.init_with(register)?;
        Ok((&self.observer, registered))
    }

    /// The installed observer's cell, if one was installed.
    pub fn get(&'static self) -> Option<&'static ObserverCell<K>>
    where
        K: 'static,
    {
        self.observer.is_initialised().then_some(&self.observer)
    }
}

#[cfg(feature = "session-slot")]
impl<K: ObserverSinks> Default for SlotApp<K> {
    fn default() -> Self {
        Self::new()
    }
}

/// What a session on the slot profile reports its iterations to, as a NAMEABLE type:
/// a closure cannot be named in an associated type, and a node that makes sessions
/// two ways (it dials and it accepts) names the application layer of both once.
/// `SlotDispatch` is the shell's own; an image with another application layer
/// implements the trait for its own type.
#[cfg(feature = "session-slot")]
pub trait SessionEvents {
    /// One iteration of the session's drive loop.
    fn on_event(&mut self, event: IterationEvent<'_>);
}

/// The application layer of one session on the slot profile: each iteration's event
/// goes to the process-wide `observer`, against THIS session's peer-written tables (in
/// its slot, reached through `handle`) and its own `requesters`, and what the observer
/// staged is drained through the session's own send path. The slot twin of
/// `dispatch_to`, with the same rule: build it over the handle the session is driven
/// with.
///
/// It owns the handle (a counted reference to the slot, so the slot lives as long as
/// the task that holds it) and the session's requesters; its size is what the
/// runtime's task cell has to hold beside the pump's handle.
#[cfg(feature = "session-slot")]
pub struct SlotDispatch<C, R, G, K = DefaultSinks>
where
    C: ClockSource + 'static,
    R: ReplySink,
    G: ReplySink,
    K: ObserverSinks + 'static,
{
    observer: &'static ObserverCell<K>,
    handle: SlotRef<CoopRuntime<C>, CoopTime<C>>,
    requesters: Requesters<R, G>,
}

#[cfg(feature = "session-slot")]
impl<C, R, G, K> SlotDispatch<C, R, G, K>
where
    C: ClockSource + 'static,
    R: ReplySink,
    G: ReplySink,
    K: ObserverSinks + 'static,
{
    /// The application layer of the session `handle` names, over `observer`.
    pub fn new(
        observer: &'static ObserverCell<K>,
        handle: SlotRef<CoopRuntime<C>, CoopTime<C>>,
        requesters: Requesters<R, G>,
    ) -> Self {
        Self {
            observer,
            handle,
            requesters,
        }
    }
}

#[cfg(feature = "session-slot")]
impl<C, R, G, K> SessionEvents for SlotDispatch<C, R, G, K>
where
    C: ClockSource + 'static,
    R: ReplySink,
    G: ReplySink,
    K: ObserverSinks + 'static,
{
    fn on_event(&mut self, event: IterationEvent<'_>) {
        let mut peers = self.handle.peers().borrow_mut();
        self.observer
            .borrow_mut()
            .dispatch(&mut peers, &mut self.requesters, event, &*self.handle);
    }
}

/// [`SlotDispatch`] as the `on_event` closure a session driver takes.
#[cfg(feature = "session-slot")]
pub fn dispatch_slot<C, R, G, K>(
    observer: &'static ObserverCell<K>,
    handle: SlotRef<CoopRuntime<C>, CoopTime<C>>,
    requesters: Requesters<R, G>,
) -> impl FnMut(IterationEvent<'_>) + 'static
where
    C: ClockSource + 'static,
    R: ReplySink + 'static,
    G: ReplySink + 'static,
    K: ObserverSinks + 'static,
{
    let mut dispatch = SlotDispatch::new(observer, handle, requesters);
    move |event| dispatch.on_event(event)
}

#[cfg(all(
    test,
    feature = "query-queryable",
    feature = "codec-response",
    feature = "pubsub-put",
    not(feature = "session-slot")
))]
mod tests {
    use super::*;
    use alloc::boxed::Box;
    use alloc::rc::Rc;
    use alloc::vec;
    use alloc::vec::Vec;
    use core::sync::atomic::{AtomicUsize, Ordering};

    use wz_codecs::push::{Push, PushVariant};
    use wz_codecs::query::Query;
    use wz_codecs::request::{Request, RequestVariant};
    use wz_codecs::wireexpr::{Wireexpr, WireexprVariant};
    use wz_codecs::wireexpr_nonlocal::WireexprNonlocal;
    use wz_runtime_coop::session_drive::{SessionDatagramLink, UdpPeer};
    use wz_session_core::driver_loop::DriverLoopOutcome;
    use wz_session_core::link::BoxedLinkDriver;
    use wz_session_core::network_message::NetworkMessage;
    use wz_session_core::session_init_params::SessionInitParams;
    use wz_session_core::signing_key::SigningKey;
    use wz_session_core::WhatAmI;

    use crate::memory::MemoryNetwork;

    #[derive(Clone, Default)]
    struct FrozenClock;
    impl ClockSource for FrozenClock {
        fn now_us(&self) -> u64 {
            0
        }
    }

    fn params() -> SessionInitParams {
        SessionInitParams {
            version: 0x05,
            whatami: WhatAmI::Peer,
            zid: vec![0x01, 0x02, 0x03, 0x04],
            seq_num_res: 2,
            req_id_res: 2,
            batch_size: 1024,
            lease_ms: 10_000,
            initial_sn: 0,
            cookie: vec![0u8; 16],
            tx_queue: wz_session_core::session_init_params::TxQueueConf::default(),
            cookie_signing_key: SigningKey::new(vec![7u8; 32]).expect(">=32-byte key"),
        }
    }

    fn wire(suffix: &str) -> Wireexpr<'_> {
        Wireexpr {
            body: WireexprVariant::WireexprNonlocal(WireexprNonlocal {
                id: 0,
                suffix_len: Some(suffix.len() as u64),
                suffix: Some(suffix),
            }),
        }
    }

    fn frame(messages: Vec<NetworkMessage>) -> DriverLoopOutcome {
        DriverLoopOutcome::FramePayload {
            priority: wz_session_core::qos::Priority::DEFAULT,
            reliable: true,
            sn: 0,
            messages,
            has_ext: false,
            extensions: Vec::new(),
        }
    }

    /// The whole seam on a link between two ends: a Push reaches the subscriber
    /// the firmware registered, and a query's reply leaves on the session's own
    /// link. The CONTROL is the same event with no registration: nothing
    /// fires, and the reply's payload is not on the wire. Something IS sent
    /// then — an unanswered query is still terminated with a ResponseFinal,
    /// which is zenoh's behaviour — so the witness is the reply's own bytes,
    /// not the number of datagrams.
    #[test]
    fn a_push_reaches_its_subscriber_and_a_reply_leaves_on_the_session() {
        let net = MemoryNetwork::new();
        let node_at = UdpPeer {
            addr: [10, 0, 0, 1],
            port: 7471,
        };
        let peer_at = UdpPeer {
            addr: [10, 0, 0, 2],
            port: 7472,
        };
        let driver = net.bind(node_at, Some(peer_at)).expect("bind node end");
        let peer = net.bind(peer_at, Some(node_at)).expect("bind peer end");

        let runtime = CoopRuntime::new(FrozenClock);
        let clock = CoopTime::new(&runtime);
        let sink: Rc<dyn BoxedLinkDriver> = driver.clone();
        let actions =
            SessionLinkActions::<CoopRuntime<FrozenClock>, CoopTime<FrozenClock>>::new_generic(
                sink,
                params(),
                clock,
            );

        let observer = Rc::new(RefCell::new(ApplicationLayerObserver::new()));
        let mut on_event = dispatch_to(observer.clone(), actions.clone());
        static PUSHES: AtomicUsize = AtomicUsize::new(0);

        let push = || {
            let mut push = Push {
                keyexpr: wire("home/temp"),
                ..Push::default()
            };
            if let PushVariant::CodecZenohMsgPut(ref mut put) = push.body {
                put.payload_len = Some(4);
                put.payload = Some(b"21.0");
            }
            NetworkMessage::Push(Box::new(push.try_into_owned().unwrap()))
        };
        let query = || {
            let request = Request {
                rid: 42,
                keyexpr: wire("svc/a"),
                body: RequestVariant::CodecZenohQuery(Query::default()),
                ..Request::default()
            };
            NetworkMessage::Request(Box::new(request.try_into_owned().unwrap()))
        };
        // Whether any datagram the peer received carries the reply payload.
        let peer_saw_pong = || {
            let mut seen = false;
            while let Some(frame) = peer.try_recv() {
                seen |= frame.bytes.windows(4).any(|w| w == b"pong");
            }
            seen
        };

        // CONTROL: nothing registered, so nothing fires and no reply leaves.
        on_event(IterationEvent::Poll(&frame(vec![push(), query()])));
        std::assert!(!peer_saw_pong(), "no queryable, no reply payload");
        std::assert_eq!(PUSHES.load(Ordering::SeqCst), 0);

        // Through the fallible `*_sink` registrations, the ones that exist on
        // both bounded backings: this crate is also built with
        // `bounded-heapless`, which compiles out the infallible wrappers.
        observer
            .borrow_mut()
            .subscribers
            .register_sink(
                "home/temp",
                wz_session_core::locality::Locality::Any,
                wz_session_core::sink::BoxedSink::new(|_| {
                    PUSHES.fetch_add(1, Ordering::SeqCst);
                }),
            )
            .expect("a fresh observer takes the subscriber");
        observer
            .borrow_mut()
            .queryables
            .register_sink(
                "svc/a",
                wz_session_core::locality::Locality::Any,
                false,
                wz_session_core::query_sink::BoxedQuerySink::new(|_query, responder| {
                    responder.reply(b"pong");
                }),
            )
            .expect("a fresh observer takes the queryable");

        on_event(IterationEvent::Poll(&frame(vec![push(), query()])));
        std::assert_eq!(
            PUSHES.load(Ordering::SeqCst),
            1,
            "the Push reached its subscriber"
        );
        std::assert_eq!(
            observer.borrow().pending_reply_count(),
            0,
            "the staged reply was drained, not left behind"
        );
        std::assert!(peer_saw_pong(), "the reply left on the session's link");
    }
}
