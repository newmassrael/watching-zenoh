// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! A node that is a CLIENT of a router and answers queries.
//!
//! `AdminNode` is a node a host reaches and reconfigures: it listens, hosts the admin space and a
//! config write, and dials what it is told to. A firmware that does one job for a router it was
//! built to know needs none of that, and a comparison with zenoh-pico's client (`z_open` in client
//! mode, `z_declare_queryable`) is a comparison of like with like only if wz can be that too. This
//! is that node:
//!
//! * the dialer and the connection manager, over a list of endpoints fixed when the image is built
//!   ([`crate::connect_manager::StaticEndpoints`]) or one a host writes
//!   ([`crate::connect_manager::EndpointSource`]);
//! * one observer, shared by every session, on which the application registers its queryables and
//!   subscribers;
//! * the declaration of each of them on every session as it establishes, since a router forwards a
//!   query or a push only to a face that declared a match, and forgets the declarations of a
//!   session that ended.
//!
//! No listener, no admin space, no config write, no accepted session. A firmware's loop is the
//! `AdminNode`'s: run the task set, service the network, `tick` the node with the time.

use alloc::boxed::Box;
use alloc::rc::Rc;
use alloc::string::String;
use alloc::vec::Vec;
use core::cell::RefCell;

use wz_runtime_coop::session_drive::SessionLinks;
use wz_runtime_coop::{ClockSource, CoopLocalSet};
use wz_session_core::limits::SessionLimits;
use wz_session_core::locality::Locality;
use wz_session_core::named_key::NamedKey;
use wz_session_core::observer::ApplicationLayerObserver;
use wz_session_core::query_sink::BoxedQuerySink;
use wz_session_core::registry_error::RegisterError;
use wz_session_core::session_init_params::SessionInitParams;
use wz_session_core::session_timeouts::SessionTimeouts;
use wz_session_core::sink::BoxedSink;

use crate::app_layer::dispatch_to;
use crate::connect_manager::{ConnectManager, EndpointSource};
use crate::dial::{EventSink, McuActions, UdpDialer};

/// Builds the sink each dialled session reports to.
type DialSink<C> = Box<dyn FnMut(&Rc<McuActions<C>>) -> EventSink>;

/// What the application asked the node to declare on every session.
enum Declaration {
    Queryable(String),
    Subscriber(String),
}

/// A client of a router that answers queries and receives pushes.
pub struct ClientNode<'a, L, C, P>
where
    L: SessionLinks,
    C: ClockSource + 'static,
    P: FnMut() -> SessionInitParams,
{
    observer: Rc<RefCell<ApplicationLayerObserver>>,
    manager: ConnectManager<UdpDialer<'a, L, C, P, DialSink<C>>>,
    /// The declarations, in the order they were registered. A declaration's id on the wire is its
    /// index plus one; ids are per session.
    declarations: Vec<Declaration>,
    /// The sessions the declarations have been sent on, by identity, and how many of them each
    /// has heard: a declaration registered after a session established is sent to it alone, and
    /// never twice, since a router reads a second declaration of an id as a different one.
    declared: Vec<(*const McuActions<C>, usize)>,
}

impl<'a, L, C, P> ClientNode<'a, L, C, P>
where
    L: SessionLinks,
    C: ClockSource + 'static,
    P: FnMut() -> SessionInitParams,
{
    /// A node that holds a session with each endpoint of `endpoints`, over the network `links`.
    /// `dial_params` gives each dialled session its parameters.
    ///
    /// The node's observer is every session's, so it is held to one snapshot of the session
    /// limits: the `limits` of the parameters `dial_params` gives, which it is asked for once
    /// here, before any dial, unless the build allows each limit one value.
    pub fn new(
        local: &'a CoopLocalSet<C>,
        links: Rc<L>,
        endpoints: &'static dyn EndpointSource,
        timeouts: SessionTimeouts,
        mut dial_params: P,
    ) -> Self {
        // A snapshot of no byte has one value, the build's: a build whose every limit is one value
        // asks the parameters nothing.
        let limits = if const { core::mem::size_of::<SessionLimits>() == 0 } {
            SessionLimits::BUILD
        } else {
            dial_params().limits
        };
        let observer = Rc::new(RefCell::new(ApplicationLayerObserver::with_limits(&limits)));
        let dial_observer = observer.clone();
        let on_event: DialSink<C> = Box::new(move |actions| {
            Box::new(dispatch_to(dial_observer.clone(), actions.clone())) as EventSink
        });
        let dialer = UdpDialer::new(local, links, timeouts, dial_params, on_event);
        Self {
            observer,
            manager: ConnectManager::new(endpoints, dialer),
            declarations: Vec::new(),
            declared: Vec::new(),
        }
    }

    /// The observer every session of this node dispatches to, for what the node has no helper
    /// for. A queryable or subscriber registered on it directly is not declared on a session; use
    /// [`Self::queryable`] and [`Self::subscriber`] for that.
    pub fn observer(&self) -> &Rc<RefCell<ApplicationLayerObserver>> {
        &self.observer
    }

    /// Answer the queries that intersect `key` with `answer`, on every session, present and to
    /// come. `Err` when the observer refuses the registration.
    pub fn queryable(&mut self, key: &str, answer: BoxedQuerySink) -> Result<(), RegisterError> {
        // `complete: false` is upstream's `QueryableInfoType::DEFAULT`.
        self.observer.borrow_mut().with_app(|app| {
            app.queryables
                .register_sink(key, Locality::Any, false, answer)
        })?;
        self.declarations
            .push(Declaration::Queryable(String::from(key)));
        Ok(())
    }

    /// Receive the pushes that intersect `key` with `sink`, on every session, present and to come.
    /// `Err` when the observer refuses the registration.
    pub fn subscriber(&mut self, key: &str, sink: BoxedSink) -> Result<(), RegisterError> {
        self.observer
            .borrow_mut()
            .register_subscriber(key, Locality::Any, sink)?;
        self.declarations
            .push(Declaration::Subscriber(String::from(key)));
        Ok(())
    }

    /// Whether the node holds a session at all, established or still being opened, and so a link
    /// that waits on its socket.
    ///
    /// A loop that leans on that wait to give the CPU away (Zephyr's does: a pass waits on its
    /// socket for up to a millisecond) has nothing to lean on while the node holds none, between
    /// two dials of a router that is not up. It must give the CPU away itself then, or it spins at
    /// its own priority and starves the network stack's threads, which are below it.
    pub fn holds_session(&self) -> bool {
        self.manager.sessions().next().is_some()
    }

    /// Whether a session towards a router is established.
    pub fn is_established(&self) -> bool {
        self.manager
            .sessions()
            .any(|(_, session)| session.actions().is_established())
    }

    /// Advance the node to `now_ms`: dial what is due, notice a session that ended, and declare
    /// what the application registered on every session that established.
    pub fn tick(&mut self, now_ms: u64) {
        self.manager.tick(now_ms);
        self.declare_on_new_sessions();
    }

    /// Send each established session the declarations it has not heard, and forget the sessions
    /// that are gone. A declaration that cannot be sent now is tried again at the next tick.
    fn declare_on_new_sessions(&mut self) {
        let live: Vec<&Rc<McuActions<C>>> =
            self.manager.sessions().map(|(_, s)| s.actions()).collect();
        self.declared
            .retain(|(done, _)| live.iter().any(|a| Rc::as_ptr(a) == *done));
        for actions in live {
            if !actions.is_established() {
                continue;
            }
            let key = Rc::as_ptr(actions);
            let row = match self.declared.iter().position(|(done, _)| *done == key) {
                Some(row) => row,
                None => {
                    self.declared.push((key, 0));
                    self.declared.len() - 1
                }
            };
            let sent = &mut self.declared[row].1;
            while *sent < self.declarations.len()
                && declare_one(actions, *sent, &self.declarations[*sent])
            {
                *sent += 1;
            }
        }
    }
}

/// Declare `declaration`, the `index`th, on `actions`: `true` once it went out.
fn declare_one<C: ClockSource + 'static>(
    actions: &McuActions<C>,
    index: usize,
    declaration: &Declaration,
) -> bool {
    let Some(id) = wz_session_core::wire_id::listed_entity_id(index) else {
        return false;
    };
    match declaration {
        Declaration::Queryable(key) => NamedKey::literal(key)
            .is_some_and(|key| actions.send_declare_queryable(id, key, false).is_ok()),
        Declaration::Subscriber(key) => NamedKey::literal(key)
            .is_some_and(|key| actions.send_declare_subscriber(id, key).is_ok()),
    }
}

// The far end of these tests is a plain acceptor session standing for the router, over the
// in-memory network.
#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    use wz_codecs::lent::{
        Query, Request, RequestVariant, Wireexpr, WireexprNonlocal, WireexprVariant,
    };
    use wz_runtime_coop::session_drive::{
        spawn_session, OpenedLink, SessionDriveConfig, SessionRole,
    };
    use wz_runtime_coop::session_runtime::new_session_actions;
    use wz_runtime_coop::{CoopRuntime, CoopTime};
    use wz_session_core::driver_loop::{DriverLoopOutcome, IterationEvent};
    use wz_session_core::network_message::NetworkMessage;
    use wz_session_core::sample::EncodingHint;

    use crate::connect_manager::StaticEndpoints;
    use crate::memory::{MemoryLinks, MemoryNetwork};

    #[derive(Clone, Default)]
    struct FrozenClock;
    impl ClockSource for FrozenClock {
        fn now_us(&self) -> u64 {
            0
        }
    }

    struct Counting(u8);
    impl wz_session_core::entropy::EntropySource for Counting {
        fn try_fill_bytes(
            &mut self,
            buf: &mut [u8],
        ) -> Result<(), wz_session_core::entropy::EntropyUnavailable> {
            for b in buf {
                self.0 = self.0.wrapping_add(1);
                *b = self.0;
            }
            Ok(())
        }
    }

    fn params(zid: u8) -> SessionInitParams {
        SessionInitParams {
            whatami: wz_session_core::WhatAmI::Client,
            zid: [zid; 4].into(),
            seq_num_res: 2,
            req_id_res: 2,
            batch_size: 1024,
            lease_ms: 10_000,
            keep_alive: wz_session_core::session_init_params::KeepAliveConf::PICO,
            initial_sn: 0,
            cookie: vec![],
            tx_queue: wz_session_core::session_init_params::TxQueueConf::of_snapshot(
                &wz_session_core::policy::SessionPolicy::defaults(),
                &wz_session_core::limits::SessionLimits::BUILD,
            ),
            link_rx: wz_session_core::session_init_params::LinkRxConf::default(),
            policy: wz_session_core::policy::SessionPolicy::defaults(),
            limits: wz_session_core::limits::SessionLimits::BUILD,
            cookie_signing_key: wz_session_core::signing_key::SigningKey::new(vec![7u8; 32])
                .expect("key"),
        }
    }

    fn get(key: &str, rid: wz_session_core::wire_id::RequestId) -> DriverLoopOutcome {
        let request = Request {
            rid,
            keyexpr: Wireexpr {
                body: WireexprVariant::WireexprNonlocal(WireexprNonlocal {
                    id: 0,
                    suffix_len: Some(key.len() as u64),
                    suffix: Some(wz_codecs::Bounded::new(key).unwrap()),
                }),
            },
            body: RequestVariant::CodecZenohQuery(Query::default()),
            ..Request::default()
        };
        DriverLoopOutcome::FramePayload {
            priority: wz_session_core::qos::Priority::DEFAULT,
            reliable: true,
            sn: 0,
            messages: vec![NetworkMessage::Request(Box::new(
                request
                    .try_into_owned_in::<wz_session_core::wire::WireStorage>()
                    .unwrap(),
            ))],
            has_ext: false,
            extensions: Vec::new(),
        }
    }

    /// What the router is shown: the declarations and the answers that reached it.
    #[derive(Default)]
    struct Seen {
        declares: core::cell::Cell<usize>,
        responses: core::cell::Cell<usize>,
        finals: core::cell::Cell<usize>,
    }

    /// The node dialled from a list fixed at build time declares what the application registered
    /// on the session once it is established, declares a registration made later on that session
    /// alone and never repeats one, and answers a query on a registered key with a reply and the
    /// final that closes it. The CONTROL is the same node before anything is registered: its
    /// session establishes and the router is told nothing.
    #[test]
    fn a_client_declares_what_is_registered_once_per_session_and_answers_a_query() {
        static ENDPOINTS: StaticEndpoints = StaticEndpoints::new(&["udp/10.0.0.1:7447"]);

        let net = MemoryNetwork::new();
        let node_links = Rc::new(MemoryLinks::new(net.clone(), [10, 0, 0, 2]));
        let far_links = MemoryLinks::new(net.clone(), [10, 0, 0, 1]);
        let runtime = CoopRuntime::new(FrozenClock);
        let local = CoopLocalSet::new(&runtime);

        let OpenedLink {
            sink: far_sink,
            pump: far_pump,
        } = far_links
            .open_acceptor(7447)
            .expect("bind the router's end");
        let far_actions =
            new_session_actions(far_sink, params(0xc3), CoopTime::new(&runtime), Counting(9));
        let seen = Rc::new(Seen::default());
        let router_sees = seen.clone();
        let _far = spawn_session(
            &local,
            far_pump,
            far_actions.clone(),
            CoopTime::new(&runtime),
            SessionDriveConfig {
                timeouts: SessionTimeouts::from_build(),
                role: SessionRole::Acceptor,
                max_iters: None,
            },
            move |event| {
                if let IterationEvent::Poll(DriverLoopOutcome::FramePayload { messages, .. }) =
                    event
                {
                    for m in messages {
                        match m {
                            NetworkMessage::Declare(_) => {
                                router_sees.declares.set(router_sees.declares.get() + 1)
                            }
                            NetworkMessage::Response(_) => {
                                router_sees.responses.set(router_sees.responses.get() + 1)
                            }
                            NetworkMessage::ResponseFinal(_) => {
                                router_sees.finals.set(router_sees.finals.get() + 1)
                            }
                            _ => {}
                        }
                    }
                }
                // A record the router's session reads where its frame lies, counted as its owned
                // form is: a Response on every in-place receive, a Declare and a ResponseFinal
                // where the build lends its control records.
                if let IterationEvent::InPlace(record) = event {
                    if record.declare().is_some() {
                        router_sees.declares.set(router_sees.declares.get() + 1)
                    }
                    if record.response().is_some() {
                        router_sees.responses.set(router_sees.responses.get() + 1)
                    }
                    if record.response_final().is_some() {
                        router_sees.finals.set(router_sees.finals.get() + 1)
                    }
                }
            },
        );

        let mut node = ClientNode::new(
            &local,
            node_links,
            &ENDPOINTS,
            SessionTimeouts::from_build(),
            || params(0xb1),
        );
        let settle = |node: &mut ClientNode<'_, _, _, _>| {
            for _ in 0..64 {
                local.run_until_idle();
                node.tick(0);
            }
        };

        // CONTROL: nothing registered, so a session that establishes has nothing to declare.
        std::assert!(
            !node.holds_session(),
            "before its first tick the node holds no session"
        );
        settle(&mut node);
        std::assert!(
            node.holds_session(),
            "the tick that dials leaves the node holding one"
        );
        std::assert!(
            node.is_established(),
            "the node dialled the endpoint it was built with"
        );
        std::assert!(
            far_actions.is_established(),
            "and the router holds the session too"
        );
        std::assert_eq!(
            seen.declares.get(),
            0,
            "CONTROL: nothing registered, nothing declared"
        );

        // A queryable registered after the session established reaches it, once.
        node.queryable(
            "@/test/status",
            BoxedQuerySink::new(|_query, out| {
                let _ = out.reply_keyed_encoded(
                    "@/test/status",
                    b"{\"ok\":true}",
                    Some(&EncodingHint::APPLICATION_JSON),
                );
            }),
        )
        .expect("a fresh observer takes the queryable");
        settle(&mut node);
        settle(&mut node);
        std::assert_eq!(
            seen.declares.get(),
            1,
            "the queryable is declared, and only once"
        );

        // A second registration is sent alone: the first is not sent again.
        node.subscriber(
            "@/test/config/**",
            BoxedSink::new(|_sample: &dyn wz_session_core::sink::SampleView| {}),
        )
        .expect("a fresh observer takes the subscriber");
        settle(&mut node);
        std::assert_eq!(seen.declares.get(), 2, "the subscriber alone is declared");

        // A query on the registered key is answered with a reply and its final.
        let actions = node
            .manager
            .sessions()
            .next()
            .map(|(_, session)| session.actions().clone())
            .expect("the session");
        let mut on_event = dispatch_to(node.observer().clone(), actions);
        on_event(IterationEvent::Poll(&get("@/test/status", 1)));
        settle(&mut node);
        std::assert_eq!(seen.responses.get(), 1, "the router received the reply");
        std::assert_eq!(seen.finals.get(), 1, "and the final that closes the query");
    }

    /// The node's observer is held to the session limits of the parameters it gives its
    /// sessions: with `MAX_SUBSCRIPTIONS` stated as two, a third subscriber is refused as a full
    /// table, and the refusal leaves the two subscribers and the two declarations. The CONTROL is
    /// the same node under the build's limits, which takes the third.
    #[test]
    fn the_observer_is_held_to_the_limits_of_the_session_parameters() {
        use wz_session_core::limit_binding::{LimitSpec, Quota};
        use wz_session_core::limits::MaxSubscriptions;
        static ENDPOINTS: StaticEndpoints = StaticEndpoints::new(&["udp/10.0.0.1:7447"]);

        let mut stated = SessionLimits::BUILD;
        if stated.select_max_subscriptions(Quota::at_most(2)).is_err() {
            // A build of one value refuses two: it has no other snapshot to hand the node.
            std::assert!(MaxSubscriptions::DOMAIN.is_singleton());
            return;
        }
        let net = MemoryNetwork::new();
        let runtime = CoopRuntime::new(FrozenClock);
        let local = CoopLocalSet::new(&runtime);
        let sink = || BoxedSink::new(|_sample: &dyn wz_session_core::sink::SampleView| {});

        let mut node = ClientNode::new(
            &local,
            Rc::new(MemoryLinks::new(net.clone(), [10, 0, 0, 2])),
            &ENDPOINTS,
            SessionTimeouts::from_build(),
            move || SessionInitParams {
                limits: stated,
                ..params(0xb1)
            },
        );
        node.subscriber("test/a", sink()).expect("under the quota");
        node.subscriber("test/b", sink()).expect("under the quota");
        std::assert_eq!(
            node.subscriber("test/c", sink()),
            Err(RegisterError::TableFull)
        );
        std::assert_eq!(
            node.observer()
                .borrow()
                .read_app(|app| app.subscribers.len()),
            2
        );
        std::assert_eq!(
            node.declarations.len(),
            2,
            "the refused one is not declared"
        );

        // CONTROL: the build's limits take the subscriber the stated ones refused.
        let mut control = ClientNode::new(
            &local,
            Rc::new(MemoryLinks::new(net.clone(), [10, 0, 0, 3])),
            &ENDPOINTS,
            SessionTimeouts::from_build(),
            || params(0xb2),
        );
        for key in ["test/a", "test/b", "test/c"] {
            control
                .subscriber(key, sink())
                .expect("the build's limits take it");
        }
        std::assert_eq!(
            control
                .observer()
                .borrow()
                .read_app(|app| app.subscribers.len()),
            3
        );
        std::assert_eq!(control.declarations.len(), 3);
    }
}
