// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! A client of a router that answers queries, on the slot profile: the node of
//! `crate::client_node` with every session, table and text in storage the image declared and no
//! allocator.
//!
//! It dials the endpoints of an [`EndpointSource`] the image knows at build time
//! ([`StaticEndpoints`](crate::connect_manager::StaticEndpoints)), keeps a session with each and
//! re-dials the ones that drop (the connect manager), and sends the declarations of the queryables
//! and subscribers it answers on every session as it establishes. What answers a query or takes a
//! sample is the observer the sessions dispatch to, built and registered by the image beforehand
//! as the admin node's is (`SlotApp`): a registration that was refused stops the image, rather
//! than starting a node that declares what nothing answers.
//!
//! | what | where | bound |
//! | --- | --- | --- |
//! | sessions it dials | `SessionSlots` / `PumpSlots` / the task table of the host | the pool's `max_sessions`, `process.max_tasks` |
//! | endpoints it manages | the connect manager's rows | `caps::MAX_STATIC_CONNECT` |
//! | the declarations | a `&'static` slice the image states | its length |
//!
//! Nothing is grown and nothing falls back to the heap; this module does not link `alloc` on the
//! profile at all.

use core::cell::RefCell;

use wz_runtime_coop::session_drive::SlotStack;
use wz_runtime_coop::session_runtime::SessionHandle;
use wz_runtime_coop::ClockSource;
use wz_session_core::encoding::PACKED_APPLICATION_JSON;
use wz_session_core::locality::Locality;
use wz_session_core::pubsub::SubscriberTable;
use wz_session_core::query::QueryableRegistry;
use wz_session_core::query_sink::{FnQuerySink, QueryView, ReplyOut};
use wz_session_core::registry_error::RegisterError;
use wz_session_core::sample_kind::SampleKind;
use wz_session_core::session_timeouts::SessionTimeouts;
use wz_session_core::slot_observer::{NoSink, ObserverSinks};

use crate::connect_manager::{ConnectManager, EndpointSource};
use crate::latest::{LatestRef, LatestSink};
use crate::slot_dial::{Bind, SessionFactory, SlotDialer, SlotSession};
use crate::slot_host::SessionHost;

/// What a declaration announces to the router.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeclarationKind {
    /// A queryable: the router forwards a GET on the key to this node.
    Queryable,
    /// A subscriber: the router forwards a PUT on the key to this node.
    Subscriber,
}

/// One declaration the node sends on every session as it establishes. Its id on the wire is its
/// place in the node's list plus one, per session.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Declaration {
    /// What it announces.
    pub kind: DeclarationKind,
    /// The key it announces, as the registration on the observer names it.
    pub key: &'static str,
}

/// A client node on the slot profile over the stack `T`, binding its sockets with `B`.
pub struct SlotClientNode<'a, C, T, B, F, const S: usize, const P: usize>
where
    C: ClockSource + 'static,
    T: SlotStack,
    B: Bind<T::Driver>,
    F: SessionFactory<C>,
{
    manager: ConnectManager<SlotDialer<'a, C, T, B, F, S, P>>,
    declarations: &'static [Declaration],
}

impl<'a, C, T, B, F, const S: usize, const P: usize> SlotClientNode<'a, C, T, B, F, S, P>
where
    C: ClockSource + 'static,
    T: SlotStack,
    B: Bind<T::Driver>,
    F: SessionFactory<C>,
{
    /// A node that dials `endpoints` through `host` (sockets from `bind`, sessions made by
    /// `factory` with the handshake deadlines `timeouts`) and declares `declarations` on each
    /// session as it establishes.
    pub fn new(
        host: &'a SessionHost<C, T, F::Entropy, S, P>,
        bind: B,
        factory: &'a RefCell<F>,
        endpoints: &'static dyn EndpointSource,
        timeouts: SessionTimeouts,
        declarations: &'static [Declaration],
    ) -> Self {
        Self {
            manager: ConnectManager::new(endpoints, SlotDialer::new(host, bind, factory, timeouts)),
            declarations,
        }
    }

    /// Whether some session is established.
    pub fn is_established(&self) -> bool {
        self.manager
            .sessions()
            .any(|(_, session)| session.actions().is_established())
    }

    /// Whether some established session's peer is verified: the zid it claimed is the zid the
    /// key it proved inside a secure channel names (decisions D1 and D9 of
    /// `docs/session-lifecycle-intent.md`). `false` over a link that is no secure channel.
    pub fn peer_verified(&self) -> bool {
        self.manager.sessions().any(|(_, session)| {
            let actions = session.actions();
            actions.is_established() && actions.peer_identity_verified()
        })
    }

    /// Ask every session's drive loop to run its next iteration now, however long its link was
    /// going to sleep. For an application that has just left something for a session's layer
    /// (a query in a [`GetMailbox`](crate::get_mailbox::GetMailbox)): the layer takes it on its
    /// next event, and without this that event waits for the link's idle wait to run out. The
    /// layer states its own deadline again on that event, so this costs one iteration.
    ///
    /// Only with `query-get`, the feature whose layer does state it again: without that, the
    /// deadline this sets would stay and the loop would never sleep.
    #[cfg(feature = "query-get")]
    pub fn wake(&self) {
        for (_, session) in self.manager.sessions() {
            session.actions().set_app_wake_deadline_ms(Some(0));
        }
    }

    /// Whether the node holds a session, established or still opening. A node that holds none has
    /// no socket either, so its loop sleeps rather than spin above the network stack's threads.
    pub fn holds_session(&self) -> bool {
        self.manager.sessions().next().is_some()
    }

    /// Advance the node to `now_ms`: keep the sessions in step with the endpoints, and send the
    /// declarations on every established session that has not had them.
    pub fn tick(&mut self, now_ms: u64) {
        self.manager.tick(now_ms);
        for (_, session) in self.manager.sessions() {
            if session.actions().is_established()
                && !session.declared()
                && declare_all(session, self.declarations)
            {
                session.mark_declared();
            }
        }
    }
}

/// Send the declarations on `session`: `true` once every one went out. A declaration that did not
/// (the session's stage was busy) leaves the rest for the next tick, which repeats the whole list;
/// a router that sees a declaration twice under one id takes the second as the first.
fn declare_all<C: ClockSource + 'static>(
    session: &SlotSession<C>,
    declarations: &[Declaration],
) -> bool {
    declarations
        .iter()
        .enumerate()
        .all(|(index, declaration)| declare(session.actions(), index as u64 + 1, declaration))
}

/// Send one declaration under `id`: `true` once it went out.
fn declare<C: ClockSource + 'static>(
    actions: &SessionHandle<C>,
    id: u64,
    declaration: &Declaration,
) -> bool {
    // `complete: false` is upstream's `QueryableInfoType::DEFAULT`.
    match declaration.kind {
        DeclarationKind::Queryable => actions
            .send_declare_queryable(id, 0, Some(declaration.key), false)
            .is_ok(),
        DeclarationKind::Subscriber => actions
            .send_declare_subscriber(id, 0, Some(declaration.key))
            .is_ok(),
    }
}

/// What a queryable answers with: one fixed JSON document, or the latest sample a subscription of
/// the node kept.
#[derive(Clone, Copy)]
pub enum Answer {
    /// A fixed document, answered under the key the query asked.
    Document(&'static str),
    /// The payload of a cell of the node's subscriptions, as it arrived. Nothing is answered while
    /// no sample has reached the cell, so a querier gets the final of an empty reply and not an
    /// invented value.
    Latest(LatestRef),
}

/// A queryable that answers every query with one JSON document, or from a subscription's latest
/// sample, under the key the query asked (`z_query_keyexpr`, as zenoh-pico's comparison image
/// replies): a function and what it answers with, stored inline, so the registry that holds it is
/// typed by it and the registration allocates nothing.
pub type DocumentSink = FnQuerySink<Answer>;

/// The observer's registrations of a client that answers documents and keeps what it subscribes to:
/// queryables of [`DocumentSink`], subscriptions of [`LatestSink`], and none of the other kinds.
pub struct DocumentSinks;

impl ObserverSinks for DocumentSinks {
    type Subscriber = LatestSink;
    type Queryable = DocumentSink;
    type Declared = NoSink;
    type Undeclared = NoSink;
}

fn answer(source: &mut Answer, query: &dyn QueryView, out: &mut dyn ReplyOut) {
    match *source {
        Answer::Document(body) => {
            let _ = out.reply_keyed_encoded_parts(
                query.keyexpr(),
                body.as_bytes(),
                PACKED_APPLICATION_JSON,
                None,
            );
        }
        Answer::Latest(cell) => cell.slots.with(cell.index, &mut |latest| {
            // A delete is not a value to answer with.
            if let Some(latest) = latest.filter(|l| l.kind == SampleKind::Put) {
                let _ = out.reply_keyed(query.keyexpr(), latest.payload);
            }
        }),
    }
}

/// Register on `queryables` a queryable under `key` that answers every query with `body`. `Err`
/// when the registry is full or `key` does not fit, which stops an image rather than starting it
/// declaring what nothing answers.
pub fn register_document(
    queryables: &mut QueryableRegistry<DocumentSink>,
    key: &str,
    body: &'static str,
) -> Result<(), RegisterError> {
    register_answer(queryables, key, Answer::Document(body))
}

/// Register on `queryables` a queryable under `key` that answers with `source`. The refusals are
/// [`register_document`]'s.
pub fn register_answer(
    queryables: &mut QueryableRegistry<DocumentSink>,
    key: &str,
    source: Answer,
) -> Result<(), RegisterError> {
    queryables
        .register_sink(key, Locality::Any, false, FnQuerySink::new(source, answer))
        .map(|_id| ())
}

/// Register on `subscribers` a subscription under `key` that keeps the latest sample in `sink`'s
/// cell. `Err` when the table is full or `key` does not fit, which stops an image rather than
/// starting it declaring what nothing takes.
pub fn register_latest(
    subscribers: &mut SubscriberTable<LatestSink>,
    key: &str,
    sink: LatestSink,
) -> Result<(), RegisterError> {
    subscribers
        .register_sink(key, Locality::Any, sink)
        .map(|_id| ())
}
