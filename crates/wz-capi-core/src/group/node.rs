// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! A group a router node holds for the program that opened it.
//!
//! The registry joins one wz group for each face it holds and one for its local plane, and the
//! aggregate ([`GroupAggregate`]) takes their union, because each of those sessions sees only the
//! members its own link reaches. A node is one data plane: what it publishes reaches every face
//! and its own hosted subscribers, and what its faces publish reaches its hosted subscriber. So a
//! node joins ONE copy, hosted over the port's engine ([`SessionEngine`], which the node is), and
//! the aggregate is the same one with one source in its union.
//!
//! The membership rules are [`wz_session_core::group_view`]'s, the ones the runtime's own group
//! runs: the same keys, the same ids refused, the same table of leases and the same reaction to an
//! event. What is the host's here is the transport: the join announces itself on the event key,
//! the event subscriber and the member's queryable are hosted on the node's data plane, the
//! keep-alive and the watchdog are the node's own periodic jobs (no tokio runtime is asked for),
//! and a member heard of by its beacon alone is asked for its record by a query of the node's own
//! face.

use std::sync::{Arc, Mutex, PoisonError};

use wz_capi_port::{
    QblId, QueryCallback, QueryHolder, QueryableSink, SessionEngine, SubId, SubscriberSink, Ticker,
    WireKey,
};
use wz_session_core::group_membership::{
    decode_member, decode_net_event, encode_member, encode_net_event, GroupNetEvent, Member,
    MemberLiveliness,
};
use wz_session_core::group_view::{
    check_ids, event_keyexpr, keepalive_period_ms, member_keyexpr, react, GroupEvent, IdError,
    MemberTable, Reaction, MEMBER_QUERY_TIMEOUT_MS, WATCHDOG_PERIOD_MS,
};
use wz_session_core::locality::Locality;
use wz_session_core::query_options::QueryOptions;
use wz_session_core::query_sink::{QueryView, ReplyOut};
use wz_session_core::reply_sink::ReplyView;
use wz_session_core::sink::SampleView;

use super::{GroupAggregate, Via};
use crate::drive::RouterState;

/// Why a node could not join a group.
#[derive(Debug)]
pub enum NodeGroupError {
    /// A group or member id may not join.
    Id(IdError),
    /// The node refused a declaration the group is made of, or could not carry its announcement.
    Refused(&'static str),
}

/// What the callbacks of one copy hold: the leases it tracks and where its events go.
struct NodeCopy {
    gid: String,
    local_mid: String,
    members: Mutex<MemberTable>,
    agg: Arc<GroupAggregate>,
    via: Via,
    engine: Arc<dyn SessionEngine>,
}

impl NodeCopy {
    fn table(&self) -> std::sync::MutexGuard<'_, MemberTable> {
        self.members.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// One event heard on the group's event key.
    fn heard(self: &Arc<Self>, event: GroupNetEvent) {
        let reaction = react(
            &mut self.table(),
            &self.local_mid,
            event,
            self.engine.now_ms(),
        );
        match reaction {
            Reaction::Joined(member) => self.agg.apply(self.via, GroupEvent::Join(member)),
            Reaction::Left(mid) => self.agg.apply(self.via, GroupEvent::Leave(mid)),
            Reaction::Unknown(mid) => self.ask(mid),
            Reaction::None => {}
        }
    }

    /// Ask a member heard of by its beacon alone for its record, which the member's own queryable
    /// serves, and take the record into the view.
    fn ask(self: &Arc<Self>, mid: String) {
        let key = member_keyexpr(&self.gid, &mid);
        // Every answer, not the newest per key: one member answers on one key, but a loopback and
        // a wire answer to the same key must both reach the view, as the runtime's group pins it.
        let options = QueryOptions::get()
            .with_allowed_destination(Locality::Any)
            .with_timeout_ms(MEMBER_QUERY_TIMEOUT_MS)
            .with_consolidation(wz_session_core::query_mode::ConsolidationMode::None);
        let copy = Arc::clone(self);
        let _ = self
            .engine
            .get_on_wire(&key, &WireKey::literal(), &options, None, &mut || {
                let copy = Arc::clone(&copy);
                Box::new(move |reply: &dyn ReplyView| {
                    if let Ok(member) = decode_member(reply.payload()) {
                        copy.table().insert(member.clone(), copy.engine.now_ms());
                        copy.agg.apply(copy.via, GroupEvent::Join(member));
                    }
                })
            });
    }

    /// The watchdog's body: evict every member whose lease has passed.
    fn sweep(&self) {
        let expired = self.table().sweep(self.engine.now_ms());
        for mid in expired {
            self.agg.apply(self.via, GroupEvent::LeaseExpired(mid));
        }
    }
}

/// What the engine holds for a copy, retracted in the order the runtime's group retracts them: the
/// beacon and the watchdog stop first, then the subscriber and the queryable go.
struct Held {
    engine: Arc<dyn SessionEngine>,
    keep_alive: Option<Ticker>,
    watchdog: Option<Ticker>,
    subscriber: SubId,
    queryable: QblId,
}

impl Drop for Held {
    fn drop(&mut self) {
        // The jobs stop first: a beacon or a sweep must not run against what is being retracted.
        drop(self.keep_alive.take());
        drop(self.watchdog.take());
        self.engine.undeclare_subscriber(self.subscriber);
        self.engine.undeclare_queryable(self.queryable);
    }
}

/// A group joined on a node: the member, the copy the node holds and the aggregate the C program
/// reads. Dropping it leaves the group.
pub struct NodeGroup {
    held: Option<Held>,
    agg: Arc<GroupAggregate>,
}

impl NodeGroup {
    /// Join `gid` as `member` on `node`: announce the member on the event key, host the event
    /// subscriber and the member's queryable, and start the beacon (for a member whose liveliness is
    /// automatic) and the watchdog. The aggregate answers the view, the leader and the events.
    pub fn join(
        node: &Arc<RouterState>,
        gid: String,
        member: Member,
        priority: wz_runtime_tokio::qos::Priority,
    ) -> Result<Self, NodeGroupError> {
        check_ids(&gid, &member.mid).map_err(NodeGroupError::Id)?;
        let engine = node.as_engine();
        let agg = Arc::new(GroupAggregate::new(gid.clone(), member.clone()));
        let copy = Arc::new(NodeCopy {
            gid: gid.clone(),
            local_mid: member.mid.clone(),
            members: Mutex::new(MemberTable::new()),
            agg: Arc::clone(&agg),
            via: Via::fresh(),
            engine: Arc::clone(&engine),
        });
        let event_key = event_keyexpr(&gid);
        let options = wz_runtime_tokio::group::event_publish_options(priority, Locality::Any);

        // The member is announced BEFORE the subscriber is declared, so that it never hears its
        // own join (a peer that already joined sees it; this one does not).
        engine
            .publish_on_wire_all(
                &event_key,
                &WireKey::literal(),
                &encode_net_event(&GroupNetEvent::Join(member.clone())),
                &options,
            )
            .map_err(|_| NodeGroupError::Refused("the join could not be announced"))?;

        let heard = Arc::clone(&copy);
        let sink: SubscriberSink = Arc::new(move || {
            let heard = Arc::clone(&heard);
            Box::new(move |sample: &dyn SampleView| {
                if let Ok(event) = decode_net_event(sample.payload()) {
                    heard.heard(event);
                }
            })
        });
        let subscriber = engine.declare_subscriber_on_wire(
            event_key.clone(),
            WireKey::literal(),
            Locality::Any,
            None,
            sink,
        );

        // The member's own record, served from its own key to whoever asks.
        let record = encode_member(&member);
        let record_key = member_keyexpr(&gid, &member.mid);
        let served = record_key.clone();
        let answer: QueryableSink = Arc::new(move |_holder: Arc<dyn QueryHolder>| {
            let (record, served) = (record.clone(), served.clone());
            Box::new(move |_view: &dyn QueryView, out: &mut dyn ReplyOut| {
                // Declared on the very key it answers under, so every query that reaches it
                // intersects it and the reply cannot be refused.
                let _ = out.reply_keyed(&served, &record);
            }) as QueryCallback
        });
        let queryable = engine
            .declare_queryable_on_wire(
                record_key,
                WireKey::literal(),
                true,
                Locality::Any,
                None,
                answer,
            )
            .ok_or(NodeGroupError::Refused(
                "the member's queryable was refused",
            ))?;

        // The keep-alive beacon, for a member that asserts its liveliness on its own.
        let keep_alive = matches!(member.liveliness, MemberLiveliness::Auto)
            .then(|| {
                let beacon = encode_net_event(&GroupNetEvent::KeepAlive(member.mid.clone()));
                let sender = Arc::clone(&engine);
                let (key, options) = (event_key.clone(), options.clone());
                Ticker::start(
                    &engine,
                    keepalive_period_ms(member.lease, member.refresh_ratio),
                    Arc::new(move || {
                        // A beacon that cannot be sent is transient: the next tick sends again,
                        // and the peers' leases have not yet run out.
                        let _ = sender.publish_on_wire_all(
                            &key,
                            &WireKey::literal(),
                            &beacon,
                            &options,
                        );
                        true
                    }),
                )
            })
            .flatten();
        let watchdog = {
            let copy = Arc::clone(&copy);
            Ticker::start(
                &engine,
                WATCHDOG_PERIOD_MS,
                Arc::new(move || {
                    copy.sweep();
                    true
                }),
            )
            .ok_or(NodeGroupError::Refused("the watchdog could not be started"))?
        };

        Ok(Self {
            held: Some(Held {
                engine,
                keep_alive,
                watchdog: Some(watchdog),
                subscriber,
                queryable,
            }),
            agg,
        })
    }

    /// The aggregate the C program reads the view, the leader and the events from.
    pub fn aggregate(&self) -> &Arc<GroupAggregate> {
        &self.agg
    }
}

impl Drop for NodeGroup {
    /// Leave the group. The C sink is retired FIRST, so that the teardown cannot deliver into a
    /// group the C program has already released, and so that its `drop(context)` runs before this
    /// returns, unless this is called from inside that group's own callback, where the sink falls
    /// with the aggregate (see `GroupAggregate::retire`).
    fn drop(&mut self) {
        let sink = self.agg.retire();
        drop(self.held.take());
        drop(sink);
    }
}
