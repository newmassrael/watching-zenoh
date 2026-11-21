// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The multicast groups a session joins, as an ABI states them to whichever engine runs the
//! session: where each group is, what the session's beacon advertises on it and what the session
//! tells it of its own declarations. Each is the calling ABI's decision (zenoh-pico and zenoh
//! disagree on every one), and each engine reads the same rules from here, so the two engines
//! cannot judge a group differently.

use alloc::string::String;

use wz_session_core::declare_form::{GroupDeclaration, GroupKey, RetractionKey};
use wz_session_core::locality::Locality;
use wz_session_core::multicast_params::MulticastParams;
use wz_session_core::wire_id::EntityId;

use crate::WireKey;
use wz_session_core::policy::SessionPolicy;
use wz_session_core::session_init_params::{LinkRxConf, TxQueueConf};
use wz_session_core::session_zid::SessionZid;
use wz_session_core::WhatAmI;

/// Open-debt item 913 — a multicast group a session joins: the endpoint that names it, and
/// what the session advertises on it.
#[derive(Clone, Debug)]
pub struct GroupJoin {
    /// `udp/<group>:<port>`, with the socket keys of its metadata (`iface`, `ttl`, `join`,
    /// `bind`, `dscp`) read as a router's group locator reads them.
    pub endpoint: String,
    /// What the session's beacon advertises on the group.
    pub profile: GroupProfile,
    /// Whether the calling ABI's upstream reports the session's transports on this group as
    /// shared-memory ones: zenoh's does when the session holds a shared-memory context
    /// (`io/zenoh-transport/src/multicast/transport.rs` @ `self.shm_context.is_some()`), and
    /// zenoh-pico has no shared memory.
    pub is_shm: bool,
    /// What the session tells the group of its own declarations.
    pub declarations: GroupDeclarations,
}

/// Open-debt item 913 — what a session tells a group it joined of its own declarations, as the
/// calling ABI's upstream does.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum GroupDeclarations {
    /// Nothing: zenoh's session on Windows, where its announcement is compiled out, and what a
    /// face replays to a group of the entities the session held before the group came up,
    /// which neither upstream announces there.
    None,
    /// Each subscriber declared while the group is up, with id 0, and never retracted, as zenoh
    /// announces a session's subscriber on each group it holds (its queryables and tokens it
    /// does not announce there).
    Subscribers,
    /// Each subscriber, queryable and liveliness token declared while the group is up, with its
    /// own entity id and literal key, and retracted with both when it is undeclared, as
    /// zenoh-pico declares a session's entities over whatever transport it holds at its
    /// default (`vendor/zenoh-pico/src/net/primitives.c` @ `z_result_t _z_send_declare(`).
    Entities,
    /// What a unicast face is told, on the group: each keyexpr the session declares while the
    /// group is up, and each subscriber, queryable and liveliness token with its entity id on
    /// the key it was declared to the peers by, retracted naming its own key. And what the
    /// session asks: the members' keyexprs once, when the group comes up, and the members'
    /// subscribers or queryables for each write filter, whose answer then holds a put back on
    /// the group as on a unicast face. zenoh-pico with `Z_FEATURE_MULTICAST_DECLARATIONS`
    /// (`vendor/zenoh-pico/src/session/keyexpr.c` @ `#if Z_FEATURE_MULTICAST_DECLARATIONS == 0`,
    /// `vendor/zenoh-pico/src/api/api.c` @ `session->_tp._type == _Z_TRANSPORT_MULTICAST_TYPE ||`).
    Mapped,
}

impl GroupDeclarations {
    /// Whether a write filter asks the group, and so whether its answer holds a put back there:
    /// only with [`Self::Mapped`]. On any other group zenoh-pico sends whatever the filter says,
    /// and zenoh routes a group's data whatever its members declared.
    pub fn asks_for_filters(self) -> bool {
        self == Self::Mapped
    }

    /// Whether the group is told the session's keyexprs, and so names a key by its declaration
    /// there as a unicast face does: only with [`Self::Mapped`]. zenoh-pico declares no keyexpr
    /// on a multicast transport at its default.
    pub fn declares_keyexprs(self) -> bool {
        self == Self::Mapped
    }

    /// Whether a liveliness subscriber asks the group for its members' tokens: with
    /// [`Self::Entities`] and [`Self::Mapped`], the groups whose session is told its entities.
    /// zenoh-pico sends the subscriber's `Interest` over whatever transport it holds, a group
    /// included (`vendor/zenoh-pico/src/net/liveliness.c` @
    /// `z_result_t _z_declare_liveliness_subscriber(`, which sends through `_z_send_declare`).
    /// Without it the subscriber still hears every token a member announces.
    pub fn asks_for_liveliness(self) -> bool {
        matches!(self, Self::Entities | Self::Mapped)
    }

    /// Whether a get is asked on the group: with [`Self::Entities`] and [`Self::Mapped`], as
    /// zenoh-pico asks every peer its transport holds and waits for a final from each
    /// (`vendor/zenoh-pico/src/net/primitives.c` @
    /// `size_t remote_targets = allow_remote ? _z_transport_get_peers_count(&zn->_tp) : 0;`).
    /// zenoh routes no query onto a group: the group's face is held apart from the faces
    /// (`zenoh/src/net/routing/gateway.rs` @ `tables.data.hats[region].mcast_groups.push(face);`),
    /// the peer hat computes a query's route over the faces alone
    /// (`zenoh/src/net/routing/hat/peer/queries.rs` @ `fn compute_query_route(`) where it adds
    /// every group to a put's (`zenoh/src/net/routing/hat/peer/pubsub.rs` @
    /// `for group in self.multicast_groups(tables) {`), and a member's face sends nothing
    /// (`zenoh/src/net/routing/gateway.rs` @ `Arc::new(DummyPrimitives),`). Asked on such a
    /// group, a get would wait for a final from members that send none, and from a member that
    /// has not heard this session's JOIN yet and drops the query, while a consolidated get holds
    /// every reply it already has until then.
    pub fn asks_queries(self) -> bool {
        matches!(self, Self::Entities | Self::Mapped)
    }

    /// The id the group is told an entity of kind `what` and id `id` by, or `None` when it is
    /// told nothing of it: zenoh announces its subscribers alone, each as id 0, and zenoh-pico
    /// every subscriber, queryable and token by its entity id. An entity that takes its own
    /// session's traffic alone (`allowed_origin` session-local) is told to no group: neither
    /// upstream declares it to the network. The id is a declaration's, 64 bits wide.
    pub fn announced_id(
        self,
        what: GroupDeclaration,
        id: EntityId,
        allowed_origin: Locality,
    ) -> Option<u64> {
        if allowed_origin == Locality::SessionLocal {
            return None;
        }
        match (self, what) {
            (Self::Subscribers, GroupDeclaration::Subscriber) => Some(0),
            (Self::Entities | Self::Mapped, _) => Some(u64::from(id)),
            _ => None,
        }
    }

    /// Whether the group is told an entity it was told of is retracted: with [`Self::Entities`]
    /// and [`Self::Mapped`]. zenoh retracts nothing on a group, its announcement being a
    /// subscriber the group keeps.
    pub fn retracts(self) -> bool {
        matches!(self, Self::Entities | Self::Mapped)
    }

    /// How the group is told the key of an entity declared on `keyexpr` and named to the peers
    /// as `wire`: by that declaration only when the group is told the session's keyexprs
    /// ([`Self::declares_keyexprs`]), and by the literal otherwise, as zenoh-pico names a key on
    /// a multicast transport at its default.
    pub fn key<'a>(self, keyexpr: &'a str, wire: &'a WireKey) -> GroupKey<'a> {
        if self.declares_keyexprs() && wire.mapping_id != 0 {
            GroupKey {
                mapping_id: wire.mapping_id,
                suffix: wire.suffix.as_deref(),
            }
        } else {
            GroupKey::literal(keyexpr)
        }
    }

    /// The key a retraction names on the group: the entity's own key the declaring ABI retracts
    /// by (`retraction`), when the group is told the session's keyexprs and the ABI names one,
    /// and else the key it was announced on ([`Self::key`]).
    pub fn retraction_key<'a>(
        self,
        keyexpr: &'a str,
        wire: &'a WireKey,
        retraction: Option<&'a RetractionKey>,
    ) -> GroupKey<'a> {
        match retraction {
            Some(own) if self.declares_keyexprs() && own.mapping_id != 0 => GroupKey {
                mapping_id: own.mapping_id,
                suffix: Some(own.suffix.as_str()),
            },
            _ => self.key(keyexpr, wire),
        }
    }
}

/// What a session's JOIN beacon advertises on a group, beside its identity and its role:
/// the calling ABI's, because zenoh-pico and zenoh disagree on every one of them.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct GroupProfile {
    /// How long the members hold this session alive after each beacon, in milliseconds.
    pub lease_ms: u64,
    /// How often the session beacons, in milliseconds.
    pub join_interval_ms: u64,
    /// How many members the session holds on the group at once,
    /// `transport/multicast/max_sessions`, or `None` for no cap of its own (zenoh-pico has none).
    /// Not beaconed: it bounds what this session admits.
    pub max_sessions: Option<usize>,
    /// The 2-bit wire code of the sequence number resolution.
    pub seq_num_res: u8,
    /// The 2-bit wire code of the request id resolution.
    pub req_id_res: u8,
    /// The largest batch the session sends on the group.
    pub batch_size: u16,
    /// Whether the session offers the group per-priority conduits.
    pub is_qos: bool,
    /// Whether the group's datagrams are batches with the one-byte `BatchHeader`, compressed
    /// when that pays: `transport/multicast/compression/enabled`. Multicast has no handshake
    /// to switch it on, so every member of the group must state the same.
    pub compression: bool,
    /// Whose rule the session judges a member's Join by: the calling ABI's upstream's.
    pub join_rule: wz_session_core::multicast_params::GroupJoinRule,
}

impl GroupProfile {
    /// The parameters a group session runs with: this profile as its beacon advertises it, for
    /// the session `zid` of role `whatami`, with the session's transmit model, what it rejoins
    /// from fragments and the snapshot of its policies. One conversion for every engine, so the
    /// beacons the two engines send for one profile, and the members they admit, are the same.
    pub fn params(
        self,
        whatami: WhatAmI,
        zid: SessionZid,
        tx_queue: TxQueueConf,
        link_rx: LinkRxConf,
        policy: SessionPolicy,
    ) -> MulticastParams {
        let Self {
            lease_ms,
            join_interval_ms,
            max_sessions,
            seq_num_res,
            req_id_res,
            batch_size,
            is_qos,
            compression,
            join_rule,
        } = self;
        MulticastParams {
            whatami,
            zid,
            lease_ms,
            join_interval_ms,
            seq_num_res,
            req_id_res,
            batch_size,
            is_qos,
            compression,
            tx_queue,
            link_rx,
            join_rule,
            max_sessions,
            policy,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Each rule over every way a session tells a group of its declarations: zenoh-pico's two
    /// (`Entities` at its default, `Mapped` with its declarations switch) are asked queries and
    /// asked for liveliness, only `Mapped` is told keyexprs and asked by a write filter, and
    /// zenoh's two (`Subscribers`, and `None` where it announces nothing) are asked none of it.
    #[test]
    fn each_rule_answers_for_every_way_a_group_is_told() {
        for (told, queries, liveliness, keyexprs, filters) in [
            (GroupDeclarations::None, false, false, false, false),
            (GroupDeclarations::Subscribers, false, false, false, false),
            (GroupDeclarations::Entities, true, true, false, false),
            (GroupDeclarations::Mapped, true, true, true, true),
        ] {
            assert_eq!(told.asks_queries(), queries, "{told:?}");
            assert_eq!(told.asks_for_liveliness(), liveliness, "{told:?}");
            assert_eq!(told.declares_keyexprs(), keyexprs, "{told:?}");
            assert_eq!(told.asks_for_filters(), filters, "{told:?}");
        }
    }

    /// What a group is told of an entity, by every way a session tells it: the id (zenoh's 0 for
    /// a subscriber alone, zenoh-pico's entity id for each kind, nothing for a session-local
    /// entity), whether its retraction is told, and the key, a declaration only where the group is
    /// told the session's keyexprs.
    #[test]
    fn what_a_group_is_told_of_an_entity_follows_how_it_is_told() {
        use alloc::string::ToString;
        let remote = Locality::Any;
        let sub = GroupDeclaration::Subscriber;
        let qbl = GroupDeclaration::Queryable { complete: true };
        assert_eq!(GroupDeclarations::None.announced_id(sub, 7, remote), None);
        assert_eq!(
            GroupDeclarations::Subscribers.announced_id(sub, 7, remote),
            Some(0)
        );
        assert_eq!(
            GroupDeclarations::Subscribers.announced_id(qbl, 7, remote),
            None
        );
        for told in [GroupDeclarations::Entities, GroupDeclarations::Mapped] {
            assert_eq!(told.announced_id(qbl, 7, remote), Some(7), "{told:?}");
            assert_eq!(
                told.announced_id(GroupDeclaration::Token, 7, remote),
                Some(7)
            );
            assert_eq!(
                told.announced_id(sub, 7, Locality::SessionLocal),
                None,
                "a session-local entity is told to no group"
            );
            assert!(told.retracts());
        }
        assert!(!GroupDeclarations::Subscribers.retracts());
        assert!(!GroupDeclarations::None.retracts());

        let wire = WireKey::aliased(3, Some("rest".to_string()));
        let own = RetractionKey {
            mapping_id: 5,
            suffix: "own".to_string(),
        };
        assert_eq!(
            GroupDeclarations::Entities.key("demo/a", &wire),
            GroupKey::literal("demo/a")
        );
        assert_eq!(
            GroupDeclarations::Mapped.key("demo/a", &wire),
            GroupKey {
                mapping_id: 3,
                suffix: Some("rest")
            }
        );
        assert_eq!(
            GroupDeclarations::Entities.retraction_key("demo/a", &wire, Some(&own)),
            GroupKey::literal("demo/a")
        );
        assert_eq!(
            GroupDeclarations::Mapped.retraction_key("demo/a", &wire, Some(&own)),
            GroupKey {
                mapping_id: 5,
                suffix: Some("own")
            }
        );
    }

    /// The parameters a profile gives a group session carry every field of the profile and the
    /// session's own identity, role and snapshot as they were handed in.
    #[test]
    fn a_profile_gives_the_group_session_its_every_field() {
        use wz_session_core::multicast_params::{zid_vec, GroupJoinRule};
        let profile = GroupProfile {
            lease_ms: 7_000,
            join_interval_ms: 300,
            max_sessions: Some(5),
            seq_num_res: 0x01,
            req_id_res: 0x03,
            batch_size: 1_500,
            is_qos: true,
            compression: true,
            join_rule: GroupJoinRule::Zenoh,
        };
        let policy = SessionPolicy::defaults();
        let zid = zid_vec(&[0x5a, 0x5b, 0x5c]);
        let params = profile.params(
            WhatAmI::Router,
            zid,
            TxQueueConf::of_snapshot(&policy, &wz_session_core::limits::SessionLimits::BUILD),
            LinkRxConf::default(),
            policy,
        );
        assert_eq!(params.whatami, WhatAmI::Router);
        assert_eq!(params.zid, zid);
        assert_eq!(
            (
                params.lease_ms,
                params.join_interval_ms,
                params.max_sessions
            ),
            (7_000, 300, Some(5))
        );
        assert_eq!((params.seq_num_res, params.req_id_res), (0x01, 0x03));
        assert_eq!(params.batch_size, 1_500);
        assert!(params.is_qos && params.compression);
        assert_eq!(params.join_rule, GroupJoinRule::Zenoh);
        assert_eq!(params.link_rx, LinkRxConf::default());
        assert_eq!(params.policy, policy);
    }
}
