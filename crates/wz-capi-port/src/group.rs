// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The multicast groups a session joins, as an ABI states them to whichever engine runs the
//! session: where each group is, what the session's beacon advertises on it and what the session
//! tells it of its own declarations. Each is the calling ABI's decision (zenoh-pico and zenoh
//! disagree on every one), and each engine reads the same rules from here, so the two engines
//! cannot judge a group differently.

use alloc::string::String;

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
}
