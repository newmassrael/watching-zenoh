// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The part of zenoh-ext's group membership that is neither a wire nor an engine: what the keys
//! are, which ids may join, what a table of known members does with the events it hears, and when
//! a lease has run out.
//!
//! Two hosts run a group: the runtime's own (`wz-runtime-tokio`, over one unicast session, with
//! tokio tasks) and a node's (over the port's engine, with the engine's periodic jobs). What they
//! share is here, written over plain values with no lock, no clock and no channel: a host keeps a
//! [`MemberTable`] behind its own lock, reads its own clock, and does with each [`Reaction`] what
//! its transport asks (tell the user, wake a waiter, ask a member for its record). The wire is
//! [`crate::group_membership`]'s.

use alloc::collections::BTreeMap;
use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;
use core::time::Duration;

use crate::group_membership::{GroupNetEvent, Member};

/// The group key-expression namespace (zenoh-ext `GROUP_PREFIX`, group.rs:37).
const GROUP_PREFIX: &str = "zenoh/ext/net/group";
/// The event-key trailing chunk (zenoh-ext `EVENT_POSTFIX`, group.rs:38).
const EVENT_POSTFIX: &str = "evt";

/// The watchdog sweep period: once per second (zenoh-ext `Duration::from_secs(1)`, group.rs:402).
pub const WATCHDOG_PERIOD_MS: u64 = 1_000;

/// The unknown-member `get` timeout. The recovered member is only relevant for the duration of its
/// lease, so an unanswered `get` (the member left between its beacon and our query) is bounded
/// tighter than the platform default: a stale member is lease-scoped, and the next beacon asks
/// again if it was a transient miss.
pub const MEMBER_QUERY_TIMEOUT_MS: u32 = 5_000;

/// The group event key `zenoh/ext/net/group/<gid>/evt`: the pub/sub channel the join, leave and
/// keep-alive events travel on.
pub fn event_keyexpr(gid: &str) -> String {
    format!("{GROUP_PREFIX}/{gid}/{EVENT_POSTFIX}")
}

/// The per-member query key `zenoh/ext/net/group/<gid>/<mid>`: the queryable each member declares
/// to serve its own record (zenoh-ext group.rs:231-234).
pub fn member_keyexpr(gid: &str, mid: &str) -> String {
    format!("{GROUP_PREFIX}/{gid}/{mid}")
}

/// Whether a group or member id contains a key-expression wildcard. zenoh-ext rejects a wild group
/// id and a wild member id (group.rs:118-120, 369-371); a non-wild key expression contains none of
/// the wildcard chunks, all of which carry a `*`.
pub fn is_wild(ke: &str) -> bool {
    ke.contains('*')
}

/// Whether `ke` is a CANONICAL key expression, the property upstream gets from its type and wz has
/// to check.
///
/// zenoh-ext types both group ids as `OwnedKeyExpr`, and a key expression must be in canon form to
/// construct one (`commons/zenoh-keyexpr/src/key_expr/borrowed.rs`
/// @ `/// Note that to be considered a valid key expression, a string MUST be canon.`), so `a//b`
/// never reaches its `Group::join`. wz types them as `String`, which carries no such guarantee, and
/// the wildcard checks alone did not supply it.
///
/// Canonical means the canonizer returns the input UNCHANGED, not merely that it succeeds, which is
/// the `autocanonize` contract upstream keeps as a separate constructor. A canonizer error (invalid
/// grammar) is likewise not canonical. The Pico dialect is used and the choice does not matter
/// here: the two dialects differ only on where a `$*` chunk lands inside a WILD run, and every
/// caller pairs this with [`is_wild`], which rejects the whole class.
pub fn is_canonical(ke: &str) -> bool {
    crate::keyexpr_canon::canonize_keyexpr(ke)
        .map(|canon| canon.as_str() == ke)
        .unwrap_or(false)
}

/// Why a group or member id cannot join.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IdError {
    /// The group id was not a canonical key expression.
    NonCanonicalGroupId(String),
    /// The group id contained a key-expression wildcard.
    WildcardGroupId(String),
    /// The member id was not a canonical key expression.
    NonCanonicalMemberId(String),
    /// The member id contained a key-expression wildcard.
    WildcardMemberId(String),
}

/// Check the two ids a join names, in the order upstream is forced into: its `try_into` to
/// `OwnedKeyExpr` (canonicity) runs first and its `is_wild` bail second, on both ids, the group's
/// before the member's.
pub fn check_ids(gid: &str, mid: &str) -> Result<(), IdError> {
    if !is_canonical(gid) {
        return Err(IdError::NonCanonicalGroupId(gid.into()));
    }
    if is_wild(gid) {
        return Err(IdError::WildcardGroupId(gid.into()));
    }
    if !is_canonical(mid) {
        return Err(IdError::NonCanonicalMemberId(mid.into()));
    }
    if is_wild(mid) {
        return Err(IdError::WildcardMemberId(mid.into()));
    }
    Ok(())
}

/// The keep-alive beacon period: `lease * refresh_ratio`, so a refresh always precedes the lease
/// elapsing (zenoh-ext group.rs:190-193). Clamped to `>= 1ms` by construction so a degenerate zero
/// period cannot spin the beacon: the floor lives here, not at the call site, so any caller is
/// spin-safe too.
pub fn keepalive_period_ms(lease: Duration, refresh_ratio: f32) -> u64 {
    (((lease.as_millis() as f64) * (refresh_ratio as f64)) as u64).max(1)
}

/// What a member of a group does to the view the user holds, as the user is told it.
#[derive(Clone, Debug)]
pub enum GroupEvent {
    /// A member joined (or was recovered via the unknown-member query).
    Join(Member),
    /// A member announced it is leaving.
    Leave(String),
    /// A member's lease elapsed without a refreshing keep-alive.
    LeaseExpired(String),
    /// The group leader changed. RESERVED and never emitted: a faithful mirror of zenoh-ext, which
    /// likewise DECLARES `GroupEvent::NewLeader` (group.rs:89) but never sends it (no construction
    /// site upstream); the leader is a pull query, not a push event. Kept for wire and API parity.
    NewLeader(String),
}

/// The members a host knows of, each with the monotonic deadline its lease runs to. The local member
/// is NOT here (it is the always-present `+1` of the view).
#[derive(Debug, Default)]
pub struct MemberTable {
    members: BTreeMap<String, (Member, u64)>,
}

impl MemberTable {
    /// An empty table.
    pub fn new() -> Self {
        Self::default()
    }

    /// Insert (or replace) a known member with a fresh lease deadline, `now_ms` plus its lease.
    pub fn insert(&mut self, member: Member, now_ms: u64) {
        let alive_till = now_ms.saturating_add(member.lease.as_millis() as u64);
        self.members
            .insert(member.mid.clone(), (member, alive_till));
    }

    /// Refresh a known member's lease deadline; `false`, with nothing touched, when the member is
    /// unknown (the caller then recovers it by asking the member for its record).
    pub fn refresh(&mut self, mid: &str, now_ms: u64) -> bool {
        match self.members.get_mut(mid) {
            Some((member, alive_till)) => {
                *alive_till = now_ms.saturating_add(member.lease.as_millis() as u64);
                true
            }
            None => false,
        }
    }

    /// Remove a member; whether it was known.
    pub fn remove(&mut self, mid: &str) -> bool {
        self.members.remove(mid).is_some()
    }

    /// Evict every member whose lease deadline has passed, and say which.
    pub fn sweep(&mut self, now_ms: u64) -> Vec<String> {
        let mut expired = Vec::new();
        self.members.retain(|mid, (_, alive_till)| {
            if *alive_till < now_ms {
                expired.push(mid.clone());
                false
            } else {
                true
            }
        });
        expired
    }

    /// The known members, ordered by member id.
    pub fn members(&self) -> impl Iterator<Item = &Member> {
        self.members.values().map(|(member, _)| member)
    }

    /// How many members are known.
    pub fn len(&self) -> usize {
        self.members.len()
    }

    /// Whether no member is known.
    pub fn is_empty(&self) -> bool {
        self.members.is_empty()
    }
}

/// What a host does after a net event has been applied to its table.
#[derive(Debug, PartialEq)]
pub enum Reaction {
    /// Nothing: the event named the local member, or a member that was not known to leave.
    None,
    /// A member entered the table: tell the user, and wake whoever waits for the view to grow.
    Joined(Member),
    /// A member left on its own: tell the user.
    Left(String),
    /// A keep-alive came from a member the table does not know: ask it for its record.
    Unknown(String),
}

/// Apply one decoded inbound event to `table`, as zenoh-ext's `net_event_handler` does
/// (group.rs:254-354). Every arm ignores an event whose member id is the local member: the join
/// before subscribe ordering already prevents a self-event, and upstream's keep-alive arm filters
/// too.
pub fn react(
    table: &mut MemberTable,
    local_mid: &str,
    event: GroupNetEvent,
    now_ms: u64,
) -> Reaction {
    match event {
        GroupNetEvent::Join(member) => {
            if member.mid == local_mid {
                return Reaction::None;
            }
            table.insert(member.clone(), now_ms);
            Reaction::Joined(member)
        }
        GroupNetEvent::Leave(mid) => {
            if mid != local_mid && table.remove(&mid) {
                Reaction::Left(mid)
            } else {
                Reaction::None
            }
        }
        GroupNetEvent::KeepAlive(mid) => {
            if mid == local_mid || table.refresh(&mid, now_ms) {
                Reaction::None
            } else {
                Reaction::Unknown(mid)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn member(mid: &str, lease_ms: u64) -> Member {
        Member::new(mid).lease(Duration::from_millis(lease_ms))
    }

    /// The keys are zenoh-ext's.
    #[test]
    fn the_keys_are_the_group_namespace() {
        assert_eq!(event_keyexpr("g"), "zenoh/ext/net/group/g/evt");
        assert_eq!(member_keyexpr("g", "m"), "zenoh/ext/net/group/g/m");
    }

    /// A wildcard and a non-canonical id are refused, the group's before the member's, canonicity
    /// before the wildcard test.
    #[test]
    fn ids_are_refused_in_upstreams_order() {
        assert_eq!(check_ids("g", "m"), Ok(()));
        assert_eq!(
            check_ids("a//b", "m"),
            Err(IdError::NonCanonicalGroupId("a//b".into()))
        );
        assert_eq!(
            check_ids("a/*", "m"),
            Err(IdError::WildcardGroupId("a/*".into()))
        );
        assert_eq!(
            check_ids("g", "a//b"),
            Err(IdError::NonCanonicalMemberId("a//b".into()))
        );
        assert_eq!(
            check_ids("g", "m/*"),
            Err(IdError::WildcardMemberId("m/*".into()))
        );
        assert_eq!(
            check_ids("a//b", "m/*"),
            Err(IdError::NonCanonicalGroupId("a//b".into())),
            "the group id is read before the member id"
        );
    }

    /// The beacon period is the lease times the ratio, and never zero.
    #[test]
    fn the_keepalive_period_is_lease_times_ratio_and_at_least_a_millisecond() {
        assert_eq!(keepalive_period_ms(Duration::from_secs(18), 0.75), 13_500);
        assert_eq!(keepalive_period_ms(Duration::from_secs(1), 0.0), 1);
    }

    /// A join enters the table with the lease it names; a beacon before the lease runs out
    /// refreshes it, and the sweep evicts only what has passed its deadline.
    #[test]
    fn a_lease_is_refreshed_by_a_beacon_and_swept_when_it_passes() {
        let mut table = MemberTable::new();
        assert_eq!(
            react(&mut table, "me", GroupNetEvent::Join(member("a", 100)), 0),
            Reaction::Joined(member("a", 100))
        );
        assert_eq!(
            react(&mut table, "me", GroupNetEvent::Join(member("b", 100)), 0),
            Reaction::Joined(member("b", 100))
        );
        assert_eq!(
            react(&mut table, "me", GroupNetEvent::KeepAlive("a".into()), 90),
            Reaction::None
        );
        // At 150 `b` (deadline 100) has run out and `a` (refreshed to 190) has not.
        assert_eq!(table.sweep(150), ["b"]);
        assert_eq!(table.len(), 1);
        assert_eq!(table.sweep(191), ["a"]);
        assert!(table.is_empty());
    }

    /// The local member is never put in its own table, whatever event names it.
    #[test]
    fn the_local_member_is_ignored_by_every_arm() {
        let mut table = MemberTable::new();
        assert_eq!(
            react(&mut table, "me", GroupNetEvent::Join(member("me", 100)), 0),
            Reaction::None
        );
        assert_eq!(
            react(&mut table, "me", GroupNetEvent::Leave("me".into()), 0),
            Reaction::None
        );
        assert_eq!(
            react(&mut table, "me", GroupNetEvent::KeepAlive("me".into()), 0),
            Reaction::None
        );
        assert!(table.is_empty());
    }

    /// A beacon from a member never heard of asks for its record, and a leave of one never heard of
    /// says nothing.
    #[test]
    fn an_unknown_beacon_asks_and_an_unknown_leave_is_silent() {
        let mut table = MemberTable::new();
        assert_eq!(
            react(&mut table, "me", GroupNetEvent::KeepAlive("x".into()), 0),
            Reaction::Unknown("x".into())
        );
        assert_eq!(
            react(&mut table, "me", GroupNetEvent::Leave("x".into()), 0),
            Reaction::None
        );
        react(&mut table, "me", GroupNetEvent::Join(member("x", 100)), 0);
        assert_eq!(
            react(&mut table, "me", GroupNetEvent::Leave("x".into()), 1),
            Reaction::Left("x".into())
        );
    }
}
