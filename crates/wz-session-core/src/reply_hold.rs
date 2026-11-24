// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! What a consolidating get holds back, and the rule it holds by.
//!
//! A get asked under `Latest` delivers one reply per key, the most recent, when its last Final
//! arrives; one asked under `Monotonic` delivers a reply as it arrives unless a more recent one
//! of its key went first. Both keep something of every key they have seen until the get ends: the
//! whole reply under `Latest`, its key and its stamp under `Monotonic`. The rule is one function
//! over a [`ReplyHold`] ([`consolidate`], [`flush_latest`]), whatever holds the replies: the
//! owned replies of one get on the heap (`reply_sink::HeapHold`), or the rows of the session's
//! one table of held replies ([`HeldReplies`]), each row tagged with the get it belongs to, its
//! bytes in the row, so holding a reply takes no allocation.

use crate::bounded::{Arena, BoundedVec, LendRefused, Lent, Profile, Storage, TableLender};
use crate::caps;
use crate::query_mode::ConsolidationMode;
use crate::reply_sink::{ReplyKind, ReplyView};
use crate::reply_stage::TimestampParts;
use crate::sample::{QosLevel, SourceInfo};

/// The bytes one held reply keeps in its row: its key and its payload, and with them its encoding
/// schema and its attachment, which share the room.
pub const HOLD_ROW_BYTES: usize =
    match caps::MAX_REPLY_PAYLOAD_BYTES.checked_add(caps::MAX_KEYEXPR_BYTES) {
        Some(bytes) => bytes,
        None => usize::MAX,
    };

/// The longest id a timestamp or a responder names on the wire.
const ZID_BYTES: usize = 16;

/// Why a reply was not held.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HoldRefused {
    /// Every row of the hold is taken.
    Full,
    /// The reply's key, payload, schema and attachment together are more than a row keeps, or an
    /// id is longer than a timestamp or a responder carries.
    TooLarge,
}

/// What a consolidating get keeps of the replies it has seen, one per key.
pub trait ReplyHold {
    /// Whether `reply` is at least as recent as what is held for its key, or nothing is.
    fn displaces(&self, reply: &dyn ReplyView) -> bool;
    /// Hold `reply` as the latest of its key, in place of what was held for it. `whole` is
    /// `false` where only its key and its stamp are read again.
    fn hold(&mut self, reply: &dyn ReplyView, whole: bool) -> Result<(), HoldRefused>;
    /// Hand every whole reply held to `each`, and hold nothing after.
    fn drain(&mut self, each: &mut dyn FnMut(&dyn ReplyView));
}

/// Whether a reply stamped `new` is at least as recent as one stamped `held`, by the ordering
/// zenoh consolidates with.
///
/// zenoh compares `Option<uhlc::Timestamp>` with `>=` (api/session.rs, the
/// Monotonic + Auto/Latest arms). `uhlc::Timestamp` derives `Ord` over its
/// fields IN ORDER — `time: NTP64` then `id: ID` (uhlc timestamp.rs) — so the
/// rule is lexicographic `(time, zid)`, and `Option`'s own ordering puts `None`
/// BELOW every `Some`. Both halves matter: a stamped reply always beats an
/// unstamped one, and two replies stamped at the same instant by different
/// sources still have a deterministic winner rather than an arrival-order race.
///
/// NAMED DIVERGENCE — pico compares `msg->_commons._timestamp.time <=
/// pen_rep->_tstamp.time` (`vendor/zenoh-pico/src/session/query.c:145`): the
/// TIME WORD ONLY, and it drops on a tie, so pico keeps the FIRST arrival among
/// equal stamps while zenoh keeps the LAST. wz follows zenoh: its order is
/// total, so the delivered reply does not depend on which peer answered first.
/// The tie is also where "no timestamps at all" lands (both read as `None`),
/// which is why the choice is not academic — an unstamped keyexpr consolidates
/// to the LAST reply here and to the FIRST under pico.
pub fn stamp_at_least(new: Option<TimestampParts<'_>>, held: Option<TimestampParts<'_>>) -> bool {
    match (new, held) {
        (None, None) | (Some(_), None) => true,
        (None, Some(_)) => false,
        (Some(n), Some(h)) => (n.time, n.zid) >= (h.time, h.zid),
    }
}

/// What [`consolidate`] did with a reply.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Consolidated {
    /// Handed on now.
    Forwarded,
    /// Held until the get ends.
    Held,
    /// Older than what its key already had: dropped.
    Stale,
    /// Not held for want of room: dropped, and the caller counts it.
    Refused(HoldRefused),
}

/// Apply `mode` to `reply`, holding in `hold` and handing on through `forward`.
///
/// An Err reply is never consolidated: upstream calls back an Err from an arm of its own that
/// never runs the consolidation match (its Err result has no key to hold it under), so it is
/// forwarded at once in every mode. `None` forwards everything. `Monotonic` forwards a reply
/// that is not stale and keeps its key and stamp. `Latest` holds the reply whole until
/// [`flush_latest`].
pub fn consolidate<H: ReplyHold + ?Sized>(
    mode: ConsolidationMode,
    hold: &mut H,
    reply: &dyn ReplyView,
    forward: &mut dyn FnMut(&dyn ReplyView),
) -> Consolidated {
    if reply.kind() == ReplyKind::Err || mode == ConsolidationMode::None {
        forward(reply);
        return Consolidated::Forwarded;
    }
    if !hold.displaces(reply) {
        return Consolidated::Stale;
    }
    let latest = mode == ConsolidationMode::Latest;
    match hold.hold(reply, latest) {
        Ok(()) if latest => Consolidated::Held,
        Ok(()) => {
            forward(reply);
            Consolidated::Forwarded
        }
        // Under `Monotonic` a reply not held is still not stale: it goes on, and only the
        // staleness record of its key is lost.
        Err(_) if !latest => {
            forward(reply);
            Consolidated::Forwarded
        }
        Err(why) => Consolidated::Refused(why),
    }
}

/// Hand on what a `Latest` get held, at its end (its last Final, or its deadline before the
/// timeout's error); nothing in any other mode, whose hold is only a staleness record.
pub fn flush_latest<H: ReplyHold + ?Sized>(
    mode: ConsolidationMode,
    hold: &mut H,
    forward: &mut dyn FnMut(&dyn ReplyView),
) {
    if mode == ConsolidationMode::Latest {
        hold.drain(forward);
    }
}

/// One held reply, read as a reply: whose it is, what it is, and its bytes (key, payload, schema,
/// attachment, in that order) in the row. Taken out of the hold whole
/// ([`HeldReplies::take`]), so it is delivered with no lock on the hold.
pub struct HeldReply<O, P: Storage> {
    owner: O,
    rid: crate::wire_id::RequestId,
    kind: ReplyKind,
    whole: bool,
    qos: Option<QosLevel>,
    stamp: Option<(u64, BoundedVec<u8, ZID_BYTES, P::Scratch>)>,
    responder: Option<(BoundedVec<u8, ZID_BYTES, P::Scratch>, u32)>,
    source_info: Option<SourceInfo>,
    encoding: Option<u32>,
    key_len: usize,
    payload_len: usize,
    schema_len: Option<usize>,
    attachment_len: Option<usize>,
    #[cfg(feature = "pubsub-ts-stack")]
    ts_stack: Option<crate::ts_stack::TsStack>,
    #[cfg(feature = "pubsub-ts-stack")]
    routed: bool,
    bytes: BoundedVec<u8, HOLD_ROW_BYTES, P::Scratch>,
}

impl<O, P: Storage> HeldReply<O, P> {
    /// An empty row of `owner`'s, filled by [`Self::fill`].
    fn empty(owner: O) -> Self {
        Self {
            owner,
            rid: 0,
            kind: ReplyKind::Put,
            whole: false,
            qos: None,
            stamp: None,
            responder: None,
            source_info: None,
            encoding: None,
            key_len: 0,
            payload_len: 0,
            schema_len: None,
            attachment_len: None,
            #[cfg(feature = "pubsub-ts-stack")]
            ts_stack: None,
            #[cfg(feature = "pubsub-ts-stack")]
            routed: false,
            bytes: BoundedVec::default(),
        }
    }

    /// Make the row `reply`, written where it lies; `TooLarge` leaves it to be let go of.
    fn fill(&mut self, reply: &dyn ReplyView, whole: bool) -> Result<(), HoldRefused> {
        let key = reply.keyexpr().as_bytes();
        let encoding = match reply.kind() {
            ReplyKind::Put => reply.put_encoding(),
            ReplyKind::Err => reply.err_encoding(),
            ReplyKind::Del => None,
        };
        let schema = encoding.and_then(|(_, schema)| schema);
        let payload = if whole { reply.payload() } else { &[] };
        let attachment = if whole { reply.attachment() } else { None };
        self.bytes.clear();
        for part in [
            key,
            payload,
            schema.unwrap_or(&[]),
            attachment.unwrap_or(&[]),
        ] {
            self.bytes
                .extend_from_slice(part)
                .map_err(|_| HoldRefused::TooLarge)?;
        }
        self.stamp = match reply.timestamp_parts() {
            Some(stamp) => Some((stamp.time, zid(stamp.zid)?)),
            None => None,
        };
        self.responder = match reply.responder() {
            Some((id, eid)) => Some((zid(id)?, eid)),
            None => None,
        };
        self.rid = reply.rid();
        self.kind = reply.kind();
        self.whole = whole;
        self.qos = reply.qos();
        self.source_info = reply.source_info().cloned();
        self.encoding = encoding.map(|(id, _)| id);
        self.key_len = key.len();
        self.payload_len = payload.len();
        self.schema_len = schema.map(<[u8]>::len);
        self.attachment_len = attachment.map(<[u8]>::len);
        #[cfg(feature = "pubsub-ts-stack")]
        {
            self.ts_stack = reply.ts_stack().cloned();
            self.routed = reply.routed();
        }
        Ok(())
    }

    /// The bytes of the row from `start`, `len` long; none past what the row holds.
    fn part(&self, start: usize, len: usize) -> &[u8] {
        start
            .checked_add(len)
            .and_then(|end| self.bytes.get(start..end))
            .unwrap_or(&[])
    }

    fn key(&self) -> &str {
        core::str::from_utf8(self.part(0, self.key_len)).unwrap_or("")
    }

    fn after_key(&self) -> usize {
        self.key_len
    }

    fn after_payload(&self) -> usize {
        self.key_len.saturating_add(self.payload_len)
    }

    fn after_schema(&self) -> usize {
        self.after_payload()
            .saturating_add(self.schema_len.unwrap_or(0))
    }

    fn stamp(&self) -> Option<TimestampParts<'_>> {
        self.stamp
            .as_ref()
            .map(|(time, zid)| TimestampParts { time: *time, zid })
    }

    fn encoding_of(&self, kind: ReplyKind) -> Option<(u32, Option<&[u8]>)> {
        if self.kind != kind {
            return None;
        }
        self.encoding.map(|id| {
            (
                id,
                self.schema_len
                    .map(|len| self.part(self.after_payload(), len)),
            )
        })
    }
}

/// `id` held in a row, refused past the bytes a timestamp or a responder carries.
fn zid<P: Storage>(id: &[u8]) -> Result<BoundedVec<u8, ZID_BYTES, P>, HoldRefused> {
    let mut held = BoundedVec::default();
    held.extend_from_slice(id)
        .map_err(|_| HoldRefused::TooLarge)?;
    Ok(held)
}

impl<O, P: Storage> ReplyView for HeldReply<O, P> {
    fn rid(&self) -> crate::wire_id::RequestId {
        self.rid
    }
    fn keyexpr(&self) -> &str {
        self.key()
    }
    fn kind(&self) -> ReplyKind {
        self.kind
    }
    fn payload(&self) -> &[u8] {
        self.part(self.after_key(), self.payload_len)
    }
    fn err_encoding(&self) -> Option<(u32, Option<&[u8]>)> {
        self.encoding_of(ReplyKind::Err)
    }
    fn attachment(&self) -> Option<&[u8]> {
        self.attachment_len
            .map(|len| self.part(self.after_schema(), len))
    }
    fn put_encoding(&self) -> Option<(u32, Option<&[u8]>)> {
        self.encoding_of(ReplyKind::Put)
    }
    fn source_info(&self) -> Option<&SourceInfo> {
        self.source_info.as_ref()
    }
    fn timestamp_parts(&self) -> Option<TimestampParts<'_>> {
        self.stamp()
    }
    fn responder(&self) -> Option<(&[u8], u32)> {
        self.responder.as_ref().map(|(id, eid)| (&**id, *eid))
    }
    fn qos(&self) -> Option<QosLevel> {
        self.qos
    }
    #[cfg(feature = "pubsub-ts-stack")]
    fn ts_stack(&self) -> Option<&crate::ts_stack::TsStack> {
        self.ts_stack.as_ref()
    }
    #[cfg(feature = "pubsub-ts-stack")]
    fn routed(&self) -> bool {
        self.routed
    }
}

/// The session's held replies: one row a key a consolidating get has seen, each tagged with its
/// get (`O`, the get's handle in the session's tables), its bytes in the row. A fixed number of
/// rows of a fixed size where the policy fixes them ([`caps::MAX_PENDING_REPLIES`] rows of
/// [`HOLD_ROW_BYTES`]), so holding a reply allocates nothing; a full hold refuses, and counts.
pub struct HeldReplies<O, P: Storage = Profile> {
    rows: BoundedVec<HeldReply<O, P>, { caps::MAX_PENDING_REPLIES }, P>,
    refused: u32,
}

impl<O, P: Storage> Default for HeldReplies<O, P> {
    fn default() -> Self {
        Self {
            rows: BoundedVec::default(),
            refused: 0,
        }
    }
}

impl<O> HeldReplies<O, Lent> {
    /// A hold of `rows` rows lent from `arena`.
    pub fn lent(arena: &mut Arena, rows: usize) -> Result<Self, LendRefused> {
        Ok(Self {
            rows: arena.lend(rows)?,
            refused: 0,
        })
    }

    /// A hold of `rows` rows lent by `lend`, as [`Self::lent`] lends one; a hold of no rows, which
    /// refuses every reply and counts it, once a table is refused, this one among them.
    pub fn lent_from(lend: &mut TableLender<'_>, rows: usize) -> Self {
        Self {
            rows: lend.table(rows),
            refused: 0,
        }
    }

    /// The bytes of an arena [`Self::lent`] takes for `rows`. `None` past the address space.
    pub const fn arena_bytes(rows: usize) -> Option<usize> {
        Arena::table_bytes::<HeldReply<O, Lent>>(rows)
    }
}

impl<O: Copy + Eq, P: Storage> HeldReplies<O, P> {
    /// How many replies were not held for want of room.
    pub fn refused(&self) -> u32 {
        self.refused
    }

    /// How many replies are held, of every get.
    pub fn len(&self) -> usize {
        self.rows.len()
    }

    /// Whether no reply is held.
    pub fn is_empty(&self) -> bool {
        self.rows.is_empty()
    }

    /// The hold of `owner`'s replies, as the rule reads it.
    pub fn of(&mut self, owner: O) -> HeldFor<'_, O, P> {
        HeldFor { hold: self, owner }
    }

    /// Let go of every reply `owner` holds: a get that ended without delivering them.
    pub fn forget(&mut self, owner: O) {
        self.rows.retain(|row| row.owner != owner);
    }

    fn held(&self, owner: O, key: &str) -> Option<&HeldReply<O, P>> {
        self.rows
            .iter()
            .find(|row| row.owner == owner && row.key() == key)
    }

    fn hold(&mut self, owner: O, reply: &dyn ReplyView, whole: bool) -> Result<(), HoldRefused> {
        let key = reply.keyexpr();
        let at = match self
            .rows
            .iter()
            .position(|row| row.owner == owner && row.key() == key)
        {
            Some(at) => at,
            None => {
                if self.rows.push(HeldReply::empty(owner)).is_err() {
                    self.refused = self.refused.saturating_add(1);
                    return Err(HoldRefused::Full);
                }
                self.rows.len().saturating_sub(1)
            }
        };
        let Some(row) = self.rows.get_mut(at) else {
            return Err(HoldRefused::Full);
        };
        if let Err(why) = row.fill(reply, whole) {
            // A row half written names no reply: it goes, and the key is held no more.
            let mut place = at;
            let _ = self.rows.take_next_where(&mut place, |_| true);
            self.refused = self.refused.saturating_add(1);
            return Err(why);
        }
        Ok(())
    }

    fn drain(&mut self, owner: O, each: &mut dyn FnMut(&dyn ReplyView)) {
        while let Some(row) = self.take(owner) {
            each(&row);
        }
    }

    /// Take out the next whole reply `owner` holds, for its caller to deliver once the hold is let
    /// go; a key held only for its stamp is let go of on the way. `None` once none is left.
    pub fn take(&mut self, owner: O) -> Option<HeldReply<O, P>> {
        let mut at = 0;
        while let Some(row) = self.rows.take_next_where(&mut at, |row| row.owner == owner) {
            if row.whole {
                return Some(row);
            }
        }
        None
    }
}

/// The replies one get holds in a [`HeldReplies`].
pub struct HeldFor<'h, O, P: Storage> {
    hold: &'h mut HeldReplies<O, P>,
    owner: O,
}

impl<O: Copy + Eq, P: Storage> ReplyHold for HeldFor<'_, O, P> {
    fn displaces(&self, reply: &dyn ReplyView) -> bool {
        // A `match`, as the crate's MSRV (1.81) has no `Option::is_none_or`.
        match self.hold.held(self.owner, reply.keyexpr()) {
            Some(held) => stamp_at_least(reply.timestamp_parts(), held.stamp()),
            None => true,
        }
    }

    fn hold(&mut self, reply: &dyn ReplyView, whole: bool) -> Result<(), HoldRefused> {
        self.hold.hold(self.owner, reply, whole)
    }

    fn drain(&mut self, each: &mut dyn FnMut(&dyn ReplyView)) {
        self.hold.drain(self.owner, each);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bounded::Static;
    use std::vec::Vec;

    /// A reply as a test states it: a key, a kind, a payload and a stamp, with an encoding and an
    /// attachment on a Put.
    struct Stated<'a> {
        key: &'a str,
        kind: ReplyKind,
        payload: &'a [u8],
        time: Option<u64>,
    }

    impl ReplyView for Stated<'_> {
        fn rid(&self) -> crate::wire_id::RequestId {
            9
        }
        fn keyexpr(&self) -> &str {
            self.key
        }
        fn kind(&self) -> ReplyKind {
            self.kind
        }
        fn payload(&self) -> &[u8] {
            self.payload
        }
        fn err_encoding(&self) -> Option<(u32, Option<&[u8]>)> {
            None
        }
        fn put_encoding(&self) -> Option<(u32, Option<&[u8]>)> {
            (self.kind == ReplyKind::Put).then_some((0x0B, Some(b"json".as_slice())))
        }
        fn attachment(&self) -> Option<&[u8]> {
            (self.kind == ReplyKind::Put).then_some(b"att".as_slice())
        }
        fn timestamp_parts(&self) -> Option<TimestampParts<'_>> {
            self.time.map(|time| TimestampParts { time, zid: &[1, 2] })
        }
    }

    fn put<'k>(key: &'k str, payload: &'static [u8], time: u64) -> Stated<'k> {
        Stated {
            key,
            kind: ReplyKind::Put,
            payload,
            time: Some(time),
        }
    }

    type Hold = HeldReplies<u32, Static>;

    /// What each owner forwards, by payload.
    fn apply(
        hold: &mut Hold,
        owner: u32,
        mode: ConsolidationMode,
        reply: &Stated<'_>,
    ) -> (Consolidated, Vec<Vec<u8>>) {
        let mut forwarded = Vec::new();
        let done = consolidate(mode, &mut hold.of(owner), reply, &mut |reply| {
            forwarded.push(reply.payload().to_vec())
        });
        (done, forwarded)
    }

    /// Under `Latest` the newest reply of each key is held, a stale one is dropped, and each get
    /// takes out only its own, whole: key, payload, encoding, attachment and stamp as they came.
    #[test]
    fn latest_holds_the_newest_of_each_key_for_each_get() {
        let mut hold = Hold::default();
        let latest = ConsolidationMode::Latest;
        assert_eq!(
            apply(&mut hold, 1, latest, &put("a", b"old", 10)).0,
            Consolidated::Held
        );
        assert_eq!(
            apply(&mut hold, 1, latest, &put("a", b"new", 20)).0,
            Consolidated::Held
        );
        assert_eq!(
            apply(&mut hold, 1, latest, &put("a", b"stale", 15)).0,
            Consolidated::Stale
        );
        assert_eq!(
            apply(&mut hold, 2, latest, &put("a", b"other", 1)).0,
            Consolidated::Held
        );
        assert_eq!(hold.len(), 2, "one row a key a get");
        let taken = hold.take(1).expect("get 1 holds one reply");
        assert_eq!(
            (taken.keyexpr(), taken.payload(), taken.rid()),
            ("a", b"new".as_slice(), 9)
        );
        assert_eq!(taken.put_encoding(), Some((0x0B, Some(b"json".as_slice()))));
        assert_eq!(taken.attachment(), Some(b"att".as_slice()));
        assert_eq!(
            taken.timestamp_parts(),
            Some(TimestampParts {
                time: 20,
                zid: &[1, 2]
            })
        );
        assert!(hold.take(1).is_none(), "get 1 held one key");
        assert_eq!(hold.len(), 1, "get 2's reply is still held");
        hold.forget(2);
        assert!(hold.is_empty());
    }

    /// Under `Monotonic` a reply that is not stale goes on at once and only its key and stamp
    /// stay; a stale one is dropped; nothing is left to take.
    #[test]
    fn monotonic_forwards_at_once_and_keeps_only_the_stamp() {
        let mut hold = Hold::default();
        let mono = ConsolidationMode::Monotonic;
        let (done, forwarded) = apply(&mut hold, 1, mono, &put("a", b"v1", 10));
        assert_eq!(
            (done, forwarded),
            (Consolidated::Forwarded, std::vec![b"v1".to_vec()])
        );
        assert_eq!(
            apply(&mut hold, 1, mono, &put("a", b"v0", 5)).0,
            Consolidated::Stale
        );
        assert_eq!(
            apply(&mut hold, 1, mono, &put("a", b"v2", 20)).0,
            Consolidated::Forwarded
        );
        assert!(
            hold.take(1).is_none(),
            "a stamp record is not a reply to deliver"
        );
    }

    /// An Err goes on at once in every mode, and is never held.
    #[test]
    fn an_err_is_forwarded_and_never_held() {
        for mode in [
            ConsolidationMode::None,
            ConsolidationMode::Monotonic,
            ConsolidationMode::Latest,
        ] {
            let mut hold = Hold::default();
            let err = Stated {
                key: "a",
                kind: ReplyKind::Err,
                payload: b"boom",
                time: None,
            };
            let (done, forwarded) = apply(&mut hold, 1, mode, &err);
            assert_eq!(
                (done, forwarded),
                (Consolidated::Forwarded, std::vec![b"boom".to_vec()])
            );
            assert!(hold.is_empty(), "{mode:?}");
        }
    }

    /// A full hold refuses a new key and counts it; a reply longer than a row is refused, counted,
    /// and leaves no row behind. Under `Monotonic` a reply not held still goes on.
    #[test]
    fn a_full_hold_and_a_reply_past_a_row_are_refused_and_counted() {
        let mut hold = Hold::default();
        let latest = ConsolidationMode::Latest;
        let keys: Vec<std::string::String> = (0..=caps::MAX_PENDING_REPLIES)
            .map(|n| std::format!("k/{n}"))
            .collect();
        let (last, first) = keys.split_last().expect("keys");
        for key in first {
            assert_eq!(
                apply(&mut hold, 1, latest, &put(key, b"x", 1)).0,
                Consolidated::Held
            );
        }
        assert_eq!(
            apply(&mut hold, 1, latest, &put(last, b"x", 1)).0,
            Consolidated::Refused(HoldRefused::Full)
        );
        assert_eq!(hold.refused(), 1);
        let (done, forwarded) = apply(
            &mut hold,
            1,
            ConsolidationMode::Monotonic,
            &put(last, b"y", 1),
        );
        assert_eq!((done, forwarded.len()), (Consolidated::Forwarded, 1));
        hold.forget(1);
        let big = std::vec![0u8; HOLD_ROW_BYTES];
        let too_large = Stated {
            key: "big",
            kind: ReplyKind::Put,
            payload: &big,
            time: Some(1),
        };
        assert_eq!(
            apply(&mut hold, 1, latest, &too_large).0,
            Consolidated::Refused(HoldRefused::TooLarge)
        );
        assert!(hold.is_empty(), "a row half written is let go of");
        assert_eq!(hold.refused(), 3);
    }

    /// The stamp order: a stamped reply displaces an unstamped one and not the other way round,
    /// and a tie goes to the later.
    #[test]
    fn a_stamp_is_ordered_by_time_then_id_and_none_is_lowest() {
        let at = |time: u64, zid: &'static [u8]| Some(TimestampParts { time, zid });
        assert!(stamp_at_least(at(1, &[1]), None));
        assert!(!stamp_at_least(None, at(1, &[1])));
        assert!(stamp_at_least(None, None));
        assert!(stamp_at_least(at(1, &[1]), at(1, &[1])));
        assert!(stamp_at_least(at(1, &[2]), at(1, &[1])));
        assert!(!stamp_at_least(at(1, &[1]), at(2, &[0])));
    }
}
