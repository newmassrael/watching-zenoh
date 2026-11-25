// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The declarations a link owes its peer, told in turns: the cooperative engine's host of
//! `wz_session_core::replay_cursor::ReplayCursor` (the `declaration-sync-pacing` policy).
//!
//! A link that has just come up has a peer that holds none of what the session declared, so the
//! session declares it again, under the ids it was declared with. The session keeps its
//! declarations in lists by kind, so the sequence the cursor walks is the lists in one fixed order
//! (`ORDER`): the key expressions first, since a subscriber or an Interest may name one, then the
//! subscribers and the Interests, the queryables, the tokens and the liveliness subscribers'
//! Interests. The place of an entry is its kind's offset in that order plus its index in the list,
//! so a declaration or a retraction that is made while the replay goes on asks the cursor what to
//! do about the peer, and every list's push and remove goes through it (`announce` and
//! `retract`).
//!
//! Without the `declaration-sync-pacing` policy the replay is one turn of the whole sequence, as
//! zenoh-pico's client reopens (`vendor/zenoh-pico/src/net/session.c` @
//! `_z_fut_fn_result_t _z_client_reopen_task_fn(void *ztc_arg, _z_executor_t *executor) {`). With
//! it a turn is a burst of declarations and the next turn is an interval away, which the read's
//! idle wait is shortened to.
//!
//! A build whose domain of the policy leaves `on` out (`ReplayPacing::REACHABLE`) reaches no
//! pace, so it holds that one turn alone, as one lap over the sequence when the link comes up,
//! and nothing of the turns: no cursor moves, no place in the order is read, every face that is
//! up is told a declaration or a retraction as it is made, and no turn is ever due.
//!
//! A refused send is answered by the replay's pace. Without one, it ends the link, as zenoh-pico's
//! reopen task clears a transport it could not send a declaration over and opens again
//! (`vendor/zenoh-pico/src/net/session.c` @ `_z_transport_clear(&s->_tp);`): this engine builds
//! every frame on the heap, so a send is refused only when the link is gone or the declaration
//! cannot be made at all, and neither is a thing a later try on the same link outlives. A paced
//! replay answers a refused turn as its pace says (`ReplayPacing::after_refusal`), as the tokio
//! host does: it tries again from the entry the link refused after the pace's own retry wait, or,
//! with no retry wait or after the no-progress bound, gives the replay up and the link with it
//! ([`TurnEnd::EndsLink`]).

use super::LinkActions;
use wz_runtime_coop::faces::{FacePlaces, FaceRecord};
use wz_runtime_coop::session_drive::SessionLinks;
use wz_runtime_coop::ClockSource;
use wz_session_core::replay_cursor::{Insertion, Removal, ReplayCursor};
use wz_session_core::replay_pacing::{RefusalStep, ReplayPacing};
use wz_session_core::session_tables::{DeclaredRow, DeclaredTable};
use wz_session_core::slot_map::Handle;
use wz_session_core::wire_id::EntityId;

use super::{Core, Face};

/// The order the session's tables of declarations are told in. A declaration names what it depends
/// on by a mapping id, and the peer's tables are empty, so what a kind depends on comes before it.
const ORDER: &[DeclaredTable] = &[
    DeclaredTable::Keyexprs,
    DeclaredTable::Subscribers,
    DeclaredTable::Interests,
    #[cfg(feature = "queryable")]
    DeclaredTable::Queryables,
    #[cfg(feature = "liveliness")]
    DeclaredTable::Tokens,
    #[cfg(feature = "liveliness")]
    DeclaredTable::LivelinessSubscribers,
];

/// What a live declaration the link refused leaves of the replay.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum OnRefusal {
    /// The declaration is stored all the same and counts as told, as a refused live send always
    /// has here: the peer learns it when the session declares over a new link.
    Forget,
    /// The declaration is not made: the replay is as it was.
    Undo,
}

/// What a turn of a replay leaves of the link it was told over.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum TurnEnd {
    /// The link stays; the replay goes on at its next turn, if one is owed.
    Kept,
    /// The replay was given up on a turn the link refused, at once without a pace or when the
    /// pace said so: the link is to end, and the session tells everything again over the next one.
    EndsLink,
}

/// What a declaration sends a link, handed to the walks of the faces by reference: whether the link
/// took it. A trait of one method, so a value handed as `&dyn` has its body made once, where a
/// `dyn Fn`'s table holds `call` and `call_once` apart, each a copy of a small body.
pub(super) trait SendTo<C: ClockSource + 'static> {
    /// Send it over `actions`: whether the link took it.
    fn send_to(&self, actions: &LinkActions<C>) -> bool;
}

impl<C: ClockSource + 'static, F: Fn(&LinkActions<C>) -> bool> SendTo<C> for F {
    fn send_to(&self, actions: &LinkActions<C>) -> bool {
        self(actions)
    }
}

/// What a retraction or an undoing tells a link, handed by reference as [`SendTo`] is: a send
/// whose refusal changes nothing.
pub(super) trait TellTo<C: ClockSource + 'static> {
    /// Tell it over `actions`.
    fn tell_to(&self, actions: &LinkActions<C>);
}

impl<C: ClockSource + 'static, F: Fn(&LinkActions<C>)> TellTo<C> for F {
    fn tell_to(&self, actions: &LinkActions<C>) {
        self(actions);
    }
}

/// Where the replay of the current link stands; its pace is the session's
/// (`SessionState::replay_pacing`).
pub(super) struct Replay {
    /// How far the peer has been told. Idle while no link is established: a cursor is never
    /// resumed on another link, whose peer holds nothing.
    cursor: ReplayCursor,
    /// Not before this time, in milliseconds on the session's clock, does the next turn send.
    next_turn_ms: u64,
    /// When the replay last told the peer a declaration, or began, in milliseconds on the
    /// session's clock: what a pace's no-progress bound on retrying refused turns counts from.
    last_progress_ms: u64,
}

impl Replay {
    /// A replay of a face whose link is not up: nothing is owed.
    pub(super) fn idle() -> Self {
        Self {
            cursor: ReplayCursor::idle(),
            next_turn_ms: 0,
            last_progress_ms: 0,
        }
    }

    /// Begin, at `now_ms`, to tell a peer that holds nothing the `owed` declarations the session
    /// holds: the first turn is due at once.
    fn begin(&mut self, owed: usize, now_ms: u64) {
        self.cursor = ReplayCursor::begin(owed);
        self.next_turn_ms = now_ms;
        self.last_progress_ms = now_ms;
    }

    /// Keep what a turn at `now_ms` paced by `pacing` did, `cursor` being where it left the
    /// replay, `told` whether the link took any declaration of it and `refused` whether the link
    /// refused one, and say what the link is left with. An unfinished replay sends its next turn
    /// after the pace's interval, or, when the link refused a send, as the pace's answer to a
    /// refusal says ([`ReplayPacing::after_refusal`]); a session that is not paced gives the
    /// replay up on a refused send, as upstream's one call does (see the module's note). When the
    /// replay is given up, nothing more is owed over this link.
    fn settle(
        &mut self,
        cursor: ReplayCursor,
        told: bool,
        refused: bool,
        now_ms: u64,
        pacing: Option<ReplayPacing>,
    ) -> TurnEnd {
        self.cursor = cursor;
        if told {
            self.last_progress_ms = now_ms;
        }
        if cursor.finished() {
            return TurnEnd::Kept;
        }
        let wait_ms = if refused {
            let step = match pacing {
                Some(pace) => pace.after_refusal(self.last_progress_ms, now_ms),
                None => RefusalStep::EndsLink,
            };
            match step {
                RefusalStep::RetryIn(wait_ms) => wait_ms,
                RefusalStep::EndsLink => {
                    self.discard();
                    return TurnEnd::EndsLink;
                }
            }
        } else {
            // A turn the link took whole leaves more owed only under a pace, whose interval it
            // waits; an unpaced turn is the whole sequence.
            pacing.map_or(0, |pace| pace.interval_ms())
        };
        self.next_turn_ms = now_ms.saturating_add(wait_ms);
        TurnEnd::Kept
    }

    /// The link is gone: what the peer was told went with it.
    pub(super) fn discard(&mut self) {
        self.cursor = ReplayCursor::idle();
    }

    /// Whether the peer has been told everything the session owes it: always, in a build that
    /// reaches no pace, whose replay is one lap made when the link comes up.
    pub(super) fn finished(&self) -> bool {
        !ReplayPacing::REACHABLE || self.cursor.finished()
    }

    /// When the next turn is due, while a replay is owed: never, in a build that reaches no pace.
    pub(super) fn next_turn_ms(&self) -> Option<u64> {
        (ReplayPacing::REACHABLE && !self.cursor.finished()).then_some(self.next_turn_ms)
    }
}

impl<L: SessionLinks + 'static, C: ClockSource + Clone + 'static> Core<L, C> {
    /// The place of the declaration at `rank` of `table`'s slot order in the replay's order.
    /// Only a replay's cursor reads a place, so a build that reaches no pace reads none.
    pub(super) fn place(&self, table: DeclaredTable, rank: usize) -> usize {
        if !ReplayPacing::REACHABLE {
            return 0;
        }
        held_before(super::tables(&self.session.registry), Some(table)).saturating_add(rank)
    }

    /// The place in the replay's order of the declaration `declared` names, the one past the last
    /// of its table for a row that names none: its rank in its table's slot order, which the
    /// replay tells them in.
    // Out of line: every kind's declaration, and the retraction of a key expression, read it.
    #[inline(never)]
    pub(super) fn place_of(&self, declared: DeclaredRow) -> usize {
        if !ReplayPacing::REACHABLE {
            return 0;
        }
        let tables = super::tables(&self.session.registry);
        let slots = tables.slots_of(declared.table);
        let rank = slots.rank_of(declared.row).unwrap_or(slots.len());
        held_before(tables, Some(declared.table)).saturating_add(rank)
    }

    /// How many declarations the session holds, which is how many a replay owes.
    fn sequence_len(&self) -> usize {
        held_before(super::tables(&self.session.registry), None)
    }

    /// Tell the peer of the declaration at `place`: whether the link took it.
    fn emit(&self, actions: &LinkActions<C>, place: usize) -> bool {
        let tables = super::tables(&self.session.registry);
        let mut left = place;
        for &table in ORDER {
            let slots = tables.slots_of(table);
            let Some(rest) = left.checked_sub(slots.len()) else {
                return slots
                    .nth_live(left)
                    .is_none_or(|row| tell(tables, actions, DeclaredRow { table, row }));
            };
            left = rest;
        }
        // A place past the sequence is a defect of the cursor and has nothing to send.
        true
    }

    /// The link of the face at `at` has been established: begin to tell its peer what the session
    /// holds, and send the first turn of it; what that turn leaves of the link. In a build that
    /// reaches no pace the first turn is the whole of it ([`Self::tell_in_one_lap`]).
    /// Out of line: a link brought up and a redeclare each begin a replay.
    #[inline(never)]
    pub(super) fn begin_replay(
        &mut self,
        at: usize,
        actions: &LinkActions<C>,
        now_ms: u64,
    ) -> TurnEnd {
        if !ReplayPacing::REACHABLE {
            return self.tell_in_one_lap(actions);
        }
        let owed = self.sequence_len();
        if let Some(face) = self.transport.links.face_mut(at) {
            face.replay.begin(owed, now_ms);
        }
        self.replay_turn(at, actions, now_ms)
    }

    /// Tell the peer over `actions` every declaration the session holds, in the replay's order,
    /// in one lap, as upstream's reopen sends its whole cache of declarations (see the module's
    /// note): what the lap leaves of the link, [`TurnEnd::EndsLink`] at the first send the link
    /// refuses, as the reopen clears a transport it could not send one over. The replay of a
    /// build that reaches no pace, which keeps no cursor: the lap ends before the session does
    /// anything else, so nothing is owed past it.
    fn tell_in_one_lap(&self, actions: &LinkActions<C>) -> TurnEnd {
        if (0..self.sequence_len()).all(|place| self.emit(actions, place)) {
            TurnEnd::Kept
        } else {
            TurnEnd::EndsLink
        }
    }

    /// One turn of the replay of the face at `at`, if one is owed and due: the burst of the pace,
    /// or everything when the session is not paced, from the entry the last turn stopped at. What
    /// the turn leaves of the link: [`TurnEnd::EndsLink`] when the replay was given up on a
    /// refused send, which the caller answers by ending the link.
    pub(super) fn replay_turn(
        &mut self,
        at: usize,
        actions: &LinkActions<C>,
        now_ms: u64,
    ) -> TurnEnd {
        // A place with no face has no replay to send.
        let Some(Face { replay, .. }) = self.transport.links.face(at) else {
            return TurnEnd::Kept;
        };
        if replay.cursor.finished() || now_ms < replay.next_turn_ms {
            return TurnEnd::Kept;
        }
        let pacing = self.session.replay_pacing;
        let burst = pacing.map_or(usize::MAX, |pace| pace.burst());
        let mut cursor = replay.cursor;
        let mut told = false;
        let mut refused = false;
        for place in cursor.turn(burst) {
            if !self.emit(actions, place) {
                cursor.refused(place);
                refused = true;
                break;
            }
            told = true;
        }
        self.transport
            .links
            .face_mut(at)
            .map_or(TurnEnd::Kept, |face| {
                face.replay.settle(cursor, told, refused, now_ms, pacing)
            })
    }

    /// A declaration takes `place` in the replay's order: tell the peer of each
    /// face that is up of it with `send`, unless it is not to be told now, and say whether it was
    /// taken. It is not told to a face that is not up, which declares it when it comes up, and
    /// when that face's replay has not reached its place, which sends it in its turn; both count
    /// as taken. A refusal is answered as `on_refusal` says: [`OnRefusal::Forget`] counts what
    /// was refused as told, and [`OnRefusal::Undo`] makes the declaration over, putting every
    /// face's replay back as it was and taking back, with `undo`, what the faces that took it
    /// were told. Call it once for each declaration.
    fn announce_with(
        &mut self,
        place: usize,
        on_refusal: OnRefusal,
        send: &dyn SendTo<C>,
        undo: &dyn TellTo<C>,
    ) -> bool {
        announce_on(
            self.transport.links.places_mut(),
            place,
            on_refusal,
            send,
            undo,
        )
    }

    /// Tell each face that is up of the declaration `declared` names, as [`Self::announce_with`]
    /// tells one: its row is the declaration itself, so the tables stored it before any link is
    /// told of it, each link is told from the row, and a refusal leaves it stored.
    // Out of line: every kind's declaration announces through it.
    #[inline(never)]
    pub(super) fn announce(&mut self, declared: DeclaredRow) {
        let place = self.place_of(declared);
        let registry = &self.session.registry;
        announce_on(
            self.transport.links.places_mut(),
            place,
            OnRefusal::Forget,
            &|actions: &LinkActions<C>| tell(super::tables(registry), actions, declared),
            &undo_nothing::<C>,
        );
    }

    /// [`Self::announce_with`] for a declaration stored at `place` that is not made when a link
    /// refuses it: whether it was made.
    // Out of line: the key expression and entity declarations that may be undone announce through it.
    #[inline(never)]
    pub(super) fn announce_or_undo_at(
        &mut self,
        place: usize,
        send: &dyn SendTo<C>,
        undo: &dyn TellTo<C>,
    ) -> bool {
        self.announce_with(place, OnRefusal::Undo, send, undo)
    }

    /// The declaration at `index` of `table`'s slot order was removed: retract it with `send`
    /// ([`Self::retract_at`]). `index` is where it lay, and the tables before it in the replay's
    /// order are as they were.
    pub(super) fn retract(&mut self, table: DeclaredTable, index: usize, send: &dyn TellTo<C>) {
        let place = self.place(table, index);
        self.retract_at(place, send);
    }

    /// The Interest `interest`, which a write filter or a matching listener held last, ended:
    /// tell each face whose peer was asked it, `rank` its place among the Interests read while
    /// it stood ([`Self::retract`]). Nothing when either is `None`.
    // Out of line: the filter's and the listener's undeclarations end their Interest alike.
    #[inline(never)]
    pub(super) fn end_interest(&mut self, interest: Option<EntityId>, rank: Option<usize>) {
        if let (Some(interest), Some(at)) = (interest, rank) {
            self.retract(
                DeclaredTable::Interests,
                at,
                &super::interest_final::<C>(u64::from(interest)),
            );
        }
    }

    /// The declaration that lay at `place` in the replay's order was removed: tell, with `send`,
    /// each face that is up and whose peer was told of it, and move every face's replay past it.
    /// Call it once, after the row went, with the place read while it stood: a send then finds
    /// none of the session's tables borrowed, and nothing is kept to send later.
    #[inline(never)]
    pub(super) fn retract_at(&mut self, place: usize, send: &dyn TellTo<C>) {
        for face in self.transport.links.faces_mut() {
            let Some(wire) = face.up() else {
                continue;
            };
            // A build that reaches no pace told the peer everything when its link came up.
            if !ReplayPacing::REACHABLE
                || matches!(face.replay.cursor.removed(place), Removal::Retract)
            {
                send.tell_to(&wire.actions);
            }
        }
    }
}

/// The undoing of a declaration that is kept whatever a link makes of it: nothing. One function
/// for every such caller, so its call through `&dyn TellTo` is made once.
fn undo_nothing<C: ClockSource + 'static>(_actions: &LinkActions<C>) {}

/// How many declarations the session holds in the tables before `end` in the replay's order, or
/// in every table when `end` is `None`: the place of `end`'s first declaration, or the length
/// of the sequence. The counts are of declarations the session holds in memory, so no sum of them
/// reaches `usize::MAX`; were one to, it would saturate to a place past the sequence, which has
/// nothing to send.
fn held_before(tables: &super::CoopTables, end: Option<DeclaredTable>) -> usize {
    ORDER
        .iter()
        .take_while(|&&table| Some(table) != end)
        .map(|&table| tables.slots_of(table).len())
        .fold(0, usize::saturating_add)
}

/// Tell the peer over `actions` of the declaration `declared` names, read from its row in
/// `tables`: whether the link took it. One body for every kind, which reads the kind, so a turn of
/// the replay and a declaration announced to the faces build each kind's message here alone. A row
/// that names none has nothing to send, which counts as taken.
fn tell<C: ClockSource + 'static>(
    tables: &super::CoopTables,
    actions: &LinkActions<C>,
    declared: DeclaredRow,
) -> bool {
    told(tables, actions, declared).unwrap_or(true)
}

/// [`tell`], `None` when `declared` names no row.
fn told<C: ClockSource + 'static>(
    tables: &super::CoopTables,
    actions: &LinkActions<C>,
    declared: DeclaredRow,
) -> Option<bool> {
    let bits = declared.row;
    Some(match declared.table {
        DeclaredTable::Keyexprs => {
            let row = tables.keyexprs().get(Handle::from_bits(bits)?)?;
            actions.send_declare_keyexpr(row.id(), row.key()).is_ok()
        }
        DeclaredTable::Subscribers => {
            let row = tables.subscribers().get(Handle::from_bits(bits)?)?;
            tables
                .named(row.key())
                .is_some_and(|key| super::SubscriberRow::declare(row.id(), key, actions))
        }
        DeclaredTable::Interests => {
            let row = tables.interests().get(Handle::from_bits(bits)?)?;
            super::send_interest(row, actions)
        }
        #[cfg(feature = "queryable")]
        DeclaredTable::Queryables => {
            let row = tables.queryables().get(Handle::from_bits(bits)?)?;
            tables.named(row.key()).is_some_and(|key| {
                super::QueryableRow::declare(row.id(), key, row.complete(), actions)
            })
        }
        #[cfg(feature = "liveliness")]
        DeclaredTable::Tokens => {
            let row = tables.tokens().get(Handle::from_bits(bits)?)?;
            tables
                .named(row.key())
                .is_some_and(|key| super::liveliness::declare_token(actions, row.id(), key))
        }
        #[cfg(feature = "liveliness")]
        DeclaredTable::LivelinessSubscribers => {
            let row = tables
                .liveliness_subscribers()
                .get(Handle::from_bits(bits)?)?;
            super::liveliness::ask(
                actions,
                row.id(),
                row.key().as_str(),
                tables.wire_of(row.key()),
                row.history(),
            )
        }
        // A kind the build keeps no table of holds no row.
        #[cfg(not(feature = "queryable"))]
        DeclaredTable::Queryables => return None,
        #[cfg(not(feature = "liveliness"))]
        DeclaredTable::Tokens | DeclaredTable::LivelinessSubscribers => return None,
    })
}

/// [`Core::announce_with`] over `faces` alone, so a caller can read another part of the session
/// (a row of the session core's tables) in `send` while the faces are written. One body for every
/// kind of declaration: `send` and `undo` are handed by reference, not as types of their own.
///
/// Each face that is up is offered the declaration where its replay stands, and the replays move
/// only once the declaration is made: a refusal that undoes it stops at the face that refused,
/// takes back what the faces before it were sent and leaves every replay as it was, so nothing is
/// kept to put back.
#[inline(never)]
fn announce_on<C: ClockSource + 'static, L: SessionLinks + 'static>(
    faces: &mut impl FacePlaces<Face<C, L>>,
    place: usize,
    on_refusal: OnRefusal,
    send: &dyn SendTo<C>,
    undo: &dyn TellTo<C>,
) -> bool {
    // Whether the replay of `face` is past the declaration, so its link is told it now: always,
    // in a build that reaches no pace, whose replay ended with the lap its link came up with.
    let emits_now = |face: &Face<C, L>| {
        if !ReplayPacing::REACHABLE {
            return true;
        }
        let mut cursor = face.replay.cursor;
        cursor.inserted(place) == Insertion::EmitNow
    };
    let mut refused_at = None;
    for (at, face) in faces.placed() {
        let Some(wire) = face.up() else {
            continue;
        };
        if emits_now(face) && !send.send_to(&wire.actions) && on_refusal == OnRefusal::Undo {
            refused_at = Some(at);
            break;
        }
    }
    if let Some(refused) = refused_at {
        for (_, face) in faces.placed().take_while(|(at, _)| *at < refused) {
            if let Some(wire) = face.up() {
                if emits_now(face) {
                    undo.tell_to(&wire.actions);
                }
            }
        }
        return false;
    }
    if ReplayPacing::REACHABLE {
        for face in faces.iter_mut() {
            if face.up().is_some() {
                // The face was told it above, or its replay tells it in its turn.
                let _ = face.replay.cursor.inserted(place);
            }
        }
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The cursor a turn of `burst` leaves when the link refuses its first send.
    fn refused_at_once(replay: &Replay, burst: usize) -> ReplayCursor {
        let mut cursor = replay.cursor;
        let places = cursor.turn(burst);
        cursor.refused(places.start);
        cursor
    }

    /// A pace of two a turn every 10 ms that answers a refused turn by waiting `retry_ms` and
    /// gives up after `bound_ms` with nothing told: values inside a host build's domains of the
    /// two retry limits.
    fn pace_answering(retry_ms: usize, bound_ms: usize) -> Option<ReplayPacing> {
        ReplayPacing::new(2, 10).map(|pace| {
            pace.with_refusal(retry_ms, bound_ms)
                .expect("a host build's domains hold every retry value")
        })
    }

    /// With no retry wait, the retry limit's default, a refused turn gives the replay up and the
    /// link with it, as the tokio host's does: it is not tried again at the turn interval, and
    /// nothing more is owed over that link.
    #[test]
    fn a_refused_turn_ends_the_link_when_the_pace_retries_nothing() {
        // A build that reaches no pace has no turn to time (`Replay::next_turn_ms`).
        if !ReplayPacing::REACHABLE {
            return;
        }
        let pace = pace_answering(0, 0);
        let mut replay = Replay::idle();
        replay.begin(5, 100);
        let cursor = refused_at_once(&replay, 2);
        assert_eq!(
            replay.settle(cursor, false, true, 100, pace),
            TurnEnd::EndsLink
        );
        assert!(replay.finished(), "the link that ends is owed nothing more");
        assert_eq!(replay.next_turn_ms(), None);
    }

    /// With a retry wait, a refused turn is tried again after that wait and not the turn
    /// interval, until no declaration has gone out for the no-progress bound, counted from the
    /// start of the replay when none has.
    #[test]
    fn a_refused_turn_is_retried_at_the_retry_wait_until_no_progress_ends_the_link() {
        // A build that reaches no pace has no turn to time (`Replay::next_turn_ms`).
        if !ReplayPacing::REACHABLE {
            return;
        }
        let pace = pace_answering(3, 50);
        let mut replay = Replay::idle();
        replay.begin(5, 100);
        let cursor = refused_at_once(&replay, 2);
        assert_eq!(replay.settle(cursor, false, true, 120, pace), TurnEnd::Kept);
        assert_eq!(
            replay.next_turn_ms(),
            Some(123),
            "the retry wait (3 ms), not the turn interval (10 ms)"
        );
        let cursor = refused_at_once(&replay, 2);
        assert_eq!(replay.settle(cursor, false, true, 149, pace), TurnEnd::Kept);
        let cursor = refused_at_once(&replay, 2);
        assert_eq!(
            replay.settle(cursor, false, true, 150, pace),
            TurnEnd::EndsLink,
            "50 ms with nothing told since the replay began"
        );
        assert!(replay.finished());
    }

    /// A declaration the link took starts the no-progress stretch again, even in a turn the link
    /// then cut short; and a no-progress bound of 0 never gives up.
    #[test]
    fn a_declaration_told_starts_the_no_progress_stretch_again() {
        // A build that reaches no pace has no turn to time (`Replay::next_turn_ms`).
        if !ReplayPacing::REACHABLE {
            return;
        }
        let pace = pace_answering(3, 50);
        let mut replay = Replay::idle();
        replay.begin(5, 100);
        let mut cursor = replay.cursor;
        let places = cursor.turn(2);
        cursor.refused(places.start + 1);
        assert_eq!(replay.settle(cursor, true, true, 140, pace), TurnEnd::Kept);
        let cursor = refused_at_once(&replay, 2);
        assert_eq!(replay.settle(cursor, false, true, 189, pace), TurnEnd::Kept);
        let cursor = refused_at_once(&replay, 2);
        assert_eq!(
            replay.settle(cursor, false, true, 190, pace),
            TurnEnd::EndsLink
        );

        let patient = pace_answering(3, 0);
        let mut replay = Replay::idle();
        replay.begin(5, 0);
        let cursor = refused_at_once(&replay, 2);
        assert_eq!(
            replay.settle(cursor, false, true, u64::MAX, patient),
            TurnEnd::Kept
        );
    }

    /// A turn the link took whole waits the interval when more is owed and nothing when all is
    /// told.
    #[test]
    fn a_turn_not_refused_waits_the_interval_until_all_is_told() {
        // A build that reaches no pace has no turn to time (`Replay::next_turn_ms`).
        if !ReplayPacing::REACHABLE {
            return;
        }
        let pace = ReplayPacing::new(2, 10);
        let mut paced = Replay::idle();
        paced.begin(5, 100);
        let mut cursor = paced.cursor;
        let _ = cursor.turn(2);
        assert_eq!(paced.settle(cursor, true, false, 100, pace), TurnEnd::Kept);
        assert_eq!(paced.next_turn_ms(), Some(110));
        let mut cursor = paced.cursor;
        let _ = cursor.turn(usize::MAX);
        assert_eq!(paced.settle(cursor, true, false, 110, pace), TurnEnd::Kept);
        assert!(paced.finished());
    }

    /// A session that is not paced gives its replay up on the first send the link refuses, even
    /// after the link took some of the turn, so the link ends and the next one is told everything
    /// from the start, as upstream's reopen does; it does not try the send again on this link.
    #[test]
    fn an_unpaced_refusal_ends_the_link() {
        let mut unpaced = Replay::idle();
        unpaced.begin(3, 100);
        let mut cursor = unpaced.cursor;
        let places = cursor.turn(usize::MAX);
        cursor.refused(places.start + 1);
        assert_eq!(
            unpaced.settle(cursor, true, true, 100, None),
            TurnEnd::EndsLink
        );
        assert!(
            unpaced.finished(),
            "the link that ends is owed nothing more"
        );
        assert_eq!(unpaced.next_turn_ms(), None);

        // Control: the same session with nothing refused tells everything and keeps its link.
        let mut whole = Replay::idle();
        whole.begin(3, 100);
        let mut cursor = whole.cursor;
        let _ = cursor.turn(usize::MAX);
        assert_eq!(whole.settle(cursor, true, false, 100, None), TurnEnd::Kept);
        assert!(whole.finished());
    }
}
