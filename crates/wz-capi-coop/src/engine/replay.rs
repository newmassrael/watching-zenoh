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
//! A refused send is answered by the replay's pace. Without one, it ends the link, as zenoh-pico's
//! reopen task clears a transport it could not send a declaration over and opens again
//! (`vendor/zenoh-pico/src/net/session.c` @ `_z_transport_clear(&s->_tp);`): this engine builds
//! every frame on the heap, so a send is refused only when the link is gone or the declaration
//! cannot be made at all, and neither is a thing a later try on the same link outlives. A paced
//! replay answers a refused turn as its pace says (`ReplayPacing::after_refusal`), as the tokio
//! host does: it tries again from the entry the link refused after the pace's own retry wait, or,
//! with no retry wait or after the no-progress bound, gives the replay up and the link with it
//! ([`TurnEnd::EndsLink`]).

use alloc::rc::Rc;

use wz_runtime_coop::session_drive::SessionLinks;
use wz_runtime_coop::ClockSource;
use wz_session_core::replay_cursor::{Insertion, Removal, ReplayCursor};
use wz_session_core::replay_pacing::{RefusalStep, ReplayPacing};
use wz_session_core::session_tables::KeyexprHandle;
#[cfg(feature = "liveliness")]
use wz_session_core::session_tables::TokenHandle;
use wz_session_mcu::dial::McuActions;

use super::{Core, Face, Link};
use crate::prelude::*;

/// The kinds of declaration a session holds, which is to say the lists the replay walks.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Kind {
    Keyexpr,
    Subscriber,
    Interest,
    #[cfg(feature = "queryable")]
    Queryable,
    #[cfg(feature = "liveliness")]
    Token,
    #[cfg(feature = "liveliness")]
    LiveSub,
}

/// The order the kinds are told in. A declaration names what it depends on by a mapping id, and
/// the peer's tables are empty, so what a kind depends on comes before it.
const ORDER: &[Kind] = &[
    Kind::Keyexpr,
    Kind::Subscriber,
    Kind::Interest,
    #[cfg(feature = "queryable")]
    Kind::Queryable,
    #[cfg(feature = "liveliness")]
    Kind::Token,
    #[cfg(feature = "liveliness")]
    Kind::LiveSub,
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

/// Where the replay of the current link stands, and how it is paced.
pub(super) struct Replay {
    /// How far the peer has been told. Idle while no link is established: a cursor is never
    /// resumed on another link, whose peer holds nothing.
    cursor: ReplayCursor,
    /// `None` is one turn for the whole sequence; the session's policy states a pace otherwise.
    pacing: Option<ReplayPacing>,
    /// Not before this time, in milliseconds on the session's clock, does the next turn send.
    next_turn_ms: u64,
    /// When the replay last told the peer a declaration, or began, in milliseconds on the
    /// session's clock: what a pace's no-progress bound on retrying refused turns counts from.
    last_progress_ms: u64,
}

impl Replay {
    /// A replay that tells at the pace `pacing` states: the session's policies' for the dial
    /// role's face, and the pace the face before it was set to for any other.
    pub(super) fn with_pacing(pacing: Option<ReplayPacing>) -> Self {
        Self {
            cursor: ReplayCursor::idle(),
            pacing,
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

    /// Keep what a turn at `now_ms` did, `cursor` being where it left the replay, `told` whether
    /// the link took any declaration of it and `refused` whether the link refused one, and say
    /// what the link is left with. An unfinished replay sends its next turn after the pace's
    /// interval, or, when the link refused a send, as the pace's answer to a refusal says
    /// ([`ReplayPacing::after_refusal`]); a session that is not paced gives the replay up on a
    /// refused send, as upstream's one call does (see the module's note). When the replay is
    /// given up, nothing more is owed over this link.
    fn settle(&mut self, cursor: ReplayCursor, told: bool, refused: bool, now_ms: u64) -> TurnEnd {
        self.cursor = cursor;
        if told {
            self.last_progress_ms = now_ms;
        }
        if cursor.finished() {
            return TurnEnd::Kept;
        }
        let wait_ms = if refused {
            let step = match self.pacing {
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
            self.pacing.map_or(0, |pace| pace.interval_ms())
        };
        self.next_turn_ms = now_ms.saturating_add(wait_ms);
        TurnEnd::Kept
    }

    /// How a link's declarations go out: what a face added beside the dial role's is told its
    /// declarations at, and what a test reads.
    #[cfg(any(feature = "listen", all(test, feature = "std")))]
    pub(super) fn pacing(&self) -> Option<ReplayPacing> {
        self.pacing
    }

    /// State how a link's declarations go out, for a caller that wants a pace regardless of the
    /// session's policies, which state it otherwise.
    pub(super) fn set_pacing(&mut self, pacing: Option<ReplayPacing>) {
        self.pacing = pacing;
    }

    /// The link is gone: what the peer was told went with it.
    pub(super) fn discard(&mut self) {
        self.cursor = ReplayCursor::idle();
    }

    /// Whether the peer has been told everything the session owes it.
    pub(super) fn finished(&self) -> bool {
        self.cursor.finished()
    }

    /// When the next turn is due, while a replay is owed.
    pub(super) fn next_turn_ms(&self) -> Option<u64> {
        (!self.cursor.finished()).then_some(self.next_turn_ms)
    }
}

impl<L: SessionLinks + 'static, C: ClockSource + Clone + 'static> Core<L, C> {
    /// How many declarations of `kind` the session holds.
    fn len_of(&self, kind: Kind) -> usize {
        match kind {
            Kind::Keyexpr => self.tables.borrow().keyexprs().len(),
            Kind::Subscriber => self.registry.borrow().app.subscribers.len(),
            Kind::Interest => self.interests.len(),
            #[cfg(feature = "queryable")]
            Kind::Queryable => self.queryables.len(),
            #[cfg(feature = "liveliness")]
            Kind::Token => self.tables.borrow().tokens().len(),
            #[cfg(feature = "liveliness")]
            Kind::LiveSub => self.live_subs.len(),
        }
    }

    /// The place of the first declaration of `kind` in the replay's order.
    fn start_of(&self, kind: Kind) -> usize {
        ORDER
            .iter()
            .take_while(|&&earlier| earlier != kind)
            .map(|&earlier| self.len_of(earlier))
            .sum()
    }

    /// The place a declaration of `kind` stored next takes in the replay's order.
    fn end_of(&self, kind: Kind) -> usize {
        self.start_of(kind) + self.len_of(kind)
    }

    /// How many declarations the session holds, which is how many a replay owes.
    fn sequence_len(&self) -> usize {
        ORDER.iter().map(|&kind| self.len_of(kind)).sum()
    }

    /// Tell the peer of the declaration at `place`: whether the link took it.
    fn emit(&self, actions: &McuActions<C>, place: usize) -> bool {
        let mut left = place;
        for &kind in ORDER {
            let len = self.len_of(kind);
            if left >= len {
                left -= len;
                continue;
            }
            return match kind {
                Kind::Keyexpr => {
                    let tables = self.tables.borrow();
                    let row = tables.keyexprs().iter().nth(left);
                    row.map_or(true, |(_, row)| {
                        actions.send_declare_keyexpr(row.id(), row.key()).is_ok()
                    })
                }
                Kind::Subscriber => match self.registry.borrow().app.subscribers.row_at(left) {
                    Some((keyexpr, row)) => row.declare(keyexpr, actions),
                    None => true,
                },
                Kind::Interest => self.interests[left].send(actions),
                #[cfg(feature = "queryable")]
                Kind::Queryable => self.queryables[left].declare(actions),
                #[cfg(feature = "liveliness")]
                Kind::Token => {
                    let tables = self.tables.borrow();
                    let row = tables.tokens().iter().nth(left);
                    let told = row.map_or(true, |(_, row)| {
                        super::liveliness::declare_token(
                            actions,
                            row.id(),
                            row.key().as_str(),
                            tables.wire_of(row.key()),
                        )
                    });
                    told
                }
                #[cfg(feature = "liveliness")]
                Kind::LiveSub => self.live_subs[left].ask(actions),
            };
        }
        // A place past the sequence is a defect of the cursor and has nothing to send.
        true
    }

    /// The link of the face at `at` has been established: begin to tell its peer what the session
    /// holds, and send the first turn of it; what that turn leaves of the link.
    pub(super) fn begin_replay(
        &mut self,
        at: usize,
        actions: &McuActions<C>,
        now_ms: u64,
    ) -> TurnEnd {
        let owed = self.sequence_len();
        self.faces[at].replay.begin(owed, now_ms);
        self.replay_turn(at, actions, now_ms)
    }

    /// One turn of the replay of the face at `at`, if one is owed and due: the burst of the pace,
    /// or everything when the session is not paced, from the entry the last turn stopped at. What
    /// the turn leaves of the link: [`TurnEnd::EndsLink`] when the replay was given up on a
    /// refused send, which the caller answers by ending the link.
    pub(super) fn replay_turn(
        &mut self,
        at: usize,
        actions: &McuActions<C>,
        now_ms: u64,
    ) -> TurnEnd {
        let replay = &self.faces[at].replay;
        if replay.cursor.finished() || now_ms < replay.next_turn_ms {
            return TurnEnd::Kept;
        }
        let burst = replay.pacing.map_or(usize::MAX, |pace| pace.burst());
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
        self.faces[at].replay.settle(cursor, told, refused, now_ms)
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
        send: impl Fn(&McuActions<C>) -> bool,
        undo: impl Fn(&McuActions<C>),
    ) -> bool {
        announce_on(&mut self.faces, place, on_refusal, send, undo)
    }

    /// [`Self::announce_with`] for a declaration that is stored whatever a link makes of it: one
    /// that a link refused is counted as told, and the peer learns it when the session declares
    /// over a new link.
    pub(super) fn announce(&mut self, kind: Kind, send: impl Fn(&McuActions<C>) -> bool) {
        let place = self.end_of(kind);
        self.announce_with(place, OnRefusal::Forget, send, |_| {});
    }

    /// Tell each face that is up of the subscriber at `index` of the session core's table, as
    /// [`Self::announce`] tells a declaration: the row is the declaration itself, so the table
    /// stored it before any link is told of it, and each link is told from the row.
    pub(super) fn announce_subscriber(&mut self, index: usize) {
        let place = self.start_of(Kind::Subscriber) + index;
        let registry = &self.registry;
        announce_on(
            &mut self.faces,
            place,
            OnRefusal::Forget,
            |actions| {
                registry
                    .borrow()
                    .app
                    .subscribers
                    .row_at(index)
                    .is_some_and(|(keyexpr, row)| row.declare(keyexpr, actions))
            },
            |_| {},
        );
    }

    /// [`Self::announce_with`] for a declaration stored at `place` that is not made when a link
    /// refuses it: whether it was made.
    pub(super) fn announce_or_undo_at(
        &mut self,
        place: usize,
        send: impl Fn(&McuActions<C>) -> bool,
        undo: impl Fn(&McuActions<C>),
    ) -> bool {
        self.announce_with(place, OnRefusal::Undo, send, undo)
    }

    /// The place in the replay's order of the key expression `handle` names, the one past the last
    /// for a handle that names none. The table's rows are walked in their slot order, which is the
    /// order the replay tells them in.
    pub(super) fn keyexpr_place(&self, handle: KeyexprHandle) -> usize {
        let tables = self.tables.borrow();
        let keyexprs = tables.keyexprs();
        let rank = keyexprs
            .iter()
            .position(|(held, _)| held == handle)
            .unwrap_or(keyexprs.len());
        self.start_of(Kind::Keyexpr) + rank
    }

    /// The place in the replay's order of the token `handle` names, the one past the last for a
    /// handle that names none: its rank in the table's slot order, which the replay tells them in.
    #[cfg(feature = "liveliness")]
    pub(super) fn token_place(&self, handle: TokenHandle) -> usize {
        let tables = self.tables.borrow();
        let tokens = tables.tokens();
        let rank = tokens
            .iter()
            .position(|(held, _)| held == handle)
            .unwrap_or(tokens.len());
        self.start_of(Kind::Token) + rank
    }

    /// Tell each face that is up of the token `handle` names, as [`Self::announce`] tells a
    /// declaration: the row is the declaration itself, so the tables stored it before any link is
    /// told of it, and each link is told from the row.
    #[cfg(feature = "liveliness")]
    pub(super) fn announce_token(&mut self, handle: TokenHandle) {
        let place = self.token_place(handle);
        let tables = &self.tables;
        announce_on(
            &mut self.faces,
            place,
            OnRefusal::Forget,
            |actions| {
                let tables = tables.borrow();
                let taken = tables.tokens().get(handle).is_some_and(|row| {
                    super::liveliness::declare_token(
                        actions,
                        row.id(),
                        row.key().as_str(),
                        tables.wire_of(row.key()),
                    )
                });
                taken
            },
            |_| {},
        );
    }

    /// The declaration at `index` of `kind`'s list is about to be removed: the links to retract it
    /// over ([`Self::retract_at`]). Call it once, before the removal.
    pub(super) fn retract(&mut self, kind: Kind, index: usize) -> Vec<Rc<McuActions<C>>> {
        let place = self.start_of(kind) + index;
        self.retract_at(place)
    }

    /// The declaration at `place` in the replay's order is about to be removed: the links to
    /// retract it over, which are those of the faces that are up and whose peers were told of it.
    /// Call it once, before the removal.
    pub(super) fn retract_at(&mut self, place: usize) -> Vec<Rc<McuActions<C>>> {
        let mut links = Vec::new();
        for face in &mut self.faces {
            let Link::Up(wire) = &face.link else {
                continue;
            };
            if matches!(face.replay.cursor.removed(place), Removal::Retract) {
                links.push(wire.actions.clone());
            }
        }
        links
    }
}

/// [`Core::announce_with`] over `faces` alone, so a caller can read another part of the session
/// (a row of the session core's tables) in `send` while the faces are written.
fn announce_on<C: ClockSource + 'static>(
    faces: &mut [Face<C>],
    place: usize,
    on_refusal: OnRefusal,
    send: impl Fn(&McuActions<C>) -> bool,
    undo: impl Fn(&McuActions<C>),
) -> bool {
    // What each face's replay was and what its link made of the declaration, so that a refusal
    // that undoes the declaration can put every face back.
    let mut told: Vec<(usize, ReplayCursor, Told)> = Vec::new();
    for (at, face) in faces.iter_mut().enumerate() {
        let Link::Up(wire) = &face.link else {
            continue;
        };
        let before = face.replay.cursor;
        let outcome = match face.replay.cursor.inserted(place) {
            Insertion::Owed => Told::Owed,
            Insertion::EmitNow if send(&wire.actions) => Told::Sent,
            Insertion::EmitNow => Told::Refused,
        };
        told.push((at, before, outcome));
    }
    let refused = told.iter().any(|(_, _, outcome)| *outcome == Told::Refused);
    if !refused || on_refusal == OnRefusal::Forget {
        return true;
    }
    for (at, before, outcome) in told {
        let face = &mut faces[at];
        face.replay.cursor = before;
        if let (Told::Sent, Link::Up(wire)) = (outcome, &face.link) {
            undo(&wire.actions);
        }
    }
    false
}

/// What a face's link made of a declaration it was offered.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Told {
    /// The face's replay has not reached the declaration: it is sent in its turn.
    Owed,
    /// The link took it now.
    Sent,
    /// The link refused it.
    Refused,
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
        let mut replay = Replay::with_pacing(pace_answering(0, 0));
        replay.begin(5, 100);
        let cursor = refused_at_once(&replay, 2);
        assert_eq!(replay.settle(cursor, false, true, 100), TurnEnd::EndsLink);
        assert!(replay.finished(), "the link that ends is owed nothing more");
        assert_eq!(replay.next_turn_ms(), None);
    }

    /// With a retry wait, a refused turn is tried again after that wait and not the turn
    /// interval, until no declaration has gone out for the no-progress bound, counted from the
    /// start of the replay when none has.
    #[test]
    fn a_refused_turn_is_retried_at_the_retry_wait_until_no_progress_ends_the_link() {
        let pace = pace_answering(3, 50);
        let mut replay = Replay::with_pacing(pace);
        replay.begin(5, 100);
        let cursor = refused_at_once(&replay, 2);
        assert_eq!(replay.settle(cursor, false, true, 120), TurnEnd::Kept);
        assert_eq!(
            replay.next_turn_ms(),
            Some(123),
            "the retry wait (3 ms), not the turn interval (10 ms)"
        );
        let cursor = refused_at_once(&replay, 2);
        assert_eq!(replay.settle(cursor, false, true, 149), TurnEnd::Kept);
        let cursor = refused_at_once(&replay, 2);
        assert_eq!(
            replay.settle(cursor, false, true, 150),
            TurnEnd::EndsLink,
            "50 ms with nothing told since the replay began"
        );
        assert!(replay.finished());
    }

    /// A declaration the link took starts the no-progress stretch again, even in a turn the link
    /// then cut short; and a no-progress bound of 0 never gives up.
    #[test]
    fn a_declaration_told_starts_the_no_progress_stretch_again() {
        let pace = pace_answering(3, 50);
        let mut replay = Replay::with_pacing(pace);
        replay.begin(5, 100);
        let mut cursor = replay.cursor;
        let places = cursor.turn(2);
        cursor.refused(places.start + 1);
        assert_eq!(replay.settle(cursor, true, true, 140), TurnEnd::Kept);
        let cursor = refused_at_once(&replay, 2);
        assert_eq!(replay.settle(cursor, false, true, 189), TurnEnd::Kept);
        let cursor = refused_at_once(&replay, 2);
        assert_eq!(replay.settle(cursor, false, true, 190), TurnEnd::EndsLink);

        let patient = pace_answering(3, 0);
        let mut replay = Replay::with_pacing(patient);
        replay.begin(5, 0);
        let cursor = refused_at_once(&replay, 2);
        assert_eq!(replay.settle(cursor, false, true, u64::MAX), TurnEnd::Kept);
    }

    /// A turn the link took whole waits the interval when more is owed and nothing when all is
    /// told.
    #[test]
    fn a_turn_not_refused_waits_the_interval_until_all_is_told() {
        let mut paced = Replay::with_pacing(ReplayPacing::new(2, 10));
        paced.begin(5, 100);
        let mut cursor = paced.cursor;
        let _ = cursor.turn(2);
        assert_eq!(paced.settle(cursor, true, false, 100), TurnEnd::Kept);
        assert_eq!(paced.next_turn_ms(), Some(110));
        let mut cursor = paced.cursor;
        let _ = cursor.turn(usize::MAX);
        assert_eq!(paced.settle(cursor, true, false, 110), TurnEnd::Kept);
        assert!(paced.finished());
    }

    /// A session that is not paced gives its replay up on the first send the link refuses, even
    /// after the link took some of the turn, so the link ends and the next one is told everything
    /// from the start, as upstream's reopen does; it does not try the send again on this link.
    #[test]
    fn an_unpaced_refusal_ends_the_link() {
        let mut unpaced = Replay::with_pacing(None);
        unpaced.begin(3, 100);
        let mut cursor = unpaced.cursor;
        let places = cursor.turn(usize::MAX);
        cursor.refused(places.start + 1);
        assert_eq!(unpaced.settle(cursor, true, true, 100), TurnEnd::EndsLink);
        assert!(
            unpaced.finished(),
            "the link that ends is owed nothing more"
        );
        assert_eq!(unpaced.next_turn_ms(), None);

        // Control: the same session with nothing refused tells everything and keeps its link.
        let mut whole = Replay::with_pacing(None);
        whole.begin(3, 100);
        let mut cursor = whole.cursor;
        let _ = cursor.turn(usize::MAX);
        assert_eq!(whole.settle(cursor, true, false, 100), TurnEnd::Kept);
        assert!(whole.finished());
    }
}
