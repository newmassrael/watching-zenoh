// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The declarations a link owes its peer, told in turns: the cooperative engine's host of
//! `wz_session_core::replay_cursor::ReplayCursor` (`docs/declaration-sync-pacing.md`).
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
//! idle wait is shortened to. A send the link refused is not lost in either case: the next turn
//! starts at the entry it failed on.

use alloc::rc::Rc;

use wz_runtime_coop::session_drive::SessionLinks;
use wz_runtime_coop::ClockSource;
use wz_session_core::replay_cursor::{Insertion, Removal, ReplayCursor};
use wz_session_core::replay_pacing::ReplayPacing;
use wz_session_mcu::dial::McuActions;

use super::{Core, Link};
use crate::prelude::*;

/// How long a turn that a refused send cut short waits when the session is not paced, so a link
/// that keeps refusing is asked again on the next step and not in a spin.
const RETRY_MS: u64 = 1;

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

/// Where the replay of the current link stands, and how it is paced.
pub(super) struct Replay {
    /// How far the peer has been told. Idle while no link is established: a cursor is never
    /// resumed on another link, whose peer holds nothing.
    cursor: ReplayCursor,
    /// `None` is one turn for the whole sequence; the build's policy states a pace otherwise.
    pacing: Option<ReplayPacing>,
    /// Not before this time, in milliseconds on the session's clock, does the next turn send.
    next_turn_ms: u64,
}

impl Replay {
    pub(super) fn new() -> Self {
        Self::with_pacing(ReplayPacing::BUILD)
    }

    /// A replay that tells at the pace `pacing` states, as the face before it was set to.
    pub(super) fn with_pacing(pacing: Option<ReplayPacing>) -> Self {
        Self {
            cursor: ReplayCursor::idle(),
            pacing,
            next_turn_ms: 0,
        }
    }

    /// How a link's declarations go out.
    pub(super) fn pacing(&self) -> Option<ReplayPacing> {
        self.pacing
    }

    /// State how a link's declarations go out, for a caller that wants a pace regardless of the
    /// build; the build states it by default.
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
            Kind::Keyexpr => self.keyexprs.len(),
            Kind::Subscriber => self.subscribers.len(),
            Kind::Interest => self.interests.len(),
            #[cfg(feature = "queryable")]
            Kind::Queryable => self.queryables.len(),
            #[cfg(feature = "liveliness")]
            Kind::Token => self.tokens.len(),
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
                    let entry = &self.keyexprs[left];
                    actions
                        .send_declare_keyexpr(entry.id, &entry.keyexpr)
                        .is_ok()
                }
                Kind::Subscriber => self.subscribers[left].declare(actions),
                Kind::Interest => self.interests[left].send(actions),
                #[cfg(feature = "queryable")]
                Kind::Queryable => self.queryables[left].declare(actions),
                #[cfg(feature = "liveliness")]
                Kind::Token => self.tokens[left].declare(actions),
                #[cfg(feature = "liveliness")]
                Kind::LiveSub => self.live_subs[left].ask(actions),
            };
        }
        // A place past the sequence is a defect of the cursor and has nothing to send.
        true
    }

    /// The link of the face at `at` has been established: begin to tell its peer what the session
    /// holds, and send the first turn of it.
    pub(super) fn begin_replay(&mut self, at: usize, actions: &McuActions<C>, now_ms: u64) {
        let owed = self.sequence_len();
        let replay = &mut self.faces[at].replay;
        replay.cursor = ReplayCursor::begin(owed);
        replay.next_turn_ms = now_ms;
        self.replay_turn(at, actions, now_ms);
    }

    /// One turn of the replay of the face at `at`, if one is owed and due: the burst of the pace,
    /// or everything when the session is not paced, from the entry the last turn stopped at.
    pub(super) fn replay_turn(&mut self, at: usize, actions: &McuActions<C>, now_ms: u64) {
        let replay = &self.faces[at].replay;
        if replay.cursor.finished() || now_ms < replay.next_turn_ms {
            return;
        }
        let burst = replay.pacing.map_or(usize::MAX, |pace| pace.burst());
        let mut cursor = replay.cursor;
        for place in cursor.turn(burst) {
            if !self.emit(actions, place) {
                cursor.refused(place);
                break;
            }
        }
        let replay = &mut self.faces[at].replay;
        replay.cursor = cursor;
        if !cursor.finished() {
            let wait_ms = replay.pacing.map_or(RETRY_MS, |pace| pace.interval_ms());
            replay.next_turn_ms = now_ms.saturating_add(wait_ms);
        }
    }

    /// A declaration of `kind` is about to be stored at the end of its list: tell the peer of each
    /// face that is up of it with `send`, unless it is not to be told now, and say whether it was
    /// taken. It is not told to a face that is not up, which declares it when it comes up, and
    /// when that face's replay has not reached its place, which sends it in its turn; both count
    /// as taken. A refusal is answered as `on_refusal` says: [`OnRefusal::Forget`] counts what
    /// was refused as told, and [`OnRefusal::Undo`] makes the declaration over, putting every
    /// face's replay back as it was and taking back, with `undo`, what the faces that took it
    /// were told. Call it once, before the push.
    fn announce_with(
        &mut self,
        kind: Kind,
        on_refusal: OnRefusal,
        send: impl Fn(&McuActions<C>) -> bool,
        undo: impl Fn(&McuActions<C>),
    ) -> bool {
        let place = self.start_of(kind) + self.len_of(kind);
        // What each face's replay was and what its link made of the declaration, so that a refusal
        // that undoes the declaration can put every face back.
        let mut told: Vec<(usize, ReplayCursor, Told)> = Vec::new();
        for (at, face) in self.faces.iter_mut().enumerate() {
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
            let face = &mut self.faces[at];
            face.replay.cursor = before;
            if let (Told::Sent, Link::Up(wire)) = (outcome, &face.link) {
                undo(&wire.actions);
            }
        }
        false
    }

    /// [`Self::announce_with`] for a declaration that is stored whatever a link makes of it: one
    /// that a link refused is counted as told, and the peer learns it when the session declares
    /// over a new link.
    pub(super) fn announce(&mut self, kind: Kind, send: impl Fn(&McuActions<C>) -> bool) {
        self.announce_with(kind, OnRefusal::Forget, send, |_| {});
    }

    /// [`Self::announce_with`] for a declaration that is not made when a link refuses it: whether
    /// it was made.
    pub(super) fn announce_or_undo(
        &mut self,
        kind: Kind,
        send: impl Fn(&McuActions<C>) -> bool,
        undo: impl Fn(&McuActions<C>),
    ) -> bool {
        self.announce_with(kind, OnRefusal::Undo, send, undo)
    }

    /// The declaration at `index` of `kind`'s list is about to be removed: the links to retract it
    /// over, which are those of the faces that are up and whose peers were told of it. Call it
    /// once, before the removal.
    pub(super) fn retract(&mut self, kind: Kind, index: usize) -> Vec<Rc<McuActions<C>>> {
        let place = self.start_of(kind) + index;
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
