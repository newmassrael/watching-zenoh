// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! What a session still waits for from its peer before its declarations are SYNCED
//! (`declarations_synced` and `wait_declarations_stable`, which the heap session answers).
//!
//! # What "synced" means
//!
//! A node's declarations are in step with a peer when two things hold: the node has told the peer
//! everything it holds (no replay is running: [`crate::reconnect::DeclarationCache::replaying`]),
//! and the peer has told the node what the node asked for. The second is what this type tracks.
//!
//! What a node asks a peer for is an `Interest`: the peer answers with the declarations that match
//! and ends the answer with a `Declare(DeclFinal)` carrying the interest's id. An interest that asks
//! for what exists NOW (`current`) is therefore answered, and the node knows the answer is complete
//! when the final arrives. One that asks only for what is declared LATER has no final to wait for.
//!
//! The peer's own initial final (`extbound::INITIAL_INTEREST_ID`) is not counted: a router never
//! sends one to a client, and a client of a router is the common case, so a wait that required it
//! would never end there. The interests the node itself sent are the answers it can always expect.
//!
//! # Why a deadline per interest
//!
//! A peer may never answer: it may not implement the interest, or the answer may be lost with the
//! link. A node that waits for ever is as wrong as one that does not wait. Each interest carries the
//! time it was sent, and one that has waited the timeout is given up on: the node is synced without
//! it, as the fork's sync goes on when its retry time is spent. The deadline is per interest and not
//! per sync, so an interest sent late is not cut short by an old one.
//!
//! This type reads no clock: its callers give it the time, which keeps it testable and keeps the
//! core free of a clock it would have to be generic over.

use alloc::vec::Vec;

/// One interest sent whose final has not arrived.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct PendingFinal {
    interest_id: u64,
    sent_at_ms: u64,
}

/// The interests a session has sent and has not yet had a final for.
#[derive(Debug, Default)]
pub struct DeclarationSync {
    pending: Vec<PendingFinal>,
}

impl DeclarationSync {
    /// A session that has sent no interest: it is synced.
    pub const fn new() -> Self {
        Self {
            pending: Vec::new(),
        }
    }

    /// An interest that asks for what exists now was sent at `now_ms`. Sending the same id again
    /// (a replay after a reconnect asks again) restarts its wait.
    pub fn interest_sent(&mut self, interest_id: u64, now_ms: u64) {
        match self
            .pending
            .iter_mut()
            .find(|held| held.interest_id == interest_id)
        {
            Some(held) => held.sent_at_ms = now_ms,
            None => self.pending.push(PendingFinal {
                interest_id,
                sent_at_ms: now_ms,
            }),
        }
    }

    /// The peer's `DeclFinal` for `interest_id` arrived. Returns whether the node was waiting for
    /// it: a final for an interest it never sent, or already had the final of, changes nothing.
    pub fn final_seen(&mut self, interest_id: u64) -> bool {
        match self
            .pending
            .iter()
            .position(|held| held.interest_id == interest_id)
        {
            Some(place) => {
                self.pending.remove(place);
                true
            }
            None => false,
        }
    }

    /// The node withdrew `interest_id` (it sent the interest's own final, or a one-shot get
    /// ended), so no answer is owed to it any more.
    pub fn forget(&mut self, interest_id: u64) {
        let _ = self.final_seen(interest_id);
    }

    /// The session ended: its next peer holds none of what was asked, and the interests are asked
    /// again by the replay, which notes each as it sends it.
    pub fn clear(&mut self) {
        self.pending.clear();
    }

    /// How many interests are still waited for at `now_ms`, those past `timeout_ms` not counted.
    pub fn outstanding(&self, now_ms: u64, timeout_ms: u64) -> usize {
        self.pending
            .iter()
            .filter(|held| now_ms.saturating_sub(held.sent_at_ms) < timeout_ms)
            .count()
    }

    /// How many interests were given up on at `now_ms`: waited for the whole timeout, no final.
    pub fn timed_out(&self, now_ms: u64, timeout_ms: u64) -> usize {
        self.pending.len() - self.outstanding(now_ms, timeout_ms)
    }

    /// Whether nothing is still waited for at `now_ms`.
    pub fn is_synced(&self, now_ms: u64, timeout_ms: u64) -> bool {
        self.outstanding(now_ms, timeout_ms) == 0
    }
}

/// Calls `each` with the interest id of every `Declare(DeclFinal)` that `event` delivers.
///
/// A final carries the id of the interest it ends in the envelope of the declaration: read from
/// the owned batch of a delivered frame, or from the Declare a build that lends its control records
/// (`rx-lent-control`) hands over where its frame lies.
#[cfg(feature = "codec-declare")]
pub fn finals_in_event(
    event: crate::driver_loop::IterationEvent<'_, '_>,
    mut each: impl FnMut(u64),
) {
    use crate::driver_loop::{DriverLoopOutcome, IterationEvent};
    use crate::network_message::NetworkMessage;
    use crate::transport_profile::owned::DeclareOwnedVariant;

    match event {
        IterationEvent::Poll(DriverLoopOutcome::FramePayload { messages, .. }) => {
            for message in crate::driver_loop::owned_records(messages).unwrap_or_default() {
                if let NetworkMessage::Declare(declare) = message {
                    if let (Some(interest_id), DeclareOwnedVariant::CodecZenohDeclFinal(_)) =
                        (declare.interest_id, &declare.body)
                    {
                        each(interest_id);
                    }
                }
            }
        }
        #[cfg(feature = "rx-lent-control")]
        IterationEvent::InPlace(record) => {
            if let Some(declare) = record.declare() {
                if let (
                    Some(interest_id),
                    wz_codecs::lent::DeclareVariant::CodecZenohDeclFinal(_),
                ) = (declare.interest_id, &declare.body)
                {
                    each(interest_id);
                }
            }
        }
        _ => {}
    }
}

/// What one delivered event shows of the peer's declaration sync.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct DeclarationProgress {
    /// At least one declaration from the peer arrived: progress, which the no-progress watch
    /// ([`stall_deadline`]) restarts on.
    pub declared: bool,
    /// At least one of them belongs to the peer's initial declarations (its envelope names the
    /// initial interest, [`crate::extbound::INITIAL_INTEREST_ID`]): the peer has begun its sync.
    pub initial_scope: bool,
}

/// [`DeclarationProgress`] of `event`, read from the owned batch of a delivered frame or from a
/// lent Declare, as [`finals_in_event`] reads the finals.
#[cfg(feature = "codec-declare")]
pub fn declaration_progress_in(
    event: crate::driver_loop::IterationEvent<'_, '_>,
) -> DeclarationProgress {
    use crate::driver_loop::{DriverLoopOutcome, IterationEvent};
    use crate::network_message::NetworkMessage;

    let mut progress = DeclarationProgress::default();
    let mut note = |interest_id: Option<u64>| {
        progress.declared = true;
        if interest_id == Some(crate::extbound::INITIAL_INTEREST_ID) {
            progress.initial_scope = true;
        }
    };
    match event {
        IterationEvent::Poll(DriverLoopOutcome::FramePayload { messages, .. }) => {
            for message in crate::driver_loop::owned_records(messages).unwrap_or_default() {
                if let NetworkMessage::Declare(declare) = message {
                    note(declare.interest_id);
                }
            }
        }
        #[cfg(feature = "rx-lent-control")]
        IterationEvent::InPlace(record) => {
            if let Some(declare) = record.declare() {
                note(declare.interest_id);
            }
        }
        _ => {}
    }
    progress
}

/// What the end of a no-progress window means for the sync it watched.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WatchExpiry {
    /// The sync is taken as cut short: the link ends as lost.
    LosesLink,
    /// The peer has no initial declarations to send: the sync is taken as complete, and nothing
    /// ends. Only under `until-declarations-synced-when-begun`, on a link this node accepted,
    /// while the peer has begun no initial declaration.
    EndsSync,
}

/// What a window that ran out with no declaration means under `mode`, on a link this node
/// `accepted` (or dialled), the peer having `begun` its initial declarations or not. A dialled
/// link and a peer that began its sync are held to the end of its declarations in every reacting
/// mode; an accepted link under `until-declarations-synced-when-begun` whose peer stayed quiet
/// takes the quiet as a sync with nothing in it, as a peer that answers no interest sends none.
pub const fn watch_expiry(
    mode: crate::policy::ReliableGapReconnect,
    accepted: bool,
    begun: bool,
) -> WatchExpiry {
    if matches!(
        mode,
        crate::policy::ReliableGapReconnect::UntilDeclarationsSyncedWhenBegun
    ) && accepted
        && !begun
    {
        WatchExpiry::EndsSync
    } else {
        WatchExpiry::LosesLink
    }
}

/// When the watch of a peer's initial declarations ends the link: `window_ms` after `baseline_ms`
/// (the later of the session's establishment and the peer's last declaration), while the
/// `reliable-gap-reconnect` `mode` reacts to a cut-short sync and the peer's initial declarations
/// are not settled (their end has not arrived, nor a quiet window ended a sync with nothing in
/// it, see [`watch_expiry`]). `None` keeps no watch: `mode` is `off`, the window is `0`, or the
/// peer's declarations are settled.
pub fn stall_deadline(
    mode: crate::policy::ReliableGapReconnect,
    peer_settled: bool,
    baseline_ms: u64,
    window_ms: u64,
) -> Option<u64> {
    let reacts = !matches!(mode, crate::policy::ReliableGapReconnect::Off);
    generated::declaration_stall_deadline(reacts, peer_settled, baseline_ms, window_ms)
}

// The deadline is an SCE `algorithm` document (`sources/algorithms/declaration_stall_deadline.scxml`),
// committed at `out/wz-session-core/` and `include!`-ed from there (regenerated by
// `scripts/regen-codegen.sh`). The policy is an enum of the build's configuration, which the
// document does not import, so it is handed over as whether the mode reacts at all.
mod generated {
    include!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../out/wz-session-core",
        "/declaration_stall_deadline.rs"
    ));
}

#[cfg(test)]
mod tests {
    use super::*;

    const TIMEOUT: u64 = 1_000;

    /// A build that lends its control records reads the peer's sync off the Declare lent where its
    /// frame lies as off the owned one: the final of an interest is seen with its id, a declaration
    /// of the initial interest is progress in its scope, and a record of another kind is neither.
    #[cfg(all(
        feature = "rx-lent-control",
        feature = "codec-declare",
        feature = "rx-control",
        feature = "codec-frame"
    ))]
    #[test]
    fn a_lent_declaration_is_read_as_the_owned_one_is() {
        use crate::declare_build::build_declare_final_reply;
        use crate::driver_loop::{InPlaceRecord, IterationEvent};
        use sce_forge_runtime::codec::SceCursor;

        let lent = |owned: &crate::transport_profile::owned::DeclareOwned| {
            owned
                .try_as_borrowed()
                .expect("a borrowed view")
                .encode_to_vec()
        };
        let wire = lent(&build_declare_final_reply(7));
        let view = wz_codecs::lent::Declare::decode(&mut SceCursor::new(&wire)).expect("decodes");
        let record = || {
            IterationEvent::InPlace(InPlaceRecord::declare_of_frame(
                &view,
                true,
                0,
                crate::qos::Priority::DEFAULT,
            ))
        };
        let mut finals = alloc::vec::Vec::new();
        finals_in_event(record(), |id| finals.push(id));
        assert_eq!(finals, [7], "the lent final names its interest");
        let progress = declaration_progress_in(record());
        assert!(progress.declared, "a lent declaration is progress");
        assert!(!progress.initial_scope, "interest 7 is not the initial one");

        let initial = lent(&build_declare_final_reply(
            crate::extbound::INITIAL_INTEREST_ID,
        ));
        let view =
            wz_codecs::lent::Declare::decode(&mut SceCursor::new(&initial)).expect("decodes");
        let progress = declaration_progress_in(IterationEvent::InPlace(
            InPlaceRecord::declare_of_frame(&view, true, 0, crate::qos::Priority::DEFAULT),
        ));
        assert!(progress.initial_scope, "the initial interest's scope begun");

        // CONTROL: an event that lends no Declare shows neither.
        let mut none = alloc::vec::Vec::new();
        finals_in_event(
            IterationEvent::Lease(crate::lease::LeaseCheckOutcome::WithinLease),
            |id| none.push(id),
        );
        assert!(none.is_empty());
    }

    /// A window that runs out ends the sync as empty only under the when-begun mode, on an
    /// accepted link whose peer began nothing; every other cell loses the link.
    #[test]
    fn a_quiet_window_ends_the_sync_only_for_an_accepted_link_whose_peer_began_none() {
        use crate::policy::ReliableGapReconnect as Mode;
        for mode in [
            Mode::UntilDeclarationsSynced,
            Mode::Always,
            Mode::UntilDeclarationsSyncedWhenBegun,
        ] {
            for accepted in [false, true] {
                for begun in [false, true] {
                    let expected = if matches!(mode, Mode::UntilDeclarationsSyncedWhenBegun)
                        && accepted
                        && !begun
                    {
                        WatchExpiry::EndsSync
                    } else {
                        WatchExpiry::LosesLink
                    };
                    assert_eq!(
                        watch_expiry(mode, accepted, begun),
                        expected,
                        "{mode:?} accepted={accepted} begun={begun}"
                    );
                }
            }
        }
        assert_eq!(
            stall_deadline(Mode::UntilDeclarationsSyncedWhenBegun, false, 10, 5),
            Some(15),
            "the when-begun mode watches as the others do until it is settled"
        );
    }

    /// The watch runs only while the mode reacts, the window is set and the peer's final has not
    /// arrived, and it ends a window after its baseline.
    #[test]
    fn the_declaration_watch_runs_only_in_a_reacting_mode_before_the_peers_final() {
        use crate::policy::ReliableGapReconnect as Mode;
        assert_eq!(stall_deadline(Mode::Off, false, 100, 250), None);
        assert_eq!(
            stall_deadline(Mode::UntilDeclarationsSynced, false, 100, 0),
            None
        );
        assert_eq!(
            stall_deadline(Mode::UntilDeclarationsSynced, true, 100, 250),
            None
        );
        assert_eq!(stall_deadline(Mode::Always, true, 100, 250), None);
        assert_eq!(
            stall_deadline(Mode::UntilDeclarationsSynced, false, 100, 250),
            Some(350)
        );
        assert_eq!(stall_deadline(Mode::Always, false, 100, 250), Some(350));
        assert_eq!(
            stall_deadline(Mode::Always, false, u64::MAX - 1, 250),
            Some(u64::MAX),
            "saturates rather than wrapping into the past"
        );
    }

    #[test]
    fn a_session_that_sent_no_interest_is_synced() {
        let sync = DeclarationSync::new();
        assert!(sync.is_synced(0, TIMEOUT));
        assert_eq!(sync.outstanding(0, TIMEOUT), 0);
    }

    #[test]
    fn an_interest_sent_is_waited_for_until_its_final_arrives() {
        let mut sync = DeclarationSync::new();
        sync.interest_sent(7, 100);
        assert!(!sync.is_synced(100, TIMEOUT));
        assert_eq!(sync.outstanding(500, TIMEOUT), 1);
        assert!(sync.final_seen(7), "it was waited for");
        assert!(sync.is_synced(500, TIMEOUT));
    }

    #[test]
    fn a_final_for_an_interest_never_sent_or_already_answered_changes_nothing() {
        let mut sync = DeclarationSync::new();
        assert!(!sync.final_seen(9), "never sent");
        sync.interest_sent(7, 0);
        assert!(sync.final_seen(7));
        assert!(!sync.final_seen(7), "already answered");
        assert!(sync.is_synced(0, TIMEOUT));
    }

    #[test]
    fn every_interest_is_waited_for_not_only_the_last() {
        let mut sync = DeclarationSync::new();
        sync.interest_sent(1, 0);
        sync.interest_sent(2, 0);
        sync.interest_sent(3, 0);
        assert!(sync.final_seen(2));
        assert_eq!(sync.outstanding(10, TIMEOUT), 2);
        assert!(sync.final_seen(1));
        assert!(!sync.is_synced(10, TIMEOUT), "3 is still owed");
        assert!(sync.final_seen(3));
        assert!(sync.is_synced(10, TIMEOUT));
    }

    #[test]
    fn an_interest_that_waited_the_whole_timeout_is_given_up_on() {
        let mut sync = DeclarationSync::new();
        sync.interest_sent(7, 100);
        assert!(!sync.is_synced(1_099, TIMEOUT), "one millisecond short");
        assert!(sync.is_synced(1_100, TIMEOUT), "the timeout is spent");
        assert_eq!(sync.timed_out(1_100, TIMEOUT), 1);
        assert_eq!(sync.outstanding(1_100, TIMEOUT), 0);
    }

    #[test]
    fn the_deadline_is_per_interest_so_a_late_one_is_not_cut_short_by_an_old_one() {
        let mut sync = DeclarationSync::new();
        sync.interest_sent(1, 0);
        sync.interest_sent(2, 900);
        // At 1_000 the first has waited its timeout and the second has waited 100 ms.
        assert_eq!(sync.outstanding(1_000, TIMEOUT), 1);
        assert!(!sync.is_synced(1_000, TIMEOUT));
        assert!(sync.is_synced(1_900, TIMEOUT));
    }

    #[test]
    fn sending_an_interest_again_restarts_its_wait() {
        let mut sync = DeclarationSync::new();
        sync.interest_sent(7, 0);
        sync.interest_sent(7, 900);
        assert_eq!(sync.outstanding(1_000, TIMEOUT), 1, "asked again at 900");
        assert!(sync.is_synced(1_900, TIMEOUT));
    }

    #[test]
    fn a_withdrawn_interest_is_no_longer_waited_for_and_a_new_session_waits_for_nothing() {
        let mut sync = DeclarationSync::new();
        sync.interest_sent(1, 0);
        sync.interest_sent(2, 0);
        sync.forget(1);
        assert_eq!(sync.outstanding(10, TIMEOUT), 1);
        sync.clear();
        assert!(sync.is_synced(10, TIMEOUT));
    }

    #[test]
    fn a_clock_that_went_back_does_not_wrap_into_a_timeout() {
        let mut sync = DeclarationSync::new();
        sync.interest_sent(7, 5_000);
        assert!(!sync.is_synced(1_000, TIMEOUT), "now before sent: not yet");
    }
}
