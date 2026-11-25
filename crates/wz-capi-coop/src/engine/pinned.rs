// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The delivery of a Push read where its frame lies, one subscriber at a time, in a session whose
//! read steps its one link itself (`direct`).
//!
//! The record is read into its sample under the session's lock, and the first subscriber its key
//! reaches is pinned there: a call begun on its row. The lock is let go of, the sample is handed
//! to the callback, and the call is ended with no lock held; a row undeclared meanwhile whose last
//! call that was is let go of under the lock and dropped after it. The next row is pinned under
//! the lock again, from the place after the last, so a callback finds the session free and what
//! it did is seen by the rows after its own. The walk's place and the key lie in this frame; the
//! tables keep nothing of a delivery under way.
//!
//! The key is not copied: it is the frame's, the face's peer's literal, or a buffer of the face's
//! peer or of this frame. The peer and its buffer are written only by the dispatch of the face's
//! records, which the read makes one at a time and which waits for this walk; a read from a
//! callback reads nothing; and the face's tables are given back only when the face is taken out,
//! which a session of its dial face alone never does, a close from a callback included. The frame
//! is the pump's, which a close leaves to the read that steps it.

use super::*;

use wz_session_core::driver_loop::InPlaceRecord;
use wz_session_core::pubsub::LentPush;
use wz_session_core::sample::Sample;
use wz_session_core::session_tables::PinnedFanOut;

use super::registry::PeerRoom;

impl<L: SessionLinks + 'static, C: ClockSource + Clone + 'static> CoopEngine<L, C> {
    /// Hand the Push `record` of face `face`, lent where its frame lies, to each subscriber its
    /// key reaches, one call at a time with the session let go of: the sample over the frame, or,
    /// for a Push the lent form does not represent, its owned projection. A closed session hands
    /// nothing.
    pub(super) fn hand_lent_push(&self, face: HeldFace, record: &InPlaceRecord<'_, '_>) {
        let mut room = PeerRoom::default();
        let owned: Option<Sample>;
        let Some(mut held) = self.live() else {
            return;
        };
        #[cfg(all(test, feature = "std"))]
        let lookups = held.0.session.registry.lookups();
        let sample = match held.0.session.registry.lend_push(face, record, &mut room) {
            // SAFETY: what the sample borrows outlives the walk below, which holds it no longer
            // than this call: the frame is lent by the pump the read holds through it, `room`
            // stays in this frame, and the face's peer and its buffer are neither written nor let
            // go of while it runs (see the module's docs).
            LentPush::Sample(sample) => Some(unsafe { past_the_lock(sample, record) }),
            LentPush::Nothing => None,
            LentPush::Owned => {
                owned = held.0.session.registry.project_push(face, record);
                owned.as_ref().map(|projected| SampleRef::of(projected))
            }
        };
        #[cfg(all(test, feature = "std"))]
        held.0.session.registry.counted_push(lookups);
        let Some(sample) = sample else {
            return;
        };
        let mut fan = PinnedFanOut::new(sample.keyexpr);
        let mut next = tables(&held.0.session.registry).pin_next_subscriber(&mut fan);
        drop(held);
        // A callback that delivers (a put to the session's own subscribers) leaves what it would
        // hand out to the delivery after this record, so no callback runs inside another.
        self.deliveries.within(|_| {
            while let Some(call) = next.take() {
                let call = SubscriberCall::new(call);
                call.hand(&sample);
                #[cfg(test)]
                self.takes.pinned.fetch_add(1, Ordering::Relaxed);
                if call.end() {
                    self.let_go_of_drained(|tables, cursor| {
                        tables
                            .release_drained_subscriber(cursor)
                            .map(|row| row.into_callback())
                    });
                }
                next = self.live().and_then(|held| {
                    tables(&held.0.session.registry).pin_next_subscriber(&mut fan)
                });
            }
        });
        #[cfg(test)]
        self.takes.pinned_records.fetch_add(1, Ordering::Relaxed);
    }
}

/// `sample`, read under the session's lock, held past it for as long as the read lends `_frame`.
///
/// # Safety
///
/// Nothing the sample borrows is written or let go of while the result is held.
unsafe fn past_the_lock<'r>(
    sample: SampleRef<'_>,
    _frame: &'r InPlaceRecord<'_, '_>,
) -> SampleRef<'r> {
    // SAFETY: the two types differ in their lifetime alone, so they are laid out alike; what the
    // result borrows is the caller's to keep where it lies.
    unsafe { core::mem::transmute::<SampleRef<'_>, SampleRef<'r>>(sample) }
}
