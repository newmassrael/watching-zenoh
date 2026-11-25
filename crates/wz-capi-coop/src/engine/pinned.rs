// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The delivery of a sample to the session's subscribers one at a time, in a session whose read
//! steps its one link itself (`direct`): a Push read where its frame lies, and a put of the
//! session's own.
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

use wz_session_core::driver_loop::{InPlaceRecord, OwedToProjection};
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
        let push = held.0.session.registry.lend_push(face, record, &mut room);
        #[cfg(test)]
        let lent = matches!(push, Ok(Some(_)));
        let sample = match push {
            // SAFETY: what the sample borrows outlives the walk below, which holds it no longer
            // than this call: the frame is lent by the pump the read holds through it, `room`
            // stays in this frame, and the face's peer and its buffer are neither written nor let
            // go of while it runs (see the module's docs).
            Ok(Some(sample)) => Some(unsafe { past_the_lock(sample, record) }),
            Ok(None) => None,
            Err(OwedToProjection) => {
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
        let reached = self.hand_row_by_row(held, &sample, &mut fan);
        #[cfg(test)]
        if reached > 0 {
            self.takes.pinned_samples.fetch_add(1, Ordering::Relaxed);
            if lent {
                self.takes.pinned_lent.fetch_add(1, Ordering::Relaxed);
            }
        }
        #[cfg(not(test))]
        let _ = reached;
    }

    /// Take the subscribers' side of `messages`, the records of a frame of face `face` the copying
    /// receive decoded, one record at a time in their order: each Push's sample is handed to each
    /// subscriber its key reaches, one call at a time with the session let go of, and any other
    /// record is taken under the lock as the frame's dispatch takes it. What the frame's other
    /// planes take follows (`Planes::BesideSubscribers`). A session closed meanwhile takes no
    /// record after the one whose callback closed it.
    pub(super) fn hand_copied_records(
        &self,
        face: HeldFace,
        messages: &[wz_session_core::network_message::NetworkMessage],
        reliable: bool,
    ) {
        let reliability = wz_session_core::sample::Reliability::from_reliable_bool(reliable);
        for message in messages {
            let Some(mut held) = self.live() else {
                return;
            };
            let Some(owned) =
                held.0
                    .session
                    .registry
                    .take_subscriber_record(face, message, reliability)
            else {
                continue;
            };
            let sample = SampleRef::of(&owned);
            let mut fan = PinnedFanOut::new(sample.keyexpr);
            let reached = self.hand_row_by_row(held, &sample, &mut fan);
            #[cfg(test)]
            if reached > 0 {
                self.takes.pinned_samples.fetch_add(1, Ordering::Relaxed);
            }
            #[cfg(not(test))]
            let _ = reached;
        }
    }

    /// Hand the plain `Put`s of a frame of face `face` the copying receive read where they lie,
    /// `puts` of `frame`, one record at a time in their order: each one's sample, over the frame,
    /// to each subscriber its key reaches, one call at a time with the session let go of. A
    /// session closed meanwhile hands no record after the one whose callback closed it.
    pub(super) fn hand_plain_puts(
        &self,
        face: HeldFace,
        frame: &wz_session_core::link::RxBytes,
        puts: &[wz_session_core::plain_push::PlainPut],
        reliable: bool,
    ) {
        let reliability = wz_session_core::sample::Reliability::from_reliable_bool(reliable);
        let mut keys = wz_session_core::pubsub::PlainPutKeys::new(frame);
        for put in puts {
            let Some(mut held) = self.live() else {
                return;
            };
            let Some(repeats) = held.0.session.registry.plain_put_key(face, &mut keys, put) else {
                continue;
            };
            let sample = keys.sample(put, reliability, repeats);
            let mut fan = PinnedFanOut::new(keys.key());
            let reached = self.hand_row_by_row(held, &SampleRef::of(&sample), &mut fan);
            #[cfg(test)]
            if reached > 0 {
                self.takes.pinned_samples.fetch_add(1, Ordering::Relaxed);
                self.takes.pinned_lent.fetch_add(1, Ordering::Relaxed);
            }
            #[cfg(not(test))]
            let _ = reached;
        }
    }

    /// A publish's leg to the session's own subscribers, when its destination admits them: each
    /// subscriber whose origin admits the session's own messages is handed it here, inside the put
    /// as zenoh-pico's does (`vendor/zenoh-pico/src/session/subscription.c` @
    /// `_z_trigger_subscriptions_impl`), one row at a time with the session let go of, so a put a
    /// callback makes on its own subscriber's key reaches it at once, at any depth. The number of
    /// subscribers reached.
    #[cfg(feature = "local-subscriber")]
    fn publish_to_subscribers(
        &self,
        keyexpr: &str,
        payload: &[u8],
        opts: &PublishOptions,
    ) -> Result<usize, FanoutError> {
        if !opts.allowed_destination.allows_local() {
            return Ok(0);
        }
        let Some(held) = self.live() else {
            return Ok(0);
        };
        let sample = opts.loopback_sample(keyexpr, payload);
        let mut fan = PinnedFanOut::local(keyexpr);
        Ok(self.hand_row_by_row(held, &SampleRef::of(&sample), &mut fan))
    }

    /// Hand `sample` to each subscriber `fan` reaches, the first pinned under `held`, one call at
    /// a time with the session let go of: how many were handed it. A row undeclared by an earlier
    /// call is passed, and one whose last call this was is let go of with no lock held.
    fn hand_row_by_row(
        &self,
        held: LiveCore<'_, L, C>,
        sample: &SampleRef<'_>,
        fan: &mut PinnedFanOut<'_>,
    ) -> usize {
        let mut next = tables(&held.0.session.registry).pin_next_subscriber(fan);
        drop(held);
        let mut reached: usize = 0;
        // A read a callback makes reads nothing, so no record is handed out inside another's call.
        self.deliveries.within(|_| {
            while let Some(call) = next.take() {
                let call = SubscriberCall::new(call);
                call.hand(sample);
                reached = reached.saturating_add(1);
                if call.end() {
                    self.let_go_of_drained(|tables, cursor| {
                        tables
                            .release_drained_subscriber(cursor)
                            .map(|row| row.into_callback())
                    });
                }
                next = self
                    .live()
                    .and_then(|held| tables(&held.0.session.registry).pin_next_subscriber(fan));
            }
        });
        reached
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
