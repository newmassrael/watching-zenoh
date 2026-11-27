// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The requesting end of a query on the cooperative engine: a get is a row of the session's
//! tables (`PendingGetRow`: its request id, gate, consolidation, legs, deadline and end), and its
//! callback that row's record ([`ReplyRow`]), whose life is the row's latch (P11), as a
//! subscriber's is. A reply let through to the get, what the get held back and its timeout are
//! each handed to the callback by a call begun on the latch under the session's lock and made
//! after it ([`GetCall`]); the call that ends last of a get retired while it ran leaves the row
//! for the session's walk (`SessionTables::release_drained_get`).
//!
//! A get ends in one of two ways, and its calls tell them apart. Ended by its answer or its
//! deadline, it still hands what it held back and its timeout, by calls the deliveries begin before
//! they retire its row. Cancelled by its asker, or by the session's close, it hands nothing more:
//! a call begun before the cancellation and made after it hands nothing, and the cancellation
//! returns only once no call of it runs, as zenoh and zenoh-pico end a get's delivery when its
//! asker undeclares it.

use wz_capi_port::cancellation::FanKey;
use wz_capi_port::ReplyCallback;
use wz_session_core::reply_sink::ReplyView;
use wz_session_core::session_tables::RowCallback;
use wz_session_core::timestamp_visibility::HiddenReplyTimestamp;

use core::sync::atomic::{AtomicBool, Ordering};

use super::{LatchedRow, RowCall};
use crate::form::Latch;

/// What a get's callback is shown beside what it is handed, and the one end of the get its calls
/// read: whether a reply keeps its timestamp (`entity-timestamp-opt-in`, read once as the get is
/// asked), the fan it was asked under, which a cancellation finds it by, and whether it was
/// cancelled. The tables' row says whether the get stands or how its answer or its deadline ended
/// it (`GetEnd`); a cancellation retires the row at once, so what a call made after it reads is
/// kept here, where the call finds it.
pub(crate) struct GetShown {
    /// Whether a reply is handed with its timestamp.
    expose: bool,
    /// The fan of the token the get was asked under, when one was.
    fan: Option<FanKey>,
    /// Set, with the session held, before a cancellation retires the row; read by each call as
    /// it is made, with no lock held.
    cancelled: AtomicBool,
}

impl GetShown {
    /// A get not cancelled, its replies handed with their timestamps when `expose`, asked under
    /// `fan`.
    pub(crate) fn new(expose: bool, fan: Option<FanKey>) -> Self {
        Self {
            expose,
            fan,
            cancelled: AtomicBool::new(false),
        }
    }
}

/// A get of the session's own as its row in the tables holds it: the program's callback and what
/// it is shown. A get keeps no key of the ABI's (its gate is the tables' copy), so its row keeps
/// no anchor.
pub(crate) type ReplyRow = LatchedRow<ReplyCallback, GetShown, ()>;

impl ReplyRow {
    /// A get handing its replies to `callback`, shown `shown`.
    pub(crate) fn for_get(callback: ReplyCallback, shown: GetShown) -> Self {
        Self {
            _anchor: (),
            sink: callback,
            shown,
            latch: Latch::new(),
        }
    }

    /// Whether the get was asked under `fan`: what a cancellation of that fan retires.
    pub(crate) fn in_fan(&self, fan: FanKey) -> bool {
        self.shown.fan == Some(fan)
    }

    /// Mark the get cancelled, with the session held, before its row is retired: no call of its
    /// callback hands anything from here, whenever it was begun.
    pub(crate) fn cancel(&self) {
        self.shown.cancelled.store(true, Ordering::Release);
    }
}

/// A call of a get's callback the session began under its lock and makes after it: a reply let
/// through, a reply the get held back, or its timeout. Neither copied nor dropped unended: each is
/// ended once ([`Self::end`]), or the get's row would keep its slot for good.
#[must_use = "a call is ended, or its get's row is never let go of"]
pub(crate) struct GetCall {
    call: RowCall<ReplyCallback, GetShown, ()>,
}

impl GetCall {
    /// `call`, begun on a get's row.
    pub(crate) fn new(call: RowCall<ReplyCallback, GetShown, ()>) -> Self {
        Self { call }
    }

    /// Hand `reply` to the get's callback, its timestamp left out unless the get shows it, unless
    /// the get was cancelled since the call was begun. A call begun before an end by answer or by
    /// deadline still hands it: the deliveries begin the calls of what the get held and of its
    /// timeout before they retire its row, and the callback is dropped only once the last of them
    /// ended.
    pub(crate) fn hand(&self, reply: &dyn ReplyView) {
        // SAFETY: the row lies where the call began until its last call ended, and this one has
        // not; nothing writes a get's callback or what it is shown after it is begun but its
        // cancellation, which is atomic.
        let row = unsafe { self.call.0.as_ref() };
        if row.shown.cancelled.load(Ordering::Acquire) {
            return;
        }
        if row.shown.expose {
            row.sink.call(reply);
        } else {
            row.sink.call(&HiddenReplyTimestamp(reply));
        }
    }

    /// End the call: `true` when it was the last call of a retired get, whose row the session's
    /// walk of its tables then lets go of (`SessionTables::release_drained_get`).
    pub(crate) fn end(self) -> bool {
        // SAFETY: the row lies where the call began (the tables never move a row) and keeps its
        // slot until its last call ended, which this one is not yet; a call ends with no lock held.
        unsafe { <ReplyRow as RowCallback>::end(self.call) }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;

    use wz_capi_port::ReplyCallback;
    use wz_session_core::reply_sink::timeout_reply;
    use wz_session_core::session_tables::RowCallback;

    use super::{GetCall, GetShown, ReplyRow};

    /// A get's row whose callback counts what it is handed in `handed`.
    fn counting(handed: &Arc<AtomicUsize>) -> ReplyRow {
        let seen = handed.clone();
        let callback =
            ReplyCallback::shared(move |_reply: &dyn wz_session_core::reply_sink::ReplyView| {
                seen.fetch_add(1, Ordering::Relaxed);
            });
        ReplyRow::for_get(callback, GetShown::new(true, None))
    }

    /// A get ended by its answer still hands the calls the deliveries began before they retired
    /// its row, and the last of them lets the row go. Turned red by a call that reads the latch's
    /// retirement as the end of the get's delivery.
    #[test]
    fn a_get_ended_by_its_answer_hands_the_calls_begun_before_its_row_was_retired() {
        let handed = Arc::new(AtomicUsize::new(0));
        let row = counting(&handed);
        let call = GetCall::new(row.begin().expect("a standing get begins a call"));
        assert!(
            !row.retire(),
            "a call runs, so the row is not let go of yet"
        );
        call.hand(&timeout_reply(7));
        assert_eq!(handed.load(Ordering::Relaxed), 1);
        assert!(call.end(), "the last call of a retired get lets its row go");
        assert!(row.begin().is_none(), "a retired get begins no call");
    }

    /// A reply racing a cancellation: one call was made before the cancellation and hands its
    /// reply, one begun before it and made after it hands nothing, and no call begins after it.
    /// The callback is reached once, and never after the cancellation, while each call still ends
    /// and the last lets the row go. Turned red by `GetCall::hand` handing a reply without reading
    /// the cancellation, or by `ReplyRow::cancel` not marking it.
    #[test]
    fn a_reply_racing_a_cancellation_never_reaches_the_callback_after_it() {
        let handed = Arc::new(AtomicUsize::new(0));
        let row = counting(&handed);
        let before = GetCall::new(row.begin().expect("a standing get begins a call"));
        let racing = GetCall::new(row.begin().expect("a standing get begins a call"));
        before.hand(&timeout_reply(7));
        assert_eq!(handed.load(Ordering::Relaxed), 1);
        row.cancel();
        assert!(
            !row.retire(),
            "two calls run, so the row is not let go of yet"
        );
        racing.hand(&timeout_reply(7));
        assert_eq!(
            handed.load(Ordering::Relaxed),
            1,
            "a call made after the cancellation hands nothing"
        );
        assert!(row.begin().is_none(), "a cancelled get begins no call");
        assert!(!before.end());
        assert!(
            racing.end(),
            "the last call of a cancelled get lets its row go"
        );
        assert_eq!(handed.load(Ordering::Relaxed), 1);
    }
}
