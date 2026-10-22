// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! Where an application that is not the session's event leaves a query to be asked.
//!
//! [`SlotDispatch::get`](crate::app_layer::SlotDispatch::get) needs the session's own pending
//! table, which lives in the application layer the session's task owns, so only code that runs as
//! that layer's event can call it. An application that runs somewhere else (the firmware's main
//! loop, another task of the same local set) puts the query in a [`GetMailbox`] instead, a
//! `static` of the image's, and the layer takes it from there on its next event
//! ([`SlotDispatch::drain_mailbox`](crate::app_layer::SlotDispatch::drain_mailbox)).
//!
//! The mailbox is a fixed number of rows, each holding the text of one query by value: the key,
//! the selector parameters and the options, and the sink the answers are delivered to. Nothing in
//! it allocates, and a query that does not fit a row (a key longer than the table keeps, parameters
//! longer than [`GET_PARAMETERS_BYTES`]) is refused when it is posted and not cut.
//!
//! Like every table of the slot profile it is not `Sync` by itself: the image declares it in a
//! `static` and asserts the profile's rule (one cooperative thread reaches it).

use core::cell::{Cell, RefCell};

use wz_session_core::caps::MAX_KEYEXPR_BYTES;
use wz_session_core::query_mode::{ConsolidationMode, QueryTarget};
use wz_session_core::sample::QosLevel;

use crate::app_layer::GetRequest;

/// The longest selector parameters a row holds.
pub const GET_PARAMETERS_BYTES: usize = 64;

/// Why a query was not left in the mailbox. Nothing was kept.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PostError {
    /// Every row holds a query that has not been asked yet.
    Full,
    /// The key is longer than a row keeps ([`MAX_KEYEXPR_BYTES`], the image's limit).
    KeyTooLong,
    /// The key is empty: the wire has no way to say a query of nothing.
    EmptyKey,
    /// The parameters are longer than [`GET_PARAMETERS_BYTES`].
    ParametersTooLong,
}

/// What the session's layer did with a row it offered to be asked.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Disposition {
    /// It was asked: the row is free again.
    Asked,
    /// It could not be asked now (no free pending row, no transport): the row stays and is offered
    /// again on the next event.
    Retry,
    /// It never can be asked: the row is freed and counted as rejected.
    Reject,
}

/// One query by value.
struct Row<R> {
    key: [u8; MAX_KEYEXPR_BYTES],
    key_len: usize,
    parameters: [u8; GET_PARAMETERS_BYTES],
    parameters_len: usize,
    consolidation: Option<ConsolidationMode>,
    target: Option<QueryTarget>,
    timeout_ms: u32,
    qos: QosLevel,
    sink: R,
}

/// `N` queries waiting to be asked, with the sink each is answered to.
pub struct GetMailbox<R, const N: usize> {
    rows: [RefCell<Option<Row<R>>>; N],
    rejected: Cell<u32>,
}

// SAFETY: the profile's rule, which the image asserts by declaring the mailbox in a `static`: one
// cooperative thread runs the program, so no two threads reach a row at once.
unsafe impl<R, const N: usize> Sync for GetMailbox<R, N> {}

impl<R, const N: usize> GetMailbox<R, N> {
    /// An empty mailbox, for a `static`.
    #[allow(clippy::declare_interior_mutable_const)]
    pub const fn new() -> Self {
        Self {
            rows: [const { RefCell::new(None) }; N],
            rejected: Cell::new(0),
        }
    }

    /// Leave `request`, to be answered to `sink`, for the session's layer to ask. The text is
    /// copied; nothing of `request` is held after this returns.
    ///
    /// The layer asks on its next event, which an idle link may not run for as long as its idle
    /// wait: a caller that wants the session's loop to run at once also wakes it
    /// ([`SlotClientNode::wake`](crate::slot_client::SlotClientNode::wake)).
    pub fn post(&self, request: &GetRequest<'_>, sink: R) -> Result<(), PostError> {
        if request.keyexpr.is_empty() {
            return Err(PostError::EmptyKey);
        }
        if request.keyexpr.len() > MAX_KEYEXPR_BYTES {
            return Err(PostError::KeyTooLong);
        }
        if request.parameters.len() > GET_PARAMETERS_BYTES {
            return Err(PostError::ParametersTooLong);
        }
        for cell in &self.rows {
            let mut row = cell.borrow_mut();
            if row.is_some() {
                continue;
            }
            let mut key = [0u8; MAX_KEYEXPR_BYTES];
            key[..request.keyexpr.len()].copy_from_slice(request.keyexpr.as_bytes());
            let mut parameters = [0u8; GET_PARAMETERS_BYTES];
            parameters[..request.parameters.len()].copy_from_slice(request.parameters);
            *row = Some(Row {
                key,
                key_len: request.keyexpr.len(),
                parameters,
                parameters_len: request.parameters.len(),
                consolidation: request.consolidation,
                target: request.target,
                timeout_ms: request.timeout_ms,
                qos: request.qos,
                sink,
            });
            return Ok(());
        }
        Err(PostError::Full)
    }

    /// How many queries wait to be asked.
    pub fn waiting(&self) -> usize {
        self.rows
            .iter()
            .filter(|row| row.borrow().is_some())
            .count()
    }

    /// How many queries were refused for good by the layer (a key the wire cannot carry) since
    /// the mailbox was made.
    pub fn rejected(&self) -> u32 {
        self.rejected.get()
    }

    /// Offer each waiting query, oldest row first, to `ask` as a request and a copy of its sink,
    /// and keep or free the row by what `ask` answers. The sink is offered as a copy because a
    /// refused offer must leave the row whole for the next one.
    pub fn drain(&self, mut ask: impl FnMut(&GetRequest<'_>, R) -> Disposition)
    where
        R: Clone,
    {
        for cell in &self.rows {
            let mut row = cell.borrow_mut();
            let Some(held) = row.as_ref() else {
                continue;
            };
            // The key is a `&str` copied whole, so it reads back as that text; a row that does
            // not is one nobody could have posted, and is freed rather than asked.
            let Ok(keyexpr) = core::str::from_utf8(&held.key[..held.key_len]) else {
                *row = None;
                self.rejected.set(self.rejected.get() + 1);
                continue;
            };
            let request = GetRequest {
                keyexpr,
                parameters: &held.parameters[..held.parameters_len],
                consolidation: held.consolidation,
                target: held.target,
                timeout_ms: held.timeout_ms,
                qos: held.qos,
            };
            match ask(&request, held.sink.clone()) {
                Disposition::Asked => *row = None,
                Disposition::Retry => {}
                Disposition::Reject => {
                    *row = None;
                    self.rejected.set(self.rejected.get() + 1);
                }
            }
        }
    }
}

impl<R, const N: usize> Default for GetMailbox<R, N> {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(all(test, feature = "alloc"))]
mod tests {
    use super::*;
    use alloc::string::ToString;
    use alloc::vec::Vec;

    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    struct Sink(u8);

    fn request<'a>(key: &'a str, parameters: &'a [u8]) -> GetRequest<'a> {
        GetRequest {
            keyexpr: key,
            parameters,
            consolidation: None,
            target: None,
            timeout_ms: 0,
            qos: QosLevel::DEFAULT,
        }
    }

    #[test]
    fn a_posted_query_is_offered_with_its_text_and_its_sink_and_freed_when_asked() {
        let mailbox: GetMailbox<Sink, 2> = GetMailbox::new();
        mailbox.post(&request("demo/a", b"x=1"), Sink(7)).unwrap();
        mailbox.post(&request("demo/b", b""), Sink(8)).unwrap();
        assert_eq!(mailbox.waiting(), 2);

        let mut seen = Vec::new();
        mailbox.drain(|request, sink| {
            seen.push((
                request.keyexpr.to_string(),
                request.parameters.to_vec(),
                sink,
            ));
            Disposition::Asked
        });
        assert_eq!(
            seen,
            [
                ("demo/a".to_string(), b"x=1".to_vec(), Sink(7)),
                ("demo/b".to_string(), Vec::new(), Sink(8)),
            ]
        );
        assert_eq!(mailbox.waiting(), 0, "an asked query leaves its row");
    }

    #[test]
    fn a_query_that_cannot_be_asked_now_stays_whole_for_the_next_offer() {
        let mailbox: GetMailbox<Sink, 1> = GetMailbox::new();
        mailbox.post(&request("demo/a", b"p"), Sink(3)).unwrap();
        mailbox.drain(|_, _| Disposition::Retry);
        assert_eq!(mailbox.waiting(), 1);
        let mut again = None;
        mailbox.drain(|request, sink| {
            again = Some((
                request.keyexpr.to_string(),
                request.parameters.to_vec(),
                sink,
            ));
            Disposition::Asked
        });
        assert_eq!(again, Some(("demo/a".to_string(), b"p".to_vec(), Sink(3))));
    }

    #[test]
    fn a_query_the_layer_refuses_for_good_is_freed_and_counted() {
        let mailbox: GetMailbox<Sink, 1> = GetMailbox::new();
        mailbox.post(&request("demo/a", b""), Sink(1)).unwrap();
        mailbox.drain(|_, _| Disposition::Reject);
        assert_eq!((mailbox.waiting(), mailbox.rejected()), (0, 1));
    }

    #[test]
    fn what_does_not_fit_a_row_is_refused_when_posted_and_not_cut() {
        let mailbox: GetMailbox<Sink, 1> = GetMailbox::new();
        assert_eq!(
            mailbox.post(&request("", b""), Sink(0)),
            Err(PostError::EmptyKey)
        );
        let long_key = "k".repeat(MAX_KEYEXPR_BYTES + 1);
        assert_eq!(
            mailbox.post(&request(&long_key, b""), Sink(0)),
            Err(PostError::KeyTooLong)
        );
        let long_parameters = [b'p'; GET_PARAMETERS_BYTES + 1];
        assert_eq!(
            mailbox.post(&request("demo/a", &long_parameters), Sink(0)),
            Err(PostError::ParametersTooLong)
        );
        assert_eq!(mailbox.waiting(), 0, "a refused query leaves no row");
        mailbox.post(&request("demo/a", b""), Sink(1)).unwrap();
        assert_eq!(
            mailbox.post(&request("demo/b", b""), Sink(2)),
            Err(PostError::Full)
        );
    }
}
