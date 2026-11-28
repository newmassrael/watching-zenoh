// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The query plane's vocabulary: a queryable's callback, which its row keeps and calls with the
//! holder of the face a query came in on, a query kept past its handler, and the reply callback of
//! one leg of a get.
//!
//! A queryable's handler answers through session-core's [`ReplyOut`] while it runs. A C program
//! may also KEEP the query (zenoh-pico's `z_query_take_from_loaned`, zenoh-c's `z_query_clone`)
//! and answer it later, from any thread: zenoh's `Query` carries the route it answers on, and the
//! query's `ResponseFinal` goes out when the last copy is dropped (`zenoh/src/api/queryable.rs` @
//! `impl Drop for QueryInner {`). How an engine holds the Final open and which route a reply
//! takes is the engine's; what an ABI needs of it is [`QueryHolder`] and [`HeldQueryId`].

use alloc::sync::Arc;

use wz_session_core::query_sink::{QueryView, ReplyOut};
use wz_session_core::reply_sink::ReplyView;
use wz_session_core::wire_id::RequestId;

use crate::Refusal;

/// The entity id a queryable is declared under on the wire, of the width [`crate::SubId`] has for
/// the same reason; what an ABI's object of the queryable keeps is its row ([`crate::EntityRow`]).
pub type QblId = wz_session_core::wire_id::EntityId;

/// A query a C program keeps past its handler, as the engine that keeps it names it
/// ([`QueryHolder::keep_query`]): plain values. Each keep is one hold of the query's
/// `ResponseFinal`, given back once ([`crate::SessionEngine::release_held`]): a query kept twice
/// is held twice, under one id or under two as the engine names its keeps.
#[must_use = "a kept query holds its Final until it is released (`SessionEngine::release_held`)"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct HeldQueryId {
    /// What the engine knows the keep by beside its request id: the cooperative engine's
    /// generation of the link the query came in on, or the row and its turn in an engine's
    /// [`crate::HeldSlab`].
    pub generation: u64,
    /// The query's request id.
    pub rid: RequestId,
}

/// What a queryable's callbacks are minted with: the session a query arrives on, as far as a query
/// needs it.
pub trait QueryHolder: Send + Sync {
    /// Keep the query `view` describes past its handler, its `ResponseFinal` held until the id
    /// answered is released ([`crate::SessionEngine::release_held`]). The engine keeps of it only
    /// what a reply is built from beside its key (the replies its parameters accept and its QoS),
    /// so a keep holds none of the session's memory but its row: the caller keeps the key and the
    /// parameters itself, and hands the key to each reply ([`crate::SessionEngine::reply_held`]).
    /// Called from inside the handler, which is what makes the hold visible before the query's
    /// Final would otherwise go out. `Ok(None)` when `view` is not the query this thread's
    /// handler answers, which nothing can keep. Refused with [`Refusal::TableFull`] when the
    /// query's row holds as many holds as a count holds, and [`Refusal::Closed`] for a closed
    /// session.
    fn keep_query(&self, view: &dyn QueryView) -> Result<Option<HeldQueryId>, Refusal>;

    /// Whether the session has been closed: zenoh-pico refuses a reply on a query whose session
    /// is closed before it does anything else.
    fn session_closed(&self) -> bool;
}

/// A queryable's callback, as an ABI hands it to an engine: one for the declaration, kept in the
/// queryable's row and called through a shared borrow with the query, the responder its replies
/// are written into and what the face the query came in on holds queries through, which the call
/// borrows. Called from any thread and at any depth, as a subscriber's callback is
/// ([`crate::SubscriberSink`]), and let go of once, after its last call: its drop is the
/// program's.
pub enum QueryableSink {
    /// A C program's closure: its function, its context and its drop, held as they are, with no
    /// heap ([`Self::raw`]).
    Raw(RawQueryCallback),
    /// A Rust program's closure, shared ([`Self::shared`]).
    Shared(Arc<SharedQueryFn>),
}

/// A Rust program's queryable callback, as [`QueryableSink::Shared`] shares it.
pub type SharedQueryFn = dyn Fn(&dyn QueryView, &mut dyn ReplyOut, &dyn QueryHolder) + Send + Sync;

/// The function a C program's queryable closure is called through ([`QueryableSink::Raw`]).
pub type RawQueryFn = unsafe fn(
    context: *mut core::ffi::c_void,
    query: &dyn QueryView,
    out: &mut dyn ReplyOut,
    holder: &dyn QueryHolder,
);

/// The parts of a C program's closure an engine calls ([`QueryableSink::Raw`]): plain values; the
/// drop runs once, when the [`QueryableSink`] holding them is dropped.
#[derive(Clone, Copy)]
pub struct RawQueryCallback {
    call: RawQueryFn,
    context: *mut core::ffi::c_void,
    drop: Option<unsafe fn(context: *mut core::ffi::c_void)>,
}

// SAFETY: as `SubscriberSink`'s: a raw callback is made only by `QueryableSink::raw`, whose caller
// promises what the marker traits ask of it; the shared one is `Send + Sync` itself.
unsafe impl Send for QueryableSink {}
// SAFETY: as `Send`.
unsafe impl Sync for QueryableSink {}

impl QueryableSink {
    /// A C program's closure: `call` with `context` for each query, and `drop` with `context`
    /// once, when the engine lets it go.
    ///
    /// # Safety
    /// As [`crate::SubscriberSink::raw`]'s.
    pub unsafe fn raw(
        call: RawQueryFn,
        context: *mut core::ffi::c_void,
        drop: Option<unsafe fn(context: *mut core::ffi::c_void)>,
    ) -> Self {
        Self::Raw(RawQueryCallback {
            call,
            context,
            drop,
        })
    }

    /// A Rust program's closure, shared.
    pub fn shared(
        call: impl Fn(&dyn QueryView, &mut dyn ReplyOut, &dyn QueryHolder) + Send + Sync + 'static,
    ) -> Self {
        Self::Shared(Arc::new(call))
    }

    /// Hand `query` to the callback, its replies written into `out` and its holds taken through
    /// `holder`.
    pub fn call(&self, query: &dyn QueryView, out: &mut dyn ReplyOut, holder: &dyn QueryHolder) {
        match self {
            // SAFETY: `Self::raw`'s contract: the call may be made from here, now.
            Self::Raw(raw) => unsafe { (raw.call)(raw.context, query, out, holder) },
            Self::Shared(call) => call(query, out, holder),
        }
    }
}

impl Drop for QueryableSink {
    fn drop(&mut self) {
        if let Self::Raw(RawQueryCallback {
            context,
            drop: Some(drop),
            ..
        }) = *self
        {
            // SAFETY: `Self::raw`'s contract: this is its one drop, after its last call, since a
            // call borrows the sink and the sink is dropped only once no borrow is left.
            unsafe { drop(context) };
        }
    }
}

/// One leg of a get: it reads each reply that leg delivers, and dropping it is that leg's end
/// (its final, its timeout, the loss of its face, its cancellation), whichever comes first. Called
/// through a shared borrow, from any thread and at any depth, as a subscriber's callback is
/// ([`crate::SubscriberSink`]).
pub enum ReplyCallback {
    /// A C program's closure: its function, its context and its drop, held as they are, with no
    /// heap ([`Self::raw`]).
    Raw(RawReplyCallback),
    /// A Rust program's closure, shared ([`Self::shared`]).
    Shared(Arc<SharedReplyFn>),
}

/// A Rust program's reply callback, as [`ReplyCallback::Shared`] shares it.
pub type SharedReplyFn = dyn Fn(&dyn ReplyView) + Send + Sync;

/// The parts of a C program's closure an engine calls ([`ReplyCallback::Raw`]).
#[derive(Clone, Copy)]
pub struct RawReplyCallback {
    call: unsafe fn(context: *mut core::ffi::c_void, reply: &dyn ReplyView),
    context: *mut core::ffi::c_void,
    drop: Option<unsafe fn(context: *mut core::ffi::c_void)>,
}

// SAFETY: as `SubscriberSink`'s: a raw callback is made only by `ReplyCallback::raw`, whose
// caller promises what the marker traits ask of it.
unsafe impl Send for ReplyCallback {}
// SAFETY: as `Send`.
unsafe impl Sync for ReplyCallback {}

impl ReplyCallback {
    /// A C program's closure: `call` with `context` for each reply, and `drop` with `context`
    /// once, at the leg's end.
    ///
    /// # Safety
    /// As [`crate::SubscriberSink::raw`]'s.
    pub unsafe fn raw(
        call: unsafe fn(context: *mut core::ffi::c_void, reply: &dyn ReplyView),
        context: *mut core::ffi::c_void,
        drop: Option<unsafe fn(context: *mut core::ffi::c_void)>,
    ) -> Self {
        Self::Raw(RawReplyCallback {
            call,
            context,
            drop,
        })
    }

    /// A Rust program's closure, shared.
    pub fn shared(call: impl Fn(&dyn ReplyView) + Send + Sync + 'static) -> Self {
        Self::Shared(Arc::new(call))
    }

    /// Hand `reply` to the callback.
    pub fn call(&self, reply: &dyn ReplyView) {
        match self {
            // SAFETY: `Self::raw`'s contract: the call may be made from here, now.
            Self::Raw(raw) => unsafe { (raw.call)(raw.context, reply) },
            Self::Shared(call) => call(reply),
        }
    }
}

impl Drop for ReplyCallback {
    fn drop(&mut self) {
        if let Self::Raw(RawReplyCallback {
            context,
            drop: Some(drop),
            ..
        }) = *self
        {
            // SAFETY: `Self::raw`'s contract: this is its one drop, at the leg's end.
            unsafe { drop(context) };
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::ffi::c_void;
    use core::sync::atomic::{AtomicUsize, Ordering};
    use wz_session_core::sample::QosLevel;

    struct Query;

    impl QueryView for Query {
        fn keyexpr(&self) -> &str {
            "demo/q"
        }
        fn parameters(&self) -> Option<&[u8]> {
            None
        }
        fn attachment(&self) -> Option<&[u8]> {
            None
        }
        fn rid(&self) -> wz_session_core::wire_id::RequestId {
            7
        }
        fn qos(&self) -> QosLevel {
            QosLevel::DEFAULT
        }
    }

    struct Out;

    impl ReplyOut for Out {
        fn reply(&mut self, _payload: &[u8]) {}
        fn reply_del(&mut self) {}
        fn reply_err(
            &mut self,
            _encoding_id: Option<u32>,
            _schema: Option<&[u8]>,
            _payload: &[u8],
        ) {
        }
        fn with_responder(&mut self, _zid: &[u8], _eid: u32) {}
        fn clear_responder(&mut self) {}
        fn responder(&self) -> Option<(&[u8], u32)> {
            None
        }
    }

    /// A face's holder whose session is closed or not.
    struct Holder(bool);

    impl QueryHolder for Holder {
        fn keep_query(&self, _view: &dyn QueryView) -> Result<Option<HeldQueryId>, Refusal> {
            Ok(None)
        }

        fn session_closed(&self) -> bool {
            self.0
        }
    }

    #[derive(Default)]
    struct Counts {
        calls: AtomicUsize,
        closed_seen: AtomicUsize,
        drops: AtomicUsize,
    }

    unsafe fn count_call(
        context: *mut c_void,
        query: &dyn QueryView,
        _out: &mut dyn ReplyOut,
        holder: &dyn QueryHolder,
    ) {
        let counts = &*(context as *const Counts);
        assert_eq!(query.keyexpr(), "demo/q");
        counts.calls.fetch_add(1, Ordering::SeqCst);
        if holder.session_closed() {
            counts.closed_seen.fetch_add(1, Ordering::SeqCst);
        }
    }

    unsafe fn count_drop(context: *mut c_void) {
        (*(context as *const Counts))
            .drops
            .fetch_add(1, Ordering::SeqCst);
    }

    /// A C program's queryable closure kept as one sink is called with the holder of each face a
    /// query came in on, through a shared borrow, and its drop runs once, when the sink is let go.
    #[test]
    fn a_raw_row_sink_is_called_with_each_faces_holder_and_dropped_once() {
        let counts = Counts::default();
        let context = &counts as *const Counts as *mut c_void;
        // SAFETY: `counts` outlives the sink, and its counters may be touched from anywhere.
        let sink = unsafe { QueryableSink::raw(count_call, context, Some(count_drop)) };
        sink.call(&Query, &mut Out, &Holder(true));
        sink.call(&Query, &mut Out, &Holder(false));
        sink.call(&Query, &mut Out, &Holder(true));
        assert_eq!(counts.calls.load(Ordering::SeqCst), 3);
        assert_eq!(counts.closed_seen.load(Ordering::SeqCst), 2);
        assert_eq!(counts.drops.load(Ordering::SeqCst), 0, "held, not dropped");
        drop(sink);
        assert_eq!(counts.drops.load(Ordering::SeqCst), 1);
    }

    /// A Rust program's closure is called with the query, the responder and the holder it is
    /// handed.
    #[test]
    fn a_shared_row_sink_reads_the_holder_it_is_handed() {
        let closed_seen = Arc::new(AtomicUsize::new(0));
        let seen = Arc::clone(&closed_seen);
        let sink = QueryableSink::shared(move |query, _out, holder| {
            assert_eq!(query.rid(), 7);
            if holder.session_closed() {
                seen.fetch_add(1, Ordering::SeqCst);
            }
        });
        sink.call(&Query, &mut Out, &Holder(false));
        sink.call(&Query, &mut Out, &Holder(true));
        assert_eq!(closed_seen.load(Ordering::SeqCst), 1);
    }
}
