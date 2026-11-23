// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The query plane's vocabulary: what a C queryable's callbacks are minted with, a query kept
//! past its handler, and the reply callback of one leg of a get.
//!
//! A queryable's handler answers through session-core's [`ReplyOut`] while it runs. A C program
//! may also KEEP the query (zenoh-pico's `z_query_take_from_loaned`, zenoh-c's `z_query_clone`)
//! and answer it later, from any thread: zenoh's `Query` carries the route it answers on, and the
//! query's `ResponseFinal` goes out when the last copy is dropped (`zenoh/src/api/queryable.rs` @
//! `impl Drop for QueryInner {`). How an engine holds the Final open and which route a reply
//! takes is the engine's; what an ABI needs of it is [`QueryHolder`] and [`HeldQuery`].

use alloc::boxed::Box;
use alloc::sync::Arc;

use wz_session_core::query_sink::{QueryView, ReplyOut};
use wz_session_core::reply_sink::ReplyView;

/// A C-level queryable id, keying what an engine holds for one C declaration: the entity id the
/// queryable is declared under, of the width [`crate::SubId`] has for the same reason.
pub type QblId = wz_session_core::wire_id::EntityId;

/// A query kept past its handler. It answers on the route the query came in on, and the query's
/// `ResponseFinal` is owed until every hold of it has been dropped; dropping this releases one.
pub trait HeldQuery: Send {
    /// Answer the query now with what `answer` writes into a responder built as the handler's
    /// was (the query's key, the replies it accepts, its QoS). Answering a query whose session
    /// has been closed, or whose link has since been lost, sends nothing.
    fn reply(&self, answer: &mut dyn FnMut(&mut dyn ReplyOut));
}

/// What a queryable's callbacks are minted with: the session a query arrives on, as far as a query
/// needs it.
pub trait QueryHolder: Send + Sync {
    /// Keep the query `view` describes past its handler. Called from inside the handler, which is
    /// what makes the hold visible before the query's Final would otherwise go out.
    fn hold_query(&self, view: &dyn QueryView) -> Box<dyn HeldQuery>;

    /// Whether the session has been closed: zenoh-pico refuses a reply on a query whose session
    /// is closed before it does anything else.
    fn session_closed(&self) -> bool;
}

/// One queryable callback: it reads the query and writes its replies.
pub type QueryCallback = Box<dyn FnMut(&dyn QueryView, &mut dyn ReplyOut) + Send + 'static>;

/// Mints one queryable callback per face, given what the face's queries are held through.
pub type QueryableSink = Arc<dyn Fn(Arc<dyn QueryHolder>) -> QueryCallback + Send + Sync>;

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

/// A get refused whole ([`crate::SessionEngine::get_held`]): it issued no leg and sent nothing,
/// and a peer or queryable it had to ask found no room to hold it pending. The bound is the
/// session's `MAX_PENDING_QUERIES`, and an ABI answers it with the code it answers any full table
/// of the session with.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NoRoomToHold;
