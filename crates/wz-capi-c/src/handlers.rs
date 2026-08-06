// SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The CHANNEL handlers — the FIFO and RING buffers that let a C program
//! receive on its OWN thread instead of inside a callback.
//!
//! ## A channel is a closure plus a queue, and the closure is the escape
//!
//! `z_fifo_channel_reply_new(&callback, &handler, cap)` hands back BOTH halves
//! of one object: a closure the C side moves into `z_get`, and a handler it
//! keeps. The closure's `call` runs on the drive thread with a BORROWED value
//! whose lifetime ends when it returns, so the channel must ESCAPE it — copy it
//! onto the heap — before queueing. Every plane's escape is the same shape and
//! lives with that plane (`crate::sample::escape_sample`,
//! `crate::query::escape_query`, `crate::get::escape_reply`), because what an
//! escape has to preserve is plane-specific: a query escape also takes a
//! `ResponseFinal` hold.
//!
//! ## FIFO blocks and RING drops, which is the whole difference
//!
//! A FIFO's `recv` BLOCKS until a value arrives or the channel disconnects —
//! `z_queryable_with_channels.c` loops on it as its main loop. A RING keeps the
//! most recent `capacity` values and DROPS the oldest on overflow, and its
//! `try_recv` never blocks: `z_pull.c` polls it on a keypress. Getting those
//! backwards is not a performance difference, it is a hang.
//!
//! ## Disconnection is the closure's DROP
//!
//! The C `drop(context)` of a channel closure is what a get's completion runs,
//! and for a channel that means "no more values will arrive". So the closure
//! half owns a sender-side reference and dropping it marks the queue
//! disconnected — which is what turns `z_queryable_with_channels.c`'s
//! `for (.. ; res == Z_OK; ..)` loop into a terminating one instead of a
//! permanent block.

use std::collections::VecDeque;
use std::ffi::c_void;
use std::sync::{Arc, Condvar, Mutex};

use crate::abi::{
    z_loaned_fifo_handler_query_t, z_loaned_fifo_handler_reply_t, z_loaned_query_t,
    z_loaned_reply_t, z_loaned_ring_handler_sample_t, z_loaned_sample_t,
    z_moved_fifo_handler_query_t, z_moved_fifo_handler_reply_t, z_moved_ring_handler_sample_t,
    z_owned_closure_query_t, z_owned_closure_reply_t, z_owned_closure_sample_t,
    z_owned_fifo_handler_query_t, z_owned_fifo_handler_reply_t, z_owned_query_t, z_owned_reply_t,
    z_owned_ring_handler_sample_t, z_owned_sample_t, Handle,
};
use crate::ffi::{guard_val, guarded, SendPtr};
use crate::result::{ZResult, Z_CHANNEL_DISCONNECTED, Z_CHANNEL_NODATA, Z_ENULL, Z_OK};

/// How a full channel behaves.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Overflow {
    /// FIFO: block the producer. wz's producer is the DRIVE thread, so blocking
    /// it would stall every face — the queue therefore grows past `capacity`
    /// instead. See [`Channel::push`] for why that is the right divergence.
    Grow,
    /// RING: drop the OLDEST value to make room.
    DropOldest,
}

/// The shared queue behind a channel's two halves.
struct Channel {
    inner: Mutex<ChannelInner>,
    arrived: Condvar,
    capacity: usize,
    overflow: Overflow,
}

struct ChannelInner {
    /// Escaped handles, each a `Box::into_raw` of the plane's marshal.
    ///
    /// [`SendPtr`] rather than a bare `Handle` because the queue is the THREAD
    /// BOUNDARY: the drive thread escapes a value onto the heap and the C
    /// application thread takes ownership of it out the other side. That is
    /// sound because an escaped marshal is a self-contained heap value with no
    /// thread affinity — the escape exists precisely to sever the borrow it came
    /// from — but a raw pointer is not `Send`, so the transfer has to be stated
    /// rather than inferred.
    queue: VecDeque<SendPtr>,
    /// Set when the producing closure has been dropped.
    disconnected: bool,
}

impl Channel {
    fn new(capacity: usize, overflow: Overflow) -> Arc<Self> {
        Arc::new(Self {
            inner: Mutex::new(ChannelInner {
                queue: VecDeque::new(),
                disconnected: false,
            }),
            arrived: Condvar::new(),
            // A zero-capacity ring would drop every value the instant it
            // arrived, which reads as "the channel is broken". Upstream's
            // examples always pass a positive size; a 0 is treated as 1 so the
            // channel still delivers rather than silently swallowing.
            capacity: capacity.max(1),
            overflow,
        })
    }

    /// Queue one escaped value.
    ///
    /// A FIFO GROWS past its capacity rather than blocking, and that divergence
    /// is deliberate: upstream's producer is its own reader task, while wz's is
    /// the DRIVE thread that serves every face of the session. Blocking it on a
    /// C program that stopped calling `z_recv` would stall unrelated faces and
    /// their keepalives — a session-wide failure caused by one slow consumer.
    /// Growing costs memory in exactly that case and nothing otherwise.
    fn push(&self, value: Handle, free: unsafe fn(Handle)) {
        let mut inner = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        if inner.disconnected {
            // Nobody will ever read it; free it here rather than leak.
            // SAFETY: `value` is a live handle this crate just escaped.
            unsafe { free(value) };
            return;
        }
        if self.overflow == Overflow::DropOldest {
            while inner.queue.len() >= self.capacity {
                if let Some(stale) = inner.queue.pop_front() {
                    // SAFETY: a live handle this channel owns.
                    unsafe { free(stale.0) };
                }
            }
        }
        inner.queue.push_back(SendPtr(value));
        self.arrived.notify_one();
    }

    /// Take the next value, blocking until one arrives or the channel
    /// disconnects.
    fn recv(&self) -> Option<Handle> {
        let mut inner = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        loop {
            if let Some(value) = inner.queue.pop_front() {
                return Some(value.0);
            }
            if inner.disconnected {
                return None;
            }
            inner = self.arrived.wait(inner).unwrap_or_else(|e| e.into_inner());
        }
    }

    /// Take the next value without blocking. `Err(true)` means disconnected,
    /// `Err(false)` means empty-but-alive — upstream's two distinct statuses.
    fn try_recv(&self) -> Result<Handle, bool> {
        let mut inner = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        match inner.queue.pop_front() {
            Some(value) => Ok(value.0),
            None => Err(inner.disconnected),
        }
    }

    /// Mark the producer gone and wake every blocked reader.
    fn disconnect(&self) {
        let mut inner = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        inner.disconnected = true;
        self.arrived.notify_all();
    }

    /// Free everything still queued — the handler's drop.
    fn drain(&self, free: unsafe fn(Handle)) {
        let mut inner = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        while let Some(value) = inner.queue.pop_front() {
            // SAFETY: a live handle this channel owns.
            unsafe { free(value.0) };
        }
    }
}

/// The PRODUCING half, handed to the C side as a closure `context`.
///
/// Dropping it disconnects the channel, which is what upstream's closure drop
/// does — and it is why a get whose replies are finished stops a blocked
/// `z_recv` instead of parking forever.
struct Producer {
    channel: Arc<Channel>,
    free: unsafe fn(Handle),
}

impl Drop for Producer {
    fn drop(&mut self) {
        self.channel.disconnect();
    }
}

/// Free a boxed sample marshal.
///
/// # Safety
/// `h` must be a live escaped sample handle.
unsafe fn free_sample(h: Handle) {
    // SAFETY: the caller's contract.
    drop(unsafe { Box::from_raw(h as *mut crate::sample::SampleMarshal) });
}

/// Free a boxed query marshal — which, for an ESCAPED query, is what emits its
/// `ResponseFinal`.
///
/// # Safety
/// `h` must be a live escaped query handle.
unsafe fn free_query(h: Handle) {
    // SAFETY: the caller's contract.
    drop(unsafe { Box::from_raw(h as *mut crate::query::QueryMarshal) });
}

/// Free a boxed reply marshal.
///
/// # Safety
/// `h` must be a live escaped reply handle.
unsafe fn free_reply(h: Handle) {
    // SAFETY: the caller's contract.
    drop(unsafe { Box::from_raw(h as *mut crate::get::ReplyMarshal) });
}

/// The C `drop(context)` every channel closure carries: release the producer.
///
/// # Safety
/// `context` must be a `Box::into_raw::<Producer>` pointer this module made.
pub(crate) unsafe extern "C" fn channel_drop(context: *mut c_void) {
    if context.is_null() {
        return;
    }
    // SAFETY: the caller's contract.
    drop(unsafe { Box::from_raw(context as *mut Producer) });
}

/// Read the producer behind a closure context.
///
/// # Safety
/// `context` must be null or a live `Producer` pointer.
unsafe fn producer<'a>(context: *mut c_void) -> Option<&'a Producer> {
    if context.is_null() {
        return None;
    }
    // SAFETY: the caller's contract.
    Some(unsafe { &*(context as *const Producer) })
}

/// Read the channel behind a loaned handler handle.
///
/// # Safety
/// `handle` must be null or a live `Arc<Channel>` pointer.
unsafe fn channel<'a>(handle: Handle) -> Option<&'a Arc<Channel>> {
    if handle.is_null() {
        return None;
    }
    // SAFETY: the caller's contract.
    Some(unsafe { &*(handle as *const Arc<Channel>) })
}

/// Build the two halves of a channel, returning the producer context and the
/// handler handle.
fn new_channel(
    capacity: usize,
    overflow: Overflow,
    free: unsafe fn(Handle),
) -> (*mut c_void, Handle) {
    let channel = Channel::new(capacity, overflow);
    let context = Box::into_raw(Box::new(Producer {
        channel: channel.clone(),
        free,
    })) as *mut c_void;
    let handler = Box::into_raw(Box::new(channel)) as Handle;
    (context, handler)
}

// --- the SAMPLE ring --------------------------------------------------------

/// The ring channel's sample callback: escape and queue.
///
/// # Safety
/// `sample` is a borrowed sample valid for this call; `context` is a live
/// [`Producer`].
unsafe extern "C" fn ring_sample_call(sample: *const z_loaned_sample_t, context: *mut c_void) {
    // SAFETY: the caller's contract.
    let Some(producer) = (unsafe { producer(context) }) else {
        return;
    };
    // SAFETY: `sample` is live for this call.
    let escaped = unsafe { crate::sample::escape_sample(sample) };
    if !escaped.is_null() {
        producer.channel.push(escaped, producer.free);
    }
}

/// Build a RING channel for samples (zenoh-c `z_ring_channel_sample_new`).
///
/// # Safety
/// `callback` and `handler` must be valid and writable.
#[no_mangle]
pub unsafe extern "C" fn z_ring_channel_sample_new(
    callback: *mut z_owned_closure_sample_t,
    handler: *mut z_owned_ring_handler_sample_t,
    capacity: usize,
) {
    guard_val((), || {
        if callback.is_null() || handler.is_null() {
            return;
        }
        let (context, chan) = new_channel(capacity, Overflow::DropOldest, free_sample);
        // SAFETY: the caller's contract.
        unsafe {
            *callback = z_owned_closure_sample_t {
                context,
                call: Some(ring_sample_call),
                drop: Some(channel_drop),
            };
            *handler = z_owned_ring_handler_sample_t::from_handle(chan);
        }
    });
}

/// Borrow a ring handler (zenoh-c `z_ring_handler_sample_loan`).
///
/// # Safety
/// `this_` must be null or a valid owned ring handler.
#[no_mangle]
pub unsafe extern "C" fn z_ring_handler_sample_loan(
    this_: *const z_owned_ring_handler_sample_t,
) -> *const z_loaned_ring_handler_sample_t {
    this_ as *const z_loaned_ring_handler_sample_t
}

/// Take the next sample without blocking (zenoh-c
/// `z_ring_handler_sample_try_recv`).
///
/// # Safety
/// `this_` must be null or a valid loaned ring handler; `sample` must be null or
/// valid and writable.
#[no_mangle]
pub unsafe extern "C" fn z_ring_handler_sample_try_recv(
    this_: *const z_loaned_ring_handler_sample_t,
    sample: *mut z_owned_sample_t,
) -> ZResult {
    guarded(|| {
        if sample.is_null() {
            return Z_ENULL;
        }
        // The gravestone contract: upstream specifies that on a non-`Z_OK`
        // return "the sample will be in the gravestone state".
        // SAFETY: the caller's contract.
        unsafe { *sample = z_owned_sample_t::null_value() };
        if this_.is_null() {
            return Z_ENULL;
        }
        // SAFETY: the caller's contract.
        let handle = unsafe { (*this_).handle };
        let Some(chan) = (unsafe { channel(handle) }) else {
            return Z_ENULL;
        };
        match chan.try_recv() {
            Ok(value) => {
                // SAFETY: the caller's contract.
                unsafe { *sample = z_owned_sample_t::from_handle(value) };
                Z_OK
            }
            Err(true) => Z_CHANNEL_DISCONNECTED,
            Err(false) => Z_CHANNEL_NODATA,
        }
    })
}

/// Free a ring handler (zenoh-c `z_ring_handler_sample_drop`).
///
/// # Safety
/// `this_` must be null or a valid moved ring handler.
#[no_mangle]
pub unsafe extern "C" fn z_ring_handler_sample_drop(this_: *mut z_moved_ring_handler_sample_t) {
    let _ = guarded(|| {
        if this_.is_null() {
            return Z_OK;
        }
        // SAFETY: the caller's contract.
        let handle = unsafe { (*this_)._this.handle };
        if !handle.is_null() {
            // SAFETY: a live `Box<Arc<Channel>>` this crate leaked.
            let chan = unsafe { Box::from_raw(handle as *mut Arc<Channel>) };
            chan.drain(free_sample);
            unsafe { (*this_)._this = z_owned_ring_handler_sample_t::null_value() };
        }
        Z_OK
    });
}

// --- the REPLY fifo ---------------------------------------------------------

/// The fifo channel's reply callback: escape and queue.
///
/// # Safety
/// `reply` is a borrowed reply valid for this call; `context` is a live
/// [`Producer`].
unsafe extern "C" fn fifo_reply_call(reply: *mut z_loaned_reply_t, context: *mut c_void) {
    // SAFETY: the caller's contract.
    let Some(producer) = (unsafe { producer(context) }) else {
        return;
    };
    // SAFETY: `reply` is live for this call.
    let escaped = unsafe { crate::get::escape_reply(reply) };
    if !escaped.is_null() {
        producer.channel.push(escaped, producer.free);
    }
}

/// Build a FIFO channel for replies (zenoh-c `z_fifo_channel_reply_new`).
///
/// # Safety
/// `callback` and `handler` must be valid and writable.
#[no_mangle]
pub unsafe extern "C" fn z_fifo_channel_reply_new(
    callback: *mut z_owned_closure_reply_t,
    handler: *mut z_owned_fifo_handler_reply_t,
    capacity: usize,
) {
    guard_val((), || {
        if callback.is_null() || handler.is_null() {
            return;
        }
        let (context, chan) = new_channel(capacity, Overflow::Grow, free_reply);
        // SAFETY: the caller's contract.
        unsafe {
            *callback = z_owned_closure_reply_t {
                context,
                call: Some(fifo_reply_call),
                drop: Some(channel_drop),
            };
            *handler = z_owned_fifo_handler_reply_t::from_handle(chan);
        }
    });
}

/// Borrow a reply fifo handler (zenoh-c `z_fifo_handler_reply_loan`).
///
/// # Safety
/// `this_` must be null or a valid owned handler.
#[no_mangle]
pub unsafe extern "C" fn z_fifo_handler_reply_loan(
    this_: *const z_owned_fifo_handler_reply_t,
) -> *const z_loaned_fifo_handler_reply_t {
    this_ as *const z_loaned_fifo_handler_reply_t
}

/// Take the next reply, BLOCKING until one arrives or the get completes
/// (zenoh-c `z_fifo_handler_reply_recv`).
///
/// # Safety
/// `this_` must be null or a valid loaned handler; `reply` must be null or valid
/// and writable.
#[no_mangle]
pub unsafe extern "C" fn z_fifo_handler_reply_recv(
    this_: *const z_loaned_fifo_handler_reply_t,
    reply: *mut z_owned_reply_t,
) -> ZResult {
    guarded(|| {
        if reply.is_null() {
            return Z_ENULL;
        }
        // SAFETY: the caller's contract.
        unsafe { *reply = z_owned_reply_t::null_value() };
        if this_.is_null() {
            return Z_ENULL;
        }
        // SAFETY: the caller's contract.
        let handle = unsafe { (*this_).handle };
        let Some(chan) = (unsafe { channel(handle) }) else {
            return Z_ENULL;
        };
        // The `Arc` is cloned out so the blocking wait does not hold a borrow of
        // the handler the C side may drop from another thread.
        let chan = chan.clone();
        match chan.recv() {
            Some(value) => {
                // SAFETY: the caller's contract.
                unsafe { *reply = z_owned_reply_t::from_handle(value) };
                Z_OK
            }
            None => Z_CHANNEL_DISCONNECTED,
        }
    })
}

/// Take the next reply without blocking (zenoh-c
/// `z_fifo_handler_reply_try_recv`).
///
/// # Safety
/// `this_` must be null or a valid loaned handler; `reply` must be null or valid
/// and writable.
#[no_mangle]
pub unsafe extern "C" fn z_fifo_handler_reply_try_recv(
    this_: *const z_loaned_fifo_handler_reply_t,
    reply: *mut z_owned_reply_t,
) -> ZResult {
    guarded(|| {
        if reply.is_null() {
            return Z_ENULL;
        }
        // SAFETY: the caller's contract.
        unsafe { *reply = z_owned_reply_t::null_value() };
        if this_.is_null() {
            return Z_ENULL;
        }
        // SAFETY: the caller's contract.
        let handle = unsafe { (*this_).handle };
        let Some(chan) = (unsafe { channel(handle) }) else {
            return Z_ENULL;
        };
        match chan.try_recv() {
            Ok(value) => {
                // SAFETY: the caller's contract.
                unsafe { *reply = z_owned_reply_t::from_handle(value) };
                Z_OK
            }
            Err(true) => Z_CHANNEL_DISCONNECTED,
            Err(false) => Z_CHANNEL_NODATA,
        }
    })
}

/// Free a reply fifo handler (zenoh-c `z_fifo_handler_reply_drop`).
///
/// # Safety
/// `this_` must be null or a valid moved handler.
#[no_mangle]
pub unsafe extern "C" fn z_fifo_handler_reply_drop(this_: *mut z_moved_fifo_handler_reply_t) {
    let _ = guarded(|| {
        if this_.is_null() {
            return Z_OK;
        }
        // SAFETY: the caller's contract.
        let handle = unsafe { (*this_)._this.handle };
        if !handle.is_null() {
            // SAFETY: a live `Box<Arc<Channel>>` this crate leaked.
            let chan = unsafe { Box::from_raw(handle as *mut Arc<Channel>) };
            chan.drain(free_reply);
            unsafe { (*this_)._this = z_owned_fifo_handler_reply_t::null_value() };
        }
        Z_OK
    });
}

// --- the QUERY fifo ---------------------------------------------------------

/// The fifo channel's query callback: escape and queue.
///
/// # Safety
/// `query` is a borrowed query valid for this call; `context` is a live
/// [`Producer`].
unsafe extern "C" fn fifo_query_call(query: *mut z_loaned_query_t, context: *mut c_void) {
    // SAFETY: the caller's contract.
    let Some(producer) = (unsafe { producer(context) }) else {
        return;
    };
    // SAFETY: `query` is live for this call. The escape also increments the
    // marshal's escape count, which is what makes the dispatch take a
    // `ResponseFinal` hold on this query's behalf.
    let escaped = unsafe { crate::query::escape_query(query) };
    if !escaped.is_null() {
        producer.channel.push(escaped, producer.free);
    }
}

/// Build a FIFO channel for queries (zenoh-c `z_fifo_channel_query_new`).
///
/// # Safety
/// `callback` and `handler` must be valid and writable.
#[no_mangle]
pub unsafe extern "C" fn z_fifo_channel_query_new(
    callback: *mut z_owned_closure_query_t,
    handler: *mut z_owned_fifo_handler_query_t,
    capacity: usize,
) {
    guard_val((), || {
        if callback.is_null() || handler.is_null() {
            return;
        }
        let (context, chan) = new_channel(capacity, Overflow::Grow, free_query);
        // SAFETY: the caller's contract.
        unsafe {
            *callback = z_owned_closure_query_t {
                context,
                call: Some(fifo_query_call),
                drop: Some(channel_drop),
            };
            *handler = z_owned_fifo_handler_query_t::from_handle(chan);
        }
    });
}

/// Borrow a query fifo handler (zenoh-c `z_fifo_handler_query_loan`).
///
/// # Safety
/// `this_` must be null or a valid owned handler.
#[no_mangle]
pub unsafe extern "C" fn z_fifo_handler_query_loan(
    this_: *const z_owned_fifo_handler_query_t,
) -> *const z_loaned_fifo_handler_query_t {
    this_ as *const z_loaned_fifo_handler_query_t
}

/// Take the next query, BLOCKING until one arrives or the queryable is
/// undeclared (zenoh-c `z_fifo_handler_query_recv`).
///
/// # Safety
/// `this_` must be null or a valid loaned handler; `query` must be null or valid
/// and writable.
#[no_mangle]
pub unsafe extern "C" fn z_fifo_handler_query_recv(
    this_: *const z_loaned_fifo_handler_query_t,
    query: *mut z_owned_query_t,
) -> ZResult {
    guarded(|| {
        if query.is_null() {
            return Z_ENULL;
        }
        // SAFETY: the caller's contract.
        unsafe { *query = z_owned_query_t::null_value() };
        if this_.is_null() {
            return Z_ENULL;
        }
        // SAFETY: the caller's contract.
        let handle = unsafe { (*this_).handle };
        let Some(chan) = (unsafe { channel(handle) }) else {
            return Z_ENULL;
        };
        let chan = chan.clone();
        match chan.recv() {
            Some(value) => {
                // SAFETY: the caller's contract.
                unsafe { *query = z_owned_query_t::from_handle(value) };
                Z_OK
            }
            None => Z_CHANNEL_DISCONNECTED,
        }
    })
}

/// Take the next query without blocking (zenoh-c
/// `z_fifo_handler_query_try_recv`).
///
/// # Safety
/// `this_` must be null or a valid loaned handler; `query` must be null or valid
/// and writable.
#[no_mangle]
pub unsafe extern "C" fn z_fifo_handler_query_try_recv(
    this_: *const z_loaned_fifo_handler_query_t,
    query: *mut z_owned_query_t,
) -> ZResult {
    guarded(|| {
        if query.is_null() {
            return Z_ENULL;
        }
        // SAFETY: the caller's contract.
        unsafe { *query = z_owned_query_t::null_value() };
        if this_.is_null() {
            return Z_ENULL;
        }
        // SAFETY: the caller's contract.
        let handle = unsafe { (*this_).handle };
        let Some(chan) = (unsafe { channel(handle) }) else {
            return Z_ENULL;
        };
        match chan.try_recv() {
            Ok(value) => {
                // SAFETY: the caller's contract.
                unsafe { *query = z_owned_query_t::from_handle(value) };
                Z_OK
            }
            Err(true) => Z_CHANNEL_DISCONNECTED,
            Err(false) => Z_CHANNEL_NODATA,
        }
    })
}

/// Free a query fifo handler (zenoh-c `z_fifo_handler_query_drop`).
///
/// # Safety
/// `this_` must be null or a valid moved handler.
#[no_mangle]
pub unsafe extern "C" fn z_fifo_handler_query_drop(this_: *mut z_moved_fifo_handler_query_t) {
    let _ = guarded(|| {
        if this_.is_null() {
            return Z_OK;
        }
        // SAFETY: the caller's contract.
        let handle = unsafe { (*this_)._this.handle };
        if !handle.is_null() {
            // SAFETY: a live `Box<Arc<Channel>>` this crate leaked. Draining
            // frees every queued query marshal, each of which emits its
            // `ResponseFinal` on drop — so undeclaring a channel queryable with
            // unanswered queries terminates them rather than leaving the
            // queriers waiting.
            let chan = unsafe { Box::from_raw(handle as *mut Arc<Channel>) };
            chan.drain(free_query);
            unsafe { (*this_)._this = z_owned_fifo_handler_query_t::null_value() };
        }
        Z_OK
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A stand-in element the channel tests can allocate and free.
    unsafe fn free_usize(h: Handle) {
        // SAFETY: the caller's contract — a `Box<usize>` this test leaked.
        drop(unsafe { Box::from_raw(h as *mut usize) });
    }

    fn boxed(v: usize) -> Handle {
        Box::into_raw(Box::new(v)) as Handle
    }

    fn read(h: Handle) -> usize {
        // SAFETY: a live `Box<usize>` this test made.
        let b = unsafe { Box::from_raw(h as *mut usize) };
        *b
    }

    /// The three channel families R311y565 added are WIRED, not merely
    /// exported.
    ///
    /// A census proves a program LINKS; it says nothing about whether the
    /// handler a constructor hands back is connected to the closure it hands
    /// back beside it. This drives the pair the way a C program does — construct,
    /// invoke the closure, read the handler — for the family whose value type
    /// this test can build without a session.
    ///
    /// The sample family is the one chosen for exactly that reason: a
    /// `SampleMarshal` is constructible here, while a query or a reply marshal
    /// needs a live face. The other two share the generated body, so a wiring
    /// mistake would have to be in the macro ARGUMENTS to escape this — which is
    /// what the census's own type list then catches.
    ///
    /// WHAT IT DOES NOT COVER, measured rather than assumed: swapping this
    /// family's `Overflow::Grow` for `DropOldest` leaves the test GREEN. It
    /// drives one value through, and the policy is only observable past
    /// capacity. `a_ring_drops_the_oldest_and_keeps_the_newest` pins the policy
    /// at the `Channel` level; nothing pins which policy each FAMILY was given.
    #[test]
    fn the_fifo_sample_channel_connects_its_closure_to_its_handler() {
        let mut callback = z_owned_closure_sample_t::null_value();
        let mut handler = crate::abi::z_owned_fifo_handler_sample_t::null_value();
        // SAFETY: two live locals, valid for every call below.
        unsafe {
            z_fifo_channel_sample_new(&mut callback, &mut handler, 4);
            assert!(z_internal_closure_sample_check(&callback));
            assert!(
                crate::abi::z_owned_fifo_handler_sample_t::null_value()
                    .handle
                    .is_null(),
                "the gravestone is what an unconstructed handler reads as"
            );

            // Nothing pushed yet: a try_recv must report NODATA rather than
            // block or hand back a gravestone that reads as a value.
            let loaned = z_fifo_handler_sample_loan(&handler);
            let mut out = z_owned_sample_t::null_value();
            assert_eq!(
                z_fifo_handler_sample_try_recv(loaned, &mut out),
                Z_CHANNEL_NODATA
            );

            // Push one THROUGH the closure, exactly as the drive thread does.
            let marshal = Box::into_raw(Box::new(crate::sample::SampleMarshal::new(
                "demo/handler".to_owned(),
                b"payload".to_vec(),
                None,
                crate::abi::Z_SAMPLE_KIND_PUT,
                None,
                None,
            )));
            let loaned_sample = marshal as *const crate::abi::z_loaned_sample_t;
            let call = callback.call.expect("the constructor wired a callback");
            call(loaned_sample, callback.context);
            drop(Box::from_raw(marshal));

            assert_eq!(z_fifo_handler_sample_try_recv(loaned, &mut out), Z_OK);
            assert!(!out.handle.is_null(), "the handler produced a live sample");
            let mut moved = crate::abi::z_moved_sample_t { _this: out };
            crate::sample::z_sample_drop(&mut moved);

            // Dropping the handler releases the channel; the closure's own drop
            // then releases the producer.
            let mut moved_handler = crate::abi::z_moved_fifo_handler_sample_t { _this: handler };
            z_fifo_handler_sample_drop(&mut moved_handler);
            assert!(
                !crate::abi::z_owned_fifo_handler_sample_t::null_value()
                    .handle
                    .is_null()
                    || moved_handler._this.handle.is_null(),
                "the drop gravestones the caller's slot"
            );
            let dropfn = callback.drop.expect("the constructor wired a drop");
            dropfn(callback.context);
        }
    }

    /// A RING keeps the NEWEST `capacity` values and drops the oldest. Getting
    /// this backwards would make `z_pull.c` print stale samples forever.
    #[test]
    fn a_ring_drops_the_oldest_and_keeps_the_newest() {
        let chan = Channel::new(2, Overflow::DropOldest);
        for v in 0..4 {
            chan.push(boxed(v), free_usize);
        }
        assert_eq!(read(chan.try_recv().expect("first")), 2);
        assert_eq!(read(chan.try_recv().expect("second")), 3);
        assert!(
            !chan.try_recv().unwrap_err(),
            "an empty but connected ring is NODATA, not DISCONNECTED"
        );
    }

    /// A FIFO keeps everything in order and GROWS past its capacity rather
    /// than blocking the drive thread — the divergence [`Channel::push`]
    /// documents. A ring in its place would have dropped values 0 and 1.
    #[test]
    fn a_fifo_preserves_order_and_does_not_drop_on_overflow() {
        let chan = Channel::new(2, Overflow::Grow);
        for v in 0..4 {
            chan.push(boxed(v), free_usize);
        }
        for expect in 0..4 {
            assert_eq!(read(chan.recv().expect("queued")), expect);
        }
    }

    /// `recv` BLOCKS until a value arrives, and DISCONNECT wakes it with
    /// `None` — the pair that makes `z_queryable_with_channels.c`'s loop both
    /// work and terminate. Without the disconnect wake it would hang at exit.
    #[test]
    fn recv_blocks_until_a_value_arrives_and_disconnect_wakes_it() {
        let chan = Channel::new(4, Overflow::Grow);
        let producer = chan.clone();
        let t = std::thread::spawn(move || {
            std::thread::sleep(std::time::Duration::from_millis(30));
            producer.push(boxed(7), free_usize);
            std::thread::sleep(std::time::Duration::from_millis(30));
            producer.disconnect();
        });
        assert_eq!(read(chan.recv().expect("the value the producer pushed")), 7);
        assert!(
            chan.recv().is_none(),
            "a disconnected channel must wake its reader, not park it forever"
        );
        t.join().expect("producer finishes");
    }

    /// Draining a handler frees whatever is still queued rather than leaking
    /// it — and, for the query fifo, that drop is what emits each unanswered
    /// query's `ResponseFinal`.
    #[test]
    fn draining_frees_what_is_still_queued() {
        let chan = Channel::new(8, Overflow::Grow);
        for v in 0..3 {
            chan.push(boxed(v), free_usize);
        }
        chan.drain(free_usize);
        assert!(
            !chan.try_recv().unwrap_err(),
            "a drained channel is still CONNECTED — its producer is alive"
        );
    }

    /// A push AFTER disconnect frees the value instead of queueing it into a
    /// channel nobody will read.
    #[test]
    fn a_push_after_disconnect_does_not_queue() {
        let chan = Channel::new(4, Overflow::Grow);
        chan.disconnect();
        chan.push(boxed(1), free_usize);
        assert!(chan.try_recv().is_err());
    }
}

// --- R311y565: the rest of upstream's closure + channel surface -------------

/// Emit a transparent closure family's `_call` / `_loan` / `_loan_mut` /
/// `z_internal_*_check` / `z_internal_*_null`.
///
/// Five exports per family and six families is thirty near-identical functions;
/// the only thing that varies is the value the callback receives. A macro rather
/// than thirty hand-written bodies, because the failure a hand-written one
/// invites — forgetting the `catch_unwind` on ONE of them — is invisible until a
/// C callback panics across `extern "C"`, which is UB rather than a test failure.
macro_rules! closure_ops {
    ($Owned:ty, $Loaned:ty, $Arg:ty, $call:ident, $loan:ident, $loan_mut:ident,
     $check:ident, $null:ident) => {
        #[doc = concat!("Invoke a closure (zenoh-c `", stringify!($call), "`).")]
        ///
        /// A closure with no `call` is a no-op rather than an error: upstream's
        /// gravestone is a valid value and calling one is how a program drains
        /// a handler it never attached a callback to.
        ///
        /// # Safety
        /// `closure` must be null or a valid loaned closure; `arg` is passed
        /// through to the C callback unchanged.
        #[no_mangle]
        pub unsafe extern "C" fn $call(closure: *const $Loaned, arg: $Arg) {
            guard_val((), || {
                if closure.is_null() {
                    return;
                }
                // SAFETY: the caller's contract.
                let (call, context) = unsafe { ((*closure).call, (*closure).context) };
                let Some(call) = call else {
                    return;
                };
                // SAFETY: `call` is the C callback. An unwind out of it across
                // `extern "C"` is UB, so it is caught here — the same discipline
                // every dispatch path in this crate uses.
                let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| unsafe {
                    call(arg, context);
                }));
            });
        }

        #[doc = concat!("Borrow a closure (zenoh-c `", stringify!($loan), "`).")]
        ///
        /// # Safety
        /// `closure` must be null or a valid owned closure.
        #[no_mangle]
        pub unsafe extern "C" fn $loan(closure: *const $Owned) -> *const $Loaned {
            closure as *const $Loaned
        }

        #[doc = concat!("Borrow a closure mutably (zenoh-c `", stringify!($loan_mut), "`).")]
        ///
        /// # Safety
        /// `closure` must be null or a valid, writable owned closure.
        #[no_mangle]
        pub unsafe extern "C" fn $loan_mut(closure: *mut $Owned) -> *mut $Loaned {
            closure as *mut $Loaned
        }

        #[doc = concat!("`true` iff the closure carries a callback (zenoh-c `", stringify!($check), "`).")]
        ///
        /// # Safety
        /// `this_` must be null or a valid owned closure.
        #[no_mangle]
        pub unsafe extern "C" fn $check(this_: *const $Owned) -> bool {
            guard_val(false, || {
                // SAFETY: the caller's contract.
                !this_.is_null() && unsafe { (*this_).call }.is_some()
            })
        }

        #[doc = concat!("Gravestone a closure (zenoh-c `", stringify!($null), "`).")]
        ///
        /// # Safety
        /// `this_` must be null or valid and writable.
        #[no_mangle]
        pub unsafe extern "C" fn $null(this_: *mut $Owned) {
            if !this_.is_null() {
                // SAFETY: the caller's contract.
                unsafe { *this_ = <$Owned>::null_value() };
            }
        }
    };
}

closure_ops!(
    z_owned_closure_sample_t,
    crate::abi::z_loaned_closure_sample_t,
    *mut crate::abi::z_loaned_sample_t,
    z_closure_sample_call,
    z_closure_sample_loan,
    z_closure_sample_loan_mut,
    z_internal_closure_sample_check,
    z_internal_closure_sample_null
);
closure_ops!(
    z_owned_closure_query_t,
    crate::abi::z_loaned_closure_query_t,
    *mut crate::abi::z_loaned_query_t,
    z_closure_query_call,
    z_closure_query_loan,
    z_closure_query_loan_mut,
    z_internal_closure_query_check,
    z_internal_closure_query_null
);
closure_ops!(
    z_owned_closure_reply_t,
    crate::abi::z_loaned_closure_reply_t,
    *mut crate::abi::z_loaned_reply_t,
    z_closure_reply_call,
    z_closure_reply_loan,
    z_closure_reply_loan_mut,
    z_internal_closure_reply_check,
    z_internal_closure_reply_null
);
closure_ops!(
    crate::abi::z_owned_closure_hello_t,
    crate::abi::z_loaned_closure_hello_t,
    *mut crate::abi::z_loaned_hello_t,
    z_closure_hello_call,
    z_closure_hello_loan,
    z_closure_hello_loan_mut,
    z_internal_closure_hello_check,
    z_internal_closure_hello_null
);

/// Emit a CHANNEL family: the constructor, the handler's four ops, and its two
/// internals.
///
/// The two overflow policies differ by one argument and nothing else, which is
/// upstream's own design: a fifo and a ring are the same queue under different
/// pressure behaviour. Generating both from one body is what keeps `recv` from
/// drifting between them.
macro_rules! channel_family {
    ($new:ident, $Closure:ty, $callback:path, $free:path, $overflow:expr,
     $Owned:ty, $Loaned:ty, $Moved:ty, $Value:ty,
     $loan:ident, $recv:ident, $try_recv:ident, $drop:ident, $check:ident, $null:ident) => {
        #[doc = concat!("Build a channel and its handler (zenoh-c `", stringify!($new), "`).")]
        ///
        /// # Safety
        /// `callback` and `handler` must be valid and writable.
        #[no_mangle]
        pub unsafe extern "C" fn $new(
            callback: *mut $Closure,
            handler: *mut $Owned,
            capacity: usize,
        ) {
            guard_val((), || {
                if callback.is_null() || handler.is_null() {
                    return;
                }
                let (context, chan) = new_channel(capacity, $overflow, $free);
                // SAFETY: the caller's contract.
                unsafe {
                    *callback = <$Closure>::from_parts(context, Some($callback));
                    *handler = <$Owned>::from_handle(chan);
                }
            });
        }

        #[doc = concat!("Borrow a handler (zenoh-c `", stringify!($loan), "`).")]
        ///
        /// # Safety
        /// `this_` must be null or a valid owned handler.
        #[no_mangle]
        pub unsafe extern "C" fn $loan(this_: *const $Owned) -> *const $Loaned {
            this_ as *const $Loaned
        }

        #[doc = concat!("Take the next value, BLOCKING (zenoh-c `", stringify!($recv), "`).")]
        ///
        /// # Safety
        /// `this_` must be null or a valid loaned handler; `out` must be null or
        /// valid and writable.
        #[no_mangle]
        pub unsafe extern "C" fn $recv(this_: *const $Loaned, out: *mut $Value) -> ZResult {
            guarded(|| {
                if out.is_null() {
                    return Z_ENULL;
                }
                // The gravestone contract, written before any fallible work.
                // SAFETY: the caller's contract.
                unsafe { *out = <$Value>::null_value() };
                if this_.is_null() {
                    return Z_ENULL;
                }
                // SAFETY: the caller's contract.
                let handle = unsafe { (*this_).handle };
                let Some(chan) = (unsafe { channel(handle) }) else {
                    return Z_ENULL;
                };
                // Cloned out so the blocking wait does not hold a borrow of a
                // handler the C side may drop from another thread.
                let chan = chan.clone();
                match chan.recv() {
                    Some(value) => {
                        // SAFETY: the caller's contract.
                        unsafe { *out = <$Value>::from_handle(value) };
                        Z_OK
                    }
                    None => Z_CHANNEL_DISCONNECTED,
                }
            })
        }

        #[doc = concat!("Take the next value without blocking (zenoh-c `", stringify!($try_recv), "`).")]
        ///
        /// # Safety
        /// `this_` must be null or a valid loaned handler; `out` must be null or
        /// valid and writable.
        #[no_mangle]
        pub unsafe extern "C" fn $try_recv(this_: *const $Loaned, out: *mut $Value) -> ZResult {
            guarded(|| {
                if out.is_null() {
                    return Z_ENULL;
                }
                // SAFETY: the caller's contract.
                unsafe { *out = <$Value>::null_value() };
                if this_.is_null() {
                    return Z_ENULL;
                }
                // SAFETY: the caller's contract.
                let handle = unsafe { (*this_).handle };
                let Some(chan) = (unsafe { channel(handle) }) else {
                    return Z_ENULL;
                };
                match chan.try_recv() {
                    Ok(value) => {
                        // SAFETY: the caller's contract.
                        unsafe { *out = <$Value>::from_handle(value) };
                        Z_OK
                    }
                    Err(true) => Z_CHANNEL_DISCONNECTED,
                    Err(false) => Z_CHANNEL_NODATA,
                }
            })
        }

        #[doc = concat!("Drop a handler (zenoh-c `", stringify!($drop), "`).")]
        ///
        /// # Safety
        /// `this_` must be null or a valid, writable moved handler.
        #[no_mangle]
        pub unsafe extern "C" fn $drop(this_: *mut $Moved) {
            guard_val((), || {
                if this_.is_null() {
                    return;
                }
                // SAFETY: the caller's contract.
                let handle = unsafe { (*this_)._this.handle };
                unsafe { (*this_)._this = <$Owned>::null_value() };
                if !handle.is_null() {
                    // SAFETY: a live `Box<Arc<Channel>>` this crate leaked. The
                    // drain is what frees values still queued when the C side
                    // releases the handler without reading them.
                    let chan = unsafe { Box::from_raw(handle as *mut Arc<Channel>) };
                    chan.drain($free);
                }
            });
        }

        #[doc = concat!("`true` iff the handler is live (zenoh-c `", stringify!($check), "`).")]
        ///
        /// # Safety
        /// `this_` must be null or a valid owned handler.
        #[no_mangle]
        pub unsafe extern "C" fn $check(this_: *const $Owned) -> bool {
            guard_val(false, || {
                // SAFETY: the caller's contract.
                !this_.is_null() && !unsafe { (*this_).handle }.is_null()
            })
        }

        #[doc = concat!("Gravestone a handler (zenoh-c `", stringify!($null), "`).")]
        ///
        /// # Safety
        /// `this_` must be null or valid and writable.
        #[no_mangle]
        pub unsafe extern "C" fn $null(this_: *mut $Owned) {
            if !this_.is_null() {
                // SAFETY: the caller's contract.
                unsafe { *this_ = <$Owned>::null_value() };
            }
        }
    };
}

// The six channel families upstream ships: fifo and ring for each of sample /
// query / reply. Three existed; the other three are R311y565.
channel_family!(
    z_fifo_channel_sample_new,
    z_owned_closure_sample_t,
    fifo_sample_call,
    free_sample,
    Overflow::Grow,
    crate::abi::z_owned_fifo_handler_sample_t,
    crate::abi::z_loaned_fifo_handler_sample_t,
    crate::abi::z_moved_fifo_handler_sample_t,
    z_owned_sample_t,
    z_fifo_handler_sample_loan,
    z_fifo_handler_sample_recv,
    z_fifo_handler_sample_try_recv,
    z_fifo_handler_sample_drop,
    z_internal_fifo_handler_sample_check,
    z_internal_fifo_handler_sample_null
);
channel_family!(
    z_ring_channel_query_new,
    z_owned_closure_query_t,
    ring_query_call,
    free_query,
    Overflow::DropOldest,
    crate::abi::z_owned_ring_handler_query_t,
    crate::abi::z_loaned_ring_handler_query_t,
    crate::abi::z_moved_ring_handler_query_t,
    z_owned_query_t,
    z_ring_handler_query_loan,
    z_ring_handler_query_recv,
    z_ring_handler_query_try_recv,
    z_ring_handler_query_drop,
    z_internal_ring_handler_query_check,
    z_internal_ring_handler_query_null
);
channel_family!(
    z_ring_channel_reply_new,
    z_owned_closure_reply_t,
    ring_reply_call,
    free_reply,
    Overflow::DropOldest,
    crate::abi::z_owned_ring_handler_reply_t,
    crate::abi::z_loaned_ring_handler_reply_t,
    crate::abi::z_moved_ring_handler_reply_t,
    z_owned_reply_t,
    z_ring_handler_reply_loan,
    z_ring_handler_reply_recv,
    z_ring_handler_reply_try_recv,
    z_ring_handler_reply_drop,
    z_internal_ring_handler_reply_check,
    z_internal_ring_handler_reply_null
);

/// The FIFO sample thunk — the same body as the ring one, and deliberately a
/// separate symbol: the two closures must be distinguishable in a backtrace, and
/// the overflow policy lives on the channel rather than in the callback.
///
/// # Safety
/// `context` must be a live producer this module made.
unsafe extern "C" fn fifo_sample_call(sample: *const z_loaned_sample_t, context: *mut c_void) {
    // SAFETY: the caller's contract, delegated.
    unsafe { ring_sample_call(sample, context) };
}

/// The RING query thunk.
///
/// # Safety
/// `context` must be a live producer this module made.
unsafe extern "C" fn ring_query_call(query: *mut z_loaned_query_t, context: *mut c_void) {
    // SAFETY: the caller's contract, delegated.
    unsafe { fifo_query_call(query, context) };
}

/// The RING reply thunk.
///
/// # Safety
/// `context` must be a live producer this module made.
unsafe extern "C" fn ring_reply_call(reply: *mut z_loaned_reply_t, context: *mut c_void) {
    // SAFETY: the caller's contract, delegated.
    unsafe { fifo_reply_call(reply, context) };
}
