//
// Copyright (c) 2023 ZettaScale Technology
//
// This program and the accompanying materials are made available under the
// terms of the Eclipse Public License 2.0 which is available at
// http://www.eclipse.org/legal/epl-2.0, or the Apache License, Version 2.0
// which is available at https://www.apache.org/licenses/LICENSE-2.0.
//
// SPDX-License-Identifier: EPL-2.0 OR Apache-2.0
//
// Contributors:
//   ZettaScale Zenoh Team, <zenoh@zettascale.tech>
//
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
// Modified by newmassrael in 2026 for watching-zenoh. Derived from zenoh 1.10.1, file
// src/api/handlers/callback.rs (https://github.com/eclipse-zenoh/zenoh, tag 1.10.1). It adds
// `Ordered`, the queue a callback is called from when the item comes from the thread of a face.

//! Callback handler trait.

use std::{fmt, sync::Arc};

use crate::api::handlers::IntoHandler;

/// A function that can transform an [`FnMut`]`(T)` into
/// an [`Fn`]`(T)` with the help of a [`Mutex`](std::sync::Mutex).
pub fn locked<T>(fnmut: impl FnMut(T)) -> impl Fn(T) {
    let lock = std::sync::Mutex::new(fnmut);
    move |x| zlock!(lock)(x)
}

pub trait CallbackParameter: 'static {
    type Message<'a>;

    fn from_message(msg: Self::Message<'_>) -> Self;
}

trait CallbackImpl<T>: Send + Sync {
    fn call(&self, t: T);

    fn call_with_message(&self, msg: T::Message<'_>)
    where
        T: CallbackParameter,
    {
        self.call(T::from_message(msg))
    }
}

impl<T, F: Fn(T) + Send + Sync> CallbackImpl<T> for F {
    fn call(&self, t: T) {
        self(t)
    }
}

struct Dropper<F>
where
    F: FnOnce() + Send + Sync,
{
    drop: Option<F>,
}
impl<F> Drop for Dropper<F>
where
    F: FnOnce() + Send + Sync,
{
    fn drop(&mut self) {
        if let Some(d) = self.drop.take() {
            (d)()
        }
    }
}
trait DropperTrait {}
impl<F> DropperTrait for Dropper<F> where F: FnOnce() + Send + Sync {}
/// Callback type used by zenoh entities.
///
/// This type stores the callback function passed to zenoh entities.
pub struct Callback<T> {
    callable: Arc<dyn CallbackImpl<T>>,
    drop: Option<Arc<dyn DropperTrait + Send + Sync>>,
}

impl<T> fmt::Debug for Callback<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Callback")
            .field("callable", &"..")
            .field("has_drop", &self.drop.is_some())
            .finish()
    }
}

impl<T> Clone for Callback<T> {
    fn clone(&self) -> Self {
        Self {
            callable: self.callable.clone(),
            drop: self.drop.clone(),
        }
    }
}

impl<T> Callback<T> {
    // upstream note: deprecate
    /// Instantiate a `Callback` from a callback function.
    pub fn new(cb: Arc<dyn Fn(T) + Send + Sync>) -> Self
    where
        T: 'static,
    {
        Self::from(move |msg| cb(msg))
    }

    /// Call the inner callback.
    #[inline]
    pub fn call(&self, arg: T) {
        self.callable.call(arg)
    }

    pub(crate) fn call_with_message(&self, msg: T::Message<'_>)
    where
        T: CallbackParameter,
    {
        self.callable.call_with_message(msg)
    }

    #[zenoh_macros::pub_visibility_if_internal]
    pub(crate) fn set_on_drop(&mut self, drop: impl FnOnce() + Send + Sync + 'static) {
        self.drop = Some(Arc::new(Dropper { drop: Some(drop) }));
    }
}

impl<T, F: Fn(T) + Send + Sync + 'static> From<F> for Callback<T> {
    fn from(value: F) -> Self {
        Self {
            callable: Arc::new(value),
            drop: None,
        }
    }
}

impl<T> IntoHandler<T> for Callback<T> {
    type Handler = ();
    fn into_handler(self) -> (Callback<T>, Self::Handler) {
        (self, ())
    }
}

impl<T, F, H> IntoHandler<T> for (F, H)
where
    F: Fn(T) + Send + Sync + 'static,
{
    type Handler = H;

    fn into_handler(self) -> (Callback<T>, Self::Handler) {
        (Callback::from(self.0), self.1)
    }
}

impl<T, H> IntoHandler<T> for (Callback<T>, H) {
    type Handler = H;

    fn into_handler(self) -> (Callback<T>, Self::Handler) {
        self
    }
}

impl<T: Send + 'static> IntoHandler<T> for (flume::Sender<T>, flume::Receiver<T>) {
    type Handler = flume::Receiver<T>;

    fn into_handler(self) -> (Callback<T>, Self::Handler) {
        let (sender, receiver) = self;
        (
            Callback::from(move |t| {
                if let Err(e) = sender.send(t) {
                    tracing::error!("{}", e)
                }
            }),
            receiver,
        )
    }
}

/// A handler containing two callback functions:
///  - `callback`: the typical callback function. `context` will be passed as its last argument.
///  - `drop`: a callback invoked when this handler is dropped.
///
/// It is guaranteed that:
///
///   - `callback` will never be called once `drop` has started.
///   - `drop` will only be called **once**, and **after** every `callback` has ended.
///   - The two previous guarantees imply that `call` and `drop` are never called concurrently.
pub struct CallbackDrop<Callback, DropFn>
where
    DropFn: FnMut() + Send + Sync + 'static,
{
    pub callback: Callback,
    pub drop: DropFn,
}

impl<Callback, DropFn> fmt::Debug for CallbackDrop<Callback, DropFn>
where
    DropFn: FnMut() + Send + Sync + 'static,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CallbackDrop")
            .field("callback", &"..")
            .field("drop", &"..")
            .finish()
    }
}

impl<Callback, DropFn> Drop for CallbackDrop<Callback, DropFn>
where
    DropFn: FnMut() + Send + Sync + 'static,
{
    fn drop(&mut self) {
        (self.drop)()
    }
}

impl<OnEvent, Event, DropFn> IntoHandler<Event> for CallbackDrop<OnEvent, DropFn>
where
    OnEvent: Fn(Event) + Send + Sync + 'static,
    DropFn: FnMut() + Send + Sync + 'static,
{
    type Handler = ();

    fn into_handler(self) -> (Callback<Event>, Self::Handler) {
        (move |evt| (self.callback)(evt), ()).into_handler()
    }
}

#[cfg(feature = "engine-tokio")]
pub(crate) use ordered::Ordered;

#[cfg(feature = "engine-tokio")]
mod ordered {
    //! Where the callback of an entity runs.
    //!
    //! Upstream runs a callback on a worker of its receive runtime, and a program writes for that:
    //! its callback may call `tokio::task::block_in_place` and wait for another thread, as
    //! upstream's own tests of the session do. The thread that reads a face here is not a worker
    //! (it drives a single-threaded runtime over state that is not `Send`), so a callback called
    //! on it would be refused `block_in_place`, and one that waits for the face would wait for the
    //! thread it is on.
    //!
    //! A callback is therefore run by a task of the receive runtime ([`ZRuntime::RX`]). What an
    //! entity is handed is queued in the order it came, and one task at a time drains the queue,
    //! so a callback is never called twice at once and sees its items in order, as it does on a
    //! thread of its own. The queue holds what keeps a wait on the entity's group open (its
    //! notifier), so a wait that returns has seen the last callback return and drop what it held.

    use std::{
        collections::VecDeque,
        sync::{
            atomic::{AtomicBool, Ordering},
            Arc, Mutex,
        },
    };

    use zenoh_runtime::ZRuntime;

    use super::Callback;
    use crate::api::cancellation::SyncGroupNotifier;

    /// Whether the calling thread is inside a single-threaded runtime: where `block_in_place` is
    /// refused, and where a call that waits for the thread it runs on never returns.
    fn on_a_single_threaded_runtime() -> bool {
        tokio::runtime::Handle::try_current().is_ok_and(|handle| {
            handle.runtime_flavor() == tokio::runtime::RuntimeFlavor::CurrentThread
        })
    }

    /// A callback and the items waiting for it, in the order they were delivered.
    pub(crate) struct Ordered<T: Send + 'static> {
        callback: Callback<T>,
        /// Held for as long as the queue is: the callback can be called while it is.
        _notifier: Option<SyncGroupNotifier>,
        queue: Mutex<VecDeque<T>>,
        /// Whether a task is draining the queue.
        running: AtomicBool,
    }

    impl<T: Send + 'static> Ordered<T> {
        pub(crate) fn new(callback: Callback<T>, notifier: Option<SyncGroupNotifier>) -> Arc<Self> {
            Arc::new(Self {
                callback,
                _notifier: notifier,
                queue: Mutex::new(VecDeque::new()),
                running: AtomicBool::new(false),
            })
        }

        /// Hand `item` to the callback. Called from a thread that may block (one of a
        /// multi-threaded runtime, or none of a runtime's: the thread of a program that publishes
        /// to its own session), it is called there, as upstream calls the callback of a delivery
        /// a session makes to itself. Called from the thread of a face, which drives a
        /// single-threaded runtime, it is queued, and a task drains the queue unless one does.
        pub(crate) fn deliver(self: &Arc<Self>, item: T) {
            if !on_a_single_threaded_runtime() {
                self.callback.call(item);
                return;
            }
            self.lock().push_back(item);
            if !self.running.swap(true, Ordering::AcqRel) {
                let drain = Arc::clone(self);
                ZRuntime::RX.spawn(async move { drain.drain() });
            }
        }

        fn lock(&self) -> std::sync::MutexGuard<'_, VecDeque<T>> {
            self.queue
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
        }

        fn drain(&self) {
            /// A callback that panics leaves the entity able to run its next item: the flag is
            /// let go.
            struct Release<'a>(&'a AtomicBool);
            impl Drop for Release<'_> {
                fn drop(&mut self) {
                    self.0.store(false, Ordering::Release);
                }
            }
            loop {
                let release = Release(&self.running);
                while let Some(item) = self.lock().pop_front() {
                    self.callback.call(item);
                }
                drop(release);
                // An item delivered after the last pop and before the flag fell found the flag set
                // and started nothing: it is taken here, unless a delivery has started a task for
                // it.
                if self.lock().is_empty() || self.running.swap(true, Ordering::AcqRel) {
                    return;
                }
            }
        }
    }

    #[cfg(test)]
    mod tests {
        use std::{sync::mpsc, time::Duration};

        use super::*;

        fn ordered(sender: mpsc::Sender<u32>) -> Arc<Ordered<u32>> {
            let sender = Mutex::new(sender);
            Ordered::new(
                Callback::from(move |item: u32| {
                    let _ = sender.lock().unwrap().send(item);
                }),
                None,
            )
        }

        /// Deliver `items` as a face does: from a thread that drives a single-threaded runtime.
        fn deliver_from_a_face(ordered: &Arc<Ordered<u32>>, items: impl IntoIterator<Item = u32>) {
            let ordered = Arc::clone(ordered);
            let items: Vec<u32> = items.into_iter().collect();
            std::thread::spawn(move || {
                tokio::runtime::Builder::new_current_thread()
                    .build()
                    .expect("runtime")
                    .block_on(async {
                        for item in items {
                            ordered.deliver(item);
                        }
                    });
            })
            .join()
            .expect("the face thread");
        }

        #[test]
        fn a_delivery_from_a_thread_that_may_block_is_called_there() {
            let (sender, received) = mpsc::channel();
            let sender = Mutex::new(sender);
            let ordered = Ordered::new(
                Callback::from(move |_: u32| {
                    let _ = sender.lock().unwrap().send(std::thread::current().id());
                }),
                None,
            );
            ordered.deliver(1);
            assert_eq!(
                received.try_recv(),
                Ok(std::thread::current().id()),
                "the callback was called before `deliver` returned, on the caller's thread"
            );
        }

        #[test]
        fn the_items_reach_the_callback_in_the_order_they_were_delivered() {
            let (sender, received) = mpsc::channel();
            let ordered = ordered(sender);
            deliver_from_a_face(&ordered, 0..200);
            let got: Vec<u32> = (0..200)
                .map(|_| {
                    received
                        .recv_timeout(Duration::from_secs(5))
                        .expect("delivered")
                })
                .collect();
            assert_eq!(got, (0..200).collect::<Vec<_>>());
        }

        #[test]
        fn a_callback_may_block_in_place() {
            let (sender, received) = mpsc::channel();
            let sender = Mutex::new(sender);
            let ordered = Ordered::new(
                Callback::from(move |item: u32| {
                    // What upstream's tests do in a callback: wait for a thread that is not this
                    // one.
                    tokio::task::block_in_place(|| {
                        std::thread::sleep(Duration::from_millis(10));
                    });
                    let _ = sender.lock().unwrap().send(item);
                }),
                None,
            );
            deliver_from_a_face(&ordered, [7]);
            assert_eq!(received.recv_timeout(Duration::from_secs(5)), Ok(7));
        }

        #[test]
        fn a_callback_that_panics_does_not_stop_the_next_item() {
            let (sender, received) = mpsc::channel();
            let sender = Mutex::new(sender);
            let ordered = Ordered::new(
                Callback::from(move |item: u32| {
                    assert!(item != 0, "the first item is refused");
                    let _ = sender.lock().unwrap().send(item);
                }),
                None,
            );
            deliver_from_a_face(&ordered, [0]);
            std::thread::sleep(Duration::from_millis(200));
            deliver_from_a_face(&ordered, [1]);
            assert_eq!(received.recv_timeout(Duration::from_secs(5)), Ok(1));
        }
    }
}
