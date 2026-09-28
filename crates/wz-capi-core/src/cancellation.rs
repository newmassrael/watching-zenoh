// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! R2948 — the ONE cancellation token both C ABIs hand out.
//!
//! ## Why it lives here
//!
//! Until R2948 there were two. The pico ABI had the real plane (an on-cancel
//! handler list, and a per-face undo set its gets registered into), while the
//! zenoh-c ABI had a bare shared flag that no get, querier get or liveliness get
//! ever consulted. Neither waited for a cancelled query's callback to finish.
//! Both upstreams do, and in the same shape, which is what makes one model the
//! right answer rather than a convenience:
//!
//! * zenoh (the Rust the zenoh-c ABI wraps): `cancel` takes the handler set,
//!   runs it, then waits on a sync group every registered query holds a
//!   notifier of until that query's callback is dropped
//!   (`zenoh/src/api/cancellation.rs` @ `Ok(_) => self.sync_group.wait(),`);
//!   a query registers its handler and notifier, and the callback's drop
//!   releases both
//!   (`zenoh/src/api/session.rs` @ `ct.remove_on_cancel_handler(handler_id);`).
//! * zenoh-pico: `_z_cancellation_token_cancel` runs the handlers, then
//!   `_z_sync_group_wait`s
//!   (`vendor/zenoh-pico/src/session/cancellation.c` @ `_z_sync_group_wait(&ct->_sync_group);`).
//!
//! ## The contract
//!
//! * [`CancellationToken::register`] is refused once a cancel has STARTED, so a
//!   query issued with an already-cancelled token fails instead of running
//!   uncancellably (upstream's "Query was cancelled" / `Z_ERR_CANCELLED`).
//! * A [`Registration`] is held by the query's callbacks. Dropping it — which
//!   happens when the query completes on its own, times out, loses its face, or
//!   is cancelled — removes its handler and releases its notifier.
//! * [`CancellationToken::cancel`] runs the handlers OUTSIDE the token's lock
//!   (a handler unregisters a pending query, whose sink drop runs the C
//!   `drop(context)`, and a C callback may re-enter the session), then blocks
//!   until every live registration has been dropped. A concurrent second
//!   `cancel` waits for the first's handlers as well as the registrations.
//! * [`CancellationToken::is_cancelled`] is true once the handlers have run,
//!   which is upstream zenoh's `cancel_result.get().is_some()`.
//!
//! ## What a cancelled query's CALLER must not do
//!
//! Call `cancel` from inside the very callback it would wait for: the wait
//! cannot finish while that callback is running. Upstream has the same
//! property (its wait is on the same notifier), and it is named here rather
//! than guarded because a guard would need to know which thread is inside
//! which callback.

use std::collections::BTreeMap;
use std::sync::{Arc, Condvar, Mutex, MutexGuard};

/// A one-shot on-cancel action.
type OnCancel = Box<dyn FnOnce() + Send>;

/// The token's state, under one lock so "cancel has started", "the handlers are
/// gone" and "no registration can land" are one fact rather than three.
struct Inner {
    /// The handlers to run on cancel, keyed so a completed query can remove its
    /// own. `None` once cancel has started.
    handlers: Option<BTreeMap<u64, OnCancel>>,
    next_id: u64,
    /// Registrations still alive, plus one while a cancel is RUNNING its
    /// handlers (upstream's `execution_finished_notifier`), so a concurrent
    /// cancel cannot return before those handlers have finished.
    active: usize,
    /// The handlers have run.
    cancelled: bool,
}

/// A cancellation token shared by every handle a C program holds on it.
pub struct CancellationToken {
    inner: Mutex<Inner>,
    idle: Condvar,
}

impl Default for CancellationToken {
    fn default() -> Self {
        Self {
            inner: Mutex::new(Inner {
                handlers: Some(BTreeMap::new()),
                next_id: 0,
                active: 0,
                cancelled: false,
            }),
            idle: Condvar::new(),
        }
    }
}

impl CancellationToken {
    /// A fresh, uncancelled token.
    pub fn new() -> Arc<Self> {
        Arc::new(Self::default())
    }

    /// Lock, treating a poisoned lock as usable: every critical section here
    /// leaves `Inner` consistent before it can panic.
    fn lock(&self) -> MutexGuard<'_, Inner> {
        self.inner.lock().unwrap_or_else(|p| p.into_inner())
    }

    /// Whether the handlers have run.
    pub fn is_cancelled(&self) -> bool {
        self.lock().cancelled
    }

    /// Register a query's on-cancel action, or answer `None` because a cancel
    /// has already started.
    ///
    /// The returned [`Registration`] must be owned by the query's callbacks, so
    /// that it drops when the query is over by any route.
    pub fn register(
        self: &Arc<Self>,
        on_cancel: impl FnOnce() + Send + 'static,
    ) -> Option<Registration> {
        let mut inner = self.lock();
        let id = inner.next_id;
        inner.handlers.as_mut()?.insert(id, Box::new(on_cancel));
        inner.next_id += 1;
        inner.active += 1;
        Some(Registration {
            token: Arc::clone(self),
            id,
        })
    }

    /// Cancel: run every registered handler, then wait until every
    /// registration has been dropped.
    pub fn cancel(&self) {
        let taken = {
            let mut inner = self.lock();
            let taken = inner.handlers.take();
            if taken.is_some() {
                // This call runs the handlers; hold the group open meanwhile.
                inner.active += 1;
            }
            taken
        };
        if let Some(handlers) = taken {
            for (_, handler) in handlers {
                handler();
            }
            let mut inner = self.lock();
            inner.cancelled = true;
            inner.active -= 1;
            if inner.active == 0 {
                self.idle.notify_all();
            }
        }
        let mut inner = self.lock();
        while inner.active > 0 {
            inner = self.idle.wait(inner).unwrap_or_else(|p| p.into_inner());
        }
    }

    /// Release one registration: remove its handler if the token has not
    /// started cancelling, and leave the sync group.
    fn release(&self, id: u64) {
        let mut inner = self.lock();
        if let Some(handlers) = inner.handlers.as_mut() {
            handlers.remove(&id);
        }
        inner.active -= 1;
        if inner.active == 0 {
            self.idle.notify_all();
        }
    }

    /// Registrations still alive, plus a running cancel. For tests and
    /// diagnostics.
    pub fn active(&self) -> usize {
        self.lock().active
    }
}

/// One query's membership of a token: its on-cancel handler and its notifier.
/// Dropping it is how the query tells the token it is over.
pub struct Registration {
    token: Arc<CancellationToken>,
    id: u64,
}

impl Drop for Registration {
    fn drop(&mut self) {
        self.token.release(self.id);
    }
}

/// The pending registrations one C get made across a fan of faces, and the seam
/// a cancelled token undoes them through.
///
/// Lifted from the pico ABI (R311y575) so the zenoh-c ABI's gets use the same
/// one. A fan issues ONE query per face, each with its own id, so cancellation
/// is a set operation; and the cancellation is registered BEFORE the first face
/// is issued (upstream's ordering), so a token cancelled mid-fan must be able to
/// stop the loop — the `None` state does both.
pub struct CancellableFan {
    /// The undo for each registration issued so far, or `None` once cancelled:
    /// both "everything issued has been undone" and "issue nothing further".
    undo: Mutex<Option<Vec<OnCancel>>>,
}

impl Default for CancellableFan {
    fn default() -> Self {
        Self {
            undo: Mutex::new(Some(Vec::new())),
        }
    }
}

impl CancellableFan {
    /// An empty, uncancelled fan.
    pub fn new() -> Arc<Self> {
        Arc::new(Self::default())
    }

    /// Record one face's registration, or report that the token cancelled while
    /// the fan was running — in which case `undo` runs HERE, since the handler
    /// that already ran could not have seen it.
    pub fn record(&self, undo: impl FnOnce() + Send + 'static) -> bool {
        let mut slot = self.undo.lock().unwrap_or_else(|p| p.into_inner());
        match slot.as_mut() {
            Some(pending) => {
                pending.push(Box::new(undo));
                true
            }
            None => {
                drop(slot);
                undo();
                false
            }
        }
    }

    /// Take the set and run every undo in it.
    pub fn cancel(&self) {
        let taken = self.undo.lock().unwrap_or_else(|p| p.into_inner()).take();
        for undo in taken.into_iter().flatten() {
            undo();
        }
    }
}

/// Register a fan against a token: the token's on-cancel handler cancels the
/// fan. `None` when the token has already started cancelling — the caller then
/// fails the get without issuing it.
pub fn register_fan(token: &Arc<CancellationToken>) -> Option<(Arc<CancellableFan>, Registration)> {
    let fan = CancellableFan::new();
    let on_cancel = Arc::clone(&fan);
    let registration = token.register(move || on_cancel.cancel())?;
    Some((fan, registration))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::time::Duration;

    /// A registration made before cancel has its handler run; one attempted
    /// after is refused; `is_cancelled` flips once the handlers have run.
    #[test]
    fn cancel_runs_handlers_and_refuses_later_registrations() {
        let token = CancellationToken::new();
        let ran = Arc::new(AtomicUsize::new(0));
        let r = Arc::clone(&ran);
        let reg = token.register(move || {
            r.fetch_add(1, Ordering::SeqCst);
        });
        assert!(reg.is_some());
        drop(reg);
        assert!(!token.is_cancelled());
        token.cancel();
        assert!(token.is_cancelled());
        assert_eq!(
            ran.load(Ordering::SeqCst),
            0,
            "a query that completed on its own removed its handler"
        );

        let token = CancellationToken::new();
        let r = Arc::clone(&ran);
        let reg = token.register(move || {
            r.fetch_add(1, Ordering::SeqCst);
        });
        // Released by the handler run, as a real query's sink drop would.
        let held = Mutex::new(reg);
        let token2 = Arc::clone(&token);
        std::thread::scope(|s| {
            s.spawn(|| token2.cancel());
            std::thread::sleep(Duration::from_millis(50));
            drop(held.lock().unwrap().take());
        });
        assert_eq!(ran.load(Ordering::SeqCst), 1);
        assert!(token.register(|| {}).is_none(), "cancel has started");
    }

    /// `cancel` does not return while a registration is still alive — the
    /// in-flight callback wait both upstreams have. The control is the
    /// ordering: the registration is dropped AFTER a delay, and `cancel` must
    /// be observed returning after that drop, never before.
    #[test]
    fn cancel_waits_for_every_live_registration() {
        let token = CancellationToken::new();
        let reg = token.register(|| {}).expect("fresh token");
        let order = Arc::new(Mutex::new(Vec::new()));
        let (o1, o2) = (Arc::clone(&order), Arc::clone(&order));
        let t = Arc::clone(&token);
        std::thread::scope(|s| {
            s.spawn(move || {
                t.cancel();
                o1.lock().unwrap().push("cancel returned");
            });
            std::thread::sleep(Duration::from_millis(100));
            o2.lock().unwrap().push("registration dropped");
            drop(reg);
        });
        assert_eq!(
            *order.lock().unwrap(),
            vec!["registration dropped", "cancel returned"]
        );
        assert_eq!(token.active(), 0);
    }

    /// A fan recorded before cancel is undone by it; one recorded after the
    /// token cancelled mid-fan is undone on the spot and reports `false`.
    #[test]
    fn a_fan_undoes_what_it_recorded_and_stops_mid_fan() {
        let token = CancellationToken::new();
        let (fan, reg) = register_fan(&token).expect("fresh token");
        let undone = Arc::new(AtomicUsize::new(0));
        let u = Arc::clone(&undone);
        assert!(fan.record(move || {
            u.fetch_add(1, Ordering::SeqCst);
        }));
        drop(reg);
        let token2 = Arc::clone(&token);
        let (fan2, reg2) = register_fan(&token2).expect("still fresh");
        let u = Arc::clone(&undone);
        assert!(fan2.record(move || {
            u.fetch_add(1, Ordering::SeqCst);
        }));
        let held = Mutex::new(Some(reg2));
        std::thread::scope(|s| {
            s.spawn(|| token.cancel());
            std::thread::sleep(Duration::from_millis(50));
            drop(held.lock().unwrap().take());
        });
        assert_eq!(
            undone.load(Ordering::SeqCst),
            1,
            "only the fan still registered is undone"
        );
        let u = Arc::clone(&undone);
        assert!(!fan2.record(move || {
            u.fetch_add(1, Ordering::SeqCst);
        }));
        assert_eq!(
            undone.load(Ordering::SeqCst),
            2,
            "a late record undoes itself"
        );
        assert!(register_fan(&token).is_none());
    }
}
