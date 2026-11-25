// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! How this crate's engines cancel the legs of a cancellable get: one undo per leg, kept by the
//! leg's fan key ([`wz_capi_port::cancellation::FanKey`]) in one table of the process's.
//!
//! The port's fan holds no undo of its own: it names its legs by its key and cancels them through
//! the one canceller its engine attaches ([`wz_capi_port::cancellation::FanCanceller`]). The
//! registry's and the node's legs are ended through the face that issued each (a pending query's
//! request id, a liveliness interest, a node's numbered get), which these engines keep no table
//! of by fan; this one keeps that undo for them, on the heap these engines already allocate on.
//! An entry goes when its fan is cancelled (its undos run) or dropped uncancelled (they are
//! forgotten), so a key, which is a fan's address, is never found standing for a later fan.

use std::collections::BTreeMap;
use std::sync::{Mutex, PoisonError};

use wz_capi_port::cancellation::{CancellableFan, Canceller, FanCanceller, FanKey};

/// A one-shot undo of one issued leg.
pub type Undo = Box<dyn FnOnce() + Send>;

/// The undos of the legs issued so far, by fan.
struct Undos(Mutex<BTreeMap<FanKey, Vec<Undo>>>);

impl Undos {
    fn take(&self, key: FanKey) -> Option<Vec<Undo>> {
        self.0
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .remove(&key)
    }
}

impl FanCanceller for Undos {
    fn cancel_fan(&self, key: FanKey) {
        // Run after the table's lock: an undo ends a pending leg, whose callback's drop may
        // re-enter the session.
        for undo in self.take(key).into_iter().flatten() {
            undo();
        }
    }

    fn fan_over(&self, key: FanKey) {
        drop(self.take(key));
    }
}

/// The process's table, the canceller every fan of these engines is attached to.
static UNDOS: Undos = Undos(Mutex::new(BTreeMap::new()));

/// Record the undo of one leg issued under `fan`, or report that the fan was cancelled while it
/// was being issued: then every undo recorded under it, `undo` among them, runs HERE, since the
/// cancel that already ran could not have seen them, and the caller issues nothing further.
pub fn record(fan: &CancellableFan, undo: Undo) -> bool {
    let key = fan.key();
    UNDOS
        .0
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .entry(key)
        .or_default()
        .push(undo);
    if fan.attach(Canceller::Static(&UNDOS)) {
        true
    } else {
        UNDOS.cancel_fan(key);
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;

    fn counting(undone: &Arc<AtomicUsize>) -> Undo {
        let undone = Arc::clone(undone);
        Box::new(move || {
            undone.fetch_add(1, Ordering::SeqCst);
        })
    }

    fn kept(key: FanKey) -> Option<usize> {
        let kept = UNDOS.0.lock().unwrap();
        kept.get(&key).map(Vec::len)
    }

    /// A cancelled fan runs every undo its legs recorded, once; one recorded after it was
    /// cancelled runs at once and stops the issuing. Turned red by a cancel that does not reach
    /// the table, or by a late leg left running.
    #[test]
    fn a_cancelled_fan_runs_each_undo_once_and_a_late_one_at_once() {
        let undone = Arc::new(AtomicUsize::new(0));
        let fan = CancellableFan::new();
        assert!(record(&fan, counting(&undone)));
        assert!(record(&fan, counting(&undone)));
        assert_eq!(kept(fan.key()), Some(2));
        fan.cancel();
        assert_eq!(undone.load(Ordering::SeqCst), 2);
        assert_eq!(kept(fan.key()), None, "the cancel took the fan's entry");
        assert!(!record(&fan, counting(&undone)), "the fan is cancelled");
        assert_eq!(undone.load(Ordering::SeqCst), 3, "the late leg is undone");
        assert_eq!(kept(fan.key()), None);
    }

    /// A fan dropped uncancelled takes its entry with it and runs none of its undos. Turned red
    /// by an entry left behind, which a later fan at the same address would cancel.
    #[test]
    fn a_fan_over_forgets_its_undos() {
        let undone = Arc::new(AtomicUsize::new(0));
        let fan = Box::new(CancellableFan::new());
        assert!(record(&fan, counting(&undone)));
        let key = fan.key();
        drop(fan);
        assert_eq!(undone.load(Ordering::SeqCst), 0);
        assert_eq!(kept(key), None);
    }
}
