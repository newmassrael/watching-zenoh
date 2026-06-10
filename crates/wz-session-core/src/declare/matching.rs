// SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! R311kh — matching-listener watch machinery (zenoh-pico
//! `Z_FEATURE_MATCHING` parity).
//!
//! pico's write-filter context fires registered matching-status callbacks
//! whenever its remote-target set transitions between empty and non-empty
//! (`_z_write_filter_ctx_update_state`, src/net/filtering.c:69-84 — the
//! targets are learned from interest-driven peer declarations). wz's
//! equivalent remote-target state is the `declared` membership table the
//! [`RemoteSubscriberRegistry`](crate::declare::subscriber::RemoteSubscriberRegistry)
//! / [`RemoteQueryableRegistry`](crate::declare::queryable::RemoteQueryableRegistry)
//! already maintain from inbound `Declare(Decl*/Undecl*)` records (the
//! backbone of the polling `get_matching_status`), so the listener form is
//! a [`MatchingWatchList`] layered on those registries: each watch holds a
//! keyexpr and the last verdict, and every membership mutation re-evaluates
//! the watches, firing a watch's [`MatchingSink`] only on a VERDICT FLIP —
//! pico's transition-only semantics (no fire on registration, no fire on a
//! same-verdict mutation).
//!
//! Model B sink shape, the matching sibling of [`crate::decl_sink`]: the
//! [`MatchingSink`] trait is the DIP seam, [`BoxedMatchingSink`] the AP
//! heap-closure adapter. The whole module is `alloc`-gated — a watch owns
//! its keyexpr `String`, and the membership table it re-evaluates against
//! is itself the `alloc`-gated half of the registries — and rides the
//! `session-matching` feature (the wz atom mirroring pico's
//! `Z_FEATURE_MATCHING`, default-on in pico's CMake cache).

use alloc::boxed::Box;
use alloc::string::String;
use alloc::vec::Vec;

/// Matching-status sink: the DIP seam a [`MatchingWatchList`] fires on a
/// verdict flip. The AP profile wraps closures via [`BoxedMatchingSink`];
/// a no-heap profile would supply a closed `enum` exactly as it does for
/// [`crate::decl_sink::DeclSink`].
pub trait MatchingSink {
    /// Observe one matching-status transition. `matching` is the NEW
    /// verdict (`true` = at least one remote declaration now intersects
    /// the watched keyexpr).
    fn on_matching_changed(&mut self, matching: bool);
}

/// Heap matching-closure type backing [`BoxedMatchingSink`].
type BoxedMatchingFn = Box<dyn FnMut(bool) + Send + 'static>;

/// AP / `alloc`-profile adapter wrapping a matching-status closure on the
/// heap (the dynamic-opt-in side of the Model B split).
pub struct BoxedMatchingSink {
    inner: BoxedMatchingFn,
}

impl BoxedMatchingSink {
    /// Wrap a capturing matching-status observer as a heap-stored sink.
    pub fn new(callback: impl FnMut(bool) + Send + 'static) -> Self {
        Self {
            inner: Box::new(callback),
        }
    }
}

impl MatchingSink for BoxedMatchingSink {
    fn on_matching_changed(&mut self, matching: bool) {
        (self.inner)(matching)
    }
}

/// One registered watch: the watched keyexpr, the last delivered verdict,
/// and the sink to fire on a flip.
struct MatchingWatch<C: MatchingSink> {
    id: u64,
    keyexpr: String,
    last: bool,
    sink: C,
}

/// Flip-fire watch list — the registry-side state behind
/// `declare_matching_listener`. IDs are list-local monotonic (the
/// registry's listener-handle currency, not a wire id).
pub struct MatchingWatchList<C: MatchingSink> {
    watches: Vec<MatchingWatch<C>>,
    next_id: u64,
}

impl<C: MatchingSink> Default for MatchingWatchList<C> {
    fn default() -> Self {
        Self::new()
    }
}

impl<C: MatchingSink> MatchingWatchList<C> {
    /// Empty watch list.
    pub const fn new() -> Self {
        Self {
            watches: Vec::new(),
            next_id: 0,
        }
    }

    /// Register a watch over `keyexpr`, seeded with the CURRENT verdict
    /// (`initial`) so the first fire is a real transition — pico seeds
    /// the write-filter state at context creation and its callbacks see
    /// transitions only (`get_matching_status` is the poll for the
    /// current value). Returns the watch id for
    /// [`unregister`](Self::unregister).
    pub fn register(&mut self, keyexpr: String, initial: bool, sink: C) -> u64 {
        let id = self.next_id;
        self.next_id += 1;
        self.watches.push(MatchingWatch {
            id,
            keyexpr,
            last: initial,
            sink,
        });
        id
    }

    /// Remove the watch with `id`. Returns whether one was removed.
    pub fn unregister(&mut self, id: u64) -> bool {
        let before = self.watches.len();
        self.watches.retain(|w| w.id != id);
        self.watches.len() != before
    }

    /// Number of registered watches.
    pub fn len(&self) -> usize {
        self.watches.len()
    }

    /// Whether no watches are registered.
    pub fn is_empty(&self) -> bool {
        self.watches.is_empty()
    }

    /// Re-evaluate every watch against `has_matching` (the owning
    /// registry's membership consult) and fire each sink whose verdict
    /// FLIPPED, recording the new verdict. Returns the count fired —
    /// a same-verdict sweep fires nothing (pico transition-only).
    pub fn reevaluate(&mut self, has_matching: impl Fn(&str) -> bool) -> usize {
        let mut fired = 0;
        for watch in self.watches.iter_mut() {
            let now = has_matching(&watch.keyexpr);
            if now != watch.last {
                watch.last = now;
                watch.sink.on_matching_changed(now);
                fired += 1;
            }
        }
        fired
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;
    use std::sync::{Arc, Mutex};

    fn recording_sink(log: &Arc<Mutex<Vec<bool>>>) -> BoxedMatchingSink {
        let log = Arc::clone(log);
        BoxedMatchingSink::new(move |m| log.lock().unwrap().push(m))
    }

    /// A watch fires only on a verdict FLIP: registration is silent, a
    /// same-verdict sweep is silent, and each transition fires exactly
    /// once with the new verdict.
    #[test]
    fn watch_fires_on_flip_only() {
        let log = Arc::new(Mutex::new(Vec::new()));
        let mut list = MatchingWatchList::new();
        let id = list.register("home/temp".into(), false, recording_sink(&log));
        assert_eq!(list.len(), 1);

        // Same verdict: silent.
        assert_eq!(list.reevaluate(|_| false), 0);
        assert!(log.lock().unwrap().is_empty(), "no fire without a flip");

        // false -> true: one fire carrying `true`.
        assert_eq!(list.reevaluate(|_| true), 1);
        // true again: silent.
        assert_eq!(list.reevaluate(|_| true), 0);
        // true -> false: one fire carrying `false`.
        assert_eq!(list.reevaluate(|_| false), 1);
        assert_eq!(*log.lock().unwrap(), vec![true, false]);

        assert!(list.unregister(id));
        assert_eq!(list.reevaluate(|_| true), 0, "unregistered watch is gone");
        assert!(!list.unregister(id), "double unregister reports false");
    }

    /// Watches re-evaluate per their own keyexpr — one sweep can flip
    /// one watch and leave another untouched.
    #[test]
    fn watches_evaluate_independently() {
        let log_a = Arc::new(Mutex::new(Vec::new()));
        let log_b = Arc::new(Mutex::new(Vec::new()));
        let mut list = MatchingWatchList::new();
        list.register("home/a".into(), false, recording_sink(&log_a));
        list.register("home/b".into(), false, recording_sink(&log_b));

        assert_eq!(list.reevaluate(|k| k == "home/a"), 1);
        assert_eq!(*log_a.lock().unwrap(), vec![true]);
        assert!(log_b.lock().unwrap().is_empty());
    }
}
