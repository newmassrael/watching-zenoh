// SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! Declare-event delivery seam (`DeclView` accessor contract + `DeclSink`
//! / `UndeclSink` traits + the `alloc`-only `BoxedDeclSink` /
//! `BoxedUndeclSink` closure adapters) for the application-layer
//! peer-declaration observer registries.
//!
//! Model B (statechart-event) callback architecture, the control-plane
//! sibling of the data-plane [`crate::sink`] seam: a remote-declaration
//! registry (`RemoteSubscriberRegistry` / `RemoteQueryableRegistry` /
//! the liveliness-token `LivelinessRegistry`) fans each inbound
//! `Declare(DeclX)` / `Declare(UndeclX)` to its installed observers
//! through a Dependency-Inversion seam rather than a hard-coded
//! `Vec<Box<dyn FnMut(&DeclXOwned, &str)>>` + `Vec<Box<dyn FnMut(&UndeclX)>>`
//! pair, so one registry implementation backs both profiles
//! (ARCHITECTURE.md §2.4 static-first, dynamic-opt-in):
//!
//! - **AP / `alloc` on** — [`BoxedDeclSink`] / [`BoxedUndeclSink`] wrap
//!   heap closures; the registry stores homogeneous observer lists,
//!   type-erasing arbitrary capturing closures via the heap (the
//!   dynamic-opt-in side).
//! - **MCU / `alloc` off** — the consumer (a hand-written app, or the
//!   SCE-Mesh / wz-standalone switchboard generator) supplies closed
//!   `enum`s whose variants route to codegen'd statechart ingress; each
//!   impls [`DeclSink`] / [`UndeclSink`] with no heap. wz ships only the
//!   traits + the AP adapters; the no-heap sinks are the consumer's
//!   (generated or hand-written) types.
//!
//! **One shared seam across subscriber / queryable / liveliness-token.**
//! The three peer-declaration wire records (`DeclSubscriberOwned`,
//! `DeclQueryableOwned`, `DeclTokenOwned`) are field-identical
//! (`{ header, id, keyexpr }`), and the only application-facing data a
//! declaration carries is `(id, resolved-keyexpr)` — so a single
//! [`DeclView`] models "a peer declared an entity"; the entity *kind* is
//! carried by which registry the sink is installed on, exactly as
//! [`crate::sink::SampleView`] is topic-agnostic. The matching
//! undeclaration carries only `id`, so [`UndeclSink`] takes a bare `u64`
//! scalar (the control-plane analogue of the reply seam's
//! `on_final(rid)`), no view needed.
//!
//! The resolved keyexpr is computed by the registry dispatch (the wire
//! record's `keyexpr` is the un-resolved mapping form), so the dispatch
//! builds a [`BorrowedDecl`] from `(decl.id, resolved)` and hands it as
//! `&dyn DeclView`; there is no separate owned projection type. The
//! liveliness *subscriber* registry is NOT covered here — it delivers a
//! `LivelinessSample` (Put/Delete state), a different shape.

#[cfg(feature = "alloc")]
use alloc::boxed::Box;

use crate::bounded::BoundedVec;
use crate::caps;
use crate::registry_error::RegisterError;

/// Read-only accessor contract for an inbound peer declaration handed to
/// a [`DeclSink`]. The delivery currency (passed as `&dyn DeclView`); a
/// contract rather than a new data representation, so the dispatch's
/// [`BorrowedDecl`] `impl`s it (DIP + ISP). Object-safe; the impls return
/// borrows tied to the source, so delivery stays heap-free and copy-free.
///
/// Both accessors are unconditional plain types: every peer declaration
/// is identified by its `id` and the `keyexpr` it was declared on (the
/// resolved literal, peer DECLARE-table lookup already applied).
pub trait DeclView {
    /// Peer-assigned declaration id (the `DeclX.id` wire field; the
    /// matching `UndeclX` carries the same id).
    fn id(&self) -> u64;
    /// Resolved keyexpr literal the entity was declared on.
    fn keyexpr(&self) -> &str;
}

/// A [`DeclView`] over loose borrowed fields — the canonical impl the
/// registry dispatch builds from `(decl.id, resolved-keyexpr)`. One
/// `DeclView` impl; not the delivery currency itself (that is
/// `&dyn DeclView`).
pub struct BorrowedDecl<'a> {
    /// Peer-assigned declaration id.
    pub id: u64,
    /// Resolved keyexpr literal.
    pub keyexpr: &'a str,
}

impl DeclView for BorrowedDecl<'_> {
    fn id(&self) -> u64 {
        self.id
    }
    fn keyexpr(&self) -> &str {
        self.keyexpr
    }
}

/// Declaration sink: the Dependency-Inversion seam a remote-declaration
/// registry fans inbound `Declare(DeclX)` records to. See the [module
/// docs](self) for the AP ([`BoxedDeclSink`]) vs MCU (consumer-supplied
/// closed `enum`) backing contract.
///
/// R311kj — RE-ENTRANCY: the production dispatch invokes this while the
/// owning registry (and on the AP profile the WHOLE
/// `ApplicationLayerObserver` mutex) is held, so a DIRECT sink install
/// must NOT call back into any observer-locking session API or it
/// self-deadlocks (std Mutex) / RefCell-panics (MCU). R311lc — the
/// Session-tier `declare_remote_*_listener` surfaces install DEFERRED
/// staging sinks (see the `deferred_fire` module) whose user callback
/// runs outside the observer lock with NO re-entrancy constraint; the
/// inline contract here remains exactly for hand-installed sinks on the
/// raw registries.
pub trait DeclSink {
    /// Observe one inbound peer declaration. The [`DeclView`] is borrowed
    /// for the duration of the call only.
    fn on_declared(&mut self, decl: &dyn DeclView);
}

/// Undeclaration sink: the seam a remote-declaration registry fans
/// inbound `Declare(UndeclX)` records to. The undeclaration carries only
/// the `id` (the peer identifies the prior declaration by id; the wire
/// `UndeclX` body has no keyexpr), so this is a bare scalar — the
/// control-plane analogue of the reply seam's `on_final(rid)`.
/// Carries the same R311kj inline re-entrancy constraint (and the same
/// R311lc deferred Session-tier alternative) as [`DeclSink`].
pub trait UndeclSink {
    /// Observe one inbound peer undeclaration, identified by its `id`.
    fn on_undeclared(&mut self, id: u64);
}

/// One keyed observer slot in a [`DeclObserverPair`] list: the
/// pair-local monotonic id (the removal currency `install_*` returns —
/// the same list-local-id pattern as the matching plane's
/// `MatchingWatchList`, not a wire id) + the sink it keys.
struct KeyedSink<S> {
    id: u64,
    sink: S,
}

/// R311gb (Track 2) — the shared declaration-observer mechanism for the
/// three `DeclSink` / `UndeclSink` registries
/// ([`crate::declare::subscriber::RemoteSubscriberRegistry`],
/// [`crate::declare::queryable::RemoteQueryableRegistry`],
/// [`crate::declare::liveliness::LivelinessRegistry`]).
///
/// Each of those registries observes a distinct `Declare` sub-type (and
/// the subscriber / queryable ones additionally track a peer-`declared`
/// membership table), but their **observer-list machinery is identical**:
/// a bounded `on_decl` list of [`DeclSink`]s + a bounded `on_undecl` list
/// of [`UndeclSink`]s, installed at startup and fanned in registration
/// order on every matching inbound declare. Rather than copy that
/// machinery into each registry (the R311hf state triplicated it), they
/// **compose** this one component — the SSOT for the 2-list observer
/// fan-out — and keep only their own dispatch + membership state. The
/// registries' public named methods (`on_subscriber_declared_sink`, …)
/// stay as thin delegators so consumer ergonomics are unchanged; the
/// separation into distinct registry *types* (the deliberate
/// scope-boundary decision) is preserved.
///
/// R311lb — observers are id-keyed: `install_*` returns the pair-local
/// id and `uninstall_*` removes by it, so a Session-tier listener handle
/// (the deferred-fire decl listeners, R311lc) can undeclare its staging
/// sinks instead of leaking dead entries against
/// [`caps::MAX_DECL_OBSERVERS`]. Removal preserves registration order
/// for the surviving observers ([`BoundedVec::retain`]).
///
/// No-alloc: both lists are [`BoundedVec`] capped at
/// [`caps::MAX_DECL_OBSERVERS`]; `fire_*` split nothing and allocate
/// nothing, so the whole component is the MCU no-heap control plane.
pub struct DeclObserverPair<D: DeclSink, U: UndeclSink> {
    on_decl: BoundedVec<KeyedSink<D>, { caps::MAX_DECL_OBSERVERS }>,
    on_undecl: BoundedVec<KeyedSink<U>, { caps::MAX_DECL_OBSERVERS }>,
    /// Monotonic id source shared by both lists (ids are unique within
    /// the pair, so a caller cannot cross-cancel a decl observer with
    /// an undecl id that happens to collide).
    next_id: u64,
}

impl<D: DeclSink, U: UndeclSink> Default for DeclObserverPair<D, U> {
    fn default() -> Self {
        Self::new()
    }
}

impl<D: DeclSink, U: UndeclSink> DeclObserverPair<D, U> {
    /// Empty observer pair. `const` so a registry may hold it in a
    /// `const` / `static` slot.
    pub const fn new() -> Self {
        Self {
            on_decl: BoundedVec::new(),
            on_undecl: BoundedVec::new(),
            next_id: 0,
        }
    }

    /// Install a declaration observer. Fallible on the no-alloc backing
    /// ([`RegisterError::TableFull`] past [`caps::MAX_DECL_OBSERVERS`]);
    /// infallible on `alloc`. Duplicate sinks are allowed; fired in
    /// registration order. R311lb — returns the pair-local observer id
    /// for [`uninstall_decl`](Self::uninstall_decl); the id is consumed
    /// only on a successful install.
    pub fn install_decl(&mut self, sink: D) -> Result<u64, RegisterError> {
        let id = self.next_id;
        self.on_decl
            .push(KeyedSink { id, sink })
            .map_err(|_| RegisterError::TableFull)?;
        self.next_id += 1;
        Ok(id)
    }

    /// Install an undeclaration observer. Same contract as
    /// [`install_decl`](Self::install_decl); the returned id feeds
    /// [`uninstall_undecl`](Self::uninstall_undecl).
    pub fn install_undecl(&mut self, sink: U) -> Result<u64, RegisterError> {
        let id = self.next_id;
        self.on_undecl
            .push(KeyedSink { id, sink })
            .map_err(|_| RegisterError::TableFull)?;
        self.next_id += 1;
        Ok(id)
    }

    /// R311lb — remove the declaration observer keyed by `id`,
    /// preserving registration order for the survivors. Returns whether
    /// one was removed (`false` = unknown or already-removed id; double
    /// removal is a no-op, mirroring the matching plane's
    /// `MatchingWatchList::unregister`).
    pub fn uninstall_decl(&mut self, id: u64) -> bool {
        let before = self.on_decl.len();
        self.on_decl.retain(|k| k.id != id);
        self.on_decl.len() != before
    }

    /// R311lb — remove the undeclaration observer keyed by `id`. Same
    /// contract as [`uninstall_decl`](Self::uninstall_decl).
    pub fn uninstall_undecl(&mut self, id: u64) -> bool {
        let before = self.on_undecl.len();
        self.on_undecl.retain(|k| k.id != id);
        self.on_undecl.len() != before
    }

    /// Number of installed declaration observers.
    pub fn decl_len(&self) -> usize {
        self.on_decl.len()
    }

    /// Number of installed undeclaration observers.
    pub fn undecl_len(&self) -> usize {
        self.on_undecl.len()
    }

    /// No-heap declaration fire: hand each declaration observer the
    /// borrowed [`DeclView`]. Returns the count fired.
    pub fn fire_declared(&mut self, view: &dyn DeclView) -> usize {
        let mut fired: usize = 0;
        for keyed in self.on_decl.iter_mut() {
            keyed.sink.on_declared(view);
            fired = fired.saturating_add(1);
        }
        fired
    }

    /// No-heap undeclaration fire: hand each undeclaration observer the
    /// bare `id`. Returns the count fired.
    pub fn fire_undeclared(&mut self, id: u64) -> usize {
        let mut fired: usize = 0;
        for keyed in self.on_undecl.iter_mut() {
            keyed.sink.on_undeclared(id);
            fired = fired.saturating_add(1);
        }
        fired
    }
}

/// Heap declaration-closure type backing [`BoxedDeclSink`]. Factored to a
/// `type` per `clippy::type_complexity` — the nested `&dyn DeclView`
/// trait object pushes the inline `Box<dyn FnMut(...)>` over the
/// complexity threshold.
#[cfg(feature = "alloc")]
type BoxedDeclFn = Box<dyn FnMut(&dyn DeclView) + Send + 'static>;

/// AP / `alloc`-profile adapter wrapping a declaration closure on the
/// heap, type-erasing it so a registry stores a homogeneous observer
/// list (the dynamic-opt-in side). No MCU counterpart — the no-heap
/// profile uses a consumer-supplied closed `enum` instead.
#[cfg(feature = "alloc")]
pub struct BoxedDeclSink {
    inner: BoxedDeclFn,
}

#[cfg(feature = "alloc")]
impl BoxedDeclSink {
    /// Wrap a capturing declaration observer as a heap-stored sink.
    pub fn new(callback: impl FnMut(&dyn DeclView) + Send + 'static) -> Self {
        Self {
            inner: Box::new(callback),
        }
    }
}

#[cfg(feature = "alloc")]
impl DeclSink for BoxedDeclSink {
    fn on_declared(&mut self, decl: &dyn DeclView) {
        (self.inner)(decl)
    }
}

/// Heap undeclaration-closure type backing [`BoxedUndeclSink`].
#[cfg(feature = "alloc")]
type BoxedUndeclFn = Box<dyn FnMut(u64) + Send + 'static>;

/// AP / `alloc`-profile adapter wrapping an undeclaration closure on the
/// heap. No MCU counterpart — the no-heap profile uses a consumer-
/// supplied closed `enum` instead.
#[cfg(feature = "alloc")]
pub struct BoxedUndeclSink {
    inner: BoxedUndeclFn,
}

#[cfg(feature = "alloc")]
impl BoxedUndeclSink {
    /// Wrap a capturing undeclaration observer as a heap-stored sink.
    pub fn new(callback: impl FnMut(u64) + Send + 'static) -> Self {
        Self {
            inner: Box::new(callback),
        }
    }
}

#[cfg(feature = "alloc")]
impl UndeclSink for BoxedUndeclSink {
    fn on_undeclared(&mut self, id: u64) {
        (self.inner)(id)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // No-heap concrete sinks: the shape an MCU consumer `enum` variant
    // takes. Read the declaration through `DeclView` / observe the
    // undeclare id with no `Box`, so they compile + run on both the
    // `alloc` and no-`alloc` profiles.
    #[derive(Default)]
    struct CountingDeclSink {
        decls: u32,
        last_id: u64,
        last_key_len: usize,
    }

    impl DeclSink for CountingDeclSink {
        fn on_declared(&mut self, decl: &dyn DeclView) {
            self.decls += 1;
            self.last_id = decl.id();
            self.last_key_len = decl.keyexpr().len();
        }
    }

    #[derive(Default)]
    struct CountingUndeclSink {
        undecls: u32,
        last_id: u64,
    }

    impl UndeclSink for CountingUndeclSink {
        fn on_undeclared(&mut self, id: u64) {
            self.undecls += 1;
            self.last_id = id;
        }
    }

    #[test]
    fn concrete_decl_sink_reads_through_view_contract() {
        let mut sink = CountingDeclSink::default();
        sink.on_declared(&BorrowedDecl {
            id: 7,
            keyexpr: "home/temp",
        });
        assert_eq!(sink.decls, 1);
        assert_eq!(sink.last_id, 7);
        assert_eq!(sink.last_key_len, 9);
    }

    #[test]
    fn concrete_undecl_sink_observes_scalar_id() {
        let mut sink = CountingUndeclSink::default();
        sink.on_undeclared(42);
        assert_eq!(sink.undecls, 1);
        assert_eq!(sink.last_id, 42);
    }

    /// R311gb (Track 2) — direct exercise of the extracted
    /// [`DeclObserverPair`] SSOT with concrete (no-`Box`) sinks: install
    /// two declaration observers + one undeclaration observer, then fire
    /// both no-heap fan-outs and confirm registration-order delivery +
    /// the returned fired-counts. This is the component the three
    /// `DeclSink` registries now compose, so one test covers all three.
    #[test]
    fn observer_pair_installs_and_fires_concrete_sinks() {
        use core::sync::atomic::{AtomicUsize, Ordering};
        use std::sync::Arc;

        struct CountDecl(Arc<AtomicUsize>);
        impl DeclSink for CountDecl {
            fn on_declared(&mut self, _d: &dyn DeclView) {
                self.0.fetch_add(1, Ordering::SeqCst);
            }
        }
        struct CountUndecl(Arc<AtomicUsize>);
        impl UndeclSink for CountUndecl {
            fn on_undeclared(&mut self, _id: u64) {
                self.0.fetch_add(1, Ordering::SeqCst);
            }
        }

        let dcount = Arc::new(AtomicUsize::new(0));
        let ucount = Arc::new(AtomicUsize::new(0));
        let mut pair: DeclObserverPair<CountDecl, CountUndecl> = DeclObserverPair::new();
        pair.install_decl(CountDecl(dcount.clone())).unwrap();
        pair.install_decl(CountDecl(dcount.clone())).unwrap();
        pair.install_undecl(CountUndecl(ucount.clone())).unwrap();
        assert_eq!(pair.decl_len(), 2);
        assert_eq!(pair.undecl_len(), 1);

        let fired = pair.fire_declared(&BorrowedDecl {
            id: 9,
            keyexpr: "k",
        });
        assert_eq!(fired, 2, "both declaration observers fire");
        assert_eq!(dcount.load(Ordering::SeqCst), 2);

        let ufired = pair.fire_undeclared(9);
        assert_eq!(ufired, 1);
        assert_eq!(ucount.load(Ordering::SeqCst), 1);
    }

    /// R311lb — id-keyed removal: `install_*` hands back a pair-local
    /// id, `uninstall_*` removes exactly that observer (survivors keep
    /// firing in registration order), double removal reports `false`,
    /// and the decl / undecl id spaces share one counter so ids never
    /// collide across the two lists.
    #[test]
    fn observer_pair_uninstalls_by_id() {
        use core::sync::atomic::{AtomicUsize, Ordering};
        use std::sync::Arc;

        struct CountDecl(Arc<AtomicUsize>);
        impl DeclSink for CountDecl {
            fn on_declared(&mut self, _d: &dyn DeclView) {
                self.0.fetch_add(1, Ordering::SeqCst);
            }
        }
        struct CountUndecl(Arc<AtomicUsize>);
        impl UndeclSink for CountUndecl {
            fn on_undeclared(&mut self, _id: u64) {
                self.0.fetch_add(1, Ordering::SeqCst);
            }
        }

        let first = Arc::new(AtomicUsize::new(0));
        let second = Arc::new(AtomicUsize::new(0));
        let ucount = Arc::new(AtomicUsize::new(0));
        let mut pair: DeclObserverPair<CountDecl, CountUndecl> = DeclObserverPair::new();
        let d0 = pair.install_decl(CountDecl(first.clone())).unwrap();
        let d1 = pair.install_decl(CountDecl(second.clone())).unwrap();
        let u0 = pair.install_undecl(CountUndecl(ucount.clone())).unwrap();
        assert_ne!(d0, d1, "decl ids are distinct");
        assert_ne!(d1, u0, "decl/undecl ids share one counter");

        assert!(pair.uninstall_decl(d0), "known id removes");
        assert!(!pair.uninstall_decl(d0), "double removal reports false");
        assert_eq!(pair.decl_len(), 1);

        let view = BorrowedDecl {
            id: 3,
            keyexpr: "k",
        };
        assert_eq!(pair.fire_declared(&view), 1, "survivor still fires");
        assert_eq!(first.load(Ordering::SeqCst), 0, "removed observer silent");
        assert_eq!(second.load(Ordering::SeqCst), 1);

        // An undecl id is not removable through the decl list (and vice
        // versa) — the lists are keyed independently.
        assert!(!pair.uninstall_decl(u0));
        assert!(pair.uninstall_undecl(u0));
        assert_eq!(pair.undecl_len(), 0);
        assert_eq!(pair.fire_undeclared(3), 0);
        assert_eq!(ucount.load(Ordering::SeqCst), 0);
    }

    #[cfg(feature = "alloc")]
    #[test]
    fn boxed_decl_sink_dispatches_to_captured_closure() {
        use std::string::{String, ToString};
        use std::sync::{Arc, Mutex};
        use std::vec::Vec;

        let seen: Arc<Mutex<Vec<(u64, String)>>> = Arc::new(Mutex::new(Vec::new()));
        let seen_cb = Arc::clone(&seen);
        let mut sink = BoxedDeclSink::new(move |decl: &dyn DeclView| {
            seen_cb
                .lock()
                .unwrap()
                .push((decl.id(), decl.keyexpr().to_string()));
        });

        sink.on_declared(&BorrowedDecl {
            id: 1,
            keyexpr: "a/b",
        });
        sink.on_declared(&BorrowedDecl {
            id: 2,
            keyexpr: "c/d",
        });

        let got = seen.lock().unwrap();
        assert_eq!(got.len(), 2);
        assert_eq!(got[0], (1, "a/b".to_string()));
        assert_eq!(got[1], (2, "c/d".to_string()));
    }

    #[cfg(feature = "alloc")]
    #[test]
    fn boxed_undecl_sink_dispatches_to_captured_closure() {
        use std::sync::{Arc, Mutex};
        use std::vec::Vec;

        let seen: Arc<Mutex<Vec<u64>>> = Arc::new(Mutex::new(Vec::new()));
        let seen_cb = Arc::clone(&seen);
        let mut sink = BoxedUndeclSink::new(move |id: u64| {
            seen_cb.lock().unwrap().push(id);
        });

        sink.on_undeclared(10);
        sink.on_undeclared(20);

        assert_eq!(*seen.lock().unwrap(), std::vec![10, 20]);
    }
}
