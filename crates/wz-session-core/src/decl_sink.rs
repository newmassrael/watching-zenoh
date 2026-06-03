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
pub trait UndeclSink {
    /// Observe one inbound peer undeclaration, identified by its `id`.
    fn on_undeclared(&mut self, id: u64);
}

/// R311gb (Track 2) — failure mode of installing a declaration observer
/// (`on_*_declared_sink` / `on_*_undeclared_sink`) on the no-alloc (MCU)
/// backing: the observer list is at its declared capacity
/// ([`crate::caps::MAX_DECL_OBSERVERS`]), surfaced fail-fast per the
/// [`crate::bounded`] contract (no silent drop). On the `alloc` (AP)
/// backing it is never returned — the list grows, so the convenience
/// closure-installer wrappers stay infallible there. Shared by the three
/// `DeclSink` / `UndeclSink` registries (subscriber / queryable /
/// liveliness).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeclRegisterError {
    /// The observer list is at its declared capacity
    /// ([`crate::caps::MAX_DECL_OBSERVERS`]).
    ObserverTableFull,
}

impl core::fmt::Display for DeclRegisterError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::ObserverTableFull => {
                f.write_str("declaration observer list at declared capacity")
            }
        }
    }
}

impl core::error::Error for DeclRegisterError {}

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
