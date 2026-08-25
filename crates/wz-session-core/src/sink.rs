// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! Sample-delivery seam (`SampleView` accessor contract + `SampleSink`
//! trait + the `alloc`-only `BoxedSink` closure adapter) for the
//! application-layer subscriber registries.
//!
//! Model B (statechart-event) callback architecture: a subscriber
//! registry dispatches matched samples through a Dependency-Inversion
//! seam rather than a hard-coded `Box<dyn FnMut>`, so one registry
//! implementation backs both profiles (ARCHITECTURE.md §2.4 static-first,
//! dynamic-opt-in):
//!
//! - **AP / `alloc` on** — [`BoxedSink`] wraps a heap closure; the
//!   registry stores a homogeneous `BoxedSink`, type-erasing arbitrary
//!   capturing closures via the heap (the §2.3-note dynamic-opt-in side).
//! - **MCU / `alloc` off** — the consumer (a hand-written app, or the
//!   SCE-Mesh / wz-standalone switchboard generator) supplies a closed
//!   `enum` whose variants route to codegen'd Worker producers /
//!   statechart `on_sample` ingress; each variant impls [`SampleSink`]
//!   with no heap. wz ships only the trait + the AP adapter; the no-heap
//!   sink is the consumer's (generated or hand-written) type.
//!
//! **Delivery currency = [`SampleView`], an accessor *contract*, not a
//! data type.** The owned [`crate::sample::Sample`] (AP retention form)
//! and the SCE link-runtime `Sample<'pool>` borrowed ingress (MCU/Mesh)
//! each `impl SampleView`, so the registry trait depends on one read
//! contract (DIP + ISP) rather than re-projecting into a third sample
//! struct. [`deliver`](SampleSink::deliver) takes `&dyn SampleView` — a
//! borrowed fat pointer, no heap and no copy — so the dispatch site
//! passes its native sample directly (`&owned as &dyn SampleView`) with
//! no projection step. wz-session-core defines only the trait; the
//! `impl SampleView for sce::Sample<'pool>` lives in the bridge crate
//! where both types are visible (a wz hand-written impl, NOT an
//! SCE-codegen one — the RFC#1 "no external trait impl" rule is about
//! generated code and is unaffected).
//!
//! SCE-generated code never impls [`SampleSink`] directly either: a wz
//! adapter wraps the SCE-owned ingress handle and impls the trait over
//! it. [`BoxedSink`] (the closure case) is such an adapter. Statechart
//! injection, by contrast, does NOT go through a `SampleSink`: it is a
//! distinct inbound adapter that threads the engine ingress port rather
//! than storing an engine handle — see [`crate::switchboard`] (R311gh
//! supersedes the gc-1 `StatechartSink`-as-`SampleSink` shape).

#[cfg(feature = "alloc")]
use alloc::boxed::Box;

use crate::reliability::Reliability;
use crate::sample_kind::SampleKind;

/// Read-only accessor contract for an inbound sample handed to a
/// [`SampleSink`]. This is the delivery currency (passed as
/// `&dyn SampleView`); see the [module docs](self) for why it is a
/// contract rather than a new data representation. Object-safe; the impls
/// return borrows tied to the source, so delivery stays heap-free and
/// copy-free.
///
/// The four routing-essential accessors (resolved keyexpr literal,
/// payload bytes, Put/Del kind, link-layer reliability) are
/// unconditional — every profile reads them. The five richer
/// metadata accessors (QoS, attachment, timestamp, encoding,
/// source-info) are `alloc`-gated provided methods that default to
/// `None`: their return types live in the `alloc`-gated
/// [`crate::sample`] module, and a no-`alloc` MCU profile carries no
/// such metadata. The AP [`crate::sample::Sample`] overrides all five
/// so an AP subscriber keeps full-fidelity field access through the
/// seam; the loose-bytes [`BorrowedSample`] keeps the `None` defaults.
pub trait SampleView {
    /// Resolved keyexpr literal (peer DECLARE table lookup already applied).
    fn keyexpr(&self) -> &str;
    /// Payload bytes. Empty for a Del sample.
    fn payload(&self) -> &[u8];
    /// Put vs Del discriminant.
    fn kind(&self) -> SampleKind;
    /// Link-layer reliability classification of the carrying frame.
    fn reliability(&self) -> Reliability;

    /// QoS level decoded from the Push outer extension chain, if any.
    /// `alloc`-only (the type lives in the `alloc`-gated `sample`
    /// module); defaults to `None` for views carrying no QoS.
    #[cfg(feature = "alloc")]
    fn qos(&self) -> Option<crate::sample::QosLevel> {
        None
    }
    /// Body-level attachment blob, if present. Defaults to `None`.
    #[cfg(feature = "alloc")]
    fn attachment(&self) -> Option<&[u8]> {
        None
    }
    /// Body-level timestamp hint, if present. Defaults to `None`.
    #[cfg(feature = "alloc")]
    fn timestamp(&self) -> Option<&crate::sample::TimestampHint> {
        None
    }
    /// Body-level encoding hint (Put-only on the wire), if present.
    /// Defaults to `None`.
    #[cfg(feature = "alloc")]
    fn encoding(&self) -> Option<&crate::sample::EncodingHint> {
        None
    }
    /// Body-level source identification, if present. Defaults to `None`.
    #[cfg(feature = "alloc")]
    fn source_info(&self) -> Option<&crate::sample::SourceInfo> {
        None
    }
}

/// A [`SampleView`] over loose borrowed bytes — the canonical impl for a
/// keyexpr + payload not backed by an owned [`crate::sample::Sample`] or
/// a pool slot (a local-publish / loopback synthesised sample, and the
/// seam's own tests). One `SampleView` impl among several; not the
/// delivery currency itself (that is `&dyn SampleView`).
pub struct BorrowedSample<'a> {
    /// Resolved keyexpr literal.
    pub keyexpr: &'a str,
    /// Payload bytes. Empty for a Del sample.
    pub payload: &'a [u8],
    /// Put vs Del discriminant.
    pub kind: SampleKind,
    /// Link-layer reliability classification.
    pub reliability: Reliability,
}

impl SampleView for BorrowedSample<'_> {
    fn keyexpr(&self) -> &str {
        self.keyexpr
    }
    fn payload(&self) -> &[u8] {
        self.payload
    }
    fn kind(&self) -> SampleKind {
        self.kind
    }
    fn reliability(&self) -> Reliability {
        self.reliability
    }
}

/// Sample-delivery sink: the Dependency-Inversion seam a subscriber
/// registry dispatches matched samples through. See the [module
/// docs](self) for the AP ([`BoxedSink`]) vs MCU (consumer-supplied
/// closed `enum`) backing contract.
pub trait SampleSink {
    /// Deliver one matched sample. The [`SampleView`] is borrowed for the
    /// duration of the call only.
    fn deliver(&mut self, sample: &dyn SampleView);
}

/// AP / `alloc`-profile adapter: wraps an arbitrary capturing closure in
/// a heap `Box`, type-erasing it so a registry stores a homogeneous
/// `BoxedSink` list of differently-captured closures (the dynamic-opt-in
/// side, ARCHITECTURE.md §2.3 note / §2.4). No MCU counterpart — the
/// no-heap profile uses a consumer-supplied closed `enum` instead.
/// Heap closure type backing [`BoxedSink`]. Factored to a `type` per
/// `clippy::type_complexity` — the nested `&dyn SampleView` trait object
/// pushes the inline `Box<dyn FnMut(...)>` over the complexity threshold.
#[cfg(feature = "alloc")]
type BoxedSampleFn = Box<dyn FnMut(&dyn SampleView) + Send + 'static>;

#[cfg(feature = "alloc")]
pub struct BoxedSink {
    inner: BoxedSampleFn,
}

#[cfg(feature = "alloc")]
impl BoxedSink {
    /// Wrap a capturing closure as a heap-stored sink.
    pub fn new(callback: impl FnMut(&dyn SampleView) + Send + 'static) -> Self {
        Self {
            inner: Box::new(callback),
        }
    }
}

#[cfg(feature = "alloc")]
impl SampleSink for BoxedSink {
    fn deliver(&mut self, sample: &dyn SampleView) {
        (self.inner)(sample)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // A no-heap-style concrete sink: the shape an MCU consumer `enum`
    // variant takes. Impls `SampleSink` without `Box`, so it compiles +
    // runs on both the `alloc` and no-`alloc` profiles.
    #[derive(Default)]
    struct CountingSink {
        calls: u32,
        last_len: usize,
        last_key_len: usize,
        last_kind: SampleKind,
    }

    impl SampleSink for CountingSink {
        fn deliver(&mut self, sample: &dyn SampleView) {
            self.calls += 1;
            self.last_len = sample.payload().len();
            self.last_key_len = sample.keyexpr().len();
            self.last_kind = sample.kind();
        }
    }

    #[test]
    fn concrete_sink_reads_through_view_contract() {
        let mut sink = CountingSink::default();
        sink.deliver(&BorrowedSample {
            keyexpr: "home/temp",
            payload: b"21.5",
            kind: SampleKind::Put,
            reliability: Reliability::Reliable,
        });
        assert_eq!(sink.calls, 1);
        assert_eq!(sink.last_len, 4);
        assert_eq!(sink.last_key_len, 9);
        assert_eq!(sink.last_kind, SampleKind::Put);
    }

    #[cfg(feature = "alloc")]
    #[test]
    fn boxed_sink_dispatches_to_captured_closure() {
        use std::string::{String, ToString};
        use std::sync::{Arc, Mutex};
        use std::vec::Vec;

        let seen: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
        let seen_cb = Arc::clone(&seen);
        let mut sink = BoxedSink::new(move |sample: &dyn SampleView| {
            seen_cb.lock().unwrap().push(sample.keyexpr().to_string());
        });

        sink.deliver(&BorrowedSample {
            keyexpr: "a/b",
            payload: b"",
            kind: SampleKind::Del,
            reliability: Reliability::Reliable,
        });
        sink.deliver(&BorrowedSample {
            keyexpr: "c/d",
            payload: b"x",
            kind: SampleKind::Put,
            reliability: Reliability::BestEffort,
        });

        let got = seen.lock().unwrap();
        assert_eq!(got.len(), 2);
        assert_eq!(got[0], "a/b");
        assert_eq!(got[1], "c/d");
    }
}
