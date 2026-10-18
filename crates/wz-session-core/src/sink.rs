// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
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
/// unconditional — every profile reads them. The richer metadata
/// accessors are provided methods that default to `None`. QoS, the attachment
/// and the source identification are there on every profile that selects a storage
/// profile (their types are plain values and a slice); the timestamp and the encoding
/// are read on every profile as their parts ([`timestamp_parts`](Self::timestamp_parts),
/// [`encoding_parts`](Self::encoding_parts): borrowed, so nothing is built to answer),
/// and as the owned hints (`timestamp`, `encoding`) on the `alloc` profile only,
/// whose [`crate::sample::Sample`] overrides all of them so an AP subscriber keeps
/// full-fidelity field access through the seam. The loose-bytes [`BorrowedSample`]
/// keeps the `None` defaults.
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
    /// Defaults to `None` for views carrying no QoS.
    #[cfg(feature = "storage-profile")]
    fn qos(&self) -> Option<crate::sample::QosLevel> {
        None
    }
    /// Body-level attachment blob, if present. Defaults to `None`.
    #[cfg(feature = "storage-profile")]
    fn attachment(&self) -> Option<&[u8]> {
        None
    }
    /// The attachment as the shareable value the view holds it in, when it holds
    /// one: the twin of [`payload_shared`](Self::payload_shared). The view of a
    /// received [`Sample`](crate::sample::Sample) answers with the range of the
    /// frame the attachment arrived in, so a subscriber that keeps the sample
    /// takes a second reference to that storage instead of copying the bytes out.
    /// Defaults to `None`, and a view that answers `None` here while
    /// [`attachment`](Self::attachment) answers `Some` is retained by copying.
    #[cfg(feature = "alloc")]
    fn attachment_shared(&self) -> Option<&crate::link::RxBytes> {
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
    #[cfg(feature = "storage-profile")]
    fn source_info(&self) -> Option<&crate::sample::SourceInfo> {
        None
    }
    /// The body-level timestamp read where it lies, if present: the NTP64 time word
    /// and the zid prefix bytes, which is what [`timestamp`](Self::timestamp)'s hint
    /// holds, without the hint. Nothing is built to answer, so it is the accessor of a
    /// profile with no allocator. Defaults to `None`.
    fn timestamp_parts(&self) -> Option<(u64, &[u8])> {
        None
    }
    /// The body-level encoding read where it lies (Put-only on the wire), if present:
    /// the packed id and the schema text, as [`encoding`](Self::encoding)'s hint
    /// holds them. Defaults to `None`.
    fn encoding_parts(&self) -> Option<(u32, Option<&str>)> {
        None
    }
    /// The payload as the shareable value the view holds it in, when it holds
    /// one: the view of a received [`Sample`](crate::sample::Sample) answers with
    /// the range of the frame it arrived in, so a subscriber that keeps the sample
    /// past the call ([`Sample::from_view`](crate::sample::Sample::from_view))
    /// takes a second reference to that storage instead of copying the bytes out.
    /// Defaults to `None`: a view over loose borrowed bytes has nothing to share,
    /// and retaining it copies, as it always did.
    #[cfg(feature = "alloc")]
    fn payload_shared(&self) -> Option<&crate::link::RxBytes> {
        None
    }
    /// [`payload_shared`](Self::payload_shared) as a value the caller owns: for a caller that
    /// keeps it, the one reference it takes, where a borrowed answer is a reference the view
    /// holds and the caller takes another of. A view that builds the answer on demand builds
    /// it once, into the caller's hands, and holds none.
    #[cfg(feature = "alloc")]
    fn payload_shared_owned(&self) -> Option<crate::link::RxBytes> {
        self.payload_shared().cloned()
    }
    /// Whether this sample's keyexpr is the keyexpr of the sample the caller delivered to the
    /// same callback in the call just before this one, as the caller says. A callback that
    /// keeps a copy of the last key may then leave it as it is instead of writing it again. The
    /// default is `false`, which is always right: a view whose caller does not know says so.
    fn keyexpr_unchanged(&self) -> bool {
        false
    }
    /// Whether this sample is a plain Put: kind `Put`, and no attachment, timestamp, source
    /// info or encoding, so that every accessor of those answers as it does for a sample that
    /// has none. A callback that kept the fields of the sample before may then read only what
    /// a plain Put still varies in (its QoS and reliability). The default is `false`, which is
    /// always right.
    fn is_plain_put(&self) -> bool {
        false
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

    /// Deliver one matched plain `Put` of a received frame
    /// ([`PlainSample`]). The default is [`Self::deliver`]; a sink that can keep what
    /// it needs of the sample as a range of the frame (a reference to the frame's
    /// storage, not a copy of the payload) overrides it, and then also
    /// [`Self::end_plain_frame`].
    #[cfg(feature = "alloc")]
    fn deliver_plain(&mut self, sample: &PlainSample<'_>) {
        self.deliver(sample);
    }

    /// The frame whose plain `Put`s were just offered through [`Self::deliver_plain`]
    /// has no more records for this table: a sink that gathered them hands over what it
    /// has. Called on every sink of the table after each such frame, matched or not, so
    /// it must cost nothing when nothing was gathered.
    #[cfg(feature = "alloc")]
    fn end_plain_frame(&mut self) {}
}

/// A plain `Put` of a received frame, as a [`SampleView`] over the frame it arrived in:
/// the keyexpr resolved for it, and the payload a range of the frame. A subscriber
/// that keeps the sample takes a second reference to the frame's storage
/// ([`SampleView::payload_shared`]) instead of copying the payload out; a sink that
/// gathers a frame's samples reads [`Self::frame`] and [`Self::payload_range`] and
/// keeps those.
#[cfg(feature = "alloc")]
pub struct PlainSample<'s> {
    keyexpr: &'s str,
    frame: &'s crate::link::RxBytes,
    range: (u32, u32),
    reliability: Reliability,
    qos: Option<crate::sample::QosLevel>,
    shared: core::cell::OnceCell<Option<crate::link::RxBytes>>,
    repeats_previous: bool,
    key_unchanged: bool,
}

#[cfg(feature = "alloc")]
impl<'s> PlainSample<'s> {
    /// The sample of the `range` of `frame`, on `keyexpr`.
    pub fn new(
        keyexpr: &'s str,
        frame: &'s crate::link::RxBytes,
        range: (u32, u32),
        reliability: Reliability,
        qos: Option<crate::sample::QosLevel>,
    ) -> Self {
        Self {
            keyexpr,
            frame,
            range,
            reliability,
            qos,
            shared: core::cell::OnceCell::new(),
            repeats_previous: false,
            key_unchanged: false,
        }
    }

    /// Say that this sample's key is the key of the sample the caller handed to the same
    /// callback in the call just before this one ([`SampleView::keyexpr_unchanged`]). A caller
    /// sets it only when that is so.
    #[must_use]
    pub fn with_unchanged_key(mut self) -> Self {
        self.key_unchanged = true;
        self
    }

    /// Say that this sample's key is the key of the sample offered just before it in the same
    /// frame, to every sink of the table alike. A caller sets it only when that is so, and a
    /// sink that keeps a list of keys may then reuse the entry it used for the sample before
    /// instead of looking the key up again.
    #[must_use]
    pub fn repeating_the_previous_key(mut self) -> Self {
        self.repeats_previous = true;
        self
    }

    /// Whether this sample's key is the previous sample's, as the caller said
    /// ([`Self::repeating_the_previous_key`]).
    pub fn repeats_previous_key(&self) -> bool {
        self.repeats_previous
    }

    /// The frame the sample arrived in, whose storage a sink may take a reference to.
    pub fn frame(&self) -> &'s crate::link::RxBytes {
        self.frame
    }

    /// Where the payload lies in [`Self::frame`], as `start..end`.
    pub fn payload_range(&self) -> core::ops::Range<usize> {
        self.range.0 as usize..self.range.1 as usize
    }
}

#[cfg(feature = "alloc")]
impl SampleView for PlainSample<'_> {
    fn keyexpr(&self) -> &str {
        self.keyexpr
    }
    fn payload(&self) -> &[u8] {
        &self.frame.as_slice()[self.payload_range()]
    }
    fn kind(&self) -> SampleKind {
        SampleKind::Put
    }
    fn reliability(&self) -> Reliability {
        self.reliability
    }
    fn qos(&self) -> Option<crate::sample::QosLevel> {
        self.qos
    }
    fn payload_shared(&self) -> Option<&crate::link::RxBytes> {
        self.shared
            .get_or_init(|| self.frame.subslice(self.payload_range()))
            .as_ref()
    }
    fn payload_shared_owned(&self) -> Option<crate::link::RxBytes> {
        // Read through the borrowed answer when it was already built; otherwise built here,
        // for the caller alone, and kept nowhere.
        match self.shared.get() {
            Some(built) => built.clone(),
            None => self.frame.subslice(self.payload_range()),
        }
    }
    fn keyexpr_unchanged(&self) -> bool {
        self.key_unchanged
    }
    fn is_plain_put(&self) -> bool {
        // A plain `Put` of a frame has nothing else: its accessors are the defaults.
        true
    }
}

/// The closed sink of a node with no allocator: a function and the state it works on,
/// stored inline. Where [`BoxedSink`] erases the type of a capturing closure behind a
/// `Box`, this names it: the state is a field, the function is a plain `fn` that is
/// handed the state and the sample, so the registration stores nothing on the heap and
/// the registry that holds it is typed by `S`.
///
/// A node that makes one kind of registration (the admin node's one config-write
/// subscriber) types its table by this; one that makes several kinds writes the
/// closed `enum` this module's docs describe and implements [`SampleSink`] for it.
pub struct FnSink<S> {
    state: S,
    call: fn(&mut S, &dyn SampleView),
}

impl<S> FnSink<S> {
    /// A sink that calls `call` with `state` and each matched sample.
    pub const fn new(state: S, call: fn(&mut S, &dyn SampleView)) -> Self {
        Self { state, call }
    }
}

impl<S> SampleSink for FnSink<S> {
    fn deliver(&mut self, sample: &dyn SampleView) {
        (self.call)(&mut self.state, sample);
    }
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

/// What a [`BoxedSink`] holds: the heap form of a [`SampleSink`], `Send` so the registry
/// that stores it can cross threads. A capturing closure is one (see
/// [`BoxedSink::new`]); a sink that gathers the plain `Put`s of a frame implements the
/// two plain methods itself ([`BoxedSink::from_frame_sink`]).
#[cfg(feature = "alloc")]
pub trait FrameSink: Send + 'static {
    /// [`SampleSink::deliver`].
    fn sample(&mut self, view: &dyn SampleView);
    /// [`SampleSink::deliver_plain`]; the default delivers the sample as any other.
    fn plain(&mut self, sample: &PlainSample<'_>) {
        self.sample(sample);
    }
    /// [`SampleSink::end_plain_frame`].
    fn plain_frame_end(&mut self) {}
}

/// A capturing closure as a [`FrameSink`]: every sample is a call of it.
#[cfg(feature = "alloc")]
struct ClosureSink(BoxedSampleFn);

#[cfg(feature = "alloc")]
impl FrameSink for ClosureSink {
    fn sample(&mut self, view: &dyn SampleView) {
        (self.0)(view)
    }
}

#[cfg(feature = "alloc")]
pub struct BoxedSink {
    inner: Box<dyn FrameSink>,
}

#[cfg(feature = "alloc")]
impl BoxedSink {
    /// Wrap a capturing closure as a heap-stored sink.
    pub fn new(callback: impl FnMut(&dyn SampleView) + Send + 'static) -> Self {
        Self {
            inner: Box::new(ClosureSink(Box::new(callback))),
        }
    }

    /// Store a sink that answers the plain-`Put` methods itself.
    pub fn from_frame_sink(sink: impl FrameSink) -> Self {
        Self {
            inner: Box::new(sink),
        }
    }
}

#[cfg(feature = "alloc")]
impl SampleSink for BoxedSink {
    fn deliver(&mut self, sample: &dyn SampleView) {
        self.inner.sample(sample)
    }

    fn deliver_plain(&mut self, sample: &PlainSample<'_>) {
        self.inner.plain(sample)
    }

    fn end_plain_frame(&mut self) {
        self.inner.plain_frame_end()
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

    /// The owned answer is the payload's own range of the frame whether or not the borrowed one
    /// was built before it, and a view with nothing shared has none either way.
    #[cfg(feature = "alloc")]
    #[test]
    fn a_plain_sample_hands_out_its_payload_range_as_an_owned_value() {
        let frame = crate::link::RxBytes::from(b"..HELLO..".to_vec());
        let sample = PlainSample::new("k", &frame, (2, 7), Reliability::Reliable, None);

        let before = sample.payload_shared_owned().expect("a range of the frame");
        assert_eq!(before.as_slice(), b"HELLO");
        assert_eq!(sample.payload(), b"HELLO");

        let borrowed = sample.payload_shared().expect("built on demand");
        assert_eq!(borrowed.as_slice(), b"HELLO");
        let after = sample
            .payload_shared_owned()
            .expect("the built one, shared");
        assert_eq!(after.as_slice(), b"HELLO");

        let loose = BorrowedSample {
            keyexpr: "k",
            payload: b"x",
            kind: SampleKind::Put,
            reliability: Reliability::Reliable,
        };
        assert!(loose.payload_shared_owned().is_none());
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
