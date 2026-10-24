// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! A FOLD OVER A CAPTURE THAT REMEMBERS WHERE IT STOPPED.
//!
//! # What this is for
//!
//! Every census plane is one fold over the messages of a capture in capture
//! order: a table, the keyexpr id spaces, and a selector read against the zids the
//! capture names. Asked again after a few more packets, a plane that starts over
//! pays for the whole capture each time, so the cost of drawing a census grows with
//! the capture and a consumer that draws it every step saturates a core. Measured
//! by that consumer: 0.8 ms at 8,000 records, 57 ms at 40,000, 131 ms at 87,000,
//! for a document that stayed 31 KB.
//!
//! A [`Resumable`] keeps the fold between calls and feeds it only the messages
//! that arrived since, which is the same fold over the same messages in the same
//! order and therefore the same table.
//!
//! # When it may continue, and what it does when it may not
//!
//! The fold continues only when the capture it stopped in is still a PREFIX of the
//! capture now: the same lists, nothing trimmed from a list's front, every new
//! message sorting after the last one folded
//! ([`Dissection::capture_order_since`](crate::Dissection) says all three), the
//! session grouping equal to the one the fold was made against, and the capture's
//! origin unchanged. Any other state starts the fold again from the first
//! message, which is what every plane always did, so the fallback is the old cost
//! and cannot be a wrong answer.
//!
//! The grouping is compared because it is an INPUT of every message the fold
//! took: which session owns a list, which zids a direction announced, and which
//! zids a selector's prefix is read against. A handshake that arrives after the
//! messages it names changes all of them for messages already folded, and a fold
//! that kept going would hold the old reading.
//!
//! # What proves it
//!
//! Not a timing. [`FoldStats`] counts the messages a memory folded and the times
//! it had to start over, so a test states the contract in work: after a step that
//! adds `n` messages the memory has folded `n` more, and after a step that
//! violates a condition above it has started over once. The other half is
//! equality: at every step of a growing capture the resumed document is the
//! document a fresh fold writes, byte for byte, and that is held across
//! captures built to violate each condition.

use crate::bounded_slots::BoundedSlots;
use crate::link::FlowKey;
use crate::node::SessionGrouping;
use crate::progress::Progress;
use crate::{Dissection, OrderMarks, TrimPolicy};
use wz_session_core::passive::PassiveFrame;

/// What a plane keeps while it folds a capture in capture order.
pub(crate) trait OrderedFold: Clone {
    /// How many planes one message feeds. A fold that is several planes fed by
    /// one walk ([`CensusFold`]) counts each message once per plane, in the
    /// progress it reports and in [`FoldStats`], which is what the planes counted
    /// when each walked the capture on its own.
    const PLANES: u64 = 1;

    /// Take one message. `list` is its position in
    /// [`Dissection::message_lists_with_origin`] and `packet` the capture packet
    /// it resolves to; `grouping` is the capture's session grouping.
    fn feed(
        &mut self,
        flow: &FlowKey,
        list: usize,
        packet: usize,
        frame: &PassiveFrame,
        grouping: &SessionGrouping,
    );
}

/// Work a memory has done: the numbers a test reads instead of a clock.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct FoldStats {
    /// Messages fed to a fold, summed over every plane that has run.
    pub messages_folded: u64,
    /// Times a fold began from the first message because it could not continue.
    pub restarts: u64,
    /// Times a fold continued from where it stopped.
    pub resumes: u64,
}

/// What a fold stopped at, so the next call can tell whether it may continue.
#[derive(Debug, Clone)]
struct Saved<F> {
    fold: F,
    grouping: SessionGrouping,
    origin_ms: Option<u64>,
    marks: OrderMarks,
}

/// A fold of one plane, kept between calls.
#[derive(Debug, Clone)]
pub(crate) struct Resumable<F> {
    saved: Option<Saved<F>>,
}

impl<F> Default for Resumable<F> {
    fn default() -> Self {
        Self { saved: None }
    }
}

impl<F: OrderedFold> Resumable<F> {
    /// The fold as it stands, or `None` before any call has made one.
    #[cfg(all(feature = "dissect", feature = "network-codecs"))]
    pub(crate) fn fold(&self) -> Option<&F> {
        self.saved.as_ref().map(|saved| &saved.fold)
    }

    /// Bring the fold up to `dissection`, continuing when it may and starting over
    /// when it may not, and hand it back.
    ///
    /// `begin` makes an empty fold against the grouping, and is called only for a
    /// start. The fold is returned by reference: a plane's reading of it is a
    /// copy, so continuing it afterwards is not disturbed.
    ///
    /// `progress` is asked once per message folded, and may stop the walk: then the
    /// answer is `None`. A continuing fold that was stopped has taken some of the
    /// new messages and not recorded where it stopped, so it is DROPPED and the next
    /// call begins it again; folding the messages it had already taken a second time
    /// would be a wrong table. A fold that was beginning keeps whatever it held
    /// before, which the stop did not touch.
    pub(crate) fn advance(
        &mut self,
        dissection: &Dissection,
        grouping: &SessionGrouping,
        stats: &mut FoldStats,
        progress: Option<&Progress<'_>>,
        begin: impl FnOnce() -> F,
    ) -> Option<&F> {
        self.advance_with(
            TrimPolicy::Restart,
            dissection,
            grouping,
            stats,
            progress,
            begin,
            None,
        )
    }

    /// [`Self::advance`] for a fold that keeps the HISTORY of the messages it has
    /// taken: it goes on across a front trim instead of beginning again, and so
    /// differs from the fold over what the capture holds NOW in whatever the
    /// trimmed messages contributed. See [`TrimPolicy`] for who may ask for it.
    ///
    /// `share` is a second reader of the same call, fed every message of this
    /// fold's walk when that walk takes exactly the messages it wants (see
    /// [`Share`]); its `fed` says whether it was.
    #[cfg(all(feature = "dissect", feature = "network-codecs"))]
    pub(crate) fn advance_across_trims(
        &mut self,
        dissection: &Dissection,
        grouping: &SessionGrouping,
        stats: &mut FoldStats,
        progress: Option<&Progress<'_>>,
        begin: impl FnOnce() -> F,
        share: Option<&mut Share<'_, '_>>,
    ) -> Option<&F> {
        self.advance_with(
            TrimPolicy::Continue,
            dissection,
            grouping,
            stats,
            progress,
            begin,
            share,
        )
    }

    // Eight: the walk's own seven and the reader it may share the walk with.
    #[allow(clippy::too_many_arguments)]
    fn advance_with(
        &mut self,
        trims: TrimPolicy,
        dissection: &Dissection,
        grouping: &SessionGrouping,
        stats: &mut FoldStats,
        progress: Option<&Progress<'_>>,
        begin: impl FnOnce() -> F,
        mut share: Option<&mut Share<'_, '_>>,
    ) -> Option<&F> {
        let origin_ms = dissection.capture_origin_ms();
        let resumed = match &self.saved {
            Some(s) if s.grouping == *grouping && s.origin_ms == origin_ms => match trims {
                TrimPolicy::Restart => dissection.capture_order_since(Some(&s.marks)),
                TrimPolicy::Continue => dissection.capture_order_since_across_trims(Some(&s.marks)),
            },
            _ => None,
        };
        if let Some(share) = share.as_deref_mut() {
            share.fed = false;
        }
        match resumed {
            Some((frames, marks)) => {
                if let Some(p) = progress {
                    p.expect(frames.iter().len() as u64 * F::PLANES);
                }
                let saved = self.saved.as_mut().expect("a resumed fold has a saved one");
                // The walk takes the messages after `saved.marks`: the reader that
                // wants the messages after the same marks reads them here.
                let mut tap =
                    share.filter(|s| matches!(s.wanted, Wanted::Since(m) if *m == saved.marks));
                let mut stopped = false;
                for (flow, list, packet, frame) in frames {
                    if !steps(progress, F::PLANES) {
                        stopped = true;
                        break;
                    }
                    saved.fold.feed(&flow, list, packet, &frame, grouping);
                    if let Some(tap) = tap.as_deref_mut() {
                        (tap.tap)(&flow, list, packet, &frame);
                    }
                    stats.messages_folded += F::PLANES;
                }
                if stopped {
                    self.saved = None;
                    return None;
                }
                if let Some(tap) = tap {
                    tap.fed = true;
                }
                saved.marks = marks;
                stats.resumes += F::PLANES;
            }
            None => {
                let (frames, marks) = dissection
                    .capture_order_since(None)
                    .expect("a walk with nothing remembered has nothing to disagree with");
                if let Some(p) = progress {
                    p.expect(frames.iter().len() as u64 * F::PLANES);
                }
                // The walk takes every message held, which is what a reader that
                // wants everything reads.
                let mut tap = share.filter(|s| matches!(s.wanted, Wanted::Everything));
                let mut fold = begin();
                for (flow, list, packet, frame) in frames {
                    if !steps(progress, F::PLANES) {
                        return None;
                    }
                    fold.feed(&flow, list, packet, &frame, grouping);
                    if let Some(tap) = tap.as_deref_mut() {
                        (tap.tap)(&flow, list, packet, &frame);
                    }
                    stats.messages_folded += F::PLANES;
                }
                if let Some(tap) = tap {
                    tap.fed = true;
                }
                self.saved = Some(Saved {
                    fold,
                    grouping: grouping.clone(),
                    origin_ms,
                    marks,
                });
                stats.restarts += F::PLANES;
            }
        }
        self.saved.as_ref().map(|saved| &saved.fold)
    }
}

/// Which messages a [`Share`]'s reader wants from a call.
///
/// Built by the field document's pairing walk alone, so a build without it
/// constructs none and only reads the type.
#[cfg_attr(
    not(all(feature = "dissect", feature = "network-codecs")),
    allow(dead_code)
)]
pub(crate) enum Wanted<'m> {
    /// Every message the capture holds, in capture order.
    Everything,
    /// The messages after these marks, in capture order, taking front trims
    /// in its stride ([`Dissection::capture_order_since_across_trims`]).
    Since(&'m OrderMarks),
}

/// A second reader of one call's messages, fed by the walk a [`Resumable`]
/// makes when that walk takes exactly the messages it wants.
///
/// Open-debt item 924 (`docs/dissect-row-index.md`, D5): a list decodes a
/// message each time it is read, so two readers that read the same messages in
/// the same order in one call share one walk, the way the census planes do
/// ([`CensusFold`]). Their lives stay their own: the reader is fed only when the
/// fold's walk is, by its own rule, the walk the reader would have made; when it
/// is not, `fed` stays `false` and the reader walks on its own, as it always did.
#[cfg_attr(
    not(all(feature = "dissect", feature = "network-codecs")),
    allow(dead_code)
)]
pub(crate) struct Share<'m, 't> {
    pub(crate) wanted: Wanted<'m>,
    /// Takes one message: its flow, its list, the packet it resolves to, and
    /// the row, which says its produced-index.
    pub(crate) tap: &'t mut dyn FnMut(&FlowKey, usize, usize, &crate::messages::Row<'_>),
    /// Whether the walk fed the reader every message it wanted.
    pub(crate) fed: bool,
}

/// `n` steps of an optional [`Progress`], each asked in turn; `false` at the
/// first that says to stop.
fn steps(progress: Option<&Progress<'_>>, n: u64) -> bool {
    (0..n).all(|_| crate::progress::step(progress))
}

/// The selector-narrowed planes of a census document, folded by ONE walk.
///
/// Open-debt item 924 (`docs/dissect-row-index.md`, D6). Each plane was its own
/// fold over the whole capture, so a census walked the capture once per plane,
/// and once a list decodes a message each time it is read, that was each message
/// decoded once per plane. They are always asked together and each takes the
/// same messages in the same order, so one walk feeds them all: the tap model of
/// the reference dissector, where one pass over the capture serves every
/// listener. Each plane's fold is the one it always was.
#[derive(Debug, Clone)]
pub(crate) struct CensusFold {
    pub(crate) keyexprs: crate::agg::AggFold,
    #[cfg(feature = "network-codecs")]
    pub(crate) exchanges: crate::exchange::ExchangeFold,
    #[cfg(feature = "network-codecs")]
    pub(crate) payloads: crate::payload::PayloadFold,
    #[cfg(feature = "network-codecs")]
    pub(crate) interests: crate::interest::InterestFold,
}

impl CensusFold {
    /// Every plane empty, against `filter` and `grouping`.
    fn begin(
        dissection: &Dissection,
        filter: &crate::filter::Filter,
        grouping: &SessionGrouping,
    ) -> Self {
        Self {
            keyexprs: crate::agg::AggFold::begin(dissection, filter, grouping),
            #[cfg(feature = "network-codecs")]
            exchanges: crate::exchange::ExchangeFold::begin(dissection, filter, grouping),
            #[cfg(feature = "network-codecs")]
            payloads: crate::payload::PayloadFold::begin(dissection, filter, grouping),
            #[cfg(feature = "network-codecs")]
            interests: crate::interest::InterestFold::begin(),
        }
    }
}

impl OrderedFold for CensusFold {
    const PLANES: u64 = if cfg!(feature = "network-codecs") {
        4
    } else {
        1
    };

    fn feed(
        &mut self,
        flow: &FlowKey,
        list: usize,
        packet: usize,
        frame: &PassiveFrame,
        grouping: &SessionGrouping,
    ) {
        self.keyexprs.feed(flow, list, packet, frame, grouping);
        #[cfg(feature = "network-codecs")]
        {
            self.exchanges.feed(flow, list, packet, frame, grouping);
            self.payloads.feed(flow, list, packet, frame, grouping);
            self.interests.feed(flow, list, packet, frame, grouping);
        }
    }
}

/// The planes of a census document folded under ONE selector.
///
/// The selector is part of every fold's state (each judged its records against
/// it), so planes made under one selector are of no use under another.
#[derive(Debug, Default)]
struct SelectorPlanes {
    planes: Resumable<CensusFold>,
}

/// The planes of a census document, kept between calls for up to
/// [`Self::selector_memories`] selectors.
///
/// The selector is part of every fold's state, so each selector has its own
/// planes: asking under the same one continues them, and asking under another
/// one continues THAT one's. Only when more selectors are in use than there are
/// memories does the least recently used selector's planes go, and that selector
/// begins again the next time it is asked, which costs what it always cost.
/// One memory is the default, which is the behaviour before there were several:
/// asking under another selector starts every plane again.
///
/// The node census is shared by every selector, since no selector narrows it.
#[derive(Debug, Default)]
pub struct CensusMemory {
    /// The node census, which no selector narrows and so outlives a change of
    /// selector.
    nodes: crate::node::NodeMemory,
    /// The planes per selector, one slot unless raised.
    planes: BoundedSlots<crate::filter::Filter, SelectorPlanes>,
    stats: FoldStats,
}

/// What the resumable memories of the folds hold that follows the row count
/// (open-debt item 924, D7), by plane.
///
/// Only the planes that keep a verdict per row are named. The tables that follow
/// the count of keyexprs or nodes are not, for the reason
/// [`crate::DissectionMemory`] gives.
#[cfg(all(feature = "dissect", feature = "network-codecs"))]
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct FoldMemory {
    /// The payload plane's verdict for every record it judged.
    pub payload_rows: usize,
    /// The exchange plane's verdict for every row that ends an exchange, and the
    /// request each closing record closed.
    pub exchange_rows: usize,
    /// The digest the field walk keeps of every row it has written, by which a
    /// later call tells a row it must write again from one that has not changed.
    /// It grows with the rows a consumer has paged through, not with the window.
    pub row_digests: usize,
}

#[cfg(all(feature = "dissect", feature = "network-codecs"))]
impl FoldMemory {
    /// Every plane's bytes together.
    pub fn total(&self) -> usize {
        self.payload_rows + self.exchange_rows + self.row_digests
    }
}

#[cfg(all(feature = "dissect", feature = "network-codecs"))]
impl CensusMemory {
    /// What the memory holds that follows the row count, summed over the
    /// selectors it keeps planes for.
    pub fn memory(&self) -> FoldMemory {
        let mut memory = FoldMemory::default();
        for slot in self.planes.values() {
            if let Some(fold) = slot.planes.fold() {
                memory.payload_rows += fold.payloads.memory();
                memory.exchange_rows += fold.exchanges.memory();
                // A census keeps no digest of its rows: it is not a document of
                // rows a later call writes again.
            }
        }
        memory
    }
}

impl CensusMemory {
    /// A memory that has folded nothing.
    pub fn new() -> Self {
        Self::default()
    }

    /// How many selectors' planes this memory keeps at once.
    pub fn selector_memories(&self) -> usize {
        self.planes.capacity()
    }

    /// Keep the planes of up to `n` selectors at once, and return the number in
    /// effect: `n` held to `1..=`[`crate::MAX_SELECTOR_MEMORIES`]. Lowering it
    /// gives up the least recently used selectors' planes at once.
    pub fn set_selector_memories(&mut self, n: usize) -> usize {
        self.planes.set_capacity(n)
    }

    /// How many selectors hold planes now.
    pub fn selectors_in_use(&self) -> usize {
        self.planes.len()
    }

    /// How many selectors' planes have been given up to make room.
    pub fn selector_evictions(&self) -> u64 {
        self.planes.evicted()
    }

    /// The work this memory has done since it was made.
    pub fn stats(&self) -> FoldStats {
        self.stats
    }

    /// The work the node census inside this memory has done.
    pub fn node_stats(&self) -> crate::node::NodeStats {
        self.nodes.stats()
    }

    /// The node census, brought up to `dissection`.
    pub(crate) fn node_census(&mut self, dissection: &Dissection) -> crate::node::NodeCensus {
        self.nodes.nodes(dissection)
    }

    /// Make the memory the one for `filter`: the planes this selector already has
    /// are continued, and a selector with none gets empty ones, taking the place of
    /// the least recently used selector's when every memory is in use. The node
    /// census is kept, since no selector narrows it.
    pub(crate) fn for_filter(&mut self, filter: &crate::filter::Filter) {
        self.planes.touch(filter, SelectorPlanes::default);
    }

    /// The selector last asked under, its planes, and the work counter. The
    /// identity selector's planes are made when nothing has been asked yet.
    fn current(&mut self) -> (crate::filter::Filter, &mut SelectorPlanes, &mut FoldStats) {
        if self.planes.is_empty() {
            self.planes
                .touch(&crate::filter::Filter::any(), SelectorPlanes::default);
        }
        let Self { planes, stats, .. } = self;
        let (filter, planes) = planes
            .newest_mut()
            .expect("a plane was made above when there was none");
        (filter.clone(), planes, stats)
    }

    /// The selector-narrowed planes, brought up to `dissection` by one walk, or
    /// `None` when `progress` stopped the fold.
    pub(crate) fn planes(
        &mut self,
        dissection: &Dissection,
        grouping: &SessionGrouping,
        progress: Option<&Progress<'_>>,
    ) -> Option<&CensusFold> {
        let (filter, planes, stats) = self.current();
        planes
            .planes
            .advance(dissection, grouping, stats, progress, || {
                CensusFold::begin(dissection, &filter, grouping)
            })
    }
}
