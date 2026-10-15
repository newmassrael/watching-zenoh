// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
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
use crate::{Dissection, OrderMarks};
use wz_session_core::passive::PassiveFrame;

/// What a plane keeps while it folds a capture in capture order.
pub(crate) trait OrderedFold: Clone {
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
        let origin_ms = dissection.capture_origin_ms();
        let resumed = match &self.saved {
            Some(s) if s.grouping == *grouping && s.origin_ms == origin_ms => {
                dissection.capture_order_since(Some(&s.marks))
            }
            _ => None,
        };
        match resumed {
            Some((frames, marks)) => {
                if let Some(p) = progress {
                    p.expect(frames.len() as u64);
                }
                let saved = self.saved.as_mut().expect("a resumed fold has a saved one");
                let mut stopped = false;
                for (flow, list, packet, frame) in frames {
                    if !crate::progress::step(progress) {
                        stopped = true;
                        break;
                    }
                    saved.fold.feed(&flow, list, packet, frame, grouping);
                    stats.messages_folded += 1;
                }
                if stopped {
                    self.saved = None;
                    return None;
                }
                saved.marks = marks;
                stats.resumes += 1;
            }
            None => {
                let (frames, marks) = dissection
                    .capture_order_since(None)
                    .expect("a walk with nothing remembered has nothing to disagree with");
                if let Some(p) = progress {
                    p.expect(frames.len() as u64);
                }
                let mut fold = begin();
                for (flow, list, packet, frame) in frames {
                    if !crate::progress::step(progress) {
                        return None;
                    }
                    fold.feed(&flow, list, packet, frame, grouping);
                    stats.messages_folded += 1;
                }
                self.saved = Some(Saved {
                    fold,
                    grouping: grouping.clone(),
                    origin_ms,
                    marks,
                });
                stats.restarts += 1;
            }
        }
        self.saved.as_ref().map(|saved| &saved.fold)
    }
}

/// The planes of a census document folded under ONE selector.
///
/// The selector is part of every fold's state (each judged its records against
/// it), so planes made under one selector are of no use under another.
#[derive(Debug, Default)]
struct SelectorPlanes {
    keyexprs: Resumable<crate::agg::AggFold>,
    #[cfg(feature = "network-codecs")]
    exchanges: Resumable<crate::exchange::ExchangeFold>,
    #[cfg(feature = "network-codecs")]
    payloads: Resumable<crate::payload::PayloadFold>,
    #[cfg(feature = "network-codecs")]
    interests: Resumable<crate::interest::InterestFold>,
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

    /// The keyexpr plane, brought up to `dissection`, or `None` when `progress`
    /// stopped the fold.
    pub(crate) fn keyexprs(
        &mut self,
        dissection: &Dissection,
        grouping: &SessionGrouping,
        progress: Option<&Progress<'_>>,
    ) -> Option<crate::agg::ThroughputTable> {
        let (filter, planes, stats) = self.current();
        Some(
            planes
                .keyexprs
                .advance(dissection, grouping, stats, progress, || {
                    crate::agg::AggFold::begin(dissection, &filter, grouping)
                })?
                .table(),
        )
    }

    /// The exchange plane, brought up to `dissection`, or `None` when `progress`
    /// stopped the fold.
    #[cfg(feature = "network-codecs")]
    pub(crate) fn exchanges(
        &mut self,
        dissection: &Dissection,
        grouping: &SessionGrouping,
        progress: Option<&Progress<'_>>,
    ) -> Option<crate::exchange::ExchangeTable> {
        let (filter, planes, stats) = self.current();
        Some(
            planes
                .exchanges
                .advance(dissection, grouping, stats, progress, || {
                    crate::exchange::ExchangeFold::begin(dissection, &filter, grouping)
                })?
                .table(),
        )
    }

    /// The payload plane, brought up to `dissection`, or `None` when `progress`
    /// stopped the fold.
    #[cfg(feature = "network-codecs")]
    pub(crate) fn payloads(
        &mut self,
        dissection: &Dissection,
        grouping: &SessionGrouping,
        progress: Option<&Progress<'_>>,
    ) -> Option<crate::payload::PayloadCensus> {
        let (filter, planes, stats) = self.current();
        Some(
            planes
                .payloads
                .advance(dissection, grouping, stats, progress, || {
                    crate::payload::PayloadFold::begin(dissection, &filter, grouping)
                })?
                .census(),
        )
    }

    /// The interest plane, brought up to `dissection`, or `None` when `progress`
    /// stopped the fold.
    #[cfg(feature = "network-codecs")]
    pub(crate) fn interests(
        &mut self,
        dissection: &Dissection,
        grouping: &SessionGrouping,
        progress: Option<&Progress<'_>>,
    ) -> Option<crate::interest::InterestCensus> {
        let (_filter, planes, stats) = self.current();
        Some(
            planes
                .interests
                .advance(
                    dissection,
                    grouping,
                    stats,
                    progress,
                    crate::interest::InterestFold::begin,
                )?
                .census(),
        )
    }
}
