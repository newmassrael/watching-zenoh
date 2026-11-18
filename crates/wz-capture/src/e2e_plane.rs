// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The end-to-end judge on the PAYLOAD PLANE: the one place a published
//! sample's frame is judged, which a selector's `e2e` terms and the field
//! document's `e2e` block both read.
//!
//! # Why the plane judges, and in capture order
//!
//! A selector's verdict on a `Push` is the payload plane's
//! ([`crate::payload::PayloadFold`]), and a frame's verdict is a fact about the
//! frames of its slot BEFORE it ([`crate::e2e_slots`]). So the plane judges
//! every sample a profile rule covers as it walks, in the order it walks:
//! capture order over the whole capture, the order the frames reached the tap.
//! A slot whose frames are spread over two flows (one sender and key over two
//! connections, or a slot that pools its senders over two connections) is
//! therefore judged in the order a receiver meeting them would judge them, and
//! not one flow and then the other.
//!
//! # One judgement, read by every document
//!
//! The judge keeps what it made of each sample ([`Judged`]) by the record that
//! carried it: its list, its row's produced-index and its place in the row's
//! batch ([`E2eJudgements`]). That key is the record's own coordinate, the one
//! the exchange plane and the field document already pair a record by, so a
//! reader finds the judgement of a record it is writing without a counter of
//! its own. The field document writes its block from the outcome kept there;
//! a selector reads the words. A live handle keeps one judge per declaration
//! text (`E2eMemory`) and hands its judgements to both; a document read once
//! makes its own over the whole capture (`judge_capture`).
//!
//! # The rules are copied, and kept with the fold
//!
//! A fold is kept between calls, and the declarations a call reads are text of
//! that call. The plane therefore keeps an owned copy of what judging needs
//! ([`JudgingRules`]): every rule's pattern in the order a key is tried, with
//! the profile of each profile rule, and the segment rules. The rule a key
//! falls to is found by the same function the declarations find it by
//! ([`crate::payload::formats::first_covering`]), so the copy cannot win a key
//! for another rule.
//!
//! # A piece first, then a frame
//!
//! As the field document reads a payload: a payload a segment rule's profile
//! recognises is a piece of a message and never a frame. A piece that completes
//! its message hands the joined message to the judge under the key, at the
//! piece's instant; a piece that completes none carries no frame, and reads
//! `none`.
//!
//! # A reply as the field document reads it
//!
//! A `Reply` carrying a `put` is read too, by the rule its own key falls to:
//! its pieces join a stream of their own per query, its frame's CRC and length
//! are judged and its counter and timeout are not (they read `unjudged`, the
//! block's `unjudged_reason` `reply`), and no slot moves for it. A query's
//! `ResponseFinal` lets go of its reply streams (`E2eJudging::close`).

use alloc::boxed::Box;
use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;

use wz_session_core::sorted_chunks::SortedChunks;

use crate::e2e_profile::Profile;
use crate::e2e_slots::{
    read_unjudged, Outcome, Reception, SlotLedger, SlotSender, Unjudged, UNREADABLE_PAYLOAD,
};
use crate::e2e_words::E2eWords;
use crate::payload::formats::{first_covering, first_segment_covering, SegmentKey};
use crate::segment_chain::{Carrier, KeyRef, SegmentLedger};
use crate::segment_profile::SegmentProfile;

/// What judging a sample end to end needs of a declaration text, owned: see
/// the module's note. Made by
/// [`FormatMap::judging_rules`](crate::payload::formats::FormatMap::judging_rules).
#[derive(Debug, Clone, Default)]
pub(crate) struct JudgingRules {
    /// Every format rule's pattern, in the order a key is tried, and the
    /// profile of each one whose target is a profile.
    rules: Vec<(String, Option<Profile>)>,
    /// The segment rules' patterns and profiles, in the order declared.
    segments: Vec<(String, SegmentProfile)>,
}

impl JudgingRules {
    pub(crate) fn new(
        rules: Vec<(String, Option<Profile>)>,
        segments: Vec<(String, SegmentProfile)>,
    ) -> Self {
        Self { rules, segments }
    }

    /// The profile of the rule `keyexpr` falls to, or `None` when that rule is
    /// not a profile rule or no rule covers the key.
    fn profile_for(&self, keyexpr: &str) -> Option<&Profile> {
        let at = first_covering(self.rules.iter().map(|(p, _)| p.as_str()), keyexpr)?;
        self.rules[at].1.as_ref()
    }

    /// The profile of the segment rule that covers `key`.
    fn segment_for(&self, key: SegmentKey<'_>) -> Option<&SegmentProfile> {
        let at = first_segment_covering(self.segments.iter().map(|(p, _)| p.as_str()), key)?;
        Some(&self.segments[at].1)
    }

    /// Whether any rule binds a key to a profile.
    fn judges_frames(&self) -> bool {
        self.rules.iter().any(|(_, profile)| profile.is_some())
    }
}

/// One published sample, as the plane hands it to the judge.
#[derive(Debug, Clone, Copy)]
pub(crate) struct Sample<'a> {
    /// The message list it came from, which keys a piece's stream.
    pub(crate) list: usize,
    /// The produced-index of the row that carried it in that list.
    pub(crate) produced: u64,
    /// Its place in that row's batch, from 0.
    pub(crate) record: u32,
    /// The key it is read under: the wire's, or the key a declaration fixed for
    /// an id the wire did not answer; `None` when neither did.
    pub(crate) keyexpr: Option<&'a str>,
    /// The id and suffix of a reference neither answered.
    pub(crate) missed: Option<(u64, Option<&'a str>)>,
    /// The payload as carried.
    pub(crate) payload: &'a [u8],
    /// The payload rides elsewhere (shared memory): the bytes above are a
    /// descriptor, not the sample.
    pub(crate) elsewhere: bool,
    /// The zid of the direction it travelled, when the capture named it.
    pub(crate) sender: Option<&'a [u8]>,
    /// The capture's instant for its packet, in nanoseconds.
    pub(crate) observed_at_ns: Option<u64>,
    /// Whether it travelled from the half of its list named first.
    pub(crate) from_low: bool,
    /// What carried it: a published sample, judged against its slot, or a
    /// reply to a query, whose frame is read and whose counter is not judged.
    pub(crate) carrier: Carrier,
}

/// What the judge made of one sample.
///
/// The outcome is read by the field document, which only a build with the
/// field layer has.
#[cfg_attr(not(feature = "dissect"), allow(dead_code))]
#[derive(Debug, Clone)]
pub(crate) struct Judged {
    /// The words a selector's `e2e` terms read; `None` where whether a profile
    /// rule covers the sample cannot be decided (its key did not resolve).
    pub(crate) words: Option<E2eWords>,
    /// The frame's outcome, which the field document writes its block from;
    /// `None` for a sample that carried no frame a profile rule covers (no such
    /// rule, a piece that completed nothing, a key that did not resolve).
    pub(crate) outcome: Option<Outcome>,
}

#[cfg_attr(not(feature = "dissect"), allow(dead_code))]
impl Judged {
    /// A sample no profile rule judges.
    const NONE: Self = Self {
        words: Some(E2eWords::NONE),
        outcome: None,
    };

    /// A sample whose key did not resolve, so no rule can be said to cover it.
    const UNDECIDED: Self = Self {
        words: None,
        outcome: None,
    };

    /// A frame the judge read, and its outcome.
    fn frame(outcome: Outcome) -> Self {
        Self {
            words: Some(E2eWords::of(&outcome)),
            outcome: Some(outcome),
        }
    }

    /// Bytes the outcome owns on the heap, allocated: the opened frame's box,
    /// its header fields and its slot. The names of a slot's message fields are
    /// the profile's and are not counted, so this is a lower bound.
    fn heap_bytes(&self) -> usize {
        use wz_session_core::heap_account::vec_bytes;
        let Some(Outcome::Opened(opened)) = &self.outcome else {
            return 0;
        };
        let sender = match &opened.slot.sender {
            SlotSender::Zid(zid) => vec_bytes(zid),
            SlotSender::Pooled | SlotSender::Unknown => 0,
        };
        core::mem::size_of::<crate::e2e_slots::Opened>()
            + vec_bytes(&opened.frame.fields)
            + opened.slot.keyexpr.capacity()
            + vec_bytes(&opened.slot.identity)
            + sender
    }
}

/// Every judgement the plane made, by the record that carried it: its list,
/// its row's produced-index and its place in the row's batch.
#[derive(Debug, Clone, Default)]
pub struct E2eJudgements {
    /// Whether a profile rule binds any key. With none, every sample reads
    /// `none` and nothing is kept.
    judges_frames: bool,
    kept: SortedChunks<(usize, u64, u32), Judged>,
}

/// The judgements a judge keeps, shared with the readers of one call.
///
/// Shared and not copied: a reader holds it for the call that reads it and lets
/// go, so the judge is its only holder when it next grows and adds to it in
/// place.
pub type E2eTable = Arc<E2eJudgements>;

// What a handle reports and trims is read by the field layer's builds only.
#[cfg_attr(not(feature = "dissect"), allow(dead_code))]
impl E2eJudgements {
    /// What was judged of the record at place `record` of the row `produced` of
    /// the list at `list`, when the judge met it.
    pub(crate) fn get(&self, list: usize, produced: u64, record: u32) -> Option<&Judged> {
        self.kept.get(&(list, produced, record))
    }

    /// The words of that record's sample; `none` when no profile rule binds
    /// any key, and undecided when the judge kept nothing for it.
    pub(crate) fn words(&self, list: usize, produced: u64, record: u32) -> Option<E2eWords> {
        if !self.judges_frames {
            return Some(E2eWords::NONE);
        }
        self.get(list, produced, record)
            .and_then(|judged| judged.words)
    }

    /// How many samples have a judgement kept.
    pub fn len(&self) -> usize {
        self.kept.len()
    }

    /// Whether no sample has a judgement kept.
    pub fn is_empty(&self) -> bool {
        self.kept.is_empty()
    }

    /// Bytes the judgements hold, allocated: the sorted chunks they are kept in
    /// and what each outcome owns. It follows the samples a profile rule covers
    /// in the rows the lists hold.
    pub fn memory(&self) -> usize {
        self.kept.allocated_bytes() + self.kept.values().map(Judged::heap_bytes).sum::<usize>()
    }

    fn keep(&mut self, sample: &Sample<'_>, judged: Judged) {
        let _ = self
            .kept
            .insert((sample.list, sample.produced, sample.record), judged);
    }

    /// Let go of the judgements of the rows of the list at `list` older than
    /// `first_held`, which no reader can ask for again.
    fn forget_before(&mut self, list: usize, first_held: u64) {
        self.kept
            .retain(|&(at, produced, _), _| at != list || produced >= first_held);
    }
}

/// Where a walk's `e2e` terms read a sample's verdict.
pub(crate) enum E2eReading<'j> {
    /// From the judge, which the walk hands every sample in the order it
    /// meets it.
    Judge(&'j mut E2eJudging),
    /// From the judge, by a walk that counts nothing else.
    JudgeOnly(&'j mut E2eJudging),
    /// From the judgements a judge of the whole capture already made.
    Read(&'j E2eJudgements),
}

impl<'j> E2eReading<'j> {
    /// The same reading, for one record of a batch: each arm hands on a
    /// reborrow of what `self` holds for the borrow of `self`, which the
    /// coercion of `&mut &mut` to `&mut` makes, so `self` keeps its reference.
    pub(crate) fn reborrow(&mut self) -> E2eReading<'_> {
        match self {
            Self::Judge(judge) => E2eReading::Judge(judge),
            Self::JudgeOnly(judge) => E2eReading::JudgeOnly(judge),
            Self::Read(table) => E2eReading::Read(table),
        }
    }

    /// Whether the walk counts nothing but the judgement.
    pub(crate) fn judges_only(&self) -> bool {
        matches!(self, Self::JudgeOnly(_))
    }

    /// The judge, when this reading is one: what lets go of a query's replies
    /// at its final.
    pub(crate) fn judge(self) -> Option<&'j mut E2eJudging> {
        match self {
            Self::Judge(judge) | Self::JudgeOnly(judge) => Some(judge),
            Self::Read(_) => None,
        }
    }

    /// The words of `sample`: judged now, or read from what was judged.
    pub(crate) fn read(self, sample: Sample<'_>) -> Option<E2eWords> {
        match self {
            Self::Judge(judge) | Self::JudgeOnly(judge) => judge.judge(sample),
            Self::Read(table) => table.words(sample.list, sample.produced, sample.record),
        }
    }
}

/// The judging a payload plane keeps while it folds: the rules, the state of
/// every slot and every stream of pieces it has met, and what it made of
/// every sample.
#[derive(Debug, Clone)]
pub(crate) struct E2eJudging {
    rules: JudgingRules,
    frames: SlotLedger,
    pieces: SegmentLedger,
    kept: E2eTable,
}

impl E2eJudging {
    /// A judging that has met no sample.
    pub(crate) fn new(rules: JudgingRules) -> Self {
        let judges_frames = rules.judges_frames();
        Self {
            rules,
            frames: SlotLedger::new(),
            pieces: SegmentLedger::new(),
            kept: Arc::new(E2eJudgements {
                judges_frames,
                kept: SortedChunks::new(),
            }),
        }
    }

    /// What it made of every sample it met, by record.
    #[cfg(feature = "dissect")]
    pub(crate) fn judgements(&self) -> &E2eTable {
        &self.kept
    }

    /// Let go of the judgements of the rows no list of `dissection` holds any
    /// more, once they outnumber what the lists hold by a margin, so a call
    /// does not pass over every judgement for the sake of a few rows.
    #[cfg(feature = "dissect")]
    pub(crate) fn forget_not_held(&mut self, dissection: &crate::Dissection) {
        let held: usize = dissection
            .message_lists_with_origin()
            .map(|(_, _, list)| list.len())
            .sum();
        if self.kept.len() <= 4 * held + 1024 {
            return;
        }
        let kept = Arc::make_mut(&mut self.kept);
        for (at, (_, _, list)) in dissection.message_lists_with_origin().enumerate() {
            kept.forget_before(at, list.produced() - list.len() as u64);
        }
    }

    /// Let go of the streams of the replies to the query `request` on `list`,
    /// at its `ResponseFinal`, which travelled as `from_low` says. What it ends
    /// unfinished is the field document's to state; here nothing is said of it.
    pub(crate) fn close(&mut self, list: usize, from_low: bool, request: u64) {
        let _ = self.pieces.close(list, Some(from_low), request);
    }

    /// Judge one sample (a `Push` or a `Reply` carrying a `put`), in the order
    /// the plane meets them, keep what it made of it, and say what the selector
    /// reads of it; `None` where whether a rule covers it cannot be decided
    /// (its key did not resolve).
    pub(crate) fn judge(&mut self, sample: Sample<'_>) -> Option<E2eWords> {
        if !self.rules.judges_frames() {
            return Some(E2eWords::NONE);
        }
        let judged = self.judged(&sample);
        let words = judged.words;
        Arc::make_mut(&mut self.kept).keep(&sample, judged);
        words
    }

    /// What one sample comes to: a piece, a frame, or neither.
    fn judged(&mut self, sample: &Sample<'_>) -> Judged {
        if let Some(piece) = self.piece(sample) {
            return piece;
        }
        let Some(keyexpr) = sample.keyexpr else {
            return Judged::UNDECIDED;
        };
        let payload = (!sample.elsewhere).then_some(sample.payload);
        self.frame(keyexpr, payload, sample)
    }

    /// The judgement of a sample a segment rule's profile recognises as a
    /// piece, or `None` for one that is not a piece.
    fn piece(&mut self, sample: &Sample<'_>) -> Option<Judged> {
        if self.rules.segments.is_empty() || sample.elsewhere {
            return None;
        }
        let (covering, key) = match (sample.keyexpr, sample.missed) {
            (Some(keyexpr), _) => (
                SegmentKey::Resolved(keyexpr),
                KeyRef::Resolved(keyexpr.into()),
            ),
            (None, Some((id, suffix))) => (
                SegmentKey::Unresolved,
                KeyRef::Unresolved {
                    id,
                    suffix: suffix.map(Box::from),
                },
            ),
            (None, None) => return None,
        };
        let profile = self.rules.segment_for(covering)?;
        let piece = profile.recognise(sample.payload)?;
        let verdict = self.pieces.receive(
            profile,
            &piece,
            sample.list,
            Some(sample.from_low),
            key,
            sample.carrier,
        );
        Some(match (verdict.joined, sample.keyexpr) {
            // The message it completed, judged at this piece's instant.
            (Some(joined), Some(keyexpr)) => self.frame(keyexpr, Some(&*joined), sample),
            // A message completed under a key that did not resolve: whether a
            // profile rule covers it is not known.
            (Some(_), None) => Judged::UNDECIDED,
            // A piece that completes nothing carries no frame.
            (None, _) => Judged::NONE,
        })
    }

    /// Judge one frame under the rule `keyexpr` falls to.
    fn frame(&mut self, keyexpr: &str, payload: Option<&[u8]>, sample: &Sample<'_>) -> Judged {
        let Some(profile) = self.rules.profile_for(keyexpr) else {
            return Judged::NONE;
        };
        let outcome = match payload {
            Some(payload) => {
                let reception = Reception {
                    profile,
                    keyexpr,
                    payload,
                    sender: sample.sender,
                    observed_at_ns: sample.observed_at_ns,
                };
                match sample.carrier {
                    Carrier::Push => self.frames.receive_from(sample.list, &reception),
                    // As the field document reads a reply: no slot moves.
                    Carrier::Reply { .. } => read_unjudged(&reception, Unjudged::Reply),
                }
            }
            None => Outcome::Unreadable {
                why: UNREADABLE_PAYLOAD,
            },
        };
        Judged::frame(outcome)
    }
}

/// The judgements of every frame of `dissection` under `map`, for a document
/// read once: one walk of the payload plane in capture order, judging and
/// counting nothing else. `grouping` is the session grouping the document reads
/// senders by.
#[cfg(feature = "dissect")]
pub(crate) fn judge_capture(
    dissection: &crate::Dissection,
    grouping: &crate::node::SessionGrouping,
    map: &crate::payload::formats::FormatMap<'_>,
) -> E2eTable {
    let mut fold = crate::payload::PayloadFold::judging_everything(dissection, grouping, map);
    crate::ordered_fold::fold_whole_capture(&mut fold, dissection, grouping);
    fold.judgements().cloned().unwrap_or_default()
}

/// THE JUDGE OF A LIVE HANDLE'S FRAMES, kept between calls for one declaration
/// text, whose judgements every door of the handle that shows a verdict reads:
/// the field documents' blocks and the selection documents' `e2e` terms.
///
/// It is the payload plane's walk in capture order, continued as the capture
/// grows and going on across a front trim, because a
/// counter is a fact about every frame before it and a frame a ceiling has
/// since taken was still met. It counts nothing but the judgement. Another
/// declaration text begins it again.
#[cfg(feature = "dissect")]
#[derive(Debug, Default)]
pub struct E2eMemory {
    /// The declaration text the judgements are for.
    key: Option<String>,
    fold: crate::ordered_fold::Resumable<crate::payload::PayloadFold>,
    nodes: crate::node::NodeMemory,
    stats: crate::FoldStats,
}

#[cfg(feature = "dissect")]
impl E2eMemory {
    /// A judge that has met nothing.
    pub fn new() -> Self {
        Self::default()
    }

    /// The judgements of every frame of `dissection` under `map`, declared from
    /// `text`, judging only the messages that arrived since the last call when
    /// it may. `None` when `progress` stopped the walk; the next call begins it
    /// again.
    ///
    /// A text with no profile rule judges nothing and keeps nothing.
    pub fn advance(
        &mut self,
        dissection: &crate::Dissection,
        map: &crate::payload::formats::FormatMap<'_>,
        text: &str,
        progress: Option<&crate::Progress<'_>>,
    ) -> Option<E2eTable> {
        if !map.has_e2e_rules() {
            self.key = None;
            self.fold = crate::ordered_fold::Resumable::default();
            return Some(E2eTable::default());
        }
        if self.key.as_deref() != Some(text) {
            self.key = Some(String::from(text));
            self.fold = crate::ordered_fold::Resumable::default();
        }
        let grouping = crate::node::SessionGrouping::of(&self.nodes.nodes_across_trims(dissection));
        self.fold.advance_across_trims(
            dissection,
            &grouping,
            &mut self.stats,
            progress,
            || crate::payload::PayloadFold::judging_everything(dissection, &grouping, map),
            None,
        )?;
        let fold = self.fold.fold_mut()?;
        fold.forget_judged_not_held(dissection);
        fold.judgements().cloned()
    }

    /// Bytes the judgements hold ([`E2eJudgements::memory`]); the slots' and
    /// the streams' state follows the count of slots and streams and is not
    /// counted.
    pub fn memory(&self) -> usize {
        self.fold
            .fold()
            .and_then(crate::payload::PayloadFold::judgements)
            .map_or(0, |judged| judged.memory())
    }

    /// The messages the judge has folded and the times it began again.
    pub fn stats(&self) -> crate::FoldStats {
        self.stats
    }
}
