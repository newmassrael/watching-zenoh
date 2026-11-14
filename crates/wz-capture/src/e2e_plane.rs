// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The end-to-end judge on the PAYLOAD PLANE: what a selector's `e2e` terms
//! read a published sample by.
//!
//! # Why the plane judges, and in capture order
//!
//! A selector's verdict on a `Push` is the payload plane's
//! ([`crate::payload::PayloadFold`]), and a frame's verdict is a fact about the
//! frames of its slot BEFORE it ([`crate::e2e_slots`]). So the plane judges
//! every sample a profile rule covers as it walks, in the order it walks:
//! capture order over the whole capture, the order the frames reached the tap.
//! The judgement is the same library the field document's block is written
//! from, the same profile read at the same offsets, the same slot and the same
//! counter judge; [`crate::e2e_words`] turns its outcome into the words.
//!
//! The field document still walks one flow at a time, so for a slot whose
//! frames are spread over two flows (one sender and key over two connections)
//! the document's block and this plane's words can part over the frames of the
//! second flow: the block judges them flow by flow, this plane in time order.
//! Within one flow they are one sequence.
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

use alloc::boxed::Box;
use alloc::string::String;
use alloc::vec::Vec;

use crate::e2e_profile::Profile;
use crate::e2e_slots::{Outcome, Reception, SlotLedger, UNREADABLE_PAYLOAD};
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
}

/// The judging a payload plane keeps while it folds: the rules and the state
/// of every slot and every stream of pieces it has met.
#[derive(Debug, Clone)]
pub(crate) struct E2eJudging {
    rules: JudgingRules,
    frames: SlotLedger,
    pieces: SegmentLedger,
}

impl E2eJudging {
    /// A judging that has met no sample.
    pub(crate) fn new(rules: JudgingRules) -> Self {
        Self {
            rules,
            frames: SlotLedger::new(),
            pieces: SegmentLedger::new(),
        }
    }

    /// Judge one published sample (a `Push` carrying a `put`), in the order the
    /// plane meets them, and say what the selector reads of it; `None` where
    /// whether a rule covers it cannot be decided (its key did not resolve).
    pub(crate) fn judge(&mut self, sample: Sample<'_>) -> Option<E2eWords> {
        if !self.rules.judges_frames() {
            return Some(E2eWords::NONE);
        }
        if let Some(piece) = self.piece(&sample) {
            return piece;
        }
        let keyexpr = sample.keyexpr?;
        let payload = (!sample.elsewhere).then_some(sample.payload);
        Some(self.frame(keyexpr, payload, &sample))
    }

    /// The answer for a sample a segment rule's profile recognises as a piece,
    /// or `None` for one that is not a piece.
    fn piece(&mut self, sample: &Sample<'_>) -> Option<Option<E2eWords>> {
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
        // Only published samples reach this plane (`is_published_sample`).
        let verdict = self.pieces.receive(
            profile,
            &piece,
            sample.list,
            Some(sample.from_low),
            key,
            Carrier::Push,
        );
        Some(match (verdict.joined, sample.keyexpr) {
            // The message it completed, judged at this piece's instant.
            (Some(joined), Some(keyexpr)) => Some(self.frame(keyexpr, Some(&*joined), sample)),
            // A message completed under a key that did not resolve: whether a
            // profile rule covers it is not known.
            (Some(_), None) => None,
            // A piece that completes nothing carries no frame.
            (None, _) => Some(E2eWords::NONE),
        })
    }

    /// Judge one frame under the rule `keyexpr` falls to.
    fn frame(&mut self, keyexpr: &str, payload: Option<&[u8]>, sample: &Sample<'_>) -> E2eWords {
        let Some(profile) = self.rules.profile_for(keyexpr) else {
            return E2eWords::NONE;
        };
        let outcome = match payload {
            Some(payload) => self.frames.receive_from(
                sample.list,
                &Reception {
                    profile,
                    keyexpr,
                    payload,
                    sender: sample.sender,
                    observed_at_ns: sample.observed_at_ns,
                },
            ),
            None => Outcome::Unreadable {
                why: UNREADABLE_PAYLOAD,
            },
        };
        E2eWords::of(&outcome)
    }
}
