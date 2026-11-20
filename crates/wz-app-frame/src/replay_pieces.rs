// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The pieces a subscriber of a segmented message receives, joined into the frames they cut.
//!
//! A message whose frames are larger than a deployment puts in one sample is sent as the pieces of
//! a declared segment profile ([`crate::segment_profile`]), live and in the answer of a replay
//! alike (the `replay-reply-shape = segmented` policy). Before a frame can be admitted to the
//! receiving judge ([`crate::replay_admission`]) and judged, its pieces are joined, with the
//! joining state every reader of such pieces uses ([`crate::segment_chain`]):
//!
//! * the live samples are one stream, and the replies to each query another: a responder numbers
//!   the transfers of an answer apart from the ones it publishes, so the two never end each
//!   other's;
//! * a transfer is one frame. A piece of the next transfer ends the one before it, joined or not:
//!   a frame one of whose pieces never came is given up ([`PieceJoiner::abandoned`]) and the frames
//!   around it are joined all the same;
//! * a query's final ends its stream ([`PieceJoiner::close`]); what was still open there is given
//!   up the same way.
//!
//! A payload that is not a piece of the profile, or whose CRC is wrong, or that cannot be placed,
//! joins nothing and is counted ([`PieceJoiner::unjoined`]).
//!
//! # How a responder numbers its answers is its own
//!
//! A responder may number the transfers of every answer from the same first number, or go on from
//! where its previous answer stopped, as wz's own replay cache does. The joining reads neither,
//! and accepts both alike, by these rules:
//!
//! * the replies to each query are a stream of their own, under the number the caller gives the
//!   query, never under the transfer numbers: a number one answer used, completed or still open,
//!   never meets the same number in another answer;
//! * within one answer a piece whose number differs from the transfer being joined starts the next
//!   transfer, whatever the number is: one more, a jump, a step back or a wrap of the field alike.
//!   No first number is expected, and none is refused;
//! * a frame that two answers both carry is one frame, under whatever number each gave it: the
//!   receiving judge tells it by its counter ([`crate::replay_admission`]) and drops it as a
//!   duplicate or as stale, so it is never judged twice, and never dropped for its number.
//!
//! What the stream of one query cannot tell apart is two responders answering it with pieces whose
//! `stream` fields agree (a get asked of every publisher at once): their transfers then share one
//! stream, and the numbering decides only how they spoil each other. A segment profile keeps
//! responders apart by a `stream` field each sender draws for itself.

use alloc::string::String;
use alloc::sync::Arc;

use crate::e2e_profile::DocError;
use crate::segment_chain::{Carrier, KeyRef, SegmentLedger};
use crate::segment_profile::SegmentProfile;

/// What one payload did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Joined {
    /// It completed a frame: the whole of it.
    Frame(Arc<[u8]>),
    /// It is a piece of a frame not yet complete.
    Pending,
    /// It joins nothing: not a piece of the profile, a CRC that does not match, or a place that
    /// does not fit.
    Unjoined,
}

/// The joining of one subscriber's pieces, live and replied.
#[derive(Debug, Clone)]
pub struct PieceJoiner {
    profile: SegmentProfile,
    ledger: SegmentLedger,
    key: String,
    abandoned: u64,
    unjoined: u64,
}

impl PieceJoiner {
    /// A joiner of the pieces `profile_text` describes, received on `key`.
    ///
    /// # Errors
    ///
    /// The profile's refusal, with the place.
    pub fn new(profile_text: &str, key: &str) -> Result<Self, DocError> {
        Ok(Self {
            profile: SegmentProfile::parse(profile_text)?,
            ledger: SegmentLedger::new(),
            key: String::from(key),
            abandoned: 0,
            unjoined: 0,
        })
    }

    /// The profile the pieces are read by.
    pub fn profile(&self) -> &SegmentProfile {
        &self.profile
    }

    /// A live sample's payload.
    pub fn live(&mut self, payload: &[u8]) -> Joined {
        self.join(Carrier::Push, payload)
    }

    /// A reply's payload, to the query the caller numbers `request`.
    pub fn reply(&mut self, request: u64, payload: &[u8]) -> Joined {
        self.join(Carrier::Reply { request }, payload)
    }

    /// The query `request` ended: let go of its stream, giving up a frame it left open.
    pub fn close(&mut self, request: u64) {
        let ended = self.ledger.close(0, None, request);
        self.abandoned = self.abandoned.saturating_add(ended.len() as u64);
    }

    /// How many frames were given up with a piece missing.
    pub fn abandoned(&self) -> u64 {
        self.abandoned
    }

    /// How many payloads joined nothing.
    pub fn unjoined(&self) -> u64 {
        self.unjoined
    }

    fn join(&mut self, carrier: Carrier, payload: &[u8]) -> Joined {
        let Some(piece) = self.profile.recognise(payload) else {
            self.unjoined = self.unjoined.saturating_add(1);
            return Joined::Unjoined;
        };
        let verdict = self.ledger.receive(
            &self.profile,
            &piece,
            0,
            None,
            KeyRef::Resolved(self.key.clone()),
            carrier,
        );
        self.abandoned = self.abandoned.saturating_add(verdict.ended.len() as u64);
        if verdict.unjoined.is_some() {
            self.unjoined = self.unjoined.saturating_add(1);
            return Joined::Unjoined;
        }
        match verdict.joined {
            Some(frame) => Joined::Frame(frame),
            None => Joined::Pending,
        }
    }
}

#[cfg(test)]
mod tests {
    use alloc::vec::Vec;

    use super::*;
    use crate::e2e_frame::{build, Values};
    use crate::e2e_profile::Profile;
    use crate::e2e_receiver::{Keying, Receiver};
    use crate::replay_admission::{admit, Admission};
    use crate::segment_sender::{Rollover, SegmentSender};

    /// A one-byte mark, a stream field and a two-byte number, total and place: synthetic.
    const PROFILE: &str = r#"{"name":"replay-pieces","segments":{"fields":[
      {"name":"mark","bytes":1,"equals":"0x7E"},
      {"name":"source","bytes":2},
      {"name":"seq","bytes":2},
      {"name":"whole","bytes":2},
      {"name":"pos","bytes":2}],
      "stream":["source"],"transfer":"seq","total":"whole","offset":"pos","total_max":1024}}"#;
    const VALUES: &str = r#"{"source": 9}"#;
    const KEY: &str = "demo/pieces/one";

    fn frame(len: usize, seed: u8) -> Vec<u8> {
        (0..len).map(|i| (i as u8).wrapping_mul(7) ^ seed).collect()
    }

    /// The pieces of `frames`, cut at `chunk` bytes, transfers numbered from `first`.
    fn pieces(frames: &[&Vec<u8>], first: u64, chunk: usize) -> Vec<Vec<Vec<u8>>> {
        let mut sender =
            SegmentSender::new(PROFILE, VALUES, first, Rollover::Refuse).expect("valid");
        frames
            .iter()
            .map(|frame| {
                let mut out = Vec::new();
                sender
                    .split(frame, chunk, |piece| {
                        out.push(piece.to_vec());
                        Ok::<(), ()>(())
                    })
                    .expect("split");
                out
            })
            .collect()
    }

    fn joiner() -> PieceJoiner {
        PieceJoiner::new(PROFILE, KEY).expect("valid")
    }

    #[test]
    fn a_frame_larger_than_one_piece_is_joined_on_its_last_piece() {
        let whole = frame(20, 0x31);
        let cut = pieces(&[&whole], 1, 8);
        assert_eq!(cut[0].len(), 3);
        let mut j = joiner();
        assert_eq!(j.reply(4, &cut[0][0]), Joined::Pending);
        assert_eq!(j.reply(4, &cut[0][1]), Joined::Pending);
        assert_eq!(j.reply(4, &cut[0][2]), Joined::Frame(Arc::from(whole)));
        assert_eq!((j.abandoned(), j.unjoined()), (0, 0));
    }

    #[test]
    fn two_frames_under_advancing_transfer_numbers_are_each_joined() {
        let (a, b) = (frame(12, 1), frame(9, 2));
        let cut = pieces(&[&a, &b], 7, 5);
        let mut j = joiner();
        let mut got = Vec::new();
        for piece in cut.iter().flatten() {
            if let Joined::Frame(f) = j.reply(1, piece) {
                got.push(f.to_vec());
            }
        }
        assert_eq!(got, [a, b]);
        assert_eq!(j.abandoned(), 0);
    }

    /// A missing piece gives up its own frame and no other: the next transfer's first piece
    /// ends it, and the next frame joins.
    #[test]
    fn a_missing_piece_gives_up_that_frame_only() {
        let (a, b, c) = (frame(15, 3), frame(15, 4), frame(6, 5));
        let cut = pieces(&[&a, &b, &c], 1, 5);
        let mut j = joiner();
        let mut got = Vec::new();
        for (index, frame_pieces) in cut.iter().enumerate() {
            for (at, piece) in frame_pieces.iter().enumerate() {
                if index == 1 && at == 1 {
                    continue;
                }
                if let Joined::Frame(f) = j.reply(2, piece) {
                    got.push(f.to_vec());
                }
            }
        }
        assert_eq!(got, [a, c]);
        assert_eq!(j.abandoned(), 1);
    }

    #[test]
    fn the_replies_to_two_queries_and_the_live_stream_never_end_each_other() {
        let (a, b) = (frame(10, 6), frame(10, 7));
        let cut_a = pieces(&[&a], 1, 6);
        // The same transfer number on another stream: a live send and a second answer.
        let cut_b = pieces(&[&b], 1, 6);
        let mut j = joiner();
        assert_eq!(j.reply(1, &cut_a[0][0]), Joined::Pending);
        assert_eq!(j.live(&cut_b[0][0]), Joined::Pending);
        assert_eq!(j.reply(2, &cut_b[0][0]), Joined::Pending);
        assert_eq!(j.reply(1, &cut_a[0][1]), Joined::Frame(Arc::from(a)));
        assert_eq!(j.live(&cut_b[0][1]), Joined::Frame(Arc::from(b.clone())));
        assert_eq!(j.reply(2, &cut_b[0][1]), Joined::Frame(Arc::from(b)));
        assert_eq!(j.abandoned(), 0);
    }

    #[test]
    fn a_query_that_ends_with_a_frame_open_gives_it_up() {
        let whole = frame(12, 8);
        let cut = pieces(&[&whole], 1, 5);
        let mut j = joiner();
        assert_eq!(j.reply(3, &cut[0][0]), Joined::Pending);
        j.close(3);
        assert_eq!(j.abandoned(), 1);
        j.close(3);
        assert_eq!(j.abandoned(), 1, "a closed stream ends nothing again");
    }

    #[test]
    fn a_payload_that_is_no_piece_joins_nothing() {
        let mut j = joiner();
        assert_eq!(j.live(b"not a piece"), Joined::Unjoined);
        assert_eq!(j.reply(1, &[]), Joined::Unjoined);
        assert_eq!(j.unjoined(), 2);
        assert!(PieceJoiner::new("{}", KEY).is_err());
    }

    /// The pieces of `frames` as one answer sends them, cut at five bytes, its transfers numbered
    /// from `first`, in the order they go out.
    fn answer(frames: &[&Vec<u8>], first: u64) -> Vec<Vec<u8>> {
        pieces(frames, first, 5).into_iter().flatten().collect()
    }

    #[test]
    fn within_one_answer_any_new_number_starts_the_next_transfer() {
        let (a, b, c) = (frame(12, 9), frame(11, 10), frame(9, 11));
        // A jump, a step back and zero: each number new to the stream, so each a frame.
        let mut sent = Vec::new();
        for (whole, number) in [(&a, 40), (&b, 3), (&c, 0)] {
            sent.extend(answer(&[whole], number));
        }
        let mut j = joiner();
        let mut got = Vec::new();
        for piece in &sent {
            if let Joined::Frame(f) = j.reply(5, piece) {
                got.push(f.to_vec());
            }
        }
        assert_eq!(got, [a, b, c]);
        assert_eq!((j.abandoned(), j.unjoined()), (0, 0));
    }

    /// A protected frame's profile: a 32-bit CRC, a two-byte counter and a length; synthetic.
    const PROTECTION: &str = r#"{
      "name": "replay-pieces-e2e",
      "fields": [{"name": "crc", "bytes": 4}, {"name": "counter", "bytes": 2},
                 {"name": "length", "bytes": 2}],
      "crc": {"field": "crc", "width": 32, "poly": "0x1EDC6F41", "init": "0xFFFFFFFF",
              "refin": true, "refout": true, "xorout": "0xFFFFFFFF",
              "cover": ["counter", "length", "@payload"]},
      "length": {"field": "length", "counts": "frame"},
      "counter": {"field": "counter", "max_gap": 3, "timeout_ms": 1000}
    }"#;

    /// The depth of the ring the answers are read from.
    const DEPTH: usize = 4;

    /// The counters the receiving judge is handed when two answers of one publisher are joined
    /// and admitted as the replay subscriber joins and admits them: the first answer carries the
    /// frames of counters 1 and 2, its transfers numbered from 1; the second, to a later query,
    /// carries 1, 2 and 3, numbered from `second_from`. The joiner is handed back for its counts.
    fn judged_over_two_answers(second_from: u64) -> (Vec<u64>, PieceJoiner) {
        let profile = Profile::parse(PROTECTION).expect("valid");
        let protected = |counter: u64| {
            build(
                &profile,
                &Values::new().whole("counter", counter),
                &[counter as u8; 6],
            )
            .expect("builds")
            .bytes
        };
        let mut receiver = Receiver::new(
            profile.clone(),
            &Values::new(),
            Keying::Indexed { streams: 1 },
            None,
            0,
        )
        .expect("made");
        let (one, two, three) = (protected(1), protected(2), protected(3));
        let answers = [
            (1, answer(&[&one, &two], 1)),
            (2, answer(&[&one, &two, &three], second_from)),
        ];
        let mut j = joiner();
        let mut judged = Vec::new();
        for (request, sent) in &answers {
            for piece in sent {
                let Joined::Frame(joined) = j.reply(*request, piece) else {
                    continue;
                };
                if admit(&receiver, 0, &joined, DEPTH) == Admission::Judge {
                    let verdict = receiver.receive(0, &joined, 0).expect("judged");
                    judged.push(verdict.counter.expect("a frame with a header"));
                }
            }
            j.close(*request);
        }
        (judged, j)
    }

    /// A responder that numbers every answer from the same first number: the second answer's
    /// numbers are the first's again, on a stream of their own.
    #[test]
    fn answers_numbered_from_one_first_number_judge_each_frame_once() {
        let (judged, j) = judged_over_two_answers(1);
        assert_eq!(
            judged,
            [1, 2, 3],
            "the frames answered twice are judged once"
        );
        assert_eq!((j.abandoned(), j.unjoined()), (0, 0));
    }

    /// A responder that goes on from where its previous answer stopped.
    #[test]
    fn answers_numbered_on_from_the_last_judge_each_frame_once() {
        let (judged, j) = judged_over_two_answers(3);
        assert_eq!(
            judged,
            [1, 2, 3],
            "the frames answered twice are judged once"
        );
        assert_eq!((j.abandoned(), j.unjoined()), (0, 0));
    }
}
