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
}
