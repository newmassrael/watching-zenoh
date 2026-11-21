// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The RECEIVING judge of end-to-end protected frames, as state: one judge per
//! stream, the rules the profile states, and a verdict beside every frame.
//!
//! [`crate::e2e_judge::Judge`] is one stream's counter and silence. A receiver
//! of a message keeps several: one per instance of the message, or one per
//! sender of it. This type keeps them, in storage sized once when it is made,
//! and is sans-I/O: the input is a stream, the frame's bytes and the instant
//! it arrived; the output is a [`Verdict`]. Nothing is dropped here: the
//! payload is always reported beside the verdict, and whether a sample whose
//! verdict is not [`Status::Ok`] reaches the application is the caller's
//! policy, not a side effect of the judgement.
//!
//! # One frame, in order
//!
//! 1. The frame is opened under the profile. A frame shorter than the header
//!    fails integrity as [`FAILED_SHORT`], with an empty payload.
//! 2. **Integrity.** The CRC, then the rules of the profile's `judge` object:
//!    the identifier field must equal the expected one in the bits it owns
//!    ([`FAILED_IDENT`]) and, when the profile says so, the length field must
//!    agree with the frame ([`FAILED_LENGTH`]). A frame that fails any of them
//!    is [`Status::Integrity`] and moves no state of the stream it is judged in.
//! 3. **The stream.** Under [`Keying::Indexed`] it is the caller's index. Under
//!    [`Keying::Senders`] it is the slot of the sender identity the frame's
//!    message cell carries: the slot that holds it, even for a frame that is
//!    not intact; otherwise, in arrival order, a free slot, taken only by an
//!    intact frame. A frame of a sender no slot holds is
//!    [`Status::Unslotted`] and is counted: a sender a bound list does not name,
//!    or one more sender than the slots. A frame that is not intact and whose
//!    sender holds no slot is [`Status::Integrity`] with no stream.
//! 4. **The counter**, in that stream's judge: the first intact frame is
//!    [`Status::First`], the baseline; then the step, reported as the profile's
//!    `counter_errors` rule says.
//!
//! # Storage
//!
//! The streams are allocated once, by [`Receiver::new`], at the count the caller
//! gives, and never grow. A fixed-memory image will take them from the static
//! tables a generator writes from the deployment's catalogue.

use alloc::vec::Vec;

use crate::e2e_frame::{logical_value, open, BuildError, OpenedFrame, Values};
use crate::e2e_judge::{CounterReason, CounterWidthError, Judge, JudgeConfig, Judgment};
use crate::e2e_profile::{CounterErrors, Profile};

/// The CRC did not match.
pub const FAILED_CRC: u8 = 1;
/// The identifier field is not the expected one.
pub const FAILED_IDENT: u8 = 2;
/// The length field does not agree with the frame.
pub const FAILED_LENGTH: u8 = 4;
/// The frame is shorter than the header.
pub const FAILED_SHORT: u8 = 8;

/// What a frame was judged to be.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Status {
    /// Intact, and the next frame of its stream.
    Ok,
    /// Intact, and the first of its stream: the baseline.
    First,
    /// Intact, and the same counter again.
    Repeated,
    /// Intact, and a step above the largest gap.
    OutOfRange,
    /// Intact, and a repetition or a step out of range, under a profile that
    /// reports the two as one.
    CounterError,
    /// Not intact: see [`Verdict::failed`].
    Integrity,
    /// Intact or not, of a sender no slot holds, so judged in no stream.
    Unslotted,
}

/// Why a frame of a sender was judged in no slot.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Unslotted {
    /// The bound list does not name the sender.
    NotListed,
    /// Every slot is taken by another sender.
    Full,
}

/// The verdict on one frame.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Verdict {
    /// What the frame was judged to be.
    pub status: Status,
    /// The integrity checks it failed, as `FAILED_*` bits; 0 when intact.
    pub failed: u8,
    /// Why it was judged in no slot, for [`Status::Unslotted`].
    pub unslotted: Option<Unslotted>,
    /// The stream it was judged in; `None` when it was judged in none.
    pub stream: Option<usize>,
    /// The counter it carries; `None` for a frame shorter than the header.
    pub counter: Option<u64>,
    /// The step from the stream's baseline, for an intact frame after the first.
    pub step: Option<u64>,
    /// The kind, result and sender identity of its message cell, when the
    /// profile names them and the frame has a header.
    pub kind: Option<u64>,
    /// See [`Verdict::kind`].
    pub result: Option<u64>,
    /// See [`Verdict::kind`].
    pub sender: Option<u64>,
    /// The silence before the frame exceeded the profile's timeout (see
    /// [`crate::e2e_judge`]); false for a frame judged in no stream, and
    /// always under a profile that states no timeout (`timeout_ms` 0).
    pub timeout: bool,
    /// The silence before the frame, when the stream has an instant to measure
    /// it from.
    pub silence_ms: Option<u64>,
    /// Where the payload starts in the frame.
    pub payload_offset: usize,
    /// How long it is.
    pub payload_bytes: usize,
}

/// How a receiver's streams are chosen.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Keying {
    /// The caller names the stream of every frame, `0..streams`: one per
    /// message, or per instance of it.
    Indexed {
        /// How many streams.
        streams: usize,
    },
    /// One stream per sender, chosen by the sender identity of the profile's
    /// message cell, in at most `slots` slots.
    Senders {
        /// How many slots.
        slots: usize,
        /// The senders the slots are bound to, in slot order; `None` for slots
        /// taken in arrival order.
        bound: Option<Vec<u64>>,
    },
}

/// Why a receiver was not made.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NewError {
    /// The expected values do not give the identifier field the profile judges.
    Expected(BuildError),
    /// A receiver of no stream or no slot.
    NoStreams,
    /// The `max_gap` given is 0 or above what the profile allows.
    MaxGap {
        /// The value given.
        given: u64,
        /// The largest the profile allows.
        limit: u64,
    },
    /// Sender keying under a profile whose message cell names no sender.
    NoSenderInCell,
    /// More slots than the build allows.
    TooManySlots {
        /// The slots asked for.
        slots: usize,
        /// The most the build allows.
        limit: usize,
    },
    /// A bound list that does not fit the slots, or names a sender twice, or
    /// names one the cell's sender part cannot hold.
    BadBoundList,
}

impl core::fmt::Display for NewError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Expected(e) => write!(f, "expected: {e}"),
            Self::NoStreams => f.write_str("a receiver keeps at least one stream"),
            Self::MaxGap { given, limit } => write!(
                f,
                "max_gap is 1 to {limit} under this profile, this one is {given}"
            ),
            Self::NoSenderInCell => {
                f.write_str("keying by sender needs the profile's `cell` to name a `sender` part")
            }
            Self::TooManySlots { slots, limit } => write!(
                f,
                "{slots} sender slots asked for, and the build allows at most {limit}"
            ),
            Self::BadBoundList => f.write_str(
                "the bound list must name at most one sender per slot, each once, each a value \
                 the cell's sender part holds",
            ),
        }
    }
}

/// Why a frame was not judged.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReceiveError {
    /// A stream the receiver does not have.
    NoSuchStream {
        /// The stream given.
        stream: usize,
        /// How many the receiver has (1 under sender keying, whose stream the
        /// receiver chooses).
        streams: usize,
    },
    /// The counter did not fit the judge's width: a frame of another profile.
    Counter(CounterWidthError),
}

impl core::fmt::Display for ReceiveError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::NoSuchStream { stream, streams } => write!(
                f,
                "stream {stream} is not one of the receiver's {streams} streams"
            ),
            Self::Counter(e) => write!(f, "{e}"),
        }
    }
}

/// How many frames were judged in no slot, by reason. Each saturates.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Counts {
    /// Frames of a sender the bound list does not name.
    pub not_listed: u64,
    /// Frames of a sender for whom no slot was free.
    pub full: u64,
}

#[derive(Debug, Clone)]
struct Stream {
    judge: Judge,
    /// The sender that holds the slot, under sender keying.
    sender: Option<u64>,
    /// The CRC of the frame that became the baseline, which the replay admission compares a
    /// reply carrying the baseline's counter with (`crate::replay_admission`).
    #[cfg(feature = "replay")]
    baseline_crc: Option<u64>,
}

/// The receiving judge of one message.
#[derive(Debug, Clone)]
pub struct Receiver {
    profile: Profile,
    /// The logical value the identifier field must carry, when it is judged.
    expected_ident: Option<u64>,
    /// Whether the slots are bound by a list (else taken in arrival order).
    bound: bool,
    by_sender: bool,
    streams: Vec<Stream>,
    counts: Counts,
}

impl Receiver {
    /// A receiver of `profile`'s frames.
    ///
    /// `expected` gives the identifier field the profile's `judge.ident` names,
    /// as a sender's values give it (a split field by its parts, a derived one
    /// from `@address`); other fields it states are not read, so a node may
    /// hand both ends the same values text. `max_gap` replaces the profile's
    /// own, up to its `max_gap_ceiling`. `slot_limit` is the most sender slots
    /// the build allows.
    pub fn new(
        profile: Profile,
        expected: &Values,
        keying: Keying,
        max_gap: Option<u64>,
        slot_limit: usize,
    ) -> Result<Self, NewError> {
        let expected_ident = match profile.rules().ident {
            Some(index) => {
                Some(logical_value(&profile, index, expected).map_err(NewError::Expected)?)
            }
            None => None,
        };
        let limit = profile.max_gap_limit();
        let config = match max_gap {
            None => profile.judge_config(),
            Some(given) if given == 0 || given > limit => {
                return Err(NewError::MaxGap { given, limit })
            }
            Some(given) => JudgeConfig {
                max_gap: given,
                ..profile.judge_config()
            },
        };
        let rules = profile.counter_rules();
        let fresh = |sender: Option<u64>| Stream {
            judge: Judge::with_rules(config, rules),
            sender,
            #[cfg(feature = "replay")]
            baseline_crc: None,
        };
        let (streams, bound, by_sender): (Vec<Stream>, bool, bool) = match keying {
            Keying::Indexed { streams } => {
                if streams == 0 {
                    return Err(NewError::NoStreams);
                }
                ((0..streams).map(|_| fresh(None)).collect(), false, false)
            }
            Keying::Senders { slots, bound } => {
                if slots == 0 {
                    return Err(NewError::NoStreams);
                }
                if slots > slot_limit {
                    return Err(NewError::TooManySlots {
                        slots,
                        limit: slot_limit,
                    });
                }
                let Some(cell) = profile.cell() else {
                    return Err(NewError::NoSenderInCell);
                };
                let Some(sender_part) = cell.sender else {
                    return Err(NewError::NoSenderInCell);
                };
                let largest = profile.fields()[cell.field].parts[sender_part].max_value();
                let table: Vec<Stream> = match &bound {
                    Some(list) => {
                        let fits = !list.is_empty() && list.len() <= slots;
                        let each_once = list
                            .iter()
                            .enumerate()
                            .all(|(i, identity)| !list[..i].contains(identity));
                        if !fits || !each_once || list.iter().any(|&identity| identity > largest) {
                            return Err(NewError::BadBoundList);
                        }
                        list.iter().map(|&identity| fresh(Some(identity))).collect()
                    }
                    None => (0..slots).map(|_| fresh(None)).collect(),
                };
                (table, bound.is_some(), true)
            }
        };
        Ok(Self {
            profile,
            expected_ident,
            bound,
            by_sender,
            streams,
            counts: Counts::default(),
        })
    }

    /// The profile the receiver judges under.
    pub fn profile(&self) -> &Profile {
        &self.profile
    }

    /// How many streams (or slots) it keeps.
    pub fn streams(&self) -> usize {
        self.streams.len()
    }

    /// Whether it chooses each frame's stream by the sender identity
    /// ([`Keying::Senders`]) rather than taking the caller's.
    pub fn keyed_by_sender(&self) -> bool {
        self.by_sender
    }

    /// The sender that holds a slot, under sender keying; `None` for a free
    /// slot, a slot the receiver does not have, or indexed keying.
    pub fn slot_sender(&self, slot: usize) -> Option<u64> {
        self.streams.get(slot).and_then(|s| s.sender)
    }

    /// The frames judged in no slot so far.
    pub fn counts(&self) -> Counts {
        self.counts
    }

    /// Where `frame`, arriving on `stream`, would be judged and the baseline it would be judged
    /// against, read without judging it; `None` when it is not intact, would be judged in no
    /// stream that holds a baseline, or names a stream the receiver does not have.
    #[cfg(feature = "replay")]
    pub(crate) fn standing(
        &self,
        stream: usize,
        frame: &[u8],
    ) -> Option<crate::replay_admission::Standing> {
        let addressable = if self.by_sender {
            1
        } else {
            self.streams.len()
        };
        if stream >= addressable {
            return None;
        }
        let opened = open(&self.profile, frame).ok()?;
        if self.integrity(&opened) != 0 {
            return None;
        }
        let slot = if self.by_sender {
            let (_, _, sender) = self.cell_values(&opened);
            let sender = sender?;
            self.streams
                .iter()
                .position(|held| held.sender == Some(sender))?
        } else {
            stream
        };
        let held = &self.streams[slot];
        let baseline = held.judge.baseline()?;
        let bits = held.judge.config().counter_bytes * 8;
        Some(crate::replay_admission::Standing {
            counter: opened.counter(&self.profile),
            crc: opened.crc_found,
            baseline,
            baseline_crc: held.baseline_crc,
            // A counter field is 1 to 8 bytes, so its width fits a byte.
            mask: crate::e2e_crc::width_mask(bits as u8),
        })
    }

    /// Judge `frame`, which arrived at `now_ms` on `stream`. Under sender
    /// keying the receiver chooses the stream, and `stream` must be 0.
    pub fn receive(
        &mut self,
        stream: usize,
        frame: &[u8],
        now_ms: u64,
    ) -> Result<Verdict, ReceiveError> {
        let addressable = if self.by_sender {
            1
        } else {
            self.streams.len()
        };
        if stream >= addressable {
            return Err(ReceiveError::NoSuchStream {
                stream,
                streams: addressable,
            });
        }
        let Ok(opened) = open(&self.profile, frame) else {
            return self.short(stream, frame.len(), now_ms);
        };
        let failed = self.integrity(&opened);
        let intact = failed == 0;
        let counter = opened.counter(&self.profile);
        let (kind, result, sender) = self.cell_values(&opened);
        let mut verdict = Verdict {
            status: Status::Integrity,
            failed,
            unslotted: None,
            stream: None,
            counter: Some(counter),
            step: None,
            kind,
            result,
            sender,
            timeout: false,
            silence_ms: None,
            payload_offset: opened.payload_offset,
            payload_bytes: opened.payload_bytes,
        };
        let slot = if self.by_sender {
            match self.slot_for(sender, intact) {
                Ok(Some(slot)) => slot,
                Ok(None) => return Ok(verdict),
                Err(why) => {
                    self.count(why);
                    verdict.status = Status::Unslotted;
                    verdict.unslotted = Some(why);
                    return Ok(verdict);
                }
            }
        } else {
            stream
        };
        verdict.stream = Some(slot);
        let judge = &mut self.streams[slot].judge;
        let before = judge.baseline();
        let first = before.is_none();
        if intact {
            verdict.step = judge.step_from_baseline(counter);
        }
        let judgment = judge
            .receive(intact, counter, now_ms)
            .map_err(ReceiveError::Counter)?;
        #[cfg(feature = "replay")]
        {
            let held = &mut self.streams[slot];
            if intact && held.judge.baseline() != before {
                held.baseline_crc = Some(opened.crc_found);
            }
        }
        verdict.timeout = judgment.timeout_error;
        verdict.silence_ms = judgment.silence_ms;
        verdict.status = self.status(intact, first, &judgment);
        Ok(verdict)
    }

    /// The verdict on a frame shorter than the header. Under indexed keying it
    /// is judged in its stream as a frame that is not intact, which moves
    /// nothing; under sender keying it names no sender and so no stream.
    fn short(&mut self, stream: usize, len: usize, now_ms: u64) -> Result<Verdict, ReceiveError> {
        let mut verdict = Verdict {
            status: Status::Integrity,
            failed: FAILED_SHORT,
            unslotted: None,
            stream: None,
            counter: None,
            step: None,
            kind: None,
            result: None,
            sender: None,
            timeout: false,
            silence_ms: None,
            payload_offset: len,
            payload_bytes: 0,
        };
        if !self.by_sender {
            let judgment = self.streams[stream]
                .judge
                .receive(false, 0, now_ms)
                .map_err(ReceiveError::Counter)?;
            verdict.stream = Some(stream);
            verdict.timeout = judgment.timeout_error;
            verdict.silence_ms = judgment.silence_ms;
        }
        Ok(verdict)
    }

    /// The `FAILED_*` bits of an opened frame.
    fn integrity(&self, opened: &OpenedFrame) -> u8 {
        let rules = self.profile.rules();
        let mut failed = 0;
        if !opened.crc_ok {
            failed |= FAILED_CRC;
        }
        if let (Some(index), Some(expected)) = (rules.ident, self.expected_ident) {
            // The expected value is made as a sender makes it, so it has no bit outside these.
            let owned = self.profile.fields()[index].owned_bits();
            if opened.fields[index].value & owned != expected {
                failed |= FAILED_IDENT;
            }
        }
        if rules.length && !opened.length_matches_frame {
            failed |= FAILED_LENGTH;
        }
        failed
    }

    /// The kind, result and sender of the frame's message cell.
    fn cell_values(&self, opened: &OpenedFrame) -> (Option<u64>, Option<u64>, Option<u64>) {
        let Some(cell) = self.profile.cell() else {
            return (None, None, None);
        };
        let parts = &opened.fields[cell.field].parts;
        let read = |part: Option<usize>| part.map(|p| parts[p]);
        (read(cell.kind), read(cell.result), read(cell.sender))
    }

    /// The slot a frame of `sender` is judged in: the one that holds it, or a
    /// free one taken in arrival order by an intact frame. `Ok(None)` for a
    /// frame that is not intact and whose sender holds no slot.
    fn slot_for(&mut self, sender: Option<u64>, intact: bool) -> Result<Option<usize>, Unslotted> {
        // Sender keying was refused at `new` for a cell with no sender part,
        // so an opened frame always carries one here.
        let Some(sender) = sender else {
            return Ok(None);
        };
        if let Some(slot) = self.streams.iter().position(|s| s.sender == Some(sender)) {
            return Ok(Some(slot));
        }
        if self.bound {
            return Err(Unslotted::NotListed);
        }
        if !intact {
            return Ok(None);
        }
        match self.streams.iter().position(|s| s.sender.is_none()) {
            Some(slot) => {
                self.streams[slot].sender = Some(sender);
                Ok(Some(slot))
            }
            None => Err(Unslotted::Full),
        }
    }

    fn count(&mut self, why: Unslotted) {
        let counter = match why {
            Unslotted::NotListed => &mut self.counts.not_listed,
            Unslotted::Full => &mut self.counts.full,
        };
        *counter = counter.saturating_add(1);
    }

    fn status(&self, intact: bool, first: bool, judgment: &Judgment) -> Status {
        if !intact {
            return Status::Integrity;
        }
        if first {
            return Status::First;
        }
        let joined = self.profile.rules().counter_errors == CounterErrors::Joined;
        match judgment.counter_reason {
            CounterReason::None => Status::Ok,
            _ if joined => Status::CounterError,
            CounterReason::Repeat => Status::Repeated,
            CounterReason::OutOfRange => Status::OutOfRange,
        }
    }
}
