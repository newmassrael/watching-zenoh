// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The SENDING side of a segment profile: one message of the application's
//! own cut into pieces whose header the profile declares.
//!
//! [`crate::segment_profile`] reads a piece and [`crate::segment_chain`] joins
//! the pieces of one transfer. A participant that speaks to a deployment which
//! splits its large messages that way must also WRITE them, and a writer kept
//! apart from the reader would be a second statement of the same header. This
//! module takes the profile the reader takes, as the same text, and writes
//! each piece with the reader's own field layout and CRC rule
//! ([`crate::segment_profile::Field::write`],
//! [`crate::segment_profile::SegmentProfile`]'s one CRC feeder): a piece this
//! module writes is one the reader joins, and the tests hold it to that.
//!
//! # Who writes which field
//!
//! * A field with `equals` holds that value. The profile writes it.
//! * The `transfer` field is the sender's: it numbers the messages of this
//!   sender's stream (below).
//! * The `total` field holds the message's length and the `offset` field
//!   where the piece's chunk starts in it. The mechanism writes them.
//! * The CRC field, when the profile has one, holds the CRC its `cover` list
//!   describes. The mechanism writes it.
//! * Every other field, the `stream` fields among them, holds the value the
//!   caller states once when the sender is made, in a JSON object keyed by
//!   field name (`{"origin": 4660}`, or `"0x1234"` as a string). A field the
//!   object leaves out is refused, and so is a field the profile or the
//!   mechanism writes: there is no rule for which of two values would win.
//!
//! A deployment that draws its stream value at random when it starts expects
//! the caller to draw it; this library does not put a value on the wire that
//! nobody stated.
//!
//! # The transfer number
//!
//! The rule is the end-to-end counter's ([`crate::e2e_sender`]):
//!
//! * The first message carries the value the sender is made with, and each
//!   message after it the next value. [`SegmentSender::set`] changes it.
//! * A message that is REFUSED (the message, the chunk size, a value that does
//!   not fit its field) emits no piece and consumes no number.
//! * A message whose first piece was handed to the caller's emitter has
//!   consumed its number, whether or not every piece then went out: a reader
//!   that saw some pieces under that number has seen the number used.
//! * The number does not wrap by default ([`Rollover::Refuse`]): the message
//!   that carries the field's largest value is split, and the next one is
//!   refused. [`Rollover::Restart`] goes back to the value the sender was made
//!   with instead, which is how a deployment that never sends 0 and wraps to
//!   1 is stated (made with 1, restarting).
//!
//! # Pieces
//!
//! The message is cut into chunks of the caller's `chunk_bytes`, the last one
//! shorter when the length is not a multiple, and the pieces are handed out in
//! order, first chunk first. A message no longer than one chunk is one piece,
//! still with its header: a reader of a key bound to a segment profile reads
//! every payload on it as a piece.
//!
//! The chunk size is the sender's choice, not the profile's: a reader places a
//! piece by its `total` and `offset` alone.

use alloc::format;
use alloc::string::String;
use alloc::vec;
use alloc::vec::Vec;
use core::fmt;

use crate::e2e_profile::{check_distinct, child, object, read_json, read_uint, DocError};
use crate::segment_profile::SegmentProfile;

/// What a sender does after the message that carried the largest transfer
/// number its field holds.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Rollover {
    /// Refuse the next message. The default.
    #[default]
    Refuse,
    /// Go back to the number the sender was made with.
    Restart,
}

/// Why a sender was not made, or a message was not split.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Refusal {
    /// The profile text is not a segment profile.
    Profile(DocError),
    /// The values text does not state the fields the caller owns, exactly.
    Values(DocError),
    /// The message is empty: no piece can place an empty whole.
    EmptyMessage,
    /// The message is longer than the profile's `total_max`.
    PastTotalMax {
        /// The message's length.
        len: usize,
        /// The profile's `total_max`.
        max: u64,
    },
    /// The chunk size is zero.
    ZeroChunk,
    /// A value the mechanism or the sender writes does not fit its field.
    DoesNotFit {
        /// The field's name.
        field: String,
        /// The value.
        value: u64,
        /// The largest value the field holds.
        max: u64,
    },
    /// The transfer number sent its largest value and the sender does not
    /// restart.
    Spent {
        /// The transfer field's name.
        field: String,
        /// The largest value it holds.
        max: u64,
    },
}

impl fmt::Display for Refusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Profile(e) => write!(f, "profile {e}"),
            Self::Values(e) => write!(f, "values {e}"),
            Self::EmptyMessage => f.write_str("the message is empty: no piece can carry it"),
            Self::PastTotalMax { len, max } => write!(
                f,
                "the message is {len} bytes, past the profile's total_max of {max}"
            ),
            Self::ZeroChunk => f.write_str("the chunk size is zero"),
            Self::DoesNotFit { field, value, max } => write!(
                f,
                "the field `{field}` would hold {value}, past the largest value it holds, {max}"
            ),
            Self::Spent { field, max } => write!(
                f,
                "the transfer field `{field}` has sent its largest value, {max}, and this \
                 sender does not restart: no piece is written"
            ),
        }
    }
}

/// What one split did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Split {
    /// The transfer number every piece carried.
    pub transfer: u64,
    /// How many pieces the message became.
    pub pieces: usize,
}

/// Why a split ended without emitting every piece.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SplitError<E> {
    /// The message was refused before any piece: nothing was consumed.
    Refused(Refusal),
    /// The caller's emitter failed. The transfer number is consumed.
    Emit {
        /// What the emitter returned.
        error: E,
        /// The number the pieces carried.
        transfer: u64,
        /// How many pieces the emitter accepted before it failed.
        sent: usize,
        /// How many pieces the message was cut into.
        pieces: usize,
    },
}

/// The piece writer of one stream of messages under one profile.
#[derive(Debug, Clone)]
pub struct SegmentSender {
    profile: SegmentProfile,
    /// A header with every field the profile and the caller fix written in,
    /// and zero in the transfer, total, offset and CRC fields.
    template: Vec<u8>,
    /// The number the sender was made with, which [`Rollover::Restart`] goes
    /// back to.
    first: u64,
    /// The number the next message carries; `None` after the largest was sent
    /// under [`Rollover::Refuse`].
    next: Option<u64>,
    rollover: Rollover,
}

impl SegmentSender {
    /// A sender for the profile `profile_text` describes, with the caller's
    /// fields stated in `values_text`, whose first message carries
    /// `first_transfer`.
    ///
    /// A first number that does not fit the transfer field is not judged here:
    /// the first split is refused like any value that does not fit, and
    /// consumes nothing.
    ///
    /// # Errors
    ///
    /// [`Refusal::Profile`] or [`Refusal::Values`], each with the place.
    pub fn new(
        profile_text: &str,
        values_text: &str,
        first_transfer: u64,
        rollover: Rollover,
    ) -> Result<Self, Refusal> {
        let profile = SegmentProfile::parse(profile_text).map_err(Refusal::Profile)?;
        let template = template(&profile, values_text).map_err(Refusal::Values)?;
        Ok(Self {
            profile,
            template,
            first: first_transfer,
            next: Some(first_transfer),
            rollover,
        })
    }

    /// The profile the sender writes by.
    pub fn profile(&self) -> &SegmentProfile {
        &self.profile
    }

    /// The number the next message carries; `None` when the largest was sent
    /// and the sender does not restart.
    pub fn next(&self) -> Option<u64> {
        self.next
    }

    /// Make `value` the number the next message carries. A value past the
    /// field's width is accepted here and refused by the split, as a first
    /// number is.
    pub fn set(&mut self, value: u64) {
        self.next = Some(value);
    }

    /// The transfer field's name.
    pub fn transfer_field(&self) -> &str {
        &self.profile.fields()[self.profile.transfer()].name
    }

    /// The largest value the transfer field holds.
    pub fn transfer_max(&self) -> u64 {
        self.profile.fields()[self.profile.transfer()].max_value()
    }

    /// Cut `message` into chunks of `chunk_bytes` and hand each piece, header
    /// and chunk, to `emit` in order.
    ///
    /// # Errors
    ///
    /// [`SplitError::Refused`] before any piece, consuming nothing;
    /// [`SplitError::Emit`] when `emit` failed, after the number was consumed.
    pub fn split<E>(
        &mut self,
        message: &[u8],
        chunk_bytes: usize,
        mut emit: impl FnMut(&[u8]) -> Result<(), E>,
    ) -> Result<Split, SplitError<E>> {
        let transfer = self
            .admit(message, chunk_bytes)
            .map_err(SplitError::Refused)?;
        self.next = self.after(transfer);

        let pieces = message.len().div_ceil(chunk_bytes);
        let header_bytes = self.profile.header_bytes();
        let fields = self.profile.fields();
        let mut piece = Vec::with_capacity(header_bytes + chunk_bytes.min(message.len()));
        for (sent, chunk) in message.chunks(chunk_bytes).enumerate() {
            piece.clear();
            piece.extend_from_slice(&self.template);
            fields[self.profile.transfer()].write(&mut piece, transfer);
            fields[self.profile.total()].write(&mut piece, message.len() as u64);
            fields[self.profile.offset()].write(&mut piece, (sent * chunk_bytes) as u64);
            piece.extend_from_slice(chunk);
            if let Some(spec) = self.profile.crc() {
                let (header, body) = piece.split_at(header_bytes);
                let crc = self.profile.crc_over(spec, header, body);
                fields[spec.field].write(&mut piece, crc);
            }
            if let Err(error) = emit(&piece) {
                return Err(SplitError::Emit {
                    error,
                    transfer,
                    sent,
                    pieces,
                });
            }
        }
        Ok(Split { transfer, pieces })
    }

    /// The number `message` would carry, once every value it needs is known
    /// to fit; nothing is consumed.
    fn admit(&self, message: &[u8], chunk_bytes: usize) -> Result<u64, Refusal> {
        if chunk_bytes == 0 {
            return Err(Refusal::ZeroChunk);
        }
        if message.is_empty() {
            return Err(Refusal::EmptyMessage);
        }
        let max = self.profile.total_max();
        if message.len() as u64 > max {
            return Err(Refusal::PastTotalMax {
                len: message.len(),
                max,
            });
        }
        let Some(transfer) = self.next else {
            return Err(Refusal::Spent {
                field: self.transfer_field().into(),
                max: self.transfer_max(),
            });
        };
        let last_offset = (message.len() - 1) / chunk_bytes * chunk_bytes;
        let p = &self.profile;
        self.fits(p.transfer(), transfer)?;
        self.fits(p.total(), message.len() as u64)?;
        self.fits(p.offset(), last_offset as u64)?;
        Ok(transfer)
    }

    fn fits(&self, index: usize, value: u64) -> Result<(), Refusal> {
        let field = &self.profile.fields()[index];
        let max = field.max_value();
        if value > max {
            return Err(Refusal::DoesNotFit {
                field: field.name.clone(),
                value,
                max,
            });
        }
        Ok(())
    }

    /// The number after `sent`, which a message has just carried.
    fn after(&self, sent: u64) -> Option<u64> {
        if sent < self.transfer_max() {
            Some(sent + 1)
        } else {
            match self.rollover {
                Rollover::Restart => Some(self.first),
                Rollover::Refuse => None,
            }
        }
    }
}

/// The header template: the `equals` values and the caller's values written,
/// every other byte zero. Refuses a values text that states a field the
/// profile or the mechanism writes, names a field the profile does not have,
/// holds a value past its field, or leaves one of the caller's fields out.
fn template(profile: &SegmentProfile, values_text: &str) -> Result<Vec<u8>, DocError> {
    let root = read_json(values_text)?;
    let entries = object(&root, "")?;
    check_distinct(entries, "")?;

    let fields = profile.fields();
    let mut header = vec![0u8; profile.header_bytes()];
    for field in fields {
        if let Some(value) = field.equals {
            field.write(&mut header, value);
        }
    }

    let written_by = |index: usize| -> Option<&'static str> {
        if fields[index].equals.is_some() {
            Some("holds the profile's fixed value (`equals`)")
        } else if index == profile.transfer() {
            Some("is the transfer field, which the sender numbers")
        } else if index == profile.total() {
            Some("is the total field, which holds the message's length")
        } else if index == profile.offset() {
            Some("is the offset field, which holds where each chunk starts")
        } else if profile.crc().is_some_and(|c| c.field == index) {
            Some("is the crc field, which holds the computed CRC")
        } else {
            None
        }
    };

    let mut stated = vec![false; fields.len()];
    for (key, value) in entries {
        let path = child("", key);
        let Some(index) = fields.iter().position(|f| &f.name == key) else {
            return Err(DocError::invalid(
                path,
                format!("the profile has no field called `{key}`"),
            ));
        };
        if let Some(why) = written_by(index) {
            return Err(DocError::invalid(
                path,
                format!("the field `{key}` {why}: it cannot be stated"),
            ));
        }
        let value = read_uint(value, &path)?;
        let field = &fields[index];
        if value > field.max_value() {
            return Err(DocError::invalid(
                path,
                format!("{value:#x} does not fit the field's {} bytes", field.bytes),
            ));
        }
        field.write(&mut header, value);
        stated[index] = true;
    }
    if let Some(missing) = (0..fields.len()).find(|&i| !stated[i] && written_by(i).is_none()) {
        let name = &fields[missing].name;
        return Err(DocError::invalid(
            child("", name),
            format!(
                "the field `{name}` is not stated: every field the profile and the \
                 mechanism do not write needs a value"
            ),
        ));
    }
    Ok(header)
}
