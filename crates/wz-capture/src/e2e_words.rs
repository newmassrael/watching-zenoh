// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The closed words a selector reads the end-to-end judge's verdict on one
//! record by: the `e2e`, `e2e.crc`, `e2e.counter` and `e2e.timeout` fields of
//! [`crate::filter`].
//!
//! # One reduction, from the judge's outcome
//!
//! The judge ([`crate::e2e_slots`]) hands a [`Outcome`] per frame, and the field
//! document writes it whole as a record's `e2e` block (`crate::e2e_row`). A
//! selector asks a narrower question of the same outcome, so the words are made
//! from it HERE and only here: [`E2eWords::of`]. Each word restates a fact of
//! the block, and none is a fact the block does not carry:
//!
//! | field | words | from the block |
//! |---|---|---|
//! | `e2e.crc` | `ok` `error` | `crc_error`; absent on a payload that is not a frame (`opened: false`) |
//! | `e2e.counter` | `none` `repeat` `out_of_range` `unjudged` | `counter_reason`; `unjudged` where it is `null`, where `first` is `true`, and where the CRC did not match |
//! | `e2e.timeout` | `ok` `error` `unjudged` | `timeout_error`; `unjudged` where it is `null` |
//! | `e2e` | `ok` `error` `unjudged` `none` | the three above, below |
//!
//! `e2e` is `error` when any part was judged an error, or the payload is shorter
//! than the profile's header (damage, `payload_shorter_than_header`); `unjudged`
//! when nothing was judged an error and some part was not judged, or the payload
//! is not one run of bytes the reader holds (`payload_not_contiguous`); `ok`
//! when every part was judged and none was an error; and `none` for a record no
//! profile rule judges at all ([`E2eWords::NONE`]).
//!
//! # Not judged is not failed
//!
//! The counter of a slot's first frame has nothing before it to be judged
//! against, a frame from a sender the capture never named has no slot, and a
//! frame whose packet carried no time is not judged for its timeout. Each of
//! those reads `unjudged`, and never `error`: a reader filtering for failures
//! writes `e2e == error` and is not shown the first frame of every stream.
//!
//! # `none` is decided
//!
//! A `Push` whose key no profile rule covers, a `del`, a query and a reply carry
//! no frame, so `e2e == none` is `yes` over them and the three parts are absent
//! (`e2e.crc == ok` is `no`, `e2e.crc != ok` is `yes`, as a path the walked tree
//! lacks answers). Whether a record IS a frame is undecidable only where the
//! judge could not be asked: the plane was handed no declarations, or the key
//! the rules are matched against did not resolve.

use crate::e2e_judge::CounterReason;
use crate::e2e_slots::{Outcome, Unopened};

/// The four fields, as the selector names them.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum E2ePart {
    /// `e2e`: the verdict on the whole frame.
    Verdict,
    /// `e2e.crc`.
    Crc,
    /// `e2e.counter`.
    Counter,
    /// `e2e.timeout`.
    Timeout,
}

/// The words of `e2e`.
pub const VERDICT_WORDS: &[&str] = &[OK, ERROR, UNJUDGED, NONE];
/// The words of `e2e.crc`.
pub const CRC_WORDS: &[&str] = &[OK, ERROR];
/// The words of `e2e.counter`: the judge's own reasons
/// ([`CounterReason::word`]) and `unjudged`.
pub const COUNTER_WORDS: &[&str] = &[
    CounterReason::None.word(),
    CounterReason::Repeat.word(),
    CounterReason::OutOfRange.word(),
    UNJUDGED,
];
/// The words of `e2e.timeout`.
pub const TIMEOUT_WORDS: &[&str] = &[OK, ERROR, UNJUDGED];

const OK: &str = "ok";
const ERROR: &str = "error";
const UNJUDGED: &str = "unjudged";
const NONE: &str = "none";

impl E2ePart {
    /// The closed set of words the field's value is one of.
    pub const fn words(self) -> &'static [&'static str] {
        match self {
            Self::Verdict => VERDICT_WORDS,
            Self::Crc => CRC_WORDS,
            Self::Counter => COUNTER_WORDS,
            Self::Timeout => TIMEOUT_WORDS,
        }
    }
}

/// What the end-to-end judge made of one record, in the four fields' words.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct E2eWords {
    verdict: &'static str,
    crc: Option<&'static str>,
    counter: Option<&'static str>,
    timeout: Option<&'static str>,
}

impl E2eWords {
    /// A record no profile rule judges: `e2e` is `none` and the parts are absent.
    pub const NONE: Self = Self {
        verdict: NONE,
        crc: None,
        counter: None,
        timeout: None,
    };

    /// The words of one judged frame.
    pub fn of(outcome: &Outcome) -> Self {
        let Outcome::Opened(opened) = outcome else {
            // Not a frame: no part was read. A payload too short for the header
            // is damage; one that is not a run of bytes this reader holds is a
            // carrier it does not follow, which is not a failure of the frame.
            let verdict = match outcome.unopened() {
                Some(Unopened::PayloadShorterThanHeader) => ERROR,
                Some(Unopened::PayloadNotContiguous) | None => UNJUDGED,
            };
            return Self {
                verdict,
                ..Self::NONE
            };
        };
        let crc_ok = opened.frame.crc_ok;
        let judgment = opened.judgment.as_ref();
        // The counter is read only from a frame whose CRC matched, and judged
        // only against a counter the slot accepted before it.
        let counter = match judgment {
            Some(j) if crc_ok && opened.previous.is_some() => j.counter_reason.word(),
            _ => UNJUDGED,
        };
        let timeout = match judgment.filter(|_| opened.timed) {
            Some(j) if j.timeout_error => ERROR,
            Some(_) => OK,
            None => UNJUDGED,
        };
        let failed = !crc_ok
            || judgment.is_some_and(|j| j.counter_error || (opened.timed && j.timeout_error));
        let verdict = if failed {
            ERROR
        } else if counter == UNJUDGED || timeout == UNJUDGED {
            UNJUDGED
        } else {
            OK
        };
        Self {
            verdict,
            crc: Some(if crc_ok { OK } else { ERROR }),
            counter: Some(counter),
            timeout: Some(timeout),
        }
    }

    /// The word of one field, or `None` where the record carries no such part.
    pub fn word(&self, part: E2ePart) -> Option<&'static str> {
        match part {
            E2ePart::Verdict => Some(self.verdict),
            E2ePart::Crc => self.crc,
            E2ePart::Counter => self.counter,
            E2ePart::Timeout => self.timeout,
        }
    }
}

/// Whether `message` is a published sample: a `Push` carrying a `put`, the one
/// record that is a frame when a profile rule covers its key. The field
/// document reads only these as frames, and so does every plane here.
#[cfg(feature = "network-codecs")]
pub(crate) fn is_published_sample(
    message: &wz_session_core::network_message::NetworkMessage,
) -> bool {
    matches!(
        message,
        wz_session_core::network_message::NetworkMessage::Push(_)
    ) && crate::agg::classify(message)
        .is_some_and(|(_, _, kind)| kind == crate::filter::RecordKind::Put)
}

/// What a plane that does not judge frames reads of `message`: `none` for a
/// record that carries no frame, which needs no declarations to decide, and
/// undecided for a published sample, whose verdict only the payload plane's
/// judge gives ([`crate::e2e_plane`]).
#[cfg(feature = "network-codecs")]
pub(crate) fn unjudged(
    message: &wz_session_core::network_message::NetworkMessage,
) -> Option<E2eWords> {
    (!is_published_sample(message)).then_some(E2eWords::NONE)
}
