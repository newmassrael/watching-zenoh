// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The SENDING side of an end-to-end protected message that is sent more than
//! once: a frame builder that keeps the message's counter.
//!
//! [`crate::e2e_json::wrap_document`] builds one frame from values the caller
//! wrote, the counter among them. A sender that repeats a message must advance
//! the counter on every send, and a caller that keeps the counter itself then
//! holds a second copy of the rule for when it advances. A [`Sender`] holds the
//! rule once: it is made for ONE message under ONE profile and writes the
//! profile's counter field itself.
//!
//! # The counter
//!
//! * The next value starts at the value the sender is made with, which is what
//!   a user typed or a restarted process passes again; [`Sender::set`] changes
//!   it later.
//! * A frame that is built carries the next value, and the next value then
//!   moves by one. A refusal of any kind (the profile is the sender's own and
//!   was read once, so these are the values text, the body, the length, or the
//!   counter) builds no frame and CONSUMES NO VALUE: the same frame can be asked
//!   for again after the text is corrected.
//! * The counter does not wrap by default. A frame that carries the largest
//!   value the counter field holds is built, and the next one is refused with
//!   a reason that names the field and the value ([`Rollover::Refuse`]): a
//!   wrapped counter puts a value on the wire that nobody asked for, and
//!   whether a receiver treats the step down as a legitimate wrap or as a
//!   fault is the receiver's rule, not this library's. [`Rollover::Wrap`]
//!   counts on from zero instead, and is chosen by the caller by name.
//! * A start value that does not fit the field is not judged when the sender is
//!   made: the first frame is refused like any value that does not fit (the
//!   values path is `/<field>`), and nothing is consumed.
//! * The values text must not state the counter field. A text that does is
//!   refused: there is no rule for which of the two would win.
//!
//! The counter advances by one, which every profile accepts as a forward step
//! (`max_gap` is at least one).
//!
//! One sender belongs to one message. Two messages that share a profile keep
//! two senders, and so two counters.

use alloc::string::String;

use crate::e2e_json::{plain_refusal, profile_refusal, wrap_supplied, Supplies};
use crate::e2e_profile::Profile;

/// What a sender does after a frame that carried the largest counter value.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Rollover {
    /// Refuse the next frame. The default.
    #[default]
    Refuse,
    /// Count on from zero.
    Wrap,
}

/// The frame builder of one message.
#[derive(Debug, Clone)]
pub struct Sender {
    profile: Profile,
    /// The counter field's name.
    field: String,
    /// The largest value the counter field holds.
    max: u64,
    /// The value the next frame carries; `None` after the largest value was
    /// sent under [`Rollover::Refuse`].
    next: Option<u64>,
    rollover: Rollover,
}

impl Sender {
    /// A sender for the message `profile_text` describes, whose first frame
    /// carries `first_counter`.
    ///
    /// # Errors
    ///
    /// The `e2e_wrap` refusal document, `{"ok":false,"profile_path":...}`, when
    /// the profile text is not a profile.
    pub fn new(profile_text: &str, first_counter: u64, rollover: Rollover) -> Result<Self, String> {
        let profile = Profile::parse(profile_text).map_err(|e| profile_refusal(&e))?;
        let counter = &profile.fields()[profile.counter().field];
        Ok(Self {
            field: counter.name.clone(),
            max: counter.max_value(),
            profile,
            next: Some(first_counter),
            rollover,
        })
    }

    /// The `e2e_wrap` document for one frame: the success when a frame was
    /// built (and the counter has moved on), a refusal when none was (and it
    /// has not).
    ///
    /// `values_text` and `payload` are as for [`crate::e2e_json::wrap_document`]
    /// less the counter field, which is the sender's.
    pub fn wrap(&mut self, values_text: &str, payload: &[u8]) -> String {
        let Some(counter) = self.next else {
            return plain_refusal(&alloc::format!(
                "the counter `{}` has sent its largest value, {}, and this sender \
                 does not wrap: no frame is built",
                self.field,
                self.max
            ));
        };
        let supplies = Supplies {
            field: &self.field,
            value: counter,
        };
        match wrap_supplied(&self.profile, values_text, payload, supplies) {
            Ok(document) => {
                self.next = self.after(counter);
                document
            }
            Err(refusal) => refusal,
        }
    }

    /// The value after `sent`, which a frame has just carried.
    fn after(&self, sent: u64) -> Option<u64> {
        if sent < self.max {
            Some(sent + 1)
        } else {
            match self.rollover {
                Rollover::Wrap => Some(0),
                Rollover::Refuse => None,
            }
        }
    }

    /// The value the next frame carries; `None` when the largest value was
    /// sent and this sender does not wrap.
    pub fn next(&self) -> Option<u64> {
        self.next
    }

    /// Make `value` the one the next frame carries. A value past the field's
    /// width is accepted here and refused by the frame, as a start value is.
    pub fn set(&mut self, value: u64) {
        self.next = Some(value);
    }

    /// The counter field's name in the profile.
    pub fn counter_field(&self) -> &str {
        &self.field
    }

    /// The largest value the counter field holds.
    pub fn counter_max(&self) -> u64 {
        self.max
    }
}
