// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The SENDING side of an end-to-end protected message, kept per stream: a
//! payload protected under a profile and the caller's header values, with the
//! counter the sender keeps for each stream it sends on.
//!
//! [`crate::e2e_frame::build`] builds one frame from values that include the
//! counter. A node that repeats a message, and sends it on several streams (the
//! instances of one message), keeps a counter per stream; a [`StreamSender`] is
//! that rule written once. Its header values are fixed when it is made, the
//! counter field excepted: a message whose header values change is another
//! sender.
//!
//! # The counter
//!
//! * Every stream starts at the same first value. A frame that is built
//!   carries its stream's next value, which then moves by one. A refusal of any
//!   kind builds no frame and consumes no value.
//! * After the largest value the counter field holds, the stream's next frame
//!   is refused under [`Rollover::Refuse`] and counts on from zero under
//!   [`Rollover::Wrap`].
//! * A first value, or a value [`StreamSender::set`] is given, that does not fit
//!   the counter field is refused there, by name.
//! * The values must not state the counter field: there would be no rule for
//!   which of the two wins.
//!
//! # The CRC cache
//!
//! A periodic message often sends the same payload again. With the cache on,
//! each stream keeps the frame it last built and the CRC register after the
//! covered pieces that come before the counter in the profile's feeding order:
//! those pieces cannot change while the payload does not, since every other
//! header value is fixed and the length follows the payload. A frame for an
//! unchanged payload is then the kept frame with the new counter written in,
//! and its CRC is the kept register fed only the pieces from the counter on. It
//! is the same CRC by construction, because feeding is associative
//! ([`crate::e2e_crc::Crc::resume`]); the tests compare it, byte for byte, with
//! the full computation of [`crate::e2e_frame::build`], which stays the
//! reference.

use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;

use crate::e2e_frame::{build, feed, write_be, BuildError, Values};
use crate::e2e_profile::{Cover, Profile};

/// What a stream does after the frame that carried the largest counter value.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Rollover {
    /// Refuse the next frame. The default.
    #[default]
    Refuse,
    /// Count on from zero.
    Wrap,
}

/// How a sender is made.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SenderOptions {
    /// How many streams the sender keeps a counter for, at least 1.
    pub streams: usize,
    /// The value the first frame of every stream carries.
    pub first_counter: u64,
    /// What a stream does after its largest value.
    pub rollover: Rollover,
    /// Whether a stream keeps its last frame to protect an unchanged payload
    /// again without the full CRC computation.
    pub crc_cache: bool,
}

impl Default for SenderOptions {
    fn default() -> Self {
        Self {
            streams: 1,
            first_counter: 0,
            rollover: Rollover::Refuse,
            crc_cache: false,
        }
    }
}

/// Why a sender was not made, or a frame not built.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SendError {
    /// The header values, or the payload, are refused as a build refuses them.
    Build(BuildError),
    /// The values state the counter field, which is the sender's.
    CounterStated {
        /// The counter field.
        field: String,
    },
    /// A counter value that does not fit the counter field.
    CounterDoesNotFit {
        /// The value given.
        value: u64,
        /// The largest the field holds.
        max: u64,
    },
    /// A sender of no stream.
    NoStreams,
    /// A stream the sender does not have.
    NoSuchStream {
        /// The stream asked for.
        stream: usize,
        /// How many the sender has.
        streams: usize,
    },
    /// The stream sent its largest value and does not wrap.
    Spent {
        /// The stream.
        stream: usize,
        /// The value it last sent.
        max: u64,
    },
}

impl core::fmt::Display for SendError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Build(e) => write!(f, "{e}"),
            Self::CounterStated { field } => write!(
                f,
                "/{field}: the sender keeps the counter field `{field}`, so the values must \
                 not state it"
            ),
            Self::CounterDoesNotFit { value, max } => write!(
                f,
                "the counter value {value} does not fit the counter field (largest {max})"
            ),
            Self::NoStreams => f.write_str("a sender keeps at least one stream"),
            Self::NoSuchStream { stream, streams } => write!(
                f,
                "stream {stream} is not one of the sender's {streams} streams"
            ),
            Self::Spent { stream, max } => write!(
                f,
                "stream {stream} has sent its largest counter value, {max}, and this sender \
                 does not wrap: no frame is built"
            ),
        }
    }
}

/// What one stream keeps.
#[derive(Debug, Clone)]
struct Stream {
    /// The value its next frame carries; `None` once spent.
    next: Option<u64>,
    /// The frame it last built and the CRC register before the counter, when
    /// the cache is on and a frame was built.
    cached: Option<Cached>,
}

#[derive(Debug, Clone)]
struct Cached {
    frame: Vec<u8>,
    register: u64,
}

/// A frame the sender built.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Protected {
    /// The frame: header, then the payload.
    pub bytes: Vec<u8>,
    /// The counter it carries.
    pub counter: u64,
    /// Whether it was built from the stream's cache.
    pub from_cache: bool,
}

/// The sender of one message under one profile.
#[derive(Debug, Clone)]
pub struct StreamSender {
    profile: Profile,
    values: Values,
    counter_field: usize,
    max: u64,
    rollover: Rollover,
    crc_cache: bool,
    /// How many covered pieces come before the counter in the feeding order:
    /// the part of the CRC the cache keeps.
    prefix: usize,
    streams: Vec<Stream>,
}

impl StreamSender {
    /// A sender of `profile`'s frames whose fixed header values are `values`.
    ///
    /// The values are checked here by building a frame with an empty payload,
    /// so a value missing, of the wrong shape, or that does not fit, and a
    /// derived field with no address, are refused now and not at the first
    /// send.
    pub fn new(
        profile: Profile,
        values: Values,
        options: SenderOptions,
    ) -> Result<Self, SendError> {
        if options.streams == 0 {
            return Err(SendError::NoStreams);
        }
        let counter_field = profile.counter().field;
        let field = &profile.fields()[counter_field];
        if values.states(&field.name) {
            return Err(SendError::CounterStated {
                field: field.name.clone(),
            });
        }
        let max = field.max_value();
        if options.first_counter > max {
            return Err(SendError::CounterDoesNotFit {
                value: options.first_counter,
                max,
            });
        }
        let trial = values.clone().whole(&field.name, 0);
        build(&profile, &trial, &[]).map_err(SendError::Build)?;
        let prefix = profile
            .crc()
            .cover
            .iter()
            .position(|&c| c == Cover::Field(counter_field))
            .unwrap_or(profile.crc().cover.len());
        let streams = (0..options.streams)
            .map(|_| Stream {
                next: Some(options.first_counter),
                cached: None,
            })
            .collect();
        Ok(Self {
            profile,
            values,
            counter_field,
            max,
            rollover: options.rollover,
            crc_cache: options.crc_cache,
            prefix,
            streams,
        })
    }

    /// The profile the sender builds under.
    pub fn profile(&self) -> &Profile {
        &self.profile
    }

    /// How many streams it keeps.
    pub fn streams(&self) -> usize {
        self.streams.len()
    }

    fn stream(&self, stream: usize) -> Result<&Stream, SendError> {
        self.streams.get(stream).ok_or(SendError::NoSuchStream {
            stream,
            streams: self.streams.len(),
        })
    }

    /// The value the stream's next frame carries; `None` when it is spent.
    pub fn next(&self, stream: usize) -> Result<Option<u64>, SendError> {
        self.stream(stream).map(|s| s.next)
    }

    /// Make `value` the one the stream's next frame carries.
    pub fn set(&mut self, stream: usize, value: u64) -> Result<(), SendError> {
        if value > self.max {
            return Err(SendError::CounterDoesNotFit {
                value,
                max: self.max,
            });
        }
        self.stream(stream)?;
        self.streams[stream].next = Some(value);
        Ok(())
    }

    /// The size of the frame that protects a payload of `payload_bytes`.
    pub fn frame_bytes(&self, payload_bytes: usize) -> usize {
        self.profile.header_bytes() + payload_bytes
    }

    /// Protect `payload` on `stream`: the frame, with the stream's counter, and
    /// the counter moved on. A refusal consumes no counter value.
    pub fn protect(&mut self, stream: usize, payload: &[u8]) -> Result<Protected, SendError> {
        let Some(counter) = self.stream(stream)?.next else {
            return Err(SendError::Spent {
                stream,
                max: self.max,
            });
        };
        let header = self.profile.header_bytes();
        let hit = self.streams[stream]
            .cached
            .as_ref()
            .filter(|c| c.frame[header..] == *payload);
        let (bytes, from_cache) = match hit {
            Some(cached) => (self.rebuild_cached(cached, counter), true),
            None => (self.full(stream, counter, payload)?, false),
        };
        self.streams[stream].next = self.after(counter);
        Ok(Protected {
            bytes,
            counter,
            from_cache,
        })
    }

    /// The frame for `payload` with `counter` by the full computation, kept in
    /// the stream's cache when the cache is on.
    fn full(&mut self, stream: usize, counter: u64, payload: &[u8]) -> Result<Vec<u8>, SendError> {
        let name = &self.profile.fields()[self.counter_field].name;
        let values = self.values.clone().whole(name, counter);
        let built = build(&self.profile, &values, payload).map_err(SendError::Build)?;
        if self.crc_cache {
            let mut digest = self.profile.crc().engine.start();
            for &item in &self.profile.crc().cover[..self.prefix] {
                feed(&self.profile, &mut digest, item, &built.bytes);
            }
            let register = digest.register();
            self.streams[stream].cached = Some(Cached {
                frame: built.bytes.clone(),
                register,
            });
        }
        Ok(built.bytes)
    }

    /// The frame for the cached payload with `counter`: the kept frame with the
    /// counter written in, its CRC resumed from the kept register.
    fn rebuild_cached(&self, cached: &Cached, counter: u64) -> Vec<u8> {
        let fields = self.profile.fields();
        let mut bytes = cached.frame.clone();
        let field = &fields[self.counter_field];
        write_be(
            &mut bytes[field.offset..field.offset + field.bytes],
            counter ^ field.xor,
        );
        let crc = self.profile.crc();
        let mut digest = crc.engine.resume(cached.register);
        for &item in &crc.cover[self.prefix..] {
            feed(&self.profile, &mut digest, item, &bytes);
        }
        let value = digest.finish();
        let crc_field = &fields[crc.field];
        write_be(
            &mut bytes[crc_field.offset..crc_field.offset + crc_field.bytes],
            value,
        );
        bytes
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
}

/// The refusal text of a sender that was not made, beginning with what was
/// refused, for a door that reports it as a string.
pub fn describe(error: &SendError) -> String {
    match error {
        SendError::Build(e) => format!("values: {e}"),
        stated @ SendError::CounterStated { .. } => format!("values: {stated}"),
        other => format!("{other}"),
    }
}
