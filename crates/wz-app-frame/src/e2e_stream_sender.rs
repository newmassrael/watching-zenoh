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

use crate::e2e_frame::{build, crc_over, feed, write_be, BuildError, Values};
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

/// Why a sender, or a frame, was refused.
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
    /// The buffer a frame is written into is shorter than the frame.
    Capacity {
        /// The frame's bytes.
        need: usize,
        /// The buffer's.
        have: usize,
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
            Self::Capacity { need, have } => write!(
                f,
                "the frame is {need} bytes and the buffer it is written into holds {have}"
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

/// A frame the sender wrote into a buffer the caller holds: how many of its bytes the frame is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Written {
    /// The frame's bytes, from the start of the buffer.
    pub len: usize,
    /// The counter it carries.
    pub counter: u64,
    /// Whether it was built from the stream's cache.
    pub from_cache: bool,
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
    /// The header every frame starts from, made when the sender is: each field written from the
    /// values, the counter, the length and the CRC written again for each frame.
    header: Vec<u8>,
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
        let header = build(&profile, &values.whole(&field.name, 0), &[])
            .map_err(SendError::Build)?
            .bytes;
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
            header,
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
    /// the counter moved on. A refusal consumes no counter value. [`Self::protect_into`] into a
    /// buffer made here.
    pub fn protect(&mut self, stream: usize, payload: &[u8]) -> Result<Protected, SendError> {
        let mut bytes = alloc::vec![0u8; self.frame_bytes(payload.len())];
        let written = self.protect_into(stream, payload, &mut bytes)?;
        Ok(Protected {
            bytes,
            counter: written.counter,
            from_cache: written.from_cache,
        })
    }

    /// Protect `payload` on `stream` into `out`, from its start: the frame, with the stream's
    /// counter, and the counter moved on. Nothing is allocated: the header is the one the sender
    /// made when it was made, and a frame the cache keeps is kept in the buffer it was kept in
    /// before. A buffer shorter than the frame is refused, and a refusal of any kind consumes no
    /// counter value.
    pub fn protect_into(
        &mut self,
        stream: usize,
        payload: &[u8],
        out: &mut [u8],
    ) -> Result<Written, SendError> {
        let Some(counter) = self.stream(stream)?.next else {
            return Err(SendError::Spent {
                stream,
                max: self.max,
            });
        };
        let len = self.frame_bytes(payload.len());
        let have = out.len();
        let Some(out) = out.get_mut(..len) else {
            return Err(SendError::Capacity { need: len, have });
        };
        let header = self.header.len();
        let hit = self.streams[stream]
            .cached
            .as_ref()
            .filter(|c| c.frame[header..] == *payload);
        let from_cache = match hit {
            Some(cached) => {
                out.copy_from_slice(&cached.frame);
                self.finish_cached(out, cached.register, counter);
                true
            }
            None => {
                self.full(stream, counter, payload, out)?;
                false
            }
        };
        self.streams[stream].next = self.after(counter);
        Ok(Written {
            len,
            counter,
            from_cache,
        })
    }

    /// The frame for `payload` with `counter` by the full computation, written into `out` (the
    /// frame's length) and kept in the stream's cache when the cache is on. The same frame
    /// [`build`] makes: every field but the counter, the length and the CRC is the header's.
    fn full(
        &mut self,
        stream: usize,
        counter: u64,
        payload: &[u8],
        out: &mut [u8],
    ) -> Result<(), SendError> {
        let fields = self.profile.fields();
        let length_field = &fields[self.profile.length().field];
        let length = self.profile.length_for(payload.len());
        if length > length_field.max_value() {
            return Err(SendError::Build(BuildError::PayloadTooLong {
                payload_bytes: payload.len(),
                length,
                field: length_field.name.clone(),
                field_bytes: length_field.bytes,
                max: length_field.max_value(),
            }));
        }
        let header = self.header.len();
        out[..header].copy_from_slice(&self.header);
        out[header..].copy_from_slice(payload);
        let write = |out: &mut [u8], index: usize, raw: u64| {
            let field = &fields[index];
            write_be(&mut out[field.offset..field.offset + field.bytes], raw);
        };
        write(out, self.profile.length().field, length ^ length_field.xor);
        let counter_field = &fields[self.counter_field];
        write(out, self.counter_field, counter ^ counter_field.xor);
        // As `build` writes it: the CRC field holds its `xor` while the CRC is computed.
        let crc_at = self.profile.crc().field;
        write(out, crc_at, fields[crc_at].xor);
        let crc = crc_over(&self.profile, out);
        write(out, crc_at, crc);
        if self.crc_cache {
            let mut digest = self.profile.crc().engine.start();
            for &item in &self.profile.crc().cover[..self.prefix] {
                feed(&self.profile, &mut digest, item, out);
            }
            let register = digest.register();
            let kept = &mut self.streams[stream].cached;
            if let Some(cached) = kept {
                // The buffer the stream kept is written again, so a payload of the size it held
                // before takes no allocation.
                cached.frame.clear();
                cached.frame.extend_from_slice(out);
                cached.register = register;
            } else {
                *kept = Some(Cached {
                    frame: out.to_vec(),
                    register,
                });
            }
        }
        Ok(())
    }

    /// The kept frame, already in `out`, with `counter` written in and its CRC: the kept register
    /// fed the covered pieces from the counter on.
    fn finish_cached(&self, out: &mut [u8], register: u64, counter: u64) {
        let fields = self.profile.fields();
        let field = &fields[self.counter_field];
        write_be(
            &mut out[field.offset..field.offset + field.bytes],
            counter ^ field.xor,
        );
        let crc = self.profile.crc();
        let mut digest = crc.engine.resume(register);
        for &item in &crc.cover[self.prefix..] {
            feed(&self.profile, &mut digest, item, out);
        }
        let value = digest.finish();
        let crc_field = &fields[crc.field];
        write_be(
            &mut out[crc_field.offset..crc_field.offset + crc_field.bytes],
            value,
        );
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
