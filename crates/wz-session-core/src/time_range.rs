// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The grammar of zenoh's `_time` selector parameter ([`crate::selector_params::TIME_RANGE_PARAM`]),
//! its resolution against "now", and the membership test: one reading for every wz crate.
//!
//! Two crates read the parameter. `wz-zenoh-util` is upstream zenoh-util's API, whose
//! `TimeRange` parses through [`parse_range`] and turns a [`RangeError`] back into upstream's
//! message; `wz-ext-pubsub` filters the advanced publisher's cache with it. Each held a grammar of
//! its own until 2026-11-19, and the two disagreed on a fixed start with a negative `;` duration.
//!
//! ## Grammar
//!
//! - range: `<[|]><start?>..<end?><[|]>`; omitting a side leaves it unbounded.
//! - duration: `<[|]><start>;<duration><[|]>`, which is `<start>..<start+duration>`. The start
//!   must be present.
//! - a bracket pointing INTO the range is inclusive, one pointing OUT is exclusive: `[a..b[`
//!   holds `a` and not `b`.
//! - a time is either `now(<-?><duration?>)` or an RFC3339 UTC timestamp, read as humantime's
//!   `parse_rfc3339_weak` reads it ([`parse_rfc3339_weak`]).
//! - a duration is a float of seconds, or a float with one of `u ms s m h d w`. The float is
//!   `f64::from_str`'s grammar, read by the reader the caller names ([`FloatRead`]): core's
//!   ([`core_float`]), or a platform's C reader handed the literal as [`decimal_text`] copies it.
//!
//! ## Where this differs from upstream
//!
//! Upstream PANICS on inputs an attacker-chosen query parameter can reach: a bare `s` as a
//! duration (it reads past the front of the text), and a `;` duration added to a fixed start when
//! the duration is negative, not a number, infinite, or past what the instant type holds (it adds
//! with `Add`, which panics). Here a bare `s` is a refused duration ([`DurationError::Float`]); a
//! negative duration moves a fixed start back, as it already moves a `now(..)` start back
//! upstream, so the end lies before the start and the range holds nothing; and a sum no instant
//! holds is [`RangeError::EndUnrepresentable`].
//!
//! ## The instant type
//!
//! This crate has no clock and no `SystemTime`. The caller names its instant type through a
//! [`Clock`], and every sum is that type's own checked arithmetic, so the instants a range can
//! reach are exactly the ones the caller's type holds (a `SystemTime` holds a different span on
//! each platform).

use core::fmt;
use core::time::Duration;

const U_TO_SECS: f64 = 0.000001;
const MS_TO_SECS: f64 = 0.001;
const M_TO_SECS: f64 = 60.0;
const H_TO_SECS: f64 = M_TO_SECS * 60.0;
const D_TO_SECS: f64 = H_TO_SECS * 24.0;
const W_TO_SECS: f64 = D_TO_SECS * 7.0;

/// The last second of year 9999, the bound humantime's `parse_rfc3339_weak` enforces on a 64-bit
/// target.
const RFC3339_MAX_SECONDS: u64 = 253_402_300_800 - 1;

/// The instant type a caller reads ranges in, and its checked arithmetic.
pub trait Clock {
    /// An instant.
    type Instant: Copy + PartialOrd;
    /// The instant `since_epoch` after 1970-01-01T00:00:00Z. Called with no more than the end of
    /// year 9999, which every instant type a wz build reads ranges in holds.
    fn from_unix(since_epoch: Duration) -> Self::Instant;
    /// `at + by`, `None` where the instant type cannot hold it.
    fn checked_add(at: Self::Instant, by: Duration) -> Option<Self::Instant>;
    /// `at - by`, `None` where the instant type cannot hold it.
    fn checked_sub(at: Self::Instant, by: Duration) -> Option<Self::Instant>;
}

/// `at` moved by `secs` seconds, forward or back: `None` where the instant type cannot hold the
/// result, and where `secs` is not a number or is infinite.
pub fn add_secs<C: Clock>(at: C::Instant, secs: f64) -> Option<C::Instant> {
    if secs >= 0.0 {
        Duration::try_from_secs_f64(secs)
            .ok()
            .and_then(|d| C::checked_add(at, d))
    } else {
        Duration::try_from_secs_f64(-secs)
            .ok()
            .and_then(|d| C::checked_sub(at, d))
    }
}

/// One end of a range. A bracket pointing out of the range is exclusive.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum Edge<T> {
    /// The end is part of the range.
    Inclusive(T),
    /// The end is the first instant outside the range.
    Exclusive(T),
    /// The range extends without limit in this direction.
    Unbounded,
}

/// A time as the selector spells it: an instant, or an offset from the moment the range is
/// evaluated.
#[derive(Debug, Copy, Clone, PartialEq)]
pub enum TimeExpr<I> {
    /// An RFC3339 instant.
    Fixed(I),
    /// `now(<offset>)`, the offset in seconds (negative reaches into the past).
    Now {
        /// Seconds added to the evaluation instant.
        offset_secs: f64,
    },
}

/// A parsed `_time` range. `T` is a [`TimeExpr`] until the offsets are resolved and an instant
/// after.
#[derive(Debug, Copy, Clone, PartialEq)]
pub struct TimeRange<T> {
    /// The lower end.
    pub start: Edge<T>,
    /// The upper end.
    pub end: Edge<T>,
}

/// Why humantime's `parse_rfc3339_weak` refuses a timestamp, with its words.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum Rfc3339Error {
    /// A number is outside its field's range, or the instant is past year 9999.
    OutOfRange,
    /// A byte where a digit is read is not one.
    InvalidDigit,
    /// The text does not have the shape of a timestamp.
    InvalidFormat,
}

impl fmt::Display for Rfc3339Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Rfc3339Error::OutOfRange => "numeric component is out of range",
            Rfc3339Error::InvalidDigit => "bad character where digit is expected",
            Rfc3339Error::InvalidFormat => "timestamp format is invalid",
        })
    }
}

impl core::error::Error for Rfc3339Error {}

/// Why the number of a duration is refused: the two refusals of `f64::from_str`, in its words, so
/// a refusal reads the same whichever reader read the number.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum FloatError {
    /// The number is empty.
    Empty,
    /// The text is not a float literal.
    Invalid,
}

impl fmt::Display for FloatError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            FloatError::Empty => "cannot parse float from empty string",
            FloatError::Invalid => "invalid float literal",
        })
    }
}

impl core::error::Error for FloatError {}

/// A reader of the number of a duration: it admits what `f64::from_str` admits and reads it to
/// the same value.
pub type FloatRead = fn(&str) -> Result<f64, FloatError>;

/// Core's reader, `f64::from_str`.
pub fn core_float(text: &str) -> Result<f64, FloatError> {
    text.parse::<f64>().map_err(|_| {
        if text.is_empty() {
            FloatError::Empty
        } else {
            FloatError::Invalid
        }
    })
}

/// The significant digits that decide how a decimal rounds to an `f64`: a halfway point between
/// two `f64`s has at most 767, so a literal's first 768 and whether any digit past them is nonzero
/// round as the whole literal does. Core's reader keeps the same digits (`DecimalSeq::MAX_DIGITS`
/// of its `dec2flt`).
pub const DECIMAL_DIGITS: usize = 768;

/// The largest power of ten [`decimal_digits`] writes: past it every `f64` is an infinity or a
/// zero.
const DECIMAL_EXPONENT: i64 = 99_999;

/// The bytes a literal is handed to a platform's C reader in: a sign, [`DECIMAL_DIGITS`] digits
/// and a sticky one, an `e`, the exponent's sign and its five digits, and the terminating NUL. A
/// literal shorter than this is copied whole ([`decimal_text`]).
pub const DECIMAL_TEXT: usize = 1 + DECIMAL_DIGITS + 1 + 1 + 1 + 5 + 1;

/// What [`decimal_text`] or [`decimal_digits`] made of a literal.
#[derive(Debug, Copy, Clone, PartialEq)]
pub enum Decimal {
    /// Read with no reader: an infinity, a NaN or a zero.
    Read(f64),
    /// Written in the buffer, this many bytes before its NUL.
    Written(usize),
}

/// `text` checked against `f64::from_str`'s grammar, and a number in it handed to a platform's C
/// reader (`strtod`) as zenoh-pico hands it: a copy of the literal's own bytes in `out`,
/// NUL-terminated, so the reader reads the literal and nothing past it, and rounds it as it
/// rounds every literal (`vendor/zenoh-pico/src/utils/time_range.c` @
/// `double value = strtod(bound->start, &err);`). A literal too long for `out` is written as
/// [`decimal_digits`] writes it, which rounds as the literal does.
///
/// The copy keeps the literal's radix character, which a C library reads in the locale the
/// program set: a reader that stops before the end of the copy is reading another radix, and the
/// caller reads the literal again as [`decimal_digits`] writes it, with none.
pub fn decimal_text(text: &str, out: &mut [u8; DECIMAL_TEXT]) -> Result<Decimal, FloatError> {
    let decimal = decimal_digits(text, out)?;
    let bytes = text.as_bytes();
    match decimal {
        Decimal::Written(_) => match out.get_mut(..=bytes.len()).and_then(<[u8]>::split_last_mut) {
            Some((nul, copy)) => {
                copy.copy_from_slice(bytes);
                *nul = 0;
                Ok(Decimal::Written(bytes.len()))
            }
            None => Ok(decimal),
        },
        Decimal::Read(_) => Ok(decimal),
    }
}

/// `text` checked against `f64::from_str`'s grammar, and a number in it written in `out` for a
/// platform's C reader: an integer of its significant digits and a power of ten, with no radix
/// character, so no locale reads it otherwise, NUL-terminated. Past [`DECIMAL_DIGITS`] significant
/// digits a nonzero one, if any, is written as one more digit `1`; no halfway point between two
/// `f64`s lies between the literal and what is written, so the two round alike.
pub fn decimal_digits(text: &str, out: &mut [u8; DECIMAL_TEXT]) -> Result<Decimal, FloatError> {
    let bytes = text.as_bytes();
    if bytes.is_empty() {
        return Err(FloatError::Empty);
    }
    let (negative, unsigned) = split_sign(bytes);
    if unsigned.eq_ignore_ascii_case(b"inf") || unsigned.eq_ignore_ascii_case(b"infinity") {
        return Ok(Decimal::Read(if negative {
            f64::NEG_INFINITY
        } else {
            f64::INFINITY
        }));
    }
    if unsigned.eq_ignore_ascii_case(b"nan") {
        return Ok(Decimal::Read(if negative { -f64::NAN } else { f64::NAN }));
    }
    let (integer, rest) = split_digits(unsigned);
    let (fraction, rest) = match rest.split_first() {
        Some((b'.', after)) => split_digits(after),
        _ => (&[][..], rest),
    };
    if integer.is_empty() && fraction.is_empty() {
        return Err(FloatError::Invalid);
    }
    let exponent = match rest.split_first() {
        None => 0,
        Some((b'e' | b'E', after)) => read_exponent(after)?,
        Some(_) => return Err(FloatError::Invalid),
    };

    let mut sink = Sink { out, len: 0 };
    if negative {
        sink.push(b'-')?;
    }
    // The literal is the integer of the digits kept times ten to `scale`. Every step of `scale`
    // is one byte of the literal, so it stays far inside an `i64` and the saturating forms are the
    // exact ones.
    let mut scale: i64 = 0;
    let mut kept = 0usize;
    let mut sticky = false;
    let digits = integer.iter().map(|digit| (*digit, false));
    for (digit, fraction) in digits.chain(fraction.iter().map(|digit| (*digit, true))) {
        if kept == 0 && digit == b'0' {
            // A leading zero: in the fraction it moves the point.
            if fraction {
                scale = scale.saturating_sub(1);
            }
        } else if kept < DECIMAL_DIGITS {
            sink.push(digit)?;
            kept = kept.saturating_add(1);
            if fraction {
                scale = scale.saturating_sub(1);
            }
        } else {
            sticky |= digit != b'0';
            if !fraction {
                scale = scale.saturating_add(1);
            }
        }
    }
    if kept == 0 {
        return Ok(Decimal::Read(if negative { -0.0 } else { 0.0 }));
    }
    if sticky {
        sink.push(b'1')?;
        scale = scale.saturating_sub(1);
    }
    let power = scale
        .saturating_add(exponent)
        .clamp(-DECIMAL_EXPONENT, DECIMAL_EXPONENT);
    if power != 0 {
        sink.push(b'e')?;
        if power < 0 {
            sink.push(b'-')?;
        }
        // At most `DECIMAL_EXPONENT`, five digits; the leading zeros of the five are not written,
        // and `power` is not zero, so a digit is.
        let magnitude = power.unsigned_abs();
        let places = [
            magnitude / 10_000 % 10,
            magnitude / 1_000 % 10,
            magnitude / 100 % 10,
            magnitude / 10 % 10,
            magnitude % 10,
        ];
        for place in places.into_iter().skip_while(|place| *place == 0) {
            // An ASCII digit is `0x30` with its value, below ten, in the low four bits.
            sink.push(b'0' | place as u8)?;
        }
    }
    sink.end()
}

/// The bytes [`decimal_digits`] has written in its buffer.
struct Sink<'a> {
    out: &'a mut [u8; DECIMAL_TEXT],
    len: usize,
}

impl Sink<'_> {
    /// `byte` after the bytes written. [`DECIMAL_TEXT`] is the longest form written, NUL
    /// included, so no byte is offered past the end; one would be refused, not cut, so a
    /// [`Decimal::Written`] length always has its NUL after it.
    fn push(&mut self, byte: u8) -> Result<(), FloatError> {
        let slot = self.out.get_mut(self.len).ok_or(FloatError::Invalid)?;
        *slot = byte;
        // `len` indexed a byte of the buffer, so one more is still a length of it.
        self.len = self.len.saturating_add(1);
        Ok(())
    }

    /// The NUL after the bytes written, and their count.
    fn end(mut self) -> Result<Decimal, FloatError> {
        let len = self.len;
        self.push(0)?;
        Ok(Decimal::Written(len))
    }
}

/// A sign at the front of `text`, if any, and the rest: whether it is `-`.
fn split_sign(text: &[u8]) -> (bool, &[u8]) {
    match text.split_first() {
        Some((b'-', rest)) => (true, rest),
        Some((b'+', rest)) => (false, rest),
        _ => (false, text),
    }
}

/// The ASCII digits at the front of `text`, and the rest.
fn split_digits(text: &[u8]) -> (&[u8], &[u8]) {
    let count = text.iter().take_while(|byte| byte.is_ascii_digit()).count();
    (
        text.get(..count).unwrap_or_default(),
        text.get(count..).unwrap_or_default(),
    )
}

/// The exponent of a literal, from the text after its `e`: a sign if any and one digit or more,
/// with nothing after them. Its magnitude is held at `u32::MAX`: past it, as past
/// [`DECIMAL_EXPONENT`], every power of ten is written alike.
fn read_exponent(text: &[u8]) -> Result<i64, FloatError> {
    let (negative, unsigned) = split_sign(text);
    let (digits, rest) = split_digits(unsigned);
    if digits.is_empty() || !rest.is_empty() {
        return Err(FloatError::Invalid);
    }
    let magnitude = digits.iter().fold(0i64, |number, digit| {
        // An ASCII digit's value is its low four bits.
        number
            .saturating_mul(10)
            .saturating_add(i64::from(digit & 0x0f))
            .min(i64::from(u32::MAX))
    });
    Ok(if negative {
        magnitude.saturating_neg()
    } else {
        magnitude
    })
}

/// Why a duration is refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DurationError<'a> {
    /// The duration is empty.
    Empty,
    /// The number before the unit (or the whole text, with no unit) is not a float.
    Float {
        /// The duration's whole text, unit included.
        text: &'a str,
        /// What the float reader said.
        error: FloatError,
    },
}

/// Why a time is refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TimeError<'a> {
    /// The time's whole text.
    pub text: &'a str,
    /// What was wrong with it.
    pub cause: TimeCause<'a>,
}

/// What was wrong with a refused time.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TimeCause<'a> {
    /// The duration of a `now(..)`.
    Duration(DurationError<'a>),
    /// The timestamp.
    Instant(Rfc3339Error),
}

/// Why a range is refused, in the order upstream's parser looks.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RangeError<'a> {
    /// Shorter than `[..]`.
    TooShort,
    /// The first character is neither `[` nor `]`.
    BadStart,
    /// The last character is neither `[` nor `]`.
    BadEnd,
    /// A side is not a time.
    Time(TimeError<'a>),
    /// The duration after `;` is not one.
    Duration(DurationError<'a>),
    /// A `;` range with no start.
    NoStart {
        /// The text between the brackets.
        inner: &'a str,
    },
    /// The start moved by the duration is an instant the caller's type cannot hold.
    EndUnrepresentable {
        /// The text between the brackets.
        inner: &'a str,
    },
    /// Neither `..` nor `;` separates the sides.
    NoSeparator {
        /// The text between the brackets.
        inner: &'a str,
    },
}

impl<I: Copy> TimeExpr<I> {
    /// The instant this expression names at `now`: `None` where an offset moves `now` past what
    /// the instant type holds.
    pub fn resolve_at<C: Clock<Instant = I>>(self, now: I) -> Option<I> {
        match self {
            TimeExpr::Fixed(t) => Some(t),
            TimeExpr::Now { offset_secs } => add_secs::<C>(now, offset_secs),
        }
    }

    /// This expression moved by `secs` seconds, forward or back: `None` where a fixed instant
    /// moves past what the instant type holds. An offset only adds.
    pub fn checked_add<C: Clock<Instant = I>>(self, secs: f64) -> Option<Self> {
        match self {
            TimeExpr::Fixed(t) => add_secs::<C>(t, secs).map(TimeExpr::Fixed),
            TimeExpr::Now { offset_secs } => Some(TimeExpr::Now {
                offset_secs: offset_secs + secs,
            }),
        }
    }
}

impl<I: Copy> Edge<TimeExpr<I>> {
    /// The end at `now`. An offset that lands outside what the instant type holds becomes an
    /// UNBOUNDED end, not an error and not a clamp: that is upstream's answer, and a clamp would
    /// turn `now(-1000000d)` used as an upper bound into "nothing".
    pub fn resolve_at<C: Clock<Instant = I>>(self, now: I) -> Edge<I> {
        match self {
            Edge::Inclusive(t) => t
                .resolve_at::<C>(now)
                .map_or(Edge::Unbounded, Edge::Inclusive),
            Edge::Exclusive(t) => t
                .resolve_at::<C>(now)
                .map_or(Edge::Unbounded, Edge::Exclusive),
            Edge::Unbounded => Edge::Unbounded,
        }
    }
}

impl<I: Copy> TimeRange<TimeExpr<I>> {
    /// The range at `now`.
    pub fn resolve_at<C: Clock<Instant = I>>(self, now: I) -> TimeRange<I> {
        TimeRange {
            start: self.start.resolve_at::<C>(now),
            end: self.end.resolve_at::<C>(now),
        }
    }
}

impl<I: Copy + PartialOrd> TimeRange<I> {
    /// Whether `instant` lies in the range.
    pub fn contains(&self, instant: I) -> bool {
        match self.start {
            Edge::Inclusive(t) if t > instant => return false,
            Edge::Exclusive(t) if t >= instant => return false,
            _ => {}
        }
        match self.end {
            Edge::Inclusive(t) => t >= instant,
            Edge::Exclusive(t) => t > instant,
            Edge::Unbounded => true,
        }
    }
}

/// Parse a `_time` value, its numbers read by core's reader.
pub fn parse_range<C: Clock>(s: &str) -> Result<TimeRange<TimeExpr<C::Instant>>, RangeError<'_>> {
    parse_range_with::<C>(s, core_float)
}

/// Parse a `_time` value, its numbers read by `read`.
pub fn parse_range_with<C: Clock>(
    s: &str,
    read: FloatRead,
) -> Result<TimeRange<TimeExpr<C::Instant>>, RangeError<'_>> {
    // The shortest range is `[..]`.
    let len = s.len();
    if len < 4 {
        return Err(RangeError::TooShort);
    }
    let mut chars = s.chars();
    let inclusive_start = match chars.next() {
        Some('[') => true,
        Some(']') => false,
        _ => return Err(RangeError::BadStart),
    };
    let inclusive_end = match chars.next_back() {
        Some(']') => true,
        Some('[') => false,
        _ => return Err(RangeError::BadEnd),
    };
    let inner = chars.as_str();
    if let Some((start, end)) = inner.split_once("..") {
        Ok(TimeRange {
            start: parse_edge::<C>(start, inclusive_start, read)?,
            end: parse_edge::<C>(end, inclusive_end, read)?,
        })
    } else if let Some((start, duration)) = inner.split_once(';') {
        // Upstream reads the start, then the duration, then asks whether there was a start.
        let start = parse_edge::<C>(start, inclusive_start, read)?;
        let secs = parse_duration_with(duration, read).map_err(RangeError::Duration)?;
        let end_time = match start {
            Edge::Inclusive(t) | Edge::Exclusive(t) => t
                .checked_add::<C>(secs)
                .ok_or(RangeError::EndUnrepresentable { inner })?,
            Edge::Unbounded => return Err(RangeError::NoStart { inner }),
        };
        let end = if inclusive_end {
            Edge::Inclusive(end_time)
        } else {
            Edge::Exclusive(end_time)
        };
        Ok(TimeRange { start, end })
    } else {
        Err(RangeError::NoSeparator { inner })
    }
}

fn parse_edge<C: Clock>(
    s: &str,
    inclusive: bool,
    read: FloatRead,
) -> Result<Edge<TimeExpr<C::Instant>>, RangeError<'_>> {
    if s.is_empty() {
        return Ok(Edge::Unbounded);
    }
    let t = parse_time_with::<C>(s, read).map_err(RangeError::Time)?;
    Ok(if inclusive {
        Edge::Inclusive(t)
    } else {
        Edge::Exclusive(t)
    })
}

/// Parse one time: `now(...)` or an RFC3339 UTC timestamp, its numbers read by core's reader.
pub fn parse_time<C: Clock>(s: &str) -> Result<TimeExpr<C::Instant>, TimeError<'_>> {
    parse_time_with::<C>(s, core_float)
}

/// Parse one time, its numbers read by `read`.
pub fn parse_time_with<C: Clock>(
    s: &str,
    read: FloatRead,
) -> Result<TimeExpr<C::Instant>, TimeError<'_>> {
    let parsed = if let Some(inner) = s
        .strip_prefix("now(")
        .and_then(|rest| rest.strip_suffix(')'))
    {
        if inner.is_empty() {
            Ok(TimeExpr::Now { offset_secs: 0.0 })
        } else if let Some(magnitude) = inner.strip_prefix('-') {
            parse_duration_with(magnitude, read)
                .map(|f| TimeExpr::Now { offset_secs: -f })
                .map_err(TimeCause::Duration)
        } else {
            parse_duration_with(inner, read)
                .map(|f| TimeExpr::Now { offset_secs: f })
                .map_err(TimeCause::Duration)
        }
    } else {
        parse_rfc3339_weak(s)
            .map(|since_epoch| TimeExpr::Fixed(C::from_unix(since_epoch)))
            .map_err(TimeCause::Instant)
    };
    parsed.map_err(|cause| TimeError { text: s, cause })
}

/// A duration literal in seconds: a bare float, or a float followed by one of `u` (microseconds),
/// `ms`, `s`, `m`, `h`, `d`, `w`, its number read by core's reader.
pub fn parse_duration(s: &str) -> Result<f64, DurationError<'_>> {
    parse_duration_with(s, core_float)
}

/// [`parse_duration`], its number read by `read`.
pub fn parse_duration_with(s: &str, read: FloatRead) -> Result<f64, DurationError<'_>> {
    let Some(&unit) = s.as_bytes().last() else {
        return Err(DurationError::Empty);
    };
    // The text before the unit; the unit is the text's last byte, so it is there to strip.
    let number = |unit: &str| s.strip_suffix(unit).unwrap_or(s);
    match unit {
        b'u' => read(number("u")).map(|u| U_TO_SECS * u),
        // A lone `s` has nothing before the unit: upstream asks for the byte before it and
        // panics; here the whole text is read as a float, which it is not.
        b's' if s.len() == 1 => read(s),
        b's' if s.ends_with("ms") => read(number("ms")).map(|ms| MS_TO_SECS * ms),
        b's' => read(number("s")),
        b'm' => read(number("m")).map(|m| M_TO_SECS * m),
        b'h' => read(number("h")).map(|h| H_TO_SECS * h),
        b'd' => read(number("d")).map(|d| D_TO_SECS * d),
        b'w' => read(number("w")).map(|w| W_TO_SECS * w),
        _ => read(s),
    }
    .map_err(|error| DurationError::Float { text: s, error })
}

/// humantime 2.4 `parse_rfc3339_weak`: an RFC3339-like UTC timestamp, as the time since
/// 1970-01-01T00:00:00Z, refused with the error humantime gives at the same check.
///
/// The quirks are kept because a selector that parses upstream has to parse here: the zone is not
/// validated beyond its position (`+` six bytes from the end ends the fraction), a leap second
/// `:60` reads as `:59`, the year is four digits from 1970 to 9999, and fractional digits past the
/// ninth are read and carry no weight.
pub fn parse_rfc3339_weak(s: &str) -> Result<Duration, Rfc3339Error> {
    let b = s.as_bytes();
    // The date and the time to the second, `2018-02-14T00:28:07`.
    let Some(head) = b.first_chunk::<19>() else {
        return Err(Rfc3339Error::InvalidFormat);
    };
    if head[4] != b'-'
        || head[7] != b'-'
        || (head[10] != b'T' && head[10] != b' ')
        || head[13] != b':'
        || head[16] != b':'
    {
        return Err(Rfc3339Error::InvalidFormat);
    }
    // Every product and sum below is of numbers of a few digits, far from `u64::MAX`, so the
    // saturating forms are the exact ones.
    let year = two(head[0], head[1])?
        .saturating_mul(100)
        .saturating_add(two(head[2], head[3])?);
    let month = two(head[5], head[6])?;
    let day = two(head[8], head[9])?;
    let hour = two(head[11], head[12])?;
    let minute = two(head[14], head[15])?;
    let mut second = two(head[17], head[18])?;

    if year < 1970 || hour > 23 || minute > 59 || second > 60 {
        return Err(Rfc3339Error::OutOfRange);
    }
    if second == 60 {
        second = 59;
    }

    let leap = year % 4 == 0 && (year % 100 != 0 || year % 400 == 0);
    let (mut ydays, mdays): (u64, u64) = match month {
        1 => (0, 31),
        2 if leap => (31, 29),
        2 => (31, 28),
        3 => (59, 31),
        4 => (90, 30),
        5 => (120, 31),
        6 => (151, 30),
        7 => (181, 31),
        8 => (212, 31),
        9 => (243, 30),
        10 => (273, 31),
        11 => (304, 30),
        12 => (334, 31),
        _ => return Err(Rfc3339Error::OutOfRange),
    };
    if day > mdays || day == 0 {
        return Err(Rfc3339Error::OutOfRange);
    }
    ydays = ydays.saturating_add(day.saturating_sub(1));
    if leap && month > 2 {
        ydays = ydays.saturating_add(1);
    }

    // `year` is at least 1970, so no difference below falls under zero.
    let before = year.saturating_sub(1);
    let leap_years = (before.saturating_sub(1968) / 4)
        .saturating_sub(before.saturating_sub(1900) / 100)
        .saturating_add(before.saturating_sub(1600) / 400);
    let days = year
        .saturating_sub(1970)
        .saturating_mul(365)
        .saturating_add(leap_years)
        .saturating_add(ydays);
    let time = second
        .saturating_add(minute.saturating_mul(60))
        .saturating_add(hour.saturating_mul(3600));

    let mut nanos = 0u32;
    let mut mult = 100_000_000u32;
    let tail = b.get(19..).unwrap_or_default();
    if tail.first() == Some(&b'.') {
        let mut rest = tail.get(1..).unwrap_or_default();
        while let [c, after @ ..] = rest {
            if *c == b'Z' {
                if after.is_empty() {
                    break;
                }
                return Err(Rfc3339Error::InvalidDigit);
            } else if *c == b'+' {
                // The start of `+00:00`, which must end the text.
                if after.len() == 5 {
                    break;
                }
                return Err(Rfc3339Error::InvalidDigit);
            }
            let digit = char::from(*c)
                .to_digit(10)
                .ok_or(Rfc3339Error::InvalidDigit)?;
            // `mult` falls a tenth a digit, so the sum stays below 1e9.
            nanos = nanos.saturating_add(mult.saturating_mul(digit));
            mult /= 10;
            rest = after;
        }
    } else if !tail.is_empty()
        && (b.len() > 25 || (tail.first() != Some(&b'Z') && tail != b"+00:00"))
    {
        return Err(Rfc3339Error::InvalidFormat);
    }

    let total_seconds = time.saturating_add(days.saturating_mul(86_400));
    if total_seconds > RFC3339_MAX_SECONDS {
        return Err(Rfc3339Error::OutOfRange);
    }
    // `nanos` is below 1e9: nine digits at most carry weight.
    Ok(Duration::new(total_seconds, nanos))
}

/// The two decimal digits `hi` and `lo` as a number.
fn two(hi: u8, lo: u8) -> Result<u64, Rfc3339Error> {
    match (char::from(hi).to_digit(10), char::from(lo).to_digit(10)) {
        // Two digits make at most 99.
        (Some(hi), Some(lo)) => Ok(u64::from(hi.saturating_mul(10).saturating_add(lo))),
        _ => Err(Rfc3339Error::InvalidDigit),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A clock whose instant is the time since the epoch, held in a `Duration`.
    enum Epoch {}

    impl Clock for Epoch {
        type Instant = Duration;
        fn from_unix(since_epoch: Duration) -> Duration {
            since_epoch
        }
        fn checked_add(at: Duration, by: Duration) -> Option<Duration> {
            at.checked_add(by)
        }
        fn checked_sub(at: Duration, by: Duration) -> Option<Duration> {
            at.checked_sub(by)
        }
    }

    fn at(secs: u64) -> Duration {
        Duration::from_secs(secs)
    }

    fn time(s: &str) -> Option<TimeExpr<Duration>> {
        parse_time::<Epoch>(s).ok()
    }

    fn range(s: &str) -> Option<TimeRange<TimeExpr<Duration>>> {
        parse_range::<Epoch>(s).ok()
    }

    /// 2022-06-30T01:02:03Z, read independently of this module's own arithmetic:
    /// 2022-07-01T00:00:00Z is 1656633600, one day earlier is 1656547200, and the
    /// time of day adds 1*3600 + 2*60 + 3.
    const T_2022_06_30: u64 = 1_656_547_200 + 3_723;

    #[test]
    fn rfc3339_weak_reads_the_forms_upstream_reads() {
        assert_eq!(
            time("2022-06-30T01:02:03Z"),
            Some(TimeExpr::Fixed(at(T_2022_06_30)))
        );
        // No zone, a space for the T, and `+00:00` are the same instant.
        assert_eq!(time("2022-06-30T01:02:03"), time("2022-06-30T01:02:03Z"));
        assert_eq!(time("2022-06-30 01:02:03Z"), time("2022-06-30T01:02:03Z"));
        assert_eq!(
            time("2022-06-30T01:02:03+00:00"),
            time("2022-06-30T01:02:03Z")
        );
        // Fractional digits are nanoseconds, to the ninth place.
        assert_eq!(
            time("2022-06-30T01:02:03.226942997Z"),
            Some(TimeExpr::Fixed(
                at(T_2022_06_30) + Duration::from_nanos(226_942_997)
            ))
        );
        assert_eq!(
            time("2022-06-30T01:02:03.5Z"),
            Some(TimeExpr::Fixed(
                at(T_2022_06_30) + Duration::from_millis(500)
            ))
        );
        // A tenth digit is read and dropped.
        assert_eq!(
            time("2022-06-30T01:02:03.1234567891Z"),
            Some(TimeExpr::Fixed(
                at(T_2022_06_30) + Duration::from_nanos(123_456_789)
            ))
        );
        // Known epoch seconds for three round dates.
        assert_eq!(time("1970-01-01T00:00:00Z"), Some(TimeExpr::Fixed(at(0))));
        assert_eq!(
            time("2000-01-01T00:00:00Z"),
            Some(TimeExpr::Fixed(at(946_684_800)))
        );
        assert_eq!(
            time("2024-01-01T00:00:00Z"),
            Some(TimeExpr::Fixed(at(1_704_067_200)))
        );
        // A leap day, and the leap second that reads as :59.
        assert_eq!(
            time("2024-02-29T00:00:00Z"),
            Some(TimeExpr::Fixed(at(1_704_067_200 + 59 * 86_400)))
        );
        assert_eq!(time("2022-06-30T01:02:60Z"), time("2022-06-30T01:02:59Z"));
        // 9999-12-31T23:59:60Z is the last second (read as :59).
        assert!(time("9999-12-31T23:59:60Z").is_some());
        // Weak: a `Z` at byte 19 ends the check, whatever follows it within 25 bytes.
        assert_eq!(time("2022-06-30T01:02:03Zx"), time("2022-06-30T01:02:03Z"));
    }

    /// Each refusal is humantime's, at the check humantime makes it.
    #[test]
    fn rfc3339_weak_refuses_with_the_error_upstream_gives() {
        use Rfc3339Error::*;
        for (s, error) in [
            ("", InvalidFormat),
            ("1h", InvalidFormat),
            ("2020-11-05", InvalidFormat),
            ("2022/06/30T01:02:03Z", InvalidFormat),
            ("2022-06-30X01:02:03Z", InvalidFormat),
            ("2022-06-30T01:02:03+01:00x", InvalidFormat),
            ("2O22-06-30T01:02:03Z", InvalidDigit),
            ("2022-06-30T01:02:03.12x4Z", InvalidDigit),
            ("2022-06-30T01:02:03.5Zx", InvalidDigit),
            ("2022-06-30T01:02:03.5+01:00x", InvalidDigit),
            ("2022-13-01T00:00:00Z", OutOfRange),
            ("2022-00-10T00:00:00Z", OutOfRange),
            ("2022-02-30T00:00:00Z", OutOfRange),
            ("2023-02-29T00:00:00Z", OutOfRange),
            ("2022-06-00T00:00:00Z", OutOfRange),
            ("1969-12-31T23:59:59Z", OutOfRange),
            ("2022-06-30T24:00:00Z", OutOfRange),
            ("2022-06-30T01:60:00Z", OutOfRange),
            ("2022-06-30T01:02:61Z", OutOfRange),
        ] {
            assert_eq!(parse_rfc3339_weak(s), Err(error), "{s}");
        }
        // Ten thousand is not four digits: the shape is wrong before any number is read.
        assert_eq!(
            parse_rfc3339_weak("10000-01-01T00:00:00Z"),
            Err(InvalidFormat)
        );
        // humantime's words.
        assert_eq!(
            std::format!("{OutOfRange} / {InvalidDigit} / {InvalidFormat}"),
            "numeric component is out of range / bad character where digit is expected / \
             timestamp format is invalid"
        );
    }

    /// Literals within an ulp's breadth of a halfway point between two `f64`s, and the halfway
    /// point itself, with more significant digits than a short reading keeps: `1 + 2^-53` lies
    /// halfway between 1 and the next `f64` up and rounds to 1 (to even), a digit less rounds to 1
    /// and a digit more to the next. Past [`DECIMAL_TEXT`] bytes, so read as [`decimal_digits`]
    /// writes them: the halfway point followed by zeros, and by zeros and a last 1.
    fn halfway_literals() -> [std::string::String; 5] {
        const HALF: &str = "1.00000000000000011102230246251565404236316680908203125";
        let zeros = "0".repeat(DECIMAL_TEXT);
        [
            HALF.into(),
            "1.00000000000000011102230246251565404236316680908203124".into(),
            "1.00000000000000011102230246251565404236316680908203126".into(),
            std::format!("{HALF}{zeros}"),
            std::format!("{HALF}{zeros}1"),
        ]
    }

    /// The halfway literals read as their own text says, by core's reader: the witness the
    /// platform's reader is held to (the pico ABI's test reads the same literals with `strtod`).
    #[test]
    fn the_halfway_literals_round_to_even_and_away_from_the_halfway_point() {
        let one = 1.0_f64;
        let next = f64::from_bits(one.to_bits() + 1);
        let read: std::vec::Vec<f64> = halfway_literals()
            .iter()
            .map(|text| core_float(text).expect("a literal"))
            .collect();
        assert_eq!(read, [one, one, next, one, next]);
    }

    /// [`decimal_text`] hands the reader the literal's own bytes and a NUL when they fit, and the
    /// form [`decimal_digits`] writes when they do not; a refusal is the grammar's. Turned red by a
    /// copy that changes a byte, leaves off the NUL, or reaches past the buffer.
    #[test]
    fn a_literal_that_fits_is_handed_over_as_its_own_bytes() {
        for text in ["1.5", "-2.5e-3", "+.5E+1", "9007199254740993"] {
            let mut out = [0xffu8; DECIMAL_TEXT];
            assert_eq!(
                decimal_text(text, &mut out),
                Ok(Decimal::Written(text.len()))
            );
            assert_eq!(&out[..text.len()], text.as_bytes());
            assert_eq!(out[text.len()], 0, "{text:?} ends in a NUL");
        }
        for text in halfway_literals() {
            let mut out = [0u8; DECIMAL_TEXT];
            let Ok(Decimal::Written(len)) = decimal_text(&text, &mut out) else {
                panic!("{text:?} is written");
            };
            let written = core::str::from_utf8(&out[..len]).expect("ASCII");
            if text.len() < DECIMAL_TEXT {
                assert_eq!(written, text, "a literal that fits is its own bytes");
            } else {
                assert!(!written.contains('.'), "a long one is written as digits");
            }
            assert_eq!(
                written.parse::<f64>().ok().map(f64::to_bits),
                core_float(&text).ok().map(f64::to_bits),
                "{text:?}"
            );
        }
        let mut out = [0u8; DECIMAL_TEXT];
        assert_eq!(decimal_text("1x", &mut out), Err(FloatError::Invalid));
        assert_eq!(decimal_text("", &mut out), Err(FloatError::Empty));
        assert_eq!(
            decimal_text("-inf", &mut out),
            Ok(Decimal::Read(f64::NEG_INFINITY))
        );
    }

    /// What [`decimal_digits`] writes reads, with a correctly rounding reader, to the value
    /// `f64::from_str` reads the literal to, and it admits and refuses what that does, in its
    /// words. Turned red by a grammar that admits a text core refuses or the reverse, a digit or a
    /// power of ten written wrong, a radix character written, or fewer digits kept than decide
    /// the rounding (the halfway literals).
    #[test]
    fn a_decimal_written_for_a_platform_reader_reads_as_core_reads_the_literal() {
        let halfway = halfway_literals();
        let corpus = [
            "0",
            "1",
            "-1",
            "+1",
            "1.",
            ".5",
            "-.5",
            "1.5",
            "0.1",
            "123.456",
            "000123",
            "1e5",
            "1E5",
            "1e+5",
            "1e-5",
            "1.e1",
            ".5e1",
            "2.5e-3",
            "1e400",
            "-1e400",
            "1e-400",
            "4.9e-324",
            "2.2250738585072014e-308",
            "1.7976931348623157e308",
            "9007199254740993",
            "0.30000000000000004",
            "1e00000000000000000000003",
            "1e99999999999999999999999",
            "1e-99999999999999999999999",
            "0e999999999999",
            "0.000",
            "-0",
            "-0.0",
            "inf",
            "-inf",
            "+INF",
            "Infinity",
            "-infinity",
            "nan",
            "NaN",
            "-nan",
            "0.000000000000000000000000000000000000000000000000000000000000000000000000000000001",
            "123456789012345678901234567890123456789012345678901234567890123456789",
            "1000000000000000000000000000000000000000000000000000000000000",
            "1.000000000000000000000000000000000000000000000000000000000001",
            "",
            ".",
            "e1",
            ".e1",
            "1e",
            "1e+",
            "1x",
            " 1",
            "1 ",
            "0x10",
            "1_000",
            "--1",
            "+-1",
            "in",
            "infin",
            "nanx",
            "1.2.3",
            "1e5.5",
        ]
        .into_iter()
        .chain(halfway.iter().map(std::string::String::as_str));
        for text in corpus {
            let mut out = [0u8; DECIMAL_TEXT];
            let ours = decimal_digits(text, &mut out).map(|decimal| match decimal {
                Decimal::Read(value) => value,
                Decimal::Written(len) => {
                    assert_eq!(out[len], 0, "{text:?} ends in a NUL");
                    let written = core::str::from_utf8(&out[..len]).expect("ASCII");
                    assert!(!written.contains('.'), "{text:?} written with no radix");
                    written.parse::<f64>().expect("a literal core reads")
                }
            });
            match (ours, core_float(text)) {
                (Ok(a), Ok(b)) => assert!(
                    a.to_bits() == b.to_bits() || (a.is_nan() && b.is_nan()),
                    "{text:?}: {a} against {b}"
                ),
                (a, b) => assert_eq!(a.map(f64::to_bits), b.map(f64::to_bits), "{text:?}"),
            }
        }
    }

    /// The longest form [`decimal_digits`] writes (a sign, every digit kept, the sticky one and
    /// the most negative power) fills [`DECIMAL_TEXT`] to its NUL. Turned red by a buffer a byte
    /// short, where the form is refused, or a writer that cuts the form instead.
    #[test]
    fn the_longest_form_fills_the_buffer_to_its_nul() {
        let text = std::format!("-{}e-200000", "1".repeat(DECIMAL_DIGITS + 32));
        let mut out = [0xffu8; DECIMAL_TEXT];
        assert_eq!(
            decimal_digits(&text, &mut out),
            Ok(Decimal::Written(DECIMAL_TEXT - 1))
        );
        let written = core::str::from_utf8(&out[..DECIMAL_TEXT - 1]).expect("ASCII");
        assert!(written.starts_with("-1"), "{written:?}");
        assert!(written.ends_with("11e-99999"), "{written:?}");
        assert_eq!(out[DECIMAL_TEXT - 1], 0);
    }

    /// A duration's number is read by the reader the caller names, and refused in that reader's
    /// words. Turned red by a parse that reads with core's reader whatever it is handed.
    #[test]
    fn a_durations_number_is_read_by_the_reader_named() {
        fn seven(_text: &str) -> Result<f64, FloatError> {
            Ok(7.0)
        }
        fn refuses(_text: &str) -> Result<f64, FloatError> {
            Err(FloatError::Invalid)
        }
        assert_eq!(parse_duration_with("1.5s", seven), Ok(7.0));
        assert_eq!(parse_duration_with("2m", seven), Ok(420.0));
        assert_eq!(
            parse_duration_with("1.5s", refuses),
            Err(DurationError::Float {
                text: "1.5s",
                error: FloatError::Invalid
            })
        );
        assert_eq!(
            parse_range_with::<Epoch>("[now(-1s)..]", seven).map(|r| r.start),
            Ok(Edge::Inclusive(TimeExpr::Now { offset_secs: -7.0 }))
        );
        assert_eq!(
            std::format!("{} / {}", FloatError::Empty, FloatError::Invalid),
            std::format!(
                "{} / {}",
                "".parse::<f64>().unwrap_err(),
                "x".parse::<f64>().unwrap_err()
            ),
            "refused in core's words"
        );
    }

    #[test]
    fn now_expressions_and_durations() {
        assert_eq!(time("now()"), Some(TimeExpr::Now { offset_secs: 0.0 }));
        assert_eq!(time("now(0)"), Some(TimeExpr::Now { offset_secs: 0.0 }));
        assert_eq!(
            time("now(123.45)"),
            Some(TimeExpr::Now {
                offset_secs: 123.45
            })
        );
        assert_eq!(
            time("now(1h)"),
            Some(TimeExpr::Now {
                offset_secs: 3600.0
            })
        );
        assert_eq!(
            time("now(-1h)"),
            Some(TimeExpr::Now {
                offset_secs: -3600.0
            })
        );
        // A leading `+` is part of the float, not a sign the grammar names.
        assert_eq!(time("now(+5s)"), Some(TimeExpr::Now { offset_secs: 5.0 }));
        for (lit, secs) in [
            ("1000u", 1e-3),
            ("2ms", 2e-3),
            ("1.5s", 1.5),
            ("2m", 120.0),
            ("1h", 3600.0),
            ("1d", 86_400.0),
            ("1w", 604_800.0),
            ("7", 7.0),
        ] {
            assert_eq!(parse_duration(lit), Ok(secs), "{lit}");
        }
        assert_eq!(parse_duration(""), Err(DurationError::Empty));
        for lit in ["xs", "s", "ms", "m", "1x", "--1s"] {
            assert!(
                matches!(parse_duration(lit), Err(DurationError::Float { text, .. }) if text == lit),
                "{lit:?}"
            );
        }
        // A refused `now(..)` names the whole time and the duration's own refusal.
        assert!(matches!(
            parse_time::<Epoch>("now(-1x)"),
            Err(TimeError {
                text: "now(-1x)",
                cause: TimeCause::Duration(DurationError::Float { text: "1x", .. })
            })
        ));
        // Not a time: no `now(`, no date.
        assert_eq!(time(""), None);
        assert_eq!(time("[;]"), None);
        assert_eq!(time("now(1h"), None);
    }

    #[test]
    fn ranges_parse_in_both_syntaxes() {
        use Edge::*;
        assert_eq!(
            range("[..]"),
            Some(TimeRange {
                start: Unbounded,
                end: Unbounded
            })
        );
        assert_eq!(
            range("[now(-1h)..now(1h)]"),
            Some(TimeRange {
                start: Inclusive(TimeExpr::Now {
                    offset_secs: -3600.0
                }),
                end: Inclusive(TimeExpr::Now {
                    offset_secs: 3600.0
                })
            })
        );
        assert_eq!(
            range("]now(-1h)..now(1h)["),
            Some(TimeRange {
                start: Exclusive(TimeExpr::Now {
                    offset_secs: -3600.0
                }),
                end: Exclusive(TimeExpr::Now {
                    offset_secs: 3600.0
                })
            })
        );
        // `;` is `start..start+duration`, the right bracket choosing the end's kind.
        assert_eq!(
            range("[now(-1h);30m]"),
            Some(TimeRange {
                start: Inclusive(TimeExpr::Now {
                    offset_secs: -3600.0
                }),
                end: Inclusive(TimeExpr::Now {
                    offset_secs: -1800.0
                })
            })
        );
        assert_eq!(
            range("]2022-06-30T01:02:03Z;1h["),
            Some(TimeRange {
                start: Exclusive(TimeExpr::Fixed(at(T_2022_06_30))),
                end: Exclusive(TimeExpr::Fixed(at(T_2022_06_30 + 3600)))
            })
        );
        // A negative duration moves a fixed start back as it moves a `now()` start back: the
        // end lies before the start.
        assert_eq!(
            range("[2022-06-30T01:02:03Z;-1h]"),
            Some(TimeRange {
                start: Inclusive(TimeExpr::Fixed(at(T_2022_06_30))),
                end: Inclusive(TimeExpr::Fixed(at(T_2022_06_30 - 3600)))
            })
        );
        assert_eq!(
            range("[now();-1h]"),
            Some(TimeRange {
                start: Inclusive(TimeExpr::Now { offset_secs: 0.0 }),
                end: Inclusive(TimeExpr::Now {
                    offset_secs: -3600.0
                })
            })
        );
        // `..` is looked for before `;`, as upstream does.
        assert!(range("[now(-1h)..now(1h);]").is_none());
    }

    /// Each refusal is the one upstream's parser reaches first.
    #[test]
    fn ranges_are_refused_in_upstreams_order() {
        fn refusal(s: &str) -> RangeError<'_> {
            parse_range::<Epoch>(s).unwrap_err()
        }
        assert_eq!(refusal(""), RangeError::TooShort);
        assert_eq!(refusal("[.]"), RangeError::TooShort);
        assert_eq!(refusal("now(-1h)"), RangeError::BadStart);
        assert_eq!(refusal("(now(-1h)..)"), RangeError::BadStart);
        assert_eq!(refusal("[now(-1h)..)"), RangeError::BadEnd);
        assert_eq!(
            refusal("[now(-1h)]"),
            RangeError::NoSeparator { inner: "now(-1h)" }
        );
        assert_eq!(refusal("[;1h]"), RangeError::NoStart { inner: ";1h" });
        assert_eq!(refusal("[;]"), RangeError::TooShort);
        // The duration is read before the start is asked for.
        assert!(matches!(
            refusal("[;x]"),
            RangeError::Duration(DurationError::Float { text: "x", .. })
        ));
        assert_eq!(
            refusal("[now(-1h);]"),
            RangeError::Duration(DurationError::Empty)
        );
        assert!(matches!(
            refusal("[now(-1h);1x]"),
            RangeError::Duration(DurationError::Float { text: "1x", .. })
        ));
        assert!(matches!(
            refusal("[now();s]"),
            RangeError::Duration(DurationError::Float { text: "s", .. })
        ));
        assert!(matches!(
            refusal("[bogus..]"),
            RangeError::Time(TimeError {
                text: "bogus",
                cause: TimeCause::Instant(Rfc3339Error::InvalidFormat)
            })
        ));
        assert!(matches!(
            refusal("[..bogus]"),
            RangeError::Time(TimeError { text: "bogus", .. })
        ));
        // A step back past the epoch is not an instant of this clock.
        assert_eq!(
            refusal("[1970-01-01T00:00:00Z;-1s]"),
            RangeError::EndUnrepresentable {
                inner: "1970-01-01T00:00:00Z;-1s"
            }
        );
        assert_eq!(
            refusal("[1970-01-01T00:00:00Z;nan]"),
            RangeError::EndUnrepresentable {
                inner: "1970-01-01T00:00:00Z;nan"
            }
        );
    }

    #[test]
    fn membership_follows_the_brackets() {
        let r = |s: &str, now: u64| range(s).unwrap().resolve_at::<Epoch>(at(now));
        let now = 1_000;
        let inside = r("[now(-10s)..now(10s)]", now);
        assert!(inside.contains(at(1_000)));
        assert!(inside.contains(at(990)));
        assert!(inside.contains(at(1_010)));
        assert!(!inside.contains(at(989)));
        assert!(!inside.contains(at(1_011)));
        // Exclusive ends drop the boundary instants.
        let open = r("]now(-10s)..now(10s)[", now);
        assert!(!open.contains(at(990)));
        assert!(!open.contains(at(1_010)));
        assert!(open.contains(at(991)));
        // A range in the past or the future holds nothing of the present.
        assert!(!r("[now(-2s)..now(-1s)]", now).contains(at(1_000)));
        assert!(!r("[now(1s)..now(2s)]", now).contains(at(1_000)));
        assert!(r("[now(-1m)..]", now).contains(at(1_000)));
        assert!(r("[..now(1m)]", now).contains(at(1_000)));
        // Both ends open holds everything, the epoch included.
        assert!(r("[..]", now).contains(at(0)));
        // A range whose end lies before its start holds nothing.
        let back = r("[2022-06-30T01:02:03Z;-1h]", now);
        for probe in [
            T_2022_06_30 - 3_601,
            T_2022_06_30 - 3_600,
            T_2022_06_30 - 1,
            T_2022_06_30,
            T_2022_06_30 + 1,
        ] {
            assert!(!back.contains(at(probe)), "{probe}");
        }
        // The duration form holds the same instants as the range it abbreviates.
        let dur = r("[2022-06-30T01:02:03Z;1h]", now);
        let rng = r("[2022-06-30T01:02:03Z..2022-06-30T02:02:03Z]", now);
        for probe in [
            T_2022_06_30 - 1,
            T_2022_06_30,
            T_2022_06_30 + 3_600,
            T_2022_06_30 + 3_601,
        ] {
            assert_eq!(dur.contains(at(probe)), rng.contains(at(probe)), "{probe}");
        }
    }

    /// An offset the instant type does not hold is an unbounded end. Read as a clamp it would
    /// turn an upper bound of `now(-1000000000d)` into "nothing", where upstream answers
    /// "everything".
    #[test]
    fn an_offset_out_of_range_is_unbounded_not_clamped() {
        let now = at(1_000);
        let far_past_end = range("[..now(-1e300d)]").unwrap().resolve_at::<Epoch>(now);
        assert_eq!(far_past_end.end, Edge::Unbounded);
        assert!(far_past_end.contains(at(1)));
        let far_future_start = range("[now(1e300d)..]").unwrap().resolve_at::<Epoch>(now);
        assert_eq!(far_future_start.start, Edge::Unbounded);
        // NaN is not a duration.
        assert_eq!(
            range("[now(nan)..]").map(|r| r.resolve_at::<Epoch>(now).start),
            Some(Edge::Unbounded)
        );
    }
}
