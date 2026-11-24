// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! THE CLOCK AND THE INTERVAL, as a selector writes them: what `time` reads
//! besides milliseconds since the Unix epoch, and what `elapsed`, `delay`,
//! `first_reply` and `completion` read besides a number of milliseconds.
//!
//! # `time`
//!
//! * A DATE AND A CLOCK TIME, ISO 8601: `2026-11-23T12:04:00`, with `T` (or
//!   `t`, or a space inside quotes) between them, the seconds and up to three
//!   digits of a fraction optional, and an offset optional: `Z`, `+09:00`,
//!   `+0900`, `+09`. A date alone is its midnight. The text fixes the instant.
//! * A CLOCK TIME with no date: `12:04`, `12:04:00`, `12:04:00.250`, the hour
//!   in one digit or two, with an offset optional. Its day is the day the
//!   capture began, as a clock at the offset reads the capture's first instant
//!   (`anchor`): `time > 12:04` over a capture that began at 12:04:30 is every
//!   row after 12:04 of that day. One day and not the nearest one, so a reader
//!   who knows when the capture began knows what a clock time names; a time
//!   past a midnight the capture crossed is written with its date.
//! * A LITERAL WITH NO OFFSET IS READ IN UTC. Which zone a reader's clock shows
//!   is not something a capture carries, so the language reads the one zone
//!   every clock can be compared in, and a consumer that shows times in another
//!   has the binder write its offset onto every literal that has none
//!   ([`crate::filter::bind_json_in_zone`]) before a door reads the selector.
//!
//! The comparison is in milliseconds, as `time` always compared, so a fraction
//! of more than three digits names an instant the field cannot compare and is
//! refused rather than rounded.
//!
//! # The intervals
//!
//! A number and a unit, `250ms`, `1.5s`, `2min`, `1h`, `500us`, `10ns`, read
//! exactly: the value must come to a whole number of milliseconds, the unit
//! the four fields compare, so `1.0005s` and `0.5ms` are refused rather than
//! rounded. A number with no unit is milliseconds, as it always was.

use alloc::string::String;

/// Milliseconds in a day.
const DAY_MS: u64 = 86_400_000;

/// The largest offset from UTC a literal or the binder writes, in minutes
/// either way: 23:59, the most an ISO 8601 offset spells.
const MAX_OFFSET_MINUTES: u32 = 23 * 60 + 59;

/// A `time` value that is not a bare integer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum TimeLiteral {
    /// A date, with or without a clock time: the instant, in milliseconds
    /// since the Unix epoch. `zoned` says whether the text carried an offset.
    Instant { ms: u64, zoned: bool },
    /// A clock time with no date: milliseconds after the midnight of the clock
    /// that runs `offset_ms` ahead of UTC, and whether the text said so.
    Clock {
        of_day_ms: u64,
        offset_ms: i64,
        zoned: bool,
    },
}

/// `text` read as a date or a clock time, or `None` for text that is neither.
pub(super) fn time_literal(text: &str) -> Option<TimeLiteral> {
    if !text.is_ascii() {
        return None;
    }
    // A date opens with four digits and a hyphen; a clock time never has a
    // hyphen before its first colon.
    if text.len() >= 10 && text.as_bytes()[4] == b'-' {
        let days = date(&text[..10])?;
        let rest = &text[10..];
        let (of_day, offset) = match rest.as_bytes().first() {
            None => (0, None),
            Some(b'T' | b't' | b' ') => {
                let (clock_text, offset) = zoned(&rest[1..])?;
                (clock(clock_text)?, offset)
            }
            Some(_) => match zoned(rest)? {
                ("", offset) => (0, offset),
                _ => return None,
            },
        };
        let local = days.checked_mul(DAY_MS)?.checked_add(of_day)?;
        let utc = i128::from(local) - i128::from(offset.unwrap_or(0));
        return Some(TimeLiteral::Instant {
            ms: u64::try_from(utc).ok()?,
            zoned: offset.is_some(),
        });
    }
    let (clock_text, offset) = zoned(text)?;
    Some(TimeLiteral::Clock {
        of_day_ms: clock(clock_text)?,
        offset_ms: offset.unwrap_or(0),
        zoned: offset.is_some(),
    })
}

/// The instant a clock time names in a capture whose first instant is
/// `origin_ms`: the moment a clock running `offset_ms` ahead of UTC shows
/// `of_day_ms` on the day that clock reads the first instant in. `None`
/// before the epoch or past `u64`.
pub(super) fn anchor(origin_ms: u64, of_day_ms: u64, offset_ms: i64) -> Option<u64> {
    let day = i128::from(DAY_MS);
    let origin = i128::from(origin_ms) + i128::from(offset_ms);
    let local = origin - origin.rem_euclid(day) + i128::from(of_day_ms);
    u64::try_from(local - i128::from(offset_ms)).ok()
}

/// `text` read as an interval with a unit, in whole milliseconds, or `None`
/// for text that is not one or does not come to a whole millisecond.
pub(super) fn duration_ms(text: &str) -> Option<u64> {
    if !text.is_ascii() {
        return None;
    }
    let unit_at = text.find(|c: char| c.is_ascii_alphabetic())?;
    let (number, unit) = text.split_at(unit_at);
    let per_unit_ns: u128 = match unit {
        "ns" => 1,
        "us" => 1_000,
        "ms" => 1_000_000,
        "s" => 1_000_000_000,
        "min" => 60_000_000_000,
        "h" => 3_600_000_000_000,
        _ => return None,
    };
    let (whole, fraction) = match number.split_once('.') {
        Some((_, "")) => return None,
        Some((whole, fraction)) => (whole, fraction),
        None => (number, ""),
    };
    let whole_ns = digits(whole)?.checked_mul(per_unit_ns)?;
    let fraction_ns = match fraction {
        "" => 0,
        _ => {
            let scale = 10u128.checked_pow(u32::try_from(fraction.len()).ok()?)?;
            let scaled = digits(fraction)?.checked_mul(per_unit_ns)?;
            // A part of a nanosecond is not a whole millisecond either.
            if scaled % scale != 0 {
                return None;
            }
            scaled / scale
        }
    };
    let ns = whole_ns.checked_add(fraction_ns)?;
    if ns % 1_000_000 != 0 {
        return None;
    }
    u64::try_from(ns / 1_000_000).ok()
}

/// The offset `minutes` east of UTC as a literal writes it (`+09:00`,
/// `-05:30`, `+00:00`), or `None` past `MAX_OFFSET_MINUTES` either way.
pub(super) fn offset_text(minutes: i32) -> Option<String> {
    let magnitude = minutes.unsigned_abs();
    if magnitude > MAX_OFFSET_MINUTES {
        return None;
    }
    let sign = if minutes < 0 { '-' } else { '+' };
    Some(alloc::format!(
        "{sign}{:02}:{:02}",
        magnitude / 60,
        magnitude % 60
    ))
}

/// `text` as one or more ASCII digits, read as a number.
fn digits(text: &str) -> Option<u128> {
    if text.is_empty() || !text.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    text.parse().ok()
}

/// `text` as exactly `width` ASCII digits, read as a number.
fn fixed(text: &str, width: usize) -> Option<u64> {
    if text.len() != width {
        return None;
    }
    u64::try_from(digits(text)?).ok()
}

/// A date, `YYYY-MM-DD`, as days since 1970-01-01; `None` for a day the
/// month does not have or a year before 1970.
fn date(text: &str) -> Option<u64> {
    let bytes = text.as_bytes();
    if bytes.len() != 10 || bytes[4] != b'-' || bytes[7] != b'-' {
        return None;
    }
    let year = fixed(&text[..4], 4)?;
    let month = fixed(&text[5..7], 2)?;
    let day = fixed(&text[8..], 2)?;
    if year < 1970 || !(1..=12).contains(&month) || day == 0 || day > days_in(year, month) {
        return None;
    }
    Some(days_from_civil(year, month, day))
}

/// The days of `month` (1 to 12) of `year`.
fn days_in(year: u64, month: u64) -> u64 {
    const DAYS: [u64; 12] = [31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];
    let leap = year % 4 == 0 && (year % 100 != 0 || year % 400 == 0);
    if month == 2 && leap {
        29
    } else {
        DAYS[(month - 1) as usize]
    }
}

/// Days from 1970-01-01 to a date of the proleptic Gregorian calendar from
/// 1970 on, counted in 400-year eras that begin on a 1 March.
fn days_from_civil(year: u64, month: u64, day: u64) -> u64 {
    let year = if month <= 2 { year - 1 } else { year };
    let era = year / 400;
    let year_of_era = year - era * 400;
    let day_of_year = (153 * ((month + 9) % 12) + 2) / 5 + day - 1;
    let day_of_era = year_of_era * 365 + year_of_era / 4 - year_of_era / 100 + day_of_year;
    era * 146_097 + day_of_era - 719_468
}

/// A clock time, `H:MM`, `HH:MM`, `HH:MM:SS` or `HH:MM:SS.f` with one to three
/// digits of a fraction, as milliseconds after midnight.
fn clock(text: &str) -> Option<u64> {
    let mut parts = text.splitn(3, ':');
    let hour = parts.next()?;
    let minute = fixed(parts.next()?, 2)?;
    if !(1..=2).contains(&hour.len()) {
        return None;
    }
    let hour = u64::try_from(digits(hour)?).ok()?;
    let (second, millis) = match parts.next() {
        None => (0, 0),
        Some(seconds) => {
            let (whole, fraction) = seconds.split_once('.').unwrap_or((seconds, ""));
            let millis = match fraction.len() {
                0 if seconds.contains('.') => return None,
                0 => 0,
                1..=3 => {
                    let scale = 10u64.pow(3 - fraction.len() as u32);
                    u64::try_from(digits(fraction)?).ok()? * scale
                }
                _ => return None,
            };
            (fixed(whole, 2)?, millis)
        }
    };
    if hour > 23 || minute > 59 || second > 59 {
        return None;
    }
    Some(((hour * 60 + minute) * 60 + second) * 1_000 + millis)
}

/// `text` split into the clock before its offset and the offset in
/// milliseconds ahead of UTC, `None` for the offset where the text has none.
fn zoned(text: &str) -> Option<(&str, Option<i64>)> {
    match text.find(|c: char| matches!(c, 'Z' | 'z' | '+' | '-')) {
        None => Some((text, None)),
        Some(at) => Some((&text[..at], Some(offset(&text[at..])?))),
    }
}

/// An offset, `Z`, `+HH:MM`, `+HHMM` or `+HH` (or `-`), in milliseconds
/// ahead of UTC.
fn offset(text: &str) -> Option<i64> {
    if text == "Z" || text == "z" {
        return Some(0);
    }
    let sign: i64 = match text.as_bytes().first()? {
        b'+' => 1,
        b'-' => -1,
        _ => return None,
    };
    let rest = &text[1..];
    let (hours, minutes) = match rest.split_once(':') {
        Some((hours, minutes)) => (fixed(hours, 2)?, fixed(minutes, 2)?),
        None if rest.len() == 4 => (fixed(&rest[..2], 2)?, fixed(&rest[2..], 2)?),
        None => (fixed(rest, 2)?, 0),
    };
    if hours > 23 || minutes > 59 {
        return None;
    }
    Some(sign * i64::try_from((hours * 60 + minutes) * 60_000).ok()?)
}

#[cfg(test)]
mod tests {
    use super::*;

    const HOUR: u64 = 3_600_000;

    /// 2026-11-23T00:00:00Z, in milliseconds since the epoch.
    const DAY_2026_11_23: u64 = 1_795_392_000_000;

    #[test]
    fn a_date_is_its_utc_midnight_and_the_epoch_is_zero() {
        assert_eq!(
            time_literal("1970-01-01"),
            Some(TimeLiteral::Instant {
                ms: 0,
                zoned: false
            })
        );
        assert_eq!(
            time_literal("2026-11-23"),
            Some(TimeLiteral::Instant {
                ms: DAY_2026_11_23,
                zoned: false
            })
        );
        // A leap day exists in 2024 and not in 2026.
        assert!(time_literal("2024-02-29").is_some());
        assert_eq!(time_literal("2026-02-29"), None);
        assert_eq!(time_literal("1969-12-31"), None);
        assert_eq!(time_literal("2026-13-01"), None);
    }

    #[test]
    fn a_date_and_time_with_an_offset_is_one_instant_whatever_the_offset() {
        let utc = DAY_2026_11_23 + 3 * HOUR + 4 * 60_000;
        for text in [
            "2026-11-23T03:04:00Z",
            "2026-11-23T12:04:00+09:00",
            "2026-11-23T12:04+0900",
            "2026-11-23t12:04:00.000+09",
            "2026-11-22T22:04:00-05:00",
            "2026-11-23 03:04:00z",
        ] {
            assert_eq!(
                time_literal(text),
                Some(TimeLiteral::Instant {
                    ms: utc,
                    zoned: true
                }),
                "{text}"
            );
        }
        assert_eq!(
            time_literal("2026-11-23T03:04:00.25"),
            Some(TimeLiteral::Instant {
                ms: utc + 250,
                zoned: false
            })
        );
        assert_eq!(
            time_literal("2026-11-23+09:00"),
            Some(TimeLiteral::Instant {
                ms: DAY_2026_11_23 - 9 * HOUR,
                zoned: true
            })
        );
    }

    #[test]
    fn a_clock_time_is_milliseconds_after_midnight_at_its_offset() {
        assert_eq!(
            time_literal("12:04:00"),
            Some(TimeLiteral::Clock {
                of_day_ms: 12 * HOUR + 4 * 60_000,
                offset_ms: 0,
                zoned: false
            })
        );
        assert_eq!(
            time_literal("12:04:00.250"),
            Some(TimeLiteral::Clock {
                of_day_ms: 12 * HOUR + 4 * 60_000 + 250,
                offset_ms: 0,
                zoned: false
            })
        );
        assert_eq!(
            time_literal("9:05-05:30"),
            Some(TimeLiteral::Clock {
                of_day_ms: 9 * HOUR + 5 * 60_000,
                offset_ms: -(5 * 3_600_000 + 30 * 60_000),
                zoned: true
            })
        );
    }

    #[test]
    fn what_is_not_a_date_or_a_clock_time_is_refused() {
        for text in [
            "24:00",
            "12:60",
            "12:04:60",
            "12:4",
            "123:04",
            "12:04:00.2500",
            "12:04:00.",
            "12:04+24:00",
            "12:04+9",
            "12:04Q",
            "2026-11-23T",
            "2026-11-23T25:00",
            "2026-11-23x",
            "noon",
            "12",
        ] {
            assert_eq!(time_literal(text), None, "{text}");
        }
    }

    #[test]
    fn a_clock_time_names_that_time_on_the_day_the_capture_began() {
        let origin = DAY_2026_11_23 + 23 * HOUR + 50 * 60_000;
        // Later the same day.
        assert_eq!(
            anchor(origin, 23 * HOUR + 55 * 60_000, 0),
            Some(origin + 5 * 60_000)
        );
        // Earlier in the day than the origin: still that day, before it.
        assert_eq!(
            anchor(origin, 10 * 60_000, 0),
            Some(DAY_2026_11_23 + 10 * 60_000)
        );
        // The origin's own time is the origin.
        assert_eq!(anchor(origin, 23 * HOUR + 50 * 60_000, 0), Some(origin));
        // At +09:00 the origin's clock reads 08:50 on the 24th, so 09:00 there
        // is ten minutes after it.
        assert_eq!(
            anchor(origin, 9 * HOUR, 9 * HOUR as i64),
            Some(origin + 10 * 60_000)
        );
    }

    #[test]
    fn an_interval_is_read_in_whole_milliseconds() {
        for (text, ms) in [
            ("250ms", 250),
            ("1.5s", 1_500),
            ("2s", 2_000),
            ("2min", 120_000),
            ("1h", 3_600_000),
            ("2000us", 2),
            ("3000000ns", 3),
            ("0.001s", 1),
            ("1.50s", 1_500),
        ] {
            assert_eq!(duration_ms(text), Some(ms), "{text}");
        }
        // A part of a millisecond, a number with no unit (milliseconds, read by
        // the caller as an integer), and what is no interval at all.
        for text in [
            "500us", "1.0005s", "0.5ms", "1.s", ".5s", "5", "5m", "ms", "1e3ms",
        ] {
            assert_eq!(duration_ms(text), None, "{text}");
        }
    }

    #[test]
    fn an_offset_is_written_as_iso_8601_spells_it() {
        assert_eq!(offset_text(540).as_deref(), Some("+09:00"));
        assert_eq!(offset_text(-330).as_deref(), Some("-05:30"));
        assert_eq!(offset_text(0).as_deref(), Some("+00:00"));
        assert_eq!(offset_text(1439).as_deref(), Some("+23:59"));
        assert_eq!(offset_text(1440), None);
        assert_eq!(offset_text(-1440), None);
    }
}
