// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! A ZONE THAT CHANGES ITS CLOCK, written as a POSIX TZ rule: what a `time`
//! literal reads where a fixed offset cannot say which offset is in force.
//!
//! # The rule
//!
//! `std offset [dst [offset] [,start[/time],end[/time]]]`, as POSIX.1-2024
//! states it for `TZ`, with the hours of a change time widened to -167..=167
//! as RFC 8536 (the TZif footer) widens them:
//!
//! * a NAME is three or more ASCII letters, or `<` three or more letters,
//!   digits, `+` or `-` `>`; the names are not read, only checked;
//! * an OFFSET is `[+|-]hh[:mm[:ss]]` and counts WEST of UTC (`CET-1` is an
//!   hour ahead); the daylight offset, when the rule gives none, is an hour
//!   ahead of the standard one;
//! * a DATE is `Jn` (1 to 365, February 29 never counted), `n` (0 to 365,
//!   counting it) or `Mm.w.d` (weekday `d` of week `w` of month `m`, Sunday
//!   0, week 5 the last); a TIME is the local time the change happens at, in
//!   the clock in force before it, 02:00:00 when the rule gives none.
//!
//! Read without a zone database, so a build with no file system reads it the
//! same way; a rule is the whole of what it says, for every year.
//!
//! # What this module refuses that POSIX leaves open
//!
//! * A rule that names a daylight zone and gives no dates: POSIX leaves the
//!   dates to the implementation, and an answer that rests on a default no
//!   text stated is not one a selector can be read again by.
//! * An offset that is not a whole number of minutes, or is more than 23:59
//!   either way: a `time` literal spells an offset in hours and minutes up to
//!   23:59, and a zone whose offset it cannot spell cannot be written onto one.
//!
//! # A local time the zone shows twice, or never
//!
//! On the day the clock goes forward the hour it skips is shown by no instant,
//! and on the day it goes back the hour it repeats is shown by two.
//! `ZoneRule::resolve` says which of the three a local time is, and its
//! callers refuse the two that name no single instant rather than pick one.

use core::fmt;

/// Milliseconds in a day.
const DAY_MS: i64 = 86_400_000;

/// Seconds in an hour.
const HOUR_S: i32 = 3_600;

/// The largest offset a `time` literal spells, in seconds either way: 23:59.
const MAX_OFFSET_S: i32 = (23 * 60 + 59) * 60;

/// The widest change time, in hours either way (RFC 8536).
const MAX_CHANGE_HOURS: u32 = 167;

/// A zone as a POSIX TZ rule states it: its standard offset and, where it has
/// one, the daylight clock and the two days it is put on and taken off.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct ZoneRule {
    /// Seconds the standard clock runs AHEAD of UTC (the text counts west).
    std_east_s: i32,
    daylight: Option<Daylight>,
}

/// The daylight clock of a zone and when it is in force.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Daylight {
    /// Seconds the daylight clock runs ahead of UTC.
    east_s: i32,
    start: Change,
    end: Change,
}

/// One of the two changes a year: the day, and the local time on it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Change {
    day: RuleDay,
    /// Seconds after the local midnight of `day`, in the clock in force
    /// before the change.
    at_s: i32,
}

/// The day of a year a change falls on, in the three forms a rule writes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RuleDay {
    /// `Jn`: the `n`th day, 1 to 365, February 29 never counted.
    Julian(u16),
    /// `n`: the day `n` days after January 1, 0 to 365, February 29 counted.
    Ordinal(u16),
    /// `Mm.w.d`: weekday `weekday` (Sunday 0) of week `week` (1 to 5, 5 the
    /// last) of month `month`.
    Month { month: u8, week: u8, weekday: u8 },
}

/// What a local time is in a zone.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Local {
    /// One instant shows it: the offset in force then, in milliseconds ahead
    /// of UTC.
    One(i64),
    /// No instant shows it: the clock went forward over it.
    Skipped,
    /// Two instants show it: the clock went back over it.
    Repeated,
}

/// Why a rule was refused, at the byte of the rule it was refused at.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct ZoneError {
    /// The byte of the rule text the refusal is at.
    pub(crate) at: usize,
    why: ZoneRefusal,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ZoneRefusal {
    Name,
    Offset,
    Unspellable,
    Date,
    Time,
    NoDates,
    Trailing,
}

impl fmt::Display for ZoneError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "the zone rule at byte {}: ", self.at)?;
        f.write_str(match self.why {
            ZoneRefusal::Name => {
                "a zone name is three or more letters, or three or more letters, digits, \
                 + or - between < and >"
            }
            ZoneRefusal::Offset => "an offset is [+|-]hh[:mm[:ss]], the hours at most 24",
            ZoneRefusal::Unspellable => {
                "an offset must be whole minutes and at most 23:59, as a time literal spells one"
            }
            ZoneRefusal::Date => {
                "a change date is Jn (1 to 365), n (0 to 365) or Mm.w.d (m 1 to 12, w 1 to 5, \
                 d 0 to 6)"
            }
            ZoneRefusal::Time => "a change time is [+|-]hh[:mm[:ss]], the hours at most 167",
            ZoneRefusal::NoDates => {
                "a rule that names a daylight zone says when it begins and ends \
                 (,start[/time],end[/time])"
            }
            ZoneRefusal::Trailing => "the rule ends here, and more text follows",
        })
    }
}

impl ZoneRule {
    /// `text` read as a POSIX TZ rule.
    ///
    /// # Errors
    ///
    /// The byte and the reason of the first thing the grammar does not admit,
    /// or a rule this module refuses (see the module doc).
    pub(super) fn parse(text: &str) -> Result<Self, ZoneError> {
        let mut rule = Cursor {
            text: text.as_bytes(),
            at: 0,
        };
        rule.name()?;
        let std_east_s = rule.zone_offset()?;
        if rule.done() {
            return Ok(Self {
                std_east_s,
                daylight: None,
            });
        }
        rule.name()?;
        let east_s = if rule.peek().is_some_and(starts_offset) {
            rule.zone_offset()?
        } else {
            let ahead = std_east_s + HOUR_S;
            if ahead > MAX_OFFSET_S {
                return Err(rule.refuse(ZoneRefusal::Unspellable));
            }
            ahead
        };
        match rule.peek() {
            None => return Err(rule.refuse(ZoneRefusal::NoDates)),
            Some(b',') => rule.at += 1,
            Some(_) => return Err(rule.refuse(ZoneRefusal::Trailing)),
        }
        let start = rule.change()?;
        if rule.peek() != Some(b',') {
            return Err(rule.refuse(ZoneRefusal::Date));
        }
        rule.at += 1;
        let end = rule.change()?;
        if !rule.done() {
            return Err(rule.refuse(ZoneRefusal::Trailing));
        }
        Ok(Self {
            std_east_s,
            daylight: Some(Daylight { east_s, start, end }),
        })
    }

    /// The offset of a zone that never changes its clock, in milliseconds
    /// ahead of UTC, or `None` for one that does.
    pub(super) fn fixed_east_ms(&self) -> Option<i64> {
        match self.daylight {
            None => Some(i64::from(self.std_east_s) * 1_000),
            Some(_) => None,
        }
    }

    /// The offset in force at the instant `utc_ms`, in milliseconds ahead of
    /// UTC.
    pub(super) fn east_ms_at(&self, utc_ms: i64) -> i64 {
        let std_ms = i64::from(self.std_east_s) * 1_000;
        let Some(daylight) = self.daylight else {
            return std_ms;
        };
        let year = civil_year((utc_ms + std_ms).div_euclid(DAY_MS));
        let start = daylight.start.instant_ms(year, self.std_east_s);
        let end = daylight.end.instant_ms(year, daylight.east_s);
        // A zone south of the equator puts its daylight clock on late in a
        // year and takes it off early in the next, so its daylight time is
        // what lies outside the year's two changes.
        let daylight_now = if start < end {
            start <= utc_ms && utc_ms < end
        } else {
            !(end <= utc_ms && utc_ms < start)
        };
        if daylight_now {
            i64::from(daylight.east_s) * 1_000
        } else {
            std_ms
        }
    }

    /// What the local time `local_ms` (milliseconds since 1970-01-01 00:00 on
    /// the zone's own clock) is in this zone: shown once, and at which offset,
    /// or skipped, or repeated.
    pub(super) fn resolve(&self, local_ms: i64) -> Local {
        let std_ms = i64::from(self.std_east_s) * 1_000;
        let Some(daylight) = self.daylight else {
            return Local::One(std_ms);
        };
        let dst_ms = i64::from(daylight.east_s) * 1_000;
        // A local time is shown at an offset when the instant it names at that
        // offset is one at which that offset is in force.
        let by_std = self.east_ms_at(local_ms - std_ms) == std_ms;
        let by_dst = self.east_ms_at(local_ms - dst_ms) == dst_ms;
        match (by_std, by_dst) {
            (true, false) => Local::One(std_ms),
            (false, true) => Local::One(dst_ms),
            (true, true) if std_ms == dst_ms => Local::One(std_ms),
            (true, true) => Local::Repeated,
            (false, false) => Local::Skipped,
        }
    }
}

impl Change {
    /// The instant of this change in `year`, in milliseconds since the epoch,
    /// for a zone whose clock before the change runs `before_east_s` ahead of
    /// UTC.
    fn instant_ms(&self, year: i64, before_east_s: i32) -> i64 {
        self.day.in_year(year) * DAY_MS + i64::from(self.at_s - before_east_s) * 1_000
    }
}

impl RuleDay {
    /// The day this falls on in `year`, in days since 1970-01-01.
    fn in_year(self, year: i64) -> i64 {
        let january_1 = days_from_civil(year, 1, 1);
        match self {
            Self::Julian(n) => {
                let n = i64::from(n);
                let leap_day = i64::from(is_leap(year) && n >= 60);
                january_1 + n - 1 + leap_day
            }
            Self::Ordinal(n) => january_1 + i64::from(n),
            Self::Month {
                month,
                week,
                weekday,
            } => {
                let first = days_from_civil(year, i64::from(month), 1);
                // 1970-01-01 was a Thursday, weekday 4.
                let first_weekday = (first + 4).rem_euclid(7);
                let mut day = first
                    + (i64::from(weekday) - first_weekday).rem_euclid(7)
                    + 7 * (i64::from(week) - 1);
                let last = first + days_in_month(year, i64::from(month)) - 1;
                // Week 5 is the last such weekday, in a month that has four.
                while day > last {
                    day -= 7;
                }
                day
            }
        }
    }
}

/// Whether `byte` can open an offset.
fn starts_offset(byte: u8) -> bool {
    byte.is_ascii_digit() || byte == b'+' || byte == b'-'
}

/// A rule being read, byte by byte.
struct Cursor<'a> {
    text: &'a [u8],
    at: usize,
}

impl Cursor<'_> {
    fn peek(&self) -> Option<u8> {
        self.text.get(self.at).copied()
    }

    fn done(&self) -> bool {
        self.at == self.text.len()
    }

    fn refuse(&self, why: ZoneRefusal) -> ZoneError {
        ZoneError { at: self.at, why }
    }

    /// A zone name, checked and passed over.
    fn name(&mut self) -> Result<(), ZoneError> {
        let from = self.at;
        if self.peek() == Some(b'<') {
            self.at += 1;
            let inner = self.at;
            while self
                .peek()
                .is_some_and(|b| b.is_ascii_alphanumeric() || b == b'+' || b == b'-')
            {
                self.at += 1;
            }
            if self.at - inner < 3 || self.peek() != Some(b'>') {
                return Err(ZoneError {
                    at: from,
                    why: ZoneRefusal::Name,
                });
            }
            self.at += 1;
            return Ok(());
        }
        while self.peek().is_some_and(|b| b.is_ascii_alphabetic()) {
            self.at += 1;
        }
        if self.at - from < 3 {
            return Err(ZoneError {
                at: from,
                why: ZoneRefusal::Name,
            });
        }
        Ok(())
    }

    /// `[+|-]hh[:mm[:ss]]` with the hours at most `max_hours`, in signed
    /// seconds, refused as `why`.
    fn signed_hms(&mut self, max_hours: u32, why: ZoneRefusal) -> Result<i32, ZoneError> {
        let from = self.at;
        let refused = ZoneError { at: from, why };
        let negative = match self.peek() {
            Some(b'-') => {
                self.at += 1;
                true
            }
            Some(b'+') => {
                self.at += 1;
                false
            }
            _ => false,
        };
        let hours = self.number(1, 3).ok_or(refused)?;
        if hours > max_hours {
            return Err(refused);
        }
        let mut seconds = hours * 3_600;
        for scale in [60, 1] {
            if self.peek() != Some(b':') {
                break;
            }
            self.at += 1;
            let part = self.number(2, 2).ok_or(refused)?;
            if part > 59 {
                return Err(refused);
            }
            seconds += part * scale;
        }
        let seconds = i32::try_from(seconds).map_err(|_| refused)?;
        Ok(if negative { -seconds } else { seconds })
    }

    /// A zone's offset, in seconds AHEAD of UTC (the text counts west).
    fn zone_offset(&mut self) -> Result<i32, ZoneError> {
        let from = self.at;
        let west = self.signed_hms(24, ZoneRefusal::Offset)?;
        if west % 60 != 0 || west.abs() > MAX_OFFSET_S {
            return Err(ZoneError {
                at: from,
                why: ZoneRefusal::Unspellable,
            });
        }
        Ok(-west)
    }

    /// A change: a date, then `/` and a time or none.
    fn change(&mut self) -> Result<Change, ZoneError> {
        let day = self.day()?;
        let at_s = if self.peek() == Some(b'/') {
            self.at += 1;
            self.signed_hms(MAX_CHANGE_HOURS, ZoneRefusal::Time)?
        } else {
            2 * HOUR_S
        };
        Ok(Change { day, at_s })
    }

    /// A change date in one of its three forms.
    fn day(&mut self) -> Result<RuleDay, ZoneError> {
        let refused = self.refuse(ZoneRefusal::Date);
        match self.peek() {
            Some(b'J') => {
                self.at += 1;
                let n = self.number(1, 3).ok_or(refused)?;
                match u16::try_from(n) {
                    Ok(n @ 1..=365) => Ok(RuleDay::Julian(n)),
                    _ => Err(refused),
                }
            }
            Some(b'M') => {
                self.at += 1;
                let month = self.small(2).ok_or(refused)?;
                let week = self.dotted().ok_or(refused)?;
                let weekday = self.dotted().ok_or(refused)?;
                if !(1..=12).contains(&month) || !(1..=5).contains(&week) || weekday > 6 {
                    return Err(refused);
                }
                Ok(RuleDay::Month {
                    month,
                    week,
                    weekday,
                })
            }
            _ => {
                let n = self.number(1, 3).ok_or(refused)?;
                match u16::try_from(n) {
                    Ok(n @ 0..=365) => Ok(RuleDay::Ordinal(n)),
                    _ => Err(refused),
                }
            }
        }
    }

    /// `.` and one digit.
    fn dotted(&mut self) -> Option<u8> {
        if self.peek() != Some(b'.') {
            return None;
        }
        self.at += 1;
        self.small(1)
    }

    /// One to `max` ASCII digits, `max` at most 2, read as a number.
    fn small(&mut self, max: usize) -> Option<u8> {
        u8::try_from(self.number(1, max)?).ok()
    }

    /// `min` to `max` ASCII digits, read as a number.
    fn number(&mut self, min: usize, max: usize) -> Option<u32> {
        let from = self.at;
        let mut value = 0u32;
        while self.at - from < max {
            match self.peek() {
                Some(b) if b.is_ascii_digit() => {
                    value = value * 10 + u32::from(b - b'0');
                    self.at += 1;
                }
                _ => break,
            }
        }
        (self.at - from >= min).then_some(value)
    }
}

/// Whether `year` of the proleptic Gregorian calendar is a leap year.
fn is_leap(year: i64) -> bool {
    year.rem_euclid(4) == 0 && (year.rem_euclid(100) != 0 || year.rem_euclid(400) == 0)
}

/// The days of `month` (1 to 12) of `year`.
fn days_in_month(year: i64, month: i64) -> i64 {
    match month {
        2 if is_leap(year) => 29,
        2 => 28,
        4 | 6 | 9 | 11 => 30,
        _ => 31,
    }
}

/// Days from 1970-01-01 to a date of the proleptic Gregorian calendar, before
/// 1970 too, counted in 400-year eras that begin on a 1 March.
fn days_from_civil(year: i64, month: i64, day: i64) -> i64 {
    let year = if month <= 2 { year - 1 } else { year };
    let era = year.div_euclid(400);
    let year_of_era = year - era * 400;
    let day_of_year = (153 * ((month + 9) % 12) + 2) / 5 + day - 1;
    let day_of_era = year_of_era * 365 + year_of_era / 4 - year_of_era / 100 + day_of_year;
    era * 146_097 + day_of_era - 719_468
}

/// The year of the proleptic Gregorian calendar `days` after 1970-01-01.
fn civil_year(days: i64) -> i64 {
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let day_of_era = z - era * 146_097;
    let year_of_era =
        (day_of_era - day_of_era / 1_460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let month_index = (5 * day_of_year + 2) / 153;
    let year = year_of_era + era * 400;
    // The era's year begins on 1 March, so January and February are the next
    // calendar year's.
    if month_index >= 10 {
        year + 1
    } else {
        year
    }
}

/// `text` split into a time and the zone rule written after it in brackets,
/// `12:04[CET-1CEST,M3.5.0,M10.5.0/3]`, or `None` for text with no rule.
pub(super) fn bracketed(text: &str) -> Option<(&str, &str)> {
    let inner = text.strip_suffix(']')?;
    let open = inner.find('[')?;
    if open == 0 {
        return None;
    }
    Some((&inner[..open], &inner[open + 1..]))
}

/// The instant a clock time names in a capture whose first instant is
/// `origin_ms`, in a zone that changes its clock: the moment the zone's clock
/// shows `of_day_ms` on the day it reads the first instant in. `None` where
/// that day skips or repeats the time, before the epoch, or past `u64`.
pub(super) fn anchor_in(origin_ms: u64, of_day_ms: u64, rule: &ZoneRule) -> Option<u64> {
    let origin = i64::try_from(origin_ms).ok()?;
    let local_origin = origin.checked_add(rule.east_ms_at(origin))?;
    let local = local_origin - local_origin.rem_euclid(DAY_MS) + i64::try_from(of_day_ms).ok()?;
    match rule.resolve(local) {
        Local::One(east_ms) => u64::try_from(local - east_ms).ok(),
        Local::Skipped | Local::Repeated => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const HOUR_MS: i64 = 3_600_000;
    const MINUTE_MS: i64 = 60_000;

    /// The local time `hour:minute` on `year-month-day`, in milliseconds since
    /// 1970-01-01 00:00 of the same clock.
    fn local(year: i64, month: i64, day: i64, hour: i64, minute: i64) -> i64 {
        days_from_civil(year, month, day) * DAY_MS + hour * HOUR_MS + minute * MINUTE_MS
    }

    /// Days since 1970-01-01 of a date.
    fn on(year: i64, month: i64, day: i64) -> i64 {
        days_from_civil(year, month, day)
    }

    fn rule(text: &str) -> ZoneRule {
        match ZoneRule::parse(text) {
            Ok(rule) => rule,
            Err(e) => panic!("{text}: {e}"),
        }
    }

    /// The first instant of a date, in milliseconds since the epoch.
    fn instant(year: i64, month: i64, day: i64) -> u64 {
        let ms = on(year, month, day) * DAY_MS;
        u64::try_from(ms).expect("after 1970")
    }

    const CET: &str = "CET-1CEST,M3.5.0,M10.5.0/3";

    #[test]
    fn the_calendar_helpers_agree_with_known_dates() {
        assert_eq!(days_from_civil(1970, 1, 1), 0);
        assert_eq!(days_from_civil(2026, 11, 23), 20_780);
        assert_eq!(days_from_civil(1969, 12, 31), -1);
        for days in [-800_000, -1, 0, 59, 60, 20_780, 2_000_000] {
            let year = civil_year(days);
            assert!(days_from_civil(year, 1, 1) <= days, "{days}");
            assert!(days < days_from_civil(year + 1, 1, 1), "{days}");
        }
        assert!(is_leap(2024) && is_leap(2000));
        assert!(!is_leap(1900) && !is_leap(2026));
    }

    #[test]
    fn every_form_of_a_change_date_falls_on_its_day() {
        // The last Sunday of March 2026 is the 29th, of October the 25th.
        let last_sunday = RuleDay::Month {
            month: 3,
            week: 5,
            weekday: 0,
        };
        assert_eq!(last_sunday.in_year(2026), days_from_civil(2026, 3, 29));
        let second_sunday = RuleDay::Month {
            month: 3,
            week: 2,
            weekday: 0,
        };
        assert_eq!(second_sunday.in_year(2026), days_from_civil(2026, 3, 8));
        // J60 is March 1 in every year; 59 is March 1 only where February has
        // 28 days.
        assert_eq!(RuleDay::Julian(60).in_year(2024), on(2024, 3, 1));
        assert_eq!(RuleDay::Julian(60).in_year(2026), on(2026, 3, 1));
        assert_eq!(RuleDay::Ordinal(59).in_year(2024), on(2024, 2, 29));
        assert_eq!(RuleDay::Ordinal(59).in_year(2026), on(2026, 3, 1));
        assert_eq!(RuleDay::Julian(1).in_year(2026), on(2026, 1, 1));
        assert_eq!(RuleDay::Ordinal(0).in_year(2026), on(2026, 1, 1));
    }

    #[test]
    fn a_fixed_zone_has_one_offset_and_shows_every_time_once() {
        let jst = rule("JST-9");
        assert_eq!(jst.fixed_east_ms(), Some(9 * HOUR_MS));
        assert_eq!(jst.east_ms_at(0), 9 * HOUR_MS);
        let skipped_elsewhere = local(2026, 3, 29, 2, 30);
        assert_eq!(jst.resolve(skipped_elsewhere), Local::One(9 * HOUR_MS));
        let quoted = rule("<+0530>-5:30");
        assert_eq!(quoted.fixed_east_ms(), Some(5 * HOUR_MS + 30 * MINUTE_MS));
        // Positive is WEST of UTC.
        assert_eq!(rule("EST5").fixed_east_ms(), Some(-5 * HOUR_MS));
        assert_eq!(rule("UTC0").fixed_east_ms(), Some(0));
        assert_eq!(rule(CET).fixed_east_ms(), None);
    }

    /// Central Europe goes forward at 01:00 UTC on the last Sunday of March
    /// (02:00 becomes 03:00) and back at 01:00 UTC on the last Sunday of
    /// October (03:00 becomes 02:00).
    #[test]
    fn the_offset_in_force_moves_at_both_changes() {
        let cet = rule(CET);
        let spring = days_from_civil(2026, 3, 29) * DAY_MS + HOUR_MS;
        let autumn = days_from_civil(2026, 10, 25) * DAY_MS + HOUR_MS;
        assert_eq!(cet.east_ms_at(spring - 1), HOUR_MS);
        assert_eq!(cet.east_ms_at(spring), 2 * HOUR_MS);
        assert_eq!(cet.east_ms_at(autumn - 1), 2 * HOUR_MS);
        assert_eq!(cet.east_ms_at(autumn), HOUR_MS);
        assert_eq!(cet.east_ms_at(on(2026, 1, 15) * DAY_MS), HOUR_MS);
        assert_eq!(cet.east_ms_at(on(2026, 7, 15) * DAY_MS), 2 * HOUR_MS);
    }

    #[test]
    fn the_hour_skipped_and_the_hour_repeated_name_no_single_instant() {
        let cet = rule(CET);
        let at = |month, day, hour, minute| cet.resolve(local(2026, month, day, hour, minute));
        assert_eq!(at(3, 29, 1, 59), Local::One(HOUR_MS));
        assert_eq!(at(3, 29, 2, 0), Local::Skipped);
        assert_eq!(at(3, 29, 2, 30), Local::Skipped);
        assert_eq!(at(3, 29, 3, 0), Local::One(2 * HOUR_MS));
        assert_eq!(at(10, 25, 1, 59), Local::One(2 * HOUR_MS));
        assert_eq!(at(10, 25, 2, 0), Local::Repeated);
        assert_eq!(at(10, 25, 2, 59), Local::Repeated);
        assert_eq!(at(10, 25, 3, 0), Local::One(HOUR_MS));
    }

    /// Eastern Australia: daylight from the first Sunday of October to the
    /// first Sunday of April, across the new year.
    #[test]
    fn a_southern_zone_keeps_its_daylight_clock_across_the_new_year() {
        let sydney = rule("AEST-10AEDT,M10.1.0,M4.1.0/3");
        let ahead = |days: i64| sydney.east_ms_at(days * DAY_MS);
        assert_eq!(ahead(on(2026, 1, 1)), 11 * HOUR_MS);
        assert_eq!(ahead(on(2026, 6, 1)), 10 * HOUR_MS);
        assert_eq!(ahead(on(2026, 12, 31)), 11 * HOUR_MS);
        let at = |month, day, hour, minute| sydney.resolve(local(2026, month, day, hour, minute));
        // 2026-10-04 is the first Sunday of October: 02:00 becomes 03:00.
        assert_eq!(at(10, 4, 2, 30), Local::Skipped);
        // 2026-04-05 is the first Sunday of April: 03:00 becomes 02:00.
        assert_eq!(at(4, 5, 2, 30), Local::Repeated);
        assert_eq!(at(4, 5, 3, 30), Local::One(10 * HOUR_MS));
    }

    /// The Julian and ordinal forms, an explicit daylight offset, a change
    /// time past 24 hours and a negative one all read as POSIX states them.
    #[test]
    fn the_julian_and_ordinal_forms_and_wide_times_read_as_stated() {
        let julian = rule("XXX3YYY2,J60/-1,J300/25");
        // Daylight from 23:00 local (02:00 UTC) on the last day of February.
        let begins = days_from_civil(2026, 3, 1) * DAY_MS - HOUR_MS + 3 * HOUR_MS;
        assert_eq!(julian.east_ms_at(begins - 1), -3 * HOUR_MS);
        assert_eq!(julian.east_ms_at(begins), -2 * HOUR_MS);
        // J300 is October 27 in 2026; 25:00 is 01:00 on the 28th, local.
        let ends = days_from_civil(2026, 10, 27) * DAY_MS + 25 * HOUR_MS + 2 * HOUR_MS;
        assert_eq!(julian.east_ms_at(ends - 1), -2 * HOUR_MS);
        assert_eq!(julian.east_ms_at(ends), -3 * HOUR_MS);
        let ordinal = rule("<-03>3<-02>,59,299/167");
        assert_eq!(ordinal.fixed_east_ms(), None);
        assert!(ZoneRule::parse("XXX3YYY,0/-167,365/167").is_ok());
    }

    #[test]
    fn what_the_grammar_does_not_admit_is_refused_at_its_byte() {
        for (text, at) in [
            ("", 0),
            ("CE-1", 0),
            ("CET", 3),
            ("CET-25", 3),
            ("CET-1:60", 3),
            ("CET-1:00:30", 3),
            ("<AB>-1", 0),
            ("<ABC-1", 0),
            ("CET-1CEST", 9),
            ("CET-1CEST;M3.5.0,M10.5.0", 9),
            ("CET-1CEST,M13.5.0,M10.5.0", 10),
            ("CET-1CEST,M3.6.0,M10.5.0", 10),
            ("CET-1CEST,M3.5.7,M10.5.0", 10),
            ("CET-1CEST,J0,M10.5.0", 10),
            ("CET-1CEST,366,M10.5.0", 10),
            ("CET-1CEST,M3.5.0", 16),
            ("CET-1CEST,M3.5.0/168,M10.5.0", 17),
            ("CET-1CEST,M3.5.0,M10.5.0/3x", 26),
            ("CET-1x", 5),
        ] {
            let error = ZoneRule::parse(text).expect_err(text);
            assert_eq!(error.at, at, "{text}: {error}");
        }
    }

    #[test]
    fn a_clock_time_on_a_capture_day_takes_that_days_offset() {
        let cet = rule(CET);
        let hour = 3_600_000;
        let noon = 12 * hour;
        // A capture that began in January reads 12:00 at +01:00, one that began
        // in July at +02:00.
        let january = instant(2026, 1, 15);
        let july = instant(2026, 7, 15);
        assert_eq!(anchor_in(january, noon, &cet), Some(january + 11 * hour));
        assert_eq!(anchor_in(july, noon, &cet), Some(july + 10 * hour));
        // On the day the clock goes forward 02:30 is shown by no instant, and
        // on the day it goes back by two.
        let spring = instant(2026, 3, 29);
        let autumn = instant(2026, 10, 25);
        let half_past_two = 2 * hour + 30 * 60_000;
        assert_eq!(anchor_in(spring, half_past_two, &cet), None);
        assert_eq!(anchor_in(autumn, half_past_two, &cet), None);
        assert!(anchor_in(spring, noon, &cet).is_some());
    }

    #[test]
    fn a_rule_in_brackets_is_split_from_its_time() {
        assert_eq!(
            bracketed("12:04[CET-1CEST,M3.5.0,M10.5.0/3]"),
            Some(("12:04", "CET-1CEST,M3.5.0,M10.5.0/3"))
        );
        assert_eq!(bracketed("12:04"), None);
        assert_eq!(bracketed("[CET-1]"), None);
        assert_eq!(bracketed("12:04[CET-1"), None);
    }
}
