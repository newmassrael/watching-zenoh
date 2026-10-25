// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! `zenoh-util`, the time range language (the first slice of the crate): upstream's crate
//! (`up_util`) and wz's (`wz_util`) given the same strings to parse, results equal as text.
//!
//! * A GRID of strings: every pair of delimiters over a set of time expressions (unbounded, offsets
//!   in each unit, the instants a parser takes and the ones it refuses, malformed offsets) in the
//!   range syntax, and the same starts over a set of durations in the duration syntax.
//! * SEEDED DRAWS of strings over the alphabet of the language and a few non-ASCII characters, so a
//!   string the grid did not think of reaches the parsers.
//! * What a parsed range does: its text, its resolution at a fixed instant, and whether it holds a
//!   set of instants; the checked sums and differences of a time expression, and the plain sum.
//!
//! Upstream parses a string that a user wrote into a time range, and two of its paths panic where
//! the user meant an error. Each is a class, built by hand, counted and held on both sides:
//!
//! * a duration that is the lone unit `s` (`now(s)`, `[now();s]`): upstream asks the iterator over
//!   the bytes for a byte it has already taken and panics, wz refuses the duration;
//! * a start that is an instant, with a duration that is negative, not a number, infinite, or past
//!   what a `SystemTime` holds: upstream adds the duration to the instant with `Add<f64>`, whose
//!   `Duration::from_secs_f64` panics on each of them, wz adds with the checked sum, so a negative
//!   duration moves the end back as it does for an offset and the ones no instant can hold are
//!   refused.
//!
//! The root of the crate (the zenoh home, the logging) is held by `zenoh_util_process.rs`, which
//! runs each in a process of its own.

use std::{
    cell::Cell,
    panic::{catch_unwind, set_hook, take_hook, AssertUnwindSafe},
    sync::Once,
    time::{Duration, SystemTime},
};

use rand::{rngs::StdRng, Rng, SeedableRng};

thread_local! {
    static QUIET: Cell<bool> = const { Cell::new(false) };
}

/// Runs `f`, and says `None` if it panicked, without the report of the panic: a parser that panics
/// is a result of this comparison, and the report would be noise.
fn guarded<T>(f: impl FnOnce() -> T) -> Option<T> {
    static HOOK: Once = Once::new();
    HOOK.call_once(|| {
        let previous = take_hook();
        set_hook(Box::new(move |info| {
            if !QUIET.with(Cell::get) {
                previous(info)
            }
        }));
    });
    QUIET.with(|q| q.set(true));
    let out = catch_unwind(AssertUnwindSafe(f)).ok();
    QUIET.with(|q| q.set(false));
    out
}

/// An error as text without the place of the crate that made it.
fn plain(e: &impl std::fmt::Display) -> String {
    let s = e.to_string();
    s.split(" at ").next().unwrap_or("").to_string()
}

const PANIC: &str = "PANIC";

/// The fixed instant the resolutions are made at, and the instants a range is asked about.
fn now() -> SystemTime {
    SystemTime::UNIX_EPOCH + Duration::from_secs(1_700_000_000)
}

fn instants() -> Vec<SystemTime> {
    vec![
        SystemTime::UNIX_EPOCH,
        now() - Duration::from_secs(3600),
        now() - Duration::from_secs(1),
        now(),
        now() + Duration::from_secs(1),
        now() + Duration::from_secs(3600),
        now() + Duration::from_secs(86_400 * 365),
    ]
}

macro_rules! time_cases {
    ($m:ident, $u:ident) => {
        mod $m {
            use std::time::{Duration, SystemTime};

            use $u::time_range::{TimeBound, TimeExpr, TimeRange};

            use super::{guarded, instants, now, plain, PANIC};

            /// The text of a value's `Display`, or `PANIC` if it panics: `humantime` cannot format
            /// an instant past the year 9999, which both crates ask it to, so a range that parses
            /// can still panic when it is shown.
            fn shown(f: impl FnOnce() -> String) -> String {
                guarded(f).unwrap_or_else(|| PANIC.to_string())
            }

            /// What a string parses to as a range, and what the range does. `PANIC` alone is a
            /// parser that panicked; a display that panics is inside an `ok`.
            pub fn range(s: &str) -> String {
                match guarded(|| s.parse::<TimeRange>()) {
                    None => PANIC.to_string(),
                    Some(Err(e)) => format!("err {}", plain(&e)),
                    Some(Ok(r)) => {
                        let resolved = r.resolve_at(now());
                        let holds: String = instants()
                            .iter()
                            .map(|t| if resolved.contains(*t) { '1' } else { '0' })
                            .collect();
                        format!(
                            "ok {r:?} | {} | {resolved:?} | {} | {holds}",
                            shown(|| r.to_string()),
                            shown(|| resolved.to_string())
                        )
                    }
                }
            }

            /// What a string parses to as a time expression.
            pub fn expr(s: &str) -> String {
                match guarded(|| s.parse::<TimeExpr>()) {
                    None => PANIC.to_string(),
                    Some(Err(e)) => format!("err {}", plain(&e)),
                    Some(Ok(t)) => format!("ok {t:?} | {}", shown(|| t.to_string())),
                }
            }

            fn exprs() -> Vec<TimeExpr> {
                vec![
                    TimeExpr::Fixed(SystemTime::UNIX_EPOCH),
                    TimeExpr::Fixed(now()),
                    TimeExpr::Now { offset_secs: 0.0 },
                    TimeExpr::Now { offset_secs: 90.5 },
                    TimeExpr::Now {
                        offset_secs: -3600.0,
                    },
                    TimeExpr::Now {
                        offset_secs: f64::MAX,
                    },
                    TimeExpr::Now {
                        offset_secs: f64::NAN,
                    },
                ]
            }

            pub const DURATIONS: [f64; 11] = [
                0.0,
                1.0,
                -1.0,
                0.25,
                3600.5,
                -86_400.0,
                1e12,
                1e19,
                f64::MAX,
                f64::INFINITY,
                f64::NAN,
            ];

            /// The checked sums and differences, the resolutions and the plain sum of every
            /// expression with every duration.
            pub fn arithmetic() -> Vec<String> {
                let mut out = Vec::new();
                for t in exprs() {
                    for d in DURATIONS {
                        out.push(format!(
                            "{t:?} + {d:?}: add {:?} sub {:?}",
                            t.checked_add(d),
                            t.checked_sub(d)
                        ));
                        let plus = guarded(|| format!("{:?}", t + d));
                        let plus_ref = guarded(|| format!("{:?}", &t + d));
                        out.push(format!("{t:?} {d:?}: plus {plus:?} plus_ref {plus_ref:?}"));
                    }
                    out.push(format!(
                        "{t:?}: resolve {:?} checked {:?}",
                        guarded(|| t.resolve_at(now())),
                        t.checked_resolve_at(now())
                    ));
                    let bound = TimeBound::Inclusive(t);
                    out.push(format!("{t:?}: bound {:?}", bound.resolve_at(now())));
                }
                out
            }

            /// The conversions between the range and bound of an expression and of an instant.
            pub fn conversions() -> Vec<String> {
                let mut out = Vec::new();
                let fixed: TimeRange<SystemTime> = TimeRange {
                    start: TimeBound::Inclusive(SystemTime::UNIX_EPOCH),
                    end: TimeBound::Exclusive(now()),
                };
                let as_expr: TimeRange<TimeExpr> = fixed.into();
                out.push(format!("{as_expr:?} | {as_expr} | {fixed}"));
                out.push(format!(
                    "{:?}",
                    TimeRange::<SystemTime>::try_from(as_expr).map(|r| r.to_string())
                ));
                let with_now: TimeRange<TimeExpr> = "[now(-1s)..now(1s)]".parse().unwrap();
                out.push(format!(
                    "{:?}",
                    TimeRange::<SystemTime>::try_from(with_now).map(|r| r.to_string())
                ));
                for t in exprs() {
                    out.push(format!("{t:?}: {:?}", SystemTime::try_from(t)));
                }
                out
            }
        }
    };
}

time_cases!(up, up_util);
time_cases!(wz, wz_util);

const DELIMITERS: [(char, char); 4] = [('[', ']'), (']', '['), ('[', '['), (']', ']')];

/// Time expressions of the language: what it takes and what it refuses.
const EXPRS: [&str; 24] = [
    "",
    "now()",
    "now(0)",
    "now(1s)",
    "now(-1s)",
    "now(1.5ms)",
    "now(2u)",
    "now(3m)",
    "now(-1h)",
    "now(1d)",
    "now(1w)",
    "now(123.45)",
    "1970-01-01T00:00:00Z",
    "2022-06-30T01:02:03.226942997Z",
    "2022-06-30 01:02:03Z",
    "2022-06-30T01:02:03",
    "2020-11-05",
    "bogus",
    "now(",
    "now(x)",
    "now(1x)",
    "now(1h4m)",
    "now(-)",
    "now(--1s)",
];

const DUR_STRINGS: [&str; 22] = [
    "0", "1s", "1.5h", "100ms", "2u", "1d", "1w", "5", "-1s", "-0.5h", "NaN", "inf", "-inf",
    "1e30", "1e19s", "1e12", "s", "ms", "m", "x", "1x", "",
];

/// The strings of the grid.
fn grid() -> Vec<String> {
    let mut out = Vec::new();
    for (l, r) in DELIMITERS {
        for start in EXPRS {
            for end in EXPRS {
                out.push(format!("{l}{start}..{end}{r}"));
            }
            for dur in DUR_STRINGS {
                out.push(format!("{l}{start};{dur}{r}"));
            }
        }
    }
    // Shapes with no separator, or the wrong delimiters, or too short.
    for s in [
        "",
        "[",
        "[]",
        "[..",
        "..]",
        "[..]",
        "(..)",
        "[.]",
        "[;]",
        "[;1h]",
        "[a;]",
        "x[..]",
        "[..]x",
        "[a..b..c]",
        "[a;b;c]",
        "[..;..]",
    ] {
        out.push(s.to_string());
    }
    out
}

/// Strings of the grid changed at a few places by a character of the alphabet of the language or a
/// few outside it (replaced, deleted, inserted, repeated), so a string near the language reaches
/// the parsers from every side, and a few drawn from the alphabet alone.
fn draws(seed: u64, n: usize) -> Vec<String> {
    let alphabet: Vec<char> = "[]..;;now()-0123456789smhdwu TZ:é日".chars().collect();
    let grid = grid();
    let mut rng = StdRng::seed_from_u64(seed);
    (0..n)
        .map(|k| {
            if k % 20 == 0 {
                let len = rng.gen_range(0..14);
                return (0..len)
                    .map(|_| alphabet[rng.gen_range(0..alphabet.len())])
                    .collect();
            }
            let mut chars: Vec<char> = grid[rng.gen_range(0..grid.len())].chars().collect();
            for _ in 0..rng.gen_range(1..4) {
                let at = rng.gen_range(0..=chars.len());
                match rng.gen_range(0..4) {
                    0 if at < chars.len() => chars[at] = alphabet[rng.gen_range(0..alphabet.len())],
                    1 if at < chars.len() => {
                        chars.remove(at);
                    }
                    2 => chars.insert(at, alphabet[rng.gen_range(0..alphabet.len())]),
                    _ if at < chars.len() => chars.insert(at, chars[at]),
                    _ => {}
                }
            }
            chars.into_iter().collect()
        })
        .collect()
}

#[test]
fn both_crates_parse_every_string_of_the_grid_to_the_same_range_but_for_the_two_classes() {
    let strings = grid();
    assert_eq!(strings.len(), 4 * 24 * (24 + 22) + 16);
    let (mut equal, mut ok, mut classed) = (0usize, 0usize, 0usize);
    for s in &strings {
        let (a, b) = (up::range(s), wz::range(s));
        // wz never panics.
        assert_ne!(b, PANIC, "{s:?}");
        if a == b {
            equal += 1;
            ok += a.starts_with("ok") as usize;
        } else {
            // The only difference: upstream panicked.
            assert_eq!(a, PANIC, "{s:?}\nup {a}\nwz {b}");
            classed += 1;
        }
    }
    assert!(equal > 4_000 && ok > 1_500, "{equal} {ok}");
    assert!(classed > 100, "{classed}");
}

#[test]
fn both_crates_parse_seeded_strings_alike_but_for_the_two_classes() {
    let strings = draws(0x7E11, 200_000);
    let (mut equal, mut ok, mut classed) = (0usize, 0usize, 0usize);
    for s in &strings {
        let (a, b) = (up::range(s), wz::range(s));
        assert_ne!(b, PANIC, "{s:?}");
        if a == b {
            equal += 1;
            ok += a.starts_with("ok") as usize;
        } else {
            assert_eq!(a, PANIC, "{s:?}\nup {a}\nwz {b}");
            classed += 1;
        }
        // The same string as a time expression.
        let (a, b) = (up::expr(s), wz::expr(s));
        assert_ne!(b, PANIC, "{s:?}");
        if a != b {
            assert_eq!(a, PANIC, "{s:?}\nup {a}\nwz {b}");
            classed += 1;
        }
    }
    assert!(equal > 190_000, "{equal}");
    // The draws reach the accepted language too, and the classes.
    assert!(ok > 50, "{ok}");
    assert!(classed > 0, "{classed}");
}

#[test]
fn both_crates_parse_every_expression_and_duration_alike_but_for_a_lone_unit() {
    // As time expressions, with the duration a time expression carries inside `now(..)`.
    let mut classed = 0usize;
    for d in DUR_STRINGS {
        for sign in ["", "-"] {
            let s = format!("now({sign}{d})");
            let (a, b) = (up::expr(&s), wz::expr(&s));
            assert_ne!(b, PANIC, "{s:?}");
            if a != b {
                // Only the lone unit.
                assert_eq!(a, PANIC, "{s:?}");
                assert!(d == "s", "{s:?}: {a} {b}");
                classed += 1;
            }
        }
    }
    // `now(s)` and `now(-s)`.
    assert_eq!(classed, 2);
}

#[test]
fn a_lone_unit_s_panics_upstream_and_is_refused_by_wz() {
    for s in [
        "now(s)",
        "now(-s)",
        "[now();s]",
        "[now(1s);s]",
        "]1970-01-01T00:00:00Z;s[",
    ] {
        let kind = if s.starts_with("now") {
            "expr"
        } else {
            "range"
        };
        let (a, b) = if kind == "expr" {
            (up::expr(s), wz::expr(s))
        } else {
            (up::range(s), wz::range(s))
        };
        assert_eq!(a, PANIC, "{s}");
        assert!(b.starts_with("err"), "{s}: {b}");
        assert!(b.contains("Invalid duration"), "{s}: {b}");
    }
    // The neighbours are read alike: a unit with something before it, and the other lone units.
    for s in [
        "now(0s)", "now(1s)", "now(ms)", "now(m)", "now(u)", "now(h)", "now(d)", "now(w)",
    ] {
        assert_eq!(up::expr(s), wz::expr(s), "{s}");
    }
    // `ms` and `m` and the like are refused by both (a unit with no number), none panics.
    for s in ["now(ms)", "now(m)", "now(u)", "now(h)", "now(d)", "now(w)"] {
        assert!(wz::expr(s).starts_with("err"), "{s}");
    }
}

#[test]
fn an_instant_with_a_duration_nothing_can_hold_panics_upstream_and_is_handled_by_wz() {
    let start = "2022-06-30T01:02:03Z";
    // Not a number, infinite, past what an instant holds: refused by wz, a panic upstream.
    for d in ["NaN", "inf", "1e30", "1e19s", "1e400"] {
        for (l, r) in DELIMITERS {
            let s = format!("{l}{start};{d}{r}");
            let (a, b) = (up::range(&s), wz::range(&s));
            assert_eq!(a, PANIC, "{s}");
            assert!(b.starts_with("err"), "{s}: {b}");
            assert!(b.contains("cannot be represented"), "{s}: {b}");
        }
    }
    // Negative: a panic upstream, and for wz the end is before the start by the duration, as it
    // is for an offset.
    for d in ["-1s", "-0.5h", "-1d"] {
        let s = format!("[{start};{d}]");
        let (a, b) = (up::range(&s), wz::range(&s));
        assert_eq!(a, PANIC, "{s}");
        assert!(b.starts_with("ok"), "{s}: {b}");
        let at_now = format!("[now();{d}]");
        assert!(wz::range(&at_now).starts_with("ok"), "{at_now}");
        assert_eq!(up::range(&at_now), wz::range(&at_now), "{at_now}");
    }
    let (a, b) = (
        up::range("[2022-06-30T01:02:03Z;-1s]"),
        wz::range("[2022-06-30T01:02:03Z;-1s]"),
    );
    assert_eq!(a, PANIC);
    assert!(
        b.contains("[2022-06-30T01:02:03Z..2022-06-30T01:02:02Z]"),
        "{b}"
    );
    // The durations an instant holds are read alike, in each of the two syntaxes.
    for d in ["0", "1s", "1.5h", "100ms", "2u", "1d", "1w", "1e12"] {
        let s = format!("[{start};{d}]");
        assert_eq!(up::range(&s), wz::range(&s), "{s}");
        assert!(wz::range(&s).starts_with("ok"), "{s}");
    }
    // An offset with any duration, which sums as a float, is read alike by both and never panics.
    for d in ["NaN", "inf", "1e30", "-1s", "1e19s"] {
        let s = format!("[now();{d}]");
        assert_eq!(up::range(&s), wz::range(&s), "{s}");
    }
}

#[test]
fn both_crates_do_the_arithmetic_of_a_time_expression_alike() {
    let (u, w) = (up::arithmetic(), wz::arithmetic());
    // Per expression: two rows for each of the eleven durations, then its resolution and its bound.
    assert_eq!(u.len(), 7 * (11 * 2 + 2));
    for (a, b) in u.iter().zip(&w) {
        assert_eq!(a, b);
    }
    // Some sums panic (a duration that cannot be an instant) and some do not.
    assert!(u.iter().any(|r| r.contains("plus None")), "{u:?}");
    assert!(u.iter().any(|r| r.contains("plus Some(")), "{u:?}");
}

#[test]
fn both_crates_convert_ranges_and_bounds_alike() {
    let (u, w) = (up::conversions(), wz::conversions());
    assert_eq!(u, w);
    assert!(u.len() >= 10);
}

/// The control: the comparison is on text, so a string that differs gives a row that differs.
#[test]
fn the_comparison_sees_a_range_that_differs() {
    assert_ne!(wz::range("[now()..now(1s)]"), wz::range("[now()..now(2s)]"));
    assert_ne!(wz::range("[now()..now(1s)]"), wz::range("]now()..now(1s)]"));
    assert_ne!(wz::expr("now(1s)"), wz::expr("now(1m)"));
    assert_ne!(wz::range("[..]"), wz::range("[..now()]"));
}
