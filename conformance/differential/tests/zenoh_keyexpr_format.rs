// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! `zenoh-keyexpr`, formats: upstream's crate (`up_keyexpr`) and wz's (`wz_keyexpr`) given the same
//! formats, targets and values, outputs equal.
//!
//! Formats are built from a small set of chunks (plain ones, specs with each kind of pattern, the two
//! spellings of a spec, and the shapes a format refuses) in every sequence up to three. Each is
//! constructed, displayed, filled in by a formatter, and used to parse every canon key expression of
//! up to three chunks over a small set of chunks, which includes the wildcards and a verbatim chunk.
//!
//! Two classes are not compared, because upstream is wrong in them and wz follows the documented
//! syntax; each is counted, and wz is held to its own definition there:
//! * a spec with a DEFAULT (`${id:pattern#default}`): upstream stores the offset of the `#` relative
//!   to the pattern and reads it as an offset into the whole spec, so the pattern of every such spec
//!   is cut wrong, and a format that has one panics or is refused. wz parses a spec with a default as
//!   the same spec without it, and uses the default for a field nothing was set for;
//! * a format whose last character is a `$`, and a format with no spec at all, on which upstream
//!   panics (an index past the end, an underflow).

macro_rules! cases {
    ($name:ident, $ke:ident) => {
        mod $name {
            use $ke::{format::KeFormat, keyexpr};

            /// An error's text without the place it was raised at.
            fn text(e: impl std::fmt::Display) -> String {
                let t = e.to_string();
                t.split(" at ").next().unwrap().to_string()
            }

            pub fn construct(f: &str) -> Result<String, String> {
                KeFormat::new(f)
                    .map(|k| format!("{k} | {k:?}"))
                    .map_err(text)
            }

            pub fn parse(f: &str, t: &str) -> Result<Vec<(String, Option<String>)>, String> {
                let format = KeFormat::new(f).map_err(text)?;
                let target = keyexpr::new(t).unwrap();
                let parsed = format.parse(target).map_err(text)?;
                let got: Vec<(String, Option<String>)> = parsed
                    .iter()
                    .map(|(id, v)| (id.to_string(), v.map(|k| k.to_string())))
                    .collect();
                // The accessor agrees with the iterator for every id.
                for (id, v) in &got {
                    assert_eq!(parsed.get(id).unwrap(), v.as_deref().unwrap_or(""));
                }
                Ok(got)
            }

            /// Fill each of `sets` in order on a fresh formatter, and build.
            pub fn format_with(f: &str, sets: &[(&str, &str)]) -> Result<String, String> {
                let format = KeFormat::new(f).map_err(text)?;
                let mut formatter = format.formatter();
                for (id, value) in sets {
                    if let Err(e) = formatter.set(id, value) {
                        return Err(format!("set {id}: {e}"));
                    }
                }
                let debug = format!("{formatter:?}");
                formatter
                    .build()
                    .map(|k| format!("{k} | {debug}"))
                    .map_err(|e| format!("{} | {debug}", text(e)))
            }
        }
    };
}

cases!(c_up, up_keyexpr);
cases!(c_wz, wz_keyexpr);

thread_local! {
    static QUIET: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

/// `f()`, or `None` if it panicked. The panic message is not printed.
fn catching<T>(f: impl FnOnce() -> T) -> Option<T> {
    static HOOK: std::sync::Once = std::sync::Once::new();
    HOOK.call_once(|| {
        let default = std::panic::take_hook();
        std::panic::set_hook(Box::new(move |info| {
            if !QUIET.with(|q| q.get()) {
                default(info)
            }
        }));
    });
    QUIET.with(|q| q.set(true));
    let out = std::panic::catch_unwind(std::panic::AssertUnwindSafe(f)).ok();
    QUIET.with(|q| q.set(false));
    out
}

/// A chunk of a format, and the chunk it is once its default (if it has one) is taken away.
type Chunk = (&'static str, &'static str);

/// The chunks a format is made of. Each spec has an id of its own, so a sequence of distinct ones
/// has no duplicate id, and a sequence that repeats one has.
const FORMAT_CHUNKS: &[Chunk] = &[
    ("a", "a"),
    ("b/c", "b/c"),
    ("${x:*}", "${x:*}"),
    ("${y:**}", "${y:**}"),
    ("${z:a}", "${z:a}"),
    ("${w:a/*}", "${w:a/*}"),
    ("${v:**/b}", "${v:**/b}"),
    ("$#{u:a$*}#", "$#{u:a$*}#"),
    ("@v", "@v"),
    ("a$*", "a$*"),
    ("*", "*"),
    ("${x:*}x", "${x:*}x"),
    ("${bad}", "${bad}"),
    ("${:*}", "${:*}"),
    ("${q:}", "${q:}"),
    // with a default
    ("${t:*#d}", "${t:*}"),
    ("${s:**#}", "${s:**}"),
    ("${p:a#b#c}", "${p:a}"),
];

/// The chunks of the key expressions a format is parsed against.
const TARGET_CHUNKS: &[&str] = &["a", "b", "c", "*", "**", "a$*", "@v", "d"];

/// Every sequence of at most `max` of `chunks`, as the format text and the same with its defaults
/// taken away.
fn formats(max: usize) -> Vec<(String, String)> {
    let mut all = Vec::new();
    let mut frontier: Vec<Vec<Chunk>> = vec![vec![]];
    for _ in 0..max {
        let mut next = Vec::new();
        for seq in &frontier {
            for c in FORMAT_CHUNKS {
                let mut s = seq.clone();
                s.push(*c);
                let join = |pick: fn(&Chunk) -> &'static str| {
                    s.iter().map(pick).collect::<Vec<_>>().join("/")
                };
                all.push((join(|c| c.0), join(|c| c.1)));
                next.push(s);
            }
        }
        frontier = next;
    }
    all
}

/// The key expressions of at most `max` of `TARGET_CHUNKS`.
fn targets(max: usize) -> Vec<String> {
    let mut all = Vec::new();
    let mut frontier: Vec<Vec<&str>> = vec![vec![]];
    for _ in 0..max {
        let mut next = Vec::new();
        for seq in &frontier {
            for c in TARGET_CHUNKS {
                let mut s = seq.clone();
                s.push(c);
                all.push(s.join("/"));
                next.push(s);
            }
        }
        frontier = next;
    }
    all.retain(|t| wz_keyexpr::keyexpr::new(t).is_ok());
    all
}

/// Whether a format has a default in it, which is the first class upstream is wrong in.
fn has_default(f: &str, stripped: &str) -> bool {
    f != stripped
}

/// Whether upstream panics on a format whatever the target: the second class.
fn upstream_panics_on_construction(f: &str) -> bool {
    catching(|| c_up::construct(f)).is_none()
}

/// What each class holds, counted.
#[derive(Default, Debug)]
struct Classes {
    compared: usize,
    defaults: usize,
    upstream_panics: usize,
}

#[test]
fn both_crates_construct_every_format_alike() {
    let mut classes = Classes::default();
    let mut built = 0;
    for (f, stripped) in formats(3) {
        if has_default(&f, &stripped) {
            classes.defaults += 1;
            // wz parses a spec with a default as the spec without it, and shows the default.
            let ours = c_wz::construct(&f);
            let plain = c_wz::construct(&stripped);
            assert_eq!(
                ours.is_ok(),
                plain.is_ok(),
                "a default changes whether `{f}` builds"
            );
            if let Ok(shown) = ours {
                // `$#{..}#` is shown as `${..}` when nothing in it needs the sharps, so the text is
                // not compared whole; the default is what must still be there.
                assert!(shown.contains('#'), "`{f}` is displayed as `{shown}`");
            }
            continue;
        }
        let Some(theirs) = catching(|| c_up::construct(&f)) else {
            classes.upstream_panics += 1;
            assert!(
                catching(|| c_wz::construct(&f)).is_some(),
                "wz panics on `{f}`"
            );
            continue;
        };
        let ours = c_wz::construct(&f);
        assert_eq!(theirs, ours, "construct of `{f}`");
        classes.compared += 1;
        built += ours.is_ok() as usize;
    }
    eprintln!("construct: {classes:?}, {built} built");
    assert!(built > 100 && classes.defaults > 0 && classes.upstream_panics > 0);
}

#[test]
fn both_crates_parse_every_target_with_every_format_alike() {
    let formats: Vec<(String, String)> = formats(3)
        .into_iter()
        .filter(|(f, s)| c_wz::construct(f).is_ok() && c_wz::construct(s).is_ok())
        .collect();
    let targets = targets(3);
    assert!(
        formats.len() > 100 && targets.len() > 100,
        "{} x {}",
        formats.len(),
        targets.len()
    );
    let mut classes = Classes::default();
    let mut parsed = 0usize;
    for (f, stripped) in &formats {
        let panics = !has_default(f, stripped) && upstream_panics_on_construction(f);
        for t in &targets {
            if has_default(f, stripped) {
                // A default does not take part in parsing: the answer is that of the plain format.
                classes.defaults += 1;
                // The values are the plain format's; a refusal's text names the format, so only
                // that it is a refusal is compared.
                let (with, without) = (c_wz::parse(f, t), c_wz::parse(stripped, t));
                if !(with.is_err() && without.is_err()) {
                    assert_eq!(with, without, "`{f}` against `{t}`");
                }
            } else if panics {
                classes.upstream_panics += 1;
                assert!(
                    catching(|| c_wz::parse(f, t)).is_some(),
                    "wz panics on `{f}` `{t}`"
                );
            } else {
                let theirs = catching(|| c_up::parse(f, t));
                let ours = c_wz::parse(f, t);
                match theirs {
                    Some(theirs) => assert_eq!(theirs, ours, "parse of `{f}` against `{t}`"),
                    None => classes.upstream_panics += 1,
                }
                classes.compared += 1;
                parsed += ours.is_ok() as usize;
            }
        }
    }
    eprintln!(
        "parse: {} formats x {} targets, {classes:?}, {parsed} parsed",
        formats.len(),
        targets.len()
    );
    assert!(parsed > 1000, "only {parsed} parses succeeded");
}

#[test]
fn both_crates_fill_and_build_every_format_alike() {
    const VALUES: &[&str] = &["a", "b", "a/b", "", "x", "**"];
    let ids = ["x", "y", "z", "w", "v", "u", "nope"];
    let mut built = 0usize;
    for (f, stripped) in formats(3) {
        if has_default(&f, &stripped) || c_wz::construct(&f).is_err() {
            continue;
        }
        if upstream_panics_on_construction(&f) {
            continue;
        }
        let mut sets_list: Vec<Vec<(&str, &str)>> = Vec::new();
        for id in ids {
            for value in VALUES {
                sets_list.push(vec![(id, *value)]);
            }
        }
        // two values set, and one set twice (the second replaces the first)
        for (a, b) in [("x", "y"), ("y", "x"), ("z", "w"), ("x", "x")] {
            for (va, vb) in [("a", "b/c"), ("b", ""), ("a/b", "a")] {
                sets_list.push(vec![(a, va), (b, vb)]);
            }
        }
        for sets in sets_list {
            let theirs = catching(|| c_up::format_with(&f, &sets));
            let ours = c_wz::format_with(&f, &sets);
            if let Some(theirs) = theirs {
                assert_eq!(theirs, ours, "format of `{f}` with {sets:?}");
            }
            built += ours.is_ok() as usize;
        }
    }
    assert!(built > 100, "only {built} formats were built");
}

#[test]
fn a_default_is_used_for_a_field_nothing_was_set_for() {
    // The class upstream is wrong in, by wz's own definition.
    assert_eq!(
        c_wz::format_with("a/${t:*#d}/z", &[]).map(|s| s.split(" | ").next().unwrap().to_string()),
        Ok("a/d/z".to_string())
    );
    assert_eq!(
        c_wz::format_with("a/${t:*#d}/z", &[("t", "q")]).map(|s| s
            .split(" | ")
            .next()
            .unwrap()
            .to_string()),
        Ok("a/q/z".to_string())
    );
    // A value must still be included by the pattern, whatever the default is.
    assert!(c_wz::format_with("a/${t:b#d}", &[("t", "q")]).is_err());
}

#[test]
fn a_format_round_trips_through_a_formatter_and_the_parser() {
    // What a formatter builds, the parser reads back: for the formats and values where both
    // succeed, in wz as in upstream.
    for f in [
        "a/${x:*}/b/${y:**}/c",
        "${x:*}/${y:**}",
        "${x:**}/@v/${y:**}",
        "p/${x:a/*}",
    ] {
        for (x, y) in [("1", "2/3"), ("1", ""), ("a/z", "q")] {
            let sets = [("x", x), ("y", y)];
            let ours = c_wz::format_with(f, &sets);
            assert_eq!(ours, c_up::format_with(f, &sets), "format `{f}`");
            if let Ok(built) = ours {
                let ke = built.split(" | ").next().unwrap().to_string();
                assert_eq!(
                    c_up::parse(f, &ke),
                    c_wz::parse(f, &ke),
                    "round trip `{f}` `{ke}`"
                );
            }
        }
    }
}
