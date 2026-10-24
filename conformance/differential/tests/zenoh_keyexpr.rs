// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! `zenoh-keyexpr`, first slice: upstream's crate (`up_keyexpr`) and wz's (`wz_keyexpr`) given the
//! same strings, outputs equal.
//!
//! The wz crate writes the key expression language from its definition and not from upstream's code,
//! so what makes the two agree is this file: every string of a small alphabet up to a length is
//! parsed and canonized by both, every pair of the valid ones up to a shorter length is compared for
//! intersection, inclusion and relation, and a seeded generator supplies the longer ones. The
//! alphabet holds each character that has a meaning in the language (`/`, `*`, `$`, `@`, and the
//! two forbidden ones, `#` and `?`) and a letter, which is enough for every rule of the language to
//! be reached by a short string.
//!
//! Each case is written once, in a macro that expands it for the crate named, so both crates are run
//! by the same source and the comparison is between two values of one shape.

use rand::{rngs::StdRng, SeedableRng};

/// What a failed parse says, without the place it was raised at (the file and line of each crate):
/// the message and the error number.
type Fault = (String, i8);

macro_rules! cases {
    ($name:ident, $ke:ident, $zr:ident) => {
        mod $name {
            use super::Fault;
            use $ke::{
                keyexpr, nonwild_keyexpr, OwnedKeyExpr, OwnedNonWildKeyExpr, SetIntersectionLevel,
            };

            fn fault(e: $zr::Error) -> Fault {
                let text = e.to_string();
                let message = text.split(" at ").next().unwrap().to_string();
                (message, $zr::ErrNo::errno(&*e).get())
            }

            pub fn parse(s: &str) -> Result<(), Fault> {
                keyexpr::new(s).map(|_| ()).map_err(fault)
            }

            pub fn autocanonize(s: &str) -> Result<String, Fault> {
                OwnedKeyExpr::autocanonize(s.to_string())
                    .map(|k| k.to_string())
                    .map_err(fault)
            }

            pub fn autocanonize_in_place(s: &str) -> Result<String, Fault> {
                let mut owned = s.to_string().into_boxed_str();
                let mut view: &mut str = &mut owned;
                keyexpr::autocanonize(&mut view)
                    .map(|k| k.to_string())
                    .map_err(fault)
            }

            pub fn relations(a: &str, b: &str) -> (bool, bool, u8) {
                let (a, b) = (keyexpr::new(a).unwrap(), keyexpr::new(b).unwrap());
                let level = match a.relation_to(b) {
                    SetIntersectionLevel::Disjoint => 0,
                    SetIntersectionLevel::Intersects => 1,
                    SetIntersectionLevel::Includes => 2,
                    SetIntersectionLevel::Equals => 3,
                };
                (a.intersects(b), a.includes(b), level)
            }

            pub fn chunks(s: &str) -> (Vec<String>, Vec<String>, Option<String>, Option<String>) {
                let ke = keyexpr::new(s).unwrap();
                let forward: Vec<String> = ke.chunks().map(|c| c.to_string()).collect();
                let backward: Vec<String> = ke.chunks().rev().map(|c| c.to_string()).collect();
                let it = ke.chunks();
                (
                    forward,
                    backward,
                    it.peek().map(|c| c.to_string()),
                    it.peek_back().map(|c| c.to_string()),
                )
            }

            pub fn is_wild(s: &str) -> bool {
                keyexpr::new(s).unwrap().is_wild()
            }

            pub fn join(a: &str, b: &str) -> Result<String, Fault> {
                let a = keyexpr::new(a).unwrap();
                a.join(b).map(|k| k.to_string()).map_err(fault)
            }

            pub fn div(a: &str, b: &str) -> String {
                let (a, b) = (keyexpr::new(a).unwrap(), keyexpr::new(b).unwrap());
                (a / b).to_string()
            }

            /// `None` when `s` is not a key expression, else whether it is also non-wild.
            pub fn nonwild(s: &str) -> Option<bool> {
                keyexpr::new(s).ok()?;
                Some(nonwild_keyexpr::new(s).is_ok())
            }

            pub fn owned_forms(s: &str) -> Result<(String, String, String, String), Fault> {
                let owned = OwnedKeyExpr::new(s).map_err(fault)?;
                let json = serde_json::to_string(&owned).unwrap();
                let back: OwnedKeyExpr = serde_json::from_str(&json).unwrap();
                let nonwild = OwnedNonWildKeyExpr::try_from(s.to_string())
                    .map(|k| format!("{k:?}"))
                    .unwrap_or_else(|e| fault(e).0);
                Ok((format!("{owned:?}"), json, back.to_string(), nonwild))
            }

            pub fn debug_display(s: &str) -> (String, String) {
                let ke = keyexpr::new(s).unwrap();
                (format!("{ke:?}"), format!("{ke}"))
            }
        }
    };
}

cases!(c_up, up_keyexpr, up);
cases!(c_wz, wz_keyexpr, wz);

/// Every string of at most `max_len` characters over `alphabet`, shortest first.
fn strings(alphabet: &[char], max_len: usize) -> Vec<String> {
    let mut all = vec![String::new()];
    let mut frontier = vec![String::new()];
    for _ in 0..max_len {
        let mut next = Vec::with_capacity(frontier.len() * alphabet.len());
        for s in &frontier {
            for c in alphabet {
                let mut t = s.clone();
                t.push(*c);
                next.push(t);
            }
        }
        all.extend(next.iter().cloned());
        frontier = next;
    }
    all
}

/// The characters with a meaning in the language, and a letter.
const ALPHABET: &[char] = &['a', '/', '*', '$', '@', '#', '?'];

#[test]
fn both_crates_judge_every_short_string_alike_and_report_the_same_fault() {
    let mut valid = 0usize;
    for s in strings(ALPHABET, 7) {
        let (up, wz) = (c_up::parse(&s), c_wz::parse(&s));
        assert_eq!(up, wz, "parse of `{s}`");
        valid += up.is_ok() as usize;
    }
    // A comparison over nothing would pass: the alphabet really reaches valid key expressions.
    assert!(valid > 100, "only {valid} valid strings");
}

thread_local! {
    /// Set while a panic is expected, so that its message is not printed once per input.
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

/// `s` with every run of `$*` inside it folded into one, which is the first rule of canonization.
fn fold_runs(s: &str) -> String {
    let mut s = s.to_string();
    while s.contains("$*$*") {
        s = s.replace("$*$*", "$*");
    }
    s
}

/// What upstream's canonizer does differently from the language's definition, which wz follows:
/// * on a string with a run of three or more `$*` it folds only part of the run, and the string is then
///   refused for the `$*$*` it left (`a$*$*$*` is refused with "`$` is not allowed after `$*`", where
///   the definition makes it `a$*`);
/// * on some malformed strings it reads past the end of its input and panics.
///
/// Both are counted, and each string of either class must be one wz answers as the definition says:
/// wz's answer for `s` is wz's answer for `s` with its runs folded, which is upstream's answer for it
/// too where upstream answers at all.
struct Divergence {
    /// Strings upstream answers otherwise than wz, all with a run of three `$*` or more.
    long_runs: Vec<String>,
    /// Strings upstream panics on.
    upstream_panics: Vec<String>,
}

fn compare_canonizers<T: PartialEq + std::fmt::Debug + Clone>(
    what: &str,
    strings: Vec<String>,
    up: impl Fn(&str) -> T,
    wz: impl Fn(&str) -> T,
) -> Divergence {
    let mut divergence = Divergence {
        long_runs: Vec::new(),
        upstream_panics: Vec::new(),
    };
    for s in strings {
        let ours = catching(|| wz(&s)).unwrap_or_else(|| panic!("wz panics on `{what}` of `{s}`"));
        let folded = fold_runs(&s);
        match catching(|| up(&s)) {
            Some(theirs) if theirs == ours => {}
            Some(_) => {
                assert!(
                    s.contains("$*$*$*"),
                    "{what} of `{s}` differs without a long run"
                );
                // The definition: the answer for `s` is the answer for its runs folded.
                assert_eq!(
                    ours,
                    wz(&folded),
                    "{what} of `{s}`: wz does not fold its runs"
                );
                divergence.long_runs.push(s);
            }
            None => {
                assert!(
                    s.contains('$'),
                    "upstream panics on `{s}`, which has no `$`"
                );
                assert_eq!(
                    ours,
                    wz(&folded),
                    "{what} of `{s}`: wz does not fold its runs"
                );
                divergence.upstream_panics.push(s);
            }
        }
    }
    divergence
}

#[test]
fn both_crates_canonize_every_short_string_alike_valid_or_not() {
    let d = compare_canonizers(
        "autocanonize",
        strings(ALPHABET, 7),
        c_up::autocanonize,
        c_wz::autocanonize,
    );
    // The exceptions are pinned, so that they cannot grow unseen: a change of these counts is a
    // change of upstream's canonizer or of the alphabet, and wants a reading.
    eprintln!(
        "autocanonize: {} long-run strings, {} upstream panics, shortest {:?} and {:?}",
        d.long_runs.len(),
        d.upstream_panics.len(),
        d.long_runs.first(),
        d.upstream_panics.first()
    );
    assert!(
        !d.long_runs.is_empty(),
        "the long-run class is empty: the check proves nothing"
    );
}

#[test]
fn canonizing_a_mutable_str_in_place_ends_alike() {
    let d = compare_canonizers(
        "in place",
        strings(&['a', '/', '*', '$'], 7),
        c_up::autocanonize_in_place,
        c_wz::autocanonize_in_place,
    );
    assert!(!d.long_runs.is_empty() || !d.upstream_panics.is_empty());
}

/// The key expressions over `alphabet` of at most `max_len` characters.
fn valid(alphabet: &[char], max_len: usize) -> Vec<String> {
    strings(alphabet, max_len)
        .into_iter()
        .filter(|s| c_wz::parse(s).is_ok())
        .collect()
}

#[test]
fn both_crates_relate_every_pair_of_short_key_expressions_alike() {
    let all = valid(&['a', '/', '*', '$', '@'], 6);
    assert!(all.len() > 200, "only {} key expressions", all.len());
    for a in &all {
        for b in &all {
            assert_eq!(
                c_up::relations(a, b),
                c_wz::relations(a, b),
                "`{a}` against `{b}`"
            );
        }
    }
}

#[test]
fn both_crates_relate_generated_pairs_alike() {
    // The generators are each crate's own, seeded alike but producing what they like: the pairs are
    // taken from wz's and both crates are asked about them.
    let mut rng = StdRng::seed_from_u64(0x6b65_7965_7870_72);
    let pool: Vec<String> = wz_keyexpr::fuzzer::KeyExprFuzzer(&mut rng)
        .take(400)
        .map(|k| k.to_string())
        .collect();
    let mut rng = StdRng::seed_from_u64(0x7570_7374_7265_616d);
    let upstream_pool: Vec<String> = up_keyexpr::fuzzer::KeyExprFuzzer(&mut rng)
        .take(400)
        .map(|k| k.to_string())
        .collect();
    for a in pool.iter().chain(&upstream_pool) {
        // Whoever generated it, each crate calls it canon and valid.
        assert_eq!(c_up::parse(a), Ok(()), "upstream refuses `{a}`");
        assert_eq!(c_wz::parse(a), Ok(()), "wz refuses `{a}`");
        for b in pool.iter().chain(&upstream_pool) {
            assert_eq!(
                c_up::relations(a, b),
                c_wz::relations(a, b),
                "`{a}` against `{b}`"
            );
        }
    }
}

#[test]
fn chunks_join_div_and_the_owned_forms_agree() {
    for s in valid(&['a', '/', '*', '$', '@'], 5) {
        assert_eq!(c_up::chunks(&s), c_wz::chunks(&s), "chunks of `{s}`");
        assert_eq!(c_up::is_wild(&s), c_wz::is_wild(&s), "is_wild of `{s}`");
        assert_eq!(c_up::nonwild(&s), c_wz::nonwild(&s), "nonwild of `{s}`");
        assert_eq!(
            c_up::owned_forms(&s),
            c_wz::owned_forms(&s),
            "owned forms of `{s}`"
        );
        assert_eq!(c_up::debug_display(&s), c_wz::debug_display(&s));
    }
    let short = valid(&['a', '/', '*', '@'], 4);
    for a in &short {
        for b in &short {
            assert_eq!(c_up::join(a, b), c_wz::join(a, b), "join `{a}` `{b}`");
            assert_eq!(c_up::div(a, b), c_wz::div(a, b), "`{a}` / `{b}`");
        }
    }
}

#[test]
fn the_generator_of_wz_makes_key_expressions_that_are_already_canon() {
    let mut rng = StdRng::seed_from_u64(7);
    for ke in wz_keyexpr::fuzzer::KeyExprFuzzer(&mut rng).take(2000) {
        let s = ke.to_string();
        assert_eq!(c_wz::autocanonize(&s), Ok(s.clone()), "`{s}` is not canon");
        assert_eq!(
            c_up::autocanonize(&s),
            Ok(s.clone()),
            "upstream changes `{s}`"
        );
    }
}
