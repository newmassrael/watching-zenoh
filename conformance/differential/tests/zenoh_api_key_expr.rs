// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! `zenoh`, the `key_expr` and `selector` modules (the fifth part of the top crate): upstream's
//! crate (`up_zenoh`) and wz's (`wz_zenoh`) given the same inputs to `KeyExpr` and to `Selector`,
//! results equal as text. The session a key expression is declared on is erased in wz's crate (the
//! anchor of docs/zenoh-api-on-the-engine.md, D2) and has no counterpart that can be driven here
//! without one; the anchor is tested in the crate itself, with a session that is a counter.
//!
//! * `KeyExpr` made by every route: `new`, `try_from` of five kinds of string, `FromStr`,
//!   `autocanonize` of two, the three unchecked constructors, and the conversions from a `keyexpr`,
//!   an `OwnedKeyExpr`, a reference of each and a reference of a `KeyExpr`, over a list of strings
//!   that are canonical, not canonical and not key expressions at all;
//! * what is done with one: `join`, `concat` (and its refusal of two stars), the two `Div`s,
//!   `borrowing_clone`, `into_owned`, `as_keyexpr`, the dummy of `internal`, the conversions out
//!   (`String`, `OwnedKeyExpr`), text, debug, equality with every kind of right side, hash, serde in
//!   and out, and the `keyexpr` it dereferences to (`includes`, `intersects`, `get_nonwild_prefix`);
//! * `Selector`: every conversion into one, the parse of a string with and without parameters, the
//!   accessors, `split`, `owned`, `borrowed`, `into_owned`, text and debug, and with `unstable` the
//!   four methods of `ZenohParameters` over parameters with and without the keys they read;
//! * what the modules re-export (the trees, the format module, the intersection level) used, to be
//!   sure each name is there.
//!
//! The one difference between the crates that is not of this module is the canonizer's, which
//! `zenoh_keyexpr.rs` records and counts: on a malformed string with a run of `$*$*` upstream's
//! reads past the end of its input and panics, and wz's follows the definition. The strings here
//! stay out of that class, so that what the module does is not confused with it.
//!
//! No other difference from upstream was seen.

use std::{
    cell::Cell,
    collections::hash_map::DefaultHasher,
    hash::{Hash, Hasher},
    panic::{catch_unwind, set_hook, take_hook, AssertUnwindSafe},
    sync::Once,
};

thread_local! {
    static QUIET: Cell<bool> = const { Cell::new(false) };
}

/// What a call that may panic made, as text, without the report of the panic.
fn caught(f: impl FnOnce() -> String) -> String {
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
    let r = catch_unwind(AssertUnwindSafe(f));
    QUIET.with(|q| q.set(false));
    match r {
        Ok(v) => v,
        Err(p) => format!(
            "PANIC {}",
            p.downcast_ref::<String>()
                .cloned()
                .or_else(|| p.downcast_ref::<&str>().map(|s| s.to_string()))
                .unwrap_or_default()
        ),
    }
}

/// An error as text without the places of the crates that made it.
fn plain(s: &str) -> String {
    let mut out = String::new();
    let mut rest = s;
    while let Some(j) = rest.find(".rs:") {
        match rest[..j].rfind(" at ") {
            Some(i) => {
                out.push_str(&rest[..i]);
                let after = &rest[j + 4..];
                let digits = after.chars().take_while(char::is_ascii_digit).count();
                rest = &after[digits..];
            }
            None => {
                out.push_str(&rest[..j + 4]);
                rest = &rest[j + 4..];
            }
        }
    }
    out.push_str(rest);
    out
}

fn shown<T: std::fmt::Display, E: std::fmt::Display>(r: Result<T, E>) -> String {
    match r {
        Ok(v) => format!("Ok({v})"),
        Err(e) => format!("Err({})", plain(&e.to_string())),
    }
}

fn hash_of<T: Hash + ?Sized>(t: &T) -> u64 {
    let mut h = DefaultHasher::new();
    t.hash(&mut h);
    h.finish()
}

/// Strings that are canonical, that are not and that are not key expressions.
const KEYS: &[&str] = &[
    "a",
    "a/b",
    "a/b/c/d/e",
    "a/*",
    "*/a",
    "a/**",
    "**/a",
    "**",
    "*",
    "a/**/b",
    "a/**/**",
    "**/**",
    "a/*/**",
    "a/**/*",
    "a$*",
    "a$*b",
    "$*a",
    "a/$*/b",
    "ab$*c$*",
    "*$*",
    "a/b$*c/d",
    "@verbatim/a",
    "a/@verbatim",
    "@a/**",
    "",
    "/",
    "/a",
    "a/",
    "a//b",
    "a/./b",
    "a/../b",
    "a?b",
    "a#b",
    "a b",
    "a/b?c=d",
    "ünï/cödé",
    "$",
    "a$",
    "a/$/b",
    "**a",
    "a**",
    "***",
];

const SELECTORS: &[&str] = &[
    "a/b",
    "a/b?",
    "a/b?x=1",
    "a/b?x=1;y=2",
    "a/**?_time=[..]",
    "a/b?_anyke",
    "a/b?_anyke;x",
    "a/b?x=1?y=2",
    "?x=1",
    "?",
    "",
    "a b?x",
    "a//b?x=1",
    "a/b?_time=[now(-2s)..now(2s)];_filter",
    "a/b?_time=not a range",
    "a/b?_time",
    "a/b?x;x",
];

macro_rules! key_cases {
    ($name:ident, $z:ident, $ke:ident) => {
        mod $name {
            use super::*;
            use $z::{
                key_expr::{keyexpr, KeyExpr, OwnedKeyExpr},
                query::{Parameters, Selector},
            };

            pub fn constructors() -> Vec<String> {
                let mut out = vec![];
                for k in KEYS {
                    let mut line = format!("{k:?}:");
                    line += &format!(" new={}", caught(|| shown(KeyExpr::new(*k))));
                    line += &format!(" str={}", caught(|| shown(KeyExpr::try_from(*k))));
                    line += &format!(" String={}", caught(|| shown(KeyExpr::try_from(k.to_string()))));
                    let s = k.to_string();
                    line += &format!(" &String={}", caught(|| shown(KeyExpr::try_from(&s))));
                    let mut m = k.to_string();
                    line += &format!(" &mut String={}", caught(|| shown(KeyExpr::try_from(&mut m))));
                    let mut m = k.to_string();
                    line += &format!(" &mut str={}", caught(|| shown(KeyExpr::try_from(m.as_mut_str()))));
                    line += &format!(
                        " from_str={}",
                        caught(|| shown(k.parse::<KeyExpr<'static>>()))
                    );
                    line += &format!(
                        " autocanonize(String)={}",
                        caught(|| shown(KeyExpr::autocanonize(k.to_string())))
                    );
                    let mut m = k.to_string();
                    line += &format!(
                        " autocanonize(&mut str)={}",
                        caught(|| shown(KeyExpr::autocanonize(m.as_mut_str())))
                    );
                    out.push(line);
                }
                out
            }

            pub fn unchecked_and_conversions() -> Vec<String> {
                let mut out = vec![];
                for k in KEYS.iter().filter(|k| keyexpr::new(**k).is_ok()) {
                    let owned = OwnedKeyExpr::new(*k).unwrap();
                    let kx = keyexpr::new(*k).unwrap();
                    let from_str = unsafe { KeyExpr::from_str_unchecked(k) };
                    let from_string = unsafe { KeyExpr::from_string_unchecked(k.to_string()) };
                    let from_boxed =
                        unsafe { KeyExpr::from_boxed_str_unchecked(k.to_string().into_boxed_str()) };
                    let from_kx: KeyExpr = kx.into();
                    let from_owned: KeyExpr = owned.clone().into();
                    let from_owned_ref: KeyExpr = (&owned).into();
                    let base = KeyExpr::try_from(*k).unwrap();
                    let from_ke_ref: KeyExpr = (&base).into();
                    let back_string: String = base.clone().into();
                    let back_owned: OwnedKeyExpr = base.clone().into();
                    out.push(format!(
                        "{k:?}: {from_str} {from_string} {from_boxed} {from_kx} {from_owned} {from_owned_ref} {from_ke_ref} {back_string} {back_owned}"
                    ));
                    out.push(format!(
                        "{k:?}: eq {} {} {} {}",
                        from_str == from_string,
                        from_kx == from_owned,
                        base.as_keyexpr() == kx,
                        base == from_ke_ref
                    ));
                }
                out
            }

            pub fn operations() -> Vec<String> {
                let mut out = vec![];
                let sample: Vec<&str> = KEYS
                    .iter()
                    .copied()
                    .filter(|k| keyexpr::new(*k).is_ok())
                    .collect();
                for k in &sample {
                    let ke = KeyExpr::try_from(*k).unwrap();
                    let mut line = format!("{k:?}: debug={ke:?} display={ke}");
                    line += &format!(" as_keyexpr={}", ke.as_keyexpr());
                    line += &format!(" borrowing_clone={}", ke.borrowing_clone());
                    line += &format!(" into_owned={}", ke.clone().into_owned());
                    line += &format!(" is_wild={}", ke.is_wild());
                    line += &format!(" nonwild_prefix={:?}", ke.get_nonwild_prefix().map(|p| p.to_string()));
                    line += &format!(" hash_equal_to_keyexpr={}", hash_of(&ke) == hash_of(&*ke));
                    for s in ["x", "x/y", "*", "**", "$*", "/x", "x/", "", "a b", "@v"] {
                        line += &format!(" join({s:?})={}", caught(|| shown(ke.join(s))));
                    }
                    for s in ["x", "/x", "*", "**", "$*", "", "*x", "x*", "$*x", "a b"] {
                        line += &format!(" concat({s:?})={}", caught(|| shown(ke.concat(s))));
                    }
                    for r in ["x", "x/y", "**", "*"] {
                        let rk = keyexpr::new(r).unwrap();
                        line += &format!(" div({r})={} {}", ke.clone() / rk, &ke / rk);
                    }
                    out.push(line);
                }
                for l in &sample {
                    for r in &sample {
                        let (a, b) = (KeyExpr::try_from(*l).unwrap(), KeyExpr::try_from(*r).unwrap());
                        out.push(format!(
                            "{l:?} vs {r:?}: eq={} includes={} intersects={}",
                            a == b,
                            a.includes(&b),
                            a.intersects(&b)
                        ));
                    }
                }
                out
            }

            pub fn serde() -> Vec<String> {
                let mut out = vec![];
                for k in KEYS {
                    let json = format!("\"{k}\"");
                    let r: Result<KeyExpr, _> = serde_json::from_str(&json);
                    out.push(format!("from json {json}: {}", caught(|| shown(r))));
                }
                for k in KEYS.iter().filter(|k| keyexpr::new(**k).is_ok()) {
                    let ke = KeyExpr::try_from(*k).unwrap();
                    out.push(format!("to json {k:?}: {}", serde_json::to_string(&ke).unwrap()));
                }
                let r: Result<KeyExpr, _> = serde_json::from_str("42");
                out.push(format!("from json 42: {}", caught(|| shown(r))));
                out
            }

            pub fn internal_and_exports() -> Vec<String> {
                let mut out = vec![];
                let dummy = KeyExpr::dummy();
                out.push(format!("dummy: {dummy} {}", dummy.is_dummy()));
                out.push(format!("a copy of the dummy: {}", dummy.clone().is_dummy()));
                out.push(format!("a key made like it: {}", KeyExpr::try_from("dummy").unwrap().is_dummy()));
                out.push(format!("owned dummy: {}", dummy.clone().into_owned().is_dummy()));
                out.push(format!("borrowed dummy: {}", dummy.borrowing_clone().is_dummy()));
                out.push(format!("level: {:?}", $z::key_expr::SetIntersectionLevel::Includes));
                let mut tree = $z::key_expr::keyexpr_tree::KeBoxTree::<u32>::new();
                use $z::key_expr::keyexpr_tree::{IKeyExprTree, IKeyExprTreeMut};
                tree.insert(keyexpr::new("a/b").unwrap(), 1);
                tree.insert(keyexpr::new("a/*").unwrap(), 2);
                out.push(format!(
                    "tree: {:?} {:?}",
                    tree.weight_at(keyexpr::new("a/b").unwrap()),
                    tree.weight_at(keyexpr::new("a/c").unwrap())
                ));
                let nw = $z::key_expr::nonwild_keyexpr::new("a/b").unwrap();
                out.push(format!("nonwild: {nw:?} {:?}", $z::key_expr::nonwild_keyexpr::new("a/*").map(|k| format!("{k:?}")).map_err(|e| plain(&e.to_string()))));
                out.push(format!(
                    "owned nonwild: {:?}",
                    $z::key_expr::OwnedNonWildKeyExpr::try_from("a/b".to_string()).map(|k| format!("{k:?}")).map_err(|e| plain(&e.to_string()))
                ));
                out.push(format!(
                    "owned nonwild of a wild one: {:?}",
                    $z::key_expr::OwnedNonWildKeyExpr::try_from("a/*".to_string()).map(|k| format!("{k:?}")).map_err(|e| plain(&e.to_string()))
                ));
                use $z::key_expr::Canonize;
                let mut s = String::from("a/**/**/b/*/**");
                s.canonize();
                out.push(format!("canonize: {s}"));
                out
            }

            pub fn selectors() -> Vec<String> {
                let mut out = vec![];
                for s in SELECTORS {
                    let mut line = format!("{s:?}:");
                    line += &format!(" try_from(&str)={}", caught(|| shown(Selector::try_from(*s))));
                    line += &format!(" try_from(String)={}", caught(|| shown(Selector::try_from(s.to_string()))));
                    let st = s.to_string();
                    line += &format!(" try_from(&String)={}", caught(|| shown(Selector::try_from(&st))));
                    line += &format!(" from_str={}", caught(|| shown(s.parse::<Selector>())));
                    if let Ok(sel) = Selector::try_from(*s) {
                        line += &format!(" debug={sel:?}");
                        line += &format!(" key_expr={} parameters={}", sel.key_expr(), sel.parameters());
                        let (k, p) = sel.clone().split();
                        line += &format!(" split=({k}, {p})");
                        line += &format!(" into_owned={}", sel.clone().into_owned());
                        let again: Selector = (&sel).into();
                        line += &format!(" from_ref={again} eq={}", again == sel);
                        let (rk, rp): (&KeyExpr, &Parameters) = (&sel).into();
                        line += &format!(" as_refs=({rk}, {rp})");
                        let (ok, op): (KeyExpr, Parameters) = sel.clone().into();
                        line += &format!(" as_owned=({ok}, {op})");
                    }
                    out.push(line);
                }
                let ke = KeyExpr::try_from("a/b").unwrap();
                let p = Parameters::from("x=1;y=2");
                out.push(format!("owned: {}", Selector::owned(ke.clone(), p.clone())));
                out.push(format!("owned from str: {}", Selector::owned(KeyExpr::try_from("a/c").unwrap(), "z=3")));
                out.push(format!("borrowed: {}", Selector::borrowed(&ke, &p)));
                out.push(format!("from a pair: {}", Selector::from((ke.clone(), "w=4"))));
                out.push(format!("from a key expr: {}", Selector::from(ke.clone())));
                out.push(format!("from &key expr: {}", Selector::from(&ke)));
                out.push(format!("from &keyexpr: {}", Selector::from(keyexpr::new("k/e").unwrap())));
                let owned = OwnedKeyExpr::new("o/k").unwrap();
                out.push(format!("from &OwnedKeyExpr: {}", Selector::from(&owned)));
                out.push(format!("from OwnedKeyExpr: {}", Selector::from(owned.clone())));
                out.push(format!("empty parameters hide the question mark: {}", Selector::owned(ke.clone(), "")));
                out.push(format!("equality: {} {}", Selector::owned(ke.clone(), "a") == Selector::owned(ke.clone(), "a"), Selector::owned(ke.clone(), "a") == Selector::owned(ke.clone(), "b")));
                out
            }

            pub fn zenoh_parameters() -> Vec<String> {
                use $z::query::{TimeRange, ZenohParameters};
                let mut out = vec![];
                for text in [
                    "",
                    "x=1",
                    "_anyke",
                    "_anyke;x",
                    "_time=[..]",
                    "_time=[now(-2s)..now(2s)]",
                    "_time=[now(-2s)..now(2s)];_anyke",
                    "_time=garbage",
                    "_time",
                    "_time=[..];_time=[..1h]",
                ] {
                    let mut p = Parameters::from(text);
                    let mut line = format!("{text:?}: any={}", p.reply_key_expr_any());
                    line += &format!(
                        " time_range={}",
                        match p.time_range() {
                            None => "None".to_string(),
                            Some(Ok(t)) => format!("Some(Ok({t}))"),
                            Some(Err(e)) => format!("Some(Err({}))", plain(&e.to_string())),
                        }
                    );
                    p.set_reply_key_expr_any();
                    line += &format!(" after set any: {p} {}", p.reply_key_expr_any());
                    p.set_reply_key_expr_any();
                    line += &format!(" twice: {p}");
                    let tr: TimeRange = "[now(-1h)..now()]".parse().unwrap();
                    p.set_time_range(tr);
                    line += &format!(" after set time: {p}");
                    p.set_time_range(None::<TimeRange>);
                    line += &format!(" after clearing: {p} {:?}", p.time_range().is_none());
                    out.push(line);
                }
                out
            }
        }
    };
}

key_cases!(up, up_zenoh, up_keyexpr);
key_cases!(wz, wz_zenoh, wz_keyexpr);

fn compare(group: &str, up: &[String], wz: &[String]) {
    assert!(up.len() > 2, "{group} holds {} line(s)", up.len());
    assert_eq!(up.len(), wz.len(), "{group}: the groups differ in length");
    if let Some((x, y)) = up.iter().zip(wz).find(|(x, y)| x != y) {
        panic!("{group}\nupstream: {x}\nwz:       {y}");
    }
    if std::env::var_os("WZ_KEYEXPR_TRANSCRIPT").is_some() {
        for line in up {
            println!("{group}: {line}");
        }
    }
}

#[test]
fn key_expressions_made_by_every_route() {
    let (u, w) = (up::constructors(), wz::constructors());
    assert!(u.iter().any(|l| l.starts_with("\"a/b\": new=Ok(a/b)")), "{u:#?}");
    assert!(u.iter().any(|l| l.starts_with("\"a//b\": new=Err(")), "{u:#?}");
    compare("constructors", &u, &w);
}

#[test]
fn the_unchecked_constructors_and_the_conversions() {
    compare(
        "unchecked and conversions",
        &up::unchecked_and_conversions(),
        &wz::unchecked_and_conversions(),
    );
}

#[test]
fn what_is_done_with_a_key_expression() {
    let (u, w) = (up::operations(), wz::operations());
    assert!(u.iter().any(|l| l.contains("concat(\"*\")=Err(")), "{u:#?}");
    assert!(u.iter().any(|l| l.contains("nonwild_prefix=Some(\"a\")")), "{u:#?}");
    compare("operations", &u, &w);
}

#[test]
fn key_expressions_in_and_out_of_serde() {
    let (u, w) = (up::serde(), wz::serde());
    assert!(u.iter().any(|l| l.starts_with("from json \"a/b\": Ok(a/b)")), "{u:#?}");
    compare("serde", &u, &w);
}

#[test]
fn the_dummy_and_the_names_the_module_re_exports() {
    let (u, w) = (up::internal_and_exports(), wz::internal_and_exports());
    assert!(u.iter().any(|l| l == "a key made like it: false"), "{u:#?}");
    compare("internal and exports", &u, &w);
}

#[test]
fn selectors_made_and_unmade() {
    let (u, w) = (up::selectors(), wz::selectors());
    assert!(u.iter().any(|l| l.contains("debug=sel\"a/b?x=1;y=2\"")), "{u:#?}");
    compare("selectors", &u, &w);
}

#[test]
fn the_parameters_zenoh_reads() {
    let (u, w) = (up::zenoh_parameters(), wz::zenoh_parameters());
    assert!(u.iter().any(|l| l.contains("Some(Err(")), "{u:#?}");
    compare("zenoh parameters", &u, &w);
}

#[test]
fn the_comparison_sees_a_key_expression_that_differs() {
    let u = up::operations();
    let mut w = wz::operations();
    let i = w.iter().position(|l| l.starts_with("\"a/b\":")).unwrap();
    w[i] = format!("{} changed", w[i]);
    assert!(u.iter().zip(&w).any(|(x, y)| x != y));
    assert_ne!(up::operations(), up::constructors());
}
