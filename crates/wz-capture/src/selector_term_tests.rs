// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The sentence a node offers ([`crate::selector_term`]): how each kind is
//! spelled and which tail is written, and THE SOUNDNESS PROPERTY that makes it
//! worth offering ([`crate::selector_term::soundness`]), held over a population
//! and not over examples.
//!
//! # The population
//!
//! The captures the fuzzers seed their `pcap` and `selector_term` targets with
//! (`captures/`, every file of at most [`MAX_CAPTURE`] bytes, each content once:
//! the rule `scripts/lib/fuzz_seeds.py` writes them by), and seeded noise over
//! every message id with every header flag reached ([`WireNoise`], the
//! population the declared shape is held to), each message one datagram. Every
//! node of every row is walked, at both levels. What was walked is printed, and
//! a population short of any message kind fails: a green over a part of the
//! kinds says nothing about the rest. The fuzz target holds the same oracle
//! over the corpus the nightly fuzzing grows.

use alloc::string::{String, ToString};
use alloc::vec::Vec;

use crate::selector_term::soundness::{self, serialise, Doors, Held};
use crate::selector_term::{read_node, term_for, term_json, ShownValue, TermRefusal, Verb};
use wz_session_core::dissect::{Field, FieldValue};
use wz_session_core::json5::{self, Json5Value};
use wz_session_core::wire_noise::{WireNoise, NETWORK_MIDS, TRANSPORT_MIDS};

/// The largest capture the fuzzers' capture targets are seeded with
/// (`MAX_CAPTURE` of `scripts/lib/fuzz_seeds.py`).
const MAX_CAPTURE: usize = 64 * 1024;

/// Rounds of noise: every message id, once per round.
const NOISE_ROUNDS: usize = 120;

fn sentence(path: &str, value: ShownValue, verb: Verb, typed: &str) -> String {
    term_for(Some(path), &value, verb, typed)
        .unwrap_or_else(|e| panic!("{path}: {e}"))
        .selector
}

/// Each kind is spelled the way the grammar reads it back, and the tail is the
/// shortest that names the field alone.
#[test]
fn each_kind_is_spelled_as_the_grammar_reads_it() {
    let filter = Verb::Filter;
    assert_eq!(
        sentence("Frame.sn", ShownValue::Uint(9), filter, ""),
        "Frame.sn == 9",
        "`sn` ends `Fragment.sn` too"
    );
    assert_eq!(
        sentence("Frame.r", ShownValue::Flag(true), filter, ""),
        "Frame.r == yes"
    );
    assert_eq!(
        sentence("Frame.qos", ShownValue::Nested, filter, ""),
        "Frame.qos",
        "a group is its presence"
    );
    assert_eq!(
        sentence(
            "Frame.payload.Push.put.payload",
            ShownValue::Bytes(alloc::vec![0x68, 0x69]),
            filter,
            ""
        ),
        "Push.put.payload == 0x6869",
        "a record's field is written from where it is one field"
    );
    assert_eq!(
        sentence(
            "Push.put.payload",
            ShownValue::Bytes(Vec::new()),
            filter,
            ""
        ),
        "Push.put.payload == \"\"",
        "an empty run has no hex spelling"
    );
    let quoted = sentence(
        "Push.keyexpr.suffix",
        ShownValue::Text(String::from("a \"b\" \\c")),
        filter,
        "",
    );
    assert!(quoted.ends_with(r#"== "a \"b\" \\c""#), "{quoted}");
    assert!(
        sentence(
            "Push.keyexpr.suffix",
            ShownValue::Text(String::from("demo/a")),
            filter,
            ""
        )
        .ends_with("== demo/a"),
        "a text that is one word is not quoted"
    );
    assert!(
        sentence(
            "Push.keyexpr.suffix",
            ShownValue::Text(String::from("or")),
            filter,
            ""
        )
        .ends_with("== \"or\""),
        "a keyword is quoted"
    );
}

/// The verbs join the sentence to the selector typed, bracketing an `or`.
#[test]
fn a_verb_joins_the_sentence_to_the_selector_typed() {
    let sn = |verb, typed| sentence("Frame.sn", ShownValue::Uint(3), verb, typed);
    assert_eq!(sn(Verb::Filter, "kind == put"), "Frame.sn == 3");
    assert_eq!(sn(Verb::Add, ""), "Frame.sn == 3");
    assert_eq!(sn(Verb::Add, "  "), "Frame.sn == 3");
    assert_eq!(
        sn(Verb::Add, "kind == put"),
        "kind == put and Frame.sn == 3"
    );
    assert_eq!(
        sn(Verb::Add, "kind == put or kind == del"),
        "(kind == put or kind == del) and Frame.sn == 3"
    );
    assert_eq!(sn(Verb::Exclude, ""), "not Frame.sn == 3");
    assert_eq!(
        sn(Verb::Exclude, "kind == put or dir == a"),
        "(kind == put or dir == a) and not Frame.sn == 3"
    );
    // A `node` term is kept for the binder.
    assert_eq!(
        sn(Verb::Add, "node == cam"),
        "node == cam and Frame.sn == 3"
    );
    let typed = term_for(Some("Frame.sn"), &ShownValue::Uint(3), Verb::Add, "kind ==");
    assert!(matches!(typed, Err(TermRefusal::Selector(_))), "{typed:?}");
}

/// What offers no sentence says why, and never offers an empty one.
#[test]
fn a_node_that_names_nothing_offers_a_reason() {
    assert_eq!(
        term_for(None, &ShownValue::Nested, Verb::Filter, ""),
        Err(TermRefusal::Unnamed)
    );
    assert!(matches!(
        term_for(
            Some("Scout.zid"),
            &ShownValue::Zid("a1".into()),
            Verb::Filter,
            ""
        ),
        Err(TermRefusal::Unjudged { .. })
    ));
    assert!(matches!(
        term_for(Some("Frame.nosuch"), &ShownValue::Uint(1), Verb::Filter, ""),
        Err(TermRefusal::Unwritable { .. })
    ));
    for (text, word) in [
        ("[1]", "\"refusal\":\"node\""),
        (r#"{"kind":"uint","value":1}"#, "\"refusal\":\"node\""),
        (
            r#"{"selector_path":null,"kind":"nested","fields":[]}"#,
            "\"refusal\":\"unnamed\"",
        ),
        (
            r#"{"selector_path":"Frame.sn","kind":"uint","value":"x"}"#,
            "\"refusal\":\"node\"",
        ),
        (
            r#"{"selector_path":"Scout.zid","kind":"zid","value":"a1"}"#,
            "\"refusal\":\"unjudged\"",
        ),
    ] {
        let doc = term_json(text, Verb::Filter, "");
        assert!(doc.contains(word), "{text}: {doc}");
    }
    let doc = term_json(
        r#"{"name":"sn","start":1,"end":2,"selector_path":"Frame.sn","kind":"uint","value":9}"#,
        Verb::Add,
        "kind ==",
    );
    assert!(
        doc.contains("\"refusal\":\"selector\"") && doc.contains("\"start\":7,\"end\":7"),
        "{doc}"
    );
    let doc = term_json(
        r#"{"selector_path":"Frame.sn","kind":"uint","value":9}"#,
        Verb::Exclude,
        "",
    );
    assert!(
        doc.contains(r#""ok":true,"term":"Frame.sn == 9","selector":"not Frame.sn == 9""#),
        "{doc}"
    );
}

/// The node object a document writes reads back as the value it showed.
#[test]
fn a_node_object_reads_back_as_its_value() {
    let tree = wz_session_core::dissect::dissect_network_message(
        &[0x1D, 0x00, 0x41, 0x08, 0x02, b'h', b'i'],
        0,
    )
    .expect("walks")
    .expect("a network message");
    let json = wz_session_core::dissect::to_json(&tree);
    let doc = json5::parse(&json).expect("JSON");
    let paths = wz_session_core::dissect_schema::node_paths(&tree);
    let mut checked = 0usize;
    walk_pairs(&tree, &doc, &mut |field, object| {
        let (path, value) = read_node(&serialise(object)).expect("a node object");
        assert_eq!(path.as_deref(), paths.of(field));
        assert_eq!(value, ShownValue::of(&field.value), "{}", field.name);
        checked += 1;
    });
    assert!(checked > 5, "{checked}");
}

/// `f` over each field of `tree` and the object the document wrote for it, in
/// the walk order both share.
fn walk_pairs(tree: &Field, object: &Json5Value, f: &mut dyn FnMut(&Field, &Json5Value)) {
    f(tree, object);
    if let (FieldValue::Nested(children), Some(Json5Value::Array(objects))) =
        (&tree.value, object.get("fields"))
    {
        assert_eq!(children.len(), objects.len());
        for (child, o) in children.iter().zip(objects) {
            walk_pairs(child, o, f);
        }
    }
}

// ── The soundness property ───────────────────────────────────────────────

/// The library's own renderer and sentence, as the oracle's doors.
struct Library<'a> {
    d: &'a crate::Dissection,
    capture: &'a [u8],
}

impl Doors for Library<'_> {
    fn document(&mut self, selector: &str) -> Option<String> {
        let filter = crate::filter::Filter::parse(selector).ok()?;
        Some(crate::fields_json::fields_json_where(
            self.d,
            self.capture,
            None,
            None,
            &filter,
        ))
    }

    fn term(&mut self, node: &str, verb: Verb) -> String {
        term_json(node, verb, "")
    }
}

/// The captures the fuzzers' capture targets are seeded with: every capture
/// file under `captures/` of at most [`MAX_CAPTURE`] bytes, each content once,
/// smallest first.
fn seed_captures() -> Vec<(String, Vec<u8>)> {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../captures");
    let mut files: Vec<std::path::PathBuf> = Vec::new();
    let mut dirs = alloc::vec![root.clone()];
    while let Some(dir) = dirs.pop() {
        for entry in std::fs::read_dir(&dir).unwrap_or_else(|e| panic!("{}: {e}", dir.display())) {
            let path = entry.expect("a directory entry").path();
            if path.is_dir() {
                dirs.push(path);
            } else if matches!(
                path.extension().and_then(|e| e.to_str()),
                Some("pcap" | "pcapng")
            ) {
                files.push(path);
            }
        }
    }
    files.sort();
    let mut seen: alloc::collections::BTreeSet<Vec<u8>> = alloc::collections::BTreeSet::new();
    let mut out: Vec<(String, Vec<u8>)> = Vec::new();
    for path in files {
        let bytes = std::fs::read(&path).unwrap_or_else(|e| panic!("{}: {e}", path.display()));
        if bytes.len() <= MAX_CAPTURE && seen.insert(bytes.clone()) {
            let name = path
                .strip_prefix(&root)
                .map_or_else(|_| path.display().to_string(), |p| p.display().to_string());
            out.push((name, bytes));
        }
    }
    out.sort_by_key(|(_, bytes)| bytes.len());
    out
}

/// One UDP datagram, as a classic pcap.
fn datagram_capture(wire: &[u8]) -> Vec<u8> {
    let packet = crate::datagram_tests::udp_packet([10, 0, 0, 1], 43210, [10, 0, 0, 2], 7447, wire);
    crate::pcap::write(crate::link::LINKTYPE_ETHERNET, &[(0, 0, packet.as_slice())])
}

/// The noise population: each transport message alone, each network message
/// in a `Frame`, one datagram each.
fn noise_captures() -> Vec<Vec<u8>> {
    let mut source = WireNoise::default();
    let mut out = Vec::new();
    for round in 0..NOISE_ROUNDS {
        let flags = source.flags();
        for mid in TRANSPORT_MIDS {
            out.push(datagram_capture(&source.message(mid | flags)));
        }
        for mid in NETWORK_MIDS {
            let mut wire = alloc::vec![wz_session_core::wire_const::T_MID_FRAME, round as u8];
            wire.extend(source.message(mid | flags));
            out.push(datagram_capture(&wire));
        }
    }
    out
}

/// Both levels of the oracle over one capture, the violations named by it.
fn hold(name: &str, capture: &[u8]) -> Held {
    let Ok(d) = crate::Dissection::from_capture(capture) else {
        return Held::default();
    };
    let mut held = soundness::hold(&mut Library { d: &d, capture }, &d);
    for report in [&mut held.records, &mut held.document] {
        for kept in report.violations.values_mut() {
            for v in kept.iter_mut() {
                *v = alloc::format!("{name}: {v}");
            }
        }
    }
    held
}

/// THE PROPERTY, over the fuzzers' capture seeds and the noise population,
/// every node of every record and of every row.
#[test]
fn every_named_node_offers_a_sentence_its_record_answers_yes() {
    let mut seeds = Held::default();
    let captures = seed_captures();
    for (name, capture) in &captures {
        seeds.absorb(hold(name, capture));
    }
    let mut noise = Held::default();
    let noise_captures = noise_captures();
    for (i, capture) in noise_captures.iter().enumerate() {
        noise.absorb(hold(&alloc::format!("noise {i}"), capture));
    }
    std::println!(
        "selector_term soundness, {} seed captures:\n{seeds}",
        captures.len()
    );
    std::println!(
        "selector_term soundness, {} noise captures:\n{noise}",
        noise_captures.len()
    );
    assert!(seeds.holds(), "the seeds:\n{seeds}");
    assert!(noise.holds(), "the noise:\n{noise}");
    // Not vacuous: the seeds were read and judged at both levels, the cover
    // rendered documents beyond the probe, and every message kind was walked.
    assert!(
        seeds.records.records >= 500 && seeds.records.sentences >= 1_000,
        "{seeds}"
    );
    assert!(
        seeds.document.rows >= 500
            && seeds.document.sentences >= 1_000
            && seeds.document.documents > captures.len(),
        "{seeds}"
    );
    let mut kinds = seeds.records.kinds.clone();
    kinds.extend(seeds.document.kinds.iter().cloned());
    kinds.extend(noise.records.kinds.iter().cloned());
    kinds.extend(noise.document.kinds.iter().cloned());
    for kind in [
        "Init",
        "Open",
        "Close",
        "KeepAlive",
        "Fragment",
        "Join",
        "Oam",
        "Frame.Push",
        "Frame.Request",
        "Frame.Response",
        "Frame.ResponseFinal",
        "Frame.Interest",
        "Frame.Declare",
        "Frame.Oam",
    ] {
        assert!(kinds.contains(kind), "{kind} was never walked: {kinds:?}");
    }
}
