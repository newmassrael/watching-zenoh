// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The tests of [`crate::proto_nanopb`]: the largest encoded size nanopb gives a
//! message.
//!
//! The numbers the tables below expect are the ones nanopb's own generator wrote
//! for the schemas under `testdata/nanopb/` (`scripts/nanopb-reference-sizes.sh`
//! regenerates them with nanopb 0.4.9.1, and `the_generators_own_sizes_are_the_
//! numbers` holds this reader to a fresh run of it wherever the generator is
//! available). They are not this module's arithmetic run twice: a number is the
//! value of a `#define Message_size` in a generated header, and a `None` is a
//! message the generator wrote no number for.

use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;

use crate::proto_describe::{describe_proto, ProtoDescription};
use crate::proto_describe_json::proto_message_json;
use crate::proto_nanopb::{SizeRefusal, REFUSAL_WORDS};
use crate::proto_schema::ProtoFile;

const SIZES: &str = include_str!("../testdata/nanopb/sizes.proto");
const SHAPES: &str = include_str!("../testdata/nanopb/shapes.proto");
const FILE_DEFAULTS: &str = include_str!("../testdata/nanopb/file_defaults.proto");

/// Stands in for nanopb's own `nanopb.proto`, which declares the options as
/// extensions. The reader does not resolve an option's extension, so the schemas
/// need the import to exist and nothing more; the witness test below reads the
/// real file.
const NANOPB_STAND_IN: &str = "syntax = \"proto2\";\n";

/// What the generator wrote for a message: its number, or no number.
type Expected = Option<u64>;

const SIZES_EXPECTED: [(&str, Expected); 13] = [
    ("Boundary", Some(450)),
    ("Compat", Some(373)),
    ("Coordinate", Some(16)),
    ("Enums", Some(16)),
    ("Everything", Some(414)),
    ("Leaf", Some(6)),
    ("Placed.Calibration", Some(4)),
    ("Placed", Some(34)),
    ("Samples", Some(54)),
    ("Unbounded", None),
    ("UnboundedBytes", None),
    ("Uncounted", None),
    ("HoldsUnbounded", None),
];

const SHAPES_EXPECTED: [(&str, Expected); 10] = [
    ("Aggregate", Some(22)),
    ("Choice", Some(27)),
    ("Dropped", Some(6)),
    ("Fixed", Some(42)),
    ("Flat", Some(24)),
    ("Ignored", Some(6)),
    ("Labelled", Some(17)),
    ("Leaf", Some(6)),
    ("MessageDefaults", Some(37)),
    // The generator is told not to write it, so there is no macro at all.
    ("Skipped", None),
];

const FILE_DEFAULTS_EXPECTED: [(&str, Expected); 5] = [
    ("Dict", Some(100)),
    ("Names", Some(72)),
    ("Outer.Inner", Some(17)),
    ("Outer", Some(24)),
    ("Registry", Some(261)),
];

/// One reference schema: its file name, its text, and what the generator wrote
/// for each of its messages.
type Reference = (
    &'static str,
    &'static str,
    &'static [(&'static str, Expected)],
);

/// The three files and what the generator wrote for each of their messages.
fn reference() -> [Reference; 3] {
    [
        ("sizes.proto", SIZES, &SIZES_EXPECTED),
        ("shapes.proto", SHAPES, &SHAPES_EXPECTED),
        (
            "file_defaults.proto",
            FILE_DEFAULTS,
            &FILE_DEFAULTS_EXPECTED,
        ),
    ]
}

fn describe(name: &str, text: &str, root: &str) -> ProtoDescription {
    let files = [
        ProtoFile {
            name,
            text: text.as_bytes(),
        },
        ProtoFile {
            name: "nanopb.proto",
            text: NANOPB_STAND_IN.as_bytes(),
        },
    ];
    describe_proto(root, &files, 0).unwrap_or_else(|d| panic!("{root} in {name}: {d}"))
}

fn size_of(text: &str, root: &str) -> Result<u64, SizeRefusal> {
    describe("a.proto", text, root).messages[0].max_encoded_size
}

/// THE NUMBERS NANOPB WROTE. Every message of every reference schema is sized by
/// this reader as the generator sized it, and a message the generator wrote no
/// number for has none here either.
#[test]
fn the_sizes_are_the_ones_nanopbs_generator_wrote() {
    let mut numbers = 0;
    let mut refusals = 0;
    for (name, text, expected) in reference() {
        for (root, want) in expected {
            let got = describe(name, text, root).messages[0].max_encoded_size;
            match want {
                Some(n) => {
                    assert_eq!(got, Ok(*n), "{name}: {root}");
                    numbers += 1;
                }
                None => {
                    assert!(got.is_err(), "{name}: {root} has a size {got:?}");
                    refusals += 1;
                }
            }
        }
    }
    // The tables are not empty: a comparison over nothing agrees with anything.
    assert_eq!((numbers, refusals), (23, 5));
}

/// A MESSAGE WITH NO NUMBER SAYS WHY, and the word is the one for the cause.
#[test]
fn a_message_without_a_size_says_which_rule_took_it_away() {
    let reason = |text: &str, root: &str| size_of(text, root).expect_err("no size");
    for root in ["Unbounded", "UnboundedBytes", "Uncounted", "HoldsUnbounded"] {
        assert_eq!(reason(SIZES, root), SizeRefusal::UnboundedField, "{root}");
    }
    assert_eq!(reason(SHAPES, "Skipped"), SizeRefusal::MessageNotGenerated);
    // A map with no `max_count` and no file default for it has no size.
    let no_default = "syntax = \"proto3\";\nmessage M { map<string, uint32> m = 1 \
                      [(nanopb).max_size = 4]; }";
    assert_eq!(reason(no_default, "M"), SizeRefusal::UnboundedField);
}

/// A CYCLE HAS NO ONE NUMBER: nanopb turns one message of it into callbacks and
/// which one depends on the order it met them, and it then writes no size for any
/// of them.
#[test]
fn a_cycle_has_no_size() {
    let text = "syntax = \"proto2\";\n\
        message Tree { optional Tree left = 1; optional uint32 v = 2; }\n\
        message Ping { optional Pong pong = 1; optional uint32 v = 2; }\n\
        message Pong { optional Ping ping = 1; optional uint32 v = 2; }\n\
        message HoldsTree { optional Tree t = 1; }";
    for root in ["Tree", "Ping", "Pong", "HoldsTree"] {
        assert_eq!(
            size_of(text, root),
            Err(SizeRefusal::RecursiveMessage),
            "{root}"
        );
    }
}

/// A message that holds a message nanopb was told not to generate has only a
/// symbolic size (`12 + Skipped_size`), which is no number.
#[test]
fn a_message_holding_a_skipped_one_is_not_a_number() {
    let text = "syntax = \"proto2\";\n\
        message Skipped { option (nanopb_msgopt).skip_message = true; optional uint32 a = 1; }\n\
        message Holder { optional Skipped s = 1; optional uint32 b = 2; }";
    assert_eq!(
        size_of(text, "Holder"),
        Err(SizeRefusal::MessageNotGenerated)
    );
}

/// AN OPTION THAT CHANGES THE SIZE AND IS NOT MODELLED IS REFUSED, not guessed:
/// `type_override` makes nanopb size the field as another type (11 where the
/// field says `uint32`), and a modelled option written with a value this reader
/// cannot read is refused for the same reason.
#[test]
fn an_option_that_changes_the_size_is_refused_rather_than_guessed() {
    for option in [
        "(nanopb).type_override = TYPE_UINT64",
        "(nanopb).label_override = LABEL_REPEATED",
        "(nanopb).max_size = \"eight\"",
        "(nanopb).int_size = IS_12",
        "(nanopb) = { nested { a: 1 } }",
    ] {
        let text =
            format!("syntax = \"proto2\";\nmessage M {{ optional uint32 a = 1 [{option}]; }}");
        assert_eq!(
            size_of(&text, "M"),
            Err(SizeRefusal::UnmodelledOption),
            "{option}"
        );
    }
    // An option nanopb reads and the size does not is no refusal.
    let text = "syntax = \"proto2\";\nmessage M { optional uint32 a = 1 \
                [(nanopb).long_names = false, (nanopb).sort_by_tag = false]; }";
    assert_eq!(size_of(text, "M"), Ok(6));
}

/// A NUMBER PAST A 64-BIT `size_t` IS NOT ONE, and neither is a chain of messages
/// longer than the reader follows.
#[test]
fn a_size_past_what_a_size_t_holds_and_a_chain_past_the_bound_are_refused() {
    let mut text = String::from("syntax = \"proto2\";\nmessage L0 { optional uint32 a = 1; }\n");
    for level in 1..=3 {
        text.push_str(&format!(
            "message L{level} {{ repeated L{} inner = 1 [(nanopb).max_count = 2147483647]; }}\n",
            level - 1
        ));
    }
    // `L0` is 6 bytes; one element of `L1` is 6 + a one-byte length + a one-byte
    // tag, and there are 2^31 - 1 of them.
    assert_eq!(size_of(&text, "L1"), Ok(2_147_483_647 * 8));
    assert_eq!(size_of(&text, "L2"), Err(SizeRefusal::TooLarge));
    assert_eq!(size_of(&text, "L3"), Err(SizeRefusal::TooLarge));

    let mut chain = String::from("syntax = \"proto2\";\n");
    for i in 0..300 {
        chain.push_str(&format!(
            "message C{i} {{ optional C{} next = 1; }}\n",
            i + 1
        ));
    }
    chain.push_str("message C300 { optional uint32 end = 1; }\n");
    assert_eq!(size_of(&chain, "C0"), Err(SizeRefusal::TooDeep));
    // The end of the chain is still a number: the refusal is about the walk.
    assert_eq!(size_of(&chain, "C300"), Ok(6));
}

/// THE DOCUMENT CARRIES A NUMBER OR A REASON, never both and never neither.
#[test]
fn the_document_has_a_number_or_a_reason() {
    let files = |text: &'static str| {
        [
            ProtoFile {
                name: "a.proto",
                text: text.as_bytes(),
            },
            ProtoFile {
                name: "nanopb.proto",
                text: NANOPB_STAND_IN.as_bytes(),
            },
        ]
    };
    let sized = proto_message_json("Everything", &files(SIZES), 0);
    assert!(
        sized.contains("\"max_encoded_size\":414,\"max_encoded_size_reason\":null"),
        "{sized}"
    );
    let unsized_ = proto_message_json("Unbounded", &files(SIZES), 0);
    assert!(
        unsized_
            .contains("\"max_encoded_size\":null,\"max_encoded_size_reason\":\"unbounded_field\""),
        "{unsized_}"
    );
    // A message the root reaches has its own number: `Placed` holds `Coordinate`.
    let placed = proto_message_json("Placed", &files(SIZES), 0);
    assert!(
        placed.contains("\"full_name\":\"Coordinate\"")
            && placed.matches("\"max_encoded_size\":").count() == 3,
        "{placed}"
    );
}

/// THE WORDS ARE THE ENUM'S.
#[test]
fn the_reason_words_are_the_refusals() {
    let words: Vec<&str> = SizeRefusal::ALL.iter().map(|r| r.word()).collect();
    assert_eq!(words, REFUSAL_WORDS);
}

/// The numbers of `#define X_size` macros in a generated header, by message
/// name as the macro spells it; a macro that is not a number (a symbolic size) is
/// absent.
fn generated_sizes(header: &str) -> alloc::collections::BTreeMap<String, u64> {
    let mut out = alloc::collections::BTreeMap::new();
    for line in header.lines() {
        let Some(rest) = line.strip_prefix("#define ") else {
            continue;
        };
        let mut parts = rest.split_whitespace();
        let (Some(name), Some(value)) = (parts.next(), parts.next()) else {
            continue;
        };
        if let (Some(message), Ok(n)) = (name.strip_suffix("_size"), value.parse::<u64>()) {
            out.insert(String::from(message), n);
        }
    }
    out
}

/// HELD TO THE GENERATOR ITSELF, where it is available: `WZ_NANOPB_REFERENCE_DIR`
/// names a directory with the headers a fresh run of nanopb's generator wrote for
/// the three reference schemas, `WZ_NANOPB_PROTO` the real `nanopb.proto` that
/// ships with it and `WZ_DESCRIPTOR_PROTO` the `descriptor.proto` it imports
/// (default `/usr/include/google/protobuf/descriptor.proto`).
///
/// `scripts/nanopb-reference-sizes.sh` provisions all three in a throwaway virtual
/// environment and runs this test. Without them the test skips, which is right on a
/// machine that does not have the generator and is the reason the numbers above
/// are written down.
#[test]
fn the_generators_own_sizes_are_the_numbers() {
    let Ok(dir) = std::env::var("WZ_NANOPB_REFERENCE_DIR") else {
        std::eprintln!(
            "skip: WZ_NANOPB_REFERENCE_DIR is not set (see scripts/nanopb-reference-sizes.sh)"
        );
        return;
    };
    let read = |path: &str| {
        std::fs::read_to_string(path).unwrap_or_else(|e| panic!("reading {path}: {e}"))
    };
    let nanopb = read(
        &std::env::var("WZ_NANOPB_PROTO")
            .expect("WZ_NANOPB_PROTO names the nanopb.proto that ships with the generator"),
    );
    let descriptor = read(
        &std::env::var("WZ_DESCRIPTOR_PROTO")
            .unwrap_or_else(|_| String::from("/usr/include/google/protobuf/descriptor.proto")),
    );
    let mut compared = 0;
    for (name, text, expected) in reference() {
        let header = read(&format!("{dir}/{}.pb.h", name.trim_end_matches(".proto")));
        let generated = generated_sizes(&header);
        let files = [
            ProtoFile {
                name,
                text: text.as_bytes(),
            },
            ProtoFile {
                name: "nanopb.proto",
                text: nanopb.as_bytes(),
            },
            ProtoFile {
                name: "google/protobuf/descriptor.proto",
                text: descriptor.as_bytes(),
            },
        ];
        for (root, _) in expected {
            let described = describe_proto(root, &files, 0)
                .unwrap_or_else(|d| panic!("{name}: {root} with the real option file: {d}"));
            let got = described.messages[0].max_encoded_size;
            let macro_name = root.replace('.', "_");
            match generated.get(&macro_name) {
                Some(n) => assert_eq!(got, Ok(*n), "{name}: {root}: the generator wrote {n}"),
                None => assert!(
                    got.is_err(),
                    "{name}: {root}: the generator wrote no number and this reader gave {got:?}"
                ),
            }
            compared += 1;
        }
    }
    assert_eq!(compared, 28);
}
