// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The selector's `zid` term over captures that hold SEVERAL zids: a prefix is
//! accepted when it names one node of the capture, and refused by name when it
//! names two.
//!
//! # Why a capture of this file's own and not an existing fixture
//!
//! A prefix is judged against the zids THE CAPTURE names, so the thing under
//! test is a property of a set, and every other fixture in this crate holds two
//! zids that differ in their first digit. These captures hold zids that share
//! eight or more leading digits, which is the case the consumer's flow list
//! makes reachable (it prints a zid as its first eight characters) and no
//! existing fixture can express.
//!
//! Every zid here is written the way the documents print it: zenoh's
//! spelling, the little-endian id read as a `u128`, so the FIRST digits are the
//! LAST wire bytes. [`zid`] turns a spelling into wire bytes through the
//! repository's own inverse, and a test that wrote the wire bytes by hand would
//! be writing the per-byte order this notation retired.

use alloc::format;
#[cfg(feature = "dissect")]
use alloc::string::String;
use alloc::string::ToString;
use alloc::vec::Vec;

use crate::datagram_tests::{frame_carrying, push, sender_space, udp_packet};
use crate::filter::{Filter, Selection};
use crate::link::LINKTYPE_ETHERNET;
use crate::node::tests::init_wire;
use crate::Dissection;

const LOW: [u8; 4] = [10, 0, 0, 1];
const HIGH: [u8; 4] = [10, 0, 0, 2];

/// Two nodes whose spellings share the eight digits `cbf383be`.
const TWIN_A: &str = "cbf383be1111111122222222aaaaaaaa";
const TWIN_B: &str = "cbf383be3333333344444444bbbbbbbb";
/// A second pair sharing `deadbeef`, so a selector can be ambiguous twice.
const PAIR_A: &str = "deadbeef5555555566666666cccccccc";
const PAIR_B: &str = "deadbeef7777777788888888dddddddd";
/// Nodes no other node here shares eight digits with.
const LONE_A: &str = "1234abcd9999999900000000eeeeeeee";
const LONE_B: &str = "fedcba98aaaaaaaa11111111ffffffff";

/// The wire bytes of the zid zenoh spells `spelled`.
fn zid(spelled: &str) -> Vec<u8> {
    wz_session_core::zid_hex::zenoh_hex_to_zid(spelled)
        .unwrap_or_else(|| panic!("{spelled:?} is not a spelling zenoh accepts"))
}

/// A capture with one link per `(low, high)` pair: each end names itself with
/// an INIT, and then each publishes ONE record under `demo/p`.
///
/// The low end's record carries one payload byte and the high end's two, so a
/// count of matched records says which side was selected as well as how many.
/// The INITs of every link come before any record, which is what makes each
/// link a LINK (both ends named themselves) before the first record is judged.
fn capture(links: &[(&str, &str)]) -> Dissection {
    let key = || sender_space(0, Some("demo/p"));
    let mut packets: Vec<Vec<u8>> = Vec::new();
    for (i, (low, high)) in links.iter().enumerate() {
        let sport = 43210 + i as u16;
        packets.push(udp_packet(LOW, sport, HIGH, 7447, &init_wire(&zid(low))));
        packets.push(udp_packet(HIGH, 7447, LOW, sport, &init_wire(&zid(high))));
    }
    for i in 0..links.len() {
        let sport = 43210 + i as u16;
        packets.push(udp_packet(
            LOW,
            sport,
            HIGH,
            7447,
            &frame_carrying(&push(key(), b"a")),
        ));
        packets.push(udp_packet(
            HIGH,
            7447,
            LOW,
            sport,
            &frame_carrying(&push(key(), b"bb")),
        ));
    }
    let mut d = Dissection::new();
    for (i, packet) in packets.iter().enumerate() {
        d.push_packet(LINKTYPE_ETHERNET, i, packet);
    }
    d.finish();
    d
}

/// What the throughput plane made of `selector` over `d`: matched, rejected
/// and undecided RECORDS.
fn judged(d: &Dissection, selector: &str) -> Selection {
    crate::agg::aggregate_where(d, &Filter::parse(selector).expect("the selector parses"))
        .selection()
}

fn counts(s: Selection) -> (usize, usize, usize) {
    (s.matched, s.rejected, s.undecided)
}

/// The two-session capture most of these tests read: four nodes, four records,
/// and one pair of nodes that share `cbf383be`.
///
/// `pub(crate)` for the key-set pin of the census document, which has to render
/// the one document that carries `ambiguous_zid_prefixes`: it needs a capture
/// in which a prefix IS ambiguous, and a second builder of one would be the
/// copy that drifts.
pub(crate) fn twins_and_two_others() -> Dissection {
    capture(&[(TWIN_A, LONE_A), (TWIN_B, LONE_B)])
}

/// The selector that is ambiguous in [`twins_and_two_others`].
pub(crate) const AMBIGUOUS_SELECTOR: &str = "zid == cbf383be";

/// A PREFIX OF EIGHT DIGITS OR MORE SELECTS THE ONE NODE IT NAMES.
///
/// The consumer's flow list shows a zid as its first eight characters, and a
/// selector written from what it shows selected nothing: `zid == cbf383be`
/// judged every row `no`, because the value was read as a whole zid of four
/// bytes that no node announced. The prefix and the full spelling must now
/// judge the same records, and the operand's case must not matter.
#[test]
fn a_unique_prefix_of_eight_digits_or_more_selects_what_the_full_spelling_selects() {
    let d = twins_and_two_others();

    // The control: the full spelling, which has always worked. One record is
    // the high end of the first link and nobody else has this zid.
    let full = judged(&d, &format!("zid == {LONE_A}"));
    assert_eq!(
        counts(full),
        (1, 3, 0),
        "the full spelling selects one node"
    );

    for prefix in ["1234abcd", "1234ABCD", "1234abcd9", &LONE_A[..31]] {
        for operand in [prefix.to_string(), format!("\"{prefix}\"")] {
            assert_eq!(
                counts(judged(&d, &format!("zid == {operand}"))),
                counts(full),
                "the prefix {operand} names one node of this capture, so it \
                 judges as the full spelling does"
            );
        }
    }
    // `!=` is the same node, negated.
    assert_eq!(
        counts(judged(&d, "zid != 1234abcd")),
        (3, 1, 0),
        "a prefix on the other side of `!=` is the same node, negated"
    );
}

/// A PREFIX OF FEWER THAN EIGHT DIGITS IS STILL A WHOLE VALUE.
///
/// Seven digits is a zid of four bytes that no node here announced, so it
/// selects nothing and is not an error: the rule that arrived with the prefix
/// begins at eight, and below it the language is what it was.
#[test]
fn a_prefix_of_fewer_than_eight_digits_is_judged_as_the_whole_value_it_is_written_as() {
    let d = twins_and_two_others();
    assert_eq!(
        counts(judged(&d, "zid == 1234abc")),
        (0, 4, 0),
        "seven digits are a whole value: no node announced it, so every \
         attributed record is rejected, and the selector is not refused"
    );
    assert_eq!(
        counts(judged(&d, "zid == 1234abcd")),
        (1, 3, 0),
        "and eight digits are a prefix: the same node, one digit later"
    );
}

/// THE PREFIX IS COMPARED AGAINST THE SPELLING THE DOCUMENTS PRINT.
///
/// Zenoh drops one leading zero nibble when it prints a zid, so a node whose
/// top byte is below `0x10` is shown without it. The eight digits a reader
/// copies from a row are the first eight of THAT text. Compared against the
/// padded 32-digit form they would be shifted by one and would name nothing.
#[test]
fn a_prefix_is_compared_against_the_written_spelling_and_not_the_padded_form() {
    // 31 digits: the 32-digit form of this id is `0bcdef01...`.
    const SHORT_SPELLING: &str = "bcdef0123456789abcdef0123456789";
    assert_eq!(SHORT_SPELLING.len(), 31);
    let d = capture(&[(SHORT_SPELLING, LONE_B)]);
    assert_eq!(
        counts(judged(&d, "zid == bcdef012")),
        (1, 1, 0),
        "the first eight digits of the printed spelling select the node"
    );
    // The padded form cannot be typed at all: a leading `0` is refused, as it
    // is for the whole value, so there is no second spelling to confuse.
    let err = Filter::parse("zid == 0bcdef01").expect_err("a leading zero is refused");
    assert!(
        matches!(
            err.kind,
            crate::filter::FilterErrorKind::UnknownValue { field: "zid", .. }
        ),
        "{err:?}"
    );
}

/// A PREFIX THAT NAMES TWO NODES OF THE CAPTURE JUDGES NOTHING.
///
/// Answering `no` from it would be false: the reader may have meant either
/// node, and each of them has records. Every record is counted UNDECIDED, none
/// matched and none rejected, and the negated form is no different. The
/// operand's other terms do not rescue it: the selector as a whole is not
/// judged, so `and bytes > 100` (which no record satisfies) does not turn the
/// undecided records into rejected ones.
#[test]
fn a_prefix_that_names_two_nodes_is_judged_by_nothing() {
    let d = twins_and_two_others();
    for selector in [
        "zid == cbf383be",
        "zid != cbf383be",
        "not zid == cbf383be",
        "zid == CBF383BE",
        "zid == cbf383be and bytes > 100",
        "zid == cbf383be or bytes > 100",
        "bytes > 100 or zid == cbf383be",
    ] {
        assert_eq!(
            counts(judged(&d, selector)),
            (0, 0, 4),
            "{selector}: an ambiguous term leaves the selector unjudged, \
             and the records are undecided rather than rejected"
        );
    }
}

/// ONE MORE DIGIT AND THE SAME PREFIX NAMES ONE NODE.
///
/// The refusal's candidates are what the reader picks between, and the next
/// digit they type is what tells them apart: the rule has to be a prefix rule
/// all the way down, not a flag set once for a text.
#[test]
fn a_prefix_made_longer_until_it_is_unique_selects_that_node() {
    let d = twins_and_two_others();
    assert_eq!(counts(judged(&d, "zid == cbf383be1")), (1, 3, 0));
    assert_eq!(counts(judged(&d, "zid == cbf383be3")), (1, 3, 0));
    // And a continuation neither candidate has names nothing, which is the
    // pre-prefix answer for a value no node announced.
    assert_eq!(counts(judged(&d, "zid == cbf383be9")), (0, 4, 0));
}

/// THE JUDGEMENT IS PER CAPTURE: one selector, two captures, two answers.
///
/// The prefix is unique among the zids a capture names, so a capture that holds
/// one of the twins resolves it and a capture that holds both does not. A rule
/// that remembered an ambiguity across captures, or resolved against a global
/// table of zids, would answer the same way twice.
#[test]
fn the_same_selector_is_ambiguous_in_one_capture_and_unique_in_another() {
    let both = twins_and_two_others();
    let only_one = capture(&[(TWIN_A, LONE_A), (LONE_B, PAIR_A)]);
    assert_eq!(counts(judged(&both, "zid == cbf383be")), (0, 0, 4));
    assert_eq!(counts(judged(&only_one, "zid == cbf383be")), (1, 3, 0));
}

/// A WHOLE VALUE KEEPS THE BEHAVIOUR IT HAD, EVEN WHEN IT IS ALSO A PREFIX.
///
/// `a1a1a1a1` is the complete spelling of a node of four bytes and the first
/// eight digits of another node's. The reader who typed all of a node's id
/// named that node, and has since the term existed; reading it as a prefix of
/// two nodes would turn a selector that worked into one that refuses.
#[test]
fn a_value_that_spells_a_node_in_full_names_it_whatever_else_it_is_a_prefix_of() {
    const SHORT_NODE: &str = "a1a1a1a1";
    const LONG_NODE: &str = "a1a1a1a1ffeeddccbbaa998877665544";
    let d = capture(&[(SHORT_NODE, LONE_A), (LONG_NODE, LONE_B)]);
    assert_eq!(
        counts(judged(&d, "zid == a1a1a1a1")),
        (1, 3, 0),
        "the whole spelling of the short node selects it alone"
    );
    assert_eq!(
        counts(judged(&d, &format!("zid == {LONG_NODE}"))),
        (1, 3, 0)
    );
    assert_eq!(
        counts(judged(&d, "zid == a1a1a1a1f")),
        (1, 3, 0),
        "and a longer prefix selects the other one, as a prefix"
    );
}

/// WHAT NAMES NO NODE STILL SELECTS NOTHING, and says so the way it always did.
#[test]
fn a_value_that_is_no_nodes_prefix_is_judged_as_before() {
    let d = twins_and_two_others();
    assert_eq!(counts(judged(&d, "zid == 99999999")), (0, 4, 0));
    assert_eq!(counts(judged(&d, "zid != 99999999")), (4, 0, 0));
}

/// The pair of ambiguities a selector can carry, over a capture that holds two
/// pairs of nodes sharing a prefix each.
fn two_pairs() -> Dissection {
    capture(&[(TWIN_A, PAIR_A), (TWIN_B, PAIR_B)])
}

#[test]
fn two_ambiguous_terms_leave_the_selector_unjudged_once() {
    let d = two_pairs();
    assert_eq!(
        counts(judged(&d, "zid == cbf383be or zid == deadbeef")),
        (0, 0, 4)
    );
    // One resolved and one not: the ambiguous half still decides the whole.
    assert_eq!(
        counts(judged(&d, "zid == cbf383be1 or zid == deadbeef")),
        (0, 0, 4)
    );
}

/// The census document narrowed by the selector: the prefix selects what the
/// full spelling selects, down to the byte, because once a prefix names one
/// node the document has no trace of the way it was written.
#[test]
fn the_census_document_of_a_unique_prefix_is_the_one_of_the_full_spelling() {
    let d = twins_and_two_others();
    let by_prefix = crate::census_json::census_json_where(
        &d,
        &Filter::parse("zid == 1234abcd").expect("parses"),
    );
    let by_full = crate::census_json::census_json_where(
        &d,
        &Filter::parse(&format!("zid == {LONE_A}")).expect("parses"),
    );
    assert_eq!(by_prefix, by_full);
    assert!(
        !by_prefix.contains("ambiguous_zid_prefixes"),
        "nothing was ambiguous, so the key is absent and not empty: {by_prefix}"
    );
}

/// The rows of the selection document, as their words.
#[cfg(feature = "dissect")]
fn selected_words(doc: &str) -> Vec<&str> {
    doc.split("\"selected\":\"")
        .skip(1)
        .map(|rest| rest.split('"').next().expect("a closing quote"))
        .collect()
}

/// Every row of the selection document and the key that explains it.
#[cfg(feature = "dissect")]
struct EveryListNumbered;

#[cfg(feature = "dissect")]
impl crate::fields_json::RowCoordinates for EveryListNumbered {
    fn list_id(&self, list: usize) -> Option<u64> {
        Some(list as u64)
    }

    fn scouting_list_id(&self, _flow: &crate::link::FlowKey) -> Option<u64> {
        None
    }
}

#[cfg(feature = "dissect")]
fn selection_of(d: &Dissection, selector: &str) -> String {
    crate::selection_json::selection_json_where_coordinated(
        d,
        &Filter::parse(selector).expect("parses"),
        &EveryListNumbered,
    )
}

/// THE SELECTION DOCUMENT: a unique prefix judges the rows the full spelling
/// does, and the document is the same one.
#[cfg(feature = "dissect")]
#[test]
fn the_selection_document_of_a_unique_prefix_is_the_one_of_the_full_spelling() {
    let d = twins_and_two_others();
    let by_prefix = selection_of(&d, "zid == 1234abcd");
    let by_full = selection_of(&d, &format!("zid == {LONE_A}"));
    assert_eq!(by_prefix, by_full);
    let words = selected_words(&by_prefix);
    assert!(
        words.contains(&"yes") && words.contains(&"no"),
        "anti-vacuity: the selector divided the rows: {words:?}"
    );
}

/// THE SELECTION DOCUMENT OF AN AMBIGUOUS PREFIX: every row unjudged, and the
/// refusal, with the candidates the reader chooses between, in the document.
#[cfg(feature = "dissect")]
#[test]
fn the_selection_document_of_an_ambiguous_prefix_carries_the_refusal() {
    let d = twins_and_two_others();
    let doc = selection_of(&d, "zid == cbf383be");
    let words = selected_words(&doc);
    assert!(!words.is_empty(), "anti-vacuity: the document has rows");
    assert!(
        words.iter().all(|w| *w == "unjudged"),
        "an ambiguous selector judges no row, so none is `no`: {words:?}"
    );
    assert!(
        doc.contains(&format!(
            ",\"ambiguous_zid_prefixes\":[{{\"start\":7,\"end\":15,\
             \"prefix\":\"cbf383be\",\"candidates\":[\"{TWIN_A}\",\"{TWIN_B}\"]}}]"
        )),
        "the term's byte span, the prefix and both candidates, in the spelling \
         the documents print: {doc}"
    );
}

/// TWO AMBIGUOUS TERMS ARE TWO ENTRIES, in the order the selector writes them,
/// each with its own span and its own candidates.
#[cfg(feature = "dissect")]
#[test]
fn each_ambiguous_term_of_a_selector_is_reported_with_its_own_span() {
    let d = two_pairs();
    let doc = selection_of(&d, "zid == DEADBEEF or zid == cbf383be");
    let want = format!(
        "\"ambiguous_zid_prefixes\":[\
         {{\"start\":7,\"end\":15,\"prefix\":\"deadbeef\",\
         \"candidates\":[\"{PAIR_A}\",\"{PAIR_B}\"]}},\
         {{\"start\":26,\"end\":34,\"prefix\":\"cbf383be\",\
         \"candidates\":[\"{TWIN_A}\",\"{TWIN_B}\"]}}]"
    );
    assert!(doc.contains(&want), "{doc}");
}

/// A selector that is not ambiguous writes no such key: the control the
/// absence of the key is measured against.
#[cfg(feature = "dissect")]
#[test]
fn a_selector_that_is_not_ambiguous_adds_no_key_to_the_selection_document() {
    let d = twins_and_two_others();
    for selector in [
        "zid == 1234abcd",
        "zid == cbf383be1",
        "bytes > 0",
        "zid == 99999999",
    ] {
        let doc = selection_of(&d, selector);
        assert!(!doc.contains("ambiguous"), "{selector}: {doc}");
    }
}

/// The census document of an ambiguous prefix says so beside the planes it
/// left undecided, in the shape the selection document uses.
#[test]
fn the_census_document_of_an_ambiguous_prefix_carries_the_refusal() {
    let d = twins_and_two_others();
    let doc = crate::census_json::census_json_where(
        &d,
        &Filter::parse("zid == cbf383be").expect("parses"),
    );
    assert!(
        doc.contains(&format!(
            ",\"ambiguous_zid_prefixes\":[{{\"start\":7,\"end\":15,\
             \"prefix\":\"cbf383be\",\"candidates\":[\"{TWIN_A}\",\"{TWIN_B}\"]}}]"
        )),
        "{doc}"
    );
    assert!(
        doc.contains("\"selection\":{\"matched\":0,\"rejected\":0,\"undecided\":4}"),
        "every record the throughput plane saw is undecided: {doc}"
    );
}
