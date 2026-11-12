// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The facts a row states beside its tree (field revision 64) against the tree
//! itself, read from the document's own JSON.
//!
//! The oracle is the `fields` tree each row carries, read here by a reader of
//! its own: the JSON is parsed, a carried entry's node is found by its span and
//! name, its body by the `mid` it holds, and each fact by the node a reader of
//! the tree would take it from. Nothing here calls `crate::tree_facts`, so a
//! fact the writer reads from the wrong node disagrees with the tree and fails.
//! The `payload` contract is held the same way: a body with a `payload` leaf
//! answers that leaf's span and `span_of: "payload"`, and `span_of: "payload"`
//! is never said of anything else.

use alloc::string::{String, ToString};
use alloc::vec::Vec;

use crate::fields_json::fields_json;
use crate::Dissection;

/// A JSON value, numbers kept as their text so a string past 2^53 and a
/// number compare by the digits they spell.
#[derive(Debug, Clone, PartialEq)]
enum Json {
    Null,
    Bool(bool),
    Number(String),
    Text(String),
    Array(Vec<Json>),
    Object(Vec<(String, Json)>),
}

impl Json {
    fn get(&self, key: &str) -> Option<&Json> {
        match self {
            Json::Object(members) => members.iter().find(|(k, _)| k == key).map(|(_, v)| v),
            _ => None,
        }
    }

    fn text(&self) -> Option<&str> {
        match self {
            Json::Text(s) => Some(s),
            _ => None,
        }
    }

    fn array(&self) -> &[Json] {
        match self {
            Json::Array(items) => items,
            _ => &[],
        }
    }

    /// The digits of an integer, whether written as a number or as a string.
    fn digits(&self) -> Option<&str> {
        match self {
            Json::Number(n) | Json::Text(n) => Some(n),
            _ => None,
        }
    }

    fn usize(&self) -> Option<usize> {
        self.digits()?.parse().ok()
    }
}

struct Parser<'a> {
    bytes: &'a [u8],
    at: usize,
}

impl Parser<'_> {
    fn space(&mut self) {
        while matches!(self.bytes.get(self.at), Some(b' ' | b'\n' | b'\r' | b'\t')) {
            self.at += 1;
        }
    }

    fn eat(&mut self, byte: u8) {
        self.space();
        assert_eq!(self.bytes.get(self.at), Some(&byte), "at {}", self.at);
        self.at += 1;
    }

    fn value(&mut self) -> Json {
        self.space();
        match self.bytes[self.at] {
            b'{' => {
                self.at += 1;
                let mut members = Vec::new();
                self.space();
                if self.bytes[self.at] == b'}' {
                    self.at += 1;
                    return Json::Object(members);
                }
                loop {
                    self.space();
                    let key = self.string();
                    self.eat(b':');
                    members.push((key, self.value()));
                    self.space();
                    self.at += 1;
                    if self.bytes[self.at - 1] == b'}' {
                        return Json::Object(members);
                    }
                }
            }
            b'[' => {
                self.at += 1;
                let mut items = Vec::new();
                self.space();
                if self.bytes[self.at] == b']' {
                    self.at += 1;
                    return Json::Array(items);
                }
                loop {
                    items.push(self.value());
                    self.space();
                    self.at += 1;
                    if self.bytes[self.at - 1] == b']' {
                        return Json::Array(items);
                    }
                }
            }
            b'"' => Json::Text(self.string()),
            b't' => {
                self.at += 4;
                Json::Bool(true)
            }
            b'f' => {
                self.at += 5;
                Json::Bool(false)
            }
            b'n' => {
                self.at += 4;
                Json::Null
            }
            _ => {
                let start = self.at;
                while matches!(
                    self.bytes.get(self.at),
                    Some(b'0'..=b'9' | b'-' | b'+' | b'.' | b'e' | b'E')
                ) {
                    self.at += 1;
                }
                Json::Number(
                    core::str::from_utf8(&self.bytes[start..self.at])
                        .unwrap()
                        .to_string(),
                )
            }
        }
    }

    fn string(&mut self) -> String {
        assert_eq!(self.bytes[self.at], b'"');
        self.at += 1;
        let mut out = Vec::new();
        loop {
            match self.bytes[self.at] {
                b'"' => {
                    self.at += 1;
                    return String::from_utf8(out).unwrap();
                }
                b'\\' => {
                    // The trees spell names and hex; an escape is kept as its
                    // two bytes, which no comparison below looks inside.
                    out.extend_from_slice(&self.bytes[self.at..self.at + 2]);
                    self.at += 2;
                }
                b => {
                    out.push(b);
                    self.at += 1;
                }
            }
        }
    }
}

fn parse(text: &str) -> Json {
    let mut p = Parser {
        bytes: text.as_bytes(),
        at: 0,
    };
    p.value()
}

/// A tree node's children.
fn children(node: &Json) -> &[Json] {
    node.get("fields").map_or(&[], Json::array)
}

fn name(node: &Json) -> &str {
    node.get("name").and_then(Json::text).unwrap_or("")
}

fn child<'a>(node: &'a Json, wanted: &str) -> Option<&'a Json> {
    children(node).iter().find(|c| name(c) == wanted)
}

fn span(node: &Json) -> (usize, usize) {
    (
        node.get("start").and_then(Json::usize).expect("a start"),
        node.get("end").and_then(Json::usize).expect("an end"),
    )
}

/// Every node of a tree, in walk order.
fn walk<'a>(node: &'a Json, out: &mut Vec<&'a Json>) {
    out.push(node);
    for c in children(node) {
        walk(c, out);
    }
}

/// The node a carried entry names: the one with its span and its message name.
fn entry_node<'a>(tree: &'a Json, entry: &Json) -> Option<&'a Json> {
    let want = (
        entry.get("start").and_then(Json::usize)?,
        entry.get("end").and_then(Json::usize)?,
    );
    let message = entry.get("message").and_then(Json::text)?;
    let mut nodes = Vec::new();
    walk(tree, &mut nodes);
    nodes
        .into_iter()
        .find(|n| name(n) == message && span(n) == want)
}

/// A message node's body: the direct child that holds a `mid`.
fn body(message: &Json) -> Option<&Json> {
    children(message)
        .iter()
        .find(|c| child(c, "mid").is_some() && c.get("fields").is_some())
}

/// The first `timestamp` under a body outside every extension chain.
fn body_time(node: &Json) -> Option<&Json> {
    if name(node) == "timestamp" {
        return child(node, "time").and_then(|t| t.get("value"));
    }
    children(node)
        .iter()
        .filter(|c| name(c) != "extensions")
        .find_map(body_time)
}

/// The first leaf called `payload` that holds bytes, anywhere under `node`.
fn payload_leaf(node: &Json) -> Option<&Json> {
    let mut nodes = Vec::new();
    walk(node, &mut nodes);
    nodes
        .into_iter()
        .find(|n| name(n) == "payload" && n.get("kind").and_then(Json::text) == Some("bytes"))
}

#[derive(Default)]
struct Seen {
    rows: usize,
    frames: usize,
    fragments: usize,
    entries: usize,
    declared: usize,
    stamped: usize,
    payload_leaves: usize,
    chain_entries: usize,
}

/// One carried entry against the message node it names.
fn entry_holds(entry: &Json, node: Option<&Json>, seen: &mut Seen, at: &str) {
    seen.entries += 1;
    let body = node.and_then(body);
    let declared = body
        .filter(|b| child(b, "keyexpr").is_some())
        .and_then(|b| child(b, "id"))
        .and_then(|id| id.get("value"));
    assert_eq!(
        entry.get("declared_id"),
        Some(declared.unwrap_or(&Json::Null)),
        "{at}: declared_id"
    );
    seen.declared += usize::from(declared.is_some());
    let time = body.and_then(body_time);
    assert_eq!(
        entry.get("timestamp_ntp64").and_then(Json::digits),
        time.and_then(Json::digits),
        "{at}: timestamp_ntp64"
    );
    assert!(
        entry.get("timestamp_ntp64").is_some(),
        "{at}: the key is there"
    );
    seen.stamped += usize::from(time.is_some());
    let payload = entry.get("payload").expect("every entry has `payload`");
    match (body.and_then(payload_leaf), payload) {
        (Some(leaf), Json::Object(_)) => {
            assert_eq!(
                payload.get("span_of").and_then(Json::text),
                Some("payload"),
                "{at}: a body with a payload leaf"
            );
            let range = (
                payload.get("start").and_then(Json::usize).unwrap(),
                payload.get("end").and_then(Json::usize).unwrap(),
            );
            assert_eq!(range, span(leaf), "{at}: the range is the leaf's span");
            seen.payload_leaves += 1;
        }
        (Some(_), other) => panic!("{at}: a body with a payload leaf said {other:?}"),
        (None, Json::Object(_)) => assert_ne!(
            payload.get("span_of").and_then(Json::text),
            Some("payload"),
            "{at}: `payload` said of a body with no payload leaf"
        ),
        (None, _) => {}
    }
}

/// Every row of a field document against its tree.
fn document_holds(doc: &str, seen: &mut Seen) {
    let doc = parse(doc);
    let mut rows = Vec::new();
    collect_rows(&doc, &mut rows);
    for row in rows {
        let tree = row.get("fields").expect("a walked row with its tree");
        let at = alloc::format!("row {}", name(row));
        seen.rows += 1;
        // The transport header.
        let header = row.get("transport_header").expect("every walked row");
        match name(tree) {
            word @ ("Frame" | "Fragment") => {
                let value = |n: &str| child(tree, n).and_then(|c| c.get("value"));
                assert_eq!(
                    header.get("sn").and_then(Json::digits),
                    value("sn").and_then(Json::digits),
                    "{at}: sn"
                );
                assert_eq!(header.get("reliable"), value("r"), "{at}: reliable");
                let more = if word == "Fragment" {
                    seen.fragments += 1;
                    value("m").cloned().expect("a Fragment's m")
                } else {
                    seen.frames += 1;
                    Json::Null
                };
                assert_eq!(header.get("more"), Some(&more), "{at}: more");
            }
            _ => assert_eq!(header, &Json::Null, "{at}: no transport header"),
        }
        // The unnamed extensions.
        let mut nodes = Vec::new();
        walk(tree, &mut nodes);
        let unnamed: Vec<&str> = nodes
            .iter()
            .filter(|n| name(n) == "ext" && child(n, "ext_name").is_none())
            .filter_map(|n| child(n, "ext_id")?.get("value")?.digits())
            .collect();
        let said: Vec<&str> = row
            .get("unnamed_extensions")
            .expect("every walked row")
            .array()
            .iter()
            .filter_map(Json::digits)
            .collect();
        assert_eq!(said, unnamed, "{at}: unnamed_extensions");
        // The carried entries: the row's own speaks for its message only when
        // it is not split into records.
        let carried = row.get("carried").map_or(&[][..], Json::array);
        let split = carried.len() > 1;
        for (i, entry) in carried.iter().enumerate() {
            let node = if i == 0 && split {
                None
            } else {
                entry_node(tree, entry)
            };
            entry_holds(entry, node, seen, &alloc::format!("{at} entry {i}"));
        }
        // A completed chain's records, against their own trees.
        if let Some(above) = row.get("above_transport").filter(|a| **a != Json::Null) {
            let trees = above.get("fields").map_or(&[][..], Json::array);
            for (i, entry) in above
                .get("carried")
                .map_or(&[][..], Json::array)
                .iter()
                .enumerate()
            {
                seen.chain_entries += 1;
                let node = trees.get(i).and_then(|t| entry_node(t, entry));
                entry_holds(entry, node, seen, &alloc::format!("{at} chain entry {i}"));
            }
        }
    }
}

/// Every object that is a walked row: one with a `fields` tree and `carried`.
fn collect_rows<'a>(value: &'a Json, out: &mut Vec<&'a Json>) {
    match value {
        Json::Object(members) => {
            let is_row = value.get("carried").is_some()
                && value.get("fields").and_then(|f| f.get("kind")).is_some();
            if is_row {
                out.push(value);
            }
            for (_, v) in members {
                collect_rows(v, out);
            }
        }
        Json::Array(items) => items.iter().for_each(|v| collect_rows(v, out)),
        _ => {}
    }
}

/// The tracked captures, each read whole.
fn tracked() -> [(&'static str, &'static [u8]); 5] {
    [
        (
            "compressed-session-refused-body",
            include_bytes!("../../../captures/compressed-session-refused-body.pcap"),
        ),
        (
            "fragmented-push-midsession-and-established",
            include_bytes!("../../../captures/fragmented-push-midsession-and-established.pcap"),
        ),
        (
            "publisher-priority-encoding-timestamp",
            include_bytes!("../../../captures/publisher-priority-encoding-timestamp.pcap"),
        ),
        (
            "raweth-transport-messages",
            include_bytes!("../../../captures/raweth-transport-messages.pcap"),
        ),
        (
            "scout-and-hello-ipv4-ipv6",
            include_bytes!("../../../captures/scout-and-hello-ipv4-ipv6.pcap"),
        ),
    ]
}

#[test]
fn every_tracked_captures_row_states_what_its_tree_holds() {
    let mut seen = Seen::default();
    for (label, file) in tracked() {
        let d = Dissection::from_capture(file).expect("the capture reads");
        let doc = fields_json(&d, file, None, None);
        let before = seen.rows;
        document_holds(&doc, &mut seen);
        assert!(seen.rows > before, "{label}: rows were read");
    }
    // The shapes the facts are FOR are in what was read, or the comparison
    // above says nothing about them.
    assert!(seen.frames > 0, "a Frame row");
    assert!(seen.fragments > 0, "a Fragment row");
    assert!(seen.stamped > 0, "a stamped sample");
    assert!(seen.payload_leaves > 0, "a payload leaf");
    assert!(seen.entries > seen.rows, "records beside rows");
}

/// A completed chain's records: their facts against the trees
/// `above_transport.fields` carries.
#[cfg(feature = "reassembly")]
#[test]
fn a_completed_chains_records_state_what_their_trees_hold() {
    let record = crate::payload::tests_support::push_declaring("demo/sensor", 0, &[1, 2, 3]);
    let (d, file) = crate::datagram_tests::reassembled_record_dissection_with_file(&record);
    let mut seen = Seen::default();
    document_holds(&fields_json(&d, &file, None, None), &mut seen);
    assert!(seen.chain_entries > 0, "a chain's record was read");
    assert!(seen.payload_leaves > 0, "its payload leaf");
}

/// A declaration's id, against its tree: the tracked captures carry no
/// declaration body, so a `Frame` batching a `DeclareKeyExpr` is built here.
#[cfg(feature = "reassembly")]
#[test]
fn a_declarations_entry_states_the_id_its_body_declares() {
    let record = crate::exchange::tests::declare_kexpr(5, "demo/a");
    let (d, file) = crate::datagram_tests::contiguous_record_dissection_with_file(&record);
    let doc = fields_json(&d, &file, None, None);
    let mut seen = Seen::default();
    document_holds(&doc, &mut seen);
    assert_eq!(seen.declared, 1, "{doc}");
    assert!(doc.contains("\"declared_id\":5,"), "{doc}");
}
