// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! THE FIELD TREE AS A PATH SEES IT: the normalised view of a
//! [`Field`](crate::dissect::Field) tree a
//! selector addresses by dotted path, and the declared shape of every tree the
//! walkers in [`crate::dissect`] can produce.
//!
//! # Why a view, and not the tree as it is walked
//!
//! The walkers name what the WIRE holds, and three of their shapes are about
//! how the wire is laid out rather than what a reader is asking about:
//!
//! * an extension is an `ext` entry whose identity is the `ext_name` label
//!   inside it, so the tree spells a QoS extension as `ext` and a reader asks
//!   for `qos`. In this view an entry is NAMED by its `ext_name`, and an entry
//!   whose carrier declares no name for its id stays `ext`;
//! * the `extensions` container is a chain, and nothing about the chain is a
//!   question: its entries are children of the message that carries it;
//! * a ZBuf body walked into a group named like its extension (`source_info`
//!   inside the `source_info` entry) is one thing written twice, so the group's
//!   children are the entry's;
//! * and because of that last rule, a NAMED entry's own header fields (the
//!   header byte and the `ext_id`, `m`, `encoding`, `z` and `ext_name` read
//!   out of it) stand one level down, under `ext`: `qos.ext.encoding` is the
//!   QoS entry's two-bit body encoding, and `query_body.encoding` the encoding
//!   the query's value was written in. Without the level the two are one path
//!   with two kinds. An entry with no name is already `ext`, and its header
//!   fields stay where they are;
//! * a body whose encoding its carrier does not fix (an entry with no name,
//!   an `Oam`) is walked as `value` whatever it holds, an integer or bytes.
//!   Under one name that is one path with two kinds, which no comparison can
//!   be written against, so in this view it is named by the encoding the wire
//!   chose, as the protocol names the two bodies: `z64` and `zbuf`.
//!
//! The rules are applied HERE, once, by
//! [`children`](crate::dissect_schema::children) and
//! [`name_in`](crate::dissect_schema::name_in), for the
//! two readers that need them to agree: the selector, which matches a path
//! against a record's tree, and the declared shape below, which says which
//! paths exist. A path the declaration lists and the matcher cannot reach, or
//! the reverse, would be a selector refused for a field that is there or
//! accepted for one that never is.
//!
//! # The declared shape
//!
//! [`roots`](crate::dissect_schema::roots) is every message root and what can
//! sit under it, already in the
//! normalised view. It is DECLARED, not derived: a tree is the output of code,
//! and the only way to enumerate what code can output is to write it down and
//! hold the code to it. The tests below dissect messages built by this crate's
//! codecs and fail on any normalised path the declaration does not hold, with
//! the kind it holds it at.

use alloc::string::String;
use alloc::vec::Vec;

use crate::dissect::{Field, FieldValue};

/// The name a node answers to in the normalised view, standing under `parent`
/// (`None` for a root).
///
/// An `ext` entry answers to its `ext_name` when its carrier declares one; a
/// `value` under a carrier that does not fix its encoding answers to that
/// encoding ([`Z64`], [`ZBUF`]); every other node to its own name.
pub fn name_in<'t>(parent: Option<&'t Field>, field: &'t Field) -> &'t str {
    if field.name == "ext" {
        if let Some(label) = ext_label(field) {
            return label;
        }
    }
    if field.name == "value" && parent.is_some_and(fixes_no_encoding) {
        match field.value {
            FieldValue::Uint(_) => return Z64,
            FieldValue::Bytes(_) => return ZBUF,
            _ => {}
        }
    }
    &field.name
}

/// A body an integer encoding wrote, under a carrier that fixes no encoding.
pub const Z64: &str = "z64";
/// A body a bytes encoding wrote, under a carrier that fixes no encoding.
pub const ZBUF: &str = "zbuf";

/// Whether `carrier` reads its body in whichever encoding the wire chose: an
/// extension entry whose carrier declares no name for its id, a named entry
/// the protocol writes in several encodings ([`SEVERAL_ENCODINGS`]), and an
/// `Oam`.
fn fixes_no_encoding(carrier: &Field) -> bool {
    carrier.name == "Oam"
        || (carrier.name == "ext"
            && ext_label(carrier).map_or(true, |name| SEVERAL_ENCODINGS.contains(&name)))
}

/// The named extension entries whose body the protocol writes in more than one
/// encoding: `usrpwd` is a unit on an `InitSyn`, an integer nonce on an
/// `InitAck` and the user and HMAC bytes on an `OpenSyn`, all under one id.
/// Their shape is [`ANY_VALUE`]; `every_declared_path_has_one_kind` holds the
/// list to the shape.
const SEVERAL_ENCODINGS: &[&str] = &["usrpwd"];

/// The `ext_name` label directly under an `ext` entry, if it has one.
fn ext_label(entry: &Field) -> Option<&str> {
    let FieldValue::Nested(children) = &entry.value else {
        return None;
    };
    children.iter().find_map(|c| match (&*c.name, &c.value) {
        ("ext_name", FieldValue::Label(word)) => Some(&**word),
        _ => None,
    })
}

/// The name of the level a named extension entry's header fields stand under.
pub const EXT_HEADER_LEVEL: &str = "ext";

/// The one transport message whose body is a batch of network messages, and
/// the group of its tree that holds them: a record a `Frame` carried stands at
/// `Frame.payload.<message>`.
pub const BATCH_CARRIER: &str = "Frame";
/// See [`BATCH_CARRIER`].
pub const BATCH_LEVEL: &str = "payload";
/// The node under [`BATCH_LEVEL`] that holds a batch's bytes past where its
/// walk stopped: a byte range, not a message.
pub const BATCH_REMAINDER: &str = "unparsed";
/// The transport message whose bodies are pieces of a batch, joined across
/// several of them: a record joined out of them stands beside the one that
/// completed it, not inside it.
pub const PIECE_CARRIER: &str = "Fragment";

// ── Names once published ─────────────────────────────────────────────────
//
// A path is a NAME a consumer keeps: in a saved selector, in a column it
// filters on, in the `selector_path` of a document it stored. So the declared
// shape is not free to forget one. Three rules, each held by a test:
//
// * every fact the shape has published (a path, the kind it is read at, and
//   each word of a closed label) is in `published_selector_paths.txt`, and that
//   file only grows: a fact is appended in the commit that declares it;
// * every published fact still holds of the shape, under the path's CURRENT
//   name: the path is declared at the same kind, and a label still carries the
//   word. A field whose kind changes is a new field and takes a new name, so a
//   saved `p == 3` never becomes a comparison of another kind;
// * a path that is no longer declared under its name was RENAMED, and the
//   rename is declared in [`RENAMED`]. The selector reads a former name as the
//   field it names now, so a saved selector keeps selecting what it selected,
//   and a former name is never declared again for another field.

/// One rename of a declared node, and with it of every path under it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Renamed {
    /// The node's full path before, from its message root.
    pub from: &'static str,
    /// The node's full path after.
    pub to: &'static str,
    /// The field document revision whose shape first carried `to`.
    pub since_fields_revision: u32,
}

/// Every rename since the shape's paths were first published, oldest first.
pub const RENAMED: &[Renamed] = &[];

/// `path` with `from` replaced by `to` when it is that node or a path under it.
/// A network message's node is the same node in the record a `Frame` carries,
/// so a rename of `Push.x` renames `Frame.payload.Push.x` with it.
fn rename_one(path: &str, from: &str, to: &str) -> Option<String> {
    let under = |path: &str| {
        let rest = path.strip_prefix(from)?;
        (rest.is_empty() || rest.starts_with('.')).then(|| alloc::format!("{to}{rest}"))
    };
    if let Some(renamed) = under(path) {
        return Some(renamed);
    }
    let record = path
        .strip_prefix(BATCH_CARRIER)?
        .strip_prefix('.')?
        .strip_prefix(BATCH_LEVEL)?
        .strip_prefix('.')?;
    under(record).map(|r| alloc::format!("{BATCH_CARRIER}.{BATCH_LEVEL}.{r}"))
}

/// The name `path` has now under `renames` (oldest first): itself when no
/// rename reaches it.
pub fn current_name_under(path: &str, renames: &[Renamed]) -> String {
    let mut name = String::from(path);
    for r in renames {
        if let Some(next) = rename_one(&name, r.from, r.to) {
            name = next;
        }
    }
    name
}

/// Every former name of `path` under `renames` (oldest first), most recent
/// first: the names a selector written before each rename used for it.
pub fn former_names_under(path: &str, renames: &[Renamed]) -> Vec<String> {
    let mut names: Vec<String> = alloc::vec![String::from(path)];
    for r in renames.iter().rev() {
        let earlier: Vec<String> = names
            .iter()
            .filter_map(|n| rename_one(n, r.to, r.from))
            .collect();
        for e in earlier {
            if !names.contains(&e) {
                names.push(e);
            }
        }
    }
    names.remove(0);
    names
}

/// One child in the normalised view.
#[derive(Clone, Copy)]
pub enum Child<'t> {
    /// A node of the tree.
    Node(&'t Field),
    /// The `ext` level of a NAMED extension entry: the entry itself stands for
    /// it (a presence test or a width reads the entry), and its header fields
    /// are what stands under it.
    HeaderLevel(&'t Field),
}

/// Whether `child` of the extension entry `entry` is one of the entry's header
/// fields: the header byte, and the readings that alias its span.
///
/// Decided by the span and not by the name, because a walked body collapsed
/// into the entry can carry the same names (`query_body`'s `encoding`).
fn is_entry_header(entry_header: &Field, child: &Field) -> bool {
    core::ptr::eq(entry_header, child)
        || (child.value.is_alias() && child.span == entry_header.span)
}

/// Visit the children of `field` in the normalised view, in wire order.
///
/// An `extensions` child is replaced by its entries, a group under an `ext`
/// entry that carries the entry's own name is replaced by its children, and a
/// named entry's header fields are moved under one [`Child::HeaderLevel`]
/// visited where the header stood: the rules in the module's note. A node that
/// is not [`Nested`](FieldValue::Nested) has no children.
pub fn children<'t>(field: &'t Field, visit: &mut dyn FnMut(Child<'t>)) {
    let FieldValue::Nested(own) = &field.value else {
        return;
    };
    let named = (field.name == "ext").then(|| ext_label(field)).flatten();
    let header = named
        .and_then(|_| own.first())
        .filter(|first| first.name == "header");
    for child in own {
        if let Some(header) = header {
            if is_entry_header(header, child) {
                if core::ptr::eq(header, child) {
                    visit(Child::HeaderLevel(field));
                }
                continue;
            }
        }
        if child.name == "extensions" {
            // A chain inside a chain is not something a walker builds, but the
            // rule is about the container and not about its depth.
            children(child, visit);
        } else if named.is_some_and(|name| child.name == name)
            && matches!(child.value, FieldValue::Nested(_))
        {
            children(child, visit);
        } else {
            visit(Child::Node(child));
        }
    }
}

/// The header fields under a [`Child::HeaderLevel`], in wire order.
pub fn header_fields<'t>(entry: &'t Field, visit: &mut dyn FnMut(&'t Field)) {
    let FieldValue::Nested(own) = &entry.value else {
        return;
    };
    let Some(header) = own.first().filter(|f| f.name == "header") else {
        return;
    };
    own.iter()
        .filter(|c| is_entry_header(header, c))
        .for_each(visit);
}

/// Every node of `root`'s normalised tree whose path ENDS with `segments`,
/// in depth-first wire order.
///
/// A path matches a contiguous chain of parent and child, which may begin at
/// any depth: `encoding.id` is the `id` under an `encoding` wherever that
/// `encoding` stands, and `Push.put.encoding.id` is only the one under a
/// `Push`'s `put`. `root` itself is the first link a chain can begin at.
pub fn matching<'t>(root: &'t Field, segments: &[&str]) -> Vec<&'t Field> {
    let mut found = Vec::new();
    if segments.is_empty() {
        return found;
    }
    let mut trail: Vec<&str> = Vec::new();
    walk(Child::Node(root), &mut trail, &mut |trail, field, _| {
        if trail.len() >= segments.len() && trail[trail.len() - segments.len()..] == *segments {
            found.push(field);
        }
    });
    found
}

/// Every normalised path of `root`'s tree, root first, with the kind word of
/// the node it ends at: what the declared shape is held to.
pub fn paths_of(root: &Field) -> Vec<(String, &'static str)> {
    let mut out = Vec::new();
    let mut trail: Vec<&str> = Vec::new();
    walk(Child::Node(root), &mut trail, &mut |trail, _, kind| {
        out.push((trail.join("."), kind));
    });
    out
}

/// THE PATH EACH NODE OF `root`'s TREE ANSWERS TO, as a selector names it:
/// what a consumer offers as "filter on this field" without building the
/// normalised view a second time.
///
/// Keyed by the node's address in `root`'s tree, and read through
/// [`NodePaths::of`]. A node the view names is reached by exactly one chain of
/// parent and child from `root`, so it has one path. A node the view does NOT
/// name has none, and that is an answer of its own rather than a missing
/// entry:
///
/// * the `extensions` container, whose entries are children of the message
///   that carries it;
/// * a walked extension body named like its entry (`source_info` inside the
///   `source_info` entry), whose children are the entry's.
///
/// Both are one thing written twice, or a layout and not a field, so no path
/// term can single them out; [`children`] is the rule that says so, and this is
/// its walk, so the two cannot disagree. A named entry's header fields stand
/// under its `ext` level and their paths say so (`Push.qos.ext.encoding`).
pub fn node_paths(root: &Field) -> NodePaths {
    let mut paths = alloc::collections::BTreeMap::new();
    let mut trail: Vec<&str> = Vec::new();
    walk(Child::Node(root), &mut trail, &mut |trail, field, _| {
        // A named entry is visited twice, as itself and as the `ext` level
        // its header fields stand under; the entry's own path is the first.
        paths
            .entry(field as *const Field as usize)
            .or_insert_with(|| trail.join("."));
    });
    NodePaths { paths }
}

/// The paths [`node_paths`] found, by node.
#[derive(Debug, Clone, Default)]
pub struct NodePaths {
    paths: alloc::collections::BTreeMap<usize, String>,
}

impl NodePaths {
    /// The path `node` answers to, or `None` for a node the normalised view
    /// does not name. `node` must be a node of the tree the paths were found
    /// over; any other node has no path here.
    pub fn of(&self, node: &Field) -> Option<&str> {
        self.paths
            .get(&(node as *const Field as usize))
            .map(String::as_str)
    }
}

/// The one depth-first walk of the normalised view: `visit` is handed the
/// path down to each node (its own name last), the field an occurrence of it
/// reads, and its kind word.
fn walk<'t>(
    node: Child<'t>,
    trail: &mut Vec<&'t str>,
    visit: &mut dyn FnMut(&[&'t str], &'t Field, &'static str),
) {
    walk_under(None, node, trail, visit);
}

/// [`walk`] of `node`, a child of `parent` in the tree (`None` for a root).
fn walk_under<'t>(
    parent: Option<&'t Field>,
    node: Child<'t>,
    trail: &mut Vec<&'t str>,
    visit: &mut dyn FnMut(&[&'t str], &'t Field, &'static str),
) {
    let (name, field, kind) = match node {
        Child::Node(f) => (name_in(parent, f), f, f.value.kind_word()),
        // The level is not a node of the tree, and its occurrence is the entry
        // it belongs to: a group, as the level is.
        Child::HeaderLevel(entry) => (EXT_HEADER_LEVEL, entry, "nested"),
    };
    trail.push(name);
    visit(trail, field, kind);
    let mut kids = Vec::new();
    match node {
        Child::Node(f) => children(f, &mut |c| kids.push(c)),
        Child::HeaderLevel(entry) => header_fields(entry, &mut |h| kids.push(Child::Node(h))),
    }
    // The node a kid is named under is the one the view visits it from: a
    // message or entry, never the `extensions` container a kid is lifted out
    // of, which is not a carrier of a body.
    for kid in kids {
        walk_under(Some(field), kid, trail, visit);
    }
    trail.pop();
}

/// One node of the declared shape.
///
/// `kind` is the [`FieldValue::kind_word`] of the node. `words` is the closed
/// set a [`Label`](FieldValue::Label) node can carry, where the set is closed;
/// `None` for every other kind.
#[derive(Debug, Clone, Copy)]
pub struct SchemaNode {
    /// The normalised name ([`name_in`]).
    pub name: &'static str,
    /// The kind word of the node's value.
    pub kind: &'static str,
    /// The words a label node can carry.
    pub words: Option<fn() -> Vec<&'static str>>,
    /// What can stand under it, as the fragments it is assembled from: a
    /// message is its header fields, its key expression, its carrier's
    /// extensions and its bodies, each written once and shared.
    pub children: &'static [&'static [SchemaNode]],
}

/// One declared path, as [`declared_paths`] lists them.
#[derive(Debug, Clone)]
pub struct DeclaredPath {
    /// The segments, root first.
    pub segments: Vec<&'static str>,
    /// The kind word of the node it ends at.
    pub kind: &'static str,
    /// The closed word set of a label node.
    pub words: Option<fn() -> Vec<&'static str>>,
}

impl DeclaredPath {
    /// The path written as a selector writes it.
    pub fn dotted(&self) -> String {
        self.segments.join(".")
    }
}

/// Every path the declared shape holds, root first, depth first. A node two
/// parents can hold is listed once under each.
pub fn declared_paths() -> Vec<DeclaredPath> {
    let mut out = Vec::new();
    let mut trail = Vec::new();
    for root in roots() {
        walk_declared(root, &mut trail, &mut out);
    }
    out
}

fn walk_declared(
    node: &'static SchemaNode,
    trail: &mut Vec<&'static str>,
    out: &mut Vec<DeclaredPath>,
) {
    trail.push(node.name);
    out.push(DeclaredPath {
        segments: trail.clone(),
        kind: node.kind,
        words: node.words,
    });
    for child in node.children.iter().flat_map(|fragment| fragment.iter()) {
        walk_declared(child, trail, out);
    }
    trail.pop();
}

// ── The declared shape ───────────────────────────────────────────────────
//
// Transcribed from the walkers in `crate::dissect`, fragment by fragment, in
// the normalised view. Where a walker can produce a field only under a
// condition (a flag, a body that walks whole, a marker earlier in the chain)
// the field is declared without the condition: the shape says what CAN stand
// at a path, and a selector over a message that does not carry it reads the
// absence as the module's note says.

const U: &str = "uint";
const B: &str = "bits";
const F: &str = "flag";
const BY: &str = "bytes";
const Z: &str = "zid";
const T: &str = "text";
const O: &str = "opaque";

const fn leaf(name: &'static str, kind: &'static str) -> SchemaNode {
    SchemaNode {
        name,
        kind,
        words: None,
        children: &[],
    }
}

const fn label(name: &'static str, words: fn() -> Vec<&'static str>) -> SchemaNode {
    SchemaNode {
        name,
        kind: "label",
        words: Some(words),
        children: &[],
    }
}

const fn group(name: &'static str, children: &'static [&'static [SchemaNode]]) -> SchemaNode {
    SchemaNode {
        name,
        kind: "nested",
        words: None,
        children,
    }
}

/// Every name any carrier gives an extension: the `ext_name` label's words.
fn ext_name_words() -> Vec<&'static str> {
    let mut out: Vec<&'static str> = Vec::new();
    for carrier in crate::ext_name::ALL_CARRIERS {
        for header in 0..=u8::MAX {
            if let Some(name) = crate::ext_name::ext_name(*carrier, header) {
                if !out.contains(&name) {
                    out.push(name);
                }
            }
        }
    }
    out
}

/// The eight priority bands' names, by walking the wire values.
fn priority_words() -> Vec<&'static str> {
    (0..crate::qos::Priority::NUM as u8)
        .map(|b| crate::qos::Priority::from_wire(b).name())
        .collect()
}

/// The congestion controls' names, by walking the two flags.
fn congestion_words() -> Vec<&'static str> {
    let mut out: Vec<&'static str> = Vec::new();
    for (nodrop, first) in [(false, false), (true, false), (false, true), (true, true)] {
        let name = crate::qos::CongestionControl::from_flags(nodrop, first).name();
        if !out.contains(&name) {
            out.push(name);
        }
    }
    out
}

fn target_words() -> Vec<&'static str> {
    crate::dissect::TARGET_WORDS.to_vec()
}

fn sn_res_words() -> Vec<&'static str> {
    crate::dissect::SN_RES_WORDS.to_vec()
}

// The extension entry: its header fields, under the `ext` level for a named
// entry and directly for an unnamed one.
const EXT_HEAD: &[SchemaNode] = &[
    leaf("header", U),
    leaf("ext_id", B),
    leaf("m", F),
    leaf("encoding", B),
    leaf("z", F),
];
const EXT_LEVEL: &[SchemaNode] = &[group(
    EXT_HEADER_LEVEL,
    &[EXT_HEAD, &[label("ext_name", ext_name_words)]],
)];
/// The body of a carrier that fixes no encoding, named by the encoding the
/// wire chose ([`name_in`]).
const ANY_VALUE: &[SchemaNode] = &[leaf(Z64, U), leaf("value_len", U), leaf(ZBUF, BY)];
/// An entry whose carrier declares no name for its id: any encoding.
const UNNAMED: &[SchemaNode] = &[group("ext", &[EXT_HEAD, ANY_VALUE])];
const Z64_VALUE: &[SchemaNode] = &[leaf("value", U)];
const ZBUF_VALUE: &[SchemaNode] = &[leaf("value_len", U), leaf("value", BY)];

// Z64 readings.
const R_NETQOS: &[SchemaNode] = &[
    label("priority", priority_words),
    label("congestion", congestion_words),
    leaf("express", F),
    leaf("undefined_bits", B),
];
const R_TQOS: &[SchemaNode] = &[label("priority", priority_words), leaf("undefined_bits", B)];
const R_TARGET: &[SchemaNode] = &[label("target", target_words)];
const R_QINFO: &[SchemaNode] = &[
    leaf("complete", F),
    leaf("distance", B),
    leaf("undefined_bits", B),
];
const R_NARROW: &[SchemaNode] = &[
    leaf("read_as", B),
    leaf("undefined_bits", B),
    leaf("absent_to_receiver", F),
];

// Shared fragments.
const F_TIMESTAMP: &[SchemaNode] = &[leaf("time", U), leaf("zid_len", U), leaf("zid", Z)];
const F_ENCODING: &[SchemaNode] = &[
    leaf("packed_id", U),
    leaf("has_schema", F),
    leaf("id", B),
    leaf("schema_len", U),
    leaf("schema", T),
];
const F_WIREEXPR: &[SchemaNode] = &[
    leaf("id", U),
    leaf("mapping", B),
    leaf("suffix_len", U),
    leaf("suffix", T),
];
const KEYEXPR: &[SchemaNode] = &[group("keyexpr", &[F_WIREEXPR])];
const F_SLICES: &[SchemaNode] = &[group(
    "slice_entry",
    &[&[
        leaf("kind", U),
        leaf("len", U),
        leaf("shm_descriptor", O),
        leaf("bytes", BY),
    ]],
)];
const LOCATOR_ENTRY: &[SchemaNode] = &[group(
    "locator_entry",
    &[&[leaf("locator_len", U), leaf("locator", T)]],
)];
const LINKSTATE: &[SchemaNode] = &[group(
    "linkstate",
    &[&[
        leaf("num_link_states", U),
        group(
            "link_states",
            &[&[group(
                "linkstate_entry",
                &[&[
                    leaf("options", U),
                    leaf("psid", U),
                    leaf("sn", U),
                    leaf("zid_len", U),
                    leaf("zid", Z),
                    leaf("whatami", U),
                    leaf("num_locators", U),
                    group("locators", &[LOCATOR_ENTRY]),
                    leaf("links_len", U),
                    group("links", &[&[leaf("psid", U)]]),
                    group("weights", &[&[leaf("weight", U)]]),
                ]],
            )]],
        ),
    ]],
)];
const SN_RES_BATCH: &[SchemaNode] = &[
    leaf("sn_res", U),
    label("sn_res_frame_sn", sn_res_words),
    label("sn_res_request_id", sn_res_words),
    leaf("batch_size", U),
];

// Walked ZBuf bodies.
const W_ZID_PREFIXED: &[SchemaNode] = &[
    leaf("hdr", U),
    leaf("zid_len_m1", B),
    leaf("zid", Z),
    leaf("eid", U),
];
const W_SOURCE_INFO: &[SchemaNode] = &[leaf("sn", U)];
const W_QUERY_BODY: &[SchemaNode] = &[group("encoding", &[F_ENCODING]), leaf("payload", BY)];
/// The shape ANY ZBuf entry of a `Query` takes when it follows the
/// shared-memory marker.
const W_QUERY_SLICED: &[SchemaNode] = &[
    group("value_encoding", &[F_ENCODING]),
    leaf("slice_count", U),
    group("slices", &[F_SLICES]),
];
const W_WIRE_EXPR: &[SchemaNode] = &[
    leaf("hdr", U),
    leaf("mapping", B),
    leaf("n", F),
    leaf("id", U),
    leaf("suffix", T),
];
const W_JOIN_QOS: &[SchemaNode] = &[group(
    "priority_sn",
    &[&[
        label("priority", priority_words),
        leaf("next_sn_reliable", U),
        leaf("next_sn_best_effort", U),
    ]],
)];
const W_SHM_INIT: &[SchemaNode] = &[
    leaf("alice_segment", U),
    leaf("alice_challenge", U),
    leaf("bob_segment", U),
];
const W_PUBKEY: &[SchemaNode] = &[
    leaf("challenge_len", U),
    leaf("challenge", BY),
    leaf("pubkey_n_len", U),
    leaf("pubkey_n", BY),
    leaf("pubkey_e_len", U),
    leaf("pubkey_e", BY),
];
const W_USRPWD: &[SchemaNode] = &[
    leaf("user_len", U),
    leaf("user", BY),
    leaf("hmac_len", U),
    leaf("hmac", BY),
];
/// The `auth` extension's body: a chain of its own, keyed by method.
const W_AUTH: &[SchemaNode] = &[
    group("pubkey", &[EXT_LEVEL, ZBUF_VALUE, W_PUBKEY]),
    group("usrpwd", &[EXT_LEVEL, ANY_VALUE, W_USRPWD]),
    UNNAMED[0],
];

// Extension sets, per carrier.
const X_QOS_NET: SchemaNode = group("qos", &[EXT_LEVEL, Z64_VALUE, R_NETQOS]);
const X_QOS_T: SchemaNode = group("qos", &[EXT_LEVEL, Z64_VALUE, R_TQOS]);
const X_TIMESTAMP: SchemaNode = group("timestamp", &[EXT_LEVEL, ZBUF_VALUE, F_TIMESTAMP]);
const X_NODE_ID: SchemaNode = group("node_id", &[EXT_LEVEL, Z64_VALUE, R_NARROW]);
const X_SOURCE_INFO: SchemaNode = group(
    "source_info",
    &[EXT_LEVEL, ZBUF_VALUE, W_ZID_PREFIXED, W_SOURCE_INFO],
);
const X_RESPONDER_ID: SchemaNode = group("responder_id", &[EXT_LEVEL, ZBUF_VALUE, W_ZID_PREFIXED]);
const X_ATTACHMENT: SchemaNode = group("attachment", &[EXT_LEVEL, ZBUF_VALUE]);
const fn marker(name: &'static str) -> SchemaNode {
    group(name, &[EXT_LEVEL])
}

const EXTS_NET_COMMON: &[SchemaNode] = &[X_QOS_NET, X_TIMESTAMP, X_NODE_ID, UNNAMED[0]];
const EXTS_REQUEST: &[SchemaNode] = &[
    X_QOS_NET,
    X_TIMESTAMP,
    X_NODE_ID,
    group("target", &[EXT_LEVEL, Z64_VALUE, R_TARGET]),
    group("budget", &[EXT_LEVEL, Z64_VALUE, R_NARROW]),
    group("timeout", &[EXT_LEVEL, Z64_VALUE]),
    UNNAMED[0],
];
const EXTS_RESPONSE: &[SchemaNode] = &[X_QOS_NET, X_TIMESTAMP, X_RESPONDER_ID, UNNAMED[0]];
const EXTS_NET_OAM: &[SchemaNode] = &[X_QOS_NET, X_TIMESTAMP, UNNAMED[0]];
const EXTS_DECLARE_COMMON: &[SchemaNode] = &[
    group("wire_expr", &[EXT_LEVEL, ZBUF_VALUE, W_WIRE_EXPR]),
    UNNAMED[0],
];
const EXTS_DECLARE_QUERYABLE: &[SchemaNode] = &[
    group("queryable_info", &[EXT_LEVEL, Z64_VALUE, R_QINFO]),
    UNNAMED[0],
];
const EXTS_PUT: &[SchemaNode] = &[X_SOURCE_INFO, marker("shm"), X_ATTACHMENT, UNNAMED[0]];
const EXTS_DEL: &[SchemaNode] = &[X_SOURCE_INFO, X_ATTACHMENT, UNNAMED[0]];
const EXTS_QUERY: &[SchemaNode] = &[
    group(
        "source_info",
        &[
            EXT_LEVEL,
            ZBUF_VALUE,
            W_ZID_PREFIXED,
            W_SOURCE_INFO,
            W_QUERY_SLICED,
        ],
    ),
    group(
        "query_body",
        &[EXT_LEVEL, ZBUF_VALUE, W_QUERY_BODY, W_QUERY_SLICED],
    ),
    group("attachment", &[EXT_LEVEL, ZBUF_VALUE, W_QUERY_SLICED]),
    group("ext", &[EXT_HEAD, ANY_VALUE, W_QUERY_SLICED]),
];
const EXTS_ERR: &[SchemaNode] = &[X_SOURCE_INFO, marker("shm"), UNNAMED[0]];
const EXTS_INIT: &[SchemaNode] = &[
    marker("qos"),
    group("qos_link", &[EXT_LEVEL, Z64_VALUE]),
    group("shm", &[EXT_LEVEL, ZBUF_VALUE, W_SHM_INIT]),
    group("auth", &[EXT_LEVEL, ZBUF_VALUE, W_AUTH]),
    group("multi_link", &[EXT_LEVEL, ZBUF_VALUE, W_PUBKEY]),
    marker("low_latency"),
    marker("compression"),
    group("patch", &[EXT_LEVEL, Z64_VALUE, R_NARROW]),
    UNNAMED[0],
];
const EXTS_OPEN: &[SchemaNode] = &[
    marker("qos"),
    group("shm", &[EXT_LEVEL, Z64_VALUE]),
    group("auth", &[EXT_LEVEL, ZBUF_VALUE, W_AUTH]),
    group("multi_link_syn", &[EXT_LEVEL, ZBUF_VALUE, W_PUBKEY]),
    marker("multi_link_ack"),
    marker("low_latency"),
    marker("compression"),
    UNNAMED[0],
];
const EXTS_JOIN: &[SchemaNode] = &[
    group("qos", &[EXT_LEVEL, ZBUF_VALUE, W_JOIN_QOS]),
    group("shm", &[EXT_LEVEL, ZBUF_VALUE]),
    group("patch", &[EXT_LEVEL, Z64_VALUE, R_NARROW]),
    UNNAMED[0],
];
const EXTS_FRAME: &[SchemaNode] = &[X_QOS_T, UNNAMED[0]];
const EXTS_FRAGMENT: &[SchemaNode] = &[X_QOS_T, marker("first"), marker("drop"), UNNAMED[0]];
const EXTS_T_OAM: &[SchemaNode] = &[X_QOS_T, UNNAMED[0]];

// Zenoh-layer bodies.
const PUT: SchemaNode = group(
    "put",
    &[
        &[
            leaf("header", U),
            leaf("mid", B),
            leaf("t", F),
            leaf("e", F),
            leaf("z", F),
            group("timestamp", &[F_TIMESTAMP]),
            group("encoding", &[F_ENCODING]),
        ],
        EXTS_PUT,
        &[
            leaf("slice_count", U),
            group("slices", &[F_SLICES]),
            leaf("payload_len", U),
            leaf("payload", BY),
        ],
    ],
);
const DEL: SchemaNode = group(
    "del",
    &[
        &[
            leaf("header", U),
            leaf("mid", B),
            leaf("t", F),
            leaf("z", F),
            group("timestamp", &[F_TIMESTAMP]),
        ],
        EXTS_DEL,
    ],
);
const QUERY: SchemaNode = group(
    "query",
    &[
        &[
            leaf("header", U),
            leaf("mid", B),
            leaf("c", F),
            leaf("p", F),
            leaf("z", F),
            leaf("consolidation", U),
            leaf("parameters_len", U),
            leaf("parameters", BY),
        ],
        EXTS_QUERY,
    ],
);
const REPLY: SchemaNode = group(
    "reply",
    &[
        &[
            leaf("header", U),
            leaf("mid", B),
            leaf("c", F),
            leaf("z", F),
            leaf("consolidation", U),
        ],
        UNNAMED,
        &[PUT, DEL],
    ],
);
const ERR: SchemaNode = group(
    "err",
    &[
        &[
            leaf("header", U),
            leaf("mid", B),
            leaf("e", F),
            leaf("z", F),
            group("encoding", &[F_ENCODING]),
        ],
        EXTS_ERR,
        &[
            leaf("payload_len", U),
            leaf("payload", BY),
            leaf("shm_descriptor", O),
        ],
    ],
);

// Declare's bodies.
const DECL_HEAD: &[SchemaNode] = &[
    leaf("header", U),
    leaf("mid", B),
    leaf("n", F),
    leaf("m", F),
    leaf("z", F),
    leaf("id", U),
];
const UNDECL_HEAD: &[SchemaNode] = &[
    leaf("header", U),
    leaf("mid", B),
    leaf("z", F),
    leaf("id", U),
];
const DECLARE_BODIES: &[SchemaNode] = &[
    group("decl_kexpr", &[DECL_HEAD, KEYEXPR]),
    group("undecl_kexpr", &[UNDECL_HEAD]),
    group("decl_subscriber", &[DECL_HEAD, KEYEXPR]),
    group("undecl_subscriber", &[UNDECL_HEAD, EXTS_DECLARE_COMMON]),
    group(
        "decl_queryable",
        &[DECL_HEAD, KEYEXPR, EXTS_DECLARE_QUERYABLE],
    ),
    group("undecl_queryable", &[UNDECL_HEAD, EXTS_DECLARE_COMMON]),
    group("decl_token", &[DECL_HEAD, KEYEXPR]),
    group("undecl_token", &[UNDECL_HEAD, EXTS_DECLARE_COMMON]),
    group(
        "decl_final",
        &[&[leaf("header", U), leaf("mid", B), leaf("z", F)]],
    ),
];

// Network messages.
const NET_ROUTED_HEAD: &[SchemaNode] = &[
    leaf("header", U),
    leaf("mid", B),
    leaf("n", F),
    leaf("m", F),
    leaf("z", F),
];
/// The messages a `Frame`'s batch holds, and a lowlatency unit is.
pub const NETWORK_ROOTS: &[SchemaNode] = &[
    group(
        "Push",
        &[NET_ROUTED_HEAD, KEYEXPR, EXTS_NET_COMMON, &[PUT, DEL]],
    ),
    group(
        "Request",
        &[
            NET_ROUTED_HEAD,
            &[leaf("rid", U)],
            KEYEXPR,
            EXTS_REQUEST,
            &[PUT, DEL, QUERY],
        ],
    ),
    group(
        "Response",
        &[
            NET_ROUTED_HEAD,
            &[leaf("request_id", U)],
            KEYEXPR,
            EXTS_RESPONSE,
            &[ERR, REPLY],
        ],
    ),
    group(
        "ResponseFinal",
        &[
            &[
                leaf("header", U),
                leaf("mid", B),
                leaf("z", F),
                leaf("request_id", U),
            ],
            EXTS_RESPONSE,
        ],
    ),
    group(
        "Interest",
        &[
            &[
                leaf("header", U),
                leaf("mid", B),
                leaf("current", F),
                leaf("future", F),
                leaf("z", F),
                leaf("interest_id", U),
                group(
                    "body",
                    &[
                        &[
                            leaf("header", U),
                            leaf("keyexprs", F),
                            leaf("subscribers", F),
                            leaf("queryables", F),
                            leaf("tokens", F),
                            leaf("restricted", F),
                            leaf("n", F),
                        ],
                        KEYEXPR,
                    ],
                ),
            ],
            EXTS_NET_COMMON,
        ],
    ),
    group(
        "Declare",
        &[
            &[
                leaf("header", U),
                leaf("mid", B),
                leaf("i", F),
                leaf("z", F),
                leaf("interest_id", U),
            ],
            EXTS_NET_COMMON,
            DECLARE_BODIES,
        ],
    ),
    group(
        "Oam",
        &[
            &[
                leaf("header", U),
                leaf("mid", B),
                leaf("encoding", B),
                leaf("z", F),
                leaf("id", U),
            ],
            EXTS_NET_OAM,
            ANY_VALUE,
            LINKSTATE,
        ],
    ),
];

// Transport and scouting messages.
const T_HEAD: &[SchemaNode] = &[leaf("header", U), leaf("mid", B), leaf("z", F)];
const IDENTITY: &[SchemaNode] = &[
    leaf("version", U),
    leaf("cbyte", U),
    leaf("whatami", B),
    leaf("zid_len", B),
    leaf("zid", Z),
];
const TRANSPORT_ROOTS: &[SchemaNode] = &[
    group(
        "Oam",
        &[
            T_HEAD,
            &[
                leaf("encoding", B),
                leaf("id", U),
                leaf(Z64, U),
                leaf("value_len", U),
                leaf(ZBUF, BY),
                leaf("body", BY),
            ],
            EXTS_T_OAM,
        ],
    ),
    group(
        "Init",
        &[
            T_HEAD,
            &[leaf("a", F), leaf("s", F)],
            IDENTITY,
            SN_RES_BATCH,
            &[leaf("cookie_len", U), leaf("cookie", BY)],
            EXTS_INIT,
        ],
    ),
    group(
        "Open",
        &[
            T_HEAD,
            &[
                leaf("a", F),
                leaf("t", F),
                leaf("lease", U),
                leaf("initial_sn", U),
                leaf("cookie_len", U),
                leaf("cookie", BY),
            ],
            EXTS_OPEN,
        ],
    ),
    group(
        "Close",
        &[T_HEAD, &[leaf("s", F), leaf("reason", U)], UNNAMED],
    ),
    group("KeepAlive", &[T_HEAD, UNNAMED]),
    group(
        "Join",
        &[
            T_HEAD,
            &[leaf("t", F), leaf("s", F)],
            IDENTITY,
            SN_RES_BATCH,
            &[
                leaf("lease", U),
                leaf("next_sn_reliable", U),
                leaf("next_sn_best_effort", U),
            ],
            EXTS_JOIN,
        ],
    ),
    group(
        BATCH_CARRIER,
        &[
            T_HEAD,
            &[leaf("r", F), leaf("sn", U)],
            EXTS_FRAME,
            &[group(
                BATCH_LEVEL,
                &[NETWORK_ROOTS, &[leaf(BATCH_REMAINDER, BY)]],
            )],
        ],
    ),
    group(
        "Fragment",
        &[
            T_HEAD,
            &[
                leaf("r", F),
                leaf("m", F),
                leaf("sn", U),
                leaf("payload", BY),
            ],
            EXTS_FRAGMENT,
        ],
    ),
    // The walker's own word for a transport id it does not know: a literal,
    // not a `MessageName`.
    group("Unknown", &[T_HEAD, &[leaf("body", BY)], UNNAMED]),
];
const SCOUTING_ROOTS: &[SchemaNode] = &[
    group(
        "Scout",
        &[&[
            leaf("header", U),
            leaf("mid", B),
            leaf("version", U),
            leaf("cbyte", U),
            leaf("what", B),
            leaf("i", F),
            leaf("zid_len_m1", B),
            leaf("zid", Z),
        ]],
    ),
    group(
        "Hello",
        &[
            &[
                leaf("header", U),
                leaf("mid", B),
                leaf("l", F),
                leaf("version", U),
                leaf("cbyte", U),
                leaf("whatami", B),
                leaf("zid_len_m1", B),
                leaf("zid", Z),
                leaf("num_locators", U),
            ],
            LOCATOR_ENTRY,
        ],
    ),
];

/// Every message root, in three families: the network messages (a record's
/// tree), the transport messages (a framing unit's) and the scouting ones.
const ROOT_FAMILIES: &[&[SchemaNode]] = &[NETWORK_ROOTS, TRANSPORT_ROOTS, SCOUTING_ROOTS];

/// Whether `name` is the root of a scouting message: a tree no session row
/// holds, read off the scouting group's datagrams.
pub fn is_scouting_root(name: &str) -> bool {
    SCOUTING_ROOTS.iter().any(|root| root.name == name)
}

/// Every message root of the declared shape, network ones first.
pub fn roots() -> impl Iterator<Item = &'static SchemaNode> {
    ROOT_FAMILIES.iter().flat_map(|family| family.iter())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dissect::{
        dissect_batch, dissect_scouting_message, dissect_transport_message, Span,
    };
    use alloc::collections::{BTreeMap, BTreeSet};
    use alloc::string::ToString;

    use crate::wire_noise::{WireNoise, NETWORK_MIDS, SCOUTING_MIDS, TRANSPORT_MIDS};

    /// Every declared path with each kind it is declared at.
    fn declared_kinds() -> BTreeSet<(String, &'static str)> {
        declared_paths()
            .into_iter()
            .map(|d| (d.dotted(), d.kind))
            .collect()
    }

    /// Every root the three readers produce over `rounds` messages per id,
    /// built from the seeded source with each id's header bits all reached.
    fn walked_roots(rounds: usize) -> Vec<Field> {
        let mut source = WireNoise::default();
        let mut roots = Vec::new();
        for _ in 0..rounds {
            let flags = source.flags();
            for mid in TRANSPORT_MIDS {
                if let Ok(root) = dissect_transport_message(&source.message(mid | flags), 0) {
                    roots.push(root);
                }
            }
            for mid in SCOUTING_MIDS {
                if let Ok(Some(root)) = dissect_scouting_message(&source.message(mid | flags), 0) {
                    roots.push(root);
                }
            }
            for mid in NETWORK_MIDS {
                roots.extend(dissect_batch(&source.message(mid | flags), 0).records);
            }
        }
        roots
    }

    /// ONE PATH, ONE KIND. A path declared at two kinds is a field no
    /// comparison can be written against: the selector refuses every term over
    /// it as ambiguous, and a longer path cannot tell the two apart because
    /// there is none. So a body the wire writes in several encodings is named
    /// by the encoding ([`name_in`]), and every carrier whose shape is
    /// [`ANY_VALUE`] is one [`fixes_no_encoding`] reads that way.
    #[test]
    fn every_declared_path_has_one_kind() {
        let mut kinds: BTreeMap<String, BTreeSet<&'static str>> = BTreeMap::new();
        for d in declared_paths() {
            kinds.entry(d.dotted()).or_default().insert(d.kind);
        }
        let twice: Vec<(&String, &BTreeSet<&'static str>)> =
            kinds.iter().filter(|(_, k)| k.len() > 1).collect();
        assert!(
            twice.is_empty(),
            "paths declared at more than one kind: {twice:?}"
        );
        // And the named entries read by encoding are exactly those declared
        // with the any-encoding body.
        for name in SEVERAL_ENCODINGS {
            assert!(
                declared_paths()
                    .iter()
                    .any(|d| d.segments.ends_with(&[*name, Z64])
                        || d.segments.ends_with(&[*name, ZBUF])),
                "`{name}` is read by encoding and declares no `{Z64}` or `{ZBUF}`"
            );
        }
    }

    /// THE DECLARED SHAPE HOLDS EVERY PATH THE WALKERS PRODUCE, at the kind
    /// they produce it at.
    ///
    /// The messages are seeded noise over every message id with every header
    /// flag reached, and not a list of built messages: a list holds the shapes
    /// its author thought of, and the fault this guards against is a shape
    /// nobody thought of. A path a walker produces and the shape lacks is a
    /// field a selector would refuse while the tree shows it.
    #[test]
    fn every_walked_path_is_declared_at_its_kind() {
        let declared = declared_kinds();
        let mut missing: BTreeSet<(String, &'static str)> = BTreeSet::new();
        let mut seen: BTreeSet<String> = BTreeSet::new();
        for root in walked_roots(20_000) {
            for (path, kind) in paths_of(&root) {
                if !declared.contains(&(path.clone(), kind)) {
                    missing.insert((path.clone(), kind));
                }
                seen.insert(path);
            }
        }
        assert!(
            missing.is_empty(),
            "walked paths the declared shape does not hold: {missing:#?}"
        );
        // Not vacuous: the noise reaches deep into the trees, extensions and
        // the header level of a named one included.
        for deep in [
            "Frame.payload.Push.put.payload",
            "Push.qos.priority",
            "Push.qos.ext.ext_id",
            "Declare.decl_subscriber.keyexpr.id",
            "Init.zid",
        ] {
            assert!(seen.contains(deep), "the walk never reached {deep}");
        }
    }

    /// THE PATH A NODE IS GIVEN IS ONE THE SELECTOR READS AS THAT NODE, and a
    /// node is given none only where the normalised view names no node.
    ///
    /// Over the same seeded noise as the declaration test: for every node of
    /// every walked tree, a path handed out is declared (so the selector's
    /// parser accepts it) and [`matching`] over the root finds that very node
    /// at it (so the term reads the field the row showed). A node with no path
    /// is the `extensions` container or a walked body named like its entry,
    /// and nothing else.
    #[test]
    fn every_node_path_is_declared_and_reaches_its_node() {
        let declared = declared_kinds();
        let mut unnamed: BTreeSet<String> = BTreeSet::new();
        let mut named = 0usize;
        for root in walked_roots(5_000) {
            let paths = node_paths(&root);
            let mut stack: Vec<(&Field, Option<&Field>)> = alloc::vec![(&root, None)];
            while let Some((node, parent)) = stack.pop() {
                match paths.of(node) {
                    Some(path) => {
                        named += 1;
                        assert!(
                            declared.contains(&(path.to_string(), node.value.kind_word())),
                            "{path} ({}) is handed out and not declared",
                            node.value.kind_word()
                        );
                        let segments: Vec<&str> = path.split('.').collect();
                        assert!(
                            matching(&root, &segments)
                                .iter()
                                .any(|hit| core::ptr::eq(*hit, node)),
                            "{path} does not reach the node it was given to"
                        );
                    }
                    None => {
                        let collapsed = parent
                            .is_some_and(|p| p.name == "ext" && ext_label(p) == Some(&*node.name));
                        assert!(
                            node.name == "extensions" || collapsed,
                            "{} has no path and is neither the chain nor a collapsed body",
                            node.name
                        );
                        unnamed.insert(node.name.to_string());
                    }
                }
                if let FieldValue::Nested(children) = &node.value {
                    stack.extend(children.iter().map(|c| (c, Some(node))));
                }
            }
        }
        // Not vacuous: both unnamed shapes were met, and most nodes are named.
        assert!(unnamed.contains("extensions"), "{unnamed:?}");
        assert!(
            unnamed.len() >= 2,
            "no collapsed body was walked: {unnamed:?}"
        );
        assert!(named > 100_000, "{named}");
    }

    /// The published registry, one fact a line.
    const PUBLISHED: &str = include_str!("published_selector_paths.txt");

    fn published() -> Vec<&'static str> {
        PUBLISHED
            .lines()
            .filter(|l| !l.is_empty() && !l.starts_with('#'))
            .collect()
    }

    /// A path as the FIELD it names: a record's path with the `Frame` that
    /// carried it taken off, so `Frame.payload.Push.x` and `Push.x` are one
    /// fact, as they are one field.
    fn field_of(path: &str) -> &str {
        path.strip_prefix(BATCH_CARRIER)
            .and_then(|p| p.strip_prefix('.'))
            .and_then(|p| p.strip_prefix(BATCH_LEVEL))
            .and_then(|p| p.strip_prefix('.'))
            .unwrap_or(path)
    }

    /// Every fact the declared shape publishes now: each field at its kind,
    /// and each word of a closed label.
    fn facts_now() -> BTreeSet<String> {
        let mut out = BTreeSet::new();
        for d in declared_paths() {
            let dotted = d.dotted();
            let path = field_of(&dotted);
            out.insert(alloc::format!("{path}\t{}", d.kind));
            for word in d.words.map(|w| w()).unwrap_or_default() {
                out.insert(alloc::format!("{path}\t{}\t{word}", d.kind));
            }
        }
        out
    }

    /// A PATH ONCE PUBLISHED IS NEVER TAKEN BACK. Every fact of the registry
    /// holds of the shape under the path's current name, every fact of the
    /// shape is in the registry, each once, and every rename names a published
    /// node that is no longer declared and a node that is.
    #[test]
    fn every_published_fact_still_holds() {
        let now = facts_now();
        let published = published();
        let broken: Vec<&str> = published
            .iter()
            .copied()
            .filter(|line| {
                let (path, rest) = line.split_once('\t').unwrap_or((line, ""));
                let current = current_name_under(path, RENAMED);
                !now.contains(&alloc::format!("{}\t{rest}", field_of(&current)))
            })
            .collect();
        assert!(
            broken.is_empty(),
            "{} published facts no longer hold. A path that moved is declared in \
             RENAMED; a field whose kind changed takes a new name; a label keeps \
             every word it published:\n{}",
            broken.len(),
            broken.join("\n")
        );
        let registry: BTreeSet<&str> = published.iter().copied().collect();
        assert_eq!(registry.len(), published.len(), "a fact is published once");
        let missing: Vec<&String> = now
            .iter()
            .filter(|f| !registry.contains(f.as_str()))
            .collect();
        for fact in &missing {
            std::println!("PUBLISH\t{fact}");
        }
        assert!(
            missing.is_empty(),
            "{} facts are declared and not published: `python3 \
             scripts/lib/publish_selector_paths.py --append <this test's output>` \
             appends the lines printed after `PUBLISH\\t`",
            missing.len()
        );
        let declared: BTreeSet<String> =
            declared_paths().iter().map(DeclaredPath::dotted).collect();
        for r in RENAMED {
            assert!(
                registry
                    .iter()
                    .any(|l| l.split('\t').next() == Some(field_of(r.from))),
                "{} is renamed and was never published",
                r.from
            );
            assert!(
                declared.contains(r.to),
                "{} is renamed to an undeclared {}",
                r.from,
                r.to
            );
            assert!(
                !declared
                    .iter()
                    .any(|d| rename_one(d, r.from, r.from).is_some()),
                "{} was renamed away and is declared again: a former name names one \
                 field for good",
                r.from
            );
        }
    }

    /// A rename reaches every path under the node, and the record a `Frame`
    /// carries; former names run back through a chain of renames.
    #[test]
    fn a_rename_reaches_every_path_under_it_and_runs_back_through_a_chain() {
        let chain = [
            Renamed {
                from: "Push.put.old",
                to: "Push.put.middle",
                since_fields_revision: 60,
            },
            Renamed {
                from: "Push.put.middle",
                to: "Push.put.payload",
                since_fields_revision: 61,
            },
        ];
        assert_eq!(
            current_name_under("Push.put.old", &chain),
            "Push.put.payload"
        );
        assert_eq!(
            current_name_under("Push.put.old.x", &chain),
            "Push.put.payload.x"
        );
        assert_eq!(
            current_name_under("Frame.payload.Push.put.old", &chain),
            "Frame.payload.Push.put.payload"
        );
        assert_eq!(
            current_name_under("Push.put.older", &chain),
            "Push.put.older"
        );
        assert_eq!(
            former_names_under("Push.put.payload", &chain),
            alloc::vec![
                String::from("Push.put.middle"),
                String::from("Push.put.old")
            ]
        );
        assert_eq!(
            former_names_under("Frame.payload.Push.put.payload", &chain),
            alloc::vec![
                String::from("Frame.payload.Push.put.middle"),
                String::from("Frame.payload.Push.put.old")
            ]
        );
        assert!(former_names_under("Push.put.encoding", &chain).is_empty());
    }

    /// The rendered field object carries the path, and `null` where there is none.
    #[test]
    fn the_rendered_tree_carries_each_nodes_path() {
        let root = query_with_walked_body();
        let json = crate::dissect::to_json(&root);
        for path in [
            r#""selector_path":"query""#,
            r#""selector_path":"query.query_body""#,
            r#""selector_path":"query.query_body.ext.encoding""#,
            r#""selector_path":"query.query_body.encoding.packed_id""#,
        ] {
            assert!(json.contains(path), "{path} missing: {json}");
        }
        // The chain and the collapsed body, and nothing else.
        assert_eq!(json.matches(r#""selector_path":null"#).count(), 2, "{json}");
    }

    /// A walked tree's label carries a word of its declared set.
    #[test]
    fn every_walked_label_word_is_declared() {
        let declared = declared_paths();
        for root in walked_roots(5_000) {
            let mut trail: Vec<&str> = Vec::new();
            walk(Child::Node(&root), &mut trail, &mut |trail, field, _| {
                let FieldValue::Label(word) = &field.value else {
                    return;
                };
                let path = trail.join(".");
                let sets: Vec<Vec<&'static str>> = declared
                    .iter()
                    .filter(|d| d.dotted() == path)
                    .filter_map(|d| d.words.map(|w| w()))
                    .collect();
                assert!(
                    sets.iter().any(|s| s.contains(&&**word)),
                    "{path} carried {word:?}, outside its declared words {sets:?}"
                );
            });
        }
    }

    fn uint(name: &'static str, v: u64, at: usize) -> Field {
        Field {
            name: name.into(),
            span: Span {
                start: at,
                end: at + 1,
            },
            value: FieldValue::Uint(v),
        }
    }

    fn alias(name: &'static str, value: FieldValue, at: usize) -> Field {
        Field {
            name: name.into(),
            span: Span {
                start: at,
                end: at + 1,
            },
            value,
        }
    }

    fn nested(name: &'static str, children: Vec<Field>) -> Field {
        let start = children.first().map_or(0, |c| c.span.start);
        let end = children.last().map_or(0, |c| c.span.end);
        Field {
            name: name.into(),
            span: Span { start, end },
            value: FieldValue::Nested(children),
        }
    }

    /// A query whose `query_body` extension was walked: the entry's header
    /// byte and its readings, then the walked group carrying its own
    /// `encoding`.
    fn query_with_walked_body() -> Field {
        let entry = nested(
            "ext",
            alloc::vec![
                uint("header", 0x43, 1),
                alias("ext_id", FieldValue::Bits(3), 1),
                alias("encoding", FieldValue::Bits(2), 1),
                alias("ext_name", FieldValue::Label("query_body".into()), 1),
                uint("value_len", 3, 2),
                nested(
                    "query_body",
                    alloc::vec![nested("encoding", alloc::vec![uint("packed_id", 0, 3)])],
                ),
            ],
        );
        nested(
            "query",
            alloc::vec![
                uint("header", 0x83, 0),
                nested("extensions", alloc::vec![entry]),
            ],
        )
    }

    /// The view's three rules, on one tree: the chain is not a level, the
    /// entry is its name, its walked group is not a second level, and its
    /// header fields stand under `ext` so the body's `encoding` is the only
    /// one at `query_body.encoding`.
    #[test]
    fn a_named_entry_keeps_its_header_one_level_down() {
        let paths: Vec<String> = paths_of(&query_with_walked_body())
            .into_iter()
            .map(|(p, _)| p)
            .collect();
        assert_eq!(
            paths,
            [
                "query",
                "query.header",
                "query.query_body",
                "query.query_body.ext",
                "query.query_body.ext.header",
                "query.query_body.ext.ext_id",
                "query.query_body.ext.encoding",
                "query.query_body.ext.ext_name",
                "query.query_body.value_len",
                "query.query_body.encoding",
                "query.query_body.encoding.packed_id",
            ]
            .map(ToString::to_string)
        );
        let tree = query_with_walked_body();
        let hits = matching(&tree, &["query_body", "encoding"]);
        assert_eq!(hits.len(), 1);
        assert!(matches!(hits[0].value, FieldValue::Nested(_)));
        let header_level = matching(&tree, &["query_body", "ext", "encoding"]);
        assert_eq!(header_level.len(), 1);
        assert_eq!(header_level[0].value, FieldValue::Bits(2));
        // The level's own occurrence is the entry it belongs to.
        let level = matching(&tree, &["query_body", "ext"]);
        assert_eq!(level.len(), 1);
        assert_eq!(level[0].name, "ext");
    }
}
