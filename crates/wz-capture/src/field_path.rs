// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! THE TREE HALF OF THE SELECTOR: a term that names any field of a record's
//! dissection by its dotted path, and what it answers.
//!
//! # What a path names
//!
//! The dissection tree's own names, joined by `.`, in the normalised view
//! `wz_session_core::dissect_schema` defines: an extension is named by what
//! it is (`qos`, `source_info`, `attachment`), the extension chain is not a
//! level, and a walked extension body is not a second one. A path may be
//! written from the message (`Push.put.encoding.id`) or as any tail of one
//! (`encoding.id`, `qos.priority`); a tail names every field it ends.
//!
//! A path is resolved against the DECLARED shape when the selector is parsed,
//! so a typo is refused with the names nearest it rather than read as a field
//! that is never there. A tail that ends fields of more than one KIND (the
//! bare `encoding` ends `put.encoding`, a group, and the two-bit `encoding` of
//! every extension header) is refused as ambiguous and the longer tails that
//! tell them apart are offered, on the rule a `zid` prefix keeps: a selector
//! whose meaning is not settled judges nothing.
//!
//! A path once published is a name a consumer keeps, so a FORMER name still
//! resolves. A written path that ends no declared path is read through the
//! renames the shape declares (`dissect_schema::RENAMED`): it names the fields
//! one of whose former names it ends, spelled by the shortest tail of their
//! current name that names exactly them, so a saved selector keeps selecting
//! what it selected. A name the shape holds now always means the field it
//! names now, and the shape never declares a former name again.
//!
//! # What a path term answers
//!
//! * The record's tree could not be built (its bytes were not kept whole, or
//!   do not walk): UNKNOWN, as every other term answers over a fact the
//!   capture does not carry.
//! * The tree was built and holds no field on the path: that is a decided
//!   fact about a message read whole, so `p == v` is `no` and `p != v`, which
//!   is `not (p == v)`, is `yes`. A reader who means "present and different"
//!   writes `p and p != v`.
//! * The tree holds the path more than once: the term is `yes` when ANY of
//!   them satisfies it, as a display filter reads a repeated field.
//!
//! # Which tree a record is
//!
//! The record's transport message with the record in it: a record a `Frame`
//! carried is the `Frame` (its header, `sn`, extensions) with this record alone
//! under its `payload`, which is the tree the field document's row shows less
//! the row's other records. So `Frame.sn` and the transport `qos.priority` are
//! fields of every record the frame carried, and a path copied off a row's node
//! (its `selector_path`) names the same node in the record's tree. A record no transport
//! message stands around (a bare network message of a lowlatency session, a
//! record of a reassembled batch) is its message alone, and a path through a
//! `Frame` is the decided `no` there.
//!
//! The `Frame` is walked from the bytes the capture holds for it. Where it
//! holds none (a datagram whose packet the caller keeps, bytes trimmed past the
//! retention window), the record's own message is still read, and a path term
//! that could only be answered by the `Frame` around it is UNKNOWN rather than
//! `no`: the frame was there and was not read.
//!
//! `len(p)` is the WIRE width of the field in bytes. For a text field that is
//! its UTF-8 byte count, which is also what a display filter's `len` counts; a
//! reader who wants characters of a multi-byte text has no term for it here.
//! The two-bit and one-bit fields read out of a header byte and the labels
//! named from one have no width of their own and refuse `len`.

use alloc::string::String;
use alloc::vec::Vec;

use crate::filter::Op;
use crate::pattern::Pattern;

mod shape;
pub(crate) use shape::with_shape;

/// A node of a record's dissection tree, as a path term reads it.
///
/// Uninhabited in a build without `dissect`: such a build has no tree to hand
/// a record, and a selector holding a path is refused when it is parsed
/// (`PathRefusal::Unsupported`), so no term ever asks for one.
#[cfg(feature = "dissect")]
pub type TreeNode = wz_session_core::dissect::Field;

/// See the `dissect` build's definition.
#[cfg(not(feature = "dissect"))]
#[derive(Debug, Clone, PartialEq)]
pub enum TreeNode {}

/// A record's dissection as a path term reads it: the tree, what is known
/// about the transport message around the record (the module's note, "Which
/// tree a record is"), and the tree that stands BESIDE it, if one does.
///
/// A row can show more than the record a selector judges on it, and every
/// node a row shows is one a path term must be able to read there. Two rows
/// do: a record joined out of `Fragment`s is shown in the row of the
/// `Fragment` that completed it, whose bytes hold a piece of the record and
/// not the record; and a `ResponseFinal` an exchange paired answers its record
/// terms as the request it closes, while its row shows the close. The tree
/// beside is that `Fragment`, or that close, and a path is read in both: `yes`
/// where either holds a field that satisfies it, `no` where neither does, and
/// undecided otherwise.
#[derive(Debug, Clone, PartialEq)]
pub struct RecordTree {
    root: TreeNode,
    envelope: Envelope,
    beside: Option<alloc::boxed::Box<RecordTree>>,
}

/// What a [`RecordTree`] knows of the transport message its record was carried in.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Envelope {
    /// The root IS the transport message: a `Frame` holding this record alone
    /// under its `payload`, or a message that is its own row (an `Init`, a
    /// `KeepAlive`).
    Read,
    /// No transport message stands around the record: the root is the record,
    /// and a path through a `Frame` or a `Fragment` is absent from it, which is
    /// a decided fact.
    Absent,
    /// A `Frame` or a `Fragment` carried the record and its bytes were not read
    /// here: the root is the record, and a path through that message is
    /// undecided.
    Unread,
    /// The root is the transport message and the record is NOT in it: the
    /// part of its batch past where the walk stopped, which may hold a record
    /// no reader read. A path through the message is read there; a path into a
    /// record is undecided.
    Remainder,
}

impl RecordTree {
    /// A tree whose root is a transport message read whole.
    pub fn transport(root: TreeNode) -> Self {
        Self::with(root, Envelope::Read)
    }

    /// A tree whose root is a record no transport message stands around.
    pub fn message(root: TreeNode) -> Self {
        Self::with(root, Envelope::Absent)
    }

    fn with(root: TreeNode, envelope: Envelope) -> Self {
        Self {
            root,
            envelope,
            beside: None,
        }
    }

    /// This tree with `other` beside it, after any tree already there: the
    /// tree of what else the record's row shows.
    pub fn beside(self, other: RecordTree) -> Self {
        Self {
            root: self.root,
            envelope: self.envelope,
            beside: Some(alloc::boxed::Box::new(match self.beside {
                Some(first) => first.beside(other),
                None => other,
            })),
        }
    }

    /// The tree.
    pub fn root(&self) -> &TreeNode {
        &self.root
    }

    /// What it knows of the transport message around the record.
    pub fn envelope(&self) -> Envelope {
        self.envelope
    }

    /// The tree beside it, if one stands there.
    pub fn beside_tree(&self) -> Option<&RecordTree> {
        self.beside.as_deref()
    }
}

/// What a path's field holds, as `wz_session_core::dissect::FieldValue::kind_word`
/// names it.
///
/// A build without `dissect` declares no path, so it never makes a kind: the
/// parser's arms over the kinds are still compiled, for the one grammar both
/// builds share, and the type is allowed to go unconstructed there.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(not(feature = "dissect"), allow(dead_code))]
pub(crate) enum PathKind {
    Bits,
    Flag,
    Uint,
    Bytes,
    Zid,
    Text,
    Opaque,
    Label,
    Nested,
}

impl PathKind {
    #[cfg_attr(not(feature = "dissect"), allow(dead_code))]
    fn of_word(word: &str) -> Option<Self> {
        Some(match word {
            "bits" => Self::Bits,
            "flag" => Self::Flag,
            "uint" => Self::Uint,
            "bytes" => Self::Bytes,
            "zid" => Self::Zid,
            "text" => Self::Text,
            "opaque" => Self::Opaque,
            "label" => Self::Label,
            "nested" => Self::Nested,
            _ => return None,
        })
    }

    /// The kind word, as the field list and a refusal print it.
    pub(crate) const fn word(self) -> &'static str {
        match self {
            Self::Bits => "bits",
            Self::Flag => "flag",
            Self::Uint => "uint",
            Self::Bytes => "bytes",
            Self::Zid => "zid",
            Self::Text => "text",
            Self::Opaque => "opaque",
            Self::Label => "label",
            Self::Nested => "nested",
        }
    }

    /// The operators a term over this kind admits, as the field list prints
    /// them. Presence (the path alone) and `len()` are not operators and are
    /// stated by [`Self::has_width`] and by the list's own note.
    pub(crate) fn operators(self) -> &'static [&'static str] {
        match self {
            Self::Bits | Self::Uint => &["==", "!=", "<", "<=", ">", ">=", "in"],
            Self::Flag | Self::Zid => &["==", "!=", "in"],
            Self::Label | Self::Text | Self::Bytes => &["==", "!=", "in", "contains", "matches"],
            Self::Opaque | Self::Nested => &[],
        }
    }

    /// Whether `len()` reads this kind: every kind that owns its bytes. A bit
    /// field, a flag and a label alias the byte another field owns.
    pub(crate) const fn has_width(self) -> bool {
        !matches!(self, Self::Bits | Self::Flag | Self::Label)
    }
}

/// A path the selector named, resolved against the declared shape.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct FieldPath {
    /// The segments as written.
    segments: Vec<String>,
    /// The kind every declared field on the path has.
    kind: PathKind,
    /// The words a label path can carry, when every field on it has a closed
    /// set: the union of them. `None` for every other kind.
    words: Option<Vec<&'static str>>,
    /// Whether a field it names can stand in the `Frame` around a record and
    /// not in the record: what makes it undecided over a record whose frame
    /// was not read ([`Envelope::Unread`]).
    #[cfg_attr(not(feature = "dissect"), allow(dead_code))]
    reads_envelope: bool,
    /// Whether a field it names can stand in a record a batch carries: what
    /// makes it undecided over the unread part of a batch
    /// ([`Envelope::Remainder`]).
    #[cfg_attr(not(feature = "dissect"), allow(dead_code))]
    reads_record: bool,
}

/// Why a written path names no field.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum PathRefusal {
    /// The build walks no tree (`dissect` is off).
    Unsupported,
    /// No declared path ends with it.
    Unknown,
    /// It ends declared fields of more than one kind; the longer tails that
    /// tell them apart, each with its kind word.
    Ambiguous(Vec<(String, &'static str)>),
}

impl FieldPath {
    /// The path as written, segments joined by `.`.
    pub(crate) fn written(&self) -> String {
        self.segments.join(".")
    }

    pub(crate) fn kind(&self) -> PathKind {
        self.kind
    }

    pub(crate) fn words(&self) -> Option<&[&'static str]> {
        self.words.as_deref()
    }

    /// Resolve `written` against the declared shape.
    pub(crate) fn resolve(written: &str) -> Result<Self, PathRefusal> {
        // A build with no tree refuses what is plainly a path as a path, and a
        // single word as the unknown field it most likely is: a typo of a fixed
        // field must not be answered with "this build walks no tree".
        if !cfg!(feature = "dissect") {
            return Err(if written.contains('.') {
                PathRefusal::Unsupported
            } else {
                PathRefusal::Unknown
            });
        }
        let written: Vec<&str> = written.split('.').collect();
        if written.iter().any(|s| s.is_empty()) {
            return Err(PathRefusal::Unknown);
        }
        with_shape(|shape| Self::resolve_in(shape, written))
    }

    /// [`Self::resolve`] of the segments `written` over `shape`.
    fn resolve_in(shape: &shape::Shape, written: Vec<&str>) -> Result<Self, PathRefusal> {
        let current: Vec<&Declared> = shape.ending_with(&written).collect();
        // A name the shape holds now means the field it names now; a former
        // name, only where no current one is spelled alike.
        let (segments, ends) = if current.is_empty() {
            formerly(&written, shape.paths())?
        } else {
            (written, current)
        };
        let first = ends[0];
        if ends.iter().any(|d| d.kind != first.kind) {
            return Err(PathRefusal::Ambiguous(longer_tails(&ends, segments.len())));
        }
        let words = (first.kind == PathKind::Label)
            .then(|| {
                let mut union: Vec<&'static str> = Vec::new();
                for d in &ends {
                    for w in d.words.as_ref()? {
                        if !union.contains(w) {
                            union.push(w);
                        }
                    }
                }
                Some(union)
            })
            .flatten();
        let reads_envelope = ends
            .iter()
            .any(|d| stands_in_the_envelope(&d.segments, segments.len()));
        let reads_record = ends
            .iter()
            .any(|d| stands_in_a_record(&d.segments, segments.len()));
        Ok(Self {
            segments: segments.into_iter().map(String::from).collect(),
            kind: first.kind,
            words,
            reads_envelope,
            reads_record,
        })
    }

    /// The fields of `tree` this path names, in wire order.
    #[cfg(feature = "dissect")]
    fn occurrences<'t>(&self, tree: &'t TreeNode) -> Vec<&'t TreeNode> {
        let segments: Vec<&str> = self.segments.iter().map(String::as_str).collect();
        wz_session_core::dissect_schema::matching(tree, &segments)
    }
}

/// A written path that ends no declared path, read as a FORMER name under the
/// renames the shape declares (`dissect_schema::RENAMED`). A build without
/// `dissect` declares no path and so no former one.
fn formerly<'d>(
    written: &[&str],
    declared: &'d [Declared],
) -> Result<(Vec<&'static str>, Vec<&'d Declared>), PathRefusal> {
    #[cfg(feature = "dissect")]
    {
        formerly_under(written, declared, wz_session_core::dissect_schema::RENAMED)
    }
    #[cfg(not(feature = "dissect"))]
    {
        let _ = (written, declared);
        Err(PathRefusal::Unknown)
    }
}

/// [`formerly`] under `renames`: the declared paths one of whose former names
/// `written` ends, and the tail of their CURRENT name to read them by.
///
/// The tail is the shortest that every one of them ends and that ends no other
/// declared path, so the term reads exactly the fields the former name named,
/// spelled as a selector written today would spell them. Where no such tail
/// exists (a former name that named fields now spelled apart), the written
/// path is refused with each field's current name, as an ambiguous tail is.
#[cfg(feature = "dissect")]
pub(crate) fn formerly_under<'d>(
    written: &[&str],
    declared: &'d [Declared],
    renames: &[wz_session_core::dissect_schema::Renamed],
) -> Result<(Vec<&'static str>, Vec<&'d Declared>), PathRefusal> {
    let images: Vec<&Declared> = declared
        .iter()
        .filter(|d| {
            wz_session_core::dissect_schema::former_names_under(&d.segments.join("."), renames)
                .iter()
                .any(|former| former.split('.').collect::<Vec<_>>().ends_with(written))
        })
        .collect();
    let Some(first) = images.first() else {
        return Err(PathRefusal::Unknown);
    };
    let shortest = images.iter().map(|d| d.segments.len()).min().unwrap_or(0);
    for width in 1..=shortest {
        let tail = &first.segments[first.segments.len() - width..];
        if !images.iter().all(|d| d.segments.ends_with(tail)) {
            continue;
        }
        let named = declared.iter().filter(|d| d.segments.ends_with(tail));
        if named.clone().count() == images.len()
            && named
                .into_iter()
                .all(|d| images.iter().any(|i| core::ptr::eq(*i, d)))
        {
            return Ok((tail.to_vec(), images));
        }
    }
    Err(PathRefusal::Ambiguous(
        images
            .iter()
            .map(|d| (d.segments.join("."), d.kind.word()))
            .collect(),
    ))
}

/// Whether the declared path `declared`, matched by a written path of `width`
/// segments (a tail of it), reaches a node of a transport message around a
/// record and not in the record: any node of a `Fragment`, and of the batch
/// carrier the carrier itself, its header, `sn` and extensions, or its
/// `payload` level, outside the record that level holds.
fn stands_in_the_envelope(declared: &[&str], width: usize) -> bool {
    #[cfg(feature = "dissect")]
    {
        use wz_session_core::dissect_schema::{BATCH_CARRIER, BATCH_LEVEL, PIECE_CARRIER};
        if declared.first() == Some(&PIECE_CARRIER) {
            return true;
        }
        if declared.first() != Some(&BATCH_CARRIER) {
            return false;
        }
        // A match beginning at the record (index 2, under `Frame.payload`) or
        // deeper reads the record alone.
        let begins = declared.len().saturating_sub(width);
        !(declared.get(1) == Some(&BATCH_LEVEL) && begins >= 2)
    }
    #[cfg(not(feature = "dissect"))]
    {
        let _ = (declared, width);
        false
    }
}

/// Whether the declared path `declared`, matched by a written path of `width`
/// segments, reaches a node of a record a batch carries. Every network message
/// is declared under the batch carrier's `payload` too, so this is a match that
/// begins at a record standing there (index 2) or deeper.
fn stands_in_a_record(declared: &[&str], width: usize) -> bool {
    #[cfg(feature = "dissect")]
    {
        use wz_session_core::dissect_schema::{BATCH_CARRIER, BATCH_LEVEL};
        declared.first() == Some(&BATCH_CARRIER)
            && declared.get(1) == Some(&BATCH_LEVEL)
            && declared.len().saturating_sub(width) >= 2
    }
    #[cfg(not(feature = "dissect"))]
    {
        let _ = (declared, width);
        false
    }
}

/// Why [`naming_tail`] has no tail to give.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum TailRefusal {
    /// The path is not one the declared shape holds (in a build without
    /// `dissect`, no path is).
    Undeclared,
    /// A segment holds a character a selector word cannot.
    Unspellable,
}

/// The tail a sentence writes for the field the declared path `path` names: the
/// shortest that names that field and no other field of the declared shape.
///
/// A record carried in a `Frame` stands at `Frame.payload.<message>`, and the
/// same message read alone stands at `<message>`: those two are ONE field, the
/// record's, and a tail naming both names only it. Any other declared path the
/// tail ends is another field, and the tail grows by a segment until none is
/// left. So `Frame.sn` stays `Frame.sn` (`sn` also ends `Fragment.sn`), and
/// `Frame.payload.Push.put.encoding.id` becomes `put.encoding.id` unless
/// another message holds that tail. The full path is always a candidate, so a
/// declared path always has a tail.
///
/// A one-segment tail the fixed table holds (`is_fixed`) is passed over: that
/// word is read as the fixed field and not as this path.
pub(crate) fn naming_tail(
    path: &str,
    is_fixed: &dyn Fn(&str) -> bool,
) -> Result<String, TailRefusal> {
    let segments: Vec<&str> = path.split('.').collect();
    if segments
        .iter()
        .any(|s| s.is_empty() || !s.chars().all(crate::filter::is_word_char))
    {
        return Err(TailRefusal::Unspellable);
    }
    with_shape(|shape| {
        if !shape.holds(&segments) {
            return Err(TailRefusal::Undeclared);
        }
        let field = record_field(&segments);
        for width in 1..=segments.len() {
            let tail = &segments[segments.len() - width..];
            if width == 1 && (is_fixed(tail[0]) || crate::filter::is_keyword(tail[0])) {
                continue;
            }
            if shape
                .ending_with(tail)
                .all(|d| record_field(&d.segments) == field)
            {
                return Ok(tail.join("."));
            }
        }
        // The full path names itself and its `Frame.payload` copy, which are
        // one field, so the loop returns at the latest at its last width.
        Err(TailRefusal::Undeclared)
    })
}

/// A declared path as the field it names: a record's path with the `Frame`
/// that carried it taken off, so `Frame.payload.Push...` and `Push...` compare
/// equal. Every other path is itself.
fn record_field<'s>(segments: &'s [&'s str]) -> &'s [&'s str] {
    #[cfg(feature = "dissect")]
    {
        use wz_session_core::dissect_schema::{BATCH_CARRIER, BATCH_LEVEL};
        if segments.len() > 2 && segments[0] == BATCH_CARRIER && segments[1] == BATCH_LEVEL {
            return &segments[2..];
        }
    }
    segments
}

/// For an ambiguous tail of `width` segments: each declared field's tail one
/// segment longer, distinct, with its kind, in the order the shape lists them.
fn longer_tails(ends: &[&Declared], width: usize) -> Vec<(String, &'static str)> {
    let mut out: Vec<(String, &'static str)> = Vec::new();
    for d in ends {
        let from = d.segments.len().saturating_sub(width + 1);
        let tail = d.segments[from..].join(".");
        if !out.iter().any(|(t, _)| *t == tail) {
            out.push((tail, d.kind.word()));
        }
    }
    out
}

/// What a path term asks of each field it names.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum PathTest {
    /// The path alone: is there such a field.
    Present,
    /// A comparison of an integer field.
    Int { op: Op, value: u64 },
    /// A flag equal to this.
    Flag(bool),
    /// A label or a text equal to this.
    Word(String),
    /// A byte field equal to these bytes.
    Bytes(Vec<u8>),
    /// A zid field naming this zid (canonical bytes).
    Zid(Vec<u8>),
    /// A label, text or byte field holding this run of bytes.
    Contains(Vec<u8>),
    /// A label, text or byte field the pattern is found in.
    Matches(Pattern),
    /// The field's wire width compared with an integer.
    Len { op: Op, value: u64 },
}

/// Judge one path term over one record's tree, and over the tree beside it.
///
/// Over one tree: `Some(true)` when any field on the path satisfies the test.
/// `Some(false)` when none does or there is none, unless the path can stand in
/// a transport message the tree did not read ([`Envelope::Unread`]) or in a
/// record it did not read ([`Envelope::Remainder`]): then `None`, because the
/// field the term asks about may be in the bytes that were not read. With a
/// tree beside, the two answers are joined by the selector's three-valued `or`.
/// The tree being absent is the caller's `Unknown` and never reaches here.
pub(crate) fn judge(tree: &RecordTree, path: &FieldPath, test: &PathTest) -> Option<bool> {
    #[cfg(feature = "dissect")]
    {
        let own = if path
            .occurrences(&tree.root)
            .into_iter()
            .any(|field| satisfies(field, test))
        {
            Some(true)
        } else {
            match tree.envelope {
                Envelope::Unread if path.reads_envelope => None,
                Envelope::Remainder if path.reads_record => None,
                _ => Some(false),
            }
        };
        match (own, tree.beside_tree()) {
            (Some(true), _) | (_, None) => own,
            (_, Some(beside)) => match (own, judge(beside, path, test)) {
                (_, Some(true)) => Some(true),
                (Some(false), Some(false)) => Some(false),
                _ => None,
            },
        }
    }
    #[cfg(not(feature = "dissect"))]
    {
        let _ = (path, test);
        match tree.root {}
    }
}

#[cfg(feature = "dissect")]
fn satisfies(field: &TreeNode, test: &PathTest) -> bool {
    use wz_session_core::dissect::FieldValue as V;
    match (test, &field.value) {
        (PathTest::Present, _) => true,
        (PathTest::Int { op, value }, V::Uint(v) | V::Bits(v)) => op.apply(*v, *value),
        (PathTest::Flag(want), V::Flag(v)) => v == want,
        (PathTest::Word(want), V::Label(v)) => **v == **want,
        (PathTest::Word(want), V::Text(v)) => v == want,
        (PathTest::Bytes(want), V::Bytes(v)) => v == want,
        // Canonical on both sides, as the `zid` term compares: a zid padded
        // with trailing zero bytes prints, and so names, the same node.
        (PathTest::Zid(want), V::Zid(v)) => {
            wz_session_core::zid_hex::canonical_zid(v) == want.as_slice()
        }
        (PathTest::Contains(needle), v) => {
            text_or_bytes(v).is_some_and(|hay| crate::filter::contains_bytes(hay, needle))
        }
        (PathTest::Matches(pattern), v) => {
            text_or_bytes(v).is_some_and(|hay| pattern.is_match(hay))
        }
        (PathTest::Len { op, value }, _) => op.apply(field.span.len() as u64, *value),
        // A field the declared shape gives one kind and the walk another. The
        // shape's tests hold the two together; a disagreement is a field the
        // term was not written for, and it does not satisfy it.
        _ => false,
    }
}

#[cfg(feature = "dissect")]
fn text_or_bytes(value: &wz_session_core::dissect::FieldValue) -> Option<&[u8]> {
    use wz_session_core::dissect::FieldValue as V;
    match value {
        V::Text(t) => Some(t.as_bytes()),
        V::Label(l) => Some(l.as_bytes()),
        V::Bytes(b) => Some(b),
        _ => None,
    }
}

/// The transport message a frame's records were carried in, walked once for
/// all of them: what [`record_tree`] puts around each record.
///
/// A build without `dissect` walks nothing and makes only [`Self::Absent`].
#[derive(Debug, Clone)]
#[cfg_attr(not(feature = "dissect"), allow(dead_code))]
pub(crate) enum FrameEnvelope {
    /// The frame's `Frame` message, walked from the bytes the capture holds
    /// for it: its root with every field but the `payload` group's records,
    /// and those records apart, each with its span.
    Walked {
        /// The `Frame` root with its `payload` group EMPTY.
        shell: TreeNode,
        /// Index of the `payload` group among the root's children; `None` for
        /// a `Frame` whose bytes end before any payload, in which no record
        /// stands.
        payload: Option<usize>,
        /// The records the walk read under `payload`, in wire order.
        records: Vec<TreeNode>,
    },
    /// The frame's records were joined out of `Fragment`s, and this is the
    /// one the frame read, walked from the bytes the capture holds for it: it
    /// stands beside each record ([`RecordTree::beside`]).
    Joined {
        /// The `Fragment` root, whole.
        carrier: TreeNode,
    },
    /// No transport message stands around the frame's records.
    Absent,
    /// A `Frame` or a `Fragment` carried the records and its bytes are not
    /// held here, or do not walk.
    Unread,
}

impl FrameEnvelope {
    /// The envelope of `frame`'s records, from `message`: the bytes the capture
    /// holds for the transport message `frame` was read from, or `None` where
    /// it holds none.
    pub(crate) fn of(
        frame: &wz_session_core::passive::PassiveFrame,
        message: Option<&[u8]>,
    ) -> Self {
        #[cfg(feature = "dissect")]
        {
            use wz_session_core::dissect::FieldValue;
            use wz_session_core::dissect_schema::{BATCH_CARRIER, BATCH_LEVEL, PIECE_CARRIER};
            let Some(carrier) = records_carrier(frame) else {
                return Self::Absent;
            };
            let walked = message.and_then(|bytes| {
                wz_session_core::dissect::dissect_transport_message(bytes, 0).ok()
            });
            if carrier == Carrier::Pieces {
                return match walked.filter(|root| root.name == PIECE_CARRIER) {
                    Some(carrier) => Self::Joined { carrier },
                    None => Self::Unread,
                };
            }
            let Some(mut root) = walked.filter(|root| root.name == BATCH_CARRIER) else {
                return Self::Unread;
            };
            let FieldValue::Nested(children) = &mut root.value else {
                return Self::Unread;
            };
            let payload = children.iter().position(|c| c.name == BATCH_LEVEL);
            let records = match payload.map(|at| &mut children[at].value) {
                Some(FieldValue::Nested(records)) => core::mem::take(records),
                Some(_) => return Self::Unread,
                None => Vec::new(),
            };
            Self::Walked {
                shell: root,
                payload,
                records,
            }
        }
        #[cfg(not(feature = "dissect"))]
        {
            let _ = (frame, message);
            Self::Absent
        }
    }
}

/// The tree of a frame whose batch holds no record and was read to its end (a
/// `Frame` of extensions alone, an empty `Fragment` body): its transport
/// message, which is then a row that carries no record. `None` where no
/// transport message was read around the batch.
#[cfg(all(feature = "dissect", feature = "network-codecs"))]
pub(crate) fn empty_batch_tree(envelope: &FrameEnvelope) -> Option<RecordTree> {
    match envelope {
        FrameEnvelope::Walked { shell, .. } => Some(RecordTree::transport(shell.clone())),
        FrameEnvelope::Joined { carrier } => Some(RecordTree::transport(carrier.clone())),
        FrameEnvelope::Absent | FrameEnvelope::Unread => None,
    }
}

/// Whether part of a batch was not read: the session's walk stopped
/// ([`wz_session_core::network_message::BatchParse::halt`]), or the field
/// walker's did, which the row then shows as an `unparsed` remainder under the
/// `Frame` `envelope` holds. The two readers can stop at different bytes; a row
/// either of them could not read to its end holds bytes no reader named.
#[cfg(all(feature = "dissect", feature = "network-codecs"))]
pub(crate) fn has_an_unread_remainder(
    envelope: Option<&FrameEnvelope>,
    batch: &wz_session_core::network_message::BatchParse,
) -> bool {
    batch.halt.is_some()
        || matches!(envelope, Some(FrameEnvelope::Walked { records, .. })
            if records.iter().any(|r| r.name == wz_session_core::dissect_schema::BATCH_REMAINDER))
}

/// The tree the part of `frame`'s batch past where its walk stopped is read
/// over, inside `envelope`, the envelope of the batch's records; `None` where
/// nothing of it can be read.
///
/// * Inside a `Frame` or beside a `Fragment`: the transport message the frame
///   read, holding under a `Frame`'s `payload` what the field walker read of
///   the part the session did not (the records it walked from where the
///   session stopped, and the `unparsed` remainder where it stopped too), and
///   nothing the session read ([`Envelope::Remainder`]). The row shows those
///   records; a record term over the part is still undecided, since the
///   session's codec read no record there.
/// * A lowlatency unit IS its network message, and the part past the stop is
///   read by the field walker as the field document reads it: the record the
///   walker names there (`Unknown` for a MID it does not know), with no
///   transport message around it.
///
/// Built where its two readers are, the row plane and the soundness oracle.
#[cfg(all(feature = "dissect", feature = "network-codecs"))]
pub(crate) fn remainder_tree(
    frame: &wz_session_core::passive::PassiveFrame,
    envelope: &FrameEnvelope,
    batch: &wz_session_core::network_message::BatchParse,
) -> Option<RecordTree> {
    use wz_session_core::dissect::FieldValue;
    use wz_session_core::inbound::InboundFrame;
    if !has_an_unread_remainder(Some(envelope), batch) {
        return None;
    }
    let root = match envelope {
        FrameEnvelope::Walked {
            shell,
            payload,
            records,
        } => {
            let mut root = shell.clone();
            if let (Some(payload), FieldValue::Nested(children)) = (payload, &mut root.value) {
                // Where the session stopped, as a byte of the walked tree.
                let stopped = batch
                    .halt
                    .as_ref()
                    .and_then(|h| children[*payload].span.start.checked_add(h.offset()));
                children[*payload].value = FieldValue::Nested(
                    records
                        .iter()
                        .filter(|r| {
                            r.name == wz_session_core::dissect_schema::BATCH_REMAINDER
                                || stopped.is_some_and(|at| r.span.start >= at)
                        })
                        .cloned()
                        .collect(),
                );
            }
            root
        }
        FrameEnvelope::Joined { carrier } => carrier.clone(),
        FrameEnvelope::Unread => return None,
        FrameEnvelope::Absent => {
            let Ok(InboundFrame::Network { payload }) = &frame.frame else {
                return None;
            };
            let start = payload.len().checked_sub(batch.unparsed_bytes)?;
            let root = wz_session_core::dissect::dissect_network_message(&payload[start..], start)
                .ok()
                .flatten()?;
            return Some(RecordTree::message(root));
        }
    };
    Some(RecordTree::with(root, Envelope::Remainder))
}

/// Where one record of a batch stands, for a plane that judges it: its span
/// in the batch, and the transport message around it where the plane's
/// selector reads a tree.
#[derive(Debug, Clone, Copy)]
pub(crate) struct RecordAt<'e> {
    /// `(offset, len)` of the record within the batch, as `BatchParse` gives it.
    pub(crate) span: Option<(usize, usize)>,
    /// `None` where the selector names no path ([`crate::filter::Filter::reads_tree`]).
    envelope: Option<&'e FrameEnvelope>,
}

impl<'e> RecordAt<'e> {
    /// The record at `span`, inside `envelope` (`None` for a selector that
    /// reads no tree).
    pub(crate) fn new(span: Option<(usize, usize)>, envelope: Option<&'e FrameEnvelope>) -> Self {
        Self { span, envelope }
    }

    /// The record's tree, or `None` where the selector reads none or the
    /// record does not walk ([`record_tree`]).
    pub(crate) fn tree(
        &self,
        frame: &wz_session_core::passive::PassiveFrame,
    ) -> Option<RecordTree> {
        record_tree(frame, self.envelope?, self.span)
    }
}

/// The transport message a frame's records have as their envelope.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(not(feature = "dissect"), allow(dead_code))]
pub(crate) enum Carrier {
    /// A `Frame`, whose batch holds the records.
    Batch,
    /// A `Fragment`, the last of those the records were joined out of.
    Pieces,
}

/// The transport message `frame`'s records were carried in, where they have
/// one [`FrameEnvelope`] reads: a batch out of a `Frame`, or a batch joined
/// out of `Fragment`s. `None` for a frame that carried no batch, and for a
/// lowlatency unit, which IS its network message.
pub(crate) fn records_carrier(frame: &wz_session_core::passive::PassiveFrame) -> Option<Carrier> {
    #[cfg(feature = "dissect")]
    {
        use wz_session_core::inbound::InboundFrame;
        use wz_session_core::passive::Carried;
        match (&frame.carried, &frame.frame) {
            (Carried::Batch(_), Ok(InboundFrame::Frame { .. })) => Some(Carrier::Batch),
            #[cfg(feature = "reassembly")]
            (Carried::Reassembled { .. }, _) => Some(Carrier::Pieces),
            _ => None,
        }
    }
    #[cfg(not(feature = "dissect"))]
    {
        let _ = frame;
        None
    }
}

/// The envelope of `frame`'s records for a selector, or `None` for one that
/// reads no tree: walked once per frame, before its records are judged.
pub(crate) fn envelope_for(
    filter: &crate::filter::Filter,
    frame: &wz_session_core::passive::PassiveFrame,
    ctx: crate::node::ListContext<'_>,
) -> Option<FrameEnvelope> {
    filter
        .reads_tree()
        .then(|| FrameEnvelope::of(frame, ctx.message()))
}

/// The tree of the record at `span` of the batch `frame` carried, inside the
/// transport message around it ([`FrameEnvelope`]), for a plane whose selector
/// reads a tree ([`crate::filter::Filter::reads_tree`]).
///
/// `None` where the record's bytes are not held whole (a frame that carried no
/// batch, a fragment that did not complete one) or its message does not walk:
/// the plane then hands its record no tree, and every path term over it is
/// undecidable rather than false. The walks are the field document's own
/// (`dissect_transport_message`, `dissect_network_message`), so a path a
/// selector names and the field a row shows are read by one walker.
///
/// Inside a walked `Frame` the record is the one the walk read where the
/// session's record begins: the record the row shows. The walk can read it to
/// another length than the session did (a body the session's codec takes and
/// the walker reads further or stops inside); the row shows the walker's, and
/// a path a reader takes off that row must select it there. A walk that read no
/// record from that byte disagrees with the session about where the record is
/// (the walk stopped before it, or read across it), and the record is read alone
/// from the session's span and stood in the `Frame` all the same: the `Frame`'s
/// own fields were read and are the row's, whatever its batch held. A `Frame`
/// whose bytes were not read leaves a path through it undecided and not wrong.
pub(crate) fn record_tree(
    frame: &wz_session_core::passive::PassiveFrame,
    envelope: &FrameEnvelope,
    span: Option<(usize, usize)>,
) -> Option<RecordTree> {
    #[cfg(feature = "dissect")]
    {
        use wz_session_core::dissect::FieldValue;
        use wz_session_core::inbound::InboundFrame;
        use wz_session_core::passive::Carried;
        let (offset, len) = span?;
        if let FrameEnvelope::Walked {
            shell,
            payload: Some(payload),
            records,
        } = envelope
        {
            let FieldValue::Nested(children) = &shell.value else {
                return None;
            };
            let start = children[*payload].span.start.checked_add(offset)?;
            if let Some(record) = records.iter().find(|r| {
                r.span.start == start && r.name != wz_session_core::dissect_schema::BATCH_REMAINDER
            }) {
                let mut root = shell.clone();
                if let FieldValue::Nested(children) = &mut root.value {
                    children[*payload].value = FieldValue::Nested(alloc::vec![record.clone()]);
                }
                return Some(RecordTree::transport(root));
            }
        }
        let batch: &[u8] = match (&frame.carried, &frame.frame) {
            (Carried::Batch(_), Ok(InboundFrame::Frame { payload, .. })) => payload,
            (Carried::Batch(_), Ok(InboundFrame::Network { payload })) => payload,
            #[cfg(feature = "reassembly")]
            (Carried::Reassembled { joined, .. }, _) => joined,
            _ => return None,
        };
        let bytes = batch.get(offset..offset.checked_add(len)?)?;
        let root = wz_session_core::dissect::dissect_network_message(bytes, offset)
            .ok()
            .flatten()?;
        Some(match envelope {
            FrameEnvelope::Absent => RecordTree::message(root),
            // No transport message stands around a joined record; the one that
            // completed it stands beside it.
            FrameEnvelope::Joined { carrier } => {
                RecordTree::message(root).beside(RecordTree::transport(carrier.clone()))
            }
            // The walk read the `Frame` and not this record: the record stands
            // in the `Frame`'s payload as the session read it.
            FrameEnvelope::Walked {
                shell,
                payload: Some(payload),
                ..
            } => {
                let mut framed = shell.clone();
                if let FieldValue::Nested(children) = &mut framed.value {
                    children[*payload].value = FieldValue::Nested(alloc::vec![root]);
                }
                RecordTree::transport(framed)
            }
            // A `Frame` the walk read to no payload: its fields are read in it,
            // beside the record the session read past them.
            FrameEnvelope::Walked {
                shell,
                payload: None,
                ..
            } => RecordTree::message(root).beside(RecordTree::transport(shell.clone())),
            FrameEnvelope::Unread => RecordTree::with(root, Envelope::Unread),
        })
    }
    #[cfg(not(feature = "dissect"))]
    {
        let _ = (frame, envelope, span);
        None
    }
}

/// One declared path, held as the resolver reads it.
pub(crate) struct Declared {
    pub(crate) segments: Vec<&'static str>,
    kind: PathKind,
    words: Option<Vec<&'static str>>,
}

/// The declared shape, as paths, read from the schema: what [`shape::Shape`]
/// is built from once. Empty in a build without `dissect`.
fn read_declared() -> Vec<Declared> {
    #[cfg(feature = "dissect")]
    {
        wz_session_core::dissect_schema::declared_paths()
            .into_iter()
            .map(|d| Declared {
                kind: PathKind::of_word(d.kind).unwrap_or(PathKind::Opaque),
                words: d.words.map(|w| w()),
                segments: d.segments,
            })
            .collect()
    }
    #[cfg(not(feature = "dissect"))]
    {
        Vec::new()
    }
}

/// One entry of the field list a consumer completes and checks against: a
/// declared path, its kind, and the words of a closed label.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CatalogPath {
    /// The path from its message root, segments joined by `.`.
    pub path: String,
    /// The kind word.
    pub kind: &'static str,
    /// The operators a term over it admits.
    pub operators: &'static [&'static str],
    /// Whether `len()` reads it.
    pub has_width: bool,
    /// The words a label path can carry, where the set is closed.
    pub words: Option<Vec<&'static str>>,
}

/// Every declared path, from its message root, in the order the shape lists
/// them: what the field list document carries.
pub fn catalog() -> Vec<CatalogPath> {
    with_shape(|shape| {
        shape
            .paths()
            .iter()
            .map(|d| CatalogPath {
                path: d.segments.join("."),
                kind: d.kind.word(),
                operators: d.kind.operators(),
                has_width: d.kind.has_width(),
                words: d.words.clone(),
            })
            .collect()
    })
}

/// One rename of a published path, as the field list carries it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RenamedPath {
    /// The node's full path before.
    pub from: &'static str,
    /// Its full path now.
    pub to: &'static str,
    /// The field document revision whose shape first carried `to`.
    pub since: u32,
}

/// Every rename the shape declares, oldest first. Empty in a build without
/// `dissect`, which declares no path.
pub fn renamed() -> Vec<RenamedPath> {
    #[cfg(feature = "dissect")]
    {
        wz_session_core::dissect_schema::RENAMED
            .iter()
            .map(|r| RenamedPath {
                from: r.from,
                to: r.to,
                since: r.since_fields_revision,
            })
            .collect()
    }
    #[cfg(not(feature = "dissect"))]
    {
        Vec::new()
    }
}

/// How many names an unknown-field refusal offers at most.
pub const NEAREST_LIMIT: usize = 5;

/// The names nearest `written` that a selector could have meant: the fixed
/// fields and every tail of a declared path with as many segments as
/// `written` has, closest first, at most [`NEAREST_LIMIT`].
///
/// Near is a prefix of the name (a name being typed) or within a few edits of
/// it (a name mistyped); a name neither is not offered, so a refusal of a word
/// that resembles nothing offers nothing rather than five unrelated names.
pub fn nearest(written: &str, fixed: &[&'static str]) -> Vec<String> {
    let width = written.split('.').count();
    let mut pool: Vec<String> = Vec::new();
    if width == 1 {
        pool.extend(fixed.iter().map(|f| String::from(*f)));
    }
    with_shape(|shape| {
        for d in shape.paths() {
            if d.segments.len() >= width {
                let tail = d.segments[d.segments.len() - width..].join(".");
                if !pool.contains(&tail) {
                    pool.push(tail);
                }
            }
        }
    });
    let budget = core::cmp::max(2, written.chars().count() / 3);
    let mut ranked: Vec<(usize, String)> = pool
        .into_iter()
        .filter(|name| name != written)
        .filter_map(|name| {
            if name.starts_with(written) {
                return Some((0, name));
            }
            let d = edit_distance(written, &name);
            (d <= budget).then_some((d, name))
        })
        .collect();
    ranked.sort();
    ranked
        .into_iter()
        .take(NEAREST_LIMIT)
        .map(|(_, n)| n)
        .collect()
}

/// Levenshtein distance over characters.
fn edit_distance(a: &str, b: &str) -> usize {
    let b: Vec<char> = b.chars().collect();
    let mut row: Vec<usize> = (0..=b.len()).collect();
    for (i, ca) in a.chars().enumerate() {
        let mut diagonal = row[0];
        row[0] = i + 1;
        for (j, cb) in b.iter().enumerate() {
            let above = row[j + 1];
            row[j + 1] = if ca == *cb {
                diagonal
            } else {
                1 + core::cmp::min(diagonal, core::cmp::min(above, row[j]))
            };
            diagonal = above;
        }
    }
    row[b.len()]
}

/// Whether this build compiles `matches` patterns.
pub fn patterns_supported() -> bool {
    Pattern::supported()
}
