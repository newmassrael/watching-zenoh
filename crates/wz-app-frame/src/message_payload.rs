// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! A MESSAGE PAYLOAD set and read field by field, at paths, under a `.proto`
//! schema read at run time: values set, the protobuf bytes of the message
//! encoded, bytes decoded, and values read back.
//!
//! ## What this is for
//!
//! A program that reads its deployment's message catalog and `.proto` files
//! when it starts has no code generated for its messages: it knows a message by
//! its full name and a field by its path. [`Payload`] is that program's message:
//! one message of a [`SchemaSet`], whose fields are set and read by path and
//! whose bytes are what the schema says they are. The schema is read by the
//! one schema reader ([`crate::proto_schema`]) and bytes are read by the one
//! typed reader ([`crate::proto_decode`]), so this module adds the values and
//! the writing of them, and no second reading of either.
//!
//! ## Paths
//!
//! A path names a field by its name as the `.proto` file spells it, a field
//! inside a message field by the holder's name, a dot and its own
//! (`origin.x`), and an element of a repeated field by its index in brackets
//! (`path[2].x`, `tags[0]`), the index decimal digits with no leading zero. A
//! repeated field is named with an index wherever a value is set or read, and
//! without one where its elements are counted or all cleared. A `map` field and
//! a `group` are not addressed: a map's entries and a group's body are not
//! fields of the message that holds them, and a decoded map is carried as its
//! wire bytes. A path is at most [`MAX_DECODE_DEPTH`] names long.
//!
//! ## Setting a value
//!
//! The value is given as the program holds it ([`Given`]) and is held as the
//! field's type, never converted by guessing: an integer goes into an integer
//! or enum field it fits, a real number into a `float` or `double` (a finite one
//! a `float` cannot hold is refused rather than made infinite), a bool into a
//! `bool`, a string into a `string` or into an enum by the name of a value, and
//! bytes into `bytes`. A closed (proto2) enum takes only the numbers its values
//! have; an open (proto3) one takes any `int32`. A message field is set by its
//! fields' paths: setting one makes every message along the path that is not
//! there yet. An element is replaced at an index the list has and appended at
//! the index one past its end; a farther index is refused, and so is anything a
//! call is refused for before it changes the payload, so a refused call leaves
//! it as it was. Setting a member of a oneof clears the other members.
//!
//! ## Reading a value
//!
//! A value is read as the program asks for it ([`Wanted`]) when the field's
//! value fits: a signed integer from any integer or enum field whose value fits
//! `i64`, an unsigned one from any whose value fits `u64`, a real number from a
//! `float` or a `double`, a string from a `string` or from an enum by its
//! value's name. A field that is not set reads as protobuf reads it: a field
//! without presence (a proto3 singular field that is not `optional`, not in a
//! oneof and not a message) as its default, `0`, `false`, empty or the enum's
//! first value; a field WITH presence, or any field of a message that is not
//! there, is refused as absent ([`Refusal::Absent`]), which is how a program
//! asks whether it was set.
//!
//! ## The bytes
//!
//! Written by the workspace's one protobuf writer ([`crate::proto_write`]), the
//! one the capture crate's writer of values given as JSON writes through too:
//! fields in ascending number; a field without presence left out at its default
//! (a `float` or `double` whose bits are all zero, so `-0.0` is written); a
//! repeated numeric, `bool` or enum field packed in proto3 unless it says
//! `[packed = false]` and unpacked in proto2 unless it says `[packed = true]`;
//! `int32` and an enum sign-extended (a negative one is ten bytes), `sint32` and
//! `sint64` zigzagged. A proto2 `required` field that is not set refuses the
//! encoding.
//!
//! ## Narrowing
//!
//! An integer is held to its field's type unless the payload was made for a
//! receiver that links nanopb ([`Payload::narrowed`] with
//! [`Narrowing::NanopbIntSize`]): then a varint field takes only what the C
//! integer its `(nanopb).int_size` chooses can hold, and a field whose nanopb
//! options leave that unknown (an `int_size` the reader cannot read, a
//! `type_override`) takes no integer at all. The range is judged where the value
//! is set, so a value the receiver would refuse is refused to the program.
//! Bytes a payload decodes are taken as they are.
//!
//! Decoding replaces the payload's values with those of the bytes, read as a
//! protobuf parser reads them: the last occurrence of a singular field wins,
//! occurrences of a message field are merged, a repeated field takes its
//! elements packed or not, and a oneof keeps its last member. A field the
//! schema does not know and every entry of a map field are KEPT as their wire
//! bytes and written back after the known fields, so a payload decoded and
//! encoded again loses nothing. Bytes that are not a message of the schema are
//! refused with the typed reader's diagnostic, and the payload is left as it
//! was.
//!
//! ## Storage
//!
//! A payload keeps its values in a store ([`Storage`]): a table of slots, one
//! per value, and the bytes its strings, bytes and kept fields are written in.
//! [`Payload::new`] keeps it on the heap, which grows; a caller that reserves
//! the store itself ([`Payload::over`]) gives one of a fixed size, and the
//! payload takes nothing more after it is made. Such a store refuses what does
//! not fit it ([`Refusal::Full`]): a set is refused and changes nothing, and a
//! decode is refused and leaves the payload empty, since its values replace the
//! payload's as they are read. Paths are judged and walked where they are
//! written, and the bytes are written into the caller's buffer
//! ([`Payload::encode_into`]), so no call takes memory of its own beyond a
//! refusal's sentence.
//!
//! ## Refusals
//!
//! Each is a [`Refusal`]: the path names no field the payload addresses, the
//! value's type is not the field's, the value does not fit the field or an index
//! is past the end of its list, a field is not set, the schema states an option
//! the writer cannot act on, the bytes are not a message, or the store is full.

use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;
use core::borrow::Borrow;
use core::fmt;

use crate::proto_decode::{
    FieldEvents, Item, SchemaMessage, SchemaSet, WireError, MAX_DECODE_DEPTH,
};
use crate::proto_parse::{Label, ScalarKind, Syntax};
use crate::proto_range::{RangeRefusal, RangeSource, ValueRange};
use crate::proto_schema::{FieldKind, Fld, Msg};
use crate::proto_write::{self, has_presence, Count, Fixed, Narrowing, Out, Wire};

/// A value as the program gives it to a field.
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum Given<'v> {
    /// A signed integer: for an integer or an enum field it fits.
    Signed(i64),
    /// An unsigned integer: for an integer or an enum field it fits.
    Unsigned(u64),
    /// A real number: for a `float` or a `double`.
    Real(f64),
    /// For a `bool`.
    Bool(bool),
    /// For a `string`, or an enum by the name of one of its values.
    Text(&'v str),
    /// For `bytes`.
    Bytes(&'v [u8]),
}

impl Given<'_> {
    fn word(self) -> &'static str {
        match self {
            Self::Signed(_) => "a signed integer",
            Self::Unsigned(_) => "an unsigned integer",
            Self::Real(_) => "a real number",
            Self::Bool(_) => "a bool",
            Self::Text(_) => "a string",
            Self::Bytes(_) => "bytes",
        }
    }
}

/// What the program asks a field's value to be read as.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Wanted {
    /// An `i64`, from an integer or an enum field.
    Signed,
    /// A `u64`, from an integer or an enum field.
    Unsigned,
    /// An `f64`, from a `float` or a `double`.
    Real,
    /// From a `bool`.
    Bool,
    /// From a `string`, or an enum's value by its name.
    Text,
    /// From `bytes`.
    Bytes,
}

impl Wanted {
    fn word(self) -> &'static str {
        match self {
            Self::Signed => "a signed integer",
            Self::Unsigned => "an unsigned integer",
            Self::Real => "a real number",
            Self::Bool => "a bool",
            Self::Text => "a string",
            Self::Bytes => "bytes",
        }
    }
}

/// A value read from a field, as the program asked for it.
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum Got<'p> {
    Signed(i64),
    Unsigned(u64),
    Real(f64),
    Bool(bool),
    Text(&'p str),
    Bytes(&'p [u8]),
}

/// Why a call on a payload was refused. A refused call changes nothing.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Refusal {
    /// The path names no field the payload addresses: not a path, a name the
    /// message has not, an index on a field that is not repeated, a repeated
    /// field where an element is needed (or the other way round), a field that
    /// holds no fields followed by a dot, a map or a group.
    Path { path: String, reason: String },
    /// The value's type is not the field's, or the field's value cannot be
    /// read as what was asked for.
    Type { path: String, reason: String },
    /// The value does not fit the field (an integer past its width, a real a
    /// `float` cannot hold, a number or a name a closed enum has not), a value
    /// does not fit what it is read as, or an index is past the end of its list.
    Range { path: String, reason: String },
    /// The field `path` names is not set: a field with presence, a required
    /// field of an encoding, or a field of a message that is not there; `at` is
    /// the first part of the path that is absent.
    Absent { path: String, at: String },
    /// The schema states an option of a field the writer cannot act on: a
    /// `packed` it cannot follow, or, for a payload that narrows by nanopb, an
    /// integer field whose nanopb options leave its range unknown.
    Schema { path: String, reason: String },
    /// The bytes are not a message of the schema.
    Wire(WireError),
    /// The payload's storage has no room left for what the call would hold: more values than its
    /// table has slots, or more bytes of strings, bytes and kept fields than it has. A refused
    /// set changes nothing; a refused decode leaves the payload empty.
    Full { path: String, reason: String },
}

impl fmt::Display for Refusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Path { path, reason } => write!(f, "path `{path}`: {reason}"),
            Self::Type { path, reason } => write!(f, "type mismatch at `{path}`: {reason}"),
            Self::Range { path, reason } => write!(f, "out of range at `{path}`: {reason}"),
            Self::Absent { path, at } if path == at => write!(f, "`{path}` is not set"),
            Self::Absent { path, at } => write!(f, "`{path}` is not set: `{at}` is absent"),
            Self::Schema { path, reason } => write!(f, "schema at `{path}`: {reason}"),
            Self::Wire(w) => write!(f, "the bytes are not a message of the schema: {w}"),
            Self::Full { path, reason } => write!(f, "no room at `{path}`: {reason}"),
        }
    }
}

/// A value as the program sets it or the bytes carry it, before the payload keeps it: a string or
/// bytes still the giver's.
#[derive(Clone, Copy, Debug)]
enum Value<'v> {
    /// `int32`, `int64`, `sint32`, `sint64`, `sfixed32`, `sfixed64`, and an
    /// enum's number.
    Int(i64),
    /// `uint32`, `uint64`, `fixed32`, `fixed64`.
    Uint(u64),
    Float(f32),
    Double(f64),
    Bool(bool),
    Text(&'v str),
    Bytes(&'v [u8]),
}

/// Where a run of bytes lies in a payload's byte store.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct Span {
    at: usize,
    len: usize,
}

/// What one slot of a payload's table holds.
#[derive(Clone, Copy, Debug, Default)]
enum Slot {
    /// A slot no value is in.
    #[default]
    Free,
    Int(i64),
    Uint(u64),
    Float(f32),
    Double(f64),
    Bool(bool),
    /// UTF-8, checked when it was given or read.
    Text(Span),
    Bytes(Span),
    /// A message: the slots whose parent this one is are its fields.
    Message,
    /// Wire bytes the message carries without addressing them: a field the schema does not know,
    /// a map's entry, a group.
    Kept(Span),
}

/// The parent of a slot that is a field of the payload's own message.
const ROOT: u32 = u32::MAX;
/// The parent a slot is given while a removal is under way, which no slot index is.
const REMOVED: u32 = u32::MAX - 1;

/// One slot of a payload's table: a value of one field, which message holds it and the field's
/// number. The elements of a repeated field are its slots under one parent in the order of the
/// table, and a message comes before every slot inside it.
#[derive(Clone, Copy, Debug, Default)]
pub struct Entry {
    number: u64,
    parent: u32,
    slot: Slot,
}

/// Where a payload keeps its values: the slots of its table and the bytes its strings, bytes and
/// kept fields are written in. A store of a fixed size refuses what does not fit; one that may grow
/// ([`HeapStorage`]) grows.
pub trait Storage {
    /// The table's slots.
    fn entries(&self) -> &[Entry];
    fn entries_mut(&mut self) -> &mut [Entry];
    /// The byte store.
    fn bytes(&self) -> &[u8];
    fn bytes_mut(&mut self) -> &mut [u8];
    /// Make room for at least `entries` slots and `bytes` bytes; whether there is. A store of a
    /// fixed size answers by what it has.
    fn reserve(&mut self, entries: usize, bytes: usize) -> bool {
        self.entries().len() >= entries && self.bytes().len() >= bytes
    }
}

/// A store on the heap, which grows as the payload needs: what [`Payload::new`] makes.
#[derive(Debug, Default)]
pub struct HeapStorage {
    entries: Vec<Entry>,
    bytes: Vec<u8>,
}

impl Storage for HeapStorage {
    fn entries(&self) -> &[Entry] {
        &self.entries
    }

    fn entries_mut(&mut self) -> &mut [Entry] {
        &mut self.entries
    }

    fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    fn bytes_mut(&mut self) -> &mut [u8] {
        &mut self.bytes
    }

    fn reserve(&mut self, entries: usize, bytes: usize) -> bool {
        if self.entries.len() < entries {
            self.entries
                .resize(entries.max(self.entries.len() * 2), Entry::default());
        }
        if self.bytes.len() < bytes {
            self.bytes.resize(bytes.max(self.bytes.len() * 2), 0);
        }
        true
    }
}

/// Why a table took no more.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum NoRoom {
    Entries,
    Bytes,
}

impl NoRoom {
    fn refusal(self, path: &str) -> Refusal {
        Refusal::Full {
            path: String::from(path),
            reason: String::from(match self {
                Self::Entries => "the payload's storage holds no more values",
                Self::Bytes => "the payload's storage holds no more bytes",
            }),
        }
    }
}

/// The values of a payload in its store: the slots in use and the bytes written.
#[derive(Debug)]
struct Table<St> {
    store: St,
    len: usize,
    used: usize,
}

impl<St: Storage> Table<St> {
    fn new(store: St) -> Self {
        Self {
            store,
            len: 0,
            used: 0,
        }
    }

    fn clear(&mut self) {
        self.len = 0;
        self.used = 0;
    }

    /// The slots in use.
    fn live(&self) -> &[Entry] {
        self.store.entries().get(..self.len).unwrap_or_default()
    }

    fn entry(&self, at: usize) -> Option<Entry> {
        self.live().get(at).copied()
    }

    fn set_slot(&mut self, at: usize, slot: Slot) {
        if let Some(entry) = self.store.entries_mut().get_mut(at) {
            entry.slot = slot;
        }
    }

    fn bytes_of(&self, span: Span) -> &[u8] {
        self.store
            .bytes()
            .get(span.at..span.at.saturating_add(span.len))
            .unwrap_or_default()
    }

    fn text_of(&self, span: Span) -> &str {
        core::str::from_utf8(self.bytes_of(span)).unwrap_or_default()
    }

    /// The slots of field `number` of the message at `parent`, in order.
    fn values(&self, parent: u32, number: u64) -> impl Iterator<Item = usize> + '_ {
        self.live()
            .iter()
            .enumerate()
            .filter(move |(_, e)| {
                e.parent == parent && e.number == number && !matches!(e.slot, Slot::Kept(_))
            })
            .map(|(at, _)| at)
    }

    /// How many values field `number` of the message at `parent` holds.
    fn count(&self, parent: u32, number: u64) -> usize {
        self.values(parent, number).count()
    }

    /// The slot of the value at `index` of field `number` of the message at `parent`.
    fn nth(&self, parent: u32, number: u64, index: usize) -> Option<usize> {
        self.values(parent, number).nth(index)
    }

    /// The slot of the last value of field `number` of the message at `parent`.
    fn last(&self, parent: u32, number: u64) -> Option<usize> {
        self.values(parent, number).last()
    }

    /// Whether `extra` more slots and `bytes` more bytes fit, the store grown or the bytes no
    /// slot holds any more given back first when they would not.
    fn room(&mut self, extra: usize, bytes: usize) -> Result<(), NoRoom> {
        let entries = self.len.saturating_add(extra);
        if self.used.saturating_add(bytes) > self.store.bytes().len() {
            self.compact();
        }
        let need = self.used.saturating_add(bytes);
        if self.store.reserve(entries, need) {
            return Ok(());
        }
        if self.store.entries().len() < entries {
            Err(NoRoom::Entries)
        } else {
            Err(NoRoom::Bytes)
        }
    }

    /// The bytes the slots hold.
    fn live_bytes(&self) -> usize {
        self.live()
            .iter()
            .map(|e| match e.slot {
                Slot::Text(s) | Slot::Bytes(s) | Slot::Kept(s) => s.len,
                _ => 0,
            })
            .sum()
    }

    /// Whether `extra` more slots fit, and `bytes` more bytes once `freed` bytes a slot holds now
    /// are let go: the store grown when it may, and nothing changed when it does not fit.
    fn fits(&mut self, extra: usize, bytes: usize, freed: usize) -> Result<(), NoRoom> {
        let entries = self.len.saturating_add(extra);
        let capacity = self.store.bytes().len();
        let in_place = self.used.saturating_add(bytes) <= capacity;
        let after_compaction = self
            .live_bytes()
            .saturating_sub(freed)
            .saturating_add(bytes)
            <= capacity;
        if self.store.entries().len() >= entries && (in_place || after_compaction) {
            return Ok(());
        }
        let need = self.used.saturating_add(bytes);
        if self.store.reserve(entries, need) {
            return Ok(());
        }
        if self.store.entries().len() < entries {
            Err(NoRoom::Entries)
        } else {
            Err(NoRoom::Bytes)
        }
    }

    /// Put a slot at the end of the table.
    fn push(&mut self, number: u64, parent: u32, slot: Slot) -> Result<usize, NoRoom> {
        self.room(1, 0)?;
        let at = self.len;
        let Some(entry) = self.store.entries_mut().get_mut(at) else {
            return Err(NoRoom::Entries);
        };
        *entry = Entry {
            number,
            parent,
            slot,
        };
        self.len += 1;
        Ok(at)
    }

    /// Write `data` into the byte store: where it lies.
    fn write(&mut self, data: &[u8]) -> Result<Span, NoRoom> {
        self.room(0, data.len())?;
        let at = self.used;
        let end = at.saturating_add(data.len());
        let Some(place) = self.store.bytes_mut().get_mut(at..end) else {
            return Err(NoRoom::Bytes);
        };
        place.copy_from_slice(data);
        self.used = end;
        Ok(Span {
            at,
            len: data.len(),
        })
    }

    /// The slot `value` is held in, its bytes written; over `old`'s bytes when they are as long
    /// at least.
    fn slot_of(&mut self, value: Value<'_>, old: Option<Slot>) -> Result<Slot, NoRoom> {
        let data = match value {
            Value::Int(v) => return Ok(Slot::Int(v)),
            Value::Uint(v) => return Ok(Slot::Uint(v)),
            Value::Float(v) => return Ok(Slot::Float(v)),
            Value::Double(v) => return Ok(Slot::Double(v)),
            Value::Bool(v) => return Ok(Slot::Bool(v)),
            Value::Text(v) => v.as_bytes(),
            Value::Bytes(v) => v,
        };
        let reuse = match old {
            Some(Slot::Text(span) | Slot::Bytes(span)) if span.len >= data.len() => Some(span),
            _ => None,
        };
        let span = match reuse {
            Some(span) => {
                if let Some(place) = self
                    .store
                    .bytes_mut()
                    .get_mut(span.at..span.at.saturating_add(data.len()))
                {
                    place.copy_from_slice(data);
                }
                Span {
                    at: span.at,
                    len: data.len(),
                }
            }
            None => self.write(data)?,
        };
        Ok(match value {
            Value::Text(_) => Slot::Text(span),
            _ => Slot::Bytes(span),
        })
    }

    /// Give back the bytes no slot holds: the runs slots hold moved down to the start, in order.
    fn compact(&mut self) {
        let mut to = 0usize;
        loop {
            // The run lying first at or past `to`: every run below `to` has moved already.
            let next = self
                .live()
                .iter()
                .enumerate()
                .filter_map(|(at, e)| match e.slot {
                    Slot::Text(s) | Slot::Bytes(s) | Slot::Kept(s) if s.len > 0 && s.at >= to => {
                        Some((at, s))
                    }
                    _ => None,
                })
                .min_by_key(|(_, s)| s.at);
            let Some((at, span)) = next else {
                break;
            };
            self.store
                .bytes_mut()
                .copy_within(span.at..span.at + span.len, to);
            let moved = Span {
                at: to,
                len: span.len,
            };
            let slot = match self.live()[at].slot {
                Slot::Text(_) => Slot::Text(moved),
                Slot::Bytes(_) => Slot::Bytes(moved),
                _ => Slot::Kept(moved),
            };
            self.set_slot(at, slot);
            to += span.len;
        }
        self.used = to;
    }

    /// Remove the slots `pick` names, with every slot inside one of them: the slots after move
    /// down, keeping their order, and each parent is the slot's new place.
    fn remove(&mut self, pick: impl Fn(usize, &Entry) -> bool) {
        let len = self.len;
        let entries = self.store.entries_mut();
        let Some(entries) = entries.get_mut(..len) else {
            return;
        };
        // A message comes before what is inside it, so one pass in order marks a slot inside a
        // removed one after the removed one was marked.
        for at in 0..entries.len() {
            let inside = match entries[at].parent {
                ROOT => false,
                parent => entries
                    .get(parent as usize)
                    .is_some_and(|p| p.parent == REMOVED),
            };
            if inside || pick(at, &entries[at]) {
                entries[at].parent = REMOVED;
            }
        }
        let removed_before = |entries: &[Entry], at: usize| {
            entries[..at].iter().filter(|e| e.parent == REMOVED).count()
        };
        for at in 0..entries.len() {
            let parent = entries[at].parent;
            if parent != ROOT && parent != REMOVED {
                let shift = removed_before(entries, parent as usize);
                entries[at].parent = parent - shift as u32;
            }
        }
        let mut to = 0usize;
        for at in 0..entries.len() {
            if entries[at].parent != REMOVED {
                entries[to] = entries[at];
                to += 1;
            }
        }
        self.len = to;
    }

    /// Remove every value of the other members of the oneof `field` of `holder` is in, in the
    /// message at `parent`.
    fn clear_oneof(&mut self, parent: u32, holder: &Msg, field: &Fld) {
        if let Some(oneof) = field.oneof {
            self.remove(|_, e| {
                e.parent == parent
                    && e.number != field.number
                    && !matches!(e.slot, Slot::Kept(_))
                    && holder
                        .fields
                        .iter()
                        .any(|f| f.number == e.number && f.oneof == Some(oneof))
            });
        }
    }

    /// Remove every value of field `number` of the message at `parent`.
    fn remove_field(&mut self, parent: u32, number: u64) {
        self.remove(|_, e| {
            e.parent == parent && e.number == number && !matches!(e.slot, Slot::Kept(_))
        });
    }
}

/// The bytes a value is written in, for a string or bytes; none for another.
fn value_len(value: Value<'_>) -> usize {
    match value {
        Value::Text(v) => v.len(),
        Value::Bytes(v) => v.len(),
        _ => 0,
    }
}

/// The index a parent is named by.
fn parent_of(at: usize) -> u32 {
    u32::try_from(at).unwrap_or(REMOVED)
}

/// One step of a path: the field, the message that holds it, its index, and
/// where the step ends in the path's text.
#[derive(Clone, Copy)]
struct Step<'s> {
    holder: &'s Msg,
    field: &'s Fld,
    index: Option<usize>,
    end: usize,
}

impl Step<'_> {
    fn repeated(&self) -> bool {
        self.field.label == Label::Repeated
    }
}

/// A part of a path: a name, and an index when it has one.
fn segment(part: &str) -> Option<(&str, Option<usize>)> {
    let (name, index) = match part.find('[') {
        None => (part, None),
        Some(open) => {
            let digits = part[open + 1..].strip_suffix(']')?;
            let plain = !digits.is_empty()
                && digits.bytes().all(|b| b.is_ascii_digit())
                && (digits.len() == 1 || !digits.starts_with('0'));
            if !plain {
                return None;
            }
            (&part[..open], Some(digits.parse::<usize>().ok()?))
        }
    };
    let first = name.bytes().next()?;
    let word =
        !first.is_ascii_digit() && name.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_');
    word.then_some((name, index))
}

/// The steps a path takes from a message, judged whole when it is made ([`route`]) and walked
/// again from its text as often as a call needs, so that no list of them is kept.
#[derive(Clone, Copy)]
struct Route<'s, 'p> {
    schema: &'s SchemaSet,
    root: &'s Msg,
    path: &'p str,
    /// How many steps the path takes.
    parts: usize,
    /// The last step: the field the path names.
    last: Step<'s>,
}

impl<'s, 'p> Route<'s, 'p> {
    /// Every step but the last, from the root: the messages that hold the field.
    fn inner(&self) -> Inner<'s, 'p> {
        Inner {
            schema: self.schema,
            holder: self.root,
            parts: self.path.split('.'),
            end: 0,
            first: true,
            left: self.parts.saturating_sub(1),
        }
    }

    /// Every step, the last included.
    fn all(&self) -> core::iter::Chain<Inner<'s, 'p>, core::iter::Once<Step<'s>>> {
        self.inner().chain(core::iter::once(self.last))
    }
}

/// The steps of a [`Route`] before its last, read again from the path's text, which [`route`]
/// judged: a part that does not read is never met, and ends the walk where it would be.
struct Inner<'s, 'p> {
    schema: &'s SchemaSet,
    holder: &'s Msg,
    parts: core::str::Split<'p, char>,
    end: usize,
    first: bool,
    left: usize,
}

impl<'s> Iterator for Inner<'s, '_> {
    type Item = Step<'s>;

    fn next(&mut self) -> Option<Step<'s>> {
        if self.left == 0 {
            return None;
        }
        self.left -= 1;
        let part = self.parts.next()?;
        self.end += part.len() + usize::from(!self.first);
        self.first = false;
        let (name, index) = segment(part)?;
        let field = self.holder.fields.iter().find(|f| f.name == name)?;
        let step = Step {
            holder: self.holder,
            field,
            index,
            end: self.end,
        };
        self.holder = match field.kind {
            FieldKind::Message(inner) => self.schema.linked_at(inner)?,
            _ => return None,
        };
        Some(step)
    }
}

/// The route `path` takes from the message `root`, every part of it judged.
fn route<'s, 'p>(
    schema: &'s SchemaSet,
    root: &'s Msg,
    path: &'p str,
) -> Result<Route<'s, 'p>, Refusal> {
    let refused = |reason: String| Refusal::Path {
        path: String::from(path),
        reason,
    };
    let parts = path.split('.').count();
    if parts > MAX_DECODE_DEPTH {
        return Err(refused(format!(
            "it goes {parts} names deep, past the {MAX_DECODE_DEPTH} a payload is read to"
        )));
    }
    let mut holder = root;
    let mut last = None;
    let mut end = 0usize;
    for (at, part) in path.split('.').enumerate() {
        end += part.len() + usize::from(at > 0);
        let Some((name, index)) = segment(part) else {
            return Err(refused(format!(
                "`{part}` is not a field name, or a field name and an index in brackets"
            )));
        };
        let Some(field) = holder.fields.iter().find(|f| f.name == name) else {
            return Err(refused(format!(
                "the message `{}` has no field `{name}`",
                holder.full_name
            )));
        };
        match field.kind {
            FieldKind::Map { .. } => {
                return Err(refused(format!(
                    "`{name}` is a map, whose entries a path does not address"
                )))
            }
            FieldKind::Group => {
                return Err(refused(format!(
                    "`{name}` is a group, which this library does not write"
                )))
            }
            _ => {}
        }
        let repeated = field.label == Label::Repeated;
        if index.is_some() && !repeated {
            return Err(refused(format!(
                "`{name}` is not repeated, so it has no element to index"
            )));
        }
        last = Some(Step {
            holder,
            field,
            index,
            end,
        });
        if at + 1 == parts {
            break;
        }
        if repeated && index.is_none() {
            return Err(refused(format!(
                "`{name}` is repeated: name one of its elements, as `{name}[0]`"
            )));
        }
        let inner = match field.kind {
            FieldKind::Message(inner) => schema.linked_at(inner),
            _ => None,
        };
        let Some(inner) = inner else {
            return Err(refused(format!(
                "`{name}` is not a message field, so no field is inside it"
            )));
        };
        holder = inner;
    }
    // `split` yields at least one part, and an empty one is refused above.
    let Some(last) = last else {
        return Err(refused(String::from("the path is empty")));
    };
    Ok(Route {
        schema,
        root,
        path,
        parts,
        last,
    })
}

/// The type of a field as the schema writes it.
fn type_name(schema: &SchemaSet, field: &Fld) -> String {
    match field.kind {
        FieldKind::Scalar(kind) => String::from(kind.keyword()),
        FieldKind::Enum(e) => schema
            .enum_at(e)
            .map_or_else(|| String::from("an enum"), |info| info.full_name.clone()),
        FieldKind::Message(m) => schema
            .linked_at(m)
            .map_or_else(|| String::from("a message"), |msg| msg.full_name.clone()),
        FieldKind::Map { .. } => String::from("a map"),
        FieldKind::Group => String::from("a group"),
    }
}

fn unsigned(kind: ScalarKind) -> bool {
    matches!(
        kind,
        ScalarKind::Uint32 | ScalarKind::Uint64 | ScalarKind::Fixed32 | ScalarKind::Fixed64
    )
}

/// The integers field `field` of `holder` takes under `narrowing`, for an
/// integer kind; the refusal when its nanopb options leave the range unknown.
fn integer_range(
    schema: &SchemaSet,
    holder: &Msg,
    field: &Fld,
    kind: ScalarKind,
    narrowing: Narrowing,
    path: &str,
) -> Result<ValueRange, Refusal> {
    match narrowing.field_range(schema, holder, field) {
        Ok(range) => Ok(range),
        Err(RangeRefusal::UnmodelledOption) => Err(Refusal::Schema {
            path: String::from(path),
            reason: format!(
                "the field's nanopb options (an int_size this reader cannot read, or a \
                 type_override) leave unknown the range of the values nanopb takes for this {}, \
                 so no value is set",
                kind.keyword()
            ),
        }),
        // An integer kind always has its type's range; the type is the honest
        // bound should the judgement ever say otherwise.
        Err(RangeRefusal::NotAnInteger | RangeRefusal::Enum | RangeRefusal::Map) => {
            ValueRange::of_type(kind).ok_or_else(|| Refusal::Type {
                path: String::from(path),
                reason: format!("the field is {}, which holds no integer", kind.keyword()),
            })
        }
    }
}

/// The value `given` as field `field` of `holder` holds it, an integer held to
/// the range `narrowing` chooses; a string or bytes still borrowed from `given`.
fn held_of<'v>(
    schema: &SchemaSet,
    holder: &Msg,
    field: &Fld,
    given: Given<'v>,
    narrowing: Narrowing,
    path: &str,
) -> Result<Value<'v>, Refusal> {
    let mismatch = || Refusal::Type {
        path: String::from(path),
        reason: format!(
            "the field is {}, and {} was given",
            type_name(schema, field),
            given.word()
        ),
    };
    let range = |reason: String| Refusal::Range {
        path: String::from(path),
        reason,
    };
    let integer = match given {
        Given::Signed(v) => Some(i128::from(v)),
        Given::Unsigned(v) => Some(i128::from(v)),
        _ => None,
    };
    match field.kind {
        FieldKind::Scalar(kind) => {
            if ValueRange::of_type(kind).is_some() {
                let Some(v) = integer else {
                    return Err(mismatch());
                };
                let ValueRange { low, high, source } =
                    integer_range(schema, holder, field, kind, narrowing, path)?;
                if !(low..=high).contains(&v) {
                    return Err(range(match source {
                        RangeSource::Type => format!(
                            "{v} does not fit a {}, whose values are {low} to {high}",
                            kind.keyword()
                        ),
                        RangeSource::NanopbIntSize { bits } => format!(
                            "{v} does not fit a {} with (nanopb).int_size = IS_{bits}, whose \
                             values are {low} to {high}",
                            kind.keyword()
                        ),
                    }));
                }
                return Ok(if unsigned(kind) {
                    Value::Uint(v as u64)
                } else {
                    Value::Int(v as i64)
                });
            }
            match (kind, given) {
                (ScalarKind::Double, Given::Real(v)) => Ok(Value::Double(v)),
                (ScalarKind::Float, Given::Real(v)) => {
                    let narrow = v as f32;
                    if v.is_finite() && narrow.is_infinite() {
                        return Err(range(format!("{v} is finite and past what a float holds")));
                    }
                    Ok(Value::Float(narrow))
                }
                (ScalarKind::Bool, Given::Bool(v)) => Ok(Value::Bool(v)),
                (ScalarKind::String, Given::Text(v)) => Ok(Value::Text(v)),
                (ScalarKind::Bytes, Given::Bytes(v)) => Ok(Value::Bytes(v)),
                _ => Err(mismatch()),
            }
        }
        FieldKind::Enum(e) => {
            let Some(info) = schema.enum_at(e) else {
                return Err(mismatch());
            };
            let number = match (given, integer) {
                (_, Some(v)) => i32::try_from(v).map_err(|_| {
                    range(format!("{v} does not fit an enum, whose values are int32"))
                })?,
                (Given::Text(name), None) => {
                    let found = info.values.iter().find(|(n, _)| n == name);
                    let Some(number) = found.and_then(|(_, v)| i32::try_from(*v).ok()) else {
                        return Err(range(format!(
                            "the enum `{}` has no value named `{name}`",
                            info.full_name
                        )));
                    };
                    number
                }
                _ => return Err(mismatch()),
            };
            let listed = info.values.iter().any(|(_, v)| *v == i128::from(number));
            if info.syntax == Syntax::Proto2 && !listed {
                return Err(range(format!(
                    "the enum `{}` is closed and has no value {number}",
                    info.full_name
                )));
            }
            Ok(Value::Int(i64::from(number)))
        }
        FieldKind::Message(_) => Err(Refusal::Type {
            path: String::from(path),
            reason: format!(
                "the field is the message {}: set its fields by their paths",
                type_name(schema, field)
            ),
        }),
        FieldKind::Map { .. } | FieldKind::Group => Err(mismatch()),
    }
}

/// A value as it is read: borrowed from the payload, or a default.
#[derive(Clone, Copy)]
enum View<'p> {
    Int(i64),
    Uint(u64),
    Float(f32),
    Double(f64),
    Bool(bool),
    Text(&'p str),
    Bytes(&'p [u8]),
    Message,
}

/// The value a field without presence reads as when it is not set.
fn default_view<'p>(schema: &'p SchemaSet, field: &Fld) -> View<'p> {
    match field.kind {
        FieldKind::Scalar(ScalarKind::Double) => View::Double(0.0),
        FieldKind::Scalar(ScalarKind::Float) => View::Float(0.0),
        FieldKind::Scalar(ScalarKind::Bool) => View::Bool(false),
        FieldKind::Scalar(ScalarKind::String) => View::Text(""),
        FieldKind::Scalar(ScalarKind::Bytes) => View::Bytes(&[]),
        FieldKind::Scalar(kind) if unsigned(kind) => View::Uint(0),
        FieldKind::Scalar(_) => View::Int(0),
        FieldKind::Enum(e) => View::Int(
            schema
                .enum_at(e)
                .and_then(|info| info.values.first())
                .and_then(|(_, v)| i64::try_from(*v).ok())
                .unwrap_or(0),
        ),
        FieldKind::Message(_) | FieldKind::Map { .. } | FieldKind::Group => View::Message,
    }
}

/// `value` of `field` as the program asked for it.
fn got<'p>(
    schema: &'p SchemaSet,
    field: &Fld,
    value: View<'p>,
    wanted: Wanted,
    path: &str,
) -> Result<Got<'p>, Refusal> {
    let range = |reason: String| Refusal::Range {
        path: String::from(path),
        reason,
    };
    let mismatch = || Refusal::Type {
        path: String::from(path),
        reason: format!(
            "the field is {}, and {} was asked for",
            type_name(schema, field),
            wanted.word()
        ),
    };
    match (wanted, value) {
        (Wanted::Signed, View::Int(v)) => Ok(Got::Signed(v)),
        (Wanted::Signed, View::Uint(v)) => i64::try_from(v)
            .map(Got::Signed)
            .map_err(|_| range(format!("{v} does not fit a signed 64-bit integer"))),
        (Wanted::Unsigned, View::Uint(v)) => Ok(Got::Unsigned(v)),
        (Wanted::Unsigned, View::Int(v)) => u64::try_from(v).map(Got::Unsigned).map_err(|_| {
            range(format!(
                "{v} is negative, and an unsigned integer was asked for"
            ))
        }),
        (Wanted::Real, View::Float(v)) => Ok(Got::Real(f64::from(v))),
        (Wanted::Real, View::Double(v)) => Ok(Got::Real(v)),
        (Wanted::Bool, View::Bool(v)) => Ok(Got::Bool(v)),
        (Wanted::Text, View::Text(v)) => Ok(Got::Text(v)),
        (Wanted::Bytes, View::Bytes(v)) => Ok(Got::Bytes(v)),
        (Wanted::Text, View::Int(v)) => {
            let FieldKind::Enum(e) = field.kind else {
                return Err(mismatch());
            };
            let name = schema.enum_at(e).and_then(|info| {
                info.values
                    .iter()
                    .find(|(_, n)| *n == i128::from(v))
                    .map(|(name, _)| name.as_str())
            });
            name.map(Got::Text)
                .ok_or_else(|| range(format!("the enum has no name for the value {v}")))
        }
        _ => Err(mismatch()),
    }
}

/// One message of a schema set, its fields set and read by path.
///
/// `S` holds the schema: a `&SchemaSet`, or a shared owner of one for a
/// payload that outlives the borrow (an `Arc<SchemaSet>`). The message must be
/// one the same set found.
///
/// `St` is where it keeps its values ([`Storage`]): the heap, growing, for a payload [`Payload::new`]
/// makes, or a store of a fixed size a caller reserved ([`Payload::over`]), which refuses what does
/// not fit it ([`Refusal::Full`]) and takes nothing else after the payload is made.
pub struct Payload<S, St = HeapStorage> {
    schema: S,
    message: SchemaMessage,
    table: Table<St>,
    narrowing: Narrowing,
}

impl<S, St> fmt::Debug for Payload<S, St> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Payload")
            .field("message", &self.message)
            .field("values", &self.table.len)
            .field("bytes", &self.table.used)
            .finish()
    }
}

impl<S: Borrow<SchemaSet>> Payload<S, HeapStorage> {
    /// An empty payload of `message` of `schema`, kept on the heap, its integers held to their
    /// fields' types.
    pub fn new(schema: S, message: SchemaMessage) -> Self {
        Self::narrowed(schema, message, Narrowing::Type)
    }

    /// [`Payload::new`], its integers held to the range `narrowing` chooses: [`Narrowing::NanopbIntSize`]
    /// for a receiver that links nanopb. See the module documentation.
    pub fn narrowed(schema: S, message: SchemaMessage, narrowing: Narrowing) -> Self {
        Self::over(schema, message, narrowing, HeapStorage::default())
    }
}

impl<S: Borrow<SchemaSet>, St: Storage> Payload<S, St> {
    /// An empty payload of `message` of `schema` keeping its values in `store`, its integers held
    /// to the range `narrowing` chooses.
    pub fn over(schema: S, message: SchemaMessage, narrowing: Narrowing, store: St) -> Self {
        Self {
            schema,
            message,
            table: Table::new(store),
            narrowing,
        }
    }

    /// The full name of the payload's message.
    pub fn message_name(&self) -> &str {
        let schema: &SchemaSet = self.schema.borrow();
        schema.message_name(self.message)
    }

    /// Set the field `path` names to `value`; see the module documentation.
    ///
    /// # Errors
    ///
    /// [`Refusal::Path`], [`Refusal::Type`] or [`Refusal::Range`], and
    /// [`Refusal::Schema`] for an integer field whose range the payload's
    /// narrowing cannot know, and [`Refusal::Full`] when the store has no room for the value; the
    /// payload is then as it was.
    pub fn set(&mut self, path: &str, value: Given<'_>) -> Result<(), Refusal> {
        let schema: &SchemaSet = self.schema.borrow();
        let route = route(schema, schema.linked(self.message), path)?;
        let last = route.last;
        if last.repeated() && last.index.is_none() {
            return Err(list_named(path, &last));
        }
        let value = held_of(schema, last.holder, last.field, value, self.narrowing, path)?;
        let table = &mut self.table;
        // What the set adds is judged before anything is changed: a holder for each step that is
        // not there, a slot for a value that replaces none, and the bytes of a string or bytes that
        // the value it replaces does not have room for.
        let mut parent = Some(ROOT);
        let mut holders = 0usize;
        for step in route.inner() {
            let number = step.field.number;
            let len = parent.map_or(0, |p| table.count(p, number));
            if let Some(index) = step.index {
                if index > len {
                    return Err(reach_refused(path, &step, len));
                }
            }
            parent = parent
                .and_then(|p| table.nth(p, number, step.index.unwrap_or(0)))
                .filter(|&at| matches!(table.entry(at).map(|e| e.slot), Some(Slot::Message)))
                .map(parent_of);
            if parent.is_none() {
                holders += 1;
            }
        }
        let number = last.field.number;
        let len = parent.map_or(0, |p| table.count(p, number));
        if let Some(index) = last.index {
            if index > len {
                return Err(reach_refused(path, &last, len));
            }
        }
        let replaced = parent
            .and_then(|p| match last.index {
                Some(index) => table.nth(p, number, index),
                None => table.last(p, number),
            })
            .and_then(|at| table.entry(at));
        let room_there = match replaced.map(|e| e.slot) {
            Some(Slot::Text(span) | Slot::Bytes(span)) => span.len,
            _ => 0,
        };
        let bytes = match value {
            Value::Text(v) if v.len() > room_there => v.len(),
            Value::Bytes(v) if v.len() > room_there => v.len(),
            _ => 0,
        };
        let slots = holders + usize::from(replaced.is_none());
        let freed = if bytes > 0 { room_there } else { 0 };
        table
            .fits(slots, bytes, freed)
            .map_err(|no| no.refusal(path))?;
        // From here every write fits.
        let mut parent = ROOT;
        for step in route.inner() {
            parent = descend(table, parent, &step).map_err(|no| no.refusal(path))?;
        }
        table.clear_oneof(parent, last.holder, last.field);
        let at = match last.index {
            Some(index) => table.nth(parent, number, index),
            None => table.last(parent, number),
        };
        let mut old = at.and_then(|at| table.entry(at)).map(|e| e.slot);
        if let (Some(at), Some(Slot::Text(span) | Slot::Bytes(span))) = (at, old) {
            if span.len < value_len(value) {
                // The bytes the value replaced are let go before the new ones are written, which
                // is the room `fits` counted.
                table.set_slot(at, Slot::Free);
                old = None;
            }
        }
        let slot = table.slot_of(value, old).map_err(|no| no.refusal(path))?;
        match at {
            Some(at) => table.set_slot(at, slot),
            None => {
                table
                    .push(number, parent, slot)
                    .map_err(|no| no.refusal(path))?;
            }
        }
        Ok(())
    }

    /// The value of the field `path` names, read as `wanted`; see the module
    /// documentation.
    ///
    /// # Errors
    ///
    /// [`Refusal::Path`], [`Refusal::Type`], [`Refusal::Range`] or
    /// [`Refusal::Absent`].
    pub fn get(&self, path: &str, wanted: Wanted) -> Result<Got<'_>, Refusal> {
        let schema: &SchemaSet = self.schema.borrow();
        let route = route(schema, schema.linked(self.message), path)?;
        let last = route.last;
        if last.repeated() && last.index.is_none() {
            return Err(list_named(path, &last));
        }
        let Some(parent) = holder_of(&self.table, route.inner(), path)? else {
            return Err(absent(path, route.inner(), &self.table));
        };
        let index = last.index.unwrap_or(0);
        if let Some(entry) = self
            .table
            .nth(parent, last.field.number, index)
            .and_then(|at| self.table.entry(at))
        {
            return got(
                schema,
                last.field,
                view(&self.table, entry.slot),
                wanted,
                path,
            );
        }
        if last.index.is_some() {
            return Err(past_end(
                path,
                &last,
                self.table.count(parent, last.field.number),
            ));
        }
        if has_presence(last.holder, last.field) {
            return Err(Refusal::Absent {
                path: String::from(path),
                at: String::from(path),
            });
        }
        got(
            schema,
            last.field,
            default_view(schema, last.field),
            wanted,
            path,
        )
    }

    /// How many elements the repeated field `path` names holds; 0 when a
    /// message along the path is not there.
    ///
    /// # Errors
    ///
    /// [`Refusal::Path`] when the path names no repeated field, or names an
    /// element of one; [`Refusal::Range`] for an index along the path past the
    /// end of its list.
    pub fn count(&self, path: &str) -> Result<usize, Refusal> {
        let schema: &SchemaSet = self.schema.borrow();
        let route = route(schema, schema.linked(self.message), path)?;
        let last = route.last;
        if !last.repeated() {
            return Err(Refusal::Path {
                path: String::from(path),
                reason: format!("`{}` is not repeated: it has no count", last.field.name),
            });
        }
        if last.index.is_some() {
            return Err(Refusal::Path {
                path: String::from(path),
                reason: format!(
                    "this names one element; the count is of `{}`",
                    last.field.name
                ),
            });
        }
        Ok(holder_of(&self.table, route.inner(), path)?
            .map_or(0, |p| self.table.count(p, last.field.number)))
    }

    /// Clear the field `path` names (every element of a repeated one), or the
    /// one element it names, the elements after it moving down. Nothing to
    /// clear, where a message along the path is not there, is not refused.
    ///
    /// # Errors
    ///
    /// [`Refusal::Path`]; [`Refusal::Range`] for an index past the end of its
    /// list.
    pub fn clear(&mut self, path: &str) -> Result<(), Refusal> {
        let schema: &SchemaSet = self.schema.borrow();
        let route = route(schema, schema.linked(self.message), path)?;
        let last = route.last;
        let Some(parent) = holder_of(&self.table, route.inner(), path)? else {
            return Ok(());
        };
        let number = last.field.number;
        let len = self.table.count(parent, number);
        match last.index {
            None => self.table.remove_field(parent, number),
            Some(index) if index >= len => return Err(past_end(path, &last, len)),
            Some(index) => {
                if let Some(at) = self.table.nth(parent, number, index) {
                    self.table.remove(|i, _| i == at);
                }
            }
        }
        Ok(())
    }

    /// Clear every field: the payload is as it was made, its narrowing kept.
    pub fn reset(&mut self) {
        self.table.clear();
    }

    /// How many bytes [`Self::encode`] writes.
    ///
    /// # Errors
    ///
    /// As [`Self::encode`].
    pub fn encoded_len(&self) -> Result<usize, Refusal> {
        let mut count = Count::default();
        self.write_to(&mut count)?;
        Ok(count.0)
    }

    /// The protobuf bytes of the payload; see the module documentation.
    ///
    /// # Errors
    ///
    /// [`Refusal::Absent`] for a required field that is not set;
    /// [`Refusal::Schema`] for a `packed` option the writer cannot act on.
    pub fn encode(&self) -> Result<Vec<u8>, Refusal> {
        let mut out = Vec::with_capacity(self.encoded_len()?);
        self.write_to(&mut out)?;
        Ok(out)
    }

    /// The protobuf bytes of the payload written into `out` from its start, and how many there
    /// are, which is more than `out` holds when the bytes do not fit it: then what fits is written
    /// and the rest is not. Nothing is allocated.
    ///
    /// # Errors
    ///
    /// As [`Self::encode`].
    pub fn encode_into(&self, out: &mut [u8]) -> Result<usize, Refusal> {
        let mut fixed = Fixed::new(out);
        self.write_to(&mut fixed)?;
        Ok(fixed.len())
    }

    fn write_to<O: Out>(&self, out: &mut O) -> Result<(), Refusal> {
        let schema: &SchemaSet = self.schema.borrow();
        let writer = Writer {
            schema,
            table: &self.table,
            root: schema.linked(self.message),
        };
        writer.message(writer.root, ROOT, out)
    }

    /// Replace the payload's values with those `bytes` carry; see the module
    /// documentation.
    ///
    /// # Errors
    ///
    /// [`Refusal::Wire`] for bytes that are not a message of the schema; the
    /// payload is then as it was. [`Refusal::Full`] for bytes whose values do not fit the store;
    /// the payload is then empty.
    pub fn decode(&mut self, bytes: &[u8]) -> Result<(), Refusal> {
        let schema: &SchemaSet = self.schema.borrow();
        // The bytes are judged whole before a value is replaced.
        schema
            .walk_fields(self.message, bytes, &mut Judged)
            .map_err(Refusal::Wire)?;
        self.table.clear();
        let root = schema.linked(self.message);
        let mut fill = Fill {
            schema,
            table: &mut self.table,
            bytes,
            open: [None; MAX_DECODE_DEPTH + 1],
            depth: 0,
            full: None,
        };
        fill.open[0] = Some((ROOT, root));
        let walked = schema.walk_fields(self.message, bytes, &mut fill);
        let full = fill.full;
        if let Err(wire) = walked {
            // The first walk read the same bytes whole, so the second cannot be refused.
            self.table.clear();
            return Err(Refusal::Wire(wire));
        }
        if let Some(no) = full {
            self.table.clear();
            return Err(no.refusal(""));
        }
        Ok(())
    }
}

/// The refusal of a set whose index is past where an element is replaced or appended.
fn reach_refused(path: &str, step: &Step<'_>, len: usize) -> Refusal {
    Refusal::Range {
        path: String::from(path),
        reason: format!(
            "`{}` has {len} element(s): an element is replaced below {len} and appended at {len}, \
             and {} is past that",
            step.field.name,
            step.index.unwrap_or(0)
        ),
    }
}

fn list_named(path: &str, last: &Step<'_>) -> Refusal {
    let name = &last.field.name;
    Refusal::Path {
        path: String::from(path),
        reason: format!("`{name}` is repeated: name one of its elements, as `{name}[0]`"),
    }
}

fn past_end(path: &str, step: &Step<'_>, len: usize) -> Refusal {
    Refusal::Range {
        path: String::from(path),
        reason: format!(
            "`{}` has {len} element(s), so the index {} is past its end",
            step.field.name,
            step.index.unwrap_or(0)
        ),
    }
}

/// The slot of the message that holds the last step's field (`ROOT` for the payload's own),
/// `None` when one along the way is not there.
fn holder_of<'s, St: Storage>(
    table: &Table<St>,
    inner: impl Iterator<Item = Step<'s>>,
    path: &str,
) -> Result<Option<u32>, Refusal> {
    let mut at = ROOT;
    for step in inner {
        let number = step.field.number;
        let index = step.index.unwrap_or(0);
        match table
            .nth(at, number, index)
            .and_then(|i| table.entry(i).map(|e| (i, e)))
        {
            Some((
                i,
                Entry {
                    slot: Slot::Message,
                    ..
                },
            )) => at = parent_of(i),
            Some(_) => return Ok(None),
            None if step.index.is_some() => {
                return Err(past_end(path, &step, table.count(at, number)))
            }
            None => return Ok(None),
        }
    }
    Ok(Some(at))
}

/// The refusal of a read whose holder is not there, naming the first part of
/// the path that is absent.
fn absent<'s, St: Storage>(
    path: &str,
    inner: impl Iterator<Item = Step<'s>>,
    table: &Table<St>,
) -> Refusal {
    let mut at = ROOT;
    for step in inner {
        let found = table
            .nth(at, step.field.number, step.index.unwrap_or(0))
            .and_then(|i| table.entry(i).map(|e| (i, e)));
        match found {
            Some((
                i,
                Entry {
                    slot: Slot::Message,
                    ..
                },
            )) => at = parent_of(i),
            _ => {
                return Refusal::Absent {
                    path: String::from(path),
                    at: String::from(path.get(..step.end).unwrap_or(path)),
                }
            }
        }
    }
    Refusal::Absent {
        path: String::from(path),
        at: String::from(path),
    }
}

/// The message a step of a set goes into, made when it is not there; the
/// index was judged before, and the room.
fn descend<St: Storage>(
    table: &mut Table<St>,
    parent: u32,
    step: &Step<'_>,
) -> Result<u32, NoRoom> {
    let number = step.field.number;
    if step.index.is_none() && table.count(parent, number) == 0 {
        table.clear_oneof(parent, step.holder, step.field);
    }
    let at = match table.nth(parent, number, step.index.unwrap_or(0)) {
        Some(at) => at,
        None => table.push(number, parent, Slot::Message)?,
    };
    if !matches!(table.entry(at).map(|e| e.slot), Some(Slot::Message)) {
        table.set_slot(at, Slot::Message);
    }
    Ok(parent_of(at))
}

/// A slot's value as it is read.
fn view<St: Storage>(table: &Table<St>, slot: Slot) -> View<'_> {
    match slot {
        Slot::Int(v) => View::Int(v),
        Slot::Uint(v) => View::Uint(v),
        Slot::Float(v) => View::Float(v),
        Slot::Double(v) => View::Double(v),
        Slot::Bool(v) => View::Bool(v),
        Slot::Text(span) => View::Text(table.text_of(span)),
        Slot::Bytes(span) => View::Bytes(table.bytes_of(span)),
        Slot::Message | Slot::Free | Slot::Kept(_) => View::Message,
    }
}

// ---- the bytes ------------------------------------------------------------

/// The writer of a payload's bytes, from its table.
struct Writer<'w, St> {
    schema: &'w SchemaSet,
    table: &'w Table<St>,
    root: &'w Msg,
}

impl<St: Storage> Writer<'_, St> {
    /// The wire form of one value of `field`, from the one writer; `None` for a message, which is
    /// written by its fields.
    fn wire_of(&self, field: &Fld, slot: Slot, at: usize) -> Result<Option<Wire<'_>>, Refusal> {
        let integer =
            |kind: ScalarKind, v: i128| ValueRange::of_type(kind).map(|_| Wire::integer(kind, v));
        let wire = match (field.kind, slot) {
            (FieldKind::Message(_), Slot::Message) => return Ok(None),
            (FieldKind::Scalar(kind), Slot::Int(v)) => integer(kind, i128::from(v)),
            (FieldKind::Scalar(kind), Slot::Uint(v)) => integer(kind, i128::from(v)),
            (FieldKind::Enum(_), Slot::Int(v)) => i32::try_from(v).ok().map(Wire::enum_number),
            (FieldKind::Scalar(ScalarKind::Float), Slot::Float(v)) => {
                Some(Wire::Fixed32(v.to_bits()))
            }
            (FieldKind::Scalar(ScalarKind::Double), Slot::Double(v)) => {
                Some(Wire::Fixed64(v.to_bits()))
            }
            (FieldKind::Scalar(ScalarKind::Bool), Slot::Bool(v)) => {
                Some(Wire::Varint(u64::from(v)))
            }
            (FieldKind::Scalar(ScalarKind::String), Slot::Text(span))
            | (FieldKind::Scalar(ScalarKind::Bytes), Slot::Bytes(span)) => {
                Some(Wire::delimited(self.table.bytes_of(span)))
            }
            _ => None,
        };
        wire.map(Some).ok_or_else(|| Refusal::Type {
            path: self.path_of(at),
            reason: format!("the field is {}", type_name(self.schema, field)),
        })
    }

    /// The fields of the message `msg` at `parent`, in ascending number, then what it keeps as
    /// wire bytes.
    fn message<O: Out>(&self, msg: &Msg, parent: u32, out: &mut O) -> Result<(), Refusal> {
        for field in &msg.fields {
            if field.label == Label::Required && self.table.count(parent, field.number) == 0 {
                let path = self.child_path(parent, &field.name);
                return Err(Refusal::Absent {
                    at: path.clone(),
                    path,
                });
            }
        }
        let mut after: Option<u64> = None;
        loop {
            let next = self
                .table
                .live()
                .iter()
                .filter(|e| e.parent == parent && !matches!(e.slot, Slot::Kept(_)))
                .map(|e| e.number)
                .filter(|&n| after.map_or(true, |a| n > a))
                .min();
            let Some(number) = next else {
                break;
            };
            after = Some(number);
            let Some(field) = msg.fields.iter().find(|f| f.number == number) else {
                continue;
            };
            self.field(msg, field, parent, out)?;
        }
        for entry in self.table.live().iter().filter(|e| e.parent == parent) {
            if let Slot::Kept(span) = entry.slot {
                out.put_slice(self.table.bytes_of(span));
            }
        }
        Ok(())
    }

    /// The values field `field` of `msg` holds in the message at `parent`.
    fn field<O: Out>(
        &self,
        msg: &Msg,
        field: &Fld,
        parent: u32,
        out: &mut O,
    ) -> Result<(), Refusal> {
        let number = field.number;
        if field.label != Label::Repeated {
            let Some(at) = self.table.last(parent, number) else {
                return Ok(());
            };
            return self.value(field, at, has_presence(msg, field), out);
        }
        let packed = proto_write::packed(msg, field).map_err(|_| Refusal::Schema {
            path: self.child_path(parent, &field.name),
            reason: format!(
                "`{}` states `packed`, which takes `true` or `false`, and `true` only on a \
                 repeated numeric, bool or enum field",
                field.name
            ),
        })?;
        if !packed {
            for at in self.table.values(parent, number) {
                self.value(field, at, true, out)?;
            }
            return Ok(());
        }
        // A run is counted before it is written, so nothing is gathered apart.
        let mut run = Count::default();
        for at in self.table.values(parent, number) {
            if let Some(wire) = self.wire_of(field, self.slot(at), at)? {
                wire.put(&mut run);
            }
        }
        if run.0 == 0 && self.table.count(parent, number) == 0 {
            return Ok(());
        }
        proto_write::put_tag(out, number, proto_write::WIRE_LEN);
        proto_write::put_varint(out, run.0 as u64);
        for at in self.table.values(parent, number) {
            if let Some(wire) = self.wire_of(field, self.slot(at), at)? {
                wire.put(out);
            }
        }
        Ok(())
    }

    /// One value of `field`, at slot `at`, under its tag: a message as its length and its fields.
    fn value<O: Out>(
        &self,
        field: &Fld,
        at: usize,
        presence: bool,
        out: &mut O,
    ) -> Result<(), Refusal> {
        if let Some(wire) = self.wire_of(field, self.slot(at), at)? {
            proto_write::put_singular(out, field.number, presence, &wire);
            return Ok(());
        }
        let FieldKind::Message(m) = field.kind else {
            return Ok(());
        };
        let Some(inner) = self.schema.linked_at(m) else {
            return Err(Refusal::Schema {
                path: self.path_of(at),
                reason: String::from("the field's message is not in the schema set"),
            });
        };
        let mut length = Count::default();
        self.message(inner, parent_of(at), &mut length)?;
        proto_write::put_tag(out, field.number, proto_write::WIRE_LEN);
        proto_write::put_varint(out, length.0 as u64);
        self.message(inner, parent_of(at), out)
    }

    fn slot(&self, at: usize) -> Slot {
        self.table.entry(at).map_or(Slot::Free, |e| e.slot)
    }

    /// The path of the value at slot `at`, written for a refusal.
    fn path_of(&self, at: usize) -> String {
        let Some(entry) = self.table.entry(at) else {
            return String::new();
        };
        let (holder, prefix) = self.holder_and_path(entry.parent);
        let Some(field) = holder.and_then(|m| m.fields.iter().find(|f| f.number == entry.number))
        else {
            return prefix;
        };
        let mut path = child(&prefix, &field.name);
        if field.label == Label::Repeated {
            let index = self
                .table
                .values(entry.parent, entry.number)
                .position(|i| i == at)
                .unwrap_or(0);
            path = format!("{path}[{index}]");
        }
        path
    }

    /// The path of field `name` of the message at `parent`, written for a refusal.
    fn child_path(&self, parent: u32, name: &str) -> String {
        child(&self.holder_and_path(parent).1, name)
    }

    /// The message type of the message at `parent` and its path.
    fn holder_and_path(&self, parent: u32) -> (Option<&Msg>, String) {
        if parent == ROOT {
            return (Some(self.root), String::new());
        }
        let at = parent as usize;
        let path = self.path_of(at);
        let Some(entry) = self.table.entry(at) else {
            return (None, path);
        };
        let (outer, _) = self.holder_and_path(entry.parent);
        let inner = outer
            .and_then(|m| m.fields.iter().find(|f| f.number == entry.number))
            .and_then(|f| match f.kind {
                FieldKind::Message(m) => self.schema.linked_at(m),
                _ => None,
            });
        (inner, path)
    }
}

/// The path of field `name` inside the message at `prefix`.
fn child(prefix: &str, name: &str) -> String {
    if prefix.is_empty() {
        String::from(name)
    } else {
        format!("{prefix}.{name}")
    }
}

// ---- decoding -------------------------------------------------------------

/// The first walk of bytes being decoded, which only judges them.
struct Judged;

impl<'b> FieldEvents<'b> for Judged {
    fn value(&mut self, _number: u64, _item: Item<'b>) {}
    fn kept(&mut self, _span: (usize, usize)) {}
    fn enter(&mut self, _number: u64) {}
    fn leave(&mut self) {}
}

/// The walk that fills a payload's table from bytes, as a parser keeps them: an element appended
/// to a repeated field, a message merged into the one there, any other value replacing it, and
/// what the payload does not address kept as its wire bytes.
struct Fill<'f, St> {
    schema: &'f SchemaSet,
    table: &'f mut Table<St>,
    bytes: &'f [u8],
    /// The messages the walk is inside, the payload's own first: each one's slot and type, `None`
    /// past the depth the walk is at, and for a message the payload does not address (whose
    /// fields are then not read).
    open: [Option<(u32, &'f Msg)>; MAX_DECODE_DEPTH + 1],
    depth: usize,
    /// What did not fit, after which nothing more is kept.
    full: Option<NoRoom>,
}

impl<'f, St: Storage> Fill<'f, St> {
    fn current(&self) -> Option<(u32, &'f Msg)> {
        self.open.get(self.depth).copied().flatten()
    }

    fn keep(&mut self, result: Result<usize, NoRoom>) {
        if let Err(no) = result {
            self.full = Some(no);
        }
    }
}

impl<'b, St: Storage> FieldEvents<'b> for Fill<'_, St> {
    fn value(&mut self, number: u64, item: Item<'b>) {
        if self.full.is_some() {
            return;
        }
        let Some((parent, msg)) = self.current() else {
            return;
        };
        let Some(field) = msg.fields.iter().find(|f| f.number == number) else {
            return;
        };
        let value = match item {
            Item::Signed(v) => Value::Int(v),
            Item::Unsigned(v) => Value::Uint(v),
            Item::Float(v) => Value::Float(v),
            Item::Double(v) => Value::Double(v),
            Item::Bool(v) => Value::Bool(v),
            Item::Text(v) => Value::Text(v),
            Item::Bytes(v) => Value::Bytes(v),
            Item::Enum(v) => Value::Int(i64::from(v)),
        };
        let slot = match self.table.slot_of(value, None) {
            Ok(slot) => slot,
            Err(no) => {
                self.full = Some(no);
                return;
            }
        };
        if field.label != Label::Repeated {
            self.table.clear_oneof(parent, msg, field);
            self.table.remove_field(parent, number);
        }
        let pushed = self.table.push(number, parent, slot);
        self.keep(pushed);
    }

    fn kept(&mut self, span: (usize, usize)) {
        if self.full.is_some() {
            return;
        }
        let Some((parent, _)) = self.current() else {
            return;
        };
        let data = self.bytes.get(span.0..span.1).unwrap_or_default();
        let kept = self
            .table
            .write(data)
            .and_then(|span| self.table.push(0, parent, Slot::Kept(span)));
        self.keep(kept);
    }

    fn enter(&mut self, number: u64) {
        let opened = match (self.full, self.current()) {
            (None, Some((parent, msg))) => self.open_message(parent, msg, number),
            _ => None,
        };
        self.depth += 1;
        if let Some(slot) = self.open.get_mut(self.depth) {
            *slot = opened;
        }
    }

    fn leave(&mut self) {
        if let Some(slot) = self.open.get_mut(self.depth) {
            *slot = None;
        }
        self.depth = self.depth.saturating_sub(1);
    }
}

impl<'f, St: Storage> Fill<'f, St> {
    /// The message field `number` of `msg` at `parent` begins: the slot its values go under, the
    /// one a singular field holds already when it does, and its type.
    fn open_message(&mut self, parent: u32, msg: &'f Msg, number: u64) -> Option<(u32, &'f Msg)> {
        let field = msg.fields.iter().find(|f| f.number == number)?;
        let FieldKind::Message(m) = field.kind else {
            return None;
        };
        let inner = self.schema.linked_at(m)?;
        let at = if field.label == Label::Repeated {
            self.table.push(number, parent, Slot::Message)
        } else {
            self.table.clear_oneof(parent, msg, field);
            match self.table.last(parent, number) {
                Some(at) => Ok(at),
                None => self.table.push(number, parent, Slot::Message),
            }
        };
        match at {
            Ok(at) => Some((parent_of(at), inner)),
            Err(no) => {
                self.full = Some(no);
                None
            }
        }
    }
}
