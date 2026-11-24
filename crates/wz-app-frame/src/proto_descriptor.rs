// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The `FileDescriptorSet` `protoc` compiles a schema into (`protoc -o`), read
//! into the type tables the typed reader and the writer read: a schema compiled
//! when the program is built, handed over as bytes, with no `.proto` text read
//! when it runs.
//!
//! ## Why the protobuf reader reads it
//!
//! A descriptor set is itself a protobuf message (`google/protobuf/descriptor.proto`),
//! so it is read by the typed reader every payload is read by
//! ([`crate::proto_decode`]), under a schema of the part of `descriptor.proto` this
//! module needs, built here as tables. A field that schema does not name is listed
//! without a name, and this module skips it: JSON names, source info, default
//! values, reserved and extension ranges, extensions and services change nothing a
//! payload is read or written by.
//!
//! ## What it gives
//!
//! The tables the `.proto` text reader links from the text the set was compiled
//! from (the tests hold the two to each other): every message and enum of every
//! file, at the indices the text reader gives them; a `map` field as a map, not as
//! the entry message `protoc` writes for it; a proto3 `optional` field as a field
//! with presence, not as the member of the oneof `protoc` makes for it. Of the
//! options, those the readers act on are carried, named as a `.proto` file writes
//! them: `packed` and `deprecated` of a field, `deprecated` of a message, and
//! nanopb's options at the three levels it sets them (`(nanopb).int_size` and the
//! rest), which `protoc` keeps as field 1010 of each options message. Every other
//! option is left out, and so is every comment.
//!
//! ## What is refused
//!
//! Bytes that are not a `FileDescriptorSet` (the typed reader's refusal, at its
//! byte); two files of one name; a file that imports one the set does not carry
//! (compiled without `--include_imports`); editions and weak imports, which the
//! text reader refuses too; a field number outside `1..=2^29 - 1`, in the range the
//! protobuf library reserves, or used twice in one message; a type the set does not
//! define, or of the other kind; a field type or label `descriptor.proto` does not
//! have; a map entry used as anything but a repeated field, or whose key or value is
//! not one a map may have; two types of one full name. Each refusal names the file
//! it is in.

use alloc::collections::btree_map::Entry;
use alloc::collections::{BTreeMap, BTreeSet};
use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;

use crate::proto_decode::{DecodedField, SchemaSet, Value};
use crate::proto_types::{
    EnumInfo, FieldKind, FieldOption, Fld, Label, MapValueKind, Msg, OptionValue, Pos,
    ProtoDiagnostic, ScalarKind, Syntax, MAX_FIELD_NUMBER,
};

// The messages of the schema of `descriptor.proto` this module reads by, at their
// indices in the tables `meta_schema` builds.
const FILE: usize = 1;
const MESSAGE: usize = 2;
const FIELD: usize = 3;
const ONEOF: usize = 4;
const ENUM: usize = 5;
const ENUM_VALUE: usize = 6;
const FILE_OPTIONS: usize = 7;
const MESSAGE_OPTIONS: usize = 8;
const FIELD_OPTIONS: usize = 9;
const NANOPB: usize = 10;

/// The field number nanopb's options extend each options message with.
const NANOPB_EXTENSION: u64 = 1010;

// `FieldDescriptorProto.Label`.
const LABEL_OPTIONAL: i64 = 1;
const LABEL_REQUIRED: i64 = 2;
const LABEL_REPEATED: i64 = 3;

// The `FieldDescriptorProto.Type` values that are not a scalar.
const TYPE_GROUP: i64 = 10;
const TYPE_MESSAGE: i64 = 11;
const TYPE_ENUM: i64 = 14;

impl SchemaSet {
    /// Read a `FileDescriptorSet`, the bytes `protoc --include_imports -o` writes,
    /// into the tables the `.proto` text reader would link from the same files.
    ///
    /// # Errors
    ///
    /// The first problem found (see the module documentation), naming the file it
    /// is in when it is in one.
    pub fn from_descriptor_set(bytes: &[u8]) -> Result<Self, ProtoDiagnostic> {
        let meta = meta_schema();
        let root = meta
            .message("google.protobuf.FileDescriptorSet")
            .map_err(ProtoDiagnostic::argument)?;
        let listing = meta.decode(root, bytes).map_err(|e| {
            ProtoDiagnostic::argument(format!("the bytes are not a FileDescriptorSet: {e}"))
        })?;
        let mut reader = Reader::default();
        for file in messages(&listing, 1) {
            reader.file(file)?;
        }
        reader.check_imports()?;
        reader.register()?;
        reader.link()
    }
}

/// The part of `descriptor.proto` (and of nanopb's options) this module reads, as
/// the tables the typed reader reads every message by. Every number is
/// `descriptor.proto`'s; the names are only for the reader's listing.
fn meta_schema() -> SchemaSet {
    use FieldKind::{Message as M, Scalar as S};
    use ScalarKind::{Bool, Int32, String as Text};
    let one = |name: &str, number: u64, kind: FieldKind| {
        Fld::new(
            String::from(name),
            number,
            kind,
            Label::Optional,
            None,
            Vec::new(),
        )
    };
    let many = |name: &str, number: u64, kind: FieldKind| {
        Fld::new(
            String::from(name),
            number,
            kind,
            Label::Repeated,
            None,
            Vec::new(),
        )
    };
    let table = |name: &str, fields: Vec<Fld>| {
        Msg::new(
            format!("google.protobuf.{name}"),
            0,
            None,
            Syntax::Proto2,
            fields,
            Vec::new(),
            Vec::new(),
        )
    };
    let nanopb = || one("nanopb", NANOPB_EXTENSION, M(NANOPB));
    let msgs = alloc::vec![
        table("FileDescriptorSet", alloc::vec![many("file", 1, M(FILE))]),
        table(
            "FileDescriptorProto",
            alloc::vec![
                one("name", 1, S(Text)),
                one("package", 2, S(Text)),
                many("dependency", 3, S(Text)),
                many("message_type", 4, M(MESSAGE)),
                many("enum_type", 5, M(ENUM)),
                one("options", 8, M(FILE_OPTIONS)),
                many("weak_dependency", 11, S(Int32)),
                one("syntax", 12, S(Text)),
                one("edition", 14, S(Int32)),
            ],
        ),
        table(
            "DescriptorProto",
            alloc::vec![
                one("name", 1, S(Text)),
                many("field", 2, M(FIELD)),
                many("nested_type", 3, M(MESSAGE)),
                many("enum_type", 4, M(ENUM)),
                one("options", 7, M(MESSAGE_OPTIONS)),
                many("oneof_decl", 8, M(ONEOF)),
            ],
        ),
        table(
            "FieldDescriptorProto",
            alloc::vec![
                one("name", 1, S(Text)),
                one("number", 3, S(Int32)),
                one("label", 4, S(Int32)),
                one("type", 5, S(Int32)),
                one("type_name", 6, S(Text)),
                one("options", 8, M(FIELD_OPTIONS)),
                one("oneof_index", 9, S(Int32)),
                one("proto3_optional", 17, S(Bool)),
            ],
        ),
        table("OneofDescriptorProto", alloc::vec![one("name", 1, S(Text))]),
        table(
            "EnumDescriptorProto",
            alloc::vec![one("name", 1, S(Text)), many("value", 2, M(ENUM_VALUE))],
        ),
        table(
            "EnumValueDescriptorProto",
            alloc::vec![one("name", 1, S(Text)), one("number", 2, S(Int32))],
        ),
        table("FileOptions", alloc::vec![nanopb()]),
        table(
            "MessageOptions",
            alloc::vec![
                one("deprecated", 3, S(Bool)),
                one("map_entry", 7, S(Bool)),
                nanopb(),
            ],
        ),
        table(
            "FieldOptions",
            alloc::vec![
                one("packed", 2, S(Bool)),
                one("deprecated", 3, S(Bool)),
                nanopb(),
            ],
        ),
        table(
            "NanoPBOptions",
            alloc::vec![
                one("max_size", 1, S(Int32)),
                one("max_count", 2, S(Int32)),
                one("type", 3, S(Int32)),
                one("skip_message", 6, S(Bool)),
                one("int_size", 7, S(Int32)),
                one("no_unions", 8, S(Bool)),
                one("max_length", 14, S(Int32)),
                one("type_override", 27, S(Int32)),
                one("label_override", 31, S(Int32)),
                one("discard_deprecated", 35, S(Bool)),
            ],
        ),
    ];
    SchemaSet::from_tables(msgs, Vec::new(), Vec::new())
}

// ---- reading a listing ------------------------------------------------------

/// Every message the listing holds at `number`, in the order of the wire.
fn messages(
    listing: &[DecodedField],
    number: u64,
) -> impl DoubleEndedIterator<Item = &[DecodedField]> {
    listing.iter().filter_map(move |f| match &f.value {
        Value::Message(inner) if f.number == number => Some(inner.as_slice()),
        _ => None,
    })
}

/// The message at `number`, the last one when the wire holds several.
fn message(listing: &[DecodedField], number: u64) -> Option<&[DecodedField]> {
    messages(listing, number).next_back()
}

/// Every string at `number`, in the order of the wire.
fn texts(listing: &[DecodedField], number: u64) -> impl DoubleEndedIterator<Item = &str> {
    listing.iter().filter_map(move |f| match &f.value {
        Value::Text(text) if f.number == number => Some(text.as_str()),
        _ => None,
    })
}

/// The string at `number`, the last one when the wire holds several.
fn text(listing: &[DecodedField], number: u64) -> Option<&str> {
    texts(listing, number).next_back()
}

/// Every integer at `number`, in the order of the wire.
fn ints(listing: &[DecodedField], number: u64) -> impl DoubleEndedIterator<Item = i64> + '_ {
    listing.iter().filter_map(move |f| match f.value {
        Value::Signed(n) if f.number == number => Some(n),
        _ => None,
    })
}

/// The integer at `number`, the last one when the wire holds several.
fn int(listing: &[DecodedField], number: u64) -> Option<i64> {
    ints(listing, number).next_back()
}

/// The boolean at `number`, the last one when the wire holds several.
fn flag(listing: &[DecodedField], number: u64) -> Option<bool> {
    listing
        .iter()
        .filter_map(|f| match f.value {
            Value::Bool(b) if f.number == number => Some(b),
            _ => None,
        })
        .next_back()
}

/// `scope.name`, or `name` at the root.
fn join(scope: &str, name: &str) -> String {
    if scope.is_empty() {
        String::from(name)
    } else {
        format!("{scope}.{name}")
    }
}

// ---- the options a reader acts on ------------------------------------------

/// An option named and valued as a `.proto` file writes it.
fn option(name: String, value: OptionValue) -> FieldOption {
    FieldOption {
        name,
        value,
        value_pos: Pos::NOWHERE,
    }
}

fn word(word: &str) -> OptionValue {
    OptionValue::Ident(String::from(word))
}

fn boolean(b: bool) -> OptionValue {
    word(if b { "true" } else { "false" })
}

/// nanopb's options as the extension `(extension)` sets them, one option per
/// member set, in the order of the wire. An enumeration is its value's name, as a
/// `.proto` file writes it, and a number when nanopb has no name for it.
fn nanopb_options(out: &mut Vec<FieldOption>, extension: &str, set: &[DecodedField]) {
    for member in set {
        let key = match member.number {
            1 => "max_size",
            2 => "max_count",
            3 => "type",
            6 => "skip_message",
            7 => "int_size",
            8 => "no_unions",
            14 => "max_length",
            27 => "type_override",
            31 => "label_override",
            35 => "discard_deprecated",
            _ => continue,
        };
        let value = match (&member.value, key) {
            (Value::Signed(n), "int_size") => match *n {
                0 => word("IS_DEFAULT"),
                8 => word("IS_8"),
                16 => word("IS_16"),
                32 => word("IS_32"),
                64 => word("IS_64"),
                _ => OptionValue::Int(i128::from(*n)),
            },
            (Value::Signed(n), "type") => match *n {
                0 => word("FT_DEFAULT"),
                1 => word("FT_CALLBACK"),
                2 => word("FT_STATIC"),
                3 => word("FT_IGNORE"),
                4 => word("FT_POINTER"),
                5 => word("FT_INLINE"),
                _ => OptionValue::Int(i128::from(*n)),
            },
            (Value::Signed(n), _) => OptionValue::Int(i128::from(*n)),
            (Value::Bool(b), _) => boolean(*b),
            _ => continue,
        };
        out.push(option(format!("({extension}).{key}"), value));
    }
}

/// The options of an options message that a reader acts on: the plain ones
/// `plain` names by field number, and nanopb's under `extension`.
fn options_of(
    listing: Option<&[DecodedField]>,
    plain: &[(u64, &str)],
    extension: &str,
) -> Vec<FieldOption> {
    let mut out = Vec::new();
    for member in listing.unwrap_or(&[]) {
        if member.number == NANOPB_EXTENSION {
            if let Value::Message(set) = &member.value {
                nanopb_options(&mut out, extension, set);
            }
            continue;
        }
        let Some((_, name)) = plain.iter().find(|(number, _)| *number == member.number) else {
            continue;
        };
        if let Value::Bool(b) = member.value {
            out.push(option(String::from(*name), boolean(b)));
        }
    }
    out
}

// ---- the reader -------------------------------------------------------------

/// One file of the set, as far as the tables need it.
struct FileIn<'d> {
    name: &'d str,
    package: &'d str,
    syntax: Syntax,
    imports: Vec<&'d str>,
    messages: Vec<&'d [DecodedField]>,
    enums: Vec<&'d [DecodedField]>,
    options: Vec<FieldOption>,
}

/// A message to link, in the order the text reader registers messages.
struct MessageIn<'d> {
    full_name: String,
    file: usize,
    parent: Option<usize>,
    desc: &'d [DecodedField],
}

/// What a full name stands for.
#[derive(Clone, Copy)]
enum Named<'d> {
    Message(usize),
    Enum(usize),
    /// The entry message `protoc` writes for a `map` field: its own listing.
    Entry(&'d [DecodedField]),
}

#[derive(Default)]
struct Reader<'d> {
    files: Vec<FileIn<'d>>,
    names: BTreeMap<String, Named<'d>>,
    messages: Vec<MessageIn<'d>>,
    enums: Vec<EnumInfo>,
}

impl<'d> Reader<'d> {
    fn refuse(&self, file: usize, reason: String) -> ProtoDiagnostic {
        ProtoDiagnostic::in_file(self.files[file].name, reason)
    }

    /// Take one `FileDescriptorProto`, refusing what this reader does not read.
    fn file(&mut self, desc: &'d [DecodedField]) -> Result<(), ProtoDiagnostic> {
        let Some(name) = text(desc, 1) else {
            return Err(ProtoDiagnostic::argument(
                "a file of the descriptor set has no name",
            ));
        };
        let refuse = |reason: &str| ProtoDiagnostic::in_file(name, reason);
        if self.files.iter().any(|f| f.name == name) {
            return Err(refuse(
                "the descriptor set holds two files of this name: imports are resolved by name, so \
                 each name can stand for one file",
            ));
        }
        let syntax = match text(desc, 12) {
            None | Some("" | "proto2") => Syntax::Proto2,
            Some("proto3") => Syntax::Proto3,
            Some("editions") => return Err(refuse("editions are not supported")),
            Some(other) => {
                return Err(ProtoDiagnostic::in_file(
                    name,
                    format!("the syntax \"{other}\" is not proto2 or proto3"),
                ))
            }
        };
        if int(desc, 14).is_some() {
            return Err(refuse("editions are not supported"));
        }
        if ints(desc, 11).next().is_some() {
            return Err(refuse(
                "a weak import is not supported: a build may leave the file it names out, so the \
                 names it would declare cannot be relied on",
            ));
        }
        self.files.push(FileIn {
            name,
            package: text(desc, 2).unwrap_or(""),
            syntax,
            imports: texts(desc, 3).collect(),
            messages: messages(desc, 4).collect(),
            enums: messages(desc, 5).collect(),
            options: options_of(message(desc, 8), &[], "nanopb_fileopt"),
        });
        Ok(())
    }

    /// Every import names a file of the set.
    fn check_imports(&self) -> Result<(), ProtoDiagnostic> {
        for (at, file) in self.files.iter().enumerate() {
            for import in &file.imports {
                if !self.files.iter().any(|f| f.name == *import) {
                    return Err(self.refuse(
                        at,
                        format!(
                            "it imports \"{import}\", which the descriptor set does not hold: \
                             compile the schema with protoc --include_imports"
                        ),
                    ));
                }
            }
        }
        Ok(())
    }

    fn declare(
        &mut self,
        file: usize,
        full: String,
        named: Named<'d>,
    ) -> Result<(), ProtoDiagnostic> {
        let file_name = self.files[file].name;
        match self.names.entry(full) {
            Entry::Occupied(taken) => Err(ProtoDiagnostic::in_file(
                file_name,
                format!("\"{}\" is defined twice in the descriptor set", taken.key()),
            )),
            Entry::Vacant(slot) => {
                slot.insert(named);
                Ok(())
            }
        }
    }

    /// Register every message and enum, in the order the text reader does: the
    /// files in the order of the set; in a file its messages, then its enums; in a
    /// message itself, its nested messages, then its enums.
    fn register(&mut self) -> Result<(), ProtoDiagnostic> {
        for file in 0..self.files.len() {
            let package = self.files[file].package;
            let (messages, enums) = (
                self.files[file].messages.clone(),
                self.files[file].enums.clone(),
            );
            for desc in messages {
                self.register_message(file, package, None, desc)?;
            }
            for desc in enums {
                self.register_enum(file, package, desc)?;
            }
        }
        Ok(())
    }

    fn register_message(
        &mut self,
        file: usize,
        scope: &str,
        parent: Option<usize>,
        desc: &'d [DecodedField],
    ) -> Result<(), ProtoDiagnostic> {
        let Some(name) = text(desc, 1) else {
            return Err(self.refuse(file, format!("a message in \"{scope}\" has no name")));
        };
        let full = join(scope, name);
        if message(desc, 7).and_then(|options| flag(options, 7)) == Some(true) {
            return self.declare(file, full, Named::Entry(desc));
        }
        let idx = self.messages.len();
        self.messages.push(MessageIn {
            full_name: full.clone(),
            file,
            parent,
            desc,
        });
        self.declare(file, full.clone(), Named::Message(idx))?;
        for nested in messages(desc, 3) {
            self.register_message(file, &full, Some(idx), nested)?;
        }
        for inner in messages(desc, 4) {
            self.register_enum(file, &full, inner)?;
        }
        Ok(())
    }

    fn register_enum(
        &mut self,
        file: usize,
        scope: &str,
        desc: &[DecodedField],
    ) -> Result<(), ProtoDiagnostic> {
        let Some(name) = text(desc, 1) else {
            return Err(self.refuse(file, format!("an enum in \"{scope}\" has no name")));
        };
        let full = join(scope, name);
        let mut values = Vec::new();
        for value in messages(desc, 2) {
            let (Some(value_name), Some(number)) = (text(value, 1), int(value, 2)) else {
                return Err(self.refuse(
                    file,
                    format!("a value of the enum \"{full}\" has no name or no number"),
                ));
            };
            values.push((String::from(value_name), i128::from(number)));
        }
        let idx = self.enums.len();
        self.enums.push(EnumInfo {
            full_name: full.clone(),
            syntax: self.files[file].syntax,
            values,
        });
        self.declare(file, full, Named::Enum(idx))
    }

    /// What the full type name `written` (`.pkg.Outer.Inner`) stands for.
    fn resolve(&self, file: usize, written: &str) -> Result<Named<'d>, ProtoDiagnostic> {
        let Some(full) = written.strip_prefix('.') else {
            return Err(self.refuse(
                file,
                format!(
                    "the type name \"{written}\" is not a full name (protoc writes a leading dot)"
                ),
            ));
        };
        self.names.get(full).copied().ok_or_else(|| {
            self.refuse(
                file,
                format!("\"{written}\" is not defined in the descriptor set"),
            )
        })
    }

    /// The message a field of message type names, by its `type_name`.
    fn message_type(
        &self,
        file: usize,
        field: &str,
        desc: &[DecodedField],
    ) -> Result<Named<'d>, ProtoDiagnostic> {
        let Some(written) = text(desc, 6) else {
            return Err(self.refuse(file, format!("the field \"{field}\" names no type")));
        };
        self.resolve(file, written)
    }

    /// The kind of a field whose type is `ty`: a scalar, an enum or a message;
    /// a map is the caller's, which knows the label.
    fn kind(
        &self,
        file: usize,
        field: &str,
        ty: i64,
        desc: &[DecodedField],
    ) -> Result<FieldKind, ProtoDiagnostic> {
        if let Some(scalar) = scalar(ty) {
            return Ok(FieldKind::Scalar(scalar));
        }
        match ty {
            TYPE_GROUP => Ok(FieldKind::Group),
            TYPE_MESSAGE => match self.message_type(file, field, desc)? {
                Named::Message(target) => Ok(FieldKind::Message(target)),
                Named::Entry(..) => Err(self.refuse(
                    file,
                    format!("the field \"{field}\" holds a map entry and is not repeated"),
                )),
                Named::Enum(_) => Err(self.refuse(
                    file,
                    format!("the field \"{field}\" is of message type and names an enum"),
                )),
            },
            TYPE_ENUM => match self.message_type(file, field, desc)? {
                Named::Enum(target) => Ok(FieldKind::Enum(target)),
                Named::Message(_) | Named::Entry(..) => Err(self.refuse(
                    file,
                    format!("the field \"{field}\" is of enum type and names a message"),
                )),
            },
            _ => Err(self.refuse(
                file,
                format!("the field \"{field}\" has the unknown type {ty}"),
            )),
        }
    }

    /// The map a repeated field of the entry message `entry` is.
    fn map(
        &self,
        file: usize,
        field: &str,
        entry: &[DecodedField],
    ) -> Result<FieldKind, ProtoDiagnostic> {
        let member = |number: i64| messages(entry, 2).find(|f| int(f, 3) == Some(number));
        let refuse = |what: &str| self.refuse(file, format!("the map field \"{field}\" {what}"));
        let (Some(key), Some(value)) = (member(1), member(2)) else {
            return Err(refuse("has an entry without a key or a value"));
        };
        let key = match int(key, 5).and_then(scalar) {
            Some(kind) if kind.may_key_a_map() => kind,
            _ => {
                return Err(refuse(
                    "has a key that is not an integral type, bool or string",
                ))
            }
        };
        let value = match int(value, 5) {
            Some(ty) => match self.kind(file, field, ty, value)? {
                FieldKind::Scalar(kind) => MapValueKind::Scalar(kind),
                FieldKind::Enum(target) => MapValueKind::Enum(target),
                FieldKind::Message(target) => MapValueKind::Message(target),
                FieldKind::Group | FieldKind::Map { .. } => {
                    return Err(refuse(
                        "has a value that is not a scalar, an enum or a message",
                    ))
                }
            },
            None => return Err(refuse("has a value with no type")),
        };
        Ok(FieldKind::Map { key, value })
    }

    /// Link every message's fields and give up the tables.
    fn link(self) -> Result<SchemaSet, ProtoDiagnostic> {
        let mut msgs = Vec::with_capacity(self.messages.len());
        for m in &self.messages {
            msgs.push(self.link_message(m)?);
        }
        let file_options = self.files.into_iter().map(|f| f.options).collect();
        Ok(SchemaSet::from_tables(msgs, self.enums, file_options))
    }

    fn link_message(&self, m: &MessageIn<'d>) -> Result<Msg, ProtoDiagnostic> {
        let file = m.file;
        let syntax = self.files[file].syntax;
        let declared: Vec<&str> = messages(m.desc, 8)
            .map(|o| text(o, 1).unwrap_or(""))
            .collect();
        let fields: Vec<&[DecodedField]> = messages(m.desc, 2).collect();
        // The oneof `protoc` makes for each proto3 `optional` field is not one the
        // text declares; the text reader gives such a field presence and no oneof.
        let mut made = alloc::vec![false; declared.len()];
        let optional = fields
            .iter()
            .filter(|f| flag(f, 17) == Some(true))
            .filter_map(|f| int(f, 9))
            .filter_map(|o| usize::try_from(o).ok());
        for o in optional {
            if let Some(slot) = made.get_mut(o) {
                *slot = true;
            }
        }
        let mut kept = alloc::vec![None; declared.len()];
        let mut oneofs = Vec::new();
        for (at, name) in declared.iter().enumerate() {
            if !made[at] {
                kept[at] = Some(oneofs.len());
                oneofs.push(String::from(*name));
            }
        }

        let mut numbers = BTreeSet::new();
        let mut linked = Vec::with_capacity(fields.len());
        for f in fields {
            let Some(name) = text(f, 1) else {
                return Err(
                    self.refuse(file, format!("a field of \"{}\" has no name", m.full_name))
                );
            };
            let full = join(&m.full_name, name);
            let refuse = |what: String| self.refuse(file, format!("the field \"{full}\" {what}"));
            let number = int(f, 3)
                .and_then(|n| u64::try_from(n).ok())
                .filter(|n| (1..=MAX_FIELD_NUMBER).contains(n))
                .ok_or_else(|| refuse(format!("has no number from 1 to {MAX_FIELD_NUMBER}")))?;
            if (19_000..=19_999).contains(&number) {
                return Err(refuse(String::from(
                    "has a number in 19000 through 19999, which the protocol buffer library reserves",
                )));
            }
            if !numbers.insert(number) {
                return Err(refuse(format!(
                    "has the number {number}, which another field of the message has"
                )));
            }
            let Some(ty) = int(f, 5) else {
                return Err(refuse(String::from("has no type")));
            };
            let written = int(f, 4);
            let oneof = match int(f, 9) {
                None => None,
                Some(o) => {
                    let Some(slot) = usize::try_from(o).ok().and_then(|o| kept.get(o)) else {
                        return Err(refuse(format!(
                            "names the oneof {o}, which the message has not"
                        )));
                    };
                    *slot
                }
            };
            let entry = match (ty, written) {
                (TYPE_MESSAGE, Some(LABEL_REPEATED)) => match self.message_type(file, &full, f)? {
                    Named::Entry(entry) => Some(entry),
                    Named::Message(_) | Named::Enum(_) => None,
                },
                _ => None,
            };
            let (kind, label) = match entry {
                Some(entry) => (self.map(file, &full, entry)?, Label::Implicit),
                None => {
                    let kind = self.kind(file, &full, ty, f)?;
                    let label = match written {
                        Some(LABEL_REPEATED) => Label::Repeated,
                        Some(LABEL_REQUIRED) => Label::Required,
                        Some(LABEL_OPTIONAL) => {
                            if flag(f, 17) == Some(true) {
                                Label::Optional
                            } else if oneof.is_some() || syntax == Syntax::Proto3 {
                                Label::Implicit
                            } else {
                                Label::Optional
                            }
                        }
                        Some(other) => {
                            return Err(refuse(format!("has the unknown label {other}")))
                        }
                        None => return Err(refuse(String::from("has no label"))),
                    };
                    (kind, label)
                }
            };
            let options = options_of(message(f, 8), &[(2, "packed"), (3, "deprecated")], "nanopb");
            linked.push(Fld::new(
                String::from(name),
                number,
                kind,
                label,
                oneof,
                options,
            ));
        }
        let options = options_of(message(m.desc, 7), &[(3, "deprecated")], "nanopb_msgopt");
        Ok(Msg::new(
            m.full_name.clone(),
            file,
            m.parent,
            syntax,
            linked,
            oneofs,
            options,
        ))
    }
}

/// The scalar a `FieldDescriptorProto.Type` value is, if it is one.
fn scalar(ty: i64) -> Option<ScalarKind> {
    Some(match ty {
        1 => ScalarKind::Double,
        2 => ScalarKind::Float,
        3 => ScalarKind::Int64,
        4 => ScalarKind::Uint64,
        5 => ScalarKind::Int32,
        6 => ScalarKind::Fixed64,
        7 => ScalarKind::Fixed32,
        8 => ScalarKind::Bool,
        9 => ScalarKind::String,
        12 => ScalarKind::Bytes,
        13 => ScalarKind::Uint32,
        15 => ScalarKind::Sfixed32,
        16 => ScalarKind::Sfixed64,
        17 => ScalarKind::Sint32,
        18 => ScalarKind::Sint64,
        _ => return None,
    })
}
