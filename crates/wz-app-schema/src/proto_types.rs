// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The type tables of a linked schema, and the words they are written in: what
//! the typed reader and the writer of every sample read, whichever reader made
//! them.
//!
//! Two readers make these tables. The `.proto` text reader (`proto_lex`,
//! `proto_parse` and `proto_schema`, behind the `proto-text` feature) tokenizes,
//! parses and links the text a program hands over; the compiled-descriptor
//! reader of `wz_app_frame::proto_descriptor` reads the `FileDescriptorSet`
//! `protoc` wrote when the program was built. The tables are the same either
//! way, so this module is in every build with `alloc` and the text reader is not.

use alloc::string::String;
use alloc::vec::Vec;
use core::fmt;

/// A place in a source file.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct Pos {
    /// 1-based line.
    pub line: u32,
    /// 1-based byte column within the line.
    pub col: u32,
}

impl Pos {
    /// The place of something no text was read for (a field or an option a compiled
    /// descriptor gave): line and column 0, which no place in a file has.
    pub const NOWHERE: Self = Self { line: 0, col: 0 };
}

/// The largest legal field number, `2^29 - 1`: the tag keeps three bits for the
/// wire type in a 32-bit varint.
pub const MAX_FIELD_NUMBER: u64 = 536_870_911;

/// The scalar type keywords. A field of one of these has no structure to name.
///
/// The declaration door only needs to know that a type IS one; the value door
/// (the capture crate's `proto_encode`) needs which, because the wire form of `int32`,
/// `sint32` and `fixed32` differ.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ScalarKind {
    Double,
    Float,
    Int32,
    Int64,
    Uint32,
    Uint64,
    Sint32,
    Sint64,
    Fixed32,
    Fixed64,
    Sfixed32,
    Sfixed64,
    Bool,
    String,
    Bytes,
}

impl ScalarKind {
    /// Every scalar kind, in the order the language guide lists them. The walk a
    /// vocabulary of type words is held to, so a kind added to the enum is a
    /// keyword a document has to declare.
    pub const ALL: [Self; 15] = [
        Self::Double,
        Self::Float,
        Self::Int32,
        Self::Int64,
        Self::Uint32,
        Self::Uint64,
        Self::Sint32,
        Self::Sint64,
        Self::Fixed32,
        Self::Fixed64,
        Self::Sfixed32,
        Self::Sfixed64,
        Self::Bool,
        Self::String,
        Self::Bytes,
    ];

    /// The kind a type keyword names, or `None` for any other word.
    pub fn from_keyword(word: &str) -> Option<Self> {
        Some(match word {
            "double" => Self::Double,
            "float" => Self::Float,
            "int32" => Self::Int32,
            "int64" => Self::Int64,
            "uint32" => Self::Uint32,
            "uint64" => Self::Uint64,
            "sint32" => Self::Sint32,
            "sint64" => Self::Sint64,
            "fixed32" => Self::Fixed32,
            "fixed64" => Self::Fixed64,
            "sfixed32" => Self::Sfixed32,
            "sfixed64" => Self::Sfixed64,
            "bool" => Self::Bool,
            "string" => Self::String,
            "bytes" => Self::Bytes,
            _ => return None,
        })
    }

    /// The keyword, as written in a `.proto` file.
    pub fn keyword(self) -> &'static str {
        match self {
            Self::Double => "double",
            Self::Float => "float",
            Self::Int32 => "int32",
            Self::Int64 => "int64",
            Self::Uint32 => "uint32",
            Self::Uint64 => "uint64",
            Self::Sint32 => "sint32",
            Self::Sint64 => "sint64",
            Self::Fixed32 => "fixed32",
            Self::Fixed64 => "fixed64",
            Self::Sfixed32 => "sfixed32",
            Self::Sfixed64 => "sfixed64",
            Self::Bool => "bool",
            Self::String => "string",
            Self::Bytes => "bytes",
        }
    }

    /// Whether a map key may be of this kind: integral types, `bool` and
    /// `string` (language guide, "Maps": the key type "can be any integral or
    /// string type"; `float`, `double` and `bytes` are out).
    pub fn may_key_a_map(self) -> bool {
        !matches!(self, Self::Double | Self::Float | Self::Bytes)
    }
}

/// Which `syntax` the file declared. Without a statement it is proto2, which is
/// what `protoc` assumes too.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Syntax {
    Proto2,
    Proto3,
}

/// The label a field was written with.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Label {
    /// None: a proto3 singular field, a member of a oneof, or a map.
    Implicit,
    Optional,
    Required,
    Repeated,
}

/// What an option's value was written as. The parser keeps the value as written
/// and does not judge it: whoever acts on an option decides what it may be.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum OptionValue {
    /// A bare word: `true`, `false`, an enum value's name, `inf`, or a signed
    /// one (`-inf`).
    Ident(String),
    Str(String),
    /// An integer literal with its sign, wide enough for every `u64` and its
    /// negation.
    Int(i128),
    /// A floating-point literal as it was written, sign included.
    Float(String),
    /// A `{ ... }` aggregate: the text between the braces, as written, trimmed.
    Aggregate(String),
}

/// One option, from a field's or an enum value's `[...]` list or from an
/// `option` statement.
///
/// The name is kept as written: a plain word (`packed`), a dotted path
/// (`foo.bar`), or an extension in parentheses with the rest of the path after it
/// (`(my.ext).field`), the parts joined by `.`.
#[derive(Clone, Debug)]
pub struct FieldOption {
    pub name: String,
    pub value: OptionValue,
    /// Where the value starts, which is where a wrong value is blamed.
    pub value_pos: Pos,
}

/// The comments `protoc` attaches to a declaration (see `proto_lex::Gap`
/// for the rule), as it stores them: the text after the comment marker, line
/// breaks included.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Docs {
    /// The comment in front of the declaration with no blank line between.
    pub leading: Option<String>,
    /// The comment after the declaration's `;`, or after the `{` that opens a
    /// message.
    pub trailing: Option<String>,
}

/// Why a schema was refused, and where.
///
/// `file`, `line` and `column` are present together when the problem is at a
/// place in a file. Lines and columns count from 1; a column counts bytes from
/// the start of the line, so a tab is one column and a multi-byte character
/// several. `file` alone means the problem is about the file as a whole (the
/// root message is not in it); none of the three means it is about an argument.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProtoDiagnostic {
    /// The name the file was handed over under.
    pub file: Option<String>,
    /// 1-based line.
    pub line: Option<usize>,
    /// 1-based byte column.
    pub column: Option<usize>,
    /// What is wrong, in a sentence.
    pub reason: String,
}

impl fmt::Display for ProtoDiagnostic {
    /// `{file}: line {line}: {reason}` for a place in a file, `{file}: {reason}`
    /// for a whole file, and the reason alone otherwise.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match (&self.file, self.line) {
            (Some(file), Some(line)) => write!(f, "{file}: line {line}: {}", self.reason),
            (Some(file), None) => write!(f, "{file}: {}", self.reason),
            (None, _) => f.write_str(&self.reason),
        }
    }
}

impl ProtoDiagnostic {
    /// A problem at `pos` in the file `file`.
    pub fn at(file: &str, pos: Pos, reason: impl Into<String>) -> Self {
        Self {
            file: Some(String::from(file)),
            line: Some(pos.line as usize),
            column: Some(pos.col as usize),
            reason: reason.into(),
        }
    }

    /// A problem of the file `file` as a whole.
    pub fn in_file(file: &str, reason: impl Into<String>) -> Self {
        Self {
            file: Some(String::from(file)),
            line: None,
            column: None,
            reason: reason.into(),
        }
    }

    /// A problem of an argument, at no place in a file.
    pub fn argument(reason: impl Into<String>) -> Self {
        Self {
            file: None,
            line: None,
            column: None,
            reason: reason.into(),
        }
    }
}

/// The `option` statements of each file of a linked schema, by the file's index
/// ([`Msg::file`]): the outermost level the nanopb options are merged from
/// (`wz_app_frame::proto_nanopb`). The linker a schema is read with and the schema set
/// a payload keeps both answer it, so an option reads the same over either.
pub trait FileOptions {
    /// The options file `file` states, in the order written; none for an index
    /// the schema has no file at.
    fn options_of_file(&self, file: usize) -> &[FieldOption];
}

/// The messages and the enums of a linked schema, at the indices its fields name them by
/// ([`FieldKind::Message`], [`FieldKind::Enum`]), with each file's options: what a walk over the
/// types of a whole schema reads (`wz_app_frame::proto_nanopb::encoded_sizes`), from the linker a
/// schema is read with or from the schema set a compiled descriptor is read into.
pub trait LinkedTypes: FileOptions {
    /// Every message, by index.
    fn linked_messages(&self) -> &[Msg];
    /// Every enum, by index.
    fn linked_enums(&self) -> &[EnumInfo];
}

/// A message as the expansion and the value door see it.
pub struct Msg {
    pub full_name: String,
    pub file: usize,
    /// The index in the schema's messages of the message this one is written inside,
    /// or `None` for a message at the top level of its file.
    pub parent: Option<usize>,
    /// The syntax of the file the message is written in: it decides whether a
    /// singular field has presence and whether a repeated one is packed.
    pub syntax: Syntax,
    pub fields: Vec<Fld>,
    /// The names of the message's oneofs, in the order written.
    pub oneofs: Vec<String>,
    /// The comments `protoc` attaches to the message.
    pub docs: Docs,
    /// The message's own `option` statements, in the order written.
    pub options: Vec<FieldOption>,
    /// What in the text keeps this message from being declared, should the
    /// expansion visit it, in the order the linker met them.
    #[cfg(feature = "proto-text")]
    pub(crate) blockers: Vec<Blocker>,
}

/// An enum, with the numbers its names stand for.
pub struct EnumInfo {
    pub full_name: String,
    /// The enum's syntax decides whether a number that is none of its values is
    /// a value anyway (proto3, an open enum) or an error (proto2, closed).
    pub syntax: Syntax,
    /// `(name, number)` in the order written.
    pub values: Vec<(String, i128)>,
}

/// What a field holds, resolved.
#[derive(Clone, Copy, Debug)]
pub enum FieldKind {
    Scalar(ScalarKind),
    Enum(usize),
    Message(usize),
    /// A `group`. Declared here so the value door can say what it refuses; it
    /// never writes one, so the group's body message is not kept.
    Group,
    Map {
        key: ScalarKind,
        value: MapValueKind,
    },
}

/// What a map's values are.
#[derive(Clone, Copy, Debug)]
pub enum MapValueKind {
    Scalar(ScalarKind),
    Enum(usize),
    Message(usize),
}

/// A `group` or an `extend` that makes a message undeclarable, and where it is.
///
/// Recorded when the schema is linked and judged only once the root is known:
/// the same text is harmless to a root that never reaches the message and fatal
/// to one that does.
#[cfg(feature = "proto-text")]
pub(crate) struct Blocker {
    /// The file the keyword is written in.
    pub(crate) file: usize,
    /// The `group` or `extend` keyword.
    pub(crate) pos: Pos,
    pub(crate) kind: BlockerKind,
}

#[cfg(feature = "proto-text")]
pub(crate) enum BlockerKind {
    /// The message holds a group of this name, which is a field of it.
    Group(String),
    /// Some `extend` block extends the message.
    Extend,
}

/// What the expansion does with a field after its own line.
#[cfg(feature = "proto-text")]
pub(crate) enum Target {
    /// Nothing: a scalar or an enum.
    Leaf,
    Message(usize),
    /// A map: `key` and `value` lines, and the value message's fields if any.
    Map(Option<usize>),
}

pub struct Fld {
    pub name: String,
    pub number: u64,
    #[cfg(feature = "proto-text")]
    pub(crate) target: Target,
    /// Where the type was written, for the diagnostics that blame it.
    #[cfg(feature = "proto-text")]
    pub(crate) ty_pos: Pos,
    /// The type the field holds, with the scalar kind and the enum
    /// kept: the declaration door needs only the tree, the value door needs
    /// what each leaf is.
    pub kind: FieldKind,
    pub label: Label,
    /// The index in the owning message's `oneofs`, if the field is a member.
    pub oneof: Option<usize>,
    /// Every `[...]` entry, in the order written.
    pub options: Vec<FieldOption>,
    /// The comments `protoc` attaches to the field.
    pub docs: Docs,
}

impl Msg {
    /// A message whose parts a reader found without the `.proto` text: the
    /// compiled descriptor's reader builds the tables the typed reader and the
    /// writer read with this, and it carries no comment.
    pub fn new(
        full_name: String,
        file: usize,
        parent: Option<usize>,
        syntax: Syntax,
        fields: Vec<Fld>,
        oneofs: Vec<String>,
        options: Vec<FieldOption>,
    ) -> Self {
        Self {
            full_name,
            file,
            parent,
            syntax,
            fields,
            oneofs,
            docs: Docs::default(),
            options,
            #[cfg(feature = "proto-text")]
            blockers: Vec::new(),
        }
    }
}

impl Fld {
    /// A field whose type a reader resolved without the `.proto` text, as
    /// [`Msg::new`] takes it; it carries no comment.
    pub fn new(
        name: String,
        number: u64,
        kind: FieldKind,
        label: Label,
        oneof: Option<usize>,
        options: Vec<FieldOption>,
    ) -> Self {
        Self {
            name,
            number,
            #[cfg(feature = "proto-text")]
            target: match kind {
                FieldKind::Message(inner) => Target::Message(inner),
                FieldKind::Map {
                    value: MapValueKind::Message(inner),
                    ..
                } => Target::Map(Some(inner)),
                FieldKind::Map { .. } => Target::Map(None),
                FieldKind::Scalar(_) | FieldKind::Enum(_) | FieldKind::Group => Target::Leaf,
            },
            // No text was read, so there is no place to blame; the expansion that
            // reads it walks only what the text reader linked.
            #[cfg(feature = "proto-text")]
            ty_pos: Pos::NOWHERE,
            kind,
            label,
            oneof,
            options,
            docs: Docs::default(),
        }
    }
}
