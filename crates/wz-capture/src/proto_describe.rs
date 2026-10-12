// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! A root message of a `.proto` schema, DESCRIBED: what a person filling it in
//! has to be shown, read by the one reader the declaration door and the value
//! door already use.
//!
//! ## What this is for
//!
//! A consumer that lets a person type the fields of a message draws one input
//! per field, and until now the only way to know the fields was to read the
//! `.proto` itself: a second reader of a language inside the program that links
//! this library, which is the thing [`crate::proto_schema`] refuses to leave
//! outstanding. [`crate::proto_schema::declarations_from_proto`] gives the paths
//! and the names, and [`crate::proto_encode`] takes values and gives bytes; this
//! is the part in between, the shape of what the values are of.
//!
//! ## What comes out
//!
//! The root message and every message reachable from it through field types
//! (a map's value type included), each ONCE, in the order the declaration door's
//! expansion first reaches them. A message that contains itself is therefore
//! described, where the declaration door refuses it: nothing here is expanded
//! into paths, so a cycle has an end. Per message the full name, the file it is
//! written in, its syntax, its oneofs, and its fields in declaration order; per
//! field the name, the JSON name, the number, the type, the label, the oneof it
//! belongs to, whether a repeated field is written packed, and what a type that
//! names another type points at.
//!
//! A message and a field also carry the comments `protoc` attaches to them (the
//! leading and the trailing comment, by `protoc`'s own rule, which the lexer
//! implements: `crate::proto_lex::Gap`) and every option written on them, in the
//! order written, none dropped and none judged. A consumer that builds a form from
//! the schema thereby reads the words the author wrote about a field and the
//! options the author set on it (an extension's option included) from the one
//! reader, and not from a second pass over the text.
//!
//! The words are closed: the `type` of a field is a scalar keyword or one of
//! `enum`, `message` and `map`, and the `label` one of `singular`, `optional`,
//! `required` and `repeated`. A `map<K, V>` is written on the wire as a repeated
//! entry message, so its label is `repeated` and its `type` is `map`, with the
//! key and value types beside it.
//!
//! ## What is refused
//!
//! What the other doors refuse and for the same reasons, since they share the
//! reader: a syntax error, a type that is not defined, a repeated or reserved
//! number, a root message that is not defined, and a `group` or an `extend` that
//! the root reaches (a group is a field this reader cannot name, and an
//! extension's fields are declared outside the message they extend, so a
//! description would have to leave them out). A recursive message and the path
//! and size bounds of the declaration door are NOT refusals here, because no
//! path is built.
//!
//! This is not a validator, as the module it stands on says: an option value is
//! not judged. A `json_name` that is not a string falls back to protoc's default
//! spelling, and a `packed` that is neither `true` nor `false` to the syntax's
//! default; the value door is the one that refuses them, when a value is built.

use alloc::string::String;
use alloc::vec::Vec;

use crate::proto_nanopb::SizeRefusal;
use crate::proto_parse::{FieldOption, Label, OptionValue, ScalarKind, Syntax};
use crate::proto_schema::{FieldKind, Linker, MapValueKind, ProtoDiagnostic, ProtoFile};

/// The words of a field's `type`: every scalar keyword, then the three that name
/// a structure.
///
/// One list, so the vocabulary a document declares and the walk it is held to
/// are the same thing.
pub fn type_words() -> Vec<&'static str> {
    let mut words: Vec<&'static str> = ScalarKind::ALL.iter().map(|k| k.keyword()).collect();
    words.extend(["enum", "message", "map"]);
    words
}

/// The scalar keywords a map may be keyed by: the integral types, `bool` and
/// `string`. The words of the `key` of a described map.
pub fn map_key_words() -> Vec<&'static str> {
    ScalarKind::ALL
        .iter()
        .filter(|k| k.may_key_a_map())
        .map(|k| k.keyword())
        .collect()
}

/// The words of a field's `label`.
pub const LABEL_WORDS: [&str; 4] = ["singular", "optional", "required", "repeated"];

/// The words of a message's `syntax`.
pub const SYNTAX_WORDS: [&str; 2] = ["proto2", "proto3"];

/// The words of an option's `kind`: how its value was written.
pub const OPTION_KIND_WORDS: [&str; 5] = ["identifier", "integer", "float", "string", "aggregate"];

/// The value of an option, as written.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum OptionValueDescription {
    /// A bare word: `true`, an enum value's name.
    Identifier(String),
    Integer(i128),
    /// The literal as written, sign included.
    Float(String),
    String(String),
    /// The text between the braces of a `{ ... }` value, as written.
    Aggregate(String),
}

impl OptionValueDescription {
    /// The word of [`OPTION_KIND_WORDS`] for this value.
    pub fn kind(&self) -> &'static str {
        match self {
            Self::Identifier(_) => OPTION_KIND_WORDS[0],
            Self::Integer(_) => OPTION_KIND_WORDS[1],
            Self::Float(_) => OPTION_KIND_WORDS[2],
            Self::String(_) => OPTION_KIND_WORDS[3],
            Self::Aggregate(_) => OPTION_KIND_WORDS[4],
        }
    }
}

/// One option of a field or a message, as written: the name the way the file
/// spelled it (`packed`, `(ext).field`) and the value, not judged.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OptionDescription {
    pub name: String,
    pub value: OptionValueDescription,
}

fn describe_options(options: &[FieldOption]) -> Vec<OptionDescription> {
    options
        .iter()
        .map(|o| OptionDescription {
            name: o.name.clone(),
            value: match &o.value {
                OptionValue::Ident(w) => OptionValueDescription::Identifier(w.clone()),
                OptionValue::Int(n) => OptionValueDescription::Integer(*n),
                OptionValue::Float(text) => OptionValueDescription::Float(text.clone()),
                OptionValue::Str(s) => OptionValueDescription::String(s.clone()),
                OptionValue::Aggregate(text) => OptionValueDescription::Aggregate(text.clone()),
            },
        })
        .collect()
}

/// An enum a field's type names, with the numbers its names stand for.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EnumDescription {
    /// The enum's full name, package included.
    pub name: String,
    /// `(name, number)` in the order written.
    pub values: Vec<(String, i128)>,
}

/// What a field or a map's value points at when its type is not a scalar.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Target {
    /// A scalar: nothing to point at.
    None,
    /// An enum, with its values.
    Enum(EnumDescription),
    /// A message, by full name; its fields are one of the described messages.
    Message(String),
}

/// A map field's two types.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MapDescription {
    /// The key's scalar keyword.
    pub key: &'static str,
    /// The value's `type` word (a scalar keyword, `enum` or `message`).
    pub value_type: &'static str,
    /// What the value points at.
    pub value: Target,
}

/// One field of a described message.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FieldDescription {
    /// The name as written.
    pub name: String,
    /// The name the JSON mapping reads: the `json_name` option when it is a
    /// string, protoc's lower-camel-case spelling otherwise.
    pub json_name: String,
    /// The field number.
    pub number: u64,
    /// One of [`type_words`].
    pub ty: &'static str,
    /// One of [`LABEL_WORDS`].
    pub label: &'static str,
    /// The name of the oneof the field is a member of.
    pub oneof: Option<String>,
    /// Whether a repeated field of a packable type is written as one run. `None`
    /// for every field that is not such a field.
    pub packed: Option<bool>,
    /// What a field of type `enum` or `message` points at.
    pub target: Target,
    /// The two types of a field of type `map`.
    pub map: Option<MapDescription>,
    /// The comment `protoc` reads as leading the field.
    pub comment: Option<String>,
    /// The comment `protoc` reads as trailing the field.
    pub trailing_comment: Option<String>,
    /// Every entry of the field's `[...]` list, in the order written.
    pub options: Vec<OptionDescription>,
}

/// One message.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MessageDescription {
    /// The full name, package included.
    pub full_name: String,
    /// The name of the file the message is written in, as it was handed over.
    pub file: String,
    /// One of [`SYNTAX_WORDS`].
    pub syntax: &'static str,
    /// The oneofs, in the order written.
    pub oneofs: Vec<String>,
    /// The fields, in declaration order.
    pub fields: Vec<FieldDescription>,
    /// The comment `protoc` reads as leading the message.
    pub comment: Option<String>,
    /// The comment `protoc` reads as trailing the message: the one after its `{`.
    pub trailing_comment: Option<String>,
    /// The message's own `option` statements, in the order written.
    pub options: Vec<OptionDescription>,
    /// The most bytes the message takes encoded, by nanopb's arithmetic, or the
    /// reason it has no number (see [`crate::proto_nanopb`]).
    pub max_encoded_size: Result<u64, SizeRefusal>,
}

/// The root message and the messages it reaches.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProtoDescription {
    /// The full name of the root message: the first of `messages`.
    pub root: String,
    /// The root message, then every message it reaches, each once.
    pub messages: Vec<MessageDescription>,
}

fn syntax_word(syntax: Syntax) -> &'static str {
    match syntax {
        Syntax::Proto2 => "proto2",
        Syntax::Proto3 => "proto3",
    }
}

/// Describe `root_message` of the schema in `files`.
///
/// `root_message` is the full name, package included; `root_file` indexes
/// `files`. The arguments are the ones
/// [`crate::proto_schema::declarations_from_proto`] takes, minus the key
/// pattern: a description is about the schema alone.
///
/// # Errors
///
/// The [`ProtoDiagnostic`] of the first problem found; see the module
/// documentation for what is refused.
pub fn describe_proto(
    root_message: &str,
    files: &[ProtoFile<'_>],
    root_file: usize,
) -> Result<ProtoDescription, ProtoDiagnostic> {
    let linker = Linker::read(files, root_file)?;
    let root = linker.root_message(root_message, root_file)?;
    linker.refuse_what_the_root_reaches(root)?;

    let enum_of = |idx: usize| EnumDescription {
        name: linker.enums[idx].full_name.clone(),
        values: linker.enums[idx].values.clone(),
    };

    let reached = linker.reached_from(root);
    let mut sizes = crate::proto_nanopb::encoded_sizes(&linker, &reached);
    let mut messages = Vec::new();
    for idx in reached {
        let msg = &linker.msgs[idx];
        let proto3 = msg.syntax == Syntax::Proto3;
        let mut fields = Vec::with_capacity(msg.fields.len());
        for f in &msg.fields {
            let json_name = f
                .options
                .iter()
                .find(|o| o.name == "json_name")
                .and_then(|o| match &o.value {
                    crate::proto_parse::OptionValue::Str(s) => Some(s.clone()),
                    _ => None,
                })
                .unwrap_or_else(|| crate::proto_encode::default_json_name(&f.name));
            let label = match f.label {
                Label::Implicit => "singular",
                Label::Optional => "optional",
                Label::Required => "required",
                Label::Repeated => "repeated",
            };
            let packable = match f.kind {
                FieldKind::Enum(_) => true,
                FieldKind::Scalar(s) => !matches!(s, ScalarKind::String | ScalarKind::Bytes),
                FieldKind::Message(_) | FieldKind::Group | FieldKind::Map { .. } => false,
            };
            let packed = if f.label == Label::Repeated && packable {
                let explicit = f
                    .options
                    .iter()
                    .find(|o| o.name == "packed")
                    .and_then(|o| match &o.value {
                        crate::proto_parse::OptionValue::Ident(w) if w == "true" => Some(true),
                        crate::proto_parse::OptionValue::Ident(w) if w == "false" => Some(false),
                        _ => None,
                    });
                Some(explicit.unwrap_or(proto3))
            } else {
                None
            };
            let (ty, target, map) = match f.kind {
                FieldKind::Scalar(s) => (s.keyword(), Target::None, None),
                FieldKind::Enum(e) => ("enum", Target::Enum(enum_of(e)), None),
                FieldKind::Message(m) => (
                    "message",
                    Target::Message(linker.msgs[m].full_name.clone()),
                    None,
                ),
                FieldKind::Map { key, value } => {
                    let (value_type, value) = match value {
                        MapValueKind::Scalar(s) => (s.keyword(), Target::None),
                        MapValueKind::Enum(e) => ("enum", Target::Enum(enum_of(e))),
                        MapValueKind::Message(m) => {
                            ("message", Target::Message(linker.msgs[m].full_name.clone()))
                        }
                    };
                    (
                        "map",
                        Target::None,
                        Some(MapDescription {
                            key: key.keyword(),
                            value_type,
                            value,
                        }),
                    )
                }
                // `refuse_what_the_root_reaches` turned the message holding a
                // group away, so a described message has none.
                FieldKind::Group => continue,
            };
            // A map is written as a repeated entry, whatever the source said.
            let label = if map.is_some() { "repeated" } else { label };
            fields.push(FieldDescription {
                name: f.name.clone(),
                json_name,
                number: f.number,
                ty,
                label,
                oneof: f.oneof.map(|i| msg.oneofs[i].clone()),
                packed,
                target,
                map,
                comment: f.docs.leading.clone(),
                trailing_comment: f.docs.trailing.clone(),
                options: describe_options(&f.options),
            });
        }
        messages.push(MessageDescription {
            full_name: msg.full_name.clone(),
            file: String::from(linker.name_of(msg.file)),
            syntax: syntax_word(msg.syntax),
            oneofs: msg.oneofs.clone(),
            fields,
            comment: msg.docs.leading.clone(),
            trailing_comment: msg.docs.trailing.clone(),
            options: describe_options(&msg.options),
            max_encoded_size: sizes
                .remove(&idx)
                .unwrap_or(Err(SizeRefusal::UnmodelledOption)),
        });
    }
    Ok(ProtoDescription {
        root: linker.msgs[root].full_name.clone(),
        messages,
    })
}
