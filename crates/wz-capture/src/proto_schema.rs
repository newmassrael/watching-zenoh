// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! `.proto` schema text turned into DECLARATION text.
//!
//! ## What this is for
//!
//! protobuf's wire format carries field numbers and no names, so a payload read
//! with [`crate::payload::formats::Protobuf`] shows `3.2` where the author wrote
//! `temperature`. [`crate::payload::formats::FormatMap`] takes the names the way
//! it takes every other piece of configuration: as declaration text, one
//! declaration per line --
//!
//! ```text
//! #@a.proto="syntax ..."           the schema file, as one JSON string
//! demo/**=protobuf@pkg.Outer       which decoder and message read the payload
//! demo/**:3=sensor                 what field 3 is called
//! demo/**:3.2=celsius              what field 2 INSIDE field 3 is called
//! ```
//!
//! A person who owns a `.proto` file should not have to type those lines, and
//! the consumer that wants to let them choose the file must not parse `.proto`
//! itself: a second reader of a language, inside the program that LINKS this
//! library, is a second opinion about which field is which, and the two
//! disagree exactly at the unusual constructs. The one reader is
//! `wz_app_frame::proto_schema`, whose items this module re-exports at the
//! paths they have always had here; what this module adds is the text, in the
//! dialect the existing doors already install and validate.
//!
//! ## What comes out
//!
//! For a key pattern `K` and a root message `pkg.Outer`:
//!
//! * one schema file line `#@<file>="<text>"` per file the root file reaches
//!   (itself and what it imports), in the order the files were handed over, so
//!   the text carries the schema and the payload is READ by its types
//!   ([`crate::proto_decode`]);
//! * the rule `K=protobuf@pkg.Outer`, naming the root message by its full name;
//! * the name lines below. They name what the typed reading names already, and
//!   are kept so that a rule a consumer rewrites to a bare `protobuf` (a walk of
//!   the wire) still names its fields, as the text this door wrote before it
//!   carried the files did;
//! * one `K:path=name` line per field of the root message, in declaration order,
//!   where `path` is the field NUMBER and `name` the field name as written;
//! * and, directly after the line of a field whose type is a message, the lines
//!   of that message's fields, whose path is the parent's path, a dot, and the
//!   field number -- the spelling [`crate::payload::formats::Protobuf`] gives a
//!   nested field (`3.2`), because a declaration is matched to a decoded path by
//!   equality of text.
//!
//! Repeated fields are the same path as a singular one: the decoder reports
//! every occurrence under one path, and one declaration names them all. A field
//! in a `oneof` is an ordinary field. An enum-typed or scalar field names its
//! own path and nothing under it.
//!
//! ### A `map<K, V>` field
//!
//! On the wire a map is a REPEATED field of an entry message whose key is field
//! 1 and whose value is field 2 (`google/protobuf/descriptor.proto`, the
//! comment on `MessageOptions.map_entry`). Declared as `m` with number 5 it
//! emits
//!
//! ```text
//! K:5=m
//! K:5.1=key
//! K:5.2=value
//! ```
//!
//! and, when `V` is a message, the lines of `V`'s fields under `5.2`. `key` and
//! `value` are the names `protoc` gives the entry message's two fields, so a
//! tree compared against a compiled descriptor needs no special case.
//!
//! ## What goes in, and what is refused
//!
//! What the reader takes and what it refuses, and in which order, is the
//! reader's documentation (`wz_app_frame::proto_schema`). This module adds two
//! refusals of its own: a key pattern or a file name that holds a line break,
//! which would end its declaration, and an expansion of more than
//! [`MAX_DECLARATIONS`](crate::proto_schema::MAX_DECLARATIONS) lines. The last matters because a schema with no cycle
//! can still expand exponentially: a message that holds two of a message that
//! holds two of another, ten times over, is a thousand paths from a ten-line
//! file.

use alloc::format;
use alloc::string::String;

use crate::payload::formats::{escape_field, FormatMap};

use wz_app_frame::proto_schema::{text_of, NameSink};
pub use wz_app_frame::proto_schema::{
    ProtoDiagnostic, ProtoFile, MAX_IMPORT_DEPTH, MAX_PATH_DEPTH,
};
// The linked tables the value, description, range and size doors of this crate
// read. Not part of this crate's surface, as they were not before they moved.
pub(crate) use wz_app_frame::proto_schema::{FieldKind, Fld, Linker, MapValueKind, Msg};

/// The most lines a result may hold, the rule line included.
pub const MAX_DECLARATIONS: usize = 16_384;

/// The declarations a schema produced.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProtoDeclarations {
    /// The declaration text: a schema file line per file read, the rule line,
    /// then one line per named path, each ending in a newline.
    pub text: String,
    /// How many declarations the text holds, which is the number
    /// [`FormatMap::declare_all`] reports installing for it.
    pub installed: usize,
}

/// Turn the schema in `files` into declarations for `key_pattern`.
///
/// `key_pattern` is a key expression as its author means it, NOT declaration
/// text: the characters the declaration dialect reserves are quoted here. It
/// must not hold a line break, which would end the declaration.
/// `root_message` is the root message's full name. `root_file` indexes `files`.
///
/// # Errors
///
/// A [`ProtoDiagnostic`] for the first problem found; see the module documentation
/// for what is refused. The produced text is always accepted by
/// [`FormatMap::declare_all`], because it is run through it before it is
/// returned: a key pattern that dialect cannot install is refused here, with the
/// installer's own words, rather than handed back to fail somewhere else.
pub fn declarations_from_proto(
    key_pattern: &str,
    root_message: &str,
    files: &[ProtoFile<'_>],
    root_file: usize,
) -> Result<ProtoDeclarations, ProtoDiagnostic> {
    if key_pattern.is_empty() {
        return Err(ProtoDiagnostic::argument("the key pattern is empty"));
    }
    if key_pattern.contains(['\n', '\r']) {
        return Err(ProtoDiagnostic::argument(
            "the key pattern holds a line break, which would end its declaration",
        ));
    }
    let linker = Linker::read(files, root_file)?;

    let root = linker.root_message(root_message, root_file)?;
    linker.refuse_what_the_root_reaches(root)?;
    let mut out = Emitter {
        key: escape_field(key_pattern),
        text: String::new(),
        lines: 0,
    };
    // The files the root file reaches, which are exactly the ones read: a
    // file nothing imports is left out, as it is never read here either.
    for (at, file) in files.iter().enumerate() {
        if linker.has_read(at) {
            out.schema_file(file, text_of(file.name, file.text)?)?;
        }
    }
    out.rule(&linker.msgs[root].full_name)?;
    linker.expand_names(root, &mut out)?;

    // The text goes through the installer it is meant for, so the result and
    // the door that takes it can never disagree about what a valid declaration
    // is. Only the key pattern is free text, so a refusal here is the pattern's.
    let mut probe = FormatMap::new();
    match probe.declare_all(&out.text) {
        Ok(installed) => Ok(ProtoDeclarations {
            text: out.text,
            installed,
        }),
        Err(bad) => Err(ProtoDiagnostic::argument(format!(
            "the key pattern cannot be declared: {}",
            bad.error
        ))),
    }
}

/// The text being written, with the line budget.
struct Emitter {
    /// The key pattern, quoted for the declaration dialect.
    key: String,
    text: String,
    lines: usize,
}

impl Emitter {
    fn reserve(&mut self) -> Result<(), ProtoDiagnostic> {
        if self.lines >= MAX_DECLARATIONS {
            return Err(ProtoDiagnostic::argument(format!(
                "the schema expands to more than {MAX_DECLARATIONS} declarations: a message \
                 reached by many paths is written out once per path"
            )));
        }
        self.lines += 1;
        Ok(())
    }

    /// One schema file: `#@<file>="<text>"`, the text as one JSON string so a
    /// file of many lines is one declaration line ([`crate::payload_typed`]).
    fn schema_file(&mut self, file: &ProtoFile<'_>, text: &str) -> Result<(), ProtoDiagnostic> {
        if file.name.contains(['\n', '\r']) {
            return Err(ProtoDiagnostic::argument(format!(
                "the file name `{}` holds a line break, which would end its declaration",
                file.name.escape_debug()
            )));
        }
        self.reserve()?;
        self.text.push_str("#@");
        self.text.push_str(&escape_field(file.name));
        self.text.push('=');
        wz_session_core::json::escape_into(text, &mut self.text);
        self.text.push('\n');
        Ok(())
    }

    /// The rule, naming the root message as the body schema, so the payload is
    /// read by its types with the files above.
    fn rule(&mut self, root_message: &str) -> Result<(), ProtoDiagnostic> {
        self.reserve()?;
        self.text.push_str(&self.key);
        self.text.push_str("=protobuf@");
        self.text.push_str(root_message);
        self.text.push('\n');
        Ok(())
    }
}

impl NameSink for Emitter {
    fn name(&mut self, path: &str, name: &str) -> Result<(), ProtoDiagnostic> {
        self.reserve()?;
        self.text.push_str(&self.key);
        self.text.push(':');
        self.text.push_str(path);
        self.text.push('=');
        self.text.push_str(name);
        self.text.push('\n');
        Ok(())
    }
}
