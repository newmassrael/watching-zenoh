// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The BODY of a protected frame, described instead of supplied: the reader of
//! the `@body` member the wrap door ([`crate::e2e_json::wrap_document`]) takes
//! in its values text in place of body bytes.
//!
//! # Why a member of the values text
//!
//! A frame is a header and a body. The header's values are the wrap door's
//! values text, and the body used to come beside it as bytes the caller had
//! serialized, which left the caller holding a second writer of the protobuf
//! wire format next to the one this library has ([`crate::proto_encode`]). The
//! wrap door now accepts the body as what it is made from, a schema and field
//! values, and builds the bytes with that writer, so a caller that asks for
//! `{"@body": ...}` gets one writer for both halves of the frame.
//!
//! It is a member of the text the door already takes, and not a second door,
//! because the door's description is JSON that grows by a key without moving
//! the C ABI: a new symbol would move the ABI revision and its four mirrors for
//! an input that fits the text. The key is `@body`, which no header field can
//! be called (a name is letters, digits, `_`, `-` and `.`, as
//! [`crate::e2e_profile`] says), so it names no field and an existing values
//! text, which never has such a key, reads exactly as it did.
//!
//! # The member
//!
//! ```text
//! {"counter":258,"ident":{"domain":3},
//!  "@body":{"files":[{"name":"pose.proto","text":"syntax = \"proto3\"; ..."}],
//!           "root_file":0,
//!           "message":"pkg.Pose",
//!           "values":{"x":1.5,"y":-2}}}
//! ```
//!
//! * `files` -- the schema, as the `.proto` door takes it
//!   ([`crate::proto_schema::ProtoFile`]): at least one file, each a `name` (the
//!   name other files import it by) and its `text`;
//! * `root_file` -- which file `message` is looked up from, an index into
//!   `files`; absent means the first;
//! * `message` -- the full name of the message to build, package included. It is
//!   the same string a profile rule carries as `body_schema`
//!   (`demo/pose=demo-a@pkg.Pose`, [`crate::e2e_rule`]), so a caller that
//!   registered the rule passes that name here unchanged;
//! * `values` -- the field values, in protobuf's JSON mapping, read as
//!   [`crate::proto_encode`] reads them.
//!
//! An unknown key, a key written twice and a value of the wrong type are
//! refused, with the JSON pointer of the place in the text the caller passed
//! (`/@body/files/0/name`). Giving the body twice, as `@body` and as bytes, is
//! refused: there is no rule that says which one wins.
//!
//! # Nesting
//!
//! A values text may nest [`MAX_JSON_DEPTH`] levels, because the reader
//! recurses once per level and a text a person chose must not exhaust the
//! stack. A body's values may nest [`MAX_VALUES_DEPTH`], the bound the protobuf
//! writer was written for, and they sit two levels down. `scan` therefore
//! gives each top-level member its own bound, the body's a wider one, and a
//! text without an `@body` member is left to the original reader, so that its
//! refusals are the ones they always were.

use alloc::string::String;
use alloc::vec::Vec;

use wz_session_core::json5::{self, Json5Value};
use wz_session_core::json5_lex::Lexer;

use crate::e2e_profile::{
    array, at, check_keys, child, object, optional, read_string, read_uint, required, DocError,
    MAX_JSON_DEPTH,
};
use crate::proto_encode::{encode_tree, EncodeError, MAX_VALUES_DEPTH};
use crate::proto_schema::ProtoFile;

/// The member of the values text that carries the body.
pub const BODY_KEY: &str = "@body";

/// The JSON pointer of the member.
pub const BODY_PATH: &str = "/@body";

/// The JSON pointer of the body's field values, which is where the protobuf
/// writer's own pointers start from.
pub const BODY_VALUES_PATH: &str = "/@body/values";

/// What a values text holds, as far as the body is concerned.
pub(crate) enum Scan {
    /// No `@body` member: the text is for the header alone and is read as it
    /// always was.
    Plain,
    /// A top-level `@body` member, and the whole text as a tree. The tree is
    /// safe to build: every member was checked against its own depth bound.
    Body(Json5Value),
    /// The `@body` member itself is not JSON, or nests past the bound.
    Refused(DocError),
}

/// Look for a top-level `@body` member in `text`.
///
/// Every failure that is not inside `@body` answers [`Scan::Plain`]: the
/// original reader then refuses the same text, in the same words, at the same
/// byte, as it did before this member existed. A failure inside `@body` is
/// this module's to report, because the member is only known to be one once its
/// name has been read.
pub(crate) fn scan(text: &str) -> Scan {
    let mut lexer = Lexer::new(text);
    if lexer.skip_trivia().is_err() || lexer.peek() != Some(b'{') {
        return Scan::Plain;
    }
    lexer.bump();
    let mut found = false;
    loop {
        if lexer.skip_trivia().is_err() {
            return Scan::Plain;
        }
        match lexer.peek() {
            Some(b'}') => {
                lexer.bump();
                break;
            }
            None => return Scan::Plain,
            _ => {}
        }
        let Ok(name) = lexer.member_name() else {
            return Scan::Plain;
        };
        let is_body = name.eq_str(BODY_KEY);
        if lexer.skip_trivia().is_err() || lexer.expect(b':', ":").is_err() {
            return Scan::Plain;
        }
        if lexer.skip_trivia().is_err() {
            return Scan::Plain;
        }
        // The root object is level one of the original bound; a member is read
        // with what is left. The body's own object is one level and its values
        // the next, which is where the protobuf writer's bound starts counting.
        let bound = if is_body {
            MAX_VALUES_DEPTH + 1
        } else {
            MAX_JSON_DEPTH - 1
        };
        if let Err(e) = lexer.skip_value(bound) {
            return if is_body {
                Scan::Refused(DocError::Syntax {
                    offset: e.offset,
                    expected: e.expected,
                })
            } else {
                Scan::Plain
            };
        }
        found |= is_body;
        if lexer.skip_trivia().is_err() {
            return Scan::Plain;
        }
        match lexer.peek() {
            Some(b',') => lexer.bump(),
            Some(b'}') => {}
            _ => return Scan::Plain,
        }
    }
    if lexer.skip_trivia().is_err() || !lexer.at_end() || !found {
        return Scan::Plain;
    }
    match json5::parse(text) {
        Ok(tree) => Scan::Body(tree),
        Err(_) => Scan::Plain,
    }
}

/// The keys a body's SCHEMA is given by, wherever it is given: the wrap door's
/// `@body` member (beside `values`) and the open door's body description
/// ([`crate::e2e_json::open_body_document`]), which is these keys alone.
pub const SCHEMA_KEYS: [&str; 3] = ["files", "root_file", "message"];

/// The schema a body is an instance of: the files, the root file and the
/// message, as the `@body` member and the open door's body description both
/// give it.
pub(crate) struct SchemaRef<'t> {
    pub(crate) files: Vec<ProtoFile<'t>>,
    pub(crate) root_file: usize,
    pub(crate) message: &'t str,
}

impl<'t> SchemaRef<'t> {
    /// Read the schema keys of the object `members`, which stands at `path` in
    /// the text the caller passed. The caller has checked which keys the object
    /// may hold.
    fn read(members: &'t [(String, Json5Value)], path: &str) -> Result<Self, DocError> {
        let files_path = child(path, "files");
        let listed = array(required(members, "files", path)?, &files_path)?;
        if listed.is_empty() {
            return Err(DocError::invalid(
                files_path,
                "a body needs at least one schema file",
            ));
        }
        let mut files = Vec::with_capacity(listed.len());
        for (i, file) in listed.iter().enumerate() {
            let here = at(&files_path, i);
            let parts = object(file, &here)?;
            check_keys(parts, &["name", "text"], &here)?;
            let name = read_string(required(parts, "name", &here)?, &child(&here, "name"))?;
            if name.is_empty() {
                return Err(DocError::invalid(
                    child(&here, "name"),
                    "a file needs a name: other files import it by that name",
                ));
            }
            let text = read_string(required(parts, "text", &here)?, &child(&here, "text"))?;
            files.push(ProtoFile {
                name,
                text: text.as_bytes(),
            });
        }

        let root_file = match optional(members, "root_file") {
            None => 0,
            Some(value) => {
                let path = child(path, "root_file");
                let index = read_uint(value, &path)?;
                usize::try_from(index).map_err(|_| {
                    DocError::invalid(path, alloc::format!("`{index}` does not fit an index"))
                })?
            }
        };
        let message = read_string(required(members, "message", path)?, &child(path, "message"))?;
        Ok(Self {
            files,
            root_file,
            message,
        })
    }

    /// Read the open door's body description: an object holding the schema
    /// keys and nothing else, at the root of its own text.
    pub(crate) fn read_description(root: &'t Json5Value) -> Result<Self, DocError> {
        let members = object(root, "")?;
        check_keys(members, &SCHEMA_KEYS, "")?;
        Self::read(members, "")
    }
}

/// A body description read out of the tree.
pub(crate) struct Description<'t> {
    schema: SchemaRef<'t>,
    values: &'t Json5Value,
}

impl<'t> Description<'t> {
    /// Read the `@body` member of `root`, the values text's tree.
    pub(crate) fn read(root: &'t Json5Value) -> Result<Self, DocError> {
        let body = required(object(root, "")?, BODY_KEY, "")?;
        let members = object(body, BODY_PATH)?;
        let [files, root_file, message] = SCHEMA_KEYS;
        check_keys(members, &[files, root_file, message, "values"], BODY_PATH)?;
        let schema = SchemaRef::read(members, BODY_PATH)?;
        let values = required(members, "values", BODY_PATH)?;
        Ok(Self { schema, values })
    }

    /// The full name of the message the body is an instance of.
    pub(crate) fn message(&self) -> &str {
        self.schema.message
    }

    /// The body's wire bytes, built by the protobuf writer, or the writer's own
    /// refusal. Never a truncated body: there is no other result.
    pub(crate) fn encode(&self) -> Result<Vec<u8>, EncodeError> {
        encode_tree(
            self.schema.message,
            &self.schema.files,
            self.schema.root_file,
            self.values,
        )
    }
}

/// The refusal for a body given twice.
pub(crate) fn given_twice() -> DocError {
    DocError::invalid(
        String::from(BODY_PATH),
        "the body is given twice: as an `@body` member and as payload bytes; give one",
    )
}
