// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
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
//! demo/**=protobuf        which decoder reads this topic's payload
//! demo/**:3=sensor        what field 3 is called
//! demo/**:3.2=celsius     what field 2 INSIDE field 3 is called
//! ```
//!
//! A person who owns a `.proto` file should not have to type those lines, and
//! the consumer that wants to let them choose the file must not parse `.proto`
//! itself: a second reader of a language, inside the program that LINKS this
//! library, is a second opinion about which field is which, and the two
//! disagree exactly at the unusual constructs. This module is the one reader,
//! and what it hands back is the dialect the existing doors already install and
//! validate.
//!
//! ## What comes out
//!
//! For a key pattern `K` and a root message `pkg.Outer`:
//!
//! * the rule `K=protobuf`, first;
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
//! ## What goes in
//!
//! A list of files, each a name and its text, one of them the root file. The
//! library reads no file and runs no callback: the caller read the bytes. An
//! `import` is resolved BY NAME against the list, by exact string equality, so
//! the caller chooses the names to match how the files import each other (the
//! path `protoc` would be given after `-I`). Only the root file and what it
//! imports, transitively, are read; a file in the list nothing imports is
//! ignored, and so is any problem in it. The well-known types
//! (`google/protobuf/timestamp.proto` and the rest) are NOT built in: a schema
//! that imports one needs it in the list, like any other file.
//!
//! The root message is named by its full name including the package
//! (`pkg.Outer`, or `Outer` when there is none). It is looked up among the
//! messages of the files that were read.
//!
//! ## What is refused, and why
//!
//! Every refusal is a [`ProtoDiagnostic`] naming a file, a line and a column,
//! except the ones that are not about a place in a file.
//!
//! * `group` fields and `extend` blocks: stated at their keyword. A group is
//!   written with the deprecated group wire types, which the payload reader
//!   stops at; an extension's fields are declared outside the message they
//!   extend, so this reader could not attach their names to it. `import weak`
//!   and editions likewise.
//! * A recursive message: one whose tree contains itself. The declaration for a
//!   field at path `1.1.1.1...` has no end, so the cycle is named and refused
//!   rather than expanded to some depth nobody chose.
//! * Everything `protoc` itself refuses that this reader needs to be sure of:
//!   syntax errors, a type that is not defined, one defined in a file the
//!   referencing file does not import, a field number that is zero, above
//!   `2^29 - 1` or in `19000..=19999`, a repeated number, a reserved number or
//!   name, a duplicate name, a map key that is not integral or `string`, a
//!   label where the syntax forbids one.
//!
//! The first problem found is the only one reported, in the order `protoc`
//! meets them: a syntax error before a semantic one, an imported file before
//! the file that imports it.
//!
//! ### What it does not check
//!
//! This is not a validator. Enum bodies are read for their names only, so an
//! enum `protoc` would refuse for its numbering is accepted here; JSON name
//! collisions, option values and `extensions` ranges are not judged. A file
//! accepted here can still fail `protoc`; a file refused here for one of the
//! reasons above would be refused by it too.
//!
//! ## Bounds
//!
//! The work is linear in the text read, except the expansion, which is bounded
//! three ways and refuses past each: messages may be nested
//! `MAX_MESSAGE_NESTING` (31, `protoc`'s own limit) levels in the text, imports
//! [`MAX_IMPORT_DEPTH`] files deep, a field path [`MAX_PATH_DEPTH`] messages
//! deep, and the output [`MAX_DECLARATIONS`] lines. The last matters because a
//! schema with no cycle can still expand exponentially: a message that holds
//! two of a message that holds two of another, ten times over, is a thousand
//! paths from a ten-line file.

use alloc::collections::{BTreeMap, BTreeSet};
use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;
use core::fmt;

use crate::payload::formats::{escape_field, FormatMap};
use crate::proto_lex::{Pos, SyntaxError};
use crate::proto_parse::{
    parse_file, EnumDecl, FieldType, FileAst, ImportKind, MapValue, MessageDecl, MAX_FIELD_NUMBER,
};

/// The most lines a result may hold, the rule line included.
pub const MAX_DECLARATIONS: usize = 16_384;

/// How many messages deep a field path may go.
///
/// This bounds the recursion that expands the tree, and it is the stack bound
/// for a chain of distinct messages each holding the next, which no cycle check
/// catches. The payload reader itself stops walking nested messages after
/// eight levels, so a name declared deeper than that can never apply; the bound
/// here is for this reader's own stack and is deliberately not that number.
pub const MAX_PATH_DEPTH: usize = 64;

/// How many files deep a chain of imports may go.
pub const MAX_IMPORT_DEPTH: usize = 64;

/// One file handed to the reader.
#[derive(Clone, Copy, Debug)]
pub struct ProtoFile<'a> {
    /// The name other files import it by, and the name diagnostics carry.
    pub name: &'a str,
    /// The file's bytes, which must be UTF-8 (the language specification: source
    /// files are UTF-8). They are checked when the file is READ, not when it is
    /// handed over: a file nothing imports is never opened, so its bytes are
    /// not judged.
    pub text: &'a [u8],
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
    fn at(file: &str, pos: Pos, reason: impl Into<String>) -> Self {
        Self {
            file: Some(String::from(file)),
            line: Some(pos.line as usize),
            column: Some(pos.col as usize),
            reason: reason.into(),
        }
    }

    fn in_file(file: &str, reason: impl Into<String>) -> Self {
        Self {
            file: Some(String::from(file)),
            line: None,
            column: None,
            reason: reason.into(),
        }
    }

    fn argument(reason: impl Into<String>) -> Self {
        Self {
            file: None,
            line: None,
            column: None,
            reason: reason.into(),
        }
    }
}

/// The declarations a schema produced.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProtoDeclarations {
    /// The declaration text: the rule line, then one line per named path, each
    /// ending in a newline.
    pub text: String,
    /// How many declarations the text holds, which is the number
    /// [`FormatMap::declare_all`] reports installing for it.
    pub installed: usize,
}

/// Read `bytes` as the text of the file `name`, or say where it stops being
/// UTF-8, with a position the way every other problem has one.
fn text_of<'a>(name: &str, bytes: &'a [u8]) -> Result<&'a str, ProtoDiagnostic> {
    match core::str::from_utf8(bytes) {
        Ok(text) => Ok(text),
        Err(e) => {
            let valid = e.valid_up_to();
            let before = &bytes[..valid];
            let line = before.iter().filter(|&&b| b == b'\n').count() + 1;
            let line_start = before
                .iter()
                .rposition(|&b| b == b'\n')
                .map_or(0, |p| p + 1);
            Err(ProtoDiagnostic::at(
                name,
                Pos {
                    line: line as u32,
                    col: (valid - line_start + 1) as u32,
                },
                "the file is not valid UTF-8",
            ))
        }
    }
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
    if root_file >= files.len() {
        return Err(ProtoDiagnostic::argument(format!(
            "the root file index {root_file} is outside the {} file(s) given",
            files.len()
        )));
    }
    let mut by_name = BTreeMap::new();
    for (i, f) in files.iter().enumerate() {
        if by_name.insert(f.name, i).is_some() {
            return Err(ProtoDiagnostic::argument(format!(
                "two files are named `{}`: imports are resolved by name, so each name can \
                 stand for one file",
                f.name
            )));
        }
    }

    let mut linker = Linker {
        files,
        by_name,
        state: alloc::vec![State::Unvisited; files.len()],
        import_sites: alloc::vec![Vec::new(); files.len()],
        exports: alloc::vec![BTreeSet::new(); files.len()],
        visible: alloc::vec![BTreeSet::new(); files.len()],
        symbols: BTreeMap::new(),
        msgs: Vec::new(),
    };
    linker.load(root_file, &mut Vec::new())?;

    let root = linker.root_message(root_message, root_file)?;
    let mut out = Emitter {
        key: escape_field(key_pattern),
        text: String::new(),
        lines: 0,
    };
    out.rule()?;
    linker.expand(root, "", &mut Vec::new(), &mut out)?;

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

#[derive(Clone, Copy, PartialEq, Eq)]
enum State {
    Unvisited,
    Loading,
    Done,
}

/// What a name in the symbol table is.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Kind {
    Package,
    Message(usize),
    Enum,
    EnumValue,
    Field,
    Oneof,
    Service,
}

impl Kind {
    /// Whether a field may have this as its type.
    fn is_type(self) -> bool {
        matches!(self, Kind::Message(_) | Kind::Enum)
    }

    /// Whether a dotted name may descend into this (`protoc`: messages,
    /// packages, enums and services).
    fn is_aggregate(self) -> bool {
        matches!(
            self,
            Kind::Message(_) | Kind::Package | Kind::Enum | Kind::Service
        )
    }
}

#[derive(Clone, Copy, Debug)]
struct Symbol {
    kind: Kind,
    file: usize,
}

/// A message as the expansion sees it.
struct Msg {
    full_name: String,
    file: usize,
    fields: Vec<Fld>,
}

/// What the expansion does with a field after its own line.
enum Target {
    /// Nothing: a scalar or an enum.
    Leaf,
    Message(usize),
    /// A map: `key` and `value` lines, and the value message's fields if any.
    Map(Option<usize>),
}

struct Fld {
    name: String,
    number: u64,
    target: Target,
    /// Where the type was written, for the diagnostics that blame it.
    ty_pos: Pos,
}

struct Linker<'f, 'a> {
    files: &'f [ProtoFile<'a>],
    by_name: BTreeMap<&'a str, usize>,
    state: Vec<State>,
    /// Per file, each import's path and position, kept for the error that
    /// names an import after the file's tree is gone.
    import_sites: Vec<Vec<(String, Pos)>>,
    /// Per file, the files whose symbols an importer of it can see: itself and
    /// whatever it imports `public`, transitively.
    exports: Vec<BTreeSet<usize>>,
    /// Per file, the files whose symbols it can name: itself, its direct
    /// imports, and what they export.
    visible: Vec<BTreeSet<usize>>,
    symbols: BTreeMap<String, Symbol>,
    msgs: Vec<Msg>,
}

impl<'a> Linker<'_, 'a> {
    fn name_of(&self, file: usize) -> &'a str {
        self.files[file].name
    }

    fn syntax_error(&self, file: usize, e: SyntaxError) -> ProtoDiagnostic {
        ProtoDiagnostic::at(self.name_of(file), e.pos, e.reason)
    }

    /// Parse `idx`, load what it imports, then link it -- the order `protoc`
    /// builds in, so the first problem found is the one it would report.
    fn load(&mut self, idx: usize, chain: &mut Vec<usize>) -> Result<(), ProtoDiagnostic> {
        if self.state[idx] == State::Done {
            return Ok(());
        }
        self.state[idx] = State::Loading;
        chain.push(idx);
        let text = text_of(self.name_of(idx), self.files[idx].text)?;
        let ast = parse_file(text).map_err(|e| self.syntax_error(idx, e))?;
        self.import_sites[idx] = ast
            .imports
            .iter()
            .map(|i| (i.path.clone(), i.pos))
            .collect();

        let mut deps: Vec<(usize, ImportKind)> = Vec::new();
        for import in &ast.imports {
            let blame = |reason: String| ProtoDiagnostic::at(self.name_of(idx), import.pos, reason);
            let Some(&target) = self.by_name.get(import.path.as_str()) else {
                return Err(blame(format!(
                    "import \"{}\" is not among the files given: imports are matched by name \
                     against that list",
                    import.path
                )));
            };
            if deps.iter().any(|(d, _)| *d == target) {
                return Err(blame(format!("import \"{}\" is listed twice", import.path)));
            }
            if self.state[target] == State::Loading {
                return Err(self.cycle(target, chain));
            }
            if chain.len() >= MAX_IMPORT_DEPTH {
                return Err(blame(format!(
                    "imports are nested more than {MAX_IMPORT_DEPTH} files deep"
                )));
            }
            self.load(target, chain)?;
            deps.push((target, import.kind));
        }

        self.link_file(idx, &ast, &deps)?;
        self.state[idx] = State::Done;
        chain.pop();
        Ok(())
    }

    /// The diagnostic for an import that comes back to a file being loaded.
    ///
    /// Blamed, as `protoc` does, in the file where the cycle starts, at the
    /// import that leads along it.
    fn cycle(&self, start: usize, chain: &[usize]) -> ProtoDiagnostic {
        let from = chain.iter().position(|&f| f == start).unwrap_or(0);
        let mut names: Vec<&str> = chain[from..].iter().map(|&f| self.name_of(f)).collect();
        names.push(self.name_of(start));
        let next = chain.get(from + 1).copied().unwrap_or(start);
        let wanted = self.name_of(next);
        let site = self.import_sites[start]
            .iter()
            .find(|(path, _)| path == wanted)
            .map(|(_, pos)| *pos)
            .unwrap_or(Pos { line: 1, col: 1 });
        ProtoDiagnostic::at(
            self.name_of(start),
            site,
            format!("file recursively imports itself: {}", names.join(" -> ")),
        )
    }

    // ---- symbols ----------------------------------------------------------

    fn declare(
        &mut self,
        full: String,
        kind: Kind,
        file: usize,
        pos: Pos,
    ) -> Result<(), ProtoDiagnostic> {
        if let Some(prev) = self.symbols.get(&full) {
            if prev.kind == Kind::Package && kind == Kind::Package {
                // Two files of one package, or a package and its parent.
                return Ok(());
            }
            let (scope, short) = match full.rfind('.') {
                Some(p) => (&full[..p], &full[p + 1..]),
                None => ("", full.as_str()),
            };
            let mut reason = if prev.file != file {
                format!(
                    "\"{short}\" is already defined in file \"{}\"",
                    self.name_of(prev.file)
                )
            } else if scope.is_empty() {
                format!("\"{short}\" is already defined")
            } else {
                format!("\"{short}\" is already defined in \"{scope}\"")
            };
            if kind == Kind::EnumValue || prev.kind == Kind::EnumValue {
                reason.push_str(
                    " (enum values are siblings of their enum, not children of it, so a value \
                     name must be unique in the enclosing scope)",
                );
            }
            return Err(ProtoDiagnostic::at(self.name_of(file), pos, reason));
        }
        self.symbols.insert(full, Symbol { kind, file });
        Ok(())
    }

    /// Register one enum: its own name, then its values as siblings.
    fn declare_enum(
        &mut self,
        scope: &str,
        e: &EnumDecl,
        file: usize,
    ) -> Result<(), ProtoDiagnostic> {
        self.declare(join(scope, &e.name.name), Kind::Enum, file, e.name.pos)?;
        for v in &e.values {
            self.declare(join(scope, &v.name), Kind::EnumValue, file, v.pos)?;
        }
        Ok(())
    }

    /// Register one message and everything inside it, in the order `protoc`
    /// does: the message, its oneofs, its fields, then its nested messages and
    /// enums. The order decides which of two clashing names is blamed.
    fn declare_message(
        &mut self,
        scope: &str,
        m: &MessageDecl,
        file: usize,
    ) -> Result<(), ProtoDiagnostic> {
        let full = join(scope, &m.name.name);
        let idx = self.msgs.len();
        self.msgs.push(Msg {
            full_name: full.clone(),
            file,
            fields: Vec::new(),
        });
        self.declare(full.clone(), Kind::Message(idx), file, m.name.pos)?;
        for o in &m.oneofs {
            self.declare(join(&full, &o.name), Kind::Oneof, file, o.pos)?;
        }
        for f in &m.fields {
            self.declare(join(&full, &f.name.name), Kind::Field, file, f.name.pos)?;
        }
        for n in &m.nested {
            self.declare_message(&full, n, file)?;
        }
        for e in &m.enums {
            self.declare_enum(&full, e, file)?;
        }
        Ok(())
    }

    fn link_file(
        &mut self,
        file: usize,
        ast: &FileAst,
        deps: &[(usize, ImportKind)],
    ) -> Result<(), ProtoDiagnostic> {
        // What this file's importers will be able to see, and what this file
        // itself can: `import public` re-exports, a plain `import` does not.
        let mut exports = BTreeSet::from([file]);
        let mut visible = BTreeSet::from([file]);
        for (dep, kind) in deps {
            visible.extend(self.exports[*dep].iter().copied());
            if *kind == ImportKind::Public {
                exports.extend(self.exports[*dep].iter().copied());
            }
        }
        self.exports[file] = exports;
        self.visible[file] = visible;

        let mut package = String::new();
        if let Some(p) = &ast.package {
            for part in p.name.split('.') {
                package = join(&package, part);
                self.declare(package.clone(), Kind::Package, file, p.pos)?;
            }
        }
        for m in &ast.messages {
            self.declare_message(&package, m, file)?;
        }
        for e in &ast.enums {
            self.declare_enum(&package, e, file)?;
        }
        for s in &ast.services {
            self.declare(join(&package, &s.name), Kind::Service, file, s.pos)?;
        }

        for m in &ast.messages {
            self.link_message(&package, m, file)?;
        }
        Ok(())
    }

    // ---- resolving field types -------------------------------------------

    fn find(&self, name: &str) -> Option<Symbol> {
        self.symbols.get(name).copied()
    }

    /// The symbol a type name written inside `relative_to` refers to, with its
    /// full name -- `protoc`'s own search (`DescriptorBuilder::LookupSymbol`):
    /// the first part of the name is looked for in the enclosing scopes from
    /// the innermost out, the first scope that has it wins, and the rest of a
    /// dotted name is then looked for inside what was found, with no turning
    /// back. A symbol of the right name that is not something a name can
    /// descend into, or not a type where one is needed, is stepped over.
    fn lookup(&self, name: &str, relative_to: &str) -> Option<(String, Symbol)> {
        if let Some(absolute) = name.strip_prefix('.') {
            return self.find(absolute).map(|s| (String::from(absolute), s));
        }
        let first_len = name.find('.').unwrap_or(name.len());
        let first = &name[..first_len];
        let mut scope = String::from(relative_to);
        loop {
            match scope.rfind('.') {
                None => return self.find(name).map(|s| (String::from(name), s)),
                Some(p) => scope.truncate(p),
            }
            let candidate = join(&scope, first);
            let Some(sym) = self.find(&candidate) else {
                continue;
            };
            if first_len < name.len() {
                if sym.kind.is_aggregate() {
                    let full = format!("{candidate}{}", &name[first_len..]);
                    return self.find(&full).map(|s| (full, s));
                }
            } else if sym.kind.is_type() {
                return Some((candidate, sym));
            }
        }
    }

    /// Resolve the type written at `pos` inside `field_full`, the full name of
    /// the field that mentions it.
    fn resolve(
        &self,
        file: usize,
        field_full: &str,
        text: &str,
        pos: Pos,
    ) -> Result<Symbol, ProtoDiagnostic> {
        let here = self.name_of(file);
        let Some((_, sym)) = self.lookup(text, field_full) else {
            return Err(ProtoDiagnostic::at(
                here,
                pos,
                format!("\"{text}\" is not defined"),
            ));
        };
        if !sym.kind.is_type() {
            return Err(ProtoDiagnostic::at(
                here,
                pos,
                format!("\"{text}\" is not a type"),
            ));
        }
        if !self.visible[file].contains(&sym.file) {
            return Err(ProtoDiagnostic::at(
                here,
                pos,
                format!(
                    "\"{text}\" seems to be defined in \"{}\", which is not imported by \
                     \"{here}\"; to use it here, add the import",
                    self.name_of(sym.file)
                ),
            ));
        }
        Ok(sym)
    }

    fn link_message(
        &mut self,
        scope: &str,
        m: &MessageDecl,
        file: usize,
    ) -> Result<(), ProtoDiagnostic> {
        let here = self.name_of(file);
        let full = join(scope, &m.name.name);
        let Some(Symbol {
            kind: Kind::Message(idx),
            ..
        }) = self.find(&full)
        else {
            // `declare_message` just registered it; its absence would be a bug
            // in this file, reported as a refusal rather than a panic.
            return Err(ProtoDiagnostic::in_file(
                here,
                "internal: message not registered",
            ));
        };

        let mut seen: BTreeMap<u64, &str> = BTreeMap::new();
        let mut fields = Vec::with_capacity(m.fields.len());
        for f in &m.fields {
            let number = f.number;
            let bad_number = if number == 0 {
                Some(String::from("field numbers must be positive integers"))
            } else if number > MAX_FIELD_NUMBER {
                Some(format!(
                    "field numbers cannot be greater than {MAX_FIELD_NUMBER}"
                ))
            } else if (19_000..=19_999).contains(&number) {
                Some(String::from(
                    "field numbers 19000 through 19999 are reserved for the protocol buffer \
                     library implementation",
                ))
            } else {
                None
            };
            if let Some(reason) = bad_number {
                return Err(ProtoDiagnostic::at(here, f.number_pos, reason));
            }
            if m.reserved_ranges
                .iter()
                .any(|&(a, b)| (a..=b).contains(&number))
            {
                return Err(ProtoDiagnostic::at(
                    here,
                    f.number_pos,
                    format!("field `{}` uses the reserved number {number}", f.name.name),
                ));
            }
            if m.reserved_names.contains(&f.name.name) {
                return Err(ProtoDiagnostic::at(
                    here,
                    f.name.pos,
                    format!("the field name `{}` is reserved", f.name.name),
                ));
            }
            if let Some(first) = seen.insert(number, f.name.name.as_str()) {
                return Err(ProtoDiagnostic::at(
                    here,
                    f.number_pos,
                    format!(
                        "field number {number} is already used in \"{full}\" by field `{first}`"
                    ),
                ));
            }

            let field_full = join(&full, &f.name.name);
            let (target, ty_pos) = match &f.ty {
                FieldType::Scalar => (Target::Leaf, f.ty_pos),
                FieldType::Named(t) => {
                    let sym = self.resolve(file, &field_full, &t.text, t.pos)?;
                    match sym.kind {
                        Kind::Message(target) => (Target::Message(target), t.pos),
                        _ => (Target::Leaf, t.pos),
                    }
                }
                FieldType::Map(map) => {
                    if let Some(reason) = &map.key_error {
                        return Err(ProtoDiagnostic::at(here, f.ty_pos, reason.clone()));
                    }
                    match &map.value {
                        MapValue::Scalar => (Target::Map(None), f.ty_pos),
                        MapValue::Named(t) => {
                            let sym = self.resolve(file, &field_full, &t.text, t.pos)?;
                            match sym.kind {
                                Kind::Message(target) => (Target::Map(Some(target)), t.pos),
                                _ => (Target::Map(None), t.pos),
                            }
                        }
                    }
                }
            };
            fields.push(Fld {
                name: f.name.name.clone(),
                number,
                target,
                ty_pos,
            });
        }
        self.msgs[idx].fields = fields;

        for n in &m.nested {
            self.link_message(&full, n, file)?;
        }
        Ok(())
    }

    // ---- the root and the expansion --------------------------------------

    fn root_message(&self, name: &str, root_file: usize) -> Result<usize, ProtoDiagnostic> {
        let here = self.name_of(root_file);
        match self.find(name) {
            Some(Symbol {
                kind: Kind::Message(idx),
                ..
            }) => Ok(idx),
            Some(Symbol { kind, .. }) => Err(ProtoDiagnostic::in_file(
                here,
                format!(
                    "`{name}` is {}, not a message",
                    match kind {
                        Kind::Enum => "an enum",
                        Kind::Package => "a package",
                        Kind::Service => "a service",
                        Kind::Field | Kind::Oneof | Kind::EnumValue =>
                            "a member of a message or enum",
                        Kind::Message(_) => "a message",
                    }
                ),
            )),
            None => Err(ProtoDiagnostic::in_file(
                here,
                format!(
                    "the message `{name}` is not defined in this file or in the files it imports \
                     (the name is the full name, package included)"
                ),
            )),
        }
    }

    /// Write the lines of `msg`'s fields under `prefix`, recursing into message
    /// types. `stack` is the messages being expanded, outermost first.
    fn expand(
        &self,
        msg: usize,
        prefix: &str,
        stack: &mut Vec<usize>,
        out: &mut Emitter,
    ) -> Result<(), ProtoDiagnostic> {
        stack.push(msg);
        for f in &self.msgs[msg].fields {
            let path = if prefix.is_empty() {
                format!("{}", f.number)
            } else {
                format!("{prefix}.{}", f.number)
            };
            out.name(&path, &f.name)?;
            match f.target {
                Target::Leaf => {}
                Target::Message(inner) => self.descend(inner, &path, f.ty_pos, stack, out)?,
                Target::Map(value) => {
                    out.name(&format!("{path}.1"), "key")?;
                    let value_path = format!("{path}.2");
                    out.name(&value_path, "value")?;
                    if let Some(inner) = value {
                        self.descend(inner, &value_path, f.ty_pos, stack, out)?;
                    }
                }
            }
        }
        stack.pop();
        Ok(())
    }

    /// Step into the message `inner` at `path`, refusing a message that is
    /// already being expanded and a chain that is too long.
    fn descend(
        &self,
        inner: usize,
        path: &str,
        ty_pos: Pos,
        stack: &mut Vec<usize>,
        out: &mut Emitter,
    ) -> Result<(), ProtoDiagnostic> {
        let holder = &self.msgs[stack.last().copied().unwrap_or(inner)];
        let here = self.name_of(holder.file);
        if let Some(from) = stack.iter().position(|&m| m == inner) {
            let mut chain: Vec<&str> = stack[from..]
                .iter()
                .map(|&m| self.msgs[m].full_name.as_str())
                .collect();
            chain.push(self.msgs[inner].full_name.as_str());
            return Err(ProtoDiagnostic::at(
                here,
                ty_pos,
                format!(
                    "the message `{}` contains itself ({}): its fields would need a declaration \
                     at every depth, so a recursive message cannot be declared",
                    self.msgs[inner].full_name,
                    chain.join(" -> ")
                ),
            ));
        }
        if stack.len() >= MAX_PATH_DEPTH {
            return Err(ProtoDiagnostic::at(
                here,
                ty_pos,
                format!("messages are nested more than {MAX_PATH_DEPTH} levels deep at `{path}`"),
            ));
        }
        self.expand(inner, path, stack, out)
    }
}

/// `scope.name`, or `name` at the root.
fn join(scope: &str, name: &str) -> String {
    if scope.is_empty() {
        String::from(name)
    } else {
        format!("{scope}.{name}")
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

    fn rule(&mut self) -> Result<(), ProtoDiagnostic> {
        self.reserve()?;
        self.text.push_str(&self.key);
        self.text.push_str("=protobuf\n");
        Ok(())
    }

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
