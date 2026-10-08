// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The `.proto` parser behind [`crate::proto_schema`].
//!
//! Private for the reason [`crate::proto_lex`] is. It turns one file's text into
//! the part of the syntax tree the declaration door needs: the package, the
//! imports, and for every message its fields (name, number, type, position),
//! its nested messages and enums, its oneofs and its reserved ranges and names.
//!
//! ## What is read and what is skipped
//!
//! Read: `syntax`, `package`, `import` and `import public`, `message` (with
//! nesting), `enum` (names only), `oneof`, `map<K, V>`, the three labels,
//! `reserved` (ranges and names) and `extensions` (ranges, ignored).
//!
//! Skipped, but with the statement's own grammar so a mistake in one lands on
//! the token that is wrong and does not swallow the statements after it:
//! `option` statements, field and enum-value `[...]` options, and `service`
//! blocks (balanced braces).
//!
//! Refused with a stated reason: `group`, `extend`, `import weak` and editions.
//!
//! ## Which refusals are the parser's and which are the linker's
//!
//! `protoc` reports a SYNTAX problem and stops; it only builds descriptors, and
//! so only reports a number, a name or a type problem, once the whole file
//! parsed. This reader keeps that order, so a file with a bad field number at
//! line 3 and a missing `;` at line 40 is blamed at line 40 by both. What is
//! therefore recorded here and judged later is everything `protoc` judges in
//! its builder: field-number ranges, duplicate numbers and names, reserved
//! numbers and names, map key types and every type reference.

use alloc::collections::VecDeque;
use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;

use crate::proto_lex::{Lexer, Pos, SyntaxError, Tok, Token};

/// The largest legal field number, `2^29 - 1`: the tag keeps three bits for the
/// wire type in a 32-bit varint.
pub(crate) const MAX_FIELD_NUMBER: u64 = 536_870_911;

/// How deeply messages may be written inside one another.
///
/// The parser recurses once per level, and a `.proto` is text a person handed
/// over: without a bound, a file of nothing but `message A {` repeated is a
/// stack overflow in whatever thread called this library. 32 is far past any
/// schema written by hand; `protoc` itself stops at 100 levels.
pub(crate) const MAX_MESSAGE_NESTING: usize = 32;

/// The scalar type keywords. A field of one of these has no structure to name.
const SCALARS: &[&str] = &[
    "double", "float", "int32", "int64", "uint32", "uint64", "sint32", "sint64", "fixed32",
    "fixed64", "sfixed32", "sfixed64", "bool", "string", "bytes",
];

/// The scalar types a map key may be: integral types and `string` (language
/// guide, "Maps": the key type "can be any integral or string type").
const MAP_KEYS: &[&str] = &[
    "int32", "int64", "uint32", "uint64", "sint32", "sint64", "fixed32", "fixed64", "sfixed32",
    "sfixed64", "bool", "string",
];

/// Which `syntax` the file declared. Without a statement it is proto2, which is
/// what `protoc` assumes too.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Syntax {
    Proto2,
    Proto3,
}

/// How a file imports another.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ImportKind {
    Normal,
    Public,
}

/// One `import` statement.
#[derive(Clone, Debug)]
pub(crate) struct Import {
    pub path: String,
    pub kind: ImportKind,
    /// The `import` keyword, which is where `protoc` blames a missing file.
    pub pos: Pos,
}

/// A name and where it was written.
#[derive(Clone, Debug)]
pub(crate) struct Named {
    pub name: String,
    pub pos: Pos,
}

/// An enum: only its names matter, to the symbol table.
#[derive(Clone, Debug)]
pub(crate) struct EnumDecl {
    pub name: Named,
    pub values: Vec<Named>,
}

/// A type reference as written, `.pkg.Outer.Inner` or `Inner`.
#[derive(Clone, Debug)]
pub(crate) struct TypeName {
    pub text: String,
    pub pos: Pos,
}

/// The value type of a map field.
#[derive(Clone, Debug)]
pub(crate) enum MapValue {
    Scalar,
    Named(TypeName),
}

/// A `map<K, V>` field.
#[derive(Clone, Debug)]
pub(crate) struct MapType {
    /// Why the key type is not allowed, judged later (see the module doc).
    pub key_error: Option<String>,
    pub value: MapValue,
}

/// What a field's type is, as far as the declaration door cares.
#[derive(Clone, Debug)]
pub(crate) enum FieldType {
    /// A scalar keyword: no nested structure.
    Scalar,
    /// A message or an enum, to be resolved.
    Named(TypeName),
    Map(MapType),
}

/// One field.
#[derive(Clone, Debug)]
pub(crate) struct FieldDecl {
    pub name: Named,
    pub number: u64,
    pub number_pos: Pos,
    pub ty: FieldType,
    /// The first token of the type, where a map key problem is blamed.
    pub ty_pos: Pos,
}

/// One message.
#[derive(Clone, Debug)]
pub(crate) struct MessageDecl {
    pub name: Named,
    pub oneofs: Vec<Named>,
    pub fields: Vec<FieldDecl>,
    pub nested: Vec<MessageDecl>,
    pub enums: Vec<EnumDecl>,
    /// Inclusive `(first, last)` ranges.
    pub reserved_ranges: Vec<(u64, u64)>,
    pub reserved_names: Vec<String>,
}

/// One parsed file.
#[derive(Clone, Debug)]
pub(crate) struct FileAst {
    pub syntax: Syntax,
    pub package: Option<Named>,
    pub imports: Vec<Import>,
    pub messages: Vec<MessageDecl>,
    pub enums: Vec<EnumDecl>,
    pub services: Vec<Named>,
}

/// A readable name for what a token is, for "expected X, found Y".
fn describe(tok: &Tok<'_>) -> String {
    match tok {
        Tok::Ident(s) => format!("`{s}`"),
        Tok::Int(n) => format!("the number {n}"),
        Tok::Float => String::from("a floating-point number"),
        Tok::Str(_) => String::from("a string"),
        Tok::Sym(c) => format!("`{c}`"),
        Tok::Eof => String::from("the end of the file"),
    }
}

/// Where a field is written: a message body, or a oneof inside one.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Scope {
    Message,
    Oneof,
}

struct Parser<'a> {
    lex: Lexer<'a>,
    ahead: VecDeque<Result<Token<'a>, SyntaxError>>,
    syntax: Syntax,
}

/// Parse one file.
///
/// The first problem is the only one reported: it is the one a person fixes
/// first, and later ones are often its consequence.
pub(crate) fn parse_file(src: &str) -> Result<FileAst, SyntaxError> {
    let mut p = Parser {
        lex: Lexer::new(src),
        ahead: VecDeque::new(),
        syntax: Syntax::Proto2,
    };
    p.file()
}

impl<'a> Parser<'a> {
    fn fill(&mut self, n: usize) {
        while self.ahead.len() <= n {
            let next = self.lex.next_token();
            self.ahead.push_back(next);
        }
    }

    /// The next token without consuming it. A lexical error surfaces here,
    /// because here is where the parser first needs the token.
    fn peek(&mut self) -> Result<&Token<'a>, SyntaxError> {
        self.fill(0);
        match &self.ahead[0] {
            Ok(t) => Ok(t),
            Err(e) => Err(e.clone()),
        }
    }

    /// The token after the next, or `None` when it does not lex: the parser
    /// will meet that error itself when it consumes up to it.
    fn peek_second(&mut self) -> Option<&Token<'a>> {
        self.fill(1);
        self.ahead[1].as_ref().ok()
    }

    fn bump(&mut self) -> Result<Token<'a>, SyntaxError> {
        self.fill(0);
        match self.ahead.pop_front() {
            Some(t) => t,
            // `fill(0)` leaves at least one entry; this arm is unreachable but
            // total, so a future edit to `fill` cannot turn it into a panic.
            None => Err(SyntaxError::new(
                Pos { line: 1, col: 1 },
                "internal: no token",
            )),
        }
    }

    fn is_sym(&mut self, c: char) -> bool {
        matches!(self.peek(), Ok(t) if t.tok == Tok::Sym(c))
    }

    fn is_ident(&mut self, word: &str) -> bool {
        matches!(self.peek(), Ok(t) if t.tok == Tok::Ident(word))
    }

    fn expect_sym(&mut self, c: char, context: &str) -> Result<Pos, SyntaxError> {
        let t = self.bump()?;
        if t.tok == Tok::Sym(c) {
            Ok(t.pos)
        } else {
            Err(SyntaxError::new(
                t.pos,
                format!("expected `{c}` {context}, found {}", describe(&t.tok)),
            ))
        }
    }

    fn expect_ident(&mut self, what: &str) -> Result<Named, SyntaxError> {
        let t = self.bump()?;
        match t.tok {
            Tok::Ident(s) => Ok(Named {
                name: String::from(s),
                pos: t.pos,
            }),
            other => Err(SyntaxError::new(
                t.pos,
                format!("expected {what}, found {}", describe(&other)),
            )),
        }
    }

    /// `ident(.ident)*`, as one dotted string.
    fn dotted_name(&mut self, what: &str) -> Result<Named, SyntaxError> {
        let first = self.expect_ident(what)?;
        let mut name = first.name;
        while self.is_sym('.') {
            self.bump()?;
            let part = self.expect_ident(what)?;
            name.push('.');
            name.push_str(&part.name);
        }
        Ok(Named {
            name,
            pos: first.pos,
        })
    }

    /// One string literal, or several adjacent ones, as text.
    fn string_value(&mut self) -> Result<(String, Pos), SyntaxError> {
        let t = self.bump()?;
        let Tok::Str(mut bytes) = t.tok else {
            return Err(SyntaxError::new(
                t.pos,
                format!("expected a string, found {}", describe(&t.tok)),
            ));
        };
        while matches!(self.peek(), Ok(n) if matches!(n.tok, Tok::Str(_))) {
            if let Tok::Str(more) = self.bump()?.tok {
                bytes.extend_from_slice(&more);
            }
        }
        String::from_utf8(bytes)
            .map(|s| (s, t.pos))
            .map_err(|_| SyntaxError::new(t.pos, "the string is not valid UTF-8"))
    }

    // ---- file level -------------------------------------------------------

    fn file(&mut self) -> Result<FileAst, SyntaxError> {
        let mut ast = FileAst {
            syntax: Syntax::Proto2,
            package: None,
            imports: Vec::new(),
            messages: Vec::new(),
            enums: Vec::new(),
            services: Vec::new(),
        };
        if self.is_ident("syntax") {
            ast.syntax = self.syntax_statement()?;
            self.syntax = ast.syntax;
        }
        loop {
            let t = self.peek()?.clone();
            match t.tok {
                Tok::Eof => return Ok(ast),
                Tok::Sym(';') => {
                    self.bump()?;
                }
                Tok::Ident("import") => {
                    let import = self.import_statement()?;
                    ast.imports.push(import);
                }
                Tok::Ident("package") => {
                    self.bump()?;
                    if ast.package.is_some() {
                        return Err(SyntaxError::new(t.pos, "a file has one package statement"));
                    }
                    let name = self.dotted_name("a package name")?;
                    self.expect_sym(';', "after the package name")?;
                    ast.package = Some(name);
                }
                Tok::Ident("option") => self.option_statement()?,
                Tok::Ident("message") => {
                    let m = self.message(0)?;
                    ast.messages.push(m);
                }
                Tok::Ident("enum") => {
                    let e = self.enum_decl()?;
                    ast.enums.push(e);
                }
                Tok::Ident("service") => {
                    self.bump()?;
                    let name = self.expect_ident("a service name")?;
                    self.skip_braces("a service")?;
                    ast.services.push(name);
                }
                Tok::Ident("extend") => return Err(refuse_extend(t.pos)),
                Tok::Ident("edition") => {
                    return Err(SyntaxError::new(
                        t.pos,
                        "editions are not supported: declare `syntax = \"proto2\";` or \
                         `syntax = \"proto3\";`",
                    ))
                }
                other => {
                    return Err(SyntaxError::new(
                        t.pos,
                        format!(
                            "expected a top-level statement (`message`, `enum`, `import`, ...), \
                             found {}",
                            describe(&other)
                        ),
                    ))
                }
            }
        }
    }

    fn syntax_statement(&mut self) -> Result<Syntax, SyntaxError> {
        self.bump()?;
        self.expect_sym('=', "after `syntax`")?;
        let (value, pos) = self.string_value()?;
        self.expect_sym(';', "after the syntax string")?;
        match value.as_str() {
            "proto2" => Ok(Syntax::Proto2),
            "proto3" => Ok(Syntax::Proto3),
            other => Err(SyntaxError::new(
                pos,
                format!(
                    "unrecognised syntax \"{other}\": this reader knows \"proto2\" and \"proto3\""
                ),
            )),
        }
    }

    fn import_statement(&mut self) -> Result<Import, SyntaxError> {
        let at = self.bump()?;
        let mut kind = ImportKind::Normal;
        if self.is_ident("public") {
            self.bump()?;
            kind = ImportKind::Public;
        } else if self.is_ident("weak") {
            let weak = self.bump()?;
            return Err(SyntaxError::new(
                weak.pos,
                "`import weak` is not supported: a weak import is a dependency a build may \
                 leave out, so the names it would declare cannot be relied on",
            ));
        }
        let (path, _) = self.string_value()?;
        self.expect_sym(';', "after the imported path")?;
        Ok(Import {
            path,
            kind,
            pos: at.pos,
        })
    }

    // ---- skipped constructs ----------------------------------------------

    /// Consume a `{ ... }` block, whatever is inside it, and report where it
    /// ended. The brace under the cursor opens it.
    fn skip_braces(&mut self, what: &str) -> Result<(), SyntaxError> {
        self.expect_sym('{', &format!("to open {what}"))?;
        let mut depth = 1usize;
        loop {
            let t = self.bump()?;
            match t.tok {
                Tok::Eof => {
                    return Err(SyntaxError::new(
                        t.pos,
                        format!("end of file inside {what} (missing `}}`)"),
                    ))
                }
                Tok::Sym('{') => depth += 1,
                Tok::Sym('}') => {
                    depth -= 1;
                    if depth == 0 {
                        return Ok(());
                    }
                }
                _ => {}
            }
        }
    }

    /// `option name = value;` with the statement's own grammar.
    fn option_statement(&mut self) -> Result<(), SyntaxError> {
        self.bump()?;
        self.option_assignment()?;
        self.expect_sym(';', "after the option")?;
        Ok(())
    }

    /// `name = value`, shared by option statements and `[...]` lists.
    fn option_assignment(&mut self) -> Result<(), SyntaxError> {
        // The name: parts joined by dots, a part being an identifier or an
        // extension name in parentheses.
        loop {
            let t = self.bump()?;
            match t.tok {
                Tok::Ident(_) => {}
                Tok::Sym('(') => loop {
                    let inner = self.bump()?;
                    match inner.tok {
                        Tok::Ident(_) | Tok::Sym('.') => {}
                        Tok::Sym(')') => break,
                        other => {
                            return Err(SyntaxError::new(
                                inner.pos,
                                format!(
                                    "expected `)` to close the extension name in an option, \
                                     found {}",
                                    describe(&other)
                                ),
                            ))
                        }
                    }
                },
                other => {
                    return Err(SyntaxError::new(
                        t.pos,
                        format!("expected an option name, found {}", describe(&other)),
                    ))
                }
            }
            if self.is_sym('.') {
                self.bump()?;
            } else {
                break;
            }
        }
        self.expect_sym('=', "after the option name")?;
        // The value: a signed identifier or number, strings, or an aggregate.
        let v = self.peek()?.clone();
        match v.tok {
            Tok::Sym('-') => {
                self.bump()?;
                let n = self.bump()?;
                if !matches!(n.tok, Tok::Ident(_) | Tok::Int(_) | Tok::Float) {
                    return Err(SyntaxError::new(
                        n.pos,
                        format!("expected a number after `-`, found {}", describe(&n.tok)),
                    ));
                }
            }
            Tok::Ident(_) | Tok::Int(_) | Tok::Float => {
                self.bump()?;
            }
            Tok::Str(_) => {
                self.string_value()?;
            }
            Tok::Sym('{') => self.skip_braces("an option value")?,
            other => {
                return Err(SyntaxError::new(
                    v.pos,
                    format!("expected an option value, found {}", describe(&other)),
                ))
            }
        }
        Ok(())
    }

    /// `[name = value, ...]` after a field or an enum value.
    fn bracketed_options(&mut self) -> Result<(), SyntaxError> {
        self.expect_sym('[', "to open the options")?;
        loop {
            self.option_assignment()?;
            let t = self.bump()?;
            match t.tok {
                Tok::Sym(',') => {}
                Tok::Sym(']') => return Ok(()),
                other => {
                    return Err(SyntaxError::new(
                        t.pos,
                        format!(
                            "expected `,` or `]` in the options, found {}",
                            describe(&other)
                        ),
                    ))
                }
            }
        }
    }

    // ---- enums ------------------------------------------------------------

    fn enum_decl(&mut self) -> Result<EnumDecl, SyntaxError> {
        self.bump()?;
        let name = self.expect_ident("an enum name")?;
        self.expect_sym('{', "to open the enum")?;
        let mut values = Vec::new();
        loop {
            let t = self.peek()?.clone();
            match t.tok {
                Tok::Sym('}') => {
                    self.bump()?;
                    return Ok(EnumDecl { name, values });
                }
                Tok::Eof => {
                    return Err(SyntaxError::new(
                        t.pos,
                        "end of file inside an enum (missing `}`)",
                    ))
                }
                Tok::Sym(';') => {
                    self.bump()?;
                }
                Tok::Ident("option") => self.option_statement()?,
                Tok::Ident("reserved") => {
                    // Ranges and names, in a grammar of numbers, `to`, `max`,
                    // commas and strings; nothing here names a declared value.
                    self.bump()?;
                    loop {
                        let r = self.bump()?;
                        match r.tok {
                            Tok::Sym(';') => break,
                            Tok::Eof => {
                                return Err(SyntaxError::new(
                                    r.pos,
                                    "end of file inside an enum reservation (missing `;`)",
                                ))
                            }
                            _ => {}
                        }
                    }
                }
                Tok::Ident(_) => {
                    let value = self.expect_ident("an enum value name")?;
                    self.expect_sym('=', "after the enum value name")?;
                    if self.is_sym('-') {
                        self.bump()?;
                    }
                    let n = self.bump()?;
                    if !matches!(n.tok, Tok::Int(_)) {
                        return Err(SyntaxError::new(
                            n.pos,
                            format!(
                                "expected the enum value's number, found {}",
                                describe(&n.tok)
                            ),
                        ));
                    }
                    if self.is_sym('[') {
                        self.bracketed_options()?;
                    }
                    self.expect_sym(';', "after the enum value")?;
                    values.push(value);
                }
                other => {
                    return Err(SyntaxError::new(
                        t.pos,
                        format!("expected an enum value, found {}", describe(&other)),
                    ))
                }
            }
        }
    }

    // ---- messages ---------------------------------------------------------

    fn message(&mut self, depth: usize) -> Result<MessageDecl, SyntaxError> {
        let keyword = self.bump()?;
        if depth >= MAX_MESSAGE_NESTING {
            return Err(SyntaxError::new(
                keyword.pos,
                format!("messages are nested more than {MAX_MESSAGE_NESTING} levels deep"),
            ));
        }
        let name = self.expect_ident("a message name")?;
        self.expect_sym('{', "to open the message")?;
        let mut msg = MessageDecl {
            name,
            oneofs: Vec::new(),
            fields: Vec::new(),
            nested: Vec::new(),
            enums: Vec::new(),
            reserved_ranges: Vec::new(),
            reserved_names: Vec::new(),
        };
        loop {
            let t = self.peek()?.clone();
            match t.tok {
                Tok::Sym('}') => {
                    self.bump()?;
                    return Ok(msg);
                }
                Tok::Eof => {
                    return Err(SyntaxError::new(
                        t.pos,
                        "end of file inside a message (missing `}`)",
                    ))
                }
                Tok::Sym(';') => {
                    self.bump()?;
                }
                Tok::Ident("message") => {
                    let nested = self.message(depth + 1)?;
                    msg.nested.push(nested);
                }
                Tok::Ident("enum") => {
                    let e = self.enum_decl()?;
                    msg.enums.push(e);
                }
                Tok::Ident("extend") => return Err(refuse_extend(t.pos)),
                Tok::Ident("option") => self.option_statement()?,
                Tok::Ident("extensions") => self.extensions(t.pos)?,
                Tok::Ident("reserved") => self.reserved(&mut msg)?,
                Tok::Ident("oneof") => self.oneof(&mut msg)?,
                _ => {
                    let f = self.field(Scope::Message)?;
                    msg.fields.push(f);
                }
            }
        }
    }

    fn oneof(&mut self, msg: &mut MessageDecl) -> Result<(), SyntaxError> {
        self.bump()?;
        let name = self.expect_ident("a oneof name")?;
        self.expect_sym('{', "to open the oneof")?;
        msg.oneofs.push(name);
        loop {
            let t = self.peek()?.clone();
            match t.tok {
                Tok::Sym('}') => {
                    self.bump()?;
                    return Ok(());
                }
                Tok::Eof => {
                    return Err(SyntaxError::new(
                        t.pos,
                        "end of file inside a oneof (missing `}`)",
                    ))
                }
                Tok::Sym(';') => {
                    self.bump()?;
                }
                Tok::Ident("option") => self.option_statement()?,
                _ => {
                    let f = self.field(Scope::Oneof)?;
                    msg.fields.push(f);
                }
            }
        }
    }

    /// `extensions 100 to 199, 300;`. The ranges are accepted and ignored: the
    /// fields that fill them are declared by `extend`, which is refused.
    fn extensions(&mut self, keyword: Pos) -> Result<(), SyntaxError> {
        self.bump()?;
        let first = self.peek()?.pos;
        if self.syntax == Syntax::Proto3 {
            return Err(SyntaxError::new(
                first,
                "extension ranges are not allowed in proto3",
            ));
        }
        let mut ranges = Vec::new();
        self.ranges(&mut ranges)?;
        if ranges.is_empty() {
            return Err(SyntaxError::new(
                keyword,
                "`extensions` needs at least one range",
            ));
        }
        if self.is_sym('[') {
            self.bracketed_options()?;
        }
        self.expect_sym(';', "after the extension ranges")?;
        Ok(())
    }

    /// `reserved 2, 15, 9 to 11;` or `reserved "foo", "bar";`.
    fn reserved(&mut self, msg: &mut MessageDecl) -> Result<(), SyntaxError> {
        self.bump()?;
        let t = self.peek()?.clone();
        match t.tok {
            Tok::Str(_) => loop {
                let (name, _) = self.string_value()?;
                msg.reserved_names.push(name);
                if self.is_sym(',') {
                    self.bump()?;
                } else {
                    break;
                }
            },
            Tok::Int(_) => {
                let mut ranges = Vec::new();
                self.ranges(&mut ranges)?;
                msg.reserved_ranges.extend(ranges);
            }
            other => {
                return Err(SyntaxError::new(
                    t.pos,
                    format!(
                        "expected a field number range or a quoted field name after `reserved`, \
                         found {}",
                        describe(&other)
                    ),
                ))
            }
        }
        self.expect_sym(';', "after the reservation")?;
        Ok(())
    }

    /// `N`, `N to M` or `N to max`, comma separated.
    fn ranges(&mut self, out: &mut Vec<(u64, u64)>) -> Result<(), SyntaxError> {
        loop {
            let a = self.bump()?;
            let Tok::Int(first) = a.tok else {
                return Err(SyntaxError::new(
                    a.pos,
                    format!("expected a field number, found {}", describe(&a.tok)),
                ));
            };
            let mut last = first;
            if self.is_ident("to") {
                self.bump()?;
                let b = self.bump()?;
                last = match b.tok {
                    Tok::Int(n) => n,
                    Tok::Ident("max") => MAX_FIELD_NUMBER,
                    other => {
                        return Err(SyntaxError::new(
                            b.pos,
                            format!(
                                "expected a field number or `max` after `to`, found {}",
                                describe(&other)
                            ),
                        ))
                    }
                };
            }
            out.push((first, last));
            if self.is_sym(',') {
                self.bump()?;
            } else {
                return Ok(());
            }
        }
    }

    /// One field, with its label if the scope has one.
    fn field(&mut self, scope: Scope) -> Result<FieldDecl, SyntaxError> {
        let first = self.peek()?.clone();
        let label = match first.tok {
            Tok::Ident(w @ ("optional" | "required" | "repeated")) => Some(w),
            _ => None,
        };
        if label.is_some() {
            if scope == Scope::Oneof {
                return Err(SyntaxError::new(
                    first.pos,
                    "fields in a oneof must not have a label (required / optional / repeated)",
                ));
            }
            self.bump()?;
            if label == Some("required") && self.syntax == Syntax::Proto3 {
                // Blamed at the type that follows the label, which is the token
                // `protoc` points at.
                let at = self.peek()?.pos;
                return Err(SyntaxError::new(
                    at,
                    "required fields are not allowed in proto3",
                ));
            }
        } else if scope == Scope::Message && self.syntax == Syntax::Proto2 {
            // A map field has no label even in proto2, and `protoc` accepts it.
            let is_map =
                self.is_ident("map") && self.peek_second().is_some_and(|t| t.tok == Tok::Sym('<'));
            if !is_map {
                return Err(SyntaxError::new(
                    first.pos,
                    "expected `required`, `optional` or `repeated` before the type (proto2 fields \
                     are labelled; declare `syntax = \"proto3\";` to drop the label)",
                ));
            }
        }

        let ty_pos = self.peek()?.pos;
        let ty =
            if self.is_ident("map") && self.peek_second().is_some_and(|t| t.tok == Tok::Sym('<')) {
                if label.is_some() {
                    return Err(SyntaxError::new(
                        ty_pos,
                        "labels (required / optional / repeated) are not allowed on map fields",
                    ));
                }
                if scope == Scope::Oneof {
                    return Err(SyntaxError::new(
                        ty_pos,
                        "map fields are not allowed in a oneof",
                    ));
                }
                FieldType::Map(self.map_type()?)
            } else if self.is_ident("group") {
                return Err(SyntaxError::new(
                    ty_pos,
                    "group fields are not supported: a group is written on the wire with the \
                 deprecated start-group / end-group markers, which the payload reader does not \
                 decode",
                ));
            } else {
                self.type_name("a field type")?
            };

        let name = self.expect_ident("a field name")?;
        self.expect_sym('=', "after the field name")?;
        let n = self.bump()?;
        let Tok::Int(number) = n.tok else {
            return Err(SyntaxError::new(
                n.pos,
                format!("expected the field number, found {}", describe(&n.tok)),
            ));
        };
        if self.is_sym('[') {
            self.bracketed_options()?;
        }
        self.expect_sym(';', "after the field")?;
        Ok(FieldDecl {
            name,
            number,
            number_pos: n.pos,
            ty,
            ty_pos,
        })
    }

    /// A type reference as written: a scalar keyword, or a possibly dotted,
    /// possibly absolute name.
    fn raw_type(&mut self, what: &str) -> Result<TypeName, SyntaxError> {
        let first = self.peek()?.clone();
        let mut text = String::new();
        if first.tok == Tok::Sym('.') {
            self.bump()?;
            text.push('.');
        }
        let head = self.expect_ident(what)?;
        text.push_str(&head.name);
        while self.is_sym('.') {
            self.bump()?;
            let part = self.expect_ident("a name after `.`")?;
            text.push('.');
            text.push_str(&part.name);
        }
        Ok(TypeName {
            text,
            pos: first.pos,
        })
    }

    /// [`Self::raw_type`], sorted into a scalar (nothing to resolve) and a
    /// name (a message or an enum, resolved by the linker).
    fn type_name(&mut self, what: &str) -> Result<FieldType, SyntaxError> {
        let raw = self.raw_type(what)?;
        Ok(if SCALARS.contains(&raw.text.as_str()) {
            FieldType::Scalar
        } else {
            FieldType::Named(raw)
        })
    }

    /// `map<K, V>` with the cursor on `map`.
    fn map_type(&mut self) -> Result<MapType, SyntaxError> {
        self.bump()?;
        self.expect_sym('<', "after `map`")?;
        let key = self.raw_type("the map's key type")?;
        let key_error = (!MAP_KEYS.contains(&key.text.as_str())).then(|| {
            format!(
                "`{}` cannot be a map key: a key must be an integral type or `string`",
                key.text
            )
        });
        self.expect_sym(',', "between the map's key and value types")?;
        let value = match self.type_name("the map's value type")? {
            FieldType::Named(t) => MapValue::Named(t),
            FieldType::Scalar | FieldType::Map(_) => MapValue::Scalar,
        };
        self.expect_sym('>', "to close the map type")?;
        Ok(MapType { key_error, value })
    }
}

fn refuse_extend(pos: Pos) -> SyntaxError {
    SyntaxError::new(
        pos,
        "`extend` is not supported: extension fields are declared outside the message they \
         extend, and this reader declares names from the message tree alone",
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(src: &str) -> FileAst {
        parse_file(src).unwrap_or_else(|e| panic!("{src}\n=> {e:?}"))
    }

    fn fail(src: &str) -> SyntaxError {
        parse_file(src).expect_err("the text must not parse")
    }

    #[test]
    fn a_file_without_a_syntax_statement_is_proto2() {
        assert_eq!(parse("message M {}").syntax, Syntax::Proto2);
        assert_eq!(parse("syntax = \"proto3\";").syntax, Syntax::Proto3);
    }

    #[test]
    fn a_message_keeps_its_fields_nesting_and_oneofs() {
        let ast = parse(
            r#"syntax = "proto3";
               package a.b;
               message M {
                 int32 x = 1;
                 repeated N n = 2 [deprecated = true];
                 oneof pick { string s = 3; int64 i = 4; }
                 map<string, N> by = 5;
                 message N { bool ok = 1; }
                 enum E { Z = 0; ONE = 1 [deprecated = true]; }
                 reserved 7, 9 to 11, 20 to max;
                 reserved "gone";
               }"#,
        );
        let m = &ast.messages[0];
        assert_eq!(ast.package.as_ref().map(|p| p.name.as_str()), Some("a.b"));
        let numbers: Vec<_> = m
            .fields
            .iter()
            .map(|f| (f.name.name.as_str(), f.number))
            .collect();
        assert_eq!(numbers, [("x", 1), ("n", 2), ("s", 3), ("i", 4), ("by", 5)]);
        assert_eq!(m.oneofs[0].name, "pick");
        assert_eq!(m.nested[0].name.name, "N");
        assert_eq!(m.enums[0].values.len(), 2);
        assert_eq!(m.reserved_ranges, [(7, 7), (9, 11), (20, MAX_FIELD_NUMBER)]);
        assert_eq!(m.reserved_names, ["gone"]);
    }

    #[test]
    fn a_proto2_map_field_needs_no_label_and_other_fields_do() {
        parse("syntax = \"proto2\"; message M { map<string, int32> m = 1; }");
        let e = fail("syntax = \"proto2\";\nmessage M {\n  int32 a = 1;\n}");
        assert_eq!(e.pos.line, 3);
        assert!(e.reason.contains("`required`, `optional` or `repeated`"));
    }

    #[test]
    fn options_and_services_are_skipped_with_their_own_grammar() {
        parse(
            r#"syntax = "proto3";
               option java_package = "x";
               option (my.ext).field = { a: 1 b: [1, 2] c { d: "}" } };
               option go = -1;
               service S { rpc A(Q) returns (R) { option deprecated = true; } }
               message M { option deprecated = true; int32 a = 1 [(x.y) = "v", json_name = "z"]; }"#,
        );
    }

    #[test]
    fn an_option_missing_its_semicolon_does_not_swallow_the_next_field() {
        let e = fail(
            "syntax = \"proto3\";\nmessage M {\n  option deprecated = true\n  int32 a = 1;\n}",
        );
        assert_eq!(e.pos.line, 4);
        assert!(e.reason.contains("expected `;`"));
    }

    #[test]
    fn group_extend_weak_and_editions_are_refused_with_a_reason() {
        let e = fail("syntax = \"proto2\";\nmessage M {\n  optional group G = 1 {\n    optional int32 x = 2;\n  }\n}");
        assert_eq!(e.pos.line, 3);
        assert!(e.reason.contains("group fields are not supported"));

        let e = fail("syntax = \"proto2\";\nmessage M { extensions 100 to 199; }\nextend M { optional int32 x = 100; }");
        assert_eq!(e.pos.line, 3);
        assert!(e.reason.contains("`extend` is not supported"));

        let e = fail("syntax = \"proto2\";\nmessage M {\n  extend X { optional int32 y = 1; }\n}");
        assert_eq!(e.pos.line, 3);
        assert!(e.reason.contains("`extend` is not supported"));

        let e = fail("syntax = \"proto3\";\nimport weak \"a.proto\";");
        assert_eq!(e.pos.line, 2);
        assert!(e.reason.contains("import weak"));

        let e = fail("edition = \"2023\";");
        assert!(e.reason.contains("editions are not supported"));
    }

    #[test]
    fn syntax_errors_name_the_token_that_is_wrong() {
        let e = fail("syntax = \"proto3\";\nmessage M {\n  int32 a = 1\n  int32 b = 2;\n}");
        assert_eq!((e.pos.line, e.pos.col), (4, 3));
        assert!(e.reason.contains("expected `;`"));

        let e = fail("syntax = \"proto3\";\nmessage M {\n  int32 = 1;\n}");
        assert_eq!(e.pos.line, 3);
        assert!(e.reason.contains("a field name"));

        let e = fail("syntax = \"proto3\";\nmessage {\n}");
        assert_eq!(e.pos.line, 2);
        assert!(e.reason.contains("a message name"));

        let e = fail("syntax = \"proto3\";\nmessage M {\n  int32 a = -1;\n}");
        assert_eq!(e.pos.line, 3);
        assert!(e.reason.contains("the field number"));

        let e = fail("syntax = \"proto3\";\nfoo bar;");
        assert_eq!(e.pos.line, 2);
        assert!(e.reason.contains("top-level statement"));

        let e = fail("syntax = \"proto3\";\nmessage M {\n  int32 a = 1;\n}\n}\n");
        assert_eq!(e.pos.line, 5);

        let e = fail("syntax = \"proto3\";\nmessage M {\n  int32 a = 1;\n");
        assert!(e.reason.contains("missing `}`"));
    }

    #[test]
    fn a_syntax_statement_is_checked_and_a_package_is_once() {
        let e = fail("syntax = \"proto4\";");
        assert_eq!((e.pos.line, e.pos.col), (1, 10));
        assert!(e.reason.contains("proto4"));
        let e = fail("syntax = \"proto3\";\npackage a;\npackage b;");
        assert_eq!(e.pos.line, 3);
        let e = fail("syntax = \"proto3\"\nmessage M {}");
        assert_eq!(e.pos.line, 2);
    }

    #[test]
    fn proto3_refuses_required_and_extension_ranges_and_labels_in_a_oneof() {
        let e = fail("syntax = \"proto3\";\nmessage M {\n  required int32 a = 1;\n}");
        assert_eq!((e.pos.line, e.pos.col), (3, 12));
        let e = fail("syntax = \"proto3\";\nmessage M {\n  extensions 100 to 199;\n}");
        assert_eq!((e.pos.line, e.pos.col), (3, 14));
        let e = fail(
            "syntax = \"proto3\";\nmessage M {\n  oneof o {\n    repeated int32 a = 1;\n  }\n}",
        );
        assert_eq!((e.pos.line, e.pos.col), (4, 5));
        let e = fail("syntax = \"proto3\";\nmessage M {\n  repeated map<int32, int32> a = 1;\n}");
        assert_eq!(e.pos.line, 3);
    }

    #[test]
    fn messages_nested_past_the_bound_are_refused_without_overflowing_the_stack() {
        let mut src = String::from("syntax = \"proto3\";\n");
        for i in 0..100_000 {
            src.push_str(&format!("message M{i} {{\n"));
        }
        let e = fail(&src);
        assert!(e.reason.contains("nested more than"));
        assert_eq!(e.pos.line as usize, MAX_MESSAGE_NESTING + 2);
    }

    #[test]
    fn a_lexical_error_after_a_syntax_error_is_not_the_one_reported() {
        // The syntax error is at line 2; the unterminated string is at line 3.
        // A parser that lexed first would report line 3.
        let e = fail("syntax = \"proto3\";\nmessage M { int32 = 1; }\n\"never closed");
        assert_eq!(e.pos.line, 2);
    }

    #[test]
    fn a_reserved_statement_must_say_what_it_reserves() {
        let e = fail("syntax = \"proto3\";\nmessage M {\n  reserved a;\n}");
        assert_eq!(e.pos.line, 3);
        let e = fail("syntax = \"proto3\";\nmessage M {\n  reserved \"a\", 5;\n}");
        assert_eq!(e.pos.line, 3);
    }

    #[test]
    fn a_map_key_that_is_not_integral_or_string_is_recorded_for_the_linker() {
        let ast = parse("syntax = \"proto3\"; message M { map<Foo, int32> a = 1; }");
        let FieldType::Map(map) = &ast.messages[0].fields[0].ty else {
            panic!("a map field");
        };
        assert!(map.key_error.is_some());
        // `float` is a scalar keyword but not a key: the linker judges it, so
        // the parser does not report it ahead of an earlier syntax error.
        let ast = parse("syntax = \"proto3\"; message M { map<float, int32> a = 1; }");
        let FieldType::Map(map) = &ast.messages[0].fields[0].ty else {
            panic!("a map field");
        };
        assert!(map.key_error.is_some());
        let ast = parse("syntax = \"proto3\"; message M { map<fixed64, int32> a = 1; }");
        let FieldType::Map(map) = &ast.messages[0].fields[0].ty else {
            panic!("a map field");
        };
        assert!(map.key_error.is_none());
    }
}
