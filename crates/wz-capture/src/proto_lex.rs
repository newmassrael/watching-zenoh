// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The `.proto` tokenizer behind [`crate::proto_schema`].
//!
//! Private for the reason [`crate::payload_builtin`] is: the one module a caller
//! reads is `proto_schema`, and the file boundary is an authoring convenience.
//!
//! ## What it reads
//!
//! protobuf's own lexical grammar (`google/protobuf/io/tokenizer.h` in the
//! upstream `protobuf` sources, and the "Lexical elements" section of the
//! language specification): identifiers, decimal / octal / hexadecimal
//! integers, floating-point literals, single- and double-quoted strings with
//! the C-style escapes, `//` and `/* */` comments, and single-character
//! symbols. A leading UTF-8 byte-order mark is skipped, which `protoc` also
//! accepts.
//!
//! ## Lazily, and why that is not a style choice
//!
//! The tokenizer hands out ONE token per call. A caller that lexed the whole
//! file first would report a lexical error at line 90 ahead of a syntax error
//! at line 3, which blames a line `protoc` does not blame. Errors therefore
//! surface at the position in the stream where the parser first needs the
//! token, which is the order `protoc` reports them in.
//!
//! ## Positions
//!
//! Lines and columns are 1-based. A column counts BYTES from the start of the
//! line, so a tab is one column and a multi-byte UTF-8 character is several;
//! `protoc` expands a tab to the next multiple of eight, which is a display
//! decision this reader does not reproduce.

use alloc::rc::Rc;
use alloc::string::String;
use alloc::vec::Vec;

/// A place in a source file.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct Pos {
    /// 1-based line.
    pub line: u32,
    /// 1-based byte column within the line.
    pub col: u32,
}

/// A lexical or syntactic refusal, with the place it is blamed on.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct SyntaxError {
    pub pos: Pos,
    pub reason: String,
}

impl SyntaxError {
    pub(crate) fn new(pos: Pos, reason: impl Into<String>) -> Self {
        Self {
            pos,
            reason: reason.into(),
        }
    }
}

/// What a token is.
#[derive(Clone, Debug, PartialEq)]
pub(crate) enum Tok<'a> {
    /// `[A-Za-z_][A-Za-z0-9_]*`.
    Ident(&'a str),
    /// A decimal, octal or hexadecimal integer that fits `u64`.
    Int(u64),
    /// A floating-point literal. The value is never needed: a float appears
    /// only in option values and default values, which are skipped.
    Float,
    /// A string literal, escapes decoded, as raw bytes. Whether the bytes are
    /// text is the parser's question, asked only where a string is USED.
    Str(Vec<u8>),
    /// One punctuation character.
    Sym(char),
    /// The end of the file.
    Eof,
}

/// The comments found in the gap in front of a token, by `protoc`'s own rules.
///
/// `protoc` does not keep every comment: it decides, at the gap between two
/// tokens, which comment trails the token before and which leads the token
/// after, and drops the rest as detached. The rule (`NextWithComments` in
/// `google/protobuf/io/tokenizer.cc`):
///
/// * a comment that starts on the same line as the token before trails it, a
///   `//` comment alone (the comments on the lines below do not join it), a
///   `/* */` comment only when nothing else follows it on its line (otherwise it
///   belongs to nobody);
/// * a run of `//` comments on the lines after, with no blank line between them
///   and the token before, trails that token too when a blank line follows the
///   run, and leads the next token when none does;
/// * a blank line detaches whatever precedes it from both;
/// * a comment before a closing `}`, `]` or `)` or before the end of the file
///   leads nothing.
///
/// The text of a comment is what `protoc` stores in `SourceCodeInfo`: after the
/// `//` or the `/*`, up to and including the newline of a line comment, with a
/// block comment's continuation lines stripped of their leading white space and
/// one `*`.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(crate) struct Gap {
    /// The comment trailing the token BEFORE this gap.
    pub trailing: Option<String>,
    /// The comment leading the token that owns this record.
    pub leading: Option<String>,
}

/// A token and where it starts.
#[derive(Clone, Debug, PartialEq)]
pub(crate) struct Token<'a> {
    pub tok: Tok<'a>,
    pub pos: Pos,
    /// Byte offsets of the token in the source text, `start..end`.
    pub start: usize,
    pub end: usize,
    /// The comments in the gap in front of the token, when there are any. Shared
    /// so that a token cloned for a look-ahead does not copy a long comment.
    pub gap: Option<Rc<Gap>>,
}

/// The tokenizer over one file's text.
pub(crate) struct Lexer<'a> {
    src: &'a str,
    at: usize,
    line: u32,
    col: u32,
    /// Whether a token has been handed out: the first gap of a file has no token
    /// before it for a comment to trail.
    started: bool,
}

/// What a `/` at the cursor starts.
enum CommentStart {
    Line,
    /// A block comment, with the place it began.
    Block(Pos),
}

/// `protoc`'s `CommentCollector`: the comment being read, and where it goes.
struct Collector {
    buffer: String,
    has_comment: bool,
    is_line: bool,
    can_attach_to_prev: bool,
    trailing: Option<String>,
}

impl Collector {
    fn new(can_attach_to_prev: bool) -> Self {
        Self {
            buffer: String::new(),
            has_comment: false,
            is_line: false,
            can_attach_to_prev,
            trailing: None,
        }
    }

    /// Line comments on consecutive lines are one comment; a block comment
    /// before them is another.
    fn line_buffer(&mut self) -> &mut String {
        if self.has_comment && !self.is_line {
            self.flush();
        }
        self.has_comment = true;
        self.is_line = true;
        &mut self.buffer
    }

    fn block_buffer(&mut self) -> &mut String {
        self.flush();
        self.has_comment = true;
        self.is_line = false;
        &mut self.buffer
    }

    fn clear(&mut self) {
        self.buffer.clear();
        self.has_comment = false;
    }

    /// End the comment being read: it trails the token before when it still may,
    /// and is detached (dropped) otherwise.
    fn flush(&mut self) {
        if self.has_comment {
            if self.can_attach_to_prev {
                self.trailing = Some(core::mem::take(&mut self.buffer));
                self.can_attach_to_prev = false;
            }
            self.clear();
        }
    }

    fn detach_from_prev(&mut self) {
        self.can_attach_to_prev = false;
    }

    /// Whatever is still being read leads the next token.
    fn finish(self) -> Gap {
        Gap {
            trailing: self.trailing,
            leading: self.has_comment.then_some(self.buffer),
        }
    }
}

fn is_ident_start(b: u8) -> bool {
    b.is_ascii_alphabetic() || b == b'_'
}

fn is_ident_continue(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'_'
}

impl<'a> Lexer<'a> {
    pub(crate) fn new(src: &'a str) -> Self {
        let at = if src.as_bytes().starts_with(b"\xEF\xBB\xBF") {
            3
        } else {
            0
        };
        Self {
            src,
            at,
            line: 1,
            col: 1,
            started: false,
        }
    }

    fn pos(&self) -> Pos {
        Pos {
            line: self.line,
            col: self.col,
        }
    }

    fn byte(&self, ahead: usize) -> Option<u8> {
        self.src.as_bytes().get(self.at + ahead).copied()
    }

    /// Advance one byte, keeping the line and column in step.
    fn bump(&mut self) {
        if let Some(b) = self.byte(0) {
            self.at += 1;
            if b == b'\n' {
                self.line += 1;
                self.col = 1;
            } else {
                self.col += 1;
            }
        }
    }

    /// Skip whitespace and comments. An unterminated block comment is the only
    /// way this fails.
    fn skip_trivia(&mut self) -> Result<(), SyntaxError> {
        loop {
            match self.byte(0) {
                Some(b' ' | b'\t' | b'\n' | b'\r' | 0x0b | 0x0c) => self.bump(),
                _ => match self.comment_start() {
                    Some(CommentStart::Line) => self.line_comment(&mut String::new()),
                    Some(CommentStart::Block(started)) => {
                        self.block_comment(&mut String::new(), started)?;
                    }
                    None => return Ok(()),
                },
            }
        }
    }

    /// Skip the blanks that are not a line break, as `protoc` counts them.
    fn blanks(&mut self) {
        while matches!(self.byte(0), Some(b' ' | b'\t' | b'\r' | 0x0b | 0x0c)) {
            self.bump();
        }
    }

    /// Consume `//` or `/*` when the cursor is on one. A `/` that is neither is a
    /// symbol, and is left for the token that follows.
    fn comment_start(&mut self) -> Option<CommentStart> {
        if self.byte(0) != Some(b'/') {
            return None;
        }
        let started = self.pos();
        match self.byte(1) {
            Some(b'/') => {
                self.bump();
                self.bump();
                Some(CommentStart::Line)
            }
            Some(b'*') => {
                self.bump();
                self.bump();
                Some(CommentStart::Block(started))
            }
            _ => None,
        }
    }

    /// The rest of a `//` comment: the text after the slashes up to and including
    /// the line break, which is what `protoc` keeps.
    fn line_comment(&mut self, out: &mut String) {
        let from = self.at;
        while !matches!(self.byte(0), None | Some(b'\n')) {
            self.bump();
        }
        if self.byte(0) == Some(b'\n') {
            self.bump();
        }
        out.push_str(&self.src[from..self.at]);
    }

    /// The rest of a `/* */` comment, as `protoc` reads it: each line's leading
    /// white space and one `*` are not part of the text, and neither is the
    /// closing `*/`. An unterminated comment is the only way this fails.
    fn block_comment(&mut self, out: &mut String, started: Pos) -> Result<(), SyntaxError> {
        let mut from = self.at;
        loop {
            while !matches!(self.byte(0), None | Some(b'*' | b'/' | b'\n')) {
                self.bump();
            }
            match self.byte(0) {
                None => {
                    // Blamed where the file ends, as `protoc` does, with the
                    // place the comment began in the text because that is the
                    // line a person must fix.
                    return Err(SyntaxError::new(
                        self.pos(),
                        alloc::format!(
                            "end of file inside a block comment that began at line {}, column {}",
                            started.line,
                            started.col
                        ),
                    ));
                }
                Some(b'\n') => {
                    self.bump();
                    out.push_str(&self.src[from..self.at]);
                    self.blanks();
                    if self.byte(0) == Some(b'*') {
                        self.bump();
                        if self.byte(0) == Some(b'/') {
                            self.bump();
                            return Ok(());
                        }
                    }
                    from = self.at;
                }
                Some(b'*') => {
                    self.bump();
                    if self.byte(0) == Some(b'/') {
                        self.bump();
                        out.push_str(&self.src[from..self.at - 2]);
                        return Ok(());
                    }
                }
                Some(_) => self.bump(),
            }
        }
    }

    /// The gap in front of the next token: the comment that trails the token
    /// before it and the one that leads this one, by the rule [`Gap`] states.
    ///
    /// Leaves the cursor on the next token, so every caller that wants only the
    /// token goes on to read it.
    fn gap(&mut self) -> Result<Gap, SyntaxError> {
        let mut c = Collector::new(self.started);
        if self.started {
            // A comment on the line of the token before is that token's.
            self.blanks();
            match self.comment_start() {
                Some(CommentStart::Line) => {
                    self.line_comment(c.line_buffer());
                    // The lines below do not join a trailing comment.
                    c.flush();
                }
                Some(CommentStart::Block(started)) => {
                    self.block_comment(c.block_buffer(), started)?;
                    self.blanks();
                    if self.byte(0) != Some(b'\n') {
                        // The next token is on this line, so the comment belongs
                        // to neither side.
                        self.skip_trivia()?;
                        return Ok(Gap::default());
                    }
                    self.bump();
                    c.flush();
                }
                None => {
                    if self.byte(0) == Some(b'\n') {
                        self.bump();
                    } else {
                        // The next token is on the same line: no comments.
                        self.skip_trivia()?;
                        return Ok(Gap::default());
                    }
                }
            }
        }
        // Now on a line after the token before, or at the start of the file.
        loop {
            self.blanks();
            match self.comment_start() {
                Some(CommentStart::Line) => self.line_comment(c.line_buffer()),
                Some(CommentStart::Block(started)) => {
                    self.block_comment(c.block_buffer(), started)?;
                    // The rest of the line is not a blank line.
                    self.blanks();
                    if self.byte(0) == Some(b'\n') {
                        self.bump();
                    }
                }
                None => {
                    if self.byte(0) == Some(b'\n') {
                        // A blank line ends the comment and cuts it off from the
                        // token before.
                        self.bump();
                        c.flush();
                        c.detach_from_prev();
                    } else {
                        // A closing bracket or the end of the file ends a scope:
                        // a comment in front of it leads nothing.
                        if matches!(self.byte(0), None | Some(b'}' | b']' | b')')) {
                            c.flush();
                        }
                        return Ok(c.finish());
                    }
                }
            }
        }
    }

    /// The next token. Calling it again after `Tok::Eof` returns `Tok::Eof`.
    pub(crate) fn next_token(&mut self) -> Result<Token<'a>, SyntaxError> {
        let gap = self.gap()?;
        self.started = true;
        let gap = (gap != Gap::default()).then(|| Rc::new(gap));
        let pos = self.pos();
        let start = self.at;
        let tok = self.token(pos)?;
        Ok(Token {
            tok,
            pos,
            start,
            end: self.at,
            gap,
        })
    }

    /// The token under the cursor, which is past any trivia.
    fn token(&mut self, pos: Pos) -> Result<Tok<'a>, SyntaxError> {
        let Some(b) = self.byte(0) else {
            return Ok(Tok::Eof);
        };
        if is_ident_start(b) {
            let start = self.at;
            while self.byte(0).is_some_and(is_ident_continue) {
                self.bump();
            }
            return Ok(Tok::Ident(&self.src[start..self.at]));
        }
        if b.is_ascii_digit() || (b == b'.' && self.byte(1).is_some_and(|n| n.is_ascii_digit())) {
            return self.number(pos);
        }
        if b == b'"' || b == b'\'' {
            return Ok(Tok::Str(self.string(b)?));
        }
        if b.is_ascii_punctuation() {
            self.bump();
            return Ok(Tok::Sym(b as char));
        }
        // Anything else is a control byte or the first byte of a non-ASCII
        // character outside a string or comment. The character is named by its
        // code point when it is one, because "invalid character" alone sends a
        // reader hunting for a byte they cannot see.
        let reason = match self.src[self.at..].chars().next() {
            Some(c) if !c.is_ascii() => alloc::format!(
                "the character U+{:04X} is not allowed outside a string or a comment",
                c as u32
            ),
            _ => alloc::format!("the control byte 0x{b:02X} is not allowed in a .proto file"),
        };
        Err(SyntaxError::new(pos, reason))
    }

    fn number(&mut self, start: Pos) -> Result<Tok<'a>, SyntaxError> {
        let begin = self.at;
        let mut float = false;
        let value: u64;
        if self.byte(0) == Some(b'0') && matches!(self.byte(1), Some(b'x' | b'X')) {
            self.bump();
            self.bump();
            let digits = self.at;
            while self.byte(0).is_some_and(|d| d.is_ascii_hexdigit()) {
                self.bump();
            }
            if digits == self.at {
                return Err(SyntaxError::new(
                    self.pos(),
                    "\"0x\" must be followed by hexadecimal digits",
                ));
            }
            value = u64::from_str_radix(&self.src[digits..self.at], 16)
                .map_err(|_| SyntaxError::new(start, "integer out of range"))?;
        } else {
            while self.byte(0).is_some_and(|d| d.is_ascii_digit()) {
                self.bump();
            }
            // A fraction, an exponent or an `f` suffix makes it a float. The
            // dot is only a fraction when it is part of this number: `.pkg` is
            // handled before this function is reached.
            if self.byte(0) == Some(b'.') {
                float = true;
                self.bump();
                while self.byte(0).is_some_and(|d| d.is_ascii_digit()) {
                    self.bump();
                }
            }
            if matches!(self.byte(0), Some(b'e' | b'E')) {
                float = true;
                self.bump();
                if matches!(self.byte(0), Some(b'+' | b'-')) {
                    self.bump();
                }
                let exp = self.at;
                while self.byte(0).is_some_and(|d| d.is_ascii_digit()) {
                    self.bump();
                }
                if exp == self.at {
                    return Err(SyntaxError::new(
                        self.pos(),
                        "an exponent needs at least one digit",
                    ));
                }
            }
            if float && matches!(self.byte(0), Some(b'f' | b'F')) {
                self.bump();
            }
            if float {
                value = 0;
            } else {
                let text = &self.src[begin..self.at];
                if text.len() > 1 && text.starts_with('0') {
                    if text.bytes().any(|d| d == b'8' || d == b'9') {
                        return Err(SyntaxError::new(
                            start,
                            "a number starting with a zero must be octal",
                        ));
                    }
                    value = u64::from_str_radix(&text[1..], 8)
                        .map_err(|_| SyntaxError::new(start, "integer out of range"))?;
                } else {
                    value = text
                        .parse::<u64>()
                        .map_err(|_| SyntaxError::new(start, "integer out of range"))?;
                }
            }
        }
        if self.byte(0).is_some_and(is_ident_start) {
            return Err(SyntaxError::new(
                self.pos(),
                "a number must be followed by a space or a symbol, not by an identifier",
            ));
        }
        Ok(if float { Tok::Float } else { Tok::Int(value) })
    }

    /// A quoted string, escapes decoded. The opening quote is under the cursor.
    fn string(&mut self, quote: u8) -> Result<Vec<u8>, SyntaxError> {
        self.bump();
        let mut out = Vec::new();
        loop {
            let here = self.pos();
            match self.byte(0) {
                None => {
                    return Err(SyntaxError::new(
                        here,
                        "end of file inside a string literal",
                    ))
                }
                Some(b'\n') => {
                    return Err(SyntaxError::new(
                        here,
                        "a string literal cannot cross a line boundary",
                    ))
                }
                Some(b) if b == quote => {
                    self.bump();
                    return Ok(out);
                }
                Some(b'\\') => {
                    self.bump();
                    self.escape(here, &mut out)?;
                }
                Some(b) => {
                    out.push(b);
                    self.bump();
                }
            }
        }
    }

    /// One escape sequence; the backslash is already consumed. `at` is the
    /// backslash's position, which is where a bad escape is blamed.
    fn escape(&mut self, at: Pos, out: &mut Vec<u8>) -> Result<(), SyntaxError> {
        let bad = || SyntaxError::new(at, "invalid escape sequence in a string literal");
        let Some(c) = self.byte(0) else {
            return Err(SyntaxError::new(
                self.pos(),
                "end of file inside a string literal",
            ));
        };
        match c {
            b'a' => out.push(0x07),
            b'b' => out.push(0x08),
            b'f' => out.push(0x0c),
            b'n' => out.push(b'\n'),
            b'r' => out.push(b'\r'),
            b't' => out.push(b'\t'),
            b'v' => out.push(0x0b),
            b'\\' | b'?' | b'\'' | b'"' => out.push(c),
            b'0'..=b'7' => {
                // Up to three octal digits.
                let mut v: u32 = 0;
                let mut n = 0;
                while n < 3 && matches!(self.byte(0), Some(b'0'..=b'7')) {
                    v = v * 8 + u32::from(self.byte(0).unwrap_or(b'0') - b'0');
                    self.bump();
                    n += 1;
                }
                out.push((v & 0xff) as u8);
                return Ok(());
            }
            b'x' | b'X' => {
                self.bump();
                let mut v: u32 = 0;
                let mut n = 0;
                while n < 2 && self.byte(0).is_some_and(|d| d.is_ascii_hexdigit()) {
                    v = v * 16 + hex_value(self.byte(0).unwrap_or(b'0'));
                    self.bump();
                    n += 1;
                }
                if n == 0 {
                    return Err(bad());
                }
                out.push(v as u8);
                return Ok(());
            }
            b'u' => {
                self.bump();
                let hi = self.hex_digits(4).ok_or_else(bad)?;
                let code = if (0xD800..0xDC00).contains(&hi) {
                    // A high surrogate is only meaningful with the low half
                    // that follows it as another `\u` escape.
                    if self.byte(0) == Some(b'\\') && self.byte(1) == Some(b'u') {
                        self.bump();
                        self.bump();
                        let lo = self.hex_digits(4).ok_or_else(bad)?;
                        if !(0xDC00..0xE000).contains(&lo) {
                            return Err(bad());
                        }
                        0x10000 + ((hi - 0xD800) << 10) + (lo - 0xDC00)
                    } else {
                        return Err(bad());
                    }
                } else {
                    hi
                };
                push_char(out, code).ok_or_else(bad)?;
                return Ok(());
            }
            b'U' => {
                self.bump();
                let code = self.hex_digits(8).ok_or_else(bad)?;
                push_char(out, code).ok_or_else(bad)?;
                return Ok(());
            }
            _ => return Err(bad()),
        }
        self.bump();
        Ok(())
    }

    fn hex_digits(&mut self, count: usize) -> Option<u32> {
        let mut v: u32 = 0;
        for _ in 0..count {
            let d = self.byte(0).filter(|d| d.is_ascii_hexdigit())?;
            v = v.checked_mul(16)?.checked_add(hex_value(d))?;
            self.bump();
        }
        Some(v)
    }
}

fn hex_value(d: u8) -> u32 {
    match d {
        b'0'..=b'9' => u32::from(d - b'0'),
        b'a'..=b'f' => u32::from(d - b'a') + 10,
        _ => u32::from(d - b'A') + 10,
    }
}

/// Append the UTF-8 encoding of `code`, or `None` when it is not a scalar value.
fn push_char(out: &mut Vec<u8>, code: u32) -> Option<()> {
    let c = char::from_u32(code)?;
    let mut buf = [0u8; 4];
    out.extend_from_slice(c.encode_utf8(&mut buf).as_bytes());
    Some(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn all(src: &str) -> Result<Vec<Tok<'_>>, SyntaxError> {
        let mut lex = Lexer::new(src);
        let mut out = Vec::new();
        loop {
            let t = lex.next_token()?;
            if t.tok == Tok::Eof {
                return Ok(out);
            }
            out.push(t.tok);
        }
    }

    fn err(src: &str) -> SyntaxError {
        all(src).expect_err("the text must not lex")
    }

    #[test]
    fn identifiers_numbers_strings_and_symbols_are_told_apart() {
        let toks = all("message M { int32 a = 0x1F; string s = 'x\\n'; float f = 1.5e3; }")
            .expect("lexes");
        assert!(toks.contains(&Tok::Ident("message")));
        assert!(toks.contains(&Tok::Int(0x1F)));
        assert!(toks.contains(&Tok::Str(b"x\n".to_vec())));
        assert!(toks.contains(&Tok::Float));
        assert!(toks.contains(&Tok::Sym('{')));
    }

    #[test]
    fn octal_and_decimal_are_read_by_their_base() {
        assert_eq!(
            all("017 17 0").expect("lexes"),
            [Tok::Int(15), Tok::Int(17), Tok::Int(0)]
        );
    }

    #[test]
    fn a_dot_before_a_digit_is_a_float_and_before_a_letter_is_a_symbol() {
        assert_eq!(all(".5").expect("lexes"), [Tok::Float]);
        assert_eq!(
            all(".pkg").expect("lexes"),
            [Tok::Sym('.'), Tok::Ident("pkg")]
        );
    }

    #[test]
    fn comments_and_whitespace_are_skipped_and_lines_are_counted() {
        let mut lex = Lexer::new("// one\n/* two\nthree */ x");
        let t = lex.next_token().expect("lexes");
        assert_eq!(t.tok, Tok::Ident("x"));
        assert_eq!(t.pos, Pos { line: 3, col: 10 });
    }

    #[test]
    fn a_byte_order_mark_is_skipped_and_does_not_move_the_column() {
        let mut lex = Lexer::new("\u{feff}syntax");
        let t = lex.next_token().expect("lexes");
        assert_eq!(t.tok, Tok::Ident("syntax"));
        assert_eq!(t.pos, Pos { line: 1, col: 1 });
    }

    #[test]
    fn every_string_escape_decodes() {
        let toks = all(r#""\a\b\f\n\r\t\v\\\?\'\"\101\x41é\U0001F600""#).expect("lexes");
        let want: Vec<u8> = [
            0x07, 0x08, 0x0c, b'\n', b'\r', b'\t', 0x0b, b'\\', b'?', b'\'', b'"', b'A', b'A',
        ]
        .into_iter()
        .chain("\u{e9}\u{1F600}".bytes())
        .collect();
        assert_eq!(toks, [Tok::Str(want)]);
    }

    #[test]
    fn a_surrogate_pair_escape_is_one_character() {
        assert_eq!(
            all(r#""😀""#).expect("lexes"),
            [Tok::Str("\u{1F600}".as_bytes().to_vec())]
        );
        assert!(err(r#""\ud83d""#).reason.contains("invalid escape"));
    }

    #[test]
    fn lexical_errors_name_the_place_that_is_wrong() {
        let e = err("a\n  \"x\\qy\"");
        assert_eq!(e.pos, Pos { line: 2, col: 5 });
        assert!(e.reason.contains("invalid escape"));

        let e = err("\n\"abc\n\"");
        assert_eq!(e.pos, Pos { line: 2, col: 5 });
        assert!(e.reason.contains("cross a line"));

        let e = err("x \"abc");
        assert!(e.reason.contains("end of file inside a string"));

        let e = err("0x");
        assert!(e.reason.contains("hexadecimal"));

        let e = err("1abc");
        assert_eq!(e.pos, Pos { line: 1, col: 2 });
        assert!(e.reason.contains("followed by"));

        let e = err("09");
        assert!(e.reason.contains("octal"));

        let e = err("99999999999999999999");
        assert!(e.reason.contains("out of range"));

        let e = err("1e+");
        assert!(e.reason.contains("exponent"));

        let e = err("\u{e9}");
        assert!(e.reason.contains("U+00E9"));
    }

    #[test]
    fn an_unterminated_block_comment_is_blamed_where_the_file_ends() {
        let e = err("a\n/* never\nclosed\n");
        assert_eq!(e.pos, Pos { line: 4, col: 1 });
        assert!(e.reason.contains("began at line 2"));
    }

    /// The gap in front of token number `index` of `src` (the end of the file
    /// counts as a token): `(trailing, leading)`.
    fn gap_before(src: &str, index: usize) -> (Option<String>, Option<String>) {
        let mut lex = Lexer::new(src);
        for _ in 0..index {
            lex.next_token().expect("lexes");
        }
        let t = lex.next_token().expect("lexes");
        let g = t.gap.map(|g| (*g).clone()).unwrap_or_default();
        (g.trailing, g.leading)
    }

    fn s(text: &str) -> Option<String> {
        Some(String::from(text))
    }

    #[test]
    fn a_comment_on_the_line_of_the_token_before_trails_it() {
        // `//` after a token trails it, and the comment on the next lines is the
        // next token's, not a continuation of the trailing one.
        assert_eq!(
            gap_before("a // t\n// l\nb", 1),
            (s(" t\n"), s(" l\n")),
            "line comments"
        );
        assert_eq!(gap_before("a /* x */\nb", 1), (s(" x "), None), "block");
        // A block comment with a token after it on its line belongs to nobody.
        assert_eq!(gap_before("a /* x */ b", 1), (None, None));
    }

    #[test]
    fn a_blank_line_detaches_and_a_run_before_one_trails() {
        // No blank line before the run, one after it: the run trails.
        assert_eq!(
            gap_before("a\n// run\n// two\n\nb", 1),
            (s(" run\n two\n"), None)
        );
        // A blank line before it: detached from both.
        assert_eq!(gap_before("a\n\n// d\n\nb", 1), (None, None));
        // No blank line after it either: it leads the next token.
        assert_eq!(gap_before("a\n\n// l\nb", 1), (None, s(" l\n")));
    }

    #[test]
    fn a_comment_before_a_closing_bracket_leads_nothing() {
        // The end of the file, and a `}`: neither takes a leading comment, and the
        // comment goes to the token before when it still may.
        assert_eq!(gap_before("a\n// end\n", 1), (s(" end\n"), None));
        assert_eq!(gap_before("a\n// end\n}", 1), (s(" end\n"), None));
        // Detached by a blank line first: nobody has it.
        assert_eq!(gap_before("a\n\n// end\n}", 1), (None, None));
    }

    #[test]
    fn a_block_comment_is_stripped_the_way_protoc_strips_it() {
        // `/**` starts the text with the second star; each continuation line loses
        // its indent and one star; the closing `*/` is not text.
        assert_eq!(
            gap_before("/**\n * hi\n *  there\n */\nx", 0),
            (None, s("*\n hi\n  there\n"))
        );
        assert_eq!(gap_before("/* one */\nx", 0), (None, s(" one ")));
    }

    #[test]
    fn the_first_token_has_no_token_before_it_for_a_comment_to_trail() {
        let mut lex = Lexer::new("// lead\nx");
        let t = lex.next_token().expect("x");
        let gap = t.gap.expect("a gap");
        assert_eq!(
            (gap.trailing.clone(), gap.leading.clone()),
            (None, s(" lead\n"))
        );
        assert_eq!((t.start, t.end), (8, 9));
    }

    #[test]
    fn a_token_keeps_its_byte_span() {
        let mut lex = Lexer::new("ab  1.5");
        let a = lex.next_token().expect("ab");
        let f = lex.next_token().expect("float");
        assert_eq!((a.start, a.end), (0, 2));
        assert_eq!((f.tok, f.start, f.end), (Tok::Float, 4, 7));
    }

    #[test]
    fn a_token_error_is_not_raised_before_the_token_before_it_is_read() {
        // The lexer is lazy: the bad string is the SECOND token, so the first
        // call must succeed. A tokenizer that lexed the file up front would
        // fail here and blame a later line than the parser's first need.
        let mut lex = Lexer::new("ok \"unterminated");
        assert_eq!(lex.next_token().expect("first").tok, Tok::Ident("ok"));
        assert!(lex.next_token().is_err());
    }
}
