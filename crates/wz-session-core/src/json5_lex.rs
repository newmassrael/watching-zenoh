// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! R2824 — the JSON5 LEXER: the grammar of `json5`, with no allocator.
//!
//! `json5` builds a tree, which needs `alloc`. A reader on a target with no
//! heap needs the same grammar and no tree: it walks the document and copies
//! out only the few values it wants, into storage of its own. Writing that
//! reader against a second copy of the grammar would give the two readers two
//! chances to disagree about what a JSON5 document is. So the grammar lives
//! here once, and both read through it: `json5::parse` builds its tree from
//! these scans, and the no-heap readers (the MCU's config-write decoder in
//! `admin_connect`) walk with them directly.
//!
//! What is here is exactly what `json5` accepted before the split: `//` and
//! `/* */` comments, unquoted identifier member names, single- and
//! double-quoted strings with the JSON5 escapes (including `\uXXXX` surrogate
//! pairs and line continuations), numbers kept as their source text, and the
//! three keywords. Error offsets are unchanged, because the scans are the old
//! parser's code moved rather than rewritten.

/// Why a document could not be read, with the byte offset it failed at.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Json5Error {
    /// Byte offset into the input where the parse stopped.
    pub offset: usize,
    /// What was expected there.
    pub expected: &'static str,
}

impl core::fmt::Display for Json5Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "at byte {}: expected {}", self.offset, self.expected)
    }
}

/// One of the three JSON5 keywords a value may be.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Json5Keyword {
    /// `true`.
    True,
    /// `false`.
    False,
    /// `null`.
    Null,
}

/// A string or member name as it appears in the source: the bytes between the
/// quotes (or the bare identifier), not yet unescaped. The scan that produced
/// it has already checked every escape and the UTF-8, so decoding it cannot
/// fail on the text — only on the destination running out of room.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Json5Str<'a> {
    raw: &'a [u8],
    /// Offset of `raw[0]` in the document, so a decode can still name a byte.
    at: usize,
    quoted: bool,
}

impl<'a> Json5Str<'a> {
    /// The raw source bytes, escapes unresolved.
    pub fn raw(&self) -> &'a [u8] {
        self.raw
    }

    /// Whether this came from a bare identifier rather than a quoted string.
    pub fn is_identifier(&self) -> bool {
        !self.quoted
    }

    /// Whether the decoded text equals `text`, without decoding into storage.
    pub fn eq_str(&self, text: &str) -> bool {
        struct Cmp<'t> {
            rest: &'t str,
            equal: bool,
        }
        impl core::fmt::Write for Cmp<'_> {
            fn write_str(&mut self, s: &str) -> core::fmt::Result {
                match self.rest.strip_prefix(s) {
                    Some(rest) if self.equal => self.rest = rest,
                    _ => self.equal = false,
                }
                Ok(())
            }
        }
        let mut cmp = Cmp {
            rest: text,
            equal: true,
        };
        // The text was validated by the scan, so the only failure is the sink's,
        // and this sink never fails.
        let _ = self.decode_into(&mut cmp);
        cmp.equal && cmp.rest.is_empty()
    }

    /// Resolve the escapes into `out`. `Err` carries the offset of the piece
    /// the destination could not take, with `expected` naming the reason.
    ///
    /// `core::fmt::Write` rather than a bespoke trait, so `String` and
    /// `heapless::String` are both destinations, and one that runs out of
    /// room says so with `fmt::Error`.
    pub fn decode_into(&self, out: &mut dyn core::fmt::Write) -> Result<(), Json5Error> {
        if !self.quoted {
            // Identifiers are ASCII by construction.
            let text = core::str::from_utf8(self.raw).unwrap_or("");
            return out.write_str(text).map_err(|_| Json5Error {
                offset: self.at,
                expected: "room for the decoded string",
            });
        }
        let mut lex = Lexer {
            bytes: self.raw,
            pos: 0,
            base: self.at,
        };
        lex.walk_string_body(None, Some(out))
    }
}

/// A cursor over a JSON5 document.
#[derive(Debug, Clone)]
pub struct Lexer<'a> {
    bytes: &'a [u8],
    pos: usize,
    /// Added to every offset this lexer reports, so a lexer over a slice of a
    /// document (a string body being decoded) still names document offsets.
    base: usize,
}

impl<'a> Lexer<'a> {
    /// A lexer at the start of `input`.
    pub fn new(input: &'a str) -> Self {
        Self::from_bytes(input.as_bytes())
    }

    /// A lexer at the start of `bytes`, which need not be valid UTF-8 as a
    /// whole: the string scans check the UTF-8 of what they return.
    pub fn from_bytes(bytes: &'a [u8]) -> Self {
        Self {
            bytes,
            pos: 0,
            base: 0,
        }
    }

    /// The current byte offset.
    pub fn pos(&self) -> usize {
        self.base + self.pos
    }

    /// Whether the whole input has been consumed.
    pub fn at_end(&self) -> bool {
        self.pos >= self.bytes.len()
    }

    /// An error at the current offset.
    pub fn err(&self, expected: &'static str) -> Json5Error {
        Json5Error {
            offset: self.pos(),
            expected,
        }
    }

    /// The next byte, not consumed.
    pub fn peek(&self) -> Option<u8> {
        self.bytes.get(self.pos).copied()
    }

    /// Consume one byte, which the caller has just peeked.
    pub fn bump(&mut self) {
        self.pos += 1;
    }

    /// Consume `byte` or fail naming `expected`.
    pub fn expect(&mut self, byte: u8, expected: &'static str) -> Result<(), Json5Error> {
        if self.peek() == Some(byte) {
            self.pos += 1;
            Ok(())
        } else {
            Err(self.err(expected))
        }
    }

    /// Whitespace and both comment forms. An unterminated block comment is an
    /// error rather than an implicit end-of-file: it would otherwise swallow
    /// the rest of a config silently.
    pub fn skip_trivia(&mut self) -> Result<(), Json5Error> {
        loop {
            match self.peek() {
                Some(b' ' | b'\t' | b'\r' | b'\n') => self.pos += 1,
                Some(b'/') => match self.bytes.get(self.pos + 1) {
                    Some(b'/') => {
                        self.pos += 2;
                        while let Some(c) = self.peek() {
                            if c == b'\n' {
                                break;
                            }
                            self.pos += 1;
                        }
                    }
                    Some(b'*') => {
                        let start = self.pos;
                        self.pos += 2;
                        loop {
                            match self.peek() {
                                None => {
                                    self.pos = start;
                                    return Err(self.err("*/ closing a block comment"));
                                }
                                Some(b'*') if self.bytes.get(self.pos + 1) == Some(&b'/') => {
                                    self.pos += 2;
                                    break;
                                }
                                Some(_) => self.pos += 1,
                            }
                        }
                    }
                    _ => return Ok(()),
                },
                _ => return Ok(()),
            }
        }
    }

    /// Whether the next byte starts a number.
    pub fn at_number(&self) -> bool {
        matches!(self.peek(), Some(c) if c == b'-' || c == b'+' || c.is_ascii_digit() || c == b'.')
    }

    /// Whether the next byte starts a quoted string.
    pub fn at_string(&self) -> bool {
        matches!(self.peek(), Some(b'"' | b'\''))
    }

    /// A keyword. NaN / Infinity are JSON5 numbers, and a config has no
    /// business carrying either; refusing them here is deliberate.
    pub fn keyword(&mut self) -> Result<Json5Keyword, Json5Error> {
        for (word, kw) in [
            ("true", Json5Keyword::True),
            ("false", Json5Keyword::False),
            ("null", Json5Keyword::Null),
        ] {
            if self.bytes[self.pos..].starts_with(word.as_bytes()) {
                self.pos += word.len();
                return Ok(kw);
            }
        }
        Err(self.err("a value"))
    }

    /// A quoted string or a bare ECMAScript-identifier key. The identifier set
    /// is the ASCII one the reference config actually uses; a key needing more
    /// than that must be quoted, which JSON5 always allows.
    pub fn member_name(&mut self) -> Result<Json5Str<'a>, Json5Error> {
        if self.at_string() {
            return self.string();
        }
        let start = self.pos;
        while let Some(c) = self.peek() {
            if c.is_ascii_alphanumeric() || c == b'_' || c == b'$' {
                self.pos += 1;
            } else {
                break;
            }
        }
        if self.pos == start || self.bytes[start].is_ascii_digit() {
            self.pos = start;
            return Err(self.err("a member name"));
        }
        Ok(Json5Str {
            raw: &self.bytes[start..self.pos],
            at: self.base + start,
            quoted: false,
        })
    }

    /// A quoted string, checked in full (escapes and UTF-8) and returned
    /// undecoded. The lexer must be at the opening quote.
    pub fn string(&mut self) -> Result<Json5Str<'a>, Json5Error> {
        let quote = self.bytes[self.pos];
        self.pos += 1;
        let body_start = self.pos;
        self.walk_string_body(Some(quote), None)?;
        // walk_string_body stops just past the closing quote.
        Ok(Json5Str {
            raw: &self.bytes[body_start..self.pos - 1],
            at: self.base + body_start,
            quoted: true,
        })
    }

    /// The one implementation of a string body. With `quote` it scans to and
    /// past the closing quote; without it (a decode over an already-scanned
    /// body) it runs to the end of the bytes. Pieces go to `out` if given.
    fn walk_string_body(
        &mut self,
        quote: Option<u8>,
        mut out: Option<&mut dyn core::fmt::Write>,
    ) -> Result<(), Json5Error> {
        let mut emit = |lex: &Self, s: &str| -> Result<(), Json5Error> {
            match out.as_deref_mut() {
                Some(w) => w
                    .write_str(s)
                    .map_err(|_| lex.err("room for the decoded string")),
                None => Ok(()),
            }
        };
        loop {
            let Some(c) = self.peek() else {
                return match quote {
                    Some(_) => Err(self.err("a closing quote")),
                    None => Ok(()),
                };
            };
            self.pos += 1;
            match c {
                c if Some(c) == quote => return Ok(()),
                b'\\' => {
                    let Some(esc) = self.peek() else {
                        return Err(self.err("an escape after backslash"));
                    };
                    self.pos += 1;
                    let piece = match esc {
                        b'"' => "\"",
                        b'\'' => "'",
                        b'\\' => "\\",
                        b'/' => "/",
                        b'b' => "\u{8}",
                        b'f' => "\u{c}",
                        b'n' => "\n",
                        b'r' => "\r",
                        b't' => "\t",
                        b'0' => "\0",
                        // A backslash-newline is a JSON5 line continuation:
                        // it contributes nothing to the value.
                        b'\n' => "",
                        b'\r' => {
                            if self.peek() == Some(b'\n') {
                                self.pos += 1;
                            }
                            ""
                        }
                        b'u' => {
                            let ch = self.unicode_escape()?;
                            let mut buf = [0u8; 4];
                            let s = ch.encode_utf8(&mut buf);
                            emit(self, s)?;
                            continue;
                        }
                        _ => {
                            self.pos -= 1;
                            return Err(self.err("a known escape"));
                        }
                    };
                    emit(self, piece)?;
                }
                _ => {
                    // Take the whole UTF-8 sequence, not the lead byte.
                    let start = self.pos - 1;
                    while self.pos < self.bytes.len() && self.bytes[self.pos] & 0xC0 == 0x80 {
                        self.pos += 1;
                    }
                    match core::str::from_utf8(&self.bytes[start..self.pos]) {
                        Ok(s) => {
                            let at = self.pos;
                            self.pos = start;
                            emit(self, s)?;
                            self.pos = at;
                        }
                        Err(_) => {
                            self.pos = start;
                            return Err(self.err("valid UTF-8"));
                        }
                    }
                }
            }
        }
    }

    /// `\uXXXX`, including a surrogate pair — a config carrying a non-BMP
    /// character in a path is unlikely but a lone unpaired surrogate must not
    /// become a silent replacement character.
    fn unicode_escape(&mut self) -> Result<char, Json5Error> {
        let hi = self.hex4()?;
        if (0xD800..0xDC00).contains(&hi) {
            if self.peek() != Some(b'\\') || self.bytes.get(self.pos + 1) != Some(&b'u') {
                return Err(self.err("a low surrogate escape"));
            }
            self.pos += 2;
            let lo = self.hex4()?;
            if !(0xDC00..0xE000).contains(&lo) {
                return Err(self.err("a low surrogate escape"));
            }
            let cp = 0x1_0000 + ((hi - 0xD800) << 10) + (lo - 0xDC00);
            return char::from_u32(cp).ok_or_else(|| self.err("a Unicode scalar"));
        }
        char::from_u32(hi).ok_or_else(|| self.err("a Unicode scalar"))
    }

    fn hex4(&mut self) -> Result<u32, Json5Error> {
        if self.pos + 4 > self.bytes.len() {
            return Err(self.err("four hex digits"));
        }
        let mut v = 0u32;
        for i in 0..4 {
            let d = (self.bytes[self.pos + i] as char)
                .to_digit(16)
                .ok_or_else(|| self.err("four hex digits"))?;
            v = v * 16 + d;
        }
        self.pos += 4;
        Ok(v)
    }

    /// Consume a number's source text. The SHAPE is validated here (so a bare
    /// `-` or `0x` is rejected at the offset it occurs) while the VALUE is
    /// left to the consumer, which knows the target type.
    pub fn number(&mut self) -> Result<&'a str, Json5Error> {
        let start = self.pos;
        if matches!(self.peek(), Some(b'-' | b'+')) {
            self.pos += 1;
        }
        let digits_start = self.pos;
        let hex =
            self.peek() == Some(b'0') && matches!(self.bytes.get(self.pos + 1), Some(b'x' | b'X'));
        if hex {
            self.pos += 2;
            let hd = self.pos;
            while matches!(self.peek(), Some(c) if c.is_ascii_hexdigit()) {
                self.pos += 1;
            }
            if self.pos == hd {
                self.pos = start;
                return Err(self.err("hex digits after 0x"));
            }
        } else {
            while matches!(self.peek(), Some(c) if c.is_ascii_digit()) {
                self.pos += 1;
            }
            if self.peek() == Some(b'.') {
                self.pos += 1;
                while matches!(self.peek(), Some(c) if c.is_ascii_digit()) {
                    self.pos += 1;
                }
            }
            if self.pos == digits_start {
                self.pos = start;
                return Err(self.err("a number"));
            }
            if matches!(self.peek(), Some(b'e' | b'E')) {
                self.pos += 1;
                if matches!(self.peek(), Some(b'-' | b'+')) {
                    self.pos += 1;
                }
                let ed = self.pos;
                while matches!(self.peek(), Some(c) if c.is_ascii_digit()) {
                    self.pos += 1;
                }
                if self.pos == ed {
                    self.pos = start;
                    return Err(self.err("exponent digits"));
                }
            }
        }
        // Every byte consumed above is ASCII.
        Ok(core::str::from_utf8(&self.bytes[start..self.pos]).unwrap_or(""))
    }

    /// Skip one whole value of any shape, checking it as it goes. For a reader
    /// that walks a document for a few members and must still refuse a
    /// malformed one it does not care about. Nesting is bounded by
    /// `max_depth`, because this runs on targets with small stacks.
    pub fn skip_value(&mut self, max_depth: usize) -> Result<(), Json5Error> {
        match self.peek() {
            Some(b'{') => {
                if max_depth == 0 {
                    return Err(self.err("a shallower value"));
                }
                self.pos += 1;
                loop {
                    self.skip_trivia()?;
                    match self.peek() {
                        Some(b'}') => {
                            self.pos += 1;
                            return Ok(());
                        }
                        None => return Err(self.err("} closing an object")),
                        _ => {}
                    }
                    self.member_name()?;
                    self.skip_trivia()?;
                    self.expect(b':', ": after a member name")?;
                    self.skip_trivia()?;
                    self.skip_value(max_depth - 1)?;
                    self.skip_trivia()?;
                    match self.peek() {
                        Some(b',') => self.pos += 1,
                        Some(b'}') => {}
                        _ => return Err(self.err(", or } after a member")),
                    }
                }
            }
            Some(b'[') => {
                if max_depth == 0 {
                    return Err(self.err("a shallower value"));
                }
                self.pos += 1;
                loop {
                    self.skip_trivia()?;
                    match self.peek() {
                        Some(b']') => {
                            self.pos += 1;
                            return Ok(());
                        }
                        None => return Err(self.err("] closing an array")),
                        _ => {}
                    }
                    self.skip_value(max_depth - 1)?;
                    self.skip_trivia()?;
                    match self.peek() {
                        Some(b',') => self.pos += 1,
                        Some(b']') => {}
                        _ => return Err(self.err(", or ] after an element")),
                    }
                }
            }
            Some(b'"' | b'\'') => self.string().map(|_| ()),
            Some(_) if self.at_number() => self.number().map(|_| ()),
            Some(_) => self.keyword().map(|_| ()),
            None => Err(self.err("a value")),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A fixed-room sink, the shape an MCU decode writes into.
    struct Fixed<const N: usize> {
        buf: [u8; N],
        len: usize,
    }
    impl<const N: usize> core::fmt::Write for Fixed<N> {
        fn write_str(&mut self, s: &str) -> core::fmt::Result {
            let end = self.len + s.len();
            if end > N {
                return Err(core::fmt::Error);
            }
            self.buf[self.len..end].copy_from_slice(s.as_bytes());
            self.len = end;
            Ok(())
        }
    }
    impl<const N: usize> Fixed<N> {
        fn new() -> Self {
            Self {
                buf: [0; N],
                len: 0,
            }
        }
        fn as_str(&self) -> &str {
            core::str::from_utf8(&self.buf[..self.len]).unwrap()
        }
    }

    #[test]
    fn a_string_decodes_into_fixed_room_or_says_it_did_not_fit() {
        let doc = r#"'tcp/1.2.3.4:7447' "x\ty""#;
        let mut lex = Lexer::new(doc);
        let s = lex.string().unwrap();
        let mut room = Fixed::<32>::new();
        s.decode_into(&mut room).unwrap();
        assert_eq!(room.as_str(), "tcp/1.2.3.4:7447");
        assert!(s.eq_str("tcp/1.2.3.4:7447"));
        assert!(!s.eq_str("tcp/1.2.3.4:744"));

        let mut tight = Fixed::<4>::new();
        let e = s.decode_into(&mut tight).unwrap_err();
        assert_eq!(e.expected, "room for the decoded string");

        lex.skip_trivia().unwrap();
        let t = lex.string().unwrap();
        let mut room = Fixed::<8>::new();
        t.decode_into(&mut room).unwrap();
        assert_eq!(room.as_str(), "x\ty");
        assert!(lex.at_end());
    }

    #[test]
    fn skip_value_checks_what_it_skips_and_bounds_its_depth() {
        let mut lex = Lexer::new("{a: [1, 'b', {c: null}], /* x */ d: true,}");
        lex.skip_value(8).unwrap();
        assert!(lex.at_end());

        let mut bad = Lexer::new("{a: [1, 'b' {c: null}]}");
        assert_eq!(
            bad.skip_value(8).unwrap_err().expected,
            ", or ] after an element"
        );

        let mut deep = Lexer::new("[[[[1]]]]");
        assert_eq!(
            deep.skip_value(3).unwrap_err().expected,
            "a shallower value"
        );
    }
}
