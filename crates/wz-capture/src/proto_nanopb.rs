// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The largest a message can be once nanopb has encoded it: the number the
//! `Message_size` macro of a nanopb-generated header holds, worked out from the
//! `.proto` text and the nanopb options written in it.
//!
//! ## What this is for
//!
//! A firmware that links nanopb sizes its encode buffer with `Message_size`, and
//! the person who writes the schema wants that number while writing it, not after
//! the generator has run. The number is nanopb's, not the protobuf language's: a
//! `string` has no size in protobuf and has one here only because a nanopb option
//! (`max_size`, `max_length`) gave it one. So this module is a model of the
//! arithmetic of `nanopb_generator.py` (`Field.encoded_size`,
//! `OneOf.encoded_size`, `Message.encoded_size`, `varint_max_size`) and of how that
//! generator merges the options that feed it, and nothing here is about the wire
//! format in general.
//!
//! ## The arithmetic
//!
//! A field is the size of its value plus the size of its tag, `varint(number << 3)`
//! bytes, and a repeated field is that times `max_count` (plus one when
//! `max_count` is 1, because a packed run of one is longer than the unpacked
//! element). The value is:
//!
//! * a scalar: its worst case, which is 10 for `int32`, `int64` and `uint64`, 5 for
//!   `uint32`, `sint32`, 10 for `sint64`, 1 for `bool`, 4 or 8 for the fixed
//!   widths, and for the integers the `int_size` option narrows (`IS_8`, `IS_16`,
//!   `IS_32`) the sizes of the narrower type (`uint32` with `IS_16` is 3);
//! * a `string`: `varint(max_size)` + `max_size` - 1, the last byte being the NUL a
//!   C string needs and the wire never carries, where `max_length` means
//!   `max_size` = `max_length` + 1; a `bytes` (and a `bytes` with `fixed_length`):
//!   `varint(max_size)` + `max_size`;
//! * an `enum`: the most bytes any of its values takes as a varint (a negative
//!   value takes 10);
//! * a message: its own size and the `varint` of that size, its length prefix.
//!
//! A `oneof` is the largest of its members, not their sum, unless the message sets
//! `no_unions`, which makes every member a field of its own. A `map<K, V>` is a
//! repeated entry message whose two fields are numbered 1 and 2; nanopb's generator
//! cannot give an entry's fields options of their own, so they have the options of
//! the FILE and no others.
//!
//! ## The options, and where they come from
//!
//! nanopb reads its options from a `.options` file, from the command line, and from
//! the `.proto` itself. Only the last is read here: `[(nanopb).max_size = 32]` on a
//! field (or the aggregate form `[(nanopb) = {max_size: 32}]`), `option
//! (nanopb_msgopt).max_count = 4;` in a message, and `option (nanopb_fileopt)...;`
//! in the file. The generator merges them outermost first, file then message then
//! field, an inner option that is SET replacing an outer one; a nested message
//! takes the file's options and NOT those of the message around it.
//!
//! ## What is not a number, and why it says so
//!
//! The answer is a number or one of a closed set of reasons ([`SizeRefusal`]), and
//! a reason is the honest answer where this model would otherwise be guessing:
//!
//! * `unbounded_field`: a `string` or `bytes` with no `max_size`, or a repeated
//!   field (a map included) with no `max_count`. nanopb gives such a field no
//!   static size, so its message has none.
//! * `recursive_message`: the message holds itself, directly or through others.
//!   nanopb breaks such a cycle by turning one message's fields into callbacks, and
//!   WHICH one depends on the order it met them, so there is no one number.
//! * `message_not_generated`: the message, or a message it holds, is one the
//!   `skip_message` option keeps nanopb from generating.
//! * `unmodelled_option`: an option that changes the size and that this module does
//!   not model (`type_override`, `label_override`), or a modelled option written
//!   with a value it cannot read.
//! * `too_large` and `too_deep`: past what a 64-bit `size_t` holds, or past the
//!   nesting this reader follows.
//!
//! ## Proof
//!
//! The arithmetic is held to numbers nanopb itself wrote: the sizes in a generated
//! header, for the sample schemas the fixtures reproduce, and a corpus run through
//! the generator (see the tests and the oracle lane).

use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::vec::Vec;

use crate::proto_parse::{FieldOption, Label, OptionValue, ScalarKind};
use crate::proto_schema::{FieldKind, Fld, Linker, MapValueKind, Msg};

/// Why a message has no number: the words of `max_encoded_size_reason`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SizeRefusal {
    UnboundedField,
    RecursiveMessage,
    MessageNotGenerated,
    UnmodelledOption,
    TooLarge,
    TooDeep,
}

impl SizeRefusal {
    /// Every refusal, in the order [`REFUSAL_WORDS`] lists them.
    pub const ALL: [Self; 6] = [
        Self::UnboundedField,
        Self::RecursiveMessage,
        Self::MessageNotGenerated,
        Self::UnmodelledOption,
        Self::TooLarge,
        Self::TooDeep,
    ];

    /// The word the document carries.
    pub fn word(self) -> &'static str {
        match self {
            Self::UnboundedField => "unbounded_field",
            Self::RecursiveMessage => "recursive_message",
            Self::MessageNotGenerated => "message_not_generated",
            Self::UnmodelledOption => "unmodelled_option",
            Self::TooLarge => "too_large",
            Self::TooDeep => "too_deep",
        }
    }
}

/// The words of `max_encoded_size_reason`, one per [`SizeRefusal`].
pub const REFUSAL_WORDS: [&str; 6] = [
    "unbounded_field",
    "recursive_message",
    "message_not_generated",
    "unmodelled_option",
    "too_large",
    "too_deep",
];

/// How deeply messages may hold messages before this reader stops following them.
/// The recursion is one frame per level and the schema is text a person handed
/// over, so it is bounded as the other readers of this text are.
const MAX_DEPTH: usize = 256;

/// The largest size a number may be: what a 64-bit `size_t` holds.
const MAX_SIZE: u128 = u64::MAX as u128;

/// The nanopb options that decide a size, merged the way the generator merges
/// them: every member is `None` until some level sets it.
///
/// The allocation (`type`) matters to a size in one way only: `FT_IGNORE` leaves
/// the field out. A static, a callback and a pointer field are all sized by the
/// same rule, because the generator sizes a field from its `max_size` and
/// `max_count` and not from how it was allocated.
#[derive(Clone, Debug, Default)]
struct Merged {
    max_size: Option<i128>,
    max_length: Option<i128>,
    max_count: Option<i128>,
    /// 0 for `IS_DEFAULT`, else the width in bits.
    int_size: Option<i128>,
    /// `type = FT_IGNORE` was set (`true`) or another `type` was (`false`).
    ignore: Option<bool>,
    skip_message: Option<bool>,
    no_unions: Option<bool>,
    discard_deprecated: Option<bool>,
    /// A size-changing option this module does not model, or a modelled one with a
    /// value it cannot read, was written.
    unmodelled: bool,
}

/// The extension that carries nanopb's options at each level.
#[derive(Clone, Copy)]
enum Level {
    File,
    Message,
    Field,
}

impl Level {
    fn extension(self) -> &'static str {
        match self {
            Self::File => "nanopb_fileopt",
            Self::Message => "nanopb_msgopt",
            Self::Field => "nanopb",
        }
    }
}

/// An option value as the merger reads it.
enum Value<'a> {
    Int(i128),
    Word(&'a str),
    Other,
}

impl Merged {
    /// Merge in the options written at `level`: the generator's `MergeFrom`, under
    /// which a member that is set replaces one set further out.
    fn merge(&mut self, options: &[FieldOption], level: Level) {
        let extension = level.extension();
        for option in options {
            let Some(rest) = strip_extension(&option.name, extension) else {
                continue;
            };
            match (rest, &option.value) {
                // The aggregate form: `(nanopb) = { max_size: 32 max_count: 4 }`.
                ("", OptionValue::Aggregate(text)) => match aggregate_entries(text) {
                    Some(entries) => {
                        for (key, value) in entries {
                            self.set(key, value);
                        }
                    }
                    None => self.unmodelled = true,
                },
                // A bare `(nanopb) = 3` is no option this module can read.
                ("", _) => self.unmodelled = true,
                (key, OptionValue::Int(n)) => self.set(key, Value::Int(*n)),
                (key, OptionValue::Ident(word)) => self.set(key, Value::Word(word)),
                (key, _) => self.set(key, Value::Other),
            }
        }
    }

    fn set(&mut self, key: &str, value: Value<'_>) {
        let boolean = |value: &Value<'_>| match value {
            Value::Word("true") => Some(true),
            Value::Word("false") => Some(false),
            _ => None,
        };
        match key {
            "max_size" | "max_length" | "max_count" => {
                let Value::Int(n) = value else {
                    self.unmodelled = true;
                    return;
                };
                match key {
                    "max_size" => self.max_size = Some(n),
                    "max_length" => self.max_length = Some(n),
                    _ => self.max_count = Some(n),
                }
            }
            "int_size" => match value {
                Value::Word("IS_DEFAULT") => self.int_size = Some(0),
                Value::Word("IS_8") => self.int_size = Some(8),
                Value::Word("IS_16") => self.int_size = Some(16),
                Value::Word("IS_32") => self.int_size = Some(32),
                Value::Word("IS_64") => self.int_size = Some(64),
                _ => self.unmodelled = true,
            },
            "type" => match value {
                Value::Word("FT_IGNORE") => self.ignore = Some(true),
                Value::Word(
                    "FT_DEFAULT" | "FT_CALLBACK" | "FT_POINTER" | "FT_STATIC" | "FT_INLINE",
                ) => self.ignore = Some(false),
                _ => self.unmodelled = true,
            },
            "skip_message" | "no_unions" | "discard_deprecated" => {
                let Some(flag) = boolean(&value) else {
                    self.unmodelled = true;
                    return;
                };
                match key {
                    "skip_message" => self.skip_message = Some(flag),
                    "no_unions" => self.no_unions = Some(flag),
                    _ => self.discard_deprecated = Some(flag),
                }
            }
            // Options that change which type the generator treats a field as.
            "type_override" | "label_override" => self.unmodelled = true,
            // `fixed_length` and `fixed_count` change the C type of a field and
            // not its encoded size. Every other option is a name, a C type or a
            // flag the size does not read.
            _ => {}
        }
    }

    fn ignored(&self) -> bool {
        self.ignore == Some(true)
    }
}

/// The part of an option name after the extension in parentheses, when the name
/// is that extension's: `(nanopb).max_size` is `max_size`, `(nanopb)` is `""`.
fn strip_extension<'n>(name: &'n str, extension: &str) -> Option<&'n str> {
    let inside = name.strip_prefix('(')?;
    let (ext, rest) = inside.split_once(')')?;
    if ext.strip_prefix('.').unwrap_or(ext) != extension {
        return None;
    }
    match rest {
        "" => Some(""),
        _ => rest.strip_prefix('.'),
    }
}

/// The `key: value` pairs of an aggregate value, or `None` for text this reader
/// does not follow (a nested message, a list). Scalars only: an integer, a word.
fn aggregate_entries(text: &str) -> Option<Vec<(&str, Value<'_>)>> {
    let bytes = text.as_bytes();
    let mut out = Vec::new();
    let mut i = 0usize;
    let separator = |b: u8| b.is_ascii_whitespace() || b == b',' || b == b';';
    while i < bytes.len() {
        if separator(bytes[i]) {
            i += 1;
            continue;
        }
        if bytes[i] == b'#' {
            while i < bytes.len() && bytes[i] != b'\n' {
                i += 1;
            }
            continue;
        }
        let key_at = i;
        while i < bytes.len()
            && (bytes[i].is_ascii_alphanumeric() || bytes[i] == b'_' || bytes[i] == b'.')
        {
            i += 1;
        }
        if i == key_at {
            return None;
        }
        let key = &text[key_at..i];
        while i < bytes.len() && bytes[i].is_ascii_whitespace() {
            i += 1;
        }
        if bytes.get(i) == Some(&b':') {
            i += 1;
        }
        while i < bytes.len() && bytes[i].is_ascii_whitespace() {
            i += 1;
        }
        let value_at = i;
        while i < bytes.len() && !separator(bytes[i]) {
            if matches!(bytes[i], b'{' | b'<' | b'[' | b'"' | b'\'') {
                return None;
            }
            i += 1;
        }
        let word = &text[value_at..i];
        if word.is_empty() {
            return None;
        }
        let value = match word.parse::<i128>() {
            Ok(n) => Value::Int(n),
            Err(_) => Value::Word(word),
        };
        out.push((key, value));
    }
    Some(out)
}

/// `varint_max_size`: how many bytes `value` takes as a varint, a negative one
/// being ten.
fn varint_size(value: u128) -> u128 {
    let mut bytes = 1u128;
    let mut rest = value >> 7;
    while rest != 0 {
        bytes += 1;
        rest >>= 7;
    }
    bytes
}

/// The worst-case encoded size of a scalar value, before its tag, with the
/// `int_size` the generator would apply.
fn scalar_size(kind: ScalarKind, int_size: i128) -> u128 {
    use ScalarKind::{
        Bool, Bytes, Double, Fixed32, Fixed64, Float, Int32, Int64, Sfixed32, Sfixed64, Sint32,
        Sint64, String as Str, Uint32, Uint64,
    };
    match kind {
        Bool => 1,
        Double | Fixed64 | Sfixed64 => 8,
        Float | Fixed32 | Sfixed32 => 4,
        // The sign extension makes a negative value ten bytes whatever the width
        // it is stored in.
        Int32 | Int64 => 10,
        Sint32 | Sint64 | Uint32 | Uint64 => match int_size {
            8 => 2,
            16 => 3,
            32 => 5,
            64 => 10,
            _ => match kind {
                Sint32 | Uint32 => 5,
                _ => 10,
            },
        },
        // Sized by their own rule, which asks for `max_size`.
        Str | Bytes => 0,
    }
}

/// What a leaf of a message is: the value a tag carries.
#[derive(Clone, Copy)]
enum Leaf {
    Scalar(ScalarKind),
    Enum(usize),
    Message(usize),
}

struct Sizer<'l, 'f, 'a> {
    linker: &'l Linker<'f, 'a>,
    memo: Vec<Option<Result<u128, SizeRefusal>>>,
    visiting: Vec<bool>,
    depth: usize,
}

impl Sizer<'_, '_, '_> {
    /// The options in force for a message: its file's, then its own.
    fn message_options(&self, msg: &Msg) -> Merged {
        let mut merged = Merged::default();
        merged.merge(&self.linker.file_options[msg.file], Level::File);
        merged.merge(&msg.options, Level::Message);
        merged
    }

    fn message(&mut self, idx: usize) -> Result<u128, SizeRefusal> {
        if let Some(done) = self.memo[idx] {
            return done;
        }
        if self.visiting[idx] {
            return Err(SizeRefusal::RecursiveMessage);
        }
        if self.depth >= MAX_DEPTH {
            return Err(SizeRefusal::TooDeep);
        }
        self.visiting[idx] = true;
        self.depth += 1;
        let answer = self.message_inner(idx);
        self.depth -= 1;
        self.visiting[idx] = false;
        // A refusal for the depth is about where the walk started, not about the
        // message, so only a verdict about the message is remembered.
        if answer != Err(SizeRefusal::TooDeep) && answer != Err(SizeRefusal::RecursiveMessage) {
            self.memo[idx] = Some(answer);
        }
        answer
    }

    fn message_inner(&mut self, idx: usize) -> Result<u128, SizeRefusal> {
        let linker = self.linker;
        let msg = &linker.msgs[idx];
        let own = self.message_options(msg);
        if own.unmodelled {
            return Err(SizeRefusal::UnmodelledOption);
        }
        if own.skip_message == Some(true) {
            return Err(SizeRefusal::MessageNotGenerated);
        }
        let no_unions = own.no_unions == Some(true);
        let mut total: u128 = 0;
        // The largest member of each oneof that has any, in the order met.
        let mut unions: BTreeMap<usize, u128> = BTreeMap::new();
        for field in &msg.fields {
            // A oneof is a union unless the message says `no_unions`, in which
            // case its members are fields like any other; and a message that
            // ignores its fields drops the union with them, whatever a member
            // says of itself.
            let member = field.oneof.filter(|_| !no_unions);
            if member.is_some() && own.ignored() {
                continue;
            }
            let mut eff = own.clone();
            eff.merge(&field.options, Level::Field);
            if eff.unmodelled {
                return Err(SizeRefusal::UnmodelledOption);
            }
            if eff.ignored() {
                continue;
            }
            if eff.discard_deprecated == Some(true) && is_deprecated(field) {
                continue;
            }
            let size = self.field(&eff, field, msg.file)?;
            match member {
                Some(which) => {
                    let largest = unions.entry(which).or_insert(0);
                    *largest = (*largest).max(size);
                }
                None => total = add(total, size)?,
            }
        }
        for size in unions.into_values() {
            total = add(total, size)?;
        }
        Ok(total)
    }

    fn field(&mut self, eff: &Merged, field: &Fld, file: usize) -> Result<u128, SizeRefusal> {
        let repeated = field.label == Label::Repeated;
        match field.kind {
            FieldKind::Scalar(kind) => self.leaf(eff, Leaf::Scalar(kind), field.number, repeated),
            FieldKind::Enum(e) => self.leaf(eff, Leaf::Enum(e), field.number, repeated),
            FieldKind::Message(m) => self.leaf(eff, Leaf::Message(m), field.number, repeated),
            FieldKind::Map { key, value } => self.map(eff, field, file, key, value),
            // A group is a message the reader refuses to describe.
            FieldKind::Group => Err(SizeRefusal::UnmodelledOption),
        }
    }

    /// A `map<K, V>`: a repeated entry message, `max_count` of them, whose two
    /// fields have the options of the file the map is written in and no others.
    fn map(
        &mut self,
        eff: &Merged,
        field: &Fld,
        file: usize,
        key: ScalarKind,
        value: MapValueKind,
    ) -> Result<u128, SizeRefusal> {
        let mut entry_options = Merged::default();
        entry_options.merge(&self.linker.file_options[file], Level::File);
        if entry_options.unmodelled {
            return Err(SizeRefusal::UnmodelledOption);
        }
        let key_size = self.leaf(&entry_options, Leaf::Scalar(key), 1, false)?;
        let value_leaf = match value {
            MapValueKind::Scalar(s) => Leaf::Scalar(s),
            MapValueKind::Enum(e) => Leaf::Enum(e),
            MapValueKind::Message(m) => Leaf::Message(m),
        };
        let value_size = self.leaf(&entry_options, value_leaf, 2, false)?;
        let entry = add(key_size, value_size)?;
        let max_count = eff.max_count.ok_or(SizeRefusal::UnboundedField)?;
        let one = add(add(entry, varint_size(entry))?, tag_size(field.number))?;
        repeat(one, max_count)
    }

    /// One tag and its value, repeated when the field is.
    fn leaf(
        &mut self,
        eff: &Merged,
        leaf: Leaf,
        number: u64,
        repeated: bool,
    ) -> Result<u128, SizeRefusal> {
        let is_string = matches!(leaf, Leaf::Scalar(ScalarKind::String));
        let is_bytes = matches!(leaf, Leaf::Scalar(ScalarKind::Bytes));
        let mut max_size = eff.max_size;
        if is_string {
            // `max_length` is the length without the NUL and overrides `max_size`.
            if let Some(length) = eff.max_length {
                max_size = Some(length + 1);
            }
        }
        if (repeated && eff.max_count.is_none()) || ((is_string || is_bytes) && max_size.is_none())
        {
            return Err(SizeRefusal::UnboundedField);
        }
        let value = match leaf {
            Leaf::Scalar(ScalarKind::String) => {
                let n = size_option(max_size)?;
                add(varint_size(n), n.saturating_sub(1))?
            }
            Leaf::Scalar(ScalarKind::Bytes) => {
                let n = size_option(max_size)?;
                add(varint_size(n), n)?
            }
            Leaf::Scalar(kind) => scalar_size(kind, eff.int_size.unwrap_or(0)),
            Leaf::Enum(e) => self.linker.enums[e]
                .values
                .iter()
                .map(|(_, n)| if *n < 0 { 10 } else { varint_size(*n as u128) })
                .max()
                .unwrap_or(1),
            Leaf::Message(m) => {
                let inner = self.message(m)?;
                add(inner, varint_size(inner))?
            }
        };
        let one = add(value, tag_size(number))?;
        if repeated {
            return repeat(one, eff.max_count.unwrap_or(0));
        }
        Ok(one)
    }
}

/// `max_size` as a size: an option the schema author set may be negative.
fn size_option(value: Option<i128>) -> Result<u128, SizeRefusal> {
    match value {
        Some(n) if n >= 0 => Ok(n as u128),
        _ => Err(SizeRefusal::UnmodelledOption),
    }
}

/// The bytes of a tag: the varint of the number shifted over the wire type.
fn tag_size(number: u64) -> u128 {
    varint_size(u128::from(number) << 3)
}

fn add(a: u128, b: u128) -> Result<u128, SizeRefusal> {
    match a.checked_add(b) {
        Some(sum) if sum <= MAX_SIZE => Ok(sum),
        _ => Err(SizeRefusal::TooLarge),
    }
}

/// `one` repeated `max_count` times: one more when there is exactly one, since a
/// packed run of a single element is longer than the element.
fn repeat(one: u128, max_count: i128) -> Result<u128, SizeRefusal> {
    let count = size_option(Some(max_count))?;
    let product = one.checked_mul(count).ok_or(SizeRefusal::TooLarge)?;
    if product > MAX_SIZE {
        return Err(SizeRefusal::TooLarge);
    }
    if count == 1 {
        return add(product, 1);
    }
    Ok(product)
}

/// Whether the field is written `[deprecated = true]`.
fn is_deprecated(field: &Fld) -> bool {
    field
        .options
        .iter()
        .any(|o| o.name == "deprecated" && o.value == OptionValue::Ident(String::from("true")))
}

/// The largest encoded size of each message in `which`, by index, in nanopb's
/// arithmetic.
pub(crate) fn encoded_sizes(
    linker: &Linker<'_, '_>,
    which: &[usize],
) -> BTreeMap<usize, Result<u64, SizeRefusal>> {
    let mut sizer = Sizer {
        linker,
        memo: alloc::vec![None; linker.msgs.len()],
        visiting: alloc::vec![false; linker.msgs.len()],
        depth: 0,
    };
    which
        .iter()
        .map(|&idx| {
            let answer = sizer.message(idx).map(|n| n as u64);
            (idx, answer)
        })
        .collect()
}
