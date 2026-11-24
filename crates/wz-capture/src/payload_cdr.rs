// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! A payload in CDR read by a ROS message definition: the format a
//! `cdr@<package>/msg/<Type>` rule installs, over the definitions
//! `crate::ros_msg` reads.
//!
//! # The bytes
//!
//! What a ROS 2 publisher on zenoh sends: the four-byte encapsulation header
//! of plain CDR (XCDR version 1), `00 01` for little-endian or `00 00` for
//! big-endian and two option bytes, then the message. Every primitive is
//! aligned to its own size counted from the end of the header, an 8-byte one
//! to 8. A string is a 4-byte length counting its terminating NUL, then its
//! bytes and the NUL; a sequence is a 4-byte count, then its elements; a fixed
//! array is its elements; a nested message is its fields, in place. A message
//! with no fields carries the one `uint8` rosidl gives every empty structure.
//! Up to three bytes past the message are the padding a serializer may append
//! to a 4-byte boundary, and are not read.
//!
//! # What a field becomes
//!
//! The listing starts at the message, `$`, and each field is a row under its
//! parent's path by NAME (`$.pose.position.x`); a sequence or an array is a
//! row and each element a row under it by index (`$.points.0`). A run of
//! `uint8`, `byte` or `char` is ONE row whose typed value is its bytes in
//! base64, as a protobuf `bytes` field's is: an image's pixels are one value,
//! not a row each. Every row carries the definition's name for the field, its
//! type as the definition spells it, and its typed value in the mapping a
//! schema's typed value uses (`crate::proto_decode_json`).
//!
//! # Where the definition and the bytes disagree
//!
//! A refusal names the field's path and the byte: the payload ending inside a
//! field, a string that is not NUL-terminated or not UTF-8, a string or a
//! sequence longer than its bound, a count the bytes left cannot hold, a
//! `bool` other than 0 or 1, and more bytes after the message than padding
//! accounts for. A representation other than plain CDR (a parameter list,
//! XCDR version 2) is refused at byte 0, naming it.
//!
//! # What is not read
//!
//! `wstring`: the width of its characters on the wire differs between
//! serializers, and a guess would be a confident misread. A field of that type
//! is refused by its path when the reading reaches it.

use alloc::format;
use alloc::rc::Rc;
use alloc::string::String;
use alloc::vec::Vec;

use crate::payload::formats::{
    BodySchema, PayloadField, PayloadFormat, PayloadFormatError, TypedValue,
};
use crate::proto_decode_json::{bytes_json, float32_json, float_json, integer_json, text_json};
use crate::ros_msg::{Arity, Base, FieldDef, MessageDef, Primitive, TypeSet};

/// The format token of a CDR rule, which names its type after the schema
/// mark: `cdr@<package>/msg/<Type>`.
pub const CDR_TOKEN: &str = "cdr";

/// The encoding a CDR payload is declared under.
const CDR_ENCODINGS: &[&str] = &["application/cdr"];

/// The encapsulation header's length; every alignment counts from its end.
const HEADER_LEN: usize = 4;

/// The member rosidl gives a message that declares none.
const EMPTY_MEMBER: &str = "structure_needs_at_least_one_member";

/// The `cdr` format with the type its rule names, found in the declared
/// definition files.
#[derive(Debug, Clone)]
pub struct CdrFormat {
    /// The type's full name, as the rule wrote it.
    type_name: String,
    /// The definitions, read once and shared by every rule of the map.
    set: Rc<TypeSet>,
}

impl CdrFormat {
    /// A rule's format: the type it names, checked against `set`.
    pub(crate) fn new(type_name: String, set: Rc<TypeSet>) -> Self {
        Self { type_name, set }
    }

    /// The rule's format token as it is written after `=`.
    pub fn token(&self) -> String {
        format!(
            "{CDR_TOKEN}{}{}",
            crate::e2e_rule::SCHEMA_MARK,
            self.type_name
        )
    }
}

impl PayloadFormat for CdrFormat {
    fn name(&self) -> &str {
        CDR_TOKEN
    }

    fn encodings(&self) -> Option<&[&str]> {
        Some(CDR_ENCODINGS)
    }

    fn decode(&self, payload: &[u8]) -> Result<Vec<PayloadField>, PayloadFormatError> {
        read(&self.set, &self.type_name, payload)
    }

    /// The type is the body schema, and it was read: a CDR rule installs only
    /// over a definition that defines it.
    fn body_schema(&self) -> Option<BodySchema<'_>> {
        Some(BodySchema {
            message: &self.type_name,
            read: true,
        })
    }
}

/// Read `payload` as an instance of `root`, with spans counted from the start
/// of `payload` (the encapsulation header included).
pub(crate) fn read(
    set: &TypeSet,
    root: &str,
    payload: &[u8],
) -> Result<Vec<PayloadField>, PayloadFormatError> {
    let Some(def) = set.message(root) else {
        return Err(PayloadFormatError::Malformed {
            at: 0,
            why: format!("no declared definition defines {root}"),
        });
    };
    if payload.len() < HEADER_LEN {
        return Err(PayloadFormatError::Truncated(payload.len()));
    }
    let little = match [payload[0], payload[1]] {
        [0x00, 0x00] => false,
        [0x00, 0x01] => true,
        [hi, lo] => {
            return Err(PayloadFormatError::Malformed {
                at: 0,
                why: format!(
                    "the encapsulation header names representation 0x{hi:02x}{lo:02x}, and \
                     only plain CDR (0x0000 big-endian, 0x0001 little-endian) is read"
                ),
            })
        }
    };
    let mut reader = Reader {
        bytes: payload,
        at: HEADER_LEN,
        little,
        rows: Vec::new(),
    };
    let slot = reader.reserve("$", None, String::from(root));
    reader.message(set, def, "$")?;
    reader.close(slot, format!("{} field(s)", def.fields.len()));
    let rest = payload.len().saturating_sub(reader.at);
    if rest >= 4 {
        return Err(PayloadFormatError::Malformed {
            at: reader.at,
            why: format!("{rest} byte(s) follow the end of {root}, more than padding"),
        });
    }
    Ok(reader.rows)
}

/// A walk over one payload: where it is, its byte order, and the rows so far.
struct Reader<'p> {
    bytes: &'p [u8],
    at: usize,
    little: bool,
    rows: Vec<PayloadField>,
}

impl<'p> Reader<'p> {
    /// Skip to the next multiple of `size` counted from the end of the header.
    fn align(&mut self, size: usize) {
        let off = self.at - HEADER_LEN;
        self.at += (size - off % size) % size;
    }

    /// The next `n` bytes, or a refusal naming `path` when the payload ends
    /// before them.
    fn take(&mut self, n: usize, path: &str, what: &str) -> Result<&'p [u8], PayloadFormatError> {
        let bytes = self.bytes;
        let start = self.at;
        match start.checked_add(n) {
            Some(end) if end <= bytes.len() => {
                self.at = end;
                Ok(&bytes[start..end])
            }
            _ => Err(PayloadFormatError::Malformed {
                at: start.min(bytes.len()),
                why: format!(
                    "{path}: the payload ends at byte {}, inside this {what}",
                    bytes.len()
                ),
            }),
        }
    }

    /// `raw` as a little-endian array, whichever order the payload is in.
    fn le<const N: usize>(&self, raw: &[u8]) -> [u8; N] {
        let mut out = [0u8; N];
        out.copy_from_slice(raw);
        if !self.little {
            out.reverse();
        }
        out
    }

    /// A 4-byte count or length.
    fn count(&mut self, path: &str, what: &str) -> Result<u32, PayloadFormatError> {
        self.align(4);
        let raw = self.take(4, path, what)?;
        Ok(u32::from_le_bytes(self.le(raw)))
    }

    /// A row whose span and value are known only once what it holds is read:
    /// a message, an array, a sequence.
    fn reserve(&mut self, path: &str, name: Option<&str>, ty: String) -> usize {
        self.rows.push(PayloadField {
            path: String::from(path),
            name: name.map(String::from),
            value: String::new(),
            start: self.at,
            end: self.at,
            typed: typed(ty, None),
        });
        self.rows.len() - 1
    }

    /// Close a reserved row: it spans from its first member's first byte, when
    /// it holds one, to where the reading stands.
    fn close(&mut self, slot: usize, value: String) {
        if let Some(first) = self.rows.get(slot + 1).map(|row| row.start) {
            self.rows[slot].start = first;
        }
        self.rows[slot].end = self.at;
        self.rows[slot].value = value;
    }

    fn message(
        &mut self,
        set: &TypeSet,
        def: &MessageDef,
        path: &str,
    ) -> Result<(), PayloadFormatError> {
        if def.fields.is_empty() {
            let member = FieldDef {
                name: String::from(EMPTY_MEMBER),
                base: Base::Primitive(Primitive::Uint8),
                arity: Arity::One,
            };
            return self.field(set, &member, path);
        }
        for field in &def.fields {
            self.field(set, field, path)?;
        }
        Ok(())
    }

    fn field(
        &mut self,
        set: &TypeSet,
        field: &FieldDef,
        parent: &str,
    ) -> Result<(), PayloadFormatError> {
        let path = format!("{parent}.{}", field.name);
        let spelling = field.spelling();
        match field.arity {
            Arity::One => self.value(set, &field.base, &path, Some(&field.name), spelling),
            Arity::Fixed(n) => self.elements(set, field, &path, n, spelling),
            Arity::Sequence(bound) => {
                let count = self.count(&path, "sequence count")?;
                if let Some(bound) = bound.filter(|bound| count > *bound) {
                    return Err(PayloadFormatError::Malformed {
                        at: self.at - 4,
                        why: format!(
                            "{path}: a sequence of {count} element(s) is longer than its bound \
                             {bound}"
                        ),
                    });
                }
                self.elements(set, field, &path, count, spelling)
            }
        }
    }

    /// `count` elements of `field`'s type, under one row for the array.
    fn elements(
        &mut self,
        set: &TypeSet,
        field: &FieldDef,
        path: &str,
        count: u32,
        spelling: String,
    ) -> Result<(), PayloadFormatError> {
        let count = count as usize;
        if let Base::Primitive(Primitive::Uint8 | Primitive::Byte | Primitive::Char) = field.base {
            let start = self.at;
            let raw = self.take(count, path, &spelling)?;
            self.rows.push(PayloadField {
                path: String::from(path),
                name: Some(field.name.clone()),
                value: format!("{count} byte(s)"),
                start,
                end: self.at,
                typed: typed(spelling, Some(bytes_json(raw))),
            });
            return Ok(());
        }
        // Every element takes at least one byte, so a count the bytes left
        // cannot hold is refused before a row is made for it.
        let left = self.bytes.len().saturating_sub(self.at);
        if count > left {
            return Err(PayloadFormatError::Malformed {
                at: self.at,
                why: format!("{path}: {count} element(s) cannot fit in the {left} byte(s) left"),
            });
        }
        let slot = self.reserve(path, Some(&field.name), spelling);
        let element_type = field.base.spelling();
        for index in 0..count {
            let element = format!("{path}.{index}");
            self.value(set, &field.base, &element, None, element_type.clone())?;
        }
        self.close(slot, format!("{count} element(s)"));
        Ok(())
    }

    /// One value of `base`, as a row named `name` at `path`.
    fn value(
        &mut self,
        set: &TypeSet,
        base: &Base,
        path: &str,
        name: Option<&str>,
        ty: String,
    ) -> Result<(), PayloadFormatError> {
        match base {
            Base::Primitive(p) => self.primitive(*p, path, name, ty),
            Base::String(bound) => self.string(*bound, path, name, ty),
            Base::WString(_) => Err(PayloadFormatError::Malformed {
                at: self.at,
                why: format!(
                    "{path}: a wstring is not read, because the width of its characters on \
                     the wire differs between serializers"
                ),
            }),
            Base::Message(inner) => {
                let Some(def) = set.message(inner) else {
                    return Err(PayloadFormatError::Malformed {
                        at: self.at,
                        why: format!("{path}: no declared definition defines {inner}"),
                    });
                };
                let slot = self.reserve(path, name, ty);
                self.message(set, def, path)?;
                self.close(slot, format!("{} field(s)", def.fields.len()));
                Ok(())
            }
        }
    }

    fn primitive(
        &mut self,
        p: Primitive,
        path: &str,
        name: Option<&str>,
        ty: String,
    ) -> Result<(), PayloadFormatError> {
        self.align(p.size());
        let start = self.at;
        let raw = self.take(p.size(), path, p.word())?;
        let integer = |v: i128| (format!("{v}"), integer_json(v));
        let (value, json) = match p {
            Primitive::Bool => match raw[0] {
                0 => (String::from("false"), String::from("false")),
                1 => (String::from("true"), String::from("true")),
                other => {
                    return Err(PayloadFormatError::Malformed {
                        at: start,
                        why: format!("{path}: a bool is 0 or 1, and this byte is {other}"),
                    })
                }
            },
            Primitive::Byte | Primitive::Char | Primitive::Uint8 => integer(i128::from(raw[0])),
            Primitive::Int8 => integer(i128::from(i8::from_le_bytes(self.le(raw)))),
            Primitive::Int16 => integer(i128::from(i16::from_le_bytes(self.le(raw)))),
            Primitive::Uint16 => integer(i128::from(u16::from_le_bytes(self.le(raw)))),
            Primitive::Int32 => integer(i128::from(i32::from_le_bytes(self.le(raw)))),
            Primitive::Uint32 => integer(i128::from(u32::from_le_bytes(self.le(raw)))),
            Primitive::Int64 => integer(i128::from(i64::from_le_bytes(self.le(raw)))),
            Primitive::Uint64 => integer(i128::from(u64::from_le_bytes(self.le(raw)))),
            Primitive::Float32 => {
                let v = f32::from_le_bytes(self.le(raw));
                (format!("{v}"), float32_json(v))
            }
            Primitive::Float64 => {
                let v = f64::from_le_bytes(self.le(raw));
                (format!("{v}"), float_json(v))
            }
        };
        self.rows.push(PayloadField {
            path: String::from(path),
            name: name.map(String::from),
            value,
            start,
            end: self.at,
            typed: typed(ty, Some(json)),
        });
        Ok(())
    }

    fn string(
        &mut self,
        bound: Option<u32>,
        path: &str,
        name: Option<&str>,
        ty: String,
    ) -> Result<(), PayloadFormatError> {
        let length = self.count(path, "string length")? as usize;
        let start = self.at - 4;
        let raw = self.take(length, path, "string")?;
        // A length of 0, which some serializers write for the empty string, has
        // no terminator to drop.
        let text = match raw.split_last() {
            None => raw,
            Some((&0, text)) => text,
            Some(_) => {
                return Err(PayloadFormatError::Malformed {
                    at: self.at - 1,
                    why: format!("{path}: the string is not terminated by a NUL"),
                })
            }
        };
        let text = core::str::from_utf8(text).map_err(|e| PayloadFormatError::Malformed {
            at: start + 4 + e.valid_up_to(),
            why: format!("{path}: the string is not UTF-8"),
        })?;
        if let Some(bound) = bound.filter(|bound| text.len() > *bound as usize) {
            return Err(PayloadFormatError::Malformed {
                at: start,
                why: format!(
                    "{path}: a string of {} byte(s) is longer than its bound {bound}",
                    text.len()
                ),
            });
        }
        self.rows.push(PayloadField {
            path: String::from(path),
            name: name.map(String::from),
            value: format!("{text:?}"),
            start,
            end: self.at,
            typed: typed(ty, Some(text_json(text))),
        });
        Ok(())
    }
}

/// The typed reading of a row: its type, and its value as JSON text where it
/// holds one.
fn typed(ty: String, json: Option<String>) -> Option<TypedValue> {
    Some(TypedValue {
        ty: Some(ty),
        json,
        enum_number: None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::payload::formats::FormatMap;
    use crate::ros_msg::DefinitionFile;
    use alloc::string::ToString;
    use alloc::vec;

    fn set_of(files: &[(&str, &str)]) -> TypeSet {
        let files: Vec<DefinitionFile<'_>> = files
            .iter()
            .map(|&(name, text)| DefinitionFile { name, text })
            .collect();
        TypeSet::read(&files).expect("definitions")
    }

    /// Each row as (path, name, type, typed value, start, end).
    fn rows(
        fields: &[PayloadField],
    ) -> Vec<(&str, Option<&str>, &str, Option<&str>, usize, usize)> {
        fields
            .iter()
            .map(|f| {
                let t = f.typed.as_ref().expect("every CDR row is typed");
                (
                    f.path.as_str(),
                    f.name.as_deref(),
                    t.ty.as_deref().expect("a type"),
                    t.json.as_deref(),
                    f.start,
                    f.end,
                )
            })
            .collect()
    }

    /// What `std_msgs/msg/String` "hello" is on the wire from a ROS 2
    /// publisher: the little-endian header, the length counting the NUL, the
    /// bytes, the NUL, and two bytes of padding to a 4-byte boundary.
    const HELLO: &[u8] = &[
        0, 1, 0, 0, 6, 0, 0, 0, b'h', b'e', b'l', b'l', b'o', 0, 0, 0,
    ];

    #[test]
    fn a_string_message_reads_as_one_named_typed_field() {
        let set = set_of(&[("std_msgs/msg/String.msg", "string data")]);
        let fields = read(&set, "std_msgs/msg/String", HELLO).expect("a String");
        assert_eq!(
            rows(&fields),
            vec![
                ("$", None, "std_msgs/msg/String", None, 4, 14),
                ("$.data", Some("data"), "string", Some("\"hello\""), 4, 14),
            ]
        );
        assert_eq!(fields[0].value, "1 field(s)");
        assert_eq!(fields[1].value, "\"hello\"");
    }

    /// Alignment counts from the end of the header, an 8-byte value to 8, and
    /// the big-endian reading of the same message gives the same rows.
    #[test]
    fn alignment_nesting_and_both_byte_orders_read_alike() {
        let set = set_of(&[
            (
                "demo/msg/Outer.msg",
                "uint8 a\nfloat64 b\nint16[] c\ndemo/Inner inner",
            ),
            ("demo/msg/Inner.msg", "bool f\nuint32 n"),
        ]);
        let little: &[u8] = &[
            0, 1, 0, 0, // header
            7, 0, 0, 0, 0, 0, 0, 0, // a, then padding to 8
            0, 0, 0, 0, 0, 0, 0xf8, 0x3f, // b = 1.5
            2, 0, 0, 0, // c's count
            0xfe, 0xff, 3, 0, // -2, 3
            1, 0, 0, 0, // inner.f, then padding to 4
            0x70, 0x11, 0x01, 0x00, // inner.n = 70000
        ];
        let big: &[u8] = &[
            0, 0, 0, 0, 7, 0, 0, 0, 0, 0, 0, 0, 0x3f, 0xf8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2, 0xff,
            0xfe, 0, 3, 1, 0, 0, 0, 0x00, 0x01, 0x11, 0x70,
        ];
        let expected = vec![
            ("$", None, "demo/msg/Outer", None, 4, 36),
            ("$.a", Some("a"), "uint8", Some("7"), 4, 5),
            ("$.b", Some("b"), "float64", Some("1.5"), 12, 20),
            ("$.c", Some("c"), "int16[]", None, 24, 28),
            ("$.c.0", None, "int16", Some("-2"), 24, 26),
            ("$.c.1", None, "int16", Some("3"), 26, 28),
            ("$.inner", Some("inner"), "demo/msg/Inner", None, 28, 36),
            ("$.inner.f", Some("f"), "bool", Some("true"), 28, 29),
            ("$.inner.n", Some("n"), "uint32", Some("70000"), 32, 36),
        ];
        for bytes in [little, big] {
            let fields = read(&set, "demo/msg/Outer", bytes).expect("an Outer");
            assert_eq!(rows(&fields), expected);
        }
    }

    #[test]
    fn a_run_of_octets_is_one_row_and_an_empty_message_reads_its_one_byte() {
        let set = set_of(&[
            ("demo/msg/Blob.msg", "uint8[] data\nint64 big"),
            ("demo/msg/Empty.msg", "# nothing"),
        ]);
        let blob: &[u8] = &[
            0, 1, 0, 0, 3, 0, 0, 0, 1, 2, 0xff, 0, // count, the bytes, padding to 8
            0, 0, 0, 0, 0, 0, 0x20, 0, // 2^53
        ];
        let fields = read(&set, "demo/msg/Blob", blob).expect("a Blob");
        assert_eq!(
            rows(&fields)[1..],
            [
                ("$.data", Some("data"), "uint8[]", Some("\"AQL/\""), 8, 11),
                (
                    "$.big",
                    Some("big"),
                    "int64",
                    Some("\"9007199254740992\""),
                    12,
                    20
                ),
            ]
        );
        let empty = read(&set, "demo/msg/Empty", &[0, 1, 0, 0, 0]).expect("an Empty");
        assert_eq!(
            rows(&empty)[1],
            (
                "$.structure_needs_at_least_one_member",
                Some("structure_needs_at_least_one_member"),
                "uint8",
                Some("0"),
                4,
                5
            )
        );
    }

    /// A service's response, by the name its samples carry.
    #[test]
    fn a_service_response_reads_by_its_own_type() {
        let set = set_of(&[("demo/srv/Add.srv", "int64 a\nint64 b\n---\nint64 sum")]);
        let fields = read(
            &set,
            "demo/srv/Add_Response",
            &[0, 1, 0, 0, 5, 0, 0, 0, 0, 0, 0, 0],
        )
        .expect("a response");
        assert_eq!(
            rows(&fields)[1],
            ("$.sum", Some("sum"), "int64", Some("5"), 4, 12)
        );
    }

    /// Every disagreement between the definition and the bytes is refused at
    /// the byte, naming the field.
    #[test]
    fn a_disagreement_names_the_field_and_the_byte() {
        let set = set_of(&[
            ("demo/msg/Flag.msg", "bool f\nfloat64 x"),
            ("demo/msg/Few.msg", "int32[<=2] few\nstring<=3 s"),
            ("demo/msg/Wide.msg", "wstring w"),
            ("std_msgs/msg/String.msg", "string data"),
        ]);
        let refused = |root: &str, bytes: &[u8]| match read(&set, root, bytes) {
            Err(PayloadFormatError::Malformed { at, why }) => (at, why),
            other => panic!("{root}: {other:?}"),
        };
        assert_eq!(
            refused("demo/msg/Flag", &[0, 1, 0, 0, 7]),
            (4, String::from("$.f: a bool is 0 or 1, and this byte is 7"))
        );
        assert_eq!(
            refused("demo/msg/Flag", &[0, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0]),
            (
                12,
                String::from("$.x: the payload ends at byte 14, inside this float64")
            )
        );
        assert_eq!(
            refused("demo/msg/Few", &[0, 1, 0, 0, 3, 0, 0, 0]),
            (
                4,
                String::from("$.few: a sequence of 3 element(s) is longer than its bound 2")
            )
        );
        assert_eq!(
            refused(
                "demo/msg/Few",
                &[0, 1, 0, 0, 0, 0, 0, 0, 5, 0, 0, 0, b'a', b'b', b'c', b'd', 0]
            ),
            (
                8,
                String::from("$.s: a string of 4 byte(s) is longer than its bound 3")
            )
        );
        assert_eq!(
            refused("std_msgs/msg/String", &[0, 1, 0, 0, 2, 0, 0, 0, b'a', b'b']),
            (
                9,
                String::from("$.data: the string is not terminated by a NUL")
            )
        );
        assert_eq!(
            refused("std_msgs/msg/String", &[0, 1, 0, 0, 2, 0, 0, 0, 0xff, 0]),
            (8, String::from("$.data: the string is not UTF-8"))
        );
        assert_eq!(refused("demo/msg/Wide", &[0, 1, 0, 0]).0, 4);
        let mut long = HELLO.to_vec();
        long.extend_from_slice(&[0, 0, 0, 0]);
        assert_eq!(
            refused("std_msgs/msg/String", &long),
            (
                14,
                String::from("6 byte(s) follow the end of std_msgs/msg/String, more than padding")
            )
        );
        assert_eq!(
            refused("std_msgs/msg/String", &[0, 3, 0, 0, 1, 0, 0, 0, 0]).0,
            0,
            "a parameter list is not plain CDR"
        );
        assert_eq!(
            read(&set, "std_msgs/msg/String", &[0, 1]),
            Err(PayloadFormatError::Truncated(2))
        );
    }

    /// The rule: installed over the declared definitions and read by them;
    /// refused without a type, without a definition file, and for a type no
    /// file defines; and a `.proto` file beside the definitions is still read
    /// by its own reader.
    #[test]
    fn a_cdr_rule_installs_over_its_definition_and_is_refused_without_one() {
        let text = "#@std_msgs/msg/String.msg=\"string data\"\n\
                    #@pose.proto=\"syntax = \\\"proto3\\\"; package pkg; message Pose { sint32 x = 1; }\"\n\
                    demo/**=cdr@std_msgs/msg/String\n\
                    pose/**=protobuf@pkg.Pose";
        let mut map = FormatMap::new();
        map.declare_all(text).expect("the declarations install");
        let rule = map.matching_rule("demo/a").expect("the cdr rule");
        assert_eq!(rule.format.name(), CDR_TOKEN);
        let schema = rule.format.body_schema().expect("a body schema");
        assert_eq!((schema.message, schema.read), ("std_msgs/msg/String", true));
        assert!(rule.format.reads_types());
        assert_eq!(rule.format.encodings(), Some(&["application/cdr"][..]));
        let fields = rule.format.decode(HELLO).expect("a String");
        assert_eq!(fields[1].path, "$.data");
        let pose = map.matching_rule("pose/a").expect("the protobuf rule");
        assert!(pose.format.reads_types(), "the proto file was read");
        assert!(map
            .declarations()
            .iter()
            .any(|d| d.text == "demo/**=cdr@std_msgs/msg/String"));

        for (declarations, says) in [
            ("demo/**=cdr", "cdr@<package>/msg/<Type>"),
            (
                "demo/**=cdr@std_msgs/msg/String",
                "no declared definition file",
            ),
            (
                "#@std_msgs/msg/String.msg=\"string data\"\ndemo/**=cdr@std_msgs/msg/Nope",
                "no declared definition defines std_msgs/msg/Nope",
            ),
            (
                "#@demo/msg/Bad.msg=\"float64\"\ndemo/**=cdr@demo/msg/Bad",
                "demo/msg/Bad.msg:1:",
            ),
            ("#cdr=a:u8", "already a format name"),
        ] {
            let mut map = FormatMap::new();
            let refused = map.declare_all(declarations).expect_err(declarations);
            assert!(
                refused.to_string().contains(says),
                "{declarations}: {refused}"
            );
        }
    }

    /// A `cdr` rule that applied marks the definition files it read by, and
    /// leaves a `.proto` file no rule read reported as unused.
    #[cfg(feature = "dissect")]
    #[test]
    fn a_cdr_rule_that_applies_marks_its_definitions_and_not_the_proto_files() {
        let text = "#@std_msgs/msg/String.msg=\"string data\"\n\
                    #@pose.proto=\"syntax = \\\"proto3\\\"; package pkg; message Pose { sint32 x = 1; }\"\n\
                    demo/**=cdr@std_msgs/msg/String";
        let mut map = FormatMap::new();
        map.declare_all(text).expect("the declarations install");
        let run = crate::payload_decode::Declarations::new(&map);
        assert!(run.rule_for_keyexpr("demo/a").is_some());
        let unused: Vec<String> = run.unused().into_iter().map(|d| d.text).collect();
        assert_eq!(unused.len(), 1, "{unused:?}");
        assert!(unused[0].starts_with("#@pose.proto="), "{unused:?}");
    }
}
