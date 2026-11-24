// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! ROS 2 message definitions read from a declaration text: the `.msg` and
//! `.srv` files a `cdr@<package>/msg/<Type>` rule reads a payload by
//! (`crate::payload_cdr` reads the bytes).
//!
//! # Why `.msg` and not the `.idl` generated from it
//!
//! A ROS package installs the `.msg` and `.srv` files its author wrote
//! (`share/<package>/msg/<Type>.msg`), and those are what a person reading a
//! topic has at hand. The `.idl` beside them is generated from them by the
//! build and says nothing about the wire they do not, in a grammar (modules,
//! typedefs, annotations) many times larger. So a declaration carries the
//! source, read by the grammar rosidl reads it with.
//!
//! # The lines
//!
//! ```text
//! #@geometry_msgs/msg/Point.msg="float64 x\nfloat64 y\nfloat64 z"
//! demo/point/**=cdr@geometry_msgs/msg/Point
//! ```
//!
//! A file is declared as a `.proto` file is (`#@<name>="<text>"`), and its
//! NAME says what it defines: `<package>/msg/<Type>.msg` the message
//! `<package>/msg/<Type>`, and `<package>/srv/<Type>.srv` the request and the
//! response of a service, `<package>/srv/<Type>_Request` and
//! `<package>/srv/<Type>_Response`, the type names a service's samples carry,
//! with the two types rosidl derives from them: `<package>/srv/<Type>_Event`,
//! the message a service's introspection publishes, and `<package>/srv/<Type>`
//! itself, which is never on the wire and exists to be hashed
//! (`crate::ros_type_hash`).
//! A field naming another message (`geometry_msgs/Point`, or `Point` for one
//! in the file's own package) is resolved among every declared file, when a
//! rule first names a type.
//!
//! # What a line is
//!
//! `<type> <name>`, with an optional default after it that a constructor fills
//! and the wire does not carry, so it is passed over; a constant
//! (`<type> <NAME>=<value>`) is passed over for the same reason; `#` begins a
//! comment. A type is a primitive (`bool`, `byte`, `char`, `float32`,
//! `float64`, `int8` to `uint64`), `string` or `string<=N`, `wstring`, or a
//! message, followed by nothing, `[N]` (a fixed array), `[]` (a sequence) or
//! `[<=N]` (a bounded sequence). A bare `Header` is the file's own package's,
//! as rosidl for ROS 2 reads it: write `std_msgs/Header`.
//!
//! # The messages ROS fixes
//!
//! A service's event message names `service_msgs/msg/ServiceEventInfo`, which
//! names `builtin_interfaces/msg/Time`. Both are part of the hash of every
//! service, and neither is something a person declaring a service should have
//! to declare, so their definitions are carried here (`FIXED`). A declared
//! file of the same name is accepted when it defines the same fields and
//! refused when it does not: a different definition under a name ROS fixes is
//! a mistake, and reading or hashing by it would be a confident misreading.

use alloc::collections::BTreeMap;
use alloc::format;
use alloc::string::String;
use alloc::vec;
use alloc::vec::Vec;

/// The member rosidl gives a structure that declares none: one `uint8`, on
/// the wire and in the type's hash.
pub(crate) const EMPTY_MEMBER: &str = "structure_needs_at_least_one_member";

/// The message a service's event carries as its `info`.
const SERVICE_EVENT_INFO: &str = "service_msgs/msg/ServiceEventInfo";

/// The messages ROS fixes that a derived type names, by full name, with their
/// fields as their `.msg` sources declare them (`builtin_interfaces/msg/Time.msg`
/// and `service_msgs/msg/ServiceEventInfo.msg`; the constants and comments of
/// the sources are on neither the wire nor the hash, and are left out).
const FIXED: &[(&str, &str)] = &[
    ("builtin_interfaces/msg/Time", "int32 sec\nuint32 nanosec"),
    (
        SERVICE_EVENT_INFO,
        "uint8 event_type\nbuiltin_interfaces/Time stamp\nchar[16] client_gid\n\
         int64 sequence_number",
    ),
];

/// A primitive type of the ROS interface definition language.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Primitive {
    Bool,
    Byte,
    Char,
    Float32,
    Float64,
    Int8,
    Uint8,
    Int16,
    Uint16,
    Int32,
    Uint32,
    Int64,
    Uint64,
}

impl Primitive {
    /// Every primitive, in declaration order.
    const ALL: [Self; 13] = [
        Self::Bool,
        Self::Byte,
        Self::Char,
        Self::Float32,
        Self::Float64,
        Self::Int8,
        Self::Uint8,
        Self::Int16,
        Self::Uint16,
        Self::Int32,
        Self::Uint32,
        Self::Int64,
        Self::Uint64,
    ];

    /// The keyword a definition writes.
    pub(crate) fn word(self) -> &'static str {
        match self {
            Self::Bool => "bool",
            Self::Byte => "byte",
            Self::Char => "char",
            Self::Float32 => "float32",
            Self::Float64 => "float64",
            Self::Int8 => "int8",
            Self::Uint8 => "uint8",
            Self::Int16 => "int16",
            Self::Uint16 => "uint16",
            Self::Int32 => "int32",
            Self::Uint32 => "uint32",
            Self::Int64 => "int64",
            Self::Uint64 => "uint64",
        }
    }

    /// The bytes one value takes on the wire, which is also its alignment.
    pub(crate) fn size(self) -> usize {
        match self {
            Self::Bool | Self::Byte | Self::Char | Self::Int8 | Self::Uint8 => 1,
            Self::Int16 | Self::Uint16 => 2,
            Self::Float32 | Self::Int32 | Self::Uint32 => 4,
            Self::Float64 | Self::Int64 | Self::Uint64 => 8,
        }
    }

    fn named(word: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|p| p.word() == word)
    }
}

/// What a field holds, before an array is applied.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Base {
    Primitive(Primitive),
    /// `string`, with the bound `string<=N` writes.
    String(Option<u32>),
    /// `wstring`, with its bound, which counts UTF-16 code units.
    WString(Option<u32>),
    /// A message, by its full name (`<package>/msg/<Type>`).
    Message(String),
}

impl Base {
    /// The type as the definition spells it, a message by its full name.
    pub(crate) fn spelling(&self) -> String {
        match self {
            Self::Primitive(p) => String::from(p.word()),
            Self::String(None) => String::from("string"),
            Self::String(Some(bound)) => format!("string<={bound}"),
            Self::WString(None) => String::from("wstring"),
            Self::WString(Some(bound)) => format!("wstring<={bound}"),
            Self::Message(name) => name.clone(),
        }
    }
}

/// How many values a field holds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Arity {
    /// One.
    One,
    /// `[N]`: exactly N, with no count on the wire.
    Fixed(u32),
    /// `[]` or `[<=N]`: a count on the wire, then that many.
    Sequence(Option<u32>),
}

/// One field of a message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct FieldDef {
    pub(crate) name: String,
    pub(crate) base: Base,
    pub(crate) arity: Arity,
}

impl FieldDef {
    /// The field's type as the definition spells it: `float64`, `string<=8[]`,
    /// `geometry_msgs/msg/Point[3]`.
    pub(crate) fn spelling(&self) -> String {
        let base = self.base.spelling();
        match self.arity {
            Arity::One => base,
            Arity::Fixed(n) => format!("{base}[{n}]"),
            Arity::Sequence(None) => format!("{base}[]"),
            Arity::Sequence(Some(bound)) => format!("{base}[<={bound}]"),
        }
    }
}

/// One message: its fields, in wire order.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct MessageDef {
    pub(crate) fields: Vec<FieldDef>,
}

impl MessageDef {
    /// The full name of every message a field of this one names, in field
    /// order.
    pub(crate) fn nested(&self) -> impl Iterator<Item = &str> {
        self.fields.iter().filter_map(|field| match &field.base {
            Base::Message(inner) => Some(inner.as_str()),
            _ => None,
        })
    }
}

/// One declared definition file: its name and its text.
pub(crate) struct DefinitionFile<'a> {
    pub(crate) name: &'a str,
    pub(crate) text: &'a str,
}

/// Whether a declared file is a ROS definition (`.msg`, `.srv`) rather than
/// a `.proto` file: the two are read by different readers.
pub(crate) fn is_definition_file(name: &str) -> bool {
    name.ends_with(".msg") || name.ends_with(".srv")
}

/// Every message the declared definition files define, by full name.
#[derive(Debug, Default)]
pub(crate) struct TypeSet {
    /// The messages a payload may be read as: the declared ones, the ones a
    /// service derives, and the ones ROS fixes (`FIXED`).
    types: BTreeMap<String, MessageDef>,
    /// The types that are never a payload and are hashed: a service's own
    /// type, whose members name its request, its response and its event.
    interfaces: BTreeMap<String, MessageDef>,
    /// Each declared file's name and the types it defines, explicit and
    /// derived, in the order of the declarations and, within a file, in the
    /// order rosidl adds them.
    files: Vec<(String, Vec<String>)>,
}

/// Which kind of file a definition is.
#[derive(Clone, Copy)]
enum Kind {
    Msg,
    Srv,
}

impl TypeSet {
    /// Read every file together. A file that is not one, by its name or by a
    /// line, refuses the set with `<file>:<line>: <why>`.
    pub(crate) fn read(files: &[DefinitionFile<'_>]) -> Result<Self, String> {
        let mut set = Self::default();
        for file in files {
            let (package, kind, type_name) = file_parts(file.name)?;
            let lines: Vec<(usize, &str)> = file.text.lines().enumerate().collect();
            let mut defined = Vec::new();
            match kind {
                Kind::Msg => {
                    let fields = read_fields(file.name, package, &lines)?;
                    let name = format!("{package}/msg/{type_name}");
                    set.insert(file.name, &mut defined, name, fields)?;
                }
                Kind::Srv => {
                    let [request, response] = sections::<2>(
                        file.name,
                        &lines,
                        "a service is its request, a line `---`, and its response",
                    )?;
                    let request = read_fields(file.name, package, request)?;
                    let response = read_fields(file.name, package, response)?;
                    let base = format!("{package}/srv/{type_name}");
                    set.service(file.name, &mut defined, &base, request, response)?;
                }
            }
            set.files.push((String::from(file.name), defined));
        }
        set.fixed_by_ros()?;
        Ok(set)
    }

    /// A service `base`: its request and its response, the event rosidl
    /// derives from them, and the service's own type, whose members name the
    /// three (rosidl_parser's `Service`, in the order its type description
    /// adds them).
    fn service(
        &mut self,
        file: &str,
        defined: &mut Vec<String>,
        base: &str,
        request: Vec<FieldDef>,
        response: Vec<FieldDef>,
    ) -> Result<(), String> {
        let request_name = format!("{base}_Request");
        let response_name = format!("{base}_Response");
        let event_name = format!("{base}_Event");
        self.claim(file, base)?;
        defined.push(String::from(base));
        self.interfaces.insert(
            String::from(base),
            MessageDef {
                fields: vec![
                    member("request_message", &request_name, Arity::One),
                    member("response_message", &response_name, Arity::One),
                    member("event_message", &event_name, Arity::One),
                ],
            },
        );
        let event = vec![
            member("info", SERVICE_EVENT_INFO, Arity::One),
            member("request", &request_name, Arity::Sequence(Some(1))),
            member("response", &response_name, Arity::Sequence(Some(1))),
        ];
        self.insert(file, defined, request_name, request)?;
        self.insert(file, defined, response_name, response)?;
        self.insert(file, defined, event_name, event)
    }

    fn insert(
        &mut self,
        file: &str,
        defined: &mut Vec<String>,
        name: String,
        fields: Vec<FieldDef>,
    ) -> Result<(), String> {
        self.claim(file, &name)?;
        defined.push(name.clone());
        self.types.insert(name, MessageDef { fields });
        Ok(())
    }

    /// That no declared file defined `name` already.
    fn claim(&self, file: &str, name: &str) -> Result<(), String> {
        if self.types.contains_key(name) || self.interfaces.contains_key(name) {
            return Err(format!(
                "{file}: {name} is defined by another declared file too"
            ));
        }
        Ok(())
    }

    /// The messages ROS fixes (`FIXED`), each where no file declared it, and
    /// a refusal where one declared it otherwise.
    fn fixed_by_ros(&mut self) -> Result<(), String> {
        for (name, text) in FIXED {
            let package = name.split('/').next().unwrap_or_default();
            let lines: Vec<(usize, &str)> = text.lines().enumerate().collect();
            let fields = read_fields(name, package, &lines)?;
            match self.types.get(*name) {
                None => {
                    self.types
                        .insert(String::from(*name), MessageDef { fields });
                }
                Some(declared) if declared.fields == fields => {}
                Some(_) => {
                    return Err(format!(
                        "{name} is fixed by ROS as \"{}\", and a declared file defines it \
                         otherwise",
                        text.replace('\n', "; ")
                    ))
                }
            }
        }
        Ok(())
    }

    /// The message of this full name.
    pub(crate) fn message(&self, name: &str) -> Option<&MessageDef> {
        self.types.get(name)
    }

    /// The type of this full name, a message or a type that is only hashed
    /// (a service's own).
    pub(crate) fn definition(&self, name: &str) -> Option<&MessageDef> {
        self.types.get(name).or_else(|| self.interfaces.get(name))
    }

    /// The types the declared file `file` defines, explicit and derived, in
    /// the order rosidl adds them; `None` for a name no file of the set has.
    pub(crate) fn types_of_file(&self, file: &str) -> Option<&[String]> {
        self.files
            .iter()
            .find(|(name, _)| name == file)
            .map(|(_, types)| types.as_slice())
    }

    /// That `name` and every message its fields reach are defined, and that
    /// none reaches itself (a message cannot contain itself on the wire).
    pub(crate) fn check(&self, name: &str) -> Result<(), String> {
        self.check_from(name, &mut Vec::new())
    }

    fn check_from(&self, name: &str, inside: &mut Vec<String>) -> Result<(), String> {
        if inside.iter().any(|outer| outer == name) {
            return Err(format!(
                "{name} contains itself, through {}",
                inside.join(" > ")
            ));
        }
        let Some(def) = self.types.get(name) else {
            return Err(match inside.last() {
                Some(outer) => {
                    format!("{outer} names {name}, which no declared definition defines")
                }
                None => format!("no declared definition defines {name}"),
            });
        };
        inside.push(String::from(name));
        for field in &def.fields {
            if let Base::Message(inner) = &field.base {
                self.check_from(inner, inside)?;
            }
        }
        inside.pop();
        Ok(())
    }
}

/// A line without its comment, trimmed.
fn code(line: &str) -> &str {
    line.split_once('#').map_or(line, |(code, _)| code).trim()
}

/// A field of a derived type that holds the message `of`.
fn member(name: &str, of: &str, arity: Arity) -> FieldDef {
    FieldDef {
        name: String::from(name),
        base: Base::Message(String::from(of)),
        arity,
    }
}

/// The `N` parts of a file that lines `---` divide, or `shape` as the refusal
/// when the file has another number of them.
fn sections<'l, 't, const N: usize>(
    file: &str,
    lines: &'l [(usize, &'t str)],
    shape: &str,
) -> Result<[&'l [(usize, &'t str)]; N], String> {
    let mut parts = lines.split(|(_, line)| code(line) == "---");
    let mut out: [&'l [(usize, &'t str)]; N] = [&lines[..0]; N];
    for part in &mut out {
        *part = parts.next().ok_or_else(|| format!("{file}: {shape}"))?;
    }
    match parts.next() {
        None => Ok(out),
        Some(_) => Err(format!("{file}: {shape}")),
    }
}

/// The package, the kind and the type a definition file's name says it
/// defines.
fn file_parts(name: &str) -> Result<(&str, Kind, &str), String> {
    let bad = || {
        format!(
            "{name}: a definition file is named <package>/msg/<Type>.msg or \
             <package>/srv/<Type>.srv"
        )
    };
    let (stem, kind) = match (name.strip_suffix(".msg"), name.strip_suffix(".srv")) {
        (Some(stem), _) => (stem, Kind::Msg),
        (_, Some(stem)) => (stem, Kind::Srv),
        _ => return Err(bad()),
    };
    let mut parts = stem.split('/');
    let (Some(package), Some(dir), Some(type_name), None) =
        (parts.next(), parts.next(), parts.next(), parts.next())
    else {
        return Err(bad());
    };
    let dir_matches = match kind {
        Kind::Msg => dir == "msg",
        Kind::Srv => dir == "srv",
    };
    if !dir_matches || !is_identifier(package) || !is_identifier(type_name) {
        return Err(bad());
    }
    Ok((package, kind, type_name))
}

/// A name a definition may use: a letter, then letters, digits and `_`.
fn is_identifier(word: &str) -> bool {
    let mut chars = word.chars();
    chars.next().is_some_and(|c| c.is_ascii_alphabetic())
        && chars.all(|c| c.is_ascii_alphanumeric() || c == '_')
}

/// The fields `lines` declare, a message type without a package being one of
/// `package`.
fn read_fields(
    file: &str,
    package: &str,
    lines: &[(usize, &str)],
) -> Result<Vec<FieldDef>, String> {
    let mut fields: Vec<FieldDef> = Vec::new();
    for (at, line) in lines {
        let bad = |why: String| format!("{file}:{}: {why}", at + 1);
        let line = code(line);
        if line.is_empty() {
            continue;
        }
        let Some((type_word, rest)) = line.split_once(char::is_whitespace) else {
            return Err(bad(format!("`{line}` names a type and no field")));
        };
        let (base, arity) = parse_type(type_word, package).map_err(bad)?;
        let rest = rest.trim_start();
        let name = rest
            .find(|c: char| c.is_whitespace() || c == '=')
            .map_or(rest, |end| &rest[..end]);
        if rest[name.len()..].trim_start().starts_with('=') {
            continue;
        }
        if !is_identifier(name) {
            return Err(bad(format!("`{name}` is not a field name")));
        }
        if fields.iter().any(|field| field.name == name) {
            return Err(bad(format!("the field `{name}` is declared twice")));
        }
        fields.push(FieldDef {
            name: String::from(name),
            base,
            arity,
        });
    }
    Ok(fields)
}

/// One type word: its base and its array.
fn parse_type(word: &str, package: &str) -> Result<(Base, Arity), String> {
    let (base_word, arity) = match word.split_once('[') {
        None => (word, Arity::One),
        Some((base, rest)) => {
            let inner = rest
                .strip_suffix(']')
                .ok_or_else(|| format!("`{word}`: an array is written `[N]`, `[]` or `[<=N]`"))?;
            let arity = match inner.strip_prefix("<=") {
                _ if inner.is_empty() => Arity::Sequence(None),
                Some(bound) => Arity::Sequence(Some(count(word, bound)?)),
                None => Arity::Fixed(count(word, inner)?),
            };
            (base, arity)
        }
    };
    if let Some(p) = Primitive::named(base_word) {
        return Ok((Base::Primitive(p), arity));
    }
    for (keyword, make) in [
        ("string", Base::String as fn(Option<u32>) -> Base),
        ("wstring", Base::WString),
    ] {
        if base_word == keyword {
            return Ok((make(None), arity));
        }
        if let Some(bound) = base_word
            .strip_prefix(keyword)
            .and_then(|tail| tail.strip_prefix("<="))
        {
            return Ok((make(Some(count(word, bound)?)), arity));
        }
    }
    let parts: Vec<&str> = base_word.split('/').collect();
    let (owner, type_name) = match parts.as_slice() {
        [type_name] => (package, *type_name),
        [owner, type_name] | [owner, "msg", type_name] => (*owner, *type_name),
        _ => return Err(format!("`{word}` is not a type")),
    };
    if !is_identifier(owner) || !is_identifier(type_name) {
        return Err(format!("`{word}` is not a type"));
    }
    Ok((Base::Message(format!("{owner}/msg/{type_name}")), arity))
}

/// A count or a bound, written in decimal.
fn count(word: &str, digits: &str) -> Result<u32, String> {
    digits
        .parse::<u32>()
        .map_err(|_| format!("`{word}`: `{digits}` is not a count"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    fn set_of(files: &[(&str, &str)]) -> Result<TypeSet, String> {
        let files: Vec<DefinitionFile<'_>> = files
            .iter()
            .map(|&(name, text)| DefinitionFile { name, text })
            .collect();
        TypeSet::read(&files)
    }

    #[test]
    fn a_message_reads_its_fields_and_passes_over_constants_defaults_and_comments() {
        let text = "# a comment line\n\
                    int32 LIMIT=5\n\
                    string NAME = \"a#b\"\n\
                    float64 x 1.5   # a default and a comment\n\
                    geometry_msgs/Point p\n\
                    Point q\n\
                    int32[3] fixed\n\
                    string<=8[] names\n\
                    uint8[<=4] small\n\
                    \n\
                    wstring w\n";
        let set = set_of(&[("demo_msgs/msg/Sample.msg", text)]).expect("a definition");
        let sample = set.message("demo_msgs/msg/Sample").expect("defined");
        let read: Vec<(&str, String)> = sample
            .fields
            .iter()
            .map(|f| (f.name.as_str(), f.spelling()))
            .collect();
        assert_eq!(
            read,
            vec![
                ("x", String::from("float64")),
                ("p", String::from("geometry_msgs/msg/Point")),
                ("q", String::from("demo_msgs/msg/Point")),
                ("fixed", String::from("int32[3]")),
                ("names", String::from("string<=8[]")),
                ("small", String::from("uint8[<=4]")),
                ("w", String::from("wstring")),
            ]
        );
        assert_eq!(sample.fields[3].arity, Arity::Fixed(3));
        assert_eq!(sample.fields[4].base, Base::String(Some(8)));
        assert_eq!(sample.fields[5].arity, Arity::Sequence(Some(4)));
    }

    #[test]
    fn a_service_defines_its_request_and_its_response() {
        let set = set_of(&[(
            "demo_srvs/srv/Add.srv",
            "int64 a\nint64 b\n---\nint64 sum\n",
        )])
        .expect("a service");
        let names = |name: &str| -> Vec<String> {
            set.message(name)
                .expect("defined")
                .fields
                .iter()
                .map(|f| f.name.clone())
                .collect()
        };
        assert_eq!(names("demo_srvs/srv/Add_Request"), vec!["a", "b"]);
        assert_eq!(names("demo_srvs/srv/Add_Response"), vec!["sum"]);
        assert!(set.message("demo_srvs/srv/Add").is_none());
    }

    /// A service file also defines the event rosidl derives (a message, read
    /// as one) and the service's own type (hashed, never read), and the file
    /// lists the four in the order rosidl adds them. The two messages ROS
    /// fixes are defined without being declared.
    #[test]
    fn a_service_derives_its_event_and_its_own_type() {
        let set = set_of(&[("demo/srv/Add.srv", "int64 a\n---\nint64 sum")]).expect("a service");
        let spell = |def: &MessageDef| -> Vec<(String, String)> {
            def.fields
                .iter()
                .map(|f| (f.name.clone(), f.spelling()))
                .collect()
        };
        let event = set
            .message("demo/srv/Add_Event")
            .expect("the event is a message");
        assert_eq!(
            spell(event),
            vec![
                (
                    String::from("info"),
                    String::from("service_msgs/msg/ServiceEventInfo")
                ),
                (
                    String::from("request"),
                    String::from("demo/srv/Add_Request[<=1]")
                ),
                (
                    String::from("response"),
                    String::from("demo/srv/Add_Response[<=1]")
                ),
            ]
        );
        assert!(set.message("demo/srv/Add").is_none());
        let own = set
            .definition("demo/srv/Add")
            .expect("the service's own type");
        assert_eq!(
            own.nested().collect::<Vec<_>>(),
            vec![
                "demo/srv/Add_Request",
                "demo/srv/Add_Response",
                "demo/srv/Add_Event"
            ]
        );
        assert_eq!(
            set.types_of_file("demo/srv/Add.srv"),
            Some(
                &[
                    String::from("demo/srv/Add"),
                    String::from("demo/srv/Add_Request"),
                    String::from("demo/srv/Add_Response"),
                    String::from("demo/srv/Add_Event"),
                ][..]
            )
        );
        assert_eq!(set.types_of_file("demo/srv/Other.srv"), None);
        let info = set
            .message("service_msgs/msg/ServiceEventInfo")
            .expect("fixed by ROS");
        assert_eq!(
            spell(info),
            vec![
                (String::from("event_type"), String::from("uint8")),
                (
                    String::from("stamp"),
                    String::from("builtin_interfaces/msg/Time")
                ),
                (String::from("client_gid"), String::from("char[16]")),
                (String::from("sequence_number"), String::from("int64")),
            ]
        );
        assert_eq!(set.check("demo/srv/Add_Event"), Ok(()));
    }

    /// A declared file under a name ROS fixes is accepted when it defines the
    /// same fields, its constants and comments aside, and refused when it
    /// defines others; and a service file with more than one `---` is refused.
    #[test]
    fn a_name_ros_fixes_is_declared_only_as_ros_fixes_it() {
        let same = "# The time\nint32 sec # seconds\nuint32 nanosec\nint32 LIMIT=3";
        assert!(set_of(&[("builtin_interfaces/msg/Time.msg", same)]).is_ok());
        let other = set_of(&[("builtin_interfaces/msg/Time.msg", "int64 sec")])
            .expect_err("a different Time");
        assert!(
            other.starts_with("builtin_interfaces/msg/Time is fixed by ROS"),
            "{other}"
        );
        let three = set_of(&[("demo/srv/S.srv", "int32 a\n---\nint32 b\n---\nint32 c")])
            .expect_err("three sections");
        assert!(three.contains("a service is its request"), "{three}");
    }

    #[test]
    fn a_file_that_is_not_a_definition_is_refused_with_its_name_and_line() {
        for (name, text, says) in [
            (
                "Point.msg",
                "float64 x",
                "is named <package>/msg/<Type>.msg",
            ),
            (
                "demo/srv/P.msg",
                "float64 x",
                "is named <package>/msg/<Type>.msg",
            ),
            (
                "demo/msg/P.msg",
                "float64",
                "demo/msg/P.msg:1: `float64` names a type",
            ),
            (
                "demo/msg/P.msg",
                "int32 a\nint32 a",
                "demo/msg/P.msg:2: the field `a`",
            ),
            (
                "demo/msg/P.msg",
                "int32[x] a",
                "demo/msg/P.msg:1: `int32[x]`: `x` is not",
            ),
            ("demo/msg/P.msg", "int32[3 a", "an array is written"),
            ("demo/srv/S.srv", "int32 a", "a service is its request"),
        ] {
            let refused = set_of(&[(name, text)]).expect_err("not a definition");
            assert!(refused.contains(says), "{name}: {refused}");
        }
        let twice = set_of(&[("demo/msg/P.msg", "int32 a"), ("demo/msg/P.msg", "int32 b")])
            .expect_err("one type twice");
        assert!(
            twice.contains("defined by another declared file"),
            "{twice}"
        );
    }

    #[test]
    fn a_type_is_checked_for_every_message_it_reaches_and_for_containing_itself() {
        let set = set_of(&[
            ("demo/msg/Outer.msg", "demo/Inner inner\nInner[] more"),
            ("demo/msg/Inner.msg", "geometry_msgs/Point at"),
            ("demo/msg/Loop.msg", "demo/Loop again"),
        ])
        .expect("definitions");
        assert_eq!(
            set.check("demo/msg/Outer"),
            Err(String::from(
                "demo/msg/Inner names geometry_msgs/msg/Point, which no declared definition \
                 defines"
            ))
        );
        assert_eq!(
            set.check("demo/msg/Nope"),
            Err(String::from("no declared definition defines demo/msg/Nope"))
        );
        assert_eq!(
            set.check("demo/msg/Loop"),
            Err(String::from(
                "demo/msg/Loop contains itself, through demo/msg/Loop"
            ))
        );
        let whole = set_of(&[
            ("demo/msg/Inner.msg", "float64 x"),
            ("demo/msg/Outer.msg", "Inner a\nInner b"),
        ])
        .expect("definitions");
        assert_eq!(whole.check("demo/msg/Outer"), Ok(()));
    }
}
