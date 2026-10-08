// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The `.proto` door (`wz_dissect_declarations_from_proto`), judged by `protoc`
//! instead of by its own author's reading of the language.
//!
//! ## The gap
//!
//! The door's unit tests were written by the person who wrote the reader, so
//! they agree with that person's idea of protobuf: the same hands chose the
//! scoping rule, the map shape and the error lines. A reader of a language the
//! author misremembers passes every one of them. `protoc` is the language's own
//! compiler, and a `.proto` file is exactly what the people who will use this
//! door already feed it, so a disagreement with it is the failure that matters.
//!
//! ## What is compared, and against what
//!
//! Every schema of a corpus is compiled by `protoc` with `--descriptor_set_out
//! --include_imports`, and the resulting `FileDescriptorSet` is read back in the
//! text form `protoc --decode=google.protobuf.FileDescriptorSet
//! google/protobuf/descriptor.proto` prints. The ORACLE is that descriptor --
//! which messages exist, their fields, the numbers, the names, and which field
//! types are messages -- and never another decoder of the `.proto` language.
//!
//! * a schema `protoc` compiles: the declaration tree is derived from the
//!   descriptor (a depth-first walk, nested message fields addressed by dotted
//!   field numbers) for EVERY message the schema defines, nested ones and ones
//!   in imported files included, and the door must write exactly those lines in
//!   that order. A map field needs no special case: `protoc` has already
//!   expanded it into the entry message whose fields are `key` and `value`.
//! * a schema `protoc` refuses: the door must refuse too, and must blame the
//!   SAME file and line. The corpus gives every erroneous schema exactly one
//!   error, because with two the order they are reported in is `protoc`'s own
//!   business and not something the door promises to copy beyond "a syntax error
//!   before a semantic one, an imported file before its importer" (which cases
//!   below pin).
//!
//! Three kinds of case are not "agree", and each is listed rather than hidden:
//! what `protoc` compiles and the door refuses ON PURPOSE (a group, an `extend`,
//! a recursive message, a size bound), what `protoc` refuses and the door does
//! not check because it is not a validator (an enum's numbering), and the one
//! error `protoc` reports without a line (a reserved number).
//!
//! ## The comparison is itself held to a control
//!
//! A comparison that cannot fail proves nothing. The two controls below run
//! WITHOUT `protoc`: a recorded descriptor is read, the tree derived from it
//! must be the one written out by hand, and a door output with one name
//! changed, a line shifted or a refusal blamed one line off must each be
//! reported as a disagreement.
//!
//! ## Why this skips, and why the lane does not
//!
//! `protoc` is a program the build does not provide, and its well-known
//! `descriptor.proto` comes from a second package on Debian
//! (`/usr/include/google/protobuf/descriptor.proto`, in `libprotobuf-dev`). A
//! machine without either skips, loudly, and `WZ_PROTOC_REQUIRE` turns that
//! skip into a failure: Layer C1bn arms it, and the hosted job installs both
//! packages, so the flag is a statement about the machine rather than a gamble.
//! A skip prints `ok` and reads as agreement, which is the thing being kept
//! from happening.
// NO CROSS-IMPL PROOF DECLARATION HERE, for the reason the tcpdump adjudicator
// next to it gives: `protoc` is a foreign TOOL and not a zenoh implementation,
// so this file contributes nothing to the cross-implementation accounting.

use std::collections::BTreeMap;
use std::ffi::{c_char, CStr, CString};
use std::path::{Path, PathBuf};
use std::process::Command;

use wz_capi_dissect::{
    wz_dissect_declarations_diagnose, wz_dissect_declarations_from_proto, wz_dissect_string_free,
    WzDissectProtoFile, WZ_DISSECT_OK,
};

/// The key pattern every case declares under.
const KEY: &str = "demo/sensor";

// ---- the judge ---------------------------------------------------------------

/// `protoc`, or `None` with the reason it cannot judge.
fn protoc() -> Result<PathBuf, String> {
    let bin = std::env::var("WZ_PROTOC_BIN").unwrap_or_else(|_| "protoc".to_string());
    let probe = Command::new(&bin)
        .arg("--version")
        .output()
        .map_err(|e| format!("`{bin}` did not run ({e})"))?;
    if !probe.status.success() {
        return Err(format!("`{bin} --version` failed"));
    }
    Ok(PathBuf::from(bin))
}

/// What `protoc` made of one schema directory.
struct Compiled {
    ok: bool,
    stderr: String,
    /// The `FileDescriptorSet` as `protoc --decode` prints it, when it compiled.
    descriptor_text: Option<String>,
}

fn compile(protoc: &Path, dir: &Path, root: &str) -> Result<Compiled, String> {
    let out = dir.join("out.pb");
    let run = Command::new(protoc)
        .arg(format!("--proto_path={}", dir.display()))
        .arg(format!("--descriptor_set_out={}", out.display()))
        .arg("--include_imports")
        .arg(root)
        .output()
        .map_err(|e| format!("protoc did not run: {e}"))?;
    let stderr = String::from_utf8_lossy(&run.stderr).into_owned();
    if !run.status.success() {
        return Ok(Compiled {
            ok: false,
            stderr,
            descriptor_text: None,
        });
    }
    let decode = Command::new(protoc)
        .arg("--decode=google.protobuf.FileDescriptorSet")
        .arg("google/protobuf/descriptor.proto")
        .stdin(std::fs::File::open(&out).map_err(|e| format!("open the descriptor set: {e}"))?)
        .output()
        .map_err(|e| format!("protoc --decode did not run: {e}"))?;
    if !decode.status.success() {
        return Err(format!(
            "`protoc --decode` could not read google/protobuf/descriptor.proto \
             (it ships in libprotobuf-dev, as /usr/include/google/protobuf/descriptor.proto): {}",
            String::from_utf8_lossy(&decode.stderr)
        ));
    }
    Ok(Compiled {
        ok: true,
        stderr,
        descriptor_text: Some(String::from_utf8_lossy(&decode.stdout).into_owned()),
    })
}

/// Where `protoc` says a schema is wrong: the first POSITIONED error if there is
/// one (a missing import is announced twice, first without a line), else the
/// first error without a position. Warnings and the notes that follow an error
/// are not blame.
fn first_blame(stderr: &str) -> Option<(String, Option<usize>)> {
    let mut unpositioned = None;
    for line in stderr.lines() {
        let mut parts = line.splitn(4, ':');
        let (Some(file), Some(l), Some(c), Some(rest)) =
            (parts.next(), parts.next(), parts.next(), parts.next())
        else {
            // `file: message`, or noise such as `[libprotobuf WARNING ...]`.
            if let Some((file, rest)) = line.split_once(": ") {
                if file.ends_with(".proto") && !rest.starts_with("warning:") {
                    unpositioned.get_or_insert((file.to_string(), None));
                }
            }
            continue;
        };
        if let (Ok(l), Ok(_)) = (l.parse::<usize>(), c.parse::<usize>()) {
            if rest.trim_start().starts_with("warning:") {
                continue;
            }
            return Some((file.to_string(), Some(l)));
        }
    }
    unpositioned
}

// ---- reading the descriptor --------------------------------------------------

/// A node of protobuf text format: `key: value` and `key { ... }` entries, in
/// the order printed, keys repeated for repeated fields.
#[derive(Debug, Default, Clone)]
struct Node {
    entries: Vec<(String, Val)>,
}

#[derive(Debug, Clone)]
enum Val {
    Scalar(String),
    Block(Node),
}

impl Node {
    fn blocks<'a>(&'a self, key: &'a str) -> impl Iterator<Item = &'a Node> + 'a {
        self.entries.iter().filter_map(move |(k, v)| match v {
            Val::Block(n) if k == key => Some(n),
            _ => None,
        })
    }

    fn scalar(&self, key: &str) -> Option<&str> {
        self.entries.iter().find_map(|(k, v)| match v {
            Val::Scalar(s) if k == key => Some(s.as_str()),
            _ => None,
        })
    }
}

#[derive(Debug, PartialEq)]
enum Tok {
    Word(String),
    Text(String),
    Open,
    Close,
    Colon,
}

fn tokenize(text: &str) -> Result<Vec<Tok>, String> {
    let mut toks = Vec::new();
    let mut chars = text.chars().peekable();
    while let Some(&c) = chars.peek() {
        match c {
            c if c.is_whitespace() => {
                chars.next();
            }
            '{' => {
                chars.next();
                toks.push(Tok::Open);
            }
            '}' => {
                chars.next();
                toks.push(Tok::Close);
            }
            ':' => {
                chars.next();
                toks.push(Tok::Colon);
            }
            '"' => {
                chars.next();
                let mut s = String::new();
                loop {
                    match chars.next() {
                        None => return Err("a string never closes".to_string()),
                        Some('"') => break,
                        Some('\\') => s.push(chars.next().ok_or("a dangling escape")?),
                        Some(other) => s.push(other),
                    }
                }
                toks.push(Tok::Text(s));
            }
            _ => {
                let mut w = String::new();
                while let Some(&c) = chars.peek() {
                    if c.is_whitespace() || matches!(c, '{' | '}' | ':' | '"') {
                        break;
                    }
                    w.push(c);
                    chars.next();
                }
                toks.push(Tok::Word(w));
            }
        }
    }
    Ok(toks)
}

fn parse_block(toks: &[Tok], at: &mut usize, nested: bool) -> Result<Node, String> {
    let mut node = Node::default();
    loop {
        match toks.get(*at) {
            None if nested => return Err("a block never closes".to_string()),
            None => return Ok(node),
            Some(Tok::Close) => {
                if !nested {
                    return Err("an unmatched `}`".to_string());
                }
                *at += 1;
                return Ok(node);
            }
            Some(Tok::Word(key)) => {
                *at += 1;
                if toks.get(*at) == Some(&Tok::Colon) {
                    *at += 1;
                }
                match toks.get(*at) {
                    Some(Tok::Open) => {
                        *at += 1;
                        let inner = parse_block(toks, at, true)?;
                        node.entries.push((key.clone(), Val::Block(inner)));
                    }
                    Some(Tok::Word(v)) | Some(Tok::Text(v)) => {
                        *at += 1;
                        node.entries.push((key.clone(), Val::Scalar(v.clone())));
                    }
                    other => return Err(format!("`{key}` is followed by {other:?}")),
                }
            }
            Some(other) => return Err(format!("unexpected {other:?}")),
        }
    }
}

fn read_text(text: &str) -> Result<Node, String> {
    let toks = tokenize(text)?;
    parse_block(&toks, &mut 0, false)
}

/// One message of the descriptor, by fully qualified name (`.pkg.Outer.Inner`).
#[derive(Debug, Default)]
struct MsgDesc {
    fields: Vec<FieldDesc>,
    map_entry: bool,
    /// The file it was defined in.
    file: String,
}

#[derive(Debug)]
struct FieldDesc {
    name: String,
    number: u32,
    /// `Some(".pkg.Msg")` for a message or group field.
    message: Option<String>,
}

fn collect(set: &Node) -> BTreeMap<String, MsgDesc> {
    fn visit(prefix: &str, node: &Node, file: &str, out: &mut BTreeMap<String, MsgDesc>) {
        let name = node.scalar("name").unwrap_or_default();
        let full = format!("{prefix}.{name}");
        let fields = node
            .blocks("field")
            .map(|f| FieldDesc {
                name: f.scalar("name").unwrap_or_default().to_string(),
                number: f
                    .scalar("number")
                    .and_then(|n| n.parse().ok())
                    .unwrap_or_default(),
                message: matches!(f.scalar("type"), Some("TYPE_MESSAGE" | "TYPE_GROUP"))
                    .then(|| f.scalar("type_name").unwrap_or_default().to_string()),
            })
            .collect();
        let map_entry = node
            .blocks("options")
            .any(|o| o.scalar("map_entry") == Some("true"));
        out.insert(
            full.clone(),
            MsgDesc {
                fields,
                map_entry,
                file: file.to_string(),
            },
        );
        for nested in node.blocks("nested_type") {
            visit(&full, nested, file, out);
        }
    }
    let mut out = BTreeMap::new();
    for file in set.blocks("file") {
        let package = file.scalar("package").unwrap_or_default();
        let prefix = if package.is_empty() {
            String::new()
        } else {
            format!(".{package}")
        };
        let name = file.scalar("name").unwrap_or_default();
        for m in file.blocks("message_type") {
            visit(&prefix, m, name, &mut out);
        }
    }
    out
}

/// The declaration lines the descriptor implies for `root` (`.pkg.Msg`), or the
/// message that closes a cycle.
fn derive(msgs: &BTreeMap<String, MsgDesc>, root: &str) -> Result<Vec<String>, String> {
    fn walk(
        msgs: &BTreeMap<String, MsgDesc>,
        msg: &str,
        prefix: &str,
        stack: &mut Vec<String>,
        lines: &mut Vec<String>,
    ) -> Result<(), String> {
        stack.push(msg.to_string());
        let desc = msgs
            .get(msg)
            .ok_or_else(|| format!("{msg} is not described"))?;
        for f in &desc.fields {
            let path = if prefix.is_empty() {
                f.number.to_string()
            } else {
                format!("{prefix}.{}", f.number)
            };
            lines.push(format!("{KEY}:{path}={}", f.name));
            if let Some(inner) = &f.message {
                if stack.contains(inner) {
                    return Err(inner.clone());
                }
                walk(msgs, inner, &path, stack, lines)?;
            }
        }
        stack.pop();
        Ok(())
    }
    let mut lines = vec![format!("{KEY}=protobuf")];
    walk(msgs, root, "", &mut Vec::new(), &mut lines)?;
    Ok(lines)
}

// ---- the door ----------------------------------------------------------------

#[derive(Debug)]
struct Door {
    ok: bool,
    declarations: String,
    installed: usize,
    file: Option<String>,
    line: Option<usize>,
    reason: String,
}

fn json_string(doc: &str, key: &str) -> Option<String> {
    let marker = format!("\"{key}\":\"");
    let rest = doc.split_once(marker.as_str())?.1;
    let mut out = String::new();
    let mut chars = rest.chars();
    while let Some(c) = chars.next() {
        match c {
            '"' => return Some(out),
            '\\' => match chars.next()? {
                'n' => out.push('\n'),
                'r' => out.push('\r'),
                't' => out.push('\t'),
                other => out.push(other),
            },
            other => out.push(other),
        }
    }
    None
}

fn json_count(doc: &str, key: &str) -> Option<usize> {
    let marker = format!("\"{key}\":");
    doc.split_once(marker.as_str())?
        .1
        .chars()
        .take_while(char::is_ascii_digit)
        .collect::<String>()
        .parse()
        .ok()
}

fn call_door(root: &str, files: &[(String, String)]) -> Door {
    let key = CString::new(KEY).expect("no NUL");
    let root = CString::new(root).expect("no NUL");
    let names: Vec<CString> = files
        .iter()
        .map(|(n, _)| CString::new(n.as_str()).expect("no NUL"))
        .collect();
    let entries: Vec<WzDissectProtoFile> = files
        .iter()
        .zip(&names)
        .map(|((_, text), name)| WzDissectProtoFile {
            name: name.as_ptr(),
            text: text.as_ptr(),
            text_len: text.len(),
        })
        .collect();
    let mut out: *mut c_char = std::ptr::null_mut();
    // SAFETY: every pointer is to a live local; the strings are NUL-terminated
    // and the buffers are as long as the lengths say.
    let rc = unsafe {
        wz_dissect_declarations_from_proto(
            key.as_ptr(),
            root.as_ptr(),
            entries.as_ptr(),
            entries.len(),
            0,
            &mut out,
        )
    };
    assert_eq!(rc, WZ_DISSECT_OK, "the door answers every well-formed call");
    // SAFETY: OK came with a string this library owns.
    let doc = unsafe { CStr::from_ptr(out) }
        .to_str()
        .expect("utf-8")
        .to_string();
    // SAFETY: `out` came from the door and is freed once.
    unsafe { wz_dissect_string_free(out) };
    Door {
        ok: doc.contains("\"ok\":true"),
        declarations: json_string(&doc, "declarations").unwrap_or_default(),
        installed: json_count(&doc, "installed").unwrap_or_default(),
        file: json_string(&doc, "file"),
        line: json_count(&doc, "line"),
        reason: json_string(&doc, "reason").unwrap_or_default(),
    }
}

/// What the existing validation door says about declaration text: `ok` and how
/// many it installed.
fn diagnose(text: &str) -> (bool, usize) {
    let text = CString::new(text).expect("no NUL");
    let mut out: *mut c_char = std::ptr::null_mut();
    // SAFETY: as above.
    let rc = unsafe { wz_dissect_declarations_diagnose(text.as_ptr(), &mut out) };
    assert_eq!(rc, WZ_DISSECT_OK);
    // SAFETY: as above.
    let doc = unsafe { CStr::from_ptr(out) }
        .to_str()
        .expect("utf-8")
        .to_string();
    // SAFETY: as above.
    unsafe { wz_dissect_string_free(out) };
    (
        doc.contains("\"ok\":true"),
        json_count(&doc, "installed").unwrap_or_default(),
    )
}

// ---- the comparisons ---------------------------------------------------------

/// A compiled schema against the door, for one root message: `None` when they
/// agree, else what differs.
fn compare_success(msgs: &BTreeMap<String, MsgDesc>, root: &str, door: &Door) -> Option<String> {
    match derive(msgs, root) {
        Err(cycle) => {
            // A cycle has no finite tree to compare; the door must say so.
            if door.ok {
                return Some(format!(
                    "{root}: protoc's descriptor is recursive through {cycle} and the door \
                     declared it anyway:\n{}",
                    door.declarations
                ));
            }
            (!door.reason.contains("contains itself")).then(|| {
                format!(
                    "{root}: the door refused a recursive message in other words: {}",
                    door.reason
                )
            })
        }
        Ok(want) => {
            if !door.ok {
                return Some(format!("{root}: the door refused: {}", door.reason));
            }
            let got: Vec<&str> = door.declarations.lines().collect();
            if got != want {
                return Some(format!(
                    "{root}: the declarations differ.\n  protoc's descriptor implies:\n    {}\n  the door wrote:\n    {}",
                    want.join("\n    "),
                    got.join("\n    ")
                ));
            }
            let (accepted, installed) = diagnose(&door.declarations);
            if !accepted || installed != want.len() || door.installed != want.len() {
                return Some(format!(
                    "{root}: the validation door says ok={accepted} installed={installed} and the \
                     door says installed={} for {} lines",
                    door.installed,
                    want.len()
                ));
            }
            None
        }
    }
}

/// A schema `protoc` refused against the door's refusal: the same file, and the
/// same line when `protoc` names one.
fn compare_refusal(blame: &(String, Option<usize>), door: &Door) -> Option<String> {
    if door.ok {
        return Some("protoc refused it and the door declared it".to_string());
    }
    if door.file.as_deref() != Some(blame.0.as_str()) {
        return Some(format!(
            "protoc blames {} and the door blames {:?} ({})",
            blame.0, door.file, door.reason
        ));
    }
    // The door is handed a root message that does not exist, so a schema it
    // read WITHOUT objection still ends in a refusal -- "the root is not
    // defined", which names a file and no line. That refusal is the door
    // ACCEPTING the schema, and it must not pass for agreement with a protoc
    // that blamed no line either (the reserved number, the 32nd nesting level):
    // found by mutating the door's nesting bound, which this comparison let by.
    let Some(got) = door.line else {
        return Some(format!(
            "protoc refused it and the door read it without objection (its refusal names no \
             line: {})",
            door.reason
        ));
    };
    match blame.1 {
        Some(want) if want != got => Some(format!(
            "protoc blames line {want} of {} and the door blames line {got}: {}",
            blame.0, door.reason
        )),
        // The same line, or protoc gives no line and the door's own is all there
        // is to report.
        _ => None,
    }
}

// ---- the corpus --------------------------------------------------------------

enum Expect {
    /// `protoc` compiles it and the door declares the same tree from every root.
    Agree,
    /// `protoc` refuses it and the door blames the same file and line.
    BothRefuse,
    /// `protoc` compiles it and the door refuses, on purpose, for this reason.
    DoorRefuses(&'static str, &'static str),
    /// `protoc` refuses it and the door does not check it (it is not a
    /// validator); the door declares from this root.
    DoorAccepts(&'static str),
}

struct Case {
    name: String,
    files: Vec<(String, String)>,
    expect: Expect,
}

fn case(name: &str, expect: Expect, files: &[(&str, &str)]) -> Case {
    Case {
        name: name.to_string(),
        files: files
            .iter()
            .map(|(n, t)| (n.to_string(), t.to_string()))
            .collect(),
        expect,
    }
}

fn one(name: &str, expect: Expect, text: &str) -> Case {
    case(name, expect, &[("a.proto", text)])
}

/// A schema of `links` messages, each holding the next.
fn chain(links: usize) -> String {
    let mut s = String::from("syntax = \"proto3\";\n");
    for i in 0..links {
        s.push_str(&format!("message M{i} {{ M{} next = 1; }}\n", i + 1));
    }
    s.push_str(&format!("message M{links} {{ int32 leaf = 1; }}\n"));
    s
}

/// A schema of `levels` messages written inside one another, each with a field.
fn nested(levels: usize) -> String {
    let mut s = String::from("syntax = \"proto3\";\n");
    for i in 0..levels {
        s.push_str(&format!("message M{i} {{\n  int32 f{i} = 1;\n"));
    }
    for _ in 0..levels {
        s.push_str("}\n");
    }
    s
}

fn corpus() -> Vec<Case> {
    use Expect::*;
    let mut cases = vec![
        // ---- schemas protoc compiles and the door must declare identically ----
        one(
            "every scalar type, proto3",
            Agree,
            r#"syntax = "proto3";
               message Scalars {
                 double a = 1; float b = 2; int32 c = 3; int64 d = 4;
                 uint32 e = 5; uint64 f = 6; sint32 g = 7; sint64 h = 8;
                 fixed32 i = 9; fixed64 j = 10; sfixed32 k = 11; sfixed64 l = 12;
                 bool m = 13; string n = 14; bytes o = 15;
               }"#,
        ),
        one(
            "proto2 labels, defaults and extension ranges",
            Agree,
            r#"syntax = "proto2";
               message Old {
                 required int32 id = 1;
                 optional string label = 2 [default = "a;b}c"];
                 repeated int32 samples = 3 [packed = true];
                 optional int32 offset = 4 [default = -5];
                 optional Inner inner = 5;
                 optional float ratio = 6 [default = 1.5e3];
                 message Inner { optional bool flag = 1 [default = true]; }
                 extensions 100 to 199;
                 extensions 1000 to max;
               }"#,
        ),
        one(
            "no syntax statement reads as proto2",
            Agree,
            "message Old { optional int32 a = 1; repeated string b = 2; }",
        ),
        one(
            "three levels of nesting and relative names",
            Agree,
            r#"syntax = "proto3";
               package deep.er;
               message Outer {
                 int32 id = 1;
                 Middle middle = 2;
                 message Middle {
                   string tag = 1;
                   Inner inner = 2;
                   Outer.Middle.Inner direct = 3;
                   message Inner { bool ok = 7; repeated Leaf leaves = 8; }
                 }
                 message Leaf { int32 v = 1; }
               }"#,
        ),
        one(
            "the innermost scope that has the first name wins",
            Agree,
            r#"syntax = "proto3";
               package p;
               message Inner { int32 shallow = 1; }
               message Holder {
                 message Inner { int32 deep = 1; string name = 2; }
                 Inner nested = 1;
                 .p.Inner top = 2;
                 p.Inner also_top = 3;
               }"#,
        ),
        one(
            "a dotted name descends from the first part it finds",
            Agree,
            r#"syntax = "proto3";
               package a.b;
               message X { int32 x = 1; }
               message Y {
                 message Z { b.X viaPackage = 1; a.b.X viaFull = 2; X plain = 3; }
                 Z z = 1;
               }"#,
        ),
        one(
            "a name that is not a type is stepped over",
            Agree,
            r#"syntax = "proto3";
               message Outer {
                 message T { int32 x = 1; }
                 message Inner {
                   int32 T = 1;
                   T other = 2;
                   enum E { Z = 0; }
                 }
                 message Second {
                   enum E { T = 0; }
                   T viaOuter = 1;
                 }
               }"#,
        ),
        one(
            "fields declared out of numeric order",
            Agree,
            r#"syntax = "proto3";
               message Order {
                 int32 seven = 7;
                 Inner two = 2;
                 int32 hundred = 100;
                 int32 one = 1;
                 message Inner { int32 z = 9; int32 a = 3; }
               }"#,
        ),
        one(
            "oneofs with message and scalar members",
            Agree,
            r#"syntax = "proto3";
               message Pick {
                 int32 before = 1;
                 oneof which { string s = 2; Choice c = 3; int64 i = 4; }
                 int32 after = 5;
                 oneof other { bool yes = 6; bool no = 7; }
                 message Choice { string label = 1; }
               }"#,
        ),
        one(
            "maps of every flavour",
            Agree,
            r#"syntax = "proto3";
               message Maps {
                 map<string, int32> by_name = 1;
                 map<int32, Entry> by_id = 2;
                 map<bool, string> flags = 3;
                 map<fixed64, Color> colors = 4;
                 map<sint64, Entry> more = 5;
                 Wrap wrap = 6;
                 message Entry { string label = 1; Deeper deeper = 2; }
                 message Deeper { map<string, Entry2> inner = 1; }
                 message Entry2 { int32 n = 1; }
                 message Wrap { map<uint32, string> nested_map = 9; }
                 enum Color { RED = 0; GREEN = 1; }
               }"#,
        ),
        one(
            "enums everywhere, aliases and negative values",
            Agree,
            r#"syntax = "proto2";
               enum Top { option allow_alias = true; A = 0; B = 0; C = -1; }
               message M {
                 optional Top top = 1;
                 optional Inner inner = 2;
                 repeated Local local = 3;
                 enum Local { X = 1; Y = 2 [deprecated = true]; reserved 5 to 9; }
                 message Inner { optional Top t = 1; }
               }"#,
        ),
        one(
            "reserved ranges and names",
            Agree,
            r#"syntax = "proto3";
               message R {
                 reserved 2, 15, 9 to 11, 40 to max;
                 reserved "foo", "bar";
                 int32 a = 1;
                 int32 b = 3;
                 int32 c = 12;
               }"#,
        ),
        one(
            "comments, options, services and strange spacing",
            Agree,
            "// leading\n/* block */ syntax /* between */ = \"proto3\" ; // trailing\n\
             option java_package = \"com.example\";\n\
             option optimize_for = SPEED;\n\
             // message Ghost { int32 g = 1; }\n\
             service Svc { rpc Do(Req) returns (Req); rpc Stream(stream Req) returns (stream Req) { option deprecated = true; } }\n\
             message Req {\n\
               // int32 hidden = 9;\n\
               int32 shown = 1 [deprecated = true, json_name = \"s;h}own\"]; /* int32 also = 8; */\n\
               string tricky = 2 [json_name = 'single \\\" quoted'];\n\
             }\n",
        ),
        one(
            "keywords as field names",
            Agree,
            r#"syntax = "proto3";
               message Words {
                 int32 message = 1; int32 enum = 2; int32 option = 3; int32 oneof = 4;
                 int32 package = 5; int32 import = 6; int32 syntax = 7; int32 reserved = 8;
                 int32 extensions = 9; int32 to = 10; int32 max = 11; int32 map = 12;
                 int32 optional = 13; int32 repeated = 14; int32 service = 15; int32 rpc = 16;
               }"#,
        ),
        one(
            "field numbers at the edges, spelled three ways",
            Agree,
            r#"syntax = "proto3";
               message Edges {
                 int32 first = 1; int32 hex = 0x10; int32 octal = 021;
                 int32 below = 18999; int32 above = 20000; int32 top = 536870911;
               }"#,
        ),
        one(
            "a byte order mark and CRLF line ends",
            Agree,
            "\u{feff}syntax = \"proto3\";\r\nmessage Crlf {\r\n  int32 a = 1;\r\n  string b = 2;\r\n}\r\n",
        ),
        one(
            "proto3 optional",
            Agree,
            r#"syntax = "proto3";
               message Opt { optional int32 a = 1; optional Sub s = 2; int32 plain = 3;
                             message Sub { optional string t = 1; } }"#,
        ),
        one(
            "forward references and one message used twice",
            Agree,
            r#"syntax = "proto3";
               message First { Later one = 1; Later two = 2; }
               message Later { int32 v = 1; Last last = 2; }
               message Last { string s = 1; }"#,
        ),
        one(
            "non-ASCII text inside comments and strings",
            Agree,
            "syntax = \"proto3\";\n// caf\u{e9} \u{1F600}\nmessage Text {\n  string s = 1 [json_name = \"h\u{e9}llo\"]; /* \u{4e2d}\u{6587} */\n}\n",
        ),
        one(
            "an empty message and a file with only an enum",
            Agree,
            "syntax = \"proto3\";\nenum E { Z = 0; }\nmessage Empty {}\nmessage HoldsEnum { E e = 1; }\n",
        ),
        case(
            "imports, a public re-export, and a root in the imported file",
            Agree,
            &[
                (
                    "app/root.proto",
                    r#"syntax = "proto3";
                       package app;
                       import "lib/mid.proto";
                       message Root { lib.Stamp at = 1; lib.deep.Deep d = 2; int32 id = 3; }"#,
                ),
                (
                    "lib/mid.proto",
                    r#"syntax = "proto3";
                       package lib;
                       import public "lib/deep.proto";
                       message Stamp { int64 secs = 1; int32 nanos = 2; deep.Deep inner = 3; }"#,
                ),
                (
                    "lib/deep.proto",
                    r#"syntax = "proto3";
                       package lib.deep;
                       message Deep { string name = 1; repeated int32 samples = 2; }"#,
                ),
            ],
        ),
        case(
            "one package spread over two files",
            Agree,
            &[
                (
                    "one.proto",
                    "syntax = \"proto3\";\npackage shared;\nimport \"two.proto\";\nmessage A { B b = 1; int32 x = 2; }\n",
                ),
                (
                    "two.proto",
                    "syntax = \"proto3\";\npackage shared;\nmessage B { string y = 1; }\n",
                ),
            ],
        ),
        one("a chain twenty messages long", Agree, &chain(20)),
        // protoc's own nesting limit, from the inside: 31 levels compile.
        one(
            "messages written 31 deep, the most protoc compiles",
            Agree,
            &nested(31),
        ),
        one("a message with three hundred fields", Agree, &{
            let mut s = String::from("syntax = \"proto3\";\nmessage Wide {\n");
            for i in 1..=300 {
                s.push_str(&format!("  int32 field_{i} = {i};\n"));
            }
            s.push_str("}\n");
            s
        }),
        // ---- schemas protoc refuses and the door must blame on the same line --
        one(
            "a missing semicolon",
            BothRefuse,
            "syntax = \"proto3\";\nmessage M {\n  int32 a = 1\n  int32 b = 2;\n}\n",
        ),
        one(
            "an undefined type",
            BothRefuse,
            "syntax = \"proto3\";\nmessage M {\n  int32 ok = 1;\n  Missing m = 2;\n}\n",
        ),
        one(
            "an undefined dotted type",
            BothRefuse,
            "syntax = \"proto3\";\npackage p;\nmessage M {\n  p.Missing m = 1;\n}\n",
        ),
        one(
            "an absolute name that is not defined",
            BothRefuse,
            "syntax = \"proto3\";\nmessage M {\n  .nowhere.T t = 1;\n}\n",
        ),
        case(
            "a type from a file that is imported only by an import",
            BothRefuse,
            &[
                (
                    "a.proto",
                    "syntax = \"proto3\";\nimport \"mid.proto\";\nmessage U {\n  Leaf l = 1;\n}\n",
                ),
                ("mid.proto", "syntax = \"proto3\";\nimport \"leaf.proto\";\n"),
                (
                    "leaf.proto",
                    "syntax = \"proto3\";\nmessage Leaf { int32 x = 1; }\n",
                ),
            ],
        ),
        one(
            "a repeated field number",
            BothRefuse,
            "syntax = \"proto3\";\nmessage M {\n  int32 a = 1;\n  int32 b = 2;\n  int32 c = 1;\n}\n",
        ),
        one(
            "a repeated field number across a oneof",
            BothRefuse,
            "syntax = \"proto3\";\nmessage M {\n  int32 a = 1;\n  oneof o {\n    int32 b = 1;\n  }\n}\n",
        ),
        one(
            "field number zero",
            BothRefuse,
            "syntax = \"proto3\";\nmessage M {\n  int32 a = 0;\n}\n",
        ),
        one(
            "a field number above 2^29 - 1",
            BothRefuse,
            "syntax = \"proto3\";\nmessage M {\n  int32 a = 536870912;\n}\n",
        ),
        one(
            "a field number inside 19000 to 19999",
            BothRefuse,
            "syntax = \"proto3\";\nmessage M {\n  int32 a = 19000;\n}\n",
        ),
        one(
            "a repeated field name",
            BothRefuse,
            "syntax = \"proto3\";\nmessage M {\n  int32 a = 1;\n  string a = 2;\n}\n",
        ),
        one(
            "a nested message named like a field",
            BothRefuse,
            "syntax = \"proto3\";\nmessage M {\n  int32 clash = 1;\n  message clash {}\n}\n",
        ),
        one(
            "a message defined twice",
            BothRefuse,
            "syntax = \"proto3\";\nmessage M {}\nmessage Other {}\nmessage M {}\n",
        ),
        one(
            "enum values that clash across two enums",
            BothRefuse,
            "syntax = \"proto3\";\nmessage M {\n  enum E { A = 0; }\n  enum F { A = 0; }\n}\n",
        ),
        one(
            "a reserved name used",
            BothRefuse,
            "syntax = \"proto3\";\nmessage M {\n  reserved \"x\";\n  int32 x = 1;\n}\n",
        ),
        one(
            "a proto2 field with no label",
            BothRefuse,
            "syntax = \"proto2\";\nmessage M {\n  optional int32 ok = 1;\n  int32 bad = 2;\n}\n",
        ),
        one(
            "required in proto3",
            BothRefuse,
            "syntax = \"proto3\";\nmessage M {\n  required int32 a = 1;\n}\n",
        ),
        one(
            "a label inside a oneof",
            BothRefuse,
            "syntax = \"proto3\";\nmessage M {\n  oneof o {\n    repeated int32 a = 1;\n  }\n}\n",
        ),
        one(
            "a label on a map",
            BothRefuse,
            "syntax = \"proto3\";\nmessage M {\n  repeated map<string, int32> a = 1;\n}\n",
        ),
        one(
            "a float map key",
            BothRefuse,
            "syntax = \"proto3\";\nmessage M {\n  map<float, int32> a = 1;\n}\n",
        ),
        one(
            "an enum map key",
            BothRefuse,
            "syntax = \"proto3\";\nenum E { Z = 0; }\nmessage M {\n  map<E, int32> a = 1;\n}\n",
        ),
        one(
            "a message map key",
            BothRefuse,
            "syntax = \"proto3\";\nmessage K {}\nmessage M {\n  map<K, int32> a = 1;\n}\n",
        ),
        one(
            "a bytes map key",
            BothRefuse,
            "syntax = \"proto3\";\nmessage M {\n  map<bytes, int32> a = 1;\n}\n",
        ),
        one(
            "an unterminated block comment",
            BothRefuse,
            "syntax = \"proto3\";\n/* never closed\nmessage M {\n  int32 a = 1;\n}\n",
        ),
        one(
            "a string that crosses a line",
            BothRefuse,
            "syntax = \"proto3\";\nmessage M {\n  int32 a = 1 [json_name = \"ab\n  cd\"];\n}\n",
        ),
        one(
            "an invalid escape",
            BothRefuse,
            "syntax = \"proto3\";\nmessage M {\n  string a = 1 [json_name = \"x\\qy\"];\n}\n",
        ),
        one(
            "0x with no digits",
            BothRefuse,
            "syntax = \"proto3\";\nmessage M {\n  int32 a = 0x;\n}\n",
        ),
        one(
            "a number run into an identifier",
            BothRefuse,
            "syntax = \"proto3\";\nmessage M {\n  int32 a = 1abc;\n}\n",
        ),
        one(
            "an octal literal with an 8",
            BothRefuse,
            "syntax = \"proto3\";\nmessage M {\n  int32 a = 08;\n}\n",
        ),
        one(
            "an integer out of range",
            BothRefuse,
            "syntax = \"proto3\";\nmessage M {\n  int32 a = 99999999999999999999;\n}\n",
        ),
        one(
            "a negative field number",
            BothRefuse,
            "syntax = \"proto3\";\nmessage M {\n  int32 a = -1;\n}\n",
        ),
        one(
            "a stray closing brace",
            BothRefuse,
            "syntax = \"proto3\";\nmessage M {\n  int32 a = 1;\n}\n}\n",
        ),
        one(
            "a message never closed",
            BothRefuse,
            "syntax = \"proto3\";\nmessage M {\n  int32 a = 1;\n",
        ),
        one(
            "a field with no name",
            BothRefuse,
            "syntax = \"proto3\";\nmessage M {\n  int32 = 1;\n}\n",
        ),
        one(
            "a message with no name",
            BothRefuse,
            "syntax = \"proto3\";\nmessage {\n}\n",
        ),
        one(
            "a field with no equals sign",
            BothRefuse,
            "syntax = \"proto3\";\nmessage M {\n  int32 a 1;\n}\n",
        ),
        one(
            "something that is not a statement",
            BothRefuse,
            "syntax = \"proto3\";\nfoo bar;\nmessage M {}\n",
        ),
        // ... and from the outside: the 32nd level is refused by both, and
        // protoc names no line for it.
        one(
            "messages written 32 deep, one past protoc's limit",
            BothRefuse,
            &nested(32),
        ),
        one(
            "an option missing its semicolon",
            BothRefuse,
            "syntax = \"proto3\";\nmessage M {\n  option deprecated = true\n  int32 a = 1;\n}\n",
        ),
        one(
            "an option with no value",
            BothRefuse,
            "syntax = \"proto3\";\nmessage M {\n  option deprecated = ;\n}\n",
        ),
        one(
            "an unknown syntax",
            BothRefuse,
            "syntax = \"proto4\";\nmessage M {}\n",
        ),
        one(
            "two package statements",
            BothRefuse,
            "syntax = \"proto3\";\npackage a;\npackage b;\nmessage M {}\n",
        ),
        one(
            "an extension range in proto3",
            BothRefuse,
            "syntax = \"proto3\";\nmessage M {\n  extensions 100 to 199;\n}\n",
        ),
        one(
            "a type that is a field",
            BothRefuse,
            "syntax = \"proto3\";\nmessage M { int32 a = 1; }\nmessage N {\n  M.a b = 1;\n}\n",
        ),
        one(
            "a dotted name never turns back to an outer scope",
            BothRefuse,
            "syntax = \"proto3\";\npackage p;\nmessage A { message B { int32 in_a_b = 1; } }\n\
             message C {\n  message A { }\n  A.B x = 1;\n}\n",
        ),
        one(
            "a semantic error followed by a syntax error",
            BothRefuse,
            "syntax = \"proto3\";\nmessage M {\n  int32 a = 0;\n  int32 b = 2\n  int32 c = 3;\n}\n",
        ),
        case(
            "an import that is not there",
            BothRefuse,
            &[(
                "a.proto",
                "syntax = \"proto3\";\nimport \"nothere.proto\";\nmessage M {}\n",
            )],
        ),
        case(
            "an import cycle",
            BothRefuse,
            &[
                (
                    "c1.proto",
                    "syntax = \"proto3\";\nimport \"c2.proto\";\nmessage A {}\n",
                ),
                (
                    "c2.proto",
                    "syntax = \"proto3\";\nimport \"c1.proto\";\nmessage B {}\n",
                ),
            ],
        ),
        case(
            "a file that imports itself",
            BothRefuse,
            &[(
                "a.proto",
                "syntax = \"proto3\";\nimport \"a.proto\";\nmessage M {}\n",
            )],
        ),
        case(
            "the same import twice",
            BothRefuse,
            &[
                (
                    "a.proto",
                    "syntax = \"proto3\";\nimport \"b.proto\";\nimport \"b.proto\";\nmessage M { B b = 1; }\n",
                ),
                ("b.proto", "syntax = \"proto3\";\nmessage B {}\n"),
            ],
        ),
        case(
            "an error in an imported file, under its own name",
            BothRefuse,
            &[
                (
                    "a.proto",
                    "syntax = \"proto3\";\nimport \"b.proto\";\nmessage A { Missing m = 1; }\n",
                ),
                (
                    "b.proto",
                    "syntax = \"proto3\";\nmessage B {\n  int32 = 1;\n}\n",
                ),
            ],
        ),
        case(
            "an undefined type in an imported file",
            BothRefuse,
            &[
                (
                    "a.proto",
                    "syntax = \"proto3\";\nimport \"b.proto\";\nmessage A { B b = 1; }\n",
                ),
                (
                    "b.proto",
                    "syntax = \"proto3\";\nmessage B {\n  int32 ok = 1;\n  Nope n = 2;\n}\n",
                ),
            ],
        ),
        // ---- what protoc compiles and the door refuses, on purpose -----------
        one(
            "a group",
            DoorRefuses("M", "group fields are not supported"),
            "syntax = \"proto2\";\nmessage M {\n  optional group G = 1 {\n    optional int32 x = 2;\n  }\n}\n",
        ),
        one(
            "an extend block",
            DoorRefuses("M", "`extend` is not supported"),
            "syntax = \"proto2\";\nmessage M {\n  optional int32 a = 1;\n  extensions 100 to 199;\n}\nextend M {\n  optional int32 x = 100;\n}\n",
        ),
        one(
            "an extend block inside a message",
            DoorRefuses("M", "`extend` is not supported"),
            "syntax = \"proto2\";\nmessage Base {\n  optional int32 a = 1;\n  extensions 100 to 199;\n}\nmessage M {\n  extend Base {\n    optional int32 x = 100;\n  }\n}\n",
        ),
        case(
            "a weak import",
            DoorRefuses("M", "import weak"),
            &[
                (
                    "a.proto",
                    "syntax = \"proto3\";\nimport weak \"b.proto\";\nmessage M {}\n",
                ),
                ("b.proto", "syntax = \"proto3\";\nmessage B {}\n"),
            ],
        ),
        one(
            "a message holding itself",
            DoorRefuses("Node", "contains itself"),
            "syntax = \"proto3\";\nmessage Node {\n  int32 value = 1;\n  repeated Node children = 2;\n}\n",
        ),
        one(
            "a cycle through three messages and a map",
            DoorRefuses("A", "A -> B -> C -> A"),
            "syntax = \"proto3\";\nmessage A { B b = 1; }\nmessage B { map<string, C> c = 1; }\nmessage C { A back = 1; }\n",
        ),
        one("an expansion past the line budget", DoorRefuses("M0", "more than 16384 declarations"), &{
            let mut s = String::from("syntax = \"proto3\";\n");
            for i in 0..20 {
                s.push_str(&format!(
                    "message M{i} {{ M{n} a = 1; M{n} b = 2; }}\n",
                    n = i + 1
                ));
            }
            s.push_str("message M20 { int32 leaf = 1; }\n");
            s
        }),
        one(
            "a chain deeper than the path bound",
            DoorRefuses("M0", "levels deep"),
            &chain(70),
        ),
        // ---- what protoc refuses and the door, not being a validator, does not -
        one(
            "a proto3 enum that does not start at zero",
            DoorAccepts("M"),
            "syntax = \"proto3\";\nenum E { ONE = 1; }\nmessage M { E e = 1; int32 x = 2; }\n",
        ),
        one(
            "duplicate enum numbers without allow_alias",
            DoorAccepts("M"),
            "syntax = \"proto3\";\nenum E { Z = 0; ALSO_ZERO = 0; }\nmessage M { E e = 1; }\n",
        ),
        one(
            "two proto3 fields with one JSON name",
            DoorAccepts("M"),
            "syntax = \"proto3\";\nmessage M {\n  int32 foo_bar = 1;\n  int32 fooBar = 2;\n}\n",
        ),
        one(
            "a field inside an extension range",
            DoorAccepts("M"),
            "syntax = \"proto2\";\nmessage M {\n  extensions 10 to 20;\n  optional int32 x = 15;\n}\n",
        ),
    ];
    // protoc refuses a reserved number without naming a line, which is the one
    // class where there is a file and no line to compare.
    cases.push(one(
        "a reserved number used",
        BothRefuse,
        "syntax = \"proto3\";\nmessage M {\n  reserved 2, 5 to 7;\n  int32 a = 6;\n}\n",
    ));
    cases
}

// ---- the run -----------------------------------------------------------------

/// Write a case's files under `dir`, creating the directories names imply.
fn write_case(dir: &Path, case: &Case) {
    for (name, text) in &case.files {
        let path = dir.join(name);
        std::fs::create_dir_all(path.parent().expect("a file has a parent"))
            .expect("create the schema directory");
        std::fs::write(&path, text).expect("write the schema");
    }
}

/// THE ADJUDICATOR: the `.proto` door judged by `protoc` over the whole corpus.
///
/// The `protoc` in the name is LOAD-BEARING for the reason the `tcpdump`
/// adjudicator beside it gives: Layer C0's skip-token rule reads the FUNCTION
/// name.
#[test]
fn the_proto_door_agrees_with_protoc_over_the_corpus() {
    let required = std::env::var("WZ_PROTOC_REQUIRE").is_ok();
    // ---- IS THE JUDGE PRESENT? ----------------------------------------------
    // A missing `protoc`, or one that cannot read its own `descriptor.proto`
    // (`/usr/include/google/protobuf/descriptor.proto`, from libprotobuf-dev),
    // is a SKIP and not a pass -- and an armed lane turns it into a failure.
    let judge = protoc().and_then(|p| {
        let dir = tempfile::tempdir().map_err(|e| e.to_string())?;
        std::fs::write(
            dir.path().join("probe.proto"),
            "syntax = \"proto3\";\nmessage P { int32 a = 1; }\n",
        )
        .map_err(|e| e.to_string())?;
        let probe = compile(&p, dir.path(), "probe.proto")?;
        if probe.descriptor_text.is_none() {
            return Err(format!("protoc refused the probe schema: {}", probe.stderr));
        }
        Ok(p)
    });
    let protoc = match judge {
        Ok(p) => p,
        Err(why) => {
            if required {
                panic!(
                    "WZ_PROTOC_REQUIRE is set and protoc cannot judge: {why}. The `.proto` door \
                     has no other adjudicator, so a lane that armed this flag was asking for the \
                     measurement, not for a skip"
                );
            }
            eprintln!(
                "skip: protoc cannot judge here ({why}); set WZ_PROTOC_REQUIRE=1 to make that a failure"
            );
            return;
        }
    };

    let mut disagreements: Vec<String> = Vec::new();
    let (mut schemas, mut roots, mut blamed, mut purposeful, mut unchecked) = (0, 0, 0, 0, 0);
    let corpus = corpus();
    let mut names: Vec<&str> = corpus.iter().map(|c| c.name.as_str()).collect();
    names.sort_unstable();
    let before = names.len();
    names.dedup();
    assert_eq!(before, names.len(), "two corpus cases share a name");

    for case in &corpus {
        let dir = tempfile::tempdir().expect("tempdir for the schemas");
        write_case(dir.path(), case);
        let root_file = &case.files[0].0;
        let compiled = match compile(&protoc, dir.path(), root_file) {
            Ok(c) => c,
            Err(e) => panic!("{}: {e}", case.name),
        };
        let say = |what: String| format!("[{}] {what}", case.name);

        match &case.expect {
            Expect::Agree => {
                let Some(text) = &compiled.descriptor_text else {
                    disagreements.push(say(format!(
                        "the corpus is wrong: protoc refused a schema marked Agree:\n{}",
                        compiled.stderr
                    )));
                    continue;
                };
                let set = read_text(text).expect("protoc's own output reads");
                let msgs = collect(&set);
                // Every message the schema defines, nested ones and ones in
                // imported files included, as a root.
                let candidates: Vec<&String> = msgs
                    .iter()
                    .filter(|(_, m)| !m.map_entry && !m.file.starts_with("google/"))
                    .map(|(name, _)| name)
                    .collect();
                assert!(
                    !candidates.is_empty(),
                    "{}: no message to compare",
                    case.name
                );
                schemas += 1;
                for root in candidates {
                    let door = call_door(root.trim_start_matches('.'), &case.files);
                    roots += 1;
                    if let Some(diff) = compare_success(&msgs, root, &door) {
                        disagreements.push(say(diff));
                    }
                }
            }
            Expect::BothRefuse => {
                if compiled.ok {
                    disagreements.push(say(
                        "the corpus is wrong: protoc compiled a schema marked BothRefuse".into(),
                    ));
                    continue;
                }
                let Some(blame) = first_blame(&compiled.stderr) else {
                    disagreements.push(say(format!(
                        "protoc refused it and named no file: {}",
                        compiled.stderr
                    )));
                    continue;
                };
                let door = call_door("X", &case.files);
                blamed += 1;
                if let Some(diff) = compare_refusal(&blame, &door) {
                    disagreements
                        .push(say(format!("{diff}\n  protoc: {}", compiled.stderr.trim())));
                }
            }
            Expect::DoorRefuses(root, reason) => {
                if !compiled.ok {
                    disagreements.push(say(format!(
                        "the corpus is wrong: protoc refused a schema the door is meant to \
                         refuse by itself:\n{}",
                        compiled.stderr
                    )));
                    continue;
                }
                let door = call_door(root, &case.files);
                purposeful += 1;
                if door.ok || !door.reason.contains(reason) {
                    disagreements.push(say(format!(
                        "protoc compiles it and the door was meant to refuse it with `{reason}`; \
                         ok={} reason={}",
                        door.ok, door.reason
                    )));
                }
            }
            Expect::DoorAccepts(root) => {
                if compiled.ok {
                    disagreements.push(say(
                        "the corpus is wrong: protoc compiled a schema marked DoorAccepts".into(),
                    ));
                    continue;
                }
                let door = call_door(root, &case.files);
                unchecked += 1;
                if !door.ok {
                    disagreements.push(say(format!(
                        "the door is not a validator and was meant to accept this: {}",
                        door.reason
                    )));
                }
            }
        }
    }

    // A comparison over an empty population is trivially true, and the four
    // counts are printed so a reader can tell a pass from a lane that measured
    // nothing.
    eprintln!(
        "proto door vs protoc: {schemas} compiled schema(s) / {roots} root(s) compared, \
         {blamed} refusal(s) blamed on the same file and line, {purposeful} deliberate \
         refusal(s), {unchecked} non-validation(s)"
    );
    assert!(
        schemas >= 20 && roots >= 40 && blamed >= 40 && purposeful >= 8 && unchecked >= 3,
        "the corpus no longer exercises each arm: {schemas}/{roots}/{blamed}/{purposeful}/{unchecked}"
    );
    assert!(
        disagreements.is_empty(),
        "the door and protoc disagree on {} point(s):\n\n{}",
        disagreements.len(),
        disagreements.join("\n\n")
    );
}

// ---- the controls: no protoc needed -------------------------------------------

/// protoc 3.21's `--decode` rendering of
/// `package p; message Outer { int32 id = 1; Inner in = 2; map<string, Inner> m = 3;
/// message Inner { string tag = 5; } }`, recorded so the reader and the walk are
/// graded on every machine.
const RECORDED: &str = r#"file {
  name: "r.proto"
  package: "p"
  message_type {
    name: "Outer"
    field { name: "id" number: 1 label: LABEL_OPTIONAL type: TYPE_INT32 json_name: "id" }
    field {
      name: "in"
      number: 2
      label: LABEL_OPTIONAL
      type: TYPE_MESSAGE
      type_name: ".p.Outer.Inner"
      json_name: "in"
    }
    field {
      name: "m"
      number: 3
      label: LABEL_REPEATED
      type: TYPE_MESSAGE
      type_name: ".p.Outer.MEntry"
      json_name: "m"
    }
    nested_type {
      name: "Inner"
      field { name: "tag" number: 5 label: LABEL_OPTIONAL type: TYPE_STRING json_name: "tag" }
    }
    nested_type {
      name: "MEntry"
      field { name: "key" number: 1 label: LABEL_OPTIONAL type: TYPE_STRING json_name: "key" }
      field {
        name: "value"
        number: 2
        label: LABEL_OPTIONAL
        type: TYPE_MESSAGE
        type_name: ".p.Outer.Inner"
        json_name: "value"
      }
      options { map_entry: true }
    }
  }
  syntax: "proto3"
}
"#;

fn door_of(text: &str, ok: bool) -> Door {
    Door {
        ok,
        declarations: text.to_string(),
        installed: text.lines().count(),
        file: None,
        line: None,
        reason: String::new(),
    }
}

#[test]
fn the_descriptor_reader_derives_the_tree_the_door_is_held_to() {
    let msgs = collect(&read_text(RECORDED).expect("reads"));
    assert!(
        msgs[".p.Outer.MEntry"].map_entry,
        "the map's entry is marked"
    );
    let want = derive(&msgs, ".p.Outer").expect("not recursive");
    assert_eq!(
        want,
        [
            "demo/sensor=protobuf",
            "demo/sensor:1=id",
            "demo/sensor:2=in",
            "demo/sensor:2.5=tag",
            "demo/sensor:3=m",
            "demo/sensor:3.1=key",
            "demo/sensor:3.2=value",
            "demo/sensor:3.2.5=tag",
        ],
        "a map is the repeated entry message protoc expanded it into"
    );
    // A recorded descriptor of a message that holds itself is a cycle, named.
    let looping = read_text(
        "file { name: \"l.proto\" message_type { name: \"N\" \
         field { name: \"next\" number: 1 type: TYPE_MESSAGE type_name: \".N\" } } }",
    )
    .expect("reads");
    assert_eq!(derive(&collect(&looping), ".N"), Err(".N".to_string()));
}

#[test]
fn the_comparison_reports_a_door_that_disagrees() {
    let msgs = collect(&read_text(RECORDED).expect("reads"));
    let right = derive(&msgs, ".p.Outer").expect("not recursive").join("\n") + "\n";
    // The control: the right text is accepted by the comparison (the validation
    // door is real, so this also holds the text to the installer).
    assert_eq!(
        compare_success(&msgs, ".p.Outer", &door_of(&right, true)),
        None
    );
    // One name changed.
    let renamed = right.replace("=tag\n", "=label\n");
    assert!(compare_success(&msgs, ".p.Outer", &door_of(&renamed, true)).is_some());
    // One path shifted.
    let shifted = right.replace(":3.2=value", ":3.3=value");
    assert!(compare_success(&msgs, ".p.Outer", &door_of(&shifted, true)).is_some());
    // Two lines swapped: the order is part of the contract.
    let mut lines: Vec<&str> = right.lines().collect();
    lines.swap(1, 2);
    let swapped = lines.join("\n") + "\n";
    assert!(compare_success(&msgs, ".p.Outer", &door_of(&swapped, true)).is_some());
    // A line dropped.
    let dropped = right.lines().take(5).collect::<Vec<_>>().join("\n") + "\n";
    assert!(compare_success(&msgs, ".p.Outer", &door_of(&dropped, true)).is_some());
    // A refusal where protoc compiled.
    assert!(compare_success(&msgs, ".p.Outer", &door_of("", false)).is_some());

    // The refusal comparison: the same file and line pass, one line off fails,
    // a different file fails, and a declaration where protoc refused fails.
    let blamed = ("a.proto".to_string(), Some(4));
    let door = |ok, file: Option<&str>, line| Door {
        ok,
        declarations: String::new(),
        installed: 0,
        file: file.map(str::to_string),
        line,
        reason: "r".to_string(),
    };
    assert_eq!(
        compare_refusal(&blamed, &door(false, Some("a.proto"), Some(4))),
        None
    );
    assert!(compare_refusal(&blamed, &door(false, Some("a.proto"), Some(5))).is_some());
    assert!(compare_refusal(&blamed, &door(false, Some("b.proto"), Some(4))).is_some());
    assert!(compare_refusal(&blamed, &door(true, None, None)).is_some());
    // protoc naming no line leaves only the file to compare.
    let no_line = ("a.proto".to_string(), None);
    assert_eq!(
        compare_refusal(&no_line, &door(false, Some("a.proto"), Some(9))),
        None
    );
    assert!(compare_refusal(&no_line, &door(false, Some("c.proto"), Some(9))).is_some());
    // ... but a door refusal with no line is the root being missing, which is
    // the door having read the schema without objection: not agreement.
    assert!(compare_refusal(&no_line, &door(false, Some("a.proto"), None)).is_some());
    assert!(compare_refusal(&blamed, &door(false, Some("a.proto"), None)).is_some());
}

#[test]
fn the_error_reader_picks_the_blame_protoc_means() {
    // A missing import is announced first without a line and then at the import.
    let missing = "nothere.proto: File not found.\n\
                   badimp.proto:2:1: Import \"nothere.proto\" was not found or had errors.\n";
    assert_eq!(
        first_blame(missing),
        Some(("badimp.proto".to_string(), Some(2)))
    );
    // A warning is not blame, and the note after an error is not the error.
    let warned = "weak.proto:2:1: warning: Import x is unused.\nweak.proto:5:9: Expected \";\".\n\
                  weak.proto:5:9: Suggested field numbers for M: 1\n";
    assert_eq!(
        first_blame(warned),
        Some(("weak.proto".to_string(), Some(5)))
    );
    // A reserved number is reported with no line at all.
    let reserved = "resnum.proto: Field \"a\" uses reserved number 5.\n\
                    resnum.proto: Suggested field numbers for M: 1\n";
    assert_eq!(
        first_blame(reserved),
        Some(("resnum.proto".to_string(), None))
    );
    // Library noise names no file.
    assert_eq!(
        first_blame("[libprotobuf WARNING google/protobuf/compiler/parser.cc:646] No syntax\n"),
        None
    );
}

#[test]
fn the_corpus_names_each_case_once_and_covers_each_arm() {
    let corpus = corpus();
    let count = |f: fn(&Expect) -> bool| corpus.iter().filter(|c| f(&c.expect)).count();
    assert!(count(|e| matches!(e, Expect::Agree)) >= 20);
    assert!(count(|e| matches!(e, Expect::BothRefuse)) >= 40);
    assert!(count(|e| matches!(e, Expect::DoorRefuses(..))) >= 8);
    assert!(count(|e| matches!(e, Expect::DoorAccepts(_))) >= 3);
    for case in &corpus {
        assert!(!case.files.is_empty(), "{} has no file", case.name);
    }
}
