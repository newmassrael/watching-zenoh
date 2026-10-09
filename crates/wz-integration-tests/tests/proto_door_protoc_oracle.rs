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
//! what `protoc` compiles and the door refuses ON PURPOSE (a group or an
//! `extend` the root message reaches, a recursive message, a size bound), what
//! `protoc` refuses and the door does not check because it is not a validator (an
//! enum's numbering, the fields of an `extend` block), and the one error `protoc`
//! reports without a line (a reserved number).
//!
//! A schema with an `extend` or a `group` is judged from named roots and not
//! from every message it defines: whether the door refuses depends on which
//! messages the root reaches, so a case lists the roots it means (`AgreeFrom`)
//! and the roots that must be refused are cases of their own.
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
//!
//! ## The judge is MEASURED, because `protoc` is not one program
//!
//! The first corpus was written against protoc 3.21.12 and went red on the
//! hosted runner, which has 3.12.4 (Ubuntu 22.04): that release refuses a
//! proto3 `optional` field unless `--experimental_allow_proto3_optional` is
//! given, and compiles messages nested 32 deep where 3.21 stops at 31. Both
//! facts had been written into the corpus as literals, so the corpus described
//! one build of the judge and not the judge. Every fact of that kind is now
//! probed from the `protoc` that runs ([`Judge`]): whether it needs the flag
//! (and the flag is passed when it does), and the deepest nesting it compiles,
//! for messages and for groups. A case about depth is decided from the probe
//! ([`depth_expect`]): where the door refuses what this `protoc` accepts it is a
//! deliberate refusal, where both refuse it is an agreement. The door's own
//! bound is 31 (`MAX_MESSAGE_NESTING`, `protoc` 3.21's limit) whatever `protoc`
//! is installed, and a control holds that number to the door.
//!
//! `WZ_PROTOC_BIN` names the `protoc` to judge with, and the `descriptor.proto`
//! fed to the door is the one beside it (`<bin>/../include`, where a package
//! unpacked with `dpkg -x` puts it), then the installed ones. To reproduce a
//! runner without installing anything: unpack its `protobuf-compiler`,
//! `libprotoc` and `libprotobuf-dev` `.deb` files into a directory, then run
//! this test with `WZ_PROTOC_BIN=<dir>/usr/bin/protoc` and
//! `LD_LIBRARY_PATH=<dir>/usr/lib/x86_64-linux-gnu`.
//!
//! ## The value door is judged here too
//!
//! `wz_dissect_proto_encode` writes the wire bytes of a message from JSON field
//! values, and the last section of this file holds it to `protoc --encode`, which
//! writes the bytes of the same message given as text format: the corpus is one
//! message in both notations per case, and the two byte strings must be equal
//! (see the section's own comment for the one place, map entries, where the
//! format leaves the order to the writer). It shares the judge, the arming flag
//! and the skip rule of the declaration door, so the lane that arms one arms the
//! other. `WZ_PROTO_VALUES_DUMP=1` prints every case with the door's bytes, for
//! pointing a second judge of the JSON notation at the same corpus.
// NO CROSS-IMPL PROOF DECLARATION HERE, for the reason the tcpdump adjudicator
// next to it gives: `protoc` is a foreign TOOL and not a zenoh implementation,
// so this file contributes nothing to the cross-implementation accounting.

use std::collections::BTreeMap;
use std::ffi::{c_char, CStr, CString};
use std::path::{Path, PathBuf};
use std::process::Command;

use wz_capi_dissect::{
    wz_dissect_declarations_diagnose, wz_dissect_declarations_from_proto, wz_dissect_proto_encode,
    wz_dissect_string_free, WzDissectProtoFile, WZ_DISSECT_OK,
};

/// The key pattern every case declares under.
const KEY: &str = "demo/sensor";

// ---- the judge ---------------------------------------------------------------

/// The deepest nesting the judge is asked about. A `protoc` that compiles this
/// many levels is reported as having no limit below it, which is all the corpus
/// needs to know.
const DEPTH_CAP: usize = 128;

/// How deeply the door lets messages, and groups, be written inside one
/// another: `MAX_MESSAGE_NESTING` in the reader, which is `protoc` 3.21's own
/// limit. Older releases accept more (3.12.4 does), so this is a fact about the
/// DOOR, held to the door by `the_door_reads_the_nesting_this_file_says_it_does`,
/// and what `protoc` does at these depths is the judge's to say.
const DOOR_NESTING: usize = 31;

/// The `protoc` that judges, with the facts about it that differ between
/// releases, each MEASURED from it (see the module documentation).
struct Judge {
    bin: PathBuf,
    /// `protoc --version`, for the log: a red from a runner has to say whose
    /// opinion it was.
    version: String,
    /// Whether it refuses a proto3 `optional` field unless told
    /// `--experimental_allow_proto3_optional`.
    needs_proto3_optional_flag: bool,
    /// The deepest `nested(n)` it compiles, up to [`DEPTH_CAP`].
    deepest_message: usize,
    /// The deepest `grouped(n)` it compiles, up to [`DEPTH_CAP`].
    deepest_group: usize,
    /// Whether `--encode` writes a proto3 `float` or `double` set to `-0.0`,
    /// which is not the default by its BITS. MEASURED, not read from a version:
    /// protoc 3.21.12 writes it and protoc 3.12.4 (the hosted runner's) omits it,
    /// as if it compared the value with zero, and no source in this tree says
    /// which release changed it.
    writes_negative_zero: bool,
}

impl Judge {
    /// Flags every compilation takes for this `protoc`.
    fn flags(&self) -> &'static [&'static str] {
        if self.needs_proto3_optional_flag {
            &["--experimental_allow_proto3_optional"]
        } else {
            &[]
        }
    }

    fn compile(&self, dir: &Path, root: &str) -> Result<Compiled, String> {
        compile(&self.bin, self.flags(), dir, root)
    }
}

/// `protoc` and what it says its version is, or why it cannot judge.
fn protoc() -> Result<(PathBuf, String), String> {
    let bin = std::env::var("WZ_PROTOC_BIN").unwrap_or_else(|_| "protoc".to_string());
    let probe = Command::new(&bin)
        .arg("--version")
        .output()
        .map_err(|e| format!("`{bin}` did not run ({e})"))?;
    if !probe.status.success() {
        return Err(format!("`{bin} --version` failed"));
    }
    let version = String::from_utf8_lossy(&probe.stdout).trim().to_string();
    Ok((PathBuf::from(bin), version))
}

/// Whether a `protoc` needs `--experimental_allow_proto3_optional`, from what it
/// said about a schema with an `optional` proto3 field compiled WITHOUT the flag.
///
/// Read from the answer and not from the version number: a release that takes
/// the field says nothing about the flag, one that does not names it (protoc
/// 3.12.4: "This file contains proto3 optional fields, but
/// --experimental_allow_proto3_optional was not set."), and anything else is a
/// refusal this function has no business explaining away.
fn proto3_optional_flag_needed(without_the_flag: &Compiled) -> Result<bool, String> {
    if without_the_flag.ok {
        Ok(false)
    } else if without_the_flag
        .stderr
        .contains("experimental_allow_proto3_optional")
    {
        Ok(true)
    } else {
        Err(format!(
            "protoc refused a proto3 `optional` field for a reason that is not the missing flag: {}",
            without_the_flag.stderr
        ))
    }
}

/// The largest `n` in `0..=cap` with `compiles(n)`, for a `compiles` that holds
/// up to some depth and fails beyond it (a nesting limit). Zero means not even
/// one level. Found by bisection, so a probe costs a handful of `protoc` runs.
fn deepest(
    cap: usize,
    compiles: &mut dyn FnMut(usize) -> Result<bool, String>,
) -> Result<usize, String> {
    let (mut low, mut high) = (0, cap);
    while low < high {
        let mid = (low + high).div_ceil(2);
        if compiles(mid)? {
            low = mid;
        } else {
            high = mid - 1;
        }
    }
    Ok(low)
}

/// Whether `protoc` compiles `text` as one file, with `flags`.
fn compiles(protoc: &Path, flags: &[&str], text: &str) -> Result<bool, String> {
    let dir = tempfile::tempdir().map_err(|e| e.to_string())?;
    std::fs::write(dir.path().join("probe.proto"), text).map_err(|e| e.to_string())?;
    Ok(run_compiler(protoc, flags, dir.path(), "probe.proto")?.ok)
}

/// Measure the `protoc` at `bin`: the facts about it that differ between
/// releases, so that no corpus case has to know which release it is.
fn measure_judge(bin: PathBuf, version: String) -> Result<Judge, String> {
    let dir = tempfile::tempdir().map_err(|e| e.to_string())?;
    let optional = "syntax = \"proto3\";\nmessage P { optional int32 a = 1; }\n";
    std::fs::write(dir.path().join("probe.proto"), optional).map_err(|e| e.to_string())?;
    let needs_proto3_optional_flag =
        proto3_optional_flag_needed(&run_compiler(&bin, &[], dir.path(), "probe.proto")?)?;
    let probe = Judge {
        bin,
        version,
        needs_proto3_optional_flag,
        deepest_message: 0,
        deepest_group: 0,
        writes_negative_zero: false,
    };
    let writes_negative_zero = measure_negative_zero(&probe, dir.path())?;
    // The plain schema, which also proves `--decode` can read descriptor.proto.
    std::fs::write(
        dir.path().join("probe.proto"),
        "syntax = \"proto3\";\nmessage P { int32 a = 1; }\n",
    )
    .map_err(|e| e.to_string())?;
    let plain = probe.compile(dir.path(), "probe.proto")?;
    if plain.descriptor_text.is_none() {
        return Err(format!("protoc refused the probe schema: {}", plain.stderr));
    }
    let (bin, flags) = (probe.bin.clone(), probe.flags());
    let depth_of = |schema: fn(usize) -> String| -> Result<usize, String> {
        let found = deepest(DEPTH_CAP, &mut |n| compiles(&bin, flags, &schema(n)))?;
        // The search assumes a limit; hold it to what it found. A `protoc` whose
        // answer is not monotone would otherwise be judged by an accident of the
        // bisection.
        if found > 0 && !compiles(&bin, flags, &schema(found))? {
            return Err(format!("protoc refuses the {found} levels the probe found"));
        }
        if found < DEPTH_CAP && compiles(&bin, flags, &schema(found + 1))? {
            return Err(format!(
                "protoc compiles {} levels past the {found} the probe found",
                found + 1
            ));
        }
        Ok(found)
    };
    Ok(Judge {
        deepest_message: depth_of(nested)?,
        deepest_group: depth_of(grouped)?,
        writes_negative_zero,
        ..probe
    })
}

/// Whether `protoc --encode` writes a proto3 float or double that is `-0.0`,
/// from what it does on a one-field schema of each, and not from its version.
///
/// A proto3 field with no presence is written when its value is not the default.
/// Whether `-0.0` is the default depends on how the release tests for it: by
/// bits (writes it) or by comparing with zero (omits it, because `-0.0 == 0.0`).
/// The two kinds must agree; a judge that wrote one and omitted the other is a
/// judge this file has no rule for, and says so instead of picking one.
fn measure_negative_zero(judge: &Judge, dir: &Path) -> Result<bool, String> {
    std::fs::write(
        dir.join("negzero.proto"),
        "syntax = \"proto3\";\nmessage F { float a = 1; }\nmessage D { double a = 1; }\n",
    )
    .map_err(|e| e.to_string())?;
    let mut answers = Vec::new();
    for message in ["F", "D"] {
        let bytes = protoc_encode(judge, dir, "negzero.proto", message, "a: -0.0")?;
        answers.push(says_negative_zero(&bytes, message)?);
    }
    if answers[0] != answers[1] {
        return Err("protoc writes -0.0 for one of float and double and not the other".to_string());
    }
    Ok(answers[0])
}

/// What the bytes `protoc --encode` wrote for `a: -0.0` say: nothing (it omits
/// the field), or the one field whose payload is all zero but the sign. Anything
/// else is not an answer to the question.
fn says_negative_zero(bytes: &[u8], message: &str) -> Result<bool, String> {
    match (message, bytes) {
        (_, []) => Ok(false),
        ("F", [0x0d, 0, 0, 0, 0x80]) => Ok(true),
        ("D", [0x09, 0, 0, 0, 0, 0, 0, 0, 0x80]) => Ok(true),
        _ => Err(format!(
            "protoc wrote {} for `a: -0.0` in {message}: neither nothing nor -0.0",
            hex(bytes)
        )),
    }
}

/// THE `-0.0` PROBE READS WHAT PROTOC WROTE and refuses what it cannot read, with
/// no protoc: nothing is "omits", the sign bit alone is "writes", and a positive
/// zero, a wrong width or another field is no answer.
#[test]
fn the_negative_zero_probe_reads_what_protoc_wrote() {
    assert_eq!(says_negative_zero(&[], "F"), Ok(false));
    assert_eq!(says_negative_zero(&[], "D"), Ok(false));
    assert_eq!(says_negative_zero(&[0x0d, 0, 0, 0, 0x80], "F"), Ok(true));
    assert_eq!(
        says_negative_zero(&[0x09, 0, 0, 0, 0, 0, 0, 0, 0x80], "D"),
        Ok(true)
    );
    for (bytes, message) in [
        (vec![0x0d, 0, 0, 0, 0], "F"),
        (vec![0x0d, 0, 0, 0, 0x80], "D"),
        (vec![0x09, 0, 0, 0, 0, 0, 0, 0, 0], "D"),
        (vec![0x15, 0, 0, 0, 0x80], "F"),
        (vec![0x0d, 0, 0, 0x80], "F"),
    ] {
        assert!(says_negative_zero(&bytes, message).is_err(), "{bytes:?}");
    }
}

/// What `protoc` made of one schema directory.
struct Compiled {
    ok: bool,
    stderr: String,
    /// The `FileDescriptorSet` as `protoc --decode` prints it, when it compiled.
    descriptor_text: Option<String>,
}

/// Run `protoc` on `root` and report whether it accepted the schema and what it
/// said. Nothing is read back: this is the question "does it compile", and it is
/// the only one a depth probe can ask, because `protoc --decode` has a recursion
/// limit of its own ("Failed to parse input" in 3.12.4 past about 100 levels)
/// that the descriptor set of a deeply nested schema can exceed although the
/// schema compiled.
fn run_compiler(protoc: &Path, flags: &[&str], dir: &Path, root: &str) -> Result<Compiled, String> {
    let out = dir.join("out.pb");
    let run = Command::new(protoc)
        .args(flags)
        .arg(format!("--proto_path={}", dir.display()))
        .arg(format!("--descriptor_set_out={}", out.display()))
        .arg("--include_imports")
        .arg(root)
        .output()
        .map_err(|e| format!("protoc did not run: {e}"))?;
    Ok(Compiled {
        ok: run.status.success(),
        stderr: String::from_utf8_lossy(&run.stderr).into_owned(),
        descriptor_text: None,
    })
}

/// [`run_compiler`], and when the schema compiled, its descriptor set read back
/// in `protoc --decode`'s text form.
fn compile(protoc: &Path, flags: &[&str], dir: &Path, root: &str) -> Result<Compiled, String> {
    let out = dir.join("out.pb");
    let ran = run_compiler(protoc, flags, dir, root)?;
    if !ran.ok {
        return Ok(ran);
    }
    let stderr = ran.stderr;
    let decode = Command::new(protoc)
        .arg("--decode=google.protobuf.FileDescriptorSet")
        .arg("google/protobuf/descriptor.proto")
        .stdin(std::fs::File::open(&out).map_err(|e| format!("open the descriptor set: {e}"))?)
        .output()
        .map_err(|e| format!("protoc --decode did not run: {e}"))?;
    if !decode.status.success() {
        return Err(format!(
            "`protoc --decode` failed: it needs google/protobuf/descriptor.proto (shipped in \
             libprotobuf-dev, beside the binary or under /usr/include) and a descriptor set \
             within its own recursion limit: {}",
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
    /// `protoc` compiles it and the door declares the same tree from these
    /// roots (full names, package included, no leading dot) -- the cases whose
    /// schema holds an `extend` or a `group`, where the door refuses some roots.
    AgreeFrom(&'static [&'static str]),
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

/// A schema of `levels` messages written inside one another, the first a
/// message and every other a group of the one before.
fn grouped(levels: usize) -> String {
    let mut s = String::from("syntax = \"proto2\";\nmessage M0 {\n");
    for i in 1..levels {
        s.push_str(&format!("optional group G{i} = 1 {{\n"));
    }
    for _ in 0..levels {
        s.push_str("}\n");
    }
    s
}

/// `Base` takes extensions; `M` holds an `extend` of it and is not itself
/// extended; `Other` reaches `M`. From `M` or `Other` the door reaches nothing
/// extended, and from `Base` it does.
const EXTEND_IN_A_MESSAGE: &str =
    "syntax = \"proto2\";\nmessage Base {\n  optional int32 a = 1;\n  extensions 100 to 199;\n}\n\
    message M {\n  optional int32 m = 1;\n  extend Base {\n    optional int32 x = 100;\n  }\n}\n\
    message Other {\n  optional M inner = 1;\n}\n";

/// A message `Holder` with a group `G`, and three roots: `Root` reaches
/// neither, `Reaches` reaches `Holder`, and `Uses` reaches only the group's
/// message `Holder.G`.
const GROUPS: &str = "syntax = \"proto2\";\n\
    message Root {\n  optional int32 a = 1;\n}\n\
    message Holder {\n  optional int32 b = 1;\n  optional group G = 2 {\n    optional int32 x = 1;\n  }\n}\n\
    message Reaches {\n  optional Holder h = 1;\n}\n\
    message Uses {\n  optional Holder.G g = 1;\n}\n";

/// `b.Base` takes extensions, `ext.proto` extends it, and the root file reads
/// both and holds it four ways: through a field, a nested message's field, a
/// map's value, and not at all (`Unrelated`).
const REACH_FILES: [(&str, &str); 3] = [
    (
        "app.proto",
        "syntax = \"proto2\";\npackage app;\nimport \"base.proto\";\nimport \"ext.proto\";\n\
         message Direct { optional b.Base base = 1; }\n\
         message Unrelated { optional int32 n = 1; }\n\
         message ViaNested { optional Mid mid = 1; message Mid { repeated b.Base bases = 1; } }\n\
         message ViaMap { map<string, b.Base> by_name = 1; }\n",
    ),
    (
        "base.proto",
        "syntax = \"proto2\";\npackage b;\nmessage Base {\n  optional int32 a = 1;\n  extensions 100 to 199;\n}\n",
    ),
    (
        "ext.proto",
        "syntax = \"proto2\";\nimport \"base.proto\";\n\nextend b.Base {\n  optional int32 x = 100;\n}\n",
    ),
];

/// The shape of the schema that exposed the defect: a root file that imports a
/// public options file, which imports `descriptor.proto` and adds an option to
/// `google.protobuf.FieldOptions` with an `extend`. `descriptor.proto` here is a
/// stand-in that holds only what the extend needs; the real one is used by
/// [`descriptor_cases`].
const STANDIN_FILES: [(&str, &str); 3] = [
    (
        "app.proto",
        "syntax = \"proto3\";\npackage app;\nimport \"fieldopts/options.proto\";\n\
         message Sensor {\n  int32 id = 1;\n  Meta meta = 2;\n  message Meta { string unit = 1; }\n}\n",
    ),
    (
        "fieldopts/options.proto",
        "syntax = \"proto2\";\npackage fieldopts;\nimport \"google/protobuf/descriptor.proto\";\n\
         message Options {\n  optional int32 max_size = 1;\n  optional bool fixed = 2;\n}\n\
         extend google.protobuf.FieldOptions {\n  optional Options opts = 1010;\n}\n",
    ),
    (
        "google/protobuf/descriptor.proto",
        "syntax = \"proto2\";\npackage google.protobuf;\nmessage FieldOptions {\n  optional bool packed = 2;\n  \
         extensions 1000 to max;\n}\n",
    ),
];

/// The two schemas whose depth is the question: written inside one another.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Nesting {
    Messages,
    Groups,
}

/// How a schema written `depth` levels deep is judged, from what each side does
/// with it. The door reads up to [`DOOR_NESTING`] levels; `protoc` reads up to
/// `protoc_deepest`, which is the probe's answer and differs between releases
/// (31 for 3.21.12, more for 3.12.4). Nothing here is a statement about one
/// release:
///
/// * both read it: messages agree, and a group is refused on purpose, because
///   the message that holds it is the root;
/// * only the door refuses it, for the depth: a deliberate refusal;
/// * only `protoc` refuses it: a non-validation (it is not a validator);
/// * both refuse it: an agreement about the blame.
fn depth_expect(shape: Nesting, depth: usize, protoc_deepest: usize) -> Expect {
    let protoc_compiles = depth <= protoc_deepest;
    let door_reads = depth <= DOOR_NESTING;
    match (shape, protoc_compiles, door_reads) {
        (Nesting::Messages, true, true) => Expect::Agree,
        (Nesting::Messages, false, true) => Expect::DoorAccepts("M0"),
        (Nesting::Groups, true, true) => {
            Expect::DoorRefuses("M0", "group fields are not supported")
        }
        (_, true, false) => Expect::DoorRefuses("M0", "nested more than"),
        (_, false, _) => Expect::BothRefuse,
    }
}

fn corpus(judge: &Judge) -> Vec<Case> {
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
        // The door's nesting bound from the inside: its 31st level. What protoc
        // does at that depth is measured, not written here.
        one(
            "messages written 31 deep, the door's last level",
            depth_expect(Nesting::Messages, DOOR_NESTING, judge.deepest_message),
            &nested(DOOR_NESTING),
        ),
        one("a message with three hundred fields", Agree, &{
            let mut s = String::from("syntax = \"proto3\";\nmessage Wide {\n");
            for i in 1..=300 {
                s.push_str(&format!("  int32 field_{i} = {i};\n"));
            }
            s.push_str("}\n");
            s
        }),
        // ---- an extend or a group the root never reaches: protoc compiles it and
        // ---- the door declares the tree its descriptor implies -----------------
        case(
            "an options file extending a descriptor message, imported and never reached",
            AgreeFrom(&["app.Sensor", "fieldopts.Options"]),
            &STANDIN_FILES,
        ),
        one(
            "an extend written inside a message, from roots that do not reach the extended one",
            AgreeFrom(&["M", "Other"]),
            EXTEND_IN_A_MESSAGE,
        ),
        case(
            "an extend whose extended message the root does not reach",
            AgreeFrom(&["app.Unrelated"]),
            &REACH_FILES,
        ),
        one(
            "a group in a message the root does not reach, and the group's own message",
            AgreeFrom(&["Root", "Uses", "Holder.G"]),
            GROUPS,
        ),
        one(
            "a group declared by an extension",
            AgreeFrom(&["Root", "G"]),
            "syntax = \"proto2\";\nmessage Base {\n  optional int32 a = 1;\n  extensions 100 to 199;\n}\n\
             extend Base {\n  optional group G = 100 {\n    optional int32 q = 1;\n  }\n}\n\
             message Root { optional G g = 1; }\n",
        ),
        one(
            "an extendee found from the innermost scope that has its name",
            AgreeFrom(&["RootTop"]),
            "syntax = \"proto2\";\n\
             message Inner { optional int32 top = 1; extensions 100 to 199; }\n\
             message Outer {\n  message Inner { optional int32 deep = 1; extensions 100 to 199; }\n  extend Inner { optional int32 x = 100; }\n}\n\
             message RootTop { optional Inner i = 1; }\n",
        ),
        case(
            "an extend block in proto3, where no label is needed",
            AgreeFrom(&["M"]),
            &[
                (
                    "app.proto",
                    "syntax = \"proto3\";\nimport \"google/protobuf/descriptor.proto\";\n\
                     message M { int32 a = 1; }\n\
                     extend google.protobuf.FieldOptions {\n  string tag = 50000;\n  optional int32 level = 50001;\n  repeated int32 levels = 50002;\n}\n",
                ),
                STANDIN_FILES[2],
            ],
        ),
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
        // ... and from the outside: the door's 32nd level is refused. protoc 3.21
        // refuses it too and names no line for it; protoc 3.12.4 compiles it,
        // and then it is a deliberate refusal.
        one(
            "messages written 32 deep, the door's first refusal",
            depth_expect(Nesting::Messages, DOOR_NESTING + 1, judge.deepest_message),
            &nested(DOOR_NESTING + 1),
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
        // ---- extend and group are read for their syntax, so a mistake in one is
        // ---- blamed where protoc blames it, whatever the root reaches ---------
        one(
            "an empty extend block",
            BothRefuse,
            "syntax = \"proto2\";\nmessage Base { extensions 100 to 199; }\nextend Base {\n}\n",
        ),
        one(
            "an extend block's field missing its semicolon",
            BothRefuse,
            "syntax = \"proto2\";\nmessage Base { extensions 100 to 199; }\nextend Base {\n  optional int32 x = 100\n}\n",
        ),
        one(
            "a stray semicolon in an extend block",
            BothRefuse,
            "syntax = \"proto2\";\nmessage Base { extensions 100 to 199; }\nextend Base {\n  optional int32 x = 100;\n  ;\n}\n",
        ),
        one(
            "an extend block with no label in proto2",
            BothRefuse,
            "syntax = \"proto2\";\nmessage Base { extensions 100 to 199; }\nextend Base {\n  int32 x = 100;\n}\n",
        ),
        one(
            "an extend of a scalar type",
            BothRefuse,
            "syntax = \"proto2\";\nextend int32 {\n  optional int32 x = 100;\n}\n",
        ),
        one(
            "a map in an extend block",
            BothRefuse,
            "syntax = \"proto2\";\nmessage Base { extensions 100 to 199; }\nextend Base {\n  map<string, int32> m = 100;\n}\n",
        ),
        one(
            "an extend block never closed",
            BothRefuse,
            "syntax = \"proto2\";\nmessage Base { extensions 100 to 199; }\nextend Base {\n  optional int32 x = 100;\n",
        ),
        one(
            "an extendee that is not defined, written on its own line",
            BothRefuse,
            "syntax = \"proto2\";\nmessage M { optional int32 a = 1; }\nextend\n    Missing.Name {\n  optional int32 x = 100;\n}\n",
        ),
        one(
            "an absolute extendee that is not defined",
            BothRefuse,
            "syntax = \"proto2\";\nmessage M { optional int32 a = 1; }\nextend .nowhere.T {\n  optional int32 x = 100;\n}\n",
        ),
        one(
            "an extendee that is an enum",
            BothRefuse,
            "syntax = \"proto2\";\nenum E { Z = 0; }\nmessage M { optional int32 a = 1; }\nextend E {\n  optional int32 x = 100;\n}\n",
        ),
        one(
            "an extendee found as a field first",
            BothRefuse,
            "syntax = \"proto2\";\nmessage Base { extensions 100 to 199; }\nmessage M {\n  optional int32 Base = 1;\n  extend Base { optional int32 x = 100; }\n}\n",
        ),
        case(
            "an extendee defined in a file that is imported only by an import",
            BothRefuse,
            &[
                (
                    "a.proto",
                    "syntax = \"proto2\";\nimport \"mid.proto\";\nmessage M { optional int32 a = 1; }\nextend b.Base {\n  optional int32 x = 100;\n}\n",
                ),
                ("mid.proto", "syntax = \"proto2\";\nimport \"base.proto\";\n"),
                REACH_FILES[1],
            ],
        ),
        one(
            "a group in proto3",
            BothRefuse,
            "syntax = \"proto3\";\nmessage M {\n  optional group G = 1 { }\n}\n",
        ),
        one(
            "a group with a lower case name",
            BothRefuse,
            "syntax = \"proto2\";\nmessage M {\n  optional group g = 1 { }\n}\n",
        ),
        one(
            "a group with no body",
            BothRefuse,
            "syntax = \"proto2\";\nmessage M {\n  optional group G = 1;\n}\n",
        ),
        one(
            "a group with no label in proto2",
            BothRefuse,
            "syntax = \"proto2\";\nmessage M {\n  group G = 1 { }\n}\n",
        ),
        one(
            "a group whose field name clashes with another field",
            BothRefuse,
            "syntax = \"proto2\";\nmessage M {\n  optional group Gr = 1 { optional int32 x = 1; }\n  optional int32 gr = 2;\n}\n",
        ),
        one(
            "a syntax error inside a group's body",
            BothRefuse,
            "syntax = \"proto2\";\nmessage M {\n  optional group G = 1 {\n    optional int32 x = 1\n  }\n}\n",
        ),
        // The group's body is a message to the nesting limit, so a group chain
        // is refused for its depth one level past the door's bound, and for the
        // group itself at the bound; which of these protoc agrees with is its
        // own limit, measured.
        one(
            "groups written 32 deep, the door's first refusal",
            depth_expect(Nesting::Groups, DOOR_NESTING + 1, judge.deepest_group),
            &grouped(DOOR_NESTING + 1),
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
        // The extended message, as the root: written inside another message,
        // the block extends `Base` and not the message it sits in.
        one(
            "an extend block inside a message, from the message it extends",
            DoorRefuses("Base", "`extend` is not supported"),
            EXTEND_IN_A_MESSAGE,
        ),
        one(
            "a group reached through a field",
            DoorRefuses("Reaches", "group fields are not supported"),
            GROUPS,
        ),
        one(
            "a group in a oneof",
            DoorRefuses("R", "group fields are not supported"),
            "syntax = \"proto2\";\nmessage R {\n  oneof o {\n    group G = 1 { optional int32 x = 1; }\n    int32 y = 2;\n  }\n}\n",
        ),
        one(
            "groups written 31 deep, the door's last level",
            depth_expect(Nesting::Groups, DOOR_NESTING, judge.deepest_group),
            &grouped(DOOR_NESTING),
        ),
        case(
            "an extend reached through a field",
            DoorRefuses("app.Direct", "`extend` is not supported"),
            &REACH_FILES,
        ),
        case(
            "an extend reached through a nested message's field",
            DoorRefuses("app.ViaNested", "`extend` is not supported"),
            &REACH_FILES,
        ),
        case(
            "an extend reached through a map's value",
            DoorRefuses("app.ViaMap", "`extend` is not supported"),
            &REACH_FILES,
        ),
        case(
            "an extend whose extendee is visible through a public import chain",
            DoorRefuses("app.Direct", "`extend` is not supported"),
            &[
                REACH_FILES[0],
                REACH_FILES[1],
                (
                    "ext.proto",
                    "syntax = \"proto2\";\nimport \"front.proto\";\n\nextend b.Base {\n  optional int32 x = 100;\n}\n",
                ),
                (
                    "front.proto",
                    "syntax = \"proto2\";\nimport public \"base.proto\";\n",
                ),
            ],
        ),
        case(
            "an options file's extend, from the message it extends",
            DoorRefuses("google.protobuf.FieldOptions", "`extend` is not supported"),
            &STANDIN_FILES,
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
        // The fields of an extend block are read for their syntax and not judged.
        one(
            "an extension number outside every extension range",
            DoorAccepts("M"),
            "syntax = \"proto3\";\nmessage M { int32 a = 1; }\nmessage Base { }\nextend Base { string foo = 50000; }\n",
        ),
        one(
            "an extension field of a type that is not defined",
            DoorAccepts("M"),
            "syntax = \"proto2\";\nmessage M { optional int32 a = 1; }\nmessage Base { extensions 100 to 199; }\nextend Base { optional Missing m = 100; }\n",
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

/// Where `descriptor.proto` is installed when it is not beside the judge: the
/// Debian package `libprotobuf-dev` (the one the armed lane installs, and the
/// comment on the skip rule names) and a local protobuf install.
const DESCRIPTOR_PROTO: &[&str] = &[
    "/usr/include/google/protobuf/descriptor.proto",
    "/usr/local/include/google/protobuf/descriptor.proto",
];

/// The `descriptor.proto` of the judge's own release, as text: the one beside
/// its binary (`<bin>/../include`, where `protoc` itself looks first for its
/// imports and for `--decode`, and where a package unpacked with `dpkg -x`
/// puts it), else an installed one. The two must be the same file or the cases
/// that feed it to the door would describe a different release than the one
/// judging them.
fn descriptor_proto_text(judge: &Judge) -> Result<String, String> {
    let beside = judge
        .bin
        .parent()
        .map(|dir| dir.join("../include/google/protobuf/descriptor.proto"));
    let fixed = DESCRIPTOR_PROTO.iter().map(PathBuf::from);
    beside
        .into_iter()
        .chain(fixed)
        .find_map(|path| std::fs::read_to_string(path).ok())
        .ok_or_else(|| {
            format!(
                "no descriptor.proto beside {} or at any of {DESCRIPTOR_PROTO:?}",
                judge.bin.display()
            )
        })
}

/// The cases that feed the REAL `google/protobuf/descriptor.proto` to the door
/// as one file of the schema, beside the options file of [`STANDIN_FILES`]
/// extending its `FieldOptions` -- the shape of the schema that exposed the
/// defect, with the file an actual schema imports.
///
/// They are built apart from [`corpus`] because the text is read from the
/// machine, and a machine without it is the skip the armed lane turns into a
/// failure. `Err` says why there is no such file.
fn descriptor_cases(judge: &Judge) -> Result<Vec<Case>, String> {
    use Expect::*;
    let descriptor = descriptor_proto_text(judge)?;
    // The schema uses the option the options file adds, which protoc can check
    // only against the real file: an option's extendee must declare
    // `uninterpreted_option`, which the stand-in does not.
    let app = "syntax = \"proto3\";\npackage app;\nimport \"fieldopts/options.proto\";\n\
               message Sensor {\n  int32 id = 1;\n  string label = 2 [(fieldopts.opts).max_size = 16];\n  \
               Meta meta = 3;\n  message Meta { string unit = 1; }\n}\n";
    let files = [
        ("app.proto", app),
        STANDIN_FILES[1],
        ("google/protobuf/descriptor.proto", descriptor.as_str()),
    ];
    Ok(vec![
        case(
            "the real descriptor.proto and an options file extending its FieldOptions, from roots that do not reach it",
            AgreeFrom(&[
                "app.Sensor",
                "fieldopts.Options",
                "google.protobuf.UninterpretedOption",
                "google.protobuf.SourceCodeInfo",
                "google.protobuf.GeneratedCodeInfo",
                "google.protobuf.EnumDescriptorProto",
                "google.protobuf.ServiceDescriptorProto",
                "google.protobuf.FileOptions",
                "google.protobuf.DescriptorProto.ExtensionRange",
            ]),
            &files,
        ),
        case(
            "the real descriptor.proto, from the root that holds a FieldOptions",
            DoorRefuses("google.protobuf.FieldDescriptorProto", "`extend` is not supported"),
            &files,
        ),
        case(
            "the real descriptor.proto, from the whole descriptor set",
            DoorRefuses("google.protobuf.FileDescriptorSet", "`extend` is not supported"),
            &files,
        ),
    ])
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
    let judge = protoc().and_then(|(bin, version)| measure_judge(bin, version));
    let judge = match judge {
        Ok(j) => j,
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
    let mut corpus = corpus(&judge);
    let from_descriptor = match descriptor_cases(&judge) {
        Ok(cases) => {
            let n = cases.len();
            corpus.extend(cases);
            n
        }
        Err(why) if required => panic!(
            "WZ_PROTOC_REQUIRE is set and the real descriptor.proto cannot be read: {why}. \
             The cases that feed it to the door are the ones that reproduce the defect with \
             the file a real schema imports"
        ),
        Err(why) => {
            eprintln!(
                "skip: {why}; the cases that feed the real descriptor.proto to the door did not \
                 run, and WZ_PROTOC_REQUIRE=1 makes that a failure"
            );
            0
        }
    };
    let mut names: Vec<&str> = corpus.iter().map(|c| c.name.as_str()).collect();
    names.sort_unstable();
    let before = names.len();
    names.dedup();
    assert_eq!(before, names.len(), "two corpus cases share a name");

    for case in &corpus {
        let dir = tempfile::tempdir().expect("tempdir for the schemas");
        write_case(dir.path(), case);
        let root_file = &case.files[0].0;
        let compiled = match judge.compile(dir.path(), root_file) {
            Ok(c) => c,
            Err(e) => panic!("{}: {e}", case.name),
        };
        let say = |what: String| format!("[{}] {what}", case.name);

        match &case.expect {
            Expect::Agree | Expect::AgreeFrom(_) => {
                let Some(text) = &compiled.descriptor_text else {
                    disagreements.push(say(format!(
                        "the corpus is wrong: protoc refused a schema marked Agree:\n{}",
                        compiled.stderr
                    )));
                    continue;
                };
                let set = read_text(text).expect("protoc's own output reads");
                let msgs = collect(&set);
                let named: Vec<String> = match &case.expect {
                    Expect::AgreeFrom(roots) => roots.iter().map(|r| format!(".{r}")).collect(),
                    _ => Vec::new(),
                };
                if let Some(missing) = named.iter().find(|r| !msgs.contains_key(*r)) {
                    disagreements.push(say(format!(
                        "the corpus is wrong: {missing} is not a message protoc compiled"
                    )));
                    continue;
                }
                // The roots a case names, or else every message the schema
                // defines, nested ones and ones in imported files included.
                let candidates: Vec<&String> = if named.is_empty() {
                    msgs.iter()
                        .filter(|(_, m)| !m.map_entry && !m.file.starts_with("google/"))
                        .map(|(name, _)| name)
                        .collect()
                } else {
                    named.iter().collect()
                };
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
         refusal(s), {unchecked} non-validation(s); {from_descriptor} case(s) feed the real \
         descriptor.proto"
    );
    // WHOSE OPINION IT WAS, and the facts measured from it that the corpus was
    // decided by -- on the line a red run is read from.
    eprintln!(
        "judge: {}; proto3 optional {}; deepest nesting compiled: {} message level(s), \
         {} group level(s) (cap {DEPTH_CAP}); the door reads {DOOR_NESTING}",
        judge.version,
        if judge.needs_proto3_optional_flag {
            "needs --experimental_allow_proto3_optional"
        } else {
            "needs no flag"
        },
        judge.deepest_message,
        judge.deepest_group,
    );
    assert!(
        schemas >= 20 && roots >= 40 && blamed >= 40 && purposeful >= 8 && unchecked >= 3,
        "the corpus no longer exercises each arm: {schemas}/{roots}/{blamed}/{purposeful}/{unchecked}"
    );
    assert!(
        !required || from_descriptor >= 3,
        "an armed run must have fed the real descriptor.proto to the door: {from_descriptor}"
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

/// A judge that was not measured, for the controls: one that nests `deepest`
/// levels of either kind and needs no flag.
fn assumed_judge(deepest: usize) -> Judge {
    Judge {
        bin: PathBuf::from("protoc"),
        version: "assumed".to_string(),
        needs_proto3_optional_flag: false,
        deepest_message: deepest,
        deepest_group: deepest,
        writes_negative_zero: true,
    }
}

#[test]
fn the_corpus_names_each_case_once_and_covers_each_arm() {
    // The corpus is decided by the judge, so it is held to its arms and to unique
    // names for a judge that stops at the door's depth (protoc 3.21) and for one
    // that goes far past it (protoc 3.12.4).
    for deepest in [DOOR_NESTING, DEPTH_CAP] {
        let corpus = corpus(&assumed_judge(deepest));
        let count = |f: fn(&Expect) -> bool| corpus.iter().filter(|c| f(&c.expect)).count();
        assert!(count(|e| matches!(e, Expect::Agree)) >= 20);
        assert!(count(|e| matches!(e, Expect::AgreeFrom(_))) >= 6);
        assert!(count(|e| matches!(e, Expect::BothRefuse)) >= 40);
        assert!(count(|e| matches!(e, Expect::DoorRefuses(..))) >= 8);
        assert!(count(|e| matches!(e, Expect::DoorAccepts(_))) >= 3);
        let mut names: Vec<&str> = corpus.iter().map(|c| c.name.as_str()).collect();
        names.sort_unstable();
        let before = names.len();
        names.dedup();
        assert_eq!(before, names.len(), "two corpus cases share a name");
        for case in &corpus {
            assert!(!case.files.is_empty(), "{} has no file", case.name);
        }
    }
}

/// THE DEPTH PROBE FINDS THE LIMIT IT IS HANDED, whatever it is. A probe that
/// answered one fixed number would be right on the release it was written
/// against and wrong on every other, which is how the hosted run went red.
#[test]
fn the_depth_probe_finds_the_deepest_level_a_judge_compiles() {
    for limit in [0, 1, 2, 31, 32, 33, 100, DEPTH_CAP - 1, DEPTH_CAP] {
        let mut asked = 0;
        let found = deepest(DEPTH_CAP, &mut |n| {
            asked += 1;
            Ok(n <= limit)
        })
        .expect("a probe over a plain predicate");
        assert_eq!(found, limit, "a judge that stops after {limit} levels");
        // Bisection: a handful of runs, never one per level.
        assert!(asked <= 8, "{asked} compilations to find {limit}");
    }
    // No limit below the cap is reported as the cap.
    assert_eq!(deepest(DEPTH_CAP, &mut |_| Ok(true)), Ok(DEPTH_CAP));
    // An infrastructure failure is the probe's failure, not a depth.
    assert_eq!(
        deepest(DEPTH_CAP, &mut |_| Err("no protoc".to_string())),
        Err("no protoc".to_string())
    );
}

/// THE PROTO3-OPTIONAL FLAG IS DECIDED BY WHAT PROTOC SAYS, not by which
/// release it is. The refusal text is protoc 3.12.4's own, as the hosted run
/// printed it.
#[test]
fn the_proto3_optional_flag_follows_what_protoc_says_without_it() {
    let said = |ok, stderr: &str| Compiled {
        ok,
        stderr: stderr.to_string(),
        descriptor_text: None,
    };
    assert_eq!(proto3_optional_flag_needed(&said(true, "")), Ok(false));
    assert_eq!(
        proto3_optional_flag_needed(&said(
            false,
            "a.proto: This file contains proto3 optional fields, but \
             --experimental_allow_proto3_optional was not set.\n"
        )),
        Ok(true)
    );
    // Any other refusal is not the flag's business.
    let other = proto3_optional_flag_needed(&said(false, "a.proto:2:1: Expected \";\".\n"));
    assert!(other.is_err(), "{other:?}");
}

/// THE DESCRIPTOR FED TO THE DOOR IS THE JUDGE'S OWN: the file beside the
/// binary wins over an installed one, so a `protoc` unpacked from a package is
/// judged with the `descriptor.proto` of its release and not of the machine's.
#[test]
fn the_descriptor_proto_beside_the_judge_is_the_one_fed_to_the_door() {
    let dir = tempfile::tempdir().expect("tempdir");
    let include = dir.path().join("usr/include/google/protobuf");
    std::fs::create_dir_all(&include).expect("create the include directory");
    // The binary's directory exists, as it does for a real package: `..` is only
    // resolved through a directory that is there.
    std::fs::create_dir_all(dir.path().join("usr/bin")).expect("create the bin directory");
    std::fs::write(include.join("descriptor.proto"), "// the judge's own\n").expect("write it");
    let mut judge = assumed_judge(DOOR_NESTING);
    judge.bin = dir.path().join("usr/bin/protoc");
    assert_eq!(
        descriptor_proto_text(&judge).as_deref(),
        Ok("// the judge's own\n")
    );
    // With nothing beside it the installed one is used, or the answer says where
    // it looked; either way it is not the file of the judge above.
    judge.bin = dir.path().join("elsewhere/bin/protoc");
    match descriptor_proto_text(&judge) {
        Ok(text) => assert_ne!(text, "// the judge's own\n"),
        Err(why) => assert!(why.contains("no descriptor.proto beside"), "{why}"),
    }
}

/// THE DEPTH CASES ARE DECIDED BY THE JUDGE'S LIMIT AND THE DOOR'S, never by a
/// number written into the corpus: the whole table, for a judge that stops
/// before the door, at it, past it and far past it.
#[test]
fn a_depth_case_is_decided_by_what_each_side_reads() {
    use Nesting::*;
    let kind = |e: &Expect| match e {
        Expect::Agree => "agree".to_string(),
        Expect::BothRefuse => "both refuse".to_string(),
        Expect::DoorAccepts(_) => "door accepts".to_string(),
        Expect::DoorRefuses(_, reason) => format!("door refuses: {reason}"),
        Expect::AgreeFrom(_) => "agree from".to_string(),
    };
    let door = DOOR_NESTING;
    // protoc 3.21: stops at the door's depth.
    assert_eq!(kind(&depth_expect(Messages, door, door)), "agree");
    assert_eq!(kind(&depth_expect(Messages, door + 1, door)), "both refuse");
    assert_eq!(
        kind(&depth_expect(Groups, door, door)),
        "door refuses: group fields are not supported"
    );
    assert_eq!(kind(&depth_expect(Groups, door + 1, door)), "both refuse");
    // protoc 3.12.4: reads past the door's depth, so the door's refusal is its own.
    assert_eq!(kind(&depth_expect(Messages, door, 100)), "agree");
    assert_eq!(
        kind(&depth_expect(Messages, door + 1, 100)),
        "door refuses: nested more than"
    );
    assert_eq!(
        kind(&depth_expect(Groups, door + 1, 100)),
        "door refuses: nested more than"
    );
    // A protoc that stops BEFORE the door's depth refuses what the door reads.
    assert_eq!(
        kind(&depth_expect(Messages, door, door - 1)),
        "door accepts"
    );
    assert_eq!(kind(&depth_expect(Groups, door, door - 1)), "both refuse");
    // The corpus carries the table: the same four cases, different expectations.
    let name = "messages written 32 deep, the door's first refusal";
    let expect_of = |deepest| {
        corpus(&assumed_judge(deepest))
            .into_iter()
            .find(|c| c.name == name)
            .map(|c| kind(&c.expect))
    };
    assert_eq!(expect_of(door).as_deref(), Some("both refuse"));
    assert_eq!(
        expect_of(DEPTH_CAP).as_deref(),
        Some("door refuses: nested more than")
    );
}

/// THE DOOR'S OWN BOUND IS THE ONE THIS FILE SAYS: 31 levels read, the 32nd
/// refused, for messages and for groups. Without protoc, so the number the
/// depth cases are built around cannot drift from the door unseen.
#[test]
fn the_door_reads_the_nesting_this_file_says_it_does() {
    let files = |text: String| vec![("a.proto".to_string(), text)];
    let door = call_door("M0", &files(nested(DOOR_NESTING)));
    assert!(door.ok, "{}", door.reason);
    let door = call_door("M0", &files(nested(DOOR_NESTING + 1)));
    assert!(
        !door.ok && door.reason.contains("nested more than"),
        "{door:?}"
    );
    // A group chain reads to the same depth, and is then refused for the group
    // it holds; one level past it, for the depth.
    let door = call_door("M0", &files(grouped(DOOR_NESTING)));
    assert!(
        !door.ok && door.reason.contains("group fields are not supported"),
        "{door:?}"
    );
    let door = call_door("M0", &files(grouped(DOOR_NESTING + 1)));
    assert!(
        !door.ok && door.reason.contains("nested more than"),
        "{door:?}"
    );
}

// ---- the value door: `wz_dissect_proto_encode`, judged by `protoc --encode` ----
//
// The value door writes the wire bytes of a message from JSON field values. Its
// unit tests were written by the person who wrote the writer, from the encoding
// guide, so they agree with that person's idea of the format. `protoc --encode`
// is the format's own writer: it reads the same message as TEXT FORMAT and
// writes the bytes, and the door's bytes for the same message must be the same
// bytes. The two inputs are different notations of one message, written side by
// side in each case (`values` for the door, `text` for protoc), so a case that
// is wrong in one notation shows as a difference rather than as agreement.
//
// What is compared is the bytes and nothing else. Map entries are the one place
// the format leaves the order to the writer, so a case that holds several marks
// itself `unordered` and is compared as the set of top-level fields `protoc
// --decode` prints for each side; every other case must match byte for byte.
//
// The door refuses what protoc has no counterpart for (a JSON value of the wrong
// type, a key that is no field), and a refusal is not a thing a text format can
// be compared on, so those are the unit tests' and not this corpus's.

/// A message in two notations.
struct ValueCase {
    name: &'static str,
    /// `(file name, text)`; the first is the root file.
    files: Vec<(&'static str, &'static str)>,
    root: &'static str,
    /// What the door reads.
    values: &'static str,
    /// What `protoc --encode` reads: the same message in text format.
    text: &'static str,
    /// Whether the order of the top-level fields on the wire is the writer's to
    /// choose (several map entries).
    unordered: bool,
    /// For a case whose bytes depend on how the judge treats `-0.0`: the door's
    /// documented bytes (hex), and the bytes (hex) a judge that omits `-0.0`
    /// writes for the same message. The door's bytes are held to the first
    /// whatever the judge does; the judge is held to the second only when it was
    /// MEASURED to omit `-0.0` ([`Judge::writes_negative_zero`]).
    negative_zero: Option<NegativeZero>,
}

/// The two expectations of a case that depends on the judge's `-0.0`.
#[derive(Clone, Copy)]
struct NegativeZero {
    door_hex: &'static str,
    judge_omitting_hex: &'static str,
}

fn value_case(
    name: &'static str,
    schema: &'static str,
    root: &'static str,
    values: &'static str,
    text: &'static str,
) -> ValueCase {
    ValueCase {
        name,
        files: vec![("a.proto", schema)],
        root,
        values,
        text,
        unordered: false,
        negative_zero: None,
    }
}

/// The corpus of messages, each in the door's notation and in text format.
fn value_corpus() -> Vec<ValueCase> {
    let mut v = vec![
        // The protobuf encoding guide's examples.
        value_case(
            "the guide's varint 150",
            "syntax = \"proto3\";\nmessage M { int32 a = 1; }",
            "M",
            r#"{"a":150}"#,
            "a: 150",
        ),
        value_case(
            "the guide's string testing",
            "syntax = \"proto3\";\nmessage M { string b = 2; }",
            "M",
            r#"{"b":"testing"}"#,
            "b: \"testing\"",
        ),
        value_case(
            "the guide's nested message",
            "syntax = \"proto3\";\nmessage T1 { int32 a = 1; } message M { T1 c = 3; }",
            "M",
            r#"{"c":{"a":150}}"#,
            "c { a: 150 }",
        ),
        value_case(
            "the guide's packed run",
            "syntax = \"proto2\";\nmessage M { repeated int32 d = 4 [packed=true]; }",
            "M",
            r#"{"d":[3,270,86942]}"#,
            "d: 3 d: 270 d: 86942",
        ),
        // Integers.
        value_case(
            "negative int32 and int64 are ten bytes",
            "syntax = \"proto3\";\nmessage M { int32 a = 1; int64 b = 2; }",
            "M",
            r#"{"a":-1,"b":"-9223372036854775808"}"#,
            "a: -1 b: -9223372036854775808",
        ),
        value_case(
            "sint32 and sint64 are zigzag",
            "syntax = \"proto3\";\nmessage M { sint32 a = 1; sint64 b = 2; sint32 c = 3; sint32 d = 4; }",
            "M",
            r#"{"a":-1,"b":"-2","c":2147483647,"d":-2147483648}"#,
            "a: -1 b: -2 c: 2147483647 d: -2147483648",
        ),
        value_case(
            "unsigned and large 64-bit values keep every bit",
            "syntax = \"proto3\";\nmessage M { uint32 a = 1; uint64 b = 2; int64 c = 3; }",
            "M",
            r#"{"a":4294967295,"b":"18446744073709551615","c":9007199254740993}"#,
            "a: 4294967295 b: 18446744073709551615 c: 9007199254740993",
        ),
        value_case(
            "fixed width integers are little endian",
            "syntax = \"proto3\";\nmessage M { fixed32 a = 1; sfixed32 b = 2; fixed64 c = 3; sfixed64 d = 4; }",
            "M",
            r#"{"a":1,"b":-1,"c":"18446744073709551615","d":"-2"}"#,
            "a: 1 b: -1 c: 18446744073709551615 d: -2",
        ),
        // Floats.
        value_case(
            "float and double values",
            "syntax = \"proto3\";\nmessage M { float a = 1; double b = 2; float c = 3; double d = 4; }",
            "M",
            r#"{"a":1.5,"b":-2.25,"c":0.1,"d":0.1}"#,
            "a: 1.5 b: -2.25 c: 0.1 d: 0.1",
        ),
        value_case(
            "the largest float and a double beyond it",
            "syntax = \"proto3\";\nmessage M { float a = 1; double b = 2; }",
            "M",
            // The largest float written out in full: protoc's text parser reads a
            // float through a double and a release may turn a double above the
            // largest float into infinity, so the shortest spelling that rounds
            // to it (3.4028235e38) is not a safe input for every judge.
            r#"{"a":3.4028234663852886e38,"b":1e300}"#,
            "a: 3.4028234663852886e38 b: 1e300",
        ),
        value_case(
            "not-a-number and the infinities",
            "syntax = \"proto3\";\nmessage M { float a = 1; double b = 2; double c = 3; }",
            "M",
            r#"{"a":"NaN","b":"Infinity","c":"-Infinity"}"#,
            "a: nan b: inf c: -inf",
        ),
        // The one case whose bytes depend on the judge: `-0.0` is not the default
        // by its bits, and protoc 3.12.4 tests the value against zero instead. The
        // door writes it either way (see `the_value_door_writes_negative_zero_by_bits`).
        ValueCase {
            negative_zero: Some(NegativeZero {
                door_hex: NEGATIVE_ZERO_DOOR_HEX,
                judge_omitting_hex: "",
            }),
            ..value_case(
                "negative zero is written and zero is not",
                "syntax = \"proto3\";\nmessage M { float a = 1; double b = 2; float c = 3; double d = 4; }",
                "M",
                r#"{"a":-0.0,"b":-0.0,"c":0.0,"d":0.0}"#,
                "a: -0.0 b: -0.0 c: 0.0 d: 0.0",
            )
        },
        // Other scalars.
        value_case(
            "bool, string and bytes",
            "syntax = \"proto3\";\nmessage M { bool a = 1; string b = 2; bytes c = 3; }",
            "M",
            r#"{"a":true,"b":"h\u00e9 \ud83d\ude00","c":"AQL/"}"#,
            "a: true b: \"h\\303\\251 \\360\\237\\230\\200\" c: \"\\001\\002\\377\"",
        ),
        value_case(
            "proto3 fields at their defaults are not written",
            "syntax = \"proto3\";\nmessage M { int32 a = 1; string b = 2; bytes c = 3; bool d = 4; double e = 5; float f = 6; }",
            "M",
            r#"{"a":0,"b":"","c":"","d":false,"e":0,"f":0}"#,
            "a: 0 b: \"\" c: \"\" d: false e: 0 f: 0",
        ),
        // Enums.
        value_case(
            "an enum by name, by number and a negative one",
            "syntax = \"proto3\";\nenum E { Z = 0; ONE = 1; NEG = -1; }\nmessage M { E a = 1; E b = 2; E c = 3; E d = 4; }",
            "M",
            r#"{"a":"ONE","b":1,"c":"NEG","d":"Z"}"#,
            "a: ONE b: 1 c: NEG d: Z",
        ),
        // Presence.
        value_case(
            "a oneof member at its default is written",
            "syntax = \"proto3\";\nmessage M { oneof pick { int32 a = 1; string b = 2; } }",
            "M",
            r#"{"a":0}"#,
            "a: 0",
        ),
        value_case(
            "a proto3 optional at its default is written",
            "syntax = \"proto3\";\nmessage M { optional int32 a = 1; optional string b = 2; int32 c = 3; }",
            "M",
            r#"{"a":0,"b":""}"#,
            "a: 0 b: \"\"",
        ),
        value_case(
            "an empty nested message is written, a default one is not",
            "syntax = \"proto3\";\nmessage N { int32 x = 1; } message M { N n = 1; N m = 2; }",
            "M",
            r#"{"n":{},"m":{"x":0}}"#,
            "n {} m { x: 0 }",
        ),
        value_case(
            "proto2 fields are written at their defaults",
            "syntax = \"proto2\";\nmessage M { optional int32 a = 1 [default = 7]; required int32 r = 2; optional string s = 3; }",
            "M",
            r#"{"a":0,"r":0}"#,
            "a: 0 r: 0",
        ),
        // Order.
        value_case(
            "fields are written by number whatever the order given",
            "syntax = \"proto3\";\nmessage M { int32 high = 9; int32 low = 1; int32 mid = 5; }",
            "M",
            r#"{"mid":2,"high":3,"low":1}"#,
            "mid: 2 high: 3 low: 1",
        ),
        // Repeated.
        value_case(
            "proto3 packs, and packed = false does not",
            "syntax = \"proto3\";\nmessage M { repeated int32 a = 1; repeated int32 b = 2 [packed=false]; repeated sint64 c = 3; }",
            "M",
            r#"{"a":[1,2,3],"b":[4,5],"c":[-1,1]}"#,
            "a: 1 a: 2 a: 3 b: 4 b: 5 c: -1 c: 1",
        ),
        value_case(
            "proto2 does not pack and packed = true does",
            "syntax = \"proto2\";\nmessage M { repeated int32 a = 1; repeated fixed32 b = 2 [packed=true]; repeated bool c = 3; }",
            "M",
            r#"{"a":[1,2,3],"b":[1,2],"c":[true,false]}"#,
            "a: 1 a: 2 a: 3 b: 1 b: 2 c: true c: false",
        ),
        value_case(
            "packed enums, and repeated strings, bytes and messages",
            "syntax = \"proto3\";\nenum E { Z = 0; ONE = 1; }\nmessage N { int32 x = 1; }\n\
             message M { repeated E e = 1; repeated string s = 2; repeated bytes b = 3; repeated N n = 4; }",
            "M",
            r#"{"e":["ONE","Z"],"s":["a","","b"],"b":["AQ==","Ag"],"n":[{"x":1},{},{"x":2}]}"#,
            "e: ONE e: Z s: \"a\" s: \"\" s: \"b\" b: \"\\001\" b: \"\\002\" n { x: 1 } n {} n { x: 2 }",
        ),
        // Maps.
        value_case(
            "a map with a default value writes both key and value",
            "syntax = \"proto3\";\nmessage M { map<string, int32> m = 1; }",
            "M",
            r#"{"m":{"":0}}"#,
            "m { key: \"\" value: 0 }",
        ),
        value_case(
            "a map of messages",
            "syntax = \"proto3\";\nmessage N { int32 x = 1; } message M { map<bool, N> m = 1; map<sint32, string> s = 2; }",
            "M",
            r#"{"m":{"true":{"x":1}},"s":{"-3":"c"}}"#,
            "m { key: true value { x: 1 } } s { key: -3 value: \"c\" }",
        ),
        // Structure.
        value_case(
            "a message nested three deep",
            "syntax = \"proto3\";\nmessage M { int32 v = 1; M next = 2; }",
            "M",
            r#"{"v":1,"next":{"v":2,"next":{"v":3}}}"#,
            "v: 1 next { v: 2 next { v: 3 } }",
        ),
    ];
    // Several map entries: the order on the wire is the writer's.
    v.push(ValueCase {
        unordered: true,
        ..value_case(
            "several map entries are the same set of fields",
            "syntax = \"proto3\";\nmessage M { map<int32, string> m = 1; map<string, int32> n = 2; }",
            "M",
            r#"{"m":{"10":"x","2":"y","-3":"z"},"n":{"b":2,"a":1}}"#,
            "m { key: 10 value: \"x\" } m { key: 2 value: \"y\" } m { key: -3 value: \"z\" } \
             n { key: \"b\" value: 2 } n { key: \"a\" value: 1 }",
        )
    });
    // Two files: the schema is the list, and the root is in the first.
    v.push(ValueCase {
        name: "a message from an imported file",
        files: vec![
            (
                "a.proto",
                "syntax = \"proto3\";\npackage p;\nimport \"b.proto\";\nmessage M { q.B b = 1; int32 id = 2; }",
            ),
            (
                "b.proto",
                "syntax = \"proto3\";\npackage q;\nmessage B { sint32 v = 3; }",
            ),
        ],
        root: "p.M",
        values: r#"{"b":{"v":-5},"id":7}"#,
        text: "b { v: -5 } id: 7",
        unordered: false,
        negative_zero: None,
    });
    v
}

/// The door's bytes for one message, through the C ABI, or the verdict's reason.
fn encode_with_the_door(
    root: &str,
    files: &[(&str, &str)],
    values: &str,
) -> Result<Vec<u8>, String> {
    let root = CString::new(root).expect("no NUL");
    let values = CString::new(values).expect("no NUL");
    let names: Vec<CString> = files
        .iter()
        .map(|(n, _)| CString::new(*n).expect("no NUL"))
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
        wz_dissect_proto_encode(
            root.as_ptr(),
            entries.as_ptr(),
            entries.len(),
            0,
            values.as_ptr(),
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
    if !doc.contains("\"ok\":true") {
        return Err(json_string(&doc, "message").unwrap_or(doc));
    }
    let hex = json_string(&doc, "payload").ok_or_else(|| format!("no payload in {doc}"))?;
    let bytes = (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).map_err(|e| e.to_string()))
        .collect::<Result<Vec<u8>, String>>()?;
    assert_eq!(
        json_count(&doc, "payload_bytes"),
        Some(bytes.len()),
        "the count is the length of the hex"
    );
    Ok(bytes)
}

/// `protoc --encode` of a text-format message, or what it said.
fn protoc_encode(
    judge: &Judge,
    dir: &Path,
    root_file: &str,
    root: &str,
    text: &str,
) -> Result<Vec<u8>, String> {
    use std::io::Write;
    let mut child = Command::new(&judge.bin)
        .args(judge.flags())
        .arg(format!("--proto_path={}", dir.display()))
        .arg(format!("--encode={root}"))
        .arg(root_file)
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .map_err(|e| format!("protoc did not run: {e}"))?;
    child
        .stdin
        .take()
        .expect("stdin was piped")
        .write_all(text.as_bytes())
        .map_err(|e| format!("write the text format: {e}"))?;
    let out = child
        .wait_with_output()
        .map_err(|e| format!("protoc did not finish: {e}"))?;
    if out.status.success() {
        Ok(out.stdout)
    } else {
        Err(String::from_utf8_lossy(&out.stderr).into_owned())
    }
}

/// `protoc --decode` of wire bytes, as the text format it prints.
fn protoc_decode(
    judge: &Judge,
    dir: &Path,
    root_file: &str,
    root: &str,
    bytes: &[u8],
) -> Result<String, String> {
    use std::io::Write;
    let mut child = Command::new(&judge.bin)
        .args(judge.flags())
        .arg(format!("--proto_path={}", dir.display()))
        .arg(format!("--decode={root}"))
        .arg(root_file)
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .map_err(|e| format!("protoc did not run: {e}"))?;
    child
        .stdin
        .take()
        .expect("stdin was piped")
        .write_all(bytes)
        .map_err(|e| format!("write the bytes: {e}"))?;
    let out = child
        .wait_with_output()
        .map_err(|e| format!("protoc did not finish: {e}"))?;
    if out.status.success() {
        Ok(String::from_utf8_lossy(&out.stdout).into_owned())
    } else {
        Err(String::from_utf8_lossy(&out.stderr).into_owned())
    }
}

/// The top-level fields of a `protoc --decode` print, sorted: a field starts at
/// a line with no indentation and a nested one is indented under it. Two prints
/// of the same set of fields in different orders are equal here.
fn top_level_fields_sorted(decoded: &str) -> Vec<String> {
    let mut fields: Vec<String> = Vec::new();
    for line in decoded.lines() {
        if line.starts_with(char::is_whitespace) || line == "}" {
            if let Some(last) = fields.last_mut() {
                last.push('\n');
                last.push_str(line);
            }
        } else {
            fields.push(line.to_string());
        }
    }
    fields.sort();
    fields
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// The door's bytes against `protoc`'s for one case: `None` when they agree,
/// else what differs. An `unordered` case is compared as the sorted top-level
/// fields each side decodes to, with `decode` supplying the decoding.
fn compare_bytes(
    case: &ValueCase,
    door: &[u8],
    protoc: &[u8],
    judge_writes_negative_zero: bool,
    decode: &dyn Fn(&[u8]) -> Result<String, String>,
) -> Option<String> {
    // A case that depends on the judge's `-0.0` pins the door to its documented
    // bytes first, whatever the judge does, so a judge that omits `-0.0` can
    // never excuse a door that does.
    if let Some(expect) = case.negative_zero {
        if hex(door) != expect.door_hex {
            return Some(format!(
                "the door does not write its documented bytes\n  door:       {}\n  documented: {}",
                hex(door),
                expect.door_hex
            ));
        }
        if !judge_writes_negative_zero {
            // The judge was measured to omit `-0.0`: it is held to exactly the
            // omission, so the difference stays the one recorded and cannot
            // hide another.
            return (hex(protoc) != expect.judge_omitting_hex).then(|| {
                format!(
                    "the judge omits -0.0 and was expected to write {:?}\n  protoc: {}",
                    expect.judge_omitting_hex,
                    hex(protoc)
                )
            });
        }
    }
    if door == protoc {
        return None;
    }
    if case.unordered {
        return match (decode(door), decode(protoc)) {
            (Ok(a), Ok(b)) => {
                (top_level_fields_sorted(&a) != top_level_fields_sorted(&b)).then(|| {
                    format!(
                        "the fields differ\n  door:   {}\n  protoc: {}",
                        hex(door),
                        hex(protoc)
                    )
                })
            }
            (a, b) => Some(format!("a side could not be decoded: {a:?} / {b:?}")),
        };
    }
    Some(format!(
        "the bytes differ\n  door:   {}\n  protoc: {}",
        hex(door),
        hex(protoc)
    ))
}

/// THE ADJUDICATOR FOR THE VALUE DOOR: the bytes `wz_dissect_proto_encode` writes
/// for each message of the corpus are the bytes `protoc --encode` writes for the
/// same message in text format.
///
/// The `protoc` in the name is LOAD-BEARING for the reason the adjudicator above
/// gives: Layer C0's skip-token rule reads the FUNCTION name.
#[test]
fn the_proto_value_door_agrees_with_protoc_encode_over_the_corpus() {
    let required = std::env::var("WZ_PROTOC_REQUIRE").is_ok();
    let judge = protoc().and_then(|(bin, version)| measure_judge(bin, version));
    let judge = match judge {
        Ok(j) => j,
        Err(why) => {
            if required {
                panic!(
                    "WZ_PROTOC_REQUIRE is set and protoc cannot judge: {why}. The value door has \
                     no other adjudicator for its bytes, so a lane that armed this flag was \
                     asking for the measurement, not for a skip"
                );
            }
            eprintln!(
                "skip: protoc cannot judge here ({why}); set WZ_PROTOC_REQUIRE=1 to make that a failure"
            );
            return;
        }
    };

    let corpus = value_corpus();
    let mut names: Vec<&str> = corpus.iter().map(|c| c.name).collect();
    names.sort_unstable();
    let before = names.len();
    names.dedup();
    assert_eq!(before, names.len(), "two value cases share a name");

    // Every case printed, with the door's bytes, when asked: the corpus is
    // data, and another judge of the JSON notation can be pointed at it.
    let dump = std::env::var("WZ_PROTO_VALUES_DUMP").is_ok();
    let mut disagreements: Vec<String> = Vec::new();
    let (mut compared, mut unordered, mut bytes_total) = (0, 0, 0);
    for case in &corpus {
        let dir = tempfile::tempdir().expect("tempdir for the schemas");
        for (name, text) in &case.files {
            std::fs::write(dir.path().join(name), text).expect("write the schema");
        }
        let root_file = case.files[0].0;
        let say = |what: String| format!("[{}] {what}", case.name);
        let door = match encode_with_the_door(case.root, &case.files, case.values) {
            Ok(bytes) => bytes,
            Err(why) => {
                disagreements.push(say(format!("the door refused it: {why}")));
                continue;
            }
        };
        let protoc = match protoc_encode(&judge, dir.path(), root_file, case.root, case.text) {
            Ok(bytes) => bytes,
            Err(why) => {
                disagreements.push(say(format!(
                    "the corpus is wrong: protoc refused the text format: {why}"
                )));
                continue;
            }
        };
        if dump {
            let escaped = |s: &str| {
                s.replace('\\', "\\\\")
                    .replace('"', "\\\"")
                    .replace('\n', "\\n")
            };
            let files: Vec<String> = case
                .files
                .iter()
                .map(|(n, t)| format!("[\"{}\",\"{}\"]", escaped(n), escaped(t)))
                .collect();
            eprintln!(
                "VALUES-CASE {{\"name\":\"{}\",\"root\":\"{}\",\"files\":[{}],\"values\":\"{}\",\"door\":\"{}\"}}",
                escaped(case.name),
                escaped(case.root),
                files.join(","),
                escaped(case.values),
                hex(&door)
            );
        }
        let decode = |bytes: &[u8]| protoc_decode(&judge, dir.path(), root_file, case.root, bytes);
        if let Some(diff) = compare_bytes(case, &door, &protoc, judge.writes_negative_zero, &decode)
        {
            disagreements.push(say(diff));
        }
        compared += 1;
        unordered += usize::from(case.unordered);
        bytes_total += protoc.len();
    }

    eprintln!(
        "value door vs protoc --encode: {compared} message(s) compared, {unordered} of them as \
         sets of fields, {bytes_total} byte(s) of protoc's output; judge: {}, which {} -0.0",
        judge.version,
        if judge.writes_negative_zero {
            "writes"
        } else {
            "omits"
        }
    );
    assert!(
        compared >= 25 && bytes_total >= 300,
        "the corpus no longer exercises the writer: {compared} case(s), {bytes_total} byte(s)"
    );
    assert!(
        disagreements.is_empty(),
        "the value door and protoc disagree on {} point(s):\n\n{}",
        disagreements.len(),
        disagreements.join("\n\n")
    );
}

/// THE VALUE COMPARISON REPORTS A DOOR THAT DISAGREES, with no protoc: bytes that
/// differ by one are a disagreement, an unordered case tolerates a reordering of
/// its top-level fields and nothing else.
#[test]
fn the_value_comparison_reports_a_door_that_disagrees() {
    let case = |unordered| ValueCase {
        unordered,
        ..value_case("c", "", "M", "{}", "")
    };
    let nothing = |_: &[u8]| -> Result<String, String> { Err("no decoder".to_string()) };
    // A judge that writes -0.0 is the ordinary one: these cases do not depend on it.
    let compare_bytes = |case: &ValueCase,
                         door: &[u8],
                         protoc: &[u8],
                         decode: &dyn Fn(&[u8]) -> Result<String, String>| {
        crate::compare_bytes(case, door, protoc, true, decode)
    };
    let good = [0x08, 0x96, 0x01];
    assert_eq!(compare_bytes(&case(false), &good, &good, &nothing), None);
    // One byte off, one byte short, one byte over: each is a difference.
    for bad in [
        &[0x08, 0x96, 0x02][..],
        &[0x08, 0x96][..],
        &[0x08, 0x96, 0x01, 0x00][..],
    ] {
        assert!(compare_bytes(&case(false), bad, &good, &nothing).is_some());
    }
    // A reordering is a difference for an ordered case, which is the contract
    // ("ascending field number").
    let (ab, ba) = ([0x08, 0x01, 0x10, 0x02], [0x10, 0x02, 0x08, 0x01]);
    assert!(compare_bytes(&case(false), &ba, &ab, &nothing).is_some());
    // For an unordered case the decoder says what each side holds.
    let decode = |bytes: &[u8]| -> Result<String, String> {
        Ok(match bytes[0] {
            0x08 => "a: 1\nm {\n  key: 1\n}\nb: 2\n".to_string(),
            0x10 => "b: 2\na: 1\nm {\n  key: 1\n}\n".to_string(),
            _ => "a: 9\n".to_string(),
        })
    };
    assert_eq!(compare_bytes(&case(true), &ba, &ab, &decode), None);
    assert!(compare_bytes(&case(true), &[0x20], &ab, &decode).is_some());
    // A decoder that fails is not agreement.
    assert!(compare_bytes(&case(true), &ba, &ab, &nothing).is_some());
    // The sorting keeps a nested block with its field.
    assert_eq!(
        top_level_fields_sorted("b: 2\na {\n  x: 1\n}\n"),
        vec!["a {\n  x: 1\n}".to_string(), "b: 2".to_string()]
    );
}

/// THE JUDGE'S `-0.0` DECIDES WHAT THE COMPARISON EXPECTS OF THE JUDGE AND NEVER
/// WHAT IT EXPECTS OF THE DOOR, with no protoc: the door's documented bytes are
/// held first, a judge that writes `-0.0` must equal the door, and a judge
/// measured to omit it must write exactly the recorded omission.
#[test]
fn the_negative_zero_case_is_judged_by_what_the_judge_does() {
    let corpus = value_corpus();
    let case = corpus
        .iter()
        .find(|c| c.negative_zero.is_some())
        .expect("a case depends on the judge's -0.0");
    let expect = case.negative_zero.expect("just found");
    let door = unhex(expect.door_hex);
    let omitted = unhex(expect.judge_omitting_hex);
    let nothing = |_: &[u8]| -> Result<String, String> { Err("no decoder".to_string()) };
    let judged = |door: &[u8], protoc: &[u8], writes: bool| {
        compare_bytes(case, door, protoc, writes, &nothing)
    };
    // A judge that writes -0.0 agrees with the door, and only with it.
    assert_eq!(judged(&door, &door, true), None);
    assert!(judged(&door, &omitted, true).is_some());
    // A judge measured to omit it is held to the omission, and agrees with it.
    assert_eq!(judged(&door, &omitted, false), None);
    assert!(
        judged(&door, &door, false).is_some(),
        "a judge measured to omit -0.0 that wrote it is not the judge that was measured"
    );
    assert!(judged(&door, &[0x08, 0x01], false).is_some());
    // Whatever the judge does, a door that stopped writing -0.0 is a failure:
    // the judge's difference cannot excuse the door's.
    assert!(judged(&omitted, &omitted, false).is_some());
    assert!(judged(&omitted, &omitted, true).is_some());
    // The corpus holds exactly one such case, and the others do not depend on it.
    assert_eq!(
        corpus.iter().filter(|c| c.negative_zero.is_some()).count(),
        1
    );
}

fn unhex(hex: &str) -> Vec<u8> {
    (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).expect("hex digits"))
        .collect()
}

/// The bytes the door documents for the `-0.0` case: field 1 a float, field 2 a
/// double, both with only the sign bit set; the two `0.0` fields are absent.
const NEGATIVE_ZERO_DOOR_HEX: &str = "0d00000080110000000000000080";

/// THE DOOR WRITES `-0.0` BY ITS BITS, whatever any judge does: the contract the
/// header states, held through the C ABI with no protoc, so a judge that omits
/// `-0.0` can record a difference but never move this.
#[test]
fn the_value_door_writes_negative_zero_by_bits() {
    let schema =
        "syntax = \"proto3\";\nmessage M { float a = 1; double b = 2; float c = 3; double d = 4; }";
    let door = |values: &str| {
        encode_with_the_door("M", &[("a.proto", schema)], values).expect("the door answers")
    };
    assert_eq!(
        hex(&door(r#"{"a":-0.0,"b":-0.0,"c":0.0,"d":0.0}"#)),
        NEGATIVE_ZERO_DOOR_HEX
    );
    // Zero is the default and is not written; the sign is what makes the
    // difference, in the number and in the string spelling alike.
    assert_eq!(hex(&door(r#"{"a":0.0,"b":0,"c":0.0,"d":0.0}"#)), "");
    assert_eq!(hex(&door(r#"{"a":"-0","b":"-0"}"#)), NEGATIVE_ZERO_DOOR_HEX);
}

/// THE VALUE CORPUS NAMES EACH CASE ONCE, covers the arms the door has and keeps
/// its two notations apart: a case whose text format is empty or equal to its
/// values would compare a notation with itself.
#[test]
fn the_value_corpus_names_each_case_once_and_covers_each_arm() {
    let corpus = value_corpus();
    let mut names: Vec<&str> = corpus.iter().map(|c| c.name).collect();
    names.sort_unstable();
    let before = names.len();
    names.dedup();
    assert_eq!(before, names.len(), "two value cases share a name");
    assert!(corpus.len() >= 25, "{}", corpus.len());
    assert!(corpus.iter().any(|c| c.unordered), "no unordered case");
    assert!(
        corpus.iter().any(|c| c.files.len() > 1),
        "no multi-file case"
    );
    for c in &corpus {
        assert!(!c.files.is_empty() && !c.text.is_empty(), "{}", c.name);
        assert_ne!(c.values, c.text, "{} reads one notation twice", c.name);
    }
    // Each notation of the arms the door has is present somewhere in the corpus.
    let schemas: String = corpus
        .iter()
        .flat_map(|c| c.files.iter().map(|(_, t)| *t))
        .collect::<Vec<_>>()
        .join("\n");
    for arm in [
        "proto2",
        "proto3",
        "sint32",
        "sint64",
        "fixed32",
        "sfixed64",
        "float",
        "double",
        "bytes",
        "enum",
        "oneof",
        "optional",
        "required",
        "repeated",
        "map<",
        "packed=true",
        "packed=false",
        "import",
    ] {
        assert!(schemas.contains(arm), "no case exercises `{arm}`");
    }
}
