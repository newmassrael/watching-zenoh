#!/usr/bin/env python3
# SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
# SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
"""R4175 (no register item) -- the server layer sits above the session engine, never below it.

The owner asked on 2026-11-03 for the server layer to be split out of
`wz-session-core`: storage (the `storage_*` modules), the admin space
(`adminspace`, `admin_*`) and the auth methods that are not the transport
handshake (`extauth_*`). They move into crates of their own in this workspace
(`wz-storage`, `wz-admin`, `wz-auth`), one landable step at a time, and each of
those crates depends on the core. The split is worth something only while the
dependency points one way: a core that names an upper crate again, through a
dependency edge or a path in its source, has folded the layers back into one,
and nothing in the build would refuse it, because Cargo accepts any acyclic
graph and a dev-dependency is not even a cycle.

`wz-app-frame` is held to the same direction without being server-layer: the
application frame (the CRC engine, the judge and the profiles) left the capture
crate so a session runtime and the C ABIs can use it, and it is built on the
core. The graph and source rules below cover it; the module rule does not,
because no application-frame module was ever the core's.

## What is checked

1. THE MODULES STILL IN CORE. A module of `crates/wz-session-core/src` (a
   `<stem>.rs` file or a `<stem>/` directory) whose stem is a server-layer stem
   (`storage_*`, `admin*`, `extauth_*`) must be named in `IN_CORE`, the list of
   the server modules not yet moved. A server module that is not in the list is a
   new one written into the core: it belongs in its upper crate. A name in the list
   with no module behind it has moved: the list is a ratchet and only shrinks, so
   the step that moves a module removes its name here in the same change. The list
   has been EMPTY since step 9 moved the last one, so the rule is strict: every
   server-layer module in the core is a finding. Stems
   that stay are not server-layer by this rule: `auth_dispatch` and `extauth` are
   the transport handshake's sub-extension, demuxed per frame by the drive loop.
2. THE GRAPH, as `cargo metadata` of the `crates/` workspace reads it (the
   manifests are not parsed here: cargo already knows what each one declares,
   renames and target tables included). The core has no dependency of any kind
   (normal, build, dev, any target's) on an upper crate; a dev edge would compile
   the core twice in one test binary, two copies of every type, which is why a
   core test that needs an upper crate moves to that crate instead. Each upper
   crate that is a workspace member has a normal dependency on the core.
3. THE SOURCE. No Rust file under `crates/wz-session-core` names an upper
   crate's path (`wz_auth::`, `wz_storage::`, `wz_admin::`, or `extern crate` of
   one). The graph rule already makes such a path fail to compile; this rule names
   the line, and it holds in a reduced build where the line is behind a feature no
   build turns on.

A population of zero is a FAIL, not a pass: no workspace member, no core among
them, or no core source file means nothing was measured.

## The extension layer of the pico C ABI

The doors of the additional features (end-to-end protection, reception
supervision, instance keys, the replay cache, the message catalog) are modules of
`crates/wz-capi-pico/src`, listed in `EXTENSION_DOORS`, layered over the pico
ABI's core in the same crate. They are to be buildable as a library of their own
that links the core through C, so a door may name the core only as that library
could, and the compiler of one crate does not hold it: every `pub(crate)` helper
of the core is in reach. So this arm reads each door's source, comments and
literals blanked, and refuses:

4. A PATH INTO THE CORE that is not its C ABI. A `crate::<module>::<item>` the
   door names (in a `use` tree or inline, `super::` read as `crate::`) must be
   one of: another extension door; an item of the extension interface
   (`ext_interface`, the versioned C interface the core exports for these doors);
   a boundary helper of `BOUNDARY_TOOLKIT`, which holds no state of the core and
   which each library compiles for itself; or an item a `pub mod` of the crate
   root declares strictly `pub` as an `extern "C"` function, a constant, a static
   or a `#[repr(C)]` type. An item the module declares nowhere (one a macro
   declares) passes only under a pico or `wz_ext` C name. A glob, the module
   itself and an associated item of a core type are refused: the C ABI has none.
5. ANOTHER CRATE OF THE STACK. The door may name `wz-app-frame` (the features'
   own rules), the stateless modules of `wz-session-core` in
   `SESSION_CORE_LIBRARY`, and of its build limits only the features' own
   (`EXTENSION_LIMITS`). Any other dependency of the pico crate (the engine port,
   the engines, the runtimes) holds the core's state, which the door reads through
   the interface instead.
6. THE CORE'S FIELDS. A struct literal of a core type with a field that is not
   strictly `pub` (or whose fields the gate cannot read, a macro's type), and a
   read `.field` of a name that is private to a core type the door names, public
   on none and no field of the layer's own types. A name both have is left to the
   compiler of the split build.
7. THE DIRECTION. No other file of the crate's `src` names a door
   (`crate::<door>` or `super::<door>`), comments included: the core never
   depends on the extension layer.
8. A CORE VALUE HELD AS NOTHING. The doors' library declares each core type the
   doors only point at as a type of no size (`wz-capi-pico-ext/src/core_view.rs`).
   A door names such a type only behind a pointer or a reference, or as the
   target of a cast: a field, a local, an argument, a result or a size of it is
   refused, since in that library a copy holds nothing and a pointer to the copy
   points into the door's own memory, which the core reads as its value. A door
   that keeps a copy of a core value has the view declare it as storage of the
   core's size, which the core's tests hold to the core.

A door listed with no file is a finding (the list is renamed with the door), and
no door file at all is a failure to grade, as is no view, or a view in which the
gate reads no type of no size.

## Modes

`--check` grades the tracked tree. `--selftest` drives the same grading over
fixture metadata and fixture source trees, red-first. There is no default mode: a
missing or unknown argument is refused by name.
"""

from __future__ import annotations

import re
import sys
import tempfile
from pathlib import Path

import cargo_workspaces
import rust_comments

ROOT = Path(__file__).resolve().parents[2]

CORE = "wz-session-core"

# Each upper crate's package name and the identifier its library is named by.
UPPER = {
    "wz-auth": "wz_auth",
    "wz-storage": "wz_storage",
    "wz-admin": "wz_admin",
}

# Every crate built on the core and never named by it: the server-layer crates
# above and the crates that are not server-layer but sit above the core all the
# same. The graph and source rules read this; the module rule reads `UPPER`.
ABOVE_CORE = {
    **UPPER,
    "wz-app-frame": "wz_app_frame",
}

# A module stem is server-layer when it matches this. `extauth` itself and
# `auth_dispatch` do not: they are the transport handshake and stay in core.
SERVER_STEM = re.compile(r"^(?:storage_\w+|admin\w*|extauth_\w+)$")

# The server modules not yet moved. A ratchet: a step that moves a module
# deletes its name here, and nothing is ever added. EMPTY since the server-layer
# split, step 9, moved `storage_config`, the last of them: the rule is strict now,
# and every server-layer module in the core is a finding.
IN_CORE: frozenset[str] = frozenset()

UPPER_PATH = re.compile(
    r"\b(?:extern\s+crate\s+(?:" + "|".join(ABOVE_CORE.values()) + r")\b|(?:"
    + "|".join(ABOVE_CORE.values())
    + r")\s*::)"
)


class InputError(Exception):
    """An input this gate could not read. Reported as a FAIL, never a traceback."""


def _kind(dep: dict) -> str:
    kind = dep.get("kind") or "normal"
    target = dep.get("target")
    return f"{kind} ({target})" if target else kind


def members(meta: dict) -> dict[str, dict]:
    """`{package name: package}` of the workspace's members."""
    ids = set(meta.get("workspace_members", []))
    return {p["name"]: p for p in meta.get("packages", []) if p.get("id") in ids}


def server_modules(src: Path) -> set[str]:
    """The server-layer module stems under a crate's `src`."""
    stems = set()
    for entry in src.iterdir():
        if entry.is_file() and entry.suffix == ".rs":
            stem = entry.stem
        elif entry.is_dir():
            stem = entry.name
        else:
            continue
        if SERVER_STEM.match(stem):
            stems.add(stem)
    return stems


def grade(meta: dict, in_core: frozenset[str]) -> tuple[list[str], str]:
    """The findings over a workspace's metadata and its core's source, and a census."""
    findings: list[str] = []
    pkgs = members(meta)
    if not pkgs:
        raise InputError("the workspace metadata lists no member package")
    if CORE not in pkgs:
        raise InputError(f"{CORE} is not a workspace member")
    core_dir = Path(pkgs[CORE]["manifest_path"]).parent
    core_src = core_dir / "src"
    if not core_src.is_dir():
        raise InputError(f"{core_src}: no source directory")

    # 1. The modules still in core.
    found = server_modules(core_src)
    for stem in sorted(found - in_core):
        findings.append(
            f"{CORE}/src/{stem} is a server-layer module that is not in IN_CORE: "
            f"write it in its upper crate ({', '.join(UPPER)}), not in the core"
        )
    for stem in sorted(in_core - found):
        findings.append(
            f"IN_CORE names {stem}, and {CORE}/src has no such module: it has moved, "
            f"so delete its name from IN_CORE (the list only shrinks)"
        )

    # 2. The graph.
    for dep in pkgs[CORE].get("dependencies", []):
        if dep.get("name") in ABOVE_CORE:
            findings.append(
                f"{CORE} has a {_kind(dep)} dependency on {dep['name']}: the core never "
                f"depends on an upper crate (a test that needs it moves to {dep['name']})"
            )
    present_upper = [u for u in ABOVE_CORE if u in pkgs]
    for upper in present_upper:
        normal = {
            d.get("name")
            for d in pkgs[upper].get("dependencies", [])
            if not d.get("kind") and not d.get("target")
        }
        if CORE not in normal:
            findings.append(
                f"{upper} has no normal dependency on {CORE}: an upper crate is built "
                f"on the core"
            )

    # 3. The source.
    rust_files = sorted(
        p for p in core_dir.rglob("*.rs") if "target" not in p.relative_to(core_dir).parts
    )
    if not rust_files:
        raise InputError(f"{core_dir}: no Rust source")
    for path in rust_files:
        for lineno, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
            if UPPER_PATH.search(line):
                rel = path.relative_to(core_dir.parent)
                findings.append(
                    f"{rel}:{lineno} names an upper crate's path: {line.strip()[:120]}"
                )

    census = (
        f"{len(found)} server module(s) still in {CORE} of {len(in_core)} listed; "
        f"{len(present_upper)} of {len(ABOVE_CORE)} upper crate(s) built; "
        f"{len(rust_files)} core Rust file(s) read"
    )
    return findings, census


# ---- The extension layer of the pico C ABI (rules 4 to 8) -----------------------------------

PICO = "wz-capi-pico"

# The modules of the extension layer: the doors of the additional features and what they share.
# A door added to the layer is added here; one that moves or is renamed is renamed here.
EXTENSION_DOORS: frozenset[str] = frozenset(
    {
        "e2e",
        "e2e_sender",
        "e2e_receiver",
        "stream_supervision",
        "instance_key",
        "replay_publisher",
        "replay_subscriber",
        "message_catalog",
        "message_payload",
        # The `.proto` files the instance keys and the message payloads both read.
        "proto_file",
        # The interface version the doors were built against, asked of them.
        "additional",
    }
)

# The versioned C interface the core exports for the doors (`wz_ext_interface_*`).
EXTENSION_INTERFACE = "ext_interface"

# Helpers of a core module that hold no state of the core: a panic guard and a pointer marked
# `Send`. Each library compiles them for itself; `ffi`'s other items (the in-callback mark, the
# closures' release latches) are the core's state, which the interface carries.
BOUNDARY_TOOLKIT: dict[str, frozenset[str]] = {
    "ffi": frozenset({"catch", "guard", "guarded", "guard_val", "SendPtr"}),
}
# Re-exports of `alloc` for a build without `std`.
TOOLKIT_MODULES = frozenset({"prelude"})

# The crates of the stack a door may name whole: the additional features' own rules.
LIBRARY_CRATES = frozenset({"wz_app_frame"})
SESSION_CORE_IDENT = "wz_session_core"
# The modules of the session core that are libraries a door links for itself: the features'
# sans-I/O models and pure values, with no session or engine behind them.
SESSION_CORE_LIBRARY = frozenset(
    {
        "keyexpr_canon",
        "policy",
        "quota",
        "replay_publisher",
        "replay_subscriber",
        "session_zid",
        "stream_supervisor",
    }
)
# The build limits of the additional features themselves; any other limit is the core's, which
# the interface reports (`querier_max_pending_queries` of the session facts).
EXTENSION_LIMITS = frozenset(
    {
        "E2E_SENDER_SLOTS",
        "E2E_SUPERVISED_STREAMS",
        "INSTANCE_KEY_FIELDS",
        "INSTANCES_PER_MESSAGE",
        "MESSAGE_CATALOG_ENTRIES",
        "REPLAY_DEPTH_MAX",
    }
)

# What a path a door names reaches in the core: (module, item, whether the item is a type).
Item = tuple[str, str, bool]

# A name of the C ABI: pico's (`z_`, `zp_`, `ze_`, `Z_`, `ZP_`, `_Z_`) or wz's own (`wz_ext_`).
C_NAME = re.compile(r"^(?:z|zp|ze|wz_ext|Z|ZP|_Z|WZ_EXT)_[A-Za-z0-9_]*$")

_IDENT = r"[A-Za-z_][A-Za-z0-9_]*"
LIB_MOD = re.compile(rf"^[ \t]*(pub(?:\s*\([^)]*\))?\s+)?mod\s+({_IDENT})\s*[;{{]", re.M)
USE_STMT = re.compile(r"(?<![\w])use\s+([^;]*);")
USE_TOKEN = re.compile(rf"::|[{{}},*]|{_IDENT}")
PATH_TAIL = rf"((?:{_IDENT}\s*::\s*)*{_IDENT})"
CRATE_INLINE = re.compile(rf"(?<![\w:])(crate|super)\s*::\s*{PATH_TAIL}")
# The opening of a struct literal: a brace whose first word is a field (`name:`, `name,`,
# `name }`) or the rest (`..`). A function body never opens that way.
LITERAL_OPEN = re.compile(rf"\s*\{{\s*(?:{_IDENT}\s*(?::(?!:)|,|\}})|\.\.)")
# The words after which a type and a brace are not a literal: a return type, a declaration.
NOT_A_LITERAL_AFTER = frozenset(
    {"->", "struct", "enum", "union", "impl", "for", "trait", "type", "mut", "const", "dyn"}
)
FIELD_READ = re.compile(rf"(?<!\.)\.\s*({_IDENT})\b(?!\s*(?:\(|::|!))")
STRUCT_HEAD = re.compile(rf"\b(?:struct|union)\s+({_IDENT})\b[^;{{(]*\{{")

# The doors' library's view of the core, beside the pico crate, and the declaration it gives a
# type the doors only point at: one field of no size.
EXT_CRATE = "wz-capi-pico-ext"
VIEW_FILE = "src/core_view.rs"
NO_SIZE_DECL = re.compile(
    rf"\bstruct\s+({_IDENT})\s*\{{\s*_opaque\s*:\s*\[\s*u8\s*;\s*0\s*\]\s*,?\s*\}}"
)
# What a type of no size may follow where a door names it: a pointer, a reference, a `NonNull`,
# or the turbofish of a cast or a null pointer, each of which leaves the value where the core put
# it.
BEHIND_A_POINTER = re.compile(
    r"(?:\*\s*(?:const|mut)|&\s*(?:'\w+\s*)?(?:mut)?|\bNonNull\s*<"
    r"|\b(?:cast|cast_const|cast_mut|null|null_mut)\s*::\s*<)$"
)


def _decl(name: str) -> re.Pattern[str]:
    """Where a module declares `name`: its visibility, qualifiers and kind."""
    return re.compile(
        r"^[ \t]*(pub(?:\s*\([^)]*\))?\s+)?"
        r"((?:(?:const|unsafe|async|extern\s*\"[^\"]*\")\s+)*)"
        rf"(fn|const|static|struct|enum|union|type|trait|mod)\s+(?:mut\s+)?{re.escape(name)}\b",
        re.M,
    )


def _code(path: Path) -> str:
    """The text of a Rust file with comments and literal bodies blanked, lines in place."""
    return rust_comments.strip_comments(path.read_text(encoding="utf-8"), blank_literals=True)


def _line(text: str, pos: int) -> int:
    return text.count("\n", 0, pos) + 1


def lib_modules(src: Path) -> dict[str, bool]:
    """`{module: strictly pub}` of the modules the crate root declares."""
    mods: dict[str, bool] = {}
    for m in LIB_MOD.finditer(_code(src / "lib.rs")):
        mods[m.group(2)] = mods.get(m.group(2), False) or (m.group(1) or "").strip() == "pub"
    return mods


def module_file(src: Path, module: str) -> Path | None:
    for candidate in (src / f"{module}.rs", src / module / "mod.rs"):
        if candidate.is_file():
            return candidate
    return None


def use_leaves(tree: str) -> list[tuple[list[str], str | None]]:
    """Each leaf of a `use` tree: its path and the name it binds (`None` for a glob)."""
    tokens = USE_TOKEN.findall(tree)
    pos = 0

    def parse(prefix: list[str]) -> list[tuple[list[str], str | None]]:
        nonlocal pos
        segs = list(prefix)
        if pos < len(tokens) and tokens[pos] == "::":
            pos += 1
        while pos < len(tokens):
            tok = tokens[pos]
            if tok == "{":
                pos += 1
                leaves: list[tuple[list[str], str | None]] = []
                while pos < len(tokens) and tokens[pos] != "}":
                    if tokens[pos] == ",":
                        pos += 1
                        continue
                    before = pos
                    leaves.extend(parse(segs))
                    if pos == before:
                        pos += 1
                pos += 1
                return leaves
            if tok == "*":
                pos += 1
                return [(segs, None)]
            if tok in ("}", ","):
                break
            segs = segs + [tok]
            pos += 1
            if pos < len(tokens) and tokens[pos] == "::":
                pos += 1
                continue
            if pos + 1 < len(tokens) and tokens[pos] == "as":
                alias = tokens[pos + 1]
                pos += 2
                return [(segs, alias)]
            return [(segs, segs[-1])]
        return [(segs, segs[-1])] if segs else []

    return parse([])


def struct_fields(text: str, name: str) -> list[tuple[str, bool]] | None:
    """`[(field, strictly pub)]` of the braced struct `name` in `text`; `None` for none."""
    for head in STRUCT_HEAD.finditer(text):
        if head.group(1) == name:
            return _fields_from(text, head.end())
    return None


def _fields_from(text: str, start: int) -> list[tuple[str, bool]]:
    depth, i = 1, start
    while i < len(text) and depth:
        depth += {"{": 1, "}": -1}.get(text[i], 0)
        i += 1
    body = text[start : i - 1]
    parts, depth, cur = [], 0, []
    for at, ch in enumerate(body):
        if ch in "<([{":
            depth += 1
        elif ch in ")]}" or (ch == ">" and body[at - 1 : at] != "-"):
            depth -= 1
        if ch == "," and depth == 0:
            parts.append("".join(cur))
            cur = []
        else:
            cur.append(ch)
    parts.append("".join(cur))
    fields = []
    for part in parts:
        part = re.sub(r"#\[[^\]]*\]", " ", part).strip()
        m = re.match(rf"(pub(?:\s*\([^)]*\))?\s+)?({_IDENT})\s*:", part)
        if m:
            fields.append((m.group(2), (m.group(1) or "").strip() == "pub"))
    return fields


def own_fields(text: str) -> set[str]:
    """The field names of every braced struct `text` declares."""
    heads = STRUCT_HEAD.finditer(text)
    return {name for head in heads for name, _ in _fields_from(text, head.end())}


def judge_item(text: str, name: str) -> tuple[str | None, bool]:
    """(why `name` of a core module is no C ABI item, or `None`; whether it is a struct, which a
    literal could name; a type a macro declares is taken for one by its `_t`)."""
    decls = list(_decl(name).finditer(text))
    if not decls:
        if C_NAME.match(name):
            return None, name.endswith("_t")
        return (
            "which its module declares nowhere the gate can read and which is no C name "
            "(an item a macro declares passes under a pico or `wz_ext` name)",
            False,
        )
    reasons = []
    for d in decls:
        vis, quals, kind = (d.group(1) or "").strip(), d.group(2), d.group(3)
        if vis != "pub":
            reasons.append(f"which is `{vis or 'private'}` to the core, not its C ABI")
        elif kind == "fn" and "extern" not in quals:
            reasons.append("a Rust function of the core, which a C caller cannot call")
        elif kind in ("trait", "mod"):
            reasons.append(f"a {kind} of the core, which the C ABI has none of")
        else:
            return None, kind in ("struct", "union")
    return reasons[0], False


def judge_external(segs: list[str]) -> str | None:
    """Why a path into another crate of the stack is refused, or `None`."""
    root = segs[0]
    if root in LIBRARY_CRATES:
        return None
    if root != SESSION_CORE_IDENT:
        return (
            "a crate of the core's own (its engine, port or runtime), whose state the "
            "interface carries"
        )
    if len(segs) < 2:
        return "the session core whole"
    module = segs[1]
    if module == "caps":
        item = segs[2] if len(segs) > 2 else None
        if item not in EXTENSION_LIMITS:
            return (
                "a build limit that is not the additional features' own: the core's limits are "
                "read through the interface"
            )
        return None
    if module not in SESSION_CORE_LIBRARY:
        return "a module of the session core that is not one of the library modules a door links"
    return None


def grade_extension(
    src: Path, deps: set[str], doors: frozenset[str] = EXTENSION_DOORS
) -> tuple[list[str], str]:
    """The findings of rules 4 to 8 over the pico crate's `src`, and a census."""
    findings: list[str] = []
    if not (src / "lib.rs").is_file():
        raise InputError(f"{src}: no crate root (lib.rs)")
    mods = lib_modules(src)
    present = {d: src / f"{d}.rs" for d in sorted(doors) if (src / f"{d}.rs").is_file()}
    for d in sorted(doors - set(present)):
        findings.append(
            f"EXTENSION_DOORS names `{d}` and {src.name}/ has no `{d}.rs`: a door that moved "
            f"or was renamed is renamed in the list"
        )
    if not present:
        raise InputError(f"{src}: no extension door file to read")
    view = src.parent.parent / EXT_CRATE / VIEW_FILE
    if not view.is_file():
        raise InputError(
            f"{view}: no view of the core for the doors' library, so no type of no size to hold"
        )
    no_size = sorted(set(NO_SIZE_DECL.findall(_code(view))))
    if not no_size:
        raise InputError(f"{view}: the gate reads no type of no size in the doors' view")
    held = re.compile(
        rf"(?<![\w:])(?:(?:crate|super)\s*::\s*{_IDENT}\s*::\s*)?({'|'.join(no_size)})\b"
    )
    if module_file(src, EXTENSION_INTERFACE) is None:
        findings.append(
            f"{src.name}/ has no `{EXTENSION_INTERFACE}.rs`: the doors have no interface"
        )
    texts: dict[str, str | None] = {}

    def module_text(module: str) -> str | None:
        if module not in texts:
            path = module_file(src, module)
            texts[module] = _code(path) if path else None
        return texts[module]

    # 7. The direction: the core names no door, comments included.
    door_path = re.compile(r"\b(?:crate|super)\s*::\s*(" + "|".join(sorted(doors)) + r")\b")
    core_files = [
        p
        for p in sorted(src.rglob("*.rs"))
        if not (p.parent == src and p.stem in doors)
        and "target" not in p.relative_to(src).parts
    ]
    for path in core_files:
        for lineno, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
            hit = door_path.search(line)
            if hit:
                findings.append(
                    f"{src.name}/{path.relative_to(src).as_posix()}:{lineno} names the extension "
                    f"door `{hit.group(1)}`: the core never depends on the extension layer"
                )

    codes = {d: _code(p) for d, p in present.items()}
    own: set[str] = set()
    for code in codes.values():
        own |= own_fields(code)
    roots = "|".join(sorted(map(re.escape, deps)))
    ext_root = re.compile(rf"(?<![\w:])({roots})\s*::\s*{PATH_TAIL}") if deps else None
    graded = 0
    for door, code in codes.items():
        rel = f"{src.name}/{door}.rs"
        named: dict[str, Item] = {}  # the name a door binds -> what it names
        referenced: set[tuple[str, str]] = set()

        def refuse(pos: int, text: str, why: str) -> None:
            findings.append(
                f"{rel}:{_line(code, pos)} names `{text}`, {why}: an extension door reaches the "
                f"core through the pico ABI and `crate::{EXTENSION_INTERFACE}` only"
            )

        def literal(item: Item, pos: int, shown: str) -> None:
            text = module_text(item[0])
            fields = struct_fields(text, item[1]) if text is not None else None
            if fields is None:
                refuse(
                    pos,
                    f"{shown} {{ .. }}",
                    "a struct literal of a core type whose fields the gate cannot read (a type "
                    "a macro declares), made through its C doors instead",
                )
                return
            hidden = [name for name, is_pub in fields if not is_pub]
            if hidden:
                refuse(
                    pos,
                    f"{shown} {{ .. }}",
                    f"a struct literal of a core type whose field `{hidden[0]}` is the core's own",
                )

        def judge_crate(segs: list[str], glob: bool) -> tuple[str | None, Item | None]:
            if len(segs) < 2:
                return "the crate root itself", None
            module, rest = segs[1], segs[2:]
            if module in doors or module in TOOLKIT_MODULES:
                return None, None
            if module in BOUNDARY_TOOLKIT:
                helpers = BOUNDARY_TOOLKIT[module]
                if glob or not rest or rest[0] not in helpers or len(rest) > 1:
                    return (
                        f"which is not one of the boundary helpers of `crate::{module}` "
                        f"({', '.join(sorted(helpers))}), which hold no state of the core",
                        None,
                    )
                return None, None
            if module == EXTENSION_INTERFACE:
                if glob or not rest or rest[0] == "self":
                    return "the interface module whole (its items are named one by one)", None
                if len(rest) > 1:
                    return (
                        f"an associated item of the interface's `{rest[0]}`, which C has no way "
                        f"to call",
                        None,
                    )
            elif module not in mods:
                if not rest and not glob and C_NAME.match(module):
                    return None, None
                return "which is no module of the crate root and no C name of it", None
            elif not mods[module]:
                return "a private module of the core", None
            if glob:
                return "a glob of a core module, whose items the gate cannot hold to the ABI", None
            if not rest or rest[0] == "self":
                return "the core module whole, whose items the gate cannot hold to the ABI", None
            if len(rest) > 1:
                return (
                    f"an associated item or nested path of the core's `{rest[0]}`, which the C ABI "
                    f"has none of",
                    None,
                )
            text = module_text(module)
            if text is None:
                return "a core module whose file the gate cannot find", None
            why, is_type = judge_item(text, rest[0])
            return why, (None if why else (module, rest[0], is_type))

        def judge(segs: list[str], glob: bool, pos: int, shown: str) -> Item | None:
            nonlocal graded
            if segs and segs[0] == "super":
                if len(segs) < 2 or segs[1] not in mods:
                    return None
                segs = ["crate"] + segs[1:]
            if not segs or segs[0] not in ({"crate"} | deps):
                return None
            graded += 1
            if segs[0] == "crate":
                why, item = judge_crate(segs, glob)
            else:
                why, item = judge_external(segs), None
            if why:
                refuse(pos, shown, why)
                return None
            if item:
                referenced.add(item[:2])
            return item

        chars = list(code)
        for stmt in USE_STMT.finditer(code):
            for segs, alias in use_leaves(stmt.group(1)):
                shown = "::".join(segs) + ("::*" if alias is None else "")
                item = judge(segs, alias is None, stmt.start(), shown)
                if item and alias:
                    named[alias] = item
            for i in range(stmt.start(), stmt.end()):
                if chars[i] != "\n":
                    chars[i] = " "
        body = "".join(chars)

        # 8. A type the doors' library declares of no size, held by value.
        for hit in held.finditer(body):
            if BEHIND_A_POINTER.search(body[max(0, hit.start() - 64) : hit.start()].rstrip()):
                continue
            findings.append(
                f"{rel}:{_line(code, hit.start())} holds `{hit.group(1)}` by value, a type the "
                f"doors' library declares of no size ({EXT_CRATE}/{VIEW_FILE}): there a copy "
                f"holds nothing and a pointer to it points into the door's own memory, which the "
                f"core reads as its value; point at it, or declare it in the view as storage of "
                f"the core's size, which the core's tests hold to the core"
            )

        for hit in CRATE_INLINE.finditer(body):
            segs = [hit.group(1)] + [s.strip() for s in hit.group(2).split("::")]
            item = judge(segs, False, hit.start(), "::".join(segs))
            if item and item[2] and opens_literal(body, hit.start(), hit.end()):
                literal(item, hit.start(), "::".join(segs))
        if ext_root:
            for hit in ext_root.finditer(body):
                segs = [hit.group(1)] + [s.strip() for s in hit.group(2).split("::")]
                judge(segs, False, hit.start(), "::".join(segs))

        for alias, item in named.items():
            for hit in re.finditer(rf"(?<![\w:.]){re.escape(alias)}\s*::\s*({_IDENT})", body):
                refuse(
                    hit.start(),
                    f"{alias}::{hit.group(1)}",
                    f"an associated item of the core's `{item[1]}`, which the C ABI has none of",
                )
            if not item[2]:
                continue
            for hit in re.finditer(rf"(?<![\w:.]){re.escape(alias)}\b", body):
                if opens_literal(body, hit.start(), hit.end()):
                    literal(item, hit.start(), alias)

        private: set[str] = set()
        public: set[str] = set()
        for module, item in referenced:
            text = module_text(module)
            fields = struct_fields(text, item) if text is not None else None
            for name, is_pub in fields or []:
                (public if is_pub else private).add(name)
        for name in sorted(private - public - own):
            for hit in FIELD_READ.finditer(body):
                if hit.group(1) == name:
                    refuse(
                        hit.start(),
                        f".{name}",
                        "a field private to a core type the door names (copy the struct as C "
                        "does, or ask the interface)",
                    )

    census = (
        f"{len(present)} extension door(s) read, {graded} path(s) into the stack graded, "
        f"{len(core_files)} core file(s) read for the direction, "
        f"{len(no_size)} type(s) of no size in the doors' view"
    )
    return findings, census


def opens_literal(body: str, start: int, end: int) -> bool:
    """Whether the type named at `body[start:end]` opens a struct literal there."""
    if not LITERAL_OPEN.match(body, end):
        return False
    word = re.search(r"(->|\w+)$", body[:start].rstrip())
    return not (word and word.group(1) in NOT_A_LITERAL_AFTER)


def pico_crate(meta: dict) -> tuple[Path, set[str]]:
    """The pico crate's `src` and the identifiers of the dependencies its library links (a crate
    only its tests link holds no state of the core the library could reach)."""
    pkg = members(meta).get(PICO)
    if pkg is None:
        raise InputError(f"{PICO} is not a workspace member")
    deps = {
        (dep.get("rename") or dep["name"]).replace("-", "_")
        for dep in pkg.get("dependencies", [])
        if (dep.get("kind") or "normal") == "normal"
    }
    return Path(pkg["manifest_path"]).parent / "src", deps


def check() -> int:
    try:
        meta = cargo_workspaces.metadata("crates")
        findings, census = grade(meta, IN_CORE)
        src, deps = pico_crate(meta)
        more, more_census = grade_extension(src, deps)
        findings += more
        census = f"{census}; {more_census}"
    except (InputError, RuntimeError, OSError) as e:
        print(f"layer-direction: FAIL -- cannot grade: {e}", file=sys.stderr)
        return 1
    if findings:
        print("layer-direction: FAIL", file=sys.stderr)
        for f in findings:
            print(f"  - {f}", file=sys.stderr)
        print(f"layer-direction: {census}", file=sys.stderr)
        return 1
    print(f"layer-direction: OK -- {census}")
    return 0


def _dep(name: str, kind: str | None = None, target: str | None = None) -> dict:
    return {"name": name, "kind": kind, "target": target}


def _fixture(
    root: Path,
    *,
    core_modules: tuple[str, ...] = ("storage_manager", "extauth", "auth_dispatch"),
    core_deps: tuple[dict, ...] = (),
    upper: dict[str, tuple[dict, ...]] | None = None,
    core_line: str = "",
) -> dict:
    """A core source tree under `root` and the metadata a workspace of it reads as."""
    upper = upper or {}
    src = root / CORE / "src"
    src.mkdir(parents=True)
    (src / "lib.rs").write_text("pub fn f() {}\n" + core_line, encoding="utf-8")
    for stem in core_modules:
        (src / f"{stem}.rs").write_text("\n", encoding="utf-8")
    packages = [
        {
            "name": CORE,
            "id": CORE,
            "manifest_path": str(root / CORE / "Cargo.toml"),
            "dependencies": list(core_deps),
        }
    ]
    for name, deps in upper.items():
        packages.append(
            {
                "name": name,
                "id": name,
                "manifest_path": str(root / name / "Cargo.toml"),
                "dependencies": list(deps),
            }
        )
    return {"packages": packages, "workspace_members": [p["id"] for p in packages]}


def selftest() -> int:
    listed = frozenset({"storage_manager"})
    # (name, fixture arguments, should_fail, substring a finding carries)
    rows = [
        ("agrees", {}, False, ""),
        (
            "a new server module in core",
            {"core_modules": ("storage_manager", "storage_new", "extauth")},
            True,
            "storage_new is a server-layer module",
        ),
        (
            "an admin module by its bare prefix",
            {"core_modules": ("storage_manager", "adminspace")},
            True,
            "adminspace is a server-layer module",
        ),
        (
            "an auth method beside the handshake",
            {"core_modules": ("storage_manager", "extauth_pubkey", "extauth")},
            True,
            "extauth_pubkey is a server-layer module",
        ),
        (
            "a listed module that moved",
            {"core_modules": ("extauth",)},
            True,
            "delete its name from IN_CORE",
        ),
        (
            "the core depends on an upper crate",
            {"core_deps": (_dep("wz-auth"),)},
            True,
            "normal dependency on wz-auth",
        ),
        (
            "a dev edge from the core",
            {"core_deps": (_dep("wz-storage", "dev"),)},
            True,
            "dev dependency on wz-storage",
        ),
        (
            "a target edge from the core",
            {"core_deps": (_dep("wz-admin", "build", "cfg(unix)"),)},
            True,
            "build (cfg(unix)) dependency on wz-admin",
        ),
        (
            "an upper crate built on the core",
            {"upper": {"wz-auth": (_dep(CORE),)}},
            False,
            "",
        ),
        (
            "an upper crate not built on the core",
            {"upper": {"wz-auth": ()}},
            True,
            "no normal dependency on",
        ),
        (
            "an upper crate that reaches the core only in its tests",
            {"upper": {"wz-auth": (_dep(CORE, "dev"),)}},
            True,
            "no normal dependency on",
        ),
        (
            "the core names an upper path",
            {"core_line": "use wz_storage::Volume;\n"},
            True,
            "names an upper crate's path",
        ),
        (
            "the core names an upper crate by extern",
            {"core_line": "extern crate wz_admin;\n"},
            True,
            "names an upper crate's path",
        ),
        (
            "the core depends on the application frame",
            {"core_deps": (_dep("wz-app-frame", "dev"),)},
            True,
            "dev dependency on wz-app-frame",
        ),
        (
            "the core names the application frame's path",
            {"core_line": "use wz_app_frame::e2e_crc::Crc;\n"},
            True,
            "names an upper crate's path",
        ),
        (
            "the application frame built on the core",
            {"upper": {"wz-app-frame": (_dep(CORE),)}},
            False,
            "",
        ),
        (
            "the application frame not built on the core",
            {"upper": {"wz-app-frame": ()}},
            True,
            "no normal dependency on",
        ),
        (
            "prose that names a crate is not a path",
            {"core_line": "// moved to the wz-auth crate (wz_auth)\n"},
            False,
            "",
        ),
    ]
    bad = 0
    for name, kwargs, should_fail, needle in rows:
        with tempfile.TemporaryDirectory() as tmp:
            meta = _fixture(Path(tmp), **kwargs)
            findings, _census = grade(meta, listed)
        failed = bool(findings)
        ok = failed == should_fail and (not should_fail or any(needle in f for f in findings))
        print(f"  selftest {'ok  ' if ok else 'BAD '} {name}: "
              f"{'refused' if failed else 'accepted'}")
        if not ok:
            bad += 1
            for f in findings:
                print(f"      {f}", file=sys.stderr)

    # A population of zero is refused, not passed.
    zero_rows = [
        ("no workspace member", lambda m: m.update(workspace_members=[]),
         "no member package"),
        ("the core is not a member", lambda m: m.update(workspace_members=["other"]),
         "no member package"),
        ("the core is missing among members",
         lambda m: m["packages"].append({"name": "other", "id": "other"})
         or m.update(workspace_members=["other"]),
         "not a workspace member"),
    ]
    for name, spoil, needle in zero_rows:
        with tempfile.TemporaryDirectory() as tmp:
            meta = _fixture(Path(tmp))
            spoil(meta)
            try:
                grade(meta, listed)
                ok = False
            except InputError as e:
                ok = needle in str(e)
        print(f"  selftest {'ok  ' if ok else 'BAD '} {name}: refused")
        if not ok:
            bad += 1

    # The tracked list must name only server-layer stems; otherwise a typo in
    # IN_CORE would be a name the module rule could never reach.
    stray = sorted(s for s in IN_CORE if not SERVER_STEM.match(s))
    if stray:
        print(f"  selftest BAD  IN_CORE names non-server stems: {stray}", file=sys.stderr)
        bad += 1
    else:
        print("  selftest ok   IN_CORE names only server-layer stems")

    bad += _extension_selftest()

    if bad:
        print(f"  layer-direction selftest FAIL: {bad} row(s)", file=sys.stderr)
        return 1
    print("  layer-direction selftest: every row held")
    return 0


# A core of the pico crate in miniature: an item of each visibility and kind the rules tell apart.
_EXT_CORE: dict[str, str] = {
    "abi.rs": (
        "pub struct z_owned_string_t {\n"
        "    pub(crate) handle: *mut u8,\n"
        "    pub(crate) _pad: [*mut u8; 3],\n"
        "}\n"
        "pub struct z_id_t {\n"
        "    pub id: [u8; 16],\n"
        "}\n"
        "macro_rules! handle {\n"
        "    ($owned:ident) => {\n"
        "        pub struct $owned {\n"
        "            pub(crate) handle: *mut u8,\n"
        "        }\n"
        "    };\n"
        "}\n"
        "handle!(z_owned_bytes_t);\n"
    ),
    "session.rs": (
        "pub struct z_loaned_session_t {\n"
        "    pub(crate) _val: *mut u8,\n"
        "    pub(crate) _cnt: *mut u8,\n"
        "}\n"
        "pub(crate) unsafe fn session_handle(zs: *const z_loaned_session_t) -> Option<u8> {\n"
        "    None\n"
        "}\n"
        "pub unsafe fn session_state(zs: *const z_loaned_session_t) -> Option<u8> {\n"
        "    None\n"
        "}\n"
        "#[no_mangle]\n"
        'pub unsafe extern "C" fn z_session_loan(obj: *const u8) -> *const z_loaned_session_t {\n'
        "    obj.cast()\n"
        "}\n"
    ),
    "session_ext.rs": "pub(crate) struct PicoSessionExt;\n",
    "ffi.rs": "pub(crate) fn guarded() {}\npub(crate) struct InCallback;\n",
    "result.rs": "pub type ZResult = i8;\npub const Z_OK: ZResult = 0;\n",
    "bytes.rs": (
        "pub(crate) unsafe fn store_owned_string() {}\n"
        "#[no_mangle]\n"
        'pub unsafe extern "C" fn z_string_copy_from_substr() {}\n'
    ),
    "ext_interface.rs": (
        "pub struct wz_ext_session_facts_t {\n"
        "    pub closed: u8,\n"
        "}\n"
        "fn holds() -> bool {\n"
        "    true\n"
        "}\n"
        "#[no_mangle]\n"
        'pub unsafe extern "C" fn wz_ext_interface_version() {}\n'
    ),
    "lib.rs": (
        "mod prelude {}\npub mod abi;\npub mod bytes;\npub mod ext_interface;\nmod ffi;\n"
        "pub mod result;\npub mod session;\nmod session_ext;\nmod e2e;\npub mod e2e_sender;\n"
    ),
    "e2e.rs": "pub(crate) fn locked() {}\n",
}

_EXT_DOORS = frozenset({"e2e", "e2e_sender"})
_EXT_DEPS = {"wz_app_frame", "wz_session_core", "wz_capi_port"}

# A door that names the core as the rules allow: the C ABI, the interface, a sibling door, a
# boundary helper, the stack's libraries, and in prose and a literal what it may not.
_EXT_CLEAN = """//! `crate::session::session_handle` in prose is no reach.
use core::ffi::c_void;
use wz_app_frame::e2e_frame::Values;
use wz_session_core::caps::E2E_SENDER_SLOTS;
use wz_session_core::replay_publisher::{Dispatch, ReplayPublisher};
use crate::abi::{z_id_t, z_owned_bytes_t, z_owned_string_t};
use crate::bytes::z_string_copy_from_substr;
use crate::e2e::locked;
use crate::ext_interface::{wz_ext_interface_version, wz_ext_session_facts_t};
use crate::ffi::guarded;
use crate::result::{ZResult, Z_OK};
use crate::session::{z_loaned_session_t, z_session_loan};

struct Own {
    handle: u8,
}

fn own(o: &Own) -> u8 {
    o.handle
}

fn id() -> z_id_t {
    let text = "crate::session::session_handle(s)";
    let facts = wz_ext_session_facts_t { closed: 0 };
    let id = z_id_t { id: [0; 16] };
    if Z_OK == 0 {
    }
    id
}
"""


# The doors' library's view in miniature: a loan only pointed at, of no size, and a loan the doors
# keep a copy of, of the core's size.
_EXT_VIEW = """pub mod pubsub {
    /// A loaned publisher, only pointed at.
    #[repr(C)]
    pub struct z_loaned_publisher_t {
        _opaque: [u8; 0],
    }
}
pub mod session {
    /// A loaned session, two words of the core's.
    #[repr(C)]
    pub struct z_loaned_session_t {
        _opaque: [*mut core::ffi::c_void; 2],
    }
}
"""


def _extension_fixture(
    root: Path,
    door: str = "",
    core: dict[str, str | None] | None = None,
    view: str | None = _EXT_VIEW,
) -> Path:
    """The fixture crate's `src` under `root`, its door `e2e_sender` the clean one and `door`,
    and the doors' library's view beside it."""
    src = root / PICO / "src"
    src.mkdir(parents=True)
    files: dict[str, str | None] = {**_EXT_CORE, "e2e_sender.rs": _EXT_CLEAN + door}
    files.update(core or {})
    for name, text in files.items():
        if text is not None:
            (src / name).write_text(text, encoding="utf-8")
    if view is not None:
        path = root / EXT_CRATE / VIEW_FILE
        path.parent.mkdir(parents=True)
        path.write_text(view, encoding="utf-8")
    return src


def _extension_selftest() -> int:
    """The rows of rules 4 to 8, red-first; how many did not hold."""
    session_names_a_door = _EXT_CORE["session.rs"] + "use crate::e2e_sender::thing;\n"
    interface_names_a_door = _EXT_CORE["ext_interface.rs"] + "// read by crate::e2e\n"
    # (name, door text, core files, doors, should fail, substring a finding carries)
    rows: list[tuple[str, str, dict[str, str | None], frozenset[str], bool, str]] = [
        ("a door that keeps to the ABI and the interface", "", {}, _EXT_DOORS, False, ""),
        (
            "a restricted function of the core",
            "use crate::session::session_handle;\n",
            {}, _EXT_DOORS, True, "`pub(crate)` to the core",
        ),
        (
            "a Rust function of the core",
            "use crate::session::session_state;\n",
            {}, _EXT_DOORS, True, "a Rust function of the core",
        ),
        (
            "a private module of the core",
            "use crate::session_ext::PicoSessionExt;\n",
            {}, _EXT_DOORS, True, "a private module of the core",
        ),
        (
            "a stateful item beside the boundary helpers",
            "use crate::ffi::InCallback;\n",
            {}, _EXT_DOORS, True, "boundary helpers",
        ),
        (
            "an inline path to a restricted helper",
            "fn f() {\n    unsafe { crate::bytes::store_owned_string() }\n}\n",
            {}, _EXT_DOORS, True, "`pub(crate)` to the core",
        ),
        (
            "a super path to a restricted helper",
            "use super::session::session_handle;\n",
            {}, _EXT_DOORS, True, "`pub(crate)` to the core",
        ),
        ("a glob of a core module", "use crate::session::*;\n", {}, _EXT_DOORS, True, "a glob"),
        ("a core module whole", "use crate::session;\n", {}, _EXT_DOORS, True, "module whole"),
        (
            "a root name that is no C name",
            "fn g() {\n    let _ = crate::keyexpr_str;\n}\n",
            {}, _EXT_DOORS, True, "no module of the crate root",
        ),
        (
            "the engine port",
            "use wz_capi_port::observation::events;\n",
            {}, _EXT_DOORS, True, "a crate of the core's own",
        ),
        (
            "a limit of the core",
            "fn h() -> usize {\n    wz_session_core::caps::QUERIER_MAX_PENDING_QUERIES\n}\n",
            {}, _EXT_DOORS, True, "a build limit",
        ),
        (
            "a session-core module that is no library",
            "use wz_session_core::session::Session;\n",
            {}, _EXT_DOORS, True, "not one of the library modules",
        ),
        (
            "an associated item of an imported core type",
            "fn n() {\n    let _ = z_owned_string_t::null_value();\n}\n",
            {}, _EXT_DOORS, True, "an associated item of the core's",
        ),
        (
            "an associated item through a path",
            "fn p() {\n    let _ = crate::abi::z_owned_string_t::null_value();\n}\n",
            {}, _EXT_DOORS, True, "an associated item or nested path",
        ),
        (
            "an associated item through a renamed import",
            "use crate::abi::z_owned_string_t as S;\nfn q() {\n    let _ = S::null_value();\n}\n",
            {}, _EXT_DOORS, True, "an associated item of the core's",
        ),
        (
            "a literal of a core type with fields of its own",
            "fn r() {\n    let _ = z_loaned_session_t { _val: 0 as _, _cnt: 0 as _ };\n}\n",
            {}, _EXT_DOORS, True, "whose field `_val` is the core's own",
        ),
        (
            "a literal of a type a macro declares",
            "fn s() {\n    let _ = z_owned_bytes_t { handle: 0 as _ };\n}\n",
            {}, _EXT_DOORS, True, "fields the gate cannot read",
        ),
        (
            "a read of a field private to the core",
            "fn t(s: *const z_loaned_session_t) -> *mut u8 {\n    unsafe { (*s)._cnt }\n}\n",
            {}, _EXT_DOORS, True, "a field private to a core type",
        ),
        (
            "a private helper of the interface",
            "use crate::ext_interface::holds;\n",
            {}, _EXT_DOORS, True, "`private` to the core",
        ),
        (
            "the interface whole",
            "use crate::ext_interface::*;\n",
            {}, _EXT_DOORS, True, "the interface module whole",
        ),
        (
            "the core names a door",
            "", {"session.rs": session_names_a_door}, _EXT_DOORS, True,
            "names the extension door `e2e_sender`",
        ),
        (
            "the interface names a door in a comment",
            "", {"ext_interface.rs": interface_names_a_door}, _EXT_DOORS, True,
            "names the extension door `e2e`",
        ),
        (
            "a listed door with no file",
            "", {}, _EXT_DOORS | {"instance_key"}, True, "EXTENSION_DOORS names `instance_key`",
        ),
        (
            "no interface",
            "", {"ext_interface.rs": None}, _EXT_DOORS, True, "has no `ext_interface.rs`",
        ),
        (
            "a loan of no size kept in a field",
            "struct Kept {\n    publisher: z_loaned_publisher_t,\n}\n",
            {}, _EXT_DOORS, True, "declares of no size",
        ),
        (
            "a loan of no size read into a local",
            "unsafe fn v(p: *const z_loaned_publisher_t) {\n"
            "    let _kept: z_loaned_publisher_t = core::ptr::read(p);\n}\n",
            {}, _EXT_DOORS, True, "declares of no size",
        ),
        (
            "the size of a loan of no size",
            "fn w() -> usize {\n    core::mem::size_of::<z_loaned_publisher_t>()\n}\n",
            {}, _EXT_DOORS, True, "declares of no size",
        ),
        (
            "a loan of no size pointed at, referred to and cast to",
            "fn x(p: *const z_loaned_publisher_t, q: &z_loaned_publisher_t) "
            "-> *mut z_loaned_publisher_t {\n"
            "    p.cast::<z_loaned_publisher_t>().cast_mut()\n}\n",
            {}, _EXT_DOORS, False, "",
        ),
        (
            "a loan the view sizes as the core's, kept in a field",
            "struct Held {\n    session: z_loaned_session_t,\n}\n",
            {}, _EXT_DOORS, False, "",
        ),
    ]
    bad = 0
    for name, door, core, doors, should_fail, needle in rows:
        with tempfile.TemporaryDirectory() as tmp:
            src = _extension_fixture(Path(tmp), door, core)
            findings, _census = grade_extension(src, _EXT_DEPS, doors)
        failed = bool(findings)
        ok = failed == should_fail and (not should_fail or any(needle in f for f in findings))
        print(f"  selftest {'ok  ' if ok else 'BAD '} {name}: "
              f"{'refused' if failed else 'accepted'}")
        if not ok:
            bad += 1
            for f in findings:
                print(f"      {f}", file=sys.stderr)

    # Nothing to read is refused, not passed.
    zero_rows = [
        ("no crate root", {"lib.rs": None}, _EXT_DOORS, "no crate root"),
        ("no door file", {}, frozenset({"absent"}), "no extension door file"),
    ]
    for name, core, doors, needle in zero_rows:
        with tempfile.TemporaryDirectory() as tmp:
            src = _extension_fixture(Path(tmp), "", core)
            try:
                grade_extension(src, _EXT_DEPS, doors)
                ok = False
            except InputError as e:
                ok = needle in str(e)
        print(f"  selftest {'ok  ' if ok else 'BAD '} {name}: refused")
        if not ok:
            bad += 1

    # Without the view the types the doors only point at are unknown: refused, not passed.
    view_rows = [
        ("no view of the core", None, "no view of the core"),
        ("a view with no type of no size", "pub mod abi {}\n", "no type of no size"),
    ]
    for name, view, needle in view_rows:
        with tempfile.TemporaryDirectory() as tmp:
            src = _extension_fixture(Path(tmp), view=view)
            try:
                grade_extension(src, _EXT_DEPS, _EXT_DOORS)
                ok = False
            except InputError as e:
                ok = needle in str(e)
        print(f"  selftest {'ok  ' if ok else 'BAD '} {name}: refused")
        if not ok:
            bad += 1

    # A crate only the pico crate's tests link is not a crate of the core's.
    meta = {
        "packages": [
            {
                "name": PICO,
                "id": PICO,
                "manifest_path": "/fixture/wz-capi-pico/Cargo.toml",
                "dependencies": [
                    _dep("wz-capi-port"),
                    _dep("wz-session-core", None, "cfg(unix)"),
                    _dep("wz-test-support", "dev"),
                ],
            }
        ],
        "workspace_members": [PICO],
    }
    _src, deps = pico_crate(meta)
    ok = deps == {"wz_capi_port", "wz_session_core"}
    print(f"  selftest {'ok  ' if ok else 'BAD '} the library's dependencies, not the tests'")
    if not ok:
        bad += 1
        print(f"      read {sorted(deps)}", file=sys.stderr)
    return bad


def main(argv: list[str]) -> int:
    modes = {"--check": check, "--selftest": selftest}
    if len(argv) != 2 or argv[1] not in modes:
        print(
            "usage: layer_direction_gate.py --check | --selftest "
            "(a mode is required; there is no default)",
            file=sys.stderr,
        )
        return 2
    return modes[argv[1]]()


if __name__ == "__main__":
    sys.exit(main(sys.argv))
