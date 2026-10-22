#!/usr/bin/env python3
# SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
# SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
"""R3398 (no register item) -- the build configuration of wz is declared once; this derives from it.

It carries the capability declaration of R3398 and the limit declaration of R3403 (no register
item), both now one file, as step 1 of docs/build-configuration.md.

## What this is

`deploy/wz-config.toml` declares every switch a build can turn (docs/build-configuration.md,
decision C1): the capabilities of the C ABI builds (their Kconfig symbol, the ABIs that export
them, what they imply, zenoh-pico's own switch for them) and the limits an image states for
itself (their Kconfig symbol, default and help). This tool is everything that derives from it:

    --emit kconfig-capabilities   print deploy/Kconfig.capabilities
    --emit kconfig-limits         print deploy/Kconfig.limits
    --emit rust-limits            print crates/wz-session-core/src/caps_generated.rs
    --write                       write all three
    --features ABI CONFIG         turn a Kconfig result (or a pico config.h) into the cargo arguments
    --check                       hold every derived file, caps.rs and the three manifests to it
    --selftest                    drive the reader, the derivations and the check on what can be wrong

## Why a declaration and not three manifests and a Rust row

wz-capi-core, wz-capi-pico and wz-capi-c each spell the same capability graph by hand in
`[features]`. Three hand-kept copies drift: `peer` implies `scout`, and a manifest that forgot it
would build a listener that cannot answer a Scout and say nothing. The declaration is the one
place the graph is written; `--check` is what makes the manifests follow it. The manifests are
checked, not generated, on purpose: Cargo cannot include a fragment, and each carries, beside the
capability edges, the runtime features that capability turns on, with the measured reason for each.

A limit's name, default and help used to be read off its row in caps.rs. They are declared here
with the capabilities, so one file holds every switch an image or a preset can name; the value the
code reads comes from the generated module, and caps.rs keeps the developer's documentation of each
limit and binds the name the code uses to the generated value.

## The rules `--check` holds

  1. Each generated file equals what `--emit` prints now.
  2. For each ABI crate (pico, c): every capability the declaration gives it is a feature, and
     the capability-to-capability edges of that feature are EXACTLY the declared `implies`
     restricted to the capabilities the crate has; it forwards `wz-capi-core/<id>`.
  3. For the core: the same capabilities are features, their edges are a SUBSET of the declared
     `implies` (the core is the model; it does not repeat an ABI's rule), and the default set
     is the base plus every capability that is on by default.
  4. The default features of each ABI crate are its base plus every capability it has that is
     on by default. A capability is on by default unless declared `default = "off"`, which is
     for a switch the reference library itself leaves off (pico's local delivery, its admin
     space): the drop-in's default exports what the reference build does.
  5. No capability feature exists in a manifest that the declaration does not name.
  6. caps.rs binds every declared limit exactly once, as `pub const <ID>: usize = generated::<ID>;`,
     and binds nothing else to the generated module; no `pub const <NAME>: usize = <number>;`
     there is a bare literal, and none reads `WZ_LIMIT_*` itself: a limit outside the declaration
     could not be stated by an image.

Usage:
    wz_config.py --check | --selftest | --write
    wz_config.py --emit kconfig-capabilities | kconfig-limits | rust-limits
    wz_config.py --features pico|c|core CONFIG
        CONFIG is a Kconfig `.config` (CONFIG_WZ_CAP_X=y) or a pico header of
        `#define Z_FEATURE_X 0|1` lines; a capability the file does not mention is OFF.
"""

from __future__ import annotations

import functools
import importlib
import json
import pathlib
import re
import subprocess
import sys

ROOT = pathlib.Path(__file__).resolve().parents[2]
DECL = ROOT / "deploy" / "wz-config.toml"
KCONFIG_CAPS = ROOT / "deploy" / "Kconfig.capabilities"
KCONFIG_LIMITS = ROOT / "deploy" / "Kconfig.limits"
RUST_LIMITS = ROOT / "crates" / "wz-session-core" / "src" / "caps_generated.rs"
CAPS_RS = ROOT / "crates" / "wz-session-core" / "src" / "caps.rs"
MANIFESTS = {
    "core": ROOT / "crates" / "wz-capi-core" / "Cargo.toml",
    "pico": ROOT / "crates" / "wz-capi-pico" / "Cargo.toml",
    "c": ROOT / "crates" / "wz-capi-c" / "Cargo.toml",
}
ABIS = ("core", "pico", "c")
SCHEMA_VERSION = 1
# rustfmt's default `max_width`; the crates carry no rustfmt.toml.
RUST_MAX_WIDTH = 100

SPDX = (
    "SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR "
    "LicenseRef-watching-zenoh-Commercial"
)
COPYRIGHT = "SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael"


# ---------------------------------------------------------------------------------------------
# the reader
# ---------------------------------------------------------------------------------------------


def read_decl_toml(text: str) -> dict:
    """The declaration file's TOML, read without `tomllib`.

    `tomllib` is stdlib from python 3.11 and the hosted floor is 3.10, so importing it died in
    Layer C0 on the first hosted run of the reader this one grew from. The declaration uses one
    small shape and this reads exactly that: `[table]` and `[[array of tables]]` headers;
    `key = value` on ONE line, the value a string, an integer or an array of strings; a `'''`
    literal string whose lines run to the closing `'''` (the newline right after the opening
    delimiter is not part of it, as TOML says); `#` comments on lines of their own. Anything else
    is refused by line number rather than skipped, so the file cannot grow a shape this reader
    silently drops. `--selftest` holds it to `tomllib` wherever the interpreter has one.
    """
    root: dict = {}
    table = root
    lines = text.splitlines()
    number = 0
    while number < len(lines):
        raw = lines[number]
        number += 1
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        header = re.fullmatch(r"\[\[([A-Za-z0-9_-]+)\]\]|\[([A-Za-z0-9_-]+)\]", line)
        if header:
            if header.group(1):
                table = {}
                root.setdefault(header.group(1), []).append(table)
            else:
                table = root.setdefault(header.group(2), {})
            continue
        pair = re.fullmatch(r"([A-Za-z0-9_-]+)\s*=\s*(.+)", line)
        if not pair:
            raise ValueError(f"line {number}: not a shape this reader knows: {line!r}")
        key, rest = pair.group(1), pair.group(2)
        if rest == "'''":
            start = number
            body: list[str] = []
            while number < len(lines) and lines[number] != "'''":
                body.append(lines[number])
                number += 1
            if number == len(lines):
                raise ValueError(f"line {start}: a ''' string is never closed")
            number += 1
            value: object = "\n".join(body) + "\n"
        elif rest.startswith("'''"):
            raise ValueError(f"line {number}: a ''' string opens a line of its own")
        else:
            try:
                value = json.loads(rest)
            except ValueError:
                raise ValueError(
                    f"line {number}: value is not a one-line string, integer or string array"
                ) from None
            if isinstance(value, bool) or not (
                isinstance(value, (str, int))
                or (isinstance(value, list) and all(isinstance(x, str) for x in value))
            ):
                raise ValueError(f"line {number}: value is not a string, integer or string array")
        if key in table:
            raise ValueError(f"line {number}: key `{key}` is set twice")
        table[key] = value
    return root


def load_decl(path: pathlib.Path = DECL) -> dict:
    data = read_decl_toml(path.read_text(encoding="utf-8"))
    problems = validate_decl(data)
    if problems:
        raise ValueError("; ".join(problems))
    caps = {c["id"]: c for c in data["capability"]}
    return {
        "catalog_version": data["catalog_version"],
        "base": data["base"],
        "caps": caps,
        "order": [c["id"] for c in data["capability"]],
        "limits": list(data["limit"]),
    }


def validate_decl(data: dict) -> list[str]:
    out: list[str] = []
    if data.get("schema_version") != SCHEMA_VERSION:
        out.append(f"schema_version is {data.get('schema_version')!r}, this reader is {SCHEMA_VERSION}")
    if not isinstance(data.get("catalog_version"), int):
        out.append("catalog_version is not an integer")
    for kind in ("base", "capability", "limit"):
        if kind not in data:
            out.append(f"the declaration has no `{kind}`")
    if out:
        return out
    out += validate_caps(data)
    out += validate_limits(data["limit"])
    symbols = [c["kconfig"] for c in data["capability"]] + [l["kconfig"] for l in data["limit"]]
    if len(symbols) != len(set(symbols)):
        out.append("a Kconfig symbol is declared twice")
    return out


def validate_caps(data: dict) -> list[str]:
    out: list[str] = []
    caps = {c["id"]: c for c in data["capability"]}
    ids = [c["id"] for c in data["capability"]]
    if len(ids) != len(set(ids)):
        out.append("a capability id is declared twice")
    for c in data["capability"]:
        for dep in c["implies"]:
            if dep not in caps:
                out.append(f"{c['id']} implies `{dep}`, which is not declared")
        for abi in c["abis"]:
            if abi not in ABIS:
                out.append(f"{c['id']} names the unknown ABI `{abi}`")
        if "core" not in c["abis"]:
            out.append(f"{c['id']} is not in core, and every capability is")
        if not c["kconfig"].startswith("WZ_CAP_"):
            out.append(f"{c['id']}: Kconfig symbol `{c['kconfig']}` is not WZ_CAP_*")
        if c.get("default", "on") not in ("on", "off"):
            out.append(f"{c['id']}: default is `{c['default']}`, which is neither on nor off")
        if "pico_flag" in c and "pico_flags_all" in c:
            out.append(f"{c['id']} names both a pico_flag and pico_flags_all; it is one or the other")
        for flag in [c.get("pico_flag", "Z_FEATURE_")] + c.get("pico_flags_all", []):
            if not flag.startswith("Z_FEATURE_"):
                out.append(f"{c['id']}: pico switch `{flag}` is not Z_FEATURE_*")
    # A dependency cycle would make the closure below loop.
    for start in caps:
        seen: set[str] = set()
        stack = [d for d in caps[start]["implies"] if d in caps]
        while stack:
            cur = stack.pop()
            if cur == start:
                out.append(f"{start} implies itself through a cycle")
                break
            if cur not in seen:
                seen.add(cur)
                stack.extend(d for d in caps[cur]["implies"] if d in caps)
    return out


def validate_limits(limits: list[dict]) -> list[str]:
    out: list[str] = []
    ids = [l.get("id") for l in limits]
    if len(ids) != len(set(ids)):
        out.append("a limit id is declared twice")
    for lim in limits:
        lid = lim.get("id", "?")
        if not re.fullmatch(r"[A-Z][A-Z0-9_]*", str(lid)):
            out.append(f"limit `{lid}`: an id is a Rust constant name, SCREAMING_SNAKE_CASE")
        if lim.get("kconfig") != f"WZ_LIMIT_{lid}":
            out.append(f"limit `{lid}`: its Kconfig symbol is `{lim.get('kconfig')}`, not WZ_LIMIT_{lid}")
        if not isinstance(lim.get("default"), int) or lim["default"] < 0:
            out.append(f"limit `{lid}`: default is not a non-negative integer")
        if not isinstance(lim.get("help"), str) or not lim["help"].strip():
            out.append(f"limit `{lid}`: it has no help")
        elif "\n\n" in lim["help"].strip():
            out.append(f"limit `{lid}`: its help is more than one paragraph")
    return out


# ---------------------------------------------------------------------------------------------
# the capability graph
# ---------------------------------------------------------------------------------------------


def default_on(cap: dict) -> bool:
    """Whether a build that names nothing has the capability: on unless declared `off`."""
    return cap.get("default", "on") == "on"


def closure(caps: dict, on: set[str]) -> set[str]:
    """`on` plus everything it implies, transitively."""
    out = set(on)
    stack = list(on)
    while stack:
        for dep in caps[stack.pop()]["implies"]:
            if dep not in out:
                out.add(dep)
                stack.append(dep)
    return out


CONFIG_RE = re.compile(r"^\s*CONFIG_(WZ_CAP_[A-Z0-9_]+)\s*=\s*y\s*$")
DEFINE_RE = re.compile(r"^\s*#\s*define\s+(Z_FEATURE_[A-Z0-9_]+)\s+([01])\b")
# pico writes one switch, `Z_FEATURE_UNSTABLE_API`, through `#cmakedefine`: a bare `#define`
# when it is on and `/* #undef ... */` when it is off, and its headers test it with `#ifdef`.
BARE_DEFINE_RE = re.compile(r"^\s*#\s*define\s+(Z_FEATURE_[A-Z0-9_]+)\s*(?://.*|/\*.*)?$")


def read_config(decl: dict, text: str) -> set[str]:
    """The capabilities a `.config` or pico header turns ON. Unmentioned means off.

    A capability with a `pico_flag` is on when that switch is; one with `pico_flags_all`
    has no switch of its own in pico and is on when every switch it names is (the
    liveliness get exists where pico has both the liveliness and the query plane).
    """
    by_kconfig = {c["kconfig"]: cid for cid, c in decl["caps"].items()}
    on: set[str] = set()
    flags_on: set[str] = set()
    for line in text.splitlines():
        m = CONFIG_RE.match(line)
        if m and m.group(1) in by_kconfig:
            on.add(by_kconfig[m.group(1)])
            continue
        d = DEFINE_RE.match(line)
        if d and d.group(2) == "1":
            flags_on.add(d.group(1))
            continue
        b = BARE_DEFINE_RE.match(line)
        if b:
            flags_on.add(b.group(1))
    for cid, cap in decl["caps"].items():
        if cap.get("pico_flag") in flags_on:
            on.add(cid)
        elif cap.get("pico_flags_all") and set(cap["pico_flags_all"]) <= flags_on:
            on.add(cid)
    return on


def features_for(decl: dict, abi: str, on: set[str]) -> list[str]:
    """The `--features` list of `abi` for the capabilities `on`, implications included."""
    have = closure(decl["caps"], on)
    mine = [cid for cid in decl["order"] if abi in decl["caps"][cid]["abis"] and cid in have]
    return list(decl["base"][abi]) + mine


def cargo_args(decl: dict, abi: str, on: set[str]) -> str:
    feats = features_for(decl, abi, on)
    return "--no-default-features" + (f" --features {','.join(feats)}" if feats else "")


# ---------------------------------------------------------------------------------------------
# the derived files
# ---------------------------------------------------------------------------------------------


def generated_header(comment: str, emit: str) -> list[str]:
    return [
        f"{comment} {SPDX}",
        f"{comment} {COPYRIGHT}",
        comment,
        f"{comment} GENERATED from deploy/wz-config.toml by scripts/lib/wz_config.py --emit {emit}.",
        f"{comment} Do not edit: `wz_config.py --check` fails when this file is stale.",
    ]


def emit_kconfig_capabilities(decl: dict) -> str:
    lines = generated_header("#", "kconfig-capabilities") + [
        "",
        'menu "wz C ABI capabilities"',
        "",
    ]
    caps = decl["caps"]
    for cid in decl["order"]:
        cap = caps[cid]
        lines.append(f"config {cap['kconfig']}")
        lines.append(f'\tbool "{cid}"')
        lines.append("\tdefault y" if default_on(cap) else "\tdefault n")
        for dep in cap["implies"]:
            lines.append(f"\tselect {caps[dep]['kconfig']}")
        lines.append("\thelp")
        lines.append(f"\t  {cap['help']}")
        flag = cap.get("pico_flag")
        if flag:
            lines.append(f"\t  zenoh-pico's switch for it: {flag}.")
        flags = cap.get("pico_flags_all")
        if flags:
            lines.append(f"\t  zenoh-pico has it when all of these are on: {', '.join(flags)}.")
        lines.append(f"\t  Exported by: {', '.join(a for a in cap['abis'] if a != 'core')}.")
        lines.append("")
    lines.append("endmenu")
    return "\n".join(lines) + "\n"


def emit_kconfig_limits(decl: dict) -> str:
    out = generated_header("#", "kconfig-limits") + [
        "",
        'menu "wz limits"',
        "",
        'comment "Each limit sizes a table of every session of the image; a build states its own."',
        "",
    ]
    for lim in decl["limits"]:
        out.append(f"config {lim['kconfig']}")
        out.append(f'\tint "{lim["id"]}"')
        out.append(f"\tdefault {lim['default']}")
        out.append("\thelp")
        for line in lim["help"].strip().splitlines():
            out.append(f"\t  {line}" if line else "\t")
        out.append("")
    out.append("endmenu")
    return "\n".join(out) + "\n"


def rust_const(name: str, value: str) -> list[str]:
    """`pub(super) const <name>: usize = <value>;` laid out as rustfmt lays it out."""
    one = f"pub(super) const {name}: usize = {value};"
    if len(one) <= RUST_MAX_WIDTH:
        return [one]
    return [f"pub(super) const {name}: usize =", f"    {value};"]


def emit_rust_limits(decl: dict) -> str:
    out = generated_header("//", "rust-limits") + [
        "",
        "//! The value of each limit as the code reads it: the number the build's environment states",
        "//! as `WZ_LIMIT_<NAME>`, or the declared default when it states none. The names the code uses",
        "//! are bound to these in `caps.rs`, beside the documentation of each.",
        "",
        "use super::limit;",
        "",
    ]
    for lim in decl["limits"]:
        value = f'limit(option_env!("{lim["kconfig"]}"), {lim["default"]})'
        out += rust_const(lim["id"], value)
    return "\n".join(out) + "\n"


GENERATED = {
    "kconfig-capabilities": (KCONFIG_CAPS, emit_kconfig_capabilities),
    "kconfig-limits": (KCONFIG_LIMITS, emit_kconfig_limits),
    "rust-limits": (RUST_LIMITS, emit_rust_limits),
}


# ---------------------------------------------------------------------------------------------
# caps.rs and the manifests
# ---------------------------------------------------------------------------------------------

BINDING_RE = re.compile(
    r"^pub const (?P<name>[A-Z0-9_]+): usize =\s*generated::(?P<target>[A-Z0-9_]+);", re.MULTILINE
)
BARE_RE = re.compile(r"^pub const (?P<name>[A-Z0-9_]+): usize =\s*\d+;", re.MULTILINE)
STATED_RE = re.compile(r'option_env!\("WZ_LIMIT_')


def check_caps_rs(decl: dict, text: str) -> list[str]:
    out: list[str] = []
    declared = [l["id"] for l in decl["limits"]]
    bound: dict[str, int] = {}
    for m in BINDING_RE.finditer(text):
        if m.group("name") != m.group("target"):
            out.append(f"caps.rs binds {m.group('name')} to generated::{m.group('target')}, "
                       "another limit's value")
        bound[m.group("target")] = bound.get(m.group("target"), 0) + 1
    for lid in declared:
        if bound.get(lid, 0) != 1:
            out.append(f"caps.rs binds the declared limit {lid} {bound.get(lid, 0)} times, not once")
    for name in sorted(set(bound) - set(declared)):
        out.append(f"caps.rs binds generated::{name}, which the declaration does not name")
    for m in BARE_RE.finditer(text):
        out.append(f"caps.rs: {m.group('name')} is a bare literal; it cannot be stated by an image")
    # The module documentation names the form a limit is read by; only code that reads one counts.
    code = "\n".join(line for line in text.splitlines() if not line.lstrip().startswith("//"))
    if STATED_RE.search(code):
        out.append("caps.rs reads a WZ_LIMIT_* itself; a limit's value comes from the generated module")
    return out


@functools.cache
def workspace_features() -> dict:
    """Every workspace package's `[features]` table, keyed by manifest path.

    Cargo is asked rather than the manifest text parsed: the manifests carry multi-line arrays
    with comments between the entries, which is not worth a hand-rolled reader, and cargo is
    the reader that decides what a feature means.
    """
    proc = subprocess.run(
        ["cargo", "metadata", "--no-deps", "--format-version", "1", "--offline"],
        cwd=ROOT / "crates",
        capture_output=True,
        text=True,
    )
    if proc.returncode != 0:
        raise OSError(f"`cargo metadata` failed, so the manifests have no input: {proc.stderr.strip()}")
    return {
        pathlib.Path(p["manifest_path"]).resolve(): p["features"]
        for p in json.loads(proc.stdout)["packages"]
    }


def manifest_features(path: pathlib.Path) -> dict:
    feats = workspace_features().get(path.resolve())
    if feats is None:
        raise KeyError(f"{path} is not a package of the crates workspace")
    return feats


def check_manifest(decl: dict, abi: str, feats: dict) -> list[str]:
    out: list[str] = []
    caps = decl["caps"]
    mine = {cid for cid, c in caps.items() if abi in c["abis"]}
    for cid in sorted(mine):
        if cid not in feats:
            out.append(f"{abi}: capability `{cid}` is declared but is no feature")
            continue
        edges = {x for x in feats[cid] if x in caps}
        declared = set(caps[cid]["implies"]) & mine
        if abi == "core":
            if not edges <= set(caps[cid]["implies"]):
                out.append(f"core: `{cid}` implies {sorted(edges - set(caps[cid]['implies']))}, "
                           f"which the declaration does not")
        elif edges != declared:
            out.append(f"{abi}: `{cid}` implies {sorted(edges)}, declared {sorted(declared)}")
        if abi != "core" and f"wz-capi-core/{cid}" not in feats[cid]:
            out.append(f"{abi}: `{cid}` does not forward wz-capi-core/{cid}")
    others = set(caps) - mine
    for cid in sorted(others & set(feats)):
        out.append(f"{abi}: has a feature `{cid}` the declaration does not give this ABI")
    default = set(feats.get("default", []))
    want = set(decl["base"][abi]) | {cid for cid in mine if default_on(caps[cid])}
    if default != want:
        out.append(f"{abi}: default is {sorted(default)}, expected {sorted(want)}")
    return out


# ---------------------------------------------------------------------------------------------
# the commands
# ---------------------------------------------------------------------------------------------


def cmd_check() -> int:
    try:
        decl = load_decl()
    except (ValueError, KeyError, OSError) as exc:
        print(f"  wz-config FAIL: {DECL.name}: {exc}", file=sys.stderr)
        return 1
    findings: list[str] = []
    for kind, (path, emit) in GENERATED.items():
        rel = path.relative_to(ROOT)
        if not path.is_file():
            findings.append(f"{rel} is missing (--emit {kind} prints it)")
        elif path.read_text(encoding="utf-8") != emit(decl):
            findings.append(f"{rel} is stale: regenerate it with --write")
    findings += check_caps_rs(decl, CAPS_RS.read_text(encoding="utf-8"))
    for abi, path in MANIFESTS.items():
        try:
            feats = manifest_features(path)
        except (KeyError, OSError) as exc:
            print(f"  wz-config FAIL: {abi}: {exc}", file=sys.stderr)
            return 1
        findings += check_manifest(decl, abi, feats)
    for finding in findings:
        print(f"  wz-config FAIL: {finding}", file=sys.stderr)
    if findings:
        return 1
    print(f"  wz-config: {len(decl['order'])} capabilities, {len(decl['limits'])} limits, "
          f"{len(GENERATED)} generated files current, caps.rs bound, {len(MANIFESTS)} manifests agree")
    return 0


def cmd_write() -> int:
    decl = load_decl()
    for path, emit in GENERATED.values():
        path.write_text(emit(decl), encoding="utf-8")
        print(f"  wz-config: wrote {path.relative_to(ROOT)}")
    return 0


SAMPLE = """\
schema_version = 1
catalog_version = 3

[base]
core = []
pico = ["p"]
c = []

[[capability]]
id = "a"
kconfig = "WZ_CAP_A"
abis = ["core", "pico"]
implies = []
help = "A."

[[limit]]
id = "MAX_A"
kconfig = "WZ_LIMIT_MAX_A"
default = 4
help = '''
A table.
'''
"""


def cmd_selftest() -> int:
    ok = bad = 0

    def expect(name: str, cond: bool) -> None:
        nonlocal ok, bad
        if cond:
            ok += 1
        else:
            bad += 1
            print(f"  wz-config selftest FAIL: {name}", file=sys.stderr)

    decl = load_decl()
    caps = decl["caps"]
    # The capability graph and its derivations.
    expect("peer closes over scout and link-udp", closure(caps, {"peer"}) == {"peer", "scout", "link-udp"})
    expect("gossip closes over peer, scout, link-udp",
           closure(caps, {"gossip"}) == {"gossip", "peer", "scout", "link-udp"})
    expect("an ABI lists only the capabilities it has",
           "timestamping" not in features_for(decl, "pico", {"advanced"})
           and "timestamping" in features_for(decl, "c", {"advanced"}))
    expect("advanced pulls liveliness and queryable in pico",
           {"liveliness", "queryable"} <= set(features_for(decl, "pico", {"advanced"})))
    expect("nothing on is the base alone", features_for(decl, "pico", set()) == decl["base"]["pico"])
    expect("a .config reads y and ignores n and comments",
           read_config(decl, "CONFIG_WZ_CAP_QUERY=y\n# CONFIG_WZ_CAP_PEER is not set\n"
                             "CONFIG_WZ_CAP_GROUP=n\nCONFIG_OTHER=y\n") == {"query"})
    expect("a pico header reads 1 and not 0",
           read_config(decl, "#define Z_FEATURE_QUERY 1\n#define Z_FEATURE_QUERYABLE 0\n") == {"query"})
    expect("an off-by-default capability is `default n` in the Kconfig and reachable by its switch",
           "config WZ_CAP_ADMIN_SPACE\n\tbool \"admin-space\"\n\tdefault n"
           in emit_kconfig_capabilities(decl)
           and "admin-space" in read_config(decl, "#define Z_FEATURE_ADMIN_SPACE 1\n"))
    expect("a capability of several pico switches is on only when all of them are",
           "liveliness-get" in read_config(
               decl, "#define Z_FEATURE_LIVELINESS 1\n#define Z_FEATURE_QUERY 1\n")
           and "liveliness-get" not in read_config(
               decl, "#define Z_FEATURE_LIVELINESS 1\n#define Z_FEATURE_QUERY 0\n"))
    expect("a bare #define is on and a #cmakedefine's #undef is off",
           read_config(decl, "#define Z_FEATURE_UNSTABLE_API\n") == {"unstable-api"}
           and read_config(decl, "/* #undef Z_FEATURE_UNSTABLE_API */\n") == set())
    expect("advanced and connectivity pull the unstable API in pico",
           "unstable-api" in features_for(decl, "pico", {"advanced"})
           and "unstable-api" in features_for(decl, "pico", {"connectivity"}))
    expect("cargo args of nothing", cargo_args(decl, "c", set()) == "--no-default-features")
    expect("cargo args name the base then the closure",
           cargo_args(decl, "pico", {"peer"}).endswith("rx-busy-poll,link-udp,scout,peer"))
    kconfig = emit_kconfig_capabilities(decl)
    expect("peer selects scout in the Kconfig", "config WZ_CAP_PEER" in kconfig
           and "\tselect WZ_CAP_SCOUT" in kconfig)
    expect("every capability has a config entry",
           all(f"config {c['kconfig']}\n" in kconfig for c in caps.values()))
    # The manifest check must be able to fail: a manifest that loses an edge, or gains a feature.
    good = manifest_features(MANIFESTS["pico"])
    expect("the shipped pico manifest passes", check_manifest(decl, "pico", good) == [])
    lost = dict(good)
    lost["peer"] = [x for x in good["peer"] if x != "scout"]
    expect("a manifest that forgets peer -> scout is a finding",
           any("peer" in f for f in check_manifest(decl, "pico", lost)))
    extra = dict(good)
    extra["group"] = ["wz-capi-core/group"]
    expect("a feature the ABI does not have is a finding",
           any("group" in f for f in check_manifest(decl, "pico", extra)))
    nofwd = dict(good)
    nofwd["query"] = []
    expect("a missing forward to the core is a finding",
           any("forward" in f for f in check_manifest(decl, "pico", nofwd)))
    # The Kconfig path reaches the very builds the size gate grades: a config that selects
    # nothing derives the features of `pico-client` and of `capic-client`, and one that selects
    # `peer` those of `pico-peer` and `capic-peer`. Were the two to part, the budget would grade
    # a build nobody can ask for.
    sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
    import capability_cost_gate as cost

    graded = {c.id: c for c in cost.CASES}

    def derived(abi: str, on: set[str]) -> set[str]:
        return set(features_for(decl, abi, on))

    def graded_features(case_id: str) -> set[str]:
        return {f for f in graded[case_id].features.split(",") if f}

    expect("an empty selection is the graded pico-client",
           derived("pico", set()) == graded_features("pico-client"))
    expect("an empty selection is the graded capic-client",
           derived("c", set()) == graded_features("capic-client"))
    expect("peer is the graded pico-peer",
           derived("pico", {"peer"}) >= graded_features("pico-peer") - {"peer"}
           and "peer" in derived("pico", {"peer"}))
    expect("peer is the graded capic-peer",
           derived("c", {"peer"}) >= {"peer", "scout", "link-udp"}
           and graded_features("capic-peer") == {"peer"})
    # The limits and their derivations.
    sample = read_decl_toml(SAMPLE)
    expect("a sample declaration validates", validate_decl(sample) == [])
    sdecl = {"limits": sample["limit"]}
    expect("a ''' help keeps its lines and drops the newline after the opener",
           sample["limit"][0]["help"] == "A table.\n")
    expect("a limit is an int in the Kconfig with its default and help",
           "config WZ_LIMIT_MAX_A\n\tint \"MAX_A\"\n\tdefault 4\n\thelp\n\t  A table.\n"
           in emit_kconfig_limits(sdecl))
    expect("a limit's value reads its environment, then its default",
           'pub(super) const MAX_A: usize = limit(option_env!("WZ_LIMIT_MAX_A"), 4);'
           in emit_rust_limits(sdecl))
    long_name = "MAX_" + "X" * 80
    expect("a value line past rustfmt's width breaks after `=` as rustfmt does",
           rust_const(long_name, "limit(1)") == [f"pub(super) const {long_name}: usize =", "    limit(1);"])
    bound = "pub const MAX_A: usize = generated::MAX_A;\n"
    expect("one binding per limit is clean", check_caps_rs(sdecl, bound) == [])
    expect("a missing binding is a finding", any("0 times" in f for f in check_caps_rs(sdecl, "")))
    expect("a binding twice is a finding",
           any("2 times" in f for f in check_caps_rs(sdecl, bound + bound)))
    expect("a binding to another limit's value is a finding",
           any("another" in f for f in check_caps_rs(
               sdecl, "pub const MAX_A: usize = generated::MAX_B;\n")))
    expect("a bare literal is a finding",
           any("bare literal" in f for f in check_caps_rs(sdecl, bound + "pub const MAX_D: usize = 3;\n")))
    expect("a row that reads WZ_LIMIT_* itself is a finding",
           any("itself" in f for f in check_caps_rs(
               sdecl, bound + 'const X: usize = limit(option_env!("WZ_LIMIT_X"), 1);\n')))
    expect("documentation that names the form is not a reading",
           check_caps_rs(sdecl, bound + '//! read as `limit(option_env!("WZ_LIMIT_<NAME>"), d)`\n') == [])
    bad_limit = SAMPLE.replace('kconfig = "WZ_LIMIT_MAX_A"', 'kconfig = "WZ_LIMIT_MAX_B"')
    expect("a limit whose symbol is not its name is refused",
           any("not WZ_LIMIT_MAX_A" in p for p in validate_decl(read_decl_toml(bad_limit))))
    two_para = SAMPLE.replace("A table.\n'''", "A table.\n\nMore.\n'''")
    expect("a limit help of two paragraphs is refused",
           any("paragraph" in p for p in validate_decl(read_decl_toml(two_para))))
    expect("a declaration of another schema is refused",
           any("schema_version" in p for p in validate_decl(read_decl_toml(
               SAMPLE.replace("schema_version = 1", "schema_version = 2")))))

    # The reader must refuse what it does not read, and must agree with `tomllib` on the
    # shipped file wherever the interpreter has one (3.11+; the hosted floor does not, which is
    # why the import is by name and not a statement the floor lint reads).
    def refuses(text: str) -> bool:
        try:
            read_decl_toml(text)
        except ValueError:
            return False
        return True

    expect("a multi-line array is refused, not skipped", not refuses('a = [\n  "x",\n]\n'))
    expect("an inline table is refused", not refuses('a = { b = "c" }\n'))
    expect("a float is refused", not refuses("a = 1.5\n"))
    expect("a boolean is refused", not refuses("a = true\n"))
    expect("a key set twice is refused", not refuses('a = "x"\na = "y"\n'))
    expect("an unclosed ''' string is refused", not refuses("a = '''\nx\n"))
    expect("a ''' string sharing its opening line is refused", not refuses("a = '''x\n'''\n"))
    expect("a table, a table array, an integer and both string shapes are read",
           read_decl_toml('n = 3\n[t]\nk = "v"\n[[c]]\nx = ["a", "b"]\n[[c]]\nx = []\ny = \'\'\'\nl\n\'\'\'\n')
           == {"n": 3, "t": {"k": "v"}, "c": [{"x": ["a", "b"]}, {"x": [], "y": "l\n"}]})
    try:
        stdlib_toml = importlib.import_module("tomllib")
    except ImportError:
        stdlib_toml = None
    if stdlib_toml is not None:
        text = DECL.read_text(encoding="utf-8")
        expect("the declaration reads the same as tomllib reads it",
               read_decl_toml(text) == stdlib_toml.loads(text))
    cyc = {"capability": [
        {"id": "a", "kconfig": "WZ_CAP_A", "abis": ["core"], "implies": ["b"]},
        {"id": "b", "kconfig": "WZ_CAP_B", "abis": ["core"], "implies": ["a"]}]}
    expect("a dependency cycle is refused", any("cycle" in p for p in validate_caps(cyc)))
    print(f"  wz-config selftest: {ok}/{ok + bad} arm(s) pass")
    return 0 if bad == 0 else 1


def main(argv: list[str]) -> int:
    if len(argv) == 2 and argv[1] == "--check":
        return cmd_check()
    if len(argv) == 2 and argv[1] == "--selftest":
        return cmd_selftest()
    if len(argv) == 2 and argv[1] == "--write":
        return cmd_write()
    if len(argv) == 3 and argv[1] == "--emit" and argv[2] in GENERATED:
        sys.stdout.write(GENERATED[argv[2]][1](load_decl()))
        return 0
    if len(argv) == 4 and argv[1] == "--features" and argv[2] in ABIS:
        decl = load_decl()
        on = read_config(decl, pathlib.Path(argv[3]).read_text(encoding="utf-8"))
        print(cargo_args(decl, argv[2], on))
        return 0
    print(__doc__, file=sys.stderr)
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv))
