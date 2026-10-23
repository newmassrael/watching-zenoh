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

    --emit kconfig-root           print deploy/Kconfig, the root of the host configuration
    --emit kconfig-axes           print deploy/Kconfig.axes, the axes no one image owns (written
                                  only while the declaration has one)
    --emit kconfig-capabilities   print deploy/Kconfig.capabilities
    --emit kconfig-limits         print deploy/Kconfig.limits
    --emit rust-limits            print crates/wz-session-core/src/caps_generated.rs
    --emit image-kconfig:IMAGE    print the axes of a declared image as Kconfig choices
                                  (<dir>/Kconfig.axes)
    --emit image-cmake:IMAGE      print the CMake that maps those choices to the image crate's
                                  features (<dir>/wz_axes.cmake)
    --write                       write every one of them
    --features ABI CONFIG         turn a Kconfig result (or a pico config.h) into the cargo arguments
    --resolve-features ABI PRESET...
                                  merge presets onto the defaults (kconfiglib) and print the cargo
                                  arguments of ABI
    --resolve-env PRESET...       the same merge; print WZ_LIMIT_<NAME>=<value> for each limit it
                                  sets off its default
    --check-presets               every registered profile (configs/profiles) resolves strictly
    --check-equivalence           the pinned kconfiglib and the copy Zephyr runs give the same
                                  configuration from the defaults and every registered profile
    --check                       hold every derived file, caps.rs and the three manifests to it
    --selftest                    drive the reader, the derivations and the check on what can be wrong

## Presets (docs/build-configuration.md, decisions C9 and C14)

A preset is a defconfig fragment that opens with `# wz-preset: 1`, `# catalog: <version>` and
`# base: <original>` and then lists only what differs from the defaults. It is resolved by the
one pinned interpreter (kconfiglib, scripts/requirements-kconfig.txt, provisioned by
scripts/provision-kconfiglib.sh into target/kconfig-venv): merged onto the generated Kconfig's
defaults in the order given, strictly. A symbol the tree does not have, a value its type or
range refuses, an assignment its dependencies do not allow and a header of another catalogue
are each an error, not a warning.

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
    wz_config.py --check | --selftest | --write | --check-presets
    wz_config.py --emit kconfig-root | kconfig-capabilities | kconfig-limits | rust-limits
    wz_config.py --resolve-features pico|c|core PRESET...
    wz_config.py --resolve-env PRESET...
    wz_config.py --features pico|c|core CONFIG
        CONFIG is a Kconfig `.config` (CONFIG_WZ_CAP_X=y) or a pico header of
        `#define Z_FEATURE_X 0|1` lines; a capability the file does not mention is OFF.
"""

from __future__ import annotations

import functools
import importlib
import importlib.util
import json
import os
import pathlib
import re
import subprocess
import sys

ROOT = pathlib.Path(__file__).resolve().parents[2]
DECL = ROOT / "deploy" / "wz-config.toml"
KCONFIG_ROOT = ROOT / "deploy" / "Kconfig"
KCONFIG_AXES = ROOT / "deploy" / "Kconfig.axes"
KCONFIG_CAPS = ROOT / "deploy" / "Kconfig.capabilities"
PROFILES = ROOT / "configs" / "profiles"
KCONFIG_VENV = ROOT / "target" / "kconfig-venv"
# A job that provisions kconfiglib arms this; where it is set, an absent interpreter is a FAIL
# in every command that needs one, never a SKIP.
KCONFIG_REQUIRED = os.environ.get("WZ_KCONFIG_REQUIRE") == "1"
# The ABI a preset's `# base:` original is built through.
BASE_ABI = {"zenoh-pico": "pico", "zenoh-c": "c", "zenoh": "core"}
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
    return decl_of(read_decl_toml(path.read_text(encoding="utf-8")))


def decl_of(data: dict) -> dict:
    """A read declaration, validated, in the shape the derivations take."""
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
        "images": [i["id"] for i in data.get("image", [])],
        "image_dirs": {i["id"]: i["dir"] for i in data.get("image", [])},
        "axes": list(data.get("axis", [])),
        "options": list(data.get("axis_option", [])),
        "rules": list(data.get("cargo_rule", [])),
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
    out += validate_images(data)
    symbols = [c["kconfig"] for c in data["capability"]] + [l["kconfig"] for l in data["limit"]]
    symbols += [a["kconfig"] for a in data.get("axis", [])]
    symbols += [o["kconfig"] for o in data.get("axis_option", [])]
    if len(symbols) != len(set(symbols)):
        out.append("a Kconfig symbol is declared twice")
    return out


IMAGE_KEYS = {"id", "dir"}
AXIS_KEYS = {"id", "image", "kconfig", "prompt", "default", "help"}
OPTION_KEYS = {"id", "axis", "kconfig", "prompt", "requires", "implies", "help"}
RULE_KEYS = {"image", "when", "features", "defaults"}


def is_global(axis: dict) -> bool:
    """An axis no one image owns (`family`, `role` ...): it has no `image` and lives in the host
    tree's deploy/Kconfig.axes, which an image's tree may source as well."""
    return "image" not in axis


def validate_images(data: dict) -> list[str]:
    """The images, the axes, the axes' options and the cargo rules hold together.

    A rule may only name the options of its own image's axes and of the global axes: what it adds
    to a crate's build is then decided by choices this file declares, never by a symbol of the
    image's own Kconfig. An option's `implies` names capabilities it selects, and only a global
    axis's option may have one: an image's own axes are in a tree that carries no capability
    symbols, while a tree that sources the global axes sources the capabilities with them (held
    by `--check`).
    """
    out: list[str] = []
    sections = (("image", IMAGE_KEYS), ("axis", AXIS_KEYS), ("axis_option", OPTION_KEYS),
                ("cargo_rule", RULE_KEYS))
    for kind, keys in sections:
        for entry in data.get(kind, []):
            unknown = set(entry) - keys
            if unknown:
                out.append(f"a {kind} has keys this reader does not know: {sorted(unknown)}")
    images = [i.get("id") for i in data.get("image", [])]
    if len(images) != len(set(images)):
        out.append("an image id is declared twice")
    axes = {}
    for axis in data.get("axis", []):
        if not is_global(axis) and axis.get("image") not in images:
            out.append(f"axis {axis.get('id')!r} names image {axis.get('image')!r}, which is not declared")
        if axis.get("id") in axes:
            out.append(f"axis {axis.get('id')!r} is declared twice")
        axes[axis.get("id")] = axis
    options: dict[str, list[dict]] = {a: [] for a in axes}
    for option in data.get("axis_option", []):
        if option.get("axis") not in axes:
            out.append(f"option {option.get('id')!r} names axis {option.get('axis')!r}, which is not declared")
            continue
        options[option["axis"]].append(option)
        implied = option.get("implies")
        if implied is None:
            continue
        if not isinstance(implied, list):
            out.append(f"option {option.get('id')!r}: `implies` is not an array of capability ids")
            continue
        if not is_global(axes[option["axis"]]):
            out.append(f"option {option.get('id')!r} of the image axis {option['axis']!r} implies "
                       f"capabilities; only a global axis's option can")
        caps = {c.get("id") for c in data.get("capability", [])}
        for cid in implied:
            if cid not in caps:
                out.append(f"option {option.get('id')!r} implies `{cid}`, which is no capability")
    for aid, axis in axes.items():
        ids = [o["id"] for o in options[aid]]
        if len(ids) < 2:
            out.append(f"axis {aid!r} has {len(ids)} option(s); a choice needs two")
        if len(ids) != len(set(ids)):
            out.append(f"axis {aid!r} declares an option twice")
        if axis.get("default") not in ids:
            out.append(f"axis {aid!r} defaults to {axis.get('default')!r}, which is not one of its options")
    for rule in data.get("cargo_rule", []):
        image = rule.get("image")
        if image not in images:
            out.append(f"a cargo rule names image {image!r}, which is not declared")
            continue
        own = {o["kconfig"] for aid, axis in axes.items()
               if is_global(axis) or axis.get("image") == image for o in options[aid]}
        when = rule.get("when") or []
        if not when:
            out.append(f"a cargo rule of {image!r} names no option in `when`")
        for symbol in when:
            if symbol not in own:
                out.append(f"a cargo rule of {image!r} names {symbol}, which is no option of its "
                           f"axes or of a global axis")
        if not rule.get("features") and rule.get("defaults") != "off":
            out.append(f"a cargo rule of {image!r} when {when} adds nothing")
        if rule.get("defaults", "off") != "off":
            out.append(f"a cargo rule of {image!r} says defaults = {rule.get('defaults')!r}; only \"off\" is a value")
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
        out += validate_upstream_defaults(c)
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


def upstream_families(cap: dict) -> set[str]:
    """The originals a capability is judged against: zenoh-pico where the pico ABI exports it,
    zenoh-c and zenoh where the zenoh-c ABI does. A capability of the pico ABI alone (pico's
    header arms, its admin space) has no counterpart switch in the other two."""
    out: set[str] = set()
    if "pico" in cap.get("abis", []):
        out.add("zenoh-pico")
    if "c" in cap.get("abis", []):
        out |= {"zenoh-c", "zenoh"}
    return out


def upstream_default(cap: dict, family: str) -> bool | None:
    """Whether `family`'s own default build has the capability; None where it is not judged."""
    if family in cap.get("upstream_on", []):
        return True
    if family in cap.get("upstream_off", []):
        return False
    return None


def validate_upstream_defaults(cap: dict) -> list[str]:
    out: list[str] = []
    on, off = cap.get("upstream_on", []), cap.get("upstream_off", [])
    for key, value in (("upstream_on", on), ("upstream_off", off)):
        if not isinstance(value, list):
            out.append(f"{cap['id']}: `{key}` is not an array of originals")
            return out
        for family in value:
            if family not in BASE_ABI:
                out.append(f"{cap['id']}: `{key}` names `{family}`, which is none of {sorted(BASE_ABI)}")
    both = set(on) & set(off)
    if both:
        out.append(f"{cap['id']}: {sorted(both)} is in both upstream_on and upstream_off")
    stated, want = set(on) | set(off), upstream_families(cap)
    if stated != want:
        out.append(f"{cap['id']}: its ABIs make it judged against {sorted(want)}, "
                   f"and upstream_on/upstream_off state {sorted(stated)}")
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
        elif re.search(r"\[`|crate::", lim["help"]):
            # A deployer reads the help in menuconfig; a Rust path or a rustdoc link is the
            # developer's text, which caps.rs keeps.
            out.append(f"limit `{lid}`: its help names Rust items; it is written for a deployer")
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


def global_axes(decl: dict) -> list[dict]:
    return [a for a in decl["axes"] if is_global(a)]


def emit_kconfig_root(decl: dict) -> str:
    """The root of the host build configuration: every generated menu, read by kconfiglib."""
    out = generated_header("#", "kconfig-root") + [
        "",
        'mainmenu "wz build configuration"',
        "",
    ]
    if global_axes(decl):
        out.append('rsource "Kconfig.axes"')
    out += [
        'rsource "Kconfig.capabilities"',
        'rsource "Kconfig.limits"',
    ]
    return "\n".join(out) + "\n"


def help_lines(text: str) -> list[str]:
    return [f"\t  {line}" if line else "\t" for line in text.strip().splitlines()]


def axes_kconfig(decl: dict, axes: list[dict]) -> list[str]:
    """`axes` as Kconfig choices: each option `depends on` what it requires and `select`s the
    capabilities it implies."""
    out: list[str] = []
    for axis in axes:
        members = [o for o in decl["options"] if o["axis"] == axis["id"]]
        default = next(o["kconfig"] for o in members if o["id"] == axis["default"])
        out += ["", f"choice {axis['kconfig']}", f'\tprompt "{axis["prompt"]}"', f"\tdefault {default}"]
        if axis.get("help"):
            out += ["\thelp"] + help_lines(axis["help"])
        for option in members:
            out += ["", f"config {option['kconfig']}", f'\tbool "{option["prompt"]}"']
            if option.get("requires"):
                out.append(f"\tdepends on {option['requires']}")
            for cid in option.get("implies", []):
                out.append(f"\tselect {decl['caps'][cid]['kconfig']}")
            if option.get("help"):
                out += ["\thelp"] + help_lines(option["help"])
        out += ["", "endchoice"]
    return out


def emit_kconfig_axes(decl: dict) -> str:
    """The global axes. Their options select capability symbols, so a tree that sources this file
    sources deploy/Kconfig.capabilities too."""
    out = generated_header("#", "kconfig-axes") + [
        "#",
        "# The axes no one image owns. An option selects the capabilities it implies, so a",
        "# Kconfig tree that sources this file sources Kconfig.capabilities as well.",
    ]
    return "\n".join(out + axes_kconfig(decl, global_axes(decl))) + "\n"


def emit_image_kconfig(decl: dict, image: str) -> str:
    """The axes of `image` as Kconfig choices, each option `depends on` what it requires."""
    out = generated_header("#", f"image-kconfig:{image}")
    axes = [a for a in decl["axes"] if a.get("image") == image]
    return "\n".join(out + axes_kconfig(decl, axes)) + "\n"


def emit_image_cmake(decl: dict, image: str) -> str:
    """What the crate of `image` is built with for the selected options: `wz_axes_features` and
    `wz_axes_no_default_features`, for the image's CMake to hand to `wz_zephyr_rust_app`."""
    out = generated_header("#", f"image-cmake:{image}") + [
        "",
        "set(wz_axes_features \"\")",
        "set(wz_axes_no_default_features \"\")",
    ]
    for rule in (r for r in decl["rules"] if r["image"] == image):
        condition = " AND ".join(f"CONFIG_{symbol}" for symbol in rule["when"])
        out.append(f"if({condition})")
        if rule.get("features"):
            out.append(f"  list(APPEND wz_axes_features {' '.join(rule['features'])})")
        if rule.get("defaults") == "off":
            out.append("  set(wz_axes_no_default_features NO_DEFAULT_FEATURES)")
        out.append("endif()")
    return "\n".join(out) + "\n"


GENERATED = {
    "kconfig-root": (KCONFIG_ROOT, emit_kconfig_root),
    "kconfig-capabilities": (KCONFIG_CAPS, emit_kconfig_capabilities),
    "kconfig-limits": (KCONFIG_LIMITS, emit_kconfig_limits),
    "rust-limits": (RUST_LIMITS, emit_rust_limits),
}


def generated_files(decl: dict) -> dict[str, tuple[pathlib.Path, str]]:
    """Every derived file, by the `--emit` kind that prints it: the host files and, for each
    declared image, its axes' Kconfig and the CMake that maps them to cargo."""
    out = {kind: (path, emit(decl)) for kind, (path, emit) in GENERATED.items()}
    if global_axes(decl):
        out["kconfig-axes"] = (KCONFIG_AXES, emit_kconfig_axes(decl))
    for image in decl["images"]:
        base = ROOT / decl["image_dirs"][image]
        out[f"image-kconfig:{image}"] = (base / "Kconfig.axes", emit_image_kconfig(decl, image))
        out[f"image-cmake:{image}"] = (base / "wz_axes.cmake", emit_image_cmake(decl, image))
    return out


RSOURCE_RE = re.compile(r'^\s*rsource\s+"([^"]+)"', re.MULTILINE)


def check_image_sources(image: str, text: str) -> list[str]:
    """An image's Kconfig that sources the global axes sources the capabilities too: an option of a
    global axis selects capability symbols, and Zephyr refuses a select of a symbol the tree does
    not define."""
    sourced = set(RSOURCE_RE.findall(text))
    if "../Kconfig.axes" in sourced and "../Kconfig.capabilities" not in sourced:
        return [f"{image}: its Kconfig sources ../Kconfig.axes but not ../Kconfig.capabilities, "
                "whose symbols the global axes select"]
    return []


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
# presets: resolved by the pinned Kconfig interpreter
# ---------------------------------------------------------------------------------------------


class PresetError(ValueError):
    """A preset that cannot be resolved as written: refused, never resolved in part (C9)."""


def kconfiglib_module():
    """The pinned kconfiglib, from the interpreter or from this checkout's venv; None if neither.

    scripts/provision-kconfiglib.sh installs it in target/kconfig-venv at the version and hashes
    scripts/requirements-kconfig.txt pins. kconfiglib is pure Python, so the venv's
    site-packages serves the interpreter that runs this tool.
    """
    try:
        return importlib.import_module("kconfiglib")
    except ImportError:
        pass
    for site in sorted(KCONFIG_VENV.glob("lib/python*/site-packages")):
        sys.path.insert(0, str(site))
        try:
            return importlib.import_module("kconfiglib")
        except ImportError:
            sys.path.remove(str(site))
    return None


PRESET_HEADER_RE = re.compile(r"^#\s*(wz-preset|catalog|base):\s*(\S+)\s*$")


def preset_header(text: str) -> dict:
    """The `# wz-preset:`, `# catalog:` and `# base:` lines a preset opens with."""
    header: dict = {}
    for line in text.splitlines():
        m = PRESET_HEADER_RE.match(line)
        if m:
            header[m.group(1)] = m.group(2)
    return header


def check_preset_header(decl: dict, name: str, text: str) -> list[str]:
    out: list[str] = []
    header = preset_header(text)
    if header.get("wz-preset") != "1":
        out.append(f"{name}: no `# wz-preset: 1` line")
    if header.get("catalog") != str(decl["catalog_version"]):
        out.append(f"{name}: written for catalogue {header.get('catalog')!r}, the declaration is "
                   f"catalogue {decl['catalog_version']}")
    if header.get("base") not in BASE_ABI:
        out.append(f"{name}: base {header.get('base')!r} is none of {sorted(BASE_ABI)}")
    return out


def zephyr_kconfiglib_module():
    """The kconfiglib Zephyr's build runs (`$ZEPHYR_BASE/scripts/kconfig/kconfiglib.py`), loaded
    by its path under a name of its own so it never stands in for the pinned one; None if there
    is no Zephyr tree. The tree is `WZ_ZEPHYR_BASE`, then `ZEPHYR_BASE`, then the workspace the
    Zephyr lanes use (`~/zephyrproject/zephyr`)."""
    base = os.environ.get("WZ_ZEPHYR_BASE") or os.environ.get("ZEPHYR_BASE")
    path = (pathlib.Path(base) if base else pathlib.Path.home() / "zephyrproject" / "zephyr")
    path = path / "scripts" / "kconfig" / "kconfiglib.py"
    if not path.is_file():
        return None
    spec = importlib.util.spec_from_file_location("zephyr_kconfiglib", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def resolve(fragments: list[pathlib.Path], kconfiglib=None):
    """The configuration the generated Kconfig gives when `fragments` are merged in order onto
    its defaults, a later fragment overriding an earlier one, read by `kconfiglib` (the pinned
    interpreter when not given).

    Strict (C9): a symbol the tree does not have, a value outside a symbol's type or range and an
    assignment its dependencies do not allow are each refused with kconfiglib's own words,
    never dropped; so is a fragment whose header names another catalogue.
    """
    kconfiglib = kconfiglib or kconfiglib_module()
    if kconfiglib is None:
        raise PresetError("kconfiglib is not installed: run scripts/provision-kconfiglib.sh")
    decl = load_decl()
    problems: list[str] = []
    for frag in fragments:
        problems += check_preset_header(decl, frag.name, frag.read_text(encoding="utf-8"))
    if problems:
        raise PresetError("; ".join(problems))
    kconf = kconfiglib.Kconfig(str(KCONFIG_ROOT), warn_to_stderr=False)
    # The interpreter's settings while fragments are merged are Zephyr's
    # (zephyr/scripts/kconfig/kconfig.py): an assignment to a symbol the tree does not have is
    # reported, and a later fragment overriding an earlier one is the merge, not a mistake.
    kconf.warn_assign_undef = True
    kconf.warn_assign_override = False
    kconf.warn_assign_redun = False
    for frag in fragments:
        kconf.load_config(str(frag), replace=False)
    problems = [w.strip() for w in kconf.warnings]
    # And Zephyr's two checks after the merge, here errors: a symbol with no prompt cannot be
    # assigned, and an assigned value must be the value the symbol got (a `select`, a
    # dependency or a range can each keep it from taking).
    for sym in kconf.unique_defined_syms:
        if sym.user_value is None or sym.choice:
            continue
        if not any(node.prompt for node in sym.nodes):
            problems.append(f"{sym.name} is assigned but has no prompt; it is not user-configurable")
            continue
        wanted = (kconfiglib.TRI_TO_STR[sym.user_value]
                  if sym.type in (kconfiglib.BOOL, kconfiglib.TRISTATE) else sym.user_value)
        if wanted != sym.str_value:
            problems.append(f"{sym.name} was assigned the value '{wanted}' but got the value "
                            f"'{sym.str_value}'")
    if problems:
        raise PresetError("; ".join(problems))
    return kconf


def resolved_caps(decl: dict, kconf) -> set[str]:
    return {cid for cid, cap in decl["caps"].items() if kconf.syms[cap["kconfig"]].tri_value == 2}


def resolved_limit_env(decl: dict, kconf) -> list[str]:
    """`WZ_LIMIT_<NAME>=<value>` for every limit the configuration sets off its default."""
    out: list[str] = []
    for lim in decl["limits"]:
        value = int(kconf.syms[lim["kconfig"]].str_value)
        if value != lim["default"]:
            out.append(f"{lim['kconfig']}={value}")
    return out


def cmd_check_presets() -> int:
    """Every registered profile resolves, strictly, on the pinned interpreter.

    Without kconfiglib the presets cannot be read, and that is a SKIP said out loud, unless the
    job that provisions it arms the requirement (WZ_KCONFIG_REQUIRE=1), where it is a FAIL.
    """
    if kconfiglib_module() is None:
        if KCONFIG_REQUIRED:
            print("  wz-config presets FAIL: kconfiglib is absent, but WZ_KCONFIG_REQUIRE=1 says "
                  "this job provisions it (scripts/provision-kconfiglib.sh)", file=sys.stderr)
            return 1
        print("  wz-config presets SKIP: kconfiglib is absent (scripts/provision-kconfiglib.sh)")
        return 0
    profiles = sorted(PROFILES.glob("*.conf"))
    if not profiles:
        print(f"  wz-config presets FAIL: no profile under {PROFILES.relative_to(ROOT)}",
              file=sys.stderr)
        return 1
    decl = load_decl()
    bad = 0
    for profile in profiles:
        try:
            kconf = resolve([profile])
        except PresetError as exc:
            print(f"  wz-config presets FAIL: {profile.name}: {exc}", file=sys.stderr)
            bad += 1
            continue
        abi = BASE_ABI[preset_header(profile.read_text(encoding="utf-8"))["base"]]
        print(f"  wz-config presets: {profile.name} -> {abi}: "
              f"{cargo_args(decl, abi, resolved_caps(decl, kconf))}")
    return 1 if bad else 0


def configuration(kconf) -> dict[str, str]:
    """Every symbol of a resolved tree and the value it got, the whole of what a `.config` says."""
    return {sym.name: sym.str_value for sym in kconf.unique_defined_syms}


def configuration_diff(pinned: dict[str, str], zephyr: dict[str, str]) -> list[str]:
    out = []
    for name in sorted(set(pinned) | set(zephyr)):
        if pinned.get(name) != zephyr.get(name):
            out.append(f"{name} is {pinned.get(name)!r} by the pinned kconfiglib and "
                       f"{zephyr.get(name)!r} by Zephyr's")
    return out


def cmd_check_equivalence() -> int:
    """The pinned kconfiglib and the copy Zephyr's build runs give the same configuration from
    the same tree and inputs (decision C11): the defaults alone, and every registered profile.

    Each interpreter that is absent is a SKIP said out loud, unless the job arms it
    (WZ_KCONFIG_REQUIRE=1 for the pinned one, WZ_ZEPHYR_KCONFIG_REQUIRE=1 for Zephyr's), where
    it is a FAIL.
    """
    pinned, zephyr = kconfiglib_module(), zephyr_kconfiglib_module()
    zephyr_required = os.environ.get("WZ_ZEPHYR_KCONFIG_REQUIRE") == "1"
    if pinned is None or zephyr is None:
        missing = "the pinned kconfiglib" if pinned is None else "Zephyr's kconfiglib"
        if (pinned is None and KCONFIG_REQUIRED) or (zephyr is None and zephyr_required):
            print(f"  wz-config equivalence FAIL: {missing} is absent and this job is armed to "
                  f"provide it", file=sys.stderr)
            return 1
        print(f"  wz-config equivalence SKIP: {missing} is absent")
        return 0
    inputs: list[tuple[str, list[pathlib.Path]]] = [("the defaults", [])]
    inputs += [(p.name, [p]) for p in sorted(PROFILES.glob("*.conf"))]
    bad = 0
    for label, fragments in inputs:
        try:
            a = configuration(resolve(fragments, pinned))
            b = configuration(resolve(fragments, zephyr))
        except PresetError as exc:
            print(f"  wz-config equivalence FAIL: {label}: {exc}", file=sys.stderr)
            bad += 1
            continue
        for difference in configuration_diff(a, b):
            print(f"  wz-config equivalence FAIL: {label}: {difference}", file=sys.stderr)
            bad += 1
    if bad:
        return 1
    print(f"  wz-config equivalence: {len(inputs)} input(s), the pinned kconfiglib "
          f"{'.'.join(map(str, pinned.VERSION))} and Zephyr's {'.'.join(map(str, zephyr.VERSION))} "
          f"give the same configuration")
    return 0


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
    files = generated_files(decl)
    for kind, (path, text) in files.items():
        rel = path.relative_to(ROOT)
        if not path.is_file():
            findings.append(f"{rel} is missing (--emit {kind} prints it)")
        elif path.read_text(encoding="utf-8") != text:
            findings.append(f"{rel} is stale: regenerate it with --write")
    if "kconfig-axes" not in files and KCONFIG_AXES.exists():
        findings.append(f"{KCONFIG_AXES.relative_to(ROOT)} exists, but the declaration has no "
                        "global axis: remove it")
    for image in decl["images"]:
        kconfig = ROOT / decl["image_dirs"][image] / "Kconfig"
        if kconfig.is_file():
            findings += check_image_sources(image, kconfig.read_text(encoding="utf-8"))
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
    n_global = len(global_axes(decl))
    print(f"  wz-config: {len(decl['order'])} capabilities, {len(decl['limits'])} limits, "
          f"{n_global} global and {len(decl['axes']) - n_global} image axes, {len(files)} "
          f"generated files current, caps.rs bound, {len(MANIFESTS)} manifests agree")
    return 0


def cmd_write() -> int:
    decl = load_decl()
    for path, text in generated_files(decl).values():
        path.write_text(text, encoding="utf-8")
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
upstream_on = ["zenoh-pico"]
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


IMAGE_SAMPLE = """\

[[image]]
id = "img"
dir = "deploy/img"

[[axis]]
id = "side"
image = "img"
kconfig = "WZ_SIDE"
prompt = "Side"
default = "l"

[[axis_option]]
id = "l"
axis = "side"
kconfig = "WZ_SIDE_L"
prompt = "Left"

[[axis_option]]
id = "r"
axis = "side"
kconfig = "WZ_SIDE_R"
prompt = "Right"
requires = "WZ_SOMETHING"

[[cargo_rule]]
image = "img"
when = ["WZ_SIDE_R"]
features = ["right"]
defaults = "off"
"""


GLOBAL_SAMPLE = """\

[[capability]]
id = "b"
kconfig = "WZ_CAP_B"
abis = ["core"]
default = "off"
implies = []
help = "B."

[[axis]]
id = "mode"
kconfig = "WZ_MODE"
prompt = "Mode"
default = "c"

[[axis_option]]
id = "c"
axis = "mode"
kconfig = "WZ_MODE_C"
prompt = "Client"

[[axis_option]]
id = "p"
axis = "mode"
kconfig = "WZ_MODE_P"
prompt = "Peer"
implies = ["b"]

[[cargo_rule]]
image = "img"
when = ["WZ_MODE_P", "WZ_SIDE_L"]
features = ["peer-left"]
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
    rusty = SAMPLE.replace("A table.\n'''", "A [`crate::x::Table`].\n'''")
    expect("a limit help naming a Rust item is refused",
           any("Rust items" in p for p in validate_decl(read_decl_toml(rusty))))
    two_para = SAMPLE.replace("A table.\n'''", "A table.\n\nMore.\n'''")
    expect("a limit help of two paragraphs is refused",
           any("paragraph" in p for p in validate_decl(read_decl_toml(two_para))))
    def caps_refused(old: str, new: str, words: str) -> bool:
        return any(words in p for p in validate_decl(read_decl_toml(SAMPLE.replace(old, new))))

    expect("a capability that states no default for an original its ABIs reach is refused",
           caps_refused('upstream_on = ["zenoh-pico"]\n', "", "judged against ['zenoh-pico']"))
    expect("a capability stating an original its ABIs do not reach is refused",
           caps_refused('upstream_on = ["zenoh-pico"]', 'upstream_on = ["zenoh-pico", "zenoh-c"]',
                        "judged against"))
    expect("an original in both upstream_on and upstream_off is refused",
           caps_refused('upstream_on = ["zenoh-pico"]',
                        'upstream_on = ["zenoh-pico"]\nupstream_off = ["zenoh-pico"]', "in both"))
    expect("an unknown original is refused",
           caps_refused('upstream_on = ["zenoh-pico"]', 'upstream_on = ["pico"]', "none of"))
    expect("the shipped declaration judges every capability against exactly its originals",
           all(upstream_default(c, f) is not None for c in caps.values()
               for f in upstream_families(c)))
    expect("a declaration of another schema is refused",
           any("schema_version" in p for p in validate_decl(read_decl_toml(
               SAMPLE.replace("schema_version = 1", "schema_version = 2")))))

    # Images: the axes as choices, and the cargo rules over their options.
    with_image = SAMPLE + IMAGE_SAMPLE
    image_data = read_decl_toml(with_image)
    expect("a sample image validates", validate_decl(image_data) == [])
    idecl = {"axes": image_data["axis"], "options": image_data["axis_option"],
             "rules": image_data["cargo_rule"]}
    kconfig = emit_image_kconfig(idecl, "img")
    expect("an axis is a choice with its default, and an option depends on what it requires",
           "choice WZ_SIDE\n\tprompt \"Side\"\n\tdefault WZ_SIDE_L\n" in kconfig
           and "config WZ_SIDE_R\n\tbool \"Right\"\n\tdepends on WZ_SOMETHING\n" in kconfig
           and kconfig.rstrip().endswith("endchoice"))
    cmake = emit_image_cmake(idecl, "img")
    expect("a rule is a conjunction of its options that adds its features and turns the defaults off",
           "if(CONFIG_WZ_SIDE_R)\n  list(APPEND wz_axes_features right)\n"
           "  set(wz_axes_no_default_features NO_DEFAULT_FEATURES)\nendif()" in cmake)

    def image_refused(old: str, new: str, words: str) -> bool:
        return any(words in p for p in validate_decl(read_decl_toml(with_image.replace(old, new))))

    expect("a rule naming a symbol that is no option of its image's axes is refused",
           image_refused('when = ["WZ_SIDE_R"]', 'when = ["WZ_MAC_X"]', "no option of its axes"))
    expect("an axis defaulting to no option of its own is refused",
           image_refused('default = "l"', 'default = "x"', "not one of its options"))
    expect("an option of an undeclared axis is refused",
           image_refused('axis = "side"\nkconfig = "WZ_SIDE_R"', 'axis = "top"\nkconfig = "WZ_SIDE_R"',
                         "not declared"))
    expect("a key the reader does not know is refused",
           image_refused('dir = "deploy/img"', 'dir = "deploy/img"\nboard = "b"', "does not know"))
    expect("an option symbol declared twice is refused",
           image_refused('kconfig = "WZ_SIDE_R"', 'kconfig = "WZ_SIDE_L"', "declared twice"))

    # Global axes: in the host tree, rsourced by the root, their options selecting capabilities.
    with_global = with_image + GLOBAL_SAMPLE
    expect("a sample global axis validates", validate_decl(read_decl_toml(with_global)) == [])
    gdecl = decl_of(read_decl_toml(with_global))
    axes_kconfig_text = emit_kconfig_axes(gdecl)
    expect("a global axis is a choice whose option selects what it implies",
           "choice WZ_MODE\n\tprompt \"Mode\"\n\tdefault WZ_MODE_C\n" in axes_kconfig_text
           and "config WZ_MODE_P\n\tbool \"Peer\"\n\tselect WZ_CAP_B\n" in axes_kconfig_text
           and "WZ_SIDE" not in axes_kconfig_text)
    expect("an image's Kconfig holds its own axes and no global one",
           "WZ_MODE" not in emit_image_kconfig(gdecl, "img"))
    expect("the root sources the global axes when there are some, and not otherwise",
           'rsource "Kconfig.axes"\nrsource "Kconfig.capabilities"' in emit_kconfig_root(gdecl)
           and "Kconfig.axes" not in emit_kconfig_root(decl_of(read_decl_toml(with_image))))
    expect("a rule may name a global axis's option",
           "if(CONFIG_WZ_MODE_P AND CONFIG_WZ_SIDE_L)\n  list(APPEND wz_axes_features peer-left)"
           in emit_image_cmake(gdecl, "img"))

    def global_refused(old: str, new: str, words: str) -> bool:
        return any(words in p for p in validate_decl(read_decl_toml(with_global.replace(old, new))))

    expect("an option implying no capability is refused",
           global_refused('implies = ["b"]', 'implies = ["z"]', "is no capability"))
    expect("an option of an image axis implying a capability is refused",
           global_refused('requires = "WZ_SOMETHING"', 'requires = "WZ_SOMETHING"\nimplies = ["a"]',
                          "only a global axis"))
    expect("an implies that is not an array is refused",
           global_refused('implies = ["b"]', 'implies = "b"', "not an array"))
    expect("an image Kconfig sourcing the global axes without the capabilities is a finding",
           check_image_sources("img", 'rsource "../Kconfig.axes"\n') != []
           and check_image_sources(
               "img", 'rsource "../Kconfig.capabilities"\nrsource "../Kconfig.axes"\n') == []
           and check_image_sources("img", 'rsource "Kconfig.axes"\n') == [])

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
    expect("two interpreters agreeing give no difference",
           configuration_diff({"A": "y", "B": "3"}, {"A": "y", "B": "3"}) == [])
    expect("a value the two interpreters give differently is a difference",
           configuration_diff({"A": "y"}, {"A": "n"})
           == ["A is 'y' by the pinned kconfiglib and 'n' by Zephyr's"])
    expect("a symbol only one interpreter has is a difference",
           configuration_diff({"A": "y"}, {}) == ["A is 'y' by the pinned kconfiglib and None by Zephyr's"])
    cyc = {"capability": [
        {"id": "a", "kconfig": "WZ_CAP_A", "abis": ["core"], "implies": ["b"]},
        {"id": "b", "kconfig": "WZ_CAP_B", "abis": ["core"], "implies": ["a"]}]}
    expect("a dependency cycle is refused", any("cycle" in p for p in validate_caps(cyc)))

    # Presets, on the pinned interpreter. Without it these arms cannot run, and that is said.
    if kconfiglib_module() is None:
        if KCONFIG_REQUIRED:
            expect("kconfiglib is present where WZ_KCONFIG_REQUIRE=1 says this job provisions it",
                   False)
        else:
            print("  wz-config selftest: the preset arms SKIP, kconfiglib is absent "
                  "(scripts/provision-kconfiglib.sh); Layer C0's --check-presets is armed where "
                  "it is not")
    else:
        import tempfile

        head = f"# wz-preset: 1\n# catalog: {decl['catalog_version']}\n# base: zenoh-c\n"

        def preset(dir_: pathlib.Path, name: str, body: str, header: str = head) -> pathlib.Path:
            path = dir_ / name
            path.write_text(header + body, encoding="utf-8")
            return path

        def refused(paths: list[pathlib.Path], words: str) -> bool:
            try:
                resolve(paths)
            except PresetError as exc:
                return words in str(exc)
            return False

        with tempfile.TemporaryDirectory() as tmp:
            d = pathlib.Path(tmp)
            comparison = PROFILES / "host-client-tcp-query.conf"
            expect("the host comparison preset resolves to the build it was measured with",
                   cargo_args(decl, "c", resolved_caps(decl, resolve([comparison])))
                   == "--no-default-features --features query")
            expect("a symbol the tree does not have is refused",
                   refused([preset(d, "unknown.conf", "CONFIG_WZ_CAP_NO_SUCH=y\n")], "NO_SUCH"))
            expect("an assignment a select overrides is refused",
                   refused([preset(d, "select.conf", "CONFIG_WZ_CAP_PEER=n\n")], "WZ_CAP_PEER"))
            expect("a limit that is not an integer is refused",
                   refused([preset(d, "int.conf", "CONFIG_WZ_LIMIT_MAX_TASKS=many\n")], "MAX_TASKS"))
            expect("a preset of another catalogue is refused",
                   refused([preset(d, "old.conf", "", head.replace(
                       f"catalog: {decl['catalog_version']}", "catalog: 0"))], "catalogue"))
            first = preset(d, "first.conf", "CONFIG_WZ_LIMIT_MAX_TASKS=4\n")
            later = preset(d, "later.conf", "CONFIG_WZ_LIMIT_MAX_TASKS=6\n")
            expect("a limit set off its default reaches the environment",
                   resolved_limit_env(decl, resolve([first])) == ["WZ_LIMIT_MAX_TASKS=4"])
            expect("a later preset overrides an earlier one",
                   resolved_limit_env(decl, resolve([first, later])) == ["WZ_LIMIT_MAX_TASKS=6"])
            expect("a preset that changes nothing resolves to the defaults",
                   resolved_caps(decl, resolve([preset(d, "empty.conf", "")]))
                   == {cid for cid, cap in caps.items() if default_on(cap)}
                   and resolved_limit_env(decl, resolve([preset(d, "empty2.conf", "")])) == [])
            # The emitted tree of the global sample, read by the interpreter: the default option
            # leaves the off capability off, and the option that implies it turns it on.
            tree = d / "tree"
            tree.mkdir()
            for name, emit in (("Kconfig", emit_kconfig_root), ("Kconfig.axes", emit_kconfig_axes),
                               ("Kconfig.capabilities", emit_kconfig_capabilities),
                               ("Kconfig.limits", emit_kconfig_limits)):
                (tree / name).write_text(emit(gdecl), encoding="utf-8")
            kconf = kconfiglib_module().Kconfig(str(tree / "Kconfig"), warn_to_stderr=False)
            off_by_default = kconf.syms["WZ_CAP_B"].tri_value == 0
            kconf.syms["WZ_MODE_P"].set_value(2)
            expect("the interpreter reads the global axes, and an option turns on what it implies",
                   off_by_default and kconf.syms["WZ_CAP_B"].tri_value == 2
                   and kconf.warnings == [])
    print(f"  wz-config selftest: {ok}/{ok + bad} arm(s) pass")
    return 0 if bad == 0 else 1


def main(argv: list[str]) -> int:
    if len(argv) == 2 and argv[1] == "--check":
        return cmd_check()
    if len(argv) == 2 and argv[1] == "--selftest":
        return cmd_selftest()
    if len(argv) == 2 and argv[1] == "--write":
        return cmd_write()
    if len(argv) == 3 and argv[1] == "--emit":
        files = generated_files(load_decl())
        if argv[2] in files:
            sys.stdout.write(files[argv[2]][1])
            return 0
    if len(argv) == 4 and argv[1] == "--features" and argv[2] in ABIS:
        decl = load_decl()
        on = read_config(decl, pathlib.Path(argv[3]).read_text(encoding="utf-8"))
        print(cargo_args(decl, argv[2], on))
        return 0
    if len(argv) == 2 and argv[1] == "--check-presets":
        return cmd_check_presets()
    if len(argv) == 2 and argv[1] == "--check-equivalence":
        return cmd_check_equivalence()
    if len(argv) >= 4 and argv[1] == "--resolve-features" and argv[2] in ABIS:
        decl = load_decl()
        try:
            kconf = resolve([pathlib.Path(p) for p in argv[3:]])
        except PresetError as exc:
            print(f"  wz-config FAIL: {exc}", file=sys.stderr)
            return 1
        print(cargo_args(decl, argv[2], resolved_caps(decl, kconf)))
        return 0
    if len(argv) >= 3 and argv[1] == "--resolve-env":
        decl = load_decl()
        try:
            kconf = resolve([pathlib.Path(p) for p in argv[2:]])
        except PresetError as exc:
            print(f"  wz-config FAIL: {exc}", file=sys.stderr)
            return 1
        for line in resolved_limit_env(decl, kconf):
            print(line)
        return 0
    print(__doc__, file=sys.stderr)
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv))
