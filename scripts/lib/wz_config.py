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
    --emit kconfig-policies       print deploy/Kconfig.policies (written only while the declaration
                                  has a policy)
    --emit rust-policies          print crates/wz-session-core/src/policy_generated.rs
    --emit defconfig:ORIGINAL     print configs/<ORIGINAL>_defconfig, an upstream original's own
                                  default build in wz's switches (zenoh, zenoh-c, zenoh-pico)
    --emit image-kconfig:IMAGE    print the axes of a declared image as Kconfig choices
                                  (<dir>/Kconfig.axes)
    --emit image-cmake:IMAGE      print the CMake that maps those choices to the image crate's
                                  features (<dir>/wz_axes.cmake)
    --write                       write every one of them
    --features ABI CONFIG         turn a Kconfig result (or a pico config.h) into the cargo arguments
    --resolve-features ABI PRESET...
                                  merge presets onto the defaults (kconfiglib) and print the cargo
                                  arguments of ABI
    --drop-in-features c HEADER   the cargo arguments of the wz-capi-c build a program compiled
                                  against an installed zenoh-c's zenoh_configure.h links
    --original-features ORIGINAL  resolve configs/<ORIGINAL>_defconfig alone and print the cargo
                                  arguments of the ABI that original is built through
    --resolve-env PRESET...       the same merge; print WZ_LIMIT_<NAME>=<value> for each limit it
                                  sets off its default
    --check-presets               every registered profile (configs/profiles) resolves strictly,
                                  and each upstream defconfig resolves to its original's values
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
  7. Every capability states the operating-system facilities it may ask for (`os_needs`, an
     empty list when it asks for none beyond the `[os]` base), from the closed vocabulary
     `OS_FACILITIES`: a capability that was never assessed has no entry, and is refused rather
     than read as "needs nothing".
  8. Every `[[platform]]` (`docs/target-build-contract.md` T3) names a triple the pinned rustc
     knows, an `os` equal to that triple's `target_os`, and a `libc` the pair (`target_os`,
     `target_env`) gives: a platform row is declared and checked against the compiler, never
     typed twice. A platform that states what it provides states at least the base, and one that
     does not is UNASSESSED, which the entry of the contract refuses and this check reports.

Usage:
    wz_config.py --check | --selftest | --write | --check-presets
    wz_config.py --emit kconfig-root | kconfig-capabilities | kconfig-limits | rust-limits
                         | kconfig-policies | rust-policies
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
import shutil
import subprocess
import sys
import textwrap

ROOT = pathlib.Path(__file__).resolve().parents[2]
DECL = ROOT / "deploy" / "wz-config.toml"
KCONFIG_ROOT = ROOT / "deploy" / "Kconfig"
KCONFIG_AXES = ROOT / "deploy" / "Kconfig.axes"
KCONFIG_CAPS = ROOT / "deploy" / "Kconfig.capabilities"
CONFIGS = ROOT / "configs"
PROFILES = CONFIGS / "profiles"
KCONFIG_VENV = ROOT / "target" / "kconfig-venv"
# A job that provisions kconfiglib arms this; where it is set, an absent interpreter is a FAIL
# in every command that needs one, never a SKIP.
KCONFIG_REQUIRED = os.environ.get("WZ_KCONFIG_REQUIRE") == "1"
# The ABI a preset's `# base:` original is built through.
BASE_ABI = {"zenoh-pico": "pico", "zenoh-c": "c", "zenoh": "core"}
KCONFIG_LIMITS = ROOT / "deploy" / "Kconfig.limits"
RUST_LIMITS = ROOT / "crates" / "wz-session-core" / "src" / "caps_generated.rs"
KCONFIG_POLICIES = ROOT / "deploy" / "Kconfig.policies"
RUST_POLICIES = ROOT / "crates" / "wz-session-core" / "src" / "policy_generated.rs"
CAPS_RS =ROOT / "crates" / "wz-session-core" / "src" / "caps.rs"
MANIFESTS = {
    "core": ROOT / "crates" / "wz-capi-core" / "Cargo.toml",
    "pico": ROOT / "crates" / "wz-capi-pico" / "Cargo.toml",
    "c": ROOT / "crates" / "wz-capi-c" / "Cargo.toml",
}
ABIS = ("core", "pico", "c")
SCHEMA_VERSION = 1
# rustfmt's default `max_width`; the crates carry no rustfmt.toml.
RUST_MAX_WIDTH = 100
# rustfmt's default `fn_call_width`: a call whose arguments are wider goes one argument a line.
RUST_FN_CALL_WIDTH = 60
# rustfmt's default `struct_lit_width`: a struct literal whose body is longer goes one field a line.
RUST_STRUCT_LIT_WIDTH = 18

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
        "policies": list(data.get("policy", [])),
        "images": [i["id"] for i in data.get("image", [])],
        "image_dirs": {i["id"]: i["dir"] for i in data.get("image", [])},
        "axes": list(data.get("axis", [])),
        "options": list(data.get("axis_option", [])),
        "rules": list(data.get("cargo_rule", [])),
        "switches": list(data.get("upstream_switch", [])),
        "os_base": list(data["os"]["base"]),
        "platforms": list(data["platform"]),
        "artifacts": list(data["artifact"]),
        "roles": list(data["role"]),
        "runtime_features": list(data["runtime_feature"]),
        "parity": list(data["parity"]),
    }


def validate_decl(data: dict) -> list[str]:
    out: list[str] = []
    if data.get("schema_version") != SCHEMA_VERSION:
        out.append(f"schema_version is {data.get('schema_version')!r}, this reader is {SCHEMA_VERSION}")
    if not isinstance(data.get("catalog_version"), int):
        out.append("catalog_version is not an integer")
    for kind in ("base", "capability", "limit", "os", "platform", "artifact", "role", "runtime_feature",
                 "parity"):
        if kind not in data:
            out.append(f"the declaration has no `{kind}`")
    if out:
        return out
    out += validate_os(data)
    out += validate_runtime_features(data)
    out += validate_parity(data)
    out += validate_caps(data)
    out += validate_platforms(data)
    out += validate_artifacts(data)
    out += validate_limits(data["limit"])
    out += validate_policies(data.get("policy", []), data["catalog_version"])
    out += validate_images(data)
    out += validate_switches(data)
    symbols = [c["kconfig"] for c in data["capability"]] + [l["kconfig"] for l in data["limit"]]
    for pol in data.get("policy", []):
        symbols += policy_symbols(pol)
    symbols += [a["kconfig"] for a in data.get("axis", [])]
    symbols += [o["kconfig"] for o in data.get("axis_option", [])]
    if len(symbols) != len(set(symbols)):
        out.append("a Kconfig symbol is declared twice")
    return out


IMAGE_KEYS = {"id", "dir"}
AXIS_KEYS = {"id", "image", "kconfig", "prompt", "default", "help"}
OPTION_KEYS = {"id", "axis", "kconfig", "prompt", "requires", "implies", "upstream_on", "help"}
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
        # An option's `upstream_on` names the originals whose own default build is that choice.
        # Only a global axis has them (an image is no original), and an axis that states it for
        # one original states it for every one, once.
        named = [(o["id"], f) for o in options[aid] for f in o.get("upstream_on", [])]
        if named and not is_global(axis):
            out.append(f"axis {aid!r} is an image's; only a global axis's options name originals")
        if named:
            stated = sorted(f for _, f in named)
            if stated != sorted(BASE_ABI):
                out.append(f"axis {aid!r} names the originals {stated}; each of "
                           f"{sorted(BASE_ABI)} is named by exactly one of its options")
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
        if "pico_flag" in c:
            out.append(f"{c['id']} names a pico_flag; a capability's pico switches are the "
                       "zenoh-pico `maps` rows to it under the upstream switches")
        for flag in c.get("pico_flags_all", []):
            if not flag.startswith("Z_FEATURE_"):
                out.append(f"{c['id']}: pico switch `{flag}` is not Z_FEATURE_*")
        out += validate_upstream_defaults(c)
        out += validate_os_needs(c, set(data.get("os", {}).get("base", [])))
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


# ─── The operating-system facilities and the platforms (docs/target-build-contract.md T3, T9) ───
#
# A FACILITY is something an artifact may ask of the operating system that not every one gives: a
# kind of socket, threads, a file system, a source of entropy. The vocabulary is closed, so a typo
# is a finding and a facility nobody declared cannot be required. A capability's `os_needs` is the
# set it MAY ask for: an upper bound, so a device that lacks one is told which capability to turn
# off; it does not say that a given configuration uses it (a TLS plane reads certificate files when
# its keys name files, and not when they hold the PEM inline). `[os] base` is what every host
# build asks for whatever its capabilities. A platform's `os_provides` is what its operating
# system gives; a platform that does not state it is UNASSESSED, never read as "provides all".
OS_FACILITIES = (
    "threads",
    "sockets-tcp",
    "sockets-udp",
    "multicast",
    "raw-ethernet",
    "unix-sockets",
    "filesystem",
    "entropy",
    "wall-clock",
    "interface-list",
)
# The packages whose features are assessed for the facilities they ask of the operating system
# (`[[runtime_feature]]`): the runtime that owns every socket, thread and file read. The core and
# the codecs take no facility of their own (they are `no_std`-capable and are handed time, entropy
# and a link), and a third-party crate's needs are the runtime's, which names the crate it pulls.
ASSESSED_PACKAGES = ("wz-runtime-tokio",)
RUNTIME_FEATURE_KEYS = {"package", "feature", "os_needs", "help"}
# What a consumer's placing path says it supports (`[[parity]]`), each held to what wz declares for it:
# the capabilities of the graph and the assessed runtime features. A need that names neither is a row
# that holds nothing; one that names a capability or feature wz no longer declares is a finding.
PARITY_KEYS = {"need", "capabilities", "runtime_features", "help"}
PLATFORM_KEYS = {
    "id", "triple", "os", "libc", "network_stack", "std", "toolchain_env_extra",
    "os_provides", "system_assumed", "bundle_from_sdk", "lane", "support", "sdk_kind", "help",
}
# The two answers to "where does a NEEDED come from" (docs/target-build-contract.md T5). A SONAME in
# `system_assumed` is one every device of the platform's kind has, because a process cannot start
# without it (the C library, the loader, libm) or because the kind is defined by it (the network
# stack's library, which is why the two QNX stacks are two rows). A SONAME in `bundle_from_sdk` is
# one the SDK ships for applications to carry and a device has only when its image's integrator put
# it there: a C++ runtime, or any library a device of the kind was measured without. The entry copies
# such a file from the SDK into the package when an artifact needs it. A name is in at most one list,
# and a platform with no named SDK has nothing to bundle from.
SONAME_RE = re.compile(r"^[A-Za-z0-9_+.-]+\.so(\.[0-9]+)*$")
# What identifies the SDK a cross build used (docs/target-build-contract.md T2): the entry knows how
# to read each kind, and a platform that names one the entry cannot read is refused by the entry.
SDK_KINDS = ("android-ndk", "yocto", "qnx-sdp")
PLATFORM_REQUIRED = {"id", "triple", "os", "libc", "std", "lane", "support", "help"}
# What is known of a build for the platform, in words a person reads (docs/target-build-contract.md
# T11). `lane` says the strongest lane that is green; `support` says why it is `none` when it is:
#   untried   no wz build for the platform has been attempted;
#   built     a build has succeeded (by hand or by the entry) and no lane has passed on it;
#   blocked   a build was attempted and does not succeed, for a reason the row's help names;
#   verified  a lane has passed, so `lane` is not `none`.
SUPPORTS = ("untried", "built", "blocked", "verified")
# The strongest lane that is green for the platform, as the catalogue states it
# (`docs/target-build-contract.md` T11): `none` until a lane exists and has passed.
LANES = ("none", "build", "run", "interop")
LIBCS = ("glibc", "bionic", "nto")
STD_KINDS = ("prebuilt", "build-std")
NETWORK_STACKS = ("io-sock", "io-pkt")
PLATFORM_ID_RE = re.compile(r"^[a-z0-9]+([-_][a-z0-9]+)*$")
TRIPLE_RE = re.compile(r"^[a-z0-9_]+(-[a-z0-9_.]+)+$")


def facility_findings(who: str, value: object, what: str) -> list[str]:
    """What is wrong with a list that must be facilities of the vocabulary, each once."""
    if not isinstance(value, list):
        return [f"{who}: {what} is not a list"]
    out = [f"{who}: {what} names `{f}`, which is not a facility ({', '.join(OS_FACILITIES)})"
           for f in value if f not in OS_FACILITIES]
    if len(value) != len(set(value)):
        out.append(f"{who}: {what} names a facility twice")
    return out


def validate_os(data: dict) -> list[str]:
    base = data["os"].get("base")
    out = facility_findings("[os]", base, "`base`")
    if isinstance(base, list) and not base:
        out.append("[os]: `base` is empty, and a host build always asks for threads, sockets and entropy")
    extra = set(data["os"]) - {"base"}
    if extra:
        out.append(f"[os] has the unknown key(s) {', '.join(sorted(extra))}")
    return out


def validate_os_needs(cap: dict, base: set[str]) -> list[str]:
    needs = cap.get("os_needs")
    if needs is None:
        return [f"{cap['id']} has no os_needs (an empty list says it asks for nothing beyond the base)"]
    out = facility_findings(cap["id"], needs, "os_needs")
    if isinstance(needs, list):
        out += [f"{cap['id']}: os_needs names `{f}`, which is in the [os] base already"
                for f in needs if f in base]
    return out


def validate_platforms(data: dict) -> list[str]:
    out: list[str] = []
    base = set(data["os"].get("base", []))
    platforms = data["platform"]
    ids = [p.get("id") for p in platforms]
    triples = [p.get("triple") for p in platforms]
    if len(ids) != len(set(ids)):
        out.append("a platform id is declared twice")
    if len(triples) != len(set(triples)):
        out.append("two platforms name the same triple; a triple names one platform")
    for p in platforms:
        who = f"platform {p.get('id')!r}"
        for key in sorted(set(p) - PLATFORM_KEYS):
            out.append(f"{who} has the unknown key `{key}`")
        for key in sorted(PLATFORM_REQUIRED - set(p)):
            out.append(f"{who} has no `{key}`")
        if not isinstance(p.get("id"), str) or not PLATFORM_ID_RE.match(p.get("id", "")):
            out.append(f"{who}: the id is not lower-case words and digits joined by `-` or `_`")
        if not isinstance(p.get("triple"), str) or not TRIPLE_RE.match(p.get("triple", "")):
            out.append(f"{who}: `{p.get('triple')}` is not a target triple")
        if p.get("libc") not in LIBCS:
            out.append(f"{who}: libc is `{p.get('libc')}`, not one of {', '.join(LIBCS)}")
        if p.get("std") not in STD_KINDS:
            out.append(f"{who}: std is `{p.get('std')}`, not one of {', '.join(STD_KINDS)}")
        if p.get("lane") not in LANES:
            out.append(f"{who}: lane is `{p.get('lane')}`, not one of {', '.join(LANES)}")
        if "sdk_kind" in p and p["sdk_kind"] not in SDK_KINDS:
            out.append(f"{who}: sdk_kind is `{p['sdk_kind']}`, not one of {', '.join(SDK_KINDS)}")
        if p.get("support") not in SUPPORTS:
            out.append(f"{who}: support is `{p.get('support')}`, not one of {', '.join(SUPPORTS)}")
        elif (p.get("support") == "verified") != (p.get("lane") not in ("none", None)):
            out.append(f"{who}: support `{p['support']}` and lane `{p.get('lane')}` disagree: a platform is "
                       "`verified` exactly when a lane is green, and `none` says nothing passed")
        if p.get("os") == "nto":
            if p.get("network_stack") not in NETWORK_STACKS:
                out.append(f"{who}: a QNX platform names its network stack ({', '.join(NETWORK_STACKS)})")
        elif "network_stack" in p:
            out.append(f"{who}: only a QNX platform has a network stack")
        for key in ("toolchain_env_extra", "system_assumed"):
            if key in p and (not isinstance(p[key], list) or not p[key]
                             or not all(isinstance(x, str) and x for x in p[key])):
                out.append(f"{who}: `{key}` is not a non-empty list of names (leave it out when unassessed)")
        bundled = p.get("bundle_from_sdk")
        if isinstance(bundled, list) and bundled and all(isinstance(x, str) and x for x in bundled):
            for name in bundled:
                if not SONAME_RE.match(name):
                    out.append(f"{who}: bundle_from_sdk names `{name}`, which is not a full SONAME")
            if len(bundled) != len(set(bundled)):
                out.append(f"{who}: bundle_from_sdk names a library twice")
            if "system_assumed" not in p:
                out.append(f"{who}: bundle_from_sdk is stated and system_assumed is not: what a device may "
                           "lack is judged against what it is assumed to have")
            elif isinstance(p["system_assumed"], list):
                for name in sorted(set(bundled) & set(p["system_assumed"])):
                    out.append(f"{who}: `{name}` is both assumed on the device and bundled from the SDK")
            if "sdk_kind" not in p:
                out.append(f"{who}: bundle_from_sdk is stated and the platform names no sdk_kind to bundle from")
        elif "bundle_from_sdk" in p:
            out.append(f"{who}: `bundle_from_sdk` is not a non-empty list of names (leave it out when nothing "
                       "is bundled)")
        if "os_provides" in p:
            out += facility_findings(who, p["os_provides"], "os_provides")
            if isinstance(p["os_provides"], list):
                for lacking in sorted(base - set(p["os_provides"])):
                    out.append(f"{who} does not provide `{lacking}`, which every host build asks for")
    return out


# ─── The artifacts the entry packages, and the roles each provides (T8) ───────────────────────
#
# An ARTIFACT is a cargo package's one file: a library or an executable, with the stamp family it
# carries (`wz-abi-stamp`) and, for a library, the ABI whose capability graph resolves what the
# build asks of a device. A ROLE is what an artifact provides and how it is reached; it is present
# in a manifest only when its `needs_feature` is on in the build, and an executable's
# `traffic-driver` takes its role words from the facts note the build wrote (`facts_list`), so no
# table of them is kept here.
#
# An executable built from a NODE DECLARATION (`docs/target-build-contract.md` 5b) is an artifact
# whose `input` is `node`: its cargo package is not a member of the crates workspace (`manifest`
# names its own Cargo.toml, `bin` the binary), the declaration picks its features and constants, and
# its `os` lists the operating systems the port under it exists for. A platform outside that list is
# refused by name, with `os_note` as the reason, before anything is built.
ARTIFACT_KEYS = {"id", "package", "kind", "file", "family", "abi", "help", "input", "manifest", "bin",
                 "os", "os_note"}
ARTIFACT_REQUIRED = {"id", "package", "kind", "file", "family", "help"}
ARTIFACT_KINDS = ("shared-library", "executable")
ARTIFACT_INPUTS = ("node",)
ROLE_IDS = ("pico-library", "zenoh-c-dropin", "session-node", "traffic-driver", "declared-node")
ROLE_KEYS = {"artifact", "id", "needs_feature", "via_argument", "via_kind", "via_key", "facts_list",
             "facts_lists", "help"}
ROLE_ABI = {"pico-library": "pico", "zenoh-c-dropin": "c"}


def validate_artifacts(data: dict) -> list[str]:
    out: list[str] = []
    artifacts = data["artifact"]
    ids = [a.get("id") for a in artifacts]
    if len(ids) != len(set(ids)):
        out.append("an artifact id is declared twice")
    by_id = {a.get("id"): a for a in artifacts}
    for a in artifacts:
        who = f"artifact {a.get('id')!r}"
        for key in sorted(set(a) - ARTIFACT_KEYS):
            out.append(f"{who} has the unknown key `{key}`")
        for key in sorted(ARTIFACT_REQUIRED - set(a)):
            out.append(f"{who} has no `{key}`")
        if a.get("kind") not in ARTIFACT_KINDS:
            out.append(f"{who}: kind is `{a.get('kind')}`, not one of {', '.join(ARTIFACT_KINDS)}")
        if a.get("kind") == "shared-library":
            if a.get("abi") not in ABIS:
                out.append(f"{who}: a library names the ABI whose capabilities it has ({', '.join(ABIS)})")
        elif "abi" in a:
            out.append(f"{who}: only a library has an ABI")
        if "input" in a:
            if a["input"] not in ARTIFACT_INPUTS:
                out.append(f"{who}: input is `{a['input']}`, not one of {', '.join(ARTIFACT_INPUTS)}")
            if a.get("kind") != "executable":
                out.append(f"{who}: only an executable is built from a declaration")
            for key in ("manifest", "bin", "os", "os_note"):
                if key not in a:
                    out.append(f"{who}: an artifact built from a declaration has no `{key}`")
        else:
            for key in ("manifest", "bin"):
                if key in a:
                    out.append(f"{who}: `{key}` belongs to an artifact built from a declaration")
        if "os" in a:
            if not isinstance(a["os"], list) or not a["os"] or not all(isinstance(o, str) for o in a["os"]):
                out.append(f"{who}: os is a non-empty list of operating system names")
            if "os_note" not in a:
                out.append(f"{who}: `os` has no `os_note`, the reason a refused platform is told")
    roles = data["role"]
    seen = set()
    for r in roles:
        who = f"role {r.get('id')!r} of {r.get('artifact')!r}"
        for key in sorted(set(r) - ROLE_KEYS):
            out.append(f"{who} has the unknown key `{key}`")
        if r.get("artifact") not in by_id:
            out.append(f"{who}: the artifact is not declared")
            continue
        if r.get("id") not in ROLE_IDS:
            out.append(f"{who}: `{r.get('id')}` is not one of {', '.join(ROLE_IDS)}")
        if (r.get("artifact"), r.get("id")) in seen:
            out.append(f"{who} is declared twice")
        seen.add((r.get("artifact"), r.get("id")))
        art = by_id[r["artifact"]]
        want = ROLE_ABI.get(r.get("id"))
        if want is not None and art.get("abi") != want:
            out.append(f"{who}: a `{r['id']}` is a library of the {want} ABI")
        if want is None and art.get("kind") != "executable":
            out.append(f"{who}: a `{r.get('id')}` is an executable")
        for key in ("facts_list", "facts_lists"):
            if key in r and art.get("kind") != "executable":
                out.append(f"{who}: only an executable carries a facts note")
        if "facts_list" in r and "facts_lists" in r:
            out.append(f"{who}: `facts_list` and `facts_lists` are two ways to say one thing")
        if "facts_lists" in r and (not isinstance(r["facts_lists"], list) or not r["facts_lists"]):
            out.append(f"{who}: facts_lists is a non-empty list of names")
        if r.get("id") == "declared-node" and art.get("input") != "node":
            out.append(f"{who}: a `declared-node` is the role of an artifact built from a declaration")
    for aid in by_id:
        if not any(r.get("artifact") == aid for r in roles):
            out.append(f"artifact {aid!r} provides no role")
    return out


def validate_runtime_features(data: dict) -> list[str]:
    out: list[str] = []
    seen = set()
    for r in data["runtime_feature"]:
        who = f"runtime_feature {r.get('package')!r}/{r.get('feature')!r}"
        for key in sorted(set(r) - RUNTIME_FEATURE_KEYS):
            out.append(f"{who} has the unknown key `{key}`")
        for key in sorted(RUNTIME_FEATURE_KEYS - set(r)):
            out.append(f"{who} has no `{key}`")
        if r.get("package") not in ASSESSED_PACKAGES:
            out.append(f"{who}: the package is not one that is assessed ({', '.join(ASSESSED_PACKAGES)})")
        if (r.get("package"), r.get("feature")) in seen:
            out.append(f"{who} is declared twice")
        seen.add((r.get("package"), r.get("feature")))
        if "os_needs" in r:
            out += facility_findings(who, r["os_needs"], "os_needs")
    return out


def validate_parity(data: dict) -> list[str]:
    out: list[str] = []
    caps = {c["id"] for c in data["capability"]}
    rows = {(r["package"], r["feature"]) for r in data["runtime_feature"] if "package" in r and "feature" in r}
    seen = set()
    for r in data["parity"]:
        who = f"parity {r.get('need')!r}"
        for key in sorted(set(r) - PARITY_KEYS):
            out.append(f"{who} has the unknown key `{key}`")
        for key in sorted(PARITY_KEYS - set(r)):
            out.append(f"{who} has no `{key}`")
        if r.get("need") in seen:
            out.append(f"{who} is declared twice")
        seen.add(r.get("need"))
        for key in ("capabilities", "runtime_features"):
            if key in r and (not isinstance(r[key], list) or not all(isinstance(x, str) for x in r[key])):
                out.append(f"{who}: `{key}` is not a list of names")
        if isinstance(r.get("capabilities"), list) and isinstance(r.get("runtime_features"), list):
            if not r["capabilities"] and not r["runtime_features"]:
                out.append(f"{who} names no capability and no runtime feature, so it holds nothing")
            for cid in r["capabilities"]:
                if cid not in caps:
                    out.append(f"{who} names the capability `{cid}`, which is not declared")
            for feature in r["runtime_features"]:
                if ("wz-runtime-tokio", feature) not in rows:
                    out.append(f"{who} names the runtime feature `{feature}`, which has no [[runtime_feature]] row")
    return out


def runtime_feature_findings(decl: dict, features_of) -> list[str]:
    """Each assessed feature against the package's real `[features]`: a row for a feature that
    no longer exists is a finding, so an assessment cannot outlive what it assessed.

    `features_of(package)` returns the package's feature names, passed in so a test can drive it.
    """
    out = []
    for r in decl["runtime_features"]:
        if r["feature"] not in features_of(r["package"]):
            out.append(f"runtime_feature {r['package']}/{r['feature']} is not a feature of {r['package']}")
    return out


def resolve_runtime_needs(decl: dict, resolved: dict[str, list[str]]) -> tuple[list[str] | None, list[str]]:
    """The facilities the resolved runtime features may ask for, and the enabled ones nobody assessed.

    `resolved` maps a package to the features cargo enabled in it. The answer is `None` (UNKNOWN,
    never a pass) when any enabled feature of an assessed package has no row; otherwise the sorted
    union of the base and of each feature's facilities. The second value lists the unassessed
    features as `package/feature`, so a reader sees which part of the answer is missing.
    """
    rows = {(r["package"], r["feature"]): r["os_needs"] for r in decl["runtime_features"]}
    unassessed: list[str] = []
    needs = set(decl["os_base"])
    for package in ASSESSED_PACKAGES:
        for feature in sorted(resolved.get(package, [])):
            if feature == "default":
                continue
            if (package, feature) in rows:
                needs |= set(rows[(package, feature)])
            else:
                unassessed.append(f"{package}/{feature}")
    return (None if unassessed else sorted(needs)), unassessed


def os_needs_of(decl: dict, on: set[str]) -> dict[str, list[str]]:
    """Each facility a build with the capabilities `on` may ask for, and who asks.

    The base is asked for by the build itself (`base`), the rest by the capabilities of the
    closure of `on`.
    """
    asks: dict[str, list[str]] = {f: ["base"] for f in decl["os_base"]}
    for cid in sorted(closure(decl["caps"], on)):
        for facility in decl["caps"][cid]["os_needs"]:
            asks.setdefault(facility, []).append(cid)
    return asks


def platform_gaps(decl: dict, platform_id: str, on: set[str]) -> dict[str, list[str]] | None:
    """The facilities a build with `on` may ask for that the platform does not provide.

    `None` when the platform states no `os_provides`: it is unassessed, and nothing can be said
    about a build on it. An empty answer is a platform that gives everything the build may ask.
    """
    platform = next((p for p in decl["platforms"] if p["id"] == platform_id), None)
    if platform is None:
        raise KeyError(f"no platform `{platform_id}` is declared")
    if "os_provides" not in platform:
        return None
    provided = set(platform["os_provides"])
    return {f: who for f, who in os_needs_of(decl, on).items() if f not in provided}


def toolchain_env(platform: dict) -> list[str]:
    """The variables cargo and the C compiler wrapper read for the platform's triple.

    Derived from the triple, so it cannot drift from it; `toolchain_env_extra` adds what the
    platform's SDK needs on top (a QNX SDK's host and target roots).
    """
    words = platform["triple"].replace("-", "_")
    return [f"CC_{words}", f"AR_{words}", f"CARGO_TARGET_{words.upper()}_LINKER",
            *platform.get("toolchain_env_extra", [])]


def libc_of(target_os: str, target_env: str) -> str | None:
    """The libc kind the compiler's own (`target_os`, `target_env`) says, or None when unknown."""
    if target_os == "android":
        return "bionic"
    if target_os == "linux" and target_env == "gnu":
        return "glibc"
    if target_os == "nto":
        return "nto"
    return None


def platform_rustc_findings(platforms: list[dict], known: set[str], cfg_of) -> list[str]:
    """What the compiler says against what each platform row declares.

    `known` is the compiler's target list and `cfg_of(triple)` its `target_os` / `target_env`;
    both are passed in so a test can drive a mismatch the installed compiler never produces.
    """
    out: list[str] = []
    for p in platforms:
        who = f"platform {p['id']!r}"
        if p["triple"] not in known:
            out.append(f"{who}: the pinned rustc has no target `{p['triple']}`")
            continue
        cfg = cfg_of(p["triple"])
        if cfg.get("target_os") != p["os"]:
            out.append(f"{who}: os is `{p['os']}` and rustc says target_os is "
                       f"`{cfg.get('target_os')}` for {p['triple']}")
        want = libc_of(cfg.get("target_os", ""), cfg.get("target_env", ""))
        if want is None:
            out.append(f"{who}: rustc's (target_os `{cfg.get('target_os')}`, target_env "
                       f"`{cfg.get('target_env')}`) is a pair this check does not classify")
        elif want != p["libc"]:
            out.append(f"{who}: libc is `{p['libc']}` and rustc's target says `{want}`")
    return out


def rustc_target_list() -> set[str]:
    run = subprocess.run(["rustc", "--print", "target-list"], capture_output=True, text=True, check=False)
    if run.returncode != 0:
        raise ValueError(f"rustc --print target-list failed: {run.stderr.strip()}")
    return set(run.stdout.split())


def rustc_cfg(triple: str) -> dict[str, str]:
    run = subprocess.run(["rustc", "--print", "cfg", "--target", triple],
                         capture_output=True, text=True, check=False)
    if run.returncode != 0:
        raise ValueError(f"rustc --print cfg --target {triple} failed: {run.stderr.strip()}")
    cfg: dict[str, str] = {}
    for line in run.stdout.splitlines():
        match = re.fullmatch(r'(target_os|target_env)="([^"]*)"', line.strip())
        if match:
            cfg[match.group(1)] = match.group(2)
    return cfg


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


SWITCH_KEYS = {"original", "switch", "class", "anchor", "note", "macro", "sense"}
# The originals whose build switches are rows here; the zenoh crate's cargo features are
# `upstream_feature_census.py`'s.
SWITCH_ORIGINALS = ("zenoh-pico", "zenoh-c")
SWITCH_CLASSES = ("maps", "always", "never", "n/a")
PICO_DROP_IN = "wz-capi-pico/"


def pico_rows_to(switches: list[dict], cid: str) -> list[str]:
    """The zenoh-pico switches a `maps` row anchors to capability `cid`, in row order."""
    return [s["switch"] for s in switches
            if s.get("original") == "zenoh-pico" and s.get("class") == "maps"
            and s.get("anchor") == PICO_DROP_IN + cid]


def pico_switches(decl: dict, cid: str) -> tuple[list[str], str]:
    """The zenoh-pico switches of a capability and how they combine: `any` (on when one of them
    is) or `all`. The `maps` rows to it, combined as it says; or, where no row reaches it, the
    `pico_flags_all` it is on under. Empty for a capability pico has no switch for."""
    cap = decl["caps"][cid]
    mapped = pico_rows_to(decl["switches"], cid)
    if mapped:
        return mapped, cap.get("pico_combine", "any")
    return list(cap.get("pico_flags_all", [])), "all"


def validate_switches(data: dict) -> list[str]:
    """The rows' shape, and how the capabilities read them. What each anchor names is held by
    `upstream_switch_map.py`, which asks cargo for the drop-ins' features."""
    out: list[str] = []
    seen: set[tuple[str, str]] = set()
    for row in data.get("upstream_switch", []):
        where = f"upstream switch {row.get('original')}/{row.get('switch')}"
        unknown = set(row) - SWITCH_KEYS
        if unknown:
            out.append(f"{where} has keys this reader does not know: {sorted(unknown)}")
        if row.get("original") not in SWITCH_ORIGINALS:
            out.append(f"{where}: original is none of {list(SWITCH_ORIGINALS)}")
        if row.get("class") not in SWITCH_CLASSES:
            out.append(f"{where}: class {row.get('class')!r} is none of {list(SWITCH_CLASSES)}")
        if not str(row.get("note", "")).strip():
            out.append(f"{where} carries no note -- a verdict with no reason is not one")
        if (row.get("class") in ("maps", "always")) != ("anchor" in row):
            out.append(f"{where}: a `maps` or `always` row names an anchor and no other does")
        if "macro" in row and not (row.get("original") == "zenoh-c" and row.get("class") == "maps"
                                   and str(row["macro"]).startswith("Z_FEATURE_")):
            out.append(f"{where}: only a zenoh-c `maps` row names a macro, and it is Z_FEATURE_*")
        if "sense" in row and (row["sense"] != "inverse" or "macro" not in row):
            out.append(f"{where}: sense is only \"inverse\", on a row that names its macro")
        key = (row.get("original"), row.get("switch"))
        if key in seen:
            out.append(f"{where} has two rows -- two answers to one question")
        seen.add(key)
    switches = data.get("upstream_switch", [])
    for cap in data.get("capability", []):
        mapped = pico_rows_to(switches, cap["id"])
        if mapped and "pico_flags_all" in cap:
            out.append(f"{cap['id']}: rows map {mapped} to it, so it names no pico_flags_all")
        combine = cap.get("pico_combine")
        if combine is not None and (combine != "all" or len(mapped) < 2):
            out.append(f"{cap['id']}: pico_combine is only \"all\", for a capability two or more "
                       f"rows map to; {len(mapped)} do")
        if mapped and "pico" not in cap.get("abis", []):
            out.append(f"{cap['id']}: zenoh-pico rows map to it and the pico ABI does not export it")
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


POLICY_KINDS = ("bool", "choice")
POLICY_ID_RE = re.compile(r"[a-z][a-z0-9]*(-[a-z0-9]+)*")
POLICY_KEYS = {"id", "kind", "kconfig", "choices", "default", "upstream", "since", "help"}


def snake(name: str) -> str:
    return name.replace("-", "_")


def camel(name: str) -> str:
    return "".join(part.capitalize() for part in name.split("-"))


def policy_symbols(pol: dict) -> list[str]:
    """The Kconfig symbols a policy declares: its own for a bool, and for a choice the choice and
    one option per value."""
    kconfig = pol.get("kconfig")
    if pol.get("kind") == "choice":
        return [kconfig] + [f"{kconfig}_{snake(c).upper()}" for c in pol.get("choices", [])]
    return [kconfig]


def validate_policies(policies: list[dict], catalog_version: int) -> list[str]:
    """A policy is behaviour upstream does not have (docs/build-configuration.md, C2 and
    section 5): it is declared with the upstream behaviour it departs from, and it defaults to that
    behaviour, so a bool defaults off and a choice defaults to the value that is upstream's."""
    out: list[str] = []
    ids = [p.get("id") for p in policies]
    if len(ids) != len(set(ids)):
        out.append("a policy id is declared twice")
    for pol in policies:
        pid = pol.get("id", "?")
        for key in sorted(set(pol) - POLICY_KEYS):
            out.append(f"policy `{pid}`: `{key}` is not a key a policy has")
        if not POLICY_ID_RE.fullmatch(str(pid)):
            out.append(f"policy `{pid}`: an id is lowercase words joined by `-`")
            continue
        kind = pol.get("kind")
        if kind not in POLICY_KINDS:
            out.append(f"policy `{pid}`: kind is {kind!r}, one of {', '.join(POLICY_KINDS)}")
            continue
        if pol.get("kconfig") != f"WZ_POLICY_{snake(pid).upper()}":
            out.append(f"policy `{pid}`: its Kconfig symbol is `{pol.get('kconfig')}`, not "
                       f"WZ_POLICY_{snake(pid).upper()}")
        if kind == "bool":
            if "choices" in pol:
                out.append(f"policy `{pid}`: a bool has no `choices`")
            if pol.get("default") != "off":
                out.append(f"policy `{pid}`: a bool policy defaults to `off`, which is upstream's "
                           f"behaviour (C2); it says {pol.get('default')!r}")
        else:
            choices = pol.get("choices")
            if not isinstance(choices, list) or len(choices) < 2:
                out.append(f"policy `{pid}`: a choice has two or more `choices`")
            else:
                if len(choices) != len(set(choices)):
                    out.append(f"policy `{pid}`: a value is listed twice in `choices`")
                for c in choices:
                    if not POLICY_ID_RE.fullmatch(str(c)):
                        out.append(f"policy `{pid}`: the value `{c}` is lowercase words joined by `-`")
                if len({camel(str(c)) for c in choices}) != len(choices):
                    out.append(f"policy `{pid}`: two values name the same Rust variant")
                if pol.get("default") not in choices:
                    out.append(f"policy `{pid}`: default {pol.get('default')!r} is not one of "
                               f"its choices")
        if not isinstance(pol.get("upstream"), str) or not pol["upstream"].strip():
            out.append(f"policy `{pid}`: it does not say what upstream does; a behaviour that "
                       "departs from no upstream behaviour is a capability or a defect, not a policy")
        if not isinstance(pol.get("since"), int) or not 1 <= pol["since"] <= catalog_version:
            out.append(f"policy `{pid}`: `since` is the catalogue version in force when it was "
                       f"added, an integer from 1 to {catalog_version}")
        if not isinstance(pol.get("help"), str) or not pol["help"].strip():
            out.append(f"policy `{pid}`: it has no help")
        elif "\n\n" in pol["help"].strip():
            out.append(f"policy `{pid}`: its help is more than one paragraph")
        elif re.search(r"\[`|crate::", pol["help"]):
            out.append(f"policy `{pid}`: its help names Rust items; it is written for a deployer")
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
UNDEF_RE = re.compile(r"^\s*/\*\s*#\s*undef\s+(Z_FEATURE_[A-Z0-9_]+)\s*\*/")


def pico_flag_states(text: str) -> tuple[set[str], set[str]]:
    """The pico switches a header turns on, and those it states off (`0`, or `#cmakedefine`'s
    `/* #undef */`). A switch it does not mention is in neither."""
    on: set[str] = set()
    off: set[str] = set()
    for line in text.splitlines():
        d = DEFINE_RE.match(line)
        if d:
            (on if d.group(2) == "1" else off).add(d.group(1))
            continue
        b = BARE_DEFINE_RE.match(line)
        if b:
            on.add(b.group(1))
            continue
        u = UNDEF_RE.match(line)
        if u:
            off.add(u.group(1))
    return on, off


ZENOH_C_DROP_IN = "wz-capi-c/"
MACRO_DEFINE_RE = re.compile(r"^\s*#\s*define\s+(Z_FEATURE_[A-Z0-9_]+)\b")


def drop_in_arm(decl: dict, text: str) -> list[str]:
    """The wz-capi-c features that select the ABI arm a program compiled against this installed
    zenoh-c's `zenoh_configure.h` needs, added to the drop-in's default build.

    zenoh-c writes one `#define Z_FEATURE_*` per cargo feature it was built with, and two of
    them move the C types a program allocates (the unstable API and shared memory). The rows that
    name a macro are those; each turns its drop-in feature on when the header states the switch,
    or when it does not where the row's sense is inverse. The arm is selected by ADDITION to the
    default, which sits at the origin of both axes (open-debt item 616, held by
    `zenoh_c_archive_arm.py`): a selection by subtraction would be handed the default back by any
    dependent that enables it. A link or a handshake zenoh-c was built without moves no type, so
    the drop-in keeps its own defaults for them.
    """
    defined = {m.group(1) for line in text.splitlines() if (m := MACRO_DEFINE_RE.match(line))}
    out: list[str] = []
    for row in decl["switches"]:
        if row.get("original") != "zenoh-c" or "macro" not in row:
            continue
        if (row["macro"] in defined) != (row.get("sense") == "inverse"):
            out.append(row["anchor"].removeprefix(ZENOH_C_DROP_IN))
    return out


def drop_in_features(decl: dict, text: str) -> str:
    """`drop_in_arm` as cargo arguments, each feature qualified by its package so the same words
    serve a build of wz-capi-c alone and one of several packages; empty for the default arm."""
    arm = drop_in_arm(decl, text)
    return f"--features {','.join(ZENOH_C_DROP_IN + f for f in arm)}" if arm else ""


def pico_header_conflicts(decl: dict, abi: str, text: str) -> list[str]:
    """Capabilities a pico header states off that the ones it turns on imply in wz.

    wz's capability graph can need more than pico does for the same switch: the advanced plane
    implies the unstable API, which pico's CMake does not force for the advanced subscription. A
    build that added the implied capability would change the option struct layouts the program
    was compiled against, so the header is refused rather than built differently from its own
    statement."""
    caps = decl["caps"]
    on = read_config(decl, text)
    flags_on, flags_off = pico_flag_states(text)
    out: list[str] = []
    for cid in sorted(closure(caps, on) - on):
        if abi not in caps[cid]["abis"]:
            continue
        flags, _ = pico_switches(decl, cid)
        if flags and all(f in flags_on | flags_off for f in flags):
            askers = sorted(x for x in on if cid in closure(caps, {x}) and x != cid)
            out.append(f"the header states {cid} off ({', '.join(flags)}), and {', '.join(askers)}, "
                       f"which it turns on, implies it in wz")
    return out


def read_config(decl: dict, text: str) -> set[str]:
    """The capabilities a `.config` or pico header turns ON. Unmentioned means off.

    A capability's pico switches are the `maps` rows to it (`pico_switches`): it is on when one
    of them is (the advanced plane, which either advanced switch asks for), or when all are where
    it says so (the multicast transport, which pico has only with its group link). One no row
    reaches is on when every switch of its `pico_flags_all` is (the liveliness get exists where
    pico has both the liveliness and the query plane).
    """
    by_kconfig = {c["kconfig"]: cid for cid, c in decl["caps"].items()}
    on: set[str] = set()
    for line in text.splitlines():
        m = CONFIG_RE.match(line)
        if m and m.group(1) in by_kconfig:
            on.add(by_kconfig[m.group(1)])
    flags_on, _ = pico_flag_states(text)
    for cid in decl["caps"]:
        flags, combine = pico_switches(decl, cid)
        if flags and (all if combine == "all" else any)(f in flags_on for f in flags):
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


def enabled_features(feats: dict, start: list[str]) -> set[str]:
    """The features of one package a build with `start` turns on, as cargo resolves them: each
    feature's entries that name another feature of the same package, transitively. An entry
    that names a dependency (`dep:x`) or a dependency's feature (`x/f`) is not this package's."""
    out: set[str] = set()
    stack = list(start)
    while stack:
        feat = stack.pop()
        if feat in out:
            continue
        if feat not in feats:
            raise KeyError(f"`{feat}` is no feature of this package")
        out.add(feat)
        stack.extend(e for e in feats[feat] if "/" not in e and not e.startswith("dep:"))
    return out


def pico_reference(decl: dict, enabled: set[str]) -> dict[str, int]:
    """The zenoh-pico build that carries what a wz-capi-pico build with the features `enabled`
    carries: every pico switch the declaration answers, set from that answer.

    `always` is on (wz has the capability in every build, so a reference without it would be
    smaller for a reason that is not the comparison's), `never` is off (wz has no such plane to
    be compared with), and `maps` is on exactly when the build has the row's feature. A switch
    the declaration calls `n/a` is not wz's to set: the reference keeps upstream's default.
    This is the denominator a size ratio is taken against, derived and never written by hand:
    a hand-written one is how the ratios of rounds 3393 to 3395 came to rest on a build nobody
    recorded."""
    out: dict[str, int] = {}
    for row in decl["switches"]:
        if row.get("original") != "zenoh-pico":
            continue
        cls = row["class"]
        if cls == "always":
            out[row["switch"]] = 1
        elif cls == "never":
            out[row["switch"]] = 0
        elif cls == "maps":
            out[row["switch"]] = int(row["anchor"].removeprefix(PICO_DROP_IN) in enabled)
    return out


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
        flags, combine = pico_switches(decl, cid)
        if len(flags) == 1:
            lines.append(f"\t  zenoh-pico's switch for it: {flags[0]}.")
        elif flags and combine == "all":
            lines.append(f"\t  zenoh-pico has it when all of these are on: {', '.join(flags)}.")
        elif flags:
            lines.append(f"\t  zenoh-pico's switches for it, either of which asks for it: "
                         f"{', '.join(flags)}.")
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


def rust_limit_const(name: str, kconfig: str, default: object) -> list[str]:
    """One limit's const as rustfmt lays it out: on one line when it fits, else after the `=`, and
    one argument a line when the arguments of `limit(..)` are themselves wider than rustfmt keeps
    a call (a long limit name is what makes them so)."""
    args = f'option_env!("{kconfig}"), {default}'
    value = f"limit({args})"
    if len(f"pub(super) const {name}: usize = {value};") > RUST_MAX_WIDTH and len(args) > RUST_FN_CALL_WIDTH:
        return [
            f"pub(super) const {name}: usize = limit(",
            f'    option_env!("{kconfig}"),',
            f"    {default},",
            ");",
        ]
    return rust_const(name, value)


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
        out += rust_limit_const(lim["id"], lim["kconfig"], lim["default"])
    return "\n".join(out) + "\n"


def emit_kconfig_policies(decl: dict) -> str:
    """A bool policy is a `bool` symbol that defaults to `n`; a choice is a Kconfig `choice` with
    one option per value, the default being upstream's. Each help ends with what upstream does."""
    out = generated_header("#", "kconfig-policies") + [
        "",
        'menu "wz policies"',
        "",
        'comment "Each policy is behaviour beyond upstream; the default of every one is upstream\'s."',
        "",
    ]
    for pol in decl["policies"]:
        help_text = pol["help"].strip().splitlines() + textwrap.wrap(
            f"Upstream: {pol['upstream'].strip()}", width=78)
        if pol["kind"] == "bool":
            out += [f"config {pol['kconfig']}", f'\tbool "{pol["id"]}"', "\tdefault n", "\thelp"]
            out += help_lines("\n".join(help_text))
            out.append("")
            continue
        default = f"{pol['kconfig']}_{snake(pol['default']).upper()}"
        out += [f"choice {pol['kconfig']}", f'\tprompt "{pol["id"]}"', f"\tdefault {default}", "\thelp"]
        out += help_lines("\n".join(help_text))
        for value in pol["choices"]:
            out += ["", f"config {pol['kconfig']}_{snake(value).upper()}", f'\tbool "{value}"']
        out += ["", "endchoice", ""]
    out.append("endmenu")
    return "\n".join(out) + "\n"


def rust_doc(text: str, indent: str) -> list[str]:
    return textwrap.wrap(text, width=92, initial_indent=f"{indent}/// ",
                         subsequent_indent=f"{indent}/// ")


def emit_rust_policies(decl: dict) -> str:
    """The module `policy.rs` includes: one enum per choice policy, and `SessionPolicy`, whose
    fields are the policies of the build and whose `Default` is what the build's environment
    (`WZ_POLICY_<NAME>`) states, or upstream's behaviour when it states nothing. Laid out so
    rustfmt leaves it alone: every call fits on a line, and a struct literal is one line only
    when rustfmt would make it one."""
    pols = decl["policies"]
    choices = [p for p in pols if p["kind"] == "choice"]
    bools = [p for p in pols if p["kind"] == "bool"]
    out = generated_header("//", "rust-policies") + [
        "",
        "//! The policies of a build as the code reads them: each is a field of [`SessionPolicy`], whose",
        "//! `Default` is the value the build's environment states as `WZ_POLICY_<NAME>`, or upstream's",
        "//! behaviour when it states none. A test names the other value by setting the field.",
        "",
    ]
    helpers = (["policy_bool"] if bools else []) + (["policy_choice"] if choices else [])
    if len(helpers) == 1:
        out += [f"use super::{helpers[0]};", ""]
    elif helpers:
        out += ["use super::{policy_bool, policy_choice};", ""]
    for pol in choices:
        name = camel(pol["id"])
        values = pol["choices"]
        out += rust_doc(f"`{pol['id']}`: {pol['help'].strip()}".replace("\n", " "), "")
        out += rust_doc(f"Upstream: {pol['upstream'].strip()}", "")
        out += ["#[derive(Clone, Copy, Debug, PartialEq, Eq)]", f"pub enum {name} {{"]
        for value in values:
            out += [f"    /// `{value}`.", f"    {camel(value)},"]
        out += ["}", "", f"impl {name} {{"]
        out += ["    /// The value as the declaration, the Kconfig and the environment spell it.",
                "    pub const fn id(self) -> &'static str {", "        match self {"]
        out += [f'            Self::{camel(v)} => "{v}",' for v in values]
        out += ["        }", "    }", ""]
        ids = ", ".join(f'"{v}"' for v in values)
        variants = ", ".join(f"Self::{camel(v)}" for v in values)
        out += [f"    const CHOICES: [&str; {len(values)}] = [{ids}];",
                f"    const ALL: [Self; {len(values)}] = [{variants}];", "",
                "    const fn stated() -> Self {",
                f'        let stated = option_env!("{pol["kconfig"]}");',
                f"        let index = policy_choice(stated, &Self::CHOICES, {values.index(pol['default'])});",
                "        Self::ALL[index]", "    }", "}", "",
                f"impl Default for {name} {{", "    fn default() -> Self {", "        Self::stated()", "    }", "}", ""]
    out += ["/// What this build decided beyond upstream's behaviour.",
            "#[derive(Clone, Copy, Debug, PartialEq, Eq)]", "#[non_exhaustive]"]
    if pols:
        out.append("pub struct SessionPolicy {")
        for pol in pols:
            out += rust_doc(f"`{pol['id']}`. Upstream: {pol['upstream'].strip()}", "    ")
            out.append(f"    pub {snake(pol['id'])}: {camel(pol['id']) if pol['kind'] == 'choice' else 'bool'},")
        out.append("}")
    else:
        out.append("pub struct SessionPolicy {}")
    out += ["", "impl SessionPolicy {",
            "    /// The policy this build states: its environment's values, else upstream's.",
            "    pub const fn from_build() -> Self {"]
    for pol in pols:
        field = snake(pol["id"])
        if pol["kind"] == "choice":
            out.append(f"        let {field} = {camel(pol['id'])}::stated();")
        else:
            out.append(f'        let {field} = policy_bool(option_env!("{pol["kconfig"]}"));')
    fields = ", ".join(snake(p["id"]) for p in pols)
    if len(fields) <= RUST_STRUCT_LIT_WIDTH:
        out.append(f"        Self {{ {fields} }}" if fields else "        Self {}")
    else:
        out += ["        Self {"] + [f"            {snake(p['id'])}," for p in pols] + ["        }"]
    out += ["    }", "}", "", "impl Default for SessionPolicy {", "    fn default() -> Self {",
            "        Self::from_build()", "    }", "}"]
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
    if decl["policies"]:
        out.append('rsource "Kconfig.policies"')
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


def defconfig_path(original: str) -> pathlib.Path:
    return CONFIGS / f"{original}_defconfig"


def original_choices(decl: dict, original: str) -> list[dict]:
    """The options of the global axes that are `original`'s own default build's choice."""
    return [o for a in global_axes(decl) for o in decl["options"]
            if o["axis"] == a["id"] and original in o.get("upstream_on", [])]


def original_values(decl: dict, original: str) -> dict[str, bool]:
    """Every capability `original` is judged for, to whether its own default build has it."""
    return {cid: upstream_default(cap, original) for cid, cap in decl["caps"].items()
            if original in upstream_families(cap)}


def emit_defconfig(decl: dict, original: str) -> str:
    """`original`'s own default build in wz's switches: its choices on the global axes, and every
    capability it is judged for whose value differs from the Kconfig default."""
    out = generated_header("#", f"defconfig:{original}") + [
        "#",
        f"# {original}'s own default build in wz's switches (docs/build-configuration.md step 2):",
        "# its choice on each global axis, and every capability it is judged for whose value",
        "# differs from the Kconfig default. A capability its ABIs do not reach keeps the default.",
        f"# A preset whose `# base:` is {original} is merged onto this file.",
        f"# catalog: {decl['catalog_version']}",
        f"# original: {original}",
    ]
    for option in original_choices(decl, original):
        out.append(f"CONFIG_{option['kconfig']}=y")
    values = original_values(decl, original)
    for cid in decl["order"]:
        if cid in values and values[cid] != default_on(decl["caps"][cid]):
            out.append(f"CONFIG_{decl['caps'][cid]['kconfig']}={'y' if values[cid] else 'n'}")
    return "\n".join(out) + "\n"


GENERATED = {
    "kconfig-root": (KCONFIG_ROOT, emit_kconfig_root),
    "kconfig-capabilities": (KCONFIG_CAPS, emit_kconfig_capabilities),
    "kconfig-limits": (KCONFIG_LIMITS, emit_kconfig_limits),
    "rust-limits": (RUST_LIMITS, emit_rust_limits),
    "rust-policies": (RUST_POLICIES, emit_rust_policies),
}


def generated_files(decl: dict) -> dict[str, tuple[pathlib.Path, str]]:
    """Every derived file, by the `--emit` kind that prints it: the host files and, for each
    declared image, its axes' Kconfig and the CMake that maps them to cargo."""
    out = {kind: (path, emit(decl)) for kind, (path, emit) in GENERATED.items()}
    if global_axes(decl):
        out["kconfig-axes"] = (KCONFIG_AXES, emit_kconfig_axes(decl))
    if decl["policies"]:
        out["kconfig-policies"] = (KCONFIG_POLICIES, emit_kconfig_policies(decl))
    for original in BASE_ABI:
        out[f"defconfig:{original}"] = (defconfig_path(original), emit_defconfig(decl, original))
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


CRATES_ROOT = ROOT / "crates"
POLICY_READ_RE = re.compile(r'\b(?:option_env|env)!\s*\(\s*"WZ_POLICY_')


def check_policy_reads(crates: pathlib.Path) -> list[str]:
    """A policy's value is read in one place, the generated module. A crate that reads a
    `WZ_POLICY_*` itself would decide a policy where the declaration cannot see it."""
    out: list[str] = []
    generated = RUST_POLICIES.name
    for base, dirs, files in os.walk(crates):
        dirs[:] = [d for d in dirs if d not in ("target", ".git", "node_modules")]
        for name in files:
            if not name.endswith(".rs") or name == generated:
                continue
            path = pathlib.Path(base) / name
            for number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
                if not line.lstrip().startswith("//") and POLICY_READ_RE.search(line):
                    out.append(f"{path.relative_to(crates.parent)}:{number} reads a WZ_POLICY_* "
                               f"itself; a policy's value comes from {generated}")
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
        # A capability both of a pico build's engines have forwards WEAKLY
        # (`wz-capi-core?/<cid>`): to the tokio engine when the build has it, and selecting no
        # engine (docs/capi-pico-on-coop-engine.md). It is a forward all the same.
        if abi != "core" and not ({f"wz-capi-core/{cid}", f"wz-capi-core?/{cid}"} & set(feats[cid])):
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


def resolve(fragments: list[pathlib.Path], kconfiglib=None, original: str | None = None):
    """The configuration the generated Kconfig gives when `fragments` are merged in order onto
    its defaults, a later fragment overriding an earlier one, read by `kconfiglib` (the pinned
    interpreter when not given).

    The merge starts from the original the presets name in their `# base:` line: its generated
    defconfig is merged first (docs/build-configuration.md section 6), so a preset says only how
    it differs from that original. Presets of two originals are one build of neither and are
    refused. `original` merges that original's defconfig with no preset (`fragments` empty).

    Strict (C9): a symbol the tree does not have, a value outside a symbol's type or range and an
    assignment its dependencies do not allow are each refused with kconfiglib's own words,
    never dropped; so is a fragment whose header names another catalogue.
    """
    kconfiglib = kconfiglib or kconfiglib_module()
    if kconfiglib is None:
        raise PresetError("kconfiglib is not installed: run scripts/provision-kconfiglib.sh")
    decl = load_decl()
    problems: list[str] = []
    bases: set[str] = set()
    for frag in fragments:
        text = frag.read_text(encoding="utf-8")
        problems += check_preset_header(decl, frag.name, text)
        bases.add(preset_header(text).get("base"))
    if len(bases) > 1:
        problems.append(f"the presets name {sorted(map(str, bases))} as their base; one build has "
                        "one original")
    if problems:
        raise PresetError("; ".join(problems))
    if fragments:
        original = bases.pop()
    if original is not None:
        fragments = [defconfig_path(original)] + list(fragments)
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


def resolved_policy(kconf, pol: dict) -> str:
    """The value a configuration gives a policy: `on` or `off` for a bool, the chosen value's id
    for a choice."""
    if pol["kind"] == "bool":
        return "on" if kconf.syms[pol["kconfig"]].tri_value == 2 else "off"
    for value in pol["choices"]:
        if kconf.syms[f"{pol['kconfig']}_{snake(value).upper()}"].tri_value == 2:
            return value
    raise PresetError(f"policy {pol['id']} has no value chosen")


def resolved_policy_env(decl: dict, kconf) -> list[str]:
    """`WZ_POLICY_<NAME>=<value>` for every policy the configuration sets off upstream's."""
    out: list[str] = []
    for pol in decl["policies"]:
        value = resolved_policy(kconf, pol)
        if value != pol["default"]:
            out.append(f"{pol['kconfig']}={value}")
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
    for original in BASE_ABI:
        try:
            kconf = resolve([], original=original)
        except PresetError as exc:
            print(f"  wz-config presets FAIL: {defconfig_path(original).name}: {exc}", file=sys.stderr)
            bad += 1
            continue
        differences = original_differences(decl, original, kconf)
        for difference in differences:
            print(f"  wz-config presets FAIL: {defconfig_path(original).name}: {difference}",
                  file=sys.stderr)
        bad += bool(differences)
        if not differences:
            print(f"  wz-config presets: {defconfig_path(original).name} reproduces {original}: "
                  f"{len(original_values(decl, original))} capabilities, "
                  f"{', '.join(o['id'] for o in original_choices(decl, original))}")
    return 1 if bad else 0


def original_differences(decl: dict, original: str, kconf) -> list[str]:
    """Where the resolved defconfig of `original` is not that original's own default build: a
    capability it is judged for with another value, or a global choice not taken."""
    out: list[str] = []
    have = resolved_caps(decl, kconf)
    for cid, want in sorted(original_values(decl, original).items()):
        if (cid in have) != want:
            out.append(f"{cid} resolves {'on' if cid in have else 'off'}, and {original}'s own "
                       f"default build has it {'on' if want else 'off'}")
    for option in original_choices(decl, original):
        if kconf.syms[option["kconfig"]].tri_value != 2:
            out.append(f"{option['kconfig']} is not the choice taken, and it is {original}'s")
    # C2: an original's own build departs from itself nowhere, so no policy is on in it.
    for pol in decl["policies"]:
        value = resolved_policy(kconf, pol)
        if value != pol["default"]:
            out.append(f"policy {pol['id']} resolves {value}, and {original}'s own build has "
                       f"upstream's behaviour, {pol['default']}")
    return out


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
    inputs: list[tuple[str, list[pathlib.Path], str | None]] = [("the defaults", [], None)]
    inputs += [(defconfig_path(o).name, [], o) for o in BASE_ABI]
    inputs += [(p.name, [p], None) for p in sorted(PROFILES.glob("*.conf"))]
    bad = 0
    for label, fragments, original in inputs:
        try:
            a = configuration(resolve(fragments, pinned, original))
            b = configuration(resolve(fragments, zephyr, original))
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
    if "kconfig-policies" not in files and KCONFIG_POLICIES.exists():
        findings.append(f"{KCONFIG_POLICIES.relative_to(ROOT)} exists, but the declaration has no "
                        "policy: remove it")
    findings += check_policy_reads(CRATES_ROOT)
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
    # The platform rows against the compiler that builds for them. A compiler that is absent is a
    # finding and not a skip: a gate that cannot reach its input must not report green.
    for package in ASSESSED_PACKAGES:
        try:
            manifest_names = set(manifest_features(ROOT / "crates" / package / "Cargo.toml"))
        except (KeyError, OSError) as exc:
            findings.append(f"{package}: {exc}")
            continue
        findings += runtime_feature_findings(
            {"runtime_features": [r for r in decl["runtime_features"] if r["package"] == package]},
            lambda _p, names=manifest_names: names)
    if shutil.which("rustc") is None:
        findings.append("rustc is absent, so the platform triples cannot be checked against it")
    else:
        try:
            findings += platform_rustc_findings(decl["platforms"], rustc_target_list(), rustc_cfg)
        except ValueError as exc:
            findings.append(str(exc))
    for finding in findings:
        print(f"  wz-config FAIL: {finding}", file=sys.stderr)
    if findings:
        return 1
    n_global = len(global_axes(decl))
    unassessed = [p["id"] for p in decl["platforms"] if "os_provides" not in p]
    print(f"  wz-config: {len(decl['order'])} capabilities, {len(decl['limits'])} limits, "
          f"{len(decl['policies'])} policies, {n_global} global and {len(decl['axes']) - n_global} image axes, {len(files)} "
          f"generated files current, caps.rs bound, {len(MANIFESTS)} manifests agree, "
          f"{len(decl['platforms'])} platforms agree with rustc")
    if unassessed:
        print(f"  wz-config: platforms with no os_provides (unassessed, refused by the entry): "
              f"{', '.join(unassessed)}")
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

[os]
base = ["threads", "sockets-tcp", "entropy"]

[[capability]]
id = "a"
kconfig = "WZ_CAP_A"
abis = ["core", "pico"]
upstream_on = ["zenoh-pico"]
implies = []
os_needs = ["sockets-udp"]
help = "A."

[[platform]]
id = "linux-x"
triple = "x86_64-unknown-linux-gnu"
os = "linux"
libc = "glibc"
std = "prebuilt"
lane = "none"
support = "built"
os_provides = ["threads", "sockets-tcp", "sockets-udp", "entropy"]
help = "A sample platform."

[[runtime_feature]]
package = "wz-runtime-tokio"
feature = "f1"
os_needs = ["sockets-udp"]
help = "A sample feature."

[[parity]]
need = "sample-need"
capabilities = ["a"]
runtime_features = ["f1"]
help = "A sample need."

[[artifact]]
id = "lib-a"
package = "pkg-a"
kind = "shared-library"
file = "pkg_a"
family = "fam-a"
abi = "pico"
help = "A sample library."

[[role]]
artifact = "lib-a"
id = "pico-library"
help = "A sample role."

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
os_needs = []
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


POLICY_SAMPLE = """\

[[policy]]
id = "wire-mode"
kind = "choice"
kconfig = "WZ_POLICY_WIRE_MODE"
choices = ["os-default", "on", "off"]
default = "os-default"
upstream = "Leaves the operating system's own setting."
since = 3
help = '''
How the wire is set.
'''

[[policy]]
id = "eager-flush"
kind = "bool"
kconfig = "WZ_POLICY_EAGER_FLUSH"
default = "off"
upstream = "Flushes on the batch boundary."
since = 3
help = '''
Flush early.
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
    expect("either advanced switch asks for the advanced plane",
           "advanced" in read_config(decl, "#define Z_FEATURE_ADVANCED_SUBSCRIPTION 1\n")
           and "advanced" in read_config(decl, "#define Z_FEATURE_ADVANCED_PUBLICATION 1\n"))
    expect("an installed zenoh-c's arm is added to the drop-in's default, each axis by its macro",
           drop_in_features(decl, "#define Z_FEATURE_UNSTABLE_API\n#define Z_FEATURE_SHARED_MEMORY\n")
           == "--features wz-capi-c/zenoh-c-shared-memory"
           and drop_in_features(decl, "#define Z_FEATURE_UNSTABLE_API\n") == ""
           and drop_in_arm(decl, "#define Z_FEATURE_TRANSPORT_TCP\n") == ["zenoh-c-no-unstable-api"]
           and drop_in_arm(decl, "// #define Z_FEATURE_UNSTABLE_API\n#define Z_FEATURE_SHARED_MEMORY\n")
           == ["zenoh-c-shared-memory", "zenoh-c-no-unstable-api"])
    sub_only = "#define Z_FEATURE_ADVANCED_PUBLICATION 0\n#define Z_FEATURE_ADVANCED_SUBSCRIPTION 1\n"
    expect("a header that asks for the advanced plane with the unstable API stated off is refused",
           any("unstable-api" in c for c in pico_header_conflicts(
               decl, "pico", sub_only + "/* #undef Z_FEATURE_UNSTABLE_API */\n")))
    expect("the same header with the unstable API on, or silent on it, is not",
           pico_header_conflicts(decl, "pico", sub_only + "#define Z_FEATURE_UNSTABLE_API\n") == []
           and pico_header_conflicts(decl, "pico", sub_only) == [])
    expect("a header reads a 0 and an #undef as stated off and a bare define as on",
           pico_flag_states("#define Z_FEATURE_A 0\n/* #undef Z_FEATURE_B */\n#define Z_FEATURE_C\n")
           == ({"Z_FEATURE_C"}, {"Z_FEATURE_A", "Z_FEATURE_B"}))
    expect("the multicast transport needs both of its switches",
           "multicast-transport" not in read_config(decl, "#define Z_FEATURE_MULTICAST_TRANSPORT 1\n")
           and "multicast-transport" in read_config(
               decl, "#define Z_FEATURE_MULTICAST_TRANSPORT 1\n#define Z_FEATURE_LINK_UDP_MULTICAST 1\n"))
    expect("a capability's pico switches are the maps rows to it",
           pico_switches(decl, "query") == (["Z_FEATURE_QUERY"], "any")
           and pico_switches(decl, "liveliness-get")
           == (["Z_FEATURE_LIVELINESS", "Z_FEATURE_QUERY"], "all")
           and pico_switches(decl, "gossip") == ([], "all"))
    expect("a bare #define is on and a #cmakedefine's #undef is off",
           read_config(decl, "#define Z_FEATURE_UNSTABLE_API\n") == {"unstable-api"}
           and read_config(decl, "/* #undef Z_FEATURE_UNSTABLE_API */\n") == set())
    expect("advanced and connectivity pull the unstable API in pico",
           "unstable-api" in features_for(decl, "pico", {"advanced"})
           and "unstable-api" in features_for(decl, "pico", {"connectivity"}))
    feats = {"default": ["a"], "a": ["b", "dep:x", "y/z"], "b": [], "c": []}
    expect("a build's features are cargo's closure within the package",
           enabled_features(feats, ["default"]) == {"default", "a", "b"}
           and enabled_features(feats, []) == set())
    try:
        enabled_features(feats, ["nope"])
        expect("a feature the package lacks is refused", False)
    except KeyError:
        pass
    bare = pico_reference(decl, set())
    expect("the reference has every always switch on, every never one off, a maps one as built",
           bare["Z_FEATURE_PUBLICATION"] == 1 and bare["Z_FEATURE_INTEREST"] == 1
           and bare["Z_FEATURE_LINK_BLUETOOTH"] == 0 and bare["Z_FEATURE_QUERY"] == 0
           and pico_reference(decl, {"query"})["Z_FEATURE_QUERY"] == 1)
    expect("an n/a switch is left at upstream's default", "Z_FEATURE_BATCH_TX_MUTEX" not in bare)
    built = set(features_for(decl, "pico", {"peer"}))
    header = "".join(f"#define {s} {v}\n" for s, v in pico_reference(decl, built).items())
    expect("the reference reads back as the build it was derived from",
           read_config(decl, header) == closure(decl["caps"], {"peer"}))
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
    wide_name = "DECLARATION_SYNC_FINAL_TIMEOUT_MS"
    expect("arguments wider than rustfmt keeps a call go one a line, as rustfmt lays them out",
           rust_limit_const(wide_name, f"WZ_LIMIT_{wide_name}", 1000) == [
               f"pub(super) const {wide_name}: usize = limit(",
               f'    option_env!("WZ_LIMIT_{wide_name}"),',
               "    1000,",
               ");"])
    expect("a short limit stays on one line",
           rust_limit_const("MAX_A", "WZ_LIMIT_MAX_A", 4)
           == ['pub(super) const MAX_A: usize = limit(option_env!("WZ_LIMIT_MAX_A"), 4);'])
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
    # The policies and their derivations.
    with_policy = SAMPLE + POLICY_SAMPLE
    expect("a sample policy declaration validates", validate_decl(read_decl_toml(with_policy)) == [])
    pdecl = decl_of(read_decl_toml(with_policy))

    def policy_refused(old: str, new: str, words: str) -> bool:
        return any(words in p for p in validate_decl(read_decl_toml(with_policy.replace(old, new))))

    expect("a bool policy that defaults on is refused",
           policy_refused('default = "off"', 'default = "on"', "defaults to `off`"))
    expect("a choice whose default is not a choice is refused",
           policy_refused('default = "os-default"', 'default = "other"', "not one of its choices"))
    expect("a policy whose Kconfig symbol is not derived from its id is refused",
           policy_refused('kconfig = "WZ_POLICY_EAGER_FLUSH"', 'kconfig = "WZ_POLICY_X"', "not WZ_POLICY_EAGER_FLUSH"))
    expect("a policy that says nothing of upstream is refused",
           policy_refused('upstream = "Flushes on the batch boundary."', 'upstream = " "',
                          "does not say what upstream does"))
    expect("a policy id that is not lowercase words is refused",
           policy_refused('id = "eager-flush"', 'id = "Eager_Flush"', "lowercase words"))
    expect("a key a policy does not have is refused",
           policy_refused('since = 3\nhelp = \'\'\'\nFlush early.', 'since = 3\nspare = 1\nhelp = \'\'\'\nFlush early.',
                          "`spare` is not a key"))
    expect("a `since` past the catalogue is refused",
           policy_refused('since = 3\nhelp = \'\'\'\nFlush early.', 'since = 9\nhelp = \'\'\'\nFlush early.',
                          "`since`"))
    expect("a choice listing a value twice is refused",
           policy_refused('["os-default", "on", "off"]', '["os-default", "on", "on"]', "listed twice"))
    expect("a policy declared twice is refused",
           any("declared twice" in p for p in validate_decl(read_decl_toml(with_policy + POLICY_SAMPLE))))
    kpolicies = emit_kconfig_policies(pdecl)
    expect("a choice policy is a Kconfig choice that defaults to upstream's value",
           "choice WZ_POLICY_WIRE_MODE\n\tprompt \"wire-mode\"\n\tdefault WZ_POLICY_WIRE_MODE_OS_DEFAULT" in kpolicies
           and "config WZ_POLICY_WIRE_MODE_OFF\n\tbool \"off\"" in kpolicies)
    expect("a bool policy defaults to n, and its help ends with what upstream does",
           "config WZ_POLICY_EAGER_FLUSH\n\tbool \"eager-flush\"\n\tdefault n" in kpolicies
           and "\t  Upstream: Flushes on the batch boundary.\n" in kpolicies)
    rpolicies = emit_rust_policies(pdecl)
    expect("a choice policy is an enum whose default index is upstream's",
           "pub enum WireMode {" in rpolicies and "policy_choice(stated, &Self::CHOICES, 0)" in rpolicies)
    expect("a choice enum's Default is the build's value, so a config struct can derive Default",
           "impl Default for WireMode {\n    fn default() -> Self {\n        Self::stated()\n" in rpolicies)
    expect("a bool policy reads its environment and nothing else",
           'let eager_flush = policy_bool(option_env!("WZ_POLICY_EAGER_FLUSH"));' in rpolicies
           and "use super::{policy_bool, policy_choice};" in rpolicies)
    expect("a literal past rustfmt's width goes one field a line",
           "        Self {\n            wire_mode,\n            eager_flush,\n        }\n" in rpolicies)
    nothing = emit_rust_policies({"policies": []})
    expect("no policy is an empty struct and no import",
           "pub struct SessionPolicy {}\n" in nothing and "        Self {}\n" in nothing
           and "use super::" not in nothing)
    one = emit_rust_policies({"policies": [p for p in pdecl["policies"] if p["kind"] == "bool"]})
    expect("a literal rustfmt would make one line is one line",
           "        Self { eager_flush }\n" in one and "use super::policy_bool;" in one)
    import tempfile

    with tempfile.TemporaryDirectory() as reads_tmp:
        reads = pathlib.Path(reads_tmp) / "crates"
        reads.mkdir()
        (reads / "a.rs").write_text('const A: bool = policy_bool(option_env!("WZ_POLICY_X"));\n', encoding="utf-8")
        (reads / "b.rs").write_text('// option_env!("WZ_POLICY_X") is how it is read\n', encoding="utf-8")
        (reads / RUST_POLICIES.name).write_text('const A: Option<&str> = option_env!("WZ_POLICY_X");\n',
                                                encoding="utf-8")
        found = check_policy_reads(reads)
        expect("a crate that reads a policy itself is a finding; a comment and the generated module are not",
               len(found) == 1 and found[0].startswith("crates/a.rs:1"))
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
    # The operating-system facilities and the platforms (docs/target-build-contract.md T3, T9).
    expect("a capability that was never assessed for facilities is refused",
           caps_refused('os_needs = ["sockets-udp"]\n', "", "has no os_needs"))
    expect("a facility outside the vocabulary is refused",
           caps_refused('os_needs = ["sockets-udp"]', 'os_needs = ["sockets-udpp"]', "not a facility"))
    expect("a facility named twice is refused",
           caps_refused('os_needs = ["sockets-udp"]', 'os_needs = ["sockets-udp", "sockets-udp"]', "twice"))
    expect("a facility the base already asks for is refused in a capability",
           caps_refused('os_needs = ["sockets-udp"]', 'os_needs = ["threads"]', "in the [os] base already"))
    expect("an assessed capability that asks for nothing validates",
           validate_decl(read_decl_toml(SAMPLE.replace('os_needs = ["sockets-udp"]', "os_needs = []"))) == [])
    expect("an empty [os] base is refused", caps_refused('base = ["threads", "sockets-tcp", "entropy"]',
                                                        "base = []", "`base` is empty"))
    expect("a platform needs every required key",
           caps_refused('lane = "none"\n', "", "has no `lane`"))
    expect("a platform with an unknown key is refused",
           caps_refused('lane = "none"\n', 'lane = "none"\nextra = "x"\n', "unknown key `extra`"))
    expect("a platform with a libc outside the list is refused",
           caps_refused('libc = "glibc"', 'libc = "musl"', "not one of glibc"))
    expect("a platform with an unknown lane is refused",
           caps_refused('lane = "none"', 'lane = "green"', "lane is `green`"))
    expect("an sdk kind outside the list is refused",
           caps_refused('support = "built"', 'support = "built"\nsdk_kind = "gcc"', "sdk_kind is `gcc`"))
    expect("an sdk kind of the list validates",
           validate_decl(read_decl_toml(SAMPLE.replace('support = "built"', 'support = "built"\nsdk_kind = "android-ndk"'))) == [])
    yocto = 'support = "built"\nsdk_kind = "yocto"\nsystem_assumed = ["libc.so.6"]'
    expect("a library bundled from a named SDK validates",
           validate_decl(read_decl_toml(SAMPLE.replace(
               'support = "built"', yocto + '\nbundle_from_sdk = ["libstdc++.so.6"]'))) == [])
    expect("a library both assumed and bundled is refused",
           caps_refused('support = "built"', yocto + '\nbundle_from_sdk = ["libc.so.6"]',
                        "both assumed on the device and bundled"))
    expect("a bundle with no SDK to take it from is refused",
           caps_refused('support = "built"', 'support = "built"\nsystem_assumed = ["libc.so.6"]\n'
                        'bundle_from_sdk = ["libstdc++.so.6"]', "names no sdk_kind"))
    expect("a bundle on a platform that assumes nothing is refused",
           caps_refused('support = "built"', 'support = "built"\nsdk_kind = "yocto"\n'
                        'bundle_from_sdk = ["libstdc++.so.6"]', "system_assumed is not"))
    expect("a bundled name that is not a SONAME is refused",
           caps_refused('support = "built"', yocto + '\nbundle_from_sdk = ["c++"]', "not a full SONAME"))
    expect("an empty bundle list is refused",
           caps_refused('support = "built"', yocto + '\nbundle_from_sdk = []', "not a non-empty list"))
    expect("a platform that states no support is refused",
           caps_refused('support = "built"\n', "", "has no `support`"))
    expect("a platform with an unknown support word is refused",
           caps_refused('support = "built"', 'support = "maybe"', "support is `maybe`"))
    expect("a lane that is green on a platform that is not verified is refused",
           caps_refused('lane = "none"', 'lane = "build"', "disagree"))
    expect("a platform called verified with no green lane is refused",
           caps_refused('support = "built"', 'support = "verified"', "disagree"))
    expect("a verified platform with a green lane validates",
           validate_decl(read_decl_toml(SAMPLE.replace('lane = "none"', 'lane = "build"').replace(
               'support = "built"', 'support = "verified"'))) == [])
    expect("untried and blocked are platforms with no green lane and validate",
           all(validate_decl(read_decl_toml(SAMPLE.replace('support = "built"', f'support = "{w}"'))) == []
               for w in ("untried", "blocked")))
    expect("a platform with an unknown std kind is refused",
           caps_refused('std = "prebuilt"', 'std = "nightly"', "std is `nightly`"))
    expect("a network stack on a platform that is not QNX is refused",
           caps_refused('lane = "none"\n', 'lane = "none"\nnetwork_stack = "io-sock"\n',
                        "only a QNX platform has a network stack"))
    qnx = SAMPLE.replace('id = "linux-x"', 'id = "qnx-x"').replace(
        'triple = "x86_64-unknown-linux-gnu"', 'triple = "aarch64-unknown-nto-qnx710"').replace(
        'os = "linux"', 'os = "nto"').replace('libc = "glibc"', 'libc = "nto"').replace(
        'std = "prebuilt"', 'std = "build-std"')
    expect("a QNX platform without a network stack is refused",
           any("names its network stack" in p for p in validate_decl(read_decl_toml(qnx))))
    expect("a QNX platform with a network stack validates",
           validate_decl(read_decl_toml(qnx.replace('lane = "none"\n', 'lane = "none"\nnetwork_stack = "io-pkt"\n'))) == [])
    expect("a platform that states what it provides must provide the base",
           caps_refused('"threads", "sockets-tcp", "sockets-udp", "entropy"]',
                        '"sockets-tcp", "sockets-udp", "entropy"]', "does not provide `threads`"))
    expect("a platform providing a facility outside the vocabulary is refused",
           caps_refused('"sockets-udp", "entropy"]', '"sockets-udp", "entropy", "gpu"]', "not a facility"))
    twice = SAMPLE + SAMPLE[SAMPLE.index("[[platform]]"):]
    expect("a platform declared twice is refused", any("declared twice" in p for p in validate_decl(read_decl_toml(twice))))
    expect("two platforms with one triple are refused",
           any("same triple" in p for p in validate_decl(read_decl_toml(
               SAMPLE + SAMPLE[SAMPLE.index("[[platform]]"):].replace('id = "linux-x"', 'id = "linux-y"')))))
    expect("a platform with no platform at all is refused",
           any("no `platform`" in p for p in validate_decl(read_decl_toml(SAMPLE[: SAMPLE.index("[[platform]]")]
                                                                           + SAMPLE[SAMPLE.index("[[limit]]"):]))))
    pdecl = decl_of(read_decl_toml(SAMPLE))
    asks = os_needs_of(pdecl, {"a"})
    expect("a build asks for the base and what its capabilities ask",
           asks == {"threads": ["base"], "sockets-tcp": ["base"], "entropy": ["base"], "sockets-udp": ["a"]})
    expect("a platform that provides what the build asks leaves no gap",
           platform_gaps(pdecl, "linux-x", {"a"}) == {})
    lacking = decl_of(read_decl_toml(SAMPLE.replace('"threads", "sockets-tcp", "sockets-udp", "entropy"]',
                                                    '"threads", "sockets-tcp", "entropy"]')))
    expect("a platform lacking a facility a capability asks for names the capability",
           platform_gaps(lacking, "linux-x", {"a"}) == {"sockets-udp": ["a"]})
    expect("the same platform has no gap for a build that does not turn that capability on",
           platform_gaps(lacking, "linux-x", set()) == {})
    unassessed = decl_of(read_decl_toml(SAMPLE.replace(
        'os_provides = ["threads", "sockets-tcp", "sockets-udp", "entropy"]\n', "")))
    expect("a platform with no os_provides is unassessed, not empty",
           platform_gaps(unassessed, "linux-x", {"a"}) is None)
    try:
        platform_gaps(pdecl, "nowhere", set())
    except KeyError:
        pass
    else:
        expect("a platform nobody declared raised nothing", False)
    expect("the toolchain variables follow the triple",
           toolchain_env({"triple": "aarch64-linux-android"})
           == ["CC_aarch64_linux_android", "AR_aarch64_linux_android",
               "CARGO_TARGET_AARCH64_LINUX_ANDROID_LINKER"])
    expect("a platform's own SDK variables come after them",
           toolchain_env({"triple": "aarch64-unknown-nto-qnx710_iosock",
                          "toolchain_env_extra": ["QNX_HOST", "QNX_TARGET"]})[3:] == ["QNX_HOST", "QNX_TARGET"]
           and toolchain_env({"triple": "aarch64-unknown-nto-qnx710_iosock"})[0]
           == "CC_aarch64_unknown_nto_qnx710_iosock")
    expect("the compiler's (os, env) pairs give the libc kinds",
           [libc_of("android", ""), libc_of("linux", "gnu"), libc_of("nto", "nto71"), libc_of("linux", "musl")]
           == ["bionic", "glibc", "nto", None])
    row = {"id": "p", "triple": "t-1", "os": "linux", "libc": "glibc"}
    fake = {"t-1": {"target_os": "linux", "target_env": "gnu"}}
    expect("a row the compiler agrees with has no finding",
           platform_rustc_findings([row], {"t-1"}, lambda t: fake[t]) == [])
    expect("a triple the compiler does not know is a finding",
           any("has no target" in f for f in platform_rustc_findings([row], set(), lambda t: fake[t])))
    expect("an os the compiler disagrees with is a finding",
           any("target_os" in f for f in platform_rustc_findings(
               [{**row, "os": "android"}], {"t-1"}, lambda t: fake[t])))
    expect("a libc the compiler disagrees with is a finding",
           any("libc is `bionic`" in f for f in platform_rustc_findings(
               [{**row, "libc": "bionic"}], {"t-1"}, lambda t: fake[t])))
    expect("a pair nobody classified is a finding, not a pass",
           any("does not classify" in f for f in platform_rustc_findings(
               [row], {"t-1"}, lambda t: {"target_os": "linux", "target_env": "musl"})))
    # The assessed runtime features (docs/target-build-contract.md T9).
    expect("a runtime feature of a package nobody assesses is refused",
           caps_refused('package = "wz-runtime-tokio"', 'package = "tokio"', "not one that is assessed"))
    expect("a runtime feature naming a facility outside the vocabulary is refused",
           caps_refused('feature = "f1"\nos_needs = ["sockets-udp"]', 'feature = "f1"\nos_needs = ["gpu"]',
                        "not a facility"))
    expect("a runtime feature with no os_needs is refused",
           caps_refused('os_needs = ["sockets-udp"]\nhelp = "A sample feature."', 'help = "A sample feature."',
                        "has no `os_needs`"))
    expect("a runtime feature declared twice is refused",
           any("declared twice" in p for p in validate_decl(read_decl_toml(
               SAMPLE + SAMPLE[SAMPLE.index("[[runtime_feature]]"):SAMPLE.index("[[artifact]]")]))))
    expect("a declaration with no runtime feature is refused",
           any("no `runtime_feature`" in p for p in validate_decl(read_decl_toml(
               SAMPLE[: SAMPLE.index("[[runtime_feature]]")] + SAMPLE[SAMPLE.index("[[artifact]]"):]))))
    # A consumer's placing path held to what wz declares.
    expect("a need naming a capability wz does not declare is refused",
           caps_refused('capabilities = ["a"]\nruntime_features = ["f1"]', 'capabilities = ["zz"]\nruntime_features = ["f1"]',
                        "which is not declared"))
    expect("a need naming a runtime feature nobody assessed is refused",
           caps_refused('capabilities = ["a"]\nruntime_features = ["f1"]', 'capabilities = ["a"]\nruntime_features = ["f9"]',
                        "has no [[runtime_feature]] row"))
    expect("a need that names nothing holds nothing and is refused",
           caps_refused('capabilities = ["a"]\nruntime_features = ["f1"]', "capabilities = []\nruntime_features = []",
                        "holds nothing"))
    expect("a need with an unknown key is refused",
           caps_refused('need = "sample-need"', 'need = "sample-need"\nwho = "x"', "unknown key `who`"))
    expect("a need declared twice is refused",
           any("declared twice" in p for p in validate_decl(read_decl_toml(
               SAMPLE + SAMPLE[SAMPLE.index("[[parity]]"):SAMPLE.index("[[artifact]]")]))))
    expect("a declaration with no parity row is refused",
           any("no `parity`" in p for p in validate_decl(read_decl_toml(
               SAMPLE[: SAMPLE.index("[[parity]]")] + SAMPLE[SAMPLE.index("[[artifact]]"):]))))
    rdecl = decl_of(read_decl_toml(SAMPLE))
    expect("an assessed feature adds its facilities to the base",
           resolve_runtime_needs(rdecl, {"wz-runtime-tokio": ["f1"]})
           == (["entropy", "sockets-tcp", "sockets-udp", "threads"], []))
    expect("an enabled feature nobody assessed makes the answer unknown and is named",
           resolve_runtime_needs(rdecl, {"wz-runtime-tokio": ["f1", "f2"]}) == (None, ["wz-runtime-tokio/f2"]))
    expect("the default feature is not a facility and is skipped",
           resolve_runtime_needs(rdecl, {"wz-runtime-tokio": ["default", "f1"]})[0] is not None)
    expect("a package that is not assessed does not make the answer unknown",
           resolve_runtime_needs(rdecl, {"tokio": ["rt"], "wz-runtime-tokio": ["f1"]})[1] == [])
    expect("a row for a feature the package lost is a finding",
           any("not a feature of" in f for f in runtime_feature_findings(rdecl, lambda p: {"other"})))
    expect("a row for a feature the package has is clean",
           runtime_feature_findings(rdecl, lambda p: {"f1"}) == [])
    # The artifacts and their roles (docs/target-build-contract.md T8).
    expect("a role naming an artifact nobody declared is refused",
           caps_refused('artifact = "lib-a"', 'artifact = "nope"', "the artifact is not declared"))
    expect("an artifact that provides no role is refused",
           caps_refused('artifact = "lib-a"', 'artifact = "nope"', "provides no role"))
    expect("an artifact kind outside the list is refused",
           caps_refused('kind = "shared-library"', 'kind = "static-library"', "not one of shared-library"))
    expect("a library that names no ABI is refused",
           caps_refused('abi = "pico"\n', "", "names the ABI"))
    expect("an artifact with an unknown key is refused",
           caps_refused('family = "fam-a"', 'family = "fam-a"\nextra = "x"', "unknown key `extra`"))
    expect("a role id outside the vocabulary is refused",
           caps_refused('id = "pico-library"', 'id = "daemon"', "is not one of pico-library"))
    expect("a pico role on a library of another ABI is refused",
           caps_refused('abi = "pico"', 'abi = "c"', "is a library of the pico ABI"))
    expect("a session role on a library is refused",
           caps_refused('id = "pico-library"', 'id = "session-node"', "is an executable"))
    expect("a role declared twice is refused",
           any("declared twice" in p for p in validate_decl(read_decl_toml(
               SAMPLE + SAMPLE[SAMPLE.index("[[role]]"):]))))
    exe = SAMPLE.replace('kind = "shared-library"', 'kind = "executable"').replace(
        'abi = "pico"\n', "").replace('id = "pico-library"', 'id = "session-node"')
    expect("an executable with a session role validates", validate_decl(read_decl_toml(exe)) == [])
    expect("an executable that names an ABI is refused",
           any("only a library has an ABI" in p for p in validate_decl(read_decl_toml(
               exe.replace('family = "fam-a"', 'family = "fam-a"\nabi = "pico"')))))
    expect("a library carrying a facts list is refused",
           caps_refused('artifact = "lib-a"\nid = "pico-library"',
                        'artifact = "lib-a"\nid = "pico-library"\nfacts_list = "x"',
                        "only an executable carries a facts note"))
    expect("a declaration with no artifact is refused",
           any("no `artifact`" in p for p in validate_decl(read_decl_toml(
               SAMPLE[: SAMPLE.index("[[artifact]]")] + SAMPLE[SAMPLE.index("[[limit]]"):]))))
    expect("an original in both upstream_on and upstream_off is refused",
           caps_refused('upstream_on = ["zenoh-pico"]',
                        'upstream_on = ["zenoh-pico"]\nupstream_off = ["zenoh-pico"]', "in both"))
    expect("an unknown original is refused",
           caps_refused('upstream_on = ["zenoh-pico"]', 'upstream_on = ["pico"]', "none of"))
    row = ('\n[[upstream_switch]]\noriginal = "zenoh-pico"\nswitch = "Z_FEATURE_A"\nclass = "maps"\n'
           'anchor = "wz-capi-pico/a"\nnote = "a"\n')
    with_row = SAMPLE + row

    def row_refused(text: str, words: str) -> bool:
        return any(words in p for p in validate_decl(read_decl_toml(text)))

    expect("a sample with a switch row validates", validate_decl(read_decl_toml(with_row)) == [])
    expect("a capability naming a pico_flag is refused",
           row_refused(SAMPLE.replace('abis = ["core", "pico"]', 'abis = ["core", "pico"]\npico_flag = "Z_FEATURE_A"'),
                       "names a pico_flag"))
    expect("a pico_flags_all on a capability a row reaches is refused",
           row_refused(with_row.replace('abis = ["core", "pico"]',
                                        'abis = ["core", "pico"]\npico_flags_all = ["Z_FEATURE_B"]'),
                       "names no pico_flags_all"))
    expect("pico_combine on a capability one row reaches is refused",
           row_refused(with_row.replace('abis = ["core", "pico"]', 'abis = ["core", "pico"]\npico_combine = "all"'),
                       "pico_combine"))
    expect("a switch row of an unknown class, or a maps row with no anchor, is refused",
           row_refused(with_row.replace('class = "maps"', 'class = "maybe"'), "class")
           and row_refused(with_row.replace('anchor = "wz-capi-pico/a"\n', ""), "anchor"))
    expect("two rows for one switch are refused", row_refused(with_row + row, "two rows"))
    expect("a macro on a zenoh-pico row, or a sense with no macro, is refused",
           row_refused(with_row.replace('note = "a"', 'note = "a"\nmacro = "Z_FEATURE_A"'), "names a macro")
           and row_refused(with_row.replace('note = "a"', 'note = "a"\nsense = "inverse"'), "sense"))
    expect("a pico row to a capability the pico ABI does not export is refused",
           row_refused(with_row.replace('abis = ["core", "pico"]', 'abis = ["core"]')
                       .replace('upstream_on = ["zenoh-pico"]\n', ""), "pico ABI does not export"))
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
    named = with_global.replace('prompt = "Client"', 'prompt = "Client"\nupstream_on = ["zenoh-pico"]') \
        .replace('prompt = "Peer"', 'prompt = "Peer"\nupstream_on = ["zenoh", "zenoh-c"]')
    expect("a global axis naming each original once validates", validate_decl(read_decl_toml(named)) == [])
    expect("a global axis naming an original twice, or leaving one out, is refused",
           any("exactly one" in p for p in validate_decl(read_decl_toml(
               named.replace('upstream_on = ["zenoh-pico"]', 'upstream_on = ["zenoh-pico", "zenoh"]'))))
           and any("exactly one" in p for p in validate_decl(read_decl_toml(
               named.replace('upstream_on = ["zenoh", "zenoh-c"]', 'upstream_on = ["zenoh"]')))))
    expect("an image axis's option naming an original is refused",
           global_refused('prompt = "Left"', 'prompt = "Left"\nupstream_on = ["zenoh"]', "only a global axis"))
    ndecl = decl_of(read_decl_toml(named))
    expect("an original's defconfig states its choices and what differs from the defaults",
           "\nCONFIG_WZ_MODE_C=y\n" in emit_defconfig(ndecl, "zenoh-pico")
           and "\nCONFIG_WZ_MODE_P=y\n" in emit_defconfig(ndecl, "zenoh")
           and "WZ_CAP_A" not in emit_defconfig(ndecl, "zenoh-pico")
           and "# original: zenoh-pico\n" in emit_defconfig(ndecl, "zenoh-pico"))
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
            expect("a preset that changes nothing resolves to its original's own default build",
                   original_differences(decl, "zenoh-c", resolve([preset(d, "empty.conf", "")])) == []
                   and resolved_limit_env(decl, resolve([preset(d, "empty2.conf", "")])) == [])
            expect("a preset that turns on what its original leaves off differs from the original",
                   any("advanced" in x for x in original_differences(
                       decl, "zenoh-c", resolve([preset(d, "adv.conf", "CONFIG_WZ_CAP_ADVANCED=y\n")]))))
            expect("presets of two originals are refused",
                   refused([preset(d, "c.conf", ""),
                            preset(d, "p.conf", "", head.replace("base: zenoh-c", "base: zenoh-pico"))],
                           "one original"))
            expect("each original's defconfig resolves to that original",
                   all(original_differences(decl, o, resolve([], original=o)) == [] for o in BASE_ABI))
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
            # The same tree with the two sample policies: each resolves to upstream's behaviour
            # until a fragment says otherwise, and only a departure reaches the environment.
            wpdecl = decl_of(read_decl_toml(with_global + POLICY_SAMPLE))
            ptree = d / "ptree"
            ptree.mkdir()
            for name, emit in (("Kconfig", emit_kconfig_root), ("Kconfig.axes", emit_kconfig_axes),
                               ("Kconfig.capabilities", emit_kconfig_capabilities),
                               ("Kconfig.limits", emit_kconfig_limits),
                               ("Kconfig.policies", emit_kconfig_policies)):
                (ptree / name).write_text(emit(wpdecl), encoding="utf-8")

            def policy_tree(*assigned: str):
                frag = d / "policy.conf"
                frag.write_text("".join(f"{a}\n" for a in assigned), encoding="utf-8")
                tree_conf = kconfiglib_module().Kconfig(str(ptree / "Kconfig"), warn_to_stderr=False)
                tree_conf.load_config(str(frag), replace=False)
                return tree_conf

            expect("a policy no fragment names resolves to upstream's behaviour",
                   [resolved_policy(policy_tree(), p) for p in wpdecl["policies"]] == ["os-default", "off"]
                   and resolved_policy_env(wpdecl, policy_tree()) == [])
            departed = policy_tree("CONFIG_WZ_POLICY_WIRE_MODE_OFF=y", "CONFIG_WZ_POLICY_EAGER_FLUSH=y")
            expect("a policy set off upstream's behaviour reaches the environment",
                   resolved_policy_env(wpdecl, departed)
                   == ["WZ_POLICY_WIRE_MODE=off", "WZ_POLICY_EAGER_FLUSH=on"])
            expect("an original's build with a policy on is not that original's",
                   any("policy eager-flush" in x for x in original_differences(wpdecl, "zenoh-c", departed)))
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
        text = pathlib.Path(argv[3]).read_text(encoding="utf-8")
        conflicts = pico_header_conflicts(decl, argv[2], text)
        for conflict in conflicts:
            print(f"  wz-config FAIL: {argv[3]}: {conflict}", file=sys.stderr)
        if conflicts:
            return 1
        print(cargo_args(decl, argv[2], read_config(decl, text)))
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
    if len(argv) == 4 and argv[1] == "--drop-in-features" and argv[2] == "c":
        # The canonical rule a consumer that builds the zenoh-c drop-in for its installed
        # zenoh-c calls, rather than keeping a copy of it.
        decl = load_decl()
        print(drop_in_features(decl, pathlib.Path(argv[3]).read_text(encoding="utf-8")))
        return 0
    if len(argv) == 3 and argv[1] == "--original-features" and argv[2] in BASE_ABI:
        # An upstream original's own default build: its defconfig alone, resolved strictly, as the
        # cargo arguments of the ABI it is built through. A lane compares this with the build its
        # interop legs link. It never skips: the lane that asks provisions the interpreter.
        decl = load_decl()
        try:
            kconf = resolve([], original=argv[2])
        except PresetError as exc:
            print(f"  wz-config FAIL: {exc}", file=sys.stderr)
            return 1
        print(cargo_args(decl, BASE_ABI[argv[2]], resolved_caps(decl, kconf)))
        return 0
    if len(argv) >= 3 and argv[1] == "--resolve-env":
        decl = load_decl()
        try:
            kconf = resolve([pathlib.Path(p) for p in argv[2:]])
        except PresetError as exc:
            print(f"  wz-config FAIL: {exc}", file=sys.stderr)
            return 1
        for line in resolved_limit_env(decl, kconf) + resolved_policy_env(decl, kconf):
            print(line)
        return 0
    print(__doc__, file=sys.stderr)
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv))
