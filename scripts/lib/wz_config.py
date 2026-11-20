#!/usr/bin/env python3
# SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
# SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
"""R3398 (no register item) -- the build configuration of wz is declared once; this derives from it.

It carries the capability declaration of R3398 and the limit declaration of R3403 (no register
item), both now one file, the one declaration every derived file of the build configuration is
generated from.

## What this is

`deploy/wz-config.toml` declares every switch a build can turn, once, and everything else is
generated from it: the capabilities of the C ABI builds (their Kconfig symbol, the ABIs that export
them, what they imply, zenoh-pico's own switch for them) and the limits an image states for
itself (their Kconfig symbol, default and help). This tool is everything that derives from it:

    --emit kconfig-root           print deploy/Kconfig, the root of the host configuration
    --emit kconfig-axes           print deploy/Kconfig.axes, the axes no one image owns (written
                                  only while the declaration has one)
    --emit kconfig-capabilities   print deploy/Kconfig.capabilities
    --emit kconfig-limits         print deploy/Kconfig.limits
    --emit rust-limits            print crates/wz-session-core/src/caps_generated.rs
    --emit rust-limit-bindings    print crates/wz-session-core/src/caps_binding_generated.rs, where
                                  each limit is bound
    --emit kconfig-policies       print deploy/Kconfig.policies (written only while the declaration
                                  has a policy)
    --emit rust-policies          print crates/wz-session-core/src/policy_generated.rs
    --emit config-schema          print deploy/wz-config.schema.json, the JSON Schema of the
                                  run-time document: the policies and limits a stage after the
                                  build decides
    --emit rust-feature-bits      print crates/wz-session-core/src/feature_bits_generated.rs
    --emit rust-conformance-items print crates/wz-conformance-build/src/items_generated.rs, the
                                  questions a build script answers for its conformance digest
    --emit statement-vectors      print crates/wz-conformance-build/statement_vectors.json, builds
                                  and the statement digest of each, which the build script's test
                                  must reproduce
    --emit defconfig:ORIGINAL     print configs/<ORIGINAL>_defconfig, an upstream original's own
                                  default build in wz's switches (zenoh, zenoh-c, zenoh-pico)
    --emit image-kconfig:IMAGE    print the axes of a declared image as Kconfig choices
                                  (<dir>/Kconfig.axes)
    --emit image-cmake:IMAGE      print the CMake that maps those choices to the image crate's
                                  features (<dir>/wz_axes.cmake), and the policies the image reads
                                  to the cargo environment that states them
    --emit image-policies:IMAGE   print the policies an image reads as Kconfig (<dir>/Kconfig.policies,
                                  written only while the declaration names one for the image)
    --write                       write every one of them
    --features ABI CONFIG         turn a Kconfig result (or a pico config.h) into the cargo arguments
    --features pico --engine coop CONFIG
                                  the same list for the cooperative engine: the features that
                                  select the tokio engine (its drive threads, the groups, gossip)
                                  are left out and `engine-coop` is named, so the build is the
                                  header arm's drop-in with the engine under it changed
    --pico-config-h [--engine coop] FEATURES
                                  the reverse: print the zenoh-pico `config.h` of the wz-capi-pico
                                  build of FEATURES (a comma list, empty for none) on the default
                                  features, or with --engine coop on `engine-coop` alone, rendered
                                  from the pinned config.h.in: every Z_FEATURE_* switch as the
                                  build carries it, every value switch a limit maps to at the
                                  WZ_LIMIT_<ID> the environment states, pico's defaults for the
                                  rest. A C program compiled against it allocates the structs
                                  that build's library writes
    --resolve-features ABI PRESET...
                                  merge presets onto the defaults (kconfiglib) and print the cargo
                                  arguments of ABI
    --drop-in-features c HEADER   the cargo arguments of the wz-capi-c build a program compiled
                                  against an installed zenoh-c's zenoh_configure.h links
    --env pico CONFIG             the WZ_LIMIT_<NAME>=<n> environment of the wz-capi-pico build
                                  that states the numbers a pico config.h states for its value
                                  switches (batch sizes, lease, timeouts), each where it differs
                                  from the default; with the capabilities the --features mode
                                  prints for the same header, the whole drop-in build
    --original-features ORIGINAL  resolve configs/<ORIGINAL>_defconfig alone and print the cargo
                                  arguments of the ABI that original is built through
    --resolve-env PRESET...       the same merge; print WZ_LIMIT_<NAME>=<value> for each limit it
                                  sets off its default, WZ_POLICY_<NAME>=<value> for each policy
                                  it sets off upstream's, and WZ_POLICY_<NAME>_ALLOWS_<VALUE>=off
                                  for each value it leaves out of a policy's domain
    --conformance-statement pico [--engine coop] CONFIG
    --conformance-statement c HEADER
    --resolve-conformance-statement ABI PRESET...
    --original-conformance-statement ORIGINAL
                                  print, as JSON, the conformance statement of the build the
                                  matching cargo-argument modes describe: every capability the ABI
                                  exports with whether the build has it, every layout switch of the
                                  ABI that is not a capability (`arm`), every limit and policy
                                  with its value, and a digest of those values (decision C15). The
                                  `c` form reads an installed zenoh-c's zenoh_configure.h, as
                                  --drop-in-features c does
    --check-presets               every registered profile (configs/profiles) resolves strictly,
                                  and each upstream defconfig resolves to its original's values
    --check-equivalence           the pinned kconfiglib and the copy Zephyr runs give the same
                                  configuration from the defaults and every registered profile
    --check                       hold every derived file, caps.rs and the three manifests to it
    --selftest                    drive the reader, the derivations and the check on what can be wrong

## Presets (re-validated strictly; a registered profile is a versioned contract)

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
  9. The enums of crates/wz-session-core/src/policy_binding.rs that the generated policy and
     limit rows name (`Scope`, `Binding`, `Mutability`, `Wire`, `Storage`) have one variant per
     word of the declaration's vocabulary, in its order.

## Domains

A policy's domain is the set of its values a stage after the build may select. The build states
it as one `WZ_POLICY_<NAME>_ALLOWS_<VALUE>` per value (`off` leaves the value out, `on` allows
it), from Kconfig through one `default y` bool per value whose prompt hides while the value is the
chosen default, so the default is always allowed. A value the build does not state is allowed on
a target with an operating system and, on a target with none, only when it is the default;
`WZ_POLICY_DOMAINS` (`full` or `defaults`) forces either rule, and `--resolve-env` states `on`
for an allowance a fragment assigns so that a configuration means the same on both. The generated
module refuses, in a constant, a build whose domain leaves out its default, and so does
`--resolve-env`.

Usage:
    wz_config.py --check | --selftest | --write | --check-presets
    wz_config.py --emit kconfig-root | kconfig-capabilities | kconfig-limits | rust-limits
                         | rust-limit-bindings | kconfig-policies | rust-policies
                         | config-schema | rust-feature-bits
    wz_config.py --resolve-features pico|c|core PRESET...
    wz_config.py --resolve-env PRESET...
    wz_config.py --conformance-statement pico [--engine coop] CONFIG
    wz_config.py --conformance-statement c HEADER
    wz_config.py --resolve-conformance-statement pico|c|core PRESET...
    wz_config.py --original-conformance-statement zenoh-pico|zenoh-c|zenoh
    wz_config.py --pico-config-h [--engine coop] FEATURES
    wz_config.py --features pico|c|core CONFIG
        CONFIG is a Kconfig `.config` (CONFIG_WZ_CAP_X=y) or a pico header of
        `#define Z_FEATURE_X 0|1` lines; a capability the file does not mention is OFF.
"""

from __future__ import annotations

import functools
import hashlib
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

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
from artifact_root import artifact  # noqa: E402  (a sibling: where products are)

ROOT = pathlib.Path(__file__).resolve().parents[2]
DECL =ROOT / "deploy" / "wz-config.toml"
KCONFIG_ROOT = ROOT / "deploy" / "Kconfig"
KCONFIG_AXES = ROOT / "deploy" / "Kconfig.axes"
KCONFIG_CAPS = ROOT / "deploy" / "Kconfig.capabilities"
CONFIGS = ROOT / "configs"
PROFILES = CONFIGS / "profiles"
# A product of scripts/provision-kconfiglib.sh, so it is where the artifact root rule puts it.
KCONFIG_VENV = artifact("target/kconfig-venv")
# A job that provisions kconfiglib arms this; where it is set, an absent interpreter is a FAIL
# in every command that needs one, never a SKIP.
KCONFIG_REQUIRED = os.environ.get("WZ_KCONFIG_REQUIRE") == "1"
# The ABI a preset's `# base:` original is built through.
BASE_ABI = {"zenoh-pico": "pico", "zenoh-c": "c", "zenoh": "core"}
KCONFIG_LIMITS = ROOT / "deploy" / "Kconfig.limits"
RUST_LIMITS = ROOT / "crates" / "wz-session-core" / "src" / "caps_generated.rs"
KCONFIG_POLICIES = ROOT / "deploy" / "Kconfig.policies"
RUST_POLICIES = ROOT / "crates" / "wz-session-core" / "src" / "policy_generated.rs"
RUST_LIMIT_BINDINGS = ROOT / "crates" / "wz-session-core" / "src" / "caps_binding_generated.rs"
# The limits a stage after the build may decide, as types and snapshots (`crate::limits`).
RUST_LIMIT_SNAPSHOTS = ROOT / "crates" / "wz-session-core" / "src" / "limits_generated.rs"
# The hand-written types the generated policy and limit rows name (`Domain`, `Bound`, the words
# of where a value is bound); `--check` holds the variants of its enums to the declaration's words.
POLICY_BINDING_RS = ROOT / "crates" / "wz-session-core" / "src" / "policy_binding.rs"
# The JSON Schema of the run-time document: what a stage after the build may decide.
CONFIG_SCHEMA = ROOT / "deploy" / "wz-config.schema.json"
RUST_FEATURE_BITS = ROOT / "crates" / "wz-session-core" / "src" / "feature_bits_generated.rs"
# What a build script reads to state its build (decision C15): the questions of a conformance
# statement and where each answer is found, for `wz-conformance-build`.
RUST_CONFORMANCE_ITEMS = ROOT / "crates" / "wz-conformance-build" / "src" / "items_generated.rs"
# Builds and their statement digests, which the build script's test must reproduce: the two
# writers of the digest held to each other over the declaration's whole domain.
STATEMENT_VECTORS = ROOT / "crates" / "wz-conformance-build" / "statement_vectors.json"
CAPS_RS =ROOT / "crates" / "wz-session-core" / "src" / "caps.rs"
# The configuration-aware derivation's own spelling of the vocabulary and of `[os] always`
# (docs/target-build-contract.md T9), held to this declaration by `--check`.
OPEN_FACILITIES_RS = ROOT / "crates" / "wz-session-core" / "src" / "facilities.rs"
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
# rustfmt's default `array_width`: an array literal whose items are wider goes one item a line.
RUST_ARRAY_WIDTH = 60
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
    small shape and this reads exactly that: `[table]` and `[[array of tables]]` headers, and
    `[array.table]`, a table of the last element of an array of tables opened before it (a
    profile's `[profile.policies]`), or of a table; `key = value` on ONE line, the value a string,
    an integer, a boolean, an array of strings or a non-empty array of integers (a limit's
    `range`); a `'''`
    literal string whose lines run to the closing `'''` (the newline right after the opening
    delimiter is not part of it, as TOML says), or one closed on the line it opens (`'''text'''`,
    with no `'''` inside); `#` comments on lines of their own. Anything else is refused by line
    number rather than skipped, so the file cannot grow a shape this reader silently drops.
    `--selftest` holds it to `tomllib` wherever the interpreter has one.

    It is the repository's one reader of TOML for a script that runs on the floor interpreter:
    a ledger round's descriptor (`round_descriptor.py`) is read with it too.
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
        sub = re.fullmatch(r"\[([A-Za-z0-9_-]+)\.([A-Za-z0-9_-]+)\]", line)
        if sub:
            parent = root.get(sub.group(1))
            owner = parent[-1] if isinstance(parent, list) and parent else parent
            if not isinstance(owner, dict):
                raise ValueError(f"line {number}: `[{sub.group(1)}.{sub.group(2)}]` names no table "
                                 f"or array of tables opened before it")
            if sub.group(2) in owner:
                raise ValueError(f"line {number}: `{sub.group(2)}` of `{sub.group(1)}` is set twice")
            table = owner[sub.group(2)] = {}
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
        elif re.fullmatch(r"'''(?:(?!''').)*'''", rest):
            value = rest[3:-3]
        elif rest.startswith("'''"):
            raise ValueError(f"line {number}: a ''' string opens a line of its own")
        else:
            try:
                value = json.loads(rest)
            except ValueError:
                raise ValueError(
                    f"line {number}: value is not a one-line string, integer, boolean or string array"
                ) from None
            # `true` and `false` are spelled alike in TOML and JSON; a bool is an int to Python, so it
            # is named first and on purpose.
            if not (
                isinstance(value, (bool, str, int))
                or (isinstance(value, list) and all(isinstance(x, str) for x in value))
                or (isinstance(value, list) and value
                    and all(isinstance(x, int) and not isinstance(x, bool) for x in value))
            ):
                raise ValueError(f"line {number}: value is not a string, integer, boolean, string "
                                 "array or integer array")
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
        "profiles": list(data.get("profile", [])),
        "facts": list(data.get("protocol_fact", [])),
        "policy_images": list(data.get("policy_image", [])),
        "images": [i["id"] for i in data.get("image", [])],
        "image_dirs": {i["id"]: i["dir"] for i in data.get("image", [])},
        "axes": list(data.get("axis", [])),
        "options": list(data.get("axis_option", [])),
        "rules": list(data.get("cargo_rule", [])),
        "switches": list(data.get("upstream_switch", [])),
        "os_base": list(data["os"]["base"]),
        "os_always": list(data["os"]["always"]),
        "platforms": list(data["platform"]),
        "artifacts": list(data["artifact"]),
        "roles": list(data["role"]),
        "assessed_packages": list(data["assessed_package"]),
        "package_features": list(data["package_feature"]),
        "parity": list(data["parity"]),
    }


def validate_decl(data: dict) -> list[str]:
    out: list[str] = []
    if data.get("schema_version") != SCHEMA_VERSION:
        out.append(f"schema_version is {data.get('schema_version')!r}, this reader is {SCHEMA_VERSION}")
    if not isinstance(data.get("catalog_version"), int):
        out.append("catalog_version is not an integer")
    for kind in ("base", "capability", "limit", "os", "platform", "artifact", "role", "assessed_package",
                 "package_feature", "parity"):
        if kind not in data:
            out.append(f"the declaration has no `{kind}`")
    if out:
        return out
    out += validate_os(data)
    out += validate_assessed_packages(data)
    out += validate_package_features(data)
    out += validate_parity(data)
    out += validate_caps(data)
    out += validate_platforms(data)
    out += validate_artifacts(data)
    out += validate_limits(data["limit"])
    out += validate_policies(data.get("policy", []), data["catalog_version"])
    out += validate_profiles(data.get("profile", []), data.get("policy", []))
    out += validate_facts(data.get("protocol_fact", []))
    out += validate_images(data)
    out += validate_policy_images(data)
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


POLICY_IMAGE_KEYS = {"policy", "image", "requires"}
REQUIRES_RE = re.compile(r"(\s*(!|&&|\|\||\(|\)|[A-Z][A-Z0-9_]*))+\s*")
SYMBOL_RE = re.compile(r"[A-Z][A-Z0-9_]*")


def validate_policy_images(data: dict) -> list[str]:
    """Which policies an image reads (`[[policy_image]]`), and when.

    A policy is a field of the session policy of a build, and an image's build gives it a value
    only if the code that reads it is in the image and is run by it. That is a fact about the
    image, so the image names it: a policy no row names is not in the image's Kconfig tree, and a
    deployer who asks for it gets Zephyr's own refusal of an undefined symbol, where a symbol that
    changed nothing would be taken for a setting. `requires` is a Kconfig expression over the
    options of the image's axes and the global axes, as a cargo rule's `when` is, and holds the
    policy to the profiles that run its code.
    """
    out: list[str] = []
    rows = data.get("policy_image", [])
    for row in rows:
        unknown = set(row) - POLICY_IMAGE_KEYS
        if unknown:
            out.append(f"a policy_image has keys this reader does not know: {sorted(unknown)}")
    policies = {p.get("id") for p in data.get("policy", [])}
    images = {i.get("id") for i in data.get("image", [])}
    axes = {a.get("id"): a for a in data.get("axis", [])}
    seen: set[tuple] = set()
    for row in rows:
        policy, image = row.get("policy"), row.get("image")
        if policy not in policies:
            out.append(f"a policy_image names policy {policy!r}, which is not declared")
        if image not in images:
            out.append(f"a policy_image names image {image!r}, which is not declared")
            continue
        if (policy, image) in seen:
            out.append(f"policy {policy!r} is named twice for image {image!r}")
        seen.add((policy, image))
        requires = row.get("requires")
        if requires is None:
            continue
        if not isinstance(requires, str) or REQUIRES_RE.fullmatch(requires) is None:
            out.append(f"policy {policy!r} of {image!r}: `requires` is not a Kconfig expression "
                       f"over option symbols ({requires!r})")
            continue
        own = {o["kconfig"] for o in data.get("axis_option", [])
               if o.get("axis") in axes
               and ("image" not in axes[o["axis"]] or axes[o["axis"]].get("image") == image)}
        for symbol in SYMBOL_RE.findall(requires):
            if symbol not in own:
                out.append(f"policy {policy!r} of {image!r} requires {symbol}, which is no option "
                           f"of the image's axes or of a global axis")
    return out


def validate_caps(data: dict) -> list[str]:
    out: list[str] = []
    caps = {c["id"]: c for c in data["capability"]}
    ids = [c["id"] for c in data["capability"]]
    if len(ids) != len(set(ids)):
        out.append("a capability id is declared twice")
    bits = [c["observation_bit"] for c in data["capability"] if "observation_bit" in c]
    if len(bits) != len(set(bits)):
        out.append("two capabilities have the same observation_bit; a bit of the snapshot's features "
                   "word names one capability")
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
        for abi in c.get("default_off_abis", []):
            if abi == "core" or abi not in c["abis"]:
                out.append(f"{c['id']}: default_off_abis names `{abi}`, which is not an ABI the "
                           "capability is exported by")
        if c.get("default_off_abis") and c.get("default", "on") == "off":
            out.append(f"{c['id']}: default_off_abis is stated for a capability that is off by "
                       "default everywhere")
        if "observation_bit" in c:
            bit = c["observation_bit"]
            if isinstance(bit, bool) or not isinstance(bit, int) or not 0 <= bit <= 63:
                out.append(f"{c['id']}: observation_bit is `{bit}`, which is not a bit of a 64-bit word")
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
# build asks for whatever its capabilities, and `[os] always` the part of it that every run asks
# for and cannot go on without. A platform's `os_provides` is what its operating system gives; a
# platform that does not state it is UNASSESSED, never read as "provides all".
#
# Each facility with what it means: what the artifact's process asks the operating system to let
# it do. A device provides a facility when an unprivileged process of the artifact may do it there,
# so a facility that needs a privilege includes that privilege.
OS_FACILITIES = {
    "threads": "start more threads of execution in the process (POSIX threads)",
    "sockets-tcp": "open TCP sockets, to dial and to listen",
    "sockets-udp": "open UDP sockets, to send and receive datagrams",
    "multicast": "join an IP multicast group on a UDP socket and send to the group",
    "raw-ethernet": "open a raw link-layer socket on an interface (Linux AF_PACKET), with the "
                    "privilege it needs (CAP_NET_RAW)",
    "unix-sockets": "open Unix domain stream sockets by a file system path",
    "filesystem": "read files by path, and write them for a plane that stores data",
    "entropy": "draw cryptographic random bytes from the operating system (getrandom, /dev/urandom)",
    "wall-clock": "read the calendar time (CLOCK_REALTIME, SystemTime), and the local time zone "
                  "when a local time is asked for (localtime); it is never set, and a wrong reading "
                  "makes certificate validity and timestamps wrong",
    "interface-list": "list the network interfaces and their addresses, or look one up by name or "
                      "index (getifaddrs, if_nametoindex, GetAdaptersAddresses)",
    "name-resolution": "resolve a host name to addresses through the operating system's resolver "
                       "(getaddrinfo): its files (/etc/hosts, nsswitch) and its DNS servers",
}
# What a built file's imports prove (docs/target-build-contract.md T9). A C-library function whose
# every call is a request for one facility is a witness of it in the file's bytes: a file that binds
# it by a relocation (`elf_facts.imported_symbols`) may ask for that facility, whatever the
# declaration says, so the entry refuses a bound that lacks it. A function that serves several
# facilities by its arguments (`socket`, `open`, `clock_gettime`, `setsockopt`) proves none and is
# not listed: it cannot refute a bound, and listing it would refute every bound.
FACILITY_IMPORTS = {
    "pthread_create": "threads",
    "getifaddrs": "interface-list",
    "if_nametoindex": "interface-list",
    "if_indextoname": "interface-list",
    "if_nameindex": "interface-list",
    "getrandom": "entropy",
    "getentropy": "entropy",
    "gettimeofday": "wall-clock",
    "localtime": "wall-clock",
    "localtime_r": "wall-clock",
    "tzset": "wall-clock",
    "mktime": "wall-clock",
    "getaddrinfo": "name-resolution",
    "getnameinfo": "name-resolution",
    "gethostbyname": "name-resolution",
    "gethostbyname_r": "name-resolution",
}
# The functions whose call is a request no facility names: a file that binds one is refused until
# the vocabulary has a word for it, since a consumer could not be told the device needs it.
UNNAMED_IMPORTS = {
    "fork": "starting a process", "vfork": "starting a process", "posix_spawn": "starting a process",
    "posix_spawnp": "starting a process", "execv": "starting a process", "execve": "starting a process",
    "execvp": "starting a process", "system": "starting a process", "popen": "starting a process",
}


def import_findings(imports: list[str], bound: list[str] | None) -> list[str]:
    """What a file's imports refute of its bound: each facility a definite import proves and the
    bound lacks, and each import no facility names. An UNKNOWN bound (`None`) is refuted only by
    the second."""
    out = [f"it imports {name}, a request no facility of the vocabulary names ({what})"
           for name, what in sorted(UNNAMED_IMPORTS.items()) if name in imports]
    if bound is not None:
        out += [f"it imports {name}, so it may ask for {facility}, which its bound lacks"
                for name, facility in sorted(FACILITY_IMPORTS.items())
                if name in imports and facility not in bound]
    return out


# The packages assessed for the facilities their code asks of the operating system
# (`[[assessed_package]]`), declared rather than written here so the set is data the entry and the
# facility oracle read alike. A package's `os_needs` is what its own code may ask for: whatever its
# features when `by_feature` is true, and then each feature of it a build enables has a
# `[[package_feature]]` row for what that feature adds; under any of its features when it is false,
# for a package whose features only forward to others. The core and the codecs take no facility of
# their own (they are `no_std`-capable and are handed time, entropy and a link), and a third-party
# crate's needs are those of the assessed package that pulls it, whose row names the crate.
ASSESSED_PACKAGE_KEYS = {"package", "by_feature", "os_needs", "help"}
PACKAGE_FEATURE_KEYS = {"package", "feature", "os_needs", "help"}
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
    always = data["os"].get("always")
    if always is None:
        out.append("[os] has no `always` (the part of the base every run asks for; T9)")
    else:
        out += facility_findings("[os]", always, "`always`")
        if isinstance(always, list) and isinstance(base, list):
            out += [f"[os]: `always` names `{f}`, which is not in `base`" for f in always if f not in base]
    extra = set(data["os"]) - {"base", "always"}
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


def validate_assessed_packages(data: dict) -> list[str]:
    out: list[str] = []
    seen = set()
    for p in data["assessed_package"]:
        who = f"assessed_package {p.get('package')!r}"
        for key in sorted(set(p) - ASSESSED_PACKAGE_KEYS):
            out.append(f"{who} has the unknown key `{key}`")
        for key in sorted(ASSESSED_PACKAGE_KEYS - set(p)):
            out.append(f"{who} has no `{key}`")
        if p.get("package") in seen:
            out.append(f"{who} is declared twice")
        seen.add(p.get("package"))
        if "by_feature" in p and not isinstance(p["by_feature"], bool):
            out.append(f"{who}: `by_feature` is not true or false")
        if "os_needs" in p:
            out += facility_findings(who, p["os_needs"], "os_needs")
    return out


def by_feature_packages(decl_or_data: dict) -> set[str]:
    """The assessed packages each of whose features is assessed on its own."""
    rows = decl_or_data.get("assessed_packages", decl_or_data.get("assessed_package", []))
    return {p["package"] for p in rows if p.get("by_feature") is True}


def validate_package_features(data: dict) -> list[str]:
    out: list[str] = []
    seen = set()
    split = by_feature_packages(data)
    for r in data["package_feature"]:
        who = f"package_feature {r.get('package')!r}/{r.get('feature')!r}"
        for key in sorted(set(r) - PACKAGE_FEATURE_KEYS):
            out.append(f"{who} has the unknown key `{key}`")
        for key in sorted(PACKAGE_FEATURE_KEYS - set(r)):
            out.append(f"{who} has no `{key}`")
        if r.get("package") not in split:
            out.append(f"{who}: the package is not one assessed by feature ({', '.join(sorted(split))})")
        if (r.get("package"), r.get("feature")) in seen:
            out.append(f"{who} is declared twice")
        seen.add((r.get("package"), r.get("feature")))
        if "os_needs" in r:
            out += facility_findings(who, r["os_needs"], "os_needs")
    return out


def validate_parity(data: dict) -> list[str]:
    out: list[str] = []
    caps = {c["id"] for c in data["capability"]}
    rows = {(r["package"], r["feature"]) for r in data["package_feature"] if "package" in r and "feature" in r}
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
                    out.append(f"{who} names the runtime feature `{feature}`, which has no [[package_feature]] row")
    return out


def package_feature_findings(decl: dict, features_of) -> list[str]:
    """Each assessed feature against the package's real `[features]`: a row for a feature that
    no longer exists is a finding, so an assessment cannot outlive what it assessed.

    `features_of(package)` returns the package's feature names, passed in so a test can drive it.
    """
    out = []
    for r in decl["package_features"]:
        if r["feature"] not in features_of(r["package"]):
            out.append(f"package_feature {r['package']}/{r['feature']} is not a feature of {r['package']}")
    return out


def resolve_package_needs(decl: dict, resolved: dict[str, list[str]],
                          own_package: str) -> tuple[list[str] | None, list[str]]:
    """The facilities an executable's assessed packages may ask for, and the enabled features nobody
    assessed.

    `resolved` maps a package to the features cargo enabled in it, and `own_package` is the
    executable's own package, which is in the build whatever cargo reported. Each assessed package in
    the build adds its `os_needs`; one assessed by feature adds each enabled feature's row too. The
    answer is `None` (UNKNOWN, never a pass) when an enabled feature of such a package has no row;
    otherwise the sorted union with the base. The second value lists the unassessed features as
    `package/feature`, so a reader sees which part of the answer is missing.
    """
    rows = {(r["package"], r["feature"]): r["os_needs"] for r in decl["package_features"]}
    unassessed: list[str] = []
    needs = set(decl["os_base"])
    for assessed in decl["assessed_packages"]:
        package = assessed["package"]
        if package not in resolved and package != own_package:
            continue
        needs |= set(assessed["os_needs"])
        if not assessed["by_feature"]:
            continue
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
# A zenoh-pico switch that carries a VALUE (a batch size, a lease) is not a capability: its `maps`
# row anchors to the limit that states the same number for the pico ABI, as `limit:<ID>`.
LIMIT_ANCHOR = "limit:"
# The pinned zenoh-pico's config template: the value switches are the CMake variables it
# substitutes as `@NAME@`, each into the macro its line defines.
PICO_CONFIG_IN = ROOT / "vendor" / "zenoh-pico" / "include" / "zenoh-pico" / "config.h.in"
PICO_VALUE_RE = re.compile(
    r'^\s*#\s*(?:define|cmakedefine)\s+([A-Z][A-Z0-9_]*)\s+"?@([A-Z][A-Z0-9_]*)@"?\s*$', re.MULTILINE)
# A number a pico `config.h` defines a value macro to: decimal, or hexadecimal as pico writes its
# resolutions.
VALUE_DEFINE_RE = re.compile(r"^\s*#\s*define\s+([A-Z][A-Z0-9_]*)\s+(0[xX][0-9a-fA-F]+|[0-9]+)\s*$")


def pico_value_macros(text: str) -> dict[str, str]:
    """Each value switch of a zenoh-pico `config.h.in` (a CMake variable it substitutes as
    `@NAME@`, other than the `Z_FEATURE_*` switches) to the macro its `config.h` defines with it."""
    return {m.group(2): m.group(1) for m in PICO_VALUE_RE.finditer(text)
            if not m.group(2).startswith("Z_FEATURE_")}


def limit_rows(decl: dict) -> list[tuple[str, str]]:
    """(switch, limit id) of every zenoh-pico `maps` row that anchors to a limit, in row order."""
    return [(s["switch"], s["anchor"][len(LIMIT_ANCHOR):]) for s in decl["switches"]
            if s.get("original") == "zenoh-pico" and s.get("class") == "maps"
            and str(s.get("anchor", "")).startswith(LIMIT_ANCHOR)]


def pico_limit_values(decl: dict, text: str,
                      macros: dict[str, str]) -> tuple[dict[str, int], list[str]]:
    """The value of every declared limit in the build a zenoh-pico `config.h` states, and the
    problems. A limit one of the header's value switches maps to takes the header's number; every
    other limit, and one whose macro the header does not define, keeps its default, which is
    pico's own. A macro defined to something that is not a number is a problem, never a default."""
    values = {lim["id"]: lim["default"] for lim in decl["limits"]}
    stated: dict[str, str] = {}
    for line in text.splitlines():
        if m := VALUE_DEFINE_RE.match(line):
            stated[m.group(1)] = m.group(2)
    problems: list[str] = []
    defined = {d.group(1) for line in text.splitlines()
               if (d := re.match(r"^\s*#\s*define\s+([A-Z][A-Z0-9_]*)\b", line))}
    for switch, lid in limit_rows(decl):
        macro = macros.get(switch)
        if macro is None:
            problems.append(f"`{switch}` maps to limit {lid}, and the pinned config.h.in has no "
                            f"value line for it")
            continue
        if macro not in stated:
            if macro in defined:
                problems.append(f"{macro} is defined to something that is not a number")
            continue
        values[lid] = int(stated[macro], 0)
    return values, problems


def pico_value_env(decl: dict, text: str, macros: dict[str, str]) -> tuple[list[str], list[str]]:
    """The `WZ_LIMIT_<ID>=<n>` lines a zenoh-pico `config.h` states for the limits its value
    switches map to, each where the header's number differs from the limit's default, and the
    problems (`pico_limit_values`)."""
    defaults = {lim["id"]: lim["default"] for lim in decl["limits"]}
    values, problems = pico_limit_values(decl, text, macros)
    lines = [f"WZ_LIMIT_{lid}={values[lid]}" for _, lid in limit_rows(decl)
             if values[lid] != defaults[lid]]
    return lines, problems


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
        anchor = str(row.get("anchor", ""))
        if anchor.startswith(LIMIT_ANCHOR):
            if row.get("original") != "zenoh-pico" or row.get("class") != "maps":
                out.append(f"{where}: only a zenoh-pico `maps` row anchors to a limit")
            elif anchor[len(LIMIT_ANCHOR):] not in {lim.get("id") for lim in data.get("limit", [])}:
                out.append(f"{where}: anchors to `{anchor}`, which no [[limit]] declares")
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


# Where a policy or a limit is bound (deploy/wz-config.toml, "Where a value is bound"). The scopes
# are listed widest first, and a limit held at several scopes lists them in this order.
SCOPES = ("runtime", "session", "link", "entity", "message")
BINDINGS = ("build", "open", "live")
MUTABILITIES = ("fixed", "quiescent", "hot")
WIRES = ("none", "timing", "visible", "negotiated")
LIMIT_STORAGES = ("capacity", "quota", "both")
# A storage profile that does not read the limit binds it at no stage.
LIMIT_BINDINGS = BINDINGS + ("none",)
# What a limit's value is to the code (deploy/wz-config.toml, "Limits"): a bound, which a build
# with no capacity of it may leave unbounded, or a parameter, inside its declared range.
LIMIT_KINDS = ("bound", "parameter")
# Who makes the table a bound limits grow: the program's own calls, or a peer's messages.
DRIVERS = ("local", "remote")
# What the heap storage profile does with a limit that is `both`: nothing (its growable table
# refuses nothing), size storage by it as the fixed profile does, or refuse past it without
# sizing anything.
LIMIT_ON_HEAP = ("advisory", "capacity", "quota")
# The most a parameter's range may reach: a limit is a `usize`, which is 32 bits on the targets
# with the narrowest word wz builds for.
LIMIT_RANGE_MOST = 4294967295
LIMIT_KEYS = {"id", "kconfig", "default", "help",
              "storage", "scope", "binding_heap", "binding_fixed", "wire",
              "kind", "driven", "range", "most", "on_heap", "zero_unbounded"}


def stated_one_of(out: list[str], where: str, row: dict, key: str,
                  values: tuple[str, ...]) -> str | None:
    """The row's `key` when it is one of `values`; otherwise None, with the problem in `out`."""
    if key not in row:
        out.append(f"{where}: it states no `{key}`, one of {', '.join(values)}")
        return None
    value = row[key]
    if not isinstance(value, str) or value not in values:
        out.append(f"{where}: `{key}` is {value!r}, one of {', '.join(values)}")
        return None
    return value


def limit_scope_problems(where: str, lim: dict) -> list[str]:
    """A limit's `scope` is one scope, or an array of the scopes it is held at when there are
    several: each once, in the order of SCOPES, so one set has one spelling."""
    if not isinstance(lim.get("scope"), list):
        out: list[str] = []
        stated_one_of(out, where, lim, "scope", SCOPES)
        return out
    scope = lim["scope"]
    canonical = [s for s in SCOPES if s in scope]
    if len(scope) < 2 or any(s not in SCOPES for s in scope) or scope != canonical:
        return [f"{where}: `scope` is {scope!r}; a limit held at more than one scope lists two or "
                f"more of {', '.join(SCOPES)}, each once, in that order"]
    return []


def limit_binding_problems(lid: str, lim: dict) -> list[str]:
    """What a limit sizes or bounds, and the latest stage each storage profile may decide it at.

    A capacity sizes storage, so no profile decides it while running; a quota bounds storage that
    is already there, so no profile fixes it at the build; a limit that is both is the capacity of
    the fixed profile and a quota of the heap profile. A limit neither profile reads is no limit.
    """
    where = f"limit `{lid}`"
    out = limit_scope_problems(where, lim)
    storage = stated_one_of(out, where, lim, "storage", LIMIT_STORAGES)
    heap = stated_one_of(out, where, lim, "binding_heap", LIMIT_BINDINGS)
    fixed = stated_one_of(out, where, lim, "binding_fixed", LIMIT_BINDINGS)
    stated_one_of(out, where, lim, "wire", WIRES)
    if heap is None or fixed is None:
        return out
    bindings = (("binding_heap", heap), ("binding_fixed", fixed))
    if heap == fixed == "none":
        out.append(f"{where}: neither storage profile reads it (`binding_heap` and `binding_fixed` "
                   "are both 'none')")
    if storage == "capacity":
        for key, stage in bindings:
            if stage == "live":
                out.append(f"{where}: a `capacity` sizes storage, so it is decided by the open at "
                           f"the latest; its `{key}` is 'live'")
    elif storage == "quota":
        for key, stage in bindings:
            if stage == "build":
                out.append(f"{where}: a `quota` bounds storage that is already there, so it is "
                           f"decided at the open or later; its `{key}` is 'build'")
    elif storage == "both" and (fixed != "build" or heap not in ("open", "live")):
        out.append(f"{where}: a limit that is `both` is the capacity of the fixed profile, decided at "
                   f"'build', and a quota of the heap profile, decided at 'open' or 'live'; it says "
                   f"`binding_heap` {heap!r} and `binding_fixed` {fixed!r}")
    return out


def limit_kind_problems(lid: str, lim: dict) -> list[str]:
    """What a limit's value is to the code. A bound names who makes its table grow (`driven`); a
    parameter names the range its code runs with (`range`, holding the default). A limit that is
    `both` names what the heap profile does with it (`on_heap`); a parameter is never advisory,
    since a number the code runs with is always read. Only a bound that sizes nothing may read a
    build value of `0` as no bound (`zero_unbounded`)."""
    where = f"limit `{lid}`"
    out: list[str] = []
    kind = stated_one_of(out, where, lim, "kind", LIMIT_KINDS)
    if kind == "bound":
        stated_one_of(out, where, lim, "driven", DRIVERS)
        if "range" in lim:
            out.append(f"{where}: a bound has no `range`; its domain is its capacity")
        most = lim.get("most")
        if most is not None:
            # The largest count the code holds, where it holds the count in a narrower type.
            if not isinstance(most, int) or isinstance(most, bool) \
                    or not 1 <= most <= LIMIT_RANGE_MOST:
                out.append(f"{where}: `most` is the largest count the code holds, an integer in "
                           f"1..={LIMIT_RANGE_MOST}")
            elif isinstance(lim.get("default"), int) and lim["default"] > most:
                out.append(f"{where}: its default {lim['default']} is above its `most` {most}")
    elif "most" in lim:
        out.append(f"{where}: only a bound states `most`; a parameter states its `range`")
    elif kind == "parameter":
        if "driven" in lim:
            out.append(f"{where}: a parameter states no `driven`; it limits no table")
        rng = lim.get("range")
        if (not isinstance(rng, list) or len(rng) != 2
                or not all(isinstance(v, int) and not isinstance(v, bool) for v in rng)):
            out.append(f"{where}: a parameter states its `range` as [least, most]")
        else:
            least, most = rng
            if not 0 <= least <= most <= LIMIT_RANGE_MOST:
                out.append(f"{where}: `range` {rng} is not 0 <= least <= most <= "
                           f"{LIMIT_RANGE_MOST}")
            elif isinstance(lim.get("default"), int) and not least <= lim["default"] <= most:
                out.append(f"{where}: its default {lim['default']} is outside its `range` {rng}")
    storage = lim.get("storage")
    if storage == "both":
        on_heap = stated_one_of(out, where, lim, "on_heap", LIMIT_ON_HEAP)
        if on_heap == "advisory" and kind == "parameter":
            out.append(f"{where}: a parameter is read by every profile that holds it, so its "
                       "`on_heap` is not 'advisory'")
    elif "on_heap" in lim:
        out.append(f"{where}: only a limit that is `both` states `on_heap`")
    if "zero_unbounded" in lim:
        if lim["zero_unbounded"] is not True:
            out.append(f"{where}: `zero_unbounded` is stated as true or not at all")
        elif kind != "bound" or storage != "quota":
            out.append(f"{where}: only a bound that sizes no storage (`quota`) reads `0` as no "
                       "bound")
    return out


def validate_limits(limits: list[dict]) -> list[str]:
    out: list[str] = []
    ids = [l.get("id") for l in limits]
    if len(ids) != len(set(ids)):
        out.append("a limit id is declared twice")
    for lim in limits:
        lid = lim.get("id", "?")
        for key in sorted(set(lim) - LIMIT_KEYS):
            out.append(f"limit `{lid}`: `{key}` is not a key a limit has")
        out += limit_binding_problems(lid, lim)
        out += limit_kind_problems(lid, lim)
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
POLICY_KEYS = {"id", "kind", "kconfig", "choices", "default", "upstream", "since", "help",
               "scope", "binding", "mutability", "boundary", "wire"}


def policy_binding_problems(pid: str, pol: dict) -> list[str]:
    """Where a policy is bound. Only a value decided while running can change, so `mutability`
    is `fixed` exactly when `binding` is not `live`; a `quiescent` change waits for a moment the
    policy names in `boundary`, which no other policy states."""
    out: list[str] = []
    where = f"policy `{pid}`"
    stated_one_of(out, where, pol, "scope", SCOPES)
    binding = stated_one_of(out, where, pol, "binding", BINDINGS)
    mutability = stated_one_of(out, where, pol, "mutability", MUTABILITIES)
    stated_one_of(out, where, pol, "wire", WIRES)
    if binding is not None and mutability is not None:
        if binding == "live" and mutability == "fixed":
            out.append(f"{where}: its `binding` is 'live', so its `mutability` is 'quiescent' or "
                       "'hot', not 'fixed'")
        elif binding != "live" and mutability != "fixed":
            out.append(f"{where}: its `binding` is {binding!r}, decided before it runs, so its "
                       f"`mutability` is 'fixed', not {mutability!r}")
    if mutability == "quiescent":
        boundary = pol.get("boundary")
        if not isinstance(boundary, str) or not boundary.strip():
            out.append(f"{where}: a 'quiescent' policy states its `boundary`, the moment a change "
                       "takes effect")
        elif not all(" " <= c <= "~" for c in boundary):
            # The generated module carries it as a Rust string literal.
            out.append(f"{where}: its `boundary` is one line of printable ASCII")
    elif mutability is not None and "boundary" in pol:
        out.append(f"{where}: `boundary` is stated only by a 'quiescent' policy; its `mutability` "
                   f"is {mutability!r}")
    return out


def snake(name: str) -> str:
    return name.replace("-", "_")


def camel(name: str) -> str:
    return "".join(part.capitalize() for part in name.split("-"))


def policy_symbols(pol: dict) -> list[str]:
    """The Kconfig symbols a policy declares: its own for a bool, and for a choice the choice and
    one option per value; and for either, one allowance per value (`policy_allows_symbol`)."""
    kconfig = pol.get("kconfig")
    if pol.get("kind") == "choice":
        choices = pol.get("choices", [])
        own = [kconfig] + [f"{kconfig}_{snake(c).upper()}" for c in choices]
    else:
        choices = ["off", "on"]
        own = [kconfig]
    return own + [f"{kconfig}_ALLOWS_{snake(str(c)).upper()}" for c in choices]


def policy_allows_symbol(pol: dict, value: str) -> str:
    """The name that says whether a build allows `value` of `pol`, the same in the Kconfig and in
    the environment of the cargo build: `WZ_POLICY_<NAME>_ALLOWS_<VALUE>`."""
    return f"{pol['kconfig']}_ALLOWS_{snake(value).upper()}"


# The variable that forces the rule an unstated allowance follows, whatever the target: `full`
# allows its value, `defaults` keeps the policy's default alone.
POLICY_DOMAINS_ENV = "WZ_POLICY_DOMAINS"


def policy_defaults_only(env: dict[str, str], no_os: bool) -> bool:
    """Whether an allowance `env` does not state keeps only the policy's default: what
    `WZ_POLICY_DOMAINS` states, else whether the build's target has no operating system (`no_os`),
    as `policy_defaults_only` of the generated module decides it in the build."""
    text = env.get(POLICY_DOMAINS_ENV)
    if text is None:
        return no_os
    if text not in ("full", "defaults"):
        raise ValueError(f"{POLICY_DOMAINS_ENV} is neither `full` nor `defaults` ({text})")
    return text == "defaults"


def policy_domain(pol: dict, env: dict[str, str], no_os: bool = False) -> list[str]:
    """The values of `pol` a build whose environment states `env` allows, in the declaration's
    order: one whose `WZ_POLICY_<NAME>_ALLOWS_<VALUE>` is `on` is allowed and `off` leaves it out.
    One it does not state is allowed, except where `policy_defaults_only` holds (a target with no
    operating system, `no_os`, or `WZ_POLICY_DOMAINS=defaults`): then only the default is. The
    build's default (its `WZ_POLICY_<NAME>`, else upstream's) must be one of them; a domain
    without it is refused here, as the generated module's constant refuses it in the build."""
    default = env.get(pol["kconfig"], pol["default"])
    defaults_only = policy_defaults_only(env, no_os)
    allowed: list[str] = []
    for value in policy_values(pol):
        name = policy_allows_symbol(pol, value)
        unstated = "off" if defaults_only and value != default else "on"
        text = env.get(name, unstated)
        if text not in ("on", "off"):
            raise ValueError(f"a WZ_POLICY_*_ALLOWS_* value is neither `on` nor `off` "
                             f"({name}={text})")
        if text == "on":
            allowed.append(value)
    if default not in allowed:
        raise ValueError(f"policy {pol['id']}: its default {default!r} is outside the domain the "
                         f"build allows ({', '.join(allowed) or 'no value'})")
    return allowed


FACT_KEYS = {"id", "pico", "c", "holds", "lacks", "help"}
FACT_ABIS = ("pico", "c")


def fact_entry_ok(entry: object) -> bool:
    """A `holds` or `lacks` entry: `<file of this tree> @ <text>`, both halves non-empty."""
    if not isinstance(entry, str) or " @ " not in entry:
        return False
    path, text = entry.split(" @ ", 1)
    return bool(path) and bool(text) and not path.startswith("/")


def validate_facts(facts: list[dict]) -> list[str]:
    """A protocol fact is what a session of an ABI states on the wire that no switch moves
    (deploy/wz-config.toml, "Protocol facts"): a value per ABI that has it, and where this tree
    holds it, as texts that must occur in files of the tree (`holds`) or must not (`lacks`).
    Whether the files still say so is checked by crates/wz-conformance-suite; here only the
    shape."""
    out: list[str] = []
    ids = [f.get("id") for f in facts]
    if len(ids) != len(set(ids)):
        out.append("a protocol fact id is declared twice")
    for fact in facts:
        fid = fact.get("id", "?")
        for key in sorted(set(fact) - FACT_KEYS):
            out.append(f"protocol fact `{fid}`: `{key}` is not a key a protocol fact has")
        if not POLICY_ID_RE.fullmatch(str(fid)):
            out.append(f"protocol fact `{fid}`: an id is lowercase words joined by `-`")
        if not any(abi in fact for abi in FACT_ABIS):
            out.append(f"protocol fact `{fid}`: names a value for no ABI ({', '.join(FACT_ABIS)})")
        for abi in FACT_ABIS:
            if abi in fact and (not isinstance(fact[abi], str) or not fact[abi]):
                out.append(f"protocol fact `{fid}`: its {abi} value is not a non-empty string")
        entries = [e for key in ("holds", "lacks") for e in fact.get(key, [])]
        if not entries:
            out.append(f"protocol fact `{fid}`: names nothing of this tree that holds it "
                       "(`holds`, `lacks`)")
        for entry in entries:
            if not fact_entry_ok(entry):
                out.append(f"protocol fact `{fid}`: {entry!r} is not `<file of this tree> @ <text>`")
        if not isinstance(fact.get("help"), str) or not fact.get("help", "").strip():
            out.append(f"protocol fact `{fid}`: has no help")
    return out


def validate_policies(policies: list[dict], catalog_version: int) -> list[str]:
    """A policy is behaviour upstream does not have, and enters one at a time with its own case:
    it is declared with the upstream behaviour it departs from, and it defaults to that
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
        out += policy_binding_problems(pid, pol)
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


PROFILE_KEYS = {"id", "help", "policies"}
# The profile that states every policy at upstream's behaviour, which each policy's `default` is.
UPSTREAM_PROFILE = "upstream"


def validate_profiles(profiles: list[dict], policies: list[dict]) -> list[str]:
    """A profile is a named set of policy values a run-time document starts from (`wz/profile`):
    each value is one the declaration gives its policy, and no policy the build alone decides is
    in it. Whether the build's domain allows a value is the open's question, not this one. The
    profile `upstream` states every policy a document may state, each at its `default`."""
    out: list[str] = []
    ids = [p.get("id") for p in profiles]
    if len(ids) != len(set(ids)):
        out.append("a profile id is declared twice")
    by_id = {p.get("id"): p for p in policies}
    for prof in profiles:
        name = prof.get("id", "?")
        where = f"profile `{name}`"
        for key in sorted(set(prof) - PROFILE_KEYS):
            out.append(f"{where}: `{key}` is not a key a profile has")
        if not POLICY_ID_RE.fullmatch(str(name)):
            out.append(f"{where}: an id is lowercase words joined by `-`")
        help_text = prof.get("help")
        if not isinstance(help_text, str) or not help_text.strip():
            out.append(f"{where}: it has no help")
        elif "\n\n" in help_text.strip():
            out.append(f"{where}: its help is more than one paragraph")
        elif re.search(r"\[`|crate::", help_text):
            out.append(f"{where}: its help names Rust items; it is written for a deployer")
        stated = prof.get("policies")
        if not isinstance(stated, dict):
            out.append(f"{where}: states its values in a `[profile.policies]` table")
            continue
        for pid, value in stated.items():
            pol = by_id.get(pid)
            if pol is None:
                out.append(f"{where}: `{pid}` is not a declared policy")
                continue
            if pol.get("binding") == "build":
                out.append(f"{where}: `{pid}` is decided by the build alone, so no profile states it")
            if pol.get("kind") == "bool":
                values = ["off", "on"]
            elif isinstance(pol.get("choices"), list):
                values = list(pol["choices"])
            else:
                continue
            if not isinstance(value, str) or value not in values:
                out.append(f"{where}: {value!r} is not a value of `{pid}` ({', '.join(values)})")
        if name == UPSTREAM_PROFILE:
            missing = [p.get("id") for p in policies
                       if p.get("binding") != "build" and p.get("id") not in stated]
            if missing:
                out.append(f"{where}: states every policy a document may state, and leaves out "
                           f"{', '.join(str(m) for m in missing)}")
            for pid, value in stated.items():
                pol = by_id.get(pid)
                if pol is not None and value != pol.get("default"):
                    out.append(f"{where}: states `{pid}` = {value!r}, and its default, upstream's "
                               f"behaviour, is {pol.get('default')!r}")
    return out


# ---------------------------------------------------------------------------------------------
# the capability graph
# ---------------------------------------------------------------------------------------------


def default_on(cap: dict, abi: str) -> bool:
    """Whether a build of `abi` that names nothing has the capability: on unless declared `off`,
    or unless `default_off_abis` names that ABI."""
    if abi in cap.get("default_off_abis", []):
        return False
    return cap.get("default", "on") == "on"


# The ABI whose default a generated Kconfig file states. A Zephyr or Linux image built from the
# Kconfig tree is a pico ABI node, so the Kconfig default of a capability is the pico ABI's, and
# an original's defconfig is the difference from that same default.
KCONFIG_ABI = "pico"


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


def coop_features(feats: list[str], table: dict) -> list[str]:
    """`feats` (a pico arm's list) for the cooperative engine, `table` the crate's feature table.

    A pico build runs its sessions on the tokio engine whenever that engine is in it, so the
    cooperative build must name no feature that selects it: one that lists `engine-tokio`, or
    lists a feature that does (the drive threads, the multicast group, gossip). What is left is
    what the engines share, which the crate forwards weakly (`wz-capi-core?/...`) and so selects
    neither, and `engine-coop` is named in the place `engine-tokio` was. The table is READ, not
    listed here, so a feature that later selects the tokio engine leaves the list by itself.
    """

    def selects_tokio(name: str, seen: frozenset = frozenset()) -> bool:
        for edge in table.get(name, []):
            if edge == "engine-tokio":
                return True
            # A forward to a dependency's feature or an optional dependency names no feature
            # of this crate.
            if "/" in edge or edge.startswith("dep:"):
                continue
            if edge in table and edge not in seen and selects_tokio(edge, seen | {name}):
                return True
        return False

    return ["engine-coop"] + [f for f in feats if f != "engine-tokio" and not selects_tokio(f)]


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
        # A value switch is not on or off: the reference keeps pico's number, which is also the
        # default of the limit a `maps` value row anchors to, so the two builds state the same one.
        if not row["switch"].startswith("Z_FEATURE_"):
            continue
        cls = row["class"]
        if cls == "always":
            out[row["switch"]] = 1
        elif cls == "never":
            out[row["switch"]] = 0
        elif cls == "maps":
            out[row["switch"]] = int(row["anchor"].removeprefix(PICO_DROP_IN) in enabled)
    return out


PICO_SOURCE = ROOT / "vendor" / "zenoh-pico"


def pico_build_features(engine: str, asked: list[str], table: dict) -> set[str]:
    """The wz-capi-pico features a build turns on, as cargo resolves them: the default features and
    `asked` for the tokio engine (`cargo build -p wz-capi-pico --features ...`), or `engine-coop`
    and `asked` alone for the cooperative one (`--no-default-features --features engine-coop,...`).
    A name the package lacks is a `KeyError`."""
    start = (["default"] if engine == "tokio" else ["engine-coop"]) + [f for f in asked if f]
    return enabled_features(table, start)


def pico_config_values(decl: dict, enabled: set[str], defaults: dict[str, str],
                       env: dict[str, str]) -> dict[str, str]:
    """The CMake variables zenoh-pico's `config.h.in` is rendered with for a wz-capi-pico build of
    the features `enabled`: pico's own defaults (`defaults`), every `Z_FEATURE_*` switch as the
    build carries it (`pico_reference`), and each value switch a limit maps to at the number the
    build reads from `env` (`WZ_LIMIT_<ID>`), where it states one."""
    values = dict(defaults)
    values.update({switch: str(on) for switch, on in pico_reference(decl, enabled).items()})
    for switch, lid in limit_rows(decl):
        stated = env.get(f"WZ_LIMIT_{lid}")
        if stated is not None:
            values[switch] = stated
    return values


def render_pico_config(template: str, values: dict[str, str]) -> str:
    """`template` (zenoh-pico's `config.h.in`) rendered with `values` as CMake's `configure_file`
    renders it (`upstream_switch_map.render_config`, the rendering `drop_in_header_gate.py` reads
    the upstream header with). A `@NAME@` outside a `#cmakedefine` with no value is a `ValueError`:
    it would define a macro to nothing, which a program's arithmetic on it reads as an error far
    from here, or not at all. A `#cmakedefine` without one is CMake's `#undef`."""
    # Imported here: the switch map imports this module.
    import upstream_switch_map as usm

    plain = "\n".join(line for line in template.splitlines()
                      if not re.match(r"\s*#cmakedefine\b", line))
    missing = sorted(set(re.findall(r"@(\w+)@", plain)) - set(values))
    if missing:
        raise ValueError(f"no value for {', '.join(missing)} in the pico config template")
    return usm.render_config(template, values)


def pico_config_header(decl: dict, enabled: set[str], env: dict[str, str],
                       source: pathlib.Path = PICO_SOURCE) -> str:
    """The `zenoh-pico/config.h` of a wz-capi-pico build of the features `enabled`: the header a C
    program compiled against that build's library must see, so that every struct it allocates has
    the size the library writes. The vendored pico's own build installs the header of pico's
    DEFAULT configuration (no unstable API, no advanced plane, no connectivity events), which is
    not the arm of wz's default build. This is the reverse of `--features pico CONFIG`."""
    import upstream_switch_map as usm

    template = (source / "include" / "zenoh-pico" / "config.h.in").read_text(encoding="utf-8")
    defaults = usm.cmake_defaults(usm.pico_cmake_text(source))
    return render_pico_config(template, pico_config_values(decl, enabled, defaults, env))


def pico_header_features(decl: dict) -> set[str]:
    """The wz-capi-pico capabilities a pico header states: those a zenoh-pico `Z_FEATURE_*` switch
    maps to. They are what a rendered header must give back, since `--features pico` reads only
    them; a capability no switch reaches is not in a header to be read."""
    return {row["anchor"].removeprefix(PICO_DROP_IN) for row in decl["switches"]
            if row.get("original") == "zenoh-pico" and row.get("class") == "maps"
            and row["switch"].startswith("Z_FEATURE_")
            and row["anchor"].removeprefix(PICO_DROP_IN) in decl["caps"]}


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
        lines.append("\tdefault y" if default_on(cap, KCONFIG_ABI) else "\tdefault n")
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
        if lim["kind"] == "parameter":
            # The range the code runs with, so menuconfig refuses what the build would.
            out.append(f"\trange {lim['range'][0]} {lim['range'][1]}")
        elif "most" in lim:
            out.append(f"\trange 0 {lim['most']}")
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


def limit_scopes(lim: dict) -> list[str]:
    """The scopes that each hold one value of `lim`, widest first: its `scope`, a word or a list."""
    return list(lim["scope"]) if isinstance(lim["scope"], list) else [lim["scope"]]


def rust_stage(stage: str) -> str:
    """A storage profile's binding of a limit as an `Option<Binding>`: `none` is a profile that
    does not read the limit."""
    return "None" if stage == "none" else f"Some(Binding::{camel(stage)})"


def emit_rust_limit_bindings(decl: dict) -> str:
    """The module `caps.rs` includes as `caps::binding`: one `LimitBinding` constant per limit,
    named as the limit is, stating what it does to storage, its scopes, the latest stage each
    storage profile decides it at and what a peer sees of it. Metadata only: no value moves."""
    out = generated_header("//", "rust-limit-bindings") + [
        "",
        "//! Where each limit is bound, as the declaration states it: what the limit does to storage, the",
        "//! scopes that each hold one value, the latest stage each storage profile decides it at, and what",
        "//! a peer sees of it. The limit's value is the constant of the same name in `crate::caps`.",
    ]
    if decl["limits"]:
        names = ["Binding", "LimitBinding", "LimitKind", "Scope", "Storage", "Wire"]
        if any(lim["kind"] == "bound" for lim in decl["limits"]):
            names.insert(1, "Driven")
        line = "use crate::policy_binding::{" + ", ".join(names) + "};"
        if len(line) <= RUST_MAX_WIDTH:
            out += ["", line]
        else:
            out += ["", "use crate::policy_binding::{",
                    "    " + ", ".join(names) + ",", "};"]
    for lim in decl["limits"]:
        scopes = [f"Scope::{camel(s)}" for s in limit_scopes(lim)]
        if len(", ".join(scopes)) <= RUST_ARRAY_WIDTH:
            scope = [f"    scope: &[{', '.join(scopes)}],"]
        else:
            scope = ["    scope: &["] + [f"        {s}," for s in scopes] + ["    ],"]
        if lim["kind"] == "bound":
            held = f"Some((0, {lim['most']}))" if "most" in lim else "None"
            kind = ["    kind: LimitKind::Bound,",
                    f"    driven: Some(Driven::{camel(lim['driven'])}),",
                    f"    range: {held},"]
        else:
            least, most = lim["range"]
            kind = ["    kind: LimitKind::Parameter,", "    driven: None,",
                    f"    range: Some(({least}, {most})),"]
        out += ["", f"/// Where [`super::{lim['id']}`] is bound.",
                f"pub const {lim['id']}: LimitBinding = LimitBinding {{"] + kind + [
                f"    storage: Storage::{camel(lim['storage'])},"] + scope + [
                f"    binding_heap: {rust_stage(lim['binding_heap'])},",
                f"    binding_fixed: {rust_stage(lim['binding_fixed'])},",
                f"    wire: Wire::{camel(lim['wire'])},",
                "};"]
    return "\n".join(out) + "\n"


def open_limits(decl: dict) -> list[dict]:
    """The limits a stage after the build may decide: every limit that is not a capacity alone.
    A capacity sizes storage only the build can size, so it stays a constant of `caps` and a
    document that states one is refused by name."""
    return [lim for lim in decl["limits"] if lim["storage"] != "capacity"]


def is_runtime_limit(lim: dict) -> bool:
    """Whether the snapshot of the node or runtime holds `lim` (its widest scope is `runtime`)
    rather than the snapshot of a session, whose links and entities take the session's value."""
    return limit_scopes(lim)[0] == "runtime"


def limit_capacity_rust(lim: dict) -> str:
    """`CAPACITY` of a limit's `LimitSpec`: the storage the build sized by it. A limit that is
    `both` sizes the fixed profile's storage, and the heap's too where `on_heap` is `capacity`; a
    limit that sizes nothing (`quota`) has none in any build."""
    value = f"caps::{lim['id']}"
    if lim["storage"] == "quota":
        return "None"
    if lim["on_heap"] == "capacity":
        return f"Some({value})"
    return f"fixed_capacity({value})"


def limit_default_rust(lim: dict) -> str:
    """`DEFAULT` of a limit's `LimitSpec`: what the code admits or runs with when no stage after
    the build states a value, which is what the build runs with today. A parameter's is the
    build's value. A bound's is its capacity where the build sized storage by it; elsewhere the
    build's value, where the code refuses past it (`quota`, or `on_heap = "quota"`), with `0`
    read as no bound where the limit says so, and no bound where the heap's growable table
    refuses nothing (`on_heap = "advisory"`)."""
    value = f"caps::{lim['id']}"
    if lim["kind"] == "parameter":
        return value
    if lim["storage"] == "quota":
        zero = "true" if lim.get("zero_unbounded") else "false"
        return f"Quota::from_build({value}, {zero})"
    # Where the heap sizes storage by it or refuses past it, both profiles run with the build's
    # value, which is the fixed profile's capacity too.
    if lim["on_heap"] != "advisory":
        return f"Quota::at_most({value})"
    return "Quota::of_build(Self::CAPACITY, Quota::UNBOUNDED)"


def rust_assoc_const(name: str, ty: str, value: str) -> list[str]:
    """`const <name>: <ty> = <value>;` in an impl, broken after the `=` when it does not fit."""
    one = f"    const {name}: {ty} = {value};"
    if len(one) <= RUST_MAX_WIDTH:
        return [one]
    return [f"    const {name}: {ty} =", f"        {value};"]


def limit_spec_rust(lim: dict) -> list[str]:
    """One limit's type and its `LimitSpec`, and the `Limited` alias a snapshot holds it in."""
    name, lid = camel_limit(lim["id"]), lim["id"]
    bound = lim["kind"] == "bound"
    ty = "Quota" if bound else "usize"
    driven = f"Some(Driven::{camel(lim['driven'])})" if bound else "None"
    out = rust_doc(f"`{lid}`: {first_sentence(lim['help'])}", "")
    out += ["#[derive(Clone, Copy, Debug, PartialEq, Eq)]", f"pub struct {name};", "",
            f"impl LimitSpec for {name} {{", f"    type Value = {ty};",
            f"    const LIMIT: &'static str = {rust_word(lid)};",
            f"    const DRIVEN: Option<Driven> = {driven};"]
    out += rust_assoc_const("CAPACITY", "Option<usize>", limit_capacity_rust(lim))
    if bound and "most" in lim:
        domain = (f"LimitDomain::of_bound_within(Self::CAPACITY, {lim['most']}, Self::DEFAULT, "
                  "DEFAULTS_ONLY)")
    elif bound:
        domain = "LimitDomain::of_bound(Self::CAPACITY, Self::DEFAULT, DEFAULTS_ONLY)"
    else:
        least, most = lim["range"]
        domain = (f"LimitDomain::of_parameter({least}, {most}, Self::CAPACITY, Self::DEFAULT, "
                  "DEFAULTS_ONLY)")
    out += rust_assoc_const("DOMAIN", "LimitDomain", domain)
    out += rust_assoc_const("DEFAULT", ty, limit_default_rust(lim))
    out += ["}", ""]
    # An associated constant is evaluated only where it is used, so the domain's own refusal of a
    # build value outside it is forced here, for every build, whether or not a reader names it.
    out += [f"const _: LimitDomain = {name}::DOMAIN;", ""]
    alias = f"type {name}Held = Limited<{name}, {{ {name}::HELD }}>;"
    if len(alias) > RUST_MAX_WIDTH:
        alias_lines = [f"type {name}Held =", f"    Limited<{name}, {{ {name}::HELD }}>;"]
    else:
        alias_lines = [alias]
    return out + [f"/// How `{lid}` is held: in no byte when its domain is one value."] + alias_lines


def camel_limit(lid: str) -> str:
    """The type of a limit, from its SCREAMING_SNAKE_CASE id: `MAX_SUBSCRIPTIONS` is
    `MaxSubscriptions`."""
    return "".join(part.capitalize() for part in lid.lower().split("_"))


def limit_snapshot_rust(snapshot: str, lims: list[dict], what: str) -> list[str]:
    """The snapshot `snapshot` of `lims`: one field per limit, its build defaults, an accessor and a
    `select_*` per field, the `LimitField` impl of each limit's type, and the table a reader that
    names a limit by its id dispatches on."""
    table = {"SessionLimits": "SESSION_LIMITS", "RuntimeLimits": "RUNTIME_LIMITS"}[snapshot]
    count = f"{table[:-len('LIMITS')]}LIMIT_COUNT"
    out = rust_doc(f"The value of every limit {what}, as one snapshot: what a creator resolved and "
                   "hands the machines of its scope. A machine reads a limit through the accessor of "
                   "its field, never from the build. Each value lies inside the build's domain of "
                   "its limit, and a limit whose domain is one value reads as that value whatever "
                   "was selected ([`Limited::get`]).", "")
    out += ["#[derive(Clone, Copy, Debug, PartialEq, Eq)]", "#[non_exhaustive]"]
    if lims:
        out.append(f"pub struct {snapshot} {{")
        for lim in lims:
            out += [f"    /// `{lim['id']}`.", f"    {lim['id'].lower()}: {camel_limit(lim['id'])}Held,"]
        out.append("}")
    else:
        out.append(f"pub struct {snapshot} {{}}")
    out += ["", f"impl {snapshot} {{",
            "    /// The build defaults: each limit's value as the build states it ([`LimitSpec::DEFAULT`]).",
            "    pub const fn from_build() -> Self {"]
    inits = [f"{lim['id'].lower()}: Limited::build_default()" for lim in lims]
    if not inits:
        out.append("        Self {}")
    else:
        out += ["        Self {"] + [f"            {init}," for init in inits] + ["        }"]
    out += ["    }", "",
            "    /// The build defaults ([`Self::from_build`]): the snapshot a creator starts from. A machine",
            "    /// does not call it; it reads the snapshot its creator handed it.",
            "    pub const fn defaults() -> Self {",
            "        Self::from_build()",
            "    }"]
    for lim in lims:
        field = lim["id"].lower()
        ty = "Quota" if lim["kind"] == "bound" else "usize"
        out += ["", f"    /// `{lim['id']}` as this snapshot holds it.",
                f"    pub const fn {field}(&self) -> {ty} {{", f"        self.{field}.get()", "    }",
                "", f"    /// Selects `{lim['id']}`, when the build's domain holds `value`."]
        one = f"    pub fn select_{field}(&mut self, value: {ty}) -> Result<(), OutsideLimitDomain> {{"
        if len(one) <= RUST_MAX_WIDTH:
            out.append(one)
        else:
            out += [f"    pub fn select_{field}(", "        &mut self,", f"        value: {ty},",
                    "    ) -> Result<(), OutsideLimitDomain> {"]
        out += [f"        self.{field} = Limited::select(value)?;", "        Ok(())", "    }"]
    out += ["}", "", f"impl Default for {snapshot} {{", "    fn default() -> Self {",
            "        Self::from_build()", "    }", "}"]
    for lim in lims:
        field, name = lim["id"].lower(), camel_limit(lim["id"])
        ty = "Quota" if lim["kind"] == "bound" else "usize"
        head = f"    fn select_in(snapshot: &mut {snapshot}, value: {ty}) -> Result<(), OutsideLimitDomain> {{"
        if len(head) <= RUST_MAX_WIDTH:
            sel = [head]
        else:
            sel = ["    fn select_in(", f"        snapshot: &mut {snapshot},", f"        value: {ty},",
                   "    ) -> Result<(), OutsideLimitDomain> {"]
        out += ["", f"impl LimitField<{snapshot}> for {name} {{"] + sel + [
                f"        snapshot.select_{field}(value)", "    }", "",
                f"    fn held_in(snapshot: &{snapshot}) -> {ty} {{",
                f"        snapshot.{field}()", "    }", "}"]
    out += ["", f"/// How many limits [`{snapshot}`] holds: the length of [`{table}`].",
            f"pub const {count}: usize = {len(lims)};", "",
            f"/// Every limit of [`{snapshot}`] as a reader that names it by its id sees it, in the order of",
            "/// its fields."]
    rows = [f"LimitEntry::of::<{camel_limit(lim['id'])}>()" for lim in lims]
    return out + rust_static_array(f"pub static {table}: [LimitEntry<{snapshot}>; {count}] =", rows)


def emit_rust_limit_snapshots(decl: dict) -> str:
    """The module `limits.rs` includes: one type per limit a stage after the build may decide
    (`open_limits`), implementing `LimitSpec` (its kind, who makes it grow, its capacity in this
    build, its domain and the build's value), and the two snapshots that hold one value of each:
    `RuntimeLimits` for a limit whose widest scope is the runtime, `SessionLimits` for the rest.
    No machine reads them yet; each limit's reader still reads `caps`, so nothing a build does
    changes."""
    lims = open_limits(decl)
    runtime = [lim for lim in lims if is_runtime_limit(lim)]
    session = [lim for lim in lims if not is_runtime_limit(lim)]
    out = generated_header("//", "rust-limit-snapshots") + [
        "",
        "//! The limits a stage after the build may decide, as the code will read them: each is a field of",
        "//! [`SessionLimits`] or of [`RuntimeLimits`], the snapshots a creator hands its machines. Their",
        "//! build defaults are what the build runs with today ([`LimitSpec::DEFAULT`]), so a snapshot",
        "//! that starts from them changes nothing; a test names another value with the field's",
        "//! `select_*`.",
        "//!",
        "//! Each limit's type implements [`LimitSpec`]: its capacity in this build, the domain the build",
        "//! allows (the build's value alone where `DEFAULTS_ONLY`), and the build's value, which the",
        "//! domain must hold: a constant after each type evaluates its domain, so a build that states a",
        "//! value outside it does not compile. A field holds no byte for a limit whose domain is one value.",
        "",
        "use crate::caps;",
        "use crate::limit_binding::{",
        "    limit_defaults_only, LimitDomain, LimitEntry, LimitField, LimitSpec, Limited,",
        "    OutsideLimitDomain, Quota,",
        "};",
        "use crate::policy_binding::Driven;",
        "",
        "/// Whether a limit's domain keeps only the build's value: what `WZ_LIMIT_DOMAINS` states, else",
        "/// whether the target has no operating system.",
        'const DEFAULTS_ONLY: bool = limit_defaults_only(option_env!("WZ_LIMIT_DOMAINS"));',
        "",
        "/// The capacity of a limit the fixed storage profile sizes storage by and the heap profile",
        "/// does not: `value` where the build's tables are fixed in size, none where they grow.",
        "const fn fixed_capacity(value: usize) -> Option<usize> {",
        "    if crate::bounded::ENFORCES_CAPACITY {",
        "        Some(value)",
        "    } else {",
        "        None",
        "    }",
        "}",
    ]
    for lim in lims:
        out += [""] + limit_spec_rust(lim)
    out += [""] + limit_snapshot_rust("SessionLimits", session, "a session holds")
    out += [""] + limit_snapshot_rust("RuntimeLimits", runtime, "a node or runtime holds")
    return "\n".join(out) + "\n"


def first_sentence(text: str) -> str:
    """The first sentence of a help, on one line: up to the first full stop that a space or the
    end follows, so the stops inside an address or a number do not end it."""
    flat = " ".join(text.split())
    match = re.search(r"\.(?=\s|$)", flat)
    return flat[: match.end()] if match else flat


def schema_annotations(row: dict, keys: tuple[str, ...]) -> dict:
    """Where a policy or a limit is bound, as `x-wz-<key>` annotations of its schema."""
    return {f"x-wz-{key.replace('_', '-')}": row[key] for key in keys if key in row}


def emit_config_schema(decl: dict) -> str:
    """The JSON Schema (draft 2020-12) of the run-time document: under `wz`, `policies` holds each
    policy a stage after the build decides (its `binding` is not `build`), as the enum of its
    values, and `limits` each limit that is not a capacity alone (`open_limits`): a bound as an
    integer of at least 1 or `"unbounded"`, a parameter as an integer in its range with the
    declared default. Each carries its help's first sentence and where it is bound (`x-wz-*`). The build may narrow a policy's values further (its domain), which a
    document is checked against when it is applied, not here. `profile` is the enum of the
    declared profiles' ids, present only where the declaration states one. `key-ids` is the shape
    of the key ids every node shares, present where the declaration has `key-wire-form`."""
    policies = {}
    for pol in decl["policies"]:
        if pol["binding"] == "build":
            continue
        policies[pol["id"]] = {
            "description": first_sentence(pol["help"]),
            "enum": policy_values(pol),
            "default": pol["default"],
            **schema_annotations(pol, ("scope", "binding", "mutability", "boundary", "wire")),
        }
    limits = {}
    for lim in open_limits(decl):
        if lim["kind"] == "bound":
            # A stated bound admits at least one: `0` would refuse everything, and no bound is
            # stated as the word. A build with a capacity narrows it further (its domain).
            count = {"type": "integer", "minimum": 1}
            if "most" in lim:
                count["maximum"] = lim["most"]
            value = {"oneOf": [count, {"const": "unbounded"}]}
        else:
            value = {"type": "integer", "minimum": lim["range"][0], "maximum": lim["range"][1],
                     "default": lim["default"]}
        limits[lim["id"]] = {
            "description": first_sentence(lim["help"]),
            **value,
            **schema_annotations(lim, ("kind", "driven", "storage", "scope", "binding_heap",
                                       "binding_fixed", "wire")),
        }
    members: dict = {}
    profiles = decl.get("profiles", [])
    if profiles:
        members["profile"] = {
            "description": ("The profile the document starts from: a named set of policy values "
                            "the build declares, which the document's own policies override."),
            "enum": [prof["id"] for prof in profiles],
        }
    members["policies"] = {"type": "object", "properties": policies, "additionalProperties": False}
    members["limits"] = {"type": "object", "properties": limits, "additionalProperties": False}
    # `wz/key-ids`, read by a build with the `shared-key-ids` capability: its forms are the values
    # of `key-wire-form`, and how many entries a dictionary may have is the build's
    # MAX_SHARED_KEY_IDS, which a build sizes, so the schema states no bound of its own.
    forms = next((policy_values(pol) for pol in decl["policies"] if pol["id"] == "key-wire-form"),
                 None)
    if forms is not None:
        members["key-ids"] = {
            "description": ("The key ids every node of a deployment shares (the shared-key-ids "
                            "capability): a dictionary of key expressions by id, and the "
                            "key-wire form of an endpoint stated apart from the session's."),
            "type": "object",
            "properties": {
                "dictionary": {
                    "type": "array",
                    "items": {
                        "type": "object",
                        "properties": {
                            "id": {"type": "integer", "minimum": 1, "maximum": 65535},
                            "key": {"type": "string", "minLength": 1},
                        },
                        "required": ["id", "key"],
                        "additionalProperties": False,
                    },
                },
                "links": {
                    "type": "array",
                    "items": {
                        "type": "object",
                        "properties": {
                            "locator": {"type": "string", "minLength": 1},
                            "form": {"enum": forms},
                        },
                        "required": ["locator", "form"],
                        "additionalProperties": False,
                    },
                },
            },
            "additionalProperties": False,
        }
    doc = {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$comment": ("GENERATED from deploy/wz-config.toml by scripts/lib/wz_config.py --emit "
                     "config-schema. Do not edit: `wz_config.py --check` fails when this file is "
                     "stale."),
        "title": "wz run-time configuration",
        "description": ("The policies and limits a document may state when a node opens or while "
                        "it runs. A policy the build fixes, and a limit only the build sizes, are "
                        "not here."),
        "type": "object",
        "properties": {
            "wz": {
                "type": "object",
                "properties": members,
                "additionalProperties": False,
            },
        },
    }
    return json.dumps(doc, indent=2, ensure_ascii=True) + "\n"


def rust_word(text: str) -> str:
    """A string literal of a word the declaration names: an id, an ABI, an environment name or a
    policy value. Such a word needs no escaping, and one that would is refused here rather than
    escaped differently from the JSON the statement digests."""
    if not re.fullmatch(r"[A-Za-z0-9_.:-]+", text):
        raise ValueError(f"{text!r} is not a declaration word")
    return f'"{text}"'


def _refuses_word(text: str) -> bool:
    """Whether `rust_word` refuses `text` (the selftest's probe of the refusal)."""
    try:
        rust_word(text)
    except ValueError:
        return True
    return False


def _refuses_toml(text: str) -> bool:
    """Whether `read_decl_toml` refuses `text` (the selftest's probe of the refusal)."""
    try:
        read_decl_toml(text)
    except ValueError:
        return True
    return False


def _refuses_env(decl: dict, env: dict[str, str]) -> bool:
    """Whether `env_statement` refuses `env` (the selftest's probe of the refusal)."""
    try:
        env_statement(decl, "pico", [], env, {})
    except ValueError:
        return True
    return False


def _refuses_domain(pol: dict, env: dict[str, str]) -> bool:
    """Whether `policy_domain` refuses `env` for `pol` (the selftest's probe of the refusal)."""
    try:
        policy_domain(pol, env)
    except ValueError:
        return True
    return False


def _refuses_text(text: str) -> bool:
    """Whether `rust_text` refuses `text` (the selftest's probe of the refusal)."""
    try:
        rust_text(text)
    except ValueError:
        return True
    return False


class RustWords(str):
    """A `&[<word>, ...]` slice literal that also keeps its items, so a layout that puts it on a
    line of its own can break it one item a line where rustfmt would."""

    items: list[str]

    def __new__(cls, items: list[str]) -> "RustWords":
        out = super().__new__(cls, "&[" + ", ".join(items) + "]")
        out.items = items
        return out


def rust_tuple_rows(rows: list[list[str]]) -> list[str]:
    """Array rows of tuples, each laid out as rustfmt lays it out: on one line when its elements
    fit the call width, else one element a line, and an element that is a slice of words
    ([`RustWords`]) one item a line when it does not fit rustfmt's array width or the line."""
    out: list[str] = []
    for parts in rows:
        inner = ", ".join(parts)
        if len(inner) <= RUST_FN_CALL_WIDTH and len(f"    ({inner}),") <= RUST_MAX_WIDTH:
            out.append(f"    ({inner}),")
            continue
        out.append("    (")
        for p in parts:
            if isinstance(p, RustWords) and (len(", ".join(p.items)) > RUST_ARRAY_WIDTH
                                              or len(f"        {p},") > RUST_MAX_WIDTH):
                out += ["        &["] + [f"            {item}," for item in p.items] + ["        ],"]
            else:
                out.append(f"        {p},")
        out.append("    ),")
    return out


def rust_word_list(words: list[str]) -> RustWords:
    return RustWords([rust_word(w) for w in words])


def emit_rust_conformance_items(decl: dict) -> str:
    """The questions a conformance statement answers (decision C15), for a build script: each
    capability with the ABIs that export it, each limit with the environment name its value is
    stated by and its default, and each policy with its environment name, the values it may take
    and upstream's. `wz-conformance-build` reads the answers of the build it runs in and digests
    them as `statement_digest` does."""
    out = generated_header("//", "rust-conformance-items") + [
        "",
        "//! The questions a conformance statement answers (a build states what it is, from",
        "//! the configuration it was built with), in the declaration's order, and where a",
        "//! build script finds each answer.",
        "",
        "/// `format` of the statement.",
        f"pub const FORMAT: &str = {rust_word(STATEMENT_FORMAT)};",
        "/// `format_version` of the statement.",
        f"pub const FORMAT_VERSION: u32 = {STATEMENT_FORMAT_VERSION};",
        "/// The declaration's `catalog_version`.",
        f"pub const CATALOG_VERSION: u32 = {decl['catalog_version']};",
        "",
        "/// The features of the pico ABI's crate that run its sessions on the cooperative engine, when",
        "/// the tokio engine is not in the build; every other build runs them on the tokio engine.",
        "pub const COOP_ENGINE_FEATURES: &[&str] = "
        f"{rust_word_list(list(STATEMENT_COOP_FEATURES))};",
        "/// The features that build a library for a platform other than a host, each with its word.",
        # One line, as rustfmt lays out a short array; the list is one row per platform.
        "pub const PLATFORM_FEATURES: &[(&str, &str)] = &["
        + ", ".join(f"({rust_word(feature)}, {rust_word(platform)})"
                    for feature, platform in STATEMENT_PLATFORM_FEATURES)
        + "];",
        "",
        "/// Each capability and the ABIs that export it: its cargo feature in those crates has its id.",
        "pub const CAPABILITIES: &[(&str, &[&str])] = &[",
    ]
    out += rust_tuple_rows([[rust_word(cid), rust_word_list(list(decl["caps"][cid]["abis"]))]
                            for cid in decl["order"]])
    arm: dict[str, list[str]] = {}
    for abi in ABIS:
        for switch in arm_switches(decl, abi):
            arm.setdefault(switch, []).append(abi)
    out += [
        "];",
        "",
        "/// Each layout switch that is not a capability (`wz_config.arm_switches`) and the ABIs whose",
        "/// crate has it as a feature: it selects the arm of the C types a program allocates.",
        "pub const ARM: &[(&str, &[&str])] = &[",
    ]
    out += rust_tuple_rows([[rust_word(switch), rust_word_list(abis)] for switch, abis in arm.items()])
    out += [
        "];",
        "",
        "/// Each limit, the environment name a build states it by, and its default.",
        "pub const LIMITS: &[(&str, &str, u64)] = &[",
    ]
    out += rust_tuple_rows([[rust_word(lim["id"]), rust_word(lim["kconfig"]), str(lim["default"])]
                            for lim in decl["limits"]])
    out += [
        "];",
        "",
        "/// Each policy, the environment name a build states it by, the values it may take (`off`",
        "/// and `on` for a bool), and upstream's value, which a build that states none runs.",
        "pub const POLICIES: &[(&str, &str, &[&str], &str)] = &[",
    ]
    out += rust_tuple_rows([
        [rust_word(pol["id"]), rust_word(pol["kconfig"]), rust_word_list(policy_values(pol)),
         rust_word(pol["default"])]
        for pol in decl["policies"]])
    out += ["];"]
    return "\n".join(out) + "\n"


# Draws per ABI of the vectors' random part. They are seeded by a fixed word, so the file is
# the same on every machine and `--check` can hold it.
STATEMENT_VECTOR_RANDOM = 8
STATEMENT_VECTOR_SEED = "wz-conformance-statement-vectors"


def vector_draws(seed: str):
    """An endless stream of 64-bit draws: SHA-256 of the seed and a counter. It does not use
    `random`, whose stream a new Python version is free to change, which would make a
    regenerated file differ for no change of the declaration."""
    counter = 0
    while True:
        yield int.from_bytes(hashlib.sha256(f"{seed}:{counter}".encode()).digest()[:8], "big")
        counter += 1


def statement_vectors(decl: dict) -> list[dict]:
    """Builds and the digest `env_statement` gives each, for the two writers of a statement's
    digest to agree on across the declaration's whole domain, not on one fixture (decision C15).
    Each vector names an ABI, the cargo features on, and the `WZ_LIMIT_*` and `WZ_POLICY_*` the
    environment states.
    - Per ABI: nothing stated; every name of the ABI on; every name of every ABI on (the other
      ABIs' names count for nothing); every limit and policy stated at its default (equal to
      nothing stated); each capability and layout switch on alone.
    - Each limit one above its default (one below, for a parameter at the top of its range), and
      one bound at the largest value read. Each policy at each value other than upstream's.
      Reading these does not depend on the ABI, so the ABIs take turns.
    - Seeded random builds: each name, limit and policy stated with probability one half. A
      parameter is drawn inside its declared range, as a build that states one outside it does
      not compile; a bound, which has no range, from 32 bits.
    """
    out: list[dict] = []

    def add(case: str, abi: str, features: list[str], env: dict[str, str]) -> None:
        digest = env_statement(decl, abi, features, env, {})["digest"]
        out.append({"case": case, "abi": abi, "features": features, "env": env, "digest": digest})

    def names(abi: str) -> list[str]:
        return arm_switches(decl, abi) + [cid for cid in decl["order"]
                                          if abi in decl["caps"][cid]["abis"]]

    every = sorted({name for abi in ABIS for name in names(abi)})
    defaults = {**{lim["kconfig"]: str(lim["default"]) for lim in decl["limits"]},
                **{pol["kconfig"]: pol["default"] for pol in decl["policies"]}}
    for abi in ABIS:
        add("nothing stated", abi, [], {})
        add("every name of the ABI on", abi, names(abi), {})
        add("every name of every ABI on", abi, every, {})
        add("every limit and policy stated at its default", abi, [], defaults)
        for name in names(abi):
            add(f"{name} alone", abi, [name], {})
    # The engine and the platform, read from the pico crate's features by the same rule on both
    # sides (`statement_engine`, `statement_platform`).
    add("the cooperative engine", "pico", ["engine-coop"], {})
    add("the zephyr platform", "pico", ["os-zephyr"], {})
    add("the tokio engine beside a cooperative feature", "pico", ["engine-tokio", "engine-coop"], {})
    for i, lim in enumerate(decl["limits"]):
        if lim["kind"] == "parameter" and lim["default"] == lim["range"][1]:
            add(f"{lim['id']} one below its default", ABIS[i % len(ABIS)], [],
                {lim["kconfig"]: str(lim["default"] - 1)})
            continue
        add(f"{lim['id']} one above its default", ABIS[i % len(ABIS)], [],
            {lim["kconfig"]: str(lim["default"] + 1)})
    first = next(lim for lim in decl["limits"] if lim["kind"] == "bound")
    add(f"{first['id']} at the largest value read", "pico", [], {first["kconfig"]: str((1 << 64) - 1)})
    turn = 0
    for pol in decl["policies"]:
        for value in policy_values(pol):
            if value != pol["default"]:
                add(f"{pol['id']} {value}", ABIS[turn % len(ABIS)], [], {pol["kconfig"]: value})
                turn += 1
    draw = vector_draws(STATEMENT_VECTOR_SEED)
    for abi in ABIS:
        for n in range(STATEMENT_VECTOR_RANDOM):
            features = [name for name in names(abi) if next(draw) % 2]
            env: dict[str, str] = {}
            for lim in decl["limits"]:
                if next(draw) % 2:
                    if lim["kind"] == "parameter":
                        least, most = lim["range"]
                        value = least + next(draw) % (most - least + 1)
                    else:
                        value = next(draw) % (1 << 32)
                    env[lim["kconfig"]] = str(value)
            for pol in decl["policies"]:
                if next(draw) % 2:
                    values = policy_values(pol)
                    env[pol["kconfig"]] = values[next(draw) % len(values)]
            add(f"random {n}", abi, features, env)
    return out


def emit_statement_vectors(decl: dict) -> str:
    """`statement_vectors` as the JSON file the build script's test reads: one vector a line, so
    a change of the declaration reads as the lines it moves."""
    head = {
        "generated": "GENERATED from deploy/wz-config.toml by scripts/lib/wz_config.py --emit "
                     "statement-vectors. Do not edit: `wz_config.py --check` fails when this file "
                     "is stale.",
        "about": "Builds of the C ABI crates and the conformance digest wz_config.py states for "
                 "each, from the configuration each was built with. wz-conformance-build's test "
                 "computes each from the same features and environment and must give the same.",
    }
    lines = ["{"]
    for key, value in head.items():
        lines.append(f"  {json.dumps(key)}: {json.dumps(value, ensure_ascii=True)},")
    lines.append('  "vectors": [')
    vectors = [json.dumps(v, sort_keys=True, separators=(", ", ": "), ensure_ascii=True)
               for v in statement_vectors(decl)]
    lines += [f"    {v}," for v in vectors[:-1]] + [f"    {vectors[-1]}"]
    lines += ["  ]", "}"]
    return "\n".join(lines) + "\n"


def emit_rust_feature_bits(decl: dict) -> str:
    """The `features` word of a resource snapshot: one bit for each capability that declares an
    `observation_bit`, in bit order. The names the code uses are bound to these in
    `resource_snapshot::feature_bits`, beside the documentation of each."""
    named = sorted(
        ((cap["observation_bit"], cid) for cid, cap in decl["caps"].items() if "observation_bit" in cap)
    )
    out = generated_header("//", "rust-feature-bits") + [
        "",
        "//! The bit each capability has in the `features` word of a resource snapshot, as the",
        "//! declaration assigns it (`observation_bit`). A bit is assigned once and never moved or reused.",
        "",
    ]
    names = [(cid.upper().replace("-", "_"), cid, bit) for bit, cid in named]
    for const, _cid, bit in names:
        out.append(f"pub(super) const {const}: u64 = 1 << {bit};")
    out += ["", f"pub(super) const NAMES: [(u64, &str); {len(names)}] = ["]
    out += [f'    ({const}, "{cid}"),' for const, cid, _bit in names]
    out.append("];")
    # The word of the instruments a crate was built with, written once for every crate. A crate
    # lists no feature by hand: `cfg!` needs a literal, so a list written in each crate drifts from
    # the crate's `[features]` without anything failing, and the generated macro lists the declared
    # capabilities, which a crate's features are named after. A crate with none of a capability's
    # feature reads that bit as off, which is what it is.
    out += [
        "",
        "/// The `features` word of the instruments the CALLING crate was built with: the bit of each",
        "/// capability whose cargo feature is on in that crate (`cfg!` is read where the macro is",
        "/// expanded). The list is the declaration's, so a crate states no list of its own.",
        "#[macro_export]",
        "macro_rules! built_feature_bits {",
        "    () => {{",
        "        // A crate that has no such feature reads it as off; the lint that asks for a feature",
        "        // to be declared is for a typo, and each name here is the declaration's.",
        "        let mut word = 0u64;",
    ]
    for const, cid, _bit in names:
        var = cid.replace("-", "_")
        out += [
            "        #[allow(unexpected_cfgs)]",
            f'        let {var} = cfg!(feature = "{cid}");',
            f"        if {var} {{",
            f"            word |= $crate::resource_snapshot::feature_bits::{const};",
            "        }",
        ]
    out += ["        word", "    }};", "}"]
    return "\n".join(out) + "\n"


def policy_kconfig(pol: dict, requires: str | None = None) -> list[str]:
    """One policy as Kconfig, followed by a blank line. A bool policy is a `bool` symbol that
    defaults to `n`; a choice is a Kconfig `choice` with one option per value, the default being
    upstream's. Each help ends with what upstream does. With `requires` the symbol (the choice,
    for a choice) `depends on` it, so a profile that does not run the policy's code has no symbol
    to set."""
    help_text = pol["help"].strip().splitlines() + textwrap.wrap(
        f"Upstream: {pol['upstream'].strip()}", width=78)
    depends = [f"\tdepends on {requires}"] if requires else []
    if pol["kind"] == "bool":
        out = [f"config {pol['kconfig']}", f'\tbool "{pol["id"]}"', "\tdefault n"] + depends + ["\thelp"]
        return out + help_lines("\n".join(help_text)) + [""]
    default = f"{pol['kconfig']}_{snake(pol['default']).upper()}"
    out = [f"choice {pol['kconfig']}", f'\tprompt "{pol["id"]}"', f"\tdefault {default}"] + depends + ["\thelp"]
    out += help_lines("\n".join(help_text))
    for value in pol["choices"]:
        out += ["", f"config {pol['kconfig']}_{snake(value).upper()}", f'\tbool "{value}"']
    return out + ["", "endchoice", ""]


def policy_domain_kconfig(pol: dict) -> list[str]:
    """One bool per value of `pol`, each `default y` and followed by a blank line: turning one off
    leaves the value out of the domain a stage after the build may select from
    (`WZ_POLICY_<NAME>_ALLOWS_<VALUE>`). A value's prompt shows only while the value is not the
    policy's chosen default, so the default is always allowed: the strict merge refuses an
    assignment the symbol does not take, as it refuses any other."""
    out: list[str] = []
    for value in policy_values(pol):
        if pol["kind"] == "bool":
            other = pol["kconfig"] if value == "off" else f"!{pol['kconfig']}"
        else:
            other = f"!{pol['kconfig']}_{snake(value).upper()}"
        out += [f"config {policy_allows_symbol(pol, value)}",
                f'\tbool "{pol["id"]} allows {value}" if {other}',
                "\tdefault y",
                "\thelp",
                f"\t  Whether `{value}` stays selectable after the build; the chosen default always does.",
                "\t  A target with no operating system keeps only the default unless this is set here.",
                ""]
    return out


def emit_kconfig_policies(decl: dict) -> str:
    """Every policy of the declaration, for the host tree, each followed by its domain."""
    out = generated_header("#", "kconfig-policies") + [
        "",
        'menu "wz policies"',
        "",
        'comment "Each policy is behaviour beyond upstream; the default of every one is upstream\'s."',
        "",
    ]
    for pol in decl["policies"]:
        out += policy_kconfig(pol) + policy_domain_kconfig(pol)
    out.append("endmenu")
    return "\n".join(out) + "\n"


def image_policy_rows(decl: dict, image: str) -> list[tuple[dict, str | None]]:
    """The policies `image` reads, in the declaration's order, each with the expression that holds
    it to the profiles that run its code (`[[policy_image]]`)."""
    rows = {r["policy"]: r.get("requires") for r in decl.get("policy_images", []) if r["image"] == image}
    return [(pol, rows[pol["id"]]) for pol in decl.get("policies", []) if pol["id"] in rows]


def emit_image_policies(decl: dict, image: str) -> str:
    """The policies of `image` as Kconfig: only those its build reads (`[[policy_image]]`), each
    depending on what holds it to the profiles that run its code."""
    out = generated_header("#", f"image-policies:{image}") + [
        "",
        'menu "wz policies"',
        "",
        'comment "Each policy is behaviour beyond upstream; the default of every one is upstream\'s."',
        'comment "Only the policies this image\'s code reads are here."',
        "",
    ]
    for pol, requires in image_policy_rows(decl, image):
        out += policy_kconfig(pol, requires)
    out.append("endmenu")
    return "\n".join(out) + "\n"


def rust_doc(text: str, indent: str) -> list[str]:
    return textwrap.wrap(text, width=92, initial_indent=f"{indent}/// ",
                         subsequent_indent=f"{indent}/// ")


def emit_rust_policies(decl: dict) -> str:
    """The module `policy.rs` includes: one enum per choice policy, and `SessionPolicy`, the
    snapshot of every policy's value a creator hands a machine. Each field is the policy's value
    bound inside the build's domain, read through an accessor and set through a `select_*` that
    refuses a value outside it; `SessionPolicy::defaults` is what the build's environment
    (`WZ_POLICY_<NAME>`) states, or upstream's behaviour when it states nothing. `POLICIES` holds
    the row a reader that names a policy by its id dispatches on, and `PROFILES` the declared
    profiles (`[[profile]]`). Laid out so rustfmt leaves it alone: every call fits on a line, a
    struct literal is one line only when rustfmt would make it one, and a signature is one line
    only when it fits the width."""
    pols = decl["policies"]
    choices = [p for p in pols if p["kind"] == "choice"]
    bools = [p for p in pols if p["kind"] == "bool"]
    out = generated_header("//", "rust-policies") + [
        "",
        "//! The policies of a build as the code reads them: each is a field of [`SessionPolicy`], the",
        "//! snapshot a creator hands each machine. Its build defaults ([`SessionPolicy::defaults`]) are",
        "//! the values the build's environment states as `WZ_POLICY_<NAME>`, or upstream's behaviour where",
        "//! it states none, and a test names another value with the field's `select_*`.",
        "//!",
        "//! A reader that names a policy by its id, as the open-stage document does, dispatches on the",
        "//! policy's row of [`POLICIES`]; [`PROFILES`] holds the named sets of policy values the",
        "//! declaration states (`[[profile]]`), which a document starts from.",
    ]
    if pols:
        out += [
            "//!",
            "//! Each policy's value type, an `Off` and `On` enum of its own for a bool policy, implements",
            "//! [`PolicyValue`]: the domain the build allows (`WZ_POLICY_<NAME>_ALLOWS_<VALUE>`, an unset name",
            "//! taking the rule of `DEFAULTS_ONLY`), the build's default, which the domain must hold, and",
            "//! where the policy is bound. A field of [`SessionPolicy`] holds no byte for a policy whose domain",
            "//! is one value.",
        ]
    out.append("")
    helpers = ((["policy_bool"] if bools else []) + (["policy_choice"] if choices else [])
               + (["policy_defaults_only"] if pols else []))
    if len(helpers) == 1:
        out += [f"use super::{helpers[0]};", ""]
    elif helpers:
        out += ["use super::{" + ", ".join(helpers) + "};", ""]
    profiles = decl.get("profiles", [])
    # The type `POLICIES` holds is named whether or not a policy is declared, and `Statement` only
    # where a profile states a value. A group of its own, so rustfmt keeps it after the `super`
    # import as written.
    if pols:
        out += ["use crate::policy_binding::{",
                "    default_is_allowed, Binding, Bound, Domain, Mutability, OutsideDomain, PolicyEntry,",
                "    PolicyField, PolicyValue, Scope, Wire,",
                "};"]
    else:
        out.append("use crate::policy_binding::PolicyEntry;")
    if any(prof["policies"] for prof in profiles):
        out += ["use crate::policy_document::{Profile, Statement};", ""]
    else:
        out += ["use crate::policy_document::Profile;", ""]
    if pols:
        out += ["/// Whether an allowance the build does not state keeps only the build default: what",
                f"/// `{POLICY_DOMAINS_ENV}` states, else whether the target has no operating system.",
                f'const DEFAULTS_ONLY: bool = policy_defaults_only(option_env!("{POLICY_DOMAINS_ENV}"));',
                ""]
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
        out += rust_static_array(f"const CHOICES: [&str; {len(values)}] =",
                                 [f'"{v}"' for v in values], "    ")
        out += rust_static_array(f"const ALL: [Self; {len(values)}] =",
                                 [f"Self::{camel(v)}" for v in values], "    ")
        out += ["",
                "    const fn stated() -> Self {",
                f'        let stated = option_env!("{pol["kconfig"]}");',
                f"        let index = policy_choice(stated, &Self::CHOICES, {values.index(pol['default'])});",
                "        Self::ALL[index]", "    }", "}", "",
                f"impl Default for {name} {{", BUILD_DEFAULT_DOC, "    fn default() -> Self {",
                "        Self::stated()", "    }", "}", ""]
    out += ["/// The value of every policy, as one snapshot: what a creator resolved and handed the machines of"]
    if pols:
        out += ["/// its scope. A machine reads a policy only through the accessor of its field, never from the",
                "/// build. Each value lies inside the build's domain of its policy ([`PolicyValue::DOMAIN`]), and a",
                "/// policy whose domain is one value reads as that value whatever was selected ([`Bound::get`])."]
    else:
        out.append("/// its scope. This build declares no policy.")
    out += ["#[derive(Clone, Copy, Debug, PartialEq, Eq)]", "#[non_exhaustive]"]
    if pols:
        out.append("pub struct SessionPolicy {")
        for pol in pols:
            out += rust_doc(f"`{pol['id']}`. Upstream: {pol['upstream'].strip()}", "    ")
            out.append(f"    {snake(pol['id'])}: {camel(pol['id'])}Bound,")
        out.append("}")
    else:
        out.append("pub struct SessionPolicy {}")
    out += ["", "impl SessionPolicy {",
            "    /// The build defaults: each policy's value as the build's environment states it",
            "    /// (`WZ_POLICY_<NAME>`), else upstream's behaviour.",
            "    pub const fn from_build() -> Self {"]
    inits = [f"{snake(p['id'])}: Bound::build_default()" for p in pols]
    if len(", ".join(inits)) <= RUST_STRUCT_LIT_WIDTH:
        out.append(f"        Self {{ {', '.join(inits)} }}" if inits else "        Self {}")
    else:
        out += ["        Self {"] + [f"            {init}," for init in inits] + ["        }"]
    out += ["    }", "",
            "    /// The build defaults ([`Self::from_build`]): the snapshot a creator starts from. A machine",
            "    /// does not call it; it reads the snapshot its creator handed it.",
            "    pub const fn defaults() -> Self {",
            "        Self::from_build()",
            "    }"]
    for pol in pols:
        out += policy_accessors_rust(pol)
    out += ["}", "", "impl Default for SessionPolicy {", "    fn default() -> Self {",
            "        Self::from_build()", "    }", "}"]
    for pol in pols:
        out += [""] + policy_value_rust(pol)
    out += [""] + policy_table_rust(pols) + profiles_rust(pols, profiles)
    return "\n".join(out) + "\n"


def rust_static_array(head: str, items: list[str], indent: str = "") -> list[str]:
    """`<head> [<items>];` at the depth `indent` gives (the top level when it is empty), as rustfmt
    lays it out: on one line when the items fit its array width and the line fits, else one item a
    line."""
    inner = ", ".join(items)
    one = f"{indent}{head} [{inner}];"
    if len(inner) <= RUST_ARRAY_WIDTH and len(one) <= RUST_MAX_WIDTH:
        return [one]
    return [f"{indent}{head} ["] + [f"{indent}    {item}," for item in items] + [f"{indent}];"]


def policy_field_rust(pol: dict) -> list[str]:
    """How a reader that names `pol` by its id reaches its field of `SessionPolicy`: the
    `PolicyField` impl of its value type, through the field's `select_*` and its `Bound`;
    preceded by a blank line."""
    name, field = camel(pol["id"]), snake(pol["id"])
    return ["", f"impl PolicyField for {name} {{",
            "    fn select_in(policy: &mut SessionPolicy, value: Self) -> Result<(), OutsideDomain<Self>> {",
            f"        policy.select_{field}(value)", "    }", "",
            "    fn held_in(policy: &SessionPolicy) -> Self {",
            f"        policy.{field}.get()", "    }", "}"]


def policy_table_rust(pols: list[dict]) -> list[str]:
    """`POLICY_COUNT` and `POLICIES`, the row of every policy a reader that names it by its id
    dispatches on, in the order of the fields of `SessionPolicy`."""
    out = ["/// How many policies the declaration states: the length of [`POLICIES`] and of every table kept",
           "/// per policy.",
           f"pub const POLICY_COUNT: usize = {len(pols)};", "",
           "/// Every policy as a reader that names it by its id sees it, in the order of the fields of",
           "/// [`SessionPolicy`]."]
    rows = [f"PolicyEntry::of::<{camel(pol['id'])}>()" for pol in pols]
    return out + rust_static_array("pub static POLICIES: [PolicyEntry; POLICY_COUNT] =", rows)


def rust_statement(pid: str, value: str) -> list[str]:
    """One statement of a profile's table, `Statement::new(<policy>, <value>),`, as rustfmt lays
    the call out: on one line when its arguments fit the call width and the line fits, else one
    argument a line."""
    policy, word = rust_word(pid), rust_word(value)
    args = f"{policy}, {word}"
    one = f"        Statement::new({args}),"
    if len(args) <= RUST_FN_CALL_WIDTH and len(one) <= RUST_MAX_WIDTH:
        return [one]
    return ["        Statement::new(", f"            {policy},", f"            {word},", "        ),"]


def profile_const(prof: dict) -> str:
    return f"PROFILE_{snake(prof['id']).upper()}"


def profiles_rust(pols: list[dict], profiles: list[dict]) -> list[str]:
    """Each profile as a constant, its statements in the order of the declaration's policies,
    and `PROFILES`, every one of them; each preceded by a blank line."""
    out: list[str] = []
    for prof in profiles:
        stated = prof["policies"]
        lines = [line for pol in pols if pol["id"] in stated
                 for line in rust_statement(pol["id"], stated[pol["id"]])]
        out += [""] + rust_doc(f"The profile `{prof['id']}`: {' '.join(prof['help'].split())}", "")
        out += [f"const {profile_const(prof)}: Profile = Profile {{",
                f"    id: {rust_word(prof['id'])},"]
        out += ["    statements: &["] + lines + ["    ],"] if lines else ["    statements: &[],"]
        out.append("};")
    out += ["", "/// Every profile the declaration states, which a document names by its id (`wz/profile`)."]
    head = f"pub static PROFILES: [Profile; {len(profiles)}] ="
    return out + rust_static_array(head, [profile_const(prof) for prof in profiles])


# The doc of a policy value type's `Default`: the value of the build, which only the build
# defaults of `SessionPolicy` stand for.
BUILD_DEFAULT_DOC = "    /// The build default; a machine reads the value of the snapshot it is handed instead."


def policy_accessors_rust(pol: dict) -> list[str]:
    """The accessor of one policy's field of `SessionPolicy`, which reads it through `Bound::get`
    (a `bool` for a bool policy), and its `select_*`, which refuses a value outside the build's
    domain; each preceded by a blank line. The `select_*` signature is on one line when it fits
    rustfmt's width, and one parameter a line otherwise, as the formatter lays it out."""
    field, name, pid = snake(pol["id"]), camel(pol["id"]), pol["id"]
    if pol["kind"] == "bool":
        out = ["", f"    /// `{pid}` as this snapshot holds it: `true` for `on`.",
               f"    pub const fn {field}(&self) -> bool {{", f"        self.{field}.get().is_on()", "    }"]
    else:
        out = ["", f"    /// `{pid}` as this snapshot holds it.",
               f"    pub const fn {field}(&self) -> {name} {{", f"        self.{field}.get()", "    }"]
    out += ["", f"    /// Selects `{pid}`, when the build's domain holds `value`."]
    one = f"    pub fn select_{field}(&mut self, value: {name}) -> Result<(), OutsideDomain<{name}>> {{"
    if len(one) <= RUST_MAX_WIDTH:
        out.append(one)
    else:
        out += [f"    pub fn select_{field}(", "        &mut self,", f"        value: {name},",
                f"    ) -> Result<(), OutsideDomain<{name}>> {{"]
    return out + [f"        self.{field} = Bound::select(value)?;", "        Ok(())", "    }"]


def rust_text(text: str) -> str:
    """A Rust string literal of a line of declaration prose (a policy's `boundary`): printable
    ASCII, which `policy_binding_problems` holds it to, with `\\` and `"` escaped."""
    if not all(" " <= c <= "~" for c in text):
        raise ValueError(f"{text!r} is not one line of printable ASCII")
    return '"' + text.replace("\\", "\\\\").replace('"', '\\"') + '"'


def rust_const_slice(name: str, ty: str, items: list[str]) -> list[str]:
    """`const <name>: <ty> = &[<items>];` in an impl, laid out as rustfmt lays it out: on one line
    when the items fit its array width and the line fits, else one item a line."""
    inner = ", ".join(items)
    one = f"    const {name}: {ty} = &[{inner}];"
    if len(inner) <= RUST_ARRAY_WIDTH and len(one) <= RUST_MAX_WIDTH:
        return [one]
    return [f"    const {name}: {ty} = &["] + [f"        {item}," for item in items] + ["    ];"]


def rust_domain_entry(word: str) -> list[str]:
    """One entry of the array a `Domain::from_stated` is given, `option_env!(<word>),`, as rustfmt
    lays it out: on one line when the line fits its width (measured: a single literal argument is
    not held to the call width), else the macro's argument on a line of its own."""
    one = f"            option_env!({word}),"
    if len(one) <= RUST_MAX_WIDTH:
        return [one]
    return ["            option_env!(", f"                {word}", "            ),"]


def rust_bound_alias(pol: dict) -> list[str]:
    """The type a field of `SessionPolicy` holds `pol` in, `Bound` with the store length the
    build's domain gives it (`PolicyValue::HELD`), followed by a blank line: on one line when it
    fits, else broken after the `=` (measured, as rustfmt lays out a type alias)."""
    name = camel(pol["id"])
    target = f"Bound<{name}, {{ {name}::HELD }}>;"
    one = f"type {name}Bound = {target}"
    lines = [one] if len(one) <= RUST_MAX_WIDTH else [f"type {name}Bound =", f"    {target}"]
    return [f"/// How `{pol['id']}` is held: in no byte when its domain is one value."] + lines + [""]


def rust_boundary(text: str) -> list[str]:
    """`const BOUNDARY: Option<&'static str> = Some(<text>);` as rustfmt lays it out: on one line
    when it fits; after the `=` when only the call's argument fits rustfmt's call width; else
    the argument on a line of its own, with the comma rustfmt adds to a function's arguments."""
    head = "    const BOUNDARY: Option<&'static str> ="
    one = f"{head} Some({text});"
    if len(text) > RUST_FN_CALL_WIDTH:
        return [f"{head} Some(", f"        {text},", "    );"]
    if len(one) <= RUST_MAX_WIDTH:
        return [one]
    return [head, f"        Some({text});"]


def rust_default_assert(name: str, pid: str) -> list[str]:
    """The constant that refuses a build whose domain of `pid` leaves out its default, laid out as
    rustfmt lays it out (the message is short enough for any id a line holds)."""
    arg = f"{name}::DEFAULT as usize"
    one = f"    default_is_allowed::<{name}>({arg}),"
    if len(arg) <= RUST_FN_CALL_WIDTH and len(one) <= RUST_MAX_WIDTH:
        check = [one]
    else:
        check = [f"    default_is_allowed::<{name}>(", f"        {arg},", "    ),"]
    return (["const _: () = assert!("] + check
            + [f'    "the default of {pid} is outside its WZ_POLICY_*_ALLOWS_*"', ");"])


def bool_value_rust(pol: dict) -> list[str]:
    """The value type of a bool policy, `Off` (upstream's) and `On`, with the conversions to and
    from the `bool` the accessor of `SessionPolicy` reads; followed by a blank line."""
    name = camel(pol["id"])
    out = rust_doc(f"`{pol['id']}` as a value; [`SessionPolicy`] reads it as a `bool`.", "")
    out += ["#[derive(Clone, Copy, Debug, PartialEq, Eq)]", f"pub enum {name} {{",
            "    /// `off`, upstream's behaviour.", "    Off,", "    /// `on`.", "    On,", "}", "",
            f"impl {name} {{",
            "    /// The value as the declaration, the Kconfig and the environment spell it.",
            "    pub const fn id(self) -> &'static str {", "        match self {",
            '            Self::Off => "off",', '            Self::On => "on",', "        }", "    }", "",
            "    /// The value as the `bool` the accessor of [`SessionPolicy`] reads.",
            "    pub const fn is_on(self) -> bool {", "        matches!(self, Self::On)", "    }", "",
            "    const fn from_bool(on: bool) -> Self {", "        if on {", "            Self::On",
            "        } else {", "            Self::Off", "        }", "    }", "",
            "    const fn stated() -> Self {",
            f'        let stated = option_env!("{pol["kconfig"]}");',
            "        Self::from_bool(policy_bool(stated))", "    }", "}", "",
            f"impl From<bool> for {name} {{", "    fn from(on: bool) -> Self {",
            "        Self::from_bool(on)", "    }", "}", "",
            f"impl From<{name}> for bool {{", f"    fn from(value: {name}) -> Self {{",
            "        value.is_on()", "    }", "}", "",
            f"impl Default for {name} {{", BUILD_DEFAULT_DOC, "    fn default() -> Self {",
            "        Self::DEFAULT", "    }", "}", ""]
    return out


def policy_value_rust(pol: dict) -> list[str]:
    """One policy's `PolicyValue` impl, after its value type when it is a bool policy (a choice's
    enum is the one above): its values, the domain the build's environment allows, the build's
    default and where it is bound; the constant that refuses a build whose domain leaves out its
    default; and its `PolicyField` impl."""
    name = camel(pol["id"])
    values = policy_values(pol)
    out = bool_value_rust(pol) if pol["kind"] == "bool" else []
    out += rust_bound_alias(pol)
    out += [f"impl PolicyValue for {name} {{",
            f"    const POLICY: &'static str = {rust_word(pol['id'])};"]
    out += rust_const_slice("ALL", "&'static [Self]", [f"Self::{camel(v)}" for v in values])
    out += rust_const_slice("IDS", "&'static [&'static str]", [rust_word(v) for v in values])
    out += ["    const DOMAIN: Domain<Self> = Domain::from_stated(", "        &["]
    for value in values:
        out += rust_domain_entry(rust_word(policy_allows_symbol(pol, value)))
    out += ["        ],",
            "        Self::DEFAULT as usize,",
            "        DEFAULTS_ONLY,",
            "    );",
            "    const DEFAULT: Self = Self::stated();",
            f"    const SCOPE: Scope = Scope::{camel(pol['scope'])};",
            f"    const BINDING: Binding = Binding::{camel(pol['binding'])};",
            f"    const MUTABILITY: Mutability = Mutability::{camel(pol['mutability'])};",
            f"    const WIRE: Wire = Wire::{camel(pol['wire'])};"]
    if "boundary" in pol:
        out += rust_boundary(rust_text(pol["boundary"]))
    else:
        out.append("    const BOUNDARY: Option<&'static str> = None;")
    out += ["", "    fn index(self) -> usize {", "        self as usize", "    }", "}", ""]
    return out + rust_default_assert(name, pol["id"]) + policy_field_rust(pol)


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
    out += policy_env_cmake(decl, image)
    return "\n".join(out) + "\n"


def policy_env_cmake(decl: dict, image: str) -> list[str]:
    """`wz_axes_policy_env`: the `WZ_POLICY_<NAME>=<value>` of every policy of `image` whose
    Kconfig value is not upstream's, for the image's CMake to hand to `wz_zephyr_rust_app` as
    cargo environment, where `SessionPolicy` reads it. A value that is upstream's states nothing,
    as `resolved_policy_env` leaves it out, so an image that sets no policy builds as it did.
    A symbol the build's Kconfig does not have (its `depends on` does not hold) is not set in
    CMake, so its condition is false."""
    rows = image_policy_rows(decl, image)
    if not rows:
        return []
    out = ["", 'set(wz_axes_policy_env "")']
    for pol, _ in rows:
        if pol["kind"] == "bool":
            out += [f"if(CONFIG_{pol['kconfig']})",
                    f"  list(APPEND wz_axes_policy_env {pol['kconfig']}=on)", "endif()"]
            continue
        for value in pol["choices"]:
            if value != pol["default"]:
                symbol = f"{pol['kconfig']}_{snake(value).upper()}"
                out += [f"if(CONFIG_{symbol})",
                        f"  list(APPEND wz_axes_policy_env {pol['kconfig']}={value})", "endif()"]
    return out


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
        f"# {original}'s own default build in wz's switches (from upstream_on and upstream_off):",
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
        if cid in values and values[cid] != default_on(decl["caps"][cid], KCONFIG_ABI):
            out.append(f"CONFIG_{decl['caps'][cid]['kconfig']}={'y' if values[cid] else 'n'}")
    return "\n".join(out) + "\n"


GENERATED = {
    "kconfig-root": (KCONFIG_ROOT, emit_kconfig_root),
    "kconfig-capabilities": (KCONFIG_CAPS, emit_kconfig_capabilities),
    "kconfig-limits": (KCONFIG_LIMITS, emit_kconfig_limits),
    "rust-limits": (RUST_LIMITS, emit_rust_limits),
    "rust-limit-bindings": (RUST_LIMIT_BINDINGS, emit_rust_limit_bindings),
    "rust-limit-snapshots": (RUST_LIMIT_SNAPSHOTS, emit_rust_limit_snapshots),
    "rust-policies": (RUST_POLICIES, emit_rust_policies),
    "config-schema": (CONFIG_SCHEMA, emit_config_schema),
    "rust-feature-bits": (RUST_FEATURE_BITS, emit_rust_feature_bits),
    "rust-conformance-items": (RUST_CONFORMANCE_ITEMS, emit_rust_conformance_items),
    "statement-vectors": (STATEMENT_VECTORS, emit_statement_vectors),
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
        if image_policy_rows(decl, image):
            out[f"image-policies:{image}"] = (base / "Kconfig.policies", emit_image_policies(decl, image))
    return out


RSOURCE_RE = re.compile(r'^\s*rsource\s+"([^"]+)"', re.MULTILINE)


def check_image_sources(image: str, text: str, has_policies: bool = False) -> list[str]:
    """An image's Kconfig that sources the global axes sources the capabilities too: an option of a
    global axis selects capability symbols, and Zephyr refuses a select of a symbol the tree does
    not define. An image that reads policies sources its own `Kconfig.policies` and never the host
    tree's `../Kconfig.policies`, which names every policy and so offers the ones the image's code
    does not read."""
    sourced = set(RSOURCE_RE.findall(text))
    out = []
    if "../Kconfig.axes" in sourced and "../Kconfig.capabilities" not in sourced:
        out.append(f"{image}: its Kconfig sources ../Kconfig.axes but not ../Kconfig.capabilities, "
                   "whose symbols the global axes select")
    if "../Kconfig.policies" in sourced:
        out.append(f"{image}: its Kconfig sources ../Kconfig.policies, which names every policy; "
                   "an image's policies are its own Kconfig.policies (`[[policy_image]]`)")
    if has_policies and "Kconfig.policies" not in sourced:
        out.append(f"{image}: it reads policies (`[[policy_image]]`) but its Kconfig does not source "
                   "its own Kconfig.policies")
    return out


# ---------------------------------------------------------------------------------------------
# caps.rs and the manifests
# ---------------------------------------------------------------------------------------------

BINDING_RE = re.compile(
    r"^pub const (?P<name>[A-Z0-9_]+): usize =\s*generated::(?P<target>[A-Z0-9_]+);", re.MULTILINE
)
BARE_RE = re.compile(r"^pub const (?P<name>[A-Z0-9_]+): usize =\s*\d+;", re.MULTILINE)
STATED_RE = re.compile(r'option_env!\("WZ_LIMIT_')


def check_open_facilities_rs(decl: dict, text: str) -> list[str]:
    """The Rust derivation's `FACILITIES` is `OS_FACILITIES`, in order, and its `ENGINE` is
    `[os] always`: a word added here and not there would be a facility one side can name and the
    other cannot."""
    out = []
    for name, want in (("FACILITIES", list(OS_FACILITIES)), ("ENGINE", list(decl["os_always"]))):
        match = re.search(rf"const {name}: \[&str; (\d+)\] = \[(.*?)\];", text, re.S)
        if match is None:
            out.append(f"{OPEN_FACILITIES_RS.name}: no `const {name}: [&str; N]`")
            continue
        got = re.findall(r'"([^"]*)"', match.group(2))
        if int(match.group(1)) != len(got):
            out.append(f"{OPEN_FACILITIES_RS.name}: {name} declares {match.group(1)} items and lists {len(got)}")
        if (sorted(got) if name == "ENGINE" else got) != (sorted(want) if name == "ENGINE" else want):
            out.append(f"{OPEN_FACILITIES_RS.name}: {name} is {got}, the declaration's is {want}")
    return out


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


# The hand-written enums the generated rows name, each with the declaration's words it spells.
BINDING_ENUMS = (("Scope", SCOPES), ("Binding", BINDINGS), ("Mutability", MUTABILITIES),
                 ("Wire", WIRES), ("Storage", LIMIT_STORAGES), ("LimitKind", LIMIT_KINDS),
                 ("Driven", DRIVERS))


def check_policy_binding_rs(text: str) -> list[str]:
    """Each enum of `policy_binding.rs` that a generated row names has one variant per word of
    the declaration's vocabulary, in its order: a word added to the declaration and not there
    would be a row that names a variant the crate does not have."""
    out: list[str] = []
    for name, words in BINDING_ENUMS:
        match = re.search(rf"^pub enum {name} \{{\n(.*?)^\}}", text, re.S | re.M)
        if match is None:
            out.append(f"{POLICY_BINDING_RS.name}: no `pub enum {name}`")
            continue
        got = re.findall(r"^    ([A-Z][A-Za-z0-9]*),$", match.group(1), re.M)
        want = [camel(w) for w in words]
        if got != want:
            out.append(f"{POLICY_BINDING_RS.name}: {name} has the variants {got}, the "
                       f"declaration's words are {want}")
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


@functools.cache
def package_features(manifest: pathlib.Path) -> dict:
    """The `[features]` table of the package `manifest` names, which may be a workspace of its own
    (an image under `deploy/`): asked of cargo, as [`workspace_features`] does, for the same reason."""
    proc = subprocess.run(
        ["cargo", "metadata", "--no-deps", "--format-version", "1", "--offline",
         "--manifest-path", str(manifest)],
        capture_output=True,
        text=True,
    )
    if proc.returncode != 0:
        raise OSError(f"`cargo metadata` of {manifest} failed: {proc.stderr.strip()}")
    wanted = manifest.resolve()
    for package in json.loads(proc.stdout)["packages"]:
        if pathlib.Path(package["manifest_path"]).resolve() == wanted:
            return package["features"]
    raise KeyError(f"{manifest} names no package of its workspace")


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
    want = set(decl["base"][abi]) | {cid for cid in mine if default_on(caps[cid], abi)}
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
    defconfig is merged first, before any preset, so a preset says only how it differs from that
    original. Presets of two originals are one build of neither and are
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


def resolved_policy_domain(kconf, pol: dict) -> list[str]:
    """The values of `pol` a configuration leaves selectable after the build: those whose
    allowance (`policy_domain_kconfig`) is `y`."""
    return [value for value in policy_values(pol)
            if kconf.syms[policy_allows_symbol(pol, value)].tri_value == 2]


def resolved_policy_env(decl: dict, kconf) -> list[str]:
    """`WZ_POLICY_<NAME>=<value>` for every policy the configuration sets off upstream's, each
    followed by `WZ_POLICY_<NAME>_ALLOWS_<VALUE>=off` for every value the configuration leaves out
    of its domain and `=on` for every other value a fragment assigns its allowance, so a
    configuration that narrows nothing states no allowance. An assigned `on` is what keeps a value
    on a target with no operating system, where an unstated allowance keeps the default alone
    (`policy_defaults_only`); the default's own allowance has no prompt and is never assigned. A
    domain without the policy's value is refused, as the build would refuse it on either target."""
    out: list[str] = []
    for pol in decl["policies"]:
        value = resolved_policy(kconf, pol)
        env = {} if value == pol["default"] else {pol["kconfig"]: value}
        domain = resolved_policy_domain(kconf, pol)
        for v in policy_values(pol):
            symbol = policy_allows_symbol(pol, v)
            if v not in domain:
                env[symbol] = "off"
            elif v != value and kconf.syms[symbol].user_value == 2:
                env[symbol] = "on"
        try:
            policy_domain(pol, env)
            policy_domain(pol, env, no_os=True)
        except ValueError as exc:
            raise PresetError(str(exc)) from exc
        out += [f"{name}={text}" for name, text in env.items()]
    return out


# The conformance statement of one build, in the
# sense of an implementation conformance statement (ISO/IEC 9646-7): what the build exports and
# the value of every limit and policy it was built with, in the declaration's vocabulary, so
# that whoever tests the build reads what it is from the build's own configuration instead of
# from a hand-kept copy that can disagree with it.
STATEMENT_FORMAT = "wz-conformance-statement"
# 2 (2026-11-07): `arm`, the layout switches that are not capabilities, joined the identity; a
# version-1 digest could not tell two zenoh-c drop-ins of different type layouts apart.
# 3 (2026-11-14): `engine` and `platform` joined the identity; a version-2 digest could not tell
# a pico build on the tokio engine from one on the cooperative engine, or a host library from a
# Zephyr one, when their capabilities were the same, and those builds run differently.
STATEMENT_FORMAT_VERSION = 3

# The features of the pico ABI's crate that run its sessions on the cooperative engine
# (docs/capi-pico-on-coop-engine.md): `engine-coop` on a host, `os-zephyr` in a Zephyr image. A
# build that names neither runs them on the tokio engine, and so does every build of the other
# ABIs, whose crates have no other engine.
STATEMENT_COOP_FEATURES = ("engine-coop", "os-zephyr")
# The features that build a library for a platform other than a host, each with the platform's
# word in the statement; a build that names none is a host's.
STATEMENT_PLATFORM_FEATURES = (("os-zephyr", "zephyr"),)


def statement_engine(abi: str, have: set[str]) -> str:
    """The engine a build of `abi` with the features `have` runs its sessions on: the pico
    crate's rule, the tokio engine whenever it is in the build, else the cooperative one when a
    feature selects it."""
    if (abi == "pico" and "engine-tokio" not in have
            and any(f in have for f in STATEMENT_COOP_FEATURES)):
        return "coop"
    return "tokio"


def statement_platform(abi: str, have: set[str]) -> str:
    """The platform a build of `abi` with the features `have` is a library for."""
    if abi == "pico":
        for feature, platform in STATEMENT_PLATFORM_FEATURES:
            if feature in have:
                return platform
    return "host"


def arm_switches(decl: dict, abi: str) -> list[str]:
    """The features of `abi`'s crate that select which arm of its C type layouts the library is,
    and are not capabilities: the zenoh-c rows that a header macro selects (`drop_in_arm`). They
    change the size of the types a program allocates, so a build is not stated without them.
    Every layout switch of the pico ABI is a capability (`multi-thread`, `unstable-api`, the
    local planes), so its list is empty, and so is the core's."""
    if abi != "c":
        return []
    return [row["anchor"].removeprefix(ZENOH_C_DROP_IN) for row in decl["switches"]
            if row.get("original") == "zenoh-c" and "macro" in row]


def conformance_statement(decl: dict, abi: str, features: list[str], limits: dict[str, int],
                          policies: dict[str, str], derived_from: dict) -> dict:
    """The conformance statement of a build of `abi` whose cargo features are `features`.

    A capability is supported when its feature is in the list, so a list that a later step has
    changed (the cooperative engine's, which leaves out what selects the tokio engine) states
    what that build has, not what its configuration asked for. Every capability the ABI exports
    is listed, supported or not, every layout switch of the ABI (`arm_switches`) on or off,
    every limit with its value and every policy with its value: a statement that left out what
    is off could not be told from one that never asked.

    `digest` identifies the build by what it states: the ABI, the catalogue and every value, and
    nothing of where they were read from, so two routes to the same build give the same digest
    and a build that differs in one value gives another.
    """
    have = set(features)
    body = {
        "format": STATEMENT_FORMAT,
        "format_version": STATEMENT_FORMAT_VERSION,
        "catalog_version": decl["catalog_version"],
        "abi": abi,
        "engine": statement_engine(abi, have),
        "platform": statement_platform(abi, have),
        "arm": [{"id": switch, "on": switch in have} for switch in arm_switches(decl, abi)],
        "capabilities": [{"id": cid, "supported": cid in have} for cid in decl["order"]
                         if abi in decl["caps"][cid]["abis"]],
        "limits": [{"id": lim["id"], "value": limits[lim["id"]], "default": lim["default"]}
                   for lim in decl["limits"]],
        "policies": [{"id": pol["id"], "value": policies[pol["id"]], "upstream": pol["default"]}
                     for pol in decl["policies"]],
    }
    # The ABI's protocol facts: fixed by the ABI and the catalogue version, which the digest
    # already covers, so they are stated beside the body and left out of what is hashed.
    facts = [{"id": f["id"], "value": f[abi]} for f in decl.get("facts", []) if abi in f]
    return {**body, "facts": facts, "derived_from": derived_from,
            "digest": statement_digest(body)}


def policy_values(pol: dict) -> list[str]:
    """The values a policy may take: its choices, or `off` and `on` for a bool."""
    return list(pol["choices"]) if pol["kind"] == "choice" else ["off", "on"]


def env_statement(decl: dict, abi: str, features: list[str], env: dict[str, str],
                  derived_from: dict) -> dict:
    """The conformance statement of a cargo build of `abi` with `features` on, run in an
    environment that states `env`: each limit by its `WZ_LIMIT_*` there and each policy by its
    `WZ_POLICY_*`, else the limit's default and upstream's policy. It is the build
    `wz-conformance-build` states from inside the build script, and it refuses what that refuses:
    a limit that is not decimal digits or exceeds 64 bits, and a policy value outside its choices.
    It also refuses a name the declaration does not read. Both sides would ignore such a name, so
    a case built to state it would state nothing."""
    limits = {lim["kconfig"]: lim for lim in decl["limits"]}
    policies = {pol["kconfig"]: pol for pol in decl["policies"]}
    unknown = sorted(set(env) - limits.keys() - policies.keys())
    if unknown:
        raise ValueError(f"{', '.join(unknown)}: not a limit or policy the declaration reads")
    for name, text in env.items():
        if name in limits and not (text.isascii() and text.isdigit() and int(text) < 1 << 64):
            raise ValueError(f"a WZ_LIMIT_* value is not a 64-bit decimal number ({name}={text})")
        if name in policies and text not in policy_values(policies[name]):
            raise ValueError(f"a WZ_POLICY_* value is not one of its policy's choices ({name}={text}; "
                             f"{policy_values(policies[name])})")
    return conformance_statement(
        decl, abi, features,
        {lim["id"]: int(env.get(lim["kconfig"], lim["default"])) for lim in decl["limits"]},
        {pol["id"]: env.get(pol["kconfig"], pol["default"]) for pol in decl["policies"]},
        derived_from)


def statement_digest(body: dict) -> str:
    """SHA-256 over the canonical JSON of what a statement says the build is: its format, ABI,
    catalogue, each layout switch's state, and each capability's support and each limit's and
    policy's value. The defaults beside the values are the catalogue's, which `catalog_version`
    already names."""
    identity = {
        "format": body["format"],
        "format_version": body["format_version"],
        "catalog_version": body["catalog_version"],
        "abi": body["abi"],
        "engine": body["engine"],
        "platform": body["platform"],
        "arm": [[a["id"], a["on"]] for a in body["arm"]],
        "capabilities": [[c["id"], c["supported"]] for c in body["capabilities"]],
        "limits": [[x["id"], x["value"]] for x in body["limits"]],
        "policies": [[p["id"], p["value"]] for p in body["policies"]],
    }
    canonical = json.dumps(identity, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    return "sha256:" + hashlib.sha256(canonical.encode("ascii")).hexdigest()


def resolved_statement(decl: dict, abi: str, kconf, derived_from: dict) -> dict:
    """The conformance statement of the `abi` build a resolved configuration gives."""
    return conformance_statement(
        decl, abi, features_for(decl, abi, resolved_caps(decl, kconf)),
        {lim["id"]: int(kconf.syms[lim["kconfig"]].str_value) for lim in decl["limits"]},
        {pol["id"]: resolved_policy(kconf, pol) for pol in decl["policies"]},
        derived_from)


def zenoh_c_header_statement(decl: dict, text: str, name: str) -> dict:
    """The conformance statement of the zenoh-c drop-in a program compiled against an installed
    zenoh-c's `zenoh_configure.h` links: `wz-capi-c`'s default build with the arm the header
    selects added (`drop_in_arm`, the build `--drop-in-features c` describes). A link or a
    handshake zenoh-c was built without moves no type, so the drop-in keeps its own defaults for
    them and the statement says so; the header states no limit and no policy, so each is the
    catalogue's default and upstream's."""
    default = {cid for cid, cap in decl["caps"].items() if default_on(cap, "c")}
    return conformance_statement(
        decl, "c", features_for(decl, "c", default) + drop_in_arm(decl, text),
        {lim["id"]: lim["default"] for lim in decl["limits"]},
        {pol["id"]: pol["default"] for pol in decl["policies"]},
        {"kind": "zenoh-c-header", "inputs": [name]})


def pico_header_statement(decl: dict, text: str, macros: dict[str, str], name: str,
                          engine_features: dict | None = None) -> tuple[dict | None, list[str]]:
    """The conformance statement of the pico drop-in a zenoh-pico `config.h` gives (the build the
    `--features pico` and `--env pico` modes describe together), and the problems.

    The header states no policy, so every policy is upstream's, which is what that build runs.
    `engine_features`, the pico crate's feature table, makes it the cooperative engine's build.
    A Kconfig result is refused: this reads the header's own switches, and a `.config` states
    its numbers through symbols this mode does not read."""
    if any(CONFIG_RE.match(line) or re.match(r"^\s*#\s*CONFIG_WZ_", line)
           for line in text.splitlines()):
        return None, [f"{name} is a Kconfig result; the statement of a build given by presets is "
                      "--resolve-conformance-statement's"]
    problems = pico_header_conflicts(decl, "pico", text)
    limits, value_problems = pico_limit_values(decl, text, macros)
    problems += value_problems
    if problems:
        return None, problems
    features = features_for(decl, "pico", read_config(decl, text))
    engine = "tokio"
    if engine_features is not None:
        features = coop_features(features, engine_features)
        engine = "coop"
    derived = {"kind": "pico-header", "inputs": [name], "engine": engine}
    return conformance_statement(decl, "pico", features, limits,
                                 {pol["id"]: pol["default"] for pol in decl["policies"]},
                                 derived), []


def print_statement(doc: dict) -> None:
    sys.stdout.write(json.dumps(doc, indent=2, ensure_ascii=False) + "\n")


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
            findings += check_image_sources(image, kconfig.read_text(encoding="utf-8"),
                                            bool(image_policy_rows(decl, image)))
        own_policies = ROOT / decl["image_dirs"][image] / "Kconfig.policies"
        if f"image-policies:{image}" not in files and own_policies.exists():
            findings.append(f"{own_policies.relative_to(ROOT)} exists, but the declaration names no "
                            f"policy for image {image}: remove it")
    findings += check_caps_rs(decl, CAPS_RS.read_text(encoding="utf-8"))
    findings += check_policy_binding_rs(POLICY_BINDING_RS.read_text(encoding="utf-8"))
    findings += check_open_facilities_rs(decl, OPEN_FACILITIES_RS.read_text(encoding="utf-8"))
    for abi, path in MANIFESTS.items():
        try:
            feats = manifest_features(path)
        except (KeyError, OSError) as exc:
            print(f"  wz-config FAIL: {abi}: {exc}", file=sys.stderr)
            return 1
        findings += check_manifest(decl, abi, feats)
    # The platform rows against the compiler that builds for them. A compiler that is absent is a
    # finding and not a skip: a gate that cannot reach its input must not report green.
    for assessed in decl["assessed_packages"]:
        package = assessed["package"]
        try:
            manifest_names = set(manifest_features(ROOT / "crates" / package / "Cargo.toml"))
        except (KeyError, OSError) as exc:
            findings.append(f"{package}: {exc}")
            continue
        findings += package_feature_findings(
            {"package_features": [r for r in decl["package_features"] if r["package"] == package]},
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
always = ["threads", "entropy"]

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

[[assessed_package]]
package = "wz-runtime-tokio"
by_feature = true
os_needs = []
help = "A sample package, assessed by feature."

[[assessed_package]]
package = "wz-app"
by_feature = false
os_needs = ["wall-clock"]
help = "A sample package, assessed whole."

[[package_feature]]
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
kind = "bound"
driven = "remote"
on_heap = "advisory"
storage = "both"
scope = "session"
binding_heap = "open"
binding_fixed = "build"
wire = "none"
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
scope = "link"
binding = "live"
mutability = "quiescent"
boundary = "the next time the link opens"
wire = "visible"
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
scope = "session"
binding = "open"
mutability = "fixed"
wire = "timing"
since = 3
help = '''
Flush early.
'''
"""


# Two profiles over POLICY_SAMPLE; the upstream one lists its values out of the declaration's
# order, which the generated table does not follow.
PROFILE_SAMPLE = """\

[[profile]]
id = "upstream"
help = '''
Every policy at upstream's behaviour.
'''

[profile.policies]
eager-flush = "off"
wire-mode = "os-default"

[[profile]]
id = "quiet"
help = '''
Flush early, wire left alone.
'''

[profile.policies]
eager-flush = "on"
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
    template = ('#cmakedefine ZP_SYSTEM_PLATFORM_HEADER "@ZP_SYSTEM_PLATFORM_HEADER@"\n'
                "#define Z_BATCH_MULTICAST_SIZE @BATCH_MULTICAST_SIZE@\n"
                "#define Z_TRANSPORT_LEASE @Z_TRANSPORT_LEASE@\n"
                "#define Z_FEATURE_QUERY @Z_FEATURE_QUERY@\n#define Z_SN_RESOLUTION 0x02\n")
    expect("a config template's value switches are its @NAME@ lines other than Z_FEATURE_*",
           pico_value_macros(template) == {"ZP_SYSTEM_PLATFORM_HEADER": "ZP_SYSTEM_PLATFORM_HEADER",
                                           "BATCH_MULTICAST_SIZE": "Z_BATCH_MULTICAST_SIZE",
                                           "Z_TRANSPORT_LEASE": "Z_TRANSPORT_LEASE"})
    value_decl = {"limits": [{"id": "MCAST", "default": 2048}, {"id": "LEASE", "default": 10000}],
                  "switches": [{"original": "zenoh-pico", "switch": "BATCH_MULTICAST_SIZE",
                                "class": "maps", "anchor": "limit:MCAST"},
                               {"original": "zenoh-pico", "switch": "Z_TRANSPORT_LEASE",
                                "class": "maps", "anchor": "limit:LEASE"},
                               {"original": "zenoh-pico", "switch": "Z_FEATURE_QUERY",
                                "class": "maps", "anchor": "wz-capi-pico/query"}]}
    macros = pico_value_macros(template)
    expect("a header's value differing from the limit's default becomes its WZ_LIMIT line",
           pico_value_env(value_decl, "#define Z_BATCH_MULTICAST_SIZE 1024\n"
                                      "#define Z_TRANSPORT_LEASE 10000\n", macros)
           == (["WZ_LIMIT_MCAST=1024"], []))
    expect("a hexadecimal value reads as its number and a header silent on a switch states nothing",
           pico_value_env(value_decl, "#define Z_BATCH_MULTICAST_SIZE 0x400\n", macros)
           == (["WZ_LIMIT_MCAST=1024"], []))
    expect("a value macro defined to something that is not a number is a problem, not a default",
           pico_value_env(value_decl, "#define Z_TRANSPORT_LEASE LEASE_MS\n", macros)[1] != [])
    expect("a value row whose switch the template does not carry is a problem",
           pico_value_env(value_decl, "", {})[1] != [])
    expect("only a zenoh-pico maps row anchors to a limit, and only to a declared one",
           validate_switches({"limit": [{"id": "MCAST"}], "upstream_switch": [
               {"original": "zenoh-pico", "switch": "BATCH_MULTICAST_SIZE", "class": "maps",
                "anchor": "limit:MCAST", "note": "x"}]}) == []
           and validate_switches({"limit": [], "upstream_switch": [
               {"original": "zenoh-pico", "switch": "BATCH_MULTICAST_SIZE", "class": "maps",
                "anchor": "limit:MCAST", "note": "x"}]}) != []
           and validate_switches({"limit": [{"id": "MCAST"}], "upstream_switch": [
               {"original": "zenoh-c", "switch": "batch", "class": "maps",
                "anchor": "limit:MCAST", "note": "x"}]}) != [])
    expect("a value switch is no switch of the pico reference build",
           all(s.startswith("Z_FEATURE_") for s in pico_reference(decl, set())))
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
    # --pico-config-h: a value outside a #cmakedefine with nothing to render is refused; a
    # #cmakedefine without one is CMake's #undef; a limit the environment states is the value.
    try:
        render_pico_config("#define A @A@\n", {})
        expect("a template value with no value is refused", False)
    except ValueError:
        pass
    expect("a #cmakedefine with no value renders as its #undef",
           render_pico_config('#cmakedefine P "@P@"\n#define A @A@\n', {"A": "1"})
           == '/* #undef P */\n#define A 1\n')
    stated_limits = limit_rows(decl)
    if stated_limits:
        switch0, lid0 = stated_limits[0]
        expect("a limit the environment states is its value switch's value",
               pico_config_values(decl, set(), {switch0: "1"}, {f"WZ_LIMIT_{lid0}": "7"})[switch0] == "7"
               and pico_config_values(decl, set(), {switch0: "1"}, {})[switch0] == "1")
    # The round trip, on the pinned template and the real manifest: the header of a build reads
    # back, through `--features pico` (`--engine coop` for a cooperative one), as a build with the
    # same header-stated capabilities, and the build's arm switches are what it was built with.
    pico_table = manifest_features(MANIFESTS["pico"])
    header_caps = pico_header_features(decl)
    for engine, asked in (("tokio", []), ("tokio", ["app-transport", "e2e-sender", "local-subscriber"]),
                          ("coop", ["query", "queryable"]), ("coop", ["peer", "multi-thread", "liveliness"])):
        label = f"{engine} {','.join(asked) or 'defaults'}"
        enabled = pico_build_features(engine, asked, pico_table)
        try:
            rendered = pico_config_header(decl, enabled, {})
        except (OSError, ValueError) as exc:
            expect(f"the header of the {label} build renders ({exc})", False)
            continue
        expect(f"the header of the {label} build states no capability against another",
               pico_header_conflicts(decl, "pico", rendered) == [])
        back = features_for(decl, "pico", read_config(decl, rendered))
        if engine == "coop":
            back = coop_features(back, pico_table)
        expect(f"the header of the {label} build reads back as that build",
               enabled_features(pico_table, back) & header_caps == enabled & header_caps)
        flags_on, flags_off = pico_flag_states(rendered)
        expect(f"the header of the {label} build states its threading arm and the unstable API",
               ("Z_FEATURE_MULTI_THREAD" in flags_on) == ("multi-thread" in enabled)
               and ("Z_FEATURE_UNSTABLE_API" in flags_on) == ("unstable-api" in enabled)
               and "Z_FEATURE_UNSTABLE_API" in flags_on | flags_off)
        if engine == "tokio" and not asked:
            # The defect this mode exists for: the vendored library installs pico's default arm,
            # which has no unstable API, under a library whose default build has it.
            expect("the default build's header has the unstable API and the advanced plane",
                   {"Z_FEATURE_UNSTABLE_API", "Z_FEATURE_ADVANCED_PUBLICATION"} <= flags_on)
    try:
        pico_build_features("tokio", ["no-such-feature"], pico_table)
        expect("a feature the pico crate lacks is refused", False)
    except KeyError:
        pass
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
    # The cooperative list is the arm's with the engine changed: the base's tokio features and a
    # capability that selects the tokio engine (the multicast group) are out, what the engines
    # share stays, and the engine is named first.
    arm = features_for(decl, "pico", {"peer", "query", "multicast-transport"})
    coop = coop_features(arm, good)
    expect("the cooperative list names its engine first and not the tokio one",
           coop[0] == "engine-coop" and "engine-tokio" not in coop)
    expect("the cooperative list drops what selects the tokio engine",
           not {"serial-drive-own-thread", "rx-busy-poll", "multicast-transport"} & set(coop))
    expect("the cooperative list keeps what the engines share",
           {"link-udp", "scout", "peer", "query"} <= set(coop))
    tokio_selecting = dict(good)
    tokio_selecting["query"] = list(good["query"]) + ["engine-tokio"]
    expect("a capability that later selects the tokio engine leaves the list by itself",
           "query" not in coop_features(arm, tokio_selecting))
    # The conformance statement (decision C15) states the build the feature list makes, every
    # capability of the ABI on or off, every limit and policy, and a digest of only those values.
    defaults = {lim["id"]: lim["default"] for lim in decl["limits"]}
    upstream = {pol["id"]: pol["default"] for pol in decl["policies"]}
    stated = conformance_statement(decl, "pico", arm, defaults, upstream, {"kind": "test"})
    pico_caps = [cid for cid in decl["order"] if "pico" in caps[cid]["abis"]]
    expect("a statement lists every capability of its ABI, the off ones too, in declared order",
           [c["id"] for c in stated["capabilities"]] == pico_caps
           and {c["id"] for c in stated["capabilities"] if c["supported"]} == set(arm) & set(pico_caps)
           and any(not c["supported"] for c in stated["capabilities"]))
    expect("a statement lists every limit and every policy with its value",
           [x["id"] for x in stated["limits"]] == [lim["id"] for lim in decl["limits"]]
           and [p["id"] for p in stated["policies"]] == [pol["id"] for pol in decl["policies"]])
    moved = dict(decl, facts=[dict(f, pico="moved") for f in decl.get("facts", []) if "pico" in f])
    expect("a statement lists its ABI's protocol facts, and they are outside the digest",
           [f["id"] for f in stated["facts"]] == [f["id"] for f in decl.get("facts", []) if "pico" in f]
           and conformance_statement(moved, "pico", arm, defaults, upstream, {"kind": "test"})["digest"]
           == stated["digest"])
    expect("a protocol fact without a value, or without a file that holds it, is refused",
           len(validate_facts([{"id": "x", "help": "h"}])) == 2
           and len(validate_facts([{"id": "x", "pico": "1", "holds": ["a/b"], "help": "h"}])) == 1
           and len(validate_facts([{"id": "x", "pico": "1", "lacks": ["/a @ t"], "help": "h"}])) == 1
           and not validate_facts([{"id": "x", "pico": "1", "holds": ["a/b @ n"],
                                    "lacks": ["a/c @ m"], "help": "h"}]))
    expect("a statement of the cooperative build states what that build has, not what was asked",
           {c["id"]: c["supported"] for c in conformance_statement(
               decl, "pico", coop, defaults, upstream, {"kind": "test"})["capabilities"]}
           ["multicast-transport"] is False
           and {c["id"]: c["supported"] for c in stated["capabilities"]}["multicast-transport"])
    expect("the digest does not depend on where the values were read from",
           conformance_statement(decl, "pico", arm, defaults, upstream, {"kind": "other"})["digest"]
           == stated["digest"] and stated["digest"].startswith("sha256:"))
    one_off = dict(defaults)
    one_off[decl["limits"][0]["id"]] += 1
    flipped = dict(upstream)
    if decl["policies"]:
        pol0 = decl["policies"][0]
        flipped[pol0["id"]] = next(v for v in pol0.get("choices", ["on", "off"]) if v != pol0["default"])
    expect("a build that differs in one limit, one policy or one capability has another digest",
           conformance_statement(decl, "pico", arm, one_off, upstream, {})["digest"] != stated["digest"]
           and (not decl["policies"] or conformance_statement(
               decl, "pico", arm, defaults, flipped, {})["digest"] != stated["digest"])
           and conformance_statement(decl, "pico", arm[:-1], defaults, upstream, {})["digest"]
           != stated["digest"])
    # The build script's digest form (wz-conformance-build, `the_fixture_has_the_canonical_form_
    # and_digest_wz_config_gives_it`) asserts this same value of this same fixture: the two
    # writers of the canonical form cannot drift apart unseen.
    fixture = {"format": STATEMENT_FORMAT, "format_version": 1, "catalog_version": 7, "abi": "pico",
               "engine": "tokio", "platform": "host",
               "arm": [{"id": "x-arm", "on": True}],
               "capabilities": [{"id": "a-cap", "supported": True}, {"id": "b-cap", "supported": False}],
               "limits": [{"id": "L_ONE", "value": 256}, {"id": "L_TWO", "value": 0}],
               "policies": [{"id": "p-one", "value": "on"}, {"id": "p-two", "value": "os-default"}]}
    expect("the build script's digest form gives the fixture the digest this one does",
           statement_digest(fixture)
           == "sha256:1504af20a23a543a7613580140ff56e39f4f6324c8f15588f62ebc5d245da4bf")
    on_coop = conformance_statement(decl, "pico", coop, defaults, upstream, {})
    same_on_tokio = conformance_statement(
        decl, "pico", ["engine-tokio"] + [f for f in coop if f != "engine-coop"], defaults,
        upstream, {})
    on_zephyr = conformance_statement(
        decl, "pico", ["os-zephyr"] + [f for f in coop if f != "engine-coop"], defaults,
        upstream, {})
    expect("a statement names its engine and platform, and each moves the digest alone",
           stated["engine"] == "tokio" and stated["platform"] == "host"
           and on_coop["engine"] == "coop" and same_on_tokio["engine"] == "tokio"
           and on_coop["capabilities"] == same_on_tokio["capabilities"]
           and on_coop["digest"] != same_on_tokio["digest"]
           and on_zephyr["engine"] == "coop" and on_zephyr["platform"] == "zephyr"
           and on_zephyr["digest"] != on_coop["digest"]
           and conformance_statement(decl, "c", ["engine-coop", "os-zephyr"], defaults,
                                     upstream, {})["engine"] == "tokio")
    # The zenoh-c drop-in (decision C15, step 15c): the arm its header selects is in the statement
    # and in the digest, and nothing else of the header is read.
    c_arm = arm_switches(decl, "c")
    shm_row = next(r for r in decl["switches"] if r.get("original") == "zenoh-c"
                   and r.get("macro") == "Z_FEATURE_SHARED_MEMORY")
    plain = zenoh_c_header_statement(decl, "", "zenoh_configure.h")
    shm = zenoh_c_header_statement(decl, "#define Z_FEATURE_SHARED_MEMORY\n", "zenoh_configure.h")
    expect("the zenoh-c ABI states its layout arm and the pico ABI has none",
           c_arm and arm_switches(decl, "pico") == [] and arm_switches(decl, "core") == []
           and [a["id"] for a in plain["arm"]] == c_arm and stated["arm"] == [])
    expect("a zenoh_configure.h that defines shared memory states that arm and another digest",
           {a["id"]: a["on"] for a in shm["arm"]}[shm_row["anchor"].removeprefix(ZENOH_C_DROP_IN)]
           and not {a["id"]: a["on"] for a in plain["arm"]}[
               shm_row["anchor"].removeprefix(ZENOH_C_DROP_IN)]
           and shm["digest"] != plain["digest"]
           and shm["capabilities"] == plain["capabilities"])
    expect("the zenoh-c header's statement is the default build's, its arm added",
           {c["id"] for c in plain["capabilities"] if c["supported"]}
           == set(features_for(decl, "c", {cid for cid, cap in caps.items() if default_on(cap, "c")}))
           & {cid for cid in decl["order"] if "c" in caps[cid]["abis"]}
           and all(x["value"] == x["default"] for x in plain["limits"])
           and plain["derived_from"] == {"kind": "zenoh-c-header", "inputs": ["zenoh_configure.h"]})
    items = emit_rust_conformance_items(decl)
    expect("the build script's questions are every capability, limit and policy of the declaration",
           all(f'("{cid}", ' in items or f'        "{cid}",' in items for cid in decl["order"])
           and all(f'"{lim["kconfig"]}"' in items for lim in decl["limits"])
           and all(f'"{pol["kconfig"]}"' in items for pol in decl["policies"]))
    expect("a word that would need escaping is refused, never escaped",
           not _refuses_word("a-cap") and _refuses_word('a"cap') and _refuses_word("a cap"))
    # The vectors the build script's test reproduces (decision C15): the environment is read as the
    # build script reads it, and the file reaches every axis of the declaration.
    lim0, pol0 = decl["limits"][0], decl["policies"][0]
    other0 = next(v for v in policy_values(pol0) if v != pol0["default"])
    from_env = env_statement(decl, "pico", arm, {lim0["kconfig"]: str(lim0["default"] + 1),
                                                pol0["kconfig"]: other0}, {})
    expect("a build's environment states its limits and policies, and stating a default is "
           "stating nothing",
           {x["id"]: x["value"] for x in from_env["limits"]}[lim0["id"]] == lim0["default"] + 1
           and {p["id"]: p["value"] for p in from_env["policies"]}[pol0["id"]] == other0
           and env_statement(decl, "pico", arm, {lim0["kconfig"]: str(lim0["default"])},
                             {})["digest"] == stated["digest"])
    expect("an environment the build script would refuse is refused: a misspelt name, a limit "
           "that is not decimal or exceeds 64 bits, a policy outside its choices",
           all(_refuses_env(decl, env) for env in (
               {"WZ_LIMIT_NO_SUCH_LIMIT": "1"}, {lim0["kconfig"]: "0x10"}, {lim0["kconfig"]: ""},
               {lim0["kconfig"]: str(1 << 64)}, {pol0["kconfig"]: "maybe"}))
           and not _refuses_env(decl, {lim0["kconfig"]: str((1 << 64) - 1)}))
    vectors = statement_vectors(decl)
    alone = {(v["abi"], v["features"][0]) for v in vectors
             if v["case"].endswith(" alone") and len(v["features"]) == 1}
    stated_env = {(name, value) for v in vectors for name, value in v["env"].items()}
    expect("the statement vectors reach each capability and layout switch of each ABI, each limit "
           "off its default and each policy value",
           all((abi, name) in alone for abi in ABIS
               for name in arm_switches(decl, abi)
               + [cid for cid in decl["order"] if abi in caps[cid]["abis"]])
           and all(any(name == lim["kconfig"] and value != str(lim["default"])
                       for name, value in stated_env) for lim in decl["limits"])
           and all((pol["kconfig"], value) in stated_env
                   for pol in decl["policies"] for value in policy_values(pol)))
    # Three kinds of case state a build another case already states, on purpose: every limit and
    # policy at its default is the build that states nothing; every name of every ABI is every
    # name of the ABI (the other ABIs' names count for nothing); and the tokio engine beside a
    # cooperative feature is the tokio engine, whose build with nothing else is the one that
    # states nothing (`statement_engine`). They are left out of the count of distinct digests and
    # held to equal their twin instead, so a change of the engine rule turns one of them red.
    same_as = {"every limit and policy stated at its default": "nothing stated",
               "every name of every ABI on": "every name of the ABI on",
               "the tokio engine beside a cooperative feature": "nothing stated"}
    by_case = {(v["abi"], v["case"]): v["digest"] for v in vectors}
    twins = [(abi, case, twin) for (abi, case) in by_case for c, twin in same_as.items()
             if case == c]
    expect("the statement vectors are the same on every run and every digest is distinct where "
           "the build differs",
           emit_statement_vectors(decl) == emit_statement_vectors(decl)
           and len({v["digest"] for v in vectors if v["case"] not in same_as})
           == len(vectors) - len(twins))
    expect("each vector that states a build another states has that build's digest",
           len(twins) == 2 * len(ABIS) + 1
           and all(by_case[(abi, case)] == by_case[(abi, twin)] for abi, case, twin in twins))
    expect("the cooperative engine and the zephyr platform each state a build of their own",
           len({by_case[("pico", "nothing stated")], by_case[("pico", "the cooperative engine")],
                by_case[("pico", "the zephyr platform")]}) == 3)
    expect("a statement's digest does not count the catalogue's defaults beside the values",
           statement_digest({**stated, "limits": [{**x, "default": 0} for x in stated["limits"]]})
           == stated["digest"])
    rows = limit_rows(decl)
    identity_macros = {switch: switch for switch, _ in rows}
    if rows:
        switch0, lid0 = rows[0]
        from_header, problems = pico_header_statement(
            decl, f"#define {switch0} {defaults[lid0] + 1}\n#define Z_FEATURE_QUERY 1\n",
            identity_macros, "config.h")
        expect("a pico header's statement takes the header's numbers and switches, and upstream's "
               "policies",
               problems == [] and from_header is not None
               and {x["id"]: x["value"] for x in from_header["limits"]}[lid0] == defaults[lid0] + 1
               and {c["id"]: c["supported"] for c in from_header["capabilities"]}["query"]
               and all(p["value"] == p["upstream"] for p in from_header["policies"])
               and from_header["derived_from"] == {"kind": "pico-header", "inputs": ["config.h"],
                                                   "engine": "tokio"})
    expect("a Kconfig result is not read as a pico header",
           pico_header_statement(decl, "CONFIG_WZ_CAP_QUERY=y\n", identity_macros, ".config")[0]
           is None)
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
    # Where a policy is bound.
    quiescent = 'mutability = "quiescent"\nboundary = "the next time the link opens"\n'
    expect("a policy that states no `wire` is refused",
           policy_refused('wire = "timing"\n', "", "states no `wire`"))
    expect("a policy that states no `binding` is refused",
           policy_refused('binding = "open"\n', "", "states no `binding`"))
    expect("a policy scope outside the scopes is refused",
           policy_refused('scope = "session"\nbinding', 'scope = "galaxy"\nbinding',
                          "policy `eager-flush`: `scope` is 'galaxy', one of runtime"))
    expect("a policy binding outside the stages is refused",
           policy_refused('binding = "open"', 'binding = "later"', "`binding` is 'later', one of build"))
    expect("a policy wire outside its set is refused",
           policy_refused('wire = "timing"', 'wire = "loud"', "`wire` is 'loud', one of none"))
    expect("a policy decided at the open that changes while running is refused",
           policy_refused('mutability = "fixed"', 'mutability = "hot"', "so its `mutability` is 'fixed'"))
    expect("a policy decided at the build that waits for a boundary is refused",
           policy_refused('binding = "open"\nmutability = "fixed"\n',
                          'binding = "build"\n' + quiescent, "so its `mutability` is 'fixed'"))
    expect("a live policy that is fixed is refused",
           policy_refused(quiescent, 'mutability = "fixed"\n', "not 'fixed'"))
    expect("a boundary on a policy that is not quiescent is refused",
           policy_refused('mutability = "fixed"\n', 'mutability = "fixed"\nboundary = "never"\n',
                          "only by a 'quiescent' policy"))
    expect("a boundary on a hot policy is refused",
           policy_refused(quiescent, 'mutability = "hot"\nboundary = "never"\n',
                          "only by a 'quiescent' policy"))
    expect("a quiescent policy without its boundary is refused",
           policy_refused('boundary = "the next time the link opens"\n', "", "states its `boundary`"))
    expect("a live policy that changes at once, with no boundary, validates",
           validate_decl(read_decl_toml(with_policy.replace(quiescent, 'mutability = "hot"\n'))) == [])
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
           "impl Default for WireMode {\n" + BUILD_DEFAULT_DOC + "\n    fn default() -> Self {\n"
           "        Self::stated()\n" in rpolicies)
    expect("a bool policy reads its environment and nothing else",
           '        let stated = option_env!("WZ_POLICY_EAGER_FLUSH");\n'
           "        Self::from_bool(policy_bool(stated))\n" in rpolicies
           and "use super::{policy_bool, policy_choice, policy_defaults_only};" in rpolicies)
    expect("each field of SessionPolicy is private and bound inside the build's domain",
           "    wire_mode: WireModeBound,\n" in rpolicies
           and "    eager_flush: EagerFlushBound,\n" in rpolicies
           and "    pub eager_flush" not in rpolicies and "    pub wire_mode" not in rpolicies)
    expect("a field holds as many values as the domain gives it, none for a one-value domain",
           "type WireModeBound = Bound<WireMode, { WireMode::HELD }>;\n" in rpolicies
           and "type EagerFlushBound = Bound<EagerFlush, { EagerFlush::HELD }>;\n" in rpolicies)
    expect("an unstated allowance takes the rule the build or its target states",
           "const DEFAULTS_ONLY: bool = policy_defaults_only(option_env!(\"WZ_POLICY_DOMAINS\"));\n"
           in rpolicies and rpolicies.count("        DEFAULTS_ONLY,\n") == len(pdecl["policies"]))
    expect("a bool policy is read as a `bool` beside a value type of its own",
           "    pub const fn eager_flush(&self) -> bool {\n        self.eager_flush.get().is_on()\n"
           in rpolicies
           and "    pub const fn wire_mode(&self) -> WireMode {\n        self.wire_mode.get()\n" in rpolicies
           and "pub enum EagerFlush {\n    /// `off`, upstream's behaviour.\n    Off,\n" in rpolicies
           and "impl From<bool> for EagerFlush {" in rpolicies
           and "impl From<EagerFlush> for bool {" in rpolicies
           and "pub enum WireMode {" in rpolicies and rpolicies.count("pub enum WireMode {") == 1)
    expect("each policy's value type implements PolicyValue, its domain one allowance per value",
           "impl PolicyValue for WireMode {" in rpolicies
           and "impl PolicyValue for EagerFlush {" in rpolicies
           and "    const ALL: &'static [Self] = &[Self::OsDefault, Self::On, Self::Off];\n" in rpolicies
           and '    const IDS: &\'static [&\'static str] = &["off", "on"];\n' in rpolicies
           and "    const DOMAIN: Domain<Self> = Domain::from_stated(\n        &[\n"
               '            option_env!("WZ_POLICY_EAGER_FLUSH_ALLOWS_OFF"),\n'
               '            option_env!("WZ_POLICY_EAGER_FLUSH_ALLOWS_ON"),\n'
               "        ],\n        Self::DEFAULT as usize,\n        DEFAULTS_ONLY,\n    );\n" in rpolicies)
    expect("each policy carries where it is bound, and only a quiescent one a boundary",
           "    const SCOPE: Scope = Scope::Link;\n    const BINDING: Binding = Binding::Live;\n"
           "    const MUTABILITY: Mutability = Mutability::Quiescent;\n"
           "    const WIRE: Wire = Wire::Visible;\n"
           '    const BOUNDARY: Option<&\'static str> = Some("the next time the link opens");\n'
           in rpolicies
           and "    const WIRE: Wire = Wire::Timing;\n"
               "    const BOUNDARY: Option<&'static str> = None;\n" in rpolicies)
    expect("a build whose domain leaves out its default is refused by a constant of each policy",
           "const _: () = assert!(\n"
           "    default_is_allowed::<EagerFlush>(EagerFlush::DEFAULT as usize),\n"
           '    "the default of eager-flush is outside its WZ_POLICY_*_ALLOWS_*"\n'
           ");\n" in rpolicies
           and rpolicies.count("const _: () = assert!(") == len(pdecl["policies"]))
    expect("a literal past rustfmt's width goes one field a line",
           "        Self {\n            wire_mode: Bound::build_default(),\n"
           "            eager_flush: Bound::build_default(),\n        }\n" in rpolicies)
    expect("the build defaults are the snapshot a creator starts from",
           "    pub const fn defaults() -> Self {\n        Self::from_build()\n    }\n" in rpolicies)
    long_id = "a-bool-policy-whose-name-is-long-enough-to-cross-the-line-width"
    long_decl = {"policies": [dict(p, id=long_id, kconfig="WZ_POLICY_" + long_id.upper().replace("-", "_"))
                              for p in pdecl["policies"] if p["kind"] == "bool"][:1]}
    rlong = emit_rust_policies(long_decl)
    expect("a select past rustfmt's width goes one parameter a line, as the formatter leaves it",
           "    pub fn select_eager_flush(\n        &mut self,\n        value: EagerFlush,\n"
           "    ) -> Result<(), OutsideDomain<EagerFlush>> {\n"
           "        self.eager_flush = Bound::select(value)?;\n        Ok(())\n" in rpolicies)
    expect("a select within the width stays on one line",
           "    pub fn select_wire_mode(&mut self, value: WireMode) -> Result<(), OutsideDomain<WireMode>> {\n"
           in rpolicies)
    expect("an allowance past rustfmt's width breaks inside the macro, and one within it does not",
           "            option_env!(\n"
           '                "WZ_POLICY_A_BOOL_POLICY_WHOSE_NAME_IS_LONG_ENOUGH_TO_CROSS_THE_LINE_WIDTH'
           '_ALLOWS_OFF"\n            ),\n' in rlong
           and rust_domain_entry('"' + "W" * 60 + '"') == ['            option_env!("' + "W" * 60 + '"),'])
    expect("a field type past rustfmt's width breaks after the `=`, as the formatter leaves it",
           "type ABoolPolicyWhoseNameIsLongEnoughToCrossTheLineWidthBound =\n"
           "    Bound<ABoolPolicyWhoseNameIsLongEnoughToCrossTheLineWidth, "
           "{ ABoolPolicyWhoseNameIsLongEnoughToCrossTheLineWidth::HELD }>;\n" in rlong)
    expect("a default check past rustfmt's call width goes one argument a line",
           "    default_is_allowed::<ABoolPolicyWhoseNameIsLongEnoughToCrossTheLineWidth>(\n"
           "        ABoolPolicyWhoseNameIsLongEnoughToCrossTheLineWidth::DEFAULT as usize,\n"
           "    ),\n" in rlong)
    expect("a boundary is laid out as rustfmt lays a call out: one line, after the `=`, or split",
           rust_boundary('"short"') == ["    const BOUNDARY: Option<&'static str> = Some(\"short\");"]
           and rust_boundary('"' + "b" * 52 + '"')
           == ["    const BOUNDARY: Option<&'static str> =", '        Some("' + "b" * 52 + '");']
           and rust_boundary('"' + "c" * 61 + '"')
           == ["    const BOUNDARY: Option<&'static str> = Some(", '        "' + "c" * 61 + '",',
               "    );"])
    expect("a boundary with a quote or a backslash is escaped, and one that is not ASCII refused",
           rust_text('say "now" \\ then') == '"say \\"now\\" \\\\ then"' and _refuses_text("café"))
    nothing = emit_rust_policies({"policies": []})
    expect("no policy is an empty struct, an empty table and no import of a policy's trait",
           "pub struct SessionPolicy {}\n" in nothing and "        Self {}\n" in nothing
           and "use super::" not in nothing and "PolicyValue" not in nothing
           and "PolicyField" not in nothing and "Statement" not in nothing
           and "use crate::policy_binding::PolicyEntry;\nuse crate::policy_document::Profile;\n"
               in nothing
           and "pub const POLICY_COUNT: usize = 0;\n" in nothing
           and "pub static POLICIES: [PolicyEntry; POLICY_COUNT] = [];\n" in nothing
           and "pub static PROFILES: [Profile; 0] = [];\n" in nothing)
    expect("each policy is reached by its id through its field and has a row of the table",
           "impl PolicyField for WireMode {\n"
           "    fn select_in(policy: &mut SessionPolicy, value: Self) -> Result<(), OutsideDomain<Self>> {\n"
           "        policy.select_wire_mode(value)\n    }\n\n"
           "    fn held_in(policy: &SessionPolicy) -> Self {\n        policy.wire_mode.get()\n    }\n}\n"
           in rpolicies
           and rpolicies.count("impl PolicyField for ") == len(pdecl["policies"])
           and "pub const POLICY_COUNT: usize = 2;\n" in rpolicies
           and "pub static POLICIES: [PolicyEntry; POLICY_COUNT] = [\n"
               "    PolicyEntry::of::<WireMode>(),\n    PolicyEntry::of::<EagerFlush>(),\n];\n"
               in rpolicies)
    expect("a table of one policy fits a line, as the formatter leaves it",
           "pub static POLICIES: [PolicyEntry; POLICY_COUNT] = [PolicyEntry::of::<EagerFlush>()];\n"
           in emit_rust_policies({"policies": [p for p in pdecl["policies"] if p["kind"] == "bool"]}))
    expect("a declaration without a profile has an empty PROFILES and no Statement",
           "pub static PROFILES: [Profile; 0] = [];\n" in rpolicies
           and "use crate::policy_document::Profile;\n" in rpolicies
           and "Statement" not in rpolicies)
    one = emit_rust_policies({"policies": [p for p in pdecl["policies"] if p["kind"] == "bool"]})
    expect("one policy's literal is past rustfmt's struct width and goes one field a line",
           "        Self {\n            eager_flush: Bound::build_default(),\n        }\n" in one
           and "use super::{policy_bool, policy_defaults_only};" in one)
    # Where each limit is bound.
    rbindings = emit_rust_limit_bindings(sdecl)
    expect("each limit is a LimitBinding constant of its own name, in the declaration's words",
           "use crate::policy_binding::{Binding, Driven, LimitBinding, LimitKind, Scope, Storage, Wire};\n"
           in rbindings
           and "/// Where [`super::MAX_A`] is bound.\n"
               "pub const MAX_A: LimitBinding = LimitBinding {\n    kind: LimitKind::Bound,\n"
               "    driven: Some(Driven::Remote),\n    range: None,\n    storage: Storage::Both,\n"
               "    scope: &[Scope::Session],\n    binding_heap: Some(Binding::Open),\n"
               "    binding_fixed: Some(Binding::Build),\n    wire: Wire::None,\n};\n" in rbindings)
    widened = emit_rust_limit_bindings({"limits": [dict(sdecl["limits"][0], scope=["runtime", "link"],
                                                        storage="capacity", binding_heap="none")]})
    expect("a limit held at several scopes lists them, and a profile that does not read it is None",
           "    scope: &[Scope::Runtime, Scope::Link],\n    binding_heap: None,\n" in widened
           and "    storage: Storage::Capacity,\n" in widened)
    expect("no limit is no import", "use crate" not in emit_rust_limit_bindings({"limits": []}))
    # The run-time document's schema: the policies and limits a stage after the build decides.
    schema = json.loads(emit_config_schema(dict(pdecl, limits=sdecl["limits"])))
    spolicies = schema["properties"]["wz"]["properties"]["policies"]["properties"]
    slimits = schema["properties"]["wz"]["properties"]["limits"]["properties"]
    expect("the schema is draft 2020-12 and closed under `wz`",
           schema["$schema"] == "https://json-schema.org/draft/2020-12/schema"
           and schema["properties"]["wz"]["additionalProperties"] is False)
    expect("a policy the open or a running node decides is in the schema with its values and binding",
           list(spolicies) == ["wire-mode", "eager-flush"]
           and spolicies["wire-mode"]["enum"] == ["os-default", "on", "off"]
           and spolicies["wire-mode"]["description"] == "How the wire is set."
           and spolicies["wire-mode"]["x-wz-binding"] == "live"
           and spolicies["wire-mode"]["x-wz-boundary"] == "the next time the link opens"
           and spolicies["eager-flush"]["enum"] == ["off", "on"]
           and "x-wz-boundary" not in spolicies["eager-flush"])
    build_bound = decl_of(read_decl_toml(with_policy.replace(
        'binding = "open"\nmutability = "fixed"\n', 'binding = "build"\nmutability = "fixed"\n')))
    expect("a policy the build fixes is not in the schema",
           list(json.loads(emit_config_schema(build_bound))["properties"]["wz"]["properties"]
                ["policies"]["properties"]) == ["wire-mode"])
    expect("a bound a stage after the build decides is a count of at least 1 or `unbounded`",
           slimits["MAX_A"] == {"description": "A table.",
                                "oneOf": [{"type": "integer", "minimum": 1},
                                          {"const": "unbounded"}],
                                "x-wz-kind": "bound", "x-wz-driven": "remote",
                                "x-wz-storage": "both", "x-wz-scope": "session",
                                "x-wz-binding-heap": "open", "x-wz-binding-fixed": "build",
                                "x-wz-wire": "none"})
    built_only = [dict(sdecl["limits"][0], storage="capacity", binding_heap=stage)
                  for stage in ("open", "none")]
    expect("a capacity alone is not in the schema, whatever stage sizes it",
           json.loads(emit_config_schema({"policies": [], "limits": built_only}))["properties"]["wz"]
           ["properties"]["limits"]["properties"] == {})
    expect("a description is the help's first sentence, a stop inside an address not ending it",
           first_sentence("A locator (for example udp/192.168.1.10:7447). A longer one\nis refused.")
           == "A locator (for example udp/192.168.1.10:7447)."
           and first_sentence("No stop at all") == "No stop at all")
    expect("every generated file includes the limit bindings and the schema",
           GENERATED.get("rust-limit-bindings", (None,))[0] == RUST_LIMIT_BINDINGS
           and GENERATED.get("rust-limit-snapshots", (None,))[0] == RUST_LIMIT_SNAPSHOTS
           and GENERATED.get("config-schema", (None,))[0] == CONFIG_SCHEMA)
    # The profiles: named sets of policy values a run-time document starts from.
    with_profile = with_policy + PROFILE_SAMPLE
    expect("a sample profile declaration validates", validate_decl(read_decl_toml(with_profile)) == [])

    def profile_refused(old: str, new: str, words: str) -> bool:
        return any(words in p for p in validate_decl(read_decl_toml(with_profile.replace(old, new))))

    expect("a profile that names no declared policy is refused",
           profile_refused('eager-flush = "on"', 'eager-burst = "on"',
                           "profile `quiet`: `eager-burst` is not a declared policy"))
    expect("a profile value that is not one of its policy's is refused",
           profile_refused('eager-flush = "on"', 'eager-flush = "sometimes"',
                           "profile `quiet`: 'sometimes' is not a value of `eager-flush` (off, on)"))
    expect("a profile value that is not a string is refused",
           profile_refused('eager-flush = "on"', "eager-flush = 1",
                           "profile `quiet`: 1 is not a value of `eager-flush`"))
    expect("a profile that states a policy only the build decides is refused",
           profile_refused('binding = "open"\nmutability = "fixed"\n',
                           'binding = "build"\nmutability = "fixed"\n',
                           "profile `quiet`: `eager-flush` is decided by the build alone"))
    expect("the upstream profile that leaves out a policy a document may state is refused",
           profile_refused('wire-mode = "os-default"\n', "",
                           "profile `upstream`: states every policy a document may state, and "
                           "leaves out wire-mode"))
    expect("the upstream profile that states a policy off its default is refused",
           profile_refused('wire-mode = "os-default"', 'wire-mode = "on"',
                           "profile `upstream`: states `wire-mode` = 'on', and its default, "
                           "upstream's behaviour, is 'os-default'"))
    expect("the upstream profile leaves out a policy only the build decides, and validates",
           validate_decl(read_decl_toml(with_profile.replace(
               'binding = "open"\nmutability = "fixed"\n', 'binding = "build"\nmutability = "fixed"\n')
               .replace('eager-flush = "off"\n', "").replace('eager-flush = "on"\n', ""))) == [])
    expect("a profile declared twice is refused",
           any("a profile id is declared twice" in p
               for p in validate_decl(read_decl_toml(with_profile + PROFILE_SAMPLE))))
    expect("a key a profile does not have is refused",
           profile_refused('id = "quiet"\n', 'id = "quiet"\nspare = 1\n',
                           "profile `quiet`: `spare` is not a key a profile has"))
    expect("a profile with no table of values is refused",
           profile_refused('\n[profile.policies]\neager-flush = "on"\n', "",
                           "profile `quiet`: states its values in a `[profile.policies]` table"))
    expect("a profile id that is not lowercase words is refused",
           profile_refused('id = "quiet"', 'id = "Quiet_One"', "an id is lowercase words"))
    expect("a profile with no help is refused",
           profile_refused("help = '''\nFlush early, wire left alone.\n'''\n", "", "it has no help"))
    expect("the reader puts a profile's values in the last profile opened",
           [p["policies"] for p in read_decl_toml(PROFILE_SAMPLE)["profile"]]
           == [{"eager-flush": "off", "wire-mode": "os-default"}, {"eager-flush": "on"}])
    expect("a `[a.b]` table of a plain table is read as TOML reads it",
           read_decl_toml('[t]\nk = "v"\n[t.u]\nw = 1\n') == {"t": {"k": "v", "u": {"w": 1}}})
    expect("a `[a.b]` table before any `a` is refused",
           _refuses_toml('[p.q]\nk = "v"\n') and _refuses_toml('n = 3\n[n.q]\n'))
    expect("a `[a.b]` table set twice on one element is refused",
           _refuses_toml('[[p]]\n[p.q]\nk = "v"\n[p.q]\n')
           and not _refuses_toml('[[p]]\n[p.q]\nk = "v"\n[[p]]\n[p.q]\nk = "w"\n'))
    profile_decl = decl_of(read_decl_toml(with_profile))
    rprofiles = emit_rust_policies(profile_decl)
    expect("a profile is a constant whose statements follow the declaration's order of policies",
           "use crate::policy_document::{Profile, Statement};\n" in rprofiles
           and "const PROFILE_UPSTREAM: Profile = Profile {\n    id: \"upstream\",\n"
               "    statements: &[\n        Statement::new(\"wire-mode\", \"os-default\"),\n"
               "        Statement::new(\"eager-flush\", \"off\"),\n    ],\n};\n" in rprofiles
           and "const PROFILE_QUIET: Profile = Profile {\n    id: \"quiet\",\n    statements: &[\n"
               "        Statement::new(\"eager-flush\", \"on\"),\n    ],\n};\n" in rprofiles)
    expect("a profile's doc is its help, and PROFILES holds every profile",
           "/// The profile `quiet`: Flush early, wire left alone.\nconst PROFILE_QUIET" in rprofiles
           and "pub static PROFILES: [Profile; 2] = [PROFILE_UPSTREAM, PROFILE_QUIET];\n" in rprofiles)
    expect("a statement past rustfmt's call width goes one argument a line",
           rust_statement("p" * 50, "v" * 20)
           == ["        Statement::new(", '            "' + "p" * 50 + '",',
               '            "' + "v" * 20 + '",', "        ),"]
           and rust_statement("p", "v") == ['        Statement::new("p", "v"),'])
    empty_profile = emit_rust_policies(dict(pdecl, profiles=[{"id": "none", "help": "None.",
                                                              "policies": {}}]))
    expect("a profile that states nothing has an empty table and no Statement import",
           "    id: \"none\",\n    statements: &[],\n};\n" in empty_profile
           and "use crate::policy_document::Profile;\n" in empty_profile
           and "Statement" not in empty_profile)
    pschema = json.loads(emit_config_schema(dict(profile_decl, limits=sdecl["limits"])))
    expect("the schema names the profiles a document may start from, before its policies",
           list(pschema["properties"]["wz"]["properties"]) == ["profile", "policies", "limits"]
           and pschema["properties"]["wz"]["properties"]["profile"]["enum"] == ["upstream", "quiet"])
    expect("a declaration without a profile has no `profile` in the schema",
           "profile" not in schema["properties"]["wz"]["properties"])
    # The domain a build allows each policy.
    weager = next(p for p in pdecl["policies"] if p["id"] == "eager-flush")
    wmode = next(p for p in pdecl["policies"] if p["id"] == "wire-mode")
    expect("an allowance the build does not name allows its value",
           policy_domain(weager, {}) == ["off", "on"]
           and policy_domain(wmode, {}) == ["os-default", "on", "off"])
    expect("an allowance `off` leaves its value out and `on` keeps it",
           policy_domain(wmode, {"WZ_POLICY_WIRE_MODE_ALLOWS_ON": "off",
                                 "WZ_POLICY_WIRE_MODE_ALLOWS_OFF": "on"}) == ["os-default", "off"])
    expect("a domain that leaves out upstream's default is refused",
           _refuses_domain(weager, {"WZ_POLICY_EAGER_FLUSH_ALLOWS_OFF": "off"}))
    expect("a domain is held to the build's stated default, not upstream's",
           _refuses_domain(weager, {"WZ_POLICY_EAGER_FLUSH": "on",
                                    "WZ_POLICY_EAGER_FLUSH_ALLOWS_ON": "off"})
           and policy_domain(weager, {"WZ_POLICY_EAGER_FLUSH": "on",
                                      "WZ_POLICY_EAGER_FLUSH_ALLOWS_OFF": "off"}) == ["on"])
    expect("an allowance that is neither on nor off is refused",
           _refuses_domain(weager, {"WZ_POLICY_EAGER_FLUSH_ALLOWS_ON": "y"}))
    expect("a target with no operating system keeps the default alone where nothing is stated",
           policy_domain(weager, {}, no_os=True) == ["off"]
           and policy_domain(wmode, {}, no_os=True) == ["os-default"]
           and policy_domain(weager, {"WZ_POLICY_EAGER_FLUSH": "on"}, no_os=True) == ["on"])
    expect("a stated allowance wins over the target's rule, so an image may widen a domain",
           policy_domain(wmode, {"WZ_POLICY_WIRE_MODE_ALLOWS_OFF": "on"}, no_os=True)
           == ["os-default", "off"])
    expect("WZ_POLICY_DOMAINS forces either rule, and any other text is refused",
           policy_domain(wmode, {"WZ_POLICY_DOMAINS": "full"}, no_os=True) == ["os-default", "on", "off"]
           and policy_domain(wmode, {"WZ_POLICY_DOMAINS": "defaults"}) == ["os-default"]
           and _refuses_domain(wmode, {"WZ_POLICY_DOMAINS": "all"}))
    expect("each value of a policy is an allowance: default y, its prompt hidden while it is the default",
           "config WZ_POLICY_EAGER_FLUSH_ALLOWS_OFF\n"
           "\tbool \"eager-flush allows off\" if WZ_POLICY_EAGER_FLUSH\n\tdefault y\n\thelp\n" in kpolicies
           and "config WZ_POLICY_EAGER_FLUSH_ALLOWS_ON\n"
               "\tbool \"eager-flush allows on\" if !WZ_POLICY_EAGER_FLUSH\n\tdefault y\n" in kpolicies
           and "config WZ_POLICY_WIRE_MODE_ALLOWS_OS_DEFAULT\n"
               "\tbool \"wire-mode allows os-default\" if !WZ_POLICY_WIRE_MODE_OS_DEFAULT\n"
               "\tdefault y\n" in kpolicies
           and kpolicies.count("_ALLOWS_") == 5)
    expect("an allowance is a declared symbol, so a value whose allowance names another's option is refused",
           policy_refused('["os-default", "on", "off"]', '["os-default", "allows-on", "on"]',
                          "declared twice"))
    expect("a boundary that is not one line of printable ASCII is refused",
           policy_refused('boundary = "the next time the link opens"',
                          'boundary = "the next time the link opens\\u00e9"', "printable ASCII"))
    binding_rs = POLICY_BINDING_RS.read_text(encoding="utf-8")
    expect("the hand-written enums spell the declaration's words",
           check_policy_binding_rs(binding_rs) == [])
    expect("an enum missing a word of the declaration is a finding",
           any("Mutability has the variants" in f
               for f in check_policy_binding_rs(binding_rs.replace("    Quiescent,\n", "", 1))))
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

    # Where a limit is bound: SAMPLE's limit is both a capacity and a quota. A limit that is not
    # `both` states no `on_heap`, so a text that makes it another storage drops that line.
    def limit_text(**stated: str) -> str:
        text = SAMPLE
        for key, value in stated.items():
            text = re.sub(rf"(?m)^{key} = .*$", f"{key} = {value}", text)
        if stated.get("storage", '"both"') != '"both"':
            text = text.replace('on_heap = "advisory"\n', "")
        return text

    def limit_refused(text: str, words: str) -> bool:
        return any(words in p for p in validate_decl(read_decl_toml(text)))

    expect("a limit that states no `storage` is refused",
           limit_refused(SAMPLE.replace('storage = "both"\n', ""), "limit `MAX_A`: it states no `storage`"))
    expect("a limit that states no `binding_fixed` is refused",
           limit_refused(SAMPLE.replace('binding_fixed = "build"\n', ""), "states no `binding_fixed`"))
    expect("a limit storage outside its set is refused",
           limit_refused(limit_text(storage='"pool"'), "`storage` is 'pool', one of capacity"))
    expect("a limit binding outside the stages is refused",
           limit_refused(limit_text(binding_heap='"later"'), "`binding_heap` is 'later', one of build"))
    expect("a limit wire outside its set is refused",
           limit_refused(limit_text(wire='"loud"'), "`wire` is 'loud', one of none"))
    expect("a limit scope outside the scopes is refused",
           limit_refused(limit_text(scope='"galaxy"'), "`scope` is 'galaxy', one of runtime"))
    expect("a key a limit does not have is refused",
           limit_refused(SAMPLE.replace("default = 4\n", "default = 4\nspare = 1\n"),
                         "`spare` is not a key a limit has"))
    expect("a capacity decided while running is refused",
           limit_refused(limit_text(storage='"capacity"', binding_heap='"live"'),
                         "a `capacity` sizes storage, so it is decided by the open at the latest; "
                         "its `binding_heap` is 'live'"))
    expect("a capacity the heap profile decides at the open validates",
           validate_decl(read_decl_toml(limit_text(storage='"capacity"'))) == [])
    expect("a capacity only the fixed profile reads validates",
           validate_decl(read_decl_toml(limit_text(storage='"capacity"', binding_heap='"none"'))) == [])
    expect("a quota fixed at the build is refused",
           limit_refused(limit_text(storage='"quota"'), "its `binding_fixed` is 'build'"))
    expect("a quota decided while running validates",
           validate_decl(read_decl_toml(limit_text(storage='"quota"', binding_heap='"live"',
                                                   binding_fixed='"live"'))) == [])
    expect("a limit that is both, decided at the open by the fixed profile, is refused",
           limit_refused(limit_text(binding_fixed='"open"'), "a limit that is `both`"))
    expect("a limit that is both, fixed at the build by the heap profile, is refused",
           limit_refused(limit_text(binding_heap='"build"'), "a limit that is `both`"))
    expect("a limit neither storage profile reads is refused",
           limit_refused(limit_text(storage='"quota"', binding_heap='"none"', binding_fixed='"none"'),
                         "neither storage profile reads it"))
    expect("a limit held at two scopes validates",
           validate_decl(read_decl_toml(limit_text(scope='["runtime", "link"]'))) == [])
    expect("a scope array out of order is refused",
           limit_refused(limit_text(scope='["link", "runtime"]'), "lists two or more"))
    expect("a scope array of one scope is refused",
           limit_refused(limit_text(scope='["session"]'), "lists two or more"))
    expect("a scope array naming a scope twice is refused",
           limit_refused(limit_text(scope='["runtime", "runtime"]'), "lists two or more"))

    # What a limit's value is to the code: a bound names who makes it grow, a parameter its range.
    # Replaced as text: an artifact of SAMPLE has a `kind` of its own, which `limit_text` would
    # rewrite too.
    parameter = (SAMPLE.replace('kind = "bound"\ndriven = "remote"\n',
                                'kind = "parameter"\nrange = [1, 8]\n')
                 .replace('on_heap = "advisory"', 'on_heap = "capacity"'))
    expect("a parameter with a range holding its default validates",
           validate_decl(read_decl_toml(parameter)) == [])
    expect("a limit that states no `kind` is refused",
           limit_refused(SAMPLE.replace('kind = "bound"\n', ""), "limit `MAX_A`: it states no `kind`"))
    expect("a kind outside its set is refused",
           limit_refused(SAMPLE.replace('kind = "bound"', 'kind = "gauge"'),
                         "`kind` is 'gauge', one of bound, parameter"))
    expect("a bound that states no `driven` is refused",
           limit_refused(SAMPLE.replace('driven = "remote"\n', ""), "states no `driven`"))
    expect("a driver outside its set is refused",
           limit_refused(limit_text(driven='"both"'), "`driven` is 'both', one of local, remote"))
    expect("a bound with a range is refused",
           limit_refused(SAMPLE.replace("default = 4\n", "default = 4\nrange = [1, 8]\n"),
                         "a bound has no `range`"))
    most_bound = SAMPLE.replace("default = 4\n", "default = 4\nmost = 65535\n")
    expect("a bound whose code holds a narrower count states it and validates",
           validate_decl(read_decl_toml(most_bound)) == [])
    expect("a bound's `most` under its default is refused",
           limit_refused(SAMPLE.replace("default = 4\n", "default = 4\nmost = 3\n"),
                         "its default 4 is above its `most` 3"))
    expect("a parameter that states `most` is refused",
           limit_refused(SAMPLE.replace('kind = "bound"\ndriven = "remote"\n',
                                        'kind = "parameter"\nrange = [1, 8]\nmost = 8\n')
                         .replace('on_heap = "advisory"', 'on_heap = "capacity"'),
                         "only a bound states `most`"))
    mdecl = decl_of(read_decl_toml(most_bound))
    expect("a bound's `most` reaches its Kconfig range, its binding row, its schema and its domain",
           "\trange 0 65535\n" in emit_kconfig_limits(mdecl)
           and "    range: Some((0, 65535)),\n" in emit_rust_limit_bindings(mdecl)
           and json.loads(emit_config_schema(mdecl))["properties"]["wz"]["properties"]["limits"]
           ["properties"]["MAX_A"]["oneOf"][0]["maximum"] == 65535
           and "LimitDomain::of_bound_within(Self::CAPACITY, 65535, Self::DEFAULT, DEFAULTS_ONLY)"
           in emit_rust_limit_snapshots(mdecl))
    expect("a parameter that names a driver is refused",
           limit_refused(parameter.replace("range = [1, 8]\n", 'range = [1, 8]\ndriven = "local"\n'),
                         "a parameter states no `driven`"))
    expect("a parameter with no range is refused",
           limit_refused(parameter.replace("range = [1, 8]\n", ""), "states its `range` as [least, most]"))
    expect("a parameter whose range leaves out its default is refused",
           limit_refused(parameter.replace("range = [1, 8]", "range = [5, 8]"),
                         "its default 4 is outside its `range` [5, 8]"))
    expect("a range past what a 32-bit limit holds is refused",
           limit_refused(parameter.replace("range = [1, 8]", "range = [1, 4294967296]"),
                         "is not 0 <= least <= most <= 4294967295"))
    expect("a range of one end is refused",
           limit_refused(parameter.replace("range = [1, 8]", "range = [1]"),
                         "states its `range` as [least, most]"))
    expect("an advisory parameter is refused",
           limit_refused(parameter.replace('on_heap = "capacity"', 'on_heap = "advisory"'),
                         "a parameter is read by every profile that holds it"))
    expect("a limit that is both and states no `on_heap` is refused",
           limit_refused(SAMPLE.replace('on_heap = "advisory"\n', ""), "states no `on_heap`"))
    expect("an `on_heap` outside its set is refused",
           limit_refused(limit_text(on_heap='"spill"'), "`on_heap` is 'spill', one of advisory"))
    expect("an `on_heap` on a limit that is not both is refused",
           limit_refused(limit_text(storage='"quota"', binding_fixed='"live"')
                         .replace("default = 4\n", 'default = 4\non_heap = "quota"\n'),
                         "only a limit that is `both` states `on_heap`"))
    quota_bound = limit_text(storage='"quota"', binding_fixed='"live"')
    expect("a bound that sizes nothing may read 0 as no bound",
           validate_decl(read_decl_toml(quota_bound.replace(
               "default = 4\n", "default = 0\nzero_unbounded = true\n"))) == [])
    expect("0 as no bound on a limit that sizes storage is refused",
           limit_refused(SAMPLE.replace("default = 4\n", "default = 4\nzero_unbounded = true\n"),
                         "only a bound that sizes no storage (`quota`) reads `0` as no bound"))
    expect("`zero_unbounded = false` is refused",
           limit_refused(quota_bound.replace("default = 4\n", "default = 4\nzero_unbounded = false\n"),
                         "`zero_unbounded` is stated as true or not at all"))
    # What the generator makes of the kinds: Kconfig ranges, binding rows, the schema, snapshots.
    pdecl = decl_of(read_decl_toml(parameter))
    expect("a parameter's Kconfig states its range",
           "\trange 1 8\n\tdefault 4\n" in emit_kconfig_limits(pdecl))
    expect("a parameter's binding row states its range and no driver",
           "    kind: LimitKind::Parameter,\n    driven: None,\n    range: Some((1, 8)),\n"
           in emit_rust_limit_bindings(pdecl))
    bdecl = decl_of(read_decl_toml(SAMPLE))
    expect("a bound's binding row states its driver",
           "    kind: LimitKind::Bound,\n    driven: Some(Driven::Remote),\n    range: None,\n"
           in emit_rust_limit_bindings(bdecl))
    bound_schema = json.loads(emit_config_schema(bdecl))["properties"]["wz"]["properties"]["limits"]
    expect("a bound's schema takes a count of at least 1 or `unbounded`",
           bound_schema["properties"]["MAX_A"]["oneOf"]
           == [{"type": "integer", "minimum": 1}, {"const": "unbounded"}])
    param_schema = json.loads(emit_config_schema(pdecl))["properties"]["wz"]["properties"]["limits"]
    expect("a parameter's schema is an integer in its range",
           {k: param_schema["properties"]["MAX_A"][k] for k in ("type", "minimum", "maximum")}
           == {"type": "integer", "minimum": 1, "maximum": 8})
    cdecl = decl_of(read_decl_toml(limit_text(storage='"capacity"')))
    expect("a capacity alone is not in the schema and has no snapshot type",
           "MAX_A" not in json.loads(emit_config_schema(cdecl))["properties"]["wz"]["properties"]
           ["limits"]["properties"]
           and "pub struct MaxA;" not in emit_rust_limit_snapshots(cdecl))
    bsnap = emit_rust_limit_snapshots(bdecl)
    expect("an advisory bound is sized only on the fixed profile and unbounded on the heap",
           "const CAPACITY: Option<usize> = fixed_capacity(caps::MAX_A);" in bsnap
           and "const DEFAULT: Quota = Quota::of_build(Self::CAPACITY, Quota::UNBOUNDED);" in bsnap)
    expect("a session-scope limit is a field of SessionLimits and in its table",
           "    max_a: MaxAHeld,\n" in bsnap
           and "pub const SESSION_LIMIT_COUNT: usize = 1;" in bsnap
           and "pub const RUNTIME_LIMIT_COUNT: usize = 0;" in bsnap)
    rsnap = emit_rust_limit_snapshots(decl_of(read_decl_toml(limit_text(scope='"runtime"'))))
    expect("a runtime-scope limit is a field of RuntimeLimits",
           "pub const RUNTIME_LIMIT_COUNT: usize = 1;" in rsnap)
    csnap = emit_rust_limit_snapshots(decl_of(read_decl_toml(
        SAMPLE.replace('on_heap = "advisory"', 'on_heap = "capacity"'))))
    expect("a bound the heap sizes too has its capacity in every build",
           "const CAPACITY: Option<usize> = Some(caps::MAX_A);" in csnap
           and "const DEFAULT: Quota = Quota::at_most(caps::MAX_A);" in csnap)
    zsnap = emit_rust_limit_snapshots(decl_of(read_decl_toml(quota_bound.replace(
        "default = 4\n", "default = 0\nzero_unbounded = true\n"))))
    expect("a bound that sizes nothing has no capacity and reads 0 as no bound",
           "const CAPACITY: Option<usize> = None;" in zsnap
           and "const DEFAULT: Quota = Quota::from_build(caps::MAX_A, true);" in zsnap)
    psnap = emit_rust_limit_snapshots(pdecl)
    expect("a parameter is held as a usize inside its range",
           "    type Value = usize;" in psnap
           and "LimitDomain::of_parameter(1, 8, Self::CAPACITY, Self::DEFAULT, DEFAULTS_ONLY)"
           in psnap)
    shipped = load_decl()
    ranges = {lim["kconfig"]: lim["range"] for lim in shipped["limits"] if lim["kind"] == "parameter"}
    outside = [(v["case"], k, x) for v in statement_vectors(shipped) for k, x in v["env"].items()
               if k in ranges and not ranges[k][0] <= int(x) <= ranges[k][1]]
    expect("every statement vector states a parameter inside its range, as a build can", outside == [])
    expect("every limit's domain is evaluated in every build, read or not",
           "}\n\nconst _: LimitDomain = MaxA::DOMAIN;\n" in psnap
           and "}\n\nconst _: LimitDomain = MaxA::DOMAIN;\n" in bsnap)

    def caps_refused(old: str, new: str, words: str) -> bool:
        return any(words in p for p in validate_decl(read_decl_toml(SAMPLE.replace(old, new))))

    expect("a capability that states no default for an original its ABIs reach is refused",
           caps_refused('upstream_on = ["zenoh-pico"]\n', "", "judged against ['zenoh-pico']"))
    expect("a capability stating an original its ABIs do not reach is refused",
           caps_refused('upstream_on = ["zenoh-pico"]', 'upstream_on = ["zenoh-pico", "zenoh-c"]',
                        "judged against"))
    # The bit a capability has in a snapshot's features word.
    expect("an observation_bit past the 64 bits of the word is refused",
           caps_refused('os_needs = ["sockets-udp"]\n', 'os_needs = ["sockets-udp"]\nobservation_bit = 64\n',
                        "not a bit of a 64-bit word"))
    expect("an observation_bit that is not a number is refused",
           caps_refused('os_needs = ["sockets-udp"]\n', 'os_needs = ["sockets-udp"]\nobservation_bit = "zero"\n',
                        "not a bit of a 64-bit word"))
    # A default one ABI overrides.
    expect("default_off_abis naming an ABI the capability is not exported by is refused",
           caps_refused('os_needs = ["sockets-udp"]\n',
                        'os_needs = ["sockets-udp"]\ndefault_off_abis = ["c"]\n',
                        "not an ABI the capability is exported by"))
    expect("default_off_abis turns the default off for the ABI it names and no other",
           not default_on({"default_off_abis": ["pico"]}, "pico")
           and default_on({"default_off_abis": ["pico"]}, "c")
           and default_on({}, "pico") and not default_on({"default": "off"}, "c"))
    long_words = [f"value-number-{n}-of-a-long-policy" for n in range(4)]
    expect("a policy's choices wider than rustfmt's array width go one a line, as rustfmt lays "
           "them, in the policy impl and in the conformance rows",
           rust_static_array("const CHOICES: [&str; 4] =", [rust_word(w) for w in long_words],
                             "    ")[0] == "    const CHOICES: [&str; 4] = ["
           and rust_tuple_rows([[rust_word("p"), rust_word("WZ_POLICY_P"),
                                 rust_word_list(long_words)]])[3] == "        &["
           and rust_static_array("const ALL: [Self; 2] =", ["Self::A", "Self::B"], "    ")
           == ["    const ALL: [Self; 2] = [Self::A, Self::B];"])
    feature_bits = emit_rust_feature_bits(load_decl())
    expect("the features word is the capabilities' observation_bits, in bit order",
           "CLOCK_SOURCE: u64 = 1 << 0;" in feature_bits and "RESOURCE_SNAPSHOT: u64 = 1 << 3;" in feature_bits
           and feature_bits.index("(CLOCK_SOURCE,") < feature_bits.index("(EVENT_RING,")
           < feature_bits.index("(SUPERVISION,") < feature_bits.index("(RESOURCE_SNAPSHOT,"))
    expect("a crate's features word is read from the declaration, one cfg! for each capability, and "
           "the lint for an undeclared feature is allowed at each",
           all(f'cfg!(feature = "{cid}")' in feature_bits for cid in
               ("clock-source", "event-ring", "supervision", "resource-snapshot"))
           and feature_bits.count("#[allow(unexpected_cfgs)]") == 4
           and "macro_rules! built_feature_bits" in feature_bits)
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
    expect("an [os] with no `always` is refused",
           caps_refused('always = ["threads", "entropy"]\n', "", "has no `always`"))
    expect("an `always` facility outside the base is refused",
           caps_refused('always = ["threads", "entropy"]', 'always = ["threads", "wall-clock"]',
                        "`always` names `wall-clock`, which is not in `base`"))
    expect("an `always` facility outside the vocabulary is refused",
           caps_refused('always = ["threads", "entropy"]', 'always = ["threadz"]', "not a facility"))
    expect("every facility of the vocabulary says what it means, in one line",
           all(isinstance(m, str) and m and "\n" not in m for m in OS_FACILITIES.values()))
    words = ", ".join(f'"{f}"' for f in OS_FACILITIES)
    rust = (f"pub const FACILITIES: [&str; {len(OS_FACILITIES)}] = [{words}];\n"
            'const ENGINE: [&str; 2] = ["threads", "entropy"];\n')
    sample_decl = {"os_always": ["threads", "entropy"]}
    expect("the Rust derivation's vocabulary and engine that match the declaration are clean",
           check_open_facilities_rs(sample_decl, rust) == [])
    expect("a Rust vocabulary missing a word is a finding",
           any("FACILITIES is" in f for f in check_open_facilities_rs(
               sample_decl, rust.replace(', "name-resolution"', "").replace(
                   f"[&str; {len(OS_FACILITIES)}]", f"[&str; {len(OS_FACILITIES) - 1}]", 1))))
    expect("a Rust engine that is not [os] always is a finding",
           any("ENGINE is" in f for f in check_open_facilities_rs({"os_always": ["threads"]}, rust)))
    expect("every import a facility is proved by names a facility of the vocabulary",
           set(FACILITY_IMPORTS.values()) <= set(OS_FACILITIES)
           and not set(FACILITY_IMPORTS) & set(UNNAMED_IMPORTS))
    expect("an import refutes a bound that lacks its facility, and not one that has it",
           import_findings(["getaddrinfo", "socket"], ["threads"])
           == ["it imports getaddrinfo, so it may ask for name-resolution, which its bound lacks"]
           and import_findings(["getaddrinfo", "socket"], ["name-resolution"]) == [])
    expect("an import no facility names is refuted whatever the bound, even an unknown one",
           import_findings(["fork"], None)
           == ["it imports fork, a request no facility of the vocabulary names (starting a process)"])
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
           caps_refused('package = "wz-runtime-tokio"\nfeature = "f1"', 'package = "tokio"\nfeature = "f1"',
                        "not one assessed by feature"))
    expect("a runtime feature naming a facility outside the vocabulary is refused",
           caps_refused('feature = "f1"\nos_needs = ["sockets-udp"]', 'feature = "f1"\nos_needs = ["gpu"]',
                        "not a facility"))
    expect("a runtime feature with no os_needs is refused",
           caps_refused('os_needs = ["sockets-udp"]\nhelp = "A sample feature."', 'help = "A sample feature."',
                        "has no `os_needs`"))
    expect("a runtime feature declared twice is refused",
           any("declared twice" in p for p in validate_decl(read_decl_toml(
               SAMPLE + SAMPLE[SAMPLE.index("[[package_feature]]"):SAMPLE.index("[[artifact]]")]))))
    expect("a declaration with no package feature is refused",
           any("no `package_feature`" in p for p in validate_decl(read_decl_toml(
               SAMPLE[: SAMPLE.index("[[package_feature]]")] + SAMPLE[SAMPLE.index("[[artifact]]"):]))))
    expect("a declaration with no assessed package is refused",
           any("no `assessed_package`" in p for p in validate_decl(read_decl_toml(
               SAMPLE[: SAMPLE.index("[[assessed_package]]")] + SAMPLE[SAMPLE.index("[[package_feature]]"):]))))
    expect("a feature row of a package assessed whole is refused",
           caps_refused('package = "wz-runtime-tokio"\nfeature = "f1"', 'package = "wz-app"\nfeature = "f1"',
                        "not one assessed by feature"))
    expect("an assessed package declared twice is refused",
           caps_refused('package = "wz-app"', 'package = "wz-runtime-tokio"', "declared twice"))
    expect("an assessed package whose `by_feature` is not a boolean is refused",
           caps_refused("by_feature = false", 'by_feature = "no"', "not true or false"))
    expect("an assessed package with a facility outside the vocabulary is refused",
           caps_refused('os_needs = ["wall-clock"]', 'os_needs = ["calendar"]', "not a facility"))
    # A consumer's placing path held to what wz declares.
    expect("a need naming a capability wz does not declare is refused",
           caps_refused('capabilities = ["a"]\nruntime_features = ["f1"]', 'capabilities = ["zz"]\nruntime_features = ["f1"]',
                        "which is not declared"))
    expect("a need naming a runtime feature nobody assessed is refused",
           caps_refused('capabilities = ["a"]\nruntime_features = ["f1"]', 'capabilities = ["a"]\nruntime_features = ["f9"]',
                        "has no [[package_feature]] row"))
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
           resolve_package_needs(rdecl, {"wz-runtime-tokio": ["f1"]}, "x")
           == (["entropy", "sockets-tcp", "sockets-udp", "threads"], []))
    expect("an enabled feature nobody assessed makes the answer unknown and is named",
           resolve_package_needs(rdecl, {"wz-runtime-tokio": ["f1", "f2"]}, "x") == (None, ["wz-runtime-tokio/f2"]))
    expect("the default feature is not a facility and is skipped",
           resolve_package_needs(rdecl, {"wz-runtime-tokio": ["default", "f1"]}, "x")[0] is not None)
    expect("a package that is not assessed does not make the answer unknown",
           resolve_package_needs(rdecl, {"tokio": ["rt"], "wz-runtime-tokio": ["f1"]}, "x")[1] == [])
    expect("a package assessed whole adds its facilities whatever its features, and none is unassessed",
           resolve_package_needs(rdecl, {"wz-app": ["anything"]}, "x")
           == (["entropy", "sockets-tcp", "threads", "wall-clock"], []))
    expect("the executable's own package is in the build when cargo names none of its features",
           "wall-clock" in resolve_package_needs(rdecl, {}, "wz-app")[0]
           and "wall-clock" not in resolve_package_needs(rdecl, {}, "x")[0])
    expect("a row for a feature the package lost is a finding",
           any("not a feature of" in f for f in package_feature_findings(rdecl, lambda p: {"other"})))
    expect("a row for a feature the package has is clean",
           package_feature_findings(rdecl, lambda p: {"f1"}) == [])
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

    # The policies an image reads: its own Kconfig, the environment that states them, and the
    # refusal of a row that names what the image does not have.
    image_policy = (with_global + POLICY_SAMPLE + """
[[policy_image]]
policy = "eager-flush"
image = "img"

[[policy_image]]
policy = "wire-mode"
image = "img"
requires = "WZ_MODE_P && !WZ_SIDE_R"
""")
    expect("a sample image that reads policies validates",
           validate_decl(read_decl_toml(image_policy)) == [])
    ipdecl = decl_of(read_decl_toml(image_policy))
    ikconfig = emit_image_policies(ipdecl, "img")
    expect("an image's policies are Kconfig, each depending on what holds it to its profile",
           "config WZ_POLICY_EAGER_FLUSH\n\tbool \"eager-flush\"\n\tdefault n\n\thelp\n" in ikconfig
           and "choice WZ_POLICY_WIRE_MODE\n\tprompt \"wire-mode\"\n\tdefault WZ_POLICY_WIRE_MODE_OS_DEFAULT\n"
               "\tdepends on WZ_MODE_P && !WZ_SIDE_R\n\thelp\n" in ikconfig)
    expect("an image's policies state no allowance: an image's CMake states no domain, so every "
           "value stays allowed there",
           "_ALLOWS_" not in ikconfig and "_ALLOWS_" not in emit_image_cmake(ipdecl, "img"))
    expect("a policy no row names is not in the image's Kconfig",
           "WZ_POLICY_WIRE_MODE" not in emit_image_policies(
               decl_of(read_decl_toml(image_policy.replace(
                   '[[policy_image]]\npolicy = "wire-mode"\nimage = "img"\nrequires = "WZ_MODE_P && !WZ_SIDE_R"\n',
                   ""))), "img"))
    icmake = emit_image_cmake(ipdecl, "img")
    expect("a bool policy is stated as on, a choice by each value that is not upstream's, and upstream's is not stated",
           "set(wz_axes_policy_env \"\")\n" in icmake
           and "if(CONFIG_WZ_POLICY_EAGER_FLUSH)\n"
               "  list(APPEND wz_axes_policy_env WZ_POLICY_EAGER_FLUSH=on)\nendif()\n" in icmake
           and "if(CONFIG_WZ_POLICY_WIRE_MODE_ON)\n  list(APPEND wz_axes_policy_env WZ_POLICY_WIRE_MODE=on)\n" in icmake
           and "if(CONFIG_WZ_POLICY_WIRE_MODE_OFF)\n  list(APPEND wz_axes_policy_env WZ_POLICY_WIRE_MODE=off)\n" in icmake
           and "CONFIG_WZ_POLICY_WIRE_MODE_OS_DEFAULT" not in icmake)
    expect("an image that reads no policy has no policy environment and no policy Kconfig",
           "wz_axes_policy_env" not in emit_image_cmake(gdecl, "img")
           and "image-policies:img" not in generated_files(gdecl))
    expect("an image that reads policies has its Kconfig.policies among the derived files",
           "image-policies:img" in generated_files(ipdecl))

    def policy_image_refused(old: str, new: str, words: str) -> bool:
        return any(words in p for p in validate_decl(read_decl_toml(image_policy.replace(old, new))))

    expect("a row naming a policy that is not declared is refused",
           policy_image_refused('policy = "eager-flush"\nimage = "img"', 'policy = "other"\nimage = "img"',
                                "which is not declared"))
    expect("a row naming an image that is not declared is refused",
           policy_image_refused('policy = "eager-flush"\nimage = "img"', 'policy = "eager-flush"\nimage = "nope"',
                                "image 'nope'"))
    expect("a policy named twice for one image is refused",
           any("named twice" in p for p in validate_decl(read_decl_toml(
               image_policy + '\n[[policy_image]]\npolicy = "eager-flush"\nimage = "img"\n'))))
    expect("a requires naming a symbol that is no option of the image or a global axis is refused",
           policy_image_refused('requires = "WZ_MODE_P && !WZ_SIDE_R"', 'requires = "WZ_NOPE"', "no option"))
    expect("a requires that is not an expression is refused",
           policy_image_refused('requires = "WZ_MODE_P && !WZ_SIDE_R"', 'requires = "WZ_MODE_P and"',
                                "not a Kconfig expression"))
    expect("a key a policy_image does not have is refused",
           policy_image_refused('policy = "eager-flush"\nimage = "img"',
                                'policy = "eager-flush"\nimage = "img"\nnote = "x"', "does not know"))
    expect("an image's Kconfig must source its own policies and never the host's",
           check_image_sources("img", 'rsource "Kconfig.policies"\n', True) == []
           and any("does not source its own" in f for f in check_image_sources("img", "", True))
           and any("names every policy" in f for f in check_image_sources(
               "img", 'rsource "../Kconfig.policies"\nrsource "Kconfig.policies"\n', True)))

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
    expect("an integer array is read (a limit's range)",
           read_decl_toml("a = [1, 2]\n") == {"a": [1, 2]})
    expect("an array mixing integers and strings is refused", not refuses('a = [1, "x"]\n'))
    expect("an array of booleans is refused", not refuses("a = [true, false]\n"))
    expect("an empty array is still a string array", read_decl_toml("a = []\n") == {"a": []})
    expect("a boolean is read as TOML reads it", read_decl_toml("a = true\nb = false\n") == {"a": True, "b": False})
    expect("a JSON null, which TOML has no spelling of, is refused", not refuses("a = null\n"))
    expect("a key set twice is refused", not refuses('a = "x"\na = "y"\n'))
    expect("an unclosed ''' string is refused", not refuses("a = '''\nx\n"))
    expect("a ''' string sharing its opening line is refused", not refuses("a = '''x\n'''\n"))
    one_line = "a = '''why it is'''\nb = '''  '''\n"
    expect("a ''' string closed on its own line is read as TOML reads it",
           read_decl_toml(one_line) == {"a": "why it is", "b": "  "})
    expect("a ''' string that closes twice on its line is refused", not refuses("a = '''x''' '''\n"))
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
        expect("a one-line ''' string reads the same as tomllib reads it",
               read_decl_toml(one_line) == stdlib_toml.loads(one_line))
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
            resolved_doc = resolved_statement(decl, "c", resolve([first]),
                                              {"kind": "presets", "inputs": ["first.conf"]})
            expect("a preset's statement states the value its preset gives and the features "
                   "--resolve-features gives",
                   {x["id"]: x["value"] for x in resolved_doc["limits"]}["MAX_TASKS"] == 4
                   and {c["id"] for c in resolved_doc["capabilities"] if c["supported"]}
                   == set(features_for(decl, "c", resolved_caps(decl, resolve([first]))))
                   & {cid for cid in decl["order"] if "c" in caps[cid]["abis"]})
            for original, abi in BASE_ABI.items():
                expect(f"{original}'s own build states every policy at upstream's",
                       all(p["value"] == p["upstream"] for p in resolved_statement(
                           decl, abi, resolve([], original=original), {})["policies"]))
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
            # The domain each policy is left with: every value until a fragment turns an
            # allowance off, and never without the policy's chosen value.
            peager = next(p for p in wpdecl["policies"] if p["id"] == "eager-flush")
            pmode = next(p for p in wpdecl["policies"] if p["id"] == "wire-mode")
            expect("a configuration that narrows nothing allows every value",
                   resolved_policy_domain(policy_tree(), peager) == ["off", "on"]
                   and resolved_policy_domain(policy_tree(), pmode) == ["os-default", "on", "off"])
            narrowed = policy_tree("CONFIG_WZ_POLICY_EAGER_FLUSH_ALLOWS_ON=n",
                                   "CONFIG_WZ_POLICY_WIRE_MODE_ALLOWS_ON=n")
            expect("an allowance turned off leaves the value out and reaches the environment",
                   resolved_policy_domain(narrowed, peager) == ["off"]
                   and resolved_policy_env(wpdecl, narrowed)
                   == ["WZ_POLICY_WIRE_MODE_ALLOWS_ON=off", "WZ_POLICY_EAGER_FLUSH_ALLOWS_ON=off"])
            widened = policy_tree("CONFIG_WZ_POLICY_EAGER_FLUSH_ALLOWS_ON=y")
            expect("an allowance a fragment assigns reaches the environment as on, for a target "
                   "with no operating system",
                   resolved_policy_domain(widened, peager) == ["off", "on"]
                   and resolved_policy_env(wpdecl, widened) == ["WZ_POLICY_EAGER_FLUSH_ALLOWS_ON=on"])
            pinned = policy_tree("CONFIG_WZ_POLICY_EAGER_FLUSH_ALLOWS_OFF=n")
            expect("the chosen default's allowance has no prompt, so turning it off does not take",
                   resolved_policy_domain(pinned, peager) == ["off", "on"]
                   and pinned.syms["WZ_POLICY_EAGER_FLUSH_ALLOWS_OFF"].user_value == 0)
            turned = policy_tree("CONFIG_WZ_POLICY_EAGER_FLUSH=y",
                                 "CONFIG_WZ_POLICY_EAGER_FLUSH_ALLOWS_OFF=n",
                                 "CONFIG_WZ_POLICY_WIRE_MODE_OFF=y",
                                 "CONFIG_WZ_POLICY_WIRE_MODE_ALLOWS_OS_DEFAULT=n")
            expect("a policy turned off upstream's value may leave upstream's value out of its domain",
                   resolved_policy_domain(turned, peager) == ["on"]
                   and resolved_policy_domain(turned, pmode) == ["on", "off"]
                   and resolved_policy_env(wpdecl, turned)
                   == ["WZ_POLICY_WIRE_MODE=off", "WZ_POLICY_WIRE_MODE_ALLOWS_OS_DEFAULT=off",
                       "WZ_POLICY_EAGER_FLUSH=on", "WZ_POLICY_EAGER_FLUSH_ALLOWS_OFF=off"])
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
    if (len(argv) == 6 and argv[1:5] == ["--features", "pico", "--engine", "coop"]):
        decl = load_decl()
        text = pathlib.Path(argv[5]).read_text(encoding="utf-8")
        conflicts = pico_header_conflicts(decl, "pico", text)
        for conflict in conflicts:
            print(f"  wz-config FAIL: {argv[5]}: {conflict}", file=sys.stderr)
        if conflicts:
            return 1
        feats = coop_features(
            features_for(decl, "pico", read_config(decl, text)),
            manifest_features(MANIFESTS["pico"]),
        )
        print("--no-default-features --features " + ",".join(feats))
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
    if len(argv) == 4 and argv[1] == "--env" and argv[2] == "pico":
        # The numbers a pico `config.h` states for its value switches, as the environment of the
        # cargo build of the drop-in; the capabilities of the same header are the --features
        # mode's.
        decl = load_decl()
        macros = pico_value_macros(PICO_CONFIG_IN.read_text(encoding="utf-8"))
        lines, problems = pico_value_env(decl, pathlib.Path(argv[3]).read_text(encoding="utf-8"), macros)
        for problem in problems:
            print(f"  wz-config FAIL: {argv[3]}: {problem}", file=sys.stderr)
        if problems:
            return 1
        for line in lines:
            print(line)
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
            lines = resolved_limit_env(decl, kconf) + resolved_policy_env(decl, kconf)
        except PresetError as exc:
            print(f"  wz-config FAIL: {exc}", file=sys.stderr)
            return 1
        for line in lines:
            print(line)
        return 0
    if len(argv) >= 4 and argv[1] == "--resolve-conformance-statement" and argv[2] in ABIS:
        # The conformance statement of the build --resolve-features and --resolve-env describe
        # for the same presets. The inputs are named by file name only: a statement travels
        # with the build, and a path of this machine means nothing where it is read.
        decl = load_decl()
        paths = [pathlib.Path(p) for p in argv[3:]]
        try:
            kconf = resolve(paths)
        except PresetError as exc:
            print(f"  wz-config FAIL: {exc}", file=sys.stderr)
            return 1
        print_statement(resolved_statement(
            decl, argv[2], kconf, {"kind": "presets", "inputs": [p.name for p in paths]}))
        return 0
    if len(argv) == 3 and argv[1] == "--original-conformance-statement" and argv[2] in BASE_ABI:
        # An upstream original's own default build, stated through the ABI it is built through.
        decl = load_decl()
        try:
            kconf = resolve([], original=argv[2])
        except PresetError as exc:
            print(f"  wz-config FAIL: {exc}", file=sys.stderr)
            return 1
        print_statement(resolved_statement(
            decl, BASE_ABI[argv[2]], kconf, {"kind": "original", "inputs": [argv[2]]}))
        return 0
    if len(argv) == 4 and argv[1:3] == ["--conformance-statement", "c"]:
        # The zenoh-c drop-in an installed zenoh_configure.h links: the build of
        # --drop-in-features c for the same header.
        decl = load_decl()
        header = pathlib.Path(argv[3])
        print_statement(zenoh_c_header_statement(decl, header.read_text(encoding="utf-8"),
                                                 header.name))
        return 0
    coop = len(argv) == 6 and argv[1:5] == ["--conformance-statement", "pico", "--engine", "coop"]
    if coop or (len(argv) == 4 and argv[1:3] == ["--conformance-statement", "pico"]):
        # The pico drop-in a zenoh-pico config.h gives: the build of --features pico (with
        # --engine coop, of the cooperative engine) and --env pico for the same header.
        decl = load_decl()
        header = pathlib.Path(argv[-1])
        macros = pico_value_macros(PICO_CONFIG_IN.read_text(encoding="utf-8"))
        doc, problems = pico_header_statement(
            decl, header.read_text(encoding="utf-8"), macros, header.name,
            manifest_features(MANIFESTS["pico"]) if coop else None)
        for problem in problems:
            print(f"  wz-config FAIL: {header}: {problem}", file=sys.stderr)
        if doc is None:
            return 1
        print_statement(doc)
        return 0
    coop_header = len(argv) == 5 and argv[1:4] == ["--pico-config-h", "--engine", "coop"]
    if coop_header or (len(argv) == 3 and argv[1] == "--pico-config-h"):
        decl = load_decl()
        try:
            enabled = pico_build_features("coop" if coop_header else "tokio", argv[-1].split(","),
                                          manifest_features(MANIFESTS["pico"]))
            header = pico_config_header(decl, enabled, dict(os.environ))
        except KeyError as exc:
            print(f"  wz-config FAIL: {argv[-1]}: {exc.args[0]}", file=sys.stderr)
            return 1
        except (ValueError, OSError) as exc:
            print(f"  wz-config FAIL: {exc}", file=sys.stderr)
            return 1
        # The header must read back as the build: a capability a switch of it states off and a
        # capability it states on implies would be a build `--features pico` refuses.
        conflicts = pico_header_conflicts(decl, "pico", header)
        for conflict in conflicts:
            print(f"  wz-config FAIL: {argv[-1]}: {conflict}", file=sys.stderr)
        if conflicts:
            return 1
        sys.stdout.write(header)
        return 0
    print(__doc__, file=sys.stderr)
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv))
