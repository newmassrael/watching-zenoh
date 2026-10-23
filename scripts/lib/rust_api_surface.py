#!/usr/bin/env python3
# SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
# SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

"""R3406 (no register item) — the public Rust API of the pinned `zenoh` crate, derived
from rustdoc JSON and committed as the surface wz's compatibility crate must equal.

Open-debt item 910 (inventory atom `api-compat-rust`, `docs/build-configuration.md`
C13): a Rust user replaces zenoh by changing one dependency line, so wz owes the
upstream crate's public paths, kinds and trait relations. This script is the
DENOMINATOR of that claim. It is the first of the gate's two halves; the other, the
same normaliser run over the compatibility crate and diffed against these files,
lands with that crate.

## Where the numbers come from

rustdoc JSON, emitted for upstream `zenoh` at the pin (`upstream_root()`, the one
resolver), once per feature ARM: the default features, `unstable`, and `unstable`
with `shared-memory`. The compiler is the dated nightly of `scripts/rustdoc-json.pin`,
and a JSON whose `format_version` is not the pinned one is refused rather than read
with a layout it was not written for. No list here is typed by hand.

## What one line of a surface is

    mod <path>                          a public module reached from the crate root
    <kind> <path>                       a public item defined in `zenoh` (struct, enum,
                                        trait, fn, type, const, static, macro, union)
    fn <path>::<Type>::<method>         a public inherent method of such a type
    impl <trait path> for <type path>   a trait implementation of such a type (not the
                                        auto traits the compiler synthesises, not
                                        blanket implementations)
    reexport <kind> <path> = <origin>   a public name for an item another crate defines
    glob <path>::* = <origin>           a public glob over another crate's module

A type or trait in an `impl` line is named by its PUBLIC path when the crate exposes
it, and by its defining path otherwise (a standard trait such as
`core::future::into_future::IntoFuture`).

## What this does NOT measure yet

* Signatures. A function is its path and kind; its parameters, return type and
  generics are the next increment, and until then two functions of one name with
  different signatures are the same line.
* What a foreign GLOB brings in. Expanding `glob` lines needs the JSON of the crate
  it points at; the line names it, so a change of origin still shows.
* Behaviour. Equal surfaces are where the drop-in claim starts, not where it ends:
  upstream's examples, tests and doctests built against the compatibility crate are
  the behaviour half (item 910).

## The arms

The committed files are `deploy/upstream-api/zenoh-<version>-<arm>.surface`. The
DEFAULT run reads only those files and the pin, so it runs anywhere (Layer C0):
every arm present, each header naming the pinned toolchain, format version and
upstream version, lines sorted and unique. `--upstream` re-emits every arm from the
pinned source and fails on any difference in either direction; it needs that source
and the toolchain, so it runs where the source is provisioned (Layer Z). `--write`
re-emits and overwrites, for the round that moves a pin or the normaliser.

Usage:
    python3 scripts/lib/rust_api_surface.py                # committed files only
    python3 scripts/lib/rust_api_surface.py --upstream     # + re-emit and compare
    python3 scripts/lib/rust_api_surface.py --write        # re-emit and overwrite
    python3 scripts/lib/rust_api_surface.py --selftest
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts" / "lib"))

import upstream_feature_census as census  # noqa: E402

PIN_FILE = ROOT / "scripts" / "rustdoc-json.pin"
SURFACE_DIR = ROOT / "deploy" / "upstream-api"
TARGET_DIR = ROOT / "target" / "rust-api-surface"
CRATE = "zenoh"

# The compatibility crate (inventory atom `api-compat-rust`): its library is named `zenoh`, so the
# same normaliser reads it under the same root. It declares none of upstream's arm features yet,
# so its one surface is held to every arm; a per-arm surface comes with the feature that splits it.
WZ_PACKAGE = "wz-zenoh"
WZ_TARGET_DIR = TARGET_DIR / "wz-zenoh"

# The count of upstream lines the compatibility crate does not yet have, per arm: a RATCHET. A
# slice that lands lowers it in the same round; a count that rises is a regression and a count
# that falls without moving it is progress the record has not taken. Either way the gate fails
# until this table is the measurement.
WZ_MISSING: dict[str, int] = {
    "default": 709,
    "unstable": 965,
    "unstable-shared-memory": 1025,
}

# The arms, by name and the features each passes. `internal` and `plugins` are not arms:
# they widen visibility for zenoh's own crates (the census excludes `internal` on that
# ground), and a user replacing zenoh does not build with them.
ARMS: tuple[tuple[str, str], ...] = (
    ("default", ""),
    ("unstable", "unstable"),
    ("unstable-shared-memory", "unstable,shared-memory"),
)

ITEM_KINDS = {
    "struct": "struct", "enum": "enum", "trait": "trait", "function": "fn",
    "type_alias": "type", "constant": "const", "static": "static", "macro": "macro",
    "proc_macro": "macro", "union": "union", "trait_alias": "trait",
}


class InputError(RuntimeError):
    """An input could not be read. Never a pass: always exit 2."""


def read_pin(path: Path = PIN_FILE) -> tuple[str, int]:
    values: dict[str, str] = {}
    try:
        lines = path.read_text().splitlines()
    except OSError as e:
        raise InputError(f"cannot read {path} ({e})") from e
    for line in lines:
        line = line.strip()
        if line and not line.startswith("#") and "=" in line:
            key, _, value = line.partition("=")
            values[key.strip()] = value.strip()
    toolchain = values.get("RUSTDOC_JSON_TOOLCHAIN", "")
    fmt = values.get("RUSTDOC_JSON_FORMAT_VERSION", "")
    if not toolchain.startswith("nightly-") or not fmt.isdigit():
        raise InputError(
            f"{path} must state RUSTDOC_JSON_TOOLCHAIN=nightly-<date> and a numeric "
            f"RUSTDOC_JSON_FORMAT_VERSION"
        )
    return toolchain, int(fmt)


# ── the normaliser ──────────────────────────────────────────────────────────


def _id(value) -> str:
    return str(value)


def _is_public(item: dict) -> bool:
    return item.get("visibility") == "public"


def _path_of(doc: dict, ident) -> str | None:
    """The defining path of an item the JSON names by id, local or foreign."""
    entry = doc.get("paths", {}).get(_id(ident))
    if not entry:
        return None
    return "::".join(entry.get("path", []))


def _type_name(doc: dict, ty, public: dict[str, str]) -> str:
    """A type in an impl header, by its public path when the crate exposes it."""
    if not isinstance(ty, dict):
        return "?"
    if "resolved_path" in ty:
        rp = ty["resolved_path"]
        ident = _id(rp.get("id"))
        return public.get(ident) or _path_of(doc, ident) or rp.get("path") or rp.get("name") or "?"
    if "primitive" in ty:
        return ty["primitive"]
    if "borrowed_ref" in ty:
        return "&" + _type_name(doc, ty["borrowed_ref"].get("type"), public)
    if "generic" in ty:
        return ty["generic"]
    return next(iter(ty), "?")


def normalise(doc: dict, fmt: int) -> list[str]:
    """The surface lines of one rustdoc JSON document, sorted and unique."""
    got = doc.get("format_version")
    if got != fmt:
        raise InputError(
            f"rustdoc JSON format_version {got}, not the pinned {fmt} -- refused rather than "
            f"read with a layout it was not written for"
        )
    index: dict = doc.get("index", {})
    root = _id(doc.get("root"))
    if root not in index:
        raise InputError("rustdoc JSON has no root module in its index")

    lines: set[str] = set()
    public: dict[str, str] = {}  # item id -> the first public path it was reached by
    types: list[tuple[str, dict]] = []  # (public path, item) of local types, for their impls
    seen: set[tuple[str, str]] = set()

    def visit_module(mod_id: str, prefix: str) -> None:
        if (mod_id, prefix) in seen:
            return
        seen.add((mod_id, prefix))
        module = index[mod_id]["inner"]["module"]
        for child in module.get("items", []):
            item = index.get(_id(child))
            if item is None or not _is_public(item):
                continue
            visit_item(_id(child), item, prefix, item.get("name"))

    def visit_item(ident: str, item: dict, prefix: str, name: str | None) -> None:
        inner = item.get("inner", {})
        kind = next(iter(inner), None)
        if kind == "use":
            use = inner["use"]
            target = _id(use.get("id")) if use.get("id") is not None else None
            if use.get("is_glob"):
                if target in index and "module" in index[target].get("inner", {}):
                    visit_module(target, prefix)
                else:
                    lines.add(f"glob {prefix}::* = {_path_of(doc, target) or use.get('source')}")
                return
            path = f"{prefix}::{use.get('name')}"
            if target in index:
                visit_item(target, index[target], prefix, use.get("name"))
            else:
                origin = doc.get("paths", {}).get(target or "", {})
                okind = ITEM_KINDS.get(origin.get("kind", ""), origin.get("kind", "item"))
                lines.add(f"reexport {okind} {path} = {_path_of(doc, target) or use.get('source')}")
                if target:
                    public.setdefault(target, path)
            return
        if not name:
            return
        path = f"{prefix}::{name}"
        if kind == "module":
            lines.add(f"mod {path}")
            public.setdefault(ident, path)
            visit_module(ident, path)
        elif kind in ITEM_KINDS:
            lines.add(f"{ITEM_KINDS[kind]} {path}")
            if ident not in public:
                public[ident] = path
                if kind in ("struct", "enum", "union"):
                    types.append((path, item))

    visit_module(root, CRATE)

    for path, item in types:
        inner = next(iter(item["inner"].values()))
        for impl_id in inner.get("impls", []):
            impl_item = index.get(_id(impl_id))
            if impl_item is None:
                continue
            impl = impl_item.get("inner", {}).get("impl", {})
            if impl.get("is_synthetic") or impl.get("blanket_impl") is not None or impl.get("is_negative"):
                continue
            trait = impl.get("trait")
            if trait is None:
                for member in impl.get("items", []):
                    fn = index.get(_id(member))
                    if fn and _is_public(fn) and "function" in fn.get("inner", {}):
                        lines.add(f"fn {path}::{fn.get('name')}")
            else:
                tid = _id(trait.get("id"))
                tname = public.get(tid) or _path_of(doc, tid) or trait.get("path") or trait.get("name")
                lines.add(f"impl {tname} for {_type_name(doc, impl.get('for'), public) if impl.get('for') else path}")
    return sorted(lines)


# ── emitting from the pinned source ─────────────────────────────────────────


def upstream_root() -> Path:
    import upstream_citation_anchor_gate as anchors

    root = anchors.upstream_root()
    if root is None:
        raise InputError(
            "no pinned zenoh checkout (upstream_citation_anchor_gate.upstream_root() found none); "
            "provision one with `bash scripts/build-zenohd.sh`"
        )
    return Path(root)


def emit(toolchain: str, features: str) -> dict:
    """rustdoc JSON of upstream `zenoh` with one feature set, from the pinned source."""
    source = upstream_root()
    cmd = ["cargo", f"+{toolchain}", "rustdoc", "-p", CRATE, "--lib", "--locked",
           "--target-dir", str(TARGET_DIR)]
    if features:
        cmd += ["--features", features]
    cmd += ["--", "-Z", "unstable-options", "--output-format", "json"]
    proc = subprocess.run(cmd, cwd=source, capture_output=True, text=True, check=False)
    if proc.returncode != 0:
        raise InputError(
            f"`{' '.join(cmd)}` in the pinned source failed (rc={proc.returncode}): "
            f"{proc.stderr.strip()[-2000:] or '<no stderr>'}"
        )
    out = TARGET_DIR / "doc" / f"{CRATE}.json"
    try:
        return json.loads(out.read_text())
    except (OSError, json.JSONDecodeError) as e:
        raise InputError(f"rustdoc wrote no readable JSON at {out} ({e})") from e


def emit_wz(toolchain: str) -> dict:
    """rustdoc JSON of the compatibility crate, from this tree."""
    cmd = ["cargo", f"+{toolchain}", "rustdoc", "-p", WZ_PACKAGE, "--lib", "--locked",
           "--target-dir", str(WZ_TARGET_DIR), "--", "-Z", "unstable-options",
           "--output-format", "json"]
    proc = subprocess.run(cmd, cwd=ROOT / "crates", capture_output=True, text=True, check=False)
    if proc.returncode != 0:
        raise InputError(
            f"`{' '.join(cmd)}` in crates/ failed (rc={proc.returncode}): "
            f"{proc.stderr.strip()[-2000:] or '<no stderr>'}"
        )
    out = WZ_TARGET_DIR / "doc" / f"{CRATE}.json"
    try:
        return json.loads(out.read_text())
    except (OSError, json.JSONDecodeError) as e:
        raise InputError(f"rustdoc wrote no readable JSON at {out} ({e})") from e


def wz_surface_file() -> Path:
    return SURFACE_DIR / f"{WZ_PACKAGE}-{census.UPSTREAM_VERSION}.surface"


def wz_header(toolchain: str, fmt: int) -> list[str]:
    return [
        "# Generated by scripts/lib/rust_api_surface.py --write. Do not edit.",
        f"# compatibility crate: {WZ_PACKAGE} {census.UPSTREAM_VERSION}",
        f"# toolchain: {toolchain}",
        f"# format_version: {fmt}",
    ]


def compatibility_arm(toolchain: str, fmt: int) -> list[str]:
    """Does the committed surface of the compatibility crate hold to every upstream arm?

    It may carry no line upstream does not (C10: a wz-only door is in `wz::ext`), and the lines
    of each arm it does not carry yet must number exactly `WZ_MISSING[arm]`."""
    failures: list[str] = []
    path = wz_surface_file()
    if not path.is_file():
        return [f"{path.relative_to(ROOT)} is missing -- emit it with --write"]
    meta, wz = read_surface(path)
    for key, value in (("toolchain", toolchain), ("format_version", str(fmt))):
        if meta.get(key) != value:
            failures.append(f"{path.relative_to(ROOT)} says {key} `{meta.get(key)}`, the pin says "
                            f"`{value}` -- re-emit it")
    if wz != sorted(set(wz)):
        failures.append(f"{path.relative_to(ROOT)} is not sorted and unique -- not this script's output")
    upstream = {arm: read_surface(surface_file(arm))[1] for arm, _features in ARMS}
    return failures + compatibility_check(wz, upstream, WZ_MISSING)


def compatibility_check(wz: list[str], upstream: dict[str, list[str]],
                        pin: dict[str, int]) -> list[str]:
    """The compatibility crate's surface against each upstream arm: no extra line, and exactly the
    pinned number of missing ones."""
    failures: list[str] = []
    for arm, lines in upstream.items():
        extra = sorted(set(wz) - set(lines))
        missing = len(set(lines) - set(wz))
        failures += [f"{arm}: the compatibility crate has `{line}`, which upstream does not "
                     f"(a wz-only door belongs in wz::ext)" for line in extra[:40]]
        if missing != pin[arm]:
            way = "fell" if missing < pin[arm] else "ROSE"
            failures.append(f"{arm}: {missing} upstream line(s) are missing from the compatibility "
                            f"crate and WZ_MISSING says {pin[arm]}: the count {way}; move the pin "
                            f"in this round if a slice landed, never to absorb a loss")
        print(f"  rust-api-surface: {WZ_PACKAGE} against {arm}: {len(lines) - missing} of "
              f"{len(lines)} line(s), {missing} missing, {len(extra)} extra")
    return failures


def surface_file(arm: str) -> Path:
    return SURFACE_DIR / f"{CRATE}-{census.UPSTREAM_VERSION}-{arm}.surface"


def header(toolchain: str, fmt: int, arm: str, features: str) -> list[str]:
    return [
        "# Generated by scripts/lib/rust_api_surface.py --write. Do not edit.",
        f"# upstream: {CRATE} {census.UPSTREAM_VERSION}",
        f"# arm: {arm} (features: {features or 'default'})",
        f"# toolchain: {toolchain}",
        f"# format_version: {fmt}",
    ]


def read_surface(path: Path) -> tuple[dict[str, str], list[str]]:
    try:
        text = path.read_text()
    except OSError as e:
        raise InputError(f"cannot read {path} ({e})") from e
    meta: dict[str, str] = {}
    body: list[str] = []
    for line in text.splitlines():
        if line.startswith("# ") and ": " in line:
            key, _, value = line[2:].partition(": ")
            meta[key] = value
        elif line and not line.startswith("#"):
            body.append(line)
    return meta, body


def committed_arm(toolchain: str, fmt: int) -> list[str]:
    """Are the committed surfaces present, current and well formed?"""
    failures: list[str] = []
    for arm, features in ARMS:
        path = surface_file(arm)
        if not path.is_file():
            failures.append(f"{path.relative_to(ROOT)} is missing -- emit it with --write")
            continue
        meta, body = read_surface(path)
        want = dict(line[2:].partition(": ")[::2] for line in header(toolchain, fmt, arm, features)[1:])
        for key, value in want.items():
            if meta.get(key) != value:
                failures.append(
                    f"{path.relative_to(ROOT)} says {key} `{meta.get(key)}`, the pin says `{value}` -- "
                    f"re-emit it in the round that moved the pin"
                )
        if not body:
            failures.append(f"{path.relative_to(ROOT)} has no surface lines -- a population of zero")
        if body != sorted(set(body)):
            failures.append(f"{path.relative_to(ROOT)} is not sorted and unique -- not this script's output")
        kinds: dict[str, int] = {}
        for line in body:
            kinds[line.split(" ", 1)[0]] = kinds.get(line.split(" ", 1)[0], 0) + 1
        print(
            f"  rust-api-surface: {arm}: {len(body)} line(s) -- "
            + ", ".join(f"{n} {k}" for k, n in sorted(kinds.items()))
        )
    return failures


def compare(old: list[str], new: list[str]) -> list[str]:
    gone = sorted(set(old) - set(new))
    came = sorted(set(new) - set(old))
    return [f"no longer emitted: {line}" for line in gone[:40]] + [
        f"newly emitted: {line}" for line in came[:40]
    ] + ([f"... and {len(gone) + len(came) - 80} more"] if len(gone) + len(came) > 80 else [])


# ── selftest ────────────────────────────────────────────────────────────────


def selftest() -> int:
    """Drive the normaliser over a small document with every shape it reads."""
    doc = {
        "format_version": 57,
        "root": 0,
        "paths": {
            "90": {"crate_id": 1, "path": ["zenoh_core", "Wait"], "kind": "trait"},
            "91": {"crate_id": 1, "path": ["zenoh_core", "Resolvable"], "kind": "trait"},
            "92": {"crate_id": 2, "path": ["core", "future", "into_future", "IntoFuture"], "kind": "trait"},
            "93": {"crate_id": 3, "path": ["zenoh_keyexpr", "key_expr"], "kind": "module"},
        },
        "index": {
            "0": {"name": "zenoh", "visibility": "public",
                  "inner": {"module": {"items": [1, 2, 3, 4, 5, 6, 7]}}},
            "1": {"name": None, "visibility": "public",
                  "inner": {"use": {"source": "zenoh_core::Wait", "name": "Wait", "id": 90, "is_glob": False}}},
            "2": {"name": "session", "visibility": "public", "inner": {"module": {"items": [10, 11]}}},
            "3": {"name": None, "visibility": "public",
                  "inner": {"use": {"source": "crate::session::Session", "name": "Session", "id": 10, "is_glob": False}}},
            "4": {"name": "hidden", "visibility": "crate", "inner": {"module": {"items": []}}},
            "5": {"name": None, "visibility": "public",
                  "inner": {"use": {"source": "zenoh_keyexpr::key_expr", "name": "key_expr", "id": 93, "is_glob": True}}},
            "6": {"name": "open", "visibility": "public", "inner": {"function": {}}},
            "7": {"name": None, "visibility": "public",
                  "inner": {"use": {"source": "zenoh_core::Resolvable", "name": "Resolvable", "id": 91, "is_glob": False}}},
            "10": {"name": "Session", "visibility": "public",
                   "inner": {"struct": {"impls": [20, 21, 22, 23, 24]}}},
            "11": {"name": "private_fn", "visibility": "default", "inner": {"function": {}}},
            "20": {"visibility": "default", "inner": {"impl": {"trait": None, "items": [30, 31], "for": {}}}},
            "21": {"visibility": "default", "inner": {"impl": {
                "trait": {"path": "Wait", "id": 90}, "items": [],
                "for": {"resolved_path": {"path": "Session", "id": 10}}}}},
            "22": {"visibility": "default", "inner": {"impl": {
                "trait": {"path": "IntoFuture", "id": 92}, "items": [],
                "for": {"resolved_path": {"path": "Session", "id": 10}}}}},
            "23": {"visibility": "default", "inner": {"impl": {
                "trait": {"path": "Send", "id": 99}, "is_synthetic": True, "items": [], "for": {}}}},
            "24": {"visibility": "default", "inner": {"impl": {
                "trait": {"path": "Resolvable", "id": 91}, "blanket_impl": {"generic": "T"}, "items": [], "for": {}}}},
            "30": {"name": "put", "visibility": "public", "inner": {"function": {}}},
            "31": {"name": "internal", "visibility": "default", "inner": {"function": {}}},
        },
    }
    want = [
        "fn zenoh::open",
        "fn zenoh::session::Session::put",
        "glob zenoh::* = zenoh_keyexpr::key_expr",
        "impl core::future::into_future::IntoFuture for zenoh::session::Session",
        "impl zenoh::Wait for zenoh::session::Session",
        "mod zenoh::session",
        "reexport trait zenoh::Resolvable = zenoh_core::Resolvable",
        "reexport trait zenoh::Wait = zenoh_core::Wait",
        # One item, two public paths: the root re-exports what a module defines, and a user
        # names it either way, so both are surface.
        "struct zenoh::Session",
        "struct zenoh::session::Session",
    ]
    got = normalise(doc, 57)
    if got != want:
        print("  selftest FAIL [the normaliser]:", file=sys.stderr)
        for line in sorted(set(got) ^ set(want)):
            print(f"    {'extra' if line in got else 'missing'}: {line}", file=sys.stderr)
        return 1
    try:
        normalise({**doc, "format_version": 56}, 57)
    except InputError:
        pass
    else:
        print("  selftest FAIL [another format_version]: ACCEPTED", file=sys.stderr)
        return 1
    try:
        normalise({**doc, "root": 404}, 57)
    except InputError:
        pass
    else:
        print("  selftest FAIL [no root module]: ACCEPTED", file=sys.stderr)
        return 1
    if compare(["a", "b"], ["b", "c"]) != ["no longer emitted: a", "newly emitted: c"]:
        print("  selftest FAIL [the comparison]", file=sys.stderr)
        return 1
    # The compatibility crate's ratchet: upstream has three lines, the crate one of them.
    up = {"default": ["fn zenoh::open", "struct zenoh::Session", "fn zenoh::scout"]}
    cases = [
        ("one of three, pinned at two missing, passes", ["fn zenoh::open"], {"default": 2}, None),
        ("a line upstream does not have fails", ["fn zenoh::open", "fn zenoh::wz_only"],
         {"default": 2}, "which upstream does not"),
        ("a count that fell without the pin moving fails",
         ["fn zenoh::open", "fn zenoh::scout"], {"default": 2}, "fell"),
        ("a count that rose fails", [], {"default": 2}, "ROSE"),
    ]
    for label, wz, pin, words in cases:
        got = compatibility_check(wz, up, pin)
        if (words is None) != (got == []) or (words is not None and not any(words in f for f in got)):
            print(f"  selftest FAIL [{label}]: {got}", file=sys.stderr)
            return 1
    print(f"  rust-api-surface: selftest -- the normaliser over {len(want)} shapes, two refusals and the comparison pass")
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(description="the pinned zenoh crate's public Rust API surface")
    mode = ap.add_mutually_exclusive_group()
    mode.add_argument("--upstream", action="store_true", help="re-emit every arm and compare")
    mode.add_argument("--write", action="store_true", help="re-emit every arm and overwrite")
    mode.add_argument("--selftest", action="store_true", help="drive the normaliser on a fixture")
    args = ap.parse_args()
    if args.selftest:
        return selftest()

    try:
        toolchain, fmt = read_pin()
        if args.write or args.upstream:
            failures: list[str] = []
            for arm, features in ARMS:
                lines = normalise(emit(toolchain, features), fmt)
                path = surface_file(arm)
                if args.write:
                    path.parent.mkdir(parents=True, exist_ok=True)
                    path.write_text("\n".join(header(toolchain, fmt, arm, features) + lines) + "\n")
                    print(f"  rust-api-surface: wrote {path.relative_to(ROOT)} ({len(lines)} lines)")
                else:
                    _, old = read_surface(path)
                    diff = compare(old, lines)
                    failures += [f"{arm}: {d}" for d in diff]
                    print(f"  rust-api-surface: {arm}: re-emitted {len(lines)} line(s), {len(diff)} difference(s)")
            wz_lines = normalise(emit_wz(toolchain), fmt)
            path = wz_surface_file()
            if args.write:
                path.write_text("\n".join(wz_header(toolchain, fmt) + wz_lines) + "\n")
                print(f"  rust-api-surface: wrote {path.relative_to(ROOT)} ({len(wz_lines)} lines)")
            else:
                _, old = read_surface(path)
                diff = compare(old, wz_lines)
                failures += [f"{WZ_PACKAGE}: {d}" for d in diff]
                print(f"  rust-api-surface: {WZ_PACKAGE}: re-emitted {len(wz_lines)} line(s), "
                      f"{len(diff)} difference(s)")
                failures += compatibility_arm(toolchain, fmt)
            if failures:
                for f in failures:
                    print(f"  rust-api-surface: FAIL -- {f}", file=sys.stderr)
                return 1
            return 0
        failures = committed_arm(toolchain, fmt)
        failures += compatibility_arm(toolchain, fmt)
    except InputError as e:
        print(f"  rust-api-surface: INPUT -- {e}", file=sys.stderr)
        return 2
    print(
        "    -- upstream arm DEFERRED: run with --upstream where the pinned zenoh source and the "
        f"{toolchain} toolchain are provisioned (Layer Z); it re-emits both surfaces, upstream's "
        f"and {WZ_PACKAGE}'s, and holds the committed files to them."
    )
    if failures:
        for f in failures:
            print(f"  rust-api-surface: FAIL -- {f}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
