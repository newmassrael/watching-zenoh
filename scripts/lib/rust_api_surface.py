#!/usr/bin/env python3
# SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
# SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

"""R3406 (no register item) — the public Rust API of the pinned `zenoh` crate and of the
crates under it, derived from rustdoc JSON and committed as the surface wz's compatibility
crates must equal.

Open-debt item 910 (inventory atom `api-compat-rust`, `docs/build-configuration.md`
C13): a Rust user replaces zenoh, so wz owes the upstream crates' public paths, kinds and
trait relations. This script is the DENOMINATOR of that claim, and the same normaliser run
over each compatibility crate and diffed against these files is the other half.

## The family

`zenoh` is not alone in a user's dependency graph: its public API names types of
`zenoh-core`, `zenoh-result`, `zenoh-keyexpr`, `zenoh-protocol` and others (a `reexport`
line carries the crate it comes from), and the ecosystem crates (`zenoh-ext`, the
plugins) import those crates directly. A Cargo graph holds one crate per package name, and
`[patch]` swaps by that name, so a replacement that is to meet an ecosystem crate on the
SAME types is a crate of upstream's name. `MEMBERS` lists the crates of that family; each
is held to its own upstream surface, with its own ratchet.

## Where the numbers come from

rustdoc JSON, emitted for each upstream member at the pin (`upstream_root()`, the one
resolver), once per feature ARM: for `zenoh` the default features, `unstable`, and
`unstable` with `shared-memory`; for a crate no feature splits, the default. The compiler
is the dated nightly of `scripts/rustdoc-json.pin`,
and a JSON whose `format_version` is not the pinned one is refused rather than read
with a layout it was not written for. No list here is typed by hand.

## What one line of a surface is

    mod <path>                          a public module reached from the crate root
    <kind> <path>                       a public item defined in `zenoh` (struct, enum,
                                        trait, type, const, static, macro, union)
    fn <path><generics>(<types>) -> <type> where <bounds> ; <qualifiers> ; in impl<..> <type>
                                        a public function, a free one or an inherent method
                                        (`; in impl` names the block a method sits in)
    impl <trait path> for <type path>   a trait implementation of such a type (not the
                                        auto traits the compiler synthesises, not
                                        blanket implementations)
    reexport <kind> <path> = <origin>   a public name for an item another crate defines
    glob <path>::* = <origin>           a public glob over another crate's module

A type or trait in an `impl` line is named by its PUBLIC path when the crate exposes
it, and by its defining path otherwise (a standard trait such as
`core::future::into_future::IntoFuture`).

## What a function's line holds

What a caller or an implementer can depend on: its generics and their bounds, the TYPES of
its parameters (a receiver included) and its return type, its qualifiers (`async`, `const`,
`unsafe`) and, for a method, the `impl` block it sits in. Left out, because they are not part
of the contract: parameter names, the names of lifetimes (renamed by order of first
appearance; `'static` and `'_` stay), the order of bounds and of `where` predicates, and the
parameter rustc invents for an `impl Trait` argument. The order of generic parameters IS
kept: a turbofish is positional. A shape of rustdoc JSON this reader does not know is
refused rather than skipped, because a line that silently dropped part of a signature would
call two different functions one.

## What this does NOT measure yet

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
import re
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts" / "lib"))

import upstream_feature_census as census  # noqa: E402

PIN_FILE = ROOT / "scripts" / "rustdoc-json.pin"
SURFACE_DIR = ROOT / "deploy" / "upstream-api"
TARGET_DIR = ROOT / "target" / "rust-api-surface"

# The arms of `zenoh`, by name and the features each passes. `internal` and `plugins` are not
# arms: they widen visibility for zenoh's own crates (the census excludes `internal` on that
# ground), and a user replacing zenoh does not build with them.
ARMS: tuple[tuple[str, str], ...] = (
    ("default", ""),
    ("unstable", "unstable"),
    ("unstable-shared-memory", "unstable,shared-memory"),
)

# A crate of upstream's own that no feature splits has the one arm.
DEFAULT_ARM: tuple[tuple[str, str], ...] = (("default", ""),)


@dataclass(frozen=True)
class Member:
    """One crate of the family wz replaces (inventory atom `api-compat-rust`, C13).

    A Rust user replaces zenoh by a `[patch.crates-io]` entry per crate, and Cargo swaps by PACKAGE
    NAME: a patch whose package is named otherwise is not used and the graph keeps upstream's crate,
    which a program that also links an ecosystem crate (`zenoh-ext`) then sees as a second, different
    `zenoh_core`. So a family crate carries upstream's package name, its library name (the root of
    every path of its surface) and its version, and this table is the list of them: the gate holds
    each to the surface rustdoc JSON gives for upstream's.

    `wz_package` is the package of the wz crate. It equals `package` for every member except `zenoh`,
    which keeps its first name until the slice that makes it patchable renames it.

    `missing` is the RATCHET of the member: the count of upstream lines per arm the wz crate does
    not yet have. A slice that lands lowers it in the same round; a count that rises is a regression
    and a count that falls without moving it is progress the record has not taken. Either way the
    gate fails until this table is the measurement.

    `split_wz` says the wz crate declares the features that split the arms, so its surface is
    emitted once per arm with that arm's features and held to that arm. A crate that declares none
    of them has the one surface, held to every arm, and the lines only an arm's features add are
    missing there; the flag is turned on in the slice that gives the features meaning."""

    package: str
    lib: str
    wz_package: str
    arms: tuple[tuple[str, str], ...]
    missing: dict[str, int]
    split_wz: bool = False


MEMBERS: tuple[Member, ...] = (
    Member("zenoh", "zenoh", "zenoh", ARMS,
           {"default": 301, "unstable": 438, "unstable-shared-memory": 442}, split_wz=True),
    Member("zenoh-result", "zenoh_result", "zenoh-result", DEFAULT_ARM, {"default": 0}),
    Member("zenoh-runtime", "zenoh_runtime", "zenoh-runtime", DEFAULT_ARM, {"default": 0}),
    Member("zenoh-core", "zenoh_core", "zenoh-core", DEFAULT_ARM, {"default": 0}),
    Member("zenoh-keyexpr", "zenoh_keyexpr", "zenoh-keyexpr",
           (("default", ""), ("unstable", "unstable")), {"default": 0, "unstable": 0},
           split_wz=True),
    Member("zenoh-macros", "zenoh_macros", "zenoh-macros", DEFAULT_ARM, {"default": 0}),
    Member("zenoh-collections", "zenoh_collections", "zenoh-collections", DEFAULT_ARM,
           {"default": 0}),
    Member("zenoh-buffers", "zenoh_buffers", "zenoh-buffers",
           (("default", ""), ("shared-memory", "shared-memory"), ("test", "test")),
           {"default": 0, "shared-memory": 0, "test": 0}, split_wz=True),
    Member("zenoh-protocol", "zenoh_protocol", "zenoh-protocol", ARMS,
           {"default": 0, "unstable": 0, "unstable-shared-memory": 0},
           split_wz=True),
    Member("zenoh-codec", "zenoh_codec", "zenoh-codec",
           (("default", ""), ("shared-memory", "shared-memory")),
           {"default": 0, "shared-memory": 0}, split_wz=True),
    Member("zenoh-shm", "zenoh_shm", "zenoh-shm", (("default", ""), ("test", "test")),
           {"default": 0, "test": 0}, split_wz=True),
    Member("zenoh-util", "zenoh_util", "zenoh-util", (("default", ""), ("test", "test")),
           {"default": 0, "test": 0}, split_wz=True),
    Member("zenoh-config", "zenoh_config", "zenoh-config",
           (("default", ""), ("unstable", "unstable"), ("transport_tcp", "transport_tcp")),
           {"default": 0, "unstable": 0, "transport_tcp": 0}, split_wz=True),
)


def wz_arms(member: Member) -> tuple[tuple[str | None, str], ...]:
    """The surfaces a member's wz crate is emitted as: one per arm when it declares the arms'
    features, else the one, which has no arm name."""
    return member.arms if member.split_wz else ((None, ""),)

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


# ── signatures ──────────────────────────────────────────────────────────────
#
# A function's line carries what a caller or an implementer can depend on: its generics and
# their bounds, the TYPES of its parameters (a receiver included) and its return type, its
# qualifiers, and, for an inherent method, the `impl` block it sits in. What it leaves out is
# what is not part of the contract: parameter names, lifetime names (renamed by order of first
# appearance, `'static` and `'_` kept), and the order of bounds and of `where` predicates. The
# order of generic parameters IS part of the contract (a turbofish is positional) and is kept.
#
# A type or trait is named by its PUBLIC path when the crate exposes it and by its defining path
# otherwise, as in an `impl` line. Every shape of rustdoc JSON a signature can hold is read; one
# this reader does not know is refused rather than skipped, because a line that silently omitted
# a part of a signature would say two different functions are the same.


class _Names:
    """Resolves the ids of a document to the paths a surface line spells."""

    def __init__(self, doc: dict, public: dict[str, str]) -> None:
        self.doc = doc
        self.public = public

    def path(self, ident, fallback: str = "?") -> str:
        ident = _id(ident)
        return self.public.get(ident) or _path_of(self.doc, ident) or fallback


def _unknown(what: str, value) -> InputError:
    return InputError(f"rustdoc JSON holds a {what} this reader does not know: {str(value)[:160]}")


def _render_args(names: _Names, args) -> str:
    if not args:
        return ""
    if "angle_bracketed" in args:
        body = args["angle_bracketed"]
        parts: list[str] = []
        for arg in body.get("args", []):
            if arg == "infer":
                parts.append("_")
            elif "lifetime" in arg:
                parts.append(arg["lifetime"])
            elif "type" in arg:
                parts.append(_render_type(names, arg["type"]))
            elif "const" in arg:
                parts.append(str(arg["const"].get("expr")))
            else:
                raise _unknown("generic argument", arg)
        for con in body.get("constraints", []):
            binding = con.get("binding", {})
            if "equality" in binding:
                term = binding["equality"]
                rhs = _render_type(names, term["type"]) if "type" in term else str(term["constant"].get("expr"))
                parts.append(f"{con['name']}{_render_args(names, con.get('args'))} = {rhs}")
            elif "constraint" in binding:
                parts.append(f"{con['name']}: {_render_bounds(names, binding['constraint'])}")
            else:
                raise _unknown("associated item constraint", con)
        return f"<{', '.join(parts)}>" if parts else ""
    if "parenthesized" in args:
        body = args["parenthesized"]
        inputs = ", ".join(_render_type(names, t) for t in body.get("inputs", []))
        out = body.get("output")
        return f"({inputs})" + (f" -> {_render_type(names, out)}" if out else "")
    raise _unknown("generic arguments", args)


def _render_path(names: _Names, path: dict) -> str:
    return names.path(path.get("id"), path.get("path") or path.get("name") or "?") + _render_args(
        names, path.get("args"))


def _render_bounds(names: _Names, bounds: list) -> str:
    out: list[str] = []
    for bound in bounds:
        if "trait_bound" in bound:
            tb = bound["trait_bound"]
            mod = {"none": "", "maybe": "?", "maybe_const": "~const "}.get(tb.get("modifier", "none"))
            if mod is None:
                raise _unknown("trait bound modifier", tb)
            hrtb = ""
            if tb.get("generic_params"):
                hrtb = "for<" + ", ".join(p["name"] for p in tb["generic_params"]) + "> "
            out.append(f"{hrtb}{mod}{_render_path(names, tb['trait'])}")
        elif "outlives" in bound:
            out.append(bound["outlives"])
        else:
            raise _unknown("generic bound", bound)
    return " + ".join(sorted(out))


def _render_type(names: _Names, ty) -> str:
    if not isinstance(ty, dict) or len(ty) != 1:
        raise _unknown("type", ty)
    kind, body = next(iter(ty.items()))
    if kind == "primitive" or kind == "generic":
        return body
    if kind == "resolved_path":
        return _render_path(names, body)
    if kind == "borrowed_ref":
        life = f"{body['lifetime']} " if body.get("lifetime") else ""
        return f"&{life}{'mut ' if body.get('is_mutable') else ''}{_render_type(names, body['type'])}"
    if kind == "raw_pointer":
        return f"*{'mut' if body.get('is_mutable') else 'const'} {_render_type(names, body['type'])}"
    if kind == "slice":
        return f"[{_render_type(names, body)}]"
    if kind == "array":
        return f"[{_render_type(names, body['type'])}; {body['len']}]"
    if kind == "tuple":
        return "(" + ", ".join(_render_type(names, t) for t in body) + ")"
    if kind == "impl_trait":
        return "impl " + _render_bounds(names, body)
    if kind == "dyn_trait":
        traits = sorted(_render_path(names, t["trait"]) for t in body.get("traits", []))
        if body.get("lifetime"):
            traits.append(body["lifetime"])
        return "dyn " + " + ".join(traits)
    if kind == "qualified_path":
        trait = f" as {_render_path(names, body['trait'])}" if body.get("trait") else ""
        return f"<{_render_type(names, body['self_type'])}{trait}>::{body['name']}{_render_args(names, body.get('args'))}"
    if kind == "function_pointer":
        sig = body["sig"]
        ins = ", ".join(_render_type(names, t) for _n, t in sig.get("inputs", []))
        out = f" -> {_render_type(names, sig['output'])}" if sig.get("output") else ""
        quals = [q for q in ("is_unsafe", "is_const", "is_async") if body.get("header", {}).get(q)]
        return f"{'unsafe ' if 'is_unsafe' in quals else ''}fn({ins}){out}"
    raise _unknown("type", ty)


def _render_generics(names: _Names, generics: dict) -> tuple[str, str]:
    """(`<params>`, ` where predicates`) of a generics block, either possibly empty. A parameter
    rustc made up for an `impl Trait` argument is not a parameter a caller can name, so it is not
    listed; its bounds are in the argument's own type."""
    params: list[str] = []
    for p in generics.get("params", []):
        kind, body = next(iter(p["kind"].items()))
        if kind == "lifetime":
            outl = f": {' + '.join(sorted(body.get('outlives', [])))}" if body.get("outlives") else ""
            params.append(f"{p['name']}{outl}")
        elif kind == "type":
            if body.get("is_synthetic"):
                continue
            bounds = f": {_render_bounds(names, body['bounds'])}" if body.get("bounds") else ""
            default = f" = {_render_type(names, body['default'])}" if body.get("default") else ""
            params.append(f"{p['name']}{bounds}{default}")
        elif kind == "const":
            default = f" = {body['default']}" if body.get("default") else ""
            params.append(f"const {p['name']}: {_render_type(names, body['type'])}{default}")
        else:
            raise _unknown("generic parameter", p)
    synthetic = {p["name"] for p in generics.get("params", [])
                 if p["kind"].get("type", {}).get("is_synthetic")}
    preds: list[str] = []
    for w in generics.get("where_predicates", []):
        kind, body = next(iter(w.items()))
        if kind == "bound_predicate":
            if isinstance(body.get("type"), dict) and body["type"].get("generic") in synthetic:
                continue
            hr = ""
            if body.get("generic_params"):
                hr = "for<" + ", ".join(g["name"] for g in body["generic_params"]) + "> "
            preds.append(f"{hr}{_render_type(names, body['type'])}: {_render_bounds(names, body['bounds'])}")
        elif kind == "lifetime_predicate":
            preds.append(f"{body['lifetime']}: {' + '.join(sorted(body.get('outlives', [])))}")
        elif kind == "eq_predicate":
            rhs = body["rhs"]
            preds.append(f"{_render_type(names, body['lhs'])} == "
                         + (_render_type(names, rhs["type"]) if "type" in rhs else str(rhs["constant"].get("expr"))))
        else:
            raise _unknown("where predicate", w)
    return (f"<{', '.join(params)}>" if params else ""), (f" where {', '.join(sorted(preds))}" if preds else "")


_LIFETIME = re.compile(r"'[A-Za-z_][A-Za-z0-9_]*")


def _canonical_lifetimes(text: str) -> str:
    """Lifetime names by order of first appearance; `'static` and `'_` are not names."""
    seen: dict[str, str] = {}

    def rename(m: re.Match) -> str:
        name = m.group(0)
        if name in ("'static", "'_"):
            return name
        return seen.setdefault(name, f"'{len(seen)}")

    return _LIFETIME.sub(rename, text)


def render_function(names: _Names, path: str, item: dict, impl: dict | None = None) -> str:
    """The surface line of one function item, in the `impl` block `impl` if it is a method."""
    fn = item.get("inner", {}).get("function")
    sig = fn.get("sig") if fn else None
    if not sig or "inputs" not in sig:
        raise InputError(f"rustdoc JSON function `{path}` has no signature to read")
    params, where = _render_generics(names, fn.get("generics", {}))
    ins = ", ".join(_render_type(names, t) for _n, t in sig["inputs"])
    out = f" -> {_render_type(names, sig['output'])}" if sig.get("output") else ""
    quals = [q[3:] for q in ("is_const", "is_async", "is_unsafe") if fn.get("header", {}).get(q)]
    line = f"fn {path}{params}({ins}){out}{where}"
    if quals:
        line += f" ; {' '.join(quals)}"
    if impl is not None:
        iparams, iwhere = _render_generics(names, impl.get("generics", {}))
        line += f" ; in impl{iparams} {_render_type(names, impl.get('for'))}{iwhere}"
    return _canonical_lifetimes(line)


def normalise(doc: dict, fmt: int, lib: str = "zenoh") -> list[str]:
    """The surface lines of one rustdoc JSON document, sorted and unique. `lib` is the library name
    the paths of the crate are rooted at."""
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
    # Functions are rendered once every public path is known, so a type a signature names is
    # spelled by the path the crate exposes it at wherever in the walk that path was found.
    functions: list[tuple[str, dict, dict | None]] = []  # (path, item, the impl it is in)
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
            if kind == "function":
                functions.append((path, item, None))
            else:
                lines.add(f"{ITEM_KINDS[kind]} {path}")
            if ident not in public:
                public[ident] = path
                if kind in ("struct", "enum", "union"):
                    types.append((path, item))

    visit_module(root, lib)

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
                        functions.append((f"{path}::{fn.get('name')}", fn, impl))
            else:
                tid = _id(trait.get("id"))
                tname = public.get(tid) or _path_of(doc, tid) or trait.get("path") or trait.get("name")
                lines.add(f"impl {tname} for {_type_name(doc, impl.get('for'), public) if impl.get('for') else path}")

    names = _Names(doc, public)
    for path, item, impl in functions:
        lines.add(render_function(names, path, item, impl))
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


def emit(toolchain: str, member: Member, features: str) -> dict:
    """rustdoc JSON of one upstream crate of the family with one feature set, from the pinned source."""
    source = upstream_root()
    cmd = ["cargo", f"+{toolchain}", "rustdoc", "-p", member.package, "--lib", "--locked",
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
    out = TARGET_DIR / "doc" / f"{member.lib}.json"
    try:
        return json.loads(out.read_text())
    except (OSError, json.JSONDecodeError) as e:
        raise InputError(f"rustdoc wrote no readable JSON at {out} ({e})") from e


def emit_wz(toolchain: str, member: Member, features: str = "") -> dict:
    """rustdoc JSON of the wz crate of one member with one feature set, from this tree."""
    target_dir = TARGET_DIR / member.wz_package
    cmd = ["cargo", f"+{toolchain}", "rustdoc", "-p", member.wz_package, "--lib", "--locked",
           "--target-dir", str(target_dir)]
    if features:
        cmd += ["--features", features]
    cmd += ["--", "-Z", "unstable-options", "--output-format", "json"]
    proc = subprocess.run(cmd, cwd=ROOT / "crates", capture_output=True, text=True, check=False)
    if proc.returncode != 0:
        raise InputError(
            f"`{' '.join(cmd)}` in crates/ failed (rc={proc.returncode}): "
            f"{proc.stderr.strip()[-2000:] or '<no stderr>'}"
        )
    out = target_dir / "doc" / f"{member.lib}.json"
    try:
        return json.loads(out.read_text())
    except (OSError, json.JSONDecodeError) as e:
        raise InputError(f"rustdoc wrote no readable JSON at {out} ({e})") from e


def wz_surface_file(member: Member, arm: str | None = None) -> Path:
    # `-wz-<arm>`: the wz crate has upstream's package name, so `<package>-<version>-<arm>` is the
    # file of upstream's own surface for that arm.
    suffix = f"-wz-{arm}" if arm else ""
    return SURFACE_DIR / f"{member.wz_package}-{census.UPSTREAM_VERSION}{suffix}.surface"


def wz_header(toolchain: str, fmt: int, member: Member) -> list[str]:
    return [
        "# Generated by scripts/lib/rust_api_surface.py --write. Do not edit.",
        f"# compatibility crate: {member.wz_package} {census.UPSTREAM_VERSION}",
        f"# toolchain: {toolchain}",
        f"# format_version: {fmt}",
    ]


def compatibility_arm(toolchain: str, fmt: int, member: Member) -> list[str]:
    """Does the committed surface of a wz crate hold to every upstream arm of its member?

    It may carry no line upstream does not (C10: a wz-only door is in `wz::ext`), and the lines
    of each arm it does not carry yet must number exactly `member.missing[arm]`."""
    failures: list[str] = []
    upstream = {arm: read_surface(surface_file(member, arm))[1] for arm, _features in member.arms}
    if set(member.missing) != set(upstream):
        failures.append(f"{member.package}: the ratchet names arm(s) {sorted(member.missing)} and the "
                        f"member has {sorted(upstream)}")
        return failures
    wz_by_arm: dict[str | None, list[str]] = {}
    for arm, _features in wz_arms(member):
        path = wz_surface_file(member, arm)
        if not path.is_file():
            return failures + [f"{path.relative_to(ROOT)} is missing -- emit it with --write"]
        meta, wz = read_surface(path)
        for key, value in (("toolchain", toolchain), ("format_version", str(fmt))):
            if meta.get(key) != value:
                failures.append(f"{path.relative_to(ROOT)} says {key} `{meta.get(key)}`, the pin "
                                f"says `{value}` -- re-emit it")
        if wz != sorted(set(wz)):
            failures.append(f"{path.relative_to(ROOT)} is not sorted and unique -- not this "
                            f"script's output")
        wz_by_arm[arm] = wz
    if not member.split_wz:
        return failures + compatibility_check(wz_by_arm[None], upstream, member.missing,
                                              member.wz_package)
    # Each arm is held to the surface the wz crate has WITH that arm's features.
    for arm, lines in upstream.items():
        failures += compatibility_check(wz_by_arm[arm], {arm: lines}, member.missing,
                                        member.wz_package)
    return failures


def compatibility_check(wz: list[str], upstream: dict[str, list[str]],
                        pin: dict[str, int], who: str = "wz-zenoh") -> list[str]:
    """A wz crate's surface against each upstream arm: no extra line, and exactly the pinned number
    of missing ones."""
    failures: list[str] = []
    for arm, lines in upstream.items():
        extra = sorted(set(wz) - set(lines))
        missing = len(set(lines) - set(wz))
        failures += [f"{who} {arm}: the crate has `{line}`, which upstream does not "
                     f"(a wz-only door belongs in wz::ext)" for line in extra[:40]]
        if missing != pin[arm]:
            way = "fell" if missing < pin[arm] else "ROSE"
            failures.append(f"{who} {arm}: {missing} upstream line(s) are missing from the crate "
                            f"and the ratchet (`Member.missing`) says {pin[arm]}: the count {way}; "
                            f"move the pin in this round if a slice landed, never to absorb a loss")
        print(f"  rust-api-surface: {who} against {arm}: {len(lines) - missing} of "
              f"{len(lines)} line(s), {missing} missing, {len(extra)} extra")
    return failures


def surface_file(member: Member, arm: str) -> Path:
    return SURFACE_DIR / f"{member.package}-{census.UPSTREAM_VERSION}-{arm}.surface"


def header(toolchain: str, fmt: int, member: Member, arm: str, features: str) -> list[str]:
    return [
        "# Generated by scripts/lib/rust_api_surface.py --write. Do not edit.",
        f"# upstream: {member.package} {census.UPSTREAM_VERSION}",
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
    for member in MEMBERS:
        for arm, features in member.arms:
            path = surface_file(member, arm)
            if not path.is_file():
                failures.append(f"{path.relative_to(ROOT)} is missing -- emit it with --write")
                continue
            meta, body = read_surface(path)
            want = dict(line[2:].partition(": ")[::2]
                        for line in header(toolchain, fmt, member, arm, features)[1:])
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
                f"  rust-api-surface: {member.package} {arm}: {len(body)} line(s) -- "
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

    def _fn(inputs, output, params=(), where=(), header=None):
        return {"sig": {"inputs": [list(i) for i in inputs], "output": output, "is_c_variadic": False},
                "generics": {"params": list(params), "where_predicates": list(where)},
                "header": header or {}, "has_body": True}

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
            "6": {"name": "open", "visibility": "public", "inner": {"function": _fn([], None)}},
            "7": {"name": None, "visibility": "public",
                  "inner": {"use": {"source": "zenoh_core::Resolvable", "name": "Resolvable", "id": 91, "is_glob": False}}},
            "10": {"name": "Session", "visibility": "public",
                   "inner": {"struct": {"impls": [20, 21, 22, 23, 24]}}},
            "11": {"name": "private_fn", "visibility": "default", "inner": {"function": {}}},
            "20": {"visibility": "default", "inner": {"impl": {
                "trait": None, "items": [30, 31], "generics": {"params": [], "where_predicates": []},
                "for": {"resolved_path": {"path": "Session", "id": 10}}}}},
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
            "30": {"name": "put", "visibility": "public", "inner": {"function": _fn(
                [("self", {"borrowed_ref": {"lifetime": None, "is_mutable": False,
                                             "type": {"generic": "Self"}}}),
                 ("value", {"primitive": "u8"})], {"primitive": "bool"})}},
            "31": {"name": "internal", "visibility": "default", "inner": {"function": {}}},
        },
    }
    want = [
        "fn zenoh::open()",
        "fn zenoh::session::Session::put(&Self, u8) -> bool ; in impl zenoh::session::Session",
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
    # Signatures: every shape a type and a bound can take, and the normalisations.
    names = _Names({"paths": {"1": {"path": ["core", "convert", "Into"]},
                              "2": {"path": ["core", "ops", "Fn"]},
                              "3": {"path": ["alloc", "string", "String"]}}}, {"9": "zenoh::KeyExpr"})
    ref = lambda inner, life=None, mut=False: {"borrowed_ref": {"lifetime": life, "is_mutable": mut, "type": inner}}
    path = lambda i, args=None: {"resolved_path": {"path": "X", "id": i, "args": args}}
    angle = lambda *a, cons=(): {"angle_bracketed": {"args": list(a), "constraints": list(cons)}}
    type_cases = [
        ("a public path wins over the defining one", path(9), "zenoh::KeyExpr"),
        ("a foreign type is its defining path", path(3), "alloc::string::String"),
        ("generic arguments, a lifetime first", path(9, angle({"lifetime": "'a"}, {"type": {"primitive": "u8"}})),
         "zenoh::KeyExpr<'a, u8>"),
        ("a reference with a lifetime and mut", ref({"generic": "T"}, "'a", True), "&'a mut T"),
        ("a slice, an array and a tuple",
         {"tuple": [{"slice": {"primitive": "u8"}}, {"array": {"type": {"primitive": "u8"}, "len": "4"}}]},
         "([u8], [u8; 4])"),
        ("the unit tuple", {"tuple": []}, "()"),
        ("a raw pointer", {"raw_pointer": {"is_mutable": False, "type": {"primitive": "u8"}}}, "*const u8"),
        ("dyn, its traits sorted", {"dyn_trait": {"traits": [{"trait": {"path": "X", "id": 2, "args": None}},
                                                              {"trait": {"path": "X", "id": 1, "args": None}}],
                                                   "lifetime": "'static"}},
         "dyn core::convert::Into + core::ops::Fn + 'static"),
        ("a qualified path", {"qualified_path": {"name": "Error", "args": None, "self_type": {"generic": "D"},
                                                 "trait": {"path": "", "id": 1, "args": None}}},
         "<D as core::convert::Into>::Error"),
        ("a parenthesized Fn bound's arguments", path(2, {"parenthesized": {"inputs": [{"primitive": "u8"}],
                                                                           "output": {"primitive": "bool"}}}),
         "core::ops::Fn(u8) -> bool"),
        ("an associated type binding", path(1, angle(cons=[{"name": "Output", "args": None,
                                                              "binding": {"equality": {"type": {"primitive": "u8"}}}}])),
         "core::convert::Into<Output = u8>"),
    ]
    for label, ty, expected in type_cases:
        got = _render_type(names, ty)
        if got != expected:
            print(f"  selftest FAIL [{label}]: {got!r}, not {expected!r}", file=sys.stderr)
            return 1
    try:
        _render_type(names, {"pattern": {}})
    except InputError:
        pass
    else:
        print("  selftest FAIL [a type kind this reader does not know]: ACCEPTED", file=sys.stderr)
        return 1
    if _canonical_lifetimes("fn f<'z, 'a>(&'a T, &'z U, &'static V, &'_ W) -> &'a X") \
            != "fn f<'0, '1>(&'1 T, &'0 U, &'static V, &'_ W) -> &'1 X":
        print("  selftest FAIL [lifetimes renamed by first appearance]", file=sys.stderr)
        return 1
    bound = lambda i: {"trait_bound": {"trait": {"path": "X", "id": i, "args": None}, "generic_params": [],
                                       "modifier": "none"}}
    generics = {"params": [{"name": "T", "kind": {"type": {"bounds": [bound(2), bound(1)], "default": None,
                                                           "is_synthetic": False}}},
                           {"name": "impl Into", "kind": {"type": {"bounds": [], "default": None,
                                                                   "is_synthetic": True}}}],
                "where_predicates": [{"bound_predicate": {"type": {"generic": "U"}, "bounds": [bound(1)],
                                                          "generic_params": []}},
                                     {"bound_predicate": {"type": {"generic": "T"}, "bounds": [bound(2)],
                                                          "generic_params": []}},
                                     {"bound_predicate": {"type": {"generic": "impl Into"},
                                                          "bounds": [bound(1)], "generic_params": []}}]}
    if _render_generics(names, generics) != (
            "<T: core::convert::Into + core::ops::Fn>", " where T: core::ops::Fn, U: core::convert::Into"):
        print(f"  selftest FAIL [generics: bounds and predicates sorted, a synthetic parameter left out]: "
              f"{_render_generics(names, generics)}", file=sys.stderr)
        return 1
    one = {"inner": {"function": _fn([("a", {"primitive": "u8"})], None,
                                     header={"is_unsafe": True, "is_async": True})}}
    two = {"inner": {"function": _fn([("b", {"primitive": "u8"})], None,
                                     header={"is_unsafe": True, "is_async": True})}}
    if render_function(names, "p", one) != render_function(names, "p", two) \
            or not render_function(names, "p", one).endswith(" ; async unsafe"):
        print(f"  selftest FAIL [a parameter name is not surface; qualifiers are]: "
              f"{render_function(names, 'p', one)!r}", file=sys.stderr)
        return 1
    if render_function(names, "p", {"inner": {"function": _fn([("a", {"primitive": "u8"})], None)}}) \
            == render_function(names, "p", {"inner": {"function": _fn([("a", {"primitive": "u16"})], None)}}):
        print("  selftest FAIL [two parameter types are two signatures]", file=sys.stderr)
        return 1
    try:
        render_function(names, "p", {"inner": {"function": {}}})
    except InputError:
        pass
    else:
        print("  selftest FAIL [a function with no signature]: ACCEPTED", file=sys.stderr)
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
    # The root of a path is the library name of the crate it describes, so one normaliser reads
    # every member of the family: the same document rooted as `zenoh_core` says `zenoh_core::...`.
    rooted = normalise(doc, 57, "zenoh_core")
    if "mod zenoh_core::session" not in rooted or any(line.startswith("mod zenoh::") for line in rooted):
        print("  selftest FAIL [the library name roots every path]", file=sys.stderr)
        return 1
    # The table of members is the population the gate guards: a package listed twice, a library
    # name that is not the package's with `_` for `-` (what Cargo makes of it), or a ratchet that
    # names other arms than the member has would each leave a crate unguarded without a failure.
    packages = [m.package for m in MEMBERS]
    if len(set(packages)) != len(packages) or not MEMBERS:
        print(f"  selftest FAIL [the members are not a non-empty set of packages]: {packages}",
              file=sys.stderr)
        return 1
    for m in MEMBERS:
        if m.lib != m.package.replace("-", "_") or set(m.missing) != {a for a, _f in m.arms}:
            print(f"  selftest FAIL [member {m.package} is inconsistent with its own arms]", file=sys.stderr)
            return 1
    print(f"  rust-api-surface: selftest -- the normaliser over {len(want)} lines, {len(type_cases)} "
          f"type shapes, the generics, qualifiers and refusals, and the comparison pass")
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(description="the pinned zenoh family's public Rust API surfaces")
    mode = ap.add_mutually_exclusive_group()
    mode.add_argument("--upstream", action="store_true", help="re-emit every arm and compare")
    mode.add_argument("--write", action="store_true", help="re-emit every arm and overwrite")
    mode.add_argument("--selftest", action="store_true", help="drive the normaliser on a fixture")
    ap.add_argument("--member", choices=[m.package for m in MEMBERS],
                    help="with --upstream or --write, re-emit this crate of the family only")
    args = ap.parse_args()
    if args.selftest:
        return selftest()
    members = tuple(m for m in MEMBERS if args.member in (None, m.package))

    try:
        toolchain, fmt = read_pin()
        if args.write or args.upstream:
            failures: list[str] = []
            for member in members:
                for arm, features in member.arms:
                    lines = normalise(emit(toolchain, member, features), fmt, member.lib)
                    path = surface_file(member, arm)
                    if args.write:
                        path.parent.mkdir(parents=True, exist_ok=True)
                        path.write_text("\n".join(header(toolchain, fmt, member, arm, features) + lines) + "\n")
                        print(f"  rust-api-surface: wrote {path.relative_to(ROOT)} ({len(lines)} lines)")
                    else:
                        _, old = read_surface(path)
                        diff = compare(old, lines)
                        failures += [f"{member.package} {arm}: {d}" for d in diff]
                        print(f"  rust-api-surface: {member.package} {arm}: re-emitted {len(lines)} "
                              f"line(s), {len(diff)} difference(s)")
                for arm, features in wz_arms(member):
                    wz_lines = normalise(emit_wz(toolchain, member, features), fmt, member.lib)
                    path = wz_surface_file(member, arm)
                    if args.write:
                        path.write_text("\n".join(wz_header(toolchain, fmt, member) + wz_lines) + "\n")
                        print(f"  rust-api-surface: wrote {path.relative_to(ROOT)} ({len(wz_lines)} lines)")
                    else:
                        _, old = read_surface(path)
                        diff = compare(old, wz_lines)
                        failures += [f"{member.wz_package} {arm or ''}: {d}" for d in diff]
                        print(f"  rust-api-surface: {member.wz_package} {arm or ''}: re-emitted "
                              f"{len(wz_lines)} line(s), {len(diff)} difference(s)")
                if not args.write:
                    failures += compatibility_arm(toolchain, fmt, member)
            if failures:
                for f in failures:
                    print(f"  rust-api-surface: FAIL -- {f}", file=sys.stderr)
                return 1
            return 0
        failures = committed_arm(toolchain, fmt)
        for member in MEMBERS:
            failures += compatibility_arm(toolchain, fmt, member)
    except InputError as e:
        print(f"  rust-api-surface: INPUT -- {e}", file=sys.stderr)
        return 2
    print(
        "    -- upstream arm DEFERRED: run with --upstream where the pinned zenoh source and the "
        f"{toolchain} toolchain are provisioned (Layer Z); it re-emits both surfaces of every member, "
        "upstream's and the wz crate's, and holds the committed files to them."
    )
    if failures:
        for f in failures:
            print(f"  rust-api-surface: FAIL -- {f}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
