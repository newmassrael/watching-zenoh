#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
# SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

"""R2115 (no register item) — a consumer who reaches for a FEATURE-GATED path
must be told WHICH FEATURE, and the compiler is the one asked.

Closes item 239 of the unregistered register, which lives outside this
repository -- which is why the citation above reads "no register item", the
same way `cdylib_soname_gate.py` does for item 521.

## The item, and how its premise turned out

Item 239 said a new consumer of `wz-capture` gets `could not find 'fields_json'
in 'wz_capture'` -- the module is not missing, the feature is off -- and that
"nothing at that point tells them which feature". It also recorded why the
obvious remedy is wrong: `compile_error!` is not lazy, so an arm that carries
one breaks every default build.

MEASURED before writing any of this, on rustc 1.97, with a real consumer crate
outside the workspace naming `wz_capture::fields_json::fields_json`:

    error[E0433]: cannot find `fields_json` in `wz_capture`
    note: found an item that was configured out
      --> crates/wz-capture/src/lib.rs:99:9
       |   ------------------- the item is gated behind the `dissect` feature

The premise is REFUTED. The toolchain grew the diagnostic and the item's reason
outlived the thing it described -- open-debt item 47's class, arriving in a
register entry rather than in a comment. A `use` import (E0432) gets the same
note; both shapes were run.

## So why a gate rather than a note saying "the compiler handles it"

Because that sentence is exactly what would rot next. The property holds today
for a reason nothing in this tree holds down: rustc emits the note only when the
`#[cfg(feature = ...)]` sits ON the item it configured out. Move the gate into a
`cfg_if!`, behind a re-export, or one module further in, and the note goes with
it -- silently, because the consumer who would have noticed is not in this
repository. A toolchain that stops emitting it does the same.

So the compiler is made an ORACLE instead of a claim: this builds a real
consumer crate against a real feature-off `wz-capture` and reads what rustc
says. Three ways to fail, and the middle one is the point:

  * the build SUCCEEDS -- the path is reachable without the feature, so the
    probe has been measuring nothing. A dead probe and a negative result are
    the same exit code, which is what this workspace keeps paying for;
  * the build fails and the note does NOT name the feature -- the consumer is
    back to guessing, which is the item;
  * a declared feature has no probe and no reason -- silence.

## Where the population comes from

`cargo metadata`, not a grep over the source. The features a package declares
and the transitive closure of `default` are cargo's own answer; every feature
outside that closure has to be either PROBED or declared as gating no public
path. A feature added tomorrow fails this until somebody decides which it is.

## What it deliberately does NOT cover, said out loud

ONE package. The axis is scoped to `wz-capture`, which is the crate item 239 is
about, and the banner counts the workspace packages it does not reach so the
bound is a number rather than an impression. Widening it is a decision about
how much build time a static-ish lane may spend, not an oversight here.
"""

from __future__ import annotations

import json
import os
import pathlib
import re
import shutil
import subprocess
import sys
import tempfile

ROOT = pathlib.Path(__file__).resolve().parents[2]
WORKSPACE = ROOT / "crates"

# The packages this axis covers, each with the library name a consumer spells
# in a path. R2193 made this a TABLE rather than a single constant: the
# workspace-wide denominator is derived by `feature_public_surface_census.py`
# from this module's tables, and a single-package constant made that derivation
# unable to follow the axis anywhere else -- which was measured, not assumed.
AXIS: dict[str, str] = {
    "wz-capture": "wz_capture",
    # R2194 — the largest public surface in the workspace, and the one an
    # external consumer actually imports. 62 of its 80 non-default features
    # gate a public item, and 44 of those gate one at the CRATE ROOT, where the
    # path a consumer would type is derivable rather than hand-written.
    "wz-runtime-tokio": "wz_runtime_tokio",
}

# package -> feature -> the probes that prove a consumer is told about it.
#
# Each probe is a whole `src/lib.rs` for a throwaway consumer. TWO SHAPES on
# purpose: a path expression resolves through E0433 and an import through
# E0432, and they are separate code paths in rustc -- a note present on one and
# absent on the other is precisely the half-answer this axis exists to catch.
# R2195 — each probe is `(label, body, extra features the PATH needs)`. The
# third element exists because a public item can sit inside a module that is
# itself feature-gated: to ask "is the consumer told about the INNER feature",
# the OUTER one has to be ON, or rustc answers about the outer instead. Those
# extras are DERIVED from the `pub mod` chain, never typed.
PROBES: dict[str, dict[str, list[tuple[str, str, frozenset[str]]]]] = {
    "wz-capture": {
        "dissect": [
            (
                "a path expression",
                "pub fn reach(d: &wz_capture::Dissection, b: &[u8]) -> String {\n"
                "    wz_capture::fields_json::fields_json(d, b, None, None)\n"
                "}\n",
                frozenset(),
            ),
            (
                "an import",
                "use wz_capture::payload_decode::Declarations;\n"
                "pub fn hold(_d: &Declarations<'_>) {}\n",
                frozenset(),
            ),
        ],
    },
    # R2194 — nothing hand-written here: every probe for this package is read
    # off its crate root by `derived_probes`. The empty entry is not an
    # omission, it is what the table-agreement check requires a package on the
    # axis to have, and an empty one says "derived, none typed".
    "wz-runtime-tokio": {},
}

# package -> feature -> why it gates no public path. A reason is what the next
# reader needs: the alternative is an empty entry, which reads the same as
# "nobody got round to it".
#
# ⚠ THIS TABLE IS NOT BELIEVED. `feature_public_surface_census.py` derives, from
# every `#[cfg(feature)]` in the tree, which features gate a publicly-visible
# item -- and it FAILS on any name declared here that its derivation puts in
# the denominator. So a wrong entry is caught by a scan rather than by a
# reader, which is what keeps this from being the escape hatch a reason-string
# table would otherwise be.
NO_PUBLIC_PATH: dict[str, dict[str, str]] = {
    "wz-capture": {},
    "wz-runtime-tokio": {
        f: (
            "no `#[cfg]` in this package attaches this feature to a publicly "
            "visible item; it gates private items, expressions or struct "
            "fields only, which the census re-derives every run"
        )
        for f in (
            "access-extauth-usrpwd",
            "adminspace-metrics",
            "adminspace-read",
            "adminspace-router-linkstate",
            "adminspace-write",
            "config-mutate-runtime",
            "ext-pubsub-sample-miss-detection",
            "multicast-declarations",
            "reply-source-info",
            "router-connect-reconcile",
            "storage-history",
            "storage-mgr-complete-flag",
            "storage-mgr-strip-prefix",
            "storage-mgr-wildcard-updates",
            "switchboard",
            "transport-compression",
            "transport-fragmentation",
            "transport-link-tls-keylog",
        )
    },
}

# package -> feature -> why it is not probed YET, though it does gate a public
# item. A THIRD state, and it earns its place rather than being an escape
# hatch: `feature_public_surface_census.py` reads this table as the workspace's
# waiting list, prints its size beside the denominator every run, and FAILS
# both on a name here that no longer gates a public item AND on a
# public-gating feature that appears in none of the three tables. The list can
# therefore shrink or be corrected, but it cannot grow in silence.
#
# R2195 emptied the SUBMODULE half of this list: `submodule_probes` now follows
# the `pub mod` chain and names the whole path, so eighteen features that were
# waiting on "the path is not derivable" are probed instead. What is left is
# ONE reason, and it is a fact about rustc rather than about this workspace.
#
# MEASURED on rustc 1.97.0, first by widening the axis and then again when the
# submodule walk was written: when an item is gated by a COMPOUND cfg -- an
# `any(...)`, an `all(...)`, a target predicate -- the note reads "the item is
# gated here" and NAMES NO FEATURE. This axis exists to hold down the property
# that a consumer is told WHICH feature is missing, so a compound-gated item
# cannot be its witness: the probe would fail for a reason that is not the
# defect. Every feature below gates its only public item that way.
#
# `transport-link-tls` is NOT here, and the difference is the point: it has a
# simple-cfg item too, and the derivation prefers that one.
DEFERRED: dict[str, dict[str, str]] = {
    "wz-capture": {},
    "wz-runtime-tokio": {
        **{
            f: (
                "every public item it gates is behind a COMPOUND cfg, and "
                "rustc's note for those reads 'the item is gated here' without "
                "naming a feature -- measured on 1.97.0"
            )
            for f in (
                "live-capture",
                "plugin-dynamic-loading",
                "storage-mgr-dynamic-volume-loading",
                "time-hlc",
                "transport-link-raweth",
                "transport-link-unixpipe",
                "transport-link-vsock",
            )
        },
        # The SECOND reason, and R2195 found it by building probes for these
        # and watching them fail with a bare E0432 and NO note: what they gate
        # is a METHOD inside an `impl` block, spelled `Type::name` and never
        # `module::name`. Turning the feature off removes a method, which rustc
        # reports as E0599 -- a different diagnostic from the E0432/E0433 pair
        # this axis is about. The census still counts them in the denominator
        # because they ARE public surface; separating "public path" from
        # "public method" there is the work that would retire this class.
        **{
            f: (
                "it gates only METHODS inside `impl` blocks, so there is no "
                "`module::name` path to import; removing one is an E0599, not "
                "the E0432/E0433 this axis adjudicates"
            )
            for f in (
                "adminspace-introspection-handlers",
                "liveliness-get",
                "router-multicast-faces",
                "routing-interceptor-hotreload",
                "routing-token-tables",
                "transport-stats",
            )
        },
        # The THIRD reason, and the axis found it by building the probe and
        # watching it SUCCEED. `link_interfaces::multicast_iface_selector_v4`
        # is declared twice -- once under the feature, once under `not` -- so
        # turning it off swaps the body and leaves the path in place. There is
        # nothing for a consumer to be told about, because nothing disappears.
        # The derivation now sees such twins and declines them, and this row
        # records the one that taught it.
        "locator-iface": (
            "the only path it gates has a `cfg(not(...))` twin, so the feature "
            "swaps an implementation rather than removing a path -- there is "
            "no resolution error for rustc to annotate"
        ),
    },
}

# A crate-root item a `#[cfg(feature)]` is attached to, by the shape that names
# it. `pub mod X;`, `pub mod X {`, a re-export, an aliased re-export, and the
# plain item keywords -- every shape measured at the root of the two crates on
# this axis, with anything else left UNNAMED so it lands in the undecided arm
# rather than being guessed at.
ROOT_ITEM = [
    re.compile(r"^pub mod ([A-Za-z_][A-Za-z0-9_]*)\s*[;{]"),
    re.compile(r"^pub use (?:[A-Za-z_][A-Za-z0-9_]*::)*([A-Za-z_][A-Za-z0-9_]*)\s*;"),
    re.compile(
        r"^pub use (?:[A-Za-z_][A-Za-z0-9_:]*)\s+as\s+([A-Za-z_][A-Za-z0-9_]*)\s*;"
    ),
    re.compile(r"^pub (?:async\s+)?fn ([A-Za-z_][A-Za-z0-9_]*)"),
    re.compile(
        r"^pub (?:struct|enum|trait|type|const|static|union) "
        r"([A-Za-z_][A-Za-z0-9_]*)"
    ),
]
# ⚠ A SINGLE-feature cfg, and nothing else. MEASURED on rustc 1.97.0: when the
# attribute is a compound (`any(...)`, `all(...)`, a target predicate), the note
# rustc emits is "the item is gated HERE" -- it points at the line and does NOT
# name a feature. That is the very property this axis exists to hold down, so a
# compound-gated item cannot serve as its witness: the probe would fail for a
# reason the gate must not accept as a pass. Found by widening the axis, not by
# reasoning about it.
ROOT_FEATURE = re.compile(r'^#\[cfg\(feature\s*=\s*"([^"]+)"\)\]$')


PUB_MOD = re.compile(r"^\s*pub mod ([A-Za-z_][A-Za-z0-9_]*)\s*;")
FEATURE_NAME = re.compile(r'feature\s*=\s*"([^"]+)"')
SIMPLE_CFG = re.compile(r'^#\[cfg\(feature\s*=\s*"([^"]+)"\)\]$')
# The OTHER half of a two-implementation pair. R2195 measured this the
# expensive way: `multicast_iface_selector_v4` is declared twice in the same
# file, once under `cfg(feature = "locator-iface")` and once under
# `cfg(not(...))`, so turning the feature OFF does not remove the path -- it
# swaps the body. The probe compiled, which this axis correctly reports as
# "measuring nothing". A name with a `not` twin is not a witness for path
# disappearance, so the derivation has to see the twin.
NEGATED_CFG = re.compile(r'^#\[cfg\(not\(feature\s*=\s*"([^"]+)"\)\)\]$')
# Items whose name IS the last segment of a consumer's path.
#
# ⚠ ANCHORED AT COLUMN ZERO, and that is not tidiness. A `pub fn` INSIDE an
# `impl` block is a METHOD: `Type::with_acl`, never `module::with_acl`. The
# first version of this walk accepted indented items and produced five probes
# for paths that had never existed, which rustc reported as a bare E0432 with
# NO note at all -- correctly, since nothing was configured out. Column zero is
# the cheap, exact test for "declared directly in this module": an inline
# `mod X { ... }` body is indented too, and leaving it out is the
# under-reporting direction, which the census turns into a finding rather than
# a silence.
PATH_ITEM = re.compile(
    r"^pub\s+(?:async\s+|unsafe\s+|extern\s+\"[^\"]*\"\s+|const\s+|default\s+)*"
    r"(?:fn|struct|enum|trait|type|const|static|union|mod)\s+"
    r"([A-Za-z_][A-Za-z0-9_]*)"
)


def _attributes_above(lines: list[str], index: int) -> list[str]:
    """The attribute stack an item at `index` carries, nearest last."""
    out: list[str] = []
    j = index - 1
    while j >= 0:
        s = lines[j].strip()
        if s.startswith("#["):
            out.insert(0, s)
            j -= 1
            continue
        if s.startswith("//") or s == "":
            j -= 1
            continue
        break
    return out


def negated_names(lines: list[str]) -> set[str]:
    """Names declared under `cfg(not(feature = ...))` in this file.

    A name that has one of these has a body for the feature-off build too, so
    the path survives the feature going away and cannot witness its removal.
    """
    out: set[str] = set()
    for i, line in enumerate(lines):
        if not NEGATED_CFG.match(line):
            continue
        for j in range(i + 1, len(lines)):
            s = lines[j].strip()
            if s == "" or s.startswith("//") or s.startswith("#["):
                continue
            m = PATH_ITEM.match(lines[j])
            if m:
                out.add(m.group(1))
            break
    return out


def _module_file(base: pathlib.Path, name: str) -> pathlib.Path | None:
    for candidate in (base / f"{name}.rs", base / name / "mod.rs"):
        if candidate.is_file():
            return candidate
    return None


def public_module_tree(
    src: pathlib.Path,
) -> dict[str, tuple[tuple[str, ...], frozenset[str]]]:
    """Every file reachable from `lib.rs` through `pub mod`, with what it needs.

    The second element is the set of features the CHAIN requires -- a module
    declared under `#[cfg(feature = "x")]` puts `x` there, and everything below
    inherits it. That is what lets a probe turn the OUTER feature on while
    turning the inner one off, which is the only way to ask rustc about the
    inner one at all.

    For an `any(...)` chain attribute the first named feature is taken: one of
    them suffices to make the module exist, and which one is not the question
    being asked below.
    """
    tree: dict[str, tuple[tuple[str, ...], frozenset[str]]] = {}

    def walk(f: pathlib.Path, chain: tuple[str, ...], need: frozenset[str]) -> None:
        key = str(f.relative_to(src))
        if key in tree:
            return
        tree[key] = (chain, need)
        try:
            lines = f.read_text(encoding="utf-8").split("\n")
        except (UnicodeDecodeError, OSError):
            return
        base = src if f.name == "lib.rs" else (
            f.parent if f.name == "mod.rs" else f.parent / f.stem
        )
        for i, line in enumerate(lines):
            m = PUB_MOD.match(line)
            if not m:
                continue
            extra: set[str] = set()
            for attr in _attributes_above(lines, i):
                if "cfg(" not in attr:
                    continue
                named = FEATURE_NAME.findall(attr)
                if not named:
                    continue
                if attr.startswith("#[cfg(any("):
                    extra.add(sorted(named)[0])
                else:
                    extra.update(named)
            nxt = _module_file(base, m.group(1)) or _module_file(src, m.group(1))
            if nxt is None:
                continue
            walk(nxt, chain + (m.group(1),), need | frozenset(extra))

    walk(src / "lib.rs", (), frozenset())
    return tree


def submodule_probes(
    package: str, crate_path: str
) -> dict[str, list[tuple[str, str, frozenset[str]]]]:
    """Probes for public items INSIDE the public module tree.

    R2195. The crate-root derivation answers for items at the root; this one
    follows `pub mod` down and names the whole path. The chain's own features
    ride along as the probe's extras, so the module exists and only the item
    under test is missing -- otherwise rustc reports the OUTER feature and the
    probe would be asking a different question than the one it claims.

    A feature that appears in its own chain is skipped: the module it would
    have to turn on is the thing being turned off, and that item's absence is
    already the root derivation's subject.
    """
    src = WORKSPACE / package / "src"
    if not (src / "lib.rs").is_file():
        return {}
    found: dict[str, list[tuple[str, str, frozenset[str]]]] = {}
    for rel, (chain, need) in sorted(public_module_tree(src).items()):
        if not chain:
            continue
        try:
            lines = (src / rel).read_text(encoding="utf-8").split("\n")
        except (UnicodeDecodeError, OSError):
            continue
        twins = negated_names(lines)
        for i, line in enumerate(lines):
            # Column zero here too: an indented `#[cfg]` is attached to
            # something inside a block, and the item it gates is not a path.
            m = SIMPLE_CFG.match(line)
            if not m:
                continue
            feature = m.group(1)
            if feature in need:
                continue
            following = None
            for j in range(i + 1, len(lines)):
                s = lines[j].strip()
                if s == "" or s.startswith("//") or s.startswith("#["):
                    continue
                following = lines[j]
                break
            if following is None:
                continue
            im = PATH_ITEM.match(following)
            if not im or im.group(1) in twins:
                continue
            path = "::".join(chain + (im.group(1),))
            found.setdefault(feature, []).append(
                (
                    f"an import of `{path}`",
                    f"#[allow(unused_imports)]\nuse {crate_path}::{path};\n",
                    need,
                )
            )
    # One probe per feature, deterministically the shortest path then the
    # alphabetically first -- a shorter path crosses fewer gated modules.
    return {
        f: [sorted(v, key=lambda e: (len(e[0]), e[0]))[0]] for f, v in found.items()
    }


def derived_probes(package: str, crate_path: str) -> dict[str, list[tuple[str, str]]]:
    """Probes read off the crate ROOT, where the consumer's path is unambiguous.

    A `#[cfg(feature = "f")]` sitting on a crate-root `pub` item means the path
    `<crate>::<name>` exists only with `f` on. That is exactly the sentence a
    probe has to falsify, and it is derived rather than typed -- so a feature
    added tomorrow gets a probe without anyone remembering to write one, and a
    renamed module cannot leave a probe pointing at nothing.

    ONE probe per feature, on the alphabetically first name it gates. The
    question is whether a consumer is TOLD which feature is missing; asking it
    once per feature answers that, and asking it once per gated name would
    multiply the builds by a factor nothing here would learn from.

    Only the IMPORT shape is derivable: an E0433 path expression needs an item
    INSIDE the module, which the root does not name. `wz-capture`'s
    hand-written pair still carries both shapes, so the axis keeps a witness
    that the two rustc code paths behave alike.
    """
    root = WORKSPACE / package / "src" / "lib.rs"
    if not root.is_file():
        return {}
    names: dict[str, set[str]] = {}
    lines = root.read_text(encoding="utf-8").split("\n")
    for i, line in enumerate(lines):
        if not line.startswith("#[cfg") or "feature" not in line:
            continue
        feats = ROOT_FEATURE.findall(line.strip())
        if not feats:
            continue
        following = None
        for j in range(i + 1, len(lines)):
            s = lines[j].strip()
            if s == "" or s.startswith("//") or s.startswith("#["):
                continue
            following = lines[j]
            break
        if following is None or not following.startswith("pub "):
            continue
        for pattern in ROOT_ITEM:
            m = pattern.match(following)
            if m:
                for f in feats:
                    names.setdefault(f, set()).add(m.group(1))
                break
    return {
        f: [
            (
                f"a crate-root import of `{sorted(n)[0]}`",
                f"#[allow(unused_imports)]\nuse {crate_path}::{sorted(n)[0]};\n",
                frozenset(),
            )
        ]
        for f, n in names.items()
    }

# The rustc note this axis is about, as a template over the feature name.
#
# The WORDING is the toolchain's and this gate is deliberately pinned to it: a
# looser match ("configured out") would keep passing on the day rustc stops
# naming the feature, which is the whole property. If a rustc release rewords
# it, the fix is here and the round that makes it should say which release.
NOTE = "the item is gated behind the `{feature}` feature"


def metadata() -> dict:
    """Cargo's own answer about this workspace."""
    out = subprocess.run(
        [
            "cargo",
            "metadata",
            "--no-deps",
            "--format-version",
            "1",
            "--manifest-path",
            str(WORKSPACE / "Cargo.toml"),
        ],
        capture_output=True,
        text=True,
        check=False,
    )
    if out.returncode != 0:
        print(
            "feature-gate-diagnostic: FAIL -- cargo metadata did not run, so the "
            "feature population could not be derived. A population this gate "
            "could not read is not an empty one.",
            file=sys.stderr,
        )
        print(out.stderr[-2000:], file=sys.stderr)
        sys.exit(1)
    return json.loads(out.stdout)


def default_closure(features: dict[str, list[str]]) -> set[str]:
    """Every feature `default` turns on, transitively.

    `dep/feature` entries are another package's business and are skipped; what
    is wanted here is the set of THIS package's features a plain build has.
    """
    seen: set[str] = set()
    stack = list(features.get("default", []))
    while stack:
        name = stack.pop()
        if "/" in name or name in seen:
            continue
        if name not in features:
            continue
        seen.add(name)
        stack.extend(features[name])
    return seen


def build_probe(
    package: str,
    feature: str,
    label: str,
    body: str,
    enabled: list[str],
    target_dir: str,
) -> tuple[int, str]:
    """Compile one throwaway consumer against a feature-OFF `wz-capture`.

    The feature set is DERIVED: everything `default` would have turned on,
    minus the one under test, with `default-features = false` so the subtraction
    actually happens. That works the same for a feature outside the default set
    and for one inside it, which is what keeps this from needing a per-feature
    recipe nobody would maintain.
    """
    tmp = tempfile.mkdtemp(prefix="wz-feature-probe-")
    try:
        crate = pathlib.Path(tmp)
        (crate / "src").mkdir()
        (crate / "src" / "lib.rs").write_text(body)
        wanted = ", ".join(f'"{f}"' for f in sorted(enabled))
        (crate / "Cargo.toml").write_text(
            "[package]\n"
            'name = "wz-feature-probe"\n'
            'version = "0.0.0"\n'
            'edition = "2021"\n'
            "publish = false\n\n"
            "[dependencies]\n"
            f'{package} = {{ path = "{WORKSPACE / package}", '
            f"default-features = false, features = [{wanted}] }}\n\n"
            "[workspace]\n"
        )
        env = dict(os.environ)
        # The workspace's own target directory, so the dependencies this probe
        # needs are the ones the lane just built. Measured: 33s cold, 1s warm.
        env["CARGO_TARGET_DIR"] = target_dir
        out = subprocess.run(
            ["cargo", "build", "--manifest-path", str(crate / "Cargo.toml")],
            capture_output=True,
            text=True,
            check=False,
            env=env,
        )
        return out.returncode, out.stderr
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def main() -> int:
    meta = metadata()
    packages = {p["name"]: p for p in meta.get("packages", [])}
    if not packages:
        print(
            "feature-gate-diagnostic: FAIL -- cargo reported no workspace "
            "package at all.",
            file=sys.stderr,
        )
        return 1
    if not AXIS:
        print(
            "feature-gate-diagnostic: FAIL -- the axis covers no package, so "
            "every check below would pass over an empty set.",
            file=sys.stderr,
        )
        return 1

    findings: list[str] = []
    # The tables must name the same packages: a probe for a package the axis
    # does not claim, or a claimed package with no tables, is a row nobody
    # would notice going stale.
    for name, table in (
        ("PROBES", PROBES),
        ("NO_PUBLIC_PATH", NO_PUBLIC_PATH),
        ("DEFERRED", DEFERRED),
    ):
        for pkg in sorted(set(table) ^ set(AXIS)):
            findings.append(
                f"`{pkg}` appears in {name} or AXIS but not both -- the axis's "
                f"scope and its tables have to name the same packages"
            )

    # Probes read off each crate root, filled in per package below once its
    # optional set is known. The DERIVATION cannot filter itself: a crate root
    # gates DEFAULT features too, and a probe for one of those would turn off a
    # feature a plain build has -- a different question from the one this axis
    # asks. Measured: six such rows, reported as stale before this filter.
    all_probes: dict[str, dict[str, list[tuple[str, str]]]] = {}
    derived_count = 0

    optional_by_pkg: dict[str, set[str]] = {}
    default_by_pkg: dict[str, set[str]] = {}
    for pkg in sorted(AXIS):
        if pkg not in packages:
            findings.append(
                f"`{pkg}` is not a member of this workspace any more, so this "
                f"axis is pointed at nothing for it"
            )
            continue
        features: dict[str, list[str]] = packages[pkg].get("features", {})
        if not features:
            findings.append(
                f"`{pkg}` declares no feature, so this axis would pass over an "
                f"empty set for it"
            )
            continue
        enabled = default_closure(features)
        optional = {f for f in features if f != "default"} - enabled
        optional_by_pkg[pkg], default_by_pkg[pkg] = optional, enabled
        # Crate-root probes first; a submodule path only fills a feature the
        # root could not answer for, since a shorter path crosses fewer gates.
        derived = {
            f: v
            for f, v in submodule_probes(pkg, AXIS[pkg]).items()
            if f in optional
        }
        derived.update(
            {
                f: v
                for f, v in derived_probes(pkg, AXIS[pkg]).items()
                if f in optional
            }
        )
        derived_count += len(derived)
        # Hand-written probes merge OVER derived ones, so a deliberate probe
        # always wins.
        merged = dict(derived)
        merged.update(PROBES.get(pkg, {}))
        all_probes[pkg] = merged
        probes = merged
        none_gated, deferred = NO_PUBLIC_PATH.get(pkg, {}), DEFERRED.get(pkg, {})
        if not optional:
            findings.append(
                f"`{pkg}` has no feature outside its default set, so every path "
                f"is reachable from a plain build and this axis has nothing to "
                f"measure there -- an empty population reads exactly like total "
                f"compliance"
            )
        for feature in sorted(
            optional - set(probes) - set(none_gated) - set(deferred)
        ):
            findings.append(
                f"`{pkg}` declares the non-default feature `{feature}` and its "
                f"tables say nothing about it. Give it a probe naming a public "
                f"path it gates, an entry in NO_PUBLIC_PATH with the reason it "
                f"gates none, or a DEFERRED row with the reason it is waiting "
                f"-- a feature nobody decided about is the silence this axis "
                f"exists to refuse"
            )
        for a, b in (
            ("probed", "declared to gate no public path"),
            ("probed", "deferred"),
            ("declared to gate no public path", "deferred"),
        ):
            first = probes if a == "probed" else none_gated
            second = (
                none_gated if b == "declared to gate no public path" else deferred
            )
            for feature in sorted(set(first) & set(second)):
                findings.append(
                    f"`{pkg}` / `{feature}` is both {a} and {b}, and those "
                    f"cannot both be true"
                )
        for feature in sorted(
            (set(probes) | set(none_gated) | set(deferred)) - optional
        ):
            where = "a default feature" if feature in enabled else "no feature"
            findings.append(
                f"the tables name `{pkg}` / `{feature}` and that package has "
                f"{where} by that name -- the row is stale"
            )
        for feature, entries in sorted(probes.items()):
            if not entries:
                findings.append(
                    f"`{pkg}` / `{feature}` is listed as probed and carries no "
                    f"probe, which is a green result over nothing"
                )

    if findings:
        print("feature-gate-diagnostic: FAIL", file=sys.stderr)
        for f in findings:
            print(f"  - {f}", file=sys.stderr)
        return 1

    target_dir = str(WORKSPACE / "target")
    probed = 0
    for pkg in sorted(AXIS):
        optional, enabled = optional_by_pkg[pkg], default_by_pkg[pkg]
        for feature in sorted(set(all_probes.get(pkg, {})) & optional):
            for label, body, extra in all_probes[pkg][feature]:
                # The path's own gates ride along, minus the one under test.
                wanted = sorted((enabled | set(extra)) - {feature})
                rc, stderr = build_probe(
                    pkg, feature, label, body, wanted, target_dir
                )
                probed += 1
                if rc == 0:
                    findings.append(
                        f"`{pkg}` / `{feature}` / {label}: the probe COMPILED "
                        f"with the feature off, so the path it names is "
                        f"reachable without it and this probe has been "
                        f"measuring nothing"
                    )
                    continue
                want = NOTE.format(feature=feature)
                if want not in stderr:
                    findings.append(
                        f"`{pkg}` / `{feature}` / {label}: the build failed and "
                        f"rustc did not say `{want}`, so a consumer is left to "
                        f"work out that a feature is what is missing. Either "
                        f"the gate moved off the item it configures out (a "
                        f"`cfg_if`, a re-export, one module further in), or "
                        f"this toolchain no longer words the note this way -- "
                        f"the compiler's output is below"
                    )
                    findings.append(
                        "    " + "\n    ".join(stderr.strip().splitlines()[-25:])
                    )

    if findings:
        print("feature-gate-diagnostic: FAIL", file=sys.stderr)
        for f in findings:
            print(f"  - {f}", file=sys.stderr)
        return 1
    if not probed:
        print(
            "feature-gate-diagnostic: FAIL -- no probe was built, so nothing "
            "was asked of the compiler.",
            file=sys.stderr,
        )
        return 1

    covered = sum(len(optional_by_pkg[p]) for p in AXIS if p in optional_by_pkg)
    declared = sum(len(NO_PUBLIC_PATH.get(p, {})) for p in AXIS)
    waiting = sum(len(DEFERRED.get(p, {})) for p in AXIS)
    hand = sum(len(PROBES.get(p, {})) for p in AXIS)
    print(
        f"  feature-gate-diagnostic: {len(AXIS)} package(s) on this axis, "
        f"{covered} non-default feature(s) between them -- {declared} gating no "
        f"public path, {waiting} deferred with a reason, {hand} hand-written "
        f"probe set(s) and {derived_count} read off a crate root; {probed} "
        f"probe(s) built and every one told by rustc which feature was "
        f"missing. How much of the WORKSPACE that is, is not this gate's to "
        f"say and is derived by feature_public_surface_census.py from these "
        f"same tables."
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
