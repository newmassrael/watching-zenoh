#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
# SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
"""R2210 (no register item) — THE ANALYSIS SURFACES DO NOT REACH CONFIGURATION,
DERIVED, because until now that sentence was only WRITTEN.

Answers item 564 of the unregistered register, which lives outside this
repository -- the reason the citation above reads "no register item", the same
position `capi_c_config_surface.py` records for 548 and `armed_oracle_census.py`
for 562. The item is named in full below so a reader grepping for it lands here.

## The item, and why its answer is a derivation rather than a door

Item 564 reads "the inspector has no door to read the config list WITHOUT A
COPY", and its own instruction is that the work is a VERDICT first, not a build:
is comparing against the source enough, or is a door needed. The verdict is that
no new door is owed, and it rests on three facts:

  1. THE DOOR ALREADY EXISTS, on the surface that owns configuration --
     `wz_capi_c_config_honoured_count` / `wz_capi_c_config_honoured` in
     `wz-capi-c` (R2172, item 548), whose strings are `'static` and freed by
     nobody. `capi_c_config_surface.py` asks the linked artifact for them, so
     that fact is measured and not remembered.
  2. THE CONSUMER WITHDREW THE REQUEST in writing, and gave the condition under
     which it would come back: the comparison holds because the pin is present
     as source. That half is theirs to measure, not this tree's.
  3. A CONFIG DOOR ON THE ANALYSIS SURFACES WOULD CONTRADICT THE TREE'S OWN
     STRUCTURE -- neither of them reaches configuration at all.

Fact 3 was the only one nobody could ask a machine. It lived as PROSE in
`analysis_surface_parity.py`'s `NO_REACH_PATH`, whose entry says the surfaces
"take capture bytes and hand back documents". That table's header is candid
about its own limit: an entry is contradicted only when a capability ROW starts
naming the same number. Nothing looks at the surfaces themselves. A surface that
grew a configuration reader WITHOUT anybody adding such a row would leave the
sentence standing and false, which is the exemption-table shape R2194 recorded:
a reason table is an escape hatch unless a SEPARATE derivation can call it out.

This is that separate derivation.

## What it derives, and why each arm is a different route to the same lie

The subject is found rather than named. The configuration SSOT is the one
tracked file DEFINING `HONOURED_CONFIG_KEYS`; two definitions would be the
second copy this whole area exists to prevent, and zero means the fact moved.
The declaration this gate underwrites is then found in `NO_REACH_PATH` by
looking for the entry whose reason NAMES that file -- so the two cannot drift
apart, and neither a renumbered entry nor a moved module can quietly separate
the sentence from the thing it is about.

  BINDING  Exactly one `NO_REACH_PATH` entry names the SSOT file. None means
           the declaration this derivation was written for is gone and somebody
           must decide again; more than one means one fact under two labels.

  CLOSURE  The PACKAGE owning the SSOT is absent from each surface's dependency
           closure -- transitively over normal and build edges, plus the
           surface's OWN dev edges, so a test-only route is inside the question
           rather than exempted from it. A surface that cannot name the module
           cannot read it.

  COPY     No honoured key appears in a STRING LITERAL of either surface's own
           tracked sources. Closure cannot see this one: a hand-copied key list
           is a configuration reader that depends on nothing. This is the arm
           that makes the item's own words -- "without a copy" -- checkable.

  VOCAB    No door of the C ABI and no flag of the command line carries the
           configuration word. This is item 564's own probe (it counted the
           `wz_dissect_*` doors and found no config among them) kept as a
           predicate instead of as a measurement somebody took once.

## The word VOCAB looks for is derived, not chosen

It is the last underscore-separated segment of the SSOT file's stem --
`zenoh_config.rs` gives `config`. The module that owns the fact names itself,
and a door delivering that fact would carry the same word. Taking it from the
file keeps this gate from acquiring a private vocabulary that ages separately
from the tree.

## Two populations must be NON-EMPTY, because silence is the failure here

Every arm of this gate reports "nothing found", which is exactly what a dead
probe reports. So:

  * COPY keeps a CONTROL. The honoured keys must be found somewhere in tracked
    `crates/` OUTSIDE the SSOT file. They are -- `wz-ap-demo`'s coverage args
    and the stock-config integration test both spell them -- and if that ever
    reaches zero the scanner has stopped seeing key literals and its silence
    about the surfaces means nothing.
  * VOCAB requires both of its populations (the ABI's doors, the CLI's flags)
    to be non-empty, since a regex that stopped matching would report a
    config-free surface with total confidence.

## What is deliberately NOT here

Whether the honoured list is COMPLETE against upstream. That is
`deepenable_audit.py`'s question and the register's item 373, and answering it
here would put one fact under two labels -- the same reason `NO_REACH_PATH`
gives for not answering it inside the parity gate.

Single-segment keys (`mode`, `id`, ...) are reported as SET ASIDE by COPY, not
silently dropped: a key with no `/` is spelled the same as an ordinary English
word and cannot serve as evidence of a copy. The predicate is mechanical and
the count is printed, so the reader sees the size of what the arm cannot see.

COMMENTS, likewise, are not evidence -- a doc comment DISCUSSING a config key
is not a reader of one, and a gate that could not tell them apart would go red
on prose and acquire an exemption list to survive, which is the shape this file
exists to remove. So COPY reads STRING LITERALS, extracted by a scanner that
tracks comment and string state rather than by a regex: `"tcp://host"` carries
a `//` that a line-comment regex would cut the rest of the line at, and cutting
text can only make this arm report LESS than the truth.
"""

from __future__ import annotations

import argparse
import json
import pathlib
import re
import subprocess
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))

import analysis_surface_parity as parity  # noqa: E402

ROOT = pathlib.Path(__file__).resolve().parents[2]

KEYS_CONST = "HONOURED_CONFIG_KEYS"


class Fatal(Exception):
    """A derivation that cannot be made. Never a silent pass."""


def tracked(*globs: str) -> list[pathlib.Path]:
    """Tracked files, from `git ls-files`, so an untracked build artifact lying
    in the tree can neither satisfy a claim nor raise one."""
    out = subprocess.run(
        ["git", "ls-files", "-z", *globs],
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=True,
    ).stdout
    return [ROOT / p for p in out.split("\0") if p]


def config_ssot(sources: dict[str, str]) -> str:
    """The one tracked path DEFINING the honoured-key list.

    Not a constant in this file on purpose: a hardcoded path is the exact
    failure `NO_REACH_PATH`'s own reason warns about one line over -- a reader
    aimed at a module that moved matches nothing and reports an empty set.
    """
    definers = sorted(
        path
        for path, text in sources.items()
        if re.search(rf"pub const {KEYS_CONST}\s*:", text)
    )
    if len(definers) != 1:
        raise Fatal(
            f"expected exactly ONE tracked definition of {KEYS_CONST}, found "
            f"{len(definers)}: {definers or '[]'}. Zero means the configuration "
            "SSOT moved and this derivation is aimed at nothing; more than one "
            "IS the second copy the door in wz-capi-c exists to remove."
        )
    return definers[0]


def honoured_keys(ssot_text: str) -> list[str]:
    """The key literals, read out of the const's own body with comments stripped
    so a key named in a `//` note cannot enter the population."""
    body = re.search(
        rf"pub const {KEYS_CONST}\s*:\s*&\[&str\]\s*=\s*&\[(.*?)\n\];",
        ssot_text,
        re.S,
    )
    if body is None:
        raise Fatal(
            f"{KEYS_CONST} is defined but its list body did not parse. A key "
            "population read from nothing is not a population."
        )
    return re.findall(r'"([^"]+)"', re.sub(r"//[^\n]*", "", body.group(1)))


def string_literals(text: str) -> list[str]:
    """Every string literal in Rust or C source, comments excluded.

    A scanner rather than a regex, for the reason the header gives: a literal
    may CONTAIN `//`, and a regex that strips line comments would cut the rest
    of that line away. Under-reporting is the one defect a gate must not have,
    so comment state and string state are tracked together and neither can be
    mistaken for the other.

    Rust raw strings (`r"..."`, `r#"..."#`) are recognised because an escape has
    no meaning inside one; a config document pasted into a fixture is exactly
    the shape that arrives as a raw string.
    """
    out: list[str] = []
    i, n = 0, len(text)
    while i < n:
        ch = text[i]
        if ch == "/" and i + 1 < n and text[i + 1] == "/":
            end = text.find("\n", i)
            i = n if end < 0 else end + 1
            continue
        if ch == "/" and i + 1 < n and text[i + 1] == "*":
            depth, i = 1, i + 2
            while i < n and depth:
                if text.startswith("/*", i):
                    depth, i = depth + 1, i + 2
                elif text.startswith("*/", i):
                    depth, i = depth - 1, i + 2
                else:
                    i += 1
            continue
        if ch == "r" and (i == 0 or not (text[i - 1].isalnum() or text[i - 1] == "_")):
            j = i + 1
            while j < n and text[j] == "#":
                j += 1
            if j < n and text[j] == '"':
                fence = '"' + "#" * (j - i - 1)
                end = text.find(fence, j + 1)
                if end < 0:
                    break
                out.append(text[j + 1 : end])
                i = end + len(fence)
                continue
        if ch == '"':
            j, buf = i + 1, []
            while j < n:
                if text[j] == "\\":
                    j += 2
                    continue
                if text[j] == '"':
                    break
                buf.append(text[j])
                j += 1
            out.append("".join(buf))
            i = j + 1
            continue
        i += 1
    return out


Member = "tuple[str, list[tuple[str, str]]]"


def parse_metadata(payload: dict) -> dict[str, tuple[str, list[tuple[str, str]]]]:
    """Workspace members from `cargo metadata`: name -> (directory, edges).

    An edge is `(dependency name, kind)` with kind one of `normal`, `dev`,
    `build`. Cargo is asked rather than the manifest text parsed, for two
    reasons and only the first is about python's floor: cargo FLATTENS the
    `[target.'cfg(...)'.dependencies]` tables into the same list, so a
    dependency behind a `cfg` cannot hide from this walk by sitting in a table
    a hand-rolled reader forgot to look in. A reach that exists on one platform
    only is still a reach.
    """
    out: dict[str, tuple[str, list[tuple[str, str]]]] = {}
    for package in payload.get("packages", []):
        name = package.get("name")
        manifest = package.get("manifest_path")
        if not name or not manifest:
            continue
        edges = [
            (dep["name"], dep.get("kind") or "normal")
            for dep in package.get("dependencies", [])
            if dep.get("name")
        ]
        out[name] = (pathlib.Path(manifest).parent.name, edges)
    return out


def manifests() -> dict[str, tuple[str, list[tuple[str, str]]]]:
    """Workspace members, read from cargo's own answer about this workspace."""
    proc = subprocess.run(
        ["cargo", "metadata", "--no-deps", "--format-version", "1", "--offline"],
        cwd=ROOT / "crates",
        capture_output=True,
        text=True,
    )
    if proc.returncode != 0:
        raise Fatal(
            "`cargo metadata` failed, so the dependency closure has no input:\n"
            + proc.stderr.strip()
        )
    members = parse_metadata(json.loads(proc.stdout))
    if not members:
        raise Fatal(
            "`cargo metadata` reported no workspace members. A closure over an "
            "empty workspace is empty, and empty reads as clean."
        )
    return members


def closure(mans: dict[str, tuple[str, list[tuple[str, str]]]], root: str) -> set[str]:
    """Transitive dependency closure of `root`.

    The root's DEV edges are included and its dependencies' are not, which is
    cargo's own rule: a dev-dependency builds that package's tests and does not
    propagate. Including the root's means a configuration reader reached only
    from this surface's test tree is a finding rather than an exemption.
    """
    seen: set[str] = set()
    stack = [(root, True)]
    while stack:
        name, is_root = stack.pop()
        entry = mans.get(name)
        if entry is None:
            continue
        for dep, kind in entry[1]:
            if kind == "dev" and not is_root:
                continue
            if dep not in seen:
                seen.add(dep)
                stack.append((dep, False))
    return seen


# --------------------------------------------------------------------------
# the four arms, each a pure function so a fixture can drive it red
# --------------------------------------------------------------------------


def arm_binding(
    no_reach: dict[int, str], ssot_rel: str
) -> tuple[list[str], int | None]:
    """The declaration in `NO_REACH_PATH` that this derivation underwrites."""
    naming = sorted(number for number, reason in no_reach.items() if ssot_rel in reason)
    if len(naming) == 1:
        return [], naming[0]
    if not naming:
        return [
            f"BINDING: no NO_REACH_PATH entry names `{ssot_rel}` any more. This "
            "derivation was written to hold up that entry's reason; with the "
            "entry gone, whether the analysis surfaces may reach configuration "
            "is an open decision again and somebody must make it -- either "
            "restore the entry naming the file, or retire this gate with the "
            "verdict written down.",
        ], None
    return [
        f"BINDING: {len(naming)} NO_REACH_PATH entries name `{ssot_rel}` "
        f"({naming}). One fact under two labels is what that table's own "
        "reasons refuse; only one number may rest on this file.",
    ], None


def arm_closure(
    mans: dict[str, tuple[str, list[tuple[str, str]]]],
    surfaces: dict[str, str],
    owner: str,
) -> list[str]:
    """The package owning configuration must be unreachable from each surface."""
    findings = []
    for label, package in sorted(surfaces.items()):
        if package not in mans:
            findings.append(
                f"CLOSURE: the {label} surface's package `{package}` is not a "
                "workspace member. A closure computed over a package that is "
                "not there is empty, and empty reads as clean."
            )
            continue
        if owner in closure(mans, package):
            findings.append(
                f"CLOSURE: `{package}` ({label}) reaches `{owner}`, which owns "
                "the configuration SSOT. The declaration that this surface "
                "neither reads nor writes configuration no longer follows from "
                "the manifests."
            )
    return findings


def arm_copy(
    keys: list[str],
    surface_literals: dict[str, dict[str, list[str]]],
    control: dict[str, list[str]],
) -> tuple[list[str], list[str], int]:
    """No honoured key spelled inside a surface; and the scanner is alive.

    A key COUNTS when it occurs anywhere inside a literal rather than only when
    it is the whole of one: a config document pasted into a fixture carries its
    keys as substrings, and that is a copy by any reading.

    Returns (findings, keys set aside as unusable evidence, control hits).
    """
    aside = [key for key in keys if "/" not in key]
    usable = [key for key in keys if "/" in key]
    findings = []
    if not usable:
        findings.append(
            "COPY: no honoured key is path-shaped, so this arm has nothing it "
            "can recognise. A population of zero reports green."
        )
        return findings, aside, 0
    for label, sources in sorted(surface_literals.items()):
        for path, literals in sorted(sources.items()):
            spelled = sorted(
                key for key in usable if any(key in lit for lit in literals)
            )
            if spelled:
                findings.append(
                    f"COPY: {path} ({label}) spells {len(spelled)} honoured "
                    f"config key(s) -- {spelled[:3]}. A copied key list is a "
                    "configuration reader that depends on nothing, which is "
                    "precisely the reach the closure arm cannot see."
                )
    hits = sum(
        1
        for literals in control.values()
        if any(key in lit for lit in literals for key in usable)
    )
    if hits == 0:
        findings.append(
            "COPY CONTROL: not one tracked file outside the SSOT spells an "
            "honoured key. The scanner has stopped recognising key literals, so "
            "its silence about the surfaces is worth nothing."
        )
    return findings, aside, hits


def arm_vocab(word: str, symbols: set[str], flags: set[str]) -> list[str]:
    """Neither surface's OWN published vocabulary names configuration."""
    findings = []
    if not symbols:
        findings.append(
            "VOCAB: the C ABI reported no doors at all. A surface read from "
            "nothing carries no word, which is not the same as carrying none."
        )
    if not flags:
        findings.append(
            "VOCAB: the command line reported no flags at all, so the same "
            "reading holds for it."
        )
    named = sorted(name for name in symbols if word in name)
    if named:
        findings.append(
            f"VOCAB: the C ABI publishes {named}, which name `{word}`. A "
            "configuration door on the analysis surface contradicts the "
            "declaration that the surface does not reach configuration -- "
            "wz-capi-c is where such a door belongs (R2172, item 548)."
        )
    flagged = sorted(flag for flag in flags if word in flag)
    if flagged:
        findings.append(
            f"VOCAB: the command line publishes {flagged}, which name `{word}`, "
            "on the same argument as the line above."
        )
    return findings


# --------------------------------------------------------------------------


def run() -> int:
    rust = {
        str(path.relative_to(ROOT)): path.read_text(errors="replace")
        for path in tracked("crates/**/*.rs")
    }
    ssot_rel = config_ssot(rust)
    keys = honoured_keys(rust[ssot_rel])
    owner_dir = pathlib.Path(ssot_rel).parts[1]
    mans = manifests()
    owner = next(
        (name for name, (directory, _) in mans.items() if directory == owner_dir), None
    )
    if owner is None:
        raise Fatal(
            f"no workspace member lives in `crates/{owner_dir}`, which is where "
            f"the configuration SSOT `{ssot_rel}` sits. The closure arm has no "
            "subject."
        )

    surfaces: dict[str, str] = {}
    for label, source in (("command line", parity.CLI), ("C ABI", parity.CAPI)):
        directory = source.relative_to(ROOT).parts[1]
        surfaces[label] = next(
            (name for name, (d, _) in mans.items() if d == directory), directory
        )

    surface_literals = {
        label: {
            str(path.relative_to(ROOT)): string_literals(path.read_text(errors="replace"))
            for path in tracked(f"crates/{mans[package][0]}/**")
            if path.suffix in {".rs", ".h", ".c"}
        }
        for label, package in surfaces.items()
        if package in mans
    }
    surface_paths = {p for sources in surface_literals.values() for p in sources}
    control = {
        path: string_literals(text)
        for path, text in rust.items()
        if path != ssot_rel and path not in surface_paths
    }

    word = pathlib.Path(ssot_rel).stem.split("_")[-1]
    if len(word) < 4:
        raise Fatal(
            f"the configuration word derived from `{ssot_rel}` is `{word}`, too "
            "short to distinguish a door from an accident."
        )

    findings: list[str] = []
    binding, number = arm_binding(parity.NO_REACH_PATH, ssot_rel)
    findings += binding
    findings += arm_closure(mans, surfaces, owner)
    copy_findings, aside, control_hits = arm_copy(keys, surface_literals, control)
    findings += copy_findings
    findings += arm_vocab(word, parity.capi_symbols(), parity.cli_flags())

    scanned = sum(len(s) for s in surface_literals.values())
    print(f"analysis-surface-config-free: SSOT {ssot_rel}, owned by `{owner}`")
    print(
        f"  binding: NO_REACH_PATH entry {number} rests on that file"
        if number is not None
        else "  binding: UNRESOLVED -- see findings"
    )
    print(
        f"  closure: {', '.join(sorted(surfaces.values()))} over "
        f"{len(mans)} workspace member(s)"
    )
    print(
        f"  copy: {len(keys)} honoured key(s), {len(keys) - len(aside)} usable as "
        f"evidence, {len(aside)} set aside as single-segment {sorted(aside)}; "
        f"{scanned} surface file(s) scanned; control found keys in "
        f"{control_hits} of {len(control)} other tracked file(s)"
    )
    print(f"  vocab: word `{word}`")

    if findings:
        print(
            "analysis-surface-config-free: FAIL -- the analysis surfaces are "
            "declared configuration-free and are not.",
            file=sys.stderr,
        )
        for finding in findings:
            print(f"  {finding}", file=sys.stderr)
        return 1
    print("analysis-surface-config-free: OK")
    return 0


# --------------------------------------------------------------------------
# selftest -- every arm driven RED by a mutation, because a gate that has never
# failed is a gate nobody has seen work. R2137's rule holds here: each fixture
# carries the shape a WEAKER implementation would have swallowed, not merely an
# obviously broken one -- the dev edge and the `cfg`-gated edge are both routes
# a plainer closure would have missed, and the dead-scanner case is the one an
# implementation without a control could not tell from a clean tree.
# --------------------------------------------------------------------------


def fail(message: str) -> int:
    print(f"analysis-surface-config-free: SELFTEST FAIL -- {message}", file=sys.stderr)
    return 1


def selftest() -> int:
    cases: list[tuple[str, list[str]]] = []

    ssot = "crates/wz-runtime-tokio/src/zenoh_config.rs"
    keys = ["mode", "connect/endpoints", "scouting/multicast/enabled"]

    cases.append(("binding, entry gone", arm_binding({1: "something else"}, ssot)[0]))
    cases.append(
        (
            "binding, two entries",
            arm_binding({2: f"feeds {ssot}", 5: f"also {ssot}"}, ssot)[0],
        )
    )
    ok_binding, number = arm_binding({2: f"fed by {ssot} which"}, ssot)
    if ok_binding or number != 2:
        return fail("binding: the healthy tree's own shape did not resolve")

    # Cargo's own shape, so the fixture exercises the reader that runs.
    metadata = {
        "packages": [
            {"name": "wz-owner", "manifest_path": "/w/wz-runtime-tokio/Cargo.toml"},
            {
                "name": "wz-mid",
                "manifest_path": "/w/wz-mid/Cargo.toml",
                "dependencies": [{"name": "wz-owner", "kind": None}],
            },
            {
                "name": "wz-surface",
                "manifest_path": "/w/wz-surface/Cargo.toml",
                "dependencies": [{"name": "wz-mid", "kind": None}],
            },
            {
                "name": "wz-clean",
                "manifest_path": "/w/wz-clean/Cargo.toml",
                "dependencies": [],
            },
            # A dev edge is the route a weaker closure would have exempted, and
            # the only route by which this member reaches the owner at all.
            {
                "name": "wz-devonly",
                "manifest_path": "/w/wz-devonly/Cargo.toml",
                "dependencies": [{"name": "wz-owner", "kind": "dev"}],
            },
            # Behind a `cfg`, which cargo hands back in the SAME list with a
            # `target` beside it -- the flattening this reader relies on.
            {
                "name": "wz-target",
                "manifest_path": "/w/wz-target/Cargo.toml",
                "dependencies": [
                    {"name": "wz-owner", "kind": None, "target": "cfg(unix)"}
                ],
            },
            # A dev edge one hop DOWN must not propagate, which is cargo's own
            # rule and the reason the walk carries `is_root`.
            {
                "name": "wz-viadev",
                "manifest_path": "/w/wz-viadev/Cargo.toml",
                "dependencies": [{"name": "wz-devonly", "kind": None}],
            },
        ]
    }
    mans = parse_metadata(metadata)
    if mans.get("wz-target") != ("wz-target", [("wz-owner", "normal")]):
        return fail("metadata: a `cfg`-targeted dependency was not read as normal")
    if mans.get("wz-devonly") != ("wz-devonly", [("wz-owner", "dev")]):
        return fail("metadata: a dev dependency lost its kind")
    cases.append(
        ("closure, transitive", arm_closure(mans, {"s": "wz-surface"}, "wz-owner"))
    )
    cases.append(
        (
            "closure, dev edge of the root",
            arm_closure(mans, {"s": "wz-devonly"}, "wz-owner"),
        )
    )
    cases.append(
        ("closure, behind a cfg", arm_closure(mans, {"s": "wz-target"}, "wz-owner"))
    )
    cases.append(
        ("closure, absent package", arm_closure(mans, {"s": "wz-ghost"}, "wz-owner"))
    )
    if arm_closure(mans, {"s": "wz-clean"}, "wz-owner"):
        return fail("closure: a package with no edges was reported as reaching")
    if arm_closure(mans, {"s": "wz-viadev"}, "wz-owner"):
        return fail("closure: a dev edge one hop down was propagated")

    lits = string_literals
    control = {"other.rs": lits('let k = "connect/endpoints";')}
    cases.append(
        (
            "copy, a key spelled in a surface",
            arm_copy(
                keys,
                {"s": {"surface.rs": lits('const K = "scouting/multicast/enabled";')}},
                control,
            )[0],
        )
    )
    cases.append(
        (
            "copy, a key inside a pasted document",
            arm_copy(
                keys,
                {"s": {"surface.rs": lits('r#"{ connect/endpoints: [] }"#')}},
                control,
            )[0],
        )
    )
    cases.append(
        (
            "copy, dead scanner",
            arm_copy(keys, {"s": {"surface.rs": []}}, {"other.rs": lits("nothing")})[0],
        )
    )
    cases.append(
        ("copy, no usable key", arm_copy(["mode", "id"], {"s": {}}, control)[0])
    )
    clean, aside, hits = arm_copy(keys, {"s": {"surface.rs": []}}, control)
    if clean:
        return fail("copy: a clean surface was reported as copying")
    if aside != ["mode"] or hits != 1:
        return fail(f"copy: accounting wrong -- set aside {aside}, control {hits}")

    # The scanner's own two traps, each the reason it is not a regex: a key
    # named only in a COMMENT is discussion and not a copy, and a literal
    # carrying `//` must not truncate the line a key sits on.
    if arm_copy(keys, {"s": {"c.rs": lits('// see "connect/endpoints"')}}, control)[0]:
        return fail("copy: a key named in a comment was read as a copy")
    if not arm_copy(
        keys,
        {"s": {"u.rs": lits('let e = "tcp://h"; let k = "connect/endpoints";')}},
        control,
    )[0]:
        return fail("copy: a key after a `//`-bearing literal went unseen")

    cases.append(
        (
            "vocab, a config door",
            arm_vocab(
                "config", {"wz_dissect_config_surface", "wz_dissect_record"}, {"--json"}
            ),
        )
    )
    cases.append(
        (
            "vocab, a config flag",
            arm_vocab("config", {"wz_dissect_record"}, {"--config"}),
        )
    )
    cases.append(("vocab, no doors read", arm_vocab("config", set(), {"--json"})))
    cases.append(
        ("vocab, no flags read", arm_vocab("config", {"wz_dissect_record"}, set()))
    )
    if arm_vocab("config", {"wz_dissect_record"}, {"--json"}):
        return fail("vocab: a clean surface was reported as naming configuration")

    for name, findings in cases:
        if not findings:
            return fail(f"{name}: the mutation produced NO finding")
        print(f"  selftest red as required: {name}")

    for label, sources in (
        ("two definitions", {"a.rs": f"pub const {KEYS_CONST}: x", "b.rs": f"pub const {KEYS_CONST}: y"}),
        ("zero definitions", {"a.rs": "nothing"}),
    ):
        try:
            config_ssot(sources)
        except Fatal:
            print(f"  selftest red as required: ssot, {label}")
        else:
            return fail(f"ssot: {label} was accepted")

    print(f"analysis-surface-config-free: selftest OK ({len(cases) + 2} mutations red)")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description="derive that the two analysis "
                                     "consumption surfaces do not reach configuration")
    parser.add_argument(
        "--selftest",
        action="store_true",
        help="drive every arm with a fixture that must make it red",
    )
    args = parser.parse_args()
    if args.selftest:
        return selftest()
    try:
        return run()
    except Fatal as exc:
        print(f"analysis-surface-config-free: FAIL -- {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
