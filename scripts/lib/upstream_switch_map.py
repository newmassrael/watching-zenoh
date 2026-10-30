#!/usr/bin/env python3
# SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
# SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

"""R3406 (no register item) — the BUILD SWITCHES of zenoh-pico and zenoh-c as a
denominator, and wz's answer to each one as the numerator.

`docs/build-configuration.md` C7: an upstream original is reproduced by naming it,
which needs every switch that original has to be judged against wz, completely and
mechanically. `upstream_feature_census.py` already does this for the `zenoh` crate's
cargo features; this script is the same instrument for the other two originals wz
replaces, in the same shape, so that the three tables can move into the single
declaration of step 1 together.

## The population

* **zenoh-pico**: every `Z_FEATURE_*` name its CMake defines with `set(` or `option(` --
  `CMakeLists.txt`, and from 1.10.2 `cmake/feature_config.cmake`, where the definitions moved
  (`pico_cmake_text` reads both). The pinned source is the `vendor/zenoh-pico` submodule, present in every
  clone that initialised submodules, so this arm runs in the DEFAULT mode.
* **zenoh-c**: every cargo feature of its package, by cargo's own answer
  (`cargo metadata --no-deps`), less the two kinds that are derivable rather than
  judged: `default`, and the implicit feature of an optional dependency whose body is
  exactly that dependency (the rule `upstream_feature_census.py` documents). The pinned
  source is the checkout `scripts/install-zenoh-c.sh` provisions (`$WZ_ZENOH_C_REF`,
  default `~/zenoh-c-ref`), which only the lanes that install the oracle have, so this
  arm runs with `--zenoh-c` and the default run PRINTS that it was deferred.

Both pins are read from the shared deriver (`upstream_release_distance`); this file
spells no version. The zenoh-pico pin is the submodule's tag (`git describe --tags`),
which a checkout without tags cannot name; the zenoh-c lane is one (a shallow
checkout), and when `--zenoh-c` also graded the zenoh-pico arm there it failed with
"the pin deriver could not name this original". So each run grades ONE upstream arm,
the one its lane provisions: the default run zenoh-pico's, `--zenoh-c` zenoh-c's, and
each prints that it deferred the other. The shape and declaration arms read only this
tree and run in both.

## The four classes

Every switch gets exactly one row, and one of:

* `maps`    a wz cargo feature of the drop-in crate toggles the same capability. The
            anchor is `<crate>/<feature>`, and the crate must declare that feature.
* `always`  wz has the capability in that ABI build with no switch. The anchor is the
            tracked file that shows it, and the file must exist.
* `never`   wz does not have it in that ABI build. No anchor; the note must cite the
            open-debt item that owns the gap (`open-debt item <n>`), because a gap
            nobody carries is a gap nobody closes.
* `n/a`     the switch has no meaning for wz (a visibility toggle, a mutex strategy of
            the C implementation). No anchor; the note states why.

A `never` row is the table working, not a defect in it: it is how the capabilities
wz still owes for an upstream original are found at all.

## Agreement with the capability declaration

The rows live in `deploy/wz-config.toml` (`[[upstream_switch]]`, docs/build-configuration.md
step 2), and a zenoh-pico `maps` row to a capability IS that capability's pico switch: the
fact is written once. What is left to agree is a `pico_flags_all`, whose every switch must be
a `maps` row.

The declaration also states each original's own default (`upstream_on` /
`upstream_off`, docs/build-configuration.md step 2). Each run holds the original it
grades: the default run every capability zenoh-pico has a switch for against the
first definition of that switch in the pinned pico CMake (on when every switch the
capability names is on), `--zenoh-c` every capability a zenoh-c `maps` row reaches
against zenoh-c's `default` features. A capability neither reaches (the query plane in
zenoh-c, which has no switch for it) is judged in the declaration alone, and the run
names the zenoh-pico ones.

## What this does NOT claim

That a `maps` or `always` capability is as DEEP as upstream's: that is the depth axis
(`depth_axis_census.py`). This is the breadth axis, per switch.

Usage:
    python3 scripts/lib/upstream_switch_map.py              # shape + pico arm
    python3 scripts/lib/upstream_switch_map.py --zenoh-c    # shape + zenoh-c arm
    python3 scripts/lib/upstream_switch_map.py --selftest
"""

from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts" / "lib"))

import upstream_release_distance as urd  # noqa: E402
import wz_config  # noqa: E402

WORKSPACE_MANIFEST = ROOT / "crates" / "Cargo.toml"
PICO_URL = "https://github.com/eclipse-zenoh/zenoh-pico"
ZENOH_C_URL = "https://github.com/eclipse-zenoh/zenoh-c"
PICO_SOURCE = ROOT / "vendor" / "zenoh-pico"
ZENOH_C_PACKAGE = "zenoh-c"

CLASSES = ("maps", "always", "never", "n/a")
DEBT_CITATION = "open-debt item "

# The rows are the declaration's `[[upstream_switch]]` (deploy/wz-config.toml), one per switch of
# an original: (switch, class, anchor, note). zenoh-pico's are judged against
# `crates/wz-capi-pico`, the pico C ABI drop-in, and zenoh-c's against `crates/wz-capi-c`, at the
# pin. A `maps` anchor is a feature of that crate; an `always` anchor is the file that shows the
# capability is unconditional.
ORIGINALS = ("zenoh-pico", "zenoh-c")


def rows_of(decl: dict, original: str) -> tuple[tuple[str, str, str | None, str], ...]:
    """The declaration's rows for `original`, in the order the declaration writes them."""
    return tuple((r["switch"], r["class"], r.get("anchor"), r["note"])
                 for r in decl["switches"] if r["original"] == original)



class InputError(RuntimeError):
    """An input could not be read. Never a pass: always exit 2."""


def _cargo_metadata(manifest: Path) -> dict:
    cmd = ["cargo", "metadata", "--format-version=1", "--no-deps", "--manifest-path", str(manifest)]
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, check=False)
    except FileNotFoundError as e:
        raise InputError("cargo is not on PATH") from e
    if proc.returncode != 0:
        raise InputError(
            f"`cargo metadata --manifest-path {manifest}` failed (rc={proc.returncode}): "
            f"{proc.stderr.strip() or '<no stderr>'}"
        )
    try:
        md = json.loads(proc.stdout)
    except json.JSONDecodeError as e:
        raise InputError(f"`cargo metadata` on {manifest} printed no JSON ({e})") from e
    if not isinstance(md, dict) or not isinstance(md.get("packages"), list):
        raise InputError(f"`cargo metadata` on {manifest} carries no `packages` array")
    return md


def crate_features() -> dict[str, set[str]]:
    """Every workspace crate to the cargo features it declares."""
    md = _cargo_metadata(WORKSPACE_MANIFEST)
    out = {p["name"]: set(p.get("features", {})) for p in md["packages"]}
    if not any(out.values()):
        raise InputError("the workspace declares NO cargo features -- a population of zero")
    return out


def pins() -> dict[str, str | None]:
    """The pinned version of each original, from the shared deriver."""
    try:
        found = {**urd.submodule_pins(), **urd.script_pins(urd.tracked_paths())}
    except Exception as e:  # noqa: BLE001 - a deriver that cannot run is an INPUT fault
        raise InputError(f"the pin deriver could not run ({e})") from e
    return {"zenoh-pico": found.get(PICO_URL), "zenoh-c": found.get(ZENOH_C_URL)}


# ── the shape arm ───────────────────────────────────────────────────────────


def shape_arm(
    table: str,
    rows: tuple[tuple[str, str, str | None, str], ...],
    features: dict[str, set[str]],
    limits: frozenset[str] = frozenset(),
) -> list[str]:
    """Is the table well formed, and does every anchor it names exist? A `maps` anchor is a
    crate's feature, or `limit:<ID>` for a value switch, which a [[limit]] of `limits` declares."""
    failures: list[str] = []
    if not rows:
        return [f"{table}: the table is empty -- a census with no population reports green about nothing"]
    seen: dict[str, int] = {}
    for switch, cls, anchor, note in rows:
        seen[switch] = seen.get(switch, 0) + 1
        where = f"{table}: `{switch}`"
        if cls not in CLASSES:
            failures.append(f"{where} has class `{cls}`, not one of {', '.join(CLASSES)}")
            continue
        if not note.strip():
            failures.append(f"{where} carries no note -- a verdict with no reason is not one")
        if cls == "maps" and (anchor or "").startswith(wz_config.LIMIT_ANCHOR):
            if anchor[len(wz_config.LIMIT_ANCHOR):] not in limits:
                failures.append(f"{where} maps to `{anchor}`, which no [[limit]] declares")
        elif cls == "maps":
            crate, _, feature = (anchor or "").partition("/")
            if not crate or not feature:
                failures.append(f"{where} is `maps` but its anchor `{anchor}` is not `<crate>/<feature>`")
            elif crate not in features:
                failures.append(f"{where} maps to crate `{crate}`, which is not a workspace member")
            elif feature not in features[crate]:
                failures.append(
                    f"{where} maps to `{crate}/{feature}`, which that crate does not declare -- "
                    f"the anchor was renamed or removed and the row points at nothing"
                )
        elif cls == "always":
            path = (anchor or "").split("::", 1)[0]
            if not path:
                failures.append(f"{where} is `always` but names no file that shows it")
            elif not (ROOT / path).is_file():
                failures.append(f"{where} is `always` by `{anchor}`, and `{path}` is not a tracked file here")
        else:
            if anchor is not None:
                failures.append(f"{where} is `{cls}` and still names an anchor `{anchor}`")
            if cls == "never" and DEBT_CITATION not in note:
                failures.append(
                    f"{where} is `never` and its note cites no register item -- write "
                    f"`{DEBT_CITATION}<n>` into it"
                )
    for switch, n in sorted(seen.items()):
        if n > 1:
            failures.append(f"{table}: `{switch}` carries {n} rows -- two answers to one question")
    return failures


def declaration_arm(decl: dict) -> list[str]:
    """Is every pico switch a capability is on under a `maps` row?

    A capability's pico switches are the `maps` rows to it, so those cannot disagree with it. What
    can is a `pico_flags_all` (a capability no row reaches, on whenever several switches are all
    on): each switch it names must be a `maps` row, to whatever capability, or wz would read a
    pico `config.h` by a switch it has not judged. `decl` is `wz_config.load_decl()`'s shape.
    """
    failures: list[str] = []
    by_switch = {r[0]: r for r in rows_of(decl, "zenoh-pico")}
    for cap_id, cap in sorted(decl["caps"].items()):
        for flag in cap.get("pico_flags_all", []):
            row = by_switch.get(flag)
            if row is None or row[1] != "maps":
                got = "no row" if row is None else f"`{row[1]}`"
                failures.append(
                    f"capability `{cap_id}` is on under pico's `{flag}`, whose row here is {got}, "
                    f"not `maps`"
                )
    return failures


# ── the upstream arms ───────────────────────────────────────────────────────

PICO_SWITCH = re.compile(r"\b(?:set|option)\(\s*(Z_FEATURE_[A-Z0-9_]+)\b")
# A switch's default is its FIRST definition at the start of a line: `set(<name> 0|1 CACHE ...)`
# or `option(<name> "<help>" ON|OFF)`. The later definitions are `FORCE`d inside conditionals
# (a platform without the facility, a switch another one needs), not the default.
PICO_DEFAULT = re.compile(
    r'^(?:set\(\s*(Z_FEATURE_[A-Z0-9_]+)\s+([01])\s+CACHE\b'
    r'|option\(\s*(Z_FEATURE_[A-Z0-9_]+)\s+"[^"]*"\s+(ON|OFF)\s*\))',
    re.MULTILINE,
)


def pico_cmake_text(source: Path) -> str:
    """The CMake text in which a zenoh-pico source tree DEFINES its switches. Up to 1.10.1 that is
    its `CMakeLists.txt`; 1.10.2 moved every definition into `cmake/feature_config.cmake`, which
    the CMakeLists `include()`s before it reads a switch, and left only the uses behind. The
    definition file comes first, as it does in the build, so a switch's FIRST definition is the
    same text under either layout."""
    parts = []
    for rel in (("cmake", "feature_config.cmake"), ("CMakeLists.txt",)):
        path = source.joinpath(*rel)
        if path.is_file():
            parts.append(path.read_text(errors="replace"))
    return "\n".join(parts)


def pico_value_defaults(source: Path) -> dict[str, str]:
    """Each VALUE switch of a zenoh-pico source tree (the CMake variables its config template
    substitutes, `wz_config.pico_value_macros`) to the text of its first definition in the
    pico CMake (`pico_cmake_text`), which is its default: `set(<name> <value> CACHE ...)`. A
    switch with no such definition reads as the empty text."""
    template = source / "include" / "zenoh-pico" / "config.h.in"
    if not template.is_file():
        raise InputError(f"no zenoh-pico config template at {template}")
    text = pico_cmake_text(source)
    out: dict[str, str] = {}
    for name in wz_config.pico_value_macros(template.read_text(errors="replace")):
        m = re.search(rf'^\s*set\(\s*{name}\s+("[^"]*"|[^\s)]+)', text, re.MULTILINE)
        out[name] = m.group(1) if m else ""
    return out


def value_arm(decl: dict, rows: tuple[tuple[str, str, str | None, str], ...],
              defaults: dict[str, str]) -> list[str]:
    """Is each value switch answered as a value, and does the number wz states for it start where
    pico's does?

    A value switch is `maps` to the limit that states the same number for the pico ABI, `never`
    (wz states a number of its own and no image can change it; a register item carries that) or
    `n/a`. It is not `always`: a number wz holds fixed is pico's default build only, and a pico
    built with another number would not be matched. A `maps` row's limit defaults to pico's own
    default, so the drop-in's default build states what pico's does."""
    failures: list[str] = []
    limits = {lim["id"]: lim["default"] for lim in decl["limits"]}
    for switch, cls, anchor, _ in rows:
        is_value = switch in defaults
        to_limit = (anchor or "").startswith(wz_config.LIMIT_ANCHOR)
        if not is_value:
            if to_limit:
                failures.append(f"zenoh-pico: `{switch}` is not a value switch and anchors to {anchor}")
            continue
        if cls == "always":
            failures.append(f"zenoh-pico: value switch `{switch}` is `always` -- a number held fixed "
                            f"matches pico's default build only; it is `maps` to a limit or `never`")
        elif cls == "maps" and not to_limit:
            failures.append(f"zenoh-pico: value switch `{switch}` maps to `{anchor}`, not to a limit")
        elif cls == "maps":
            lid = anchor[len(wz_config.LIMIT_ANCHOR):]
            try:
                upstream = int(defaults[switch], 0)
            except ValueError:
                failures.append(f"zenoh-pico: value switch `{switch}` maps to limit {lid}, and its "
                                f"default `{defaults[switch]}` is not a number")
                continue
            if lid in limits and limits[lid] != upstream:
                failures.append(f"zenoh-pico: limit {lid} defaults to {limits[lid]}, and pico's "
                                f"`{switch}` to {upstream} -- the drop-in's default build would state "
                                f"another number")
    return failures


def pico_switches(source: Path) -> tuple[str, set[str]]:
    """(version, switches) of a zenoh-pico source tree: its `Z_FEATURE_*` switches. Its value
    switches are `pico_value_defaults`'s, and the population is the two together."""
    cmake = source / "CMakeLists.txt"
    version_file = source / "version.txt"
    if not cmake.is_file() or not version_file.is_file():
        raise InputError(
            f"no zenoh-pico source at {source} (CMakeLists.txt and version.txt). It is a "
            f"submodule: `git submodule update --init vendor/zenoh-pico`"
        )
    switches = set(PICO_SWITCH.findall(pico_cmake_text(source)))
    if not switches:
        raise InputError(f"{cmake} and cmake/feature_config.cmake define no Z_FEATURE_* switch -- "
                         f"not a zenoh-pico source")
    return version_file.read_text().strip(), switches


def pico_defaults(source: Path) -> dict[str, bool]:
    """Each switch of a zenoh-pico CMake (`pico_cmake_text`) to whether its default build has it on."""
    out: dict[str, bool] = {}
    text = pico_cmake_text(source)
    for m in PICO_DEFAULT.finditer(text):
        name = m.group(1) or m.group(3)
        out.setdefault(name, (m.group(2) or m.group(4)) in ("1", "ON"))
    return out


def upstream_default_arm(original: str, decl: dict, expected: dict[str, bool]) -> list[str]:
    """Does each capability's declared default for `original` equal what the original's own
    default build has? `expected` maps a capability id to the value the pinned source gives."""
    failures: list[str] = []
    for cap_id, want in sorted(expected.items()):
        got = wz_config.upstream_default(decl["caps"][cap_id], original)
        if got is None:
            failures.append(f"capability `{cap_id}` states no default for {original}, whose "
                            f"default build has it {'on' if want else 'off'}")
        elif got != want:
            failures.append(f"capability `{cap_id}` is declared {'on' if got else 'off'} in "
                            f"{original}'s default build, and the pinned source has it "
                            f"{'on' if want else 'off'}")
    return failures


def pico_expected(decl: dict, defaults: dict[str, bool]) -> dict[str, bool]:
    """The capabilities zenoh-pico has a switch for, to the value its defaults give, read as a
    pico `config.h` is read (`wz_config.pico_switches`): on when one of its switches is, or all
    where it combines them so."""
    out: dict[str, bool] = {}
    for cap_id in decl["caps"]:
        flags, combine = wz_config.pico_switches(decl, cap_id)
        if flags:
            out[cap_id] = (all if combine == "all" else any)(defaults.get(f, False) for f in flags)
    return out


def zenoh_c_expected(decl: dict, rows, default_features: set[str]) -> dict[str, bool]:
    """The capabilities a zenoh-c `maps` row reaches (`wz-capi-c/<capability>`), to whether that
    zenoh-c feature is in its `default`."""
    out: dict[str, bool] = {}
    for switch, cls, anchor, _ in rows:
        if cls == "maps" and anchor and anchor.startswith("wz-capi-c/"):
            cap_id = anchor.split("/", 1)[1]
            if cap_id in decl["caps"]:
                out[cap_id] = switch in default_features
    return out


def zenoh_c_source() -> Path:
    return Path(os.environ.get("WZ_ZENOH_C_REF", Path.home() / "zenoh-c-ref"))


def zenoh_c_switches(source: Path) -> tuple[str, set[str], dict[str, str], set[str]]:
    """(version, capability features, {derived feature: why}, default features) of a zenoh-c
    checkout."""
    injected = os.environ.get("WZ_ZENOH_C_METADATA")
    if injected:
        try:
            md = json.loads(Path(injected).read_text())
        except (OSError, json.JSONDecodeError) as e:
            raise InputError(f"the injected WZ_ZENOH_C_METADATA {injected} is not readable JSON ({e})") from e
        if not isinstance(md, dict) or not isinstance(md.get("packages"), list):
            raise InputError(f"the injected WZ_ZENOH_C_METADATA {injected} carries no `packages` array")
    else:
        manifest = source / "Cargo.toml"
        if not manifest.is_file():
            raise InputError(
                f"no zenoh-c checkout at {source}. Provision it with `bash scripts/install-zenoh-c.sh` "
                f"or point WZ_ZENOH_C_REF at a clone of the pinned tag"
            )
        md = _cargo_metadata(manifest)
    pkgs = [p for p in md["packages"] if isinstance(p, dict) and p.get("name") == ZENOH_C_PACKAGE]
    if len(pkgs) != 1:
        raise InputError(f"expected exactly one `{ZENOH_C_PACKAGE}` package, found {len(pkgs)}")
    pkg = pkgs[0]
    features: dict[str, list[str]] = pkg.get("features", {})
    optional = {d["name"] for d in pkg.get("dependencies", []) if d.get("optional")}
    derived: dict[str, str] = {}
    for name, body in features.items():
        if name == "default":
            derived[name] = "cargo's `default` aggregate"
        elif name in optional and body == [f"dep:{name}"]:
            derived[name] = f"cargo's implicit feature for the optional dependency `{name}`"
    return pkg.get("version", ""), set(features) - set(derived), derived, set(features.get("default", []))


ZENOH_C_MACRO_TABLE = re.compile(r"RUST_TO_C_FEATURES[^{]*\{(?P<body>.*?)\};", re.DOTALL)
ZENOH_C_MACRO_ROW = re.compile(r'"([^"]+)"\s*=>\s*"(Z_FEATURE_[A-Z0-9_]+)"')


def zenoh_c_macros(source: Path) -> dict[str, str]:
    """zenoh-c's own table of the macro it writes into `zenoh_configure.h` for each cargo
    feature (`buildrs/cbindgen_generator.rs`, `RUST_TO_C_FEATURES`)."""
    path = source / "buildrs" / "cbindgen_generator.rs"
    if not path.is_file():
        raise InputError(f"no {path}: the zenoh-c checkout carries no feature-to-macro table")
    m = ZENOH_C_MACRO_TABLE.search(path.read_text(errors="replace"))
    table = dict(ZENOH_C_MACRO_ROW.findall(m.group("body"))) if m else {}
    if not table:
        raise InputError(f"{path} has no RUST_TO_C_FEATURES table -- not zenoh-c's build script")
    return table


def macro_arm(decl: dict, table: dict[str, str]) -> list[str]:
    """Does each zenoh-c row that names a macro name the one zenoh-c writes for its switch?"""
    failures: list[str] = []
    for row in decl["switches"]:
        if row.get("original") != "zenoh-c" or "macro" not in row:
            continue
        want = table.get(row["switch"])
        if want != row["macro"]:
            failures.append(
                f"zenoh-c: the row for `{row['switch']}` names the macro `{row['macro']}`, and "
                f"zenoh-c writes {('`' + want + '`') if want else 'none'} for it"
            )
    return failures


def upstream_arm(
    table: str,
    rows: tuple[tuple[str, str, str | None, str], ...],
    version: str,
    pinned: str | None,
    switches: set[str],
) -> list[str]:
    """Does the table still equal what the pinned original declares, both ways?"""
    if pinned is None:
        return [f"{table}: the pin deriver could not name this original -- graded against nothing"]
    if version != pinned:
        return [
            f"{table}: the source is version {version or '<unreadable>'}, not the pinned {pinned}. "
            f"Re-judge the rows in the round that moves the pin"
        ]
    judged = {r[0] for r in rows}
    failures = [
        f"{table}: upstream declares `{s}`, which no row judges -- a switch arrived UNJUDGED"
        for s in sorted(switches - judged)
    ]
    failures += [
        f"{table}: a row judges `{s}`, which upstream no longer declares -- the row outlived its subject"
        for s in sorted(judged - switches)
    ]
    return failures


# ── report ──────────────────────────────────────────────────────────────────


def report(table: str, rows: tuple[tuple[str, str, str | None, str], ...]) -> None:
    counts = {c: sum(1 for r in rows if r[1] == c) for c in CLASSES}
    print(
        f"  upstream-switch-map: {table}: {len(rows)} switch(es) -- "
        + ", ".join(f"{counts[c]} {c}" for c in CLASSES)
    )
    width = max((len(r[0]) for r in rows), default=4)
    for switch, cls, anchor, _ in rows:
        print(f"    {switch.ljust(width)}  {cls.ljust(6)}  {anchor or '-'}")
    never = [r[0] for r in rows if r[1] == "never"]
    if never:
        print(f"    -- NEVER by name: {', '.join(never)}")


# ── selftest ────────────────────────────────────────────────────────────────


def selftest() -> int:
    """Drive every failure branch from a faithful control, one mutation per case."""
    import tempfile

    features = {"wz-capi-pico": {"link-udp", "query"}, "wz-capi-c": {"query"}}
    control = (
        ("Z_FEATURE_LINK_UDP_UNICAST", "maps", "wz-capi-pico/link-udp", "the udp link"),
        ("Z_FEATURE_QUERY", "maps", "wz-capi-pico/query", "the query plane"),
        ("Z_FEATURE_PUBLICATION", "always", "crates/wz-capi-pico/Cargo.toml", "always built"),
        ("Z_FEATURE_LINK_BLUETOOTH", "never", None, "absent; open-debt item 1"),
        ("Z_FEATURE_BATCH_TX_MUTEX", "n/a", None, "a mutex strategy of the C implementation"),
    )
    def as_switches(rows: tuple, original: str = "zenoh-pico") -> list[dict]:
        out = []
        for switch, cls, anchor, note in rows:
            row = {"original": original, "switch": switch, "class": cls, "note": note}
            if anchor is not None:
                row["anchor"] = anchor
            out.append(row)
        return out

    # The shape `wz_config.load_decl()` returns, which is what main() passes: a fixture of any
    # other shape let the declaration arm grade nothing in the real run while its cases passed.
    decl = {
        "caps": {
            "link-udp": {"id": "link-udp", "upstream_on": ["zenoh-pico"]},
            "query": {"id": "query", "upstream_off": ["zenoh-pico"]},
        },
        "switches": as_switches(control),
    }
    switches = {r[0] for r in control}

    def swap(i: int, row: tuple) -> tuple:
        return control[:i] + (row,) + control[i + 1:]

    shape_cases: list[tuple[str, tuple, bool]] = [
        ("the faithful table passes", control, True),
        ("an empty table fails", (), False),
        ("an unknown class fails", swap(4, ("Z_FEATURE_BATCH_TX_MUTEX", "maybe", None, "x")), False),
        ("a maps row to an undeclared feature fails",
         swap(1, ("Z_FEATURE_QUERY", "maps", "wz-capi-pico/queries", "x")), False),
        ("a maps row to a non-member crate fails",
         swap(1, ("Z_FEATURE_QUERY", "maps", "wz-nope/query", "x")), False),
        ("an always row naming a missing file fails",
         swap(2, ("Z_FEATURE_PUBLICATION", "always", "crates/no/such.rs", "x")), False),
        ("a never row citing no register item fails",
         swap(3, ("Z_FEATURE_LINK_BLUETOOTH", "never", None, "absent")), False),
        ("an n/a row with an anchor fails",
         swap(4, ("Z_FEATURE_BATCH_TX_MUTEX", "n/a", "wz-capi-pico/query", "x")), False),
        ("a row with no note fails", swap(4, ("Z_FEATURE_BATCH_TX_MUTEX", "n/a", None, " ")), False),
        ("a duplicated switch fails", control + (control[0],), False),
    ]
    for label, rows, want_ok in shape_cases:
        got_ok = not shape_arm("t", rows, features)
        if got_ok != want_ok:
            print(f"  selftest FAIL [{label}]: expected {'pass' if want_ok else 'FAIL'}", file=sys.stderr)
            return 1

    def with_all(flags: list[str]) -> dict:
        return {**decl, "caps": {**decl["caps"], "both": {"id": "both", "pico_flags_all": flags}}}

    decl_cases: list[tuple[str, dict, bool]] = [
        ("the declaration agrees", decl, True),
        ("a capability on under several switches agrees when each has a maps row",
         with_all(["Z_FEATURE_LINK_UDP_UNICAST", "Z_FEATURE_QUERY"]), True),
        ("a capability on under a switch whose row is not maps fails",
         with_all(["Z_FEATURE_QUERY", "Z_FEATURE_BATCH_TX_MUTEX"]), False),
        ("a capability on under a switch no row judges fails",
         with_all(["Z_FEATURE_QUERY", "Z_FEATURE_NO_SUCH"]), False),
    ]
    for label, d, want_ok in decl_cases:
        got_ok = not declaration_arm(d)
        if got_ok != want_ok:
            print(f"  selftest FAIL [{label}]: expected {'pass' if want_ok else 'FAIL'}", file=sys.stderr)
            return 1

    # A capability two rows map to reads pico's defaults as a config.h is read: either switch on
    # asks for it, unless it combines them with `all`.
    two = {"caps": {"adv": {"id": "adv"}}, "switches": as_switches((
        ("Z_FEATURE_PUB", "maps", "wz-capi-pico/adv", "x"),
        ("Z_FEATURE_SUB", "maps", "wz-capi-pico/adv", "x")))}
    half_on = {"Z_FEATURE_PUB": True, "Z_FEATURE_SUB": False}
    both_needed = {**two, "caps": {"adv": {"id": "adv", "pico_combine": "all"}}}
    if pico_expected(two, half_on) != {"adv": True} or pico_expected(both_needed, half_on) != {"adv": False}:
        print("  selftest FAIL [two switches to one capability, any and all]: "
              f"{pico_expected(two, half_on)} {pico_expected(both_needed, half_on)}", file=sys.stderr)
        return 1

    # An original's defaults: link-udp is declared on and query off in zenoh-pico.
    default_cases: list[tuple[str, dict[str, bool], bool]] = [
        ("defaults that agree pass", {"link-udp": True, "query": False}, True),
        ("a capability declared on that the original leaves off fails", {"link-udp": False}, False),
        ("a capability declared off that the original turns on fails", {"query": True}, False),
    ]
    for label, expected, want_ok in default_cases:
        got_ok = not upstream_default_arm("zenoh-pico", decl, expected)
        if got_ok != want_ok:
            print(f"  selftest FAIL [{label}]: expected {'pass' if want_ok else 'FAIL'}", file=sys.stderr)
            return 1
    if upstream_default_arm("zenoh-c", decl, {"query": True}) == []:
        print("  selftest FAIL [an original a capability states nothing for]: ACCEPTED", file=sys.stderr)
        return 1
    macro_decl = {"switches": [{"original": "zenoh-c", "switch": "unstable",
                                "macro": "Z_FEATURE_UNSTABLE_API"}]}
    if macro_arm(macro_decl, {"unstable": "Z_FEATURE_UNSTABLE_API"}) != [] \
            or macro_arm(macro_decl, {"unstable": "Z_FEATURE_UNSTABLE"}) == [] \
            or macro_arm(macro_decl, {}) == []:
        print("  selftest FAIL [a row's macro held to zenoh-c's table]", file=sys.stderr)
        return 1
    with tempfile.TemporaryDirectory() as td:
        build = Path(td) / "buildrs"
        build.mkdir()
        (build / "cbindgen_generator.rs").write_text(
            'static RUST_TO_C_FEATURES: phf::Map<&str, &str> = phf_map! {\n'
            '    "unstable" => "Z_FEATURE_UNSTABLE_API",\n'
            '    "transport_vsock" => "Z_FEATURE_VSOCK",\n};\n')
        if zenoh_c_macros(Path(td)) != {"unstable": "Z_FEATURE_UNSTABLE_API",
                                        "transport_vsock": "Z_FEATURE_VSOCK"}:
            print("  selftest FAIL [the zenoh-c macro table reader]", file=sys.stderr)
            return 1
    mapped = zenoh_c_expected(
        {"caps": {"link-udp": {}, "query": {}}, "switches": []},
        (("transport_udp", "maps", "wz-capi-c/link-udp", "x"), ("stats", "maps", "wz-capi-c/stats", "x"),
         ("transport_tcp", "always", "crates/x", "x")),
        {"transport_udp"},
    )
    if mapped != {"link-udp": True}:
        print(f"  selftest FAIL [the zenoh-c expectation]: {mapped}", file=sys.stderr)
        return 1

    up_cases: list[tuple[str, str, str | None, set[str], bool]] = [
        ("the faithful upstream passes", "1.0.0", "1.0.0", switches, True),
        ("a switch upstream GREW is unjudged", "1.0.0", "1.0.0", switches | {"Z_FEATURE_NEW"}, False),
        ("a switch upstream DROPPED is stale", "1.0.0", "1.0.0", switches - {"Z_FEATURE_QUERY"}, False),
        ("a source at another version is refused", "0.9.0", "1.0.0", switches, False),
        ("an unreadable pin is refused", "1.0.0", None, switches, False),
    ]
    for label, version, pinned, ups, want_ok in up_cases:
        got_ok = not upstream_arm("t", control, version, pinned, ups)
        if got_ok != want_ok:
            print(f"  selftest FAIL [{label}]: expected {'pass' if want_ok else 'FAIL'}", file=sys.stderr)
            return 1

    # Value switches: a number is `maps` to a limit that starts where pico does, or `never`/`n/a`.
    vdefaults = {"BATCH_MULTICAST_SIZE": "2048", "Z_TRANSPORT_LEASE": "10000", "ZP_HEADER": '""'}
    vdecl = {"limits": [{"id": "MCAST", "default": 2048}]}
    value_cases: list[tuple[str, dict, tuple, bool]] = [
        ("a value switch maps to a limit that defaults to pico's number", vdecl,
         (("BATCH_MULTICAST_SIZE", "maps", "limit:MCAST", "x"),), True),
        ("a value switch is never or n/a", vdecl,
         (("Z_TRANSPORT_LEASE", "never", None, "x"), ("ZP_HEADER", "n/a", None, "x")), True),
        ("a limit that starts elsewhere than pico fails", {"limits": [{"id": "MCAST", "default": 1024}]},
         (("BATCH_MULTICAST_SIZE", "maps", "limit:MCAST", "x"),), False),
        ("a value switch held fixed (always) fails", vdecl,
         (("Z_TRANSPORT_LEASE", "always", "crates/x", "x"),), False),
        ("a value switch mapped to a feature fails", vdecl,
         (("BATCH_MULTICAST_SIZE", "maps", "wz-capi-pico/query", "x"),), False),
        ("a capability switch anchored to a limit fails", vdecl,
         (("Z_FEATURE_QUERY", "maps", "limit:MCAST", "x"),), False),
        ("a value switch with no numeric default mapped to a limit fails", vdecl,
         (("ZP_HEADER", "maps", "limit:MCAST", "x"),), False),
    ]
    for label, d, rows, want_ok in value_cases:
        got_ok = not value_arm(d, rows, vdefaults)
        if got_ok != want_ok:
            print(f"  selftest FAIL [{label}]: expected {'pass' if want_ok else 'FAIL'}", file=sys.stderr)
            return 1
    limit_row = (("BATCH_MULTICAST_SIZE", "maps", "limit:MCAST", "a number"),)
    if shape_arm("t", limit_row, features, frozenset({"MCAST"})) != [] \
            or shape_arm("t", limit_row, features, frozenset()) == []:
        print("  selftest FAIL [a limit anchor names a declared limit]", file=sys.stderr)
        return 1

    # The readers: a CMakeLists with both spellings, and every unusable zenoh-c answer.
    with tempfile.TemporaryDirectory() as td:
        vsrc = Path(td) / "valued"
        (vsrc / "include" / "zenoh-pico").mkdir(parents=True)
        (vsrc / "include" / "zenoh-pico" / "config.h.in").write_text(
            "#define Z_BATCH_MULTICAST_SIZE @BATCH_MULTICAST_SIZE@\n"
            "#define Z_FEATURE_QUERY @Z_FEATURE_QUERY@\n#define Z_TRANSPORT_LEASE @Z_TRANSPORT_LEASE@\n")
        (vsrc / "CMakeLists.txt").write_text(
            'set(BATCH_MULTICAST_SIZE 2048 CACHE STRING "m")\n'
            'if(X)\n  set(BATCH_MULTICAST_SIZE 512 CACHE STRING "m" FORCE)\nendif()\n')
        if pico_value_defaults(vsrc) != {"BATCH_MULTICAST_SIZE": "2048", "Z_TRANSPORT_LEASE": ""}:
            print(f"  selftest FAIL [the pico value reader]: {pico_value_defaults(vsrc)}", file=sys.stderr)
            return 1
    with tempfile.TemporaryDirectory() as td:
        src = Path(td)
        (src / "version.txt").write_text("1.0.0\n")
        (src / "CMakeLists.txt").write_text(
            'set(Z_FEATURE_QUERY 1 CACHE STRING "q")\noption(Z_FEATURE_LINK_TCP "t" ON)\n'
            'set(Z_FEATURE_RX_CACHE 0 CACHE STRING "r")\n'
            "# Z_FEATURE_COMMENTED is not a definition\n"
            'if(NOT Z_FEATURE_LINK_TCP)\n  set(Z_FEATURE_QUERY 0 CACHE STRING "q" FORCE)\nendif()\n'
        )
        version, found = pico_switches(src)
        if version != "1.0.0" or found != {"Z_FEATURE_QUERY", "Z_FEATURE_LINK_TCP", "Z_FEATURE_RX_CACHE"}:
            print(f"  selftest FAIL [the pico reader]: read {version} {sorted(found)}", file=sys.stderr)
            return 1
        defaults = pico_defaults(src)
        if defaults != {"Z_FEATURE_QUERY": True, "Z_FEATURE_LINK_TCP": True, "Z_FEATURE_RX_CACHE": False}:
            print(f"  selftest FAIL [the pico default reader, a FORCE inside a branch is not the "
                  f"default]: {defaults}", file=sys.stderr)
            return 1
        (src / "CMakeLists.txt").write_text("project(x)\n")
        try:
            pico_switches(src)
        except InputError:
            pass
        else:
            print("  selftest FAIL [a CMakeLists with no switch]: ACCEPTED", file=sys.stderr)
            return 1
        # The 1.10.2 layout: the definitions in cmake/feature_config.cmake, the CMakeLists only
        # including it and reading the switches.
        (src / "cmake").mkdir()
        (src / "cmake" / "feature_config.cmake").write_text(
            'set(Z_FEATURE_QUERY 1 CACHE STRING "q")\nset(Z_FEATURE_RX_CACHE 0 CACHE STRING "r")\n'
            'if(X)\n  set(Z_FEATURE_QUERY 0 CACHE STRING "q" FORCE)\nendif()\n')
        (src / "CMakeLists.txt").write_text("include(feature_config)\nmessage(${Z_FEATURE_QUERY})\n")
        version, found = pico_switches(src)
        if version != "1.0.0" or found != {"Z_FEATURE_QUERY", "Z_FEATURE_RX_CACHE"} \
                or pico_defaults(src) != {"Z_FEATURE_QUERY": True, "Z_FEATURE_RX_CACHE": False}:
            print(f"  selftest FAIL [the pico reader on the split layout]: read {version} "
                  f"{sorted(found)} {pico_defaults(src)}", file=sys.stderr)
            return 1
        (src / "cmake" / "feature_config.cmake").unlink()
        (src / "cmake").rmdir()

        meta = src / "meta.json"
        meta.write_text(json.dumps({"packages": [{
            "name": ZENOH_C_PACKAGE, "version": "1.0.0",
            "features": {"default": ["a"], "a": [], "zenoh-ext": ["dep:zenoh-ext"], "b": ["dep:zenoh-shm", "a"]},
            "dependencies": [{"name": "zenoh-ext", "optional": True}, {"name": "zenoh-shm", "optional": True}],
        }]}))
        os.environ["WZ_ZENOH_C_METADATA"] = str(meta)
        try:
            version, caps, derived, default_features = zenoh_c_switches(src)
        finally:
            os.environ.pop("WZ_ZENOH_C_METADATA", None)
        if caps != {"a", "b"} or set(derived) != {"default", "zenoh-ext"} or default_features != {"a"}:
            print(f"  selftest FAIL [the zenoh-c reader]: {sorted(caps)} {sorted(derived)} "
                  f"{sorted(default_features)}", file=sys.stderr)
            return 1
        for label, text in (("an empty file", ""), ("JSON with no packages", '{"x": 1}'),
                            ("packages that is not an array", '{"packages": {}}'),
                            ("no zenoh-c package", '{"packages": []}')):
            meta.write_text(text)
            os.environ["WZ_ZENOH_C_METADATA"] = str(meta)
            try:
                zenoh_c_switches(src)
            except InputError:
                continue
            except Exception as e:  # noqa: BLE001 - the defect IS "some other exception"
                print(f"  selftest FAIL [{label}]: raised {type(e).__name__}, not InputError", file=sys.stderr)
                return 1
            else:
                print(f"  selftest FAIL [{label}]: ACCEPTED", file=sys.stderr)
                return 1
            finally:
                os.environ.pop("WZ_ZENOH_C_METADATA", None)

    print(
        f"  upstream-switch-map: selftest {len(shape_cases)} shape + {len(decl_cases)} declaration "
        f"+ {len(default_cases) + 2} default + {len(up_cases)} upstream + {len(value_cases) + 1} value "
        f"case(s) and the readers pass"
    )
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(description="zenoh-pico and zenoh-c build switches against wz")
    ap.add_argument(
        "--zenoh-c",
        action="store_true",
        help="grade the zenoh-c table against its checkout instead of the zenoh-pico table against its pin",
    )
    ap.add_argument("--selftest", action="store_true", help="drive every failure branch on fixtures")
    args = ap.parse_args()
    if args.selftest:
        return selftest()

    try:
        features = crate_features()
        pinned = pins()
        decl = wz_config.load_decl()
    except (InputError, ValueError) as e:
        print(f"  upstream-switch-map: INPUT -- {e}", file=sys.stderr)
        return 2

    failures: list[str] = []
    tables = {original: rows_of(decl, original) for original in ORIGINALS}
    for table, rows in tables.items():
        report(table, rows)
        failures += shape_arm(table, rows, features, frozenset(lim["id"] for lim in decl["limits"]))
    failures += declaration_arm(decl)

    try:
        if args.zenoh_c:
            version, caps, derived, default_features = zenoh_c_switches(zenoh_c_source())
            for name, why in sorted(derived.items()):
                print(f"    zenoh-c not a switch: {name} -- {why}")
            failures += upstream_arm("zenoh-c", tables["zenoh-c"], version, pinned["zenoh-c"], caps)
            expected = zenoh_c_expected(decl, tables["zenoh-c"], default_features)
            failures += upstream_default_arm("zenoh-c", decl, expected)
            failures += macro_arm(decl, zenoh_c_macros(zenoh_c_source()))
            print(f"    zenoh-c defaults: {len(expected)} capability default(s) held to its "
                  f"`default` features")
            print(
                "    -- zenoh-pico upstream arm DEFERRED: the default run grades it, in a lane "
                "whose checkout carries the submodule's tags."
            )
        else:
            version, switches = pico_switches(PICO_SOURCE)
            value_defaults = pico_value_defaults(PICO_SOURCE)
            failures += upstream_arm("zenoh-pico", tables["zenoh-pico"], version, pinned["zenoh-pico"],
                                     switches | set(value_defaults))
            failures += value_arm(decl, tables["zenoh-pico"], value_defaults)
            print(f"    zenoh-pico value switches: {len(value_defaults)} judged as values "
                  f"({', '.join(sorted(value_defaults))})")
            expected = pico_expected(decl, pico_defaults(PICO_SOURCE))
            failures += upstream_default_arm("zenoh-pico", decl, expected)
            unswitched = sorted(cid for cid, cap in decl["caps"].items()
                                if "zenoh-pico" in wz_config.upstream_families(cap) and cid not in expected)
            print(f"    zenoh-pico defaults: {len(expected)} capability default(s) held to its "
                  f"CMakeLists; judged with no pico switch: {', '.join(unswitched) or 'none'}")
            print(
                "    -- zenoh-c upstream arm DEFERRED: run with --zenoh-c where the pinned "
                "zenoh-c checkout is provisioned. Without it, a switch zenoh-c GREW cannot be seen."
            )
    except InputError as e:
        print(f"  upstream-switch-map: INPUT -- {e}", file=sys.stderr)
        return 2

    if failures:
        for f in failures:
            print(f"  upstream-switch-map: FAIL -- {f}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
