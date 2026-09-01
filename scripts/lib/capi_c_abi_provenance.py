#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
# SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
"""R2239 (no register item) — check WHY each §5.27 api-compat-c footprint is the
number it is, against upstream's own declarations.

The citation is `no register item` in the sense `debt_plane_census.py` uses: the
item this closes — open-debt 586, completion condition 2, "each type's size must
be DERIVABLE from upstream's field composition, not fitted to a literal" — lives
in the agent-memory register and has no store id for `gate_provenance_lint.py`
to resolve. It is named in prose here instead.

## The class

`scripts/check-capi-c-opaque-arms.sh` measures every opaque footprint this crate
declares against upstream's generator, on all four feature arms. It answers "is
the number right". It cannot answer "is the number right FOR THE REASON the
crate states", because the reasons were prose.

They were also wrong. `REPLY_ERR_SIZE` was `BYTES_SIZE + ENCODING_SIZE`,
justified by a comment saying upstream's `ReplyError` is
`{ ZBytes payload, Encoding encoding }`. zenoh 1.10.0 gave that struct a third
field behind `feature = "unstable"`, so the composition became false on two of
the four arms — and the comment stating it stayed exactly as it was, because
nothing reads a comment. The size error surfaced two rounds later as a red
hosted job.

## What this checks, and how each half is derived rather than declared

1. NAME SET. `WZ_CAPI_C_ABI_ORIGIN` in `abi_origin.rs` must cover exactly the
   union of the three `WZ_CAPI_C_LAYOUT_NAMES_*` tables in `abi.rs` — the same
   artifact the arms gate reads out of the cdylib, here read out of the source
   so this can run without a build.

2. ORIGIN. Every row claiming an upstream Rust type must agree, string for
   string, with `get_opaque_type_data!` in zenoh-c's
   `build-resources/opaque-types/src/lib.rs`. The `@transparent` / `@synthetic`
   classifications are checked in the OTHER direction: a name so marked must be
   ABSENT from the generator's declarations. An unclassified name is a failure,
   so the two markers cannot be used to make a hard row go away.

3. COMPOSITION. Every type whose footprint MOVES across the arms it exists on
   must carry a row in `WZ_CAPI_C_ABI_COMPOSITION`, and that row must evaluate
   to upstream's own number on every one of those arms. The population is
   derived from upstream's four generated tables, not from the crate's list, so
   a type that STARTS moving arrives as a missing row. That is the check that
   would have caught `ReplyError` at the pin bump instead of two rounds later.

An empty population on any of the three is a failure, not a pass: a run that
compared nothing has not agreed with anything.
"""

from __future__ import annotations

import argparse
import pathlib
import re
import sys
import tempfile

# `get_opaque_type_data!(<rust type expr>, <c name>);`, possibly across lines.
UPSTREAM_DECL = re.compile(
    r"get_opaque_type_data!\(\s*(.+?)\s*,\s*(\w+)\s*\)\s*;", re.S
)
SIZE_RECORD = re.compile(r"type: (\w+), align: (\d+), size: (\d+)")
ARMS = ("nounstable", "unstable", "nounstable-shm", "unstable-shm")


def die(msg: str) -> None:
    print(f"[capi-c-abi-provenance] FAIL — {msg}", file=sys.stderr)


def say(msg: str) -> None:
    print(f"[capi-c-abi-provenance] {msg}")


def upstream_origins(path: pathlib.Path) -> dict[str, str]:
    """`{c_name: upstream rust type expression}` from zenoh-c's own generator."""
    text = path.read_text(errors="replace")
    return {
        m.group(2): " ".join(m.group(1).split()) for m in UPSTREAM_DECL.finditer(text)
    }


def arm_tables(directory: pathlib.Path) -> dict[str, dict[str, int]]:
    """`{arm: {c_name: size}}` from the four generator stderr files."""
    out: dict[str, dict[str, int]] = {}
    for arm in ARMS:
        f = directory / f"{arm}.stderr"
        if not f.is_file():
            continue
        text = f.read_text(errors="replace")
        table = {m.group(1): int(m.group(3)) for m in SIZE_RECORD.finditer(text)}
        if table:
            out[arm] = table
    return out


def rust_pairs(text: str, const_name: str) -> list[tuple[str, str]] | None:
    """The `(&str, &str)` rows of a named Rust slice constant."""
    m = re.search(
        r"pub const " + const_name + r": &\[\(&str, &str\)\] = &\[(.*?)\n\];",
        text,
        re.S,
    )
    if not m:
        return None
    return re.findall(r'\(\s*"((?:[^"\\]|\\.)*)"\s*,\s*"((?:[^"\\]|\\.)*)"\s*,?\s*\)', m.group(1))


def layout_names(text: str) -> list[str]:
    """The union of the three `WZ_CAPI_C_LAYOUT_NAMES_*` tables.

    Both `#[cfg]` arms of each are read and merged: the crate's own test checks
    the per-arm subset, and this needs the union it can see without a build.
    """
    names: list[str] = []
    for m in re.finditer(
        r"pub const WZ_CAPI_C_LAYOUT_NAMES_\w+: &\[&str\] = &\[", text
    ):
        rest = text[m.end():]
        # The body ends at a `];` in COLUMN ZERO. A `.*?\n\];` non-greedy scan
        # gets this wrong twice over: one of the row comments contains
        # `uint8_t _0[24]; }`, and the empty `= &[];` arms carry no terminator
        # of that shape at all, so the match runs on into the next constant and
        # swallows the `#[cfg(feature = "...")]` strings between them.
        empty = re.match(r"\s*\];", rest)
        if empty:
            continue
        end = re.search(r"^\];", rest, re.M)
        if end is None:
            continue
        names.extend(re.findall(r'"([^"]+)"', rest[: end.start()]))
    return names


def arm_has(arm: str, axis: str) -> bool:
    if axis == "shm":
        return arm.endswith("-shm")
    if axis == "unstable":
        return not arm.startswith("nounstable")
    raise ValueError(axis)


def evaluate(expr: str, arm: str, table: dict[str, int]) -> int | None:
    """Evaluate one composition expression on one arm, or `None` if a term is
    a type the arm's table does not describe."""
    total = 0
    for term in expr.split("+"):
        term = term.strip()
        head, _, axis = term.partition("@")
        head = head.strip()
        axis = axis.strip()
        if axis and not arm_has(arm, axis):
            continue
        if head.isdigit():
            total += int(head)
        else:
            if head not in table:
                return None
            total += table[head]
    return total


def check(
    origin_rows: list[tuple[str, str]],
    composition_rows: list[tuple[str, str]],
    declared: list[str],
    upstream: dict[str, str],
    tables: dict[str, dict[str, int]],
) -> int:
    rc = 0

    # ── 1. name set ─────────────────────────────────────────────────────────
    origin_names = [n for n, _ in origin_rows]
    if not declared:
        die("the crate declares NO layout names; nothing to attribute.")
        return 1
    if not origin_names:
        die("WZ_CAPI_C_ABI_ORIGIN is empty; every footprint is unattributed.")
        return 1
    missing = sorted(set(declared) - set(origin_names))
    extra = sorted(set(origin_names) - set(declared))
    for n in missing:
        print(f"  UNATTRIBUTED {n}: declared in a layout table, no origin row",
              file=sys.stderr)
    for n in extra:
        print(f"  ORPHAN ORIGIN {n}: origin row for a name no layout table declares",
              file=sys.stderr)
    if missing or extra:
        rc = 1
    say(f"name set: {len(declared)} declared footprint(s), "
        f"{len(origin_names)} origin row(s), {len(missing)} unattributed, "
        f"{len(extra)} orphan")

    # ── 2. origin ───────────────────────────────────────────────────────────
    if not upstream:
        die("upstream declared NO opaque types; the origin table has nothing "
            "to be checked against, and calling that agreement would be vacuous.")
        return 1
    claimed = disagreed = classified = 0
    for name, origin in origin_rows:
        if origin.startswith("@"):
            if origin not in ("@transparent", "@synthetic"):
                print(f"  UNKNOWN CLASS {name}: {origin}", file=sys.stderr)
                rc = 1
                continue
            classified += 1
            if name in upstream:
                # The escape hatch, checked in the direction that matters.
                print(
                    f"  MISCLASSIFIED {name}: marked {origin}, but upstream's "
                    f"opaque generator DOES declare it as {upstream[name]}",
                    file=sys.stderr,
                )
                rc = 1
            continue
        claimed += 1
        if name not in upstream:
            print(
                f"  NO UPSTREAM DECL {name}: claims origin {origin!r}, which "
                f"upstream's opaque generator does not declare at all",
                file=sys.stderr,
            )
            disagreed += 1
            rc = 1
        elif upstream[name] != origin:
            print(
                f"  ORIGIN MISMATCH {name}: crate says {origin!r}, upstream "
                f"declares {upstream[name]!r}",
                file=sys.stderr,
            )
            disagreed += 1
            rc = 1
    if claimed == 0:
        die("no row claims an upstream origin; every footprint was classified "
            "away, which is the shape this gate refuses.")
        rc = 1
    say(f"origin: {claimed} row(s) checked against upstream's own declaration, "
        f"{classified} classified (@transparent / @synthetic, checked absent "
        f"from it), {disagreed} disagree")

    # ── 3. composition ──────────────────────────────────────────────────────
    if len(tables) != len(ARMS):
        die(f"only {len(tables)} of {len(ARMS)} generator tables are present "
            f"({sorted(tables)}); the moving-type population is derived from "
            f"all four and a partial derivation would under-report it.")
        return 1
    moving: set[str] = set()
    for name in declared:
        sizes = {arm: t[name] for arm, t in tables.items() if name in t}
        if len(set(sizes.values())) > 1:
            moving.add(name)
    composed = {n for n, _ in composition_rows}
    if not moving:
        die("NO declared type moves across the four arms. Upstream's tables "
            "make the two axes independent, so an empty population means the "
            "tables were not read, not that nothing moves.")
        return 1
    for n in sorted(moving - composed):
        print(f"  UNCOMPOSED {n}: its footprint moves across the arms and no "
              f"WZ_CAPI_C_ABI_COMPOSITION row says why", file=sys.stderr)
        rc = 1
    for n in sorted(composed - moving):
        print(f"  STATIC COMPOSITION {n}: composed, but upstream's tables give "
              f"it one size on every arm it exists on", file=sys.stderr)
        rc = 1
    bad = 0
    for name, expr in composition_rows:
        for arm, table in sorted(tables.items()):
            if name not in table:
                continue
            got = evaluate(expr, arm, table)
            if got is None:
                print(f"  UNEVALUABLE {name} on {arm}: {expr!r} names a type "
                      f"that arm's table does not describe", file=sys.stderr)
                bad += 1
                rc = 1
            elif got != table[name]:
                print(f"  COMPOSITION MISMATCH {name} on {arm}: {expr} = {got}, "
                      f"upstream says {table[name]}", file=sys.stderr)
                bad += 1
                rc = 1
    say(f"composition: {len(moving)} type(s) move across the arms, "
        f"{len(composition_rows)} row(s) evaluated on {len(tables)} arm(s), "
        f"{bad} disagree")

    if rc == 0:
        say("OK — every footprint is attributed to upstream's own declaration "
            "and every moving one derives to upstream's own number.")
    return rc


def run(opaque_types: pathlib.Path, tables_dir: pathlib.Path,
        crate_src: pathlib.Path) -> int:
    if not opaque_types.is_file():
        die(f"zenoh-c's opaque-type source is absent at {opaque_types}. This "
            f"gate reads upstream's own declaration of the correspondence; "
            f"without it there is nothing to check against.")
        return 1
    abi = crate_src / "abi.rs"
    origin = crate_src / "abi_origin.rs"
    for f in (abi, origin):
        if not f.is_file():
            die(f"{f} is absent.")
            return 1
    origin_text = origin.read_text()
    rows = rust_pairs(origin_text, "WZ_CAPI_C_ABI_ORIGIN")
    comp = rust_pairs(origin_text, "WZ_CAPI_C_ABI_COMPOSITION")
    if rows is None or comp is None:
        die(f"could not read the origin / composition tables out of {origin}.")
        return 1
    return check(
        rows, comp, layout_names(abi.read_text()),
        upstream_origins(opaque_types), arm_tables(tables_dir),
    )


# ── selftest ────────────────────────────────────────────────────────────────
#
# The fixture is deliberately the shape the OLD crate had: `z_owned_reply_err_t`
# composed as bytes + encoding with no unstable term, against 1.10.0's tables
# where it moves on that axis. A fixture that could not express the swallowed
# case would make this gate green from birth.

_FIX_UPSTREAM = """
get_opaque_type_data!(ZBytes, z_owned_bytes_t);
get_opaque_type_data!(Encoding, z_owned_encoding_t);
get_opaque_type_data!(ReplyError, z_owned_reply_err_t);
get_opaque_type_data!(Option<Session>, z_owned_session_t);
"""

_FIX_SIZES = {
    "nounstable": {"z_owned_bytes_t": 32, "z_owned_encoding_t": 40,
                   "z_owned_reply_err_t": 72, "z_owned_session_t": 8},
    "unstable": {"z_owned_bytes_t": 32, "z_owned_encoding_t": 40,
                 "z_owned_reply_err_t": 104, "z_owned_session_t": 8},
    "nounstable-shm": {"z_owned_bytes_t": 40, "z_owned_encoding_t": 48,
                       "z_owned_reply_err_t": 88, "z_owned_session_t": 8},
    "unstable-shm": {"z_owned_bytes_t": 40, "z_owned_encoding_t": 48,
                     "z_owned_reply_err_t": 120, "z_owned_session_t": 8},
}

_FIX_ABI = '''
pub const WZ_CAPI_C_LAYOUT_NAMES_BASE: &[&str] = &[
    "z_owned_bytes_t",
    "z_owned_encoding_t",
    "z_owned_reply_err_t",
    "z_owned_session_t",
    "z_get_options_t",
];
'''

_FIX_ORIGIN_OK = '''
pub const WZ_CAPI_C_ABI_ORIGIN: &[(&str, &str)] = &[
    ("z_owned_bytes_t", "ZBytes"),
    ("z_owned_encoding_t", "Encoding"),
    ("z_owned_reply_err_t", "ReplyError"),
    ("z_owned_session_t", "Option<Session>"),
    ("z_get_options_t", "@transparent"),
];
pub const WZ_CAPI_C_ABI_COMPOSITION: &[(&str, &str)] = &[
    ("z_owned_bytes_t", "32 + 8@shm"),
    ("z_owned_encoding_t", "40 + 8@shm"),
    ("z_owned_reply_err_t", "z_owned_bytes_t + z_owned_encoding_t + 32@unstable"),
];
'''


def _write_fixture(root: pathlib.Path, origin_src: str,
                   upstream_src: str = _FIX_UPSTREAM,
                   sizes: dict[str, dict[str, int]] | None = None) -> tuple[
                       pathlib.Path, pathlib.Path, pathlib.Path]:
    src = root / "src"
    src.mkdir(parents=True, exist_ok=True)
    (src / "abi.rs").write_text(_FIX_ABI)
    (src / "abi_origin.rs").write_text(origin_src)
    up = root / "opaque.rs"
    up.write_text(upstream_src)
    tabs = root / "tables"
    tabs.mkdir(exist_ok=True)
    for arm, table in (sizes if sizes is not None else _FIX_SIZES).items():
        (tabs / f"{arm}.stderr").write_text(
            "".join(f"type: {n}, align: 8, size: {v}\n" for n, v in table.items())
        )
    return up, tabs, src


def selftest() -> int:
    cases: list[tuple[str, str, int]] = [
        ("the honest fixture passes", _FIX_ORIGIN_OK, 0),
        # The swallowed shape: the pre-1.10.0 composition against 1.10.0 tables.
        ("a composition that lost its unstable term reds",
         _FIX_ORIGIN_OK.replace(" + 32@unstable", ""), 1),
        ("a wrong upstream origin reds",
         _FIX_ORIGIN_OK.replace('"ReplyError"', '"Option<ReplyError>"'), 1),
        ("dropping an origin row reds",
         _FIX_ORIGIN_OK.replace('    ("z_owned_session_t", "Option<Session>"),\n', ""),
         1),
        ("classifying a real opaque type away reds",
         _FIX_ORIGIN_OK.replace('"ReplyError"', '"@transparent"'), 1),
        ("dropping a composition row for a moving type reds",
         _FIX_ORIGIN_OK.replace('    ("z_owned_bytes_t", "32 + 8@shm"),\n', ""), 1),
        ("composing a type that does not move reds",
         _FIX_ORIGIN_OK.replace(
             '    ("z_owned_bytes_t", "32 + 8@shm"),\n',
             '    ("z_owned_bytes_t", "32 + 8@shm"),\n'
             '    ("z_owned_session_t", "8"),\n'), 1),
        ("an empty origin table reds",
         re.sub(r"WZ_CAPI_C_ABI_ORIGIN: &\[\(&str, &str\)\] = &\[.*?\n\];",
                "WZ_CAPI_C_ABI_ORIGIN: &[(&str, &str)] = &[\n];",
                _FIX_ORIGIN_OK, flags=re.S), 1),
    ]
    failures = 0
    for label, origin_src, want in cases:
        with tempfile.TemporaryDirectory() as d:
            up, tabs, src = _write_fixture(pathlib.Path(d), origin_src)
            got = run(up, tabs, src)
        ok = got == want
        failures += not ok
        print(f"  [{'ok' if ok else 'FAILED'}] {label} (want rc={want}, got {got})")

    # Two more that vary the OTHER inputs rather than the crate's tables.
    with tempfile.TemporaryDirectory() as d:
        up, tabs, src = _write_fixture(pathlib.Path(d), _FIX_ORIGIN_OK,
                                       upstream_src="// nothing\n")
        got = run(up, tabs, src)
    ok = got == 1
    failures += not ok
    print(f"  [{'ok' if ok else 'FAILED'}] an upstream source declaring nothing "
          f"reds rather than passing vacuously (want rc=1, got {got})")

    with tempfile.TemporaryDirectory() as d:
        flat = {arm: dict(t) for arm, t in _FIX_SIZES.items()}
        for arm in flat:
            flat[arm] = {n: 8 for n in flat[arm]}
        up, tabs, src = _write_fixture(pathlib.Path(d), _FIX_ORIGIN_OK, sizes=flat)
        got = run(up, tabs, src)
    ok = got == 1
    failures += not ok
    print(f"  [{'ok' if ok else 'FAILED'}] tables in which nothing moves red "
          f"rather than reporting an empty population as agreement "
          f"(want rc=1, got {got})")

    with tempfile.TemporaryDirectory() as d:
        partial = {a: t for a, t in _FIX_SIZES.items() if a != "unstable-shm"}
        up, tabs, src = _write_fixture(pathlib.Path(d), _FIX_ORIGIN_OK, sizes=partial)
        got = run(up, tabs, src)
    ok = got == 1
    failures += not ok
    print(f"  [{'ok' if ok else 'FAILED'}] three of four tables red rather than "
          f"deriving the population from a partial read (want rc=1, got {got})")

    print(f"[capi-c-abi-provenance] selftest: {failures} failure(s)")
    return 1 if failures else 0


def main() -> int:
    root = pathlib.Path(__file__).resolve().parents[2]
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--opaque-types", type=pathlib.Path)
    ap.add_argument("--tables", type=pathlib.Path,
                    default=root / "target/zenoh-c-opaque")
    ap.add_argument("--crate-src", type=pathlib.Path,
                    default=root / "crates/wz-capi-c/src")
    ap.add_argument("--selftest", action="store_true",
                    help="drive the checks against fixtures, including the "
                         "shape the old crate swallowed")
    args = ap.parse_args()
    if args.selftest:
        return selftest()
    opaque = args.opaque_types
    if opaque is None:
        import os
        ref = pathlib.Path(os.environ.get("WZ_ZENOH_C_REF", pathlib.Path.home() / "zenoh-c-ref"))
        opaque = ref / "build-resources/opaque-types/src/lib.rs"
    return run(opaque, args.tables, args.crate_src)


if __name__ == "__main__":
    sys.exit(main())
