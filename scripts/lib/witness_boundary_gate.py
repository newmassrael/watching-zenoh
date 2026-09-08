#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
# SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
"""R2450 (no register item) — a codec-elision WITNESS is a name whose existence
must be guaranteed, and nothing said so.

The citation is `no register item` for the reason `config_key_fixture_gate.py`
gives for its own: the item this pays down -- unregistered open-debt item 695,
piece 3 (hosted Layer F red) -- lives in the agent-memory register, which has no
store id for `gate_provenance_lint.py` to resolve. Naming "nothing" is the true
answer here; the item is named in prose throughout this header.

## The defect, and it had already been paid for once

`measure-codec-footprint.sh` judges each codec-X atomic feature two ways:

  * a BYTE DELTA between the baseline binary and a minus-codec-X binary, and
  * a BY-NAME WITNESS -- `CODEC_ELISION_WITNESS[codec-X]` -- a symbol the codec
    owns which must be present in the baseline and absent from the minus build.

The witness half exists BECAUSE the byte half is unreliable: a difference of two
2.7MB binaries whose inlining differs tracks the CALLER's inline boundary, not
the codec, and three separate rounds re-pinned a floor for exactly that reason
(R311y437, R311y580, R311y822, each recorded in that script).

R311y822 moved codec-close's claim onto a witness,
`wz_session_core::handshake_encode::encode_close`. THE WITNESS HALF THEN
INHERITED THE WEAKNESS IT WAS BUILT TO ESCAPE, because whether a name EXISTS in
the baseline is itself an inlining decision. The per-symbol diff R311y822
recorded reads `-86 ... encode_close (86 -> 0)`: the function was out-of-line
that day, and nothing held it there. An 86-byte body reached from three call
sites is on the knife edge, and a `wz-runtime-tokio` change that touched neither
that file nor that feature pushed it across. Hosted Layer F shard 1/4 then
redded `WITNESS MISSING codec-close` on EVERY completed run from 2026-09-05 to
2026-09-08 -- roughly twenty-five of them -- while the sibling witness
`codec-keep-alive` stayed green, because R311y878 had given ITS function an
`#[inline(never)]` boundary in the same commit that pinned it.

So one witness held by construction and the other by the optimizer's grace, and
the two were indistinguishable at the point where a witness is WRITTEN DOWN.

## What this gate checks, and why each direction matters

For every entry in `CODEC_ELISION_WITNESS`, read out of that script so the map
stays the single source:

1. The named function EXISTS in the named crate's sources. A witness pointing at
   a renamed function is a witness pointing at nothing, and the runtime gate
   cannot tell that case from an inlined one -- its own message lists three
   possible causes and guesses between them. Answered here by name, statically.
2. Its module half is real: the last module segment is the file's own stem, or a
   `mod <segment>` that file declares. A path that resolves to a function of the
   right name in the wrong module is a name that will drift silently.
3. It carries `#[inline(never)]`. This is the whole point: the attribute is what
   makes "the symbol exists in the baseline" a property of the SOURCE rather
   than of an optimizer decision that an unrelated edit can flip. Both existing
   precedents in this tree say so in their own doc comments -- R311y878 on
   `decode_keep_alive` and R311y802 on `declare_envelope_extensions`, the second
   of which was itself bisected to a codec-close Layer F red.

## Why a static gate can answer this at all, and where it runs

BOTH SIDES ARE READABLE WITHOUT BUILDING ANYTHING: the map is a bash
associative array and the boundary is an attribute in a tracked `.rs` file. So
this costs milliseconds, which is why it runs in `pre-push` as well as at the
TOP of Layer F -- ahead of that lane's sixteen release builds, so an authoring
defect is reported in a tenth of a second instead of four minutes.

`pre-push` is the placement that matters for this class. Layer F is hosted-only
by policy (CLAUDE.md: the hook is a fast gate, not a CI mirror), and that is
precisely how this red survived twenty-five completed runs unread. A witness
pinned without a boundary is now refused before it is published.

## Anti-vacuity

An empty population FAILS. A gate whose subject set is derived can report green
by finding nothing to grade, and this tree has paid for that shape repeatedly
(the `--census` note in `nondefault-tests-gate.sh` names it). The count of
witnesses read is PRINTED, so "it passed" can never be confused with "it looked
at nothing". Every resolution failure is likewise a FAIL, never a skip: a gate
that cannot read its input must not report green.
"""

import pathlib
import re
import sys
import tempfile

SCRIPT_REL = "scripts/measure-codec-footprint.sh"
MAP_NAME = "CODEC_ELISION_WITNESS"
BOUNDARY = "#[inline(never)]"

# `[codec-close]="wz_session_core::handshake_encode::encode_close"`
_ENTRY = re.compile(r'^\s*\[([^\]]+)\]\s*=\s*"([^"]*)"\s*$')


def witnesses(script: pathlib.Path) -> "list[tuple[str, str]]":
    """The (codec, witness-path) pairs declared in the footprint script.

    Derived from the script's own array so the map is not written twice. Comment
    lines inside the block -- of which there are many, carrying the measurement
    history -- are skipped, and the block ends at its closing paren.
    """
    out: "list[tuple[str, str]]" = []
    inside = False
    for line in script.read_text().splitlines():
        if not inside:
            if re.match(rf"^\s*declare\s+-A\s+{MAP_NAME}=\(\s*$", line):
                inside = True
            continue
        if re.match(r"^\s*\)\s*$", line):
            break
        if line.lstrip().startswith("#"):
            continue
        m = _ENTRY.match(line)
        if m:
            out.append((m.group(1), m.group(2)))
    return out


def fn_def_pattern(name: str) -> "re.Pattern[str]":
    return re.compile(
        r"^\s*(?:pub(?:\([^)]*\))?\s+)?"
        r"(?:default\s+)?(?:const\s+)?(?:async\s+)?(?:unsafe\s+)?"
        r'(?:extern\s+"[^"]*"\s+)?'
        r"fn\s+" + re.escape(name) + r"\s*[(<]"
    )


def find_definitions(src_root: pathlib.Path, name: str) -> "list[tuple[pathlib.Path, int]]":
    """Every `fn <name>` definition under a crate's sources, as (file, index)."""
    pat = fn_def_pattern(name)
    hits: "list[tuple[pathlib.Path, int]]" = []
    for path in sorted(src_root.rglob("*.rs")):
        for i, line in enumerate(path.read_text(errors="replace").splitlines()):
            if pat.match(line):
                hits.append((path, i))
    return hits


def has_boundary(lines: "list[str]", idx: int) -> bool:
    """Does the attribute run attached to `lines[idx]` carry `#[inline(never)]`?

    Walked UPWARD with a bracket balance rather than by line shape, because an
    attribute may span lines (`#[cfg(all(` .. `))]`) and a shape test for that
    is a guess. A blank line or a comment does not break the run -- Rust
    attaches across both -- but the first line of real code does, so an
    attribute belonging to a previous item can never be read as this one's.
    """
    buf: "list[str]" = []
    i = idx - 1
    while i >= 0:
        stripped = lines[i].strip()
        if not buf and (stripped == "" or stripped.startswith("//")):
            i -= 1
            continue
        buf.insert(0, lines[i])
        joined = "".join(buf)
        if joined.count("[") == joined.count("]") and joined.count("(") == joined.count(")"):
            head = joined.strip()
            if not (head.startswith("#[") or head.startswith("#![")):
                return False
            if BOUNDARY.replace(" ", "") in head.replace(" ", ""):
                return True
            buf = []
        i -= 1
    return False


def findings(root: pathlib.Path) -> "tuple[list[str], list[str]]":
    """(problems, resolved) for every witness the footprint script declares."""
    problems: "list[str]" = []
    resolved: "list[str]" = []

    script = root / SCRIPT_REL
    if not script.is_file():
        return ([f"{SCRIPT_REL} is not a file, so the witness map cannot be read"], [])

    pairs = witnesses(script)
    if not pairs:
        return (
            [
                f"read 0 witness(es) from {SCRIPT_REL}::{MAP_NAME} -- either the map "
                "is empty or its shape changed and this gate is grading nothing"
            ],
            [],
        )

    for codec, path_str in pairs:
        segments = path_str.split("::")
        if len(segments) < 2:
            problems.append(
                f"{codec}: witness `{path_str}` is not a `crate::..::fn` path, so "
                "neither the crate nor the function it names can be resolved"
            )
            continue
        crate_snake, mods, fn_name = segments[0], segments[1:-1], segments[-1]
        crate_dir = root / "crates" / crate_snake.replace("_", "-")
        src_root = crate_dir / "src"
        if not src_root.is_dir():
            problems.append(
                f"{codec}: witness `{path_str}` names crate `{crate_snake}`, but "
                f"{src_root.relative_to(root)} is not a directory"
            )
            continue

        hits = find_definitions(src_root, fn_name)
        if not hits:
            problems.append(
                f"{codec}: witness `{path_str}` names `fn {fn_name}`, which is not "
                f"defined anywhere under {src_root.relative_to(root)}. Either it was "
                "renamed (fix CODEC_ELISION_WITNESS) or it is gone -- and the "
                "runtime gate cannot tell that from an inlined symbol."
            )
            continue
        if len(hits) > 1:
            where = ", ".join(f"{p.relative_to(root)}:{i + 1}" for p, i in hits)
            problems.append(
                f"{codec}: witness `{path_str}` names `fn {fn_name}`, which is "
                f"defined {len(hits)} times ({where}). The witness must identify "
                "ONE function; nm reports one name and this gate must not guess."
            )
            continue

        path, idx = hits[0]
        lines = path.read_text(errors="replace").splitlines()
        rel = path.relative_to(root)

        if mods:
            leaf = mods[-1]
            declares = re.search(rf"^\s*(?:pub(?:\([^)]*\))?\s+)?mod\s+{re.escape(leaf)}\b", "\n".join(lines), re.M)
            if path.stem != leaf and not declares:
                problems.append(
                    f"{codec}: witness `{path_str}` puts `{fn_name}` in module "
                    f"`{leaf}`, but it is defined in {rel}, whose stem is not "
                    f"`{leaf}` and which declares no `mod {leaf}`"
                )
                continue

        if not has_boundary(lines, idx):
            problems.append(
                f"{codec}: witness `{path_str}` ({rel}:{idx + 1}) does NOT carry "
                f"`{BOUNDARY}`. Its presence in the baseline binary is then an "
                "optimizer decision, which an unrelated edit flips -- that is the "
                "R2450 red, and R311y878/R311y802 are the two precedents. Add the "
                "attribute with its reason; do not drop the witness."
            )
            continue

        resolved.append(f"{codec} -> {rel}:{idx + 1} {BOUNDARY}")

    return (problems, resolved)


def selftest() -> int:
    failures: "list[str]" = []

    def build(tmp: pathlib.Path, entries: str, files: "dict[str, str]") -> pathlib.Path:
        root = tmp
        script = root / SCRIPT_REL
        script.parent.mkdir(parents=True, exist_ok=True)
        script.write_text(f"declare -A {MAP_NAME}=(\n{entries})\n")
        for rel, body in files.items():
            target = root / rel
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(body)
        return root

    good = "/// doc\n#[cfg(feature = \"f\")]\n#[inline(never)]\npub fn w() -> u8 { 1 }\n"

    cases = [
        # A witness with the boundary resolves.
        ("boundary present", '  [c]="wz_x::m::w"\n', {"crates/wz-x/src/m.rs": good}, True),
        # The R2450 defect itself: pinned, reachable, no boundary.
        (
            "boundary absent",
            '  [c]="wz_x::m::w"\n',
            {"crates/wz-x/src/m.rs": "pub fn w() -> u8 { 1 }\n"},
            False,
        ),
        # A renamed function -- the cause the runtime gate can only guess at.
        (
            "renamed away",
            '  [c]="wz_x::m::w"\n',
            {"crates/wz-x/src/m.rs": "#[inline(never)]\npub fn other() -> u8 { 1 }\n"},
            False,
        ),
        # Right name, wrong module.
        ("wrong module", '  [c]="wz_x::gone::w"\n', {"crates/wz-x/src/m.rs": good}, False),
        # Ambiguous: nm reports one name, so two definitions cannot be graded.
        (
            "ambiguous name",
            '  [c]="wz_x::m::w"\n',
            {"crates/wz-x/src/m.rs": good, "crates/wz-x/src/n.rs": good},
            False,
        ),
        # An absent crate is a FAIL, not a skip.
        ("crate absent", '  [c]="wz_nope::m::w"\n', {"crates/wz-x/src/m.rs": good}, False),
        # ANTI-VACUITY: a map with no entries must not report green.
        ("empty map", "", {"crates/wz-x/src/m.rs": good}, False),
        # Comment lines inside the block are skipped, not parsed as entries.
        (
            "comments skipped",
            '  # [c]="wz_x::m::nope"\n  [c]="wz_x::m::w"\n',
            {"crates/wz-x/src/m.rs": good},
            True,
        ),
        # A multi-line attribute above the boundary must not break the walk.
        (
            "multi-line attribute",
            '  [c]="wz_x::m::w"\n',
            {
                "crates/wz-x/src/m.rs": "#[inline(never)]\n#[cfg(all(\n  feature = \"f\",\n))]\npub fn w() -> u8 { 1 }\n"
            },
            True,
        ),
        # A boundary on the PREVIOUS item must not be read as this one's.
        (
            "previous item's attribute",
            '  [c]="wz_x::m::w"\n',
            {
                "crates/wz-x/src/m.rs": "#[inline(never)]\npub fn earlier() -> u8 { 0 }\npub fn w() -> u8 { 1 }\n"
            },
            False,
        ),
        # An inline `mod` in another file's body still resolves the module half.
        (
            "inline module",
            '  [c]="wz_x::m::w"\n',
            {"crates/wz-x/src/lib.rs": "pub mod m {\n" + good + "}\n"},
            True,
        ),
    ]

    for name, entries, files, want_ok in cases:
        with tempfile.TemporaryDirectory() as tmp:
            root = build(pathlib.Path(tmp), entries, files)
            problems, resolved = findings(root)
            got_ok = not problems
            if got_ok != want_ok:
                failures.append(
                    f"{name}: ok={got_ok}, want ok={want_ok} "
                    f"(problems={problems}, resolved={resolved})"
                )
            if want_ok and not resolved:
                failures.append(f"{name}: passed while resolving nothing")

    if failures:
        for line in failures:
            print(f"  witness-boundary-gate SELFTEST FAIL: {line}", file=sys.stderr)
        return 1
    print(f"  witness-boundary-gate: selftest {len(cases)} case(s) OK")
    return 0


def main() -> int:
    if "--selftest" in sys.argv:
        return selftest()
    root = pathlib.Path(__file__).resolve().parents[2]
    problems, resolved = findings(root)
    if problems:
        print("  witness-boundary-gate FAIL:", file=sys.stderr)
        for line in problems:
            print(f"    - {line}", file=sys.stderr)
        return 1
    print(f"  witness-boundary-gate: {len(resolved)} witness(es) hold a boundary")
    for line in resolved:
        print(f"    {line}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
