#!/usr/bin/env python3
# SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
# SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
"""R311y843 (no register item) wrote Layer C0f for one lane; this is that check for every lane,
which is item 212 in the UNREGISTERED set (no store `debt-` id): "C0f knows only
`layer_z_zenohd_interop`, and nobody swept the other lanes for an opening/restore pair".

THE CLASS. cargo uplifts every feature variant of one artifact to ONE path (R311y269), so a lane
that builds a package twice with two feature statements leaves whichever came last at that path,
and every leg after it runs that one. Layer Z opens with a large feature set, rebuilds for two
one-leg variants, and then RESTATES the opening list to restore it. The two lists are one fact
written twice; R311y842 added `zenoh-config` to the opening line only, and every leg past the
restore ran a demo without it. The duplication cannot be removed (`feature_closure.py`'s A4-5
scraper reads the literal line, so a shell variable there would drop the whole set from the
closure); what can be removed is the silence.

THE POPULATION, derived. Every function of `scripts/run-ci.sh`, every `cargo build` in it (a
continued line is one line, and one line may hold several builds), grouped by package and by
what selects the artifact (`--target`, `--bin`, `--example`, `--release`, `--target-dir`, ...).
A build that makes a feature statement (`--features`, `--no-default-features`) is one of the
group's builds; a build that makes none is the crate's own default, restates nothing and cannot
drift. A group whose builds make at least two different statements is a member.

THE RULE. Every member is declared, here, as one of three shapes, and the declaration is held
both ways (a member with none fails, and so does a declaration that names no member):

  `restores` -- the lane rebuilds an earlier statement after one-leg variants; its FIRST and LAST
               statements must be one set (Layer Z's invariant, now for any lane that declares it).
  `staged`   -- each build is followed only by the legs that need it, up to the next build, and
               no leg after a later build needs an earlier one back: nothing is restated.
  `compiles` -- the builds prove that each statement compiles; no leg of the lane runs that
               artifact after them.

A new lane that grows a second statement for one artifact is a member with no declaration, so it
fails until its author says which of the three it is, which is the question the restore line's
author never had to answer.

WHAT THIS DOES NOT REACH, stated: a lane that runs an artifact it did not build (it inherits
whichever lane ran last), and whether a `staged` lane's legs really need only the build in front
of them, which is the declaration's claim and is read by a person, not here.

Usage:
    lane_build_restore_gate.py --check [scripts/run-ci.sh]
    lane_build_restore_gate.py --selftest
Exit: 0 every member declared and every restore restores; 1 otherwise; 2 the script is unreadable.
"""

from __future__ import annotations

import re
import sys
from collections import defaultdict
from pathlib import Path

RUN_CI = Path(__file__).resolve().parents[1] / "run-ci.sh"
FUNCTION = re.compile(r"^([A-Za-z_][A-Za-z0-9_]*)\(\) \{")
BUILD = re.compile(r"(?=\bcargo build\b)")
# Where one command of a shell line ends.
COMMAND_END = re.compile(r"&&|\|\||\)|;|\||`")
# The flags that pick which artifact a build writes, so two builds that differ in them do not
# share a path. A flag that takes a value is listed with `=`.
SELECTOR_VALUE = ("--target=", "--bin=", "--example=", "--target-dir=", "--profile=", "--test=")
SELECTOR_FLAG = ("--bins", "--lib", "--examples", "--tests", "--release", "--all-targets")
SHAPES = ("restores", "staged", "compiles")

# `(function, package) -> (shape, why)`. One row per member; the shapes are the module docstring's.
DECLARED: dict[tuple[str, str], tuple[str, str]] = {
    ("layer_z_zenohd_interop", "wz-ap-demo"): (
        "restores",
        "the session-extqos and session-extshm legs rebuild the demo, then the opening set returns",
    ),
    ("layer_c1ay_cargo_test_router_hat", "wz-ap-demo"): (
        "compiles",
        "three one-feature demo builds close the lane; nothing runs after them",
    ),
    ("layer_c1bp_plugin_dynamic_loading", "wz-ap-demo"): (
        "staged",
        "the pico legs run on preset-ap-full, then the config-write leg on its zenoh-config build",
    ),
    ("layer_c1k_cargo_test_scouting_static", "wz-runtime-coop"): (
        "compiles",
        "library builds of the static scouting plane, with and without alloc",
    ),
    ("layer_c1z_cargo_test_storage_driver", "wz"): (
        "compiles",
        "one facade build per storage feature closes the lane",
    ),
    ("layer_e3_router_multi_peer", "wz-ap-demo"): (
        "staged",
        "the multi-peer legs, then the routing-routes build and every leg after it",
    ),
    ("layer_e6f_adminspace_metrics", "wz-ap-demo"): (
        "staged",
        "metrics, transport-stats and resource-snapshot builds, each with the legs after it",
    ),
    ("layer_e6g_adminspace_read", "wz-ap-demo"): (
        "staged",
        "the read-deny leg, then the config-file leg on the zenoh-config build",
    ),
    ("layer_e6h_adminspace_config_hotreload", "wz-ap-demo"): (
        "staged",
        "the hot-reload leg, then every config-file leg on the zenoh-config build",
    ),
    ("layer_e7b_router_connect_reconcile", "wz-ap-demo"): (
        "staged",
        "the reconcile legs, then the feature-off negative on its own build",
    ),
    ("layer_e8t_router_hat_hlc_stamp_pico", "wz-ap-demo"): (
        "staged",
        "the time-hlc legs, the config-file legs, then the negative twin without time-hlc",
    ),
    ("layer_g_cross_compile_cortex_m", "wz"): (
        "compiles",
        "cross builds for bare-metal targets; the host runs none of them",
    ),
    ("layer_g_cross_compile_cortex_m", "wz-runtime-coop"): (
        "compiles",
        "cross builds for bare-metal targets; the host runs none of them",
    ),
    ("layer_g_cross_compile_cortex_m", "wz-session-core"): (
        "compiles",
        "cross builds for bare-metal targets; the host runs none of them",
    ),
    ("layer_m_scouting_multicast", "wz-ap-demo"): (
        "staged",
        "each demo build precedes the legs that spawn it; the legs between spawn no demo",
    ),
}

# `(no-default-features, features)`: what one build states.
Statement = tuple[bool, frozenset[str]]


def logical_lines(text: str) -> list[tuple[int, str]]:
    """`[(first physical line, text)]` with backslash continuations joined."""
    out: list[tuple[int, str]] = []
    pending = ""
    start = 0
    for number, line in enumerate(text.split("\n"), 1):
        if not pending:
            start = number
        if line.endswith("\\"):
            pending += line[:-1] + " "
            continue
        out.append((start, pending + line))
        pending = ""
    if pending:
        out.append((start, pending))
    return out


def option_value(tokens: list[str], index: int) -> tuple[str, str] | None:
    """`(--flag, value)` for a `--flag value` or `--flag=value` token at `index`."""
    token = tokens[index]
    for flag in (*SELECTOR_VALUE, "--features="):
        name = flag[:-1]
        if token.startswith(flag):
            return name, token[len(flag) :]
        if token == name and index + 1 < len(tokens):
            return name, tokens[index + 1]
    return None


def parse_build(command: str) -> tuple[list[str], str, Statement | None]:
    """`(packages, selector, statement)` of one `cargo build ...` command; the statement is None
    when the build makes no feature statement."""
    tokens = command.split()
    packages = [tokens[i + 1] for i, t in enumerate(tokens[:-1]) if t == "-p"]
    packages += [t[len("--package=") :] for t in tokens if t.startswith("--package=")]
    features: str | None = None
    no_default = "--no-default-features" in tokens
    selector: list[str] = []
    for index, token in enumerate(tokens):
        if token in SELECTOR_FLAG:
            selector.append(token)
            continue
        found = option_value(tokens, index)
        if found is None:
            continue
        name, value = found
        if name == "--features":
            features = value
        else:
            selector.append(f"{name}={value}")
    if features is None and not no_default:
        return packages, " ".join(sorted(selector)), None
    names = frozenset(f for f in (features or "").strip("\"'").split(",") if f)
    return packages, " ".join(sorted(selector)), (no_default, names)


def builds(text: str) -> dict[tuple[str, str, str], list[tuple[int, Statement]]]:
    """`(function, package, selector) -> [(line, statement)]` for every stating build."""
    found: dict[tuple[str, str, str], list[tuple[int, Statement]]] = defaultdict(list)
    function: str | None = None
    for number, line in logical_lines(text):
        opened = FUNCTION.match(line)
        if opened:
            function = opened.group(1)
            continue
        if line.startswith("}"):
            function = None
            continue
        if function is None or line.lstrip().startswith("#"):
            continue
        for piece in BUILD.split(line)[1:]:
            command = COMMAND_END.split(piece, 1)[0]
            packages, selector, statement = parse_build(command)
            if statement is None:
                continue
            for package in packages:
                found[(function, package, selector)].append((number, statement))
    return found


def members(found: dict) -> dict[tuple[str, str, str], list[tuple[int, Statement]]]:
    """The groups whose builds make at least two different statements."""
    return {key: seq for key, seq in found.items() if len({s for _, s in seq}) >= 2}


def spell(statement: Statement) -> str:
    no_default, names = statement
    return ("--no-default-features " if no_default else "") + (",".join(sorted(names)) or "(none)")


def judge(
    groups: dict[tuple[str, str, str], list[tuple[int, Statement]]],
    declared: dict[tuple[str, str], tuple[str, str]],
) -> list[str]:
    problems: list[str] = []
    for (function, package), (shape, _) in sorted(declared.items()):
        if shape not in SHAPES:
            problems.append(f"{function} / {package} is declared `{shape}`, not one of {SHAPES}")
    seen = set()
    for (function, package, selector), seq in sorted(groups.items()):
        seen.add((function, package))
        where = f"{function} / {package}" + (f" [{selector}]" if selector else "")
        row = declared.get((function, package))
        if row is None:
            lines = ", ".join(str(n) for n, _ in seq)
            problems.append(
                f"{where} builds {len(seq)} times with {len({s for _, s in seq})} different "
                f"feature statements (lines {lines}) and declares no shape: say whether it "
                f"restores, is staged or only compiles, in {Path(__file__).name}"
            )
            continue
        if row[0] == "restores":
            (first_line, first), (last_line, last) = seq[0], seq[-1]
            if first != last:
                problems.append(
                    f"{where} opens with one feature statement and restores a DIFFERENT one, so "
                    f"every leg past the restore runs a build the lane did not mean\n"
                    f"      opened   (line {first_line}): {spell(first)}\n"
                    f"      restored (line {last_line}): {spell(last)}\n"
                    f"      fix: make the restore line's statement identical to the opening line's"
                )
    for key in sorted(set(declared) - seen):
        problems.append(
            f"{key[0]} / {key[1]} is declared but builds no two different statements any more: "
            "drop the row"
        )
    return problems


def check(path: Path) -> int:
    try:
        text = path.read_text(encoding="utf-8")
    except OSError as error:
        print(f"  Layer C0f FAIL: cannot read {path}: {error}", file=sys.stderr)
        return 2
    found = builds(text)
    groups = members(found)
    # POPULATION, not exit status: a reader that matched nothing would hold every rule.
    if not groups or not found:
        print(
            f"  Layer C0f FAIL: read {len(found)} stating build group(s) and {len(groups)} "
            "member(s) in the lanes, so either the lanes were restructured or this reader "
            "stopped matching them",
            file=sys.stderr,
        )
        return 1
    problems = judge(groups, DECLARED)
    for problem in problems:
        print(f"  Layer C0f FAIL: {problem}", file=sys.stderr)
    if problems:
        return 1
    shapes = defaultdict(int)
    for function, package, _ in groups:
        shapes[DECLARED[(function, package)][0]] += 1
    print(
        f"  C0f: {len(groups)} lane build group(s) restate a feature statement; "
        + ", ".join(f"{shapes[s]} {s}" for s in SHAPES)
        + "; every restore restores its opening statement"
    )
    return 0


def selftest() -> int:
    script = "\n".join(
        [
            "layer_x() {",
            "    (cd crates && cargo build -p demo --features a,b --quiet) || return 1",
            "    # cargo build -p demo --features nope",
            "    (cd crates && cargo build -p demo --features q --quiet) || return 1",
            "    (cd crates \\",
            "        && cargo build -p demo --features b,a --quiet \\",
            "        && cargo build -p probe --quiet) || return 1",
            "}",
            "layer_y() {",
            "    (cd crates && cargo build -p demo --no-default-features \\",
            "        --features a --quiet) || return 1",
            "    (cd crates && cargo build -p demo --quiet) || return 1",
            "    (cd crates && cargo build -p demo --features a --quiet) || return 1",
            "    cargo build -p lib --target thumbv7em --features a",
            "    cargo build -p lib --target=thumbv6m --features b",
            "}",
        ]
    )
    found = builds(script)
    # A comment is not a build, a continued line is one line, and the order is kept.
    assert [s for _, s in found[("layer_x", "demo", "")]] == [
        (False, frozenset({"a", "b"})),
        (False, frozenset({"q"})),
        (False, frozenset({"a", "b"})),
    ], found
    # A build with no statement is the default and not a member's build; probe states nothing.
    assert ("layer_x", "probe", "") not in found
    assert [s for _, s in found[("layer_y", "demo", "")]] == [
        (True, frozenset({"a"})),
        (False, frozenset({"a"})),
    ], found
    # Two targets are two paths: one statement each, so neither is a member.
    groups = members(found)
    assert set(groups) == {("layer_x", "demo", ""), ("layer_y", "demo", "")}, groups

    restores = {("layer_x", "demo"): ("restores", "t"), ("layer_y", "demo"): ("staged", "t")}
    assert judge(groups, restores) == []
    # The R311y842 shape: the opening line gains a feature the restore line does not.
    drifted = members(builds(script.replace("--features a,b --quiet", "--features a,b,c --quiet")))
    problems = judge(drifted, restores)
    assert len(problems) == 1 and "restores a DIFFERENT one" in problems[0], problems
    # `--no-default-features` is part of what a build states.
    nodef = judge(groups, {("layer_x", "demo"): ("staged", "t"), ("layer_y", "demo"): ("restores", "t")})
    assert len(nodef) == 1 and "layer_y" in nodef[0], nodef
    # Both directions: an undeclared member, a declaration that names none, an unknown shape.
    missing = judge(groups, {("layer_x", "demo"): ("restores", "t")})
    assert len(missing) == 1 and "declares no shape" in missing[0], missing
    stale = dict(restores)
    stale[("layer_gone", "demo")] = ("staged", "t")
    assert len(judge(groups, stale)) == 1
    odd = dict(restores)
    odd[("layer_y", "demo")] = ("swapped", "t")
    assert any("not one of" in p for p in judge(groups, odd))

    # The selector is read in both spellings.
    assert parse_build("cargo build -p lib --target=thumbv6m --release --features=b")[1:] == (
        "--release --target=thumbv6m",
        (False, frozenset({"b"})),
    )
    # Every declared shape is a known one.
    assert all(shape in SHAPES for shape, _ in DECLARED.values())
    print("lane-build-restore selftest: OK")
    return 0


def main(argv: list[str]) -> int:
    if argv == ["--selftest"]:
        return selftest()
    if argv[:1] == ["--check"] and len(argv) <= 2:
        return check(Path(argv[1]) if len(argv) == 2 else RUN_CI)
    print(__doc__, file=sys.stderr)
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
