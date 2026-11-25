#!/usr/bin/env python3
# SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
# SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
"""R2940 (no register item) — the workspace members that force
`sce-rust-runtime/no_std`, or the cooperative C library's lent-only receive,
derived.

`sce-rust-runtime`'s `no_std` and `http-send` are mutually exclusive (a
`compile_error!` in the runtime), and `wz-runtime-tokio` pulls `http-send`.
So any workspace member whose own dependency declarations switch `no_std` on
cannot share a feature-unified graph with the rest: `cargo test --workspace`
(Layer C1) and `cargo clippy --workspace` (Layer C2) must exclude it, and it is
built and tested on its own lane instead.

Those two lanes used to carry the excluded set as a hand-written list, twice.
R2916 gave `wz-runtime-zephyr` a `wz-session-core` dependency with `no_std` on,
nobody added it to either list, and C1 stopped compiling at all (hosted run
36338677128, and at HEAD). This derives the set from the resolved feature graph
instead: a member is in it when its OWN build -- `cargo tree -p <member>`, its
default features and its dev-dependencies, which is what the workspace lanes
unify -- enables `sce-rust-runtime feature "no_std"`.

The cooperative engine's C library is the second kind (docs/c-abi-engine-and-
memory.md, P1): `wz-capi-pico`'s default build names `engine-coop`, which
switches `wz-session-core/rx-lent-only` on, and `wz-runtime-tokio` refuses to
be built in a graph that has it (a const assertion in its `lib.rs`). A member
whose own build enables `wz-session-core feature "rx-lent-only"` is excluded by
the same per-member rule, and tested on its own lane (Layer C1pc).

The first cut read the whole workspace's inverted tree and took every member
under the no_std node. That answered 18 where the lanes need 4: a member that
merely DEPENDS on a no_std-forcing crate appears under the node in the unified
graph without forcing anything in its own build (`wz`, `wz-ap-demo`,
`wz-integration-tests` build in C1 today). The predicate is per member.

Usage:
    nostd_workspace_members.py            print the members, one per line
    nostd_workspace_members.py --selftest check the parser on fixed trees

Exit 0 with the set printed (it may be empty), 2 when cargo cannot answer.
The count goes to stderr, so a lane shows what it excluded.
"""

import json
import re
import subprocess
import sys
from pathlib import Path

CRATES = Path(__file__).resolve().parents[2] / "crates"
TARGET = "sce-rust-runtime"
FEATURE_NODE = f'{TARGET} feature "no_std"'
# The second exclusive feature: the cooperative C library's lent-only receive, which the tokio
# engine's runtime refuses to share a graph with.
LENT_TARGET = "wz-session-core"
LENT_NODE = f'{LENT_TARGET} feature "rx-lent-only"'
# Each (package the tree is inverted at, the feature node that excludes a member).
EXCLUSIVE = ((TARGET, FEATURE_NODE), (LENT_TARGET, LENT_NODE))
# `cargo tree --prefix depth`: the depth, then the node text.
LINE = re.compile(r"^(\d+)(.*)$")


def enables_node(tree: str, node: str) -> bool:
    """Whether one member's inverted tree has the feature node `node`."""
    for raw in tree.splitlines():
        m = LINE.match(raw)
        if m and m.group(2).strip() == node:
            return True
    return False

def excluded(member: str) -> bool:
    """Whether `member`'s own build switches on a feature the workspace graph cannot hold."""
    return any(enables_node(member_tree(member, target), node) for target, node in EXCLUSIVE)


def workspace_members() -> list:
    out = subprocess.run(
        ["cargo", "metadata", "--no-deps", "--format-version", "1"],
        cwd=CRATES,
        check=True,
        capture_output=True,
        text=True,
    ).stdout
    return sorted(pkg["name"] for pkg in json.loads(out)["packages"])


def member_tree(member: str, target: str = TARGET) -> str:
    """`member`'s own build, inverted at `target`; empty when it does not
    depend on it at all (cargo then prints a warning and nothing)."""
    done = subprocess.run(
        [
            "cargo", "tree", "-p", member, "-e", "features", "-i", target,
            "--prefix", "depth",
        ],
        cwd=CRATES,
        capture_output=True,
        text=True,
    )
    if done.returncode != 0:
        # `-i` names a package this member's graph does not contain.
        if "did not match any packages" in done.stderr:
            return ""
        raise subprocess.CalledProcessError(done.returncode, done.args, done.stdout, done.stderr)
    return done.stdout


def selftest() -> int:
    forcing = "\n".join([
        "0sce-rust-runtime v0.1.0 (/x/runtime)",
        '1sce-rust-runtime feature "default"',
        "2wz-session-core v0.1.0 (/x/wz-session-core)",
        '1sce-rust-runtime feature "no_std"',
        '2wz-session-core feature "no_std"',
        "3wz-runtime-zephyr v0.1.0 (/x/wz-runtime-zephyr)",
    ])
    std_only = "\n".join([
        "0sce-rust-runtime v0.1.0 (/x/runtime)",
        '1sce-rust-runtime feature "http-send"',
        "2wz-runtime-tokio v0.1.0 (/x/wz-runtime-tokio)",
    ])
    # A feature merely NAMED in a line (a dependent's "no_std" of another
    # crate) is not the runtime's own no_std node.
    other_no_std = "\n".join([
        "0sce-rust-runtime v0.1.0 (/x/runtime)",
        '1wz-session-core feature "no_std"',
    ])
    lent = "\n".join([
        "0wz-session-core v0.1.0 (/x/wz-session-core)",
        '1wz-session-core feature "rx-lent-only"',
        '2wz-capi-pico feature "engine-coop"',
        '3wz-capi-pico feature "default"',
        "4wz-capi-pico v0.1.0 (/x/wz-capi-pico)",
    ])
    owned = "\n".join([
        "0wz-session-core v0.1.0 (/x/wz-session-core)",
        '1wz-session-core feature "default"',
        "2wz-runtime-tokio v0.1.0 (/x/wz-runtime-tokio)",
    ])
    # The lent-only feature of another crate (`wz-capi-coop`'s `tx-lend-only` style) is not the
    # session core's receive selector.
    other_lent = "\n".join([
        "0wz-session-core v0.1.0 (/x/wz-session-core)",
        '1wz-capi-coop feature "rx-lent-only"',
    ])
    cases = [
        (forcing, FEATURE_NODE, True, "a member whose build switches the runtime's no_std on"),
        (std_only, FEATURE_NODE, False, "a member whose build is std"),
        (other_no_std, FEATURE_NODE, False, "another crate's no_std feature"),
        ("", FEATURE_NODE, False, "a member that does not depend on the runtime"),
        (lent, LENT_NODE, True, "a member whose default build names the cooperative engine"),
        (owned, LENT_NODE, False, "a member whose session core keeps the owned receive"),
        (other_lent, LENT_NODE, False, "another crate's feature of the same name"),
        ("", LENT_NODE, False, "a member that does not depend on the session core"),
        (lent, FEATURE_NODE, False, "the lent-only receive is not the runtime's no_std"),
    ]
    for tree, node, want, what in cases:
        if enables_node(tree, node) != want:
            print(f"selftest FAIL: {what}: answered {not want}", file=sys.stderr)
            return 1
    if [target for target, _ in EXCLUSIVE] != [TARGET, LENT_TARGET]:
        print("selftest FAIL: the excluded features are the runtime's no_std and the session "
              "core's lent-only receive", file=sys.stderr)
        return 1
    print(f"nostd-workspace-members: selftest OK ({len(cases)} cases)")
    return 0


def main() -> int:
    if sys.argv[1:] == ["--selftest"]:
        return selftest()
    if sys.argv[1:]:
        print(f"unknown argument {sys.argv[1]!r}; expected none or --selftest", file=sys.stderr)
        return 2
    try:
        members = workspace_members()
        found = [m for m in members if excluded(m)]
    except (subprocess.CalledProcessError, FileNotFoundError, KeyError, ValueError) as e:
        print(f"nostd-workspace-members: cargo could not answer: {e}", file=sys.stderr)
        return 2
    for name in found:
        print(name)
    print(
        f"nostd-workspace-members: {len(found)} member(s) force {TARGET}/no_std or "
        f"{LENT_TARGET}/rx-lent-only: "
        + (" ".join(found) or "none"),
        file=sys.stderr,
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
