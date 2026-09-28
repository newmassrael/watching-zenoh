#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
# SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
"""The workspace members that force `sce-rust-runtime/no_std`, derived.

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
# `cargo tree --prefix depth`: the depth, then the node text.
LINE = re.compile(r"^(\d+)(.*)$")


def enables_no_std(tree: str) -> bool:
    """Whether one member's inverted tree has the no_std feature node."""
    for raw in tree.splitlines():
        m = LINE.match(raw)
        if m and m.group(2).strip() == FEATURE_NODE:
            return True
    return False


def workspace_members() -> list:
    out = subprocess.run(
        ["cargo", "metadata", "--no-deps", "--format-version", "1"],
        cwd=CRATES,
        check=True,
        capture_output=True,
        text=True,
    ).stdout
    return sorted(pkg["name"] for pkg in json.loads(out)["packages"])


def member_tree(member: str) -> str:
    """`member`'s own build, inverted at the runtime; empty when it does not
    depend on the runtime at all (cargo then prints a warning and nothing)."""
    done = subprocess.run(
        [
            "cargo", "tree", "-p", member, "-e", "features", "-i", TARGET,
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
    cases = [
        (forcing, True, "a member whose build switches the runtime's no_std on"),
        (std_only, False, "a member whose build is std"),
        (other_no_std, False, "another crate's no_std feature"),
        ("", False, "a member that does not depend on the runtime"),
    ]
    for tree, want, what in cases:
        if enables_no_std(tree) != want:
            print(f"selftest FAIL: {what}: answered {not want}", file=sys.stderr)
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
        found = [m for m in members if enables_no_std(member_tree(m))]
    except (subprocess.CalledProcessError, FileNotFoundError, KeyError, ValueError) as e:
        print(f"nostd-workspace-members: cargo could not answer: {e}", file=sys.stderr)
        return 2
    for name in found:
        print(name)
    print(
        f"nostd-workspace-members: {len(found)} member(s) force {TARGET}/no_std: "
        + (" ".join(found) or "none"),
        file=sys.stderr,
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
