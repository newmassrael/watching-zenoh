#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
# SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
r"""R2333 (no register item) — a SHIPPED multicast drive loop that runs for the
node's life must be one a host can ask to stop.

The citation is `no register item` in the sense `debt_plane_census.py` uses: the
item this answers for -- unregistered open-debt item 15, the PARTIAL atom track,
and inside it the `transport-multicast` atom's residual -- lives in an
agent-memory register outside this repository, which has no store id for
`gate_provenance_lint.py` to resolve. The item is named in prose here.

## The defect this closes

`transport-multicast`'s recorded residual read, verbatim: "NO PRODUCTION CALLER
DRIVES IT. `spawn_router_mcast_egress` still runs the no-signal entry point with
`max_iters: None`". The library had grown the graceful stop at R311y772 and its
WIRE half -- the departing `Close` multicast to the group -- at R311y782, and
both were tested. What no test could see is that nothing shipped ever asked. A
wz router therefore left its group SILENTLY, and every member held a stale peer
entry for it until the lease expired.

R2333 wired both router group faces to a stop handle. This gate is the part that
keeps them wired, and it exists because the defect is INVISIBLE to the test
suite by construction: a drive loop with no stop is not a failing test, it is a
missing caller, and `cargo test` cannot fail on an absence.

## The population is DERIVED, and the derivation is the point

The residual named ONE function. That is who noticed, not the population.

* The ENTRY POINTS are read out of the tree: every `pub [async] fn` whose name
  starts `drive_multicast_session` or is `run_multicast_session`. Adding a
  fourth entry point does not need this file edited.
* Whether an entry point can be stopped is read from its OWN SIGNATURE -- does
  it take a `watch::Receiver<bool>` -- not from a list of names here.
* The CALL SITES are every call of one of those in SHIPPED source: tracked
  `*.rs` outside `tests/`, `benches/`, `examples/`, `vendor/` and `out/`, with
  each file's `#[cfg(test)] mod tests` block cut out first. A test may drive an
  unbounded loop and drop it; a shipped host cannot.
* The SUBSET that must be stoppable is derived from the call's own argument
  text: `max_iters: None` means "the loop runs for the node's life", which is
  the property that makes an un-stoppable loop a defect. A bounded call
  (`max_iters: Some(..)`) ends on its own and is not in scope -- that is why
  the MCU e2e host, which is bounded, is not reported here and why its loop's
  missing stop signal stays the separately-recorded open half.

An EMPTY population FAILS. A gate whose subject has silently moved would
otherwise report green forever, which is the failure mode this tree has paid
for repeatedly.

## What is checked

For every unbounded shipped call:

1. the entry point it calls must be shutdown-capable by its own signature; and
2. when that entry point takes the signal as an `Option`, the call must pass
   something other than `None` -- capability is not wiring, and
   `drive_multicast_session_with_membership(.., None)` is exactly the shape the
   router ingress face had.
"""

from __future__ import annotations

import argparse
import re
import subprocess
import sys
from pathlib import Path

# A drive-loop entry point declaration. The two families are named by PREFIX
# rather than enumerated, so a new `drive_multicast_session_*` is in the
# population the moment it is written.
ENTRY_DECL = re.compile(
    r"^\s*pub\s+(?:async\s+)?fn\s+(drive_multicast_session\w*|run_multicast_session)\b",
    re.MULTILINE,
)

# The shutdown parameter, recognised by TYPE. `watch::Receiver<bool>` is the
# signal's type wherever it is spelled, so a re-import or a path change does not
# blind this.
SHUTDOWN_PARAM = re.compile(r"watch::Receiver\s*<\s*bool\s*>")

# `max_iters: None` inside the call's own `MulticastDriveConfig` literal. The
# whitespace is loose because rustfmt puts the field on its own line.
UNBOUNDED = re.compile(r"\bmax_iters\s*:\s*None\b")

SKIP_DIR_PARTS = ("tests", "benches", "examples", "vendor", "out")


def tracked_rust(repo: Path) -> list[Path]:
    out = subprocess.run(
        ["git", "-C", str(repo), "ls-files", "*.rs"],
        check=True,
        capture_output=True,
        text=True,
    ).stdout.split()
    return [repo / rel for rel in out]


def shipped(repo: Path) -> list[Path]:
    """Tracked Rust that a deploy actually ships."""
    keep = []
    for path in tracked_rust(repo):
        parts = path.relative_to(repo).parts
        if any(part in SKIP_DIR_PARTS for part in parts):
            continue
        keep.append(path)
    return keep


def strip_test_module(src: str) -> str:
    """Blank out every `#[cfg(test)] mod tests { .. }` block, keeping offsets.

    Replacing with spaces rather than deleting keeps `line_of` honest: a
    reported line number must be the line the reader will open.
    """
    out = list(src)
    for m in re.finditer(r"#\[cfg\(test\)\]\s*(?:pub\s+)?mod\s+\w+\s*\{", src):
        depth = 0
        i = m.end() - 1
        while i < len(src):
            if src[i] == "{":
                depth += 1
            elif src[i] == "}":
                depth -= 1
                if depth == 0:
                    break
            i += 1
        for j in range(m.start(), min(i + 1, len(src))):
            if out[j] != "\n":
                out[j] = " "
    return "".join(out)


def call_args(src: str, open_paren: int) -> str | None:
    """The text between a call's parentheses, by balanced scan."""
    depth = 0
    i = open_paren
    while i < len(src):
        if src[i] == "(":
            depth += 1
        elif src[i] == ")":
            depth -= 1
            if depth == 0:
                return src[open_paren + 1 : i]
        i += 1
    return None


def last_argument(args: str) -> str:
    """The final top-level argument of a call's argument text."""
    depth = 0
    start = 0
    pieces = []
    for i, ch in enumerate(args):
        if ch in "([{<":
            depth += 1
        elif ch in ")]}>":
            depth -= 1
        elif ch == "," and depth == 0:
            pieces.append(args[start:i])
            start = i + 1
    pieces.append(args[start:])
    for piece in reversed(pieces):
        # Skip the trailing-comma empty tail and any comment-only remainder.
        stripped = re.sub(r"//[^\n]*", "", piece).strip()
        if stripped:
            return stripped
    return ""


def line_of(src: str, offset: int) -> int:
    return src.count("\n", 0, offset) + 1


# The block openers that REPEAT. `loop` is what a group face uses; `while` and
# `for` are accepted because the property under test is "this drive call can run
# more than once", and refusing a correct `while !stopped` shape would push a
# future author to satisfy the gate rather than the requirement.
REPEATING_BLOCK = re.compile(r"\b(loop|while|for)\s*$")


def inside_repeating_block(src: str, offset: int) -> bool:
    """Is `offset` lexically inside a `loop` / `while` / `for` body?

    Walks OUTWARD from the call: scanning backwards, every `}` passed is a block
    that closed before us (skip to its `{`), and every `{` reached at depth zero
    is a block that ENCLOSES us. If any enclosing opener repeats, the call can
    run more than once.

    There is no need to stop at the function body: the depth accounting already
    prevents escaping into a SIBLING function, because that function's closing
    `}` is passed on the way out and its own `{` is consumed matching it. So the
    walk simply runs out of enclosing blocks and answers no.

    Text-level, like the rest of this gate: a `loop` inside a string literal
    would fool it. That is the same exposure the existing checks carry and the
    same reason it is acceptable -- this reads wz's own rustfmt'd source, not
    hostile input, and the failure direction is a false PASS on source no one
    writes by accident.
    """
    depth = 0
    i = offset - 1
    while i >= 0:
        ch = src[i]
        if ch == "}":
            depth += 1
        elif ch == "{":
            if depth == 0:
                if REPEATING_BLOCK.search(src[:i].rstrip()):
                    return True
            else:
                depth -= 1
        i -= 1
    return False


def entry_points(files: list[Path]) -> dict[str, bool]:
    """name -> is it shutdown-capable, read from each declaration's signature."""
    found: dict[str, bool] = {}
    for path in files:
        src = path.read_text(encoding="utf-8")
        for m in ENTRY_DECL.finditer(src):
            name = m.group(1)
            # The signature runs from the declaration to the opening brace of
            # the body; the return type and where-clause ride along harmlessly.
            body = src.find("{", m.end())
            sig = src[m.start() : body if body != -1 else len(src)]
            found[name] = bool(SHUTDOWN_PARAM.search(sig))
    return found


def audit(repo: Path) -> tuple[list[str], list[str], dict[str, bool]]:
    files = shipped(repo)
    points = entry_points(files)
    if not points:
        return (
            [],
            ["no multicast drive entry point found at all -- the gate's subject moved"],
            points,
        )

    call = re.compile(r"\b(" + "|".join(sorted(points, key=len, reverse=True)) + r")\s*\(")
    population: list[str] = []
    violations: list[str] = []
    for path in sorted(files):
        raw = path.read_text(encoding="utf-8")
        if not any(name in raw for name in points):
            continue
        src = strip_test_module(raw)
        rel = path.relative_to(repo)
        for m in call.finditer(src):
            name = m.group(1)
            # A declaration is not a call.
            if re.search(r"\bfn\s+$", src[: m.start(1)]):
                continue
            args = call_args(src, m.end() - 1)
            if args is None or not UNBOUNDED.search(args):
                continue
            where = f"{rel}:{line_of(src, m.start())} ({name})"
            population.append(where)
            if not points[name]:
                violations.append(
                    f"{where} drives an UNBOUNDED loop through an entry point that "
                    f"takes no shutdown signal -- the host cannot stop this face"
                )
                continue
            if last_argument(args) == "None":
                violations.append(
                    f"{where} is shutdown-CAPABLE but passes `None` -- capability "
                    f"is not wiring; hand it a signal"
                )
                continue
            # R2376 (open-debt item 15, `session-reconnect`) — REJOIN wiring, on
            # the same derived population and for the same reason the stop check
            # exists: a shipped face that runs its drive loop ONCE cannot come
            # back from a `LinkLost`, and `cargo test` cannot fail on a missing
            # `loop` any more than it could on a missing stop signal. Both group
            # faces had exactly this shape -- bind once, drive once, return the
            # outcome to a host that had already spawned and forgotten them --
            # so an interface that dropped and returned took the face out for the
            # life of the process.
            if not inside_repeating_block(src, m.start()):
                violations.append(
                    f"{where} runs its unbounded drive ONCE -- the call is not "
                    f"inside a loop, so a `LinkLost` ends this face permanently "
                    f"and nothing re-joins the group (pico re-arms the same "
                    f"reopen task from multicast lease failure)"
                )
    return population, violations, points


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--repo", default=".", help="repository root")
    ap.add_argument(
        "--list",
        action="store_true",
        help="print the derived population and each entry point's capability",
    )
    args = ap.parse_args()
    repo = Path(args.repo).resolve()

    population, violations, points = audit(repo)

    if args.list:
        for name in sorted(points):
            print(f"  entry point {name}: shutdown-capable={points[name]}")
        for row in population:
            print(f"  unbounded shipped drive: {row}")

    if not population:
        print(
            "multicast-stop-wiring: FAIL -- the derived population is EMPTY. "
            "No shipped source drives a multicast loop with `max_iters: None`, "
            "so this gate is measuring nothing. Either the hosts moved (re-aim "
            "the derivation) or they are gone (retire the gate); a population "
            "of zero must never read as a pass.",
            file=sys.stderr,
        )
        return 1

    if violations:
        for v in violations:
            print(f"multicast-stop-wiring: {v}", file=sys.stderr)
        # R2376 — "cannot be stopped by their host" was accurate while that was
        # the only check; it is not now, and a summary that mis-describes its own
        # violations is how a reader learns to distrust the line rather than the
        # code. The per-violation lines above say which property failed.
        print(
            f"multicast-stop-wiring: FAIL -- {len(violations)} of "
            f"{len(population)} unbounded shipped multicast drive loop(s) are "
            f"not correctly wired to their host's lifecycle.",
            file=sys.stderr,
        )
        return 1

    print(
        f"multicast-stop-wiring: OK -- {len(population)} unbounded shipped "
        f"multicast drive loop(s), all stoppable by their host and all able to "
        f"re-join a lost group ({len(points)} entry point(s) read)."
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
