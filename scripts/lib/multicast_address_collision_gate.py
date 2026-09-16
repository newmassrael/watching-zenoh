#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
# SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
"""R2672 (no register item) — NO TWO TESTS MAY JOIN THE SAME MULTICAST ADDRESS.

The citation is `no register item` for the reason `round_fed_gate_reach.py` and
`scouting_socket_axis_census.py` both give for theirs: the item this closes --
unregistered open-debt item 774 -- lives in the operator's agent-memory
register, which has no store `debt-` id for `gate_provenance_lint.py` to
resolve. Naming it in prose here and `no register item` in the citation is the
honest pair.

## The defect this exists to make impossible

A multicast group is not a process-local resource and not even a machine-local
one: a datagram sent to `224.0.0.224:7446` is delivered to EVERY socket on the
host that has joined that group on that port, whatever process it belongs to.
Cargo runs test functions concurrently inside a binary AND runs test binaries
concurrently with each other, so two tests that pick the same address are one
scheduler decision away from reading each other's traffic.

That is not hypothetical here. `scout_discovers_peer_locator_over_multicast`
bound the file's default `(224.0.0.224, 7446)` while a sibling test's CONTROL
arm deliberately sprayed a Hello carrying a DIFFERENT locator at that exact
address -- the sibling's whole claim being "a node that ignored its config and
stayed on the compiled-in default would hear this". The scout resolved the
sibling's locator and the assertion failed on a value that was never about the
code under test. It reproduced on two consecutive hosted runs and passed
locally, because the difference is scheduling, not correctness.

⚠ THE SIBLING CANNOT MOVE, and that is why this is a gate rather than a tidy-up.
Its control arm MUST target the compiled-in default: send it anywhere else and a
node that wrongly stayed on the default would also hear nothing, so the test
would pass vacuously. The address belongs to whoever is testing the default;
everyone else must be somewhere their neighbour will never spray.

## What it refuses, and what it cannot see

REFUSED: two distinct test functions -- in one file or across files -- that BIND
the same `(group, port)`. That is the whole predicate. It deliberately does not
try to prove a collision is REACHED at runtime, because reachability here is a
scheduling property and a gate that waits for a race is a gate that reports
green on a lucky day.

⚠ DEFERRED, and printed every run rather than silently dropped: a bind whose
group or port this reader cannot resolve to a literal (computed at runtime, or
passed in as a parameter). Those are named with their file and function so the
number is visible; they are NOT counted as safe.

The population is DERIVED -- every `crates/*/tests/*.rs` that calls
`bind_multicast` -- never a list in this file, because a list stops covering the
test somebody adds tomorrow, which is exactly how this defect arrived.
"""

import pathlib
import re
import sys

BIND = re.compile(r"bind_multicast\(\s*([A-Za-z_][\w:]*|Ipv4Addr::new\([^)]*\))\s*,\s*([A-Za-z_]\w*|\d+)\s*,")
FN = re.compile(r"^\s*(?:pub\s+)?(?:async\s+)?fn\s+(\w+)")
MOD = re.compile(r"^\s*(?:pub\s+)?mod\s+\w+\s*\{")
CONST_IP = re.compile(r"const\s+(\w+)\s*:\s*Ipv4Addr\s*=\s*Ipv4Addr::new\(\s*(\d+)\s*,\s*(\d+)\s*,\s*(\d+)\s*,\s*(\d+)\s*\)")
CONST_U16 = re.compile(r"const\s+(\w+)\s*:\s*u16\s*=\s*(\d+)")
IP_LITERAL = re.compile(r"Ipv4Addr::new\(\s*(\d+)\s*,\s*(\d+)\s*,\s*(\d+)\s*,\s*(\d+)\s*\)")


def test_files(root: pathlib.Path) -> list[pathlib.Path]:
    """Every integration-test source in the workspace. Derived, not listed."""
    return sorted(p for p in root.glob("crates/*/tests/*.rs") if p.is_file())


def resolve(
    name: str, lines: list[str], upto: int, fn_start: int, pattern: re.Pattern
) -> str | None:
    """Innermost binding of `name` visible at line `upto`, respecting SCOPE.

    A function-local `const` SHADOWS the file-level one, and missing that is not
    hypothetical: tests in the scouting file look identical to a reader who only
    scans the file header, because they redefine PORT inside their own body.

    ⚠ BUT A LOCAL CONST MUST NOT LEAK FORWARD INTO THE NEXT FUNCTION, which is
    the bug the first cut of this reader shipped: it kept the last match anywhere
    above the use site, so a `const PORT` declared inside one test silently
    became the answer for every test after it, and the gate then reported
    collisions on addresses nobody binds while missing the real one. The search
    is therefore TWO passes -- the enclosing function's own body first, and only
    then file scope, meaning lines outside any function.
    """
    def last_match(lo: int, hi: int) -> re.Match | None:
        found = None
        for i in range(lo, hi):
            m = pattern.search(lines[i])
            if m and m.group(1) == name:
                found = m
        return found

    found = last_match(fn_start, upto)
    if not found:
        # MODULE scope, which is a real scope between the function and the file
        # and NOT an optional refinement: this file's `mod round2` and
        # `mod round3_tls` each declare their own `const PORT`, and a reader that
        # skips module scope resolves both to the file-level one and reports two
        # collisions that do not exist while the file's own comment says those
        # tests were already separated. The first cut of this gate did exactly
        # that. The enclosing module is the nearest `mod` whose block has not
        # closed above the use site.
        depth, mod_start = 0, None
        for i in range(upto):
            s = lines[i]
            if MOD.match(s) and mod_start is None:
                mod_start, depth = i, 0
            if mod_start is not None:
                depth += s.count("{") - s.count("}")
                if depth <= 0 and i > mod_start:
                    mod_start = None
        if mod_start is not None:
            found = last_match(mod_start, upto)
    if not found:
        # File scope: a const indented into a function or module body belongs to
        # that body, so only column-0 declarations count here.
        for i in range(upto):
            m = pattern.search(lines[i])
            if m and m.group(1) == name and not lines[i].startswith((" ", "\t")):
                found = m
    if not found:
        return None
    if pattern is CONST_IP:
        return ".".join(found.group(2, 3, 4, 5))
    return found.group(2)


def binds(path: pathlib.Path) -> tuple[list[tuple[str, str, str]], list[tuple[str, str]]]:
    """(resolved, deferred) for one file -- (fn, group, port) and (fn, why)."""
    return binds_text(path.read_text(errors="replace"))


def binds_text(text: str) -> tuple[list[tuple[str, str, str]], list[tuple[str, str]]]:
    """The reader, over TEXT, so `--selftest` needs no tree on disk."""
    lines = text.splitlines()
    fns = [(i, m.group(1)) for i, l in enumerate(lines) if (m := FN.match(l))]
    resolved, deferred = [], []
    for i, line in enumerate(lines):
        m = BIND.search(line)
        if not m:
            continue
        enclosing = [f for f in fns if f[0] < i] or [(0, "<file scope>")]
        fn_start, owner = enclosing[-1]
        graw, praw = m.group(1), m.group(2)
        if (lit := IP_LITERAL.match(graw)):
            group = ".".join(lit.group(1, 2, 3, 4))
        else:
            group = resolve(graw.split("::")[-1], lines, i, fn_start, CONST_IP)
        port = praw if praw.isdigit() else resolve(praw, lines, i, fn_start, CONST_U16)
        if group is None or port is None:
            deferred.append((owner, f"{graw}/{praw} does not resolve to a literal"))
            continue
        resolved.append((owner, group, port))
    return resolved, deferred


def run(root: pathlib.Path) -> int:
    files = test_files(root)
    claims: dict[tuple[str, str], list[str]] = {}
    deferred_all: list[str] = []
    n_files = 0
    for f in files:
        resolved, deferred = binds(f)
        if not resolved and not deferred:
            continue
        n_files += 1
        rel = f.relative_to(root).as_posix()
        for owner, group, port in resolved:
            claims.setdefault((group, port), []).append(f"{rel}::{owner}")
        for owner, why in deferred:
            deferred_all.append(f"{rel}::{owner} -- {why}")

    total = sum(len(v) for v in claims.values())
    print(
        f"multicast-address-collision: {total} bind(s) across {n_files} test file(s); "
        f"{len(claims)} distinct (group, port); {len(deferred_all)} unresolved"
    )
    for d in deferred_all:
        print(f"  UNRESOLVED  {d}")

    # A population of zero is a FAIL, not a pass: it means this reader stopped
    # seeing the thing it guards, which is indistinguishable from a clean tree
    # by exit status alone.
    if total == 0:
        print("multicast-address-collision: FAIL -- population is ZERO; the reader "
              "found no multicast bind at all, so it graded nothing")
        return 1

    collisions = {
        addr: sorted(set(owners))
        for addr, owners in claims.items()
        if len(set(owners)) > 1
    }
    if collisions:
        print("multicast-address-collision: FAIL")
        for (group, port), owners in sorted(collisions.items()):
            print(f"  {group}:{port} is bound by {len(owners)} test(s):")
            for o in owners:
                print(f"      {o}")
        print("  A multicast group is machine-wide, so these tests read each "
              "other's datagrams whenever the scheduler overlaps them. Give each "
              "test an address no other test binds -- and leave the compiled-in "
              "default to whichever test is actually ABOUT the default.")
        return 1

    print("multicast-address-collision: OK -- every test binds an address no "
          "other test binds")
    return 0


#: THE SCOPE FIXTURE. Both of this reader's shipped bugs were scope bugs, and
#: both produced CONFIDENT WRONG findings rather than silence -- collisions on
#: addresses nobody bound, while the real one went unreported. A resolver that
#: answers from the wrong scope is indistinguishable from a correct one by exit
#: status, so the three levels are pinned here by construction.
SELFTEST_SRC = """\
const GROUP: Ipv4Addr = Ipv4Addr::new(224, 0, 0, 224);
const PORT: u16 = 7446;

async fn uses_file_scope() {
    let d = UdpDriver::bind_multicast(GROUP, PORT, cfg).await;
}

async fn shadows_it_locally() {
    const PORT: u16 = 7450;
    let d = UdpDriver::bind_multicast(GROUP, PORT, cfg).await;
}

async fn must_not_inherit_the_previous_local() {
    let d = UdpDriver::bind_multicast(GROUP, PORT, cfg).await;
}

mod inner {
    const PORT: u16 = 7448;

    async fn uses_module_scope() {
        let d = UdpDriver::bind_multicast(GROUP, PORT, cfg).await;
    }
}

async fn unresolvable(port: u16) {
    let d = UdpDriver::bind_multicast(GROUP, port, cfg).await;
}
"""


def selftest() -> int:
    resolved, deferred = binds_text(SELFTEST_SRC)
    got = {fn: f"{g}:{p}" for fn, g, p in resolved}
    want = {
        "uses_file_scope": "224.0.0.224:7446",
        # A local const wins over the file's.
        "shadows_it_locally": "224.0.0.224:7450",
        # ...and must NOT leak forward: this was the first shipped bug.
        "must_not_inherit_the_previous_local": "224.0.0.224:7446",
        # A module's const beats the file's: this was the second.
        "uses_module_scope": "224.0.0.224:7448",
    }
    bad = [(k, want[k], got.get(k)) for k in want if got.get(k) != want[k]]
    for fn, exp, act in bad:
        print(f"selftest FAIL: {fn} resolved {act}, expected {exp}")
    if [fn for fn, _ in deferred] != ["unresolvable"]:
        print(f"selftest FAIL: deferred set is {[f for f, _ in deferred]}, "
              "expected exactly ['unresolvable']")
        bad.append(("deferred", "", ""))
    if bad:
        return 1
    print("multicast-address-collision selftest OK -- file, local and module "
          "scope each resolve, a local does not leak forward, and an "
          "unresolvable bind is deferred rather than counted safe")
    return 0


def main() -> int:
    if len(sys.argv) > 1 and sys.argv[1] == "--selftest":
        return selftest()
    if len(sys.argv) > 1 and sys.argv[1] not in ("--check",):
        print(f"multicast_address_collision_gate: unknown argument {sys.argv[1]!r}")
        return 2
    return run(pathlib.Path(__file__).resolve().parents[2])


if __name__ == "__main__":
    sys.exit(main())
