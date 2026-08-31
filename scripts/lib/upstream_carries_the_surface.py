#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
# SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

"""R2230 (no register item) — is every key wz calls UPSTREAM SURFACE a key the
pinned upstream actually CARRIES?

It answers for open-debt items 579 and 582, which live in the agent-memory
register OUTSIDE this tree and therefore have no `debt-` id to cite — the same
position `deepenable_audit.py`, `upstream_feature_census.py` and
`debt_plane_census.py` each record for themselves.

## The gap this closes

`HONOURED_CONFIG_KEYS` + `UNHONOURED_UPSTREAM_CONFIG_KEYS` are read as coverage:
"of what a real zenoh does from its file, wz does N of M". That reading needs
every member to name something upstream DOES. Nothing checked it.

`deepenable_audit.py` walks the same surface and cannot answer this. It hands
each key a deeper shape and classifies by what zenohd says, so it sees three
answers -- mode table, refusal, or "the node came up" -- and the third is
ambiguous in exactly the place that matters. Measured in R2229: the pin move to
1.10.0 made it report `routing/peer/mode` and
`routing/peer/linkstate/transport_weights` as newly "accepting a deeper shape",
which reads as "upstream grew a subtree here". The truth was the opposite --
upstream RETIRED the keys, wrapping them in a deprecated shim typed
`Option<Value>` that accepts any shape at all. "Accepts anything" and "means
something" are indistinguishable to a probe that only asks whether the process
starts.

⛔ The premise item 582 was filed on was also wrong, and re-measuring is what
found it: it recorded "zenohd accepts any object at a key it does not know".
zenohd does not. `Config` is `deny_unknown_fields` all the way down -- an
unknown key panics the daemon by name, at any depth (measured: both
`zzz_definitely_not_a_key` at the root and `routing.zzz_not_a_key`). So the
three keys are not unknown to upstream. They are known, deprecated, and inert,
which is a THIRD state neither the old probe nor the old two-list partition
could express.

## The oracle, and why it is not a list

zenohd prints its own resolved configuration on startup (`Initial conf: {...}`),
and upstream marks a retired key `#[serde(default, skip_serializing)]`. So the
daemon's own serializer answers the question directly, for the whole surface, in
one process start. Nothing here enumerates what upstream has; the population
comes from wz's constants and the verdict comes from upstream's binary, so this
cannot go stale the way a transcribed list does -- when the pin moves, the
answer moves with it.

Measured when written, against `zenohd v1.10.0`: 108 of 108 surface keys carried,
and the 3 extension keys absent from a dump produced by a run that NAMED them.

## Why the extension list cannot be an escape hatch

`WZ_EXTENSION_CONFIG_KEYS` is a list of keys exempt from the surface, which is
the shape that lets a later round shrink a denominator to make a gate green.
Membership is therefore not declared here -- it is ADJUDICATED, in both
directions, and every key lands in exactly one of three measured states:

  * KNOWN + CARRIED   -> upstream surface. Must be on the surface lists.
  * KNOWN + DISCARDED -> deprecated/inert. Must be in the extension list.
  * UNKNOWN           -> upstream removed the name outright. Must be on NEITHER.

A key in the wrong bucket is a FAIL, whichever way it points. Moving a live key
into the extension list reds; upstream reviving one of these reds too; and an
UNKNOWN key reds rather than being quietly tolerated, because a name upstream no
longer has is a wz invention that needs a decision and not an exemption.

The third bucket is deliberately a FAIL rather than a category with members. It
has no population today and this file says so instead of hiding it: a branch
nobody has run is a branch nobody has checked, so it fails loudly and states
what it found, which is the treatment `deepenable_audit.py` gives its own
UNDECIDED key.

## Where this runs

Layer Z (`scripts/run-ci.sh`), beside `deepenable_audit.py`, for the same reason:
that is the layer which already provisions a pinned zenohd. Cost is 4 daemon
starts -- one baseline plus one per extension key -- against the 108 that a
per-key sweep would need, because the dump answers the whole surface at once.

`--selftest` drives the classifier over synthetic verdicts with no zenohd at
all, so Layer C0 can prove the discrimination is real on a machine with no
upstream binary. It fails the classifier in both directions on purpose: a
selftest whose fixtures only exercise the passing path is a fixture set the old
implementation would also have swallowed.

Usage:
    python3 scripts/lib/upstream_carries_the_surface.py [--verbose]
    python3 scripts/lib/upstream_carries_the_surface.py --selftest
"""

from __future__ import annotations

import argparse
import json
import os
import pathlib
import re
import subprocess
import sys
import tempfile
import time

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))

# The constant reader is `deepenable_audit`'s, imported rather than copied. Its
# docstring records that a sweep which does not strip Rust comments reads PROSE
# AS DATA and inflated this very surface by five once; a second parser here
# would be a second chance to make that mistake, and the two scripts read the
# same constants out of the same file. Importing is side-effect free -- that
# module does its work under `if __name__ == "__main__"`.
import deepenable_audit  # noqa: E402  -- after the path insert that finds it

REPO_ROOT = pathlib.Path(__file__).resolve().parents[2]
ZENOHD = pathlib.Path(
    os.environ.get("WZ_ZENOHD_BIN") or REPO_ROOT / "target" / "zenohd" / "zenohd"
)

# The same override `deepenable_audit` and the test harness read, so this cannot
# end up interrogating a different binary than the layer around it tests.
INITIAL_CONF = re.compile(r"Initial conf: (\{.*\})\s*$")
UNKNOWN_FIELD = re.compile(r"unknown field `([^`]+)`")

# Below this the reader is not reading the surface, whatever it returned. The
# floor is far under the measured 108 so ordinary movement does not trip it; it
# exists because "the regex matched nothing" and "the surface is empty" produce
# the same green in a check that only compares two sets.
SURFACE_FLOOR = 100

STARTUP_TIMEOUT_S = 20.0


def rust_const(name: str) -> list[str]:
    try:
        return deepenable_audit.rust_const(name)
    except SystemExit as exc:  # its message names the other script
        raise SystemExit(
            f"upstream-carries: FAIL -- could not read {name}: {exc}"
        ) from exc


def document_for(key: str, value: str) -> str:
    """`{ <key as nested objects>: <value> }` -- json5, the shape zenohd takes."""
    inner = value
    for seg in reversed(key.split("/")):
        inner = "{ %s: %s }" % (seg, inner)
    return inner


def run_zenohd(doc: str) -> tuple[dict | None, str]:
    """Start zenohd on `doc`; return its resolved config and everything it said.

    The config is read from the daemon's own startup line rather than from any
    file this tree keeps, which is the whole point: the answer has to come from
    the binary the pin builds.
    """
    with tempfile.NamedTemporaryFile(
        "w", suffix=".json5", delete=False, dir=tempfile.gettempdir()
    ) as handle:
        handle.write(doc + "\n")
        cfg = handle.name
    said: list[str] = []
    dump: dict | None = None
    proc = subprocess.Popen(
        [str(ZENOHD), "-c", cfg, "--no-multicast-scouting"],
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
    )
    try:
        deadline = time.monotonic() + STARTUP_TIMEOUT_S
        while time.monotonic() < deadline:
            line = proc.stdout.readline()
            if not line:
                break
            said.append(line.rstrip("\n"))
            match = INITIAL_CONF.search(line)
            if match:
                try:
                    dump = json.loads(match.group(1))
                except json.JSONDecodeError as exc:
                    said.append(f"(the Initial conf line did not parse: {exc})")
                break
    finally:
        proc.kill()
        proc.wait()
        os.unlink(cfg)
    return dump, "\n".join(said)


def carries(dump: dict, path: str) -> bool:
    """Does the daemon's own resolved config contain this leaf path?

    A `null` COUNTS. Upstream renders a key it carries but has no value for as
    an explicit null (`"policies":null`), and a retired key not at all -- that
    difference is precisely the signal, so "present with a falsey value" must
    not be folded into "absent".
    """
    node: object = dump
    for seg in path.split("/"):
        if not isinstance(node, dict) or seg not in node:
            return False
        node = node[seg]
    return True


def classify(known: bool, carried: bool) -> str:
    """The three measured states a key can be in. No fourth, and no default."""
    if not known:
        return "UNKNOWN"
    return "CARRIED" if carried else "DISCARDED"


def verdict_for(key: str, state: str, on_surface: bool, on_extension: bool) -> str | None:
    """The complaint this key earns, or None. Both directions, no silent pass."""
    if on_surface and on_extension:
        return (
            f"{key} is on the upstream surface AND in the extension list, so it "
            f"is exempted from a denominator it is also counted in"
        )
    if not on_surface and not on_extension:
        return (
            f"{key} was measured but is on neither list -- this check's "
            f"population comes from those lists, so reaching here means one was "
            f"read wrong"
        )
    if state == "CARRIED" and not on_surface:
        return (
            f"{key} IS carried by the pinned upstream's own resolved config, so "
            f"it is a live upstream capability being held out of the surface. "
            f"Move it back onto HONOURED_CONFIG_KEYS or "
            f"UNHONOURED_UPSTREAM_CONFIG_KEYS"
        )
    if state == "DISCARDED" and on_surface:
        return (
            f"{key} is claimed as upstream surface and the pinned upstream "
            f"PARSES AND DISCARDS it -- it is absent from the daemon's own "
            f"resolved config even when the file names it. It names no upstream "
            f"capability, so counting it makes the honoured fraction divide by a "
            f"non-feature. Move it to WZ_EXTENSION_CONFIG_KEYS"
        )
    if state == "UNKNOWN":
        return (
            f"{key} is REFUSED BY NAME by the pinned upstream, which is neither "
            f"of the two states either list means. Upstream removed the name; wz "
            f"accepting it is a wz invention that needs a decision (keep it as a "
            f"wz-only key with its own claim, or drop it), not a place on either "
            f"list"
        )
    return None


def selftest() -> int:
    """Drive the classifier in BOTH directions, with no upstream binary.

    Every row here is a shape the pre-R2230 arrangement would have passed: the
    surface list carried a discarded key and nothing said so, and there was no
    extension list for a live key to hide in. A selftest whose fixtures only
    exercise the passing path proves nothing about a check that was written to
    catch the failing one.
    """
    cases = [
        # (known, carried, on_surface, on_extension, must_complain)
        (True, True, True, False, False),  # a live key on the surface
        (True, False, False, True, False),  # a retired key in the extension list
        (True, False, True, False, True),  # R2229's actual state
        (True, True, False, True, True),  # a live key hidden in the extension
        (False, False, False, True, True),  # a name upstream no longer has
        (False, False, True, False, True),  # ... claimed as surface
        (True, True, True, True, True),  # counted and exempted at once
        (True, True, False, False, True),  # on neither list
    ]
    failures = 0
    for known, carried, on_surface, on_extension, must_complain in cases:
        state = classify(known, carried)
        complaint = verdict_for("k", state, on_surface, on_extension)
        if (complaint is not None) != must_complain:
            failures += 1
            print(
                f"  upstream-carries: SELFTEST FAIL -- known={known} "
                f"carried={carried} surface={on_surface} extension={on_extension} "
                f"-> state {state}, complaint {complaint!r}, expected "
                f"{'a complaint' if must_complain else 'none'}"
            )
    # A classifier that complained about everything would pass every row above
    # that expects a complaint, so the silent rows have to be present AND
    # counted; this asserts the check discriminates rather than merely fires.
    silent = sum(1 for c in cases if not c[4])
    if silent < 2:
        print("  upstream-carries: SELFTEST FAIL -- too few passing rows to show")
        failures += 1
    if failures:
        return 1
    print(
        f"  upstream-carries: selftest ok -- {len(cases)} classifier row(s), "
        f"{silent} of them silent"
    )
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--verbose", action="store_true")
    parser.add_argument(
        "--selftest",
        action="store_true",
        help="drive the classifier over synthetic verdicts; needs no zenohd",
    )
    args = parser.parse_args()

    if args.selftest:
        return selftest()

    surface = sorted(
        set(rust_const("HONOURED_CONFIG_KEYS"))
        | set(rust_const("UNHONOURED_UPSTREAM_CONFIG_KEYS"))
    )
    extension = sorted(set(rust_const("WZ_EXTENSION_CONFIG_KEYS")))
    if len(surface) < SURFACE_FLOOR:
        print(
            f"  upstream-carries: FAIL -- read only {len(surface)} surface key(s) "
            f"out of {SOURCE_NAME}, under the floor of {SURFACE_FLOOR}. The "
            f"constant reader is not reading the surface, so nothing below this "
            f"is a claim about it.",
            file=sys.stderr,
        )
        return 2
    if not extension:
        print(
            "  upstream-carries: FAIL -- the extension list is EMPTY, so the "
            "half of this check that adjudicates it has no population. A check "
            "over nothing must not report green.",
            file=sys.stderr,
        )
        return 2
    if not ZENOHD.is_file() or not os.access(ZENOHD, os.X_OK):
        print(
            f"  upstream-carries: FAIL -- no zenohd at {ZENOHD}. The oracle IS "
            f"the pinned binary's own resolved config; without it there is no "
            f"answer to report. Build it with scripts/build-zenohd.sh, or point "
            f"WZ_ZENOHD_BIN at one.",
            file=sys.stderr,
        )
        return 2

    baseline, said = run_zenohd('{ mode: "peer" }')
    if baseline is None:
        print(
            "  upstream-carries: FAIL -- the pinned zenohd printed no parseable "
            "`Initial conf:` line, so its resolved config could not be read. "
            "Everything below depends on it; nothing was graded. It said:",
            file=sys.stderr,
        )
        print("    " + said.replace("\n", "\n    "), file=sys.stderr)
        return 2

    complaints: list[str] = []
    states: dict[str, str] = {}

    # The surface, answered wholesale by one dump. A key here is KNOWN by
    # construction -- it is in a document the daemon accepted, or it would not
    # have started -- so the only open question is whether upstream carries it.
    for key in surface:
        state = classify(True, carries(baseline, key))
        states[key] = state
        complaint = verdict_for(key, state, on_surface=True, on_extension=key in extension)
        if complaint:
            complaints.append(complaint)

    # The extension keys, in two steps, and THE ORDER IS THE DESIGN.
    #
    # The baseline dump is asked FIRST, because it settles the case that matters
    # most: a key upstream still carries is in that dump whether or not any file
    # names it, so a live key smuggled into the extension list is caught right
    # here, by the same evidence that judged the surface. Measured while writing
    # this: putting `routing/interests/timeout` in the extension list and probing
    # it per-key first produced "not graded" (a FAIL, so the hatch was shut, but
    # a FAIL that named the wrong problem) -- zenohd refused the probe's bare
    # `true` for its VALUE, since that key is a number. Asking the dump first
    # turns that into the classification error it actually is.
    #
    # Only a key the baseline does NOT carry needs its own start, and then the
    # start is doing something the dump cannot: distinguishing "upstream parses
    # this and throws it away" from "upstream no longer has the name at all".
    # That probe hands the key a bare `true` and reads the MESSAGE, not the exit
    # status -- a complaint about the VALUE is itself proof the name is known,
    # which is the method `deepenable_audit.py` documents at length.
    for key in extension:
        if carries(baseline, key):
            state = "CARRIED"
        else:
            dump, said = run_zenohd(document_for(key, "true"))
            if dump is None:
                unknown = UNKNOWN_FIELD.search(said)
                segments = set(key.split("/"))
                if unknown and unknown.group(1) in segments:
                    state = "UNKNOWN"
                else:
                    print(
                        f"  upstream-carries: FAIL -- zenohd neither started nor "
                        f"refused {key} by name, so this key was NOT graded. It "
                        f"said:",
                        file=sys.stderr,
                    )
                    print("    " + said.replace("\n", "\n    "), file=sys.stderr)
                    return 2
            else:
                # The strong form, and the reason this start happens at all: the
                # document NAMED the key and the daemon's own resolved config
                # still does not carry it. That is upstream discarding it, not
                # this probe having failed to ask.
                state = classify(True, carries(dump, key))
        states[key] = state
        complaint = verdict_for(key, state, on_surface=key in surface, on_extension=True)
        if complaint:
            complaints.append(complaint)

    if args.verbose:
        for key in sorted(states):
            print(f"    {states[key]:<9} {key}")

    for complaint in complaints:
        print(f"  upstream-carries: {complaint}", file=sys.stderr)

    carried = sum(1 for k in surface if states[k] == "CARRIED")
    discarded = sum(1 for k in extension if states[k] == "DISCARDED")
    print(
        f"  upstream-carries: surface {len(surface)}, {carried} carried by the "
        f"pinned zenohd's own resolved config; extension {len(extension)}, "
        f"{discarded} named-and-discarded"
    )
    return 1 if complaints else 0


SOURCE_NAME = deepenable_audit.SOURCE

if __name__ == "__main__":
    raise SystemExit(main())
