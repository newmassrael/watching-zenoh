#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
# SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

"""R2079 (no register item) — is `DEEPENABLE_UPSTREAM_KEYS` COMPLETE?

It answers for open-debt item 502, which lives in the agent-memory register
OUTSIDE this tree and therefore has no `debt-` id to cite — the same position
`debt_plane_census.py` records for itself.

## The question this answers, and the one it does not

`wz_reads_a_stock_zenohd_config`'s LEG 9 asks a real zenohd about every key the
constant NAMES. That protects the entries. It cannot see a key the constant is
MISSING, and that is the dangerous direction: a key wrongly off the list makes wz
refuse a file a real zenohd starts on, and the only detection path left is an
operator reporting that their node will not come up.

This script asks the other question. It walks the WHOLE upstream surface --
`HONOURED_CONFIG_KEYS` + `UNHONOURED_UPSTREAM_CONFIG_KEYS` -- hands each key a
deeper shape, and classifies the key by what zenohd ANSWERS. Run it in any round
that moves the surface or the exception list.

MEASURED when it was written: it found `listen/retry` accepting a deeper shape
and absent from the list, which R2078 had introduced and no test could see.

## Why the probe needs no per-key value knowledge

Every key gets `{ zzz_not_a_mode: 1 }`, which is not a mode name and not a valid
value for anything. The classification is the MESSAGE, not the exit code:

  * the process comes up                       -> the subtree is OPAQUE
  * "expected one of `router`, `peer`, `client`" -> the key is MODE-DEPENDENT
  * anything else                               -> the key takes no deeper shape

⛔ Reading the message rather than the status is the whole method. Six probes in
the round that built the list came back "refused" and were DEAD -- four because
the fixture restated a key its own document already had (`duplicate field`), two
because the value shape was wrong. An exit code cannot tell a negative result
from a broken probe.

⚠ ONE KEY IS A KNOWN DEAD PROBE HERE, and it is named rather than silently
excused: `plugins` answers `plugins.zzz_not_a_mode must be object` -- a complaint
about the VALUE, not about the name -- while `plugins: { rest: { zzz: 1 } }`
starts. It is reported as UNDECIDED so the reader is told, not told nothing.

## The SECOND question, added in R2149 (open-debt item 538)

The classification above already separates a mode table from an opaque subtree,
and until R2149 the file threw that apart away -- both folded into one `accepts`
set, the distinction surviving only in `--verbose` output and compared against
nothing. So `MODE_DEPENDENT_CONFIG_KEYS` was never asked of upstream at all,
while every existing gate over it checks wz's constants against wz's OWN reader.
A wz that is wrong about upstream and self-consistent passes all of them.

It matters because that constant decides whether `inside_a_mode_table` lifts
every leaf under a key OUT of the ignored report. A key wrongly on it makes wz
read an operator's typo as a row of a table it honours: not applied, not
reported, silent.

⛔ THE TWO DIRECTIONS ARE ASYMMETRIC, AND THAT ASYMMETRY IS THE DESIGN. A
declared key is refuted only by REFUSED. OPAQUE does NOT refute one: measured,
a real zenohd answers OPAQUE for `scouting/multicast/autoconnect_strategy`,
which belongs on the list -- upstream declares it
`ModeDependentValue<TargetDependentValue<AutoConnectStrategy>>` and the inner
`Dependent` arm accepts any object, so this probe's value parses and the node
starts. OPAQUE is a fact about THE PROBE's reach, not about the key, so those
keys are printed by name and folded into no pass. The other direction needs no
such care and carries the worse consequence: a HONOURED key upstream resolves as
a mode table which wz has not declared is a spelling wz refuses and zenohd
accepts, so the node does not start on a file zenohd runs.

## Where this runs

Layer Z (`scripts/run-ci.sh`), which the hosted `interop` job runs with
`WZ_Z_REQUIRE=1` after BUILDING zenohd -- so the oracle is provisioned there
rather than absent. That lane SKIPs on a machine which has not built zenohd and
FAILs under `WZ_Z_REQUIRE`; this script still exits 2 on a missing binary, for
the same reason in the smaller. A gate whose input is absent must not report
green.

pre-push never runs Layer Z, so none of this slows a push. Wall clock is why it
sits there and not in a fast lane: one zenohd startup per key, measured at 117s
for the 111-key surface in R2149 -- the same figure `run-ci.sh` carries beside
the call, deliberately, because two numbers for one measurement is how the pair
this round had to correct went stale in the first place.

⚠ Until R2149 this section was titled "Why this is NOT wired into a CI layer"
and said the oracle is one "no CI runner has". That had been false since R2080
wired it into Layer Z, and a reader who believed it would have taken every
check below for a local convenience nothing enforces.

Usage:
    python3 scripts/lib/deepenable_audit.py [--verbose]
"""

from __future__ import annotations

import argparse
import os
import pathlib
import re
import subprocess
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))

import rust_comments  # noqa: E402  -- after the path insert that finds it
import tempfile
import time

REPO_ROOT = pathlib.Path(__file__).resolve().parents[2]
SOURCE = REPO_ROOT / "crates" / "wz-runtime-tokio" / "src" / "zenoh_config.rs"
# R2080 — the same override the test harness reads (`zenohd_binary()`), so the
# lane and this script cannot end up asking two different binaries.
ZENOHD = pathlib.Path(
    os.environ.get("WZ_ZENOHD_BIN") or REPO_ROOT / "target" / "zenohd" / "zenohd"
)

MODE_TABLE_MARKER = "expected one of `router`, `peer`, `client`"
STARTED_MARKER = "Zenoh can be reached at"
RESOLVED_MARKER = "Initial conf:"

# The one key whose generic probe is answered about its VALUE rather than its
# shape. See the module doc: naming it is the point.
UNDECIDABLE_BY_THIS_PROBE = {"plugins"}


def rust_const(name: str) -> list[str]:
    """Read a `&[&str]` constant out of the reader's own source.

    R2083 — COMMENT LINES ARE DROPPED FIRST, and that is not tidiness. These
    constants carry long `//` rationales between their entries, and several of
    those quote a phrase: `"wz cannot do this"`, `"the reader does not read
    this"`. A string sweep that does not strip comments reads PROSE AS DATA —
    measured, it turned `HONOURED_CONFIG_KEYS`'s 30 entries into 35 and put a
    wrong surface number into this project's own notes for a round. The floors
    below could not catch it: counting too MANY passes every one of them.
    """
    src = SOURCE.read_text()
    m = re.search(r"(?:pub )?const " + name + r": &\[&str\] = &\[(.*?)\n\];", src, re.S)
    if not m:
        raise SystemExit(f"deepenable-audit: FAIL -- {name} not found in {SOURCE}")
    # R2131 (unregistered open-debt item 402) — the stripping moved to
    # `rust_comments`, which two other sweeps measured this round now share. It
    # BLANKS a comment rather than dropping its line, which is stricter than the
    # whole-line test this used to do: a trailing `// "phrase"` after a real
    # entry was never covered by "the line starts with //".
    body = rust_comments.strip_comments(m.group(1))
    return re.findall(r'"([^"]+)"', body)


def document_for(key: str) -> str:
    """`{ mode: "peer", <key as nested objects>: { zzz_not_a_mode: 1 } }`."""
    if key == "mode":
        return '{ mode: { zzz_not_a_mode: 1 } }'
    inner = "{ zzz_not_a_mode: 1 }"
    for seg in reversed(key.split("/")):
        inner = "{ %s: %s }" % (seg, inner)
    return '{ mode: "peer", %s }' % inner[1:-1].strip()


def verdict_for(key: str, workdir: pathlib.Path) -> str:
    """Run one probe, and STOP as soon as the answer is on the page.

    R2080 — the first cut let `subprocess.run` hit a fixed timeout, so every key
    whose subtree is opaque cost the whole timeout instead of the ~60ms it takes
    zenohd to print its resolved config. Waiting for a deadline that has already
    been answered is not caution, it is just slower; the refusals still cost what
    zenohd's own startup costs, and that part is not ours to shorten.
    """
    config = workdir / "probe.json5"
    config.write_text(document_for(key) + "\n")
    log = workdir / "probe.log"
    accepted = False
    with open(log, "wb") as sink:
        proc = subprocess.Popen(
            [str(ZENOHD), "-c", str(config), "--rest-http-port", "none"],
            stdout=sink,
            stderr=sink,
        )
        deadline = time.monotonic() + 30.0
        while True:
            blob = log.read_text(errors="replace")
            if STARTED_MARKER in blob or RESOLVED_MARKER in blob:
                accepted = True
                break
            if proc.poll() is not None:
                break
            if time.monotonic() > deadline:
                break
            time.sleep(0.02)
        if proc.poll() is None:
            proc.kill()
        proc.wait()

    if accepted:
        return "OPAQUE"
    blob = log.read_text(errors="replace")
    if MODE_TABLE_MARKER in blob:
        return "MODE_TABLE"
    return "REFUSED"


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--verbose", action="store_true")
    args = ap.parse_args()

    if not ZENOHD.is_file():
        print(
            f"deepenable-audit: FAIL -- no zenohd at {ZENOHD}. This audit's whole "
            f"content is what UPSTREAM answers, so an absent oracle is a failure "
            f"and not a skip. Run scripts/build-zenohd.sh.",
            file=sys.stderr,
        )
        return 2

    surface = sorted(
        set(rust_const("HONOURED_CONFIG_KEYS"))
        | set(rust_const("UNHONOURED_UPSTREAM_CONFIG_KEYS"))
    )
    declared = set(rust_const("DEEPENABLE_UPSTREAM_KEYS"))
    # R2080 — FLOORS, not just non-emptiness. The constants are read out of Rust
    # by regex, so a reformat that split one of them differently would be read
    # PARTIALLY, and a partial read PASSES: fewer keys probed, nothing said. That
    # is "a population of zero is green" in its quieter form. The floors sit far
    # below the measured 116 / 17, so ordinary movement of the surface does not
    # touch them and only a broken read can reach them.
    if len(surface) < 100:
        raise SystemExit(
            f"deepenable-audit: FAIL -- read only {len(surface)} surface key(s) out "
            f"of {SOURCE.name}. The constant moved, so this sweep is measuring a "
            f"fraction of the surface while reporting on all of it."
        )
    if len(declared) < 10:
        raise SystemExit(
            f"deepenable-audit: FAIL -- read only {len(declared)} deepenable key(s). "
            f"A partial read of the exception list makes every key it lost look "
            f"like a missing entry."
        )

    accepts: set[str] = set()
    undecided: set[str] = set()
    verdicts: dict[str, str] = {}
    with tempfile.TemporaryDirectory() as tmp:
        workdir = pathlib.Path(tmp)
        for key in surface:
            verdict = verdict_for(key, workdir)
            verdicts[key] = verdict
            if key in UNDECIDABLE_BY_THIS_PROBE:
                undecided.add(key)
            elif verdict in ("OPAQUE", "MODE_TABLE"):
                accepts.add(key)
            if args.verbose:
                print(f"  {key:48s} {verdict}")

    missing = sorted(accepts - declared)
    stale = sorted(declared - accepts - undecided)

    for key in missing:
        print(
            f"  deepenable-audit: {key} accepts a deeper shape and is NOT in "
            f"DEEPENABLE_UPSTREAM_KEYS. wz REFUSES a file zenohd starts on."
        )
    for key in stale:
        print(
            f"  deepenable-audit: {key} is in DEEPENABLE_UPSTREAM_KEYS and refuses "
            f"a deeper shape. wz accepts a typo zenohd would catch."
        )
    for key in sorted(undecided):
        print(
            f"  deepenable-audit: {key} UNDECIDED -- this probe's value is wrong "
            f"for it, not its shape. Judge it by hand."
        )

    # ── the MODE-TABLE cross-check (R2149, open-debt item 538) ──────────
    #
    # This probe already SEPARATES a mode table from an opaque subtree -- the
    # message says which -- and until now it threw that apart away, folding both
    # into `accepts`. Nothing anywhere compared it to
    # `MODE_DEPENDENT_CONFIG_KEYS`, which is the constant deciding whether
    # `inside_a_mode_table` lifts every leaf under a key OUT of the ignored
    # report. A key wrongly in that list makes wz read an operator's typo as a
    # row of a table it honours: not applied, not reported, silent.
    #
    # ⚠ WHAT THIS ADDS AND WHAT IT DOES NOT, MEASURED IN R2149 RATHER THAN
    # CLAIMED. Item 538 said the two existing gates pass both wrong directions
    # green. They do not. Driven with the whole `zenoh_config::` module under
    # three constant mutations -- a declared key removed, an undeclared key
    # added, and a mode table re-modelled as named subtree fields -- each one
    # reds a PRE-EXISTING test in `zenoh_config.rs` (47 tests: 45, 45 and 46
    # passing). A constant edit alone always breaks wz's internal agreement
    # first, so nothing below is a new catch for an ordinary slip.
    #
    # What is new is the QUESTION. Every one of those gates checks wz's
    # constants against wz's OWN reader, and the `missing`/`stale` pair above
    # asks upstream only whether a key takes a deeper shape AT ALL -- which is
    # precisely the question that conflates a mode table with an opaque
    # subtree. A wz that is wrong about upstream and self-consistent passes all
    # of them: R2141 moved three keys onto this list on a hand reading of
    # upstream's types and nothing re-asked zenohd. This re-asks, once per key,
    # against a running node.
    #
    # ⛔ THE OBVIOUS COMPARISON IS WRONG, AND IT WAS MEASURED WRONG BEFORE THIS
    # SHIPPED. Item 538 prescribed comparing the MODE_TABLE set against the
    # constant in BOTH directions. Run that way, a real zenohd answers OPAQUE
    # for `scouting/multicast/autoconnect_strategy`, which IS in the constant and
    # belongs there -- upstream declares it
    # `ModeDependentValue<TargetDependentValue<AutoConnectStrategy>>`, and the
    # inner `TargetDependentValue::Dependent` arm accepts any object, so this
    # probe's `{ zzz_not_a_mode: 1 }` parses and the node starts. The verdict is
    # a fact about THE PROBE's reach, not about the key. So:
    #
    #   * a declared key is refuted only by REFUSED -- zenohd rejecting the
    #     deeper shape outright. OPAQUE is "this probe cannot tell", and those
    #     keys are printed BY NAME rather than folded into a pass;
    #   * the other direction needs no such care and is the dangerous one: a
    #     HONOURED key a real zenohd answers MODE_TABLE for, which wz has not
    #     declared, is a table spelling wz REFUSES and zenohd accepts -- the node
    #     does not start. Scoped to honoured keys because the constant is
    #     documented as the honoured ones; the unhonoured mode-dependent keys
    #     (`scouting/gossip/*`, the `connect`/`listen` timeouts) are correctly
    #     absent.
    mode_dependent = set(rust_const("MODE_DEPENDENT_CONFIG_KEYS"))
    honoured = set(rust_const("HONOURED_CONFIG_KEYS"))
    if not mode_dependent:
        raise SystemExit(
            "deepenable-audit: FAIL -- MODE_DEPENDENT_CONFIG_KEYS read as empty, "
            "so both directions below compare against nothing and pass."
        )
    upstream_tables = {k for k, v in verdicts.items() if v == "MODE_TABLE"}
    if not upstream_tables:
        raise SystemExit(
            "deepenable-audit: FAIL -- no key on the whole surface answered "
            "MODE_TABLE. The marker no longer matches what zenohd prints, so "
            "this cross-check is measuring nothing."
        )

    # A declared key that is not on the surface at all would make BOTH checks
    # below pass by absence -- `verdicts.get` answers None, which is neither
    # REFUSED nor MODE_TABLE. That is this file's own "a population of zero is
    # green" shape, one level in, so it is a FAIL rather than a silence. It
    # cannot happen while the Rust side holds MODE_DEPENDENT ⊆ DEEPENABLE ⊆
    # surface; this is here for when that stops being true.
    offsurface = sorted(k for k in mode_dependent if k not in verdicts)
    if offsurface:
        raise SystemExit(
            "deepenable-audit: FAIL -- "
            + ", ".join(offsurface)
            + " is declared mode-dependent and is not on the measured surface, "
            "so nothing below judges it."
        )

    # A KNOWN DEAD PROBE MUST NOT REFUTE A DECLARATION. `plugins` answers a
    # complaint about the VALUE rather than the name, so it lands in REFUSED
    # while saying nothing about whether the key takes a deeper shape -- which is
    # the whole reason this file names it rather than excusing it silently. Were
    # it ever declared mode-dependent, the check below would red on the strength
    # of a broken probe, and "an exit code cannot tell a negative result from a
    # broken probe" is this file's own doctrine. So an undecidable key is treated
    # exactly like OPAQUE: printed by name, refuting nothing. Measured today the
    # two sets do not intersect, so this is a ratchet and not a fix.
    refuted = sorted(
        k
        for k in mode_dependent
        if verdicts.get(k) == "REFUSED" and k not in UNDECIDABLE_BY_THIS_PROBE
    )
    unreached = sorted(
        k
        for k in mode_dependent
        if verdicts.get(k) == "OPAQUE" or k in UNDECIDABLE_BY_THIS_PROBE
    )
    undeclared = sorted((upstream_tables & honoured) - mode_dependent)

    for key in refuted:
        print(
            f"  deepenable-audit: {key} is in MODE_DEPENDENT_CONFIG_KEYS and a "
            f"real zenohd REFUSES a deeper shape at it. wz lifts every leaf "
            f"under it out of the ignored report, so an operator's typo there is "
            f"neither applied nor reported."
        )
    for key in undeclared:
        print(
            f"  deepenable-audit: {key} is honoured and a real zenohd resolves it "
            f"as a {{ router, peer, client }} table, but wz has not declared it "
            f"mode-dependent. wz REFUSES the table spelling zenohd accepts, so "
            f"the node does not start on a file zenohd runs."
        )

    print(
        f"  deepenable-audit: surface {len(surface)}, declared {len(declared)}, "
        f"measured accepting {len(accepts)}, undecided {len(undecided)}"
    )
    print(
        f"  deepenable-audit: mode tables — {len(upstream_tables)} measured, "
        f"{len(mode_dependent)} declared by wz, "
        f"{len(upstream_tables & honoured)} of the measured are honoured"
    )
    if unreached:
        # Named, never a count folded into the pass: these are the keys whose
        # value type swallows the probe, so the audit is SILENT about them
        # rather than agreeing with wz.
        print(
            "  deepenable-audit: this probe cannot decide mode-dependence for "
            + ", ".join(unreached)
            + " (their value type accepts the probe's object, so the node "
            "starts); wz's declaration stands on upstream's own type."
        )
    outside = sorted(upstream_tables - honoured)
    if outside:
        # The `undeclared` direction is SCOPED to honoured keys, and a scope is a
        # claim like any other -- one that reads as coverage while it is really
        # an exclusion. So the excluded keys are printed BY NAME rather than left
        # as the arithmetic between the two counts above. Each is a real mode
        # table upstream which wz does not honour, so the constant is right to
        # omit it TODAY; each also becomes a FAIL the moment its key joins
        # HONOURED_CONFIG_KEYS without joining MODE_DEPENDENT_CONFIG_KEYS, which
        # is the transition this list exists to make visible before it happens.
        print(
            "  deepenable-audit: mode tables upstream that wz does not honour, "
            "so the constant omits them and the check above does not reach "
            "them: " + ", ".join(outside)
        )
    return 1 if missing or stale or refuted or undeclared else 0


if __name__ == "__main__":
    sys.exit(main())
