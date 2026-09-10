#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
# SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

"""R2228 (no register item) — how far behind each pinned upstream this tree is,
as a number a command produces rather than one a person happens to ask for.

The citation is `no register item` for the reason `lane_reach_gate.py` gives for
its own: the item this answers — unregistered open-debt item 578 — lives in the
agent-memory register, which has no store `debt-` id for `gate_provenance_lint`
to resolve. Naming it in prose here and `no register item` in the citation is
the honest pair; inventing a store id would make the join it checks a fiction.

## Why this exists, measured

On 2026-08-31 a round judged what "a genuine zenoh does" from a checkout it
never version-checked, and the pin turned out to be five minors old. The
conclusion survived, but it survived because someone ASKED — the user's "isn't
that just because upstream is an old version?" — and nothing in the tree would
have raised it. That is the whole of item 578: this tree's discipline is "cite
file:line for any source claim", and NOBODY MEASURES WHICH RELEASE those lines
were read from.

## What it measures, and why each half is DERIVED rather than listed

Both halves come from somewhere that already exists, because a third list would
be the copy item 567 refused:

* the POPULATION — every repository this tree fetches — from
  `gate_reason_claims.upstream_urls`, which reads the `url` of every submodule
  and every `git clone` in a tracked script or workflow. Seven repositories,
  and note that item 578's own text named TWO (`ZENOHD_VERSION` and the
  vendored pico). Deriving found `zenoh-c` pinned at the same `1.5.0` as zenoh,
  an axis the item did not know it had. That gap is the argument for ②.
* the PIN — from the structure that does the pinning, three shapes, each of
  which this tree actually uses:
    1. a submodule, whose checked-out `git describe --tags` names its base tag;
    2. `git clone --branch "$VAR"` in a script that also writes
       `VAR="${VAR:-VALUE}"`;
    3. `git clone` followed by `checkout "$VAR"` in a workflow whose `env:`
       block writes `VAR: VALUE`.
* the UPSTREAM SIDE — the GitHub releases API. Not a table of known versions;
  the repository's own answer.

## ⛔ A GATE THAT CANNOT MEASURE MUST NOT REPORT GREEN

Item 578's condition ③, and it is the reason this is NOT wired into `pre-push`.
An unreachable API, a missing `gh`, an empty response: each FAILS. The cost is
stated rather than hidden — this lane depends on the network, which no other
lane in this tree does, so a GitHub outage reds a run. That is the trade item
578 asked for in as many words ("못 재는 게이트는 초록을 보고하면 안 된다"),
and the alternative — a SKIP that goes green — is the exact failure this gate
exists to prevent, one layer up.

⚠ `NO_RELEASES` is NOT that escape. It is an OBSERVATION: the API answered, and
its answer was an empty list. The two are told apart by whether the call
succeeded, and a repository classified `NO_RELEASES` must ALSO fail to yield a
pin — `vendor/sce` has no tags at all, so `git describe` and the releases API
agree about it. A repository that has releases but whose pin cannot be derived
is RED, which is the direction that keeps the classification from being a
declaration.

## The verdicts, and why they are pinned in BOTH directions

`DISTANCE` below is not a budget somebody chose; it is the measurement, frozen.
One more release upstream and the number rises and this reds — which is the
whole point, since item 578 exists so that "five minors behind" cannot happen
again unnoticed. One fewer and it reds too, so that a pin bump must move this
line rather than quietly leaving it high. R2217 pinned a count the same way and
for the same reason.

⚠ `PIN_NOT_A_RELEASE` would be an escape hatch if it were merely tolerated:
pin by SHA and the distance question goes away. So the set carrying it is
pinned too. Zephyr is in it because `ZEPHYR_REF` is a commit, and a second
repository joining it is a RED that asks why a tagged pin was abandoned.
"""

from __future__ import annotations

import argparse
import json
import os
import pathlib
import re
import subprocess
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))

import gate_reason_claims as grc  # noqa: E402

ROOT = pathlib.Path(__file__).resolve().parents[2]

# The measurement, frozen in both directions. `distance` is how many releases
# upstream has published since the pinned one; `verdict` is the classification
# whose alternatives are documented above.
#
# MEASURED 2026-08-31 (R2228). Read the module docstring before changing a row:
# a rising number is upstream moving and belongs to open-debt item 579, not to
# this table.
#
# R2229 (item 579) moved zenoh and zenoh-c from 9 to 0 by bumping the pins to
# 1.10.0, and this table RED-ed on the way through — in the falling direction,
# which is the half a one-sided budget would have missed. That is the round this
# gate was built one round early for.
#
# R2501 (open-debt item 711) — zenoh 0 -> 1, zenoh-c 0 -> 1, zenoh-pico 1 -> 2.
# UPSTREAM PUBLISHED; the pins did not move. This is the RISING direction the
# docstring above describes, and moving the table is the maintenance it asks
# for: the row is the measurement, not a tolerance.
#
# ⚠ AND THIS ROW MOVE IS NOT THE PIN BUMP. The gate's own FAIL text says a
# rising number "is open-debt item 579's work, not this table's" — but 579 is
# CLOSED (R2236), and so are the two items above it: 578 built this gate and
# handed its remaining condition to 581 (CLOSED R2228 / R2241). So the sentence
# points at an owner that no longer exists, which is why item 711 was filed to
# hold the position. It splits the work deliberately: moving this row is the
# cheap per-observation MAINTENANCE, and bumping the real pins (1.10.0 -> next,
# which drags Layer Z / Ewire re-verification behind it) is a ROUND that 711
# still owes. ⛔ Do not let the first stand in for the second — that is how
# "five minors behind" happens again, which is the thing item 578 existed to
# prevent.
#
# ⚠⚠ THIS RED WAS INVISIBLE FOR THE WHOLE WINDOW, and that is why it arrives as
# a jump rather than one release at a time: Layer U sits at step 18 behind the
# C0 pair, which failed at leg 68 from R2448 until R2498 repaired it. Item 695
# had predicted exactly this — it recorded Layer U as one of two legs that "have
# never received a verdict since the window opened" and said to read them first
# in the run where C0 is released. Run 34417146811 is that run.
#
# R2527 (open-debt item 711) — zenoh 1 -> 0 and zenoh-c 1 -> 0, and THIS ONE IS
# THE PIN BUMP, not the maintenance the clause above distinguishes it from. The
# pins moved: `UPSTREAM_VERSION`, `ZENOHD_VERSION` and `ZENOH_C_VERSION` are all
# 1.10.1. So this is the FALLING direction again, the same half R2229 exercised,
# and the table red-ed on the way through exactly as it did then
# (`pinned distance=1, observed distance=0`, twice).
#
# R2528 (open-debt item 711) — zenoh-pico 2 -> 0. R2527 left it deliberately,
# on the reasoning that a vendored C submodule crossing a MINOR is a different
# risk from a Rust patch. That reasoning was right to hold the round back and
# WRONG about the size: the entire public-header delta between 1.9.0 and 1.10.1
# is one changed declaration (`zp_spin_once` void -> bool), a doc clarification
# on `z_timestamp_new`, a test-hooks-gated override typedef (pico's own test
# scaffolding, not consumer ABI), and one doc word.
# Measured by diffing the headers, which is the same move that made R2527 cheap.
#
# R2529 (open-debt item 711) — FreeRTOS-Kernel 3 -> 0, V11.1.0 -> V11.3.1, and
# with it EVERY MEASURED ROW IS AT ZERO. The declared threshold is 0, so the
# threshold arm below now has nothing to report — which is the first time this
# table has been able to say that since the gate was built.
#
# Measured first, as with the two before it, and the surface is small by
# construction rather than by luck: `crates/freertos-sys` binds TEN symbols and
# compiles FIVE files. All ten are still declared at V11.3.1, all five still
# exist at their paths, the GCC/ARM_CM3 port directory is intact, `xTaskCreate`'s
# prototype is unchanged, and the ARM_CM3 `portmacro.h` still typedefs
# `BaseType_t` as `long`, `UBaseType_t` as `unsigned long` and `StackType_t` as
# `uint32_t` — the three wz mirrors in `freertos-sys/src/lib.rs`.
#
# ⚠ AND THIS ONE WAS VERIFIED BY RUNNING, not only by reading, because the
# toolchain happened to be present: Layer G's `G.14 cross-real freertos-sys
# thumbv7m-none-eabi` and `G.15 wz-runtime-freertos` both compiled, and Layer Q's
# `Q.frt run mcu-freertos-demo via qemu-system-arm mps2-an385` BOOTED the new
# kernel and passed. A header read cannot tell you a scheduler still schedules.
PINNED: dict[str, tuple[str, int]] = {
    "FreeRTOS/FreeRTOS-Kernel": ("MEASURED", 0),
    "eclipse-zenoh/zenoh": ("MEASURED", 0),
    "eclipse-zenoh/zenoh-c": ("MEASURED", 0),
    "eclipse-zenoh/zenoh-pico": ("MEASURED", 0),
    "lwip-tcpip/lwip": ("NO_RELEASES", 0),
    "newmassrael/scxml-core-engine": ("NO_RELEASES", 0),
    "zephyrproject-rtos/zephyr": ("PIN_NOT_A_RELEASE", 0),
}

# R2521 (open-debt item 711) — HOW FAR BEHIND IS TOO FAR, and it is deliberately
# undeclared.
#
# ## Why the question lives here and not in a register paragraph
#
# The table above says what the distance IS. Nothing said what distance is
# ACCEPTABLE, and that gap is not academic: item 578 built this gate so that
# "five minors behind" could not happen unnoticed again, 579 bumped the pins
# when the distance had reached NINE, and 581 carried the remainder. All three
# are closed — and the sentence that held "when do we bump" closed with them.
# Nobody removed it; it simply stopped existing, which is how a policy kept in
# prose dies. Item 711 was filed to hold the position and says the repair
# outright: pin the threshold HERE, as a ratchet, or the next closing chain
# takes it again.
#
# ## The decision, taken (owner, 2026-09-10)
#
# R2521 left this `None` and said the three alternatives were genuinely
# different projects: ⑴ track every release immediately, ⑵ open a bump ROUND
# once N releases behind, ⑶ bump only when a feature needs it. Asked directly,
# the owner chose ⑴ — track every release immediately.
#
# ## Why ⑴ is ZERO and not one
#
# The check below is `dist > threshold`, so the constant is how many releases
# behind are TOLERATED, not how many trigger the round. "Track every release"
# tolerates none, which is `0`. Declaring `1` would say "one release behind is
# fine", a different policy that nobody chose. The selftest drives exactly this
# case (`(0, [...])` in `threshold_cases`), so the reading is graded rather than
# asserted here.
#
# ## ⛔ R2537 (open-debt item 716) — WHAT THIS CONSTANT NO LONGER DOES
#
# It no longer FAILs, and the paragraph that used to stand here — "what arming
# it does immediately: it reds Layer U, on purpose" — described exactly that.
# The owner's decision of 2026-09-10 refined the policy: only a step the size of
# 1.11.0 opens a bump round. A count cannot express that (a patch and a minor
# are both one release), so `BUMP_GRADE` below became the round-opening
# predicate and THIS one became the DRIFT REPORT that feeds it context.
#
# Measured before the change, on this file's own shipped functions: `judge`
# returns `("MEASURED", 1)` for a pin one PATCH behind, one MINOR behind and one
# MAJOR behind alike, and no value of this constant separates them — at 0 all
# three open a round and at 1 or more none of them does.
#
# ⛔ The MEASUREMENT is untouched, which is the half the docstring above
# protects. `PINNED` is still pinned in both directions and still REDs the
# moment any distance moves, so a patch is still loud; what changed is that
# being loud and owing a bump ROUND are now two different sentences.
#
# ⚠ THE SCOPE IS WIDER THAN THE QUESTION THAT SETTLED IT, and the correction
# belongs next to the decision rather than in a round summary that scrolls away.
# The question named the three zenoh pins at distance 1/1/2. The gate's derived
# population is SEVEN repositories, and FOUR are past zero:
#
#     FreeRTOS/FreeRTOS-Kernel   distance=3   V11.1.0 -> V11.3.1 (submodule)
#     eclipse-zenoh/zenoh-pico   distance=2   1.9.0-10-g3b3ab65c -> 1.10.1
#     eclipse-zenoh/zenoh        distance=1   1.10.0 -> 1.10.1
#     eclipse-zenoh/zenoh-c      distance=1   1.10.0 -> 1.10.1
#
# The policy does not change with scope — it is a rule about how far behind this
# project sits, not a per-repository judgement — so the decision stands as
# given. What the wider scope changes is the SIZE of the round it opens, and
# FreeRTOS-Kernel (which drags the MCU deploy targets) was not in the owner's
# view when they answered. If that is more than was meant, the value moves here
# and the gate follows; it does not move quietly anywhere else.
#
# ⭐ MEASURED, and it cuts the other way from item 711's own cost estimate: the
# zenoh family's move is 1.10.0 -> 1.10.1, a PATCH release. The entry feared a
# "판올림" that moves the grading basis of the whole catalog, which is what a
# minor bump does; a patch is a smaller thing. The re-verification item 579's
# four done-when clauses demand (Layer Z / Ewire / Ewirez / Epico + the config
# axis denominator) still has to RUN, because "a patch cannot break it" is a
# prediction and this workspace grades predictions by running them.
#
# ⛔ THIS DOES NOT CLOSE ITEM 711. The entry splits it: ⒜ keeping the table on
# the observation (paid R2501, and repeated every time upstream releases) and ⒝
# the bump itself. Arming the ratchet is the THRESHOLD half of ⒝ — the half that
# went missing when 578/579/581 all closed — not the bump. 711 closes when the
# bump round has run.
BUMP_THRESHOLD: int | None = 0


def threshold_findings(
    pinned: dict[str, tuple[str, int]], threshold: int | None
) -> list[str]:
    """Repos whose MEASURED distance is past `threshold`, worst first.

    `None` yields nothing: an undeclared threshold cannot be exceeded, and
    saying otherwise would make the gate red for a decision nobody has taken.
    Only `MEASURED` rows can be past it — `NO_RELEASES` and `PIN_NOT_A_RELEASE`
    carry a distance of 0 that means "not applicable", not "up to date".
    """
    if threshold is None:
        return []
    over = [
        (repo, dist)
        for repo, (verdict, dist) in pinned.items()
        if verdict == "MEASURED" and dist > threshold
    ]
    over.sort(key=lambda row: (-row[1], row[0]))
    return [f"{repo} is {dist} release(s) behind" for repo, dist in over]


# ── R2537 (open-debt item 716): the GRADE, which is what opens a round ──────
#
# ## The defect was the UNIT, not the value
#
# `distance` is defined at the top of this file as "how many releases upstream
# has published since the pinned one", so a PATCH and a MINOR are both one step.
# Measured on the shipped code before this was written, and it is the whole
# argument:
#
#     judge("1.10.0", ["1.10.1", ...])  ->  ("MEASURED", 1)
#     judge("1.10.0", ["1.11.0", ...])  ->  ("MEASURED", 1)
#     judge("1.10.0", ["2.0.0",  ...])  ->  ("MEASURED", 1)
#
# All three identical, and NO value of `BUMP_THRESHOLD` separates them: at 0 all
# three open a round, at 1 or more none of them does. The owner's decision of
# 2026-09-10 — "from now on only something big like 1.11.0 opens a bump round" —
# is therefore not expressible as a count, whatever the count is set to. That is
# why this is a second predicate rather than a new number.
#
# ## What must NOT happen, and the shape that avoids it
#
# This file's own docstring forbids the obvious shortcut: `DISTANCE` is "not a
# budget somebody chose; it is the measurement, frozen". Turning the patch axis
# off would revive, on that axis, exactly the "five minors behind and nobody
# knew" that item 578 built this gate to prevent.
#
# So NOTHING about the measurement moves. `PINNED` stays pinned in BOTH
# directions and still REDs the moment upstream publishes anything at all — that
# red says "upstream moved, update the row". What changes is that a second,
# narrower predicate now says "open a bump ROUND", and only it reads the grade.
# Two different demands, which is why they are two predicates and not one
# constant with a new meaning.
#
# ## Every verdict is answered BY NAME, and an unanswered axis is RED
#
# Four of the seven derived repositories are `MEASURED`; the other three are
# `NO_RELEASES` x2 and `PIN_NOT_A_RELEASE` x1, and a semver grade is not a thing
# they have. A predicate that quietly skipped them would be the confident zero
# this workspace keeps paying for, so each verdict resolves to a NAMED answer
# and anything that resolves to none is `ungraded`, which FAILs.
#
# `ungraded` is not a formality. `semver` refuses a tag it cannot read whole —
# `1.9.0-10-g3b3ab65c`, the `git describe` shape a submodule pin takes, parses
# to nothing rather than silently to `1.9.0`. Reading a describe as its base tag
# is how a pin ten commits past a release would grade as being ON it.
_SEMVER = re.compile(r"^[vV]?(\d+)\.(\d+)\.(\d+)$")

# Ordered weakest to strongest; `bump_findings` compares by index, so the order
# IS the policy and there is no second table saying which outranks which.
GRADES = ("patch", "minor", "major")

# The smallest step that opens a bump round (owner, 2026-09-10). A patch is
# still measured, still printed, and does not open one.
BUMP_GRADE: str = "minor"


def semver(tag: str) -> tuple[int, int, int] | None:
    """`(major, minor, patch)`, or `None` for a tag this cannot read WHOLE.

    A partial read is worse than a refusal here: the grade is a comparison, and
    comparing a describe's base tag against a real release would report a pin
    that is ten commits past 1.9.0 as sitting exactly on it.
    """
    m = _SEMVER.match(tag.strip())
    if not m:
        return None
    return (int(m.group(1)), int(m.group(2)), int(m.group(3)))


def step(pin: tuple[int, int, int], tag: tuple[int, int, int]) -> str | None:
    """The grade of the move from `pin` to `tag`, or `None` if it is not ahead.

    `None` covers equal and BACKWARDS, and backwards is deliberately not an
    error here: a releases list can carry an older tag published later (a
    maintenance release on an old line), and that is not a reason to open a
    round on the new one.
    """
    if tag <= pin:
        return None
    if tag[0] != pin[0]:
        return "major"
    if tag[1] != pin[1]:
        return "minor"
    return "patch"


def release_grade(
    verdict: str, pin: str | None, tags: list[str], distance: int
) -> tuple[str, str]:
    """`(grade, why)` for one repository — a NAMED answer for every verdict.

    `grade` is one of `GRADES`, or `none` (nothing ahead of the pin), or
    `n/a` (the verdict has no release line to grade), or `ungraded` (an axis
    this could not answer, which the caller must treat as RED).

    The three non-`MEASURED` answers are derived FROM THE VERDICT, not from a
    list of repository names — so a repository that changes class changes its
    answer with it, and adding a repository cannot silently miss this axis.
    """
    if verdict == "NO_RELEASES":
        return ("n/a", "the releases API answered with an empty list, so there "
                       "is no release line to grade")
    if verdict == "PIN_NOT_A_RELEASE":
        return ("n/a", "the pin is not a point on the release line, so no step "
                       "from it has a grade")
    if verdict == "PIN_NOT_DERIVED":
        return ("ungraded", "no structure here explains this repository's pin, "
                            "so there is nothing to grade FROM")
    if verdict != "MEASURED":
        return ("ungraded", f"verdict {verdict} has no declared answer on this "
                            f"axis; give it one rather than letting it pass")
    if pin is None:
        return ("ungraded", "MEASURED without a pin, which cannot happen and "
                            "must not pass if it does")
    base = semver(pin)
    if base is None:
        return ("ungraded", f"the pin {pin!r} is not a whole semver, so the "
                            f"step from it cannot be graded")
    newer = tags[:distance]
    if not newer:
        return ("none", "nothing has been published since the pin")
    worst: str | None = None
    for tag in newer:
        ahead = semver(tag)
        if ahead is None:
            return ("ungraded", f"upstream tag {tag!r} is not a whole semver, "
                                f"so the step to it cannot be graded")
        moved = step(base, ahead)
        if moved is None:
            continue
        if worst is None or GRADES.index(moved) > GRADES.index(worst):
            worst = moved
    if worst is None:
        return ("none", "every release since the pin is at or behind it")
    return (worst, f"upstream published {newer[0]} since {pin}")


def bump_findings(graded: dict[str, tuple[str, str]], opens_at: str) -> list[str]:
    """Rows that OPEN A BUMP ROUND, strongest first, plus every ungraded row.

    An `ungraded` row is a finding whatever `opens_at` is: this axis exists to
    answer a question, and a repository it could not answer for is the one case
    where staying quiet would be indistinguishable from being satisfied.
    """
    floor = GRADES.index(opens_at)
    out: list[tuple[int, str, str]] = []
    for repo, (grade, why) in graded.items():
        if grade == "ungraded":
            out.append((len(GRADES), repo, f"{repo}: UNGRADED — {why}"))
        elif grade in GRADES and GRADES.index(grade) >= floor:
            out.append((GRADES.index(grade), repo,
                        f"{repo}: {grade} — {why}"))
    out.sort(key=lambda row: (-row[0], row[1]))
    return [line for _, _, line in out]


class Unmeasurable(RuntimeError):
    """The gate could not measure. Never a green."""


def tracked_paths() -> list[str]:
    out = subprocess.run(
        ["git", "-C", str(ROOT), "ls-files"], capture_output=True, text=True, check=True
    )
    return out.stdout.split()


def github_repos(urls: frozenset[str]) -> dict[str, str]:
    """`owner/repo` for every derived GitHub URL, mapped back to the URL.

    A non-GitHub URL is not silently dropped — it is returned by
    [`unroutable_urls`] and reds, because a pin this gate cannot reach is the
    same blind spot as a pin it never looked for.
    """
    repos: dict[str, str] = {}
    for url in urls:
        m = re.match(r"(?:https://|git@)github\.com[:/](?P<owner>[^/]+)/(?P<repo>[^/]+)$", url)
        if not m:
            continue
        repo = m.group("repo")
        if repo.endswith(".git"):
            repo = repo[: -len(".git")]
        repos[f"{m.group('owner')}/{repo}"] = url
    return repos


def unroutable_urls(urls: frozenset[str]) -> list[str]:
    routed = set(github_repos(urls).values())
    return sorted(u for u in urls if u not in routed)


def submodule_pins() -> dict[str, str]:
    """`url -> base tag`, for every submodule whose checkout carries a tag.

    `git describe --tags` yields either the tag itself (`V11.1.0`) or the tag
    plus a distance (`1.9.0-10-g3b3ab65c`); the base tag is what the releases
    API can be asked about, so the suffix is stripped. A submodule with NO tags
    raises nothing here and simply does not appear — the caller decides whether
    that is `NO_RELEASES` (upstream publishes none) or a RED.
    """
    text = (ROOT / ".gitmodules").read_text(errors="replace")
    pins: dict[str, str] = {}
    for block in re.split(r"^\[submodule ", text, flags=re.M)[1:]:
        path = re.search(r"path\s*=\s*(\S+)", block)
        url = re.search(r"url\s*=\s*(\S+)", block)
        if not path or not url:
            continue
        got = subprocess.run(
            ["git", "-C", str(ROOT / path.group(1)), "describe", "--tags"],
            capture_output=True,
            text=True,
        )
        if got.returncode != 0:
            continue
        described = got.stdout.strip()
        base = re.sub(r"-\d+-g[0-9a-f]+$", "", described)
        if base:
            pins[url.group(1).rstrip("/")] = base
    return pins


def script_pins(paths: list[str]) -> dict[str, str]:
    """`url -> pinned ref`, from a `git clone` whose ref is a shell/YAML variable.

    Two shapes, both of which this tree uses:
      * `git clone --branch "$VAR" URL` beside `VAR="${VAR:-VALUE}"`;
      * `git clone URL` followed by `checkout "$VAR"` beside a YAML `VAR: VALUE`.

    ⚠ LINE CONTINUATIONS ARE JOINED FIRST — `build-zenohd.sh` puts the URL on
    the line after `--branch "$V" \\`, and R2217 measured that a line-at-a-time
    scan misses exactly the repository this gate is most about.
    """
    pins: dict[str, str] = {}
    for path in paths:
        if not path.startswith(grc.UPSTREAM_SOURCES) or path == ".gitmodules":
            continue
        try:
            text = (ROOT / path).read_text(errors="replace")
        except OSError:
            continue
        joined = text.replace("\\\n", " ")
        defaults = dict(re.findall(r'(\w+)="\$\{\1:-([^}"]+)\}"', joined))
        defaults.update(dict(re.findall(r"^\s*(\w+):\s*([0-9a-zA-Z._-]+)\s*$", joined, re.M)))
        for clone in re.findall(r"git\s+clone[^\n]*", joined):
            urls = re.findall(r"(?:https://|git@)\S+", clone)
            if not urls:
                continue
            url = urls[0].strip("\"' \\").rstrip("/")
            branch = re.search(r'--branch\s+"?\$\{?(\w+)\}?"?', clone)
            names = [branch.group(1)] if branch else []
            if not names:
                after = joined.split(clone, 1)[1][:400]
                names = re.findall(r'checkout\s+"?\$\{?(\w+)\}?"?', after)
            for name in names:
                if name in defaults:
                    pins[url] = defaults[name]
                    break
    return pins


def releases(repo: str, fetch=None) -> list[str]:
    """Tag names newest-first, from the repository's own releases API.

    Raises [`Unmeasurable`] when the call fails. An EMPTY list is a result, not
    a failure, and the difference is the whole of item 578's condition ③.
    """
    if fetch is not None:
        return fetch(repo)
    got = subprocess.run(
        ["gh", "api", f"repos/{repo}/releases?per_page=100", "--jq",
         ".[] | [.tag_name, .published_at] | @tsv"],
        capture_output=True,
        text=True,
    )
    if got.returncode != 0:
        raise Unmeasurable(f"{repo}: releases API failed: {got.stderr.strip()[:200]}")
    rows = [line.split("\t") for line in got.stdout.strip().splitlines() if line.strip()]
    if any(len(r) != 2 for r in rows):
        raise Unmeasurable(f"{repo}: releases API returned a row this gate cannot read")
    rows.sort(key=lambda r: r[1], reverse=True)
    return [r[0] for r in rows]


def judge(pin: str | None, tags: list[str]) -> tuple[str, int]:
    if not tags:
        return ("NO_RELEASES", 0)
    if pin is None:
        return ("PIN_NOT_DERIVED", 0)
    if pin in tags:
        return ("MEASURED", tags.index(pin))
    return ("PIN_NOT_A_RELEASE", 0)


# ── R2229 (open-debt item 579): the SECOND question, inside the tree ────────
#
# The distance above is about upstream. This is about whether this tree agrees
# with ITSELF about which release it pins, and it was added because moving one
# pin turned out to touch SEVEN places: the script's default, a `rustup
# toolchain install` in the workflow, and five cache keys. A cache key naming
# the old release is the dangerous one — it restores an old binary under a new
# pin, and every lane then grades wz against a router nobody meant to run.
#
# ⚠ THE POPULATION IS STRUCTURAL, NOT A LIST OF PLACES SOMEBODY REMEMBERED.
# Two shapes, both of which are what the workflow actually writes:
#   * `rustup toolchain install <channel>` — must equal the channel the pinned
#     release itself declares in `rust-toolchain.toml`;
#   * `key: <name>-<version>-<os>-…` — the version must be one this tree pins
#     somewhere. Not "the zenoh one": ANY derived pin, so a key for a different
#     upstream is not forced to name zenoh's.
# Anything matching a shape and resolving to neither is RED. There is no
# exemption table, because a version literal that is allowed to mean nothing is
# how the workflow drifted from the script in the first place.
CACHE_KEY = re.compile(r"^\s*key:\s*[a-z0-9-]+?-(\d+\.\d+\.\d+)-[a-z]", re.M)
TOOLCHAIN_INSTALL = re.compile(r"rustup\s+toolchain\s+install\s+(\d+\.\d+\.\d+)")


def release_toolchain(repo: str, ref: str, fetch=None) -> str | None:
    """The channel `ref` of `repo` pins, read from its own `rust-toolchain.toml`."""
    if fetch is not None:
        return fetch(repo, ref)
    got = subprocess.run(
        ["gh", "api", f"repos/{repo}/contents/rust-toolchain.toml?ref={ref}", "--jq", ".content"],
        capture_output=True,
        text=True,
    )
    if got.returncode != 0:
        raise Unmeasurable(f"{repo}@{ref}: cannot read rust-toolchain.toml")
    import base64

    try:
        raw = base64.b64decode(got.stdout).decode("utf-8", "replace")
    except ValueError as exc:
        raise Unmeasurable(f"{repo}@{ref}: rust-toolchain.toml is not base64: {exc}") from None
    m = re.search(r'channel\s*=\s*"([^"]+)"', raw)
    return m.group(1) if m else None


def pin_consistency(workflow: str, pins: dict[str, str], toolchains: set[str]) -> list[str]:
    """Complaints about version literals in the workflow that no pin explains."""
    bad: list[str] = []
    known = set(pins.values())
    for version in set(CACHE_KEY.findall(workflow)):
        if version not in known:
            bad.append(
                f"cache key names {version}, which no pin in this tree derives "
                f"(derived: {sorted(known)})"
            )
    for channel in set(TOOLCHAIN_INSTALL.findall(workflow)):
        if channel not in toolchains:
            bad.append(
                f"the workflow installs toolchain {channel}, which no pinned "
                f"release declares (declared: {sorted(toolchains)})"
            )
    return sorted(bad)


def run(fetch=None, tc_fetch=None) -> int:
    paths = tracked_paths()
    urls = grc.upstream_urls(paths)
    stray = unroutable_urls(urls)
    repos = github_repos(urls)
    pins = {**submodule_pins(), **script_pins(paths)}

    observed: dict[str, tuple[str, int]] = {}
    # R2537 (item 716) — the TAGS are kept, not discarded. `judge` reduces them
    # to an index, and an index cannot say whether the releases it counted were
    # patches or minors; the grade axis below needs the tags themselves.
    graded: dict[str, tuple[str, str]] = {}
    failures: list[str] = []
    for repo, url in sorted(repos.items()):
        try:
            tags = releases(repo, fetch=fetch)
        except Unmeasurable as exc:
            failures.append(str(exc))
            continue
        verdict, distance = judge(pins.get(url), tags)
        observed[repo] = (verdict, distance)
        graded[repo] = release_grade(verdict, pins.get(url), tags, distance)

    # The workflow's own version literals, checked against the pins above. A
    # `rustup toolchain install` is only meaningful next to the release that
    # declares that channel, so the declared set is derived per pinned repo.
    toolchains: set[str] = set()
    for repo, url in sorted(repos.items()):
        ref = pins.get(url)
        if ref is None:
            continue
        try:
            channel = release_toolchain(repo, ref, fetch=tc_fetch)
        except Unmeasurable as exc:
            # A repository with no `rust-toolchain.toml` is the normal case, and
            # `gh` reports that as a failed call. Only a repo the workflow
            # actually installs a channel for can make this matter, and that is
            # what the comparison below decides -- so this is recorded, not
            # fatal.
            del exc
            continue
        if channel:
            toolchains.add(channel)
    workflow_path = ROOT / ".github" / "workflows" / "ci.yml"
    drift: list[str] = []
    try:
        drift = pin_consistency(workflow_path.read_text(errors="replace"), pins, toolchains)
    except OSError as exc:
        failures.append(f"cannot read {workflow_path}: {exc}")

    print(f"upstream-release-distance: {len(repos)} repository(ies) derived from the tree")
    for repo in sorted(observed):
        verdict, distance = observed[repo]
        pinned = PINNED.get(repo)
        mark = "  " if pinned == observed[repo] else "!!"
        print(f"  {mark} {repo:38s} {verdict:18s} distance={distance}")
    print(f"  workflow pin consistency: {len(drift)} complaint(s); "
          f"channels declared by pinned releases: {sorted(toolchains)}")

    bad = False
    if drift:
        bad = True
        print("upstream-release-distance: FAIL — the workflow disagrees with the pins:")
        for line in drift:
            print(f"    {line}")
        print("    A cache key or toolchain naming the old release restores the old")
        print("    binary under the new pin, and every lane then grades wz against a")
        print("    router nobody meant to run.")
    if stray:
        bad = True
        print("upstream-release-distance: FAIL — a derived URL this gate cannot route:")
        for url in stray:
            print(f"    {url}")
        print("    Every upstream must be reachable by the releases API, or the")
        print("    distance question simply goes unasked for it.")
    if failures:
        bad = True
        print("upstream-release-distance: FAIL — could not measure:")
        for line in failures:
            print(f"    {line}")
        print("    A gate that cannot measure must not report green (item 578 ③).")
    for repo in sorted(set(observed) | set(PINNED)):
        want, got = PINNED.get(repo), observed.get(repo)
        if repo not in observed and repo not in failures:
            if repo not in {r for r in repos}:
                bad = True
                print(f"upstream-release-distance: FAIL — pinned row {repo} names a")
                print("    repository the tree no longer fetches; drop the row.")
            continue
        if want is None:
            bad = True
            print(f"upstream-release-distance: FAIL — {repo} is fetched by this tree")
            print(f"    and carries no pinned row. Observed {got[0]} distance={got[1]}.")
        elif want != got:
            bad = True
            print(f"upstream-release-distance: FAIL — {repo}: pinned {want[0]}"
                  f" distance={want[1]}, observed {got[0]} distance={got[1]}.")
            if got[0] == "MEASURED" and want[0] == "MEASURED" and got[1] > want[1]:
                print("    Upstream published a release. Moving THIS ROW is the")
                print("    maintenance; bumping the real pin is a round of its own,")
                print("    and open-debt item 711 owes it.")
                # R2521 — this used to name item 579, which is CLOSED (R2236),
                # as are 578 and 581 above it. The sentence was true when it was
                # written and became a pointer at nobody, which is precisely what
                # item 711 was filed to hold. A gate that names a closed owner
                # tells a reader to go nowhere.
    if any(v[0] == "PIN_NOT_DERIVED" for v in observed.values()):
        print("    PIN_NOT_DERIVED means the tree fetches a repository whose pin no")
        print("    structure here explains. Add the shape, never an exception.")
    # R2521 (open-debt item 711) — the THRESHOLD, reported on every run whether
    # or not it is declared. An undeclared one is the state item 711 exists for,
    # and printing it is what keeps the question from disappearing again the way
    # it did when 578/579/581 closed.
    if BUMP_THRESHOLD is None:
        worst = max(
            (d for v, d in PINNED.values() if v == "MEASURED"), default=0
        )
        print("upstream-release-distance: NO BUMP THRESHOLD IS DECLARED — open-debt")
        print("    item 711 owes that decision, and it is the owner's: track every")
        print("    release, open a round at N behind, or bump only when a feature")
        print(f"    needs it. Furthest behind right now: {worst} release(s).")
        print("    This is a REPORT, not a failure: a gate must not red for a")
        print("    decision nobody has taken. Set `BUMP_THRESHOLD` and the check")
        print("    below starts enforcing it.")
    else:
        over = threshold_findings(PINNED, BUMP_THRESHOLD)
        if over:
            # R2537 (item 716) — REPORTED, not failed, and the distinction is
            # the owner's decision of 2026-09-10. Drift past the threshold is
            # still measured and still named here; what it no longer does on its
            # own is open a bump ROUND. The grade axis below decides that.
            #
            # ⛔ This is NOT the measurement being turned off. `PINNED` above is
            # pinned in both directions and REDs the moment any of these numbers
            # moves, so "five minors behind and nobody knew" still cannot happen
            # — it reds as a stale ROW rather than as an owed round.
            print("upstream-release-distance: drift past the declared threshold of")
            print(f"    {BUMP_THRESHOLD} release(s) — measured, and not on its own")
            print("    a reason to open a round:")
            for line in over:
                print(f"    {line}")
        else:
            print(
                f"upstream-release-distance: threshold {BUMP_THRESHOLD} release(s),"
                " and nothing is past it."
            )
    # ── R2537 (open-debt item 716): the GRADE axis, which opens rounds ──────
    #
    # Printed for EVERY derived repository, including the ones that have no
    # grade, because an axis that reports only its findings cannot be told from
    # one that examined nobody. The population is asserted against the row count
    # for the same reason: a zero here would otherwise read as "all clear".
    print(f"  bump grade: opens at `{BUMP_GRADE}` or above; "
          f"{len(graded)} repository(ies) answered")
    for repo in sorted(graded):
        grade, why = graded[repo]
        print(f"    {repo:38s} {grade:9s} {why}")
    if observed and not graded:
        bad = True
        print("upstream-release-distance: FAIL — repositories were measured and NONE")
        print("    was graded, so this axis examined nobody. A population of zero")
        print("    must not report all clear.")
    opens = bump_findings(graded, BUMP_GRADE)
    if opens:
        bad = True
        print("upstream-release-distance: FAIL — a bump ROUND is owed; upstream has")
        print(f"    published a `{BUMP_GRADE}`-or-greater step since these pins:")
        for line in opens:
            print(f"    {line}")
        print("    The bump is a ROUND (Layer Z / Ewire re-verification comes")
        print("    with it); open-debt item 579's four done-when clauses are the")
        print("    template, and item 711 holds the position now.")
    else:
        print(f"upstream-release-distance: no repository is a `{BUMP_GRADE}` or"
              " greater step behind, so no bump round is owed.")
    print("upstream-release-distance:", "FAIL" if bad else "OK")
    return 1 if bad else 0


FIXTURE_TAGS = {
    "a/one": ["v3", "v2", "v1"],
    "a/two": [],
}


def selftest() -> int:
    """Drive [`judge`] and the measurement/observation split against fixtures.

    ⚠ The fixtures are shapes THE OLD ANSWER WOULD HAVE SWALLOWED: an empty
    release list (which a gate that treated "no data" as "nothing to do" would
    call green) and a pin absent from a non-empty list (which a gate comparing
    only the newest tag would call up to date).
    """
    cases = [
        (("v1", FIXTURE_TAGS["a/one"]), ("MEASURED", 2)),
        (("v3", FIXTURE_TAGS["a/one"]), ("MEASURED", 0)),
        (("v9", FIXTURE_TAGS["a/one"]), ("PIN_NOT_A_RELEASE", 0)),
        ((None, FIXTURE_TAGS["a/one"]), ("PIN_NOT_DERIVED", 0)),
        (("v1", FIXTURE_TAGS["a/two"]), ("NO_RELEASES", 0)),
        ((None, FIXTURE_TAGS["a/two"]), ("NO_RELEASES", 0)),
    ]
    bad = 0
    for (pin, tags), want in cases:
        got = judge(pin, tags)
        if got != want:
            bad += 1
            print(f"  selftest FAIL: judge({pin!r}, {tags!r}) = {got}, want {want}")

    # R2521 (open-debt item 711) — THE THRESHOLD IS GRADED, not merely declared.
    #
    # A constant nothing checks is prose in a constant's clothing, which is the
    # failure this whole mechanism exists to end. So the four answers are driven:
    # undeclared yields nothing (the gate must not red for an undecided policy),
    # a distance past the line is reported WORST FIRST, a distance exactly on it
    # is not past it, and the not-applicable verdicts never count as "behind" —
    # `NO_RELEASES` carries a 0 that means the question does not apply, and a
    # threshold reading it as "up to date" would be the confident zero this
    # workspace keeps paying for.
    table = {
        "a/behind": ("MEASURED", 5),
        "a/edge": ("MEASURED", 2),
        "a/close": ("MEASURED", 1),
        # ⚠ A NON-ZERO distance on a NOT-APPLICABLE verdict, which the live table
        # cannot produce and which is exactly why it is here. MEASURED: with
        # every non-measured row carrying 0, `dist > threshold` is false for them
        # whatever the filter does, so the first draft of these cases stayed
        # GREEN when the `verdict == "MEASURED"` guard was deleted — a control
        # that graded nothing. The filter is what keeps "the question does not
        # apply" from being read as "behind", and this row is what makes that
        # claim falsifiable.
        "a/none": ("NO_RELEASES", 9),
        "a/tagless": ("PIN_NOT_A_RELEASE", 4),
    }
    threshold_cases = [
        (None, []),
        (2, ["a/behind is 5 release(s) behind"]),
        (0, [
            "a/behind is 5 release(s) behind",
            "a/edge is 2 release(s) behind",
            "a/close is 1 release(s) behind",
        ]),
        (5, []),
    ]
    for threshold, want_lines in threshold_cases:
        got_lines = threshold_findings(table, threshold)
        if got_lines != want_lines:
            bad += 1
            print(
                f"  selftest FAIL: threshold_findings(threshold={threshold!r})"
                f" = {got_lines}, want {want_lines}"
            )

    # ── R2537 (open-debt item 716): THE BOUNDARY, GRADED FROM BOTH SIDES ────
    #
    # The item's first done-when, in as many words: "1.11.0 opens and 1.10.2
    # does not", BOTH arms, because one arm cannot grade a boundary. A suite
    # holding only the opening arm passes on a predicate that opens on
    # everything; one holding only the closing arm passes on a predicate that
    # opens on nothing. So both are here and both are named.
    #
    # ⚠ The population on the live tree is currently ZERO — every MEASURED row
    # sits at distance 0 since R2529, so `newer` is empty for all four and the
    # grade is `none` everywhere. That is exactly the state in which a real run
    # cannot exercise this, which is why the arms below are fixtures rather than
    # a reading of `PINNED`: an arm that only runs when upstream happens to have
    # released is an arm nobody is grading today.
    grade_cases = [
        # (label, verdict, pin, tags, distance) -> expected grade
        ("a PATCH does not open a round",
         ("MEASURED", "1.10.0", ["1.10.2", "1.10.1", "1.10.0"], 2), "patch"),
        ("a MINOR opens a round",
         ("MEASURED", "1.10.0", ["1.11.0", "1.10.0"], 1), "minor"),
        ("a MAJOR opens a round",
         ("MEASURED", "1.10.0", ["2.0.0", "1.10.0"], 1), "major"),
        # The strongest step in the window wins, not the newest one: upstream
        # publishing 1.11.0 and then a 1.11.1 must still open the round.
        ("the strongest step in the window is the grade",
         ("MEASURED", "1.10.0", ["1.11.1", "1.11.0", "1.10.0"], 2), "minor"),
        ("nothing published since the pin has no grade",
         ("MEASURED", "1.10.0", ["1.10.0", "1.9.0"], 0), "none"),
        # The three NOT-MEASURED verdicts, each answered BY NAME. The item's
        # third done-when: an axis with no answer must red, so these must come
        # back `n/a` rather than falling through to a default.
        #
        # ⚠ THE GRADE ALONE IS NOT ENOUGH TO GRADE THIS, and a damage probe is
        # what said so. Deleting the `PIN_NOT_DERIVED` branch outright left the
        # suite GREEN, because the catch-all below it returns `ungraded` too —
        # the verdict was right and the NAMING, which is what the item asks for,
        # was gone. So each of these also pins a phrase only its own branch
        # produces. The catch-all stays as a backstop; what it may not do is
        # stand in for an answer silently.
        ("NO_RELEASES is answered, not skipped",
         ("NO_RELEASES", "1.0.0", [], 0), "n/a", "empty list"),
        ("PIN_NOT_A_RELEASE is answered, not skipped",
         ("PIN_NOT_A_RELEASE", "deadbeef", ["1.0.0"], 0), "n/a",
         "not a point on the release line"),
        ("PIN_NOT_DERIVED is UNGRADED, which reds",
         ("PIN_NOT_DERIVED", None, ["1.0.0"], 0), "ungraded",
         "nothing to grade FROM"),
        # A `git describe` pin must NOT be read as its base tag. If it were,
        # a pin ten commits past 1.9.0 would grade as sitting exactly on it.
        ("a describe-shaped pin is ungraded, never its base tag",
         ("MEASURED", "1.9.0-10-g3b3ab65c", ["1.11.0", "1.9.0-10-g3b3ab65c"], 1),
         "ungraded"),
        ("an unreadable upstream tag is ungraded",
         ("MEASURED", "1.10.0", ["release-candidate", "1.10.0"], 1), "ungraded"),
        # The `V` prefix is real: FreeRTOS-Kernel tags are `V11.3.1`.
        ("a V-prefixed tag family grades like any other",
         ("MEASURED", "V11.1.0", ["V11.3.1", "V11.1.0"], 1), "minor"),
    ]
    for case in grade_cases:
        label, (verdict, pin, tags, distance), want_grade = case[:3]
        want_why = case[3] if len(case) > 3 else None
        got_grade, why = release_grade(verdict, pin, tags, distance)
        if got_grade != want_grade:
            bad += 1
            print(f"  selftest FAIL: {label} — grade {got_grade!r}, want {want_grade!r}")
        if not why:
            bad += 1
            print(f"  selftest FAIL: {label} — the answer carries no reason")
        if want_why is not None and want_why not in why:
            bad += 1
            print(f"  selftest FAIL: {label} — the reason is {why!r}, which does not"
                  f" name this verdict's own answer ({want_why!r}); a catch-all"
                  f" standing in for a named branch is what this pins")

    # And the PREDICATE over those grades, which is where the boundary actually
    # lives. Driven as a table so the two arms sit next to each other and a
    # change that collapses them fails visibly.
    boundary = {
        "a/patch": ("patch", "1.10.2 since 1.10.0"),
        "a/minor": ("minor", "1.11.0 since 1.10.0"),
        "a/major": ("major", "2.0.0 since 1.10.0"),
        "a/none": ("none", "nothing since the pin"),
        "a/na": ("n/a", "no release line"),
        "a/broken": ("ungraded", "a tag this cannot read"),
    }
    opens = bump_findings(boundary, "minor")
    opened = {line.split(":")[0] for line in opens}
    for repo, want_open in (
        ("a/minor", True),   # the item's arm ⑴: 1.11.0 OPENS
        ("a/patch", False),  # the item's arm ⑵: 1.10.2 does NOT
        ("a/major", True),
        ("a/none", False),
        ("a/na", False),
        ("a/broken", True),  # an unanswered axis reds whatever the floor is
    ):
        if (repo in opened) != want_open:
            bad += 1
            print(f"  selftest FAIL: bump_findings at `minor` — {repo} "
                  f"{'did not open' if want_open else 'opened'} a round")
    # Strongest first, so a reader sees the biggest step at the top.
    if opens and not opens[0].startswith(("a/broken", "a/major")):
        bad += 1
        print(f"  selftest FAIL: bump_findings did not sort strongest first: {opens}")
    # The FLOOR is what the owner's decision sets, so moving it must move the
    # verdict — otherwise the constant is decoration.
    if {line.split(":")[0] for line in bump_findings(boundary, "patch")} < opened:
        bad += 1
        print("  selftest FAIL: lowering the floor to `patch` did not widen the set")
    if "a/minor" in {line.split(":")[0] for line in bump_findings(boundary, "major")}:
        bad += 1
        print("  selftest FAIL: raising the floor to `major` still opened on a minor")

    # An API failure must be an exception, never an empty list that reads as
    # NO_RELEASES. This is the one distinction condition ③ is made of.
    def explode(_repo: str) -> list[str]:
        raise Unmeasurable("fixture: the API is down")

    try:
        releases("a/one", fetch=explode)
        bad += 1
        print("  selftest FAIL: a failing fetch did not raise Unmeasurable")
    except Unmeasurable:
        pass

    # ── THE TWO ARMS WHOSE POPULATION IS ZERO ON THIS TREE ────────────────
    #
    # Every URL here is currently a GitHub one and every pin currently derives,
    # so `unroutable_urls` and `PIN_NOT_DERIVED` never fire in a real run — and
    # an arm that never fires is indistinguishable from one that cannot. They
    # are driven on fixtures instead, WITH the narrowing half: a GitHub URL must
    # NOT be reported stray, or the arm would red on everything and mean nothing.
    fixture_urls = frozenset(
        {
            "https://github.com/a/b",
            "https://github.com/a/c.git",
            "git@github.com:a/d",
            "https://gitlab.com/e/f",
            "git@bitbucket.org:g/h",
        }
    )
    routed = github_repos(fixture_urls)
    if sorted(routed) != ["a/b", "a/c", "a/d"]:
        bad += 1
        print(f"  selftest FAIL: github_repos routed {sorted(routed)}")
    stray = unroutable_urls(fixture_urls)
    if stray != ["git@bitbucket.org:g/h", "https://gitlab.com/e/f"]:
        bad += 1
        print(f"  selftest FAIL: unroutable_urls reported {stray}")

    # ── R2229: the workflow-consistency arm, with its narrowing control ────
    #
    # On a tree that has just been moved, this arm reports zero — and a zero
    # from a check that cannot fire reads the same as a tree that agrees with
    # itself. The control is the FIRST case: a workflow matching the pins must
    # produce NO complaint, or the arm would red on everything and mean nothing.
    fx_pins = {"https://github.com/eclipse-zenoh/zenoh": "1.10.0"}
    fx_tcs = {"1.97.1"}
    agreeing = (
        "          key: zenohd-1.10.0-ubuntu-22.04-x\n"
        "          run: rustup toolchain install 1.97.1 --profile minimal\n"
    )
    stale_key = agreeing.replace("zenohd-1.10.0", "zenohd-1.5.0")
    stale_tc = agreeing.replace("install 1.97.1", "install 1.85.0")
    for label, wf, want_complaints in (
        ("a workflow that agrees", agreeing, 0),
        ("a cache key at the old release", stale_key, 1),
        ("a toolchain at the old channel", stale_tc, 1),
        ("both stale", stale_key.replace("install 1.97.1", "install 1.85.0"), 2),
    ):
        got = pin_consistency(wf, fx_pins, fx_tcs)
        if len(got) != want_complaints:
            bad += 1
            print(f"  selftest FAIL: {label} gave {len(got)} complaint(s), want {want_complaints}")

    if bad:
        print(f"upstream-release-distance selftest: FAIL ({bad})")
        return 1
    # R2521 — the threshold cases are NAMED in the total, not folded into it. A
    # summary that says "6 cases" while running ten cannot tell a reader which
    # arms ran, and this workspace's standing rule is that a gate prints the
    # population it read.
    print(
        f"upstream-release-distance selftest: OK ({len(cases)} classifier case(s), "
        f"{len(threshold_cases)} threshold case(s), {len(grade_cases)} grade "
        f"case(s) plus the boundary from both sides, the measure/observe split, "
        f"the two zero-population arms, and the workflow-consistency arm with "
        f"its control)"
    )
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--selftest", action="store_true", help="drive the classifier on fixtures")
    args = ap.parse_args()
    if args.selftest:
        return selftest()
    return run()


if __name__ == "__main__":
    sys.exit(main())
