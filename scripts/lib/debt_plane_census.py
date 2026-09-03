#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
# SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

r"""R311y919 (no register item) — how many ANALYZER-PLANE debts are still open,
as a number a command produces rather than one a session remembers.

It closes no register item on purpose: it is the INSTRUMENT a repayment loop
measures itself with, not the repayment of anything. The debt it does surface is
its own -- item 454, that this input lives outside the repository.

## Why this exists

The analyzer's open debts live in an agent-memory register outside this
repository, and until this round the only way to answer "how many are left" was
to read it and judge. That was done twice in one session and gave two different
answers -- 25 by a keyword sweep and 73 by reading all 380 open items -- because
the register is written in Korean and names CONCEPTS ("the interest plane", "the
verdict", "the report") that share no token with any crate name. Open-debt item
190 had already recorded that a keyword sweep is structurally a FLOOR; this is
its third demonstration.

So the judgement is made once, written into the register as a ROSTER, and this
script is what reads it back. A repayment loop needs a completion condition it
cannot talk itself out of, and a number one command prints is that.

## What it checks, and why each direction matters

1. Every rostered number EXISTS in the register. A roster naming an item that
   was renumbered away is a roster that has stopped pointing at anything.
2. Every rostered number is OPEN. A closed item still on the roster inflates the
   remaining count, which is the direction that makes a loop run forever.
3. No open item's number exceeds `swept_through`. This is the ratchet: a debt
   filed after the sweep arrives UNJUDGED, and without this the roster goes
   quietly stale the moment the next round files a residue -- which every round
   in this series does.
4. The roster's two classes are disjoint, and the owner-decision class is
   reported separately rather than folded into the target. An item whose own
   text says "nobody has decided whether to" is not work a loop can finish, and
   counting it would make the completion condition unreachable.

## The PRIORITY queue (R2101) -- a claim the next round cannot walk past

The roster answers "how many are left". It does NOT answer "which one next",
and until R2101 nothing did: the loop picked, and a pick is a judgement made
once and forgotten. When the owner names an item to take FIRST -- as happened
on 2026-08-25 for item 524 -- that instruction had nowhere to live except
prose, and prose is what this whole file exists to replace.

So the roster block carries an ORDERED `priority` line, and its head is the
claim on the next round. Three properties make it a claim rather than a note:

* It is printed FIRST, above the count. A reader who runs this sees what to
  take before seeing how much is left.
* A standing claim EXITS 3. Not 0, because a queue with work in it is not a
  clean state; not 1, because the register is not broken. Two verdicts, two
  codes, so "you owe a pick" can never be misread as "the roster is damaged".
* The head STAYS the head until the item is closed. There is no way to
  discharge a claim except by closing the item it names, which is the ratchet
  that makes "pick it first" enforceable rather than advisory.

`WZ_DEBT_PRIORITY_ACK=<n>` is how a round declares it is taking the claim,
and it is checked against the HEAD specifically. Acking a different open item
FAILS and names the head -- otherwise the ack would be a way to acknowledge
the queue while working on something else, which is exactly the move it
exists to prevent.

Priority is a SEPARATE AXIS from the roster and deliberately not a subset of
it: three of the four items filed on 2026-08-25 are analyzer-plane `밖`
(a missing SONAME, an undeclared apt dependency, an argv default) and are
still work the owner can put at the front. What priority DOES require is that
the item was judged (`<= swept_through`) and is not held for an owner
decision -- a queue cannot order a round to take something nobody decided.

## The RANKING and LINEAGE axes (R2302, open-debt item 639)

The round discipline names four more axes and, until this round, NOTHING read
any of them -- they were prose, which is the failure the operator's standing
rule (10) names ("a reason written in prose is one nobody measures"). MEASURED
before the change: `grep -n 'critical\|ordinary\|unranked\|@from\|deferred'`
over this file returned ZERO lines, while the register already carried the
annotations on fifteen items. Declared, never judged.

* `critical` / `ordinary` -- which open item to take first. Rule (11) says to
  take from the critical line when it is not empty; there was no such line.
* `@from: <n>` / `@from: none` -- whether the item was CREATED by the round
  paying item `<n>`, or merely ENCOUNTERED while paying something. Rule (13)
  turns on that distinction, because charging an encountered debt to the round
  that tripped over it lengthens every chain and sinks old debt.
* chain depth -- DERIVED here from `@from:`, never read from prose. Item 637
  wrote "chain depth 2: 631 -> 634 -> 637" by hand; a hand-written depth is a
  second copy of a derivable fact, so this reader derives it and judges the
  hand-written one against the derivation rather than trusting it.
* `deferred` -- an item whose chain is deeper than `reaim_cap` is registered
  but NOT paid this round (rule 14). Declared deferral and derived deferral
  must agree in BOTH directions.

### Where an annotation lives, and why that is structural

An item's HEADER is its bold title span: from the item line to the line where
the `**` balance closes, counting only `**` OUTSIDE inline-code spans. That
last clause is not decoration -- item 435's title contains a literal
`char **` inside backticks, and a balance that counted it ran the header 15
lines into the body. MEASURED with the code-span rule: 662 of 662 item lines
close cleanly, 0 runaway.

The annotation RUN is what follows the first `@from:` that carries a VALUE.
That is also structural rather than tidy: item 639's own title lists the four
axis names, including a backticked `` `deferred` `` and a valueless
`` `@from:` ``, and any reader that scanned the whole header would have marked
the item that FILED this debt as deferred. Anchoring on `@from: <value>` and
reading only what follows excludes the axis-name prose by construction.

### `ranked_from`, and why the frontier is DECLARED but pinned

Hundreds of open items predate the discipline. Requiring a ranking on all of
them would make this gate red forever, and exempting them by a hand-written
list would be the escape hatch rule (6) forbids. So the roster DECLARES a
frontier and this reader pins it from both sides:

* every item at or above it must carry `@from:`, and every OPEN one must carry
  a ranking -- unclassified is RED, never a pass;
* no item BELOW it may carry an annotation -- which is what stops a round from
  raising the frontier to dodge. Raising it leaves annotated items underneath;
  stripping those annotations to fix that pushes the unranked count above its
  baseline. The two rules interlock, so the frontier has exactly one value the
  data admits and moving it means doing the work.

### The `unranked` ratchet, and whether 0 is reachable

Rule (12) says the unranked count only falls. Rule (5) says to ask whether a
completion predicate has any path to 0 at all before trusting it, so: the
population is the OPEN items below the frontier, 314 of them when this was
written. It falls when one of them closes and when one of them is annotated
(which pulls the frontier down to it), and nothing but filing an item below
the frontier -- impossible, numbers only grow -- can raise it. The path to 0
exists and is the ordinary course of the repayment loop.

The baseline is DECLARED in the roster, not derived, for R2301's reason: a
baseline derived from the population it measures follows that population and
can never fail. It is judged in BOTH directions, the doc-link-budget idiom
this workspace already uses -- above it means an item arrived unranked, below
it means lower the number in the same commit.

### Why the critical line does NOT change the exit code

The PRIORITY queue exits 3 because it is a claim on ONE round. A ranking is an
ordering over the whole open set, so making `critical` non-empty exit non-zero
would mean this census can never report clean while any critical item is open
-- a value with no path to 0, which is the trap rule (5) exists to catch. The
critical and deferred lines are printed, above the count, where rules (11) and
(14) say to read them. What DOES exit 1 is an axis nobody classified.

## What it deliberately does NOT do

It does not judge. Nothing here decides whether an item is analyzer-plane -- the
roster is a human judgement recorded in the register, and a script that
re-derived it from keywords would reintroduce exactly the floor this file
exists to replace.

It also does not decide a RANKING. `critical` and `ordinary` are the operator's
words in the register; this file reads them, counts what carries neither, and
refuses to guess.

## Why it is NOT wired into a CI layer

Its input is machine-local: the register lives in the agent-memory directory,
which no clone and no CI runner has. A gate whose input is absent must FAIL
rather than skip -- "a population of zero is green" is this workspace's most
expensive recurring defect -- so wiring it into a hosted layer would make every
CI run red. It therefore exits 2 (not 0) when the register is unreadable, and
lives as a LOCAL tool until the roster moves into the store, which is where
`debt-carry-N48` already says debt items belong. That move is open-debt item
454.
"""

from __future__ import annotations

import os
import pathlib
import re
import sys
import typing

DEFAULT_REGISTER = (
    pathlib.Path.home()
    / ".claude"
    / "projects"
    / "-home-coin-watching-zenoh"
    / "memory"
    / "project_open_debt_unregistered.md"
)

BEGIN = "<!-- ANALYZER-ROSTER-BEGIN -->"
END = "<!-- ANALYZER-ROSTER-END -->"

# The register numbers items in THREE shapes and a reader that knows only one
# reports dozens of items as absent. Both forms, always -- see the register's
# own "이 파일을 기계로 셀 때" section, and open-debt item 295.
ITEM_FORMS = (
    re.compile(r"^-\s*\*\*\s*(?:[^\w\s]+\s*)*(\d{1,3})\.\s", re.M),
    re.compile(r"^(\d{1,3})\.\s", re.M),
)


def register_path() -> pathlib.Path:
    """The register, overridable so a damage probe can point at a fixture."""
    override = os.environ.get("WZ_DEBT_REGISTER")
    return pathlib.Path(override) if override else DEFAULT_REGISTER


def item_lines(text: str) -> tuple[dict[int, str], dict[int, str]]:
    """`(live titles, archived titles)`, split by whether a fold encloses them.

    R2250b (open-debt item 603). The register's own closing convention writes
    the CLOSED verdict ABOVE and folds the item's original wording BELOW, into
    `<details>`. Reading the file as flat text and letting the last match win
    therefore returns the ARCHIVED title, which carries no verdict word because
    it was written before there was one -- so an item closed by the convention
    this repository actually uses reads back as open. MEASURED on the register
    at the time this was written: seven of them, `558 559 580 582 595 598 600`,
    two of which sit on the analyzer roster.

    ⚠ The population GROWS every time a round closes an item properly, which is
    why the defect survived: closing 600 by the convention took the count from
    six to seven. It also escaped the guard one level up -- "item N is CLOSED
    and still on the roster" can never fire for an item whose title is read as
    open.

    The depth scan is the one `unclosed_folds` already does, deliberately reused
    rather than reimplemented: one balance, no HTML parser, for the reason
    stated there.
    """
    live: dict[int, str] = {}
    archived: dict[int, str] = {}
    depth = 0
    for line in text.split("\n"):
        if "<details>" in line:
            depth += 1
        for form in ITEM_FORMS:
            m = form.match(line)
            if m:
                (archived if depth > 0 else live)[int(m.group(1))] = line
                break
        if "</details>" in line:
            depth = max(0, depth - 1)
    return live, archived


def items(text: str) -> dict[int, str]:
    """Every item's number mapped to its LIVE title line.

    An item that exists only in archived form keeps that title, so a number is
    never silently absent; what an archive must not do is OVERWRITE a live
    verdict, which is what `item_lines` separates.
    """
    live, archived = item_lines(text)
    return {**archived, **live}


#: The words a title uses to say an item is discharged. DERIVED from the
#: register, not chosen: `CLOSED` (277 titles), `REFUTED` (3, where the round
#: that filed the item disproved it) and `DUPLICATE` (1, item 213, kept under
#: its number on purpose). `PAID` is NOT here although the operator's counting
#: recipe names it -- no title uses it, and `verdict_findings` refuses a word
#: this register does not carry, because a vocabulary entry that can never
#: match is an exemption nothing judges.
VERDICTS = ("CLOSED", "REFUTED", "DUPLICATE")

#: The mark a discharged title carries beside its word. Two of the three words
#: are always preceded by it; `DUPLICATE` is not, which is why the word list
#: exists at all rather than just this.
DISCHARGED = "✅"


def is_open(title: str) -> bool:
    if DISCHARGED in title:
        return False
    return not any(word in title for word in VERDICTS)


def verdict_findings(live: dict[int, str]) -> list[str]:
    """The vocabulary, judged in BOTH directions against the register.

    Forward: a title marked discharged whose verdict word this reader does not
    know is a FAIL and not an open item -- unclassified is red, or the mark
    becomes a way to close an item the counter keeps counting.

    Backward: a word in `VERDICTS` that no live title uses is a FAIL too. That
    is the arm that keeps this list from growing into a table of possibilities
    nobody has to justify, and it is the one that removed `PAID`.
    """
    out: list[str] = []
    for number, title in sorted(live.items()):
        if DISCHARGED in title and not any(w in title for w in VERDICTS):
            out.append(
                f"item {number} is marked {DISCHARGED} and its title carries no "
                f"verdict this reader knows ({', '.join(VERDICTS)}). An "
                f"unclassified verdict must be a FAIL: read as open it keeps "
                f"being counted, read as closed by the mark alone the word list "
                f"stops meaning anything"
            )
    for word in VERDICTS:
        if not any(word in title for title in live.values()):
            out.append(
                f"`{word}` is in VERDICTS and no live title uses it. A word that "
                f"cannot match is an entry nothing judges -- drop it in the "
                f"commit that stops using it"
            )
    return out


#: The lineage token, and it REQUIRES a value. A bare `` `@from:` `` occurs in
#: item 639's own title, which lists the axis names -- see the module doc.
FROM_RE = re.compile(r"@from:\s*(none|\d{1,3})")

#: The two ranking words. A header carrying BOTH is a FAIL, not a coin toss.
RANK_WORDS = ("critical", "ordinary")

#: The deferral marker and the hand-written depth beside it. The depth is
#: OPTIONAL -- what is not optional is that it agree with the derivation.
DEFER_RE = re.compile(r"\bdeferred\b")
DECLARED_DEPTH_RE = re.compile(r"(?:사슬 깊이|chain depth)\s*(\d+)")


def outside_code(blob: str) -> str:
    """`blob` with every inline-code span removed.

    An UNCLOSED backtick swallows the rest, which is exactly what a header cut
    mid-span looks like and is why this is a split rather than a regex over
    matched pairs. Markdown agrees: `**` inside backticks is literal text.
    """
    parts = blob.split("`")
    return "".join(parts[i] for i in range(0, len(parts), 2))


def item_headers(text: str) -> tuple[dict[int, str], dict[int, str], list[int]]:
    """`(live headers, archived headers, unbalanced item numbers)`.

    A header is the item's bold title span, joined into one string. It ends at
    the line where the `**` balance outside inline code first closes; a blank
    line or the next item line stops it too, and reaching either without a
    close is reported rather than swallowed -- a runaway header would read an
    item's BODY as its annotation run.
    """
    lines = text.split("\n")
    starts: set[int] = set()
    marks: list[tuple[int, int, int]] = []  # (line index, number, fold depth)
    depth = 0
    for i, line in enumerate(lines):
        if "<details>" in line:
            depth += 1
        for form in ITEM_FORMS:
            m = form.match(line)
            if m:
                starts.add(i)
                marks.append((i, int(m.group(1)), depth))
                break
        if "</details>" in line:
            depth = max(0, depth - 1)

    live: dict[int, str] = {}
    archived: dict[int, str] = {}
    unbalanced: list[int] = []
    for i, number, fold in marks:
        got: list[str] = []
        closed = False
        for j in range(i, len(lines)):
            if j > i and (j in starts or not lines[j].strip()):
                break
            got.append(lines[j].strip())
            if outside_code(" ".join(got)).count("**") >= 2 and (
                outside_code(" ".join(got)).count("**") % 2 == 0
            ):
                closed = True
                break
        if not closed:
            unbalanced.append(number)
        (archived if fold > 0 else live)[number] = " ".join(got)
    return live, archived, sorted(set(unbalanced))


class Axis(typing.NamedTuple):
    """One item's four axis values, read from its annotation run."""

    parent: str | None  # "none", a number as text, or None when unannotated
    ranks: tuple[str, ...]  # the ranking words present; not exactly one is a FAIL
    deferred: bool
    declared_depth: int | None


def axes(headers: dict[int, str]) -> dict[int, Axis]:
    """Every item's axis values, read from the run AFTER `@from: <value>`."""
    out: dict[int, Axis] = {}
    for number, header in headers.items():
        m = FROM_RE.search(header)
        if not m:
            out[number] = Axis(None, (), False, None)
            continue
        run = header[m.end() :]
        ranks = tuple(w for w in RANK_WORDS if re.search(rf"\b{w}\b", run))
        depth_m = DECLARED_DEPTH_RE.search(run)
        out[number] = Axis(
            m.group(1),
            ranks,
            bool(DEFER_RE.search(run)),
            int(depth_m.group(1)) if depth_m else None,
        )
    return out


def chain_depth(
    number: int, table: dict[int, Axis], frontier: int
) -> tuple[int | None, str | None]:
    """`(depth, error)` -- derived from `@from:`, never read from prose.

    A parent BELOW the frontier is a ROOT, by the frontier's definition: the
    discipline starts there and an older ancestor was never asked for lineage.
    A parent that does not exist, or a cycle, is an error rather than a depth,
    because a chain that does not terminate cannot answer rule (14).
    """
    depth = 0
    seen: list[int] = [number]
    cur = number
    while True:
        axis = table.get(cur)
        if axis is None or axis.parent is None or axis.parent == "none":
            return depth, None
        parent = int(axis.parent)
        if parent < frontier:
            return depth, None
        if parent not in table:
            return None, (
                f"item {cur} declares `@from: {parent}` and the register has no "
                f"such item -- a lineage that points at nothing cannot be walked"
            )
        if parent in seen:
            chain = " -> ".join(str(n) for n in seen + [parent])
            return None, f"the `@from:` chain {chain} is a CYCLE"
        seen.append(parent)
        cur = parent
        depth += 1


class Roster(typing.NamedTuple):
    """What the roster block declares, as four independent facts.

    A tuple rather than four returns, because R2101 added the fourth and a
    positional 4-tuple is how a caller silently reads `priority` as `swept`.
    """

    target: set[int]
    owner: set[int]
    swept: int
    priority: list[int]
    ranked_from: int
    unranked_baseline: int
    reaim_cap: int


#: The roster keys that carry a single integer. Named in ONE place because a
#: key parsed but not required, or required but not parsed, is how a declared
#: baseline quietly stops being read.
SCALAR_KEYS = ("swept_through", "ranked_from", "unranked_baseline", "reaim_cap")


def roster(text: str) -> Roster:
    """The rostered target set, the owner-decision set, the ORDERED priority
    queue, and the four declared scalars."""
    try:
        block = text.split(BEGIN, 1)[1].split(END, 1)[0]
    except IndexError:
        raise SystemExit(
            f"debt-plane-census: FAIL -- no {BEGIN} block in the register. "
            f"The roster IS the denominator; without it this script would "
            f"report zero remaining, which reads exactly like done."
        )
    target: set[int] = set()
    owner: set[int] = set()
    # A LIST, not a set: the head is the claim, so order is the whole content
    # of this line. Reading it into a set would leave the queue looking right
    # and pointing at whichever number happened to sort first.
    priority: list[int] = []
    scalars: dict[str, int] = {}
    for line in block.splitlines():
        line = line.strip()
        if line.startswith("plane:analyzer-owner-decision"):
            owner |= {int(n) for n in re.findall(r"\d{1,3}", line.split("=", 1)[1])}
        elif line.startswith("plane:analyzer"):
            target |= {int(n) for n in re.findall(r"\d{1,3}", line.split("=", 1)[1])}
        elif line.startswith("priority"):
            priority += [int(n) for n in re.findall(r"\d{1,3}", line.split("=", 1)[1])]
        else:
            for key in SCALAR_KEYS:
                if line.startswith(key):
                    scalars[key] = int(line.split("=", 1)[1].strip())
                    break
    missing = [k for k in SCALAR_KEYS if k not in scalars]
    if missing:
        # A declared baseline that is ABSENT must not read as satisfied. Each
        # of these pins something the reader below would otherwise have to
        # invent, and an invented baseline follows its population.
        raise SystemExit(
            f"debt-plane-census: FAIL -- the roster names no "
            f"{', '.join('`' + k + '`' for k in missing)}"
        )
    swept = scalars["swept_through"]
    return Roster(
        target,
        owner,
        swept,
        priority,
        scalars["ranked_from"],
        scalars["unranked_baseline"],
        scalars["reaim_cap"],
    )


def unclosed_folds(text: str) -> list[int]:
    """Line numbers of every `<details>` the register never closes.

    R2088 -- MEASURED, on the real register. A round that closes an item folds
    its old wording into `<details><summary>...`, and R2081 opened one for item
    500 without closing it. Every item after 500 -- seven of them, all open --
    then rendered INSIDE that collapsed fold, so a person reading the register
    in anything that understands HTML saw the debt backlog end at 500 while this
    script happily counted the items behind it.

    That is the sharpest possible version of the failure this file exists to
    prevent: the instrument and the human were reading different documents, and
    the instrument was the one that was right. `is_open` looks at a title line
    and never at structure, so nothing here could have noticed -- verified by
    running this script against a fixture with an unclosed fold, which printed a
    clean count and exited 0.

    Deliberately a LINE SCAN and not an HTML parse: the register is Markdown
    with a handful of literal tags in it, and a parser would bring opinions
    about everything else in the file. What is wanted is one balance.
    """
    depth = 0
    opened: list[int] = []
    for i, line in enumerate(text.splitlines(), 1):
        if "<details>" in line:
            depth += 1
            opened.append(i)
        if "</details>" in line:
            depth -= 1
            if opened:
                opened.pop()
    return opened


#: R2250b -- the fixture carries ONE TITLE PER VERDICT WORD and one item closed
#: the way this register actually closes things: the verdict above, the original
#: folded below. Without those shapes the vocabulary arms are never executed,
#: and item 16 is the exact case item 603 was filed for -- under the previous
#: reader its folded original won and the item read back as open.
#: R2302 (item 639) adds items 18-20, the RANKED frontier. 18 is a root, 19 its
#: child, 20 its grandchild -- the shortest fixture that reaches a chain past a
#: `reaim_cap` of 1, which is the arm no shallower fixture can execute. 20 also
#: writes its depth by hand so the "declared disagrees with derived" arm has a
#: subject. Item 17 carries a literal `char **` inside backticks: without the
#: code-span rule its header runs into the body, which is the shape MEASURED on
#: the real register at item 435.
SELFTEST_ROSTER = """\
- **10. an open analyzer item.**
- **11. another open one.**
- **12. ✅ CLOSED -- a discharged item.**
- **13. an open item nobody put on any list.**
- **14. ⛔ DUPLICATE of 10 -- kept under its own number on purpose.**
- **15. ✅ REFUTED (Round 1) -- the round that filed it disproved it.**
- **16. ✅ CLOSED -- discharged, with its original folded below.**

  <details><summary>original</summary>

- **16. the open-looking wording this item had before it was closed.**

  </details>

- **17. ✅ CLOSED -- a title quoting `wz_surfaces(char **buf)` in code.**
- **18. a root at the ranking frontier. `@from: none` · ordinary**
- **19. a child of 18. `@from: {p19}` · critical**
- **20. a grandchild of 19. `@from: 19` · ordinary ·
  ⚠ **deferred**(사슬 깊이 {d20})**
{extra}
{begin}
plane:analyzer = 10 11
plane:analyzer-owner-decision = 13
priority = {priority}
swept_through = {swept}
ranked_from = {ranked_from}
unranked_baseline = {unranked_baseline}
reaim_cap = {reaim_cap}
{end}
"""


def selftest() -> int:
    """R2101 -- drive every PRIORITY arm against fixtures, because a gate whose
    arms are never executed cannot be told apart from one that always passes.

    This is the objection Layer C0g raised against `apt-install.sh` and Layer
    C0i against `append-round.sh`, answered the same way. The census itself
    cannot be a CI layer -- its input is an agent-memory register no runner
    carries -- but THIS function's input is a fixture string, so the logic is
    gradable even where the register is absent. That split is the point: the
    reader stays local, the RULES it enforces do not.
    """
    import subprocess
    import tempfile

    cases: list[tuple[str, dict[str, str], int, str]] = [
        # (label, roster fields, expected exit, a substring the output must carry)
        # `args` and `extra` are optional fields; see `args_for` / the template.
        ("head is named first", {"priority": "10 11"}, 3, "take item 10 next"),
        ("ack of the head clears it", {"priority": "10 11"}, 0, "acknowledged"),
        ("ack of a NON-head fails", {"priority": "10 11"}, 1, "does not name the head"),
        ("empty queue says so", {"priority": ""}, 0, "queue empty"),
        ("a CLOSED item on the queue fails", {"priority": "12"}, 1, "is CLOSED and still"),
        ("an ABSENT item on the queue fails", {"priority": "99"}, 1, "no such item"),
        ("a DUPLICATE on the queue fails", {"priority": "10 10"}, 1, "appears twice"),
        ("an UNJUDGED item on the queue fails", {"priority": "10", "swept": "9"}, 1, "past `swept_through"),
        ("an OWNER-DECISION item on the queue fails", {"priority": "13"}, 1, "held for an OWNER DECISION"),
        # R2250b (item 603). A folded original must not reopen its item: 10, 11,
        # 13 and the three ranked items are the open ones, and 16's archived
        # wording is the shape that used to win.
        ("a folded original does not reopen its item", {"priority": ""}, 0, "open = 6  closed = 5"),
        # The verdict vocabulary, forward: a mark with a word this reader does
        # not know is a FAIL rather than an open item.
        (
            "a discharge mark with an unknown word fails",
            {"priority": "", "extra": "- **21. ✅ DISCHARGED -- a word nobody taught this reader.**"},
            1,
            "no verdict this reader knows",
        ),
        # R2302 (item 639) -- the ranking and lineage axes. Every arm below was
        # unreachable before this round because nothing read the axes at all.
        (
            "an item past the frontier with no `@from:` fails",
            {"priority": "", "extra": "- **21. no lineage at all. ordinary**"},
            1,
            "carries no `@from:`",
        ),
        (
            "an OPEN item past the frontier with no ranking fails",
            {"priority": "", "extra": "- **21. lineage but no ranking. `@from: none`**"},
            1,
            "carries no ranking",
        ),
        (
            "a header claiming BOTH rankings fails",
            {"priority": "", "extra": "- **21. `@from: none` · critical · ordinary**"},
            1,
            "a ranking that says both orders nothing",
        ),
        # The frontier is pinned from BELOW as well: raising it past an
        # annotated item is the dodge this arm forbids.
        (
            "an annotated item BELOW the frontier fails",
            {"priority": "", "ranked_from": "19"},
            1,
            "sits BELOW `ranked_from = 19`",
        ),
        (
            "a `@from:` pointing at no item fails",
            {"priority": "", "extra": "- **21. `@from: 99` · ordinary**"},
            1,
            "the register has no such item",
        ),
        (
            "a lineage CYCLE fails",
            {
                "priority": "",
                "extra": "- **21. `@from: 22` · ordinary**\n- **22. `@from: 21` · ordinary**",
            },
            1,
            "is a CYCLE",
        ),
        # Depth is DERIVED. Both directions of the deferral rule, and the
        # hand-written depth judged against the derivation.
        (
            "a chain past the cap that does not say `deferred` fails",
            {"priority": "", "extra": "- **21. `@from: 20` · ordinary**"},
            1,
            "does not say `deferred`",
        ),
        (
            "a `deferred` the derivation does not support fails",
            {"priority": "", "reaim_cap": "2"},
            1,
            "a deferral the derivation does not support",
        ),
        (
            "a hand-written chain depth that disagrees fails",
            {"priority": "", "d20": "5"},
            1,
            "the derivation is the fact",
        ),
        # The ratchet, both directions. 10, 11 and 13 are the open unranked
        # items below the frontier.
        (
            "an unranked count ABOVE the baseline fails",
            {"priority": "", "unranked_baseline": "2"},
            1,
            "an item arrived unranked",
        ),
        (
            "an unranked count BELOW the baseline fails",
            {"priority": "", "unranked_baseline": "4"},
            1,
            "lower it to 3 in this same edit",
        ),
        # The header derivation itself. A title whose bold never closes would
        # otherwise read its own BODY as an annotation run.
        (
            "a title whose bold never closes fails",
            {"priority": "", "extra": "- **21. `@from: none` · ordinary, and no closing mark."},
            1,
            "bold title span never closes",
        ),
        # The lines rules (11) and (14) are told to read. Printed, not exiting:
        # see the module doc on why a ranking must not move the exit code.
        ("the critical line names the take", {"priority": ""}, 0, "CRITICAL -- take item 19 next"),
        ("the deferred line names the held", {"priority": ""}, 0, "DEFERRED -- 1 item(s) held"),
    ]
    env_for = {
        "ack of the head clears it": {"WZ_DEBT_PRIORITY_ACK": "10"},
        "ack of a NON-head fails": {"WZ_DEBT_PRIORITY_ACK": "11"},
    }
    args_for = {"a folded original does not reopen its item": ["--count"]}

    failures = 0
    for label, fields, want_rc, want_text in cases:
        body = SELFTEST_ROSTER.format(
            begin=BEGIN,
            end=END,
            priority=fields.get("priority", ""),
            swept=fields.get("swept", "30"),
            extra=fields.get("extra", ""),
            ranked_from=fields.get("ranked_from", "18"),
            unranked_baseline=fields.get("unranked_baseline", "3"),
            reaim_cap=fields.get("reaim_cap", "1"),
            p19=fields.get("p19", "18"),
            d20=fields.get("d20", "2"),
        )
        with tempfile.NamedTemporaryFile("w", suffix=".md", delete=False) as fh:
            fh.write(body)
            fixture = fh.name
        env = dict(os.environ)
        env.pop("WZ_DEBT_PRIORITY_ACK", None)
        env["WZ_DEBT_REGISTER"] = fixture
        env.update(env_for.get(label, {}))
        run = subprocess.run(
            [sys.executable, __file__, *args_for.get(label, [])],
            capture_output=True,
            text=True,
            env=env,
        )
        got = run.stdout + run.stderr
        ok = run.returncode == want_rc and want_text in got
        if not ok:
            failures += 1
            print(f"  FAIL  {label}")
            print(f"        want rc={want_rc} and {want_text!r}; got rc={run.returncode}")
            for line in got.splitlines():
                print(f"        | {line}")
        else:
            print(f"  ok    {label}  (rc={run.returncode})")
        pathlib.Path(fixture).unlink()

    print(f"debt-plane-census selftest: {len(cases) - failures}/{len(cases)} arm(s) pass")
    return 1 if failures else 0


class Ranking(typing.NamedTuple):
    """What the axes say once derived, for the lines rules (11) and (14) read."""

    critical: list[int]
    ordinary: list[int]
    unranked: list[int]
    deferred: list[int]


def axis_findings(
    text: str, found: dict[int, str], rst: Roster
) -> tuple[list[str], Ranking]:
    """The four axes, judged. Unclassified is RED -- never a quiet pass.

    `found` is the open/closed map the caller already built, so open-ness is
    read from the same title line every other rule here reads it from.
    """
    live, archived, unbalanced = item_headers(text)
    headers = {**archived, **live}
    table = axes(headers)
    findings: list[str] = []

    for number in unbalanced:
        findings.append(
            f"item {number}'s bold title span never closes, so its header runs "
            f"into its body and whatever the body says would be read as its "
            f"annotation run -- close the `**` on the title"
        )

    frontier = rst.ranked_from
    for number in sorted(found):
        axis = table.get(number, Axis(None, (), False, None))
        annotated = axis.parent is not None or bool(axis.ranks) or axis.deferred
        if number < frontier:
            if annotated:
                findings.append(
                    f"item {number} carries a ranking/lineage annotation and sits "
                    f"BELOW `ranked_from = {frontier}`. Lower the frontier to "
                    f"include it -- and every item in between -- or drop the "
                    f"annotation; a frontier with annotated items underneath is "
                    f"one a later round can raise to dodge this gate"
                )
            continue
        if axis.parent is None:
            findings.append(
                f"item {number} is at or above `ranked_from = {frontier}` and its "
                f"title carries no `@from:` -- write `@from: <n>` when the round "
                f"paying <n> CREATED it, `@from: none` when the round merely met "
                f"it. Unclassified is RED: read as `none` it would shorten every "
                f"chain that runs through it"
            )
        if len(axis.ranks) > 1:
            findings.append(
                f"item {number}'s annotation run carries {' and '.join(axis.ranks)}; "
                f"a ranking that says both orders nothing"
            )
        elif not axis.ranks and is_open(found[number]):
            findings.append(
                f"open item {number} is at or above `ranked_from = {frontier}` and "
                f"carries no ranking -- write `critical` or `ordinary` beside its "
                f"`@from:`. Rule (12) makes `unranked` a ratchet, and a ratchet "
                f"that admits new entries is not one"
            )

    # Depth, DERIVED. The declared depth beside a `deferred` marker is judged
    # against it rather than trusted -- a hand-written depth is a second copy.
    for number in sorted(n for n in found if n >= frontier):
        axis = table.get(number, Axis(None, (), False, None))
        if axis.parent is None:
            continue
        depth, error = chain_depth(number, table, frontier)
        if error is not None:
            findings.append(error)
            continue
        assert depth is not None
        if axis.declared_depth is not None and axis.declared_depth != depth:
            findings.append(
                f"item {number} writes chain depth {axis.declared_depth} and its "
                f"`@from:` chain derives {depth} -- the derivation is the fact, so "
                f"correct the sentence"
            )
        over = depth > rst.reaim_cap
        if over and not axis.deferred:
            findings.append(
                f"item {number} has derived chain depth {depth}, past "
                f"`reaim_cap = {rst.reaim_cap}`, and does not say `deferred`. "
                f"Rule (14) registers it and does NOT pay it this round; say so "
                f"in the title or the next round picks it up as ordinary work"
            )
        if axis.deferred and not over:
            findings.append(
                f"item {number} says `deferred` and its derived chain depth is "
                f"{depth}, within `reaim_cap = {rst.reaim_cap}` -- a deferral the "
                f"derivation does not support is work being held for no reason"
            )

    openn = [n for n in sorted(found) if is_open(found[n])]
    critical = [n for n in openn if "critical" in table.get(n, Axis(None, (), False, None)).ranks]
    ordinary = [n for n in openn if "ordinary" in table.get(n, Axis(None, (), False, None)).ranks]
    unranked = [n for n in openn if not table.get(n, Axis(None, (), False, None)).ranks]
    deferred = [n for n in openn if table.get(n, Axis(None, (), False, None)).deferred]

    # The ratchet, judged in BOTH directions. Below the frontier only: at and
    # above it the ranking is REQUIRED outright, so folding those in would let
    # a missing ranking read as a budget line rather than as the RED it is.
    tail = [n for n in unranked if n < frontier]
    if len(tail) > rst.unranked_baseline:
        findings.append(
            f"{len(tail)} open items below `ranked_from = {frontier}` carry no "
            f"ranking and `unranked_baseline` says {rst.unranked_baseline}. The "
            f"count only falls (rule 12); a rise means an item arrived unranked"
        )
    elif len(tail) < rst.unranked_baseline:
        findings.append(
            f"only {len(tail)} open items below `ranked_from = {frontier}` carry "
            f"no ranking and `unranked_baseline` still says "
            f"{rst.unranked_baseline} -- lower it to {len(tail)} in this same "
            f"edit, or the ratchet stops ratcheting"
        )

    return findings, Ranking(critical, ordinary, unranked, deferred)


def main() -> int:
    if "--selftest" in sys.argv:
        return selftest()
    path = register_path()
    if not path.is_file():
        # EXIT 2, never 0. The register is machine-local, and a reader that
        # cannot see its input must not report a clean count -- see the module
        # doc's last section.
        print(
            f"debt-plane-census: UNREADABLE -- {path} is absent. This tool reads "
            f"an agent-memory register that no clone carries; it is local-only "
            f"until open-debt item 454 moves the roster into the store.",
            file=sys.stderr,
        )
        return 2
    text = path.read_text(encoding="utf-8")
    live, archived = item_lines(text)
    found = {**archived, **live}

    if "--count" in sys.argv:
        # R2250b (open-debt item 603), the OTHER consumer. The only reader of
        # this register inside the repository is this file; the reader that
        # actually gets the count wrong every round is the operator's ad-hoc
        # regex, rewritten from memory at each round start. It has now been
        # wrong twice in two different ways on the same file -- 329 by not
        # knowing about folds, then 325 by a verdict vocabulary that counted
        # ✅ REFUTED as open and ⛔ DUPLICATE as closed. Neither is a defect in
        # the register; both are a predicate re-typed instead of run.
        opened = sorted(n for n, title in found.items() if is_open(title))
        closed = sorted(n for n in found if n not in set(opened))
        for line in verdict_findings(live):
            print(f"  debt-plane-census: FAIL -- {line}", file=sys.stderr)
        print(
            f"  debt-register: open = {len(opened)}  closed = {len(closed)}  "
            f"max = {max(found) if found else 0}  "
            f"(archived titles ignored: {len(set(archived) & set(live))})"
        )
        if opened:
            print(f"  newest open: {' '.join(str(n) for n in opened[-8:])}")
        # The ranking axes belong in the counting mode too: this is the output
        # the operator's round-start recipe reads, and `unranked` is the number
        # rule (12) ratchets. Its FINDINGS stay with the default mode, which is
        # where the roster the ratchet is judged against is parsed.
        _, rank = axis_findings(text, found, roster(text))
        print(
            f"  debt-ranking: critical = {len(rank.critical)}  ordinary = "
            f"{len(rank.ordinary)}  unranked = {len(rank.unranked)}  deferred = "
            f"{len(rank.deferred)}"
        )
        return 1 if verdict_findings(live) else 0

    rst = roster(text)
    target, owner, swept, priority = rst.target, rst.owner, rst.swept, rst.priority

    findings: list[str] = []
    findings.extend(verdict_findings(live))
    axis_lines, rank = axis_findings(text, found, rst)
    findings.extend(axis_lines)
    for line_no in unclosed_folds(text):
        findings.append(
            f"the `<details>` opened at line {line_no} is never closed, so every "
            f"item after it renders inside that collapsed fold. The count below "
            f"would still be right and the file would still read as if the "
            f"backlog ended there -- close it in the same edit"
        )
    for n in sorted(target | owner):
        if n not in found:
            findings.append(f"the roster names item {n} and the register has no such item")
    for n in sorted(target | owner):
        if n in found and not is_open(found[n]):
            findings.append(
                f"item {n} is CLOSED and still on the roster -- a closed item left "
                f"here inflates the remaining count, which is the direction that "
                f"makes a repayment loop never finish"
            )
    both = target & owner
    if both:
        findings.append(
            f"item(s) {sorted(both)} are in BOTH classes; the owner-decision set is "
            f"the target's complement, not a label on top of it"
        )
    unjudged = sorted(n for n, t in found.items() if is_open(t) and n > swept)
    if unjudged:
        findings.append(
            f"open item(s) {unjudged} are numbered past `swept_through = {swept}`, so "
            f"nothing has judged whether they are analyzer-plane. Judge them and move "
            f"the marker in the same edit"
        )

    # R2101 -- the priority queue, checked in the four directions that can make
    # a claim lie about what is next.
    seen: set[int] = set()
    for n in priority:
        if n in seen:
            findings.append(
                f"item {n} appears twice on the priority line; a queue that names "
                f"one item twice has two heads after the first is closed"
            )
        seen.add(n)
        if n not in found:
            findings.append(f"the priority queue names item {n} and the register has no such item")
        elif not is_open(found[n]):
            findings.append(
                f"item {n} is CLOSED and still on the priority queue -- a discharged "
                f"claim left here keeps pointing the next round at finished work"
            )
        if n > swept:
            findings.append(
                f"priority item {n} is numbered past `swept_through = {swept}`; a "
                f"queue cannot order a round to take something nothing has judged"
            )
        if n in owner:
            findings.append(
                f"priority item {n} is held for an OWNER DECISION; a queue cannot "
                f"order a round to take work nobody has decided to do"
            )

    if findings:
        print("debt-plane-census: FAIL")
        for f in findings:
            print(f"  - {f}")
        print("\n  Edit the ANALYZER-ROSTER block in the register in the same round.")
        return 1

    # The claim is printed FIRST, above the count -- a reader must see what to
    # take before seeing how much is left, or the count is what they act on.
    ack = os.environ.get("WZ_DEBT_PRIORITY_ACK", "").strip()
    outstanding = 0
    if priority:
        head = priority[0]
        rest = " ".join(str(n) for n in priority[1:])
        print(f"  debt-plane-census: PRIORITY -- take item {head} next.")
        if rest:
            print(f"    then: {rest}")
        if ack and ack != str(head):
            print(
                f"    FAIL -- WZ_DEBT_PRIORITY_ACK={ack} does not name the head. "
                f"The claim is item {head}; acking anything else would be a way "
                f"to acknowledge the queue while working on something else."
            )
            return 1
        if ack:
            print(f"    acknowledged: this round is taking item {head}.")
        else:
            outstanding = 3
    else:
        # SAID, not silent. An empty queue is a state a reader must be able to
        # tell apart from a queue this script failed to read.
        print("  debt-plane-census: PRIORITY -- queue empty; pick from the roster.")

    # Rule (11) reads this line; before R2302 nothing printed it. Newest first,
    # matching the roster's own "most recent, because an old item's reason has
    # gone stale" order, and DEFERRED items are withheld because rule (14) says
    # they are registered and not paid.
    takeable = [n for n in reversed(rank.critical) if n not in set(rank.deferred)]
    if takeable:
        print(
            f"  debt-plane-census: CRITICAL -- take item {takeable[0]} next "
            f"({len(takeable)} open: {' '.join(str(n) for n in takeable)})."
        )
    else:
        # SAID, for the same reason the empty queue is.
        print("  debt-plane-census: CRITICAL -- none open; take by rule (11)'s fallback.")
    if rank.deferred:
        print(
            f"  debt-plane-census: DEFERRED -- {len(rank.deferred)} item(s) held by "
            f"`reaim_cap = {rst.reaim_cap}`: {' '.join(str(n) for n in rank.deferred)}. "
            f"Registered, not unpaid; first candidates when the cap lifts."
        )
    else:
        print("  debt-plane-census: DEFERRED -- none; no chain is past the cap.")
    print(
        f"  debt-plane-census: RANKED -- critical {len(rank.critical)} / ordinary "
        f"{len(rank.ordinary)} / unranked {len(rank.unranked)} (baseline "
        f"{rst.unranked_baseline} below `ranked_from = {rst.ranked_from}`)."
    )

    remaining = sorted(n for n in target if n in found and is_open(found[n]))
    print(
        f"  debt-plane-census: analyzer open = {len(remaining)} "
        f"({len(owner)} held for an owner decision, swept through {swept})"
    )
    if remaining:
        print(f"  remaining: {' '.join(str(n) for n in remaining)}")
    if outstanding:
        print(
            f"  exit 3: a claim is outstanding. It is discharged by CLOSING item "
            f"{priority[0]}, not by running this again -- set "
            f"WZ_DEBT_PRIORITY_ACK={priority[0]} while the round is doing that."
        )
    return outstanding


if __name__ == "__main__":
    sys.exit(main())
