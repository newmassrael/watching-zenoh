#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
# SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

"""R311y919 (no register item) — how many ANALYZER-PLANE debts are still open,
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

## What it deliberately does NOT do

It does not judge. Nothing here decides whether an item is analyzer-plane -- the
roster is a human judgement recorded in the register, and a script that
re-derived it from keywords would reintroduce exactly the floor this file
exists to replace.

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


class Roster(typing.NamedTuple):
    """What the roster block declares, as four independent facts.

    A tuple rather than four returns, because R2101 added the fourth and a
    positional 4-tuple is how a caller silently reads `priority` as `swept`.
    """

    target: set[int]
    owner: set[int]
    swept: int
    priority: list[int]


def roster(text: str) -> Roster:
    """The rostered target set, the owner-decision set, `swept_through`, and
    the ORDERED priority queue."""
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
    swept: int | None = None
    # A LIST, not a set: the head is the claim, so order is the whole content
    # of this line. Reading it into a set would leave the queue looking right
    # and pointing at whichever number happened to sort first.
    priority: list[int] = []
    for line in block.splitlines():
        line = line.strip()
        if line.startswith("plane:analyzer-owner-decision"):
            owner |= {int(n) for n in re.findall(r"\d{1,3}", line.split("=", 1)[1])}
        elif line.startswith("plane:analyzer"):
            target |= {int(n) for n in re.findall(r"\d{1,3}", line.split("=", 1)[1])}
        elif line.startswith("priority"):
            priority += [int(n) for n in re.findall(r"\d{1,3}", line.split("=", 1)[1])]
        elif line.startswith("swept_through"):
            swept = int(line.split("=", 1)[1].strip())
    if swept is None:
        raise SystemExit("debt-plane-census: FAIL -- the roster names no `swept_through`")
    return Roster(target, owner, swept, priority)


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
{extra}
{begin}
plane:analyzer = 10 11
plane:analyzer-owner-decision = 13
priority = {priority}
swept_through = {swept}
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
        # R2250b (item 603). A folded original must not reopen its item: 10, 11
        # and 13 are the only open ones, and 16's archived wording is the shape
        # that used to win.
        ("a folded original does not reopen its item", {"priority": ""}, 0, "open = 3  closed = 4"),
        # The verdict vocabulary, forward: a mark with a word this reader does
        # not know is a FAIL rather than an open item.
        (
            "a discharge mark with an unknown word fails",
            {"priority": "", "extra": "- **17. ✅ DISCHARGED -- a word nobody taught this reader.**"},
            1,
            "no verdict this reader knows",
        ),
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
            swept=fields.get("swept", "20"),
            extra=fields.get("extra", ""),
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
        return 1 if verdict_findings(live) else 0

    target, owner, swept, priority = roster(text)

    findings: list[str] = []
    findings.extend(verdict_findings(live))
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
