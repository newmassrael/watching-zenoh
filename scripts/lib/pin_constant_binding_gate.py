#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
# SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
"""R2540 (no register item) — a script that SPELLS a pin must READ one.

The citation is `no register item` for the reason `bump_sweep.py` gives for its
own: the item this answers — unregistered open-debt item 690 — lives in the
operator's agent-memory register and has no store `debt-` id for
`gate_provenance_lint` to resolve. Naming it in prose here is the honest pair.

## The defect, and why four rounds paid for it one red at a time

Item 690 was filed as "the upstream pin version is not declared in ONE place,
so the next version migration leaks again". R2496 re-measured that premise and
found most of it already false: the constants that spell a pin are mostly bound
to a SSOT and refuse when the two disagree. What survived the re-measurement is
narrower and sharper, and it is what this grades:

    a constant that spells the pin is a TRIPWIRE, not a copy — it exists so
    that moving the pin FORCES a human to re-derive the paired data the file
    carries. `sn_resolution_words.py` says so in its own refusal: "a mapping
    carried across a pin bump is one nobody re-read." Dissolving those literals
    into an auto-read would destroy the tripwire, which is why item 690's own
    note tells the round that takes it to first judge whether consolidating is
    worth anything. It is not.

    What a tripwire needs is the OTHER half: something that trips. A constant
    whose file never READS the pin SSOT cannot compare, so it does not trip —
    it just quietly grades against whatever it last said.

`upstream_feature_census.py` was exactly that. Its `UPSTREAM_VERSION` was
compared only against the version of the zenoh SOURCE TREE it found, never
against the pin — and its comment asserted the binding that its code did not
make ("build-zenohd.sh asserts the same equality"). That is the both-operands-
stale shape R2535 paid a hosted red for: on a machine whose checkout is as old
as the constant, the two agree, the gate is green, and only hosted — where
`build-zenohd.sh` provisions AT the pin — ever disagrees.

## What is graded

Every occurrence of a CURRENT pin literal in an executable script under
`scripts/`, classified into exactly one kind, with the counts printed every run
so the population can never be silently empty:

  * `ssot`     — the shell default the pin is declared in. It IS the source.
  * `bound`    — a code-read literal in a file that also READS a pin SSOT
                 (directly, or through the shared deriver). The tripwire works.
  * `unbound`  — a code-read literal in a file that reads no pin at all. FAIL.
  * `fixture`  — a literal inside a test/selftest/fixture function.
  * `prose`    — a comment or docstring. It rots without breaking anything,
                 which is a different defect with a different prescription
                 (R2333 class), so it is counted and not failed.

## ⛔ THE POPULATION IS DERIVED FROM THE LIVE PINS, NEVER FROM A VERSION LITERAL

This file spells no version. It asks `upstream_release_distance` for the pins
this tree actually holds — the same deriver `bump_sweep` uses — so bumping a pin
moves this gate's population with no edit here, and a SEVENTH pin added tomorrow
is covered by construction. Item 690's hand list named two pins; the derived
population is six, across four distinct ref literals, and the third shell SSOT
(`install-mbedtls.sh`) was in none of the item's notes.

## ⚠ WHAT THIS DOES NOT REACH, stated rather than discovered

`fixture` is COUNTED, not graded. Item 690 asks that a selftest fixture spell a
FAKE version, so that a fixture cannot silently stop exercising its claim when
the pin moves — R2535 measured that exact loss. Both fixture sites carrying a
current pin today (`upstream_release_distance.py:904`, `:943`) were opened and
are NOT that defect: their values are self-contained arithmetic cases whose
literals merely happen to equal a live pin, with nothing coupling them to the
tree. Failing them would be a false positive, and the discriminator that would
separate a coincidence from a coupling is not derived yet. Counting the kind
keeps the axis visible and countable instead of absent.
"""

from __future__ import annotations

import argparse
import ast
import io
import pathlib
import re
import sys
import tokenize

ROOT = pathlib.Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts" / "lib"))

import upstream_release_distance as urd  # noqa: E402

# `ZENOHD_VERSION="${ZENOHD_VERSION:-0.0.0}"` — the shape every pin SSOT in
# this tree uses. Anchored on the self-referential default so a mention of the
# variable elsewhere cannot enlarge the set.
#
# ⛔ The version in that example is FAKE on purpose, and this file spells no
# live pin anywhere. A gate against pin rot that seeds one more rotting copy of
# the pin in its own prose is not a gate anyone should trust; run `--check`
# against this file and it contributes zero sites, which is the intended shape.
SSOT_RE = re.compile(r'^\s*(\w+)="\$\{\1:-([^}"]+)\}"', re.M)

# The deriver's own pin entry points. A file that CALLS one of these has the
# pin from the same place this gate does, which is a binding.
DERIVER_CALLS = frozenset({"script_pins", "submodule_pins", "pins"})

READERS = frozenset({"read_text", "open"})
FIXTURE_WORDS = ("test", "fixture")

SSOT, BOUND, UNBOUND, FIXTURE, PROSE = "ssot", "bound", "unbound", "fixture", "prose"
KINDS = (SSOT, BOUND, UNBOUND, FIXTURE, PROSE)


class Site:
    """One occurrence of a current pin literal, and what it is."""

    def __init__(self, path: str, line: int, kind: str, text: str) -> None:
        self.path, self.line, self.kind, self.text = path, line, kind, text.strip()

    def __repr__(self) -> str:  # pragma: no cover - diagnostics only
        return f"{self.path}:{self.line} [{self.kind}] {self.text[:60]}"


def live_literals() -> list[str]:
    """Every ref this tree currently pins, longest first.

    Longest first so a short ref cannot shadow a longer one that contains it.
    """
    pinned = {**urd.submodule_pins(), **urd.script_pins(urd.tracked_paths())}
    return sorted({v for v in pinned.values() if v}, key=len, reverse=True)


def ssot_names(texts: dict[str, str]) -> set[str]:
    """Basenames of the scripts that DECLARE a pin, derived from their shape."""
    return {
        pathlib.PurePosixPath(path).name
        for path, text in texts.items()
        if path.endswith(".sh") and SSOT_RE.search(text)
    }


def reads_a_pin(text: str, ssots: set[str]) -> bool:
    """Does this module obtain a pin, rather than merely mention one?

    Two shapes, and the difference between them is the whole point of this
    gate: naming `build-zenohd.sh` in a comment or an error message is NOT
    reading it. `upstream_feature_census.py` did exactly that.
    """
    try:
        tree = ast.parse(text)
    except SyntaxError:
        return False
    # Module-level `NAME = "some/path.sh"` bindings, so a read spelled through
    # a constant resolves the same as one spelled inline.
    consts = {
        t.id: node.value.value
        for node in ast.walk(tree)
        if isinstance(node, ast.Assign) and isinstance(node.value, ast.Constant)
        and isinstance(node.value.value, str)
        for t in node.targets
        if isinstance(t, ast.Name)
    }
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        fn = node.func
        name = fn.attr if isinstance(fn, ast.Attribute) else getattr(fn, "id", "")
        if name in DERIVER_CALLS:
            return True
        if name not in READERS:
            continue
        seg = ast.get_source_segment(text, node) or ""
        expanded = seg + " " + " ".join(v for k, v in consts.items() if k in seg)
        if any(b in expanded for b in ssots):
            return True
    return False


def _code_before_comment(line: str, literals: list[str]) -> bool:
    """Is the literal on the CODE side of a trailing `#`, not inside it?

    A trailing comment on a real assignment must not launder the assignment.
    """
    head = line.split("#", 1)[0]
    return any(l in head for l in literals)


def classify_py(path: str, text: str, literals: list[str], ssots: set[str]) -> list[Site]:
    lines = text.splitlines()
    hits = [(i + 1, ln) for i, ln in enumerate(lines) if any(l in ln for l in literals)]
    if not hits:
        return []
    try:
        tree = ast.parse(text)
    except SyntaxError:
        return [Site(path, n, PROSE, ln) for n, ln in hits]
    comments: set[int] = set()
    try:
        for tok in tokenize.generate_tokens(io.StringIO(text).readline):
            if tok.type == tokenize.COMMENT:
                comments.add(tok.start[0])
    except (tokenize.TokenError, IndentationError):
        pass
    docs: set[int] = set()
    for node in ast.walk(tree):
        if (isinstance(node, ast.Expr) and isinstance(node.value, ast.Constant)
                and isinstance(node.value.value, str)):
            docs.update(range(node.lineno, (node.end_lineno or node.lineno) + 1))
    fixtures = [
        (n.lineno, n.end_lineno or n.lineno)
        for n in ast.walk(tree)
        if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))
        and any(w in n.name.lower() for w in FIXTURE_WORDS)
    ]
    bound = reads_a_pin(text, ssots)
    out: list[Site] = []
    for n, ln in hits:
        if n in docs:
            kind = PROSE
        elif n in comments and not _code_before_comment(ln, literals):
            kind = PROSE
        elif any(a <= n <= b for a, b in fixtures):
            kind = FIXTURE
        else:
            kind = BOUND if bound else UNBOUND
        out.append(Site(path, n, kind, ln))
    return out


def classify_sh(path: str, text: str, literals: list[str]) -> list[Site]:
    out: list[Site] = []
    for i, ln in enumerate(text.splitlines(), start=1):
        if not any(l in ln for l in literals):
            continue
        if SSOT_RE.match(ln):
            kind = SSOT
        elif ln.lstrip().startswith("#") or not _code_before_comment(ln, literals):
            kind = PROSE
        else:
            # A shell script that spells a pin outside its own declaration is
            # a second copy with nothing measuring the gap (item 47's class).
            kind = UNBOUND
        out.append(Site(path, i, kind, ln))
    return out


def classify(texts: dict[str, str], literals: list[str]) -> list[Site]:
    ssots = ssot_names(texts)
    sites: list[Site] = []
    for path in sorted(texts):
        text = texts[path]
        if path.endswith(".py"):
            sites.extend(classify_py(path, text, literals, ssots))
        else:
            sites.extend(classify_sh(path, text, literals))
    return sites


def tree_texts(literals: list[str]) -> dict[str, str]:
    """Executable scripts that carry at least one CURRENT pin literal."""
    texts: dict[str, str] = {}
    for rel in urd.tracked_paths():
        if not rel.startswith("scripts/") or not rel.endswith((".py", ".sh")):
            continue
        try:
            text = (ROOT / rel).read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        if any(l in text for l in literals):
            texts[rel] = text
    return texts


def report(sites: list[Site], literals: list[str], files: int) -> tuple[int, list[str]]:
    counts = {k: sum(1 for s in sites if s.kind == k) for k in KINDS}
    lines = [
        f"  pin-constant-binding: {len(literals)} live pin literal(s), "
        f"{len(sites)} site(s) in {files} script(s) -- "
        + " ".join(f"{k}={counts[k]}" for k in KINDS)
    ]
    if not sites:
        lines.append(
            "  pin-constant-binding: FAIL -- no site carries a current pin "
            "literal. The pins are DERIVED, so an empty population means the "
            "deriver stopped deriving, not that the tree stopped pinning: a "
            "population of zero is not a pass."
        )
        return 1, lines
    bad = [s for s in sites if s.kind == UNBOUND]
    if bad:
        for s in bad:
            lines.append(
                f"  pin-constant-binding: FAIL -- {s.path}:{s.line} spells a "
                f"current pin but the file READS no pin SSOT.\n"
                f"    {s.text[:88]}\n"
                f"    A constant that cannot compare itself to the pin is not a "
                f"tripwire; it grades\n    against whatever it last said, and only "
                f"a machine provisioned AT the pin ever\n    disagrees. Read the "
                f"pin (a SSOT script, or the shared deriver) and refuse when the "
                f"two\n    differ, in the mode that runs WITHOUT a provisioned "
                f"checkout."
            )
        return 1, lines
    lines.append(
        "  pin-constant-binding: OK -- every code-read pin literal is in a file "
        "that reads a pin."
    )
    return 0, lines


def check() -> int:
    literals = live_literals()
    if not literals:
        print(
            "  pin-constant-binding: FAIL -- the deriver returned no pin at "
            "all. This gate's population comes from it, and a gate that cannot "
            "read its input must not report green.",
            file=sys.stderr,
        )
        return 1
    texts = tree_texts(literals)
    sites = classify(texts, literals)
    rc, lines = report(sites, literals, len(texts))
    for ln in lines:
        print(ln, file=sys.stderr if rc else sys.stdout)
    return rc


# ── selftest ────────────────────────────────────────────────────────────────
# ⛔ The fixtures below spell a FAKE pin (`0.0.0`), never a live one. That is
# item 690's own rule and the defect it predicted: a fixture holding the real
# pin stops exercising its claim the moment the pin moves, silently, which is
# what R2535 measured in `sn_resolution_words.py`'s mutation fixture.
FAKE = "0.0.0"


def selftest() -> int:
    fails: list[str] = []
    arms = 0

    def want(label: str, got: object, exp: object) -> None:
        nonlocal arms
        arms += 1
        if got != exp:
            fails.append(f"  pin-constant-binding SELFTEST: {label}: {got!r} != {exp!r}")

    ssot_sh = f'ZENOHD_VERSION="${{ZENOHD_VERSION:-{FAKE}}}"\n'
    base = {"scripts/build-zenohd.sh": ssot_sh}
    want("the declaration is the source", classify(base, [FAKE])[0].kind, SSOT)

    def kinds(name: str, body: str) -> list[str]:
        both = dict(base)
        both[f"scripts/lib/{name}"] = body
        return [s.kind for s in classify(both, [FAKE]) if s.path.endswith(name)]

    # A constant in a file that READS the SSOT is bound; the SAME constant in a
    # file that only NAMES it is not. Both arms, or the predicate is untested.
    reading = (
        'BUILD = "scripts/build-zenohd.sh"\n'
        f'PIN = "{FAKE}"\n'
        "def arm():\n"
        "    return (ROOT / BUILD).read_text()\n"
    )
    naming = (
        f'PIN = "{FAKE}"\n'
        "def arm():\n"
        "    return 'provision with bash scripts/build-zenohd.sh'\n"
    )
    want("a file that reads the SSOT is bound", kinds("reading.py", reading), [BOUND])
    want("naming the SSOT in a message is NOT reading it",
         kinds("naming.py", naming), [UNBOUND])

    # The shared deriver is the other legitimate binding.
    via = f'PIN = "{FAKE}"\ndef arm():\n    return urd.script_pins(urd.tracked_paths())\n'
    want("the shared deriver is a binding", kinds("via.py", via), [BOUND])

    # Prose and fixtures are counted, not failed.
    prose = f'"""The pin is {FAKE} today."""\n# and {FAKE} in a comment\n'
    want("prose is prose", set(kinds("prose.py", prose)), {PROSE})
    fx = f'N = 1\ndef selftest():\n    return ["{FAKE}"]\n'
    want("a selftest literal is a fixture", kinds("fx.py", fx), [FIXTURE])

    # A trailing comment must not launder the assignment on the same line.
    want("a trailing comment does not launder an assignment",
         kinds("trailing.py", f'PIN = "{FAKE}"  # the pin\n'), [UNBOUND])

    # The verdict arms, driven through `report` so the gate's own accounting is
    # what is graded rather than the classifier alone.
    want("an unbound site fails",
         report(classify({"scripts/lib/naming.py": naming}, [FAKE]), [FAKE], 1)[0], 1)
    want("a bound site passes",
         report(classify({**base, "scripts/lib/reading.py": reading}, [FAKE]),
                [FAKE], 2)[0], 0)
    want("an empty population fails", report([], [FAKE], 0)[0], 1)

    for f in fails:
        print(f, file=sys.stderr)
    if fails:
        return 1
    print(f"  pin-constant-binding: selftest OK -- {arms} arm(s)")
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(description="a script that spells a pin must read one")
    ap.add_argument("--check", action="store_true", help="grade the tree")
    ap.add_argument("--selftest", action="store_true", help="drive both directions")
    args = ap.parse_args()
    if args.selftest:
        return selftest()
    if args.check:
        return check()
    ap.error("one of --check / --selftest is required")
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
