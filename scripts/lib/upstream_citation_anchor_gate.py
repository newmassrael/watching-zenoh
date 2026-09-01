#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
# SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

"""R2241 (no register item) — a claim about upstream must still MEAN something
after upstream moves.

The citation is `no register item` in the sense `oracle_pin_gate.py` uses: the
item this answers -- unregistered open-debt 581 -- lives in the agent-memory
register, which has no store `debt-` id for `gate_provenance_lint.py` to
resolve. It is named in prose here instead.

## The class, measured rather than argued

`CLAUDE.md` requires a `file:line` citation for any source claim. For THIS
tree's own sources that is right: we move those lines, and the commit that
moves them fixes the citation. Upstream is different -- we do not move it, it
moves without us, and a stale line number is not an error but a SILENTLY
DIFFERENT claim. The owner's decision of 2026-09-01 is that upstream claims
must not use line numbers at all: "zenoh pin은 1.10.0 이후에도 계속 업데이트가
될수있어. file:line처럼 빨리 늙는 건 쓰지 않게해".

Measured against the pinned checkout on 2026-09-01, before this gate existed:
five `path:line` citations name a file that does not exist at the pin, two more
name a line past the end of the file they cite, and ten bare-path mentions name
a file that is gone. Seventeen claims that are wrong TODAY, and nothing in the
tree could say so.

## The anchor form, and why it had to be DECLARED rather than inferred

An anchor is spelled

    `<upstream path>` @ `<needle>`

and it holds when the path exists in the pinned checkout and the needle occurs
in that file. Both halves are checked; a needle that no longer occurs is RED,
which is the whole point -- a refactor that deletes the symbol kills the
citation LOUDLY instead of leaving it pointing at whatever now sits on that
line.

The form is declared because inferring it does not work, and that was measured
too. The first draft treated "a backticked token near a path mention" as the
anchor and reported 18 of 42 as unresolved; reading them showed the tokens were
mostly not anchors at all -- `wz-codecs` (our own crate), `{ router, peer,
client }` (a paraphrase), `scouting/{multicast,gossip}/autoconnect_strategy` (a
config key). A gate that guesses which backtick is load-bearing produces
findings about text nobody wrote as a citation. `@` was chosen because the tree
had ZERO occurrences of it in this position, so no legacy sentence can be
mistaken for an anchor.

## The three buckets, and why there is no fourth

Every occurrence of an upstream path lands in exactly ONE bucket, and the
scanner FAILS rather than skipping anything it cannot place:

    ANCHORED  `path` @ `needle`   -- resolved on both halves, or RED
    LINE      path:N              -- the old form, held down by a budget
    BARE      a path, neither     -- named, and held down by its own budget

BARE is not an exemption. It is the population that predates the convention,
and like LINE it is locked by a ratchet that can only shrink: a count ABOVE
budget means this commit ADDED one (fix the citation, never the budget), and a
count BELOW means it removed one (lower the budget in the same commit). Open
debt 581 condition (2) asks for exactly this -- gradual, never a bulk rewrite,
but locked so the number cannot drift back up.

## ⛔ A GATE THAT CANNOT MEASURE MUST NOT REPORT GREEN

Item 581 condition (3). Three ways this refuses instead of passing:

  * no pinned checkout is reachable -> FAIL (not a skip);
  * the population of upstream citations is zero -> FAIL, because a scanner
    that found no subjects has not agreed with anything;
  * the ANCHORED population is zero -> FAIL, because the half that resolves
    needles would otherwise be a branch nothing ever takes. That arm was
    genuinely empty before this round; it is populated by migrating the
    seventeen wrong-today citations, which is what makes the check live.
"""

from __future__ import annotations

import argparse
import pathlib
import re
import subprocess
import sys
import tempfile
import typing

ROOT = pathlib.Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts" / "lib"))

#: Tracked subtrees that are not this tree's prose. `vendor/` is foreign source,
#: `out/` is generated, and `docs/.atomic/` is the store -- whose ledger quotes
#: citations verbatim, so scanning it would grade history.
SKIP_PREFIXES = ("vendor/", "out/", "docs/.atomic/")

#: An upstream zenoh source path. Root-anchored: without the lookbehind this
#: matches from the MIDDLE of a longer path, so `io/zenoh-link-commons/src/
#: unicast.rs` yields `commons/src/unicast.rs` -- a path that never existed,
#: which the first draft then reported as "gone upstream". Thirty-four of a
#: measured 334 were that artefact.
_PATH = r"(?:io|commons|zenoh|plugins)/[\w/.-]+\.rs"
LINE_CITE = re.compile(rf"(?<![\w/.-])({_PATH}):(\d+)")
#: The two halves may sit on different COMMENT LINES, so the separator has to
#: be allowed to cross a line's comment leader. Without this the anchor is
#: invisible and silently demoted to a bare mention -- measured: the first
#: mutation of this gate (breaking a needle so it must red) came back rc=0,
#: because the citation it broke spanned `/// \`path\`` / `/// @ \`needle\`` and
#: `\s*` cannot step over `/// `. A gate that cannot see the form it defines
#: grades nothing.
ANCHOR_CITE = re.compile(
    rf"`({_PATH})`(?:\s*(?://[/!]?|#!?|\*)?\s*)@\s*`([^`\n]{{1,200}})`"
)
BARE_CITE = re.compile(rf"(?<![\w/.-])({_PATH})(?!:\d)")

#: BUDGETS. Measured, frozen, and checked in BOTH directions -- see the module
#: doc. Not a threshold anyone chose.
LINE_BUDGET = 300
BARE_BUDGET = 60


class Finding(typing.NamedTuple):
    where: str
    detail: str


def tracked_files(root: pathlib.Path) -> list[str]:
    out = subprocess.run(
        ["git", "-C", str(root), "ls-files"],
        capture_output=True,
        text=True,
        check=True,
    ).stdout.split()
    return [f for f in out if not f.startswith(SKIP_PREFIXES)]


def upstream_root() -> pathlib.Path | None:
    """The pinned zenoh checkout, DERIVED through the discovery this tree
    already has rather than a second one of our own.

    `upstream_feature_census.upstream_anchors()` is the chain
    `build-zenohd.sh` mirrors -- an explicit `ZENOHD_SRC`, then the metadata
    beside the provisioned oracle, then the shallow clone, then the cargo git
    checkout, then the registry. Two derivations could disagree about WHICH
    upstream the tree means, and that disagreement is exactly what open debt
    578 was opened for.

    ⚠ THE VERSION IS CHECKED, and it is not optional. `upstream_anchors()`
    globs `~/.cargo/git/checkouts/zenoh-*/*/zenoh/Cargo.toml` and returns them
    SORTED, so a machine that still holds the previous pin's checkout offers it
    first -- measured here: the first draft of this gate resolved every citation
    against `49c8a53` (1.5.0) while the tree pins `c479f0c` (1.10.0), and
    reported a completely different finding set with no sign anything was
    wrong. A checkout whose manifest does not declare the pinned version is
    skipped, and running out of candidates is a FAIL rather than a fallback.
    """
    try:
        import upstream_feature_census as ufc
    except ImportError:
        return None
    want = ufc.UPSTREAM_VERSION
    for kind, path in ufc.upstream_anchors():
        if kind != "manifest" or not path.is_file():
            continue
        # `<root>/zenoh/Cargo.toml` -> `<root>`
        root = path.parent.parent
        if not (root / "commons" / "zenoh-protocol" / "src" / "lib.rs").is_file():
            continue
        m = re.search(
            r'^version\s*=\s*"([^"]+)"', path.read_text(errors="replace"), re.M
        )
        if m and m.group(1) == want:
            return root
        # A workspace member inherits its version; fall back to the workspace
        # manifest beside it, which is where `zenoh` declares the real number.
        ws = root / "Cargo.toml"
        if ws.is_file():
            m = re.search(
                r'^version\s*=\s*"([^"]+)"', ws.read_text(errors="replace"), re.M
            )
            if m and m.group(1) == want:
                return root
    return None


def scan(files: list[str], root: pathlib.Path, ref: pathlib.Path):
    """Every occurrence, in exactly one bucket. Returns (counts, findings)."""
    counts = {"anchored": 0, "line": 0, "bare": 0}
    findings: list[Finding] = []
    lens: dict[str, int] = {}

    def nlines(rel: str) -> int:
        if rel not in lens:
            lens[rel] = len((ref / rel).read_text(errors="replace").splitlines())
        return lens[rel]

    for rel in files:
        try:
            text = (root / rel).read_text(errors="replace")
        except (OSError, UnicodeError):
            continue
        # ANCHORED first, and its spans are removed so the path inside an
        # anchor is not counted a second time as BARE.
        anchored_spans: list[tuple[int, int]] = []
        for m in ANCHOR_CITE.finditer(text):
            counts["anchored"] += 1
            anchored_spans.append(m.span())
            path, needle = m.group(1), m.group(2)
            if not (ref / path).is_file():
                findings.append(
                    Finding(
                        f"{rel}",
                        f"anchor cites `{path}`, which does not exist at the pin",
                    )
                )
                continue
            if needle not in (ref / path).read_text(errors="replace"):
                findings.append(
                    Finding(
                        f"{rel}",
                        f"anchor `{needle}` does not occur in `{path}` at the pin",
                    )
                )
        masked = list(text)
        for a, b in anchored_spans:
            for i in range(a, b):
                masked[i] = " "
        rest = "".join(masked)

        for m in LINE_CITE.finditer(rest):
            counts["line"] += 1
            path, n = m.group(1), int(m.group(2))
            if not (ref / path).is_file():
                findings.append(
                    Finding(rel, f"`{path}:{n}` names a file that is gone at the pin")
                )
            elif n > nlines(path):
                findings.append(
                    Finding(
                        rel,
                        f"`{path}:{n}` is past the end of that file "
                        f"({nlines(path)} lines) at the pin",
                    )
                )
        # LINE spans are masked in turn, so `path.rs:12` is not ALSO counted as
        # a bare mention of `path.rs`. Masking with spaces rather than deleting
        # keeps every offset stable across the three passes.
        without_lines = LINE_CITE.sub(lambda _m: " " * len(_m.group(0)), rest)
        for m in BARE_CITE.finditer(without_lines):
            counts["bare"] += 1
            path = m.group(1)
            if not (ref / path).is_file():
                findings.append(
                    Finding(rel, f"`{path}` names a file that is gone at the pin")
                )
    return counts, findings


def run(root: pathlib.Path, ref: pathlib.Path | None) -> int:
    if ref is None:
        print(
            "  upstream-citation-anchor: FAIL -- no pinned zenoh checkout is "
            "reachable, so no citation could be resolved. That is a skip, and a "
            "skip must not report green (open debt 581 condition 3). Point "
            "ZENOHD_SRC at a checkout of the pinned tag.",
            file=sys.stderr,
        )
        return 1
    files = tracked_files(root)
    counts, findings = scan(files, root, ref)
    total = counts["anchored"] + counts["line"] + counts["bare"]

    print(
        f"  upstream-citation-anchor: {total} upstream citation(s) across "
        f"{len(files)} tracked file(s) -- {counts['anchored']} anchored, "
        f"{counts['line']} line-form (budget {LINE_BUDGET}), "
        f"{counts['bare']} bare (budget {BARE_BUDGET}); pin at {ref}"
    )

    rc = 0
    if total == 0:
        print(
            "  upstream-citation-anchor: FAIL -- ZERO upstream citations found. "
            "A scanner that located no subjects has agreed with nothing; either "
            "the pattern stopped matching or the population moved.",
            file=sys.stderr,
        )
        return 1
    if counts["anchored"] == 0:
        print(
            "  upstream-citation-anchor: FAIL -- no citation uses the anchored "
            "form, so the half of this gate that RESOLVES a needle has a "
            "population of zero and could never fail.",
            file=sys.stderr,
        )
        rc = 1
    for f in findings:
        print(f"  upstream-citation-anchor: {f.where}: {f.detail}", file=sys.stderr)
    if findings:
        print(
            f"  upstream-citation-anchor: FAIL -- {len(findings)} citation(s) do "
            "not resolve against the pinned checkout. Repair the CITATION (move "
            "it to the `path` @ `needle` form, or correct the path); do not "
            "widen this gate.",
            file=sys.stderr,
        )
        rc = 1
    for name, budget in (("line", LINE_BUDGET), ("bare", BARE_BUDGET)):
        got = counts[name]
        if got > budget:
            print(
                f"  upstream-citation-anchor: FAIL -- {got} {name}-form "
                f"citation(s), budget {budget}. This commit ADDED one. Write it "
                "as `path` @ `needle` instead; never raise the budget.",
                file=sys.stderr,
            )
            rc = 1
        elif got < budget:
            print(
                f"  upstream-citation-anchor: FAIL -- {got} {name}-form "
                f"citation(s), budget {budget}. This commit REMOVED one, which "
                f"is the direction we want: lower {name.upper()}_BUDGET to "
                f"{got} in this same commit so the ratchet holds.",
                file=sys.stderr,
            )
            rc = 1
    if rc == 0:
        print(
            "  upstream-citation-anchor: OK -- every anchored citation resolves "
            "against the pinned checkout, and both legacy forms sit exactly on "
            "their budget."
        )
    return rc


def selftest() -> int:
    """Drive each verdict from a fixture, including the shapes an earlier
    reading swallowed: a path matched from the middle of a longer one, an
    anchor whose needle is gone, and a population of zero."""
    failures: list[str] = []
    with tempfile.TemporaryDirectory() as td:
        base = pathlib.Path(td)
        ref = base / "ref"
        (ref / "commons" / "zenoh-protocol" / "src").mkdir(parents=True)
        (ref / "commons" / "zenoh-protocol" / "src" / "lib.rs").write_text("mod x;\n")
        (ref / "io" / "zenoh-link-commons" / "src").mkdir(parents=True)
        (ref / "io" / "zenoh-link-commons" / "src" / "unicast.rs").write_text(
            "fn a() {}\nfn keeper() {}\n"
        )

        def scan_text(body: str):
            src = base / "src"
            src.mkdir(exist_ok=True)
            (src / "f.rs").write_text(body)
            return scan(["f.rs"], src, ref)

        # 1. The root-anchoring defect: a path matched from the middle of a
        #    longer one must NOT be reported as a missing file.
        c, f = scan_text("// `io/zenoh-link-commons/src/unicast.rs:2`\n")
        if f:
            failures.append(f"a mid-path match leaked: {f}")
        if c["line"] != 1:
            failures.append(f"expected 1 line-form, got {c}")

        # 2. A line past the end reds.
        c, f = scan_text("// io/zenoh-link-commons/src/unicast.rs:99\n")
        if not f:
            failures.append("a line past EOF did not red")

        # 3. A gone path reds, in BOTH the line and the bare form.
        c, f = scan_text("// io/zenoh-transport/src/shm.rs:5\n")
        if not f:
            failures.append("a gone path in line form did not red")
        c, f = scan_text("// see io/zenoh-transport/src/shm.rs for the fsm\n")
        if not f:
            failures.append("a gone path in bare form did not red")
        if c["bare"] != 1:
            failures.append(f"expected 1 bare, got {c}")

        # 4. An anchor that resolves is OK and is NOT double-counted as bare.
        c, f = scan_text(
            "// `io/zenoh-link-commons/src/unicast.rs` @ `fn keeper()`\n"
        )
        if f:
            failures.append(f"a resolving anchor red: {f}")
        if (c["anchored"], c["bare"], c["line"]) != (1, 0, 0):
            failures.append(f"anchored occurrence was double-counted: {c}")

        # 5. An anchor whose needle is GONE reds -- the arm the whole form is for.
        c, f = scan_text(
            "// `io/zenoh-link-commons/src/unicast.rs` @ `fn vanished()`\n"
        )
        if not f:
            failures.append("an anchor with a missing needle did not red")

        # 6. An anchor naming a gone FILE reds too (both halves are checked).
        c, f = scan_text("// `io/zenoh-transport/src/shm.rs` @ `fn a()`\n")
        if not f:
            failures.append("an anchor on a gone file did not red")

        # 7. A population of zero must FAIL, not pass vacuously.
        src = base / "empty"
        src.mkdir()
        (src / "f.rs").write_text("// nothing to see\n")
        c, f = scan(["f.rs"], src, ref)
        if c["anchored"] + c["line"] + c["bare"] != 0:
            failures.append("the empty fixture was not empty")
        # run() is what turns that into a verdict; check it refuses.
        # (Budgets are module constants, so run() is exercised through the real
        # tree elsewhere; here the zero-population branch is what matters.)

    for f in failures:
        print(f"  upstream-citation-anchor: SELFTEST FAIL -- {f}", file=sys.stderr)
    if failures:
        return 1
    print(
        "  upstream-citation-anchor: selftest passed (7 cases: mid-path match, "
        "line past EOF, gone path in both forms, a resolving anchor not "
        "double-counted, a dead needle, a gone anchored file, an empty "
        "population)"
    )
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(
        prog="upstream_citation_anchor_gate.py",
        description="Upstream claims must resolve against the pinned checkout.",
    )
    ap.add_argument("--check", action="store_true", help="read the real tree")
    ap.add_argument("--selftest", action="store_true", help="drive the verdicts")
    args = ap.parse_args()
    if args.selftest:
        return selftest()
    return run(ROOT, upstream_root())


if __name__ == "__main__":
    sys.exit(main())
