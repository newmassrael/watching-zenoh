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
#: matches from the MIDDLE of a longer path -- a link-commons unicast path
#: yields a `commons/src/...` fragment, a path that never existed, which the
#: first draft then reported as "gone upstream". Thirty-four of a measured 334
#: were that artefact. (The fragment is DESCRIBED rather than written out: this
#: file is inside the population it scans, so a literal here would be a citation
#: -- see `selftest`'s case 8.)
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

#: A LIVE invocation of the RESOLUTION arm. R2242 split this gate in two and,
#: in doing so, made `--resolve` a flag someone can simply stop passing: delete
#: the Layer Z line and the form arm goes on printing "DEFERRED to Layer Z"
#: while nothing resolves anything and every lane stays green. That is
#: condition (3) -- a skip must not report green -- defeated one level up, by
#: the very split that exists to honour it. So the arm that DEFERS is the arm
#: that has to prove the deferral arrives somewhere.
RESOLVE_WIRED = re.compile(r"upstream_citation_anchor_gate\.py\s+--check\s+--resolve")


def resolution_arm_is_wired(root: pathlib.Path) -> bool:
    """Does this tree still RUN the half the form arm defers?

    NON-COMMENT lines only. `lane-reach` paid for that distinction one file
    over -- "a stem named ONLY inside a run-ci comment is not run by it" -- and
    here it is a live case rather than a hypothetical: Layer C0's own comment
    block discusses resolving at length without invoking it. Counting prose
    would make this check satisfiable by the sentence that describes the
    problem. Measured on this tree while the check was being written: one live
    invocation, zero comment-only mentions, and the C0 block carries no literal
    of the flag -- so deleting the Layer Z line really does flip it.

    Checked HERE rather than by a separate Layer C0 lint on purpose. A second
    lint would be a second derivation of "is the resolution arm wired", and two
    derivations can disagree -- which is exactly why `upstream_root()` reuses
    `upstream_anchors()` instead of discovering the pin a second time.

    An ABSENT `run-ci.sh` answers False, not "not applicable": a tree that
    cannot be asked whether it wires the other arm has not answered yes.
    """
    runci = root / "scripts" / "run-ci.sh"
    if not runci.is_file():
        return False
    for line in runci.read_text(errors="replace").splitlines():
        if line.lstrip().startswith("#"):
            continue
        if RESOLVE_WIRED.search(line):
            return True
    return False


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


def run(root: pathlib.Path, ref: pathlib.Path | None, resolve: bool) -> int:
    """`resolve=False` runs the FORM arm only; `resolve=True` adds the
    RESOLUTION arm and requires a checkout.

    THE SPLIT IS A MEASUREMENT, not a convenience. Scanning this tree against
    the pinned checkout and against an EMPTY directory gives identical counts
    (20/303/62 both ways when it was measured) and 6 findings versus 385: the
    classification and the budgets need no upstream source at all, and every
    finding needs one. So the two arms can live in different lanes without
    either becoming a skip.

    They have to. The hosted C0 jobs (`ci`, `validate-codegen`) provision no
    zenoh source -- no `build-zenohd`, no `ZENOHD_SRC`, no cargo checkout -- so
    a single-armed gate wired there would fail on EVERY hosted run under its own
    condition (3). R2241 shipped exactly that. The form arm belongs in C0, where
    it can always measure; the resolution arm belongs in Layer Z, which builds
    zenohd and therefore has a source tree, and where "no checkout" is a real
    failure rather than a fact about the runner.

    `upstream_feature_census.py` already splits this way for the same reason,
    and it PRINTS the deferral rather than letting a green shape arm read as a
    graded surface. So does this.
    """
    if resolve and ref is None:
        print(
            "  upstream-citation-anchor: FAIL -- no pinned zenoh checkout is "
            "reachable, so no citation could be resolved. That is a skip, and a "
            "skip must not report green (open debt 581 condition 3). Point "
            "ZENOHD_SRC at a checkout of the pinned tag.",
            file=sys.stderr,
        )
        return 1
    files = tracked_files(root)
    # With `resolve=False` the scan still walks every occurrence -- the buckets
    # and the budgets are what the form arm is -- but its findings are DROPPED
    # rather than reported, because without a real checkout every one of them
    # would be "this path is gone" about a path that is merely unreachable here.
    counts, findings = scan(files, root, ref if ref is not None else root / ".git")
    if not resolve:
        findings = []
    total = counts["anchored"] + counts["line"] + counts["bare"]

    where = f"pin at {ref}" if resolve else "FORM arm only"
    print(
        f"  upstream-citation-anchor: {total} upstream citation(s) across "
        f"{len(files)} tracked file(s) -- {counts['anchored']} anchored, "
        f"{counts['line']} line-form (budget {LINE_BUDGET}), "
        f"{counts['bare']} bare (budget {BARE_BUDGET}); {where}"
    )
    if not resolve:
        print(
            "  upstream-citation-anchor: the RESOLUTION arm (does each path and "
            "needle still exist upstream?) is DEFERRED to Layer Z, which has a "
            "pinned source tree. This run graded the FORM only -- do not read "
            "it as "
            "'every citation resolves'."
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
    if not resolve and not resolution_arm_is_wired(root):
        print(
            "  upstream-citation-anchor: FAIL -- this run DEFERRED resolution "
            "to Layer Z, and no live (non-comment) line of scripts/run-ci.sh "
            "invokes this gate with `--check --resolve`. A half deferred to "
            "nothing is a skip reporting green, which is the rule this gate "
            "enforces one level down (open debt 581 condition 3). Restore the "
            "Layer Z invocation; do not relax this check.",
            file=sys.stderr,
        )
        rc = 1
    if rc == 0:
        # The two arms must not claim the same thing. A FORM-arm run that said
        # "every citation resolves" would be the escape hatch this whole split
        # exists to avoid -- it graded no path and no needle.
        print(
            "  upstream-citation-anchor: OK -- every anchored citation resolves "
            "against the pinned checkout, and both legacy forms sit exactly on "
            "their budget."
            if resolve
            else "  upstream-citation-anchor: OK (FORM) -- every occurrence is "
            "classified and both legacy forms sit exactly on their budget. "
            "Nothing here was resolved against upstream."
        )
    return rc


def selftest() -> int:
    """Drive each verdict from a fixture, including the shapes an earlier
    reading swallowed: a path matched from the middle of a longer one, an
    anchor whose needle is gone, and a population of zero.

    ⚠ EVERY upstream path below is ASSEMBLED from segments rather than written
    as a literal, and that is load-bearing rather than style. This file is
    tracked, so it is IN the population it scans, and a literal
    zenoh-transport path written out in a fixture is indistinguishable from a
    claim someone made about upstream. R2241 shipped it with literals and the
    gate reported SIX findings against its own test data the moment `git add`
    put it under `git ls-files` -- the R2191 class ("a gate whose population
    comes from `git ls-files` cannot see itself before the commit"), walked into
    with the lesson already written down.

    Assembly rather than an exclusion list, because the two are not the same
    thing. An exclusion excuses a FILE and would hide a real citation written
    beside the fixtures; assembly removes only what was never a citation, and a
    control run confirms it: a literal path in a probe file counts 1 and finds
    1, the assembled twin counts 0, and a citation written as prose in a
    neighbouring file still counts 1 and finds 1.
    """
    failures: list[str] = []
    # Segment tuples, joined at runtime. `_p` never appears in this source as a
    # path, which is the whole point.
    def _p(*seg: str) -> str:
        return "/".join(seg)

    UNICAST = _p("io", "zenoh-link-commons", "src", "unicast.rs")
    GONE = _p("io", "zenoh-transport", "src", "shm.rs")
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
        c, f = scan_text(f"// `{UNICAST}:2`\n")
        if f:
            failures.append(f"a mid-path match leaked: {f}")
        if c["line"] != 1:
            failures.append(f"expected 1 line-form, got {c}")

        # 2. A line past the end reds.
        c, f = scan_text(f"// {UNICAST}:99\n")
        if not f:
            failures.append("a line past EOF did not red")

        # 3. A gone path reds, in BOTH the line and the bare form.
        c, f = scan_text(f"// {GONE}:5\n")
        if not f:
            failures.append("a gone path in line form did not red")
        c, f = scan_text(f"// see {GONE} for the fsm\n")
        if not f:
            failures.append("a gone path in bare form did not red")
        if c["bare"] != 1:
            failures.append(f"expected 1 bare, got {c}")

        # 4. An anchor that resolves is OK and is NOT double-counted as bare.
        c, f = scan_text(f"// `{UNICAST}` @ `fn keeper()`\n")
        if f:
            failures.append(f"a resolving anchor red: {f}")
        if (c["anchored"], c["bare"], c["line"]) != (1, 0, 0):
            failures.append(f"anchored occurrence was double-counted: {c}")

        # 5. An anchor whose needle is GONE reds -- the arm the whole form is for.
        c, f = scan_text(f"// `{UNICAST}` @ `fn vanished()`\n")
        if not f:
            failures.append("an anchor with a missing needle did not red")

        # 6. An anchor naming a gone FILE reds too (both halves are checked).
        c, f = scan_text(f"// `{GONE}` @ `fn a()`\n")
        if not f:
            failures.append("an anchor on a gone file did not red")

        # 8. THE FIXTURE PATHS ARE ASSEMBLED, and this is the arm that keeps
        #    that true. A future edit that inlines one back as a literal makes
        #    this file cite upstream, which is exactly the R2241 defect; the
        #    check is on THIS SOURCE, so it cannot be satisfied by the fixture.
        own = pathlib.Path(__file__).read_text(errors="replace")
        leaked = [m.group(1) for m in BARE_CITE.finditer(own)] + [
            m.group(1) for m in LINE_CITE.finditer(own)
        ]
        if leaked:
            failures.append(
                f"this file writes upstream path literal(s) {sorted(set(leaked))}; "
                "assemble them from segments so the gate does not cite upstream"
            )

        # 7. A population of zero must FAIL, not pass vacuously.
        src = base / "empty"
        src.mkdir()
        (src / "f.rs").write_text("// nothing to see\n")
        c, f = scan(["f.rs"], src, ref)
        if c["anchored"] + c["line"] + c["bare"] != 0:
            failures.append("the empty fixture was not empty")

        # 9. EVERY VERDICT `run()` CAN REACH, driven from a fixture.
        #
        # Until R2242 this file tested `scan()` and left `run()` -- the layer
        # that turns counts into a verdict -- reachable only from `main()`. Its
        # branches had been exercised by hand on the real tree and by nothing
        # that would run again, so a future edit could delete any of them and
        # this selftest would stay green. That is the shape this whole gate
        # exists to refuse, one level up.
        #
        # `all green` is not decoration: without a case that returns 0, "every
        # branch reds" cannot be told from "this gate refuses everything".
        # Budgets are module constants, so they are swapped around each call and
        # restored -- the alternative is a fixture that can never exercise a
        # ratchet, which is the same vacuity in a different place.
        # `runci` writes a `scripts/run-ci.sh` and is NOT git-added on purpose:
        # `resolution_arm_is_wired` reads the filesystem, and leaving the file
        # untracked keeps it out of `tracked_files`, so these fixtures' citation
        # counts stay exactly what their `body` says. A tracked one would work
        # too (the wiring line carries no upstream path) but it would couple two
        # unrelated numbers.
        def git_fixture(
            name: str, body: str | None, runci: str | None = None
        ) -> pathlib.Path:
            d = base / name
            d.mkdir()
            subprocess.run(["git", "-C", str(d), "init", "-q"], check=True)
            if runci is not None:
                (d / "scripts").mkdir()
                (d / "scripts" / "run-ci.sh").write_text(runci)
            if body is not None:
                (d / "f.rs").write_text(body)
                subprocess.run(["git", "-C", str(d), "add", "f.rs"], check=True)
            return d

        # The fixture REF, not the machine's checkout: this selftest has to be
        # runnable where no pinned tree exists, which is most of CI.
        empty_repo = git_fixture("repo_empty", None)
        line_repo = git_fixture("repo_line", f"// {UNICAST}:1\n")
        anchor_repo = git_fixture("repo_anchor", f"// `{UNICAST}` @ `fn keeper()`\n")
        # A fixture carrying BOTH forms, so a budget row is not shadowed by the
        # anchored==0 guard. Measured: with a line-only fixture, disabling the
        # budget guard left the selftest green because `anchored == 0` caught
        # the same run -- a control group that cannot separate two guards has
        # not tested either.
        mixed_repo = git_fixture(
            "repo_mixed", f"// `{UNICAST}` @ `fn keeper()`\n// {UNICAST}:1\n"
        )
        # The FINDINGS guard is the resolution arm's whole verdict, and nothing
        # covered it until R2242 measured that too: disabling it left this
        # selftest green AND `--check --resolve` green on the real tree. This
        # fixture is built so findings is the ONLY guard that can fire -- two
        # anchored citations (so `anchored != 0`), zero line and bare (so both
        # budgets sit at 0), one needle alive and one dead.
        dead_needle_repo = git_fixture(
            "repo_dead_needle",
            f"// `{UNICAST}` @ `fn keeper()`\n// `{UNICAST}` @ `fn vanished()`\n",
        )
        keep = (LINE_BUDGET, BARE_BUDGET)

        def verdict(root: pathlib.Path, r, resolve: bool, line_b: int, bare_b: int):
            globals()["LINE_BUDGET"], globals()["BARE_BUDGET"] = line_b, bare_b
            try:
                return run(root, r, resolve=resolve)
            finally:
                globals()["LINE_BUDGET"], globals()["BARE_BUDGET"] = keep

        # ⚠ MEASURED OVERLAP, recorded rather than hidden: disabling the
        # zero-population guard does NOT make the first row fail, because an
        # empty tree also has no anchored citation and the next guard catches
        # it. So that row pins "an empty tree reds", not "this branch reds" --
        # the two are redundant on this fixture and no fixture can separate them
        # (a tree with zero citations cannot have a non-zero anchored count).
        # The redundancy is deliberate defence, not dead code: if the PATTERN
        # ever stops matching, both fire. The rows that ARE separable were
        # checked by mutation and each one reds alone.
        for label, got, want in (
            ("a population of zero", verdict(empty_repo, ref, True, *keep), 1),
            ("no anchored citation", verdict(line_repo, ref, True, 1, 0), 1),
            ("a budget exceeded", verdict(mixed_repo, ref, True, 0, 0), 1),
            ("a budget undershot", verdict(mixed_repo, ref, True, 9, 0), 1),
            ("the mixed fixture otherwise clean", verdict(mixed_repo, ref, True, 1, 0), 0),
            ("a dead needle, findings the only guard",
             verdict(dead_needle_repo, ref, True, 0, 0), 1),
            ("no checkout, resolving", verdict(anchor_repo, None, True, 0, 0), 1),
            ("a clean tree", verdict(anchor_repo, ref, True, 0, 0), 0),
        ):
            if got != want:
                failures.append(f"run() on {label}: expected rc={want}, got {got}")

        # 10. THE FORM ARM MUST NOT RESOLVE, MUST NOT CLAIM IT DID, AND MUST
        #     REFUSE TO DEFER INTO A VOID.
        #
        # The three rows below are the escape hatch `--resolve` opened and the
        # bolt on it. Row 1 is the wiring defect R2242 repaid: with the other
        # arm wired, no checkout is FINE here. Rows 2 and 3 are the bolt --
        # delete the Layer Z line and the form arm reds; write it in a COMMENT
        # and it still reds, which is the distinction `lane-reach` measured one
        # file over. The `#` row is not decoration: without it the check would
        # be satisfiable by the prose that describes the deferral, and Layer
        # C0's real comment block does discuss resolving without invoking it.
        WIRED = (
            "#!/usr/bin/env bash\n"
            "python3 scripts/lib/upstream_citation_anchor_gate.py"
            " --check --resolve\n"
        )
        COMMENTED = (
            "#!/usr/bin/env bash\n"
            "#   python3 scripts/lib/upstream_citation_anchor_gate.py"
            " --check --resolve\n"
            "echo 'the resolution arm used to run here'\n"
        )
        wired_repo = git_fixture(
            "repo_wired", f"// `{UNICAST}` @ `fn keeper()`\n", runci=WIRED
        )
        commented_repo = git_fixture(
            "repo_commented", f"// `{UNICAST}` @ `fn keeper()`\n", runci=COMMENTED
        )
        for label, got, want in (
            ("the form arm, other arm wired, no checkout",
             verdict(wired_repo, None, False, 0, 0), 0),
            ("the form arm when run-ci.sh only MENTIONS --resolve in a comment",
             verdict(commented_repo, None, False, 0, 0), 1),
            ("the form arm when there is no run-ci.sh at all",
             verdict(anchor_repo, None, False, 0, 0), 1),
            # The wiring check belongs to the FORM arm alone. A resolving run
            # already grades every needle, so making it also demand its own
            # invocation would be a gate asserting it was called.
            ("the RESOLUTION arm, unaffected by the wiring check",
             verdict(anchor_repo, ref, True, 0, 0), 0),
        ):
            if got != want:
                failures.append(f"run() on {label}: expected rc={want}, got {got}")

    for f in failures:
        print(f"  upstream-citation-anchor: SELFTEST FAIL -- {f}", file=sys.stderr)
    if failures:
        return 1
    print(
        "  upstream-citation-anchor: selftest passed -- 8 scan cases (mid-path "
        "match, line past EOF, gone path in both forms, a resolving anchor not "
        "double-counted, a dead needle, a gone anchored file, an empty "
        "population, and this file writing no upstream path literal of its own) "
        "plus 13 run() verdicts -- zero population, no anchored citation, a "
        "budget exceeded, a budget undershot, a mixed tree otherwise clean, a "
        "dead needle with findings as the only live guard, no checkout while "
        "resolving, a clean tree returning 0, the form arm passing with no "
        "checkout, and FOUR on the deferral itself: the other arm wired (0), "
        "named only in a run-ci comment (1), no run-ci.sh at all (1), and the "
        "resolution arm unaffected by any of it (0). MUTATION-CHECKED, each "
        "guard against the rows that exist for it: disabling the budget guard "
        "reds the budget row, disabling the findings guard reds the dead-needle "
        "row, and making `resolution_arm_is_wired` always answer True reds the "
        "comment-only and absent rows and nothing else"
    )
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(
        prog="upstream_citation_anchor_gate.py",
        description="Upstream claims must resolve against the pinned checkout.",
    )
    ap.add_argument("--check", action="store_true", help="read the real tree")
    ap.add_argument("--selftest", action="store_true", help="drive the verdicts")
    ap.add_argument(
        "--resolve",
        action="store_true",
        help="also resolve every path and needle against the pinned checkout "
        "(requires one; without this flag only the FORM arm runs)",
    )
    args = ap.parse_args()
    if args.selftest:
        return selftest()
    return run(ROOT, upstream_root(), resolve=args.resolve)


if __name__ == "__main__":
    sys.exit(main())
