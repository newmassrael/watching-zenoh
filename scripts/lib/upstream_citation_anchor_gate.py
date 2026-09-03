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

## The buckets, and why the scanner places every occurrence in one

Every occurrence of an upstream path lands in exactly ONE bucket, and the
scanner FAILS rather than skipping anything it cannot place:

    ANCHORED  `path` @ `needle`   -- resolved on both halves, or RED
    LINE      path:N              -- the old form, held down by a budget
    BARE      a path, neither     -- named, and held down by its own budget

    ROOTLESS-LINE  seg/...:N      -- a path written WITHOUT its root
    ROOTLESS-BARE  seg/...        -- ditto, neither form

BARE is not an exemption. It is the population that predates the convention,
and like LINE it is locked by a ratchet that can only shrink: a count ABOVE
budget means this commit ADDED one (fix the citation, never the budget), and a
count BELOW means it removed one (lower the budget in the same commit). Open
debt 581 condition (2) asks for exactly this -- gradual, never a bulk rewrite,
but locked so the number cannot drift back up.

## The ROOT-LESS axis (R2317, unregistered open debt 647)

`_PATH` is root-anchored, and it has to be -- see its own comment. The cost is
that a citation written WITHOUT its root is not LINE, not BARE, and not
ANCHORED: it is INVISIBLE. It is counted in no budget, it never reaches the
resolution arm, and so it can never go red no matter how far upstream moves
away from it. Measured on this tree when the axis was added: 172 such
occurrences, and 49 of them named a file that does not exist at the pin --
while the gate printed "407 upstream citation(s)" as though that were the
population.

The invisible set is the one that rots fastest, because nothing grades it.

Root-less citations therefore get their OWN two buckets and their OWN
ratchets, rather than being folded into LINE and BARE. Folding them in would
have meant raising those budgets from 300/60 to 447/85, which is the move this
gate exists to refuse: a budget raised to admit a defect has stopped being a
ratchet.

⚠ THE POPULATION IS DERIVED, NOT LISTED. `ROOTLESS_SEGMENTS` declares which
first segments this axis GRADES, but `rootless_candidates()` derives, from the
tree's own root-anchored citations, every first segment that COULD be one --
and the residue is itself ratcheted. So the declaration cannot quietly be the
whole answer: a segment left undeclared shows up as a number that can only
shrink. That is the R2194 shape -- a declared table is an escape hatch unless a
separate derivation judges it.

The derivation is pin-free on purpose: a directory component of a citation the
tree ALREADY writes root-anchored is, by construction, an upstream directory
name. That runs in both arms, so the FORM arm (which has no checkout) grades
the residue too. Measured: the rule yields 50 candidate segments and admits
none of the tree's non-upstream path-like tokens -- no SCE path, no gate
fixture name, no `OUT_DIR` -- because none of those is a component of any
zenoh path this tree cites.

⚠ WHAT THIS AXIS DOES NOT SEE, stated rather than left implied: a root-less
citation whose FIRST SEGMENT is itself gone upstream (a 1.5.0 directory name)
is not a component of any current citation, so the derivation cannot propose
it, and an abbreviated spelling that was never a directory name at all cannot
be derived by anything. Both are measured residues, filed rather than papered
over.

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

#: First segments that spell an upstream path WITHOUT its root. DECLARED, and
#: judged for completeness by `rootless_candidates()` -- see the module doc.
#: `hat` is the segment R2317 made visible and repaired; the rest of the
#: derived candidate set is held down by `ROOTLESS_UNDECLARED_BUDGET` below.
ROOTLESS_SEGMENTS = ("hat",)

_ROOTLESS_PATH = rf"(?:{'|'.join(ROOTLESS_SEGMENTS)})/[\w/.-]+\.rs"
#: The SAME lookbehind as `_PATH`, and it is what makes this axis safe to add:
#: it blocks a match that starts after a `/`, so the `hat/...` INSIDE a
#: root-anchored citation is not counted a second time here. Measured on this
#: tree: 172 root-less occurrences and 16 root-anchored ones naming a file
#: under the same directory, with no overlap between the two counts.
ROOTLESS_LINE_CITE = re.compile(rf"(?<![\w/.-])({_ROOTLESS_PATH}):(\d+)")
ROOTLESS_BARE_CITE = re.compile(rf"(?<![\w/.-])({_ROOTLESS_PATH})(?!:\d)")

#: Any path-like token, whatever its first segment. Used ONLY to size the
#: undeclared residue; the lookbehind keeps it from matching from inside a
#: longer path, so a root-anchored citation contributes its own first segment
#: (a known root) and nothing else.
_ANY_TOKEN = re.compile(r"(?<![\w/.-])(\w[\w-]*)/[\w/.-]+\.rs")

#: BUDGETS. Measured, frozen, and checked in BOTH directions -- see the module
#: doc. Not a threshold anyone chose.
LINE_BUDGET = 300
BARE_BUDGET = 60
#: The root-less axis, after R2317 repaired the 49 citations that named a file
#: gone at the pin. Same two-directional ratchet as LINE and BARE.
ROOTLESS_LINE_BUDGET = 104
ROOTLESS_BARE_BUDGET = 16
#: Root-less LINE citations whose file EXISTS at the pin but whose line number
#: is past its end -- 1.5.0 line numbers on files that shrank. Measured, not
#: chosen, and graded only by the RESOLUTION arm (it takes a checkout to know).
#: See `_rootless_finding` for why this is a ratchet and the gone-path case is
#: a finding.
ROOTLESS_STALE_LINE_BUDGET = 46
#: Occurrences under a DERIVED candidate segment this axis does not yet grade.
#: This is the residue of open debt 647 made monotone rather than argued: it
#: can only shrink, so declaring a segment forces it down in the same commit,
#: and writing a NEW root-less citation of an undeclared segment reds.
ROOTLESS_UNDECLARED_BUDGET = 736

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


def rootless_candidates(root: pathlib.Path, files: list[str]) -> set[str]:
    """Which first segments COULD spell an upstream path without its root?

    DERIVED, pin-free, from the tree's own root-anchored citations: every
    directory component of a path this tree already writes with its root is an
    upstream directory name by construction. Minus the roots themselves (they
    are not root-LESS) and minus any directory name of THIS tree, because
    `src/lib.rs` and `session/publisher.rs` are ours and naming them is not a
    claim about upstream.

    Pin-free is the point. The completeness check has to run in the FORM arm
    too -- that arm is what every hosted C0 job runs, and a residue graded only
    where a checkout exists is a residue graded almost nowhere.

    ⚠ MEASURED, because the looser rule was tried first and is wrong: dropping
    the "component of a rooted citation" requirement and keeping only "not a
    directory of this tree" yields 80 segments and 203 tokens that match no
    upstream file -- and almost all of that is not upstream at all (SCE's
    `sce-build/...`, this repo's own gate fixtures `alpha/...` and `beta/...`,
    `OUT_DIR/...`). A check that reports those has stopped being about
    citations. The component rule admits none of them.
    """
    own_dirs: set[str] = set()
    for f in files:
        own_dirs.update(pathlib.PurePosixPath(f).parts[:-1])
    roots = set(re.findall(r"\w+", _PATH.split("/")[0]))
    seen: set[str] = set()
    for rel in files:
        try:
            text = (root / rel).read_text(errors="replace")
        except (OSError, UnicodeError):
            continue
        for m in BARE_CITE.finditer(text):
            seen.update(pathlib.PurePosixPath(m.group(1)).parts[:-1])
        for m in LINE_CITE.finditer(text):
            seen.update(pathlib.PurePosixPath(m.group(1)).parts[:-1])
        for m in ANCHOR_CITE.finditer(text):
            seen.update(pathlib.PurePosixPath(m.group(1)).parts[:-1])
    return {s for s in seen if s not in own_dirs and s not in roots}


def rootless_undeclared(root: pathlib.Path, files: list[str]) -> int:
    """How many occurrences sit under a candidate segment this axis does not
    grade? The residue, sized rather than described."""
    cands = rootless_candidates(root, files) - set(ROOTLESS_SEGMENTS)
    if not cands:
        return 0
    n = 0
    for rel in files:
        try:
            text = (root / rel).read_text(errors="replace")
        except (OSError, UnicodeError):
            continue
        for m in _ANY_TOKEN.finditer(text):
            if m.group(1) in cands:
                n += 1
    return n


def rootless_locations(ref: pathlib.Path) -> dict[str, pathlib.Path | None]:
    """Where does each DECLARED segment live at the pin? Globbed, never
    written down -- a location constant here would be a second copy of
    upstream's layout, and the one thing this gate knows about upstream is
    that it moves.

    `None` means the segment is not a UNIQUE directory at the pin, which is a
    FAIL rather than a skip: a declared segment the gate cannot place is a
    population it cannot resolve, and this gate does not report green on those.
    """
    out: dict[str, pathlib.Path | None] = {}
    for seg in ROOTLESS_SEGMENTS:
        hits = sorted({p.parent for p in ref.glob(f"**/{seg}") if p.is_dir()})
        out[seg] = hits[0] if len(hits) == 1 else None
    return out


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


def scan(
    files: list[str],
    root: pathlib.Path,
    ref: pathlib.Path,
    rootless_loc: dict[str, pathlib.Path | None] | None = None,
):
    """Every occurrence, in exactly one bucket. Returns (counts, findings).

    `rootless_loc` is the DECLARED segments' locations at the pin, and `None`
    means "do not resolve the root-less axis" -- the form arm's shape, where
    the counts are still wanted but no path can be looked up.
    """
    counts = {"anchored": 0, "line": 0, "bare": 0, "rootless_line": 0,
              "rootless_bare": 0, "rootless_stale_line": 0}
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
        for m in ROOTLESS_LINE_CITE.finditer(rest):
            counts["rootless_line"] += 1
            got, stale = _rootless_finding(
                rel, m.group(1), int(m.group(2)), ref, rootless_loc, nlines
            )
            findings.extend(got)
            counts["rootless_stale_line"] += stale
        # LINE spans are masked in turn, so `path.rs:12` is not ALSO counted as
        # a bare mention of `path.rs`. Masking with spaces rather than deleting
        # keeps every offset stable across the passes.
        blank = lambda _m: " " * len(_m.group(0))  # noqa: E731
        without_lines = LINE_CITE.sub(blank, rest)
        without_lines = ROOTLESS_LINE_CITE.sub(blank, without_lines)
        for m in BARE_CITE.finditer(without_lines):
            counts["bare"] += 1
            path = m.group(1)
            if not (ref / path).is_file():
                findings.append(
                    Finding(rel, f"`{path}` names a file that is gone at the pin")
                )
        for m in ROOTLESS_BARE_CITE.finditer(without_lines):
            counts["rootless_bare"] += 1
            got, _ = _rootless_finding(
                rel, m.group(1), None, ref, rootless_loc, nlines
            )
            findings.extend(got)
    return counts, findings


def _rootless_finding(
    rel: str,
    path: str,
    n: int | None,
    ref: pathlib.Path,
    rootless_loc: dict[str, pathlib.Path | None] | None,
    nlines,
) -> tuple[list[Finding], int]:
    """Resolve ONE root-less citation. Returns (findings, stale-line count).

    THE PATH IS A FINDING; THE LINE NUMBER IS A RATCHET, and the split is
    deliberate rather than convenient:

    * a path that does not exist at the pin is a claim about a file that is
      GONE, and there is no reading of it that is still true. Open debt 647's
      own subject, and R2317 repaired all 49 of them.
    * a line number past the end of a file that DOES exist is the ordinary rot
      the LINE form was always going to suffer -- which is why the rooted
      population has a budget rather than an amnesty. The root-less population
      had no grading at all until this round, so it arrives with a backlog:
      46 measured. Those are counted by `rootless_stale_line` and held by a
      two-directional ratchet, so the backlog can only shrink and a NEW stale
      line reds. Filed as its own debt rather than folded into 647, because it
      is a different defect with a different repair.

    A budget is not an exemption HERE for the same reason it is not one for
    BARE: the number is printed every run, it is checked in both directions,
    and nothing can raise it.

    `rootless_loc is None` is the form arm and yields nothing -- the counts are
    the form arm's whole product. It is NOT a skip that reports green: `run()`
    prints that the arm resolved nothing and refuses to be the only arm wired.
    """
    if rootless_loc is None:
        return [], 0
    seg = path.split("/", 1)[0]
    loc = rootless_loc.get(seg)
    if loc is None:
        # A declared segment with no unique directory at the pin. Reported per
        # occurrence rather than once, because the repair is per citation: each
        # one has to name where it went, and upstream deleting a directory is
        # exactly when every claim under it needs re-reading.
        return [
            Finding(
                rel,
                f"`{path}` is root-less and its segment `{seg}/` is not a "
                "unique directory at the pin, so nothing can resolve it. "
                "Write the citation with its root, in the `path` @ `needle` "
                "form",
            )
        ], 0
    full = (loc / path).as_posix()
    shown = f"`{path}`" + (f":{n}" if n is not None else "")
    if not (ref / full).is_file():
        return [
            Finding(
                rel,
                f"{shown} is root-less and resolves to `{full}`, which does "
                "not exist at the pin",
            )
        ], 0
    if n is not None and n > nlines(full):
        return [], 1
    return [], 0


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
    rootless_loc = rootless_locations(ref) if resolve and ref is not None else None
    counts, findings = scan(
        files, root, ref if ref is not None else root / ".git", rootless_loc
    )
    if not resolve:
        findings = []
    total = (counts["anchored"] + counts["line"] + counts["bare"]
             + counts["rootless_line"] + counts["rootless_bare"])
    undeclared = rootless_undeclared(root, files)
    candidates = rootless_candidates(root, files)

    where = f"pin at {ref}" if resolve else "FORM arm only"
    print(
        f"  upstream-citation-anchor: {total} upstream citation(s) across "
        f"{len(files)} tracked file(s) -- {counts['anchored']} anchored, "
        f"{counts['line']} line-form (budget {LINE_BUDGET}), "
        f"{counts['bare']} bare (budget {BARE_BUDGET}), "
        f"{counts['rootless_line']}/{counts['rootless_bare']} root-less "
        f"line/bare (budgets {ROOTLESS_LINE_BUDGET}/{ROOTLESS_BARE_BUDGET}) "
        f"over {len(ROOTLESS_SEGMENTS)} declared segment(s); {where}"
    )
    print(
        f"  upstream-citation-anchor: root-less residue -- {undeclared} "
        f"occurrence(s) under {len(candidates - set(ROOTLESS_SEGMENTS))} derived "
        f"candidate segment(s) this axis does not yet grade "
        f"(budget {ROOTLESS_UNDECLARED_BUDGET}); open debt 647"
    )
    if resolve:
        print(
            "  upstream-citation-anchor: root-less stale lines -- "
            f"{counts['rootless_stale_line']} citation(s) name a line past the "
            f"end of a file that still exists (budget "
            f"{ROOTLESS_STALE_LINE_BUDGET}). The PATH of every root-less "
            "citation resolved; these line NUMBERS did not."
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
    if not candidates:
        print(
            "  upstream-citation-anchor: FAIL -- the root-less candidate "
            "derivation found NO segment. It reads the directory components of "
            "this tree's own root-anchored citations, so an empty answer means "
            "those stopped matching, not that the residue is clean.",
            file=sys.stderr,
        )
        rc = 1
    # ⚠ THERE IS DELIBERATELY NO "every DECLARED segment must also be DERIVED"
    # check, and the reason is worth writing down because the first draft had
    # one. The derivation exists to PROPOSE segments nobody declared -- that is
    # what the residue ratchet is for -- and it proposes from root-anchored
    # citations. A declared segment need not have one: the whole point of the
    # axis is citations written WITHOUT a root. Requiring the derivation to
    # re-propose it tests the tree's prose, not the declaration, and it reds on
    # any tree whose root-less citations are the only ones it has. What DOES
    # validate a declaration is `rootless_locations` -- the pin, not our prose --
    # and it FAILs per occurrence when a declared segment is not a unique
    # directory there.
    for name, budget in (
        ("line", LINE_BUDGET),
        ("bare", BARE_BUDGET),
        ("rootless_line", ROOTLESS_LINE_BUDGET),
        ("rootless_bare", ROOTLESS_BARE_BUDGET),
    ):
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
    if resolve and counts["rootless_stale_line"] != ROOTLESS_STALE_LINE_BUDGET:
        got = counts["rootless_stale_line"]
        moved = "ADDED" if got > ROOTLESS_STALE_LINE_BUDGET else "REMOVED"
        print(
            f"  upstream-citation-anchor: FAIL -- {got} root-less line-form "
            f"citation(s) name a line past the end of a file that DOES exist "
            f"at the pin, budget {ROOTLESS_STALE_LINE_BUDGET}. This commit "
            f"{moved} one. Up means a new stale line was written: cite it as "
            "`path` @ `needle` with its root instead. Down means one was "
            "repaired: lower ROOTLESS_STALE_LINE_BUDGET to "
            f"{got} in this same commit so the ratchet holds.",
            file=sys.stderr,
        )
        rc = 1
    if undeclared != ROOTLESS_UNDECLARED_BUDGET:
        moved = "ADDED" if undeclared > ROOTLESS_UNDECLARED_BUDGET else "REMOVED"
        print(
            f"  upstream-citation-anchor: FAIL -- {undeclared} root-less "
            f"occurrence(s) under an UNGRADED candidate segment, budget "
            f"{ROOTLESS_UNDECLARED_BUDGET}. This commit {moved} one. "
            "Up means a new root-less citation was written: give it its root, "
            "in the `path` @ `needle` form. Down means one was repaired or its "
            "segment declared: lower ROOTLESS_UNDECLARED_BUDGET to "
            f"{undeclared} in this same commit so the ratchet holds.",
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
            "against the pinned checkout, every root-less path resolves under "
            "the location the pin gives its segment, and all four legacy forms "
            "plus the two root-less ratchets sit exactly on their budget."
            if resolve
            else "  upstream-citation-anchor: OK (FORM) -- every occurrence is "
            "classified and all four legacy forms sit exactly on their budget. "
            "Nothing here was resolved against upstream, so neither the "
            "root-less paths nor the stale-line ratchet was graded."
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
    #: The root-less axis's fixtures. `SEG` is the declared segment, and it is
    #: read from `ROOTLESS_SEGMENTS` rather than written, so a future round that
    #: declares a different segment cannot leave these rows testing a name the
    #: gate no longer grades.
    SEG = ROOTLESS_SEGMENTS[0]
    ROOTED_RL = _p("zenoh", "src", "net", "routing", SEG, "peer", "mod.rs")
    RL = _p(SEG, "peer", "mod.rs")
    RL_GONE = _p(SEG, "vanished", "mod.rs")
    #: A SECOND segment, never declared, so the residue ratchet has a subject.
    #: It has to be a component of a root-anchored citation the fixture also
    #: carries -- otherwise the derivation does not propose it and the residue is
    #: zero, which is the trap this pair exists to avoid.
    OTHER = "dispatcher"
    ROOTED_OTHER = _p("zenoh", "src", "net", "routing", OTHER, "tables.rs")
    RL_OTHER = _p(OTHER, "tables.rs")
    with tempfile.TemporaryDirectory() as td:
        base = pathlib.Path(td)
        ref = base / "ref"
        (ref / "commons" / "zenoh-protocol" / "src").mkdir(parents=True)
        (ref / "commons" / "zenoh-protocol" / "src" / "lib.rs").write_text("mod x;\n")
        (ref / "io" / "zenoh-link-commons" / "src").mkdir(parents=True)
        (ref / "io" / "zenoh-link-commons" / "src" / "unicast.rs").write_text(
            "fn a() {}\nfn keeper() {}\n"
        )
        (ref / "zenoh" / "src" / "net" / "routing" / SEG / "peer").mkdir(parents=True)
        (ref / ROOTED_RL).write_text("fn hat_keeper() {}\nfn b() {}\n")
        (ref / "zenoh" / "src" / "net" / "routing" / OTHER).mkdir(parents=True)
        (ref / ROOTED_OTHER).write_text("fn other_keeper() {}\n")
        # A SECOND ref where the declared segment is NOT a unique directory, so
        # `rootless_locations` has to answer None and the gate has to refuse.
        ref2 = base / "ref2"
        for extra in ("a", "b"):
            (ref2 / extra / SEG).mkdir(parents=True)
        floc = rootless_locations(ref)
        if floc.get(SEG) is None:
            failures.append(
                f"the fixture ref has one `{SEG}` directory but "
                "rootless_locations() could not place it"
            )
        if rootless_locations(ref2).get(SEG) is not None:
            failures.append(
                f"two `{SEG}` directories must be UNPLACEABLE, not resolved to "
                "the first one -- a gate that guesses which of two it meant has "
                "stopped measuring"
            )

        def scan_text(body: str, loc=None):
            src = base / "src"
            src.mkdir(exist_ok=True)
            (src / "f.rs").write_text(body)
            return scan(["f.rs"], src, ref, loc)

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

        # 6b. THE ROOT-LESS AXIS (R2317). Six rows, and the FIRST is the one the
        #     axis lives or dies on: adding `hat` to a pattern must not make the
        #     `hat/...` INSIDE a root-anchored citation count twice. That is
        #     case 1's defect on the new axis, and the lookbehind is what stops
        #     it -- delete the lookbehind and this row reds while every other
        #     row stays green.
        #     ⚠ THE FIXTURE HAS TO USE THE **LINE** AND **BARE** FORMS, and that
        #     was measured the hard way: the first draft used the ANCHORED form
        #     and the row could not fail, because `scan` MASKS anchored spans
        #     before the root-less passes run -- so the inner segment was
        #     invisible whether the lookbehind was there or not. A control run
        #     with the lookbehind deleted came back GREEN. These two forms are
        #     NOT masked when the root-less passes see them, so they are the
        #     only fixtures that can exercise it.
        c, f = scan_text(f"// {ROOTED_RL}:1\n", floc)
        if (c["line"], c["rootless_line"], c["rootless_bare"]) != (1, 0, 0):
            failures.append(
                f"a root-anchored LINE citation was also counted on the "
                f"root-less axis: {c}"
            )
        c, f = scan_text(f"// see {ROOTED_RL} for it\n", floc)
        if (c["bare"], c["rootless_line"], c["rootless_bare"]) != (1, 0, 0):
            failures.append(
                f"a root-anchored BARE citation was also counted on the "
                f"root-less axis: {c}"
            )
        c, f = scan_text(f"// `{ROOTED_RL}` @ `fn hat_keeper()`\n", floc)
        if (c["anchored"], c["rootless_line"], c["rootless_bare"]) != (1, 0, 0):
            failures.append(
                f"a ROOT-ANCHORED citation was also counted on the root-less "
                f"axis: {c}"
            )
        # A root-less citation lands on the root-less axis and NOWHERE else.
        c, f = scan_text(f"// {RL}:1\n", floc)
        if (c["rootless_line"], c["line"], c["bare"], c["anchored"]) != (1, 0, 0, 0):
            failures.append(f"a root-less line citation was misfiled: {c}")
        if f:
            failures.append(f"a resolving root-less citation red: {f}")
        c, f = scan_text(f"// see {RL} for it\n", floc)
        if (c["rootless_bare"], c["bare"]) != (1, 0):
            failures.append(f"a root-less bare citation was misfiled: {c}")
        # A root-less path that does not exist under the derived location REDS.
        c, f = scan_text(f"// {RL_GONE}:1\n", floc)
        if not f:
            failures.append("a root-less citation of a GONE path did not red")
        # A root-less line PAST EOF is the ratchet, not a finding -- the split
        # `_rootless_finding` documents.
        c, f = scan_text(f"// {RL}:99\n", floc)
        if f:
            failures.append(f"a root-less stale LINE produced a finding: {f}")
        if c["rootless_stale_line"] != 1:
            failures.append(f"a root-less stale LINE was not counted: {c}")
        # `rootless_loc=None` is the FORM arm: counts, no resolution.
        c, f = scan_text(f"// {RL_GONE}:1\n", None)
        if c["rootless_line"] != 1 or f:
            failures.append(f"the form arm resolved the root-less axis: {c} {f}")
        # A declared segment the pin cannot place must RED per occurrence.
        c, f = scan_text(f"// {RL}:1\n", rootless_locations(ref2))
        if not f:
            failures.append(
                "a declared segment that is not a unique directory at the pin "
                "did not red -- an unplaceable population reported green"
            )

        # 6c. THE CANDIDATE DERIVATION, both directions. It reads the directory
        #     components of ROOT-ANCHORED citations, so a tree that cites one
        #     proposes the segment, and a tree that cites none does not.
        cand_src = base / "cand"
        (cand_src / "src").mkdir(parents=True)
        # The fixture file sits under `src/` on purpose: `src` is then a
        # directory of the SCANNED tree, which is what the exclusion row below
        # actually tests. With the file at the root there is no such directory
        # and that row passes without exercising anything.
        cand_f = cand_src / "src" / "f.rs"
        CAND = ["src/f.rs"]
        cand_f.write_text(f"// `{ROOTED_RL}` @ `fn hat_keeper()`\n")
        got = rootless_candidates(cand_src, CAND)
        if SEG not in got:
            failures.append(
                f"the derivation did not propose `{SEG}` from a root-anchored "
                f"citation that names it: {sorted(got)}"
            )
        if "src" in got:
            failures.append(
                "the derivation proposed `src`, which is a directory of the "
                "scanned tree -- ours, not upstream's"
            )
        cand_f.write_text("// nothing upstream here\n")
        if rootless_candidates(cand_src, CAND):
            failures.append("the derivation invented a candidate from no citation")
        # The RESIDUE is sized from the tree, and only for UNDECLARED segments.
        cand_f.write_text(
            f"// `{ROOTED_RL}` @ `fn hat_keeper()`\n"
            f"// `{ROOTED_OTHER}` @ `fn other_keeper()`\n"
            f"// {RL}:1\n"
            f"// {RL_OTHER}:1\n"
        )
        n = rootless_undeclared(cand_src, CAND)
        if n != 1:
            failures.append(
                "the residue must count the UNDECLARED segment only (1 here: "
                f"the `{OTHER}` token, not the declared `{SEG}` one), got {n}"
            )
        # And it must be ZERO when the only root-less token's segment was never
        # proposed -- the arm that keeps SCE paths and gate fixtures out.
        cand_f.write_text(
            f"// `{ROOTED_RL}` @ `fn hat_keeper()`\n"
            f"// {_p('sce-build', 'src', 'generator.rs')}:1\n"
        )
        if rootless_undeclared(cand_src, CAND) != 0:
            failures.append(
                "the residue counted a token whose segment no root-anchored "
                "citation proposes -- that is how a non-upstream path gets in"
            )

        # 8. THE FIXTURE PATHS ARE ASSEMBLED, and this is the arm that keeps
        #    that true. A future edit that inlines one back as a literal makes
        #    this file cite upstream, which is exactly the R2241 defect; the
        #    check is on THIS SOURCE, so it cannot be satisfied by the fixture.
        #    R2317 extended it to the ROOT-LESS patterns for the same reason:
        #    this file now defines a pattern that matches `<seg>/....rs`, so a
        #    literal of that shape written here would be a citation too.
        own = pathlib.Path(__file__).read_text(errors="replace")
        leaked = (
            [m.group(1) for m in BARE_CITE.finditer(own)]
            + [m.group(1) for m in LINE_CITE.finditer(own)]
            + [m.group(1) for m in ROOTLESS_BARE_CITE.finditer(own)]
            + [m.group(1) for m in ROOTLESS_LINE_CITE.finditer(own)]
        )
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
        # A fixture that EXERCISES the root-less axis through `run()`: one
        # root-anchored anchor (so `anchored != 0` and the derivation proposes
        # the segment) plus one root-less line citation.
        rootless_repo = git_fixture(
            "repo_rootless",
            f"// `{ROOTED_RL}` @ `fn hat_keeper()`\n// {RL}:1\n",
        )
        # The same, with a root-less token under an UNDECLARED candidate segment,
        # so the residue ratchet has a population of one.
        residue_repo = git_fixture(
            "repo_residue",
            f"// `{ROOTED_OTHER}` @ `fn other_keeper()`\n// {RL_OTHER}:1\n",
        )
        #: EVERY budget this module carries, so a fixture cannot silently inherit
        #: the real tree's numbers. R2317 added four and the first selftest run
        #: after that reported 120 failures for exactly this reason -- the helper
        #: swapped two of six.
        _BUDGETS = (
            "LINE_BUDGET",
            "BARE_BUDGET",
            "ROOTLESS_LINE_BUDGET",
            "ROOTLESS_BARE_BUDGET",
            "ROOTLESS_STALE_LINE_BUDGET",
            "ROOTLESS_UNDECLARED_BUDGET",
        )
        keep = {name: globals()[name] for name in _BUDGETS}

        def verdict(root: pathlib.Path, r, resolve: bool, line_b: int, bare_b: int,
                    **over: int):
            globals()["LINE_BUDGET"], globals()["BARE_BUDGET"] = line_b, bare_b
            for name in _BUDGETS[2:]:
                globals()[name] = over.get(name, 0)
            try:
                return run(root, r, resolve=resolve)
            finally:
                globals().update(keep)

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
            ("a population of zero",
             verdict(empty_repo, ref, True, keep["LINE_BUDGET"],
                     keep["BARE_BUDGET"],
                     **{k: keep[k] for k in _BUDGETS[2:]}), 1),
            ("no anchored citation", verdict(line_repo, ref, True, 1, 0), 1),
            ("a budget exceeded", verdict(mixed_repo, ref, True, 0, 0), 1),
            ("a budget undershot", verdict(mixed_repo, ref, True, 9, 0), 1),
            ("the mixed fixture otherwise clean", verdict(mixed_repo, ref, True, 1, 0), 0),
            ("a dead needle, findings the only guard",
             verdict(dead_needle_repo, ref, True, 0, 0), 1),
            ("no checkout, resolving", verdict(anchor_repo, None, True, 0, 0), 1),
            ("a clean tree", verdict(anchor_repo, ref, True, 0, 0), 0),
            # R2317 -- the root-less axis's five verdicts. Each fixture is built
            # so the row's own guard is the only one that can fire.
            ("a root-less tree on all four budgets",
             verdict(rootless_repo, ref, True, 0, 0, ROOTLESS_LINE_BUDGET=1), 0),
            ("the root-less line budget exceeded",
             verdict(rootless_repo, ref, True, 0, 0), 1),
            ("the root-less line budget undershot",
             verdict(rootless_repo, ref, True, 0, 0, ROOTLESS_LINE_BUDGET=9), 1),
            ("the root-less stale-line ratchet, off by one",
             verdict(rootless_repo, ref, True, 0, 0, ROOTLESS_LINE_BUDGET=1,
                     ROOTLESS_STALE_LINE_BUDGET=1), 1),
            ("the residue ratchet on budget",
             verdict(residue_repo, ref, True, 0, 0, ROOTLESS_UNDECLARED_BUDGET=1), 0),
            ("the residue ratchet off budget",
             verdict(residue_repo, ref, True, 0, 0), 1),
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
        "  upstream-citation-anchor: selftest passed -- the rooted scan cases "
        "(mid-path match, line past EOF, gone path in both forms, a resolving "
        "anchor not double-counted, a dead needle, a gone anchored file, an "
        "empty population, and this file writing no upstream path literal of "
        "its own), NINE on the root-less axis (a root-anchored LINE, BARE and "
        "ANCHORED citation each NOT double-counted on it; a root-less line and "
        "a root-less bare filed there and nowhere else; a gone root-less path "
        "as a finding; a stale root-less line as a RATCHET and not a finding; "
        "the form arm counting without resolving; and a declared segment the "
        "pin cannot uniquely place reding per occurrence), FIVE on the "
        "candidate derivation (it proposes a segment a rooted citation names, "
        "excludes a directory of the scanned tree, invents nothing from no "
        "citation, sizes the residue over UNDECLARED segments only, and leaves "
        "a token no rooted citation proposes out of it), plus 18 run() "
        "verdicts -- zero population, no anchored citation, a budget exceeded, "
        "a budget undershot, a mixed tree otherwise clean, a dead needle with "
        "findings as the only live guard, no checkout while resolving, a clean "
        "tree returning 0, SIX on the root-less budgets (all four on budget, "
        "the line budget exceeded and undershot, the stale-line ratchet off by "
        "one, the residue ratchet on and off budget), the form arm passing "
        "with no checkout, and FOUR on the deferral itself: the other arm "
        "wired (0), named only in a run-ci comment (1), no run-ci.sh at all "
        "(1), and the resolution arm unaffected by any of it (0). "
        "MUTATION-CHECKED, each guard against the rows that exist for it: "
        "disabling the budget guard reds the budget row, disabling the findings "
        "guard reds the dead-needle row, and making `resolution_arm_is_wired` "
        "always answer True reds the comment-only and absent rows and nothing "
        "else. R2317 ran the same control over its six new guards and one came "
        "back GREEN -- the lookbehind row, whose fixture used the ANCHORED form, "
        "which `scan` masks before the root-less passes; re-cast on the LINE "
        "and BARE forms it reds. The other five red as written: dropping the "
        "gone-path finding, the stale count, the refusal to guess between two "
        "candidate directories, the residue count, and the component rule in "
        "the candidate derivation"
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
