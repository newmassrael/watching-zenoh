#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
# SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

r"""R2316 (no register item) — which `Interest` builder each PLANE may reach for,
so a router-plane emit cannot be served by an api-plane builder.

The citation is `no register item` for the reason `anyke_reader_gate.py` gives
for its own: the item this closes -- unregistered open-debt item 4 -- lives in
the operator's register file, which has no store id for
`gate_provenance_lint.py` to resolve. The item is named in prose below.

## The defect, and why nothing could see it

Open-debt item 4 said wz's outbound Interest carries `extensions: None` -- no
`ext_nodeid`, no `ext_qos`. R2316 re-measured both halves against the pinned
1.10.0 reference and MOST of the item is refuted:

* `ext_nodeid` is `NodeIdType::DEFAULT` at every one of the THIRTEEN Interest
  construction sites upstream has -- the seven api-level ones, where
  `zenoh/src/api/session.rs` @ `ext_nodeid: interest::ext::NodeIdType::DEFAULT`
  occurs seven times, and the six in its routing hats. `DEFAULT` is
  `node_id: 0` and encodes to nothing, so wz omitting it is agreement, not a
  gap.
* `ext_qos` was paid for the api plane by R311y801, which stamped it on
  `build_interest_liveliness_subscriber` and nowhere else -- exactly upstream's
  api-plane split, where `zenoh/src/api/session.rs`
  @ `ext_qos: interest::ext::QoSType::INTEREST` occurs exactly ONCE and the
  other six sites are `DEFAULT`.

What survived is the plane the item did not look at. Every Interest a zenoh
ROUTING HAT propagates carries that same stamp, all six sites, with no
Current/CurrentFuture split: three occurrences in
`zenoh/src/net/routing/hat/client/interests.rs`
@ `ext_qos: interest::ext::QoSType::INTEREST` and three in
`zenoh/src/net/routing/hat/peer/interests.rs`
@ `ext_qos: interest::ext::QoSType::INTEREST`. wz's own propagation --
`LinkstateForwarder::propagate_current_interest` -- reached for the two
API-plane builders by mode, so the CurrentFuture arm was right BY ACCIDENT
(it borrowed a stamp meant for the api plane) and the Current arm went out
bare.

Nothing could see it because the seam's witness counted frames. `a_brokered_
interest_reaches_the_upstream_and_withholds_the_clients_final` asserts
`frame_count == 1`, which is true of a copy carrying anything at all.

## What this gate DERIVES

* STAMPING vs BARE builders -- read out of `interest_build.rs` itself by
  whether each `pub fn build_interest_*` body calls `set_interest_qos`. Not a
  list: a builder joins a set by what its body does, so adding one classifies
  it automatically.
* ROUTER-plane vs API-plane files -- a file is router-plane when its
  production region speaks in `FaceId`. That is the type a module has only if
  it forwards BETWEEN peers; the api-plane emitters (`session/publisher.rs`,
  `session/querier.rs`, `session/mod.rs`, `session/liveliness.rs`) do not
  mention it, and the seven that do are the routing modules.
* The call sites -- every production `build_interest_<name>(` under `crates/`,
  outside the defining file.

Then: every ROUTER-plane call must name a STAMPING builder.

Each population must be NON-EMPTY, in both classes and both builder sets. A
gate whose subject can vanish reports green when the pattern stops matching,
and this one has four ways to lose its subject.

## What it DECLARES, and why that is only one name

`ROUTER_PLANE_BUILDER`. Deriving WHICH stamping builder belongs to the router
plane from the builder itself is not possible without reading its prose, so the
name is declared -- and then judged from four directions that are all derived:
it must exist, it must stamp, at least one router-plane site must call it, and
NO api-plane site may. That last one is the reverse bite: the api plane leaves
`ext_qos` at DEFAULT on six of seven sites, so a fix applied one layer too low
-- stamping the shared `build_liveliness_token_interest` -- would make wz
uniform where upstream is not, and this fails on it.

## The direct-construction ratchet, stated as a ratchet

A router-plane file that writes `InterestOwned { .. }` in production bypasses
every builder and therefore this gate. Production count today is ZERO (the four
literals in the routing modules are all test fixtures), so this arm is a
RATCHET, not coverage: it asserts nothing about the tree as it stands and exists
to fail the first time someone opens that route.
"""

import pathlib
import re
import subprocess
import sys
import tempfile

REPO = pathlib.Path(__file__).resolve().parents[2]

#: Where the builders live. Both the STAMPING/BARE derivation and the
#: "call sites elsewhere" population are defined against this one file.
BUILDER_FILE = "crates/wz-session-core/src/interest_build.rs"

#: The one declared name: the builder the ROUTER plane is meant to use. Judged
#: from four derived directions (see the header) rather than trusted.
ROUTER_PLANE_BUILDER = "build_interest_propagated"

#: A public builder's definition line.
BUILDER_DEF = re.compile(r"^pub fn (build_interest_\w+)\s*\(")

#: The stamp that makes a builder router-plane-capable.
STAMP_CALL = re.compile(r"\bset_interest_qos\s*\(")

#: A call to one of the builders.
BUILDER_CALL = re.compile(r"\b(build_interest_\w+)\s*\(")

#: The type a module holds only if it forwards between peers.
FACE_ID = re.compile(r"\bFaceId\b")

#: A direct envelope construction, which no builder mediates.
DIRECT_BUILD = re.compile(r"\bInterestOwned\s*\{")

#: An inline module's opening line. WHETHER it is a test module is decided
#: separately, from two signals, because neither alone is enough in this tree:
#: `declare_ext_qos.rs` names one `interest_tests` (so "mod tests" misses it),
#: and several are gated by a multi-line `#[cfg(all(test, feature = ...))]`
#: whose attribute sits nowhere a naive `#[cfg(test)]` rule would look -- the
#: shape that broke `anyke_reader_gate.py`'s first draft.
MODULE_OPEN = re.compile(r"^\s*(?:pub(?:\([^)]*\))?\s+)?mod\s+(\w+)\s*\{")

#: An attribute line, accumulated until its brackets close so a multi-line
#: `#[cfg(all(test, ...))]` is read whole.
ATTR_OPEN = re.compile(r"^\s*#\[")

#: A top-level closing brace. `cargo fmt` puts a top-level item's at column 0
#: and indents everything nested, and Layer C1 keeps that true.
MODULE_END = re.compile(r"^\}")


def tracked_rust(repo: pathlib.Path = REPO) -> list[pathlib.Path]:
    """Every tracked Rust source under `crates/`.

    `repo` is a parameter so `findings()` can be driven against a FIXTURE tree
    (R2320, open debt 648). It defaults to this checkout, so every production
    caller is unchanged.
    """
    out = subprocess.run(
        ["git", "-C", str(repo), "ls-files", "crates/**/*.rs", "crates/*.rs"],
        capture_output=True,
        text=True,
        check=True,
    ).stdout.split()
    return [pathlib.Path(p) for p in out]


def test_lines(path: pathlib.Path, lines: list[str]) -> set[int]:
    """The 1-based lines inside a test module.

    A file named `tests.rs` is test code throughout. Otherwise each
    `mod tests {` opens a region running to the next column-0 closing brace; a
    file may hold SEVERAL, which is why this returns a set rather than one
    boundary line.
    """
    if path.name == "tests.rs":
        return set(range(1, len(lines) + 1))
    inside: set[int] = set()
    open_at: int | None = None
    attr_buf = ""  # an attribute whose brackets have not closed yet
    pending = ""  # completed attributes decorating whatever item comes next
    for i, line in enumerate(lines, start=1):
        if open_at is not None:
            inside.add(i)
            if MODULE_END.match(line):
                open_at = None
            continue
        if attr_buf or ATTR_OPEN.match(line):
            attr_buf += line
            if attr_buf.count("[") <= attr_buf.count("]"):
                pending += attr_buf
                attr_buf = ""
            continue
        stripped = line.strip()
        if not stripped or stripped.startswith("//"):
            # Blank lines and doc comments sit between an attribute and the item
            # it decorates, so they must not clear it.
            continue
        m = MODULE_OPEN.match(line)
        if m and ("test" in m.group(1) or "test" in pending):
            open_at = i
            inside.add(i)
        pending = ""
    return inside


def is_comment(line: str) -> bool:
    stripped = line.lstrip()
    return stripped.startswith("//") or stripped.startswith("*")


def classify_builders(text: str) -> tuple[set[str], set[str]]:
    """(stamping, bare) — read out of the builder file's own bodies.

    A builder's region runs from its `pub fn` line to the next one (or to the
    test module / end of file), which is enough to see whether it calls the
    stamp: `cargo fmt` keeps every public item at column 0, so the definitions
    do not nest.

    COMMENT LINES ARE DROPPED from the region first, and that is load-bearing
    rather than tidy: a region ends one line before the NEXT builder's `pub fn`,
    so it swallows that builder's doc comment. A doc that names the stamp --
    which the router-plane builder's does, at length -- would otherwise
    reclassify its bare NEIGHBOUR as stamping.
    """
    lines = text.splitlines()
    in_test = test_lines(pathlib.Path(BUILDER_FILE), lines)
    stop = min(in_test) - 1 if in_test else len(lines)
    starts: list[tuple[int, str]] = []
    for i, line in enumerate(lines[:stop], start=1):
        m = BUILDER_DEF.match(line)
        if m:
            starts.append((i, m.group(1)))
    stamping: set[str] = set()
    bare: set[str] = set()
    for idx, (line_no, name) in enumerate(starts):
        end = starts[idx + 1][0] - 1 if idx + 1 < len(starts) else stop
        body = "\n".join(
            line for line in lines[line_no - 1 : end] if not is_comment(line)
        )
        (stamping if STAMP_CALL.search(body) else bare).add(name)
    return stamping, bare


def is_router_plane(path: pathlib.Path, lines: list[str], in_test: set[int]) -> bool:
    """Whether a file's PRODUCTION region speaks in `FaceId`.

    Production, not the whole file: a test that builds a `FaceId` fixture for a
    session-plane module would otherwise reclassify it, and the api-plane
    emitters' tests do reach for routing fixtures.
    """
    for n, line in enumerate(lines, start=1):
        if n in in_test or is_comment(line):
            continue
        if FACE_ID.search(line):
            return True
    return False


def call_sites(
    repo: pathlib.Path = REPO,
) -> tuple[list[tuple[str, int, str, bool]], list[str]]:
    """Every production builder call outside the builder file.

    Returns `(sites, direct)` where a site is
    `(file, line, builder_name, router_plane)` and `direct` names the
    router-plane files constructing an `InterestOwned` literal in production.

    `repo` threads through to `tracked_rust` for the same reason -- see there.
    """
    sites: list[tuple[str, int, str, bool]] = []
    direct: list[str] = []
    for rel in tracked_rust(repo):
        key = rel.as_posix()
        if key == BUILDER_FILE:
            continue
        path = repo / rel
        try:
            text = path.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError):
            continue
        if "build_interest_" not in text and "InterestOwned" not in text:
            continue
        lines = text.splitlines()
        in_test = test_lines(rel, lines)
        router = is_router_plane(rel, lines, in_test)
        for n, line in enumerate(lines, start=1):
            if n in in_test or is_comment(line):
                continue
            for m in BUILDER_CALL.finditer(line):
                sites.append((key, n, m.group(1), router))
            if router and DIRECT_BUILD.search(line):
                direct.append(f"{key}:{n}")
    return sites, direct


def findings(repo: pathlib.Path = REPO) -> tuple[list[str], dict[str, int]]:
    """Every problem this gate can report, and the counts it prints.

    ⚠ `repo` EXISTS SO THE SELFTEST CAN DRIVE THIS FUNCTION. Open debt 648: for
    its whole life `findings()` was reachable only from `main()`, so its TWELVE
    failure branches were exercised by nothing that would run again -- two had
    ever fired at all, and those two by a control group on the real tree, not by
    a test. Among the ten that had never run were FOUR "the population is empty,
    so FAIL" guards, which exist precisely to stop a zero population reporting
    green: the device against that trap had itself never been tripped.

    The parameter defaults to this checkout, so `main()` is unchanged.
    """
    out: list[str] = []
    builder_path = repo / BUILDER_FILE
    if not builder_path.is_file():
        return ([f"{BUILDER_FILE} does not exist; the builders have moved"], {})
    stamping, bare = classify_builders(builder_path.read_text(encoding="utf-8"))

    if not stamping:
        out.append(
            f"NO builder in {BUILDER_FILE} calls `set_interest_qos`. Either the "
            f"stamp was renamed or the api-plane ext_qos R311y801 paid for is "
            f"gone; either way every router-plane check below has nothing to "
            f"require."
        )
    if not bare:
        out.append(
            f"EVERY builder in {BUILDER_FILE} stamps `ext_qos`. Upstream leaves it "
            f"at DEFAULT on six of its seven api-level Interests "
            f"(`api/session.rs`), so a uniform wz is a wz that diverges -- the "
            f"stamp has been applied a layer too low."
        )

    sites, direct = call_sites(repo)
    router_sites = [s for s in sites if s[3]]
    api_sites = [s for s in sites if not s[3]]

    if not sites:
        out.append(
            "NO production `build_interest_*` call anywhere under crates/. The "
            "population is empty, so every check passed by having nothing to look "
            "at -- the builders have been renamed or the callers have gone."
        )
    if not router_sites:
        out.append(
            "NO production `build_interest_*` call in a router-plane file (one "
            "whose production region speaks in `FaceId`). This gate's whole "
            "subject is that set; empty, it cannot fail."
        )
    if not api_sites:
        out.append(
            "NO production `build_interest_*` call in an api-plane file. The two "
            "planes are what this gate distinguishes, and one of them has "
            "vanished -- the `FaceId` discriminator has stopped discriminating."
        )

    for key, line, name, _ in router_sites:
        if name in bare:
            out.append(
                f"{key}:{line} propagates through `{name}`, which does not stamp "
                f"`ext_qos`. Every one of upstream's six routing-hat propagation "
                f"sites writes `QoSType::INTEREST` -- three in the client hat's "
                f"`interests.rs` and three in the peer hat's -- with no "
                f"Current/CurrentFuture split. Call `{ROUTER_PLANE_BUILDER}`."
            )
        elif name not in stamping:
            out.append(
                f"{key}:{line} calls `{name}`, which {BUILDER_FILE} does not define "
                f"as a public builder. A router-plane emit through an unclassified "
                f"builder is one this gate cannot judge."
            )

    if ROUTER_PLANE_BUILDER not in stamping | bare:
        out.append(
            f"the declared router-plane builder `{ROUTER_PLANE_BUILDER}` is not "
            f"defined in {BUILDER_FILE}; the baseline is stale"
        )
    else:
        if ROUTER_PLANE_BUILDER not in stamping:
            out.append(
                f"`{ROUTER_PLANE_BUILDER}` is declared as the router-plane builder "
                f"and does not call `set_interest_qos`. That is the one thing the "
                f"plane requires of it."
            )
        if not any(name == ROUTER_PLANE_BUILDER for _, _, name, r in sites if r):
            out.append(
                f"no router-plane file calls `{ROUTER_PLANE_BUILDER}`. A builder "
                f"the router never reaches is a fix that has been routed around."
            )
        for key, line, name, _ in api_sites:
            if name == ROUTER_PLANE_BUILDER:
                out.append(
                    f"{key}:{line} calls `{ROUTER_PLANE_BUILDER}` from an api-plane "
                    f"file. Upstream's api plane leaves `ext_qos` at DEFAULT on six "
                    f"of seven sites (`api/session.rs`); stamping here makes wz "
                    f"uniform where upstream is not."
                )

    for where in direct:
        out.append(
            f"{where} builds an `InterestOwned` literal in a router-plane file's "
            f"production code. A direct construction reaches the wire without any "
            f"builder, so no plane rule applies to it -- route it through "
            f"`{ROUTER_PLANE_BUILDER}`."
        )

    counts = {
        "stamping": len(stamping),
        "bare": len(bare),
        "router_calls": len(router_sites),
        "api_calls": len(api_sites),
    }
    return out, counts


CASES: list[tuple[str, str, str, bool]] = [
    # (label, file, body, must_be_reported_as_a_router_plane_bare_call)
    #
    # THE SHAPE THIS GATE WAS BUILT FOR: the pre-R2316 propagation, picking an
    # api-plane builder by mode inside a file that speaks in FaceId.
    (
        "the defect",
        "crates/x/src/y_forward.rs",
        "fn p(&self, f: FaceId) {\n"
        "    let b = build_interest_liveliness_get(1, 0, Some(t));\n"
        "}\n",
        True,
    ),
    (
        "the fix",
        "crates/x/src/y_forward.rs",
        "fn p(&self, f: FaceId) {\n"
        "    let b = build_interest_propagated(1, cf, 0, Some(t));\n"
        "}\n",
        False,
    ),
    # An api-plane file may call a bare builder: that IS upstream's shape.
    (
        "api plane may go bare",
        "crates/x/src/session/mod.rs",
        "fn declare(&self) {\n"
        "    let b = build_interest_liveliness_get(1, 0, Some(t));\n"
        "}\n",
        False,
    ),
    # A router-plane file's TEST fixtures are free to use anything.
    (
        "test module is exempt",
        "crates/x/src/y_forward.rs",
        "fn p(&self, f: FaceId) {}\n"
        "#[cfg(test)]\nmod tests {\n"
        "    fn t() { build_interest_liveliness_get(1, 0, None); }\n"
        "}\n",
        False,
    ),
    # ...including one gated by a multi-line attribute, the shape that keying
    # on `#[cfg(test)]` misreads as production.
    (
        "multi-line-gated test module is exempt",
        "crates/x/src/y_forward.rs",
        "fn p(&self, f: FaceId) {}\n"
        '#[cfg(all(\n  test,\n  feature = "q",\n))]\nmod tests {\n'
        "    fn t() { build_interest_liveliness_get(1, 0, None); }\n"
        "}\n",
        False,
    ),
    # A call named in prose is not a call.
    (
        "a comment is not a call",
        "crates/x/src/y_forward.rs",
        "fn p(&self, f: FaceId) {}\n// use build_interest_liveliness_get here\n",
        False,
    ),
    # FaceId appearing ONLY in a test does not make the file router-plane --
    # the api-plane emitters' own tests do reach for routing fixtures.
    (
        "FaceId in a test does not reclassify",
        "crates/x/src/session/mod.rs",
        "fn declare(&self) { build_interest_liveliness_get(1, 0, None); }\n"
        "#[cfg(test)]\nmod tests {\n"
        "    fn t() { let f = FaceId(0); }\n"
        "}\n",
        False,
    ),
    # A production call AFTER a test module has closed is production again --
    # a single-boundary rule swallows this one.
    (
        "production resumes after a test module",
        "crates/x/src/y_forward.rs",
        "fn q(&self, f: FaceId) {}\n"
        "#[cfg(test)]\nmod tests {\n    fn t() {}\n}\n"
        "fn p(&self) { build_interest_liveliness_get(1, 0, None); }\n",
        True,
    ),
    # A test module NOT named `tests`. `declare_ext_qos.rs` names one
    # `interest_tests`, and a `mod tests`-only rule read its whole body as
    # production -- MEASURED: five calls, all of them assertions.
    (
        "a test module named something else is still a test module",
        "crates/x/src/y_forward.rs",
        "fn p(&self, f: FaceId) {}\n"
        "#[cfg(test)]\nmod interest_tests {\n"
        "    fn t() { build_interest_liveliness_get(1, 0, None); }\n"
        "}\n",
        False,
    ),
    # ...and one gated by a multi-line attribute AND named something else --
    # neither signal alone catches this.
    (
        "cfg(test) reaches a module across a doc comment",
        "crates/x/src/y_forward.rs",
        "fn p(&self, f: FaceId) {}\n"
        '#[cfg(all(\n  test,\n  feature = "q",\n))]\n'
        "/// The interest arm's own tests.\n"
        "mod wire_vectors {\n"
        "    fn t() { build_interest_liveliness_get(1, 0, None); }\n"
        "}\n",
        False,
    ),
    # An ORDINARY module must NOT be swallowed: an attribute that says nothing
    # about tests leaves the module production, whatever it is named.
    (
        "an ordinary gated module stays production",
        "crates/x/src/y_forward.rs",
        "fn p(&self, f: FaceId) {}\n"
        '#[cfg(feature = "routing-peer")]\n'
        "mod broker {\n"
        "    fn t() { build_interest_liveliness_get(1, 0, None); }\n"
        "}\n",
        True,
    ),
    # A `#[cfg(test)]` on something that is NOT a module must not leak onto the
    # next module it happens to precede.
    (
        "a cfg(test) fn does not make the next module a test module",
        "crates/x/src/y_forward.rs",
        "fn p(&self, f: FaceId) {}\n"
        "#[cfg(test)]\nfn helper() {}\n"
        "mod broker {\n"
        "    fn t() { build_interest_liveliness_get(1, 0, None); }\n"
        "}\n",
        True,
    ),
]


def selftest() -> int:
    """Drive the classifier over shapes the tree cannot produce on demand.

    Every case is one the version this replaced would have SWALLOWED or one that
    broke a draft of it -- a fixture the predecessor also handled proves nothing
    about the change.
    """
    failures: list[str] = []
    bare_names = {"build_interest_liveliness_get"}

    for label, name, body, want in CASES:
        rel = pathlib.Path(name)
        lines = body.splitlines()
        in_test = test_lines(rel, lines)
        router = is_router_plane(rel, lines, in_test)
        got = False
        for n, line in enumerate(lines, start=1):
            if n in in_test or is_comment(line):
                continue
            for m in BUILDER_CALL.finditer(line):
                if router and m.group(1) in bare_names:
                    got = True
        if got != want:
            failures.append(f"{label}: reported={got}, want {want}")

    # The builder classifier itself, against a fixture holding one of each. The
    # bodies matter, not the names: that is what makes a new builder classify
    # itself.
    #
    # `build_interest_a` is BARE and is followed by a builder whose DOC names
    # the stamp — the exact adjacency the real file has, and the one a
    # region-to-next-`pub fn` split reclassifies unless comments are dropped.
    # `build_interest_c` is in a test module and must not be classified at all.
    fixture = (
        "pub fn build_interest_a(\n) -> R {\n    inner()\n}\n\n"
        "/// Stamps via `set_interest_qos(..)` because the router plane says so.\n"
        "pub fn build_interest_b(\n) -> R {\n"
        "    let mut i = inner()?;\n"
        "    set_interest_qos(&mut i, QOS_DECLARE);\n"
        "    Ok(i)\n}\n\n"
        "#[cfg(test)]\nmod tests {\n"
        "    pub fn build_interest_c() { set_interest_qos(x); }\n}\n"
    )
    stamping, bare = classify_builders(fixture)
    if stamping != {"build_interest_b"}:
        failures.append(f"classify_builders stamping = {sorted(stamping)}, want [build_interest_b]")
    if bare != {"build_interest_a"}:
        failures.append(f"classify_builders bare = {sorted(bare)}, want [build_interest_a]")

    # A direct envelope construction in a router-plane file's production code.
    direct_body = "fn p(&self, f: FaceId) {\n    let i = InterestOwned {\n    };\n}\n"
    rel = pathlib.Path("crates/x/src/y_forward.rs")
    lines = direct_body.splitlines()
    in_test = test_lines(rel, lines)
    if not (
        is_router_plane(rel, lines, in_test)
        and any(
            DIRECT_BUILD.search(line)
            for n, line in enumerate(lines, start=1)
            if n not in in_test and not is_comment(line)
        )
    ):
        failures.append("the direct-construction ratchet did not fire on its own fixture")

    reported, branch_total = _findings_branches(failures)

    if failures:
        for line in failures:
            print(f"  router-interest-qos SELFTEST FAIL: {line}", file=sys.stderr)
        return 1
    print(
        f"  router-interest-qos: selftest {len(CASES) + 3} predicate case(s) OK, "
        f"plus every one of {branch_total} `findings()` failure branch(es) fired "
        f"from a fixture ({reported} message(s) collected). The branch population "
        "is DERIVED from this file's own syntax tree, not counted by hand"
    )
    return 0


#: The fixture trees that drive `findings()`. Each is (label, files, expected
#: branch-prefix) where `files` maps a repo-relative path to its content; the
#: builder file's own path is `BUILDER_FILE`.
#:
#: ⚠ WHY THIS EXISTS AT ALL (open debt 648). `findings()` was reachable only
#: from `main()`, so its twelve failure branches were exercised by nothing that
#: would run again. TWO had ever fired, and by a control group on the real tree
#: rather than by a test. Four of the ten that had never fired are "the
#: population is empty, so FAIL" guards -- the device that stops a zero
#: population reporting green, itself never once tripped.
#:
#: ⛔ Counting the branches and comparing to a literal would be the R2185 trap
#: ("a gate that checks its own table against its own number can never fail"),
#: so `_findings_branches` DERIVES the branch set from this module's AST and
#: requires every one to have been produced by some fixture below.
_STAMPING_BUILDER = (
    "/// Stamps via `set_interest_qos(..)`.\n"
    "pub fn build_interest_propagated(\n) -> R {\n"
    "    let mut i = inner()?;\n"
    "    set_interest_qos(&mut i, QOS_DECLARE);\n"
    "    Ok(i)\n}\n"
)
_BARE_BUILDER = "pub fn build_interest_bare(\n) -> R {\n    inner()\n}\n"
_ROUTER_CALL = (
    "fn p(&self, f: FaceId) {\n    let _ = build_interest_propagated();\n}\n"
)
_API_CALL = "fn q(&self) {\n    let _ = build_interest_bare();\n}\n"


def _findings_branches(failures: list[str]) -> tuple[int, int]:
    """Fire every `findings()` failure branch from a fixture tree.

    Returns `(messages produced, branches derived)`. Appends to `failures` for
    any branch the fixtures did not reach, which is the only way this can pass:
    the population comes from the AST, so ADDING a thirteenth branch and not
    covering it reds this row.
    """
    import ast

    src = pathlib.Path(__file__).read_text(encoding="utf-8")
    fn = next(
        n
        for n in ast.parse(src).body
        if isinstance(n, ast.FunctionDef) and n.name == "findings"
    )
    wanted: list[str] = []
    for node in ast.walk(fn):
        head = None
        if (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Attribute)
            and node.func.attr == "append"
            and node.args
        ):
            head = node.args[0]
        elif isinstance(node, ast.Return) and isinstance(node.value, ast.Tuple):
            first = node.value.elts[0]
            if isinstance(first, ast.List) and first.elts:
                head = first.elts[0]
        if head is None:
            continue
        chunks = (
            [v.value for v in head.values if isinstance(v, ast.Constant)]
            if isinstance(head, ast.JoinedStr)
            else [head.value] if isinstance(head, ast.Constant) else []
        )
        text = "".join(c for c in chunks if isinstance(c, str)).strip()
        # A distinctive, position-independent fragment of the message. Short
        # ones (`:`, `` ` ``) come from f-strings that OPEN with a substitution,
        # so fall through to the next literal chunk that carries words.
        frag = next(
            (c.strip() for c in chunks
             if isinstance(c, str) and len(c.strip()) >= 12),
            text,
        )
        if frag:
            wanted.append(frag[:40])

    produced: list[str] = []
    with tempfile.TemporaryDirectory() as td:
        base = pathlib.Path(td)

        def tree(name: str, files: dict[str, str]) -> pathlib.Path:
            d = base / name
            d.mkdir()
            subprocess.run(["git", "-C", str(d), "init", "-q"], check=True)
            for rel, body in files.items():
                p = d / rel
                p.parent.mkdir(parents=True, exist_ok=True)
                p.write_text(body, encoding="utf-8")
                subprocess.run(["git", "-C", str(d), "add", rel], check=True)
            return d

        # Each fixture is shaped so it produces the branch(es) it is named for.
        FIXTURES: list[tuple[str, dict[str, str]]] = [
            # the builder file itself is gone -> the early return
            ("gone", {"crates/x/src/a.rs": "fn a() {}\n"}),
            # no builder stamps; no calls at all -> NO stamping + both empty
            # populations + stale baseline
            ("nostamp", {BUILDER_FILE: _BARE_BUILDER}),
            # every builder stamps -> EVERY builder stamps, and the router
            # builder is reached, leaving the api plane empty
            ("allstamp", {
                BUILDER_FILE: _STAMPING_BUILDER,
                "crates/x/src/y_forward.rs": _ROUTER_CALL,
            }),
            # a router-plane call through a BARE builder, plus an api call, so
            # neither plane is empty
            ("bare_router", {
                BUILDER_FILE: _STAMPING_BUILDER + "\n" + _BARE_BUILDER,
                "crates/x/src/y_forward.rs":
                    "fn p(&self, f: FaceId) {\n"
                    "    let _ = build_interest_bare();\n}\n",
                "crates/x/src/api.rs": _API_CALL,
            }),
            # a router-plane call through a builder the builder file does not
            # define at all -> unclassified
            ("unclassified", {
                BUILDER_FILE: _STAMPING_BUILDER,
                "crates/x/src/y_forward.rs":
                    "fn p(&self, f: FaceId) {\n"
                    "    let _ = build_interest_unknown();\n"
                    "    let _ = build_interest_propagated();\n}\n",
            }),
            # the router builder exists but does NOT stamp
            ("router_bare", {
                BUILDER_FILE:
                    "pub fn build_interest_propagated(\n) -> R {\n"
                    "    inner()\n}\n" + _STAMPING_BUILDER.replace(
                        "build_interest_propagated", "build_interest_other"
                    ),
                "crates/x/src/y_forward.rs": _ROUTER_CALL,
                "crates/x/src/api.rs": _API_CALL,
            }),
            # the api plane calls the ROUTER builder
            ("api_calls_router", {
                BUILDER_FILE: _STAMPING_BUILDER + "\n" + _BARE_BUILDER,
                "crates/x/src/y_forward.rs": _ROUTER_CALL,
                "crates/x/src/api.rs":
                    "fn q(&self) {\n"
                    "    let _ = build_interest_propagated();\n}\n",
            }),
            # a direct envelope construction in router-plane production code
            ("direct", {
                BUILDER_FILE: _STAMPING_BUILDER + "\n" + _BARE_BUILDER,
                "crates/x/src/y_forward.rs":
                    "fn p(&self, f: FaceId) {\n"
                    "    let _ = build_interest_propagated();\n"
                    "    let i = InterestOwned {\n    };\n}\n",
                "crates/x/src/api.rs": _API_CALL,
            }),
        ]
        for label, files in FIXTURES:
            got, _counts = findings(tree(label, files))
            if not got:
                failures.append(
                    f"fixture `{label}` produced NO finding -- it was built to "
                    "drive a branch and drove nothing"
                )
            produced.extend(got)

    for frag in wanted:
        if not any(frag in m for m in produced):
            failures.append(
                f"no fixture fired the `findings()` branch beginning {frag!r} -- "
                "the branch population is derived from this file's AST, so a "
                "branch added without a fixture reds here"
            )
    return len(produced), len(wanted)


def main() -> int:
    if "--selftest" in sys.argv:
        return selftest()
    problems, counts = findings()
    if problems:
        print("  router-interest-qos FAIL:", file=sys.stderr)
        for line in problems:
            print(f"    - {line}", file=sys.stderr)
        return 1
    print(
        "  router-interest-qos: {router_calls} router-plane call(s) all through a "
        "stamping builder ({stamping} stamping / {bare} bare; {api_calls} "
        "api-plane call(s) left alone)".format(**counts)
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
