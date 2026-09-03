#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
# SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
r"""R2326 (no register item) — every FOREIGN ORACLE root this tree resolves must
be judged by some provenance mechanism, and every route to one must reach that
judgement.

The citation is `no register item` in the sense `debt_plane_census.py` uses: the
item this closes -- unregistered open-debt item 10 -- lives in an agent-memory
register outside this repository, which has no store id for
`gate_provenance_lint.py` to resolve. The item is named in prose below.

## What item 10 said, and what re-measuring it found

Item 10: "nobody measures a foreign oracle's staleness -- `zenohd_binary` /
`zenoh_pico_cli_binary` just pick the file up if it exists; the comparison
target is not a wz source but the VENDORED SUBMODULE's HEAD."

Re-measured, the item was HALF PAID and half understated.

  * PAID. R2240 built `oracle_pin_gate.py` for the zenohd family after the SHM
    oracle was found the expensive way -- a lane GREEN against a v1.5.0 binary
    that goes RED the moment the oracle is built at the 1.10.0 pin. It derives
    its population from `build-zenohd.sh`'s own `INSTALL_DIR=` assignments and
    reads each binary's `--version`, which is a STRONGER axis than the one item
    10 prescribed: the binary's own answer rather than a claim about it. This
    gate does not re-judge those four; it ASKS that gate which roots it covers
    (`--roots`) and requires the union to be complete.
  * UNDERSTATED. The item named two resolvers. The resolver layer resolves
    SEVEN `target/…` oracle roots, and the two it did not name include
    `target/mbedtls` -- whose headers every pico drop-in compile needs, TLS legs
    included -- and `target/zenoh-pico-build`, whose CMake-generated `config.h`
    is what the pico ABI layout probe measures against. Naming a resolver is
    "who noticed", not the population.

## Why the pico oracles could not use the zenohd mechanism

`oracle_pin_gate.py` asks the binary. MEASURED on 2026-09-04: `strings
target/zenoh-pico-cli/z_put | grep -E '^[0-9]+\.[0-9]+\.[0-9]+'` returns
nothing, and `readelf -d target/zenoh-pico-build/lib/libzenohpico.so` reports
the unversioned soname `libzenohpico.so`. The submodule those were built from is
at `1.9.0-10-g3b3ab65c`, a state no release number names at all. An oracle that
cannot answer has to be GIVEN a record, which is what
`scripts/lib/vendored-oracle.sh` writes and what this gate checks for.

## The two questions, and why both are needed

A stamp nobody reads is not coverage, and a reader with nothing to read is not
either. So the gate asks both, and each population is DERIVED:

1. PROVISIONER coverage. Every resolved root must be judged. The judgement is
   either `oracle_pin_gate.py`'s (asked, not copied) or a stamp written by the
   script that OWNS the root -- found by resolving the root literal to the shell
   variable it is assigned to, then requiring a `vendored_oracle_stamp_root`
   call on that variable. Resolving through the variable is what makes this a
   structural read rather than a keyword sweep: `install-mbedtls.sh` mentions
   its prefix in five places and assigns it in one.
2. CONSUMER coverage. Every `project_root().join("target/<root>…")` site in the
   resolver crate must REACH the provenance assertion -- directly, or by
   delegating to a resolver that does. A root can be perfectly stamped and still
   be read by a fixture that joins the path itself, which is exactly what two
   sites in `pico_abi_option_layout.rs` did before this round.

   This question is asked of STAMPED roots only, and the reason is the
   mechanisms' own nature rather than an exemption. `oracle_pin_gate.py` reads
   the BINARY's `--version`, so it is a LANE STEP that judges a host's oracles
   without any resolver's help -- run-ci Layer C0 runs it unarmed and Layer Z
   `--require`s it, and demanding a second reading at resolver time would be
   one fact checked twice. A STAMP has no lane reading by design (see "What this
   gate does NOT claim"), so for a stamped root the resolver IS the only reader
   and a route that skips it skips everything. The counts of lane-scoped roots
   and of the routes not required because of them are PRINTED, so a deferral
   can never read as coverage.

## What this gate does NOT claim

It judges ROUTES and RECORDS, never freshness. Whether a particular tree's
oracle is actually current is the runtime question, and the runtime is where it
is answered: the Rust `assert_oracle_provenance` refuses a STALE root
unconditionally and an UNSTAMPED one where `WZ_PICO_REQUIRE` is set. A static
gate cannot ask that -- the roots are untracked build output and CI hosts that
never provisioned them are the normal case, so a gate that read them would
report on whichever machine happened to run it.

`vendor/sce` is deliberately outside this population. Its oracle is installed to
`vendor/sce/target/release/`, not under this tree's `target/`, and it has had
its own provenance mechanism since R1994 (`sce-codegen-oracle.sh`, whose token
primitives this round extracted into the shared library). Widening this gate to
reach it would mean a second root convention for no gain.

## A population of zero is a HARD FAIL

Both derivations. A gate that found no subjects must not report a pass -- and
this one has two ways to lose its subject that are worth naming, because both
are edits somebody would plausibly make: renaming the resolver crate's module
path, and rewriting a resolver to build its path some way this reader does not
recognise. Either leaves the tree with no judged oracles and this gate saying
so.
"""

import argparse
import pathlib
import re
import subprocess
import sys
import tempfile
import typing

ROOT = pathlib.Path(__file__).resolve().parents[2]

# The resolver layer: the crate whose `common` module every fixture reaches a
# foreign oracle through, plus its own tests. Both are read because a fixture
# that joins `target/…` itself is precisely the route this gate exists to find.
RESOLVER_LIB = pathlib.Path("crates/wz-integration-tests/src/lib.rs")
RESOLVER_TESTS = pathlib.Path("crates/wz-integration-tests/tests")

# The provisioner scripts, and the pin gate that answers for the zenohd family.
PROVISIONER_DIR = pathlib.Path("scripts")
PIN_GATE = pathlib.Path("scripts/lib/oracle_pin_gate.py")
STAMP_LIB = pathlib.Path("scripts/lib/vendored-oracle.sh")

# `project_root().join("target/zenoh-pico-cli")` and
# `project_root().join("target/zenohd/zenohd")` — the root is the FIRST segment
# after `target/`, because that is the granularity a provisioner owns and a
# stamp records.
RESOLVED_ROOT_RE = re.compile(r'project_root\(\)\s*\.\s*join\(\s*"target/([A-Za-z0-9._-]+)')

# `PREFIX="${WZ_MBEDTLS_PREFIX:-$ROOT/target/mbedtls}"` and
# `INSTALL_DIR="$ROOT/target/zenoh-pico-cli"` — an ASSIGNMENT, so a mention of
# the path in a comment cannot make a script look like the owner.
SHELL_ASSIGN_RE = re.compile(
    r'^\s*([A-Za-z_][A-Za-z0-9_]*)="(?:\$\{[A-Za-z_][A-Za-z0-9_]*:-)?'
    r'\$(?:ROOT|\{ROOT\})/target/([A-Za-z0-9._-]+)\}?"',
    re.M,
)

# `vendored_oracle_stamp_root "$INSTALL_DIR" "$_wzpico_token"`.
STAMP_CALL_RE = re.compile(r'vendored_oracle_stamp_root\s+"\$\{?([A-Za-z_][A-Za-z0-9_]*)\}?"')

# The Rust assertion a route has to reach, and the resolvers that reach it.
ASSERT_FNS = ("assert_oracle_provenance", "assert_zenoh_pico_oracle_fresh")

# `fn name(` / `pub fn name(` — used to attribute a resolved-root site to its
# enclosing function, the same route-attribution idiom `binary_freshness_lint.py`
# uses for the demo corpus.
FN_RE = re.compile(r"^\s*(?:pub(?:\([^)]*\))?\s+)?(?:async\s+)?fn\s+([A-Za-z_][A-Za-z0-9_]*)\s*[(<]")


def pin_gate_roots(root: pathlib.Path) -> set[str]:
    """Which `target/…` roots `oracle_pin_gate.py` judges — ASKED, not copied.

    A failure to ask is a hard failure rather than an empty set: "that gate
    covers nothing" and "we could not reach that gate" are different facts, and
    silently treating the second as the first would make every zenohd root look
    uncovered the day the interpreter changed.
    """
    gate = root / PIN_GATE
    if not gate.is_file():
        raise SystemExit(f"oracle-provenance-gate: FAIL -- {PIN_GATE} is missing")
    proc = subprocess.run(
        [sys.executable, str(gate), "--roots"],
        capture_output=True,
        text=True,
        timeout=120,
        check=False,
    )
    if proc.returncode != 0:
        raise SystemExit(
            f"oracle-provenance-gate: FAIL -- `{PIN_GATE} --roots` exited "
            f"{proc.returncode}; it is this gate's only reading of which roots that "
            f"mechanism covers.\n{proc.stderr.strip()}"
        )
    return {
        line.split("/", 1)[1]
        for line in (l.strip() for l in proc.stdout.splitlines())
        if line.startswith("target/")
    }


def stamped_roots(root: pathlib.Path) -> dict[str, str]:
    """Roots whose owning script stamps them, mapped to that script's path.

    Two structural steps, and the second is the load-bearing one: the root
    literal gives a shell VARIABLE NAME, and the stamp call has to name that
    same variable. Matching the literal against the whole script text would call
    `install-mbedtls.sh` a stamper for any root it merely mentions.
    """
    found: dict[str, str] = {}
    for script in sorted((root / PROVISIONER_DIR).glob("*.sh")):
        text = script.read_text()
        stamped_vars = set(STAMP_CALL_RE.findall(text))
        if not stamped_vars:
            continue
        for var, target_root in SHELL_ASSIGN_RE.findall(text):
            if var in stamped_vars:
                found.setdefault(target_root, str(script.relative_to(root)))
    return found


def enclosing_fn(lines: list[str], index: int) -> tuple[str, int] | None:
    """The `fn` a line sits inside, searching upward. `None` at module scope."""
    for i in range(index, -1, -1):
        m = FN_RE.match(lines[i])
        if m:
            return m.group(1), i
    return None


def fn_body(lines: list[str], start: int) -> str:
    """The source of the function opening at `start`, by brace balance.

    Balanced on the whole line rather than tokenised: a resolver body here is
    plain control flow, and a brace inside a string literal would have to be
    unbalanced to mislead this, which nothing in the corpus is. The next `fn` at
    the same or lower indentation ends the search regardless, so a miscount
    cannot run away over the file.
    """
    depth = 0
    out: list[str] = []
    for line in lines[start:]:
        out.append(line)
        depth += line.count("{") - line.count("}")
        if depth <= 0 and out and "{" in "".join(out):
            break
    return "\n".join(out)


class Route(typing.NamedTuple):
    file: str
    line: int
    root: str
    holder: str
    reaches: bool


def resolved_routes(root: pathlib.Path) -> list["Route"]:
    """Every resolver-layer site that names a `target/<root>` oracle path.

    Read from the LIB and from `tests/`, because the defect is a fixture that
    resolves a root without asking about it -- so the population has to include
    the places that could do that, not only the places meant to.
    """
    sources = [root / RESOLVER_LIB]
    sources.extend(sorted((root / RESOLVER_TESTS).glob("*.rs")))
    routes: list[Route] = []
    for path in sources:
        if not path.is_file():
            continue
        lines = path.read_text().splitlines()
        for index, line in enumerate(lines):
            for m in RESOLVED_ROOT_RE.finditer(line):
                site = enclosing_fn(lines, index)
                if site is None:
                    holder, reaches = "<module scope>", False
                else:
                    holder, fn_start = site
                    body = fn_body(lines, fn_start)
                    reaches = any(f"{fn}(" in body for fn in ASSERT_FNS)
                routes.append(
                    Route(
                        file=str(path.relative_to(root)),
                        line=index + 1,
                        root=m.group(1),
                        holder=holder,
                        reaches=reaches,
                    )
                )
    return routes


def delegating_resolvers(root: pathlib.Path) -> set[str]:
    """Resolver functions that reach the assertion, so a caller of one is covered.

    ONE hop, deliberately. A transitive walk would let a chain of five
    delegations count as coverage, and a reader following it could not say where
    the check actually happens; one hop is what a person reading the resolver
    sees.
    """
    path = root / RESOLVER_LIB
    lines = path.read_text().splitlines()
    reached: set[str] = set()
    for index, line in enumerate(lines):
        m = FN_RE.match(line)
        if not m:
            continue
        body = fn_body(lines, index)
        if any(f"{fn}(" in body for fn in ASSERT_FNS):
            reached.add(m.group(1))
    return reached


def run(root: pathlib.Path) -> int:
    fail: list[str] = []

    if not (root / STAMP_LIB).is_file():
        raise SystemExit(
            f"oracle-provenance-gate: FAIL -- {STAMP_LIB} is missing; it is what every "
            "provisioner stamps through, so its absence means no root can be covered."
        )

    routes = resolved_routes(root)
    if not routes:
        raise SystemExit(
            "oracle-provenance-gate: FAIL -- derived ZERO resolved oracle roots from "
            f"{RESOLVER_LIB} and {RESOLVER_TESTS}. A gate that found no subjects must not "
            "report a pass; the reader has lost its population (a renamed resolver crate, "
            "or a resolver that builds its path some other way)."
        )

    pinned = pin_gate_roots(root)
    stamped = stamped_roots(root)
    if not pinned and not stamped:
        raise SystemExit(
            "oracle-provenance-gate: FAIL -- derived ZERO provenance mechanisms. Every "
            "oracle root would be uncovered by construction, which is a broken reader "
            "rather than a finding."
        )

    delegates = delegating_resolvers(root)

    # (1) PROVISIONER coverage, per root.
    roots = sorted({r.root for r in routes})
    for name in roots:
        if name in pinned:
            print(f"  oracle-provenance-gate: PIN-GATE   target/{name} -- {PIN_GATE.name}")
        elif name in stamped:
            print(f"  oracle-provenance-gate: STAMPED    target/{name} -- {stamped[name]}")
        else:
            fail.append(
                f"  oracle-provenance-gate: UNJUDGED   target/{name} -- resolved by the "
                f"test harness and covered by NO provenance mechanism.\n"
                f"    A foreign oracle that nothing grades survives a pin bump, a branch "
                f"switch and a rebase unchanged, and a stale one does not look stale: it "
                f"renders a confident verdict against an implementation this tree no "
                f"longer carries (R2240 measured that on the SHM zenohd oracle).\n"
                f"    Fix: have the script that assigns this root call "
                f"`vendored_oracle_stamp_root \"$VAR\" \"$token\"` on the SAME variable, "
                f"after the build succeeds."
            )

    # (2) CONSUMER coverage, per route — for STAMPED roots only. A pin-gated
    # root is judged by a lane step reading the binary itself, so there is no
    # resolver-time reading for a route to bypass; see the module doc.
    runtime_roots = set(stamped) - pinned
    deferred = [r for r in routes if r.root in pinned]
    uncovered = [
        r
        for r in routes
        if not r.reaches and r.holder not in delegates and r.root in runtime_roots
    ]
    for r in uncovered:
        fail.append(
            f"  oracle-provenance-gate: UNCHECKED  {r.file}:{r.line} -- `{r.holder}` "
            f"resolves target/{r.root} without reaching a provenance assertion.\n"
            f"    The root is judged, so this is a ROUTE that skips the judgement: the "
            f"stamp is written and read, and this caller does not read it.\n"
            f"    Fix: resolve it through the resolver that grades the root, or call "
            f"`{ASSERT_FNS[0]}` here."
        )

    print(
        f"  oracle-provenance-gate: {len(roots)} resolved root(s) over {len(routes)} route(s); "
        f"{len(pinned & set(roots))} pin-gated, {len(set(stamped) & set(roots))} stamped, "
        f"{len(uncovered)} unchecked route(s)"
    )
    # PRINTED, never silent: these routes were not required to reach a
    # resolver-time assertion because their root's mechanism is a lane step.
    # A deferral that does not say so is indistinguishable from coverage.
    print(
        f"  oracle-provenance-gate: route check DEFERRED for {len(deferred)} route(s) over "
        f"{len(pinned & set(roots))} lane-scoped root(s) "
        f"({', '.join(sorted(pinned & set(roots))) or 'none'}) -- judged by "
        f"{PIN_GATE.name} in run-ci Layer C0 (unarmed) and Layer Z (--require)"
    )
    if fail:
        print()
        for line in fail:
            print(line)
        return 1
    return 0


def selftest() -> int:
    """Drive both derivations against fixtures shaped like the defect.

    Each case is a shape the PRE-R2326 tree actually held, not an invented one:
    an oracle root with no mechanism (`target/zenoh-pico-cli` before this
    round), and a route that joins a judged root directly (the two sites in
    `pico_abi_option_layout.rs`). A fixture that only exercises the fixed shape
    would pass against a reader that had stopped checking.
    """
    failures: list[str] = []

    def build(tmp: pathlib.Path, *, stamp_it: bool, route_checks: bool) -> pathlib.Path:
        (tmp / "scripts/lib").mkdir(parents=True)
        (tmp / RESOLVER_TESTS).mkdir(parents=True)
        (tmp / "crates/wz-integration-tests/src").mkdir(parents=True)
        (tmp / STAMP_LIB).write_text("# stub\n")
        # A pin gate that judges nothing, so the fixtures test THIS gate's
        # derivations rather than the other mechanism's.
        (tmp / PIN_GATE).write_text("import sys\nsys.exit(0)\n")
        # A DECOY that is always stamped, so "this root is uncovered" is
        # distinguishable from "the reader found no mechanisms at all" -- two
        # different verdicts that a fixture carrying only the subject would
        # merge. It names a root the resolver layer never resolves, so it never
        # enters the coverage report itself.
        provisioner = 'ROOT=x\nDECOY_DIR="$ROOT/target/decoy"\n'
        provisioner += 'vendored_oracle_stamp_root "$DECOY_DIR" "$tok"\n'
        provisioner += 'INSTALL_DIR="$ROOT/target/zenoh-pico-cli"\n'
        if stamp_it:
            provisioner += 'vendored_oracle_stamp_root "$INSTALL_DIR" "$tok"\n'
        else:
            # The shape that must NOT count: the root IS assigned and IS
            # mentioned, and the stamp calls name other variables. A reader
            # matching the root literal against the whole script would call
            # this covered.
            provisioner += '# stamp $INSTALL_DIR later, maybe\n'
        (tmp / "scripts/build-fixture.sh").write_text(provisioner)
        check = "        assert_oracle_provenance(&root, None, \"x\");\n" if route_checks else ""
        (tmp / RESOLVER_LIB).write_text(
            "pub fn cli() -> PathBuf {\n"
            '        let root = project_root().join("target/zenoh-pico-cli");\n'
            f"{check}"
            "        root\n"
            "}\n"
        )
        (tmp / RESOLVER_TESTS / "probe.rs").write_text(
            "fn direct() -> PathBuf {\n"
            '    project_root().join("target/zenoh-pico-cli/x")\n'
            "}\n"
        )
        return tmp

    def verdict(**kw: bool) -> int:
        with tempfile.TemporaryDirectory() as d:
            return run(build(pathlib.Path(d), **kw))

    # Unstamped root -> UNJUDGED. The pre-R2326 state of every pico root.
    if verdict(stamp_it=False, route_checks=True) == 0:
        failures.append("an oracle root with no mechanism was reported as covered")
    # Stamped root, but tests/probe.rs joins it directly -> UNCHECKED route.
    if verdict(stamp_it=True, route_checks=True) == 0:
        failures.append("a fixture joining a judged root directly was reported as covered")
    # Stamped root, resolver does not check, so BOTH sites are unchecked routes.
    if verdict(stamp_it=True, route_checks=False) == 0:
        failures.append("a resolver that never asserts was reported as covered")

    # And a shape that must PASS, so the checks above are not passing for the
    # wrong reason: a stamped root whose only routes reach the assertion.
    with tempfile.TemporaryDirectory() as d:
        tmp = build(pathlib.Path(d), stamp_it=True, route_checks=True)
        (tmp / RESOLVER_TESTS / "probe.rs").write_text("fn direct() -> u8 { 0 }\n")
        if run(tmp) != 0:
            failures.append("a fully covered fixture was reported as failing")

    # Both population-zero refusals, which are the two ways this reader can
    # lose its subject. They exit rather than return, so they are the shape a
    # `--selftest` most easily leaves untested.
    for label, mutate in (
        ("no resolved roots", lambda t: (t / RESOLVER_LIB).write_text("fn nothing() {}\n")),
        (
            "no provenance mechanisms",
            lambda t: (t / "scripts/build-fixture.sh").write_text("ROOT=x\n"),
        ),
    ):
        with tempfile.TemporaryDirectory() as d:
            tmp = build(pathlib.Path(d), stamp_it=True, route_checks=True)
            (tmp / RESOLVER_TESTS / "probe.rs").write_text("fn direct() -> u8 { 0 }\n")
            mutate(tmp)
            try:
                run(tmp)
            except SystemExit:
                pass
            else:
                failures.append(f"a fixture with {label} did not hard-fail")

    if failures:
        print("  oracle-provenance-gate: SELFTEST FAILED")
        for f in failures:
            print(f"    - {f}")
        return 1
    print(
        "  oracle-provenance-gate: selftest passed "
        "(3 defect shapes, 2 population-zero refusals, 1 clean)"
    )
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(
        prog="oracle_provenance_gate.py",
        description=(
            "Every foreign-oracle root the test harness resolves must be judged by a "
            "provenance mechanism, and every route to one must reach that judgement."
        ),
    )
    ap.add_argument("--check", action="store_true", help="read the real tree (default)")
    ap.add_argument("--selftest", action="store_true", help="drive the derivations against fixtures")
    args = ap.parse_args()
    if args.selftest:
        return selftest()
    return run(ROOT)


if __name__ == "__main__":
    sys.exit(main())
