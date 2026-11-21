#!/usr/bin/env python3
# SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
# SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
"""R4582 (no register item) -- the completeness scoreboard: wz's architecture is held to be
more complete than zenoh-pico's, and than a deployment's own pico-compatible build, by four
criteria, each a figure that may not get worse.

The owner's decision of 2026-11-21 names the criteria and the form. Each criterion is read
from the gate or the lane that already computes it; this file computes none of them again. It
compares each figure with its row of `deploy/completeness_ratchet.json`, fails on a figure
worse than its row, prints the row to commit when a figure is better, and prints the whole
board with `--report`. `docs/completeness-scoreboard.md` is the reader's page.

## The criteria and where each figure comes from

(a) Upstream tests on wz. zenoh-pico's own API tests and zenoh-c's own tests, run against wz,
    pass at least as many programs as against the original library. Read from the lanes that
    run them (Layer Z for pico, Layer C1cc for zenoh-c) without running anything: the test
    files declare which upstream programs run on wz, which are pinned as unable to link, and
    what the control (the original library) does with each pinned one; the lane's count guard
    in `scripts/run-ci.sh` must agree with the file, or the reading is refused. Two figures
    per suite: the SHORTFALL (programs the original passes and wz does not; the criterion is
    met at 0) and the programs wz passes (a record that may not fall).
(b) A deployment's feature catalogue accepted as default-off switches. The catalogue is a
    document outside this repository, given by path in `WZ_FEATURE_CATALOGUE`; each feature
    names the switch of `deploy/wz-config.toml` that carries it. A feature is accepted when
    the switch exists and a build that names nothing leaves it off. The document, its results
    and its own ratchet stay outside the repository; unset, the criterion is NOT-MEASURED.
(c) Upstream debt zero. The inventory atoms graded PARTIAL (`depth_axis_census.partial_atoms`)
    and the crates and files the logic census leaves unplaced
    (`logic_census_coverage_gate.coverage`), each ratcheted down to 0.
(d) Structural contracts enforced. A fixed list (`CONTRACTS`), each mapped to the gates that
    enforce it. A gate is live when its file exists and a non-comment line of
    `scripts/run-ci.sh` that names it sits in a function a dispatched lane reaches; a contract
    with a dead gate is unenforced, and that figure is held at 0.

## The ratchet

A row is `locked` (the criterion is met: the figure must equal its target), `ratchet` (the
figure may move only in the direction its `better` names) or `local` (criterion (b), whose
figure is never committed). A ratchet row whose figure has a target it does not meet names its
debt: a `debt-` id the store's inventory holds, or `pending:<slug>` until one is filed. A
figure with no row, or a row with no figure, is a failure: the table and the gate move together.

## What this does NOT claim

That a lane PASSED. (a) reads what a lane's guard requires, not a run's result; the lane's own
verdict is the run. (d) holds that a gate is wired, not that it is green.
"""

from __future__ import annotations

import argparse
import dataclasses
import datetime
import json
import os
import pathlib
import re
import shlex
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))

import guarded_count_shell  # noqa: E402
import runci_plan  # noqa: E402

ROOT = pathlib.Path(__file__).resolve().parents[2]
RATCHET = "deploy/completeness_ratchet.json"
RUNCI = "scripts/run-ci.sh"
CATALOGUE_ENV = "WZ_FEATURE_CATALOGUE"
INTEGRATION_TESTS = "crates/wz-integration-tests/tests/it/files"
STATES = ("locked", "ratchet", "local")
BETTER = ("lower", "higher")
DATE = re.compile(r"^\d{4}-\d{2}-\d{2}$")
PENDING_DEBT = re.compile(r"^pending:[a-z0-9][a-z0-9-]*$")
STORE_DEBT = re.compile(r"^debt-[a-z0-9][a-z0-9-]*$")


class Fatal(Exception):
    """A figure that cannot be read. Never a silent pass."""


# ---------------------------------------------------------------------------------------------
# (a) upstream tests on wz
# ---------------------------------------------------------------------------------------------


@dataclasses.dataclass(frozen=True)
class Suite:
    """One upstream test suite: the integration-test files that run it on wz (each one lane
    invocation with a count guard) and, where the tree vendors upstream, the glob of its
    programs, which the files' declarations together must cover exactly."""

    key: str
    title: str
    files: tuple[str, ...]
    upstream_glob: str | None


SUITES: tuple[Suite, ...] = (
    Suite("pico-api", "zenoh-pico API tests",
          ("pico_upstream_api_tests_on_wz", "pico_local_delivery_upstream_tests_on_wz"),
          "vendor/zenoh-pico/tests/z_api_*_test.c"),
    Suite("zenoh-c", "zenoh-c tests", ("zenoh_c_upstream_api_tests_on_wz",), None),
)

# The invocation of a file's `upstream_tests!` macro (not its `macro_rules!` definition), and
# one entry of it: `<kind> <fn> => "<program>"`.
MACRO_BLOCK = re.compile(r"^upstream_tests! \{\n(.*?)^\}", re.M | re.S)
MACRO_ENTRY = re.compile(r'^\s*[a-z]+\s+[a-z0-9_]+\s*=>\s*"([^"]+)"', re.M)
# A test that runs one program by its literal name.
DIRECT_RUN = re.compile(r'\brun_upstream_test\(\s*"([^"]+)"')
# A program wz cannot link, and what the control does with it.
PINNED = re.compile(r'\bpinned\(\s*"([^"]+)"[^;]*?Control::(RunsBesideAZenohd|CannotLink)')


@dataclasses.dataclass
class Declared:
    """What one test file declares about upstream programs."""

    runs: list[str]
    pinned_control_runs: list[str]
    pinned_neither: list[str]

    def tests(self) -> int:
        return len(self.runs) + len(self.pinned_control_runs) + len(self.pinned_neither)


def declared(source: str) -> Declared:
    runs: list[str] = []
    for block in MACRO_BLOCK.finditer(source):
        runs += MACRO_ENTRY.findall(block.group(1))
    runs += DIRECT_RUN.findall(source)
    control: list[str] = []
    neither: list[str] = []
    for prog, verdict in PINNED.findall(source):
        (control if verdict == "RunsBesideAZenohd" else neither).append(prog)
    return Declared(runs, control, neither)


def whole_file_guard(runci: str, stem: str) -> tuple[int, int]:
    """(count, line) of the count guard of the lane invocation that runs every test of
    `stem`: `wz_test_args wz-integration-tests <stem>` with no filter word, then the next
    `_runci_guarded_test`. Exactly one is required."""
    lines = runci.split("\n")
    want = ["wz_test_args", "wz-integration-tests", stem]
    found: list[tuple[int, int]] = []
    for i, line in enumerate(lines):
        if line.split() != want:
            continue
        for j in range(i + 1, min(i + 4, len(lines))):
            words = lines[j].strip().rstrip("\\").strip()
            if not words.startswith("_runci_guarded_test"):
                continue
            try:
                tokens = shlex.split(words)
            except ValueError as exc:
                raise Fatal(f"{RUNCI}:{j + 1}: the guard of {stem} does not read ({exc})") from exc
            if len(tokens) < 3 or not tokens[2].isdigit():
                raise Fatal(f"{RUNCI}:{j + 1}: the guard of {stem} states no exact count")
            found.append((int(tokens[2]), j + 1))
            break
    if len(found) != 1:
        raise Fatal(f"{RUNCI}: {len(found)} whole-file count guard(s) of {stem}; one is read")
    return found[0]


@dataclasses.dataclass
class SuiteReading:
    suite: Suite
    wz_passes: int
    control_passes: int
    population: int
    lanes: list[str]
    population_checked: bool

    @property
    def shortfall(self) -> int:
        return max(0, self.control_passes - self.wz_passes)


def read_suite(suite: Suite, runci: str, sources: dict[str, str], lanes_of_line,
               upstream: list[str] | None) -> SuiteReading:
    """The figures of one suite. `sources` maps a file stem to its text; `upstream` is the
    list of upstream program names when the tree holds them, else None."""
    runs: set[str] = set()
    control: set[str] = set()
    everything: set[str] = set()
    lanes: set[str] = set()
    for stem in suite.files:
        if stem not in sources:
            raise Fatal(f"{INTEGRATION_TESTS}/{stem}.rs is missing: the suite lost its lane")
        decl = declared(sources[stem])
        if not decl.tests():
            raise Fatal(f"{stem}.rs declares no upstream program: the reader lost its subject")
        guard, line = whole_file_guard(runci, stem)
        if guard != decl.tests():
            raise Fatal(f"{RUNCI}:{line} guards {guard} test(s) of {stem} and the file declares "
                        f"{decl.tests()}; `count_guard_lint.py` names which side moved")
        lanes |= set(lanes_of_line(line))
        runs |= set(decl.runs)
        control |= set(decl.runs) | set(decl.pinned_control_runs)
        everything |= set(decl.runs) | set(decl.pinned_control_runs) | set(decl.pinned_neither)
    checked = False
    if upstream:
        missing = sorted(set(upstream) - everything)
        extra = sorted(everything - set(upstream))
        if missing or extra:
            raise Fatal(f"{suite.title}: upstream has {', '.join(missing) or 'nothing'} that no "
                        f"file declares, and the files declare {', '.join(extra) or 'nothing'} "
                        f"upstream does not have")
        checked = True
    return SuiteReading(suite, len(runs), len(control), len(everything), sorted(lanes), checked)


# ---------------------------------------------------------------------------------------------
# (b) a deployment's feature catalogue
# ---------------------------------------------------------------------------------------------

SWITCH = re.compile(r"^(capability|policy|limit):([A-Za-z0-9_-]+)(?:=([a-z0-9-]+))?$")


def switch_verdict(switch: object, decl: dict, default_on) -> str | None:
    """None when `switch` names a switch of the declaration that a build naming nothing
    leaves off, else why not. `default_on(cap, abi)` is `wz_config.default_on`."""
    if not isinstance(switch, str) or not switch:
        return "names no switch"
    m = SWITCH.match(switch)
    if m is None:
        return f"`{switch}` is not `capability:<id>`, `policy:<id>[=<value>]` or `limit:<ID>`"
    kind, sid, value = m.groups()
    if kind == "capability":
        cap = decl["caps"].get(sid)
        if cap is None:
            return f"no capability `{sid}`"
        if value is not None:
            return f"capability `{sid}` takes no value"
        on = [abi for abi in cap.get("abis", []) if default_on(cap, abi)]
        return f"capability `{sid}` is on by default for {', '.join(on)}" if on else None
    if kind == "policy":
        pol = next((p for p in decl["policies"] if p.get("id") == sid), None)
        if pol is None:
            return f"no policy `{sid}`"
        if pol.get("kind") == "bool":
            value = value or "on"
            legal = ["off", "on"]
        else:
            if value is None:
                return f"policy `{sid}` is a choice: name the value that carries the feature"
            legal = list(pol.get("choices", []))
        if value not in legal:
            return f"policy `{sid}` has no value `{value}`"
        if value == pol.get("default"):
            return f"`{sid}={value}` is the policy's default"
        return None
    lim = next((x for x in decl["limits"] if x.get("id") == sid), None)
    if lim is None:
        return f"no limit `{sid}`"
    if value is not None:
        return f"limit `{sid}` takes no value"
    if lim.get("default") != 0:
        return f"limit `{sid}` defaults to {lim.get('default')}, not 0 (off)"
    return None


@dataclasses.dataclass
class CatalogueReading:
    accepted: int
    total: int
    refused: list[tuple[str, str]]
    ratchet: dict | None


def read_catalogue(doc: object, decl: dict, default_on) -> CatalogueReading:
    if not isinstance(doc, dict) or not isinstance(doc.get("features"), list):
        raise Fatal("the catalogue is not a JSON object with a `features` list")
    features = doc["features"]
    if not features:
        raise Fatal("the catalogue lists no feature: nothing would be measured")
    refused: list[tuple[str, str]] = []
    for i, entry in enumerate(features):
        if not isinstance(entry, dict) or not isinstance(entry.get("feature"), str):
            raise Fatal(f"catalogue entry {i} is not an object with a `feature` name")
        why = switch_verdict(entry.get("switch"), decl, default_on)
        if why is not None:
            refused.append((entry["feature"], why))
    ratchet = doc.get("ratchet")
    if ratchet is not None and not (isinstance(ratchet, dict)
                                    and isinstance(ratchet.get("accepted"), int)):
        raise Fatal('the catalogue\'s `ratchet` is not `{"accepted": <int>, "read": <date>}`')
    return CatalogueReading(len(features) - len(refused), len(features), refused, ratchet)


# ---------------------------------------------------------------------------------------------
# (d) structural contracts
# ---------------------------------------------------------------------------------------------


@dataclasses.dataclass(frozen=True)
class Gate:
    """A file that enforces a contract, and the text by which a lane of run-ci.sh runs it."""

    path: str
    needle: str


@dataclasses.dataclass(frozen=True)
class Contract:
    key: str
    holds: str
    gates: tuple[Gate, ...]


CONTRACTS: tuple[Contract, ...] = (
    Contract("layer-direction",
             "the session core names no crate above it, and the pico ABI's core none of its "
             "extension doors",
             (Gate("scripts/lib/layer_direction_gate.py",
                   "scripts/lib/layer_direction_gate.py --check"),)),
    Contract("hourglass-c-abi",
             "each C ABI crate exports a C surface only, its symbol set graded against the "
             "upstream library and its ABI pinned",
             (Gate("scripts/lib/feature_public_surface_census.py",
                   "scripts/lib/feature_public_surface_census.py --check"),
              Gate(f"{INTEGRATION_TESTS}/pico_abi_symbol_census.rs",
                   "wz_test_args wz-integration-tests pico_abi_symbol_census"),
              Gate(f"{INTEGRATION_TESTS}/zenoh_c_abi_symbol_census.rs",
                   "wz_test_args wz-integration-tests zenoh_c_abi_symbol_census"),
              Gate("scripts/lib/capi_c_abi_pin.py", "python3 scripts/lib/capi_c_abi_pin.py"),
              Gate("scripts/lib/abi_stamp_gate.py", "python3 scripts/lib/abi_stamp_gate.py"))),
    Contract("no-allocation-in-operation",
             "an MCU image links no allocator, and a session of the MCU profile allocates "
             "nothing once it is open",
             (Gate("scripts/lib/no_allocator_link_gate.py",
                   "scripts/lib/no_allocator_link_gate.py --population"),
              Gate("crates/wz-session-lwip/tests/session_slot_allocations.rs",
                   "wz_test_args wz-session-lwip session_slot_allocations"),
              Gate("crates/wz-session-lwip/tests/rx_frame_allocations.rs",
                   "wz_test_args wz-session-lwip rx_frame_allocations"),
              Gate("crates/wz-session-lwip/tests/tx_allocations.rs",
                   "wz_test_args wz-session-lwip tx_allocations"))),
    Contract("lock-order",
             "no two of the runtime's locks are taken in both orders: a debug build stops the "
             "thread that closes a cycle",
             (Gate("crates/wz-runtime-tokio/src/sync/lock_order.rs", "WZ_LOCK_ORDER=panic"),)),
)

FN_WORD = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")


def lane_resolver(runci: str):
    """A function from a line number of `runci` to the ids of the lanes that reach it: the
    lanes whose dispatched function is the line's enclosing function or calls it, directly or
    through other functions. A line outside every function, or a comment, reaches none."""
    fns = guarded_count_shell.functions(runci)
    lines = runci.split("\n")
    names = {name for name, _, _ in fns}
    calls: dict[str, set[str]] = {}
    for name, lo, hi in fns:
        code = [line for line in lines[lo:hi - 1] if not line.lstrip().startswith("#")]
        calls[name] = {w for line in code for w in FN_WORD.findall(line) if w in names} - {name}
    reach: dict[str, set[str]] = {}
    for m in runci_plan.DISPATCH.finditer(runci):
        lane, root = m.group(1), m.group(2)
        seen: set[str] = set()
        frontier = [root]
        while frontier:
            fn = frontier.pop()
            if fn in seen:
                continue
            seen.add(fn)
            frontier += sorted(calls.get(fn, set()))
        for fn in seen:
            reach.setdefault(fn, set()).add(lane)

    def lanes_of_line(lineno: int) -> list[str]:
        if lines[lineno - 1].lstrip().startswith("#"):
            return []
        fn = guarded_count_shell.enclosing(fns, lineno)
        return sorted(reach.get(fn, set())) if fn else []

    return lanes_of_line


def gate_lanes(gate: Gate, runci: str, lanes_of_line, exists) -> list[str]:
    """The lanes that run `gate`; empty when its file is missing or no lane names it."""
    if not exists(gate.path):
        return []
    out: set[str] = set()
    for i, line in enumerate(runci.split("\n"), start=1):
        if gate.needle in line:
            out |= set(lanes_of_line(i))
    return sorted(out)


def read_contracts(contracts: tuple[Contract, ...], runci: str, lanes_of_line,
                   exists) -> list[tuple[Contract, list[tuple[Gate, list[str]]]]]:
    return [(c, [(g, gate_lanes(g, runci, lanes_of_line, exists)) for g in c.gates])
            for c in contracts]


# ---------------------------------------------------------------------------------------------
# the ratchet
# ---------------------------------------------------------------------------------------------


def row_problems(name: str, row: object, known_debt) -> list[str]:
    """What is wrong with one row of the table, before any figure is compared."""
    if not isinstance(row, dict):
        return [f"{name}: the row is not an object"]
    state = row.get("state")
    if state not in STATES:
        return [f"{name}: state {state!r} is not one of {', '.join(STATES)}"]
    if state == "local":
        return [] if name.startswith("b.") else [f"{name}: only criterion (b) is local"]
    out: list[str] = []
    if row.get("better") not in BETTER:
        out.append(f"{name}: better {row.get('better')!r} is not one of {', '.join(BETTER)}")
    value, target = row.get("value"), row.get("target")
    if not isinstance(value, int) or isinstance(value, bool):
        out.append(f"{name}: value {value!r} is not an integer")
    if target is not None and (not isinstance(target, int) or isinstance(target, bool)):
        out.append(f"{name}: target {target!r} is not an integer or null")
    if not isinstance(row.get("read"), str) or not DATE.match(row["read"]):
        out.append(f"{name}: read {row.get('read')!r} is not a YYYY-MM-DD date")
    if out:
        return out
    debt = row.get("debt")
    if state == "locked":
        if target is None or value != target:
            out.append(f"{name}: a locked row holds its target; value {value}, target {target}")
        if debt is not None:
            out.append(f"{name}: a locked row carries no debt")
    elif target is not None and value != target:
        if not isinstance(debt, str):
            out.append(f"{name}: short of its target {target}, so it names its debt "
                       f"(`debt-<id>` or `pending:<slug>`)")
        elif STORE_DEBT.match(debt):
            if not known_debt(debt):
                out.append(f"{name}: debt `{debt}` is not in the store's inventory")
        elif not PENDING_DEBT.match(debt):
            out.append(f"{name}: debt {debt!r} is neither `debt-<id>` nor `pending:<slug>`")
    return out


def judge(rows: dict, readings: dict[str, int], known_debt,
          today: str) -> tuple[list[str], list[str]]:
    """(failures, notices) of `readings` against the table `rows`."""
    failures: list[str] = []
    notices: list[str] = []
    for name in sorted(set(readings) - set(rows)):
        failures.append(f"{name} = {readings[name]} has no row in {RATCHET}")
    for name in sorted(rows):
        problems = row_problems(name, rows[name], known_debt)
        if problems:
            failures += problems
            continue
        row = rows[name]
        if row["state"] == "local":
            continue
        if name not in readings:
            failures.append(f"{name}: the row names a figure this gate does not read")
            continue
        now, was, target = readings[name], row["value"], row.get("target")
        if row["state"] == "locked":
            if now != target:
                failures.append(f"{name}: locked at {target} and reads {now}")
            continue
        worse = now > was if row["better"] == "lower" else now < was
        if worse:
            failures.append(f"{name}: reads {now}, worse than its ratchet {was}")
            continue
        if now != was:
            tighter = dict(row, value=now, read=today)
            notices.append(f"{name}: reads {now}, better than {was}; commit the row "
                           f"{json.dumps(tighter, sort_keys=True)}")
        if target is not None and now == target:
            notices.append(f"{name}: meets its target {target}; lock it (state `locked`, "
                           f"debt null)")
    return failures, notices


# ---------------------------------------------------------------------------------------------
# reading the tree
# ---------------------------------------------------------------------------------------------


@dataclasses.dataclass
class Board:
    suites: list[SuiteReading]
    partial: list[str]
    unplaced: list[str]
    contracts: list[tuple[Contract, list[tuple[Gate, list[str]]]]]
    catalogue: CatalogueReading | None

    def readings(self) -> dict[str, int]:
        out: dict[str, int] = {}
        for s in self.suites:
            out[f"a.{s.suite.key}.shortfall"] = s.shortfall
            out[f"a.{s.suite.key}.wz-passes"] = s.wz_passes
        out["c.partial-atoms"] = len(self.partial)
        out["c.logic-census-unplaced"] = len(self.unplaced)
        out["d.contracts-unenforced"] = sum(
            1 for _, gates in self.contracts if any(not lanes for _, lanes in gates))
        return out


def read_catalogue_env() -> CatalogueReading | None:
    path = os.environ.get(CATALOGUE_ENV)
    if not path:
        return None
    import wz_config

    try:
        doc = json.loads(pathlib.Path(path).read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise Fatal(f"{CATALOGUE_ENV} names a catalogue that cannot be read ({exc})") from exc
    return read_catalogue(doc, wz_config.load_decl(), wz_config.default_on)


def read_board() -> Board:
    import depth_axis_census
    import logic_census_coverage_gate

    runci = (ROOT / RUNCI).read_text(encoding="utf-8")
    lanes_of_line = lane_resolver(runci)
    suites: list[SuiteReading] = []
    for suite in SUITES:
        sources = {}
        for stem in suite.files:
            path = ROOT / INTEGRATION_TESTS / f"{stem}.rs"
            if path.is_file():
                sources[stem] = path.read_text(encoding="utf-8")
        upstream = None
        if suite.upstream_glob:
            upstream = sorted(p.stem for p in ROOT.glob(suite.upstream_glob)) or None
        suites.append(read_suite(suite, runci, sources, lanes_of_line, upstream))
    try:
        partial = sorted(depth_axis_census.partial_atoms())
    except depth_axis_census.Fatal as exc:
        raise Fatal(f"the PARTIAL atoms could not be read: {exc}") from exc
    try:
        unplaced, _ = logic_census_coverage_gate.coverage(ROOT)
    except logic_census_coverage_gate.LostSubject as exc:
        raise Fatal(f"the logic census could not be read: {exc}") from exc
    contracts = read_contracts(CONTRACTS, runci, lanes_of_line, lambda p: (ROOT / p).is_file())
    return Board(suites, partial, unplaced, contracts, read_catalogue_env())


def store_debt_ids() -> set[str]:
    import depth_axis_census

    try:
        data = json.loads((ROOT / depth_axis_census.STORE).read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise Fatal(f"the inventory could not be read for the debt ids ({exc})") from exc
    return {eid for eid in data.get("inventory_entries", {}) if eid.startswith("debt-")}


def load_rows() -> dict:
    try:
        data = json.loads((ROOT / RATCHET).read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise Fatal(f"{RATCHET} could not be read ({exc})") from exc
    rows = data.get("figures") if isinstance(data, dict) else None
    if not isinstance(rows, dict) or not rows:
        raise Fatal(f"{RATCHET} holds no `figures` object")
    return rows


def catalogue_judgement(cat: CatalogueReading, today: str) -> tuple[list[str], list[str]]:
    """The catalogue's figure against the ratchet the catalogue itself carries."""
    row = json.dumps({"accepted": cat.accepted, "read": today})
    if cat.ratchet is None:
        return [], [f"b: the catalogue carries no ratchet; add `\"ratchet\": {row}` to it"]
    was = cat.ratchet["accepted"]
    if cat.accepted < was:
        return [f"b: {cat.accepted} feature(s) accepted, fewer than the catalogue's ratchet "
                f"{was}"], []
    if cat.accepted > was:
        return [], [f"b: {cat.accepted} accepted, more than {was}; write {row} into the "
                    f"catalogue's ratchet"]
    return [], []


def check() -> int:
    today = datetime.date.today().isoformat()
    try:
        board = read_board()
        rows = load_rows()
        debt_ids = store_debt_ids()
    except Fatal as exc:
        print(f"completeness: FAIL -- {exc}", file=sys.stderr)
        return 1
    readings = board.readings()
    failures, notices = judge(rows, readings, debt_ids.__contains__, today)
    for contract, gates in board.contracts:
        for gate, lanes in gates:
            if not lanes:
                failures.append(f"d: contract `{contract.key}`: `{gate.path}` is missing or no "
                                f"lane of {RUNCI} runs it (by `{gate.needle}`)")
    if board.catalogue is not None:
        cat_failures, cat_notices = catalogue_judgement(board.catalogue, today)
        failures += cat_failures
        notices += cat_notices
    for notice in notices:
        print(f"  notice: {notice}")
    if failures:
        print("completeness: FAIL", file=sys.stderr)
        for failure in failures:
            print(f"  - {failure}", file=sys.stderr)
        return 1
    cat = board.catalogue
    measured = "NOT-MEASURED" if cat is None else f"{cat.accepted}/{cat.total} accepted"
    print(f"completeness: ok -- {len(readings)} figure(s) held to {RATCHET}; (b) {measured}")
    return 0


def report() -> int:
    try:
        board = read_board()
        rows = load_rows()
    except Fatal as exc:
        print(f"completeness: FAIL -- {exc}", file=sys.stderr)
        return 1
    readings = board.readings()

    def line(name: str) -> str:
        row = rows.get(name, {})
        target = row.get("target")
        return (f"    {name:<28} {readings.get(name, '-'):>5} {row.get('value', '-'):>8} "
                f"{'-' if target is None else target:>7}  {row.get('state', 'NO ROW'):<8} "
                f"{row.get('debt') or ''}")

    print(f"completeness scoreboard ({RATCHET})")
    print(f"    {'figure':<28} {'now':>5} {'ratchet':>8} {'target':>7}  {'state':<8} debt")
    print("(a) upstream tests on wz: what the original passes, wz passes too")
    for s in board.suites:
        pop = "" if s.population_checked else "; population not cross-checked"
        print(f"  {s.suite.title}: wz {s.wz_passes}, original {s.control_passes}, "
              f"{s.population} declared (lanes {', '.join(s.lanes) or 'none'}{pop})")
        print(line(f"a.{s.suite.key}.shortfall"))
        print(line(f"a.{s.suite.key}.wz-passes"))
    print("(b) a deployment's feature catalogue as default-off switches")
    if board.catalogue is None:
        print(f"    NOT-MEASURED ({CATALOGUE_ENV} unset)")
    else:
        cat = board.catalogue
        print(f"    accepted {cat.accepted}/{cat.total}; refused {len(cat.refused)}")
        for feature, why in cat.refused:
            print(f"      - {feature}: {why}")
    print("(c) upstream debt")
    print(line("c.partial-atoms") + (f"  [{', '.join(board.partial)}]" if board.partial else ""))
    print(line("c.logic-census-unplaced"))
    print("(d) structural contracts")
    print(line("d.contracts-unenforced"))
    for contract, gates in board.contracts:
        dead = [g.path for g, lanes in gates if not lanes]
        lanes = sorted({lane for _, ls in gates for lane in ls})
        state = f"DEAD: {', '.join(dead)}" if dead else f"lanes {', '.join(lanes)}"
        print(f"    {contract.key:<28} {len(gates)} gate(s); {state}")
    return 0


# ---------------------------------------------------------------------------------------------
# selftest
# ---------------------------------------------------------------------------------------------

RUNCI_SAMPLE = """\
helper_runs() {
    python3 scripts/lib/alpha_gate.py --check
}
orphan() {
    python3 scripts/lib/beta_gate.py --check
}
layer_x_lane() {
    # python3 scripts/lib/gamma_gate.py --check
    helper_runs || return 1
    wz_test_args wz-integration-tests one_file
    _runci_guarded_test "X one file" 3 \\
        cargo test -p wz-integration-tests "${WZ_TEST_ARGS[@]}" -- --ignored || return 1
    wz_test_args wz-integration-tests two_guards
    _runci_guarded_test X 1 cargo test || return 1
    wz_test_args wz-integration-tests two_guards
    _runci_guarded_test X 1 cargo test || return 1
    wz_test_args wz-integration-tests at_least
    _runci_guarded_test X + cargo test || return 1
    wz_test_args wz-integration-tests one_file one_test
    _runci_guarded_test X 1 cargo test || return 1
}
python3 scripts/lib/delta_gate.py --check
run_layer X layer_x_lane || overall=1
"""

RUST_SAMPLE = """\
macro_rules! upstream_tests {
    ($( $kind:ident $fn_name:ident => $prog:literal ; )+) => {};
}
upstream_tests! {
    alone runs_a => "z_a";
    routed runs_b => "z_b", WITH_X;
}
fn pinned_c() {
    pinned(
        "z_c",
        &Build::default(),
        &["_z_private"],
        Control::RunsBesideAZenohd,
    );
}
fn pinned_d() {
    pinned("z_d", &WITH_HOOKS, &["_z_x"], Control::CannotLink(&["_z_x"]));
}
fn direct() {
    run_upstream_test("z_e");
}
"""


def selftest() -> int:
    failures: list[str] = []

    def expect(name: str, got, want) -> None:
        ok = got == want
        print(f"  selftest -- {name}: {'ok' if ok else f'FAIL got {got!r} want {want!r}'}")
        if not ok:
            failures.append(name)

    def raises(fn) -> str:
        try:
            fn()
        except Fatal as exc:
            return str(exc)
        return ""

    # ---- (a)
    decl = declared(RUST_SAMPLE)
    expect("macro entries and direct runs are what wz runs", sorted(decl.runs),
           ["z_a", "z_b", "z_e"])
    expect("a pinned program the control runs", decl.pinned_control_runs, ["z_c"])
    expect("a pinned program neither links", decl.pinned_neither, ["z_d"])
    expect("a file's tests count every declaration", decl.tests(), 5)
    expect("a whole-file guard is read with a quoted label",
           whole_file_guard(RUNCI_SAMPLE, "one_file"), (3, 11))
    expect("two whole-file guards are refused",
           "2 whole-file" in raises(lambda: whole_file_guard(RUNCI_SAMPLE, "two_guards")), True)
    expect("a guard of no exact count is refused",
           "no exact count" in raises(lambda: whole_file_guard(RUNCI_SAMPLE, "at_least")), True)
    expect("a file with no whole-file guard is refused",
           "0 whole-file" in raises(lambda: whole_file_guard(RUNCI_SAMPLE, "absent")), True)
    lanes = lane_resolver(RUNCI_SAMPLE)
    suite = Suite("s", "sample", ("one_file",), None)
    # z_a and z_b run on wz; z_c only on the control: the three tests the sample lane guards.
    three = (RUST_SAMPLE.replace('run_upstream_test("z_e");', "")
             .replace('pinned("z_d", &WITH_HOOKS, &["_z_x"], Control::CannotLink(&["_z_x"]));',
                      ""))
    got = read_suite(suite, RUNCI_SAMPLE, {"one_file": three}, lanes, None)
    expect("wz passes the programs it runs", got.wz_passes, 2)
    expect("the original also passes the pinned program it runs", got.control_passes, 3)
    expect("the shortfall is what the original passes and wz does not", got.shortfall, 1)
    expect("the suite's lane is the lane of its guard", got.lanes, ["X"])
    expect("a guard that disagrees with the file is refused",
           "guards 3" in raises(lambda: read_suite(suite, RUNCI_SAMPLE,
                                                   {"one_file": RUST_SAMPLE}, lanes, None)),
           True)
    expect("a missing file is refused",
           "missing" in raises(lambda: read_suite(suite, RUNCI_SAMPLE, {}, lanes, None)), True)
    expect("an upstream program no file declares is refused",
           "z_new" in raises(lambda: read_suite(suite, RUNCI_SAMPLE, {"one_file": three}, lanes,
                                                ["z_a", "z_b", "z_c", "z_new"])), True)
    expect("a declared program upstream does not have is refused",
           "z_c" in raises(lambda: read_suite(suite, RUNCI_SAMPLE, {"one_file": three}, lanes,
                                              ["z_a", "z_b"])), True)
    expect("an upstream population the files cover is cross-checked",
           read_suite(suite, RUNCI_SAMPLE, {"one_file": three}, lanes,
                      ["z_a", "z_b", "z_c"]).population_checked, True)

    # ---- (b)
    decl_sample = {
        "caps": {"off-cap": {"id": "off-cap", "abis": ["pico", "c"], "default": "off"},
                 "on-cap": {"id": "on-cap", "abis": ["pico"]},
                 "half-cap": {"id": "half-cap", "abis": ["pico", "c"],
                              "default_off_abis": ["pico"]}},
        "policies": [{"id": "flag", "kind": "bool", "default": "off"},
                     {"id": "mode", "kind": "choice", "choices": ["a", "b"], "default": "a"}],
        "limits": [{"id": "QUOTA", "default": 0}, {"id": "TABLE", "default": 16}],
    }

    def default_on(cap: dict, abi: str) -> bool:
        if abi in cap.get("default_off_abis", []):
            return False
        return cap.get("default", "on") == "on"

    def verdict(switch) -> str:
        return switch_verdict(switch, decl_sample, default_on) or ""

    expect("a default-off capability is accepted", verdict("capability:off-cap"), "")
    expect("a default-on capability is refused", "on by default" in verdict("capability:on-cap"),
           True)
    expect("a capability off for one ABI only is refused",
           "for c" in verdict("capability:half-cap"), True)
    expect("a bool policy carries a feature by `on`", verdict("policy:flag"), "")
    expect("a choice policy carries a feature by a value other than its default",
           verdict("policy:mode=b"), "")
    expect("a choice's default value carries nothing", "default" in verdict("policy:mode=a"),
           True)
    expect("a choice named without its value is refused",
           "name the value" in verdict("policy:mode"), True)
    expect("a value a policy does not have is refused", "no value" in verdict("policy:mode=z"),
           True)
    expect("a limit at 0 is off", verdict("limit:QUOTA"), "")
    expect("a limit in force by default is refused", "not 0" in verdict("limit:TABLE"), True)
    expect("an unknown switch is refused", "no capability" in verdict("capability:nope"), True)
    expect("a feature with no switch is refused", verdict(None), "names no switch")
    expect("a switch of no known kind is refused", "is not" in verdict("axis:x"), True)
    cat = read_catalogue({"features": [{"feature": "f1", "switch": "capability:off-cap"},
                                       {"feature": "f2", "switch": None}],
                          "ratchet": {"accepted": 2, "read": "2026-01-01"}},
                         decl_sample, default_on)
    expect("the accepted fraction", (cat.accepted, cat.total), (1, 2))
    expect("fewer accepted than the catalogue's ratchet fails",
           len(catalogue_judgement(cat, "2026-01-02")[0]), 1)
    expect("an empty catalogue is refused",
           "no feature" in raises(lambda: read_catalogue({"features": []}, decl_sample,
                                                         default_on)), True)

    # ---- (d)
    present = {"scripts/lib/alpha_gate.py", "scripts/lib/beta_gate.py",
               "scripts/lib/gamma_gate.py", "scripts/lib/delta_gate.py"}

    def live(path: str, needle: str) -> list[str]:
        return gate_lanes(Gate(path, needle), RUNCI_SAMPLE, lanes, present.__contains__)

    expect("a gate a lane reaches through a helper is live",
           live("scripts/lib/alpha_gate.py", "alpha_gate.py --check"), ["X"])
    expect("a gate in a function no lane calls is dead",
           live("scripts/lib/beta_gate.py", "beta_gate.py --check"), [])
    expect("a gate named only in a comment is dead",
           live("scripts/lib/gamma_gate.py", "gamma_gate.py --check"), [])
    expect("a gate outside every function is dead",
           live("scripts/lib/delta_gate.py", "delta_gate.py --check"), [])
    expect("a gate whose file is missing is dead",
           live("scripts/lib/gone_gate.py", "alpha_gate.py --check"), [])
    expect("every contract names a gate", all(c.gates for c in CONTRACTS), True)
    expect("contract keys are unique", len({c.key for c in CONTRACTS}), len(CONTRACTS))

    # ---- the ratchet
    def row(**kw) -> dict:
        base = {"state": "ratchet", "better": "lower", "value": 3, "target": 0,
                "read": "2026-01-01", "debt": "pending:x"}
        base.update(kw)
        return base

    def j(rows: dict, readings: dict) -> tuple[list[str], list[str]]:
        return judge(rows, readings, {"debt-known"}.__contains__, "2026-01-02")

    expect("an unchanged figure passes", j({"f": row()}, {"f": 3}), ([], []))
    expect("a worse figure fails", len(j({"f": row()}, {"f": 4})[0]), 1)
    expect("a higher-is-better figure that falls fails",
           len(j({"f": row(better="higher", target=None, debt=None)}, {"f": 2})[0]), 1)
    f, n = j({"f": row()}, {"f": 1})
    expect("a better figure passes and prints the row to commit",
           (f, '"value": 1' in n[0] and '"read": "2026-01-02"' in n[0]), ([], True))
    expect("a figure at its target asks to be locked",
           "lock it" in j({"f": row()}, {"f": 0})[1][-1], True)
    expect("a locked figure that moves fails",
           len(j({"f": row(state="locked", value=0, debt=None)}, {"f": 1})[0]), 1)
    expect("a locked row off its target is refused",
           len(j({"f": row(state="locked", value=2, debt=None)}, {"f": 2})[0]), 1)
    expect("a figure with no row fails", len(j({}, {"f": 0})[0]), 1)
    expect("a row with no figure fails", len(j({"f": row()}, {})[0]), 1)
    expect("a shortfall row without a debt fails", len(j({"f": row(debt=None)}, {"f": 3})[0]), 1)
    expect("a store debt id the store holds passes",
           j({"f": row(debt="debt-known")}, {"f": 3}), ([], []))
    expect("a store debt id the store lacks fails",
           len(j({"f": row(debt="debt-gone")}, {"f": 3})[0]), 1)
    expect("a debt of neither form fails", len(j({"f": row(debt="ZZ")}, {"f": 3})[0]), 1)
    expect("a local row is not compared", j({"b.x": {"state": "local"}}, {}), ([], []))
    expect("only criterion (b) is local", len(j({"a.x": {"state": "local"}}, {})[0]), 1)
    expect("a row whose date does not read fails",
           len(j({"f": row(read="soon")}, {"f": 3})[0]), 1)
    print(f"completeness selftest: {'OK' if not failures else 'FAILED: ' + ', '.join(failures)}")
    return 1 if failures else 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--check", action="store_true")
    group.add_argument("--selftest", action="store_true")
    group.add_argument("--report", action="store_true")
    args = parser.parse_args()
    if args.selftest:
        return selftest()
    return check() if args.check else report()


if __name__ == "__main__":
    sys.exit(main())
