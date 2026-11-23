#!/usr/bin/env python3
# SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
# SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
"""R4618 (no register item) -- the release proof of the pico C ABI Windows DLL, held to zenoh-pico's
own surface and to the lanes it cites.

    release_proof_ledger_gate.py --check
    release_proof_ledger_gate.py --selftest

## What it holds

The owner's release criteria of 2026-11-23 for the Windows DLL (no_std, no heap after open,
os-windows, the one library of the package profile host-peer-ext) ask for a run of every zenoh-pico
feature on that DLL and production evidence for every door zenoh-pico does not have.
`docs/release-proof-pico-windows.md` is the ledger of that evidence: for every public function,
build switch, example and test of zenoh-pico at the pin, and every `wz_ext_*` door, the lanes that
run it and whether one of them runs the release form. This gate keeps the ledger from saying more
than the tree does:

* POPULATIONS. The API rows claim every function zenoh-pico's header declares whose name starts
  `z_`, `zp_` or `ze_` (read by `drop_in_header_gate.upstream_functions`, the one reader of that
  header) and every generic macro of `api/macros.h`, each name by the first row one of whose
  `fnmatch` patterns it matches, and every pattern claims a name. The switch rows are exactly the
  `Z_FEATURE_*` switches of zenoh-pico's CMake (`upstream_switch_map.pico_switches`), each with its
  default. The example and test rows are exactly the programs of those directories. The door rows
  claim every `wz_ext_*` function `wz_ext.h` declares, every `#if` arm kept.
* LANES. Every source file and workflow job a lane names exists, every program pattern matches a
  file, and `release form` is `yes` exactly when the host is Windows, the form `nostd` and the
  profile `host-peer-ext`.
* STATUSES. `proven`, `observed`, `unproven` and `none` are derived from the cited lanes (a gated
  lane of the release form, one that is not gated, lanes of other forms only, no lane) and a row
  stating another is refused. A lane cited on an API row names one of the row's names in its
  programs (comments removed); a lane cited on an example or test row runs that program.
* GAPS. A row short of `proven` names a work item (`W<nn>`), an `n/a` row gives its reason, every
  cited work item exists and every work item is cited.

An empty population or a missing table fails: a reader that stopped matching reads as a ledger
with nothing to prove, which is the one answer this gate must never give.

Exit 0 when the ledger holds, 1 on a finding, 2 on a usage error.
"""

from __future__ import annotations

import fnmatch
import pathlib
import re
import shutil
import sys
import tempfile

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import drop_in_header_gate as dig  # noqa: E402  the one reader of zenoh-pico's header
import upstream_switch_map as usm  # noqa: E402  the one reader of zenoh-pico's switches

ROOT = pathlib.Path(__file__).resolve().parents[2]
LEDGER = ROOT / "docs" / "release-proof-pico-windows.md"
PICO = ROOT / "vendor" / "zenoh-pico"
EXT = ROOT / "crates" / "wz-capi-core" / "include" / "wz_ext.h"

PUBLIC = re.compile(r"(?:z|zp|ze)_\w+")
MACRO = re.compile(r"^\s*#\s*define\s+((?:z|zp|ze)_\w+)", re.M)
NAME_REF = re.compile(r"\b(?:z|zp|ze)_\w+\b")
BLOCK_COMMENT = re.compile(r"/\*.*?\*/", re.S)
LINE_COMMENT = re.compile(r"//[^\n]*")
EXAMPLE_DIRS = ("examples/unix/c11", "examples/unix/c99", "examples/windows")
TEST_SUFFIXES = (".c", ".py", ".sh")
EXT_PREFIX = "wz_ext_"

MARKER = re.compile(r"^<!-- release-proof: ([a-z]+) -->\s*$")
TICKS = re.compile(r"\x60([^\x60]+)\x60")
ANCHORED = re.compile(r"(\x60[^\x60]+\x60)\s*@\s*\x60[^\x60]*\x60")
LANE_ID = re.compile(r"\bL\d{2}\b")
WORK_ID = re.compile(r"\bW\d{2}\b")
LANE_LIST = re.compile(r"L\d{2}(?:,\s*L\d{2})*")
SEPARATOR = re.compile(r":?-{3,}:?")
NOTHING = "—"

TABLES = {
    "lanes": ("lane", "what runs", "programs", "source", "host", "form", "profile", "gated", "release form"),
    "api": ("row", "feature", "names", "lanes", "status", "gap"),
    "switches": ("switch", "pico default", "pico on Windows", "wz", "lanes", "status", "gap"),
    "examples": ("program", "lanes", "status", "gap"),
    "tests": ("program", "kind", "lanes", "status", "gap"),
    "criteria": ("row", "cell", "reading", "lanes", "status", "gap"),
    "ext": ("row", "feature", "doors", "release DLL", "tests", "fuzz", "sanitizer", "coverage floor", "docs", "gap"),
    "work": ("item", "priority", "what", "estimate", "files"),
}
ROW_KEY = {"api": "row", "criteria": "row", "ext": "row", "work": "item", "lanes": "lane"}
ROW_SHAPE = {"api": r"A\d{2}", "criteria": r"C\d{2}", "ext": r"E\d{2}", "work": r"W\d{2}", "lanes": r"L\d{2}"}

HOSTS = ("linux", "windows", "macos")
FORMS = ("std", "nostd")
GATED = ("gate", "observed", "manual")
RELEASE = ("windows", "nostd", "host-peer-ext")
DERIVED = ("proven", "observed", "unproven", "none")
STATED = ("absent", "n/a")
TEST_KINDS = ("api", "program", "internal", "script")
PRIORITIES = ("P0", "P1", "P2")
EVIDENCE = ("tests", "fuzz", "sanitizer", "coverage floor", "docs")


def cells(line: str) -> list[str]:
    return [c.strip() for c in line.strip().strip("|").split("|")]


def ticks(cell: str) -> list[str]:
    return TICKS.findall(cell)


def paths(cell: str) -> list[str]:
    """The files a cell names: its tokens in backticks, each anchored citation (a path, an at sign
    and a needle, the form upstream_citation_anchor_gate.py resolves against the submodule) read
    as its path alone."""
    return ticks(ANCHORED.sub(lambda m: m.group(1), cell))


def tables(text: str) -> tuple[dict[str, list[dict[str, str]]], list[str]]:
    """Each marked table of the ledger as rows of {column: cell}, and findings."""
    lines = text.splitlines()
    out: dict[str, list[dict[str, str]]] = {}
    findings: list[str] = []
    i = 0
    while i < len(lines):
        match = MARKER.match(lines[i])
        i += 1
        if not match:
            continue
        name = match.group(1)
        block = []
        while i < len(lines) and lines[i].startswith("|"):
            block.append(lines[i])
            i += 1
        if name not in TABLES:
            findings.append(f"a marker names a table this gate does not know: {name}")
            continue
        if name in out:
            findings.append(f"table {name} is marked twice")
            continue
        out[name] = []
        if len(block) < 2 or not all(SEPARATOR.fullmatch(c) for c in cells(block[1])):
            findings.append(f"table {name}: no header and separator line right after its marker")
            continue
        header = tuple(cells(block[0]))
        if header != TABLES[name]:
            findings.append(f"table {name}: columns {list(header)}, expected {list(TABLES[name])}")
            continue
        for line in block[2:]:
            row = cells(line)
            if len(row) != len(header):
                findings.append(f"table {name}: a row of {len(row)} cells where {len(header)} are expected: {line}")
                continue
            out[name].append(dict(zip(header, row)))
    for name in TABLES:
        if name not in out:
            findings.append(f"table {name} is missing (no <!-- release-proof: {name} --> marker)")
        elif not out[name]:
            findings.append(f"table {name} has no row")
    return out, findings


def strip_comments(path: str, text: str) -> str:
    if path.endswith((".c", ".h")):
        return LINE_COMMENT.sub(" ", BLOCK_COMMENT.sub(" ", text))
    return text


def lane_list(cell: str, where: str, findings: list[str]) -> list[str]:
    if cell == NOTHING:
        return []
    if not LANE_LIST.fullmatch(cell):
        findings.append(f"{where}: lanes are {NOTHING} or a comma-separated list of lane ids, not '{cell}'")
        return []
    return LANE_ID.findall(cell)


def read_lanes(rows: list[dict[str, str]], root: pathlib.Path, findings: list[str]) -> dict[str, dict]:
    lanes: dict[str, dict] = {}
    for row in rows:
        lid = row["lane"]
        where = f"lane {lid}"
        for column, allowed in (("host", HOSTS), ("form", FORMS), ("gated", GATED), ("release form", ("yes", "no"))):
            if row[column] not in allowed:
                findings.append(f"{where}: {column} '{row[column]}' is not one of {', '.join(allowed)}")
        release = (row["host"], row["form"], row["profile"]) == RELEASE
        if (row["release form"] == "yes") != release:
            findings.append(f"{where}: release form '{row['release form']}', but host {row['host']}, form "
                            f"{row['form']} and profile {row['profile']} make it {'yes' if release else 'no'}")
        sources = ticks(row["source"])
        if not sources:
            findings.append(f"{where}: names no source")
        for source in sources:
            rel, _, job = source.partition("#")
            path = root / rel
            if not path.is_file():
                findings.append(f"{where}: source {rel} does not exist")
                continue
            if job and not re.search(rf"(?m)^  {re.escape(job)}:\s*$", path.read_text(encoding="utf-8")):
                findings.append(f"{where}: {rel} has no job {job}")
        files: set[str] = set()
        if row["programs"] != NOTHING:
            patterns = paths(row["programs"])
            if not patterns:
                findings.append(f"{where}: programs are {NOTHING} or paths in backticks")
            for pattern in patterns:
                if any(ch in pattern for ch in "*?["):
                    matched = {p.relative_to(root).as_posix() for p in root.glob(pattern) if p.is_file()}
                else:
                    matched = {pattern} if (root / pattern).is_file() else set()
                if not matched:
                    findings.append(f"{where}: program {pattern} matches no file")
                files |= matched
        names: set[str] = set()
        for rel in sorted(files):
            names |= set(NAME_REF.findall(strip_comments(rel, (root / rel).read_text(encoding="utf-8", errors="replace"))))
        lanes[lid] = {"release": release, "gated": row["gated"], "files": files, "names": names}
    return lanes


def derived_status(cited: list[str], lanes: dict[str, dict]) -> str:
    release = [lanes[lid] for lid in cited if lid in lanes and lanes[lid]["release"]]
    if any(lane["gated"] == "gate" for lane in release):
        return "proven"
    if release:
        return "observed"
    return "unproven" if cited else "none"


def judge_status(where: str, row: dict[str, str], cited: list[str], lanes: dict[str, dict],
                 findings: list[str]) -> None:
    status, gap = row["status"], row["gap"]
    if status not in DERIVED + STATED:
        findings.append(f"{where}: status '{status}' is not one of {', '.join(DERIVED + STATED)}")
        return
    if status in DERIVED:
        want = derived_status(cited, lanes)
        if status != want:
            findings.append(f"{where}: status {status}, but its lanes make it {want}")
    if status == "proven":
        if gap != NOTHING:
            findings.append(f"{where}: proven, so its gap is {NOTHING}, not '{gap}'")
    elif status == "n/a":
        if gap in ("", NOTHING):
            findings.append(f"{where}: n/a with no reason in its gap")
    elif not WORK_ID.search(gap):
        findings.append(f"{where}: {status} and its gap names no work item")


def claim(rows: list[dict[str, str]], key: str, column: str, population: set[str], what: str,
          findings: list[str]) -> dict[str, set[str]]:
    """Each name of the population to the first row one of whose patterns matches it."""
    patterns = {row[key]: ticks(row[column]) for row in rows}
    claimed: dict[str, set[str]] = {row[key]: set() for row in rows}
    if not population:
        findings.append(f"the population of {what} is empty: its reader stopped matching")
    for name in sorted(population):
        for row in rows:
            if any(fnmatch.fnmatchcase(name, p) for p in patterns[row[key]]):
                claimed[row[key]].add(name)
                break
        else:
            findings.append(f"{what}: {name} is claimed by no row")
    for row in rows:
        if not patterns[row[key]]:
            findings.append(f"{what} {row[key]}: names no pattern")
        for pattern in patterns[row[key]]:
            if not any(fnmatch.fnmatchcase(n, pattern) for n in claimed[row[key]]):
                findings.append(f"{what} {row[key]}: pattern {pattern} claims no name (an earlier row "
                                f"took them, or none is declared)")
    return claimed


def program_rows(rows: list[dict[str, str]], population: set[str], what: str, lanes: dict[str, dict],
                 findings: list[str]) -> set[str]:
    seen: set[str] = set()
    cited_all: set[str] = set()
    for row in rows:
        named = paths(row["program"])
        if len(named) != 1:
            findings.append(f"{what}: a row names {len(named)} programs, not one: {row['program']}")
            continue
        program = named[0]
        where = f"{what} {program}"
        if program in seen:
            findings.append(f"{where}: two rows")
        seen.add(program)
        cited = lane_list(row["lanes"], where, findings)
        cited_all |= set(cited)
        for lid in cited:
            if lid in lanes and lanes[lid]["files"] and program not in lanes[lid]["files"]:
                findings.append(f"{where}: cites {lid}, which does not run it")
        judge_status(where, row, cited, lanes, findings)
        if what == "tests":
            if row["kind"] not in TEST_KINDS:
                findings.append(f"{where}: kind '{row['kind']}' is not one of {', '.join(TEST_KINDS)}")
            elif row["kind"] == "internal" and row["status"] != "n/a":
                findings.append(f"{where}: a test of zenoh-pico's private code reads n/a, not {row['status']}")
    for program in sorted(population - seen):
        findings.append(f"{what}: {program} has no row")
    for program in sorted(seen - population):
        findings.append(f"{what}: {program} is a row and not a program of zenoh-pico at the pin")
    return cited_all


def check(text: str, pops: dict, root: pathlib.Path) -> list[str]:
    """Findings of the ledger `text` against the populations `pops` (api, switches, switch_defaults,
    examples, tests, ext) and the files under `root`."""
    found, findings = tables(text)
    for name, key in ROW_KEY.items():
        ids = [row[key] for row in found.get(name, [])]
        for rid in ids:
            if not re.fullmatch(ROW_SHAPE[name], rid):
                findings.append(f"table {name}: row id '{rid}' is not of the form {ROW_SHAPE[name]}")
        for rid in sorted({r for r in ids if ids.count(r) > 1}):
            findings.append(f"table {name}: {rid} is two rows")
    lanes = read_lanes(found.get("lanes", []), root, findings)
    cited_lanes: set[str] = set()

    api_rows = found.get("api", [])
    claimed = claim(api_rows, "row", "names", pops["api"], "the API", findings)
    for row in api_rows:
        where = f"API {row['row']}"
        cited = lane_list(row["lanes"], where, findings)
        cited_lanes |= set(cited)
        for lid in cited:
            if lid in lanes and lanes[lid]["files"] and not claimed.get(row["row"], set()) & lanes[lid]["names"]:
                findings.append(f"{where}: cites {lid}, whose programs name none of its names")
        judge_status(where, row, cited, lanes, findings)

    seen_switches: set[str] = set()
    for row in found.get("switches", []):
        named = ticks(row["switch"])
        switch = named[0] if len(named) == 1 else row["switch"]
        where = f"switch {switch}"
        if switch in seen_switches:
            findings.append(f"{where}: two rows")
        seen_switches.add(switch)
        default = pops["switch_defaults"].get(switch)
        if row["pico default"] not in ("on", "off"):
            findings.append(f"{where}: pico default '{row['pico default']}' is not on or off")
        elif default is not None and (row["pico default"] == "on") != (default == "1"):
            findings.append(f"{where}: pico default {row['pico default']}, but zenoh-pico's CMake sets {default}")
        if row["pico on Windows"] not in ("yes", "no"):
            findings.append(f"{where}: pico on Windows '{row['pico on Windows']}' is not yes or no")
        elif row["pico on Windows"] == "no" and row["status"] != "n/a":
            findings.append(f"{where}: zenoh-pico has no such feature on Windows, so it reads n/a, not {row['status']}")
        cited = lane_list(row["lanes"], where, findings)
        cited_lanes |= set(cited)
        judge_status(where, row, cited, lanes, findings)
    if not pops["switches"]:
        findings.append("the population of switches is empty: its reader stopped matching")
    for switch in sorted(pops["switches"] - seen_switches):
        findings.append(f"switches: {switch} has no row")
    for switch in sorted(seen_switches - pops["switches"]):
        findings.append(f"switches: {switch} is a row and not a switch of zenoh-pico at the pin")

    cited_lanes |= program_rows(found.get("examples", []), pops["examples"], "examples", lanes, findings)
    cited_lanes |= program_rows(found.get("tests", []), pops["tests"], "tests", lanes, findings)

    for row in found.get("criteria", []):
        where = f"criterion {row['row']}"
        cited = lane_list(row["lanes"], where, findings)
        cited_lanes |= set(cited)
        judge_status(where, row, cited, lanes, findings)

    ext_rows = found.get("ext", [])
    claim(ext_rows, "row", "doors", pops["ext"], "the doors", findings)
    for row in ext_rows:
        where = f"door row {row['row']}"
        carried = row["release DLL"]
        if carried not in ("yes", "no"):
            findings.append(f"{where}: release DLL '{carried}' is not yes or no")
            continue
        if carried == "no":
            if row["gap"] in ("", NOTHING):
                findings.append(f"{where}: not in the release DLL, and its gap gives no reason")
            continue
        for column in EVIDENCE:
            cell = row[column]
            if cell in ("", NOTHING):
                findings.append(f"{where}: carried by the release DLL and its {column} cell is empty")
            elif cell.startswith("none") and not WORK_ID.search(row["gap"]):
                findings.append(f"{where}: {column} reads none and its gap names no work item")
            for token in ticks(cell):
                if "/" in token and not (root / token).exists():
                    findings.append(f"{where}: {column} names {token}, which does not exist")
            cited_lanes |= set(LANE_ID.findall(cell))

    work_rows = found.get("work", [])
    items = {row["item"] for row in work_rows}
    for row in work_rows:
        if row["priority"] not in PRIORITIES:
            findings.append(f"work {row['item']}: priority '{row['priority']}' is not one of {', '.join(PRIORITIES)}")
    cited_work: set[str] = set()
    for name in ("api", "switches", "examples", "tests", "criteria", "ext"):
        for row in found.get(name, []):
            cited_work |= set(WORK_ID.findall(row["gap"]))
            for cell in row.values():
                for lid in LANE_ID.findall(cell):
                    if lid not in lanes:
                        findings.append(f"table {name}: cites {lid}, which is not a lane")
    for item in sorted(cited_work - items):
        findings.append(f"{item} is cited and is not a work item")
    for item in sorted(items - cited_work):
        findings.append(f"work {item} is cited by no row")
    for lid in sorted(set(lanes) - cited_lanes):
        findings.append(f"lane {lid} is cited by no row")
    return findings


def ext_doors(header: str) -> set[str]:
    """The `wz_ext_*` functions a header declares in any of its `#if` arms: its text with the
    comments removed, read by the drop-in gate's declaration reader."""
    text = LINE_COMMENT.sub(" ", BLOCK_COMMENT.sub(" ", header))
    return {n for n in dig.declared_functions(text)
            if n.startswith(EXT_PREFIX) and not n.endswith(("_fn", "_t"))}


def populations(root: pathlib.Path, pico: pathlib.Path, ext: pathlib.Path) -> tuple[dict, list[str]]:
    findings: list[str] = []
    upstream, more = dig.upstream_functions(pico)
    findings += more
    api = {n for n in upstream if PUBLIC.fullmatch(n) and not n.endswith("_t")}
    macros = pico / "include" / "zenoh-pico" / "api" / "macros.h"
    api |= set(MACRO.findall(macros.read_text(encoding="utf-8")))
    try:
        _, switches = usm.pico_switches(pico)
    except usm.InputError as exc:
        findings.append(str(exc))
        switches = set()
    defaults = usm.cmake_defaults(usm.pico_cmake_text(pico))
    examples = {p.relative_to(root).as_posix() for d in EXAMPLE_DIRS for p in (pico / d).glob("*.c")}
    tests = {p.relative_to(root).as_posix() for p in (pico / "tests").iterdir()
             if p.is_file() and p.suffix in TEST_SUFFIXES}
    return {
        "api": api,
        "switches": {s for s in switches if s.startswith("Z_FEATURE_")},
        "switch_defaults": {k: v for k, v in defaults.items() if k.startswith("Z_FEATURE_")},
        "examples": examples,
        "tests": tests,
        "ext": ext_doors(ext.read_text(encoding="utf-8")),
    }, findings


def tally(text: str) -> str:
    found, _ = tables(text)
    parts = []
    for name in ("api", "switches", "examples", "tests", "criteria"):
        counts: dict[str, int] = {}
        for row in found.get(name, []):
            counts[row["status"]] = counts.get(row["status"], 0) + 1
        parts.append(f"{name} " + ", ".join(f"{k} {v}" for k, v in sorted(counts.items())))
    return "; ".join(parts)


def cmd_check() -> int:
    if shutil.which("cc") is None:
        print("  release-proof FAIL: no `cc` on PATH: zenoh-pico's header cannot be preprocessed, and "
              "nothing here was read", file=sys.stderr)
        return 1
    if not LEDGER.is_file():
        print(f"  release-proof FAIL: {LEDGER.relative_to(ROOT)} is missing", file=sys.stderr)
        return 1
    pops, findings = populations(ROOT, PICO, EXT)
    text = LEDGER.read_text(encoding="utf-8")
    findings += check(text, pops, ROOT)
    for finding in findings:
        print(f"  release-proof FAIL: {finding}", file=sys.stderr)
    if findings:
        return 1
    print(f"  release-proof: {LEDGER.relative_to(ROOT)} holds against zenoh-pico at the pin "
          f"({len(pops['api'])} public names, {len(pops['switches'])} switches, {len(pops['examples'])} "
          f"examples, {len(pops['tests'])} tests, {len(pops['ext'])} doors); {tally(text)}")
    return 0


# ---------------------------------------------------------------------------
# selftest
# ---------------------------------------------------------------------------

def fixture_tables() -> dict[str, list[list[str]]]:
    return {
        "lanes": [
            ["L01", "a lane of another form", "\x60t/a.c\x60", "\x60src/x.rs\x60", "linux", "std", "p", "gate", "no"],
            ["L02", "the release form", "\x60t/a.c\x60 \x60ex/*.c\x60", "\x60wf.yml#job1\x60", "windows", "nostd",
             "host-peer-ext", "gate", "yes"],
            ["L03", "a lane of other names", "\x60t/b.c\x60", "\x60src/x.rs\x60", "linux", "std", "p", "observed", "no"],
        ],
        "api": [
            ["A01", "put", "\x60z_put\x60 \x60z_put_*\x60", "L01, L02", "proven", NOTHING],
            ["A02", "open", "\x60z_open*\x60", "L01", "unproven", "W01"],
        ],
        "switches": [
            ["\x60Z_FEATURE_X\x60", "on", "yes", "\x60c/x\x60", "L02", "proven", NOTHING],
            ["\x60Z_FEATURE_Y\x60", "off", "no", "n/a", NOTHING, "n/a", "pico's Windows port refuses it"],
        ],
        "examples": [
            ["\x60ex/z_put.c\x60", "L02", "proven", NOTHING],
        ],
        "tests": [
            ["\x60ts/z_api_t.c\x60", "api", NOTHING, "none", "W01"],
            ["\x60ts/z_priv.c\x60", "internal", NOTHING, "n/a", "tests a private module"],
        ],
        "criteria": [
            ["C01", "size", "a reading", "L03", "unproven", "W01"],
        ],
        "ext": [
            ["E01", "f", "\x60wz_ext_a*\x60", "yes", "\x60src/x.rs\x60", "none", "none", "none", "\x60src/x.rs\x60", "W01"],
            ["E02", "g", "\x60wz_ext_b\x60", "no", NOTHING, NOTHING, NOTHING, NOTHING, NOTHING, "not in the release DLL"],
        ],
        "work": [
            ["W01", "P0", "do it", "small", "\x60src/x.rs\x60"],
        ],
    }


def render(tabs: dict[str, list[list[str]]], drop: str | None = None,
           header: tuple[str, list[str]] | None = None) -> str:
    out = ["# fixture", ""]
    for name, rows in tabs.items():
        if name == drop:
            continue
        columns = list(TABLES[name])
        if header is not None and header[0] == name:
            columns = header[1]
        out.append(f"<!-- release-proof: {name} -->")
        out.append("| " + " | ".join(columns) + " |")
        out.append("|" + "|".join("---" for _ in columns) + "|")
        out.extend("| " + " | ".join(row) + " |" for row in rows)
        out.append("")
    return "\n".join(out)


def fixture_pops() -> dict:
    return {
        "api": {"z_put", "z_put_options_default", "z_open", "z_open_options_default"},
        "switches": {"Z_FEATURE_X", "Z_FEATURE_Y"},
        "switch_defaults": {"Z_FEATURE_X": "1", "Z_FEATURE_Y": "0"},
        "examples": {"ex/z_put.c"},
        "tests": {"ts/z_api_t.c", "ts/z_priv.c"},
        "ext": {"wz_ext_a1", "wz_ext_a2", "wz_ext_b"},
    }


def cmd_selftest() -> int:
    ok = bad = 0

    def expect(name: str, cond: bool, detail: object = "") -> None:
        nonlocal ok, bad
        if cond:
            ok += 1
        else:
            bad += 1
            print(f"  release-proof selftest FAIL: {name} {detail}", file=sys.stderr)

    with tempfile.TemporaryDirectory() as tmp:
        root = pathlib.Path(tmp)
        files = {
            "t/a.c": "int main(void) { z_open(0); z_put(0); /* z_sub(0) */ return 0; }\n",
            "t/b.c": "int main(void) { z_sub(0); // z_open(0)\n return 0; }\n",
            "ex/z_put.c": "int main(void) { z_put(0); return 0; }\n",
            "src/x.rs": "// a source\n",
            "wf.yml": "jobs:\n  job1:\n    runs-on: x\n",
        }
        for rel, body in files.items():
            (root / rel).parent.mkdir(parents=True, exist_ok=True)
            (root / rel).write_text(body, encoding="utf-8")

        def run(change=None, pops_change=None, drop=None, header=None) -> list[str]:
            tabs = fixture_tables()
            if change is not None:
                change(tabs)
            pops = fixture_pops()
            if pops_change is not None:
                pops_change(pops)
            return check(render(tabs, drop, header), pops, root)

        def has(findings: list[str], needle: str) -> bool:
            return any(needle in f for f in findings)

        clean = run()
        expect("the fixture holds", clean == [], clean)

        def set_cell(table: str, index: int, column: str, value: str):
            def change(tabs):
                tabs[table][index][list(TABLES[table]).index(column)] = value
            return change

        def add_row(table: str, row: list[str]):
            def change(tabs):
                tabs[table].append(row)
            return change

        expect("a public name no row claims",
               has(run(pops_change=lambda p: p["api"].add("z_delete")), "z_delete is claimed by no row"))
        expect("a pattern that claims no name",
               has(run(set_cell("api", 1, "names", "\x60z_open*\x60 \x60z_close\x60")), "pattern z_close claims no name"))
        expect("a name an earlier row took leaves the later pattern with nothing",
               has(run(set_cell("api", 0, "names", "\x60z_put\x60 \x60z_put_*\x60 \x60z_open*\x60")),
                   "pattern z_open* claims no name"))
        expect("a stated status its lanes do not make",
               has(run(set_cell("api", 1, "status", "observed")), "its lanes make it unproven"))
        expect("a release lane that is not gated makes a row observed, not proven",
               has(run(set_cell("lanes", 1, "gated", "observed")), "but its lanes make it observed"))
        expect("a release form the host, form and profile do not make",
               has(run(set_cell("lanes", 0, "release form", "yes")), "make it no"))
        expect("a lane whose programs name none of a row's names (comments do not count)",
               has(run(set_cell("api", 1, "lanes", "L01, L03")), "cites L03, whose programs name none"))
        expect("a source that does not exist",
               has(run(set_cell("lanes", 0, "source", "\x60src/nope.rs\x60")), "source src/nope.rs does not exist"))
        expect("a workflow job that does not exist",
               has(run(set_cell("lanes", 1, "source", "\x60wf.yml#job2\x60")), "has no job job2"))
        expect("an anchored program reads as its path, its needle as no program",
               paths("\x60t/a.c\x60 @ \x60int main(\x60 \x60t/b.c\x60") == ["t/a.c", "t/b.c"])
        expect("a program pattern that matches no file",
               has(run(set_cell("lanes", 2, "programs", "\x60t/none.c\x60")), "matches no file"))
        expect("a switch of zenoh-pico with no row",
               has(run(pops_change=lambda p: p["switches"].add("Z_FEATURE_Z")), "Z_FEATURE_Z has no row"))
        expect("a switch row zenoh-pico does not have",
               has(run(pops_change=lambda p: p["switches"].discard("Z_FEATURE_Y")), "Z_FEATURE_Y is a row and not"))
        expect("a switch default that is not zenoh-pico's",
               has(run(set_cell("switches", 0, "pico default", "off")), "but zenoh-pico's CMake sets 1"))
        expect("a switch zenoh-pico refuses on Windows reads n/a",
               has(run(set_cell("switches", 1, "status", "none")), "reads n/a, not none"))
        expect("an example whose cited lane does not run it",
               has(run(set_cell("examples", 0, "lanes", "L01, L02")), "cites L01, which does not run it"))
        expect("an example of zenoh-pico with no row",
               has(run(pops_change=lambda p: p["examples"].add("ex/z_sub.c")), "ex/z_sub.c has no row"))
        expect("a test of private code that does not read n/a",
               has(run(set_cell("tests", 1, "status", "none")), "reads n/a, not none"))
        expect("a test kind outside the vocabulary",
               has(run(set_cell("tests", 0, "kind", "unit")), "kind 'unit'"))
        expect("a gap that names no work item",
               has(run(set_cell("api", 1, "gap", "later")), "names no work item"))
        expect("a proven row with a gap",
               has(run(set_cell("api", 0, "gap", "W01")), "proven, so its gap"))
        expect("an n/a row with no reason",
               has(run(set_cell("tests", 1, "gap", NOTHING)), "n/a with no reason"))
        expect("a work item cited and missing",
               has(run(set_cell("api", 1, "gap", "W09")), "W09 is cited and is not a work item"))
        expect("a work item nobody cites",
               has(run(add_row("work", ["W02", "P1", "x", "y", NOTHING])), "work W02 is cited by no row"))
        expect("a priority outside the vocabulary",
               has(run(set_cell("work", 0, "priority", "high")), "priority 'high'"))
        expect("a lane cited that does not exist",
               has(run(set_cell("criteria", 0, "lanes", "L09")), "cites L09, which is not a lane"))
        expect("a lane no row cites",
               has(run(add_row("lanes", ["L04", "idle", NOTHING, "\x60src/x.rs\x60", "linux", "std", "p", "gate", "no"])),
                   "lane L04 is cited by no row"))
        expect("a door no row claims",
               has(run(pops_change=lambda p: p["ext"].add("wz_ext_c")), "wz_ext_c is claimed by no row"))
        expect("a carried door with an empty evidence cell",
               has(run(set_cell("ext", 0, "docs", NOTHING)), "docs cell is empty"))
        expect("a carried door reading none with no work item",
               has(run(set_cell("ext", 0, "gap", "later")), "fuzz reads none and its gap names no work item"))
        expect("a carried door naming a file that does not exist",
               has(run(set_cell("ext", 0, "tests", "\x60src/gone.rs\x60")), "src/gone.rs, which does not exist"))
        expect("a door left out with no reason",
               has(run(set_cell("ext", 1, "gap", NOTHING)), "gives no reason"))
        expect("a row id of the wrong shape",
               has(run(set_cell("api", 1, "row", "B2")), "row id 'B2'"))
        expect("a row id twice",
               has(run(add_row("criteria", ["C01", "x", "y", NOTHING, "none", "W01"])), "C01 is two rows"))
        expect("a table that is missing",
               has(run(drop="work"), "table work is missing"))
        expect("a table with other columns",
               has(run(header=("examples", ["program", "lanes", "state", "gap"])), "table examples: columns"))
        expect("a lanes cell that is not a list of lane ids",
               has(run(set_cell("api", 1, "lanes", "L01 and L03")), "comma-separated list"))
        expect("an empty population fails rather than passing",
               has(run(pops_change=lambda p: p["api"].clear()), "population of the API is empty"))
        expect("the door reader keeps every #if arm and drops comments, function types and types",
               ext_doors("/* wz_ext_old(void); */\nint wz_ext_a(void);\n#if X\nint wz_ext_b(int x);\n#endif\n"
                         "typedef int wz_ext_cb_fn(void *c);\n// wz_ext_c(void);\n")
               == {"wz_ext_a", "wz_ext_b"})
        expect("comments of a C program are not names it calls",
               NAME_REF.findall(strip_comments("p.c", "z_a(); /* z_b() */ // z_c()\n")) == ["z_a"])
    print(f"  release-proof selftest: {ok}/{ok + bad} arm(s) pass")
    return 1 if bad else 0


def main(argv: list[str]) -> int:
    if argv == ["--check"]:
        return cmd_check()
    if argv == ["--selftest"]:
        return cmd_selftest()
    print(__doc__, file=sys.stderr)
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
