#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
# SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
"""R3082 (no register item) -- the Zephyr BOARD TABLE and what its grades may claim.

The debt it answers for, open-debt item 867 (and 864, which makes a board an
argument), lives in the operator's agent-memory register, which has no store
`debt-` id for `gate_provenance_lint.py` to resolve; the honest pair is this
sentence and `no register item` in the citation.

## The defect this ends

`deploy/zephyr-app` booted on one QEMU machine and the words "supports Zephyr"
carried no more precision than that. A consumer asked which boards are
supported and by whom they are measured, and the answer had nowhere to live: the
only thing ever run was QEMU, hosted CI has no hardware, and "supported" read
the same for a board that had been built, a board that had been booted on an
emulator and a board someone had held in their hand.

`deploy/zephyr-boards.json` is that place: one row per BOARD x LINK x APP, each
with a grade, and a grade is a claim about EVIDENCE, not about intent:

  DECLARED  a target. Nothing was built for it.
  BUILT     hosted CI builds the image for the row (Layer Qzb). Nothing ran it.
  QEMU      the image boots on an emulated machine and a lane reads a verdict
            from it (`witness.lane`).
  HARDWARE  somebody ran it on the board, and a ledger entry records what ran:
            image hash, the verdict sentence, the date, who.

A claim goes no higher than the lowest grade its evidence reaches, so the gate
asks of every row what its grade requires and reads that off the tree rather
than off the row's own say-so.

## What it checks, and where each answer is read

  1. The table parses, has the canonical grade order, and is NOT EMPTY (a
     population of zero is a gate that has lost its subject, not a clean one).
  2. Every row has its keys, a known grade, a unique (board, link, app), an app
     that exists under `deploy/`, and a `network` the app's own Kconfig offers.
  3. DECLARED carries no witness: a witness on a declared row is a claim the
     grade does not make.
  4. BUILT and HARDWARE rows are the population Layer Qzb builds. The gate
     requires Layer Qzb to be registered in `scripts/run-ci.sh` AND invoked by a
     hosted job in `ci.yml`, and a `rust_target` on the row, because the lane
     reads the toolchain it needs from there and then checks that the build's
     own derivation (`wz_zephyr_board.cmake`) agrees.
  5. QEMU rows name a lane that `run-ci.sh` registers, a hosted job runs, and
     whose body boots the machine the row names (`-machine <m>` or `-M <m>`).
  6. HARDWARE rows carry the whole record AND the ledger entry it cites exists
     in the atomic store. A record with no entry behind it is a claim with no
     witness, which is exactly what the grade was invented to forbid. The
     record is read against its entry, not only for its presence: the image
     hash is 64 lowercase hex digits and appears in the entry's text (a hash
     copied wrongly into the table is a claim about an image nobody ran), the
     date is a date, and for an app that publishes a verdict grammar
     (`deploy/<app>/HARDWARE_VERDICT.md`) the entry names every step of it as
     OK, the first marker after the step's name being the one that counts, so a
     FAIL in a step cannot be outvoted by an OK later in the entry. An app with
     a HARDWARE row and no grammar file is refused: there is nothing the record
     could have satisfied.
  7. Per-board settings (`deploy/<app>/boards/*.conf`) and the table agree both
     ways: every conf belongs to a row of that app (a board configured but not
     declared is a support claim nobody graded), a row that selects a network
     backend finds it set in the conf, and a conf that sets one sets the row's.
  8. THE FIXTURE ENTROPY RULE. `CONFIG_TEST_RANDOM_GENERATOR=y` makes the
     session's cookie nonces and signing key PREDICTABLE. It is Zephyr's own
     test generator and Zephyr permits it only for boards whose sole purpose is
     testing. A conf that sets it may belong only to DECLARED or QEMU rows: a
     BUILT or HARDWARE row that carries it is a board shipping a vulnerability
     under the name of support.
  9. COMPANIONS. Some boards run more than one image, and a row's image
     does not run without the others: on a T2G chip the M7 core's image runs
     only if the CM0+ core's image has brought the clock tree up and started it.
     The first boot of an M7 image on a kit whose CM0+ image did neither ran at a
     44th of its speed and printed nothing for minutes. `companions` lists those
     images (board, app, `starts` = the row board they start, grade, witness), a
     row names what it needs in `requires`, and the gate refuses a row that
     requires an image the table does not list, or lists below the row's own
     grade: a row's claim goes no higher than the lowest grade of what it runs
     with. A companion is graded DECLARED, BUILT or HARDWARE, and a HARDWARE
     companion carries the same record keys a row does, read the same way
     (item 6; the grammar steps are the ROW's, since a companion is not run on
     its own). A HARDWARE row that requires companions is HARDWARE only together
     with them, and each cites the SAME ledger entry as the row: what ran was
     the images together, and one image's record says nothing about the pair.
 10. BUILD-ONLY OVERLAYS. Layer Qzb has no lab to state the values a build needs,
     so a row may list an overlay of numbers made up so that the image is whole (a
     PLCA id, an address). Such an overlay describes no board, and an image built
     with it that reached a bench would configure a segment by accident. An overlay
     says it is one with the marker `WZ-BUILD-VALUES-ONLY` in the comment block that
     opens the file (the class is read from the FILE, so a rename cannot take it
     out of the class), and a file whose name says `build_values` is read as one
     too, so that dropping the marker does not either. A row or companion that is
     HARDWARE, or that cites a hardware record, may list none: what a lab ran must
     not be an image configured with invented values.

## Why it reads run-ci.sh and ci.yml as text

Both are tracked files and the claims it checks are claims about them: that a
lane exists, that a hosted job runs it, that it boots the machine the row
names. A table that names a lane nobody runs is the exact failure the grade
system exists to prevent, and no other gate reads the table.

`--build-rows` is the lane's reader: Layer Qzb asks THIS file which rows to
build, so the lane and the gate cannot disagree about the population.
"""

from __future__ import annotations

import json
import re
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
TABLE = "deploy/zephyr-boards.json"
RUN_CI = "scripts/run-ci.sh"
CI_YML = ".github/workflows/ci.yml"
STORE = "docs/.atomic/workspace.atomic.json"

GRADES = ["DECLARED", "BUILT", "QEMU", "HARDWARE"]
REQUIRED_KEYS = ("board", "link", "app", "network", "grade")
NETWORKS = ("zephyr-sockets", "lwip-mac")
HARDWARE_RECORD = ("record", "image_sha256", "verdict", "date", "by")
BUILD_LANE = "Qzb"
FIXTURE_ENTROPY = "CONFIG_TEST_RANDOM_GENERATOR=y"
COMPANION_KEYS = ("board", "app", "starts", "grade")
COMPANION_GRADES = ("DECLARED", "BUILT", "HARDWARE")
GRAMMAR_FILE = "HARDWARE_VERDICT.md"
SHA256 = re.compile(r"[0-9a-f]{64}")
DATE = re.compile(r"\d{4}-\d{2}-\d{2}")
# A step is a line of the grammar file that starts `HW.<n> `. In an entry's
# text the steps run on in one paragraph, so the split is at each `HW.<n> `.
STEP_LINE = re.compile(r"^HW\.(\d+) ", re.M)
STEP_SPLIT = re.compile(r"(?=HW\.\d+ )")
STEP_MARK = re.compile(r" - OK|FAIL")
# An overlay that exists so a build can be made, and describes no board.
BUILD_ONLY_MARKER = "WZ-BUILD-VALUES-ONLY"
BUILD_ONLY_NAMES = ("build_values", "build-values")


def build_only_overlay(path: Path) -> bool:
    """Whether the overlay at `path` is one of made-up build values.

    The marker is read from the comment block that opens the file (a line starting
    `#` before the first line that is not a comment or blank), so a marker buried
    among settings, where it would not be a statement about the file, does not count.
    The name is read too: an overlay called `*build_values*` is of the class
    whether or not it carries the marker.
    """
    if any(token in path.name for token in BUILD_ONLY_NAMES):
        return True
    for line in path.read_text().splitlines():
        stripped = line.strip()
        if not stripped:
            continue
        if not stripped.startswith("#"):
            return False
        if BUILD_ONLY_MARKER in stripped:
            return True
    return False


def claims_hardware(item: dict) -> bool:
    """Whether a row or companion is HARDWARE or cites a hardware record."""
    witness = item.get("witness")
    return item.get("grade") == "HARDWARE" or (
        isinstance(witness, dict) and "record" in witness
    )


def build_only_findings(label: str, item: dict, app_dir: Path) -> list[str]:
    """The finding for each build-only overlay a hardware-claiming `item` lists."""
    if not claims_hardware(item):
        return []
    out: list[str] = []
    for extra in item.get("conf_overlay", []):
        path = app_dir / extra
        if path.is_file() and build_only_overlay(path):
            out.append(
                f"{label}: claims hardware but lists conf_overlay {extra!r}, which is of made-up "
                f"build values ({BUILD_ONLY_MARKER}): an image configured with values nobody "
                f"chose is not what a lab ran"
            )
    return out


def conf_name(board: str) -> str:
    """Zephyr's per-board settings file: `mps2/an385` -> `mps2_an385.conf`."""
    return board.replace("/", "_") + ".conf"


def registered_lanes(run_ci: str) -> dict[str, str]:
    """`lane -> function`, from the dispatch block's `run_layer` lines."""
    return dict(re.findall(r"^run_layer\s+(\S+)\s+(\S+)\s+\|\|", run_ci, re.M))


def function_body(run_ci: str, name: str) -> str:
    """The text of shell function `name`, up to its closing brace at column 0."""
    m = re.search(rf"^{re.escape(name)}\(\)\s*\{{\n(.*?)^\}}", run_ci, re.M | re.S)
    return m.group(1) if m else ""


def hosted_layers(ci_yml: str) -> set[str]:
    """Every layer a hosted job invokes through `run-ci.sh --layer X`."""
    return set(re.findall(r"scripts/run-ci\.sh\s+--layer\s+(\w+)", ci_yml))


def conf_text(root: Path, app: str, board: str) -> str | None:
    path = root / "deploy" / app / "boards" / conf_name(board)
    return path.read_text() if path.is_file() else None


def kconfig_backends(root: Path, app: str) -> set[str]:
    """The `WZ_NET_BACKEND_*` choices the app's Kconfig defines, as
    `zephyr-sockets`-style names. Empty when the app has no such choice."""
    path = root / "deploy" / app / "Kconfig"
    if not path.is_file():
        return set()
    found = re.findall(r"^config\s+WZ_NET_BACKEND_([A-Z0-9_]+)", path.read_text(), re.M)
    return {name.lower().replace("_", "-") for name in found}


def conf_backends(text: str) -> set[str]:
    found = re.findall(r"^CONFIG_WZ_NET_BACKEND_([A-Z0-9_]+)=y", text, re.M)
    return {name.lower().replace("_", "-") for name in found}


def store_entries(root: Path) -> dict:
    """The changelog entries of the atomic store at `root`, by id; empty if none."""
    path = root / STORE
    if not path.is_file():
        return {}
    return json.loads(path.read_text()).get("changelog_entries", {})


def grammar_steps(root: Path, app: str) -> list[str] | None:
    """The step numbers `deploy/<app>/HARDWARE_VERDICT.md` publishes, or `None`
    when the app publishes no grammar."""
    path = root / "deploy" / app / GRAMMAR_FILE
    if not path.is_file():
        return None
    return sorted(set(STEP_LINE.findall(path.read_text())), key=int)


def step_verdicts(text: str) -> dict[str, bool]:
    """Step number -> whether the entry's text says that step held.

    A VERDICT SENTENCE is a step's name followed, within the same sentence, by
    a marker: ` - OK` or `FAIL`. The sentence ends at the first `. ` or line
    break after the name, so a marker further on (the last step's stretch runs
    to the end of the entry) cannot speak for a step that was only MENTIONED
    ("HW.0 to HW.7 held", "HW.4 and HW.5 differ ..."). A step held when it has
    a sentence that says OK and none that says FAIL: a record that contains
    both is a record that does not know."""
    ok: set[str] = set()
    failed: set[str] = set()
    for part in STEP_SPLIT.split(text):
        m = re.match(r"HW\.(\d+) ", part)
        if not m:
            continue
        # `. `, a line break (written `\n` in the entry's JSON) or the end of the
        # string value the sentence sits in.
        ends = [i for i in (part.find(". "), part.find("\\n"), part.find('", "'),
                            part.find('"}')) if i >= 0]
        sentence = part[: min(ends)] if ends else part
        mark = STEP_MARK.search(sentence)
        if mark:
            (ok if mark.group() == " - OK" else failed).add(m.group(1))
    return {n: n not in failed for n in ok | failed}


def check_record(label: str, witness: dict, root: Path, steps: list[str] | None) -> list[str]:
    """The findings about one HARDWARE witness (module item 6).

    `steps` are the grammar's step numbers for a ROW's app; `None` for a
    companion, whose entry is the row's and is read for its steps there."""
    absent = [k for k in HARDWARE_RECORD if not witness.get(k)]
    if absent:
        return [f"{label}: HARDWARE record lacks {absent}"]
    out: list[str] = []
    if not SHA256.fullmatch(witness["image_sha256"]):
        out.append(
            f"{label}: image_sha256 {witness['image_sha256']!r} is not 64 lowercase hex digits"
        )
    if not DATE.fullmatch(witness["date"]):
        out.append(f"{label}: date {witness['date']!r} is not YYYY-MM-DD")
    entry = store_entries(root).get(witness["record"])
    if entry is None:
        out.append(
            f"{label}: HARDWARE record {witness['record']!r} is not a "
            f"changelog entry in the store -- a record with no entry is a "
            f"claim with no witness"
        )
        return out
    text = json.dumps(entry, ensure_ascii=False)
    if witness["image_sha256"] not in text:
        out.append(
            f"{label}: image_sha256 does not appear in the text of {witness['record']!r} "
            f"-- the table names an image the record never mentions"
        )
    if steps is not None:
        held = step_verdicts(text)
        for n in steps:
            if n not in held:
                out.append(f"{label}: {witness['record']!r} never names step HW.{n}")
            elif not held[n]:
                out.append(f"{label}: {witness['record']!r} does not say HW.{n} held (OK)")
    return out


def check_companions(
    table: dict, root: Path, rows: list, lanes: dict[str, str], hosted: set[str]
) -> list[str]:
    """The findings about `companions` and the rows' `requires` (module item 9)."""
    companions = table.get("companions", [])
    if not isinstance(companions, list):
        return [f"{TABLE}: companions must be a list"]
    out: list[str] = []
    good_rows = [r for r in rows if isinstance(r, dict)]
    row_boards = {r["board"] for r in good_rows if r.get("board")}
    listed: list[dict] = []
    seen: set[tuple[str, str]] = set()
    for n, c in enumerate(companions):
        if not isinstance(c, dict):
            out.append(f"companion {n}: not an object")
            continue
        label = f"companion {n} ({c.get('board')} / {c.get('app')})"
        missing = [k for k in COMPANION_KEYS if not c.get(k)]
        if missing:
            out.append(f"{label}: missing {missing}")
            continue
        if (c["board"], c["app"]) in seen:
            out.append(f"{label}: the (board, app) pair is not unique")
        seen.add((c["board"], c["app"]))
        if not (root / "deploy" / c["app"] / "CMakeLists.txt").is_file():
            out.append(f"{label}: deploy/{c['app']}/CMakeLists.txt does not exist")
        if c["starts"] not in row_boards:
            out.append(
                f"{label}: starts {c['starts']!r}, which no row of {TABLE} is for -- "
                f"a companion of an image nobody grades"
            )
        grade, witness = c["grade"], c.get("witness")
        if grade not in COMPANION_GRADES:
            out.append(f"{label}: grade {grade!r} is not one of {COMPANION_GRADES}")
            continue
        listed.append(c)
        out.extend(build_only_findings(label, c, root / "deploy" / c["app"]))
        if grade == "DECLARED":
            if witness:
                out.append(f"{label}: DECLARED carries a witness, which the grade does not make")
            continue
        if grade == "BUILT":
            if not isinstance(witness, dict) or witness.get("lane") != BUILD_LANE:
                out.append(f"{label}: BUILT's witness lane must be {BUILD_LANE}")
        else:
            out.extend(
                check_record(label, witness if isinstance(witness, dict) else {}, root, None)
            )
        if BUILD_LANE not in lanes:
            out.append(f"{label}: Layer {BUILD_LANE} is not registered in {RUN_CI}")
        if BUILD_LANE not in hosted:
            out.append(f"{label}: no hosted job in {CI_YML} runs --layer {BUILD_LANE}")
    for row in good_rows:
        needs = row.get("requires", [])
        label = f"row ({row.get('board')} / {row.get('link')})"
        if not isinstance(needs, list):
            out.append(f"{label}: requires must be a list")
            continue
        for app in needs:
            comp = next(
                (c for c in listed if c["app"] == app and c["starts"] == row.get("board")), None
            )
            if comp is None:
                out.append(
                    f"{label}: requires {app!r}, which no companion in {TABLE} starts for "
                    f"{row.get('board')}"
                )
            elif (
                row.get("grade") in GRADES
                and GRADES.index(comp["grade"]) < GRADES.index(row["grade"])
            ):
                out.append(
                    f"{label}: is {row['grade']} but requires {app!r}, which is only "
                    f"{comp['grade']} -- a row's claim goes no higher than the lowest grade "
                    f"of what it runs with"
                )
            elif row.get("grade") == "HARDWARE" and _record_of(comp) != _record_of(row):
                out.append(
                    f"{label}: is HARDWARE on {_record_of(row)!r} but requires {app!r}, whose "
                    f"record is {_record_of(comp)!r} -- what ran was the images together, so "
                    f"the row and its companions cite the one entry"
                )
    return out


def _record_of(item: dict) -> object:
    """The ledger entry id a row or companion's HARDWARE witness cites, or `None`."""
    witness = item.get("witness")
    return witness.get("record") if isinstance(witness, dict) else None


def check(table: dict, root: Path = ROOT) -> list[str]:
    """The findings for `table` against the tree at `root`; empty is clean."""
    out: list[str] = []
    if table.get("schema") != 1:
        out.append(f"{TABLE}: schema must be 1, found {table.get('schema')!r}")
    if table.get("grades") != GRADES:
        out.append(f"{TABLE}: grades must be exactly {GRADES} in that order")
    rows = table.get("rows")
    if not isinstance(rows, list) or not rows:
        out.append(f"{TABLE}: no rows -- a table with no population grades nothing")
        return out

    run_ci = (root / RUN_CI).read_text() if (root / RUN_CI).is_file() else ""
    ci_yml = (root / CI_YML).read_text() if (root / CI_YML).is_file() else ""
    lanes = registered_lanes(run_ci)
    hosted = hosted_layers(ci_yml)

    seen: set[tuple[str, str, str]] = set()
    rows_by_conf: dict[tuple[str, str], list[dict]] = {}
    for n, row in enumerate(rows):
        if not isinstance(row, dict):
            out.append(f"row {n}: not an object")
            continue
        label = f"row {n} ({row.get('board')} / {row.get('link')} / {row.get('app')})"
        missing = [k for k in REQUIRED_KEYS if not row.get(k)]
        if missing:
            out.append(f"{label}: missing {missing}")
            continue
        key = (row["board"], row["link"], row["app"])
        if key in seen:
            out.append(f"{label}: the (board, link, app) triple is not unique")
        seen.add(key)
        grade = row["grade"]
        if grade not in GRADES:
            out.append(f"{label}: unknown grade {grade!r}")
            continue
        app_dir = root / "deploy" / row["app"]
        if not (app_dir / "CMakeLists.txt").is_file():
            out.append(f"{label}: deploy/{row['app']}/CMakeLists.txt does not exist")
        for extra in row.get("conf_overlay", []):
            if not (app_dir / extra).is_file():
                out.append(
                    f"{label}: conf_overlay {extra!r} is not a file under deploy/{row['app']}/"
                    f" -- Layer {BUILD_LANE} would build the row without it"
                )
        out.extend(build_only_findings(label, row, app_dir))
        rows_by_conf.setdefault((row["app"], conf_name(row["board"])), []).append(row)

        # The network the row names must be one the app offers.
        if row["network"] not in NETWORKS:
            out.append(f"{label}: network {row['network']!r} is not one of {NETWORKS}")
        else:
            offered = kconfig_backends(root, row["app"])
            if offered and row["network"] not in offered:
                out.append(
                    f"{label}: network {row['network']!r} is not among the backends "
                    f"deploy/{row['app']}/Kconfig defines ({sorted(offered)})"
                )
            if not offered and row["network"] != "zephyr-sockets":
                out.append(
                    f"{label}: deploy/{row['app']}/Kconfig defines no network backend "
                    f"choice, so the only network it can have is 'zephyr-sockets'"
                )

        witness = row.get("witness")
        if grade == "DECLARED":
            if witness:
                out.append(f"{label}: DECLARED carries a witness, which the grade does not make")
        else:
            if not isinstance(witness, dict) or not witness:
                out.append(f"{label}: {grade} needs a witness")
                witness = {}
        if grade in ("BUILT", "HARDWARE"):
            if not row.get("rust_target"):
                out.append(f"{label}: {grade} needs rust_target (Layer {BUILD_LANE} reads its toolchain from it)")
            if BUILD_LANE not in lanes:
                out.append(f"{label}: Layer {BUILD_LANE} is not registered in {RUN_CI}")
            if BUILD_LANE not in hosted:
                out.append(f"{label}: no hosted job in {CI_YML} runs --layer {BUILD_LANE}")
        if grade == "BUILT" and witness.get("lane") != BUILD_LANE:
            out.append(f"{label}: BUILT's witness lane must be {BUILD_LANE}")
        if grade == "QEMU":
            lane, machine = witness.get("lane"), witness.get("qemu_machine")
            if not lane or not machine:
                out.append(f"{label}: QEMU needs witness.lane and witness.qemu_machine")
            else:
                fn = lanes.get(lane)
                if fn is None:
                    out.append(f"{label}: lane {lane} is not registered in {RUN_CI}")
                elif lane not in hosted:
                    out.append(f"{label}: no hosted job in {CI_YML} runs --layer {lane}")
                else:
                    # The lane's own body, or a helper it hands the QEMU command
                    # to, must boot the machine the row names.
                    body = function_body(run_ci, fn)
                    if not re.search(rf"(?:-machine|-M)\s+{re.escape(machine)}\b", body):
                        out.append(
                            f"{label}: lane {lane} ({fn}) never starts QEMU with "
                            f"-machine {machine}"
                        )
        if grade == "HARDWARE":
            steps = grammar_steps(root, row["app"])
            if steps is None:
                out.append(
                    f"{label}: HARDWARE but deploy/{row['app']}/{GRAMMAR_FILE} does not exist "
                    f"-- there is no verdict grammar the record could have satisfied"
                )
            elif not steps:
                out.append(
                    f"deploy/{row['app']}/{GRAMMAR_FILE}: names no step (a line starting "
                    f"`HW.<n> `), so it grades nothing"
                )
            out.extend(check_record(label, witness, root, steps))

    # The settings files and the table, both ways.
    apps = sorted({row["app"] for row in rows if isinstance(row, dict) and row.get("app")})
    for app in apps:
        boards_dir = root / "deploy" / app / "boards"
        if not boards_dir.is_dir():
            continue
        for conf in sorted(boards_dir.glob("*.conf")):
            owners = rows_by_conf.get((app, conf.name), [])
            if not owners:
                out.append(
                    f"deploy/{app}/boards/{conf.name}: configures a board no row of "
                    f"{TABLE} declares for {app}"
                )
                continue
            text = conf.read_text()
            if FIXTURE_ENTROPY in text:
                for row in owners:
                    if row["grade"] in ("BUILT", "HARDWARE"):
                        out.append(
                            f"deploy/{app}/boards/{conf.name}: sets {FIXTURE_ENTROPY} but "
                            f"the row {row['board']} / {row['link']} is {row['grade']} -- "
                            f"predictable cookie nonces and signing key on a board that "
                            f"claims support"
                        )
            chosen = conf_backends(text)
            for row in owners:
                if chosen and row["network"] not in chosen:
                    out.append(
                        f"deploy/{app}/boards/{conf.name}: selects {sorted(chosen)} but the "
                        f"row {row['board']} / {row['link']} says {row['network']!r}"
                    )
    for (app, name), owners in rows_by_conf.items():
        for row in owners:
            if row["network"] == "lwip-mac" and row["grade"] != "DECLARED":
                text = conf_text(root, app, row["board"])
                if text is None or "lwip-mac" not in conf_backends(text):
                    out.append(
                        f"row {row['board']} / {row['link']}: network lwip-mac but "
                        f"deploy/{app}/boards/{name} does not select CONFIG_WZ_NET_BACKEND_LWIP_MAC=y"
                    )
    out.extend(check_companions(table, root, rows, lanes, hosted))
    return out


def build_rows(table: dict) -> list[dict]:
    """The rows Layer Qzb builds: BUILT and HARDWARE."""
    return [r for r in table["rows"] if r.get("grade") in ("BUILT", "HARDWARE")]


def build_companions(table: dict) -> list[dict]:
    """The companions Layer Qzb builds beside the rows: BUILT and HARDWARE, as for rows."""
    return [c for c in table.get("companions", []) if c.get("grade") in ("BUILT", "HARDWARE")]


# ---------------------------------------------------------------------------
# Selftest: the verdict's refusal arms run on fixtures before the real table.
# ---------------------------------------------------------------------------

_FIX_RUN_CI = """\
layer_qz_boot() {
    qemu-system-arm -cpu cortex-m3 -machine mps2-an385 -nographic
}
layer_qzb_matrix() {
    :
}
run_layer Qz layer_qz_boot || overall=1
run_layer Qzb layer_qzb_matrix || overall=1
"""
_FIX_CI = "run: bash scripts/run-ci.sh --layer Qz\nrun: bash scripts/run-ci.sh --layer Qzb\n"
_FIX_KCONFIG = (
    "choice WZ_NET_BACKEND\n"
    "config WZ_NET_BACKEND_ZEPHYR_SOCKETS\n\tbool\n"
    "config WZ_NET_BACKEND_LWIP_MAC\n\tbool\n"
    "endchoice\n"
)


def _good_table() -> dict:
    return {
        "schema": 1,
        "grades": GRADES,
        "rows": [
            {
                "board": "mps2/an385", "link": "eth", "app": "adm",
                "network": "zephyr-sockets", "rust_target": "thumbv7m-none-eabi",
                "grade": "QEMU", "witness": {"lane": "Qz", "qemu_machine": "mps2-an385"},
            },
            {
                "board": "real/board", "link": "rmii", "app": "adm",
                "network": "lwip-mac", "rust_target": "thumbv7em-none-eabihf",
                "grade": "BUILT", "witness": {"lane": "Qzb"},
                "conf_overlay": ["extra.conf"], "requires": ["launch"],
            },
            {
                "board": "other/board", "link": "t1s", "app": "adm",
                "network": "lwip-mac", "grade": "DECLARED",
            },
        ],
        "companions": [
            {
                "board": "real/board-m0p", "app": "launch", "starts": "real/board",
                "grade": "BUILT", "witness": {"lane": "Qzb"},
            },
        ],
    }


def _tree(tmp: Path, store_entries: dict | None = None) -> Path:
    (tmp / "scripts").mkdir(parents=True)
    (tmp / "scripts/run-ci.sh").write_text(_FIX_RUN_CI)
    (tmp / ".github/workflows").mkdir(parents=True)
    (tmp / ".github/workflows/ci.yml").write_text(_FIX_CI)
    app = tmp / "deploy/adm"
    (app / "boards").mkdir(parents=True)
    (app / "CMakeLists.txt").write_text("project(x)\n")
    (app / "Kconfig").write_text(_FIX_KCONFIG)
    (app / "boards/mps2_an385.conf").write_text(
        "CONFIG_TEST_RANDOM_GENERATOR=y\nCONFIG_WZ_NET_BACKEND_ZEPHYR_SOCKETS=y\n"
    )
    (app / "boards/real_board.conf").write_text("CONFIG_WZ_NET_BACKEND_LWIP_MAC=y\n")
    (app / "extra.conf").write_text("CONFIG_X=y\n")
    (app / GRAMMAR_FILE).write_text(
        "```\nHW.0 the console says who\nHW.1 GET before the write\nHW.2 the stack\n```\n"
    )
    (tmp / "deploy/launch").mkdir(parents=True)
    (tmp / "deploy/launch/CMakeLists.txt").write_text("project(y)\n")
    (tmp / "docs/.atomic").mkdir(parents=True)
    (tmp / "docs/.atomic/workspace.atomic.json").write_text(
        json.dumps({"changelog_entries": store_entries or {}})
    )
    return tmp


def selftest() -> int:
    failures: list[str] = []

    def expect(name: str, table: dict, needle: str | None, mutate=None, entries=None) -> None:
        with tempfile.TemporaryDirectory() as d:
            root = _tree(Path(d), entries)
            if mutate:
                mutate(root)
            got = check(table, root)
        if needle is None:
            if got:
                failures.append(f"{name}: expected clean, got {got}")
        elif not any(needle in line for line in got):
            failures.append(f"{name}: expected a finding with {needle!r}, got {got}")

    expect("a consistent table is clean", _good_table(), None)

    t = _good_table(); t["rows"] = []
    expect("an empty table", t, "no rows")
    t = _good_table(); t["grades"] = ["BUILT"]
    expect("a reordered grade list", t, "grades must be exactly")
    t = _good_table(); t["rows"][0]["grade"] = "SUPPORTED"
    expect("an unknown grade", t, "unknown grade")
    t = _good_table(); t["rows"].append(dict(t["rows"][0]))
    expect("a duplicate triple", t, "not unique")
    t = _good_table(); t["rows"][2]["witness"] = {"lane": "Qz"}
    expect("a witness on DECLARED", t, "DECLARED carries a witness")
    t = _good_table(); t["rows"][1].pop("rust_target")
    expect("BUILT without a rust target", t, "needs rust_target")
    t = _good_table(); t["rows"][0]["witness"]["lane"] = "Qghost"
    expect("a QEMU lane nobody registers", t, "not registered")
    t = _good_table(); t["rows"][0]["witness"]["qemu_machine"] = "virt"
    expect("a QEMU lane that boots another machine", t, "never starts QEMU")
    t = _good_table(); t["rows"][1]["network"] = "carrier-pigeon"
    expect("an unknown network", t, "is not one of")

    def drop_hosted(root: Path) -> None:
        (root / ".github/workflows/ci.yml").write_text("run: bash scripts/run-ci.sh --layer Qz\n")

    expect("Qzb in no hosted job", _good_table(), "runs --layer Qzb", drop_hosted)

    def lose_overlay(root: Path) -> None:
        (root / "deploy/adm/extra.conf").unlink()

    expect("a conf_overlay that is not a file", _good_table(), "conf_overlay", lose_overlay)

    def orphan_conf(root: Path) -> None:
        (root / "deploy/adm/boards/stray_board.conf").write_text("CONFIG_X=y\n")

    expect("a conf with no row", _good_table(), "no row of", orphan_conf)

    def fixture_on_built(root: Path) -> None:
        (root / "deploy/adm/boards/real_board.conf").write_text(
            "CONFIG_TEST_RANDOM_GENERATOR=y\nCONFIG_WZ_NET_BACKEND_LWIP_MAC=y\n"
        )

    expect("fixture entropy on a BUILT board", _good_table(), "predictable cookie", fixture_on_built)

    def wrong_backend(root: Path) -> None:
        (root / "deploy/adm/boards/real_board.conf").write_text(
            "CONFIG_WZ_NET_BACKEND_ZEPHYR_SOCKETS=y\n"
        )

    expect("a conf selecting another backend", _good_table(), "selects", wrong_backend)

    def no_backend(root: Path) -> None:
        (root / "deploy/adm/boards/real_board.conf").write_text("CONFIG_X=y\n")

    expect("lwip-mac without its backend selected", _good_table(), "does not select", no_backend)

    def lose_companion_app(root: Path) -> None:
        (root / "deploy/launch/CMakeLists.txt").unlink()

    expect("a companion whose app is absent", _good_table(), "does not exist", lose_companion_app)
    t = _good_table(); t["companions"][0]["starts"] = "nowhere/board"
    expect("a companion that starts no graded image", t, "which no row")
    t = _good_table(); t["companions"][0]["witness"] = {"lane": "Qz"}
    expect("a BUILT companion witnessed by another lane", t, "witness lane must be")
    t = _good_table(); t["companions"][0]["grade"] = "SUPPORTED"
    expect("a companion graded outside the scale", t, "is not one of")
    t = _good_table(); t["companions"] = {}
    expect("companions that are not a list", t, "must be a list")
    t = _good_table(); t["companions"] = []
    expect("a row that requires an unlisted companion", t, "which no companion")
    t = _good_table(); t["companions"][0]["grade"] = "DECLARED"; t["companions"][0].pop("witness")
    expect("a row above its companion's grade", t, "lowest grade of what it runs with")
    t = _good_table(); t["rows"][1]["requires"] = "launch"
    expect("requires that is not a list", t, "requires must be a list")
    t = _good_table(); t["companions"][0]["witness"] = {"lane": "Qzb"}; t["companions"][0]["grade"] = "DECLARED"
    expect("a witness on a DECLARED companion", t, "carries a witness")
    t = _good_table(); t["companions"].append(dict(t["companions"][0]))
    expect("a duplicate companion", t, "not unique")

    # HARDWARE. A whole record is a row AND the companion it requires, both
    # citing one entry that holds each image's hash and every step of the
    # fixture grammar (HW.0 to HW.2) as OK.
    app_hash, launch_hash = "ab" * 32, "cd" * 32

    def hardware_table() -> dict:
        t = _good_table()
        t["rows"][1]["grade"] = "HARDWARE"
        t["rows"][1]["witness"] = {
            "record": "Round 9", "image_sha256": app_hash, "verdict": "HW.0 to HW.2 OK",
            "date": "2026-10-08", "by": "the lab session",
        }
        t["companions"][0]["grade"] = "HARDWARE"
        t["companions"][0]["witness"] = {
            "record": "Round 9", "image_sha256": launch_hash, "verdict": "started the image",
            "date": "2026-10-08", "by": "the lab session",
        }
        return t

    def entry(sentences: str | None = None, extra: str = "") -> dict:
        said = sentences or "HW.0 a - OK. HW.1 b - OK. HW.2 stack: peak 1 of 4 bytes - OK."
        return {
            "decision_summary": "The run held, HW.0 to HW.2 all of them.",
            "verification": f"{said} Images {app_hash} {launch_hash}. {extra}",
        }

    whole = {"Round 9": entry()}
    expect("a HARDWARE row with its companion and a whole record", hardware_table(), None,
           entries=whole)
    expect("HARDWARE whose entry is absent", hardware_table(), "not a changelog entry")
    t = hardware_table(); t["companions"][0]["witness"]["record"] = "Round 8"
    expect("a companion citing another entry", t, "cite the one entry",
           entries={"Round 9": entry(), "Round 8": entry()})
    t = hardware_table(); t["companions"][0]["witness"]["image_sha256"] = "ef" * 32
    expect("a companion hash the record never mentions", t, "does not appear", entries=whole)
    t = hardware_table(); t["rows"][1]["witness"]["image_sha256"] = "ab"
    expect("a hash that is not a sha256", t, "64 lowercase hex", entries=whole)
    t = hardware_table(); t["rows"][1]["witness"]["date"] = "yesterday"
    expect("a date that is not a date", t, "YYYY-MM-DD", entries=whole)
    expect("a record missing a step", hardware_table(), "never names step HW.2",
           entries={"Round 9": entry("HW.0 a - OK. HW.1 b - OK.")})
    expect("a step the record only mentions", hardware_table(), "never names step HW.1",
           entries={"Round 9": entry("HW.0 a - OK. HW.2 c - OK. HW.1 was skipped.",
                                     extra="Another line - OK.")})
    expect("a step that failed", hardware_table(), "does not say HW.1 held",
           entries={"Round 9": entry("HW.0 a - OK. HW.1 b FAIL. HW.2 c - OK.")})
    expect("a step that failed and was later said OK", hardware_table(), "does not say HW.1 held",
           entries={"Round 9": entry("HW.0 a - OK. HW.1 b FAIL. HW.1 b - OK. HW.2 c - OK.")})
    expect("a word FAIL in another paragraph fails no step", hardware_table(), None,
           entries={"Round 9": entry(extra="The check prints a FAIL line when it does not hold.")})
    t = hardware_table(); t["rows"][1]["witness"] = {"record": "Round 9"}
    expect("a HARDWARE row with a partial record", t, "lacks", entries=whole)
    t = hardware_table(); t["companions"][0]["witness"] = {"record": "Round 9"}
    expect("a HARDWARE companion with a partial record", t, "lacks", entries=whole)

    def lose_grammar(root: Path) -> None:
        (root / "deploy/adm" / GRAMMAR_FILE).unlink()

    expect("HARDWARE for an app with no grammar", hardware_table(), "no verdict grammar",
           lose_grammar, entries=whole)

    def empty_grammar(root: Path) -> None:
        (root / "deploy/adm" / GRAMMAR_FILE).write_text("nothing to grade\n")

    expect("a grammar that names no step", hardware_table(), "names no step", empty_grammar,
           entries=whole)
    t = hardware_table(); t["companions"][0]["grade"] = "BUILT"
    t["companions"][0]["witness"] = {"lane": "Qzb"}
    expect("a HARDWARE row above its BUILT companion", t, "lowest grade of what it runs with",
           entries=whole)
    t = hardware_table(); t["rows"][1]["grade"] = "BUILT"; t["rows"][1]["witness"] = {"lane": "Qzb"}
    expect("a BUILT row over a HARDWARE companion", t, None, entries=whole)

    # BUILD-ONLY OVERLAYS (module item 10). A BUILT row may list one; a row or
    # companion that claims hardware may not, whatever the file is called.
    def build_values_overlays(root: Path) -> None:
        (root / "deploy/adm/values.conf").write_text(
            f"# Values for a build.\n# {BUILD_ONLY_MARKER}\n\nCONFIG_X=y\n"
        )
        (root / "deploy/adm/lab_build_values.conf").write_text("CONFIG_X=y\n")
        (root / "deploy/adm/buried.conf").write_text(
            f"CONFIG_X=y\n# {BUILD_ONLY_MARKER}\n"
        )
        (root / "deploy/launch/values.conf").write_text(f"# {BUILD_ONLY_MARKER}\n")

    t = _good_table(); t["rows"][1]["conf_overlay"] = ["values.conf"]
    expect("a BUILT row may list a build-only overlay", t, None, build_values_overlays)
    t = hardware_table(); t["rows"][1]["conf_overlay"] = ["values.conf"]
    expect("a HARDWARE row listing a build-only overlay", t, "made-up build values",
           build_values_overlays, entries=whole)
    t = hardware_table(); t["rows"][1]["conf_overlay"] = ["extra.conf", "values.conf"]
    expect("a build-only overlay among others on a HARDWARE row", t, "'values.conf'",
           build_values_overlays, entries=whole)
    t = hardware_table(); t["rows"][1]["conf_overlay"] = ["lab_build_values.conf"]
    expect("a build-only overlay known by its name alone", t, "made-up build values",
           build_values_overlays, entries=whole)
    t = hardware_table(); t["rows"][1]["conf_overlay"] = ["buried.conf"]
    expect("a marker below the settings is not the file's statement", t, None,
           build_values_overlays, entries=whole)
    t = _good_table(); t["rows"][1]["conf_overlay"] = ["values.conf"]
    t["rows"][1]["witness"] = {"lane": "Qzb", "record": "Round 9"}
    expect("a row that cites a record is a hardware claim", t, "made-up build values",
           build_values_overlays, entries=whole)
    t = hardware_table(); t["companions"][0]["conf_overlay"] = ["values.conf"]
    expect("a HARDWARE companion listing a build-only overlay", t, "made-up build values",
           build_values_overlays, entries=whole)

    if failures:
        print("zephyr-board-table: SELFTEST FAIL")
        for line in failures:
            print(f"  {line}")
        return 1
    print("zephyr-board-table: selftest ok (every refusal arm fires on its fixture)")
    return 0


def main(argv: list[str]) -> int:
    if argv[1:] == ["--selftest"]:
        return selftest()
    table_path = ROOT / TABLE
    try:
        table = json.loads(table_path.read_text())
    except (OSError, ValueError) as exc:
        print(f"zephyr-board-table: cannot read {TABLE}: {exc}")
        return 2
    if argv[1:] == ["--build-rows"]:
        findings = check(table)
        if findings:
            for line in findings:
                print(f"zephyr-board-table: {line}", file=sys.stderr)
            return 1
        # Six tab-separated fields: board, app, Rust target, link, the row board a
        # companion starts, overlay. A field with nothing to say is `-`, because
        # the reader's `read` folds a run of tabs into one separator and an empty
        # middle field would shift the rest left; only the last may be empty.
        for r in build_rows(table):
            print("\t".join([
                r["board"], r["app"], r["rust_target"], r["link"], "-",
                ";".join(r.get("conf_overlay", [])),
            ]))
        for c in build_companions(table):
            print("\t".join([
                c["board"], c["app"], "-", "companion", c["starts"],
                ";".join(c.get("conf_overlay", [])),
            ]))
        return 0
    if argv[1:]:
        print(f"zephyr-board-table: unknown argument {argv[1]!r}; use --selftest or --build-rows")
        return 2
    findings = check(table)
    if findings:
        print(f"zephyr-board-table: FAIL -- {len(findings)} finding(s)")
        for line in findings:
            print(f"  {line}")
        return 1
    by = {g: sum(1 for r in table["rows"] if r["grade"] == g) for g in GRADES}
    print(f"zephyr-board-table: OK -- {len(table['rows'])} row(s): "
          + ", ".join(f"{n} {g}" for g, n in by.items()))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
