#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
# SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
"""R3075 (no register item) -- the Zephyr BOARD TABLE and what its grades may claim.

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
     witness, which is exactly what the grade was invented to forbid.
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
            absent = [k for k in HARDWARE_RECORD if not witness.get(k)]
            if absent:
                out.append(f"{label}: HARDWARE record lacks {absent}")
            else:
                store_path = root / STORE
                entries = {}
                if store_path.is_file():
                    entries = json.loads(store_path.read_text()).get("changelog_entries", {})
                if witness["record"] not in entries:
                    out.append(
                        f"{label}: HARDWARE record {witness['record']!r} is not a "
                        f"changelog entry in the store -- a record with no entry is a "
                        f"claim with no witness"
                    )

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
    return out


def build_rows(table: dict) -> list[dict]:
    """The rows Layer Qzb builds: BUILT and HARDWARE."""
    return [r for r in table["rows"] if r.get("grade") in ("BUILT", "HARDWARE")]


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
                "conf_overlay": ["extra.conf"],
            },
            {
                "board": "other/board", "link": "t1s", "app": "adm",
                "network": "lwip-mac", "grade": "DECLARED",
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

    hw = _good_table()
    hw["rows"][1]["grade"] = "HARDWARE"
    hw["rows"][1]["witness"] = {
        "record": "Round 9", "image_sha256": "ab", "verdict": "ZEPHYR-WZ-ADMIN READY",
        "date": "2026-10-07", "by": "lab",
    }
    expect("HARDWARE whose entry is absent", hw, "not a changelog entry")
    expect("HARDWARE whose entry exists", hw, None, entries={"Round 9": {}})
    hw2 = _good_table()
    hw2["rows"][1]["grade"] = "HARDWARE"
    hw2["rows"][1]["witness"] = {"record": "Round 9"}
    expect("HARDWARE with a partial record", hw2, "lacks", entries={"Round 9": {}})

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
        for r in build_rows(table):
            print("\t".join([
                r["board"], r["app"], r["rust_target"], r["link"],
                ";".join(r.get("conf_overlay", [])),
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
