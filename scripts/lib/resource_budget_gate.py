#!/usr/bin/env python3
# SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
# SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

"""R3449 (no register item) -- the resource budget of an image is a figure that is committed, and a
change that moves it moves the row (docs/build-configuration.md step 13, storage-policy D5).

## What was missing

`stack_frame_gate.py` holds what the compiler can tell: the worst chain of direct calls under an
image's entry, committed as `peak`. Nothing held what the firmware says it did. The kit prints its
own high-water mark of the main stack (`stack: peak N of M bytes`, `StackWatch`), and the host
times the round trip of a query it asks; both were quoted in ledger entries and documents and
checked by nobody, so a change that made the image use 2 KB more, or answer 40 percent slower,
looked the same as one that did not.

## What is held

`deploy/resource_budget.json` has one row per image whose static worst chain is committed:

* `static_chain_bytes` is a COPY of that figure, and is held equal to `stack_frame_gate.py`'s. The
  copy is the point: a commit that moves the static figure alone, or the row alone, is a red, so
  moving it is a decision made in both places;
* `peak_stack_bytes` and `peak_stack_tolerance_bytes`: the firmware's own reading over a dial, a
  handshake and the queries the kit harness asks. It is a count of words the stack has written, the
  same on every run of an image, so its tolerance is small and a change that moves it is visible;
* `get_median_us` and `get_median_tolerance_pct`: the host's view of a GET to the image over the
  kit's Ethernet. It varies from run to run and from image to image of one configuration, so it has
  a tolerance of its own, and both directions are held: a run that is much faster than the row says
  the row is stale as much as a slower one says the image regressed.

## Modes

    --check      no hardware: the table covers the stack gate's population, copies its figure, and a
                 measured peak lies under the static chain and under the declared stack
    --measure KEY --log LOG [--result JSON ...]
                 the kit lane: the last stack line of a serial log and the GET medians of the
                 harness's result files, against the row (exit 1 outside it)
    --selftest   the rules, driven over tables that are wrong in each way
    --list       the keys

The measured figures come from the T2G kit and cannot be taken by a hosted job, so `--check` runs
everywhere and `--measure` where the kit is.
"""

from __future__ import annotations

import argparse
import json
import re
import statistics
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import stack_frame_gate as stack  # noqa: E402

ROOT = Path(__file__).resolve().parents[2]
TABLE = ROOT / "deploy" / "resource_budget.json"

ROW_KEYS = {
    "built_as": str,
    "static_chain_bytes": int,
    "peak_stack_bytes": int,
    "peak_stack_tolerance_bytes": int,
    "get_median_us": int,
    "get_median_tolerance_pct": int,
    "measured": str,
    "evidence": str,
}

#: The line the firmware prints when its stack high-water mark moves (`StackWatch`).
STACK_LINE = re.compile(r"stack: peak (\d+) of (\d+) bytes")


def read_table(path: Path = TABLE) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def population() -> dict[str, "stack.Image"]:
    """The images whose static worst chain is committed: the rows this table must have."""
    return {image.key: image for image in stack.IMAGES if image.peak is not None}


def problems(table: dict, images: dict[str, "stack.Image"], declared: dict[str, int]) -> list[str]:
    """Every way `table` fails to hold the population. Nothing here reads a file, so the selftest
    can drive it over a table that is wrong in each way."""
    out: list[str] = []
    if not images:
        return ["the stack gate commits no worst chain, so this table has no population (a population of "
                "zero is green about nothing)"]
    if table.get("schema") != 1:
        out.append(f"schema is {table.get('schema')!r}, this reader reads 1")
    rows = table.get("images")
    if not isinstance(rows, dict):
        return out + ["`images` is not an object"]
    for key in sorted(set(images) - set(rows)):
        out.append(f"{key}: the stack gate commits a worst chain for this image and the table has no row")
    for key in sorted(set(rows) - set(images)):
        out.append(f"{key}: a row with no committed worst chain in the stack gate behind it")
    for key in sorted(set(rows) & set(images)):
        row = rows[key]
        for field, kind in ROW_KEYS.items():
            if field not in row:
                out.append(f"{key}: no `{field}`")
            elif not isinstance(row[field], kind) or isinstance(row[field], bool):
                out.append(f"{key}: `{field}` is not a {kind.__name__}")
            elif kind is str and not row[field].strip():
                out.append(f"{key}: `{field}` is empty")
            elif kind is int and row[field] <= 0:
                out.append(f"{key}: `{field}` is not positive")
        for field in sorted(set(row) - set(ROW_KEYS)):
            out.append(f"{key}: `{field}` is a key nothing reads")
        if any(f not in row or not isinstance(row[f], ROW_KEYS[f]) for f in ROW_KEYS):
            continue
        if row["static_chain_bytes"] != images[key].peak:
            out.append(
                f"{key}: static_chain_bytes is {row['static_chain_bytes']} and the stack gate commits "
                f"{images[key].peak}: they move together or not at all"
            )
        if row["peak_stack_bytes"] > row["static_chain_bytes"]:
            out.append(
                f"{key}: the firmware reached {row['peak_stack_bytes']} bytes of stack and the static chain "
                f"is {row['static_chain_bytes']}: the chain misses a path the image takes"
            )
        if key in declared and row["peak_stack_bytes"] > declared[key]:
            out.append(f"{key}: the measured peak {row['peak_stack_bytes']} is over the declared stack {declared[key]}")
        if not 0 < row["get_median_tolerance_pct"] < 100:
            out.append(f"{key}: get_median_tolerance_pct is not between 0 and 100")
    return out


def last_stack_line(log: str) -> tuple[int, int] | None:
    hits = STACK_LINE.findall(log)
    return (int(hits[-1][0]), int(hits[-1][1])) if hits else None


def get_medians_us(results: list[dict]) -> tuple[float, int] | None:
    """The median of the GET round trips over the harness's result files, in microseconds, and how many
    answers were wrong. Both documents the harness asks count, as the ledger's figures do."""
    samples: list[float] = []
    bad = 0
    for result in results:
        for field in ("get_status_ms", "get_config_ms"):
            samples += [1000.0 * ms for ms in result.get(field, [])]
        bad += int(result.get("get_status_bad", 0)) + int(result.get("get_config_bad", 0))
    return (statistics.median(samples), bad) if samples else None


def measure_problems(row: dict, declared: int | None, log: str, results: list[dict]) -> list[str]:
    """Where a kit run lies outside `row`."""
    out: list[str] = []
    peak = last_stack_line(log)
    if peak is None:
        out.append("the log has no `stack: peak N of M bytes` line: the firmware did not say what it used")
    else:
        used, size = peak
        low, high = row["peak_stack_bytes"] - row["peak_stack_tolerance_bytes"], row["peak_stack_bytes"] + row["peak_stack_tolerance_bytes"]
        if not low <= used <= high:
            out.append(f"the stack peak is {used} bytes, the row holds {row['peak_stack_bytes']} +/- {row['peak_stack_tolerance_bytes']}")
        if declared is not None and size != declared:
            out.append(f"the firmware says its stack is {size} bytes and the image declares {declared}")
    if results:
        median = get_medians_us(results)
        if median is None:
            out.append("the result files hold no GET round trip")
        else:
            value, bad = median
            if bad:
                out.append(f"{bad} answer(s) of the kit's queries were wrong: a latency of wrong answers is not one")
            low = row["get_median_us"] * (100 - row["get_median_tolerance_pct"]) / 100
            high = row["get_median_us"] * (100 + row["get_median_tolerance_pct"]) / 100
            if not low <= value <= high:
                out.append(f"the GET median is {value:.0f} us, the row holds {row['get_median_us']} us "
                           f"+/- {row['get_median_tolerance_pct']} percent ({low:.0f} to {high:.0f})")
    return out


def declared_stacks(images: dict[str, "stack.Image"]) -> dict[str, int]:
    return {key: stack.declared_stack(image, ROOT) for key, image in images.items()}


def check() -> int:
    images = population()
    declared = declared_stacks(images) if images else {}
    found = problems(read_table(), images, declared)
    for line in found:
        print(f"  resource-budget FAIL: {line}", file=sys.stderr)
    if not found:
        rows = read_table()["images"]
        for key in sorted(rows):
            margin = declared[key] - rows[key]["peak_stack_bytes"]
            print(f"  resource-budget: {key}: static chain {rows[key]['static_chain_bytes']}, "
                  f"measured peak {rows[key]['peak_stack_bytes']} of {declared[key]} "
                  f"({margin} bytes of margin), GET {rows[key]['get_median_us']} us")
        print(f"  resource-budget: {len(rows)} image(s) held")
    return 1 if found else 0


def measure(key: str, log_path: Path, result_paths: list[Path]) -> int:
    images = population()
    rows = read_table().get("images", {})
    if key not in rows or key not in images:
        print(f"  resource-budget FAIL: {key} has no row (keys: {sorted(rows)})", file=sys.stderr)
        return 1
    declared = stack.declared_stack(images[key], ROOT)
    found = measure_problems(
        rows[key],
        declared,
        log_path.read_text(encoding="utf-8", errors="replace"),
        [json.loads(p.read_text(encoding="utf-8")) for p in result_paths],
    )
    for line in found:
        print(f"  resource-budget FAIL: {key}: {line}", file=sys.stderr)
    if not found:
        print(f"  resource-budget: {key}: the run is inside its row")
    return 1 if found else 0


def selftest() -> int:
    failures: list[str] = []

    def expect(label: str, got: object, want: object) -> None:
        if got != want:
            failures.append(f"{label}: got {got!r}, want {want!r}")

    image = stack.Image(key="k", elf=None, source="s", pattern="p", unit=1, entry="e", peak=6808)
    row = {
        "built_as": "x", "static_chain_bytes": 6808, "peak_stack_bytes": 5936, "peak_stack_tolerance_bytes": 16,
        "get_median_us": 400, "get_median_tolerance_pct": 30, "measured": "m", "evidence": "e",
    }
    good = {"schema": 1, "images": {"k": row}}
    declared = {"k": 9216}

    def case(label: str, table: dict, images: dict | None = None, want: str | None = None) -> None:
        found = problems(table, {"k": image} if images is None else images, declared)
        if want is None:
            expect(label, found, [])
        else:
            expect(label, [p for p in found if want in p] != [], True)

    case("a table that holds its population is clean", good)
    case("an image with no row", {"schema": 1, "images": {}}, want="no row")
    case("a row with no image behind it", {"schema": 1, "images": {"k": row, "z": row}}, want="no committed worst chain")
    case("a static figure that moved alone", {"schema": 1, "images": {"k": dict(row, static_chain_bytes=7000)}}, want="move together")
    case("a measured peak over the static chain", {"schema": 1, "images": {"k": dict(row, peak_stack_bytes=6900)}}, want="misses a path")
    case("a measured peak over the declared stack", {"schema": 1, "images": {"k": dict(row, static_chain_bytes=6808, peak_stack_bytes=9300)}}, want="over the declared stack")
    case("a key nothing reads", {"schema": 1, "images": {"k": dict(row, extra=1)}}, want="nothing reads")
    case("a missing figure", {"schema": 1, "images": {"k": {f: v for f, v in row.items() if f != "get_median_us"}}}, want="no `get_median_us`")
    case("a tolerance of nothing", {"schema": 1, "images": {"k": dict(row, get_median_tolerance_pct=0)}}, want="between 0 and 100")
    case("a wrong schema", {"schema": 2, "images": {"k": row}}, want="schema")
    expect("an empty population is a finding", problems(good, {}, {}) != [], True)

    log = "boot\nstack: peak 5900 of 9216 bytes\nstack: peak 5944 of 9216 bytes\n"
    expect("the last stack line is read", last_stack_line(log), (5944, 9216))
    expect("no stack line", last_stack_line("nothing"), None)
    inside = {"get_status_ms": [0.39, 0.40, 0.41], "get_config_ms": [0.40], "get_status_bad": 0, "get_config_bad": 0}
    expect("a run inside the row", measure_problems(row, 9216, log, [inside]), [])
    expect("a peak outside its tolerance", measure_problems(row, 9216, "stack: peak 6000 of 9216 bytes", [inside]) != [], True)
    expect("a wrong stack size", measure_problems(row, 8192, log, [inside]) != [], True)
    slow = dict(inside, get_status_ms=[0.9], get_config_ms=[0.9])
    expect("a slow run", measure_problems(row, 9216, log, [slow]) != [], True)
    fast = dict(inside, get_status_ms=[0.1], get_config_ms=[0.1])
    expect("a run much faster than the row says the row is stale", measure_problems(row, 9216, log, [fast]) != [], True)
    expect("a wrong answer", measure_problems(row, 9216, log, [dict(inside, get_status_bad=1)]) != [], True)
    expect("no stack line", measure_problems(row, 9216, "boot", [inside]) != [], True)

    for line in failures:
        print(f"  resource-budget selftest FAIL: {line}", file=sys.stderr)
    if not failures:
        print("  resource-budget selftest: the rules hold over tables wrong in each way")
    return 1 if failures else 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n", 1)[0])
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--check", action="store_true")
    mode.add_argument("--measure", metavar="KEY")
    mode.add_argument("--selftest", action="store_true")
    mode.add_argument("--list", action="store_true")
    parser.add_argument("--log", type=Path)
    parser.add_argument("--result", type=Path, action="append", default=[])
    args = parser.parse_args()
    if args.selftest:
        return selftest()
    if args.list:
        print("\n".join(sorted(population())))
        return 0
    if args.measure:
        if args.log is None:
            parser.error("--measure needs --log")
        return measure(args.measure, args.log, args.result)
    return check()


if __name__ == "__main__":
    sys.exit(main())
