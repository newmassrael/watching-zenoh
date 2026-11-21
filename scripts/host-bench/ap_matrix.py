#!/usr/bin/env python3
# SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
# SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
"""The AP superiority matrix (docs/ap-superiority-matrix.md, docs/upstream-parity.md D13): the
application-processor presets of wz held against upstream zenoh in every aspect the matrix names
(performance, size and memory, completeness), as a ratchet and a debt loop. The reading, the verdict
and the ratchet of a figure are the pico performance matrix's (D10), imported from perf_matrix.py.

TWO PAIRS, each measured on one host in one run, its two arms alternating by repetition:

  * router  arm W is the wz router preset (wz-ap-demo reading a stock zenohd configuration document
            with --config), arm U is zenohd at UPSTREAM_VERSION; both start on the same document.
            The programs around the router are upstream's examples built against upstream zenoh in
            both arms, so a difference is the router's.
  * api     arm W is upstream's example programs built against wz-zenoh (the family patched in),
            arm U the same sources built against upstream zenoh (z8_upstream_suite.py examples:
            one manifest and upstream's release profile for both). A cell through a router uses
            zenohd in both arms, so a difference is the API's.

    ap_matrix.py --selftest
        every rule of the gate and every reader of the runner, on synthetic input
    ap_matrix.py --check-table [TABLE]
        the committed table (deploy/ap_superiority.json): its shape, its rows exactly the population
        of the matrix, a debt on every row that is not locked, and every filled completeness row
        held to the figure the tree states now (those figures need no run)
    ap_matrix.py --gate READING [--table TABLE]
        a run's reading judged row by row. Exit 0 every row held, 1 a row failed, 2 an input refused,
        3 nothing failed and a row was not measured (a narrowed run, a cell with no harness)
    ap_matrix.py --fill READING [--table TABLE] [--write]
        the rows the reading writes (a null row filled, a ratchet tightened, a WIN locked), printed;
        with --write, written into TABLE. A row only moves toward WIN.
    ap_matrix.py cells [SELECTOR]
        the cells of the matrix, each with its kind and, where it has none, why it has no harness
    ap_matrix.py run --cells SELECTOR[,SELECTOR...] --run DIR [--reps 5] [--client-cpus 4-7]
                     [--server-cpus 8-11] [--router-cpus 12-19] [--warmup-s 3] [--window-s 10]
                     [--pings 20000] [--bin-dir DIR] [--table TABLE]
        build both sides (unless --bin-dir names the programs of an earlier run), measure the
        selected cells and write DIR/reading.json, then judge it. SELECTOR is a shell pattern over
        cell keys (<pair>/<workload>/<topology>/<parameter>), or all.

A ROW is one figure of one cell, keyed <pair>/<workload>/<topology>/<parameter>/<figure>. A
performance or size row reads the COST RATIO of D10 (wz's figure over upstream's when lower is
better, upstream's over wz's when higher is better, so below 1 is wz ahead) with its bootstrap 95%
interval over the repetitions, and its verdict is D1's: WIN, TIE or LOSS. A completeness row reads a
SHORTFALL: how many of upstream's own tests, scenarios or configuration keys wz does not yet meet,
held toward 0. A row of the table is {"held": H, "debt": D}: H is null (not filled: NOT-MEASURED
when the run did not measure it, a failure that prints the row when it did), {"locked": true} (only
a WIN, or a shortfall of 0, passes), {"ratio_at_most": R} or {"shortfall_at_most": N} (the ratchet:
a reading may not be worse, and a better one prints the tighter row) or {"reference_lost": WHY}; D is
the open-debt item of a row that is not locked (debt-<id> of the store's inventory, or debt-TBD
until it is filed, which a filled row may not keep).
"""

from __future__ import annotations

import argparse
import dataclasses
import fnmatch
import json
import math
import os
import pathlib
import re
import shutil
import socket
import statistics
import struct
import subprocess
import sys
import threading
import time

HERE = pathlib.Path(__file__).resolve().parent
ROOT = HERE.parents[1]
LIB = ROOT / "scripts" / "lib"
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(LIB))

import perf_matrix as pm  # noqa: E402  -- D10's reading, verdict and ratchet
from nodrop import FOREIGN_LIMIT, MAX_RUNS, busy_seconds, cpu_list  # noqa: E402
from parity import BARE_NUMBER, MIN_REPORTS, RTT_TAGGED, Lost, Process  # noqa: E402

TABLE = ROOT / "deploy" / "ap_superiority.json"
TABLE_SCHEMA = "wz-ap-superiority/1"
READING_SCHEMA = "wz-ap-reading/1"
PAIRS = ("router", "api")
#: U upstream zenoh (zenohd, or a program built against upstream's crates), W wz.
ARMS = ("U", "W")
DEBT_PLACEHOLDER = "debt-TBD"
DEBT_ID = re.compile(r"debt-[a-z0-9][a-z0-9-]*")
COMPLETE_KINDS = ("locked", "shortfall_at_most")

#: Every figure a row can hold: which way it is better, and its unit.
METRICS = {
    "msgs_per_s": ("higher", "messages a second delivered"),
    "cpu_ns_per_msg": ("lower", "nanoseconds of CPU per delivered message"),
    "rss_kib": ("lower", "KiB of resident set"),
    "rtt_p50_us": ("lower", "microseconds"),
    "rtt_p99_us": ("lower", "microseconds"),
    "query_rtt_p50_us": ("lower", "microseconds"),
    "query_rtt_p99_us": ("lower", "microseconds"),
    "queries_per_s": ("higher", "replies a second"),
    "tokens_per_s": ("higher", "liveliness tokens declared and undeclared a second"),
    "open_us": ("lower", "microseconds"),
    "heap_peak_kib": ("lower", "KiB held through the C allocator at its peak"),
    "stripped_bytes": ("lower", "bytes"),
    "shortfall": ("lower", "upstream items wz does not meet"),
}

#: How a cell is read. TIMED: a figure of time or CPU, valid only while the pinned CPUs were used by
#: nothing else. FUNCTIONAL: a figure of memory, read once per repetition. SINGLE: one figure per
#: build. STATIC: a figure the tree states, read with no build.
TIMED, FUNCTIONAL, SINGLE, STATIC = "timed", "functional", "single", "static"
WORKLOAD_KIND = {
    "thr": TIMED, "lat": TIMED, "fanout": TIMED, "multihop": TIMED, "scaling": TIMED, "flows": TIMED,
    "query": TIMED, "churn": TIMED, "open": TIMED, "idle": FUNCTIONAL, "heap": FUNCTIONAL,
    "size": SINGLE, "complete": STATIC,
}

SIZES = (8, 1024, 65536)
LAT_SIZES = (8, 1024)
FANOUT = (1, 16, 128)
CORES = (1, 2, 4, 8)
FLOWS = 1000
THR = ("msgs_per_s", "cpu_ns_per_msg", "rss_kib")
LAT = ("rtt_p50_us", "rtt_p99_us")
#: The pair and the topology of the cells that run upstream's throughput and round-trip programs:
#: peer to peer, and through one router.
STREAMS = (("api", "p2p"), ("api", "r1"), ("router", "r1"))

#: The cells no harness measures yet, and why; each row of them is NOT-MEASURED and a debt.
NO_HARNESS = (
    ("router/flows/*", "upstream's example programs publish on one key at one rate; a load program "
                       "written against the zenoh API, compiled against each crate, that drives a "
                       "thousand keys at mixed rates is owed"),
    ("*/query/*", "upstream's z_get makes one query and exits, so a round trip or a rate would hold its "
                  "session open; a looping getter written against the zenoh API is owed"),
    ("*/churn/*", "no program of upstream's examples declares and undeclares liveliness tokens in a "
                  "loop; a churn program written against the zenoh API is owed"),
    ("router/complete/plugin-storage-manager/*",
     "no harness starts the storage manager configuration zenohd accepts on the wz router and "
     "compares what each accepts and serves"),
    ("router/complete/plugin-rest/*",
     "no harness starts the REST plugin configuration zenohd accepts on the wz router and compares "
     "what each accepts and serves"),
)

#: The programs of upstream's examples package both API arms are built with (z8_upstream_suite.py
#: PARITY_EXAMPLES).
PROGRAMS = ("z_put", "z_sub", "z_get", "z_queryable", "z_pub_thr", "z_sub_thr", "z_ping", "z_pong")
#: The wz router preset: wz-ap-demo's default features with the router run-mode and the reader of a
#: stock zenohd configuration document. The declaration has no zenohd original whose defconfig
#: would derive these (docs/ap-superiority-matrix.md, section 7), so they are stated here.
ROUTER_FEATURES = ("routing-router", "zenoh-config")
#: The seconds a server side is given before the client side starts (parity.py's).
SETTLE_S = 1.5
#: The longest a router is given to accept a connection on its port.
ROUTER_WAIT_S = 20.0
#: The seconds two routers are given to link before a client opens.
LINK_S = 2.0
#: The seconds an idle program is left before its resident set is read.
IDLE_S = 5.0
#: The opens of z_put one repetition of an open cell times.
OPEN_SAMPLES = 20
#: The longest one z_put may take, open, put and close.
OPEN_BOUND_S = 30.0
#: What z_ping may take past its warm-up.
PING_BOUND_S = 120.0


class Fatal(Exception):
    """A figure the tree states that cannot be read. Never a silent pass."""


class Refusal(Exception):
    """An input or a build a run cannot measure from: the run is NOT-MEASURED (exit 2)."""


class Skipped(Exception):
    """A cell this host cannot run as asked (too few CPUs on a side): neither arm's loss."""


# -- the matrix -------------------------------------------------------------------------------------

def matrix() -> list[tuple[str, tuple[str, ...]]]:
    """Every cell of the matrix and the figures each holds, in the order a run measures them."""
    out: list[tuple[str, tuple[str, ...]]] = []
    for pair, topo in STREAMS:
        out += [(f"{pair}/thr/{topo}/{size}", THR) for size in SIZES]
    for pair, topo in STREAMS:
        out += [(f"{pair}/lat/{topo}/{size}", LAT) for size in LAT_SIZES]
    for pair in PAIRS:
        out += [(f"{pair}/fanout/r1/{n}", THR) for n in FANOUT]
    out.append(("router/multihop/r2/8", ("msgs_per_s", *LAT)))
    out += [(f"router/scaling/r1/{cores}", ("msgs_per_s",)) for cores in CORES]
    out.append((f"router/flows/r1/{FLOWS}", ("msgs_per_s", "rtt_p99_us")))
    for pair, topo in STREAMS:
        out.append((f"{pair}/query/{topo}/0", ("query_rtt_p50_us", "query_rtt_p99_us", "queries_per_s")))
    out += [(f"{pair}/churn/r1/0", ("tokens_per_s",)) for pair in ("api", "router")]
    out += [(f"api/open/{topo}/0", ("open_us",)) for topo in ("p2p", "r1")]
    out += [("router/idle/r1/0", ("rss_kib",)), ("api/idle/p2p/0", ("rss_kib",))]
    out += [("router/heap/r1/1024", ("heap_peak_kib",)), ("api/heap/p2p/1024", ("heap_peak_kib",))]
    out += [("router/size/bin/0", ("stripped_bytes",)), ("api/size/bin/0", ("stripped_bytes",))]
    out += [(f"{cell}/0", ("shortfall",)) for cell in (
        "api/complete/z8-tests", "api/complete/z8-examples", "router/complete/config-keys",
        "router/complete/plugin-storage-manager", "router/complete/plugin-rest")]
    return out


def population() -> list[str]:
    """Every row of the matrix, in its order."""
    return [f"{cell}/{metric}" for cell, metrics in matrix() for metric in metrics]


def cell_of(key: str) -> str:
    return key.rsplit("/", 1)[0]


def workload_of(cell: str) -> str:
    return cell.split("/")[1]


def kind_of(cell: str) -> str:
    return WORKLOAD_KIND[workload_of(cell)]


def is_complete(key: str) -> bool:
    return key.split("/")[1] == "complete"


def metrics_of(cell: str) -> tuple[str, ...]:
    return dict(matrix()).get(cell, ())


def no_harness(cell: str) -> str | None:
    for pattern, why in NO_HARNESS:
        if fnmatch.fnmatchcase(cell, pattern):
            return why
    return None


def row_order(key: str) -> tuple[int, str]:
    order = {k: i for i, k in enumerate(population())}
    return order.get(key, len(order)), key


def select(spec: str) -> list[str]:
    """The cells a comma list of shell patterns names, in the matrix's order; `all` is every cell. A
    pattern that names no cell is a ValueError."""
    cells = [cell for cell, _ in matrix()]
    patterns = [p.strip() for p in spec.split(",") if p.strip()]
    if not patterns:
        raise ValueError("no cell selector was given")
    if patterns == ["all"]:
        return cells
    picked: set[str] = set()
    for pattern in patterns:
        hit = {cell for cell in cells if fnmatch.fnmatchcase(cell, pattern)}
        if not hit:
            raise ValueError(f"the selector {pattern} names no cell (ap_matrix.py cells lists them)")
        picked |= hit
    return [cell for cell in cells if cell in picked]


# -- the table --------------------------------------------------------------------------------------

def is_locked(held: object) -> bool:
    return isinstance(held, dict) and held.get("locked") is True


def complete_held_error(held: object) -> str | None:
    if held is None:
        return None
    if not isinstance(held, dict) or len(held) != 1 or next(iter(held)) not in COMPLETE_KINDS:
        return ('a completeness row holds null, {"locked": true} or {"shortfall_at_most": N}, not '
                + json.dumps(held))
    kind, given = next(iter(held.items()))
    if kind == "locked" and given is not True:
        return "`locked` is true or the row is something else"
    if kind == "shortfall_at_most" and (isinstance(given, bool) or not isinstance(given, int) or given < 1):
        return "`shortfall_at_most` is a count of at least 1; a shortfall of 0 is a locked row"
    return None


def entry_error(key: str, row: object) -> str | None:
    """Why one row of a table is malformed, or None."""
    parts = key.split("/")
    if len(parts) != 5 or parts[0] not in PAIRS or not parts[3].isdigit() or parts[4] not in METRICS:
        return (f"the key is not <pair>/<workload>/<topology>/<parameter>/<figure> with a pair of "
                f"{', '.join(PAIRS)} and a figure of METRICS")
    if not isinstance(row, dict) or set(row) != {"held", "debt"}:
        return 'a row is {"held": ..., "debt": ...} and nothing else'
    held, debt = row["held"], row["debt"]
    error = complete_held_error(held) if is_complete(key) else pm.row_error(held)
    if error:
        return error
    if is_locked(held):
        if debt is not None and not (isinstance(debt, str) and DEBT_ID.fullmatch(debt)):
            return "a locked row's debt is null, or the debt-<id> its WIN closed"
    elif not (isinstance(debt, str) and (debt == DEBT_PLACEHOLDER or DEBT_ID.fullmatch(debt))):
        return (f"a row that is not locked names its debt: debt-<id> of the store's inventory, or "
                f"{DEBT_PLACEHOLDER} until one is filed")
    return None


def parse_table(text: str) -> tuple[dict[str, dict], float]:
    """The rows and the tolerance of a table."""
    try:
        doc = json.loads(text, object_pairs_hook=pm.refuse_duplicates)
    except ValueError as error:
        raise pm.Refused(f"not JSON: {error}") from None
    if not isinstance(doc, dict) or doc.get("schema") != TABLE_SCHEMA:
        raise pm.Refused(f"the schema is not {TABLE_SCHEMA}")
    tolerance = doc.get("tolerance")
    if isinstance(tolerance, bool) or not isinstance(tolerance, (int, float)) or not 0 <= tolerance < 1:
        raise pm.Refused("`tolerance` is a number from 0 up to, not including, 1")
    rows = doc.get("rows")
    if not isinstance(rows, dict):
        raise pm.Refused("`rows` is an object of row keys")
    for key, row in rows.items():
        error = entry_error(key, row)
        if error:
            raise pm.Refused(f"{key}: {error}")
    return rows, float(tolerance)


def load_table(path: pathlib.Path) -> tuple[dict[str, dict], float]:
    try:
        text = path.read_text(encoding="utf-8")
    except OSError as error:
        raise pm.Refused(f"{path} cannot be read: {error}") from None
    try:
        return parse_table(text)
    except pm.Refused as why:
        raise pm.Refused(f"{path}: {why}") from None


def table_text(doc: dict) -> str:
    """A table as it is committed: its head keys, then one line per row in the matrix's order."""
    lines = ["{"]
    for key, value in doc.items():
        if key != "rows":
            lines.append(f"  {json.dumps(key)}: {json.dumps(value, ensure_ascii=False)},")
    lines.append('  "rows": {')
    keys = sorted(doc["rows"], key=row_order)
    for i, key in enumerate(keys):
        comma = "," if i < len(keys) - 1 else ""
        lines.append(f"    {json.dumps(key)}: {json.dumps(doc['rows'][key])}{comma}")
    lines += ["  }", "}"]
    return "\n".join(lines) + "\n"


# -- the figures the tree states (completeness) -----------------------------------------------------

def short_list(names: list[str], limit: int = 6) -> str:
    if not names:
        return "none"
    shown = ", ".join(names[:limit])
    return shown if len(names) <= limit else f"{shown} and {len(names) - limit} more"


def by_status(statuses) -> str:
    """How many rows have each status, the commonest first: an unmeasured row is told from one that
    was measured short."""
    counts: dict[str, int] = {}
    for status in statuses:
        counts[status] = counts.get(status, 0) + 1
    return ", ".join(f"{n} {s}" for s, n in sorted(counts.items(), key=lambda kv: (-kv[1], kv[0])))


def completeness_figures(tests_text: str | None = None, examples_text: str | None = None,
                         unhonoured: list[str] | None = None) -> dict[str, tuple[int, str]]:
    """Each completeness cell that has a reader, as (shortfall, what it says). The figures are read
    from the tables the API-compatibility program grades its runs against, and from the reader's
    own list of the zenohd configuration keys it does not honour; nothing is run."""
    import deepenable_audit
    import z8_expectation_gate as zeg

    try:
        tests = zeg.parse_table(zeg.EXPECTED.read_text(encoding="utf-8") if tests_text is None else tests_text)
        scenarios = zeg.parse_examples_table(
            zeg.EXAMPLES_EXPECTED.read_text(encoding="utf-8") if examples_text is None else examples_text)
        keys = deepenable_audit.rust_const("UNHONOURED_UPSTREAM_CONFIG_KEYS") if unhonoured is None else unhonoured
    except (OSError, ValueError, SystemExit) as why:
        raise Fatal(str(why)) from None
    if not tests or not scenarios:
        raise Fatal("a table of the API-compatibility program declares no row: nothing would be read")
    out: dict[str, tuple[int, str]] = {}
    short = sorted(name for name, (status, _minimum, _lane, _reason) in tests.items()
                   if status not in ("pass", "empty"))
    out["api/complete/z8-tests/0"] = (
        len(short), f"{len(tests) - len(short)} of {len(tests)} files of upstream's tests pass (or run no "
                    f"test upstream either) against wz-zenoh by docs/z8-expected.tsv "
                    f"({by_status(s for s, _m, _l, _r in tests.values())}); the rest: {short_list(short)}")
    short = sorted(name for name, scenario in scenarios.items() if scenario.status != "same")
    out["api/complete/z8-examples/0"] = (
        len(short), f"{len(scenarios) - len(short)} of {len(scenarios)} scenarios of upstream's examples show "
                    f"the same on wz-zenoh by docs/z8-examples-expected.tsv "
                    f"({by_status(s.status for s in scenarios.values())}); the rest: {short_list(short)}")
    out["router/complete/config-keys/0"] = (
        len(keys), f"{len(keys)} key(s) of zenohd's configuration the wz reader does not honour "
                   f"(UNHONOURED_UPSTREAM_CONFIG_KEYS): {short_list(sorted(keys))}")
    return out


def judge_complete(figures: dict[str, tuple[int, str]], rows: dict[str, object]) -> list[pm.Judged]:
    """Every completeness row of the table and every completeness figure read, judged."""
    out: list[pm.Judged] = []
    keys = {f"{cell}/shortfall" for cell in figures} | set(rows)
    for key in sorted(keys, key=row_order):
        cell = cell_of(key)
        got = figures.get(cell)
        if got is None:
            why = no_harness(cell)
            out.append(pm.Judged(key, "NOT-MEASURED",
                                 f"no harness: {why}" if why else "this run did not read the figure"))
            continue
        value, said = got
        fill = {"locked": True} if value == 0 else {"shortfall_at_most": value}
        if key not in rows:
            out.append(pm.Judged(key, "FAIL", f"the run reads this figure and the table has no row for it "
                                              f"({said})", fill))
            continue
        held = rows[key]
        if held is None:
            out.append(pm.Judged(key, "FAIL", f"the row is not filled; paste the row below ({said})", fill))
        elif is_locked(held):
            if value == 0:
                out.append(pm.Judged(key, "PASS", said))
            else:
                out.append(pm.Judged(key, "FAIL", f"locked at a shortfall of 0, and reads {value}: {said}"))
        else:
            limit = held["shortfall_at_most"]
            if value > limit:
                out.append(pm.Judged(key, "FAIL", f"a shortfall of {value} is over the ratchet {limit}: {said}"))
            elif value == 0:
                out.append(pm.Judged(key, "PASS", f"met: {said}; lock the row", {"locked": True}))
            elif value < limit:
                out.append(pm.Judged(key, "PASS", f"{value} is under the ratchet {limit}, so tighten it: {said}",
                                     {"shortfall_at_most": value}))
            else:
                out.append(pm.Judged(key, "PASS", f"within the ratchet {limit}: {said}"))
    return out


# -- the readings of a run --------------------------------------------------------------------------

def positive(value: object) -> bool:
    return isinstance(value, (int, float)) and not isinstance(value, bool) and value > 0


def cost_ratio(metric: str, wz: list[float], ref: list[float]) -> tuple[float, float, float]:
    """D10's cost ratio: wz over upstream when the figure is better lower, upstream over wz when
    better higher, so below 1 is wz ahead either way, with its bootstrap 95% interval."""
    if METRICS[metric][0] == "lower":
        return pm.bootstrap_ratio(wz, ref)
    return pm.bootstrap_ratio(ref, wz)


def readings(cells: list[dict]) -> dict[str, pm.Reading]:
    """Every row a run's repetitions read, as D10 reads them: a repetition the host disturbed is no
    repetition, any other repetition wz lost fails its rows, a reference that lost every repetition
    leaves the rows without a ratio, and fewer than three measured repetitions of an arm give none."""
    groups: dict[str, dict[str, dict]] = {}
    for cell in cells:
        arm = groups.setdefault(cell["cell"], {}).setdefault(cell["arm"], {"figures": [], "lost": []})
        if cell["status"] == "measured":
            arm["figures"].append(cell["figures"])
        elif cell["status"] == "lost" and not cell.get("disturbed"):
            arm["lost"].append(f"r{cell['rep']}: {cell.get('why', 'no reason given')}")
    out: dict[str, pm.Reading] = {}
    for name, arms in groups.items():
        wz, ref = arms.get("W"), arms.get("U")
        if wz is None or ref is None:
            continue
        for metric in metrics_of(name):
            key = f"{name}/{metric}"
            if wz["lost"]:
                out[key] = pm.Reading("wz-lost", f"wz lost {len(wz['lost'])} repetition(s) ({wz['lost'][0]})")
                continue
            if not ref["figures"] and ref["lost"]:
                out[key] = pm.Reading("reference-lost", f"upstream lost every repetition ({ref['lost'][0]})")
                continue
            ws = [f[metric] for f in wz["figures"] if positive(f.get(metric))]
            rs = [f[metric] for f in ref["figures"] if positive(f.get(metric))]
            if len(ws) < pm.MIN_REPS or len(rs) < pm.MIN_REPS:
                out[key] = pm.Reading("too-few", f"{len(ws)} repetition(s) of wz and {len(rs)} of upstream gave "
                                                 f"{metric}, and an interval needs {pm.MIN_REPS} of each")
                continue
            point, lo, hi = cost_ratio(metric, ws, rs)
            out[key] = pm.Reading("ratio", point=point, lo=lo, hi=hi, verdict=pm.verdict_of(lo, hi))
    return out


def size_readings(sizes: dict) -> dict[str, pm.Reading]:
    """A size is one figure per build (D1): its ratio is exact, WIN when wz is smaller."""
    out: dict[str, pm.Reading] = {}
    for name, arms in sizes.items():
        for metric in metrics_of(name):
            key = f"{name}/{metric}"
            wz, ref = arms.get("W"), arms.get("U")
            if not positive(wz) or not positive(ref):
                side = "wz" if not positive(wz) else "upstream"
                out[key] = pm.Reading("too-few", f"the reading has no size of {side}")
                continue
            ratio = wz / ref
            out[key] = pm.Reading("ratio", point=ratio, lo=ratio, hi=ratio, verdict=pm.verdict_of(ratio, ratio))
    return out


def reading_document(cells: list[dict], sizes: dict | None = None, completeness: dict | None = None,
                     record: dict | None = None, not_measured: dict | None = None) -> dict:
    """The one shape of a reading: what the runner writes, what the gate reads (check_reading) and
    what the selftest builds. `cells` is a list of cell records ({cell, arm, rep, status, figures |
    why}), `sizes` maps a size cell to {W, U}, `completeness` maps a completeness cell to {shortfall,
    said}. Nothing is coerced, so a value of the wrong shape reaches check_reading and is refused."""
    return {"schema": READING_SCHEMA, "record": {} if record is None else record, "cells": cells,
            "sizes": {} if sizes is None else sizes, "completeness": {} if completeness is None else completeness,
            "not_measured": {} if not_measured is None else not_measured}


def load_reading(path: pathlib.Path) -> dict:
    try:
        doc = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as why:
        raise pm.Refused(f"{path} cannot be read: {why}") from None
    return check_reading(doc, str(path))


def check_reading(doc: object, where: str) -> dict:
    if not isinstance(doc, dict) or doc.get("schema") != READING_SCHEMA:
        raise pm.Refused(f"{where} is not a reading of schema {READING_SCHEMA}")
    for name, kind in (("cells", list), ("sizes", dict), ("completeness", dict)):
        if not isinstance(doc.get(name), kind):
            raise pm.Refused(f"{where}: `{name}` is not a {kind.__name__}")
    for cell in doc["cells"]:
        if not isinstance(cell, dict) or not {"cell", "arm", "rep", "status"} <= set(cell):
            raise pm.Refused(f"{where}: a cell record lacks one of cell, arm, rep, status: {json.dumps(cell)[:120]}")
    return doc


# -- the gate ---------------------------------------------------------------------------------------

def grade(doc: dict, rows: dict[str, dict], tolerance: float) -> list[pm.Judged]:
    """Every row of the table and every row the reading has, judged: the performance and size rows
    by D10's judge, the completeness rows by their shortfall, and a filled row that is not locked
    fails while it names no registered debt."""
    found = readings(doc.get("cells", []))
    found.update(size_readings(doc.get("sizes", {})))
    perf_rows = {key: row["held"] for key, row in rows.items() if not is_complete(key)}
    judged = []
    for j in pm.judge(found, perf_rows, tolerance):
        why = no_harness(cell_of(j.key))
        if j.outcome == "NOT-MEASURED" and j.reading is None and why:
            j = dataclasses.replace(j, sentence=f"no harness: {why}")
        judged.append(j)
    figures = {name: (int(value["shortfall"]), str(value.get("said", "")))
               for name, value in doc.get("completeness", {}).items()}
    judged += judge_complete(figures, {key: row["held"] for key, row in rows.items() if is_complete(key)})
    out = []
    for j in judged:
        row = rows.get(j.key)
        locks = j.edit is not None and j.edit.get("locked") is True
        if (row is not None and j.outcome == "PASS" and row["held"] is not None and not is_locked(row["held"])
                and row["debt"] == DEBT_PLACEHOLDER and not locks):
            j = dataclasses.replace(j, outcome="FAIL", sentence=(
                f"{j.sentence}; the row names no registered debt ({DEBT_PLACEHOLDER}): a cell that is no WIN is "
                f"an open-debt item (D5), so file it in the store's inventory and write its debt-<id>"))
        out.append(j)
    return out


def fill_edits(judged: list[pm.Judged], rows: dict[str, dict]) -> dict[str, dict]:
    """The rows a judgement writes, each replacing the row of its key: only rows of the matrix, and
    only the edits the judge prints (a fill, a tighter ratchet, a lock), so a row moves only toward
    WIN. A lock drops a placeholder debt; any other edit keeps the row's debt."""
    wanted = set(population())
    out: dict[str, dict] = {}
    for j in judged:
        if j.edit is None or j.key not in wanted:
            continue
        debt = rows.get(j.key, {}).get("debt", DEBT_PLACEHOLDER)
        registered = isinstance(debt, str) and DEBT_ID.fullmatch(debt) is not None
        if j.edit.get("locked") is True:
            debt = debt if registered else None
        elif not registered:
            debt = DEBT_PLACEHOLDER
        out[j.key] = {"held": j.edit, "debt": debt}
    return out


def print_judged(judged: list[pm.Judged], rows: dict[str, dict], table: str, tolerance: float) -> str:
    outcome = pm.outcome_of(judged)
    counts = {o: sum(j.outcome == o for j in judged) for o in ("PASS", "FAIL", "NOT-MEASURED")}
    print(f"ap-gate: {len(judged)} row(s), {counts['PASS']} pass, {counts['FAIL']} fail, "
          f"{counts['NOT-MEASURED']} not measured (table {table}, tolerance {tolerance})", flush=True)
    harnessless = [j for j in judged if j.outcome == "NOT-MEASURED" and j.sentence.startswith("no harness")]
    for j in judged:
        if j not in harnessless and (j.outcome != "PASS" or j.edit is not None):
            print(f"  {j.outcome} {j.key}: {j.sentence}", flush=True)
    edits = fill_edits(judged, rows)
    if edits:
        print("ap-gate: rows to write into the table's rows (each replaces the row of its key; "
              "ap_matrix.py --fill --write writes them):", flush=True)
        for key, value in edits.items():
            print(f"  {json.dumps(key)}: {json.dumps(value)},", flush=True)
    owed = pm.debts([j for j in judged if not is_complete(j.key)])
    if owed:
        print(f"ap-gate: {len(owed)} row(s) not WIN, the debts, largest ratio first:", flush=True)
        for j in owed:
            print(f"  {j.key}: {j.reading.shown()} ({rows.get(j.key, {}).get('debt', 'no row')})", flush=True)
    short = [j for j in judged if is_complete(j.key) and j.outcome != "NOT-MEASURED"
             and not (j.edit or {}).get("locked") and not is_locked(rows.get(j.key, {}).get("held"))]
    if short:
        print(f"ap-gate: {len(short)} completeness row(s) short of upstream, each a debt:", flush=True)
        for j in short:
            print(f"  {j.key}: {j.sentence} ({rows.get(j.key, {}).get('debt', 'no row')})", flush=True)
    if harnessless:
        cells = sorted({cell_of(j.key) for j in harnessless}, key=lambda c: row_order(f"{c}/{metrics_of(c)[0]}"))
        print(f"ap-gate: {len(harnessless)} row(s) of {len(cells)} cell(s) have no harness, each a debt:", flush=True)
        for cell in cells:
            print(f"  {cell}: {no_harness(cell)}", flush=True)
    print(f"ap-gate: {outcome}", flush=True)
    return outcome


def cmd_gate(reading: pathlib.Path, table: pathlib.Path) -> int:
    try:
        doc = load_reading(reading)
        rows, tolerance = load_table(table)
        judged = grade(doc, rows, tolerance)
    except (KeyError, TypeError, ValueError, pm.Refused) as why:
        print(f"ap-gate: refused: {why}", file=sys.stderr, flush=True)
        return 2
    return pm.exit_status([print_judged(judged, rows, str(table), tolerance)])


def cmd_fill(reading: pathlib.Path, table: pathlib.Path, write: bool) -> int:
    try:
        doc = load_reading(reading)
        rows, tolerance = load_table(table)
        edits = fill_edits(grade(doc, rows, tolerance), rows)
    except (KeyError, TypeError, ValueError, pm.Refused) as why:
        print(f"ap-fill: refused: {why}", file=sys.stderr, flush=True)
        return 2
    if not edits:
        print("ap-fill: the reading writes no row", flush=True)
        return 0
    for key, value in edits.items():
        print(f"  {json.dumps(key)}: {json.dumps(value)},", flush=True)
    if write:
        whole = json.loads(table.read_text(encoding="utf-8"))
        whole["rows"].update(edits)
        table.write_text(table_text(whole), encoding="utf-8")
        print(f"ap-fill: {len(edits)} row(s) written into {table}", flush=True)
    return 0


def check_table(path: pathlib.Path) -> int:
    """The committed table's shape, its rows exactly the matrix's population, and each filled
    completeness row held to the figure the tree states now."""
    try:
        rows, tolerance = load_table(path)
    except pm.Refused as why:
        print(f"ap-gate table: refused: {why}", file=sys.stderr)
        return 2
    wanted = population()
    missing = [key for key in wanted if key not in rows]
    extra = sorted(set(rows) - set(wanted))
    for key in missing:
        print(f"  ap-gate table FAIL: no row for {key}, a row of the matrix", file=sys.stderr)
    for key in extra:
        print(f"  ap-gate table FAIL: the row {key} is no row of the matrix", file=sys.stderr)
    if missing or extra:
        return 1
    try:
        figures = completeness_figures()
    except Fatal as why:
        print(f"ap-gate table: refused: a completeness figure cannot be read: {why}", file=sys.stderr)
        return 2
    filled = {key: row["held"] for key, row in rows.items() if is_complete(key) and row["held"] is not None}
    held = [j for j in judge_complete(figures, filled) if j.key in filled]
    failed = [j for j in held if j.outcome == "FAIL"]
    for j in failed:
        print(f"  ap-gate table FAIL {j.key}: {j.sentence}", file=sys.stderr)
    for j in held:
        if j.outcome == "PASS" and j.edit is not None:
            print(f"  ap-gate table: {j.key}: {j.sentence}; the row to write: {json.dumps(j.edit)}")
    for key in wanted:
        if is_complete(key) and rows[key]["held"] is None and cell_of(key) in figures:
            value, said = figures[cell_of(key)]
            fill = {"locked": True} if value == 0 else {"shortfall_at_most": value}
            print(f"  ap-gate table: {key} is not filled; the tree reads {json.dumps(fill)} ({said})")
    if failed:
        return 1
    count = sum(row["held"] is not None for row in rows.values())
    harnessless = sum(no_harness(cell_of(key)) is not None for key in rows)
    placeholders = sum(row["debt"] == DEBT_PLACEHOLDER for row in rows.values())
    print(f"  ap-gate table: {len(rows)} row(s), the population of the matrix; {count} filled, "
          f"{len(rows) - count} not yet; {harnessless} with no harness; {placeholders} under {DEBT_PLACEHOLDER} "
          f"(tolerance {tolerance})")
    return 0


# -- the readers of the runner ----------------------------------------------------------------------

def percentile(values: list[float], q: float) -> float:
    """The nearest-rank percentile q (0 < q <= 1) of the values."""
    ordered = sorted(values)
    return ordered[max(1, math.ceil(q * len(ordered))) - 1]


def window_rates(lines: list[str], mark: int) -> list[float]:
    """The rates z_sub_thr reported after the first `mark` lines of its output."""
    return [r for r in (float(m.group(1)) for m in map(BARE_NUMBER.match, lines[mark:]) if m) if r > 0]


def round_size(size: int, subscribers: int) -> int:
    """The messages of one report of z_sub_thr (its -n): a report every few hundred milliseconds at
    the rates each size reaches, so that a window holds enough of them, and fewer per report when
    one publisher's rate is shared by many subscribers."""
    base = 100_000 if size <= 1024 else 2_000
    return max(200, base // subscribers)


def open_gap(stamps: list[tuple[float, str]]) -> float:
    """The microseconds z_put spent opening its session: from its line before the open to its line
    after it, as the lines arrived."""
    for i, (at, line) in enumerate(stamps):
        if line.strip() == "Opening session...":
            for later, text in stamps[i + 1:]:
                if text.startswith("Putting Data"):
                    return (later - at) * 1e6
            break
    raise Lost("z_put did not print its line before and its line after the open")


def vm_rss_kib(status: str) -> int | None:
    """The resident set of /proc/<pid>/status text, in KiB."""
    m = re.search(r"^VmRSS:\s+(\d+)\s+kB", status, re.M)
    return int(m.group(1)) if m else None


def upstream_release_profile(manifest: str) -> dict[str, str]:
    """The [profile.release] of upstream's root manifest as the CARGO_PROFILE_RELEASE_* environment
    that builds the wz router with the same profile (lto, codegen-units, opt-level, panic, debug)."""
    m = re.search(r"(?ms)^\[profile\.release\]\n(.*?)(?=^\[|\Z)", manifest)
    env: dict[str, str] = {}
    for line in (m.group(1) if m else "").splitlines():
        line = line.split("#", 1)[0].strip()
        if "=" not in line:
            continue
        key, value = (part.strip() for part in line.split("=", 1))
        env["CARGO_PROFILE_RELEASE_" + key.upper().replace("-", "_")] = value.strip('"')
    return env


def router_document(port: int, connect: int | None) -> dict:
    """The configuration both routers start on: a router listening on the loopback, multicast
    scouting off so that no node of another run on the host joins, and the router it dials."""
    doc: dict = {"mode": "router", "listen": {"endpoints": [f"tcp/127.0.0.1:{port}"]},
                 "scouting": {"multicast": {"enabled": False}}}
    if connect is not None:
        doc["connect"] = {"endpoints": [f"tcp/127.0.0.1:{connect}"]}
    return doc


def peer_args(role: str, port: int) -> list[str]:
    return ["-m", "peer", "-l" if role == "listen" else "-e", f"tcp/127.0.0.1:{port}", "--no-multicast-scouting"]


def client_args(port: int) -> list[str]:
    return ["-m", "client", "-e", f"tcp/127.0.0.1:{port}", "--no-multicast-scouting"]


def client_arm(pair: str, arm: str) -> str:
    """The arm of the programs around the router: upstream's in the router pair, the cell's in the
    API pair."""
    return "U" if pair == "router" else arm


def router_arm(pair: str, arm: str) -> str:
    """The arm of the router: the cell's in the router pair, zenohd in the API pair."""
    return arm if pair == "router" else "U"


def free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def resolve_upstream(resolver=None, at_pin=None, version: str | None = None) -> pathlib.Path:
    """The pinned upstream tree, from upstream_root() and no other resolver, at UPSTREAM_VERSION and
    no other version. Refused when there is none."""
    if resolver is None or at_pin is None or version is None:
        import upstream_citation_anchor_gate as anchors
        import upstream_feature_census as ufc

        resolver = resolver or anchors.upstream_root
        at_pin = at_pin or anchors.checkout_at_pin
        version = version or ufc.UPSTREAM_VERSION
    root = resolver()
    if root is None:
        raise Refusal(f"upstream_root() found no checkout of zenoh {version} "
                      f"(scripts/lib/upstream_citation_anchor_gate.py); the matrix compares with that version only")
    if not at_pin(root, version):
        raise Refusal(f"{root} is not a checkout of zenoh {version}")
    return pathlib.Path(root)


def artifact_of(report: str, name: str, kind: str) -> pathlib.Path | None:
    """The executable of the target `name` of the kind `kind` (bin, example) a cargo JSON report names."""
    for line in report.splitlines():
        if not line.startswith("{"):
            continue
        try:
            msg = json.loads(line)
        except ValueError:
            continue
        target = msg.get("target") or {}
        if (msg.get("reason") == "compiler-artifact" and target.get("name") == name
                and kind in target.get("kind", []) and msg.get("executable")):
            return pathlib.Path(msg["executable"])
    return None


# -- the runner -------------------------------------------------------------------------------------

def capture(argv: list[str], log: pathlib.Path, env: dict[str, str] | None = None,
            cwd: pathlib.Path = ROOT) -> str:
    """Run a build step: its standard output is returned and its errors kept in the log. A failure
    refuses the run."""
    full = dict(os.environ)
    full.update(env or {})
    with log.open("w", encoding="utf-8") as err:
        done = subprocess.run(argv, cwd=cwd, env=full, stdout=subprocess.PIPE, stderr=err, text=True, check=False)
    if done.returncode != 0:
        raise Refusal(f"{' '.join(argv)} failed with exit {done.returncode} (see {log})")
    return done.stdout


def build(run: pathlib.Path) -> tuple[dict[str, pathlib.Path], dict]:
    """Both sides of both pairs, built on this host into run/bin: the API arms from upstream's
    examples package generated over the tree upstream_root() resolves, zenohd as Layer Z provisions
    it at UPSTREAM_VERSION (its version asserted from the binary), the wz router with upstream's
    release profile, and the heap shim."""
    import upstream_feature_census as ufc
    import z8_upstream_suite as z8
    from artifact_root import artifact

    version = ufc.UPSTREAM_VERSION
    root = resolve_upstream()
    bins = run / "bin"
    logs = run / "build"
    bins.mkdir(parents=True, exist_ok=True)
    logs.mkdir(parents=True, exist_ok=True)
    capture(["bash", "scripts/provision-kconfiglib.sh"], logs / "kconfiglib.log")
    preset = capture(["python3", "-I", "scripts/lib/wz_config.py", "--original-features", "zenoh"], logs / "preset.log")
    m = re.search(r"--features (\S+)", preset)
    core = m.group(1) if m else ""
    for arm, side in (("stock", "U"), ("wz", "W")):
        pkg = artifact(f"target/ap-matrix/examples-{arm}")
        capture(["python3", "-I", "scripts/lib/z8_upstream_suite.py", "examples", "--arm", arm,
                 "--core-features", core], logs / f"generate-{arm}.log",
                {"Z8_UPSTREAM_SRC": str(root), "Z8_OUT": str(pkg)})
        report = capture(["cargo", "build", "--release", "--target-dir", str(pkg / "target"),
                          *[w for p in PROGRAMS for w in ("--example", p)],
                          "--message-format", "json-render-diagnostics"], logs / f"build-{arm}.log", cwd=pkg)
        for program in PROGRAMS:
            exe = z8.executable_of(report, program)
            if exe is None:
                raise Refusal(f"the {arm} examples built no {program} (see {logs / f'build-{arm}.log'})")
            shutil.copy2(exe, bins / f"{program}_{side}")
    capture(["bash", "scripts/build-zenohd.sh"], logs / "zenohd.log", {"ZENOHD_VERSION": version})
    zenohd = artifact("target/zenohd/zenohd")
    said = capture([str(zenohd), "--version"], logs / "zenohd-version.log").strip()
    if version not in said:
        raise Refusal(f"{zenohd} answers {said!r}, not zenoh {version}: the matrix compares with that version only")
    shutil.copy2(zenohd, bins / "router_U")
    profile = upstream_release_profile((root / "Cargo.toml").read_text(encoding="utf-8"))
    target = artifact("target/ap-matrix/router")
    report = capture(["cargo", "build", "--release", "-p", "wz-ap-demo", "--features", ",".join(ROUTER_FEATURES),
                      "--target-dir", str(target), "--message-format", "json-render-diagnostics"],
                     logs / "build-router.log", profile, cwd=ROOT / "crates")
    exe = artifact_of(report, "wz-ap-demo", "bin")
    if exe is None:
        raise Refusal(f"the wz router built no wz-ap-demo (see {logs / 'build-router.log'})")
    shutil.copy2(exe, bins / "router_W")
    capture(["cc", "-O2", "-shared", "-fPIC", "-o", str(bins / "heap_peak.so"), str(HERE / "heap_peak.c")],
            logs / "heap-shim.log")
    rustc = capture(["rustc", "-V"], logs / "rustc.log", cwd=ROOT / "crates").strip()
    record = {"upstream_version": version, "upstream_root": str(root), "zenohd": said,
              "router_features": list(ROUTER_FEATURES), "router_profile": profile,
              "api_core_features": core, "rustc": rustc}
    return given_bins(bins), record


def given_bins(directory: pathlib.Path) -> dict[str, pathlib.Path]:
    """The programs a run measures, from a directory of an earlier build; refused when one lacks."""
    names = [f"{p}_{a}" for p in PROGRAMS for a in ARMS] + [f"router_{a}" for a in ARMS] + ["heap_peak.so"]
    missing = [n for n in names if not (directory / n).is_file()]
    if missing:
        raise Refusal(f"{directory} lacks {', '.join(missing)}")
    return {n: directory / n for n in names}


@dataclasses.dataclass
class Stream:
    """What one run of upstream's throughput programs read: each subscriber's median rate over the
    window, the CPU seconds the routers and the programs used in it, and the processes."""

    rates: list[float]
    cpu_routers: float
    cpu_clients: float
    window_s: float
    routers: list[Process]
    clients: list[Process]

    @property
    def delivered(self) -> float:
        return sum(self.rates)

    def own(self) -> float:
        return sum(p.own_seconds() for p in self.routers + self.clients)


def heap_peak(proc: Process) -> int:
    """The heap peak the shim wrote for a process (heap_peak.c), in bytes."""
    path = proc.out_path.with_suffix(".heap")
    data = path.read_bytes() if path.exists() else b""
    if len(data) < 16:
        raise Lost(f"{proc.out_path.name} left no heap figures (was the shim preloaded?)")
    return struct.unpack("<qq", data[:16])[0]


class Runner:
    def __init__(self, args: argparse.Namespace, run: pathlib.Path, bins: dict[str, pathlib.Path]):
        self.args = args
        self.bins = bins
        self.logs = run / "logs"
        self.logs.mkdir(parents=True, exist_ok=True)
        self.sizes = run / "sizes"
        self.serial = 0
        self.cpus = sorted(set(cpu_list(args.client_cpus)) | set(cpu_list(args.server_cpus))
                           | set(cpu_list(args.router_cpus)))

    def log(self, label: str) -> pathlib.Path:
        self.serial += 1
        return self.logs / f"{self.serial:05d}.{label}.out"

    def start(self, program: str, arm: str, argv: list[str], cpus: str, label: str, heap: bool = False) -> Process:
        out = self.log(label)
        env = {}
        if heap:
            env = {"LD_PRELOAD": str(self.bins["heap_peak.so"]), "HEAP_PEAK_FILE": str(out.with_suffix(".heap"))}
        return Process([str(self.bins[f"{program}_{arm}"]), *argv], cpus, out, env)

    def router(self, arm: str, port: int, connect: int | None, label: str, cpus: str | None = None,
               heap: bool = False) -> Process:
        doc = self.logs / f"{label}.json5"
        doc.write_text(json.dumps(router_document(port, connect)), encoding="utf-8")
        flag = "-c" if arm == "U" else "--config"
        proc = self.start("router", arm, [flag, str(doc)], cpus or self.args.router_cpus, label, heap)
        deadline = time.monotonic() + ROUTER_WAIT_S
        while True:
            try:
                with socket.create_connection(("127.0.0.1", port), timeout=0.2):
                    return proc
            except OSError:
                pass
            if proc.cpu_seconds() is None or time.monotonic() > deadline:
                proc.stop()
                raise Lost(f"the router of arm {arm} did not listen on {port} ({pm.last_words(proc.text())})")
            time.sleep(0.1)

    def routers(self, pair: str, topo: str, arm: str, label: str, cpus: str | None = None,
                heap: bool = False) -> tuple[list[Process], int, int]:
        """The routers of a topology (none, one, or two linked), and the ports the publishing and the
        subscribing programs dial."""
        if topo == "p2p":
            return [], 0, 0
        first = free_port()
        procs = [self.router(router_arm(pair, arm), first, None, f"{label}.router1", cpus, heap)]
        if topo == "r1":
            return procs, first, first
        try:
            last = free_port()
            procs.append(self.router(router_arm(pair, arm), last, first, f"{label}.router2", cpus, heap))
        except Lost:
            procs[0].stop()
            raise
        time.sleep(LINK_S)
        return procs, first, last

    def stream(self, pair: str, topo: str, arm: str, label: str, size: int, subs: int = 1, pubs: int = 1,
               cpus: str | None = None, heap: str = "") -> Stream:
        """z_sub_thr and z_pub_thr of the cell's arm around its routers: after the warm-up, each
        subscriber's reports over the window, and the CPU of the routers and of the programs."""
        ca = client_arm(pair, arm)
        routers, pub_port, sub_port = self.routers(pair, topo, arm, label, cpus, heap == "router")
        subscribers: list[Process] = []
        publishers: list[Process] = []
        try:
            port = free_port()
            for i in range(subs):
                where = peer_args("listen", port) if topo == "p2p" else client_args(sub_port)
                subscribers.append(self.start("z_sub_thr", ca, ["-s", "1000000", "-n", str(round_size(size, subs)),
                                                                *where], self.args.server_cpus, f"{label}.sub{i}",
                                              heap == "clients"))
            time.sleep(SETTLE_S)
            for i in range(pubs):
                where = peer_args("connect", port) if topo == "p2p" else client_args(pub_port)
                publishers.append(self.start("z_pub_thr", ca, [str(size), *where], self.args.client_cpus,
                                             f"{label}.pub{i}", heap == "clients"))
            time.sleep(self.args.warmup_s)
            marks = [len(p.text().splitlines()) for p in subscribers]
            cpu0 = [p.cpu_seconds() for p in routers + subscribers + publishers]
            t0 = time.monotonic()
            time.sleep(self.args.window_s)
            cpu1 = [p.cpu_seconds() for p in routers + subscribers + publishers]
            window = time.monotonic() - t0
            texts = [p.text().splitlines() for p in subscribers]
        finally:
            for p in publishers + subscribers + routers[::-1]:
                p.stop()
        if None in cpu0 or None in cpu1:
            raise Lost("a program of the stream ended inside the window")
        rates = []
        for i, (lines, mark) in enumerate(zip(texts, marks)):
            reports = window_rates(lines, mark)
            if len(reports) < MIN_REPORTS:
                raise Lost(f"subscriber {i} reported {len(reports)} rates in the window, fewer than {MIN_REPORTS}")
            rates.append(statistics.median(reports))
        used = [b - a for a, b in zip(cpu0, cpu1)]
        return Stream(rates, sum(used[:len(routers)]), sum(used[len(routers):]), window, routers,
                      subscribers + publishers)

    def pingpong(self, pair: str, topo: str, arm: str, label: str, size: int) -> tuple[list[float], list[Process]]:
        """z_pong and z_ping of the cell's arm around its routers: the round trips z_ping printed."""
        ca = client_arm(pair, arm)
        routers, ping_port, pong_port = self.routers(pair, topo, arm, label)
        pong = ping = None
        done = False
        try:
            port = free_port()
            where = peer_args("listen", port) if topo == "p2p" else client_args(pong_port)
            pong = self.start("z_pong", ca, where, self.args.server_cpus, f"{label}.pong")
            time.sleep(SETTLE_S)
            where = peer_args("connect", port) if topo == "p2p" else client_args(ping_port)
            ping = self.start("z_ping", ca, [str(size), "-n", str(self.args.pings), "-w", f"{self.args.warmup_s:g}",
                                             *where], self.args.client_cpus, f"{label}.ping")
            done = ping.reap(self.args.warmup_s + PING_BOUND_S)
        finally:
            for p in [ping, pong, *routers[::-1]]:
                if p is not None:
                    p.stop()
        if not done:
            raise Lost("z_ping did not finish in time")
        rtts = [float(m.group(1)) for m in map(RTT_TAGGED.search, ping.text().splitlines()) if m]
        if len(rtts) != self.args.pings:
            raise Lost(f"z_ping printed {len(rtts)} round trips of {self.args.pings}")
        return rtts, [ping, pong, *routers]

    def one_open(self, arm: str, where: list[str], label: str) -> tuple[float, float]:
        """One z_put of the arm: the microseconds of its open, and the CPU seconds it used."""
        argv = ["taskset", "-c", self.args.client_cpus, str(self.bins[f"z_put_{arm}"]), *where]
        proc = subprocess.Popen(argv, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        stamps: list[tuple[float, str]] = []

        def read() -> None:
            for raw in proc.stdout:
                stamps.append((time.monotonic(), raw.decode("utf-8", errors="replace").rstrip("\n")))

        reader = threading.Thread(target=read, daemon=True)
        reader.start()
        deadline = time.monotonic() + OPEN_BOUND_S
        rusage = None
        while rusage is None:
            pid, status, usage = os.wait4(proc.pid, os.WNOHANG)
            if pid == proc.pid:
                rusage = usage
                proc.returncode = os.waitstatus_to_exitcode(status)
            elif time.monotonic() > deadline:
                proc.kill()
                _, status, _ = os.wait4(proc.pid, 0)
                proc.returncode = os.waitstatus_to_exitcode(status)
                reader.join(5)
                proc.stdout.close()
                raise Lost("z_put did not end in time")
            else:
                time.sleep(0.01)
        reader.join(5)
        proc.stdout.close()
        self.log(label).write_text("".join(f"{at:.6f} {line}\n" for at, line in stamps), encoding="utf-8")
        if proc.returncode != 0:
            raise Lost(f"z_put exited {proc.returncode}")
        return open_gap(stamps), rusage.ru_utime + rusage.ru_stime

    def opens(self, topo: str, arm: str, label: str) -> tuple[list[float], float]:
        """OPEN_SAMPLES opens of z_put of the arm, to a peer z_sub of the same arm or to zenohd."""
        routers, port, _ = self.routers("api", topo, arm, label)
        standing = list(routers)
        samples: list[float] = []
        own = 0.0
        try:
            if topo == "p2p":
                port = free_port()
                standing.append(self.start("z_sub", arm, peer_args("listen", port), self.args.server_cpus,
                                           f"{label}.sub"))
                time.sleep(SETTLE_S)
            where = peer_args("connect", port) if topo == "p2p" else client_args(port)
            for i in range(OPEN_SAMPLES):
                gap, cpu = self.one_open(arm, where, f"{label}.put{i}")
                samples.append(gap)
                own += cpu
        finally:
            for p in standing[::-1]:
                p.stop()
        return samples, own + sum(p.own_seconds() for p in standing)

    def timed(self, body) -> dict[str, float]:
        """The figures of body() from a run in which the pinned CPUs were used by nothing else
        (nodrop.py's rule), up to MAX_RUNS runs; a program's own failure is lost at once."""
        reasons = []
        for _ in range(MAX_RUNS):
            busy0, wall0 = busy_seconds(self.cpus), time.monotonic()
            figures, own = body()
            wall = time.monotonic() - wall0
            foreign = max(0.0, busy_seconds(self.cpus) - busy0 - own) / (wall * len(self.cpus))
            if foreign <= FOREIGN_LIMIT:
                return figures
            reasons.append(f"the pinned CPUs were {foreign * 100:.0f}% used by something else")
            time.sleep(5)
        raise pm.Disturbed("no valid run in " + str(MAX_RUNS) + ": " + "; ".join(reasons))

    def stream_figures(self, pair: str, s: Stream) -> dict[str, float]:
        """The throughput figures of a stream: the routers' CPU and resident set in the router pair,
        the programs' in the API pair."""
        cpu, procs = (s.cpu_routers, s.routers) if pair == "router" else (s.cpu_clients, s.clients)
        return {"msgs_per_s": s.delivered, "cpu_ns_per_msg": cpu / s.window_s / s.delivered * 1e9,
                "rss_kib": sum(p.rss_kib() for p in procs)}

    def measure(self, cell: str, arm: str, rep: int) -> dict[str, float]:
        """One repetition of one cell on one arm."""
        pair, workload, topo, param = cell.split("/")
        value = int(param)
        label = f"{cell.replace('/', '_')}.{arm}.r{rep}"
        if workload in ("thr", "fanout"):
            size, subs = (8, value) if workload == "fanout" else (value, 1)

            def body():
                s = self.stream(pair, topo, arm, label, size, subs=subs)
                return self.stream_figures(pair, s), s.own()
            return self.timed(body)
        if workload == "lat":
            def body():
                rtts, procs = self.pingpong(pair, topo, arm, label, value)
                return ({"rtt_p50_us": percentile(rtts, 0.50), "rtt_p99_us": percentile(rtts, 0.99)},
                        sum(p.own_seconds() for p in procs))
            return self.timed(body)
        if workload == "multihop":
            def body():
                s = self.stream(pair, topo, arm, f"{label}.thr", value)
                rtts, procs = self.pingpong(pair, topo, arm, f"{label}.lat", value)
                return ({"msgs_per_s": s.delivered, "rtt_p50_us": percentile(rtts, 0.50),
                         "rtt_p99_us": percentile(rtts, 0.99)}, s.own() + sum(p.own_seconds() for p in procs))
            return self.timed(body)
        if workload == "scaling":
            side = cpu_list(self.args.router_cpus)
            if len(side) < value:
                raise Skipped(f"the router side has {len(side)} CPU(s) and the cell asks {value}")
            cpus = ",".join(map(str, side[:value]))

            def body():
                s = self.stream(pair, topo, arm, label, 8, subs=value, pubs=value, cpus=cpus)
                return {"msgs_per_s": s.delivered}, s.own()
            return self.timed(body)
        if workload == "open":
            def body():
                samples, own = self.opens(topo, arm, label)
                return {"open_us": statistics.median(samples)}, own
            return self.timed(body)
        if workload == "idle":
            return self.idle(pair, arm, label)
        if workload == "heap":
            s = self.stream(pair, topo, arm, label, value, heap="router" if pair == "router" else "clients")
            held = s.routers if pair == "router" else s.clients
            return {"heap_peak_kib": sum(heap_peak(p) for p in held) / 1024}
        raise Lost(f"no harness measures {cell}")

    def idle(self, pair: str, arm: str, label: str) -> dict[str, float]:
        if pair == "router":
            proc = self.router(arm, free_port(), None, label)
        else:
            proc = self.start("z_sub", arm, peer_args("listen", free_port()), self.args.server_cpus, label)
        try:
            time.sleep(IDLE_S)
            try:
                rss = vm_rss_kib(pathlib.Path(f"/proc/{proc.pid}/status").read_text(encoding="ascii", errors="replace"))
            except OSError:
                rss = None
        finally:
            proc.stop()
        if rss is None:
            raise Lost(f"the program ended before its idle resident set was read ({pm.last_words(proc.text())})")
        return {"rss_kib": rss}

    def size(self, cell: str) -> dict[str, int]:
        """The stripped bytes of each arm's file: the router, or the smallest client program."""
        program = "router" if cell.startswith("router/") else "z_put"
        self.sizes.mkdir(parents=True, exist_ok=True)
        out = {}
        for arm in ARMS:
            stripped = self.sizes / f"{program}_{arm}.stripped"
            subprocess.run(["strip", "--strip-unneeded", "-o", str(stripped), str(self.bins[f"{program}_{arm}"])],
                           check=True)
            out[arm] = stripped.stat().st_size
        return out


def measure_all(runner: Runner, cells: list[str], reps: int, sink) -> list[dict]:
    """Every repetition of every cell on both arms, the order of the arms alternating by repetition,
    and one more pass over the repetitions the host disturbed in all their runs."""
    records = []
    for rep in range(1, reps + 1):
        order = ("U", "W") if rep % 2 else ("W", "U")
        for cell in cells:
            for arm in order:
                records.append(measure_one(runner, cell, arm, rep, sink))
    for i, record in enumerate(list(records)):
        if record["status"] == "lost" and record.get("disturbed"):
            again = measure_one(runner, record["cell"], record["arm"], record["rep"], sink)
            again["second_pass"] = True
            records[i] = again
    return records


def measure_one(runner: Runner, cell: str, arm: str, rep: int, sink) -> dict:
    record: dict = {"cell": cell, "arm": arm, "rep": rep}
    try:
        record.update(status="measured", figures=runner.measure(cell, arm, rep))
    except Skipped as why:
        record.update(status="skipped", why=str(why))
    except pm.Disturbed as why:
        record.update(status="lost", disturbed=True, why=str(why))
    except Lost as why:
        record.update(status="lost", why=str(why))
    sink(record)
    return record


def host_record(args: argparse.Namespace) -> dict:
    def first(argv: list[str]) -> str:
        try:
            return subprocess.run(argv, capture_output=True, text=True, check=False).stdout.strip().splitlines()[0]
        except (OSError, IndexError):
            return "unknown"

    cpu = "unknown"
    try:
        found = re.search(r"^model name\s*:\s*(.*)$", pathlib.Path("/proc/cpuinfo").read_text(), re.M)
        cpu = found.group(1) if found else cpu
    except OSError:
        pass
    return {"date": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), "host": socket.gethostname(),
            "kernel": os.uname().release, "cpu": cpu, "threads": os.cpu_count(),
            "tree": first(["git", "-C", str(ROOT), "rev-parse", "HEAD"]),
            "client_cpus": args.client_cpus, "server_cpus": args.server_cpus, "router_cpus": args.router_cpus,
            "reps": args.reps, "warmup_s": args.warmup_s, "window_s": args.window_s, "pings": args.pings}


def cmd_run(args: argparse.Namespace) -> int:
    try:
        cells = select(args.cells)
    except ValueError as why:
        print(f"ap-matrix: {why}", file=sys.stderr)
        return 64
    if args.reps < pm.MIN_REPS:
        print(f"ap-matrix: --reps {args.reps} gives no interval; D10 reads {pm.MIN_REPS} at the least",
              file=sys.stderr)
        return 64
    run = pathlib.Path(args.run)
    if run.exists() and any(run.iterdir()):
        print(f"ap-matrix: {run} is not empty; a run writes a directory of its own", file=sys.stderr)
        return 2
    run.mkdir(parents=True, exist_ok=True)
    doc = reading_document([], record=host_record(args))
    for cell in cells:
        why = no_harness(cell)
        if why:
            doc["not_measured"][cell] = why
    if any(kind_of(c) == STATIC and not no_harness(c) for c in cells):
        try:
            figures = completeness_figures()
        except Fatal as why:
            print(f"ap-matrix: NOT-MEASURED, a completeness figure cannot be read: {why}", flush=True)
            return 2
        for cell in cells:
            if cell in figures:
                doc["completeness"][cell] = {"shortfall": figures[cell][0], "said": figures[cell][1]}
    measured = [c for c in cells if kind_of(c) != STATIC and not no_harness(c)]
    if measured:
        try:
            if args.bin_dir:
                bins = given_bins(pathlib.Path(args.bin_dir))
                doc["record"]["programs"] = f"given ({args.bin_dir})"
            else:
                bins, built = build(run)
                doc["record"].update(built)
        except Refusal as why:
            print(f"ap-matrix: NOT-MEASURED, {why}", flush=True)
            return 2
        runner = Runner(args, run, bins)
        for cell in measured:
            if kind_of(cell) == SINGLE:
                doc["sizes"][cell] = runner.size(cell)
                print(f"  ap-matrix {cell}: {doc['sizes'][cell]}", flush=True)
        with (run / "cells.jsonl").open("a", encoding="utf-8") as sink:
            def keep(record: dict) -> None:
                sink.write(json.dumps(record, sort_keys=True) + "\n")
                sink.flush()
                said = record.get("figures") or record.get("why", "")
                print(f"  ap-matrix {record['cell']} {record['arm']} r{record['rep']}: {record['status']} {said}",
                      flush=True)

            doc["cells"] = measure_all(runner, [c for c in measured if kind_of(c) != SINGLE], args.reps, keep)
    reading = run / "reading.json"
    reading.write_text(json.dumps(doc, indent=1, sort_keys=True) + "\n", encoding="utf-8")
    print(f"ap-matrix: the reading is {reading}", flush=True)
    return cmd_gate(reading, pathlib.Path(args.table))


def cmd_cells(spec: str) -> int:
    try:
        cells = select(spec)
    except ValueError as why:
        print(f"ap-matrix: {why}", file=sys.stderr)
        return 64
    for cell in cells:
        why = no_harness(cell)
        print(f"{cell}  {kind_of(cell)}  {','.join(metrics_of(cell))}" + (f"  no harness: {why}" if why else ""))
    return 0



# -- the selftest -----------------------------------------------------------------------------------

def cmd_selftest() -> int:
    ok = 0
    bad = 0

    def expect(name: str, cond: bool) -> None:
        nonlocal ok, bad
        if cond:
            ok += 1
        else:
            bad += 1
            print(f"  ap-matrix selftest FAIL: {name}", file=sys.stderr)

    def raises(kind, call) -> bool:
        try:
            call()
        except kind:
            return True
        return False

    # The matrix.
    rows_all = population()
    cells = [cell for cell, _ in matrix()]
    expect("every row of the matrix is one key", len(rows_all) == len(set(rows_all)))
    expect("every key is <pair>/<workload>/<topology>/<parameter>/<figure> of a known pair and figure",
           all(entry_error(k, {"held": None, "debt": DEBT_PLACEHOLDER}) is None for k in rows_all))
    expect("every workload has a kind", all(workload_of(c) in WORKLOAD_KIND for c in cells))
    expect("every figure of METRICS is held by some row",
           {k.rsplit("/", 1)[1] for k in rows_all} == set(METRICS))
    expect("every pattern of NO_HARNESS names a cell",
           all(any(fnmatch.fnmatchcase(c, p) for c in cells) for p, _ in NO_HARNESS))
    expect("the runner measures exactly the workloads that have a harness",
           {workload_of(c) for c in cells if not no_harness(c) and kind_of(c) not in (STATIC, SINGLE)}
           == {"thr", "fanout", "lat", "multihop", "scaling", "open", "idle", "heap"})
    expect("both pairs carry throughput, latency, fan-out, memory and size cells",
           all(any(c.startswith(f"{pair}/{w}/") for c in cells) for pair in PAIRS
               for w in ("thr", "lat", "fanout", "idle", "heap", "size", "complete")))
    expect("a selector picks its cells in the matrix's order, and all picks every cell",
           select("router/thr/*") == ["router/thr/r1/8", "router/thr/r1/1024", "router/thr/r1/65536"]
           and select("all") == cells and select("api/open/*,api/open/p2p/0") == ["api/open/p2p/0", "api/open/r1/0"])
    expect("a selector that names no cell is refused", raises(ValueError, lambda: select("router/nothing/*")))

    # The table.
    blank = {key: {"held": None, "debt": DEBT_PLACEHOLDER} for key in rows_all}
    doc = {"about": "x", "schema": TABLE_SCHEMA, "tolerance": 0.05, "rows": blank}
    parsed, tolerance = parse_table(table_text(doc))
    expect("a table of null rows under the placeholder reads back as it was written",
           parsed == blank and tolerance == 0.05)
    thr = "api/thr/p2p/8/msgs_per_s"
    short_key = "api/complete/z8-tests/0/shortfall"
    expect("a row without its debt is refused", entry_error(thr, {"held": None}) is not None)
    expect("a row that is not locked and names no debt is refused",
           entry_error(thr, {"held": {"ratio_at_most": 1.2}, "debt": None}) is not None)
    expect("a locked row under the placeholder is refused",
           entry_error(thr, {"held": {"locked": True}, "debt": DEBT_PLACEHOLDER}) is not None)
    expect("a locked row with no debt, and a ratchet under a registered debt, are rows",
           entry_error(thr, {"held": {"locked": True}, "debt": None}) is None
           and entry_error(thr, {"held": {"ratio_at_most": 1.2}, "debt": "debt-ap-x"}) is None)
    expect("a completeness row holds no ratio, and a shortfall of 0 is a lock",
           entry_error(short_key, {"held": {"ratio_at_most": 1.2}, "debt": "debt-x"}) is not None
           and entry_error(short_key, {"held": {"shortfall_at_most": 0}, "debt": "debt-x"}) is not None
           and entry_error(short_key, {"held": {"shortfall_at_most": 3}, "debt": "debt-x"}) is None)
    expect("a performance row holds no shortfall",
           entry_error(thr, {"held": {"shortfall_at_most": 3}, "debt": "debt-x"}) is not None)
    expect("a key of an unknown figure or pair is refused",
           entry_error("api/thr/p2p/8/speed", {"held": None, "debt": DEBT_PLACEHOLDER}) is not None
           and entry_error("pico/thr/p2p/8/msgs_per_s", {"held": None, "debt": DEBT_PLACEHOLDER}) is not None)
    head = '{"schema": "' + TABLE_SCHEMA + '", "tolerance": 0.05, "rows": '
    expect("a key written twice is refused",
           raises(pm.Refused, lambda: parse_table(head + '{"' + thr + '": {"held": null, "debt": "debt-TBD"}, "'
                                                 + thr + '": {"held": null, "debt": "debt-TBD"}}}')))
    expect("a table of another schema or a tolerance of 1 is refused",
           raises(pm.Refused, lambda: parse_table('{"schema": "x", "tolerance": 0.05, "rows": {}}'))
           and raises(pm.Refused, lambda: parse_table(
               '{"schema": "' + TABLE_SCHEMA + '", "tolerance": 1, "rows": {}}')))

    # The readings.
    def cells_of(cell: str, w: list[dict], u: list[dict]) -> list[dict]:
        out = [{"cell": cell, "arm": "W", "rep": i + 1, "status": "measured", "figures": f} for i, f in enumerate(w)]
        return out + [{"cell": cell, "arm": "U", "rep": i + 1, "status": "measured", "figures": f}
                      for i, f in enumerate(u)]

    rate = "api/thr/p2p/8"
    lat = "api/lat/p2p/8"
    fast = cells_of(rate, [{"msgs_per_s": v, "cpu_ns_per_msg": 50, "rss_kib": 900} for v in (200, 210, 205)],
                    [{"msgs_per_s": v, "cpu_ns_per_msg": 100, "rss_kib": 1000} for v in (100, 105, 102)])
    found = readings(fast)
    expect("wz faster on a rate is a WIN at a cost ratio below 1",
           found[f"{rate}/msgs_per_s"].verdict == "WIN" and found[f"{rate}/msgs_per_s"].point < 1)
    expect("wz cheaper on a figure better lower is a WIN",
           found[f"{rate}/cpu_ns_per_msg"].verdict == "WIN" and found[f"{rate}/rss_kib"].verdict == "WIN")
    slow = readings(cells_of(lat, [{"rtt_p50_us": v, "rtt_p99_us": v} for v in (20, 21, 22)],
                             [{"rtt_p50_us": v, "rtt_p99_us": v} for v in (10, 11, 12)]))
    expect("wz slower on a figure better lower is a LOSS", slow[f"{lat}/rtt_p50_us"].verdict == "LOSS")
    tie_cells = cells_of(lat, [{"rtt_p50_us": v, "rtt_p99_us": v} for v in (10, 12, 14)],
                         [{"rtt_p50_us": v, "rtt_p99_us": v} for v in (9, 11, 13)])
    tie = readings(tie_cells)
    expect("intervals that straddle 1 are a TIE", tie[f"{lat}/rtt_p50_us"].verdict == "TIE")
    lost = fast + [{"cell": rate, "arm": "W", "rep": 4, "status": "lost", "why": "z_sub_thr reported nothing"}]
    expect("a repetition wz lost on its own fails its rows", readings(lost)[f"{rate}/msgs_per_s"].state == "wz-lost")
    disturbed = fast + [{"cell": rate, "arm": "W", "rep": 4, "status": "lost", "disturbed": True, "why": "busy"}]
    expect("a repetition the host disturbed is no repetition",
           readings(disturbed)[f"{rate}/msgs_per_s"].verdict == "WIN")
    gone = [c for c in fast if c["arm"] == "W"] + [{"cell": rate, "arm": "U", "rep": 1, "status": "lost", "why": "x"}]
    expect("a reference that lost every repetition leaves the row without a ratio",
           readings(gone)[f"{rate}/msgs_per_s"].state == "reference-lost")
    expect("two repetitions give no interval", readings(fast[1:3] + fast[4:6])[f"{rate}/msgs_per_s"].state == "too-few")
    skipped = [{"cell": "router/scaling/r1/8", "arm": a, "rep": 1, "status": "skipped", "why": "4 CPUs"} for a in ARMS]
    expect("a cell the host could not run is measured by neither arm",
           readings(skipped)["router/scaling/r1/8/msgs_per_s"].state == "too-few")
    sizes = size_readings({"router/size/bin/0": {"W": 900, "U": 1000}, "api/size/bin/0": {"W": 1000, "U": 1000}})
    expect("a size is exact: smaller is a WIN, the same a TIE",
           sizes["router/size/bin/0/stripped_bytes"].verdict == "WIN"
           and sizes["api/size/bin/0/stripped_bytes"].verdict == "TIE")

    # The gate.
    def judged_of(cells_read: list[dict], rows: dict, sizes_read: dict | None = None,
                  complete: dict | None = None) -> dict[str, pm.Judged]:
        reading = check_reading(reading_document(cells_read, sizes_read, complete), "the selftest's reading")
        return {j.key: j for j in grade(reading, rows, 0.05)}

    j = judged_of(fast, blank)
    expect("a null row the run measured fails and prints its lock",
           j[f"{rate}/msgs_per_s"].outcome == "FAIL" and j[f"{rate}/msgs_per_s"].edit == {"locked": True})
    expect("a row the run did not measure is NOT-MEASURED", j[f"{lat}/rtt_p50_us"].outcome == "NOT-MEASURED")
    expect("a row with no harness is NOT-MEASURED and says so, never a pass",
           j["router/flows/r1/1000/msgs_per_s"].outcome == "NOT-MEASURED"
           and j["router/flows/r1/1000/msgs_per_s"].sentence.startswith("no harness")
           and j["router/complete/plugin-rest/0/shortfall"].outcome == "NOT-MEASURED")
    locked = dict(blank, **{f"{rate}/{m}": {"held": {"locked": True}, "debt": None} for m in THR})
    expect("a locked row that reads a WIN passes",
           all(judged_of(fast, locked)[f"{rate}/{m}"].outcome == "PASS" for m in THR))
    expect("a locked row that reads a TIE fails",
           judged_of(tie_cells, dict(blank, **{f"{lat}/rtt_p50_us": {"held": {"locked": True}, "debt": None}}))
           [f"{lat}/rtt_p50_us"].outcome == "FAIL")
    over = cells_of(lat, [{"rtt_p50_us": 110, "rtt_p99_us": 110}] * 3, [{"rtt_p50_us": 100, "rtt_p99_us": 100}] * 3)

    def ratchet(at_most: float, debt: str) -> pm.Judged:
        rows = dict(blank, **{f"{lat}/rtt_p50_us": {"held": {"ratio_at_most": at_most}, "debt": debt}})
        return judged_of(over, rows)[f"{lat}/rtt_p50_us"]

    expect("a reading under its ratchet passes and prints the tighter row",
           ratchet(1.2, "debt-ap-x").outcome == "PASS" and ratchet(1.2, "debt-ap-x").edit == {"ratio_at_most": 1.1})
    expect("a reading within its ratchet passes and writes nothing",
           ratchet(1.1, "debt-ap-x").outcome == "PASS" and ratchet(1.1, "debt-ap-x").edit is None)
    expect("a reading over its ratchet by more than the tolerance fails", ratchet(1.0, "debt-ap-x").outcome == "FAIL")
    expect("a filled row that names no registered debt fails", ratchet(1.2, DEBT_PLACEHOLDER).outcome == "FAIL")
    won = dict(blank, **{f"{rate}/msgs_per_s": {"held": {"ratio_at_most": 1.3}, "debt": DEBT_PLACEHOLDER}})
    expect("a ratchet that reads a WIN passes and prints its lock, with or without its debt",
           judged_of(fast, won)[f"{rate}/msgs_per_s"].outcome == "PASS"
           and judged_of(fast, won)[f"{rate}/msgs_per_s"].edit == {"locked": True})
    stray = {k: v for k, v in blank.items() if k != f"{rate}/rss_kib"}
    expect("a row the run has and the table lacks fails", judged_of(fast, stray)[f"{rate}/rss_kib"].outcome == "FAIL")
    def won_by_wz(cell: str) -> list[dict]:
        wz = [{m: 1.0 for m in metrics_of(cell)}] * 3
        up = [{m: 2.0 if METRICS[m][0] == "lower" else 0.5 for m in metrics_of(cell)}] * 3
        return cells_of(cell, wz, up)

    every = []
    for cell in cells:
        if kind_of(cell) in (TIMED, FUNCTIONAL) and not no_harness(cell):
            every += won_by_wz(cell)
    all_locked = {key: {"held": {"locked": True}, "debt": None} for key in rows_all}
    full = list(judged_of(every, all_locked, {c: {"W": 1, "U": 2} for c in cells if kind_of(c) == SINGLE},
                          {c: {"shortfall": 0, "said": "met"} for c in cells
                           if kind_of(c) == STATIC and not no_harness(c)}).values())
    expect("a run that wins every measured cell is still NOT-MEASURED while a cell has no harness",
           pm.outcome_of(full) == "NOT-MEASURED" and not any(j.outcome == "FAIL" for j in full)
           and pm.exit_status([pm.outcome_of(full)]) == 3)

    # The completeness rows.
    def complete(value: int, held: object) -> pm.Judged:
        return judge_complete({cell_of(short_key): (value, "said")}, {short_key: held})[0]

    expect("a null completeness row fails and prints its row",
           complete(0, None).outcome == "FAIL" and complete(0, None).edit == {"locked": True}
           and complete(3, None).edit == {"shortfall_at_most": 3})
    expect("a locked completeness row passes at 0 and fails above it",
           complete(0, {"locked": True}).outcome == "PASS" and complete(1, {"locked": True}).outcome == "FAIL")
    expect("a completeness ratchet only moves down, and locks at 0",
           complete(6, {"shortfall_at_most": 5}).outcome == "FAIL"
           and complete(3, {"shortfall_at_most": 5}).edit == {"shortfall_at_most": 3}
           and complete(0, {"shortfall_at_most": 5}).edit == {"locked": True}
           and complete(5, {"shortfall_at_most": 5}).edit is None
           and complete(5, {"shortfall_at_most": 5}).outcome == "PASS")
    tests_tsv = ("# a comment\na\tpass\t3\tyes\tall pass\nb\tempty\t0\tno\tignored upstream\n"
                 "c\tfail\t2\tyes\tone test waits\nd\tunmeasured\t0\tno\tnot measured yet\n")
    examples_tsv = ("pubsub\tsub:stand=z_sub -l {ep} ; put:run:5=z_put -e {ep}\tsub >=1 Received\tsame\tyes\t"
                    "shown\nquery\tq:stand=z_queryable -l {ep} ; g:run:5=z_get -e {ep}\tg >=1 Received\t"
                    "differs\tno\tdiffers\n")
    figures = completeness_figures(tests_tsv, examples_tsv, ["a/b", "c"])
    expect("the shortfall of upstream's tests counts every file that neither passes nor is empty upstream",
           figures["api/complete/z8-tests/0"][0] == 2)
    expect("the shortfall of upstream's examples counts every scenario that is not the same",
           figures["api/complete/z8-examples/0"][0] == 1)
    expect("a figure says how many rows have each status",
           "(1 differs, 1 same)" in figures["api/complete/z8-examples/0"][1]
           and "(1 empty, 1 fail, 1 pass, 1 unmeasured)" in figures["api/complete/z8-tests/0"][1])
    expect("the shortfall of zenohd's configuration is the keys the reader does not honour",
           figures["router/complete/config-keys/0"][0] == 2)
    expect("every completeness cell has a reader or a reason it has none",
           all(c in figures or no_harness(c) for c in cells if kind_of(c) == STATIC))
    expect("a table of the API-compatibility program with no row is refused",
           raises(Fatal, lambda: completeness_figures("# nothing\n", examples_tsv, [])))

    # The edits.
    edits = fill_edits([pm.Judged(thr, "PASS", "", {"locked": True}),
                        pm.Judged(f"{lat}/rtt_p50_us", "PASS", "", {"ratio_at_most": 1.1}),
                        pm.Judged("api/thr/p2p/9/msgs_per_s", "FAIL", "", {"locked": True})],
                       dict(blank, **{f"{lat}/rtt_p50_us": {"held": {"ratio_at_most": 1.2}, "debt": "debt-ap-x"}}))
    expect("a lock drops the placeholder, a ratchet keeps its debt, and no row outside the matrix is written",
           edits == {thr: {"held": {"locked": True}, "debt": None},
                     f"{lat}/rtt_p50_us": {"held": {"ratio_at_most": 1.1}, "debt": "debt-ap-x"}})

    # The readers of the runner.
    expect("a percentile is the nearest rank",
           percentile(list(range(1, 101)), 0.5) == 50 and percentile(list(range(1, 101)), 0.99) == 99
           and percentile([7.0], 0.99) == 7.0)
    sub_lines = ["Press CTRL-C to quit...", "100.5 msg/s", "200 msg/s", "Received 5 messages over 1.00s: 5msg/s"]
    expect("the window's rates are the reports after the mark, and a closing line is no report",
           window_rates(sub_lines, 1) == [100.5, 200.0] and window_rates(sub_lines, 2) == [200.0])
    expect("a report holds fewer messages when many subscribers share a publisher",
           round_size(8, 1) == 100_000 and round_size(65536, 1) == 2_000 and round_size(8, 128) == 781
           and round_size(65536, 128) == 200)
    expect("an open is timed from the line before it to the line after it",
           abs(open_gap([(1.0, "Opening session..."), (1.0025, "Putting Data ('a': 'b')...")]) - 2500) < 1e-3)
    expect("a z_put that did not say both lines is lost",
           raises(Lost, lambda: open_gap([(1.0, "Opening session...")])))
    expect("the idle resident set is read from the status file",
           vm_rss_kib("Name:\tz_sub\nVmRSS:\t   1234 kB\n") == 1234 and vm_rss_kib("Name:\tz\n") is None)
    manifest = ('[workspace]\nmembers = []\n\n[profile.release]\ncodegen-units = 1\n'
                'debug = false     # a comment\nlto = "fat"\nopt-level = 3\npanic = "abort"\n\n'
                '[profile.dev]\ndebug = true\n')
    expect("upstream's release profile becomes the environment of the router's build",
           upstream_release_profile(manifest) == {
               "CARGO_PROFILE_RELEASE_CODEGEN_UNITS": "1", "CARGO_PROFILE_RELEASE_DEBUG": "false",
               "CARGO_PROFILE_RELEASE_LTO": "fat", "CARGO_PROFILE_RELEASE_OPT_LEVEL": "3",
               "CARGO_PROFILE_RELEASE_PANIC": "abort"})
    expect("both routers start on one document: a router on the loopback, multicast scouting off",
           router_document(7447, None) == {"mode": "router", "listen": {"endpoints": ["tcp/127.0.0.1:7447"]},
                                            "scouting": {"multicast": {"enabled": False}}}
           and router_document(7448, 7447)["connect"] == {"endpoints": ["tcp/127.0.0.1:7447"]})
    expect("the router pair runs upstream's programs around each router, the API pair zenohd under each arm",
           client_arm("router", "W") == "U" and router_arm("router", "W") == "W"
           and client_arm("api", "W") == "W" and router_arm("api", "W") == "U")
    expect("peers listen and dial, clients dial the router, none scouts",
           peer_args("listen", 1) == ["-m", "peer", "-l", "tcp/127.0.0.1:1", "--no-multicast-scouting"]
           and client_args(2) == ["-m", "client", "-e", "tcp/127.0.0.1:2", "--no-multicast-scouting"])
    expect("no upstream tree, or one of another version, is refused",
           raises(Refusal, lambda: resolve_upstream(lambda: None, lambda r, v: True, "9.9.9"))
           and raises(Refusal, lambda: resolve_upstream(lambda: "/u", lambda r, v: False, "9.9.9"))
           and resolve_upstream(lambda: "/u", lambda r, v: v == "9.9.9", "9.9.9") == pathlib.Path("/u"))
    built = json.dumps({"reason": "compiler-artifact", "target": {"name": "wz-ap-demo", "kind": ["bin"]},
                        "executable": "/t/release/wz-ap-demo"})
    expect("the router's file is read from cargo's report",
           artifact_of(f"Compiling\n{built}\n", "wz-ap-demo", "bin") == pathlib.Path("/t/release/wz-ap-demo")
           and artifact_of(built, "wz-ap-demo", "example") is None)
    other = dict(reading_document([]), schema="x")
    expect("a reading of another schema is refused", raises(pm.Refused, lambda: check_reading(other, "r")))
    expect("a reading whose cells are not a list of records is refused",
           raises(pm.Refused, lambda: check_reading(reading_document({rate: fast}), "r"))
           and raises(pm.Refused, lambda: check_reading(reading_document([{"cell": rate, "arm": "W"}]), "r")))
    expect("the reading the runner starts from is one the gate reads",
           check_reading(reading_document([], record={"host": "h"}), "r")["cells"] == [])
    print(f"  ap-matrix selftest: {ok}/{ok + bad} arm(s) pass")
    return 0 if bad == 0 else 1


def main(argv: list[str]) -> int:
    if argv[1:] == ["--selftest"]:
        return cmd_selftest()
    if len(argv) in (2, 3) and argv[1] == "--check-table":
        return check_table(pathlib.Path(argv[2]) if len(argv) == 3 else TABLE)
    if len(argv) >= 2 and argv[1] in ("--gate", "--fill"):
        parser = argparse.ArgumentParser(prog=f"ap_matrix.py {argv[1]}")
        parser.add_argument("reading")
        parser.add_argument("--table", default=str(TABLE))
        if argv[1] == "--fill":
            parser.add_argument("--write", action="store_true")
            args = parser.parse_args(argv[2:])
            return cmd_fill(pathlib.Path(args.reading), pathlib.Path(args.table), args.write)
        args = parser.parse_args(argv[2:])
        return cmd_gate(pathlib.Path(args.reading), pathlib.Path(args.table))
    if len(argv) in (2, 3) and argv[1] == "cells":
        return cmd_cells(argv[2] if len(argv) == 3 else "all")
    if len(argv) < 2 or argv[1] != "run":
        print(__doc__, file=sys.stderr)
        return 64
    parser = argparse.ArgumentParser(prog="ap_matrix.py run")
    parser.add_argument("--cells", required=True)
    parser.add_argument("--run", required=True)
    parser.add_argument("--reps", type=int, default=5)
    parser.add_argument("--client-cpus", default="4-7")
    parser.add_argument("--server-cpus", default="8-11")
    parser.add_argument("--router-cpus", default="12-19")
    parser.add_argument("--warmup-s", type=float, default=3.0)
    parser.add_argument("--window-s", type=float, default=10.0)
    parser.add_argument("--pings", type=int, default=20000)
    parser.add_argument("--bin-dir", default="")
    parser.add_argument("--table", default=str(TABLE))
    return cmd_run(parser.parse_args(argv[2:]))


if __name__ == "__main__":
    sys.exit(main(sys.argv))
