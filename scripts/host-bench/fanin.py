#!/usr/bin/env python3
# SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
# SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
"""The rounds of a fan-in run (`scripts/pico-compare.sh fanin`): several publishers of large samples to one
subscriber, the program `wz_fanin` (conformance/host-bench/wz_fanin.rs) built once over upstream's `zenoh`
(arm P) and once with the family patched in (arm W), run on this host over TCP loopback in rounds that
alternate the arms (P W, W P, ...), as the parity boots do, so a drift of the host falls on both alike.
`--pairs` names what a round runs as `<subscriber arm><publishers' arm>`: `PP,WW` by default, and a crossed
pair (`PW`: upstream's subscriber, wz's publishers) tells which side of a defect it is on.

A ROUND of an arm is one subscriber listening and `--publishers` publishers connecting to it, each putting
`--size` bytes `--hz` times a second for `--seconds` with the congestion control `--cc`; the subscriber
counts for `--seconds` plus a drain after its first sample. Every process is started afresh.

What a round is judged on is what the arms must both hold, not which is faster:

  * every process ended 0 and printed its line;
  * no sample arrived corrupt, behind a number already seen (a duplicate or a reordering), or foreign;
  * with `--cc block`, every sample a publisher put arrived (the transport is reliable and a put that
    cannot be queued waits): `lost` is 0.

A round that breaks one of them is a DEFECT of that arm and is named in the report. The figures (delivered
fraction, one-way latency on this host's clock, the time a put took, the peak RSS of each side) are
reported per arm as the median of its rounds; they are readings, not a verdict.

    fanin.py --bin-dir DIR --run DIR [--rounds 4] [--publishers 3] [--size 4000000] [--hz 20]
             [--seconds 10] [--cc block|drop] [--drain-s 3] [--pairs PP,WW]
    fanin.py --selftest                           the parsing and the judgement, on printed lines

DIR holds wz_fanin_P and wz_fanin_W. The run directory gets one directory per round and pair with what each
process printed, `rounds.jsonl` (one line per round and pair) and `report.txt`. Exit 0 when every round of
every pair ran and none is a defect, 1 when one is a defect, 2 when a round did not run.
"""

from __future__ import annotations

import argparse
import json
import pathlib
import random
import statistics
import subprocess
import sys
import time

ARMS = ("P", "W")
#: The last lines of a process's errors that the report quotes when the process did not end well.
ERR_TAIL = 3
#: How wz_fanin's subscriber ends when no sample arrived within its wait (it still prints its line).
NOTHING_ARRIVED = 3
#: The seconds the subscriber is given to listen before the publishers start.
LISTEN_SETTLE_S = 1.5
#: The seconds each publisher waits after its session opens, so every publisher's first put meets the
#: subscriber's declaration.
PUB_SETTLE_S = 2.0
#: The seconds a process may run past what its arguments ask before it is stopped and the round lost.
GRACE_S = 60.0


def endpoint() -> str:
    return f"tcp/127.0.0.1:{20000 + random.randrange(20000)}"


def session_args(role: str, where: str) -> list[str]:
    return ["-m", "peer", "-l" if role == "listen" else "-e", where, "--no-multicast-scouting"]


def last_json(text: str) -> dict | None:
    for line in reversed(text.splitlines()):
        line = line.strip()
        if line.startswith("{"):
            try:
                return json.loads(line)
            except json.JSONDecodeError:
                return None
    return None


def err_tail(path: pathlib.Path) -> str:
    lines = [l for l in path.read_text(errors="replace").splitlines() if l.strip()]
    return " | ".join(lines[-ERR_TAIL:]) if lines else "nothing on its errors"


def run_round(sub_bin: pathlib.Path, pub_bin: pathlib.Path, out: pathlib.Path, args: argparse.Namespace) -> dict:
    """One round of one pair: the subscriber, then the publishers; what each printed, judged."""
    out.mkdir(parents=True)
    where = endpoint()
    sub_argv = [str(sub_bin), "--role", "sub", "--seconds", f"{args.seconds + args.drain_s:g}",
                *session_args("listen", where)]
    files = []
    sub_out, sub_err = (out / "sub.out").open("wb"), (out / "sub.err").open("wb")
    files += [sub_out, sub_err]
    sub = subprocess.Popen(sub_argv, stdout=sub_out, stderr=sub_err)
    time.sleep(LISTEN_SETTLE_S)
    pubs = []
    for i in range(args.publishers):
        o, e = (out / f"pub{i}.out").open("wb"), (out / f"pub{i}.err").open("wb")
        files += [o, e]
        argv = [str(pub_bin), "--role", "pub", "--id", str(i), "--size", str(args.size), "--hz", f"{args.hz:g}",
                "--seconds", f"{args.seconds:g}", "--settle", f"{PUB_SETTLE_S:g}", "--cc", args.cc,
                *session_args("connect", where)]
        pubs.append(subprocess.Popen(argv, stdout=o, stderr=e))
    bound = time.monotonic() + LISTEN_SETTLE_S + PUB_SETTLE_S + args.seconds + args.drain_s + GRACE_S
    stopped = []
    for name, proc in [*((f"pub{i}", p) for i, p in enumerate(pubs)), ("sub", sub)]:
        try:
            proc.wait(timeout=max(1.0, bound - time.monotonic()))
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait()
            stopped.append(name)
    for f in files:
        f.close()
    problems: list[str] = [f"{name} did not end in time and was killed" for name in stopped]
    pub_lines = []
    for i, p in enumerate(pubs):
        line = last_json((out / f"pub{i}.out").read_text(errors="replace"))
        if p.returncode != 0 or line is None:
            problems.append(f"pub{i} ended {p.returncode} {'with' if line else 'without'} its line: "
                            f"{err_tail(out / f'pub{i}.err')}")
        if line:
            pub_lines.append(line)
    sub_line = last_json((out / "sub.out").read_text(errors="replace"))
    # A subscriber that saw no sample ends NOTHING_ARRIVED with its line: that is a reading of the
    # delivery, which the judgement below makes, not a round that did not run.
    if sub.returncode not in (0, NOTHING_ARRIVED) or sub_line is None:
        problems.append(f"sub ended {sub.returncode} {'with' if sub_line else 'without'} its line: "
                        f"{err_tail(out / 'sub.err')}")
    row: dict = {"ran": not problems, "problems": problems, "defects": []}
    if sub_line is None or len(pub_lines) != args.publishers:
        return row
    row.update(judge(pub_lines, sub_line, args.cc))
    return row


def judge(pub_lines: list[dict], sub_line: dict, cc: str) -> dict:
    """The defects and the figures of a round, from the lines its processes printed."""
    received = {p["id"]: p for p in sub_line["publishers"]}
    sent = sum(p["sent"] for p in pub_lines)
    got = sum(p["received"] for p in sub_line["publishers"])
    defects: list[str] = []
    for p in pub_lines:
        r = received.get(p["id"], {"received": 0, "gaps": 0, "behind": 0, "corrupt": 0})
        lost = p["sent"] - r["received"]
        if r["corrupt"]:
            defects.append(f"pub{p['id']}: {r['corrupt']} sample(s) arrived corrupt")
        if r["behind"]:
            defects.append(f"pub{p['id']}: {r['behind']} sample(s) arrived behind a number already seen")
        if cc == "block" and lost != 0:
            defects.append(f"pub{p['id']}: {lost} of {p['sent']} sample(s) put under block did not arrive")
        if p["put_errors"]:
            defects.append(f"pub{p['id']}: {p['put_errors']} put(s) returned an error")
    if sub_line["foreign"]:
        defects.append(f"sub: {sub_line['foreign']} sample(s) were not the probe's")
    return {
        "defects": defects,
        "sent": sent,
        "received": got,
        "delivered": got / sent if sent else 0.0,
        "lat_us_p50": sub_line["lat_us_p50"],
        "lat_us_p99": sub_line["lat_us_p99"],
        "lat_us_max": sub_line["lat_us_max"],
        "put_us_p99": max(p["put_us_p99"] for p in pub_lines),
        "put_us_max": max(p["put_us_max"] for p in pub_lines),
        "late": sum(p["late"] for p in pub_lines),
        "rss_kib_sub": sub_line["rss_kib"],
        "rss_kib_pub_max": max(p["rss_kib"] for p in pub_lines),
    }


FIGURES = ("delivered", "lat_us_p50", "lat_us_p99", "lat_us_max", "put_us_p99", "put_us_max", "late",
           "rss_kib_sub", "rss_kib_pub_max")


def report(rows: list[dict], args: argparse.Namespace, pairs: list[str]) -> str:
    lines = [f"fan-in: {args.publishers} publisher(s) x {args.size} B at {args.hz:g} Hz for {args.seconds:g} s, "
             f"cc={args.cc}, {args.rounds} round(s) of each pair (subscriber arm, publishers' arm), TCP loopback, "
             "one-way latency on this host's clock"]
    lines.append("figure".ljust(18) + "".join(p.rjust(14) for p in pairs))
    for fig in FIGURES:
        cells = []
        for pair in pairs:
            vals = [r[fig] for r in rows if r["pair"] == pair and fig in r]
            cells.append(f"{statistics.median(vals):.4g}" if vals else "-")
        lines.append(fig.ljust(18) + "".join(c.rjust(14) for c in cells))
    for r in rows:
        for what in r["problems"]:
            lines.append(f"NOT RUN  {r['pair']} round {r['round']}: {what}")
        for what in r["defects"]:
            lines.append(f"DEFECT   {r['pair']} round {r['round']}: {what}")
    return "\n".join(lines) + "\n"


def selftest() -> int:
    """The parsing and the judgement, on lines of the shape wz_fanin prints."""
    assert last_json("noise\n{\"a\": 1}\n\n") == {"a": 1}
    assert last_json("{broken\n") is None and last_json("") is None

    def pub(i: int, sent: int, errors: int = 0) -> dict:
        return {"id": i, "sent": sent, "put_errors": errors, "late": 0, "put_us_p99": 5, "put_us_max": 9,
                "rss_kib": 100}

    def sub(rows: list[tuple[int, int, int, int]], foreign: int = 0) -> dict:
        return {"foreign": foreign, "lat_us_p50": 1, "lat_us_p99": 2, "lat_us_max": 3, "rss_kib": 200,
                "publishers": [{"id": i, "received": r, "gaps": 0, "behind": b, "corrupt": c, "bytes": 0}
                               for i, r, b, c in rows]}

    whole = judge([pub(0, 10), pub(1, 10)], sub([(0, 10, 0, 0), (1, 10, 0, 0)]), "block")
    assert whole["defects"] == [] and whole["delivered"] == 1.0, whole
    lost = judge([pub(0, 10)], sub([(0, 7, 0, 0)]), "block")
    assert lost["defects"] == ["pub0: 3 of 10 sample(s) put under block did not arrive"], lost
    assert judge([pub(0, 10)], sub([(0, 7, 0, 0)]), "drop")["defects"] == [], "drop may lose"
    # A publisher the subscriber never heard from is lost whole, not skipped.
    silent = judge([pub(0, 5), pub(1, 5)], sub([(0, 5, 0, 0)]), "block")
    assert silent["defects"] == ["pub1: 5 of 5 sample(s) put under block did not arrive"], silent
    bad = judge([pub(0, 4, errors=1)], sub([(0, 4, 1, 2)], foreign=3), "drop")
    assert bad["defects"] == [
        "pub0: 2 sample(s) arrived corrupt",
        "pub0: 1 sample(s) arrived behind a number already seen",
        "pub0: 1 put(s) returned an error",
        "sub: 3 sample(s) were not the probe's",
    ], bad
    rows = [{"pair": "PP", "round": 0, "problems": [], "defects": [], "delivered": 1.0},
            {"pair": "WW", "round": 0, "problems": ["sub ended 1"], "defects": ["x"]}]
    text = report(rows, argparse.Namespace(publishers=1, size=24, hz=1.0, seconds=1.0, cc="block", rounds=1),
                  ["PP", "WW"])
    assert "NOT RUN  WW round 0: sub ended 1" in text and "DEFECT   WW round 0: x" in text, text
    print("fanin selftest: OK")
    return 0


def main() -> int:
    if sys.argv[1:] == ["--selftest"]:
        return selftest()
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--bin-dir", required=True, type=pathlib.Path)
    ap.add_argument("--run", required=True, type=pathlib.Path)
    ap.add_argument("--rounds", type=int, default=4)
    ap.add_argument("--publishers", type=int, default=3)
    ap.add_argument("--size", type=int, default=4_000_000)
    ap.add_argument("--hz", type=float, default=20.0)
    ap.add_argument("--seconds", type=float, default=10.0)
    ap.add_argument("--cc", choices=("block", "drop"), default="block")
    ap.add_argument("--drain-s", type=float, default=3.0)
    ap.add_argument("--pairs", default="PP,WW",
                    help="what a round runs, comma separated: the subscriber's arm then the publishers' (PP, WW, PW, WP)")
    args = ap.parse_args()
    pairs = args.pairs.split(",")
    if not pairs or any(len(p) != 2 or set(p) - set(ARMS) for p in pairs):
        ap.error(f"--pairs {args.pairs}: each is two of {''.join(ARMS)}")
    binaries = {arm: args.bin_dir / f"wz_fanin_{arm}" for arm in ARMS}
    missing = [str(b) for b in binaries.values() if not b.is_file()]
    if missing:
        print(f"fanin: no program at {', '.join(missing)}", file=sys.stderr)
        return 2
    args.run.mkdir(parents=True, exist_ok=False)
    rows: list[dict] = []
    with (args.run / "rounds.jsonl").open("w") as log:
        for k in range(args.rounds):
            for pair in (pairs if k % 2 == 0 else pairs[::-1]):
                row = run_round(binaries[pair[0]], binaries[pair[1]], args.run / f"{pair}-r{k}", args)
                row.update({"pair": pair, "round": k})
                rows.append(row)
                log.write(json.dumps(row) + "\n")
                log.flush()
    text = report(rows, args, pairs)
    (args.run / "report.txt").write_text(text)
    print(text, end="")
    if not all(r["ran"] for r in rows):
        return 2
    return 1 if any(r["defects"] for r in rows) else 0


if __name__ == "__main__":
    sys.exit(main())
