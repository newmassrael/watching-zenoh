#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
# SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
"""R3213 (no register item) -- the admin node's verdict, run by ONE program
against an emulated node and against a board.

The debt this answers for, open-debt item 876, lives in the operator's
agent-memory register, which has no store `debt-` id for
`gate_provenance_lint.py` to resolve; the honest pair is this sentence and
`no register item` in the citation.

## The defect this ends

The steps of `deploy/zephyr-admin-node/HARDWARE_VERDICT.md` (HW.0 to HW.7) were
the body of a shell function in `scripts/run-ci.sh`, and only the emulator lanes
(Layer Qa, Layer Qza) ran that function. On a board the lab ran the same checks
BY HAND: it started two routers, watched the console, asked the REST plugin and
wrote down each sentence. The ledger entry and `zephyr_board_table_gate.py` then
read that transcription, and nothing could tell a sentence that a check printed
from one somebody typed. A wrong address, a wrong hash or a step that was never
put reads exactly like a right one.

This program IS the steps. The way it reaches the node is its argument:

  qemu   it boots the node with the QEMU command it is given, reads the
         console off QEMU's output, and talks to the node through QEMU's user
         networking (the host forward to 10.0.2.15:7447, the host at 10.0.2.2
         as the guest sees it). Layer Qa and Layer Qza call this, and their
         output is the lines they printed before the steps moved here, byte for
         byte (the label, the em dash before OK, a stack line with the
         console's carriage return kept).
  board  the node is already running on a board; it is reached at the locator
         the node printed on its console, and its console is a capture file
         the lab keeps. The output is the grammar of HARDWARE_VERDICT.md, one
         line per step on standard output and nothing else there, so the lines
         go into the ledger entry as they were printed. Why a step failed goes
         to standard error, on lines that name no step.

Both modes run the same judging code (`JUDGES` below); only the address book and
the rendering differ.

## How a lab runs it against a board

  1. Start a capture of the board's console into a file, from BEFORE the reset
     of the boot under test (any tool that appends the console's bytes to a
     file). The capture must hold ONE boot: a capture with two READY lines is
     refused at HW.0, because the stack peak and the READY line it reads would
     not be of the same boot.
  2. Reset the board. Run nothing else against the node before this program:
     HW.5 reads the node's write counter and expects this program's write to be
     its first.
  3. On a host with a link to the board:

       python3 scripts/lib/admin_node_verdict.py board \\
           --node udp/<node address>:7447 \\
           --host <this host's address on the board's subnet> \\
           --console <the capture file> \\
           --zenohd <a stock zenohd of the pinned version>

     `--node` is the first locator of the node's READY line. The REST plugin
     must sit beside zenohd (`libzenoh_plugin_rest.so`). Optional:
     `--b-port` (B's port, default 17448), `--rest-port` (A's REST port on
     127.0.0.1, default 17800).
  4. Exit 0: every step held, and standard output is the eight sentences to
     quote in the record. Exit 1: a step did not hold; its line says FAIL and
     standard error says why. Exit 2: the program could not run (a missing
     file, a malformed argument).

The routers it starts are those of "What the host runs" in the grammar file. B
listens on `udp/<host>:<b-port>` and nothing else; A dials `--node`, holds no
listener of its own (`listen/endpoints` empty) and carries the REST plugin on
127.0.0.1 only; both have multicast scouting off and fixed ids (sixteen `a`,
sixteen `b`). In qemu mode A keeps zenohd's default listener, as the emulator
lanes always ran it: on the loopback-only QEMU topology it reaches nothing the
node could report.

## What this cannot settle

The steps after HW.7 (the second interface, HW.8 to HW.25) read instruments,
segment captures and a cable pull; none of them is here. HW.16 to HW.20 are
HW.1 to HW.5 with other routers and could be added as a third address book.
Whether a board passes is settled only by running this against a board.

## Its own test

`--selftest` drives the judging code against a FAKE node (hand-made REST
replies and console lines) step by step: every step has a fault that makes that
step, and only that step, red, and every step's comparison is then weakened in
turn to show its fault case goes green without it (the red-first pair). It runs
the program end to end with a fake QEMU and a fake zenohd, and holds the lane's
output to the bytes the lanes printed before the move. It reads the published
grammar and requires every board sentence to be an instance of it, and it hands
the board output to `zephyr_board_table_gate.step_verdicts`, the reader of the
record, to show that a record quoting it is read as the steps it printed.
"""

from __future__ import annotations

import argparse
import io
import json
import os
import re
import shutil
import signal
import subprocess
import sys
import tempfile
import threading
import time
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Callable

ROOT = Path(__file__).resolve().parents[2]
GRAMMAR = ROOT / "deploy" / "zephyr-admin-node" / "HARDWARE_VERDICT.md"

A_ID = "a" * 16
B_ID = "b" * 16
# QEMU's user networking: the guest's own address and the host as the guest
# sees it. The node listens on 7447.
QEMU_GUEST = "10.0.2.15"
QEMU_HOST = "10.0.2.2"
NODE_PORT = 7447
READY_PREFIX = "ZEPHYR-WZ-ADMIN "
READY_LINE = re.compile(r"ZEPHYR-WZ-ADMIN READY ([0-9a-f]+)((?: udp/\S+)+)")
STACK_PREFIX = "stack: peak "
STACK_LINE = re.compile(r"stack: peak ([0-9]+) of ([0-9]+) bytes")
LAST_STEP = 7

# The sentence a step prints when it holds. Steps 0, 4 and 7 carry a value
# read off the run and are built where it is known.
SENTENCES = {
    0: "the node's console says who and where it is",
    1: "GET before the write: the node reports A only",
    2: "PUT connect/endpoints: the node dialled B, GET reports A and B",
    3: "GET config names the written list",
    5: "status/connect: the write was replaced, B is live and established",
    6: "a group of two is refused, and status/connect says multi_link_group",
}
STACK_SENTENCE = "the main stack kept a quarter free"


def links_sentence(listener: str) -> str:
    return f"every session names its link src/dst; A reached {listener}"


@dataclass(frozen=True)
class Timing:
    """How long each wait lasts. The defaults are the lanes' own."""

    ready_tries: int = 600
    ready_interval: float = 0.1
    await_tries: int = 60
    await_interval: float = 1.0
    group_tries: int = 30
    group_interval: float = 1.0
    http_timeout: float = 5.0
    stack_settle: float = 1.0


@dataclass(frozen=True)
class Plan:
    """Who the node is and where each party is, as the node sees it."""

    label: str
    grammar: bool  # True: HARDWARE_VERDICT.md lines; False: the lane's lines
    node_id: str | None  # None: read off the READY line
    ready: "EreReady | BoardReady | None"  # None: no step 0
    a_dial: str  # the locator A dials to reach the node
    b_listen: str  # the locator B listens on
    b_dial: str  # the locator the node is told to dial to reach B
    node_listener: str  # the node's listener as the node itself sees it
    stack_verdict: bool
    a_extra: tuple[str, ...] = ()

    def group_second(self) -> str:
        """The second locator of HW.6's group: B's host, a port nobody serves."""
        return self.b_dial.rsplit(":", 1)[0] + ":9"


# ---------------------------------------------------------------- judging --
#
# One comparison per step. The scenario reads its observations and hands them
# to these; the selftest weakens each in turn. Nothing else decides a step.
#
# Why each is what it is (moved with the steps from `scripts/run-ci.sh`):
#
#   1   the CONTROL: the GET before the write must list B nowhere, so step 2's
#       B can only have come from the write. Every step asserts on the ids in
#       the JSON, never on an HTTP status alone.
#   4   R2841: every session names its link's two ends as upstream does, and
#       the one A reached is the node's listener as the node sees it.
#   5   R2846/R2851: the node's own account of the write at the wz key
#       `status/connect`, and `seq` 1 because step 2's PUT is the first write
#       the node got.
#   6   a group of two locators is one transport over two links, which the
#       node refuses BY NAME for each locator; the host reads the reason.
#   7   R3081: a firmware that measures its own stack says so on its console
#       (`stack: peak N of M bytes`, once for each new peak), and a peak that
#       leaves less than a quarter of the stack free is refused. A stack that
#       runs out does not fault at its own end, it overwrites the memory below
#       it, and the machine dies later with a register file that names none of
#       it. The admin node's did, with a 16 KiB stack it needed 20,012 bytes
#       of, and the lane said only that a GET came back empty. A quarter, and
#       not the 256 bytes the single-run MCU deploys allow themselves, because
#       this node's depth follows what its peers send and this scenario is not
#       every thing they can send. A console with NO such line is a failure
#       too: a node that stopped measuring reads exactly like one that measured
#       and fit.


def _judge_ready(found: list[str], plan: Plan) -> bool:
    if isinstance(plan.ready, BoardReady):
        if len(found) != 1:
            return False
        m = READY_LINE.fullmatch(found[0])
        return bool(m) and m.group(2).split()[0] == plan.node_listener
    return bool(found)


def _judge_status_after_write(doc: object, plan: Plan) -> bool:
    return doc["last_write"] == {"seq": 1, "verdict": "replace"} and doc["endpoints"] == [
        {"endpoint": plan.b_dial, "state": "live", "established": True}
    ]


def _judge_status_after_group(doc: object, plan: Plan) -> bool:
    return (
        doc["last_write"] == {"seq": 2, "verdict": "replace"}
        and len(doc["endpoints"]) == 2
        and all(e["state"] == "refused" and e["reason"] == "multi_link_group" for e in doc["endpoints"])
    )


JUDGES: dict[int, Callable[..., bool]] = {
    0: _judge_ready,
    1: lambda got, plan: got == A_ID,
    2: lambda got, plan: got == f"{A_ID} {B_ID}",
    3: lambda body, plan: plan.b_dial.encode() in body,
    4: lambda report, plan: report is not None
    and not report[0]
    and report[1] == plan.node_listener,
    5: _judge_status_after_write,
    6: _judge_status_after_group,
    7: lambda peak, size, plan: peak * 4 <= size * 3,
}


def judge(step: int, *args) -> bool:
    """A comparison that raises on a malformed reply has not held."""
    try:
        return bool(JUDGES[step](*args))
    except (KeyError, IndexError, TypeError, AttributeError, ValueError):
        return False


# ------------------------------------------------------- reading replies --


def _replies(body: bytes) -> list:
    replies = json.loads(body)
    if not isinstance(replies, list):
        raise ValueError("not a list of replies")
    return replies


def sessions_seen(body: bytes) -> str:
    """The node's sessions as its sorted peer ids, space-separated."""
    try:
        return " ".join(
            sorted(s["peer"] for r in _replies(body) for s in r["value"].get("sessions", []))
        )
    except (ValueError, KeyError, TypeError, AttributeError):
        return ""


def links_report(body: bytes) -> tuple[list, object] | None:
    """(links that are not udp at both ends, the src of A's link), or None."""
    try:
        bad, accepted = [], None
        for r in _replies(body):
            for s in r["value"].get("sessions", []):
                for link in s.get("links", []):
                    if not link.get("src", "").startswith("udp/") or not link.get(
                        "dst", ""
                    ).startswith("udp/"):
                        bad.append((s["peer"], link))
                    if s["peer"] == A_ID:
                        accepted = link.get("src")
        return bad, accepted
    except (ValueError, KeyError, TypeError, AttributeError):
        return None


def status_doc(body: bytes) -> object:
    try:
        return [r["value"] for r in _replies(body)][0]
    except (ValueError, IndexError, KeyError, TypeError):
        return None


def console_lines(raw: bytes) -> list[str]:
    """The console split at line feeds only, a carriage return kept."""
    return raw.decode("utf-8", "surrogateescape").split("\n")


def last_stack_line(raw: bytes) -> str:
    lines = [ln for ln in console_lines(raw) if ln.startswith(STACK_PREFIX)]
    return lines[-1] if lines else ""


# ---------------------------------------------------------------- ready --


class EreReady:
    """The lanes' READY wait: an extended regex (grep's, POSIX classes and
    all) a line of the console must match."""

    def __init__(self, pattern: str) -> None:
        self.pattern = pattern

    def find(self, console: Path) -> list[str]:
        r = subprocess.run(
            ["grep", "-E", "--", self.pattern, str(console)],
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
        )
        if r.returncode != 0:
            return []
        return [ln for ln in r.stdout.decode("utf-8", "surrogateescape").split("\n") if ln]

    def fail_text(self, found: list[str], plan: Plan, timing: Timing) -> str:
        return f"the node never printed its READY line (/{self.pattern}/)"


class BoardReady:
    """A board's READY line: `ZEPHYR-WZ-ADMIN READY <id> <locator>...`, once
    in the capture, its first locator the one the lab named."""

    def find(self, console: Path) -> list[str]:
        try:
            raw = console.read_bytes()
        except OSError:
            return []
        return [
            ln.rstrip()
            for ln in console_lines(raw)
            if READY_LINE.fullmatch(ln.rstrip())
        ]

    def fail_text(self, found: list[str], plan: Plan, timing: Timing) -> str:
        if not found:
            secs = timing.ready_tries * timing.ready_interval
            return f"no `{READY_PREFIX}READY` line reached the capture in {secs:g} s"
        if len(found) > 1:
            return (
                f"the capture holds {len(found)} READY lines, so it spans more than "
                f"one boot: capture one boot, from before its reset"
            )
        return f"the node printed `{found[0]}`, whose first locator is not {plan.node_listener}"


# ------------------------------------------------------------- verdicts --


@dataclass
class Verdict:
    step: int
    held: bool | None  # None: not run, because an earlier step did not hold
    sentence: str
    fail_text: str = ""
    quote: str | None = None  # HW.0's READY line, in the grammar only


class Renderer:
    """Writes each verdict as it is reached, to two byte streams."""

    def __init__(self, plan: Plan, out, err) -> None:
        self.plan, self.out, self.err = plan, out, err

    def _write(self, stream, text: str) -> None:
        stream.write(text.encode("utf-8", "surrogateescape"))
        stream.flush()

    def step(self, v: Verdict) -> None:
        if self.plan.grammar:
            sentence = v.sentence.rstrip()
            if v.quote:
                sentence += f": {v.quote}"
            mark = "OK" if v.held else "FAIL"
            self._write(self.out, f"HW.{v.step} {sentence} - {mark}\n")
            if v.held is None:
                self._write(self.err, "  not run: an earlier step did not hold\n")
            elif not v.held:
                self._write(self.err, f"  {v.fail_text}\n")
            return
        # The lanes print nothing for a step that was not run.
        if v.held:
            self._write(self.out, f"  {self.plan.label}.{v.step} {v.sentence} \u2014 OK\n")
        elif v.held is False:
            self._write(self.err, f"  {self.plan.label}.{v.step} {v.fail_text}\n")

    def not_run(self, first: int, last: int, sentences: dict[int, str]) -> None:
        for n in range(first, last + 1):
            self.step(Verdict(n, None, sentences[n]))

    def raw(self, data: bytes) -> None:
        self.err.write(data)
        self.err.flush()

    def note(self, text: str) -> None:
        self._write(self.err, text)


def tail(data: bytes, n: int) -> bytes:
    """`tail -n`: the last n lines, a final line without a newline counted."""
    lines = re.findall(rb"[^\n]*\n|[^\n]+$", data)
    return b"".join(lines[-n:])


# -------------------------------------------------------------- scenario --


def _plain_sentences(plan: Plan) -> dict[int, str]:
    s = dict(SENTENCES)
    s[4] = links_sentence(plan.node_listener)
    s[7] = STACK_SENTENCE
    return s


def run_scenario(plan: Plan, env: "Env", timing: Timing, out: Renderer) -> int:
    last = LAST_STEP if plan.stack_verdict else LAST_STEP - 1
    plain = _plain_sentences(plan)
    env.start_console()
    try:
        node_id = plan.node_id
        if plan.ready is not None:
            found: list[str] = []
            for _ in range(timing.ready_tries):
                found = plan.ready.find(env.console_path)
                if found:
                    break
                if not env.console_alive():
                    break
                env.sleep(timing.ready_interval)
            if not judge(0, found, plan):
                out.step(Verdict(0, False, plain[0], plan.ready.fail_text(found, plan, timing)))
                if plan.grammar:
                    out.not_run(1, last, plain)
                env.stop()
                env.dump(out, routers=False)
                return 1
            quote = None
            if isinstance(plan.ready, BoardReady) and found:
                m = READY_LINE.fullmatch(found[0])
                if m:
                    node_id = node_id or m.group(1)
                quote = found[0][len(READY_PREFIX):] if found[0].startswith(READY_PREFIX) else found[0]
            out.step(Verdict(0, True, plain[0], quote=quote))
        if node_id is None:
            out.note("  the node's id is unknown: no READY line named it\n")
            return 2
        env.start_routers(plan, node_id)

        fail = False

        def await_sessions(step: int) -> tuple[bool, str]:
            got = ""
            for _ in range(timing.await_tries):
                got = sessions_seen(env.get(""))
                if judge(step, got, plan):
                    return True, got
                env.sleep(timing.await_interval)
            return False, got

        held, got = await_sessions(1)
        if held:
            out.step(Verdict(1, True, plain[1]))
        else:
            out.step(Verdict(1, False, plain[1], f"GET before the write FAIL: sessions [{got}], want [A]"))
            fail = True
        if not fail:
            env.put("/config/connect/endpoints", f'["{plan.b_dial}"]'.encode())
            held, got = await_sessions(2)
            if held:
                out.step(Verdict(2, True, plain[2]))
            else:
                out.step(
                    Verdict(2, False, plain[2], f"PUT connect/endpoints FAIL: sessions [{got}], want [A B]")
                )
                fail = True
            if judge(3, env.get("/config"), plan):
                out.step(Verdict(3, True, plain[3]))
            else:
                out.step(Verdict(3, False, plain[3], "GET config FAIL: the written endpoint is not in it"))
                fail = True
            body = env.get("")
            report = links_report(body)
            if judge(4, report, plan):
                out.step(Verdict(4, True, plain[4]))
            else:
                if report is None:
                    detail = f"the reply is not a JSON list of replies: {body[:200]!r}"
                else:
                    detail = f"bad={report[0]} accepted_src={report[1]}"
                out.step(Verdict(4, False, plain[4], f"link src/dst FAIL: {detail}"))
                fail = True
            doc = status_doc(env.get("/status/connect"))
            if judge(5, doc, plan):
                out.step(Verdict(5, True, plain[5]))
            else:
                out.step(Verdict(5, False, plain[5], f"status/connect FAIL: {doc}"))
                fail = True
            group = json.dumps(
                [{"strategy": "allOf", "locators": [plan.b_dial, plan.group_second()]}],
                separators=(",", ":"),
            )
            env.put("/config/connect/endpoints", group.encode())
            held = False
            for _ in range(timing.group_tries):
                doc = status_doc(env.get("/status/connect"))
                if judge(6, doc, plan):
                    held = True
                    break
                env.sleep(timing.group_interval)
            if held:
                out.step(Verdict(6, True, plain[6]))
            else:
                out.step(Verdict(6, False, plain[6], f"status/connect after a group write FAIL: {doc}"))
                fail = True
        elif plan.grammar:
            out.not_run(2, LAST_STEP - 1, plain)

        if plan.stack_verdict:
            env.sleep(timing.stack_settle)  # the node samples a few times a second
            line = last_stack_line(env.console_text())
            m = STACK_LINE.match(line)
            if m is None:
                out.step(
                    Verdict(
                        7,
                        False,
                        plain[7],
                        "the main stack FAIL: the node printed no `stack: peak N of M bytes` line",
                    )
                )
                fail = True
            else:
                sentence = f"{STACK_SENTENCE}: {line}"
                if judge(7, int(m.group(1)), int(m.group(2)), plan):
                    out.step(Verdict(7, True, sentence))
                else:
                    out.step(
                        Verdict(7, False, sentence, f"the main stack FAIL: {line} leaves under a quarter free")
                    )
                    fail = True

        env.stop()
        if fail:
            env.dump(out, routers=True)
        return 1 if fail else 0
    finally:
        env.stop()
        env.cleanup()


# ------------------------------------------------------------------- env --


class Env:
    """How the scenario reaches the console, the routers and the REST plugin."""

    console_path: Path

    def start_console(self) -> None: ...
    def console_alive(self) -> bool: return True
    def console_text(self) -> bytes: return self.console_path.read_bytes()
    def start_routers(self, plan: Plan, node_id: str) -> None: ...
    def get(self, suffix: str) -> bytes: raise NotImplementedError
    def put(self, suffix: str, body: bytes) -> None: raise NotImplementedError
    def sleep(self, seconds: float) -> None: time.sleep(seconds)
    def stop(self) -> None: ...
    def dump(self, out: Renderer, routers: bool) -> None: ...
    def cleanup(self) -> None: ...


def router_argv(zenohd: str, plan: Plan, rest_port: int) -> tuple[list[str], list[str]]:
    """B's and A's command lines, in the order the lanes started them."""
    b = [zenohd, "--no-multicast-scouting", "-l", plan.b_listen, '--cfg=id:"bbbbbbbbbbbbbbbb"']
    a = [
        zenohd,
        "--no-multicast-scouting",
        "-e",
        plan.a_dial,
        "--rest-http-port",
        f"127.0.0.1:{rest_port}",
        "--plugin-search-dir",
        os.path.dirname(zenohd) or ".",
        '--cfg=id:"aaaaaaaaaaaaaaaa"',
        *plan.a_extra,
    ]
    return b, a


class HostEnv(Env):
    """The real host: processes, files, HTTP."""

    def __init__(
        self,
        zenohd: str,
        rest_port: int,
        timing: Timing,
        qemu: list[str] | None = None,
        capture: Path | None = None,
    ) -> None:
        self.zenohd, self.rest_port, self.timing = zenohd, rest_port, timing
        self.qemu, self.capture = qemu, capture
        self.dir = Path(tempfile.mkdtemp())
        self.console_path = capture if capture is not None else self.dir / "qemu.log"
        self.procs: list[subprocess.Popen] = []
        self.qemu_proc: subprocess.Popen | None = None
        self.base = ""

    def _spawn(self, argv: list[str], log: Path) -> subprocess.Popen:
        with log.open("wb") as fh:
            p = subprocess.Popen(argv, stdin=subprocess.DEVNULL, stdout=fh, stderr=subprocess.STDOUT)
        self.procs.append(p)
        return p

    def start_console(self) -> None:
        if self.qemu is not None:
            self.qemu_proc = self._spawn(self.qemu, self.console_path)

    def console_alive(self) -> bool:
        return self.qemu_proc is None or self.qemu_proc.poll() is None

    def start_routers(self, plan: Plan, node_id: str) -> None:
        b, a = router_argv(self.zenohd, plan, self.rest_port)
        self._spawn(b, self.dir / "zenohd-b.log")
        self._spawn(a, self.dir / "zenohd-a.log")
        self.base = f"http://127.0.0.1:{self.rest_port}/@/{node_id}/peer"

    def get(self, suffix: str) -> bytes:
        try:
            with urllib.request.urlopen(self.base + suffix, timeout=self.timing.http_timeout) as r:
                return r.read()
        except urllib.error.HTTPError as e:
            return e.read()
        except (OSError, ValueError):
            return b""

    def put(self, suffix: str, body: bytes) -> None:
        req = urllib.request.Request(
            self.base + suffix, data=body, method="PUT", headers={"content-type": "application/json"}
        )
        try:
            with urllib.request.urlopen(req, timeout=self.timing.http_timeout) as r:
                r.read()
        except (OSError, ValueError):
            pass

    def stop(self) -> None:
        for p in self.procs:
            if p.poll() is None:
                p.terminate()
        for p in self.procs:
            try:
                p.wait(timeout=10)
            except subprocess.TimeoutExpired:
                p.kill()
                p.wait()

    def _read(self, path: Path) -> bytes:
        try:
            return path.read_bytes()
        except OSError:
            return b""

    def dump(self, out: Renderer, routers: bool) -> None:
        if self.capture is None:
            out.note("  --- qemu\n")
            out.raw(self._read(self.console_path))
        else:
            out.note("  --- console (tail)\n")
            out.raw(tail(self._read(self.console_path), 40))
        if routers:
            out.note("  --- zenohd A (tail)\n")
            out.raw(tail(self._read(self.dir / "zenohd-a.log"), 20))
            out.note("  --- zenohd B (tail)\n")
            out.raw(tail(self._read(self.dir / "zenohd-b.log"), 10))

    def cleanup(self) -> None:
        shutil.rmtree(self.dir, ignore_errors=True)


# ------------------------------------------------------------------- cli --


def qemu_plan(args: argparse.Namespace) -> Plan:
    return Plan(
        label=args.label,
        grammar=False,
        node_id=args.node_id,
        ready=None if args.ready == "-" else EreReady(args.ready),
        a_dial=f"udp/127.0.0.1:{args.fwd_port}",
        b_listen=f"udp/127.0.0.1:{args.b_port}",
        b_dial=f"udp/{QEMU_HOST}:{args.b_port}",
        node_listener=f"udp/{QEMU_GUEST}:{NODE_PORT}",
        stack_verdict=args.stack_verdict,
    )


def _udp(host: str, port: int) -> str:
    return f"udp/[{host}]:{port}" if ":" in host else f"udp/{host}:{port}"


def board_plan(args: argparse.Namespace) -> Plan:
    return Plan(
        label="HW",
        grammar=True,
        node_id=None,
        ready=BoardReady(),
        a_dial=args.node,
        b_listen=_udp(args.host, args.b_port),
        b_dial=_udp(args.host, args.b_port),
        node_listener=args.node,
        stack_verdict=True,
        a_extra=("--cfg=listen/endpoints:[]",),
    )


def _default_zenohd() -> str:
    return os.environ.get("WZ_ZENOHD_BIN") or str(ROOT / "target" / "zenohd" / "zenohd")


def _refuse(text: str) -> int:
    sys.stderr.write(f"admin_node_verdict: {text}\n")
    sys.stderr.flush()
    return 2


def _on_sigterm(signum, frame) -> None:
    # A terminated run still stops its routers and its QEMU (the `finally`).
    raise SystemExit(128 + signum)


def main(argv: list[str]) -> int:
    if argv == ["--selftest"]:
        return selftest()
    ap = argparse.ArgumentParser(prog="admin_node_verdict.py")
    sub = ap.add_subparsers(dest="mode", required=True)
    q = sub.add_parser("qemu", help="boot the node under QEMU and judge it (the lanes)")
    q.add_argument("--label", required=True)
    q.add_argument("--node-id", required=True)
    q.add_argument("--ready", required=True, help="extended regex of the READY line, or -")
    q.add_argument("--stack-verdict", action="store_true")
    q.add_argument("--zenohd", default=None)
    q.add_argument("--fwd-port", type=int, required=True)
    q.add_argument("--b-port", type=int, required=True)
    q.add_argument("--rest-port", type=int, required=True)
    q.add_argument("qemu", nargs=argparse.REMAINDER)
    b = sub.add_parser("board", help="judge a node already running on a board")
    b.add_argument("--node", required=True, help="the node's locator, udp/<address>:<port>")
    b.add_argument("--host", required=True, help="this host's address on the board's subnet")
    b.add_argument("--console", required=True, type=Path, help="the console capture file")
    b.add_argument("--zenohd", default=None)
    b.add_argument("--b-port", type=int, default=17448)
    b.add_argument("--rest-port", type=int, default=17800)
    args = ap.parse_args(argv)

    zenohd = args.zenohd or _default_zenohd()
    timing = Timing()
    signal.signal(signal.SIGTERM, _on_sigterm)
    if args.mode == "qemu":
        cmd = args.qemu[1:] if args.qemu[:1] == ["--"] else args.qemu
        if not cmd:
            return _refuse("no QEMU command after --")
        fwd = f"hostfwd=udp:127.0.0.1:{args.fwd_port}-{QEMU_GUEST}:{NODE_PORT}"
        if not any(fwd in a for a in cmd):
            return _refuse(
                f"the QEMU command does not carry {fwd}: A would dial a port the node is not behind"
            )
        plan = qemu_plan(args)
        env = HostEnv(zenohd, args.rest_port, timing, qemu=cmd)
    else:
        if not re.fullmatch(r"udp/(\[[0-9a-fA-F:.]+\]|[^\s:/\[\]]+):[0-9]+", args.node):
            return _refuse(f"--node {args.node!r} is not a locator of the form udp/<address>:<port>")
        if not args.console.is_file():
            return _refuse(f"no console capture at {args.console}")
        if not os.access(zenohd, os.X_OK):
            return _refuse(f"zenohd is not an executable at {zenohd}")
        plugin = Path(os.path.dirname(zenohd) or ".") / "libzenoh_plugin_rest.so"
        if not plugin.is_file():
            return _refuse(f"the REST plugin is not beside zenohd ({plugin})")
        plan = board_plan(args)
        env = HostEnv(zenohd, args.rest_port, timing, capture=args.console)
    return run_scenario(plan, env, timing, Renderer(plan, sys.stdout.buffer, sys.stderr.buffer))


# -------------------------------------------------------------- selftest --
#
# The fake node. Each fault changes ONE observation, so that it reds one step.

FAULTS_ALL = (
    "no_ready",
    "extra_before",
    "never_dials",
    "config_forgets",
    "link_src",
    "link_proto",
    "status_not_live",
    "status_seq",
    "group_accepted",
    "group_reason",
    "stack_deep",
    "stack_absent",
    "ready_wrong_locator",
    "two_boots",
)


@dataclass
class FakeBoard:
    zid: str
    node_listener: str
    b_dial: str
    faults: frozenset = field(default_factory=frozenset)
    seq: int = 0
    written: list = field(default_factory=list)
    status: dict | None = None
    dialled: bool = False

    def console(self, stack_peak: int = 20080) -> bytes:
        lines = ["*** Booting Zephyr OS ***", "wz: core clock 25000000 Hz"]
        ready = f"ZEPHYR-WZ-ADMIN READY {self.zid} {self.node_listener}"
        if "ready_wrong_locator" in self.faults:
            ready = f"ZEPHYR-WZ-ADMIN READY {self.zid} udp/198.51.100.7:7447"
        if "two_boots" in self.faults:
            lines += [ready, "stack: peak 3000 of 32768 bytes", "*** Booting Zephyr OS ***"]
        if "no_ready" not in self.faults:
            lines.append(ready)
        lines.append("stack: peak 3524 of 32768 bytes")
        if "stack_absent" in self.faults:
            lines = [ln for ln in lines if not ln.startswith(STACK_PREFIX)]
        else:
            peak = 30000 if "stack_deep" in self.faults else stack_peak
            lines.append(f"stack: peak {peak} of 32768 bytes")
        return "".join(f"{ln}\r\n" for ln in lines).encode()

    def _reply(self, suffix: str, value: object) -> bytes:
        return json.dumps(
            [{"key": f"@/{self.zid}/peer{suffix}", "value": value, "encoding": "application/json"}]
        ).encode()

    def get(self, suffix: str) -> bytes:
        if suffix == "":
            src = "udp/10.9.9.9:7447" if "link_src" in self.faults else self.node_listener
            sessions = [{"peer": A_ID, "links": [{"src": src, "dst": "udp/127.0.0.1:40000"}]}]
            if "extra_before" in self.faults:
                sessions.append({"peer": "c" * 16, "links": [{"src": src, "dst": "udp/127.0.0.1:40002"}]})
            if self.dialled:
                dst = self.b_dial.replace("udp/", "tcp/") if "link_proto" in self.faults else self.b_dial
                sessions.append({"peer": B_ID, "links": [{"src": "udp/10.0.2.15:40001", "dst": dst}]})
            return self._reply("", {"zid": self.zid, "sessions": sessions})
        if suffix == "/config":
            eps = [] if "config_forgets" in self.faults else self.written
            return self._reply("/config", {"connect": {"endpoints": eps}})
        if suffix == "/status/connect":
            return self._reply("/status/connect", self.status) if self.status else b"[]"
        return b"[]"

    def put(self, suffix: str, body: bytes) -> None:
        if suffix != "/config/connect/endpoints":
            return
        eps = json.loads(body)
        self.seq += 1
        self.written = eps
        seq = self.seq + 1 if "status_seq" in self.faults else self.seq
        if all(isinstance(e, str) for e in eps):
            if self.b_dial in eps and "never_dials" not in self.faults:
                self.dialled = True
            live = "status_not_live" not in self.faults
            self.status = {
                "last_write": {"seq": seq, "verdict": "replace"},
                "endpoints": [
                    {"endpoint": e, "state": "live" if live else "connecting", "established": live}
                    for e in eps
                ],
            }
        else:
            locs = [loc for g in eps for loc in g["locators"]]
            if "group_accepted" in self.faults:
                ends = [{"endpoint": loc, "state": "live", "established": True} for loc in locs]
            else:
                reason = "unreachable" if "group_reason" in self.faults else "multi_link_group"
                ends = [{"endpoint": loc, "state": "refused", "reason": reason} for loc in locs]
            self.status = {"last_write": {"seq": self.seq, "verdict": "replace"}, "endpoints": ends}


class FakeEnv(Env):
    def __init__(self, board: FakeBoard, tmp: Path) -> None:
        self.board = board
        self.console_path = tmp / "console.log"
        self.console_path.write_bytes(board.console())

    def get(self, suffix: str) -> bytes:
        return self.board.get(suffix)

    def put(self, suffix: str, body: bytes) -> None:
        self.board.put(suffix, body)

    def sleep(self, seconds: float) -> None:
        pass

    def dump(self, out: Renderer, routers: bool) -> None:
        out.note("  --- dump\n")


FAST = Timing(ready_tries=3, await_tries=3, group_tries=3)
QZA_ID = "ccbbaa005452"
QZA_READY = r"^ZEPHYR-WZ-ADMIN READY ccbbaa005452 udp/10\.0\.2\.15:7447[[:space:]]*$"
BOARD_NODE = "udp/192.0.2.10:7447"
BOARD_HOST = "192.0.2.1"

# What Layer Qza printed before the steps moved here (a local run of the lane
# on the tree it moved from), byte for byte. The stack line keeps the carriage
# return the Zephyr console ends it with.
EXPECTED_QZA = (
    "  Qza.0 the node's console says who and where it is \u2014 OK\n"
    "  Qza.1 GET before the write: the node reports A only \u2014 OK\n"
    "  Qza.2 PUT connect/endpoints: the node dialled B, GET reports A and B \u2014 OK\n"
    "  Qza.3 GET config names the written list \u2014 OK\n"
    "  Qza.4 every session names its link src/dst; A reached udp/10.0.2.15:7447 \u2014 OK\n"
    "  Qza.5 status/connect: the write was replaced, B is live and established \u2014 OK\n"
    "  Qza.6 a group of two is refused, and status/connect says multi_link_group \u2014 OK\n"
    "  Qza.7 the main stack kept a quarter free: stack: peak 20080 of 32768 bytes\r \u2014 OK\n"
).encode()
# Layer Qa: no READY wait, no stack verdict.
EXPECTED_QA = b"".join(
    ln.replace(b"Qza.", b"Qa.") + b"\n"
    for ln in EXPECTED_QZA.split(b"\n")
    if ln.startswith((b"  Qza.1", b"  Qza.2", b"  Qza.3", b"  Qza.4", b"  Qza.5", b"  Qza.6"))
)

# Each fault, the step it reds, and the line the lane printed for it (the
# lane's own wording; `None` where only the board can show the fault).
B_DIAL_QEMU = "udp/10.0.2.2:17448"
LANE_FAIL = {
    "no_ready": (0, f"  Qza.0 the node never printed its READY line (/{QZA_READY}/)"),
    "extra_before": (
        1,
        "  Qza.1 GET before the write FAIL: sessions [aaaaaaaaaaaaaaaa cccccccccccccccc], want [A]",
    ),
    "never_dials": (2, "  Qza.2 PUT connect/endpoints FAIL: sessions [aaaaaaaaaaaaaaaa], want [A B]"),
    "config_forgets": (3, "  Qza.3 GET config FAIL: the written endpoint is not in it"),
    "link_src": (4, "  Qza.4 link src/dst FAIL: bad=[] accepted_src=udp/10.9.9.9:7447"),
    "link_proto": (
        4,
        "  Qza.4 link src/dst FAIL: bad=[('bbbbbbbbbbbbbbbb', {'src': 'udp/10.0.2.15:40001', "
        "'dst': 'tcp/10.0.2.2:17448'})] accepted_src=udp/10.0.2.15:7447",
    ),
    "status_not_live": (
        5,
        "  Qza.5 status/connect FAIL: {'last_write': {'seq': 1, 'verdict': 'replace'}, "
        "'endpoints': [{'endpoint': 'udp/10.0.2.2:17448', 'state': 'connecting', "
        "'established': False}]}",
    ),
    "status_seq": (
        5,
        "  Qza.5 status/connect FAIL: {'last_write': {'seq': 2, 'verdict': 'replace'}, "
        "'endpoints': [{'endpoint': 'udp/10.0.2.2:17448', 'state': 'live', 'established': True}]}",
    ),
    "group_accepted": (
        6,
        "  Qza.6 status/connect after a group write FAIL: {'last_write': {'seq': 2, 'verdict': "
        "'replace'}, 'endpoints': [{'endpoint': 'udp/10.0.2.2:17448', 'state': 'live', "
        "'established': True}, {'endpoint': 'udp/10.0.2.2:9', 'state': 'live', 'established': True}]}",
    ),
    "group_reason": (
        6,
        "  Qza.6 status/connect after a group write FAIL: {'last_write': {'seq': 2, 'verdict': "
        "'replace'}, 'endpoints': [{'endpoint': 'udp/10.0.2.2:17448', 'state': 'refused', "
        "'reason': 'unreachable'}, {'endpoint': 'udp/10.0.2.2:9', 'state': 'refused', "
        "'reason': 'unreachable'}]}",
    ),
    "stack_deep": (7, "  Qza.7 the main stack FAIL: stack: peak 30000 of 32768 bytes\r leaves under a quarter free"),
    "stack_absent": (7, "  Qza.7 the main stack FAIL: the node printed no `stack: peak N of M bytes` line"),
    "ready_wrong_locator": (0, None),
    "two_boots": (0, None),
}


def _qza_plan(b_port: int = 17448) -> Plan:
    ns = argparse.Namespace(
        label="Qza", node_id=QZA_ID, ready=QZA_READY, stack_verdict=True, fwd_port=17447, b_port=b_port
    )
    return qemu_plan(ns)


def _qa_plan() -> Plan:
    ns = argparse.Namespace(
        label="Qa", node_id="1000055434d7a77", ready="-", stack_verdict=False, fwd_port=17447, b_port=17448
    )
    return qemu_plan(ns)


def _board_plan() -> Plan:
    ns = argparse.Namespace(node=BOARD_NODE, host=BOARD_HOST, b_port=17448)
    return board_plan(ns)


def _fake_run(plan: Plan, faults: tuple[str, ...], tmp: Path) -> tuple[int, bytes, bytes]:
    board = FakeBoard(plan.node_id or "cfacc5282fa", plan.node_listener, plan.b_dial, frozenset(faults))
    out, err = io.BytesIO(), io.BytesIO()
    rc = run_scenario(plan, FakeEnv(board, tmp), FAST, Renderer(plan, out, err))
    return rc, out.getvalue(), err.getvalue()


def _grammar_steps(stdout: bytes) -> dict[int, bool]:
    """Board output -> step -> held, read off its own lines."""
    held = {}
    for ln in stdout.decode().splitlines():
        m = re.fullmatch(r"HW\.(\d+) (.*) - (OK|FAIL)", ln)
        if m:
            held[int(m.group(1))] = m.group(3) == "OK"
    return held


def _lane_failed_steps(stderr: bytes, label: str) -> set[int]:
    return {int(n) for n in re.findall(rf"^  {label}\.(\d+) ".encode(), stderr, re.M)}


def _grammar_templates() -> dict[int, re.Pattern]:
    """HW.0 to HW.7 of the published grammar, `<...>` read as any value."""
    text = GRAMMAR.read_text()
    out = {}
    for m in re.finditer(r"^HW\.([0-7]) (.+)$", text, re.M):
        n = int(m.group(1))
        if n in out:
            continue
        parts = re.split(r"<[^>]+>", m.group(2))
        out[n] = re.compile(".+".join(re.escape(p) for p in parts))
    return out


class _FakeRest(BaseHTTPRequestHandler):
    board: FakeBoard  # set on a subclass per server

    def _send(self, body: bytes) -> None:
        self.send_response(200)
        self.send_header("content-type", "application/json")
        self.send_header("content-length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _suffix(self) -> str:
        prefix = f"/@/{self.board.zid}/peer"
        return self.path[len(prefix):] if self.path.startswith(prefix) else "?"

    def do_GET(self) -> None:
        self._send(self.board.get(self._suffix()))

    def do_PUT(self) -> None:
        body = self.rfile.read(int(self.headers.get("content-length", "0")))
        self.board.put(self._suffix(), body)
        self._send(b"")

    def log_message(self, *args) -> None:
        pass


def _serve(board: FakeBoard) -> ThreadingHTTPServer:
    handler = type("Handler", (_FakeRest,), {"board": board})
    server = ThreadingHTTPServer(("127.0.0.1", 0), handler)  # held for the whole case
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server


def _fake_tools(tmp: Path, console: bytes) -> tuple[Path, Path]:
    """A zenohd that records its arguments and waits, the REST plugin's file
    beside it, and a QEMU that prints the console and waits."""
    bindir = tmp / "bin"
    bindir.mkdir()
    zenohd = bindir / "zenohd"
    zenohd.write_text('#!/bin/sh\nprintf "%s\\n" "$*" >> "$0.argv"\nexec sleep 600\n')
    zenohd.chmod(0o755)
    (bindir / "libzenoh_plugin_rest.so").write_bytes(b"")
    (tmp / "console.bin").write_bytes(console)
    qemu = tmp / "qemu.py"
    qemu.write_text(
        "import sys, time\n"
        f"sys.stdout.buffer.write(open({str(tmp / 'console.bin')!r}, 'rb').read())\n"
        "sys.stdout.flush()\n"
        "time.sleep(600)\n"
    )
    return zenohd, qemu


def _cli(argv: list[str]) -> tuple[int, bytes, bytes]:
    r = subprocess.run(
        [sys.executable, str(Path(__file__).resolve()), *argv],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=120,
    )
    return r.returncode, r.stdout, r.stderr


def selftest() -> int:
    failures: list[str] = []

    def check(name: str, cond: bool, detail: str = "") -> None:
        if not cond:
            failures.append(f"{name}: {detail}" if detail else name)

    with tempfile.TemporaryDirectory() as td:
        tmp = Path(td)
        n = iter(range(10_000))

        def case_dir() -> Path:
            d = tmp / f"c{next(n)}"
            d.mkdir()
            return d

        # 1. A healthy node: the lanes' exact output, and the board's eight lines.
        rc, out, err = _fake_run(_qza_plan(), (), case_dir())
        check("Qza healthy rc", rc == 0, f"rc {rc} err {err!r}")
        check("Qza healthy output is the lane's bytes", out == EXPECTED_QZA, f"{out!r}")
        check("Qza healthy writes nothing to stderr", err == b"", f"{err!r}")
        rc, out, err = _fake_run(_qa_plan(), (), case_dir())
        check("Qa healthy output is the lane's bytes", rc == 0 and out == EXPECTED_QA and err == b"", f"{out!r}")
        rc, board_out, err = _fake_run(_board_plan(), (), case_dir())
        check("board healthy rc", rc == 0 and err == b"", f"rc {rc} err {err!r}")
        steps = _grammar_steps(board_out)
        check("board healthy prints HW.0 to HW.7, all OK", steps == {i: True for i in range(8)}, f"{board_out!r}")
        check(
            "board output is only step lines",
            all(ln.startswith("HW.") for ln in board_out.decode().splitlines()),
            f"{board_out!r}",
        )
        check(
            "board HW.0 quotes the READY line and HW.7 the stack line, no carriage return",
            b"HW.0 the node's console says who and where it is: READY cfacc5282fa udp/192.0.2.10:7447 - OK\n"
            in board_out
            and b"HW.7 the main stack kept a quarter free: stack: peak 20080 of 32768 bytes - OK\n" in board_out,
            f"{board_out!r}",
        )

        # 2. Every board sentence is an instance of the published grammar.
        templates = _grammar_templates()
        check("the grammar publishes HW.0 to HW.7", sorted(templates) == list(range(8)), f"{sorted(templates)}")
        for ln in board_out.decode().splitlines():
            m = re.fullmatch(r"HW\.(\d) (.*) - OK", ln)
            if m and int(m.group(1)) in templates:
                check(
                    f"HW.{m.group(1)} is the grammar's sentence",
                    bool(templates[int(m.group(1))].fullmatch(m.group(2))),
                    ln,
                )

        # 3. The record's reader reads the output as the steps it printed.
        sys.path.insert(0, str(Path(__file__).resolve().parent))
        try:
            import zephyr_board_table_gate as gate
        finally:
            sys.path.pop(0)
        for joiner in ("\n", " "):
            entry = {"verification_bullets": ["THE VERDICT. " + joiner.join(board_out.decode().splitlines())]}
            held = gate.step_verdicts(json.dumps(entry))
            check(
                f"the gate reads the pasted output (joined by {joiner!r}) as HW.0 to HW.7 held",
                held == {str(i): True for i in range(8)},
                f"{held}",
            )
        _, red_out, _ = _fake_run(_board_plan(), ("config_forgets",), case_dir())
        held = gate.step_verdicts(json.dumps({"v": [" ".join(red_out.decode().splitlines())]}))
        check("the gate reads a pasted FAIL as not held", held.get("3") is False, f"{held}")

        # 4. Each fault reds its step and no other; the lane prints its line.
        for fault, (step, lane_line) in LANE_FAIL.items():
            if lane_line is not None:
                rc, out, err = _fake_run(_qza_plan(), (fault,), case_dir())
                red = _lane_failed_steps(err, "Qza")
                check(f"lane {fault}: rc 1", rc == 1, f"rc {rc}")
                check(f"lane {fault}: only Qza.{step} is red", red == {step}, f"{red} {err!r}")
                check(
                    f"lane {fault}: the lane's own FAIL line",
                    (lane_line + "\n").encode() in err,
                    f"{err!r}",
                )
                ok_steps = {int(x) for x in re.findall(rb"^  Qza\.(\d+) .* \xe2\x80\x94 OK$", out, re.M)}
                want_ok = set(range(8)) - {step} - (set(range(2, 7)) if step == 1 else set())
                if step == 0:
                    want_ok = set()
                check(f"lane {fault}: the other steps held", ok_steps == want_ok, f"{ok_steps} {out!r}")
            rc, out, err = _fake_run(_board_plan(), (fault,), case_dir())
            steps = _grammar_steps(out)
            red = {k for k, v in steps.items() if not v}
            want_red = {step}
            if step == 0:
                want_red = set(range(8))
            elif step == 1:
                want_red = set(range(1, 7))
            check(f"board {fault}: rc 1 and every step printed", rc == 1 and sorted(steps) == list(range(8)), f"{out!r}")
            check(f"board {fault}: red steps {sorted(want_red)}", red == want_red, f"{red} {out!r}")
            check(
                f"board {fault}: no stderr line names a step",
                not re.search(rb"HW\.\d+ ", err),
                f"{err!r}",
            )

        # 5. The red-first pairs: weaken one step's comparison and its fault
        #    case goes green there. A fault that stays red without its
        #    comparison was red for some other reason and proves nothing.
        weak_cases = {
            0: [("lane", "no_ready"), ("board", "ready_wrong_locator"), ("board", "two_boots")],
            1: [("lane", "extra_before")],
            2: [("lane", "never_dials")],
            3: [("lane", "config_forgets")],
            4: [("lane", "link_src"), ("lane", "link_proto")],
            5: [("lane", "status_not_live"), ("lane", "status_seq")],
            6: [("lane", "group_accepted"), ("lane", "group_reason")],
            7: [("lane", "stack_deep")],
        }
        covered = {f for cases in weak_cases.values() for _, f in cases}
        check(
            "every fault has a weakening pair (or is a missing observation)",
            covered | {"stack_absent"} == set(FAULTS_ALL) == set(LANE_FAIL),
            f"{sorted(set(FAULTS_ALL) ^ (covered | {'stack_absent'}))}",
        )
        for step, cases in weak_cases.items():
            saved = JUDGES[step]
            JUDGES[step] = lambda *a: True
            try:
                for where, fault in cases:
                    plan = _qza_plan() if where == "lane" else _board_plan()
                    rc, out, err = _fake_run(plan, (fault,), case_dir())
                    if where == "lane":
                        green = step not in _lane_failed_steps(err, "Qza")
                    else:
                        green = _grammar_steps(out).get(step) is True
                    check(f"weakened step {step}: {where} {fault} goes green there", green, f"{out!r} {err!r}")
            finally:
                JUDGES[step] = saved

        # 6. End to end: the program as the lanes call it, with a fake QEMU
        #    and a fake zenohd, the REST plugin served by a fake node.
        for faults in ((), ("config_forgets",)):
            d = case_dir()
            board = FakeBoard(QZA_ID, f"udp/{QEMU_GUEST}:7447", B_DIAL_QEMU, frozenset(faults))
            zenohd, qemu = _fake_tools(d, board.console())
            server = _serve(board)
            try:
                rc, out, err = _cli(
                    [
                        "qemu", "--label", "Qza", "--node-id", QZA_ID, "--ready", QZA_READY,
                        "--stack-verdict", "--zenohd", str(zenohd), "--fwd-port", "17447",
                        "--b-port", "17448", "--rest-port", str(server.server_address[1]), "--",
                        sys.executable, str(qemu),
                        "-nic", "user,model=lan9118,hostfwd=udp:127.0.0.1:17447-10.0.2.15:7447",
                    ]
                )
            finally:
                server.shutdown()
                server.server_close()
            argv = (d / "bin" / "zenohd.argv").read_text().splitlines()
            check(
                f"cli qemu {faults}: the routers' arguments are the lanes'",
                sorted(argv)
                == sorted(
                    [
                        '--no-multicast-scouting -l udp/127.0.0.1:17448 --cfg=id:"bbbbbbbbbbbbbbbb"',
                        "--no-multicast-scouting -e udp/127.0.0.1:17447 --rest-http-port "
                        f"127.0.0.1:{server.server_address[1]} --plugin-search-dir {d / 'bin'} "
                        '--cfg=id:"aaaaaaaaaaaaaaaa"',
                    ]
                ),
                f"{argv}",
            )
            if not faults:
                check("cli qemu healthy: the lane's bytes", rc == 0 and out == EXPECTED_QZA and err == b"",
                      f"rc {rc} {out!r} {err!r}")
            else:
                want = EXPECTED_QZA.replace(b"  Qza.3 GET config names the written list \xe2\x80\x94 OK\n", b"")
                want_err = (
                    b"  Qza.3 GET config FAIL: the written endpoint is not in it\n"
                    b"  --- qemu\n" + board.console() + b"  --- zenohd A (tail)\n  --- zenohd B (tail)\n"
                )
                check("cli qemu config fault: rc 1, the other lines", rc == 1 and out == want, f"rc {rc} {out!r}")
                check("cli qemu config fault: the lane's FAIL line and dumps", err == want_err, f"{err!r}")

        d = case_dir()
        board = FakeBoard("cfacc5282fa", BOARD_NODE, f"udp/{BOARD_HOST}:17448")
        zenohd, _ = _fake_tools(d, b"")
        capture = d / "capture.log"
        capture.write_bytes(board.console())
        server = _serve(board)
        try:
            rc, out, err = _cli(
                [
                    "board", "--node", BOARD_NODE, "--host", BOARD_HOST, "--console", str(capture),
                    "--zenohd", str(zenohd), "--rest-port", str(server.server_address[1]),
                ]
            )
        finally:
            server.shutdown()
            server.server_close()
        check("cli board healthy: the eight lines", rc == 0 and out == board_out and err == b"",
              f"rc {rc} {out!r} {err!r}")
        argv = (d / "bin" / "zenohd.argv").read_text().splitlines()
        check(
            "cli board: B on the host's address only, A with no listener",
            sorted(argv)
            == sorted(
                [
                    f'--no-multicast-scouting -l udp/{BOARD_HOST}:17448 --cfg=id:"bbbbbbbbbbbbbbbb"',
                    f"--no-multicast-scouting -e {BOARD_NODE} --rest-http-port "
                    f"127.0.0.1:{server.server_address[1]} --plugin-search-dir {d / 'bin'} "
                    '--cfg=id:"aaaaaaaaaaaaaaaa" --cfg=listen/endpoints:[]',
                ]
            ),
            f"{argv}",
        )

        # 7. What it refuses to run on.
        rc, _, err = _cli(["qemu", "--label", "X", "--node-id", "1", "--ready", "-", "--fwd-port", "1",
                           "--b-port", "2", "--rest-port", "3", "--", "true"])
        check("a QEMU command without the forward is refused", rc == 2 and b"hostfwd" in err, f"{rc} {err!r}")
        rc, _, err = _cli(["board", "--node", "udp/192.0.2.10", "--host", "h", "--console", str(capture),
                           "--zenohd", str(zenohd)])
        check("a locator without a port is refused", rc == 2, f"{rc} {err!r}")
        (d / "bin" / "libzenoh_plugin_rest.so").unlink()
        rc, _, err = _cli(["board", "--node", BOARD_NODE, "--host", "h", "--console", str(capture),
                           "--zenohd", str(zenohd)])
        check("a zenohd without the REST plugin is refused", rc == 2 and b"REST plugin" in err, f"{rc} {err!r}")

    for f in failures:
        print(f"admin_node_verdict selftest FAIL: {f}", file=sys.stderr)
    if failures:
        return 1
    print("admin_node_verdict selftest: OK")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
