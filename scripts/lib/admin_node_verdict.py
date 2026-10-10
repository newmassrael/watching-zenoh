#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
# SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
"""R3215 (no register item) -- the admin node's verdict, run by ONE program
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

## The transmit pool image: HW.26 to HW.30

These steps read files the run leaves behind, so they are judged once it is
over, by a second call of the same mode:

  1. Start the console capture as above, and a capture of the node's frames on
     the host's adapter, both from before the reset:

       tcpdump -i <the adapter> -U -s 0 -w <capture.pcap> host <node address>

     A classic pcap with every frame whole: a frame captured short fails HW.30.
  2. Reset the board and run the board mode as above, with its standard output
     saved to a file: those are the eight onboard lines on this image.
  3. Hold a session with the node for at least 30 seconds (a stock router with
     A's settings), so that the counts lines record frames the pool sent.
  4. Stop both captures, then:

       python3 scripts/lib/admin_node_verdict.py board --pool-image \\
           --node udp/<node address>:7447 \\
           --console <the capture file> \\
           --onboard <the file the output of 2 went to> \\
           --pcap <capture.pcap>

     It prints HW.26 to HW.30, one line each, on standard output and nothing
     else there. Standard error carries one line of counts for the console and
     one for the capture (frames, datagrams from the node and the seconds they
     span, each kind of failure), then why a step failed and which frames did,
     on lines that name no step. The exit codes are the board mode's; a file
     that is not a classic pcap of Ethernet frames is exit 2. The router
     options (--host, --zenohd, the ports) are refused: no router is started.

The routers it starts are those of "What the host runs" in the grammar file. B
listens on `udp/<host>:<b-port>` and nothing else; A dials `--node`, holds no
listener of its own (`listen/endpoints` empty) and carries the REST plugin on
127.0.0.1 only; both have multicast scouting off and fixed ids (sixteen `a`,
sixteen `b`). In qemu mode A keeps zenohd's default listener, as the emulator
lanes always ran it: on the loopback-only QEMU topology it reaches nothing the
node could report.

## What this cannot settle

The steps of the second interface (HW.8 to HW.25) read instruments, segment
captures and a cable pull; none of them is here. HW.16 to HW.20 are HW.1 to
HW.5 with other routers and could be added as a third address book.
Whether a board passes is settled only by running this against a board.

Of the pool steps: HW.26 cannot ask the REST plugin again, so for HW.1 to HW.6
it rests on the board run's output, bound to the boot by the READY line the
capture holds (the node draws its id at each boot). The 30 seconds of the hold
are the lab's; the program does not time them, and prints the span of the
node's datagrams in the capture for the record. HW.30 checks checksums and
nothing of zenoh: the stock router's decoding is HW.2 and HW.5.

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

For the pool steps it builds consoles, board-run outputs and pcap files (both
byte orders) in the test. A healthy set holds all five; each fault reds the
steps that read it and no other (a missing pool line reds HW.27 and HW.28, a
console with no counts line HW.28 and HW.29, since both read them; a capture
with no datagram from the node is red). Each clause of `POOL_CLAUSES` is
dropped in turn and the fault it exists for goes green; the step 0 and step 7
comparisons are weakened and HW.26's faults for them go green, which shows
HW.26 runs them; and mutants of the capture reader (no header checksum, no
pseudo header, a zero checksum taken as valid, every source counted, one byte
order only) are each caught by some case. The two console regexes and the five
sentences are held to the grammar file, the pool output is handed to the
record's reader as above, and the CLI is run end to end on files.
"""

from __future__ import annotations

import argparse
import io
import json
import os
import re
import shutil
import signal
import struct
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


def ready_lines(raw: bytes) -> list[str]:
    """The console's READY lines, trailing white space (the carriage return) cut."""
    return [ln.rstrip() for ln in console_lines(raw) if READY_LINE.fullmatch(ln.rstrip())]


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
        return ready_lines(raw)

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


# ------------------------------------------------- the transmit pool image --
#
# HW.26 to HW.30, read from three files the lab keeps once the run is over: the
# console capture of the boot, the board run's own standard output (HW.0 to HW.7
# printed on this image) and a packet capture of the node's frames. Nothing is
# reached on the network. Each step is a list of clauses; it holds when every
# clause does, and the selftest drops each clause in turn to show the fault it
# exists for goes green without it.
#
#   26  the board run's output is the eight onboard lines in order, each OK
#       ("lines"); the capture holds one READY line, its first locator the node
#       (the step 0 comparison, `JUDGES[0]`: "ready"); the output is THIS boot's,
#       because its sentences are the ones this program prints for this capture
#       (its READY line, the node's locator, one of its stack lines:
#       "sentences"); and the boot as a whole kept a quarter of its stack free
#       (the step 7 comparison on the capture's last stack line: "stack"). The
#       steps HW.1 to HW.6 asked the REST plugin, which no file can answer
#       again; what binds their sentences to this boot is the READY line, whose
#       id the node draws at each boot.
#   27  one pool line (one boot prints one); its slots span 8 times 1536 bytes;
#       start and end lie inside the section, an end being one past the last
#       byte as the firmware prints both.
#   28  the last counts line has in place and started above zero, and its last
#       descriptor lies at or after the pool's start and before its end.
#   29  EVERY counts line is read (a line that holds the prefix and is not the
#       grammar's line is a failure, not a line skipped), there is at least one
#       (an empty population is not a verdict), and each keeps both identities;
#       a negative started minus completed is a lost slot too.
#   30  every UDP datagram from the node's address has a valid IPv4 header
#       checksum and a valid UDP checksum over the pseudo header. A zero UDP
#       checksum is a failure: IPv4 lets a sender omit it, and this node's lwIP
#       generates one in software, which is what makes the step a witness of the
#       bytes the controller read. A fragment, a datagram whose lengths
#       disagree, and a frame captured short are failures, because their
#       checksums cannot be checked from the frame; a capture with no datagram
#       from the node fails, not passes.

POOL_SLOTS = 8
SLOT_BYTES = 1536
# The frames the MAC's transmit ring can hold: the most a pool can have started
# and not yet seen completed.
RING_FRAMES = 4
POOL_PREFIX = "wz: eth0: transmit pool"
COUNTS_PREFIX = "wz: tx-pool:"
# The grammar's two console regexes, character for character; the selftest holds
# them to the file.
POOL_LINE = re.compile(
    r"^wz: eth0: transmit pool of 8 slots at (0x[0-9a-f]{8}) to (0x[0-9a-f]{8}), "
    r"in the non-cacheable section (0x[0-9a-f]{8}) to (0x[0-9a-f]{8}), read in place by the MAC$"
)
COUNTS_LINE = re.compile(
    r"^wz: tx-pool: in place ([0-9]+), copied ([0-9]+), last descriptor (0x[0-9a-f]{8}|none); "
    r"pool lent ([0-9]+), started ([0-9]+), completed ([0-9]+), unarmed ([0-9]+), "
    r"abandoned ([0-9]+), free ([0-9]+) of 8$"
)
POOL_STEPS = (26, 27, 28, 29, 30)
# Each step's sentence up to its first colon; HW.27, HW.28 and HW.30 add the
# values they read.
POOL_HEADS = {
    26: "the onboard verdict held on the transmit pool image: its eight onboard sentences "
    "each ended OK on this image",
    27: "the pool sits where the MAC reads it uncached",
    28: "a frame left from a pool slot read in place",
    29: "every slot came home: on every counts line lent minus abandoned, completed and "
    "unarmed is 8 minus free, and started minus completed is at most 4",
    30: "the frames read out of slots were right on the wire",
}
STEP_OUT = re.compile(r"HW\.(\d+) (.*) - (OK|FAIL)")
IPV4_OCTET = r"(?:25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])"
IPV4_LOCATOR = re.compile(rf"udp/({IPV4_OCTET}(?:\.{IPV4_OCTET}){{3}}):[0-9]+")


@dataclass(frozen=True)
class PoolPlace:
    start: int
    end: int
    section_start: int
    section_end: int


@dataclass(frozen=True)
class TxCounts:
    line: int  # the console line it is on, counted from 1
    in_place: int
    copied: int
    last_descriptor: int | None
    lent: int
    started: int
    completed: int
    unarmed: int
    abandoned: int
    free: int


@dataclass(frozen=True)
class PoolConsole:
    places: tuple[PoolPlace, ...]
    counts: tuple[TxCounts, ...]
    # (line number, text) of a line that holds a pool or counts prefix and is
    # not the grammar's line: a garbled line is not one to skip.
    unread: tuple[tuple[int, str], ...]

    def unread_with(self, prefix: str) -> list[tuple[int, str]]:
        return [u for u in self.unread if prefix in u[1]]


def read_pool_console(raw: bytes) -> PoolConsole:
    places: list[PoolPlace] = []
    counts: list[TxCounts] = []
    unread: list[tuple[int, str]] = []
    for number, line in enumerate(console_lines(raw), 1):
        line = line.rstrip("\r")
        m = POOL_LINE.fullmatch(line)
        if m:
            places.append(PoolPlace(*(int(g, 16) for g in m.groups())))
            continue
        m = COUNTS_LINE.fullmatch(line)
        if m:
            g = m.groups()
            desc = None if g[2] == "none" else int(g[2], 16)
            counts.append(TxCounts(number, int(g[0]), int(g[1]), desc, *(int(x) for x in g[3:])))
            continue
        if POOL_PREFIX in line or COUNTS_PREFIX in line:
            unread.append((number, line))
    return PoolConsole(tuple(places), tuple(counts), tuple(unread))


@dataclass(frozen=True)
class OnboardRecord:
    """The board run's output beside the capture of the boot it ran against."""

    lines: tuple[str, ...]  # the output, line by line
    ready: tuple[str, ...]  # the capture's READY lines
    stacks: tuple[str, ...]  # the capture's stack lines, carriage return cut
    plan: Plan


def output_lines(raw: bytes) -> list[str]:
    lines = raw.decode("utf-8", "surrogateescape").split("\n")
    if lines and lines[-1] == "":
        lines.pop()
    return lines


def onboard_record(console_raw: bytes, output_raw: bytes, plan: Plan) -> OnboardRecord:
    stacks = [ln.rstrip() for ln in console_lines(console_raw) if ln.startswith(STACK_PREFIX)]
    return OnboardRecord(
        tuple(output_lines(output_raw)), tuple(ready_lines(console_raw)), tuple(stacks), plan
    )


def _onboard_bodies(rec: OnboardRecord) -> dict[int, str]:
    got: dict[int, str] = {}
    for ln in rec.lines:
        m = STEP_OUT.fullmatch(ln)
        if m:
            got.setdefault(int(m.group(1)), m.group(2))
    return got


def _onboard_wanted(rec: OnboardRecord) -> dict[int, set[str]]:
    """The sentence bodies this program prints for this capture."""
    plain = _plain_sentences(rec.plan)
    wanted = {n: {plain[n]} for n in range(1, LAST_STEP)}
    if rec.ready:
        wanted[0] = {f"{plain[0]}: {rec.ready[0][len(READY_PREFIX):]}"}
    else:
        wanted[0] = set()
    wanted[LAST_STEP] = {f"{STACK_SENTENCE}: {s}" for s in rec.stacks}
    return wanted


def _onboard_lines_hold(rec: OnboardRecord) -> bool:
    found = [STEP_OUT.fullmatch(ln) for ln in rec.lines]
    return (
        all(found)
        and [int(m.group(1)) for m in found] == list(range(LAST_STEP + 1))
        and all(m.group(3) == "OK" for m in found)
    )


def _onboard_lines_why(rec: OnboardRecord) -> str:
    for i, ln in enumerate(rec.lines):
        m = STEP_OUT.fullmatch(ln)
        if m is None:
            return f"line {i + 1} of the board run's output is not a step's line"
        if int(m.group(1)) != i:
            return f"line {i + 1} of the board run's output is step {m.group(1)}, where step {i} belongs"
        if m.group(3) != "OK":
            return f"step {i} of the board run's output ends FAIL"
    return (
        f"the board run's output holds {len(rec.lines)} lines, not the {LAST_STEP + 1} onboard steps"
    )


def _onboard_sentences_hold(rec: OnboardRecord) -> bool:
    got, wanted = _onboard_bodies(rec), _onboard_wanted(rec)
    return all(got.get(n) in wanted[n] for n in range(LAST_STEP + 1))


def _onboard_sentences_why(rec: OnboardRecord) -> str:
    got, wanted = _onboard_bodies(rec), _onboard_wanted(rec)
    off = [str(n) for n in range(LAST_STEP + 1) if got.get(n) not in wanted[n]]
    return (
        f"the board run's output is not of this capture's boot at step(s) {', '.join(off)}: "
        f"its sentences must quote this capture's READY line, the node {rec.plan.node_listener} "
        f"and one of this capture's stack lines"
    )


def _ready_why(rec: OnboardRecord) -> str:
    if not rec.ready:
        return f"the console capture holds no `{READY_PREFIX}READY` line"
    if len(rec.ready) > 1:
        return (
            f"the console capture holds {len(rec.ready)} READY lines, so it spans more than one "
            f"boot: capture one boot, from before its reset"
        )
    return f"the capture's READY line `{rec.ready[0]}` does not name {rec.plan.node_listener} first"


def _stack_holds(rec: OnboardRecord) -> bool:
    m = STACK_LINE.fullmatch(rec.stacks[-1])
    return m is not None and judge(LAST_STEP, int(m.group(1)), int(m.group(2)), rec.plan)


def _stack_why(rec: OnboardRecord) -> str:
    if not rec.stacks:
        return "the console capture holds no `stack: peak N of M bytes` line"
    return f"the capture's last stack line `{rec.stacks[-1]}` leaves under a quarter free"


def _place(console: PoolConsole) -> PoolPlace:
    return console.places[0]


def _place_text(p: PoolPlace) -> str:
    return (
        f"slots {p.start:#010x} to {p.end:#010x} inside the non-cacheable section "
        f"{p.section_start:#010x} to {p.section_end:#010x}"
    )


def _last(console: PoolConsole) -> TxCounts:
    return console.counts[-1]


def _descriptor_text(c: TxCounts) -> str:
    return "none" if c.last_descriptor is None else f"{c.last_descriptor:#010x}"


def _unread_text(lines: list[tuple[int, str]]) -> str:
    return "; ".join(f"console line {n} `{t}` is not the grammar's line" for n, t in lines)


def _identity_breaks(console: PoolConsole) -> list[TxCounts]:
    return [
        c
        for c in console.counts
        if c.lent - c.abandoned - c.completed - c.unarmed != POOL_SLOTS - c.free
    ]


def _in_flight_breaks(console: PoolConsole) -> list[TxCounts]:
    return [c for c in console.counts if not 0 <= c.started - c.completed <= RING_FRAMES]


@dataclass
class CaptureReport:
    """What a packet capture holds of the node's IPv4 traffic."""

    node: str
    frames: int = 0
    node_udp: int = 0  # UDP datagrams from the node, whether or not they could be checked
    good: int = 0  # of those, the ones whose two checksums were checked and valid
    bad_ipv4: int = 0
    bad_udp: int = 0
    zero_udp: int = 0
    fragments: int = 0
    malformed: int = 0
    truncated: int = 0
    first: float | None = None
    last: float | None = None
    findings: list[str] = field(default_factory=list)

    def seen(self, when: float) -> None:
        self.first = when if self.first is None else min(self.first, when)
        self.last = when if self.last is None else max(self.last, when)

    def span(self) -> float:
        return 0.0 if self.first is None or self.last is None else self.last - self.first


@dataclass(frozen=True)
class Clause:
    name: str
    holds: Callable[[object], bool]
    why: Callable[[object], str]


POOL_CLAUSES: dict[int, list[Clause]] = {
    26: [
        Clause("lines", _onboard_lines_hold, _onboard_lines_why),
        Clause("ready", lambda rec: judge(0, list(rec.ready), rec.plan), _ready_why),
        Clause("sentences", _onboard_sentences_hold, _onboard_sentences_why),
        Clause("stack", _stack_holds, _stack_why),
    ],
    27: [
        Clause(
            "one line",
            lambda con: len(con.places) == 1 and not con.unread_with(POOL_PREFIX),
            lambda con: _unread_text(con.unread_with(POOL_PREFIX))
            or f"the console holds {len(con.places)} pool lines, where one boot prints one",
        ),
        Clause(
            "size",
            lambda con: _place(con).end - _place(con).start == POOL_SLOTS * SLOT_BYTES,
            lambda con: f"the slots span {_place(con).end - _place(con).start} bytes, not "
            f"{POOL_SLOTS} times {SLOT_BYTES}",
        ),
        Clause(
            "inside",
            lambda con: _place(con).section_start
            <= _place(con).start
            < _place(con).end
            <= _place(con).section_end,
            lambda con: f"the pool is not inside the section: {_place_text(_place(con))}",
        ),
    ],
    28: [
        Clause(
            "above zero",
            lambda con: _last(con).in_place > 0 and _last(con).started > 0,
            lambda con: "the console holds no counts line"
            if not con.counts
            else f"the last counts line (console line {_last(con).line}) has in place "
            f"{_last(con).in_place} and started {_last(con).started}: the pool was not exercised",
        ),
        Clause(
            "descriptor",
            lambda con: len(con.places) == 1
            and _last(con).last_descriptor is not None
            and _place(con).start <= _last(con).last_descriptor < _place(con).end,
            lambda con: "no counts line names a descriptor"
            if not con.counts
            else "there is no one pool line to place the last descriptor against"
            if len(con.places) != 1
            else f"the last descriptor {_descriptor_text(_last(con))} is not inside the pool "
            f"{_place(con).start:#010x} to {_place(con).end:#010x}",
        ),
    ],
    29: [
        Clause(
            "every line read",
            lambda con: bool(con.counts) and not con.unread_with(COUNTS_PREFIX),
            lambda con: _unread_text(con.unread_with(COUNTS_PREFIX))
            or "the console holds no counts line, and a step on every line of none is no verdict",
        ),
        Clause(
            "identity",
            lambda con: not _identity_breaks(con),
            lambda con: "; ".join(
                f"console line {c.line}: lent {c.lent} minus abandoned {c.abandoned}, completed "
                f"{c.completed} and unarmed {c.unarmed} is "
                f"{c.lent - c.abandoned - c.completed - c.unarmed}, 8 minus free is {POOL_SLOTS - c.free}"
                for c in _identity_breaks(con)
            ),
        ),
        Clause(
            "in flight",
            lambda con: not _in_flight_breaks(con),
            lambda con: "; ".join(
                f"console line {c.line}: started {c.started} minus completed {c.completed} is "
                f"{c.started - c.completed}, outside 0 to {RING_FRAMES}"
                for c in _in_flight_breaks(con)
            ),
        ),
    ],
    30: [
        Clause(
            "population",
            lambda r: r.node_udp > 0,
            lambda r: f"the capture holds no UDP datagram from {r.node}: a capture of nothing is "
            f"not a verdict",
        ),
        Clause("ipv4", lambda r: r.bad_ipv4 == 0,
               lambda r: f"{r.bad_ipv4} IPv4 packet(s) from the node have a bad header checksum"),
        Clause("udp", lambda r: r.bad_udp == 0,
               lambda r: f"{r.bad_udp} datagram(s) from the node have a bad UDP checksum"),
        Clause("zero", lambda r: r.zero_udp == 0,
               lambda r: f"{r.zero_udp} datagram(s) from the node carry no UDP checksum (zero)"),
        Clause("fragments", lambda r: r.fragments == 0,
               lambda r: f"{r.fragments} datagram(s) from the node are fragments, whose UDP "
               f"checksum one frame cannot check"),
        Clause("malformed", lambda r: r.malformed == 0,
               lambda r: f"{r.malformed} frame(s) are IPv4 whose lengths or version do not read"),
        Clause("truncated", lambda r: r.truncated == 0,
               lambda r: f"{r.truncated} frame(s) were captured short (capture with a snapshot "
               f"length of 0, and stop the capture before reading it)"),
    ],
}


def clause_failures(step: int, obs: object) -> list[str]:
    """Why each clause of `step` that does not hold fails; empty when it holds.
    A clause that raises on a missing observation has not held."""
    out = []
    for clause in POOL_CLAUSES[step]:
        try:
            held = bool(clause.holds(obs))
        except (KeyError, IndexError, TypeError, AttributeError, ValueError):
            held = False
        if not held:
            try:
                out.append(clause.why(obs))
            except (KeyError, IndexError, TypeError, AttributeError, ValueError):
                out.append(f"{clause.name} does not hold")
    return out


def pool_sentence(step: int, obs: object) -> str:
    head = POOL_HEADS[step]
    if step == 27 and obs.places:
        return f"{head}: {_place_text(obs.places[0])}"
    if step == 28 and obs.counts:
        c = obs.counts[-1]
        return (
            f"{head}: in place {c.in_place} and started {c.started} above zero, "
            f"last descriptor {_descriptor_text(c)} inside the pool"
        )
    if step == 30:
        return (
            f"{head}: {obs.good} of {obs.node_udp} datagrams from the node in the capture "
            f"had valid IPv4 and UDP checksums"
        )
    return head


# ----------------------------------------------------------- the capture --
#
# A classic pcap file (either byte order, microsecond or nanosecond stamps) of
# Ethernet II frames, an 802.1Q tag allowed. pcapng is refused by name.


class CaptureError(ValueError):
    """The file is not a capture this program reads; nothing was judged."""


def inet_sum(data: bytes) -> int:
    """The ones' complement sum of 16-bit words, folded; 0xffff over a span
    that carries its own valid checksum."""
    if len(data) % 2:
        data += b"\x00"
    total = sum(struct.unpack(f"!{len(data) // 2}H", data))
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return total


def ipv4_header_ok(header: bytes) -> bool:
    return inet_sum(header) == 0xFFFF


def udp_checksum_verdict(ip: bytes, datagram: bytes) -> str:
    """'ok', 'bad', or 'zero' (sent with no checksum)."""
    if datagram[6:8] == b"\x00\x00":
        return "zero"
    pseudo = ip[12:20] + struct.pack("!BBH", 0, 17, len(datagram))
    return "ok" if inet_sum(pseudo + datagram) == 0xFFFF else "bad"


def from_node(ip: bytes, node: bytes) -> bool:
    return ip[12:16] == node


def pcap_byte_order(raw: bytes) -> tuple[str, float]:
    """The file's byte order as `struct` spells it, and its stamp's fraction unit."""
    if len(raw) < 24:
        raise CaptureError("it is shorter than a pcap file header")
    for order in ("<", ">"):
        magic = struct.unpack_from(order + "I", raw, 0)[0]
        if magic == 0xA1B2C3D4:
            return order, 1e-6
        if magic == 0xA1B23C4D:
            return order, 1e-9
    if raw[:4] == b"\x0a\x0d\x0d\x0a":
        raise CaptureError("it is pcapng; write the capture as a classic pcap (tcpdump -w does)")
    raise CaptureError(f"it is not a pcap file (it opens {raw[:4].hex()})")


def _ipv4_of(frame: bytes) -> bytes | None:
    """The IPv4 packet an Ethernet II frame carries, or None."""
    if len(frame) < 14:
        return None
    kind, l3 = struct.unpack_from("!H", frame, 12)[0], 14
    if kind == 0x8100 and len(frame) >= 18:
        kind, l3 = struct.unpack_from("!H", frame, 16)[0], 18
    return frame[l3:] if kind == 0x0800 else None


def analyse_capture(raw: bytes, node_address: str) -> CaptureReport:
    order, unit = pcap_byte_order(raw)
    link = struct.unpack_from(order + "I", raw, 20)[0] & 0xFFFF
    if link != 1:
        raise CaptureError(f"its link type is {link}, not Ethernet (1)")
    node = bytes(int(x) for x in node_address.split("."))
    r = CaptureReport(node_address)
    off = 24
    while off < len(raw):
        if off + 16 > len(raw):
            r.truncated += 1
            r.findings.append("the file ends inside a record's header")
            break
        sec, frac, incl, orig = struct.unpack_from(order + "IIII", raw, off)
        off += 16
        if off + incl > len(raw):
            r.truncated += 1
            r.findings.append(f"the file ends inside frame {r.frames + 1}")
            break
        frame = raw[off : off + incl]
        off += incl
        r.frames += 1
        n, when = r.frames, sec + frac * unit
        ip = _ipv4_of(frame)
        if incl < orig:
            r.truncated += 1
            r.findings.append(f"frame {n} was captured {incl} of {orig} bytes")
            if ip is not None and len(ip) >= 20 and from_node(ip, node):
                r.seen(when)
                r.node_udp += ip[9] == 17
            continue
        if ip is None:
            if len(frame) < 14:
                r.malformed += 1
                r.findings.append(f"frame {n} is {len(frame)} bytes, shorter than an Ethernet header")
            continue
        if len(ip) < 20:
            r.malformed += 1
            r.findings.append(f"frame {n} carries an IPv4 packet shorter than its header")
            continue
        if not from_node(ip, node):
            continue
        r.seen(when)
        udp = ip[9] == 17
        r.node_udp += udp
        ihl = (ip[0] & 0x0F) * 4
        total = struct.unpack_from("!H", ip, 2)[0]
        if ip[0] >> 4 != 4 or ihl < 20 or not ihl <= total <= len(ip):
            r.malformed += 1
            r.findings.append(f"frame {n}: version {ip[0] >> 4}, header {ihl} bytes, total length {total}")
            continue
        ip_ok = ipv4_header_ok(ip[:ihl])
        if not ip_ok:
            r.bad_ipv4 += 1
            r.findings.append(f"frame {n}: the IPv4 header checksum is wrong")
        if not udp:
            continue
        if struct.unpack_from("!H", ip, 6)[0] & 0x3FFF:
            r.fragments += 1
            r.findings.append(f"frame {n} is a fragment")
            continue
        datagram = ip[ihl:total]
        if len(datagram) < 8 or struct.unpack_from("!H", datagram, 4)[0] != len(datagram):
            r.malformed += 1
            r.findings.append(f"frame {n}: the UDP length does not match the IPv4 payload")
            continue
        verdict = udp_checksum_verdict(ip, datagram)
        if verdict == "zero":
            r.zero_udp += 1
            r.findings.append(f"frame {n}: the UDP checksum is zero")
        elif verdict == "bad":
            r.bad_udp += 1
            r.findings.append(f"frame {n}: the UDP checksum is wrong")
        r.good += ip_ok and verdict == "ok"
    return r


def console_summary(console: PoolConsole, rec: OnboardRecord) -> str:
    return (
        f"  console: {len(rec.ready)} READY line(s), {len(console.places)} pool line(s), "
        f"{len(console.counts)} counts line(s), {len(console.unread)} unread, "
        f"{len(rec.stacks)} stack line(s)\n"
    )


def capture_summary(r: CaptureReport) -> str:
    return (
        f"  capture: {r.frames} frames; {r.node_udp} UDP datagrams from {r.node} over "
        f"{r.span():.1f} s, {r.good} with both checksums valid; {r.bad_ipv4} bad IPv4 header "
        f"checksums, {r.bad_udp} bad UDP checksums, {r.zero_udp} zero UDP checksums, "
        f"{r.fragments} fragments, {r.malformed} malformed, {r.truncated} truncated\n"
    )


# The findings a failing capture prints, at most.
FINDINGS_SHOWN = 10


def pool_plan(node: str) -> Plan:
    """The pool steps reach no party: only the node's locator and the board's
    rendering are used, and the routers' locators stay empty."""
    return Plan(
        label="HW",
        grammar=True,
        node_id=None,
        ready=BoardReady(),
        a_dial=node,
        b_listen="",
        b_dial="",
        node_listener=node,
        stack_verdict=True,
    )


def run_pool(plan: Plan, console_raw: bytes, output_raw: bytes, report: CaptureReport, out: Renderer) -> int:
    console = read_pool_console(console_raw)
    obs = {
        26: onboard_record(console_raw, output_raw, plan),
        27: console,
        28: console,
        29: console,
        30: report,
    }
    fail = False
    for step in POOL_STEPS:
        why = clause_failures(step, obs[step])
        out.step(Verdict(step, not why, pool_sentence(step, obs[step]), "; ".join(why)))
        fail = fail or bool(why)
    out.note(console_summary(console, obs[26]))
    out.note(capture_summary(report))
    for finding in report.findings[:FINDINGS_SHOWN]:
        out.note(f"  {finding}\n")
    if len(report.findings) > FINDINGS_SHOWN:
        out.note(f"  and {len(report.findings) - FINDINGS_SHOWN} more\n")
    return 1 if fail else 0


def node_ipv4(locator: str) -> str | None:
    m = IPV4_LOCATOR.fullmatch(locator)
    return m.group(1) if m else None


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


DEFAULT_B_PORT = 17448
DEFAULT_REST_PORT = 17800


def pool_main(args: argparse.Namespace) -> int:
    """`board --pool-image`: HW.26 to HW.30 from the files a run left."""
    if args.host is not None or args.zenohd is not None or args.b_port is not None or (
        args.rest_port is not None
    ):
        return _refuse(
            "--pool-image reads files and starts no router: --host, --zenohd, --b-port and "
            "--rest-port belong to the board run that wrote --onboard"
        )
    address = node_ipv4(args.node)
    if address is None:
        return _refuse(
            f"--node {args.node!r} is not udp/<IPv4 address>:<port>; the capture is read as IPv4"
        )
    for flag, path in (("--console", args.console), ("--onboard", args.onboard), ("--pcap", args.pcap)):
        if path is None:
            return _refuse(f"--pool-image needs {flag}")
        if not path.is_file():
            return _refuse(f"{flag}: no file at {path}")
    try:
        report = analyse_capture(args.pcap.read_bytes(), address)
    except CaptureError as e:
        return _refuse(f"--pcap {args.pcap}: {e}")
    plan = pool_plan(args.node)
    out = Renderer(plan, sys.stdout.buffer, sys.stderr.buffer)
    return run_pool(plan, args.console.read_bytes(), args.onboard.read_bytes(), report, out)


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
    b.add_argument("--host", default=None, help="this host's address on the board's subnet")
    b.add_argument("--console", required=True, type=Path, help="the console capture file")
    b.add_argument("--zenohd", default=None)
    b.add_argument("--b-port", type=int, default=None, help=f"default {DEFAULT_B_PORT}")
    b.add_argument("--rest-port", type=int, default=None, help=f"default {DEFAULT_REST_PORT}")
    b.add_argument(
        "--pool-image",
        action="store_true",
        help="judge HW.26 to HW.30 of the transmit pool image from files, after the run",
    )
    b.add_argument("--onboard", type=Path, default=None, help="the board run's standard output")
    b.add_argument("--pcap", type=Path, default=None, help="a capture of the node's frames")
    args = ap.parse_args(argv)

    if args.mode == "board" and args.pool_image:
        return pool_main(args)
    if args.mode == "board":
        if args.onboard is not None or args.pcap is not None:
            return _refuse("--onboard and --pcap are read only with --pool-image")
        if args.host is None:
            return _refuse("--host is required: this host's address on the board's subnet")
        args.b_port = DEFAULT_B_PORT if args.b_port is None else args.b_port
        args.rest_port = DEFAULT_REST_PORT if args.rest_port is None else args.rest_port
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
    """Every step of the published grammar, `<...>` read as any value."""
    text = GRAMMAR.read_text()
    out = {}
    for m in re.finditer(r"^HW\.(\d+) (.+)$", text, re.M):
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


# The transmit pool image's fixtures: a console of one boot, the board run's
# output (the healthy board case's own lines) and a pcap, each fault changing
# one of them.

BOARD_ZID = "cfacc5282fa"
POOL_NODE_IP = "192.0.2.10"  # BOARD_NODE's address
POOL_START, POOL_END = 0x2800C860, 0x2800F860
POOL_SECTION = (0x28008000, 0x28010000)
# in place, copied, last descriptor, lent, started, completed, unarmed,
# abandoned, free: every row keeps both identities, one has 4 in flight.
POOL_COUNTS = (
    (0, 1, None, 0, 0, 0, 0, 0, 8),
    (6, 4, 0x2800CE82, 9, 8, 6, 1, 0, 6),
    (14, 7, 0x2800D482, 18, 17, 13, 1, 1, 5),
    (20, 9, 0x2800CE82, 22, 20, 20, 1, 1, 8),
    (20, 12, 0x2800CE82, 22, 20, 20, 1, 1, 8),
    (20, 15, 0x2800CE82, 22, 20, 20, 1, 1, 8),
)

# Each fault, the steps it reds, and the clause whose removal turns it green on
# its step (`None` where two clauses read it, so that neither alone does).
POOL_FAULTS: dict[str, tuple[set[int], tuple[int, str] | None]] = {
    "onboard_fail_mark": ({26}, (26, "lines")),
    "onboard_missing_line": ({26}, None),
    "two_boots": ({26}, (26, "ready")),
    "onboard_other_boot": ({26}, (26, "sentences")),
    "onboard_other_stack": ({26}, (26, "sentences")),
    "stack_deep_later": ({26}, (26, "stack")),
    # Two pool lines: HW.28 cannot say which pool the descriptor is in.
    "two_pool_lines": ({27, 28}, (27, "one line")),
    "no_pool_line": ({27, 28}, None),
    "pool_size": ({27}, (27, "size")),
    "pool_outside": ({27}, (27, "inside")),
    "in_place_zero": ({28}, (28, "above zero")),
    "descriptor_outside": ({28}, (28, "descriptor")),
    "no_counts": ({28, 29}, (29, "every line read")),
    "garbled_counts": ({29}, (29, "every line read")),
    "identity_broken": ({29}, (29, "identity")),
    "in_flight_5": ({29}, (29, "in flight")),
    "no_node_datagrams": ({30}, (30, "population")),
    "bad_ipv4": ({30}, (30, "ipv4")),
    "bad_udp": ({30}, (30, "udp")),
    "zero_udp": ({30}, (30, "zero")),
    "fragment": ({30}, (30, "fragments")),
    "malformed_udp": ({30}, (30, "malformed")),
    "truncated_frame": ({30}, (30, "truncated")),
    "file_cut_short": ({30}, (30, "truncated")),
}


def _pool_line(start: int = POOL_START, end: int = POOL_END, section: tuple[int, int] = POOL_SECTION) -> str:
    return (
        f"wz: eth0: transmit pool of 8 slots at {start:#010x} to {end:#010x}, in the "
        f"non-cacheable section {section[0]:#010x} to {section[1]:#010x}, read in place by the MAC"
    )


def _counts_line(row: list) -> str:
    in_place, copied, desc, lent, started, completed, unarmed, abandoned, free = row
    d = "none" if desc is None else f"{desc:#010x}"
    return (
        f"wz: tx-pool: in place {in_place}, copied {copied}, last descriptor {d}; pool lent "
        f"{lent}, started {started}, completed {completed}, unarmed {unarmed}, abandoned "
        f"{abandoned}, free {free} of 8"
    )


def _pool_console(fault: str | None) -> bytes:
    rows = [list(r) for r in POOL_COUNTS]
    if fault == "identity_broken":
        rows[2][8] = 6
    if fault == "in_flight_5":
        rows[2][4] = 18
    if fault == "in_place_zero":
        rows[-1][0] = 0
    if fault == "descriptor_outside":
        rows[-1][2] = 0x28010040
    place = _pool_line()
    if fault == "pool_outside":
        place = _pool_line(section=(0x28000000, 0x28008000))
    if fault == "pool_size":
        place = _pool_line(end=POOL_END - 1)
    ready = f"ZEPHYR-WZ-ADMIN READY {BOARD_ZID} {BOARD_NODE}"
    counts = [_counts_line(r) for r in rows]
    if fault == "garbled_counts":
        counts.insert(3, "wz: tx-pool: in place 20, copied 1")
    if fault == "no_counts":
        counts = []
    lines = ["*** Booting Zephyr OS ***", "wz: core clock 350000000 Hz"]
    lines += [] if fault == "no_pool_line" else [place]
    lines += [place] if fault == "two_pool_lines" else []
    lines += [ready, ready] if fault == "two_boots" else [ready]
    lines += counts[:1]
    lines += ["stack: peak 3524 of 32768 bytes", "stack: peak 20080 of 32768 bytes"]
    lines += counts[1:]
    if fault == "stack_deep_later":
        lines.append("stack: peak 30000 of 32768 bytes")
    return "".join(f"{ln}\r\n" for ln in lines).encode()


def _pool_onboard(healthy: bytes, fault: str | None) -> bytes:
    text = healthy.decode()
    if fault == "onboard_fail_mark":
        text = text.replace("names the written list - OK", "names the written list - FAIL")
    if fault == "onboard_missing_line":
        text = "".join(f"{ln}\n" for ln in text.splitlines() if not ln.startswith("HW.5 "))
    if fault == "onboard_other_boot":
        text = text.replace(f"READY {BOARD_ZID} ", "READY 0123456789a ")
    if fault == "onboard_other_stack":
        text = text.replace("peak 20080 of", "peak 20081 of")
    return text.encode()


def _ip_frame(
    src: str,
    dst: str,
    payload: bytes,
    *,
    sport: int = 7447,
    dport: int = 40000,
    proto: int = 17,
    vlan: bool = False,
    options: bytes = b"",
    frag: int = 0x4000,
    ip_fault: bool = False,
    zero_udp: bool = False,
    udp_len_extra: int = 0,
    flip: bool = False,
) -> bytes:
    """An Ethernet II frame of one IPv4 packet, its checksums computed, then
    the one fault the arguments name put in."""
    s, d = (bytes(int(x) for x in a.split(".")) for a in (src, dst))
    l4 = payload
    if proto == 17:
        l4 = struct.pack("!HHHH", sport, dport, 8 + len(payload), 0) + payload
        if not zero_udp:
            c = 0xFFFF - inet_sum(s + d + struct.pack("!BBH", 0, 17, len(l4)) + l4)
            l4 = l4[:6] + struct.pack("!H", c or 0xFFFF) + l4[8:]
        l4 = l4[:4] + struct.pack("!H", len(l4) + udp_len_extra) + l4[6:]
        if flip:
            l4 = l4[:-1] + bytes([l4[-1] ^ 0x5A])
    ihl = (20 + len(options)) // 4
    hdr = struct.pack(
        "!BBHHHBBH4s4s", 0x40 | ihl, 0, 20 + len(options) + len(l4), 7, frag, 255, proto, 0, s, d
    ) + options
    c = 0xFFFF - inet_sum(hdr)
    hdr = hdr[:10] + struct.pack("!H", c ^ 1 if ip_fault else c) + hdr[12:]
    tag = struct.pack("!HH", 0x8100, 5) if vlan else b""
    frame = bytes.fromhex("020000000001020000000002") + tag + b"\x08\x00" + hdr + l4
    return frame + bytes(max(0, 60 - len(frame)))


def _arp_frame() -> bytes:
    return bytes.fromhex("ffffffffffff020000000001") + b"\x08\x06" + bytes(46)


def _pcap_file(records: list[tuple[bytes, int]], order: str = "<", cut: int = 0) -> bytes:
    out = struct.pack(order + "IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)
    for i, (data, orig) in enumerate(records):
        out += struct.pack(order + "IIII", 1_700_000_000 + i, 250_000, len(data), orig) + data
    return out[: len(out) - cut]


def _pool_pcap(fault: str | None, order: str = "<") -> bytes:
    n, h = POOL_NODE_IP, BOARD_HOST

    def node(i: int, payload: bytes, **kw) -> bytes:
        # The node's i-th UDP datagram carries the fault the case names for it.
        kw.update(
            {
                ("bad_ipv4", 0): {"ip_fault": True},
                ("zero_udp", 1): {"zero_udp": True},
                ("malformed_udp", 2): {"udp_len_extra": 1},
                ("fragment", 3): {"frag": 0x2000},
                ("bad_udp", 4): {"flip": True},
            }.get((fault, i), {})
        )
        return _ip_frame(n, h, payload, **kw)

    frames = [
        _arp_frame(),
        node(0, bytes(range(115))),
        node(1, b"\x05"),  # a 1-byte datagram in a padded frame
        _ip_frame(h, n, b"\x01\x02", sport=40000, dport=7447, zero_udp=True),  # not the node's
        node(2, bytes(33), vlan=True),
        node(3, b"\x09" * 9, options=b"\x01\x01\x01\x00"),
        node(4, bytes(range(40)), sport=55188, dport=17448),
        _ip_frame(h, n, b"\x07", sport=40000, dport=7447, ip_fault=True),  # not the node's
        _ip_frame(n, h, b"\x08\x00" + bytes(6), proto=1),  # the node's, not UDP
    ]
    records = [(f, len(f)) for f in frames]
    if fault == "no_node_datagrams":
        records = [records[i] for i in (0, 3, 7, 8)]
    if fault == "truncated_frame":
        records[1] = (frames[1][:40], len(frames[1]))
    return _pcap_file(records, order, cut=3 if fault == "file_cut_short" else 0)


def _pool_fixture(fault: str | None, onboard: bytes, order: str = "<") -> tuple[bytes, bytes, bytes]:
    return _pool_console(fault), _pool_onboard(onboard, fault), _pool_pcap(fault, order)


def _pool_run(console: bytes, onboard: bytes, pcap: bytes) -> tuple[int, bytes, bytes]:
    plan = pool_plan(BOARD_NODE)
    out, err = io.BytesIO(), io.BytesIO()
    try:
        report = analyse_capture(pcap, POOL_NODE_IP)
    except CaptureError as e:
        return 2, b"", str(e).encode()
    rc = run_pool(plan, console, onboard, report, Renderer(plan, out, err))
    return rc, out.getvalue(), err.getvalue()


def _pool_case_failures(onboard: bytes) -> list[str]:
    """Every pool case's expectation that does not hold: the healthy set in
    both byte orders holds all five, each fault reds exactly its steps."""
    fails = []
    for order in ("<", ">"):
        rc, out, err = _pool_run(*_pool_fixture(None, onboard, order))
        steps = _grammar_steps(out)
        if rc != 0 or steps != {s: True for s in POOL_STEPS}:
            fails.append(f"healthy ({order}): rc {rc} {out!r} {err!r}")
    for fault, (want_red, _) in POOL_FAULTS.items():
        rc, out, err = _pool_run(*_pool_fixture(fault, onboard))
        steps = _grammar_steps(out)
        red = {k for k, v in steps.items() if not v}
        if rc != 1 or sorted(steps) != list(POOL_STEPS) or red != want_red:
            fails.append(f"{fault}: rc {rc}, red {sorted(red)}, want {sorted(want_red)}: {err!r}")
        if re.search(rb"HW\.\d+ ", err):
            fails.append(f"{fault}: a standard error line names a step: {err!r}")
    return fails


def _parser_mutants() -> dict[str, tuple[str, Callable]]:
    real_udp = udp_checksum_verdict
    return {
        "the IPv4 header checksum not checked": ("ipv4_header_ok", lambda header: True),
        "the UDP checksum without the pseudo header": (
            "udp_checksum_verdict",
            lambda ip, d: "zero" if d[6:8] == b"\x00\x00" else ("ok" if inet_sum(d) == 0xFFFF else "bad"),
        ),
        "a zero UDP checksum taken as valid": (
            "udp_checksum_verdict",
            lambda ip, d: "ok" if d[6:8] == b"\x00\x00" else real_udp(ip, d),
        ),
        "datagrams from every address counted": ("from_node", lambda ip, node: True),
        "every file read as little endian": ("pcap_byte_order", lambda raw: ("<", 1e-6)),
    }


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
        check(
            "the grammar publishes HW.0 to HW.7 and the pool steps",
            set(range(8)) | set(POOL_STEPS) <= set(templates),
            f"{sorted(templates)}",
        )
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
        rc, _, err = _cli(["board", "--node", BOARD_NODE, "--console", str(capture), "--zenohd", str(zenohd)])
        check("a live board run without --host is refused", rc == 2 and b"--host" in err, f"{rc} {err!r}")

        # 8. The transmit pool image. The board run's output is the healthy
        #    board case's own lines, so HW.26 reads what this program printed.
        onboard = board_out
        for fault in POOL_FAULTS:
            if fault.startswith("onboard_"):
                check(f"pool {fault}: the fixture changes the output", _pool_onboard(onboard, fault) != onboard)
        pool_fails = _pool_case_failures(onboard)
        check("pool cases: healthy holds, each fault reds exactly its steps", not pool_fails, f"{pool_fails}")
        rc, pool_out, pool_err = _pool_run(*_pool_fixture(None, onboard))
        check(
            "pool healthy: standard error is the two count lines",
            pool_err.decode().splitlines()
            == [
                "  console: 1 READY line(s), 1 pool line(s), 6 counts line(s), 0 unread, 2 stack line(s)",
                "  capture: 9 frames; 5 UDP datagrams from 192.0.2.10 over 7.0 s, 5 with both checksums "
                "valid; 0 bad IPv4 header checksums, 0 bad UDP checksums, 0 zero UDP checksums, "
                "0 fragments, 0 malformed, 0 truncated",
            ],
            f"{pool_err!r}",
        )
        check(
            "pool healthy: the values read are the console's",
            b"HW.27 the pool sits where the MAC reads it uncached: slots 0x2800c860 to 0x2800f860 inside "
            b"the non-cacheable section 0x28008000 to 0x28010000 - OK\n" in pool_out
            and b"HW.28 a frame left from a pool slot read in place: in place 20 and started 20 above zero, "
            b"last descriptor 0x2800ce82 inside the pool - OK\n" in pool_out
            and b": 5 of 5 datagrams from the node in the capture had valid IPv4 and UDP checksums - OK\n"
            in pool_out,
            f"{pool_out!r}",
        )
        for ln in pool_out.decode().splitlines():
            m = re.fullmatch(r"HW\.(\d+) (.*) - OK", ln)
            check(
                f"pool HW.{m.group(1) if m else '?'} is the grammar's sentence",
                bool(m) and bool(templates[int(m.group(1))].fullmatch(m.group(2))),
                ln,
            )
        grammar_text = GRAMMAR.read_text()
        for label, pattern in (("pool place", POOL_LINE), ("tx counts", COUNTS_LINE)):
            m = re.search(rf"^{label} +(\^.*\$)$", grammar_text, re.M)
            check(
                f"the {label} regex is the grammar's",
                bool(m) and m.group(1) == pattern.pattern,
                f"{m.group(1) if m else None!r} != {pattern.pattern!r}",
            )

        # Each clause dropped: the fault it exists for goes green on its step.
        paired = {pair for _, pair in POOL_FAULTS.values() if pair}
        for step, clauses in POOL_CLAUSES.items():
            for i, clause in enumerate(clauses):
                check(f"HW.{step} clause {clause.name!r} has a fault", (step, clause.name) in paired)
                clauses[i] = Clause(clause.name, lambda obs: True, clause.why)
                try:
                    for fault, (_, pair) in POOL_FAULTS.items():
                        if pair != (step, clause.name):
                            continue
                        _, out, err = _pool_run(*_pool_fixture(fault, onboard))
                        check(
                            f"HW.{step} without {clause.name!r}: {fault} goes green there",
                            _grammar_steps(out).get(step) is True,
                            f"{out!r} {err!r}",
                        )
                finally:
                    clauses[i] = clause
        # HW.26 runs the step 0 and step 7 comparisons themselves.
        for step, fault in ((0, "two_boots"), (LAST_STEP, "stack_deep_later")):
            saved = JUDGES[step]
            JUDGES[step] = lambda *a: True
            try:
                _, out, _ = _pool_run(*_pool_fixture(fault, onboard))
                check(f"weakened step {step}: pool {fault} goes green on HW.26", _grammar_steps(out).get(26) is True,
                      f"{out!r}")
            finally:
                JUDGES[step] = saved
        # Each mutant of the capture reader is caught by some case.
        for name, (target, mutant) in _parser_mutants().items():
            saved = globals()[target]
            globals()[target] = mutant
            try:
                check(f"mutant caught: {name}", bool(_pool_case_failures(onboard)))
            finally:
                globals()[target] = saved
        check("pool cases hold again once the mutants are gone", not _pool_case_failures(onboard))

        # The record's reader reads the onboard and pool lines as the steps.
        record = "THE VERDICT. " + " ".join(onboard.decode().splitlines() + pool_out.decode().splitlines())
        held = gate.step_verdicts(json.dumps({"verification_bullets": [record]}))
        check(
            "the gate reads the pasted pool output as HW.26 to HW.30 held",
            held == {str(i): True for i in [*range(8), *POOL_STEPS]},
            f"{held}",
        )
        _, red_out, _ = _pool_run(*_pool_fixture("pool_outside", onboard))
        held = gate.step_verdicts(json.dumps({"v": [" ".join(red_out.decode().splitlines())]}))
        check("the gate reads a pasted pool FAIL as not held", held.get("27") is False and held.get("28") is True,
              f"{held}")

        # End to end on files, and what it refuses.
        d = case_dir()
        files = dict(zip(("console", "onboard", "pcap"), _pool_fixture(None, onboard)))
        for name, data in files.items():
            (d / name).write_bytes(data)
        pool_argv = ["board", "--pool-image", "--node", BOARD_NODE, "--console", str(d / "console"),
                     "--onboard", str(d / "onboard")]
        rc, out, err = _cli([*pool_argv, "--pcap", str(d / "pcap")])
        check("cli pool healthy: the five lines", rc == 0 and out == pool_out and err == pool_err,
              f"rc {rc} {out!r} {err!r}")
        (d / "bad").write_bytes(_pool_pcap("bad_udp"))
        rc, out, _ = _cli([*pool_argv, "--pcap", str(d / "bad")])
        check("cli pool bad UDP checksum: rc 1, HW.30 FAIL", rc == 1 and _grammar_steps(out).get(30) is False,
              f"rc {rc} {out!r}")
        (d / "ng").write_bytes(b"\x0a\x0d\x0d\x0a" + bytes(40))
        refusals = [
            ("no --pcap", pool_argv, b"--pcap"),
            ("a pcapng file", [*pool_argv, "--pcap", str(d / "ng")], b"pcapng"),
            ("a router option", [*pool_argv, "--pcap", str(d / "pcap"), "--host", BOARD_HOST], b"no router"),
            (
                "an IPv6 node",
                ["board", "--pool-image", "--node", "udp/[2001:db8::1]:7447", "--console", str(d / "console"),
                 "--onboard", str(d / "onboard"), "--pcap", str(d / "pcap")],
                b"IPv4",
            ),
            (
                "--pcap without --pool-image",
                ["board", "--node", BOARD_NODE, "--host", BOARD_HOST, "--console", str(d / "console"),
                 "--pcap", str(d / "pcap")],
                b"--pool-image",
            ),
        ]
        for name, argv, needle in refusals:
            rc, out, err = _cli(argv)
            check(f"cli pool refuses {name}", rc == 2 and out == b"" and needle in err, f"rc {rc} {out!r} {err!r}")

    for f in failures:
        print(f"admin_node_verdict selftest FAIL: {f}", file=sys.stderr)
    if failures:
        return 1
    print("admin_node_verdict selftest: OK")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
