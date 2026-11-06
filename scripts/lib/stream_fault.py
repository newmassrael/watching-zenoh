#!/usr/bin/env python3
# SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
# SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
"""R4313 (no register item) -- a fault-injecting TCP proxy: the instrument the stream steps of the node
verdict (HARDWARE_VERDICT.md, `admin_node_stream_steps.py`) are made with.

The debt this answers for is the one `admin_node_verdict.py` states (open-debt item 876): a verdict that
is the program's output and not a transcription. The datagram steps need nothing of the network but a
healthy peer; the steps for what only a stream can suffer need the network to be made to do it, and this
is what does it. It lives in the operator's register, which has no store `debt-` id to resolve, so the
honest pair is this sentence and `no register item` in the citation.

## Why an instrument of its own

A stream differs from a datagram in what the network can do to it, and none of it can be asked of a
healthy peer: a connection ends in two ways (a FIN after which the other end may still send, and a
RST after which nothing is delivered), it can fall silent with no end at all (a half-open
connection, which only a lease can tell from a quiet one), a listener can stop taking connections,
and the bytes of one write can arrive as many reads, or many writes as one. A step that holds a node
to its behaviour under these needs the host to DO them, on a chosen connection, at a chosen moment,
and to be sure that it did. A real router's own behaviour (it reconnects when it likes, it closes
when it likes) is not that: it is a second subject.

## The controls

  close_all()   an orderly release: FIN to both ends, then each end is drained until it closes its own
                (the textbook half-close), so unread data in flight never turns the release into a RST.
  reset_all()   an abortive release: both ends are closed with a zero linger, so the kernel sends a
                RST to both and discards what it held.
  blackhole(on) the half-open case: while on, every byte either end sends is read and dropped, and no
                connection is closed; the ends are alive to the kernel and silent to each other. An
                end that closes its own while it is on (a router whose lease ran out) is not heard by
                the other: the close is counted `swallowed` and delivered when the black hole ends.
                Without that, the half-open case would end at the first end's own lease and a step
                could not tell the other end's lease from the first's.
  reject(on)    the peer that dials and is turned away: while on, a connection is taken from the
                listener and reset at once, never reaching the upstream. Every connection taken is
                stamped on the proxy's own clock (`stats().attempts`), joined or not, so the gaps
                between a node's dials are read from events and not from polling its status.
  refuse(on)    the listener's absence: while on, the listening socket is closed, so a connect is
                refused; held connections are untouched.
  segment(n)    the stream's lack of boundaries: bytes are forwarded in writes of at most n bytes.
  hold(on) / release()
                the other direction: while on, what is read is buffered and nothing is forwarded (what was
                buffered is logged as it is, `stats().held_log`, so a barrier can be a content and not a
                size or a time); release() ends the hold and sends each direction's buffer as ONE write,
                in one step under the direction's lock, and returns the writes it made.

## Why it does not flake (the design, not the luck)

An instrument that a verdict is built on has to be deterministic by construction, and a test of it
cannot depend on how fast a machine is. Five rules, each of which a flake of an earlier version broke:

  1. Order the observable after its record. A counter is raised BEFORE the bytes it counts are
     sent, so whoever has seen the bytes has the count, and never the reverse.
  2. Wait for events, not for time. Every thread blocks in `select` on its sockets and on a wake
     pipe; nothing polls with a timeout and nothing is decided by one. A deadline exists only as a guard
     against a hang, and a case that reaches it fails.
  3. A control returns when its effect is in place. The thread that owns a resource (the listener, a
     pair's sockets) carries a control out and acknowledges it; a control is never a race with the thread
     that is using the resource, and a connection the kernel established before a control is one the
     control applies to (the backlog is taken first).
  4. A property is judged where the instrument controls it. Segmentation is judged by the writes the
     proxy made (its log), not by how the kernel happens to group them into reads at the far end; a
     merge is an explicit barrier (`hold`, `flush`), not a timer.
  5. A state change is signalled, and a test waits on it (`wait`), so a case never sleeps and then looks.

`--selftest` holds each control to its effect as the ends see it, and `--stress N` runs the cases N times
in one process (and, with `--load`, beside busy threads), which is how the absence of a flake is shown
and not assumed.
"""

from __future__ import annotations

import os
import select
import socket
import struct
import subprocess
import sys
import threading
import time
from dataclasses import dataclass, field, replace
from typing import Callable

#: A guard against a hang, never a condition: a wait that reaches it has failed.
HANG_GUARD_S = 10.0


@dataclass
class Stats:
    """What the proxy has done, read by a step to know its fault landed on something."""

    accepted: int = 0  # connections taken from the listener and joined to the upstream
    closed: int = 0  # connections that have ended, by any cause
    up: int = 0  # bytes committed to be forwarded towards the upstream
    down: int = 0  # bytes committed to be forwarded towards the client
    dropped: int = 0  # bytes read and discarded by a black hole
    held: int = 0  # bytes buffered by `hold` and not yet flushed
    swallowed: int = 0  # ends' closings a black hole kept from the other end (delivered when it ends)
    rejected: int = 0  # connections taken from the listener and reset at once by `reject`
    attempts: list = field(default_factory=list)  # time.monotonic() at each connection taken, joined or not
    writes: list = field(default_factory=list)  # (direction, size) of each write the proxy made
    held_log: list = field(default_factory=list)  # (direction, bytes) of each read `hold` buffered, in order


class _Pair:
    """One client connection and its upstream, forwarded by two threads that wait on events."""

    def __init__(self, proxy: "StreamProxy", client: socket.socket, upstream: socket.socket) -> None:
        self.proxy, self.client, self.upstream = proxy, client, upstream
        for s in (client, upstream):
            s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            s.settimeout(HANG_GUARD_S)  # bounds a send to a peer that never reads
        self.wake_r, self.wake_w = os.pipe()
        self.stopping = False
        self.ended = threading.Event()
        self._lock = threading.Lock()
        self._closed = False
        self._left = 2
        self._held = {True: b"", False: b""}
        # One lock for each direction orders what is held, what is written and the end of a hold: a write
        # that follows the end of a hold in a direction goes after every byte that hold buffered.
        self._dlock = {True: threading.Lock(), False: threading.Lock()}
        self.holding = {True: False, False: False}
        self.threads = [
            threading.Thread(target=self._pump, args=(client, upstream, True), daemon=True),
            threading.Thread(target=self._pump, args=(upstream, client, False), daemon=True),
        ]

    def start(self) -> None:
        """Begin forwarding: after the proxy has counted the pair, so no byte is counted before its connection."""
        for t in self.threads:
            t.start()

    def _pump(self, src: socket.socket, dst: socket.socket, up: bool) -> None:
        try:
            while not self.stopping:
                readable, _, _ = select.select([src, self.wake_r], [], [])
                if self.wake_r in readable or self.stopping:
                    return
                try:
                    data = src.recv(65536)
                except OSError:
                    if self.proxy._blackhole:
                        self._swallow()  # a reset the far end must not hear is not forwarded either
                    return
                if not data:
                    if self.proxy._blackhole and not self._swallow():
                        return
                    try:
                        self._flush_direction(up, dst)
                        dst.shutdown(socket.SHUT_WR)
                    except OSError:
                        pass
                    return
                self._handle(data, dst, up)
        finally:
            with self._lock:
                self._left -= 1
                last = self._left == 0
            # An abort closes the pair itself, after the pumps have stopped, and decides how.
            if last and not self.stopping:
                self._finish()

    def _swallow(self) -> bool:
        """An end closed its own while the network is a black hole: the other end does not hear it. The
        record is made first (rule 1), then the pump waits for the state change that ends the black hole
        (rule 5: a notification on the proxy's condition, never a timer). False when the pair was stopped
        meanwhile, so the close is not delivered to sockets an abort is closing."""
        self.proxy._count(swallowed=1)
        with self.proxy._cv:
            self.proxy._cv.wait_for(lambda: not self.proxy._blackhole or self.stopping)
        return not self.stopping

    def _handle(self, data: bytes, dst: socket.socket, up: bool) -> None:
        proxy = self.proxy
        if proxy._blackhole:
            proxy._count(dropped=len(data))
            return
        with self._dlock[up]:
            if self.holding[up]:
                self._held[up] += data
                proxy._count(held=len(data), held_log=[("up" if up else "down", data)])
                return
            self._write(dst, data, up)

    def _write(self, dst: socket.socket, data: bytes, up: bool) -> None:
        size = self.proxy._segment or len(data)
        pieces = [data[i : i + size] for i in range(0, len(data), size)]
        # Rule 1: the record first, then the effect.
        self.proxy._count(
            up=len(data) if up else 0,
            down=0 if up else len(data),
            writes=[("up" if up else "down", len(p)) for p in pieces],
        )
        try:
            for piece in pieces:
                dst.sendall(piece)
        except OSError:
            pass

    def _flush_direction(self, up: bool, dst: socket.socket, end_hold: bool = False) -> int:
        """Send what is buffered in a direction as one write; returns its size (0: nothing was buffered)."""
        with self._dlock[up]:
            if end_hold:
                self.holding[up] = False
            data, self._held[up] = self._held[up], b""
            if data:
                self.proxy._count(held=-len(data))
                self._write(dst, data, up)
            return len(data)

    def set_hold(self, on: bool) -> None:
        for up in (True, False):
            with self._dlock[up]:
                self.holding[up] = on

    def flush(self, end_hold: bool = False) -> list[tuple[str, int]]:
        """Send what `hold` buffered, each direction as one write; with `end_hold` the hold ends in the
        same step, under the direction's lock, so nothing read afterwards can be sent before it. Returns
        the writes it made, (direction, size): the proxy's own account of what this call sent, which no
        write made by a later read can be mistaken for."""
        made = [
            ("up", self._flush_direction(True, self.upstream, end_hold)),
            ("down", self._flush_direction(False, self.client, end_hold)),
        ]
        return [(d, n) for d, n in made if n]

    def _finish(self, reset: bool = False) -> None:
        """The one place the sockets are closed, once: a zero linger first when the end is a RST."""
        with self._lock:
            if self._closed:
                return
            self._closed = True
        for s in (self.client, self.upstream):
            try:
                if reset:
                    s.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack("ii", 1, 0))
                s.close()
            except OSError:
                pass
        for fd in (self.wake_r, self.wake_w):
            try:
                os.close(fd)
            except OSError:
                pass
        self.ended.set()
        self.proxy._count(closed=1)

    def orderly(self) -> None:
        """FIN to both ends; the pumps carry on until each end has closed its own."""
        self.flush()
        for s in (self.client, self.upstream):
            try:
                s.shutdown(socket.SHUT_WR)
            except OSError:
                pass

    def abort(self, reset: bool) -> None:
        """End the pair now. The pumps are stopped first, so no thread is in a call on a socket that is
        being closed, and then a zero linger makes the close a RST."""
        self.stopping = True
        try:
            os.write(self.wake_w, b"x")
        except OSError:
            pass
        with self.proxy._cv:  # a pump parked by a black hole is woken too
            self.proxy._cv.notify_all()
        for t in self.threads:
            if t is not threading.current_thread() and t.is_alive():
                t.join(timeout=HANG_GUARD_S)
        self._finish(reset)


class StreamProxy:
    """Forward a listening address to an upstream address, and do to the connections what a network does."""

    def __init__(self, listen: tuple[str, int], upstream: tuple[str, int]) -> None:
        self.listen_addr, self.upstream = listen, upstream
        self._blackhole = False
        self._reject = False
        self._hold = False
        self._segment = 0
        self._stats = Stats()
        self._pairs: list[_Pair] = []
        self._cv = threading.Condition()
        self._commands: list[tuple[str, threading.Event]] = []
        self._cmd_r, self._cmd_w = os.pipe()
        self._stopping = False
        self._stopped = False
        self._thread: threading.Thread | None = None
        self._bound = threading.Event()

    # -- lifecycle ---------------------------------------------------------------------------

    def start(self) -> "StreamProxy":
        self._thread = threading.Thread(target=self._accept_loop, daemon=True)
        self._thread.start()
        if not self._bound.wait(HANG_GUARD_S):
            raise OSError("the proxy's listener was not bound")
        return self

    def stop(self) -> None:
        """End the proxy: its listener, its pairs and its pipe. Idempotent: a caller that stops it twice (the
        verdict stops its environment on the way out and again from its `finally`) must not write to a pipe
        the first stop closed, which is an error where the descriptor is still closed and a byte into some
        other file where the number has been reused."""
        with self._cv:
            if self._stopped:
                return
            self._stopped = True
        self._stopping = True
        os.write(self._cmd_w, b"x")
        if self._thread is not None:
            self._thread.join(timeout=HANG_GUARD_S)
        with self._cv:
            pairs = list(self._pairs)
        for pair in pairs:
            if not pair.ended.is_set():
                pair.abort(reset=False)
        for fd in (self._cmd_r, self._cmd_w):
            try:
                os.close(fd)
            except OSError:
                pass

    @property
    def port(self) -> int:
        """The port the proxy listens on (the one asked for, or the one the kernel gave for 0)."""
        return self.listen_addr[1]

    def _command(self, name: str) -> None:
        """Rule 3: ask the thread that owns the listener to do `name`, and return when it has."""
        done = threading.Event()
        with self._cv:
            self._commands.append((name, done))
        os.write(self._cmd_w, b"x")
        if not done.wait(HANG_GUARD_S):
            raise OSError(f"the proxy's accept loop did not carry out {name!r}")

    def _bind(self) -> socket.socket:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind(self.listen_addr)
        s.listen(16)
        self.listen_addr = s.getsockname()
        return s

    def _join(self, client: socket.socket) -> None:
        """Join an accepted connection to the upstream and forward it, or, while `reject` is on, reset it
        at once. The attempt is stamped first (rule 1), so whoever sees a connection has its time; the stamp
        is the proxy's own clock, which is how a step reads the gaps between a node's dials without polling."""
        self._count(attempt=time.monotonic())
        if self._reject:
            try:
                client.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack("ii", 1, 0))
            except OSError:
                pass
            client.close()
            self._count(rejected=1)
            return
        try:
            upstream = socket.create_connection(self.upstream, timeout=HANG_GUARD_S)
        except OSError:
            client.close()
            return
        client.setblocking(True)
        pair = _Pair(self, client, upstream)
        with self._cv:
            pair.holding = {True: self._hold, False: self._hold}  # read where `hold` takes its pairs: one or the other sees it
            self._pairs.append(pair)
        self._count(accepted=1)
        pair.start()

    def _drain(self, listener: socket.socket) -> None:
        """Take every connection the kernel has established and the loop has not yet accepted."""
        listener.setblocking(False)
        while True:
            try:
                client, _ = listener.accept()
            except (BlockingIOError, OSError):
                return
            self._join(client)

    def _accept_loop(self) -> None:
        listener: socket.socket | None = self._bind()
        self._bound.set()
        try:
            while not self._stopping:
                watched = [self._cmd_r] + ([listener] if listener is not None else [])
                readable, _, _ = select.select(watched, [], [])
                if self._cmd_r in readable:
                    os.read(self._cmd_r, 4096)
                    with self._cv:
                        commands, self._commands = self._commands, []
                    for name, done in commands:
                        if name == "drain" and listener is not None:
                            self._drain(listener)
                        elif name == "close" and listener is not None:
                            # What the kernel established before the fault is served; a connect after it is refused.
                            self._drain(listener)
                            listener.close()
                            listener = None
                        elif name == "open" and listener is None:
                            listener = self._bind()
                        elif name in ("reject_on", "reject_off") and listener is not None:
                            # What the kernel established before the control is served under the old mode.
                            self._drain(listener)
                            self._reject = name == "reject_on"
                        elif name in ("reject_on", "reject_off"):
                            self._reject = name == "reject_on"
                        done.set()
                if listener is not None and listener in readable:
                    try:
                        client, _ = listener.accept()
                    except OSError:
                        continue
                    self._join(client)
        finally:
            if listener is not None:
                listener.close()

    # -- observation -------------------------------------------------------------------------

    def _count(
        self,
        accepted: int = 0,
        closed: int = 0,
        up: int = 0,
        down: int = 0,
        dropped: int = 0,
        held: int = 0,
        swallowed: int = 0,
        rejected: int = 0,
        attempt: float | None = None,
        writes: list | None = None,
        held_log: list | None = None,
    ) -> None:
        with self._cv:
            s = self._stats
            s.accepted += accepted
            s.closed += closed
            s.up += up
            s.down += down
            s.dropped += dropped
            s.held += held
            s.swallowed += swallowed
            s.rejected += rejected
            if attempt is not None:
                s.attempts.append(attempt)
            if writes:
                s.writes.extend(writes)
            if held_log:
                s.held_log.extend(held_log)
            self._cv.notify_all()

    def _snapshot(self) -> Stats:
        """A copy of the counters; the caller holds `_cv`."""
        return replace(
            self._stats,
            writes=list(self._stats.writes),
            attempts=list(self._stats.attempts),
            held_log=list(self._stats.held_log),
        )

    def stats(self) -> Stats:
        with self._cv:
            return self._snapshot()

    def live(self) -> int:
        """Connections held now."""
        with self._cv:
            return sum(1 for p in self._pairs if not p.ended.is_set())

    def wait(self, predicate: Callable[[Stats], bool], what: str = "", timeout: float | None = None) -> Stats:
        """Rule 5: wait for a state change to make `predicate(stats)` true. The deadline is a hang guard (the
        default, or the longer one a caller who knows how long the event may take states)."""
        with self._cv:
            def ready() -> bool:
                return predicate(self._snapshot())

            if not self._cv.wait_for(ready, timeout=HANG_GUARD_S if timeout is None else timeout):
                raise TimeoutError(f"the proxy did not reach the state waited for ({what})")
        return self.stats()

    # -- the controls ------------------------------------------------------------------------

    def _live_pairs(self) -> list[_Pair]:
        self._command("drain")
        with self._cv:
            return [p for p in self._pairs if not p.ended.is_set()]

    def close_all(self) -> int:
        """An orderly release of every connection: FIN to both ends (each is drained until it closes its
        own). Returns how many it released."""
        pairs = self._live_pairs()
        for pair in pairs:
            pair.orderly()
        return len(pairs)

    def reset_all(self) -> int:
        """An abortive release of every connection: RST to both ends. Returns how many it ended."""
        pairs = self._live_pairs()
        for pair in pairs:
            pair.abort(reset=True)
        return len(pairs)

    def blackhole(self, on: bool) -> None:
        """While on, bytes from either end are read and dropped and no connection is closed: an end that
        closes its own (a lease that ran out, a reset) is not heard by the other, which is what a
        half-open connection is. What was swallowed is delivered when the black hole ends."""
        with self._cv:
            self._blackhole = on
            self._cv.notify_all()

    def refuse(self, on: bool) -> None:
        """While on, the listening socket is closed (a connect is refused); held connections are untouched,
        and so are the ones the kernel had established and the loop had not yet taken (they are served)."""
        self._command("close" if on else "open")

    def reject(self, on: bool) -> None:
        """While on, a connection taken from the listener is reset at once and never reaches the upstream:
        the listener is there (unlike `refuse`) and the peer's dial reaches it and fails, so every attempt
        is stamped in `stats().attempts`. Returns when the accept thread has applied it."""
        self._command("reject_on" if on else "reject_off")

    def segment(self, size: int | None) -> None:
        """Forward in writes of at most `size` bytes; None to forward as read."""
        self._segment = size or 0

    def hold(self, on: bool) -> None:
        """While on, what is read is buffered and not forwarded, on the connections there are and on the ones
        made meanwhile; `release()` sends it. What was buffered is logged (`stats().held_log`) as it is, so
        a barrier can be a content the buffer holds and not a size or a time."""
        with self._cv:
            self._hold = on
            pairs = [p for p in self._pairs if not p.ended.is_set()]
        for pair in pairs:
            pair.set_hold(on)

    def flush(self) -> list[tuple[str, int]]:
        """Send what `hold` buffered, each direction as one write, leaving the hold on. Returns the writes
        this call made, (direction, size)."""
        with self._cv:
            pairs = [p for p in self._pairs if not p.ended.is_set()]
        made: list[tuple[str, int]] = []
        for pair in pairs:
            made += pair.flush()
        return made

    def release(self) -> list[tuple[str, int]]:
        """End the hold: what it buffered is sent, each direction as one write, and what is read afterwards
        goes after it. The end and the send are one step under each direction's lock, so a read that lands
        between them is neither sent ahead of the buffer nor left in it. Returns the writes this call made,
        (direction, size): exactly the buffer's, and none that a read after the hold made."""
        with self._cv:
            self._hold = False
            pairs = [p for p in self._pairs if not p.ended.is_set()]
        made: list[tuple[str, int]] = []
        for pair in pairs:
            made += pair.flush(end_hold=True)
        return made


# ------------------------------------------------------------------------------------ selftest --


class _Reads(list):
    """What the echo upstream read, and an event that is set when one of its connections reaches EOF."""

    def __init__(self) -> None:
        super().__init__()
        self.eof = threading.Event()


def _server() -> tuple[socket.socket, _Reads]:
    """An upstream that records each read it makes, and echoes each read back (the record comes first)."""
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(("127.0.0.1", 0))
    s.listen(8)
    reads = _Reads()

    def serve() -> None:
        while True:
            try:
                c, _ = s.accept()
            except OSError:
                return
            threading.Thread(target=echo, args=(c,), daemon=True).start()

    def echo(c: socket.socket) -> None:
        try:
            while True:
                data = c.recv(65536)
                if not data:
                    reads.eof.set()
                    c.close()
                    return
                reads.append(data)
                c.sendall(data)
        except OSError:
            return

    threading.Thread(target=serve, daemon=True).start()
    return s, reads


def _client(port: int) -> socket.socket:
    c = socket.create_connection(("127.0.0.1", port), timeout=HANG_GUARD_S)
    return c


def _recv_exact(c: socket.socket, n: int) -> bytes:
    got = b""
    while len(got) < n:
        chunk = c.recv(n - len(got))
        if not chunk:
            break
        got += chunk
    return got


def _cases(proxy: StreamProxy, reads: list, failures: list) -> None:
    """Every control held to its effect as the ends see it."""

    def check(label: str, cond: bool, detail: str = "") -> None:
        if not cond:
            failures.append(f"{label}: {detail}")

    port = proxy.port
    base = proxy.stats()

    # Forwarding, and Rule 1: whoever has the echo has the count.
    c = _client(port)
    c.sendall(b"hello")
    check("forward: the echo comes back", _recv_exact(c, 5) == b"hello")
    st = proxy.stats()
    check("stats: the bytes are counted by the time they are seen", st.up - base.up == 5 and st.down - base.down == 5, str(st))
    check("live: one connection held", proxy.live() == 1, str(proxy.live()))

    # close_all: an orderly release is an EOF at the client (and never a reset), even with data in flight.
    c.sendall(b"y" * 20000)
    ended = proxy.close_all()
    check("close_all: it released the one connection", ended == 1, str(ended))
    try:
        while c.recv(65536):
            pass
        eof = True
    except ConnectionResetError:
        eof = False
    check("close_all: the client reads to EOF with no reset, though data was in flight", eof)
    c.close()
    proxy.wait(lambda s: s.closed >= base.closed + 1, "the pair closed once both ends had")
    check("close_all: the proxy holds none", proxy.live() == 0, str(proxy.live()))

    # reset_all: an abortive release is a reset at the client.
    c = _client(port)
    c.sendall(b"x")
    _recv_exact(c, 1)
    proxy.reset_all()
    try:
        got = c.recv(16)
        check("reset_all: the client is reset", False, f"read {got!r}")
    except ConnectionResetError:
        pass
    c.close()
    check("reset_all: the proxy holds none", proxy.live() == 0, str(proxy.live()))

    # blackhole: the ends are alive and silent; what is sent is counted dropped and not forwarded.
    c = _client(port)
    c.sendall(b"a")
    _recv_exact(c, 1)
    up_before = proxy.stats().up
    reads_before = len(reads)
    proxy.blackhole(True)
    dropped_before = proxy.stats().dropped
    c.sendall(b"dropped")
    proxy.wait(lambda s: s.dropped >= dropped_before + 7, "the bytes were dropped")
    st = proxy.stats()
    check("blackhole: nothing was forwarded", st.up == up_before and len(reads) == reads_before, str(st))
    check("blackhole: the connection is still held", proxy.live() == 1, str(proxy.live()))
    c.settimeout(0.3)
    try:
        got = c.recv(16)
        check("blackhole: the client hears nothing", False, f"read {got!r}")
    except socket.timeout:
        pass
    c.settimeout(HANG_GUARD_S)
    proxy.blackhole(False)
    c.sendall(b"b")
    check("blackhole: forwarding resumes when it is off", _recv_exact(c, 1) == b"b")
    c.close()
    proxy.wait(lambda s: s.closed >= base.closed + 3, "the pair of the black hole case ended")

    # blackhole and a close: an end that closes its own under a black hole is not heard by the other, and
    # the close is delivered when the black hole ends (the half-open case ends at the OTHER end's lease and
    # never at the first end's own).
    reads.eof.clear()
    c = _client(port)
    c.sendall(b"a")
    _recv_exact(c, 1)
    swallowed_before = proxy.stats().swallowed
    proxy.blackhole(True)
    c.shutdown(socket.SHUT_WR)
    proxy.wait(lambda s: s.swallowed >= swallowed_before + 1, "the close was swallowed")
    # An absence can only be shown by waiting; the wait is bounded and can only turn a broken proxy red
    # (a correct one passes at any speed), the same asymmetry as the data case above.
    check("blackhole: the far end did not hear the close", not reads.eof.wait(0.3))
    check("blackhole: the connection is still held after a close", proxy.live() == 1, str(proxy.live()))
    proxy.blackhole(False)
    check("blackhole: the swallowed close is delivered when it ends", reads.eof.wait(HANG_GUARD_S))
    c.close()
    proxy.wait(lambda s: s.closed >= base.closed + 4, "the pair ended once the close was delivered")

    # blackhole and a stop: a pump parked by a swallowed close does not hold the proxy up.
    c = _client(port)
    c.sendall(b"a")
    _recv_exact(c, 1)
    swallowed_before = proxy.stats().swallowed
    proxy.blackhole(True)
    c.close()
    proxy.wait(lambda s: s.swallowed >= swallowed_before + 1, "the close was swallowed again")
    proxy.reset_all()  # the abort wakes the parked pump, and the pair ends
    proxy.wait(lambda s: s.closed >= base.closed + 5, "the parked pair was ended by an abort")
    proxy.blackhole(False)

    # reject: the listener is there, the connect succeeds and the connection is reset at once, never reaching
    # the upstream; every attempt is stamped, in order, and a joined connection is stamped too.
    attempts_before = len(proxy.stats().attempts)
    up_reads = len(reads)
    proxy.reject(True)
    for _ in range(3):
        c = _client(port)  # the connect itself succeeds: the kernel completed the handshake
        try:
            got = c.recv(16)
            check("reject: the dialled connection is reset", False, f"read {got!r}")
        except ConnectionResetError:
            pass
        c.close()
    st = proxy.wait(lambda s: s.rejected >= 3, "three connections were rejected")
    stamps = st.attempts[attempts_before:]
    check("reject: three attempts were stamped", len(stamps) == 3, str(stamps))
    check("reject: the stamps are in time order", stamps == sorted(stamps), str(stamps))
    check("reject: nothing reached the upstream", len(reads) == up_reads, f"{len(reads)} vs {up_reads}")
    proxy.reject(False)
    c = _client(port)
    c.sendall(b"ok")
    check("reject: when it is off the connection is joined", _recv_exact(c, 2) == b"ok")
    check("reject: and the joined attempt is stamped as well", len(proxy.stats().attempts) == attempts_before + 4)
    c.close()

    # refuse: a closed listener refuses a connect, held connections stay, and it comes back.
    c = _client(port)
    proxy.refuse(True)
    try:
        socket.create_connection(("127.0.0.1", port), timeout=HANG_GUARD_S).close()
        check("refuse: a connect is refused", False, "it connected")
    except ConnectionRefusedError:
        pass
    c.sendall(b"still")
    check("refuse: a held connection still works", _recv_exact(c, 5) == b"still")
    proxy.refuse(False)
    try:
        socket.create_connection(("127.0.0.1", port), timeout=HANG_GUARD_S).close()
    except OSError as e:
        failures.append(f"refuse: the listener did not come back: {e!r}")
    c.close()

    # segment: the proxy's writes are small pieces, whatever the far end's reads make of them.
    c = _client(port)
    proxy.segment(3)
    n = len(proxy.stats().writes)
    c.sendall(b"0123456789")
    check("segment: the bytes arrive unchanged", _recv_exact(c, 10) == b"0123456789")
    up_writes = [size for d, size in proxy.stats().writes[n:] if d == "up"]
    check("segment: every write the proxy made towards the upstream is at most 3 bytes", up_writes and max(up_writes) <= 3, str(up_writes))
    check("segment: and there was more than one", len(up_writes) > 1, str(up_writes))
    proxy.segment(None)

    # hold / flush: two writes apart are ONE write once the barrier is lifted; nothing is forwarded before.
    proxy.hold(True)
    n = len(proxy.stats().writes)
    up_before = proxy.stats().up
    log0 = len(proxy.stats().held_log)  # before the writes: a read the proxy buffers early must still be in view
    c.sendall(b"ab")
    c.sendall(b"cd")
    # The barrier is a content the buffer holds, as the log of what was buffered says it, and not a size.
    proxy.wait(
        lambda s: b"abcd" in b"".join(d for k, d in s.held_log[log0:] if k == "up"), "the two writes buffered"
    )
    check("hold: nothing was forwarded while held", proxy.stats().up == up_before, str(proxy.stats()))
    made = proxy.release()
    check("hold: release returns the one write it made, and no other", made == [("up", 4)], str(made))
    c.sendall(b"ef")  # read after the end of the hold: it goes after the buffer, never ahead of it
    check("hold: the bytes arrive unchanged and in order", _recv_exact(c, 6) == b"abcdef")
    up_writes = [size for d, size in proxy.stats().writes[n:] if d == "up"]
    check("hold: the buffer was one write and what followed another", up_writes == [4, 2], str(up_writes))
    check("hold: nothing is left held", proxy.stats().held == 0, str(proxy.stats()))
    # A connection made while the hold is on is held too, and the hold ends on it with the rest.
    proxy.hold(True)
    c2 = _client(port)
    c2.sendall(b"zz")
    proxy.wait(lambda s: b"zz" in b"".join(d for k, d in s.held_log if k == "up"), "a new connection's bytes held")
    proxy.release()
    check("hold: a connection made during the hold is held and released", _recv_exact(c2, 2) == b"zz")
    c2.close()
    c.close()


def _run_once() -> list[str]:
    failures: list[str] = []
    server, reads = _server()
    proxy = StreamProxy(("127.0.0.1", 0), server.getsockname()).start()
    try:
        _cases(proxy, reads, failures)
    except (OSError, TimeoutError) as e:
        failures.append(f"an unexpected error ended the cases early: {e!r}")
    finally:
        proxy.stop()
        try:
            proxy.stop()  # a second stop is a no-op: it must not touch the pipe the first one closed
        except OSError as e:
            failures.append(f"stop: a second stop failed: {e!r}")
        server.close()
    return failures


def selftest(runs: int = 1, load: int = 0) -> int:
    # The load is processes of their own, so it competes for the cores and not for this interpreter's lock.
    burners = [
        subprocess.Popen([sys.executable, "-c", "while True: pass"], stdin=subprocess.DEVNULL)
        for _ in range(load)
    ]
    failures: list[str] = []
    try:
        for i in range(runs):
            for f in _run_once():
                failures.append(f"run {i + 1}: {f}")
    finally:
        for p in burners:
            p.kill()
        for p in burners:
            p.wait()
    if failures:
        sys.stderr.write("stream_fault selftest FAIL:\n" + "\n".join(f"  {f}" for f in failures[:20]) + "\n")
        return 1
    print(f"stream_fault selftest: OK ({runs} run(s))")
    return 0


if __name__ == "__main__":
    args = sys.argv[1:]
    if args[:1] == ["--selftest"]:
        sys.exit(selftest())
    if args[:1] == ["--stress"] and len(args) >= 2:
        sys.exit(selftest(int(args[1]), load=int(args[2]) if len(args) > 2 else 0))
    sys.stderr.write("usage: stream_fault.py --selftest | --stress N [BUSY_THREADS]\n")
    sys.exit(64)
