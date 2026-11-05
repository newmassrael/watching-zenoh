#!/usr/bin/env python3
# SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
# SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
"""R4315 (no register item) -- the steps for what only a stream suffers, of the node verdict.

The debt this answers for is the one `admin_node_verdict.py` states (open-debt item 876): a verdict that
is the program's output and not a transcription. HARDWARE_VERDICT.md, "The steps for what only a stream
suffers (design)", is the design; this is its first steps, and a reference model that holds them.

## What a step is

A stimulus the host applies (a fault on one leg, made by `stream_fault.StreamProxy`), an observation the
host reads through the node's admin surface on the OTHER leg, and a comparison that is a pure function
of what was observed. The comparisons are here and nothing else decides a step; the selftest breaks
each in turn.

## The steps of this slice

  HW.36  an orderly release by the peer ends that peer's session and no other, and is noticed at once:
         within a bound that a lease could not meet, so a node that waits out its lease fails.
  HW.37  an abortive release (a RST) by the peer: the same.
  HW.38  conservation and re-establishment: after every release, the node takes the peer back and holds
         one session for it, through more releases than the node has cells (so a cell lost on a release is
         a node that stops accepting).
  HW.39  silence: a peer that falls silent with its connection open (a black hole on the leg, which also
         swallows the close the peer's own lease would make) is detected by the LEASE: its session ends,
         no other does, not before the earliest moment a lease could have run out (a node that drops a
         quiet peer early breaks the lease) and not after the lease and one more keep-alive interval, and
         the peer is taken back.

## Where the numbers come from

Not from a run. The node's contract states them: the lease it advertises and the keep-alives in it, the
retry schedule of a dial (upstream's, restarted for each outage), and the cells of its connection pool.
`SPEC` is the program's copy, and `check_spec_against_source` holds it equal to the node's own source, so a
constant that moves is a failure that names it. A bound read off the host's clock is a GUARD against a hang:
a property of NOT happening, so a run that fails it failed by never and not by lateness. The one bound
that separates two behaviours (a release noticed at once from one noticed by the lease) sits below the
earliest moment a lease could have expired, which is derived from the contract.

## The reference model, and why it is the acceptance test

`StreamModel` is the contract as a small executable machine on a virtual clock, driven by the same
faults the real proxies apply. A step is accepted when each way a node can break its property is caught
by exactly the step that holds it and by no other, and when the comparison weakened lets the fault
through: a model with a cell lost on a reset must red HW.38 and not HW.36 or HW.37; a model that ignores a
FIN until the lease must red HW.36; a model that never takes its peer back must red HW.38 and leave
HW.37 not run. The node that passes is evidence only after the models that fail have been caught.
"""

from __future__ import annotations

import re
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Protocol

ROOT = Path(__file__).resolve().parents[2]

A_ID = "a" * 16
B_ID = "b" * 16


@dataclass(frozen=True)
class StreamSpec:
    """The node's contract, as far as the stream steps need it."""

    lease_ms: int = 10_000  # the lease the node advertises (SessionInitParams.lease_ms)
    keep_alive_per_lease: int = 4  # keep-alives in one lease (KeepAliveConf, upstream's default)
    retry_init_ms: int = 1_000  # a dial's first wait (RetryPolicy::ZENOH_DEFAULT)
    retry_max_ms: int = 4_000  # and its ceiling
    retry_factor: float = 2.0
    cells: int = 3  # the connection pool: one for each session and one waiting to be taken
    sessions: int = 2  # sessions the node holds at most

    @property
    def earliest_lease_detection_ms(self) -> int:
        """The soonest a node that waits for its lease can notice a peer that went away: the last
        keep-alive it heard was at most one keep-alive interval before, so the lease runs out no sooner
        than a lease less that interval after the peer was lost."""
        return self.lease_ms - self.lease_ms // self.keep_alive_per_lease

    @property
    def prompt_bound_ms(self) -> int:
        """What 'at once' means: three quarters of the earliest moment a lease could have expired, so a
        release noticed by a close is inside it and a release noticed by the lease is not."""
        return self.earliest_lease_detection_ms * 3 // 4

    @property
    def silence_bound_ms(self) -> int:
        """The latest a lease can be noticed: it runs out at most a lease after the last thing the node
        heard, and a node that looks at it once per keep-alive interval sees it one interval later. The
        peer here is the stock router, whose own lease is the default 10 s, the node's own figure."""
        return self.lease_ms + self.lease_ms // self.keep_alive_per_lease

    @property
    def return_guard_ms(self) -> int:
        """How long a peer that was released may take to be back: the guard for the peer's own redial,
        which is upstream's schedule (three of its longest waits, for a dial that fails twice first)."""
        return 3 * self.retry_max_ms

    @property
    def cycles(self) -> int:
        """Releases enough to lose every cell, and two more: a node that loses one cell for each release
        stops accepting before the last."""
        return self.cells + 2


SPEC = StreamSpec()

SENTENCES = {
    36: "an orderly release by the peer ends its session and no other, at once",
    37: "an abortive release by the peer ends its session and no other, at once",
    38: "the node takes its peer back after every release and holds one session for it",
    39: "a peer that falls silent is detected by the lease and only its session ends, and it is taken back",
}
STEPS = (36, 37, 38, 39)
#: What the grammar's `<...>` is for a step that was not run or could not be judged (the printed sentence
#: is an instance of the grammar either way).
UNRUN_TAIL = {38: ": 0 of 0 returned", 39: ": after 0 ms"}


def unrun_sentence(step: int) -> str:
    return SENTENCES[step] + UNRUN_TAIL.get(step, "")


# ------------------------------------------------------------------------------- the comparisons --


def judge_release(sessions: set[str] | None, elapsed_ms: float, spec: StreamSpec = SPEC) -> bool:
    """The released peer is gone, the other is kept, and it was noticed within the prompt bound."""
    return sessions == {B_ID} and elapsed_ms <= spec.prompt_bound_ms


def judge_silence(
    sessions: set[str] | None, elapsed_ms: float, back: bool, spec: StreamSpec = SPEC
) -> bool:
    """The silent peer is gone and the other kept, it was noticed by the lease (no sooner than a lease
    could have run out, no later than the lease and one keep-alive interval), and the peer came back."""
    return (
        sessions == {B_ID}
        and spec.earliest_lease_detection_ms <= elapsed_ms <= spec.silence_bound_ms
        and back
    )


def judge_conservation(returns: list[tuple[str, bool]], final: set[str] | None) -> bool:
    """Every release was followed by the peer's return, and the node holds the two sessions, one each."""
    return bool(returns) and all(ok for _, ok in returns) and final == {A_ID, B_ID}


# ------------------------------------------------------------------------------------------ env --


class StreamEnv(Protocol):
    """What the steps need of the host: the sessions the node reports through a router, a fault on a
    leg, and time. The real host implements it with routers, proxies and the host's clock, and the
    reference model with a virtual one."""

    def sessions(self, via: str) -> set[str] | None: ...
    def fault(self, leg: str, action: str) -> int: ...
    def sleep(self, seconds: float) -> None: ...
    def now(self) -> float: ...


@dataclass
class Result:
    step: int
    held: bool | None  # None: not run
    sentence: str
    fail_text: str = ""


def _await(env: StreamEnv, pred: Callable[[], bool], guard_s: float, interval_s: float) -> tuple[bool, float]:
    """Wait for a state, and say how long it took in the env's clock. The guard is a hang guard."""
    start = env.now()
    while True:
        if pred():
            return True, (env.now() - start) * 1000.0
        if env.now() - start >= guard_s:
            return False, (env.now() - start) * 1000.0
        env.sleep(interval_s)


def _changed(env: StreamEnv, both: set[str]) -> bool:
    """The node's sessions read, and they are no longer both: an unreadable answer is not yet a state."""
    seen = env.sessions("B")
    return seen is not None and seen != both


def _released(
    env: StreamEnv, action: str, spec: StreamSpec, interval_s: float
) -> tuple[int, float, bool, set[str] | None]:
    """Release the connection of A, and read how the node took it: (connections the fault landed on,
    milliseconds until the node's sessions were no longer both, whether they were, the sessions then).

    The leg is closed to new connections first (counter before effect: the refusal is in place before the
    release), so the absence of A's session is a state that holds until it is read and not a moment that a
    router redialling at once would have passed; the leg is opened again when it has been read, whatever
    happened. The wait runs to the hang guard (two leases), not to the bound: how long the node took is
    measured here and judged by `judge_release` alone, so the comparison is the only decider."""
    env.fault("A", "refuse")
    try:
        landed = env.fault("A", action)
        if landed == 0:
            return 0, 0.0, False, None
        settled, ms = _await(env, lambda: _changed(env, {A_ID, B_ID}), spec.lease_ms * 2 / 1000, interval_s)
        return landed, ms, settled, env.sessions("B")
    finally:
        env.fault("A", "admit")


def _silenced(
    env: StreamEnv, spec: StreamSpec, interval_s: float
) -> tuple[int, float, set[str] | None, bool]:
    """Make the leg to A a black hole (the connection stays open and nothing crosses, and a close either end
    makes is not heard by the other), and read how the node took it: (connections it landed on,
    milliseconds until the node's sessions were no longer both, the sessions then, whether the peer was
    back after the black hole ended).

    The leg is closed to new connections for the measurement, as in `_released`, so the only way the node
    can lose A is its own lease. The black hole ends when the node has been read, whatever happened, and
    the leg is opened after it; then the peer's return is awaited."""
    both = {A_ID, B_ID}
    env.fault("A", "refuse")
    try:
        landed = env.fault("A", "silence")
        if landed == 0:
            return 0, 0.0, None, False
        try:
            _, ms = _await(env, lambda: _changed(env, both), spec.lease_ms * 2 / 1000, interval_s)
            seen = env.sessions("B")
        finally:
            env.fault("A", "speak")
    finally:
        env.fault("A", "admit")
    back, _ = _await(env, lambda: env.sessions("B") == both, spec.return_guard_ms / 1000, interval_s)
    return landed, ms, seen, back


def run_stream_steps(env: StreamEnv, spec: StreamSpec = SPEC, interval_s: float = 0.2) -> list[Result]:
    """Run HW.36 to HW.39 against a node holding sessions with routers A and B, the leg to A through a
    proxy. A fault on that leg is observed through B, so no step asks a connection about its own end."""
    out: dict[int, Result] = {}
    both = {A_ID, B_ID}
    returns: list[tuple[str, bool]] = []

    def fixture() -> bool:
        ok, _ = _await(env, lambda: env.sessions("B") == both, spec.return_guard_ms / 1000, interval_s)
        return ok

    def restore(label: str) -> bool:
        ok, ms = _await(env, lambda: env.sessions("B") == both, spec.return_guard_ms / 1000, interval_s)
        returns.append((f"{label}: {'back in %.0f ms' % ms if ok else 'not back in %.0f ms' % ms}", ok))
        return ok

    def release(step: int, action: str) -> bool:
        """Apply the fault, wait for the peer to go, judge. False where the step could not be judged."""
        landed, ms, _, seen = _released(env, action, spec, interval_s)
        if landed == 0:
            out[step] = Result(step, False, SENTENCES[step], "the fault landed on no connection: the leg to A held none")
            return False
        if judge_release(seen, ms, spec):
            out[step] = Result(step, True, SENTENCES[step])
        else:
            if seen is None or (seen != both and seen != {B_ID}):
                why = f"B lost too or the answer was unreadable: sessions {sorted(seen) if seen is not None else None}"
            elif seen == both:
                why = f"the peer was still listed after {ms:.0f} ms (guard reached)"
            else:
                why = (
                    f"the peer went after {ms:.0f} ms and the bound is {spec.prompt_bound_ms} ms "
                    f"(a lease runs out no sooner than {spec.earliest_lease_detection_ms} ms)"
                )
            out[step] = Result(step, False, SENTENCES[step], f"{action} release FAIL: {why}")
        return True

    if not fixture():
        for step in STEPS:
            out[step] = Result(
                step, False, unrun_sentence(step), "the fixture was not established: the node does not hold A and B"
            )
        return [out[s] for s in STEPS]

    release(36, "close")
    back = restore("after the orderly release")
    if back:
        release(37, "reset")
        back = restore("after the reset")
    else:
        out[37] = Result(37, None, SENTENCES[37], "not run: the peer was not back after the release before it (HW.38 holds that)")
    if back:
        for i in range(spec.cycles):
            action = ("close", "reset")[i % 2]
            landed, _, gone, _ = _released(env, action, spec, interval_s)
            if landed == 0:
                returns.append((f"cycle {i + 1}: the fault landed on no connection", False))
                back = False
                break
            if not gone:
                returns.append((f"cycle {i + 1}: the peer was never noticed gone", False))
                back = False
                break
            if not restore(f"cycle {i + 1} ({action})"):
                back = False
                break
    final = env.sessions("B")
    tally = f"{sum(1 for _, good in returns if good)} of {len(returns)} returned"
    conserved = judge_conservation(returns, final)
    if conserved:
        out[38] = Result(38, True, f"{SENTENCES[38]}: {tally}")
    else:
        failed = [label for label, good in returns if not good]
        out[38] = Result(
            38,
            False,
            f"{SENTENCES[38]}: {tally}",
            f"re-establishment FAIL: {failed[0] if failed else 'the node ended without both sessions'}; "
            f"sessions {sorted(final) if final is not None else None} after {len(returns)} release(s)",
        )

    if not conserved:
        out[39] = Result(39, None, unrun_sentence(39), "not run: the node did not take its peer back after the releases (HW.38)")
    else:
        landed, ms, seen, back_ok = _silenced(env, spec, interval_s)
        said = f"{SENTENCES[39]}: after {ms:.0f} ms"
        if landed == 0:
            out[39] = Result(39, False, said, "the black hole landed on no connection: the leg to A held none")
        elif judge_silence(seen, ms, back_ok, spec):
            out[39] = Result(39, True, said)
        else:
            if seen is None or (seen != both and seen != {B_ID}):
                why = f"B lost too or the answer was unreadable: sessions {sorted(seen) if seen is not None else None}"
            elif seen == both:
                why = f"the silent peer was still listed after {ms:.0f} ms (guard reached): the lease was never enforced"
            elif ms < spec.earliest_lease_detection_ms:
                why = (
                    f"the silent peer was dropped after {ms:.0f} ms, before a lease could have run out "
                    f"({spec.earliest_lease_detection_ms} ms): a quiet peer is not a dead one"
                )
            elif ms > spec.silence_bound_ms:
                why = f"the silent peer was dropped after {ms:.0f} ms, past the lease and a keep-alive interval ({spec.silence_bound_ms} ms)"
            else:
                why = f"the peer was not taken back within {spec.return_guard_ms} ms of the black hole ending"
            out[39] = Result(39, False, said, f"silence FAIL: {why}")
    return [out[s] for s in STEPS]


# -------------------------------------------------------------------- the reference model --------


FAULTS = (
    "leak_on_reset",  # a RST does not give the connection's cell back
    "leak_on_close",  # an orderly close does not give it back
    "fin_ignored",  # an orderly close is noticed only when the lease runs out
    "accept_stuck",  # after the first release the node accepts no more
    "reset_ignored",  # a RST is noticed only when the lease runs out
    "kills_other",  # a release of A's connection ends B's session too
    "silence_never_detected",  # a peer that goes silent is held for ever: the lease is never enforced
    "silence_premature",  # a peer that goes quiet is dropped after a second, long before its lease
)


class StreamModel:
    """The contract of the node's stream links, on a virtual clock. It is what the steps are accepted by:
    each fault is a way a node can break one property, and the steps must catch it where it belongs."""

    A_REDIAL_S = 1.0  # router A's own first redial, upstream's schedule

    def __init__(self, spec: StreamSpec = SPEC, faults: tuple[str, ...] = ()) -> None:
        self.spec, self.faults = spec, frozenset(faults)
        self.t = 0.0
        self.sess = {A_ID: True, B_ID: True}
        self.cells_used = 2
        self.refusing = False  # the proxy's listener is closed: A's dial is refused and retried
        self.events: list[tuple[float, str, str]] = []  # (at, kind, peer)
        self.released = 0

    def _free_cell(self) -> None:
        self.cells_used = max(0, self.cells_used - 1)

    def advance(self, dt: float) -> None:
        end = self.t + dt
        while True:
            due = sorted(e for e in self.events if e[0] <= end)
            if not due:
                break
            at, kind, peer = due[0]
            self.events.remove(due[0])
            self.t = at
            if kind == "gone" and self.sess.get(peer):
                self.sess[peer] = False
            elif kind == "free":
                self._free_cell()
            elif kind == "back":
                stuck = "accept_stuck" in self.faults and self.released > 0
                if self.sess.get(peer):
                    pass  # the node never lost this peer, so there is nothing to take back
                elif self.refusing or stuck or self.cells_used >= self.spec.cells:
                    self.events.append((self.t + self.A_REDIAL_S, "back", peer))  # the peer tries again
                else:
                    self.cells_used += 1
                    self.sess[peer] = True
        self.t = end

    # StreamEnv
    def sessions(self, via: str) -> set[str] | None:
        return {p for p, up in self.sess.items() if up}

    def fault(self, leg: str, action: str) -> int:
        if leg == "A" and action in ("refuse", "admit"):
            self.refusing = action == "refuse"
            return 1
        if leg == "A" and action == "speak":
            return 1  # the black hole ends; what the node does about a silent peer was decided when it began
        if leg != "A" or not self.sess.get(A_ID):
            return 0
        if action == "silence":
            # Nothing crosses and no close is heard, so the node can lose the peer only by its lease.
            self.released += 1
            if "silence_never_detected" not in self.faults:
                lost = 1.0 if "silence_premature" in self.faults else self.spec.lease_ms / 1000.0
                self.events.append((self.t + lost, "gone", A_ID))
                self.events.append((self.t + lost, "free", A_ID))
                self.events.append((self.t + lost + self.A_REDIAL_S, "back", A_ID))
            return 1
        self.released += 1
        detect = 0.05
        if (action == "close" and "fin_ignored" in self.faults) or (action == "reset" and "reset_ignored" in self.faults):
            detect = self.spec.lease_ms / 1000.0
        self.events.append((self.t + detect, "gone", A_ID))
        if "kills_other" in self.faults:
            self.events.append((self.t + detect, "gone", B_ID))
        leaks = (action == "reset" and "leak_on_reset" in self.faults) or (
            action == "close" and "leak_on_close" in self.faults
        )
        if not leaks:
            self.events.append((self.t + detect, "free", A_ID))
        self.events.append((self.t + detect + self.A_REDIAL_S, "back", A_ID))
        return 1

    def sleep(self, seconds: float) -> None:
        self.advance(seconds)

    def now(self) -> float:
        return self.t


# ---------------------------------------------------------------------------- the drift check ------


def check_spec_against_source(spec: StreamSpec = SPEC, root: Path = ROOT) -> list[str]:
    """Hold the program's copy of the contract equal to the node's own source."""
    problems: list[str] = []

    def read(rel: str) -> str:
        try:
            return (root / rel).read_text()
        except OSError as e:
            problems.append(f"{rel}: {e}")
            return ""

    retry = read("crates/wz-session-core/src/retry_period.rs")
    m = re.search(r"ZENOH_DEFAULT: Self = Self \{\s*period_init_ms: (\d+),\s*period_max_ms: (\d+),\s*period_increase_factor: ([\d.]+)", retry)
    if not m:
        problems.append("retry_period.rs: no RetryPolicy::ZENOH_DEFAULT found")
    elif (int(m.group(1)), int(m.group(2)), float(m.group(3))) != (spec.retry_init_ms, spec.retry_max_ms, spec.retry_factor):
        problems.append(
            f"retry_period.rs: ZENOH_DEFAULT is {m.groups()} and the steps hold "
            f"{(spec.retry_init_ms, spec.retry_max_ms, spec.retry_factor)}"
        )
    params = read("crates/wz-session-core/src/session_init_params.rs")
    m = re.search(r"KEEP_ALIVE_PER_LEASE: u32 = (\d+)", params)
    if not m or int(m.group(1)) != spec.keep_alive_per_lease:
        problems.append(f"session_init_params.rs: KEEP_ALIVE_PER_LEASE is {m.group(1) if m else None}, the steps hold {spec.keep_alive_per_lease}")
    for rel in (
        "deploy/zephyr-admin-node/rust/src/fixed_tcp.rs",
        "deploy/mcu-admin-node/src/fixed_tcp.rs",
    ):
        src = read(rel)
        m = re.search(r"lease_ms: (\d[\d_]*),", src)
        if not m or int(m.group(1).replace("_", "")) != spec.lease_ms:
            problems.append(f"{rel}: lease_ms is {m.group(1) if m else None}, the steps hold {spec.lease_ms}")
        sessions = re.search(r"const SESSIONS: usize = (\d+);", src)
        queue = re.search(r"const QUEUE: usize = (\d+);", src)
        if not sessions or int(sessions.group(1)) != spec.sessions:
            problems.append(f"{rel}: SESSIONS is {sessions.group(1) if sessions else None}, the steps hold {spec.sessions}")
        if not sessions or not queue or int(sessions.group(1)) + int(queue.group(1)) != spec.cells:
            problems.append(f"{rel}: the cells are SESSIONS + QUEUE, the steps hold {spec.cells}")
    return problems


# ------------------------------------------------------------------------------------- selftest ---


def _held(results: list[Result]) -> dict[int, bool | None]:
    return {r.step: r.held for r in results}


def selftest() -> int:
    failures: list[str] = []

    def check(label: str, cond: bool, detail: str = "") -> None:
        if not cond:
            failures.append(f"{label}: {detail}")

    # The contract the steps hold is the node's.
    drift = check_spec_against_source()
    check("the steps' contract is the node's source", not drift, "; ".join(drift))
    check(
        "the prompt bound is below the earliest lease detection",
        SPEC.prompt_bound_ms < SPEC.earliest_lease_detection_ms == 7500,
        f"{SPEC.prompt_bound_ms} {SPEC.earliest_lease_detection_ms}",
    )

    check(
        "the silence bounds are the earliest detection and the lease and a keep-alive",
        (SPEC.earliest_lease_detection_ms, SPEC.silence_bound_ms) == (7500, 12500),
        f"{SPEC.earliest_lease_detection_ms} {SPEC.silence_bound_ms}",
    )

    # A node that keeps its contract holds all four.
    healthy = run_stream_steps(StreamModel())
    check(
        "healthy: HW.36 to HW.39 held",
        _held(healthy) == {36: True, 37: True, 38: True, 39: True},
        str([(r.step, r.held, r.fail_text) for r in healthy]),
    )
    check(
        "healthy: HW.39 says when the lease was enforced (the lease, to the poll interval)",
        re.search(r": after 10[0-3]\d\d ms$", healthy[3].sentence) is not None,
        healthy[3].sentence,
    )
    check(
        "healthy: HW.38 counts the returns (two releases and the cycles)",
        healthy[2].sentence.endswith(f"{2 + SPEC.cycles} of {2 + SPEC.cycles} returned"),
        healthy[2].sentence,
    )

    # Each way a node breaks a property is caught by the step that holds it, and by no other.
    expect: dict[str, dict[int, bool | None]] = {
        "leak_on_reset": {36: True, 37: True, 38: False, 39: None},
        "leak_on_close": {36: True, 37: True, 38: False, 39: None},
        "fin_ignored": {36: False, 37: True, 38: True, 39: True},
        "reset_ignored": {36: True, 37: False, 38: True, 39: True},
        "accept_stuck": {36: True, 37: None, 38: False, 39: None},
        "kills_other": {36: False, 37: None, 38: False, 39: None},
        "silence_never_detected": {36: True, 37: True, 38: True, 39: False},
        "silence_premature": {36: True, 37: True, 38: True, 39: False},
    }
    check("every fault has an expectation", set(expect) == set(FAULTS), str(set(expect) ^ set(FAULTS)))
    for fault, want in expect.items():
        got = _held(run_stream_steps(StreamModel(faults=(fault,))))
        check(f"{fault}: the steps red exactly where the property is", got == want, f"{got} want {want}")

    # The comparisons weakened let their fault through: the faults are red for the comparison's own sake.
    global judge_release, judge_conservation, judge_silence
    saved = (judge_release, judge_conservation, judge_silence)
    try:
        judge_silence = lambda sessions, elapsed_ms, back, spec=SPEC: sessions == {B_ID} and back  # no lease bounds
        got = _held(run_stream_steps(StreamModel(faults=("silence_premature",))))
        check("weakened HW.39: a peer dropped long before its lease goes green there", got.get(39) is True, str(got))
        judge_silence = saved[2]
        judge_release = lambda sessions, elapsed_ms, spec=SPEC: sessions == {B_ID}  # no promptness
        got = _held(run_stream_steps(StreamModel(faults=("fin_ignored",))))
        check("weakened HW.36: a FIN ignored until the lease goes green there", got.get(36) is True, str(got))
        judge_release = saved[0]
        judge_conservation = lambda returns, final: True
        got = _held(run_stream_steps(StreamModel(faults=("leak_on_reset",))))
        check("weakened HW.38: a cell lost on a reset goes green there", got.get(38) is True, str(got))
    finally:
        judge_release, judge_conservation, judge_silence = saved

    # The comparisons themselves.
    lo, hi = SPEC.earliest_lease_detection_ms, SPEC.silence_bound_ms
    check("judge_silence: detected inside the lease window, the other kept, the peer back", judge_silence({B_ID}, 10000.0, True))
    check("judge_silence: the window's two ends are inside it", judge_silence({B_ID}, float(lo), True) and judge_silence({B_ID}, float(hi), True))
    check("judge_silence: before a lease could run out is premature", not judge_silence({B_ID}, lo - 1.0, True))
    check("judge_silence: after the lease and a keep-alive is late", not judge_silence({B_ID}, hi + 1.0, True))
    check("judge_silence: a peer not taken back is not held", not judge_silence({B_ID}, 10000.0, False))
    check("judge_silence: the other session lost is not kept", not judge_silence(set(), 10000.0, True))
    check("judge_silence: the peer still listed is not detected", not judge_silence({A_ID, B_ID}, 10000.0, True))
    check("judge_silence: an unreadable answer is not detected", not judge_silence(None, 10000.0, True))
    check("judge_release: a peer gone at once and the other kept", judge_release({B_ID}, 200.0))
    check("judge_release: too late is not at once", not judge_release({B_ID}, SPEC.prompt_bound_ms + 1))
    check("judge_release: the other lost is not kept", not judge_release(set(), 10.0))
    check("judge_release: the peer still listed is not gone", not judge_release({A_ID, B_ID}, 10.0))
    check("judge_release: an unreadable answer is not gone", not judge_release(None, 10.0))
    check("judge_conservation: all returned and both held", judge_conservation([("x", True)], {A_ID, B_ID}))
    check("judge_conservation: one not back", not judge_conservation([("x", True), ("y", False)], {A_ID, B_ID}))
    check("judge_conservation: nothing judged is not held", not judge_conservation([], {A_ID, B_ID}))

    # A fixture that was never established is a failure that says so, for every step.
    class Empty(StreamModel):
        def sessions(self, via: str) -> set[str] | None:
            return set()

    got = run_stream_steps(Empty())
    check("no fixture: every step fails and names it", all(r.held is False and "fixture" in r.fail_text for r in got), str(got))

    if failures:
        sys.stderr.write("admin_node_stream_steps selftest FAIL:\n" + "\n".join(f"  {f}" for f in failures) + "\n")
        return 1
    print("admin_node_stream_steps selftest: OK")
    return 0


if __name__ == "__main__":
    if sys.argv[1:] == ["--selftest"]:
        sys.exit(selftest())
    sys.stderr.write("usage: admin_node_stream_steps.py --selftest\n")
    sys.exit(64)
