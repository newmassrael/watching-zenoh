#!/usr/bin/env python3
# SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
# SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
"""R3847 (no register item) -- the stack bound of a fixed-memory image, with the calls through a register followed.

`stack_frame_gate.py` reads the worst chain of DIRECT calls, which is a reading and not a bound: a call
through a register (a trait object, a function pointer, a C callback) hides its callee's frame from it,
and Rounds 3828 and 3842 had read a figure that fell with such a call as if it were a bound. This gate
follows those calls. A register can hold only an address the image holds somewhere (a data word, a
literal pool, a movw/movt pair, an adr), so for each call by register in a function the bound reaches,
`deploy/stack_call_contracts.json` names, among the functions whose address the image holds, the ones its
site may call. A site no rule claims fails the gate: there is no reading of the vtable slot and none of
the method named on the line, because a reading is what the earlier figure was.

What it asserts of an image, in this order:

1. every call by register in a function the bound reaches has a rule (a source file and line from the
   line table, or a C function's name), and a rule that names nobody for a site that uses it is refused;
2. the premise of every rule that says "nobody" (`absent`, `absent_reached`) still holds;
3. no cycle in the call graph other than the recursion the contract declares, with its depth;
4. the bound, which is the worst chain's frames in bytes, equals the figure committed in
   `deploy/resource_budget.json` (`static_bound_bytes`), so that a change which moves it moves the row;
5. the bound stays inside 75 percent of the image's stack (the rule `resource_budget_gate.py` applies
   to the measured peak, applied here to the bound, which is what a margin is for);
6. the stack peak the kit measured is not above the bound. A measurement above a bound is a hole in the
   model, never a bound that holds;
7. the stack of the image is what its bound needs, in units of 64 bytes, and not more than 512 bytes above
   it: the reservation is a function of the bound, so a bound that falls gives the RAM back;
8. a rule with no line (a whole file, a whole C function) pins, for each image, how many calls through a
   register it claims, so that a call added to such a file is read against the rule's callees and is not
   claimed in silence.

What the bound still rests on, stated: the rules are written by a person and read against the code; other
threads and interrupts are taken to run on their own stacks; the recursion the contract declares has the
depth it declares; a panic path ends in an abort and is cold. The image has to be built with line tables
(`CARGO_PROFILE_RELEASE_DEBUG=line-tables-only`, which the kit lane sets), whose text is the shipped one.

    stack_bound_gate.py --check KEY --elf ELF     the gate, for an image of stack_frame_gate.IMAGES
    stack_bound_gate.py --emit KEY --elf ELF      the bound and the worst chain, nothing asserted
    stack_bound_gate.py --list                    the images whose row commits a bound
    stack_bound_gate.py --selftest                each rule of the gate driven on a small model
"""
from __future__ import annotations

import argparse
import bisect
import json
import re
import subprocess
import sys
from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import stack_frame_gate as g  # noqa: E402

ROOT = HERE.parents[1]
CONTRACTS = ROOT / "deploy" / "stack_call_contracts.json"
BUDGET = ROOT / "deploy" / "resource_budget.json"

#: The share of the stack a bound may take: `bound * MARGIN_DEN <= stack * MARGIN_NUM`.
MARGIN_NUM, MARGIN_DEN = 3, 4

SITE = re.compile(r"^\s*([0-9a-f]+):\s+blx\s+(?:r\d+|ip)\s*$")
MOVW = re.compile(r"^\s*([0-9a-f]+):\s+movw\s+(r\d+|ip),\s*#(\d+)")
MOVT = re.compile(r"^\s*([0-9a-f]+):\s+movt\s+(r\d+|ip),\s*#(\d+)")
ADR = re.compile(
    r"^\s*([0-9a-f]+):\s+(?:adr(?:\.w|\.n)?|add(?:\.w)?)\s+(?:r\d+|ip),\s*"
    r"(?:pc,\s*#\d+\s*@\s*\(adr\s+r\d+,\s*|)([0-9a-f]{6,8})\b"
)


# ── the model of an image ───────────────────────────────────────────────────────────────────────────


@dataclass
class Func:
    start: int
    name: str  # as objdump demangles it
    norm: str  # the same without generic arguments
    frame: int
    calls: set[int] = field(default_factory=set)  # direct calls, to other functions
    sites: list[int] = field(default_factory=list)  # addresses of its calls by register


@dataclass
class Model:
    funcs: dict[int, Func]
    taken: dict[int, str]  # the functions whose address the image holds, by norm name
    waker: set[int]  # the four functions of the executor's RawWakerVTable
    where: dict[int, tuple[str, int | None]]  # a call by register: its source file and line
    entry: str


def norm(name: str) -> str:
    """The name without generic arguments; `<A<B> as T>::m` keeps its qualified-path brackets."""
    out: list[str] = []
    i, n = 0, len(name)
    while i < n:
        ch = name[i]
        if ch == "<":
            prev = name[i - 1] if i else " "
            depth, j = 1, i + 1
            while j < n and depth:
                depth += (name[j] == "<") - (name[j] == ">")
                j += 1
            inner = name[i + 1 : j - 1]
            if prev.isalnum() or prev in "_>:#}":
                if prev == ":" and out[-2:] == [":", ":"]:
                    del out[-2:]  # the turbofish `::<..>` goes whole
                i = j  # generic arguments: dropped
                continue
            out.append("<" + norm(inner) + ">")
            i = j
            continue
        out.append(ch)
        i += 1
    return "".join(out)


def _run(*argv: str) -> str:
    return subprocess.run(argv, capture_output=True, text=True, check=True).stdout


def load(elf: str, entry: str) -> Model:
    """Read an ELF: its functions with their frames and calls, the addresses it holds, the source lines."""
    dis = _run("arm-none-eabi-objdump", "-d", "--no-show-raw-insn", "-C", elf)
    blocks: list[tuple[int, str, list[str]]] = []
    for line in dis.splitlines():
        head = g._HEAD.match(line)
        if head:
            blocks.append((int(head.group(1), 16), head.group(2), [line]))
        elif blocks:
            blocks[-1][2].append(line)
    starts = [b[0] for b in blocks]
    func_start = set(starts)
    funcs: dict[int, Func] = {}
    for start, name, lines in blocks:
        found = g.frames("\n".join(lines))
        fn = Func(start, name, norm(name), found[0][0] if found else 0)
        for line in lines[1:]:
            call = g._CALL.search(line)
            if call:
                at = _owner(starts, int(call.group(1), 16))
                if at is not None and at != start:
                    fn.calls.add(at)
            site = SITE.match(line)
            if site:
                fn.sites.append(int(site.group(1), 16))
        funcs[start] = fn

    # every word of every allocated section, and the addresses the code builds itself
    words = _alloc_words(elf)
    taken_at: set[int] = set()
    for w in words.values():
        if (w & 1) and (w - 1) in func_start:
            taken_at.add(w - 1)
    pending: dict[str, int] = {}
    for line in dis.splitlines():
        mw = MOVW.match(line)
        if mw:
            pending[mw.group(2)] = int(mw.group(3))
            continue
        mt = MOVT.match(line)
        if mt and mt.group(2) in pending:
            val = (int(mt.group(3)) << 16) | pending.pop(mt.group(2))
            if (val & 1) and (val - 1) in func_start:
                taken_at.add(val - 1)
        ma = ADR.match(line)
        if ma:
            tgt = int(ma.group(2), 16)
            for cand in (tgt, tgt - 1):
                if cand in func_start:
                    taken_at.add(cand)
    taken = {a: funcs[a].norm for a in taken_at}

    waker: set[int] = set()
    for fn in funcs.values():
        if fn.norm == "wz_runtime_coop::executor_static::waker_clone":
            for addr, w in words.items():
                if w == fn.start + 1:
                    for j in range(4):
                        v = words.get(addr + 4 * j)
                        if v is not None and (v - 1) in func_start:
                            waker.add(v - 1)

    sites = [a for fn in funcs.values() if "::" in fn.name for a in fn.sites]
    return Model(funcs, taken, waker, _locate(elf, sites), entry)


def _owner(starts: list[int], addr: int) -> int | None:
    at = bisect.bisect_right(starts, addr) - 1
    return starts[at] if at >= 0 else None


def _alloc_words(elf: str) -> dict[int, int]:
    header = _run("arm-none-eabi-objdump", "-h", elf).splitlines()
    sections = []
    for i, line in enumerate(header):
        m = re.match(r"\s*\d+\s+(\S+)\s+[0-9a-f]+\s+[0-9a-f]+\s+[0-9a-f]+", line)
        if m and i + 1 < len(header) and "ALLOC" in header[i + 1]:
            sections.append(m.group(1))
    words: dict[int, int] = {}
    for sec in sections:
        for line in _run("arm-none-eabi-objdump", "-s", "-j", sec, elf).splitlines():
            m = re.match(r"\s([0-9a-f]{4,8})\s+((?:[0-9a-f]{8}\s?){1,4})", line)
            if not m:
                continue
            base = int(m.group(1), 16)
            for k, w in enumerate(m.group(2).split()):
                words[base + 4 * k] = int.from_bytes(bytes.fromhex(w), "little")
    return words


def _locate(elf: str, addrs: list[int]) -> dict[int, tuple[str, int | None]]:
    """The innermost source file and line of each address, from the line table."""
    out: dict[int, tuple[str, int | None]] = {}
    if not addrs:
        return out
    text = _run("arm-none-eabi-addr2line", "-a", "-i", "-f", "-C", "-e", elf, *[hex(a) for a in addrs])
    lines = text.splitlines()
    k = 0
    while k < len(lines):
        if lines[k].startswith("0x"):
            at = int(lines[k], 16)
            if k + 2 < len(lines) and not lines[k + 1].startswith("0x"):
                path, _, ln = lines[k + 2].rpartition(":")
                ln = ln.split()[0] if ln else ""
                out[at] = (path, int(ln) if ln.isdigit() and int(ln) > 0 else None)
            k += 1
        else:
            k += 1
    return out


# ── the contract and the analysis ───────────────────────────────────────────────────────────────────


@dataclass
class Result:
    claims: dict[str, int] = field(default_factory=dict)  # rule id -> its sites in the functions reached
    unclaimed: list[tuple[str, str]] = field(default_factory=list)  # (function, where)
    empty_rules: list[str] = field(default_factory=list)  # rules that name nobody but are used
    premises: list[str] = field(default_factory=list)  # a NONE rule whose premise has failed
    cycles: list[tuple[str, str]] = field(default_factory=list)  # undeclared
    unused: list[str] = field(default_factory=list)  # rules no site of this image used
    reached: int = 0
    sites: int = 0
    bound: int = 0
    chain: list[tuple[int, str]] = field(default_factory=list)
    # The graph the bound was read from, for a reader that asks for another path than the worst (a
    # function's deepest path, which the measured peak of a run may be on and the bound is not).
    edges: dict[int, set[int]] = field(default_factory=dict)
    cold: set[int] = field(default_factory=set)
    root: int = 0


def _match_rule(rules: list[dict], fn: Func, where: tuple[str, int | None] | None) -> dict | None:
    for rule in rules:
        w = rule["where"]
        if "function" in w:
            if re.search(w["function"], fn.norm):
                return rule
        elif where is not None:
            path, line = where
            if path.endswith(w["file"]) and (w.get("line") is None or w["line"] == line):
                return rule
    return None


def analyse(model: Model, contract: dict) -> Result:
    rules = contract["rules"]
    res = Result()
    cold_rx = [re.compile(c) for c in contract.get("cold", [])]
    cold = {s for s, f in model.funcs.items() if g._COLD.search(f.name) or any(c.search(f.norm) for c in cold_rx)}
    recursion = [(re.compile(r["function"]), int(r["depth"])) for r in contract.get("recursion", [])]

    def depth_of(fn: Func) -> int | None:
        for rx, depth in recursion:
            if rx.search(fn.norm):
                return depth
        return None

    used: set[str] = set()
    edges: dict[int, set[int]] = {}
    claimed_by: dict[int, list[dict]] = {}
    unclaimed: dict[int, list[str]] = defaultdict(list)
    empty: set[str] = set()
    for start, fn in model.funcs.items():
        out = set(fn.calls)
        for addr in fn.sites:
            where = model.where.get(addr)
            rule = _match_rule(rules, fn, where)
            if rule is None:
                unclaimed[start].append(f"{where[0].rpartition('/')[2]}:{where[1]}" if where else "no line")
                continue
            used.add(rule["id"])
            claimed_by.setdefault(start, []).append(rule)
            callees = rule["callees"]
            if callees == "NONE":
                continue
            if callees == "WAKER":
                got = set(model.waker)
            elif callees == "TRAIT_METHODS":
                got = {a for a, n in model.taken.items() if n.startswith("<") and " as " in n}
            else:
                rx = re.compile(callees)
                got = {a for a, n in model.taken.items() if rx.search(n)}
            if not got:
                empty.add(rule["id"])
            out |= got
        edges[start] = out

    roots_entry = [s for s, f in model.funcs.items() if model.entry in f.name and f.frame > 0]
    if not roots_entry:
        res.unclaimed.append((model.entry, "the entry function is not in the image"))
        return res
    root = max(roots_entry, key=lambda s: model.funcs[s].frame)
    tasks = [s for s, f in model.funcs.items() if g.POLLED_TASK in f.name and f.frame > 0]

    reach: set[int] = set()
    todo = [root, *tasks]
    while todo:
        s = todo.pop()
        if s in reach or s in cold:
            continue
        reach.add(s)
        todo.extend(edges[s])
    res.reached = len(reach)
    res.sites = sum(len(model.funcs[s].sites) for s in reach)

    for s in sorted(reach):
        for w in unclaimed.get(s, []):
            res.unclaimed.append((model.funcs[s].norm, w))
        for r in claimed_by.get(s, []):
            res.claims[r["id"]] = res.claims.get(r["id"], 0) + 1
    for rule_id in sorted(empty):
        users = [s for s in reach for r in claimed_by.get(s, []) if r["id"] == rule_id]
        if users:
            res.empty_rules.append(rule_id)
    for rule in rules:
        if rule.get("callees") != "NONE":
            continue
        if rule.get("absent") and any(re.search(rule["absent"], n) for n in model.taken.values()):
            res.premises.append(f"{rule['id']}: the image holds a function matching `{rule['absent']}`")
        if rule.get("absent_reached") and any(re.search(rule["absent_reached"], model.funcs[s].norm) for s in reach):
            res.premises.append(f"{rule['id']}: the bound reaches a function matching `{rule['absent_reached']}`")
    res.unused = sorted(r["id"] for r in rules if r["id"] not in used)

    memo: dict[int, tuple[int, tuple[int, ...]]] = {}
    stack: list[int] = []
    cycles: set[tuple[int, int]] = set()

    def deepest(s: int) -> tuple[int, tuple[int, ...]]:
        if s in memo:
            return memo[s]
        stack.append(s)
        best: tuple[int, tuple[int, ...]] = (0, ())
        for t in sorted(edges[s]):
            if t in cold:
                continue
            if t in stack:
                if depth_of(model.funcs[t]) is None:
                    cycles.add((s, t))
                continue
            below = deepest(t)
            if below[0] > best[0]:
                best = below
        stack.pop()
        mult = depth_of(model.funcs[s]) or 1
        memo[s] = (model.funcs[s].frame * mult + best[0], (s, *best[1]))
        return memo[s]

    total, path = deepest(root)
    for task in tasks:
        below_total, below_path = deepest(task)
        if model.funcs[root].frame + below_total > total:
            total, path = model.funcs[root].frame + below_total, (root, *below_path)
    res.bound = total
    res.edges, res.cold, res.root = edges, cold, root
    res.chain = [(model.funcs[s].frame, model.funcs[s].norm) for s in path]
    res.cycles = sorted((model.funcs[a].norm, model.funcs[b].norm) for a, b in cycles)
    return res


# ── the gate ────────────────────────────────────────────────────────────────────────────────────────


#: A stack is sized from the bound it must hold: the bound over three quarters, in units of this.
STACK_UNIT = 64
#: How much above that a stack may be before the bytes it holds idle are a finding.
STACK_SLACK = 512


def derived_stack(bound: int) -> int:
    """The smallest stack, in units of STACK_UNIT, that keeps the bound within three quarters of it."""
    need = -(-bound * MARGIN_DEN // MARGIN_NUM)
    return -(-need // STACK_UNIT) * STACK_UNIT


def verdicts(
    res: Result, key: str, bound_row: int | None, peak: int | None, stack: int, contract: dict | None = None
) -> list[str]:
    """What is wrong with an image's bound, one sentence each; empty when nothing is."""
    bad: list[str] = []
    # A rule with no line claims every call by register of a file or of a C function, so a call added
    # there is claimed without anyone reading it. Its number of sites is committed for each image, and
    # a change of it is the moment the rule is read again.
    pins = (contract or {}).get("site_pins", {})
    for rule in (contract or {}).get("rules", []):
        if "line" in rule["where"]:
            continue
        n, pinned = res.claims.get(rule["id"], 0), pins.get(rule["id"], {}).get(key)
        if n and pinned is None:
            bad.append(f"rule `{rule['id']}` has no line and claims {n} call(s) in {key}; pin them in `site_pins`")
        elif pinned is not None and pinned != n:
            bad.append(
                f"rule `{rule['id']}` claims {n} call(s) through a register in {key} and pins {pinned}: "
                f"read the new ones against its callees, then move the pin"
            )
    for fn, where in res.unclaimed[:12]:
        bad.append(
            f"`{fn}` calls through a register at {where} and no rule of {CONTRACTS.name} claims the site"
        )
    if len(res.unclaimed) > 12:
        bad.append(f"... and {len(res.unclaimed) - 12} more unclaimed call(s) through a register")
    for rule_id in res.empty_rules:
        bad.append(f"rule `{rule_id}` names no function the image holds, and a site uses it: say NONE and why, or fix the rule")
    bad.extend(f"premise of a NONE rule is false -- {p}" for p in res.premises)
    for a, b in res.cycles:
        bad.append(f"a cycle `{a}` -> `{b}` that the contract does not declare as recursion")
    if bound_row is None:
        bad.append(f"{BUDGET.name} has no `static_bound_bytes` for {key}; the bound reads {res.bound}")
    elif bound_row != res.bound:
        bad.append(
            f"the bound reads {res.bound} bytes and {BUDGET.name} holds {bound_row} for {key}: "
            f"a change that moves the bound moves the row in the same commit"
        )
    if res.bound * MARGIN_DEN > stack * MARGIN_NUM:
        bad.append(
            f"the bound {res.bound} is over {MARGIN_NUM}/{MARGIN_DEN} of the {stack}-byte stack "
            f"({stack * MARGIN_NUM // MARGIN_DEN})"
        )
    want = derived_stack(res.bound)
    if stack > want + STACK_SLACK:
        bad.append(
            f"the stack of {key} is {stack} bytes and its bound needs {want}: the overlay holds "
            f"{stack - want} bytes more than the {STACK_SLACK} of slack allowed; set it to {want}"
        )
    if peak is not None and peak > res.bound:
        bad.append(
            f"the kit measured a stack peak of {peak} bytes, above the bound {res.bound}: "
            f"the model has a hole, and a bound the measurement exceeds is not a bound"
        )
    return bad


def _contract() -> dict:
    return json.loads(CONTRACTS.read_text())


def _row(key: str) -> dict:
    return json.loads(BUDGET.read_text()).get("images", {}).get(key, {})


def _image(key: str) -> g.Image:
    for image in g.IMAGES:
        if image.key == key:
            return image
    raise SystemExit(f"stack-bound: {key} is not an image of stack_frame_gate.IMAGES")


def report(res: Result) -> str:
    out = [
        f"{res.reached} function(s) reached, {res.sites} call(s) through a register in them, "
        f"{len(res.unused)} rule(s) unused by this image, bound {res.bound} bytes over {len(res.chain)} frame(s)"
    ]
    out.extend(f"   + {frame:5} {name[:100]}" for frame, name in res.chain)
    return "\n".join(out)


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--check")
    ap.add_argument("--emit")
    ap.add_argument("--elf")
    ap.add_argument("--selftest", action="store_true")
    ap.add_argument("--list", action="store_true", help="the images whose row commits a bound")
    args = ap.parse_args()
    if args.selftest:
        return selftest()
    if args.list:
        rows = json.loads(BUDGET.read_text()).get("images", {})
        print("\n".join(k for k, row in rows.items() if "static_bound_bytes" in row))
        return 0
    key = args.check or args.emit
    if not key or not args.elf:
        ap.error("--check and --emit take an image key and --elf")
    image = _image(key)
    model = load(args.elf, image.entry)
    res = analyse(model, _contract())
    contract = _contract()
    if args.emit:
        print(report(res))
        for fn, where in res.unclaimed:
            print(f"   UNCLAIMED {fn} at {where}")
        for a, b in res.cycles:
            print(f"   CYCLE {a} -> {b}")
        for rule in contract["rules"]:
            if "line" not in rule["where"] and res.claims.get(rule["id"]):
                print(f"   SITES {rule['id']} {res.claims[rule['id']]}")
        print(f"   STACK declared {g.declared_stack(image, ROOT)}, derived {derived_stack(res.bound)}")
        return 0
    row = _row(key)
    bad = verdicts(
        res, key, row.get("static_bound_bytes"), row.get("peak_stack_bytes"), g.declared_stack(image, ROOT), contract
    )
    if bad:
        print(f"stack-bound: FAIL {key}")
        for b in bad:
            print(f"  - {b}")
        print(report(res))
        return 1
    print(
        f"stack-bound: OK {key}: bound {res.bound} bytes over {len(res.chain)} frame(s), "
        f"{res.sites} call(s) through a register in {res.reached} function(s), all claimed"
    )
    return 0


# ── the selftest ────────────────────────────────────────────────────────────────────────────────────


def _model(extra_taken: dict[int, str] | None = None) -> Model:
    """main -> worker -> (register call) -> leaf_a | leaf_b, and a poll task; frames in bytes."""
    names = {
        0x100: "wz_app_main",
        0x200: "worker",
        0x300: "leaf_a",
        0x400: "leaf_b",
        0x500: "deep_b",
        0x600: "recur",
    }
    frames = {0x100: 100, 0x200: 50, 0x300: 10, 0x400: 40, 0x500: 200, 0x600: 8}
    funcs = {a: Func(a, n, n, frames[a]) for a, n in names.items()}
    funcs[0x100].calls.add(0x200)
    funcs[0x200].sites.append(0x210)
    funcs[0x400].calls.add(0x500)
    funcs[0x600].calls.add(0x600)
    taken = {0x300: "leaf_a", 0x400: "leaf_b", **(extra_taken or {})}
    return Model(funcs, taken, set(), {0x210: ("crates/x/src/lib.rs", 7)}, "wz_app_main")


def selftest() -> int:
    fails: list[str] = []
    controls = [0]

    def eq(what: str, got, want) -> None:
        controls[0] += 1
        if got != want:
            fails.append(f"{what}: got {got!r}, wanted {want!r}")

    rule = {"id": "r", "where": {"file": "lib.rs", "line": 7}, "callees": "^leaf_", "why": "t"}
    base = {"rules": [rule]}
    res = analyse(_model(), base)
    eq("the register call reaches leaf_b and the frames below it", res.bound, 100 + 50 + 40 + 200)
    eq("nothing unclaimed", res.unclaimed, [])
    # a rule names the site by line: another line is unclaimed
    other = {"rules": [{**rule, "where": {"file": "lib.rs", "line": 8}}]}
    eq("a site no rule claims is reported", len(analyse(_model(), other).unclaimed), 1)
    # a rule that names a function the image does not hold, used by a site
    none_held = {"rules": [{**rule, "callees": "^nothing$"}]}
    eq("a rule that names nobody is refused", analyse(_model(), none_held).empty_rules, ["r"])
    # NONE reaches nothing and carries its premise
    none = {"rules": [{**rule, "callees": "NONE", "absent": "^leaf_b$"}]}
    r_none = analyse(_model(), none)
    eq("NONE reaches nothing", r_none.bound, 100 + 50)
    eq("a false premise is reported", len(r_none.premises), 1)
    none_ok = {"rules": [{**rule, "callees": "NONE", "absent": "^nobody$"}]}
    eq("a true premise is not", analyse(_model(), none_ok).premises, [])
    # the cold list drops a function and what is under it
    cold = {"rules": [rule], "cold": ["^leaf_b$"]}
    eq("a cold function is not on the chain", analyse(_model(), cold).bound, 100 + 50 + 10)
    # recursion: refused unless declared, and counted with its depth when declared
    m = _model()
    m.funcs[0x200].calls.add(0x600)
    eq("an undeclared cycle is reported", len(analyse(m, base).cycles), 1)
    declared = {"rules": [rule], "recursion": [{"function": "^recur$", "depth": 3}]}
    res_rec = analyse(m, declared)
    eq("a declared recursion is not a cycle", res_rec.cycles, [])
    eq("the worst chain is unchanged by a shallower recursion", res_rec.bound, 390)
    # the verdicts
    ok = analyse(_model(), base)
    eq("a clean image has nothing wrong", verdicts(ok, "k", 390, 300, 1000), [])
    eq("a moved bound is a moved row", len(verdicts(ok, "k", 380, 300, 1000)), 1)
    eq("a bound over three quarters of the stack", len(verdicts(ok, "k", 390, 300, 400)), 1)
    eq("a measurement above the bound is a hole", len(verdicts(ok, "k", 390, 391, 1000)), 1)
    eq("no row is a refusal", len(verdicts(ok, "k", None, None, 1000)), 1)
    eq("the stack a bound needs", derived_stack(390), 576)
    eq("a stack far above what the bound needs", len(verdicts(ok, "k", 390, 300, 2000)), 1)
    broad = {"rules": [{"id": "b", "where": {"file": "lib.rs"}, "callees": "^leaf_", "why": "t"}]}
    res_b = analyse(_model(), broad)
    eq("a rule with no line has to pin its sites", len(verdicts(res_b, "k", 390, 300, 1000, broad)), 1)
    pinned = {**broad, "site_pins": {"b": {"k": 1}}}
    eq("a pinned rule holds", verdicts(res_b, "k", 390, 300, 1000, pinned), [])
    moved = {**broad, "site_pins": {"b": {"k": 2}}}
    eq("a pin that moved is a rule to read again", len(verdicts(res_b, "k", 390, 300, 1000, moved)), 1)
    # norm drops generic arguments and keeps a qualified path
    eq("norm: generics", norm("a::b::<T>::c"), "a::b::c")
    eq("norm: qualified path", norm("<X<Y> as T>::m"), "<X as T>::m")
    if fails:
        for f in fails:
            print(f"stack-bound selftest FAIL: {f}")
        return 1
    print(f"stack-bound selftest: every rule driven, {controls[0]} controls hold")
    return 0


if __name__ == "__main__":
    sys.exit(main())
