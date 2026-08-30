#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
# SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

"""R2199 (no register item) -- every HANDSHAKE-NEGOTIATED axis is asserted
somewhere, as a number a command produces rather than a sentence a reply makes.

The citation is `no register item` for the reason `config_key_fixture_gate.py`
gives for its own: the item this answers -- unregistered open-debt item 557,
the consuming surface's 2026-08-30 claim -- lives in the agent-memory register,
which has no store id for `gate_provenance_lint.py` to resolve. The item is
named in prose here instead.

## Why this exists

The consuming surface reported, at its own pin, that it could find no test
measuring `sn_resolution` or `patch` AS NEGOTIATED VALUES: its probe was
`grep -rn 'sn_resolution' crates/ --include='*.rs'`, which reads ZERO in this
tree. Re-measured here, that probe is right about its own string and wrong
about the claim: wz does not spell the field that way. The session's adopted
SN ring is `negotiated_sn_mask` and the peer's advertisement is `seq_num_res`,
so the consumer searched the upstream vocabulary and this tree answers in its
own -- and the tests it was looking for exist, and have since R311kb / R311y817.

Answering that in prose would settle it for exactly one round. The reply names
tests, and a named test is a claim that ages: rename it, drop its assertion, or
move it out of every lane, and the reply keeps saying what is no longer true
while nothing measures the gap. So the answer is written as a PREDICATE instead
-- this gate -- and the reply cites the gate rather than the list.

## What it checks, and why each direction matters

The subject is the set of values the 4-way handshake NEGOTIATES, and it is
DERIVED from two places in the source rather than transcribed into a table
here (which would be a list compared against its own length -- the class
`self_counted_table_gate.py` exists for):

  * the BODY axis is the fields of `PeerInitCaps`. That struct is the decode of
    what a peer advertises in an INIT body, so its field set IS the wire spec's
    negotiable body parameters; adding one widens this gate by construction.
  * the EXT axis is the `pub fn negotiate_<x>_against_peer` methods. The name is
    not the derivation -- the SIGNATURE is: each takes what the peer offered and
    merges it into a slot, and it is that WRITTEN SLOT this gate resolves, one
    setter hop deep, because `negotiate_qos_link_against_peer` reaches its slot
    through `set_qos_link_metadata`.

For each axis it then derives the RESULT ACCESSORS -- the `pub fn`s that read
that slot (or, for a body field, that read `inbound_peer_init_caps` and name
the field) -- and asks whether any of them is READ INSIDE AN ASSERTION.

Four ways to be red, and the first two are what keep it from going vacuous:

  1. an axis population of ZERO. If either derivation stops resolving -- the
     struct renamed, the `_against_peer` convention abandoned -- this gate would
     otherwise report "all axes witnessed" over nothing at all.
  2. an axis with NO result accessor. The slot moved and the derivation did not
     follow, so the axis is unmeasurable rather than measured.
  3. an axis no assertion reads. This is the finding the item was filed for.
  4. a negotiation method whose written slot cannot be resolved. UNCLASSIFIED
     is red, never a pass: an axis this gate cannot see is not an axis it has
     cleared.

There is no exemption list, on purpose. An axis that genuinely cannot be
asserted would have to be argued in the register, not silenced here.

## What "read inside an assertion" means, exactly

An accessor call textually inside the argument list of an `assert!` family
macro, with the argument list found by BRACKET MATCHING rather than by line --
this tree writes multi-line assertions constantly, and a line-anchored regex
reads `negotiated_patch` as ZERO witnesses when four assertions carry it. That
was measured on a one-line probe before this gate was written, and it is the
same shape as the consumer's own miss.

Plus ONE binding hop: `let mtu = opened.actions.negotiated_batch_mtu();` then
`assert_eq!(mtu, 64)` is how several of this tree's interop legs are written,
and refusing it would report a witnessed axis as unwitnessed. The hop is scoped
to the enclosing function, so a same-named local elsewhere cannot supply it.

## The SHARED accessor, and why a body axis needs more than a call

`init_ack_params()` reads all three body fields and hands back the whole
`SessionInitParams`, so an assertion that merely CALLS it would witness three
axes at once -- and the first draft of this gate reported exactly that: 9 of 9,
with one accessor covering `seq_num_res`, `req_id_res` and `batch_size`
together. That is the shape a gate is supposed to catch, not produce: three
axes cleared by one assertion about whichever field it actually reads.

So a body axis distinguishes its accessors. One that names ONLY that field is
DEDICATED and a call to it is the witness; one that names several is SHARED, and
witnessing through it additionally requires the FIELD ITSELF to appear in the
same assertion. `assert_eq!(params.req_id_res, 2)` witnesses `req_id_res`;
`assert_eq!(params.batch_size, 512)` does not.
"""

import os
import pathlib
import re
import sys
import tempfile

REPO = pathlib.Path(__file__).resolve().parents[2]

ACTIONS_REL = "crates/wz-session-core/src/session_actions.rs"
CAPS_REL = "crates/wz-session-core/src/peer_init_caps.rs"

# The struct whose fields ARE the negotiable body parameters, and the slot that
# holds a peer's decoded advertisement of them.
CAPS_STRUCT = "PeerInitCaps"
CAPS_SLOT = "inbound_peer_init_caps"

# A method that takes what the peer offered and merges it. The gate derives the
# axis from the slot each one WRITES, not from this pattern.
NEGOTIATE_RE = re.compile(r"^    pub fn (negotiate_[a-z0-9_]+_against_peer)\b")

# `pub fn NAME` at an impl's indentation. Column-anchored: a `pub fn` deeper in
# the file is inside a nested block or a `mod tests`, and neither is the API
# surface a consumer reads (the R2195 lesson about deriving paths from Rust).
PUB_FN_RE = re.compile(r"^    pub (?:const )?fn ([a-z0-9_]+)\b")

# `R::with_mutex_mut(&self.slot` / `R::with_mutex(&self.slot` -- how every slot
# in `SessionLinkActions` is reached.
SLOT_WRITE_RE = re.compile(r"R::with_mutex(?:_mut)?\(&self\.([a-z0-9_]+)")
# One setter hop: `self.set_x(...)`.
SETTER_CALL_RE = re.compile(r"\bself\.(set_[a-z0-9_]+)\(")

ASSERT_MACROS = (
    "assert",
    "assert_eq",
    "assert_ne",
    "debug_assert",
    "debug_assert_eq",
    "debug_assert_ne",
)
ASSERT_OPEN_RE = re.compile(r"\b(" + "|".join(ASSERT_MACROS) + r")!\s*[\(\[\{]")

# `let NAME = ...` -- the one binding hop.
LET_RE = re.compile(r"\blet\s+(?:mut\s+)?([a-z_][a-z0-9_]*)\s*(?::[^=;]+)?=")

FN_HEAD_RE = re.compile(r"\s*(?:pub(?:\([a-z]+\))? )?(?:async )?fn [a-z0-9_]+")


def block_from(lines: list[str], start: int) -> str:
    """The brace-matched block beginning at or after `lines[start]`.

    Brace matching and not a blank-line heuristic: several of these bodies carry
    nested closures, and a `match` arm block would end the function early.
    """
    depth = 0
    started = False
    body: list[str] = []
    for j in range(start, len(lines)):
        body.append(lines[j])
        for ch in lines[j]:
            if ch == "{":
                depth += 1
                started = True
            elif ch == "}":
                depth -= 1
        if started and depth <= 0:
            break
    return "\n".join(body)


def fn_bodies(text: str) -> dict[str, str]:
    """Every impl-level `pub fn` mapped to its body."""
    out: dict[str, str] = {}
    lines = text.splitlines()
    for i, line in enumerate(lines):
        m = PUB_FN_RE.match(line)
        if m:
            out[m.group(1)] = block_from(lines, i)
    return out


def negotiation_methods(text: str) -> list[str]:
    return [
        m.group(1)
        for line in text.splitlines()
        if (m := NEGOTIATE_RE.match(line))
    ]


def written_slot(name: str, bodies: dict[str, str]) -> str | None:
    """The slot a negotiation method writes, one setter hop deep."""
    body = bodies.get(name)
    if body is None:
        return None
    direct = SLOT_WRITE_RE.search(body)
    if direct:
        return direct.group(1)
    for setter in SETTER_CALL_RE.findall(body):
        setter_body = bodies.get(setter)
        if setter_body is None:
            continue
        hop = SLOT_WRITE_RE.search(setter_body)
        if hop:
            return hop.group(1)
    return None


def accessors_reading(slot: str, bodies: dict[str, str]) -> list[str]:
    """`pub fn`s that READ a slot -- the result accessors for its axis.

    Setters and the negotiation methods themselves are excluded: an axis
    witnessed by its own mutator would be witnessed by construction.
    """
    needle = re.compile(r"&self\." + re.escape(slot) + r"\b")
    out = []
    for name, body in bodies.items():
        if name.startswith("set_") or name.startswith("negotiate_"):
            continue
        if needle.search(body):
            out.append(name)
    return sorted(out)


def caps_fields(text: str) -> list[str]:
    """The `PeerInitCaps` fields -- the body axis, straight off the struct."""
    m = re.search(r"pub struct " + CAPS_STRUCT + r"\s*\{(.*?)\n\}", text, re.S)
    if not m:
        return []
    return re.findall(r"^\s*pub ([a-z0-9_]+):", m.group(1), re.M)


def body_accessors(
    field: str, fields: list[str], bodies: dict[str, str]
) -> list[tuple[str, bool]]:
    """`pub fn`s that read the peer-caps slot AND name this field.

    Each is tagged SHARED when it also names another body field, because such an
    accessor hands back all of them at once and a call to it says nothing about
    which one an assertion is measuring.
    """
    slot = re.compile(r"&self\." + re.escape(CAPS_SLOT) + r"\b")
    named = re.compile(r"\b" + re.escape(field) + r"\b")
    out = []
    for name, body in bodies.items():
        if name.startswith("set_") or name.startswith("negotiate_"):
            continue
        if not (slot.search(body) and named.search(body)):
            continue
        shared = any(
            other != field and re.search(r"\b" + re.escape(other) + r"\b", body)
            for other in fields
        )
        out.append((name, shared))
    return sorted(out)


def assert_arguments(text: str) -> list[str]:
    """Every `assert!` family argument list, by bracket matching.

    Line-anchored matching is what this replaces: it reads four multi-line
    assertions on `negotiated_patch` as zero.
    """
    out = []
    for m in ASSERT_OPEN_RE.finditer(text):
        open_at = m.end() - 1
        opener = text[open_at]
        closer = {"(": ")", "[": "]", "{": "}"}[opener]
        depth = 0
        in_str = False
        esc = False
        for k in range(open_at, len(text)):
            ch = text[k]
            if esc:
                esc = False
                continue
            if ch == "\\":
                esc = True
                continue
            if ch == '"':
                in_str = not in_str
                continue
            if in_str:
                continue
            if ch == opener:
                depth += 1
            elif ch == closer:
                depth -= 1
                if depth == 0:
                    out.append(text[open_at + 1 : k])
                    break
    return out


def fn_blocks(text: str) -> list[str]:
    """Bodies of `fn`s at any indentation -- the scope a binding hop lives in."""
    lines = text.splitlines()
    return [
        block_from(lines, i)
        for i, line in enumerate(lines)
        if FN_HEAD_RE.match(line)
    ]


def statement_after(fn: str, at: int) -> str:
    """The text from `at` to the end of that statement."""
    end = fn.find(";", at)
    return fn[at:] if end < 0 else fn[at : end + 1]


def witnesses(
    accessor: str, sources: list[tuple[str, str]], also: str | None = None
) -> list[str]:
    """Files where an assertion READS this accessor, directly or one hop.

    `also`, when given, is a second token the SAME assertion must carry -- the
    field a SHARED body accessor would otherwise clear by association.
    """
    call = re.compile(r"\.\s*" + re.escape(accessor) + r"\s*\(")
    extra = re.compile(r"\b" + re.escape(also) + r"\b") if also else None

    def carries(arg: str) -> bool:
        return call.search(arg) is not None and (
            extra is None or extra.search(arg) is not None
        )

    found = []
    for path, text in sources:
        if not call.search(text):
            continue
        if any(carries(arg) for arg in assert_arguments(text)):
            found.append(path)
            continue
        for fn in fn_blocks(text):
            bound = {
                m.group(1)
                for m in LET_RE.finditer(fn)
                if call.search(statement_after(fn, m.end()))
            }
            if not bound:
                continue
            hit = any(
                re.search(r"\b" + re.escape(b) + r"\b", arg)
                and (extra is None or extra.search(arg))
                for arg in assert_arguments(fn)
                for b in bound
            )
            if hit:
                found.append(path)
                break
    return found


def rust_sources(root: pathlib.Path) -> list[tuple[str, str]]:
    out = []
    for p in sorted(root.rglob("*.rs")):
        if "/target/" in str(p) or "/vendor/" in str(p):
            continue
        out.append((str(p.relative_to(root)), p.read_text(encoding="utf-8")))
    return out


def run(root: pathlib.Path) -> int:
    actions = (root / ACTIONS_REL).read_text(encoding="utf-8")
    caps = (root / CAPS_REL).read_text(encoding="utf-8")
    bodies = fn_bodies(actions)

    # An axis is (label, slot, [(accessor, token the same assertion must also
    # carry, or None)]).
    axes: list[tuple[str, str, list[tuple[str, str | None]]]] = []
    unresolved: list[str] = []

    for method in negotiation_methods(actions):
        slot = written_slot(method, bodies)
        if slot is None:
            unresolved.append(method)
            continue
        axes.append(
            (
                f"ext:{method}",
                slot,
                [(a, None) for a in accessors_reading(slot, bodies)],
            )
        )

    fields = caps_fields(caps)
    for field in fields:
        axes.append(
            (
                f"body:{field}",
                field,
                [
                    (name, field if shared else None)
                    for name, shared in body_accessors(field, fields, bodies)
                ],
            )
        )

    failures: list[str] = []
    if not axes:
        failures.append(
            "negotiated-axis: the axis population is EMPTY -- neither "
            f"{CAPS_STRUCT} nor a `negotiate_*_against_peer` method resolved, "
            "so this gate would report green over nothing"
        )
    for method in unresolved:
        failures.append(
            f"negotiated-axis: {method} writes a slot this gate cannot "
            "resolve -- UNCLASSIFIED is red, not a pass"
        )

    sources = rust_sources(root / "crates")
    witnessed = 0
    for axis, slot, accessors in sorted(axes):
        if not accessors:
            failures.append(
                f"negotiated-axis: {axis} (slot `{slot}`) has NO result "
                "accessor -- the axis is unmeasurable, so it cannot be measured"
            )
            continue
        hits = [
            (a, f) for a, also in accessors for f in witnesses(a, sources, also)
        ]
        if hits:
            witnessed += 1
            acc, path = hits[0]
            more = f" (+{len(hits) - 1} more)" if len(hits) > 1 else ""
            print(f"  negotiated-axis: {axis} witnessed by {acc}() in {path}{more}")
        else:
            spelled = ", ".join(
                a + (f" (SHARED, needs `{also}` in the same assertion)" if also else "")
                for a, also in accessors
            )
            failures.append(
                f"negotiated-axis: {axis} (slot `{slot}`) is NEGOTIATED and "
                f"never ASSERTED -- accessors [{spelled}] appear in no "
                "assertion, so nothing measures that the negotiated value is "
                "the one applied"
            )

    print(f"  negotiated-axis: {witnessed} of {len(axes)} axis(es) asserted")
    for line in failures:
        print("  " + line)
    return 1 if failures else 0


FIXTURE_ACTIONS = '''
impl<R> SessionLinkActions<R> {
    pub fn negotiate_alpha_against_peer(&self, peer_offered: bool) {
        R::with_mutex_mut(&self.is_alpha, |s| *s &= peer_offered);
    }

    pub fn is_alpha(&self) -> bool {
        R::with_mutex_mut(&self.is_alpha, |s| *s)
    }

    pub fn negotiate_beta_against_peer(&self, peer: u8) {
        self.set_beta(peer);
    }

    pub fn set_beta(&self, v: u8) {
        R::with_mutex_mut(&self.beta_slot, |s| *s = Some(v));
    }

    pub fn negotiated_beta(&self) -> u8 {
        R::with_mutex_mut(&self.beta_slot, |s| s.unwrap_or(0))
    }

    pub fn negotiated_gamma_mask(&self) -> u64 {
        let peer = R::with_mutex_mut(&self.inbound_peer_init_caps, |slot| *slot);
        match peer {
            Some(p) => self.params.gamma_res.min(p.gamma_res),
            None => self.params.gamma_res,
        }
    }

    pub fn merged_params(&self) -> SessionInitParams {
        let peer = R::with_mutex_mut(&self.inbound_peer_init_caps, |slot| *slot);
        let mut params = self.params.clone();
        if let Some(p) = peer {
            params.gamma_res = params.gamma_res.min(p.gamma_res);
            params.delta_size = params.delta_size.min(p.delta_size);
        }
        params
    }
}
'''

# TWO body fields, so the SHARED rule has a subject at all. `merged_params`
# names both, `negotiated_gamma_mask` names one -- which is the pairing this
# tree really has (`init_ack_params` beside `negotiated_sn_mask`).
FIXTURE_CAPS = '''
pub struct PeerInitCaps {
    pub gamma_res: u8,
    pub delta_size: u16,
}
'''

# The witness for `is_alpha` is written the way this tree writes them and the
# way the pre-gate one-line probe MISSED: the call is on its own line inside a
# multi-line `assert_eq!`. The `negotiated_beta` witness is the BINDING HOP.
# `negotiated_gamma_mask` has NO witness, so arm 1 must be red.
FIXTURE_TEST = '''
#[test]
fn alpha_is_asserted() {
    assert_eq!(
        actions.is_alpha(),
        true,
        "the negotiated alpha is what the session adopted"
    );
}

#[test]
fn beta_is_asserted_through_a_binding() {
    let level = actions.negotiated_beta();
    assert_eq!(level, 3, "the admitted level is what the session negotiates");
}
'''

FIXTURE_GAMMA_WITNESS = '''
#[test]
fn gamma_is_asserted() {
    assert_eq!(
        actions.negotiated_gamma_mask(),
        0xFF,
        "the negotiated SN ring is the min of the two advertisements"
    );
}
'''

# The shape the SHARED rule exists to REFUSE: `merged_params` is called and
# asserted on, but what the assertion reads is the OTHER field. Without the
# rule this clears `delta_size` by association.
FIXTURE_SHARED_NEAR_MISS = '''
#[test]
fn the_merge_runs_but_reads_the_other_field() {
    let p = actions.merged_params();
    assert_eq!(p.gamma_res, 1, "gamma capped to peer");
}
'''

FIXTURE_SHARED_WITNESS = '''
#[test]
fn delta_is_asserted_through_the_shared_accessor() {
    let p = actions.merged_params();
    assert_eq!(p.delta_size, 512, "delta_size capped to peer");
}
'''

FIXTURE_UNRESOLVED = '''
impl<R> SessionLinkActions<R> {
    pub fn negotiate_delta_against_peer(&self, peer: u8) {
        let _ = peer;
    }
}
'''


def selftest() -> int:
    """Drive the gate against a fixture whose shape the OLD probe swallowed.

    Five arms, because a fixture that is only red proves the gate can fail and
    one that is only green proves it can pass; neither alone shows it
    DISCRIMINATES. Arm 1's fixture is the shape a line-anchored probe reports
    as zero witnesses -- the defect this gate replaces -- so a regression back
    to that reading reddens arm 2 rather than passing silently.

    Arms 4 and 5 are the SHARED rule's own pair, and they exist because without
    them that branch is never taken: the first fixture had ONE body field, so
    no accessor could be shared and the rule was green from birth.
    """
    rc = 0

    def arm(n: int, what: str, expect: int, actions_src: str, probe_src: str,
            root: pathlib.Path, probe: pathlib.Path) -> int:
        print(f"  selftest arm {n} -- {what}:")
        (root / ACTIONS_REL).write_text(actions_src, encoding="utf-8")
        probe.write_text(probe_src, encoding="utf-8")
        got = run(root)
        if got != expect:
            print(f"  selftest FAIL: arm {n} returned {got}, expected {expect}")
            return 1
        return 0

    with tempfile.TemporaryDirectory() as td:
        root = pathlib.Path(td)
        (root / "crates/wz-session-core/src").mkdir(parents=True)
        (root / "crates/wz-runtime-tokio/tests").mkdir(parents=True)
        (root / CAPS_REL).write_text(FIXTURE_CAPS, encoding="utf-8")
        probe = root / "crates/wz-runtime-tokio/tests/probe.rs"

        # Arms 1-3 hold `delta_size` witnessed so the arm under test is the only
        # thing moving; arms 4-5 hold `gamma_res` witnessed for the same reason.
        base = FIXTURE_TEST + FIXTURE_SHARED_WITNESS
        rc |= arm(1, "an unasserted axis must be RED", 1,
                  FIXTURE_ACTIONS, base, root, probe)
        rc |= arm(2, "assert it, and the gate must go GREEN", 0,
                  FIXTURE_ACTIONS, base + FIXTURE_GAMMA_WITNESS, root, probe)
        rc |= arm(3, "an UNRESOLVED negotiation method is RED", 1,
                  FIXTURE_ACTIONS + FIXTURE_UNRESOLVED,
                  base + FIXTURE_GAMMA_WITNESS, root, probe)
        rc |= arm(4, "a SHARED accessor asserted on ANOTHER field is NOT a "
                     "witness", 1, FIXTURE_ACTIONS,
                  FIXTURE_TEST + FIXTURE_GAMMA_WITNESS + FIXTURE_SHARED_NEAR_MISS,
                  root, probe)
        rc |= arm(5, "the SAME accessor asserted on THIS field IS a witness", 0,
                  FIXTURE_ACTIONS,
                  FIXTURE_TEST + FIXTURE_GAMMA_WITNESS + FIXTURE_SHARED_WITNESS,
                  root, probe)
    return rc


def main(argv: list[str]) -> int:
    mode = argv[1] if len(argv) > 1 else "--check"
    if mode == "--selftest":
        return selftest()
    if mode != "--check":
        print(
            f"negotiated_axis_witness_gate: unknown argument {mode!r} "
            "-- use --check or --selftest",
            file=sys.stderr,
        )
        return 2
    return run(pathlib.Path(os.environ.get("WZ_REPO_ROOT", REPO)))


if __name__ == "__main__":
    sys.exit(main(sys.argv))
