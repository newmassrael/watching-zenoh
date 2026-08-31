#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
# SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

"""R2221 (no register item) -- how many HANDSHAKE-NEGOTIATED axes are witnessed
by a test that drives a FOREIGN implementation, as a ratcheted number.

The citation is `no register item` for the reason `negotiated_axis_witness_gate.py`
gives for its own: the item this answers -- unregistered open-debt item 568,
the consuming surface's 2026-08-31 claim -- lives in the agent-memory register,
which has no store id for `gate_provenance_lint.py` to resolve.

## Why this exists BESIDE the gate it extends, and not inside it

Item 568 closed with a named obligation: decide whether R2199's gate should be
widened, "because otherwise the next axis stands in the same place". R2199 asks
whether every negotiated axis is asserted SOMEWHERE, and its own output is the
argument for widening -- every one of the nine axes reports its FIRST witness
from a `wz-runtime-tokio` test, i.e. from a wire this tree wrote. An encoder and
a decoder in one tree that are wrong together satisfy every such assertion.

It is a SEPARATE gate because the widening needs a second population -- which
tests can witness a foreign implementation -- and that population already has an
owner: `crossimpl_corpus.py`, which derives it by resolving the harness call
graph for Layer A4. Re-deriving foreignness inside R2199's gate would be a
second implementation of it, and this tree's standing finding is that the second
copy is the one that goes wrong (`PassiveFrame::unit_len`'s own doc records the
last time: `wz-analyze` re-read the two prefix bytes and walked the second
message of a batch as the first).

So NEITHER derivation is written here. The axes come from
`negotiated_axis_witness_gate`, the corpus from `crossimpl_corpus`, and this
file is the JOIN plus the ratchet.

## What it checks

For each axis R2199 derives, whether ANY of its result accessors is read inside
an assertion in a file the corpus calls foreign. Then:

  * RED when the axis population is EMPTY. Inherited from the gate it extends,
    and for the same reason: a join over nothing reports success.
  * RED when the corpus is EMPTY. The same trap one level over: if
    `crossimpl_corpus` stopped resolving, every axis would read SYNTHETIC-ONLY
    and the floor would catch it -- but only by luck, and only downward.
  * RED when the genuine count is BELOW the floor. An axis lost its genuine
    witness.
  * RED when the genuine count is ABOVE the floor. The round that gains one
    raises the floor in the same commit, which is what keeps the number a
    ratchet rather than a high-water mark nobody maintains.

A floor rather than "all axes must be genuine": today's answer is not nine, and
a gate that reds on the whole tree from birth is a stop-the-line, not a measure.
What it forbids is going backwards silently, and it names the SYNTHETIC-ONLY
axes on every run so which ones are outstanding is a number anyone can read
instead of a claim in a reply.
"""

import os
import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))

import crossimpl_corpus  # noqa: E402
import negotiated_axis_witness_gate as base  # noqa: E402

REPO = pathlib.Path(__file__).resolve().parents[2]

# MEASURED, not chosen — the number this gate itself printed once the R2221
# witnesses existed. The three are `body:batch_size` (which already had one, in
# `wz_fragment_tx_to_pico_zsub.rs`), plus `body:seq_num_res` and
# `ext:negotiate_patch_against_peer`, both from
# `wz_negotiated_axes_zenohd_interop.rs`. The other six print SYNTHETIC-ONLY on
# every run, which is the outstanding work stated as a list rather than as a
# sentence in a reply. Raise this in the commit that adds the next one; the gate
# reds in both directions, which is the point.
GENUINE_AXIS_FLOOR = 3


def corpus_files() -> set[str]:
    """The foreign-interop corpus, as paths relative to `crates/`.

    Derived by `crossimpl_corpus`, whose own paths are relative to the repo
    root; `base.rust_sources` reports relative to `crates/`. Normalised here so
    the join compares one spelling.
    """
    out: set[str] = set()
    for cf in crossimpl_corpus.scan_all():
        if not cf.classes:
            continue
        rel = cf.path.relative_to(crossimpl_corpus.REPO_ROOT)
        parts = rel.parts
        if parts and parts[0] == "crates":
            rel = pathlib.Path(*parts[1:])
        out.add(str(rel))
    return out


def axes_of(root: pathlib.Path):
    """R2199's axis derivation, called rather than copied.

    Returns `(axes, unresolved)` in that gate's own shape:
    `(label, slot, [(accessor, co-required token or None)])`.
    """
    actions = (root / base.ACTIONS_REL).read_text(encoding="utf-8")
    caps = (root / base.CAPS_REL).read_text(encoding="utf-8")
    bodies = base.fn_bodies(actions)

    axes = []
    unresolved = []
    for method in base.negotiation_methods(actions):
        slot = base.written_slot(method, bodies)
        if slot is None:
            unresolved.append(method)
            continue
        axes.append(
            (
                f"ext:{method}",
                slot,
                [(a, None) for a in base.accessors_reading(slot, bodies)],
            )
        )
    fields = base.caps_fields(caps)
    for field in fields:
        axes.append(
            (
                f"body:{field}",
                field,
                [
                    (name, field if shared else None)
                    for name, shared in base.body_accessors(field, fields, bodies)
                ],
            )
        )
    return axes, unresolved


def join(axes, sources, corpus: set[str]) -> dict[str, list[str]]:
    """Which FOREIGN-CORPUS files witness each axis.

    A pure function of its three inputs so the selftest can drive it with
    fixtures instead of a repository.
    """
    out: dict[str, list[str]] = {}
    for axis, _slot, accessors in axes:
        hits: list[str] = []
        for accessor, also in accessors:
            for path in base.witnesses(accessor, sources, also):
                if path in corpus and path not in hits:
                    hits.append(path)
        out[axis] = sorted(hits)
    return out


def decide(genuine: int, floor: int) -> tuple[int, str | None]:
    """The ratchet, split out so both directions are testable."""
    if genuine < floor:
        return 1, (
            f"genuine-axis: {genuine} axis(es) have a foreign witness and the "
            f"floor is {floor} -- an axis LOST its genuine witness. Restore it, "
            "or lower the floor in the same commit and say which axis went"
        )
    if genuine > floor:
        return 1, (
            f"genuine-axis: {genuine} axis(es) have a foreign witness and the "
            f"floor is {floor} -- raise GENUINE_AXIS_FLOOR to {genuine} in this "
            "commit. A high-water mark nobody moves stops being a ratchet"
        )
    return 0, None


def run(root: pathlib.Path, floor: int = GENUINE_AXIS_FLOOR) -> int:
    axes, unresolved = axes_of(root)
    failures: list[str] = []
    if not axes:
        failures.append(
            "genuine-axis: the axis population is EMPTY -- the join would "
            "report over nothing"
        )
    for method in unresolved:
        failures.append(
            f"genuine-axis: {method} writes a slot the axis derivation cannot "
            "resolve -- UNCLASSIFIED is red, not a pass"
        )

    corpus = corpus_files()
    if not corpus:
        failures.append(
            "genuine-axis: the FOREIGN CORPUS is empty -- every axis would read "
            "synthetic-only and this gate would be measuring its own inability "
            "to resolve the corpus"
        )

    sources = base.rust_sources(root / "crates")
    witnessed = join(axes, sources, corpus)

    genuine = 0
    for axis in sorted(witnessed):
        hits = witnessed[axis]
        if hits:
            genuine += 1
            more = f" (+{len(hits) - 1} more)" if len(hits) > 1 else ""
            print(f"  genuine-axis: {axis} witnessed by {hits[0]}{more}")
        else:
            print(f"  genuine-axis: {axis} SYNTHETIC-ONLY -- no foreign-corpus witness")

    print(
        f"  genuine-axis: {genuine} of {len(axes)} axis(es) have a foreign "
        f"witness (floor {floor})"
    )
    rc, message = decide(genuine, floor)
    if message:
        failures.append(message)
    for line in failures:
        print("  " + line)
    return 1 if failures else rc


def selftest() -> int:
    """The join and the ratchet, each driven to both verdicts.

    Fixtures rather than a repository: the two DERIVATIONS this gate stands on
    have their own selftests in their own files, and re-testing them here would
    be the third copy of what this module exists not to copy. What is this
    module's own is the join and the floor, and those are what is driven.

    The join fixture carries a witness in a NON-corpus file for the same axis
    that has one in a corpus file -- so an implementation that ignored the
    corpus entirely, which is exactly what R2199 does, passes arm 1 and fails
    arm 2.
    """
    rc = 0
    # METHOD calls, because that is the shape the derivation matches -- a
    # result accessor is read off a session, and a bare-function fixture would
    # pass arm 1 for the wrong reason (nothing matched at all) and fail arm 2.
    # Measured: the first draft of this fixture did exactly that.
    sources = [
        (
            "wz-runtime-tokio/tests/synthetic.rs",
            "fn t() { assert_eq!(actions.negotiated_alpha(), 1); }",
        ),
        (
            "wz-integration-tests/tests/foreign.rs",
            "fn t() { assert_eq!(actions.negotiated_beta(), 2); }",
        ),
    ]
    corpus = {"wz-integration-tests/tests/foreign.rs"}
    axes = [
        ("ext:alpha", "alpha", [("negotiated_alpha", None)]),
        ("ext:beta", "beta", [("negotiated_beta", None)]),
    ]
    got = join(axes, sources, corpus)

    def arm(n: int, what: str, ok: bool) -> int:
        print(f"  selftest arm {n} -- {what}: {'ok' if ok else 'FAIL'}")
        return 0 if ok else 1

    rc |= arm(
        1,
        "an axis asserted ONLY in a non-corpus file is synthetic-only",
        got["ext:alpha"] == [],
    )
    rc |= arm(
        2,
        "an axis asserted in a corpus file is genuine",
        got["ext:beta"] == ["wz-integration-tests/tests/foreign.rs"],
    )
    rc |= arm(3, "below the floor is RED", decide(1, 2)[0] == 1)
    rc |= arm(4, "above the floor is RED", decide(3, 2)[0] == 1)
    rc |= arm(5, "at the floor is GREEN", decide(2, 2)[0] == 0)
    # The corpus is not allowed to be the thing that makes a run green. An
    # empty corpus makes every axis synthetic-only, which `decide` alone would
    # answer with "below the floor" -- true, but for the wrong reason, and only
    # while the floor is above zero.
    rc |= arm(
        6,
        "an EMPTY corpus witnesses nothing",
        join(axes, sources, set()) == {"ext:alpha": [], "ext:beta": []},
    )
    return rc


def main(argv: list[str]) -> int:
    mode = argv[1] if len(argv) > 1 else "--check"
    if mode == "--selftest":
        return selftest()
    if mode != "--check":
        print(
            f"genuine_axis_witness_gate: unknown argument {mode!r} "
            "-- use --check or --selftest",
            file=sys.stderr,
        )
        return 2
    return run(pathlib.Path(os.environ.get("WZ_REPO_ROOT", REPO)))


if __name__ == "__main__":
    sys.exit(main(sys.argv))
