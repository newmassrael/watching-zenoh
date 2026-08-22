#!/usr/bin/env python3
# SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
# SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
"""R2038 (debt-census-arm-gate) — a census arm must be gated like its variant.

Open-debt item 334, which lives in the unregistered register. The store entry
`debt-census-arm-gate` exists so this citation RESOLVES: a gate that cannot name
what it closed leaves the register unable to answer "which gate answers this?"
mechanically, and `(no register item)` would have been false.

THE COUPLING THIS HOLDS. `DroppedFrameCensus::absorb` matches every
`InboundFrame` variant and counts it into its own bucket. Both halves are
feature-gated, and they are gated in DIFFERENT FILES: the variant in
`inbound.rs`, the arm in `passive_messages.rs`. Nothing joined them, so the two
can drift silently in either direction.

WHY IT IS THREE PLACES AND NOT TWO. `passive_messages` is itself declared under
`#[cfg(all(alloc, codec-init-body, codec-open-body, codec-close, codec-frame))]`,
so inside it those four variants are unconditionally present and their arms are
CORRECTLY ungated. An arm needs its own `#[cfg]` exactly when the variant's
feature is one the module gate does not already supply. A checker that ignored
the module gate would demand four gates that must not be there.

THE FAILURE IT IS AIMED AT, from the item that asked for it. `Oam` is ungated on
both sides today, and that is right because the variant needs no generated body
codec. The day one is added -- `codec-oam`, say -- the variant gains a gate, the
arm does not, and the build breaks only in the profiles that turn the feature
off. Item 334 filed that as "nothing tells you to move both".

⚠ AND THE ITEM'S OWN DESCRIPTION OF THE SIBLINGS WAS WRONG, which is why the
rule below is written from the three files rather than from the item: it says
every sibling but `Frame` carries its variant's feature, and `Init`, `Open` and
`Close` are ungated too -- correctly, because the module gate supplies them.

WHY A STATIC SCAN AND NOT A BUILD. The same argument `duplicate_module_lint`
makes: catching a mismatched gate by BUILDING needs the one feature combination
that turns the variant's feature off while the module's gate still holds, and a
lane that happens to cover that today is a coincidence rather than a gate. The
invariant does not depend on features -- it is a statement about the gates
themselves -- so it is checked where it is true, by reading them.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
CRATE = ROOT / "crates" / "wz-session-core" / "src"
INBOUND = CRATE / "inbound.rs"
CENSUS = CRATE / "passive_messages.rs"
LIB = CRATE / "lib.rs"

ENUM = re.compile(r"pub enum InboundFrame \{(?P<body>.*?)\n\}", re.S)
"""The variant list, anchored on both ends.

A regex that found the opening and ran to the end of the file would keep
matching after a rename of the closing shape and quietly widen its population,
which is the failure this workspace has paid for in doc gates twice.
"""

MODULE_GATE = re.compile(
    r"#\[cfg\(all\((?P<feats>[^)]*)\)\)\]\s*\npub mod passive_messages;", re.S
)
"""The `pub mod passive_messages;` declaration together with its own gate."""

FEATURE = re.compile(r'feature\s*=\s*"([a-z0-9-]+)"')
VARIANT = re.compile(
    r"(?P<gate>(?:^[ \t]*#\[cfg\([^\]]*\)\]\n)*)^[ \t]{4}(?P<name>[A-Z][A-Za-z0-9]*)\s*[{,]",
    re.M,
)
ARM = re.compile(
    r"(?P<gate>(?:^[ \t]*#\[cfg\([^\]]*\)\]\n)*)"
    r"^[ \t]*Ok\(crate::inbound::InboundFrame::(?P<name>[A-Z][A-Za-z0-9]*)",
    re.M,
)


def _feature_of(gate: str) -> str | None:
    """The single feature a gate names, or `None` for no gate at all.

    A gate naming more than one feature is refused rather than guessed at: this
    checker's whole claim is that one variant answers to one feature, and a
    compound predicate is a decision someone made that this rule has not been
    taught to read.
    """
    if not gate.strip():
        return None
    feats = FEATURE.findall(gate)
    if len(feats) != 1:
        raise SystemExit(
            f"census-arm-gate: a gate names {len(feats)} feature(s) and this "
            f"rule reads exactly one: {gate.strip()!r}"
        )
    return feats[0]


def main() -> int:
    for path in (INBOUND, CENSUS, LIB):
        if not path.is_file():
            print(f"census-arm-gate: cannot read {path}", file=sys.stderr)
            return 1

    enum_body = ENUM.search(INBOUND.read_text(encoding="utf-8"))
    if not enum_body:
        print(
            "census-arm-gate: cannot find `pub enum InboundFrame { .. }` -- "
            "re-anchor this regex on whatever it is called now",
            file=sys.stderr,
        )
        return 1

    module_gate = MODULE_GATE.search(LIB.read_text(encoding="utf-8"))
    if not module_gate:
        print(
            "census-arm-gate: cannot find the `pub mod passive_messages;` gate "
            "-- the arms below cannot be judged without knowing what the module "
            "already requires",
            file=sys.stderr,
        )
        return 1
    supplied = set(FEATURE.findall(module_gate.group("feats")))

    variants = {m.group("name"): _feature_of(m.group("gate")) for m in VARIANT.finditer(enum_body.group("body"))}
    arms = {m.group("name"): _feature_of(m.group("gate")) for m in ARM.finditer(CENSUS.read_text(encoding="utf-8"))}

    # ANTI-VACUITY, three ways. An empty variant set, an empty arm set, or a
    # module gate that supplied nothing would each make every check below true
    # over nothing -- the population-of-zero pass this workspace keeps paying
    # for, arriving in the gate written to prevent a different one.
    if not variants:
        print("census-arm-gate: no variants matched -- the sweep is dead", file=sys.stderr)
        return 1
    if not arms:
        print("census-arm-gate: no census arms matched -- the sweep is dead", file=sys.stderr)
        return 1
    if not supplied:
        print("census-arm-gate: the module gate names no feature", file=sys.stderr)
        return 1

    failures: list[str] = []

    for name, arm_gate in arms.items():
        if name not in variants:
            failures.append(
                f"`absorb` counts `InboundFrame::{name}` and the enum has no "
                "such variant"
            )
            continue
        want = variants[name]
        if want is not None and want in supplied:
            want = None  # the module gate already guarantees it
        if want == arm_gate:
            continue
        if want is None:
            failures.append(
                f"the `{name}` arm is gated on `{arm_gate}` and its variant "
                "needs no such gate here -- the arm would stop counting a "
                "variant that is still in the build"
            )
        elif arm_gate is None:
            failures.append(
                f"`InboundFrame::{name}` is gated on `{want}` and the `absorb` "
                f"arm naming it is not, and `{want}` is not one of the features "
                "the module already requires -- the two gates move together or "
                "the build breaks only in the profiles that turn it off"
            )
        else:
            failures.append(
                f"the `{name}` arm is gated on `{arm_gate}` and its variant on "
                f"`{want}`"
            )

    for name, want in variants.items():
        if name not in arms and name != "Unknown":
            failures.append(
                f"`InboundFrame::{name}` has no `absorb` arm -- a variant this "
                "census cannot see is a message it silently miscounts"
            )

    for line in failures:
        print(f"  FAIL {line}")
    print(
        f"census-arm-gate: {len(variants)} variant(s), {len(arms)} census arm(s), "
        f"module gate supplies {', '.join(sorted(supplied))}"
    )
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
