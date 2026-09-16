#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
# SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
"""R2642 (no register item) -- the set of config keys wz can change at RUNTIME
must be DERIVED from the code that can change them, never counted in prose.

The citation is `no register item` in the sense this tree's provenance lint uses:
the defect this closes was found while re-measuring the atom `config-mutate-runtime`
and has no store `debt-` id of its own.

## What was actually wrong, measured rather than argued

wz carries two config surfaces and nothing stated the relationship between them:
the keys honoured when a document is READ at startup, and the keys mutable while
the node runs. The second had no declaration at all. Its size was being carried
as an ENGLISH ORDINAL inside each field's own doc comment -- "the SECOND
runtime-mutable typed slice", "the THIRD" -- plus one sentence in an atom reason.

That is a number spelled at four sites and derived at none, and it had already
gone stale: the atom reason still says "there are now TWO" (a correction filed
when the second landed) while the tree has carried three since the router link
weights arrived. Nothing could catch it, because nothing read the code to count.

## What this gate does, and why in this shape

THE POPULATION IS DERIVED FROM STRUCTURE. A runtime-mutable slice is a PRIVATE
field of `WzConfig` carrying a `set_*` or `reconfigure_*` method. That predicate
is not a list someone maintains -- it falls out of what the type offers:

  * a `with_*` builder CONSUMES `self`, so it cannot mutate a running node's
    config; the four `with_*`-only fields are correctly outside the population
  * `set_*` / `reconfigure_*` take `&self` or `&mut self`, which is exactly the
    capability the subject is about

A POPULATION OF ZERO IS A FAILURE, not a pass. If the parse stops matching the
file -- a rename, a formatting change -- this gate would otherwise report a
clean surface over a surface it can no longer see, which is the shape this tree
has been bitten by more than once.

THE SET IS PINNED, NOT THE COUNT. A count agrees with itself when one slice
leaves and another arrives in the same round; the set does not.

THE FEATURE IS CHECKED AGAINST THE REAL `#[cfg]`. The table carries each row's
gating feature as DATA rather than as a `#[cfg]` on the row itself, because a
conditional member would shrink the table on the builds that elide it and a
table that shrinks by build cannot state a surface. Carrying it as data is only
honest if something compares it to the truth, which is what this does.
"""

from __future__ import annotations

import argparse
import pathlib
import re
import sys

ROOT = pathlib.Path(__file__).resolve().parents[2]
CONFIG_RS = ROOT / "crates" / "wz-runtime-tokio" / "src" / "config.rs"
ZENOH_CONFIG_RS = ROOT / "crates" / "wz-runtime-tokio" / "src" / "zenoh_config.rs"

#: A parse that finds fewer than this many private fields has stopped matching
#: the file. Three is what the tree carries; the floor is deliberately the real
#: number rather than 1, because "some" is not a population either.
MIN_SLICES = 3

#: The pinned SET of runtime-mutable slices. Two-directional: a slice added
#: without a row here fails, and so does one removed without the row leaving.
#:
#: R2667 — `connect_endpoints` joins, and the WHY is a measurement rather than a
#: preference. `config-mutate-runtime` listed 44 keys wz honours at startup but
#: could not apply at runtime, and each was graded on one predicate: does a
#: RUNTIME change produce an OBSERVABLE difference. 38 were eliminated because
#: upstream reads them into a builder or a constructor and stores them — the
#: three transport managers for the whole `transport/*` family, and
#: `start_client` / `start_peer` / `start_router` for the scouting and endpoint
#: block — so upstream accepts the write and nothing re-reads it.
#: `connect/endpoints` is the one that passed: `closed_session` and
#: `closed_link` lock the LIVE config at CLOSE time and re-read the list to
#: decide what to re-dial.
#: ⚠ `listen/endpoints` did NOT pass and is deliberately absent despite the
#: symmetric name — it is read only in the start path.
PINNED_SLICES = frozenset(
    {"interceptors", "admin_permissions", "router_link_weights", "connect_endpoints"}
)


def _struct_body(text: str, name: str) -> str:
    start = text.index("pub struct %s {" % name)
    depth = 0
    for i in range(start, len(text)):
        if text[i] == "{":
            depth += 1
        elif text[i] == "}":
            depth -= 1
            if depth == 0:
                return text[start:i]
    raise SystemExit("%s: unterminated `pub struct %s`" % (CONFIG_RS.name, name))


def private_fields(text: str) -> dict[str, str | None]:
    """Private `WzConfig` fields -> the feature gating them (or None).

    Reads the struct body only, so a same-named local elsewhere cannot join the
    population.
    """
    body = _struct_body(text, "WzConfig")
    out: dict[str, str | None] = {}
    pending: str | None = None
    for line in body.splitlines():
        stripped = line.strip()
        cfg = re.match(r'#\[cfg\(feature = "([^"]+)"\)\]$', stripped)
        if cfg:
            pending = cfg.group(1)
            continue
        field = re.match(r"([a-z_][a-z0-9_]*)\s*:\s*.+,$", stripped)
        if field and not stripped.startswith("pub "):
            out[field.group(1)] = pending
        if not stripped.startswith("///") and not stripped.startswith("#["):
            pending = None
    return out


def mutable_slices(text: str) -> dict[str, str | None]:
    """The DERIVED population: private fields with a `set_*`/`reconfigure_*`."""
    fields = private_fields(text)
    methods = set(re.findall(r"pub fn (set_[a-z0-9_]+|reconfigure_[a-z0-9_]+)\s*\(", text))
    out = {}
    for field, feature in fields.items():
        if ("set_%s" % field) in methods or ("reconfigure_%s" % field) in methods:
            out[field] = feature
    return out


def table_rows(text: str) -> list[dict[str, str]]:
    """The DECLARED table, parsed out of `RUNTIME_MUTABLE_CONFIG_KEYS`."""
    m = re.search(
        r"pub const RUNTIME_MUTABLE_CONFIG_KEYS: &\[RuntimeMutableKey\] = &\[(.*?)\n\];",
        text,
        re.S,
    )
    if not m:
        raise SystemExit("config.rs: no `RUNTIME_MUTABLE_CONFIG_KEYS` table found")
    rows = []
    for chunk in re.finditer(
        r"RuntimeMutableKey\s*\{(.*?)\}", m.group(1), re.S
    ):
        body = chunk.group(1)

        def field(name: str) -> str:
            # ⚠ The class MUST carry `-`: cargo features are hyphenated
            # (`routing-peer`), and the first draft of this pattern silently
            # truncated every one of them at the hyphen, then reported ten
            # mismatches against a table that was correct. A parser that
            # narrows its input invents findings.
            f = re.search(
                r"\b%s:\s*(?:MutationDiscipline::)?\"?([A-Za-z0-9_/-]+)\"?" % name, body
            )
            if not f:
                raise SystemExit("config.rs: a table row has no `%s`" % name)
            return f.group(1)

        rows.append(
            {
                "key": field("key"),
                "slice": field("slice"),
                "discipline": field("discipline"),
                "feature": field("feature"),
            }
        )
    return rows


def applied_keys(text: str) -> frozenset[str]:
    """The keys `WzConfig::apply_one_key` actually has an arm for.

    R2643 — the registry says which key lands in which slice; this says which
    key the document->live mapping can actually carry. Without this check the
    two halves drift: a row could name a slice while no arm ever applies it, and
    the registry would keep asserting a join nothing performs.
    """
    m = re.search(r"fn apply_one_key\(.*?\n    \}\n", text, re.S)
    if not m:
        raise SystemExit("config.rs: no `apply_one_key` to read")
    # R2650 — the segment repeat is `*`, not `+`. With `+` this pattern required
    # every key to carry at least one `/`, and TWO of the registry's ten do not:
    # `downsampling` and `low_pass_filter` are single-segment upstream keys. The
    # asymmetry was silent and guaranteed a WRONG finding -- `key_lists` below
    # reads a key list with plain `"([^"]+)"`, so those two were read from the
    # LISTS and could never be read from the ARMS, which made this gate report
    # "no arm for it" against an arm sitting right there.
    return frozenset(
        re.findall(r'"([A-Za-z0-9_]+(?:/[A-Za-z0-9_]+)*)"\s*=>', m.group(0))
    )


def key_lists(text: str) -> dict[str, frozenset[str]]:
    out = {}
    for name in ("HONOURED_CONFIG_KEYS", "UNHONOURED_UPSTREAM_CONFIG_KEYS"):
        m = re.search(r"pub const %s: &\[&str\] = &\[(.*?)\n\];" % name, text, re.S)
        if not m:
            raise SystemExit("zenoh_config.rs: no `%s`" % name)
        out[name] = frozenset(re.findall(r'"([^"]+)"', m.group(1)))
    return out


def grade(config_text: str, zenoh_text: str) -> tuple[int, list[str]]:
    findings: list[str] = []
    derived = mutable_slices(config_text)
    rows = table_rows(config_text)

    if len(derived) < MIN_SLICES:
        findings.append(
            "only %d runtime-mutable slice(s) derived from config.rs, expected at "
            "least %d. The parse has stopped matching the file; a surface this "
            "gate cannot see must not report clean."
            % (len(derived), MIN_SLICES)
        )
        return 1, findings

    declared = {r["slice"] for r in rows}
    if declared != set(derived):
        for slice_ in sorted(set(derived) - declared):
            findings.append(
                "slice `%s` is runtime-mutable (it has a set_/reconfigure_ method) "
                "but no RUNTIME_MUTABLE_CONFIG_KEYS row names it. Add its upstream "
                "key(s) there -- do not count slices in prose." % slice_
            )
        for slice_ in sorted(declared - set(derived)):
            findings.append(
                "RUNTIME_MUTABLE_CONFIG_KEYS names slice `%s`, which has no "
                "set_/reconfigure_ method on WzConfig. Either the method left and "
                "the row must follow it, or the row is a claim nothing backs."
                % slice_
            )

    if declared == set(derived) and declared != PINNED_SLICES:
        findings.append(
            "the runtime-mutable SET moved: %s, pinned %s. A set is pinned rather "
            "than a count so that one slice leaving as another arrives cannot "
            "cancel out. Move PINNED_SLICES in the same commit and say which "
            "slice and why."
            % (sorted(declared), sorted(PINNED_SLICES))
        )

    for row in rows:
        want = derived.get(row["slice"])
        if want is not None and row["feature"] != want:
            findings.append(
                "row `%s` declares feature `%s` but the field `%s` is gated "
                "`%s`. The table carries the feature as DATA, which is only "
                "honest while something compares it to the `#[cfg]`."
                % (row["key"], row["feature"], row["slice"], want)
            )

    lists = key_lists(zenoh_text)
    honoured = [r for r in rows if r["key"] in lists["HONOURED_CONFIG_KEYS"]]
    unhonoured = [r for r in rows if r["key"] in lists["UNHONOURED_UPSTREAM_CONFIG_KEYS"]]
    unknown = [
        r["key"]
        for r in rows
        if r["key"] not in lists["HONOURED_CONFIG_KEYS"]
        and r["key"] not in lists["UNHONOURED_UPSTREAM_CONFIG_KEYS"]
    ]
    for key in unknown:
        findings.append(
            "key `%s` is runtime-mutable but appears in NEITHER zenoh_config key "
            "list. A key wz can write but has never classified for reading is a "
            "key no surface count includes." % key
        )

    # R2643 — a key wz HONOURS must also be carried by the document->live
    # mapping. An UNHONOURED key deliberately is not: the reader refuses it by
    # name, so a document could never name it, and an arm for it would be an
    # arm nothing can reach. That asymmetry is the measured one this gate
    # already prints -- `interceptors` is mutable and unhonoured.
    applied = applied_keys(config_text)
    if not applied:
        findings.append(
            "`apply_one_key` has no key arms at all. The document->live mapping "
            "is the half of the join the registry cannot state, and an empty one "
            "would let every row claim a join nothing performs."
        )
    for row in rows:
        if row["key"] not in lists["HONOURED_CONFIG_KEYS"]:
            continue
        if row["key"] not in applied:
            findings.append(
                "key `%s` is HONOURED and runtime-mutable, but `apply_one_key` "
                "has no arm for it, so a config document naming it changes "
                "nothing. Add the arm, or the registry row asserts a join that "
                "does not happen." % row["key"]
            )
    for key in sorted(applied - {r["key"] for r in rows}):
        findings.append(
            "`apply_one_key` applies `%s`, which no RUNTIME_MUTABLE_CONFIG_KEYS "
            "row names. The mapping and the registry must agree in both "
            "directions." % key
        )

    push = sum(1 for r in rows if r["discipline"] == "Push")
    pull = sum(1 for r in rows if r["discipline"] == "Pull")
    print(
        "runtime-mutable-surface: %d key(s) over %d slice(s) derived from "
        "config.rs -- %d push, %d pull; %d honoured at startup, %d unhonoured, "
        "%d unclassified; %d carried by the document->live mapping"
        % (
            len(rows),
            len(derived),
            push,
            pull,
            len(honoured),
            len(unhonoured),
            len(unknown),
            len(applied),
        )
    )
    print(
        "  the two surfaces are NOT nested: %s"
        % (
            ", ".join(
                "%s=%s"
                % (
                    s,
                    "honoured"
                    if all(
                        r["key"] in lists["HONOURED_CONFIG_KEYS"]
                        for r in rows
                        if r["slice"] == s
                    )
                    else "unhonoured",
                )
                for s in sorted(derived)
            )
        )
    )
    return (1 if findings else 0), findings


def selftest() -> int:
    """Drive BOTH directions; a gate that only proves the green case proves the
    green case."""
    real = CONFIG_RS.read_text(encoding="utf-8")
    zenoh = ZENOH_CONFIG_RS.read_text(encoding="utf-8")

    rc, findings = grade(real, zenoh)
    if rc != 0:
        print("selftest FAIL: the real tree does not grade clean: %s" % findings)
        return 1

    # A slice whose row is deleted must be caught.
    damaged = re.sub(
        r"    RuntimeMutableKey \{\n        key: \"routing/router/linkstate/transport_weights\",.*?\n    \},\n",
        "",
        real,
        flags=re.S,
    )
    if damaged == real:
        print("selftest FAIL: could not damage the table; the fixture is inert")
        return 1
    rc, findings = grade(damaged, zenoh)
    if rc == 0 or not any("router_link_weights" in f for f in findings):
        print("selftest FAIL: a slice with no row was not caught: %s" % findings)
        return 1

    # A row whose feature disagrees with the field's #[cfg] must be caught.
    wrong = real.replace(
        'key: "adminspace/permissions/read",\n        slice: "admin_permissions",\n'
        "        discipline: MutationDiscipline::Pull,\n"
        '        feature: "adminspace-core",',
        'key: "adminspace/permissions/read",\n        slice: "admin_permissions",\n'
        "        discipline: MutationDiscipline::Pull,\n"
        '        feature: "routing-peer",',
    )
    if wrong == real:
        print("selftest FAIL: could not damage a row's feature; the fixture is inert")
        return 1
    rc, findings = grade(wrong, zenoh)
    if rc == 0 or not any("declares feature" in f for f in findings):
        print("selftest FAIL: a wrong feature was not caught: %s" % findings)
        return 1

    # R2643 — a HONOURED row whose mapping arm is gone must be caught.
    #
    # R2646 re-anchored the damage onto the arm's KEY LITERAL ALONE. It used to
    # carry the arm's body text (`=> match ingest.config.adminspace {`), and when
    # `apply_one_key` grew its delete half — the same arms now serve both, so the
    # body changed shape — this replacement stopped matching and the fixture went
    # INERT. It was the selftest's own inertness check that said so rather than a
    # green run, which is the whole reason that check exists; the lesson is that a
    # damage anchored to a body is a damage that decays whenever the body is
    # refactored, while the key literal is what the gate actually parses.
    unmapped = real.replace(
        '            "adminspace/permissions/write" =>',
        '            "adminspace/permissions/WRITE" =>',
    )
    if unmapped == real:
        print("selftest FAIL: could not damage a mapping arm; the fixture is inert")
        return 1
    rc, findings = grade(unmapped, zenoh)
    if rc == 0 or not any(
        "has no arm for it" in f and "adminspace/permissions/write" in f for f in findings
    ):
        print("selftest FAIL: a honoured row with no mapping arm was not caught: %s" % findings)
        return 1

    # R2650 — a SINGLE-SEGMENT key's arm is readable, which the arm pattern used
    # to make impossible.
    #
    # `mutable_slices`'s key regex required at least one `/`, so `downsampling`
    # and `low_pass_filter` -- two of the registry's ten, and upstream keys with
    # no slash in them -- could be read from a key LIST and never from an ARM.
    # The gate then reported "has no arm for it" against an arm sitting in the
    # file. Nothing here would have caught it: every fixture key was multi-segment,
    # so the population that could expose the bug was empty.
    #
    # The control is the damage, as everywhere else: renaming the single-segment
    # arm must be NOTICED. If the pattern regresses to `+`, the key becomes
    # invisible, the rename changes nothing the gate can see, and this fails.
    single = real.replace(
        '            "low_pass_filter" =>',
        '            "low_pass_FILTER" =>',
    )
    if single == real:
        print("selftest FAIL: could not damage the single-segment arm; fixture is inert")
        return 1
    rc, findings = grade(single, zenoh)
    if rc == 0 or not any(
        "has no arm for it" in f and "low_pass_filter" in f for f in findings
    ):
        print(
            "selftest FAIL: a single-segment key's missing arm was not caught -- "
            "the arm pattern cannot see keys without a `/`: %s" % findings
        )
        return 1

    print("runtime-mutable-surface: selftest OK (5 derivations driven)")
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(
        description="derive the runtime-mutable config surface from the code"
    )
    ap.add_argument("--check", action="store_true", help="read the real tree")
    ap.add_argument("--selftest", action="store_true", help="drive both directions")
    args = ap.parse_args()
    if args.selftest:
        return selftest()
    if not args.check:
        ap.error("one of --check or --selftest is required")
    rc, findings = grade(
        CONFIG_RS.read_text(encoding="utf-8"), ZENOH_CONFIG_RS.read_text(encoding="utf-8")
    )
    for f in findings:
        print("runtime-mutable-surface FAIL: %s" % f)
    if rc == 0:
        print("runtime-mutable-surface OK")
    return rc


if __name__ == "__main__":
    sys.exit(main())
