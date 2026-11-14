#!/usr/bin/env python3
# SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
# SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

"""R2079 (no register item) — is `DEEPENABLE_UPSTREAM_KEYS` COMPLETE?

It answers for open-debt item 502, which lives in the agent-memory register
OUTSIDE this tree and therefore has no `debt-` id to cite — the same position
`debt_plane_census.py` records for itself.

## The question this answers, and the one it does not

`wz_reads_a_stock_zenohd_config`'s LEG 9 asks a real zenohd about every key the
constant NAMES. That protects the entries. It cannot see a key the constant is
MISSING, and that is the dangerous direction: a key wrongly off the list makes wz
refuse a file a real zenohd starts on, and the only detection path left is an
operator reporting that their node will not come up.

This script asks the other question. It walks the WHOLE upstream surface --
`HONOURED_CONFIG_KEYS` + `UNHONOURED_UPSTREAM_CONFIG_KEYS` -- hands each key a
deeper shape, and classifies the key by what zenohd ANSWERS. Run it in any round
that moves the surface or the exception list.

MEASURED when it was written: it found `listen/retry` accepting a deeper shape
and absent from the list, which R2078 had introduced and no test could see.

## The probe value, and the one shape it has to know

Every key gets `{ zzz_not_a_mode: 1 }`, which is not a mode name and not a valid
value for anything. The classification is the MESSAGE, not the exit code:

  * the process comes up                       -> the subtree is OPAQUE
  * "expected one of `router`, `peer`, `client`" -> the key is MODE-DEPENDENT
  * anything else                               -> the key takes no deeper shape

⛔ Reading the message rather than the status is the whole method. Six probes in
the round that built the list came back "refused" and were DEAD -- four because
the fixture restated a key its own document already had (`duplicate field`), two
because the value shape was wrong. An exit code cannot tell a negative result
from a broken probe.

A key whose value is a MAP OF NAMED MEMBERS gets the same object one level
further down, and `MEMBER_MAP_KEYS` is where such a key is declared. `plugins` is
the one: upstream reads it as plugin name -> that plugin's document and refuses a
member that is not an object before anything reads it
(`commons/zenoh-config/src/lib.rs` @ `bail!("{} must be object", title);`). Handed
the generic object, the daemon answered `plugins.zzz_not_a_mode must be object`,
which is about the probe's VALUE and says nothing about whether a deeper shape is
accepted. One level down the probe is a plugin's own document, which upstream
hands to that plugin unread; a plugin nobody required costs the node one logged
line (`zenoh/src/api/loader.rs` @ `tracing::error!("Plugin load failure: {e}")`).

Until this round that key was printed as UNDECIDED and left to a reader to judge
by hand, which is a verdict nobody records. The probe is the thing that was
wrong, so the probe is what changed: `plugins` is measured like every other key
now, and a declared key whose probe is dead reds as a stale entry instead of
being excused by name.

## The SECOND question, added in R2149 (open-debt item 538)

The classification above already separates a mode table from an opaque subtree,
and until R2149 the file threw that apart away -- both folded into one `accepts`
set, the distinction surviving only in `--verbose` output and compared against
nothing. So `MODE_DEPENDENT_CONFIG_KEYS` was never asked of upstream at all,
while every existing gate over it checks wz's constants against wz's OWN reader.
A wz that is wrong about upstream and self-consistent passes all of them.

It matters because that constant decides whether `inside_a_mode_table` lifts
every leaf under a key OUT of the ignored report. A key wrongly on it makes wz
read an operator's typo as a row of a table it honours: not applied, not
reported, silent.

⛔ THE TWO DIRECTIONS ARE ASYMMETRIC, AND THAT ASYMMETRY IS THE DESIGN. A
declared key is refuted only by a measured NOT-A-TABLE. OPAQUE does NOT refute
one: it is a fact about THE PROBE's reach, not about the key, so a declared key
the probe cannot reach is printed by name and folded into no pass. The other
direction needs no such care and carries the worse consequence: a HONOURED key
upstream resolves as a mode table which wz has not declared is a spelling wz
refuses and zenohd accepts, so the node does not start on a file zenohd runs.

## The resolved-config probe, for the keys the message cannot reach

Two keys answered OPAQUE to the generic probe while belonging on the list:
`scouting/gossip/autoconnect_strategy` and `scouting/multicast/autoconnect_strategy`.
Upstream reads them as `ModeDependentValue<TargetDependentValue<AutoConnectStrategy>>`,
whose deserializer tries the mode table first and, when that fails, reads the
same object as a TARGET table
(`commons/zenoh-config/src/mode_dependent.rs` @ `if let Ok(values) =`), and a
target table keeps only its `to_` members and drops the rest
(`commons/zenoh-config/src/mode_dependent.rs` @ `serde_with::with_prefix!(target_prefix "to_");`).
So no object the probe can hand them is an error, and no message will ever say
"mode table" for them.

What does say it is the daemon's own resolved config
(`zenohd/src/main.rs` @ `tracing::info!("Initial conf: {}", &config);`), the
oracle `upstream_carries_the_surface.py` reads. `RESOLVED_TABLE_PROBES` gives each
such key a value of its OWN type, and the key is asked twice:

  * the CONTROL, the value alone. It must resolve to itself, or the value is not
    one the key takes and the second answer would be about the probe -- a FAIL,
    never a verdict;
  * the TABLE, `{ router: <value> }` on a node that is a peer. A mode table
    resolves to exactly that; a target table drops the `router` member, which
    is not one of its `to_` fields.

The table names a mode the node is NOT, so the member can survive only because
the value was read as a table keyed by mode, and not because something resolved
it for the node's own mode.

## The decision on the unhonoured half

The surface this sweeps is the honoured parts plus
`UNHONOURED_UPSTREAM_CONFIG_KEYS`, and every key of that second list must be
either built or excluded with a reason. `UNHONOURED_DISPOSITIONS` records which,
one row per key, and this script reads it before any probe runs: a key nobody
decided about, a row for a key wz now honours, an unknown kind, an empty reason
or an excluded reader gap is a FAIL, and the split is printed beside the surface
with every excluded key named. The Rust unit test
`every_unhonoured_key_carries_one_disposition` holds the same table in every
lane that compiles the crate; this is the reading the surface count sits next to.

## Where this runs

Layer Z (`scripts/run-ci.sh`), which the hosted `interop` job runs with
`WZ_Z_REQUIRE=1` after BUILDING zenohd -- so the oracle is provisioned there
rather than absent. That lane SKIPs on a machine which has not built zenohd and
FAILs under `WZ_Z_REQUIRE`; this script still exits 2 on a missing binary, for
the same reason in the smaller. A gate whose input is absent must not report
green.

pre-push never runs Layer Z, so none of this slows a push. Wall clock is why it
sits there and not in a fast lane: one zenohd startup per key, re-measured in
R2230 at 122s for the 115-key surface under the 1.10.0 pin -- the same figure
`run-ci.sh` carries beside the call, deliberately, because two numbers for one
measurement is how the pair R2149 had to correct went stale in the first place.
The resolved-config probe adds two starts per key it holds.

`--selftest` drives the probe documents and every classifier over synthetic
input with no zenohd at all, which is what Layer C0 runs.

⚠ R2230 -- THIS SCRIPT CANNOT SEE THE THIRD STATE A KEY CAN BE IN, and the pin
move to 1.10.0 is where that stopped being theoretical. It reported
`routing/peer/mode` and `routing/peer/linkstate/transport_weights` as newly
"accepting a deeper shape", which reads as upstream having GROWN a subtree.
Upstream had RETIRED them, into a deprecated shim typed `Option<Value>` that
accepts any shape at all -- and "accepts anything" is indistinguishable from
"means something" to a probe that classifies by whether the node started.
`upstream_carries_the_surface.py` asks the question this one structurally
cannot, by reading the daemon's own serialized config; the two run beside each
other in Layer Z and neither subsumes the other.

⚠ Until R2149 this section was titled "Why this is NOT wired into a CI layer"
and said the oracle is one "no CI runner has". That had been false since R2080
wired it into Layer Z, and a reader who believed it would have taken every
check below for a local convenience nothing enforces.

Usage:
    python3 scripts/lib/deepenable_audit.py [--verbose]
    python3 scripts/lib/deepenable_audit.py --selftest
"""

from __future__ import annotations

import argparse
import json
import os
import pathlib
import re
import subprocess
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))

import rust_comments  # noqa: E402  -- after the path insert that finds it
from artifact_root import artifact  # noqa: E402  -- where the oracle is installed
import tempfile
import time

REPO_ROOT = pathlib.Path(__file__).resolve().parents[2]
SOURCE = REPO_ROOT / "crates" / "wz-runtime-tokio" / "src" / "zenoh_config.rs"
# R2080 — the same override the test harness reads (`zenohd_binary()`), so the
# lane and this script cannot end up asking two different binaries.
ZENOHD = pathlib.Path(os.environ.get("WZ_ZENOHD_BIN") or artifact("target/zenohd/zenohd"))

MODE_TABLE_MARKER = "expected one of `router`, `peer`, `client`"
STARTED_MARKER = "Zenoh can be reached at"
RESOLVED_MARKER = "Initial conf:"
# The daemon's resolved config, as the one line it prints it on. Shared with
# `upstream_carries_the_surface.py`, which imports it rather than spelling it
# again: two readers of one line are one pattern.
INITIAL_CONF = re.compile(r"Initial conf: (\{.*\})\s*$")

# The value every key is probed with.
GENERIC_PROBE = "{ zzz_not_a_mode: 1 }"

# The keys whose value is a map from a free member name to an object, so the
# deeper shape the question is about starts one level further down. See the
# module doc: the generic value at `plugins` is refused for its type.
MEMBER_MAP_KEYS = frozenset({"plugins"})

# The keys whose value type accepts any object, each with a value of its own
# type for the resolved-config probe. See the module doc for why the message
# probe cannot reach them and what this one reads instead.
RESOLVED_TABLE_PROBES: dict[str, dict] = {
    "scouting/gossip/autoconnect_strategy": {"to_router": "greater-zid"},
    "scouting/multicast/autoconnect_strategy": {"to_router": "greater-zid"},
}

# The mode the table probe names. Not the probe node's own mode (`peer`), so a
# member that survives was read as a row of a table and not resolved for the
# node.
TABLE_PROBE_MODE = "router"

# What `value_at` answers for a path the resolved config does not carry. A
# sentinel rather than None, because `null` is a value the config does carry.
MISSING = object()


def rust_const(name: str, text: str | None = None) -> list[str]:
    """Read a `&[&str]` constant out of the reader's own source.

    `text` is the source to read INSTEAD of the file, for a caller that grades
    a text it was handed (`runtime_mutable_surface_gate.py` damages copies of it
    in its selftest). Passing it changes where the bytes come from and nothing
    about how they are read.

    R2083 — COMMENT LINES ARE DROPPED FIRST, and that is not tidiness. These
    constants carry long `//` rationales between their entries, and several of
    those quote a phrase: `"wz cannot do this"`, `"the reader does not read
    this"`. A string sweep that does not strip comments reads PROSE AS DATA —
    measured, it turned `HONOURED_CONFIG_KEYS`'s 30 entries into 35 and put a
    wrong surface number into this project's own notes for a round. The floors
    below could not catch it: counting too MANY passes every one of them.
    """
    src = SOURCE.read_text() if text is None else text
    # R2230 — TWO shapes, and the single-line one is not a nicety. The pattern
    # was `= &\[(.*?)\n\];`, which a const declared entirely on its own line
    # (`= &["routing/peer/mode"];`) does not match at all -- so `.*?` ran on to
    # the NEXT `\n];` in the file and swallowed a whole other constant. Measured
    # the day it was introduced: `WZ_EXTENSION_HONOURED_KEYS` read as 80 keys
    # instead of 1, and `config_key_fixture_gate` reported 116 honoured keys and
    # 79 "missing" fixture entries. It did not fail to read; it read something
    # else and said nothing, which is the failure mode this whole file is about.
    m = re.search(
        r"(?:pub )?const " + name + r": &\[&str\] = &\[([^\n]*?)\];", src
    ) or re.search(
        r"(?:pub )?const " + name + r": &\[&str\] = &\[(.*?)\n\];", src, re.S
    )
    if not m:
        raise SystemExit(f"deepenable-audit: FAIL -- {name} not found in {SOURCE}")
    # The anti-swallow guard, because the bug above was silent and a louder
    # pattern is not the same as a checked one: no `&[&str]` constant's BODY
    # contains another item declaration, so finding one means the match ran past
    # the constant it was asked for.
    if re.search(r"^\s*(?:pub )?(?:const|fn|struct|enum) ", m.group(1), re.M):
        raise SystemExit(
            f"deepenable-audit: FAIL -- the read of {name} ran past its own "
            f"`];` and swallowed a following item. Do not widen this pattern to "
            f"accept the result: fix the shape it could not match."
        )
    # R2131 (unregistered open-debt item 402) — the stripping moved to
    # `rust_comments`, which two other sweeps measured this round now share. It
    # BLANKS a comment rather than dropping its line, which is stricter than the
    # whole-line test this used to do: a trailing `// "phrase"` after a real
    # entry was never covered by "the line starts with //".
    body = rust_comments.strip_comments(m.group(1))
    return re.findall(r'"([^"]+)"', body)


def rust_const_rows(name: str, text: str | None = None) -> list[tuple[str, str, str]]:
    """Read a `&[(&str, &str, &str)]` constant out of the reader's own source.

    Comments are blanked first, for the reason `rust_const` gives, and the
    anti-swallow guard is the same one. rustfmt puts each member of a long row
    on its own line, so a row is read across newlines.
    """
    src = SOURCE.read_text() if text is None else text
    m = re.search(
        r"(?:pub )?const " + name + r": &\[\(&str, &str, &str\)\] = &\[(.*?)\n\];",
        src,
        re.S,
    )
    if not m:
        raise SystemExit(f"deepenable-audit: FAIL -- {name} not found in {SOURCE}")
    if re.search(r"^\s*(?:pub )?(?:const|fn|struct|enum) ", m.group(1), re.M):
        raise SystemExit(
            f"deepenable-audit: FAIL -- the read of {name} ran past its own "
            f"`];` and swallowed a following item."
        )
    body = rust_comments.strip_comments(m.group(1))
    return re.findall(
        r'\(\s*"([^"]*)"\s*,\s*"([^"]*)"\s*,\s*"([^"]*)"\s*,?\s*\)', body, re.S
    )


def disposition_failures(
    unhonoured: list[str],
    reader_gap: list[str],
    rows: list[tuple[str, str, str]],
    kinds: list[str],
) -> list[str]:
    """What is wrong with the decision table, as sentences; empty when nothing.

    The table must decide every unhonoured key exactly once, in a known kind,
    with a reason, and must not exclude a reader gap: a key whose capability wz
    already has is not one wz can decline.
    """
    failures: list[str] = []
    if not kinds:
        failures.append("UNHONOURED_DISPOSITION_KINDS read as empty")
    if not rows:
        failures.append("UNHONOURED_DISPOSITIONS read as empty, so it decides nothing")
    decided: dict[str, str] = {}
    for key, kind, reason in rows:
        if key in decided:
            failures.append(f"{key} carries two dispositions")
        decided[key] = kind
        if kind not in kinds:
            failures.append(f"{key}: kind {kind!r} is not one of {kinds}")
        if not reason.strip():
            failures.append(f"{key}: a decision with no reason")
        if key not in unhonoured:
            failures.append(f"{key}: decided and not unhonoured; drop its row")
    for key in unhonoured:
        if key not in decided:
            failures.append(f"{key}: unhonoured and nobody decided build or exclude")
    for key in reader_gap:
        if decided.get(key) == "exclude":
            failures.append(
                f"{key}: excluded while wz has its capability (a reader gap)"
            )
    return failures


def rust_const_usize(name: str) -> int:
    """Read a `usize` literal constant out of the reader's own source."""
    src = rust_comments.strip_comments(SOURCE.read_text())
    m = re.search(r"(?:pub )?const " + name + r": usize = (\d+);", src)
    if not m:
        raise SystemExit(f"deepenable-audit: FAIL -- {name} not found in {SOURCE}")
    return int(m.group(1))


def honoured_surface(text: str | None = None) -> list[str]:
    """Every honoured key of the upstream surface, in `HONOURED_SURFACE_PARTS` order.

    R2963 (open-debt item 843) -- the parts are read BY NAME out of that
    constant, so a list added to it is a list every caller of this function
    counts the day it lands. Before this, each script wrote
    `HONOURED_CONFIG_KEYS` out by hand, R2957 added a second honoured list to
    the Rust predicate, and the surface these scripts printed fell from 113 to
    111 without one of them turning red.

    The parts constant is a `&[&[&str]]` of identifiers, not string literals, so
    it is read with the identifier pattern: comments are blanked first, for the
    reason `rust_const` gives.
    """
    src = rust_comments.strip_comments(SOURCE.read_text() if text is None else text)
    m = re.search(
        r"(?:pub )?const HONOURED_SURFACE_PARTS: &\[&\[&str\]\] = &\[(.*?)\];",
        src,
        re.S,
    )
    if not m:
        raise SystemExit(
            f"deepenable-audit: FAIL -- HONOURED_SURFACE_PARTS not found in {SOURCE}"
        )
    parts = re.findall(r"\b[A-Z][A-Z0-9_]*\b", m.group(1))
    if not parts:
        raise SystemExit(
            "deepenable-audit: FAIL -- HONOURED_SURFACE_PARTS names no list, so "
            "the honoured half of the surface would read as empty and pass."
        )
    return [key for part in parts for key in rust_const(part, text)]


def upstream_surface() -> list[str]:
    """The UPSTREAM config surface, sorted: the honoured parts, then the
    unhonoured list -- and REFUSED unless it is exactly `UPSTREAM_SURFACE_SIZE`
    distinct keys.

    The size check is the reason this is a function and not a union each caller
    writes. The pin is a literal in Rust that the unit test holds; checking it
    here as well makes a surface that moved without a decision red in every
    instrument that counts it, instead of only in the one that happens to know
    the literal.
    """
    keys = honoured_surface() + rust_const("UNHONOURED_UPSTREAM_CONFIG_KEYS")
    distinct = sorted(set(keys))
    if len(distinct) != len(keys):
        dupes = sorted({k for k in keys if keys.count(k) > 1})
        raise SystemExit(
            f"deepenable-audit: FAIL -- {len(keys) - len(distinct)} key(s) sit in "
            f"two parts of the upstream surface: {dupes}"
        )
    pinned = rust_const_usize("UPSTREAM_SURFACE_SIZE")
    if len(distinct) != pinned:
        raise SystemExit(
            f"deepenable-audit: FAIL -- the upstream surface composed from "
            f"HONOURED_SURFACE_PARTS and UNHONOURED_UPSTREAM_CONFIG_KEYS has "
            f"{len(distinct)} key(s) and UPSTREAM_SURFACE_SIZE pins {pinned}. A "
            f"surface that moved needs a decision beside a measurement "
            f"(upstream_carries_the_surface.py), not a quiet new denominator."
        )
    return distinct


def probe_value(key: str) -> str:
    """The deeper shape `key` is handed: the generic object, one level further
    down for a key whose members are named."""
    if key in MEMBER_MAP_KEYS:
        return "{ zzz_not_a_mode: %s }" % GENERIC_PROBE
    return GENERIC_PROBE


def document_with(key: str, value: str) -> str:
    """`{ mode: "peer", <key as nested objects>: <value> }`, json5."""
    if key == "mode":
        return "{ mode: %s }" % value
    inner = value
    for seg in reversed(key.split("/")):
        inner = "{ %s: %s }" % (seg, inner)
    return '{ mode: "peer", %s }' % inner[1:-1].strip()


def document_for(key: str) -> str:
    """The shape probe's document for `key`."""
    return document_with(key, probe_value(key))


def run_zenohd(document: str, workdir: pathlib.Path, answered) -> tuple[bool, str]:
    """Start zenohd on `document`; stop as soon as `answered(log)` holds.

    Returns whether it held and everything the daemon said.

    R2080 — the first cut let `subprocess.run` hit a fixed timeout, so every key
    whose subtree is opaque cost the whole timeout instead of the ~60ms it takes
    zenohd to print its resolved config. Waiting for a deadline that has already
    been answered is not caution, it is just slower; the refusals still cost what
    zenohd's own startup costs, and that part is not ours to shorten.
    """
    config = workdir / "probe.json5"
    config.write_text(document + "\n")
    log = workdir / "probe.log"
    held = False
    with open(log, "wb") as sink:
        proc = subprocess.Popen(
            [str(ZENOHD), "-c", str(config), "--rest-http-port", "none"],
            stdout=sink,
            stderr=sink,
        )
        deadline = time.monotonic() + 30.0
        while True:
            if answered(log.read_text(errors="replace")):
                held = True
                break
            if proc.poll() is not None:
                break
            if time.monotonic() > deadline:
                break
            time.sleep(0.02)
        if proc.poll() is None:
            proc.kill()
        proc.wait()
    blob = log.read_text(errors="replace")
    # A daemon that wrote its answer and exited between the read and the poll
    # above has still answered.
    return held or answered(blob), blob


def started(blob: str) -> bool:
    """The node came up, or got as far as printing the config it resolved."""
    return STARTED_MARKER in blob or RESOLVED_MARKER in blob


def classify_shape(accepted: bool, blob: str) -> str:
    """What the shape probe's answer says about the key."""
    if accepted:
        return "OPAQUE"
    if MODE_TABLE_MARKER in blob:
        return "MODE_TABLE"
    return "REFUSED"


def verdict_for(key: str, workdir: pathlib.Path) -> str:
    """Run the shape probe for one key."""
    accepted, blob = run_zenohd(document_for(key), workdir, started)
    return classify_shape(accepted, blob)


def initial_conf_json(blob: str) -> str | None:
    """The JSON of the daemon's `Initial conf:` line, or None.

    Only a line the daemon has FINISHED writing counts: the log is read while
    zenohd writes it, and half a line of JSON is not a config.
    """
    for line in blob.splitlines(keepends=True):
        if not line.endswith("\n"):
            continue
        match = INITIAL_CONF.search(line.rstrip("\n"))
        if match:
            return match.group(1)
    return None


def value_at(dump: object, key: str) -> object:
    """The resolved value at `key`, or `MISSING`."""
    node = dump
    for seg in key.split("/"):
        if not isinstance(node, dict) or seg not in node:
            return MISSING
        node = node[seg]
    return node


def prune_nulls(value: object) -> object:
    """`value` with every `null` member of every object left out.

    Upstream renders a field it carries and has no value for as an explicit
    null, and an absent member and a null one both state nothing, so neither
    may decide a comparison.
    """
    if isinstance(value, dict):
        return {k: prune_nulls(v) for k, v in value.items() if v is not None}
    if isinstance(value, list):
        return [prune_nulls(v) for v in value]
    return value


def table_verdict(control: object, table: object, value: object, mode: str) -> str:
    """What the two resolved answers say about mode-dependence.

    DEAD when the control did not resolve to the value it was handed: the value
    is then not one the key takes, and the table answer is about the probe.
    """
    if control != value:
        return "DEAD"
    if table == {mode: value}:
        return "MODE_TABLE"
    return "NOT_A_MODE_TABLE"


def resolved_at(key: str, value: object, workdir: pathlib.Path) -> object:
    """Start zenohd with `value` at `key` and read back what it resolved there."""
    document = document_with(key, json.dumps(value))
    _, blob = run_zenohd(
        document, workdir, lambda text: initial_conf_json(text) is not None
    )
    text = initial_conf_json(blob)
    if text is None:
        raise SystemExit(
            f"deepenable-audit: FAIL -- zenohd printed no complete `Initial conf:` "
            f"line for {document}, so the resolved-config probe of {key} has "
            f"nothing to read. Its last words:\n{blob[-2000:]}"
        )
    try:
        dump = json.loads(text)
    except json.JSONDecodeError as exc:
        raise SystemExit(
            f"deepenable-audit: FAIL -- the `Initial conf:` line for {document} "
            f"is not JSON ({exc}), so the resolved-config probe of {key} reads "
            f"nothing."
        ) from exc
    return prune_nulls(value_at(dump, key))


def mode_verdict(shape: str, table: str | None) -> str:
    """MODE_TABLE, NOT_A_MODE_TABLE or UNREACHED for one key.

    The resolved-config probe decides a key it holds; otherwise the shape
    probe's message does, and an OPAQUE answer decides nothing.
    """
    if table is not None:
        return table
    return {
        "MODE_TABLE": "MODE_TABLE",
        "REFUSED": "NOT_A_MODE_TABLE",
        "OPAQUE": "UNREACHED",
    }[shape]


def selftest() -> int:
    """Drive the probe documents and every classifier, with no zenohd.

    Each classifier is driven in BOTH directions, because a check whose
    fixtures only reach its passing arm proves nothing about the arm it exists
    for.
    """
    failures: list[str] = []

    def expect(got: object, want: object, what: str) -> None:
        if got != want:
            failures.append(f"{what}: got {got!r}, want {want!r}")

    expect(
        document_for("plugins"),
        '{ mode: "peer", plugins: { zzz_not_a_mode: { zzz_not_a_mode: 1 } } }',
        "a member-map key is probed one level further down",
    )
    expect(
        document_for("connect/retry"),
        '{ mode: "peer", connect: { retry: { zzz_not_a_mode: 1 } } }',
        "any other key gets the generic object at the key",
    )
    expect(
        document_for("mode"),
        "{ mode: { zzz_not_a_mode: 1 } }",
        "mode is its own document",
    )
    expect(
        document_with(
            "scouting/multicast/autoconnect_strategy",
            json.dumps({TABLE_PROBE_MODE: {"to_router": "greater-zid"}}),
        ),
        '{ mode: "peer", scouting: { multicast: { autoconnect_strategy: '
        '{"router": {"to_router": "greater-zid"}} } } }',
        "the table probe's document",
    )

    expect(classify_shape(True, ""), "OPAQUE", "a node that came up")
    expect(
        classify_shape(False, "unknown field `zzz_not_a_mode`, " + MODE_TABLE_MARKER),
        "MODE_TABLE",
        "the mode-table message",
    )
    expect(
        classify_shape(False, "plugins.zzz_not_a_mode must be object"),
        "REFUSED",
        "any other refusal",
    )
    expect(started("x Initial conf: {}\n"), True, "the resolved line is an answer")
    expect(started("panicked at ..."), False, "a refusal is not")

    line = '\x1b[2m2026\x1b[0m INFO zenohd: Initial conf: {"a":{"b":1}}\n'
    expect(initial_conf_json(line), '{"a":{"b":1}}', "a finished resolved line")
    expect(initial_conf_json(line.rstrip("\n")), None, "a line still being written")
    expect(initial_conf_json("Zenoh can be reached at x\n"), None, "no resolved line")

    expect(value_at({"a": {"b": 1}}, "a/b"), 1, "a carried path")
    expect(value_at({"a": {}}, "a/b") is MISSING, True, "a path not carried")
    expect(value_at({"a": 5}, "a/b") is MISSING, True, "a scalar on the path")
    expect(
        prune_nulls({"to_router": "x", "to_peer": None, "n": [{"k": None}]}),
        {"to_router": "x", "n": [{}]},
        "nulls left out at every depth",
    )
    expect(prune_nulls(MISSING) is MISSING, True, "MISSING passes through")

    value = {"to_router": "greater-zid"}
    expect(
        table_verdict(value, {"router": value}, value, "router"),
        "MODE_TABLE",
        "the table resolved as a table",
    )
    expect(
        table_verdict(value, {}, value, "router"),
        "NOT_A_MODE_TABLE",
        "a target table dropped the mode member",
    )
    expect(
        table_verdict(value, value, value, "router"),
        "NOT_A_MODE_TABLE",
        "the table was read as the value itself",
    )
    expect(
        table_verdict(MISSING, {"router": value}, value, "router"),
        "DEAD",
        "the control carried nothing",
    )
    expect(
        table_verdict({}, {"router": value}, value, "router"),
        "DEAD",
        "the control dropped its own value",
    )

    expect(mode_verdict("MODE_TABLE", None), "MODE_TABLE", "the message said table")
    expect(mode_verdict("REFUSED", None), "NOT_A_MODE_TABLE", "the message refused")
    expect(mode_verdict("OPAQUE", None), "UNREACHED", "opaque decides nothing")
    expect(mode_verdict("OPAQUE", "MODE_TABLE"), "MODE_TABLE", "the second probe wins")
    expect(
        mode_verdict("OPAQUE", "NOT_A_MODE_TABLE"),
        "NOT_A_MODE_TABLE",
        "the second probe refutes",
    )

    gap = ["g"]
    good = [("a", "build", "why"), ("g", "build", "has it"), ("x", "exclude", "why not")]
    kinds = ["build", "exclude"]
    expect(disposition_failures(["a", "g", "x"], gap, good, kinds), [], "a total table")
    for what, unhonoured, rows in (
        ("an undecided key", ["a", "g", "x", "y"], good),
        ("a row for a key wz honours", ["a", "g"], good),
        ("a duplicate row", ["a", "g", "x"], good + [("a", "build", "again")]),
        ("an unknown kind", ["a", "g", "x"], [("a", "later", "why")] + good[1:]),
        ("an empty reason", ["a", "g", "x"], [("a", "build", " ")] + good[1:]),
        ("an excluded reader gap", ["a", "g", "x"], [good[0], ("g", "exclude", "no"), good[2]]),
        ("an empty table", ["a"], []),
    ):
        expect(
            bool(disposition_failures(unhonoured, gap, rows, kinds)),
            True,
            f"the disposition check passed {what}",
        )
    table = (
        'pub const UNHONOURED_DISPOSITIONS: &[(&str, &str, &str)] = &[\n'
        '    // a "quoted" comment is not a row\n'
        '    ("k/a", "build", "short"),\n'
        "    (\n"
        '        "k/b",\n'
        '        "exclude",\n'
        '        "a reason, with a comma",\n'
        "    ),\n"
        "];\n"
    )
    expect(
        rust_const_rows("UNHONOURED_DISPOSITIONS", table),
        [("k/a", "build", "short"), ("k/b", "exclude", "a reason, with a comma")],
        "a table read across rustfmt's row shapes, comments blanked",
    )

    # The two probe tables are disjoint, name no `mode`, and hand the table
    # probe objects, which is the only shape the comparison above is about.
    expect(
        sorted(MEMBER_MAP_KEYS & set(RESOLVED_TABLE_PROBES)), [], "the tables overlap"
    )
    expect("mode" in RESOLVED_TABLE_PROBES, False, "mode in the table probes")
    expect(
        [k for k, v in RESOLVED_TABLE_PROBES.items() if not isinstance(v, dict)],
        [],
        "a table probe value that is not an object",
    )

    if failures:
        for failure in failures:
            print(f"  deepenable-audit: SELFTEST FAIL -- {failure}")
        return 1
    print("  deepenable-audit: selftest ok")
    return 0


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--verbose", action="store_true")
    ap.add_argument(
        "--selftest",
        action="store_true",
        help="drive the probe documents and classifiers; needs no zenohd",
    )
    args = ap.parse_args()

    if args.selftest:
        return selftest()

    if not ZENOHD.is_file():
        print(
            f"deepenable-audit: FAIL -- no zenohd at {ZENOHD}. This audit's whole "
            f"content is what UPSTREAM answers, so an absent oracle is a failure "
            f"and not a skip. Run scripts/build-zenohd.sh.",
            file=sys.stderr,
        )
        return 2

    surface = upstream_surface()
    declared = set(rust_const("DEEPENABLE_UPSTREAM_KEYS"))
    # R2080 — FLOORS, not just non-emptiness. The constants are read out of Rust
    # by regex, so a reformat that split one of them differently would be read
    # PARTIALLY, and a partial read PASSES: fewer keys probed, nothing said. That
    # is "a population of zero is green" in its quieter form. The floors sit far
    # below the measured 116 / 17, so ordinary movement of the surface does not
    # touch them and only a broken read can reach them.
    if len(surface) < 100:
        raise SystemExit(
            f"deepenable-audit: FAIL -- read only {len(surface)} surface key(s) out "
            f"of {SOURCE.name}. The constant moved, so this sweep is measuring a "
            f"fraction of the surface while reporting on all of it."
        )
    if len(declared) < 10:
        raise SystemExit(
            f"deepenable-audit: FAIL -- read only {len(declared)} deepenable key(s). "
            f"A partial read of the exception list makes every key it lost look "
            f"like a missing entry."
        )
    # The surface's unhonoured half, and what wz decided about each key of it.
    # Read before any probe runs: it needs no zenohd, and a table that does not
    # decide the surface it sits beside is a red the probes cannot change.
    unhonoured = rust_const("UNHONOURED_UPSTREAM_CONFIG_KEYS")
    dispositions = rust_const_rows("UNHONOURED_DISPOSITIONS")
    undecided_table = disposition_failures(
        unhonoured,
        rust_const("UNHONOURED_READER_GAP"),
        dispositions,
        rust_const("UNHONOURED_DISPOSITION_KINDS"),
    )
    for failure in undecided_table:
        print(f"  deepenable-audit: {failure}")

    # A probe for a key the surface does not have would measure nothing anyone
    # counts, and pass by having no subject.
    for name, keys in (
        ("MEMBER_MAP_KEYS", MEMBER_MAP_KEYS),
        ("RESOLVED_TABLE_PROBES", set(RESOLVED_TABLE_PROBES)),
    ):
        off = sorted(set(keys) - set(surface))
        if off:
            raise SystemExit(
                f"deepenable-audit: FAIL -- {name} holds {off}, which the upstream "
                f"surface does not. A probe shape for a key nobody counts is a "
                f"row with no subject; drop it or put the key back on the surface."
            )

    accepts: set[str] = set()
    verdicts: dict[str, str] = {}
    table_verdicts: dict[str, str] = {}
    with tempfile.TemporaryDirectory() as tmp:
        workdir = pathlib.Path(tmp)
        for key in surface:
            verdict = verdict_for(key, workdir)
            verdicts[key] = verdict
            if verdict in ("OPAQUE", "MODE_TABLE"):
                accepts.add(key)
            if args.verbose:
                print(f"  {key:48s} {verdict}")
        for key, value in sorted(RESOLVED_TABLE_PROBES.items()):
            # The second probe exists for the keys the first cannot reach. A
            # key the message already decides does not need it, and keeping the
            # row would hide the day upstream's type stopped swallowing the
            # probe.
            if verdicts[key] != "OPAQUE":
                raise SystemExit(
                    f"deepenable-audit: FAIL -- {key} is in RESOLVED_TABLE_PROBES "
                    f"and the shape probe answered {verdicts[key]}, so its message "
                    f"decides the key. Drop the row."
                )
            control = resolved_at(key, value, workdir)
            table = resolved_at(key, {TABLE_PROBE_MODE: value}, workdir)
            verdict = table_verdict(control, table, value, TABLE_PROBE_MODE)
            if verdict == "DEAD":
                raise SystemExit(
                    f"deepenable-audit: FAIL -- {key} resolved {value!r} to "
                    f"{control!r}, so that value is not one the key takes and the "
                    f"table probe would measure the probe. Fix its row in "
                    f"RESOLVED_TABLE_PROBES; a dead probe is not a verdict."
                )
            table_verdicts[key] = verdict
            if args.verbose:
                print(f"  {key:48s} {verdict} (resolved {table!r})")

    missing = sorted(accepts - declared)
    stale = sorted(declared - accepts)

    for key in missing:
        print(
            f"  deepenable-audit: {key} accepts a deeper shape and is NOT in "
            f"DEEPENABLE_UPSTREAM_KEYS. wz REFUSES a file zenohd starts on."
        )
    for key in stale:
        print(
            f"  deepenable-audit: {key} is in DEEPENABLE_UPSTREAM_KEYS and refuses "
            f"a deeper shape. wz accepts a typo zenohd would catch -- or this "
            f"key's probe value is wrong for its type, which MEMBER_MAP_KEYS is "
            f"where to say."
        )

    # ── the MODE-TABLE cross-check (R2149, open-debt item 538) ──────────
    #
    # This probe already SEPARATES a mode table from an opaque subtree -- the
    # message says which -- and until R2149 it threw that apart away, folding
    # both into `accepts`. Nothing anywhere compared it to
    # `MODE_DEPENDENT_CONFIG_KEYS`, which is the constant deciding whether
    # `inside_a_mode_table` lifts every leaf under a key OUT of the ignored
    # report. A key wrongly in that list makes wz read an operator's typo as a
    # row of a table it honours: not applied, not reported, silent.
    #
    # ⚠ WHAT THIS ADDS AND WHAT IT DOES NOT, MEASURED IN R2149 RATHER THAN
    # CLAIMED. Item 538 said the two existing gates pass both wrong directions
    # green. They do not. Driven with the whole `zenoh_config::` module under
    # three constant mutations -- a declared key removed, an undeclared key
    # added, and a mode table re-modelled as named subtree fields -- each one
    # reds a PRE-EXISTING test in `zenoh_config.rs` (47 tests: 45, 45 and 46
    # passing). A constant edit alone always breaks wz's internal agreement
    # first, so nothing below is a new catch for an ordinary slip.
    #
    # What is new is the QUESTION. Every one of those gates checks wz's
    # constants against wz's OWN reader, and the `missing`/`stale` pair above
    # asks upstream only whether a key takes a deeper shape AT ALL -- which is
    # precisely the question that conflates a mode table with an opaque
    # subtree. A wz that is wrong about upstream and self-consistent passes all
    # of them: R2141 moved three keys onto this list on a hand reading of
    # upstream's types and nothing re-asked zenohd. This re-asks, once per key,
    # against a running node.
    #
    # ⛔ THE OBVIOUS COMPARISON IS WRONG, AND IT WAS MEASURED WRONG BEFORE R2149
    # SHIPPED. Item 538 prescribed comparing the MODE_TABLE set against the
    # constant in BOTH directions. Run that way, a real zenohd answers OPAQUE
    # for `scouting/multicast/autoconnect_strategy`, which IS in the constant and
    # belongs there. So:
    #
    #   * a declared key is refuted only by a measured NOT_A_MODE_TABLE --
    #     zenohd rejecting the table shape outright, or resolving the table
    #     probe as something else. OPAQUE is "the message cannot tell", and a
    #     declared key left there is printed BY NAME rather than folded into a
    #     pass; the two autoconnect strategies are decided by the
    #     resolved-config probe instead;
    #   * the other direction needs no such care and is the dangerous one: a
    #     HONOURED key a real zenohd answers MODE_TABLE for, which wz has not
    #     declared, is a table spelling wz REFUSES and zenohd accepts -- the node
    #     does not start. Scoped to honoured keys because the constant is
    #     documented as the honoured ones.
    mode_dependent = set(rust_const("MODE_DEPENDENT_CONFIG_KEYS"))
    honoured = set(honoured_surface())
    if not mode_dependent:
        raise SystemExit(
            "deepenable-audit: FAIL -- MODE_DEPENDENT_CONFIG_KEYS read as empty, "
            "so both directions below compare against nothing and pass."
        )
    mode_verdicts = {
        key: mode_verdict(shape, table_verdicts.get(key))
        for key, shape in verdicts.items()
    }
    upstream_tables = {k for k, v in mode_verdicts.items() if v == "MODE_TABLE"}
    if not upstream_tables:
        raise SystemExit(
            "deepenable-audit: FAIL -- no key on the whole surface answered "
            "MODE_TABLE. The marker no longer matches what zenohd prints, so "
            "this cross-check is measuring nothing."
        )

    # A declared key that is not on the surface at all would make BOTH checks
    # below pass by absence -- `mode_verdicts.get` answers None, which is
    # neither NOT_A_MODE_TABLE nor MODE_TABLE. That is this file's own "a
    # population of zero is green" shape, one level in, so it is a FAIL rather
    # than a silence. It cannot happen while the Rust side holds MODE_DEPENDENT
    # ⊆ DEEPENABLE ⊆ surface; this is here for when that stops being true.
    offsurface = sorted(k for k in mode_dependent if k not in mode_verdicts)
    if offsurface:
        raise SystemExit(
            "deepenable-audit: FAIL -- "
            + ", ".join(offsurface)
            + " is declared mode-dependent and is not on the measured surface, "
            "so nothing below judges it."
        )

    refuted = sorted(
        k for k in mode_dependent if mode_verdicts[k] == "NOT_A_MODE_TABLE"
    )
    unreached = sorted(k for k in mode_dependent if mode_verdicts[k] == "UNREACHED")
    undeclared = sorted((upstream_tables & honoured) - mode_dependent)

    for key in refuted:
        print(
            f"  deepenable-audit: {key} is in MODE_DEPENDENT_CONFIG_KEYS and a "
            f"real zenohd does not read a {{ router, peer, client }} table at it. "
            f"wz lifts every leaf under it out of the ignored report, so an "
            f"operator's typo there is neither applied nor reported."
        )
    for key in undeclared:
        print(
            f"  deepenable-audit: {key} is honoured and a real zenohd resolves it "
            f"as a {{ router, peer, client }} table, but wz has not declared it "
            f"mode-dependent. wz REFUSES the table spelling zenohd accepts, so "
            f"the node does not start on a file zenohd runs."
        )

    print(
        f"  deepenable-audit: surface {len(surface)}, declared {len(declared)}, "
        f"measured accepting {len(accepts)}"
    )
    # The split of the surface, and the decision on its unhonoured half. The
    # excluded keys are named, because an exclusion is a claim a reader checks
    # against its reason, and a count hides which claim it is.
    built = sorted(k for k, kind, _ in dispositions if kind == "build")
    excluded = sorted(k for k, kind, _ in dispositions if kind == "exclude")
    print(
        f"  deepenable-audit: surface {len(surface)} = honoured "
        f"{len(surface) - len(unhonoured)} + unhonoured {len(unhonoured)} "
        f"(to build {len(built)}, excluded {len(excluded)}"
        + (": " + ", ".join(excluded) if excluded else "")
        + ")"
    )
    print(
        f"  deepenable-audit: mode tables — {len(upstream_tables)} measured "
        f"({len(table_verdicts)} from the resolved config), "
        f"{len(mode_dependent)} declared by wz, "
        f"{len(upstream_tables & honoured)} of the measured are honoured"
    )
    if unreached:
        # Named, never a count folded into the pass: these are the keys whose
        # value type swallows the probe and that no resolved-config probe holds,
        # so the audit is SILENT about them rather than agreeing with wz.
        print(
            "  deepenable-audit: this probe cannot decide mode-dependence for "
            + ", ".join(unreached)
            + " (their value type accepts the probe's object, so the node "
            "starts); give each a value of its own type in RESOLVED_TABLE_PROBES."
        )
    outside = sorted(upstream_tables - honoured)
    if outside:
        # The `undeclared` direction is SCOPED to honoured keys, and a scope is a
        # claim like any other -- one that reads as coverage while it is really
        # an exclusion. So the excluded keys are printed BY NAME rather than left
        # as the arithmetic between the two counts above. Each is a real mode
        # table upstream which wz does not honour, so the constant is right to
        # omit it TODAY; each also becomes a FAIL the moment its key joins
        # HONOURED_CONFIG_KEYS without joining MODE_DEPENDENT_CONFIG_KEYS, which
        # is the transition this list exists to make visible before it happens.
        print(
            "  deepenable-audit: mode tables upstream that wz does not honour, "
            "so the constant omits them and the check above does not reach "
            "them: " + ", ".join(outside)
        )
    return 1 if missing or stale or refuted or undeclared or undecided_table else 0


if __name__ == "__main__":
    sys.exit(main())
