#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
# SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

"""R2336 (no register item) - does the pinned upstream READ every key wz counts
as upstream config surface?

The citation reads "no register item" for the reason `denied_term_lane_gate.py`
and `reason_citation_gate.py` do: the item this answers for -- unregistered
item 15, the PARTIAL-atom track -- lives in the operator's register outside this
repository, so there is no `debt-` id here for a citation to resolve. The atom
this round took off that track is `access-extauth-pubkey`, whose recorded
residual named "no `key_size` knob" as a wz gap.

## The gap this closes

`HONOURED_CONFIG_KEYS` + `UNHONOURED_UPSTREAM_CONFIG_KEYS` are read as coverage:
"of what a real zenoh does from its file, wz does N of M". R2230 established
that the sentence is only true while every member names something upstream
actually DOES, and built `upstream_carries_the_surface.py` to enforce it.

That gate asks upstream's SERIALIZER. It starts the pinned zenohd, reads the
daemon's own `Initial conf:` dump, and treats presence as "upstream carries
this" -- which is exactly right for the case it was built on, a `#[deprecated]`
shim marked `#[serde(skip_serializing)]` and therefore absent from the dump.

Serialization and CONSUMPTION are not the same question, and they come apart in
one direction that gate structurally cannot see: an ORDINARY field, serialized
like every other, whose value no upstream code ever reads.
`transport/auth/pubkey/key_size` and `transport/auth/pubkey/known_keys_file` are
that. A real zenohd resolves both, prints both, accepts a file that sets either
-- and `AuthPubKey::from_config` reads the four PEM fields beside them and stops
at `// @TODO: populate lookup file`, while nothing anywhere constructs a key of
`key_size` bits. MEASURED when this was written, over the pinned checkout: each
of those two leaf identifiers occurs exactly ONCE in 647 upstream `.rs` files,
on its own declaration line, and the other 113 surface keys all occur elsewhere.

⛔ The tree already KNEW this, and said so in prose. A frozen ledger entry reads
"A CONFIG KEY IS NOT A FEATURE. `known_keys_file` parses, appears in
DEFAULT_CONFIG.json5, prints in the router's startup config dump, and does
NOTHING -- the code that would read it is a `@TODO`", and two doc comments in
this tree say the same. The denominator went on counting both keys anyway, for
rounds. That is the shape R2335 named one layer up: a correction that only
NARRATES hands the claim straight to the next reader who greps it. The answer is
a gate, and this is it.

## The population, and why it is not a list

The population is wz's OWN constants, read out of `zenoh_config.rs`, and the
verdict is the pinned upstream's source. Nothing here enumerates what zenoh has,
so a pin move re-answers the question instead of ageing an answer. The floor
below exists because "the constant reader matched nothing" and "the surface is
empty" produce the same green in a check that only compares two sets.

## Both directions, or it is an exemption list

`UPSTREAM_INERT_CONFIG_KEYS` is a list of keys exempt from the surface, which is
precisely the shape that lets a later round shrink a denominator to make a check
green. So membership is ADJUDICATED here rather than declared, and every key
lands in exactly one of three measured states:

  * READ        -> upstream consumes the value. Must be on the surface lists.
  * INERT       -> declared exactly once, upstream-wide, and read nowhere. Must
                   be in the inert list.
  * UNDECIDABLE -> read nowhere, but its leaf occurs more than once (or not at
                   all) in upstream's config schema. FAILS by name.

A key in the wrong bucket fails, whichever way it points. The third state is a
FAIL rather than a category with members, for the reason
`upstream_carries_the_surface.py` gives its own: a branch nobody has run is a
branch nobody has checked, and a key whose leaf upstream does not declare at all
is a wz invention needing a decision, not an exemption.

## What "read" means here, and which way the coarseness points

A leaf is READ when its identifier occurs in any upstream `.rs` file OTHER than
the config schema's own declaration file. That is deliberately coarse: a generic
leaf like `enabled` matches in hundreds of places that have nothing to do with
the key. The coarseness therefore only ever produces MORE "read" verdicts, which
is the safe direction -- it can hide an inert key, never invent one. A key this
reports as inert has no mention anywhere in upstream outside one declaration
line, and no spelling of "upstream reads it" survives that.

The schema's accessors carry the field's own name (`config.public_key_pem()`),
and a `Config::get_json("transport/auth/pubkey/key_size")` string path contains
it too, so both routes to a value are matched by the same identifier scan.

## Where this runs

Layer Z (`scripts/run-ci.sh`), beside `upstream_carries_the_surface.py` and the
resolution arm of `upstream_citation_anchor_gate.py`, because it needs a zenoh
SOURCE tree and that is the lane which provisions one. The upstream root is
resolved through `upstream_citation_anchor_gate.upstream_root()` rather than a
second discovery of our own: two derivations could disagree about WHICH upstream
the tree means, which is what open debt 578 was opened for.

`--selftest` drives the classifier over a synthetic upstream with no checkout at
all, so Layer C0 can prove the discrimination is real on a machine that has no
zenoh source. It fails the classifier in BOTH directions on purpose: a selftest
whose fixtures only exercise the passing path is a fixture set the old
implementation would also have swallowed.

Usage:
    python3 scripts/lib/upstream_reads_the_surface.py [--verbose]
    python3 scripts/lib/upstream_reads_the_surface.py --selftest
"""

import pathlib
import re
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))

# The constant reader is `deepenable_audit`'s, imported rather than copied, for
# the reason `upstream_carries_the_surface.py` imports it: a second parser here
# would be a second chance to read Rust PROSE as data, which inflated this very
# surface by five once.
import deepenable_audit  # noqa: E402  -- after the path insert that finds it
import upstream_citation_anchor_gate  # noqa: E402  -- same

# Where upstream declares its config schema -- `commons/zenoh-config/src/lib.rs`
# @ `PubKeyConf`, spelled here as SEGMENTS for the reason
# `upstream_feature_census.upstream_anchors` spells its manifest path that way:
# a rooted upstream path in a string literal is a BARE citation to
# `upstream_citation_anchor_gate`, and this one is not a citation. It is an
# input, adjudicated by EXECUTION -- `upstream_texts` refuses with rc=2 when the
# file is not there, which is a stronger check than a static path scan, because
# the exclusion this path defines is what makes "read" mean "read somewhere
# other than the declaration". A wrong path would silently turn every key into a
# read and the gate could never fail.
SCHEMA_REL = pathlib.PurePosixPath("commons", "zenoh-config", "src", "lib.rs")

# Below this the reader is not reading the surface, whatever it returned.
SURFACE_FLOOR = 100

# Below this the scan is not looking at zenoh, whatever it found. A root that
# resolved to a directory with three Rust files would report every key inert.
UPSTREAM_FILE_FLOOR = 200


class InputError(Exception):
    """The gate could not READ its input, so it graded nothing (exit 2)."""


def rust_const(name: str) -> list[str]:
    try:
        return deepenable_audit.rust_const(name)
    except SystemExit as exc:  # its message names the other script
        raise InputError(f"could not read {name}: {exc}") from exc


def leaf_of(key: str) -> str:
    """The config leaf a key path ends in -- the identifier upstream declares.

    `transport/auth/pubkey/key_size` -> `key_size`. The schema macro names each
    accessor after its field, so this is the identifier a reader would spell.
    """
    return key.rsplit("/", 1)[-1]


def occurrences(leaf: str, texts: dict[str, str], schema: str) -> tuple[int, int]:
    """`(in the schema file, everywhere else)` for one leaf identifier.

    Whole-identifier matching, so `key_size` does not match `max_key_size` and
    `user` does not match `username` -- a substring scan would call every key
    read and the gate could never fail.
    """
    pat = re.compile(r"\b" + re.escape(leaf) + r"\b")
    inside = len(pat.findall(texts.get(schema, "")))
    outside = sum(len(pat.findall(t)) for rel, t in texts.items() if rel != schema)
    return inside, outside


def classify(
    surface: list[str],
    inert: list[str],
    texts: dict[str, str],
    schema: str,
) -> list[str]:
    """Every key's verdict against upstream's source. Returns the FINDINGS.

    An empty return is a pass. Each finding says which key, which direction and
    what to do, because the two repairs are opposites and a message that omits
    which one was found sends the reader to edit the wrong list.
    """
    findings: list[str] = []

    overlap = sorted(set(surface) & set(inert))
    if overlap:
        findings.append(
            f"inert AND on the surface, so counted in the denominator it was "
            f"moved out of: {overlap}"
        )

    for key in sorted(surface):
        _, outside = occurrences(leaf_of(key), texts, schema)
        if outside == 0:
            findings.append(
                f"{key}: wz counts this as upstream surface and the pinned "
                f"upstream READS it nowhere -- `{leaf_of(key)}` occurs in no "
                f"upstream source file outside the config schema. It names no "
                f"capability wz is failing to reach. Move it to "
                f"UPSTREAM_INERT_CONFIG_KEYS."
            )

    for key in sorted(inert):
        leaf = leaf_of(key)
        inside, outside = occurrences(leaf, texts, schema)
        if outside > 0:
            findings.append(
                f"{key}: declared INERT, but the pinned upstream mentions "
                f"`{leaf}` {outside} time(s) outside the config schema. "
                f"Upstream consumes it, so it is surface: move it back to "
                f"HONOURED_CONFIG_KEYS or UNHONOURED_UPSTREAM_CONFIG_KEYS."
            )
        elif inside != 1:
            findings.append(
                f"{key}: declared INERT and read nowhere, but `{leaf}` occurs "
                f"{inside} time(s) in the config schema where a plain "
                f"declaration occurs once. This is UNDECIDABLE by this scan, "
                f"not a pass -- read the schema and decide. A key upstream "
                f"does not declare at all is a wz invention needing a "
                f"decision, not a list entry."
            )

    return findings


def check_population(surface: list[str], inert: list[str]) -> None:
    """Refuse to grade a population that cannot fail.

    A separate function rather than two `if`s inside `main` so `--selftest` can
    RUN both branches. A floor nobody has ever crossed is a floor nobody has
    checked, and this file's whole subject is a check that could not fail.
    """
    if len(surface) < SURFACE_FLOOR:
        raise InputError(
            f"read {len(surface)} surface key(s) out of zenoh_config.rs, under "
            f"the floor of {SURFACE_FLOOR}. A comparison over an empty "
            f"population reports green without grading anything"
        )
    if not inert:
        raise InputError(
            "UPSTREAM_INERT_CONFIG_KEYS is empty, so the direction that keeps "
            "it from being an exemption list grades nothing"
        )


def upstream_texts() -> tuple[pathlib.Path, dict[str, str]]:
    """Every `.rs` file of the pinned upstream checkout, keyed by relative path.

    The root comes from `upstream_citation_anchor_gate.upstream_root()`, which
    is `upstream_feature_census.upstream_anchors()` plus a VERSION check -- the
    chain `build-zenohd.sh` mirrors. A machine holding the previous pin's
    checkout offers it first, and that gate measured what happens when nothing
    checks: a whole finding set resolved against the wrong release with no sign
    anything was wrong.
    """
    root = upstream_citation_anchor_gate.upstream_root()
    if root is None:
        raise InputError(
            "no zenoh SOURCE checkout at the pinned version is reachable. "
            "Tried ZENOHD_SRC, the metadata beside a provisioned zenohd, "
            "scripts/build-zenohd.sh's shallow clone, the cargo git checkouts "
            "and the registry cache. Provision one (bash scripts/build-zenohd.sh) "
            "or point ZENOHD_SRC at a checkout of the pinned tag."
        )
    schema = root / SCHEMA_REL
    if not schema.is_file():
        raise InputError(
            f"{root} has no {SCHEMA_REL} -- that path is the exclusion this "
            f"gate's verdict is defined against, so a wrong one would make "
            f"every key look read and the check could never fail"
        )
    texts: dict[str, str] = {}
    for path in root.rglob("*.rs"):
        rel = path.relative_to(root)
        # R2338 — RELATIVE to the checkout, and that is the whole fix. This
        # skips a build directory INSIDE the upstream tree; testing the ABSOLUTE
        # path instead asks whether any ancestor is named `target`, and hosted CI
        # puts the checkout at <repo>/target/zenohd-build/zenoh-src -- so every
        # file matched, the walk yielded nothing, and the floor below turned that
        # into rc 2. Layer Z had been red on it, correctly refusing to grade,
        # while the tree it was pointed at was complete: the ci.yml guard that
        # asserts this very checkout's protocol lib root passed in the same job.
        # Reproduced by pointing ZENOHD_SRC at the SAME tree through a path with
        # a `target` component -- same content, 647 files or 0 depending only on
        # where it sits.
        #
        # The exclusion STAYS rather than being deleted, and the reason is the
        # same environment: a developer's cargo-git checkout has no build tree
        # inside it (measured at the pin: zero directories named `target`, zero
        # `.rs` under one, of 647 in all), so locally this line never skips
        # anything. Hosted CI BUILDS zenoh in the tree it cloned, so the inner
        # build directory exists precisely there. The filter has no subject on
        # the machine where it looks harmless and a real one on the machine where
        # it bit.
        if "target" in rel.parts:
            continue
        try:
            texts[rel.as_posix()] = path.read_text(errors="replace")
        except OSError as exc:
            raise InputError(f"{path} is not readable ({exc})") from exc
    if len(texts) < UPSTREAM_FILE_FLOOR:
        raise InputError(
            f"{root} yielded {len(texts)} Rust file(s), under the floor of "
            f"{UPSTREAM_FILE_FLOOR}. A scan over a near-empty tree would report "
            f"every surface key inert, which is a verdict about zenoh issued by "
            f"a run that never read zenoh"
        )
    return root, texts


def selftest() -> int:
    """Drive the classifier in BOTH directions over a synthetic upstream.

    No checkout, no zenohd, no wz constants -- so this runs on Layer C0 and
    proves the discrimination is real rather than proving a path exists.
    """
    schema = SCHEMA_REL.as_posix()
    # A SYNTHETIC consumer path. It deliberately does not spell a real upstream
    # directory: a fixture that names one would be a citation to a file this
    # fixture never reads, and `upstream_citation_anchor_gate` would count it.
    consumer = "some/consumer.rs"
    texts = {
        schema: "struct Conf { live_key: Option<u8>, dead_key: Option<u8> }",
        consumer: "let n = conf.live_key();",
    }
    failures: list[str] = []

    def expect(label: str, got: list[str], want: bool) -> None:
        if bool(got) != want:
            failures.append(f"{label}: expected {'a finding' if want else 'none'}, got {got}")

    # The passing shape: a read key on the surface, an unread key declared inert.
    expect(
        "the correct partition passes",
        classify(["a/live_key"], ["b/dead_key"], texts, schema),
        False,
    )
    # Direction 1 -- a key upstream never reads, counted as surface. This is the
    # finding the round was opened on.
    expect(
        "an unread key on the surface reds",
        classify(["a/live_key", "b/dead_key"], [], texts, schema),
        True,
    )
    # Direction 2 -- a LIVE key parked in the exemption list. Without this the
    # list is an escape hatch: the cheapest way to green direction 1 is to move
    # the offending key here.
    expect(
        "a read key declared inert reds",
        classify([], ["a/live_key"], texts, schema),
        True,
    )
    # A key upstream does not declare at all is not silently inert.
    expect(
        "an undeclared key is UNDECIDABLE, not a pass",
        classify([], ["z/absent_key"], texts, schema),
        True,
    )
    # A key declared twice in the schema and read nowhere is undecidable too --
    # the plain-declaration count is what makes "inert" mechanical.
    twice = dict(texts)
    twice[schema] += "\n// dead_key is also mentioned here"
    expect(
        "a twice-mentioned schema key is UNDECIDABLE",
        classify([], ["b/dead_key"], twice, schema),
        True,
    )
    # Whole-identifier matching: a longer name that CONTAINS the leaf is not a
    # read of it. Without this every key looks read and the gate cannot fail.
    substring = {
        schema: "struct Conf { dead_key: Option<u8> }",
        consumer: "let n = conf.dead_key_size();",
    }
    expect(
        "a substring match is not a read",
        classify([], ["b/dead_key"], substring, schema),
        False,
    )
    # Both lists at once: a key cannot be counted and exempted together.
    expect(
        "a key in both buckets reds",
        classify(["a/live_key"], ["a/live_key"], texts, schema),
        True,
    )

    # The two population floors, RUN rather than declared. Each is what stops
    # the two directions above from grading nothing and reporting green, so a
    # floor this selftest never crosses is a floor nobody has checked.
    def refuses(label: str, surface: list[str], inert: list[str]) -> None:
        try:
            check_population(surface, inert)
        except InputError:
            return
        failures.append(f"{label}: check_population accepted a population that cannot fail")

    refuses("a surface under the floor is refused", ["a/one"], ["b/two"])
    refuses("an empty inert list is refused", [f"k{i}/leaf{i}" for i in range(SURFACE_FLOOR)], [])
    try:
        check_population([f"k{i}/leaf{i}" for i in range(SURFACE_FLOOR)], ["b/two"])
    except InputError as exc:
        failures.append(f"a sufficient population was refused: {exc}")

    for line in failures:
        print(f"  upstream-reads: SELFTEST FAIL -- {line}")
    if failures:
        return 1
    print("  upstream-reads: selftest ok -- classifier fails in both directions")
    return 0


def main(argv: list[str]) -> int:
    unknown = [a for a in argv if a not in ("--selftest", "--verbose")]
    if unknown:
        print(f"  upstream-reads: FAIL -- unknown argument(s): {unknown}")
        return 2
    if "--selftest" in argv:
        return selftest()
    verbose = "--verbose" in argv

    try:
        surface = sorted(
            set(rust_const("HONOURED_CONFIG_KEYS"))
            | set(rust_const("UNHONOURED_UPSTREAM_CONFIG_KEYS"))
        )
        inert = sorted(set(rust_const("UPSTREAM_INERT_CONFIG_KEYS")))
        check_population(surface, inert)
        root, texts = upstream_texts()
    except InputError as exc:
        print(f"  upstream-reads: FAIL -- {exc}")
        print("  upstream-reads: NOTHING was graded; this is not a claim about the lists.")
        return 2

    findings = classify(surface, inert, texts, SCHEMA_REL.as_posix())
    if verbose:
        print(f"  upstream-reads: upstream {root} ({len(texts)} rust file(s))")
        for key in inert:
            inside, outside = occurrences(leaf_of(key), texts, SCHEMA_REL.as_posix())
            print(f"  upstream-reads: inert {key} -- schema {inside}, elsewhere {outside}")
    for line in findings:
        print(f"  upstream-reads: FAIL -- {line}")
    if findings:
        return 1
    print(
        f"  upstream-reads: {len(surface)} surface key(s) all read by the pinned "
        f"upstream; {len(inert)} inert key(s) read by none of it"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
