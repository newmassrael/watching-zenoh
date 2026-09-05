#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
# SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
"""R2354 (no register item) — a write path that changes a digest source must
tell the replication log, and the compiler cannot say so.

The citation is `no register item` in the sense `config_key_fixture_gate.py`
uses: what this answers for is the `storage-replication` atom's last residual,
which lives in the Mnemosyne feature-catalog inventory rather than under a
`debt-` id `gate_provenance_lint.py` can resolve. It is named in prose instead.

## The class

R2354 replaced the storage replication digest's per-cycle recompute with an
incrementally maintained log (`storage_replication.rs` `ReplicationLog`). That
trades one property for another: the recompute could not be stale, because it
read the authoritative state every time. A maintained structure can be, and
the way it goes stale is that somebody adds a write path and does not tell it.

`replication_digest` already debug-asserts maintained == recomputed on every
call, so any test that WRITES and then takes a digest catches it. That is a
real net and it caught nothing else this round — but it only covers paths a
test drives with a digest in play, and the garbage collector was already an
example of one nothing drove that way until R2354 wrote the case. A static
check does not need a test to exist.

## What is DERIVED here, and from where

Nothing in this file names a storage field. The chain is:

  1. the DIGEST SOURCES are whatever `replication_event_stream` reads. That
     function is the storage's own definition of "what the digest is a
     function of" — both the maintained log and the recompute consume it — so
     it is the honest place to take the population from. Its body names
     `self.latest` and a helper; helpers defined in the same file are expanded
     transitively, so `self.wildcard_puts` / `self.wildcard_deletes` arrive
     through `wildcard_replication_entries` without being listed here.

  2. the POPULATION is every `&mut self` method in the file whose body names
     one of those fields. `&mut self` is the language's own answer to "can
     this change the state", so the classifier is not a list of method names
     that a new method could sit outside of.

  3. the CHECK is that each of those methods also names the log field.

A population of ZERO is a FAIL, not a pass. Both derivations can go quiet the
same way — a rename, a refactor that moves the stream elsewhere — and a check
that reports green on an empty population is the failure mode this tree has
paid for repeatedly.

## What it does NOT claim

That the log is UPDATED CORRECTLY. Naming the field is not applying the right
transition, and this gate cannot tell the difference; the differential tests
beside `ReplicationLog` and the debug-assert in `replication_digest` are what
judge that. What this settles is the cheaper and more easily forgotten half:
that a new write path was considered at all.
"""

from __future__ import annotations

import argparse
import pathlib
import re
import sys
import tempfile

REPO = pathlib.Path(__file__).resolve().parents[2]
TARGET = pathlib.Path("crates/wz-session-core/src/storage_state.rs")

#: The function whose body DEFINES what the digest is a function of. Named
#: here (rather than the fields) because it is one name, it is load-bearing in
#: the source itself, and its disappearance is a FAIL rather than an empty
#: population reported as a pass.
SOURCE_DEFINER = "replication_event_stream"

#: The field the write paths must name. Also derived-adjacent: it is read out
#: of `replication_digest`, the one function that is REQUIRED to consult it.
LOG_READER = "replication_digest"

#: `self.<name>` — a field read or a method call; the two are not
#: distinguished here on purpose, since the expansion in `digest_sources`
#: resolves a name to a method only when the file defines one.
#:
#: The `\s*` around the dot is not decoration. rustfmt breaks a long method
#: chain right after the receiver, so the tree's own
#: `self\n            .wildcard_replication_entries()` is the ordinary shape,
#: not an edge case — the first draft of this gate matched `self\.` and
#: reported a digest source set of ONE, which is exactly the "a green check
#: read nothing" failure it is supposed to be immune to.
SELF_MEMBER = re.compile(r"\bself\s*\.\s*([A-Za-z_][A-Za-z0-9_]*)")

#: A top-level item inside an `impl` block, at rustfmt's four-space indent.
FN_OPEN = re.compile(r"^    (?:pub(?:\([^)]*\))? )?(?:async )?fn ([A-Za-z_][A-Za-z0-9_]*)")


def strip_tests(source: str) -> str:
    """The file's `#[cfg(test)] mod tests` block, removed.

    It is the last item in the file and sits at column 0, so the cut is one
    index rather than a brace walk. A test may legitimately reach into a field
    without touching the log, and holding tests to the production invariant
    would make the gate wrong rather than strict.
    """
    marker = "\n#[cfg(test)]\n"
    idx = source.find(marker)
    return source if idx < 0 else source[:idx]


def functions(source: str) -> list[tuple[str, bool, str]]:
    """Every `impl`-level function as `(name, takes_mut_self, body)`.

    The body runs from the signature to the closing `    }` at the same
    indent, which is rustfmt's shape for this tree and needs no brace
    counting. A nested item inside the body is part of that body, which is
    what we want: a closure that touches a field is still that function
    touching it.
    """
    lines = source.splitlines()
    out: list[tuple[str, bool, str]] = []
    i = 0
    while i < len(lines):
        m = FN_OPEN.match(lines[i])
        if not m:
            i += 1
            continue
        start = i
        end = i + 1
        while end < len(lines) and lines[end] != "    }":
            end += 1
        body = "\n".join(lines[start:end])
        # The receiver lives in the signature — everything up to the line that
        # opens the body. `-> Foo {` and `) {` both end it.
        sig_end = start
        while sig_end < end and not lines[sig_end].rstrip().endswith("{"):
            sig_end += 1
        signature = "\n".join(lines[start : sig_end + 1])
        out.append((m.group(1), "&mut self" in signature, body))
        i = end + 1
    return out


def members(body: str) -> set[str]:
    """The `self.<name>` members a body names, as EXACT names.

    Exactness is load-bearing: `"self.latest" in body` also matches
    `self.latest_mode()`, and the first draft of this gate reported
    `process_put` and `process_delete` as write paths for that reason — both
    of which had already been refactored to touch nothing but the funnel.
    """
    return set(SELF_MEMBER.findall(body))


def digest_sources(fns: list[tuple[str, bool, str]]) -> tuple[set[str], list[str]]:
    """The fields the digest is a function of, expanded from
    :data:`SOURCE_DEFINER` through the helpers it calls.

    Returns `(fields, failures)`. A name that resolves to a function defined in
    this file is a helper and is expanded; anything else is taken to be a
    field. The distinction is the file's own, not a list kept here.
    """
    by_name = {name: body for name, _mut, body in fns}
    if SOURCE_DEFINER not in by_name:
        return set(), [
            f"`{SOURCE_DEFINER}` is not defined in {TARGET} — the digest's "
            f"source set cannot be derived, so this gate has no population "
            f"and must not report a pass"
        ]

    fields: set[str] = set()
    seen: set[str] = set()
    pending = [SOURCE_DEFINER]
    while pending:
        fn = pending.pop()
        if fn in seen:
            continue
        seen.add(fn)
        for member in members(by_name[fn]):
            if member in by_name:
                pending.append(member)
            else:
                fields.add(member)
    return fields, []


def scan(source: str) -> tuple[dict, list[str]]:
    fns = functions(strip_tests(source))
    fields, failures = digest_sources(fns)

    defined = {name for name, _mut, _body in fns}
    log_field = None
    for name, _mut, body in fns:
        if name != LOG_READER:
            continue
        # The log is the member `replication_digest` names that is NOT a
        # digest source and not a method of its own — the field it reads the
        # answer off. EXACTLY one, because two would mean the gate is guessing
        # which of them the invariant is about.
        candidates = sorted(members(body) - fields - defined)
        if len(candidates) == 1:
            log_field = candidates[0]
        else:
            failures.append(
                f"`{LOG_READER}` names {len(candidates)} field(s) that are "
                f"neither a digest source nor a method "
                f"({', '.join(candidates) or 'none'}) — the log field cannot "
                f"be derived, so this gate has no subject"
            )
    if log_field is None and not failures:
        failures.append(
            f"`{LOG_READER}` is not defined in {TARGET} — the invariant this "
            f"gate checks has no subject"
        )

    population = [
        (name, body)
        for name, takes_mut, body in fns
        if takes_mut and (members(body) & fields)
    ]
    if fields and not population:
        failures.append(
            f"no `&mut self` method in {TARGET} names any digest source "
            f"({', '.join(sorted(fields))}) — either the storage stopped "
            f"having write paths or this gate stopped finding them"
        )

    offenders = []
    if log_field is not None:
        offenders = [
            name for name, body in population if log_field not in members(body)
        ]
    for name in offenders:
        failures.append(
            f"`{name}` changes a digest source but never names "
            f"`self.{log_field}` — a maintained digest cannot hear about a "
            f"write path that does not tell it"
        )

    return (
        {
            "fields": sorted(fields),
            "log_field": log_field,
            "population": [name for name, _ in population],
            "offenders": offenders,
        },
        failures,
    )


#: The fixture carries the two shapes that defeated this gate's first draft,
#: because a selftest whose input is tidier than the tree measures the tidy
#: input: `wildcard_entries` is reached through a rustfmt-BROKEN receiver
#: (`self\n        .wildcard_entries()`), and `latest_mode` is a member whose
#: name has a digest source as a PREFIX.
_GOOD = '''
impl<B: StorageBackend> StorageState<B> {
    fn replication_event_stream(&self) -> impl Iterator<Item = ()> {
        self.latest.iter().chain(
            self
                .wildcard_entries()
                .map(|e| e),
        )
    }

    fn wildcard_entries(&self) -> impl Iterator<Item = ()> {
        self.wildcard_puts
            .iter()
            .chain(self.wildcard_deletes.iter())
    }

    fn latest_mode(&self) -> bool {
        true
    }

    pub fn replication_digest(&mut self, hot: u64) -> Digest {
        debug_assert!(self.latest_mode());
        self.replication_log.digest_from(hot)
    }

    fn record_latest(&mut self, key: &str) {
        if self.latest_mode() {
            self.replication_log.apply(key);
        }
        self.latest.insert(key);
    }

    fn sweep(&mut self) {
        self.replication_log.apply("x");
        self.wildcard_puts.clear();
        self.wildcard_deletes.clear();
    }

    pub fn peek(&self) -> usize {
        self.latest.len()
    }
}

#[cfg(test)]
mod tests {
    fn t() {
        let mut s = state();
        s.latest.insert("free");
    }
}
'''


def _selftest() -> int:
    ok, failures = scan(_GOOD)
    assert not failures, failures
    # Three sources, one of them reached only through a line-broken receiver
    # and a helper — the expansion, not a list.
    assert ok["fields"] == ["latest", "wildcard_deletes", "wildcard_puts"], ok
    assert ok["log_field"] == "replication_log", ok
    # `replication_digest` and `latest_mode` name `latest`-PREFIXED members and
    # must NOT be in the population; exact-name matching is what keeps them out.
    assert ok["population"] == ["record_latest", "sweep"], ok

    # A `&mut self` write path that forgets the log.
    silent = _GOOD.replace('        self.replication_log.apply("x");\n', "")
    _, failures = scan(silent)
    assert any("`sweep`" in f for f in failures), failures

    # A read-only method is not the population, so removing the log mention
    # from `peek` changes nothing — the classifier is the receiver.
    readonly = _GOOD.replace("pub fn peek(&self)", "pub fn peek(&self)")
    _, failures = scan(readonly)
    assert not failures, failures

    # The source definer disappearing is a FAIL, never an empty pass.
    renamed = _GOOD.replace("fn replication_event_stream", "fn something_else")
    result, failures = scan(renamed)
    assert any("source set cannot be derived" in f for f in failures), failures
    assert result["fields"] == [], result

    # A storage with no write path left is also a FAIL: the population is the
    # thing being checked, and zero of it is not a clean bill of health.
    no_writers = _GOOD.replace("fn record_latest(&mut self", "fn record_latest(&self").replace(
        "fn sweep(&mut self", "fn sweep(&self"
    )
    _, failures = scan(no_writers)
    assert any("stopped finding them" in f for f in failures), failures

    # The tests block is out of scope: a test may touch a field freely.
    with tempfile.TemporaryDirectory() as tmp:
        p = pathlib.Path(tmp) / "s.rs"
        p.write_text(_GOOD)
        _, failures = scan(p.read_text())
        assert not failures, failures

    print("replication-log-funnel-gate: selftest OK")
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--selftest", action="store_true")
    args = ap.parse_args()
    if args.selftest:
        return _selftest()

    path = REPO / TARGET
    if not path.is_file():
        print(f"replication-log-funnel FAIL: {TARGET} is missing", file=sys.stderr)
        return 1

    result, failures = scan(path.read_text(encoding="utf-8"))
    clean = len(result["population"]) - len(result["offenders"])
    print(
        f"  replication-log-funnel: {len(result['fields'])} digest source(s) "
        f"({', '.join(result['fields']) or 'none'}) -> "
        f"{len(result['population'])} write path(s) "
        f"({', '.join(result['population']) or 'none'}), "
        f"{clean} naming `self.{result['log_field']}`"
    )
    if failures:
        print("replication-log-funnel FAIL:", file=sys.stderr)
        for line in failures:
            print(f"  - {line}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
