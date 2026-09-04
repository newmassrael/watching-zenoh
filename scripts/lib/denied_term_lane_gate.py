#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
# SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
"""R2335 (no register item) - a CI lane may not claim of itself a term the test
it runs has DENIED of itself.

The citation reads "no register item" for the same reason
`reason_citation_gate.py` and `config_key_fixture_gate.py` do: the item this
answers for -- unregistered item 15, the PARTIAL-atom track -- lives in the
operator's register outside this repository, so there is no `debt-` id here for
a citation to resolve. The atom this round took off that track is
`ext-pubsub-advanced-publisher`, and the item is named in prose below.

## The defect, which had run for many rounds under its own correction

The `ext-pubsub-advanced-publisher` atom's reason said its CI lane proved a
composed end-to-end at the WIRE, and the lane's own comment in `run-ci.sh` said
the same. The test both sentences were describing says, in its doc, that the
dispatch stays in-process and does not traverse the Push/Response codec -- it
names itself session-API loopback and denies the stronger term in as many
words.

R311y441 had already FOUND this. It wrote a correction into the atom's reason
naming both copies, and fixed NEITHER. The false sentence therefore survived
directly above its own refutation, in two files, for every round since.

That is the shape worth a gate. A lane that overstates what it proves is worse
than one that proves less, because the overstatement is what stops the next
reader re-checking; and a correction that only DESCRIBES the overstatement
leaves the reader who greps for the claim finding the claim.

## The witness is the test, and the population is DERIVED from it

Nothing here is a word list. A term becomes checkable only because a test
DECLARED it inadmissible about itself, in the one place that is authoritative
about what a test proves -- its own doc:

    /// ... so this is "session-API loopback", not "wire-level"

That `not "<term>"` spelling is an established idiom in this tree, not one
invented for this gate: MEASURED when it was written, 55 quoted denials live in
`crates/**/*.rs` doc blocks, 24 of them on a `#[test]`/`#[tokio::test]`
function. The gate reads those 24; it cannot be made to pass by editing a list,
because there is no list -- deleting a denial deletes the only thing that made
its term checkable, and that shows up as the population shrinking.

The other half of the population is derived too. A lane's comment is the
contiguous `#` block above `layer_<name>()`; a lane's tests are read from the
`cargo test` invocations in its body, after backslash continuations are joined
and comment lines dropped. A (denial, lane) pair exists when the lane's `-p`
package is the test's package, the target kind agrees (`--lib` for a test under
`src/`, `--test <name>` for one under `tests/`), and the lane's filter, if it
names one, is a substring of the test's module path or of its name. MEASURED:
24 denials x 155 lanes yields 25 pairs over 8 distinct denied tests, and
exactly ONE lane comment contradicted a test it runs.

## Population floors, because a scanner that finds nothing reads as coverage

Four counts are FAILURES at zero: the denials, the lanes, the `cargo test`
invocations parsed out of them, and the pairs. Each has a plausible way to go
quietly to zero -- a doc-comment reformat, a rename of the `layer_*` prefix, a
change in how lanes spell an invocation, a package rename -- and every one of
them would otherwise leave this exiting 0 forever.

## Two residues, stated rather than hidden

FEATURES ARE NOT MODELLED. A lane that names no test filter is taken to run
every test in that target, which is what cargo does -- but whether a given test
was COMPILED depends on the lane's `--features`, and that is not read here. The
effect is over-reach, never under-reach: five lanes are paired with a test only
one of them compiles. Over-reach is the safe direction for this question, since
the verdict is about what a comment CLAIMS, and it costs a false red only if an
unrelated lane comment happens to spell another test's denied phrase.

THE STORE'S COPY IS OUT OF REACH, and not by oversight. The same false sentence
also sits in the atom's `reason`, where corrections are APPENDED and the
original is never rewritten -- that is the convention every atom in the store
follows. A rule forbidding the term there would be red forever and could only
be satisfied by breaking the convention, so the reason carries a correction and
this gate carries the enforceable half.
"""

import os
import re
import subprocess
import sys

DENY = re.compile(r'not\s+"([^"]{3,60})"')
DOC = re.compile(r'\s*///')
ATTR = re.compile(r'\s*#\[')
FN = re.compile(r'\s*(?:pub\s+)?(?:async\s+)?fn\s+([A-Za-z0-9_]+)')
LANE_HEAD = re.compile(r'^layer_([a-z0-9_]+)\(\)\s*\{')
LANE_REG = re.compile(r'^\s*run_layer\s+([A-Za-z0-9]+)\s+layer_([a-z0-9_]+)')
CARGO_TEST = re.compile(r'\bcargo\s+test\b([^\n]*)')


def target_of(path, fn):
    """Module path and cargo target kind for a test function in `path`."""
    parts = path.split('/')
    if 'src' in parts:
        rel = parts[parts.index('src') + 1:]
        rel[-1] = rel[-1][:-3]
        while rel and rel[-1] in ('mod', 'lib'):
            rel = rel[:-1]
        return '::'.join(rel + ['tests', fn]), 'lib'
    return fn, os.path.basename(path)[:-3]


def scan_denials(path, text, pkg):
    """Quoted self-denials on test functions in one Rust source."""
    out = []
    lines = text.split('\n')
    i = 0
    while i < len(lines):
        if not DOC.match(lines[i]):
            i += 1
            continue
        j = i
        while j < len(lines) and (DOC.match(lines[j]) or ATTR.match(lines[j])):
            j += 1
        block = '\n'.join(lines[i:j])
        sig = lines[j] if j < len(lines) else ''
        m = FN.match(sig)
        if m and ('#[test]' in block or '#[tokio::test]' in block):
            for term in DENY.findall(block):
                mod, kind = target_of(path, m.group(1))
                out.append(dict(file=path, line=i + 1, fn=m.group(1),
                                term=term, pkg=pkg, mod=mod, kind=kind))
        i = j
    return out


def scan_lanes(ci_text):
    """Every `layer_*()` with the comment block above it and its body."""
    lines = ci_text.split('\n')
    lanes = {}
    for idx, line in enumerate(lines):
        m = LANE_HEAD.match(line)
        if not m:
            continue
        k = idx - 1
        comment = []
        while k >= 0 and lines[k].lstrip().startswith('#'):
            comment.append(lines[k])
            k -= 1
        comment.reverse()
        b = idx + 1
        body = []
        while b < len(lines) and lines[b] != '}':
            body.append(lines[b])
            b += 1
        lanes[m.group(1)] = dict(comment='\n'.join(comment),
                                 body='\n'.join(body), line=idx + 1)
    return lanes


def lane_ids(ci_text):
    ids = {}
    for line in ci_text.split('\n'):
        m = LANE_REG.match(line)
        if m:
            ids[m.group(2)] = m.group(1)
    return ids


def invocations(lane_name, body):
    """The `cargo test` invocations a lane body actually runs."""
    joined = body.replace('\\\n', ' ')
    out = []
    for raw in joined.split('\n'):
        stripped = raw.lstrip()
        if stripped.startswith('#') or stripped.startswith('`#'):
            continue
        for m in CARGO_TEST.finditer(raw):
            seg = m.group(1)
            pkg = re.search(r'-p\s+([A-Za-z0-9_-]+)', seg)
            if not pkg:
                continue
            tgt = re.search(r'--test\s+([A-Za-z0-9_]+)', seg)
            filt = re.search(
                r'--(?:lib|test\s+[A-Za-z0-9_]+)\s+((?!--)[A-Za-z0-9_:]+)', seg)
            out.append(dict(lane=lane_name, pkg=pkg.group(1),
                            lib='--lib' in seg,
                            test=tgt.group(1) if tgt else None,
                            filt=filt.group(1) if filt else None))
    return out


def reach(denials, invs):
    """(denial, invocation) pairs where the lane runs that test."""
    pairs = []
    for d in denials:
        for iv in invs:
            if iv['pkg'] != d['pkg']:
                continue
            if d['kind'] == 'lib':
                if not iv['lib']:
                    continue
            elif iv['test'] != d['kind']:
                continue
            f = iv['filt']
            if f and f not in d['mod'] and f not in d['fn']:
                continue
            pairs.append((d, iv))
    return pairs


def contradictions(pairs, lanes):
    bad = []
    for d, iv in pairs:
        comment = lanes[iv['lane']]['comment']
        if d['term'].lower() in comment.lower():
            bad.append(dict(lane=iv['lane'], term=d['term'], fn=d['fn'],
                            file=d['file'], line=d['line']))
    return bad


def package_of(path, cache):
    d = path.split('/')[1]
    if d not in cache:
        name = d
        try:
            t = open(os.path.join('crates', d, 'Cargo.toml'), encoding='utf-8').read()
            m = re.search(r'^\s*name\s*=\s*"([^"]+)"', t, re.M)
            if m:
                name = m.group(1)
        except OSError:
            pass
        cache[d] = name
    return cache[d]


def selftest():
    """Both verdicts, driven through the functions the real run uses."""
    rust = '\n'.join([
        '#[cfg(test)]',
        'mod tests {',
        '    /// The dispatch never leaves the process, so this is',
        '    /// "in-process handoff", not "sealed-envelope".',
        '    #[test]',
        '    fn a_handoff_recovers_what_it_stored() {}',
        '',
        '    /// An ordinary test with nothing denied.',
        '    #[test]',
        '    fn an_ordinary_test() {}',
        '}',
    ])
    ci = '\n'.join([
        '# Layer Q1 — the honest one',
        '# It runs the handoff test and describes it as an in-process handoff.',
        'layer_q1_honest() {',
        '    cargo test -p wz-fixture --lib a_handoff --quiet',
        '}',
        '',
        '# Layer Q2 — the overstating one',
        '# This lane calls the same test a sealed-envelope proof.',
        'layer_q2_overstating() {',
        '    cargo test -p wz-fixture --lib a_handoff --quiet',
        '}',
        '',
        '# Layer Q3 — spells the term but runs another package',
        '# A sealed-envelope claim about something else entirely.',
        'layer_q3_elsewhere() {',
        '    cargo test -p wz-other --lib a_handoff --quiet',
        '}',
        'run_layer Q1 layer_q1_honest',
        'run_layer Q2 layer_q2_overstating',
        'run_layer Q3 layer_q3_elsewhere',
    ])
    fails = []
    dn = scan_denials('crates/wz-fixture/src/handoff.rs', rust, 'wz-fixture')
    if len(dn) != 1 or dn[0]['term'] != 'sealed-envelope':
        fails.append('scan_denials did not find exactly the one denied term: %r' % dn)
    if dn and dn[0]['mod'] != 'handoff::tests::a_handoff_recovers_what_it_stored':
        fails.append('module path wrong: %r' % dn[0]['mod'])

    lanes = scan_lanes(ci)
    if set(lanes) != {'q1_honest', 'q2_overstating', 'q3_elsewhere'}:
        fails.append('scan_lanes found %r' % sorted(lanes))
    invs = []
    for name, lane in lanes.items():
        invs += invocations(name, lane['body'])
    if len(invs) != 3:
        fails.append('expected 3 invocations, got %r' % invs)

    pairs = reach(dn, invs)
    lanes_reached = sorted({iv['lane'] for _, iv in pairs})
    if lanes_reached != ['q1_honest', 'q2_overstating']:
        fails.append('reach should skip the other package: %r' % lanes_reached)

    bad = contradictions(pairs, lanes)
    flagged = sorted(b['lane'] for b in bad)
    if flagged != ['q2_overstating']:
        fails.append('the overstating lane alone must be flagged, got %r' % flagged)

    # A denial that no longer exists must take its verdict with it: the term is
    # only checkable because a test declared it, never because this file knows it.
    without = rust.replace(', not "sealed-envelope"', '')
    dn2 = scan_denials('crates/wz-fixture/src/handoff.rs', without, 'wz-fixture')
    if contradictions(reach(dn2, invs), lanes):
        fails.append('a lane was flagged with no denial to flag it against')

    # Each population floor must be INDEPENDENTLY reachable. Emptying one input
    # at a time is the only way to see that: the first draft of this selftest
    # emptied the denials alone, which empties the PAIRS too, so the pair floor
    # answered for both and the denial floor could be deleted with the selftest
    # still passing -- measured, by deleting it.
    floors = [('denials', population_failures([], lanes, invs, pairs)),
              ('lanes', population_failures(dn, {}, invs, pairs)),
              ('invocations', population_failures(dn, lanes, [], pairs)),
              ('pairs', population_failures(dn, lanes, invs, []))]
    for name, msgs in floors:
        if len(msgs) != 1:
            fails.append('the %s floor did not fire alone: %r' % (name, msgs))
    if population_failures(dn, lanes, invs, pairs):
        fails.append('a fully populated run tripped a floor')

    for f in fails:
        sys.stderr.write('denied-term-lane selftest: %s\n' % f)
    return 1 if fails else 0


def population_failures(denials, lanes, invs, pairs):
    out = []
    if not denials:
        out.append('no quoted self-denial found on any test function')
    if not lanes:
        out.append('no `layer_*()` lane parsed out of run-ci.sh')
    if not invs:
        out.append('no `cargo test` invocation parsed out of any lane body')
    if not pairs:
        out.append('no lane runs any test that denies a term about itself')
    return out


def main(argv):
    if '--selftest' in argv:
        rc = selftest()
        print('denied-term-lane: selftest %s' % ('PASS' if rc == 0 else 'FAIL'))
        return rc

    files = [p for p in subprocess.run(['git', 'ls-files', 'crates'],
                                       capture_output=True, text=True,
                                       check=True).stdout.split()
             if p.endswith('.rs')]
    cache = {}
    denials = []
    for p in files:
        with open(p, encoding='utf-8', errors='replace') as fh:
            denials += scan_denials(p, fh.read(), package_of(p, cache))

    with open('scripts/run-ci.sh', encoding='utf-8', errors='replace') as fh:
        ci = fh.read()
    lanes = scan_lanes(ci)
    ids = lane_ids(ci)
    invs = []
    for name, lane in lanes.items():
        invs += invocations(name, lane['body'])
    pairs = reach(denials, invs)

    print('denied-term-lane: %d denial(s) on test fns / %d lane(s) / '
          '%d cargo-test invocation(s) / %d reached pair(s) over %d test(s)'
          % (len(denials), len(lanes), len(invs), len(pairs),
             len({d['fn'] for d, _ in pairs})))

    floor = population_failures(denials, lanes, invs, pairs)
    for f in floor:
        print('denied-term-lane: POPULATION FAIL -- %s' % f)

    bad = contradictions(pairs, lanes)
    seen = set()
    for b in bad:
        key = (b['lane'], b['term'])
        if key in seen:
            continue
        seen.add(key)
        print('denied-term-lane: FAIL -- lane %s (%s) claims a term that '
              '%s denies of itself'
              % (ids.get(b['lane'], b['lane']), 'layer_' + b['lane'], b['fn']))
        print('    the denial: %s:%d' % (b['file'], b['line']))
        print('    reword the lane comment; do not quote the denied phrase, '
              'because a quotation of it is still an occurrence of it')
    if floor or seen:
        return 1
    print('denied-term-lane: OK')
    return 0


if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))
