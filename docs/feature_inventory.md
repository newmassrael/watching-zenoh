# Feature inventory — composable framework atomic + preset catalog

> **NOT THE SSOT — DO NOT DERIVE AN ATOM SET FROM THIS FILE.**
>
> R408 retired this document as a parsed/validated surface. The SSOT is the
> atomic store; nothing gates this file against it. To answer "which atoms
> exist / what is this atom's status", derive it:
>
> ```
> mnemosyne-cli query --list-inventory        # the atom set + statuses
> mnemosyne-cli query --inventory <atom-id>   # one atom
> ./scripts/audit-catalog-status.sh --layer A3
> ```
>
> R311y316 removed every census this file carried — the §5 per-atom
> enumeration, the §6 preset definitions, and the §2.1 domain list —
> rather than keep warning about them: a banner over a trap is still a
> trap. What is left is design reasoning, which does not rot the way a
> list does:
>
> - **§1-§4** — purpose, the naming + preset-naming CONVENTIONS, the 3-test
>   definitions, conflict policy. This file is their ONLY copy: the store's
>   counterpart sections exist but are title-only placeholders, so deleting
>   them here would destroy them. (Measured: 20 of this doc's 51 store
>   sections are title-only — a decompose gap, not a deliberate scope call.)
> - **§5, §6** — headings kept as pointers; each records what was removed
>   and why, since a silent deletion reads as "this never existed".
> - **§7-§9** — the emission-mechanism placeholders and the change log.
>
> This banner's own first draft (R311y316) is the cautionary case. It
> exempted "§2 naming / §3 tests / §4 conflict policy / §6 preset
> contracts" from census-rot, and was wrong twice in one paragraph: §2.1
> held a 19-domain list against the store's 27, and §6's "rule" excluded 7
> atoms that preset-ap-full does not contain. An exemption is a claim; it
> gets measured like any other. Both were caught by review, not by the
> author.

**Status.** R301 entry. First-pass catalog of atomic features across
the domains, plus the initial semver-named presets — counts deliberately
not restated here (R311y316; they were "~140 / 19 / 6" and every one had
drifted). Materializes
the composable-framework north star (R267 ratify, R299+ refined) by
naming the contract every future SCXML / Rust crate must conform to
when emitting a per-cargo-feature subset of zenoh's full feature
catalog.

**Scope.** This document defines the *names* and *3-test verdicts*
for atomic features + the *named contracts* for presets. The actual
emission mechanism (`<sce:requires feature="X"/>` SCXML attribute,
`Cargo.toml::[features]` table, etc.) is referenced as the R302+
open carry — §7 and §8 below are placeholders.

**Inputs (historical, NOT normative).** zenoh upstream 1.5.0; zenoh-pico;
zenoh-cpp public API shape as the cross-feature consistency anchor; and a
wz implementation snapshot pinned at HEAD `5f2b3cc` (R300 close) — that
pin is why everything below is a snapshot rather than a description of
today's tree.

R311y315 — the machine-local absolute paths that used to appear here
(a `~/.cargo/git/checkouts/zenoh-*/…` checkout and `~/zenoh-pico/`) are
REMOVED. They are the exact failure CLAUDE.md's "External references"
rule was written against after R311y302: a path correct on one clone is
wrong on the next, it leaks the author's home layout, and nothing gates
it, so it rots silently while still being cited. Both had in fact rotted
— zenoh-pico is now vendored in-repo at `vendor/zenoh-pico/`. Resolve
reference paths per machine; never commit them.

**Outputs.** Atomic feature names following the
`<domain>-<capability>` convention, each labelled *active*
(implemented in wz at R300) or *reserved* (roadmap, not yet
implemented but plausibility-confirmed against upstream); preset
names following the `preset-<target>-<level>` convention. Both sets
now live in the store — derive, do not count from here.
3-test definitions (Footprint / Plausibility / Coherence). Conflict
policy: silently ALLOW (cargo monotone-additive semantics).

**Non-outputs.** Cargo feature edges (which features imply which
others), SCXML feature-gate grammar, build-time evaluation flow,
inspect-tool design — all deferred to R302+. This document is the
**naming** contract, not the **mechanism** contract.

---

## §1 Purpose

The composable-framework north star (R267 ratify) defines wz's
unique value over zenoh / zenoh-pico / zenoh-cpp as the ability to
emit an *arbitrary user-selected subset* of zenoh's full feature
catalog. zenoh ships one fixed binary; wz authors SCXML once and
emits per-cargo-feature combinations à la Linux kconfig / Zephyr
project config / Buildroot / NixOS USE flag.

That ambition rests on a contract every future SCXML and Rust crate
must conform to: each feature is named under a convention, each
feature stands on its own (Coherence), and the catalog is fixed at
spec time so feature edges can be reasoned about ahead of build
time. This document establishes that contract.

Two layers of abstraction (R299+ refined):

1. **Atomic features** — the smallest unit that can be turned on or
   off. Naming `<domain>-<capability>`. Each must pass the
   Footprint + Plausibility + Coherence three-test.
2. **Presets** — semver-versioned named contracts that bundle atomic
   features. Naming `preset-<target>-<level>`, covering the common
   deploy shapes.

Atomic features are the units that build correctness reasons about;
presets are the units that downstream projects depend on.

## §2 Naming convention

### §2.1 Atomic features

Atomic feature names follow `<domain>-<capability>` strict kebab-
case, ASCII-only, no version suffix in the name. Maximum three
segments (a `<domain>-<capability>` may extend to
`<domain>-<capability>-<modifier>` where the modifier disambiguates
a closely related sibling, e.g. `transport-link-udp` vs
`transport-link-tcp` where `link` is the modifier subdivision of
the `transport` domain).

The domain set is derived from the store, not listed here. R311y316
removed the 19-domain list that stood in this paragraph: the store
carries 27 domains, so it was missing 8 (`adminspace`, `api`, `config`,
`ext`, `plugin`, `rest`, `router`, `switchboard`) covering 40 atoms. It
was a census inside the section this file's banner had exempted from
census-rot — the exemption was wrong, not the measurement. Derive it:

```
mnemosyne-cli query --list-inventory --json \
  | python3 -c "import json,sys; print(sorted({r['id'].split('-')[0] \
      for r in json.load(sys.stdin) if not r['id'].startswith('preset-')}))"
```

Adding a domain still requires an explicit R-round ratification; that
rule is the design reasoning, and it is what survives here.

Capability segments are nouns (the thing being offered) or
qualified nouns (e.g. `wildcard-double` distinguishing `**` from
`*`); not verbs.

### §2.2 Presets

Preset names follow `preset-<target>-<level>` strict kebab-case.
Target is the deploy shape (`mcu`, `ap`, `zenoh-cpp` for the
upstream-parity bundle). Level is the maturity tier
(`minimal`, `extended`, `client`, `router`, `full`).

Presets carry a separate semver string in their definition
(`preset-mcu-minimal v0.1.0`); a *contract* is the (name × semver)
pair. Adding an atomic feature to an existing preset version
without changing semver is a breaking-change anti-pattern; the
contract is what downstream depends on.

## §3 Three-test definitions

Every atomic feature must pass all three tests before landing
(§5 enumerated them until R311y316; derive the set from the store). The tests are independent — failing any one rejects the
candidate as an atomic feature (it must be split, merged, renamed,
or accepted as a non-atomic preset-only concept).

### §3.1 Footprint

**Test.** The feature contributes a *measurable*, *bounded*, and
*isolatable* footprint when enabled — measurable in at least one
of: lines of code (LOC) added to the codegen output, binary size
delta (bytes) under `--release`, RAM delta under a representative
workload.

**Active features** (already implemented in wz at R300) get an
empirical measurement from the current code. **Reserved features**
get an estimated upper bound from the corresponding zenoh /
zenoh-pico module size; the estimate becomes empirical once the
feature lands.

A feature whose footprint cannot be bounded (e.g. a
configuration-only knob that pulls in no extra code) is not atomic
— it belongs in a preset's parameterization, not in the catalog.

### §3.2 Plausibility

**Test.** The feature is *named* and *implemented* somewhere in
the upstream surface — zenoh (Rust), zenoh-pico (C), or zenoh-cpp
(C++ public API). The citation is a file-path + symbol/section
reference, not a vague "this exists somewhere".

The plausibility test prevents the catalog from drifting into
hypothetical-future-state names. Every reserved feature carries a
citation — it lives in the store's inventory `source` field, which is
what §5's deleted `(status, source)` tags were a stale copy of. If
upstream removes the feature, the citation is invalidated and the entry
moves to deprecated.

### §3.3 Coherence

**Test.** Turning the feature off cleanly removes its footprint
without breaking unrelated features. The dependency edge from
this feature to others is *named* (in inventory) or *empty* (no
edge needed).

Coherence is the hard test for atomicity. A feature that
silently requires another feature to be on (without naming the
edge) is *not* atomic — it's a fragment of a larger atomic unit
that must be merged or renamed. Conversely, a feature whose
turning-off breaks a sibling without a named edge violates
Coherence and rejects.

## §4 Conflict policy

**Conflicts between atomic features are silently ALLOWED.** This
respects cargo's monotone-additive feature-flag semantics:
enabling more features must never break a build that succeeds
with fewer features.

Conflict *detection* is not a build-time error. It is surfaced by
the planned `cargo wz-config inspect` tool (R302+ open carry)
informationally — "you enabled feature A and feature B, which the
catalog says are mutually-exclusive in practice; pick one". The
tool emits a warning but the build proceeds; the user's choice
wins.

Rationale: cargo features are not designed for mutual exclusion.
Forcing one would make wz incompatible with downstream projects
that pull in multiple wz consumers with different feature sets.

## §5 Atomic feature catalog

**The per-atom enumeration that stood here was removed in R311y316.**
It listed 19 domains as `` - `atom` — description (status, source) ``
bullets. R311y315 measured it against the store and found roughly half
its status labels disagreeing, plus dozens of store atoms never listed
here at all — re-derive those numbers rather than quoting these words.
Nothing kept it in sync: R408 retired this file as a parsed surface, so
no gate ever compared the two.

This section's own preamble had already recorded why it was redundant:
the inventory primitive (R273, the 5th-entity surface) stores the
structured per-feature record — id / status / section_ref / source /
reason — in the atomic store, and the markdown body here was merely "the
human-readable enumeration" of it. A hand-maintained second copy of a
primitive-backed record is a census, and a census rots.

Derive the catalog instead:

```
mnemosyne-cli query --list-inventory        # the atom set + statuses
mnemosyne-cli query --inventory <atom-id>   # one atom
./scripts/audit-catalog-status.sh --layer A3
```

Per-domain design notes live in the store's own §5.x sections, which
cover more domains than this file ever did (§5.20-§5.27 were never
written here). Read one with:

```
mnemosyne-cli query "§feature-inventory--composable-framework-atomic--preset-catalog/5-atomic-feature-catalog/5-9-query"
```

§6 below is deliberately NOT removed. A preset contract is not a census:
it states the RULE that generates a membership ("same as preset-ap-full
except the MCU/embedded flavor"), and that rule is design reasoning the
store's expanded per-atom closure does not carry. It is stale in one
respect only — it describes 6 presets where the store now has 9.


## §6 Presets

**The six preset definitions that stood here were removed in R311y316**,
one commit after the same round kept them — the justification for keeping
them did not survive review, and it was wrong on both halves.

It claimed a preset contract states the RULE generating a membership,
which the store's expanded per-atom closure does not carry. But the store
states the rule, in the section `intent`, for the presets that have one —
including the very rule quoted in this file's defence:

- `§6.6` intent: "Functionally equivalent to preset-ap-full minus the 3
  wz-superset backends"
- `§6.4` intent: "preset-ap-client scope + router topology + gossip +
  multicast"
- `§6.2` intent: "preset-mcu-minimal scope + query + liveliness +
  wildcards + active scouting"

And the rule kept here had rotted to a no-op. §6.6 read "same as
preset-ap-full except ... explicitly excludes `runtime-coop`,
`runtime-no-std`, `platform-bare-metal`, `platform-freertos`,
`platform-zephyr`, `transport-link-serial`, `locator-serial`". Executed
against the store: NONE of those 7 atoms is in preset-ap-full, so every
exclusion is vacuous; the rule yields 136 atoms where the store's
zenoh-cpp closure is 121, and the real exclusion set is 15 entirely
different atoms. A rule that computes the wrong answer is not design
reasoning worth preserving — it is a census that stopped being checked.

The store carries 9 presets; this file carried 6. Derive them:

```
mnemosyne-cli query --list-inventory | grep preset-
mnemosyne-cli query "§feature-inventory--composable-framework-atomic--preset-catalog/6-presets/6-6-preset-zenoh-cpp"
```

§2.2 above keeps the preset NAMING contract (`preset-<target>-<level>`,
and the (name × semver) pair as the unit downstream depends on). That is
convention, not membership, and it does not rot the way a list does.


## §7 Cargo feature emission mechanism

R302+ open carry. The Cargo.toml::[features] table layout, the
default feature set, the feature-implication edges, and the
`#[cfg(feature = ...)]` gate placement in emitted Rust source are
all deferred. The R302 candidate work is to design this surface.

Reference points for the future design:
- Linux kconfig — declarative menus + select/depends edges
- Zephyr west config — overlay + per-board defaults
- Buildroot — package-graph + per-package config
- NixOS USE flags — propagation + override

## §8 SCE feature gate mechanism

R302+ open carry. The SCXML attribute (`<sce:requires
feature="X"/>` or similar) that lets SCXML authors gate generated
output by an atomic feature flag is deferred. The R302 candidate
work is to ratify the attribute shape against SCE codegen.

Initial sketch (subject to ratify):
- `<sce:requires feature="<atomic-feature-name>"/>` — element
  is emitted only if the feature is enabled
- `<sce:requires preset="<preset-name>"/>` — element is emitted
  only if any preset including the named atomic is enabled
- Combinable via boolean operators (and/or/not)

The mechanism design depends on SCE codegen support; this is the
first cross-repo deliverable on the composable-framework track.

## §9 Change log

ChangelogEntry records appended via the Mnemosyne
`append_changelog_entry_v2` primitive (R273+ atomic ledger
surface). The R301 entry is the registration round; subsequent
entries record catalog additions / preset version bumps / 3-test
re-evaluations.

The legacy date-based prose entries used elsewhere in the
workspace do not apply to this doc — feature_inventory.md is
born after the atomic ledger surface landed.
