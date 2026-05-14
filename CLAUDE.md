# watching-zenoh — AI Agent Operating Guide

This file is auto-read by Claude Code at every session start. It defines
**Mnemosyne SSOT operating rules** for the 13 design docs registered in
`mnemosyne.toml`.

Prior-session context is recovered from the atomic store changelog
(`query_section(.., include_changelog=true)` or `list_sections` →
ChangelogEntry traversal). The legacy `notes/SESSION_KICKOFF.md`
activity log was removed in Round 10 — atomic ledger entries (Round 1+)
are the audit-traced replacement.

## SSOT contract

The 13 docs in `mnemosyne.toml::workspace.docs` are governed by Mnemosyne.
For these docs, mutations route through the Mnemosyne MCP server, not
through `Edit` / `Write` on the raw markdown. The justification is the
same as for any audit-traced spec system: a typed primitive validates
each change against tier rules (T1 cross-ref orphan, T2 frozen ledger,
round-trip preservation) before persisting, while a regex-based `Edit`
silently drifts structure.

## Before any action on a registered doc

1. **Read the Mnemosyne concepts you have not yet internalized this
   session** (in order; `anti-patterns` is must-read second — skipping
   it caused this workspace's NarrativeSection mis-recommendation in
   the 2026-05-08 session):
   - `mnemosyne://concepts/overview`
   - `mnemosyne://concepts/anti-patterns`
   - `mnemosyne://concepts/atomic-store`
   - `mnemosyne://concepts/frozen-ledger`
   - `mnemosyne://concepts/tier-rules`
   - `mnemosyne://concepts/workflow`
2. Run `validate_workspace` to surface the current baseline (orphan
   count, round-trip status, style violations). Snapshot the numbers —
   you will compare against this after your mutation.
3. For section-targeted changes: `query_section(section_id,
   include_related=true, include_changelog=true)` first.

## Mutation rules

- **Markdown body edits** to a registered doc → reach for the
  `set_section_*` / `add_section_*` primitives via the Mnemosyne MCP.
  Do not `Edit` / `Write` the markdown directly.
- **Sidecar direct `Write` / `Edit`** on
  `docs/.atomic/workspace.atomic.json` is forbidden by default
  (`anti-patterns` #8). MCP mutate primitives cascade-update
  `docs/GENERATED.md` automatically; direct sidecar edits do not —
  they leave `GENERATED.md=stale` and the next `validate_workspace`
  exits 1. If an explicit user override is granted (e.g. revert after
  a demo), follow the direct edit with `mnemosyne-cli generate-docs`
  to restore `GENERATED.md=sync`.
- **Changelog entries** for `rfc-open-questions-log.md::Change log` →
  use `append_changelog_entry_v2`. New entries must use the configured
  `entry_id_prefix = "Round "` (the date-based legacy entries remain as
  prose under the section heading; do not retrofit them to `Round N`
  form — frozen-ledger spirit applies even though they predate the
  atomic store).
- **After every mutation** → `validate_workspace`. Confirm orphan delta
  = 0 (no new orphans), round-trip mandatory still N/N, T3 warn count
  not increased, atomic ledger drift consistent with the mutation
  (entries / sections delta matches what the call should have produced).
- If a mutation needs to reference a section that does not exist yet,
  add the target section first (avoid creating new orphans).

## Atomic store adoption — full migration plan

`docs/.atomic/workspace.atomic.json` is initialized
(`schema_version=1`, `sections={}`, `changelog_entries={}` as of
2026-05-08). The full atomic mutate API surface (14 primitives) is now
usable on this workspace.

`docs/GENERATED.md` is the cascade output of every MCP mutate
primitive (the MCP tool schema has no `--no-regenerate`; only
`mnemosyne-cli` does). For watching-zenoh it is **not the
human-readable surface** — the 13 prose docs in
`mnemosyne.toml::workspace.docs` remain the human-readable surface
during migration. `docs/GENERATED.md` is therefore listed in
`.gitignore` and treated as a byproduct.

Long-term direction: **all 13 docs migrate to atomic Section +
CrossRef decomposition.** No NarrativeSection / `prose_blocks`
escape-hatch — that route is `mnemosyne://concepts/anti-patterns` #9
violation (schema extensions are out of scope; the 4 entity types are
closed-form per Round 60 ratify). If a piece of prose appears
"un-decomposable", that is a signal to restructure the prose, not to
add an escape-hatch field.

Phased rollout (one phase per session, do not bundle):
- **Phase A (next session)**: `oq-w15-ratification-summary.md` — 7
  sections, decision-record-shaped, smallest blast radius. First
  mapping trial of intent / rationale / alternatives_rejected /
  impact_scope / inputs / outputs across a complete doc.
- **Phase B**: `rfc-sce-protocol-synthesis.md` §5 kinds atomic
  decompose — ~11 kinds × ~6 atomic fields each. Heaviest phase.
- **Phase C**: 3 FSM docs (`session-fsm.md` / `scouting-fsm.md` /
  `reassembly-fsm.md`) — each state = 1 Section, transition =
  CrossRef edge, Mermaid / state diagram in `examples` field.
- **Phase D**: residual prose (`intrinsics-runtime-symbols.md`,
  `runtime-crate-{lwip,tokio}.md`, `wire-spec-subset.md`,
  `ARCHITECTURE.md`). README.md (0-byte stub) and SESSION_KICKOFF.md
  (activity-log genre) removed from workspace.docs per Round 7 scope
  correction; latter moved to `notes/`. README prose authoring
  deferred to Phase E (re-register on completion).

## Raw `Edit` carve-out — transitional only, per-doc

While a doc still lives in raw markdown form (i.e. before its phase
above completes), raw `Edit` / `Write` on that doc is permissible
**only when**:
1. `validate_workspace` passes before the edit (clean baseline).
2. The edit preserves round-trip (re-validate after).
3. T1 orphan delta = 0 (no new orphans introduced).

Once a doc completes its phase migration its sections live in the
atomic store; the carve-out no longer applies to that doc — mutation
must route through the typed primitives.

## Local CI gate

A pre-commit hook at `.githooks/pre-commit` runs `mnemosyne-cli
validate-workspace` and blocks any commit that introduces a new T1
orphan, a resolved-but-still-ledgered entry (drift catch), or a
round-trip mandatory break. One-time install per clone:

```
git config core.hooksPath .githooks
```

The hook requires `mnemosyne-cli` on `PATH` (install via
`cargo install --path /path/to/mnemosyne/crates/mnemosyne-cli`).

## Hard prohibitions

- Do not `Edit` / `Write` `mnemosyne.toml` to bypass validation
  (e.g. removing a doc from `workspace.docs` to silence its orphans).
  If a doc genuinely cannot be carried, raise it explicitly.
- Do not retroactively rewrite an existing changelog entry body —
  frozen-ledger anti-pattern. New corrections arrive as new entries.
- Do not drive T3 warn / T4 info counts to zero by mass prose
  rewrite — Round 138 tier mobility ratify, the warning surface is
  intentionally non-zero.

## External references (carry from SESSION_KICKOFF)

- SCE source: `/home/coin/scxml-core-engine/` — read directly when SCE
  state is in question, do not infer from memory.
- Zenoh upstream (1.5.0): `/home/coin/.cargo/git/checkouts/zenoh-*/49c8a53/`
- zenoh-pico upstream: `~/zenoh-pico/`

## Response style

- Korean for prose; file paths and code identifiers in English.
- Cite file:line for any source claim. No memory-only assertions about
  SCE / Zenoh state — verify by direct read.
- Complex multi-line regex on a registered doc → ask the user to apply
  it manually rather than risk corruption.
