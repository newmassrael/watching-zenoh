# watching-zenoh — AI Agent Operating Guide

This file is auto-read by Claude Code at every session start. It defines
**Mnemosyne SSOT operating rules** for the 12 design docs registered in
`mnemosyne.toml`.

Prior-session context is recovered from the atomic store changelog
(`query_section(.., include_changelog=true)` or `list_sections` →
ChangelogEntry traversal). The legacy `notes/SESSION_KICKOFF.md`
activity log was removed in Round 10 — atomic ledger entries (Round 1+)
are the audit-traced replacement.

## SSOT contract

The 12 docs in `mnemosyne.toml::workspace.docs` are governed by Mnemosyne.
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

## Atomic store baseline

`docs/.atomic/workspace.atomic.json` holds the workspace as 215
atomic Sections + 274 ChangelogEntries across the 12 registered docs
(R275 baseline). The full atomic mutate API surface (14 primitives)
is the only path for mutating Section / ChangelogEntry bodies.

`docs/GENERATED.md` is the cascade output of every MCP mutate
primitive (the MCP tool schema has no `--no-regenerate`; only
`mnemosyne-cli` does). For watching-zenoh it is **not the
human-readable surface** — the 12 prose docs in
`mnemosyne.toml::workspace.docs` remain the human-readable surface;
`docs/GENERATED.md` is gitignored and treated as a byproduct.

No NarrativeSection / `prose_blocks` escape-hatch — that route is
`mnemosyne://concepts/anti-patterns` #9 violation (schema extensions
are out of scope; the 4 entity types are closed-form per Round 60
ratify). If a piece of prose appears "un-decomposable", that is a
signal to restructure the prose, not to add an escape-hatch field.

Phase A / B / C / D / E atomic-decompose migration completed at
Round 27 (Phase E final — README atomic decompose). All 12 registered
docs live in the atomic store with typed Section bodies; no doc
remains in the transitional raw-markdown state.

## Raw `Edit` carve-out — closed

The transitional `Edit` / `Write` carve-out applied while docs were
mid-migration from raw markdown to atomic Section form. With migration
complete at Round 27, no registered doc remains in the transitional
state; all Section body mutations route through the typed primitives.
The clause is preserved here as historical context only.

## Local CI gates

`.githooks/` provides three hooks. One-time install per clone:

```
git config core.hooksPath .githooks
```

- **pre-commit** — fast `mnemosyne-cli validate-workspace` gate;
  blocks any commit that introduces a new T1 orphan, a
  resolved-but-still-ledgered entry (drift catch), or a
  round-trip mandatory break.
- **commit-msg** — enforces `COMMIT_FORMAT.md` (subject and body
  ≤72 bytes per line, no multi-line bullet wraps, no
  Co-Authored-By / "Generated with Claude Code" / emoji).
- **pre-push** — re-runs `mnemosyne-cli validate-workspace` at
  push time so the integrity gate also covers post-commit state
  changes (manual atomic.json edits, amends, rebases) before
  remote share.

`pre-commit` and `pre-push` require `mnemosyne-cli` on `PATH`
(install via
`cargo install --path /path/to/mnemosyne/crates/mnemosyne-cli`).
`commit-msg` needs only bash + GNU grep with the `-P` flag.

## License + SPDX header policy

This project is **dual-licensed**: `LGPL-3.0-or-later` (free, with
LGPL-3 obligations including anti-tivoization) OR
`LicenseRef-watching-zenoh-Commercial` (paid, 5-way exemption). See
`LICENSE` for the overview, `LICENSE-LGPL-3.0.md` /
`LICENSE-GPL-3.0.md` for the verbatim free-tier texts, and
`LICENSE-COMMERCIAL.md` for the commercial alternative.

Author-side source files (SCXML, Rust, C, header, deploy YAML) carry
the SPDX header:

```
SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
```

Applies to: `sources/**.scxml`, `crates/**/*.rs`,
`runtime/**/*.{rs,c,h}`, `deploy/**.yaml`.

**Generated files** (`out/**`) carry SCE's MIT header per
`sce-codegen` policy (see `LICENSE-GENERATED.md` in the SCE repo); do
not overwrite SCE-emitted headers — SCE owns the generation-time
header policy.

**Third-party vendored code** keeps its original SPDX header. When the
first vendored snippet lands, add a top-level `THIRD_PARTY.md` ledger
recording origin, version, and license.

**Doc / config files** that are not source (Markdown, JSON metadata,
config TOML) inherit the repo-level `LICENSE` and do not require
in-file SPDX headers.

## Hard prohibitions

- Do not `Edit` / `Write` `mnemosyne.toml` to bypass validation
  (e.g. removing a doc from `workspace.docs` to silence its orphans).
  If a doc genuinely cannot be carried, raise it explicitly.
- Do not retroactively rewrite an existing changelog entry body —
  frozen-ledger anti-pattern. New corrections arrive as new entries.
- Do not drive T3 warn / T4 info counts to zero by mass prose
  rewrite — Round 138 tier mobility ratify, the warning surface is
  intentionally non-zero.

## External references

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

## Auto-kickoff trigger

사용자가 첫 메시지로 `/load`, `시작`, `이어가자`, `kickoff` 중 하나만
입력하면 아래 5단계를 그대로 수행한다 (R58: NEXT_SESSION.md 활동 로그
genre가 atomic ledger의 carry_forward와 중복이라 제거됨 — 시작 프롬프트는
이 파일이 단일 소스):

1. Mnemosyne concept 6종 적재 (overview → anti-patterns →
   atomic-store → frozen-ledger → tier-rules → workflow) — 이번 세션에
   아직 안 읽은 것만
2. `validate_workspace` 로 베이스라인 (T1 orphan / round-trip /
   entries / sections / GENERATED.md sync) 캡처
3. 가장 최근 atomic changelog entry 조회 후 `carry_forward` 복원 —
   `docs/GENERATED.md` 의 마지막 `### Round N` 블록 읽거나
   `query_section` 으로 latest impact_refs 추적
4. `git status` + `git log --oneline -5` 로 미푸시 commit + 최근 활동 확인
5. SCE 상태가 작업에 필요하면 `/home/coin/scxml-core-engine/` 직접 read

실행 시 "kickoff 시작" 만 짧게 알리고 중간 단계별 verbose 보고는 생략.
종료 후 carry 우선순위 + 다음 단계 제안.
