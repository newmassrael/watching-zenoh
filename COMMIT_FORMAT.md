# Commit Message Format Guide (watching-zenoh)

## Structure

```
<type>(<scope>): <subject>

- <detail 1>
- <detail 2>
- <detail 3>
```

## Rules

### 1. Subject Line
- Format: `<type>(<scope>): <subject>` (scope is optional)
- Types: `feat`, `fix`, `refactor`, `test`, `docs`, `build`, `chore`
- Subject: Clear and concise description of the change
- No period at the end
- Max 72 characters

### 2. Scope (Optional)
- Mnemosyne workspace: `mnemosyne`, `atomic`, `meta`
- RFC body: `rfc`
- ARCHITECTURE: `arch`
- Open Questions log: `oq`
- FSM docs (session/scouting/reassembly): `fsm`
- Intrinsics runtime symbols: `intrinsics`
- Wire spec subset: `wire`
- Runtime crate (tokio/lwip): `runtime`
- Deploy skeletons: `deploy`
- SCXML authoring: `scxml`
- Activity notes: `notes`

### 3. Body
- One blank line after subject
- Bullet points (- prefix) only
- **1-3 items** - focus on key changes (fewer is better)
- **One bullet = one line, max 72 characters total (incl. "- " prefix)**
  - No continuation / indented wrap lines. If a bullet does not fit in
    72 chars, rewrite it tighter or split into a separate bullet.
  - Verify with: `git log -1 --format=%B | awk '{print length, $0}'`
- Be specific and technical
- Reference RFC sections in `§N.M` form (e.g., §5.O, §6.2.6, §5.J.2)
- Reference Open Questions explicitly (e.g., OQ-W15, Q13)
- Reference SCE land via 8-char commit SHA when catching up upstream

### 4. Style
- **No emojis**
- **No "Generated with Claude Code"**
- **No "Co-Authored-By" tags**
- Professional and technical tone
- Focus on "what" and "why", not "how"
- Quantify progress when possible (e.g., "entries 9 → 11", "T3 warn 843 → 851")

## Type Guidelines

| Type | When to Use | Examples |
|------|-------------|----------|
| `feat` | New section, kind, OQ entry, decision, Phase milestone | Register OQ-W24 spec restructure track, Land Phase A6 CRC16 gate |
| `fix` | Spec correctness fix, catch-up to SCE land, cross-ref repair | §6.2.6 verify CLI rename to sce-codegen, Fix orphan cross-ref in §5.M |
| `refactor` | Structural change without semantic shift | Scope-correction via workspace.docs membership, Move kickoff doc to notes/ |
| `test` | Round-trip / orphan / validation regression coverage | Add OQ-W24 round-trip regression, Cover atomic-entry-ref orphan ledger |
| `docs` | Comment-only fix, README, doc clarification | Clarify R7 scope-correction mechanism in mnemosyne.toml comment |
| `build` | Tooling, hooks, mnemosyne.toml schema | Pin mnemosyne-cli v0.1.0, Add .githooks/pre-commit validate gate |
| `chore` | Project structure, gitignore, housekeeping | Add docs/GENERATED.md to .gitignore, Reorganize notes/ |

## Examples

### Good: Mnemosyne Phase close (feat)
```
feat(mnemosyne): Phase D close — typed-populate ARCH + 4 docs subs (R9)

- ARCHITECTURE 34 sub-sections + 4 §-prefix docs 69 subs populated
- atomic sections 102 → 205; validate clean (T1=0, RT 11/11)
- Round 8 'parser limit' carry retired (empirical falsification)
```

### Good: Round close with OQ outcome (feat)
```
feat(mnemosyne): R11 OQ-W15 (a) closure + OQ-W24 registration

- OQ-W15 open → answered (Q1=No RNG / Q2=Yes HMAC ratified to plugin)
- OQ-W24 reg: §5.I Architectural-tier vs Peripheral-tier separation
- entries 10 → 11, parser sections 297 → 298, T1=0 preserved
```

### Good: RFC body catch-up to SCE (fix)
```
fix(rfc): §6.2.6 verify CLI rename + template-hash catch-up to SCE

- `sce-build verify` → `sce-codegen verify` (SCE 97836fa0 unified CLI)
- template-hash now `template tree + Cargo.lock` (binary-id proxy)
- raw-Edit carve-out; R10 audit; T1=0, RT 11/11 preserved
```

### Good: OQ resolution (feat)
```
feat(oq): OQ-W22 close — listener-link trust-class lifecycle (R6)

- Option 3 (codegen split) ratified; sibling-pair emit pattern
- RFC §5.M + §5.C amended; 2 new diagnostics; 5 cross-doc cascade
- deploy.yaml schema unchanged; status open → answered
```

### Good: FSM detail addition (feat)
```
feat(fsm): session §2.7 stateless_accept hardening detail (G-SFM-5)

- Three-step hardening (half-open cap / accept-rate cap / cookie HMAC)
- Cross-ref to RFC §5.K stateless_accept block; OQ-W15 raised
- 4 typed mutations; impact_scope expanded to §5.K + §5.M
```

### Good: Intrinsics doc ratify (feat)
```
feat(intrinsics): §2.5 RNG / §2.6 HMAC ratify plugin path (R11)

- intent + 4 caveats + impact_scope on §2.5; same shape on §2.6
- OQ-W15 (a) Q1=No / Q2=Yes outcome encoded in atomic fields
- impact_scope: OQ-W15 + OQ-W24; T1=0, RT 11/11 preserved
```

### Good: Phase A milestone (feat)
```
feat(scxml): Phase A6 — CRC16 byte-equivalent gate (Rust + C11)

- sources/algorithms/crc16_ccitt.scxml authored; 6-backend codegen
- forge_conformance fixture: 2 entries (bit-by-bit + table form)
- numerical_reference.json 7-vector oracle; matches SCE 758aea3f
```

### Good: Comment-only fix (docs)
```
docs(mnemosyne): Clarify R7 scope-correction via membership, not ledger

- mnemosyne.toml comment cited R254; mechanism is membership 13 → 11
- Comment-only; validate baseline unchanged (T1=0, RT 11/11)
```

### Good: Concise (1-2 items when sufficient)
```
refactor(notes): Move SESSION_KICKOFF.md out of workspace.docs scope

- Activity-log genre is not Mnemosyne-governed; relocate to notes/
- R7 scope correction; workspace.docs 13 → 12 (SESSION_KICKOFF only)
```

### Bad: Too Many Details
```
feat(rfc): Update various RFC sections

- §5.A note
- §5.B note
- §5.C note
- §5.D note
- §5.E note
- Update mnemosyne.toml
- Add tests
```
**Problem**: 7 items - condense to 2-3 key changes

### Bad: Multi-line bullet (continuation/indented wrap)
```
fix(rfc): §6.2.6 drift detection wording catch-up to SCE

- Update CLI name from sce-build verify to sce-codegen verify
  matching SCE commit 97836fa0 unified codegen orchestrator
- Template hash composition now includes Cargo.lock as a binary
  identity proxy per SCE forge::drift implementation
```
**Problem**: each bullet wraps onto continuation lines. Rule is
**one bullet = one line ≤72 chars**. Rewrite tighter or split:
```
fix(rfc): §6.2.6 verify CLI rename + template-hash catch-up to SCE

- `sce-build verify` → `sce-codegen verify` (SCE 97836fa0 unified)
- template-hash includes Cargo.lock (binary-id proxy, forge::drift)
- raw-Edit carve-out; T1=0, RT 11/11 preserved
```

### Bad: Too Vague
```
feat: Update Mnemosyne workspace

- Edit some sections
- Update OQ entries
- Fix issues
```
**Problem**: Which sections? Which OQ? No § / OQ-W## reference or metric

## Common Mistakes to Avoid

### Bad
```
feat: Add new OQ-W24 entry for tier separation! 🎯

- Register §5.I tier-explicit separation 🛡️
- Cross-ref OQ-W15 resolution

🤖 Generated with Claude Code

Co-Authored-By: Claude Opus 4.6 <noreply@anthropic.com>
```
**Problems**: Emojis, attribution tags, exclamation marks

### Good
```
feat(oq): OQ-W24 reg — RFC §5.I Architectural vs Peripheral tier

- SCE counter-offer for baseline boundary hardening (R11)
- parser sections 297 → 298; T1=0, RT 11/11 preserved
```

## Domain-Specific Guidelines

### Mnemosyne workspace mutations
- Reference primitive name (e.g., set_section_intent,
  append_changelog_entry_v2, set_section_impact_scope)
- Cite atomic ledger delta: `entries N → M`, `sections N → M`,
  `parser sections N → M`
- Cite validate metrics: `T1=0`, `RT N/N`, `T3 warn N → M`
- Round N audit entry as the close marker

**Example**:
```
feat(mnemosyne): R8 ARCHITECTURE densify — §2.4 + §10-16 populate

- §2.4 rationale_bullets (6 invariants); §10-16 intent + impact_scope
- §11.4 + §11.5 detailed (intent + 5 rationale + impact_scope each)
- 22 typed mutations; entries 7 → 8; T1=0, RT 11/11, T3 warn 895 → ...
```

### RFC body edits
- `§N.M` reference style (e.g., §5.O, §6.2.6, §5.J.2)
- Cite SCE land commit (8-char SHA) when catching up upstream
- Carve-out vs typed-primitive path explicitly

**Example**:
```
feat(rfc): §5.O sourcemap JSON sidecar contract for 6 backends

- Add `out/{lang}/sce_sourcemap.json` byte-identical sidecar
- Pin §5.O.b symbol naming OQ-W16 (a) delimiter choice
- raw-Edit carve-out; SCE Atomic 0a parity (commit 4716f4d5)
```

### Open Questions tracking
- Reference OQ-W## or Q## explicitly
- Status transition: `open → answered`, `→ deferred`, `→ withdrawn`
- Resolution block cites SCE source / external evidence
- Bundle count when multiple OQs close together

**Example**:
```
feat(oq): OQ-W13/W17/W18/W19 bundled close at deploy/ skeleton authoring

- W13 worker_slot_budget_us defaults pinned per Cortex-M class
- W17 F4 fuzz: libFuzzer baseline; W19 stage_copy_policy=error
- W18 VLE/TLV coefficients estimate-quality (HIL measure carry)
```

### Phase rollout milestones
- Phase A/B/C/D/E in title or body
- Specific milestone tag (e.g., A3, A6, B9, C13)
- Bundle land count when batched

**Example**:
```
feat(scxml): Phase B9 — generated source drift detection wiring

- forge::drift + verify CLI lands; per-file SCE-GENERATED headers
- 19 unit tests cover hash determinism + idempotent prepend
- SCE 97836fa0 commit alignment; round-trip 11/11 preserved
```

### Atomic store metric format

Always quantify mutations with validate output deltas:

- **Entries**: `entries 9 → 11` (atomic ledger growth)
- **Sections**: `sections 102 → 205` (atomic typed-populate) or
  `parser sections 297 → 298` (raw-markdown auto-detect)
- **Validate**: `T1=0` (orphan), `RT 11/11` (round-trip mandatory),
  `T3 warn 843 → 851` (style advisory delta)
- **GENERATED.md**: `sync` (cascade verified) or `stale` (needs regen)
- **Orphan delta**: `T1 orphan total=0 (ledger=N, new=+0, resolved=-0)`

**Key Points**:
- 1-3 items (use fewer when sufficient)
- No emojis, no attribution tags
- Specific §N.M sections, OQ-W##, primitive names, SCE commit SHAs
- Quantify atomic-ledger delta and validate metrics
- Note carve-out vs typed-primitive mutation path
