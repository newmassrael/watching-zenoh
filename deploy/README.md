<!--
SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
-->

# deploy/

Canonical deploy.yaml skeletons that pin the per-target build
parameters for each deploy class. The same `sources/` SCXML pool
emits to different backend + runtime combinations driven by these
skeletons; values that differ per target (cache line size,
cooperative budget, link kind) live here so the SCXML stays
target-agnostic.

## Deploy classes

| File | Target | Runtime | Phase |
|---|---|---|---|
| ap_standalone.yaml | AP-only (x86_64 Linux) | `wz-runtime-tokio` (mio epoll, io_uring opt-in) | D.1 (pending Phase C closure) |
| mcu_target.yaml | MCU-only (STM32H747 Cortex-M7) | `wz-runtime-lwip` (cooperative scheduler) | A–C track (zenoh-pico parity) |
| ap_mcu_pair.yaml | Hybrid AP + MCU | Both runtimes paired | D.1 + A–C |

Each skeleton's header comment lists the resolved
`rfc-open-questions-log.md` answers (OQ-W6 / W8 / W12 / W13 /
W17 / W18 / W19 for the MCU side; W6 / W8 / W12 / W13 / W19 for
the AP side) and the RFC §5.K platform block fields.

## Validation

`scripts/validate-deploy.sh` does a lightweight schema check
(YAML well-formedness + top-level `machines:` key + per-machine
required fields) and runs in Layer D of the local CI. The
end-to-end `sce-codegen build deploy/<x>.yaml` exercise is a
known carry — it requires SCE upstream's `build` subcommand,
tracked under R50 / R123b in the atomic changelog.

## Editing

Author-side edits land directly in these files. Every numeric
default is annotated with its derivation (zenoh-pico precedent
or empirical measurement); revisions should preserve the
annotation so future readers can trace why each number is what
it is.
