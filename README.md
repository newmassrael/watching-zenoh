<!--
SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
-->

# watching-zenoh

zenoh 와이어 프로토콜의 임베디드 / 서버 양면 호환 구현체. SCXML +
[SCE Forge](https://github.com/newmassrael/scxml-core-engine) 기반
build-time codegen 으로 6 backend (Rust / C11 / C++ / Kotlin / Go /
Python) 대응 single source 를 유지한다.

## 무엇인가

이 저장소는 두 가지를 동시에 만든다.

1. **와이어 호환성**: [zenoh-pico](https://github.com/eclipse-zenoh/zenoh-pico)
   1.5.x 클라이언트 / [zenoh](https://github.com/eclipse-zenoh/zenoh)
   1.5.x 라우터 / 피어가 주고받는 wire format 의 MVP 부분집합을
   재구현한다. 부분집합 범위는 [`docs/wire-spec-subset.md`](docs/wire-spec-subset.md)
   에 명시된 §3 scouting / §4 transport session / §5 network routing
   / §6 zenoh payload / §7 extension chain. 확장 (compression / patch /
   liveliness 전체 등) 은 Phase B+ 로 미룬다.

2. **단일 SoT 6 backend codegen**: 동일 SCXML 소스 (sources/) 가
   Rust no_std (MCU) / C11 / C++ / Kotlin / Go / Python 으로 generate
   되며, 같은 conformance harness 가 6 언어를 동일하게 검증한다.
   설계 RFC 는 [`docs/rfc-sce-protocol-synthesis.md`](docs/rfc-sce-protocol-synthesis.md).

설계 SSoT 진입점은 [`ARCHITECTURE.md`](ARCHITECTURE.md); 11 개 spec
doc 은 `docs/` 하위에서 [Mnemosyne](https://github.com/newmassrael/mnemosyne)
atomic-store + GENERATED.md 라이프사이클로 관리된다 (자세한 규칙은
[`CLAUDE.md`](CLAUDE.md) 참조).

## 현재 상태 (Round 23 기준, 2026-05-15)

- **Phase A3 (author-side SCXML 적재)**: 9 SCXML, algorithm-kind,
  6-backend Layer 1 emit verified —
  CRC16 / VLE u64 decode / VLE byte-length / KeyExpr intersect /
  KeyExpr includes / §7 extension dispatch / §3·§4·§5·§5.1·§6 6 종
  MID validator.
- **Phase A4** (cursor / Result type + RFC §5.F const-fold gate): SCE
  upstream 대기. 의존 carry — `tlv_advance`, `vle_u64_encode`, 메시지별
  codec body (Put / Del / Query / Reply / Err).
- **Phase B+**: SCE schema 확장 (test-vector multi-arg / non-bytes 지원)
  및 외부 ratify 의존 (BASELINE_SYMBOLS / Layer 2 fixture / vendor pin
  갱신) 라운드.

진행 상태와 결정 이력은 [`docs/rfc-open-questions-log.md`](docs/rfc-open-questions-log.md)
와 atomic changelog (`docs/.atomic/workspace.atomic.json`) 의 Round
entry 가 SSoT 다.

## 디렉터리

| 경로 | 역할 |
|---|---|
| `ARCHITECTURE.md` | 설계 진입점 (7-subdir 구조 §428 등) |
| `docs/` | Mnemosyne 관리 11 spec doc (workspace.docs) |
| `docs/.atomic/` | atomic-store sidecar (Mnemosyne typed primitive 만 mutate) |
| `docs/GENERATED.md` | atomic-store cascade-render 결과 (gitignored, 직접 편집 금지) |
| `sources/` | SCE Forge 입력 SCXML — [`sources/README.md`](sources/README.md) 참조 |
| `scripts/` | `build-sce.sh` (submodule build) + `verify-codegen.sh` (Layer 1/2 verify) |
| `vendor/sce/` | SCE git submodule, vendor pin (R14 land) |
| `notes/` | activity-log 장르 (Mnemosyne 관리 대상 아님) |
| `.githooks/` | pre-commit / commit-msg / pre-push 게이트 |
| `deploy/` | deploy.yaml skeleton (Phase B+) |

## 빌드 + 검증

SCE codegen 바이너리는 vendor submodule 에서 빌드한다.

```sh
git submodule update --init --recursive
./scripts/build-sce.sh
```

특정 SCXML 의 6-backend emit 을 검증한다 (Layer 1).

```sh
./scripts/verify-codegen.sh sources/algorithms/crc16_ccitt.scxml
```

SCE upstream 에 paired fixture 가 있는 경우 두 번째 인자로 byte-golden
diff 까지 활성화한다 (Layer 2 — RFC §5.O traceability anchor normalize
후 body equivalence).

```sh
./scripts/verify-codegen.sh \
  sources/algorithms/keyexpr_intersect.scxml \
  vendor/sce/tests/forge/resources/algorithm_keyexpr_intersect_exact.scxml
```

## Local CI gates

한 번만 install (clone 직후).

```sh
git config core.hooksPath .githooks
```

세 hook 이 자동 작동한다.

- **pre-commit** — `mnemosyne-cli validate-workspace` (T1 cross-ref
  orphan / round-trip / atomic ledger drift).
- **commit-msg** — [`COMMIT_FORMAT.md`](COMMIT_FORMAT.md) 강제
  (subject + 본문 ≤72 byte/line, no emoji / co-author / wrap).
- **pre-push** — push 시점 재검증 (manual atomic.json 편집 / amend /
  rebase 직후 상태 catch).

`pre-commit` / `pre-push` 는 `mnemosyne-cli` 가 PATH 에 있어야 한다.

```sh
cargo install --path /path/to/mnemosyne/crates/mnemosyne-cli
```

## 라이센스

이 저장소는 **dual-licensed** 다.

- **`LGPL-3.0-or-later`** — free tier, LGPL-3 의무사항 (anti-tivoization
  포함) 동의. 자세히는 [`LICENSE-LGPL-3.0.md`](LICENSE-LGPL-3.0.md) +
  [`LICENSE-GPL-3.0.md`](LICENSE-GPL-3.0.md).
- **`LicenseRef-watching-zenoh-Commercial`** — paid tier, 5-way 면제.
  자세히는 [`LICENSE-COMMERCIAL.md`](LICENSE-COMMERCIAL.md).

개요는 [`LICENSE`](LICENSE) 가 출발점.

저작자측 소스 파일 (sources/\*\*.scxml / crates/\*\*/\*.rs / runtime/\*\*/\*.{rs,c,h}
/ deploy/\*\*.yaml) 은 다음 SPDX 헤더를 carry 한다.

```
SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
```

생성 파일 (`out/**`) 은 SCE 의 MIT 헤더를 carry; vendored 코드는 원본
SPDX 헤더 유지 + `THIRD_PARTY.md` 원장 (첫 vendored snippet land 시
생성).

## 외부 참조

- SCE (build infra): [scxml-core-engine](https://github.com/newmassrael/scxml-core-engine)
- Mnemosyne (atomic-store + GENERATED.md lifecycle): [mnemosyne](https://github.com/newmassrael/mnemosyne)
- zenoh upstream: [eclipse-zenoh/zenoh](https://github.com/eclipse-zenoh/zenoh)
- zenoh-pico upstream: [eclipse-zenoh/zenoh-pico](https://github.com/eclipse-zenoh/zenoh-pico)

## 기여

이 단계는 SSOT contract / atomic-store 라이프사이클 / SPDX 헤더 정책이
프로젝트 인프라의 핵심이라 [`CLAUDE.md`](CLAUDE.md) 가 명시한 절차를
따라야 한다 (AI agent operating guide 형식이지만 사람 기여자에게도
규칙 자체는 동일). 결정 이력은 atomic changelog 의 Round entry, 활동
로그는 [`notes/NEXT_SESSION.md`](notes/NEXT_SESSION.md).
