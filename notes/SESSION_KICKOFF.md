# watching-zenoh — 다음 세션 시작 스크립트

아래 블록을 다음 세션 첫 메시지로 그대로 붙여넣으세요.

---

## 세션 시작 프롬프트 (복사용)

```
watching-zenoh 프로젝트 작업을 이어서 할게. 먼저 현재 상태를 파악해줘.

필독 파일 (이 순서로):
1. /home/coin/watching-zenoh/docs/SESSION_KICKOFF.md           ← 이전 세션 결정사항 요약
2. /home/coin/watching-zenoh/ARCHITECTURE.md                   ← 설계 문서 (MVP=zenoh-pico 파리티)
3. /home/coin/watching-zenoh/docs/rfc-sce-protocol-synthesis.md ← SCE 확장 RFC
4. /home/coin/watching-zenoh/docs/wire-spec-subset.md          ← Zenoh 1.x 메시지 enumerate (MVP 분류표)
5. /home/coin/watching-zenoh/docs/session-fsm.md               ← 세션 FSM prose sketch (unicast + multicast, Q13 resolution)
6. /home/coin/watching-zenoh/docs/rfc-open-questions-log.md    ← Q1–Q14, OQ-W1–OQ-W12 트래킹 로그

참조 저장소:
- /home/coin/scxml-core-engine/   ← SCE 소스. Forge/Mesh 상태 확인 시 직접 읽기.
  - sce-build/src/generator.rs:35                     (enum Language {Rust,Cpp,Kotlin,Go,Python,C11} — 6 backends)
  - sce-build/src/forge/generator.rs:241              (Language::Rust arm)
  - sce-build/src/forge/model.rs:70                   (ForgeKind 11개 enum, is_supported() 모두 true)
  - sce-build/src/mesh/codegen.rs:849                 (Language::Cpp 아닌 경우 UnsupportedLanguage)
  - sce-forge-runtime/rust/src/lib.rs:16              (#![no_std] — Forge 런타임은 이미 no_std + no-alloc)
  - sce-rust-runtime/Cargo.toml                       (statechart 런타임, std 기반 — RFC §5.J.2 대상)
  - tools/codegen/templates/forge/{rust,cpp,kotlin,go,python,c}/  (6개 언어 emitter; C11은 758aea3f 시점 클로즈드)
  - tools/codegen/templates/mesh/cpp/                 (Mesh는 cpp만)
- /home/coin/.cargo/git/checkouts/zenoh-*/49c8a53/   ← Zenoh 1.5.0 업스트림 (wire-spec-subset 근거)
  - commons/zenoh-protocol/src/lib.rs:31              (VERSION = 0x09)
  - commons/zenoh-protocol/src/{scouting,transport,network,zenoh}/

작업 환경:
- git 저장소, branch: main, 커밋은 아직 안 함 (사용자가 명시 지시할 때만 커밋)
- 코드는 아직 없음 (pre-implementation). SCE Phase A 대기 중.
- 한국어로 응답, 파일 경로와 코드 식별자는 영문 유지.

규칙:
- 추정하지 말고 실제 파일 확인할 것 (SCE 상태 질문은 항상 /home/coin/scxml-core-engine/ 직접 읽기)
- 복잡한 정규식으로 파일 손상 우려 있으면 사용자에게 직접 수정 요청
- 테스트 파일은 생성 후 바로 삭제, 임시 파일 금지

읽기 완료 후 "현재 상태 파악 완료"라고 말하고 다음 단계 제안해줘.
```

---

## 이전 세션 (2026-04-24) 결정 사항 핵심

### 확정된 설계 원칙

1. **MVP 기준 = zenoh-pico 파리티** (peer + client 모드)
   - "leaf subset"이 아니라 zenoh-pico가 하는 모든 기능을 MCU에서 재현
   - AP 백엔드 = zenoh의 peer/client 모드 Rust 재구현
   - MCU 백엔드 = zenoh-pico의 peer/client 모드 C 재구현
   - 둘 다 같은 SCXML에서 내려옴

2. **장기 비전 = 모든 Zenoh 기능 마이그레이션**
   - "Out of scope"는 두 종류로 분리:
     - **Permanent** (MCU class 물리 제약): router on MCU, heap, script
     - **Deferred** (MVP 유예, 마이그레이션 경로 명시): AP router, BLE/Raweth, API shim 등
   - AP는 결국 full zenoh를 할 수 있어야 함

3. **확장성 불변량 6개** (ARCHITECTURE.md §2.4)
   - Static-first, dynamic-opt-in
   - Link drivers are extensible (open set via target plugin)
   - Kinds are additive
   - Generated code exports as library, not monolith
   - Platform gating only when necessary
   - `out/` is SSoT-downstream (manual edit 금지)

4. **Cargo workspace 구조** (ARCHITECTURE.md §5)
   - `out/ap/` = library crate (rlib + cdylib), 실행 파일 아님
   - `crates/watching_zenoh_api/` = 옵션 API shim
   - `crates/watching_zenoh_bin/` = 기본 AP 바이너리
   - 미래의 플러그인은 workspace 크레이트로 추가

### SCE 상태 (2026-04-24 직접 확인)

- **ForgeKind**: 11개 존재, 전원 `is_supported() == true` (`sce-build/src/forge/model.rs:70`).
  `Statechart, Transform, Lookup, Condition, Codec, Procedure, Validator, Filter, Interpolation, Timer, Observer`
- **RuntimeDep 티어**: `None` / `ForgeRuntime` / `ForgeRuntimeHal` / `SceRuntime`
  — RFC §5가 제안하는 신규 kind(`algorithm`, `link`, `buffer-pool`, `worker`,
  `bounded-collection`)는 이 티어 체계에 편입되어야 함.
- **Forge 다언어 emitter**: Rust/Cpp/Kotlin/Go/Python/C11 6개 모두 존재
  (`sce-build/src/generator.rs:35 enum Language`). 11 kinds × 6 backends 매트릭스는
  `758aea3f test(forge): close C11 byte-golden parity with 5 backends` 커밋에서 클로즈드.
- **Mesh**: **Cpp-only**, 다른 언어는 `UnsupportedLanguage` 오류 (`mesh/codegen.rs:849`).
- **C11 backend**: 존재 (758aea3f 시점). RFC §5.J.1이 요구하는 작업은
  *기존 11 kind × C11* 가 아니라 *RFC가 추가하는 새 kind × C11* (algorithm/link/
  buffer-pool/worker/bounded-collection 등); RFC §5.J.4 매트릭스 참조.
- **Rust `no_std` 상태 (정밀화 — 이전 "없음" 주장 대체)**:
  - **Forge 런타임(`sce-forge-runtime/rust/`)은 이미 `#![no_std]` + no-alloc 베이스라인.**
    → `Transform`/`Codec`/`Validator`/`Procedure` 등 순수 함수 kind는 Rust 쪽에서 이미 MCU 가능.
  - **Statechart 런타임(`sce-rust-runtime/`)은 std 기반**, `no_std` feature 없음.
    → 세션/declare/query/fragment FSM이 MCU에서 돌려면 RFC §5.J.2가 이 크레이트에 `no_std` feature gate 추가 필요.
  - 즉 갭은 "Rust 전체"가 아니라 **statechart 런타임에 한정**.

### RFC §5 kinds 상태

MVP에 포함된 kind (§5.A ~ §5.N):
- 5.A algorithm (bounded loops, no recursion)
- 5.B Codec DSL (VLE, variant, flags, present-if, len-prefix, repeat, until-eof, TLV chain with bounds, DMA alignment, test-vector)
- 5.C link (byte-stream I/O, open-set drivers via target plugin)
- 5.D Timer/worker
- 5.E Buffer pool (cache-policy: maintain/non-cacheable/none; reassembly variant)
- 5.F Build-time const-fold
- 5.I sce:extern (concrete atomics with acquire/release/acq_rel/seq_cst, cache maintenance intrinsics, IRQ save/restore, target plugin 확장)
- 5.J C11 + Rust no_std codegen
- 5.K Deploy model (has_dcache, dcache_line_size, core_count, worker_stack_budget, target_plugin)
- **5.L bounded-collection** (신규, Phase C1)
- **5.M Fragment/reassembly** (buffer-pool 변형 + FSM 패턴)
- **5.N Multi-link concurrency** (§5.C 보강, codegen contract)

Phase 2 deferred:
- 5.G Parametric kinds
- 5.H Recursive/tree types

### Phase rollout (RFC §7)

- **Phase A** (w1–6): Foundation, algorithm kind, C11 skeleton, CRC parity gate
- **Phase B** (w7–16): 전체 Zenoh 메시지 세트 codec, link UDP/TCP, buffer-pool, drift detection
- **Phase C** (w17–26): Worker, no_std, intrinsics, bounded-collection, runtime KeyExpr matching, client mode FSM, fragment/reassembly, multi-link, Serial/WebSocket → **C14에서 zenoh-pico parity gate 테스트**
- **Phase D** (w27+): Parametric kinds, recursive types, AP router prerequisites, API shim, BLE/Raweth target plugin

### LOC 추정치

- **SCE-side 추가**: 8,000–12,000 LOC (모든 phase 합계)
- **Downstream authoring**: ~10,700 LOC (SCXML 7K + 런타임 1.7K + 테스트 2K)
- vs 수작업 대체 구현: 35–50K LOC → **3–5배 압축** + **구조적 drift 제거**

### Open questions

**정식 트래킹 로그: `docs/rfc-open-questions-log.md`** — 아래는 요약 인덱스.

SCE-side (Q1–Q14, RFC §8):

- Q1: algorithm kind 이름
- **Q2 (needs-verification)**: 기존 Timer kind가 §5.D 수용? — Timer 실존·`RuntimeDep::ForgeRuntimeHal` 확인됨. §5.D 요구사항 매치 여부만 남음.
- Q3: algorithm → algorithm call 허용?
- Q4: compute-at="build"를 Transform에도 허용?
- Q5: §5.B codec DSL PR 분할 전략
- Q6: C11 vs C99
- Q7: sce:extern 화이트리스트 위치
- **Q8 (답변됨)**: Link drivers extensible? → Yes, via target plugin
- Q9: sram_regions 포맷 (64K vs 65536)
- Q10: parametric kinds XSD shape
- Q11: bounded-collection capacity source (deploy vs const)
- Q12: fragment/reassembly를 author-level vs shipped template
- Q13: client/peer FSM variants 표현 (두 파일 vs mode-attribute vs 파라메트릭)
- Q14: algorithm이 bounded-collection ops 호출하는 방식

Wire-subset side (OQ-W1–OQ-W8, `wire-spec-subset.md` §10):

- OQ-W1: zenoh-pico release pin for Phase-A freeze
- OQ-W2: Auth baseline methods (proposal: `{none, usrpwd}`)
- OQ-W3: Interest semantics with no router present (router-only vs peer-capable in 1.x)
- OQ-W4: `ext::Compression` critical-bit 안전성
- OQ-W5: OAM drop semantics (proposal: 진단 이벤트)
- OQ-W6: batch/fragment 기본값 (deploy 저작 시 확정)
- OQ-W7: `ext::PatchType` mismatch policy
- OQ-W8: bounded-collection 기본 capacity (deploy 저작 시 확정)

## 이번 세션(2026-04-24 continuation) 완료 작업

- **`docs/wire-spec-subset.md` 신규** — Zenoh 1.x 메시지 전체 enumerate
  (Scout/Hello · Init/Open/Close/KeepAlive/Frame/Fragment/Join/OAM ·
  Push/Request/Response/ResponseFinal/Interest/Declare/OAM · Put/Del/Query/Reply/Err),
  확장 체인·transport 매트릭스·RFC §5 kind 역참조·OQ-W1~W8 오픈 퀘스천. 근거는
  업스트림 `zenoh-protocol` 1.5.0 소스 직접 읽기.
- **`docs/rfc-open-questions-log.md` 신규** — Q1–Q14 + OQ-W1–OQ-W8 통합 트래킹.
  Q2는 실증(`ForgeKind::Timer` 실존·`RuntimeDep::ForgeRuntimeHal`)으로
  `open` → `needs-verification` 다운그레이드. Q8은 `answered` 기록.
- **`ARCHITECTURE.md` §4.1/§4.2 정밀화** — 11개 ForgeKind 전체 나열 + RuntimeDep 티어,
  Forge 런타임 `no_std` 상태, Statechart 런타임 std-only 갭 명시.
- **RFC `§4` 및 `§5.J/§5.J.2` 정밀화** — "Ten kinds"→"Eleven kinds",
  §5.J 문제진술 및 5.J.2 범위를 statechart 런타임에 한정.

## 이번 세션(2026-04-25) 완료 작업

- **`docs/session-fsm.md` 신규 (708줄)** — Peer/Client 세션 FSM prose-level sketch.
  근거는 업스트림 zenoh 1.5.0 `io/zenoh-transport/src/{unicast/establishment,
  multicast}` 직접 읽기. 핵심 발견:
  - **Q13 mis-cast 확인**: 세션 레이어는 peer/client wire-identical
    (`open.rs`에 `OpenLink` 단일 struct, `whatami`만 파라미터로 받음).
    구조적 차이는 unicast(4-way 핸드셰이크) vs multicast(핸드셰이크 없음,
    주기적 Join + peer-table 학습)에 존재.
  - 따라서 세션 SCXML은 **transport class로 분할**:
    `session_unicast.scxml` + `session_multicast.scxml`
    (peer/client는 둘 다 unicast FSM 공유).
  - Close reasons 7종 매핑, `Established` 병렬 영역 4개(RxDispatch,
    TxSchedule, Keepalive, LeaseMonitor) 구조 확정.
  - 8개 timer 표준화 (§2.5).
  - Design gap G-SFM-1~4 기록.
- **`docs/rfc-open-questions-log.md` 갱신**:
  - Q13 `open` → `answered` (unicast/multicast 분할 근거 기록)
  - OQ-W9~W12 4개 신규 (client+multicast 참여 여부, ext::Auth multi-step 핸드셰이크,
    Multi-link TX dispatch 정책, Closing timeout 기본값)
- **`ARCHITECTURE.md` §5/§4.3/§8.2 갱신** — 소스 레이아웃에
  `session_unicast.scxml` + `session_multicast.scxml` + `scouting.scxml`
  반영; §8.2 session FSM 스케치는 `docs/session-fsm.md` 포인터 추가.
- **`docs/rfc-sce-protocol-synthesis.md` 갱신**:
  - §7 Phase C C8 리타겟 (Client-mode variant → Multicast session FSM)
  - §8 Q13 답변 반영 (unicast/multicast 분할 근거)
- **`docs/wire-spec-subset.md` §4 갱신** — `session_peer/client.scxml` 참조를
  `session_unicast/multicast.scxml`로 변경 + Q13 resolution 포인터.

## 이번 세션(2026-04-25 후속 review 반영) 완료 작업

리뷰 피드백 두 항목 반영 (cooperative-scheduler WCET / 멀티코어 HW 세마포어):

- **`ARCHITECTURE.md` §3.4 / §7.2 / §4.2 갱신**
  - §3.4: cooperative scheduler WCET 디시플린 명시 + cross-core sync는
    target_plugin으로 HW sem (HSEM/spinlock/mailbox) 등록되는 경로 추가.
  - §7.2: cooperative scheduler bullet에 `worker_slot_budget_us` /
    `keepalive_jitter_budget_us` 적용 명시; 멀티코어 deploy 경로 명시.
  - §4.2 deploy.yaml 필드 목록에 `worker_slot_budget_us` /
    `keepalive_jitter_budget_us` 추가.

- **`docs/rfc-sce-protocol-synthesis.md` §5.A / §5.I / §5.K 갱신**
  - §5.A `<sce:wcet-bound>` 어노테이션 (`static`/`measured`/`opaque`)
    + 진단 3종 (`algorithm/wcet-bound-missing`,
    `algorithm/wcet-exceeds-slot-budget`,
    `algorithm/wcet-mode-opaque-under-cooperative`).
  - §5.I target_plugin 섹션에 HW 세마포어 worked example
    (`sce_hw_sem_take` / `release` / `mbox_send`) +
    `cross_core_sync` deploy.yaml subsection 추가.
  - §5.K scheduler 섹션에 `worker_slot_budget_us`,
    `keepalive_jitter_budget_us` 신규 필드 + 진단 5종
    (`deploy/worker-slot-budget-missing`,
    `deploy/keepalive-jitter-budget-missing`,
    `worker/slot-budget-exceeded`,
    `worker/keepalive-jitter-violation`,
    `deploy/multicore-without-target-plugin`).

- **`docs/rfc-open-questions-log.md` 갱신** — OQ-W13/W14 신규.
  - OQ-W13: `worker_slot_budget_us` 기본값과 KeyExpr WCET 소스
    (static vs measured) — Phase A 진입 전 결정 필요.
  - OQ-W14: HW 세마포어 심볼명 표준화 (SCE 표준 vs ad-hoc + symbol-map).
  - id-space 헤더와 change log 갱신.

## 이번 세션(2026-04-25 후속 review #2 반영) 완료 작업

리뷰 피드백 3항목 명료화 (DMA 정렬 의미론 / 링커 ALIGN(x) 디펜스 인 뎁스 /
no_std heapless 콜렉션 플랜):

- **`ARCHITECTURE.md` §3.4 / §6.2 갱신**
  - §3.4 alignment bullet에 "wire-format field offset" vs "host buffer
    allocation" 경계 명시. AP는 `bytes::BytesMut` 정렬 의무 없음, MCU만
    링크 타임 pool slot 정렬. AP↔MCU는 wire 통신, shared memory 없음을
    못박음 (리뷰어 2.2 오독 방지).
  - §6.2 `linker_fragment.ld` bullet을 "explicit `ALIGN(x)` per pool +
    paired DMA descriptor section ALIGN()" 로 확장. `aligned()` 속성 +
    section ALIGN + `_Static_assert` 3중 방어 명시 (리뷰어 2.1 보강).

- **`docs/rfc-sce-protocol-synthesis.md` §5.B / §5.E / §5.J.2 갱신**
  - §5.B "DMA alignment semantics" 에 "Scope: wire layout, not host
    allocator" 단락 추가. AP `bytes::BytesMut` 정렬 의무 없음 명시.
  - §5.E codegen contract의 linker fragment bullet을 확장 — `SECTIONS`
    예시 shape (`.sram1_pool`/`.sram1_desc` ALIGN(32)) + 3중 방어 논리.
  - §5.J.2 끝에 "No-alloc collection plan (cross-reference)" 표 추가.
    statechart event queue / bounded-collection / TX queue / String
    backing을 §5.D/§5.L/§5.N 로 한 곳에 매핑 (리뷰어 2.3 가시성 보강).

## 이번 세션(2026-04-25 후속 review #3 반영) 완료 작업

리뷰 피드백 3항목 반영 (WCET 측정 워크플로우 / pool slot ownership FSM /
KeyExpr trie 가이던스):

- **`docs/rfc-sce-protocol-synthesis.md` §5.E 대폭 확장**
  - 신규 단락 "Slot lifecycle FSM (ownership tracking)" 추가.
    7개 상태 (`free` / `cpu-mut` / `dma-armed-{tx,rx}` /
    `dma-busy-{tx,rx}` / `cpu-ref`) + 11개 허용 transition 정의.
    cache maintenance 호출 위치를 `cpu-mut → dma-armed-tx` (clean)
    와 `dma-busy-rx → cpu-ref` (invalidate) edge 에 고정.
    author code의 직접 cache_clean/invalidate 호출 금지.
  - 신규 author-visible API (`pool_acquire_for_encode`, `link_arm_tx`,
    `link_arm_rx`, `pool_return`) 와 phantom-typed `Slot<state>` 명시.
  - 신규 진단 5종: `pool/ownership-violation`,
    `pool/cache-maintenance-misplaced`, `pool/slot-leak-on-error-path`,
    `pool/double-arm`, `pool/return-on-dma-state`.

- **`docs/rfc-sce-protocol-synthesis.md` §5.A WCET 워크플로우 명시화**
  - 신규 단락 "Measurement workflow" 추가. `mode="measured"` 가
    `target=` (deploy descriptor 매칭) + `source-hash=`
    (canonical IR sha256, staleness detection) 두 binding field 를
    가짐을 명시. `sce-bench` 워크플로우 3단계 기록.
  - 신규 진단 2종: `algorithm/wcet-measured-target-mismatch`,
    `algorithm/wcet-measured-stale-against-source-hash`.

- **`docs/rfc-sce-protocol-synthesis.md` §5.F worked example +
  매칭 정책 가이던스 추가**
  - "Worked examples" 섹션에 KeyExpr trie 추가. flat (offset-based)
    representation 은 §5.F 로 즉시 buildable, recursive node 는
    §5.H Phase 2 대기 명시.
  - "Choosing static trie vs runtime bounded-collection" 결정 매트릭스
    표 추가 (3 use case × 권장 path). MVP baseline 은 runtime
    bounded-collection 임을 못박음 (zenoh-pico parity 요구).

- **`ARCHITECTURE.md` §2.4 invariant 1 + §3.4 갱신**
  - §2.4 invariant 1 에 KeyExpr matching 정책 가이던스 단락 추가
    (Runtime bounded-collection / Build-time static trie / Hybrid 3옵션
    + per-machine deploy.yaml 선택).
  - §3.4 cache coherency bullet 을 "lifecycle FSM 의 specific edge 에
    pinned" 로 강화. pool slot ownership 추적이 IR build-time
    borrow-check 임을 신규 bullet 로 명시.

## 이번 세션(2026-04-25 후속 review #4 반영) 완료 작업

리뷰 피드백 4항목 중 3건 보강 (B항은 직전 라운드에서 처리 완료, 리뷰어 인정):

- **(A) MTU / fragmentation 정적 분석** — RFC §5.K + §5.M + ARCHITECTURE §9.3
  - §5.K `links` 항목에 `mtu_bytes` (필수, fragment-emitting link)
    + `expected_p99_bytes` (optional, stage-copy rate 경고 driver) 신규.
  - §5.K 진단 3종 추가 (`deploy/link-mtu-missing-on-fragmenting-link`,
    `deploy/link-mtu-below-driver-floor`,
    `deploy/link-expected-p99-exceeds-mtu`).
  - §5.M "Build-time fragmentation analysis" 단락 신규.
    3개 정량 룰 (reassembly capacity / stage-copy rate ≤ 25% /
    slot-size recommendation) + 진단 3종
    (`reassembly/max-fragments-insufficient-for-mtu` 하드에러,
    `reassembly/expected-fragmentation-rate-high` 경고,
    `reassembly/slot-size-recommendation` informational).
  - ARCHITECTURE §9.3 prose 가이던스 → 정량 룰 3종 표로 교체.

- **(C) Application-facing API contract** — RFC §5.E
  - 신규 단락 "Application-facing API contract" — lifecycle FSM 이
    SCE-internal 만 커버하던 boundary 를 public façade 까지 확장.
  - **Rust:** `Sample<'pool>` borrow + `SlotGuard` RAII +
    `take()` stage-copy. lifetime 으로 callback escape 차단.
  - **C:** `sce_sample_t` opaque slot handle + `sce_sample_take()`
    명시적 stage-copy. Debug build (`-DSCE_DEBUG_OWNERSHIP=1`)
    에서 `0xDE` poisoning + double-take/take-after-callback 트랩.
  - 진단 2종 추가 (`pool/sample-take-without-stage-pool`,
    `pool/sample-callback-signature-non-borrow`).

- **(D) Adversarial fuzz testing** — ARCHITECTURE §11.6 + RFC [Adversarial fuzz harness](rfc-sce-protocol-synthesis.md#625-adversarial-fuzz-harness)
  - ARCHITECTURE §11.6 "Adversarial input (fuzz testing)" 신규.
    5개 canonical fuzz target (vle / tlv-chain / length-prefix /
    variant / borrow-mode-overrun), AP `cargo fuzz` + MCU host-build
    libFuzzer/AFL with sanitizers, 24h coverage gate, slow-input fail
    (>1ms), corpus seed from §11.2 wire-replay pcap, 회귀 vector 를
    §11.1 cross-backend parity 로 영구화. session-FSM 차원 fuzzing
    (OPEN 이후 임의 byte → 패닉 없이 valid update 또는 typed Closing) 도 포함.
  - RFC [Adversarial fuzz harness](rfc-sce-protocol-synthesis.md#625-adversarial-fuzz-harness) 신규 — codegen 이 fuzz
    target 자동 생성, "임의 바이트 → parsed value | typed CodecError,
    panic/trap/hang/OOB 절대 금지" 계약. 진단 2종
    (`codec/fuzz-harness-not-generated`,
    `codec/fuzz-harness-stale-against-source-hash`).
  - 기존 6.2.5 "Generated source drift detection" 은 6.2.6 으로
    번호 이동. ARCHITECTURE §11.5 + RFC Phase B9 상호 참조 갱신.

- **(B) KeyExpr 매칭 정책 세분화** — 직전 라운드(#3)에서 이미 처리됨.
  리뷰어가 *"문서상의 Hybrid 접근법이 이 부분을 잘 짚고 있습니다"* 인정.
  추가 작업 없음.

## 이번 세션(2026-04-25 후속 review #5 반영) 완료 작업

리뷰 피드백 2항목 반영 (cache-line slot_size invariant / C 소유권 정적 분석
multi-layer):

- **(A) Cache-line slot_size invariant** — RFC §5.E + ARCHITECTURE §3.4
  - §5.E "Cache policy semantics" 단락 뒤에 "Cache-line invariants under
    `maintain`" 신규 단락. ARM cache maintenance by VA 가 partial line
    까지 invalidate 한다는 사실 기반 (CMSIS 명세). 두 invariant 명시:
    pool start aligned + slot_size 가 cache line 배수.
  - 신규 진단 `mem/slot-size-not-cache-line-multiple` — `cache-policy:
    maintain` AND `slot_size % platform.dcache_line_size != 0` →
    빌드 에러. 250 byte slot + 32 byte line 사례로 false sharing
    시나리오 worked example 명기.
  - 정책: codegen은 silently pad 하지 않음 — author 가 명시적으로
    cache-line-multiple slot_size 선언.
  - ARCHITECTURE §3.4 cache coherency bullet 에 두 invariant cross-ref 추가.

- **(C) C 소유권 multi-layer 정적 분석** — RFC §5.E
  - "Application-facing API contract" C 섹션을 Layer 1~4 형태로 재구성:
    - **Layer 1 (compile-time, Clang only):** `consumable` typestate
      + `capability` + `callable_when` + `set_typestate` +
      `param_typestate` + `warn_unused_result`. `-Wconsumed
      -Wthread-safety` 에서 use-after-take / double-take / callback
      escape leak 컴파일 타임 잡힘. **release build 에서도 작동.**
      `__has_attribute()` gate 로 portability 확보.
    - **Layer 2 (compile-time, 분석기 의존):** PC-Lint `custodial(1)`,
      Coverity `+free`, Polyspace 호환 주석. Clang 아닌 toolchain 에서도
      같은 클래스의 위반 잡음.
    - **Layer 3 (runtime, debug only):** 기존 `-DSCE_DEBUG_OWNERSHIP=1`
      포이즈닝 유지. Layer 1~2 가 못잡는 동적 간접 호출 case 보완.
    - **Layer 4 (release runtime):** 검증 없음. Layer 1/2 가 release
      방어선이라는 점 명시.
  - 4개 layer 의 trade-off 표 명기 (build mode / toolchain / 잡는
    버그 / 비용).
  - 권장 정책 명시: release build 는 Clang + `-Wconsumed -Wthread-safety`
    하드 에러 OR 인정된 정적 분석기 CI; Layer 4 단독 의존은 디스카리지.
  - 신규 진단 `pool/sample-typestate-attributes-disabled` — Clang 빌드인데
    `__has_attribute(consumable)` 이 false 인 경우 경고.

## 이번 세션(2026-04-25 후속 review #6 반영) 완료 작업

리뷰 피드백 6항목 중 5건 보강 (1건은 이미 처리됨):

- **(#1 TLV 스택 폭발)** 이미 처리됨. §5.B max-depth + iterative-only +
  `codec/tlv-chain-depth-exceeds-stack-budget` 진단으로 다층 방어.
  추가 작업 없음.

- **(#2 Host WCET 부정확성)** RFC §5.A measurement workflow 격상.
  - `measured_on=` 신규 attribute (HIL / sim / host w/ calibration)
    + 정확도/안전 마진 매트릭스 (×1.0 / ×1.2 / ×3.0).
  - host 측정값은 ×3.0 적용된 값으로 slot budget 비교.
  - 진단 2종 (`algorithm/wcet-measurement-class-missing`,
    `algorithm/wcet-measurement-class-untrusted-without-margin`).

- **(#3 RX burst vs cooperative scheduler)** RFC §5.K + §5.E 신규.
  - §5.K links 에 `burst_pps` + `rx_dispatch` (`isr_to_pool` /
    `worker_tick`) 필드 신규. 진단 4종.
  - §5.E "Burst absorption analysis (RX pools)" 단락 신규.
    isr_to_pool: `slot_count ≥ burst_pps × max_handler_latency_us / 1M
    × 2.0`; worker_tick: `slot_count ≥ burst_pps × tick_period_us / 1M
    × 2.0`. wire-rate ceiling 계산 및 build report 출력.

- **(#4 Cross-compile 퍼징)** ARCHITECTURE §11.6 + RFC [Adversarial fuzz harness](rfc-sce-protocol-synthesis.md#625-adversarial-fuzz-harness) 매트릭스화.
  - F1 (x86_64 + libFuzzer/AFL + ASan/UBSan), F2 (i686 32-bit
    cross-build), F3 (qemu-system-arm Cortex-M3/M4/M7) 3-tier 의무 +
    F4 HIL Phase D 권장.
  - F2/F3 만에서 재현되는 크래시는 architecture-specific 로 별도
    추적. 진단 1종 (`codec/fuzz-cross-target-tier-disabled`).

- **(#5 Hidden allocation)** ARCHITECTURE §11.4 + RFC [No-alloc guard layered](rfc-sce-protocol-synthesis.md#624-no-alloc-guard-layered) 5-layer 격상.
  - Layer 1 (stub trap symbols), Layer 2 (linker --wrap), Layer 3
    (libc variant pin: nano.specs / picolibc-tiny), Layer 4 (post-link
    call-graph reachability vs deny-list: vasprintf/asprintf/strdup/
    getline/posix_memalign), Layer 5 (-fno-exceptions -fno-rtti).
  - 진단 3종 (`noalloc/libc-variant-not-pinned`,
    `noalloc/reachable-allocator-from-deny-list`,
    `noalloc/exceptions-not-disabled`).

- **(#6 Linker flavor)** RFC §5.I + ARCHITECTURE §6.2 명시화.
  - target_plugin 에 `linker_flavor` 필드 신규 (`gnu_ld` 기본 |
    `scatter_arm` | `icf_iar` | `os_managed`).
  - 벤더 매트릭스 표 (GCC/Clang/ESP-IDF/MCUXpresso/Zephyr = gnu_ld
    Phase A; Keil/IAR = Phase C+; Zephyr/NuttX OS-managed = Phase A
    passthrough).
  - 진단 2종 (`extern/linker-flavor-unsupported`,
    `extern/linker-flavor-os-managed-without-cmake-import`).

## 이번 세션(2026-04-25 후속 review #7 반영) 완료 작업

리뷰 피드백 7항목 보강 (Critical 3 + Medium 2 + Low 2):

- **(#1 VLE + 정적 패딩 모순)** RFC §5.B "DMA alignment semantics" 에
  scope 단락 신규 — alignment 적용 가능 위치 (offset 0, 모든 선행 필드
  fixed-width, padding-to-boundary 직후) 와 거부 위치 (vle_*, len-prefix,
  repeat with runtime count, until-eof) 명시. 진단
  `codec/dma-alignment-unsatisfiable` 가 그 거부를 강제함을 narrative 에
  연결.

- **(#2 Crypto FSM 상태)** RFC §5.E lifecycle FSM 에 4개 reserved 상태
  (`crypto-armed-rx`, `crypto-busy-rx`, `crypto-armed-tx`,
  `crypto-busy-tx`) + transition skeleton + cache maintenance pinning 추가
  (Phase D+ marker). MVP codegen 은 거부, target_plugin 가 crypto_engine
  declare 시 활성. §2.4 invariant 3 (additive kinds) 의 FSM 차원 적용
  명시.

- **(#3 Reassembly DoS)** RFC §5.M reassembly-pool 에
  `<sce:per-peer-quota>` 필드 신규. 빌드 invariant
  (`peer_table.capacity × per-peer-quota ≥ slot_count`), 런타임 enforcement
  (peer X 가 quota 도달 시 X 한정 거부), `on-overflow` 와의 우선순위
  (quota 가 먼저). 진단 4종 추가
  (`reassembly/per-peer-quota-build-invariant-violated`,
  `reassembly/per-peer-quota-exhausted`,
  `reassembly/per-peer-quota-missing-on-untrusted-link`,
  `reassembly/stage-copy-wcet-exceeds-slot-budget`).

- **(#4 Stage copy WCET)** RFC §5.K platform 에 `clock_freq_mhz` +
  `memcpy_cycles_per_byte` 필드 추가 (M0+:4.0 / M3-M4:2.0 / M7:1.0 /
  A-class:0.5 default). RFC §5.M build-time fragmentation analysis 에
  4번째 룰 추가: `stage_copy_wcet_us = expected_p99_bytes × cycles /
  freq` 가 `worker_slot_budget_us` 초과 시 하드 에러. M0+ 에서 16KB ×
  4 / 48 ≈ 1.4ms 가 200µs 슬롯의 7배라는 검증 사례 명기. 4가지 author
  resolution path 명시.

- **(#5 Callback escape)** RFC §5.E API contract 에 Layer 3.5 신규.
  `-DSCE_DEFENSIVE_OWNERSHIP=1` release-mode opt-in. callback enter/exit
  시 slot-state shadow 비교 + use-after-callback-return trap. ≈10 cycles
  per callback + uint8_t/slot 비용. Layer 표 5행 (1, 2, 3, 3.5, 4) 으로
  확장. 안전 critical / 서드파티 콜백 호스팅 / adversarial 환경 권장.

- **(#6 QEMU F3 한계)** ARCHITECTURE §11.6 fuzz 매트릭스를 4-tier 5-column
  (Tier / Env / catches / **MISSES** / Cost) 로 재구성. F3 가 미에뮬하는
  것 명시 (D-Cache / MPU / DMA+ISR timing / peripheral / vendor libc).
  F4 를 *"recommended Phase D"* → *"strongly recommended for production,
  **mandatory for safety-critical**"* 로 격상. F4 내부에 HIL 또는 Renode
  옵션 양립. F4 crash 가 F3 에 재현 안 되는 경우 `memory-subsystem-specific`
  태그. production deployment guidance 명시.

- **(#7 Parametric 지연 → 중복 코드)** ARCHITECTURE §13 에 7번 항목 추가.
  Phase A/B 임시 meta-generator workflow: `tools/meta/vle.scxml.j2` 템플릿
  + `tools/meta/expand.py` Python 드라이버 + 생성된 `vle_*.scxml` 은
  gitignore. 각 emitted SCXML 에 `META-GENERATED` 헤더 + template-hash +
  source-hash; `tools/meta/verify.py` 가 CI 에서 sce-codegen 전에 실행.
  RFC §5.H/§5.G 가 land 하면 meta-generator 는 retire (clean delete).

## 이번 세션(2026-04-25 후속 review #8 반영) 완료 작업

리뷰 피드백 5항목 중 3건 보강 + 2건 trade-off 메모. 사용자 직접 결정:
- #3 (domain_plugin) drop — SCE Mesh 에 `mesh/transport/zenoh.rs` (179줄)
  이미 존재하여 정치 논리 약함 + deploy.yaml 추가 필드는 실제로
  embedded-networking-generic. §5.K 에 자기방어 메모만 추가.
- #5 (meta-generator) keep — 사용자 #7 결정 유지, retreat 안 함.
  §13 에 trade-off 메모만 추가.

- **(#1 RX 캐시 양단 maintenance)** RFC §5.E + §5.K
  - lifecycle FSM transition 표에 `free → dma-armed-rx
    [+cache_invalidate if maintain && has_speculative_prefetch]` edge 추가.
  - "Cache maintenance pinning" 단락에 양단 정책 prose 신규
    (ARM CMSIS / App Note 321 근거, STM32H7 packet corruption 사례,
    `has_speculative_prefetch` 게이팅 이유).
  - §5.K platform 에 `has_speculative_prefetch` 필드 신규 (M7+/A=true,
    M0/M0+/M3/M4=false default, has_dcache:true 인데 미선언 시 빌드 에러).
  - 진단 2종 (`pool/cache-pre-arm-invalidate-missing-on-speculative-core`,
    `pool/speculative-prefetch-flag-missing`).

- **(#2 GCC Layer 1 무력화)** RFC §5.E API contract
  - "GCC ecosystem fallback" 단락 신규. CMakeLists.txt 가 자동으로
    Clang-Tidy 병렬 검증 stage emit (`CXX_CLANG_TIDY` + warnings-as-errors).
    GCC 빌드는 Clang-Tidy 가 typestate annotation 을 side-channel 로
    분석. 빌드 컴파일러는 GCC 유지.
  - Layer 3.5 default 를 GCC 빌드에선 default-on, Clang 빌드에선
    default-off 로 설정. toolchain × static / runtime / cost 매트릭스
    표 신규 (Clang ≥ 9 / GCC + Clang-Tidy / GCC alone / 상용 분석기).
  - 진단 1종 (`pool/clang-tidy-not-configured`).

- **(#4 UDP spoofing → reassembly DoS)** RFC §5.M
  - "Trust class requirement (UDP spoofing hardening)" 단락 신규.
    `trust_class: untrusted | session_arming | established_session` enum,
    reassembly pool 바인딩은 `established_session` 만 허용 (untrusted /
    session_arming 은 하드 에러). per-peer-quota 의 "peer" 가
    Zenoh ZID (handshake-derived, 16-byte) 임을 명시 — wire source
    address (spoofable) 가 아님.
  - 트러스트 클래스 × 허용 트래픽 × reassembly 바인딩 매트릭스 표.
  - 직전 placeholder 진단 `reassembly/per-peer-quota-missing-on-untrusted-link`
    을 제거하고 hard error 진단 3종으로 격상 +
    (`reassembly/untrusted-link-binding`,
    `reassembly/trust-class-missing-on-fragmenting-link`,
    `reassembly/peer-id-not-zid-on-established-session`).

- **(#3 SCE 도메인 오염 — drop, 메모만)** RFC §5.K
  - "Schema-genericness policy" 단락 신규. 이번 RFC 가 추가한 모든
    deploy.yaml 필드가 embedded-networking / 하드웨어 generic 임을
    명시 — zenoh-specific 지식은 sources/ SCXML 에만.
  - Mesh 의 zenoh transport 선례 (`mesh/transport/zenoh.rs` 179줄,
    zenoh::Session 통합) 를 자기방어 근거로 명기. "SCE 가 zenoh
    transport integration 을 이미 받아들였으므로 generic deploy
    schema 추가는 strictly 더 약한 의존" 이라는 정치 논리.

- **(#5 Meta-generator — keep, 메모만)** ARCHITECTURE §13 #7
  - "Trade-off considered" sub-paragraph 추가. 하드코딩 + §11.1
    test-vector parity 대안의 장점 (낮은 setup) 과 한계 (semantic
    drift 만 잡고 stylistic 은 못 잡음) 명기. 6~12개월 사용 기간 동안
    수동 동기화 위험 vs meta-generator 의 self-contained retire 비교.
    채택 이유 명시.

## 이번 세션(2026-04-25 후속 review #9 반영) 완료 작업

리뷰 피드백 6항목 중 1건만 실 액션 (5건은 이미 처리되었거나 오독으로 판정).
유일한 유효 지적: **session_arming DoS 갭** — RFC §5.M:1936 "rate-limited
by the session FSM" 단언이 구체 메커니즘 없이 단언만 되어 있던 문제.

- **`docs/session-fsm.md` §2.2 / §2.5 / [Trust-class interaction](session-fsm.md#26-trust-class-interaction-cross-ref-to-5m) / [Accept-side hardening detail](session-fsm.md#27-accept-side-hardening-detail) / §8.1 / §12 갱신**
  - §2.2 Cookie handling 단락 다음에 "Half-open accept hardening
    (anti-flood)" 단락 신규 — 3 caps 도입.
  - §2.2 inbound transition 다이어그램에 `Init → Accepting.*` 가드
    표현 (`half_open_cap_available`, `accept_rate_token_available`,
    `cookie_valid`) 명시화. `stateless_accept` 모드의 deferred
    state allocation 흐름 별도 단락.
  - §2.5 timer 표 4 행 신규 (`accept_rate_window`,
    `accepting_inactivity_timeout`, `cookie_hmac_lifetime`,
    `cookie_hmac_key_rotation`).
  - **[Trust-class interaction](session-fsm.md#26-trust-class-interaction-cross-ref-to-5m) 신규** trust-class × hardening-required 매트릭스. `untrusted
    _source: true` 시 `stateless_accept` 강제 명시.
  - **[Accept-side hardening detail](session-fsm.md#27-accept-side-hardening-detail) 신규** (a) half-open capacity / (b) per-source token bucket
    (table capacity 포함, saturated 시 degraded mode 명시) /
    (c) `stateless_accept: cookie_hmac_sha256` (HMAC-SHA-256 / 32-byte
    cookie / 2-key rotation window / silent-drop 정책 명시 — DoS
    reflector 방지). HMAC kind 권장 위치 (`sources/algorithm/
    hmac_sha256.scxml`) 와 WCET 처리 명시.
  - §8.1 G-SFM-5 신규 — 스테이트리스 액셉트 primitive (HMAC + RNG)
    소유권 (intrinsics whitelist vs target plugin vs algorithm-only).
  - §12 change log review #9 항목.

- **`docs/rfc-sce-protocol-synthesis.md` §5.K / §5.M 갱신**
  - §5.K `links.<name>` 블록에 7개 신규 필드:
    `domain_attrs.untrusted_source`, `session_arming_quota`,
    `accept_rate_per_sec`, `accept_rate_burst`,
    `accept_rate_table_capacity`, `accepting_inactivity_timeout_ms`,
    `stateless_accept` 서브블록 (mode / cookie_lifetime_ms /
    key_rotation_s / hmac_extern / rng_extern).
  - §5.K 빌드 진단 8종 신규: `deploy/session-arming-quota-missing`,
    `deploy/accept-rate-config-missing`,
    `deploy/session-arming-fields-on-non-arming-link`,
    `deploy/session-arming-quota-vs-peer-table-invariant-violated`,
    `deploy/stateless-accept-required-on-untrusted-source`,
    `deploy/stateless-accept-extern-not-whitelisted`,
    `deploy/stateless-accept-key-rotation-shorter-than-lifetime`,
    + 런타임 4종 (`session/half-open-cap-exceeded`,
    `session/accept-rate-exceeded`,
    `session/accept-rate-table-saturated`,
    `session/cookie-rejected`).
  - §5.M:1934-1940 "rate-limited by the session FSM" 단언 교체 —
    3 caps (half-open cap / per-source rate / stateless accept) 명시
    cross-ref + 빌드 게이트가 없으면 `deploy/session-arming-quota-
    missing` / `deploy/accept-rate-config-missing` 로 build refusal,
    즉 텍스트 약속이 아닌 **mechanically backed assertion** 임을 명기.

- **`docs/rfc-open-questions-log.md` 갱신**
  - id-space 헤더 `OQ-W14` → `OQ-W15`.
  - **OQ-W15 신규** — (a) HMAC + RNG primitive 위치 결정 (intrinsics
    whitelist vs target plugin vs algorithm-only), 옵션 2(HMAC) +
    옵션 1(RNG) 제안. (b) MCU/AP 기본값 매트릭스 (8/4/8/30000/3600
    vs 32/16/32/30000/3600) — 정상 reconnect storm × spoofed flood ×
    HMAC WCET headroom 3 시나리오 검증 후 확정. Phase A 일부 차단
    (public listener bearing MCU).
  - change log review #9 항목.

## 이번 세션(2026-04-25 후속 review #10 반영) 완료 작업

리뷰 피드백 1항목 보강 (직전 라운드에서 사용자가 #10 개선판을 별도로 도출,
6항목 중 1·2·3위만 신규 액션 — 그중 1위만 이번 세션 처리).

- **(#1 Generated-source traceability)** RFC 신규 §5.O + 4개 파일 갱신.
  - **`docs/rfc-sce-protocol-synthesis.md` §5.O 신설** (§5.N 다음, §6 직전).
    3-layer 제안: (a) C `#line` 디렉티브 (DWARF 직접 사용), (b) Rust
    `#[doc = "SCE-MAP: ..."]` 어트리뷰트 + fallback `//` 코멘트
    (release 빌드 생존), (c) `out/{ap,mcu}/sce_sourcemap.json` 구조화
    매핑 (symbol → scxml_file/state_path/xpath/line_range/wcet_us).
    표준 심볼명 `<machine>__<state_path>__<artifact>` (예:
    `session_unicast__Opening__on_init_ack`). 신규 도구 `addr2sce`
    (PC/symbol/coredump/Rust panic → SCXML 위치). 진단 6종
    (`traceability/state-id-collision`,
    `traceability/symbol-name-exceeds-c-identifier-limit`,
    `traceability/sourcemap-source-hash-mismatch`,
    `traceability/scxml-line-range-missing`,
    `traceability/sce-map-attribute-stripped`,
    `traceability/meta-generated-source-line-marker-missing`).
    §5.A WCET / §5.B test-vector / §5.E pool ownership / [Adversarial fuzz harness](rfc-sce-protocol-synthesis.md#625-adversarial-fuzz-harness) fuzz /
    [Generated source drift detection](rfc-sce-protocol-synthesis.md#626-generated-source-drift-detection) drift 와 cross-ref.
  - **`ARCHITECTURE.md` §11.5 갱신** — drift 검증 artifact 집합에
    `sce_sourcemap.json` 명시 추가; sourcemap source_hash 가 코드 헤더와
    일치해야 `sce-build verify` 통과한다는 invariant 명시.
  - **`ARCHITECTURE.md` §13 #7 (meta-generator) 갱신** — 생성 SCXML 의
    각 state/transition 에 `<sce:source-line file="..." line="..."/>`
    마커 emit 의무 추가; `tools/meta/verify.py` 가 마커 존재 확인;
    진단 `traceability/meta-generated-source-line-marker-missing`
    cross-ref.
  - **`docs/rfc-open-questions-log.md` 갱신** — OQ-W16 신설.
    (a) state-path delimiter (`_` / `__` / `__s_` 3옵션, `__` + `_u_`
    escape 제안), (b) Rust SCE-MAP 보존 메커니즘 (`#[doc]` /
    proc-macro / 코멘트, `#[doc]` 제안 + fallback 코멘트 병행). Phase
    A5 acceptance gate (CRC16 byte-equiv 테스트 + addr2sce resolution
    check) 차단 항목으로 명시. id-space 헤더 `OQ-W15` → `OQ-W16`,
    change log review #10 항목.

리뷰 #10 의 #2위 (lwIP ↔ pool slot FSM 매핑) 와 #3위 (OQ-W13 WCET
디폴트) 는 다음 세션 후보로 이월 — 둘 다 Runtime crate API 스텁
설계 / `deploy/` 스켈레톤 작성과 자연스럽게 묶임 (아래 후보 1·2 참고).

## 이번 세션(2026-04-25 후속 review #11 반영) 완료 작업

리뷰 피드백 1항목 보강 — F4 fuzz 커버리지 피드백 메커니즘 미정. ARCHITECTURE
§11.6 매트릭스가 *"on-device coverage feedback"* 만 명기하고 엔진 / transport /
corpus pipeline 이 비어 있어, F4 가 실제로 어떻게 libFuzzer/cargo fuzz
인프라에 꽂히는지 결정 공간이 열려 있던 문제.

- **`ARCHITECTURE.md` §11.6 신규 단락 "F4 coverage feedback architecture"**
  - 두 가지 구조 결정 명시:
    - (1) coverage signal 출처 = 컴파일러 instrumentation
      (`-fsanitize-coverage=trace-pc-guard` / `inline-8bit-counters`).
      ETM / SWO branch trace decode 는 edge-ID 공간이 호환되지 않아 gate
      신호로는 거부, post-hoc evidence 만 허용.
    - (2) fuzzer 엔진 = Centipede (out-of-process executor) over
      libFuzzer-native (in-process). F2/F3/F4 가 단일 mutator/corpus/
      minimization 파이프라인을 공유. F1 (AP `cargo fuzz`) 은 libFuzzer
      유지하되 corpus 경계에서 어댑팅.
  - On-target coverage agent 명시 — fuzz 빌드 (`BUILD_FUZZ_HARNESS` /
    `[features] fuzz`) 한정, `__sancov_*` 영역을 `.fuzz_cov` 섹션에 배치,
    iteration reset hook, §11.4 Layer 4 deny-list 는 fuzz 빌드에서도
    armed 유지.
  - Transport 계약 — `deliver_input(&[u8])` + `read_coverage_bitmap(&mut [u8])`
    두 primitive, 플러그인이 iteration timeout / bitmap size / counter
    region symbol pair 도 제공.
  - Renode vs HIL 책임 분할:
    - Renode = 결정론적 시뮬 클럭으로 cache/MPU 정확성 + FSM-timing
      퍼징 (RxDispatch / LeaseMonitor / TxSchedule 전이 레이스).
    - HIL = real DMA + ISR + 벤더 libc + peripheral state corruption.
  - Throughput-aware corpus pipeline:
    `F1 (10⁹ execs/nightly) → cmin → distilled seed (10⁴) →
     F4-Renode (10⁷ execs/weekly) → F4-HIL (10⁵ execs/weekly)`.
    F4 는 corpus 성장이 아닌 F1 distilled corpus consumption + F4-only
    엣지 발견 책임. 코퍼지 맵은 tier 간 비호환이지만 byte-sequence
    corpus 는 호환 (§11.1 invariant).
  - CI gates 2종 추가: F4 transport 도달 불가 → fail, F4 instrumentation
    부재 (no `__sancov_guards`) → fail.

- **`docs/rfc-sce-protocol-synthesis.md` §5.I 신규 단락
  "Fuzz coverage transport (Phase D+)"**
  - target_plugin `fuzz_coverage_transport` 블록 신규 — `kind` /
    `bitmap_section` / `bitmap_max_bytes` / `iteration_timeout_us` +
    transport-specific 필드. STM32H7 SEGGER RTT worked example.
  - 5종 canonical transport 매트릭스: `renode_sysbus` (Phase D, native
    memory) / `segger_rtt` (J-Link, ~MB/s) / `openocd_memmap` (vendor-
    neutral, ~50–200 execs/s) / `dma_uart` (Phase D+) / `semihosting`
    (fallback).
  - 진단 5종 신규: `fuzz/coverage-transport-on-pre-D-tier`,
    `fuzz/coverage-transport-not-declared-on-f4-target`,
    `fuzz/coverage-instrumentation-mismatch-across-tiers`,
    `fuzz/coverage-bitmap-section-symbol-missing`,
    `fuzz/coverage-transport-kind-unsupported-by-plugin`.
  - 플러그인 확장 가능성 (계약은 두 primitive + bitmap section
    convention) 명기. ARCHITECTURE §11.6 Renode/HIL 분할에서 transport
    선택이 *executor* 만 바꾸고 분할 자체는 안 바꾼다고 cross-ref.

- **`docs/rfc-open-questions-log.md` 갱신**
  - id-space 헤더 `OQ-W16` → `OQ-W17`.
  - **OQ-W17 신규** — (a) 엔진 일관성: 4 tier 전부 Centipede 통일 vs
    F1 만 libFuzzer 유지 (제안: 후자, AP `cargo fuzz` 유지).
    (b) 기본 transport: 무기본 vs `renode_sysbus` 통일 vs MCU 클래스별
    (제안: `renode_sysbus` 통일, Phase D 진입은 Renode 가 first-mover).
    Phase D 진입 차단 + [Adversarial fuzz harness](rfc-sce-protocol-synthesis.md#625-adversarial-fuzz-harness) codegen contract freeze 부분 차단 명시.
  - **OQ-W13 갱신** — `Bundling` 라인 추가, OQ-W17 과 동시 해소
    (`deploy/mcu_target.yaml` 스켈레톤 단일 커밋에서 둘 다 결정).
  - change log review #11 항목.

이로써 §11.6 의 "on-device coverage feedback" 약속이 mechanically backed
계약으로 격상됨. ETM 디코드 vs 컴파일러 instrumentation 의 corpus-portability
trade-off, Renode 가 F4 first-mover 인 이유 (vendor-neutral 전체 MMU/cache
시뮬), HIL 의 throughput 한계 때문에 corpus 성장은 F1 책임이라는 분업이
모두 §11.6 본문에 박힘.

## 이번 세션(2026-04-25 후속 review #12 반영) 완료 작업

리뷰 피드백 3항목 보강 — VLE/codec-level WCET aggregation 갭, inter-pool
padding 명시화, stage-copy strict 정책. 1번은 리뷰어가 짚은 VLE 자체보다
더 큰 문제 (codec aggregate)로 확장 채택, 2번은 묵시적 해결분 명시화 +
set-associativity vs line-level conflation 분리, 3번은 가장 깨끗한 추가.

- **`docs/rfc-sce-protocol-synthesis.md` §5.B "Codec aggregate WCET" 신규 단락**
  - 문제 제기: 한 프레임 = 다수 codec 필드 디코드 + 그 안의 algorithm
    호출 그래프. 적대적 peer 가 모든 가변 필드를 max 로 채우면 per-field
    WCET 가 곱셈으로 누적 → keepalive jitter (panic 아닌 sub-symptom).
    §11.6 fuzz "slow input >1ms" gate 는 F1 한정 + sub-1ms 케이스 못 잡음.
  - Per-field WCET 모델 표 (7행): fixed (상수) / `vle_uK`
    (`ceil(K/7) × cycles_per_byte / clock_freq_mhz`) / `len-prefix`
    (`max-bytes × memcpy_cycles / clock_freq`, parse-mode 별 분기) /
    TLV chain (`max-depth × (tlv_overhead_us + per-entry-body)`) /
    repeat (build-time-known 또는 runtime source max) / algorithm
    invocation (algorithm `<sce:wcet-bound>` × payload size factor) /
    variant (max(arm WCETs)).
  - 신규 IR 어노테이션 `<sce:codec-wcet-bound mode="derived">` —
    빌드가 자동 emit, author 가 `mode="measured"` 로 override 가능
    (§5.A measurement workflow 동일 shape).
  - TLV chain 단독 `max-depth × per-entry` 만으로도 슬롯 못 차지하도록
    별도 invariant + 진단.
  - Author resolution path 4가지 명시 (max-depth/max-bytes 낮춤,
    FSM 슬롯 분할, TX-only 로 이동, measured override).
  - 신규 진단 7종: `codec/wcet-aggregate-exceeds-slot-budget` (하드 에러),
    `codec/wcet-aggregate-undeclared-on-rx-codec` (경고, 단
    `pool.stage_copy_policy: error|forbid` 시 하드 에러로 격상),
    `codec/wcet-aggregate-vle-cycles-missing`,
    `codec/wcet-aggregate-tlv-overhead-missing`,
    `codec/wcet-aggregate-repeat-unbounded`,
    `codec/tlv-chain-aggregate-wcet-exceeds-slot-budget`,
    `codec/wcet-measured-override-stale`.

- **`docs/rfc-sce-protocol-synthesis.md` §5.A "Codec aggregation cross-reference"**
  - 짧은 단락 — algorithm 의 `<sce:wcet-bound>` 가 enclosing codec 의
    aggregate 에 합산됨. `mode="opaque"` algorithm 이 RX-path codec 에
    바인딩되면 §5.A 가 이미 거부했더라도 §5.B 에서 한 번 더 잡힘
    (defense-in-depth).

- **`docs/rfc-sce-protocol-synthesis.md` §5.K platform 필드 2종 신규**
  - `vle_decode_cycles_per_byte` (M0+:12.0 / M3-M4:8.0 / M7:6.0 / A:3.0)
  - `tlv_chain_per_entry_overhead_us` (M0+:1.5 / M3-M4:0.8 / M7:0.5 / A:0.2)
  - 둘 다 codec 에 해당 필드 + cooperative scheduler 시 필수.

- **`docs/rfc-sce-protocol-synthesis.md` §5.E inter-pool padding 명시화**
  - linker fragment 예제에 explicit `. = ALIGN(<line_size>);` sentinel
    추가 (pool_a → sentinel → pool_b → sentinel → desc).
  - "Scope: line-level cross-contamination only" 단락 — sentinel 은
    line-level concern (cache invalidate by VA 가 인접 pool 첫 라인 건드림)
    만 다룸. **Set associativity contention 은 별도 문제 — `cache-policy`
    분리 또는 별도 메모리 뱅크가 답, padding 은 무관**. 리뷰어 conflate
    방지 클래리피케이션.
  - 신규 진단 `mem/inter-pool-padding-not-emitted` (codegen self-check,
    template regression guard).

- **`ARCHITECTURE.md` §3.4 cache coherency bullet 확장**
  - 두 invariant → 세 invariant (3번째 = inter-pool sentinel).
  - "address line-level cross-contamination only, NOT set associativity
    contention" 단락 추가. Set 컨텐션 답은 `cache-policy` 분리 / 메모리
    뱅크 분리 명기.

- **`docs/rfc-sce-protocol-synthesis.md` §5.K `pool_defaults.stage_copy_policy` 신규**
  - `warn | error | forbid` 3-tier:
    - `warn` (현 default) — `reassembly/expected-fragmentation-rate-high`
      경고 + per-link `<sce:accept-stage-copy-rate>` suppress.
    - `error` — 경고 → 하드 에러 (`pool/stage-copy-policy-error`),
      per-link opt-out 은 justification reference 와 함께 여전히 유효.
    - `forbid` — 같은 하드 에러 + opt-out 자체 거부
      (`pool/stage-copy-accept-rejected-under-forbid`). Safety-critical
      (medical / automotive / aerospace) 용.
  - Per-machine 설정 (per-pool 아님) — 정책은 deploy 단위 trust 클래스.
  - 신규 진단 3종: `pool/stage-copy-policy-error`,
    `pool/stage-copy-accept-rejected-under-forbid`,
    `deploy/stage-copy-policy-unknown`.

- **`ARCHITECTURE.md` §9.3 "Stage-copy policy (deploy-wide)" 단락**
  - 3-tier 정책 가이던스: prototype/AP=`warn`, embedded production=`error`,
    safety-critical=`forbid`. 정책은 per-machine 인 이유 명기 (single
    deploy 가 AP=`warn` + MCU=`forbid` 자연 표현 가능).

- **`docs/rfc-sce-protocol-synthesis.md` §5.M stage-copy 경고 단락 확장**
  - 기존 warning 텍스트 끝에 `pool_defaults.stage_copy_policy: error |
    forbid` 로 격상 가능 명기 + 격상된 진단 두 개 cross-ref.

- **`docs/rfc-open-questions-log.md` 갱신**
  - id-space 헤더 `OQ-W17` → `OQ-W19`.
  - **OQ-W18 신규** — (a) `vle_decode_cycles_per_byte` /
    `tlv_chain_per_entry_overhead_us` 플랫폼별 defaults 측정 (M0+/M4/M7
    참조 보드 측정 필요), (b) `sce-bench --measure-vle-coefficients`
    parametric 하네스 위치. Phase A entry 차단 (Zenoh 와이어는 VLE 도배,
    cooperative MCU 빌드 불가).
  - **OQ-W19 신규** — `pool_defaults.stage_copy_policy` 3개 스켈레톤
    별 default. `ap_standalone=warn`, `mcu_target=error`, `ap_mcu_pair`
    = AP/MCU 비대칭 (warn + error). `forbid` 는 downstream opt-in 으로
    유보.
  - **OQ-W13 갱신** — `Bundling` 라인 W17 → W17/W18/W19 4개로 확장.
    `deploy/mcu_target.yaml` 단일 커밋에서 4개 동시 해소.
  - change log review #12 항목 (W18/W19 신규 + W13 bundling 확장).

이로써 codec parse-time 적대적 시나리오 (max-depth TLV + max-byte VLE 도배)
가 빌드 타임에 차단됨. §11.6 fuzz 의 "slow input >1ms" 런타임 gate 와는
별개로, **모든 RX-path codec 이 정적 WCET aggregate 를 갖고 worker_slot_budget_us
와 비교**되어 keepalive jitter 시나리오 자체가 ship 못 함. Stage-copy
는 prototype 외 모든 deploy 에서 explicit 하게 허용/거부 가능.

## 이번 세션(2026-04-25 후속 review #13 반영) 완료 작업

**프로젝트 우선순위 재확인 + OS-axis 도입 (design-only, 구현 작업 아님).**
사용자 명시: *"qnx는 ap에서 지원해야하지만 나중의 일이야. 가장 먼저해야하는건
mcu 제노 피코 완전 대체야. 그이후에 ap 작업을 할꺼야. 대신 설계에는
고려되어야해."*

이 결정의 핵심:
- **MCU zenoh-pico 완전 대체 (Phase A–C, C14 parity gate) = 최우선, 변경 없음.**
- AP 작업은 Phase D 진입 후. Linux 먼저 (D.1), QNX 다음 (D.2).
- QNX 는 deferred non-goal 이 아니라 *design-considered first-class*.
  지금 schema 에 namespace 박아서 Phase D 진입 시 refactor 비용 0.

이 review 의 모든 변경은 **design / schema / namespace** 만 — Phase A–C
구현 부담 0, MCU 작업 일정 영향 0.

- **`docs/rfc-sce-protocol-synthesis.md` §5.K platform.os 필드 신규**
  - enum: `linux | qnx | macos | freebsd | windows | bare_metal | rtos`.
  - Per-OS phase availability 명시 (bare_metal=A+, linux=D+, qnx=D+,
    macos/freebsd/windows=E+).
  - class × os 호환성 invariant: `mcu` ↔ `bare_metal | rtos`,
    `ap` ↔ `linux | qnx | macos | freebsd | windows`.
  - 진단 4종: `deploy/platform-os-missing`,
    `deploy/platform-os-class-mismatch`,
    `deploy/platform-os-not-implemented-in-current-phase`,
    `deploy/runtime-crate-mismatch-with-os`.

- **`docs/rfc-sce-protocol-synthesis.md` §2.2 MVP deferrals 표 확장**
  - 신규 3행: AP on Linux (Phase D.1, 첫 AP target), AP on QNX
    (Phase D.2, 두 번째 AP target), AP on macOS/FreeBSD/Windows
    (Phase E).
  - 각 항목에 phase marker + migration path 명시 — schema 가
    review #13 시점부터 호환.

- **`docs/rfc-sce-protocol-synthesis.md` §3 target end-state 갱신**
  - `out/ap/*.rs` 표현을 OS-parameterized 로 재서술
    (linux→tokio, qnx→qnx, macos→kqueue, ...).
  - "Phase scope today" 단락 추가 — MCU = priority track, AP =
    Phase D 이후, runtime-crate-per-OS dispatch 가 review #13
    부터 schema-stable.

- **`docs/rfc-sce-protocol-synthesis.md` §5.C link-class enum 확장**
  - 미래 namespace 4종 예약: `unix_socket`, `unix_seqpacket`,
    `qnx_msg`, `qnx_shm`. Phase 마커 (D.1+ / D.1+ / D.2+ / D.2+).
  - 진단 2종: `link/link-class-deferred-to-phase` (전 phase 에서
    예약된 class 사용 시도), `link/link-class-incompatible-with-os`
    (예: `qnx_msg` + `os: linux`).
  - 현재 활성 class 표 갱신 — udp/tcp/serial/websocket/raw_eth 의
    OS 별 phase availability 명기.

- **`docs/rfc-sce-protocol-synthesis.md` §5.J 5.J.3 신규 단락
  "Backend coverage as a 3-tuple"**
  - 백엔드 = `(language, target_os, runtime_crate)` 3-tuple 로 재정의.
  - `sce_link_runtime_<os>` 명명 규약 형식화 (lwip/tokio/qnx/kqueue/
    iocp/<rtos_id>).
  - OS-axis 매트릭스 표 + phase 매핑.
  - 명령: deploy.yaml 에서 `runtime_crate:` override 가능하지만
    기본은 `platform.os` 가 자동 결정. 진단 2종 신규.

- **`docs/rfc-sce-protocol-synthesis.md` §7 Phase rollout 정밀화**
  - Phase D 를 D.1 (AP Linux baseline, blocks D.2) / D.2 (AP QNX
    baseline) / D.3 (migration enablers) 3 sub-phase 로 분할.
  - D.1 항목 5개 (sce_link_runtime_tokio / AP code emission /
    io_uring opt-in / unix sockets / linux interop test).
  - D.2 항목 4개 (sce_link_runtime_qnx / qnx_msg/qnx_shm
    phase-gate / realtime scheduler / qnx interop test).
  - D.3 = 기존 D 의 migration enablers (parametric / recursive /
    aggregation / shim / target plugins).
  - Phase E 신규 (macOS/FreeBSD/Windows/RTOS 추가 AP targets).
  - **MCU-first invariant 단락 신규** — Phase A–C C14 parity gate
    가 priority track, OS axis 는 design-only during Phase A–C
    임을 §7 본문에 명시.

- **`ARCHITECTURE.md` §9.5 신규 단락 "Platform-aware link substrate
  (design philosophy)"**
  - 5행 매트릭스 — MCU bare_metal (A–C, current) / AP linux+epoll
    (D.1) / AP linux+io_uring fixed buffers (D.1 opt-in) / AP qnx
    +io-sock (D.2) / AP qnx+qnx_shm (D.2+).
  - 같은 §5.E lifecycle FSM 의 OS-native 인스턴스, edge actions 만
    OS-specific.
  - 사용자의 5-section "Platform-Aware High-Performance Networking"
    framing 흡수 — io_uring 이득 ≅ MCU DMA 이득의 구조적 isomorphism
    명시.
  - "Phase A–C 동안에도 의미 있다" 단락 — 작성 중인 SCXML 이
    implicit portable substrate code 임. Phase D 에서 unchanged
    실행. 단 namespace 만 reserve 된 row 들은 build refusal.

- **`docs/rfc-open-questions-log.md` OQ-W20 신규**
  - id-space 헤더 `OQ-W19` → `OQ-W20`.
  - 질문: `sce_link_runtime_qnx` reactor — (1) mio QNX 백엔드
    포팅, (2) 별도 QNX-native runtime, (3) hybrid.
  - 초기 제안: 옵션 2 (QNX dispatch + io-sock 직접). 근거: QNX
    가치는 RT + adaptive partitioning, mio 추상화는 그걸 못 노출.
    Link trait 표면이 작아 (~1.5K LOC) 재구현 비용 bounded.
  - **Phase D.2 진입 차단, Phase A–C 무관** 명시.
  - Bundling 노트: OQ-W13/W17/W18/W19 (deploy-defaults bundle) 와
    독립이지만, *지금* 옵션 2 를 가정하면 `sce_link_runtime_*`
    trait 표면을 작게 유지하는 design 압박이 정당화됨.

- **`docs/rfc-open-questions-log.md` change log review #13 항목**

이로써 SCXML 저작자가 Phase A–C 동안 작성하는 모든 codec / link / pool
정의는 **OS-portable by construction**. Phase D.1 진입 시 AP linux
runtime 만 추가하면 같은 SCXML 이 emit. Phase D.2 진입 시 AP qnx
runtime 만 추가하면 같은 SCXML 이 emit. MCU 우선 작업 일정에 영향 0.

## 이번 세션(2026-04-30 후속 review #14 반영) 완료 작업

리뷰 피드백 5건 반영 (verdict: Reject-but-rework-possible). 본 라운드는 사용자
가 받아온 외부 review 의 corrected (정정 5종 적용 후) 권고를 SCE 758aea3f 의
실제 상태와 대조 검증 후 적용. 정정 핵심: "C11 backend 없음" stale claim 은
KICKOFF 측 문제, RFC §5.J.1 본문이 요구하는 *새 kinds × C11 emitter* 작업은
별개로 유효.

- **Phase 0 #1 — RFC §5.J.1 phrasing patch**
  - "There is no C backend in `generator::Language`" 첫 문장 정정. SCE
    `758aea3f` 시점부터 `Language::C11` 변이 + 11 kinds × 6 backends
    매트릭스 클로즈드. RFC 가 요구하는 작업은 *기존 11 kind* 가 아닌
    *RFC 가 추가하는 새 kinds* 의 6-backend emitter 와 statechart
    `no_std` runtime 임을 본문에서 명시 분리. §5.J 본문 + "Generator
    dispatch" 단락 동기화.

- **Phase 1 — Generic-class kinds 6-backend commitment** (RFC §5.J.4 / §5.J.5
  + §5.A / §5.B / §5.F / §5.L / §5.O codegen contract 갱신)
  - **§5.J.4 신규** "Kind × language matrix (parity invariant)" — 새
    kinds 를 *generic-class* (모든 6 backend 필수) vs *MCU-class*
    (`(rust|c11) × (bare_metal|linux|qnx)` 만 활성, 다른 언어 백엔드는
    hard error) 로 명시 분리. 758aea3f 매트릭스 회귀 차단.
  - **§5.J.5 신규** "Per-language emitter contracts (new generic-class
    kinds)" — §5.A / §5.B / §5.F / §5.L / §5.O 의 Rust/Cpp/Kotlin/Go/
    Python/C11 별 emitter shape 표. 6 backend 각각의 함수 signature,
    storage 타입, traceability marker 형식 명시.
  - **§5.A codegen contract** Rust+C 한정 텍스트를 6 backend 공통
    invariant + per-language 차이 prose 로 확장.
  - **§5.B codegen contract** 6 backend 별 cursor / error / NeedMoreBytes
    shape 명시. MCU-only 서브피처(`dma-burst-align`, codec-aggregate
    WCET gate) 는 `(rust, *) + (c11, bare_metal)` 한정 + hard error.
  - **§5.F execution model** 단락에 6 backend 별 const 배열 emit shape
    추가 (`pub static` / `inline constexpr std::array` / Kotlin top-level
    `val` / Go `[N]T` / Python `tuple` / C11 `static const`). 한 host
    interpreter → 6 backend serialize.
  - **§5.L element type resolution** Rust+C 한정 텍스트를 6 backend
    fixed-capacity container shape 표로 확장.
  - **§5.O proposal (a)** Cpp/Kotlin/Go/Python 의 traceability marker
    추가 (`#line` for Cpp, `// SCE-MAP:` for Kotlin, `//line` for Go,
    `# SCE-MAP:` for Python). 6 backend 의 `sce_sourcemap.json`
    sidecar 가 byte-identical 임을 invariant 로 명시.
  - 신규 진단 2종: `codegen/mcu-class-kind-on-non-mcu-language` (MCU-
    class kind 가 cpp/kotlin/go/python 에 author 시), `codegen/generic-
    kind-backend-emit-missing` (generic-class kind 가 한 backend 에서
    template 누락 시 — SCE 자체 회귀 차단).

- **Phase 2 — MCU-only kinds target-plugin 재분류**
  - §5.C / §5.D / §5.E / §5.M 본문 첫 단락에 "Backend coverage (MCU-
    class kind)" 단락 추가. 각 § 가 `(rust, *) + (c11, bare_metal)` 한정
    임을 명시, cpp/kotlin/go/python 백엔드 author 시도 시 `codegen/
    mcu-class-kind-on-non-mcu-language` 하드 에러로 거부됨을 cross-
    reference. (이 단락들은 §5.J.4 매트릭스의 자연 결과 — 본문에서
    재인용함으로써 author 가 § 진입 시 즉시 알 수 있게 함.)

- **미래 namespace reservation 3건 제거** (`feedback_pre_release_no_compat` /
  `feedback_planned_not_yagni`)
  - **(a) §5.K cookie 정정** — `cookie_hmac_v1` → `cookie_hmac_sha256`
    (false signal 제거, 단일 algorithm variant selector 임을 naming 으로
    표현). `cookie_hmac_v2_blake2s reserved for SoCs without SHA-256
    acceleration` 미사용 enum value 제거 — 실제 필요 시점에 land.
  - **(b) §5.E "Reserved states for hardware accelerators" 단락 제거**
    (lines 1039–1088). 4 crypto state + transition shape 미리 land 하던
    forward-namespace reservation 삭제. "FSM extension policy" 단락으로
    교체 — 미래 bus master 의 state 는 land 시점에 추가, 미리 declare
    하지 않음. §2.4 invariant 3 ("kinds are additive") 의 *additive*
    의미가 "added when wired" 임을 못박음.
  - **(c) §5.C link-class enum 의 `unix_socket` / `unix_seqpacket` /
    `qnx_msg` / `qnx_shm` namespace reservation 제거**. enum 4행 +
    "four future namespace reservations" 단락 + `link/link-class-
    deferred-to-phase` 진단 모두 삭제. 새 단락으로 교체 — OS-specific
    classes 는 해당 phase 진입 시 추가 enum 행 + driver + 진단 같은
    patch 에서 land. `link/link-class-unknown` (기존 unknown-value
    diagnostic) 으로 reject. §5.J.3 runtime crate bullet 의 `qnx_msg/
    qnx_shm` 언급 + §7 D.1.4/D.2.2 phase rollout 텍스트 + §2.2 MVP
    deferrals 표 의 "AP on QNX" / "AP on macOS/FreeBSD/Windows" 행도
    동기화.
  - 같은 rename 을 `docs/session-fsm.md` (6 occurrences) +
    `docs/rfc-open-questions-log.md` (2) + `docs/SESSION_KICKOFF.md` (1)
    에 일관 적용.

- **GCC Layer 1 silently inert 해소** (RFC §5.E API contract C 섹션,
  `feedback_silently_broken_hooks`)
  - "GCC ecosystem fallback" 단락을 "GCC ecosystem fallback (Clang-Tidy
    mandatory + auto-on Layer 3.5)" 로 격상. CMakeLists.txt 의
    `find_program(CLANG_TIDY_EXE clang-tidy REQUIRED)` 가 configure
    time 에 fail 한다는 점 명시. **GCC alone 은 accepted release
    configuration 이 아님** 을 못박음 — 진단 `pool/clang-tidy-not-
    configured` 를 warning → **hard error at configure time** 으로
    격상. 우회로 한 가지: `build.static_analyzer: pc_lint | coverity |
    polyspace` 명시 선언 (Layer 2 substitute) 시 hard error 우회 허용.
  - "Layer trade-off summary" 마지막 행 ("Authors are encouraged to
    ship release builds with...") 을 건의문에서 명시 거부 정책으로
    재작성. 권장 posture 표 의 "GCC, no Clang-Tidy" 행을 "**not
    accepted**" 로 라벨, hard error 발생 위치 명시.
  - 진단 정의 자체 (`pool/clang-tidy-not-configured`) 본문도 warning
    텍스트에서 hard error 텍스트로 교체 — Layer 2 substitute 우회로
    명시.

- **`docs/SESSION_KICKOFF.md` line 22 / 86–89 stale 정정**
  - line 22: `enum Language {Rust,Cpp,Kotlin,Go,Python} — C 변이 없음` →
    `enum Language {Rust,Cpp,Kotlin,Go,Python,C11} — 6 backends`.
    line 28 의 `templates/forge/{rust,cpp,kotlin,go,python}/  (5개 언어
    emitter)` → `{rust,cpp,kotlin,go,python,c}/  (6개 언어 emitter; C11은
    758aea3f 시점 클로즈드)`.
  - line 86–89: "Forge 다언어 emitter 5개 모두 존재 ... C11 backend: 없음
    — RFC §5.J.1 신규 요청" → "6개 모두 존재 ... `758aea3f` 커밋에서
    11 kinds × 6 backends 매트릭스 클로즈드. RFC §5.J.1 요구는 *기존 11
    kind × C11* 이 아니라 *RFC 가 추가하는 새 kind × C11*; §5.J.4
    매트릭스 참조".

- **`docs/rfc-open-questions-log.md` change log review #14 항목**
  - 새 OQ 없음 (review #14 는 corrections / namespace removals / parity
    commitment — 새 미해결 질문을 만들지 않음).
  - 본 라운드의 모든 변경이 **parity 회복 + namespace reservation 제거 +
    silently broken hook 해소** 셋으로 분류됨을 명기.

이로써 다음이 보장됨: (1) 758aea3f 매트릭스 회귀 없음 — generic-class
kinds 6 backend wire 약속이 §5.J.4/§5.J.5 표로 mechanically backed.
(2) MCU-class kinds 의 비대칭이 silently broken 이 아니라 명시적 hard
error — `codegen/mcu-class-kind-on-non-mcu-language`. (3) Pre-release
forward-namespace 0 — `cookie_hmac_v2`, hardware crypto reserved
states, OS-specific link-classes 모두 land 시점에 추가. (4) GCC alone
release config 거부 — `pool/clang-tidy-not-configured` hard error +
Layer 2 substitute 명시 우회로.

## 이번 세션(2026-05-01) 완료 작업 — `deploy/` 스켈레톤 3종

KICKOFF "다음 세션 후보 작업" 의 우선순위 #1 항목 처리. OQ-W6/W8/W12/W13/
W17(b)/W19 의 6 항목을 한 커밋에서 해소 + W18 의 estimate-quality 기본값
committed (empirical measurement 만 외부 의존으로 잔존).

- **`deploy/mcu_target.yaml` 신규** — STM32H747I-DISCO M7 베이스라인.
  RFC §5.K 전체 필드 채움 (platform / scheduler / memory / links /
  session / qos / scouting / limits / pool_defaults / buffer_pools /
  extern_symbols). 4 link 정의 (udp_scout / udp_session 활성, tcp_session
  / serial_console disabled-by-default). Buffer pool 4종 (scout_rx /
  session_rx / session_tx / reassembly), 모두 cache-line × DMA 정렬
  invariant 준수. `serial_console` 의 `closing_timeout_ms: 250` 으로
  OQ-W12 의 Serial @ 115200 baud 엣지 케이스 대응 (per-link override
  pattern 확립).

- **`deploy/ap_standalone.yaml` 신규** — x86_64 Linux + tokio 베이스라인.
  Phase D.1 진입 전까지 `deploy/platform-os-not-implemented-in-current-
  phase` 로 build-refused 되지만 schema 는 review #13 시점부터 stable.
  `scheduler.kind: tokio` 이므로 `worker_slot_budget_us` /
  `keepalive_jitter_budget_us` 미선언 (preemptive scheduler 는 게이트
  안 함). `stage_copy_policy: warn` (OQ-W19 AP). Limits 는 MCU 의 16배
  (peer_table 256, local_subscriptions 256, in_flight_reassembly 32).
  Buffer pool 의 `section: heap` 은 AP-specific marker — `bytes::BytesMut`
  arena 사용을 의미.

- **`deploy/ap_mcu_pair.yaml` 신규** — 단일 deploy.yaml 안에 mcu_node +
  ap_node 두 machine. 각 machine 의 fields 는 single-machine skeletons
  와 verbatim 일치. **canonical asymmetric pattern**: AP `pool_defaults.
  stage_copy_policy: warn` + MCU `error` 가 같은 deploy.yaml 안에서
  per-machine 으로 자연 표현 (OQ-W19 hybrid). 같은 SCXML sources 가
  두 machine 모두에 emit, deploy.yaml 의 capacity 만 다름 (§2.4
  invariant 1 "static-first" 의 deploy-side parameterization).

- **OQ-W6/W8/W12/W13/W17(b)/W18/W19 closure** — `docs/rfc-open-questions-
  log.md` 의 7개 항목 status downgrade. W6/W8/W12/W13/W19 는 `answered`,
  W17 은 `partially answered` (b 만 closed; a 는 SCE sync 대기), W18
  은 `initial-proposal committed` + measurement pending. Change log
  entry "2026-05-01" 추가 — 7 OQ-W resolution + bundle 닫힘 + 외부
  의존 단 1건 (W18 측정) 명기.

이로써 `deploy/` 스켈레톤이 RFC §5.K 의 모든 필드 + OQ 7건의 ratified
defaults 를 수용함. SCE Phase A 진입 (RFC §5.J.1 새 kinds × C11 emitter)
가 완료되면 이 deploy.yaml + sources/SCXML 만 있으면 빌드 가능. AP linux
는 Phase D.1 entry 까지는 schema-stable artifact 로 남음.

남은 외부 의존: OQ-W18 의 M0+/M3-M4/M7 reference board 측정 (HIL 가용 시).
M7 의 6.0 cycles/byte / 0.5 µs/entry 추정값으로 codec aggregate WCET
는 build 가능하지만 `algorithm/wcet-measurement-class-untrusted-without-
margin` warning 동반.

## 이번 세션(2026-05-01 후속) 완료 작업 — `docs/reassembly-fsm.md`

KICKOFF "다음 세션 후보 작업" #4 항목 처리. RFC §5.M 의 3-state sketch
(`Idle/Assembling/Complete`) 를 four-state slot FSM (`Empty/Receiving/
Complete/Aborted` + `TimedOut` 별도 terminal) 로 확장 + Router + N parallel
slot regions hierarchy 명시. ≈530 줄, `session-fsm.md` 패턴 mirror.

- **`docs/reassembly-fsm.md` 신규** — §1 framing overview / §2 Reassembly
  FSM (states/transitions/Router) / §3 TX fragmentation / §4 timer/quota
  config (deploy.yaml cross-ref) / §5 trust-class interaction / §6
  buffer-pool lifecycle FSM cross-ref / §7 build-time analysis (4
  invariants 구체 적용) / §8 design gaps + 신규 OQ / §9 RFC feedback /
  §10 next-step / §11 self-review / §12 change log.

- **3 design gaps 발견** — 가장 큰 가치는 prose 가 *실제로 stress-test*
  역할을 했다는 것:
  - **G-RFM-1** (out-of-order Continue policy): RFC §5.M 의 sketch 가
    BEST_EFFORT 의 reordering 처리 미정. proposed reliability-conditional
    (RELIABLE → reject; BEST_EFFORT → bitmap-based tolerate). → **OQ-W21** 신규.
  - **G-RFM-2** (listener-link trust class lifecycle): listener link 의
    `trust_class: session_arming` 과 post-handshake `established_session`
    traffic 의 충돌. proposed option 3 (codegen split into accepting +
    established link instances at handshake completion). → **OQ-W22** 신규.
  - **G-RFM-3** (deploy capacity invariant violation): `slot_size <
    max_fragments × mtu_bytes` 가 3 deploy 모두에서 깨짐. **즉시 수정.**

- **Deploy 3 file 보정** — `qos.max_fragment_count` 와 `buffer_pools.
  reassembly_pool.max_fragments_per_message` 를 같이 수정:
  - MCU (mcu_target.yaml + ap_mcu_pair.yaml mcu_node): 16 → **2**
    (4096 ≥ 2 × 1472 = 2944 ✓). MCU IoT 메시지 사이즈 typical < 3 KB.
  - AP (ap_standalone.yaml + ap_mcu_pair.yaml ap_node): 256 → **44**
    (65536 ≥ 44 × 1472 = 64768 ✓). AP 의 64 KB 메시지 capacity 보존.

- **RFC §5.M 진단 6종 추가** (`reassembly/aborted` 가 7개 reason
  code 를 단일 diagnostic 의 `reason=` field 로 캐리) —
  `reassembly/timeout-fired`, `reassembly/aborted` (reason codes:
  `incomplete-final` / `evicted` / `codec-error` / `reliable-out-
  of-order` / `unmatched-key` / `out-of-bounds-index` / `duplicate-
  index`), `reassembly/unmatched-continue`, `reassembly/unmatched-
  final`, `reassembly/slot-pool-full`, `reassembly/message-complete`
  (opt-in observability). 각 진단은 reassembly-fsm.md 의 specific
  transition edge 에서 emit.

- **OQ-log + cross-refs** — `docs/rfc-open-questions-log.md` 에 OQ-W21 +
  OQ-W22 신규 등록 (둘 다 Phase A SCXML authoring 차단; deploy/ 작업은
  무관). id-space 헤더 W20 → W22. change log "2026-05-01 (later)" entry.
  `docs/wire-spec-subset.md` §4.2 Fragment row 에 `docs/reassembly-fsm.md`
  포인터. `docs/session-fsm.md` §2.3 RxDispatch Fragment branch 도 같은
  포인터.

이로써 RFC §5.M 의 design surface 가 prose-verified 되었음 — 3-state
sketch 가 four-state expansion + Router 분리를 mechanically 견디는지
확인됨. Phase A SCXML authoring 진입 차단 항목은 deploy 가 아니라
**OQ-W21 + OQ-W22** 두 question 의 해소 (전자는 zenoh-pico source 검증,
후자는 RFC §5.M 또는 §5.C 패치).

## 이번 세션(2026-05-01 후속 #2) 완료 작업 — OQ-W21 close

KICKOFF 우선순위 #1 (남은 reassembly 진입 차단 항목 중 zenoh-pico
검증으로 해소 가능한 것) 처리. zenoh-pico 1.9.0 HEAD `3b3ab65` 직접
read 로 G-RFM-1 / OQ-W21 의 3 핵심 질문 답.

- **zenoh-pico checkout** `~/zenoh-pico` 신규 (1.9.0 `version.txt`,
  HEAD `3b3ab65cadbb10a8d7f32ba04cb15c26b8435dd5`). Phase A freeze
  pin 은 OQ-W1 미정 — 검증은 main HEAD 로 충분.

- **3 질문 답 (file:line 인용)**:
  - **(a) OOO Continue** → 전체 dbuf drop (chain abort).
    `_z_unicast_handle_fragment_inner` `~/zenoh-pico/src/transport/
    unicast/rx.c:145-273`. SN regression branch lines 166-168/180-182,
    forward-gap (non-consecutive) branch lines 187-191. multicast
    handler 동일 패턴 `~/zenoh-pico/src/transport/multicast/rx.c:
    233-369` (251-287 mirror). `_z_sn_consecutive` 정의 `(sn_right -
    sn_left) == 1 mod resolution` `~/zenoh-pico/src/transport/utils.c:
    85-88`.
  - **(b) RELIABLE vs BEST_EFFORT** → 동일 정책. 두 reliability
    band 가 각자 inline `_z_wbuf_t` 두 개 (`_dbuf_reliable`,
    `_dbuf_best_effort`) 와 두 state byte 를 가짐
    (`~/zenoh-pico/include/zenoh-pico/transport/transport.h:50-68`)
    이지만 OOO 처리 if/else 양쪽이 대칭 (action 동일, buffer
    pointer 만 다름).
  - **(c) state shape** → streaming write-buffer (bitmap 아님),
    peer 당 2 buffer (N parallel 아님), 자체 timeout 없음.
    `_z_wbuf_write_bytes(dbuf, payload.start, 0, payload.len)`
    `unicast/rx.c:222`. 버퍼 크기 `Z_FRAG_MAX_SIZE` 기본 4096
    `~/zenoh-pico/CMakeLists.txt:306`. cleanup 은 (i) next-arrival
    OOO/non-consecutive, (ii) overflow, (iii) Final 완료, (iv) peer
    disconnect (`~/zenoh-pico/src/transport/peer.c:58-59`) 만.
    Wire-level chain key 실제 `(peer, reliability)` 2-tuple —
    `_z_t_msg_fragment_t = {_payload, _sn, first, drop}`
    `~/zenoh-pico/include/zenoh-pico/protocol/definitions/transport.h:
    494-499` (priority/sn_base 없음). Patch markers `FRAGMENT_FIRST`
    (0x02) / `FRAGMENT_DROP` (0x03) `~/zenoh-pico/include/zenoh-pico/
    protocol/ext.h:49-50`, `_Z_PATCH_HAS_FRAGMENT_MARKERS(patch >= 1)`
    `~/zenoh-pico/include/zenoh-pico/protocol/definitions/transport.h:
    102`.

- **결정** — option 2 (strict in-order, identical for both
  reliability classes). watching-zenoh `docs/reassembly-fsm.md` §2.5
  의 reliability-conditional + bitmap 제안은 **MVP 에서 reject** —
  zenoh-pico parity invariant (ARCHITECTURE §2) 위배. Bitmap-based
  BEST_EFFORT tolerance 는 Phase D++ 강화 옵션으로 보류.

- **`docs/reassembly-fsm.md`** 갱신:
  - §2.5 amend — Resolution 블록 추가 (upstream 인용 + amended
    Continue handler streaming-cursor 동작 + `out-of-order` 단일
    reason).
  - §8.1 G-RFM-1 → resolved (OQ-W21 close cross-ref).
  - §8.2 OQ-W21 row → answered + 정책 요약.
  - §12 change log 신규 entry "2026-05-01 (later) — OQ-W21 close".
  - 4 cascading FSM-shape amendments (chain key 4→2-tuple, slot
    count N→2 per peer, no per-chain timeout, `start` →
    `FRAGMENT_FIRST` ext) 는 deferred revision pass 로 §2.5 안에
    별도 항목 명기. **OQ-W21 closure 는 막지 않지만 Phase A SCXML
    authoring 은 막음.**

- **`docs/rfc-open-questions-log.md`** 갱신:
  - OQ-W21 status `open` → `answered`, Resolution 블록 (file:line
    인용 8건), Cascading items 항목 추가.
  - Change log entry "2026-05-01 (OQ-W21 close)" 신규.

- **OQ-W22 잔존** — listener-link trust class lifecycle 은 RFC
  §5.M 또는 §5.C 패치 필요 항목 (upstream 검증으로 해소 불가).
  Phase A SCXML authoring 차단 사항.

이로써 Phase A SCXML authoring 의 reassembly 측 차단 사항은
**(1) OQ-W22 (RFC patch 필요), (2) reassembly-fsm.md §2.5 의 4
cascading FSM-shape amendments 정리** 두 항목으로 좁혀짐. (1) 은
external dependency, (2) 는 prose-only follow-up.

## 이번 세션(2026-05-01 후속 #3) 완료 작업 — `docs/reassembly-fsm.md` cascading revision pass

KICKOFF 우선순위 #4 의 잔존 prose-only follow-up 처리. OQ-W21 close
(2026-05-01 후속 #2) 가 §2.5 에 deferred 로 명기한 4 cascading items
를 본문에 흡수.

- **A. Chain key 4-tuple → 2-tuple** — §1 재작성. 키는
  `(peer_zid, reliability)` 만, `priority` / `sn_base` 제거.
  근거: upstream `_z_t_msg_fragment_t = {_payload, _sn, first, drop}`
  (`~/zenoh-pico/include/zenoh-pico/protocol/definitions/transport.h:494-499`)
  에 priority 와 sn_base 없음. 4-tuple 은 `wire-spec-subset.md` §4.2
  에서 추출된 watching-zenoh extrapolation, upstream 무근거.

- **B. Slot count — N parallel slot pool 유지 + parity invariant** —
  §2.1 재작성. upstream 의 inline 2-buffer-per-peer 모델은 MCU 에서
  ~128 KB 메모리 폭증 (peer_table × 2 × slot_size). ARCHITECTURE §2.4
  invariant #1 (static-first) 와 호환되지 않아 거부. 대신 **upstream-
  divergent generalization** 으로 명시 — 공유 bounded slot pool size N,
  slot 당 (peer_zid, reliability) 태그 + one-active-per-key invariant
  (duplicate Fragment.First → existing chain Aborted with reason
  `duplicate-first`). Parity invariant: `slot_count ≥ 2 ×
  peer_table.capacity` 시 upstream 행위 정확히 재현. MCU 의 over-commit
  ratio 8× / AP 의 16× 는 의도적. **Parity gate posture (Phase C C14)**:
  pool-exhaustion sub-test disabled until end-to-end equivalence harness
  lands (혹은 security-feature divergence 로 영구 documented).

- **C. Per-chain `reassembly_timeout_ms` — defense-in-depth** —
  [Receiving → TimedOut](reassembly-fsm.md#245-receiving--timedout-timer) / §2.2 / §4 / §5 / §11 행 5 갱신. 타이머 유지하되 zenoh-pico
  parity 가 아닌 **defense-in-depth beyond upstream** 으로 framing.
  근거: §5 attack-cost 산식의 핵심 자산 — handshake-paying attacker
  가 `Fragment.First + one Continue` 만 보내고 stall 하면 upstream 은
  disconnect 까지 dbuf 무한 점유 (next-OOO/overflow/Final/disconnect
  cleanup 모두 attacker 통제 가능). 정상 트래픽 (`reassembly_timeout_ms
  = 500` ≫ 정상 chain RTT) 에는 invisible, parity gate 영향 0.

- **D. `start` flag → `FRAGMENT_FIRST` / `FRAGMENT_DROP` patch-gated
  ext** — §1 wire shape 재작성. 헤더 비트는 `_Z_FLAG_T_FRAGMENT_M`
  (more, 0x40) + `_Z_FLAG_T_FRAGMENT_R` (reliability) 두 개만.
  `FRAGMENT_FIRST` (id 0x02) + `FRAGMENT_DROP` (id 0x03) 는
  `_Z_PATCH_HAS_FRAGMENT_MARKERS(patch >= 1)` 게이트 extension. Legacy
  peer (patch 0) 는 implicit chain framing — "buffer empty AND SN
  consecutive" 추론. 신규 `Fragment.Drop` 이벤트 → `Receiving →
  Aborted (peer-drop)` (2.4.7a 신규). Router pseudo-code 에 `Fragment.
  Drop` 분기 + `unmatched-drop` 진단 추가.

- **§2.4 transitions 본문 streaming-cursor 정합** — §2.5 Resolution
  의 streaming-cursor 모델을 [Empty→Receiving](reassembly-fsm.md#241-empty--receiving)–[Aborted (codec error)](reassembly-fsm.md#247-receiving--aborted-codec-error) 본문으로 끌어올림.
  `slot.bitmap` 제거, `slot.last_sn` 도입; idx 기반 검증 → SN-precedence
  + consecutive 검증 (`_z_sn_precedes` + `_z_sn_consecutive`,
  `~/zenoh-pico/src/transport/utils.c:85-88`). [Aborted (out-of-order continue)](reassembly-fsm.md#244-receiving--aborted-out-of-order-continue) 재정의: "incomplete
  bitmap" → "out-of-order continue" (streaming-cursor 모델에서 발생
  안 하는 케이스 제거 + 발생하는 단일 abort path 표면화). [Aborted (Router-driven eviction)](reassembly-fsm.md#246-receiving--aborted-router-driven-eviction)
  expanded: oldest-wins eviction + duplicate-first 두 sub-cause.

- **§2.5 Cascading deferred-list 자체 정리** — 4 bullet 본문 흡수
  완료 후 short self-reference 로 축소. §8.1 G-RFM-1 follow-up 이
  Phase A SCXML authoring blocker 에서 OQ-W22 로 수렴.

- **§9.2 diagnostic list reason codes 갱신** — `out-of-order` (single,
  replaces `reliable-out-of-order`) / `duplicate-first` / `peer-drop`
  추가, bitmap-era reason codes (`incomplete-final` /
  `out-of-bounds-index` / `duplicate-index`) 제거. Router-side
  `reassembly/unmatched-drop` 신규.

- **`docs/wire-spec-subset.md` §4.2 Fragment row amend** — 헤더 비트
  / extensions 분리, chain key 2-tuple 표기, patch >=1 의존성 명기,
  `docs/reassembly-fsm.md` §1 cross-ref.

- **§7.1 + §9.1 historical update** — deploy 수정 (2026-05-01 후속
  #1, MCU 16→2 / AP 256→44) 이미 적용됨을 §9.1 에서 "Resolved" 로,
  §7.1 의 invariant check 결과를 "Fails" → ✓ 로 정정. §7.1 에 slot
  pool parity check (informational) 추가.

- **§10 / §11 row 5 / §12 change log** — Authoring blocked items 에서
  OQ-W21 + cascading 항목 제거 (OQ-W22 만 잔존). §11 row 5 에서
  reliability 별 runtime branch 표현 평탄화. §12 에 cascading revision
  pass entry 추가.

이로써 **Phase A SCXML authoring 의 reassembly-측 잔존 차단 항목 =
OQ-W22 단 1건** (RFC §5.M 또는 §5.C 패치 필요, upstream 검증
불가 항목). cascading items 는 모두 prose-verified 형태로 본문에 명시.

## 이번 세션(2026-05-01 후속 #4) 완료 작업 — `docs/scouting-fsm.md`

KICKOFF "다음 세션 후보 작업" #3 항목 처리 + 동일 zenoh-pico read 세션
에서 OQ-W3 / OQ-W9 두 건 동시 close. sibling FSM prose-sketch 패턴
(reassembly-fsm.md / session-fsm.md) mirror, ≈1458 줄.

- **`docs/scouting-fsm.md` 신규 (1458 줄)** — §1 framing overview /
  §2 Scouting FSM (active / passive / static 3 mode bodies, hierarchy,
  states, transitions, timer / bounded-collection invariants) /
  §3 Interest와의 관계 (OQ-W3 답 — file:line 인용 8건) / §4 deploy.yaml
  cross-ref (활성 13 필드 + 미존재 3 필드 OQ-W23 차단) / §5 build-time
  analysis (3 quantitative checks) / §6 trust-class composition + OQ-W9
  closure / §7 §6 self-review (intermediate) / §8 design gaps (G-SCT-1/2/3)
  + 신규 OQ-W23 / §9 RFC feedback (6 build diagnostics + 4 runtime
  diagnostics + 1 ARCHITECTURE invariant footnote) / §10 next-step
  scaffolding / §11 ARCHITECTURE §2.4 self-review / §12 change log.
  근거는 zenoh-pico 1.9.0 HEAD `3b3ab65` 직접 read
  (`src/{session/scout.c, net/{session.c, primitives.c}, api/api.c,
  transport/{multicast/{transport.c, lease.c, rx.c}, unicast/accept.c},
  session/interest.c, protocol/definitions/transport.c}` +
  `include/zenoh-pico/{api/{constants.h, primitives.h}, config.h.in,
  protocol/definitions/transport.h}`).

- **핵심 발견 1 — three-mode framing 의 정직화** ([Three modes and the zenoh-pico mapping](scouting-fsm.md#14-three-modes-and-the-zenoh-pico-mapping)). zenoh-pico 의
  scouting 메커니즘은 *active 단발 1종* 만 존재
  (`scout.c:142-165` `_z_scout_inner`). watching-zenoh 의 deploy
  `scouting.mode = {active, passive, static}` enum 은 zenoh-pico 의
  단일 메커니즘에 대한 **운영 추상화**:
  - `active` = parity (1:1 매핑, exit_on_first guard 만 다름)
  - `passive` = **watching-zenoh 추가물**, parity 아님 (G-SCT-1 / OQ-W23)
  - `static` = parity 의 scouting-bypass 표현 (`session.c:87-118` 의
    `connect=` config short-circuit). codegen 이 mode 를 컴파일타임
    상수로 elide 하므로 mode-gating = ARCHITECTURE §2.4 invariant #5
    의 deploy-attribute 차원 확장 ([ARCHITECTURE §2.4 invariant #5 footnote](scouting-fsm.md#97-architecture-24--invariant-5-footnote-on-mode-gating) 권장).

- **핵심 발견 2 — OQ-W3 close** (§3, file:line 인용 8건).
  Interest semantics 는 **router-only 가 아니다**. Three transport-
  class-specific mechanisms:
  - **Unicast peer-peer (Mechanism 1)**: acceptor 가 handshake 완료
    직후 ALL local declares + DeclareFinal 을 unsolicited push
    (`unicast/accept.c:148-149` →
    `interest.c:194-201` `_z_interest_push_declarations_to_peer`).
    Inbound Interest 는 unicast 경로에서 **무응답 무시**
    (`interest.c:531-535` 의 `if (zn->_tp._type ==
    _Z_TRANSPORT_UNICAST_TYPE) return _Z_RES_OK;`).
  - **Multicast peer mesh (Mechanism 2)**: peer 가 multicast session
    open 시 `Interest{CURRENT, KEYEXPRS}` pull
    (`session.c:149-153` → `interest.c:203-214`); 수신 peer 는
    매칭된 declares + DeclareFinal 응답
    (`interest.c:546-566`). **router 없이 peer 가 답함.**
  - **Client unicast to router (Mechanism 3)**: router-side push
    (Mechanism 1 의 router 측 변형). Client 단독 + router 부재 시
    Mechanism 1/2 모두 부재 — 이게 원래 OQ-W3 의 "router-only"
    framing 이 적용되는 *유일한* 토폴로지.
  - 결과: MCU Interest handler 는 **multicast 에서 진짜 참여자
    (Included, bounded form), unicast 에서 no-op**. `wire-spec-
    subset.md` §5 의 Interest Included 분류와 [Permanent-on-MCU network features](wire-spec-subset.md#52-permanent-on-mcu-network-features) 의 router-scale
    aggregation Permanent-on-MCU 분류가 mechanically 정합.
    `declare_fsm.scxml` authoring contract 가 §3.4 에서 결정됨
    (transport-class guard 가 receive handler 의 첫 줄).

- **핵심 발견 3 — OQ-W9 close** ([OQ-W9 closure: client+multicast session](scouting-fsm.md#64-oq-w9-closure-clientmulticast-session)).
  zenoh-pico clients 는 multicast **session** 거부, multicast
  **scouting** 참여. `_z_multicast_open_client`
  (`multicast/transport.c:153-162`) 명시적으로
  `_Z_ERR_CONFIG_UNSUPPORTED_CLIENT_MULTICAST` 반환
  (`// @TODO: not implemented` 주석). 대조 peer path
  (`transport.c:116-151` `_z_multicast_open_peer`) 는 완전 구현,
  `Z_JOIN` with `whatami=Z_WHATAMI_PEER` 발사 (`transport.c:130`).
  Scouting layer 는 whatami-agnostic — `_z_s_msg_make_scout`
  (`protocol/definitions/transport.c:419-428`) 가 sender 의 role 을
  encode 하지 않음, role 은 Hello reply 에서만 전달됨
  (`transport.c:431-445` `_z_s_msg_make_hello`). 빌드타임 강제:
  새 진단 `deploy/client-multicast-session-unsupported` (hard error)
  RFC §5.K 에 추가 권장.

- **OQ-W23 신규** (§8.2) — passive scouting mode justification +
  schema. Two-part question:
  - (a) `scouting.mode: passive` 가 MVP 에 들어가야 하나? Trade-off:
    operator ergonomics (rolling deploy / late-arriving peer 자동
    재발견) vs scope expansion beyond zenoh-pico parity.
  - (b) Yes 면 deploy.yaml 신규 3 필드 (`scout_retry_interval_ms`
    proposal `30000`, `scout_retry_jitter_pct` proposal `25`,
    `hello_entry_lease_ms` proposal `5 × scout_retry_interval_ms`)
    의 defaults. Validation: rolling-deploy 시나리오 + 24h 정상
    mesh 의 spurious-Scout cost 측정.
  - Phase A SCXML authoring 차단: passive mode SCXML 만 차단,
    active+static 은 차단 안 함.

- **G-SCT-1/2/3** filed (§8.1):
  - **G-SCT-1**: passive mode justification + schema (→ OQ-W23).
  - **G-SCT-2**: unsolicited Hello broadcaster 부재 (multicast
    Z_JOIN 이 announcer role 을 cover 하므로 잔존 케이스 = unicast-
    session-only nodes wanting discoverability — speculative,
    no OQ filed).
  - **G-SCT-3**: `scout_rx_pool.slot_size` 의 realistic-vs-worst-
    case Hello 사이즈. 8 locators × 64 bytes worst case (≈ 549 B)
    가 MCU 256 / AP 512 slot_size 모두 초과; realistic case
    (1-2 locators × 80 B ≈ 185 B) 는 fit. Informational diagnostic
    `scouting/hello-slot-size-recommendation` 권장.

- **`docs/rfc-open-questions-log.md` 갱신**:
  - id-space 헤더 `OQ-W22` → `OQ-W23`.
  - **OQ-W3** status `open` → `answered`, Resolution 블록 (3
    mechanisms + file:line 인용) 추가.
  - **OQ-W9** status `open` → `answered`, Resolution 블록 (file:line
    인용 + build-time enforcement diagnostic) 추가.
  - **OQ-W23 신규** entry — (a) passive justification (b) deploy
    fields proposal + validation requirement.
  - Change log entry "2026-05-01 후속 (scouting-fsm.md authoring)"
    추가, 76 줄.

- **`docs/session-fsm.md` cross-doc amend**:
  - §3.4 closing sentence (`**Open question OQ-W9** (§8.2).`) 를
    OQ-W9 closure prose + cross-ref `docs/scouting-fsm.md` [OQ-W9 closure: client+multicast session](scouting-fsm.md#64-oq-w9-closure-clientmulticast-session) /
    §9.4 로 교체 (file:line 인용 포함).
  - §8.2 OQ-W9 row status `open` → answered, evidence + cross-ref
    포함된 single bullet 으로 압축.

- **RFC patches recommended** (`docs/scouting-fsm.md` §9):
  - **§5.K 신규 6 build diagnostics**: `deploy/scouting-{retry-
    interval,retry-jitter,hello-lease}-missing-on-passive-mode`
    (3종, OQ-W23 (a)=yes 시 hard error),
    `deploy/scouting-passive-fields-on-non-passive-mode` (warning),
    `deploy/client-multicast-session-unsupported` (hard error,
    OQ-W9 강제),
    `deploy/untrusted-source-on-untrusted-link` (hard error, §6.2
    schema-validation).
  - **§5.K 조건부 신규 3 필드**: `scout_retry_interval_ms` /
    `scout_retry_jitter_pct` / `hello_entry_lease_ms` (OQ-W23 (a)
    closure 조건부).
  - **§5.M 신규 3 informational diagnostics**:
    `scouting/hello-max-peers-exceeds-peer-tables` (hard error, [hello_max_peers vs peer-table invariant](scouting-fsm.md#52-hello_max_peers-vs-peer-table-invariant)),
    `scouting/rx-pool-overprovisioned-vs-burst-pps` (informational, [Burst absorption / rx-pool sizing](scouting-fsm.md#51-burst-absorption-rx-pool-sizing)),
    `scouting/hello-slot-size-recommendation` (informational, [scout_rx_pool.slot_size / hello upper bound](scouting-fsm.md#53-scout_rx_poolslot_size--hello-upper-bound)).
  - **runtime diagnostics**: `scout/{tx-failed, decode-failed,
    timeout, hello.peer_table_full, peer-aged-out, client-looking-
    for-clients}` — §2.3 transition 다이어그램에서 emit.
  - **ARCHITECTURE §2.4 invariant #5** footnote 권장 — mode-gating
    이 deploy-attribute 차원의 platform-gating 임 ([ARCHITECTURE §2.4 invariant #5 footnote](scouting-fsm.md#97-architecture-24--invariant-5-footnote-on-mode-gating)).

이로써 **Phase A SCXML authoring 의 scouting-측 차단 항목**:
- `mode ∈ {active, static}` SCXML 저작 = **차단 없음** — `docs/
  scouting-fsm.md` [Active](scouting-fsm.md#241-active) / [Static](scouting-fsm.md#243-static) 본문이 fully-grounded.
- `mode = passive` SCXML 저작 = **OQ-W23 (a)+(b) 차단** (binary
  include/defer-to-Phase-D 결정 + 3 deploy fields defaults).

세 prose-sketch (session / reassembly / scouting) 의 collective
잔존 차단 항목:
- **OQ-W22** (listener-link trust class lifecycle, RFC §5.M 또는
  §5.C 패치 필요) — reassembly+session 측.
- **OQ-W23** (passive mode justification + schema) — scouting 측,
  binary 결정 항목.
- **reassembly-fsm.md §2.5 cascading items** — *완료* (2026-05-01
  후속 #3); reassembly 측 차단 없음.

## 이번 세션(2026-05-01 후속 #5) 완료 작업 — Runtime crate API + OQ batch close

KICKOFF "다음 세션 후보 작업" #2 ("Runtime crate API 스텁 설계") 처리
+ OQ-W23 (a) binary 결정 + OQ-W4/W7/W10 batch 검증 (zenoh-pico 1.9.0
HEAD `3b3ab65` 직접 read). 5건 OQ closure 한 라운드.

### 신규 prose doc 3종 (≈900 줄 합계)

- **`docs/runtime-crate-tokio.md` 신규** — `(rust, linux,
  sce_link_runtime_tokio)` 3-tuple 의 Rust trait 표면 (RFC
  §5.J.3). `LinkDriver` 4-method trait
  (`open`/`send`/`close`/`poll_event`) + `LinkEvent` 6-variant
  enum 가 `docs/session-fsm.md` §6 inbound events 에 1:1 매핑.
  Trust-class compile-time gating 이 trait surface
  presence/absence 로 표현 (untrusted / session_arming /
  established_session). io_uring fixed-buffer opt-in 은 trait
  surface 변경 0 — §5.E pool lifecycle FSM edge actions 만 차이
  (ARCHITECTURE §9.5 row 3). Phase A–C 동안은 design-only.

- **`docs/runtime-crate-lwip.md` 신규** — tokio doc 의 C11 자매.
  `(c11, bare_metal, sce_link_runtime_lwip)` 3-tuple. 같은 6-event
  계약을 `sce_link_event_t` enum + `sce_link_t` opaque +
  `sce_pool_slot_handle_t` opaque (§5.E lifecycle ownership-
  inheritance edge handle) + cooperative-scheduler poll 함수 +
  ISR-side dispatch entry 로 표현. RFC §5.E Layer 1 typestate
  annotations (`consumable`/`callable_when`/`set_typestate`) 이
  slot handle 에 propagate — Clang `-Wconsumed` 가 use-after-take
  / double-take 컴파일 타임 catch. **Phase A direct authoring
  blocker** (헤더가 codegen 의 target).

- **`docs/intrinsics-runtime-symbols.md` 신규** —
  `sce_intrinsics_runtime_{c,rust}` 의 symbol surface (RFC §5.I
  whitelist host). 7 symbol categories (atomics / fences / cache /
  IRQ / RNG / HMAC / HW-sem) 와 whitelist-vs-target-plugin policy
  column. **OQ-W15 (a) initial proposal 박힘**: §2.5 RNG → core
  whitelist (option 1, universal entropy primitive); [HMAC — OQ-W15 (a) initial proposal: target plugin](intrinsics-runtime-symbols.md#26-hmac--oq-w15-a-initial-proposal-target-plugin) →
  target plugin (option 2, per-SoC accelerator selection).
  §5.J.2 statechart `no_std` HAL trait shape (`now_us`/`wake`/
  `irq_save`/`irq_restore`) 이 §2 symbols 에 매핑. ARCHITECTURE
  §9.5 5-row matrix 의 "same shape, different body" 보존 — 5 row
  symbol name 동일, body 만 platform 별 차이.

### OQ batch closures (5건)

- **OQ-W23 (a) closed — defer to Phase D+** (장기 정합성 권고
  채택). 3 reasons: MVP=zenoh-pico parity (passive 는 upstream
  무 equivalent), YAGNI/scope discipline (application-layer
  `z_scout()` retry 가 parity-aligned workaround), reversibility
  asymmetry (additive enum extension at Phase D+ vs breaking
  schema removal). RFC review #14 "pre-release forward-namespace
  0" 규율과 정합. Cross-doc 효과: `docs/scouting-fsm.md` 7곳
  amend ([Three modes and the zenoh-pico mapping](scouting-fsm.md#14-three-modes-and-the-zenoh-pico-mapping) row label, [Passive — deferred to Phase D](scouting-fsm.md#242-passive--deferred-to-phase-d) deferral 단락 단축, §2.5 timer
  3 row 제거, §4.2 reframe, §8.1 G-SCT-1 resolved, §8.2 OQ-W23
  answered/deferred, §9.3 RFC §5.K passive-mode patch
  *withdrawn*, §10 next-step 갱신, §12 change log entry); MVP
  `mode` enum `{active, static}` 잠김.

- **OQ-W4 closed — Compression 자체가 zenoh-pico 1.9.0 에 부재.**
  `~/zenoh-pico/include/zenoh-pico/protocol/ext.h:46-50` ext-ID
  열거 5종에 Compression 없음; `transport.c:230-233` unknown-
  mandatory→ refuse, unknown-non-mandatory → silently ignore
  (어떤 future upstream Compression 이든 M-flag set 이면 refuse
  로 안전). MVP wire surface 는 Compression 생략
  (`docs/wire-spec-subset.md` §7.2 accept-and-ignore 와 mechanically
  정합).

- **OQ-W7 closed — direction-asymmetric PatchType policy.**
  Initiator 측 InitAck reception 은 **REFUSE** if peer patch >
  ours (`unicast/transport.c:141-149`); Acceptor 측은 **min-clamp**
  (`peer.c:225`, `multicast/rx.c:407`). `_Z_NO_PATCH=0x00`,
  `_Z_CURRENT_PATCH=0x01` (transport.h:100-101), patch enum 2-valued
  + `Z_FEATURE_FRAGMENTATION` gate. 원래 OQ-W7 "refuse" 제안은
  initiator 만 정확; acceptor 는 min-clamp. SCXML body 가
  방향 honor.

- **OQ-W10 closed — Auth 자체가 zenoh-pico 1.9.0 에 부재.**
  `Z_FEATURE_AUTH`/`USRPWD` gate 없음, `Z_CONFIG_USER_KEY`/
  `PASSWORD_KEY` (config.h.in:110, 117) 정의되었지만 src/ 에서
  미참조, ext.h:46-50 에 Auth ext-ID 없음, `*usrpwd*`/`*auth*`
  파일 transport tree 에 없음. MCU parity baseline = `{none}`;
  USRPWD multi-step shape 질문 자체가 MVP 에서 무의미.
  `Opening.*` sub-states 평탄 유지 (session-fsm §2.2).

- **OQ-W2 closed (sibling effect)** — Auth baseline 이
  `{none, usrpwd}` 에서 `{none}` 으로 축소; USRPWD 와 pubkey
  모두 Phase D+ Auth landing 시 OQ-W10 re-open 과 함께 land.

### 잔존 Phase A 차단 항목 (이번 라운드 후)

- **OQ-W22** (listener-link trust class lifecycle) — RFC §5.M
  또는 §5.C 패치 필요 (upstream 검증 불가, RFC 저작 차원).
- **OQ-W15** (HMAC + RNG primitive ownership) — initial proposal
  (§2.5 core whitelist RNG / [HMAC — OQ-W15 (a) initial proposal: target plugin](intrinsics-runtime-symbols.md#26-hmac--oq-w15-a-initial-proposal-target-plugin) HMAC) SCE
  maintainer ratification 대기. `stateless_accept` SCXML
  authoring 차단 (public-internet listener bearing MCU).

다른 OQ 들은 모두 answered 또는 design-only-during-Phase-A-C
(Phase D+ 작업의 자체 차단 항목 — OQ-W11/W17/W20 — 은 priority
MCU track 을 막지 않음).

## 이번 세션(2026-05-01 후속 #6) 완료 작업 — OQ-W22 close + OQ-W15 ratification artifact

KICKOFF "다음 세션 후보 작업" 의 우선순위 #5 (OQ-W22 RFC §5.M 패치)
+ #6 (OQ-W15 ratification 자료 준비) 두 항목 한 라운드 처리. Phase A
SCXML authoring 의 prose-side 잔존 차단 두 항목 중 자력 close 가능한
OQ-W22 자력 closure + SCE-maintainer-dependency 인 OQ-W15 (a) 는
ratification artifact 까지만.

### A. OQ-W22 close — option 3 ratified (codegen split)

- **RFC §5.M 신규 단락 "Listener-link trust-class lifecycle"** —
  "Trust class requirement (UDP spoofing hardening)" 단락과
  "Per-peer quota (DoS hardening)" 단락 사이에 삽입. 트러스트
  클래스 표가 *link instance*'s `trust_class` 에 키된 정적
  체크임을 응결, listener 가 두 logical link-instance 로 분기
  (`session_arming` + `established_session` sibling) 임을 명시,
  build-time 게이트가 socket-scoped 가 아닌 link-instance-scoped
  로 fully static 함을 못박음. 신규 진단 1종 추가
  (`reassembly/binding-on-unpaired-listener`, hard error).

- **RFC §5.C 신규 단락 "Listener-link sibling emission"** —
  "Codegen contract" bullet 목록과 "Diagnostics:" 헤더 사이에
  삽입. sibling 의 *codegen mechanics* 4 항목 명시 (synthesized,
  inheritance pattern, `<sce:rx-pool>` resolution, runtime-crate
  trait/header 확장 패턴). 신규 진단 1종 추가
  (`link/listener-link-not-paired-with-established-sibling`, hard
  error, codegen self-check / template regression guard).

- **`docs/reassembly-fsm.md` 4섹션 갱신**
  - §5 trust-class 표 preface 를 "link instance trust_class" 로
    재키잉, "Listener links emit two instances" 부단락 신규
    (deploy.yaml schema 미변경 + RFC 본문 cross-ref).
  - §8.1 G-RFM-2 → resolved (option (c) ratified 명시, 진단 2종
    cross-ref).
  - §8.2 OQ-W22 → answered (close summary).
  - §10 authoring-blocker section 을 "unblocked" 로 flip
    (dispatcher SCXML 이 listener 의 sibling 에 codegen-time 으로
    바인딩됨 명시).
  - §12 change log 에 "2026-05-01 후속 #6 — OQ-W22 close" entry
    추가.

- **`docs/session-fsm.md` [Trust-class interaction](session-fsm.md#26-trust-class-interaction-cross-ref-to-5m)** — trust-class 표 끝에
  "Listener-link logical split (OQ-W22 resolution)" 부단락 신규.
  `Established` entry action 이 traffic ownership 을 sibling 으로
  migrate 하는 시점임을 RFC §5.M / §5.C cross-ref 와 함께 명시.

- **`docs/runtime-crate-lwip.md` §4** — "Listener-link two-instance
  emission" 단락 신규. C11 헤더 surface 가 listener 한 entry 에서
  두 `sce_link_t` 인스턴스 emit, peer-state-driven RX dispatch 가
  runtime crate 안에 산다는 점 명시. 진단 2종 cross-ref.

- **`docs/runtime-crate-tokio.md` §2.4** — 같은 shape 의 Rust trait
  두 `LinkDriver` impl 단락. `io_uring` opt-in 과 orthogonal 임을
  명시 (양쪽 sibling 이 독립적으로 reactor flavor 선택 가능).

- **`docs/rfc-open-questions-log.md`** — OQ-W22 entry status
  `open → answered`, Resolution 블록 (5 cross-doc amend list +
  진단 2종 cross-ref + RFC 패치 위치 인용) 추가. Change log
  "2026-05-01 후속 #6 (OQ-W22 close)" entry 추가.

### B. OQ-W15 (a) ratification artifact

- **`docs/oq-w15-ratification-summary.md` 신규** (≈190줄) — 1-page
  SCE-maintainer-facing summary. 6-section 구조 (Decision needed /
  Why now / Initial proposal with 3 reasons each for RNG and HMAC /
  Counter-options for both decisions / Blast radius for each cell
  of 2x2 RNG×HMAC matrix / Action requested). Source material
  citation: `docs/intrinsics-runtime-symbols.md` §2.5 / [HMAC — OQ-W15 (a) initial proposal: target plugin](intrinsics-runtime-symbols.md#26-hmac--oq-w15-a-initial-proposal-target-plugin) / §3
  + `docs/session-fsm.md` [Accept-side hardening detail](session-fsm.md#27-accept-side-hardening-detail) (c).
  - placement 결정: 신규 doc (옵션 A) — `intrinsics-runtime-
    symbols.md` 의 §A 별첨 (옵션 B) 가 아닌 이유: source/audience
    분리 (전자는 internal developer, 후자는 external SCE
    maintainer); 미래 OQ-W14 등 같은 종류 artifact 가 sibling 으로
    늘어나는 패턴.
  - status 미변경 — OQ-W15 (a) 는 SCE 측 ratification 대기로
    `open` 유지. (b) 는 HIL 측정 의존으로 별도.

- **`docs/rfc-open-questions-log.md`** — OQ-W15 entry 의 Action
  필드에 1-page summary pointer 추가. Change log "2026-05-01
  후속 #6 (OQ-W15 ratification artifact)" entry 추가.

### 산출물 요약

- 신규 파일 1개 (`docs/oq-w15-ratification-summary.md`, ≈190줄)
- 갱신 파일 7개 (RFC §5.M / §5.C, reassembly-fsm.md 4섹션 + change
  log, session-fsm.md [Trust-class interaction](session-fsm.md#26-trust-class-interaction-cross-ref-to-5m), runtime-crate-lwip.md §4,
  runtime-crate-tokio.md §2.4, rfc-open-questions-log.md OQ-W22 +
  OQ-W15 + change log 2종, SESSION_KICKOFF.md)
- 합계 ≈ 450 줄
- OQ status 변경: OQ-W22 `open → answered`. OQ-W15 미변경
  (artifact 만 prepared).
- 신규 진단 2종 (RFC §5.C 1, §5.M 1).
- deploy.yaml schema 변경 0.

이로써 **Phase A SCXML authoring 의 watching-zenoh prose-side 잔존
차단 항목은 OQ-W15 (a) ratification 단 1건** (SCE maintainer sync
의존, artifact 는 prepared). private-LAN MCU listener 는 OQ-W15
없이도 land 가능; public-Internet-facing MCU listener 만이 OQ-W15
ratification 을 기다림. **다음 세션의 자력 prose work 후보는 사실상
없음** — SCE Phase A (RFC §5.J.1 새 kinds × C11 emitter + §5.J.2
statechart `no_std` runtime feature) 가 land 할 때까지 자연스러운
다음 작업 없음.

## 다음 세션 후보 작업

우선순위 높음 (Phase A 대기 중에도 유용, throw-away 없음):

1. **`deploy/` 스켈레톤 3종 작성** — **완료 (2026-05-01).** 위 단락 참조.
   - OQ-W18 의 empirical measurement 만 외부 의존으로 잔존 (HIL 보드).

2. **Runtime crate API 스텁 설계** — **완료 (2026-05-01 후속 #5).**
   3 doc 신규 (`runtime-crate-tokio.md` / `runtime-crate-lwip.md` /
   `intrinsics-runtime-symbols.md`); OQ-W15 (a) initial proposal
   박힘. SCE generator 저자 target shape 제공 완료. 잔존 차단
   = OQ-W15 ratification (SCE maintainer sync 필요).

3. **`docs/scouting-fsm.md` prose sketch** — **완료 (2026-05-01 후속 #4).**
   2026-05-01 후속 #5 에서 OQ-W23 (a) close — defer to Phase D+
   (passive mode 추후 land); MVP `mode` 는 `{active, static}` 잠김.

4. **`docs/reassembly-fsm.md` prose sketch** — **완료 (2026-05-01 후속).**
   OQ-W21 은 2026-05-01 후속 #2 에서 close (option 2, strict in-order).
   §2.5 cascading FSM-shape revision pass 는 2026-05-01 후속 #3 에서
   완료. 잔존 차단 항목 = **OQ-W22 단 1건** (RFC §5.M 또는 §5.C
   패치 필요).

우선순위 중간:

5. **OQ-W22 RFC §5.M 패치 작성** — **완료 (2026-05-01 후속 #6).**
   option 3 (codegen split) ratified, RFC §5.M "Listener-link
   trust-class lifecycle" + RFC §5.C "Listener-link sibling
   emission" 두 단락 land. 5 cross-doc amend (reassembly-fsm.md /
   session-fsm.md / runtime-crate-{lwip,tokio}.md / OQ-log).
   진단 2종 신규. deploy.yaml schema 미변경.

6. **OQ-W15 (a) ratification 자료 준비** — **완료 (2026-05-01
   후속 #6).** `docs/oq-w15-ratification-summary.md` 신규 (1-page,
   6-section). status 미변경 (SCE sync 대기).

7. **Pcap 코퍼스 수집 계획** — Zenoh 업스트림에서 SCOUT/HELLO/INIT/OPEN/PUT/SUB 트래픽 캡처. SCE Phase A 진입 전에도 유용 (test-vector source).

8. **§5.L XSD schema 초안** — bounded-collection 공식 XSD (현재 shape 수준). prose-only, throw-away 없음.

9. **OQ-W4/W7/W10 업스트림 검증** — **완료 (2026-05-01 후속 #5).**
   3건 모두 zenoh-pico 1.9.0 source 직접 read 로 close. 추가
   작업 없음.

우선순위 낮음 (SCE Phase A 랜딩 이후, 또는 외부 의존 해소 후):

10. 실제 SCXML 저작 시작 (Phase A 완료 전에는 의미 없음)
11. 생성 코드 검증 하네스 작성
12. **OQ-W15 (a) close** — SCE maintainer sync 결과 반영
    (`docs/oq-w15-ratification-summary.md` artifact 활용)
13. **OQ-W18 empirical measurement** — Cortex-M0+/M3-M4/M7
    reference board HIL 측정 (`vle_decode_cycles_per_byte` /
    `tlv_chain_per_entry_overhead_us` / HMAC cycles)
