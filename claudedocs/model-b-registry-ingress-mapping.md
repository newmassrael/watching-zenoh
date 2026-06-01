# 모델 B: registry ↔ SCE ingress 매핑 설계 (R311gb)

작성 2026-06-01. 상태: **결정 확정 + 구현 착수(R311gb-1 완료)**.
근거: SCE RFC#1/#2 응답(검증됨) + wz-session-core 콜백 audit.

## 0. 배경 / 결정 요약

- 목표: 단일 SCXML 소스 → AP(heap) / MCU(no-heap) 두 투영 (북극성 §2.4).
- 콜백 저장 모델: **모델 B(statechart-event)** 채택. 콜백 행위를 SCXML
  (statechart/Worker)로 올려 codegen 대상으로, transport 측 콜백은 "샘플/이벤트
  주입" 고정 어댑터로 축소.
- SCE RFC#2 검증: 모델 B는 **기존 SCE kind로 전부 표현 가능, SCE 신규 작업 0,
  wz 측 unsafe 영구 0**. no-heap 저장 인프라(`Inbox<E>`, buffer-pool slot)는 SCE
  제공. → 원래 "no-alloc 콜백 저장 부채(R311gb)" 대부분 소멸.
- 포지셔닝: wz = **독립 Zenoh 프레임워크 + SCE Mesh 백엔드** 둘 다.

### SCE ingress 2경로 (검증된 사실)

- **Path 1 — sync borrow**: `sce-link-runtime/src/lib.rs`
  `Sample::payload() -> &[u8]`(:248) zero-copy borrow, `<sce:on-sample link=X>`
  statechart 측. 단순 반응형 = 완전 no-heap(take 없음).
  - `take() -> M::Owned`(:281)는 `StageCopyHook::stage_copy(&[u8]) -> Vec<u8>`
    (:189, 시그니처 하드코딩) 경유 = **본질적 heap(AP 전용)**. MCU
    owned-retention은 take() 금지.
- **Path 2 — async decoupled**: `worker.rs.jinja2` `Inbox<E>`(E 제네릭, Copy
  제약 없음, `const fn new`, SPSC `split`/`try_push`/`try_pop`),
  `<sce:link-rx>` + `<sce:inbox depth=N>` Worker 측. E = codec decoded
  struct(고정) 또는 buffer-pool slot handle(zero-copy 보유). no-heap.

## 1. 분류표 (실제 registry 전수)

| Registry (file) | plane | 콜백 현행 | 데이터 | 기본 Path | retention opt-in | churn | 출력 |
|---|---|---|---|---|---|---|---|
| `pubsub::SubscriberRegistry` | data | `FnMut(&Sample)` | owned Sample(Vec) | **Path 1** | Path 2 (Worker inbox, pool-slot) | register/unregister → 정적+활성플래그 | 無 |
| `query::QueryableRegistry` | request | `FnMut(&QueryEvent, &mut ReplyEmitter)` | QueryEvent borrowed | **Path 1** (sync) | — (req-resp inline) | 동일 | **有: ReplySink 주입** |
| `reply::ReplyRegistry` on_reply | response | `FnMut(&InboundReply)` | owned InboundReply(Vec) | Path 1(단순) / **Path 2**(누적) | Path 2 bounded inbox | per-get → bounded rid-table | 無 |
| `reply::ReplyRegistry` on_final | response | `FnMut(u64)` | **u64(Copy)** | **scalar tag** (메서드/Event\<D>) | n/a | terminal-remove | 無 |
| `declare::subscriber::Remote*` | control | `FnMut(&DeclSubscriberOwned,&str)` + Undecl | 소형 control | **Path 1** | 드묾 | install-once | 無 |
| `declare::queryable::Remote*` | control | `FnMut(&DeclQueryableOwned,&str)` + Undecl | 소형 control | **Path 1** | 드묾 | install-once | 無 |
| `declare::liveliness*` | liveliness | `FnMut(LivelinessSample<'_>)` + token decl/undecl | borrowed | **Path 1** | 드묾 | install-once/flag | 無 |

데이터 형태(검증): `Sample`(sample.rs:298)·`InboundReply`(reply.rs:177)는 owned
(`String`+`Vec`). `QueryEvent<'a>`(query_event.rs:70)·`LivelinessSample<'a>`·
`ReplyEmitter<'a>`는 borrowed. → data-plane data만 retention 압력 → Path 2 의미;
나머지는 이미 borrowed → Path 1 자명.

## 2. DIP 경계 설계

```rust
// wz-session-core (wz 소유 trait — SCE codegen이 impl하지 않음)
pub trait SampleView { fn keyexpr(&self) -> &str; fn payload(&self) -> &[u8]; }  // §5-3: currency = accessor contract
pub trait SampleSink { fn deliver(&mut self, s: &dyn SampleView); }   // existing Sample types impl SampleView
pub struct SubscriberRegistry<C: SampleSink> {
    sinks: BoundedVec<C, N>,   // alloc=Vec / no-alloc=heapless
    // keyexpr 테이블 / 매칭 / churn = hand-written, C 무관 (SSOT)
}
```

heterogeneity 해결:
- **AP**: `C = BoxedSink(Box<dyn FnMut(&dyn SampleView)>)` — heap으로 소거, dynamic OK.
- **MCU**: `C = AppSubSink` — 앱 정적 Worker producer/statechart ref 닫힌 enum
  (소비자=Mesh 생성 / 앱 손 작성), heap 0·unsafe 0.

SCE "외부 trait impl 금지" 해소: wz가 generic 어댑터(`BoxedSink` /
`WorkerSink<P>` / `StatechartSink<S>`)로 trait impl을 떠맡고, SCE/Mesh 생성
코드는 SCE 소유 ingress 핸들만 내놓음(wz 어댑터가 다리). 손 작성 독립 앱은 사람
코드라 wz trait 직접 impl 무방(금지는 SCE codegen 한정).

## 3. 어려운 케이스 2건

(a) **queryable 출력**: `trait QuerySink { fn handle(&mut self, q: &QueryEvent,
out: &mut dyn ReplyOut); }` — `ReplyOut`(wz 소유 출력 trait, QueryResponder
어댑터 impl)을 주입(Q4 HAL-주입의 출력판, §4.10 trampoline 선례).

(b) **reply rid-correlation + on_final churn**: rid→pending 상관 + on_final-후
-remove = wz 프로토콜 로직(hand-written, MCU `BoundedVec<Pending,N>`). on_reply
단순=Path 1 / 누적=Path 2 bounded inbox. on_final `u64`=Copy 태그(메서드/Event\<D>).

## 4. 소멸 / 유지

소멸: `Vec<Box<dyn FnMut>>` → `BoundedVec<C,N>`(AP=BoxedSink / MCU=닫힌 enum).
inline-fn pool·unsafe 영구 불필요. owned Sample/InboundReply는 AP retention 폼
강등; MCU 전달은 SampleRef(Path 1) 또는 pool-slot/decoded-struct(Path 2).

유지(프로토콜, 프로파일 무관): keyexpr 매칭·subscription 테이블·rid 상관·
on_final-remove·wire decode/dispatch — `C` generic화될 뿐 로직 그대로.

## 5. 확정된 결정 (2026-06-01)

스위치보드 출처 3가지(모두 같은 seam 위): Mesh 모드=SCE Mesh 생성(deploy.yaml) /
독립 선언형=wz 생성기(R311gc) / 독립 명령형=앱 손 작성. **wz 코어는 seam만 제공,
생성기 안 만듦.**

1. **스위치보드** → wz 코어는 생성기 미제작. 독립 선언형 생성기 = **R311gc 별도
   레이어**(seam 이후). 입력 = **Mesh deploy.yaml 재사용**(새 포맷 없음). caveat:
   ① subscribe 방향은 target에서 추론(wz 생성기가 동일 유도) ② Mesh 자체
   EventSubscribe는 Phase 3.5 전까지 FireForget로 degrade(SCE_MESH.md:57)
   ③ deploy.yaml 핸들은 SCXML-machine 전용(모델 B); 손 작성 클로저는 명령형 경로.
2. **AP도 Worker?** → wz가 `BoxedSink`(클로저)+`WorkerSink`(Worker) 둘 다 제공,
   소비자 per-subscription 선택. 선언된 구독은 AP도 Worker(단일소스), 런타임
   동적만 클로저.
3. **currency 타입** → 원안 "SCE Sample<'pool> 직접" → (1차) wz `SampleRef`
   struct → **(최종) `trait SampleView` accessor 계약**. 사용자 SSOT 지적으로
   재교정: SampleRef는 *3번째 데이터 표현*이라 SSOT 약화. SampleView는 데이터
   타입 0 추가 — "핸들러가 sample에서 읽는 것"을 한 trait으로 정의하고 기존
   타입(owned Sample, SCE Sample<'pool>)이 `impl SampleView`. `deliver(&mut
   self, &dyn SampleView)` (object-safe, fat-pointer borrow = no-heap/no-copy,
   투영 단계 없음). wz-session-core는 trait만 정의(sce-link-runtime 미의존);
   `impl SampleView for sce::Sample`는 bridge 크레이트(wz 손 impl, SCE codegen
   아님 → "외부 trait impl 금지" 무관). `BorrowedSample`은 SampleView의 한
   impl(loose bytes/loopback)로 강등. DIP + ISP.

## 6. 구현 로드맵 + 진행

- **R311gb-1 ✅ 완료** (LOCAL commit 4af6b71, 미푸시): `sink.rs` seam primitive
  — `trait SampleView` + `trait SampleSink(&dyn SampleView)` + `BoxedSink`(alloc)
  + `BorrowedSample`(SampleView impl). 양 프로파일 test(alloc 2 / no-alloc 1)
  + clippy -D warnings green, 호출부 무변경(additive, bounded.rs 선례).
- **R311gb-2 다음**: `pubsub::SubscriberRegistry` → generic `Registry<C:
  SampleSink>`; `impl SampleView for crate::sample::Sample`(AP) 추가 후 dispatch가
  `&owned as &dyn SampleView`로 투영 없이 전달. 콜백 시그니처 변경(owned `&Sample`
  → `&dyn SampleView`)은 no-heap 위한 principled exemption
  ([[feedback_signature_stability]] wire-data 예외와 동류); 호출부(wz-runtime-
  tokio 재노출 + 테스트) 동반 마이그레이션, 테스트 green 유지. SampleView에 sample
  kind(Put/Del) 등 accessor 추가도 이 단계(SampleKind unconditional 이동 동반).
- **R311gb-3+**: 나머지 registry fan-out(query/reply/declare/liveliness),
  QuerySink + ReplyOut(출력) / on_final scalar 태그.
- **R311gc**: 독립 선언형 스위치보드 생성기(deploy.yaml → enum, seam 위에).
