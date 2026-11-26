# The C ABI library: target architecture

Status: decision of the owner, 2026-11-23 («비용 무시하고 가장 장기적으로 올바른 궁극적인 구조로 학술적으로
교과서적이게 설계해»). It extends `docs/c-abi-engine-and-memory.md` (one sans-I/O engine, no heap after
open) and `docs/c-abi-no-heap-pools.md` (the pools), and it is the reference every size and
structure change of the pico and zenoh-c presets is judged against.

## 1. Why a new structure: what is measured

The release form (`os-posix` / `os-windows`, no `std`, `capi-nostd` profile) against zenoh-pico
built as the same build, function bytes with aliases of one address counted once (int5, 2026-11-23):

| area | wz | zenoh-pico | ratio |
|---|---:|---:|---:|
| sessions, routing, entities (declare, subscribe, query, reply, interest) | 106,043 | 27,666 | 3.83 |
| C ABI doors (`z_*`, `zp_*`) | 77,243 | 16,926 | 4.56 |
| transport (establishment, tx, rx) | 65,315 | 18,731 | 3.49 |
| runtime / driver | 27,322 | 6,639 | 4.12 |
| key expressions | 19,914 | 13,284 | 1.50 |
| wire codec | 37,861 | 36,462 | 1.04 |
| language support (Rust core/alloc/drop glue; zenoh-pico's collections and buffers) | 35,627 | 32,570 | 1.09 |
| total | 379,112 | 170,500 | 2.22 |

The codec and the language support are at parity. The excess is in the four areas where wz has a
LAYER of its own above another layer that already holds the same fact: `wz-session-core`, written
for every engine, holds the session's tables; the cooperative engine (`wz-capi-coop`) holds a
registry, a target table, a key table and a delivery lane of its own over them; the port
(`wz-capi-port`) re-describes the engine as a trait; the doors (`wz-capi-pico`) keep marshals and
copies of what the engine already holds. Each layer has its own tables, its own dispatch and its
own owned copy of what crosses it. Local folding inside those layers removed 2 to 6 KB per change;
the structure itself costs the other 200 KB.

## 2. Principles

P1. **One fact, one owner.** Every piece of session state (a declaration, a subscription, a
pending query, a key, a link's sequence numbers) lives in exactly one table, in exactly one layer.
Other layers name it by a handle; none keeps a copy.

P2. **Sans-I/O cores, drivers outside.** The protocol is a pure state machine over bytes and time
(`process(input, now) -> effects`); it performs no I/O, takes no lock, spawns nothing. Drivers
(caller-driven, driver thread, async adapter, router thread-per-core) feed it. (Brett Cannon's
sans-I/O, the `quinn-proto` / `rustls` structure.)

P3. **Region memory.** A session is one region sized at build time from the limits
(`wz_config.py` generates the capacities) and reserved at open; every table is a fixed-capacity
pool inside it addressed by a generation-checked index (slot map). Exhaustion is an error code at
the call that asks, never a panic and never a growth. No reference counting inside a session:
one owner (the session), borrowed by its driver. A value several parts of the session reach (its
round of deliveries) lies in the region, owned by one `Placed` and reached by `PlacedRef`
handles that count nothing; whoever takes a handle (`Placed::share`) answers that no copy of it
is dereferenced after the owner is dropped or beside a `&mut` the owner gave, which the owner's
place among the session's fields, dropped after every holder of a handle, keeps.

P4. **Zero-copy views.** Received bytes are read where they lie; a decoded message is a view whose
lifetime is the receive buffer's. Outgoing bytes are encoded into a lent slot. An owned message
exists only where an application asks to keep one, and then in a pool.

P5. **Static composition.** A build links exactly one engine, one platform and one feature set;
generics are instantiated once (one `L, C` per build), trait objects appear only at the edges a
program supplies at run time (its transport, its callbacks). Shared logic over several types is a
non-generic core plus thin typed wrappers.

P6. **Total functions in release paths.** No panic is reachable from input: indexing is checked by
construction (`get`, iterators, views of known length), arithmetic is checked or saturating,
every refusal is a value. Enforced by lints on the core crates
(`clippy::indexing_slicing`, `unwrap_used`, `expect_used`, `panic`, `arithmetic_side_effects`,
and the other panicking macros `unreachable`, `todo` and `unimplemented`, in non-test code;
section 7) and by the size gate (the formatting machinery a panic path drags in is a symbol the
gate forbids). An `assert!` outside a test is a panic no lint names; it is converted with the
module that holds it.

P7. **The C ABI is a façade.** A door validates its arguments once, maps the C handle to a slot
handle, calls the session core, and maps the result to the C code. It owns no state but the
process pools of objects made before a session (configs, payloads, hellos; decision Q1) and keeps
no copy of anything the core holds.

P8. **Specification first.** Every state machine (transport establishment, lease, interest,
query lifecycle) is an SCXML document generated by SCE; hand-written code is the data plane
around it. Behaviour is fixed by differential tests against zenoh-pico (its own tests and
examples, run on the release library) and against upstream zenoh.

P9. **Measured budgets per area.** The size ledger of section 1 is a gate: each area has a ratio
ratchet against zenoh-pico's same area, so a change that grows an area is refused where it grows,
not only in the total.

P10. **Typed outcomes, no sentinels.** Every operation that can be refused returns
`Result<Handle, Refusal>` at every layer boundary (L3 to the port, the port to L4). A handle is a
generation-checked slot index whose index part is `NonZero`, so `Option<Handle>` costs nothing
and no value of the handle type means "refused". `Refusal` names the cause the caller can act on
(`TableFull`, `KeyTooLong`, `NoEntityId`, `Closed`, `NotBuilt`); each preset ABI maps it to its
own codes in ONE table owned by its façade (zenoh-pico: `_Z_ERR_SYSTEM_OUT_OF_MEMORY` for the
first three, `_Z_ERR_SESSION_CLOSED` for `Closed`). Measured why: a matching listener the
cooperative engine refused came back as id 0, which the AP engine hands out as a live id, so the
door could not tell a refusal from a listener and answered `Z_OK` for one that would never be
called.

P11. **A callback's lifetime is a property of its row.** A row holds its callback in an
`Fn`-shaped form (a C `(call, context, drop)` triple, or a shared Rust `Fn`), so a call is a
shared borrow and reentrance is sound, as zenoh-pico's is. Undeclaring a row returns after the
last running call of it has returned and its `drop` has run (zenoh-pico holds the entity's lock
across the call and clears the closure under it). The row, not each entity's door, carries that
protocol, so no entity can lack it. Measured why: the matching listener was the one entity whose
door did not wait, and zenoh-pico's own test of drop-on-undeclare found it.

P12. **zenoh-pico's programs are the behavioural specification.** Its API tests and examples run
on the release library in the environment its own CI gives them (a network namespace per
program, `lo` with multicast on). A program is judged only where it passes on zenoh-pico in that
same run (the control). A wz failure where the control passes is a defect of wz whatever its
cause. A program that fails on zenoh-pico itself by its construction is listed with that reason
and its feature is measured by a sibling program; it is never retried until it passes.

## 3. The layers

```
  C program
     │  z_* / zp_* / wz_ext_*            L4  façade        wz-capi-pico (one crate per preset ABI)
     ▼
  session core: entities, keys, routing  L3  session       wz-session-core (one table set)
     ▼
  transport: establishment, lease, sn,   L2  transport     wz-session-core::transport (sans-I/O)
  batching, fragmentation, reassembly
     ▼
  wire codec: views and lent encoders    L1  codec         wz-codecs (SCE generated)
     ▼
  driver: wait set, timers, read task    L0  driver        wz-runtime-coop + wz-runtime-posix/windows/zephyr
```

- **L1 codec.** Already at parity. Remaining: the generator's per-file panic locations keep
  identical decode functions from folding (SCE proposal P1/P2, `peek_array`/`peek_u8`).
- **L2 transport.** One implementation of establishment, lease, sequence numbers, batching and
  reassembly, judged from views (`ControlFacts`), driven by the SCE transport machine. It owns the
  link records (one pool), the tx batch slots and the reassembly chains.
- **L3 session.** One table set: key arena, declared key expressions, local entities
  (publishers, subscribers, queryables, tokens, matching listeners), remote declarations per face,
  pending queries and replies, interests. Routing/matching is a function over these tables. The
  callback of a local entity is stored in the entity's row (a C function pointer and context, or
  a Rust closure in a pool row); delivery calls it from the row, holding the row pinned, with no
  intermediate lane and no copy. A callback is a `Fn`, called through a shared borrow: a C
  closure's function, context and drop held as they are, a Rust closure an `Arc<dyn Fn + Send +
  Sync>` as upstream zenoh's. So it is called with no lock held, from any thread and from inside
  itself, as zenoh-pico calls it (a put a callback makes on its own subscriber's key reaches it
  again at once; `wz_ext.h`, "callbacks"), and it is let go of once, after its last call.
- **L0 driver.** The wait set, the timer wheel and the read task. It owns no protocol state. One
  task table, reserved at open.
- **L4 façade.** As P7. The port trait (`wz-capi-port`) disappears from the release build: the
  façade calls L3 of the one engine the build has (P5). The trait remains only where a second
  engine is genuinely selected at build time, and then as a generic parameter instantiated once,
  not a trait object.

The AP (tokio) engine and the router are other DRIVERS of the same L2/L3 (the router adds a
routing table to L3 behind a feature). No engine keeps protocol tables of its own.

## 4. What moves (from the measured structure)

| today | target |
|---|---|
| `wz-capi-coop` registry, targets, keyexprs, held queries, delivery lane, its own key table | L3 rows (one table each); the lane is removed: delivery calls the row's callback |
| `wz-capi-port` trait objects between doors and engine | direct calls into L3 of the build's engine |
| door marshals copying keys, payloads, options | views lent for the length of the call; a copy only when the program keeps the object |
| owned `InboundFrame` for control messages | `ControlFacts` views (landed on branch size-handshake) |
| `Rc`/`Arc`/`Mutex` per entity and per callback | one session lock at the façade (as zenoh-pico's session mutex); rows are plain data |
| `HashMap` and `Vec` growth after open | slot maps and fixed tables in the session region |
| per-file panic locations, `expect` messages | total functions (P6) |

## 5. Migration

Each phase keeps every test green, is measured against the ledger, and lands on its own:

1. **Ledger gate (P9).** `scripts/lib/size_ledger_gate.py`: area classification of both
   libraries, a ratio ratchet per area in `deploy/size_ledger.json`, run in Layer C1cs beside the
   total. Each byte of a function goes to the source file its line table names (the innermost
   location, so a helper fat LTO inlined into a door stays in the helper's area; inlined Rust
   core, alloc and std code goes to its innermost caller outside them, as the same work in C is
   the caller's own operators and macros, and only an out-of-line standard library body is
   language support), read from the
   library's one build, which carries its line tables and is measured and shipped with its debug
   information taken off (its executable sections held to the build's byte for byte); that file's crate::module (wz) or export path (zenoh-pico) is placed by
   the owner rules, and bytes of no source line are counted apart under a limit of their own. The
   section 1 table was read the earlier way, a whole body to the area of its symbol, which put
   inlined helpers in their caller's area. Its `--explain` says what holds an area's bytes (wz
   modules, source files, bodies and generic copies, zenoh-pico files), with the symbol reading's
   bytes beside each area, and keeps the whole lists as JSON to diff.
2. **Totality lints (P6)** on `wz-session-core`, `wz-capi-coop`, `wz-capi-pico`,
   `wz-runtime-coop` in non-test code, debt rows for the sites that remain, paid largest first.
   The lints are denied at each crate root; the modules that remain are the register of
   section 7, held by `scripts/lib/totality_debt_gate.py`.
3. **Transport views (L2).** Landed. Every participant's receive reads a JOIN and a transport OAM
   (a ZBuf body and ZBuf extensions included) by its view and keeps nothing of it: in place, into
   the receive's slot (`InboundFrame::Refused`), and on a group's walk. The decode that keeps
   them whole is the observer's (`parse_inbound`).
4. **One table set (L3).** The cooperative engine's registry, targets and key table fold into
   the session core's rows; the delivery lane is removed (callback in the row). The largest phase:
   one entity kind at a time (subscribers, then queryables, then tokens, then queries/replies).
5. **Thin façade (L4).** Doors call L3 directly; marshals lend views; the port trait leaves the
   release build.
6. **Thin driver (L0).** The engine crate keeps only the wait set, timers and the read task.
   Each fact the cooperative engine holds today goes to the layer that owns it:

   | fact (today in `wz-capi-coop`) | owner |
   |---|---|
   | the session lock, the read task (`start_reader`), the wait set (`LinkWaits`, `IdleWait`, the waits of `LinkRooms`, the clock's wake), the task and timer tables, the reservation of the region | L0 |
   | each face's link lifecycle (`LinkSupervisor`'s link states, `poll_face`, `dial`, `redial_later`), making a link's session (`start_wire`: its parameters, cookie key, admission, gates, cells), the reassembly Router, the endpoints' rows, a face's send state (the held drop, `sending_on`) and the hand-off of a dropped publish to the other faces | L2 |
   | the entity tables and their counters, the keys and the shared key ids, the query plane and pending gets, the round of deliveries, the declaration watches, the face reports, what a face that comes up is told again (`replay`), which faces a publish goes to | L3 |
   | the places of the ABI's handle and objects | L4 |

   Steps, each landing on its own:
   - **6a region.** The arena's plan is the sum of each layer's rows (`TransportRows` for L2,
     `SessionRows` for L3, `PlaceRows` for L4); L0 adds them up, reserves the region and opens
     one `TableLender` over it, which each layer lends its own tables from, with one refusal asked
     at the end.
   - **6b face lifecycle.** L2 holds a sans-I/O transport value that answers each step with
     effects (dial, a link opened, a face gone); L0 carries them out over the stack and the task
     table.
   - **6c sending.** L3's routing names the faces; L2's face sends, drops or hands the publish off,
     the hand-off kept in rows of the region.
   - **6d session state and delivery.** With phase 4.
7. **SCE codegen totality** (SCE change, reviewed by an SCE session, then a pin move).

Targets: every area at or under zenoh-pico's ratio 1.0 locked; allocations after open 0 in every
family; every cell of the host performance matrix WIN, on Linux and on pc3-win.

## 6. Rejected alternatives

- **Keep the layers and diet each.** Measured: 2–6 KB per change against a 200 KB excess.
- **A second, MCU-only engine.** Two engines diverge (`c-abi-engine-and-memory.md` E1); the target
  is one L2/L3 with several drivers.
- **nightly `build-std` with `panic_immediate_abort`.** It removes the panic machinery's bytes
  without removing the panics; P6 removes the panics. It stays a possible addition, not the design.

## 7. Totality debt register

The six crates deny the totality lints outside a test build, at their roots:

```rust
#![cfg_attr(
    not(test),
    deny(
        clippy::indexing_slicing,
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        clippy::unreachable,
        clippy::todo,
        clippy::unimplemented,
        clippy::arithmetic_side_effects
    )
)]
```

A module not yet converted is allowed the lints it still needs by name, at its declaration in the
crate root, under the line that names its row here (`// Totality debt TD-NNN
(docs/c-abi-architecture.md section 7).`). Nothing else may allow a totality lint: no allow on an
item, no inner allow, no `cfg_attr` or `expect` form, no `clippy::restriction`. New code is total,
so the register only shrinks: `scripts/lib/totality_debt_gate.py` refuses a row past the last id
given (TD-229) and holds the register's lint cells (0) to its ratchet, which a paid row
lowers in its own commit. The ratchet moves up only when a crate is brought under the lints, in a
commit that adds that crate's rows and changes no code: `wz-session-mcu` came in so with TD-207 to
TD-227, and `wz-capi-port` with TD-228 and TD-229. For the lints a text read decides (`unwrap_used`, `expect_used` and the panicking macros)
it also holds each row to its module's sites, both ways; indexing and arithmetic are held by the
build's clippy alone.

A module leaves the register when its sites are total functions: `get`, iterators and views of a
known length for indexing; checked or saturating arithmetic where the operands are not bounded by
construction; a refusal returned as a value where the old code panicked. Paid in the change that
switched the lints on, on the release library's path (`pico-client-coop-nostd`): in
`wz-runtime-coop` the critical sections, the timer table, the link storage, the task table, the
in-place reassembly and the datagram link; in `wz-capi-coop` the arena plan and the datagram
scout. Paid by the generator: the buffer pools `session_slot_pool_mcu` and
`reassembly_pool_mcu`, whose slot tables SCE reaches through a slot type with no value out of
range; `keyexpr_match`, whose algorithms compute every operation the interval analysis proved
through the forge runtime's `proven` functions, a shift by a count below its width included
(`proven::shl` and `proven::shr` in `keyexpr_relation_dp`); and `reset_generations`, whose
tagged result answers the record of a case as an `Option` (`as_duplicate`) where it panicked on
another case. A module the text read found no site in is not in the register.

The classes: **open**, hand-written code not converted yet; **in flight**, a module another branch
is restructuring now (the cooperative engine of step 4, the session core's entity modules, the pico
doors of step 5), converted as it lands;
**generated**, SCE output, whose totality is the generator's (step 7). `sites` is the text count of candidate sites when the row was made, which
orders the payment (largest first) and is not a measurement of what clippy reports. The rows of
`wz-session-mcu` count clippy's own reports instead, over the crate's default build, its build
with every feature, and its build with every feature but `session-slot`, which takes three modules
out; those of `wz-capi-port` over its default build and its build with every feature.

The register holds no row: no module of the six crates is allowed a totality lint.

| id | crate | module | lints | sites | class |
|---|---|---|---|---:|---|

A `WZ_POLICY_*` value no policy takes is refused with neither a panic nor an index: the helpers of
`policy.rs` answer `None` for such a word, a policy's value is found by its word in arrays that
share their length by type, and `policy_generated.rs`, which `wz_config.py` writes, refuses the
`None` in a constant assertion, the form `caps.rs` refuses a misspelt `WZ_LIMIT_*` value in. A
generated key table is checked the other way: the library answers `try_new`, and the
image's own crate, which `wz_key_set.py` writes, turns a refusal into the build error.

SCE's forge runtime makes a list whose bounds the build checks with constructors that cannot
fail: `Bounded::one` for a list of one entry, `Bounded::proven` for an array, and
`Bounded::widened` for a list held within bounds as narrow or narrower, each checking its bounds
in a `const`. `held_list::one_entry` and its fixed-capacity twin `lent_control::chain_of` are `Bounded::one`,
and `NamedKeyexpr` holds its body as a buffer within `NAMED_KEYEXPR_BYTES`, which
`Bounded::widened` lends to the `ZBuf`'s u32 bound.
The one QoS entry of a Push's outer chain (`lent_push::put_with_qos`) is `Bounded::one` too.
A `SessionZid` holds its bytes within one to sixteen, the bounds of the codec's zid field, and
lends them through `Bounded::as_bytes` (`SessionZid::as_field`), so the Scout's zid
(`scouting_host`) needs no check.
The multicast beacon (`multicast_join`) is total the same way: its QoS SN body is an
`ArraySink` the build admits only where the array holds the widest write
(`[[Vle<u64>; 2]; Priority::NUM]`, whose most bytes size the array), lent to the `ZBuf` as
`Bytes` with no check, and its zid is `SessionZid::as_field`. `encode_join_into` then refuses
only what its sink refuses, and `encode_join`, over a `VecSink` that refuses nothing, has no
refusal left.

The transmit buffer names its refusal (`TxBuf::Error`, `CodecError` for every buffer today). A body
a send hands its dispatch can refuse its own message (a key or a payload past its protocol bound),
whatever buffer it is written into, so a heap send answers that refusal as a value
(`SendWireError::Codec`, `PushOutcome::Refused`); an owned message, which its writer cannot
refuse, is framed through the codec's own vector sink, which refuses no write.

`bounded` left the register with one panic no lint names: `BoundedVec::remove` keeps
`Vec::remove`'s documented panic for an index past the end (an `assert!` on the lent backing,
which guards the unsafe move). Its value form, `Option<T>`, moves the callers in the cooperative
engine and the entity modules, and is converted with them.

## 8. The read: every face read where it lies, no round

Status: decision of the owner, 2026-11-25. It replaces the round of deliveries and the executor's
per-message pass in every build, and it is the structure the L0 driver of section 5 step 6 keeps.

### 8.1 What is measured, and why the round goes

The shipped nostd form (the pico preset's `zenoh-pico_defconfig` limits, features `os-posix`,
`link-udp`, `scout`, `peer`, `multicast-transport`, `query`, `queryable`, `liveliness`,
`liveliness-get`, `multi-thread`) reads one received message in 6,097 instructions against
zenoh-pico's 2,941 (2026-11-25, callgrind, exclusive costs). The preset turns `multi-thread` on,
and with it `threads`, `listen` (`peer`) and `group` (`multicast-transport`): every shipped
build reads through the round. The executor's pass and the round account for about 1.2 K of the
3.2 K excess: `run_among`, `poll_erased`, `step_after`, `Core::idle_wait`, `hand_out`,
`RoundDelivery::deliver_ref`, `Round::writable`, the walk of every holder's deadlines
(`ManyHolders`, `keepalive_deadlines`) and the wait set gathered again for each message.

The round exists because a read stepped every face of the session under the session's lock as
tasks of one local set, so a record could not be handed to its callback where it was read: the
lock was held, and the next face's task was still to run. Once each face is read on its own, under
a lock of its own, nothing stands between the record and its callback.

### 8.2 The structure

As zenoh-pico's read task per transport (`_zp_unicast_read_task`, `_zp_multicast_read_task`)
and upstream zenoh's receive task per link, a link's read decodes what the link holds as soon as
the link is ready and hands each record to its subscribers where it is read: no queue between the
decode and the callback, and no pass of an executor per message.

- **With `threads`**: every face (the dial role's link, each link a port accepted, each group)
  has a read task of its own, blocked on that face's link alone and stepping that face's pump.
  Faces are read in parallel; one face is read by one thread at a time.
- **Without `threads`**: the program's read waits on one wait set of every face and port, and
  steps the pump of the face that is ready, at once.
- Both are one body: the read of a set of faces (`read_faces`), whose set is one face for a face's
  task and every face for the program's read. There is no second path chosen by configuration at
  run time and no path kept for a session of one face.
- **The executor keeps the timers alone**: keep-alive, lease, a get's deadline, the pace of a
  replay, the periodic jobs and the reassembly sweep. It holds no link task and runs nothing per
  message. With `threads` its turn is the lease task's (zenoh-pico's `_zp_lease_task`); without,
  it is the wait set's timeout and the look after the wait.

### 8.3 Who owns each face's read

| face | read slot holds | made | read by (threads / one thread) |
|---|---|---|---|
| dial role | the link's pump (receive state, sequence numbers, the Router it stages fragments in), its records, the dial under way | at the open, kept for the session's life | its task / the program's read |
| accepted | the same, for the accepted link | by the port's accept | its task, started by the accept / the program's read |
| group | the group's pump (the members' receive order, their leases, the JOIN it reads) | at the join | its task / the program's read |
| port | the listener | at the open | the port's task / the program's read |

A face is two places: its **read slot** (the pump and the records being read) and its **send
place** (the wire: the batch being written, the transmit sequence numbers, the link's send half).
A read holds the slot for the length of one step of the pump; a send holds the send place for the
length of one write. A record read holds no send place, so a callback that sends on the face it is
called from finds the send place free.

Each lock is the form's (`LockForm`): the host's or the kernel's mutex with `threads`, a flag
without. What a face lends its link's session (its link state, its actions) is held under the
runtime's lock kind (`LockKind`); with `threads` that kind is a lock per value on every target,
the kernel's where there is no host lock, because a face's read reaches those values without the
session's lock.

### 8.4 Lock order

```
read slot  ->  send place  ->  session (Core)  ->  a row's latch
```

- A thread takes a face's place before the session's lock, never after. A step of a pump holds the
  read slot, and takes the session's lock once for each record it dispatches, letting it go before
  the record's callbacks are called.
- No thread holds two faces' read slots. A publish that reaches several faces takes their send
  places one at a time, each let go before the next is taken.
- Every other operation that sends (a declaration, an undeclaration, a get, a reply) holds the
  send place of every face whose place holds a link, in the order of the face table, and then the
  session's lock, as the writer of a big-reader lock takes every reader's lock in one order: what
  it tells any face under the session's lock is written through a place it holds, so nothing is
  left owed to a face whose place another holder had, and no retraction has to be kept for later.
  The places are taken in one order and a publish holds one at a time, so no two holders wait on
  each other. A place that held no link when the faces were walked is not held and is reached by
  a try, which nothing else holds in a build of one thread. With `threads` the walk holds a place
  whether or not it holds a link (step 4), so a link seated after the walk is held too.
- A callback is called with no lock held but the read slot of the face its record came from.

### 8.5 A callback that calls the session

- **A put, a get, a reply** take send places and the session's lock: never the read slot, so they
  finish while the read that called the callback holds it.
- **Another thread's put that waits for something** (a get's reply, a full batch flushed) finishes
  too: no read slot is held by the thread it waits on, except the one whose callback runs, and that
  thread holds no session lock.
- **A read from inside a callback** reads nothing: the slot is held, and the slot's owner word (the
  thread that holds it) tells a read on the same thread to return at once rather than wait for
  itself. A read on another thread reads the other faces.
- **An undeclare** waits for the calls of the row in flight on other threads (the row's latch) and
  not for the call of its own thread, so an undeclare inside the row's own callback returns, and the
  row is told gone once: the latch's last release lets the callback go.
- **A close** ends every face's life under the session's lock and asks each read to stop. A face's
  read sees the end once its step returns, lets the pump go, and its task ends; the close does not
  wait for a read on its own thread.

### 8.6 A change of a face's site without a deadlock

A face is added, taken out or given a new link by a thread that may hold the session's lock (an
accept found while the session settles, a lost link seen by the lease timer). Taking the face's
place there would invert the order of 8.4. So a change of a site is written into the face table
under the session's lock as a debt of the face (its ledger), and carried out after the lock is let
go, by taking the face's place first and the session's lock after it. The read that holds the
place pays the face's debts when it lets the place go; a read that finds its face ended lets the
pump go and does not take the session for it. A redeclare told on a face that came up is a debt of
the same kind: its first lap is the face's to run, and a declaration made before that lap is told
once, by the lap.

### 8.7 The life of an accepted face

1. The port's read (its task, or the program's read on the port's readiness) accepts the link and,
   under the session's lock, takes a free row of the face table, which the open reserved; a full
   table refuses the link and closes it.
2. The face's read slot and send place are made in that row's place, the face's handshake runs on
   its read, and the face is told up under the session's lock (its tables, its replay).
3. With `threads` the accept starts the face's read task from the task table the open reserved
   (one entry per face); a table with no entry left refuses the link as a full face table does.
4. When the link is lost or its lease ends, the face's life ends under the session's lock; its read
   sees the end, lets the pump go and stops; the face's tables go under the face's place and then
   the session's lock (8.6), and the row is free for the next accept once its last hold went.

### 8.8 The read of a group

A group is one face over one socket shared by many members. Its read slot holds the group's pump:
each datagram is read whole, its source names the member, the member's receive order and lease are
the pump's, and each record is dispatched under the session's lock and handed out where it is read,
as a unicast face's. A JOIN admits a member under the session's lock. What the session sends on the
group is written through the group's send place by the sending thread, as zenoh-pico's put writes a
multicast message on its caller's thread; the timers send the JOIN beacon and sweep the members'
leases.

### 8.9 What the read costs

Per message, a read pays the decode, one take of the session's lock for the dispatch, and the
callbacks. Per receive (every batch the link took from its stack in one read, 8.13) it pays one
wait, one reading of the clock (the lease's last-heard time, written by the read, read by the lease
timer) and one gathering of the pump's deadlines; no division of a 64-bit number, no executor pass.
Shipped nostd adds no runtime symbol.

### 8.10 Tests

Each holds for every form that builds it (`threads`, `listen`, `group`, and their absence):

- a callback in which another thread puts and waits for the put to be sent returns, and both end;
- a slow callback on one face does not hold up another thread's put on that face or another;
- an undeclare inside the row's own callback is told to the peer once, and the callback is let go
  once, after its last call;
- puts from several threads on one face reach the peer as whole frames, none interleaved;
- a listening peer delivers what each of its faces received in that face's order;
- a group's member is read and delivered with no unicast face open;
- the refusals: an accept past the face table, a read task past the task table, a read from inside
  a callback (reads nothing), a build without `threads` (the program's read steps every face).

### 8.11 Steps

Each lands on its own, builds and passes its tests:

1. **Locks.** The runtime's lock per value in every `threads` build, the kernel's mutex where there
   is no host lock; a hold of a place as a value (`HoldKind`) for the read slot and the send place.
2. **Accepted faces read directly.** The read slot and send place per face row; the port's accept
   and the face's read task; the site changes of 8.6.
3. **Groups read directly.**
4. **`threads` reads directly**: the read task per face; the executor keeps the timers.
5. **The round goes**: `round.rs`, `HandBack`, `RoundDelivery`'s round, the work form's step and
   its `cfg` (`wz_round`, `KEEP_THE_ROUND`).

Judged by the shipped form's instructions per message (the executor's and the round's 1.2 K gone),
its heap after open (none) and its text.

### 8.12 Rejected alternatives

- **A read path chosen at run time by configuration** (direct for one face, the round for more):
  two paths of delivery, each with its own ordering and reentrancy rules, both shipped.
- **A fast path for a session of one face**: the shipped preset is a listening peer in a group, and
  the one-face path would not be the one measured.
- **Keeping the executor and polling the link tasks less often**: the pass per message is what is
  measured; its count, not its rate, is the cost.

### 8.13 The 5a reading

Step 5a (the shipped preset, `group` and `threads`, reading every face directly with no round)
raised the shipped form's receive from 4,840.8 instructions a message (the round, at its last
commit) to 5,663.5, where 8.1 expected about 1,170 fewer. Both are callgrind's exclusive costs of
the subscriber of `pico-compare subprofile` (8 B, 10,000 messages past the first 2,000, at 10,000
messages a second, a listening peer read over TCP); zenoh-pico's is 3,755.1.

Each function's own cost a message, the round against 5a, gathered by what the function does
(the rows of 8 or more either way; the rest of each part is in its sum):

| part | round | 5a | change |
|---|---|---|---|
| driving the read: the wait, the look at the life, the step, the deadlines, the locks | 1,410 | 2,404 | +994 |
| handing the sample out: dispatch, the subscribers' rows, the callbacks' bookkeeping | 1,184 | 989 | -194 |
| decoding and the link (`walk_records`, `read_push`, `recv_with`, ...), the callback | 2,247 | 2,271 | +23 |
| total | 4,841 | 5,664 | +823 |

| driving, function | round | 5a | change |
|---|---|---|---|
| `CoopEngine::face_turn` (the look at the life, the step, `pump_turn` inlined) | 0 | 797 | +797 |
| `CoopEngine::wait_on_faces` (`link_wait`: the session's lock, every face's held input) | 0 | 412 | +412 |
| `run_body` (`read_faces` inlined: each face's slot tried, the faces' due, the groups) | 61 | 357 | +295 |
| `UnicastTransport::due_ms` (the pump's deadlines, gathered after each step) | 0 | 169 | +169 |
| `keepalive_deadlines`, `max_stamp`, `KeepaliveDeadlines::earliest` (the same) | 0 | 152 | +152 |
| `PosixClock::now_us`, `clock_gettime` | 58 | 145 | +87 |
| `CoopEngine::live`, `RawLock` lock, unlock, try | 82 | 210 | +128 |
| `DirectSlot::pay_site`, `LinkSupervisor::read_node`, `EndFlags::over` | 0 | 71 | +71 |
| `LinkSupervisor::waited` | 97 | 66 | -31 |
| `Core::idle_wait` | 255 | 0 | -255 |
| `CoopEngine::step_after` | 239 | 0 | -239 |
| `ExecutorState::run_among`, `classify`, `settle` | 272 | 0 | -272 |
| `poll_erased` (the session's task) | 142 | 0 | -142 |
| `Core::run_tasks_at` | 29 | 0 | -29 |
| `RoundGate` (`recv_with`, `takes_input`, `holds_input`, `lend`, `service`) | 128 | 0 | -128 |
| `StreamDriver::service`, `holds_input` | 31 | 3 | -28 |

| handing out, function | round | 5a | change |
|---|---|---|---|
| `CoopEngine::hand_lent_push` | 0 | 245 | +245 |
| `SessionTables::pin_subscribers`, `PinnedFanOut::new`, its `memset` | 0 | 240 | +240 |
| `keyexpr_intersects_asked`, `row_reaches`, `memcmp` (each row's key, each message) | 0 | 73 | +73 |
| `Deliveries::within`, `delivers`, `CoopEngine::deliver` | 48 | 222 | +174 |
| `CoopEngine::hand_row_by_row`, `SubscriberRow::hand`, `Core::next_in` | 0 | 107 | +107 |
| `DirectSink::event`, `drain_pushes` | 0 | 91 | +91 |
| `SubscriberPeer::dispatch_iteration_event` | 284 | 0 | -284 |
| `RoundDelivery::deliver_ref` | 226 | 0 | -226 |
| `CoopEngine::hand_out`, `send_handed_now`, `let_go_of_released` | 236 | 0 | -236 |
| `Round::writable`, `Table::place`, `Table::end_calls` | 194 | 0 | -194 |
| `FaceDispatch` (`event`, `end_records`) | 112 | 0 | -112 |

What it reads:

- **The handing out is cheaper**, by 194: the round's queue and its pass went, as 8.1 counted.
- **The driving is dearer, by 994, and it is paid once a batch.** A step of a face's pump took one
  unit of the link's input (`take_input_now`), so every batch the subscriber received paid a whole
  read: the wait worked out under the session's lock (`link_wait`, a walk of every face's held
  input, which answers at once while the link holds the next batch), the look at the face's life
  under the lock again (the clock, the life's input, the ledger, the periodic jobs), the change of
  the face's place owed, the step, the gathering of every deadline of the pump after it
  (`due_ms`, `keepalive_deadlines`), the facts told, the faces' due noted, and the groups'
  read. The round's executor pass, which 8.1 counted against it, was once a batch too, and lighter.
  8.9 had the read pay one wait and one reading of the clock for what one receive brings; it paid
  them once a batch. One receive brings about ten batches here: `strace` counts 0.1 `recvfrom`
  and 0.1 `poll` a message on both sides.
- **The subscriber snapshot did not move it** because the locks of the handing out were not where
  the cost was: the driving is.
- `walk_records_in_place`'s monomorph differs (the sink is `DirectSink` behind `LinkSink` over
  `CellRc<dyn SessionDatagramLink>`) but its own cost is 58 against the round's 56, the dynamic
  link's own calls add 5 to 8 a message, and the decoding's part is 23 apart: neither the walk's
  shape nor the dynamic link is the cause.

The cause is fixed where it lies: a step takes the batches its link already holds, one after
another, before the read ends (`CoopEngine::take_held_input`), as zenoh-pico's read of a peer's
socket processes what the read left behind its first batch before it waits again
(`vendor/zenoh-pico/src/transport/unicast/read.c` @
`_Z_RETURN_IF_ERR(_z_unicast_handle_remaining_data(ztu, curr_peer, extra_data, &to_read,`).
What the link holds bounds the run: the next batch read from the stack is the next read's, after
the wait and the look at the life, so what falls due is served as before. The driving is then paid
once a receive. Expected, at about ten batches a receive: the driving's 2,404 falls to about 240 a
message and the receive to about 3,500, under the round's 4,841 and zenoh-pico's 3,755; the
measurement is the main session's.

What remains of the driving once a receive, and the handing out's own costs (each row's key matched
for each message where the round read the cached match set, the fan-out zeroed for each sample, the
drain and its lock once a frame), are the next steps of the lane, each judged by the same
measurement.

#### After the fix of the step

Measured with the fix (the main session's `r5a-5`, the same subprofile): 5,687.1 a message, where
the run before it read 5,663.5, and zenoh-pico in the same run 2,723.2. The fix did not move it,
so in this harness a receive brings about one batch under callgrind (the `strace` run, whose
subscriber is slowed by every system call, is where ten came together). Each read is then paid
once a message, and the driving is what must fall below zenoh-pico's own, not be spread over a
burst.

Where a message's 5,687 go, from the inclusive costs of the frames of the read (each row the frame
less the one inside it):

| part | a message | what it is |
|---|---|---|
| the records: decode, dispatch, hand out, callback (`take_input`) | 2,512 | the work itself |
| the receive outside the records (`recv_with`, the framing's front) | 268 | once a receive |
| the step outside the receive (`face_turn` of the pump: lend, service checks, deadlines, facts) | 461 | once a step |
| the looks at the faces' lives (`CoopEngine::face_turn` less the step) | 1,110 | two faces turned |
| the wait (`wait_on_faces`: the session's lock, the faces' held input, `idle_wait`, `poll_on`) | 782 | once a read |
| the read's own lines and the task's loop (the rest of `run_body` and `entry`) | 554 | once a read |
| total | 5,687 | |

The records alone (2,512) are under zenoh-pico's whole message (2,723) by 211; everything else is
the driving, 3,175 a message, which zenoh-pico pays as a `select` and its read task's loop (its own
costs: `_zp_unicast_read_task_fn` 129, `_z_socket_wait_readable` 127, `select` 91,
`_z_unicast_wait_iter_next` 52). wz at or under zenoh-pico needs the driving cut to a few hundred and the
records trimmed by as much again. The driving's own costs a message, and the structure that pays
each:

| function (own cost) | a message | paid because |
|---|---|---|
| `CoopEngine::face_turn` and the slice walk, `NonNull`, `Option` lines inlined in it | 521 | each read turns the dial role's face too, which holds no link in a listening peer: a whole look (the lock, the clock, `next_input`, the ledger, the jobs) for nothing |
| `PosixClock::now_us`, `clock_gettime` | 145 | once a face turned: twice a read |
| `wait_on_faces` and its slice walk | 135 | the session's lock and a walk of every face's held input before each wait |
| `poll_on` | 84 | the `pollfd` set written for the link, the port and the wake, each wait |
| `CoopEngine::live` | 75 | the session's lock taken by the wait, each look, the push's dispatch and the drain: about five a message |
| `run_body` (`read_faces` inlined): the slice walk, its own lines, the atomics | 174 | three walks of every row of the face table a read (the slots tried, the turned faces, the faces' due), ten rows where one face holds a link |
| `Deliveries::within`, `deliver`'s closure | 141 | the deliveries entered after each face's turn and after each drain |

The structure that removes them, largest first, each a step of the lane judged by the same
measurement:

1. **A face at rest is not turned.** A face whose slot holds no pump, no dial and no opened link,
   whose life stands idle or closed with no wake, and whose Router holds no chain, has nothing a
   look would move: its read passes it over while another face is turned, whose look serves the
   session's own bookkeeping (the ledger, the gets, the jobs, the ports), and turns it all the same
   when no face is. The rest is noted by the face's own look, under the session's lock, and ends
   when the slot is given a link. The dial role's face of a listening peer is such a face. Expected:
   about half of the 1,110 of the looks, and one of the two readings of the clock (about 500).
2. **The walks of the face table stop at the last row that holds a face.** The rows past it hold
   none, and a read walks the table three times; the bound is kept where the rows are held and let
   go of, under the session's lock. Expected: most of the 174 of the walks in `run_body`.
3. **The wait taken without the session where a link holds input**, and the deliveries entered
   once a read rather than once a face and once a drain, after the two above are measured.

This is not the fast path of one face 8.12 rejects: every face is in the one walk, and a face is
passed over by what its own slot says, whatever the session's preset.
