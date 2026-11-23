# Measured verification of the cooperative engine's crates

How wz shows that the code of its cooperative engine is correct and safe, beyond each test's own
assertions: what the tests reach (coverage), whether the threads they run race (ThreadSanitizer),
whether any access is out of bounds or after free (AddressSanitizer), and whether the unsafe code
that lends places of an arena is defined behaviour (the Miri interpreter). Each is a lane of
`scripts/run-ci.sh`, a job of the `ci` workflow and a unit of the fleet (`bx --checks ci`), and each
says below what it proves and what it does not.

## What is measured, and in which builds

The crates are the engine's: `wz-session-core`, `wz-session-mcu`, `wz-runtime-coop`,
`wz-capi-coop`, `wz-capi-pico`, and for the interpreter `wz-capi-port`. A crate is not tested in
its default features alone: a figure about a build nobody ships says little about the ones that
ship. `scripts/lib/verify_plan.py` names each unit (a crate and where its feature set comes from)
and resolves the set when the lane runs:

| source | the set | why |
|---|---|---|
| `library` | the pico C library's profile (`configs/profiles/host-peer-ext.conf`, resolved by the pinned Kconfig interpreter, as the release package builds it), and for each crate under it the features cargo enables for it in that build | the C library is what a program links |
| `kit:<image>` | the features cargo enables for the crate in a kit image's build (`deploy/zephyr-admin-node/rust` as the fixed-memory client that asks, `deploy/zephyr-capi-pico/rust` with zenoh-pico's multi-threaded arm), from the image's lock file | the kit images are what a board runs |
| `args` | a set written in the plan | a path a lane exists to look at (the cooperative engine's read task with `multi-thread`, the host lock), or a unit the interpreter can run |

A crate a build does not reach fails the lane; it is never measured as an empty set. Run
`bash scripts/verify.sh units <lane>` to print a lane's units as they resolve.

Every lane builds with the nightly `crates/wz-fuzz/rust-toolchain.toml` pins, the one nightly of
the tree: branch coverage, the sanitizers, `-Zbuild-std` and the interpreter exist only there.
Moving it is a commit of its own, for the fuzz targets and these lanes together.
`scripts/verify.sh` installs it and the components a lane needs.

## Layer Vcov: line, branch and function coverage

The units' tests are built with `-Cinstrument-coverage -Zcoverage-options=branch`, every process
writes its profile, and the merge is exported over every test executable with `llvm-cov export`.
`scripts/lib/coverage_floor_gate.py` sums each crate's files under `crates/<crate>/src/` (without
the files that hold only tests) and holds lines, branches and functions to the crate's row of
`deploy/coverage_floor.json`: a fall past the tolerance fails, a rise passes and prints the
tighter row to commit, a row not filled yet is NOT-MEASURED, which fails the lane. The functions no
test reached are written to `target/verify/coverage/uncovered.txt` (the hosted job uploads it and
`summary.json` as the artifact `coverage`): each is a test to write.

The same table holds a row for each door module of the doors the pico C ABI has and zenoh-pico does
not (`modules`, a module named by its file, its figure that file and the files of its directory),
so that one door's share cannot fall behind a rise elsewhere in its crate; those rows are the
coverage floor of section 8 of `docs/release-proof-pico-windows.md`. A module with no branch has
none to cover and passes that measure; a module the export holds no line of fails, as a crate does.

Proves: the share of each crate's lines, branches and functions the tests of all five crates
execute, in the shipped feature sets, and that the share does not fall unnoticed; and the same of
each door module of the pico C ABI's own doors.

Does not prove: that an executed line was checked by an assertion (Layer Cmut measures that, by
mutation, `docs/mutation-testing.md`); anything about code only another feature set compiles;
lines reached only through the C programs, whose processes are not among the exported executables.
A test module inside a source file counts with that file.

## Layer Vtsan: ThreadSanitizer

The units' tests (leg `tests`) and the C examples of the library (leg `programs`, the release
package's programs built by `scripts/pico-c-program.sh` with `WZ_PICO_SANITIZER=thread`) run with
`-Zsanitizer=thread`, the standard library rebuilt under it, `halt_on_error=1`. Any report fails,
including one a test's child process printed.

The tests include `files::ext_handles_across_threads` of `wz-capi-pico`'s integration tests: the
handles of the additional doors (an end-to-end sender and receiver, an instance keyer, a message
catalog and a payload schema) each shared by several threads at once, as their documentation
allows, so that the lock each handle holds its state behind is what this lane reads.

Proves: no data race and no lock-order inversion on any interleaving the runs took, in the
multi-threaded arm of the engine, its host lock, the C ABI's threads and the handles of its
additional doors, with std's own synchronisation seen.

Does not prove: freedom from races on interleavings no run took (the detector observes; it does not
explore); anything about the MCU builds, whose concurrency is interrupts and a single core.

## Layer Vasan: AddressSanitizer

The same units and programs with `-Zsanitizer=address` and the standard library rebuilt under it.
Leak detection is off: the tests leak the areas they lend on purpose, and a leak is not a
memory-safety defect.

The leg `programs` then runs each C program again under the C compiler's UndefinedBehaviorSanitizer
(`WZ_PICO_SANITIZER=undefined`: `-fsanitize=undefined -fno-sanitize-recover=undefined`), the library
built without a sanitizer, so the run sees none of the lane's flags: a program's signed overflow, a
misaligned, null or out-of-bounds access through a pointer the library handed it, or a shift past
its width, ends the run with its report.

Proves: no out-of-bounds access, use after free, double free or use after return on the paths the
runs took, in Rust code, in std where wz handed it memory, and in the C programs; and no undefined
behaviour the C compiler's sanitizer detects in the C programs on those paths.

Does not prove: anything about paths not run; leaks; uninitialised reads (MemorySanitizer, which
this tree does not run); undefined behaviour in Rust code, which no sanitizer reads (the
interpreter's lane, Layer Vmiri, reads it for its units).

## Layer Vmiri: the interpreter

The units whose unsafe code lends places of an arena (`wz-session-core`'s `key_arena`,
`bounded` in both backings, the lent records; `wz-capi-coop`'s delivery lane and arena plan) and the
host lock made in its place (`wz-capi-port`'s `os` with `std`) run under Miri, selected by test
name. A test of those modules that opens the host's sockets is marked
`#[cfg_attr(miri, ignore = "...")]`: the interpreter has no sockets. Leaks are not judged, for
the reason above.

Proves: on the runs taken, no undefined behaviour the interpreter detects: an access outside an
allocation or with a pointer whose provenance does not allow it, a borrow the aliasing model
refuses, an uninitialised read, a data race between its threads.

Does not prove: anything about tests not selected, or code that calls the host's C library or a
socket; the aliasing model is the interpreter's default, and a pointer pattern only another model
accepts is reported as it reads under that one.

## What the lanes have found

Each finding is named by the lane that found it, with where it was repaired.

| lane | finding | repair |
|---|---|---|
| Vtsan | Three C examples of the library (`examples/c/profiles.c`, `examples/c/transports.c`, `tests/c/pico_app_transport.c`) waited for a get to end by polling a `volatile` flag that the reply closure's drop sets on a session thread: a data race in the program, which no library can give a happens-before edge to. | The examples wait under a mutex (`ex_counter_t`, a `z_owned_mutex_t`), as zenoh-pico's own `examples/unix/c11/z_get.c` waits for its drop under a mutex and a condition variable. |
| Vtsan | A data race on a key's reference count in the cooperative engine: `z_undeclare_subscriber` drops the subscriber's entry outside the session lock (`crates/wz-capi-coop/src/engine.rs`, the undeclare's `drop((entry, callback))`) while the read task takes a declaration that names the same key (`absorb_declare_view`, `crates/wz-session-core/src/pubsub.rs`). | Open: repaired by a change of its own. Until it lands the hosted step of Layer Vtsan is soft (`deploy/soft_jobs.json`), and it becomes a gate once it reads green on two consecutive main runs. |
| Vcov | The in-memory link the engine's tests run sessions over (`wz-session-mcu`'s `memory`) lent no outbound slot, so a session of the C library's build, which sends only from storage its link lends, could not send its handshake, and a test of the admission gate never opened. | The memory link lends two slots, as every link of the cooperative runtime does. |
| Vcov | The tests of the lent control records fed the build that lends every record (the MCU kit's) owned frames, which that build asserts it never raises, and one walk test named a record kind the kit's build does not lend. | The tests feed such a build the one form it has and pin the lent result; the walk test is gated on the kinds it walks. |

## Running them

Each lane is opt-in in a full sweep, as Layers S and Cmut are:

```
bash scripts/run-ci.sh --layer Vcov     # or Vtsan, Vasan, Vmiri; WZ_RUN_LAYER_VERIFY=1 adds all four
bx --checks ci -- python3 scripts/lib/runci_plan.py --only Vcov,Vtsan,Vasan,Vmiri
```

The first measurement fills `deploy/coverage_floor.json`: after a Vcov run, `python3
scripts/lib/coverage_floor_gate.py --fill target/verify/coverage/export.json` prints the `crates`
and `modules` objects to commit. A row is never written by hand, and `--fill` never loosens a filled one.
