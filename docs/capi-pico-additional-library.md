# The pico C ABI as one library or two

The pico C ABI library (`wz-capi-pico`) carries zenoh-pico's API over a wz engine and wz's own doors.
Among those doors, the doors of the additional features are a layer over the rest, the core:

- end-to-end protection (`e2e.rs`, `e2e_sender.rs`, `e2e_receiver.rs`),
- reception supervision per stream (`stream_supervision.rs`),
- instance keys (`instance_key.rs`, `proto_file.rs`),
- the replay cache (`replay_publisher.rs`, `replay_subscriber.rs`),
- the message catalog and its payloads (`message_catalog.rs`, `message_payload.rs`),
- the interface version the doors were built against (`additional.rs`).

This document says how that layer is held apart from the core, how the same sources build as one
library or as two, what crosses between the two, and how the two forms are held to one behaviour.

## The layer

A door names the core only as a library linked through C could: an `extern "C"` function, a
constant, a static or a `#[repr(C)]` type of a public module of the crate root, or an item of the
extension interface (`crates/wz-capi-pico/src/ext_interface.rs`, `wz_ext_interface_*`), the
versioned C interface through which the doors read what the core holds beyond the pico API: a
session's facts, a payload's bytes in place, and the core's in-callback mark. Of the other crates
of the stack a door names only stateless libraries (`wz-app-frame`, the models and pure values of
`wz-session-core`). No file of the core names a door, comments included.
`scripts/lib/layer_direction_gate.py` holds both directions over the sources (its rules 4 to 8 and
`EXTENSION_DOORS`).

## Two forms from one source

| Form | Libraries | How it is built |
|---|---|---|
| one library (the default) | `wz_capi_pico` | `wz-capi-pico` with the profile's features |
| two libraries | `wz_capi_pico`, `wz_capi_pico_ext` | the core: `wz-capi-pico` with the same features, compiled with `--cfg wz_additional_apart`; the doors: `wz-capi-pico-ext` with the features of that list it declares |

`wz_additional_apart` takes the door modules out of the core's crate root and nothing else: the
extension interface stays, since the other library calls it. It is a cfg given to the core's own
compile (`cargo rustc -p wz-capi-pico -- --cfg wz_additional_apart`) and not a cargo feature,
because it takes exports away, and a feature that removes what another crate of a build relies on
breaks feature unification. The core alone states the same capabilities as the one library and
answers the same conformance digest: the pair is the build the profile describes.

`wz-capi-pico-ext` writes no door. Its crate root compiles the door files of `wz-capi-pico/src`
again, by path, with the same cfgs, and gives them what they name:

- `crate::result`: the core's `result.rs`, constants only;
- `crate::ffi`: the core's `ffi/boundary.rs`, the panic guard and the thread-crossing pointer,
  which hold no state and which each library compiles for itself;
- every other `crate::<module>`: a module of `src/core_view.rs`, the core's C ABI as the doors
  name it, declared as a C program declares it from the headers and imported from the core library.

The features of the doors' library are the doors' own and the arm of the C types they read
(`unstable-api`, `local-queryable`, `query`, `event-ring`, `multi-thread`), each the core's
feature of that name; both libraries are built from one list. On Windows the imports name the core's
DLL (`raw-dylib`); elsewhere `WZ_CAPI_PICO_CORE_DIR` names the directory of the core the doors'
library is linked to, which it then records as a library it needs.

`scripts/pico-additional-forms.sh` builds both forms on Linux; `scripts/lib/pico_windows_package.py
--form split` makes the Windows package of the second form, both DLLs with their import libraries
and symbols.

## What crosses between the two

The boundary is an hourglass: a narrow C interface between two libraries that each keep their own
state, allocator and runtime.

1. **Handles are opaque.** A value of the core that a door holds (an owned string, a key
   expression view, a closure, a subscriber, a queryable, the copy of a loaned session or publisher
   a replay door keeps) is declared in `core_view.rs` as so many words of storage, the core's size,
   with no field the door could read; a type only pointed at is a type of no size. A door never
   holds a type of no size by value: in the doors' library the copy would hold nothing, and a
   pointer to it would point into the door's own memory, which the core reads as its value
   (`layer_direction_gate.py` rule 8). Fields are declared only where the C header declares them
   for a program to set (`z_get_options_t`) or read (`wz_ext_session_facts_t`,
   `wz_ext_decl_event_t`, `z_id_t`). A door's own handles (`wz_ext_owned_e2e_sender_t`, ...) are a
   word the core never reads.
2. **What a library allocates, that library frees.** A door boxes its own state and frees it in its
   own `*_drop`. A refusal string a door writes is made by the core's `z_string_copy_from_substr`
   and dropped by the program with the core's `z_string_drop`. A payload a door puts is made by the
   core's `z_bytes_copy_from_buf` and moved into the core's put. Storage the program hands a door (a
   replay cache's rings, a subscriber's table of publishers) stays the program's and is never freed
   by either library.
3. **No object of a language runtime crosses.** No `FILE`, no heap block of one C runtime for the
   other to free, no Rust value: a door and the core exchange C scalars, pointers to `#[repr(C)]`
   storage and C function pointers. Each library links its own Rust standard library and allocator.
4. **The interface's version is asked.** `wz_ext_interface_version` answers the core's major and
   minor version. The doors call `wz_ext_interface_major_1`, a function named by the major
   version, so the system's loader does not load the doors' library over a core of another major
   version, and a function added in a later minor version is an import the loader resolves by name
   too. At run time `wz_ext_additional_interface` answers the version the doors were built against
   and whether the core answers one they run on.

## How the two forms are held to one behaviour

- **The view is the core's.** `crates/wz-capi-pico/src/additional_view_tests.rs` compiles
  `core_view.rs` into the core's tests and holds each declaration to the core's own: the size,
  alignment and field offsets of each type, the value of each constant, and the signature of each
  imported function, type for type. A declaration that drifts fails the core's build.
- **The doors keep to the interface.** `layer_direction_gate.py`, as above; a door that named a
  core item the view does not declare would not compile in the doors' library.
- **The wire is the same.** `crates/wz-integration-tests/tests/it/files/pico_additional_split_wire.rs`
  compiles one scenario (`crates/wz-capi-pico/tests/c/additional_split_scenario.c`: the interface
  version, an end-to-end sender and receiver, a replay cache served to a subscriber that comes
  later, a refusal string dropped across the boundary) against each form, runs it through a
  recording relay between its two sessions, and compares the network messages each side sent. The
  scenario's zenoh ids are fixed, so the ids and the sequence numbers derived from them are the same
  in every run; the messages are compared as a multiset per side and channel, since which of two
  threads of a session sends first is the scheduler's in either form. Layer Epico builds both forms
  (`scripts/pico-additional-forms.sh`) and runs the test with `WZ_PICO_FORMS_REQUIRE=1`, so a form
  missing there is a failure; any other run that finds no forms says so and passes.
- **A program sees one library.** The Windows package's test compiles every example and the check
  program against each form's package and runs them; the check program asks
  `wz_ext_additional_interface` of the pair it links.
