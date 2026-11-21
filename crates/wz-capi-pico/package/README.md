<!--
SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
-->

# wz pico C ABI library for Windows

This package holds `wz_capi_pico.dll`, a library that exports zenoh-pico's C API (`z_*`, `zp_*`)
with watching-zenoh's session engine behind it, and wz's own extension doors (`wz_ext_*`). A
program written for zenoh-pico compiles against the headers of this package and links this
library in place of zenoh-pico's. The packaging script is `scripts/lib/pico_windows_package.py`
in the watching-zenoh repository; this file is `crates/wz-capi-pico/package/README.md` there.

The library is made for one width of Windows, which the package's name (`windows-x64` or
`windows-x86`) and the `target` of its `manifest.json` (`x86_64-pc-windows-msvc` or
`i686-pc-windows-msvc`) both state. A 64-bit program links the x64 package and a 32-bit program
the x86 one; a program cannot load a library of the other width. The two packages are made from
the same commit and profile and carry the same headers.

## What is in the package

| Path | What it is |
|---|---|
| `release/bin/wz_capi_pico.dll`, `release/bin/wz_capi_pico.pdb` | the optimised library and its symbols |
| `release/lib/wz_capi_pico.lib` | its import library, which a program links |
| `debug/bin/`, `debug/lib/` | the same three files of the debug build |
| `include/zenoh-pico.h`, `include/zenoh-pico/` | zenoh-pico's own headers, with the `config.h` of this library's build |
| `include/wz_ext.h` | the declarations of wz's own doors |
| `examples/` | C programs that use the library, each a complete exchange that checks itself |
| `config/` | a message catalog sample and the schemas of the catalog and of the run-time configuration |
| `build-statement.json` | what this build is: every capability with whether it is in, every limit and policy value |
| `RELEASE-NOTES.md` | what this release carries, and the facts of this build |
| `LICENSE`, `LICENSE-COMMERCIAL.md` | the licence of the library |
| `THIRD-PARTY-NOTICES.md`, `licenses/` | the packages the library links, and their licence texts |
| `manifest.json` | the size and SHA-256 of every other file of the package |

The debug and release libraries have the same file name, so a program takes one directory pair,
`release\` or `debug\`, for both its link and its run.

## Building a program

From the Visual Studio command prompt of the package's width, in the package directory: "x64 Native
Tools Command Prompt" for the x64 package, "x86 Native Tools Command Prompt" for the x86 one
(`vcvarsall.bat x64` or `vcvarsall.bat x86`):

```
cl /std:c11 /DZENOH_WINDOWS /I include my_program.c release\lib\wz_capi_pico.lib
```

* `ZENOH_WINDOWS` selects zenoh-pico's Windows platform header, as zenoh-pico's own Windows build
  does.
* Compile with MSVC's `cl`. zenoh-pico's Windows header names an inline function `__asm__`, which a
  compiler in GNU mode reads as a keyword. The package's own test compiles every example with `cl`.
* Compile against THIS package's `include\` and no other zenoh-pico installation.
  `include\zenoh-pico\config.h` states the switches this library was built with (its unstable API,
  its multi-threaded arm, its planes and sizes), which decide the size of every type a program
  allocates. A program compiled against another `config.h` allocates structs of another size, and
  the library writes past them.
* A program that calls a `wz_ext_*` door includes `wz_ext.h` after `zenoh-pico.h`. A program that
  does not include it is portable to zenoh-pico.

## One library or two

A package is in one of two forms, which its name and the `form` of its `manifest.json` state. Both
are built from the same sources and the same profile, and a program is written the same for both.

* The one library (`form` `single`): `wz_capi_pico.dll` holds everything above, zenoh-pico's API,
  the session engine and every `wz_ext_*` door.
* Two libraries (`form` `split`, `-split` in the package's name): `wz_capi_pico.dll` is the core
  (zenoh-pico's API, the engine, the doors of the core and the extension interface
  `wz_ext_interface_*`), and `wz_capi_pico_ext.dll` holds the doors of the additional features
  (`wz_ext_e2e_*`, `wz_ext_stream_supervisor_*`, the instance keys, the replay cache, the message
  catalog and payloads, and `wz_ext_additional_interface`). The additional library needs the core
  and reaches it only through its C API: `release\lib\` and `debug\lib\` hold both import libraries,
  and a program links both, the core's first:

  ```
  cl /std:c11 /DZENOH_WINDOWS /I include my_program.c release\lib\wz_capi_pico.lib release\lib\wz_capi_pico_ext.lib
  ```

  and runs with both DLLs beside it or on its `PATH`. Across the two: a handle is opaque to the
  library that did not make it; each library frees what it allocated (a refusal string a door of
  the additional library writes is the core's, dropped with `z_string_drop`; storage the program
  hands a door stays the program's); no object of a C runtime crosses between them; and
  `wz_ext_additional_interface` says which version of the extension interface the additional
  library needs and whether the core answers it. The additional library is not loaded at all over
  a core of another major version of the interface, whose `wz_ext_interface_major_<n>` it does not
  find.

## Running a program

Put `wz_capi_pico.dll` beside the program's executable or on its `PATH`; keep the `.pdb` beside
the DLL for a debugger. The library links the Microsoft C runtime dynamically (`vcruntime140.dll`
and the Universal C runtime), which a machine has with the Visual C++ Redistributable of the
package's width (x64, or x86 for the x86 package, which a 64-bit Windows runs a 32-bit program
with).

## Threads and callbacks

The library's engine is the cooperative one: a session moves only when it is stepped, as a
zenoh-pico session does. zenoh-pico has two arms, and so does this library. In the single-threaded
arm the program steps the session itself with `zp_read` and `zp_spin_once`, and every callback
runs inside those calls. In the multi-threaded arm, which is this package's (its `config.h` defines
`Z_FEATURE_MULTI_THREAD`), the session is stepped by its read task: a thread `z_open` starts
unless the open's options set `auto_start_read_task` to false, and which `zp_start_read_task` and
`zp_stop_read_task` start and stop. The read task reads, keeps the lease and runs every callback;
while it is stopped the session reads nothing and sends no keep-alive, and a put still writes, on
the caller's thread. A callback runs with no lock of the library held, so it may call into the
session; what it shares with the program's own thread the program locks, or it reads samples
through a ring or fifo channel and pulls them with the channel's `try_recv`. A program written for
the single-threaded arm links a build of that arm, which this package is not: the two arms differ
in the size of types a program allocates. The order a program with its own scheduler calls the
run API in is written in `wz_ext.h`, in the section "the periodic run API", and
`examples\periodic.c` runs it.

## wz's own doors in this build

Every door is declared in `wz_ext.h` with its arguments, its results and its refusals; a door of a
capability this build does not have is declared there too and does not link. The capabilities of
this build are listed in `RELEASE-NOTES.md` and `build-statement.json`. Its extension doors:

| Capability | Doors | What they do |
|---|---|---|
| app-transport | `wz_ext_transport_*`, `wz_ext_config_transport` | a network stack the program supplies, in place of the system's sockets |
| config-document | `wz_ext_config_document` | a configuration document handed to a config: the profile, policies and limits a session opens under, chosen at run time |
| e2e-sender | `wz_ext_e2e_sender_*` | end-to-end protection of a message: a frame built under a profile, a counter per stream |
| e2e-receiver | `wz_ext_e2e_receiver_*` | the receiving judge of protected frames: a verdict per frame, the payload always handed on |
| e2e-sender-demux | options of `wz_ext_e2e_receiver_new` | the judge kept one per sender, keyed by the frame's sender identity |
| e2e-supervision | `wz_ext_stream_supervisor_*` | a deadline per periodic stream, a loss told once, error counts |
| instance-key | `wz_ext_instance_keyer_*` | the instance of a message read from fields of its payload, a last value per instance |
| message-catalog | `wz_ext_message_catalog_*` | a deployment's messages declared once as JSON5, and the senders, receivers and supervision rows made from it |
| message-payload | `wz_ext_payload_schema_*`, `wz_ext_message_payload_*` | a catalog message's payload set and read by field path under `.proto` files read at run time, its protobuf bytes encoded and decoded |
| replay-cache | `wz_ext_replay_publisher_*`, `wz_ext_replay_subscriber_*` | what each publisher last sent, replayed to a subscriber that arrives later |
| replay-cache | `wz_ext_decl_watch_*` | the declarations a session's peers make and retract, told to the program |
| shared-key-ids | `wz_ext_config_key_ids`, `wz_ext_config_key_wire_form_for` | key ids every node of a deployment shares, used with no declaration first |
| (every build) | `wz_ext_conformance_digest` | the digest of this build's configuration, equal to `build-statement.json`'s `digest` |
| (every build) | `wz_ext_config_policy`, `wz_ext_config_profile` | one policy, or the profile, of the sessions a config opens, stated from code |
| (every build) | `wz_ext_config_device_requires`, `wz_ext_redeclare`, `wz_ext_get_to_peer` | what an open asks of the system; declarations re-sent; a get addressed to one node |

Each door returns zenoh-pico's result codes, and wz's own two outside their range:
`WZ_EXT_ERR_POLICY_OFF` (-2), a call the build's policy does not allow, and
`WZ_EXT_ERR_UNSUPPORTED` (-3), a call this engine or build does not do. A door that refuses a text
it reads (a profile, a catalog) writes why into the `z_owned_string_t` it is handed, which the
program drops. The message payload's doors answer a refused call with `WZ_EXT_ERR_PAYLOAD_PATH`
(-20), `_TYPE` (-21), `_RANGE` (-22), `_ABSENT` (-23) or `_WIRE` (-24), and
`wz_ext_message_payload_refusal` gives the sentence of the last one.

## Configuration

A session is configured as zenoh-pico configures it: `z_config_default`, then `zp_config_insert`
with zenoh-pico's keys (`Z_CONFIG_MODE_KEY`, `Z_CONFIG_CONNECT_KEY`, `Z_CONFIG_LISTEN_KEY`, ...).
What is wz's own is in `config\`:

* `message-catalog.sample.json5`: a message catalog of two nodes, a protected and supervised
  periodic message and an event message with a replay depth and a segment profile. Every name and
  value in it is made up. It is the catalog the library's own tests read, and the package's test
  reads it through `wz_ext_message_catalog_new` of the library it ships with. A program passes the
  text of its own catalog to that door.
* `message-catalog.schema.json`: the shape of a catalog, with the words of each refusal.
* `wz-config.schema.json`: the policies and limits a stage after the build may decide, the shape
  of the `wz` member of a configuration document (next section). Their values in this build are
  in `build-statement.json`.

## Choosing policies and limits at run time

One library serves every profile: the policies and limits of a session are chosen when it opens,
by a configuration document handed to its config before `z_open`:

```c
z_owned_session_t session;
z_owned_config_t config;
z_config_default(&config);
zp_config_insert(z_config_loan_mut(&config), Z_CONFIG_CONNECT_KEY, "tcp/192.0.2.1:7447");
z_result_t rc = wz_ext_config_document(z_config_loan_mut(&config),
    "{ wz: { profile: \"upstream\", policies: { \"entity-timestamp-opt-in\": \"on\" } } }");
if (rc != Z_OK) { /* refused: the config is as it was */ }
z_open(&session, z_config_move(&config), NULL);
```

The document is the zenoh JSON5 document a zenoh-c program opens with; this library reads only
its `wz` member, so one file configures both. A program reads the file and hands its text to
`wz_ext_config_document`; a second call replaces the first. The members of `wz`, whose every
name and value `config\wz-config.schema.json` lists:

* `profile`: a named set of policy values the session starts from. `upstream` states every
  policy at upstream's behaviour, whatever this build's defaults are.
* `policies`: a policy's id mapped to one of its values' ids, over the profile.
* `limits`: a session limit's id mapped to a whole number or `"unbounded"`, over the build's.
* `key-ids`: the key ids every node of the deployment shares (the shared-key-ids capability).

A session's policies are composed lowest first: this build's defaults, the profile
(`wz_ext_config_profile`'s, else the document's), the document's `policies`, then each
`wz_ext_config_policy` statement. A config handed no document opens under this build's defaults.

The door checks the document when it is handed, as the open will compose it, and answers
`_Z_ERR_CONFIG_INVALID_VALUE` (-89), leaving the config with what it held before, for: text
that is no JSON5 object; a `wz` member that is not an object, that names a member other than
these four, or that names one twice; a profile, a policy, a value or a limit this build does
not have; a value of a policy that this build's domain leaves out; a policy or a limit only the
build decides; a limit of a runtime rather than of a session; a limit's value that is neither a
whole number nor `"unbounded"`; a refused part of `key-ids`. A NULL config or text answers
`_Z_ERR_NULL`. The code is the whole answer: the door names no reason. `examples\profiles.c`
hands it four refused documents and checks that each leaves the config as it was.

## Examples

Each example is one C file that exchanges between two sessions of one process, over the loopback
or, in `own_transport.c` and `pico_app_transport.c`, over a stack the program implements, and
exits 0 when every check held. Every example but `pico_app_transport.c` includes
`example_common.h` from the same directory. Build one as above, for instance
`cl /std:c11 /DZENOH_WINDOWS /I include examples\e2e.c release\lib\wz_capi_pico.lib`.

| File | What it shows |
|---|---|
| `profiles.c` | publication, subscription and a query under the build's defaults, then under two profiles chosen when the sessions open (`wz_ext_config_document`), and the documents the library refuses |
| `transports.c` | tcp, udp and a multicast group over the system's sockets; the group is joined only when `WZ_EXAMPLE_GROUP_IFACE` names an interface in `#iface=` form (on Windows, an adapter's interface GUID) |
| `own_transport.c` | the same three over a network stack of the program's own, registered with `wz_ext_transport_*`: the guide to plugging in a TCP/IP stack that is not the system's, with partial sends, would-blocks, an asynchronous connect and a refused one |
| `pico_app_transport.c` | the same three over a transport the program supplies, with partial sends and would-blocks injected |
| `batching.c` | batching on and off, and a flush |
| `e2e.c` | end-to-end protection across a session: a sender, a receiver and its verdicts |
| `supervision.c` | supervision of a periodic stream that stops |
| `periodic.c` | a program's own periodic task over the run API |
| `keyed.c` | a keyed topic: two instances of one message on one key expression, told apart by a field of the payload, with the last value of each |
| `history.c` | history for a late subscriber: the last frames a publisher sent, replayed oldest first, then the live ones, each judged by an end-to-end receiver |

## Checking the package

`manifest.json` lists every other file with its size and SHA-256. In PowerShell,
`Get-FileHash -Algorithm SHA256 release\bin\wz_capi_pico.dll` prints the hash to compare. The
repository's `scripts/lib/pico_windows_package.py --verify <package>` checks every file at once,
and reports a file that differs, one that is missing and one the manifest does not list.

## Licence

The library is watching-zenoh, under the watching-zenoh Non-Commercial License 1.0 (`LICENSE`) or a
commercial licence (`LICENSE-COMMERCIAL.md`). Read section 4 of `LICENSE` before using it in or
for an organisation. The packages it links keep their own licences: `THIRD-PARTY-NOTICES.md`.
