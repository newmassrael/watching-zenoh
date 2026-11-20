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

## Running a program

Put `wz_capi_pico.dll` beside the program's executable or on its `PATH`; keep the `.pdb` beside
the DLL for a debugger. The library links the Microsoft C runtime dynamically (`vcruntime140.dll`
and the Universal C runtime), which a machine has with the Visual C++ Redistributable of the
package's width (x64, or x86 for the x86 package, which a 64-bit Windows runs a 32-bit program
with).

## Threads and callbacks

The library runs each session on threads of its own (the tokio engine, the only engine of the
Windows library). It reads, keeps the lease and runs every callback on those threads, whether or
not the program starts the read task. A program written for zenoh-pico's single-threaded arm,
whose callbacks run only inside its own calls, must therefore lock what its callbacks share with
its own thread, or read samples through a ring or fifo channel and pull them with the channel's
`try_recv`. `zp_read`, `zp_send_keep_alive` and `zp_spin_once` answer for a live session and do no
work. The order a program with its own scheduler calls the run API in is written in `wz_ext.h`,
in the section "the periodic run API", and `examples\periodic.c` runs it.

## wz's own doors in this build

Every door is declared in `wz_ext.h` with its arguments, its results and its refusals; a door of a
capability this build does not have is declared there too and does not link. The capabilities of
this build are listed in `RELEASE-NOTES.md` and `build-statement.json`. Its extension doors:

| Capability | Doors | What they do |
|---|---|---|
| app-transport | `wz_ext_transport_*`, `wz_ext_config_transport` | a network stack the program supplies, in place of the system's sockets |
| e2e-sender | `wz_ext_e2e_sender_*` | end-to-end protection of a message: a frame built under a profile, a counter per stream |
| e2e-receiver | `wz_ext_e2e_receiver_*` | the receiving judge of protected frames: a verdict per frame, the payload always handed on |
| e2e-sender-demux | options of `wz_ext_e2e_receiver_new` | the judge kept one per sender, keyed by the frame's sender identity |
| e2e-supervision | `wz_ext_stream_supervisor_*` | a deadline per periodic stream, a loss told once, error counts |
| instance-key | `wz_ext_instance_keyer_*` | the instance of a message read from fields of its payload, a last value per instance |
| message-catalog | `wz_ext_message_catalog_*` | a deployment's messages declared once as JSON5, and the senders, receivers and supervision rows made from it |
| replay-cache | `wz_ext_replay_publisher_*`, `wz_ext_replay_subscriber_*` | what each publisher last sent, replayed to a subscriber that arrives later |
| replay-cache | `wz_ext_decl_watch_*` | the declarations a session's peers make and retract, told to the program |
| shared-key-ids | `wz_ext_config_key_ids`, `wz_ext_config_key_wire_form_for` | key ids every node of a deployment shares, used with no declaration first |
| (every build) | `wz_ext_conformance_digest` | the digest of this build's configuration, equal to `build-statement.json`'s `digest` |
| (every build) | `wz_ext_config_device_requires`, `wz_ext_redeclare`, `wz_ext_get_to_peer` | what an open asks of the system; declarations re-sent; a get addressed to one node |

Each door returns zenoh-pico's result codes, and wz's own two outside their range:
`WZ_EXT_ERR_POLICY_OFF` (-2), a call the build's policy does not allow, and
`WZ_EXT_ERR_UNSUPPORTED` (-3), a call this engine or build does not do. A door that refuses a text
it reads (a profile, a catalog) writes why into the `z_owned_string_t` it is handed, which the
program drops.

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
* `wz-config.schema.json`: the policies and limits a stage after the build may decide. Their values
  in this build are in `build-statement.json`.

## Examples

Each example is one C file that exchanges between two sessions of one process, over the loopback
or, in `own_transport.c` and `pico_app_transport.c`, over a stack the program implements, and
exits 0 when every check held. Every example but `pico_app_transport.c` includes
`example_common.h` from the same directory. Build one as above, for instance
`cl /std:c11 /DZENOH_WINDOWS /I include examples\e2e.c release\lib\wz_capi_pico.lib`.

| File | What it shows |
|---|---|
| `profiles.c` | publication, subscription and a query under the upstream profile |
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
