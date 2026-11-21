<!--
SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
-->

# Release notes: wz pico C ABI library for Windows

## What this release carries

- The pico C ABI library for one width of Windows, in a debug and a release build, each with its
  import library and its symbols (`.pdb`): `x86_64-pc-windows-msvc` in the x64 package,
  `i686-pc-windows-msvc` in the x86 one. "This build" below names the target of this package.
- zenoh-pico's API as zenoh-pico's own headers declare it, for this library's build: the
  multi-threaded arm, the unstable API, publication and subscription, queries and queryables,
  liveliness, scouting, unicast and multicast transports over tcp and udp, the advanced publisher
  and subscriber, and connectivity events.
- wz's extension doors of the build's profile, `host-peer-ext`: a transport the program supplies;
  the policies and limits of a session chosen when it opens, by a configuration document;
  end-to-end protection, its receiving judge and a judge per sender; supervision of periodic
  streams; message instances; the message catalog; the replay cache and the declaration watch;
  and key ids shared by every node of a deployment. `README.md` lists their doors.
- The examples of the C API, a message catalog sample, the usage notes, the licence of the
  library and the notices of every package it links.

## How it was checked

Before this package was published, the workflow that built it extracted the zip, held every file
to `manifest.json`, then, with MSVC's `cl` of the package's width, compiled the static assertions
that each type a program allocates holds what the library writes into it, and compiled every
example and a package check program against the package's own headers and import library, for
the debug and the release build, and ran each. The check program holds the library to the
conformance digest of `build-statement.json` and reads `config\message-catalog.sample.json5`
through it.

## Known limits

- Sessions run on the cooperative engine and are stepped by their read task, as in zenoh-pico's
  multi-threaded arm. zenoh-pico's single-threaded arm, where the program steps the session with
  `zp_read` and `zp_spin_once` and callbacks run inside its calls, is a build of its own and not
  this package: `README.md`, "Threads and callbacks".
- Gossip, which a session told of a node by a peer uses to dial it, is not in this build: the pico
  C API never starts it, and zenoh-pico has no such plane. Its peers are found by scouting and the
  endpoints the program configures.
- The library and its import library are not code-signed.
- The library is linked with `/Brepro`, so its image carries no build time. Whether two builds of
  one commit give the same bytes has not been measured.
