# ring 0.17.14 as patched by wz

This directory is `ring` 0.17.14 from crates.io (Apache-2.0 AND ISC, see `LICENSE`,
`LICENSE-BoringSSL` and `LICENSE-other-bits`), with one change, selected by `[patch.crates-io]` in
`crates/Cargo.toml`.

## The change

`src/rand.rs`, one place: `target_os = "nto"` joins the list of operating systems for which
`SystemRandom` uses the `getrandom` crate.

ring lists the systems whose entropy source it trusts, and QNX Neutrino is not among them, so on
`aarch64-unknown-nto-qnx710` and `aarch64-unknown-nto-qnx710_iosock` `ring::rand::SystemRandom`
implements no `SecureRandom` and everything that asks rustls for a random value fails to compile
(`the trait bound SystemRandom: SecureRandom is not satisfied`). `getrandom` 0.2, the version ring
depends on, supports QNX through `/dev/urandom` (its documented table has a `*-nto-qnx*` row), so the
fix is the entry, not a new source of randomness.

Nothing else changes. On every other target the file is what upstream ships. The C and assembly
that ring compiles are untouched; on QNX they are compiled by the SDP's `qcc`, which is the C
compiler `scripts/qnx-toolchain-env.sh` names.

What the entry does not give: ring detects the CPU's cryptographic extensions at run time only on
the systems it knows (Linux, Android, Apple, Windows, Fuchsia), so on QNX it uses what the target
enables at compile time. That is a speed question, not a correctness one, and it has not been
measured on a board.

The device is NOT assumed to have a random source because a table says so: `/dev/urandom` is the
board's service, which no header declares. The platform row says that in its `os_provides` help.

## Removal

Delete this directory and the `[patch.crates-io]` entry once a released `ring` lists
`target_os = "nto"` for `SystemRandom`. The change to send upstream is the one above.

Files that are not upstream's: this file only. `Cargo.toml` is the normalised one the registry ships;
the registry's `Cargo.lock` is not carried.
