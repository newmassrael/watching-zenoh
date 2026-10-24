# socket2 0.6.3 as patched by wz

This directory is `socket2` 0.6.3 from crates.io (MIT OR Apache-2.0, see `LICENSE-MIT` and
`LICENSE-APACHE`), with one change, selected by `[patch.crates-io]` in `crates/Cargo.toml`.

## The change

`src/sys/unix.rs`, three places, all about the TCP keep-alive idle time on QNX:

`libc` defines `TCP_KEEPALIVE` for QNX only on the io-pkt network stack (`target_env` `nto70` and
`nto71`). On io-sock (`nto71_iosock`, `nto80`) it defines neither `TCP_KEEPALIVE` nor `TCP_KEEPIDLE`,
so `socket2` 0.6.3 does not compile there (`unresolved import libc::TCP_KEEPALIVE`). The patch
makes the QNX arm io-pkt only and, on io-sock, makes `TcpKeepalive::with_time` fail at the set and
`keepalive_time` fail at the get with `ErrorKind::Unsupported`. Nothing else changes: on every other
target the file is what upstream ships, and on io-pkt the arm is the one upstream has.

The value of the missing constant is NOT guessed, and it was not known when the patch was written.
It has since been read: the SDK's io-sock `netinet/tcp.h` declares `TCP_KEEPIDLE` as 256 ("start
keepalives after this period") and no `TCP_KEEPALIVE`, so the option exists there under the Linux
name. The patch does not use it yet: that would define a constant `libc` does not carry, which is
what the upstream change is for.

wz itself never sets or reads the keep-alive idle time through `socket2` (no call in `crates/`), so
no wz behaviour depends on it.

## Removal

Delete this directory, the `[patch.crates-io]` entry and the workspace `exclude` once a released
`socket2` (or `libc`) compiles for `aarch64-unknown-nto-qnx710_iosock`. The change to send upstream
is the one above, with the constant read from the header.

Files that are not upstream's: this file only. `Cargo.toml` is the normalised one the registry ships.
