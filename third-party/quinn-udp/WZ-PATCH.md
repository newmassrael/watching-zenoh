# quinn-udp 0.5.14 as patched by wz

This directory is `quinn-udp` 0.5.14 from crates.io (MIT OR Apache-2.0, see `LICENSE-MIT` and
`LICENSE-APACHE`), with changes in two files, selected by `[patch.crates-io]` in `crates/Cargo.toml`.

## The change

`src/unix.rs` asks the socket to deliver the IPv4 type-of-service byte (`IP_RECVTOS`) and decodes it
when it arrives. `libc` declares `IP_RECVTOS` for no QNX target, so the crate does not compile for
`aarch64-unknown-nto-qnx710` or `aarch64-unknown-nto-qnx710_iosock` (`cannot find value IP_RECVTOS in
crate libc`, two places). The two QNX network stacks differ, and the patch follows the SDP headers:

- **io-sock** (`target_env` `nto71_iosock`, `nto80`): `netinet/in.h` declares `IP_RECVTOS` as 68, the
  number FreeBSD uses and the stack derives from. The patch defines that constant in `src/unix.rs`
  for `target_os = "nto"` and leaves every use as upstream has it.
- **io-pkt** (`nto70`, `nto71`): `netinet/in.h` declares no such option. The two uses are left out
  there with the new `nto_iopkt` alias of `build.rs`, the way upstream leaves them out on OpenBSD and
  NetBSD, so an io-pkt socket does not request the IPv4 TOS and ECN is read from the IPv6 traffic
  class only.

On every other target the files are what upstream ships.

What this is not: a run. That the io-sock stack delivers a received TOS as a control message of type
`IP_RECVTOS`, as FreeBSD does and as the existing arm of the crate expects, follows from the header
and the lineage and has not been observed on a board.

## Removal

Delete this directory and the `[patch.crates-io]` entry once a released `libc` declares `IP_RECVTOS`
for QNX with the io-sock stack, or a released `quinn-udp` stops requiring it there. The change to
send upstream is the one above, with the io-pkt exclusion.

Files that are not upstream's: this file only. `Cargo.toml` is the normalised one the registry ships;
the registry's `Cargo.lock` is not carried.
