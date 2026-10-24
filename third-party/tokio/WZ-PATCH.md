# tokio 1.52.3 as patched by wz

This directory is `tokio` 1.52.3 from crates.io (MIT, see `LICENSE`), with one change, selected by
`[patch.crates-io]` in `crates/Cargo.toml`. It is carried whole (sources and tests, so that the
manifest's explicit `[[test]]` targets exist), except its `Cargo.lock`, `CHANGELOG.md` and `docs/`.

## The change

`src/net/unix/ucred.rs`, marked `WZ PATCH`: reading the credentials of a Unix-socket peer.

tokio takes the NetBSD implementation for every QNX target, and that one imports `unpcbid` and
`LOCAL_PEEREID` from `libc`. `libc` defines them only on the io-pkt network stack (`target_env`
`nto70`, `nto71`); on io-sock (`nto71_iosock`, `nto80`) it does not, so tokio does not compile there
(`unresolved imports libc::unpcbid, libc::LOCAL_PEEREID`).

The patch keeps the NetBSD implementation for io-pkt and gives io-sock a new `impl_unsupported`,
which returns `ErrorKind::Unsupported`. It deliberately does NOT use tokio's existing `impl_noproc`:
that one reports `uid 0, gid 0` as a success, which would tell a caller that every peer is root.

Nothing else changes: on every other target the file is what upstream ships, and on io-pkt the arm
is the one upstream has. wz does not call `UnixStream::peer_cred`.

Whether io-sock has an equivalent of `LOCAL_PEEREID`, and under which name, is in the SDK's headers,
which were not read when this was written, so no value is guessed.

## Removal

Delete this directory, the `[patch.crates-io]` entry and the workspace `exclude` entry once a
released `tokio` (or `libc`) compiles for `aarch64-unknown-nto-qnx710_iosock`. The change to send
upstream is the one above, with the constant read from the header.

Files that are not upstream's: this file only.

This copy is 5.7 MB and has to be re-made at every tokio upgrade (the `[patch]` pins a version): a
cost accepted while the change is not upstream, and the reason to send it.
