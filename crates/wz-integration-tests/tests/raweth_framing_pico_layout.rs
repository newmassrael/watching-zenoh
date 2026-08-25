// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! R311y579 (G9) — wz's raweth framing against zenoh-pico's OWN structs.
//!
//! [`wz_session_core::raweth_link`] reproduces a header that pico builds as a C
//! struct and `memcpy`s onto the wire. Every property that makes those bytes
//! what they are — the 16 / 20-byte widths, the field offsets, the fact that
//! `ethtype` rides the host's byte order while `data_length` does not — is a
//! property of a C compiler's layout of a type in `vendor/zenoh-pico`, not of
//! anything wz can decide. Transcribing them into Rust constants and asserting
//! the Rust constants against each other proves nothing.
//!
//! So this test compiles a C probe against pico's real header, runs it, and
//! compares:
//!
//! * `sizeof` and `offsetof` for both header structs, against wz's constants;
//! * `_ZP_ETH_TYPE_VLAN` and `_ZP_MAX_ETH_FRAME_SIZE`, against wz's;
//! * and — the part the constants cannot cover — the BYTES of a header pico
//!   itself filled in, against the bytes wz's encoder produces for the same
//!   inputs. A layout that matched on every size and offset could still
//!   disagree on byte order; only the byte compare sees that.
//!
//! The probe forces `Z_FEATURE_RAWETH_TRANSPORT` on after including pico's
//! `config.h`, because THIS TREE'S pico build has raweth OFF (the CMake
//! configure product at `target/zenoh-pico-build` pins it to 0). That is also
//! why there is no runtime pico leg here: with the feature off, the built
//! `libzenohpico` carries no raweth code to drive. The header is compiled, not
//! linked, so the probe needs nothing from the library.
//!
//! `#[ignore]` (toolchain + provisioned-headers dep): needs a C compiler and
//! `scripts/build-zenoh-pico-cli.sh` to have produced the generated
//! `config.h`. Run via `--ignored`.

use std::collections::HashMap;
use std::process::Command;

use wz_integration_tests::common::{project_root, zenoh_pico_include_dirs};
use wz_session_core::raweth_link::{
    frame, RawEthHeader, ETH_HEADER_LEN, ETH_TYPE_VLAN, ETH_VLAN_HEADER_LEN, MAX_ETH_FRAME_SIZE,
};

/// The MACs and values the probe and wz both use. Shared here so the two sides
/// cannot drift into comparing different inputs, which would make a match
/// meaningless.
const DMAC: [u8; 6] = [1, 2, 3, 4, 5, 6];
const SMAC: [u8; 6] = [17, 18, 19, 20, 21, 22];
const ETHTYPE: u16 = 0x72e0;
const VLAN_TAG: u16 = 0x0102;
const PAYLOAD: &[u8] = b"abc";

const PROBE_C: &str = r#"
#include <stdio.h>
#include <string.h>
#include <stddef.h>
#include <arpa/inet.h>
#include "zenoh-pico/config.h"
/* This tree's pico build pins the feature to 0, which would #if-out the very
   structs the probe reads. Forced on AFTER config.h so the declarations exist;
   nothing here links pico, so no feature-gated symbol is needed. */
#undef Z_FEATURE_RAWETH_TRANSPORT
#define Z_FEATURE_RAWETH_TRANSPORT 1
#include "zenoh-pico/link/transport/raweth.h"

int main(void) {
    printf("ETH_HEADER_LEN=%zu\n", sizeof(_zp_eth_header_t));
    printf("ETH_VLAN_HEADER_LEN=%zu\n", sizeof(_zp_eth_vlan_header_t));
    printf("OFF_ethtype=%zu\n", offsetof(_zp_eth_header_t, ethtype));
    printf("OFF_data_length=%zu\n", offsetof(_zp_eth_header_t, data_length));
    printf("OFF_vlan_type=%zu\n", offsetof(_zp_eth_vlan_header_t, vlan_type));
    printf("OFF_vlan_tag=%zu\n", offsetof(_zp_eth_vlan_header_t, tag));
    printf("VLAN_TYPE=%u\n", (unsigned)_ZP_ETH_TYPE_VLAN);
    printf("MAX_ETH_FRAME_SIZE=%u\n", (unsigned)_ZP_MAX_ETH_FRAME_SIZE);
    printf("MAC_LEN=%u\n", (unsigned)_ZP_MAC_ADDR_LENGTH);

    unsigned char d[6] = {1,2,3,4,5,6}, s[6] = {17,18,19,20,21,22};
    /* Built exactly as src/transport/raweth/tx.c:138-146 builds it. */
    _zp_eth_header_t h;
    memset(&h, 0, sizeof(h));
    memcpy(h.dmac, d, 6);
    memcpy(h.smac, s, 6);
    h.ethtype = 0x72e0;
    h.data_length = htons((uint16_t)3);
    printf("PLAIN=");
    for (size_t i = 0; i < sizeof(h); i++) printf("%02x", ((unsigned char *)&h)[i]);
    printf("\n");

    /* ...and the VLAN arm exactly as tx.c:124-136 builds it. */
    _zp_eth_vlan_header_t v;
    memset(&v, 0, sizeof(v));
    memcpy(v.dmac, d, 6);
    memcpy(v.smac, s, 6);
    v.vlan_type = _ZP_ETH_TYPE_VLAN;
    v.tag = 0x0102;
    v.ethtype = 0x72e0;
    v.data_length = htons((uint16_t)3);
    printf("VLAN=");
    for (size_t i = 0; i < sizeof(v); i++) printf("%02x", ((unsigned char *)&v)[i]);
    printf("\n");
    return 0;
}
"#;

/// Compile and run the probe, returning its `key=value` output.
fn run_probe() -> HashMap<String, String> {
    let dir = tempfile::tempdir().expect("probe tempdir");
    let src = dir.path().join("reth_probe.c");
    let bin = dir.path().join("reth_probe");
    std::fs::write(&src, PROBE_C).expect("write probe source");

    let cc = std::env::var("CC").unwrap_or_else(|_| String::from("cc"));
    let mut command = Command::new(&cc);
    // ZENOH_LINUX selects pico's platform header; without it `platform.h`
    // stops at `#error "Unknown platform"` before any raweth type is seen.
    command.arg("-DZENOH_LINUX=1");
    for dir in zenoh_pico_include_dirs() {
        command.arg("-I").arg(dir);
    }
    let output = command
        .arg("-o")
        .arg(&bin)
        .arg(&src)
        .current_dir(project_root())
        .output()
        .unwrap_or_else(|e| panic!("could not run {cc}: {e}"));
    assert!(
        output.status.success(),
        "the pico raweth probe did not compile:\n{}",
        String::from_utf8_lossy(&output.stderr)
    );

    let run = Command::new(&bin).output().expect("run the probe");
    assert!(run.status.success(), "the probe exited {:?}", run.status);
    String::from_utf8_lossy(&run.stdout)
        .lines()
        .filter_map(|l| l.split_once('='))
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect()
}

#[track_caller]
fn usize_of(probe: &HashMap<String, String>, key: &str) -> usize {
    probe
        .get(key)
        .unwrap_or_else(|| panic!("the probe did not report {key}: {probe:?}"))
        .parse()
        .unwrap_or_else(|e| panic!("{key} is not a number: {e}"))
}

#[test]
#[ignore = "toolchain dep: needs a C compiler and the generated pico config.h"]
fn wz_raweth_header_layout_matches_the_pico_struct() {
    let probe = run_probe();
    assert_eq!(usize_of(&probe, "MAC_LEN"), 6);
    assert_eq!(usize_of(&probe, "ETH_HEADER_LEN"), ETH_HEADER_LEN);
    assert_eq!(usize_of(&probe, "ETH_VLAN_HEADER_LEN"), ETH_VLAN_HEADER_LEN);
    assert_eq!(usize_of(&probe, "MAX_ETH_FRAME_SIZE"), MAX_ETH_FRAME_SIZE);
    assert_eq!(usize_of(&probe, "VLAN_TYPE"), ETH_TYPE_VLAN as usize);
    // wz writes the MACs first and the two u16s last, in both widths; the
    // offsets are what make that the same placement pico's compiler chose.
    assert_eq!(usize_of(&probe, "OFF_ethtype"), 12);
    assert_eq!(usize_of(&probe, "OFF_data_length"), 14);
    assert_eq!(usize_of(&probe, "OFF_vlan_type"), 12);
    assert_eq!(usize_of(&probe, "OFF_vlan_tag"), 14);
}

#[test]
#[ignore = "toolchain dep: needs a C compiler and the generated pico config.h"]
fn wz_raweth_frame_bytes_match_the_bytes_pico_puts_on_the_wire() {
    let probe = run_probe();

    // The plain arm. wz's `frame` fills data_length from the payload, which is
    // what pico's tx.c does; the probe hard-codes htons(3) for the same reason.
    let wz_plain = frame(&RawEthHeader::new(DMAC, SMAC, ETHTYPE, 0), PAYLOAD).expect("frame");
    let pico_plain = probe.get("PLAIN").expect("probe PLAIN");
    assert_eq!(
        hex(&wz_plain[..ETH_HEADER_LEN]),
        *pico_plain,
        "wz's plain raweth header is not the bytes pico's struct lays out"
    );
    assert_eq!(&wz_plain[ETH_HEADER_LEN..], PAYLOAD);

    // The VLAN arm.
    let wz_vlan = frame(
        &RawEthHeader::new(DMAC, SMAC, ETHTYPE, 0).with_vlan(VLAN_TAG),
        PAYLOAD,
    )
    .expect("frame vlan");
    let pico_vlan = probe.get("VLAN").expect("probe VLAN");
    assert_eq!(
        hex(&wz_vlan[..ETH_VLAN_HEADER_LEN]),
        *pico_vlan,
        "wz's VLAN raweth header is not the bytes pico's struct lays out"
    );

    // The byte compare above is the discriminating one, and this says why:
    // on a little-endian host the ethtype lands byte-SWAPPED and the length
    // does not. An encoder that made both big-endian would pass every size
    // and offset assertion in the sibling test and fail here.
    #[cfg(target_endian = "little")]
    {
        assert!(
            pico_plain.contains("e072"),
            "pico did not swap the ethtype, so this host's assumption is wrong: {pico_plain}"
        );
        assert!(
            pico_plain.ends_with("0003"),
            "pico did not put the length big-endian: {pico_plain}"
        );
    }
}

fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    let mut out = String::new();
    for b in bytes {
        let _ = write!(out, "{b:02x}");
    }
    out
}
