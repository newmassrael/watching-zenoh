// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! GENERATED FROM `captures/corpus/` -- DO NOT EDIT.
//!
//! The counts of the corpus and the weights computed from them
//! (`docs/flow-zenoh-verdict.md` section 6.2), written by
//! `zenoh_calibration_tests::the_generated_calibration_is_current`, which
//! fails when this file is not what the corpus gives. Regenerate with
//! `scripts/regen-calibration.sh` and commit the result with the capture
//! that moved it. The counts are those of a build that opens lz4.
//!
//! The corpus: 140 zenoh files in 22 groups, 18 null files in 18 groups.

use crate::zenoh_evidence::model::measured::Member;
use crate::zenoh_evidence::Weight;

/// `log2(1 - e)` of the cookie echo, in millibits.
pub const COOKIE_ECHO_FIDELITY: i64 = -7;

/// The weight of a cookie that differs.
pub const COOKIE_ECHO_VIOLATED: Weight = Weight::both(-7_671);
/// The weight of two Inits of opposite kinds.
pub const INIT_ROLES_CONFIRMED: Weight = Weight::both(993);
/// The weight of two Inits of the same kind.
pub const INIT_ROLES_VIOLATED: Weight = Weight::both(-6_676);
/// The weight of a version byte that is this reader's.
pub const VERSION_HEADER: Weight = Weight::both(7_996);
/// The weight of a version byte that names another version.
pub const VERSION_FOREIGN: Weight = Weight::both(-8_668);
/// The weight of a unit read whole.
pub const UNIT_EXPLAINED: Weight = Weight::pair(967, 3_546);
/// The weight of a unit with bytes left over.
pub const UNIT_RESIDUAL: Weight = Weight::pair(-14_012, -12_594);
/// The weight of a unit that did not decode.
pub const UNIT_UNDECODED: Weight = Weight::pair(-14_012, -13_124);
/// The weight of a stream direction that framed a unit.
pub const FRAMING_HELD: Weight = Weight::pair(2_838, 6_453);
/// The weight of a stream direction that lost its framing.
pub const FRAMING_LOST: Weight = Weight::pair(-7_611, -7_594);

/// The null protocols, in the manifest's order.
pub const NULL: [Member; 18] = [
    Member {
        file: "lan-dns.pcap",
        units: [26, 32, 320],
        framing: [0, 0],
    },
    Member {
        file: "lan-mdns.pcap",
        units: [13, 8, 15],
        framing: [0, 0],
    },
    Member {
        file: "lan-ssdp.pcap",
        units: [0, 0, 26],
        framing: [0, 0],
    },
    Member {
        file: "stack-mqtt.pcap",
        units: [6, 28, 7],
        framing: [0, 84],
    },
    Member {
        file: "stack-rtps.pcap",
        units: [0, 2, 147],
        framing: [0, 0],
    },
    Member {
        file: "stack-coap.pcap",
        units: [0, 24, 144],
        framing: [0, 0],
    },
    Member {
        file: "stack-someip.pcap",
        units: [0, 28, 278],
        framing: [0, 0],
    },
    Member {
        file: "stack-quic.pcap",
        units: [0, 22, 0],
        framing: [0, 0],
    },
    Member {
        file: "busylan-dhcp.pcap",
        units: [16, 98, 133],
        framing: [0, 0],
    },
    Member {
        file: "busylan-ntp.pcap",
        units: [5, 183, 0],
        framing: [0, 0],
    },
    Member {
        file: "busylan-wsd.pcap",
        units: [5, 12, 155],
        framing: [0, 0],
    },
    Member {
        file: "stack-http.pcap",
        units: [0, 0, 0],
        framing: [0, 0],
    },
    Member {
        file: "stack-tls.pcap",
        units: [0, 0, 0],
        framing: [0, 0],
    },
    Member {
        file: "stack-http-post.pcap",
        units: [0, 0, 0],
        framing: [0, 50],
    },
    Member {
        file: "stack-redis.pcap",
        units: [0, 0, 0],
        framing: [0, 120],
    },
    Member {
        file: "stack-postgres.pcap",
        units: [0, 531, 0],
        framing: [0, 48],
    },
    Member {
        file: "stack-ssh.pcap",
        units: [33, 20, 40],
        framing: [0, 34],
    },
    Member {
        file: "stack-smtp.pcap",
        units: [0, 0, 0],
        framing: [0, 20],
    },
];

/// The zenoh files' framing units: read whole, residual, undecoded.
pub const ZENOH_UNITS: [u64; 3] = [49_505, 0, 0];

/// The zenoh files' stream directions captured from their start: framing held, lost.
pub const ZENOH_FRAMING: [u64; 2] = [584, 0];

/// The zenoh files' cookie echoes: matched, differing.
pub const ZENOH_COOKIE: [u64; 2] = [609, 0];

/// The zenoh files' Init pairs: of opposite kinds, of one kind.
pub const ZENOH_ROLES: [u64; 2] = [611, 0];

/// The zenoh files' version headers: this reader's, another.
pub const ZENOH_VERSIONS: [u64; 2] = [1_222, 0];
