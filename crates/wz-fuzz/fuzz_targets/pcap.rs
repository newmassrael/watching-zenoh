// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! Every door that reads a whole capture file (`wz_dissect_pcap_*`), on one
//! file.
//!
//! Input: eight bytes of arguments, then the file. A capture from `captures/`
//! with eight bytes in front is a seed (`scripts/fuzz.sh seed`).
//!
//! | byte | argument |
//! |------|----------|
//! | 0    | the limits preset (`limits`) |
//! | 1    | how many messages a flow shows (`max_messages_shown_per_flow`) |
//! | 2, 3 | the packet `wz_dissect_pcap_frame_bytes` is asked for |
//! | 4    | the link type the packet and option doors are asked about |
//! | 5    | the selector, from `SELECTORS` |
//! | 6    | the declarations, from `DECLARATIONS` |
//! | 7    | reserved |

#![no_main]

use std::ffi::CString;

use libfuzzer_sys::fuzz_target;
use wz_capi_dissect::*;
use wz_fuzz::{
    buffer_door, limits, link_type, string_door, OnFailure, Reader, DECLARATIONS, SELECTORS,
};

fuzz_target!(|data: &[u8]| {
    let mut r = Reader::new(data);
    let limits = limits(r.u8());
    let shown = usize::from(r.u8());
    let packet = u64::from(r.u16());
    let link = link_type(r.u8(), u32::from(r.u8()));
    let selector = CString::new(SELECTORS[usize::from(r.u8()) % SELECTORS.len()]).unwrap();
    let declarations =
        CString::new(DECLARATIONS[usize::from(r.u8()) % DECLARATIONS.len()]).unwrap();
    let file = r.rest();
    let (b, n) = (file.as_ptr(), file.len());
    let (sel, dec) = (selector.as_ptr(), declarations.as_ptr());

    // SAFETY (every call below): `b` points at `n` readable bytes, every
    // string is NUL-terminated and outlives the call, and every out pointer is
    // a writable local or a buffer `buffer_door` sized.
    string_door("pcap_summary", |o| unsafe {
        wz_dissect_pcap_summary(b, n, o)
    });
    string_door("pcap_summary_bounded", |o| unsafe {
        wz_dissect_pcap_summary_bounded(b, n, o)
    });
    string_door("pcap_census", |o| unsafe {
        wz_dissect_pcap_census(b, n, o)
    });
    string_door("pcap_census_bounded", |o| unsafe {
        wz_dissect_pcap_census_bounded(b, n, o)
    });
    string_door("pcap_census_where", |o| unsafe {
        wz_dissect_pcap_census_where(b, n, sel, o)
    });
    string_door("pcap_census_where_limited", |o| unsafe {
        wz_dissect_pcap_census_where_limited(b, n, sel, limits, o)
    });
    string_door("pcap_fields", |o| unsafe {
        wz_dissect_pcap_fields(b, n, shown, o)
    });
    string_door("pcap_fields_with_payloads", |o| unsafe {
        wz_dissect_pcap_fields_with_payloads(b, n, shown, dec, o)
    });
    string_door("pcap_fields_limited", |o| unsafe {
        wz_dissect_pcap_fields_limited(b, n, shown, dec, limits, o)
    });
    string_door("pcap_fields_where_limited", |o| unsafe {
        wz_dissect_pcap_fields_where_limited(b, n, shown, sel, dec, limits, o)
    });
    string_door("pcap_session_table", |o| unsafe {
        wz_dissect_pcap_session_table(b, n, limits, o)
    });

    buffer_door::<u8>(
        "pcap_frame_bytes",
        OnFailure::NeedsZero,
        |out, cap, needed| unsafe { wz_dissect_pcap_frame_bytes(b, n, packet, out, cap, needed) },
    );

    let mut partial = -1;
    let packets = buffer_door::<WzDissectRawPacket>(
        "pcap_packets_of_link_type",
        OnFailure::NeedsZero,
        |out, cap, needed| unsafe {
            wz_dissect_pcap_packets_of_link_type(b, n, link, out, cap, needed, &mut partial)
        },
    );
    assert!(
        partial == 0 || partial == 1 || packets.is_none(),
        "packets_of_link_type: partial is {partial}"
    );
    for p in packets.unwrap_or_default() {
        let end = p.offset.checked_add(u64::from(p.len));
        assert!(
            end.is_some_and(|end| end <= n as u64),
            "packets_of_link_type: packet {} at {}+{} lies outside the {n} bytes it was read from",
            p.packet,
            p.offset,
            p.len
        );
    }

    let mut malformed = usize::MAX;
    let mut partial = -1;
    buffer_door::<WzDissectCustomOption>(
        "pcap_custom_options_of_link_type",
        OnFailure::NeedsZero,
        |out, cap, needed| unsafe {
            wz_dissect_pcap_custom_options_of_link_type(
                b,
                n,
                link,
                out,
                cap,
                needed,
                &mut malformed,
                &mut partial,
            )
        },
    );
    buffer_door::<WzDissectLocalOption>(
        "pcap_local_options_of_link_type",
        OnFailure::NeedsZero,
        |out, cap, needed| unsafe {
            wz_dissect_pcap_local_options_of_link_type(
                b,
                n,
                link,
                out,
                cap,
                needed,
                &mut malformed,
                &mut partial,
            )
        },
    );
});
