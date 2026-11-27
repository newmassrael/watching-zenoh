// SCE-GENERATED — DO NOT EDIT
// source-hash: 5ff5a7f6767d72ecda7febd6d568e333f98840d18f1c583dece709347c32b1e4
// source: pico_link_properties.scxml
// SCE-MAP: pico_link_properties.scxml:27 :: _forge_body

// SCE Forge: Auto-generated from Extended SCXML (sce:kind="algorithm")
// Runtime: none
// Do not edit — regenerate from the source SCXML file.
//
// RFC §synth-5-A: pure synchronous function with bounded loops. Free
// function, no instance state. `#![no_std]`-clean when no `bytes`
// parameter (this fixture: no_std_clean = true).

use super::pico_link_reported;

#[allow(clippy::all)]
#[allow(unused_assignments)]
pub fn pico_link_properties(kind: u8, reported_mtu: u16, streamed: bool, reliable: bool) -> pico_link_reported::PicoLinkReportedPayload {
    if kind == 0 {
        let none = pico_link_reported::PicoLinkReportedPayload { mtu: 0, streamed: false, reliable: false };
        return none;
    }
    if kind == 1 || kind == 2 {
        let tcp = pico_link_reported::PicoLinkReportedPayload { mtu: 65535, streamed: true, reliable: true };
        return tcp;
    }
    if kind == 3 {
        let udp = pico_link_reported::PicoLinkReportedPayload { mtu: 1450, streamed: false, reliable: false };
        return udp;
    }
    if kind == 4 {
        let ws = pico_link_reported::PicoLinkReportedPayload { mtu: 65535, streamed: false, reliable: true };
        return ws;
    }
    if kind == 5 {
        let serial = pico_link_reported::PicoLinkReportedPayload { mtu: 1500, streamed: false, reliable: false };
        return serial;
    }
    let registry = pico_link_reported::PicoLinkReportedPayload { mtu: reported_mtu, streamed: streamed, reliable: reliable };
    return registry;
}