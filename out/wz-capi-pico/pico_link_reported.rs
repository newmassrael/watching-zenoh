// SCE-GENERATED — DO NOT EDIT
// source-hash: 67cd73a5bcb8ce528b6c1541e424cf270949610eac606c2d67d6b4a6d7801a1c
// source: pico_link_reported.scxml
// SCE-MAP: pico_link_reported.scxml:11 :: _forge_body

// SCE Forge: Auto-generated from Extended SCXML (sce:kind="event-schema")
// Runtime: none
// Event name: pico.link_reported
// Do not edit — regenerate from the source SCXML file.


/// The event this schema types (`sce:event-name`), as a host names it.
#[allow(dead_code)]
pub const EVENT_NAME: &str = "pico.link_reported";
/// The revision of the schema (`sce:revision`, 1 when the document declares none).
#[allow(dead_code)]
pub const REVISION: u32 = 1;
/// The most bytes the event's `_event.data` JSON text takes: every list full, every
/// text at its bound, every number at its longest spelling.
#[allow(dead_code)]
pub const DATA_MAX_LEN: u64 = 47;
/// The id of the payload's schema, `urn:sce:schema:<document>:<revision>`: the
/// `$id` of `JSON_SCHEMA`.
#[allow(dead_code)]
pub const SCHEMA_ID: &str = "urn:sce:schema:pico_link_reported:1";
/// The payload as a JSON Schema (2020-12): one spelling of each value, every
/// bound as this build resolved it, a text's in UTF-8 bytes in `x-sce-max-bytes`.
#[allow(dead_code)]
pub const JSON_SCHEMA: &str = "{\"$schema\":\"https://json-schema.org/draft/2020-12/schema\",\"$id\":\"urn:sce:schema:pico_link_reported:1\",\"x-sce-source-hash\":\"67cd73a5bcb8ce528b6c1541e424cf270949610eac606c2d67d6b4a6d7801a1c\",\"description\":\"x-sce-max-bytes bounds a text in UTF-8 bytes; maxLength counts characters\",\"type\":\"object\",\"properties\":{\"mtu\":{\"type\":\"integer\",\"minimum\":0,\"maximum\":65535},\"streamed\":{\"type\":\"boolean\"},\"reliable\":{\"type\":\"boolean\"}},\"required\":[\"mtu\",\"streamed\",\"reliable\"],\"additionalProperties\":false}";

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct PicoLinkReportedPayload {
    pub mtu: u16,
    pub streamed: bool,
    pub reliable: bool,
}

/// docs/adr/0108, D1: a payload is a key of a map by its fields, in the order
/// its schema declares them.
impl ::sce_portable_bytes::MapKey for PicoLinkReportedPayload {
    fn feed_key(&self, into: &mut dyn ::sce_portable_bytes::KeyFeed) {
        ::sce_portable_bytes::MapKey::feed_key(&self.mtu, into);
        ::sce_portable_bytes::MapKey::feed_key(&self.streamed, into);
        ::sce_portable_bytes::MapKey::feed_key(&self.reliable, into);
    }
}