// SCE-GENERATED — DO NOT EDIT
// source-hash: 7f29311ad0e1ba3670d5e5035f487c79bd2dde6df37e00032da1dc0a40ea7f63
// source: e2e_sender_slot_held.scxml
// SCE-MAP: e2e_sender_slot_held.scxml:11 :: _forge_body

// SCE Forge: Auto-generated from Extended SCXML (sce:kind="event-schema")
// Runtime: none
// Event name: e2e.sender_slot
// Do not edit — regenerate from the source SCXML file.


/// The event this schema types (`sce:event-name`), as a host names it.
#[allow(dead_code)]
pub const EVENT_NAME: &str = "e2e.sender_slot";
/// The revision of the schema (`sce:revision`, 1 when the document declares none).
#[allow(dead_code)]
pub const REVISION: u32 = 1;
/// The most bytes the event's `_event.data` JSON text takes: every list full, every
/// text at its bound, every number at its longest spelling.
#[allow(dead_code)]
pub const DATA_MAX_LEN: u64 = 19;
/// The id of the payload's schema, `urn:sce:schema:<document>:<revision>`: the
/// `$id` of `JSON_SCHEMA`.
#[allow(dead_code)]
pub const SCHEMA_ID: &str = "urn:sce:schema:e2e_sender_slot_held:1";
/// The payload as a JSON Schema (2020-12): one spelling of each value, every
/// bound as this build resolved it, a text's in UTF-8 bytes in `x-sce-max-bytes`.
#[allow(dead_code)]
pub const JSON_SCHEMA: &str = "{\"$schema\":\"https://json-schema.org/draft/2020-12/schema\",\"$id\":\"urn:sce:schema:e2e_sender_slot_held:1\",\"x-sce-source-hash\":\"7f29311ad0e1ba3670d5e5035f487c79bd2dde6df37e00032da1dc0a40ea7f63\",\"description\":\"x-sce-max-bytes bounds a text in UTF-8 bytes; maxLength counts characters\",\"type\":\"object\",\"properties\":{\"slot\":{\"type\":\"integer\",\"minimum\":0,\"maximum\":4294967295}},\"required\":[\"slot\"],\"additionalProperties\":false}";

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct E2eSenderSlotHeldPayload {
    pub slot: u32,
}

/// docs/adr/0108, D1: a payload is a key of a map by its fields, in the order
/// its schema declares them.
impl ::sce_portable_bytes::MapKey for E2eSenderSlotHeldPayload {
    fn feed_key(&self, into: &mut dyn ::sce_portable_bytes::KeyFeed) {
        ::sce_portable_bytes::MapKey::feed_key(&self.slot, into);
    }
}