// SCE-GENERATED — DO NOT EDIT
// source-hash: 2adf93fe83d33fbdce4d30820f3ffd0ae4e530fc7fbdac76f3206664bb817bf2
// source: key_facts_schema.scxml
// SCE-MAP: key_facts_schema.scxml:16 :: _forge_body

// SCE Forge: Auto-generated from Extended SCXML (sce:kind="event-schema")
// Runtime: none
// Event name: key.facts
// Do not edit — regenerate from the source SCXML file.


/// The event this schema types (`sce:event-name`), as a host names it.
#[allow(dead_code)]
pub const EVENT_NAME: &str = "key.facts";
/// The revision of the schema (`sce:revision`, 1 when the document declares none).
#[allow(dead_code)]
pub const REVISION: u32 = 1;
/// The most bytes the event's `_event.data` JSON text takes: every list full, every
/// text at its bound, every number at its longest spelling.
#[allow(dead_code)]
pub const DATA_MAX_LEN: u64 = 26;
/// The id of the payload's schema, `urn:sce:schema:<document>:<revision>`: the
/// `$id` of `JSON_SCHEMA`.
#[allow(dead_code)]
pub const SCHEMA_ID: &str = "urn:sce:schema:key_facts_schema:1";
/// The payload as a JSON Schema (2020-12): one spelling of each value, every
/// bound as this build resolved it, a text's in UTF-8 bytes in `x-sce-max-bytes`.
#[allow(dead_code)]
pub const JSON_SCHEMA: &str = "{\"$schema\":\"https://json-schema.org/draft/2020-12/schema\",\"$id\":\"urn:sce:schema:key_facts_schema:1\",\"x-sce-source-hash\":\"2adf93fe83d33fbdce4d30820f3ffd0ae4e530fc7fbdac76f3206664bb817bf2\",\"description\":\"x-sce-max-bytes bounds a text in UTF-8 bytes; maxLength counts characters\",\"type\":\"object\",\"properties\":{\"wild\":{\"type\":\"boolean\"},\"key\":{\"type\":\"boolean\"}},\"required\":[\"wild\",\"key\"],\"additionalProperties\":false}";

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct KeyFactsSchemaPayload {
    pub wild: bool,
    pub key: bool,
}

/// docs/adr/0108, D1: a payload is a key of a map by its fields, in the order
/// its schema declares them.
impl ::sce_portable_bytes::MapKey for KeyFactsSchemaPayload {
    fn feed_key(&self, into: &mut dyn ::sce_portable_bytes::KeyFeed) {
        ::sce_portable_bytes::MapKey::feed_key(&self.wild, into);
        ::sce_portable_bytes::MapKey::feed_key(&self.key, into);
    }
}