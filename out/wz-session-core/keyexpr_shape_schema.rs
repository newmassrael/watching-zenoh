// SCE-GENERATED — DO NOT EDIT
// source-hash: efe483b8c23efdefdaa54278e5db4cf384518b44642a21e3544dccee9803aa15
// SCE-MAP: keyexpr_shape_schema.scxml:15 :: _forge_body

// SCE Forge: Auto-generated from Extended SCXML (sce:kind="event-schema")
// Runtime: none
// Event name: keyexpr.shape
// Do not edit — regenerate from the source SCXML file.


/// The event this schema types (`sce:event-name`), as a host names it.
#[allow(dead_code)]
pub const EVENT_NAME: &str = "keyexpr.shape";
/// The revision of the schema (`sce:revision`, 1 when the document declares none).
#[allow(dead_code)]
pub const REVISION: u32 = 1;
/// The most bytes the event's `_event.data` JSON text takes: every list full, every
/// text at its bound, every number at its longest spelling.
#[allow(dead_code)]
pub const DATA_MAX_LEN: u64 = 69;
/// The id of the payload's schema, `urn:sce:schema:<document>:<revision>`: the
/// `$id` of `JSON_SCHEMA`.
#[allow(dead_code)]
pub const SCHEMA_ID: &str = "urn:sce:schema:keyexpr_shape_schema:1";
/// The payload as a JSON Schema (2020-12): one spelling of each value, every
/// bound as this build resolved it, a text's in UTF-8 bytes in `x-sce-max-bytes`.
#[allow(dead_code)]
pub const JSON_SCHEMA: &str = "{\"$schema\":\"https://json-schema.org/draft/2020-12/schema\",\"$id\":\"urn:sce:schema:keyexpr_shape_schema:1\",\"x-sce-source-hash\":\"efe483b8c23efdefdaa54278e5db4cf384518b44642a21e3544dccee9803aa15\",\"description\":\"x-sce-max-bytes bounds a text in UTF-8 bytes; maxLength counts characters\",\"type\":\"object\",\"properties\":{\"chunks\":{\"type\":\"integer\",\"minimum\":0,\"maximum\":4294967295},\"star\":{\"type\":\"boolean\"},\"double_star\":{\"type\":\"boolean\"},\"dollar\":{\"type\":\"boolean\"}},\"required\":[\"chunks\",\"star\",\"double_star\",\"dollar\"],\"additionalProperties\":false}";

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct KeyexprShapeSchemaPayload {
    pub chunks: u32,
    pub star: bool,
    pub double_star: bool,
    pub dollar: bool,
}