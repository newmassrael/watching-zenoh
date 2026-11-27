// SCE-GENERATED — DO NOT EDIT
// source-hash: e3b0162176992026d8b588969c0e7ccc3217810a93648b72fa82f845fcf64455
// source: fragment_pacing_step.scxml
// SCE-MAP: fragment_pacing_step.scxml:13 :: _forge_body

// SCE Forge: Auto-generated from Extended SCXML (sce:kind="event-schema")
// Runtime: none
// Event name: fragment.pacing_step
// Do not edit — regenerate from the source SCXML file.


/// The event this schema types (`sce:event-name`), as a host names it.
#[allow(dead_code)]
pub const EVENT_NAME: &str = "fragment.pacing_step";
/// The revision of the schema (`sce:revision`, 1 when the document declares none).
#[allow(dead_code)]
pub const REVISION: u32 = 1;
/// The most bytes the event's `_event.data` JSON text takes: every list full, every
/// text at its bound, every number at its longest spelling.
#[allow(dead_code)]
pub const DATA_MAX_LEN: u64 = 51;
/// The id of the payload's schema, `urn:sce:schema:<document>:<revision>`: the
/// `$id` of `JSON_SCHEMA`.
#[allow(dead_code)]
pub const SCHEMA_ID: &str = "urn:sce:schema:fragment_pacing_step:1";
/// The payload as a JSON Schema (2020-12): one spelling of each value, every
/// bound as this build resolved it, a text's in UTF-8 bytes in `x-sce-max-bytes`.
#[allow(dead_code)]
pub const JSON_SCHEMA: &str = "{\"$schema\":\"https://json-schema.org/draft/2020-12/schema\",\"$id\":\"urn:sce:schema:fragment_pacing_step:1\",\"x-sce-source-hash\":\"e3b0162176992026d8b588969c0e7ccc3217810a93648b72fa82f845fcf64455\",\"description\":\"x-sce-max-bytes bounds a text in UTF-8 bytes; maxLength counts characters\",\"type\":\"object\",\"properties\":{\"wait_us\":{\"type\":\"string\",\"pattern\":\"^(0|[1-9][0-9]{0,18}|1[0-7][0-9]{18}|18[0-3][0-9]{17}|184[0-3][0-9]{16}|1844[0-5][0-9]{15}|18446[0-6][0-9]{14}|184467[0-3][0-9]{13}|1844674[0-3][0-9]{12}|184467440[0-6][0-9]{10}|1844674407[0-2][0-9]{9}|18446744073[0-6][0-9]{8}|1844674407370[0-8][0-9]{6}|18446744073709[0-4][0-9]{5}|184467440737095[0-4][0-9]{4}|18446744073709550[0-9]{3}|18446744073709551[0-5][0-9]{2}|1844674407370955160[0-9]|1844674407370955161[0-5])$\"},\"run\":{\"type\":\"integer\",\"minimum\":0,\"maximum\":4294967295}},\"required\":[\"wait_us\",\"run\"],\"additionalProperties\":false}";

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct FragmentPacingStepPayload {
    pub wait_us: u64,
    pub run: u32,
}

/// docs/adr/0108, D1: a payload is a key of a map by its fields, in the order
/// its schema declares them.
impl ::sce_portable_bytes::MapKey for FragmentPacingStepPayload {
    fn feed_key(&self, into: &mut dyn ::sce_portable_bytes::KeyFeed) {
        ::sce_portable_bytes::MapKey::feed_key(&self.wait_us, into);
        ::sce_portable_bytes::MapKey::feed_key(&self.run, into);
    }
}