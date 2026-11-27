// SCE-GENERATED — DO NOT EDIT
// source-hash: fd495f69b523e7a214b53af6e12be7602adb86afa99eb18fddb29193c140173a
// source: e2e_sender_slot_result.scxml
// SCE-MAP: e2e_sender_slot_result.scxml:10 :: _forge_body

// SCE Forge: Auto-generated from Extended SCXML (sce:kind="union")
// Runtime: none
// Do not edit — regenerate from the source SCXML file.

use super::e2e_sender_slot_kind;
use super::e2e_sender_slot_held;

/// The revision of the union: its tag enum's, `e2e_sender_slot_kind`'s (a union declares none of its own).
#[allow(dead_code)]
pub const REVISION: u32 = 1;
/// The most bytes a value's JSON text takes: its largest case, every list full,
/// every text at its bound, every number at its longest spelling.
#[allow(dead_code)]
pub const DATA_MAX_LEN: u64 = 36;
/// The id of the union's schema, `urn:sce:schema:<document>:<revision>`: the
/// `$id` of `JSON_SCHEMA`.
#[allow(dead_code)]
pub const SCHEMA_ID: &str = "urn:sce:schema:e2e_sender_slot_result:1";
/// A value as a JSON Schema (2020-12): the `oneOf` of the cases, each its tag
/// `kind` beside the fields of its record, every bound as this build resolved it.
#[allow(dead_code)]
pub const JSON_SCHEMA: &str = "{\"$schema\":\"https://json-schema.org/draft/2020-12/schema\",\"$id\":\"urn:sce:schema:e2e_sender_slot_result:1\",\"x-sce-source-hash\":\"fd495f69b523e7a214b53af6e12be7602adb86afa99eb18fddb29193c140173a\",\"description\":\"x-sce-max-bytes bounds a text in UTF-8 bytes; maxLength counts characters\",\"oneOf\":[{\"type\":\"object\",\"properties\":{\"kind\":{\"const\":\"slotted\"},\"slot\":{\"type\":\"integer\",\"minimum\":0,\"maximum\":4294967295}},\"required\":[\"kind\",\"slot\"],\"additionalProperties\":false},{\"type\":\"object\",\"properties\":{\"kind\":{\"const\":\"not_listed\"}},\"required\":[\"kind\"],\"additionalProperties\":false},{\"type\":\"object\",\"properties\":{\"kind\":{\"const\":\"full\"}},\"required\":[\"kind\"],\"additionalProperties\":false},{\"type\":\"object\",\"properties\":{\"kind\":{\"const\":\"no_claim\"}},\"required\":[\"kind\"],\"additionalProperties\":false}]}";

/// A value of `e2e_sender_slot_result`: exactly one case, told apart by its tag `kind`, a
/// value of `e2e_sender_slot_kind::E2eSenderSlotKind`. Two values are equal when they are in one case and
/// their records are equal.
#[derive(Debug, Clone, PartialEq)]
pub enum E2eSenderSlotResult {
    /// The case `slotted`, holding its record.
    Slotted(e2e_sender_slot_held::E2eSenderSlotHeldPayload),
    /// The case `not_listed`, its tag alone.
    NotListed,
    /// The case `full`, its tag alone.
    Full,
    /// The case `no_claim`, its tag alone.
    NoClaim,
}

#[allow(dead_code)]
impl E2eSenderSlotResult {
    /// The case this value is in: the tag its text writes under `kind`.
    pub fn kind(&self) -> e2e_sender_slot_kind::E2eSenderSlotKind {
        match self {
            Self::Slotted(_) => e2e_sender_slot_kind::E2eSenderSlotKind::Slotted,
            Self::NotListed => e2e_sender_slot_kind::E2eSenderSlotKind::NotListed,
            Self::Full => e2e_sender_slot_kind::E2eSenderSlotKind::Full,
            Self::NoClaim => e2e_sender_slot_kind::E2eSenderSlotKind::NoClaim,
        }
    }

    /// The record of the case `slotted`, or `None` when the value is in
    /// another case.
    pub fn as_slotted(&self) -> Option<&e2e_sender_slot_held::E2eSenderSlotHeldPayload> {
        match self {
            Self::Slotted(record) => Some(record),
            _ => None,
        }
    }
}