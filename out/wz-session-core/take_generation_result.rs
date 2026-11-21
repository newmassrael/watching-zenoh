// SCE-GENERATED — DO NOT EDIT
// source-hash: da587786f03d96a523081386197ffe5102b366a70e9011ee82e88452b688ea37
// source: take_generation_result.scxml
// SCE-MAP: take_generation_result.scxml:10 :: _forge_body

// SCE Forge: Auto-generated from Extended SCXML (sce:kind="union")
// Runtime: none
// Do not edit — regenerate from the source SCXML file.

use super::take_generation_kind;
use super::take_generation_duplicate;

/// The revision of the union: its tag enum's, `take_generation_kind`'s (a union declares none of its own).
#[allow(dead_code)]
pub const REVISION: u32 = 1;
/// The most bytes a value's JSON text takes: its largest case, every list full,
/// every text at its bound, every number at its longest spelling.
#[allow(dead_code)]
pub const DATA_MAX_LEN: u64 = 50;
/// The id of the union's schema, `urn:sce:schema:<document>:<revision>`: the
/// `$id` of `JSON_SCHEMA`.
#[allow(dead_code)]
pub const SCHEMA_ID: &str = "urn:sce:schema:take_generation_result:1";
/// A value as a JSON Schema (2020-12): the `oneOf` of the cases, each its tag
/// `kind` beside the fields of its record, every bound as this build resolved it.
#[allow(dead_code)]
pub const JSON_SCHEMA: &str = "{\"$schema\":\"https://json-schema.org/draft/2020-12/schema\",\"$id\":\"urn:sce:schema:take_generation_result:1\",\"x-sce-source-hash\":\"da587786f03d96a523081386197ffe5102b366a70e9011ee82e88452b688ea37\",\"description\":\"x-sce-max-bytes bounds a text in UTF-8 bytes; maxLength counts characters\",\"oneOf\":[{\"type\":\"object\",\"properties\":{\"kind\":{\"const\":\"taken\"}},\"required\":[\"kind\"],\"additionalProperties\":false},{\"type\":\"object\",\"properties\":{\"kind\":{\"const\":\"duplicate\"},\"last\":{\"type\":\"string\",\"pattern\":\"^(0|[1-9][0-9]{0,18}|1[0-7][0-9]{18}|18[0-3][0-9]{17}|184[0-3][0-9]{16}|1844[0-5][0-9]{15}|18446[0-6][0-9]{14}|184467[0-3][0-9]{13}|1844674[0-3][0-9]{12}|184467440[0-6][0-9]{10}|1844674407[0-2][0-9]{9}|18446744073[0-6][0-9]{8}|1844674407370[0-8][0-9]{6}|18446744073709[0-4][0-9]{5}|184467440737095[0-4][0-9]{4}|18446744073709550[0-9]{3}|18446744073709551[0-5][0-9]{2}|1844674407370955160[0-9]|1844674407370955161[0-5])$\"}},\"required\":[\"kind\",\"last\"],\"additionalProperties\":false},{\"type\":\"object\",\"properties\":{\"kind\":{\"const\":\"no_room\"}},\"required\":[\"kind\"],\"additionalProperties\":false}]}";

/// A value of `take_generation_result`: exactly one case, told apart by its tag `kind`, a
/// value of `take_generation_kind::TakeGenerationKind`. Two values are equal when they are in one case and
/// their records are equal.
#[derive(Debug, Clone, PartialEq)]
pub enum TakeGenerationResult {
    /// The case `taken`, its tag alone.
    Taken,
    /// The case `duplicate`, holding its record.
    Duplicate(take_generation_duplicate::TakeGenerationDuplicatePayload),
    /// The case `no_room`, its tag alone.
    NoRoom,
}

#[allow(dead_code)]
impl TakeGenerationResult {
    /// The case this value is in: the tag its text writes under `kind`.
    pub fn kind(&self) -> take_generation_kind::TakeGenerationKind {
        match self {
            Self::Taken => take_generation_kind::TakeGenerationKind::Taken,
            Self::Duplicate(_) => take_generation_kind::TakeGenerationKind::Duplicate,
            Self::NoRoom => take_generation_kind::TakeGenerationKind::NoRoom,
        }
    }

    /// The record of the case `duplicate`, read where a test of the tag proved
    /// the value is in it.
    pub fn proven_duplicate(&self) -> &take_generation_duplicate::TakeGenerationDuplicatePayload {
        match self {
            Self::Duplicate(record) => record,
            _ => unreachable!("a value of {} read as {} is in another case", "take_generation_result", "duplicate"),
        }
    }
}