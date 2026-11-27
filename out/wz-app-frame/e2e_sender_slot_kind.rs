// SCE-GENERATED — DO NOT EDIT
// source-hash: 0037bbbe8f565bc68d29bf923386a4490e197c4b24c48c79b91bf9b962f229e0
// source: e2e_sender_slot_kind.scxml
// SCE-MAP: e2e_sender_slot_kind.scxml:12 :: _forge_body

// SCE Forge: Auto-generated from Extended SCXML (sce:kind="enum")
// Runtime: none
// Do not edit — regenerate from the source SCXML file.

#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum E2eSenderSlotKind {
    #[default]
    Slotted = 0,
    NotListed = 1,
    Full = 2,
    NoClaim = 3,
}

#[allow(dead_code)]
impl E2eSenderSlotKind {
    /// The carrier value this variant declares.
    pub const fn to_underlying(self) -> u8 {
        self as u8
    }

    /// The variant `raw` declares, or `None` — the declared set is closed,
    /// so a value outside it is not a value of this type.
    pub const fn from_underlying(raw: u8) -> Option<Self> {
        match raw {
            0 => Some(Self::Slotted),
            1 => Some(Self::NotListed),
            2 => Some(Self::Full),
            3 => Some(Self::NoClaim),
            _ => None,
        }
    }

    /// The name the document declares for this variant.
    pub const fn declared_name(self) -> &'static str {
        match self {
            Self::Slotted => "slotted",
            Self::NotListed => "not_listed",
            Self::Full => "full",
            Self::NoClaim => "no_claim",
        }
    }
}

/// docs/adr/0108, D1: a value of this enum is a key of a map by the number its
/// document declares for it.
impl ::sce_portable_bytes::MapKey for E2eSenderSlotKind {
    fn feed_key(&self, into: &mut dyn ::sce_portable_bytes::KeyFeed) {
        ::sce_portable_bytes::MapKey::feed_key(&self.to_underlying(), into);
    }
}