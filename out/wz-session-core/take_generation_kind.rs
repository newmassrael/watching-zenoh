// SCE-GENERATED — DO NOT EDIT
// source-hash: df4f4fc8f8ef12aa6b837c435ecbf37d371db2346fc207360218c412b7fb9984
// source: take_generation_kind.scxml
// SCE-MAP: take_generation_kind.scxml:10 :: _forge_body

// SCE Forge: Auto-generated from Extended SCXML (sce:kind="enum")
// Runtime: none
// Do not edit — regenerate from the source SCXML file.

#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum TakeGenerationKind {
    #[default]
    Taken = 0,
    Duplicate = 1,
    NoRoom = 2,
}

#[allow(dead_code)]
impl TakeGenerationKind {
    /// The carrier value this variant declares.
    pub const fn to_underlying(self) -> u8 {
        self as u8
    }

    /// The variant `raw` declares, or `None` — the declared set is closed,
    /// so a value outside it is not a value of this type.
    pub const fn from_underlying(raw: u8) -> Option<Self> {
        match raw {
            0 => Some(Self::Taken),
            1 => Some(Self::Duplicate),
            2 => Some(Self::NoRoom),
            _ => None,
        }
    }

    /// The name the document declares for this variant.
    pub const fn declared_name(self) -> &'static str {
        match self {
            Self::Taken => "taken",
            Self::Duplicate => "duplicate",
            Self::NoRoom => "no_room",
        }
    }
}

/// docs/adr/0108, D1: a value of this enum is a key of a map by the number its
/// document declares for it.
impl ::sce_portable_bytes::MapKey for TakeGenerationKind {
    fn feed_key(&self, into: &mut dyn ::sce_portable_bytes::KeyFeed) {
        ::sce_portable_bytes::MapKey::feed_key(&self.to_underlying(), into);
    }
}