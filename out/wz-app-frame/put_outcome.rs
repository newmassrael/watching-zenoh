// SCE-GENERATED — DO NOT EDIT
// source-hash: efd881c5eccc48410d333e3cc105c16319c4ec1a6b4bc834f39b841dfccafabf
// source: put_outcome.scxml
// SCE-MAP: put_outcome.scxml:17 :: _forge_body

// SCE Forge: Auto-generated from Extended SCXML (sce:kind="enum")
// Runtime: none
// Do not edit — regenerate from the source SCXML file.

#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum PutOutcome {
    #[default]
    Inserted = 0,
    Replaced = 1,
    Full = 2,
}

#[allow(dead_code)]
impl PutOutcome {
    /// The carrier value this variant declares.
    pub const fn to_underlying(self) -> u8 {
        self as u8
    }

    /// The variant `raw` declares, or `None` — the declared set is closed,
    /// so a value outside it is not a value of this type.
    pub const fn from_underlying(raw: u8) -> Option<Self> {
        match raw {
            0 => Some(Self::Inserted),
            1 => Some(Self::Replaced),
            2 => Some(Self::Full),
            _ => None,
        }
    }

    /// The name the document declares for this variant.
    pub const fn declared_name(self) -> &'static str {
        match self {
            Self::Inserted => "inserted",
            Self::Replaced => "replaced",
            Self::Full => "full",
        }
    }
}

/// docs/adr/0108, D1: a value of this enum is a key of a map by the number its
/// document declares for it.
impl ::sce_portable_bytes::MapKey for PutOutcome {
    fn feed_key(&self, into: &mut dyn ::sce_portable_bytes::KeyFeed) {
        ::sce_portable_bytes::MapKey::feed_key(&self.to_underlying(), into);
    }
}