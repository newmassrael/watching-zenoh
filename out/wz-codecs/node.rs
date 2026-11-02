// SCE Forge: Auto-generated deployment `Node` from deploy/codec_node.yaml
// Do not edit — regenerate from the deploy input and the codec documents.

/// The deployment of deploy/codec_node.yaml: a storage profile whose every field of a
/// codec of its set is held inline, at the capacity the deploy input gives it
/// or at the field's bound. Past what it holds a storing decode refuses with
/// `CodecError::CapacityExceeded`, and a frame it cannot hold is still judged
/// whole first (docs/adr/0077 §7).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Node;

impl ::sce_forge_runtime::codec::Copying for Node {}

// `decl_final`
#[cfg(feature = "codec-declare")]
impl ::sce_forge_runtime::codec::HoldsList<super::decl_final::DeclFinalExtensionsField> for Node {
    type List<T> = ::sce_forge_runtime::heapless::Vec<T, 8> where T: Default + ::core::fmt::Debug + Clone + PartialEq;
}

// `decl_kexpr`
#[cfg(feature = "codec-declare")]
impl ::sce_forge_runtime::codec::HoldsList<super::decl_kexpr::DeclKexprExtensionsField> for Node {
    type List<T> = ::sce_forge_runtime::heapless::Vec<T, 8> where T: Default + ::core::fmt::Debug + Clone + PartialEq;
}

// `decl_queryable`
#[cfg(feature = "codec-declare")]
impl ::sce_forge_runtime::codec::HoldsList<super::decl_queryable::DeclQueryableExtensionsField> for Node {
    type List<T> = ::sce_forge_runtime::heapless::Vec<T, 8> where T: Default + ::core::fmt::Debug + Clone + PartialEq;
}

// `decl_subscriber`
#[cfg(feature = "codec-declare")]
impl ::sce_forge_runtime::codec::HoldsList<super::decl_subscriber::DeclSubscriberExtensionsField> for Node {
    type List<T> = ::sce_forge_runtime::heapless::Vec<T, 8> where T: Default + ::core::fmt::Debug + Clone + PartialEq;
}

// `decl_token`
#[cfg(feature = "codec-declare")]
impl ::sce_forge_runtime::codec::HoldsList<super::decl_token::DeclTokenExtensionsField> for Node {
    type List<T> = ::sce_forge_runtime::heapless::Vec<T, 8> where T: Default + ::core::fmt::Debug + Clone + PartialEq;
}

// `declare`
#[cfg(feature = "codec-declare")]
impl ::sce_forge_runtime::codec::HoldsList<super::declare::DeclareExtensionsField> for Node {
    type List<T> = ::sce_forge_runtime::heapless::Vec<T, 8> where T: Default + ::core::fmt::Debug + Clone + PartialEq;
}

// `encoding`
impl ::sce_forge_runtime::codec::HoldsStr<super::encoding::EncodingSchemaField> for Node {
    type Str = ::sce_forge_runtime::codec::InlineStr<128>;
}

// `err`
#[cfg(feature = "codec-response")]
impl ::sce_forge_runtime::codec::HoldsList<super::err::ErrExtensionsField> for Node {
    type List<T> = ::sce_forge_runtime::heapless::Vec<T, 8> where T: Default + ::core::fmt::Debug + Clone + PartialEq;
}
#[cfg(feature = "codec-response")]
impl ::sce_forge_runtime::codec::HoldsBytes<super::err::ErrPayloadField> for Node {
    type Bytes = ::sce_forge_runtime::codec::InlineBytes<256>;
}

// `ext_envelope`
impl ::sce_forge_runtime::codec::HoldsList<super::ext_envelope::ExtEnvelopeExtensionsField> for Node {
    type List<T> = ::sce_forge_runtime::heapless::Vec<T, 8> where T: Default + ::core::fmt::Debug + Clone + PartialEq;
}

// `ext_zbuf`
impl ::sce_forge_runtime::codec::HoldsBytes<super::ext_zbuf::ExtZbufValueField> for Node {
    type Bytes = ::sce_forge_runtime::codec::InlineBytes<32>;
}

// `fragment`
#[cfg(feature = "codec-fragment")]
impl ::sce_forge_runtime::codec::HoldsBytes<super::fragment::FragmentPayloadField> for Node {
    type Bytes = ::sce_forge_runtime::codec::InlineBytes<65536>;
}

// `frame`
#[cfg(feature = "codec-frame")]
impl ::sce_forge_runtime::codec::HoldsBytes<super::frame::FramePayloadField> for Node {
    type Bytes = ::sce_forge_runtime::codec::InlineBytes<65536>;
}

// `hello`
#[cfg(feature = "codec-hello")]
impl ::sce_forge_runtime::codec::HoldsBytes<super::hello::HelloZidField> for Node {
    type Bytes = ::sce_forge_runtime::codec::InlineBytes<16>;
}
#[cfg(feature = "codec-hello")]
impl ::sce_forge_runtime::codec::HoldsList<super::hello::HelloLocatorsField> for Node {
    type List<T> = ::sce_forge_runtime::heapless::Vec<T, 64> where T: Default + ::core::fmt::Debug + Clone + PartialEq;
}

// `init_body`
#[cfg(feature = "codec-init-body")]
impl ::sce_forge_runtime::codec::HoldsBytes<super::init_body::InitBodyZidField> for Node {
    type Bytes = ::sce_forge_runtime::codec::InlineBytes<16>;
}
#[cfg(feature = "codec-init-body")]
impl ::sce_forge_runtime::codec::HoldsBytes<super::init_body::InitBodyCookieField> for Node {
    type Bytes = ::sce_forge_runtime::codec::InlineBytes<128>;
}

// `interest`
impl ::sce_forge_runtime::codec::HoldsList<super::interest::InterestExtensionsField> for Node {
    type List<T> = ::sce_forge_runtime::heapless::Vec<T, 8> where T: Default + ::core::fmt::Debug + Clone + PartialEq;
}

// `join`
#[cfg(feature = "codec-join")]
impl ::sce_forge_runtime::codec::HoldsBytes<super::join::JoinZidField> for Node {
    type Bytes = ::sce_forge_runtime::codec::InlineBytes<16>;
}

// `linkstate`
#[cfg(feature = "codec-linkstate")]
impl ::sce_forge_runtime::codec::HoldsBytes<super::linkstate::LinkstateZidField> for Node {
    type Bytes = ::sce_forge_runtime::codec::InlineBytes<16>;
}
#[cfg(feature = "codec-linkstate")]
impl ::sce_forge_runtime::codec::HoldsList<super::linkstate::LinkstateLocatorsField> for Node {
    type List<T> = ::sce_forge_runtime::heapless::Vec<T, 64> where T: Default + ::core::fmt::Debug + Clone + PartialEq;
}
#[cfg(feature = "codec-linkstate")]
impl ::sce_forge_runtime::codec::HoldsList<super::linkstate::LinkstateLinksField> for Node {
    type List<T> = ::sce_forge_runtime::heapless::Vec<T, 64> where T: Default + ::core::fmt::Debug + Clone + PartialEq;
}
#[cfg(feature = "codec-linkstate")]
impl ::sce_forge_runtime::codec::HoldsList<super::linkstate::LinkstateWeightsField> for Node {
    type List<T> = ::sce_forge_runtime::heapless::Vec<T, 64> where T: Default + ::core::fmt::Debug + Clone + PartialEq;
}

// `linkstate_list`
#[cfg(feature = "codec-linkstate")]
impl ::sce_forge_runtime::codec::HoldsList<super::linkstate_list::LinkstateListLinkStatesField> for Node {
    type List<T> = ::sce_forge_runtime::heapless::Vec<T, 64> where T: Default + ::core::fmt::Debug + Clone + PartialEq;
}

// `locator`
impl ::sce_forge_runtime::codec::HoldsStr<super::locator::LocatorLocatorField> for Node {
    type Str = ::sce_forge_runtime::codec::InlineStr<128>;
}

// `msg_del`
impl ::sce_forge_runtime::codec::HoldsList<super::msg_del::MsgDelExtensionsField> for Node {
    type List<T> = ::sce_forge_runtime::heapless::Vec<T, 8> where T: Default + ::core::fmt::Debug + Clone + PartialEq;
}

// `msg_put`
impl ::sce_forge_runtime::codec::HoldsList<super::msg_put::MsgPutExtensionsField> for Node {
    type List<T> = ::sce_forge_runtime::heapless::Vec<T, 8> where T: Default + ::core::fmt::Debug + Clone + PartialEq;
}
impl ::sce_forge_runtime::codec::HoldsBytes<super::msg_put::MsgPutPayloadField> for Node {
    type Bytes = ::sce_forge_runtime::codec::InlineBytes<256>;
}
impl ::sce_forge_runtime::codec::HoldsList<super::msg_put::MsgPutSlicesField> for Node {
    type List<T> = ::sce_forge_runtime::heapless::Vec<T, 4> where T: Default + ::core::fmt::Debug + Clone + PartialEq;
}

// `oam`
impl ::sce_forge_runtime::codec::HoldsList<super::oam::OamExtensionsField> for Node {
    type List<T> = ::sce_forge_runtime::heapless::Vec<T, 8> where T: Default + ::core::fmt::Debug + Clone + PartialEq;
}

// `open_body`
#[cfg(feature = "codec-open-body")]
impl ::sce_forge_runtime::codec::HoldsBytes<super::open_body::OpenBodyCookieField> for Node {
    type Bytes = ::sce_forge_runtime::codec::InlineBytes<128>;
}

// `push`
#[cfg(feature = "codec-push")]
impl ::sce_forge_runtime::codec::HoldsList<super::push::PushExtensionsField> for Node {
    type List<T> = ::sce_forge_runtime::heapless::Vec<T, 8> where T: Default + ::core::fmt::Debug + Clone + PartialEq;
}

// `query`
#[cfg(feature = "codec-request")]
impl ::sce_forge_runtime::codec::HoldsBytes<super::query::QueryParametersField> for Node {
    type Bytes = ::sce_forge_runtime::codec::InlineBytes<256>;
}
#[cfg(feature = "codec-request")]
impl ::sce_forge_runtime::codec::HoldsList<super::query::QueryExtensionsField> for Node {
    type List<T> = ::sce_forge_runtime::heapless::Vec<T, 8> where T: Default + ::core::fmt::Debug + Clone + PartialEq;
}

// `query_value_zbuf`
#[cfg(feature = "codec-request")]
impl ::sce_forge_runtime::codec::HoldsBytes<super::query_value_zbuf::QueryValueZbufValueField> for Node {
    type Bytes = ::sce_forge_runtime::codec::InlineBytes<32>;
}
#[cfg(feature = "codec-request")]
impl ::sce_forge_runtime::codec::HoldsList<super::query_value_zbuf::QueryValueZbufSlicesField> for Node {
    type List<T> = ::sce_forge_runtime::heapless::Vec<T, 4> where T: Default + ::core::fmt::Debug + Clone + PartialEq;
}

// `reply`
#[cfg(feature = "codec-response")]
impl ::sce_forge_runtime::codec::HoldsList<super::reply::ReplyExtensionsField> for Node {
    type List<T> = ::sce_forge_runtime::heapless::Vec<T, 8> where T: Default + ::core::fmt::Debug + Clone + PartialEq;
}

// `request`
#[cfg(feature = "codec-request")]
impl ::sce_forge_runtime::codec::HoldsList<super::request::RequestExtensionsField> for Node {
    type List<T> = ::sce_forge_runtime::heapless::Vec<T, 8> where T: Default + ::core::fmt::Debug + Clone + PartialEq;
}

// `response`
#[cfg(feature = "codec-response")]
impl ::sce_forge_runtime::codec::HoldsList<super::response::ResponseExtensionsField> for Node {
    type List<T> = ::sce_forge_runtime::heapless::Vec<T, 8> where T: Default + ::core::fmt::Debug + Clone + PartialEq;
}

// `response_final`
#[cfg(feature = "codec-response-final")]
impl ::sce_forge_runtime::codec::HoldsList<super::response_final::ResponseFinalExtensionsField> for Node {
    type List<T> = ::sce_forge_runtime::heapless::Vec<T, 8> where T: Default + ::core::fmt::Debug + Clone + PartialEq;
}

// `scout`
#[cfg(feature = "codec-scout")]
impl ::sce_forge_runtime::codec::HoldsBytes<super::scout::ScoutZidField> for Node {
    type Bytes = ::sce_forge_runtime::codec::InlineBytes<16>;
}

// `serial_envelope`
#[cfg(feature = "codec-serial")]
impl ::sce_forge_runtime::codec::HoldsBytes<super::serial_envelope::SerialEnvelopePayloadField> for Node {
    type Bytes = ::sce_forge_runtime::codec::InlineBytes<1500>;
}

// `stream_envelope`
impl ::sce_forge_runtime::codec::HoldsBytes<super::stream_envelope::StreamEnvelopePayloadField> for Node {
    type Bytes = ::sce_forge_runtime::codec::InlineBytes<65535>;
}

// `timestamp`
impl ::sce_forge_runtime::codec::HoldsBytes<super::timestamp::TimestampZidField> for Node {
    type Bytes = ::sce_forge_runtime::codec::InlineBytes<16>;
}

// `undecl_kexpr`
#[cfg(feature = "codec-declare")]
impl ::sce_forge_runtime::codec::HoldsList<super::undecl_kexpr::UndeclKexprExtensionsField> for Node {
    type List<T> = ::sce_forge_runtime::heapless::Vec<T, 8> where T: Default + ::core::fmt::Debug + Clone + PartialEq;
}

// `undecl_queryable`
#[cfg(feature = "codec-declare")]
impl ::sce_forge_runtime::codec::HoldsList<super::undecl_queryable::UndeclQueryableExtensionsField> for Node {
    type List<T> = ::sce_forge_runtime::heapless::Vec<T, 8> where T: Default + ::core::fmt::Debug + Clone + PartialEq;
}

// `undecl_subscriber`
#[cfg(feature = "codec-declare")]
impl ::sce_forge_runtime::codec::HoldsList<super::undecl_subscriber::UndeclSubscriberExtensionsField> for Node {
    type List<T> = ::sce_forge_runtime::heapless::Vec<T, 8> where T: Default + ::core::fmt::Debug + Clone + PartialEq;
}

// `undecl_token`
#[cfg(feature = "codec-declare")]
impl ::sce_forge_runtime::codec::HoldsList<super::undecl_token::UndeclTokenExtensionsField> for Node {
    type List<T> = ::sce_forge_runtime::heapless::Vec<T, 8> where T: Default + ::core::fmt::Debug + Clone + PartialEq;
}

// `wireexpr_local`
impl ::sce_forge_runtime::codec::HoldsStr<super::wireexpr_local::WireexprLocalSuffixField> for Node {
    type Str = ::sce_forge_runtime::codec::InlineStr<128>;
}

// `wireexpr_nonlocal`
impl ::sce_forge_runtime::codec::HoldsStr<super::wireexpr_nonlocal::WireexprNonlocalSuffixField> for Node {
    type Str = ::sce_forge_runtime::codec::InlineStr<128>;
}

// `zbuf_slice`
impl ::sce_forge_runtime::codec::HoldsBytes<super::zbuf_slice::ZbufSliceBytesField> for Node {
    type Bytes = ::sce_forge_runtime::codec::InlineBytes<256>;
}
