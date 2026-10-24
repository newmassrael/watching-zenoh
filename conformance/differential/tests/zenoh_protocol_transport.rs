// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! `zenoh-protocol`, the `transport` module (the opening, keeping and closing of a session, and the
//! frames the network messages travel in): upstream's crate (`up_protocol`) and wz's
//! (`wz_protocol`) given the same inputs, outputs equal.
//!
//! The constants (ids, flags, extension ids, batch sizes, close reasons) are compared as one text
//! per module; the reason of a close over every byte; the QoS and patch extensions over every one of
//! their 256 raw values, every priority they are built from and every wider value converted from a
//! 64-bit extension; and each kind of transport message, with every field set, through its
//! `Display`, `Debug`, equality and the conversions into a transport message. What each returns is
//! compared as text.
//!
//! The `test` feature's random constructors are held by SHAPE: the set of classes of value that
//! 20 000 draws reach is the same for both crates, a composite being reported by the classes of each
//! of its fields and a length by its first value, its last and the middle.
//!
//! The crates are built without `shared-memory`; that arm is held by the surface gate.
//!
//! One place is a definition and not a behaviour: wz reads the priority of a QoS extension by a
//! `match` where upstream transmutes the three low bits, and the test holds the two to the same
//! eight classes for every byte.

macro_rules! transport_cases {
    ($name:ident, $p:ident, $b:ident) => {
        mod $name {
            use std::{collections::BTreeSet, time::Duration};

            use $b::{buffer::Buffer, ZBuf, ZSlice};
            use $p::{
                common::{ZExtBody, ZExtUnit, ZExtZ64, ZExtZBuf},
                core::{Priority, Reliability, Resolution, WhatAmI, ZenohIdProto},
                network::{NetworkBody, NetworkMessage, NetworkMessageExt, Push},
                transport::{
                    batch_size, close, fragment, frame, id, init, join, keepalive, oam, open,
                    BatchSize, Close, Fragment, FragmentHeader, Frame, FrameHeader, InitAck,
                    InitSyn, Join, KeepAlive, Oam, OpenAck, OpenSyn, PrioritySn, TransportBody,
                    TransportBodyLowLatency, TransportBodyLowLatencyRef, TransportMessage,
                    TransportMessageLowLatency, TransportMessageLowLatencyRef, TransportSn,
                },
                zenoh::{Put, PushBody},
            };

            fn bytes(fill: u8, n: usize) -> ZBuf {
                ZBuf::from(vec![fill; n])
            }

            fn slice(fill: u8, n: usize) -> ZSlice {
                ZSlice::from(vec![fill; n])
            }

            /// Not `default()`: that is a random id, and a random one differs per crate.
            fn zid() -> ZenohIdProto {
                ZenohIdProto::try_from([1u8, 2, 3, 4].as_slice()).unwrap()
            }

            /// The ids, flags, extension ids, batch sizes and close reasons, one line per module.
            pub fn constants() -> Vec<String> {
                vec![
                    format!(
                        "ids {} {} {} {} {} {} {} {}",
                        id::OAM,
                        id::INIT,
                        id::OPEN,
                        id::CLOSE,
                        id::KEEP_ALIVE,
                        id::FRAME,
                        id::FRAGMENT,
                        id::JOIN
                    ),
                    format!(
                        "batch {} {} {} {}",
                        batch_size::UNICAST,
                        batch_size::MULTICAST,
                        BatchSize::MAX,
                        std::mem::size_of::<$p::transport::AtomicBatchSize>()
                    ),
                    format!(
                        "close {} {} | {} {} {} {} {} {} {} {}",
                        close::flag::S,
                        close::flag::Z,
                        close::reason::GENERIC,
                        close::reason::UNSUPPORTED,
                        close::reason::INVALID,
                        close::reason::MAX_SESSIONS,
                        close::reason::MAX_LINKS,
                        close::reason::EXPIRED,
                        close::reason::UNRESPONSIVE,
                        close::reason::CONNECTION_TO_SELF
                    ),
                    format!(
                        "fragment {} {} {} | ext {} {} {}",
                        fragment::flag::R,
                        fragment::flag::M,
                        fragment::flag::Z,
                        fragment::ext::QoS::ID,
                        fragment::ext::First::ID,
                        fragment::ext::Drop::ID
                    ),
                    format!(
                        "frame {} {} | ext {}",
                        frame::flag::R,
                        frame::flag::Z,
                        frame::ext::QoS::ID
                    ),
                    format!(
                        "init {} {} {} | ext {} {} {} {} {} {} {}",
                        init::flag::A,
                        init::flag::S,
                        init::flag::Z,
                        init::ext::QoS::ID,
                        init::ext::QoSLink::ID,
                        init::ext::Auth::ID,
                        init::ext::MultiLink::ID,
                        init::ext::LowLatency::ID,
                        init::ext::Compression::ID,
                        init::ext::Patch::ID
                    ),
                    format!("init region name ext {}", init::ext::RegionName::ID),
                    format!(
                        "open {} {} {} | ext {} {} {} {} {} {} {}",
                        open::flag::A,
                        open::flag::T,
                        open::flag::Z,
                        open::ext::QoS::ID,
                        open::ext::Auth::ID,
                        open::ext::MultiLinkSyn::ID,
                        open::ext::MultiLinkAck::ID,
                        open::ext::LowLatency::ID,
                        open::ext::Compression::ID,
                        open::ext::RemoteBound::ID
                    ),
                    format!(
                        "join {} {} {} | ext {} {} {}",
                        join::flag::T,
                        join::flag::S,
                        join::flag::Z,
                        join::ext::QoS::ID,
                        join::ext::Shm::ID,
                        join::ext::Patch::ID
                    ),
                    format!("keepalive {}", keepalive::flag::Z),
                    format!(
                        "oam {} {} | ext {}",
                        oam::flag::T,
                        oam::flag::Z,
                        oam::ext::QoS::ID
                    ),
                    format!(
                        "priority sn {:?} {} {}",
                        PrioritySn::DEFAULT,
                        Priority::NUM,
                        std::mem::size_of::<TransportSn>()
                    ),
                ]
            }

            /// The reason of a close, as text, for every byte.
            pub fn close_reasons() -> Vec<String> {
                (0..=255u8)
                    .map(|r| format!("{r}: {}", close::reason_to_str(r)))
                    .collect()
            }

            /// The QoS extension over every raw value, every priority and every wider value of the
            /// 64-bit extension it is converted from.
            pub fn qos_table() -> Vec<String> {
                type Qos = fragment::ext::QoSType;
                let mut out = Vec::new();
                for v in 0..=255u64 {
                    let q = Qos::from(ZExtZ64::<{ fragment::ext::QoS::ID }>::new(v));
                    out.push(format!(
                        "{v}: {q:?} {:?} {}",
                        q.priority(),
                        ZExtZ64::<{ fragment::ext::QoS::ID }>::from(q).value
                    ));
                }
                for v in [0x100u64, 0x105, 0xFFFF, 0x1_0005, u64::MAX] {
                    let q = Qos::from(ZExtZ64::<{ fragment::ext::QoS::ID }>::new(v));
                    out.push(format!(
                        "wide {v:#x}: {q:?} {:?} {}",
                        q.priority(),
                        ZExtZ64::<{ fragment::ext::QoS::ID }>::from(q).value
                    ));
                }
                for p in (0..8u8).map(|v| Priority::try_from(v).unwrap()) {
                    let q = Qos::new(p);
                    out.push(format!(
                        "new {p:?}: {q:?} {:?} {}",
                        q.priority(),
                        ZExtZ64::<{ fragment::ext::QoS::ID }>::from(q).value
                    ));
                }
                out.push(format!(
                    "DEFAULT {:?} {:?} {}",
                    Qos::DEFAULT,
                    Qos::default(),
                    Qos::DEFAULT == Qos::default()
                ));
                out
            }

            /// The patch extension over every raw value, their order, and what a wider value of the
            /// 64-bit extension becomes.
            pub fn patch_table() -> Vec<String> {
                type Patch = init::ext::PatchType;
                let mut out = Vec::new();
                for v in 0..=255u8 {
                    let p = Patch::new(v);
                    out.push(format!(
                        "{v}: {p:?} {} {} {}",
                        p.raw(),
                        p.has_fragmentation_markers(),
                        ZExtZ64::<{ init::ext::Patch::ID }>::from(p).value
                    ));
                }
                for v in [0x100u64, 0x101, 0xFFFF, u64::MAX] {
                    let p = Patch::from(ZExtZ64::<{ init::ext::Patch::ID }>::new(v));
                    out.push(format!(
                        "wide {v:#x}: {p:?} {} {}",
                        p.raw(),
                        p.has_fragmentation_markers()
                    ));
                }
                for a in [0u8, 1, 2, 255] {
                    for b in [0u8, 1, 2, 255] {
                        let (x, y) = (Patch::new(a), Patch::new(b));
                        out.push(format!(
                            "{a}/{b}: {:?} {} {} {}",
                            x.partial_cmp(&y),
                            x == y,
                            x < y,
                            x.max(y).raw()
                        ));
                    }
                }
                out.push(format!(
                    "NONE {:?} CURRENT {:?} {}",
                    Patch::NONE,
                    Patch::CURRENT,
                    Patch::CURRENT.has_fragmentation_markers()
                ));
                out
            }

            fn network_messages(reliability: Reliability) -> Vec<NetworkMessage> {
                let put = Put {
                    payload: bytes(7, 4),
                    ..Put::default()
                };
                let mut push = Push::from(PushBody::from(put));
                push.wire_expr = $p::core::WireExpr {
                    scope: 3,
                    suffix: std::borrow::Cow::Borrowed("a/b"),
                    mapping: $p::network::Mapping::Sender,
                };
                vec![
                    NetworkMessage {
                        body: NetworkBody::Push(push.clone()),
                        reliability,
                    },
                    NetworkMessage {
                        body: NetworkBody::Push(Push::from(PushBody::from(Put::default()))),
                        reliability,
                    },
                ]
            }

            fn all_messages() -> Vec<TransportMessage> {
                let resolution = Resolution::default();
                let init_syn = InitSyn {
                    version: 9,
                    whatami: WhatAmI::Peer,
                    zid: zid(),
                    resolution,
                    batch_size: 4_096,
                    ext_qos: Some(ZExtUnit::new()),
                    ext_qos_link: Some(ZExtZ64::new(0x1234)),
                    ext_auth: Some(ZExtZBuf::new(bytes(1, 3))),
                    ext_mlink: Some(ZExtZBuf::new(bytes(2, 2))),
                    ext_lowlatency: Some(ZExtUnit::new()),
                    ext_compression: Some(ZExtUnit::new()),
                    ext_patch: init::ext::PatchType::CURRENT,
                    ext_region_name: Some(ZExtZBuf::new(bytes(3, 5))),
                };
                let init_syn_bare = InitSyn {
                    version: 0,
                    whatami: WhatAmI::Client,
                    zid: zid(),
                    resolution,
                    batch_size: 0,
                    ext_qos: None,
                    ext_qos_link: None,
                    ext_auth: None,
                    ext_mlink: None,
                    ext_lowlatency: None,
                    ext_compression: None,
                    ext_patch: init::ext::PatchType::NONE,
                    ext_region_name: None,
                };
                let init_ack = InitAck {
                    version: 9,
                    whatami: WhatAmI::Router,
                    zid: zid(),
                    resolution,
                    batch_size: BatchSize::MAX,
                    cookie: slice(9, 16),
                    ext_qos: Some(ZExtUnit::new()),
                    ext_qos_link: None,
                    ext_auth: Some(ZExtZBuf::new(bytes(4, 3))),
                    ext_mlink: None,
                    ext_lowlatency: None,
                    ext_compression: Some(ZExtUnit::new()),
                    ext_patch: init::ext::PatchType::new(7),
                    ext_region_name: None,
                };
                let open_syn = OpenSyn {
                    lease: Duration::from_millis(10_000),
                    initial_sn: 77,
                    cookie: slice(5, 8),
                    ext_qos: Some(ZExtUnit::new()),
                    ext_auth: Some(ZExtZBuf::new(bytes(6, 2))),
                    ext_mlink: Some(ZExtZBuf::new(bytes(7, 1))),
                    ext_lowlatency: None,
                    ext_compression: Some(ZExtUnit::new()),
                    ext_remote_bound: Some(ZExtZ64::new(1)),
                };
                let open_ack = OpenAck {
                    lease: Duration::from_secs(10),
                    initial_sn: u32::MAX,
                    ext_qos: None,
                    ext_auth: Some(ZExtZBuf::new(bytes(8, 4))),
                    ext_mlink: Some(ZExtUnit::new()),
                    ext_lowlatency: Some(ZExtUnit::new()),
                    ext_compression: None,
                    ext_remote_bound: None,
                };
                let frame_reliability = Reliability::Reliable;
                let frame = Frame {
                    reliability: frame_reliability,
                    sn: 5,
                    ext_qos: frame::ext::QoSType::new(Priority::DataHigh),
                    payload: network_messages(frame_reliability),
                };
                let fragment = Fragment {
                    reliability: Reliability::BestEffort,
                    more: true,
                    sn: 6,
                    payload: slice(2, 10),
                    ext_qos: fragment::ext::QoSType::new(Priority::Background),
                    ext_first: Some(ZExtUnit::new()),
                    ext_drop: Some(ZExtUnit::new()),
                };
                let join_full = Join {
                    version: 9,
                    whatami: WhatAmI::Peer,
                    zid: zid(),
                    resolution,
                    batch_size: batch_size::MULTICAST,
                    lease: Duration::from_millis(1_500),
                    next_sn: PrioritySn {
                        reliable: 1,
                        best_effort: 2,
                    },
                    ext_qos: Some(Box::new(
                        [PrioritySn {
                            reliable: 3,
                            best_effort: 4,
                        }; Priority::NUM],
                    )),
                    ext_shm: Some(ZExtZBuf::new(bytes(1, 2))),
                    ext_patch: join::ext::PatchType::CURRENT,
                };
                let oam = Oam {
                    id: 0x0102,
                    body: ZExtBody::Z64(3),
                    ext_qos: oam::ext::QoSType::new(Priority::Control),
                };
                vec![
                    TransportMessage::from(init_syn),
                    TransportMessage::from(init_syn_bare),
                    TransportMessage::from(init_ack),
                    TransportMessage::from(open_syn),
                    TransportMessage::from(open_ack),
                    TransportMessage::from(Close {
                        reason: close::reason::EXPIRED,
                        session: true,
                    }),
                    TransportMessage::from(Close {
                        reason: 200,
                        session: false,
                    }),
                    TransportMessage::from(KeepAlive),
                    TransportMessage::from(frame),
                    TransportMessage::from(fragment),
                    TransportMessage::from(join_full),
                    TransportMessage {
                        body: TransportBody::OAM(oam),
                    },
                    TransportMessage::from(TransportBody::KeepAlive(KeepAlive)),
                ]
            }

            /// Every message as text, through `Display`, `Debug`, equality and clone.
            pub fn messages() -> Vec<String> {
                all_messages()
                    .into_iter()
                    .map(|m| {
                        let c = m.clone();
                        format!("{m} | {m:?} | clone eq {} | body eq {}", c == m, c.body == m.body)
                    })
                    .collect()
            }

            /// The headers and the low-latency forms, which are not a transport message.
            pub fn headers_and_low_latency() -> Vec<String> {
                let mut out = Vec::new();
                for reliability in [Reliability::Reliable, Reliability::BestEffort] {
                    let fh = FrameHeader {
                        reliability,
                        sn: 11,
                        ext_qos: frame::ext::QoSType::new(Priority::Data),
                    };
                    out.push(format!("{fh:?} {}", fh == fh.clone()));
                    let gh = FragmentHeader {
                        reliability,
                        more: false,
                        sn: 12,
                        ext_qos: fragment::ext::QoSType::new(Priority::RealTime),
                        ext_first: Some(ZExtUnit::new()),
                        ext_drop: None,
                    };
                    out.push(format!("{gh:?} {}", gh == gh.clone()));
                }
                let net = network_messages(Reliability::Reliable).remove(0);
                let low = TransportMessageLowLatency::try_from(net.clone()).unwrap();
                out.push(format!("{low:?}"));
                let by_ref = TransportMessageLowLatencyRef {
                    body: TransportBodyLowLatencyRef::Network(NetworkMessageExt::as_ref(&net)),
                };
                out.push(format!("{by_ref:?} {:?}", by_ref.clone()));
                for body in [
                    TransportBodyLowLatency::Close(Close {
                        reason: 1,
                        session: true,
                    }),
                    TransportBodyLowLatency::KeepAlive(KeepAlive),
                ] {
                    out.push(format!("{body:?}"));
                }
                let r = TransportBodyLowLatencyRef::Close(Close {
                    reason: 2,
                    session: false,
                });
                out.push(format!("{r:?} {:?}", r.clone()));
                out.push(format!("{:?}", TransportBodyLowLatencyRef::KeepAlive(KeepAlive)));
                out
            }

            /// What the `test` feature's random constructors can make, as the set of classes of
            /// value seen over many draws.
            pub fn rand_shapes() -> Vec<(&'static str, BTreeSet<String>)> {
                const DRAWS: usize = 20_000;
                fn axes<T>(
                    draw: impl Fn() -> T,
                    classes: impl Fn(&T) -> Vec<String>,
                ) -> BTreeSet<String> {
                    let mut set = BTreeSet::new();
                    for _ in 0..DRAWS {
                        set.extend(classes(&draw()));
                    }
                    set
                }
                // A length as its first value, its last, the ones between, or `OUT`: outside.
                fn span(n: usize, first: usize, last: usize) -> &'static str {
                    if n == first {
                        "first"
                    } else if n == last {
                        "last"
                    } else if n < first || n > last {
                        "OUT"
                    } else {
                        "mid"
                    }
                }
                let some = |label: &str, present: bool| format!("{label} {present}");
                let lease = |d: &Duration| format!("lease secs>>60 {}", d.as_secs() >> 60);
                let kind = |m: &TransportMessage| {
                    let s: &str = match &m.body {
                        TransportBody::InitSyn(_) => "init syn",
                        TransportBody::InitAck(_) => "init ack",
                        TransportBody::OpenSyn(_) => "open syn",
                        TransportBody::OpenAck(_) => "open ack",
                        TransportBody::Close(_) => "close",
                        TransportBody::KeepAlive(_) => "keep alive",
                        TransportBody::Frame(_) => "frame",
                        TransportBody::Fragment(_) => "fragment",
                        TransportBody::OAM(_) => "oam",
                        TransportBody::Join(_) => "join",
                    };
                    s.to_string()
                };
                let init_common = |version: u8, resolution: &Resolution, batch: u16| {
                    vec![
                        format!("version high {}", version >> 7),
                        format!("resolution {resolution:?}"),
                        format!("batch high {}", batch >> 15),
                    ]
                };
                vec![
                    (
                        "priority sn",
                        axes(PrioritySn::rand, |s| {
                            vec![
                                format!("reliable high {}", s.reliable >> 31),
                                format!("best effort high {}", s.best_effort >> 31),
                            ]
                        }),
                    ),
                    (
                        "qos",
                        axes(fragment::ext::QoSType::rand, |q| {
                            vec![format!("priority {:?}", q.priority())]
                        }),
                    ),
                    (
                        "patch",
                        axes(init::ext::PatchType::rand, |p| {
                            vec![
                                format!("raw high {}", p.raw() >> 7),
                                some("markers", p.has_fragmentation_markers()),
                            ]
                        }),
                    ),
                    (
                        "close",
                        axes(Close::rand, |c| {
                            vec![
                                some("session", c.session),
                                format!("reason {}", close::reason_to_str(c.reason)),
                            ]
                        }),
                    ),
                    ("keep alive", axes(KeepAlive::rand, |_| vec!["keep alive".into()])),
                    (
                        "oam",
                        axes(Oam::rand, |o| {
                            vec![
                                format!("id high {}", o.id >> 15),
                                match &o.body {
                                    ZExtBody::Unit => "unit".to_string(),
                                    ZExtBody::Z64(v) => format!("z64 high {}", v >> 63),
                                    ZExtBody::ZBuf(z) => {
                                        format!("zbuf {}", span(z.len(), 8, 64))
                                    }
                                },
                                format!("priority {:?}", o.ext_qos.priority()),
                            ]
                        }),
                    ),
                    (
                        "frame header",
                        axes(FrameHeader::rand, |h| {
                            vec![
                                format!("reliability {:?}", h.reliability),
                                format!("sn high {}", h.sn >> 31),
                                format!("priority {:?}", h.ext_qos.priority()),
                            ]
                        }),
                    ),
                    (
                        "frame",
                        axes(Frame::rand, |f| {
                            vec![
                                format!("reliability {:?}", f.reliability),
                                format!("sn high {}", f.sn >> 31),
                                format!("payload {}", f.payload.len()),
                                format!("priority {:?}", f.ext_qos.priority()),
                                format!(
                                    "payload reliability agrees {}",
                                    f.payload.iter().all(|m| m.reliability == f.reliability)
                                ),
                            ]
                        }),
                    ),
                    (
                        "fragment header",
                        axes(FragmentHeader::rand, |h| {
                            vec![
                                format!("reliability {:?}", h.reliability),
                                some("more", h.more),
                                format!("sn high {}", h.sn >> 31),
                                some("first", h.ext_first.is_some()),
                                some("drop", h.ext_drop.is_some()),
                                format!("priority {:?}", h.ext_qos.priority()),
                            ]
                        }),
                    ),
                    (
                        "fragment",
                        axes(Fragment::rand, |f| {
                            vec![
                                format!("reliability {:?}", f.reliability),
                                some("more", f.more),
                                format!("sn high {}", f.sn >> 31),
                                format!("payload {}", span(f.payload.len(), 8, 127)),
                                some("first", f.ext_first.is_some()),
                                some("drop", f.ext_drop.is_some()),
                                format!("priority {:?}", f.ext_qos.priority()),
                            ]
                        }),
                    ),
                    (
                        "init syn",
                        axes(InitSyn::rand, |m| {
                            let mut v = init_common(m.version, &m.resolution, m.batch_size);
                            v.extend([
                                format!("whatami {:?}", m.whatami),
                                some("qos", m.ext_qos.is_some()),
                                some("qos link", m.ext_qos_link.is_some()),
                                some("auth", m.ext_auth.is_some()),
                                some("mlink", m.ext_mlink.is_some()),
                                some("lowlatency", m.ext_lowlatency.is_some()),
                                some("compression", m.ext_compression.is_some()),
                                some("region name", m.ext_region_name.is_some()),
                                format!("patch high {}", m.ext_patch.raw() >> 7),
                            ]);
                            v
                        }),
                    ),
                    (
                        "init ack",
                        axes(InitAck::rand, |m| {
                            let mut v = init_common(m.version, &m.resolution, m.batch_size);
                            v.extend([
                                format!("whatami {:?}", m.whatami),
                                format!("cookie {}", m.cookie.len()),
                                some("qos", m.ext_qos.is_some()),
                                some("qos link", m.ext_qos_link.is_some()),
                                some("auth", m.ext_auth.is_some()),
                                some("mlink", m.ext_mlink.is_some()),
                                some("lowlatency", m.ext_lowlatency.is_some()),
                                some("compression", m.ext_compression.is_some()),
                                some("region name", m.ext_region_name.is_some()),
                                format!("patch high {}", m.ext_patch.raw() >> 7),
                            ]);
                            v
                        }),
                    ),
                    (
                        "open syn",
                        axes(OpenSyn::rand, |m| {
                            vec![
                                lease(&m.lease),
                                format!("initial sn high {}", m.initial_sn >> 31),
                                format!("cookie {}", span(m.cookie.len(), 32, 1_024)),
                                some("qos", m.ext_qos.is_some()),
                                some("auth", m.ext_auth.is_some()),
                                some("mlink", m.ext_mlink.is_some()),
                                some("lowlatency", m.ext_lowlatency.is_some()),
                                some("compression", m.ext_compression.is_some()),
                                some("remote bound", m.ext_remote_bound.is_some()),
                            ]
                        }),
                    ),
                    (
                        "open ack",
                        axes(OpenAck::rand, |m| {
                            vec![
                                lease(&m.lease),
                                format!("initial sn high {}", m.initial_sn >> 31),
                                some("qos", m.ext_qos.is_some()),
                                some("auth", m.ext_auth.is_some()),
                                some("mlink", m.ext_mlink.is_some()),
                                some("lowlatency", m.ext_lowlatency.is_some()),
                                some("compression", m.ext_compression.is_some()),
                                some("remote bound", m.ext_remote_bound.is_some()),
                            ]
                        }),
                    ),
                    (
                        "join",
                        axes(Join::rand, |m| {
                            let mut v = init_common(m.version, &m.resolution, m.batch_size);
                            v.extend([
                                format!("whatami {:?}", m.whatami),
                                lease(&m.lease),
                                format!("next sn high {}", m.next_sn.reliable >> 31),
                                some("qos", m.ext_qos.is_some()),
                                some("shm", m.ext_shm.is_some()),
                                format!("patch high {}", m.ext_patch.raw() >> 7),
                            ]);
                            v
                        }),
                    ),
                    (
                        "transport message",
                        axes(TransportMessage::rand, |m| vec![kind(m)]),
                    ),
                ]
            }

            pub fn qos_priority_of(raw: u64) -> String {
                format!(
                    "{:?}",
                    fragment::ext::QoSType::from(ZExtZ64::<{ fragment::ext::QoS::ID }>::new(raw))
                        .priority()
                )
            }

            pub fn close_text(reason: u8) -> String {
                close::reason_to_str(reason).to_string()
            }
        }
    };
}

transport_cases!(up, up_protocol, up_buffers);
transport_cases!(wz, wz_protocol, wz_buffers);

fn same(label: &str, a: Vec<String>, b: Vec<String>) -> usize {
    assert_eq!(a.len(), b.len(), "{label}");
    for (i, (x, y)) in a.iter().zip(&b).enumerate() {
        assert_eq!(x, y, "{label}, line {i}");
    }
    a.len()
}

#[test]
fn both_crates_name_the_ids_flags_extension_ids_and_sizes_of_the_transport_messages_alike() {
    let n = same("constants", up::constants(), wz::constants());
    assert_eq!(n, 12);
    // Not empty: the first line says each of the eight ids.
    assert!(wz::constants()[0].starts_with("ids 0 1 2 3 4 5 6 7"));
    let n = same("close reasons", up::close_reasons(), wz::close_reasons());
    assert_eq!(n, 256);
}

#[test]
fn both_crates_make_and_read_the_qos_and_patch_extensions_alike() {
    let n = same("qos", up::qos_table(), wz::qos_table());
    // 256 raw values, 5 wider ones, 8 built, the default.
    assert_eq!(n, 256 + 5 + 8 + 1);
    let n = same("patch", up::patch_table(), wz::patch_table());
    // 256 raw values, 4 wider ones, 16 pairs, the constants.
    assert_eq!(n, 256 + 4 + 16 + 1);
}

#[test]
fn both_crates_show_every_transport_message_alike() {
    let n = same("messages", up::messages(), wz::messages());
    assert_eq!(n, 13);
    let n = same(
        "headers and low latency",
        up::headers_and_low_latency(),
        wz::headers_and_low_latency(),
    );
    // Two headers in two reliabilities, the owned and the borrowed low-latency message, the two
    // owned bodies, and the two borrowed ones.
    assert_eq!(n, 4 + 2 + 2 + 2);
}

#[test]
fn both_crates_make_the_same_shapes_with_the_test_feature_constructors() {
    let (up, wz) = (up::rand_shapes(), wz::rand_shapes());
    assert_eq!(up.len(), wz.len());
    for ((name, a), (_, b)) in up.iter().zip(&wz) {
        assert_eq!(a, b, "random {name}");
        assert!(
            !a.iter().any(|class| class.contains("OUT")),
            "random {name} made a value outside its range: {a:?}"
        );
        // A constructor that only ever made one shape would pass by being constant. One does by
        // upstream's definition: a keep alive has no field.
        assert!(
            a.len() > 1 || *name == "keep alive",
            "random {name} made one shape"
        );
    }
    let count = |n: &str| up.iter().find(|(m, _)| *m == n).unwrap().1.len();
    // The classes are many where upstream's draws are: 8 priorities, 10 kinds of transport message.
    assert_eq!(count("qos"), 8);
    assert_eq!(count("transport message"), 10);
    // A close reason is any byte, so its text is one of the eight named reasons or `UNKNOWN`.
    let reasons: Vec<_> = up
        .iter()
        .find(|(m, _)| *m == "close")
        .unwrap()
        .1
        .iter()
        .filter(|c| c.starts_with("reason"))
        .collect();
    assert_eq!(reasons.len(), 9);
    // A frame made by `rand` has its messages as reliable as itself, and one to three of them.
    let frame = &up.iter().find(|(m, _)| *m == "frame").unwrap().1;
    assert!(frame.contains("payload reliability agrees true"));
    assert!(!frame.contains("payload reliability agrees false"));
    for n in 1..=3 {
        assert!(frame.contains(&format!("payload {n}")), "{n}");
    }
    assert!(!frame.contains("payload 0"));
}

/// The one definition: the priority of a QoS extension is the eight classes of the three low bits
/// for every value, on both sides, and wz's reading of it is not a transmute.
#[test]
fn both_crates_read_the_priority_of_a_qos_extension_by_its_three_low_bits() {
    for raw in 0..=0x3FFu64 {
        assert_eq!(
            up::qos_priority_of(raw),
            wz::qos_priority_of(raw),
            "{raw:#x}"
        );
    }
    let classes: std::collections::BTreeSet<_> = (0..8u64).map(wz::qos_priority_of).collect();
    assert_eq!(classes.len(), 8);
    assert_eq!(wz::qos_priority_of(0xF8), wz::qos_priority_of(0));
    assert_eq!(wz::qos_priority_of(7), "Background");
}

/// The control: the comparison is on text, so an input that changes the answer changes the line.
#[test]
fn the_comparison_sees_a_transport_message_that_differs() {
    assert_eq!(up::close_text(5), wz::close_text(5));
    assert_ne!(wz::close_text(5), wz::close_text(6));
    assert_ne!(wz::qos_priority_of(1), wz::qos_priority_of(2));
    assert_ne!(wz::messages()[0], wz::messages()[1]);
}
