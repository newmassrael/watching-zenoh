use super::*;
use wz_session_core::query_sink::{BorrowedQuery, ReplyError};
use wz_session_core::reply_stage::ReplyStage;

/// A recorded source identity `(zid_prefix, eid, sn)`, or `None` when the
/// reply carried none.
type RecSource = Option<(Vec<u8>, u32, u32)>;
/// One Del-arm emission: `(keyexpr, timestamp, source_info)`.
type RecDel = (String, u64, RecSource);

/// R311y562 — one recorded emission's value metadata:
/// `(encoding packed_id + schema, attachment)`.
type RecMeta = (Option<(u32, Option<String>)>, Option<Vec<u8>>);

/// Shared `ReplyOut` recorder for the `answer_from_ring` integration
/// tests: captures each reply's `(keyexpr, payload)` and its source
/// identity `(zid_prefix, eid, sn)` (or `None`).
///
/// R311y561 — `arms` records which reply ARM each emission took, in emit
/// order, and `dels` the Del arm's own `(keyexpr, timestamp, source_info)`.
/// Without `arms` a Del replayed on the Put arm (the pre-y561 behaviour, and
/// the resurrect-a-deleted-key bug) is INVISIBLE to a recorder that only
/// collects `(keyexpr, payload)` — a cached Del carries an empty payload, so
/// it would land in `keyed` as `("demo/k", vec![])` and read as a legitimate
/// empty Put.
#[derive(Default)]
struct Rec {
    keyed: Vec<(String, Vec<u8>)>,
    sourced: Vec<RecSource>,
    arms: Vec<&'static str>,
    dels: Vec<RecDel>,
    /// R311y562 — the encoding + attachment each emission carried, in emit
    /// order. Recorded on the META arms specifically: routing the recorder
    /// through the DEFAULT `reply_keyed_meta` chain would drop the
    /// attachment before it ever reached a recorder method, so a test built
    /// on the old arms alone cannot tell "the cache dropped it" from "the
    /// recorder dropped it".
    metas: Vec<RecMeta>,
}
impl ReplyOut for Rec {
    fn reply(&mut self, payload: &[u8]) {
        self.keyed.push((String::new(), payload.to_vec()));
        self.arms.push("put");
    }
    fn reply_keyed_sourced(
        &mut self,
        keyexpr: &str,
        payload: &[u8],
        _encoding: Option<&EncodingHint>,
        _timestamp: &TimestampHint,
        source_info: Option<&SourceInfo>,
    ) -> Result<(), ReplyError> {
        self.keyed.push((keyexpr.to_string(), payload.to_vec()));
        self.sourced
            .push(source_info.map(|si| (si.zid_prefix().to_vec(), si.eid, si.sn)));
        self.arms.push("put");
        Ok(())
    }
    fn reply_keyed_del_sourced(
        &mut self,
        keyexpr: &str,
        timestamp: &TimestampHint,
        source_info: Option<&SourceInfo>,
    ) -> Result<(), ReplyError> {
        self.dels.push((
            keyexpr.to_string(),
            timestamp.time,
            source_info.map(|si| (si.zid_prefix().to_vec(), si.eid, si.sn)),
        ));
        self.arms.push("del");
        Ok(())
    }
    fn reply_keyed_meta(
        &mut self,
        keyexpr: &str,
        payload: &[u8],
        meta: ReplyMeta<'_>,
    ) -> Result<(), ReplyError> {
        self.metas.push((
            meta.encoding.map(|e| (e.packed_id, e.schema.clone())),
            meta.attachment.map(<[u8]>::to_vec),
        ));
        // Delegate the identity bookkeeping to the arm the pre-y562 tests
        // already assert on, so `arms` / `keyed` / `sourced` keep their
        // meaning and those tests keep measuring what they measured.
        self.reply_keyed_sourced(
            keyexpr,
            payload,
            meta.encoding,
            meta.timestamp.expect("the cache always stamps a timestamp"),
            meta.source_info,
        )
    }
    fn reply_keyed_del_meta(
        &mut self,
        keyexpr: &str,
        meta: ReplyMeta<'_>,
    ) -> Result<(), ReplyError> {
        self.metas.push((
            meta.encoding.map(|e| (e.packed_id, e.schema.clone())),
            meta.attachment.map(<[u8]>::to_vec),
        ));
        self.reply_keyed_del_sourced(
            keyexpr,
            meta.timestamp.expect("the cache always stamps a timestamp"),
            meta.source_info,
        )
    }
    fn reply_del(&mut self) {
        self.arms.push("bare-del");
    }
    fn reply_err(&mut self, _: Option<u32>, _: Option<&str>, _: &[u8]) {}
    fn with_responder(&mut self, _: &[u8], _: u32) {}
    fn clear_responder(&mut self) {}
    fn responder(&self) -> Option<(&[u8], u32)> {
        None
    }
}

/// A query on `demo/k` carrying `params`.
fn query(params: Option<&'static [u8]>) -> BorrowedQuery<'static> {
    BorrowedQuery {
        keyexpr: "demo/k",
        parameters: params,
        attachment: None,
        source_info: None,
        payload: None,
        encoding: None,
        rid: 0,
        is_local: true,
        qos: QosLevel::DEFAULT,
    }
}

/// R311y442 REWROTE this test, and the old expectation is the diagnosis: it
/// fed `_sn=10..20&_max=5` and asserted BOTH keys came back, certifying the
/// `&` dialect as the cache's contract. The querier side joined on `&` too,
/// so wz agreed with wz and neither agreed with upstream. The fixture here is
/// now the byte string a real zenoh advanced subscriber sends — `;`-separated
/// and terminated by the bare `_anyke` flag.
#[test]
fn param_value_extracts_selectors() {
    let zenoh_shaped = b"_sn=10..20;_max=5;_anyke";
    assert_eq!(param_value(Some(zenoh_shaped), "_sn"), Some("10..20"));
    assert_eq!(param_value(Some(zenoh_shaped), "_max"), Some("5"));
    assert_eq!(param_value(Some(b"_sn=10..20"), "_max"), None);
    assert_eq!(param_value(None, "_sn"), None);
}

#[test]
fn parse_sn_range_mirrors_decode_range() {
    assert_eq!(parse_sn_range("10..20"), (Some(10), Some(20)));
    assert_eq!(parse_sn_range("10.."), (Some(10), None));
    assert_eq!(parse_sn_range("..20"), (None, Some(20)));
    assert_eq!(parse_sn_range(".."), (None, None));
    assert_eq!(parse_sn_range("7"), (Some(7), Some(7)));
}

/// Integration over `answer_from_ring`: a populated ring + a synthetic
/// query exercise the `_sn` filter, the `_max` cap, and the
/// timestamp-stamped reply fan together.
#[test]
fn answer_from_ring_filters_and_replies() {
    let mut ring = VecDeque::new();
    for sn in 0..3u32 {
        ring.push_back(CachedSample::new(
            "demo/k",
            vec![sn as u8],
            Some(SourceInfo::new(&[0x07], 9, sn)),
            TimestampHint {
                time: 100 + sn as u64,
                zid: vec![1],
            },
            SampleKind::Put,
        ));
    }

    // `_sn=1..` → sn 1 and 2, oldest-first. (No `_time` param, so the
    // `now` argument is irrelevant here — passed `0`.)
    let mut out = Rec::default();
    answer_from_ring(
        &ring,
        &query(Some(b"_sn=1..")),
        &mut out,
        0,
        RepliesConfig::default(),
    );
    assert_eq!(
        out.keyed,
        vec![
            ("demo/k".to_string(), vec![1]),
            ("demo/k".to_string(), vec![2])
        ]
    );

    // `_max=1` → only the newest (sn 2).
    let mut out = Rec::default();
    answer_from_ring(
        &ring,
        &query(Some(b"_max=1")),
        &mut out,
        0,
        RepliesConfig::default(),
    );
    assert_eq!(out.keyed, vec![("demo/k".to_string(), vec![2])]);

    // No params → all three, each carrying its source_info (zid, eid, sn)
    // so a recovery subscriber can re-key / reorder the retransmissions.
    let mut out = Rec::default();
    answer_from_ring(&ring, &query(None), &mut out, 0, RepliesConfig::default());
    assert_eq!(out.keyed.len(), 3);
    assert_eq!(
        out.sourced,
        vec![
            Some((vec![0x07], 9, 0)),
            Some((vec![0x07], 9, 1)),
            Some((vec![0x07], 9, 2)),
        ],
        "each recovery reply carries the cached sample's source_info",
    );
}

/// R311y561 — a cached DELETE replays on the Del arm, under its own key,
/// carrying its timestamp and its `(zid, eid, sn)`.
///
/// The assertion that carries the weight is `arms`, not the payloads: a Del
/// replayed on the Put arm emits `("demo/k", vec![])`, which a
/// payload-only recorder cannot tell from a legitimate empty Put — and that
/// mistake is exactly the one that resurrects a deleted key on the
/// recovering subscriber. Point the reply arm at `reply_keyed_sourced`
/// unconditionally (the pre-y561 shape) and this test fails on `arms` while
/// `keyed` still looks plausible.
///
/// The kind-agnostic `_sn` filter is asserted too: the Del occupies sn 1
/// like any other sample, so `_sn=1..` starts AT it. Excluding deletes from
/// the range would re-open the apparent gap the shared sn counter exists to
/// close.
#[test]
fn cached_delete_replays_on_the_del_arm() {
    // sn 0 Put, sn 1 DEL, sn 2 Put — one mixed stream from one publisher.
    let mut ring = VecDeque::new();
    for sn in 0..3u32 {
        let kind = if sn == 1 {
            SampleKind::Del
        } else {
            SampleKind::Put
        };
        ring.push_back(CachedSample::new(
            "demo/k",
            if kind == SampleKind::Del {
                Vec::new()
            } else {
                vec![sn as u8]
            },
            Some(SourceInfo::new(&[0x07], 9, sn)),
            TimestampHint {
                time: 100 + sn as u64,
                zid: vec![1],
            },
            kind,
        ));
    }

    let mut out = Rec::default();
    answer_from_ring(&ring, &query(None), &mut out, 0, RepliesConfig::default());

    assert_eq!(
        out.arms,
        vec!["put", "del", "put"],
        "the retained kind decides the reply arm, in ring order"
    );
    assert_eq!(
        out.keyed,
        vec![
            ("demo/k".to_string(), vec![0]),
            ("demo/k".to_string(), vec![2])
        ],
        "only the two Puts carry a payload; the Del never reaches the Put arm"
    );
    assert_eq!(
        out.dels,
        vec![("demo/k".to_string(), 101, Some((vec![0x07], 9, 1)))],
        "the Del reply carries its own concrete key, its timestamp, and its \
         (zid, eid, sn) — the identity the subscriber re-keys it by"
    );

    // The `_sn` range is kind-agnostic: `_sn=1..` starts at the DELETE.
    let mut out = Rec::default();
    answer_from_ring(
        &ring,
        &query(Some(b"_sn=1..")),
        &mut out,
        0,
        RepliesConfig::default(),
    );
    assert_eq!(
        out.arms,
        vec!["del", "put"],
        "a Del occupies its sequence number like any other sample, so a \
         recovery range starting at it replays it"
    );

    // ... and so is `_max`, which counts the Del as one of the newest.
    let mut out = Rec::default();
    answer_from_ring(
        &ring,
        &query(Some(b"_max=2")),
        &mut out,
        0,
        RepliesConfig::default(),
    );
    assert_eq!(out.arms, vec!["del", "put"], "_max counts the Del");
}

/// R311y562 — a recovery reply carries the cached sample's ENCODING and
/// ATTACHMENT, and a cached DELETE carries neither.
///
/// The Put half is the closing of the y561 residual: before this the ring
/// retained neither field and `answer_from_ring` passed a hard-coded `None`
/// encoding with no attachment slot at all, so every recovered sample
/// arrived rendered as the peer's DEFAULT content type with its side-band
/// silently gone. Revert either `with_encoding` / `with_attachment` in
/// `answer_from_ring`'s `meta` chain and the corresponding `metas` entry
/// goes `None` while every other assertion in this file still passes —
/// which is why the fields are asserted by VALUE and not merely for
/// presence.
///
/// The Del half is a claim about the WIRE, not about the cache: a Del body
/// emits no attachment ext (`has_attachment = _is_put && ..`) and no
/// encoding (read only inside the `_is_put` branch),
/// `vendor/zenoh-pico/src/protocol/codec/message.c:263,269-276`. So the
/// `(None, None)` asserted for the Del is upstream parity, and a future
/// round that "fixes" it by threading either field would be building
/// something the codec discards.
#[test]
fn recovery_reply_carries_encoding_and_attachment() {
    let enc = EncodingHint {
        packed_id: 0x0B,
        schema: Some("utf8".to_string()),
    };
    let mut ring = VecDeque::new();
    // sn 0: a Put carrying BOTH metadata fields.
    ring.push_back(
        CachedSample::new(
            "demo/k",
            vec![0xAA],
            Some(SourceInfo::new(&[0x07], 9, 0)),
            TimestampHint {
                time: 100,
                zid: vec![1],
            },
            SampleKind::Put,
        )
        .with_encoding(Some(enc.clone()))
        .with_attachment(Some(b"side-band".to_vec())),
    );
    // sn 1: a Put carrying NEITHER — the honest-absence arm, so a green
    // result cannot come from the recorder inventing a default.
    ring.push_back(CachedSample::new(
        "demo/k",
        vec![0xBB],
        Some(SourceInfo::new(&[0x07], 9, 1)),
        TimestampHint {
            time: 101,
            zid: vec![1],
        },
        SampleKind::Put,
    ));
    // sn 2: a DELETE. Carries neither by construction (the wire's rule).
    ring.push_back(CachedSample::new(
        "demo/k",
        Vec::new(),
        Some(SourceInfo::new(&[0x07], 9, 2)),
        TimestampHint {
            time: 102,
            zid: vec![1],
        },
        SampleKind::Del,
    ));

    let mut out = Rec::default();
    answer_from_ring(&ring, &query(None), &mut out, 0, RepliesConfig::default());

    assert_eq!(out.arms, vec!["put", "put", "del"], "ring order preserved");
    assert_eq!(
        out.metas,
        vec![
            (
                Some((0x0B, Some("utf8".to_string()))),
                Some(b"side-band".to_vec())
            ),
            (None, None),
            (None, None),
        ],
        "the recovery reply replays the cached encoding + attachment by \
         value; a sample that carried neither replays neither; and a Del \
         carries neither because a Del body encodes neither",
    );
}

#[test]
fn sn_filter_includes_and_excludes() {
    // No range → all (incl un-sequenced).
    assert!(sample_matches_sn(Some(5), None));
    assert!(sample_matches_sn(None, None));
    // Unbounded `..` → all.
    assert!(sample_matches_sn(Some(5), Some((None, None))));
    // Open upper (`10..`): recovery's main form.
    assert!(sample_matches_sn(Some(10), Some((Some(10), None))));
    assert!(!sample_matches_sn(Some(9), Some((Some(10), None))));
    // Closed range.
    assert!(sample_matches_sn(Some(15), Some((Some(10), Some(20)))));
    assert!(!sample_matches_sn(Some(21), Some((Some(10), Some(20)))));
    // Bounded range needs a present sn.
    assert!(!sample_matches_sn(None, Some((Some(10), None))));
}

/// The cache filter resolves a `_time` value the way the selector's own grammar
/// does (`crate::time_range` carries the grammar's tests): the wz
/// history-query form, an absolute RFC3339 bound and the `[t;duration]` form
/// all FILTER now, where the first used to be the only one that did.
#[test]
fn the_cache_filter_resolves_every_form_the_grammar_accepts() {
    let now = 1_000u64 << 32; // NTP64 = 1000 wall-clock seconds
    let filter = |selector: &str| {
        TimeRange::parse(selector).map(|r| r.resolve_at(ntp64_to_system_time(now)))
    };
    let at = |secs: u64| secs << 32;
    // `[now(-30s)..]` keeps 970s and later: the wz history-query form.
    let recent = filter("[now(-30s)..]");
    assert!(sample_matches_time(at(970), recent));
    assert!(sample_matches_time(at(1_000), recent));
    assert!(!sample_matches_time(at(969), recent));
    // Exclusive both ends: `]now(-2m)..now(-1m)[` is 880s..940s, ends excluded.
    let window = filter("]now(-2m)..now(-1m)[");
    assert!(sample_matches_time(at(881), window));
    assert!(sample_matches_time(at(939), window));
    assert!(!sample_matches_time(at(880), window));
    assert!(!sample_matches_time(at(940), window));
    // An offset that reaches before the epoch holds everything up to it.
    assert!(sample_matches_time(at(1), filter("[now(-2000s)..]")));
    // An absolute bound: 2024-01-01T00:00:00Z is 1704067200s.
    let absolute = filter("[2024-01-01T00:00:00Z..]");
    assert!(sample_matches_time(at(1_704_067_200), absolute));
    assert!(!sample_matches_time(at(1_704_067_199), absolute));
    // The duration form: one hour from 2024-01-01T00:00:00Z, both ends held.
    let hour = filter("[2024-01-01T00:00:00Z;1h]");
    assert!(sample_matches_time(at(1_704_067_200 + 3_600), hour));
    assert!(!sample_matches_time(at(1_704_067_200 + 3_601), hour));
    // A value zenoh's parser rejects is no range: every sample replies.
    for bad in ["now(-30s)", "[now(-30s)]", "[bogus..]", "[;1h]", ""] {
        let range = filter(bad);
        assert!(range.is_none(), "{bad:?}");
        assert!(sample_matches_time(at(1), range), "{bad:?}");
    }
}

#[test]
fn time_filter_includes_and_excludes() {
    let now = ntp64_to_system_time(100u64 << 32);
    let threshold = 70u64 << 32; // = now(100s) - 30s
                                 // No range -> all.
    assert!(sample_matches_time(60u64 << 32, None));
    // [70s, unbounded): 80s in, 60s out, 70s in (inclusive).
    let r = TimeRange::parse("[now(-30s)..]").map(|r| r.resolve_at(now));
    assert!(sample_matches_time(80u64 << 32, r));
    assert!(sample_matches_time(threshold, r));
    assert!(!sample_matches_time(60u64 << 32, r));
    // Exclusive lower bound drops the boundary sample.
    let rex = TimeRange::parse("]now(-30s)..]").map(|r| r.resolve_at(now));
    assert!(!sample_matches_time(threshold, rex));
}

/// Integration: `answer_from_ring` actually applies the `_time` filter in
/// its reply chain. A ring spanning three wall-clock seconds + a
/// `_time=[now(-30s)..]` query (now = 100s) replies only the samples newer
/// than 70s, oldest-first.
#[test]
fn answer_from_ring_applies_time_filter() {
    let now = 100u64 << 32;
    let mut ring = VecDeque::new();
    for (i, secs) in [60u64, 80, 100].into_iter().enumerate() {
        ring.push_back(CachedSample::new(
            "demo/k",
            vec![i as u8],
            Some(SourceInfo::new(&[0x07], 9, i as u32)),
            TimestampHint {
                time: secs << 32,
                zid: vec![1],
            },
            SampleKind::Put,
        ));
    }
    let mut out = Rec::default();
    answer_from_ring(
        &ring,
        &query(Some(b"_time=[now(-30s)..]")),
        &mut out,
        now,
        RepliesConfig::default(),
    );
    // threshold = 70s -> the 80s (payload 1) + 100s (payload 2) samples;
    // the 60s (payload 0) sample is dropped.
    assert_eq!(
        out.keyed,
        vec![
            ("demo/k".to_string(), vec![1]),
            ("demo/k".to_string(), vec![2]),
        ],
        "the _time filter drops the out-of-range sample"
    );
}

/// The handler a store gives out reads "now" from the function it was given, once per query,
/// and from nothing else: a store built in this crate has no clock of its own, so the same ring
/// answers a `_time` window differently as the host's clock moves.
#[test]
fn the_query_handler_reads_now_from_the_host_and_from_nothing_else() {
    use std::sync::atomic::{AtomicU64, Ordering};

    let store = CacheStore::new(CacheConfig {
        max_samples: 8,
        ..CacheConfig::default()
    });
    for (i, secs) in [60u64, 80, 100].into_iter().enumerate() {
        store.cache_sample(CachedSample::new(
            "demo/k",
            vec![i as u8],
            None,
            TimestampHint {
                time: secs << 32,
                zid: vec![1],
            },
            SampleKind::Put,
        ));
    }
    let clock = Arc::new(AtomicU64::new(100u64 << 32));
    let host_clock = Arc::clone(&clock);
    let mut handler = store.query_handler(move || host_clock.load(Ordering::SeqCst));
    let asked = query(Some(b"_time=[now(-30s)..]"));

    let mut out = Rec::default();
    handler(&asked, &mut out);
    assert_eq!(out.keyed.len(), 2, "at 100s the window holds 80s and 100s");

    // The host's clock moves and the same ring answers for the new now.
    clock.store(200u64 << 32, Ordering::SeqCst);
    let mut out = Rec::default();
    handler(&asked, &mut out);
    assert!(out.keyed.is_empty(), "at 200s the window holds none");
}

/// R2596 — `replies_config` OVERRIDES the query's QoS on every cache reply,
/// on BOTH arms, and an ordinary reply on the same responder still
/// inherits.
///
/// This is the case that separates this round from R2594's. There a reply
/// INHERITED its query's QoS, and a cache that only inherited would pass
/// any test whose query already asks for what the cache would have said.
/// So the query here asks for something the cache must refuse to echo —
/// `RealTime` / `Drop` / express against the cache's `Data` / `Block` /
/// not-express — and every field differs, so an implementation that
/// forwarded any one of them reds.
///
/// The third leg is the anti-vacuity one: `reply` staged directly on the
/// same responder must still carry the QUERY's QoS. Without it this test
/// would also pass against a build that had simply stopped inheriting.
#[test]
fn the_cache_replies_on_its_own_qos_not_the_querys() {
    use wz_session_core::qos::{CongestionControl, Priority};
    use wz_session_core::query::{QueryReply, QueryResponder};
    use wz_session_core::reply_acceptance::ReplyKeyExpr;

    let asked = QosLevel::from_parts(Priority::RealTime, CongestionControl::Drop, true);
    let configured = RepliesConfig::default();
    assert_ne!(
        configured.qos(),
        asked,
        "the fixture is only discriminating while the two differ"
    );

    // One Put and one Del, so both reply arms are exercised.
    let mut ring = VecDeque::new();
    for (sn, kind) in [(0u32, SampleKind::Put), (1u32, SampleKind::Del)] {
        ring.push_back(CachedSample::new(
            "demo/k",
            if kind == SampleKind::Del {
                Vec::new()
            } else {
                vec![sn as u8]
            },
            Some(SourceInfo::new(&[0x07], 9, sn)),
            TimestampHint {
                time: 100 + sn as u64,
                zid: vec![1],
            },
            kind,
        ));
    }

    let view = BorrowedQuery {
        keyexpr: "demo/k",
        parameters: None,
        attachment: None,
        source_info: None,
        payload: None,
        encoding: None,
        rid: 7,
        is_local: true,
        qos: asked,
    };

    let mut replies = ReplyStage::new();
    {
        let mut responder = QueryResponder::new(
            7,
            "demo/k".to_string(),
            ReplyKeyExpr::MatchingQuery,
            asked,
            &mut replies,
        );
        answer_from_ring(&ring, &view, &mut responder, 0, configured);
        // The anti-vacuity leg, staged through the SAME responder.
        responder
            .send_reply(b"not-from-the-cache")
            .expect("the growable stage refuses nothing");
    }

    let staged: Vec<QosLevel> = replies
        .iter()
        .map(|r| match &r {
            QueryReply::Reply { qos, .. } => *qos,
            #[allow(unreachable_patterns)]
            _ => panic!("the cache stages only Reply records"),
        })
        .collect();
    assert_eq!(staged.len(), 3, "one Put, one Del, one ordinary reply");
    assert_eq!(
        &staged[..2],
        &[configured.qos(), configured.qos()],
        "both cache arms carry the CACHE's QoS, not the query's {asked:?}"
    );
    assert_eq!(
        staged[2], asked,
        "a reply the cache did not make still inherits the query's QoS"
    );

    // And the config is READ rather than defaulted: a different one reaches
    // the wire record.
    let custom = RepliesConfig {
        priority: Priority::InteractiveHigh,
        congestion_control: CongestionControl::Drop,
        is_express: true,
    };
    let mut replies = ReplyStage::new();
    {
        let mut responder = QueryResponder::new(
            7,
            "demo/k".to_string(),
            ReplyKeyExpr::MatchingQuery,
            asked,
            &mut replies,
        );
        answer_from_ring(&ring, &view, &mut responder, 0, custom);
    }
    for reply in replies.iter() {
        // With the reply kinds this build has, `Reply` may be the only one, and the pattern then
        // always matches; a build with more of them is why the `else` is written.
        #[allow(irrefutable_let_patterns)]
        let QueryReply::Reply { qos, .. } = &reply
        else {
            panic!("the cache stages only Reply records");
        };
        assert_eq!(*qos, custom.qos(), "a configured QoS reaches every reply");
    }
}

/// A sample keeps what it retains until the ring lets the sample go — by
/// eviction, which is when the reference library releases the key a cached
/// sample held, and not before.
#[test]
fn a_sample_keeps_what_it_retains_until_the_ring_lets_it_go() {
    use std::sync::atomic::{AtomicUsize, Ordering};

    struct Held(Arc<AtomicUsize>);
    impl Drop for Held {
        fn drop(&mut self) {
            self.0.fetch_add(1, Ordering::SeqCst);
        }
    }

    let released = Arc::new(AtomicUsize::new(0));
    let store = CacheStore::new(CacheConfig {
        max_samples: 1,
        ..CacheConfig::default()
    });
    let sample = |released: &Arc<AtomicUsize>| {
        CachedSample::new(
            "demo/k",
            vec![1],
            None,
            TimestampHint::default(),
            SampleKind::Put,
        )
        .keeping(Some(Retained::new(Arc::new(Held(Arc::clone(released))))))
    };

    store.cache_sample(sample(&released));
    assert_eq!(
        released.load(Ordering::SeqCst),
        0,
        "a sample in the ring holds what it retains"
    );
    store.cache_sample(sample(&released));
    assert_eq!(
        released.load(Ordering::SeqCst),
        1,
        "the evicted sample lets go of what it retained, and only that one"
    );
    drop(store);
    assert_eq!(
        released.load(Ordering::SeqCst),
        2,
        "dropping the store releases the sample still in it"
    );
}
