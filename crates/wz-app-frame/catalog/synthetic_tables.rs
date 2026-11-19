// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
//
// GENERATED from crates/wz-app-frame/catalog/synthetic.json5 by scripts/lib/message_catalog.py --write.
// Do not edit: `message_catalog.py --check` fails when this file is stale.

/// The message catalog of `crates/wz-app-frame/catalog/synthetic.json5`, as the static tables of
/// `wz_app_frame::message_catalog_table`.
#[rustfmt::skip]
pub mod catalog_tables {
    #![allow(dead_code)]
    use wz_app_frame::message_catalog_table::*;

    /// The limits the tables were generated against.
    pub const LIMITS: Limits = Limits {
        messages: 64,
        replay_depth_max: 32,
        sender_slots: 8,
    };

    /// The catalog.
    pub const CATALOG: Table = Table {
        nodes: &[
            NodeRow {
                name: "north",
                address: Some(499968),
            },
            NodeRow {
                name: "south",
                address: Some(504320),
            },
        ],
        e2e_profiles: &[
            DocumentRow {
                name: "cat-demo",
                text: r#"{"name":"cat-demo","fields":[{"name":"counter","bytes":1},{"name":"ident","bytes":2,"xor":"0x0C3F","split":[{"name":"group","lsb":10,"width":6},{"name":"msg","lsb":0,"width":10}]},{"name":"length","bytes":2},{"name":"cell","bytes":3,"split":[{"name":"kind","lsb":20,"width":4},{"name":"sender","lsb":0,"width":20,"derive":{"from":"address","mask":"0x000FFF00","xor":"0x33"}}]},{"name":"crc","bytes":2}],"crc":{"field":"crc","width":16,"poly":"0x8BB7","init":"0x0000","refin":false,"refout":false,"xorout":"0x0000","cover":["ident","counter","@payload","length","cell"]},"length":{"field":"length","counts":"frame"},"counter":{"field":"counter","max_gap":3,"timeout_ms":400},"judge":{"ident":"ident","length":true},"cell":{"field":"cell","kind":"kind","sender":"sender"}}"#,
            },
        ],
        segment_profiles: &[
            DocumentRow {
                name: "cat-pieces",
                text: r#"{"name":"cat-pieces","segments":{"fields":[{"name":"mark","bytes":1,"equals":"0x7E"},{"name":"run","bytes":2},{"name":"seq","bytes":1},{"name":"whole","bytes":4,"order":"little"},{"name":"from","bytes":4,"order":"little"}],"stream":["run"],"transfer":"seq","total":"whole","offset":"from","total_max":65536}}"#,
            },
        ],
        supervision_start_delay_ms: 750,
        messages: &[
            MessageRow {
                key_expr: "demo/catalog/pose",
                id: 401,
                publishers: &[0],
                subscribers: &[1],
                period_ms: Some(40),
                protection: Some(ProtectionRow {
                    profile: 0,
                    values: r#"{"ident":{"group":21,"msg":300},"cell":{"kind":6}}"#,
                }),
                senders: &[],
                instance_key: &[],
                replay_depth: None,
                supervision: Some(SupervisionRow {
                    factor: 4,
                    awaited: true,
                }),
                segment_profile: None,
            },
            MessageRow {
                key_expr: "demo/catalog/map",
                id: 402,
                publishers: &[1],
                subscribers: &[0],
                period_ms: None,
                protection: None,
                senders: &[],
                instance_key: &[],
                replay_depth: Some(6),
                supervision: None,
                segment_profile: Some(0),
            },
        ],
    };

    #[test]
    fn the_tables_pass_the_catalog_reader() {
        if let Err(refusal) = wz_app_frame::message_catalog::Catalog::from_table(&CATALOG, LIMITS) {
            panic!("the catalog reader refuses the generated tables: {refusal}");
        }
    }
}
