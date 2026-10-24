// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

// The program both probes compile: one use of every macro of `zenoh-macros`, and a `transcript`
// of what the uses computed. It is included by `probe-up` and `probe-wz`, so the two are the same
// text under two crates' macros, and what differs between their transcripts is what differs
// between the macros' expansions.

use zenoh::key_expr::keyexpr;
use zenoh_macros::{ke, kedefine, keformat, kewrite, nonwild_ke};

kedefine!(
    pub robot: "robot/${id:*}/sensor/${kind:**}",
    pub pair: "${a:*}/${b:**}/tail",
    fixed: "no/${only:*}",
);

// An error's text without the place it was raised at.
fn text(e: impl core::fmt::Display) -> String {
    let t = e.to_string();
    t.split(" at ").next().unwrap().to_string()
}

fn literals(t: &mut Vec<String>) {
    t.push(format!("ke {}", ke!("a/b/**")));
    t.push(format!("ke {}", ke!("a/$*b/@v")));
    t.push(format!("nonwild {:?}", nonwild_ke!("a/b/c")));
    let k: &keyexpr = ke!("x/*");
    t.push(format!("ke is_wild {}", k.is_wild()));
}

fn formats(t: &mut Vec<String>) {
    t.push(format!(
        "robot Format {:?} | {}",
        robot::Format,
        robot::Format
    ));
    t.push(format!("pair into_inner {}", pair::Format.into_inner()));
    for target in [
        "robot/r1/sensor/lidar/front",
        "robot/r1/sensor",
        "robot/r2/sensor/a",
        "robot/x/y/z",
        "other",
    ] {
        let target = keyexpr::new(target).unwrap();
        match robot::parse(target) {
            Ok(p) => t.push(format!(
                "robot parse {target}: id={} kind={:?}",
                p.id(),
                p.kind().map(|k| k.as_str().to_string())
            )),
            Err(e) => t.push(format!("robot parse {target}: error {}", text(e))),
        }
    }
    for target in ["a/b/tail", "a/b/c/d/tail", "a/tail", "x/tail/tail"] {
        let target = keyexpr::new(target).unwrap();
        match pair::parse(target) {
            Ok(p) => t.push(format!(
                "pair parse {target}: a={} b={:?}",
                p.a(),
                p.b().map(|k| k.as_str().to_string())
            )),
            Err(e) => t.push(format!("pair parse {target}: error {}", text(e))),
        }
    }
    match fixed::parse(keyexpr::new("no/thing").unwrap()) {
        Ok(p) => t.push(format!("fixed parse: only={}", p.only())),
        Err(e) => t.push(format!("fixed parse: error {}", text(e))),
    }

    let mut f = robot::formatter();
    t.push(format!("robot formatter fresh {f:?}"));
    let r = kewrite!(f, id = "r7", kind = "a/b").map(|_| ());
    t.push(format!("robot kewrite {:?} {f:?}", r.map_err(text)));
    t.push(format!("robot build {:?}", f.build().map_err(text)));

    let mut f = robot::formatter();
    t.push(format!(
        "robot keformat {:?}",
        keformat!(f, id = "r8", kind = "k").map_err(text)
    ));
    let mut f = robot::formatter();
    t.push(format!(
        "robot keformat bad id {:?}",
        keformat!(f, id = "has/slash", kind = "k").map_err(text)
    ));
    let mut f = robot::formatter();
    let (id, kind) = ("r9", "z");
    t.push(format!(
        "robot keformat shorthand {:?}",
        keformat!(f, id, kind).map_err(text)
    ));
    let mut f = robot::formatter();
    t.push(format!(
        "robot keformat missing {:?}",
        keformat!(f, id = "only").map_err(text)
    ));
    let mut f = pair::formatter();
    t.push(format!(
        "pair setters {:?}",
        f.a("x").and_then(|f| f.b("y/z")).map(|_| ()).map_err(text)
    ));
    t.push(format!("pair build {:?}", f.build().map_err(text)));
    let mut f = fixed::formatter();
    t.push(format!(
        "fixed build {:?}",
        keformat!(f, only = "v").map_err(text)
    ));
}

mod attrs {
    /// Brief.
    ///
    /// More.
    #[zenoh_macros::unstable]
    pub fn only_unstable() -> u8 {
        1
    }
    #[zenoh_macros::unstable_doc]
    pub fn doc_only() -> u8 {
        2
    }
    #[zenoh_macros::internal]
    pub fn only_internal() -> u8 {
        3
    }
    #[zenoh_macros::pub_visibility_if_internal]
    pub(crate) fn exposed() -> u8 {
        4
    }
    #[zenoh_macros::internal_or_unstable]
    fn either() -> u8 {
        5
    }
    pub fn call_either() -> u8 {
        either()
    }

    mod traits {
        pub trait Setters: Sized {
            fn set_a(self, a: u8) -> Self;
            fn get_a(&self) -> u8;
            fn scaled<T: Into<u8>>(&self, by: T) -> u8
            where
                T: Copy;
        }
    }
    pub struct Builder(u8);
    // The inherent methods the macro writes are called below with no import of the trait.
    #[zenoh_macros::internal_trait]
    impl traits::Setters for Builder {
        fn set_a(self, a: u8) -> Self {
            Builder(a)
        }
        fn get_a(&self) -> u8 {
            self.0
        }
        fn scaled<T: Into<u8>>(&self, by: T) -> u8
        where
            T: Copy,
        {
            self.0.wrapping_mul(by.into())
        }
    }
    pub fn builder_values() -> (u8, u8) {
        let b = Builder(1).set_a(5);
        (b.get_a(), b.scaled(3u8))
    }
    pub fn all() -> Vec<u8> {
        vec![
            only_unstable(),
            doc_only(),
            only_internal(),
            exposed(),
            call_either(),
        ]
    }
}

mod runtime {
    use std::{borrow::Borrow, env};

    use lazy_static::lazy_static;
    use serde::Deserialize;
    use zenoh_macros::{GenericRuntimeParam, RegisterParam};

    pub type Runtime = String;
    pub type Result<T> = core::result::Result<T, String>;
    pub const ZENOH_RUNTIME_ENV: &str = "WZ_MACROS_PROBE_RUNTIME";

    #[derive(Debug, Clone, Copy, GenericRuntimeParam)]
    pub struct RuntimeParam {
        pub worker_threads: usize,
        pub max_blocking_threads: usize,
    }

    impl Default for RuntimeParam {
        fn default() -> Self {
            Self {
                worker_threads: 1,
                max_blocking_threads: 50,
            }
        }
    }

    impl RuntimeParam {
        fn build(&self, rt: ZRuntime) -> Result<Runtime> {
            Ok(format!(
                "{rt}:{}:{}",
                self.worker_threads, self.max_blocking_threads
            ))
        }
    }

    #[derive(Debug, Copy, Clone, PartialEq, Eq, Hash, RegisterParam, Deserialize)]
    #[param(RuntimeParam)]
    pub enum ZRuntime {
        #[serde(rename = "app")]
        #[param(worker_threads = 2)]
        Application,
        #[serde(rename = "net")]
        #[param(worker_threads = 3, max_blocking_threads = 7)]
        Net,
        #[serde(rename = "tx")]
        Tx,
    }

    pub fn lines() -> Vec<String> {
        ZRuntime::iter()
            .map(|rt| {
                let param: &RuntimeParam = rt.borrow();
                format!("{rt} {rt:?} {param:?} {:?}", rt.init())
            })
            .collect()
    }
}

/// What every macro of the crate produced, one line each.
pub fn transcript() -> Vec<String> {
    let mut t = Vec::new();
    literals(&mut t);
    formats(&mut t);
    t.push(format!("attrs {:?}", attrs::all()));
    t.push(format!("builder {:?}", attrs::builder_values()));
    t.extend(runtime::lines());
    t
}

/// The compiler's release and commit, as the macro reads them.
pub fn compiler() -> (&'static str, &'static str) {
    zenoh_macros::rustc_version_release!()
}
