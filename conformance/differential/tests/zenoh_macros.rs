// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! `zenoh-macros`: upstream's crate and wz's, each compiled into a program that uses every macro
//! (`probes/body.rs`), and the two programs' transcripts held equal.
//!
//! A macro cannot be called as a function, so there is no call to make with the same input to both
//! and compare outputs: what is compared is the program the expansion becomes. Each probe is the
//! same source compiled against one crate's macros, with its own stub of the `zenoh` the expanded
//! code names (`probes/stub.rs`), and its transcript is what the compiled uses of `ke!`,
//! `nonwild_ke!`, `kedefine!`, `kewrite!`, `keformat!`, the attributes and the derives computed:
//! literals, the parse of five targets against two formats with and without a trailing `**`, the
//! setters, the writes with a value that does not fit, a missing field, and the shorthand form, the
//! items the attributes gate and the inherent methods `internal_trait` writes, and the whole
//! runtime-parameter machinery of `zenoh-runtime` (the names, the defaults, a configuration read
//! from the environment) built by the two derives. What a macro refuses at compile time (a
//! literal that is no key expression) is not a program, and is tested in the crate against the
//! text of the error of the key expression crate.

use std::sync::OnceLock;

/// The configuration both probes read when their runtime parameters are first used: the variable
/// is read once per process, so it is set before either is touched, and both read the same text.
const RUNTIME_ENV: &str = "(app: (worker_threads: 9), net: (max_blocking_threads: 11))";

fn transcripts() -> &'static (Vec<String>, Vec<String>) {
    static ONCE: OnceLock<(Vec<String>, Vec<String>)> = OnceLock::new();
    ONCE.get_or_init(|| {
        std::env::set_var("WZ_MACROS_PROBE_RUNTIME", RUNTIME_ENV);
        (probe_up::transcript(), probe_wz::transcript())
    })
}

#[test]
fn both_crates_macros_become_programs_that_compute_alike() {
    let (up, wz) = transcripts();
    for (i, (a, b)) in up.iter().zip(wz).enumerate() {
        assert_eq!(a, b, "line {i} of the transcript");
    }
    assert_eq!(up.len(), wz.len());
    // The comparison saw every family of macro and both outcomes of the fallible ones.
    assert!(up.len() >= 30, "{} lines", up.len());
    for needle in [
        "ke a/b/**",
        "nonwild ",
        "robot parse robot/r1/sensor/lidar/front: id=r1 kind=Some(\"lidar/front\")",
        "robot parse robot/r1/sensor: id=r1 kind=None",
        "error",
        "robot keformat Ok(",
        "robot keformat bad id Err(",
        "attrs [1, 2, 3, 4, 5]",
        "builder (5, 15)",
    ] {
        assert!(
            up.iter().any(|l| l.contains(needle)),
            "no line holds `{needle}`:\n{}",
            up.join("\n")
        );
    }
}

#[test]
fn the_derives_read_the_configuration_from_the_environment_in_both_crates() {
    let (up, wz) = transcripts();
    let line = |t: &[String], name: &str| {
        t.iter()
            .find(|l| l.starts_with(name))
            .unwrap_or_else(|| panic!("no `{name}` line"))
            .clone()
    };
    for t in [up, wz] {
        // Overridden by the environment, with the variant's own default for the field it left out.
        assert!(line(t, "app ").contains("worker_threads: 9"), "{t:?}");
        assert!(
            line(t, "net ").contains("max_blocking_threads: 11"),
            "{t:?}"
        );
        assert!(line(t, "net ").contains("worker_threads: 3"), "{t:?}");
        // Not named by it: the defaults of the variant, and of the struct.
        assert!(line(t, "tx ").contains("worker_threads: 1"), "{t:?}");
    }
}

#[test]
fn the_compilers_both_crates_report_are_the_one_that_built_them() {
    let (up, wz) = (probe_up::compiler(), probe_wz::compiler());
    assert_eq!(up, wz);
    assert!(!up.0.is_empty() && !up.1.is_empty());
    assert!(up.0.chars().next().unwrap().is_ascii_digit(), "{up:?}");
}

/// The control: the comparison is made on lines, so a transcript that lost one must differ.
#[test]
fn the_comparison_sees_a_transcript_that_lacks_a_line() {
    let (up, wz) = transcripts();
    let mut short = wz.clone();
    short.remove(3);
    assert_ne!(up, &short);
    let mut changed = wz.clone();
    changed[0].push('!');
    assert_ne!(up, &changed);
}
