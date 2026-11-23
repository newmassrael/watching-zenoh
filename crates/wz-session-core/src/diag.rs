// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The session core's diagnostics: the warnings an operator reads when a peer sends what the
//! session refuses or a bound turns out too small, and the debug notes of the scouting window.
//!
//! They are written with [`diag_warn!`](crate::diag_warn) and [`diag_debug!`](crate::diag_debug),
//! which take a format string and its arguments, as `log::warn!` and `log::debug!` do
//! without a `target:`. With the crate's `log` feature each is that `log` macro, and the
//! record reaches whatever logger the program installed. Without it each compiles to nothing: no
//! record is built, no argument is formatted or evaluated and no logger is called, so a library that
//! installs no logger links neither the facade nor the formatting its records name, as zenoh-pico
//! compiles its log calls out unless a log level is selected when it is built.
//!
//! The choice is made once, here, by the crate that owns the calls; a crate above that wants the
//! records turns on `wz-session-core/log`, which is in the default features.

/// The `log` facade, for the expansion of the diagnostic macros in a crate that does not name it.
#[cfg(feature = "log")]
#[doc(hidden)]
pub use log as __log;

/// A warning: `log::warn!` with the crate's `log` feature, nothing without it.
#[cfg(feature = "log")]
#[macro_export]
macro_rules! diag_warn {
    ($($arg:tt)+) => {
        $crate::diag::__log::warn!($($arg)+)
    };
}

/// A warning: `log::warn!` with the crate's `log` feature, nothing without it. The format
/// string and its arguments are still checked by the compiler, in a branch that is never taken,
/// so a call that names a variable keeps it used in either build.
#[cfg(not(feature = "log"))]
#[macro_export]
macro_rules! diag_warn {
    ($($arg:tt)+) => {
        if false {
            let _ = ::core::format_args!($($arg)+);
        }
    };
}

/// A debug note: `log::debug!` with the crate's `log` feature, nothing without it.
#[cfg(feature = "log")]
#[macro_export]
macro_rules! diag_debug {
    ($($arg:tt)+) => {
        $crate::diag::__log::debug!($($arg)+)
    };
}

/// A debug note: `log::debug!` with the crate's `log` feature, nothing without it, its format
/// checked as [`diag_warn!`](crate::diag_warn)'s is.
#[cfg(not(feature = "log"))]
#[macro_export]
macro_rules! diag_debug {
    ($($arg:tt)+) => {
        if false {
            let _ = ::core::format_args!($($arg)+);
        }
    };
}

#[cfg(test)]
mod tests {
    use core::cell::Cell;

    /// Counts the times it is formatted, so a test can tell whether a diagnostic formatted it.
    struct Counted<'a>(&'a Cell<u32>);

    impl core::fmt::Display for Counted<'_> {
        fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
            self.0.set(self.0.get() + 1);
            f.write_str("counted")
        }
    }

    /// Both macros take a format string with inline and positional arguments, stand where a
    /// statement or a match arm's value of type `()` does, and borrow their arguments rather than
    /// taking them.
    #[test]
    fn a_diagnostic_borrows_its_arguments_and_is_a_statement() {
        let attempted = 9000usize;
        let name = alloc::string::String::from("demo/doc");
        crate::diag_warn!("{attempted} bytes past {}", name.len());
        let outcome: Result<(), ()> = Ok(());
        match outcome {
            Ok(()) => crate::diag_debug!("{name}: {}", attempted),
            Err(()) => crate::diag_warn!("refused"),
        }
        assert_eq!(name, "demo/doc", "the argument is still the caller's");
    }

    /// Without the `log` feature a diagnostic neither evaluates nor formats its arguments.
    #[cfg(not(feature = "log"))]
    #[test]
    fn without_the_log_feature_nothing_is_evaluated_or_formatted() {
        let formatted = Cell::new(0);
        let evaluated = Cell::new(0);
        let touch = || {
            evaluated.set(evaluated.get() + 1);
            Counted(&formatted)
        };
        crate::diag_warn!("{}", touch());
        crate::diag_debug!("{}", touch());
        assert_eq!(evaluated.get(), 0);
        assert_eq!(formatted.get(), 0);
    }

    /// With the `log` feature and no level enabled, the facade's own check stands before the
    /// arguments: they are neither evaluated nor formatted, which is what a library whose host
    /// installed no logger pays.
    #[cfg(feature = "log")]
    #[test]
    fn with_the_log_feature_a_disabled_level_formats_nothing() {
        if log::log_enabled!(log::Level::Debug) {
            // A logger of this test binary turned the level on; the property is about one that
            // did not, so there is nothing to read here.
            return;
        }
        let formatted = Cell::new(0);
        crate::diag_debug!("{}", Counted(&formatted));
        assert_eq!(formatted.get(), 0);
    }
}
