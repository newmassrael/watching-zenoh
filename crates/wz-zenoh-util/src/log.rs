//
// Copyright (c) 2024 ZettaScale Technology
//
// This program and the accompanying materials are made available under the
// terms of the Eclipse Public License 2.0 which is available at
// http://www.eclipse.org/legal/epl-2.0, or the Apache License, Version 2.0
// which is available at https://www.apache.org/licenses/LICENSE-2.0.
//
// SPDX-License-Identifier: EPL-2.0 OR Apache-2.0
//
// Contributors:
//   ZettaScale Zenoh Team, <zenoh@zettascale.tech>
//
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
// Modified by newmassrael in 2026 for watching-zenoh. Derived from zenoh-util 1.10.2, file
// src/log.rs (https://github.com/eclipse-zenoh/zenoh, tag 1.10.2).
use std::{fmt, thread, thread::ThreadId};

use tracing::{field::Field, span, Event, Metadata, Subscriber};
use tracing_subscriber::{
    layer::{Context, SubscriberExt},
    registry::LookupSpan,
    EnvFilter,
};

/// A utility function to enable the tracing formatting subscriber.
///
/// The [`tracing_subscriber`]` is initialized from the `RUST_LOG` environment variable.
/// If `RUST_LOG` is not set, then logging is not enabled.
///
/// # Safety
///
/// Calling this function initializes a `lazy_static` in the [`tracing`] crate.
/// Such static is not deallocated prior to process exiting, thus tools such as `valgrind`
/// will report a memory leak.
/// Refer to this issue: <https://github.com/tokio-rs/tracing/issues/2069>
pub fn try_init_log_from_env() {
    if let Ok(env_filter) = EnvFilter::try_from_default_env() {
        init_env_filter(env_filter);
    }
}

/// A utility function to enable the tracing formatting subscriber.
///
/// The [`tracing_subscriber`] is initialized from the `RUST_LOG` environment variable.
/// If `RUST_LOG` is not set, then fallback directives are used.
///
/// # Safety
/// Calling this function initializes a `lazy_static` in the [`tracing`] crate.
/// Such static is not deallocated prior to process existing, thus tools such as `valgrind`
/// will report a memory leak.
/// Refer to this issue: <https://github.com/tokio-rs/tracing/issues/2069>
pub fn init_log_from_env_or<S>(fallback: S)
where
    S: AsRef<str>,
{
    let env_filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(fallback));
    init_env_filter(env_filter);
}

/// Install `subscriber` as the process's, for `tracing` events and for the records of the `log`
/// crate.
///
/// Modified by newmassrael: upstream installs a subscriber with `set_global_default`, which
/// carries only what is recorded through `tracing`. The engine of this workspace, and the
/// crates it is built on, record through the `log` crate, so under that call a process that set
/// up its logging here saw not one line of the router's face lifecycle, its flow control or its
/// dials. `try_init` installs the same subscriber and, with the `tracing-log` feature of
/// `tracing-subscriber` (on by default), the bridge that turns a `log` record into a `tracing`
/// event, so the one filter governs both. An installation that fails because the process has a
/// subscriber already is ignored, as upstream's was.
fn install<S: tracing_subscriber::util::SubscriberInitExt>(subscriber: S) {
    let _ = subscriber.try_init();
}

fn init_env_filter(env_filter: EnvFilter) {
    let subscriber = tracing_subscriber::fmt()
        .with_env_filter(env_filter)
        .with_thread_ids(true)
        .with_thread_names(true)
        .with_level(true)
        .with_target(true);

    install(subscriber.finish());
}

#[derive(Debug)]
pub struct LogRecord {
    pub target: String,
    pub level: tracing::Level,
    pub file: Option<&'static str>,
    pub line: Option<u32>,
    pub thread_id: ThreadId,
    pub thread_name: Option<String>,
    pub message: Option<String>,
    pub attributes: Vec<(&'static str, String)>,
}

#[derive(Clone)]
struct SpanFields(Vec<(&'static str, String)>);

struct Layer<Enabled, Callback> {
    enabled: Enabled,
    callback: Callback,
}

impl<S, E, C> tracing_subscriber::Layer<S> for Layer<E, C>
where
    S: Subscriber + for<'a> LookupSpan<'a>,
    E: Fn(&Metadata) -> bool + 'static,
    C: Fn(LogRecord) + 'static,
{
    fn enabled(&self, metadata: &Metadata<'_>, _: Context<'_, S>) -> bool {
        (self.enabled)(metadata)
    }

    fn on_new_span(&self, attrs: &span::Attributes<'_>, id: &span::Id, ctx: Context<'_, S>) {
        let span = ctx.span(id).unwrap();
        let mut extensions = span.extensions_mut();
        let mut fields = vec![];
        attrs.record(&mut |field: &Field, value: &dyn fmt::Debug| {
            fields.push((field.name(), format!("{value:?}")))
        });
        extensions.insert(SpanFields(fields));
    }

    fn on_record(&self, id: &span::Id, values: &span::Record<'_>, ctx: Context<'_, S>) {
        let span = ctx.span(id).unwrap();
        let mut extensions = span.extensions_mut();
        let fields = extensions.get_mut::<SpanFields>().unwrap();
        values.record(&mut |field: &Field, value: &dyn fmt::Debug| {
            fields.0.push((field.name(), format!("{value:?}")))
        });
    }

    fn on_event(&self, event: &Event<'_>, ctx: Context<'_, S>) {
        let thread = thread::current();
        let mut record = LogRecord {
            target: event.metadata().target().into(),
            level: *event.metadata().level(),
            file: event.metadata().file(),
            line: event.metadata().line(),
            thread_id: thread.id(),
            thread_name: thread.name().map(Into::into),
            message: None,
            attributes: vec![],
        };
        if let Some(scope) = ctx.event_scope(event) {
            for span in scope.from_root() {
                let extensions = span.extensions();
                let fields = extensions.get::<SpanFields>().unwrap();
                record.attributes.extend(fields.0.iter().cloned());
            }
        }
        event.record(&mut |field: &Field, value: &dyn fmt::Debug| {
            if field.name() == "message" {
                record.message = Some(format!("{value:?}"));
            } else {
                record.attributes.push((field.name(), format!("{value:?}")))
            }
        });
        (self.callback)(record);
    }
}

pub fn init_log_with_callback(
    enabled: impl Fn(&Metadata) -> bool + Send + Sync + 'static,
    callback: impl Fn(LogRecord) + Send + Sync + 'static,
) {
    install(tracing_subscriber::registry().with(Layer { enabled, callback }));
}

#[cfg(feature = "test")]
// Used to verify memory leaks for valgrind CI.
// `EnvFilter` internally uses a static reference that is not cleaned up yielding to false positive in valgrind.
// This function enables logging without calling `EnvFilter` for env configuration.
pub fn init_log_test() {
    let subscriber = tracing_subscriber::fmt()
        .with_max_level(tracing::Level::INFO)
        .with_thread_ids(false) // Disable thread ids and name because
        .with_thread_names(false) // there is a memory leak in tracing_subscriber crate with these enabled.
        .with_level(true)
        .with_target(true);

    let subscriber = subscriber.finish();
    let _ = tracing::subscriber::set_global_default(subscriber);
}

/// Added by newmassrael: the one test of this module. The subscriber is process-wide and is
/// installed once, so it is one test, through [`init_log_with_callback`], which shares
/// [`install`] with the setup from the environment: what carries a `log` record for the one
/// carries it for the other.
#[cfg(test)]
mod tests {
    use std::sync::Mutex;

    use super::{init_log_with_callback, LogRecord};

    static RECORDS: Mutex<Vec<LogRecord>> = Mutex::new(Vec::new());

    /// The engine of this workspace records through the `log` crate. Under upstream's
    /// installation (`set_global_default`) that record never reached the subscriber, and a host
    /// that took its logs through the callback was handed none of the router's lines.
    #[test]
    fn a_record_of_the_log_crate_reaches_the_callback_of_a_host() {
        init_log_with_callback(
            |_| true,
            |record| RECORDS.lock().expect("records").push(record),
        );
        log::error!("a router line recorded through the log crate");
        let records = RECORDS.lock().expect("records");
        assert!(
            records.iter().any(|record| record
                .message
                .as_deref()
                .is_some_and(|message| message.contains("recorded through the log crate"))),
            "the callback was handed {} record(s), none of them the line the `log` crate was given",
            records.len()
        );
    }
}
