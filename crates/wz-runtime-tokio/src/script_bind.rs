// SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! R311eo — generic SCXML script-action binders.
//!
//! Helpers that register a native function onto an [`IScriptEngine`]
//! whose closure body captures a shared `Arc<A>` deps bundle. Extracted
//! from `session_glue.rs` (where they were hard-coded to
//! `Arc<SessionLinkActions>`) and generalised over the deps type `A`.
//!
//! Sole consumer today is the still-Lua-bound session FSM glue
//! (`session_glue.rs`). The scouting FSM was its second consumer until
//! R311ik made scouting engine-free (native `<sce:action>` host-trait
//! dispatch, no `IScriptEngine`), so `scouting_glue.rs` no longer binds
//! through here. The module stays generic over `A` so the binder is
//! ready for any further Lua-bound FSM, and remains neutral — it depends
//! on no glue module, so no inter-glue module edge is created.
//!
//! `bind_close_reason` / `bind_bool` stay in `session_glue.rs` — they
//! are specialised to the session FSM's [`CloseReason`] dispatch and a
//! constant-boolean guard respectively, with no second consumer.
//!
//! [`CloseReason`]: wz_session_core::close_reason::CloseReason

use std::sync::Arc;

use sce_rust_runtime::scripting::{IScriptEngine, NativeMethod, ScriptValue};

/// Register a unit script action: the closure receives the captured
/// `Arc<A>` deps and runs for side effects only, returning
/// [`ScriptValue::Null`]. Sibling to [`bind_guard`] (which returns a
/// `bool` verdict).
pub(crate) fn bind_unit<A, F>(lua: &dyn IScriptEngine, name: &str, actions: &Arc<A>, body: F)
where
    A: Send + Sync + 'static,
    F: Fn(&Arc<A>) + Send + Sync + 'static,
{
    let captured = actions.clone();
    let cb: NativeMethod = Box::new(move |_args: &[ScriptValue]| -> ScriptValue {
        body(&captured);
        ScriptValue::Null
    });
    let ok = lua.register_global_function(name, cb);
    assert!(ok, "register_global_function failed for {name}");
}

/// Register a dynamic boolean guard: the closure receives the captured
/// `Arc<A>` deps and returns a `bool` verdict per invocation (evaluated
/// at guard-check time, not at registration time). Sibling to
/// [`bind_unit`] (which returns Null).
pub(crate) fn bind_guard<A, F>(lua: &dyn IScriptEngine, name: &str, actions: &Arc<A>, body: F)
where
    A: Send + Sync + 'static,
    F: Fn(&Arc<A>) -> bool + Send + Sync + 'static,
{
    let captured = actions.clone();
    let cb: NativeMethod = Box::new(move |_args: &[ScriptValue]| -> ScriptValue {
        ScriptValue::Bool(body(&captured))
    });
    let ok = lua.register_global_function(name, cb);
    assert!(ok, "register_global_function failed for {name}");
}
