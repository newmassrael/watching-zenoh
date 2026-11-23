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
// Modified by newmassrael in 2026 for watching-zenoh. Derived from zenoh 1.10.2, file
// src/api/config.rs (https://github.com/eclipse-zenoh/zenoh, tag 1.10.2).
use std::{
    env, fmt,
    path::Path,
    sync::{Arc, Mutex, MutexGuard},
};

use serde::{
    de,
    ser::{SerializeMap, SerializeSeq},
    Deserialize, Serialize,
};
use zenoh_config::ExpandedConfig;
use zenoh_result::{bail, ZResult};

/// Zenoh configuration.
///
/// The zenoh configuration is unstable, so no direct access to the fields is provided.
/// The only way to change the configuration is to load the JSON configuration from a file or a string,
/// with [`Config::from_file`](crate::config::Config::from_file) or
/// [`Config::from_json5`](crate::config::Config::from_json5),
/// or to use the [`Config::insert_json5`](crate::config::Config::insert_json5)
/// and [`Config::remove`](crate::config::Config::remove) methods to modify the configuration tree.
///
/// Example configuration file:
#[doc = concat!(
    "```json5\n",
    include_str!("../../DEFAULT_CONFIG.json5"),
    "\n```"
)]
///
/// Most options are optional as a way to keep defaults flexible. Some of the options have different
/// default values depending on the rest of the configuration.
///
/// The document may also hold a `wz` member, wz's own statements about the node (`wz/profile`,
/// `wz/policies`), which the open resolves; zenoh's own configuration has no such key, so the
/// member is held beside it.
#[derive(Default, Debug, Clone)]
pub struct Config(pub(crate) zenoh_config::Config, pub(crate) WzStatements);

impl Config {
    /// Default environment variable containing the file path used in [`Config::from_env`].
    pub const DEFAULT_CONFIG_PATH_ENV: &'static str = "ZENOH_CONFIG";

    /// Load configuration from the file path specified in the [`Self::DEFAULT_CONFIG_PATH_ENV`]
    /// environment variable.
    pub fn from_env() -> ZResult<Self> {
        let path = env::var(Self::DEFAULT_CONFIG_PATH_ENV)?;
        Ok(Config::from(zenoh_config::Config::from_file(Path::new(
            &path,
        ))?))
    }

    /// Load configuration from the file at `path`.
    pub fn from_file<P: AsRef<Path>>(path: P) -> ZResult<Self> {
        Ok(Config::from(zenoh_config::Config::from_file(path)?))
    }

    /// Load configuration from the JSON5 string `input`.
    pub fn from_json5(input: &str) -> ZResult<Config> {
        let mut wz = WzStatements::default();
        let mut deserializer = json5::Deserializer::from_str(input)?;
        let read = zenoh_config::Config::from_deserializer(wz.splitting(&mut deserializer));
        match read {
            Ok(config) => Ok(Config(config, wz)),
            Err(Ok(_)) => {
                Err(zerror!("The config was correctly deserialized, but it is invalid").into())
            }
            Err(Err(err)) => Err(err.into()),
        }
    }

    pub fn remove<K: AsRef<str>>(&mut self, key: K) -> ZResult<()> {
        self.0.remove(key.as_ref())
    }

    /// See [`zenoh_config::Config::try_remove_json5_array_item`].
    pub fn try_remove_json5_array_item<K: AsRef<str>>(&mut self, key: K) -> ZResult<bool> {
        self.0.try_remove_json5_array_item(key)
    }

    /// Inserts configuration value `value` at `key`.
    pub fn insert_json5(&mut self, key: &str, value: &str) -> ZResult<()> {
        if let Some(path) = wz_path(key) {
            return self.1.insert(path, value);
        }
        self.0
            .insert_json5(key, value)
            .map_err(|err| zerror!("{err}").into())
    }

    /// See [`zenoh_config::Config::try_insert_json5_array_item`].
    pub fn try_insert_json5_array_item(&mut self, key: &str, value: &str) -> ZResult<bool> {
        self.0
            .try_insert_json5_array_item(key, value)
            .map_err(|err| zerror!("{err}").into())
    }

    /// Returns a JSON string containing the configuration at `key`.
    pub fn get_json(&self, key: &str) -> ZResult<String> {
        if let Some(path) = wz_path(key) {
            return self.1.get_json(path);
        }
        self.0.get_json(key).map_err(|err| zerror!("{err}").into())
    }

    // REVIEW(fuzzypixelz): the error variant of the Result is a Result because this does
    // deserialization AND validation.
    #[zenoh_macros::unstable]
    // yellowhatter (upstream note): clippy says that Error here is extremely large (1k)
    #[allow(clippy::result_large_err)]
    pub fn from_deserializer<'d, D: serde::Deserializer<'d>>(
        d: D,
    ) -> Result<Self, Result<Self, D::Error>>
    where
        Self: serde::Deserialize<'d>,
    {
        let mut wz = WzStatements::default();
        let read = zenoh_config::Config::from_deserializer(wz.splitting(d));
        match read {
            Ok(config) => Ok(Config(config, wz)),
            Err(result) => match result {
                Ok(config) => Err(Ok(Config(config, wz))),
                Err(err) => Err(Err(err)),
            },
        }
    }
}

#[cfg(feature = "engine-tokio")]
impl Config {
    /// The policies an open of the configuration runs under: the build defaults, then the profile
    /// the open's caller names or else the one the `wz` member names, then the member's
    /// `wz/policies`, then what the caller states, each value with the layer that set it. The
    /// limits the member's `wz/limits` states are resolved with them, over the build defaults of
    /// a session's limits; a session holds no runtime's limits, so a runtime's limit is refused. A
    /// refusal of any of them refuses the open, with every refusal named.
    pub(crate) fn resolve_policies(&self) -> ZResult<wz_session_core::policy_document::Resolved> {
        self.1.resolve()
    }

    /// The key ids an open of the configuration hands its session: what the `wz` member's
    /// `wz/key-ids` states, read by the reader that resolves its policies
    /// ([`Self::resolve_policies`]), which refuses the member first when it refuses any of it.
    #[cfg(feature = "shared-key-ids")]
    pub(crate) fn resolve_key_ids(&self) -> ZResult<wz_session_core::shared_key_ids::KeyIdsAtOpen> {
        self.1.key_ids()
    }
}

/// The door of the open's own layer of policies, wz's beyond upstream's surface.
#[cfg(feature = "open-policies")]
impl Config {
    /// State `value` for the policy `policy` at the open, over what the document's `wz` member
    /// states. A second statement of the same policy replaces the first.
    ///
    /// Judged at once against the build: a policy it does not have, a value the policy does not
    /// have, a value the build leaves out of the policy's domain, a policy only the build decides.
    /// A refused statement changes nothing.
    pub fn state_policy(&mut self, policy: &str, value: &str) -> ZResult<()> {
        let statement = [wz_session_core::policy_document::Statement::new(
            policy, value,
        )];
        judge_alone(wz_session_core::policy_document::Overrides {
            profile: None,
            statements: wz_session_core::policy_document::Stated::Read(&statement),
            limits: wz_session_core::policy_document::StatedLimits::Read(&[]),
        })?;
        match self
            .1
            .policies
            .iter_mut()
            .find(|(stated, _)| stated == policy)
        {
            Some((_, held)) => *held = value.to_owned(),
            None => self.1.policies.push((policy.to_owned(), value.to_owned())),
        }
        Ok(())
    }

    /// Name the profile the open starts from, in place of the one the document's `wz` member
    /// names. A second profile replaces the first.
    ///
    /// Judged at once against the build: a profile it does not have, or one that states a value
    /// the build leaves out of a domain, is refused and changes nothing.
    pub fn state_profile(&mut self, profile: &str) -> ZResult<()> {
        judge_alone(wz_session_core::policy_document::Overrides {
            profile: Some(profile),
            ..wz_session_core::policy_document::Overrides::default()
        })?;
        self.1.profile = Some(profile.to_owned());
        Ok(())
    }
}

/// `overrides` resolved over the build defaults with no document: what the build refuses of them
/// whatever document they are stated beside.
#[cfg(feature = "open-policies")]
fn judge_alone(overrides: wz_session_core::policy_document::Overrides<'_, '_>) -> ZResult<()> {
    let nothing = wz_session_core::json5::Json5Value::Object(Vec::new());
    wz_session_core::policy_document::resolve_document_under(
        wz_session_core::policy::SessionPolicy::defaults(),
        &nothing,
        overrides,
    )
    .map(|_| ())
    .map_err(|refusals| zerror!("{refusals}").into())
}

impl Serialize for Config {
    /// zenoh's configuration, and each `wz` member after it when the document states one.
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        if self.1.member.is_empty() {
            return self.0.serialize(serializer);
        }
        let zenoh = serde_json::to_value(&self.0).map_err(serde::ser::Error::custom)?;
        let serde_json::Value::Object(members) = zenoh else {
            return Err(serde::ser::Error::custom(
                "the configuration is not an object",
            ));
        };
        let mut map = serializer.serialize_map(Some(members.len() + self.1.member.len()))?;
        for (key, value) in &members {
            map.serialize_entry(key, value)?;
        }
        for member in &self.1.member {
            map.serialize_entry(WZ_MEMBER, member)?;
        }
        map.end()
    }
}

impl<'de> Deserialize<'de> for Config {
    /// zenoh's configuration, with each `wz` member taken out of it before zenoh's reader, which
    /// has no such key, judges the rest.
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let mut wz = WzStatements::default();
        let config = zenoh_config::Config::deserialize(wz.splitting(deserializer))?;
        Ok(Config(config, wz))
    }
}

/// The top-level member of a document that holds wz's own statements about the node.
const WZ_MEMBER: &str = "wz";

/// The path under the `wz` member that `key` names (`""` for the member itself), or `None` for a
/// key of zenoh's. Leading separators are dropped, as zenoh's own keys drop them.
fn wz_path(key: &str) -> Option<&str> {
    match key.trim_start_matches('/').strip_prefix(WZ_MEMBER)? {
        "" => Some(""),
        rest => rest.strip_prefix('/'),
    }
}

/// wz's own statements in a configuration: the `wz` member of the document it was read from and
/// what the open's caller states beside it. The member is kept as stated, a member stated twice
/// included, so that the open judges it as the other ABIs judge the same text.
#[derive(Clone, Debug, Default, PartialEq)]
pub(crate) struct WzStatements {
    /// Each top-level `wz` member of the document other than a `null`, which states nothing.
    member: Vec<Stated>,
    /// The profile the open's caller names.
    profile: Option<String>,
    /// The policies the open's caller states, each once, in the order first stated.
    policies: Vec<(String, String)>,
}

impl WzStatements {
    /// `inner` with each top-level `wz` member it holds taken into this.
    fn splitting<D>(&mut self, inner: D) -> Splitting<'_, D> {
        Splitting {
            inner,
            member: &mut self.member,
        }
    }

    /// Set `value`, a JSON5 text, at `path` under the `wz` member (`""` for the member itself).
    /// A value already there is replaced; a member on the way that holds something other than an
    /// object refuses the insert, which then changes nothing.
    fn insert(&mut self, path: &str, value: &str) -> ZResult<()> {
        let value: Stated = json5::from_str(value)
            .map_err(|error| zerror!("`wz/{path}` cannot be set to {value}: {error}"))?;
        if path.is_empty() {
            self.member = match value {
                Stated::Null => Vec::new(),
                value => vec![value],
            };
            return Ok(());
        }
        let segments: Vec<&str> = path.split('/').collect();
        if segments.iter().any(|segment| segment.is_empty()) {
            bail!("`wz/{path}` names a member with no name");
        }
        let Some((key, rest)) = segments.split_first() else {
            bail!("`wz/{path}` names no member");
        };
        if self.member.is_empty() {
            self.member.push(Stated::Object(Vec::new()));
        }
        let last = self.member.len() - 1;
        insert_at(&mut self.member[last], WZ_MEMBER, key, rest, value)
    }

    /// The JSON text of what is stated at `path` under the `wz` member, the last of a member
    /// stated twice as a reader takes it.
    fn get_json(&self, path: &str) -> ZResult<String> {
        let mut found = self.member.last();
        if !path.is_empty() {
            for segment in path.split('/') {
                found = match found {
                    Some(Stated::Object(members)) => members
                        .iter()
                        .rev()
                        .find(|(key, _)| key == segment)
                        .map(|(_, value)| value),
                    _ => None,
                };
            }
        }
        match found {
            Some(value) => serde_json::to_string(value).map_err(|error| zerror!("{error}").into()),
            None => bail!("the configuration states nothing at `{WZ_MEMBER}/{path}`"),
        }
    }

    /// Each `wz` member, gathered in its order as the members of a document of its own, which is
    /// what the reader of the member reads.
    #[cfg(feature = "engine-tokio")]
    fn tree(&self) -> wz_session_core::json5::Json5Value {
        wz_session_core::json5::Json5Value::Object(
            self.member
                .iter()
                .map(|member| (WZ_MEMBER.to_owned(), member.to_json5()))
                .collect(),
        )
    }

    /// The key ids the member states (`wz/key-ids`).
    #[cfg(feature = "shared-key-ids")]
    fn key_ids(&self) -> ZResult<wz_session_core::shared_key_ids::KeyIdsAtOpen> {
        let tree = self.tree();
        wz_session_core::policy_document::statements_from_json5(&tree)
            .map(|read| read.key_ids)
            .map_err(|refusals| zerror!("the `wz` member is refused: {refusals}").into())
    }

    #[cfg(feature = "engine-tokio")]
    fn resolve(&self) -> ZResult<wz_session_core::policy_document::Resolved> {
        use wz_session_core::{
            policy::SessionPolicy,
            policy_document::{resolve_document_under, Overrides, Stated, Statement},
        };

        let tree = self.tree();
        let statements: Vec<Statement<'_>> = self
            .policies
            .iter()
            .map(|(policy, value)| Statement::new(policy.as_str(), value.as_str()))
            .collect();
        let overrides = Overrides {
            profile: self.profile.as_deref(),
            statements: Stated::Read(&statements),
            ..Overrides::default()
        };
        resolve_document_under(SessionPolicy::defaults(), &tree, overrides)
            .map_err(|refusals| zerror!("the `wz` member is refused: {refusals}").into())
    }
}

/// `value` set at `key` and then `rest` under `node`, the member `at` names.
fn insert_at(node: &mut Stated, at: &str, key: &str, rest: &[&str], value: Stated) -> ZResult<()> {
    let Stated::Object(members) = node else {
        bail!("`{at}` holds something other than an object, so `{at}/{key}` cannot be set");
    };
    match rest.split_first() {
        None => {
            match members.iter().position(|(stated, _)| stated == key) {
                // The first keeps its place and takes the value; a later one of the same key
                // would be read over it, so it goes.
                Some(first) => {
                    members[first].1 = value;
                    let mut index = 0;
                    members.retain(|(stated, _)| {
                        let keep = index == first || stated != key;
                        index += 1;
                        keep
                    });
                }
                None => members.push((key.to_owned(), value)),
            }
            Ok(())
        }
        Some((next, deeper)) => {
            let index = match members.iter().rposition(|(stated, _)| stated == key) {
                Some(index) => index,
                None => {
                    members.push((key.to_owned(), Stated::Object(Vec::new())));
                    members.len() - 1
                }
            };
            let path = format!("{at}/{key}");
            insert_at(&mut members[index].1, &path, next, deeper, value)
        }
    }
}

/// A JSON5 value as a document states it: an object keeps every member in order, one stated
/// twice included, and a number its text.
#[derive(Clone, Debug, PartialEq)]
pub(crate) enum Stated {
    Null,
    Bool(bool),
    Number(String),
    String(String),
    Array(Vec<Stated>),
    Object(Vec<(String, Stated)>),
}

impl Stated {
    /// The same value as the tree wz's own JSON5 reader makes.
    #[cfg(feature = "engine-tokio")]
    fn to_json5(&self) -> wz_session_core::json5::Json5Value {
        use wz_session_core::json5::Json5Value;
        match self {
            Stated::Null => Json5Value::Null,
            Stated::Bool(value) => Json5Value::Bool(*value),
            Stated::Number(text) => Json5Value::Number(text.clone()),
            Stated::String(text) => Json5Value::String(text.clone()),
            Stated::Array(items) => Json5Value::Array(items.iter().map(Stated::to_json5).collect()),
            Stated::Object(members) => Json5Value::Object(
                members
                    .iter()
                    .map(|(key, value)| (key.clone(), value.to_json5()))
                    .collect(),
            ),
        }
    }
}

impl Serialize for Stated {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        match self {
            Stated::Null => serializer.serialize_unit(),
            Stated::Bool(value) => serializer.serialize_bool(*value),
            Stated::Number(text) => {
                if let Ok(value) = text.parse::<u64>() {
                    serializer.serialize_u64(value)
                } else if let Ok(value) = text.parse::<i64>() {
                    serializer.serialize_i64(value)
                } else if let Ok(value) = text.parse::<f64>() {
                    serializer.serialize_f64(value)
                } else {
                    serializer.serialize_str(text)
                }
            }
            Stated::String(text) => serializer.serialize_str(text),
            Stated::Array(items) => {
                let mut seq = serializer.serialize_seq(Some(items.len()))?;
                for item in items {
                    seq.serialize_element(item)?;
                }
                seq.end()
            }
            Stated::Object(members) => {
                let mut map = serializer.serialize_map(Some(members.len()))?;
                for (key, value) in members {
                    map.serialize_entry(key, value)?;
                }
                map.end()
            }
        }
    }
}

impl<'de> Deserialize<'de> for Stated {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        deserializer.deserialize_any(StatedVisitor)
    }
}

struct StatedVisitor;

impl<'de> de::Visitor<'de> for StatedVisitor {
    type Value = Stated;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("a JSON5 value")
    }

    fn visit_unit<E: de::Error>(self) -> Result<Stated, E> {
        Ok(Stated::Null)
    }

    fn visit_none<E: de::Error>(self) -> Result<Stated, E> {
        Ok(Stated::Null)
    }

    fn visit_some<D: serde::Deserializer<'de>>(self, deserializer: D) -> Result<Stated, D::Error> {
        Stated::deserialize(deserializer)
    }

    fn visit_bool<E: de::Error>(self, value: bool) -> Result<Stated, E> {
        Ok(Stated::Bool(value))
    }

    fn visit_i64<E: de::Error>(self, value: i64) -> Result<Stated, E> {
        Ok(Stated::Number(value.to_string()))
    }

    fn visit_u64<E: de::Error>(self, value: u64) -> Result<Stated, E> {
        Ok(Stated::Number(value.to_string()))
    }

    fn visit_f64<E: de::Error>(self, value: f64) -> Result<Stated, E> {
        Ok(Stated::Number(value.to_string()))
    }

    fn visit_str<E: de::Error>(self, value: &str) -> Result<Stated, E> {
        Ok(Stated::String(value.to_owned()))
    }

    fn visit_string<E: de::Error>(self, value: String) -> Result<Stated, E> {
        Ok(Stated::String(value))
    }

    fn visit_seq<A: de::SeqAccess<'de>>(self, mut seq: A) -> Result<Stated, A::Error> {
        let mut items = Vec::new();
        while let Some(item) = seq.next_element()? {
            items.push(item);
        }
        Ok(Stated::Array(items))
    }

    fn visit_map<A: de::MapAccess<'de>>(self, mut map: A) -> Result<Stated, A::Error> {
        let mut members = Vec::new();
        while let Some(member) = map.next_entry::<String, Stated>()? {
            members.push(member);
        }
        Ok(Stated::Object(members))
    }
}

/// A deserializer of zenoh's configuration that hands its reader every top-level member but
/// `wz`, which it keeps. The reader's own deserializer reads every key, so what it refuses and
/// where it says it is as without the member.
struct Splitting<'s, D> {
    inner: D,
    member: &'s mut Vec<Stated>,
}

impl<'de, D: serde::Deserializer<'de>> serde::Deserializer<'de> for Splitting<'_, D> {
    type Error = D::Error;

    fn deserialize_any<V: de::Visitor<'de>>(self, visitor: V) -> Result<V::Value, D::Error> {
        self.inner.deserialize_any(SplittingVisitor {
            inner: visitor,
            member: self.member,
        })
    }

    fn deserialize_map<V: de::Visitor<'de>>(self, visitor: V) -> Result<V::Value, D::Error> {
        self.inner.deserialize_map(SplittingVisitor {
            inner: visitor,
            member: self.member,
        })
    }

    fn deserialize_struct<V: de::Visitor<'de>>(
        self,
        name: &'static str,
        fields: &'static [&'static str],
        visitor: V,
    ) -> Result<V::Value, D::Error> {
        self.inner.deserialize_struct(
            name,
            fields,
            SplittingVisitor {
                inner: visitor,
                member: self.member,
            },
        )
    }

    fn is_human_readable(&self) -> bool {
        self.inner.is_human_readable()
    }

    // The configuration is read as a struct; any other shape is read as the format has it.
    serde::forward_to_deserialize_any! {
        bool i8 i16 i32 i64 i128 u8 u16 u32 u64 u128 f32 f64 char str string bytes byte_buf
        option unit unit_struct newtype_struct seq tuple tuple_struct enum identifier ignored_any
    }
}

struct SplittingVisitor<'s, V> {
    inner: V,
    member: &'s mut Vec<Stated>,
}

impl<'de, V: de::Visitor<'de>> de::Visitor<'de> for SplittingVisitor<'_, V> {
    type Value = V::Value;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.inner.expecting(formatter)
    }

    fn visit_map<A: de::MapAccess<'de>>(self, map: A) -> Result<V::Value, A::Error> {
        self.inner.visit_map(SplittingMap {
            inner: map,
            member: self.member,
        })
    }

    fn visit_seq<A: de::SeqAccess<'de>>(self, seq: A) -> Result<V::Value, A::Error> {
        self.inner.visit_seq(seq)
    }
}

struct SplittingMap<'s, A> {
    inner: A,
    member: &'s mut Vec<Stated>,
}

impl<'de, A: de::MapAccess<'de>> de::MapAccess<'de> for SplittingMap<'_, A> {
    type Error = A::Error;

    fn next_key_seed<K: de::DeserializeSeed<'de>>(
        &mut self,
        mut seed: K,
    ) -> Result<Option<K::Value>, A::Error> {
        loop {
            match self.inner.next_key_seed(KeySeed(seed))? {
                None => return Ok(None),
                Some(Key::Other(key)) => return Ok(Some(key)),
                Some(Key::Wz(unused)) => {
                    let stated: Stated = self.inner.next_value()?;
                    if !matches!(stated, Stated::Null) {
                        self.member.push(stated);
                    }
                    seed = unused;
                }
            }
        }
    }

    fn next_value_seed<T: de::DeserializeSeed<'de>>(
        &mut self,
        seed: T,
    ) -> Result<T::Value, A::Error> {
        self.inner.next_value_seed(seed)
    }

    fn size_hint(&self) -> Option<usize> {
        self.inner.size_hint()
    }
}

/// A key of the configuration's top level: the `wz` member, with the reader's seed handed back
/// unused, or a key of zenoh's as the reader's seed read it.
enum Key<K, T> {
    Wz(K),
    Other(T),
}

/// The reader's seed for a key, which reads the key inside the format's deserializer of it, so
/// that a key the reader refuses is reported where the format reports one.
struct KeySeed<K>(K);

impl<'de, K: de::DeserializeSeed<'de>> de::DeserializeSeed<'de> for KeySeed<K> {
    type Value = Key<K, K::Value>;

    fn deserialize<D: serde::Deserializer<'de>>(
        self,
        deserializer: D,
    ) -> Result<Self::Value, D::Error> {
        deserializer.deserialize_identifier(KeyVisitor(self.0))
    }
}

struct KeyVisitor<K>(K);

impl<'de, K: de::DeserializeSeed<'de>> de::Visitor<'de> for KeyVisitor<K> {
    type Value = Key<K, K::Value>;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("a field identifier")
    }

    fn visit_str<E: de::Error>(self, value: &str) -> Result<Self::Value, E> {
        if value == WZ_MEMBER {
            return Ok(Key::Wz(self.0));
        }
        self.0
            .deserialize(de::value::StrDeserializer::<E>::new(value))
            .map(Key::Other)
    }

    fn visit_bytes<E: de::Error>(self, value: &[u8]) -> Result<Self::Value, E> {
        if value == WZ_MEMBER.as_bytes() {
            return Ok(Key::Wz(self.0));
        }
        self.0
            .deserialize(de::value::BytesDeserializer::<E>::new(value))
            .map(Key::Other)
    }

    fn visit_u64<E: de::Error>(self, value: u64) -> Result<Self::Value, E> {
        self.0
            .deserialize(de::value::U64Deserializer::<E>::new(value))
            .map(Key::Other)
    }
}

#[zenoh_macros::unstable]
impl std::ops::Deref for Config {
    type Target = zenoh_config::Config;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

#[zenoh_macros::unstable]
impl std::ops::DerefMut for Config {
    fn deref_mut(&mut self) -> &mut <Self as std::ops::Deref>::Target {
        &mut self.0
    }
}

#[doc(hidden)]
impl From<zenoh_config::Config> for Config {
    fn from(value: zenoh_config::Config) -> Self {
        Self(value, WzStatements::default())
    }
}

#[doc(hidden)]
impl From<Config> for zenoh_config::Config {
    fn from(value: Config) -> Self {
        value.0
    }
}

impl fmt::Display for Config {
    /// zenoh's own text, and each `wz` member after its members when the document states one.
    /// zenoh's text is kept as it is because only its writer knows which values to keep private.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.1.member.is_empty() {
            return write!(f, "{}", self.0);
        }
        let mut zenoh = String::new();
        fmt::Write::write_fmt(&mut zenoh, format_args!("{}", self.0))?;
        let Some(open) = zenoh.strip_suffix('}') else {
            return f.write_str(&zenoh);
        };
        f.write_str(open)?;
        let mut first = open.trim_end().ends_with('{');
        for member in &self.1.member {
            if !first {
                f.write_str(",")?;
            }
            first = false;
            let text = serde_json::to_string(member).map_err(|_| fmt::Error)?;
            write!(f, "\"{WZ_MEMBER}\":{text}")?;
        }
        f.write_str("}")
    }
}

pub type Notification = Arc<str>;

struct NotifierInner<T> {
    inner: Mutex<T>,
    subscribers: Mutex<Vec<flume::Sender<Notification>>>,
}

/// The wrapper for a [`Config`] that allows to subscribe to changes.
/// This type is returned by [`Session::config`](crate::Session::config) and allows
/// the `Session` to immediately react to changes applied to the configuration.
pub struct Notifier<T> {
    inner: Arc<NotifierInner<T>>,
}

impl<T> fmt::Debug for Notifier<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("Notifier").field(&"..").finish()
    }
}

impl<T> Clone for Notifier<T> {
    fn clone(&self) -> Self {
        Self {
            inner: self.inner.clone(),
        }
    }
}

fn ensure_config_key_is_dynamically_writable(key: &str) -> ZResult<()> {
    if !key.starts_with("plugins/") {
        bail!(
            "Error inserting conf value {} : updating config is only \
                supported for keys starting with `plugins/`",
            key
        );
    }
    Ok(())
}

impl Notifier<ExpandedConfig> {
    pub fn new(inner: ExpandedConfig) -> Self {
        Notifier {
            inner: Arc::new(NotifierInner {
                inner: Mutex::new(inner),
                subscribers: Mutex::new(Vec::new()),
            }),
        }
    }

    #[cfg(feature = "plugins")]
    pub fn subscribe(&self) -> flume::Receiver<Notification> {
        let (tx, rx) = flume::unbounded();
        self.lock_subscribers().push(tx);
        rx
    }

    pub fn notify<K: AsRef<str>>(&self, key: K) {
        let key = key.as_ref();
        let key: Arc<str> = Arc::from(key);
        let mut marked = Vec::new();
        let mut subscribers = self.lock_subscribers();

        for (i, sub) in subscribers.iter().enumerate() {
            if sub.send(key.clone()).is_err() {
                marked.push(i)
            }
        }

        for i in marked.into_iter().rev() {
            subscribers.swap_remove(i);
        }
    }

    pub fn lock(&self) -> MutexGuard<'_, ExpandedConfig> {
        self.lock_config()
    }

    fn lock_subscribers(&self) -> MutexGuard<'_, Vec<flume::Sender<Notification>>> {
        self.inner
            .subscribers
            .lock()
            .expect("acquiring Notifier's subscribers Mutex should not fail")
    }

    fn lock_config(&self) -> MutexGuard<'_, ExpandedConfig> {
        self.inner
            .inner
            .lock()
            .expect("acquiring Notifier's Config Mutex should not fail")
    }

    pub fn remove<K: AsRef<str>>(&self, key: K) -> ZResult<()> {
        self.lock_config().remove(key.as_ref())?;
        self.notify(key);
        Ok(())
    }

    pub fn try_remove_json5_array_item<K: AsRef<str>>(&self, key: K) -> ZResult<bool> {
        let applied = self
            .lock_config()
            .try_remove_json5_array_item(key.as_ref())?;
        if applied {
            self.notify(key);
        }
        Ok(applied)
    }

    pub fn insert_json5(&self, key: &str, value: &str) -> ZResult<()> {
        ensure_config_key_is_dynamically_writable(key)?;
        self.lock_config().insert_json5(key, value)?;
        self.notify(key);
        Ok(())
    }

    pub fn try_insert_json5_array_item(&self, key: &str, value: &str) -> ZResult<bool> {
        ensure_config_key_is_dynamically_writable(key)?;
        let applied = self.lock_config().try_insert_json5_array_item(key, value)?;
        if applied {
            self.notify(key);
        }
        Ok(applied)
    }
}

/// What a session hands out as its configuration ([`Session::config`](crate::Session::config)):
/// the notifier of the configuration the session was opened with, read and written through the
/// interface the configuration crate names.
#[cfg(feature = "unstable")]
impl zenoh_config::IConfig for Notifier<ExpandedConfig> {
    fn get(&self, key: &str) -> ZResult<String> {
        self.lock()
            .get_json(key)
            .map_err(|err| zerror!("{err}").into())
    }

    fn queries_default_timeout_ms(&self) -> u64 {
        let guard = self.lock();
        let config = &guard;
        zenoh_config::unwrap_or_default!(config.queries_default_timeout())
    }

    fn insert_json5(&self, key: &str, value: &str) -> ZResult<()> {
        self.insert_json5(key, value)
    }

    fn to_json(&self) -> String {
        self.lock().to_string()
    }
}

#[cfg(test)]
mod tests {
    use zenoh_config::{InterceptorFlow, QosOverwriteItemConf};

    use super::{Stated, WzStatements};
    use crate::Config;

    fn text(value: &str) -> Stated {
        Stated::String(value.to_owned())
    }

    fn object(members: &[(&str, Stated)]) -> Stated {
        Stated::Object(
            members
                .iter()
                .map(|(key, value)| ((*key).to_owned(), value.clone()))
                .collect(),
        )
    }

    /// zenoh's reader is not handed the member, and the member keeps what it states, a policy
    /// stated twice included, for the open to judge.
    #[test]
    fn a_wz_member_is_held_beside_zenohs_configuration_as_stated() {
        let config = Config::from_json5(
            r#"{ mode: "peer", wz: { policies: { "key-set": "open", "key-set": "closed" } } }"#,
        )
        .expect("zenoh's reader does not see the member");
        assert_eq!(
            config.1.member,
            [object(&[(
                "policies",
                object(&[("key-set", text("open")), ("key-set", text("closed"))])
            )])]
        );
        assert_eq!(config.get_json("mode").unwrap(), r#""peer""#);
    }

    /// A configuration that states no member reads and writes as zenoh's does.
    #[test]
    fn a_configuration_with_no_wz_member_is_zenohs_alone() {
        let config = Config::from_json5(r#"{ mode: "peer" }"#).expect("zenoh's");
        assert_eq!(config.1, WzStatements::default());
        assert_eq!(config.to_string(), config.0.to_string());
        assert_eq!(
            serde_json::to_value(&config).unwrap(),
            serde_json::to_value(&config.0).unwrap()
        );
        let error = Config::from_json5(r#"{ colour: "blue" }"#)
            .map(|_| ())
            .unwrap_err()
            .to_string();
        assert!(error.contains("unknown field `colour`"), "{error}");
    }

    /// The member's `wz/limits`, read whole or inserted, resolves as the reader of a document
    /// resolves it for a creator that holds a session's limits, for each member of the corpus
    /// every door is held to: the limits it selects, or the refusals it meets, each named.
    #[cfg(feature = "engine-tokio")]
    #[test]
    fn the_members_limits_resolve_as_the_corpus_states_for_a_session() {
        use wz_session_core::limit_corpus::{cases, Expected};

        for case in cases() {
            let read = Config::from_json5(&case.document())
                .unwrap_or_else(|error| panic!("{}: {error}", case.name));
            let mut inserted = Config::default();
            inserted
                .insert_json5("wz/limits", &case.limits)
                .unwrap_or_else(|error| panic!("{}: {error}", case.name));
            for config in [read, inserted] {
                match (&case.session, config.resolve_policies()) {
                    (Expected::Selected(_), Ok(resolved)) => {
                        if let Err(why) = case.session.check_session(&resolved.limits.session) {
                            panic!("{}: {why}", case.name);
                        }
                    }
                    (Expected::Refused(_), Err(error)) => {
                        let error = error.to_string();
                        for text in case.session.refusal_texts() {
                            assert!(error.contains(&text), "{}: {error}", case.name);
                        }
                    }
                    (Expected::Selected(_), Err(error)) => panic!("{}: {error}", case.name),
                    (Expected::Refused(reasons), Ok(_)) => {
                        panic!("{}: taken, and the case expects {reasons:?}", case.name)
                    }
                }
            }
        }
    }

    /// Each top-level member is kept, a second one included, and a `null` states nothing.
    #[test]
    fn every_top_level_wz_member_but_a_null_is_kept() {
        let config =
            Config::from_json5(r#"{ wz: { profile: "upstream" }, wz: null, wz: {} }"#).unwrap();
        assert_eq!(
            config.1.member,
            [object(&[("profile", text("upstream"))]), object(&[])]
        );
    }

    /// An insert under `wz` replaces what the path held, as an insert of a zenoh key does, and
    /// one the member cannot take changes nothing.
    #[test]
    fn an_insert_under_wz_replaces_and_a_refused_one_changes_nothing() {
        let mut config = Config::default();
        config
            .insert_json5("wz/policies/key-set", r#""open""#)
            .unwrap();
        config
            .insert_json5("wz/policies/key-set", r#""closed""#)
            .unwrap();
        assert_eq!(
            config.get_json("wz/policies/key-set").unwrap(),
            r#""closed""#
        );
        assert_eq!(
            config.get_json("wz").unwrap(),
            r#"{"policies":{"key-set":"closed"}}"#
        );
        config
            .insert_json5("wz", r#"{ profile: "upstream" }"#)
            .unwrap();
        assert_eq!(config.get_json("wz").unwrap(), r#"{"profile":"upstream"}"#);
        assert!(config.insert_json5("wz/profile/id", r#""x""#).is_err());
        assert!(config.insert_json5("wz//profile", r#""x""#).is_err());
        assert!(config.insert_json5("wz/profile", "{").is_err());
        assert_eq!(config.get_json("wz").unwrap(), r#"{"profile":"upstream"}"#);
        assert!(config.get_json("wz/policies").is_err());
        // A key that only begins with the member's name is zenoh's, which has no such key.
        assert!(config.insert_json5("wzx", "1").is_err());
        config.insert_json5("wz", "null").unwrap();
        assert_eq!(config.1, WzStatements::default());
    }

    /// The member is written after zenoh's own members, by the text and by serde, and read back.
    #[test]
    fn the_member_is_written_with_the_configuration_and_read_back() {
        let config = Config::from_json5(r#"{ wz: { profile: "upstream" } }"#).unwrap();
        let written = config.to_string();
        assert!(
            written.ends_with(r#","wz":{"profile":"upstream"}}"#),
            "{written}"
        );
        let parsed: serde_json::Value = serde_json::from_str(&written).expect("JSON");
        assert_eq!(parsed["wz"]["profile"], "upstream");
        let serialized = serde_json::to_value(&config).unwrap();
        assert_eq!(
            serialized["wz"],
            serde_json::json!({ "profile": "upstream" })
        );
        let read: Config =
            serde_json::from_str(r#"{ "mode": "peer", "wz": { "profile": "upstream" } }"#)
                .expect("serde reads the member as from_json5 does");
        assert_eq!(read.1.member, config.1.member);
        assert_eq!(read.get_json("mode").unwrap(), r#""peer""#);
    }

    /// The member resolves as the document's `wz` member does on every ABI, and a refused one
    /// names each refusal.
    #[cfg(feature = "engine-tokio")]
    #[test]
    fn the_member_resolves_as_a_document_and_a_refused_one_names_each_refusal() {
        use wz_session_core::{json5::parse, policy::SessionPolicy, policy_document};

        let document =
            r#"{ wz: { policies: { "subscriber-overload": "block", "key-set": "open" } } }"#;
        let config = Config::from_json5(document).unwrap();
        let tree = parse(document).unwrap();
        assert_eq!(
            config.resolve_policies().ok(),
            policy_document::resolve_document(SessionPolicy::defaults(), &tree).ok()
        );
        assert_eq!(
            Config::default().resolve_policies().ok(),
            Some(policy_document::Resolved::unchanged(
                SessionPolicy::defaults()
            ))
        );
        let refused =
            Config::from_json5(r#"{ wz: { profile: "no-such-profile", colour: "blue" } }"#)
                .unwrap();
        let error = refused.resolve_policies().unwrap_err().to_string();
        assert!(error.starts_with("the `wz` member is refused: "), "{error}");
        assert!(error.contains("`wz/colour`"), "{error}");
        assert!(error.contains("`no-such-profile`"), "{error}");
    }

    /// The key ids the member states are read as a document's are on every ABI: the member read
    /// whole and its `wz/key-ids` inserted give the same key ids, and a refused part of it
    /// refuses the policies of the member with it.
    #[cfg(feature = "shared-key-ids")]
    #[test]
    fn the_members_key_ids_are_read_as_a_documents() {
        use wz_session_core::policy::KeyWireForm;
        use wz_session_core::shared_key_ids::{KeyIds, KeyIdsAtOpen};

        let member = r#"{ dictionary: [ { id: 40, key: "lab/rig" }, { id: 41, key: "lab/rig/alpha" } ],
                          links: [ { locator: "tcp/192.0.2.7:7447", form: "literal" } ] }"#;
        let expected = KeyIdsAtOpen {
            ids: Some(std::sync::Arc::new(
                KeyIds::new([(40, "lab/rig"), (41, "lab/rig/alpha")]).expect("valid"),
            )),
            links: vec![("tcp/192.0.2.7:7447".to_owned(), KeyWireForm::Literal)],
        };
        let read = Config::from_json5(&format!(
            r#"{{ mode: "peer", wz: {{ "key-ids": {member} }} }}"#
        ))
        .expect("zenoh's reader does not see the member");
        assert_eq!(read.resolve_key_ids().ok(), Some(expected.clone()));
        assert!(read.resolve_policies().is_ok());
        let mut inserted = Config::default();
        inserted
            .insert_json5("wz/key-ids", member)
            .expect("the member takes an object");
        assert_eq!(inserted.resolve_key_ids().ok(), Some(expected));
        assert_eq!(
            Config::default().resolve_key_ids().ok(),
            Some(KeyIdsAtOpen::default())
        );
        let refused = Config::from_json5(
            r#"{ wz: { "key-ids": { dictionary: [ { id: 0, key: "lab/rig" } ] } } }"#,
        )
        .unwrap();
        let error = refused.resolve_policies().unwrap_err().to_string();
        assert!(
            error.contains("id 0 in entry 0 of `wz/key-ids/dictionary`"),
            "{error}"
        );
        assert!(refused.resolve_key_ids().is_err());
    }

    /// A build without the capability refuses `wz/key-ids` with the policies of the member, by
    /// name, and opens nothing on it.
    #[cfg(all(feature = "engine-tokio", not(feature = "shared-key-ids")))]
    #[test]
    fn the_members_key_ids_are_refused_without_the_capability() {
        let config = Config::from_json5(
            r#"{ wz: { "key-ids": { dictionary: [ { id: 40, key: "lab/rig" } ] } } }"#,
        )
        .unwrap();
        let error = config.resolve_policies().unwrap_err().to_string();
        assert!(
            error.contains("a build without the `shared-key-ids` capability"),
            "{error}"
        );
    }

    /// A statement of the open's own layer that the build refuses is refused at once and changes
    /// nothing; a second statement of a policy replaces the first.
    #[cfg(feature = "open-policies")]
    #[test]
    fn the_opens_statements_are_judged_at_once() {
        let mut config = Config::default();
        let error = config
            .state_policy("no-such-policy", "on")
            .unwrap_err()
            .to_string();
        assert!(
            error.contains("the build has no policy `no-such-policy`"),
            "{error}"
        );
        assert!(config.state_policy("key-set", "ajar").is_err());
        let error = config
            .state_profile("no-such-profile")
            .unwrap_err()
            .to_string();
        assert!(
            error.contains("names the profile `no-such-profile`"),
            "{error}"
        );
        assert_eq!(config.1, WzStatements::default());
        let held = wz_session_core::policy::SessionPolicy::defaults()
            .key_set()
            .id();
        config.state_policy("key-set", held).unwrap();
        config.state_policy("key-set", held).unwrap();
        assert_eq!(config.1.policies, [("key-set".to_owned(), held.to_owned())]);
    }

    #[test]
    fn runtime_try_insert_json5_array_item_rejects_non_plugin_keys() {
        let config = super::Notifier::new(zenoh_config::Config::default().expanded());
        let before = config.lock().get_json("qos/network").unwrap();

        let err = config
            .try_insert_json5_array_item(
                "qos/network/id=item1",
                r#"{
                    id: "item1",
                    messages: ["put"],
                    key_exprs: ["**"],
                    overwrite: { priority: "real_time" },
                    flows: ["egress"]
                }"#,
            )
            .unwrap_err();

        assert!(err
            .to_string()
            .contains("supported for keys starting with `plugins/`"));
        assert_eq!(config.lock().get_json("qos/network").unwrap(), before);
    }

    #[test]
    fn insert_remove_json5_array_item() {
        let mut config = Config::default();

        let item1 = r#"{
            id: "item1",
            messages: ["put"],
            key_exprs: ["**"],
            overwrite: {
                priority: "real_time",
            },
            flows: ["egress"]
        }"#;
        assert!(config
            .try_insert_json5_array_item("qos/network/id=item1", item1)
            .unwrap());
        let items = serde_json::from_str::<Vec<QosOverwriteItemConf>>(
            &config.get_json("qos/network").unwrap(),
        )
        .unwrap();
        assert_eq!(items.len(), 1);
        assert_eq!(items[0].id.as_ref().unwrap(), "item1");
        assert_eq!(
            *items[0].flows.as_ref().unwrap().first(),
            InterceptorFlow::Egress
        );

        let item1 = r#"{
            id: "item1",
            messages: ["put"],
            key_exprs: ["**"],
            overwrite: {
                priority: "real_time",
            },
            flows: ["ingress"]
        }"#;
        assert!(config
            .try_insert_json5_array_item("qos/network/id=item1", item1)
            .unwrap());
        let items = serde_json::from_str::<Vec<QosOverwriteItemConf>>(
            &config.get_json("qos/network").unwrap(),
        )
        .unwrap();
        assert_eq!(items.len(), 1);
        assert_eq!(items[0].id.as_ref().unwrap(), "item1");
        assert_eq!(
            *items[0].flows.as_ref().unwrap().first(),
            InterceptorFlow::Ingress
        );

        let item2 = r#"{
            id: "item2",
            messages: ["put"],
            key_exprs: ["**"],
            overwrite: {
                priority: "real_time",
            },
            flows: ["egress"]
        }"#;
        assert!(config
            .try_insert_json5_array_item("qos/network/id=item2", item2)
            .unwrap());
        let items = serde_json::from_str::<Vec<QosOverwriteItemConf>>(
            &config.get_json("qos/network").unwrap(),
        )
        .unwrap();
        assert_eq!(items.len(), 2);
        assert_eq!(items[0].id.as_ref().unwrap(), "item1");
        assert_eq!(
            *items[0].flows.as_ref().unwrap().first(),
            InterceptorFlow::Ingress
        );
        assert_eq!(items[1].id.as_ref().unwrap(), "item2");
        assert_eq!(
            *items[1].flows.as_ref().unwrap().first(),
            InterceptorFlow::Egress
        );

        assert!(config
            .try_remove_json5_array_item("qos/network/id=item2")
            .unwrap());
        let items = serde_json::from_str::<Vec<QosOverwriteItemConf>>(
            &config.get_json("qos/network").unwrap(),
        )
        .unwrap();
        assert_eq!(items.len(), 1);
        assert_eq!(items[0].id.as_ref().unwrap(), "item1");
        assert_eq!(
            *items[0].flows.as_ref().unwrap().first(),
            InterceptorFlow::Ingress
        );

        assert!(config
            .try_remove_json5_array_item("qos/network/id=item1")
            .unwrap());
        let items = serde_json::from_str::<Vec<QosOverwriteItemConf>>(
            &config.get_json("qos/network").unwrap(),
        )
        .unwrap();
        assert_eq!(items.len(), 0);
    }
}
