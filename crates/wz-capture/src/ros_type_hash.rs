// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The ROS 2 type hash of a declared type: the `RIHS01_<hex>` a ROS 2 key
//! carries beside its type name, computed from the definitions
//! `crate::ros_msg` reads.
//!
//! # What is hashed
//!
//! The ROS Interface Hashing Standard, version 1, as rosidl's generator
//! computes it (`rosidl_generator_type_description`): SHA-256 over the JSON
//! text of the type's description with every default value removed. The
//! description is the type itself and every type it reaches, transitively,
//! sorted by name:
//!
//! ```text
//! {"type_description": T, "referenced_type_descriptions": [R1, R2, ...]}
//! T = {"type_name": "pkg/msg/Name", "fields": [F, ...]}
//! F = {"name": "x", "type": {"type_id": N, "capacity": N,
//!      "string_capacity": N, "nested_type_name": "pkg/msg/Inner"}}
//! ```
//!
//! written with `", "` and `": "` between items and keys, in this key order,
//! with no other whitespace. Constants and comments are in no description. A
//! type with no fields is described with the one `uint8` rosidl gives it. The
//! `type_id` is `type_description_interfaces/msg/FieldType`'s number for the
//! field's type, plus 48 for a fixed array, 96 for a bounded sequence and 144
//! for an unbounded one; `capacity` is the array's size or the sequence's
//! bound, and `string_capacity` a bounded string's bound. A `.msg` `char` is
//! a `uint8` and a `byte` an `octet`, as rosidl's `.msg` reader turns them.
//!
//! A service's own type (`pkg/srv/Name`, whose members are its request, its
//! response and its event) and an action's are hashed as a message is; their
//! descriptions reach `service_msgs/msg/ServiceEventInfo` and
//! `builtin_interfaces/msg/Time`, which `crate::ros_msg` carries.
//!
//! Every name the definition grammar admits is ASCII letters, digits, `_`
//! and `/`, so the JSON needs no escape and `ensure_ascii` changes nothing.

use alloc::collections::BTreeMap;
use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;
use core::fmt::Write as _;

use crate::ros_msg::{Arity, Base, FieldDef, MessageDef, Primitive, TypeSet, EMPTY_MEMBER};

/// What every hash of this version opens with.
const RIHS01_PREFIX: &str = "RIHS01_";

/// `FieldType`'s number for a `uint8`, the type of the member an empty type
/// is given.
const UINT8: u32 = 3;

/// The RIHS01 hash of the type `name`, a message or a service's or an
/// action's own type, or why it cannot be computed: the type, or one it
/// reaches, is defined by no declared definition.
pub(crate) fn type_hash(set: &TypeSet, name: &str) -> Result<String, String> {
    let top = set
        .definition(name)
        .ok_or_else(|| format!("no declared definition defines {name}"))?;
    let mut referenced: BTreeMap<&str, &MessageDef> = BTreeMap::new();
    let mut queue: Vec<&str> = top.nested().collect();
    while let Some(next) = queue.pop() {
        if referenced.contains_key(next) {
            continue;
        }
        let def = set.definition(next).ok_or_else(|| {
            format!("{name} reaches {next}, which no declared definition defines")
        })?;
        referenced.insert(next, def);
        queue.extend(def.nested());
    }
    let mut json = String::from("{\"type_description\": ");
    describe(name, top, &mut json);
    json.push_str(", \"referenced_type_descriptions\": [");
    for (at, (inner, def)) in referenced.iter().enumerate() {
        if at > 0 {
            json.push_str(", ");
        }
        describe(inner, def, &mut json);
    }
    json.push_str("]}");
    let mut out = String::from(RIHS01_PREFIX);
    for byte in crate::sha256::digest(json.as_bytes()) {
        let _ = write!(out, "{byte:02x}");
    }
    Ok(out)
}

/// One type's individual description.
fn describe(name: &str, def: &MessageDef, out: &mut String) {
    let _ = write!(out, "{{\"type_name\": \"{name}\", \"fields\": [");
    if def.fields.is_empty() {
        field(EMPTY_MEMBER, UINT8, 0, 0, "", out);
    }
    for (at, f) in def.fields.iter().enumerate() {
        if at > 0 {
            out.push_str(", ");
        }
        let (capacity, string_capacity, nested) = shape(f);
        field(&f.name, type_id(f), capacity, string_capacity, nested, out);
    }
    out.push_str("]}");
}

/// One field's description.
fn field(
    name: &str,
    type_id: u32,
    capacity: u32,
    string_capacity: u32,
    nested: &str,
    out: &mut String,
) {
    let _ = write!(
        out,
        "{{\"name\": \"{name}\", \"type\": {{\"type_id\": {type_id}, \"capacity\": {capacity}, \
         \"string_capacity\": {string_capacity}, \"nested_type_name\": \"{nested}\"}}}}"
    );
}

/// A field's `capacity`, `string_capacity` and `nested_type_name`.
fn shape(f: &FieldDef) -> (u32, u32, &str) {
    let capacity = match f.arity {
        Arity::Fixed(size) | Arity::Sequence(Some(size)) => size,
        Arity::One | Arity::Sequence(None) => 0,
    };
    let (string_capacity, nested) = match &f.base {
        Base::String(Some(bound)) | Base::WString(Some(bound)) => (*bound, ""),
        Base::Message(inner) => (0, inner.as_str()),
        Base::Primitive(_) | Base::String(None) | Base::WString(None) => (0, ""),
    };
    (capacity, string_capacity, nested)
}

/// `FieldType`'s number for a field: its value type's, moved by its array.
fn type_id(f: &FieldDef) -> u32 {
    let value = match &f.base {
        Base::Message(_) => 1,
        Base::Primitive(p) => match p {
            Primitive::Int8 => 2,
            Primitive::Uint8 | Primitive::Char => UINT8,
            Primitive::Int16 => 4,
            Primitive::Uint16 => 5,
            Primitive::Int32 => 6,
            Primitive::Uint32 => 7,
            Primitive::Int64 => 8,
            Primitive::Uint64 => 9,
            Primitive::Float32 => 10,
            Primitive::Float64 => 11,
            Primitive::Bool => 15,
            Primitive::Byte => 16,
        },
        Base::String(None) => 17,
        Base::WString(None) => 18,
        Base::String(Some(_)) => 21,
        Base::WString(Some(_)) => 22,
    };
    value
        + match f.arity {
            Arity::One => 0,
            Arity::Fixed(_) => 48,
            Arity::Sequence(Some(_)) => 96,
            Arity::Sequence(None) => 144,
        }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ros_msg::DefinitionFile;

    fn set_of(files: &[(&str, &str)]) -> TypeSet {
        let files: Vec<DefinitionFile<'_>> = files
            .iter()
            .map(|&(name, text)| DefinitionFile { name, text })
            .collect();
        TypeSet::read(&files).expect("definitions")
    }

    /// The four published hashes, each from its package's own source file,
    /// comments and the doubled space of `Twist.msg` included: two messages,
    /// one nested, and two service types, whose descriptions reach the
    /// service event and the two messages ROS fixes.
    #[test]
    fn the_published_hashes_are_computed_exactly() {
        let set = set_of(&[
            (
                "std_msgs/msg/String.msg",
                "# This was originally provided as an example message.\n\
                 # It is deprecated as of Foxy\n\nstring data\n",
            ),
            (
                "geometry_msgs/msg/Twist.msg",
                "# This expresses velocity in free space.\n\nVector3  linear\nVector3  angular\n",
            ),
            (
                "geometry_msgs/msg/Vector3.msg",
                "# This represents a vector in free space.\n\nfloat64 x\nfloat64 y\nfloat64 z\n",
            ),
            ("std_srvs/srv/Empty.srv", "---\n"),
            (
                "example_interfaces/srv/AddTwoInts.srv",
                "int64 a\nint64 b\n---\nint64 sum\n",
            ),
        ]);
        for (name, hash) in [
            (
                "std_msgs/msg/String",
                "RIHS01_df668c740482bbd48fb39d76a70dfd4bd59db1288021743503259e948f6b1a18",
            ),
            (
                "geometry_msgs/msg/Twist",
                "RIHS01_9c45bf16fe0983d80e3cfe750d6835843d265a9a6c46bd2e609fcddde6fb8d2a",
            ),
            (
                "example_interfaces/srv/AddTwoInts",
                "RIHS01_e118de6bf5eeb66a2491b5bda11202e7b68f198d6f67922cf30364858239c81a",
            ),
            (
                "std_srvs/srv/Empty",
                "RIHS01_5888399dedec5ccc85ea6451949fd2c9f97bfdf963f9a588821639fcd31b5d19",
            ),
        ] {
            assert_eq!(type_hash(&set, name).as_deref(), Ok(hash), "{name}");
        }
    }

    /// Every type a service file defines has a hash, the derived ones and the
    /// two ROS fixes included, and they differ from one another.
    #[test]
    fn every_type_a_service_derives_is_hashed() {
        let set = set_of(&[("demo/srv/Add.srv", "int64 a\n---\nint64 sum")]);
        let mut seen: Vec<String> = Vec::new();
        for name in [
            "demo/srv/Add",
            "demo/srv/Add_Request",
            "demo/srv/Add_Response",
            "demo/srv/Add_Event",
            "service_msgs/msg/ServiceEventInfo",
            "builtin_interfaces/msg/Time",
        ] {
            let hash = type_hash(&set, name).expect(name);
            assert!(
                hash.starts_with(RIHS01_PREFIX) && hash.len() == 71,
                "{name}: {hash}"
            );
            assert!(!seen.contains(&hash), "{name} shares a hash");
            seen.push(hash);
        }
    }

    /// An action's derived service, read from its `.action` source as turtlesim
    /// ships it, hashes to the published value: the request is `goal_id` (a
    /// UUID) then `goal`, the response `accepted` then `stamp` (a Time), and
    /// the description reaches the goal, the UUID, the Time and the service
    /// event.
    #[test]
    fn a_published_action_service_hash_is_computed_exactly() {
        let set = set_of(&[(
            "turtlesim_msgs/action/RotateAbsolute.action",
            "# The desired heading in radians\nfloat32 theta\n---\n\
             # The angular displacement in radians to the starting position\nfloat32 delta\n\
             ---\n# The remaining rotation in radians\nfloat32 remaining\n",
        )]);
        assert_eq!(
            type_hash(&set, "turtlesim_msgs/action/RotateAbsolute_SendGoal").as_deref(),
            Ok("RIHS01_3d5d3cfcbb721f88038eaedcd4af95565360a82b36f1983e3a6c7448d2d18fbe")
        );
    }

    /// An action's own type and the types it derives are hashed. The action's
    /// own hash is pinned to the value the recipe that reproduces the published
    /// hashes above (the action service's included) gives when it is extended
    /// by rosidl's `add_action`: a change to how an action is described moves
    /// it.
    #[test]
    fn an_action_and_every_type_it_derives_is_hashed() {
        let set = set_of(&[(
            "example_interfaces/action/Fibonacci.action",
            "int32 order\n---\nint32[] sequence\n---\nint32[] sequence",
        )]);
        assert_eq!(
            type_hash(&set, "example_interfaces/action/Fibonacci").as_deref(),
            Ok("RIHS01_9508051da1ea4658de144b09bd0690ff3de52104683d847aed764d2915906f51")
        );
        for name in set
            .types_of_file("example_interfaces/action/Fibonacci.action")
            .expect("declared")
        {
            assert!(type_hash(&set, name).is_ok(), "{name}");
        }
    }

    /// A type that reaches one no file defines has no hash, and says which.
    #[test]
    fn a_type_that_reaches_an_undefined_one_has_no_hash() {
        let set = set_of(&[("demo/msg/Outer.msg", "demo/Inner inner")]);
        assert_eq!(
            type_hash(&set, "demo/msg/Outer"),
            Err(String::from(
                "demo/msg/Outer reaches demo/msg/Inner, which no declared definition defines"
            ))
        );
        assert_eq!(
            type_hash(&set, "demo/msg/Nope"),
            Err(String::from("no declared definition defines demo/msg/Nope"))
        );
    }

    /// Each field type's number, its capacities and its nested name, against
    /// `FieldType.msg`: a `char` is a `uint8` and a `byte` an octet.
    #[test]
    fn a_field_type_is_numbered_as_field_type_numbers_it() {
        let set = set_of(&[
            (
                "demo/msg/All.msg",
                "char c\nbyte b\nbool f\nstring<=5 s\nwstring w\nwstring<=3[<=2] ws\n\
             demo/All2[4] fixed\nuint8[] seq\nfloat32[<=7] few",
            ),
            ("demo/msg/All2.msg", ""),
        ]);
        let all = set.message("demo/msg/All").expect("defined");
        let read: Vec<(u32, (u32, u32, &str))> =
            all.fields.iter().map(|f| (type_id(f), shape(f))).collect();
        assert_eq!(
            read,
            [
                (3, (0, 0, "")),
                (16, (0, 0, "")),
                (15, (0, 0, "")),
                (21, (0, 5, "")),
                (18, (0, 0, "")),
                (22 + 96, (2, 3, "")),
                (1 + 48, (4, 0, "demo/msg/All2")),
                (3 + 144, (0, 0, "")),
                (10 + 96, (7, 0, "")),
            ]
        );
    }
}
