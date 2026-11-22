// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The value of a limit, the values of it a build allows, and the types that carry it from the
//! build to the stage that selects it.
//!
//! # Capacity and quota
//!
//! A limit has the two values `setrlimit` gives a resource. Its **capacity** is the hard limit:
//! the number of rows or bytes of storage the build sized by it, decided when the image is
//! compiled and never above. Its **quota** is the soft limit: the most the running code admits,
//! decided when the thing its scope names is opened, and never above the capacity. A build whose
//! storage the limit does not size (a growable table, or a limit that sizes nothing) has no
//! capacity, which is the hard limit `RLIM_INFINITY` stands for, and only there may the quota be
//! [`Quota::UNBOUNDED`].
//!
//! # Bound and parameter
//!
//! A limit of the kind [`LimitKind::Bound`] is a count or a size past which something is refused,
//! and its value is a [`Quota`]; who makes the table it limits grow, the program or a peer, is
//! its [`Driven`]. A limit of the kind [`LimitKind::Parameter`] is a number the code
//! runs with and never "no limit" (a time, a window, a batch size), and its value is an integer
//! inside the range the declaration states, whose ends are what the code assumes of it.
//!
//! # Domain and selection
//!
//! The build narrows each limit to its domain ([`LimitDomain`]), the values a later stage may
//! select: a bound's is `1..=capacity`, or every count and `unbounded` where it has no capacity; a
//! parameter's is its declared range, and no more than its capacity where it sizes storage. On a
//! target with no operating system the domain is the build's value alone (`WZ_LIMIT_DOMAINS`,
//! `full` or `defaults`, forces either rule; [`limit_defaults_only`]), as the policies' is
//! (`WZ_POLICY_DOMAINS`). A limit whose domain is one value is a constant of the build:
//! [`Limited::get`] returns it without reading the selected value, decided in a `const` block, and
//! a [`Limited`] of it holds no byte ([`LimitSpec::HELD`]).
//!
//! # What is generated
//!
//! Each limit a stage after the build may decide has a type of its own in the generated
//! `limits_generated.rs` (`crate::limits`) that implements [`LimitSpec`]: its id, kind, who makes
//! it grow, whether its machines read it from the snapshot, its capacity in this build, its domain
//! and the build's value. The snapshots that hold one value of each, `SessionLimits` and
//! `RuntimeLimits`, are generated there too, and the tables `SESSION_LIMITS` and `RUNTIME_LIMITS`
//! hold the [`LimitEntry`] a reader that names a limit by its id dispatches on. The types here
//! are written by hand, so the generator emits only one row per limit.

use core::fmt;

use crate::policy_binding::{Driven, LimitKind};

/// The quota of a bound: the most the running code admits, or no bound at all.
///
/// Held as `setrlimit` holds a limit: one word, whose every bit set (`usize::MAX`, what
/// `RLIM_INFINITY` is) is no bound. That is exact rather than a sentinel: a quota of `usize::MAX`
/// admits every count a `usize` can hold, which is what no bound admits, so the two are one value.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[repr(transparent)]
pub struct Quota(usize);

impl Quota {
    /// No bound: every request is admitted. Only a build with no capacity of the limit allows it.
    pub const UNBOUNDED: Self = Self(usize::MAX);

    /// At most `most`. `0` admits nothing, which is what a build that sizes a table of no rows
    /// runs with.
    pub const fn at_most(most: usize) -> Self {
        Self(most)
    }

    /// Whether a holder that would have `count` once admitted is inside the quota. Asked before
    /// any state changes, with the count the request would leave (`occupied + 1`, or a size), so a
    /// quota lowered under what is held keeps what is in and refuses what is new.
    pub const fn admits(self, count: usize) -> bool {
        count <= self.0
    }

    /// Whether there is no bound.
    pub const fn is_unbounded(self) -> bool {
        self.0 == usize::MAX
    }

    /// The bound, or `None` where there is none.
    pub const fn most(self) -> Option<usize> {
        if self.is_unbounded() {
            None
        } else {
            Some(self.0)
        }
    }

    /// The quota as a statement names it.
    pub const fn as_value(self) -> LimitValue {
        match self.most() {
            None => LimitValue::Unbounded,
            Some(most) => LimitValue::Integer(most),
        }
    }

    /// The quota a statement names.
    pub const fn of_value(value: LimitValue) -> Self {
        match value {
            LimitValue::Unbounded => Self::UNBOUNDED,
            LimitValue::Integer(most) => Self(most),
        }
    }

    /// The quota a build's value of a limit states where no storage is sized by it: the number,
    /// or no bound where the number is `0` and the limit reads `0` as none (`zero_unbounded`).
    pub const fn from_build(value: usize, zero_unbounded: bool) -> Self {
        if value == 0 && zero_unbounded {
            Self::UNBOUNDED
        } else {
            Self(value)
        }
    }

    /// The build's quota of a bound: its capacity where the build sized storage by it, else
    /// `uncapped`, what the build runs with when nothing is sized.
    pub const fn of_build(capacity: Option<usize>, uncapped: Self) -> Self {
        match capacity {
            Some(capacity) => Self(capacity),
            None => uncapped,
        }
    }

    /// The tighter of `self` and `other`: a holder bound by both is bound by this one. No bound
    /// is the widest quota, so it is the other whenever one of the two has a number.
    pub const fn tighter(self, other: Self) -> Self {
        if self.0 <= other.0 {
            self
        } else {
            other
        }
    }

    /// How many rows (or bytes) the storage this bound sizes is lent when its session opens
    /// (`binding_fixed = "open"`, `crate::bounded::Lent`), `self` being the value the open
    /// selected and `ceiling` the build's value of the limit.
    ///
    /// The build fixes the most memory a session may take, and a stage after it chooses within
    /// that and never adds to it, so `self` is lent where it is at most the ceiling and refused
    /// where it is more. A quota of no bound states no bound tighter than the build's own and is
    /// lent the ceiling: a build that sizes storage by the limit has no such quota in its domain,
    /// and on one whose table grows it is the growable table's "no bound of its own". A ceiling of
    /// no bound sizes nothing and is refused.
    pub const fn lent_under(self, ceiling: Self) -> Result<usize, UnlentRows> {
        let Some(ceiling) = ceiling.most() else {
            return Err(UnlentRows::NoCeiling);
        };
        match self.most() {
            None => Ok(ceiling),
            Some(value) if value <= ceiling => Ok(value),
            Some(value) => Err(UnlentRows::OverCeiling { value, ceiling }),
        }
    }
}

/// Why a bound gives the storage it sizes no length at open ([`Quota::lent_under`]).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum UnlentRows {
    /// The build states no value of the limit (a build value of `0` read as no bound), so
    /// nothing sizes the storage, and storage lent at open needs a number.
    NoCeiling,
    /// The value selected is over the build's: a stage after the build only lowers it.
    OverCeiling {
        /// The value selected.
        value: usize,
        /// The build's value.
        ceiling: usize,
    },
}

impl fmt::Display for UnlentRows {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NoCeiling => f.write_str(
                "the build states no value of the limit, so the storage it sizes has no length",
            ),
            Self::OverCeiling { value, ceiling } => write!(
                f,
                "{value} is over the build's {ceiling}, which a later stage may only lower"
            ),
        }
    }
}

impl core::error::Error for UnlentRows {}

impl fmt::Display for Quota {
    /// `unbounded`, or the number.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(&self.as_value(), f)
    }
}

/// The word a statement and the build's environment name an unbounded quota by.
pub const UNBOUNDED: &str = "unbounded";

/// One value of a limit as a statement names it, whatever the limit's kind: an integer, or
/// `unbounded`. A bound reads it as a [`Quota`]; a parameter reads the integer.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum LimitValue {
    /// `unbounded`.
    Unbounded,
    /// An integer.
    Integer(usize),
}

impl fmt::Display for LimitValue {
    /// `unbounded`, or the number.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unbounded => f.write_str(UNBOUNDED),
            Self::Integer(value) => write!(f, "{value}"),
        }
    }
}

/// The type a limit's value is held in: a [`Quota`] for a bound, a `usize` for a parameter.
pub trait LimitValueType: Copy + Eq + fmt::Debug + 'static {
    /// The kind of limit whose value this is.
    const KIND: LimitKind;

    /// The value as a statement names it.
    fn to_value(self) -> LimitValue;

    /// The value a statement names, or `None` where this type has no such value (`unbounded` for a
    /// parameter).
    fn from_value(value: LimitValue) -> Option<Self>;
}

impl LimitValueType for Quota {
    const KIND: LimitKind = LimitKind::Bound;

    fn to_value(self) -> LimitValue {
        self.as_value()
    }

    fn from_value(value: LimitValue) -> Option<Self> {
        Some(Self::of_value(value))
    }
}

impl LimitValueType for usize {
    const KIND: LimitKind = LimitKind::Parameter;

    fn to_value(self) -> LimitValue {
        LimitValue::Integer(self)
    }

    fn from_value(value: LimitValue) -> Option<Self> {
        match value {
            LimitValue::Unbounded => None,
            LimitValue::Integer(value) => Some(value),
        }
    }
}

/// The values of one limit a build allows a later stage to select: `unbounded` or not, and the
/// integers `least..=most` (none where `least > most`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LimitDomain {
    kind: LimitKind,
    unbounded: bool,
    least: usize,
    most: usize,
    /// Whether `most` is the capacity of the build rather than the end of a declared range.
    capped: bool,
    /// Whether the build keeps its own value alone ([`limit_defaults_only`]).
    pinned: bool,
}

impl LimitDomain {
    /// The domain of a bound whose capacity in this build is `capacity` (`None`: the build has
    /// none): `0..=capacity`, or every count and `unbounded`. A quota of `0` admits nothing, which
    /// is what a build that sizes a table of no rows runs with; a document that states `0` is
    /// refused by the document's own rule, not by the domain.
    pub const fn bound(capacity: Option<usize>) -> Self {
        // `usize::MAX` is the quota no bound is held as ([`Quota`]), so the integers stop under it.
        Self::bound_within(capacity, usize::MAX - 1)
    }

    /// [`Self::bound`] of a bound whose code holds no count above `most` (a counter of a narrower
    /// type): `0..=most` and `unbounded` where the build has no capacity, and no more than the
    /// capacity where it has one. A count above `most` is refused as outside its range.
    pub const fn bound_within(capacity: Option<usize>, most: usize) -> Self {
        match capacity {
            None => Self::with(LimitKind::Bound, true, 0, most, false),
            Some(capacity) if capacity <= most => {
                Self::with(LimitKind::Bound, false, 0, capacity, true)
            }
            Some(_) => Self::with(LimitKind::Bound, false, 0, most, false),
        }
    }

    /// The domain of a parameter whose declared range is `least..=most`, and no more than
    /// `capacity` where the build sizes storage by it.
    pub const fn parameter(least: usize, most: usize, capacity: Option<usize>) -> Self {
        assert!(least <= most, "a parameter's range is empty");
        match capacity {
            Some(capacity) if capacity < most => {
                Self::with(LimitKind::Parameter, false, least, capacity, true)
            }
            _ => Self::with(LimitKind::Parameter, false, least, most, false),
        }
    }

    /// The domain a build allows of a bound whose capacity is `capacity` and whose build value is
    /// `value`: [`Self::bound`], kept to `value` alone where `defaults_only`.
    pub const fn of_bound(capacity: Option<usize>, value: Quota, defaults_only: bool) -> Self {
        Self::bound(capacity).keeping(value.as_value(), defaults_only)
    }

    /// [`Self::of_bound`] of a bound whose code holds no count above `most`
    /// ([`Self::bound_within`]).
    pub const fn of_bound_within(
        capacity: Option<usize>,
        most: usize,
        value: Quota,
        defaults_only: bool,
    ) -> Self {
        Self::bound_within(capacity, most).keeping(value.as_value(), defaults_only)
    }

    /// The domain a build allows of a parameter whose range is `least..=most`, whose capacity is
    /// `capacity` and whose build value is `value`: [`Self::parameter`], kept to `value` alone
    /// where `defaults_only`.
    pub const fn of_parameter(
        least: usize,
        most: usize,
        capacity: Option<usize>,
        value: usize,
        defaults_only: bool,
    ) -> Self {
        Self::parameter(least, most, capacity).keeping(LimitValue::Integer(value), defaults_only)
    }

    /// `self` where the build keeps every value it allows, or only `value`, the build's own, where
    /// `defaults_only`. `value` must be inside `self`; a domain that leaves it out does not compile.
    pub const fn keeping(self, value: LimitValue, defaults_only: bool) -> Self {
        assert!(
            self.contains(value),
            "a limit's build value is outside the domain the build allows"
        );
        if !defaults_only {
            return self;
        }
        match value {
            LimitValue::Unbounded => Self {
                unbounded: true,
                least: 1,
                most: 0,
                pinned: true,
                ..self
            },
            LimitValue::Integer(value) => Self {
                unbounded: false,
                least: value,
                most: value,
                pinned: true,
                ..self
            },
        }
    }

    const fn with(
        kind: LimitKind,
        unbounded: bool,
        least: usize,
        most: usize,
        capped: bool,
    ) -> Self {
        Self {
            kind,
            unbounded,
            least,
            most,
            capped,
            pinned: false,
        }
    }

    /// The kind of the limit this is a domain of.
    pub const fn kind(self) -> LimitKind {
        self.kind
    }

    /// Whether `unbounded` is allowed.
    pub const fn allows_unbounded(self) -> bool {
        self.unbounded
    }

    /// The integers allowed, `(least, most)`, or `None` where no integer is.
    pub const fn integers(self) -> Option<(usize, usize)> {
        if self.least <= self.most {
            Some((self.least, self.most))
        } else {
            None
        }
    }

    /// Whether `value` is allowed.
    pub const fn contains(self, value: LimitValue) -> bool {
        match value {
            LimitValue::Unbounded => self.unbounded,
            LimitValue::Integer(value) => self.least <= value && value <= self.most,
        }
    }

    /// Whether exactly one value is allowed, which makes the limit a constant of the build.
    pub const fn is_singleton(self) -> bool {
        if self.unbounded {
            self.least > self.most
        } else {
            self.least == self.most
        }
    }

    /// How many values a holder of the limit keeps: none where the domain is one value, whose value
    /// is then the build's, and one otherwise. The length of a [`Limited`]'s store.
    pub const fn held(self) -> usize {
        if self.is_singleton() {
            0
        } else {
            1
        }
    }

    /// `Ok` where `value` is allowed, else why it is not.
    pub const fn check(self, value: LimitValue) -> Result<(), Outside> {
        if self.contains(value) {
            return Ok(());
        }
        if self.pinned {
            let only = if self.unbounded {
                LimitValue::Unbounded
            } else {
                LimitValue::Integer(self.least)
            };
            return Err(Outside::Pinned { only });
        }
        Err(match value {
            LimitValue::Unbounded => match self.kind {
                LimitKind::Parameter => Outside::UnboundedParameter,
                LimitKind::Bound => Outside::UnboundedOverCapacity {
                    capacity: self.most,
                },
            },
            LimitValue::Integer(value) if value < self.least => {
                Outside::Below { least: self.least }
            }
            LimitValue::Integer(_) if self.capped => Outside::OverCapacity {
                capacity: self.most,
            },
            LimitValue::Integer(_) => Outside::OutsideRange {
                least: self.least,
                most: self.most,
            },
        })
    }
}

/// Why a value is outside a limit's domain ([`LimitDomain::check`]).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Outside {
    /// The build keeps its own value alone (`WZ_LIMIT_DOMAINS`, or a target with no operating
    /// system), and this is another.
    Pinned {
        /// The one value the build allows.
        only: LimitValue,
    },
    /// `unbounded` for a parameter, which has no such value.
    UnboundedParameter,
    /// `unbounded` for a bound the build sized storage by: its quota is at most the capacity.
    UnboundedOverCapacity {
        /// The build's capacity of the limit.
        capacity: usize,
    },
    /// An integer under the least the limit allows: `1` for a bound, the low end of a parameter's
    /// range.
    Below {
        /// The least value allowed.
        least: usize,
    },
    /// An integer over the capacity the build sized storage by.
    OverCapacity {
        /// The build's capacity of the limit.
        capacity: usize,
    },
    /// An integer outside a parameter's declared range.
    OutsideRange {
        /// The low end of the range.
        least: usize,
        /// The high end of the range.
        most: usize,
    },
}

/// A value refused by [`Limited::select`] or [`LimitEntry::select`]: the limit, the value, and why.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct OutsideLimitDomain {
    /// The limit's id, as the declaration spells it.
    pub limit: &'static str,
    /// The value refused.
    pub value: LimitValue,
    /// The domain it is outside of.
    pub domain: LimitDomain,
    /// Why.
    pub why: Outside,
}

impl fmt::Display for OutsideLimitDomain {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write_outside(f, self.limit, self.value, self.why)
    }
}

impl core::error::Error for OutsideLimitDomain {}

/// Why `value` is outside the domain of the limit `limit`, as a sentence: what
/// [`OutsideLimitDomain`] says, and what a document's refusal of the value says after it.
pub(crate) fn write_outside(
    f: &mut fmt::Formatter<'_>,
    limit: &str,
    value: LimitValue,
    why: Outside,
) -> fmt::Result {
    match why {
        Outside::Pinned { only } => match only {
            LimitValue::Integer(only) => write!(
                f,
                "the build fixes the limit `{limit}` at {only}; `{value}` is another value"
            ),
            LimitValue::Unbounded => write!(
                f,
                "the build fixes the limit `{limit}` at `{UNBOUNDED}`; `{value}` is another value"
            ),
        },
        Outside::UnboundedParameter => write!(
            f,
            "the limit `{limit}` is a parameter, which is never `{UNBOUNDED}`"
        ),
        Outside::UnboundedOverCapacity { capacity } => write!(
            f,
            "the build sizes the storage of the limit `{limit}` at {capacity}, so it is not \
             `{UNBOUNDED}`"
        ),
        Outside::Below { least } => write!(
            f,
            "the limit `{limit}` is at least {least}; `{value}` is less"
        ),
        Outside::OverCapacity { capacity } => write!(
            f,
            "the build sizes the storage of the limit `{limit}` at {capacity}; `{value}` is more"
        ),
        Outside::OutsideRange { least, most } => write!(
            f,
            "the limit `{limit}` is between {least} and {most}; `{value}` is outside"
        ),
    }
}

/// Whether the engine this build links lends the bytes of every parameter bound at the open
/// (`binding_fixed = "open"`) from a session's arena under the build's value, whatever the policy of
/// this crate's own tables (`limits-lent-at-open`). Where it does, the [`LimitSpec::CAPACITY`] of
/// such a parameter is the build's value, so its domain stops there and a stage after the build only
/// lowers it: a document that states more is refused by name, not by the open's arena.
pub const LIMITS_LENT_AT_OPEN: bool = cfg!(feature = "limits-lent-at-open");

/// Whether a limit's domain keeps only the build's value: what `WZ_LIMIT_DOMAINS` states (`full`
/// keeps every value the build allows, `defaults` only its own), else whether the target has no
/// operating system. A value that is neither word is a compile error, not a default.
pub const fn limit_defaults_only(stated: Option<&str>) -> bool {
    let Some(text) = stated else {
        return cfg!(target_os = "none");
    };
    if same(text, "full") {
        false
    } else if same(text, "defaults") {
        true
    } else {
        panic!("WZ_LIMIT_DOMAINS is neither `full` nor `defaults`")
    }
}

const fn same(a: &str, b: &str) -> bool {
    let (a, b) = (a.as_bytes(), b.as_bytes());
    if a.len() != b.len() {
        return false;
    }
    let mut index = 0;
    while index < a.len() {
        if a[index] != b[index] {
            return false;
        }
        index += 1;
    }
    true
}

/// One limit a stage after the build may decide: its id, its kind, who makes it grow, its capacity
/// in this build, the values the build allows and the build's value. The generated module
/// implements it for one type per limit.
pub trait LimitSpec: 'static {
    /// The type the value is held in: [`Quota`] for a bound, `usize` for a parameter.
    type Value: LimitValueType;
    /// The limit's id, as the declaration spells it.
    const LIMIT: &'static str;
    /// Who makes the table a bound limits grow; `None` for a parameter.
    const DRIVEN: Option<Driven>;
    /// Whether the machines of the limit's scope read it from the snapshot their creator hands
    /// them. Where they still read the build's value, a value a later stage states would be taken
    /// and never read, so a reader of a document refuses a statement of the limit by name.
    const READ_FROM_SNAPSHOT: bool;
    /// The capacity this build sized storage by, or `None` where it sized none by this limit.
    const CAPACITY: Option<usize>;
    /// The values the build allows a later stage to select.
    const DOMAIN: LimitDomain;
    /// The build's value: what the code admits or runs with when no later stage states one.
    /// Always inside [`Self::DOMAIN`].
    const DEFAULT: Self::Value;
    /// How many values a [`Limited`] of the limit stores ([`LimitDomain::held`]): none where the
    /// build allows one value.
    const HELD: usize = Self::DOMAIN.held();
}

/// A limit's value, selected inside the build's domain, kept in `HELD` slots: none where the domain
/// is one value ([`LimitSpec::HELD`]), so a limit the build fixes costs its holder no byte. The
/// generated snapshots name `HELD` per limit, as `SessionPolicy` does for a policy's `Bound`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Limited<L: LimitSpec, const HELD: usize> {
    value: [L::Value; HELD],
}

impl<L: LimitSpec, const HELD: usize> Limited<L, HELD> {
    /// `value`, when the build's domain allows it.
    pub fn select(value: L::Value) -> Result<Self, OutsideLimitDomain> {
        let stated = value.to_value();
        match L::DOMAIN.check(stated) {
            Ok(()) => Ok(Self {
                value: [value; HELD],
            }),
            Err(why) => Err(OutsideLimitDomain {
                limit: L::LIMIT,
                value: stated,
                domain: L::DOMAIN,
                why,
            }),
        }
    }

    /// The selected value. Where the build's domain is one value, that value is the build's and
    /// nothing is read: the `const` block decides the branch when the build is compiled.
    pub const fn get(&self) -> L::Value {
        if const { L::DOMAIN.is_singleton() } {
            L::DEFAULT
        } else {
            match self.value.first() {
                Some(value) => *value,
                None => L::DEFAULT,
            }
        }
    }

    /// The build's value, which the domain always holds. Read by the generated snapshots'
    /// `from_build`, the one place a snapshot of the limits starts from the build.
    pub(crate) const fn build_default() -> Self {
        Self {
            value: [L::DEFAULT; HELD],
        }
    }
}

impl<L: LimitSpec<Value = Quota>, const HELD: usize> Limited<L, HELD> {
    /// Whether the table this bound limits admits a holder that would leave `count` in it. Asked
    /// before any state changes, with the count the request would leave (`occupied + 1`, or a
    /// size), so a quota lowered under what is held keeps what is in and refuses what is new.
    ///
    /// Where the build's domain is one value and that value is the capacity the storage was sized
    /// by, the storage is the bound: it refuses the same request this would. Nothing is read or
    /// compared then, decided in a `const` block when the build is compiled, so an image that
    /// fixes the bound carries no comparison of its own.
    pub const fn admits(&self, count: usize) -> bool {
        if const { L::DOMAIN.is_singleton() && storage_is_the_bound::<L>() } {
            true
        } else {
            self.get().admits(count)
        }
    }
}

/// Whether the build's value of `L` is the capacity its storage was sized by, so that storage
/// refuses past the value by itself.
const fn storage_is_the_bound<L: LimitSpec<Value = Quota>>() -> bool {
    match (L::CAPACITY, L::DEFAULT.most()) {
        (Some(capacity), Some(most)) => capacity == most,
        _ => false,
    }
}

impl<L: LimitSpec, const HELD: usize> Default for Limited<L, HELD> {
    /// The build's value.
    fn default() -> Self {
        Self::build_default()
    }
}

/// A limit that is a field of the snapshot `S`: how a reader that names the limit by its id
/// reaches the field. The generated module implements it for every limit's type.
pub trait LimitField<S>: LimitSpec {
    /// Selects `value` in `snapshot`, refusing one the build's domain leaves out; a refusal leaves
    /// `snapshot` as it was.
    fn select_in(snapshot: &mut S, value: Self::Value) -> Result<(), OutsideLimitDomain>;

    /// The value `snapshot` holds.
    fn held_in(snapshot: &S) -> Self::Value;
}

/// How an entry selects a value in its snapshot.
type Selector<S> = fn(&mut S, LimitValue) -> Result<(), OutsideLimitDomain>;

/// One limit as a reader that names it by its id sees it, in the snapshot `S` that holds it.
pub struct LimitEntry<S: 'static> {
    id: &'static str,
    kind: LimitKind,
    driven: Option<Driven>,
    read_from_snapshot: bool,
    capacity: Option<usize>,
    domain: LimitDomain,
    /// `None` for a limit no machine reads from the snapshot: a statement of it is refused before
    /// any value is selected, so the entry links no selector for it.
    select: Option<Selector<S>>,
    held: fn(&S) -> LimitValue,
}

// Written out rather than derived: a derive would ask `S` for each trait, and an entry holds no `S`.
impl<S> Clone for LimitEntry<S> {
    fn clone(&self) -> Self {
        *self
    }
}

impl<S> Copy for LimitEntry<S> {}

impl<S> fmt::Debug for LimitEntry<S> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("LimitEntry")
            .field("id", &self.id)
            .field("kind", &self.kind)
            .field("driven", &self.driven)
            .field("read_from_snapshot", &self.read_from_snapshot)
            .field("capacity", &self.capacity)
            .field("domain", &self.domain)
            .finish()
    }
}

impl<S> LimitEntry<S> {
    /// The entry of the limit whose type is `L`.
    pub const fn of<L: LimitField<S>>() -> Self {
        Self {
            id: L::LIMIT,
            kind: <L::Value as LimitValueType>::KIND,
            driven: L::DRIVEN,
            read_from_snapshot: L::READ_FROM_SNAPSHOT,
            capacity: L::CAPACITY,
            domain: L::DOMAIN,
            // Decided where the table is evaluated: a limit read from the build gets no selector,
            // and a build links the selection of none of them.
            select: if L::READ_FROM_SNAPSHOT {
                Some(select_at::<S, L>)
            } else {
                None
            },
            held: held_at::<S, L>,
        }
    }

    /// The limit's id, as the declaration spells it ([`LimitSpec::LIMIT`]).
    pub const fn id(&self) -> &'static str {
        self.id
    }

    /// Whether it is a bound or a parameter.
    pub const fn kind(&self) -> LimitKind {
        self.kind
    }

    /// Who makes the table a bound limits grow; `None` for a parameter ([`LimitSpec::DRIVEN`]).
    pub const fn driven(&self) -> Option<Driven> {
        self.driven
    }

    /// Whether the machines of the limit's scope read it from the snapshot their creator hands
    /// them ([`LimitSpec::READ_FROM_SNAPSHOT`]).
    pub const fn read_from_snapshot(&self) -> bool {
        self.read_from_snapshot
    }

    /// The capacity this build sized storage by ([`LimitSpec::CAPACITY`]).
    pub const fn capacity(&self) -> Option<usize> {
        self.capacity
    }

    /// The values the build allows a later stage to select ([`LimitSpec::DOMAIN`]).
    pub const fn domain(&self) -> LimitDomain {
        self.domain
    }

    /// Selects `value` in `snapshot`. A refusal leaves `snapshot` as it was. `None` for a limit no
    /// machine reads from the snapshot ([`Self::read_from_snapshot`]), which has no selector: a
    /// value selected in a field nothing reads would be accepted and never applied.
    pub fn select(
        &self,
        snapshot: &mut S,
        value: LimitValue,
    ) -> Option<Result<(), OutsideLimitDomain>> {
        self.select.map(|select| select(snapshot, value))
    }

    /// The value `snapshot` holds.
    pub fn value_in(&self, snapshot: &S) -> LimitValue {
        (self.held)(snapshot)
    }
}

/// The selection behind [`LimitEntry::select`]: `value` read as `L`'s type, through
/// [`LimitField::select_in`]. `unbounded` for a parameter is refused here, as its domain refuses it.
fn select_at<S, L: LimitField<S>>(
    snapshot: &mut S,
    value: LimitValue,
) -> Result<(), OutsideLimitDomain> {
    match <L::Value as LimitValueType>::from_value(value) {
        Some(typed) => L::select_in(snapshot, typed),
        None => Err(OutsideLimitDomain {
            limit: L::LIMIT,
            value,
            domain: L::DOMAIN,
            why: Outside::UnboundedParameter,
        }),
    }
}

/// The value `snapshot` holds of `L`, as a statement names it.
fn held_at<S, L: LimitField<S>>(snapshot: &S) -> LimitValue {
    L::held_in(snapshot).to_value()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A bound of a build that sized no storage by it: every quota, `unbounded` the build's.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    struct Open;

    impl LimitSpec for Open {
        type Value = Quota;
        const LIMIT: &'static str = "TEST_OPEN";
        const DRIVEN: Option<Driven> = Some(Driven::Remote);
        const READ_FROM_SNAPSHOT: bool = true;
        const CAPACITY: Option<usize> = None;
        const DOMAIN: LimitDomain = LimitDomain::bound(Self::CAPACITY);
        const DEFAULT: Quota = Quota::UNBOUNDED;
    }

    /// A bound of a build that sized a table of 8 rows by it.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    struct Sized8;

    impl LimitSpec for Sized8 {
        type Value = Quota;
        const LIMIT: &'static str = "TEST_SIZED";
        const DRIVEN: Option<Driven> = Some(Driven::Local);
        const READ_FROM_SNAPSHOT: bool = false;
        const CAPACITY: Option<usize> = Some(8);
        const DOMAIN: LimitDomain = LimitDomain::bound(Self::CAPACITY);
        const DEFAULT: Quota = Quota::of_build(Self::CAPACITY, Quota::UNBOUNDED);
    }

    /// A parameter in `1..=64` the build keeps at its own 4 alone.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    struct Pinned4;

    impl LimitSpec for Pinned4 {
        type Value = usize;
        const LIMIT: &'static str = "TEST_PINNED";
        const DRIVEN: Option<Driven> = None;
        const READ_FROM_SNAPSHOT: bool = true;
        const CAPACITY: Option<usize> = None;
        const DOMAIN: LimitDomain =
            LimitDomain::parameter(1, 64, None).keeping(LimitValue::Integer(4), true);
        const DEFAULT: usize = 4;
    }

    struct Snapshot {
        open: Limited<Open, { Open::HELD }>,
        sized: Limited<Sized8, { Sized8::HELD }>,
    }

    impl LimitField<Snapshot> for Open {
        fn select_in(snapshot: &mut Snapshot, value: Quota) -> Result<(), OutsideLimitDomain> {
            snapshot.open = Limited::select(value)?;
            Ok(())
        }

        fn held_in(snapshot: &Snapshot) -> Quota {
            snapshot.open.get()
        }
    }

    impl LimitField<Snapshot> for Sized8 {
        fn select_in(snapshot: &mut Snapshot, value: Quota) -> Result<(), OutsideLimitDomain> {
            snapshot.sized = Limited::select(value)?;
            Ok(())
        }

        fn held_in(snapshot: &Snapshot) -> Quota {
            snapshot.sized.get()
        }
    }

    #[test]
    fn a_quota_admits_up_to_its_bound_and_unbounded_admits_every_count() {
        let three = Quota::at_most(3);
        assert!(three.admits(3));
        assert!(!three.admits(4));
        assert_eq!(three.most(), Some(3));
        assert!(Quota::at_most(0).admits(0));
        assert!(!Quota::at_most(0).admits(1));
        assert!(Quota::UNBOUNDED.admits(usize::MAX));
        assert_eq!(Quota::UNBOUNDED.most(), None);
        // A quota of every count a `usize` holds is no bound: the two are one value.
        assert_eq!(Quota::at_most(usize::MAX), Quota::UNBOUNDED);
        assert_eq!(std::format!("{}", Quota::UNBOUNDED), "unbounded");
        assert_eq!(std::format!("{three}"), "3");
    }

    #[test]
    fn a_build_value_of_zero_is_no_bound_only_where_the_limit_reads_it_so() {
        assert_eq!(Quota::from_build(0, true), Quota::UNBOUNDED);
        assert_eq!(Quota::from_build(0, false), Quota::at_most(0));
        assert_eq!(Quota::from_build(5, true), Quota::at_most(5));
        assert_eq!(
            Quota::of_build(Some(8), Quota::UNBOUNDED),
            Quota::at_most(8)
        );
        assert_eq!(Quota::of_build(None, Quota::UNBOUNDED), Quota::UNBOUNDED);
    }

    #[test]
    fn the_tighter_of_two_quotas_is_the_smaller_and_no_bound_is_the_widest() {
        let unbounded = Quota::UNBOUNDED;
        assert_eq!(unbounded.tighter(unbounded), unbounded, "neither bounds");
        assert_eq!(unbounded.tighter(Quota::at_most(4)), Quota::at_most(4));
        assert_eq!(Quota::at_most(4).tighter(unbounded), Quota::at_most(4));
        assert_eq!(
            Quota::at_most(3).tighter(Quota::at_most(4)),
            Quota::at_most(3)
        );
        assert_eq!(
            Quota::at_most(4).tighter(Quota::at_most(3)),
            Quota::at_most(3)
        );
        assert_eq!(
            Quota::at_most(0).tighter(unbounded),
            Quota::at_most(0),
            "a quota that admits nothing is the tightest"
        );
    }

    #[test]
    fn a_bound_with_no_capacity_allows_unbounded_and_every_count() {
        let domain = Open::DOMAIN;
        assert_eq!(domain.kind(), LimitKind::Bound);
        assert!(domain.allows_unbounded());
        assert!(domain.contains(LimitValue::Unbounded));
        assert!(domain.contains(LimitValue::Integer(0)));
        assert!(domain.contains(LimitValue::Integer(1 << 20)));
        assert!(!domain.is_singleton());
        assert_eq!(Open::HELD, 1);
    }

    #[test]
    fn a_bound_with_a_capacity_allows_up_to_it_and_names_it_past_it() {
        let domain = Sized8::DOMAIN;
        assert!(!domain.allows_unbounded());
        assert_eq!(domain.integers(), Some((0, 8)));
        assert_eq!(domain.check(LimitValue::Integer(8)), Ok(()));
        assert_eq!(
            domain.check(LimitValue::Integer(9)),
            Err(Outside::OverCapacity { capacity: 8 })
        );
        assert_eq!(
            domain.check(LimitValue::Unbounded),
            Err(Outside::UnboundedOverCapacity { capacity: 8 })
        );
        assert_eq!(Sized8::DEFAULT, Quota::at_most(8));
        // A table of no rows has the one quota that admits nothing.
        let none = LimitDomain::bound(Some(0));
        assert!(none.is_singleton());
        assert!(none.contains(LimitValue::Integer(0)));
    }

    #[test]
    fn a_bound_its_code_holds_in_a_narrower_count_stops_there() {
        let open = LimitDomain::bound_within(None, 65535);
        assert!(open.allows_unbounded());
        assert!(open.contains(LimitValue::Integer(65535)));
        assert_eq!(
            open.check(LimitValue::Integer(65536)),
            Err(Outside::OutsideRange {
                least: 0,
                most: 65535
            })
        );
        // A capacity under the count is the capacity; one over it is the count.
        assert_eq!(
            LimitDomain::bound_within(Some(8), 65535).check(LimitValue::Integer(9)),
            Err(Outside::OverCapacity { capacity: 8 })
        );
        assert_eq!(
            LimitDomain::bound_within(Some(70000), 65535).integers(),
            Some((0, 65535))
        );
        assert_eq!(
            LimitDomain::bound(None),
            LimitDomain::bound_within(None, usize::MAX - 1)
        );
    }

    #[test]
    fn a_parameter_is_never_unbounded_and_stays_in_its_range_and_capacity() {
        let domain = LimitDomain::parameter(1, 64, None);
        assert_eq!(domain.kind(), LimitKind::Parameter);
        assert_eq!(
            domain.check(LimitValue::Unbounded),
            Err(Outside::UnboundedParameter)
        );
        assert_eq!(
            domain.check(LimitValue::Integer(0)),
            Err(Outside::Below { least: 1 })
        );
        assert_eq!(
            domain.check(LimitValue::Integer(65)),
            Err(Outside::OutsideRange { least: 1, most: 64 })
        );
        let sized = LimitDomain::parameter(1, 64, Some(24));
        assert_eq!(sized.integers(), Some((1, 24)));
        assert_eq!(
            sized.check(LimitValue::Integer(25)),
            Err(Outside::OverCapacity { capacity: 24 })
        );
        // A capacity above the range leaves the range as it is.
        assert_eq!(
            LimitDomain::parameter(1, 64, Some(100)).integers(),
            Some((1, 64))
        );
    }

    #[test]
    fn a_domain_kept_to_the_build_value_is_one_value_and_held_in_no_byte() {
        assert!(Pinned4::DOMAIN.is_singleton());
        assert_eq!(Pinned4::HELD, 0);
        assert_eq!(
            core::mem::size_of::<Limited<Pinned4, { Pinned4::HELD }>>(),
            0
        );
        assert_eq!(
            Pinned4::DOMAIN.check(LimitValue::Integer(5)),
            Err(Outside::Pinned {
                only: LimitValue::Integer(4)
            })
        );
        assert_eq!(Limited::<Pinned4, 0>::default().get(), 4);
        let unbounded = LimitDomain::bound(None).keeping(LimitValue::Unbounded, true);
        assert!(unbounded.is_singleton());
        assert!(unbounded.contains(LimitValue::Unbounded));
        assert!(!unbounded.contains(LimitValue::Integer(3)));
        // The refusal names the value the build keeps, so a reader that holds no domain can say it.
        assert_eq!(
            unbounded.check(LimitValue::Integer(3)),
            Err(Outside::Pinned {
                only: LimitValue::Unbounded
            })
        );
        // Without the rule the domain is what the build allows.
        assert_eq!(
            LimitDomain::bound(None).keeping(LimitValue::Unbounded, false),
            LimitDomain::bound(None)
        );
    }

    #[test]
    #[should_panic(expected = "outside the domain the build allows")]
    fn a_build_value_outside_the_domain_is_refused() {
        LimitDomain::parameter(1, 16, None).keeping(LimitValue::Integer(17), false);
    }

    #[test]
    fn a_quota_is_held_in_one_word_and_a_selection_outside_the_domain_is_refused() {
        assert_eq!(core::mem::size_of::<Quota>(), core::mem::size_of::<usize>());
        let refused = Limited::<Sized8, 1>::select(Quota::at_most(9)).unwrap_err();
        assert_eq!(refused.limit, "TEST_SIZED");
        assert_eq!(
            std::format!("{refused}"),
            "the build sizes the storage of the limit `TEST_SIZED` at 8; `9` is more"
        );
        assert_eq!(
            Limited::<Sized8, 1>::select(Quota::at_most(2)).map(|held| held.get()),
            Ok(Quota::at_most(2))
        );
    }

    #[test]
    fn an_entry_selects_by_the_value_a_statement_names_and_reads_it_back() {
        let mut snapshot = Snapshot {
            open: Limited::default(),
            sized: Limited::default(),
        };
        let open = LimitEntry::<Snapshot>::of::<Open>();
        let sized = LimitEntry::<Snapshot>::of::<Sized8>();
        assert_eq!(open.id(), "TEST_OPEN");
        assert_eq!(open.driven(), Some(Driven::Remote));
        // An entry carries whether the limit's machines read the snapshot, as its type states it.
        assert!(open.read_from_snapshot());
        assert!(!sized.read_from_snapshot());
        assert_eq!(sized.capacity(), Some(8));
        assert_eq!(open.value_in(&snapshot), LimitValue::Unbounded);
        open.select(&mut snapshot, LimitValue::Integer(12))
            .expect("a limit read from the snapshot has a selector")
            .expect("inside");
        assert_eq!(open.value_in(&snapshot), LimitValue::Integer(12));
        // A limit read from the build has no selector in its entry.
        assert!(sized
            .select(&mut snapshot, LimitValue::Integer(4))
            .is_none());
        let refused =
            select_at::<Snapshot, Sized8>(&mut snapshot, LimitValue::Unbounded).unwrap_err();
        assert_eq!(refused.why, Outside::UnboundedOverCapacity { capacity: 8 });
        // A refusal leaves the snapshot as it was.
        assert_eq!(sized.value_in(&snapshot), LimitValue::Integer(8));
    }

    #[test]
    fn each_refusal_names_the_limit_and_why() {
        let refused = |domain: LimitDomain, value| OutsideLimitDomain {
            limit: "X",
            value,
            domain,
            why: domain.check(value).unwrap_err(),
        };
        let parameter = LimitDomain::parameter(1, 64, None);
        assert_eq!(
            std::format!("{}", refused(parameter, LimitValue::Unbounded)),
            "the limit `X` is a parameter, which is never `unbounded`"
        );
        assert_eq!(
            std::format!("{}", refused(parameter, LimitValue::Integer(0))),
            "the limit `X` is at least 1; `0` is less"
        );
        assert_eq!(
            std::format!("{}", refused(parameter, LimitValue::Integer(70))),
            "the limit `X` is between 1 and 64; `70` is outside"
        );
        assert_eq!(
            std::format!(
                "{}",
                refused(LimitDomain::bound(Some(4)), LimitValue::Unbounded)
            ),
            "the build sizes the storage of the limit `X` at 4, so it is not `unbounded`"
        );
        let pinned = parameter.keeping(LimitValue::Integer(4), true);
        assert_eq!(
            std::format!("{}", refused(pinned, LimitValue::Integer(5))),
            "the build fixes the limit `X` at 4; `5` is another value"
        );
        let unbounded = LimitDomain::bound(None).keeping(LimitValue::Unbounded, true);
        assert_eq!(
            std::format!("{}", refused(unbounded, LimitValue::Integer(5))),
            "the build fixes the limit `X` at `unbounded`; `5` is another value"
        );
    }

    #[test]
    fn an_unset_rule_keeps_every_value_on_a_target_with_an_operating_system() {
        assert!(!limit_defaults_only(Some("full")));
        assert!(limit_defaults_only(Some("defaults")));
        assert_eq!(limit_defaults_only(None), cfg!(target_os = "none"));
    }

    /// A value the open selects at or under the build's is lent as selected, `0` included: a
    /// table of no rows admits nothing.
    #[test]
    fn a_quota_at_or_under_the_ceiling_is_lent_as_selected() {
        let ceiling = Quota::at_most(8);
        assert_eq!(Quota::at_most(3).lent_under(ceiling), Ok(3));
        assert_eq!(Quota::at_most(8).lent_under(ceiling), Ok(8));
        assert_eq!(Quota::at_most(0).lent_under(ceiling), Ok(0));
    }

    /// A value over the build's is refused, naming both: the build fixes the most a session may
    /// take, and a later stage only lowers it.
    #[test]
    fn a_quota_over_the_ceiling_is_refused() {
        assert_eq!(
            Quota::at_most(9).lent_under(Quota::at_most(8)),
            Err(UnlentRows::OverCeiling {
                value: 9,
                ceiling: 8
            })
        );
    }

    /// A quota of no bound is lent the ceiling; a ceiling of no bound sizes nothing, whatever the
    /// quota.
    #[test]
    fn no_bound_is_lent_the_ceiling_and_no_ceiling_is_refused() {
        assert_eq!(Quota::UNBOUNDED.lent_under(Quota::at_most(8)), Ok(8));
        assert_eq!(
            Quota::at_most(3).lent_under(Quota::UNBOUNDED),
            Err(UnlentRows::NoCeiling)
        );
        assert_eq!(
            Quota::UNBOUNDED.lent_under(Quota::from_build(0, true)),
            Err(UnlentRows::NoCeiling)
        );
    }
}
