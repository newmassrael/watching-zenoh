// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! Where the value of a policy or a limit is decided, and the types that carry a policy's value
//! from the build to the stage that selects it.
//!
//! # Domain and selection
//!
//! The build narrows each policy to its domain, the set of values a later stage may select: one
//! `WZ_POLICY_<NAME>_ALLOWS_<VALUE>` per value, `on` allowing the value and `off` leaving it out.
//! A value the build does not name is allowed on a target with an operating system, and on a
//! target with none only when it is the build's default (`WZ_POLICY_DOMAINS`, `full` or
//! `defaults`, forces either rule; [`Domain::from_stated`]). The build's default
//! (`WZ_POLICY_<NAME>`) is always inside the domain; a build whose domain leaves it out does not
//! compile. The open (or, for a policy bound `live`, a running session) then selects one value
//! inside the domain with [`Bound::select`].
//!
//! A policy whose domain is one value is a constant of the build: [`Bound::get`] returns it
//! without reading the selected value, decided in a `const` block so the branch that would read it
//! is not compiled into the build, and a [`Bound`] of it holds no byte ([`PolicyValue::HELD`]).
//!
//! # What is generated
//!
//! Each policy's value type implements [`PolicyValue`] in the generated `policy_generated.rs`, and
//! each limit's [`LimitBinding`] is a constant of the generated `caps_binding_generated.rs`
//! (`crate::caps::binding`). The types here are written by hand, so the generator emits only one
//! row per policy and per limit. The words of [`Scope`], [`Binding`], [`Mutability`], [`Wire`] and
//! [`Storage`] are the declaration's (`deploy/wz-config.toml`, "Where a value is bound"), and
//! `scripts/lib/wz_config.py --check` holds the variants here to them.

use core::fmt;
use core::marker::PhantomData;

/// What holds one value of a policy or a limit. Each scope lies inside the one before it, except
/// that a link and an entity are both inside a session and neither inside the other.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Scope {
    /// One node and everything it opens.
    Runtime,
    /// One session of a node, with one peer or one group.
    Session,
    /// One link of a session.
    Link,
    /// One declared publisher, subscriber, queryable, querier or token of a session.
    Entity,
    /// One call or one message.
    Message,
}

impl Scope {
    /// The scope as the declaration spells it.
    pub const fn id(self) -> &'static str {
        match self {
            Self::Runtime => "runtime",
            Self::Session => "session",
            Self::Link => "link",
            Self::Entity => "entity",
            Self::Message => "message",
        }
    }
}

/// The latest stage a value may be decided at.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Binding {
    /// When the image or library is compiled.
    Build,
    /// When the thing its scope names is opened; the value then holds for its life.
    Open,
    /// Any moment while it runs.
    Live,
}

impl Binding {
    /// The stage as the declaration spells it.
    pub const fn id(self) -> &'static str {
        match self {
            Self::Build => "build",
            Self::Open => "open",
            Self::Live => "live",
        }
    }
}

/// Whether a policy's value may change once it was first decided.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Mutability {
    /// It may not; every value bound at the build or the open is fixed.
    Fixed,
    /// It may, taking effect only at the moment [`PolicyValue::BOUNDARY`] names.
    Quiescent,
    /// It may, taking effect at its next use.
    Hot,
}

impl Mutability {
    /// The mutability as the declaration spells it.
    pub const fn id(self) -> &'static str {
        match self {
            Self::Fixed => "fixed",
            Self::Quiescent => "quiescent",
            Self::Hot => "hot",
        }
    }
}

/// What a peer sees when a value changes within its range.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Wire {
    /// The bytes a peer receives are the same.
    None,
    /// The same bytes, sent at other moments or in other turns.
    Timing,
    /// Other bytes, which a peer reads without having agreed to them.
    Visible,
    /// The value is exchanged with the peer when the session opens, and both ends adopt what they
    /// agree on.
    Negotiated,
}

impl Wire {
    /// The word as the declaration spells it.
    pub const fn id(self) -> &'static str {
        match self {
            Self::None => "none",
            Self::Timing => "timing",
            Self::Visible => "visible",
            Self::Negotiated => "negotiated",
        }
    }
}

/// What a limit does to storage.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Storage {
    /// It sizes storage, so no storage profile decides it while running.
    Capacity,
    /// It bounds storage that is already there, so no storage profile fixes it at the build.
    Quota,
    /// The capacity of the fixed storage profile and a quota of the heap storage profile.
    Both,
}

impl Storage {
    /// The word as the declaration spells it.
    pub const fn id(self) -> &'static str {
        match self {
            Self::Capacity => "capacity",
            Self::Quota => "quota",
            Self::Both => "both",
        }
    }
}

/// Where a limit is bound, as the declaration states it. The limit's value is the constant of the
/// same name in [`crate::caps`]; this is what may decide it, and when.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LimitBinding {
    /// Whether it sizes storage, bounds storage already there, or both.
    pub storage: Storage,
    /// The scopes that each hold one value, widest first.
    pub scope: &'static [Scope],
    /// The latest stage the heap storage profile decides it at, or `None` where that profile
    /// does not read it.
    pub binding_heap: Option<Binding>,
    /// The latest stage the fixed storage profile decides it at, or `None` where that profile
    /// does not read it.
    pub binding_fixed: Option<Binding>,
    /// What a peer sees when the value changes within its range.
    pub wire: Wire,
}

/// The most values one policy may have: a [`Domain`] holds one bit per value.
pub const MAX_VALUES: usize = 32;

/// The values of one policy a build allows: a set over the positions of [`PolicyValue::ALL`].
pub struct Domain<T> {
    bits: u32,
    _values: PhantomData<fn() -> T>,
}

// Written out rather than derived: a derive would ask `T` for each trait, and a domain is a set of
// bits whatever its value type is.
impl<T> Clone for Domain<T> {
    fn clone(&self) -> Self {
        *self
    }
}

impl<T> Copy for Domain<T> {}

impl<T> PartialEq for Domain<T> {
    fn eq(&self, other: &Self) -> bool {
        self.bits == other.bits
    }
}

impl<T> Eq for Domain<T> {}

impl<T> fmt::Debug for Domain<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Domain").field("bits", &self.bits).finish()
    }
}

impl<T: PolicyValue> Domain<T> {
    /// Every value of the policy.
    pub const fn full() -> Self {
        let count = T::ALL.len();
        assert!(
            count <= MAX_VALUES,
            "a policy has more values than a domain holds"
        );
        let bits = if count == MAX_VALUES {
            u32::MAX
        } else {
            (1u32 << count) - 1
        };
        Self::with_bits(bits)
    }

    /// The values whose entry in `allowed` is true, `allowed` having one entry per value in the
    /// order of [`PolicyValue::ALL`].
    pub const fn from_allowed(allowed: &[bool]) -> Self {
        assert!(
            allowed.len() == T::ALL.len(),
            "a domain states one entry per value of its policy"
        );
        assert!(
            allowed.len() <= MAX_VALUES,
            "a policy has more values than a domain holds"
        );
        let mut bits = 0u32;
        let mut index = 0;
        while index < allowed.len() {
            if allowed[index] {
                bits |= 1u32 << index;
            }
            index += 1;
        }
        Self::with_bits(bits)
    }

    /// The domain a build states: `stated` holds each value's `WZ_POLICY_<NAME>_ALLOWS_<VALUE>`
    /// in the order of [`PolicyValue::ALL`], `on` allowing the value and `off` leaving it out.
    /// A value the build does not state is allowed unless `defaults_only`
    /// ([`crate::policy::policy_defaults_only`]), and then only when it is the build's default,
    /// at `default_index`.
    pub const fn from_stated(
        stated: &[Option<&str>],
        default_index: usize,
        defaults_only: bool,
    ) -> Self {
        assert!(
            stated.len() == T::ALL.len(),
            "a domain states one entry per value of its policy"
        );
        assert!(
            stated.len() <= MAX_VALUES,
            "a policy has more values than a domain holds"
        );
        let mut bits = 0u32;
        let mut index = 0;
        while index < stated.len() {
            let unstated = !defaults_only || index == default_index;
            if crate::policy::policy_allows(stated[index], unstated) {
                bits |= 1u32 << index;
            }
            index += 1;
        }
        Self::with_bits(bits)
    }

    const fn with_bits(bits: u32) -> Self {
        Self {
            bits,
            _values: PhantomData,
        }
    }

    /// Whether the value at `index` of [`PolicyValue::ALL`] is allowed; false past the last value.
    pub const fn contains_index(self, index: usize) -> bool {
        index < MAX_VALUES && (self.bits & (1u32 << index)) != 0
    }

    /// Whether `value` is allowed.
    pub fn contains(self, value: T) -> bool {
        self.contains_index(value.index())
    }

    /// How many values are allowed.
    pub const fn len(self) -> usize {
        self.bits.count_ones() as usize
    }

    /// Whether no value is allowed. A domain a build states always holds its default, so only a
    /// domain made by hand is empty.
    pub const fn is_empty(self) -> bool {
        self.bits == 0
    }

    /// Whether exactly one value is allowed, which makes the policy a constant of the build.
    pub const fn is_singleton(self) -> bool {
        self.bits.count_ones() == 1
    }

    /// How many values a holder of the policy keeps: none where the domain is one value, whose
    /// value is then the build's default, and one otherwise. The length of a [`Bound`]'s store.
    pub const fn held(self) -> usize {
        if self.is_singleton() {
            0
        } else {
            1
        }
    }

    /// The one value allowed, when the domain is a singleton.
    pub const fn only(self) -> Option<T> {
        if self.is_singleton() {
            Some(T::ALL[self.bits.trailing_zeros() as usize])
        } else {
            None
        }
    }
}

/// The value type of one policy: its values, the domain the build allows, the build's default,
/// and where the policy is bound. The generated module implements it for every policy's value
/// type; a bool policy's is a two-value enum of its own, `Off` and `On`.
pub trait PolicyValue: Copy + Eq + 'static {
    /// The policy's id, as the declaration spells it.
    const POLICY: &'static str;
    /// Every value, in the declaration's order; a [`Domain`] is a set over these positions.
    const ALL: &'static [Self];
    /// Each value of [`Self::ALL`] as the declaration, the Kconfig and the environment spell it.
    const IDS: &'static [&'static str];
    /// The values the build allows a later stage to select.
    const DOMAIN: Domain<Self>;
    /// The build's value (`WZ_POLICY_<NAME>`), or upstream's behaviour when it states none;
    /// always inside [`Self::DOMAIN`].
    const DEFAULT: Self;
    /// What holds one value.
    const SCOPE: Scope;
    /// The latest stage the value may be decided at.
    const BINDING: Binding;
    /// Whether the value may change once decided.
    const MUTABILITY: Mutability;
    /// What a peer sees when the value changes.
    const WIRE: Wire;
    /// The moment a change takes effect, for a policy whose mutability is
    /// [`Mutability::Quiescent`]; `None` for every other policy.
    const BOUNDARY: Option<&'static str>;
    /// How many values a [`Bound`] of the policy stores ([`Domain::held`]): none where the build
    /// allows one value.
    const HELD: usize = Self::DOMAIN.held();

    /// The value's position in [`Self::ALL`].
    fn index(self) -> usize;
}

/// Whether the build's default of `P`, at `default_index` of [`PolicyValue::ALL`], is inside the
/// build's domain. The generated module asserts it of every policy in a constant, so a build whose
/// `WZ_POLICY_<NAME>_ALLOWS_*` leave out its default does not compile.
#[doc(hidden)]
pub const fn default_is_allowed<P: PolicyValue>(default_index: usize) -> bool {
    P::DOMAIN.contains_index(default_index)
}

/// A policy's value, selected inside the build's domain, kept in `HELD` slots: none where the
/// domain is one value ([`PolicyValue::HELD`]), so a policy the build fixes costs its holder no
/// byte, and one otherwise. The generated `SessionPolicy` names `HELD` per concrete policy, which
/// is how a stable compiler lets the storage depend on the domain: a const generic argument may
/// be any constant expression that names no generic parameter.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Bound<P: PolicyValue, const HELD: usize> {
    value: [P; HELD],
}

impl<P: PolicyValue, const HELD: usize> Bound<P, HELD> {
    /// `value`, when the build's domain allows it.
    pub fn select(value: P) -> Result<Self, OutsideDomain<P>> {
        if P::DOMAIN.contains(value) {
            Ok(Self {
                value: [value; HELD],
            })
        } else {
            Err(OutsideDomain { value })
        }
    }

    /// The selected value. Where the build's domain is one value, that value is the build's
    /// default and nothing is read: the `const` block decides the branch when the build is
    /// compiled, which a plain call of a `const fn` would not, and a store of no slot has nothing
    /// to read either. A `const fn` itself, so a constant can still be computed from a snapshot.
    pub const fn get(&self) -> P {
        if const { P::DOMAIN.is_singleton() } {
            P::DEFAULT
        } else {
            match self.value.first() {
                Some(value) => *value,
                None => P::DEFAULT,
            }
        }
    }

    /// The build's default, which the domain always holds. Read by the generated
    /// `SessionPolicy::from_build`, the one place a snapshot starts from the build.
    pub(crate) const fn build_default() -> Self {
        Self {
            value: [P::DEFAULT; HELD],
        }
    }
}

impl<P: PolicyValue, const HELD: usize> Default for Bound<P, HELD> {
    /// The build's default.
    fn default() -> Self {
        Self::build_default()
    }
}

/// A value the build's domain leaves out, refused by [`Bound::select`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct OutsideDomain<P> {
    /// The value refused.
    pub value: P,
}

impl<P: PolicyValue> fmt::Display for OutsideDomain<P> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "the build leaves `{}` out of the domain of the policy `{}`",
            P::IDS[self.value.index()],
            P::POLICY
        )
    }
}

impl<P: PolicyValue + fmt::Debug> core::error::Error for OutsideDomain<P> {}

#[cfg(test)]
mod tests {
    use super::*;

    /// A three-value policy whose build leaves the middle value out.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    enum Mode {
        Low,
        Mid,
        High,
    }

    impl PolicyValue for Mode {
        const POLICY: &'static str = "test-mode";
        const ALL: &'static [Self] = &[Self::Low, Self::Mid, Self::High];
        const IDS: &'static [&'static str] = &["low", "mid", "high"];
        const DOMAIN: Domain<Self> = Domain::from_allowed(&[true, false, true]);
        const DEFAULT: Self = Self::Low;
        const SCOPE: Scope = Scope::Session;
        const BINDING: Binding = Binding::Open;
        const MUTABILITY: Mutability = Mutability::Fixed;
        const WIRE: Wire = Wire::None;
        const BOUNDARY: Option<&'static str> = None;

        fn index(self) -> usize {
            self as usize
        }
    }

    /// A two-value policy whose build allows only `On`, its default.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    enum Pinned {
        Off,
        On,
    }

    impl PolicyValue for Pinned {
        const POLICY: &'static str = "test-pinned";
        const ALL: &'static [Self] = &[Self::Off, Self::On];
        const IDS: &'static [&'static str] = &["off", "on"];
        const DOMAIN: Domain<Self> = Domain::from_allowed(&[false, true]);
        const DEFAULT: Self = Self::On;
        const SCOPE: Scope = Scope::Link;
        const BINDING: Binding = Binding::Live;
        const MUTABILITY: Mutability = Mutability::Quiescent;
        const WIRE: Wire = Wire::Timing;
        const BOUNDARY: Option<&'static str> = Some("the next time the link opens");

        fn index(self) -> usize {
            self as usize
        }
    }

    #[test]
    fn a_domain_holds_the_values_it_was_given_and_no_other() {
        let domain = Domain::<Mode>::from_allowed(&[true, false, true]);
        assert!(domain.contains(Mode::Low));
        assert!(!domain.contains(Mode::Mid));
        assert!(domain.contains(Mode::High));
        assert_eq!(domain.len(), 2);
        assert!(!domain.is_empty());
        assert!(!domain.is_singleton());
        assert_eq!(domain.only(), None);
        // A position past the last value, and one past the bits a domain has, are not in it.
        assert!(!domain.contains_index(3));
        assert!(!domain.contains_index(MAX_VALUES + 8));
    }

    #[test]
    fn a_full_domain_holds_every_value() {
        let full = Domain::<Mode>::full();
        assert_eq!(full.len(), 3);
        assert!(Mode::ALL.iter().all(|&value| full.contains(value)));
        assert_eq!(full, Domain::from_allowed(&[true, true, true]));
        assert_ne!(full, Mode::DOMAIN);
    }

    #[test]
    fn a_domain_of_one_value_is_a_singleton_that_names_it() {
        let one = Domain::<Mode>::from_allowed(&[false, false, true]);
        assert!(one.is_singleton());
        assert_eq!(one.len(), 1);
        assert_eq!(one.only(), Some(Mode::High));
        let none = Domain::<Mode>::from_allowed(&[false, false, false]);
        assert!(none.is_empty());
        assert!(!none.is_singleton());
        assert_eq!(none.only(), None);
    }

    #[test]
    fn a_domain_is_computed_in_a_constant() {
        const ONLY: Option<Pinned> = Pinned::DOMAIN.only();
        const LEN: usize = Mode::DOMAIN.len();
        assert_eq!(ONLY, Some(Pinned::On));
        assert_eq!(LEN, 2);
    }

    #[test]
    #[should_panic(expected = "one entry per value of its policy")]
    fn a_domain_that_does_not_state_every_value_is_refused() {
        Domain::<Mode>::from_allowed(&[true, true]);
    }

    #[test]
    fn select_takes_a_value_inside_the_domain_and_refuses_one_outside() {
        assert_eq!(
            Bound::<Mode, 1>::select(Mode::High).map(|bound| bound.get()),
            Ok(Mode::High)
        );
        assert_eq!(
            Bound::<Mode, 1>::select(Mode::Low).map(|bound| bound.get()),
            Ok(Mode::Low)
        );
        assert_eq!(
            Bound::<Mode, 1>::select(Mode::Mid),
            Err(OutsideDomain { value: Mode::Mid })
        );
        assert_eq!(
            Bound::<Pinned, 0>::select(Pinned::Off),
            Err(OutsideDomain { value: Pinned::Off })
        );
    }

    #[test]
    fn a_refusal_names_the_value_and_the_policy() {
        let refused = Bound::<Mode, 1>::select(Mode::Mid).unwrap_err();
        assert_eq!(
            std::format!("{refused}"),
            "the build leaves `mid` out of the domain of the policy `test-mode`"
        );
    }

    #[test]
    fn get_of_a_singleton_domain_is_the_default_whatever_was_stored() {
        // Only a value inside the domain can be selected; the field is set here directly to
        // show that `get` does not read it.
        let stored_off = Bound::<Pinned, 1> {
            value: [Pinned::Off],
        };
        assert_eq!(stored_off.get(), Pinned::On);
        assert_eq!(Bound::<Pinned, 0>::default().get(), Pinned::On);
    }

    #[test]
    fn get_of_a_wider_domain_is_the_stored_value() {
        let stored_high = Bound::<Mode, 1> {
            value: [Mode::High],
        };
        assert_eq!(stored_high.get(), Mode::High);
        assert_eq!(Bound::<Mode, 1>::default().get(), Mode::Low);
    }

    /// A policy the build fixes to one value is held in no byte, and a wider one in the bytes of
    /// its value: the store's length is the domain's.
    #[test]
    fn a_one_value_domain_is_held_in_no_byte() {
        assert_eq!(Pinned::HELD, 0);
        assert_eq!(Mode::HELD, 1);
        assert_eq!(core::mem::size_of::<Bound<Pinned, { Pinned::HELD }>>(), 0);
        assert_eq!(
            core::mem::size_of::<Bound<Mode, { Mode::HELD }>>(),
            core::mem::size_of::<Mode>()
        );
        let pinned = Bound::<Pinned, { Pinned::HELD }>::select(Pinned::On).expect("the default");
        assert_eq!(pinned.get(), Pinned::On);
        assert_eq!(Bound::<Pinned, 0>::build_default(), pinned);
    }

    /// An allowance the build states wins; one it does not allows its value unless the rule keeps
    /// only the default, which then is the one value allowed.
    #[test]
    fn a_stated_domain_is_read_by_the_rule_for_what_it_does_not_state() {
        let unstated = [None, None, None];
        assert_eq!(
            Domain::<Mode>::from_stated(&unstated, 0, false),
            Domain::full()
        );
        let defaults = Domain::<Mode>::from_stated(&unstated, 0, true);
        assert_eq!(defaults.only(), Some(Mode::Low));
        assert_eq!(defaults.held(), 0);
        // An `on` widens a default-only domain, and an `off` narrows a full one.
        let widened = Domain::<Mode>::from_stated(&[None, None, Some("on")], 0, true);
        assert_eq!(widened, Domain::from_allowed(&[true, false, true]));
        assert_eq!(widened.held(), 1);
        let narrowed = Domain::<Mode>::from_stated(&[None, Some("off"), None], 2, false);
        assert_eq!(narrowed, Domain::from_allowed(&[true, false, true]));
        // The default is the one kept, wherever it sits.
        let at_two = Domain::<Mode>::from_stated(&unstated, 2, true);
        assert_eq!(at_two.only(), Some(Mode::High));
    }

    #[test]
    #[should_panic(expected = "one entry per value of its policy")]
    fn a_stated_domain_that_does_not_state_every_value_is_refused() {
        Domain::<Mode>::from_stated(&[None, None], 0, false);
    }

    #[test]
    fn the_default_is_allowed_only_where_the_domain_holds_it() {
        assert!(default_is_allowed::<Mode>(0));
        assert!(!default_is_allowed::<Mode>(1));
        assert!(default_is_allowed::<Pinned>(1));
        assert!(!default_is_allowed::<Pinned>(0));
    }

    #[test]
    fn each_word_is_spelled_as_the_declaration_spells_it() {
        assert_eq!(Scope::Entity.id(), "entity");
        assert_eq!(Binding::Live.id(), "live");
        assert_eq!(Mutability::Quiescent.id(), "quiescent");
        assert_eq!(Wire::Negotiated.id(), "negotiated");
        assert_eq!(Storage::Both.id(), "both");
        assert_eq!(Pinned::BOUNDARY, Some("the next time the link opens"));
        assert_eq!(Mode::BOUNDARY, None);
    }
}
