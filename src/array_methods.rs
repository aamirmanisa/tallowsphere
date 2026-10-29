//! BP21 — the array method registry.
//!
//! A method call on an `Array` receiver is resolved **at check time** against
//! this table. The table is not a proposal: every row is a method the
//! interpreter (`src/interp.rs`, `Interpreter::call_method`) actually executes
//! for a `Value::Array`, and every row was measured on both planes before its
//! `native` flag was recorded (see `tests/array_methods.rs`, which re-runs that
//! measurement on every build).
//!
//! The three components used to disagree about whether these methods exist:
//! `push` was implemented in the interpreter, unknown to the checker, and
//! lowered by codegen into something that printed a raw `0x02` byte. `tallow
//! check` — the command a user runs before shipping — said the program was
//! fine. The registry is the single place that answers "does this method exist
//! on this receiver, with this arity, and can the native plane lower it".
//!
//! Rules this table encodes (docs/spec/ARRAY-METHODS.md):
//!
//!   * an unknown name on an `Array` receiver is `E0625` at check time;
//!   * a wrong argument count is a named error (`E0626`), never a runtime
//!     surprise;
//!   * a row with `native = false` is a named build refusal on the native plane
//!     (`the native backend has no lowering for Array.<name>; run with
//!     --interpret`), never a call that silently yields a byte;
//!   * `push` is *functional*: it returns a new array and mutates nothing. A
//!     bare `a.push(2)` discards the result — the method looks mutating and is
//!     not, which is exactly the trap a type checker exists to make visible.
//!
//! Receivers of type `Unknown` are left alone: nothing here applies to a type
//! the checker cannot see, and the interpreter remains the fallback plane.

/// Argument a row accepts. Recorded as data; the checker enforces the *count*
/// (`E0626`) and the API docs read the kinds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Param {
    /// Any value.
    Any,
    /// An integer (an index, a count, a chunk size, `anonymize`'s k).
    Int,
    /// A string (a separator, a substring).
    Str,
    /// An array of the receiver's element type (the second operand of `union`,
    /// `zip`, `concat`, …).
    Array,
    /// A closure over the element (`map`, `filter`, `any`, …).
    Closure,
    /// A two-parameter closure (`reduce`, `sort_by`: accumulator/element or
    /// element/element).
    Closure2,
}

impl Param {
    /// Human rendering used in diagnotics and API docs.
    pub fn describe(self) -> &'static str {
        match self {
            Param::Any => "any",
            Param::Int => "int",
            Param::Str => "string",
            Param::Array => "array",
            Param::Closure => "closure",
            Param::Closure2 => "closure (2 parameters)",
        }
    }
}

/// What the call evaluates to, relative to the receiver's element type `T`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Ret {
    /// A new array of the same element type (`[]T`).
    Same,
    /// One element (`T`), or `nil` when the array is empty.
    Element,
    /// An array of arrays (`[][]T`).
    ArrayOfArray,
    /// An array whose element type is the closure's result — not statically
    /// known from the receiver, so the checker records `Unknown`.
    Mapped,
    /// An integer (`len`, `count`, `sum`, `index_of`, …).
    Int,
    /// A boolean (`is_empty`, `contains`, `any`, `all`, …).
    Bool,
    /// A string (`join`, `to_string`, `to_json`).
    String,
    /// No useful value (`each`, `for_each`, `each_ok`).
    Void,
}

/// One row of the registry.
#[derive(Debug)]
pub struct ArrayMethod {
    /// The method name as the interpreter's `match method` spells it.
    pub name: &'static str,
    /// Fewest arguments the interpreter implements the method with.
    pub min_args: u8,
    /// Most arguments the method reads. Anything beyond this is `E0626`.
    pub max_args: u8,
    /// Argument kinds, in order, for documentation and future checking.
    pub params: &'static [Param],
    /// The result type relative to the receiver's element type.
    pub ret: Ret,
    /// Whether the native backend lowers this method for an array receiver.
    /// `false` is a *named refusal*, not a silent byte — and it was measured,
    /// not guessed.
    pub native: bool,
    /// Whether the method returns a new array and mutates nothing. `push` is
    /// `true`; there is no mutating method in this table.
    pub functional: bool,
    /// One sentence a user can act on.
    pub doc: &'static str,
}

impl ArrayMethod {
    /// Whether a call with `n` arguments is well-formed.
    pub fn accepts_arity(&self, n: usize) -> bool {
        n >= self.min_args as usize && n <= self.max_args as usize
    }

    /// The arity clause of the named arity error: "expects 1 argument",
    /// "expects 0 or 1 arguments", "expects 2 arguments".
    pub fn arity_clause(&self) -> String {
        let (lo, hi) = (self.min_args, self.max_args);
        if lo == hi {
            format!("takes {lo} argument{}", if lo == 1 { "" } else { "s" })
        } else {
            format!("takes {lo} or {hi} arguments")
        }
    }
}

/// The refusal the native backend emits for a registry method it cannot lower.
///
/// One spelling, cited by both the emitter and the tests: a caller that reads
/// stderr must be able to see which method needs the interpreter.
pub fn native_refusal(name: &str) -> String {
    format!("the native backend has no lowering for Array.{name}; run with --interpret")
}

const A: &[Param] = &[Param::Any];
const I: &[Param] = &[Param::Int];
const S: &[Param] = &[Param::Str];
const C: &[Param] = &[Param::Closure];
const C2: &[Param] = &[Param::Closure2];
const ARR: &[Param] = &[Param::Array];
const I_NONE: &[Param] = &[];

/// The interpreter's array method set, one row per method.
///
/// Derivation: `Interpreter::call_method` in `src/interp.rs` — every arm whose
/// `Value::Array` branch executes. `len`, `to_array`, `to_string`, `to_json`
/// are answered by the generic arms that dispatch through `Value::len()` /
/// `display()`; the rest are the explicit array arms.
pub const ARRAY_METHODS: &[ArrayMethod] = &[
    ArrayMethod {
        name: "push",
        min_args: 1,
        max_args: 1,
        params: A,
        ret: Ret::Same,
        // Codegen has an arm for this name and it is wrong on this plane (the
        // bound result printed a raw byte). The contract for BP21 is explicit:
        // a registry method the native plane cannot lower is a named refusal.
        native: false,
        functional: true,
        doc: "returns a NEW array with the value appended; a bare `a.push(2)` mutates nothing",
    },
    ArrayMethod {
        name: "len",
        min_args: 0,
        max_args: 0,
        params: I_NONE,
        ret: Ret::Int,
        native: true,
        functional: true,
        doc: "the number of elements",
    },
    ArrayMethod {
        name: "first",
        min_args: 0,
        max_args: 0,
        params: I_NONE,
        ret: Ret::Element,
        native: true,
        functional: true,
        doc: "the first element, or nil when the array is empty",
    },
    ArrayMethod {
        name: "last",
        min_args: 0,
        max_args: 0,
        params: I_NONE,
        ret: Ret::Element,
        native: true,
        functional: true,
        doc: "the last element, or nil when the array is empty",
    },
    ArrayMethod {
        name: "sum",
        min_args: 0,
        max_args: 0,
        params: I_NONE,
        ret: Ret::Int,
        native: true,
        functional: true,
        doc: "the sum of the elements",
    },
    ArrayMethod {
        name: "reverse",
        min_args: 0,
        max_args: 0,
        params: I_NONE,
        ret: Ret::Same,
        native: true,
        functional: true,
        doc: "a new array with the elements in reverse order",
    },
    ArrayMethod {
        name: "join",
        min_args: 0,
        max_args: 1,
        params: S,
        ret: Ret::String,
        native: true,
        functional: true,
        doc: "the elements rendered and joined; the separator defaults to the empty string",
    },
    ArrayMethod {
        name: "is_empty",
        min_args: 0,
        max_args: 0,
        params: I_NONE,
        ret: Ret::Bool,
        native: true,
        functional: true,
        doc: "true when the array has no elements",
    },
    ArrayMethod {
        name: "contains",
        min_args: 1,
        max_args: 1,
        params: A,
        ret: Ret::Bool,
        native: true,
        functional: true,
        doc: "true when an element equals the argument",
    },
    ArrayMethod {
        name: "index_of",
        min_args: 1,
        max_args: 1,
        params: A,
        ret: Ret::Int,
        native: true,
        functional: true,
        doc: "the index of the first equal element, or -1",
    },
    ArrayMethod {
        name: "count",
        min_args: 0,
        max_args: 1,
        params: A,
        ret: Ret::Int,
        native: true,
        functional: true,
        doc: "the length; with a closure, how many elements the predicate accepts; with a value, how many equal it",
    },
    ArrayMethod {
        name: "to_array",
        min_args: 0,
        max_args: 0,
        params: I_NONE,
        ret: Ret::Same,
        native: false,
        functional: true,
        doc: "the same elements as an array — refused on the native plane: the result is not tracked as an array, so `.len()` on it read strlen (measured: 1 for a 2-element array)",
    },
    ArrayMethod {
        name: "to_string",
        min_args: 0,
        max_args: 0,
        params: I_NONE,
        ret: Ret::String,
        native: false,
        functional: true,
        doc: "the array rendered as text (`[1, 2]`)",
    },
    ArrayMethod {
        name: "to_json",
        min_args: 0,
        max_args: 0,
        params: I_NONE,
        ret: Ret::String,
        native: false,
        functional: true,
        doc: "the array rendered as JSON",
    },
    ArrayMethod {
        name: "map",
        min_args: 1,
        max_args: 1,
        params: C,
        ret: Ret::Mapped,
        native: true,
        functional: true,
        doc: "a new array of the closure's results",
    },
    ArrayMethod {
        name: "filter",
        min_args: 1,
        max_args: 1,
        params: C,
        ret: Ret::Same,
        native: true,
        functional: true,
        doc: "a new array of the elements the predicate accepts",
    },
    ArrayMethod {
        name: "each",
        min_args: 1,
        max_args: 1,
        params: C,
        ret: Ret::Void,
        native: true,
        functional: true,
        doc: "calls the closure once per element for its effect",
    },
    ArrayMethod {
        name: "each_ok",
        min_args: 1,
        max_args: 1,
        params: C,
        ret: Ret::Void,
        native: true,
        functional: true,
        doc: "calls the closure for the Ok values of an array of Result",
    },
    ArrayMethod {
        name: "flat_map",
        min_args: 1,
        max_args: 1,
        params: C,
        ret: Ret::Same,
        native: true,
        functional: true,
        doc: "maps each element to an array and concatenates the results",
    },
    ArrayMethod {
        name: "flatten",
        min_args: 0,
        max_args: 0,
        params: I_NONE,
        ret: Ret::Same,
        native: true,
        functional: true,
        doc: "one level of nesting removed",
    },
    ArrayMethod {
        name: "unique",
        min_args: 0,
        max_args: 0,
        params: I_NONE,
        ret: Ret::Same,
        native: true,
        functional: true,
        doc: "the elements with duplicates removed, first occurrence kept; string elements compare by value",
    },
    ArrayMethod {
        name: "to_set",
        min_args: 0,
        max_args: 0,
        params: I_NONE,
        ret: Ret::Same,
        native: false,
        functional: true,
        doc: "alias for `unique`",
    },
    ArrayMethod {
        name: "distinct",
        min_args: 0,
        max_args: 0,
        params: I_NONE,
        ret: Ret::Same,
        native: false,
        functional: true,
        doc: "alias for `unique`",
    },
    ArrayMethod {
        name: "union",
        min_args: 1,
        max_args: 1,
        params: ARR,
        ret: Ret::Same,
        native: false,
        functional: true,
        doc: "the elements of either array, first occurrence kept",
    },
    ArrayMethod {
        name: "intersection",
        min_args: 1,
        max_args: 1,
        params: ARR,
        ret: Ret::Same,
        native: false,
        functional: true,
        doc: "the elements present in both arrays",
    },
    ArrayMethod {
        name: "difference",
        min_args: 1,
        max_args: 1,
        params: ARR,
        ret: Ret::Same,
        native: false,
        functional: true,
        doc: "the elements of the receiver not present in the argument",
    },
    ArrayMethod {
        name: "symmetric_difference",
        min_args: 1,
        max_args: 1,
        params: ARR,
        ret: Ret::Same,
        native: false,
        functional: true,
        doc: "the elements present in exactly one of the two arrays",
    },
    ArrayMethod {
        name: "is_subset",
        min_args: 1,
        max_args: 1,
        params: ARR,
        ret: Ret::Bool,
        native: false,
        functional: true,
        doc: "true when every element of the receiver is in the argument",
    },
    ArrayMethod {
        name: "concat",
        min_args: 1,
        max_args: 1,
        params: ARR,
        ret: Ret::Same,
        native: false,
        functional: true,
        doc: "the receiver's elements followed by the argument's",
    },
    ArrayMethod {
        name: "zip",
        min_args: 1,
        max_args: 1,
        params: ARR,
        ret: Ret::ArrayOfArray,
        native: true,
        functional: true,
        doc: "pairs of elements from the two arrays, as two-element arrays",
    },
    ArrayMethod {
        name: "enumerate",
        min_args: 0,
        max_args: 0,
        params: I_NONE,
        ret: Ret::ArrayOfArray,
        native: true,
        functional: true,
        doc: "`[index, element]` pairs",
    },
    ArrayMethod {
        name: "take",
        min_args: 1,
        max_args: 1,
        params: I,
        ret: Ret::Same,
        native: true,
        functional: true,
        doc: "the first n elements",
    },
    ArrayMethod {
        name: "skip",
        min_args: 1,
        max_args: 1,
        params: I,
        ret: Ret::Same,
        native: true,
        functional: true,
        doc: "the elements after the first n",
    },
    ArrayMethod {
        name: "slice",
        min_args: 1,
        max_args: 2,
        params: &[Param::Int, Param::Int],
        ret: Ret::Same,
        native: true,
        functional: true,
        doc: "the elements from `start` up to (not including) `end`",
    },
    ArrayMethod {
        name: "sort",
        min_args: 0,
        max_args: 0,
        params: I_NONE,
        ret: Ret::Same,
        native: true,
        functional: true,
        doc: "a new array in ascending order",
    },
    ArrayMethod {
        name: "sort_by",
        min_args: 1,
        max_args: 1,
        params: C,
        ret: Ret::Same,
        native: false,
        functional: true,
        // The interpreter's `sort_by` takes a KEY EXTRACTOR (`{ item -> key }`)
        // and sorts by the extracted key; `emit_array_sort_by_inline` in the
        // native backend calls the closure with TWO arguments and treats the
        // result as an ordering. Those are different contracts for the same
        // name, so the native plane must not answer this one.
        doc: "a new array ordered by the key the closure extracts from each element",
    },
    ArrayMethod {
        name: "min",
        min_args: 0,
        max_args: 0,
        params: I_NONE,
        ret: Ret::Element,
        native: true,
        functional: true,
        doc: "the smallest element, or nil when empty",
    },
    ArrayMethod {
        name: "max",
        min_args: 0,
        max_args: 0,
        params: I_NONE,
        ret: Ret::Element,
        native: true,
        functional: true,
        doc: "the largest element, or nil when empty",
    },
    ArrayMethod {
        name: "min_by",
        min_args: 1,
        max_args: 1,
        params: C,
        ret: Ret::Element,
        native: false,
        functional: true,
        doc: "the element with the smallest key under the closure",
    },
    ArrayMethod {
        name: "max_by",
        min_args: 1,
        max_args: 1,
        params: C,
        ret: Ret::Element,
        native: false,
        functional: true,
        doc: "the element with the largest key under the closure",
    },
    ArrayMethod {
        name: "group_by",
        min_args: 1,
        max_args: 1,
        params: C,
        ret: Ret::Mapped,
        native: false,
        functional: true,
        doc: "elements grouped by the closure's key",
    },
    ArrayMethod {
        name: "find",
        min_args: 1,
        max_args: 1,
        params: C,
        ret: Ret::Element,
        native: true,
        functional: true,
        doc: "the first element the predicate accepts, or nil",
    },
    ArrayMethod {
        name: "find_index",
        min_args: 1,
        max_args: 1,
        params: C,
        ret: Ret::Int,
        native: false,
        functional: true,
        doc: "the index of the first element the predicate accepts, or -1",
    },
    ArrayMethod {
        name: "any",
        min_args: 1,
        max_args: 1,
        params: C,
        ret: Ret::Bool,
        native: true,
        functional: true,
        doc: "true when the predicate accepts at least one element",
    },
    ArrayMethod {
        name: "all",
        min_args: 1,
        max_args: 1,
        params: C,
        ret: Ret::Bool,
        native: true,
        functional: true,
        doc: "true when the predicate accepts every element",
    },
    ArrayMethod {
        name: "reduce",
        // `reduce(closure)` folds from the first element; `reduce(init, closure)`
        // folds from `init`. The interpreter implements both (src/interp.rs,
        // the `(Some(func), None)` arm), so both are the signature.
        min_args: 1,
        max_args: 2,
        params: &[Param::Any, Param::Closure2],
        ret: Ret::Element,
        native: true,
        functional: true,
        doc: "folds the elements into an accumulator, starting from the initial value (or the first element when it is omitted)",
    },
    ArrayMethod {
        name: "chunk",
        min_args: 1,
        max_args: 1,
        params: I,
        ret: Ret::ArrayOfArray,
        native: true,
        functional: true,
        doc: "consecutive groups of at most n elements",
    },
    ArrayMethod {
        name: "chunks",
        min_args: 1,
        max_args: 1,
        params: I,
        ret: Ret::ArrayOfArray,
        native: false,
        functional: true,
        doc: "alias for `chunk`",
    },
    ArrayMethod {
        name: "window",
        min_args: 1,
        max_args: 1,
        params: I,
        ret: Ret::ArrayOfArray,
        native: false,
        functional: true,
        doc: "every sliding window of n elements",
    },
    ArrayMethod {
        name: "windows",
        min_args: 1,
        max_args: 1,
        params: I,
        ret: Ret::ArrayOfArray,
        native: false,
        functional: true,
        doc: "alias for `window`",
    },
    ArrayMethod {
        name: "pop",
        min_args: 0,
        max_args: 0,
        params: I_NONE,
        ret: Ret::Element,
        native: false,
        functional: true,
        doc: "the last element; the array itself is unchanged",
    },
    ArrayMethod {
        name: "collect_ok",
        min_args: 0,
        max_args: 0,
        params: I_NONE,
        ret: Ret::Mapped,
        native: false,
        functional: true,
        doc: "the Ok values of an array of Result, or the first Err",
    },
    ArrayMethod {
        name: "filter_ok",
        min_args: 0,
        max_args: 0,
        params: I_NONE,
        ret: Ret::Same,
        native: false,
        functional: true,
        doc: "the Ok values of an array of Result, dropping the Errs",
    },
    ArrayMethod {
        name: "partition_result",
        min_args: 0,
        max_args: 0,
        params: I_NONE,
        ret: Ret::ArrayOfArray,
        native: false,
        functional: true,
        doc: "a two-element array of the Ok values and the Err values",
    },
    ArrayMethod {
        name: "parallel_map",
        min_args: 1,
        max_args: 1,
        params: C,
        ret: Ret::Mapped,
        native: false,
        functional: true,
        doc: "`map` over a bounded worker pool",
    },
    ArrayMethod {
        name: "anonymize",
        min_args: 1,
        max_args: 2,
        params: &[Param::Int, Param::Array],
        ret: Ret::Same,
        native: false,
        functional: true,
        doc: "k-anonymised copies of an array of structs",
    },
];

/// Resolve a method name against the array registry.
pub fn lookup(name: &str) -> Option<&'static ArrayMethod> {
    ARRAY_METHODS.iter().find(|m| m.name == name)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn registry_has_no_duplicate_names() {
        let mut seen = std::collections::HashSet::new();
        for m in ARRAY_METHODS {
            assert!(seen.insert(m.name), "duplicate registry row: {}", m.name);
        }
    }

    #[test]
    fn every_row_declares_a_usable_arity() {
        for m in ARRAY_METHODS {
            assert!(
                m.min_args <= m.max_args,
                "{}: min_args > max_args",
                m.name
            );
            assert!(
                m.accepts_arity(m.min_args as usize) && m.accepts_arity(m.max_args as usize),
                "{}: bounds do not accept themselves",
                m.name
            );
            assert!(!m.doc.is_empty(), "{}: a row without a doc trains nobody", m.name);
        }
    }

    #[test]
    fn params_are_recorded_in_order() {
        for m in ARRAY_METHODS {
            assert!(
                m.params.len() as u8 <= m.max_args,
                "{}: more declared params ({}) than max_args ({})",
                m.name,
                m.params.len(),
                m.max_args
            );
        }
    }

    #[test]
    fn push_is_functional_and_declares_its_trap() {
        let push = lookup("push").expect("push is an interpreter array method");
        assert!(push.functional, "push returns a new array; it mutates nothing");
        assert!(
            push.doc.contains("mutates nothing"),
            "the doc must say so: a method that looks mutating and is not is the trap"
        );
        assert_eq!(push.min_args, 1);
        assert_eq!(push.max_args, 1);
        assert!(!push.native, "the native plane has no correct lowering for Array.push");
    }

    #[test]
    fn native_refusal_names_the_type_and_the_method() {
        let msg = native_refusal("push");
        assert!(msg.contains("Array.push"), "{msg}");
        assert!(msg.contains("--interpret"), "{msg}");
    }

    #[test]
    fn unknown_names_do_not_resolve() {
        assert!(lookup("frobnicate").is_none());
        // Methods the *native* backend knows but the interpreter does not are
        // not array methods: the registry is the interpreter's set.
        assert!(lookup("insert").is_none());
        assert!(lookup("remove").is_none());
    }
}
