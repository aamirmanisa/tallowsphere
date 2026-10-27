//! Declared result types for `stdlib/*.tl` module calls.
//!
//! # Why this exists
//!
//! The generic stdlib bridge (`src/runtime/stdlib_bridge_ffi.rs`) returns a
//! pointer to a marshalled value: raw UTF-8 for a `String`, `\x1fJ`-prefixed
//! JSON for everything else. Codegen used to have no declared return type for a
//! stdlib module call — `resolve_imports` skips `import tallow.*` outright — so
//! a bridged call's result was a bare `ptr`, and a module that returned `Int`
//! printed `\x1fJ1` where the interpreter printed `1`, and a `Bool` was truthy
//! because its pointer was non-null. A wrong answer wearing a plausible shape.
//!
//! # Where the signature comes from
//!
//! From the declarations, not from a second table: `stdlib/ip.tl` already says
//! `native fn ip.lookup(table: IpAsnTable, ip: String) -> AsnMatch`, and there
//! are 1034 such declarations across 92 files. They are *Tallow*, so the only
//! parser that can be trusted with them is `crate::parser` — a line scanner
//! would be a second grammar (`stdlib/session.tl:29` already splits a
//! declaration over three lines). A build script cannot call the crate's own
//! parser, so the split is:
//!
//! * `build.rs` embeds every `stdlib/*.tl` verbatim (`STDLIB_SOURCES`, sorted);
//! * this module lexes and parses them **once, lazily**, the first time a
//!   bridged call asks for a signature, and indexes the result by qualified
//!   name.
//!
//! Carrying the declarations through `resolve_imports` instead was the cheaper
//! option on paper — no build step, no embedded text — but it would have made a
//! *foreign* import (`import tallow.ip`) load a file from the filesystem at
//! compile time, which the installed binary cannot do: `install.sh` ships the
//! binary and no `stdlib/` directory. Embedding is what makes an installed
//! compiler answer the same question as a build-tree one.
//!
//! # What a caller does with it
//!
//! `codegen::emit_stdlib_bridge_call` maps each [`RetKind`] onto a
//! representation: a scalar is unboxed by a runtime entry point
//! (`tallow_json_as_i64`/`_f64`/`_bool`), a `String` and a named struct keep the
//! pointer the bridge already returns, and a kind this pass cannot decode
//! (`T?`, `[]T`, `Map<K,V>`, `Result<T>`) becomes
//! `LLType::BridgeOpaque` — a value that can still be handed back to another
//! bridged call but cannot be printed, compared, indexed or branched on, because
//! each of those would be the same plausible-shape wrong answer as a scalar.

use std::collections::HashMap;
use std::sync::OnceLock;

use crate::ast::{FnDecl, Item, TypeExpr, TypeExprKind};

include!(concat!(env!("OUT_DIR"), "/stdlib_declarations.rs"));

/// What a bridged call's result is declared to be.
///
/// The split is not "which Tallow type" but "which representation codegen can
/// produce honestly". `Named` keeps the bridge's pointer because a struct
/// round-trips through the `__type` tag (proven by `tests/api_parity_native.rs`);
/// `Opaque` exists so an undecodable kind is refused by name instead of being
/// passed off as a value.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RetKind {
    Int,
    Float,
    Bool,
    Str,
    /// A named type — a struct, a map-newtype, anything the bridge round-trips
    /// as tagged JSON. The spelling is carried for diagnostics.
    Named(String),
    /// Declared, but not decodable in this pass: an optional, a slice, a
    /// `Map`, a `Result`, a tuple, a function type. The spelling is the
    /// declaration's own, so a refusal can name what was refused.
    Opaque(String),
    /// `-> ()`, or a declaration with no arrow: nothing to unbox.
    Void,
}

/// One parsed declaration: the qualified call name and its result kind.
struct Declared {
    ret: RetKind,
}

impl Declared {
    fn from_fn(stem: &str, f: &FnDecl) -> Option<(String, Declared)> {
        // A `native fn` with no body is a module declaration; a `fn` with a body
        // in the same file is not this module's ABI, but it is still a
        // *declaration* of the module's shape, and a bridged call never reaches
        // it (the bridge dispatches on the native surface). Both are indexed so
        // a documented wrapper resolves too, and `is_native` is not consulted —
        // the question is "what does this name return", not "is it implemented
        // in Rust".
        let name = if f.name.contains('.') {
            f.name.clone()
        } else {
            format!("{stem}.{}", f.name)
        };
        let ret = match &f.return_type {
            None => RetKind::Void,
            Some(ty) => classify(ty),
        };
        Some((name, Declared { ret }))
    }
}

/// Map a declared type onto the representation codegen can produce.
fn classify(ty: &TypeExpr) -> RetKind {
    match &ty.kind {
        TypeExprKind::Named(name) => match name.as_str() {
            "Int" | "i64" | "i32" | "i16" | "i8" | "u8" | "u16" | "u32" | "u64" | "usize"
            | "isize" => RetKind::Int,
            "Float" | "f64" | "f32" => RetKind::Float,
            "Bool" | "bool" => RetKind::Bool,
            "String" | "str" => RetKind::Str,
            "()" | "unit" => RetKind::Void,
            other => RetKind::Named(other.to_string()),
        },
        // Everything with structure is refused for now rather than guessed:
        // a `[][]String` printed as a pointer is the defect, not a feature.
        _ => RetKind::Opaque(render(ty)),
    }
}

/// The declaration's own spelling of a type, for a refusal message.
fn render(ty: &TypeExpr) -> String {
    match &ty.kind {
        TypeExprKind::Named(name) => name.clone(),
        TypeExprKind::Generic { name, args } => {
            let inner: Vec<String> = args.iter().map(render).collect();
            format!("{name}<{}>", inner.join(", "))
        }
        TypeExprKind::Slice(inner) => format!("[]{}", render(inner)),
        TypeExprKind::Optional(inner) => format!("{}?", render(inner)),
        TypeExprKind::Tuple(items) => {
            let inner: Vec<String> = items.iter().map(render).collect();
            format!("({})", inner.join(", "))
        }
        TypeExprKind::Function {
            params,
            return_type,
            ..
        } => {
            let inner: Vec<String> = params.iter().map(render).collect();
            format!("fn({}) -> {}", inner.join(", "), render(return_type))
        }
        TypeExprKind::Boxed(inner) => format!("Box<{}>", render(inner)),
        TypeExprKind::ImplTrait(name) => format!("impl {name}"),
        TypeExprKind::DynTrait(name) => format!("dyn {name}"),
    }
}

/// Parse every embedded stdlib source once and index the declarations.
///
/// Sorted by file stem and first-wins, so the table — and any diagnostic that
/// quotes it — cannot depend on iteration order. A file the parser rejects is
/// skipped: its declarations are then simply unknown, which the caller treats as
/// "no declared type" rather than as a guess.
fn table() -> &'static HashMap<String, Declared> {
    static TABLE: OnceLock<HashMap<String, Declared>> = OnceLock::new();
    TABLE.get_or_init(|| {
        let mut map: HashMap<String, Declared> = HashMap::new();
        for (stem, source) in STDLIB_SOURCES {
            let (tokens, _errors) = crate::lexer::tokenize(source);
            let Ok(program) = crate::parser::Parser::parse(tokens) else {
                continue;
            };
            for item in &program.items {
                if let Item::Fn(f) = item {
                    if let Some((name, declared)) = Declared::from_fn(stem, f) {
                        map.entry(name).or_insert(declared);
                    }
                }
            }
        }
        map
    })
}

/// The declared result kind of `module.method`, as the stdlib's own `.tl`
/// files spell it.
///
/// `None` means no declaration was found for that name — an alias not used in
/// the declarations (`intel_ip` for `ip`), a method the `.tl` surface does not
/// document, or a file the parser rejected. The caller keeps the pre-existing
/// untyped pointer for those; inventing a kind would be the guess this module
/// exists to prevent.
pub fn declared_return(module: &str, method: &str) -> Option<RetKind> {
    let table = table();
    let exact = format!("{module}.{method}");
    if let Some(declared) = table.get(&exact) {
        return Some(declared.ret.clone());
    }
    // Case-insensitive module spelling: the same surface is written `Entity.x`
    // and `entity.x` in `stdlib/entity.tl`, and `Provenance.x` for
    // `provenance.x`. The *method* stays case-sensitive — it is a Rust symbol.
    let lowered = module.to_ascii_lowercase();
    if lowered != module {
        if let Some(declared) = table.get(&format!("{lowered}.{method}")) {
            return Some(declared.ret.clone());
        }
    }
    // Namespace aliases the router accepts (`stdlib::dispatch` folds
    // `intel_ip` into `ip`, `relayroom` into `relay_room`). They are call-site
    // spellings of the same module, so they must resolve to the same
    // declarations.
    for alias in ["intel_ip", "intel_api", "intel_traffic", "relayroom"] {
        if lowered == alias {
            let canonical = match alias {
                "intel_ip" => "ip",
                "intel_api" => "api",
                "intel_traffic" => "traffic",
                _ => "relay_room",
            };
            if let Some(declared) = table.get(&format!("{canonical}.{method}")) {
                return Some(declared.ret.clone());
            }
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The declarations must resolve for the modules the bridge actually
    /// lowers — otherwise a scalar result silently goes back to being a bare
    /// pointer, which is the defect this whole file is about.
    #[test]
    fn scalar_result_kinds_resolve() {
        assert_eq!(declared_return("finance", "roa"), Some(RetKind::Float));
        assert_eq!(declared_return("finance", "pv"), Some(RetKind::Float));
        assert_eq!(declared_return("geocode", "is_zip5"), Some(RetKind::Bool));
        assert_eq!(
            declared_return("decimal", "decimal_cmp"),
            Some(RetKind::Int)
        );
        assert_eq!(declared_return("math", "sqrt"), Some(RetKind::Float));
        assert_eq!(
            declared_return("api", "openapi_load"),
            Some(RetKind::Named("ApiInventory".to_string()))
        );
        assert_eq!(
            declared_return("entity", "name_similarity"),
            Some(RetKind::Float)
        );
    }

    /// A declaration with structure is not silently typed as a struct: it is
    /// `Opaque`, so the call site can refuse it by name.
    #[test]
    fn structural_results_are_opaque_not_named() {
        assert_eq!(
            declared_return("csv", "read"),
            Some(RetKind::Opaque("[][]String".to_string()))
        );
        assert_eq!(
            declared_return("env", "get"),
            Some(RetKind::Opaque("String?".to_string()))
        );
        assert_eq!(
            declared_return("db", "connect"),
            Some(RetKind::Opaque("Result<Connection>".to_string()))
        );
    }

    /// Aliases the router folds must resolve to the canonical declarations.
    #[test]
    fn router_aliases_resolve_to_the_canonical_module() {
        assert_eq!(
            declared_return("intel_ip", "lookup"),
            Some(RetKind::Named("AsnMatch".to_string()))
        );
    }

    /// No declaration, no invented type.
    #[test]
    fn an_undeclared_method_has_no_kind() {
        assert_eq!(declared_return("finance", "not_a_function"), None);
        assert_eq!(declared_return("not_a_module", "x"), None);
    }

    /// Every embedded file is measured: how many parse with the real parser and
    /// how many declarations reach the table. This is the "cost" half of the
    /// signature-source choice, as a number rather than a claim.
    #[test]
    fn every_embedded_file_parses_and_the_table_is_measured() {
        let mut files = 0usize;
        let mut parsed = 0usize;
        let mut rejected: Vec<&str> = Vec::new();
        for (stem, source) in STDLIB_SOURCES {
            files += 1;
            let (tokens, _errors) = crate::lexer::tokenize(source);
            if crate::parser::Parser::parse(tokens).is_ok() {
                parsed += 1;
            } else {
                rejected.push(stem);
            }
        }
        println!(
            "stdlib declarations: {files} embedded files, {parsed} parsed, \
             {} rejected {rejected:?}, {} indexed names",
            rejected.len(),
            table().len()
        );
        assert!(
            files >= 90,
            "expected the whole stdlib to be embedded, got {files}"
        );
        assert!(
            rejected.is_empty(),
            "a stdlib file the parser rejects loses its declarations silently: {rejected:?}"
        );
    }
}
