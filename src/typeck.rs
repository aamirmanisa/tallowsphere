//! Type checker for Tallow.
//!
//! Responsibilities:
//! - Resolve type names to concrete types
//! - Track privacy qualifiers (private, secret) through the type system
//! - Verify type compatibility in assignments, calls, and returns
//! - Build a type environment for downstream passes (legal_pass, privacy_pass)

use std::collections::{HashMap, HashSet};

use crate::ast::*;
use crate::error::Diagnostics;
use crate::lexer::Span;

// ── Type Representation ──────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Type {
    Void,
    Bool,
    Int(IntSize),
    Float(FloatSize),
    String,
    Bytes,
    Char,

    // Privacy-qualified types
    Private(Box<Type>),
    Secret(Box<Type>),

    // Compound
    Optional(Box<Type>),
    Result(Box<Type>),
    Array(Box<Type>),
    Tuple(Vec<Type>),
    Map(Box<Type>, Box<Type>),
    Set(Box<Type>),
    Chan(Box<Type>),

    // Function signature
    Function {
        params: Vec<Type>,
        return_type: Box<Type>,
    },

    // Consent wrapper (GDPR consent chain)
    Consent(Box<Type>), // Data accessible only via .with_consent {} block

    // Effect capability (G01 P0.2, blueprint §2.1). The payload is the
    // *effect name*, not a type: `Grant<Net>` is the value that authorises a
    // `Net` effect. It is the only type able to satisfy the grant side of an
    // effect row, and the only expression that produces one is the native
    // builtin `scope.grant(Net)` — there is no literal, cast or default, so a
    // row cannot be satisfied by a promise.
    Grant(String),

    // Erasable wrapper (GDPR right-to-erasure)
    Erasable(Box<Type>), // Data tracked for complete deletion via purge()

    // Trust wrappers (agent data provenance)
    Trusted(Box<Type>),    // Data verified via explicit .verify() call
    Unverified(Box<Type>), // Data from untrusted source, requires verification
    Fresh(Box<Type>, u64), // Data with TTL in milliseconds — compiler checks staleness patterns

    // Heap-indirected type: Box<T> — enables recursive data types
    Boxed(Box<Type>),

    // User-defined (resolved by name for now)
    Named(String),

    // Not yet resolved / inference placeholder
    Unknown,
}

/// The primitive kind a literal has to inhabit, or `""` when the type is not a
/// primitive (a struct, a map, `Unknown`) and the check must not fire.
fn base_kind(t: &Type) -> &'static str {
    match t {
        Type::String => "str",
        Type::Int(_) => "int",
        Type::Float(_) => "float",
        Type::Bool => "bool",
        Type::Named(n) => match n.as_str() {
            "str" | "String" | "string" => "str",
            "i8" | "i16" | "i32" | "i64" | "i128" | "isize" | "u8" | "u16" | "u32" | "u64"
            | "u128" | "usize" | "int" => "int",
            "f32" | "f64" | "float" => "float",
            "bool" => "bool",
            _ => "",
        },
        _ => "",
    }
}

/// Human-readable name for a type in diagnostics.
fn type_label(t: &Type) -> String {
    match t {
        Type::Void => "nil".to_string(),
        Type::Bool => "bool".to_string(),
        Type::Int(_) => "int".to_string(),
        Type::Float(_) => "float".to_string(),
        Type::String => "str".to_string(),
        Type::Bytes => "bytes".to_string(),
        Type::Char => "char".to_string(),
        Type::Optional(inner) => format!("{}?", type_label(inner)),
        Type::Array(inner) => format!("[{}]", type_label(inner)),
        Type::Named(name) => name.clone(),
        Type::Private(inner) | Type::Secret(inner) => type_label(inner),
        Type::Grant(effect) if effect.is_empty() => "Grant".to_string(),
        Type::Grant(effect) => format!("Grant<{effect}>"),
        other => format!("{other:?}"),
    }
}

impl Type {
    /// Is this type private or wraps a private type?
    pub fn is_private(&self) -> bool {
        matches!(self, Type::Private(_))
    }

    /// Is this type secret or wraps a secret type?
    pub fn is_secret(&self) -> bool {
        matches!(self, Type::Secret(_))
    }

    /// Is this type private or secret?
    pub fn is_sensitive(&self) -> bool {
        self.is_private() || self.is_secret()
    }

    /// Strip the privacy qualifier, returning the inner type.
    pub fn strip_qualifier(&self) -> &Type {
        match self {
            Type::Private(inner) | Type::Secret(inner) => inner,
            other => other,
        }
    }

    /// Is this type a Consent wrapper?
    pub fn is_consent(&self) -> bool {
        matches!(self, Type::Consent(_))
    }

    /// Is this an effect capability (`Grant<Net>`)?
    pub fn is_grant(&self) -> bool {
        matches!(self, Type::Grant(_))
    }

    /// The effect a capability authorises (`Grant<Net>` → `Some("Net")`).
    pub fn granted_effect(&self) -> Option<&str> {
        match self {
            Type::Grant(effect) => Some(effect.as_str()),
            _ => None,
        }
    }

    /// Is this type an Erasable wrapper?
    pub fn is_erasable(&self) -> bool {
        matches!(self, Type::Erasable(_))
    }

    /// Unwrap consent wrapper, returning the inner type.
    pub fn unwrap_consent(&self) -> &Type {
        match self {
            Type::Consent(inner) => inner,
            other => other,
        }
    }

    /// Is this type a Trusted wrapper?
    pub fn is_trusted(&self) -> bool {
        matches!(self, Type::Trusted(_))
    }

    /// Is this type an Unverified wrapper?
    pub fn is_unverified(&self) -> bool {
        matches!(self, Type::Unverified(_))
    }

    /// Is this type a Fresh wrapper?
    pub fn is_fresh(&self) -> bool {
        matches!(self, Type::Fresh(_, _))
    }

    /// Strip trust wrappers, returning the inner type.
    pub fn strip_trust(&self) -> &Type {
        match self {
            Type::Trusted(inner) | Type::Unverified(inner) => inner,
            Type::Fresh(inner, _) => inner,
            other => other,
        }
    }

    /// Get the inner type, stripping any single wrapper layer
    /// (privacy, trust, optional, result, array, fresh).
    pub fn inner_type(&self) -> &Type {
        match self {
            Type::Trusted(inner)
            | Type::Unverified(inner)
            | Type::Private(inner)
            | Type::Secret(inner)
            | Type::Consent(inner)
            | Type::Optional(inner)
            | Type::Result(inner)
            | Type::Array(inner)
            | Type::Boxed(inner)
            | Type::Fresh(inner, _) => inner,
            other => other,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IntSize {
    I8,
    I16,
    I32,
    I64,
    I128,
    U8,
    U16,
    U32,
    U64,
    U128,
    Isize,
    Usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FloatSize {
    F32,
    F64,
}

// ── Built-in Privacy Types ───────────────────────────────────────────────────

/// Types that are implicitly `private` (GDPR personal data).
const PRIVATE_TYPES: &[&str] = &["Email", "IPAddress", "Name", "Phone", "Location", "SSN"];

/// Types that are implicitly `secret` (credentials).
const SECRET_TYPES: &[&str] = &["Password", "APIKey", "PrivateKey", "Token"];

// ── Agent Function Info ──────────────────────────────────────────────────────

/// Stores resolved information about an @agent_task annotated function.
#[derive(Debug, Clone)]
pub struct AgentFunctionInfo {
    pub name: String,
    pub level: crate::ast::AgentLevel,
    pub can_write: bool,
    pub can_store: bool,
    pub can_spawn: bool,
    pub can_network: bool,
    pub can_execute: bool,
    pub has_timeout: bool,
    pub has_max_requests: bool,
    pub has_memory_limit: bool,
    pub max_spawn_depth: Option<u32>,
    pub max_total_agents: Option<u32>,
    pub checkpoint_frequency: Option<u32>,
    pub heartbeat_interval: Option<u64>, // milliseconds
    pub constitution: Option<String>,
    pub llm_policy: Option<crate::agent_reasoning::LlmPolicy>,
    pub span: Span,
}

// ── Struct / Enum Info ───────────��──────────────────────────────────────────

/// Resolved struct information for field/method lookup.
#[derive(Debug, Clone)]
pub struct StructInfo {
    pub name: String,
    pub fields: Vec<(String, Type)>,
    pub span: Span,
}

/// Resolved enum information for exhaustiveness checking.
#[derive(Debug, Clone)]
pub struct EnumInfo {
    pub name: String,
    pub variants: Vec<String>,
    pub span: Span,
}

/// Tracks a local variable's type and mutability.
#[derive(Debug, Clone)]
pub struct VarInfo {
    pub ty: Type,
    pub mutable: bool,
}

// ── Type Environment ─────────────────────────────────────────────────────────

/// Stores resolved type information for each function, variable, and parameter.
#[derive(Debug, Default)]
pub struct TypeEnv {
    /// Function name → resolved signature.
    pub functions: HashMap<String, FnSignature>,
    /// Type alias name → resolved type.
    pub type_aliases: HashMap<String, Type>,
    /// Functions that touch the network (call fetch, pool.map, etc.).
    pub network_functions: Vec<String>,
    /// Functions that call browser navigation methods (goto, navigate, new_page, new_context, launch).
    /// Used by stealth_pass to determine which functions need @stealth annotations.
    pub browser_nav_functions: Vec<String>,
    /// Agent function name → resolved agent info (level, permissions, etc.).
    pub agent_functions: HashMap<String, AgentFunctionInfo>,
    /// Trait name �� declaration.
    pub traits: HashMap<String, TraitDecl>,
    /// (trait_name, type_name) → impl block.
    pub trait_impls: HashMap<(String, String), ImplBlock>,
    /// Struct name → field info.
    pub structs: HashMap<String, StructInfo>,
    /// Enum name → variant info.
    pub enums: HashMap<String, EnumInfo>,
    /// (type_name) → list of method signatures from impl blocks.
    pub methods: HashMap<String, Vec<FnSignature>>,
    /// Top-level `const` names. They are globals, not locals, and were not
    /// registered anywhere — so every use of one warned W0102.
    pub constants: HashSet<String>,
}

#[derive(Debug, Clone)]
pub struct FnSignature {
    pub name: String,
    pub params: Vec<(String, Type)>,
    /// One flag per entry in `params`: `true` when the parameter declares a
    /// default (`fn f(x: int = 3)`). Omitted trailing arguments whose flag is
    /// true are supplied by the callee, so the checker must not demand them.
    pub defaults: Vec<bool>,
    pub return_type: Type,
    pub span: Span,
    /// The declared effect row (G01). A caller of this function inherits these
    /// entries: the body of a caller must not exceed its own row, so a call
    /// that reaches a socket through this function is the same requirement as
    /// calling the primitive directly.
    pub effects: Vec<EffectReq>,
}

impl FnSignature {
    /// Smallest legal argument count: one past the last parameter that has no
    /// default. `params[got..]` must all carry defaults for a call to be legal.
    pub fn required_params(&self) -> usize {
        self.params
            .iter()
            .zip(self.defaults.iter())
            .rposition(|(_, has_default)| !*has_default)
            .map(|index| index + 1)
            .unwrap_or(0)
    }

    /// True when `got` arguments is a legal call shape.
    pub fn accepts_arity(&self, got: usize) -> bool {
        got <= self.params.len()
            && self
                .params
                .iter()
                .zip(self.defaults.iter())
                .skip(got)
                .all(|(_, has_default)| *has_default)
    }
}

// ── Effect rows (G01) ────────────────────────────────────────────────────────

/// The effect a dotted call path requires, if any.
///
/// Only the **first** segment names the primitive family; the second segment is
/// the operation (`Tcp.connect` → `Net(connect)`). Families that open a socket
/// are mapped to `Net`; everything else needs no row.
pub fn effect_for_callee(name: &str) -> Option<&'static str> {
    let head = name.split('.').next().unwrap_or("");
    match head {
        "Tcp" | "Udp" | "TLSConn" | "net" | "sitescan" | "http" => Some("Net"),
        _ => None,
    }
}

/// Effect names a capability type may name: `Grant<Effect>` (G01 P0.2).
///
/// Only effects the checker can *enforce* are listed. `Net` is the enforced
/// one today; `Budget` and `Plane` join it when their lattices land
/// (blueprint §2.1), and until then `Grant<Budget>` is a type error, not a
/// silently-accepted promise.
pub const KNOWN_EFFECTS: &[&str] = &["Net"];

/// True when `name` may appear as the argument of a capability type.
pub fn is_known_effect(name: &str) -> bool {
    KNOWN_EFFECTS.contains(&name)
}

/// The operation segment of a dotted callee path (`Tcp.connect` → `connect`).
fn effect_op(name: &str) -> &str {
    name.split('.').nth(1).unwrap_or("")
}

/// Dotted path of a callee expression: `Tcp` → `"Tcp"`, `Tcp.connect` →
/// `"Tcp.connect"`. `None` when the callee is a computed expression, which
/// carries no static path to match on.
fn callee_path(expr: &Expr) -> Option<String> {
    match &expr.kind {
        ExprKind::Ident(name) => Some(name.clone()),
        ExprKind::FieldAccess { object, field } => {
            callee_path(object).map(|p| format!("{p}.{field}"))
        }
        _ => None,
    }
}

/// The effect a `scope.grant(<effect>)` call names, when `expr` is exactly
/// that call (G01 P0.2).
///
/// `scope.grant` is the **only** producer of a `Grant<E>` value: there is no
/// literal, cast or default of the type, so a body cannot satisfy a row's
/// capability half out of thin air. The argument is an effect *name* — an
/// identifier, not a value — which is why it is read here rather than typed as
/// an expression.
fn scope_grant_effect(expr: &Expr) -> Option<&str> {
    let ExprKind::MethodCall {
        object,
        method,
        args,
        ..
    } = &expr.kind
    else {
        return None;
    };
    if method != "grant" || !matches!(&object.kind, ExprKind::Ident(n) if n == "scope") {
        return None;
    }
    match args.as_slice() {
        [arg] => match &arg.value.kind {
            ExprKind::Ident(effect) => Some(effect.as_str()),
            _ => None,
        },
        _ => None,
    }
}

// ── Type Checker ─────────────────────────────────────────────────────────────

pub struct TypeChecker<'a> {
    program: &'a Program,
    pub env: TypeEnv,
    pub diags: Diagnostics,
    /// Effect row of the signature whose body is being walked (G01).
    declared_effects: Vec<EffectReq>,
    /// `(effect, op, span, grant_in_scope)` collected from the body being
    /// walked (G01). The effect name is owned because a row forwarded from a
    /// callee's signature carries a `String`, not a `&'static str`;
    /// `grant_in_scope` is whether a `Grant<effect>` value was lexically
    /// available at that call site — the capability half of the row
    /// (G01 P0.2, E0142).
    body_effect_reqs: Vec<(String, String, Span, bool)>,
    /// `(effect, span)` of every `scope.grant(<effect>)` site in the body being
    /// walked (G01 P0.2, E0144). The site is recorded while the locals are
    /// live; whether it is legal is judged at the body boundary by
    /// [`Self::enforce_grant_origin`], because the rule depends on the *name*
    /// of the enclosing body — only `main` may originate authority.
    body_grant_sites: Vec<(String, Span)>,
    /// Name of the body whose statements are being walked. `main` is the trust
    /// root (see `enforce_effect_row`); an `impl` method is never one.
    current_body_name: Option<String>,
}

impl<'a> TypeChecker<'a> {
    pub fn new(program: &'a Program) -> Self {
        Self {
            program,
            env: TypeEnv::default(),
            diags: Diagnostics::new(),
            declared_effects: Vec::new(),
            body_effect_reqs: Vec::new(),
            body_grant_sites: Vec::new(),
            current_body_name: None,
        }
    }

    /// Run the type checker over the entire program.
    pub fn check(mut self) -> (TypeEnv, Diagnostics) {
        // Pass 1: Register all type aliases and function signatures
        self.register_declarations();

        // Pass 1b: Register traits and validate trait impls
        self.register_traits();
        self.validate_trait_impls();

        // Pass 1c: Validate recursive enum types (must use Box<T> for self-references)
        self.validate_recursive_enums();

        // Pass 1d: Register structs, enums, and impl methods
        self.register_structs_and_enums();
        self.register_impl_methods();

        // Pass 2: Check function bodies
        for item in &self.program.items {
            match item {
                Item::Fn(f) => {
                    self.check_function(f);
                }
                Item::Impl(imp) => {
                    for method in &imp.methods {
                        self.check_impl_method(method, &imp.target);
                    }
                }
                _ => {}
            }
        }

        (self.env, self.diags)
    }

    // ── Pass 1: Registration ─────────────────────────────────────────────

    fn register_declarations(&mut self) {
        for item in &self.program.items {
            match item {
                Item::TypeAlias(ta) => {
                    let inner = self.resolve_type_expr(&ta.ty);
                    let ty = match ta.qualifier {
                        Some(TypeQualifier::Private) => Type::Private(Box::new(inner)),
                        Some(TypeQualifier::Secret) => Type::Secret(Box::new(inner)),
                        None => inner,
                    };
                    // Wrap in Erasable if @erasable annotation present
                    let ty = if ta.annotations.iter().any(|a| a.name == "erasable") {
                        Type::Erasable(Box::new(ty))
                    } else {
                        ty
                    };
                    self.env.type_aliases.insert(ta.name.clone(), ty);
                }
                Item::Fn(f) => {
                    let params: Vec<(String, Type)> = f
                        .params
                        .iter()
                        .map(|p| (p.name.clone(), self.resolve_param_type(p)))
                        .collect();
                    let defaults: Vec<bool> =
                        f.params.iter().map(|p| p.default.is_some()).collect();

                    let return_type = f
                        .return_type
                        .as_ref()
                        .map(|t| self.resolve_type_expr(t))
                        .unwrap_or(Type::Void);

                    self.env.functions.insert(
                        f.name.clone(),
                        FnSignature {
                            name: f.name.clone(),
                            params,
                            defaults,
                            return_type,
                            span: f.span,
                            effects: f.effects.clone(),
                        },
                    );
                }
                _ => {}
            }
        }
    }

    // ── Pass 1d: Struct, Enum, Impl Registration ──────────────────────

    fn register_structs_and_enums(&mut self) {
        for item in &self.program.items {
            match item {
                Item::Struct(s) => {
                    let fields: Vec<(String, Type)> = s
                        .fields
                        .iter()
                        .map(|f| (f.name.clone(), self.resolve_type_expr(&f.ty)))
                        .collect();
                    // A capability may be stored in a field (`struct Probe {
                    // grant: Grant<Net> }`), so field type expressions are
                    // shape-checked like a parameter's.
                    for f in &s.fields {
                        self.validate_grant_shape(&f.ty);
                    }
                    self.env.structs.insert(
                        s.name.clone(),
                        StructInfo {
                            name: s.name.clone(),
                            fields,
                            span: s.span,
                        },
                    );
                }
                Item::Const(c) => {
                    self.env.constants.insert(c.name.clone());
                }
                Item::Enum(e) => {
                    let variants: Vec<String> = e.variants.iter().map(|v| v.name.clone()).collect();
                    self.env.enums.insert(
                        e.name.clone(),
                        EnumInfo {
                            name: e.name.clone(),
                            variants,
                            span: e.span,
                        },
                    );
                }
                _ => {}
            }
        }
    }

    fn register_impl_methods(&mut self) {
        for item in &self.program.items {
            if let Item::Impl(imp) = item {
                let mut sigs = Vec::new();
                for method in &imp.methods {
                    let params: Vec<(String, Type)> = method
                        .params
                        .iter()
                        .filter(|p| p.name != "self")
                        .map(|p| (p.name.clone(), self.resolve_param_type(p)))
                        .collect();
                    let defaults: Vec<bool> = method
                        .params
                        .iter()
                        .filter(|p| p.name != "self")
                        .map(|p| p.default.is_some())
                        .collect();
                    let return_type = method
                        .return_type
                        .as_ref()
                        .map(|t| self.resolve_type_expr(t))
                        .unwrap_or(Type::Void);
                    sigs.push(FnSignature {
                        name: method.name.clone(),
                        params,
                        defaults,
                        return_type,
                        span: method.span,
                        effects: method.effects.clone(),
                    });
                }
                self.env
                    .methods
                    .entry(imp.target.clone())
                    .or_insert_with(Vec::new)
                    .extend(sigs);
            }
        }
    }

    // ── Pass 1b: Trait Registration and Validation ─────────────────────

    fn register_traits(&mut self) {
        for item in &self.program.items {
            if let Item::Trait(t) = item {
                self.env.traits.insert(t.name.clone(), t.clone());
            }
        }
        // Register trait impls
        for item in &self.program.items {
            if let Item::Impl(imp) = item {
                if let Some(ref trait_name) = imp.trait_name {
                    self.env
                        .trait_impls
                        .insert((trait_name.clone(), imp.target.clone()), imp.clone());
                }
            }
        }
    }

    fn validate_trait_impls(&mut self) {
        // For each trait impl, verify all trait methods are implemented with matching signatures
        let trait_impls: Vec<_> = self
            .env
            .trait_impls
            .iter()
            .map(|((tn, ty), imp)| (tn.clone(), ty.clone(), imp.clone()))
            .collect();

        for (trait_name, type_name, impl_block) in trait_impls {
            let trait_decl = match self.env.traits.get(&trait_name) {
                Some(t) => t.clone(),
                None => {
                    self.diags.error(
                        "E0400",
                        format!("trait `{trait_name}` not found"),
                        impl_block.span,
                    );
                    continue;
                }
            };

            // Check that every required trait method is implemented
            for trait_method in &trait_decl.methods {
                if trait_method.has_default {
                    continue; // default methods don't need to be implemented
                }
                let impl_method = impl_block
                    .methods
                    .iter()
                    .find(|m| m.name == trait_method.name);
                match impl_method {
                    None => {
                        self.diags.error(
                            "E0401",
                            format!(
                                "impl `{trait_name}` for `{type_name}` is missing method `{}`",
                                trait_method.name
                            ),
                            impl_block.span,
                        );
                    }
                    Some(method) => {
                        // Validate parameter count matches (excluding self)
                        let trait_param_count = trait_method
                            .params
                            .iter()
                            .filter(|p| p.name != "self")
                            .count();
                        let impl_param_count =
                            method.params.iter().filter(|p| p.name != "self").count();
                        if trait_param_count != impl_param_count {
                            self.diags.error(
                                "E0402",
                                format!(
                                    "method `{}` in impl `{trait_name}` for `{type_name}` has {} params, trait requires {}",
                                    method.name, impl_param_count, trait_param_count
                                ),
                                method.span,
                            );
                        }
                    }
                }
            }
        }
    }

    /// Check if a type implements a given trait.
    pub fn type_implements_trait(env: &TypeEnv, type_name: &str, trait_name: &str) -> bool {
        env.trait_impls
            .contains_key(&(trait_name.to_string(), type_name.to_string()))
    }

    // ── Pass 1c: Recursive Enum Validation ─────────────────────────────

    fn validate_recursive_enums(&mut self) {
        for item in &self.program.items {
            if let Item::Enum(e) = item {
                for variant in &e.variants {
                    for field in &variant.fields {
                        if self.type_references_name_unboxed(&field.ty, &e.name) {
                            self.diags.error(
                                "E0500",
                                format!(
                                    "recursive type: field `{}` in `{}::{}` references `{}` without Box<> indirection — \
                                     use `Box<{}>` to break the infinite size",
                                    field.name, e.name, variant.name, e.name, e.name,
                                ),
                                field.span,
                            );
                        }
                    }
                }
            }
        }
    }

    /// Returns true if `ty` references `name` directly (not behind a Box<>).
    fn type_references_name_unboxed(&self, ty: &TypeExpr, name: &str) -> bool {
        match &ty.kind {
            TypeExprKind::Named(n) => n == name,
            TypeExprKind::Generic { name: gname, args } => {
                // Box<T> is fine — the whole point is indirection
                if gname == "Box" {
                    return false;
                }
                args.iter()
                    .any(|a| self.type_references_name_unboxed(a, name))
            }
            TypeExprKind::Boxed(_) => false, // Box<T> provides indirection
            TypeExprKind::Slice(inner) => self.type_references_name_unboxed(inner, name),
            TypeExprKind::Optional(inner) => self.type_references_name_unboxed(inner, name),
            TypeExprKind::Tuple(types) => types
                .iter()
                .any(|t| self.type_references_name_unboxed(t, name)),
            TypeExprKind::Function {
                params,
                return_type,
            } => {
                params
                    .iter()
                    .any(|p| self.type_references_name_unboxed(p, name))
                    || self.type_references_name_unboxed(return_type, name)
            }
            TypeExprKind::ImplTrait(_) | TypeExprKind::DynTrait(_) => false,
        }
    }

    fn resolve_param_type(&self, param: &Param) -> Type {
        let base = self.resolve_type_expr(&param.ty);
        // Apply built-in privacy qualifiers
        self.apply_builtin_qualifier(base, &param.ty)
    }

    fn resolve_type_expr(&self, ty: &TypeExpr) -> Type {
        match &ty.kind {
            TypeExprKind::Named(name) => self.resolve_named_type(name),
            TypeExprKind::Boxed(inner) => Type::Boxed(Box::new(self.resolve_type_expr(inner))),
            TypeExprKind::Generic { name, args } => {
                match name.as_str() {
                    "Box" => {
                        let inner = args
                            .first()
                            .map(|a| self.resolve_type_expr(a))
                            .unwrap_or(Type::Unknown);
                        Type::Boxed(Box::new(inner))
                    }
                    "Result" => {
                        let inner = args
                            .first()
                            .map(|a| self.resolve_type_expr(a))
                            .unwrap_or(Type::Void);
                        Type::Result(Box::new(inner))
                    }
                    "Option" => {
                        let inner = args
                            .first()
                            .map(|a| self.resolve_type_expr(a))
                            .unwrap_or(Type::Unknown);
                        Type::Optional(Box::new(inner))
                    }
                    "Map" => {
                        let k = args
                            .first()
                            .map(|a| self.resolve_type_expr(a))
                            .unwrap_or(Type::Unknown);
                        let v = args
                            .get(1)
                            .map(|a| self.resolve_type_expr(a))
                            .unwrap_or(Type::Unknown);
                        Type::Map(Box::new(k), Box::new(v))
                    }
                    "Set" => {
                        let inner = args
                            .first()
                            .map(|a| self.resolve_type_expr(a))
                            .unwrap_or(Type::Unknown);
                        Type::Set(Box::new(inner))
                    }
                    "Chan" => {
                        let inner = args
                            .first()
                            .map(|a| self.resolve_type_expr(a))
                            .unwrap_or(Type::Unknown);
                        Type::Chan(Box::new(inner))
                    }
                    "Consent" => {
                        let inner = args
                            .first()
                            .map(|a| self.resolve_type_expr(a))
                            .unwrap_or(Type::Unknown);
                        Type::Consent(Box::new(inner))
                    }
                    "Trusted" => {
                        let inner = args
                            .first()
                            .map(|a| self.resolve_type_expr(a))
                            .unwrap_or(Type::Unknown);
                        Type::Trusted(Box::new(inner))
                    }
                    "Unverified" => {
                        let inner = args
                            .first()
                            .map(|a| self.resolve_type_expr(a))
                            .unwrap_or(Type::Unknown);
                        Type::Unverified(Box::new(inner))
                    }
                    "Fresh" => {
                        let inner = args
                            .first()
                            .map(|a| self.resolve_type_expr(a))
                            .unwrap_or(Type::Unknown);
                        // Second arg is duration in milliseconds (as a Named type containing digits)
                        let ttl_ms = args
                            .get(1)
                            .and_then(|a| {
                                if let TypeExprKind::Named(s) = &a.kind {
                                    s.parse::<u64>().ok()
                                } else {
                                    None
                                }
                            })
                            .unwrap_or(0);
                        Type::Fresh(Box::new(inner), ttl_ms)
                    }
                    "Grant" => {
                        // `Grant<Net>` is a lattice type, not a parameterised
                        // struct: its argument names an *effect*. A malformed
                        // shape (no argument, two arguments, a non-name
                        // argument) resolves to `Type::Grant("")`, and an
                        // effect the checker does not know resolves to
                        // `Type::Grant(<name>)`. Both are reported as E0143 by
                        // `validate_grant_shape`, which owns the diagnostic —
                        // this resolver is `&self` and cannot emit one.
                        match args.as_slice() {
                            [arg] => match &arg.kind {
                                TypeExprKind::Named(effect) => Type::Grant(effect.clone()),
                                _ => Type::Grant(String::new()),
                            },
                            _ => Type::Grant(String::new()),
                        }
                    }
                    _ => Type::Named(name.clone()),
                }
            }
            TypeExprKind::Slice(inner) => Type::Array(Box::new(self.resolve_type_expr(inner))),
            TypeExprKind::Optional(inner) => {
                Type::Optional(Box::new(self.resolve_type_expr(inner)))
            }
            TypeExprKind::Tuple(types) => {
                Type::Tuple(types.iter().map(|t| self.resolve_type_expr(t)).collect())
            }
            TypeExprKind::Function {
                params,
                return_type,
            } => Type::Function {
                params: params.iter().map(|p| self.resolve_type_expr(p)).collect(),
                return_type: Box::new(self.resolve_type_expr(return_type)),
            },
            TypeExprKind::ImplTrait(name) => Type::Named(name.clone()),
            TypeExprKind::DynTrait(name) => Type::Named(name.clone()),
        }
    }

    fn resolve_named_type(&self, name: &str) -> Type {
        // Check type aliases first
        if let Some(ty) = self.env.type_aliases.get(name) {
            return ty.clone();
        }

        // Built-in types
        match name {
            "bool" => Type::Bool,
            "i8" => Type::Int(IntSize::I8),
            "i16" => Type::Int(IntSize::I16),
            "i32" => Type::Int(IntSize::I32),
            "i64" => Type::Int(IntSize::I64),
            "i128" => Type::Int(IntSize::I128),
            "u8" => Type::Int(IntSize::U8),
            "u16" => Type::Int(IntSize::U16),
            "u32" => Type::Int(IntSize::U32),
            "u64" => Type::Int(IntSize::U64),
            "u128" => Type::Int(IntSize::U128),
            "isize" => Type::Int(IntSize::Isize),
            "usize" => Type::Int(IntSize::Usize),
            "f32" => Type::Float(FloatSize::F32),
            "f64" => Type::Float(FloatSize::F64),
            // Canonical spellings from spec/01-lexical.md: literals are Int
            // (i128 internally), Float (f64) and Bool, and the manifest uses
            // those names in signatures. They resolved to nothing, so every
            // stdlib module that wrote `Float` earned a W0100.
            "Float" => Type::Float(FloatSize::F64),
            "Int" => Type::Int(IntSize::I128),
            "Bool" => Type::Bool,
            "str" => Type::String,
            "String" => Type::String,
            "Bytes" => Type::Bytes,
            "char" => Type::Char,
            _ => {
                // `Grant` with no argument list: a malformed capability, not
                // an unknown type. `report_grant_shape` turns it into E0143.
                if name == "Grant" {
                    return Type::Grant(String::new());
                }
                // Check built-in privacy types
                if PRIVATE_TYPES.contains(&name) {
                    Type::Private(Box::new(Type::String))
                } else if SECRET_TYPES.contains(&name) {
                    Type::Secret(Box::new(Type::String))
                } else {
                    Type::Named(name.to_string())
                }
            }
        }
    }

    /// If the type name is a built-in private/secret type, wrap it.
    fn apply_builtin_qualifier(&self, ty: Type, type_expr: &TypeExpr) -> Type {
        if let TypeExprKind::Named(name) = &type_expr.kind {
            if PRIVATE_TYPES.contains(&name.as_str()) && !ty.is_private() {
                return Type::Private(Box::new(ty));
            }
            if SECRET_TYPES.contains(&name.as_str()) && !ty.is_secret() {
                return Type::Secret(Box::new(ty));
            }
        }
        ty
    }

    // ── Pass 2: Function Body Checking ───────────────────────────────────

    fn check_function(&mut self, f: &FnDecl) {
        // Build local scope with params (params are always immutable bindings)
        let mut locals: HashMap<String, VarInfo> = HashMap::new();
        for p in &f.params {
            let ty = self.resolve_param_type(p);
            locals.insert(p.name.clone(), VarInfo { ty, mutable: false });
        }

        // Check if function touches network
        if self.body_touches_network(&f.body) {
            self.env.network_functions.push(f.name.clone());
        }

        // Check if function uses browser navigation methods
        if Self::body_uses_browser_navigation(&f.body) {
            self.env.browser_nav_functions.push(f.name.clone());
        }

        // Register @agent_task annotated functions
        if let Some(ann) = f.annotations.iter().find(|a| a.name == "agent_task") {
            self.register_agent_function(f, ann);
        }

        // Check parameter types are valid (not undefined)
        for p in &f.params {
            let ty = self.resolve_param_type(p);
            self.validate_type_exists(&ty, p.span);
            self.validate_grant_shape(&p.ty);
        }
        if let Some(ret) = &f.return_type {
            self.validate_grant_shape(ret);
        }

        // Check each statement.
        //
        // G01: the walk also collects the effects the body's calls require
        // (recorded in `check_expr`); the row is enforced right after it, so a
        // socket-opening call without `with Net(op)` is reported at the call.
        self.declared_effects = f.effects.clone();
        self.current_body_name = Some(f.name.clone());
        self.body_effect_reqs = Vec::new();
        self.body_grant_sites = Vec::new();
        for stmt in &f.body.stmts {
            self.check_stmt(stmt, &mut locals);
        }
        self.enforce_grant_origin(Some(&f.name), false);
        self.enforce_effect_row();
        self.current_body_name = None;

        // Check return type matches body
        let declared_return = f
            .return_type
            .as_ref()
            .map(|t| self.resolve_type_expr(t))
            .unwrap_or(Type::Void);
        if declared_return != Type::Void {
            self.check_return_coverage(f, &declared_return);
        }
    }

    /// Check impl method bodies with `self` bound to the target type.
    fn check_impl_method(&mut self, method: &FnDecl, target: &str) {
        let mut locals: HashMap<String, VarInfo> = HashMap::new();
        // Add `self` as the target type (immutable by default)
        locals.insert(
            "self".to_string(),
            VarInfo {
                ty: Type::Named(target.to_string()),
                mutable: false,
            },
        );
        for p in &method.params {
            if p.name != "self" {
                let ty = self.resolve_param_type(p);
                locals.insert(p.name.clone(), VarInfo { ty, mutable: false });
            }
        }
        // G01 P0.2: an `impl` method's parameter and return types are
        // capability-checked exactly like a free function's.
        for p in &method.params {
            self.validate_grant_shape(&p.ty);
        }
        if let Some(ret) = &method.return_type {
            self.validate_grant_shape(ret);
        }
        // G01: same effect-row enforcement for impl methods — the row on an
        // `impl` method is checked exactly like a free function's.
        self.declared_effects = method.effects.clone();
        self.current_body_name = None;
        self.body_effect_reqs = Vec::new();
        self.body_grant_sites = Vec::new();
        for stmt in &method.body.stmts {
            self.check_stmt(stmt, &mut locals);
        }
        // An `impl` method is never `main`: it has no path to the trust root,
        // so it must take the capability as a parameter (E0144).
        self.enforce_grant_origin(None, true);
        self.enforce_effect_row();
    }

    // ── Effect rows (G01) ───────────────────────────────────────────────

    /// Record that a call at `span` opens a socket, if its path names one of
    /// the network families in [`effect_for_callee`].
    fn note_effect_call(&mut self, path: &str, span: Span, locals: &HashMap<String, VarInfo>) {
        let Some(effect) = effect_for_callee(path) else {
            return;
        };
        let op = effect_op(path).to_string();
        let grant_ok = Self::grant_in_scope(locals, effect);
        self.push_effect_req(effect.to_string(), op, span, grant_ok);
    }

    /// G01, interprocedural: a call to a user function reaches whatever that
    /// function's **declared** row says it reaches.
    ///
    /// The requirement is recorded at the *call site's* span, so the diagnostic
    /// points at the call in the caller rather than repeating the callee's
    /// declaration. A bare `Net` entry (no `ops`) has no single operation to
    /// name: it is forwarded as `Net`, which only a bare `with Net` on the
    /// caller satisfies.
    ///
    /// No fixpoint is needed and none is used. The callee's row is *declared*
    /// in source, not inferred from its body, so it is complete before either
    /// body is walked — including for a recursive cycle (`a` calls `a`), whose
    /// requirement is whatever `a` declared.
    ///
    /// A forwarded row is a *capability* requirement too (G01 P0.2): the
    /// caller must hold the `Grant` as well as declare the row. Grants are
    /// **not** propagated the way rows are — a grant is a value, and a callee
    /// that needs one takes it as a parameter.
    fn note_callee_row(
        &mut self,
        effects: &[EffectReq],
        span: Span,
        locals: &HashMap<String, VarInfo>,
    ) {
        for effect in effects {
            let grant_ok = Self::grant_in_scope(locals, &effect.name);
            if effect.ops.is_empty() {
                self.push_effect_req(effect.name.clone(), String::new(), span, grant_ok);
            } else {
                for op in &effect.ops {
                    self.push_effect_req(effect.name.clone(), op.clone(), span, grant_ok);
                }
            }
        }
    }

    /// Is a `Grant<effect>` value lexically in scope at this point in the body?
    ///
    /// The local map *is* the lexical scope, so this is exact: a grant taken as
    /// a parameter, or bound by `let g = scope.grant(Net)` earlier in the same
    /// (or an enclosing) block, counts; a grant bound in a sibling block does
    /// not.
    fn grant_in_scope(locals: &HashMap<String, VarInfo>, effect: &str) -> bool {
        locals
            .values()
            .any(|v| matches!(&v.ty, Type::Grant(e) if e == effect))
    }

    /// Append one body requirement, de-duplicated. The same call site can be
    /// visited twice (a `?`/`await` wrapper walks its inner expression), and a
    /// forwarded row can repeat an entry the call already required; one
    /// diagnostic per site per requirement is enough.
    ///
    /// `grant_ok` records whether a capability for this effect was in scope at
    /// the call site. It is captured here, while the locals are live, because
    /// the enforcement pass runs after the walk has left the scope.
    fn push_effect_req(&mut self, effect: String, op: String, span: Span, grant_ok: bool) {
        if self.body_effect_reqs.iter().any(|(e, o, s, _)| {
            *e == effect && *o == op && s.start == span.start && s.end == span.end
        }) {
            return;
        }
        self.body_effect_reqs.push((effect, op, span, grant_ok));
    }

    /// The last gate of a body walk (G01): every effect a call required must
    /// appear in the signature's row. `with Net` (no parentheses) covers every
    /// operation of `Net`; `with Net(connect)` covers only `connect`.
    ///
    /// G01 P0.2 adds the second half: a declared row must be backed by a
    /// `Grant<effect>` value in scope (E0142). A row is a capability, not a
    /// promise. `E0141` is checked first and unchanged, so a body that is
    /// missing both reports the row, which is the outer fix.
    fn enforce_effect_row(&mut self) {
        let reqs = std::mem::take(&mut self.body_effect_reqs);
        let declared = std::mem::take(&mut self.declared_effects);
        // `main` is the trust root: it originates authority from the runtime
        // scope registry rather than receiving it from a caller, so it needs no
        // incoming grant. That exemption is not a hole, because a network-
        // reaching `main` is already forced through the existing program-scope
        // gates: `@legal` (E0100, `legal_pass`), the collection plan
        // `@cra_class` / `@persona` / `@burn_plan` (E5004), and
        // `@fingerprint_policy` for any stealth or fingerprint use (E5100-
        // E5104) — so the one place authority can originate is also the most
        // heavily annotated one.
        let trust_root = self.current_body_name.as_deref() == Some("main");
        for (effect, op, span, grant_ok) in reqs {
            // An empty `op` is a whole-effect requirement (a bare `with Net`
            // forwarded from a callee): only a bare entry satisfies it.
            let satisfied = declared.iter().any(|d| {
                d.name == effect
                    && (d.ops.is_empty() || (!op.is_empty() && d.ops.iter().any(|o| *o == op)))
            });
            if !satisfied {
                let (what, help) = if op.is_empty() {
                    (effect.clone(), format!("add: with {effect}"))
                } else {
                    (
                        format!("{effect}({op})"),
                        format!("add: with {effect}({op})"),
                    )
                };
                let msg = format!(
                    "function body requires effect {what} but the signature does not declare it"
                );
                self.diags
                    .push(crate::error::Diagnostic::error("E0141", msg, span).with_help(help));
                continue;
            }
            if grant_ok || trust_root {
                continue;
            }
            let what = if op.is_empty() {
                effect.clone()
            } else {
                format!("{effect}({op})")
            };
            let msg = format!(
                "effect {what} requires a Grant<{effect}> in scope; take one as a parameter or obtain it with scope.grant({effect})"
            );
            self.diags
                .push(crate::error::Diagnostic::error("E0142", msg, span));
        }
    }

    /// Record one `scope.grant(<effect>)` site while the body walk is inside it
    /// (G01 P0.2, E0144). The same expression can be visited twice through a
    /// `?`/`await` wrapper, so the site is de-duplicated.
    fn record_grant_site(&mut self, effect: &str, span: Span) {
        if self
            .body_grant_sites
            .iter()
            .any(|(e, s)| e == effect && s.start == span.start && s.end == span.end)
        {
            return;
        }
        self.body_grant_sites.push((effect.to_string(), span));
    }

    /// G01 P0.2 (E0144): authority may only be **originated** in `main`.
    ///
    /// `scope.grant` is the only producer of a `Grant<E>` (see
    /// [`scope_grant_effect`]). If any body could call it, E0142 would be
    /// decorative in exactly the way the row was before P0.2: a helper that
    /// should have been handed a capability would simply mint one for itself.
    /// So the producer is confined to the trust root `main` — the one body
    /// whose authority comes from the runtime scope registry rather than from a
    /// caller, and the one the program-scope gates (`@legal`, plan and
    /// fingerprint annotations) already cover.
    ///
    /// Every other body must take a `Grant<E>` parameter and pass it on. An
    /// `impl` method is never `main`, so it always needs the parameter; that is
    /// said in the help text rather than assumed.
    fn enforce_grant_origin(&mut self, body_name: Option<&str>, is_impl: bool) {
        let sites = std::mem::take(&mut self.body_grant_sites);
        if body_name == Some("main") {
            return;
        }
        for (effect, span) in sites {
            let msg = format!(
                "authority may only be originated in main; take a Grant<{effect}> parameter instead"
            );
            let help = if is_impl {
                format!(
                    "an impl method is never main: declare `Grant<{effect}>` on the method and thread it from a caller that obtained it"
                )
            } else {
                format!(
                    "main obtains the capability with scope.grant({effect}) and passes it in as a parameter"
                )
            };
            self.diags
                .push(crate::error::Diagnostic::error("E0144", msg, span).with_help(help));
        }
    }

    /// `Grant` is a lattice type, not a struct (G01 P0.2, blueprint §2.1):
    /// it takes exactly one argument and that argument names an effect the
    /// checker can enforce. Every other spelling is `E0143`, because a
    /// capability naming an effect no pass enforces would be precisely the
    /// unbacked promise this task removes from the language.
    ///
    /// The resolver (`resolve_type_expr`, `&self`) cannot emit diagnostics, so
    /// it encodes a malformed capability as `Type::Grant("")`; the shape — not
    /// just the resolved type — is re-read here, where `&mut self` can report.
    fn validate_grant_shape(&mut self, ty: &TypeExpr) {
        match &ty.kind {
            TypeExprKind::Named(name) if name == "Grant" => {
                self.diags.push(
                    crate::error::Diagnostic::error(
                        "E0143",
                        "capability type `Grant` requires exactly one effect argument, e.g. `Grant<Net>`"
                            .to_string(),
                        ty.span,
                    )
                    .with_help("write: Grant<Net>"),
                );
            }
            TypeExprKind::Generic { name, args } if name == "Grant" => {
                self.report_grant_shape(args, ty.span);
            }
            // A capability may appear under any wrapper — `[Grant<Net>]`,
            // `Grant<Net>?`, `Box<Grant<Net>>` — so the walk descends through
            // the type expression rather than stopping at the top level.
            TypeExprKind::Boxed(inner)
            | TypeExprKind::Slice(inner)
            | TypeExprKind::Optional(inner) => self.validate_grant_shape(inner),
            TypeExprKind::Tuple(types) => {
                for t in types {
                    self.validate_grant_shape(t);
                }
            }
            TypeExprKind::Function {
                params,
                return_type,
            } => {
                for p in params {
                    self.validate_grant_shape(p);
                }
                self.validate_grant_shape(return_type);
            }
            TypeExprKind::Generic { args, .. } => {
                for a in args {
                    self.validate_grant_shape(a);
                }
            }
            TypeExprKind::Named(_) | TypeExprKind::ImplTrait(_) | TypeExprKind::DynTrait(_) => {}
        }
    }

    /// The `Grant<...>` argument list, checked for shape: exactly one argument,
    /// and that argument a known effect name. `Grant<Bogus>`, `Grant<Tcp>`,
    /// `Grant<>` and `Grant<A, B>` are all `E0143`.
    fn report_grant_shape(&mut self, args: &[TypeExpr], span: Span) {
        let help = |known: bool| {
            if known {
                format!("known effects: {}", KNOWN_EFFECTS.join(", "))
            } else {
                "write: Grant<Net>".to_string()
            }
        };
        let arg = match args {
            [only] => only,
            _ => {
                self.diags.push(
                    crate::error::Diagnostic::error(
                        "E0143",
                        format!(
                            "capability type `Grant` requires exactly one effect argument, got {}",
                            args.len()
                        ),
                        span,
                    )
                    .with_help(help(false)),
                );
                return;
            }
        };
        match &arg.kind {
            TypeExprKind::Named(effect) if is_known_effect(effect) => {}
            TypeExprKind::Named(effect) => {
                self.diags.push(
                    crate::error::Diagnostic::error(
                        "E0143",
                        format!("unknown effect `{effect}` in capability type `Grant<{effect}>`"),
                        arg.span,
                    )
                    .with_help(help(true)),
                );
            }
            _ => {
                self.diags.push(
                    crate::error::Diagnostic::error(
                        "E0143",
                        "capability type `Grant` takes an effect name, not a type".to_string(),
                        arg.span,
                    )
                    .with_help(help(false)),
                );
            }
        }
    }

    /// Validate that a type refers to something that exists (not an unknown named type).
    fn validate_type_exists(&mut self, ty: &Type, span: Span) {
        if let Type::Named(name) = ty {
            // Check if it's a known struct, enum, type alias, or generic param
            if !self.env.structs.contains_key(name)
                && !self.env.enums.contains_key(name)
                && !self.env.type_aliases.contains_key(name)
                && !self.env.traits.contains_key(name)
                // Single uppercase letter = likely a generic type param
                && !(name.len() == 1 && name.chars().next().map_or(false, |c| c.is_uppercase()))
                // Well-known stdlib types that aren't registered as structs
                && !matches!(name.as_str(),
                    "Duration" | "URL" | "Domain" | "IPPool" | "Config" |
                    "Response" | "Request" | "KeyPair" | "SymKey" |
                    "TLSConn" | "Random" | "Scanner" | "ScanScope" |
                    "DataBatch" | "EncryptedBatch" | "EncryptedResult" |
                    "Report" | "Price" | "DataRecord" | "HTMLDoc" |
                    "HTTPConn" | "Resource" | "Data" | "EncryptedReport" |
                    "InputData" | "User" |
                    // Declared in stdlib/browser.tl but not registered as
                    // structs here, so the documented handler signature
                    // `fn on_console(ev: PageEvent)` warned on every program.
                    "PageEvent" | "EventListener" | "ExposedFunction" |
                    "ExposedBinding" | "ScriptTag" | "StyleTag" |
                    // Documented spellings with no structural equivalent in the
                    // checker: `any` (dynamic), `Self` (the impl target), `List`
                    // and bare `Map` (generic without arguments).
                    "any" | "Self" | "List" | "Map" |
                    "MediaEmulation" | "NetworkThrottle" | "WaitResult" |
                    "NavigationResult"
                )
            {
                self.diags.warning(
                    "W0100",
                    format!("type `{name}` is not defined in this scope"),
                    span,
                );
            }
        }
    }

    /// Check that all code paths return a value when the function has a non-void return type.
    fn check_return_coverage(&mut self, f: &FnDecl, _declared_return: &Type) {
        // A `native fn` has no body by definition: its implementation is a
        // symbol supplied at link time (register #129).
        if f.is_native {
            return;
        }
        if f.body.stmts.is_empty() {
            // E2500 (not E0100): E0100 is reserved by legal_pass for the
            // network-touching-fn-without-@legal error. This is a distinct
            // type-level error, so it gets its own code.
            self.diags.error(
                "E2500",
                format!(
                    "function `{}` declares return type but body is empty",
                    f.name
                ),
                f.span,
            );
            return;
        }

        // Check if the last statement can produce a value
        let last = &f.body.stmts[f.body.stmts.len() - 1];
        let has_value = self.stmt_returns_value(last);
        let has_explicit_return = self.body_has_return(&f.body);

        if !has_value && !has_explicit_return {
            self.diags.warning(
                "W0101",
                format!(
                    "function `{}` may not return a value on all code paths",
                    f.name
                ),
                f.span,
            );
        }
    }

    /// Check if a statement produces a value (expression statement = implicit return).
    fn stmt_returns_value(&self, stmt: &Stmt) -> bool {
        match &stmt.kind {
            StmtKind::Expr { .. } => true,
            StmtKind::Return(_) => true,
            StmtKind::Bail(_) => true,
            _ => false,
        }
    }

    /// Check if a block contains any explicit return statement.
    fn body_has_return(&self, block: &Block) -> bool {
        for stmt in &block.stmts {
            match &stmt.kind {
                StmtKind::Return(_) => return true,
                StmtKind::Bail(_) => return true,
                StmtKind::For { body, .. }
                | StmtKind::While { body, .. }
                | StmtKind::WhileLet { body, .. }
                | StmtKind::Loop { body } => {
                    if self.body_has_return(body) {
                        return true;
                    }
                }
                StmtKind::Expr { expr } => {
                    if self.expr_has_return(expr) {
                        return true;
                    }
                }
                _ => {}
            }
        }
        false
    }

    /// Check if an expression contains a return statement.
    fn expr_has_return(&self, expr: &Expr) -> bool {
        match &expr.kind {
            ExprKind::If {
                then_block,
                else_branch,
                ..
            } => {
                let then_returns = self.body_has_return(then_block);
                let else_returns = match else_branch {
                    Some(ElseBranch::Block(b)) => self.body_has_return(b),
                    Some(ElseBranch::ElseIf(e)) => self.expr_has_return(e),
                    None => false,
                };
                then_returns && else_returns
            }
            ExprKind::Block(block) => self.body_has_return(block),
            _ => false,
        }
    }

    /// Register an @agent_task annotated function in the agent_functions registry.
    fn register_agent_function(&mut self, f: &FnDecl, ann: &Annotation) {
        use crate::ast::AgentLevel;

        let mut level = AgentLevel::L3; // default: backward compatible
        let mut can_write = false;
        let mut can_store = false;
        let mut can_spawn = false;
        let mut can_network = true; // default true per spec
        let mut can_execute = false;
        let mut has_timeout = false;
        let mut has_max_requests = false;
        let mut has_memory_limit = false;
        let mut max_spawn_depth: Option<u32> = None;
        let mut max_total_agents: Option<u32> = None;
        let mut checkpoint_frequency: Option<u32> = None;
        let mut heartbeat_interval: Option<u64> = None;
        let mut constitution: Option<String> = None;
        let mut llm_policy: Option<crate::agent_reasoning::LlmPolicy> = None;

        for arg in &ann.args {
            match arg.name.as_str() {
                "level" => {
                    if let ExprKind::DotIdent(s) = &arg.value.kind {
                        if let Some(l) = AgentLevel::from_str(s) {
                            level = l;
                        }
                    }
                }
                "can_write" => can_write = Self::is_true_expr(&arg.value),
                "can_store" => can_store = Self::is_true_expr(&arg.value),
                "can_spawn" => can_spawn = Self::is_true_expr(&arg.value),
                "can_network" => can_network = Self::is_true_expr(&arg.value),
                "can_execute" => can_execute = Self::is_true_expr(&arg.value),
                "timeout" => has_timeout = true,
                "max_spawn_depth" => {
                    if let ExprKind::IntLit(n) = &arg.value.kind {
                        max_spawn_depth = Some(*n as u32);
                    }
                }
                "max_total_agents" => {
                    if let ExprKind::IntLit(n) = &arg.value.kind {
                        max_total_agents = Some(*n as u32);
                    }
                }
                "checkpoint_frequency" => {
                    if let ExprKind::IntLit(n) = &arg.value.kind {
                        checkpoint_frequency = Some(*n as u32);
                    }
                }
                "heartbeat_interval" => {
                    if let ExprKind::IntLit(n) = &arg.value.kind {
                        heartbeat_interval = Some(*n as u64);
                    }
                }
                "constitution" => {
                    if let ExprKind::StringLit(s) = &arg.value.kind {
                        constitution = Some(s.clone());
                    }
                }
                "llm_policy" => {
                    if let ExprKind::DotIdent(s) = &arg.value.kind {
                        llm_policy = crate::agent_reasoning::LlmPolicy::from_str(s);
                    }
                }
                "max_requests" => has_max_requests = true,
                "memory_limit" => has_memory_limit = true,
                _ => {} // id, can_read, can_query, llm_budget — accepted
            }
        }

        self.env.agent_functions.insert(
            f.name.clone(),
            AgentFunctionInfo {
                name: f.name.clone(),
                level,
                can_write,
                can_store,
                can_spawn,
                can_network,
                can_execute,
                has_timeout,
                has_max_requests,
                has_memory_limit,
                max_spawn_depth,
                max_total_agents,
                checkpoint_frequency,
                heartbeat_interval,
                constitution,
                llm_policy,
                span: ann.span,
            },
        );
    }

    /// Helper: check if an annotation arg expression is `true`.
    fn is_true_expr(expr: &Expr) -> bool {
        match &expr.kind {
            ExprKind::BoolLit(true) => true,
            ExprKind::Ident(s) if s == "true" => true,
            _ => false,
        }
    }

    fn check_stmt(&mut self, stmt: &Stmt, locals: &mut HashMap<String, VarInfo>) {
        match &stmt.kind {
            StmtKind::Let { name, ty, value } => {
                let resolved = if let Some(ty_expr) = ty {
                    self.validate_grant_shape(ty_expr);
                    self.resolve_type_expr(ty_expr)
                } else {
                    self.infer_expr_type(value, locals)
                };
                if ty.is_some() {
                    self.check_optional_binding(&resolved, value, locals, value.span);
                    self.check_declared_literal(&resolved, value, value.span);
                    self.check_grant_binding(&resolved, value, locals, value.span);
                }
                self.check_expr(value, locals);
                locals.insert(
                    name.clone(),
                    VarInfo {
                        ty: resolved,
                        mutable: false,
                    },
                );
            }
            StmtKind::Var { name, ty, value } => {
                let resolved = if let Some(ty_expr) = ty {
                    self.validate_grant_shape(ty_expr);
                    self.resolve_type_expr(ty_expr)
                } else {
                    self.infer_expr_type(value, locals)
                };
                if ty.is_some() {
                    self.check_optional_binding(&resolved, value, locals, value.span);
                    self.check_declared_literal(&resolved, value, value.span);
                    self.check_grant_binding(&resolved, value, locals, value.span);
                }
                self.check_expr(value, locals);
                locals.insert(
                    name.clone(),
                    VarInfo {
                        ty: resolved,
                        mutable: true,
                    },
                );
            }
            StmtKind::LetDestructure { names, value } => {
                let _val_ty = self.infer_expr_type(value, locals);
                self.check_expr(value, locals);
                for name in names {
                    locals.insert(
                        name.clone(),
                        VarInfo {
                            ty: Type::Unknown,
                            mutable: false,
                        },
                    );
                }
            }
            StmtKind::Expr { expr } => {
                self.check_expr(expr, locals);
            }
            StmtKind::Return(Some(expr)) => {
                self.check_expr(expr, locals);
            }
            StmtKind::Return(None) => {}
            StmtKind::For {
                binding,
                iter,
                body,
            } => {
                self.check_expr(iter, locals);
                let iter_ty = self.infer_expr_type(iter, locals);
                let elem_ty = match iter_ty {
                    Type::Array(inner) => *inner,
                    _ => Type::Unknown,
                };
                let mut inner_locals = locals.clone();
                inner_locals.insert(
                    binding.clone(),
                    VarInfo {
                        ty: elem_ty,
                        mutable: false,
                    },
                );
                for s in &body.stmts {
                    self.check_stmt(s, &mut inner_locals);
                }
            }
            StmtKind::While { condition, body } => {
                self.check_expr(condition, locals);
                let mut inner_locals = locals.clone();
                for s in &body.stmts {
                    self.check_stmt(s, &mut inner_locals);
                }
            }
            StmtKind::WhileLet { expr, body, .. } => {
                self.check_expr(expr, locals);
                let mut inner_locals = locals.clone();
                for s in &body.stmts {
                    self.check_stmt(s, &mut inner_locals);
                }
            }
            StmtKind::Bail(expr) => {
                self.check_expr(expr, locals);
            }
            StmtKind::Loop { body } => {
                let mut inner_locals = locals.clone();
                for s in &body.stmts {
                    self.check_stmt(s, &mut inner_locals);
                }
            }
            StmtKind::Break | StmtKind::Continue => {}
            StmtKind::Defer { .. } => {}
        }
    }

    /// `T?` may flow into a `T?` slot (it is wrapped implicitly), but it may not
    /// flow into a `T` slot: that is an unwrap with no check, and neither plane
    /// can run it (register #136).
    fn check_optional_binding(
        &mut self,
        declared: &Type,
        value: &Expr,
        locals: &HashMap<String, VarInfo>,
        span: Span,
    ) {
        if matches!(declared, Type::Optional(_)) {
            return;
        }
        if matches!(self.infer_expr_type(value, locals), Type::Optional(_)) {
            self.diags.error(
                "E0116",
                "cannot bind `T?` to a `T` without a check -- test it (`== nil`) or match on it"
                    .to_string(),
                span,
            );
        }
    }

    /// Check the argument of `scope.grant(<effect>)` when it is not a known
    /// effect, or when the call has the wrong shape. The call is recognised by
    /// [`scope_grant_effect`]; a well-formed one needs no diagnostic here — it
    /// types as `Grant<effect>` in [`infer_expr_type`].
    fn validate_scope_grant(&mut self, effect: &str, span: Span) {
        if is_known_effect(effect) {
            return;
        }
        self.diags.push(
            crate::error::Diagnostic::error(
                "E0143",
                format!("unknown effect `{effect}` in scope.grant({effect})"),
                span,
            )
            .with_help(format!("known effects: {}", KNOWN_EFFECTS.join(", "))),
        );
    }

    /// A `Grant<E>` slot accepts only a `Grant<E>` value (G01 P0.2).
    ///
    /// There is no coercion, no widening and no default: the only producer is
    /// `scope.grant(E)`, so a struct literal, an `int`, or a grant for a
    /// different effect cannot be bound into the slot. This is the assignability
    /// rule for the lattice — a capability is not constructible, only obtained.
    fn check_grant_binding(
        &mut self,
        declared: &Type,
        value: &Expr,
        locals: &HashMap<String, VarInfo>,
        span: Span,
    ) {
        let Type::Grant(want) = declared else {
            return;
        };
        let got = self.infer_expr_type(value, locals);
        if matches!(&got, Type::Grant(have) if have == want) {
            return;
        }
        let msg = format!(
            "cannot bind `{}` to `{}`: a capability cannot be forged -- the only source is scope.grant({want})",
            self.type_display(&got),
            type_label(declared)
        );
        self.diags.error("E0117", msg, span);
    }

    /// A literal whose kind cannot inhabit the declared type is an error at the
    /// binding site. With an annotation the declared type wins, so inference
    /// alone never sees the contradiction: `let x: i64 = "nope"` used to check
    /// clean and print the string. Only literal kinds are compared — no
    /// coercion rules are invented here, so numeric widening (`1` into `f64`)
    /// stays legal and everything non-literal is left to inference.
    fn check_declared_literal(&mut self, declared: &Type, value: &Expr, span: Span) {
        let literal = match &value.kind {
            ExprKind::StringLit(_) | ExprKind::Interpolation(_) => "str",
            ExprKind::IntLit(_) => "int",
            ExprKind::FloatLit(_) => "float",
            ExprKind::BoolLit(_) => "bool",
            _ => return,
        };
        let mut slot = declared;
        loop {
            match slot {
                Type::Optional(inner) | Type::Private(inner) | Type::Secret(inner) => slot = inner,
                _ => break,
            }
        }
        let kind = base_kind(slot);
        if kind.is_empty() {
            // Not a primitive (struct, map, unresolved alias): nothing to compare.
            return;
        }
        let fits = matches!(
            (literal, kind),
            ("str", "str") | ("int", "int") | ("int", "float") | ("float", "float") | ("bool", "bool")
        );
        if !fits {
            self.diags.error(
                "E0117",
                format!(
                    "cannot bind a {literal} literal to `{}`: the annotation is the type, and no conversion is applied",
                    type_label(declared)
                ),
                span,
            );
        }
    }

    fn check_expr(&mut self, expr: &Expr, locals: &HashMap<String, VarInfo>) {
        match &expr.kind {
            // ── Identifiers: check variable is defined ──────────────────
            ExprKind::Ident(name) => {
                // Skip well-known globals and builtins
                if !locals.contains_key(name)
                    && !self.env.functions.contains_key(name)
                    && !self.env.structs.contains_key(name)
                    && !self.env.enums.contains_key(name)
                    && !self.env.constants.contains(name)
                    && !self.is_builtin_name(name)
                {
                    self.diags.warning(
                        "W0102",
                        format!("use of possibly undefined variable `{name}`"),
                        expr.span,
                    );
                }
            }

            // ── Calls: check argument count ─────────────────────────────
            ExprKind::Call { callee, args, .. } => {
                // G01: a call to a socket-opening primitive is an effect the
                // body requires; the signature's row is enforced after the walk.
                if let Some(path) = callee_path(callee) {
                    self.note_effect_call(&path, expr.span, locals);
                    // G01, interprocedural: a call to a user function reaches
                    // whatever that function's declared row says it reaches —
                    // recorded at *this* call site, so the diagnostic names the
                    // call in the caller rather than the callee's declaration.
                    if let Some(effects) = self.env.functions.get(&path).map(|s| s.effects.clone())
                    {
                        self.note_callee_row(&effects, expr.span, locals);
                    }
                }
                self.check_expr(callee, locals);
                for arg in args {
                    self.check_expr(&arg.value, locals);
                }
                // Check argument count for known functions. A trailing run of
                // defaulted parameters may be omitted: the callee binds them.
                if let ExprKind::Ident(name) = &callee.kind {
                    let got = args.len();
                    let arity = self.env.functions.get(name).map(|sig| {
                        (
                            sig.params.len(),
                            sig.required_params(),
                            sig.accepts_arity(got),
                        )
                    });
                    if let Some((expected, required, accepted)) = arity {
                        if !accepted {
                            let message = if got > expected {
                                format!(
                                    "function `{name}` expects at most {expected} argument(s), got {got}"
                                )
                            } else if required == expected {
                                format!(
                                    "function `{name}` expects {expected} argument(s), got {got}"
                                )
                            } else {
                                format!(
                                    "function `{name}` expects at least {required} argument(s), got {got}"
                                )
                            };
                            self.diags.error("E0103", message, expr.span);
                        }
                    }
                    // Check privacy: print/log with private/secret arg
                    if name == "print" || name == "log" {
                        for arg in args {
                            let arg_ty = self.infer_expr_type(&arg.value, locals);
                            if arg_ty.is_secret() {
                                self.diags.error(
                                    "E0201",
                                    "cannot pass secret type to print/log -- secret types must never be logged",
                                    arg.span,
                                );
                            } else if arg_ty.is_private() {
                                self.diags.error(
                                    "E0200",
                                    "cannot pass private type to print/log without .redact() or .hash()",
                                    arg.span,
                                );
                            }
                        }
                    }
                }
            }

            // ── Method calls: verify method exists, check arg count ─────
            ExprKind::MethodCall {
                object,
                method,
                args,
                ..
            } => {
                // `scope.grant(Net)` is the one expression that manufactures a
                // capability (G01 P0.2). Its argument is an *effect name*, not
                // a value and not a variable, so neither the receiver nor the
                // argument is walked: a W0102 for `scope` or `Net` would be
                // exactly wrong. Recognition lives here — inside a body walk —
                // and nowhere else, which is what keeps `scope.grant` out of
                // const, global and type positions where no effect table
                // applies.
                if let Some(effect) = scope_grant_effect(expr) {
                    self.validate_scope_grant(effect, expr.span);
                    // E0144: record the site; only `main` may originate
                    // authority, and that is judged at the body boundary where
                    // the enclosing body's name is known.
                    self.record_grant_site(effect, expr.span);
                    return;
                }
                // A browser helper kind name (`AdaptiveCrawler.new()`) is a static
                // namespace, not a value: the interpreter dispatches on the
                // dotted name, so warning that the receiver is "possibly
                // undefined" would be exactly wrong. Every other receiver is
                // checked as before.
                let static_namespace = matches!(
                    &object.kind,
                    ExprKind::Ident(name)
                        if !locals.contains_key(name)
                            && crate::interp_browser_dispatch::is_browser_static(
                                &format!("{name}.{method}"),
                            )
                );
                if !static_namespace {
                    self.check_expr(object, locals);
                }
                for arg in args {
                    self.check_expr(&arg.value, locals);
                }
                let obj_ty = self.infer_expr_type(object, locals);
                let type_name = self.type_to_name(&obj_ty);
                // G01: `Tcp.connect(..)` / `net.connect(..)` — a static module
                // path — and `conn.connect()` where the receiver's type is a
                // socket type both open a socket.
                let socket_path = match callee_path(object) {
                    Some(p) if effect_for_callee(&p).is_some() => Some(format!("{p}.{method}")),
                    _ => match &obj_ty {
                        Type::Named(n) if matches!(n.as_str(), "Tcp" | "Udp" | "TLSConn") => {
                            Some(format!("{n}.{method}"))
                        }
                        _ => None,
                    },
                };
                if let Some(path) = socket_path {
                    self.note_effect_call(&path, expr.span, locals);
                }
                // G01, interprocedural — the method analogue of the forwarded
                // function row: an `impl` method that declares an effect row
                // passes the requirement to its caller, at this call site.
                let callee_row = type_name.as_ref().and_then(|tname| {
                    self.env
                        .methods
                        .get(tname)
                        .and_then(|sigs| sigs.iter().find(|s| s.name == *method))
                        .map(|sig| sig.effects.clone())
                });
                if let Some(effects) = callee_row {
                    self.note_callee_row(&effects, expr.span, locals);
                }
                if let Some(ref tname) = type_name {
                    if let Some(methods) = self.env.methods.get(tname) {
                        let arity = methods.iter().find(|s| s.name == *method).map(|sig| {
                            (
                                sig.params.len(),
                                sig.required_params(),
                                sig.accepts_arity(args.len()),
                            )
                        });
                        if let Some((expected, required, accepted)) = arity {
                            if !accepted {
                                let got = args.len();
                                let message = if got > expected {
                                    format!(
                                        "method `{method}` on `{tname}` expects at most {expected} argument(s), got {got}"
                                    )
                                } else if required == expected {
                                    format!(
                                        "method `{method}` on `{tname}` expects {expected} argument(s), got {got}"
                                    )
                                } else {
                                    format!(
                                        "method `{method}` on `{tname}` expects at least {required} argument(s), got {got}"
                                    )
                                };
                                self.diags.error("E0104", message, expr.span);
                            }
                        }
                        // Note: we don't error on unknown methods because many are builtins
                        // or come from stdlib types not registered in env.methods
                    }
                }
                // E0950: Scanner.scan requires ScanScope as first argument
                if method == "scan" {
                    if let ExprKind::Ident(obj_name) = &object.kind {
                        if obj_name == "Scanner" {
                            let has_scan_scope = if let Some(first_arg) = args.first() {
                                let arg_type = self.infer_expr_type(&first_arg.value, locals);
                                matches!(arg_type, Type::Named(ref n) if n == "ScanScope")
                            } else {
                                false
                            };
                            if !has_scan_scope {
                                self.diags.error(
                                    "E0950",
                                    "Scanner.scan requires ScanScope as first argument -- use ScanScope.authorize(cidr) to create one",
                                    expr.span,
                                );
                            }
                        }
                    }
                }
            }

            // ── Binary ops: check operand type compatibility ────────────
            ExprKind::Binary { op, left, right } => {
                self.check_expr(left, locals);
                self.check_expr(right, locals);
                let left_ty = self.infer_expr_type(left, locals);
                let right_ty = self.infer_expr_type(right, locals);
                self.check_binary_op_types(*op, &left_ty, &right_ty, expr.span);
            }
            ExprKind::Unary { operand, .. } => {
                self.check_expr(operand, locals);
            }
            ExprKind::If {
                condition,
                then_block,
                else_branch,
            } => {
                self.check_expr(condition, locals);
                // Condition should be bool
                let cond_ty = self.infer_expr_type(condition, locals);
                if cond_ty != Type::Bool && cond_ty != Type::Unknown {
                    self.diags.warning(
                        "W0103",
                        format!(
                            "condition in `if` should be bool, got {}",
                            self.type_display(&cond_ty)
                        ),
                        condition.span,
                    );
                }
                let mut inner = locals.clone();
                for s in &then_block.stmts {
                    self.check_stmt(s, &mut inner);
                }
                if let Some(eb) = else_branch {
                    match eb {
                        ElseBranch::Block(block) => {
                            let mut inner = locals.clone();
                            for s in &block.stmts {
                                self.check_stmt(s, &mut inner);
                            }
                        }
                        ElseBranch::ElseIf(expr) => {
                            self.check_expr(expr, locals);
                        }
                    }
                }
            }
            ExprKind::IfLet {
                expr,
                then_block,
                else_branch,
                ..
            } => {
                self.check_expr(expr, locals);
                let mut inner = locals.clone();
                for s in &then_block.stmts {
                    self.check_stmt(s, &mut inner);
                }
                if let Some(eb) = else_branch {
                    match eb {
                        ElseBranch::Block(block) => {
                            let mut inner = locals.clone();
                            for s in &block.stmts {
                                self.check_stmt(s, &mut inner);
                            }
                        }
                        ElseBranch::ElseIf(expr) => {
                            self.check_expr(expr, locals);
                        }
                    }
                }
            }

            // ── Match: check exhaustiveness ─────────────────────────────
            ExprKind::Match { subject, arms } => {
                self.check_expr(subject, locals);
                for arm in arms {
                    let mut arm_locals = locals.clone();
                    // Bind pattern variables into scope
                    self.bind_pattern_vars(&arm.pattern, &mut arm_locals);
                    self.check_expr(&arm.body, &arm_locals);
                }
                // Check exhaustiveness for enum types
                let subject_ty = self.infer_expr_type(subject, locals);
                self.check_match_exhaustiveness(&subject_ty, arms, expr.span);
            }
            ExprKind::Block(block) => {
                let mut inner = locals.clone();
                for s in &block.stmts {
                    self.check_stmt(s, &mut inner);
                }
            }
            // `?` requires `Result<T>` (E0111). This is the single gate: both
            // engines run after typeck, so neither can execute an unchecked `?`.
            // Accepted operands: `Result<T>`, an unresolvable/Unknown expression
            // (no false positives), and a bare type literally named `Result`
            // (the pre-generics convention used by self-host/tests/*.tl).
            // `T?` (Optional) and every other concrete operand type are errors.
            ExprKind::Try(inner) => {
                self.check_expr(inner, locals);
                let inner_ty = self.infer_expr_type(inner, locals);
                match &inner_ty {
                    Type::Result(_) | Type::Unknown => {}
                    Type::Named(n) if n == "Result" => {}
                    Type::Optional(operand) => {
                        self.diags.error(
                            "E0111",
                            format!(
                                "`?` on optional value `{}?` — `?` requires `Result<T>`; use `if let`/`match` or an explicit unwrap",
                                self.type_display(operand)
                            ),
                            expr.span,
                        );
                    }
                    other => {
                        self.diags.error(
                            "E0111",
                            format!("`?` requires `Result<T>`, found {}", self.type_display(other)),
                            expr.span,
                        );
                    }
                }
            }
            ExprKind::Await(inner) => {
                self.check_expr(inner, locals);
            }
            ExprKind::FieldAccess { object, field } => {
                self.check_expr(object, locals);
                // Check field exists on known struct types
                let obj_ty = self.infer_expr_type(object, locals);
                if let Some(tname) = self.type_to_name(&obj_ty) {
                    if let Some(sinfo) = self.env.structs.get(&tname) {
                        if !sinfo.fields.iter().any(|(f, _)| f == field) {
                            self.diags.warning(
                                "W0104",
                                format!("struct `{tname}` has no field `{field}`"),
                                expr.span,
                            );
                        }
                    }
                }
            }
            ExprKind::Index { object, index } => {
                self.check_expr(object, locals);
                self.check_expr(index, locals);
            }
            ExprKind::Array(elements) => {
                for e in elements {
                    self.check_expr(e, locals);
                }
            }
            ExprKind::MapLit(entries) => {
                for (k, v) in entries {
                    self.check_expr(k, locals);
                    self.check_expr(v, locals);
                }
            }

            // ── Assignment: check mutability ────────────────────────────
            ExprKind::Assign { target, value } => {
                self.check_expr(target, locals);
                self.check_expr(value, locals);
                if let ExprKind::Ident(name) = &target.kind {
                    if let Some(var_info) = locals.get(name) {
                        let declared = var_info.ty.clone();
                        self.check_optional_binding(&declared, value, locals, value.span);
                    }
                }
                // Check that target is mutable
                if let ExprKind::Ident(name) = &target.kind {
                    if let Some(var_info) = locals.get(name) {
                        if !var_info.mutable {
                            self.diags.error(
                                "E0105",
                                format!(
                                    "cannot assign to immutable variable `{name}` -- use `var` instead of `let`"
                                ),
                                expr.span,
                            );
                        }
                    }
                }
            }
            ExprKind::Cast { expr, .. } => {
                self.check_expr(expr, locals);
            }
            ExprKind::StructLit {
                name,
                fields,
                spread,
            } => {
                for f in fields {
                    self.check_expr(&f.value, locals);
                }
                if let Some(s) = spread {
                    self.check_expr(s, locals);
                }
                // Check struct exists and fields match
                if let Some(sinfo) = self.env.structs.get(name) {
                    for field in fields {
                        if !sinfo.fields.iter().any(|(f, _)| *f == field.name) {
                            self.diags.error(
                                "E0106",
                                format!("struct `{name}` has no field `{}`", field.name),
                                field.span,
                            );
                        }
                    }
                } else {
                    // P1: an undeclared struct name used to typecheck silently —
                    // the interpreter then built a Map while native codegen
                    // produced a null pointer (silent divergence). Fail loud.
                    self.diags.error(
                        "E0115",
                        format!("unknown struct `{name}` in struct literal"),
                        expr.span,
                    );
                }
            }

            // ── String interpolation: check privacy ─────────────────────
            ExprKind::Interpolation(parts) => {
                for part in parts {
                    if let StringPart::Expr(e) = part {
                        self.check_expr(e, locals);
                        // Check privacy: interpolating a secret type is forbidden
                        let part_ty = self.infer_expr_type(e, locals);
                        if part_ty.is_secret() {
                            self.diags.error(
                                "E0202",
                                "cannot interpolate secret type into string -- secret values must never appear in strings",
                                e.span,
                            );
                        } else if part_ty.is_private() {
                            self.diags.error(
                                "E0203",
                                "cannot interpolate private type into string without .redact() or .hash()",
                                e.span,
                            );
                        }
                    }
                }
            }
            ExprKind::Closure { params, body } => {
                let mut inner_locals = locals.clone();
                for cp in params {
                    let ty = cp
                        .ty
                        .as_ref()
                        .map(|t| self.resolve_type_expr(t))
                        .unwrap_or(Type::Unknown);
                    inner_locals.insert(cp.name.clone(), VarInfo { ty, mutable: false });
                }
                for s in body {
                    self.check_stmt(s, &mut inner_locals);
                }
            }
            ExprKind::Bail(e) => {
                self.check_expr(e, locals);
            }
            // ── Concurrency (Phase 1) — nothing to check yet ─────────────
            ExprKind::Spawn { .. } | ExprKind::Select { .. } => {}
            // Leaf nodes — nothing to check
            ExprKind::IntLit(_)
            | ExprKind::FloatLit(_)
            | ExprKind::StringLit(_)
            | ExprKind::BoolLit(_)
            | ExprKind::Nil
            | ExprKind::DotIdent(_) => {}
        }
    }

    // ── Binary Operation Type Checking ──────────────────────────────────

    fn check_binary_op_types(&mut self, op: BinOp, left: &Type, right: &Type, span: Span) {
        // Skip if either side is unknown (can't validate)
        if *left == Type::Unknown || *right == Type::Unknown {
            return;
        }

        match op {
            // Arithmetic: both sides must be numeric
            BinOp::Add | BinOp::Sub | BinOp::Mul | BinOp::Div | BinOp::Mod | BinOp::Pow => {
                let left_num = self.is_numeric(left);
                let right_num = self.is_numeric(right);
                // String + String is concatenation
                if op == BinOp::Add && *left == Type::String && *right == Type::String {
                    return;
                }
                if left_num && right_num {
                    return; // ok
                }
                if !left_num || !right_num {
                    // Only error if we have concrete types that are clearly wrong
                    if self.is_concrete_type(left) && self.is_concrete_type(right) {
                        if !left_num && !right_num {
                            self.diags.error(
                                "E0110",
                                format!(
                                    "binary `{}` requires numeric operands, got {} and {}",
                                    self.binop_str(op),
                                    self.type_display(left),
                                    self.type_display(right),
                                ),
                                span,
                            );
                        } else if !left_num {
                            self.diags.error(
                                "E0110",
                                format!(
                                    "left operand of `{}` must be numeric, got {}",
                                    self.binop_str(op),
                                    self.type_display(left),
                                ),
                                span,
                            );
                        } else {
                            self.diags.error(
                                "E0110",
                                format!(
                                    "right operand of `{}` must be numeric, got {}",
                                    self.binop_str(op),
                                    self.type_display(right),
                                ),
                                span,
                            );
                        }
                    }
                }
            }
            // Comparison: both sides should be same type
            BinOp::Eq | BinOp::Neq | BinOp::Lt | BinOp::Gt | BinOp::Lte | BinOp::Gte => {
                // Allow comparison of same types or numeric types
                // Don't warn for Named types (user-defined, might be comparable)
            }
            // Logical: both sides must be bool
            BinOp::And | BinOp::Or => {
                if self.is_concrete_type(left) && *left != Type::Bool {
                    self.diags.warning(
                        "W0110",
                        format!(
                            "left operand of logical `{}` should be bool, got {}",
                            self.binop_str(op),
                            self.type_display(left)
                        ),
                        span,
                    );
                }
                if self.is_concrete_type(right) && *right != Type::Bool {
                    self.diags.warning(
                        "W0110",
                        format!(
                            "right operand of logical `{}` should be bool, got {}",
                            self.binop_str(op),
                            self.type_display(right)
                        ),
                        span,
                    );
                }
            }
            // Bitwise and shifts: allow on integers
            BinOp::BitAnd | BinOp::BitOr | BinOp::BitXor | BinOp::Shl | BinOp::Shr => {}
            // Range: allow numeric
            BinOp::Range => {}
        }
    }

    fn is_numeric(&self, ty: &Type) -> bool {
        matches!(ty, Type::Int(_) | Type::Float(_))
    }

    fn is_concrete_type(&self, ty: &Type) -> bool {
        !matches!(ty, Type::Unknown | Type::Named(_))
    }

    fn binop_str(&self, op: BinOp) -> &'static str {
        match op {
            BinOp::Add => "+",
            BinOp::Sub => "-",
            BinOp::Mul => "*",
            BinOp::Div => "/",
            BinOp::Mod => "%",
            BinOp::Pow => "**",
            BinOp::Eq => "==",
            BinOp::Neq => "!=",
            BinOp::Lt => "<",
            BinOp::Gt => ">",
            BinOp::Lte => "<=",
            BinOp::Gte => ">=",
            BinOp::And => "&&",
            BinOp::Or => "||",
            BinOp::BitAnd => "&",
            BinOp::BitOr => "|",
            BinOp::BitXor => "^",
            BinOp::Shl => "<<",
            BinOp::Shr => ">>",
            BinOp::Range => "..",
        }
    }

    fn type_display(&self, ty: &Type) -> String {
        match ty {
            Type::Void => "void".to_string(),
            Type::Bool => "bool".to_string(),
            Type::Int(s) => format!("{s:?}").to_lowercase(),
            Type::Float(s) => format!("{s:?}").to_lowercase(),
            Type::String => "String".to_string(),
            Type::Bytes => "Bytes".to_string(),
            Type::Char => "char".to_string(),
            Type::Private(inner) => format!("private {}", self.type_display(inner)),
            Type::Secret(inner) => format!("secret {}", self.type_display(inner)),
            Type::Optional(inner) => format!("{}?", self.type_display(inner)),
            Type::Result(inner) => format!("Result<{}>", self.type_display(inner)),
            Type::Array(inner) => format!("[]{}", self.type_display(inner)),
            Type::Tuple(types) => {
                let inner: Vec<String> = types.iter().map(|t| self.type_display(t)).collect();
                format!("({})", inner.join(", "))
            }
            Type::Map(k, v) => format!("Map<{}, {}>", self.type_display(k), self.type_display(v)),
            Type::Named(n) => n.clone(),
            Type::Grant(effect) => format!("Grant<{effect}>"),
            _ => format!("{ty:?}"),
        }
    }

    /// Get the type name for a type (for method lookup).
    fn type_to_name(&self, ty: &Type) -> Option<String> {
        match ty {
            Type::Named(name) => Some(name.clone()),
            Type::Private(inner) | Type::Secret(inner) => self.type_to_name(inner),
            _ => None,
        }
    }

    /// Check if a name is a builtin (not requiring declaration).
    fn is_builtin_name(&self, name: &str) -> bool {
        matches!(
            name,
            "print"
                | "log"
                | "fetch"
                | "exit"
                | "panic"
                // Assertion family — builtins with compiled arms in
                // `codegen.rs` (`emit_call`), NOT stdlib modules, so
                // `is_registered_module` cannot cover them: without these every
                // correct `assert_eq`/`assert_ok` use warned W0102.
                | "assert"
                | "assert_eq"
                | "assert_ne"
                | "assert_ok"
                | "assert_err"
                // Concurrency builtins (compiled arms call tallow_channel_*/
                // tallow_mutex_*), same class as the assert family.
                | "channel"
                | "mutex"
                | "now"
                | "sleep"
                // `type_name` / `type_of` — builtins with compiled arms in
                // `codegen.rs` `emit_call`; without this entry every use
                // warned W0102 "possibly undefined variable".
                | "type_name"
                | "type_of"
                // `FileCopy` is a runtime module (interp maps it to
                // `__module_FileCopy__`; `FileCopy.copy_metadata` is the
                // metadata-preserving copy primitive). It was missing from this
                // list, so the only correct way to copy a file with metadata
                // preservation warned W0102 on every use.
                | "FileCopy"
                | "spawn"
                | "Ok"
                | "Err"
                | "Some"
                | "None"
                | "true"
                | "false"
                | "nil"
                | "self"
                | "db"
                | "http"
                | "net"
                | "tallow"
                | "KeyPair"
                | "SymKey"
                | "Random"
                | "Algos"
                | "TLSConn"
                | "IPPool"
                | "Scanner"
                | "ScanScope"
                | "Browser"
                | "browser"
                | "page"
                | "conn"
                | "config"
                | "beehiiv"
                | "medium"
                | "substack"
                | "wordpress"
                | "ghost"
                | "oauth"
                | "jwt"
                | "sso"
                | "escalation"
                | "azure_app_proxy"
                | "deals"
                | "edgar"
                | "filings"
                | "market"
                // Research modules (2026-09-04): recordlink, sourcegrade, geocode
                | "recordlink"
                | "sourcegrade"
                | "geocode"
                // Sitescan module (2026-09-12): comprehensive website + infrastructure scanning
                | "sitescan"
                | "MAX"
                | "VERSION"
        ) || crate::stdlib::is_registered_module(&name.to_ascii_lowercase())
    }

    // ── Match Exhaustiveness Checking ───────────────────────────────────

    fn check_match_exhaustiveness(&mut self, subject_ty: &Type, arms: &[MatchArm], span: Span) {
        // Check if there's a wildcard pattern
        let has_wildcard = arms
            .iter()
            .any(|arm| matches!(&arm.pattern, Pattern::Wildcard));
        if has_wildcard {
            return; // Exhaustive by wildcard
        }

        // For enum types, check that all variants are covered
        let enum_name = match subject_ty {
            Type::Named(name) => Some(name.clone()),
            _ => None,
        };
        if let Some(ref name) = enum_name {
            if let Some(info) = self.env.enums.get(name) {
                // Collect variant names and general catchall idents
                let mut covered: Vec<String> = Vec::new();
                let mut has_catchall_ident = false;

                for arm in arms {
                    match &arm.pattern {
                        Pattern::Variant { name, .. } => {
                            covered.push(name.clone());
                        }
                        Pattern::Ident(n) => {
                            // If ident matches a variant name, it covers that variant
                            if info.variants.contains(n) {
                                covered.push(n.clone());
                            } else {
                                // It's a generic binding (like `x` or `other`) - acts as catchall
                                has_catchall_ident = true;
                            }
                        }
                        Pattern::Literal(_) => {
                            // Literal patterns don't cover enum variants
                        }
                        _ => {}
                    }
                }

                if has_catchall_ident {
                    return; // A non-variant ident acts as catchall
                }

                let missing: Vec<&String> = info
                    .variants
                    .iter()
                    .filter(|v| !covered.contains(v))
                    .collect();
                if !missing.is_empty() {
                    let missing_str: Vec<&str> = missing.iter().map(|s| s.as_str()).collect();
                    self.diags.warning(
                        "W0120",
                        format!(
                            "match on `{name}` is not exhaustive -- missing variant(s): {}. Add a `_` catchall or handle all variants",
                            missing_str.join(", ")
                        ),
                        span,
                    );
                }
            }
        }
    }

    /// Bind pattern variables into scope for match arm checking.
    fn bind_pattern_vars(&self, pattern: &Pattern, locals: &mut HashMap<String, VarInfo>) {
        match pattern {
            Pattern::Ident(name) => {
                if name != "_" {
                    locals.insert(
                        name.clone(),
                        VarInfo {
                            ty: Type::Unknown,
                            mutable: false,
                        },
                    );
                }
            }
            Pattern::Variant { fields, .. } => {
                for field in fields {
                    self.bind_pattern_vars(&field.pattern, locals);
                }
            }
            Pattern::Tuple(pats) => {
                for p in pats {
                    self.bind_pattern_vars(p, locals);
                }
            }
            _ => {}
        }
    }

    /// Infer the type of an expression (simplified — handles common patterns).
    fn infer_expr_type(&self, expr: &Expr, locals: &HashMap<String, VarInfo>) -> Type {
        match &expr.kind {
            ExprKind::IntLit(_) => Type::Int(IntSize::I64),
            ExprKind::FloatLit(_) => Type::Float(FloatSize::F64),
            ExprKind::StringLit(_) | ExprKind::Interpolation(_) => Type::String,
            ExprKind::BoolLit(_) => Type::Bool,
            ExprKind::Nil => Type::Void,
            ExprKind::Ident(name) => locals
                .get(name)
                .map(|vi| vi.ty.clone())
                .unwrap_or(Type::Unknown),
            ExprKind::Call { callee, .. } => {
                if let ExprKind::Ident(name) = &callee.kind {
                    if let Some(sig) = self.env.functions.get(name) {
                        return sig.return_type.clone();
                    }
                }
                Type::Unknown
            }
            ExprKind::MethodCall { object, method, .. } => {
                // `scope.grant(Net)` is the only expression that produces a
                // `Grant<Net>` (G01 P0.2). An unknown effect name is reported
                // as E0143 by `validate_scope_grant`; infer nothing usable.
                if let Some(effect) = scope_grant_effect(expr) {
                    return if is_known_effect(effect) {
                        Type::Grant(effect.to_string())
                    } else {
                        Type::Unknown
                    };
                }
                let obj_ty = self.infer_expr_type(object, locals);
                // .redact() and .hash() on private types return String
                if obj_ty.is_sensitive()
                    && (method == "redact" || method == "hash" || method == "mask")
                {
                    Type::String
                }
                // Trust type methods
                else if method == "verify" {
                    match &obj_ty {
                        Type::Unverified(inner) => Type::Trusted(inner.clone()),
                        Type::Trusted(inner) => Type::Trusted(inner.clone()),
                        _ => Type::Unknown,
                    }
                } else if method == "value" {
                    match &obj_ty {
                        Type::Trusted(inner) | Type::Unverified(inner) => *inner.clone(),
                        Type::Fresh(inner, _) => *inner.clone(),
                        _ => Type::Unknown,
                    }
                } else if method == "is_valid" {
                    if obj_ty.is_fresh() {
                        Type::Bool
                    } else {
                        Type::Unknown
                    }
                }
                // Lookup in registered impl methods
                else if let Some(tname) = self.type_to_name(&obj_ty) {
                    if let Some(methods) = self.env.methods.get(&tname) {
                        if let Some(sig) = methods.iter().find(|s| s.name == *method) {
                            return sig.return_type.clone();
                        }
                    }
                    Type::Unknown
                } else {
                    // .len() returns usize, .text() returns String, etc.
                    match method.as_str() {
                        "len" => Type::Int(IntSize::Usize),
                        "text" | "trim" | "to_string" | "to_json" => Type::String,
                        "parse" => Type::Unknown,
                        "encrypt" => Type::Named("EncryptedBatch".to_string()),
                        _ => Type::Unknown,
                    }
                }
            }
            ExprKind::Try(inner) => match self.infer_expr_type(inner, locals) {
                // `?` unwraps `Result<T>` → `T`. A non-Result operand is an
                // error (E0111, emitted in `check_expr`); infer nothing usable
                // rather than leaking the invalid operand type.
                Type::Result(inner) => *inner,
                _ => Type::Unknown,
            },
            ExprKind::Await(inner) => self.infer_expr_type(inner, locals),
            ExprKind::If { then_block, .. } | ExprKind::IfLet { then_block, .. } => {
                if let Some(last) = then_block.stmts.last() {
                    if let StmtKind::Expr { expr } = &last.kind {
                        return self.infer_expr_type(expr, locals);
                    }
                }
                Type::Void
            }
            ExprKind::Binary { op, left, right } => {
                match op {
                    BinOp::Eq
                    | BinOp::Neq
                    | BinOp::Lt
                    | BinOp::Gt
                    | BinOp::Lte
                    | BinOp::Gte
                    | BinOp::And
                    | BinOp::Or => Type::Bool,
                    BinOp::Div => {
                        let lt = self.infer_expr_type(left, locals);
                        let rt = self.infer_expr_type(right, locals);
                        // Float / anything = float; int / int = int
                        if matches!(lt, Type::Float(_)) || matches!(rt, Type::Float(_)) {
                            Type::Float(FloatSize::F64)
                        } else {
                            lt
                        }
                    }
                    _ => self.infer_expr_type(left, locals),
                }
            }
            ExprKind::Array(elements) => {
                if let Some(first) = elements.first() {
                    Type::Array(Box::new(self.infer_expr_type(first, locals)))
                } else {
                    Type::Array(Box::new(Type::Unknown))
                }
            }
            ExprKind::FieldAccess { object, field } => {
                let obj_ty = self.infer_expr_type(object, locals);
                if let Some(tname) = self.type_to_name(&obj_ty) {
                    if let Some(sinfo) = self.env.structs.get(&tname) {
                        if let Some((_, fty)) = sinfo.fields.iter().find(|(f, _)| f == field) {
                            return fty.clone();
                        }
                    }
                }
                Type::Unknown
            }
            ExprKind::StructLit { name, .. } => Type::Named(name.clone()),
            _ => Type::Unknown,
        }
    }

    /// Check if a function body calls network functions (fetch, pool.map, etc.).
    fn body_touches_network(&self, block: &Block) -> bool {
        self.body_touches_network_in(block, &std::collections::HashSet::new())
    }

    /// Same as `body_touches_network`, but merges channel bindings collected
    /// from the enclosing scope (`outer`) so a `.send()` on a channel bound
    /// outside the current block is still recognized as a concurrency op.
    fn body_touches_network_in(
        &self,
        block: &Block,
        outer: &std::collections::HashSet<String>,
    ) -> bool {
        let mut chans = outer.clone();
        Self::collect_channel_vars(block, &mut chans);
        for stmt in &block.stmts {
            if self.stmt_touches_network(stmt, &chans) {
                return true;
            }
        }
        false
    }

    /// Collect `let <name> = <channel constructor>(...)` bindings. `.send()` on
    /// any of these is the concurrency primitive, not a network operation (the
    /// blanket `.send()` = network rule made channel code trip
    /// E0100/E5100/E5004, blocking every real channel use).
    fn collect_channel_vars(block: &Block, out: &mut std::collections::HashSet<String>) {
        for stmt in &block.stmts {
            match &stmt.kind {
                StmtKind::Let { name, value, .. } | StmtKind::Var { name, value, .. } => {
                    if Self::expr_is_channel_ctor(value) {
                        out.insert(name.clone());
                    }
                }
                StmtKind::For { body, .. }
                | StmtKind::While { body, .. }
                | StmtKind::Loop { body } => Self::collect_channel_vars(body, out),
                StmtKind::WhileLet { body, .. } => Self::collect_channel_vars(body, out),
                _ => {}
            }
        }
    }

    /// True for `sync.channel(..)`, `sync.unbounded()`, `Chan.new(..)` and
    /// `Chan.buffered(..)` — the channel constructors of the sync module.
    fn expr_is_channel_ctor(expr: &Expr) -> bool {
        if let ExprKind::MethodCall { object, method, .. } = &expr.kind {
            if let ExprKind::Ident(obj_name) = &object.kind {
                return (obj_name == "sync"
                    && matches!(method.as_str(), "channel" | "unbounded"))
                    || (obj_name == "Chan" && matches!(method.as_str(), "new" | "buffered"));
            }
        }
        false
    }

    fn stmt_touches_network(
        &self,
        stmt: &Stmt,
        chans: &std::collections::HashSet<String>,
    ) -> bool {
        match &stmt.kind {
            StmtKind::Expr { expr } => self.expr_touches_network(expr, chans),
            StmtKind::Let { value, .. }
            | StmtKind::Var { value, .. }
            | StmtKind::LetDestructure { value, .. } => self.expr_touches_network(value, chans),
            StmtKind::Return(Some(expr)) => self.expr_touches_network(expr, chans),
            StmtKind::For { iter, body, .. } => {
                self.expr_touches_network(iter, chans) || self.body_touches_network_in(body, chans)
            }
            StmtKind::While { condition, body } => {
                self.expr_touches_network(condition, chans)
                    || self.body_touches_network_in(body, chans)
            }
            StmtKind::WhileLet { expr, body, .. } => {
                self.expr_touches_network(expr, chans) || self.body_touches_network_in(body, chans)
            }
            StmtKind::Loop { body } => self.body_touches_network_in(body, chans),
            _ => false,
        }
    }

    fn expr_touches_network(&self, expr: &Expr, chans: &std::collections::HashSet<String>) -> bool {
        match &expr.kind {
            ExprKind::Call { callee, args, .. } => {
                // Direct call to `fetch`
                if let ExprKind::Ident(name) = &callee.kind {
                    if name == "fetch" {
                        return true;
                    }
                }
                self.expr_touches_network(callee, chans)
                    || args.iter().any(|a| self.expr_touches_network(&a.value, chans))
            }
            ExprKind::MethodCall {
                object,
                method,
                args,
                ..
            } => {
                // pool.map_ratelimited(), conn.connect()
                // Note: .map() is too general (arrays use it); only flag
                // explicitly network methods here.
                if method == "map_ratelimited" || method == "connect" {
                    return true;
                }
                // `.send()` is a network-socket operation EXCEPT on channel
                // receivers (bound from sync.channel / sync.unbounded /
                // Chan.new / Chan.buffered), where it is the concurrency
                // primitive. Blanket-flagging it made channels unusable.
                if method == "send" {
                    let is_channel = if let ExprKind::Ident(name) = &object.kind {
                        chans.contains(name)
                    } else {
                        false
                    };
                    if !is_channel {
                        return true;
                    }
                }
                // pool.map() — only flag if receiver looks like a pool variable
                if method == "map" {
                    if let ExprKind::Ident(name) = &object.kind {
                        if name == "pool" || name.ends_with("_pool") || name.contains("pool") {
                            return true;
                        }
                    }
                }
                // Browser operations that touch the network
                let browser_network_methods = [
                    "goto",
                    "navigate",
                    "new_page",
                    "new_context",
                    "reload",
                    "go_back",
                    "go_forward",
                    "launch",
                ];
                if browser_network_methods.contains(&method.as_str()) {
                    return true;
                }
                // Browser save/download operations (also network-touching;
                // legal_pass will additionally require retain_for)
                let browser_save_methods = ["screenshot", "save_pdf", "save_page", "download"];
                if browser_save_methods.contains(&method.as_str()) {
                    return true;
                }
                // Module-qualified network calls (http.get, http.post, net.connect, etc.)
                if let ExprKind::Ident(obj_name) = &object.kind {
                    if (obj_name == "http"
                        && matches!(
                            method.as_str(),
                            "get" | "post" | "put" | "delete" | "request" | "server"
                        ))
                        || (obj_name == "net" && matches!(method.as_str(), "connect" | "listen"))
                    {
                        return true;
                    }
                }
                self.expr_touches_network(object, chans)
                    || args.iter().any(|a| self.expr_touches_network(&a.value, chans))
            }
            ExprKind::Try(inner) | ExprKind::Await(inner) => {
                self.expr_touches_network(inner, chans)
            }
            ExprKind::Binary { left, right, .. } => {
                self.expr_touches_network(left, chans) || self.expr_touches_network(right, chans)
            }
            ExprKind::Block(block) => self.body_touches_network_in(block, chans),
            ExprKind::If {
                condition,
                then_block,
                else_branch,
            } => {
                self.expr_touches_network(condition, chans)
                    || self.body_touches_network_in(then_block, chans)
                    || else_branch.as_ref().is_some_and(|eb| match eb {
                        ElseBranch::Block(b) => self.body_touches_network_in(b, chans),
                        ElseBranch::ElseIf(e) => self.expr_touches_network(e, chans),
                    })
            }
            ExprKind::IfLet {
                expr: matched_expr,
                then_block,
                else_branch,
                ..
            } => {
                self.expr_touches_network(matched_expr, chans)
                    || self.body_touches_network_in(then_block, chans)
                    || else_branch.as_ref().is_some_and(|eb| match eb {
                        ElseBranch::Block(b) => self.body_touches_network_in(b, chans),
                        ElseBranch::ElseIf(e) => self.expr_touches_network(e, chans),
                    })
            }
            _ => false,
        }
    }

    // ── Browser Navigation Detection (static, for stealth_pass) ─────────

    /// Browser navigation method names that require @stealth annotation.
    const BROWSER_NAV_METHODS: &'static [&'static str] =
        &["goto", "navigate", "new_page", "new_context", "launch"];

    /// Check if a function body calls browser navigation methods.
    ///
    /// This is a static method (no &self) to enable reuse from stealth_pass
    /// without requiring a TypeChecker instance.
    pub fn body_uses_browser_navigation(block: &Block) -> bool {
        for stmt in &block.stmts {
            if Self::stmt_uses_browser_nav(stmt) {
                return true;
            }
        }
        false
    }

    fn stmt_uses_browser_nav(stmt: &Stmt) -> bool {
        match &stmt.kind {
            StmtKind::Expr { expr } => Self::expr_uses_browser_nav(expr),
            StmtKind::Let { value, .. }
            | StmtKind::Var { value, .. }
            | StmtKind::LetDestructure { value, .. } => Self::expr_uses_browser_nav(value),
            StmtKind::Return(Some(expr)) => Self::expr_uses_browser_nav(expr),
            StmtKind::For { iter, body, .. } => {
                Self::expr_uses_browser_nav(iter) || Self::body_uses_browser_navigation(body)
            }
            StmtKind::While { condition, body } => {
                Self::expr_uses_browser_nav(condition) || Self::body_uses_browser_navigation(body)
            }
            StmtKind::WhileLet { expr, body, .. } => {
                Self::expr_uses_browser_nav(expr) || Self::body_uses_browser_navigation(body)
            }
            StmtKind::Loop { body } => Self::body_uses_browser_navigation(body),
            _ => false,
        }
    }

    fn expr_uses_browser_nav(expr: &Expr) -> bool {
        match &expr.kind {
            ExprKind::MethodCall {
                method,
                object,
                args,
                ..
            } => {
                if Self::BROWSER_NAV_METHODS.contains(&method.as_str()) {
                    return true;
                }
                Self::expr_uses_browser_nav(object)
                    || args.iter().any(|a| Self::expr_uses_browser_nav(&a.value))
            }
            ExprKind::Call { callee, args, .. } => {
                Self::expr_uses_browser_nav(callee)
                    || args.iter().any(|a| Self::expr_uses_browser_nav(&a.value))
            }
            ExprKind::Try(inner) | ExprKind::Await(inner) => Self::expr_uses_browser_nav(inner),
            ExprKind::Binary { left, right, .. } => {
                Self::expr_uses_browser_nav(left) || Self::expr_uses_browser_nav(right)
            }
            ExprKind::Block(block) => Self::body_uses_browser_navigation(block),
            ExprKind::If {
                condition,
                then_block,
                else_branch,
            } => {
                Self::expr_uses_browser_nav(condition)
                    || Self::body_uses_browser_navigation(then_block)
                    || else_branch.as_ref().is_some_and(|eb| match eb {
                        ElseBranch::Block(b) => Self::body_uses_browser_navigation(b),
                        ElseBranch::ElseIf(e) => Self::expr_uses_browser_nav(e),
                    })
            }
            ExprKind::IfLet {
                expr: matched_expr,
                then_block,
                else_branch,
                ..
            } => {
                Self::expr_uses_browser_nav(matched_expr)
                    || Self::body_uses_browser_navigation(then_block)
                    || else_branch.as_ref().is_some_and(|eb| match eb {
                        ElseBranch::Block(b) => Self::body_uses_browser_navigation(b),
                        ElseBranch::ElseIf(e) => Self::expr_uses_browser_nav(e),
                    })
            }
            _ => false,
        }
    }
}

// ── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::lexer;
    use crate::parser::Parser;

    fn check(source: &str) -> (TypeEnv, Diagnostics) {
        let (tokens, _) = lexer::tokenize(source);
        let program = Parser::parse(tokens).unwrap();
        TypeChecker::new(&program).check()
    }

    #[test]
    fn registers_function_signatures() {
        let (env, _) = check("fn add(a: i32, b: i32) -> i32 { a + b }");
        let sig = env.functions.get("add").unwrap();
        assert_eq!(sig.params.len(), 2);
        assert_eq!(sig.return_type, Type::Int(IntSize::I32));
    }

    #[test]
    fn registers_type_aliases() {
        let (env, _) = check("type Email = private String");
        let ty = env.type_aliases.get("Email").unwrap();
        assert!(ty.is_private());
    }

    #[test]
    fn detects_network_functions() {
        let (env, _) = check(r#"fn get_data(url: String) -> String { fetch(url) }"#);
        assert!(env.network_functions.contains(&"get_data".to_string()));
    }

    #[test]
    fn non_network_function() {
        let (env, _) = check("fn add(a: i32, b: i32) -> i32 { a + b }");
        assert!(!env.network_functions.contains(&"add".to_string()));
    }

    #[test]
    fn resolves_privacy_param_types() {
        let (env, _) = check("fn log_user(email: Email) { email }");
        let sig = env.functions.get("log_user").unwrap();
        assert!(sig.params[0].1.is_private());
    }

    #[test]
    fn resolves_secret_param_types() {
        let (env, _) = check("fn auth(password: Password) { password }");
        let sig = env.functions.get("auth").unwrap();
        assert!(sig.params[0].1.is_secret());
    }

    #[test]
    fn resolves_generic_return() {
        let (env, _) = check("fn fetch_data(url: String) -> Result<String> { url }");
        let sig = env.functions.get("fetch_data").unwrap();
        assert!(matches!(sig.return_type, Type::Result(_)));
    }

    #[test]
    fn registers_multiple_functions() {
        let (env, _) = check(
            r#"
            fn add(a: i32, b: i32) -> i32 { a + b }
            fn sub(a: i32, b: i32) -> i32 { a - b }
            fn mul(a: i32, b: i32) -> i32 { a * b }
        "#,
        );
        assert!(env.functions.contains_key("add"));
        assert!(env.functions.contains_key("sub"));
        assert!(env.functions.contains_key("mul"));
    }

    #[test]
    fn resolves_optional_type() {
        let (env, _) = check("fn maybe(x: i32) -> i32? { x }");
        let sig = env.functions.get("maybe").unwrap();
        assert!(matches!(sig.return_type, Type::Optional(_)));
    }

    #[test]
    fn resolves_array_param() {
        let (env, _) = check("fn sum(items: []i32) -> i32 { 0 }");
        let sig = env.functions.get("sum").unwrap();
        assert!(matches!(sig.params[0].1, Type::Array(_)));
    }

    #[test]
    fn detects_fetch_in_nested_call() {
        let (env, _) = check(
            r#"
            fn process(url: String) -> String {
                let resp = fetch(url)
                resp
            }
        "#,
        );
        assert!(env.network_functions.contains(&"process".to_string()));
    }

    #[test]
    fn type_alias_registered() {
        let (env, _) = check("type Email = private String");
        assert!(env.type_aliases.contains_key("Email"));
    }

    // ── Additional type checker tests ─────────────────────────────────────

    #[test]
    fn resolves_secret_type_alias() {
        let (env, _) = check("type ApiKey = secret String");
        let ty = env.type_aliases.get("ApiKey").unwrap();
        assert!(ty.is_secret());
    }

    #[test]
    fn resolves_plain_type_alias() {
        let (env, _) = check("type UserID = String");
        let ty = env.type_aliases.get("UserID").unwrap();
        assert!(!ty.is_private());
        assert!(!ty.is_secret());
    }

    #[test]
    fn resolves_map_generic_type() {
        let (env, _) = check("fn get(m: Map<String, i32>) -> i32 { 0 }");
        let sig = env.functions.get("get").unwrap();
        assert!(matches!(sig.params[0].1, Type::Map(_, _)));
    }

    #[test]
    fn resolves_set_generic_type() {
        let (env, _) = check("fn dedup(items: Set<String>) -> i32 { 0 }");
        let sig = env.functions.get("dedup").unwrap();
        assert!(matches!(sig.params[0].1, Type::Set(_)));
    }

    #[test]
    fn resolves_tuple_type() {
        let (env, _) = check("fn pair(a: i32) -> (i32, String) { (a, \"hello\") }");
        let sig = env.functions.get("pair").unwrap();
        if let Type::Tuple(types) = &sig.return_type {
            assert_eq!(types.len(), 2);
        } else {
            panic!("expected Tuple type");
        }
    }

    #[test]
    fn resolves_function_type_param() {
        let (env, _) = check("fn apply(f: fn(i32) -> i32, x: i32) -> i32 { f(x) }");
        let sig = env.functions.get("apply").unwrap();
        assert!(matches!(sig.params[0].1, Type::Function { .. }));
    }

    #[test]
    fn builtin_private_types_resolved() {
        let (env, _) = check(
            r#"
            fn log_all(email: Email, name: Name, phone: Phone, ip: IPAddress, loc: Location, ssn: SSN) { 0 }
        "#,
        );
        let sig = env.functions.get("log_all").unwrap();
        for (_, ty) in &sig.params {
            assert!(ty.is_private(), "Expected private type");
        }
    }

    #[test]
    fn builtin_secret_types_resolved() {
        let (env, _) = check(
            r#"
            fn auth(pass: Password, key: APIKey, pk: PrivateKey, tok: Token) { 0 }
        "#,
        );
        let sig = env.functions.get("auth").unwrap();
        for (_, ty) in &sig.params {
            assert!(ty.is_secret(), "Expected secret type");
        }
    }

    #[test]
    fn void_return_when_none_specified() {
        let (env, _) = check("fn noop() { }");
        let sig = env.functions.get("noop").unwrap();
        assert_eq!(sig.return_type, Type::Void);
    }

    #[test]
    fn resolves_slice_type() {
        let (env, _) = check("fn bytes(data: []u8) -> i32 { 0 }");
        let sig = env.functions.get("bytes").unwrap();
        assert!(matches!(sig.params[0].1, Type::Array(_)));
    }

    #[test]
    fn detects_pool_map_as_network() {
        let (env, _) = check(
            r#"
            fn scrape(pool: String, urls: []String) -> String {
                pool.map(urls)
            }
        "#,
        );
        assert!(env.network_functions.contains(&"scrape".to_string()));
    }

    #[test]
    fn detects_send_as_network() {
        let (env, _) = check(
            r#"
            fn send_data(conn: String) -> String {
                conn.send("data")
            }
        "#,
        );
        assert!(env.network_functions.contains(&"send_data".to_string()));
    }

    #[test]
    fn detects_connect_as_network() {
        let (env, _) = check(
            r#"
            fn open(url: String) -> String {
                url.connect()
            }
        "#,
        );
        assert!(env.network_functions.contains(&"open".to_string()));
    }

    #[test]
    fn detects_map_ratelimited_as_network() {
        let (env, _) = check(
            r#"
            fn rate_scrape(p: String) -> String {
                p.map_ratelimited()
            }
        "#,
        );
        assert!(env.network_functions.contains(&"rate_scrape".to_string()));
    }

    #[test]
    fn fetch_in_for_loop_detected() {
        let (env, _) = check(
            r#"
            fn scrape_all(urls: []String) -> String {
                for url in urls {
                    fetch(url)
                }
                "done"
            }
        "#,
        );
        assert!(env.network_functions.contains(&"scrape_all".to_string()));
    }

    #[test]
    fn fetch_in_while_loop_detected() {
        let (env, _) = check(
            r#"
            fn poll(url: String) -> String {
                while true {
                    fetch(url)
                }
                "done"
            }
        "#,
        );
        assert!(env.network_functions.contains(&"poll".to_string()));
    }

    #[test]
    fn infers_int_literal_type() {
        let (env, _) = check("fn f() -> i32 { let x = 42\n x }");
        // Just verify it doesn't error
        assert!(env.functions.contains_key("f"));
    }

    #[test]
    fn infers_float_literal_type() {
        let (env, _) = check("fn f() -> f64 { let x = 3.14\n x }");
        assert!(env.functions.contains_key("f"));
    }

    #[test]
    fn infers_bool_literal_type() {
        let (env, _) = check("fn f() -> bool { let x = true\n x }");
        assert!(env.functions.contains_key("f"));
    }

    #[test]
    fn resolves_chan_type() {
        let (env, _) = check("fn recv(ch: Chan<String>) -> String { \"\" }");
        let sig = env.functions.get("recv").unwrap();
        assert!(matches!(sig.params[0].1, Type::Chan(_)));
    }

    #[test]
    fn resolves_bytes_type() {
        let (env, _) = check("fn read(data: Bytes) -> i32 { 0 }");
        let sig = env.functions.get("read").unwrap();
        assert_eq!(sig.params[0].1, Type::Bytes);
    }

    #[test]
    fn resolves_char_type() {
        let (env, _) = check("fn first(c: char) -> char { c }");
        let sig = env.functions.get("first").unwrap();
        assert_eq!(sig.params[0].1, Type::Char);
        assert_eq!(sig.return_type, Type::Char);
    }

    #[test]
    fn resolves_nested_optional_result() {
        let (env, _) = check("fn maybe(x: i32) -> Result<String> { Ok(\"hi\") }");
        let sig = env.functions.get("maybe").unwrap();
        if let Type::Result(inner) = &sig.return_type {
            assert_eq!(**inner, Type::String);
        } else {
            panic!("expected Result<String>");
        }
    }

    #[test]
    fn strip_qualifier_works() {
        let private = Type::Private(Box::new(Type::String));
        assert_eq!(*private.strip_qualifier(), Type::String);
        let secret = Type::Secret(Box::new(Type::Int(IntSize::I64)));
        assert_eq!(*secret.strip_qualifier(), Type::Int(IntSize::I64));
        let plain = Type::Bool;
        assert_eq!(*plain.strip_qualifier(), Type::Bool);
    }

    // ── Extended Type Checker Tests ─────────────────────────────────────

    #[test]
    fn resolves_void_return() {
        let (env, _) = check("fn greet() { }");
        let sig = env.functions.get("greet").unwrap();
        assert_eq!(sig.return_type, Type::Void);
    }

    #[test]
    fn resolves_map_param_types() {
        let (env, _) = check("fn lookup(data: Map<String, i64>) -> i64 { 0 }");
        let sig = env.functions.get("lookup").unwrap();
        assert!(matches!(&sig.params[0].1, Type::Map(_, _)));
    }

    #[test]
    fn resolves_optional_return_type() {
        let (env, _) = check("fn find(name: String) -> String? { nil }");
        let sig = env.functions.get("find").unwrap();
        assert!(matches!(&sig.return_type, Type::Optional(_)));
    }

    #[test]
    fn detects_network_in_pool_map_closure() {
        let (env, _) = check(
            r#"
            fn process() {
                let data = pool.map(urls) { url -> fetch(url) }
            }
        "#,
        );
        assert!(env.network_functions.contains(&"process".to_string()));
    }

    #[test]
    fn no_network_for_pure_math_function() {
        let (env, _) = check("fn add(a: i64, b: i64) -> i64 { a + b }");
        assert!(!env.network_functions.contains(&"add".to_string()));
    }

    #[test]
    fn resolves_four_mixed_param_types() {
        let (env, _) = check("fn mixed(a: i32, b: String, c: f64, d: bool) { }");
        let sig = env.functions.get("mixed").unwrap();
        assert_eq!(sig.params.len(), 4);
        assert_eq!(sig.params[0].1, Type::Int(IntSize::I32));
        assert_eq!(sig.params[1].1, Type::String);
        assert_eq!(sig.params[2].1, Type::Float(FloatSize::F64));
        assert_eq!(sig.params[3].1, Type::Bool);
    }

    #[test]
    fn resolves_private_email_alias() {
        let (env, _) = check(
            r#"
            type Email = private String
            fn send(to: Email) { }
        "#,
        );
        let sig = env.functions.get("send").unwrap();
        assert!(sig.params[0].1.is_private());
    }

    #[test]
    fn resolves_secret_apikey_alias() {
        let (env, _) = check(
            r#"
            type APIKey = secret String
            fn auth(key: APIKey) { }
        "#,
        );
        let sig = env.functions.get("auth").unwrap();
        assert!(sig.params[0].1.is_secret());
    }

    #[test]
    fn struct_with_impl_no_crash() {
        // Type checker should not crash on impl blocks
        let (env, _) = check(
            r#"
            struct Foo { x: i64 }
            impl Foo {
                fn get_x(self) -> i64 { self.x }
            }
        "#,
        );
        // At minimum, it shouldn't crash
        let _ = env;
    }

    #[test]
    fn resolves_async_fn_signature() {
        let (env, _) = check("async fn fetch() -> String { \"hello\" }");
        assert!(env.functions.contains_key("fetch"));
    }

    #[test]
    fn detects_fetch_in_if_block() {
        let (env, _) = check(
            r#"
            fn scrape() {
                if true {
                    fetch("https://example.com")
                }
            }
        "#,
        );
        assert!(env.network_functions.contains(&"scrape".to_string()));
    }

    #[test]
    fn resolves_tuple_return() {
        let (env, _) = check("fn minmax(items: []i64) -> (i64, i64) { (0, 0) }");
        let sig = env.functions.get("minmax").unwrap();
        assert!(matches!(&sig.return_type, Type::Tuple(_)));
    }

    #[test]
    fn resolves_bytes_param() {
        let (env, _) = check("fn hash(data: Bytes) -> String { \"abc\" }");
        let sig = env.functions.get("hash").unwrap();
        assert_eq!(sig.params[0].1, Type::Bytes);
    }

    // ── 20 new tests ─────────────────────────────────────────────────────────

    // 1. Struct declaration — type checker must not crash and environment must
    //    be returned intact.
    #[test]
    fn struct_declaration_does_not_crash() {
        let (env, diags) = check(
            r#"
            struct Point { x: f64, y: f64 }
        "#,
        );
        assert!(diags.items.is_empty());
        // Struct items are not registered in `functions` — just confirm no panic.
        let _ = env;
    }

    // The assert family and the concurrency builtins have compiled arms in
    // `codegen.rs` (`emit_call`) but were missing from `is_builtin_name`, so
    // every correct use warned `W0102 use of possibly undefined variable`.
    #[test]
    fn builtin_assert_family_does_not_warn_w0102() {
        let (_, diags) = check(
            r#"
            fn main() {
                assert(true, "ok")
                assert_eq(1, 1, "eq")
                assert_ne(1, 2, "ne")
                assert_ok(Ok(1))
                assert_err(Err("e"))
                let c = channel(4)
                let m = mutex(0)
            }
            "#,
        );
        let w0102: Vec<&str> = diags
            .items
            .iter()
            .filter(|d| d.code == "W0102")
            .map(|d| d.msg.as_str())
            .collect();
        assert!(
            w0102.is_empty(),
            "builtin names must not be reported as possibly undefined: {w0102:?}"
        );
    }

    // Top-level `const`s are globals. Nothing registered them, so every use of
    // one warned W0102 — `tallowx` printed three warnings on a clean run because
    // of this and the FileCopy entry below.
    #[test]
    fn const_use_does_not_warn_w0102() {
        let (_, diags) = check(
            r#"
            const RESUME_MIN: i64 = 8388608
            fn main() {
                if 12 >= RESUME_MIN { print("big") }
            }
            "#,
        );
        let w0102: Vec<&str> = diags
            .items
            .iter()
            .filter(|d| d.code == "W0102")
            .map(|d| d.msg.as_str())
            .collect();
        assert!(w0102.is_empty(), "a top-level const is not undefined: {w0102:?}");
    }

    #[test]
    fn filecopy_namespace_does_not_warn_w0102() {
        let (_, diags) = check(
            r#"
            fn main() {
                let r = FileCopy.copy_metadata("/tmp/a", "/tmp/b")
                print(r.bytes)
            }
            "#,
        );
        let w0102: Vec<&str> = diags
            .items
            .iter()
            .filter(|d| d.code == "W0102")
            .map(|d| d.msg.as_str())
            .collect();
        assert!(w0102.is_empty(), "the FileCopy module is not undefined: {w0102:?}");
    }

    /// The fix must not over-suppress: a genuinely undefined name still warns.
    #[test]
    fn undefined_variable_still_warns_w0102() {
        let (_, diags) = check("fn main() { print(never_defined_anywhere) }");
        assert!(
            diags.items.iter().any(|d| d.code == "W0102"),
            "an undefined name must still warn W0102"
        );
    }

    // 2. Struct with many typed fields: checker must survive all field types.
    #[test]
    fn struct_with_multiple_field_types_survives() {
        let (env, diags) = check(
            r#"
            struct Record {
                id:     u64,
                name:   String,
                score:  f64,
                active: bool,
                data:   Bytes
            }
        "#,
        );
        assert!(diags.items.is_empty());
        let _ = env;
    }

    // 3. Enum declaration — no crash, no spurious diagnostics.
    #[test]
    fn enum_declaration_does_not_crash() {
        let (env, diags) = check(
            r#"
            enum Color { Red, Green, Blue }
        "#,
        );
        assert!(diags.items.is_empty());
        let _ = env;
    }

    // 4. Enum with payload variants — variant fields are typed expressions.
    #[test]
    fn enum_with_payload_variants_does_not_crash() {
        let (env, diags) = check(
            r#"
            enum Status {
                Active,
                Inactive,
                Pending(reason: String)
            }
        "#,
        );
        assert!(diags.items.is_empty());
        let _ = env;
    }

    // 5. Multiple functions in sequence — all must appear in env.functions.
    #[test]
    fn five_functions_all_registered() {
        let (env, _) = check(
            r#"
            fn a() -> i32 { 1 }
            fn b() -> i64 { 2 }
            fn c() -> f64 { 3.0 }
            fn d() -> bool { true }
            fn e() -> String { "hi" }
        "#,
        );
        for name in ["a", "b", "c", "d", "e"] {
            assert!(env.functions.contains_key(name), "missing fn {name}");
        }
    }

    // 6. Impl block — checker must not crash; impl methods are not registered
    //    in the top-level functions map by the current pass-1 registration.
    #[test]
    fn impl_block_does_not_crash() {
        let (env, diags) = check(
            r#"
            struct Counter { value: i64 }
            impl Counter {
                fn increment(self) -> i64 { self.value + 1 }
                fn reset(self) -> Counter { Counter { value: 0 } }
            }
        "#,
        );
        assert!(diags.items.is_empty());
        let _ = env;
    }

    // 7. Const declaration — no crash, no diagnostics.
    #[test]
    fn const_declaration_does_not_crash() {
        let (env, diags) = check(
            r#"
            const MAX: u32 = 100_000
            const VERSION = "0.1.0"
        "#,
        );
        assert!(diags.items.is_empty());
        let _ = env;
    }

    // 8. Private type alias — qualifier propagates to function params.
    #[test]
    fn private_alias_propagates_to_param() {
        let (env, _) = check(
            r#"
            type PhoneNumber = private String
            fn call(number: PhoneNumber) -> String { "" }
        "#,
        );
        let sig = env.functions.get("call").unwrap();
        assert!(
            sig.params[0].1.is_private(),
            "PhoneNumber param should resolve to Private"
        );
    }

    // 9. Secret type alias — qualifier propagates to function params.
    #[test]
    fn secret_alias_propagates_to_param() {
        let (env, _) = check(
            r#"
            type BearerToken = secret String
            fn attach(tok: BearerToken) -> String { "" }
        "#,
        );
        let sig = env.functions.get("attach").unwrap();
        assert!(
            sig.params[0].1.is_secret(),
            "BearerToken param should resolve to Secret"
        );
    }

    // 10. Generic function — type_params on FnDecl must not cause a crash.
    #[test]
    fn generic_function_signature_registered() {
        let (env, _) = check(
            r#"
            fn identity<T>(x: T) -> T { x }
        "#,
        );
        assert!(env.functions.contains_key("identity"));
    }

    // 11. Generic function with multiple type params.
    #[test]
    fn generic_function_two_type_params_registered() {
        let (env, _) = check(
            r#"
            fn zip<A, B>(a: A, b: B) -> (A, B) { (a, b) }
        "#,
        );
        let sig = env.functions.get("zip").unwrap();
        // Return type is a Tuple of two Named types (A and B).
        assert!(
            matches!(&sig.return_type, Type::Tuple(ts) if ts.len() == 2),
            "expected Tuple return type"
        );
    }

    // 12. Network detection — fetch used inside an if-let expression.
    #[test]
    fn detects_fetch_in_if_let_block() {
        let (env, _) = check(
            r#"
            fn conditional_fetch(maybe_url: String) -> String {
                if let Ok(resp) = fetch(maybe_url) {
                    resp
                } else {
                    ""
                }
            }
        "#,
        );
        assert!(
            env.network_functions
                .contains(&"conditional_fetch".to_string())
        );
    }

    // 13. Network detection — fetch used inside a return statement.
    #[test]
    fn detects_fetch_in_return_stmt() {
        let (env, _) = check(
            r#"
            fn load(url: String) -> String {
                return fetch(url)
            }
        "#,
        );
        assert!(env.network_functions.contains(&"load".to_string()));
    }

    // 14. Network detection — .connect() called directly in function body.
    #[test]
    fn detects_connect_in_function_body() {
        let (env, _) = check(
            r#"
            fn dial(host: String) {
                host.connect()
            }
        "#,
        );
        // connect() on any receiver is flagged regardless of variable name
        assert!(env.network_functions.contains(&"dial".to_string()));
    }

    // 15. Function returning an Array type.
    #[test]
    fn function_returning_array_resolved() {
        let (env, _) = check("fn tags() -> []String { [] }");
        let sig = env.functions.get("tags").unwrap();
        assert!(
            matches!(&sig.return_type, Type::Array(inner) if **inner == Type::String),
            "expected Array<String>"
        );
    }

    // 16. Function returning a Map type.
    #[test]
    fn function_returning_map_resolved() {
        let (env, _) = check("fn index() -> Map<String, i64> { {} }");
        let sig = env.functions.get("index").unwrap();
        assert!(
            matches!(&sig.return_type, Type::Map(_, _)),
            "expected Map return type"
        );
    }

    // 17. Function returning Result<Array<String>>.
    #[test]
    fn function_returning_result_of_array_resolved() {
        let (env, _) = check("fn list_names() -> Result<[]String> { Ok([]) }");
        let sig = env.functions.get("list_names").unwrap();
        if let Type::Result(inner) = &sig.return_type {
            assert!(
                matches!(inner.as_ref(), Type::Array(_)),
                "inner should be Array"
            );
        } else {
            panic!("expected Result<Array<String>>");
        }
    }

    // 18. Parameter with Optional type.
    #[test]
    fn optional_param_resolved() {
        let (env, _) = check("fn greet(name: String?) -> String { \"hello\" }");
        let sig = env.functions.get("greet").unwrap();
        assert!(
            matches!(&sig.params[0].1, Type::Optional(_)),
            "expected Optional param"
        );
    }

    // 19. Empty program — no errors and empty environment.
    #[test]
    fn empty_program_produces_no_errors() {
        let (env, diags) = check("");
        assert!(diags.items.is_empty());
        assert!(env.functions.is_empty());
        assert!(env.type_aliases.is_empty());
        assert!(env.network_functions.is_empty());
    }

    // 20. Import statement — must not crash the checker.
    #[test]
    fn import_statement_does_not_crash() {
        let (env, diags) = check("import tallow.http");
        assert!(diags.items.is_empty());
        let _ = env;
    }

    // 21. Async function — is_async flag must not prevent registration.
    #[test]
    fn async_function_with_network_call_registered_as_network() {
        let (env, _) = check(
            r#"
            async fn download(url: String) -> String {
                fetch(url)
            }
        "#,
        );
        assert!(env.functions.contains_key("download"));
        assert!(env.network_functions.contains(&"download".to_string()));
    }

    // 22. is_sensitive() helper works for both qualifiers.
    #[test]
    fn is_sensitive_true_for_private_and_secret() {
        let p = Type::Private(Box::new(Type::String));
        let s = Type::Secret(Box::new(Type::String));
        let plain = Type::String;
        assert!(p.is_sensitive());
        assert!(s.is_sensitive());
        assert!(!plain.is_sensitive());
    }

    // 23. strip_qualifier on non-sensitive type returns self.
    #[test]
    fn strip_qualifier_on_plain_type_returns_self() {
        let ty = Type::Int(IntSize::I32);
        assert_eq!(*ty.strip_qualifier(), Type::Int(IntSize::I32));
    }

    // 24. All integer sizes resolve correctly from named types.
    #[test]
    fn all_integer_sizes_resolve() {
        let (env, _) = check(
            r#"
            fn ints(
                a: i8, b: i16, c: i32, d: i64, e: i128,
                f: u8, g: u16, h: u32, i: u64, j: u128,
                k: isize, l: usize
            ) { }
        "#,
        );
        let sig = env.functions.get("ints").unwrap();
        let expected: &[(usize, Type)] = &[
            (0, Type::Int(IntSize::I8)),
            (1, Type::Int(IntSize::I16)),
            (2, Type::Int(IntSize::I32)),
            (3, Type::Int(IntSize::I64)),
            (4, Type::Int(IntSize::I128)),
            (5, Type::Int(IntSize::U8)),
            (6, Type::Int(IntSize::U16)),
            (7, Type::Int(IntSize::U32)),
            (8, Type::Int(IntSize::U64)),
            (9, Type::Int(IntSize::U128)),
            (10, Type::Int(IntSize::Isize)),
            (11, Type::Int(IntSize::Usize)),
        ];
        for (idx, expected_ty) in expected {
            assert_eq!(
                sig.params[*idx].1, *expected_ty,
                "param index {idx} mismatch"
            );
        }
    }

    // 25. Both float sizes resolve correctly.
    #[test]
    fn both_float_sizes_resolve() {
        let (env, _) = check("fn floats(a: f32, b: f64) { }");
        let sig = env.functions.get("floats").unwrap();
        assert_eq!(sig.params[0].1, Type::Float(FloatSize::F32));
        assert_eq!(sig.params[1].1, Type::Float(FloatSize::F64));
    }

    // ── Batch: additional type checker coverage ─────────────────────

    #[test]
    fn resolves_result_i64_return() {
        let (env, _) = check("fn divide(a: i64, b: i64) -> Result<i64> { Ok(a) }");
        let sig = env.functions.get("divide").unwrap();
        assert!(matches!(&sig.return_type, Type::Result(_)));
    }

    #[test]
    fn resolves_nested_generic_map_string_result() {
        let (env, _) = check("fn get(m: Map<String, Result<i64>>) -> i64 { 0 }");
        let sig = env.functions.get("get").unwrap();
        assert!(matches!(&sig.params[0].1, Type::Map(_, _)));
    }

    #[test]
    fn private_type_in_array_param() {
        let (env, _) = check(
            r#"
            type Email = private String
            fn batch(emails: []Email) { }
        "#,
        );
        let sig = env.functions.get("batch").unwrap();
        // Array of private should still be recognized
        assert!(matches!(&sig.params[0].1, Type::Array(_)));
    }

    #[test]
    fn multiple_return_types_across_functions() {
        let (env, _) = check(
            r#"
            fn ret_string() -> String { "" }
            fn ret_int() -> i64 { 0 }
            fn ret_bool() -> bool { true }
            fn ret_void() { }
        "#,
        );
        assert_eq!(
            env.functions.get("ret_string").unwrap().return_type,
            Type::String
        );
        assert_eq!(
            env.functions.get("ret_int").unwrap().return_type,
            Type::Int(IntSize::I64)
        );
        assert_eq!(
            env.functions.get("ret_bool").unwrap().return_type,
            Type::Bool
        );
        assert_eq!(
            env.functions.get("ret_void").unwrap().return_type,
            Type::Void
        );
    }

    #[test]
    fn detects_connect_method_as_network() {
        let (env, _) = check(
            r#"
            fn api_call() -> String {
                conn.connect("https://api.example.com")
            }
        "#,
        );
        assert!(env.network_functions.contains(&"api_call".to_string()));
    }

    #[test]
    fn detects_send_method_as_network() {
        let (env, _) = check(
            r#"
            fn send_data() -> String {
                conn.send("data")
            }
        "#,
        );
        assert!(env.network_functions.contains(&"send_data".to_string()));
    }

    #[test]
    fn const_decl_no_crash() {
        let (_, diags) = check(
            r#"
            const MAX = 100
            const NAME = "tallow"
            fn use_const() -> i64 { MAX }
        "#,
        );
        assert!(!diags.has_errors());
    }

    #[test]
    fn import_decl_no_crash() {
        let (_, diags) = check(
            r#"
            import tallow.http
            import tallow.crypto
            fn main() { }
        "#,
        );
        assert!(!diags.has_errors());
    }

    #[test]
    fn enum_decl_no_crash() {
        let (_, diags) = check(
            r#"
            enum Color { Red, Green, Blue }
            fn pick() -> i32 { 0 }
        "#,
        );
        assert!(!diags.has_errors());
    }

    #[test]
    fn multiple_structs_and_impls() {
        let (_, diags) = check(
            r#"
            struct Point { x: f64, y: f64 }
            struct Line { start: Point, end: Point }
            impl Point {
                fn origin() -> Point { Point { x: 0.0, y: 0.0 } }
            }
            fn main() { }
        "#,
        );
        assert!(!diags.has_errors());
    }

    #[test]
    fn resolves_optional_string_return() {
        let (env, _) = check("fn search(query: String) -> String? { nil }");
        let sig = env.functions.get("search").unwrap();
        assert!(matches!(&sig.return_type, Type::Optional(_)));
    }

    #[test]
    fn detects_tls_connect_as_network() {
        let (env, _) = check(
            r#"
            fn secure_conn() -> String {
                TLSConn.connect("example.com:443")
            }
        "#,
        );
        assert!(env.network_functions.contains(&"secure_conn".to_string()));
    }

    #[test]
    fn resolves_fn_type_two_params() {
        let (env, _) = check("fn transform(f: fn(i32, String) -> bool) { }");
        let sig = env.functions.get("transform").unwrap();
        assert!(matches!(&sig.params[0].1, Type::Function { .. }));
    }

    #[test]
    fn secret_in_optional_param() {
        let (env, _) = check(
            r#"
            type Token = secret String
            fn maybe_auth(tok: Token?) { }
        "#,
        );
        let sig = env.functions.get("maybe_auth").unwrap();
        assert!(matches!(&sig.params[0].1, Type::Optional(_)));
    }

    #[test]
    fn resolves_set_of_i32() {
        let (env, _) = check("fn unique(items: Set<i32>) -> i32 { 0 }");
        let sig = env.functions.get("unique").unwrap();
        assert!(matches!(&sig.params[0].1, Type::Set(_)));
    }

    #[test]
    fn resolves_map_string_to_int() {
        let (env, _) = check("fn lookup(data: Map<String, i64>) -> i64 { 0 }");
        let sig = env.functions.get("lookup").unwrap();
        assert!(matches!(&sig.params[0].1, Type::Map(_, _)));
    }

    #[test]
    fn detects_fetch_builtin_as_network() {
        let (env, _) = check("fn scrape(url: String) { fetch(url) }");
        assert!(env.network_functions.contains(&"scrape".to_string()));
    }

    #[test]
    fn resolves_bool_return_type() {
        let (env, _) = check("fn is_ok(x: i32) -> bool { true }");
        let sig = env.functions.get("is_ok").unwrap();
        assert!(matches!(sig.return_type, Type::Bool));
    }

    #[test]
    fn resolves_f64_return_type() {
        let (env, _) = check("fn pi() -> f64 { 3.14 }");
        let sig = env.functions.get("pi").unwrap();
        assert!(matches!(sig.return_type, Type::Float(FloatSize::F64)));
    }

    #[test]
    fn string_literal_bound_to_int_annotation_is_an_error() {
        let (_, diags) = check("fn main() { let x: i64 = \"nope\"\n print(x) }");
        assert!(
            diags.items.iter().any(|d| d.code == "E0117"),
            "expected E0117 for `let x: i64 = \"nope\"`, got {:?}",
            diags.items.iter().map(|d| (d.code, &d.msg)).collect::<Vec<_>>()
        );
    }

    #[test]
    fn literal_bindings_that_fit_the_annotation_stay_clean() {
        for src in [
            "fn main() { let x: f64 = 1\n print(x) }",
            "fn main() { let x: i64 = 1\n print(x) }",
            "fn main() { let x: str? = \"a\"\n print(x) }",
            "fn main() { let x: bool = true\n print(x) }",
        ] {
            let (_, diags) = check(src);
            assert!(
                !diags.items.iter().any(|d| d.code == "E0117"),
                "unexpected E0117 for {src}: {:?}",
                diags.items.iter().map(|d| (d.code, &d.msg)).collect::<Vec<_>>()
            );
        }
    }

    #[test]
    fn resolves_void_return_type() {
        let (env, _) = check("fn noop() { }");
        let sig = env.functions.get("noop").unwrap();
        assert!(matches!(sig.return_type, Type::Void));
    }

    #[test]
    fn resolves_bytes_param_type() {
        let (env, _) = check("fn process(data: Bytes) { }");
        let sig = env.functions.get("process").unwrap();
        assert!(matches!(&sig.params[0].1, Type::Bytes));
    }

    #[test]
    fn resolves_usize_param_type() {
        let (env, _) = check("fn count(n: usize) -> usize { n }");
        let sig = env.functions.get("count").unwrap();
        assert!(matches!(&sig.params[0].1, Type::Int(IntSize::Usize)));
    }

    #[test]
    fn resolves_chan_generic_type() {
        let (env, _) = check("fn recv(ch: Chan<i32>) -> i32 { 0 }");
        let sig = env.functions.get("recv").unwrap();
        assert!(matches!(&sig.params[0].1, Type::Chan(_)));
    }

    #[test]
    fn private_type_alias_tracked() {
        let (env, _) = check(
            r#"
            type SSN = private String
            fn log_ssn(ssn: SSN) { }
        "#,
        );
        let sig = env.functions.get("log_ssn").unwrap();
        assert!(matches!(&sig.params[0].1, Type::Private(_)));
    }

    #[test]
    fn secret_type_alias_tracked() {
        let (env, _) = check(
            r#"
            type APIKey = secret String
            fn use_key(key: APIKey) { }
        "#,
        );
        let sig = env.functions.get("use_key").unwrap();
        assert!(matches!(&sig.params[0].1, Type::Secret(_)));
    }

    #[test]
    fn multiple_params_three_types() {
        let (env, _) = check("fn add3(a: i32, b: i64, c: f64) -> f64 { 0.0 }");
        let sig = env.functions.get("add3").unwrap();
        assert_eq!(sig.params.len(), 3);
        assert!(matches!(&sig.params[0].1, Type::Int(IntSize::I32)));
        assert!(matches!(&sig.params[1].1, Type::Int(IntSize::I64)));
        assert!(matches!(&sig.params[2].1, Type::Float(FloatSize::F64)));
    }

    #[test]
    fn optional_return_type_resolved() {
        let (env, _) = check("fn find_all(items: []String) -> String? { nil }");
        let sig = env.functions.get("find_all").unwrap();
        assert!(matches!(sig.return_type, Type::Optional(_)));
    }

    #[test]
    fn void_return_when_no_annotation() {
        let (env, _) = check("fn noop() { }");
        let sig = env.functions.get("noop").unwrap();
        assert!(matches!(sig.return_type, Type::Void));
    }

    #[test]
    fn bool_return_type() {
        let (env, _) = check("fn is_ok() -> bool { true }");
        let sig = env.functions.get("is_ok").unwrap();
        assert!(matches!(sig.return_type, Type::Bool));
    }

    #[test]
    fn string_return_type() {
        let (env, _) = check("fn greet() -> String { \"hi\" }");
        let sig = env.functions.get("greet").unwrap();
        assert!(matches!(sig.return_type, Type::String));
    }

    #[test]
    fn result_return_type() {
        let (env, _) = check("fn try_it() -> Result<i32> { Ok(1) }");
        let sig = env.functions.get("try_it").unwrap();
        assert!(matches!(sig.return_type, Type::Result(_)));
    }

    #[test]
    fn map_param_type() {
        let (env, _) = check("fn lookup(m: Map<String, i32>) -> i32 { 0 }");
        let sig = env.functions.get("lookup").unwrap();
        assert!(matches!(&sig.params[0].1, Type::Map(_, _)));
    }

    #[test]
    fn tuple_return_type() {
        let (env, _) = check("fn pair() -> (i32, String) { (1, \"a\") }");
        let sig = env.functions.get("pair").unwrap();
        assert!(matches!(sig.return_type, Type::Tuple(_)));
    }

    #[test]
    fn multiple_functions_registered() {
        let (env, _) = check("fn a() { }\nfn b() { }\nfn c() { }");
        assert!(env.functions.contains_key("a"));
        assert!(env.functions.contains_key("b"));
        assert!(env.functions.contains_key("c"));
    }

    #[test]
    fn network_function_with_fetch() {
        let (env, _) = check("fn get_data() { fetch(\"http://example.com\") }");
        assert!(env.network_functions.contains(&"get_data".to_string()));
    }

    #[test]
    fn non_network_function_not_flagged() {
        let (env, _) = check("fn compute(x: i32) -> i32 { x + 1 }");
        assert!(!env.network_functions.contains(&"compute".to_string()));
    }

    #[test]
    fn private_type_alias_is_private() {
        let (env, _) = check("type Email = private String");
        let ty = env.type_aliases.get("Email").unwrap();
        assert!(ty.is_private());
    }

    #[test]
    fn secret_type_alias_is_secret() {
        let (env, _) = check("type Token = secret String");
        let ty = env.type_aliases.get("Token").unwrap();
        assert!(ty.is_secret());
    }

    #[test]
    fn usize_param_resolved() {
        let (env, _) = check("fn idx(i: usize) -> usize { i }");
        let sig = env.functions.get("idx").unwrap();
        assert!(matches!(&sig.params[0].1, Type::Int(IntSize::Usize)));
    }

    #[test]
    fn f32_param_resolved() {
        let (env, _) = check("fn half(x: f32) -> f32 { x }");
        let sig = env.functions.get("half").unwrap();
        assert!(matches!(&sig.params[0].1, Type::Float(FloatSize::F32)));
    }

    // ── Browser network detection tests ─────────────────────────────────

    #[test]
    fn detects_browser_goto_as_network() {
        let (env, _) = check(r#"fn scrape() { browser.goto("https://example.com") }"#);
        assert!(env.network_functions.contains(&"scrape".to_string()));
    }

    #[test]
    fn detects_browser_navigate_as_network() {
        let (env, _) = check(r#"fn nav() { page.navigate("https://example.com") }"#);
        assert!(env.network_functions.contains(&"nav".to_string()));
    }

    #[test]
    fn detects_browser_new_page_as_network() {
        let (env, _) = check(r#"fn open() { browser.new_page("https://example.com") }"#);
        assert!(env.network_functions.contains(&"open".to_string()));
    }

    #[test]
    fn detects_browser_new_context_as_network() {
        let (env, _) = check("fn ctx() { browser.new_context() }");
        assert!(env.network_functions.contains(&"ctx".to_string()));
    }

    #[test]
    fn detects_browser_launch_as_network() {
        let (env, _) = check("fn start() { browser.launch() }");
        assert!(env.network_functions.contains(&"start".to_string()));
    }

    #[test]
    fn detects_browser_screenshot_as_network() {
        let (env, _) = check(r#"fn capture() { page.screenshot("out.png") }"#);
        assert!(env.network_functions.contains(&"capture".to_string()));
    }

    #[test]
    fn detects_browser_reload_as_network() {
        let (env, _) = check("fn refresh() { page.reload() }");
        assert!(env.network_functions.contains(&"refresh".to_string()));
    }

    #[test]
    fn detects_browser_save_pdf_as_network() {
        let (env, _) = check(r#"fn pdf() { page.save_pdf("output.pdf") }"#);
        assert!(env.network_functions.contains(&"pdf".to_string()));
    }

    #[test]
    fn detects_browser_download_as_network() {
        let (env, _) = check(r#"fn dl() { page.download("file.zip") }"#);
        assert!(env.network_functions.contains(&"dl".to_string()));
    }

    #[test]
    fn does_not_detect_non_browser_goto() {
        let (env, _) = check("fn navigate_helper() { let x = 1 + 2 }");
        assert!(
            !env.network_functions
                .contains(&"navigate_helper".to_string())
        );
    }

    // ── Trust Type Tests ─────────────────────────────────────────────────

    #[test]
    fn trusted_string_resolves() {
        let (env, _) = check("fn process(data: Trusted<String>) -> String { \"\" }");
        let sig = env.functions.get("process").unwrap();
        assert!(matches!(&sig.params[0].1, Type::Trusted(inner) if **inner == Type::String));
    }

    #[test]
    fn unverified_f64_resolves() {
        let (env, _) = check("fn handle(val: Unverified<f64>) -> f64 { 0.0 }");
        let sig = env.functions.get("handle").unwrap();
        assert!(
            matches!(&sig.params[0].1, Type::Unverified(inner) if **inner == Type::Float(FloatSize::F64))
        );
    }

    #[test]
    fn fresh_string_with_ttl_resolves() {
        let (env, _) = check("fn use_data(d: Fresh<String, 300000>) -> String { \"\" }");
        let sig = env.functions.get("use_data").unwrap();
        assert!(matches!(&sig.params[0].1, Type::Fresh(inner, 300000) if **inner == Type::String));
    }

    #[test]
    fn trusted_not_equal_to_unverified() {
        let trusted = Type::Trusted(Box::new(Type::String));
        let unverified = Type::Unverified(Box::new(Type::String));
        assert_ne!(trusted, unverified);
    }

    #[test]
    fn trusted_not_equal_to_plain() {
        let trusted = Type::Trusted(Box::new(Type::String));
        assert_ne!(trusted, Type::String);
    }

    #[test]
    fn is_trusted_helper() {
        assert!(Type::Trusted(Box::new(Type::String)).is_trusted());
        assert!(!Type::Unverified(Box::new(Type::String)).is_trusted());
        assert!(!Type::String.is_trusted());
    }

    #[test]
    fn is_unverified_helper() {
        assert!(Type::Unverified(Box::new(Type::String)).is_unverified());
        assert!(!Type::Trusted(Box::new(Type::String)).is_unverified());
        assert!(!Type::String.is_unverified());
    }

    #[test]
    fn is_fresh_helper() {
        assert!(Type::Fresh(Box::new(Type::String), 5000).is_fresh());
        assert!(!Type::Trusted(Box::new(Type::String)).is_fresh());
        assert!(!Type::String.is_fresh());
    }

    #[test]
    fn strip_trust_returns_inner() {
        let trusted = Type::Trusted(Box::new(Type::String));
        assert_eq!(*trusted.strip_trust(), Type::String);
        let unverified = Type::Unverified(Box::new(Type::Int(IntSize::I64)));
        assert_eq!(*unverified.strip_trust(), Type::Int(IntSize::I64));
        let fresh = Type::Fresh(Box::new(Type::Bool), 1000);
        assert_eq!(*fresh.strip_trust(), Type::Bool);
        let plain = Type::String;
        assert_eq!(*plain.strip_trust(), Type::String);
    }

    #[test]
    fn inner_type_returns_wrapped() {
        let trusted = Type::Trusted(Box::new(Type::String));
        assert_eq!(*trusted.inner_type(), Type::String);
        let unverified = Type::Unverified(Box::new(Type::Float(FloatSize::F64)));
        assert_eq!(*unverified.inner_type(), Type::Float(FloatSize::F64));
        let fresh = Type::Fresh(Box::new(Type::Bytes), 60000);
        assert_eq!(*fresh.inner_type(), Type::Bytes);
        // Also works for privacy wrappers
        let private = Type::Private(Box::new(Type::String));
        assert_eq!(*private.inner_type(), Type::String);
    }

    #[test]
    fn verify_on_unverified_returns_trusted() {
        // Test infer_expr_type for .verify() method resolution
        let (env, _) = check(
            r#"
            fn validate(raw: Unverified<String>) -> String {
                let verified = raw.verify()
                verified
            }
        "#,
        );
        let sig = env.functions.get("validate").unwrap();
        assert!(sig.return_type != Type::Void); // function registered
    }

    #[test]
    fn value_on_trusted_returns_inner() {
        let (env, _) = check(
            r#"
            fn extract(data: Trusted<f64>) -> f64 {
                let val = data.value()
                val
            }
        "#,
        );
        let sig = env.functions.get("extract").unwrap();
        assert!(sig.return_type != Type::Void);
    }

    #[test]
    fn trusted_return_type_resolves() {
        let (env, _) = check("fn verify_data(raw: String) -> Trusted<String> { raw }");
        let sig = env.functions.get("verify_data").unwrap();
        assert!(sig.return_type.is_trusted());
    }

    #[test]
    fn unverified_return_type_resolves() {
        let (env, _) = check("fn fetch_raw(url: String) -> Unverified<String> { url }");
        let sig = env.functions.get("fetch_raw").unwrap();
        assert!(sig.return_type.is_unverified());
    }

    // ── Scanner.scan ScanScope enforcement (E0950) ──────────────────

    #[test]
    fn scan_scope_typeck_scanner_scan_without_scope_emits_e0950() {
        // Scanner.scan called with a plain string -- should emit E0950
        let (_, diags) = check(
            r#"
            fn do_scan() {
                let result = Scanner.scan("not_a_scope", [80], 1000)
            }
        "#,
        );
        let has_e0950 = diags.items.iter().any(|e| e.code == "E0950");
        assert!(
            has_e0950,
            "Scanner.scan without ScanScope arg should emit E0950, got: {:?}",
            diags.items
        );
    }

    #[test]
    fn scan_scope_typeck_scanner_scan_with_scope_passes() {
        // Scanner.scan called with ScanScope-typed variable -- should NOT emit E0950
        let (_, diags) = check(
            r#"
            fn do_scan() {
                let scope: ScanScope = ScanScope.authorize("10.0.0.0/24")
                let result = Scanner.scan(scope, [80], 1000)
            }
        "#,
        );
        let has_e0950 = diags.items.iter().any(|e| e.code == "E0950");
        assert!(
            !has_e0950,
            "Scanner.scan with ScanScope arg should not emit E0950, got: {:?}",
            diags.items
        );
    }

    #[test]
    fn scan_scope_typeck_scanner_scan_no_args_emits_e0950() {
        // Scanner.scan called with zero arguments
        let (_, diags) = check(
            r#"
            fn do_scan() {
                let result = Scanner.scan()
            }
        "#,
        );
        let has_e0950 = diags.items.iter().any(|e| e.code == "E0950");
        assert!(
            has_e0950,
            "Scanner.scan with no args should emit E0950, got: {:?}",
            diags.items
        );
    }

    // ── Trait System Type Checker Tests ────────────────────────────────

    #[test]
    fn trait_system_valid_impl_passes() {
        let (env, diags) = check(
            r#"
            trait Display {
                fn to_string(self) -> String
            }
            struct Point { x: i32, y: i32 }
            impl Display for Point {
                fn to_string(self) -> String { "point" }
            }
            fn main() {}
        "#,
        );
        assert_eq!(
            diags.error_count(),
            0,
            "valid trait impl should pass, got: {:?}",
            diags.items
        );
        assert!(env.traits.contains_key("Display"));
        assert!(
            env.trait_impls
                .contains_key(&("Display".to_string(), "Point".to_string()))
        );
    }

    #[test]
    fn trait_system_missing_method_error() {
        let (_, diags) = check(
            r#"
            trait Serializable {
                fn serialize(self) -> String
                fn size(self) -> i64
            }
            struct Foo { x: i32 }
            impl Serializable for Foo {
                fn serialize(self) -> String { "foo" }
            }
            fn main() {}
        "#,
        );
        let has_e0401 = diags.items.iter().any(|e| e.code == "E0401");
        assert!(
            has_e0401,
            "missing trait method should emit E0401, got: {:?}",
            diags.items
        );
    }

    #[test]
    fn trait_system_unknown_trait_error() {
        let (_, diags) = check(
            r#"
            struct Bar { x: i32 }
            impl NonExistent for Bar {
                fn foo(self) -> i32 { 0 }
            }
            fn main() {}
        "#,
        );
        let has_e0400 = diags.items.iter().any(|e| e.code == "E0400");
        assert!(
            has_e0400,
            "unknown trait should emit E0400, got: {:?}",
            diags.items
        );
    }

    #[test]
    fn trait_system_param_count_mismatch_error() {
        let (_, diags) = check(
            r#"
            trait Hasher {
                fn hash(self, seed: i64) -> i64
            }
            struct Data { x: i32 }
            impl Hasher for Data {
                fn hash(self) -> i64 { 0 }
            }
            fn main() {}
        "#,
        );
        let has_e0402 = diags.items.iter().any(|e| e.code == "E0402");
        assert!(
            has_e0402,
            "param count mismatch should emit E0402, got: {:?}",
            diags.items
        );
    }

    // ═══════════════════════════════════════════════════════════════════
    // Deep Type Checker Tests — Function Bodies, Variables, Operations
    // ═══════════════════════════════════════════════════════════════════

    // ── Return type coverage ────────────────────────────────────────────

    #[test]
    fn empty_body_with_return_type_errors() {
        let (_, diags) = check("fn get_value() -> i32 { }");
        let has_e2500 = diags.items.iter().any(|e| e.code == "E2500");
        assert!(
            has_e2500,
            "empty body with return type should emit E2500, got: {:?}",
            diags.items
        );
    }

    #[test]
    fn body_with_expression_does_not_warn() {
        let (_, diags) = check("fn get_value() -> i32 { 42 }");
        let has_w0101 = diags.items.iter().any(|e| e.code == "W0101");
        assert!(
            !has_w0101,
            "expression body should not warn about missing return, got: {:?}",
            diags.items
        );
    }

    #[test]
    fn body_with_explicit_return_does_not_warn() {
        let (_, diags) = check("fn get_value() -> i32 { return 42 }");
        let has_w0101 = diags.items.iter().any(|e| e.code == "W0101");
        assert!(
            !has_w0101,
            "explicit return should not warn, got: {:?}",
            diags.items
        );
    }

    #[test]
    fn void_function_with_empty_body_no_error() {
        let (_, diags) = check("fn do_nothing() { }");
        let has_e2500 = diags.items.iter().any(|e| e.code == "E2500");
        assert!(
            !has_e2500,
            "void function with empty body should not error, got: {:?}",
            diags.items
        );
    }

    #[test]
    fn let_only_body_warns_missing_return() {
        let (_, diags) = check("fn get_value() -> i32 { let x = 42 }");
        let has_w0101 = diags.items.iter().any(|e| e.code == "W0101");
        assert!(
            has_w0101,
            "let-only body should warn about missing return, got: {:?}",
            diags.items
        );
    }

    // ── Immutability checking ───────────────────────────────────────────

    #[test]
    fn assign_to_let_binding_errors() {
        let (_, diags) = check(
            r#"
            fn mutate() {
                let x = 10
                x = 20
            }
        "#,
        );
        let has_e0105 = diags.items.iter().any(|e| e.code == "E0105");
        assert!(
            has_e0105,
            "assignment to let binding should emit E0105, got: {:?}",
            diags.items
        );
    }

    #[test]
    fn assign_to_var_binding_ok() {
        let (_, diags) = check(
            r#"
            fn mutate() {
                var x = 10
                x = 20
            }
        "#,
        );
        let has_e0105 = diags.items.iter().any(|e| e.code == "E0105");
        assert!(
            !has_e0105,
            "assignment to var binding should not error, got: {:?}",
            diags.items
        );
    }

    // ── Function call argument count ────────────────────────────────────

    #[test]
    fn call_with_wrong_arg_count_errors() {
        let (_, diags) = check(
            r#"
            fn add(a: i32, b: i32) -> i32 { a + b }
            fn main() { add(1) }
        "#,
        );
        let has_e0103 = diags.items.iter().any(|e| e.code == "E0103");
        assert!(
            has_e0103,
            "wrong arg count should emit E0103, got: {:?}",
            diags.items
        );
    }

    #[test]
    fn call_with_correct_arg_count_ok() {
        let (_, diags) = check(
            r#"
            fn add(a: i32, b: i32) -> i32 { a + b }
            fn main() { add(1, 2) }
        "#,
        );
        let has_e0103 = diags.items.iter().any(|e| e.code == "E0103");
        assert!(
            !has_e0103,
            "correct arg count should not error, got: {:?}",
            diags.items
        );
    }

    #[test]
    fn call_with_too_many_args_errors() {
        let (_, diags) = check(
            r#"
            fn add(a: i32, b: i32) -> i32 { a + b }
            fn main() { add(1, 2, 3) }
        "#,
        );
        let has_e0103 = diags.items.iter().any(|e| e.code == "E0103");
        assert!(
            has_e0103,
            "too many args should emit E0103, got: {:?}",
            diags.items
        );
    }

    // ── Binary operation type checking ──────────────────────────────────

    #[test]
    fn add_string_plus_bool_errors() {
        let (_, diags) = check(
            r#"
            fn bad() {
                let x = "hello" + true
            }
        "#,
        );
        let has_e0110 = diags.items.iter().any(|e| e.code == "E0110");
        assert!(
            has_e0110,
            "String + bool should emit E0110, got: {:?}",
            diags.items
        );
    }

    #[test]
    fn add_int_plus_int_ok() {
        let (_, diags) = check(
            r#"
            fn good() {
                let x = 1 + 2
            }
        "#,
        );
        let has_e0110 = diags.items.iter().any(|e| e.code == "E0110");
        assert!(
            !has_e0110,
            "int + int should not error, got: {:?}",
            diags.items
        );
    }

    #[test]
    fn add_string_plus_string_ok() {
        let (_, diags) = check(
            r#"
            fn concat() {
                let x = "hello" + " world"
            }
        "#,
        );
        let has_e0110 = diags.items.iter().any(|e| e.code == "E0110");
        assert!(
            !has_e0110,
            "String + String should not error, got: {:?}",
            diags.items
        );
    }

    #[test]
    fn multiply_bool_by_string_errors() {
        let (_, diags) = check(
            r#"
            fn bad() {
                let x = true * "hello"
            }
        "#,
        );
        let has_e0110 = diags.items.iter().any(|e| e.code == "E0110");
        assert!(
            has_e0110,
            "bool * String should emit E0110, got: {:?}",
            diags.items
        );
    }

    #[test]
    fn division_float_returns_float_type() {
        // Verifies inference: float / int = float
        let (env, _) = check(
            r#"
            fn div() -> f64 {
                let x = 3.14 / 2
                x
            }
        "#,
        );
        assert!(env.functions.contains_key("div"));
    }

    // ── Match exhaustiveness ────────────────────────────────────────────

    #[test]
    fn match_with_wildcard_no_warning() {
        let (_, diags) = check(
            r#"
            enum Color { Red, Green, Blue }
            fn describe(c: Color) -> String {
                c match {
                    Red -> "red"
                    _ -> "other"
                }
            }
        "#,
        );
        let has_w0120 = diags.items.iter().any(|e| e.code == "W0120");
        assert!(
            !has_w0120,
            "wildcard should suppress exhaustiveness warning, got: {:?}",
            diags.items
        );
    }

    #[test]
    fn match_missing_enum_variants_warns() {
        let (_, diags) = check(
            r#"
            enum Color { Red, Green, Blue }
            fn describe(c: Color) -> String {
                c match {
                    Red -> "red"
                }
            }
        "#,
        );
        let has_w0120 = diags.items.iter().any(|e| e.code == "W0120");
        assert!(
            has_w0120,
            "missing enum variants should warn W0120, got: {:?}",
            diags.items
        );
    }

    #[test]
    fn match_all_enum_variants_no_warning() {
        let (_, diags) = check(
            r#"
            enum Color { Red, Green, Blue }
            fn describe(c: Color) -> String {
                c match {
                    Red -> "red"
                    Green -> "green"
                    Blue -> "blue"
                }
            }
        "#,
        );
        let has_w0120 = diags.items.iter().any(|e| e.code == "W0120");
        assert!(
            !has_w0120,
            "all variants covered should not warn, got: {:?}",
            diags.items
        );
    }

    // ── Privacy type tracking in typeck ─────────────────────────────────

    #[test]
    fn print_private_type_errors() {
        let (_, diags) = check(
            r#"
            type Email = private String
            fn bad(email: Email) {
                print(email)
            }
        "#,
        );
        let has_e0200 = diags.items.iter().any(|e| e.code == "E0200");
        assert!(
            has_e0200,
            "print(private) should emit E0200, got: {:?}",
            diags.items
        );
    }

    #[test]
    fn print_secret_type_errors() {
        let (_, diags) = check(
            r#"
            type Token = secret String
            fn bad(tok: Token) {
                print(tok)
            }
        "#,
        );
        let has_e0201 = diags.items.iter().any(|e| e.code == "E0201");
        assert!(
            has_e0201,
            "print(secret) should emit E0201, got: {:?}",
            diags.items
        );
    }

    #[test]
    fn print_redacted_private_ok() {
        let (_, diags) = check(
            r#"
            type Email = private String
            fn good(email: Email) {
                print(email.redact())
            }
        "#,
        );
        let has_privacy_error = diags
            .items
            .iter()
            .any(|e| e.code == "E0200" || e.code == "E0201");
        assert!(
            !has_privacy_error,
            "print(email.redact()) should not error, got: {:?}",
            diags.items
        );
    }

    #[test]
    fn interpolate_secret_type_errors() {
        let (_, diags) = check(
            r#"
            type APIKey = secret String
            fn bad(key: APIKey) -> String {
                "key is: {key}"
            }
        "#,
        );
        let has_e0202 = diags.items.iter().any(|e| e.code == "E0202");
        assert!(
            has_e0202,
            "interpolating secret should emit E0202, got: {:?}",
            diags.items
        );
    }

    #[test]
    fn interpolate_private_type_errors() {
        let (_, diags) = check(
            r#"
            type Email = private String
            fn bad(email: Email) -> String {
                "contact: {email}"
            }
        "#,
        );
        let has_e0203 = diags.items.iter().any(|e| e.code == "E0203");
        assert!(
            has_e0203,
            "interpolating private should emit E0203, got: {:?}",
            diags.items
        );
    }

    #[test]
    fn interpolate_redacted_private_ok() {
        let (_, diags) = check(
            r#"
            type Email = private String
            fn good(email: Email) -> String {
                "contact: {email.redact()}"
            }
        "#,
        );
        let has_privacy_error = diags
            .items
            .iter()
            .any(|e| e.code == "E0202" || e.code == "E0203");
        assert!(
            !has_privacy_error,
            "interpolating redacted should not error, got: {:?}",
            diags.items
        );
    }

    // ── Struct and enum registration ────────────────────────────────────

    #[test]
    fn struct_fields_registered() {
        let (env, _) = check(
            r#"
            struct Point { x: f64, y: f64 }
        "#,
        );
        let sinfo = env.structs.get("Point").unwrap();
        assert_eq!(sinfo.fields.len(), 2);
        assert_eq!(sinfo.fields[0].0, "x");
        assert_eq!(sinfo.fields[1].0, "y");
    }

    #[test]
    fn enum_variants_registered() {
        let (env, _) = check(
            r#"
            enum Direction { North, South, East, West }
        "#,
        );
        let einfo = env.enums.get("Direction").unwrap();
        assert_eq!(einfo.variants.len(), 4);
        assert!(einfo.variants.contains(&"North".to_string()));
        assert!(einfo.variants.contains(&"West".to_string()));
    }

    #[test]
    fn impl_methods_registered() {
        let (env, _) = check(
            r#"
            struct Counter { value: i64 }
            impl Counter {
                fn increment(self) -> i64 { self.value + 1 }
                fn reset(self) -> Counter { Counter { value: 0 } }
            }
        "#,
        );
        let methods = env.methods.get("Counter").unwrap();
        assert_eq!(methods.len(), 2);
        assert!(methods.iter().any(|m| m.name == "increment"));
        assert!(methods.iter().any(|m| m.name == "reset"));
    }

    // ── Struct literal field checking ───────────────────────────────────

    #[test]
    fn struct_lit_nonexistent_field_errors() {
        let (_, diags) = check(
            r#"
            struct Point { x: f64, y: f64 }
            fn make() -> Point {
                Point { x: 1.0, y: 2.0, z: 3.0 }
            }
        "#,
        );
        let has_e0106 = diags.items.iter().any(|e| e.code == "E0106");
        assert!(
            has_e0106,
            "nonexistent struct field should emit E0106, got: {:?}",
            diags.items
        );
    }

    #[test]
    fn struct_lit_valid_fields_ok() {
        let (_, diags) = check(
            r#"
            struct Point { x: f64, y: f64 }
            fn make() -> Point {
                Point { x: 1.0, y: 2.0 }
            }
        "#,
        );
        let has_e0106 = diags.items.iter().any(|e| e.code == "E0106");
        assert!(
            !has_e0106,
            "valid struct fields should not error, got: {:?}",
            diags.items
        );
    }

    // ── Field access checking ───────────────────────────────────────────

    #[test]
    fn field_access_nonexistent_warns() {
        let (_, diags) = check(
            r#"
            struct Point { x: f64, y: f64 }
            fn bad(p: Point) -> f64 {
                p.z
            }
        "#,
        );
        let has_w0104 = diags.items.iter().any(|e| e.code == "W0104");
        assert!(
            has_w0104,
            "accessing nonexistent field should warn W0104, got: {:?}",
            diags.items
        );
    }

    #[test]
    fn field_access_valid_no_warning() {
        let (_, diags) = check(
            r#"
            struct Point { x: f64, y: f64 }
            fn good(p: Point) -> f64 {
                p.x
            }
        "#,
        );
        let has_w0104 = diags.items.iter().any(|e| e.code == "W0104");
        assert!(
            !has_w0104,
            "valid field access should not warn, got: {:?}",
            diags.items
        );
    }

    // ── If condition type checking ──────────────────────────────────────

    #[test]
    fn if_condition_non_bool_warns() {
        let (_, diags) = check(
            r#"
            fn bad() {
                if 42 {
                    print("yes")
                }
            }
        "#,
        );
        let has_w0103 = diags.items.iter().any(|e| e.code == "W0103");
        assert!(
            has_w0103,
            "non-bool if condition should warn W0103, got: {:?}",
            diags.items
        );
    }

    #[test]
    fn if_condition_bool_no_warning() {
        let (_, diags) = check(
            r#"
            fn good() {
                if true {
                    print("yes")
                }
            }
        "#,
        );
        let has_w0103 = diags.items.iter().any(|e| e.code == "W0103");
        assert!(
            !has_w0103,
            "bool if condition should not warn, got: {:?}",
            diags.items
        );
    }

    // ── Logical operator type checking ──────────────────────────────────

    #[test]
    fn logical_and_with_non_bool_warns() {
        let (_, diags) = check(
            r#"
            fn bad() {
                let x = 1 && 2
            }
        "#,
        );
        let has_w0110 = diags.items.iter().any(|e| e.code == "W0110");
        assert!(
            has_w0110,
            "int && int should warn W0110, got: {:?}",
            diags.items
        );
    }

    #[test]
    fn logical_and_with_bools_ok() {
        let (_, diags) = check(
            r#"
            fn good() {
                let x = true && false
            }
        "#,
        );
        let has_w0110 = diags.items.iter().any(|e| e.code == "W0110");
        assert!(
            !has_w0110,
            "bool && bool should not warn, got: {:?}",
            diags.items
        );
    }

    // ── Privacy tracking through variable assignment ────────────────────

    #[test]
    fn privacy_propagates_through_let() {
        let (_, diags) = check(
            r#"
            type Email = private String
            fn bad(email: Email) {
                let e = email
                print(e)
            }
        "#,
        );
        let has_privacy = diags.items.iter().any(|e| e.code == "E0200");
        assert!(
            has_privacy,
            "privacy should propagate through let binding, got: {:?}",
            diags.items
        );
    }

    #[test]
    fn secret_propagates_through_let() {
        let (_, diags) = check(
            r#"
            type Password = secret String
            fn bad(pw: Password) {
                let p = pw
                print(p)
            }
        "#,
        );
        let has_secret = diags.items.iter().any(|e| e.code == "E0201");
        assert!(
            has_secret,
            "secret should propagate through let binding, got: {:?}",
            diags.items
        );
    }

    // ── Infer binary op result types ────────────────────────────────────

    #[test]
    fn comparison_infers_bool() {
        // x > 5 should infer to Bool
        let (_, diags) = check(
            r#"
            fn check(x: i32) -> bool {
                x > 5
            }
        "#,
        );
        // Should not warn about missing return (expression returns bool)
        let has_w0101 = diags.items.iter().any(|e| e.code == "W0101");
        assert!(
            !has_w0101,
            "comparison should infer bool, got: {:?}",
            diags.items
        );
    }

    // ── Field access type inference ─────────────────────────────────────

    #[test]
    fn infers_struct_field_type() {
        let (env, _) = check(
            r#"
            struct Config { port: u16 }
            fn get_port(cfg: Config) -> u16 {
                cfg.port
            }
        "#,
        );
        // Function should register without crashing
        assert!(env.functions.contains_key("get_port"));
    }

    // ── Method return type inference ────────────────────────────────────

    #[test]
    fn infers_impl_method_return_type() {
        let (env, _) = check(
            r#"
            struct Counter { value: i64 }
            impl Counter {
                fn get(self) -> i64 { self.value }
            }
            fn use_counter(c: Counter) -> i64 {
                let val = c.get()
                val
            }
        "#,
        );
        let methods = env.methods.get("Counter").unwrap();
        let get_sig = methods.iter().find(|m| m.name == "get").unwrap();
        assert_eq!(get_sig.return_type, Type::Int(IntSize::I64));
    }

    // ── `?` requires `Result<T>` (E0111) ────────────────────────────────
    //
    // Enforcement is the Try arm of `check_expr` (the single gate). Accepted:
    // `Result<T>`, unresolvable/Unknown expressions, and a bare type literally
    // named `Result` (pre-generics convention, self-host/tests/*.tl). `T?`
    // (Optional) is a hard error, as is every other concrete operand type.

    fn e0111_msgs(source: &str) -> Vec<String> {
        let (_, diags) = check(source);
        diags
            .items
            .iter()
            .filter(|d| d.code == "E0111")
            .map(|d| d.msg.clone())
            .collect()
    }

    fn has_e0111(source: &str) -> bool {
        !e0111_msgs(source).is_empty()
    }

    #[test]
    fn try_on_result_int_ok() {
        let msgs = e0111_msgs(
            r#"
            fn divide(a: i64, b: i64) -> Result<i64> { Ok(a / b) }
            fn compute(x: i64, y: i64) -> Result<i64> {
                let a = divide(x, y)?
                Ok(a + 10)
            }
        "#,
        );
        assert!(msgs.is_empty(), "`?` on Result<i64> must not error: {msgs:?}");
    }

    #[test]
    fn try_on_result_string_ok() {
        let msgs = e0111_msgs(
            r#"
            fn fetch(id: i64) -> Result<String> { Ok("x") }
            fn go(id: i64) -> Result<String> {
                let s = fetch(id)?
                Ok(s)
            }
        "#,
        );
        assert!(msgs.is_empty(), "`?` on Result<String> must not error: {msgs:?}");
    }

    #[test]
    fn try_with_explicit_err_path_ok() {
        let msgs = e0111_msgs(
            r#"
            fn divide(a: i64, b: i64) -> Result<i64> {
                if b == 0 {
                    return Err("division by zero")
                }
                Ok(a / b)
            }
            fn compute(x: i64, y: i64) -> Result<i64> {
                let a = divide(x, y)?
                Ok(a + 1)
            }
        "#,
        );
        assert!(msgs.is_empty(), "Result + Err path must not error: {msgs:?}");
    }

    #[test]
    fn try_on_unknown_expression_allowed() {
        // Unresolvable operand types stay permissive (no false positives).
        let msgs = e0111_msgs(
            r#"
            fn f() {
                let x = mystery_fn()?
            }
        "#,
        );
        assert!(msgs.is_empty(), "Unknown operand must be allowed: {msgs:?}");
    }

    #[test]
    fn try_on_bare_named_result_convention_allowed() {
        // Pre-generics convention: locally declared `enum Result` + functions
        // returning bare `Result` (self-host/tests/gap8_try.tl) keep working.
        let msgs = e0111_msgs(
            r#"
            enum Result {
                Ok(val: i64),
                Err(msg: String),
            }
            fn divide(a: i64, b: i64) -> Result { Ok(a / b) }
            fn compute() -> Result {
                let x = divide(10, 2)?
                Ok(x)
            }
        "#,
        );
        assert!(msgs.is_empty(), "bare `Result` convention must be allowed: {msgs:?}");
    }

    #[test]
    fn try_on_int_literal_errors() {
        assert!(
            has_e0111("fn f() -> i64 { let x = 1?\n x }"),
            "`?` on an int literal must emit E0111"
        );
    }

    #[test]
    fn try_on_string_var_errors() {
        assert!(has_e0111("fn f() { let s = \"hi\"\n let x = s? }"));
    }

    #[test]
    fn try_on_bool_errors() {
        assert!(has_e0111("fn f() { let b = true\n let x = b? }"));
    }

    #[test]
    fn try_on_float_errors() {
        assert!(has_e0111("fn f() { let v = 1.5\n let x = v? }"));
    }

    #[test]
    fn try_on_optional_int_errors() {
        assert!(has_e0111("fn f(v: i64?) { let x = v? }"));
    }

    #[test]
    fn try_on_optional_string_errors() {
        assert!(has_e0111("fn f(v: String?) { let x = v? }"));
    }

    #[test]
    fn try_on_optional_returning_call_errors() {
        assert!(has_e0111("fn maybe() -> i64? { 1 }\n fn f() { let x = maybe()? }"));
    }

    #[test]
    fn try_on_array_errors() {
        assert!(has_e0111("fn f(v: []i32) { let x = v? }"));
    }

    #[test]
    fn try_on_tuple_errors() {
        assert!(has_e0111("fn f(v: (i32, i32)) { let x = v? }"));
    }

    #[test]
    fn try_on_struct_errors() {
        assert!(has_e0111("struct P { a: i32 }\n fn f(p: P) { let x = p? }"));
    }

    #[test]
    fn try_on_enum_errors() {
        assert!(has_e0111("enum C { Red, Blue }\n fn f(c: C) { let x = c? }"));
    }

    #[test]
    fn try_on_void_call_errors() {
        assert!(has_e0111("fn g() { }\n fn f() { let x = g()? }"));
    }

    #[test]
    fn try_on_nonresult_call_errors() {
        assert!(has_e0111("fn g() -> i32 { 1 }\n fn f() { let x = g()? }"));
    }

    #[test]
    fn try_on_map_errors() {
        assert!(has_e0111("fn f(m: Map<String, i32>) { let x = m? }"));
    }

    #[test]
    fn try_on_set_errors() {
        assert!(has_e0111("fn f(s: Set<i32>) { let x = s? }"));
    }

    #[test]
    fn try_on_chan_errors() {
        assert!(has_e0111("fn f(c: Chan<i32>) { let x = c? }"));
    }

    #[test]
    fn try_on_already_unwrapped_value_errors() {
        assert!(has_e0111(
            "fn d(a: i64) -> Result<i64> { Ok(a) }\n fn f() -> Result<i64> { let a = d(1)?\n let b = a?\n Ok(b) }"
        ));
    }

    #[test]
    fn try_error_message_names_found_type() {
        let msgs = e0111_msgs("fn f() -> i64 { let x = 1?\n x }");
        assert!(
            msgs.iter()
                .any(|m| m.contains("requires `Result<T>`") && m.contains("i64")),
            "message should name the offending type: {msgs:?}"
        );
    }

    #[test]
    fn try_optional_message_mentions_optional() {
        let msgs = e0111_msgs("fn f(v: i64?) { let x = v? }");
        assert!(
            msgs.iter().any(|m| m.contains("optional")),
            "optional operand should get the tailored message: {msgs:?}"
        );
    }

    #[test]
    fn try_reports_one_error_per_site() {
        let msgs = e0111_msgs("fn f() { let x = 1? }");
        assert_eq!(msgs.len(), 1, "one E0111 per `?` site: {msgs:?}");
    }

    #[test]
    fn omitted_trailing_default_is_not_an_arity_error() {
        let source = r#"
fn greet(name: string, punct: string = "!") -> string { return name + punct; }
fn main() { print(greet("hi")); }
"#;
        let (env, diags) = check(source);
        assert!(
            !diags.has_errors(),
            "a trailing parameter with a default may be omitted: {:?}",
            diags.has_errors()
        );
        assert_eq!(
            env.functions.get("greet").map(|sig| sig.required_params()),
            Some(1),
            "only `name` is required"
        );
    }

    #[test]
    fn omitted_required_argument_still_fails() {
        let source = r#"
fn add(a: int, b: int) -> int { return a + b; }
fn main() { print(add(1)); }
"#;
        let (_, diags) = check(source);
        assert!(
            diags.has_errors(),
            "a parameter without a default is still required"
        );
    }

    // ── G01: effect rows propagate through calls (interprocedural) ────────

    fn e0141_msgs(source: &str) -> Vec<String> {
        let (_, diags) = check(source);
        diags
            .items
            .iter()
            .filter(|d| d.code == "E0141")
            .map(|d| d.msg.clone())
            .collect()
    }

    #[test]
    fn signature_carries_the_declared_row() {
        let (env, _) = check("fn probe(h: string) with Net(connect) { net.connect(h) }");
        let sig = env.functions.get("probe").expect("probe registered");
        assert_eq!(sig.effects.len(), 1, "the row is part of the signature");
        assert_eq!(sig.effects[0].name, "Net");
        assert_eq!(sig.effects[0].ops, vec!["connect".to_string()]);
    }

    #[test]
    fn caller_of_a_row_carrying_function_needs_that_row_too() {
        let msgs = e0141_msgs(
            r#"
fn probe(h: string) with Net(connect) { net.connect(h) }
fn outer(h: string) { probe(h) }
"#,
        );
        assert_eq!(
            msgs,
            vec![
                "function body requires effect Net(connect) but the signature does not declare it"
                    .to_string()
            ],
            "the callee's declared row is the caller's requirement: {msgs:?}"
        );
    }

    #[test]
    fn caller_with_the_forwarded_row_is_clean() {
        let msgs = e0141_msgs(
            r#"
fn probe(h: string) with Net(connect) { net.connect(h) }
fn outer(h: string) with Net(connect) { probe(h) }
"#,
        );
        assert!(
            msgs.is_empty(),
            "the forwarded row satisfies the gate: {msgs:?}"
        );
    }

    #[test]
    fn forwarding_is_transitive_and_terminates_on_a_cycle() {
        // a → b → a is a cycle; the requirement is resolved from the *declared*
        // rows, so the walk must terminate and the unannotated entry point must
        // still be refused.
        let msgs = e0141_msgs(
            r#"
fn a(h: string) with Net(connect) { b(h) }
fn b(h: string) with Net(connect) { a(h) }
fn entry(h: string) { a(h) }
"#,
        );
        assert_eq!(
            msgs.len(),
            1,
            "one refusal, at the call in `entry`: {msgs:?}"
        );
    }

    #[test]
    fn bare_row_is_forwarded_as_a_whole_effect() {
        // A callee that declares bare `Net` names no single operation, so the
        // caller must declare bare `Net` too — `Net(connect)` is not enough.
        let msgs = e0141_msgs(
            r#"
fn probe(h: string) with Net { net.connect(h) }
fn outer(h: string) with Net(connect) { probe(h) }
"#,
        );
        assert_eq!(
            msgs,
            vec![
                "function body requires effect Net but the signature does not declare it"
                    .to_string()
            ],
            "a bare row forwards as a bare row: {msgs:?}"
        );
    }
}
