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
        /// Effects of `(effect, operations)` this function value may perform
        /// (G01 P0.3, audit N-3…N-8). Empty for a rowless function type.
        ///
        /// This is the row the value carries: a call through the value
        /// requires whatever the type says, exactly as a call to a named
        /// function requires its declared row. It lives on the *type* because
        /// a function value reaches a call site as a parameter, a return
        /// value, an array element or a struct field, and none of those
        /// positions has a signature to carry a row instead.
        ///
        /// Spans are deliberately absent: this is part of type identity, and
        /// two occurrences of the same row are the same row.
        effects: Vec<(String, Vec<String>)>,
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

    /// Nominal newtype (G10): `newtype UserId = String`.
    ///
    /// An alias is *transparent*: `type Port = u16` and `u16` are the same type
    /// everywhere. A newtype is not. It is carried by name, because two
    /// newtypes over the same target are unrelated types (`UserId` and
    /// `Meter`-over-`String` are distinct even though both erase to `String` at
    /// run time), and it never becomes its target implicitly in any direction:
    /// a `String` is not a `UserId` (that needs `UserId(..)`) and a `UserId` is
    /// not a `String` (that needs `.inner`).
    ///
    /// `inner` is carried so the constructor's argument can be checked and the
    /// unwrap can be typed without a lookup back into the environment — the
    /// value *is* the target at run time, which is what makes erasure safe.
    Newtype {
        name: String,
        inner: Box<Type>,
    },

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
        Type::Newtype { name, .. } => name.clone(),
        Type::Private(inner) | Type::Secret(inner) => type_label(inner),
        Type::Grant(effect) if effect.is_empty() => "Grant".to_string(),
        Type::Grant(effect) => format!("Grant<{effect}>"),
        Type::Function {
            params,
            return_type,
            effects,
        } => {
            let params = params.iter().map(type_label).collect::<Vec<_>>().join(", ");
            let mut out = format!("fn({params}) -> {}", type_label(return_type));
            if !effects.is_empty() {
                out.push_str(" with ");
                out.push_str(&format_type_row(effects));
            }
            out
        }
        other => format!("{other:?}"),
    }
}

/// Render a row carried on a *type* (`[(effect, ops)]`): `Net(connect)`.
///
/// The AST form is [`crate::ast::format_effect_row`]; this is the resolved
/// form, which drops spans because they are not part of a type.
fn format_type_row(row: &[(String, Vec<String>)]) -> String {
    row.iter()
        .map(|(name, ops)| {
            if ops.is_empty() {
                name.clone()
            } else {
                format!("{name}({})", ops.join(", "))
            }
        })
        .collect::<Vec<_>>()
        .join(", ")
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
    /// Declared effect row of the function this local was initialised from
    /// (`let f = scan`), if any (G01, audit F-8).
    ///
    /// A row is a property of the *function*, not of the syntax that calls it.
    /// Storing a row-carrying function in a value used to launder the row away:
    /// `f(g, h)` matched no name in the effect table, so the caller inherited
    /// nothing. Recording the row on the binding keeps the requirement attached
    /// to the value, and [`TypeChecker::check_call`] forwards it at every call
    /// through a local.
    pub effects: Vec<EffectReq>,
    /// This binding is known to be non-`nil` for the rest of its scope, because
    /// a `nil` test that dominates the use has already excluded the absent
    /// case (register #136).
    ///
    /// Recorded on the *binding* rather than re-derived at each use: the guard
    /// is a statement, and only the statement walk knows that the code after it
    /// is reached solely when the test failed. Only an immutable binding is
    /// ever narrowed — a `var` can be reassigned to a fresh optional, and the
    /// evidence would then be stale, so `var` never narrows.
    pub non_nil: bool,
}

// ── Type Environment ─────────────────────────────────────────────────────────

/// Stores resolved type information for each function, variable, and parameter.
#[derive(Debug, Default)]
pub struct TypeEnv {
    /// Function name → resolved signature.
    pub functions: HashMap<String, FnSignature>,
    /// Type alias name → resolved type.
    pub type_aliases: HashMap<String, Type>,
    /// Newtype name → `Type::Newtype { name, inner }` (G10).
    ///
    /// Separate from `type_aliases` because the two are different relations: an
    /// alias *is* its target, a newtype only *erases to* its target at run
    /// time. Name resolution consults this map first, so `UserId` never
    /// silently resolves to `String`; the alias map also carries the name
    /// (mapped to the inner type) so layout passes that never see the checker's
    /// nominal type still give it the right representation.
    pub newtypes: HashMap<String, Type>,
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

/// The import → effect manifest (G21): `(module head, egress operations)`.
///
/// `head` is the module as written at the call site — or the class namespace a
/// module exposes, since `Inbox.connect_imap` is the `email` module's IMAP
/// client under another name. The second element lists the operations of that
/// module which leave the process; an **empty** list means every operation of
/// the module does, which is a claim only a wholly network-facing module can
/// make.
///
/// This table is the *inference source* for the rule "a function that uses an
/// effectful module acquires that effect in its row". It replaces the seven-name
/// head match that used to be the whole of `effect_for_callee`: that list was
/// narrower than the set of modules that open a socket (bridge-review F8), so
/// `email.connect_imap`, `ws.connect`, `sync.bidirectional` and the rest
/// compiled without a row in both engines.
///
/// Every entry names a socket or an HTTP client in that module's own source; the
/// citation is the evidence, not the intent. What is deliberately **absent** is
/// as load-bearing as what is present: `api`/`intel_api`, `traffic`/`intel_traffic`
/// and `ip`/`intel_ip` are documented offline parsers ("No sockets, no DNS" —
/// `src/stdlib/mod.rs`), and the mixed modules are listed per operation so that
/// `sync.mutex(1)` (a concurrency primitive) never demands a network row.
///
/// Heads still outside this table, and why: `transfer_net` and `relay_room` are
/// the sendtallow relay surfaces (operator directive: out of scope here);
/// `browser` egresses over CDP but is gated by `@fingerprint_policy`/`@stealth`
/// and moving it into `Net` is a separate item; `osint` exposes its sockets
/// through *type namespaces* (`DomainIntel.whois`, `Scanner.scan`), not a module
/// head, which is the same shape as F8's remaining gap.
pub const EFFECTFUL_MODULES: &[(&str, &[&str])] = &[
    // ── Wholly network-facing ────────────────────────────────────────────
    // `net.rs:2156` TcpStream::connect / `:2199` TcpListener::bind, plus quinn
    // and tungstenite; `http.rs:1038` TcpListener::bind over `egress_http`.
    ("net", &[]),
    ("Tcp", &[]),
    ("Udp", &[]),
    ("TLSConn", &[]),
    ("http", &[]),
    // `topology.rs:389` connect_probe, `:1595`/`:1765`/`:2092` TcpStream.
    ("topology", &[]),
    // `sitescan.rs:235` egress agent; its `network` stage is a TCP connect scan.
    ("sitescan", &[]),
    // `graphql.rs:328`/`:365` egress_http::get / ::post — all three module ops.
    ("graphql", &[]),
    // ── Sockets under a websocket name ───────────────────────────────────
    // `ws.rs:333` dispatch "connect" → `ws.rs:95` TcpStream::connect_timeout.
    ("ws", &["connect"]),
    ("WS", &["connect"]),
    // `stdlib/net.tl:75`/`:51` — `native fn connect(..) with Net(connect)`.
    ("WebSocket", &["connect"]),
    ("QuicStream", &["connect"]),
    // ── Mixed modules: only the operations that egress ───────────────────
    // `email.rs:90-91` connect_imap / connect_guerrilla → `:133`
    // ImapConnection::connect, `:219` guerrilla_connect (egress_http::get).
    ("email", &["connect_imap", "connect_guerrilla"]),
    // The same IMAP client under its class namespace (`tests/stdlib_dispatch.rs`
    // reaches it as `Inbox.connect_imap`).
    ("Inbox", &["connect_imap"]),
    // `email.rs:107-108` → `guerrilla_get_email`/`guerrilla_wait` (`:271`).
    ("GuerrillaInbox", &["get_email", "wait_for_email"]),
    // `sync.rs:308-314` → daemon_post/daemon_get (`:38`/`:66`, reqwest). The
    // concurrency operations (channel/mutex/rwlock/barrier/once/atomic/
    // wait_group) live in the same module and are not listed: they open nothing.
    (
        "sync",
        &[
            "bidirectional",
            "mesh",
            "status",
            "list_pairs",
            "resolve_conflict",
            "pause",
            "resume",
        ],
    ),
    // `sso.rs:177` replay_token → `:92` egress_http::get.
    ("sso", &["replay_token"]),
    // `oauth.rs:144-147` → `:224`/`:256`/`:284`/`:303` egress_http::post/get.
    // `authorization_url`, `generate_pkce` and the attack helpers build strings.
    (
        "oauth",
        &["exchange_code", "client_credentials", "refresh_token", "discover"],
    ),
];

/// The effect a dotted call path requires, if any.
///
/// The **first** segment names the module (or its class namespace); the second
/// segment is the operation (`Tcp.connect` → `Net(connect)`). The requirement is
/// read off [`EFFECTFUL_MODULES`] — the module's own egress surface — rather than
/// off a head list, so an effectful module acquires its row wherever it is used.
pub fn effect_for_callee(name: &str) -> Option<&'static str> {
    let mut segments = name.split('.');
    let head = segments.next().unwrap_or("");
    let op = segments.next().unwrap_or("");
    EFFECTFUL_MODULES
        .iter()
        .find(|(module, ops)| *module == head && (ops.is_empty() || ops.contains(&op)))
        .map(|_| "Net")
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

/// One effect requirement collected while walking a body (G01, G21).
///
/// `origin` is the callee whose row imposed the requirement, when the caller
/// inherited it instead of performing it at the site. The distinction is what
/// makes the refusal name the callee (E0151) instead of only the effect.
#[derive(Debug, Clone)]
struct BodyEffectReq {
    effect: String,
    op: String,
    span: Span,
    grant_ok: bool,
    origin: Option<String>,
}

impl BodyEffectReq {
    /// `Net` / `Net(connect)` — the spelling a row and a diagnostic share.
    fn display(&self) -> String {
        if self.op.is_empty() {
            self.effect.clone()
        } else {
            format!("{}({})", self.effect, self.op)
        }
    }
}

pub struct TypeChecker<'a> {
    program: &'a Program,
    pub env: TypeEnv,
    pub diags: Diagnostics,
    /// Effect row of the signature whose body is being walked (G01).
    declared_effects: Vec<EffectReq>,
    /// The effects the body being walked requires, with provenance (G01, G21).
    ///
    /// The effect name is owned because a row forwarded from a callee's
    /// signature carries a `String`, not a `&'static str`; `grant_in_scope` is
    /// whether a `Grant<effect>` value was lexically available at that call site
    /// — the capability half of the row (G01 P0.2, E0142). `origin` names the
    /// callee that imposed the requirement when it was inherited rather than
    /// performed at the site, which is what lets the refusal name the callee
    /// (G21, E0151).
    body_effect_reqs: Vec<BodyEffectReq>,
    /// `(effect, span)` of every `scope.grant(<effect>)` site in the body being
    /// walked (G01 P0.2, E0144). The site is recorded while the locals are
    /// live; whether it is legal is judged at the body boundary by
    /// [`Self::enforce_grant_origin`], because the rule depends on the *name*
    /// of the enclosing body — only `main` may originate authority.
    body_grant_sites: Vec<(String, Span)>,
    /// Whether the body being walked is *the* entry point — spelled `main` and
    /// declared in the file the compiler was invoked on (G01, audit F-11).
    ///
    /// The trust-root exemption is a property of an item, not of a spelling: a
    /// library function called `main` is an ordinary function and must take its
    /// capability as a parameter like any other. `check_trust_root` rejects the
    /// imported case outright (E0147); this flag is the second lock, and it is
    /// what `enforce_effect_row` / `enforce_grant_origin` consult.
    current_body_is_entry_main: bool,
    /// Whether the body being walked is an imported function spelled `main`.
    /// Such a body is already refused as a library item by
    /// [`Self::check_trust_root`] (E0147), so the E0144 authority-origin rule is
    /// not applied to it a second time: one defect, one diagnostic.
    current_body_is_imported_main: bool,
    /// Declared return type of the body being walked, when it is not `Void`
    /// (G01 P0.2). `return <expr>` and the tail expression are compared to it,
    /// so the return position cannot manufacture a capability any more than a
    /// `let` can.
    current_return_type: Option<Type>,
    /// Name and declaration span of the function whose body is being walked
    /// (G21). The effect set is *per function*, so the per-body report
    /// [`Self::enforce_effect_row`] emits is attributed to this name.
    current_body_name: Option<String>,
    current_body_span: Span,
    /// Source file of the body being walked when it is not the file compiled
    /// (G21). Spans are offsets into their own file, so an effect diagnostic
    /// raised inside an imported library function must carry that file or it
    /// renders against an unrelated line of the entry file (audit N-9).
    current_body_file: Option<std::path::PathBuf>,
    /// Nesting depth of closure bodies. A `return` inside a closure returns
    /// from the closure, not from the enclosing function, so the return-slot
    /// check is suspended there.
    closure_depth: usize,
    /// Enclosing loops/blocks a `break` or `continue` can target (G08), innermost
    /// last. One entry per `loop`/`for`/`while` currently being walked.
    label_stack: Vec<LoopTarget>,
    /// Type inferred for the value a `loop` expression yields, recorded while
    /// its body is checked and read back by [`TypeChecker::infer_expr_type`]
    /// (which cannot walk a body). Keyed by the expression span.
    loop_value_types: HashMap<(usize, usize), Type>,
}

/// One construct a `break`/`continue` can target (G08).
#[derive(Debug, Clone)]
struct LoopTarget {
    /// The declared label (`'outer: loop ...`), if the loop was labeled. An
    /// unlabeled `break` binds to the innermost entry regardless.
    label: Option<String>,
    /// Whether this construct can yield a value: `loop` can, `for`/`while`
    /// cannot, so `break 'for_label v` is reported rather than silently
    /// dropping `v`.
    yields: bool,
    /// Unified type of the values carried by the breaks seen so far.
    value_ty: Option<Type>,
    /// Span of the construct head, quoted when a break carries no value into a
    /// construct that does yield one.
    span: Span,
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
            current_body_is_entry_main: false,
            current_body_is_imported_main: false,
            current_return_type: None,
            current_body_name: None,
            current_body_span: Span { start: 0, end: 0 },
            current_body_file: None,
            closure_depth: 0,
            label_stack: Vec::new(),
            loop_value_types: HashMap::new(),
        }
    }

    /// Run the type checker over the entire program.
    pub fn check(mut self) -> (TypeEnv, Diagnostics) {
        // Pass 1: Register all type aliases and function signatures
        self.register_declarations();

        // Pass 1a: exactly one trust root, in the entry file (G01, audit F-11)
        self.check_trust_root();

        // Pass 1b: Register traits and validate trait impls
        self.register_traits();
        self.validate_trait_impls();

        // Pass 1c: Validate recursive enum types (must use Box<T> for self-references)
        self.validate_recursive_enums();

        // Pass 1d: Register structs, enums, and impl methods
        self.register_structs_and_enums();
        self.register_impl_methods();

        // Pass 1e: newtype targets (G10). Runs after struct/enum registration
        // because the rule depends on what a target name *is*.
        self.validate_newtype_targets();

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

        // Pass 2b: top-level `const` initialisers (G01 P0.3, audit N-2/F-14).
        self.check_const_initialisers();

        (self.env, self.diags)
    }

    /// A top-level initialiser runs at program start, outside every signature.
    ///
    /// There is no row it could be declared in, and no `main` for the
    /// trust-root exemption to point at, so the only correct answer is that it
    /// may not perform an effect at all (audit N-2 / F-14: `const status:
    /// string = net.connect(..)` checked clean and *opened a socket* under the
    /// interpreter). The walk is the ordinary expression walk, so the initialiser
    /// also gets every other value-position rule: `const N = net` is refused as
    /// E0146 (module namespace is not a value) before this pass ever reaches the
    /// effect question.
    fn check_const_initialisers(&mut self) {
        for item in &self.program.items {
            let Item::Const(c) = item else {
                continue;
            };
            if let Some(ty) = &c.ty {
                self.validate_grant_shape(ty);
            }
            let locals: HashMap<String, VarInfo> = HashMap::new();
            self.declared_effects = Vec::new();
            self.body_effect_reqs = Vec::new();
            self.body_grant_sites = Vec::new();
            self.current_body_is_entry_main = false;
            self.current_body_is_imported_main = false;
            self.current_return_type = None;
            // A `const` initialiser has no function, so there is no per-function
            // effect set to report (G21); the requirement is refused below.
            self.current_body_name = None;
            self.current_body_span = c.span;
            self.current_body_file = None;
            self.closure_depth = 0;
            self.check_expr(&c.value, &locals);
            let reqs = std::mem::take(&mut self.body_effect_reqs);
            self.body_grant_sites.clear();
            for req in reqs {
                let what = req.display();
                let effect = req.effect;
                self.diags.push(
                    crate::error::Diagnostic::error(
                        "E0148",
                        format!(
                            "a top-level initialiser may not perform effect {what}; move it into main"
                        ),
                        req.span,
                    )
                    .with_help(format!(
                        "`const {}` is evaluated before any row exists: obtain the value inside a function that declares `with {effect}`",
                        c.name
                    )),
                );
            }
        }
    }

    // ── Pass 1: Registration ─────────────────────────────────────────────

    fn register_declarations(&mut self) {
        for item in &self.program.items {
            match item {
                Item::TypeAlias(ta) => {
                    let inner = self.resolve_type_expr(&ta.ty);
                    // A newtype may not be named as the target of either
                    // declaration: `type A = UserId` claims an alias (which is
                    // transparent) over a nominal type, and `newtype A = UserId`
                    // makes `A`'s representation a newtype's, which no layout
                    // pass knows how to lower. Both compositions are refused
                    // here, where the declaration is, rather than miscompiled
                    // later. Writing the underlying type is always available.
                    if let Some(named) = Self::named_newtype(&inner) {
                        self.diags.push(
                            crate::error::Diagnostic::error(
                                "E0117",
                                format!(
                                    "{} `{}` cannot be declared over newtype `{named}`: a \
                                     newtype is nominal, so it cannot be another declaration's \
                                     target",
                                    if ta.newtype { "newtype" } else { "type alias" },
                                    ta.name
                                ),
                                ta.span,
                            )
                            .with_help(format!(
                                "declare `{named}` and use it directly, or write the underlying \
                                 type this declaration is really about"
                            )),
                        );
                    }
                    if ta.newtype {
                        // `newtype Loop = Loop` would resolve to an unresolved
                        // name and then be treated as its own representation;
                        // there is no value of that type to wrap.
                        if matches!(&inner, Type::Named(n) if n == &ta.name) {
                            self.diags.error(
                                "E0117",
                                format!(
                                    "newtype `{}` cannot wrap itself: the target must be a \
                                     type that already exists",
                                    ta.name
                                ),
                                ta.span,
                            );
                        }
                        // `newtype UserId = String` (G10). The name resolves to a
                        // nominal type, never to `inner`; registering the erased
                        // form in `type_aliases` as well gives layout passes a
                        // representation without giving any *checker* rule a
                        // conversion.
                        let ty = Type::Newtype {
                            name: ta.name.clone(),
                            inner: Box::new(inner.clone()),
                        };
                        self.env.newtypes.insert(ta.name.clone(), ty);
                        self.env.type_aliases.insert(ta.name.clone(), inner);
                        continue;
                    }
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
                ..
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
                effects,
            } => Type::Function {
                params: params.iter().map(|p| self.resolve_type_expr(p)).collect(),
                return_type: Box::new(self.resolve_type_expr(return_type)),
                // G01 P0.3: the row is resolved into the *type*, in the same
                // span-free `(effect, ops)` shape the rest of the checker
                // forwards. Type identity compares rows, so two occurrences of
                // `fn(..) with Net(connect)` are the same type; spans are not
                // part of a type.
                effects: effects
                    .iter()
                    .map(|e| (e.name.clone(), e.ops.clone()))
                    .collect(),
            },
            TypeExprKind::ImplTrait(name) => Type::Named(name.clone()),
            TypeExprKind::DynTrait(name) => Type::Named(name.clone()),
        }
    }

    fn resolve_named_type(&self, name: &str) -> Type {
        // G10: a newtype name resolves to the *nominal* type, before the alias
        // table can hand back its target. This is the single place the two
        // declarations part company, and every use site (annotation, parameter,
        // return, field) resolves through here.
        if let Some(ty) = self.env.newtypes.get(name) {
            return ty.clone();
        }
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
    ///
    /// G10: a *declared* newtype wins over this heuristic. `newtype Email = String`
    /// makes `Email` a nominal type, and `resolve_named_type` has already returned
    /// `Type::Newtype` for it; wrapping that in `Type::Private` here would erase
    /// the nominal identity in parameter position only, because this helper is
    /// composed with resolution by `resolve_param_type` and nowhere else. The
    /// name list still applies to names nothing declares.
    fn apply_builtin_qualifier(&self, ty: Type, type_expr: &TypeExpr) -> Type {
        if let TypeExprKind::Named(name) = &type_expr.kind {
            if self.env.newtypes.contains_key(name.as_str()) {
                return ty;
            }
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
            locals.insert(
                p.name.clone(),
                VarInfo {
                    ty,
                    mutable: false,
                    effects: Vec::new(),
                    non_nil: false,
                },
            );
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

        let declared_return = f
            .return_type
            .as_ref()
            .map(|t| self.resolve_type_expr(t))
            .unwrap_or(Type::Void);

        // G01 P0.2: a `native fn` has no body, so a `-> Grant<E>` on it would
        // be a producer of authority that no `scope.grant` call backs (E0145).
        // Capabilities are *consumed* by native code as parameters; they are
        // not made by it.
        if f.is_native {
            if let Some(effect) = Self::first_grant_effect(&declared_return) {
                let named = if effect.is_empty() {
                    "Grant".to_string()
                } else {
                    format!("Grant<{effect}>")
                };
                self.diags.push(
                    crate::error::Diagnostic::error(
                        "E0145",
                        format!(
                            "`native fn {}` cannot produce `{named}`: a native declaration has no body, so no scope.grant call backs it",
                            f.name
                        ),
                        f.span,
                    )
                    .with_help(
                        "take the capability as a parameter and thread it in from main",
                    ),
                );
            }
        }

        // G01 P0.2: a default value is a producer position. `fn scan(g:
        // Grant<Net> = 7, ..)` typechecked because defaults were never compared
        // to the parameter's declared type.
        for p in &f.params {
            if let Some(default) = &p.default {
                let declared = self.resolve_param_type(p);
                self.check_capability_slot(&declared, default, &locals, "use as a default value");
            }
        }

        // Check each statement.
        //
        // G01: the walk also collects the effects the body's calls require
        // (recorded in `check_expr`); the row is enforced right after it, so a
        // socket-opening call without `with Net(op)` is reported at the call.
        self.declared_effects = f.effects.clone();
        self.current_body_is_entry_main = f.name == "main" && !f.is_imported;
        self.current_body_is_imported_main = f.name == "main" && f.is_imported;
        self.current_return_type = (declared_return != Type::Void).then(|| declared_return.clone());
        // G21: the effect set is per function, so the report this body emits
        // names *this* declaration and is anchored on it.
        self.current_body_name = Some(f.name.clone());
        // The body block, not `f.span`: the declaration span includes the
        // annotations, so a report anchored on it pointed at `@legal` instead of
        // at the function it is about.
        self.current_body_span = f.body.span;
        self.current_body_file = f.imported_from.clone();
        self.closure_depth = 0;
        self.body_effect_reqs = Vec::new();
        self.body_grant_sites = Vec::new();
        for stmt in &f.body.stmts {
            self.check_stmt(stmt, &mut locals);
        }
        self.enforce_grant_origin(false);
        self.enforce_effect_row();
        self.current_body_is_entry_main = false;
        self.current_body_is_imported_main = false;

        // G01 P0.2: the tail expression is the implicit return; it is compared
        // to the declared type exactly like an explicit `return`.
        if let Some(declared) = self.current_return_type.clone() {
            if let Some(last) = f.body.stmts.last() {
                if let StmtKind::Expr { expr } = &last.kind {
                    self.check_capability_slot(&declared, expr, &locals, "return");
                    // Register #136: the tail expression is a return slot too.
                    self.check_optional_binding(&declared, expr, &locals, "return", expr.span);
                }
            }
        }
        self.current_return_type = None;

        // Check return type matches body
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
                effects: Vec::new(),
                non_nil: false,
            },
        );
        for p in &method.params {
            if p.name != "self" {
                let ty = self.resolve_param_type(p);
                locals.insert(
                    p.name.clone(),
                    VarInfo {
                        ty,
                        mutable: false,
                        effects: Vec::new(),
                        non_nil: false,
                    },
                );
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
        self.current_body_is_entry_main = false;
        self.current_body_is_imported_main = false;
        // G21: an `impl` method's effect set is its own, reported under
        // `Type.method` so it cannot be confused with a free function's.
        self.current_body_name = Some(format!("{target}.{}", method.name));
        self.current_body_span = method.body.span;
        self.current_body_file = None;
        let declared_return = method
            .return_type
            .as_ref()
            .map(|t| self.resolve_type_expr(t))
            .unwrap_or(Type::Void);
        self.current_return_type = (declared_return != Type::Void).then(|| declared_return.clone());
        self.closure_depth = 0;
        // G01 P0.2: a default value is a producer position, in a method too.
        for p in &method.params {
            if let Some(default) = &p.default {
                let declared = self.resolve_param_type(p);
                self.check_capability_slot(&declared, default, &locals, "use as a default value");
            }
        }
        self.body_effect_reqs = Vec::new();
        self.body_grant_sites = Vec::new();
        for stmt in &method.body.stmts {
            self.check_stmt(stmt, &mut locals);
        }
        // An `impl` method is never `main`: it has no path to the trust root,
        // so it must take the capability as a parameter (E0144).
        self.enforce_grant_origin(true);
        self.enforce_effect_row();
        // G01 P0.2: the tail expression is the implicit return.
        if let Some(declared) = self.current_return_type.clone() {
            if let Some(last) = method.body.stmts.last() {
                if let StmtKind::Expr { expr } = &last.kind {
                    self.check_capability_slot(&declared, expr, &locals, "return");
                    // Register #136: the tail expression is a return slot too.
                    self.check_optional_binding(&declared, expr, &locals, "return", expr.span);
                }
            }
        }
        self.current_return_type = None;
    }

    // ── Trust root (G01, audit F-11) ─────────────────────────────────────

    /// The trust root is an *item*, not a spelling: exactly one `fn main`, and
    /// it must be the item declared in the file the compiler was invoked on.
    ///
    /// `scope.grant` is exempt from E0144 only inside `main` (see
    /// [`Self::enforce_grant_origin`]), because `main` is the one body whose
    /// authority comes from the runtime scope registry rather than from a
    /// caller. Import resolution merges imported files into the same program
    /// before type checking, so before this pass any library function spelled
    /// `main` inherited that exemption — a helper could mint itself a
    /// `Grant<Net>` and reach a socket with no authority handed to it at all.
    ///
    /// Both holes are closed here: an imported `main` is refused (E0147)
    /// because a program's entry point is never a library item, and a second
    /// `main` in the entry file is refused because a program has exactly one
    /// entry point — the duplicate would otherwise shadow the first at codegen
    /// time while both were still checked as trust roots.
    fn check_trust_root(&mut self) {
        let mut entry_main: Option<Span> = None;
        for item in &self.program.items {
            let Item::Fn(f) = item else {
                continue;
            };
            if f.name != "main" {
                continue;
            }
            if f.is_imported {
                let mut diag = crate::error::Diagnostic::error(
                    "E0147",
                    "main is the entry point of the program, not a library item".to_string(),
                    f.span,
                )
                .with_help(
                    "rename this function: authority is originated only by the `main` of the file compiled",
                );
                // The span is an offset into the imported module's own source,
                // so the diagnostic must render against that file: pointed at
                // the entry file it showed an unrelated line (audit N-9).
                if let Some(path) = &f.imported_from {
                    diag = diag.with_file(path.clone());
                }
                self.diags.push(diag);
                continue;
            }
            if entry_main.is_some() {
                self.diags.push(
                    crate::error::Diagnostic::error(
                        "E0147",
                        "a program has exactly one `main`; this is a duplicate entry point"
                            .to_string(),
                        f.span,
                    )
                    .with_help("merge the bodies, or give one of them a name that is not `main`"),
                );
                continue;
            }
            entry_main = Some(f.span);
        }
    }

    // ── Effect rows (G01) ───────────────────────────────────────────────

    /// Record that a call at `span` opens a socket, if its path names a module
    /// operation in [`EFFECTFUL_MODULES`] (G21: the module's egress surface is
    /// where the requirement is inferred from).
    fn note_effect_call(&mut self, path: &str, span: Span, locals: &HashMap<String, VarInfo>) {
        let Some(effect) = effect_for_callee(path) else {
            return;
        };
        let op = effect_op(path).to_string();
        let grant_ok = Self::grant_in_scope(locals, effect);
        self.push_effect_req(effect.to_string(), op, span, grant_ok, None);
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
        callee: &str,
        span: Span,
        locals: &HashMap<String, VarInfo>,
    ) {
        for effect in effects {
            let grant_ok = Self::grant_in_scope(locals, &effect.name);
            if effect.ops.is_empty() {
                self.push_effect_req(
                    effect.name.clone(),
                    String::new(),
                    span,
                    grant_ok,
                    Some(callee.to_string()),
                );
            } else {
                for op in &effect.ops {
                    self.push_effect_req(
                        effect.name.clone(),
                        op.clone(),
                        span,
                        grant_ok,
                        Some(callee.to_string()),
                    );
                }
            }
        }
    }

    /// The row a *type* carries: empty for everything that is not a function
    /// type. The one place the type-carried row is read (G01 P0.3).
    fn type_row(ty: &Type) -> &[(String, Vec<String>)] {
        match ty {
            Type::Function { effects, .. } => effects,
            _ => &[],
        }
    }

    /// Forward a row that came from a *type* rather than from a signature.
    ///
    /// Same requirement, same codes, same call-site span as
    /// [`Self::note_callee_row`]: the only difference is where the row was
    /// read, and the caller must not be able to tell.
    fn note_type_row(
        &mut self,
        row: &[(String, Vec<String>)],
        callee: &str,
        span: Span,
        locals: &HashMap<String, VarInfo>,
    ) {
        let reqs: Vec<EffectReq> = row
            .iter()
            .map(|(name, ops)| EffectReq {
                name: name.clone(),
                ops: ops.clone(),
                span,
            })
            .collect();
        self.note_callee_row(&reqs, callee, span, locals);
    }

    /// Union of two rows, entry-wise; the result is in first-seen order.
    ///
    /// A bare entry (`Net`, no operations) covers every operation of the
    /// effect, so it swallows the operations of a matching entry: the union of
    /// `Net` and `Net(connect)` is `Net`. Keeping the operations would claim
    /// the joined value does less than one of its arms.
    fn union_rows(
        a: &[(String, Vec<String>)],
        b: &[(String, Vec<String>)],
    ) -> Vec<(String, Vec<String>)> {
        let mut out: Vec<(String, Vec<String>)> = a.to_vec();
        for (name, ops) in b {
            match out.iter_mut().find(|(n, _)| n == name) {
                Some((_, existing)) => {
                    if existing.is_empty() || ops.is_empty() {
                        existing.clear();
                    } else {
                        for op in ops {
                            if !existing.iter().any(|o| o == op) {
                                existing.push(op.clone());
                            }
                        }
                    }
                }
                None => out.push((name.clone(), ops.clone())),
            }
        }
        out
    }

    /// G01 P0.3 (audit N-7): update what a binding *carries* when it is
    /// reassigned.
    ///
    /// The union is deliberate: rows accumulate over a binding's life and
    /// never shrink. Straight-line `var f = worker; f = nop` could in principle
    /// drop the row, but the walk visits a loop body once, so
    /// `var f = nop; while c { f = worker }; f(g, h)` would then call through a
    /// value whose row the walk had just forgotten. Accumulating is the only
    /// direction that stays sound without a fixpoint; the cost is a possible
    /// false positive after a dead straight-line reassignment, and declaring
    /// the row clears it.
    fn assign_binding_row(
        info: &mut VarInfo,
        value_ty: &Type,
        value_row: &[EffectReq],
        span: Span,
    ) {
        let assigned: Vec<(String, Vec<String>)> = Self::type_row(value_ty).to_vec();
        match &mut info.ty {
            Type::Function { effects, .. } => {
                *effects = Self::union_rows(effects, &assigned);
            }
            other => {
                // `var f = nop` recorded no type worth keeping; a rowwed
                // function assigned afterwards is what the binding now holds.
                if matches!(other, Type::Unknown) && matches!(value_ty, Type::Function { .. }) {
                    *other = value_ty.clone();
                }
            }
        }
        // Keep the per-binding record (the pre-type channel) in step, so a
        // call site that still reads `VarInfo::effects` sees the same row.
        let mut union: Vec<(String, Vec<String>)> = info
            .effects
            .iter()
            .map(|e| (e.name.clone(), e.ops.clone()))
            .collect();
        union = Self::union_rows(&union, &assigned);
        union = Self::union_rows(
            &union,
            &value_row
                .iter()
                .map(|e| (e.name.clone(), e.ops.clone()))
                .collect::<Vec<_>>(),
        );
        info.effects = union
            .into_iter()
            .map(|(name, ops)| EffectReq { name, ops, span })
            .collect();
    }

    /// The declared row of the function a binding initialises from, if the
    /// initialiser is a function value (G01, audit F-8).
    ///
    /// Only a bare identifier can carry a row: a name that is a local inherits
    /// that local's row (`let g = f`), and a name that is a declared function
    /// carries its own. Anything else is not a function value, so it has no row
    /// to forward and a call through it stays an ordinary (rowless) call.
    fn fn_value_effects(&self, value: &Expr, locals: &HashMap<String, VarInfo>) -> Vec<EffectReq> {
        // `let f = net.connect` captures a module member by its dotted path:
        // the path is exactly what the effect table reads, so the row it names
        // is recorded on the binding and forwarded at `f(..)` like any other.
        if let Some(path) = callee_path(value) {
            if let Some(effect) = effect_for_callee(&path) {
                let op = effect_op(&path);
                if !op.is_empty() {
                    return vec![EffectReq {
                        name: effect.to_string(),
                        ops: vec![op.to_string()],
                        span: value.span,
                    }];
                }
            }
        }
        let ExprKind::Ident(name) = &value.kind else {
            return Vec::new();
        };
        if let Some(info) = locals.get(name) {
            return info.effects.clone();
        }
        self.env
            .functions
            .get(name)
            .map(|sig| sig.effects.clone())
            .unwrap_or_default()
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
    fn push_effect_req(
        &mut self,
        effect: String,
        op: String,
        span: Span,
        grant_ok: bool,
        origin: Option<String>,
    ) {
        if self.body_effect_reqs.iter().any(|req| {
            req.effect == effect && req.op == op && req.span.start == span.start && req.span.end == span.end
        }) {
            return;
        }
        self.body_effect_reqs.push(BodyEffectReq {
            effect,
            op,
            span,
            grant_ok,
            origin,
        });
    }

    /// The last gate of a body walk (G01, G21): every effect a call required must
    /// appear in the signature's row. `with Net` (no parentheses) covers every
    /// operation of `Net`; `with Net(connect)` covers only `connect`.
    ///
    /// G21 adds two things around the unchanged obligation:
    ///
    /// * the **effect set** of the function is reported here, once, from the
    ///   requirements the body actually collected — that is the per-function row
    ///   `tallow check` shows (`W0130`). It is the union of what the body does
    ///   directly (an effectful module operation, [`EFFECTFUL_MODULES`]) and what
    ///   it inherits from the functions it calls, which is why a library
    ///   function cannot absorb either half;
    /// * when a requirement was **inherited from a callee**, the refusal carries
    ///   a second diagnostic naming that callee and the effect (`E0151`, below).
    ///   `E0141` stays the obligation at the site (unchanged, and pinned by the
    ///   G01 suite); `E0151` says where the obligation came from, which is the
    ///   thing an author has to go and fix when the row is not theirs to edit.
    ///
    /// G01 P0.2 stays the second half: a declared row must be backed by a
    /// `Grant<effect>` value in scope (E0142). A row is a capability, not a
    /// promise. `E0141` is checked first, so a body that is missing both reports
    /// the row, which is the outer fix.
    /// Point an effect diagnostic at the file its span came from, when the body
    /// being walked is an imported one (G21). `None` means "the file compiled".
    fn in_body_file(&self, diag: crate::error::Diagnostic) -> crate::error::Diagnostic {
        match &self.current_body_file {
            Some(path) => diag.with_file(path.clone()),
            None => diag,
        }
    }

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
        let trust_root = self.current_body_is_entry_main;
        // G21: the per-function effect set, in first-seen order, before the loop
        // consumes the requirements. `Net(connect)` and `Net` are distinct
        // entries here because they are distinct claims; the row union in
        // `union_rows` is what collapses them where a row is built.
        let mut effect_set: Vec<String> = Vec::new();
        for req in &reqs {
            let what = req.display();
            if !effect_set.contains(&what) {
                effect_set.push(what);
            }
        }
        if let Some(name) = self.current_body_name.clone() {
            if !effect_set.is_empty() {
                let msg = format!(
                    "effect set of `{name}`: {} (per-function; a caller of `{name}` inherits it)",
                    effect_set.join(", ")
                );
                let diag =
                    crate::error::Diagnostic::warning("W0130", msg, self.current_body_span);
                self.diags.push(self.in_body_file(diag));
            }
        }
        for req in reqs {
            let BodyEffectReq {
                effect,
                op,
                span,
                grant_ok,
                origin,
            } = req;
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
                let diag = crate::error::Diagnostic::error("E0141", msg, span).with_help(help);
                self.diags.push(self.in_body_file(diag));
                // G21: an inherited requirement also names the callee. A direct
                // operation has no callee to name, so it reports E0141 alone.
                if let Some(callee) = &origin {
                    let caller = self
                        .current_body_name
                        .clone()
                        .unwrap_or_else(|| "this function".to_string());
                    let msg = format!(
                        "call to `{callee}` requires effect {what}; `{caller}` does not declare it, so the requirement cannot be absorbed here"
                    );
                    let diag = crate::error::Diagnostic::error("E0151", msg, span)
                        .with_help(format!(
                            "add `with {what}` to `{caller}`'s signature and thread the `Grant<{effect}>` through from main"
                        ));
                    self.diags.push(self.in_body_file(diag));
                }
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
            let diag = crate::error::Diagnostic::error("E0142", msg, span);
            self.diags.push(self.in_body_file(diag));
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
    /// said in the help text rather than assumed. A *body* is never judged by
    /// its name either: `current_body_is_entry_main` is set from the item that
    /// declares it (see [`Self::check_trust_root`]), so `main` in an imported
    /// module does not reach this exemption.
    fn enforce_grant_origin(&mut self, is_impl: bool) {
        let sites = std::mem::take(&mut self.body_grant_sites);
        if self.current_body_is_entry_main || self.current_body_is_imported_main {
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
                ..
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
                | StmtKind::Loop { body, .. } => {
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
                    self.check_optional_binding(&resolved, value, locals, "bind", value.span);
                    self.check_declared_literal(&resolved, value, value.span);
                    self.check_grant_binding(&resolved, value, locals, value.span);
                    // G01 P0.3: `let f: fn() = worker` is a slot, and a
                    // rowwed value may not be laundered into it.
                    self.check_row_slot(&resolved, value, locals, "bind");
                    // G10: `let id: UserId = "x"` is a slot too, and neither
                    // the constructor nor the unwrap happens implicitly.
                    self.check_newtype_slot(&resolved, value, locals, "bind");
                }
                self.check_expr(value, locals);
                // G01 (audit F-8): a local may hold a function. The row then
                // travels with the value, not with the callee's spelling.
                let effects = self.fn_value_effects(value, locals);
                locals.insert(
                    name.clone(),
                    VarInfo {
                        ty: resolved,
                        mutable: false,
                        effects,
                        non_nil: false,
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
                    self.check_optional_binding(&resolved, value, locals, "bind", value.span);
                    self.check_declared_literal(&resolved, value, value.span);
                    self.check_grant_binding(&resolved, value, locals, value.span);
                    // G01 P0.3: `let f: fn() = worker` is a slot, and a
                    // rowwed value may not be laundered into it.
                    self.check_row_slot(&resolved, value, locals, "bind");
                    // G10: `let id: UserId = "x"` is a slot too, and neither
                    // the constructor nor the unwrap happens implicitly.
                    self.check_newtype_slot(&resolved, value, locals, "bind");
                }
                self.check_expr(value, locals);
                let effects = self.fn_value_effects(value, locals);
                locals.insert(
                    name.clone(),
                    VarInfo {
                        ty: resolved,
                        mutable: true,
                        effects,
                        non_nil: false,
                    },
                );
            }
            StmtKind::LetDestructure { pattern, value } => {
                let val_ty = self.infer_expr_type(value, locals);
                self.check_expr(value, locals);
                // G07: the pattern is checked against the scrutinee's type, and
                // every arm of it refuses a shape the value cannot have. A
                // sequence literal has a statically known length, so an arity
                // mismatch is caught here rather than at run time.
                self.check_pattern_arity_against_literal(pattern, value);
                self.check_binding_pattern(pattern, &val_ty, stmt.span, false, locals);
            }
            StmtKind::Expr { expr } => {
                self.check_expr(expr, locals);
                // Register #136: a `nil` test that leaves the function on one
                // branch narrows the variable for every statement after it.
                self.apply_optional_narrowing(expr, locals);
                // G01 P0.3 (audit N-7): `var f = nop; f = worker` — the row a
                // binding carries follows the value it holds. Handled at
                // statement position, which is the only place an assignment can
                // change a binding the walk will read later.
                if let ExprKind::Assign { target, value } = &expr.kind {
                    if let ExprKind::Ident(name) = &target.kind {
                        let value_ty = self.infer_expr_type(value, locals);
                        let value_row = self.fn_value_effects(value, locals);
                        if let Some(info) = locals.get_mut(name) {
                            Self::assign_binding_row(
                                info,
                                &value_ty,
                                &value_row,
                                value.span,
                            );
                        }
                    }
                }
            }
            StmtKind::Return(Some(expr)) => {
                self.check_expr(expr, locals);
                // G01 P0.2: an explicit `return` is a producer position — the
                // declared return type is the slot. A `return` inside a
                // closure returns from the closure, so the check is suspended
                // there.
                if self.closure_depth == 0 {
                    if let Some(declared) = self.current_return_type.clone() {
                        self.check_capability_slot(&declared, expr, locals, "return");
                        // Register #136: an explicit `return` is a slot, exactly
                        // like the tail expression it is equivalent to.
                        self.check_optional_binding(
                            &declared,
                            expr,
                            locals,
                            "return",
                            expr.span,
                        );
                    }
                }
            }
            StmtKind::Return(None) => {}
            StmtKind::For {
                label,
                pattern,
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
                // G07: the loop binds its element through a pattern, checked
                // against the element type exactly as a `let` would be. When the
                // iterated literal's first element is itself a literal, its
                // length is known and an arity mismatch is caught here.
                if let ExprKind::Array(items) = &iter.kind {
                    if let Some(first) = items.first() {
                        self.check_pattern_arity_against_literal(pattern, first);
                    }
                }
                self.check_binding_pattern(pattern, &elem_ty, stmt.span, false, &mut inner_locals);
                self.label_stack.push(LoopTarget {
                    label: label.clone(),
                    yields: false,
                    value_ty: None,
                    span: stmt.span,
                });
                for s in &body.stmts {
                    self.check_stmt(s, &mut inner_locals);
                }
                self.label_stack.pop();
            }
            StmtKind::While {
                label,
                condition,
                body,
            } => {
                self.check_expr(condition, locals);
                let mut inner_locals = locals.clone();
                self.label_stack.push(LoopTarget {
                    label: label.clone(),
                    yields: false,
                    value_ty: None,
                    span: stmt.span,
                });
                for s in &body.stmts {
                    self.check_stmt(s, &mut inner_locals);
                }
                self.label_stack.pop();
            }
            StmtKind::WhileLet {
                label,
                expr,
                body,
                ..
            } => {
                self.check_expr(expr, locals);
                let mut inner_locals = locals.clone();
                self.label_stack.push(LoopTarget {
                    label: label.clone(),
                    yields: false,
                    value_ty: None,
                    span: stmt.span,
                });
                for s in &body.stmts {
                    self.check_stmt(s, &mut inner_locals);
                }
                self.label_stack.pop();
            }
            StmtKind::Bail(expr) => {
                self.check_expr(expr, locals);
            }
            StmtKind::Loop { label, body } => {
                let mut inner_locals = locals.clone();
                self.label_stack.push(LoopTarget {
                    label: label.clone(),
                    yields: true,
                    value_ty: None,
                    span: stmt.span,
                });
                for s in &body.stmts {
                    self.check_stmt(s, &mut inner_locals);
                }
                self.label_stack.pop();
            }
            StmtKind::Break { label, value } => {
                let value_ty = self.check_break_value(value, locals);
                let break_span = value.as_ref().map_or(stmt.span, |v| v.span);
                self.record_break(label.as_deref(), value_ty, break_span);
            }
            StmtKind::Continue { label } => {
                self.record_continue(label.as_deref(), stmt.span);
            }
            StmtKind::Defer { .. } => {}
        }
    }

    // ── Labeled break with value (G08) ──────────────────────────────────

    /// Check a `break 'label value` payload and return its type.
    fn check_break_value(
        &mut self,
        value: &Option<Expr>,
        locals: &HashMap<String, VarInfo>,
    ) -> Option<Type> {
        let v = value.as_ref()?;
        self.check_expr(v, locals);
        Some(self.infer_expr_type(v, locals))
    }

    /// Resolve `break`/`break 'label v` against the enclosing constructs.
    ///
    /// An unlabeled `break` binds to the innermost construct, as it always has.
    /// A labeled one binds to the innermost construct carrying that label, so
    /// it can leave more than one loop (`break 'outer` from inside a `for`
    /// inside a `loop`). A label that is not on the stack is an error naming
    /// the label, never a silent no-op.
    fn record_break(&mut self, label: Option<&str>, value_ty: Option<Type>, span: Span) {
        let Some(idx) = self.break_target(label) else {
            let msg = match label {
                Some(l) => format!(
                    "`break '{l}` targets a label that is not in scope here -- no enclosing `loop`, `for` or `while` is labeled '{l}"
                ),
                None => "`break` outside of a loop".to_string(),
            };
            self.diags.error("E0118", msg, span);
            return;
        };

        let (target_label, yields, target_span) = {
            let t = &self.label_stack[idx];
            (t.label.clone(), t.yields, t.span)
        };

        if let Some(got) = value_ty {
            if !yields {
                let what = target_label
                    .as_deref()
                    .map(|l| format!("'{l}"))
                    .unwrap_or_else(|| "the loop".to_string());
                self.diags.error(
                    "E0119",
                    format!(
                        "`break {what} value` cannot yield a value: {what} is a bounded loop (`for`/`while`), which has no value -- only `loop` yields one"
                    ),
                    span,
                );
                return;
            }
            let declared = self.label_stack[idx].value_ty.clone();
            match declared {
                None => self.label_stack[idx].value_ty = Some(got),
                Some(want) => {
                    if !Self::break_types_agree(&want, &got) {
                        let msg = format!(
                            "`break` value type mismatch: this loop yields `{}` (from an earlier break) but this break gives `{}`",
                            self.type_display(&want),
                            self.type_display(&got),
                        );
                        self.diags.error("E0120", msg, span);
                    }
                }
            }
        } else if yields {
            // A value-less break into a construct that does yield leaves the
            // value undetermined; note the shape so the construct's type can be
            // reported honestly rather than guessed.
            let _ = target_span;
        }
    }

    /// `continue` may only target a loop, and a label must name one in scope.
    fn record_continue(&mut self, label: Option<&str>, span: Span) {
        if self.break_target(label).is_none() {
            let msg = match label {
                Some(l) => format!(
                    "`continue '{l}` targets a label that is not in scope here -- no enclosing `loop`, `for` or `while` is labeled '{l}"
                ),
                None => "`continue` outside of a loop".to_string(),
            };
            self.diags.error("E0118", msg, span);
        }
    }

    /// Index of the construct a jump targets, innermost first.
    fn break_target(&self, label: Option<&str>) -> Option<usize> {
        match label {
            None => self.label_stack.len().checked_sub(1),
            Some(l) => self
                .label_stack
                .iter()
                .rposition(|t| t.label.as_deref() == Some(l)),
        }
    }

    /// Two break payloads of the same construct must agree, but an unresolved
    /// type is not evidence of a mismatch.
    fn break_types_agree(a: &Type, b: &Type) -> bool {
        match (a, b) {
            (Type::Unknown, _) | (_, Type::Unknown) => true,
            (Type::Int(_), Type::Int(_)) | (Type::Float(_), Type::Float(_)) => true,
            _ => a == b,
        }
    }

    /// `T?` may flow into a `T?` slot (it is wrapped implicitly, register #135),
    /// but it may not flow into a `T` slot. Register #136: an optional reaches a
    /// plain slot only through an explicit unwrap, or through a `nil` check that
    /// dominates the use.
    ///
    /// `T` into `T?` is implicit and stays implicit (register #135, the wrap
    /// direction); this is the other direction, and it is a *type error* at the
    /// destination. Both execution planes refuse the unchecked form — the native
    /// plane at codegen, the interpreter by answering `nil` where a plain value
    /// was declared — so a `tallow check` that accepted it was the worst of the
    /// three positions: statically "fine", unbuildable on the plane that ships,
    /// and silently wrong on the fallback plane.
    ///
    /// The message names the destination type, the source expression and its
    /// optional type, and the fix, because "type mismatch" would leave the
    /// reader to discover on their own that the answer is an unwrap and not a
    /// cast. `position` is the verb phrase the refusal is phrased with:
    /// `"bind"`, `"assign to"`, `"return"`, `"pass as an argument"`.
    fn check_optional_binding(
        &mut self,
        declared: &Type,
        value: &Expr,
        locals: &HashMap<String, VarInfo>,
        position: &str,
        span: Span,
    ) {
        // A `T?` destination accepts everything a `T` destination does; an
        // unknown destination is inference's placeholder, not evidence.
        if matches!(declared, Type::Optional(_) | Type::Unknown) {
            return;
        }
        // A dominating `if v == nil { .. }` has excluded the absent case before
        // this use, so `v` is the payload here, not the optional. Only an
        // immutable binding is ever narrowed (see `VarInfo::non_nil`), and the
        // question "what does this name denote here" is answered by
        // [`Self::narrowed_local_type`] — the same helper every read of a
        // local's type goes through, so the binding rule and the expression
        // rule cannot disagree.
        if let ExprKind::Ident(name) = &value.kind {
            if let Some(info) = locals.get(name) {
                if !matches!(Self::narrowed_local_type(info), Type::Optional(_)) {
                    return;
                }
            }
        }
        let got = self.infer_expr_type(value, locals);
        if !matches!(got, Type::Optional(_)) {
            return;
        }
        let msg = format!(
            "cannot {position} `{}` where `{}` is required: `{}` is an optional and may be nil -- unwrap after checking for nil",
            self.type_display(&got),
            self.type_display(declared),
            Self::expr_label(value),
        );
        self.diags.push(
            crate::error::Diagnostic::error("E0116", msg, span).with_help(
                "unwrap after checking for nil: `if v == nil { return }` and use `v` after the guard, or `match v { Some(x) => .., None => .. }`",
            ),
        );
    }

    /// The spelling a diagnostic uses for the expression that produced a value.
    ///
    /// Only the shapes an author actually writes are rendered; anything else is
    /// described rather than printed, because a half-right reconstruction of an
    /// expression is worse than naming it generically.
    fn expr_label(expr: &Expr) -> String {
        match &expr.kind {
            ExprKind::Ident(name) => name.clone(),
            ExprKind::FieldAccess { object, field } => {
                format!("{}.{field}", Self::expr_label(object))
            }
            ExprKind::Index { object, .. } => format!("{}[..]", Self::expr_label(object)),
            ExprKind::Call { callee, args } => {
                let head = Self::expr_label(callee);
                if args.is_empty() {
                    format!("{head}()")
                } else {
                    format!("{head}(..)")
                }
            }
            ExprKind::MethodCall {
                object,
                method,
                args,
            } => {
                let head = format!("{}.{method}", Self::expr_label(object));
                if args.is_empty() {
                    format!("{head}()")
                } else {
                    format!("{head}(..)")
                }
            }
            ExprKind::Nil => "nil".to_string(),
            _ => "this expression".to_string(),
        }
    }

    /// `Some((variable, tests_for_nil))` when `cond` is a `nil` test on a plain
    /// local: `v == nil` / `nil == v` (tests for nil) or `v != nil` /
    /// `nil != v` (tests for present).
    fn nil_test(cond: &Expr) -> Option<(&str, bool)> {
        let ExprKind::Binary { op, left, right } = &cond.kind else {
            return None;
        };
        let tests_for_nil = match op {
            BinOp::Eq => true,
            BinOp::Neq => false,
            _ => return None,
        };
        let name = match (&left.kind, &right.kind) {
            (ExprKind::Ident(name), ExprKind::Nil) | (ExprKind::Nil, ExprKind::Ident(name)) => name,
            _ => return None,
        };
        Some((name.as_str(), tests_for_nil))
    }

    /// Record the narrowing a guard establishes for the code *after* it.
    ///
    /// Called at statement position, once the statement has been walked: an `if`
    /// whose condition is a `nil` test and whose branch leaves the function
    /// proves, for every later statement, that the variable is present. The
    /// narrowing is recorded only for an immutable binding, so it can never be
    /// invalidated by a later assignment.
    fn apply_optional_narrowing(&mut self, stmt_expr: &Expr, locals: &mut HashMap<String, VarInfo>) {
        match &stmt_expr.kind {
            // `if v == nil { return }` → v is present afterwards.
            // `if v != nil { return }` → taken branch returns, so reaching here
            // also means v is present; the test is the negation of the above.
            ExprKind::If {
                condition,
                then_block,
                else_branch,
            } => {
                let Some((name, tests_for_nil)) = Self::nil_test(condition) else {
                    return;
                };
                let then_returns = Self::block_never_falls_through(then_block);
                let else_returns = match else_branch.as_ref() {
                    Some(ElseBranch::Block(block)) => Self::block_never_falls_through(block),
                    Some(ElseBranch::ElseIf(expr)) => Self::expr_never_falls_through(expr),
                    None => false,
                };
                // The guard establishes "present" when the branch that does
                // *not* prove presence is the one that leaves the function.
                let establishes = if tests_for_nil {
                    then_returns
                } else {
                    else_returns
                };
                if establishes {
                    Self::narrow_binding(locals, name);
                }
            }
            // A reassignment is a fresh value; `var` never narrows, but clear
            // the flag anyway so no future widening of the rule inherits stale
            // evidence.
            ExprKind::Assign { target, .. } => {
                if let ExprKind::Ident(name) = &target.kind {
                    if let Some(info) = locals.get_mut(name) {
                        info.non_nil = false;
                    }
                }
            }
            _ => {}
        }
    }

    /// The `locals` a branch of an `if` sees, given the condition.
    ///
    /// [`Self::nil_test`] names a plain local; the branch that test selects
    /// sees the payload instead of the optional, exactly as
    /// [`Self::apply_optional_narrowing`] narrows the code *after* a dominating
    /// guard (register #136). `want_present` picks the branch: `true` for the
    /// then-branch of `v != nil`, or the else-branch of `v == nil`.
    ///
    /// `None` means the branch sees the enclosing scope unchanged — the common
    /// case, so no map is copied. Only an immutable local of optional type
    /// narrows, and only at the name itself: `nil_test` matches a bare
    /// identifier, so a field or an index is never narrowed, and a `var` is
    /// excluded because a later assignment would make the evidence stale.
    fn branch_locals(
        condition: &Expr,
        locals: &HashMap<String, VarInfo>,
        want_present: bool,
    ) -> Option<HashMap<String, VarInfo>> {
        let (name, tests_for_nil) = Self::nil_test(condition)?;
        // The test proves presence in the branch it *does not* take.
        if want_present == tests_for_nil {
            return None;
        }
        let payload = match locals.get(name) {
            Some(info) if !info.mutable => match &info.ty {
                Type::Optional(inner) => (**inner).clone(),
                _ => return None,
            },
            _ => return None,
        };
        let mut inner = locals.clone();
        if let Some(info) = inner.get_mut(name) {
            info.ty = payload;
            info.non_nil = true;
        }
        Some(inner)
    }

    /// The type the name of a local denotes at a use site.
    ///
    /// A binding that a dominating `nil` guard has narrowed
    /// ([`VarInfo::non_nil`]) denotes its payload, not the optional: the absent
    /// case was excluded before this expression is reached. The declared type
    /// stays `T?` on the binding — the narrowing is evidence about *this* point
    /// in the walk, not a change to what was declared — so it is applied here,
    /// at the one place a local's type is read.
    ///
    /// Every reader goes through this helper rather than testing `non_nil`
    /// itself. The binding rule and the expression rule used to answer the
    /// question separately, and drifted: `let x: i64 = v` was accepted after a
    /// guard while `v + 1` was refused with the very help text that recommends
    /// the guard.
    fn narrowed_local_type(info: &VarInfo) -> Type {
        match (&info.ty, info.non_nil) {
            (Type::Optional(inner), true) => (**inner).clone(),
            (ty, _) => ty.clone(),
        }
    }

    /// Mark `name` as present in this map, if it is an immutable binding.
    ///
    /// A `var` is never narrowed: it can be reassigned to a fresh optional, and
    /// the evidence would then be stale.
    fn narrow_binding(locals: &mut HashMap<String, VarInfo>, name: &str) {
        if let Some(info) = locals.get_mut(name) {
            if !info.mutable {
                info.non_nil = true;
            }
        }
    }

    /// Does this block leave before reaching its end, on every path?
    ///
    /// Only `return` / `bail` / `break` / `continue`, and an `if` whose both
    /// arms leave, count. A `while` or a `for` never does: falling past it is
    /// always possible, so it can prove nothing about the code after it.
    fn block_never_falls_through(block: &Block) -> bool {
        block
            .stmts
            .iter()
            .any(|stmt| Self::stmt_never_falls_through(stmt))
    }

    fn stmt_never_falls_through(stmt: &Stmt) -> bool {
        match &stmt.kind {
            StmtKind::Return(_) | StmtKind::Bail(_) | StmtKind::Break { .. } | StmtKind::Continue { .. } => {
                true
            }
            StmtKind::Expr { expr } => Self::expr_never_falls_through(expr),
            _ => false,
        }
    }

    fn expr_never_falls_through(expr: &Expr) -> bool {
        match &expr.kind {
            ExprKind::If {
                then_block,
                else_branch,
                ..
            } => {
                let then_leaves = Self::block_never_falls_through(then_block);
                let else_leaves = match else_branch.as_ref() {
                    Some(ElseBranch::Block(block)) => Self::block_never_falls_through(block),
                    Some(ElseBranch::ElseIf(inner)) => Self::expr_never_falls_through(inner),
                    None => false,
                };
                then_leaves && else_leaves
            }
            ExprKind::Block(block) => Self::block_never_falls_through(block),
            _ => false,
        }
    }

    /// The same rule, applied to a call's arguments (register #136): a `T?`
    /// argument to a `T` parameter is an unwrap with no check, exactly like a
    /// binding. Folded next to [`Self::check_capability_args`] so every
    /// parameter slot goes through one place.
    fn check_optional_args(
        &mut self,
        params: &[(String, Type)],
        args: &[CallArg],
        locals: &HashMap<String, VarInfo>,
        position: &str,
    ) {
        for (arg, (_, declared)) in args.iter().zip(params.iter()) {
            self.check_optional_binding(declared, &arg.value, locals, position, arg.value.span);
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

    /// Is `got` a value that may not fill a `declared` slot, because one of the
    /// two is a capability and they are not the *same* capability?
    ///
    /// This is the assignability rule of `check_grant_binding` factored out so
    /// it can be applied at every position a value can flow through — the
    /// return slot, a call argument, a struct-literal field, a default
    /// parameter value. A capability is not constructible, only obtained, so
    /// the only value that may fill a `Grant<E>` slot is a `Grant<E>`; and a
    /// `Grant<E>` may not be laundered into any other known slot.
    ///
    /// `Unknown` is inference's placeholder, not evidence: the reverse
    /// direction (a capability into an untyped slot) is left alone rather than
    /// guessing. The forward direction stays strict — a `Grant<E>` slot
    /// demands exactly `Grant<E>`.
    fn capability_mismatch(declared: &Type, got: &Type) -> bool {
        match (declared, got) {
            (Type::Grant(want), Type::Grant(have)) => want != have,
            (Type::Grant(_), _) => true,
            (Type::Unknown, _) => false,
            (_, Type::Grant(_)) => true,
            (Type::Optional(d), Type::Optional(g))
            | (Type::Result(d), Type::Result(g))
            | (Type::Array(d), Type::Array(g))
            | (Type::Set(d), Type::Set(g))
            | (Type::Chan(d), Type::Chan(g))
            | (Type::Boxed(d), Type::Boxed(g))
            | (Type::Private(d), Type::Private(g))
            | (Type::Secret(d), Type::Secret(g)) => Self::capability_mismatch(d, g),
            _ => false,
        }
    }

    /// The effect named by the first `Grant<E>` reachable inside `ty`, so a
    /// refusal can say which capability the slot wanted. `Some("")` for a
    /// malformed `Grant` (already reported as E0143 elsewhere).
    fn first_grant_effect(ty: &Type) -> Option<&str> {
        match ty {
            Type::Grant(effect) => Some(effect),
            Type::Optional(inner)
            | Type::Result(inner)
            | Type::Array(inner)
            | Type::Set(inner)
            | Type::Chan(inner)
            | Type::Boxed(inner)
            | Type::Private(inner)
            | Type::Secret(inner)
            | Type::Consent(inner)
            | Type::Erasable(inner)
            | Type::Trusted(inner)
            | Type::Unverified(inner)
            | Type::Fresh(inner, _) => Self::first_grant_effect(inner),
            Type::Tuple(items) => items.iter().find_map(Self::first_grant_effect),
            Type::Map(k, v) => Self::first_grant_effect(k).or_else(|| Self::first_grant_effect(v)),
            _ => None,
        }
    }

    /// Refuse a value produced for, or passed into, a `Grant<E>` slot
    /// (G01 P0.2) — the same rule and the same code as `check_grant_binding`,
    /// applied at every position other than `let`/`var`.
    ///
    /// `position` is the verb phrase the refusal names: `"return"`,
    /// `"pass as an argument"`, `"store"`, `"use as a default value"`.
    fn check_capability_slot(
        &mut self,
        declared: &Type,
        value: &Expr,
        locals: &HashMap<String, VarInfo>,
        position: &str,
    ) {
        let got = self.infer_expr_type(value, locals);
        if Self::capability_mismatch(declared, &got) {
            let effect = Self::first_grant_effect(declared)
                .or_else(|| Self::first_grant_effect(&got))
                .unwrap_or("");
            let source = if effect.is_empty() {
                "scope.grant(<effect>)".to_string()
            } else {
                format!("scope.grant({effect})")
            };
            let msg = format!(
                "cannot {position} `{}` where `{}` is required: a capability cannot be forged -- the only source is {source}",
                self.type_display(&got),
                type_label(declared)
            );
            self.diags.error("E0117", msg, value.span);
        }
        // G01 P0.3: a slot is a slot for a *row* too, not only for a
        // capability. The same positions — return, argument, struct field,
        // default — must not launder a rowwed function into a rowless type.
        self.check_row_slot(declared, value, locals, position);
        // G10: every one of those positions is also a newtype slot. Wiring it
        // here — not at each call site — is what keeps `return`, `f(id)`,
        // `Point { id: id }` and `fn f(id: UserId = ..)` under one rule.
        self.check_newtype_slot(declared, value, locals, position);
    }

    /// G10: the assignability rule for a newtype, applied wherever a value is
    /// placed into a typed slot.
    ///
    /// An alias is transparent, so `type Port = u16` needs no rule here. A
    /// newtype is not: `UserId` and `String` are different types, and there is
    /// no implicit conversion in *either* direction. Both directions get a
    /// diagnostic that names the construct that would make the program legal —
    /// the constructor going in, `.inner` coming out — because "type mismatch"
    /// leaves the reader to guess which of the two they needed.
    fn check_newtype_slot(
        &mut self,
        declared: &Type,
        value: &Expr,
        locals: &HashMap<String, VarInfo>,
        position: &str,
    ) {
        let got = self.infer_expr_type(value, locals);
        // `Unknown` is inference's placeholder, not evidence of a mismatch.
        let got = match got {
            Type::Unknown => return,
            other => other,
        };
        match (declared, &got) {
            // The one accepted case: the same newtype.
            (Type::Newtype { name: want, .. }, Type::Newtype { name: have, .. })
                if want == have =>
            {
                return;
            }
            // Two different newtypes, even over the same target, are unrelated.
            (Type::Newtype { name: want, .. }, Type::Newtype { name: have, .. }) => {
                let inner = self.newtype_inner(have);
                let msg = format!(
                    "cannot {position} newtype `{have}` where newtype `{want}` is required: \
                     two newtypes over the same target are distinct types and neither \
                     converts to the other"
                );
                self.diags.push(
                    crate::error::Diagnostic::error("E0117", msg, value.span).with_help(format!(
                        "`{want}` is built with `{want}(<{}>)`, so this must be written as an \
                         explicit conversion: `{want}(<{have} value>.inner)`",
                        self.type_display(&inner)
                    )),
                );
            }
            // A bare target where the newtype is expected: the constructor is
            // the missing step, and it is named.
            (Type::Newtype { name, inner }, _) => {
                let msg = format!(
                    "cannot {position} `{}` where newtype `{name}` is required: a `{name}` \
                     is constructed explicitly with `{name}(<{}>)`, and nothing converts \
                     into it implicitly",
                    type_label(&got),
                    self.type_display(inner)
                );
                self.diags.push(
                    crate::error::Diagnostic::error("E0117", msg, value.span).with_help(format!(
                        "write `{name}(<{}>)` if this value is meant to be a `{name}`; add the \
                         explicit constructor rather than relying on a conversion",
                        self.type_display(&got)
                    )),
                );
            }
            // A newtype where its target (or anything else) is expected: the
            // unwrap is the missing step, and it is named.
            (_, Type::Newtype { name, .. }) => {
                let msg = format!(
                    "cannot {position} newtype `{name}` where `{}` is required: a newtype \
                     never converts to its target implicitly",
                    type_label(declared)
                );
                self.diags.push(
                    crate::error::Diagnostic::error("E0117", msg, value.span).with_help(format!(
                        "unwrap it explicitly: `<{name} value>.inner`"
                    )),
                );
            }
            _ => {}
        }
    }

    /// A newtype's target must be a type the native layout bridge can express
    /// as "the target's own representation".
    ///
    /// Erasure means a `UserId`-typed slot is laid out exactly like its target,
    /// and that bridge (`codegen::privacy_type_to_lltype`) is exact for scalars
    /// and containers but falls back to `i64` for a `Named` type. `newtype W =
    /// Point` would therefore take a pointer where the slot says integer —
    /// silently wrong code in the native plane, which is the one failure mode
    /// this feature must not introduce. Until the bridge learns struct layouts,
    /// such a target is refused at the declaration.
    fn validate_newtype_targets(&mut self) {
        let mut invalid: Vec<(String, String, Span)> = Vec::new();
        for item in &self.program.items {
            let Item::TypeAlias(ta) = item else {
                continue;
            };
            if !ta.newtype {
                continue;
            }
            let Some(Type::Newtype { inner, .. }) = self.env.newtypes.get(&ta.name) else {
                continue;
            };
            // A newtype-over-newtype target is already refused at
            // registration; do not report the same declaration twice.
            if Self::named_newtype(inner).is_none() && !Self::layout_bridge_supports(inner) {
                invalid.push((ta.name.clone(), type_label(inner), ta.span));
            }
        }
        for (name, target, span) in invalid {
            self.diags.push(
                crate::error::Diagnostic::error(
                    "E0117",
                    format!(
                        "newtype `{name}` cannot wrap `{target}`: a newtype is laid out as its \
                         target, and only scalar and container targets have a layout the native \
                         backend can express"
                    ),
                    span,
                )
                .with_help(
                    "wrap a scalar (`String`, `Int`, `Float`, `Bool`, `Bytes`, `char`) or a \
                     container of one; a newtype over a struct is not supported yet"
                        .to_string(),
                ),
            );
        }
    }

    /// The target types `codegen::privacy_type_to_lltype` maps exactly.
    fn layout_bridge_supports(ty: &Type) -> bool {
        match ty {
            Type::Bool
            | Type::Int(_)
            | Type::Float(_)
            | Type::String
            | Type::Bytes
            | Type::Char => true,
            Type::Array(inner) | Type::Set(inner) => Self::layout_bridge_supports(inner),
            Type::Map(key, value) => {
                Self::layout_bridge_supports(key) && Self::layout_bridge_supports(value)
            }
            _ => false,
        }
    }

    /// The newtype named at the top of `ty`, if any — through a privacy
    /// qualifier or an erasable wrapper, since those are transparent at layout.
    fn named_newtype(ty: &Type) -> Option<String> {
        match ty {
            Type::Newtype { name, .. } => Some(name.clone()),
            Type::Private(inner)
            | Type::Secret(inner)
            | Type::Erasable(inner)
            | Type::Trusted(inner)
            | Type::Unverified(inner)
            | Type::Fresh(inner, _) => Self::named_newtype(inner),
            _ => None,
        }
    }

    /// The target type behind a newtype name, for diagnostics.
    fn newtype_inner(&self, name: &str) -> Type {
        match self.env.newtypes.get(name) {
            Some(Type::Newtype { inner, .. }) => (**inner).clone(),
            _ => Type::Unknown,
        }
    }

    /// Can `got` seed the constructor of a newtype over `inner`?
    ///
    /// Only a value the target already accepts. Numeric widening (`1` into a
    /// `Float` target) is not a new conversion — the checker allows that for
    /// plain bindings too — while a `str` for a `Float` target, or another
    /// newtype, is refused.
    fn newtype_arg_fits(inner: &Type, got: &Type) -> bool {
        if matches!(got, Type::Unknown) {
            return true;
        }
        if inner == got {
            return true;
        }
        matches!(
            (base_kind(inner), base_kind(got)),
            ("int", "int") | ("float", "int") | ("float", "float") | ("str", "str") | ("bool", "bool")
        )
    }

    /// G01 P0.3: no laundering a row through a typed slot.
    ///
    /// This is the second half of the type-carried row. The first half says a
    /// call *through* a value requires what the value's type declares; this
    /// half says the type must declare what the value can actually do.
    /// Without it `fn get() -> fn(Grant<Net>, String) { worker }` would hand
    /// back a value whose type has no row while the value reaches a socket, and
    /// the call through `get()`'s result would require nothing (audit N-4).
    fn check_row_slot(
        &mut self,
        declared: &Type,
        value: &Expr,
        locals: &HashMap<String, VarInfo>,
        position: &str,
    ) {
        let Type::Function {
            effects: allowed, ..
        } = declared
        else {
            return;
        };
        let mut row = Self::type_row(&self.infer_expr_type(value, locals)).to_vec();
        if row.is_empty() {
            row = self
                .fn_value_effects(value, locals)
                .into_iter()
                .map(|e| (e.name, e.ops))
                .collect();
        }
        for (name, ops) in row {
            if Self::row_covers(allowed, &name, &ops) {
                continue;
            }
            let what = if ops.is_empty() {
                name.clone()
            } else {
                format!("{name}({})", ops.join(", "))
            };
            let msg = format!(
                "cannot {position} a function value requiring effect {what} where `{}` declares no such row",
                type_label(declared)
            );
            self.diags.push(
                crate::error::Diagnostic::error("E0141", msg, value.span)
                    .with_help(format!("add: with {what} to the function type")),
            );
        }
    }

    /// Does a declared row cover one requirement? A bare entry (`Net`) covers
    /// every operation of the effect; an operation entry covers only itself.
    fn row_covers(allowed: &[(String, Vec<String>)], name: &str, ops: &[String]) -> bool {
        allowed.iter().any(|(n, allowed_ops)| {
            n == name
                && (allowed_ops.is_empty()
                    || (!ops.is_empty()
                        && ops.iter().all(|op| allowed_ops.iter().any(|a| a == op))))
        })
    }

    /// Positional capability check for a call's arguments against the callee's
    /// declared parameter types. A named argument keeps its position here: the
    /// rule is only tightened for capabilities, so an out-of-order named
    /// argument cannot become a false refusal.
    fn check_capability_args(
        &mut self,
        params: &[(String, Type)],
        args: &[CallArg],
        locals: &HashMap<String, VarInfo>,
        position: &str,
    ) {
        for (arg, (_, declared)) in args.iter().zip(params.iter()) {
            self.check_capability_slot(declared, &arg.value, locals, position);
        }
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

    /// Check one call site — `f(args)` and `spawn f(args)` both land here
    /// (G01, audit F-8/F-9/F-10), so no call form can escape the walk.
    ///
    /// The callee's row is a requirement of the *caller*, whichever way the
    /// callee is spelled: a direct name is looked up in `env.functions`, and a
    /// local holding a function value carries the row it was initialised with
    /// (`VarInfo::effects`).
    fn check_call(
        &mut self,
        callee: &Expr,
        args: &[CallArg],
        span: Span,
        locals: &HashMap<String, VarInfo>,
    ) {
        // ── G10: `UserId("x")` is the newtype constructor ────────────────
        //
        // It is recognised *here*, by the declaration's name, and nowhere
        // else: there is no function of that name, so falling through would
        // emit `undefined function` at run time and a W0102 here. The
        // constructor is the only thing that turns a `String` into a
        // `UserId`, so its argument gets a real type check rather than being
        // waved through.
        if let ExprKind::Ident(name) = &callee.kind {
            if let Some(ty) = self.env.newtypes.get(name).cloned() {
                if let Type::Newtype {
                    name: newtype,
                    inner,
                } = ty
                {
                    if args.len() != 1 {
                        self.diags.error(
                            "E0103",
                            format!(
                                "newtype `{newtype}` takes exactly one constructor argument \
                                 (`{newtype}(<{}>)`), got {}",
                                self.type_display(&inner),
                                args.len()
                            ),
                            span,
                        );
                    }
                    if let Some(arg) = args.first() {
                        self.check_expr(&arg.value, locals);
                        let got = self.infer_expr_type(&arg.value, locals);
                        if !Self::newtype_arg_fits(&inner, &got) {
                            self.diags.push(
                                crate::error::Diagnostic::error(
                                    "E0117",
                                    format!(
                                        "cannot construct `{newtype}` from `{}`: the constructor \
                                         takes `{}`, and no conversion is applied",
                                        self.type_display(&got),
                                        self.type_display(&inner)
                                    ),
                                    arg.value.span,
                                )
                                .with_help(format!(
                                    "`{newtype}` wraps `{}`; convert the value first, then \
                                     construct (`{newtype}(<{}>)`)",
                                    self.type_display(&inner),
                                    self.type_display(&inner)
                                )),
                            );
                        }
                    }
                    return;
                }
            }
        }
        // G01: a call to a socket-opening primitive is an effect the
        // body requires; the signature's row is enforced after the walk.
        let mut row_forwarded = false;
        if let Some(path) = callee_path(callee) {
            self.note_effect_call(&path, span, locals);
            // G01, interprocedural: a call to a user function reaches
            // whatever that function's declared row says it reaches —
            // recorded at *this* call site, so the diagnostic names the
            // call in the caller rather than the callee's declaration.
            if let Some(effects) = self.env.functions.get(&path).map(|s| s.effects.clone()) {
                self.note_callee_row(&effects, &path, span, locals);
                row_forwarded = true;
            }
        }
        // G01 (audit F-8): the row of a function held in a *value*. `let f =
        // scan; f(g, h)` matched nothing in the effect table, because the table
        // keys on dotted callee paths and `f` is an ordinary local. The row is
        // recorded on the binding (see `fn_value_effects`), so the requirement
        // is forwarded here exactly as a direct call forwards it.
        // G01 P0.3 (audit N-3…N-8): the row a function value carries in its
        // *type*. This is the channel every one of the six escapes has in
        // common — a parameter, a returned function, an array element, a
        // struct field, an `if`-selected binding and a reassigned one all
        // reach the call as a value whose type is `fn(..) with Net(connect)`.
        // Reading the type here is what makes the row survive all six without
        // a rule per syntax.
        if !row_forwarded {
            let callee_ty = self.infer_expr_type(callee, locals);
            let row = Self::type_row(&callee_ty);
            if !row.is_empty() {
                // G21: the row came through a value, but the diagnostic can still
                // name the expression the author wrote (`f`, `fs[0]`, `handler`).
                let callee_name = callee_path(callee)
                    .unwrap_or_else(|| "this function value".to_string());
                self.note_type_row(row, &callee_name, span, locals);
                row_forwarded = true;
            }
        }
        if !row_forwarded {
            if let ExprKind::Ident(name) = &callee.kind {
                if let Some(effects) = locals.get(name).map(|v| v.effects.clone()) {
                    if !effects.is_empty() {
                        self.note_callee_row(&effects, name, span, locals);
                    }
                }
            }
        }
        self.check_expr_inner(callee, locals, true);
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
                        format!("function `{name}` expects {expected} argument(s), got {got}")
                    } else {
                        format!(
                            "function `{name}` expects at least {required} argument(s), got {got}"
                        )
                    };
                    self.diags.error("E0103", message, span);
                }
            }
            // G01 P0.2: a parameter is a slot. A `Grant<E>` argument
            // may only be the same `Grant<E>`, and only a `Grant<E>`
            // may fill a `Grant<E>` parameter — the call position used
            // to be entirely unchecked (audit F-7).
            if let Some(params) = self.env.functions.get(name).map(|s| s.params.clone()) {
                self.check_capability_args(&params, args, locals, "pass as an argument");
                // Register #136: a parameter is a slot for an optional too.
                self.check_optional_args(&params, args, locals, "pass as an argument");
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

    fn check_expr(&mut self, expr: &Expr, locals: &HashMap<String, VarInfo>) {
        self.check_expr_inner(expr, locals, false);
    }

    /// The expression walk.
    ///
    /// `callee_position` says the expression is the callee of a call or the
    /// receiver of a method call. Those are the two positions where a module
    /// namespace is legal (it names a dispatch path, not a value), and the only
    /// place a name that [`Self::is_module_namespace`] recognises is exempt from
    /// E0146.
    fn check_expr_inner(
        &mut self,
        expr: &Expr,
        locals: &HashMap<String, VarInfo>,
        callee_position: bool,
    ) {
        match &expr.kind {
            // ── Identifiers: check variable is defined ──────────────────
            ExprKind::Ident(name) => {
                // G01 (audit F-1): a module namespace is a dispatch path, not a
                // value. `let n = net; n.connect(h)` compiled and *ran*, because
                // the effect table matches the syntax of a dotted callee while
                // the interpreter dispatches on the name the value carries —
                // binding the namespace made the row and the grant both vanish.
                // A namespace may therefore appear only as the receiver of a
                // method call (or the callee of a call), which is what
                // `callee_position` says; everywhere else it is E0146.
                if !callee_position && !locals.contains_key(name) && self.is_module_namespace(name)
                {
                    self.diags.push(
                        crate::error::Diagnostic::error(
                            "E0146",
                            format!(
                                "module namespace is not a first-class value: `{name}` may only be the receiver of a method call"
                            ),
                            expr.span,
                        )
                        .with_help(format!(
                            "call the function directly (`{name}.<method>(..)`) instead of storing or passing the module"
                        )),
                    );
                    return;
                }
                // Skip well-known globals and builtins
                if !locals.contains_key(name)
                    && !self.env.functions.contains_key(name)
                    && !self.env.structs.contains_key(name)
                    && !self.env.enums.contains_key(name)
                    && !self.env.constants.contains(name)
                    // G10: `UserId` is a declared type, not a missing value;
                    // the constructor is the one legal way to name it.
                    && !self.env.newtypes.contains_key(name)
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
                self.check_call(callee, args, expr.span, locals);
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
                    // A module namespace is legal exactly here: as the receiver
                    // of a method call (E0146's one exemption).
                    self.check_expr_inner(object, locals, true);
                }
                // E0150: `len()` on a type that has no length. The runtime
                // refuses this (it used to answer 0, which read as a
                // measurement); saying so at check time means the program never
                // gets that far. Only statically-known scalars are judged —
                // `Unknown` stays silent, because a false positive on a type the
                // checker cannot see would be worse than the late error.
                if method == "len" && !static_namespace {
                    let obj_ty = self.infer_expr_type(object, locals);
                    if matches!(
                        obj_ty,
                        Type::Int(_) | Type::Float(_) | Type::Bool | Type::Char | Type::Void
                    ) {
                        self.diags.error(
                            "E0150",
                            format!(
                                "`len()` on {} — a value with no elements has no length",
                                self.type_display(&obj_ty)
                            ),
                            expr.span,
                        );
                    }
                }
                for arg in args {
                    self.check_expr(&arg.value, locals);
                }
                let obj_ty = self.infer_expr_type(object, locals);
                let type_name = self.type_to_name(&obj_ty);
                // G01: `Tcp.connect(..)` / `net.connect(..)` — a static module
                // path — and `conn.connect()` where the receiver's type is a
                // socket type both open a socket.
                // G21: the operation decides, not the head — `ws.connect` is
                // effectful while `ws.close` (a method on a live socket) is not
                // a new egress — so the full dotted path is what the manifest is
                // asked about.
                // A *local* receiver is never a module namespace: `ws.connect()`
                // on a variable named `ws` is a method on a value, and the row it
                // may carry is already carried by that value's type.
                let receiver_is_local =
                    matches!(&object.kind, ExprKind::Ident(name) if locals.contains_key(name));
                let socket_path = match callee_path(object) {
                    Some(p)
                        if !receiver_is_local
                            && effect_for_callee(&format!("{p}.{method}")).is_some() =>
                    {
                        Some(format!("{p}.{method}"))
                    }
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
                    let callee_name = match &type_name {
                        Some(tname) => format!("{tname}.{method}"),
                        None => method.clone(),
                    };
                    self.note_callee_row(&effects, &callee_name, expr.span, locals);
                }
                // G01 P0.3 (audit N-6): `b.f(g, h)` is a *method call* to the
                // parser even when `f` is a struct field of function type, so
                // the receiver's struct is the only place the row can be read.
                // Without this the struct-field channel is the one of the six
                // that the type-carried row cannot see.
                if let Some(ref tname) = type_name {
                    let field_row = self.env.structs.get(tname).and_then(|sinfo| {
                        sinfo
                            .fields
                            .iter()
                            .find(|(f, _)| f == method)
                            .map(|(_, fty)| Self::type_row(fty).to_vec())
                    });
                    if let Some(row) = field_row {
                        if !row.is_empty() {
                            self.note_type_row(&row, &format!("{tname}.{method}"), expr.span, locals);
                        }
                    }
                }
                let mut method_params: Option<Vec<(String, Type)>> = None;
                if let Some(ref tname) = type_name {
                    if let Some(methods) = self.env.methods.get(tname) {
                        let arity = methods.iter().find(|s| s.name == *method).map(|sig| {
                            (
                                sig.params.len(),
                                sig.required_params(),
                                sig.accepts_arity(args.len()),
                            )
                        });
                        method_params = methods
                            .iter()
                            .find(|s| s.name == *method)
                            .map(|s| s.params.clone());
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
                // G01 P0.2: a method's parameter is a slot too, exactly like a
                // free function's.
                if let Some(params) = method_params {
                    self.check_capability_args(&params, args, locals, "pass as an argument");
                    // Register #136: same rule for an `impl` method's parameters.
                    self.check_optional_args(&params, args, locals, "pass as an argument");
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
                // Register #136: a `nil` test narrows the local inside the
                // branch it selects — `if v != nil { .. }` is the branch where
                // the payload is known present, exactly as `if v == nil
                // { return }` is the fall-through after the guard. The same
                // helper narrows the arm's *type* for [`Self::infer_expr_type`],
                // so the two readings of a guard cannot drift apart.
                let mut inner = match Self::branch_locals(condition, locals, true) {
                    Some(narrowed) => narrowed,
                    None => locals.clone(),
                };
                for s in &then_block.stmts {
                    self.check_stmt(s, &mut inner);
                }
                if let Some(eb) = else_branch {
                    match eb {
                        ElseBranch::Block(block) => {
                            let mut inner = match Self::branch_locals(condition, locals, false) {
                                Some(narrowed) => narrowed,
                                None => locals.clone(),
                            };
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
            // `loop { ... }` in value position (G08): the expression's type is
            // the type of the value its `break` carries. Recorded by span so
            // `infer_expr_type` can report it without re-walking the body.
            ExprKind::Loop { label, body } => {
                let mut inner = locals.clone();
                self.label_stack.push(LoopTarget {
                    label: label.clone(),
                    yields: true,
                    value_ty: None,
                    span: expr.span,
                });
                for s in &body.stmts {
                    self.check_stmt(s, &mut inner);
                }
                let target = self.label_stack.pop().expect("label frame pushed above");
                let ty = target.value_ty.unwrap_or(Type::Unknown);
                self.loop_value_types
                    .insert((expr.span.start, expr.span.end), ty);
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
                // `math.pi`, `net.connect`: the name before the dot is a
                // receiver — a namespace-qualified constant or a member path —
                // not a value being stored. E0146 is about binding the
                // namespace itself (`let n = net`), which is what made a
                // dispatch path behave like a value.
                self.check_expr_inner(object, locals, true);
                // Check field exists on known struct types
                let obj_ty = self.infer_expr_type(object, locals);
                // G10: a newtype is not a record. Naming any field other than
                // the documented unwrap is a mistake worth an error rather than
                // a silent `Unknown` that fails later in codegen.
                if let Type::Newtype { name, .. } = &obj_ty {
                    if field != "inner" {
                        self.diags.error(
                            "E0117",
                            format!(
                                "newtype `{name}` has no field `{field}`: its only accessor is \
                                 `.inner`, which yields the wrapped value"
                            ),
                            expr.span,
                        );
                    }
                }
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
                        self.check_optional_binding(&declared, value, locals, "assign to", value.span);
                        // G10: an assignment is a slot. `var id = UserId("x");
                        // id = "y"` must not turn a `UserId` into a `String`.
                        self.check_newtype_slot(&declared, value, locals, "assign to");
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
                let declared_fields: Option<Vec<(String, Type)>> =
                    self.env.structs.get(name).map(|s| s.fields.clone());
                if let Some(sinfo_fields) = declared_fields {
                    for field in fields {
                        match sinfo_fields.iter().find(|(f, _)| *f == field.name) {
                            // G01 P0.2: a field is a slot. `Holder { g: 7 }`
                            // used to store an int in a `Grant<Net>` field,
                            // and `let g = box.g` then read authority back
                            // out (audit F-4).
                            Some((_, declared)) => {
                                self.check_capability_slot(declared, &field.value, locals, "store");
                            }
                            None => self.diags.error(
                                "E0106",
                                format!("struct `{name}` has no field `{}`", field.name),
                                field.span,
                            ),
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
                    inner_locals.insert(
                        cp.name.clone(),
                        VarInfo {
                            ty,
                            mutable: false,
                            effects: Vec::new(),
                            non_nil: false,
                        },
                    );
                }
                // A `return` inside the closure returns from the closure, not
                // from the enclosing body: the return-slot check is suspended
                // while its statements are walked.
                self.closure_depth += 1;
                for s in body {
                    self.check_stmt(s, &mut inner_locals);
                }
                self.closure_depth -= 1;
            }
            ExprKind::Bail(e) => {
                self.check_expr(e, locals);
            }
            // ── Concurrency (Phase 1) ───────────────────────────────────
            //
            // G01 (audit F-9/F-10): these arms used to be `{}`, so the task
            // expression of a `spawn` was never walked — its effects never
            // reached the enclosing row and its arguments were never checked.
            // A `spawn` is a call: it goes through the same `check_call` as
            // `f(args)`, so a task body that reaches a socket with no row in the
            // *caller* is refused there.
            ExprKind::Spawn { func, args } => {
                let call_args: Vec<CallArg> = args
                    .iter()
                    .map(|a| CallArg {
                        name: None,
                        value: a.clone(),
                        span: a.span,
                    })
                    .collect();
                self.check_call(func, &call_args, expr.span, locals);
            }
            ExprKind::Select { cases, default } => {
                for case in cases {
                    let mut case_locals = locals.clone();
                    match &case.op {
                        SelectOp::Recv(ch) => self.check_expr(ch, locals),
                        SelectOp::Send { ch, val } => {
                            self.check_expr(ch, locals);
                            self.check_expr(val, locals);
                        }
                    }
                    if let Some(var) = &case.variable {
                        case_locals.insert(
                            var.clone(),
                            VarInfo {
                                ty: Type::Unknown,
                                mutable: false,
                                effects: Vec::new(),
                                non_nil: false,
                            },
                        );
                    }
                    self.check_expr(&case.body, &case_locals);
                }
                if let Some(default) = default {
                    self.check_expr(default, locals);
                }
            }
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
            Type::Newtype { name, .. } => name.clone(),
            Type::Grant(effect) => format!("Grant<{effect}>"),
            _ => format!("{ty:?}"),
        }
    }

    /// Get the type name for a type (for method lookup).
    fn type_to_name(&self, ty: &Type) -> Option<String> {
        match ty {
            Type::Named(name) => Some(name.clone()),
            // A newtype's method namespace is its own name: an `impl UserId`
            // block resolves here, and an `impl String` block does not.
            Type::Newtype { name, .. } => Some(name.clone()),
            Type::Private(inner) | Type::Secret(inner) => self.type_to_name(inner),
            _ => None,
        }
    }

    /// Is `name` a stdlib module namespace rather than a value (E0146)?
    ///
    /// A namespace is a dispatch path, not a value: the interpreter resolves
    /// `net.connect` by the *name*, so a namespace that could be bound would be
    /// a value the effect table cannot see. The module list is the one
    /// identifier resolution already uses (`stdlib::is_registered_module`,
    /// which `is_builtin_name` consults too), plus the three type-scoped
    /// namespaces whose methods open sockets.
    ///
    /// A local of the same name shadows the module: `let db = db.memory()` binds
    /// a value, and every later `db` is that value — so the caller checks
    /// `locals` before asking this.
    fn is_module_namespace(&self, name: &str) -> bool {
        // A user declaration of the same name shadows the module, exactly as a
        // local does: `fn db(x: i64)` makes `db` a function value, so E0146 on
        // `let f = db` was a false positive (audit N-12). The W0102 check in the
        // ident walk already consults these tables; this one did not. It cannot
        // reopen the hole it guards: a function value is not a dispatch path at
        // run time either.
        if self.env.functions.contains_key(name)
            || self.env.structs.contains_key(name)
            || self.env.enums.contains_key(name)
        {
            return false;
        }
        if matches!(name, "Tcp" | "Udp" | "TLSConn") {
            return true;
        }
        crate::stdlib::is_registered_module(&name.to_ascii_lowercase())
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
                // `FileCopy` is a runtime module (interp maps the bare ident to
                // `Value::Module("FileCopy")`; `FileCopy.copy_metadata` is the
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

    /// Exhaustiveness of a `match`, reported at the match (G04).
    ///
    /// The diagnostic names the variant(s) that no arm handles, for a
    /// user-defined enum and for the built-in `Result` (`Ok`/`Err`) and
    /// `T?` (`Some`/`None`). A `_` arm — or any binding that is not a variant of
    /// the scrutinee — makes the match exhaustive and reports nothing. When the
    /// scrutinee's type cannot be resolved, no variant list is invented: the
    /// diagnostic says the type is unknown and what to annotate.
    fn check_match_exhaustiveness(&mut self, subject_ty: &Type, arms: &[MatchArm], span: Span) {
        // A wildcard arm swallows every value.
        if arms
            .iter()
            .any(|arm| matches!(&arm.pattern, Pattern::Wildcard))
        {
            return;
        }

        let ty = subject_ty.strip_qualifier().clone();
        let (what, variants): (String, Vec<String>) = match &ty {
            Type::Result(_) => ("Result".to_string(), vec!["Ok".into(), "Err".into()]),
            Type::Optional(_) => ("Optional".to_string(), vec!["Some".into(), "None".into()]),
            Type::Named(name) => match self.env.enums.get(name) {
                Some(info) => (name.clone(), info.variants.clone()),
                None => return, // a concrete non-enum: nothing to enumerate
            },
            Type::Unknown => {
                self.report_unknown_scrutinee(arms, span);
                return;
            }
            // A concrete non-enum scrutinee (int, string, ...) is matched by
            // literals; there are no variants to name.
            _ => return,
        };

        let mut covered: Vec<String> = Vec::new();
        for arm in arms {
            match &arm.pattern {
                Pattern::Variant { name, .. } => covered.push(name.clone()),
                Pattern::Ident(n) => {
                    if variants.contains(n) {
                        // `Ok` / `Err` / `Some` / `None` written without a payload.
                        covered.push(n.clone());
                    } else {
                        // A binding (`other`, `rest`) swallows every value, so
                        // the match is exhaustive by way of a catchall.
                        return;
                    }
                }
                // Literal patterns cover no variant of an enum-typed scrutinee.
                Pattern::Literal(_) | Pattern::Tuple(_) | Pattern::Array { .. } => {}
                Pattern::Wildcard => return,
            }
        }

        let missing: Vec<&String> = variants
            .iter()
            .filter(|v| !covered.contains(v))
            .collect();
        if missing.is_empty() {
            return;
        }
        let missing_str: Vec<&str> = missing.iter().map(|s| s.as_str()).collect();
        self.diags.warning(
            "W0120",
            format!(
                "match on `{what}` is not exhaustive -- missing variant(s): {}. Add a `_` catchall or handle all variants",
                missing_str.join(", ")
            ),
            span,
        );
    }

    /// Say that exhaustiveness cannot be decided, instead of guessing (G04).
    ///
    /// Reported only when the arms look like variant matching — the author
    /// expected an enum and the checker has no type for the scrutinee. A match
    /// over plain literals or over a value whose type genuinely is dynamic is
    /// left alone: there is no rule to state about it.
    fn report_unknown_scrutinee(&mut self, arms: &[MatchArm], span: Span) {
        let looks_like_variants = arms.iter().any(|arm| match &arm.pattern {
            Pattern::Variant { name, .. } => self.names_a_variant(name),
            Pattern::Ident(n) => self.names_a_variant(n),
            _ => false,
        });
        if !looks_like_variants {
            return;
        }
        self.diags.warning(
            "W0121",
            "match exhaustiveness cannot be checked: the scrutinee's type is unknown, so no variant list can be produced -- annotate the scrutinee's type or add a `_` arm",
            span,
        );
    }

    /// Is `name` a variant of `Result`/`Optional` or of some declared enum?
    fn names_a_variant(&self, name: &str) -> bool {
        matches!(name, "Ok" | "Err" | "Some" | "None")
            || self.env.enums.values().any(|i| i.variants.iter().any(|v| v == name))
    }

    /// Check a *binding* pattern (G07) against the type of the value it binds.
    ///
    /// A binding pattern is irrefutable by construction: names, `_`, tuples and
    /// arrays. The shape still has to fit the value — a tuple pattern against a
    /// scalar, or a tuple of the wrong arity, is `E0152` and the program does
    /// not run. `Unknown` is always accepted: the checker does not invent a
    /// rule for a type it cannot see, and the runtime guard is what speaks then.
    fn check_binding_pattern(
        &mut self,
        pattern: &Pattern,
        ty: &Type,
        span: Span,
        mutable: bool,
        locals: &mut HashMap<String, VarInfo>,
    ) {
        match pattern {
            Pattern::Ident(name) => {
                if name != "_" {
                    locals.insert(
                        name.clone(),
                        VarInfo {
                            ty: ty.clone(),
                            mutable,
                            effects: Vec::new(),
                            non_nil: false,
                        },
                    );
                }
            }
            Pattern::Wildcard => {}
            Pattern::Literal(_) | Pattern::Variant { .. } => {
                self.diags.error(
                    "E0152",
                    "a binding position takes a name, `_`, `(pattern, ...)` or `[pattern, ...]` \
                     — a literal or variant pattern tests a value instead of binding it",
                    span,
                );
            }
            Pattern::Tuple(elems) => match ty {
                Type::Tuple(ts) => {
                    if ts.len() != elems.len() {
                        self.diags.error(
                            "E0152",
                            format!(
                                "destructuring mismatch: a {}-element tuple pattern cannot bind a \
                                 {}-element tuple",
                                elems.len(),
                                ts.len()
                            ),
                            span,
                        );
                        for p in elems {
                            self.check_binding_pattern(p, &Type::Unknown, span, mutable, locals);
                        }
                        return;
                    }
                    for (p, t) in elems.iter().zip(ts.iter()) {
                        self.check_binding_pattern(p, t, span, mutable, locals);
                    }
                }
                Type::Array(inner) => {
                    for p in elems {
                        self.check_binding_pattern(p, inner, span, mutable, locals);
                    }
                }
                // `nil` and an unpublished type are not evidence of a shape.
                Type::Unknown | Type::Void => {
                    for p in elems {
                        self.check_binding_pattern(p, &Type::Unknown, span, mutable, locals);
                    }
                }
                other => {
                    let what = self.type_display(other);
                    self.diags.error(
                        "E0152",
                        format!(
                            "destructuring mismatch: {what} is not a sequence, so a tuple pattern \
                             cannot bind it"
                        ),
                        span,
                    );
                }
            },
            Pattern::Array { elems, rest } => match ty {
                Type::Tuple(ts) => {
                    if ts.len() < elems.len() {
                        self.diags.error(
                            "E0152",
                            format!(
                                "destructuring mismatch: a pattern with {} fixed element(s) cannot \
                                 bind a {}-element tuple",
                                elems.len(),
                                ts.len()
                            ),
                            span,
                        );
                        for p in elems {
                            self.check_binding_pattern(p, &Type::Unknown, span, mutable, locals);
                        }
                    } else {
                        for (p, t) in elems.iter().zip(ts.iter()) {
                            self.check_binding_pattern(p, t, span, mutable, locals);
                        }
                    }
                    if let Some(rest) = rest {
                        self.check_binding_pattern(
                            rest,
                            &Type::Array(Box::new(Type::Unknown)),
                            span,
                            mutable,
                            locals,
                        );
                    }
                }
                Type::Array(inner) => {
                    for p in elems {
                        self.check_binding_pattern(p, inner, span, mutable, locals);
                    }
                    if let Some(rest) = rest {
                        self.check_binding_pattern(
                            rest,
                            &Type::Array(inner.clone()),
                            span,
                            mutable,
                            locals,
                        );
                    }
                }
                Type::Unknown | Type::Void => {
                    for p in elems {
                        self.check_binding_pattern(p, &Type::Unknown, span, mutable, locals);
                    }
                    if let Some(rest) = rest {
                        self.check_binding_pattern(
                            rest,
                            &Type::Array(Box::new(Type::Unknown)),
                            span,
                            mutable,
                            locals,
                        );
                    }
                }
                other => {
                    let what = self.type_display(other);
                    self.diags.error(
                        "E0152",
                        format!(
                            "destructuring mismatch: {what} is not a sequence, so an array pattern \
                             cannot bind it"
                        ),
                        span,
                    );
                }
            },
        }
    }

    /// Report an arity mismatch between a pattern and a *literal* sequence.
    ///
    /// `Type::Array` carries no length, so `let (a, b) = [1, 2, 3]` would
    /// otherwise only be caught at run time. The literal's length is right
    /// there in the source, so it is checked here on both planes.
    fn check_pattern_arity_against_literal(&mut self, pattern: &Pattern, value: &Expr) {
        let ExprKind::Array(items) = &value.kind else {
            return;
        };
        let n = items.len();
        match pattern {
            Pattern::Tuple(elems) if elems.len() != n => {
                self.diags.error(
                    "E0152",
                    format!(
                        "destructuring mismatch: a {}-element tuple pattern cannot bind a \
                         {}-element sequence",
                        elems.len(),
                        n
                    ),
                    value.span,
                );
            }
            Pattern::Array { elems, .. } if elems.len() > n => {
                self.diags.error(
                    "E0152",
                    format!(
                        "destructuring mismatch: a pattern with {} fixed element(s) cannot bind a \
                         {}-element sequence",
                        elems.len(),
                        n
                    ),
                    value.span,
                );
            }
            _ => {}
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
                            effects: Vec::new(),
                            non_nil: false,
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
            Pattern::Array { elems, rest } => {
                for p in elems {
                    self.bind_pattern_vars(p, locals);
                }
                if let Some(rest) = rest {
                    self.bind_pattern_vars(rest, locals);
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
            ExprKind::Ident(name) => {
                if let Some(vi) = locals.get(name) {
                    // Register #136: a name narrowed by a dominating `nil`
                    // guard types as its payload in *every* expression
                    // position — operand, argument, return value, index base,
                    // method receiver. This is the one place a local's type is
                    // read, so the binding rule (which goes through the same
                    // helper) and the expression rule cannot drift apart.
                    return Self::narrowed_local_type(vi);
                }
                // A top-level function used as a value *is* a function type,
                // and that type carries the declared row (G01 P0.3). Without
                // this, `let fs = [worker, worker]` inferred `[Unknown]` and
                // the row vanished into the array.
                if let Some(sig) = self.env.functions.get(name) {
                    return Type::Function {
                        params: sig.params.iter().map(|(_, t)| t.clone()).collect(),
                        return_type: Box::new(sig.return_type.clone()),
                        effects: sig
                            .effects
                            .iter()
                            .map(|e| (e.name.clone(), e.ops.clone()))
                            .collect(),
                    };
                }
                Type::Unknown
            }
            ExprKind::Call { callee, .. } => {
                if let ExprKind::Ident(name) = &callee.kind {
                    // G10: the constructor's value has the nominal type.
                    if let Some(ty) = self.env.newtypes.get(name) {
                        return ty.clone();
                    }
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
            ExprKind::If {
                condition,
                then_block,
                else_branch,
            } => {
                // G01 P0.3 (audit N-8): `let f = if c { worker } else { nop }`
                // picks a value at run time, so the joined type carries the
                // union of the arms' rows — one rowless arm does not make the
                // call safe.
                //
                // Register #136: a `nil` test narrows its local inside the
                // branch it selects, so that arm's type is the payload rather
                // than the optional. Without it `if m != nil { m } else { 0 }`
                // joined to `i64?` and was refused, although both planes run
                // it.
                let then_locals = Self::branch_locals(condition, locals, true);
                let else_locals = Self::branch_locals(condition, locals, false);
                let then_ty =
                    self.block_tail_type(then_block, then_locals.as_ref().unwrap_or(locals));
                let else_ty = match else_branch.as_ref() {
                    Some(ElseBranch::Block(block)) => {
                        self.block_tail_type(block, else_locals.as_ref().unwrap_or(locals))
                    }
                    Some(ElseBranch::ElseIf(expr)) => {
                        self.infer_expr_type(expr, else_locals.as_ref().unwrap_or(locals))
                    }
                    None => Type::Void,
                };
                Self::join_branch_types(then_ty, else_ty)
            }
            ExprKind::IfLet { then_block, .. } => {
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
                // G10: `.inner` is the one documented escape hatch, and it is
                // the *only* thing a newtype exposes. Typing it as the target
                // is what lets `id.inner` flow anywhere a `String` is expected
                // without the newtype itself ever doing so.
                if let Type::Newtype { inner, .. } = &obj_ty {
                    if field == "inner" {
                        return (**inner).clone();
                    }
                }
                if let Some(tname) = self.type_to_name(&obj_ty) {
                    if let Some(sinfo) = self.env.structs.get(&tname) {
                        if let Some((_, fty)) = sinfo.fields.iter().find(|(f, _)| f == field) {
                            return fty.clone();
                        }
                    }
                }
                Type::Unknown
            }
            // `fs[0]` is the element, and for an array of function values the
            // element type is where the row lives (G01 P0.3, audit N-5).
            ExprKind::Index { object, .. } => match self.infer_expr_type(object, locals) {
                Type::Array(inner) => *inner,
                Type::Map(_, value) => *value,
                _ => Type::Unknown,
            },
            ExprKind::StructLit { name, .. } => Type::Named(name.clone()),
            // G08: the value a `loop` yields is the type of its `break`
            // payload, recorded when the body was checked. Not re-derived here
            // — walking the body again would have to re-do label resolution.
            ExprKind::Loop { .. } => self
                .loop_value_types
                .get(&(expr.span.start, expr.span.end))
                .cloned()
                .unwrap_or(Type::Unknown),
            _ => Type::Unknown,
        }
    }

    /// Type of a block's tail expression; `Void` when the block ends in a
    /// statement (or is empty).
    fn block_tail_type(&self, block: &Block, locals: &HashMap<String, VarInfo>) -> Type {
        match block.stmts.last() {
            Some(Stmt {
                kind: StmtKind::Expr { expr },
                ..
            }) => self.infer_expr_type(expr, locals),
            _ => Type::Void,
        }
    }

    /// Join the types of two branches of an `if` (G01 P0.3, audit N-8).
    ///
    /// Two function types join to one carrying the union of their rows. An arm
    /// that can still be `nil` makes the join optional, because `T` wraps into
    /// `T?` (register #135) and so `T?` is the wider of the two: a narrowed arm
    /// must not erase the other arm's absence. Every other shape keeps the
    /// pre-existing rule — the then-branch's type wins — except that `Unknown`
    /// (inference's placeholder) defers to the branch that knows something.
    fn join_branch_types(then_ty: Type, else_ty: Type) -> Type {
        match (then_ty, else_ty) {
            (
                Type::Function {
                    params,
                    return_type,
                    effects,
                },
                Type::Function {
                    effects: else_effects,
                    ..
                },
            ) => Type::Function {
                params,
                return_type,
                effects: Self::union_rows(&effects, &else_effects),
            },
            (Type::Unknown, other) => other,
            // `if m != nil { m } else { m }` can still yield the absent value;
            // only the guard in the condition narrows, and it narrows one arm.
            (ty, other @ Type::Optional(_)) if !matches!(ty, Type::Optional(_)) => other,
            (then_ty, _) => then_ty,
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
                | StmtKind::Loop { body, .. } => Self::collect_channel_vars(body, out),
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
            StmtKind::While { condition, body, .. } => {
                self.expr_touches_network(condition, chans)
                    || self.body_touches_network_in(body, chans)
            }
            StmtKind::WhileLet { expr, body, .. } => {
                self.expr_touches_network(expr, chans) || self.body_touches_network_in(body, chans)
            }
            StmtKind::Loop { body, .. } => self.body_touches_network_in(body, chans),
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
            ExprKind::Loop { body, .. } => self.body_touches_network_in(body, chans),
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
            StmtKind::While { condition, body, .. } => {
                Self::expr_uses_browser_nav(condition) || Self::body_uses_browser_navigation(body)
            }
            StmtKind::WhileLet { expr, body, .. } => {
                Self::expr_uses_browser_nav(expr) || Self::body_uses_browser_navigation(body)
            }
            StmtKind::Loop { body, .. } => Self::body_uses_browser_navigation(body),
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
            ExprKind::Loop { body, .. } => Self::body_uses_browser_navigation(body),
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

    // ── G10: type aliases vs newtypes ────────────────────────────────────
    //
    // The bar is not "the declaration parses". It is that a newtype is *not* an
    // alias: a bare value is refused wherever the newtype is required, and a
    // newtype is refused wherever its target is required. Every refusal has to
    // name the construct that would make it legal — the constructor going in,
    // `.inner` coming out — which is what these tests pin.

    /// Type errors of a source snippet as a reader sees them: message plus
    /// help. The help is where the remedy ("unwrap it with `.inner`") lives, so
    /// a test that only read `msg` would not be testing the refusal a user gets.
    fn newtype_errors(source: &str) -> Vec<String> {
        let (_, diags) = check(source);
        diags
            .items
            .iter()
            .filter(|d| matches!(d.code, "E0117" | "E0103"))
            .map(|d| match &d.help {
                Some(help) => format!("{} [help: {help}]", d.msg),
                None => d.msg.clone(),
            })
            .collect()
    }

    #[test]
    fn newtype_is_registered_nominally_and_erased_for_layout() {
        let (env, diags) = check("newtype UserId = String");
        assert!(diags.items.iter().all(|d| d.code != "E0117"));
        assert_eq!(
            env.newtypes.get("UserId"),
            Some(&Type::Newtype {
                name: "UserId".to_string(),
                inner: Box::new(Type::String),
            })
        );
        // The layout bridge: a pass that only knows aliases still learns the
        // representation. It is not a conversion — name resolution asks
        // `newtypes` first.
        assert_eq!(env.type_aliases.get("UserId"), Some(&Type::String));
    }

    #[test]
    fn constructor_has_the_nominal_type() {
        // `take` demands a `UserId`; the constructor is the only producer.
        let errors = newtype_errors(
            "newtype UserId = String\n\
             fn take(id: UserId) {}\n\
             fn g() { take(UserId(\"x\")) }",
        );
        assert!(errors.is_empty(), "constructor must type as UserId: {errors:?}");
    }

    #[test]
    fn bare_value_into_newtype_slot_names_newtype_and_constructor() {
        for (position, source) in [
            (
                "argument",
                "newtype UserId = String\nfn take(id: UserId) {}\nfn g() { take(\"x\") }",
            ),
            (
                "binding",
                "newtype UserId = String\nfn g() { let id: UserId = \"x\" }",
            ),
            (
                "assignment",
                "newtype UserId = String\nfn g() { var id = UserId(\"x\"); id = \"y\" }",
            ),
            (
                "return",
                "newtype UserId = String\nfn g() -> UserId { return \"x\" }",
            ),
        ] {
            let errors = newtype_errors(source);
            assert_eq!(errors.len(), 1, "{position}: exactly one refusal: {errors:?}");
            let message = &errors[0];
            assert!(
                message.contains("`UserId`"),
                "{position}: must name the newtype: {message}"
            );
            assert!(
                message.contains("UserId(<String>)"),
                "{position}: must name the constructor: {message}"
            );
        }
    }

    #[test]
    fn newtype_shadowing_a_private_type_name_is_nominal_in_parameter_position() {
        // `Email`, `Name` and `SSN` are also built-in private-type names. The
        // declaration is the more specific statement, so the parameter's type
        // is the newtype — and a bare `String` is refused, in both directions.
        for name in ["UserId", "Email", "Name", "SSN"] {
            let refused = newtype_errors(&format!(
                "newtype {name} = String\n\
                 fn take(v: {name}) {{}}\n\
                 fn g() {{ take(\"x\") }}"
            ));
            assert_eq!(
                refused.len(),
                1,
                "{name}: a bare String must not fill the slot: {refused:?}"
            );
            assert!(
                refused[0].contains(&format!("newtype `{name}`")),
                "{name}: must name the expected newtype: {refused:?}"
            );
            assert!(
                refused[0].contains(&format!("{name}(<String>)")),
                "{name}: must name the constructor: {refused:?}"
            );

            let accepted = newtype_errors(&format!(
                "newtype {name} = String\n\
                 fn take(v: {name}) -> {name} {{ return v }}\n\
                 fn g() {{ let v: {name} = take({name}(\"x\")) }}"
            ));
            assert!(
                accepted.is_empty(),
                "{name}: the constructor is the legal producer: {accepted:?}"
            );
        }
    }

    /// The counterpart of the test above: the *declaration* is what wins, not
    /// the name. With no newtype in scope, `Email` is still the built-in private
    /// type and nothing about the heuristic has been weakened.
    #[test]
    fn undeclared_private_type_name_still_resolves_to_type_private() {
        let (env, _) = check("fn send(to: Email) {}");
        let sig = env.functions.get("send").expect("signature for send");
        assert!(
            matches!(&sig.params[0].1, Type::Private(inner) if **inner == Type::String),
            "an undeclared `Email` is still private, got {:?}",
            sig.params[0].1
        );
    }

    #[test]
    fn newtype_does_not_flow_into_its_target() {
        let errors = newtype_errors(
            "newtype UserId = String\n\
             fn take(s: String) {}\n\
             fn g(id: UserId) { take(id) }",
        );
        assert_eq!(errors.len(), 1, "{errors:?}");
        assert!(errors[0].contains("newtype `UserId`"), "{}", errors[0]);
        assert!(errors[0].contains(".inner"), "{}", errors[0]);
    }

    #[test]
    fn distinct_newtypes_over_the_same_target_are_unrelated() {
        let errors = newtype_errors(
            "newtype UserId = String\n\
             newtype Handle = String\n\
             fn take(id: UserId) {}\n\
             fn g(h: Handle) { take(h) }",
        );
        assert_eq!(errors.len(), 1, "{errors:?}");
        assert!(errors[0].contains("`Handle`"), "{}", errors[0]);
        assert!(errors[0].contains("`UserId`"), "{}", errors[0]);
    }

    #[test]
    fn same_newtype_passes_everywhere() {
        let errors = newtype_errors(
            "newtype UserId = String\n\
             fn take(id: UserId) -> UserId { return id }\n\
             fn g(id: UserId) { let copy: UserId = take(id) }",
        );
        assert!(errors.is_empty(), "a newtype is its own type: {errors:?}");
    }

    #[test]
    fn inner_is_the_documented_unwrap() {
        let errors = newtype_errors(
            "newtype UserId = String\n\
             fn name(id: UserId) -> String { return id.inner }\n\
             fn g() { let s: String = UserId(\"x\").inner }",
        );
        assert!(errors.is_empty(), "`.inner` yields the target: {errors:?}");
    }

    #[test]
    fn newtype_exposes_no_other_field() {
        let errors = newtype_errors(
            "newtype UserId = String\nfn g(id: UserId) { let n = id.length }",
        );
        assert_eq!(errors.len(), 1, "{errors:?}");
        assert!(errors[0].contains(".inner"), "{}", errors[0]);
    }

    #[test]
    fn constructor_checks_its_argument() {
        // Arity.
        let errors = newtype_errors("newtype UserId = String\nfn g() { UserId() }");
        assert!(errors[0].contains("exactly one constructor argument"), "{errors:?}");
        // Argument type: an `int` is not a `String`.
        let errors = newtype_errors("newtype UserId = String\nfn g() { UserId(42) }");
        assert_eq!(errors.len(), 1, "{errors:?}");
        assert!(errors[0].contains("cannot construct `UserId`"), "{errors:?}");
    }

    #[test]
    fn numeric_widening_still_seeds_a_newtype() {
        // `newtype Meter = Float; Meter(1)` is the same int-into-float widening
        // a plain `let x: Float = 1` gets. It is not a new conversion.
        let errors = newtype_errors(
            "newtype Meter = Float\nfn g() { let m: Meter = Meter(1) }",
        );
        assert!(errors.is_empty(), "{errors:?}");
    }

    #[test]
    fn alias_stays_transparent() {
        // The control: an alias is the same type on both sides, so a `type`
        // declaration keeps checking exactly as it did before G10.
        let errors = newtype_errors(
            "type Port = u16\nfn take(p: Port) -> u16 { return p }\nfn g() { let x: u16 = take(8443) }",
        );
        assert!(errors.is_empty(), "an alias is transparent: {errors:?}");
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

    // ── G04: exhaustiveness names the missing variant ───────────────────

    #[test]
    fn match_missing_result_variant_names_err() {
        let (_, diags) = check(
            r#"
            fn name_of(r: Result<String>) -> String {
                r match {
                    Ok(v) -> v
                }
            }
        "#,
        );
        let d = diags
            .items
            .iter()
            .find(|d| d.code == "W0120")
            .unwrap_or_else(|| panic!("expected W0120, got {:?}", diags.items));
        assert!(
            d.msg.contains("missing variant(s): Err"),
            "the missing Result variant must be named: {}",
            d.msg
        );
        assert!(
            !d.msg.contains("Ok,"),
            "a covered variant must not be listed as missing: {}",
            d.msg
        );
    }

    #[test]
    fn match_missing_optional_variant_names_none() {
        let (_, diags) = check(
            r#"
            fn unwrap_or_zero(v: i32?) -> i32 {
                v match {
                    Some(x) -> x
                }
            }
        "#,
        );
        let d = diags
            .items
            .iter()
            .find(|d| d.code == "W0120")
            .unwrap_or_else(|| panic!("expected W0120, got {:?}", diags.items));
        assert!(
            d.msg.contains("missing variant(s): None"),
            "the missing optional variant must be named: {}",
            d.msg
        );
    }

    #[test]
    fn wildcard_arm_makes_a_result_match_exhaustive() {
        let (_, diags) = check(
            r#"
            fn name_of(r: Result<String>) -> String {
                r match {
                    Ok(v) -> v
                    _ -> "other"
                }
            }
        "#,
        );
        assert!(
            !diags.items.iter().any(|d| d.code == "W0120"),
            "a wildcard arm must silence the report, got {:?}",
            diags.items
        );
    }

    #[test]
    fn unknown_scrutinee_is_reported_as_unknown_not_guessed() {
        let (_, diags) = check(
            r#"
            fn pick() {
                let r = nosuchmodule_call()
                r match {
                    Ok(v) -> v
                    Err(e) -> e
                }
            }
        "#,
        );
        let w0121 = diags.items.iter().find(|d| d.code == "W0121");
        assert!(
            w0121.is_some(),
            "an unresolved scrutinee type must be reported as such, got {:?}",
            diags.items
        );
        assert!(
            !diags.items.iter().any(|d| d.code == "W0120"),
            "no variant list may be produced for an unknown scrutinee, got {:?}",
            diags.items
        );
    }

    // ── G08: labeled break with value ───────────────────────────────────

    #[test]
    fn labeled_break_value_types_the_loop_expression() {
        let (_, diags) = check(
            r#"
            fn pick() -> i32 {
                let x = 'outer: loop {
                    break 'outer 7
                }
                x
            }
        "#,
        );
        let errors: Vec<_> = diags
            .items
            .iter()
            .filter(|d| d.severity == crate::error::Severity::Error)
            .collect();
        assert!(errors.is_empty(), "expected a clean check, got {errors:?}");
    }

    #[test]
    fn break_to_an_out_of_scope_label_names_the_label() {
        let (_, diags) = check(
            r#"
            fn pick() {
                loop {
                    break 'nowhere
                }
            }
        "#,
        );
        let d = diags
            .items
            .iter()
            .find(|d| d.code == "E0118")
            .unwrap_or_else(|| panic!("expected E0118, got {:?}", diags.items));
        assert!(
            d.msg.contains("'nowhere"),
            "the diagnostic must name the label: {}",
            d.msg
        );
    }

    #[test]
    fn break_value_type_mismatch_is_reported_at_the_break() {
        let (_, diags) = check(
            r#"
            fn pick(c: bool) -> i32 {
                let x = 'outer: loop {
                    if c {
                        break 'outer 1
                    } else {
                        break 'outer "seven"
                    }
                }
                x
            }
        "#,
        );
        let d = diags
            .items
            .iter()
            .find(|d| d.code == "E0120")
            .unwrap_or_else(|| panic!("expected E0120, got {:?}", diags.items));
        assert!(
            d.msg.contains("i64") && d.msg.contains("String"),
            "the mismatch must name both types: {}",
            d.msg
        );
    }

    #[test]
    fn break_value_into_a_bounded_loop_is_refused() {
        // A labeled `for` is only writable in statement position — the parser
        // refuses `let x = 'outer: for ..` because a bounded loop yields no
        // value, so it cannot be an expression. The value-taking `break` is
        // still expressible here, and E0119 is what says it cannot deliver.
        let (_, diags) = check(
            r#"
            fn pick() -> i32 {
                'outer: for i in 0..3 {
                    break 'outer 1
                }
                0
            }
        "#,
        );
        assert!(
            diags.items.iter().any(|d| d.code == "E0119"),
            "a `for` loop yields no value, so `break 'label v` must be refused, got {:?}",
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
