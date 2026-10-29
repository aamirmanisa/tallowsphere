pub use crate::lexer::Span;

// ── Program (root node) ─────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct Program {
    pub items: Vec<Item>,
    pub span: Span,
}

// ── Top-level Items ──────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub enum Item {
    Fn(FnDecl),
    Struct(StructDecl),
    Enum(EnumDecl),
    Impl(ImplBlock),
    Trait(TraitDecl),
    Const(ConstDecl),
    TypeAlias(TypeAlias),
    Import(ImportDecl),
}

impl Item {
    pub fn span(&self) -> Span {
        match self {
            Item::Fn(f) => f.span,
            Item::Struct(s) => s.span,
            Item::Enum(e) => e.span,
            Item::Impl(i) => i.span,
            Item::Trait(t) => t.span,
            Item::Const(c) => c.span,
            Item::TypeAlias(t) => t.span,
            Item::Import(i) => i.span,
        }
    }

    /// The visibility marker written in front of the item (G09).
    pub fn visibility(&self) -> Visibility {
        match self {
            Item::Fn(f) => f.visibility,
            Item::Struct(s) => s.visibility,
            Item::Enum(e) => e.visibility,
            Item::Impl(i) => i.visibility,
            Item::Trait(t) => t.visibility,
            Item::Const(c) => c.visibility,
            Item::TypeAlias(t) => t.visibility,
            Item::Import(i) => i.visibility,
        }
    }

    /// The name this item contributes to a namespace, when it contributes one.
    ///
    /// An `impl` block declares no new name (its methods belong to the target
    /// type) and an `import` contributes whatever it imports, so both answer
    /// `None`. This is the name import resolution compares against a use site
    /// when it decides whether an item crosses a file boundary (G09).
    pub fn name(&self) -> Option<&str> {
        match self {
            Item::Fn(f) => Some(&f.name),
            Item::Struct(s) => Some(&s.name),
            Item::Enum(e) => Some(&e.name),
            Item::Impl(_) => None,
            Item::Trait(t) => Some(&t.name),
            Item::Const(c) => Some(&c.name),
            Item::TypeAlias(t) => Some(&t.name),
            Item::Import(_) => None,
        }
    }
}

// ── Visibility (G09) ─────────────────────────────────────────────────────────

/// The visibility marker in front of an item declaration (G09).
///
/// `pub` and `pub(crate)` are contextual: neither is a keyword, and the marker
/// is only read when it sits at item position in front of `fn`, `struct`,
/// `enum`, `impl`, `trait`, `const`, `type` (or `import`, which refuses it with
/// E0154). `pub` therefore remains an ordinary identifier everywhere else.
///
/// See `docs/spec/MODULE-VISIBILITY.md`. Enforcement lives in import
/// resolution (`crate::visibility`), so an item that is not visible to a file
/// never reaches that file's namespace.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Visibility {
    /// No marker: visible only to items declared in the same file.
    #[default]
    Private,
    /// `pub`: visible to every file that imports this module.
    Pub,
    /// `pub(crate)`: visible to every file in the same package — the directory
    /// tree rooted at the entry-point file's directory.
    PubCrate,
}

// ── Function Declaration ─────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct FnDecl {
    /// `pub` / `pub(crate)` in front of the declaration (G09). No marker is
    /// [`Visibility::Private`]: visible only inside the declaring file.
    pub visibility: Visibility,
    pub annotations: Vec<Annotation>,
    pub is_async: bool,
    /// `native fn name(...) -> T` — a declaration with no body, implemented by a
    /// symbol of the same name at link time (register #129).
    pub is_native: bool,
    /// True when this item was parsed out of an imported module rather than the
    /// file the compiler was invoked on (`resolve_imports`). The item is merged
    /// into the program before type checking, and this flag is what keeps the
    /// trust root (`main`, see `typeck::TypeChecker::check_trust_root`) anchored
    /// to an entry-point file rather than to a spelling.
    pub is_imported: bool,
    /// The file an imported item came from, when `is_imported` is set.
    ///
    /// Spans are byte offsets into *their own* file, so a diagnostic about an
    /// imported item rendered against the entry file's text points at the wrong
    /// line (audit N-9: E0147 rendered an imported `main` against the caller's
    /// source). Carrying the path lets the diagnostic read the right file.
    pub imported_from: Option<std::path::PathBuf>,
    pub name: String,
    pub type_params: Vec<String>,
    pub params: Vec<Param>,
    pub return_type: Option<TypeExpr>,
    /// Effect row declared after the return type: `with Net(connect), Net(read)`.
    ///
    /// An empty vector is the empty row (every function written before 2.0).
    /// `with Net` (no parentheses) declares the whole effect and is treated as
    /// covering every operation of it.
    pub effects: Vec<EffectReq>,
    pub body: Block,
    pub span: Span,
}

/// One entry of a function's effect row: `Net(connect)` or bare `Net`.
///
/// G01 (blueprint §2.1/§4): the socket-opening primitives in [`crate::typeck`]
/// require the enclosing signature to declare them; `E0141` is reported at the
/// call site when it does not.
#[derive(Debug, Clone)]
pub struct EffectReq {
    pub name: String,
    /// Empty for the bare `Net` form — "all operations of this effect".
    pub ops: Vec<String>,
    pub span: Span,
}

impl EffectReq {
    /// `Net(connect)` / `Net` — the spelling an effect row is written in.
    ///
    /// Shared by the diagnostic layer, the formatter and the type-display
    /// path so a row can never be rendered three slightly different ways.
    pub fn display(&self) -> String {
        if self.ops.is_empty() {
            self.name.clone()
        } else {
            format!("{}({})", self.name, self.ops.join(", "))
        }
    }
}

/// Render a whole row: `Net(connect), Net(read)`; empty string for an empty
/// row.
pub fn format_effect_row(effects: &[EffectReq]) -> String {
    effects
        .iter()
        .map(|e| e.display())
        .collect::<Vec<_>>()
        .join(", ")
}

#[derive(Debug, Clone)]
pub struct Param {
    pub name: String,
    pub ty: TypeExpr,
    /// Declared default value: `fn f(x: int = 3)`.
    ///
    /// R2-3 (audit a01:77): defaults used to be parsed then **dropped** ("the
    /// AST Param does not carry it"). The AST now carries the expression, and
    /// the interpreter applies it when a call omits the argument on paths
    /// that bypass static arity checking (dynamic/local function values,
    /// agent children, object methods). Direct calls still require every
    /// argument (E0103), and the compiled backends keep their hard arity
    /// error — see the omitted-arg binding sites in `src/interp.rs`.
    pub default: Option<Expr>,
    pub span: Span,
}

// ── Struct ───────────────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct StructDecl {
    /// G09 visibility marker; see [`Visibility`].
    pub visibility: Visibility,
    pub name: String,
    pub type_params: Vec<String>,
    pub fields: Vec<FieldDecl>,
    pub span: Span,
}

#[derive(Debug, Clone)]
pub struct FieldDecl {
    pub name: String,
    pub ty: TypeExpr,
    pub default: Option<Expr>,
    pub span: Span,
}

// ── Enum ─────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct EnumDecl {
    /// G09 visibility marker; see [`Visibility`].
    pub visibility: Visibility,
    pub name: String,
    pub type_params: Vec<String>,
    pub variants: Vec<EnumVariant>,
    pub span: Span,
}

#[derive(Debug, Clone)]
pub struct EnumVariant {
    pub name: String,
    pub fields: Vec<FieldDecl>,
    pub span: Span,
}

// ── Trait Declaration ────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct TraitDecl {
    /// G09 visibility marker; see [`Visibility`].
    pub visibility: Visibility,
    pub name: String,
    pub type_params: Vec<String>,
    pub methods: Vec<TraitMethod>,
    pub span: Span,
}

#[derive(Debug, Clone)]
pub struct TraitMethod {
    pub name: String,
    pub params: Vec<Param>,
    pub return_type: Option<TypeExpr>,
    pub has_default: bool,
    pub body: Option<Block>,
    pub span: Span,
}

// ── Impl Block ───────────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct ImplBlock {
    /// G09 visibility marker; see [`Visibility`]. An impl contributes no name
    /// of its own, so the marker is carried but never consulted by resolution.
    pub visibility: Visibility,
    pub trait_name: Option<String>,
    pub type_params: Vec<String>,
    pub target: String,
    pub methods: Vec<FnDecl>,
    pub span: Span,
}

// ── Const ────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct ConstDecl {
    /// G09 visibility marker; see [`Visibility`].
    pub visibility: Visibility,
    pub name: String,
    pub ty: Option<TypeExpr>,
    pub value: Expr,
    pub span: Span,
}

// ── Type Alias ───────────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct TypeAlias {
    /// G09 visibility marker; see [`Visibility`].
    pub visibility: Visibility,
    pub name: String,
    pub annotations: Vec<Annotation>,
    pub qualifier: Option<TypeQualifier>,
    pub ty: TypeExpr,
    /// `true` for `newtype UserId = String`, `false` for `type Port = u16`.
    ///
    /// The two declarations share a node because they share a *shape* (a name
    /// and a target type), not a meaning: an alias is transparent at every use
    /// site, a newtype is a distinct type that is only related to its target by
    /// the constructor `UserId(..)` and the `.inner` unwrap (G10). Keeping one
    /// node keeps every pass that already walks type declarations — imports,
    /// privacy, codegen's layout scan — operating on both without a second
    /// exhaustive `Item` arm.
    pub newtype: bool,
    pub span: Span,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TypeQualifier {
    Private,
    Secret,
}

// ── Agent Autonomy Levels ───────────────────────────────────────────────────

/// Agent autonomy levels L1-L5. Each level maps to a preset of allowed/denied
/// capabilities. Higher levels can do everything lower levels can, plus more.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum AgentLevel {
    L1, // Tool: single external operation, immediate return
    L2, // Script: fixed sequence, no conditional branching on external results
    L3, // Reactive: conditional branching, predefined actions, no spawning
    L4, // Autonomous: planning, spawning, adaptation with bounded resources
    L5, // Self-directed: goal generation, requires constitution
}

impl AgentLevel {
    pub fn from_str(s: &str) -> Option<Self> {
        match s {
            "L1" => Some(AgentLevel::L1),
            "L2" => Some(AgentLevel::L2),
            "L3" => Some(AgentLevel::L3),
            "L4" => Some(AgentLevel::L4),
            "L5" => Some(AgentLevel::L5),
            _ => None,
        }
    }

    pub fn name(&self) -> &'static str {
        match self {
            AgentLevel::L1 => "Tool",
            AgentLevel::L2 => "Script",
            AgentLevel::L3 => "Reactive",
            AgentLevel::L4 => "Autonomous",
            AgentLevel::L5 => "Self-directed",
        }
    }
}

// ── Import ───────────────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct ImportDecl {
    /// A marker written in front of `import`, which is always refused (E0154):
    /// re-exports are out of scope for 2.0. Carried so import resolution can
    /// name the refusal instead of the marker being dropped silently.
    pub visibility: Visibility,
    pub path: Vec<String>,
    /// Destructured imports: `import foo.bar.{Baz, Qux}` → items = ["Baz", "Qux"]
    pub items: Vec<String>,
    pub span: Span,
}

// ── Annotations (@legal, @agent_task) ────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct Annotation {
    pub name: String,
    pub args: Vec<AnnotationArg>,
    pub span: Span,
}

#[derive(Debug, Clone)]
pub struct AnnotationArg {
    pub name: String,
    pub value: Expr,
    pub span: Span,
}

// ── Block ────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct Block {
    pub stmts: Vec<Stmt>,
    pub span: Span,
}

// ── Statements ───────────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct Stmt {
    pub kind: StmtKind,
    pub span: Span,
}

#[derive(Debug, Clone)]
pub enum StmtKind {
    Let {
        name: String,
        ty: Option<TypeExpr>,
        value: Expr,
    },
    Var {
        name: String,
        ty: Option<TypeExpr>,
        value: Expr,
    },
    LetDestructure {
        /// The pattern that shapes the binding (G07). A bare name is
        /// `Pattern::Ident`; the `(`/`[` forms bind several names at once.
        pattern: Pattern,
        value: Expr,
    },
    Expr {
        expr: Expr,
    },
    Return(Option<Expr>),
    For {
        /// Loop label (`'outer: for ...`), if any (G08).
        label: Option<String>,
        /// The binding pattern: a name, or a `(`/`[` pattern whose scrutinee is
        /// the iteration element (G07).
        pattern: Pattern,
        iter: Expr,
        body: Block,
    },
    While {
        /// Loop label (`'outer: while ...`), if any (G08).
        label: Option<String>,
        condition: Expr,
        body: Block,
    },
    WhileLet {
        /// Loop label (`'outer: while let ...`), if any (G08).
        label: Option<String>,
        pattern: Box<Pattern>,
        expr: Expr,
        body: Block,
    },
    Bail(Expr),
    /// `break` / `break 'label` / `break 'label value` (G08).
    ///
    /// `label: None` is today's unlabeled `break`. A `value` is only accepted
    /// when it names a construct that yields one (`loop`, or a labeled block);
    /// typeck reports the type of the target against the type of `value`.
    Break {
        label: Option<String>,
        value: Option<Expr>,
    },
    /// `continue` / `continue 'label` (G08).
    Continue {
        label: Option<String>,
    },
    Loop {
        /// Loop label (`'outer: loop ...`), if any (G08).
        label: Option<String>,
        body: Block,
    },
    Defer {
        body: Block,
    },
}

// ── Expressions ──────────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct Expr {
    pub kind: ExprKind,
    pub span: Span,
}

impl Expr {
    pub fn new(kind: ExprKind, span: Span) -> Self {
        Self { kind, span }
    }
}

#[derive(Debug, Clone)]
pub enum ExprKind {
    // Literals
    IntLit(i128),
    FloatLit(f64),
    StringLit(String),
    BoolLit(bool),
    Nil,

    // Names
    Ident(String),
    DotIdent(String), // .variant_name (enum shorthand in annotations)

    // Operators
    Binary {
        op: BinOp,
        left: Box<Expr>,
        right: Box<Expr>,
    },
    Unary {
        op: UnOp,
        operand: Box<Expr>,
    },

    // Calls
    Call {
        callee: Box<Expr>,
        args: Vec<CallArg>,
    },
    MethodCall {
        object: Box<Expr>,
        method: String,
        args: Vec<CallArg>,
    },
    FieldAccess {
        object: Box<Expr>,
        field: String,
    },
    Index {
        object: Box<Expr>,
        index: Box<Expr>,
    },

    // Control flow
    If {
        condition: Box<Expr>,
        then_block: Block,
        else_branch: Option<ElseBranch>,
    },
    IfLet {
        pattern: Box<Pattern>,
        expr: Box<Expr>,
        then_block: Block,
        else_branch: Option<ElseBranch>,
    },
    Match {
        subject: Box<Expr>,
        arms: Vec<MatchArm>,
    },
    Block(Block),

    /// `loop { ... }` / `'name: loop { ... }` in value position (G08).
    ///
    /// Statement-position `loop` stays [`StmtKind::Loop`]; this is the form
    /// whose `break 'name v` has somewhere to deliver `v`.
    Loop {
        label: Option<String>,
        body: Block,
    },

    // Collections
    Array(Vec<Expr>),
    MapLit(Vec<(Expr, Expr)>),

    // Postfix
    Try(Box<Expr>),   // expr?
    Await(Box<Expr>), // expr.await

    // Assignment
    Assign {
        target: Box<Expr>,
        value: Box<Expr>,
    },

    // Struct literal
    StructLit {
        name: String,
        fields: Vec<StructLitField>,
        spread: Option<Box<Expr>>,
    },

    // Type cast: expr as Type
    Cast {
        expr: Box<Expr>,
        ty: TypeExpr,
    },

    // String interpolation: "hello {name}, you have {items.len()} items"
    Interpolation(Vec<StringPart>),

    // Closure: { x: i32 -> x * 2 } or { item -> process(item) }
    Closure {
        params: Vec<ClosureParam>,
        body: Vec<Stmt>,
    },

    // Bail: bail "error message"
    Bail(Box<Expr>),

    // ── Concurrency (Phase 1) ──

    /// Spawn a goroutine: `spawn func(args)`
    /// `func` is the callable expression, `args` are the evaluated arguments.
    Spawn {
        func: Box<Expr>,
        args: Vec<Expr>,
    },

    /// Select across channel operations: `select { recv(ch) -> x { ... } send(ch, v) -> s { ... } default { ... } }`
    Select {
        cases: Vec<SelectCase>,
        default: Option<Box<Expr>>,
    },
}

/// A segment of an interpolated string.
#[derive(Debug, Clone)]
pub enum StringPart {
    /// Literal text between interpolations
    Lit(String),
    /// An embedded expression: `{expr}`
    Expr(Box<Expr>),
}

/// A case arm in a `select` expression.
///
/// Each case specifies a channel operation (recv or send) and a body
/// to execute when that operation is ready. An optional variable name
/// binds the received or sent value.
#[derive(Debug, Clone)]
pub struct SelectCase {
    /// The channel operation for this case.
    pub op: SelectOp,
    /// Optional variable name to bind the received/sent value.
    pub variable: Option<String>,
    /// The body expression to execute when this case is selected.
    pub body: Box<Expr>,
}

/// Channel operation within a `select` case.
#[derive(Debug, Clone)]
pub enum SelectOp {
    /// Receive from a channel: `recv(ch)`
    Recv(Box<Expr>),
    /// Send to a channel: `send(ch, value)`
    Send {
        ch: Box<Expr>,
        val: Box<Expr>,
    },
}

/// A closure parameter: `x` or `x: i32`
#[derive(Debug, Clone)]
pub struct ClosureParam {
    pub name: String,
    pub ty: Option<TypeExpr>,
}

#[derive(Debug, Clone)]
pub enum ElseBranch {
    Block(Block),
    ElseIf(Box<Expr>),
}

#[derive(Debug, Clone)]
pub struct CallArg {
    pub name: Option<String>,
    pub value: Expr,
    pub span: Span,
}

#[derive(Debug, Clone)]
pub struct StructLitField {
    pub name: String,
    pub value: Expr,
    pub span: Span,
}

// ── Match Arms & Patterns ────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct MatchArm {
    pub pattern: Pattern,
    pub body: Expr,
    pub span: Span,
}

#[derive(Debug, Clone)]
pub enum Pattern {
    Literal(Expr),
    Ident(String),
    Wildcard,
    Variant {
        name: String,
        fields: Vec<PatternField>,
    },
    /// `(a, b, c)` — positional destructuring of a sequence.
    ///
    /// The arity is exact: a sequence of any other length does not match, and
    /// both planes refuse it (G07). A tuple has no value of its own in this
    /// language (there is no tuple expression), so the pattern destructures a
    /// sequence value by position — the shape `let (a, b) = pair` has always
    /// meant.
    Tuple(Vec<Pattern>),
    /// `[a, b, ..rest]` — the first `elems.len()` positions, plus the remainder
    /// bound as one sequence (G07).
    ///
    /// `rest: None` requires at least `elems.len()` elements; `rest:
    /// Some(pattern)` binds the tail — empty when the value is exactly
    /// `elems.len()` long — as a sequence of the same element type.
    Array {
        elems: Vec<Pattern>,
        rest: Option<Box<Pattern>>,
    },
}

impl Pattern {
    /// Every name this pattern binds, in source order.
    ///
    /// Wildcards bind nothing and `_` is not a name, so neither appears. The
    /// policy passes use this to register the bindings a destructuring
    /// introduces without knowing the pattern's shape.
    pub fn bound_names(&self) -> Vec<String> {
        let mut out = Vec::new();
        self.collect_bound_names(&mut out);
        out
    }

    fn collect_bound_names(&self, out: &mut Vec<String>) {
        match self {
            Pattern::Ident(name) => {
                if name != "_" {
                    out.push(name.clone());
                }
            }
            Pattern::Wildcard | Pattern::Literal(_) => {}
            Pattern::Variant { fields, .. } => {
                for field in fields {
                    field.pattern.collect_bound_names(out);
                }
            }
            Pattern::Tuple(pats) => {
                for p in pats {
                    p.collect_bound_names(out);
                }
            }
            Pattern::Array { elems, rest } => {
                for p in elems {
                    p.collect_bound_names(out);
                }
                if let Some(rest) = rest {
                    rest.collect_bound_names(out);
                }
            }
        }
    }
}

#[derive(Debug, Clone)]
pub struct PatternField {
    pub name: Option<String>,
    pub pattern: Pattern,
}

// ── Operators ────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BinOp {
    Add,
    Sub,
    Mul,
    Div,
    Mod,
    Eq,
    Neq,
    Lt,
    Gt,
    Lte,
    Gte,
    And,
    Or,
    BitAnd,
    BitOr,
    BitXor,
    Shl,
    Shr,
    Pow,
    Range,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UnOp {
    Neg,
    Not,
    BitNot,
    Deref, // *expr — unbox a Box<T>
}

// ── Type Expressions ─────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct TypeExpr {
    pub kind: TypeExprKind,
    pub span: Span,
}

impl TypeExpr {
    pub fn new(kind: TypeExprKind, span: Span) -> Self {
        Self { kind, span }
    }
}

#[derive(Debug, Clone)]
pub enum TypeExprKind {
    /// Simple named type: `i32`, `String`, `Email`
    Named(String),
    /// Generic: `Result<T>`, `Map<K, V>`
    Generic { name: String, args: Vec<TypeExpr> },
    /// Slice: `[]T`
    Slice(Box<TypeExpr>),
    /// Optional: `T?`
    Optional(Box<TypeExpr>),
    /// Tuple: `(T, U)`
    Tuple(Vec<TypeExpr>),
    /// Function type: `fn(i32) -> i32`, optionally carrying an effect row:
    /// `fn(Grant<Net>, String) with Net(connect)`.
    ///
    /// G01 P0.3 (audit N-3…N-8): the row is part of the *type*, not of the
    /// syntax that calls the value. A function value can reach a caller as a
    /// parameter, a return value, an array element, a struct field or an
    /// `if`-selected binding; in every one of those positions the only place a
    /// row can travel is the type. Enforcing the row at a call through a value
    /// therefore starts here.
    ///
    /// Grammar note: a `with` row immediately following a function type binds
    /// to that type (the innermost one), because the row is written where the
    /// type ends. A declaration's own row is written after its parameter list;
    /// when that list's last parameter, or the return type, is a function type
    /// with a row, the row read there belongs to the function type.
    Function {
        params: Vec<TypeExpr>,
        return_type: Box<TypeExpr>,
        effects: Vec<EffectReq>,
    },
    /// Heap-indirected type: `Box<T>` — enables recursive data types
    Boxed(Box<TypeExpr>),
    /// `impl TraitName` — static dispatch trait constraint
    ImplTrait(String),
    /// `dyn TraitName` — dynamic dispatch trait object
    DynTrait(String),
}
