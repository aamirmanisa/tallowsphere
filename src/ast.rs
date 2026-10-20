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
}

// ── Function Declaration ─────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct FnDecl {
    pub annotations: Vec<Annotation>,
    pub is_async: bool,
    /// `native fn name(...) -> T` — a declaration with no body, implemented by a
    /// symbol of the same name at link time (register #129).
    pub is_native: bool,
    pub name: String,
    pub type_params: Vec<String>,
    pub params: Vec<Param>,
    pub return_type: Option<TypeExpr>,
    pub body: Block,
    pub span: Span,
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
    pub trait_name: Option<String>,
    pub type_params: Vec<String>,
    pub target: String,
    pub methods: Vec<FnDecl>,
    pub span: Span,
}

// ── Const ────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct ConstDecl {
    pub name: String,
    pub ty: Option<TypeExpr>,
    pub value: Expr,
    pub span: Span,
}

// ── Type Alias ───────────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct TypeAlias {
    pub name: String,
    pub annotations: Vec<Annotation>,
    pub qualifier: Option<TypeQualifier>,
    pub ty: TypeExpr,
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
        names: Vec<String>,
        value: Expr,
    },
    Expr {
        expr: Expr,
    },
    Return(Option<Expr>),
    For {
        binding: String,
        iter: Expr,
        body: Block,
    },
    While {
        condition: Expr,
        body: Block,
    },
    WhileLet {
        pattern: Box<Pattern>,
        expr: Expr,
        body: Block,
    },
    Bail(Expr),
    Break,
    Continue,
    Loop {
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
    Tuple(Vec<Pattern>),
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
    /// Function type: `fn(i32) -> i32`
    Function {
        params: Vec<TypeExpr>,
        return_type: Box<TypeExpr>,
    },
    /// Heap-indirected type: `Box<T>` — enables recursive data types
    Boxed(Box<TypeExpr>),
    /// `impl TraitName` — static dispatch trait constraint
    ImplTrait(String),
    /// `dyn TraitName` — dynamic dispatch trait object
    DynTrait(String),
}
