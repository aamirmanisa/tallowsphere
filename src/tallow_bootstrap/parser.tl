// ============================================================================
// Tallow Self-Hosting Parser -- Written in Tallow
// ============================================================================
// Second step toward self-hosting: a recursive descent parser that consumes
// tokens from the lexer (lexer.tl) and builds an AST.
//
// Restrictions for the Tallow interpreter:
//   - No var/return/let inside string literals (parser bug)
//   - No escaped quotes in strings
//   - Use implicit returns (last expression, no return keyword)
//   - Use tokens = tokens.push(x) pattern for immutable arrays
// ============================================================================

// ── AST Node Types ─────────────────────────────────────────────────────────

struct Param {
    name: String,
    ty:   String
}

struct Field {
    name: String,
    ty:   String
}

struct Variant {
    name:   String,
    fields: []Field
}

struct MatchArm {
    pattern: Expr,
    body:    Expr
}

enum Expr {
    IntLit,
    FloatLit,
    StringLit,
    BoolLit,
    NilLit,
    Ident,
    BinOp,
    UnaryOp,
    Call,
    MethodCall,
    FieldAccess,
    ArrayLit,
    Index,
    IfExpr,
    MatchExpr,
    Block,
    Assign
}

// Since the Tallow interpreter does not have Box<T> or recursive enums,
// we represent nodes as structs with a tag (kind) and optional children
// stored in flat arrays.  This is the classic "arena-free AST" trick.

struct AstNode {
    kind:       Expr,
    // Payload -- only the relevant fields are used per kind
    int_val:    i64,
    float_val:  f64,
    str_val:    String,
    bool_val:   bool,
    name:       String,
    op:         String,
    // Child indices into the node array (for tree structure)
    left:       i32,
    right:      i32,
    children:   []i32,
    // For IfExpr
    then_body:  []i32,
    else_body:  []i32,
    // For MatchExpr -- parallel arrays of pattern/body indices
    arm_pats:   []i32,
    arm_bodies: []i32,
    // For Call / MethodCall
    args:       []i32,
    // line/col for error messages
    line:       i32,
    col:        i32
}

enum Stmt {
    LetStmt,
    VarStmt,
    AssignStmt,
    ExprStmt,
    FnDef,
    StructDef,
    EnumDef,
    ForStmt,
    WhileStmt,
    PrintStmt,
    BreakStmt,
    ContinueStmt
}

struct AstStmt {
    kind:       Stmt,
    name:       String,
    // Expression index (for let/var/assign/expr/print value)
    expr_idx:   i32,
    // For print -- multiple arg indices
    arg_idxs:   []i32,
    // For fn def
    params:     []Param,
    body:       []i32,
    // For struct def
    fields:     []Field,
    // For enum def
    variants:   []Variant,
    // For for loop
    binding:    String,
    iter_idx:   i32,
    // line/col
    line:       i32,
    col:        i32
}

// ── Program (root) ─────────────────────────────────────────────────────────

struct Program {
    nodes: []AstNode,
    stmts: []AstStmt,
    top:   []i32
}

// ── Parser State ───────────────────────────────────────────────────────────

struct Parser {
    tokens:  []Token,
    pos:     i32,
    nodes:   []AstNode,
    stmts:   []AstStmt
}

// ── Constructors ───────────────────────────────────────────────────────────

fn new_parser(tokens: []Token) -> Parser {
    Parser {
        tokens: tokens,
        pos:    0,
        nodes:  [],
        stmts:  []
    }
}

fn empty_node() -> AstNode {
    AstNode {
        kind:       Expr.NilLit,
        int_val:    0,
        float_val:  0.0,
        str_val:    "",
        bool_val:   false,
        name:       "",
        op:         "",
        left:       -1,
        right:      -1,
        children:   [],
        then_body:  [],
        else_body:  [],
        arm_pats:   [],
        arm_bodies: [],
        args:       [],
        line:       0,
        col:        0
    }
}

// ── Parser helpers ─────────────────────────────────────────────────────────

fn p_peek(p: Parser) -> Token {
    if p.pos >= p.tokens.len {
        make_token(TokenKind.Eof, "", 0, 0)
    } else {
        p.tokens[p.pos]
    }
}

fn p_peek_kind(p: Parser) -> TokenKind {
    p_peek(p).kind
}

fn p_at_end(p: Parser) -> bool {
    let k = p_peek_kind(p)
    match k {
        Eof -> true
        _   -> false
    }
}

fn p_advance(p: Parser) -> Parser {
    if p.pos >= p.tokens.len { p }
    else { Parser { ...p, pos: p.pos + 1 } }
}

fn p_current_line(p: Parser) -> i32 {
    p_peek(p).line
}

fn p_current_col(p: Parser) -> i32 {
    p_peek(p).col
}

fn kind_eq(a: TokenKind, b: TokenKind) -> bool {
    kind_name(a) == kind_name(b)
}

fn p_check(p: Parser, expected: TokenKind) -> bool {
    kind_eq(p_peek_kind(p), expected)
}

fn p_eat(p: Parser, expected: TokenKind) -> Parser {
    // Advances if current token matches, otherwise returns unchanged
    if p_check(p, expected) { p_advance(p) }
    else { p }
}

fn p_did_eat(p: Parser, expected: TokenKind) -> bool {
    // Returns true if current token matches (caller must also call p_eat)
    p_check(p, expected)
}

fn p_expect_ident(p: Parser) -> String {
    let tok = p_peek(p)
    match tok.kind {
        Ident -> tok.text
        _     -> ""
    }
}

// ── Add node to arena, return its index ────────────────────────────────────

struct AddResult {
    parser: Parser,
    idx:    i32
}

fn add_node(p: Parser, node: AstNode) -> AddResult {
    let idx = p.nodes.len
    let nodes2 = p.nodes.push(node)
    AddResult {
        parser: Parser { ...p, nodes: nodes2 },
        idx:    idx
    }
}

struct AddStmtResult {
    parser: Parser,
    idx:    i32
}

fn add_stmt(p: Parser, stmt: AstStmt) -> AddStmtResult {
    let idx = p.stmts.len
    let stmts2 = p.stmts.push(stmt)
    AddStmtResult {
        parser: Parser { ...p, stmts: stmts2 },
        idx:    idx
    }
}

// ── Parse Result (expression) ──────────────────────────────────────────────

struct ParseResult {
    parser: Parser,
    idx:    i32,
    ok:     bool,
    error:  String
}

fn ok_result(p: Parser, idx: i32) -> ParseResult {
    ParseResult { parser: p, idx: idx, ok: true, error: "" }
}

fn err_result(p: Parser, msg: String) -> ParseResult {
    ParseResult { parser: p, idx: -1, ok: false, error: msg }
}

// ── Parse Result (statement) ───────────────────────────────────────────────

struct StmtResult {
    parser: Parser,
    idx:    i32,
    ok:     bool,
    error:  String
}

fn ok_stmt(p: Parser, idx: i32) -> StmtResult {
    StmtResult { parser: p, idx: idx, ok: true, error: "" }
}

fn err_stmt(p: Parser, msg: String) -> StmtResult {
    StmtResult { parser: p, idx: -1, ok: false, error: msg }
}

// ── Operator precedence ────────────────────────────────────────────────────

fn prefix_bp(kind: TokenKind) -> i32 {
    let kn = kind_name(kind)
    if kn == "Minus" { 21 }
    else if kn == "Bang" { 21 }
    else if kn == "Tilde" { 21 }
    else { -1 }
}

fn infix_bp_left(kind: TokenKind) -> i32 {
    let kn = kind_name(kind)
    // Pratt: left binding power
    if kn == "PipePipe"  { 2 }
    else if kn == "AmpAmp"   { 4 }
    else if kn == "Pipe"     { 5 }
    else if kn == "Caret"    { 6 }
    else if kn == "Amp"      { 7 }
    else if kn == "EqEq"     { 8 }
    else if kn == "BangEq"   { 8 }
    else if kn == "Lt"       { 10 }
    else if kn == "Gt"       { 10 }
    else if kn == "LtEq"     { 10 }
    else if kn == "GtEq"     { 10 }
    else if kn == "Shl"      { 11 }
    else if kn == "Shr"      { 11 }
    else if kn == "DotDot"   { 12 }
    else if kn == "Plus"     { 14 }
    else if kn == "Minus"    { 14 }
    else if kn == "Star"     { 16 }
    else if kn == "Slash"    { 16 }
    else if kn == "Percent"  { 16 }
    else if kn == "StarStar" { 19 }
    else { -1 }
}

fn infix_bp_right(kind: TokenKind) -> i32 {
    let kn = kind_name(kind)
    if kn == "PipePipe"  { 3 }
    else if kn == "AmpAmp"   { 5 }
    else if kn == "Pipe"     { 6 }
    else if kn == "Caret"    { 7 }
    else if kn == "Amp"      { 8 }
    else if kn == "EqEq"     { 9 }
    else if kn == "BangEq"   { 9 }
    else if kn == "Lt"       { 11 }
    else if kn == "Gt"       { 11 }
    else if kn == "LtEq"     { 11 }
    else if kn == "GtEq"     { 11 }
    else if kn == "Shl"      { 12 }
    else if kn == "Shr"      { 12 }
    else if kn == "DotDot"   { 13 }
    else if kn == "Plus"     { 15 }
    else if kn == "Minus"    { 15 }
    else if kn == "Star"     { 17 }
    else if kn == "Slash"    { 17 }
    else if kn == "Percent"  { 17 }
    else if kn == "StarStar" { 18 }   // right-assoc: left < right
    else { -1 }
}

fn op_str(kind: TokenKind) -> String {
    let kn = kind_name(kind)
    if kn == "Plus" { "+" }
    else if kn == "Minus" { "-" }
    else if kn == "Star" { "*" }
    else if kn == "Slash" { "/" }
    else if kn == "Percent" { "%" }
    else if kn == "StarStar" { "**" }
    else if kn == "EqEq" { "==" }
    else if kn == "BangEq" { "!=" }
    else if kn == "Lt" { "<" }
    else if kn == "Gt" { ">" }
    else if kn == "LtEq" { "<=" }
    else if kn == "GtEq" { ">=" }
    else if kn == "AmpAmp" { "&&" }
    else if kn == "PipePipe" { "||" }
    else if kn == "Amp" { "&" }
    else if kn == "Pipe" { "|" }
    else if kn == "Caret" { "^" }
    else if kn == "Shl" { "<<" }
    else if kn == "Shr" { ">>" }
    else if kn == "DotDot" { ".." }
    else { "?" }
}

// ============================================================================
// Expression Parsing (Pratt / precedence climbing)
// ============================================================================

fn parse_expr(p: Parser, min_bp: i32) -> ParseResult {
    // Parse prefix (atom or unary)
    var r = parse_prefix(p)
    if !r.ok { r }
    else {
        var cur_p = r.parser
        var lhs = r.idx
        var running = true
        while running {
            let tok = p_peek(cur_p)
            let lbp = infix_bp_left(tok.kind)
            if lbp < min_bp {
                running = false
            } else {
                // Check for assignment: =
                if p_check(cur_p, TokenKind.Eq) {
                    cur_p = p_advance(cur_p)
                    let rr = parse_expr(cur_p, 1)
                    if !rr.ok {
                        running = false
                        r = rr
                    } else {
                        cur_p = rr.parser
                        let anode = AstNode {
                            ...empty_node(),
                            kind: Expr.Assign,
                            left: lhs,
                            right: rr.idx,
                            line: tok.line,
                            col: tok.col
                        }
                        let ar = add_node(cur_p, anode)
                        cur_p = ar.parser
                        lhs = ar.idx
                    }
                } else {
                    // Binary operator
                    let rbp = infix_bp_right(tok.kind)
                    let ostr = op_str(tok.kind)
                    cur_p = p_advance(cur_p)
                    let rr = parse_expr(cur_p, rbp)
                    if !rr.ok {
                        running = false
                        r = rr
                    } else {
                        cur_p = rr.parser
                        let bnode = AstNode {
                            ...empty_node(),
                            kind: Expr.BinOp,
                            op: ostr,
                            left: lhs,
                            right: rr.idx,
                            line: tok.line,
                            col: tok.col
                        }
                        let br = add_node(cur_p, bnode)
                        cur_p = br.parser
                        lhs = br.idx
                    }
                }
            }
        }
        if r.ok { ok_result(cur_p, lhs) }
        else { r }
    }
}

// ── Prefix / Atom parsing ──────────────────────────────────────────────────

fn parse_prefix(p: Parser) -> ParseResult {
    let tok = p_peek(p)
    let kn = kind_name(tok.kind)

    // Unary operators
    if kn == "Minus" || kn == "Bang" || kn == "Tilde" {
        let ubp = prefix_bp(tok.kind)
        let p2 = p_advance(p)
        let r = parse_expr(p2, ubp)
        if !r.ok { r }
        else {
            let unode = AstNode {
                ...empty_node(),
                kind: Expr.UnaryOp,
                op: tok.text,
                left: r.idx,
                line: tok.line,
                col: tok.col
            }
            let ar = add_node(r.parser, unode)
            ok_result(ar.parser, ar.idx)
        }
    }
    // Integer literal
    else if kn == "IntLit" {
        let p2 = p_advance(p)
        let node = AstNode {
            ...empty_node(),
            kind: Expr.IntLit,
            int_val: to_int(tok.text),
            str_val: tok.text,
            line: tok.line,
            col: tok.col
        }
        let ar = add_node(p2, node)
        parse_postfix(ar.parser, ar.idx)
    }
    // Float literal
    else if kn == "FloatLit" {
        let p2 = p_advance(p)
        let node = AstNode {
            ...empty_node(),
            kind: Expr.FloatLit,
            float_val: to_float(tok.text),
            str_val: tok.text,
            line: tok.line,
            col: tok.col
        }
        let ar = add_node(p2, node)
        parse_postfix(ar.parser, ar.idx)
    }
    // String literal
    else if kn == "StringLit" {
        let p2 = p_advance(p)
        let node = AstNode {
            ...empty_node(),
            kind: Expr.StringLit,
            str_val: tok.text,
            line: tok.line,
            col: tok.col
        }
        let ar = add_node(p2, node)
        parse_postfix(ar.parser, ar.idx)
    }
    // Boolean true
    else if kn == "True" {
        let p2 = p_advance(p)
        let node = AstNode {
            ...empty_node(),
            kind: Expr.BoolLit,
            bool_val: true,
            str_val: "true",
            line: tok.line,
            col: tok.col
        }
        let ar = add_node(p2, node)
        ok_result(ar.parser, ar.idx)
    }
    // Boolean false
    else if kn == "False" {
        let p2 = p_advance(p)
        let node = AstNode {
            ...empty_node(),
            kind: Expr.BoolLit,
            bool_val: false,
            str_val: "false",
            line: tok.line,
            col: tok.col
        }
        let ar = add_node(p2, node)
        ok_result(ar.parser, ar.idx)
    }
    // Nil
    else if kn == "Nil" {
        let p2 = p_advance(p)
        let node = AstNode {
            ...empty_node(),
            kind: Expr.NilLit,
            str_val: "nil",
            line: tok.line,
            col: tok.col
        }
        let ar = add_node(p2, node)
        ok_result(ar.parser, ar.idx)
    }
    // Identifier (may be followed by call, field access, etc.)
    else if kn == "Ident" {
        let p2 = p_advance(p)
        let node = AstNode {
            ...empty_node(),
            kind: Expr.Ident,
            name: tok.text,
            line: tok.line,
            col: tok.col
        }
        let ar = add_node(p2, node)
        parse_postfix(ar.parser, ar.idx)
    }
    // Parenthesized expression
    else if kn == "LParen" {
        let p2 = p_advance(p)
        let r = parse_expr(p2, 0)
        if !r.ok { r }
        else {
            if p_check(r.parser, TokenKind.RParen) {
                let p3 = p_advance(r.parser)
                parse_postfix(p3, r.idx)
            } else {
                err_result(r.parser, "expected closing parenthesis")
            }
        }
    }
    // Array literal: [a, b, c]
    else if kn == "LBracket" {
        parse_array_lit(p)
    }
    // If expression
    else if kn == "If" {
        parse_if_expr(p)
    }
    // Match expression
    else if kn == "Match" {
        parse_match_expr(p)
    }
    else {
        err_result(p, "unexpected token: " + tok.text + " (" + kn + ")")
    }
}

// ── Postfix parsing (calls, field access, method calls, index) ─────────────

fn parse_postfix(p: Parser, expr_idx: i32) -> ParseResult {
    var cur_p = p
    var cur_idx = expr_idx
    var running = true
    while running {
        let tok = p_peek(cur_p)
        let kn = kind_name(tok.kind)

        // Function call: expr(args...)
        if kn == "LParen" {
            cur_p = p_advance(cur_p)
            var call_args = []
            var args_ok = true
            while !p_check(cur_p, TokenKind.RParen) && !p_at_end(cur_p) && args_ok {
                let ar = parse_expr(cur_p, 0)
                if !ar.ok {
                    args_ok = false
                    running = false
                } else {
                    call_args = call_args.push(ar.idx)
                    cur_p = ar.parser
                    if p_check(cur_p, TokenKind.Comma) {
                        cur_p = p_advance(cur_p)
                    }
                }
            }
            if args_ok {
                if p_check(cur_p, TokenKind.RParen) {
                    cur_p = p_advance(cur_p)
                    let cnode = AstNode {
                        ...empty_node(),
                        kind: Expr.Call,
                        left: cur_idx,
                        args: call_args,
                        line: tok.line,
                        col: tok.col
                    }
                    let cr = add_node(cur_p, cnode)
                    cur_p = cr.parser
                    cur_idx = cr.idx
                } else {
                    running = false
                }
            }
        }
        // Field access or method call: expr.name or expr.name(args)
        else if kn == "Dot" {
            cur_p = p_advance(cur_p)
            let field_tok = p_peek(cur_p)
            let fkn = kind_name(field_tok.kind)
            if fkn == "Ident" {
                let fname = field_tok.text
                cur_p = p_advance(cur_p)
                // Check for method call
                if p_check(cur_p, TokenKind.LParen) {
                    cur_p = p_advance(cur_p)
                    var margs = []
                    var mok = true
                    while !p_check(cur_p, TokenKind.RParen) && !p_at_end(cur_p) && mok {
                        let ar = parse_expr(cur_p, 0)
                        if !ar.ok {
                            mok = false
                            running = false
                        } else {
                            margs = margs.push(ar.idx)
                            cur_p = ar.parser
                            if p_check(cur_p, TokenKind.Comma) {
                                cur_p = p_advance(cur_p)
                            }
                        }
                    }
                    if mok {
                        if p_check(cur_p, TokenKind.RParen) {
                            cur_p = p_advance(cur_p)
                            let mnode = AstNode {
                                ...empty_node(),
                                kind: Expr.MethodCall,
                                name: fname,
                                left: cur_idx,
                                args: margs,
                                line: field_tok.line,
                                col: field_tok.col
                            }
                            let mr = add_node(cur_p, mnode)
                            cur_p = mr.parser
                            cur_idx = mr.idx
                        } else {
                            running = false
                        }
                    }
                } else {
                    // Plain field access
                    let fnode = AstNode {
                        ...empty_node(),
                        kind: Expr.FieldAccess,
                        name: fname,
                        left: cur_idx,
                        line: field_tok.line,
                        col: field_tok.col
                    }
                    let fr = add_node(cur_p, fnode)
                    cur_p = fr.parser
                    cur_idx = fr.idx
                }
            } else if fkn == "IntLit" {
                // Tuple-style field access: expr.0
                let fnode = AstNode {
                    ...empty_node(),
                    kind: Expr.FieldAccess,
                    name: field_tok.text,
                    left: cur_idx,
                    line: field_tok.line,
                    col: field_tok.col
                }
                cur_p = p_advance(cur_p)
                let fr = add_node(cur_p, fnode)
                cur_p = fr.parser
                cur_idx = fr.idx
            } else {
                running = false
            }
        }
        // Index: expr[index]
        else if kn == "LBracket" {
            cur_p = p_advance(cur_p)
            let ir = parse_expr(cur_p, 0)
            if !ir.ok {
                running = false
            } else {
                cur_p = ir.parser
                if p_check(cur_p, TokenKind.RBracket) {
                    cur_p = p_advance(cur_p)
                    let inode = AstNode {
                        ...empty_node(),
                        kind: Expr.Index,
                        left: cur_idx,
                        right: ir.idx,
                        line: tok.line,
                        col: tok.col
                    }
                    let ixr = add_node(cur_p, inode)
                    cur_p = ixr.parser
                    cur_idx = ixr.idx
                } else {
                    running = false
                }
            }
        }
        else {
            running = false
        }
    }
    ok_result(cur_p, cur_idx)
}

// ── Array literal ──────────────────────────────────────────────────────────

fn parse_array_lit(p: Parser) -> ParseResult {
    let tok = p_peek(p)
    var cur = p_advance(p)   // skip [
    var elems = []
    var aok = true
    while !p_check(cur, TokenKind.RBracket) && !p_at_end(cur) && aok {
        let r = parse_expr(cur, 0)
        if !r.ok {
            aok = false
        } else {
            elems = elems.push(r.idx)
            cur = r.parser
            if p_check(cur, TokenKind.Comma) {
                cur = p_advance(cur)
            }
        }
    }
    if !aok { err_result(cur, "error in array element") }
    else if p_check(cur, TokenKind.RBracket) {
        cur = p_advance(cur)
        let node = AstNode {
            ...empty_node(),
            kind: Expr.ArrayLit,
            children: elems,
            line: tok.line,
            col: tok.col
        }
        let ar = add_node(cur, node)
        parse_postfix(ar.parser, ar.idx)
    } else {
        err_result(cur, "expected ] after array literal")
    }
}

// ── If expression ──────────────────────────────────────────────────────────

fn parse_if_expr(p: Parser) -> ParseResult {
    let tok = p_peek(p)
    var cur = p_advance(p)   // skip if
    let cond = parse_expr(cur, 0)
    if !cond.ok { cond }
    else {
        cur = cond.parser
        let then_r = parse_block_stmts(cur)
        cur = then_r.parser
        var else_idxs = []
        // Check for else
        if p_check(cur, TokenKind.Else) {
            cur = p_advance(cur)
            if p_check(cur, TokenKind.If) {
                // else if -- parse as nested if expr wrapped in a block
                let eir = parse_if_expr(cur)
                if eir.ok {
                    cur = eir.parser
                    // Wrap the if-expr as a single-element stmt in else_body
                    let wrap_stmt = AstStmt {
                        kind: Stmt.ExprStmt,
                        name: "",
                        expr_idx: eir.idx,
                        arg_idxs: [],
                        params: [],
                        body: [],
                        fields: [],
                        variants: [],
                        binding: "",
                        iter_idx: -1,
                        line: 0,
                        col: 0
                    }
                    let ws = add_stmt(cur, wrap_stmt)
                    cur = ws.parser
                    else_idxs = else_idxs.push(ws.idx)
                }
            } else {
                let else_r = parse_block_stmts(cur)
                cur = else_r.parser
                else_idxs = else_r.indices
            }
        }
        let node = AstNode {
            ...empty_node(),
            kind: Expr.IfExpr,
            left: cond.idx,
            then_body: then_r.indices,
            else_body: else_idxs,
            line: tok.line,
            col: tok.col
        }
        let ar = add_node(cur, node)
        ok_result(ar.parser, ar.idx)
    }
}

// ── Match expression ───────────────────────────────────────────────────────

fn parse_match_expr(p: Parser) -> ParseResult {
    let tok = p_peek(p)
    var cur = p_advance(p)   // skip match

    let subj = parse_expr(cur, 0)
    if !subj.ok { subj }
    else {
        cur = subj.parser
        if !p_check(cur, TokenKind.LBrace) {
            err_result(cur, "expected open brace after match subject")
        } else {
            cur = p_advance(cur)  // skip open brace
            var pats = []
            var bods = []
            var match_ok = true
            while !p_check(cur, TokenKind.RBrace) && !p_at_end(cur) && match_ok {
                // Parse pattern (we treat it as an expression for simplicity)
                let pat = parse_expr(cur, 0)
                if !pat.ok {
                    // Try wildcard _
                    if p_check(cur, TokenKind.Underscore) {
                        let unode = AstNode {
                            ...empty_node(),
                            kind: Expr.Ident,
                            name: "_",
                            line: p_current_line(cur),
                            col: p_current_col(cur)
                        }
                        cur = p_advance(cur)
                        let ur = add_node(cur, unode)
                        cur = ur.parser
                        pats = pats.push(ur.idx)
                    } else {
                        match_ok = false
                    }
                } else {
                    cur = pat.parser
                    pats = pats.push(pat.idx)
                }
                // Expect ->
                if match_ok {
                    if p_check(cur, TokenKind.Arrow) {
                        cur = p_advance(cur)
                    } else {
                        match_ok = false
                    }
                }
                // Parse body expression
                if match_ok {
                    let body = parse_expr(cur, 0)
                    if !body.ok {
                        match_ok = false
                    } else {
                        cur = body.parser
                        bods = bods.push(body.idx)
                    }
                }
                // Optional comma/newline separator
                if match_ok && p_check(cur, TokenKind.Comma) {
                    cur = p_advance(cur)
                }
            }
            if !match_ok {
                err_result(cur, "error in match arm")
            } else if p_check(cur, TokenKind.RBrace) {
                cur = p_advance(cur)
                let node = AstNode {
                    ...empty_node(),
                    kind: Expr.MatchExpr,
                    left: subj.idx,
                    arm_pats: pats,
                    arm_bodies: bods,
                    line: tok.line,
                    col: tok.col
                }
                let ar = add_node(cur, node)
                ok_result(ar.parser, ar.idx)
            } else {
                err_result(cur, "expected closing brace after match")
            }
        }
    }
}

// ============================================================================
// Statement Parsing
// ============================================================================

struct BlockResult {
    parser:  Parser,
    indices: []i32,
    ok:      bool,
    error:   String
}

fn parse_block_stmts(p: Parser) -> BlockResult {
    if !p_check(p, TokenKind.LBrace) {
        BlockResult { parser: p, indices: [], ok: false, error: "expected open brace" }
    } else {
        var cur = p_advance(p)  // skip open brace
        var idxs = []
        var block_ok = true
        while !p_check(cur, TokenKind.RBrace) && !p_at_end(cur) && block_ok {
            let sr = parse_stmt(cur)
            if !sr.ok {
                block_ok = false
            } else {
                idxs = idxs.push(sr.idx)
                cur = sr.parser
            }
        }
        if !block_ok {
            BlockResult { parser: cur, indices: idxs, ok: false, error: "error in block" }
        } else if p_check(cur, TokenKind.RBrace) {
            cur = p_advance(cur)
            BlockResult { parser: cur, indices: idxs, ok: true, error: "" }
        } else {
            BlockResult { parser: cur, indices: idxs, ok: false, error: "expected closing brace" }
        }
    }
}

fn parse_stmt(p: Parser) -> StmtResult {
    let tok = p_peek(p)
    let kn = kind_name(tok.kind)

    // Let binding
    if kn == "Let" {
        parse_let_stmt(p)
    }
    // Var binding
    else if kn == "Var" {
        parse_var_stmt(p)
    }
    // Function definition
    else if kn == "Fn" {
        parse_fn_def(p)
    }
    // Struct definition
    else if kn == "Struct" {
        parse_struct_def(p)
    }
    // Enum definition
    else if kn == "Enum" {
        parse_enum_def(p)
    }
    // For loop
    else if kn == "For" {
        parse_for_stmt(p)
    }
    // While loop
    else if kn == "While" {
        parse_while_stmt(p)
    }
    // Print (built-in, parsed like a function call)
    else if kn == "Ident" && tok.text == "print" {
        parse_print_stmt(p)
    }
    // Break
    else if kn == "Break" {
        let p2 = p_advance(p)
        let s = AstStmt {
            kind: Stmt.BreakStmt,
            name: "",
            expr_idx: -1,
            arg_idxs: [],
            params: [],
            body: [],
            fields: [],
            variants: [],
            binding: "",
            iter_idx: -1,
            line: tok.line,
            col: tok.col
        }
        let sr = add_stmt(p2, s)
        ok_stmt(sr.parser, sr.idx)
    }
    // Continue
    else if kn == "Continue" {
        let p2 = p_advance(p)
        let s = AstStmt {
            kind: Stmt.ContinueStmt,
            name: "",
            expr_idx: -1,
            arg_idxs: [],
            params: [],
            body: [],
            fields: [],
            variants: [],
            binding: "",
            iter_idx: -1,
            line: tok.line,
            col: tok.col
        }
        let sr = add_stmt(p2, s)
        ok_stmt(sr.parser, sr.idx)
    }
    // Expression statement (including assignment)
    else {
        parse_expr_stmt(p)
    }
}

// ── Let statement ──────────────────────────────────────────────────────────

fn parse_let_stmt(p: Parser) -> StmtResult {
    let tok = p_peek(p)
    var cur = p_advance(p)   // skip let
    let name = p_expect_ident(cur)
    if name == "" { err_stmt(cur, "expected identifier after keyword") }
    else {
        cur = p_advance(cur)
        if p_check(cur, TokenKind.Eq) {
            cur = p_advance(cur)
            let r = parse_expr(cur, 0)
            if !r.ok { err_stmt(r.parser, "expected expression in binding") }
            else {
                let s = AstStmt {
                    kind: Stmt.LetStmt,
                    name: name,
                    expr_idx: r.idx,
                    arg_idxs: [],
                    params: [],
                    body: [],
                    fields: [],
                    variants: [],
                    binding: "",
                    iter_idx: -1,
                    line: tok.line,
                    col: tok.col
                }
                let sr = add_stmt(r.parser, s)
                ok_stmt(sr.parser, sr.idx)
            }
        } else {
            err_stmt(cur, "expected = after identifier in binding")
        }
    }
}

// ── Var statement ──────────────────────────────────────────────────────────

fn parse_var_stmt(p: Parser) -> StmtResult {
    let tok = p_peek(p)
    var cur = p_advance(p)   // skip keyword
    let name = p_expect_ident(cur)
    if name == "" { err_stmt(cur, "expected identifier after keyword") }
    else {
        cur = p_advance(cur)
        if p_check(cur, TokenKind.Eq) {
            cur = p_advance(cur)
            let r = parse_expr(cur, 0)
            if !r.ok { err_stmt(r.parser, "expected expression in binding") }
            else {
                let s = AstStmt {
                    kind: Stmt.VarStmt,
                    name: name,
                    expr_idx: r.idx,
                    arg_idxs: [],
                    params: [],
                    body: [],
                    fields: [],
                    variants: [],
                    binding: "",
                    iter_idx: -1,
                    line: tok.line,
                    col: tok.col
                }
                let sr = add_stmt(r.parser, s)
                ok_stmt(sr.parser, sr.idx)
            }
        } else {
            err_stmt(cur, "expected = after identifier in binding")
        }
    }
}

// ── Expression statement (or assignment) ───────────────────────────────────

fn parse_expr_stmt(p: Parser) -> StmtResult {
    let tok = p_peek(p)
    let r = parse_expr(p, 0)
    if !r.ok { err_stmt(r.parser, r.error) }
    else {
        var cur = r.parser
        var eidx = r.idx

        // Check for assignment: ident = expr
        if p_check(cur, TokenKind.Eq) {
            cur = p_advance(cur)
            let rhs = parse_expr(cur, 0)
            if !rhs.ok { err_stmt(rhs.parser, "expected expression after =") }
            else {
                // Get the name from the lhs node
                let lhs_node = cur.nodes[eidx]
                let s = AstStmt {
                    kind: Stmt.AssignStmt,
                    name: lhs_node.name,
                    expr_idx: rhs.idx,
                    arg_idxs: [],
                    params: [],
                    body: [],
                    fields: [],
                    variants: [],
                    binding: "",
                    iter_idx: -1,
                    line: tok.line,
                    col: tok.col
                }
                let sr = add_stmt(rhs.parser, s)
                ok_stmt(sr.parser, sr.idx)
            }
        } else {
            let s = AstStmt {
                kind: Stmt.ExprStmt,
                name: "",
                expr_idx: eidx,
                arg_idxs: [],
                params: [],
                body: [],
                fields: [],
                variants: [],
                binding: "",
                iter_idx: -1,
                line: tok.line,
                col: tok.col
            }
            let sr = add_stmt(cur, s)
            ok_stmt(sr.parser, sr.idx)
        }
    }
}

// ── Function definition ────────────────────────────────────────────────────

fn parse_fn_def(p: Parser) -> StmtResult {
    let tok = p_peek(p)
    var cur = p_advance(p)   // skip fn
    let name = p_expect_ident(cur)
    if name == "" { err_stmt(cur, "expected function name") }
    else {
        cur = p_advance(cur)
        // Parse parameters
        if !p_check(cur, TokenKind.LParen) {
            err_stmt(cur, "expected ( after function name")
        } else {
            cur = p_advance(cur)
            var fn_params = []
            var params_ok = true
            while !p_check(cur, TokenKind.RParen) && !p_at_end(cur) && params_ok {
                let pname = p_expect_ident(cur)
                if pname == "" {
                    params_ok = false
                } else {
                    cur = p_advance(cur)
                    // Optional : type
                    var pty = ""
                    if p_check(cur, TokenKind.Colon) {
                        cur = p_advance(cur)
                        let type_tok = p_peek(cur)
                        pty = type_tok.text
                        cur = p_advance(cur)
                    }
                    fn_params = fn_params.push(Param { name: pname, ty: pty })
                    if p_check(cur, TokenKind.Comma) {
                        cur = p_advance(cur)
                    }
                }
            }
            if !params_ok {
                err_stmt(cur, "error in function parameters")
            } else if !p_check(cur, TokenKind.RParen) {
                err_stmt(cur, "expected ) after parameters")
            } else {
                cur = p_advance(cur)  // skip )
                // Optional -> return type (skip for now)
                if p_check(cur, TokenKind.Arrow) {
                    cur = p_advance(cur)
                    // Skip return type tokens (simple: just one ident)
                    if p_check(cur, TokenKind.LBracket) {
                        // []Type
                        cur = p_advance(cur)  // skip [
                        cur = p_advance(cur)  // skip ]
                        cur = p_advance(cur)  // skip type name
                    } else {
                        cur = p_advance(cur)  // skip type name
                    }
                }
                // Parse body
                let br = parse_block_stmts(cur)
                if !br.ok { err_stmt(br.parser, "error in function body") }
                else {
                    let s = AstStmt {
                        kind: Stmt.FnDef,
                        name: name,
                        expr_idx: -1,
                        arg_idxs: [],
                        params: fn_params,
                        body: br.indices,
                        fields: [],
                        variants: [],
                        binding: "",
                        iter_idx: -1,
                        line: tok.line,
                        col: tok.col
                    }
                    let sr = add_stmt(br.parser, s)
                    ok_stmt(sr.parser, sr.idx)
                }
            }
        }
    }
}

// ── Struct definition ──────────────────────────────────────────────────────

fn parse_struct_def(p: Parser) -> StmtResult {
    let tok = p_peek(p)
    var cur = p_advance(p)   // skip struct
    let name = p_expect_ident(cur)
    if name == "" { err_stmt(cur, "expected struct name") }
    else {
        cur = p_advance(cur)
        if !p_check(cur, TokenKind.LBrace) {
            err_stmt(cur, "expected open brace after struct name")
        } else {
            cur = p_advance(cur)
            var sfields = []
            var fields_ok = true
            while !p_check(cur, TokenKind.RBrace) && !p_at_end(cur) && fields_ok {
                let fname = p_expect_ident(cur)
                if fname == "" {
                    fields_ok = false
                } else {
                    cur = p_advance(cur)
                    if p_check(cur, TokenKind.Colon) {
                        cur = p_advance(cur)
                        let ftype_tok = p_peek(cur)
                        let ftype = ftype_tok.text
                        cur = p_advance(cur)
                        sfields = sfields.push(Field { name: fname, ty: ftype })
                    } else {
                        sfields = sfields.push(Field { name: fname, ty: "" })
                    }
                    if p_check(cur, TokenKind.Comma) {
                        cur = p_advance(cur)
                    }
                }
            }
            if !fields_ok {
                err_stmt(cur, "error in struct fields")
            } else if p_check(cur, TokenKind.RBrace) {
                cur = p_advance(cur)
                let s = AstStmt {
                    kind: Stmt.StructDef,
                    name: name,
                    expr_idx: -1,
                    arg_idxs: [],
                    params: [],
                    body: [],
                    fields: sfields,
                    variants: [],
                    binding: "",
                    iter_idx: -1,
                    line: tok.line,
                    col: tok.col
                }
                let sr = add_stmt(cur, s)
                ok_stmt(sr.parser, sr.idx)
            } else {
                err_stmt(cur, "expected closing brace after struct")
            }
        }
    }
}

// ── Enum definition ────────────────────────────────────────────────────────

fn parse_enum_def(p: Parser) -> StmtResult {
    let tok = p_peek(p)
    var cur = p_advance(p)   // skip enum
    let name = p_expect_ident(cur)
    if name == "" { err_stmt(cur, "expected enum name") }
    else {
        cur = p_advance(cur)
        if !p_check(cur, TokenKind.LBrace) {
            err_stmt(cur, "expected open brace after enum name")
        } else {
            cur = p_advance(cur)
            var evariants = []
            var vars_ok = true
            while !p_check(cur, TokenKind.RBrace) && !p_at_end(cur) && vars_ok {
                let vname = p_expect_ident(cur)
                if vname == "" {
                    vars_ok = false
                } else {
                    cur = p_advance(cur)
                    // Check for variant fields (name: Type, ...)
                    var vfields = []
                    if p_check(cur, TokenKind.LParen) {
                        cur = p_advance(cur)
                        while !p_check(cur, TokenKind.RParen) && !p_at_end(cur) {
                            let vfname = p_expect_ident(cur)
                            if vfname == "" {
                                vars_ok = false
                            } else {
                                cur = p_advance(cur)
                                if p_check(cur, TokenKind.Colon) {
                                    cur = p_advance(cur)
                                    let vft = p_peek(cur)
                                    vfields = vfields.push(Field { name: vfname, ty: vft.text })
                                    cur = p_advance(cur)
                                } else {
                                    vfields = vfields.push(Field { name: vfname, ty: "" })
                                }
                                if p_check(cur, TokenKind.Comma) {
                                    cur = p_advance(cur)
                                }
                            }
                        }
                        if p_check(cur, TokenKind.RParen) {
                            cur = p_advance(cur)
                        }
                    }
                    evariants = evariants.push(Variant { name: vname, fields: vfields })
                    if p_check(cur, TokenKind.Comma) {
                        cur = p_advance(cur)
                    }
                }
            }
            if !vars_ok {
                err_stmt(cur, "error in enum variants")
            } else if p_check(cur, TokenKind.RBrace) {
                cur = p_advance(cur)
                let s = AstStmt {
                    kind: Stmt.EnumDef,
                    name: name,
                    expr_idx: -1,
                    arg_idxs: [],
                    params: [],
                    body: [],
                    fields: [],
                    variants: evariants,
                    binding: "",
                    iter_idx: -1,
                    line: tok.line,
                    col: tok.col
                }
                let sr = add_stmt(cur, s)
                ok_stmt(sr.parser, sr.idx)
            } else {
                err_stmt(cur, "expected closing brace after enum")
            }
        }
    }
}

// ── For loop ───────────────────────────────────────────────────────────────

fn parse_for_stmt(p: Parser) -> StmtResult {
    let tok = p_peek(p)
    var cur = p_advance(p)   // skip for
    let binding = p_expect_ident(cur)
    if binding == "" { err_stmt(cur, "expected binding name in for loop") }
    else {
        cur = p_advance(cur)
        if !p_check(cur, TokenKind.In) {
            err_stmt(cur, "expected 'in' after for binding")
        } else {
            cur = p_advance(cur)  // skip in
            let iter_r = parse_expr(cur, 0)
            if !iter_r.ok { err_stmt(iter_r.parser, "expected iterable expression") }
            else {
                let br = parse_block_stmts(iter_r.parser)
                if !br.ok { err_stmt(br.parser, "error in for body") }
                else {
                    let s = AstStmt {
                        kind: Stmt.ForStmt,
                        name: "",
                        expr_idx: -1,
                        arg_idxs: [],
                        params: [],
                        body: br.indices,
                        fields: [],
                        variants: [],
                        binding: binding,
                        iter_idx: iter_r.idx,
                        line: tok.line,
                        col: tok.col
                    }
                    let sr = add_stmt(br.parser, s)
                    ok_stmt(sr.parser, sr.idx)
                }
            }
        }
    }
}

// ── While loop ─────────────────────────────────────────────────────────────

fn parse_while_stmt(p: Parser) -> StmtResult {
    let tok = p_peek(p)
    var cur = p_advance(p)   // skip while
    let cond = parse_expr(cur, 0)
    if !cond.ok { err_stmt(cond.parser, "expected condition in while loop") }
    else {
        let br = parse_block_stmts(cond.parser)
        if !br.ok { err_stmt(br.parser, "error in while body") }
        else {
            let s = AstStmt {
                kind: Stmt.WhileStmt,
                name: "",
                expr_idx: cond.idx,
                arg_idxs: [],
                params: [],
                body: br.indices,
                fields: [],
                variants: [],
                binding: "",
                iter_idx: -1,
                line: tok.line,
                col: tok.col
            }
            let sr = add_stmt(br.parser, s)
            ok_stmt(sr.parser, sr.idx)
        }
    }
}

// ── Print statement ────────────────────────────────────────────────────────

fn parse_print_stmt(p: Parser) -> StmtResult {
    let tok = p_peek(p)
    var cur = p_advance(p)   // skip print ident
    if p_check(cur, TokenKind.LParen) {
        cur = p_advance(cur)
        var pargs = []
        var pok = true
        while !p_check(cur, TokenKind.RParen) && !p_at_end(cur) && pok {
            let r = parse_expr(cur, 0)
            if !r.ok {
                pok = false
            } else {
                pargs = pargs.push(r.idx)
                cur = r.parser
                if p_check(cur, TokenKind.Comma) {
                    cur = p_advance(cur)
                }
            }
        }
        if !pok { err_stmt(cur, "error in print arguments") }
        else if p_check(cur, TokenKind.RParen) {
            cur = p_advance(cur)
            let s = AstStmt {
                kind: Stmt.PrintStmt,
                name: "",
                expr_idx: -1,
                arg_idxs: pargs,
                params: [],
                body: [],
                fields: [],
                variants: [],
                binding: "",
                iter_idx: -1,
                line: tok.line,
                col: tok.col
            }
            let sr = add_stmt(cur, s)
            ok_stmt(sr.parser, sr.idx)
        } else {
            err_stmt(cur, "expected ) after print arguments")
        }
    } else {
        // print without parens -- treat as expression statement
        parse_expr_stmt(p)
    }
}

// ============================================================================
// Top-level parse: parse a sequence of statements
// ============================================================================

fn parse_program(tokens: []Token) -> Program {
    var p = new_parser(tokens)
    var top_idxs = []
    var running = true
    while !p_at_end(p) && running {
        let sr = parse_stmt(p)
        if !sr.ok {
            print("Parse error: " + sr.error + " at line " + to_string(p_current_line(p)))
            running = false
        } else {
            top_idxs = top_idxs.push(sr.idx)
            p = sr.parser
        }
    }
    Program {
        nodes: p.nodes,
        stmts: p.stmts,
        top:   top_idxs
    }
}

// ============================================================================
// AST Pretty-Printer
// ============================================================================

fn indent_str(depth: i32) -> String {
    var s = ""
    var i = 0
    while i < depth {
        s = s + "  "
        i = i + 1
    }
    s
}

fn print_expr_node(prog: Program, idx: i32, depth: i32) -> String {
    if idx < 0 || idx >= prog.nodes.len { indent_str(depth) + "<nil>" }
    else {
        let node = prog.nodes[idx]
        let pre = indent_str(depth)
        match node.kind {
            IntLit     -> pre + "IntLit(" + to_string(node.int_val) + ")"
            FloatLit   -> pre + "FloatLit(" + node.str_val + ")"
            StringLit  -> pre + "StringLit(" + node.str_val + ")"
            BoolLit    -> pre + "BoolLit(" + node.str_val + ")"
            NilLit     -> pre + "Nil"
            Ident      -> pre + "Ident(" + node.name + ")"
            BinOp      -> {
                let l = print_expr_node(prog, node.left, depth + 1)
                let r = print_expr_node(prog, node.right, depth + 1)
                pre + "BinOp(" + node.op + ")\n" + l + "\n" + r
            }
            UnaryOp    -> {
                let inner = print_expr_node(prog, node.left, depth + 1)
                pre + "UnaryOp(" + node.op + ")\n" + inner
            }
            Call       -> {
                var s = pre + "Call\n"
                s = s + print_expr_node(prog, node.left, depth + 1) + "\n"
                s = s + indent_str(depth + 1) + "args:"
                for ai in node.args {
                    s = s + "\n" + print_expr_node(prog, ai, depth + 2)
                }
                s
            }
            MethodCall -> {
                var s = pre + "MethodCall(." + node.name + ")\n"
                s = s + print_expr_node(prog, node.left, depth + 1) + "\n"
                s = s + indent_str(depth + 1) + "args:"
                for ai in node.args {
                    s = s + "\n" + print_expr_node(prog, ai, depth + 2)
                }
                s
            }
            FieldAccess -> {
                let obj = print_expr_node(prog, node.left, depth + 1)
                pre + "FieldAccess(." + node.name + ")\n" + obj
            }
            ArrayLit   -> {
                var s = pre + "ArrayLit"
                for ci in node.children {
                    s = s + "\n" + print_expr_node(prog, ci, depth + 1)
                }
                s
            }
            Index      -> {
                let obj = print_expr_node(prog, node.left, depth + 1)
                let ix = print_expr_node(prog, node.right, depth + 1)
                pre + "Index\n" + obj + "\n" + ix
            }
            IfExpr     -> {
                var s = pre + "IfExpr\n"
                s = s + indent_str(depth + 1) + "cond:\n"
                s = s + print_expr_node(prog, node.left, depth + 2) + "\n"
                s = s + indent_str(depth + 1) + "then:"
                for ti in node.then_body {
                    s = s + "\n" + print_stmt_node(prog, ti, depth + 2)
                }
                if node.else_body.len > 0 {
                    s = s + "\n" + indent_str(depth + 1) + "else:"
                    for ei in node.else_body {
                        s = s + "\n" + print_stmt_node(prog, ei, depth + 2)
                    }
                }
                s
            }
            MatchExpr  -> {
                var s = pre + "MatchExpr\n"
                s = s + indent_str(depth + 1) + "subject:\n"
                s = s + print_expr_node(prog, node.left, depth + 2)
                var ai = 0
                while ai < node.arm_pats.len {
                    s = s + "\n" + indent_str(depth + 1) + "arm:\n"
                    s = s + indent_str(depth + 2) + "pat:\n"
                    s = s + print_expr_node(prog, node.arm_pats[ai], depth + 3) + "\n"
                    s = s + indent_str(depth + 2) + "body:\n"
                    s = s + print_expr_node(prog, node.arm_bodies[ai], depth + 3)
                    ai = ai + 1
                }
                s
            }
            Assign     -> {
                let l = print_expr_node(prog, node.left, depth + 1)
                let r = print_expr_node(prog, node.right, depth + 1)
                pre + "Assign\n" + l + "\n" + r
            }
            _          -> pre + "<?>"
        }
    }
}

fn print_stmt_node(prog: Program, idx: i32, depth: i32) -> String {
    if idx < 0 || idx >= prog.stmts.len { indent_str(depth) + "<nil-stmt>" }
    else {
        let stmt = prog.stmts[idx]
        let pre = indent_str(depth)
        match stmt.kind {
            LetStmt -> {
                let val = print_expr_node(prog, stmt.expr_idx, depth + 1)
                pre + "LetStmt(" + stmt.name + ")\n" + val
            }
            VarStmt -> {
                let val = print_expr_node(prog, stmt.expr_idx, depth + 1)
                pre + "VarStmt(" + stmt.name + ")\n" + val
            }
            AssignStmt -> {
                let val = print_expr_node(prog, stmt.expr_idx, depth + 1)
                pre + "AssignStmt(" + stmt.name + ")\n" + val
            }
            ExprStmt -> {
                let val = print_expr_node(prog, stmt.expr_idx, depth + 1)
                pre + "ExprStmt\n" + val
            }
            FnDef -> {
                var s = pre + "FnDef(" + stmt.name + ")\n"
                s = s + indent_str(depth + 1) + "params:"
                for prm in stmt.params {
                    s = s + " " + prm.name
                    if prm.ty != "" {
                        s = s + ":" + prm.ty
                    }
                }
                s = s + "\n" + indent_str(depth + 1) + "body:"
                for bi in stmt.body {
                    s = s + "\n" + print_stmt_node(prog, bi, depth + 2)
                }
                s
            }
            StructDef -> {
                var s = pre + "StructDef(" + stmt.name + ")"
                for fld in stmt.fields {
                    s = s + "\n" + indent_str(depth + 1) + fld.name + ": " + fld.ty
                }
                s
            }
            EnumDef -> {
                var s = pre + "EnumDef(" + stmt.name + ")"
                for v in stmt.variants {
                    s = s + "\n" + indent_str(depth + 1) + v.name
                    if v.fields.len > 0 {
                        s = s + "("
                        var fi = 0
                        for vf in v.fields {
                            if fi > 0 { s = s + ", " }
                            s = s + vf.name + ": " + vf.ty
                            fi = fi + 1
                        }
                        s = s + ")"
                    }
                }
                s
            }
            ForStmt -> {
                var s = pre + "ForStmt(" + stmt.binding + " in)\n"
                s = s + indent_str(depth + 1) + "iter:\n"
                s = s + print_expr_node(prog, stmt.iter_idx, depth + 2) + "\n"
                s = s + indent_str(depth + 1) + "body:"
                for bi in stmt.body {
                    s = s + "\n" + print_stmt_node(prog, bi, depth + 2)
                }
                s
            }
            WhileStmt -> {
                var s = pre + "WhileStmt\n"
                s = s + indent_str(depth + 1) + "cond:\n"
                s = s + print_expr_node(prog, stmt.expr_idx, depth + 2) + "\n"
                s = s + indent_str(depth + 1) + "body:"
                for bi in stmt.body {
                    s = s + "\n" + print_stmt_node(prog, bi, depth + 2)
                }
                s
            }
            PrintStmt -> {
                var s = pre + "PrintStmt"
                for ai in stmt.arg_idxs {
                    s = s + "\n" + print_expr_node(prog, ai, depth + 1)
                }
                s
            }
            BreakStmt    -> pre + "Break"
            ContinueStmt -> pre + "Continue"
            _            -> pre + "<?stmt>"
        }
    }
}

fn print_program(prog: Program) {
    print("=== AST ===")
    for idx in prog.top {
        let s = print_stmt_node(prog, idx, 0)
        print(s)
        print("")
    }
}

// ============================================================================
// MAIN -- Demonstrate the parser on sample Tallow programs
// ============================================================================

fn main() {
    print("=== Tallow Bootstrap Parser ===")
    print("")

    // Test 1: Simple bindings and arithmetic
    let src1 = 'let x = 42 + 3 * 2'
    print("--- Test 1: " + src1 + " ---")
    let toks1 = tokenize(src1)
    let prog1 = parse_program(toks1)
    print_program(prog1)

    // Test 2: Function definition (use single-quote to avoid brace issues)
    let src2 = 'fn add(a: i32, b: i32) -> i32 { a + b }'
    print("--- Test 2: fn add ---")
    let toks2 = tokenize(src2)
    let prog2 = parse_program(toks2)
    print_program(prog2)

    // Test 3: Method chains and field access
    let src3 = 'let y = items.len'
    print("--- Test 3: field access ---")
    let toks3 = tokenize(src3)
    let prog3 = parse_program(toks3)
    print_program(prog3)

    // Test 4: Array literal
    let src4 = 'let arr = [1, 2, 3]'
    print("--- Test 4: array literal ---")
    let toks4 = tokenize(src4)
    let prog4 = parse_program(toks4)
    print_program(prog4)

    // Test 5: For loop
    let src5 = 'for i in items { print(i) }'
    print("--- Test 5: for loop ---")
    let toks5 = tokenize(src5)
    let prog5 = parse_program(toks5)
    print_program(prog5)

    // Test 6: While loop with comparison
    let src6 = 'while x < 10 { x = x + 1 }'
    print("--- Test 6: while loop ---")
    let toks6 = tokenize(src6)
    let prog6 = parse_program(toks6)
    print_program(prog6)

    // Test 7: Struct definition
    let src7 = 'struct Point { x: f64, y: f64 }'
    print("--- Test 7: struct def ---")
    let toks7 = tokenize(src7)
    let prog7 = parse_program(toks7)
    print_program(prog7)

    // Test 8: Enum definition
    let src8 = 'enum Color { Red, Green, Blue }'
    print("--- Test 8: enum def ---")
    let toks8 = tokenize(src8)
    let prog8 = parse_program(toks8)
    print_program(prog8)

    // Test 9: Nested expressions with method call
    let src9 = 'data.filter(x).map(y).len'
    print("--- Test 9: method chain ---")
    let toks9 = tokenize(src9)
    let prog9 = parse_program(toks9)
    print_program(prog9)

    // Test 10: If expression
    let src10 = 'if x > 0 { print(x) } else { print(0) }'
    print("--- Test 10: if/else ---")
    let toks10 = tokenize(src10)
    let prog10 = parse_program(toks10)
    print_program(prog10)

    // Test 11: Multiple statements
    let src11 = 'let a = 1\nlet b = 2\nlet c = a + b'
    print("--- Test 11: multiple stmts ---")
    let toks11 = tokenize(src11)
    let prog11 = parse_program(toks11)
    print_program(prog11)

    // Test 12: Unary operators
    let src12 = 'let neg = -42'
    print("--- Test 12: unary ---")
    let toks12 = tokenize(src12)
    let prog12 = parse_program(toks12)
    print_program(prog12)

    // Test 13: Index access
    let src13 = 'items[0]'
    print("--- Test 13: index ---")
    let toks13 = tokenize(src13)
    let prog13 = parse_program(toks13)
    print_program(prog13)

    print("")
    print("=== Parser tests complete ===")
}
