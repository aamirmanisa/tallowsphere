//! SMT-LIB2 verification condition export from contract annotations.
//!
//! Translates `@requires`, `@ensures`, and `@invariant` contract expressions
//! into SMT-LIB2 format suitable for Z3/CVC5 verification.
//!
//! The approach: given preconditions P and postcondition Q, we assert P and
//! (not Q). If the solver returns `unsat`, Q always holds given P.
//! If `sat`, a counterexample exists.

use crate::ast::*;

// ── Result type ────────────────────────────────────────────────────────────

/// Result of SMT-LIB2 export for a single function.
pub struct SmtResult {
    pub function_name: String,
    pub smt_text: String,
    pub skipped: bool,
    pub skip_reason: Option<String>,
}

// ── Type mapping ───────────────────────────────────────────────────────────

/// Map a Tallow type expression to an SMT-LIB2 sort.
/// Returns None for types that cannot be represented in SMT.
pub fn tallow_type_to_smt_sort(ty: &TypeExpr) -> Option<&'static str> {
    match &ty.kind {
        TypeExprKind::Named(name) => match name.as_str() {
            "i8" | "i16" | "i32" | "i64" | "i128" | "u8" | "u16" | "u32" | "u64" | "u128"
            | "isize" | "usize" => Some("Int"),
            "f32" | "f64" => Some("Real"),
            "bool" => Some("Bool"),
            _ => None,
        },
        _ => None,
    }
}

// ── Expression translation ─────────────────────────────────────────────────

/// Convert a Tallow AST expression to an SMT-LIB2 S-expression string.
pub fn expr_to_smt(expr: &Expr) -> String {
    match &expr.kind {
        ExprKind::IntLit(n) => {
            if *n < 0 {
                format!("(- {})", n.unsigned_abs())
            } else {
                format!("{}", n)
            }
        }
        ExprKind::FloatLit(f) => format!("{:.6}", f),
        ExprKind::BoolLit(b) => {
            if *b {
                "true".to_string()
            } else {
                "false".to_string()
            }
        }
        ExprKind::Ident(name) => name.clone(),
        ExprKind::Binary { op, left, right } => {
            let smt_op = match op {
                BinOp::Add => "+",
                BinOp::Sub => "-",
                BinOp::Mul => "*",
                BinOp::Div => "div",
                BinOp::Mod => "mod",
                BinOp::Eq => "=",
                BinOp::Neq => "distinct",
                BinOp::Lt => "<",
                BinOp::Gt => ">",
                BinOp::Lte => "<=",
                BinOp::Gte => ">=",
                BinOp::And => "and",
                BinOp::Or => "or",
                _ => "unsupported",
            };
            let l = expr_to_smt(left);
            let r = expr_to_smt(right);
            format!("({} {} {})", smt_op, l, r)
        }
        ExprKind::Unary { op, operand } => {
            let smt_op = match op {
                UnOp::Neg => "-",
                UnOp::Not => "not",
                UnOp::BitNot => "unsupported",
                UnOp::Deref => "unsupported",
            };
            let o = expr_to_smt(operand);
            format!("({} {})", smt_op, o)
        }
        ExprKind::FieldAccess { object, field } => {
            if let ExprKind::Ident(name) = &object.kind {
                if name == "self" {
                    return field.clone();
                }
            }
            let obj = expr_to_smt(object);
            format!("{}_{}", obj, field)
        }
        ExprKind::MethodCall { .. } | ExprKind::Call { .. } | ExprKind::Index { .. } => {
            "unsupported".to_string()
        }
        ExprKind::DotIdent(_) => "unsupported".to_string(),
        ExprKind::Nil => "false".to_string(),
        // Fallback for any other expression kind
        _ => "unsupported".to_string(),
    }
}

// ── Single function SMT generation ─────────────────────────────────────────

/// Generate SMT-LIB2 verification conditions for a single function.
///
/// `struct_fields` is provided when the function is an impl method:
/// each entry is `(field_name, smt_sort)` for fields with SMT-exportable types.
pub fn generate_smt(
    f: &FnDecl,
    struct_fields: Option<&[(String, &str)]>,
) -> SmtResult {
    // Collect contract annotations
    let mut requires: Vec<&Expr> = Vec::new();
    let mut ensures: Vec<&Expr> = Vec::new();
    let mut invariants: Vec<&Expr> = Vec::new();

    for ann in &f.annotations {
        match ann.name.as_str() {
            "requires" => {
                if let Some(arg) = ann.args.first() {
                    if arg.name.is_empty() {
                        requires.push(&arg.value);
                    }
                }
            }
            "ensures" => {
                if let Some(arg) = ann.args.first() {
                    if arg.name.is_empty() {
                        ensures.push(&arg.value);
                    }
                }
            }
            "invariant" => {
                if let Some(arg) = ann.args.first() {
                    if arg.name.is_empty() {
                        invariants.push(&arg.value);
                    }
                }
            }
            _ => {}
        }
    }

    // No contracts → skip
    if requires.is_empty() && ensures.is_empty() && invariants.is_empty() {
        return SmtResult {
            function_name: f.name.clone(),
            smt_text: String::new(),
            skipped: true,
            skip_reason: Some("no contracts".to_string()),
        };
    }

    // Check that at least one param has an SMT-exportable type.
    // If ALL params are unsupported, skip.
    let supported_params: Vec<(&str, &str)> = f
        .params
        .iter()
        .filter_map(|p| {
            tallow_type_to_smt_sort(&p.ty).map(|sort| (p.name.as_str(), sort))
        })
        .collect();

    if supported_params.is_empty() && !f.params.is_empty() {
        return SmtResult {
            function_name: f.name.clone(),
            smt_text: String::new(),
            skipped: true,
            skip_reason: Some("all parameter types unsupported for SMT".to_string()),
        };
    }

    // Determine logic: any float → QF_LIRA, else QF_LIA
    let has_real = f.params.iter().any(|p| {
        matches!(&p.ty.kind, TypeExprKind::Named(n) if n == "f32" || n == "f64")
    }) || f
        .return_type
        .as_ref()
        .map(|rt| matches!(&rt.kind, TypeExprKind::Named(n) if n == "f32" || n == "f64"))
        .unwrap_or(false)
        || struct_fields
            .map(|sf| sf.iter().any(|(_, sort)| *sort == "Real"))
            .unwrap_or(false);

    let logic = if has_real { "QF_LIRA" } else { "QF_LIA" };

    // Build SMT text
    let mut lines: Vec<String> = Vec::new();

    lines.push(format!(
        "; Verification conditions for function: {}",
        f.name
    ));
    lines.push("; Generated by Tallow compiler".to_string());
    lines.push(format!("(set-logic {})", logic));

    // Declare params
    for (name, sort) in &supported_params {
        lines.push(format!("(declare-const {} {})", name, sort));
    }

    // Declare result if return type is supported
    if let Some(ref rt) = f.return_type {
        if let Some(sort) = tallow_type_to_smt_sort(rt) {
            lines.push(format!("(declare-const result {})", sort));
        }
    }

    // Declare struct fields
    if let Some(fields) = struct_fields {
        for (field_name, sort) in fields {
            lines.push(format!("(declare-const {} {})", field_name, sort));
        }
    }

    // Assert preconditions
    for req in &requires {
        lines.push("; Precondition".to_string());
        lines.push(format!("(assert {})", expr_to_smt(req)));
    }

    // Assert negated postconditions
    for ens in &ensures {
        lines.push("; Postcondition (negated)".to_string());
        lines.push(format!("(assert (not {}))", expr_to_smt(ens)));
    }

    // Assert negated invariants
    for inv in &invariants {
        lines.push("; Invariant (negated)".to_string());
        lines.push(format!("(assert (not {}))", expr_to_smt(inv)));
    }

    lines.push("(check-sat)".to_string());
    lines.push(
        "; unsat = postcondition always holds given precondition".to_string(),
    );
    lines.push("; sat = counterexample exists".to_string());
    lines.push("(get-model)".to_string());

    SmtResult {
        function_name: f.name.clone(),
        smt_text: lines.join("\n"),
        skipped: false,
        skip_reason: None,
    }
}

// ── Program-level SMT generation ───────────────────────────────────────────

/// Generate SMT-LIB2 verification conditions for all functions in a program.
///
/// Returns all results including skipped functions (caller can filter).
pub fn generate_all_smt(program: &Program) -> Vec<SmtResult> {
    let mut results = Vec::new();

    // Collect struct field info for impl methods
    let mut struct_field_map: std::collections::HashMap<String, Vec<(String, &str)>> =
        std::collections::HashMap::new();

    for item in &program.items {
        if let Item::Struct(s) = item {
            let fields: Vec<(String, &str)> = s
                .fields
                .iter()
                .filter_map(|field| {
                    tallow_type_to_smt_sort(&field.ty)
                        .map(|sort| (field.name.clone(), sort))
                })
                .collect();
            if !fields.is_empty() {
                struct_field_map.insert(s.name.clone(), fields);
            }
        }
    }

    for item in &program.items {
        match item {
            Item::Fn(f) => {
                results.push(generate_smt(f, None));
            }
            Item::Impl(imp) => {
                let fields = struct_field_map.get(&imp.target);
                let field_refs: Option<Vec<(String, &str)>> = fields.map(|f| {
                    f.iter()
                        .map(|(name, sort)| (name.clone(), *sort))
                        .collect()
                });
                let field_slice: Option<Vec<(String, &str)>> = field_refs;
                for method in &imp.methods {
                    let sf: Option<&[(String, &str)]> =
                        field_slice.as_deref();
                    results.push(generate_smt(method, sf));
                }
            }
            _ => {}
        }
    }

    results
}

// ── Feature 7: ProVerif protocol verification export ───────────────────────

/// Check if a function declaration has a given annotation.
fn has_annotation(f: &FnDecl, name: &str) -> bool {
    f.annotations.iter().any(|a| a.name == name)
}

/// Extract a string annotation argument by name.
/// Returns `None` if the annotation or argument is absent.
fn annotation_string_arg<'a>(f: &'a FnDecl, ann_name: &str, arg_name: &str) -> Option<String> {
    f.annotations.iter().find(|a| a.name == ann_name).and_then(|ann| {
        ann.args.iter().find(|a| a.name == arg_name).map(|a| {
            match &a.value.kind {
                ExprKind::StringLit(s) => s.clone(),
                ExprKind::Ident(s) => s.clone(),
                ExprKind::FieldAccess { field, .. } => field.clone(),
                other => format!("{other:?}"),
            }
        })
    })
}

/// Generate a ProVerif process algebra model from `@legal` and `@agent_task`
/// annotations in a Tallow program.
///
/// ProVerif is a formal security protocol verifier. The generated model
/// encodes each `@agent_task` function as a parallel process and each
/// `@legal`-annotated function as a protocol step. This allows verification
/// of non-interference, authentication, and secrecy properties.
///
/// Output can be fed directly to ProVerif:
/// ```
/// proverif model.pv
/// ```
pub fn export_proverif(program: &Program) -> String {
    let mut out = String::new();

    out.push_str("(* ProVerif model generated by Tallow compiler *)\n");
    out.push_str("(* https://proverif.inria.fr/ *)\n\n");

    // Collect all functions (top-level + impl methods)
    let mut all_fns: Vec<&FnDecl> = Vec::new();
    for item in &program.items {
        match item {
            Item::Fn(f) => all_fns.push(f),
            Item::Impl(imp) => {
                for method in &imp.methods {
                    all_fns.push(method);
                }
            }
            _ => {}
        }
    }

    // ── Type declarations ──────────────────────────────────────────────────
    out.push_str("(* Channel and type declarations *)\n");
    out.push_str("free c: channel.\n");
    out.push_str("free priv_c: channel [private].\n\n");
    out.push_str("type key.\n");
    out.push_str("type nonce.\n");
    out.push_str("type agent_id.\n\n");

    // ── Cryptographic function symbols ─────────────────────────────────────
    out.push_str("(* Cryptographic function symbols *)\n");
    out.push_str("fun encrypt(bitstring, key): bitstring.\n");
    out.push_str("fun decrypt(bitstring, key): bitstring\n");
    out.push_str("    reduc forall m: bitstring, k: key; decrypt(encrypt(m, k), k) = m.\n");
    out.push_str("fun sign(bitstring, key): bitstring.\n");
    out.push_str("fun pk(key): key.\n\n");

    // ── Events from @legal annotations ────────────────────────────────────
    let legal_fns: Vec<&&FnDecl> = all_fns.iter()
        .filter(|f| has_annotation(f, "legal"))
        .collect();

    if !legal_fns.is_empty() {
        out.push_str("(* Events from @legal annotations *)\n");
        for f in &legal_fns {
            let purpose = annotation_string_arg(f, "legal", "purpose")
                .unwrap_or_else(|| "unspecified".into());
            let basis = annotation_string_arg(f, "legal", "basis")
                .unwrap_or_else(|| "unknown".into());
            out.push_str(&format!(
                "event DataAccess_{}(bitstring). (* purpose: {}, basis: {} *)\n",
                f.name, purpose, basis
            ));
        }
        out.push('\n');
    }

    // ── Queries: verify secrecy and authentication ─────────────────────────
    out.push_str("(* Secrecy and authentication queries *)\n");
    out.push_str("query attacker(new secret_data).\n");
    for f in &legal_fns {
        out.push_str(&format!(
            "query event(DataAccess_{}(_)).\n",
            f.name
        ));
    }
    out.push('\n');

    // ── Agent processes from @agent_task annotations ───────────────────────
    let agent_fns: Vec<&&FnDecl> = all_fns.iter()
        .filter(|f| has_annotation(f, "agent_task"))
        .collect();

    if !agent_fns.is_empty() {
        out.push_str("(* Agent processes from @agent_task annotations *)\n");
        for f in &agent_fns {
            let timeout = annotation_string_arg(f, "agent_task", "timeout")
                .unwrap_or_else(|| "60s".into());
            let can_write = annotation_string_arg(f, "agent_task", "can_write")
                .unwrap_or_else(|| "false".into());
            out.push_str(&format!("let Agent_{}() =\n", f.name));
            out.push_str("  new session_key: key;\n");
            out.push_str("  new nonce: nonce;\n");
            out.push_str("  in(c, data: bitstring);\n");
            out.push_str("  let processed = encrypt(data, session_key) in\n");
            if legal_fns.iter().any(|lf| lf.name == f.name) {
                out.push_str(&format!("  event DataAccess_{}(data);\n", f.name));
            }
            out.push_str("  out(priv_c, processed).\n");
            out.push_str(&format!(
                "  (* timeout: {timeout}, can_write: {can_write} *)\n\n"
            ));
        }
    }

    // Functions with @legal but not @agent_task → protocol steps
    let legal_only_fns: Vec<&&FnDecl> = legal_fns.iter()
        .copied()
        .filter(|f| !has_annotation(f, "agent_task"))
        .collect();

    if !legal_only_fns.is_empty() {
        out.push_str("(* Protocol steps from @legal-annotated functions *)\n");
        for f in &legal_only_fns {
            let purpose = annotation_string_arg(f, "legal", "purpose")
                .unwrap_or_else(|| "data_access".into());
            out.push_str(&format!("let Step_{}() =\n", f.name));
            out.push_str("  in(c, data: bitstring);\n");
            out.push_str(&format!("  event DataAccess_{}(data);\n", f.name));
            out.push_str("  out(c, data).\n");
            out.push_str(&format!("  (* purpose: {purpose} *)\n\n"));
        }
    }

    // ── Main parallel composition ──────────────────────────────────────────
    out.push_str("(* Main process — parallel composition of all agents and steps *)\n");
    out.push_str("process\n");

    let mut processes: Vec<String> = Vec::new();
    for f in &agent_fns {
        processes.push(format!("  !Agent_{}()", f.name));
    }
    for f in &legal_only_fns {
        processes.push(format!("  !Step_{}()", f.name));
    }

    if processes.is_empty() {
        out.push_str("  0\n");
    } else {
        out.push_str(&processes.join("\n| "));
        out.push('\n');
    }

    out
}

// ── Tests ──────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::lexer;
    use crate::parser::Parser;

    /// Helper: parse source code and return the Program AST.
    fn parse_nx(src: &str) -> Program {
        let (tokens, errors) = lexer::tokenize(src);
        assert!(
            errors.is_empty(),
            "lex errors: {:?}",
            errors
        );
        Parser::parse(tokens).expect("parse error")
    }

    /// Helper: get the first FnDecl from a program.
    fn first_fn(program: &Program) -> &FnDecl {
        for item in &program.items {
            if let Item::Fn(f) = item {
                return f;
            }
        }
        panic!("no function found in program");
    }

    // ── 1. test_int_params_to_smt ──────────────────────────────────────────

    #[test]
    fn test_int_params_to_smt() {
        let src = r#"
@requires(x > 0)
fn foo(x: i32) -> i32 {
    x
}
"#;
        let prog = parse_nx(src);
        let f = first_fn(&prog);
        let result = generate_smt(f, None);
        assert!(!result.skipped);
        assert!(result.smt_text.contains("(declare-const x Int)"));
        assert!(result.smt_text.contains("QF_LIA"));
    }

    // ── 2. test_float_params_to_smt ────────────────────────────────────────

    #[test]
    fn test_float_params_to_smt() {
        let src = r#"
@requires(x > 0.0)
fn foo(x: f64) -> f64 {
    x
}
"#;
        let prog = parse_nx(src);
        let f = first_fn(&prog);
        let result = generate_smt(f, None);
        assert!(!result.skipped);
        assert!(result.smt_text.contains("(declare-const x Real)"));
        assert!(result.smt_text.contains("QF_LIRA"));
    }

    // ── 3. test_bool_params_to_smt ─────────────────────────────────────────

    #[test]
    fn test_bool_params_to_smt() {
        let src = r#"
@requires(flag)
fn foo(flag: bool) -> bool {
    flag
}
"#;
        let prog = parse_nx(src);
        let f = first_fn(&prog);
        let result = generate_smt(f, None);
        assert!(!result.skipped);
        assert!(result.smt_text.contains("(declare-const flag Bool)"));
    }

    // ── 4. test_requires_assertion ─────────────────────────────────────────

    #[test]
    fn test_requires_assertion() {
        let src = r#"
@requires(x > 0)
fn foo(x: i32) -> i32 {
    x
}
"#;
        let prog = parse_nx(src);
        let f = first_fn(&prog);
        let result = generate_smt(f, None);
        assert!(!result.skipped);
        assert!(
            result.smt_text.contains("(assert (> x 0))"),
            "expected (assert (> x 0)) in:\n{}",
            result.smt_text
        );
    }

    // ── 5. test_ensures_negated ────────────────────────────────────────────

    #[test]
    fn test_ensures_negated() {
        let src = r#"
@ensures(result >= 0)
fn foo(x: i32) -> i32 {
    x
}
"#;
        let prog = parse_nx(src);
        let f = first_fn(&prog);
        let result = generate_smt(f, None);
        assert!(!result.skipped);
        assert!(
            result.smt_text.contains("(assert (not (>= result 0)))"),
            "expected negated ensures in:\n{}",
            result.smt_text
        );
    }

    // ── 6. test_binary_ops_add_sub_mul ─────────────────────────────────────

    #[test]
    fn test_binary_ops_add_sub_mul() {
        let src = r#"
@requires(a + b > 0)
@ensures(result > a - b)
fn foo(a: i32, b: i32) -> i32 {
    a * b
}
"#;
        let prog = parse_nx(src);
        let f = first_fn(&prog);
        let result = generate_smt(f, None);
        assert!(!result.skipped);
        assert!(result.smt_text.contains("(+ a b)"));
        assert!(result.smt_text.contains("(- a b)"));
    }

    // ── 7. test_binary_ops_comparison ──────────────────────────────────────

    #[test]
    fn test_binary_ops_comparison() {
        let src = r#"
@requires(a == b)
@ensures(result != 0)
fn foo(a: i32, b: i32) -> i32 {
    a
}
"#;
        let prog = parse_nx(src);
        let f = first_fn(&prog);
        let result = generate_smt(f, None);
        assert!(!result.skipped);
        assert!(
            result.smt_text.contains("(= a b)"),
            "expected (= a b) in:\n{}",
            result.smt_text
        );
        assert!(
            result.smt_text.contains("(distinct result 0)"),
            "expected (distinct result 0) in:\n{}",
            result.smt_text
        );
    }

    // ── 8. test_binary_ops_logic ───────────────────────────────────────────

    #[test]
    fn test_binary_ops_logic() {
        let src = r#"
@requires(a > 0 && b > 0)
fn foo(a: i32, b: i32) -> i32 {
    a
}
"#;
        let prog = parse_nx(src);
        let f = first_fn(&prog);
        let result = generate_smt(f, None);
        assert!(!result.skipped);
        assert!(
            result.smt_text.contains("(and (> a 0) (> b 0))"),
            "expected (and ...) in:\n{}",
            result.smt_text
        );
    }

    // ── 9. test_unary_neg ──────────────────────────────────────────────────

    #[test]
    fn test_unary_neg() {
        let src = r#"
@requires(x > 0)
@ensures(result == -x)
fn negate(x: i32) -> i32 {
    0 - x
}
"#;
        let prog = parse_nx(src);
        let f = first_fn(&prog);
        let result = generate_smt(f, None);
        assert!(!result.skipped);
        // The parser may parse `-x` as Unary(Neg, x) producing `(- x)`
        assert!(
            result.smt_text.contains("(- x)"),
            "expected (- x) in:\n{}",
            result.smt_text
        );
    }

    // ── 10. test_unary_not ─────────────────────────────────────────────────

    #[test]
    fn test_unary_not() {
        // Test expr_to_smt directly for unary not, since the annotation parser
        // doesn't support `!` as leading token in annotation args.
        use crate::lexer::Span;
        let expr = Expr::new(
            ExprKind::Unary {
                op: UnOp::Not,
                operand: Box::new(Expr::new(
                    ExprKind::Ident("done".to_string()),
                    Span::new(0, 0),
                )),
            },
            Span::new(0, 0),
        );
        let smt = expr_to_smt(&expr);
        assert_eq!(smt, "(not done)");
    }

    // ── 11. test_nested_expr ───────────────────────────────────────────────

    #[test]
    fn test_nested_expr() {
        // Parser handles `a + b > c` as `a + (b > c)` or `(a + b) > c`
        // depending on precedence. Test with direct AST construction.
        use crate::lexer::Span;
        let expr = Expr::new(
            ExprKind::Binary {
                op: BinOp::Gt,
                left: Box::new(Expr::new(
                    ExprKind::Binary {
                        op: BinOp::Add,
                        left: Box::new(Expr::new(
                            ExprKind::Ident("a".to_string()),
                            Span::new(0, 0),
                        )),
                        right: Box::new(Expr::new(
                            ExprKind::Ident("b".to_string()),
                            Span::new(0, 0),
                        )),
                    },
                    Span::new(0, 0),
                )),
                right: Box::new(Expr::new(
                    ExprKind::Ident("c".to_string()),
                    Span::new(0, 0),
                )),
            },
            Span::new(0, 0),
        );
        let smt = expr_to_smt(&expr);
        assert_eq!(smt, "(> (+ a b) c)");
    }

    // ── 12. test_self_field_access ─────────────────────────────────────────

    #[test]
    fn test_self_field_access() {
        // Test expr_to_smt for self.field access pattern directly via AST
        use crate::lexer::Span;
        let expr = Expr::new(
            ExprKind::FieldAccess {
                object: Box::new(Expr::new(
                    ExprKind::Ident("self".to_string()),
                    Span::new(0, 0),
                )),
                field: "count".to_string(),
            },
            Span::new(0, 0),
        );
        let smt = expr_to_smt(&expr);
        assert_eq!(smt, "count", "self.count should produce 'count'");

        // Also test non-self field access
        let expr2 = Expr::new(
            ExprKind::FieldAccess {
                object: Box::new(Expr::new(
                    ExprKind::Ident("obj".to_string()),
                    Span::new(0, 0),
                )),
                field: "value".to_string(),
            },
            Span::new(0, 0),
        );
        let smt2 = expr_to_smt(&expr2);
        assert_eq!(smt2, "obj_value", "obj.value should produce 'obj_value'");
    }

    // ── 13. test_no_contracts_skipped ──────────────────────────────────────

    #[test]
    fn test_no_contracts_skipped() {
        let src = r#"
fn foo(x: i32) -> i32 {
    x + 1
}
"#;
        let prog = parse_nx(src);
        let f = first_fn(&prog);
        let result = generate_smt(f, None);
        assert!(result.skipped);
        assert_eq!(result.skip_reason.as_deref(), Some("no contracts"));
    }

    // ── 14. test_string_param_skip ─────────────────────────────────────────

    #[test]
    fn test_string_param_skip() {
        let src = r#"
@requires(true)
fn foo(s: String) -> String {
    s
}
"#;
        let prog = parse_nx(src);
        let f = first_fn(&prog);
        let result = generate_smt(f, None);
        assert!(result.skipped);
        assert_eq!(
            result.skip_reason.as_deref(),
            Some("all parameter types unsupported for SMT")
        );
    }

    // ── 15. test_negative_int_literal ──────────────────────────────────────

    #[test]
    fn test_negative_int_literal() {
        let src = r#"
@requires(x > -1)
fn foo(x: i32) -> i32 {
    x
}
"#;
        let prog = parse_nx(src);
        let f = first_fn(&prog);
        let result = generate_smt(f, None);
        assert!(!result.skipped);
        // `-1` is parsed as Unary(Neg, IntLit(1)) → (- 1)
        assert!(
            result.smt_text.contains("(- 1)"),
            "expected (- 1) in:\n{}",
            result.smt_text
        );
    }

    // ── 16. test_multiple_requires ─────────────────────────────────────────

    #[test]
    fn test_multiple_requires() {
        let src = r#"
@requires(x > 0)
@requires(x < 100)
fn foo(x: i32) -> i32 {
    x
}
"#;
        let prog = parse_nx(src);
        let f = first_fn(&prog);
        let result = generate_smt(f, None);
        assert!(!result.skipped);
        // Both preconditions should be asserted
        assert!(
            result.smt_text.contains("(assert (> x 0))"),
            "expected first requires in:\n{}",
            result.smt_text
        );
        assert!(
            result.smt_text.contains("(assert (< x 100))"),
            "expected second requires in:\n{}",
            result.smt_text
        );
        // Count "; Precondition" occurrences
        let precondition_count = result
            .smt_text
            .matches("; Precondition")
            .count();
        assert_eq!(precondition_count, 2);
    }

    // ── 17. test_generate_all_smt ──────────────────────────────────────────

    #[test]
    fn test_generate_all_smt() {
        let src = r#"
@requires(x > 0)
@ensures(result >= 0)
fn contracted(x: i32) -> i32 {
    x
}

fn uncontracted(y: i32) -> i32 {
    y + 1
}

@ensures(result > 0)
fn also_contracted(a: i32, b: i32) -> i32 {
    a + b
}
"#;
        let prog = parse_nx(src);
        let results = generate_all_smt(&prog);

        // Should have 3 results total (including skipped)
        assert_eq!(results.len(), 3);

        // First: contracted (not skipped)
        assert_eq!(results[0].function_name, "contracted");
        assert!(!results[0].skipped);

        // Second: uncontracted (skipped)
        assert_eq!(results[1].function_name, "uncontracted");
        assert!(results[1].skipped);

        // Third: also_contracted (not skipped)
        assert_eq!(results[2].function_name, "also_contracted");
        assert!(!results[2].skipped);
    }

    // ── 18. test_check_sat_and_get_model_present ───────────────────────────

    #[test]
    fn test_check_sat_and_get_model_present() {
        let src = r#"
@requires(x > 0)
fn foo(x: i32) -> i32 {
    x
}
"#;
        let prog = parse_nx(src);
        let f = first_fn(&prog);
        let result = generate_smt(f, None);
        assert!(!result.skipped);
        assert!(result.smt_text.contains("(check-sat)"));
        assert!(result.smt_text.contains("(get-model)"));
    }

    // ── 19. test_return_type_declared ──────────────────────────────────────

    #[test]
    fn test_return_type_declared() {
        let src = r#"
@ensures(result > 0)
fn foo(x: i32) -> i32 {
    x
}
"#;
        let prog = parse_nx(src);
        let f = first_fn(&prog);
        let result = generate_smt(f, None);
        assert!(!result.skipped);
        assert!(
            result.smt_text.contains("(declare-const result Int)"),
            "expected result declaration in:\n{}",
            result.smt_text
        );
    }

    // ── 20. test_impl_with_struct_fields ───────────────────────────────────

    #[test]
    fn test_impl_with_struct_fields() {
        // Test generate_all_smt with an impl block that has struct fields
        let src = r#"
struct Gauge {
    value: f64,
    min: f64,
    max: f64
}
impl Gauge {
    @requires(v >= 0.0)
    fn set(v: f64) -> f64 {
        v
    }
}
"#;
        let prog = parse_nx(src);
        let results = generate_all_smt(&prog);

        // Find the non-skipped result
        let smt = results.iter().find(|r| !r.skipped).expect("no SMT result");
        assert_eq!(smt.function_name, "set");
        assert!(smt.smt_text.contains("QF_LIRA")); // has f64 → Real
        // Struct fields should be declared
        assert!(
            smt.smt_text.contains("(declare-const value Real)"),
            "expected struct field 'value' in:\n{}",
            smt.smt_text
        );
        assert!(
            smt.smt_text.contains("(declare-const min Real)"),
            "expected struct field 'min' in:\n{}",
            smt.smt_text
        );
        assert!(
            smt.smt_text.contains("(declare-const max Real)"),
            "expected struct field 'max' in:\n{}",
            smt.smt_text
        );
    }

    // ── Feature 7: ProVerif export tests ──────────────────────────────────

    #[test]
    fn test_proverif_empty_program() {
        let prog = parse_nx("fn no_annotations() { }");
        let pv = export_proverif(&prog);
        assert!(pv.contains("ProVerif model generated by Tallow compiler"));
        assert!(pv.contains("free c: channel."));
        // No agents → main process should be "0"
        assert!(pv.contains("process\n  0"), "empty program should emit '0' process, got:\n{pv}");
    }

    #[test]
    fn test_proverif_agent_task_generates_process() {
        let src = r#"
@agent_task(id: task_id, timeout: 60.seconds, max_requests: 100, can_write: false)
@legal(basis: .public_data, purpose: "market research")
async fn research_prices(query: String) -> String {
    "result"
}
"#;
        let prog = parse_nx(src);
        let pv = export_proverif(&prog);
        assert!(pv.contains("let Agent_research_prices()"), "should emit agent process");
        assert!(pv.contains("event DataAccess_research_prices(data)"), "should emit event");
        assert!(pv.contains("!Agent_research_prices()"), "should appear in main process");
    }

    #[test]
    fn test_proverif_legal_only_generates_step() {
        let src = r#"
@legal(basis: .public_data, purpose: "price monitoring", personal_data: false)
fn scrape_prices(urls: []String) -> []String {
    urls
}
"#;
        let prog = parse_nx(src);
        let pv = export_proverif(&prog);
        assert!(pv.contains("event(DataAccess_scrape_prices(_))"), "should emit query");
        assert!(pv.contains("let Step_scrape_prices()"), "should emit step process");
        assert!(pv.contains("!Step_scrape_prices()"), "should appear in main process");
        // Verify purpose annotation is preserved
        assert!(pv.contains("price monitoring"), "purpose should appear in comment");
    }
}
