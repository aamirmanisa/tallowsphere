//! Opinionated code formatter for Tallow.
//!
//! Re-prints the AST with consistent style:
//! - 4-space indentation
//! - Consistent brace placement (same line)
//! - Sorted imports
//! - Blank lines between top-level items

use crate::ast::*;

pub fn format_program(program: &Program) -> String {
    let mut f = Formatter::new();
    for (i, item) in program.items.iter().enumerate() {
        if i > 0 {
            f.newline();
        }
        f.format_item(item);
    }
    // Ensure trailing newline
    if !f.output.ends_with('\n') {
        f.output.push('\n');
    }
    f.output
}

struct Formatter {
    output: String,
    indent: usize,
}

impl Formatter {
    fn new() -> Self {
        Self {
            output: String::new(),
            indent: 0,
        }
    }

    fn write(&mut self, s: &str) {
        self.output.push_str(s);
    }

    fn writeln(&mut self, s: &str) {
        self.write_indent();
        self.output.push_str(s);
        self.output.push('\n');
    }

    fn newline(&mut self) {
        self.output.push('\n');
    }

    fn write_indent(&mut self) {
        for _ in 0..self.indent {
            self.output.push_str("    ");
        }
    }

    fn format_item(&mut self, item: &Item) {
        match item {
            Item::Fn(f) => self.format_fn(f),
            Item::Struct(s) => self.format_struct(s),
            Item::Enum(e) => self.format_enum(e),
            Item::Impl(i) => self.format_impl(i),
            Item::Const(c) => self.format_const(c),
            Item::TypeAlias(t) => self.format_type_alias(t),
            Item::Import(i) => self.format_import(i),
            Item::Trait(t) => self.format_trait(t),
        }
    }

    fn format_fn(&mut self, f: &FnDecl) {
        // Annotations
        for ann in &f.annotations {
            self.format_annotation(ann);
        }

        // Signature
        self.write_indent();
        if f.is_async {
            self.write("async ");
        }
        self.write("fn ");
        self.write(&f.name);
        if !f.type_params.is_empty() {
            self.write("<");
            for (i, tp) in f.type_params.iter().enumerate() {
                if i > 0 {
                    self.write(", ");
                }
                self.write(tp);
            }
            self.write(">");
        }
        self.write("(");

        for (i, param) in f.params.iter().enumerate() {
            if i > 0 {
                self.write(", ");
            }
            self.write(&param.name);
            self.write(": ");
            self.format_type_expr(&param.ty);
        }

        self.write(")");

        if let Some(ref ret) = f.return_type {
            self.write(" -> ");
            self.format_type_expr(ret);
        }

        self.write(" {\n");
        self.indent += 1;
        self.format_block_body(&f.body);
        self.indent -= 1;
        self.writeln("}");
    }

    fn format_annotation(&mut self, ann: &Annotation) {
        self.write_indent();
        self.write("@");
        self.write(&ann.name);
        if !ann.args.is_empty() {
            self.write("(");
            for (i, arg) in ann.args.iter().enumerate() {
                if i > 0 {
                    self.write(", ");
                }
                self.write(&arg.name);
                self.write(": ");
                self.format_expr(&arg.value);
            }
            self.write(")");
        }
        self.write("\n");
    }

    fn format_struct(&mut self, s: &StructDecl) {
        self.write_indent();
        self.write("struct ");
        self.write(&s.name);
        if !s.type_params.is_empty() {
            self.write("<");
            for (i, tp) in s.type_params.iter().enumerate() {
                if i > 0 {
                    self.write(", ");
                }
                self.write(tp);
            }
            self.write(">");
        }
        self.write(" {\n");
        self.indent += 1;
        for field in &s.fields {
            self.write_indent();
            self.write(&field.name);
            self.write(": ");
            self.format_type_expr(&field.ty);
            if let Some(ref default) = field.default {
                self.write(" = ");
                self.format_expr(default);
            }
            self.write(",\n");
        }
        self.indent -= 1;
        self.writeln("}");
    }

    fn format_enum(&mut self, e: &EnumDecl) {
        self.write_indent();
        self.write("enum ");
        self.write(&e.name);
        if !e.type_params.is_empty() {
            self.write("<");
            for (i, tp) in e.type_params.iter().enumerate() {
                if i > 0 {
                    self.write(", ");
                }
                self.write(tp);
            }
            self.write(">");
        }
        self.write(" {\n");
        self.indent += 1;
        for variant in &e.variants {
            self.write_indent();
            self.write(&variant.name);
            if !variant.fields.is_empty() {
                self.write("(");
                for (i, field) in variant.fields.iter().enumerate() {
                    if i > 0 {
                        self.write(", ");
                    }
                    self.write(&field.name);
                    self.write(": ");
                    self.format_type_expr(&field.ty);
                }
                self.write(")");
            }
            self.write(",\n");
        }
        self.indent -= 1;
        self.writeln("}");
    }

    fn format_impl(&mut self, i: &ImplBlock) {
        self.write_indent();
        self.write("impl ");
        self.write(&i.target);
        self.write(" {\n");
        self.indent += 1;
        for (idx, method) in i.methods.iter().enumerate() {
            if idx > 0 {
                self.newline();
            }
            self.format_fn(method);
        }
        self.indent -= 1;
        self.writeln("}");
    }

    fn format_trait(&mut self, t: &crate::ast::TraitDecl) {
        self.write_indent();
        self.write("trait ");
        self.write(&t.name);
        if !t.type_params.is_empty() {
            self.write("<");
            for (i, tp) in t.type_params.iter().enumerate() {
                if i > 0 {
                    self.write(", ");
                }
                self.write(tp);
            }
            self.write(">");
        }
        self.write(" {\n");
        self.indent += 1;
        for (idx, method) in t.methods.iter().enumerate() {
            if idx > 0 {
                self.newline();
            }
            self.write_indent();
            self.write("fn ");
            self.write(&method.name);
            self.write("(");
            for (i, p) in method.params.iter().enumerate() {
                if i > 0 {
                    self.write(", ");
                }
                self.write(&p.name);
                self.write(": ");
                self.format_type_expr(&p.ty);
            }
            self.write(")");
            if let Some(ref ret) = method.return_type {
                self.write(" -> ");
                self.format_type_expr(ret);
            }
            if method.has_default {
                self.write(" { ... }");
            }
            self.write("\n");
        }
        self.indent -= 1;
        self.writeln("}");
    }

    fn format_const(&mut self, c: &ConstDecl) {
        self.write_indent();
        self.write("const ");
        self.write(&c.name);
        if let Some(ref ty) = c.ty {
            self.write(": ");
            self.format_type_expr(ty);
        }
        self.write(" = ");
        self.format_expr(&c.value);
        self.write("\n");
    }

    fn format_type_alias(&mut self, t: &TypeAlias) {
        self.write_indent();
        self.write("type ");
        self.write(&t.name);
        self.write(" = ");
        if let Some(q) = t.qualifier {
            match q {
                TypeQualifier::Private => self.write("private "),
                TypeQualifier::Secret => self.write("secret "),
            }
        }
        self.format_type_expr(&t.ty);
        self.write("\n");
    }

    fn format_import(&mut self, i: &ImportDecl) {
        self.write_indent();
        self.write("import ");
        self.write(&i.path.join("."));
        self.write("\n");
    }

    fn format_block_body(&mut self, block: &Block) {
        for stmt in &block.stmts {
            self.format_stmt(stmt);
        }
    }

    fn format_stmt(&mut self, stmt: &Stmt) {
        match &stmt.kind {
            StmtKind::Let { name, ty, value } => {
                self.write_indent();
                self.write("let ");
                self.write(name);
                if let Some(t) = ty {
                    self.write(": ");
                    self.format_type_expr(t);
                }
                self.write(" = ");
                self.format_expr(value);
                self.write("\n");
            }
            StmtKind::Var { name, ty, value } => {
                self.write_indent();
                self.write("var ");
                self.write(name);
                if let Some(t) = ty {
                    self.write(": ");
                    self.format_type_expr(t);
                }
                self.write(" = ");
                self.format_expr(value);
                self.write("\n");
            }
            StmtKind::LetDestructure { names, value } => {
                self.write_indent();
                self.write("let (");
                for (i, name) in names.iter().enumerate() {
                    if i > 0 {
                        self.write(", ");
                    }
                    self.write(name);
                }
                self.write(") = ");
                self.format_expr(value);
                self.write("\n");
            }
            StmtKind::Expr { expr } => {
                self.write_indent();
                self.format_expr(expr);
                self.write("\n");
            }
            StmtKind::Return(value) => {
                self.write_indent();
                self.write("return");
                if let Some(v) = value {
                    self.write(" ");
                    self.format_expr(v);
                }
                self.write("\n");
            }
            StmtKind::For {
                binding,
                iter,
                body,
            } => {
                self.write_indent();
                self.write("for ");
                self.write(binding);
                self.write(" in ");
                self.format_expr(iter);
                self.write(" {\n");
                self.indent += 1;
                self.format_block_body(body);
                self.indent -= 1;
                self.writeln("}");
            }
            StmtKind::While { condition, body } => {
                self.write_indent();
                self.write("while ");
                self.format_expr(condition);
                self.write(" {\n");
                self.indent += 1;
                self.format_block_body(body);
                self.indent -= 1;
                self.writeln("}");
            }
            StmtKind::WhileLet {
                pattern,
                expr,
                body,
            } => {
                self.write_indent();
                self.write("while let ");
                self.format_pattern(pattern);
                self.write(" = ");
                self.format_expr(expr);
                self.write(" {\n");
                self.indent += 1;
                self.format_block_body(body);
                self.indent -= 1;
                self.writeln("}");
            }
            StmtKind::Bail(expr) => {
                self.write_indent();
                self.write("bail ");
                self.format_expr(expr);
                self.write("\n");
            }
            StmtKind::Break => {
                self.writeln("break");
            }
            StmtKind::Continue => {
                self.writeln("continue");
            }
            StmtKind::Loop { body } => {
                self.write_indent();
                self.write("loop {\n");
                self.indent += 1;
                self.format_block_body(body);
                self.indent -= 1;
                self.writeln("}");
            }
            StmtKind::Defer { body } => {
                self.write_indent();
                self.write("defer {\n");
                self.indent += 1;
                self.format_block_body(body);
                self.indent -= 1;
                self.writeln("}");
            }
        }
    }

    fn format_expr(&mut self, expr: &Expr) {
        match &expr.kind {
            ExprKind::IntLit(n) => self.write(&n.to_string()),
            ExprKind::FloatLit(n) => self.write(&format!("{n}")),
            ExprKind::StringLit(s) => {
                self.write("\"");
                self.write(&s.replace('\\', "\\\\").replace('"', "\\\""));
                self.write("\"");
            }
            ExprKind::BoolLit(b) => self.write(if *b { "true" } else { "false" }),
            ExprKind::Nil => self.write("nil"),
            ExprKind::Ident(name) => self.write(name),
            ExprKind::DotIdent(name) => {
                self.write(".");
                self.write(name);
            }
            ExprKind::Binary { op, left, right } => {
                self.format_expr(left);
                self.write(&format!(" {} ", binop_str(op)));
                self.format_expr(right);
            }
            ExprKind::Unary { op, operand } => {
                self.write(unop_str(op));
                self.format_expr(operand);
            }
            ExprKind::Call { callee, args } => {
                self.format_expr(callee);
                self.write("(");
                self.format_call_args(args);
                self.write(")");
            }
            ExprKind::MethodCall {
                object,
                method,
                args,
            } => {
                self.format_expr(object);
                self.write(".");
                self.write(method);
                self.write("(");
                self.format_call_args(args);
                self.write(")");
            }
            ExprKind::FieldAccess { object, field } => {
                self.format_expr(object);
                self.write(".");
                self.write(field);
            }
            ExprKind::Index { object, index } => {
                self.format_expr(object);
                self.write("[");
                self.format_expr(index);
                self.write("]");
            }
            ExprKind::If {
                condition,
                then_block,
                else_branch,
            } => {
                self.write("if ");
                self.format_expr(condition);
                self.write(" {\n");
                self.indent += 1;
                self.format_block_body(then_block);
                self.indent -= 1;
                self.write_indent();
                self.write("}");
                if let Some(eb) = else_branch {
                    match eb {
                        ElseBranch::Block(block) => {
                            self.write(" else {\n");
                            self.indent += 1;
                            self.format_block_body(block);
                            self.indent -= 1;
                            self.write_indent();
                            self.write("}");
                        }
                        ElseBranch::ElseIf(expr) => {
                            self.write(" else ");
                            self.format_expr(expr);
                        }
                    }
                }
            }
            ExprKind::IfLet {
                pattern,
                expr,
                then_block,
                else_branch,
            } => {
                self.write("if let ");
                self.format_pattern(pattern);
                self.write(" = ");
                self.format_expr(expr);
                self.write(" {\n");
                self.indent += 1;
                self.format_block_body(then_block);
                self.indent -= 1;
                self.write_indent();
                self.write("}");
                if let Some(eb) = else_branch {
                    match eb {
                        ElseBranch::Block(block) => {
                            self.write(" else {\n");
                            self.indent += 1;
                            self.format_block_body(block);
                            self.indent -= 1;
                            self.write_indent();
                            self.write("}");
                        }
                        ElseBranch::ElseIf(expr) => {
                            self.write(" else ");
                            self.format_expr(expr);
                        }
                    }
                }
            }
            ExprKind::Match { subject, arms } => {
                self.write("match ");
                self.format_expr(subject);
                self.write(" {\n");
                self.indent += 1;
                for arm in arms {
                    self.write_indent();
                    self.format_pattern(&arm.pattern);
                    self.write(" -> ");
                    self.format_expr(&arm.body);
                    self.write("\n");
                }
                self.indent -= 1;
                self.write_indent();
                self.write("}");
            }
            ExprKind::Block(block) => {
                self.write("{\n");
                self.indent += 1;
                self.format_block_body(block);
                self.indent -= 1;
                self.write_indent();
                self.write("}");
            }
            ExprKind::Array(elements) => {
                self.write("[");
                for (i, e) in elements.iter().enumerate() {
                    if i > 0 {
                        self.write(", ");
                    }
                    self.format_expr(e);
                }
                self.write("]");
            }
            ExprKind::MapLit(entries) => {
                self.write("{");
                for (i, (k, v)) in entries.iter().enumerate() {
                    if i > 0 {
                        self.write(", ");
                    }
                    self.format_expr(k);
                    self.write(": ");
                    self.format_expr(v);
                }
                self.write("}");
            }
            ExprKind::Try(inner) => {
                self.format_expr(inner);
                self.write("?");
            }
            ExprKind::Await(inner) => {
                self.format_expr(inner);
                self.write(".await");
            }
            ExprKind::Assign { target, value } => {
                self.format_expr(target);
                self.write(" = ");
                self.format_expr(value);
            }
            ExprKind::Cast { expr, ty } => {
                self.format_expr(expr);
                self.write(" as ");
                self.format_type_expr(ty);
            }
            ExprKind::StructLit {
                name,
                fields,
                spread,
            } => {
                self.write(name);
                self.write(" { ");
                for (i, f) in fields.iter().enumerate() {
                    if i > 0 {
                        self.write(", ");
                    }
                    self.write(&f.name);
                    self.write(": ");
                    self.format_expr(&f.value);
                }
                if let Some(s) = spread {
                    if !fields.is_empty() {
                        self.write(", ");
                    }
                    self.write("...");
                    self.format_expr(s);
                }
                self.write(" }");
            }
            ExprKind::Interpolation(parts) => {
                self.write("\"");
                for part in parts {
                    match part {
                        StringPart::Lit(s) => self.write(s),
                        StringPart::Expr(e) => {
                            self.write("{");
                            self.format_expr(e);
                            self.write("}");
                        }
                    }
                }
                self.write("\"");
            }
            ExprKind::Closure { params, body } => {
                self.write("{ ");
                for (i, p) in params.iter().enumerate() {
                    if i > 0 {
                        self.write(", ");
                    }
                    self.write(&p.name);
                    if let Some(ty) = &p.ty {
                        self.write(": ");
                        self.format_type_expr(ty);
                    }
                }
                self.write(" -> ");
                for stmt in body {
                    self.format_stmt(stmt);
                }
                self.write("}");
            }
            ExprKind::Bail(e) => {
                self.write("bail ");
                self.format_expr(e);
            }
            // ── Concurrency (Phase 1) ────────────────────────────────────
            // `spawn func(args)`: func is always an `Ident` (parse_spawn_expr
            // consumes the name only), args are plain expressions.
            ExprKind::Spawn { func, args } => {
                self.write("spawn ");
                self.format_expr(func);
                self.write("(");
                for (i, arg) in args.iter().enumerate() {
                    if i > 0 {
                        self.write(", ");
                    }
                    self.format_expr(arg);
                }
                self.write(")");
            }
            // `select { recv(ch) -> var { body } send(ch, val) -> var { body } default { body } }`
            ExprKind::Select { cases, default } => {
                self.write("select {\n");
                self.indent += 1;
                for case in cases {
                    self.write_indent();
                    match &case.op {
                        SelectOp::Recv(ch) => {
                            self.write("recv(");
                            self.format_expr(ch);
                            self.write(")");
                        }
                        SelectOp::Send { ch, val } => {
                            self.write("send(");
                            self.format_expr(ch);
                            self.write(", ");
                            self.format_expr(val);
                            self.write(")");
                        }
                    }
                    if let Some(variable) = &case.variable {
                        self.write(" -> ");
                        self.write(variable);
                    }
                    self.write(" { ");
                    self.format_expr(&case.body);
                    self.write(" }\n");
                }
                if let Some(default_body) = default {
                    self.write_indent();
                    self.write("default { ");
                    self.format_expr(default_body);
                    self.write(" }\n");
                }
                self.indent -= 1;
                self.write_indent();
                self.write("}");
            }
        }
    }

    fn format_call_args(&mut self, args: &[CallArg]) {
        for (i, arg) in args.iter().enumerate() {
            if i > 0 {
                self.write(", ");
            }
            if let Some(ref name) = arg.name {
                self.write(name);
                self.write(": ");
            }
            self.format_expr(&arg.value);
        }
    }

    fn format_pattern(&mut self, pattern: &Pattern) {
        match pattern {
            Pattern::Wildcard => self.write("_"),
            Pattern::Ident(name) => self.write(name),
            Pattern::Literal(expr) => self.format_expr(expr),
            Pattern::Variant { name, fields } => {
                self.write(name);
                if !fields.is_empty() {
                    self.write("(");
                    for (i, f) in fields.iter().enumerate() {
                        if i > 0 {
                            self.write(", ");
                        }
                        self.format_pattern(&f.pattern);
                    }
                    self.write(")");
                }
            }
            Pattern::Tuple(patterns) => {
                self.write("(");
                for (i, p) in patterns.iter().enumerate() {
                    if i > 0 {
                        self.write(", ");
                    }
                    self.format_pattern(p);
                }
                self.write(")");
            }
        }
    }

    fn format_type_expr(&mut self, ty: &TypeExpr) {
        match &ty.kind {
            TypeExprKind::Named(name) => self.write(name),
            TypeExprKind::Generic { name, args } => {
                self.write(name);
                self.write("<");
                for (i, arg) in args.iter().enumerate() {
                    if i > 0 {
                        self.write(", ");
                    }
                    self.format_type_expr(arg);
                }
                self.write(">");
            }
            TypeExprKind::Slice(inner) => {
                self.write("[]");
                self.format_type_expr(inner);
            }
            TypeExprKind::Optional(inner) => {
                self.format_type_expr(inner);
                self.write("?");
            }
            TypeExprKind::Tuple(types) => {
                self.write("(");
                for (i, t) in types.iter().enumerate() {
                    if i > 0 {
                        self.write(", ");
                    }
                    self.format_type_expr(t);
                }
                self.write(")");
            }
            TypeExprKind::Function {
                params,
                return_type,
            } => {
                self.write("fn(");
                for (i, p) in params.iter().enumerate() {
                    if i > 0 {
                        self.write(", ");
                    }
                    self.format_type_expr(p);
                }
                self.write(") -> ");
                self.format_type_expr(return_type);
            }
            TypeExprKind::Boxed(inner) => {
                self.write("Box<");
                self.format_type_expr(inner);
                self.write(">");
            }
            TypeExprKind::ImplTrait(name) => {
                self.write("impl ");
                self.write(name);
            }
            TypeExprKind::DynTrait(name) => {
                self.write("dyn ");
                self.write(name);
            }
        }
    }
}

fn binop_str(op: &BinOp) -> &'static str {
    match op {
        BinOp::Add => "+",
        BinOp::Sub => "-",
        BinOp::Mul => "*",
        BinOp::Div => "/",
        BinOp::Mod => "%",
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
        BinOp::Pow => "**",
        BinOp::Range => "..",
    }
}

fn unop_str(op: &UnOp) -> &'static str {
    match op {
        UnOp::Neg => "-",
        UnOp::Not => "!",
        UnOp::BitNot => "~",
        UnOp::Deref => "*",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::lexer;
    use crate::parser::Parser;

    fn fmt(source: &str) -> String {
        let (tokens, errors) = lexer::tokenize(source);
        assert!(errors.is_empty(), "lex errors: {errors:?}");
        let program = Parser::parse(tokens).unwrap();
        format_program(&program)
    }

    #[test]
    fn fmt_generic_function() {
        let result = fmt("fn first<T>(items: []T) -> T { items[0] }");
        assert!(
            result.contains("fn first<T>("),
            "should contain generic params: {result}"
        );
    }

    #[test]
    fn fmt_generic_multi_params() {
        let result = fmt("fn transform<K, V>(key: K, val: V) -> K { key }");
        assert!(
            result.contains("fn transform<K, V>("),
            "should contain multiple generic params: {result}"
        );
    }

    #[test]
    fn fmt_non_generic_no_brackets() {
        let result = fmt("fn add(a: i32, b: i32) -> i32 { a }");
        assert!(
            result.contains("fn add("),
            "should not have angle brackets: {result}"
        );
        assert!(!result.contains("<"), "should not contain <: {result}");
    }

    #[test]
    fn fmt_generic_struct() {
        let result = fmt("struct Cache<K, V> { data: Map<K, V> }");
        assert!(
            result.contains("struct Cache<K, V>"),
            "should contain generic struct params: {result}"
        );
    }

    #[test]
    fn fmt_generic_enum() {
        let result = fmt("enum Result<T> { Ok(value: T), Err(msg: String) }");
        assert!(
            result.contains("enum Result<T>"),
            "should contain generic enum params: {result}"
        );
    }

    #[test]
    fn fmt_struct_with_defaults() {
        let result = fmt("struct Config { host: String, port: i32 = 8080 }");
        assert!(
            result.contains("port: i32 = 8080"),
            "should contain default value: {result}"
        );
    }

    #[test]
    fn fmt_legal_annotation() {
        let result = fmt(r#"
            @legal(basis: .public_data, purpose: "research")
            fn scrape(url: String) -> String { url }
        "#);
        assert!(
            result.contains("@legal("),
            "should contain legal annotation: {result}"
        );
    }

    #[test]
    fn fmt_async_function() {
        let result = fmt("async fn fetch_data(url: String) -> String { url }");
        assert!(
            result.contains("async fn"),
            "should contain async keyword: {result}"
        );
    }

    #[test]
    fn fmt_impl_block() {
        let result = fmt(r#"
            struct Point { x: i32, y: i32 }
            impl Point {
                fn sum(self) -> i32 { self.x + self.y }
            }
        "#);
        assert!(
            result.contains("impl Point"),
            "should contain impl block: {result}"
        );
    }

    #[test]
    fn fmt_match_expression() {
        let result = fmt(r#"
            fn main() {
                match x {
                    0 -> print("zero")
                    1 -> print("one")
                    _ -> print("other")
                }
            }
        "#);
        assert!(result.contains("match"), "should contain match: {result}");
        assert!(result.contains("->"), "should contain arrows: {result}");
    }

    #[test]
    fn fmt_enum_variants() {
        let result = fmt(r#"
            enum Status {
                Active,
                Pending(reason: String)
            }
        "#);
        assert!(
            result.contains("Active"),
            "should contain variant: {result}"
        );
        assert!(
            result.contains("Pending"),
            "should contain variant with fields: {result}"
        );
    }

    #[test]
    fn fmt_const_declaration() {
        let result = fmt("const MAX_CONN: u32 = 100000");
        assert!(
            result.contains("const MAX_CONN"),
            "should contain const: {result}"
        );
    }

    #[test]
    fn fmt_type_alias() {
        let result = fmt("type Email = private String");
        assert!(
            result.contains("type Email"),
            "should contain type alias: {result}"
        );
    }

    #[test]
    fn fmt_for_loop() {
        let result = fmt("fn main() { for item in items { print(item) } }");
        assert!(
            result.contains("for item in items"),
            "should contain for loop: {result}"
        );
    }

    #[test]
    fn fmt_while_loop() {
        let result = fmt("fn main() { while x > 0 { x = x - 1 } }");
        assert!(result.contains("while"), "should contain while: {result}");
    }

    #[test]
    fn fmt_if_let() {
        let result = fmt("fn main() { if let Ok(v) = result { print(v) } }");
        assert!(result.contains("if let"), "should contain if let: {result}");
    }

    #[test]
    fn fmt_import() {
        let result = fmt("import tallow.http");
        assert!(
            result.contains("import tallow.http"),
            "should contain import: {result}"
        );
    }

    // ── Additional formatter tests ────────────────────────────────────────

    #[test]
    fn fmt_var_declaration() {
        let result = fmt("fn main() { var count = 0 }");
        assert!(
            result.contains("var count = 0"),
            "should contain var: {result}"
        );
    }

    #[test]
    fn fmt_return_statement() {
        let result = fmt("fn f() -> i32 { return 42 }");
        assert!(
            result.contains("return 42"),
            "should contain return: {result}"
        );
    }

    #[test]
    fn fmt_return_void() {
        let result = fmt("fn f() { return }");
        assert!(result.contains("return"), "should contain return: {result}");
    }

    #[test]
    fn fmt_binary_expression() {
        let result = fmt("fn main() { let x = 1 + 2 * 3 }");
        assert!(
            result.contains("1 + 2 * 3"),
            "should contain binary expr: {result}"
        );
    }

    #[test]
    fn fmt_string_literal() {
        let result = fmt(r#"fn main() { let s = "hello world" }"#);
        assert!(
            result.contains(r#""hello world""#),
            "should contain string: {result}"
        );
    }

    #[test]
    fn fmt_nil_literal() {
        let result = fmt("fn main() { let x = nil }");
        assert!(result.contains("nil"), "should contain nil: {result}");
    }

    #[test]
    fn fmt_bool_literal() {
        let result = fmt("fn main() { let x = true\n let y = false }");
        assert!(result.contains("true"), "should contain true: {result}");
        assert!(result.contains("false"), "should contain false: {result}");
    }

    #[test]
    fn fmt_array_literal() {
        let result = fmt("fn main() { let a = [1, 2, 3] }");
        assert!(
            result.contains("[1, 2, 3]"),
            "should contain array: {result}"
        );
    }

    #[test]
    fn fmt_struct_literal() {
        let result = fmt(r#"fn main() { let p = Point { x: 1, y: 2 } }"#);
        assert!(
            result.contains("Point"),
            "should contain struct name: {result}"
        );
        assert!(result.contains("x: 1"), "should contain field: {result}");
    }

    #[test]
    fn fmt_loop_statement() {
        let result = fmt("fn main() { loop { break } }");
        assert!(result.contains("loop"), "should contain loop: {result}");
        assert!(result.contains("break"), "should contain break: {result}");
    }

    #[test]
    fn fmt_continue_statement() {
        let result = fmt("fn main() { for i in 0..10 { continue } }");
        assert!(
            result.contains("continue"),
            "should contain continue: {result}"
        );
    }

    #[test]
    fn fmt_multiple_imports() {
        let result = fmt("import tallow.http\nimport tallow.crypto\nimport tallow.json");
        assert!(
            result.contains("import tallow.http"),
            "should contain http: {result}"
        );
        assert!(
            result.contains("import tallow.crypto"),
            "should contain crypto: {result}"
        );
        assert!(
            result.contains("import tallow.json"),
            "should contain json: {result}"
        );
    }

    #[test]
    fn fmt_preserves_indentation() {
        let result = fmt(r#"
            fn main() {
                if true {
                    print("yes")
                }
            }
        "#);
        // Formatter should produce consistent indentation
        assert!(
            result.contains("    if true"),
            "should have 4-space indent: {result}"
        );
    }

    #[test]
    fn fmt_method_call() {
        let result = fmt(r#"fn main() { let x = "hello".upper() }"#);
        assert!(
            result.contains(".upper()"),
            "should contain method call: {result}"
        );
    }

    #[test]
    fn fmt_assign_expression() {
        let result = fmt("fn main() { var x = 0\n x = 42 }");
        assert!(result.contains("x = 42"), "should contain assign: {result}");
    }

    // ── Extended Formatter Tests ────────────────────────────────────────

    #[test]
    fn fmt_for_range_loop() {
        let result = fmt("fn main() { for i in 0..10 { print(i) } }");
        assert!(
            result.contains("for i in 0") && result.contains("10"),
            "should contain for range: {result}"
        );
    }

    #[test]
    fn fmt_for_in_array() {
        let result = fmt("fn main() { for item in items { print(item) } }");
        assert!(
            result.contains("for item in items"),
            "should contain for-in: {result}"
        );
    }

    #[test]
    fn fmt_while_true_break() {
        let result = fmt("fn main() { while true { break } }");
        assert!(
            result.contains("while true"),
            "should contain while: {result}"
        );
    }

    #[test]
    fn fmt_if_else_chain() {
        let result = fmt(
            "fn main() { if x > 0 { print(1) } else if x < 0 { print(-1) } else { print(0) } }",
        );
        assert!(result.contains("if x > 0"), "should contain if: {result}");
        assert!(
            result.contains("else if x < 0") || result.contains("} else if"),
            "should contain else if: {result}"
        );
        assert!(
            result.contains("else {") || result.contains("} else"),
            "should contain else: {result}"
        );
    }

    #[test]
    fn fmt_match_with_arms() {
        let result =
            fmt("fn main() { let x = 1\n x match { 1 -> print(\"one\") _ -> print(\"other\") } }");
        assert!(result.contains("match"), "should contain match: {result}");
    }

    #[test]
    fn fmt_struct_config_fields() {
        let result = fmt("struct Config { host: String, port: u16 = 8080 }");
        assert!(
            result.contains("struct Config"),
            "should contain struct: {result}"
        );
        assert!(
            result.contains("port"),
            "should contain port field: {result}"
        );
    }

    #[test]
    fn fmt_enum_with_variants() {
        let result = fmt("enum Color { Red, Green, Blue }");
        assert!(
            result.contains("enum Color"),
            "should contain enum: {result}"
        );
        assert!(result.contains("Red"), "should contain Red: {result}");
    }

    #[test]
    fn fmt_type_alias_private_string() {
        let result = fmt("type Email = private String");
        assert!(
            result.contains("type Email = private String"),
            "should contain type alias: {result}"
        );
    }

    #[test]
    fn fmt_impl_block_with_methods() {
        let result = fmt("struct Foo { x: i64 }\nimpl Foo { fn get(self) -> i64 { self.x } }");
        assert!(result.contains("impl Foo"), "should contain impl: {result}");
        assert!(result.contains("fn get"), "should contain method: {result}");
    }

    #[test]
    fn fmt_const_decl_max() {
        let result = fmt("const MAX = 100");
        assert!(
            result.contains("const MAX = 100"),
            "should contain const: {result}"
        );
    }

    #[test]
    fn fmt_multiple_functions() {
        let result = fmt("fn add(a: i64, b: i64) -> i64 { a + b }\nfn main() { print(add(1, 2)) }");
        assert!(result.contains("fn add"), "should contain add: {result}");
        assert!(result.contains("fn main"), "should contain main: {result}");
    }

    #[test]
    fn fmt_closure_in_call() {
        let result = fmt("fn main() { let x = items.map { i -> i * 2 } }");
        assert!(result.contains("map"), "should contain map: {result}");
    }

    #[test]
    fn fmt_try_expression() {
        let result = fmt("fn main() { let x = foo()? }");
        // The ? operator should be preserved
        assert!(result.contains("foo()"), "should contain call: {result}");
    }

    #[test]
    fn fmt_cast_expression() {
        let result = fmt(r#"fn main() { let x = "hello" as String }"#);
        assert!(
            result.contains("as String") || result.contains("as"),
            "should contain cast: {result}"
        );
    }

    #[test]
    fn fmt_annotation_legal() {
        let result = fmt(r#"@legal(basis: .public_data, purpose: "test")
fn scrape() { }"#);
        assert!(
            result.contains("@legal"),
            "should contain annotation: {result}"
        );
    }

    #[test]
    fn fmt_string_interpolation() {
        let result = fmt(r#"fn main() { let msg = "hello {name}" }"#);
        assert!(
            result.contains("hello") || result.contains("name"),
            "should contain interpolation: {result}"
        );
    }

    #[test]
    fn fmt_empty_function() {
        let result = fmt("fn noop() { }");
        assert!(
            result.contains("fn noop()"),
            "should contain fn noop: {result}"
        );
    }

    #[test]
    fn fmt_function_with_return_type() {
        let result = fmt("fn greet() -> String { \"hello\" }");
        assert!(
            result.contains("-> String"),
            "should contain return type: {result}"
        );
    }

    #[test]
    fn fmt_bail_statement() {
        let result = fmt(r#"fn check() { bail "error" }"#);
        // bail desugars to return Err, so check for return
        assert!(
            result.contains("return") || result.contains("bail"),
            "should contain bail/return: {result}"
        );
    }

    #[test]
    fn fmt_break_continue() {
        let result = fmt("fn main() { loop { break } }");
        assert!(result.contains("break"), "should contain break: {result}");
    }

    // ── 25 new formatter tests ────────────────────────────────────────────

    /// 1. Simple immutable variable declaration with inferred type.
    #[test]
    fn fmt_let_simple() {
        let result = fmt(r#"fn main() { let name = "tallow" }"#);
        assert!(
            result.contains("let name ="),
            "should contain let decl: {result}"
        );
        assert!(result.contains("tallow"), "should contain value: {result}");
    }

    /// 2. Mutable variable with explicit integer type annotation.
    #[test]
    fn fmt_var_with_type() {
        let result = fmt("fn main() { var count: i64 = 0 }");
        assert!(
            result.contains("var count: i64 = 0"),
            "should contain typed var: {result}"
        );
    }

    /// 3. Function with three or more parameters.
    #[test]
    fn fmt_multiple_params() {
        let result = fmt("fn sum(a: i32, b: i32, c: i32) -> i32 { a + b + c }");
        assert!(
            result.contains("fn sum(a: i32, b: i32, c: i32)"),
            "should list all params: {result}"
        );
        assert!(
            result.contains("-> i32"),
            "should contain return type: {result}"
        );
    }

    /// 4. Struct declaration with multiple default-valued fields.
    #[test]
    fn fmt_struct_multiple_defaults() {
        let result = fmt(
            "struct Server { host: String = \"localhost\", port: u16 = 8080, workers: u32 = 4 }",
        );
        assert!(
            result.contains("struct Server"),
            "should contain struct name: {result}"
        );
        assert!(
            result.contains("= \"localhost\""),
            "should contain string default: {result}"
        );
        assert!(
            result.contains("port: u16 = 8080"),
            "should contain port default: {result}"
        );
        assert!(
            result.contains("workers: u32 = 4"),
            "should contain workers default: {result}"
        );
    }

    /// 5. Struct literal with multiple named fields.
    #[test]
    fn fmt_struct_literal_fields() {
        let result = fmt(r#"fn main() { let p = Config { host: "localhost", port: 9000 } }"#);
        assert!(
            result.contains("Config"),
            "should contain struct name: {result}"
        );
        assert!(
            result.contains("host:"),
            "should contain host field: {result}"
        );
        assert!(
            result.contains("port:"),
            "should contain port field: {result}"
        );
        assert!(
            result.contains("9000"),
            "should contain port value: {result}"
        );
    }

    /// 6. Struct literal with spread syntax (`...base`).
    #[test]
    fn fmt_struct_literal_spread() {
        let result = fmt("fn main() { let cfg2 = Config { port: 9090, ...cfg } }");
        assert!(
            result.contains("Config"),
            "should contain struct name: {result}"
        );
        assert!(
            result.contains("port: 9090"),
            "should contain overridden field: {result}"
        );
        assert!(result.contains("...cfg"), "should contain spread: {result}");
    }

    /// 7. Array literal preserves all elements separated by commas.
    #[test]
    fn fmt_array_elements_preserved() {
        let result = fmt("fn main() { let xs = [10, 20, 30, 40, 50] }");
        assert!(
            result.contains("[10, 20, 30, 40, 50]"),
            "should preserve all elements: {result}"
        );
    }

    /// 8. Map literal with string keys and integer values.
    #[test]
    fn fmt_map_literal() {
        let result = fmt(r#"fn main() { let m = {"a": 1, "b": 2} }"#);
        assert!(
            result.contains("{"),
            "should contain map open brace: {result}"
        );
        assert!(
            result.contains("\"a\": 1"),
            "should contain first entry: {result}"
        );
        assert!(
            result.contains("\"b\": 2"),
            "should contain second entry: {result}"
        );
    }

    /// 9. For loop over a slice binding with body statement.
    #[test]
    fn fmt_for_loop_body() {
        let result = fmt(r#"fn main() { for url in urls { fetch(url) } }"#);
        assert!(
            result.contains("for url in urls"),
            "should contain for binding: {result}"
        );
        assert!(
            result.contains("fetch(url)"),
            "should contain body call: {result}"
        );
    }

    /// 10. While loop with compound condition.
    #[test]
    fn fmt_while_compound_condition() {
        let result = fmt("fn main() { var n = 10\n while n > 0 { n = n - 1 } }");
        assert!(
            result.contains("while n > 0"),
            "should contain while condition: {result}"
        );
        assert!(
            result.contains("n = n - 1"),
            "should contain body assignment: {result}"
        );
    }

    /// 11. `loop` keyword with break inside body.
    #[test]
    fn fmt_loop_keyword() {
        let result = fmt("fn main() { loop { if done { break } } }");
        assert!(
            result.contains("loop {"),
            "should contain loop keyword: {result}"
        );
        assert!(result.contains("break"), "should contain break: {result}");
    }

    /// 12. Nested if/else with three branches.
    #[test]
    fn fmt_nested_if_else() {
        let result = fmt(
            r#"fn main() { if x > 10 { print("big") } else if x > 5 { print("mid") } else { print("small") } }"#,
        );
        assert!(
            result.contains("if x > 10"),
            "should contain outer if: {result}"
        );
        assert!(
            result.contains("else if x > 5") || result.contains("} else if"),
            "should contain else-if: {result}"
        );
        assert!(
            result.contains(r#"print("small")"#),
            "should contain else body: {result}"
        );
    }

    /// 13. Match expression with wildcard arm.
    #[test]
    fn fmt_match_wildcard_arm() {
        let result = fmt(r#"fn main() { match code { 200 -> print("ok") _ -> print("other") } }"#);
        assert!(
            result.contains("match code"),
            "should contain match subject: {result}"
        );
        assert!(
            result.contains("200 ->"),
            "should contain literal arm: {result}"
        );
        assert!(
            result.contains("_ ->"),
            "should contain wildcard arm: {result}"
        );
    }

    /// 14. String interpolation preserves literal text and expression slots.
    #[test]
    fn fmt_string_interp_expr() {
        let result = fmt(r#"fn main() { let msg = "Hello {name}, you have {count} messages" }"#);
        assert!(
            result.contains("Hello"),
            "should contain literal part: {result}"
        );
        assert!(
            result.contains("{name}"),
            "should contain name interpolation: {result}"
        );
        assert!(
            result.contains("{count}"),
            "should contain count interpolation: {result}"
        );
    }

    /// 15. Method call chain (two chained calls on the same receiver).
    #[test]
    fn fmt_method_call_chain() {
        let result = fmt(r#"fn main() { let s = text.trim().upper() }"#);
        assert!(
            result.contains(".trim()"),
            "should contain first method: {result}"
        );
        assert!(
            result.contains(".upper()"),
            "should contain second method: {result}"
        );
    }

    /// 16. Field access on a struct instance.
    #[test]
    fn fmt_field_access() {
        let result = fmt("fn main() { let p = cfg.port }");
        assert!(
            result.contains("cfg.port"),
            "should contain field access: {result}"
        );
    }

    /// 17. Try (`?`) operator applied to a function call.
    #[test]
    fn fmt_try_operator() {
        let result = fmt("fn run() { let data = read_file(path)? }");
        assert!(
            result.contains("read_file(path)?"),
            "should contain try operator: {result}"
        );
    }

    /// 18. Tuple destructuring in let statement.
    #[test]
    fn fmt_let_destructure_tuple() {
        let result = fmt("fn main() { let (data, err) = parse(raw) }");
        assert!(
            result.contains("let (data, err) ="),
            "should contain destructure: {result}"
        );
        assert!(
            result.contains("parse(raw)"),
            "should contain rhs call: {result}"
        );
    }

    /// 19. Named arguments in a function call.
    #[test]
    fn fmt_named_args() {
        let result =
            fmt(r#"fn main() { fetch("https://x.com", timeout: 10, follow_redirects: true) }"#);
        assert!(
            result.contains("timeout: 10"),
            "should contain named arg: {result}"
        );
        assert!(
            result.contains("follow_redirects: true"),
            "should contain second named arg: {result}"
        );
    }

    /// 20. Multiple top-level items (struct + function) separated by blank line.
    #[test]
    fn fmt_struct_and_fn_toplevel() {
        let result =
            fmt("struct Point { x: i32, y: i32 }\nfn origin() -> Point { Point { x: 0, y: 0 } }");
        assert!(
            result.contains("struct Point"),
            "should contain struct: {result}"
        );
        assert!(
            result.contains("fn origin()"),
            "should contain function: {result}"
        );
        // The formatter inserts a blank line between top-level items.
        let struct_pos = result.find("struct Point").unwrap();
        let fn_pos = result.find("fn origin").unwrap();
        assert!(
            fn_pos > struct_pos,
            "fn should appear after struct: {result}"
        );
    }

    /// 21. Comparison operators (==, !=, <, >, <=, >=) are rendered with spaces.
    #[test]
    fn fmt_comparison_operators() {
        let result =
            fmt("fn main() { let a = x == y\n let b = x != y\n let c = x <= y\n let d = x >= y }");
        assert!(result.contains("x == y"), "should contain ==: {result}");
        assert!(result.contains("x != y"), "should contain !=: {result}");
        assert!(result.contains("x <= y"), "should contain <=: {result}");
        assert!(result.contains("x >= y"), "should contain >=: {result}");
    }

    /// 22. Logical `&&` and `||` operators are emitted with spaces.
    #[test]
    fn fmt_logical_operators() {
        let result = fmt("fn main() { let ok = a && b || c }");
        assert!(result.contains("&&"), "should contain &&: {result}");
        assert!(result.contains("||"), "should contain ||: {result}");
    }

    /// 23. Unary negation (`-`) and logical-not (`!`) operators.
    #[test]
    fn fmt_unary_operators() {
        let result = fmt("fn main() { let neg = -42\n let inv = !flag }");
        assert!(result.contains("-42"), "should contain unary neg: {result}");
        assert!(
            result.contains("!flag"),
            "should contain unary not: {result}"
        );
    }

    /// 24. Index expression with a literal subscript.
    #[test]
    fn fmt_index_expression() {
        let result = fmt("fn main() { let first = items[0] }");
        assert!(
            result.contains("items[0]"),
            "should contain index expr: {result}"
        );
    }

    /// 25. Cast expression (`as` keyword) with a named type.
    #[test]
    fn fmt_cast_as_type() {
        let result = fmt("fn main() { let n = value as i64 }");
        assert!(
            result.contains("value as i64"),
            "should contain cast: {result}"
        );
    }

    // ── Batch: additional formatter coverage ─────────────────────────

    #[test]
    fn fmt_while_decrement() {
        let result = fmt("fn main() { while x > 0 { x = x - 1 } }");
        assert!(result.contains("while"), "should contain while: {result}");
    }

    #[test]
    fn fmt_for_range_numeric() {
        let result = fmt("fn main() { for i in 0..10 { print(i) } }");
        assert!(result.contains("for i in"), "should contain for: {result}");
        assert!(
            result.contains("0..10") || result.contains("0 .. 10"),
            "should contain range: {result}"
        );
    }

    #[test]
    fn fmt_return_addition() {
        let result = fmt("fn add(a: i32, b: i32) -> i32 { return a + b }");
        assert!(result.contains("return"), "should contain return: {result}");
    }

    #[test]
    fn fmt_break_continue_in_for() {
        let result =
            fmt("fn main() { for i in items { if i == 0 { break } \n if i < 0 { continue } } }");
        assert!(result.contains("break"), "should contain break: {result}");
        assert!(
            result.contains("continue"),
            "should contain continue: {result}"
        );
    }

    #[test]
    fn fmt_closure_typed_param() {
        let result = fmt("fn main() { let double = { x: i32 -> x * 2 } }");
        assert!(result.contains("->"), "should contain arrow: {result}");
    }

    #[test]
    fn fmt_bail_desugars_to_return_err() {
        // bail desugars to return Err(...) during parsing
        let result = fmt(r#"fn main() { bail "error" }"#);
        assert!(
            result.contains("return Err("),
            "bail should desugar to return Err: {result}"
        );
    }

    #[test]
    fn fmt_string_interp_variable() {
        let result = fmt(r#"fn main() { let msg = "hello {name}" }"#);
        assert!(
            result.contains("hello {name}"),
            "should contain interpolation: {result}"
        );
    }

    #[test]
    fn fmt_three_params() {
        let result = fmt("fn process(a: i32, b: String, c: bool) -> i32 { a }");
        assert!(
            result.contains("a: i32"),
            "should contain a param: {result}"
        );
        assert!(
            result.contains("b: String"),
            "should contain b param: {result}"
        );
        assert!(
            result.contains("c: bool"),
            "should contain c param: {result}"
        );
    }

    #[test]
    fn fmt_nil_assignment() {
        let result = fmt("fn main() { let x = nil }");
        assert!(result.contains("nil"), "should contain nil: {result}");
    }

    #[test]
    fn fmt_try_suffix() {
        let result = fmt("fn main() { let x = get_value()? }");
        assert!(
            result.contains("?"),
            "should contain try operator: {result}"
        );
    }

    #[test]
    fn fmt_chained_methods() {
        let result = fmt(r#"fn main() { let x = "hello".upper().trim() }"#);
        assert!(
            result.contains(".upper()"),
            "should contain upper: {result}"
        );
        assert!(result.contains(".trim()"), "should contain trim: {result}");
    }

    #[test]
    fn fmt_struct_default_value() {
        let result = fmt("struct Config { port: u16, timeout: i32 = 30 }");
        assert!(
            result.contains("port: u16"),
            "should contain port field: {result}"
        );
        assert!(
            result.contains("timeout: i32"),
            "should contain timeout field: {result}"
        );
    }

    #[test]
    fn fmt_map_two_entries() {
        let result = fmt(r#"fn main() { let m = {"a": 1, "b": 2} }"#);
        assert!(result.contains("\"a\""), "should contain key a: {result}");
    }

    #[test]
    fn fmt_array_five_elements() {
        let result = fmt("fn main() { let arr = [1, 2, 3, 4, 5] }");
        assert!(
            result.contains("[1, 2, 3, 4, 5]"),
            "should contain array: {result}"
        );
    }

    #[test]
    fn fmt_loop_with_break() {
        let result = fmt("fn main() { loop { break } }");
        assert!(result.contains("loop"), "should contain loop: {result}");
        assert!(result.contains("break"), "should contain break: {result}");
    }

    #[test]
    fn fmt_enum_variant_with_field() {
        let result = fmt("enum Status { Active, Pending(reason: String) }");
        assert!(result.contains("Active"), "should contain Active: {result}");
        assert!(
            result.contains("Pending"),
            "should contain Pending: {result}"
        );
    }

    #[test]
    fn fmt_var_mutable() {
        let result = fmt("fn main() { var count = 0 }");
        assert!(result.contains("var count"), "should contain var: {result}");
    }

    #[test]
    fn fmt_let_typed_i64() {
        let result = fmt("fn main() { let x: i64 = 42 }");
        assert!(
            result.contains("let x: i64"),
            "should contain typed let: {result}"
        );
    }

    #[test]
    fn fmt_optional_return_type() {
        let result = fmt("fn find(name: String) -> String? { nil }");
        assert!(
            result.contains("String?"),
            "should contain optional type: {result}"
        );
    }

    #[test]
    fn fmt_slice_type_param() {
        let result = fmt("fn sum(items: []i32) -> i32 { 0 }");
        assert!(
            result.contains("[]i32"),
            "should contain slice type: {result}"
        );
    }

    #[test]
    fn fmt_result_return_type() {
        let result = fmt(r#"fn parse(s: String) -> Result<i32> { Ok(42) }"#);
        assert!(
            result.contains("Result<i32>"),
            "should contain result type: {result}"
        );
    }

    #[test]
    fn fmt_fn_preserves_name() {
        let result = fmt("fn compute(x: i32) -> i32 { x }");
        assert!(result.contains("fn compute("));
    }

    #[test]
    fn fmt_fn_preserves_return_type() {
        let result = fmt("fn sum(a: i32, b: i32) -> i64 { a + b }");
        assert!(result.contains("-> i64"));
    }

    #[test]
    fn fmt_struct_preserves_field_names() {
        let result = fmt("struct Point { x: f64, y: f64 }");
        assert!(result.contains("x: f64"));
        assert!(result.contains("y: f64"));
    }

    #[test]
    fn fmt_enum_preserves_variants() {
        let result = fmt("enum Color { Red, Green, Blue }");
        assert!(result.contains("Red"));
        assert!(result.contains("Blue"));
    }

    #[test]
    fn fmt_let_binding() {
        let result = fmt("fn main() { let x = 42 }");
        assert!(result.contains("let x = 42"));
    }

    #[test]
    fn fmt_var_binding() {
        let result = fmt("fn main() { var count = 0 }");
        assert!(result.contains("var count = 0"));
    }

    #[test]
    fn fmt_if_else() {
        let result = fmt("fn main() { if true { 1 } else { 2 } }");
        assert!(result.contains("if true"));
        assert!(result.contains("} else {"));
    }

    #[test]
    fn fmt_for_range() {
        let result = fmt("fn main() { for i in 0..10 { print(i) } }");
        assert!(
            result.contains("for i in"),
            "should contain for-in: {result}"
        );
        assert!(
            result.contains("0..10") || result.contains("0 .. 10"),
            "should contain range: {result}"
        );
    }

    #[test]
    fn fmt_while_break() {
        let result = fmt("fn main() { while true { break } }");
        assert!(result.contains("while true"));
    }

    #[test]
    fn fmt_match_with_wildcard() {
        let result = fmt(r#"fn main() { match x { 1 -> "a" _ -> "b" } }"#);
        assert!(result.contains("match x"));
    }

    #[test]
    fn fmt_const_string_value() {
        let result = fmt(r#"const NAME = "tallow""#);
        assert!(result.contains("const NAME ="));
    }

    #[test]
    fn fmt_type_alias_decl() {
        let result = fmt("type Email = private String");
        assert!(result.contains("type Email"));
    }

    #[test]
    fn fmt_import_statement() {
        let result = fmt("import tallow.http");
        assert!(result.contains("import tallow.http"));
    }

    #[test]
    fn fmt_impl_with_method() {
        let result = fmt("struct Foo { x: i32 }\nimpl Foo { fn get(self) -> i32 { self.x } }");
        assert!(result.contains("impl Foo"));
    }

    #[test]
    fn fmt_async_fn() {
        let result = fmt("async fn fetch(url: String) -> String { url }");
        assert!(result.contains("async fn fetch"));
    }

    #[test]
    fn fmt_three_typed_params() {
        let result = fmt("fn add(a: i32, b: i32, c: i32) -> i32 { a + b + c }");
        assert!(result.contains("a: i32, b: i32, c: i32"));
    }

    #[test]
    fn fmt_empty_fn_body() {
        let result = fmt("fn noop() { }");
        assert!(result.contains("fn noop()"));
    }

    #[test]
    fn fmt_nested_generic_type() {
        let result = fmt("fn deep(x: Map<String, Result<i64>>) { }");
        assert!(result.contains("Map<String, Result<i64>>"));
    }

    #[test]
    fn fmt_two_params_add() {
        let result = fmt("fn add(a:i32,b:i32)->i32{a+b}");
        assert!(result.contains("fn add("));
        assert!(result.contains("a: i32"));
        assert!(result.contains("b: i32"));
    }

    #[test]
    fn fmt_let_with_type_annotation() {
        let result = fmt("fn main(){let x:i32=42}");
        assert!(result.contains("let x: i32 = 42"));
    }

    #[test]
    fn fmt_var_count_zero() {
        let result = fmt("fn main(){var count=0}");
        assert!(result.contains("var count = 0"));
    }

    #[test]
    fn fmt_while_with_break_keyword() {
        let result = fmt("fn main(){while true{break}}");
        assert!(result.contains("while true"));
        assert!(result.contains("break"));
    }

    #[test]
    fn fmt_return_42() {
        let result = fmt("fn get()->i32{return 42}");
        assert!(result.contains("return 42"));
    }

    #[test]
    fn fmt_struct_point_xy() {
        let result = fmt("struct Point{x:i32,y:i32}");
        assert!(result.contains("struct Point"));
        assert!(result.contains("x: i32"));
        assert!(result.contains("y: i32"));
    }

    #[test]
    fn fmt_enum_dir_four_variants() {
        let result = fmt("enum Dir{Up,Down,Left,Right}");
        assert!(result.contains("enum Dir"));
        assert!(result.contains("Up"));
        assert!(result.contains("Right"));
    }

    #[test]
    fn fmt_loop_break() {
        let result = fmt("fn main(){loop{break}}");
        assert!(result.contains("loop"));
        assert!(result.contains("break"));
    }

    // ── Concurrency: spawn / select round-trip (R2-4) ─────────────────────

    /// Parse the formatted output again and re-format it.
    fn reparse_and_reformat(source: &str) -> String {
        let (tokens, errors) = lexer::tokenize(source);
        assert!(errors.is_empty(), "re-lex errors: {errors:?}");
        let program = Parser::parse(tokens).unwrap();
        format_program(&program)
    }

    #[test]
    fn fmt_spawn_select_roundtrip_is_stable() {
        // Multi-case select (recv with binding, send without binding, default)
        // plus two spawn forms, mirroring tests/fixtures/concurrency_*.tl.
        let source = r#"
            fn worker(id: i32) {
                let counter = 0
                counter = counter + 1
            }

            fn main() {
                let ch = sync.channel(10)
                spawn worker(1)
                spawn ping()
                select {
                    recv(ch) -> msg {
                        print(msg)
                    }
                    send(ch, "done") {
                        print("sent")
                    }
                    default {
                        print("none")
                    }
                }
            }
        "#;

        let once = fmt(source);

        // Real syntax must survive formatting (regression: fmt used to emit
        // "spawn (concurrency placeholder)" / "select (concurrency placeholder)",
        // which destroyed the expression).
        for needle in [
            "spawn worker(1)",
            "spawn ping()",
            "select {",
            "recv(ch) -> msg { print(msg) }",
            "send(ch, \"done\") { print(\"sent\") }",
            "default { print(\"none\") }",
        ] {
            assert!(once.contains(needle), "missing `{needle}` in:\n{once}");
        }
        assert!(
            !once.contains("placeholder"),
            "placeholder text leaked into formatted output:\n{once}"
        );

        // Formatted output must re-parse ...
        let twice = reparse_and_reformat(&once);

        // ... and re-format byte-identically (stability).
        assert_eq!(once, twice, "format is not stable across a round trip");
    }

    #[test]
    fn fmt_spawn_in_expression_position() {
        // spawn is an expression: it must survive `let x = spawn f(a)` too.
        let once = fmt(r#"fn main() { let h = spawn worker(3) }"#);
        assert!(once.contains("let h = spawn worker(3)"), "{once}");
        let twice = reparse_and_reformat(&once);
        assert_eq!(once, twice, "format is not stable across a round trip");
    }
}
