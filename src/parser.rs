use crate::ast::*;
use crate::lexer::{Span, Token, TokenKind};

// ── Parse Error ──────────────────────────────────────────────────────────────

#[derive(Debug, thiserror::Error)]
#[error("{msg}")]
pub struct ParseError {
    pub msg: String,
    pub span: Span,
}

impl ParseError {
    fn new(msg: impl Into<String>, span: Span) -> Self {
        Self {
            msg: msg.into(),
            span,
        }
    }
}

// ── Parser ───────────────────────────────────────────────────────────────────

pub struct Parser {
    tokens: Vec<Token>,
    pos: usize,
    /// Accumulated errors when running in recovery mode.
    errors: Vec<ParseError>,
    /// When true, the parser collects errors and continues instead of
    /// returning on the first failure.
    recover_mode: bool,
}

impl Parser {
    pub fn new(tokens: Vec<Token>) -> Self {
        Self {
            tokens,
            pos: 0,
            errors: Vec::new(),
            recover_mode: false,
        }
    }

    /// Parse a complete program. Returns the AST or the first error.
    pub fn parse(tokens: Vec<Token>) -> Result<Program, ParseError> {
        let mut parser = Parser::new(tokens);
        parser.parse_program()
    }

    /// Parse a complete program with error recovery enabled.
    ///
    /// On parse error the failed declaration is skipped and parsing resumes
    /// at the next synchronisation point.  The returned `Program` contains
    /// all declarations that were successfully parsed.  Any collected errors
    /// are available through [`Parser::errors`].
    pub fn parse_recovering(tokens: Vec<Token>) -> (Program, Vec<ParseError>) {
        let mut parser = Parser::new(tokens);
        parser.recover_mode = true;
        let program = parser.parse_program().unwrap_or_else(|e| {
            parser.errors.push(e);
            Program {
                items: Vec::new(),
                span: Span::new(0, 0),
            }
        });
        (program, parser.errors)
    }

    /// Return all errors collected during recovery-mode parsing.
    pub fn errors(&self) -> &[ParseError] {
        &self.errors
    }

    /// Enable or disable error-recovery mode.
    pub fn set_recover_mode(&mut self, enabled: bool) {
        self.recover_mode = enabled;
    }

    // ── Top Level ────────────────────────────────────────────────────────

    fn parse_program(&mut self) -> Result<Program, ParseError> {
        let start = self.span();
        let mut items = Vec::new();

        while !self.at_eof() {
            // `module tallow.csv` — stdlib sources name the module they implement.
            // The engine keys modules by path (`src/stdlib/mod.rs`), so the header
            // carries no information the compiler needs; accept and skip it so the
            // .tl corpus parses (register #128).
            if matches!(self.peek_kind(), TokenKind::Ident(n) if n == "module") {
                self.advance();
                if matches!(self.peek_kind(), TokenKind::Ident(_)) {
                    self.advance();
                    while self.check(TokenKind::Dot) {
                        self.advance();
                        if matches!(self.peek_kind(), TokenKind::Ident(_)) {
                            self.advance();
                        } else {
                            break;
                        }
                    }
                }
                continue;
            }
            if self.recover_mode {
                match self.parse_item() {
                    Ok(item) => items.push(item),
                    Err(err) => {
                        self.errors.push(err);
                        self.try_recover();
                    }
                }
            } else {
                items.push(self.parse_item()?);
            }
        }

        let end = self.span();
        Ok(Program {
            items,
            span: Span::new(start.start, end.end),
        })
    }

    /// Skip tokens until a top-level synchronisation point is reached.
    ///
    /// Synchronisation points are tokens that can begin a new top-level
    /// declaration or mark a clear statement boundary: `fn`, `struct`,
    /// `enum`, `impl`, `trait`, `const`, `type`, `import`, `@`, `}`,
    /// `;`, and EOF.
    fn try_recover(&mut self) {
        loop {
            match self.peek_kind() {
                TokenKind::Eof => break,
                TokenKind::Fn
                | TokenKind::Struct
                | TokenKind::Enum
                | TokenKind::Impl
                | TokenKind::Trait
                | TokenKind::Const
                | TokenKind::Type
                | TokenKind::Import
                | TokenKind::At => break,
                // A closing brace or semicolon marks the end of a block/stmt;
                // consume it and then let the loop try again.
                TokenKind::RBrace | TokenKind::Semi => {
                    self.advance();
                    // After consuming a `}` or `;` we may be at a sync point;
                    // check again on the next iteration rather than consuming
                    // one more token.
                    break;
                }
                _ => {
                    self.advance();
                }
            }
        }
    }

    fn parse_item(&mut self) -> Result<Item, ParseError> {
        // Collect annotations
        let annotations = self.parse_annotations()?;
        let is_async = self.eat(TokenKind::Async);
        // `native fn name(...) -> T` declares a function implemented by a symbol
        // of the same name at link time (register #129). `native` is not a
        // keyword: it is only a modifier when the next token is `fn`, so an
        // identifier named `native` elsewhere keeps working.
        let is_native = matches!(self.peek_kind(), TokenKind::Ident(n) if n == "native")
            && matches!(self.peek_kind_ahead(1), Some(TokenKind::Fn));
        if is_native {
            self.advance();
        }

        match self.peek_kind() {
            TokenKind::Fn => {
                let f = self.parse_fn_decl(annotations, is_async, is_native)?;
                Ok(Item::Fn(f))
            }
            TokenKind::Struct => {
                if !annotations.is_empty() {
                    return Err(self.error("annotations not allowed on struct declarations"));
                }
                Ok(Item::Struct(self.parse_struct_decl()?))
            }
            TokenKind::Enum => {
                if !annotations.is_empty() {
                    return Err(self.error("annotations not allowed on enum declarations"));
                }
                Ok(Item::Enum(self.parse_enum_decl()?))
            }
            TokenKind::Impl => {
                if !annotations.is_empty() {
                    return Err(self.error("annotations not allowed on impl blocks"));
                }
                Ok(Item::Impl(self.parse_impl_block()?))
            }
            TokenKind::Trait => {
                if !annotations.is_empty() {
                    return Err(self.error("annotations not allowed on trait declarations"));
                }
                Ok(Item::Trait(self.parse_trait_decl()?))
            }
            TokenKind::Const => {
                if !annotations.is_empty() {
                    return Err(self.error("annotations not allowed on const declarations"));
                }
                Ok(Item::Const(self.parse_const_decl()?))
            }
            TokenKind::Type => {
                let mut ta = self.parse_type_alias()?;
                ta.annotations = annotations;
                Ok(Item::TypeAlias(ta))
            }
            TokenKind::Import => {
                if !annotations.is_empty() {
                    return Err(self.error("annotations not allowed on imports"));
                }
                Ok(Item::Import(self.parse_import()?))
            }
            // Friendly migration hint: `pub` lexes as a plain identifier now
            // (Tallow has no visibility modifiers), so item-position `pub`
            // would otherwise fall through to the generic item error.
            TokenKind::Ident(name) if name == "pub" => Err(self.error(
                "found `pub` at item position — Tallow has no visibility modifiers; \
                 flat imports put every item in one namespace, so remove `pub`",
            )),
            _ => Err(self.error(format!(
                "expected item (fn, struct, enum, impl, trait, const, type, import), found {}",
                self.peek_kind()
            ))),
        }
    }

    // ── Annotations ──────────────────────────────────────────────────────

    fn parse_annotations(&mut self) -> Result<Vec<Annotation>, ParseError> {
        let mut annotations = Vec::new();
        while self.check(TokenKind::At) {
            annotations.push(self.parse_annotation()?);
        }
        Ok(annotations)
    }

    fn parse_annotation(&mut self) -> Result<Annotation, ParseError> {
        let start = self.span();
        self.expect(TokenKind::At)?;
        let name = self.expect_ident()?;
        let mut args = Vec::new();

        if self.eat(TokenKind::LParen) {
            while !self.check(TokenKind::RParen) && !self.at_eof() {
                let arg = self.parse_annotation_arg()?;
                args.push(arg);
                if !self.eat(TokenKind::Comma) {
                    break;
                }
            }
            self.expect(TokenKind::RParen)?;
        }

        Ok(Annotation {
            name,
            args,
            span: Span::new(start.start, self.prev_span().end),
        })
    }

    fn parse_annotation_arg(&mut self) -> Result<AnnotationArg, ParseError> {
        let start = self.span();

        // Positional arg: starts with `.` (e.g., @dns_policy(.doh))
        if self.check(TokenKind::Dot) {
            let value = self.parse_annotation_value()?;
            return Ok(AnnotationArg {
                name: String::new(),
                value,
                span: Span::new(start.start, self.prev_span().end),
            });
        }

        // Positional numeric/string/bool/array args (e.g., @epsilon(0.1), @purpose("analytics"))
        if matches!(
            self.peek_kind(),
            TokenKind::IntLit(_)
                | TokenKind::FloatLit(_)
                | TokenKind::StringLit(_)
                | TokenKind::True
                | TokenKind::False
                | TokenKind::LBracket
                | TokenKind::Minus
        ) {
            let value = self.parse_annotation_value()?;
            return Ok(AnnotationArg {
                name: String::new(),
                value,
                span: Span::new(start.start, self.prev_span().end),
            });
        }

        let name = self.expect_ident()?;

        // If no colon follows, treat as positional value
        if !self.eat(TokenKind::Colon) {
            // Check if followed by an expression operator (e.g., `n > 0`, `a + b == c`)
            // If so, backtrack and parse as full expression for contract annotations
            let is_expr_continuation = matches!(
                self.peek_kind(),
                TokenKind::Plus
                    | TokenKind::Minus
                    | TokenKind::Star
                    | TokenKind::Slash
                    | TokenKind::Percent
                    | TokenKind::Gt
                    | TokenKind::Lt
                    | TokenKind::GtEq
                    | TokenKind::LtEq
                    | TokenKind::EqEq
                    | TokenKind::BangEq
                    | TokenKind::AmpAmp
                    | TokenKind::PipePipe
                    | TokenKind::Dot
                    | TokenKind::LParen
            );
            if is_expr_continuation {
                // Backtrack: restore position to before ident, then parse full expression
                self.pos -= 1;
                let value = self.parse_expr()?;
                return Ok(AnnotationArg {
                    name: String::new(),
                    value,
                    span: Span::new(start.start, self.prev_span().end),
                });
            }
            let value = Expr::new(
                ExprKind::Ident(name.clone()),
                Span::new(start.start, self.prev_span().end),
            );
            return Ok(AnnotationArg {
                name: String::new(),
                value,
                span: Span::new(start.start, self.prev_span().end),
            });
        }

        let value = self.parse_annotation_value()?;
        Ok(AnnotationArg {
            name,
            value,
            span: Span::new(start.start, self.prev_span().end),
        })
    }

    /// Parse an annotation value — supports dot-idents, strings, numbers,
    /// bools, arrays, and method-call chains like `7.days` or `2.per_second`.
    fn parse_annotation_value(&mut self) -> Result<Expr, ParseError> {
        let start = self.span();

        // Array: [.us, .eu]
        if self.check(TokenKind::LBracket) {
            return self.parse_array_expr();
        }

        // .dot_ident (enum shorthand) — also handles .method(args)
        if self.check(TokenKind::Dot) {
            self.advance();
            let name = self.expect_ident()?;
            let mut expr = Expr::new(
                ExprKind::DotIdent(name),
                Span::new(start.start, self.prev_span().end),
            );
            // Allow method call: .per_second(1)
            if self.check(TokenKind::LParen) {
                expr = self.parse_postfix(expr)?;
            }
            return Ok(expr);
        }

        // String literal
        if let TokenKind::StringLit(s) = self.peek_kind().clone() {
            self.advance();
            let mut expr = Expr::new(
                ExprKind::StringLit(s),
                Span::new(start.start, self.prev_span().end),
            );
            // Allow method chains on strings
            expr = self.parse_postfix(expr)?;
            return Ok(expr);
        }

        // Bool
        if self.check(TokenKind::True) {
            self.advance();
            return Ok(Expr::new(
                ExprKind::BoolLit(true),
                Span::new(start.start, self.prev_span().end),
            ));
        }
        if self.check(TokenKind::False) {
            self.advance();
            return Ok(Expr::new(
                ExprKind::BoolLit(false),
                Span::new(start.start, self.prev_span().end),
            ));
        }

        // Negative number: -0.5, -1
        if self.check(TokenKind::Minus) {
            self.advance();
            if let TokenKind::FloatLit(n) = self.peek_kind().clone() {
                self.advance();
                let inner = Expr::new(
                    ExprKind::FloatLit(n),
                    Span::new(start.start, self.prev_span().end),
                );
                return Ok(Expr::new(
                    ExprKind::Unary {
                        op: UnOp::Neg,
                        operand: Box::new(inner),
                    },
                    Span::new(start.start, self.prev_span().end),
                ));
            }
            if let TokenKind::IntLit(n) = self.peek_kind().clone() {
                self.advance();
                let inner = Expr::new(
                    ExprKind::IntLit(n),
                    Span::new(start.start, self.prev_span().end),
                );
                return Ok(Expr::new(
                    ExprKind::Unary {
                        op: UnOp::Neg,
                        operand: Box::new(inner),
                    },
                    Span::new(start.start, self.prev_span().end),
                ));
            }
            return Err(self.error("expected number after '-' in annotation"));
        }

        // Number — might be followed by .ident (method call like 7.days)
        if let TokenKind::IntLit(n) = self.peek_kind().clone() {
            self.advance();
            let mut expr = Expr::new(
                ExprKind::IntLit(n),
                Span::new(start.start, self.prev_span().end),
            );
            // Check for .method (e.g., 7.days, 2.per_second)
            expr = self.parse_postfix(expr)?;
            return Ok(expr);
        }

        if let TokenKind::FloatLit(n) = self.peek_kind().clone() {
            self.advance();
            return Ok(Expr::new(
                ExprKind::FloatLit(n),
                Span::new(start.start, self.prev_span().end),
            ));
        }

        // Identifier (could be a reference)
        if let TokenKind::Ident(_) = self.peek_kind() {
            let name = self.expect_ident()?;
            return Ok(Expr::new(
                ExprKind::Ident(name),
                Span::new(start.start, self.prev_span().end),
            ));
        }

        Err(self.error("expected annotation value"))
    }

    // ── Function Declaration ─────────────────────────────────────────────

    fn parse_fn_decl(
        &mut self,
        annotations: Vec<Annotation>,
        is_async: bool,
        is_native: bool,
    ) -> Result<FnDecl, ParseError> {
        let start = if let Some(a) = annotations.first() {
            a.span
        } else {
            self.span()
        };

        self.expect(TokenKind::Fn)?;
        let mut name = self.expect_ident()?;
        // Type-scoped free functions: `fn CAPTCHA.detect(...)`, `fn URL.parse(...)`.
        // The stdlib manifest declares hundreds of these, and the runtime already
        // dispatches `Module.function` by exactly this spelling; the parser
        // rejected the declaration form, which is why 30 modules failed `check`.
        while self.eat(TokenKind::Dot) {
            let member = self.expect_ident()?;
            name.push('.');
            name.push_str(&member);
        }
        let name = name;

        // Optional generic type parameters: fn first<T>(...)
        let type_params = if self.eat(TokenKind::Lt) {
            let mut tps = Vec::new();
            while !self.check(TokenKind::Gt) && !self.at_eof() {
                tps.push(self.expect_ident()?);
                if !self.eat(TokenKind::Comma) {
                    break;
                }
            }
            self.expect(TokenKind::Gt)?;
            tps
        } else {
            Vec::new()
        };

        self.expect(TokenKind::LParen)?;
        let params = self.parse_params()?;
        self.expect(TokenKind::RParen)?;

        let return_type = if self.eat(TokenKind::Arrow) {
            Some(self.parse_type()?)
        } else {
            None
        };

        let body = if is_native {
            Block {
                stmts: Vec::new(),
                span: Span::new(start.start, self.prev_span().end),
            }
        } else {
            self.parse_block()?
        };

        Ok(FnDecl {
            annotations,
            is_async,
            is_native,
            name,
            type_params,
            params,
            return_type,
            body,
            span: Span::new(start.start, self.prev_span().end),
        })
    }

    fn parse_params(&mut self) -> Result<Vec<Param>, ParseError> {
        let mut params = Vec::new();
        // Handle `self` as first param
        if self.check(TokenKind::SelfValue) {
            let start = self.span();
            self.advance();
            // `self` has implicit type of Self
            params.push(Param {
                name: "self".to_string(),
                ty: TypeExpr::new(TypeExprKind::Named("Self".to_string()), start),
                default: None,
                span: start,
            });
            if self.eat(TokenKind::Comma) {
                // more params follow
            } else {
                return Ok(params);
            }
        }
        while !self.check(TokenKind::RParen) && !self.at_eof() {
            let start = self.span();
            let name = self.expect_ident()?;
            self.expect(TokenKind::Colon)?;
            let ty = self.parse_type()?;
            // Optional default parameter value: `fn launch(headless: bool = true)`.
            // R2-3 (audit a01:77): the parsed default is carried on the AST
            // Param instead of being dropped; the interpreter applies it when
            // a call omits the argument on paths that bypass static arity
            // checking. Direct calls still require every argument (E0103), so
            // each backend stays loud where it cannot honor a default.
            let default = if self.eat(TokenKind::Eq) {
                Some(self.parse_expr()?)
            } else {
                None
            };
            params.push(Param {
                name,
                ty,
                default,
                span: Span::new(start.start, self.prev_span().end),
            });
            if !self.eat(TokenKind::Comma) {
                break;
            }
        }
        Ok(params)
    }

    // ── Struct Declaration ───────────────────────────────────────────────

    fn parse_struct_decl(&mut self) -> Result<StructDecl, ParseError> {
        let start = self.span();
        self.expect(TokenKind::Struct)?;
        let name = self.expect_ident()?;

        // Optional generic type parameters: struct Cache<K, V> { ... }
        let type_params = if self.eat(TokenKind::Lt) {
            let mut tps = Vec::new();
            while !self.check(TokenKind::Gt) && !self.at_eof() {
                tps.push(self.expect_ident()?);
                if !self.eat(TokenKind::Comma) {
                    break;
                }
            }
            self.expect(TokenKind::Gt)?;
            tps
        } else {
            Vec::new()
        };

        self.expect(TokenKind::LBrace)?;
        let mut fields = Vec::new();
        while !self.check(TokenKind::RBrace) && !self.at_eof() {
            let fstart = self.span();
            let fname = self.expect_ident()?;
            self.expect(TokenKind::Colon)?;
            let ty = self.parse_type()?;
            let default = if self.eat(TokenKind::Eq) {
                Some(self.parse_expr()?)
            } else {
                None
            };
            fields.push(FieldDecl {
                name: fname,
                ty,
                default,
                span: Span::new(fstart.start, self.prev_span().end),
            });
            // Fields separated by commas or newlines
            self.eat(TokenKind::Comma);
        }
        self.expect(TokenKind::RBrace)?;

        Ok(StructDecl {
            name,
            type_params,
            fields,
            span: Span::new(start.start, self.prev_span().end),
        })
    }

    // ── Enum Declaration ─────────────────────────────────────────────────

    fn parse_enum_decl(&mut self) -> Result<EnumDecl, ParseError> {
        let start = self.span();
        self.expect(TokenKind::Enum)?;
        let name = self.expect_ident()?;

        // Optional generic type parameters: enum Result<T> { ... }
        let type_params = if self.eat(TokenKind::Lt) {
            let mut tps = Vec::new();
            while !self.check(TokenKind::Gt) && !self.at_eof() {
                tps.push(self.expect_ident()?);
                if !self.eat(TokenKind::Comma) {
                    break;
                }
            }
            self.expect(TokenKind::Gt)?;
            tps
        } else {
            Vec::new()
        };

        self.expect(TokenKind::LBrace)?;
        let mut variants = Vec::new();
        while !self.check(TokenKind::RBrace) && !self.at_eof() {
            let vstart = self.span();
            let vname = self.expect_ident()?;
            let mut fields = Vec::new();

            // Variant with fields: Pending(reason: String)
            if self.eat(TokenKind::LParen) {
                while !self.check(TokenKind::RParen) && !self.at_eof() {
                    let fstart = self.span();
                    let fname = self.expect_ident()?;
                    self.expect(TokenKind::Colon)?;
                    let ty = self.parse_type()?;
                    fields.push(FieldDecl {
                        name: fname,
                        ty,
                        default: None,
                        span: Span::new(fstart.start, self.prev_span().end),
                    });
                    if !self.eat(TokenKind::Comma) {
                        break;
                    }
                }
                self.expect(TokenKind::RParen)?;
            }

            variants.push(EnumVariant {
                name: vname,
                fields,
                span: Span::new(vstart.start, self.prev_span().end),
            });
            self.eat(TokenKind::Comma);
        }
        self.expect(TokenKind::RBrace)?;

        Ok(EnumDecl {
            name,
            type_params,
            variants,
            span: Span::new(start.start, self.prev_span().end),
        })
    }

    // ── Impl Block ───────────────────────────────────────────────────────

    fn parse_impl_block(&mut self) -> Result<ImplBlock, ParseError> {
        let start = self.span();
        self.expect(TokenKind::Impl)?;
        let first_ident = self.expect_ident()?;

        // Optional type parameters: impl<T> ...
        let type_params = if self.eat(TokenKind::Lt) {
            let mut tps = Vec::new();
            while !self.check(TokenKind::Gt) && !self.at_eof() {
                tps.push(self.expect_ident()?);
                if !self.eat(TokenKind::Comma) {
                    break;
                }
            }
            self.expect(TokenKind::Gt)?;
            tps
        } else {
            Vec::new()
        };

        // Check for `impl TraitName for TypeName { ... }`
        let (trait_name, target) = if self.eat(TokenKind::For) {
            let target = self.expect_ident()?;
            (Some(first_ident), target)
        } else {
            (None, first_ident)
        };

        self.expect(TokenKind::LBrace)?;
        let mut methods = Vec::new();
        while !self.check(TokenKind::RBrace) && !self.at_eof() {
            let annotations = self.parse_annotations()?;
            let is_async = self.eat(TokenKind::Async);
            // `native fn` is allowed on impl methods too: a struct or trait impl
            // may declare a method whose body is a link-time symbol.
            let is_native = matches!(self.peek_kind(), TokenKind::Ident(n) if n == "native")
                && matches!(self.peek_kind_ahead(1), Some(TokenKind::Fn));
            if is_native {
                self.advance();
            }
            methods.push(self.parse_fn_decl(annotations, is_async, is_native)?);
        }
        self.expect(TokenKind::RBrace)?;

        Ok(ImplBlock {
            trait_name,
            type_params,
            target,
            methods,
            span: Span::new(start.start, self.prev_span().end),
        })
    }

    fn parse_trait_decl(&mut self) -> Result<TraitDecl, ParseError> {
        let start = self.span();
        self.expect(TokenKind::Trait)?;
        let name = self.expect_ident()?;

        // Optional type parameters: trait Container<T> { ... }
        let type_params = if self.eat(TokenKind::Lt) {
            let mut tps = Vec::new();
            while !self.check(TokenKind::Gt) && !self.at_eof() {
                tps.push(self.expect_ident()?);
                if !self.eat(TokenKind::Comma) {
                    break;
                }
            }
            self.expect(TokenKind::Gt)?;
            tps
        } else {
            Vec::new()
        };

        self.expect(TokenKind::LBrace)?;
        let mut methods = Vec::new();
        while !self.check(TokenKind::RBrace) && !self.at_eof() {
            methods.push(self.parse_trait_method()?);
        }
        self.expect(TokenKind::RBrace)?;

        Ok(TraitDecl {
            name,
            type_params,
            methods,
            span: Span::new(start.start, self.prev_span().end),
        })
    }

    fn parse_trait_method(&mut self) -> Result<TraitMethod, ParseError> {
        let start = self.span();
        self.expect(TokenKind::Fn)?;
        let name = self.expect_ident()?;

        self.expect(TokenKind::LParen)?;
        let params = self.parse_params()?;
        self.expect(TokenKind::RParen)?;

        let return_type = if self.eat(TokenKind::Arrow) {
            Some(self.parse_type()?)
        } else {
            None
        };

        // Optional body (default impl)
        let (has_default, body) = if self.check(TokenKind::LBrace) {
            let block = self.parse_block()?;
            (true, Some(block))
        } else {
            (false, None)
        };

        Ok(TraitMethod {
            name,
            params,
            return_type,
            has_default,
            body,
            span: Span::new(start.start, self.prev_span().end),
        })
    }

    // ── Const Declaration ────────────────────────────────────────────────

    fn parse_const_decl(&mut self) -> Result<ConstDecl, ParseError> {
        let start = self.span();
        self.expect(TokenKind::Const)?;
        let name = self.expect_ident()?;
        let ty = if self.eat(TokenKind::Colon) {
            Some(self.parse_type()?)
        } else {
            None
        };
        self.expect(TokenKind::Eq)?;
        let value = self.parse_expr()?;

        Ok(ConstDecl {
            name,
            ty,
            value,
            span: Span::new(start.start, self.prev_span().end),
        })
    }

    // ── Type Alias ───────────────────────────────────────────────────────

    fn parse_type_alias(&mut self) -> Result<TypeAlias, ParseError> {
        let start = self.span();
        self.expect(TokenKind::Type)?;
        let name = self.expect_ident()?;
        // Generic alias: `type MetaPrivate<T> = private T`. The parameters are
        // accepted and not substituted — the alias erases to its target type,
        // which is what the stdlib manifest uses it for.
        if self.eat(TokenKind::Lt) {
            while !self.check(TokenKind::Gt) && !self.at_eof() {
                self.expect_ident()?;
                if !self.eat(TokenKind::Comma) {
                    break;
                }
            }
            self.expect(TokenKind::Gt)?;
        }
        self.expect(TokenKind::Eq)?;

        // Check for privacy qualifier: `type Email = private String`
        let qualifier = if self.check(TokenKind::Private) {
            self.advance();
            Some(TypeQualifier::Private)
        } else if self.check(TokenKind::Secret) {
            self.advance();
            Some(TypeQualifier::Secret)
        } else {
            None
        };

        let ty = self.parse_type()?;

        Ok(TypeAlias {
            name,
            annotations: vec![],
            qualifier,
            ty,
            span: Span::new(start.start, self.prev_span().end),
        })
    }

    // ── Import ───────────────────────────────────────────────────────────

    fn parse_import(&mut self) -> Result<ImportDecl, ParseError> {
        let start = self.span();
        self.expect(TokenKind::Import)?;

        let mut path = vec![self.expect_ident()?];
        while self.eat(TokenKind::Dot) {
            // Check for destructured import: `import foo.bar.{Baz, Qux}`
            if self.check(TokenKind::LBrace) {
                break;
            }
            // Allow keywords as path segments (e.g., `import x.import.y`)
            if let TokenKind::Ident(name) = self.peek_kind().clone() {
                self.advance();
                path.push(name);
            } else {
                // Try to consume keyword as ident for path purposes
                let name = format!("{}", self.peek_kind());
                if matches!(
                    self.peek_kind(),
                    TokenKind::Import
                        | TokenKind::Type
                        | TokenKind::Match
                        | TokenKind::Return
                        | TokenKind::For
                        | TokenKind::If
                ) {
                    self.advance();
                    path.push(name);
                } else {
                    path.push(self.expect_ident()?);
                }
            }
        }

        let mut items = Vec::new();
        if self.eat(TokenKind::LBrace) {
            while !self.check(TokenKind::RBrace) && !self.at_eof() {
                items.push(self.expect_ident()?);
                if !self.eat(TokenKind::Comma) {
                    break;
                }
            }
            self.expect(TokenKind::RBrace)?;
        }

        Ok(ImportDecl {
            path,
            items,
            span: Span::new(start.start, self.prev_span().end),
        })
    }

    // ── Block ────────────────────────────────────────────────────────────

    fn parse_block(&mut self) -> Result<Block, ParseError> {
        let start = self.span();
        self.expect(TokenKind::LBrace)?;

        let mut stmts = Vec::new();
        while !self.check(TokenKind::RBrace) && !self.at_eof() {
            stmts.push(self.parse_stmt()?);
        }
        self.expect(TokenKind::RBrace)?;

        Ok(Block {
            stmts,
            span: Span::new(start.start, self.prev_span().end),
        })
    }

    // ── Statements ───────────────────────────────────────────────────────

    fn parse_stmt(&mut self) -> Result<Stmt, ParseError> {
        let start = self.span();

        match self.peek_kind() {
            TokenKind::Let => self.parse_let_stmt(),
            TokenKind::Var => self.parse_var_stmt(),
            TokenKind::Return => self.parse_return_stmt(),
            TokenKind::For => self.parse_for_stmt(),
            TokenKind::While => self.parse_while_stmt(),
            TokenKind::Bail => self.parse_bail_stmt(),
            TokenKind::BailIf => self.parse_bail_if_stmt(),
            TokenKind::Break => {
                self.advance();
                self.eat(TokenKind::Semi);
                Ok(Stmt {
                    kind: StmtKind::Break,
                    span: Span::new(start.start, self.prev_span().end),
                })
            }
            TokenKind::Continue => {
                self.advance();
                self.eat(TokenKind::Semi);
                Ok(Stmt {
                    kind: StmtKind::Continue,
                    span: Span::new(start.start, self.prev_span().end),
                })
            }
            TokenKind::Loop => self.parse_loop_stmt(),
            TokenKind::Defer => {
                self.advance();
                let body = if self.check(TokenKind::LBrace) {
                    self.parse_block()?
                } else {
                    // Allow `defer expr` as shorthand for `defer { expr }`
                    let expr = self.parse_expr()?;
                    self.eat(TokenKind::Semi);
                    Block {
                        stmts: vec![Stmt {
                            kind: StmtKind::Expr { expr },
                            span: Span::new(start.start, self.prev_span().end),
                        }],
                        span: Span::new(start.start, self.prev_span().end),
                    }
                };
                Ok(Stmt {
                    kind: StmtKind::Defer { body },
                    span: Span::new(start.start, self.prev_span().end),
                })
            }
            _ => {
                let expr = self.parse_expr()?;
                // Consume optional semicolon
                self.eat(TokenKind::Semi);
                Ok(Stmt {
                    kind: StmtKind::Expr { expr },
                    span: Span::new(start.start, self.prev_span().end),
                })
            }
        }
    }

    fn parse_let_stmt(&mut self) -> Result<Stmt, ParseError> {
        let start = self.span();
        self.expect(TokenKind::Let)?;

        // Skip optional `mut` keyword: let mut x = ...
        self.eat(TokenKind::Mut);

        // Check for tuple destructuring: let (a, b) = expr
        if self.check(TokenKind::LParen) {
            self.advance(); // consume (
            let mut names = Vec::new();
            loop {
                names.push(self.expect_ident()?);
                if !self.eat(TokenKind::Comma) {
                    break;
                }
            }
            self.expect(TokenKind::RParen)?;
            self.expect(TokenKind::Eq)?;
            let value = self.parse_expr()?;
            self.eat(TokenKind::Semi);
            return Ok(Stmt {
                kind: StmtKind::LetDestructure { names, value },
                span: Span::new(start.start, self.prev_span().end),
            });
        }

        // Allow `_` as discard binding
        let name = if self.check(TokenKind::Underscore) {
            self.advance();
            "_".to_string()
        } else {
            self.expect_ident()?
        };
        let ty = if self.eat(TokenKind::Colon) {
            Some(self.parse_type()?)
        } else {
            None
        };
        self.expect(TokenKind::Eq)?;
        let value = self.parse_expr()?;
        self.eat(TokenKind::Semi);

        Ok(Stmt {
            kind: StmtKind::Let { name, ty, value },
            span: Span::new(start.start, self.prev_span().end),
        })
    }

    fn parse_var_stmt(&mut self) -> Result<Stmt, ParseError> {
        let start = self.span();
        self.expect(TokenKind::Var)?;
        let name = self.expect_ident()?;
        let ty = if self.eat(TokenKind::Colon) {
            Some(self.parse_type()?)
        } else {
            None
        };
        self.expect(TokenKind::Eq)?;
        let value = self.parse_expr()?;
        self.eat(TokenKind::Semi);

        Ok(Stmt {
            kind: StmtKind::Var { name, ty, value },
            span: Span::new(start.start, self.prev_span().end),
        })
    }

    fn parse_return_stmt(&mut self) -> Result<Stmt, ParseError> {
        let start = self.span();
        self.expect(TokenKind::Return)?;
        let value = if self.check(TokenKind::RBrace) || self.check(TokenKind::Semi) || self.at_eof()
        {
            None
        } else {
            Some(self.parse_expr()?)
        };
        self.eat(TokenKind::Semi);

        Ok(Stmt {
            kind: StmtKind::Return(value),
            span: Span::new(start.start, self.prev_span().end),
        })
    }

    fn parse_for_stmt(&mut self) -> Result<Stmt, ParseError> {
        let start = self.span();
        self.expect(TokenKind::For)?;
        let binding = if self.check(TokenKind::LParen) {
            self.advance();
            let mut names: Vec<String> = Vec::new();
            names.push(self.expect_ident()?);
            while self.check(TokenKind::Comma) {
                self.advance();
                names.push(self.expect_ident()?);
            }
            self.expect(TokenKind::RParen)?;
            // Encode tuple binding as "(a,b,c)" — interp will detect & split.
            format!("({})", names.join(","))
        } else {
            self.expect_ident()?
        };
        self.expect(TokenKind::In)?;
        let iter = self.parse_expr()?;
        let body = self.parse_block()?;

        Ok(Stmt {
            kind: StmtKind::For {
                binding,
                iter,
                body,
            },
            span: Span::new(start.start, self.prev_span().end),
        })
    }

    fn parse_while_stmt(&mut self) -> Result<Stmt, ParseError> {
        let start = self.span();
        self.expect(TokenKind::While)?;

        // Check for `while let Pattern = expr { ... }`
        if self.check(TokenKind::Let) {
            self.advance(); // consume 'let'
            let pattern = self.parse_pattern()?;
            self.expect(TokenKind::Eq)?;
            let expr = self.parse_expr()?;
            let body = self.parse_block()?;

            return Ok(Stmt {
                kind: StmtKind::WhileLet {
                    pattern: Box::new(pattern),
                    expr,
                    body,
                },
                span: Span::new(start.start, self.prev_span().end),
            });
        }

        let condition = self.parse_expr()?;
        let body = self.parse_block()?;

        Ok(Stmt {
            kind: StmtKind::While { condition, body },
            span: Span::new(start.start, self.prev_span().end),
        })
    }

    fn parse_loop_stmt(&mut self) -> Result<Stmt, ParseError> {
        let start = self.span();
        self.expect(TokenKind::Loop)?;
        let body = self.parse_block()?;

        Ok(Stmt {
            kind: StmtKind::Loop { body },
            span: Span::new(start.start, self.prev_span().end),
        })
    }

    fn parse_bail_stmt(&mut self) -> Result<Stmt, ParseError> {
        let start = self.span();
        self.expect(TokenKind::Bail)?;
        let value = self.parse_expr()?;
        self.eat(TokenKind::Semi);

        // Desugar: `bail x` → `return Err(x)`
        let err_call = Expr::new(
            ExprKind::Call {
                callee: Box::new(Expr::new(ExprKind::Ident("Err".to_string()), start)),
                args: vec![CallArg {
                    name: None,
                    value,
                    span: Span::new(start.start, self.prev_span().end),
                }],
            },
            Span::new(start.start, self.prev_span().end),
        );

        Ok(Stmt {
            kind: StmtKind::Return(Some(err_call)),
            span: Span::new(start.start, self.prev_span().end),
        })
    }

    fn parse_bail_if_stmt(&mut self) -> Result<Stmt, ParseError> {
        let start = self.span();
        self.expect(TokenKind::BailIf)?;
        let condition = self.parse_expr()?;
        self.expect(TokenKind::Comma)?;
        let message = self.parse_expr()?;
        self.eat(TokenKind::Semi);

        // Desugar: `bail_if cond, msg` → `if cond { return Err(msg) }`
        let err_call = Expr::new(
            ExprKind::Call {
                callee: Box::new(Expr::new(ExprKind::Ident("Err".to_string()), start)),
                args: vec![CallArg {
                    name: None,
                    value: message,
                    span: Span::new(start.start, self.prev_span().end),
                }],
            },
            Span::new(start.start, self.prev_span().end),
        );

        let return_stmt = Stmt {
            kind: StmtKind::Return(Some(err_call)),
            span: Span::new(start.start, self.prev_span().end),
        };

        let then_block = Block {
            stmts: vec![return_stmt],
            span: Span::new(start.start, self.prev_span().end),
        };
        let span = Span::new(start.start, self.prev_span().end);

        Ok(Stmt {
            kind: StmtKind::Expr {
                expr: Expr::new(
                    ExprKind::If {
                        condition: Box::new(condition),
                        then_block,
                        else_branch: None,
                    },
                    span,
                ),
            },
            span,
        })
    }

    // ── Expressions (Pratt Parser) ───────────────────────────────────────

    fn parse_expr(&mut self) -> Result<Expr, ParseError> {
        self.parse_expr_bp(0)
    }

    /// Pratt parser: parse expression with minimum binding power.
    fn parse_expr_bp(&mut self, min_bp: u8) -> Result<Expr, ParseError> {
        // Parse prefix (unary) or primary
        let mut lhs = self.parse_prefix()?;

        loop {
            // Postfix operations: call, field access, method call, index, try
            lhs = self.parse_postfix(lhs)?;

            // Assignment
            if min_bp == 0 && matches!(self.peek_kind(), TokenKind::Eq) {
                // Only allow assignment at the top level (bp=0)
                // Make sure LHS is an assignable target
                self.advance();
                let rhs = self.parse_expr_bp(0)?;
                let span = Span::new(lhs.span.start, rhs.span.end);
                lhs = Expr::new(
                    ExprKind::Assign {
                        target: Box::new(lhs),
                        value: Box::new(rhs),
                    },
                    span,
                );
                continue;
            }

            // Compound assignment (+=, -=, *=, /=, %=) — desugar to x = x op expr
            if min_bp == 0 {
                if let Some(binop) = compound_assign_op(self.peek_kind()) {
                    self.advance();
                    let rhs = self.parse_expr_bp(0)?;
                    let span = Span::new(lhs.span.start, rhs.span.end);
                    // Desugar: x += expr → x = x + expr
                    let binary = Expr::new(
                        ExprKind::Binary {
                            op: binop,
                            left: Box::new(lhs.clone()),
                            right: Box::new(rhs),
                        },
                        span,
                    );
                    lhs = Expr::new(
                        ExprKind::Assign {
                            target: Box::new(lhs),
                            value: Box::new(binary),
                        },
                        span,
                    );
                    continue;
                }
            }

            // Infix binary operators
            if let Some((l_bp, r_bp)) = infix_binding_power(self.peek_kind()) {
                if l_bp < min_bp {
                    break;
                }

                let op = match self.peek_kind() {
                    TokenKind::Plus => BinOp::Add,
                    TokenKind::Minus => BinOp::Sub,
                    TokenKind::Star => BinOp::Mul,
                    TokenKind::Slash => BinOp::Div,
                    TokenKind::Percent => BinOp::Mod,
                    TokenKind::EqEq => BinOp::Eq,
                    TokenKind::BangEq => BinOp::Neq,
                    TokenKind::Lt => BinOp::Lt,
                    TokenKind::Gt => BinOp::Gt,
                    TokenKind::LtEq => BinOp::Lte,
                    TokenKind::GtEq => BinOp::Gte,
                    TokenKind::AmpAmp => BinOp::And,
                    TokenKind::PipePipe => BinOp::Or,
                    TokenKind::Amp => BinOp::BitAnd,
                    TokenKind::Pipe => BinOp::BitOr,
                    TokenKind::Caret => BinOp::BitXor,
                    TokenKind::Shl => BinOp::Shl,
                    TokenKind::Shr => BinOp::Shr,
                    TokenKind::StarStar => BinOp::Pow,
                    TokenKind::DotDot => BinOp::Range,
                    _ => break,
                };

                self.advance(); // consume operator

                // For range operator `..`, the right side is optional (half-open range: `start..`)
                if op == BinOp::Range
                    && (self.check(TokenKind::RBracket)
                        || self.check(TokenKind::RParen)
                        || self.check(TokenKind::RBrace)
                        || self.check(TokenKind::Comma)
                        || self.at_eof())
                {
                    let span = Span::new(lhs.span.start, self.prev_span().end);
                    // Use a sentinel "None" value for the missing end
                    let none_expr =
                        Expr::new(ExprKind::Ident("__range_open".into()), self.prev_span());
                    lhs = Expr::new(
                        ExprKind::Binary {
                            op,
                            left: Box::new(lhs),
                            right: Box::new(none_expr),
                        },
                        span,
                    );
                    continue;
                }

                let rhs = self.parse_expr_bp(r_bp)?;
                let span = Span::new(lhs.span.start, rhs.span.end);
                lhs = Expr::new(
                    ExprKind::Binary {
                        op,
                        left: Box::new(lhs),
                        right: Box::new(rhs),
                    },
                    span,
                );
                continue;
            }

            // `as` type cast (infix-like)
            if matches!(self.peek_kind(), TokenKind::As) {
                if 23 < min_bp {
                    break;
                }
                self.advance();
                let ty = self.parse_type()?;
                let span = Span::new(lhs.span.start, ty.span.end);
                lhs = Expr::new(
                    ExprKind::Cast {
                        expr: Box::new(lhs),
                        ty,
                    },
                    span,
                );
                continue;
            }

            // `match` postfix: `expr match { ... }`
            // Only if `{` follows `match` immediately — otherwise it's keyword form
            if matches!(self.peek_kind(), TokenKind::Match)
                && matches!(self.peek_kind_ahead(1), Some(TokenKind::LBrace))
            {
                self.advance();
                self.expect(TokenKind::LBrace)?;
                let arms = self.parse_match_arms()?;
                self.expect(TokenKind::RBrace)?;
                let span = Span::new(lhs.span.start, self.prev_span().end);
                lhs = Expr::new(
                    ExprKind::Match {
                        subject: Box::new(lhs),
                        arms,
                    },
                    span,
                );
                continue;
            }

            break;
        }

        Ok(lhs)
    }

    /// Parse prefix expression (unary operators) or primary.
    fn parse_prefix(&mut self) -> Result<Expr, ParseError> {
        let start = self.span();

        // Unary operators
        match self.peek_kind() {
            TokenKind::Minus => {
                self.advance();
                let operand = self.parse_expr_bp(27)?; // unary binding power
                let span = Span::new(start.start, operand.span.end);
                Ok(Expr::new(
                    ExprKind::Unary {
                        op: UnOp::Neg,
                        operand: Box::new(operand),
                    },
                    span,
                ))
            }
            TokenKind::Bang => {
                self.advance();
                let operand = self.parse_expr_bp(27)?;
                let span = Span::new(start.start, operand.span.end);
                Ok(Expr::new(
                    ExprKind::Unary {
                        op: UnOp::Not,
                        operand: Box::new(operand),
                    },
                    span,
                ))
            }
            TokenKind::Tilde => {
                self.advance();
                let operand = self.parse_expr_bp(27)?;
                let span = Span::new(start.start, operand.span.end);
                Ok(Expr::new(
                    ExprKind::Unary {
                        op: UnOp::BitNot,
                        operand: Box::new(operand),
                    },
                    span,
                ))
            }
            TokenKind::Star => {
                self.advance();
                let operand = self.parse_expr_bp(27)?;
                let span = Span::new(start.start, operand.span.end);
                Ok(Expr::new(
                    ExprKind::Unary {
                        op: UnOp::Deref,
                        operand: Box::new(operand),
                    },
                    span,
                ))
            }
            _ => self.parse_primary(),
        }
    }

    /// Parse a primary expression (leaves and compound expressions).
    fn parse_primary(&mut self) -> Result<Expr, ParseError> {
        let start = self.span();

        match self.peek_kind() {
            // Integer literal
            TokenKind::IntLit(n) => {
                let n = *n;
                self.advance();
                Ok(Expr::new(
                    ExprKind::IntLit(n),
                    Span::new(start.start, self.prev_span().end),
                ))
            }

            // Float literal
            TokenKind::FloatLit(n) => {
                let n = *n;
                self.advance();
                Ok(Expr::new(
                    ExprKind::FloatLit(n),
                    Span::new(start.start, self.prev_span().end),
                ))
            }

            // String literal (no interpolation)
            TokenKind::StringLit(_) => {
                let mut combined = match self.peek_kind() {
                    TokenKind::StringLit(s) => s.clone(),
                    _ => unreachable!(),
                };
                self.advance();

                // Adjacent string concatenation: "foo" "bar" → "foobar"
                // Don't concat if the next string is followed by -> (match arm pattern)
                loop {
                    match self.peek_kind() {
                        TokenKind::StringLit(s2) => {
                            // Check: if the string AFTER this one is `->`, it's a match arm,
                            // not concatenation. Don't consume.
                            if matches!(self.peek_kind_ahead(1), Some(TokenKind::Arrow)) {
                                break;
                            }
                            combined.push_str(s2);
                            self.advance();
                        }
                        TokenKind::StringStart(s2) => {
                            let mut prefix = combined;
                            prefix.push_str(s2);
                            self.advance();
                            return self.parse_interpolated_string(prefix, start);
                        }
                        _ => break,
                    }
                }
                Ok(Expr::new(
                    ExprKind::StringLit(combined),
                    Span::new(start.start, self.prev_span().end),
                ))
            }

            // Interpolated string: "hello {name}!"
            TokenKind::StringStart(s) => {
                let s = s.clone();
                self.advance();
                self.parse_interpolated_string(s, start)
            }

            // Boolean literals
            TokenKind::True => {
                self.advance();
                Ok(Expr::new(
                    ExprKind::BoolLit(true),
                    Span::new(start.start, self.prev_span().end),
                ))
            }
            TokenKind::False => {
                self.advance();
                Ok(Expr::new(
                    ExprKind::BoolLit(false),
                    Span::new(start.start, self.prev_span().end),
                ))
            }

            // Nil
            TokenKind::Nil => {
                self.advance();
                Ok(Expr::new(
                    ExprKind::Nil,
                    Span::new(start.start, self.prev_span().end),
                ))
            }

            // Prefix range: ..end (half-open from start)
            TokenKind::DotDot => {
                self.advance();
                let end = self.parse_expr_bp(18)?; // higher than range bp
                let open_start = Expr::new(ExprKind::Ident("__range_open".into()), start);
                Ok(Expr::new(
                    ExprKind::Binary {
                        op: BinOp::Range,
                        left: Box::new(open_start),
                        right: Box::new(end),
                    },
                    Span::new(start.start, self.prev_span().end),
                ))
            }

            // Identifier (or struct literal, or contextual keywords)
            TokenKind::Ident(name) => {
                let name = name.clone();

                // Phase 1: contextual keywords `spawn` and `select`
                // `spawn("x")` is a function call, `spawn my_func(x)` is a spawn expression
                if name == "spawn" {
                    // Only treat as spawn keyword if NOT immediately followed by `(`
                    if !matches!(self.peek_kind_ahead(1), Some(TokenKind::LParen)) {
                        self.advance();
                        return self.parse_spawn_expr(name, start);
                    }
                }
                // `select { ... }` is select expression, `select.field` is field access
                if name == "select" {
                    if matches!(self.peek_kind_ahead(1), Some(TokenKind::LBrace)) {
                        self.advance();
                        return self.parse_select_expr(start);
                    }
                }

                self.advance();
                // Check for struct literal: Name { field: val, ... }
                if self.check(TokenKind::LBrace) && self.looks_like_struct_lit() {
                    return self.parse_struct_literal(name, start);
                }
                Ok(Expr::new(
                    ExprKind::Ident(name),
                    Span::new(start.start, self.prev_span().end),
                ))
            }

            // self keyword as expression
            TokenKind::SelfValue => {
                self.advance();
                Ok(Expr::new(
                    ExprKind::Ident("self".to_string()),
                    Span::new(start.start, self.prev_span().end),
                ))
            }

            // Dot-ident (.variant)
            TokenKind::Dot => {
                self.advance();
                if let TokenKind::Ident(_) = self.peek_kind() {
                    let name = self.expect_ident()?;
                    Ok(Expr::new(
                        ExprKind::DotIdent(name),
                        Span::new(start.start, self.prev_span().end),
                    ))
                } else {
                    Err(self.error("expected identifier after '.'"))
                }
            }

            // Grouped expression or tuple: (expr) or (a, b)
            TokenKind::LParen => {
                self.advance();
                if self.check(TokenKind::RParen) {
                    self.advance();
                    // Unit / empty tuple
                    return Ok(Expr::new(
                        ExprKind::Nil,
                        Span::new(start.start, self.prev_span().end),
                    ));
                }
                let first = self.parse_expr()?;
                if self.eat(TokenKind::Comma) {
                    // Tuple
                    let mut elements = vec![first];
                    while !self.check(TokenKind::RParen) && !self.at_eof() {
                        elements.push(self.parse_expr()?);
                        if !self.eat(TokenKind::Comma) {
                            break;
                        }
                    }
                    self.expect(TokenKind::RParen)?;
                    Ok(Expr::new(
                        ExprKind::Array(elements), // reuse Array for tuple exprs
                        Span::new(start.start, self.prev_span().end),
                    ))
                } else {
                    self.expect(TokenKind::RParen)?;
                    // Grouped expression — just return inner
                    Ok(first)
                }
            }

            // Array literal: [a, b, c]
            TokenKind::LBracket => self.parse_array_expr(),

            // If expression
            TokenKind::If => self.parse_if_expr(),

            // Prefix match expression
            TokenKind::Match => self.parse_match_expr(),

            // Map literal, closure, or block expression
            TokenKind::LBrace => {
                if self.looks_like_map_lit() {
                    self.parse_map_literal()
                } else if self.looks_like_closure() {
                    self.parse_closure()
                } else {
                    let block = self.parse_block()?;
                    let span = block.span;
                    Ok(Expr::new(ExprKind::Block(block), span))
                }
            }

            _ => Err(self.error(format!("expected expression, found {}", self.peek_kind()))),
        }
    }

    /// Parse postfix operations: call, field access, method call, index, try (?).
    fn parse_postfix(&mut self, mut expr: Expr) -> Result<Expr, ParseError> {
        loop {
            match self.peek_kind() {
                // Function call: expr(args)
                TokenKind::LParen => {
                    self.advance();
                    let args = self.parse_call_args()?;
                    self.expect(TokenKind::RParen)?;
                    let span = Span::new(expr.span.start, self.prev_span().end);
                    expr = Expr::new(
                        ExprKind::Call {
                            callee: Box::new(expr),
                            args,
                        },
                        span,
                    );
                }

                // Field access or method call: expr.name or expr.name(args)
                TokenKind::Dot => {
                    // Don't consume DotDot as field access
                    if matches!(self.peek_kind_ahead(1), Some(TokenKind::Dot)) {
                        break; // It's `..` (range), not field access
                    }
                    self.advance(); // consume '.'

                    // Check for .await
                    if self.check(TokenKind::Await) {
                        self.advance();
                        let span = Span::new(expr.span.start, self.prev_span().end);
                        expr = Expr::new(ExprKind::Await(Box::new(expr)), span);
                        continue;
                    }

                    let mut field = self.expect_ident()?;

                    // Optional turbofish: `.parse::<T>(...)` or `.parse::<Map<String, Any>>()`
                    if self.check(TokenKind::ColonColon)
                        && matches!(self.peek_kind_ahead(1), Some(TokenKind::Lt))
                    {
                        self.advance(); // ::
                        self.advance(); // <
                        // Parse type with nested generics by tracking < > depth
                        // Handle >> (Shr token) as two closing >
                        let mut depth = 1;
                        let mut type_str = String::new();
                        while depth > 0 && !self.at_eof() {
                            match self.peek_kind() {
                                TokenKind::Lt => {
                                    depth += 1;
                                    type_str.push('<');
                                    self.advance();
                                }
                                TokenKind::Gt => {
                                    depth -= 1;
                                    if depth > 0 {
                                        type_str.push('>');
                                    }
                                    self.advance();
                                }
                                TokenKind::Shr => {
                                    // >> = two closing >
                                    depth -= 2;
                                    if depth >= 0 {
                                        type_str.push('>');
                                    }
                                    self.advance();
                                }
                                TokenKind::Comma => {
                                    type_str.push_str(", ");
                                    self.advance();
                                }
                                TokenKind::Ident(n) => {
                                    type_str.push_str(n);
                                    self.advance();
                                }
                                _ => {
                                    let token_text = self.peek_kind().to_string();
                                    type_str.push_str(&token_text);
                                    self.advance();
                                }
                            }
                        }
                        field = format!("{}::<{}>", field, type_str);
                    }

                    if self.check(TokenKind::LParen) {
                        // Method call: expr.name(args)
                        self.advance();
                        let args = self.parse_call_args()?;
                        self.expect(TokenKind::RParen)?;

                        // Check for trailing closure: expr.name(args) { ... }
                        let mut all_args = args;
                        if self.check(TokenKind::LBrace) && self.looks_like_closure() {
                            let closure = self.parse_closure()?;
                            all_args.push(CallArg {
                                name: None,
                                value: closure,
                                span: self.prev_span(),
                            });
                        }

                        let span = Span::new(expr.span.start, self.prev_span().end);
                        expr = Expr::new(
                            ExprKind::MethodCall {
                                object: Box::new(expr),
                                method: field,
                                args: all_args,
                            },
                            span,
                        );
                    } else if self.check(TokenKind::LBrace)
                        && (self.looks_like_closure() || self.looks_like_trailing_block())
                    {
                        // Trailing closure/block as sole argument: expr.name { x -> body } or expr.name { expr }
                        let closure = if self.looks_like_closure() {
                            self.parse_closure()?
                        } else {
                            // Block argument: .or_else { expr }
                            let block = self.parse_block()?;
                            let span = block.span;
                            Expr::new(ExprKind::Block(block), span)
                        };
                        let span = Span::new(expr.span.start, self.prev_span().end);
                        expr = Expr::new(
                            ExprKind::MethodCall {
                                object: Box::new(expr),
                                method: field,
                                args: vec![CallArg {
                                    name: None,
                                    value: closure,
                                    span: self.prev_span(),
                                }],
                            },
                            span,
                        );
                    } else {
                        // Field access
                        let span = Span::new(expr.span.start, self.prev_span().end);
                        expr = Expr::new(
                            ExprKind::FieldAccess {
                                object: Box::new(expr),
                                field,
                            },
                            span,
                        );
                    }
                }

                // Index: expr[index] or expr[start..end] or expr[start..] or expr[..end]
                TokenKind::LBracket => {
                    // Don't treat `[]` as index — it's a new empty array expression
                    if matches!(self.peek_kind_ahead(1), Some(TokenKind::RBracket)) {
                        break;
                    }
                    self.advance();
                    let index = self.parse_expr()?;
                    // Handle half-open range: expr[start..] (no end before ])
                    if self.check(TokenKind::RBracket) {
                        // Normal index or the range expr already consumed everything
                    } else if self.check(TokenKind::DotDot) {
                        // Shouldn't happen — parse_expr should have consumed ..
                    }
                    self.expect(TokenKind::RBracket)?;
                    let span = Span::new(expr.span.start, self.prev_span().end);
                    expr = Expr::new(
                        ExprKind::Index {
                            object: Box::new(expr),
                            index: Box::new(index),
                        },
                        span,
                    );
                }

                // Try: expr?
                TokenKind::Question => {
                    self.advance();
                    let span = Span::new(expr.span.start, self.prev_span().end);
                    expr = Expr::new(ExprKind::Try(Box::new(expr)), span);
                }

                // Catch: expr catch { handler }
                TokenKind::Catch => {
                    self.advance();
                    let handler = self.parse_closure()?;
                    let span = Span::new(expr.span.start, self.prev_span().end);
                    expr = Expr::new(
                        ExprKind::MethodCall {
                            object: Box::new(expr),
                            method: "__catch__".to_string(),
                            args: vec![CallArg {
                                name: None,
                                value: handler,
                                span,
                            }],
                        },
                        span,
                    );
                }

                _ => break,
            }
        }
        Ok(expr)
    }

    fn parse_call_args(&mut self) -> Result<Vec<CallArg>, ParseError> {
        let mut args = Vec::new();
        while !self.check(TokenKind::RParen) && !self.at_eof() {
            let start = self.span();

            // Check for named argument: name: value
            let (name, value) = if self.is_named_arg() {
                let n = self.expect_ident()?;
                self.expect(TokenKind::Colon)?;
                let v = self.parse_expr()?;
                (Some(n), v)
            } else {
                (None, self.parse_expr()?)
            };

            args.push(CallArg {
                name,
                value,
                span: Span::new(start.start, self.prev_span().end),
            });

            if !self.eat(TokenKind::Comma) {
                break;
            }
        }
        Ok(args)
    }

    /// Heuristic: is the current position `ident : expr`?
    fn is_named_arg(&self) -> bool {
        matches!(self.peek_kind(), TokenKind::Ident(_))
            && matches!(self.peek_kind_ahead(1), Some(TokenKind::Colon))
    }

    fn parse_array_expr(&mut self) -> Result<Expr, ParseError> {
        let start = self.span();
        self.expect(TokenKind::LBracket)?;
        let mut elements = Vec::new();
        while !self.check(TokenKind::RBracket) && !self.at_eof() {
            elements.push(self.parse_annotation_value_or_expr()?);
            if !self.eat(TokenKind::Comma) {
                break;
            }
        }
        self.expect(TokenKind::RBracket)?;
        Ok(Expr::new(
            ExprKind::Array(elements),
            Span::new(start.start, self.prev_span().end),
        ))
    }

    /// In annotation context, parse a value (supports .dot_ident).
    /// In expression context, parse a normal expression.
    fn parse_annotation_value_or_expr(&mut self) -> Result<Expr, ParseError> {
        if self.check(TokenKind::Dot) {
            let start = self.span();
            self.advance();
            let name = self.expect_ident()?;
            Ok(Expr::new(
                ExprKind::DotIdent(name),
                Span::new(start.start, self.prev_span().end),
            ))
        } else {
            self.parse_expr()
        }
    }

    fn parse_if_expr(&mut self) -> Result<Expr, ParseError> {
        let start = self.span();
        self.expect(TokenKind::If)?;

        // Check for `if let Pattern = expr { ... }`
        if self.check(TokenKind::Let) {
            self.advance(); // consume 'let'
            let pattern = self.parse_pattern()?;
            self.expect(TokenKind::Eq)?;
            let expr = self.parse_expr()?;
            let then_block = self.parse_block()?;

            let else_branch = if self.eat(TokenKind::Else) {
                if self.check(TokenKind::If) {
                    let else_if = self.parse_if_expr()?;
                    Some(ElseBranch::ElseIf(Box::new(else_if)))
                } else {
                    Some(ElseBranch::Block(self.parse_block()?))
                }
            } else {
                None
            };

            return Ok(Expr::new(
                ExprKind::IfLet {
                    pattern: Box::new(pattern),
                    expr: Box::new(expr),
                    then_block,
                    else_branch,
                },
                Span::new(start.start, self.prev_span().end),
            ));
        }

        let condition = self.parse_expr()?;
        let then_block = self.parse_block()?;

        let else_branch = if self.eat(TokenKind::Else) {
            if self.check(TokenKind::If) {
                let else_if = self.parse_if_expr()?;
                Some(ElseBranch::ElseIf(Box::new(else_if)))
            } else {
                Some(ElseBranch::Block(self.parse_block()?))
            }
        } else {
            None
        };

        Ok(Expr::new(
            ExprKind::If {
                condition: Box::new(condition),
                then_block,
                else_branch,
            },
            Span::new(start.start, self.prev_span().end),
        ))
    }

    fn parse_match_expr(&mut self) -> Result<Expr, ParseError> {
        let start = self.span();
        self.expect(TokenKind::Match)?;
        let subject = self.parse_expr()?;
        self.expect(TokenKind::LBrace)?;
        let arms = self.parse_match_arms()?;
        self.expect(TokenKind::RBrace)?;

        Ok(Expr::new(
            ExprKind::Match {
                subject: Box::new(subject),
                arms,
            },
            Span::new(start.start, self.prev_span().end),
        ))
    }

    fn parse_match_arms(&mut self) -> Result<Vec<MatchArm>, ParseError> {
        let mut arms = Vec::new();
        while !self.check(TokenKind::RBrace) && !self.at_eof() {
            let start = self.span();
            let pattern = self.parse_pattern()?;
            self.expect(TokenKind::Arrow)?;
            // Match arm body: expression, block, or return statement
            let body = if self.check(TokenKind::Return) {
                // Allow `return expr` as match arm body — wrap in a block expr
                let ret_stmt = self.parse_stmt()?;
                Expr::new(
                    ExprKind::Block(Block {
                        stmts: vec![ret_stmt],
                        span: Span::new(start.start, self.prev_span().end),
                    }),
                    Span::new(start.start, self.prev_span().end),
                )
            } else {
                self.parse_expr()?
            };
            // Optional comma between arms
            self.eat(TokenKind::Comma);
            arms.push(MatchArm {
                pattern,
                body,
                span: Span::new(start.start, self.prev_span().end),
            });
        }
        Ok(arms)
    }

    // ── Concurrency (Phase 1) ───────────────────────────────────────────────

    /// Parse a spawn expression: `spawn func(arg1, arg2, ...)`
    ///
    /// Called after consuming the `spawn` keyword token.
    /// Produces `ExprKind::Spawn { func, args }`.
    fn parse_spawn_expr(&mut self, _keyword: String, start: Span) -> Result<Expr, ParseError> {
        // Parse only the function name (not a full call expression — parse_expr()
        // would greedily consume the argument list as a function call).
        // Use expect_ident to get the function name, then manually parse the args.
        let func_name = self.expect_ident()?;

        let func = Expr::new(
            ExprKind::Ident(func_name),
            Span::new(self.prev_span().start, self.prev_span().end),
        );

        // Expect parenthesized argument list
        if !self.eat(TokenKind::LParen) {
            return Err(self.error("expected '(' after spawn function"));
        }

        let mut args = Vec::new();
        if !self.check(TokenKind::RParen) {
            loop {
                args.push(self.parse_expr()?);
                if !self.eat(TokenKind::Comma) {
                    break;
                }
            }
        }
        self.expect(TokenKind::RParen)?;

        Ok(Expr::new(
            ExprKind::Spawn {
                func: Box::new(func),
                args,
            },
            Span::new(start.start, self.prev_span().end),
        ))
    }

    /// Parse a select expression: `select { recv(ch) -> x { body } send(ch, v) -> s { body } default { body } }`
    ///
    /// Called after consuming the `select` keyword token.
    /// Produces `ExprKind::Select { cases, default }`.
    fn parse_select_expr(&mut self, start: Span) -> Result<Expr, ParseError> {
        self.expect(TokenKind::LBrace)?;

        let mut cases = Vec::new();
        let mut default = None;

        while !self.check(TokenKind::RBrace) && !self.at_eof() {
            // Check for the `default` keyword
            if let TokenKind::Ident(name) = self.peek_kind() {
                if name == "default" {
                    self.advance(); // consume 'default'
                    self.expect(TokenKind::LBrace)?;

                    // Parse the default body
                    let body = self.parse_expr()?;
                    self.expect(TokenKind::RBrace)?;

                    default = Some(Box::new(body));
                    break; // default must be last
                }
            }

            // Parse a select case: `recv(ch) -> var { body }` or `send(ch, val) -> var { body }`
            let case = self.parse_select_case()?;
            cases.push(case);
        }

        self.expect(TokenKind::RBrace)?;

        Ok(Expr::new(
            ExprKind::Select { cases, default },
            Span::new(start.start, self.prev_span().end),
        ))
    }

    /// Parse a single select case: `recv(ch) -> var { body }` or `send(ch, val) -> var { body }`
    fn parse_select_case(&mut self) -> Result<SelectCase, ParseError> {
        // Expect: recv(expr) or send(expr, expr)
        let op = match self.expect_ident()?.as_str() {
            "recv" => {
                self.expect(TokenKind::LParen)?;
                let ch = self.parse_expr()?;
                self.expect(TokenKind::RParen)?;
                SelectOp::Recv(Box::new(ch))
            }
            "send" => {
                self.expect(TokenKind::LParen)?;
                let ch = self.parse_expr()?;
                self.expect(TokenKind::Comma)?;
                let val = self.parse_expr()?;
                self.expect(TokenKind::RParen)?;
                SelectOp::Send {
                    ch: Box::new(ch),
                    val: Box::new(val),
                }
            }
            other => {
                return Err(self.error(&format!(
                    "expected recv or send in select case, got '{other}'"
                )))
            }
        };

        // Optional variable binding: `-> var`
        let variable = if self.eat(TokenKind::Arrow) {
            Some(self.expect_ident()?)
        } else {
            None
        };

        // Body in braces
        self.expect(TokenKind::LBrace)?;
        let body = self.parse_expr()?;
        self.expect(TokenKind::RBrace)?;

        Ok(SelectCase {
            op,
            variable,
            body: Box::new(body),
        })
    }

    fn parse_struct_literal(&mut self, name: String, start: Span) -> Result<Expr, ParseError> {
        self.expect(TokenKind::LBrace)?;
        let mut fields = Vec::new();
        let mut spread = None;

        while !self.check(TokenKind::RBrace) && !self.at_eof() {
            let fstart = self.span();

            // Spread: ...expr
            if self.check(TokenKind::DotDot) {
                self.advance(); // first ..
                if self.eat(TokenKind::Dot) {
                    // consumed ... (DotDot + Dot)
                    let expr = self.parse_expr()?;
                    spread = Some(Box::new(expr));
                    self.eat(TokenKind::Comma);
                    continue;
                }
            }

            let fname = self.expect_ident()?;
            self.expect(TokenKind::Colon)?;
            let value = self.parse_expr()?;
            fields.push(StructLitField {
                name: fname,
                value,
                span: Span::new(fstart.start, self.prev_span().end),
            });
            if !self.eat(TokenKind::Comma) {
                break;
            }
        }
        self.expect(TokenKind::RBrace)?;

        Ok(Expr::new(
            ExprKind::StructLit {
                name,
                fields,
                spread,
            },
            Span::new(start.start, self.prev_span().end),
        ))
    }

    /// Heuristic: does { look like a struct literal or a block?
    /// Struct lit: `Name { field: ... }`
    /// Block: `{ stmt; ... }`
    fn looks_like_struct_lit(&self) -> bool {
        // Look for `{ ident :` pattern
        if let Some(t1) = self.peek_ahead(1) {
            if let TokenKind::Ident(_) = &t1.kind {
                if let Some(t2) = self.peek_ahead(2) {
                    return t2.kind == TokenKind::Colon;
                }
            }
            // Spread: { ...
            if t1.kind == TokenKind::DotDot {
                return true;
            }
        }
        false
    }

    // ── String Interpolation ────────────────────────────────────────────

    /// Parse an interpolated string. We've already consumed StringStart(first_text).
    /// Tokens alternate: [expr tokens] StringMid [expr tokens] ... StringEnd
    fn parse_interpolated_string(
        &mut self,
        first_text: String,
        start: Span,
    ) -> Result<Expr, ParseError> {
        let mut parts: Vec<StringPart> = Vec::new();

        if !first_text.is_empty() {
            parts.push(StringPart::Lit(first_text));
        }

        loop {
            // Parse the embedded expression
            let expr = self.parse_expr()?;
            parts.push(StringPart::Expr(Box::new(expr)));

            // Skip format specifier if present: {expr:.2f}, {expr:>10}, etc.
            // Format spec starts with `:` followed by non-`}` tokens until StringMid/StringEnd
            if self.check(TokenKind::Colon) {
                self.advance(); // consume :
                // Consume format tokens until we hit StringMid or StringEnd
                while !matches!(
                    self.peek_kind(),
                    TokenKind::StringMid(_) | TokenKind::StringEnd(_)
                ) && !self.at_eof()
                {
                    self.advance();
                }
            }

            // Next token must be StringMid or StringEnd
            match self.peek_kind() {
                TokenKind::StringMid(text) => {
                    let text = text.clone();
                    self.advance();
                    if !text.is_empty() {
                        parts.push(StringPart::Lit(text));
                    }
                    // Loop to parse next expression
                }
                TokenKind::StringEnd(text) => {
                    let text = text.clone();
                    self.advance();
                    if !text.is_empty() {
                        parts.push(StringPart::Lit(text));
                    }
                    break;
                }
                _ => {
                    return Err(self.error(format!(
                        "expected string continuation, found {}",
                        self.peek_kind()
                    )));
                }
            }
        }

        // Adjacent string concatenation after interpolation end
        // e.g., "hello {name}" "more text" → join the text parts
        while matches!(
            self.peek_kind(),
            TokenKind::StringLit(_) | TokenKind::StringStart(_)
        ) {
            match self.peek_kind() {
                TokenKind::StringLit(s2) => {
                    let s2 = s2.clone();
                    self.advance();
                    if !s2.is_empty() {
                        parts.push(StringPart::Lit(s2));
                    }
                }
                TokenKind::StringStart(s2) => {
                    let s2 = s2.clone();
                    self.advance();
                    if !s2.is_empty() {
                        parts.push(StringPart::Lit(s2));
                    }
                    // Continue parsing interpolated parts
                    loop {
                        let expr = self.parse_expr()?;
                        parts.push(StringPart::Expr(Box::new(expr)));
                        // Skip format specifier: {expr:.1}, {expr:>10}
                        if self.check(TokenKind::Colon) {
                            self.advance();
                            while !matches!(
                                self.peek_kind(),
                                TokenKind::StringMid(_) | TokenKind::StringEnd(_)
                            ) && !self.at_eof()
                            {
                                self.advance();
                            }
                        }
                        match self.peek_kind() {
                            TokenKind::StringMid(text) => {
                                let text = text.clone();
                                self.advance();
                                if !text.is_empty() {
                                    parts.push(StringPart::Lit(text));
                                }
                            }
                            TokenKind::StringEnd(text) => {
                                let text = text.clone();
                                self.advance();
                                if !text.is_empty() {
                                    parts.push(StringPart::Lit(text));
                                }
                                break;
                            }
                            _ => break,
                        }
                    }
                }
                _ => break,
            }
        }

        Ok(Expr::new(
            ExprKind::Interpolation(parts),
            Span::new(start.start, self.prev_span().end),
        ))
    }

    // ── Closures ──────────────────────────────────────────────────────────

    /// Heuristic: does { look like a closure or a block?
    /// Closure patterns:
    ///   { ident -> ... }         — untyped single param
    ///   { ident: Type -> ... }   — typed single param
    ///   { -> ... }               — no params (just arrow inside block)
    fn looks_like_closure(&self) -> bool {
        // Look ahead from `{` (current token)
        if let Some(t1) = self.peek_ahead(1) {
            // { -> ... } — parameterless closure
            if t1.kind == TokenKind::Arrow {
                return true;
            }
            // { (a, b) -> ... } — tuple param closure
            if t1.kind == TokenKind::LParen {
                // Scan forward past the parens to find ->
                let mut depth = 0;
                let mut i = 1;
                loop {
                    if let Some(t) = self.peek_ahead(i) {
                        match &t.kind {
                            TokenKind::LParen => depth += 1,
                            TokenKind::RParen => {
                                depth -= 1;
                                if depth == 0 {
                                    i += 1;
                                    break;
                                }
                            }
                            _ => {}
                        }
                        i += 1;
                        if i > 20 {
                            break;
                        }
                    } else {
                        break;
                    }
                }
                if let Some(t) = self.peek_ahead(i) {
                    if t.kind == TokenKind::Arrow {
                        return true;
                    }
                }
            }
            // { ident -> ... } or { ident: type -> ... }
            if let TokenKind::Ident(_) = &t1.kind {
                if let Some(t2) = self.peek_ahead(2) {
                    // { ident -> ... }
                    if t2.kind == TokenKind::Arrow {
                        return true;
                    }
                    // { ident: type -> ... } — scan forward to find ->
                    if t2.kind == TokenKind::Colon {
                        // Scan forward to find -> before }
                        let mut i = 3;
                        while let Some(t) = self.peek_ahead(i) {
                            match &t.kind {
                                TokenKind::Arrow => return true,
                                TokenKind::RBrace | TokenKind::Eof => return false,
                                // { ident, ident2 -> ... } multi-param
                                _ => i += 1,
                            }
                        }
                    }
                    // { ident, ... -> } — multi-param
                    if t2.kind == TokenKind::Comma {
                        let mut i = 3;
                        while let Some(t) = self.peek_ahead(i) {
                            match &t.kind {
                                TokenKind::Arrow => return true,
                                TokenKind::RBrace | TokenKind::Eof => return false,
                                _ => i += 1,
                            }
                        }
                    }
                }
            }
        }
        false
    }

    /// Check if `{` starts a map literal: `{ "key": val }` or `{ ident: val, ... }`
    /// Distinguishes from closures (which have `->`) and blocks.
    /// Heuristic: does `{` after `.method_name` look like a trailing block argument?
    /// Returns true if `{ ... }` is followed by `.` (method chain) or `,` or `)` (end of args).
    fn looks_like_trailing_block(&self) -> bool {
        // Scan ahead to find matching }, then check what follows
        if !self.check(TokenKind::LBrace) {
            return false;
        }
        let mut depth = 0;
        let mut i = 0;
        loop {
            if let Some(t) = self.peek_ahead(i) {
                match &t.kind {
                    TokenKind::LBrace => depth += 1,
                    TokenKind::RBrace => {
                        depth -= 1;
                        if depth == 0 {
                            // Check what follows the closing }
                            if let Some(after) = self.peek_ahead(i + 1) {
                                return matches!(
                                    after.kind,
                                    TokenKind::Dot
                                        | TokenKind::Comma
                                        | TokenKind::RParen
                                        | TokenKind::Question
                                        | TokenKind::Semi
                                );
                            }
                            return false;
                        }
                    }
                    _ => {}
                }
                i += 1;
                if i > 50 {
                    return false;
                } // safety limit
            } else {
                return false;
            }
        }
    }

    fn looks_like_map_lit(&self) -> bool {
        // Empty map: `{}`
        if let Some(t1) = self.peek_ahead(1) {
            if t1.kind == TokenKind::RBrace {
                return true;
            }
        }
        // { string_lit : ... } — always a map (strings can't be closure params)
        if let Some(t1) = self.peek_ahead(1) {
            if let TokenKind::StringLit(_) | TokenKind::IntLit(_) = &t1.kind {
                if let Some(t2) = self.peek_ahead(2) {
                    if t2.kind == TokenKind::Colon {
                        return true;
                    }
                }
            }
        }
        // { ident : expr , ... } — map literal (not closure, because closures use ->)
        // Heuristic: { ident : ident , } or { ident : ident . } is a map
        // BUT: { ident : type , ident : type -> } is a closure with typed params, not a map.
        // So if we see the map-like pattern, scan ahead to check for -> before }.
        if let Some(t1) = self.peek_ahead(1) {
            if let TokenKind::Ident(_) = &t1.kind {
                if let Some(t2) = self.peek_ahead(2) {
                    if t2.kind == TokenKind::Colon {
                        // Check t3: if it's followed by an ident then comma/rbrace/dot, it COULD be a map
                        if let Some(t3) = self.peek_ahead(3) {
                            if let TokenKind::Ident(_) = &t3.kind {
                                if let Some(t4) = self.peek_ahead(4) {
                                    if t4.kind == TokenKind::Comma
                                        || t4.kind == TokenKind::RBrace
                                        || t4.kind == TokenKind::Dot
                                    {
                                        // Before committing to map, scan ahead for -> which would indicate a closure
                                        let mut i = 4;
                                        while let Some(t) = self.peek_ahead(i) {
                                            match &t.kind {
                                                TokenKind::Arrow => return false, // it's a closure, not a map
                                                TokenKind::RBrace | TokenKind::Eof => break,
                                                _ => i += 1,
                                            }
                                            if i > 50 {
                                                break;
                                            } // safety limit
                                        }
                                        return true;
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
        false
    }

    /// Parse a map literal: `{ key: value, key2: value2 }`
    fn parse_map_literal(&mut self) -> Result<Expr, ParseError> {
        let start = self.span();
        self.expect(TokenKind::LBrace)?;

        let mut entries = Vec::new();

        if !self.check(TokenKind::RBrace) {
            loop {
                let key = self.parse_expr()?;
                self.expect(TokenKind::Colon)?;
                let value = self.parse_expr()?;
                entries.push((key, value));
                if !self.eat(TokenKind::Comma) {
                    break;
                }
                // Allow trailing comma
                if self.check(TokenKind::RBrace) {
                    break;
                }
            }
        }

        self.expect(TokenKind::RBrace)?;
        let span = Span::new(start.start, self.prev_span().end);
        Ok(Expr::new(ExprKind::MapLit(entries), span))
    }

    /// Parse a closure expression: `{ params -> body }`
    fn parse_closure(&mut self) -> Result<Expr, ParseError> {
        let start = self.span();
        self.expect(TokenKind::LBrace)?;

        let mut params = Vec::new();

        // Parse params until ->
        if !self.check(TokenKind::Arrow) {
            // Handle tuple destructuring: { (a, b) -> ... }
            if self.check(TokenKind::LParen) {
                self.advance(); // consume (
                while !self.check(TokenKind::RParen) && !self.at_eof() {
                    let name = self.expect_ident()?;
                    let ty = if self.eat(TokenKind::Colon) {
                        Some(self.parse_type()?)
                    } else {
                        None
                    };
                    params.push(ClosureParam { name, ty });
                    if !self.eat(TokenKind::Comma) {
                        break;
                    }
                }
                self.expect(TokenKind::RParen)?;
            } else {
                loop {
                    let name = self.expect_ident()?;
                    let ty = if self.eat(TokenKind::Colon) {
                        Some(self.parse_type()?)
                    } else {
                        None
                    };
                    params.push(ClosureParam { name, ty });
                    if !self.eat(TokenKind::Comma) {
                        break;
                    }
                }
            }
        }

        self.expect(TokenKind::Arrow)?;

        // Parse body statements
        let mut stmts = Vec::new();
        while !self.check(TokenKind::RBrace) && !self.at_eof() {
            stmts.push(self.parse_stmt()?);
        }
        self.expect(TokenKind::RBrace)?;

        Ok(Expr::new(
            ExprKind::Closure {
                params,
                body: stmts,
            },
            Span::new(start.start, self.prev_span().end),
        ))
    }

    // ── Patterns ─────────────────────────────────────────────────────────

    fn parse_pattern(&mut self) -> Result<Pattern, ParseError> {
        match self.peek_kind().clone() {
            // Wildcard
            TokenKind::Underscore => {
                self.advance();
                Ok(Pattern::Wildcard)
            }
            // Negative integer literal pattern: -42
            TokenKind::Minus => {
                let start = self.span();
                self.advance();
                if let TokenKind::IntLit(n) = self.peek_kind().clone() {
                    self.advance();
                    Ok(Pattern::Literal(Expr::new(
                        ExprKind::IntLit(-n),
                        Span::new(start.start, self.prev_span().end),
                    )))
                } else if let TokenKind::FloatLit(n) = self.peek_kind().clone() {
                    self.advance();
                    Ok(Pattern::Literal(Expr::new(
                        ExprKind::FloatLit(-n),
                        Span::new(start.start, self.prev_span().end),
                    )))
                } else {
                    Err(self.error("expected number after '-' in pattern".to_string()))
                }
            }
            // Integer literal pattern
            TokenKind::IntLit(n) => {
                let start = self.span();
                self.advance();
                Ok(Pattern::Literal(Expr::new(
                    ExprKind::IntLit(n),
                    Span::new(start.start, self.prev_span().end),
                )))
            }
            // Float literal pattern
            TokenKind::FloatLit(n) => {
                let start = self.span();
                self.advance();
                Ok(Pattern::Literal(Expr::new(
                    ExprKind::FloatLit(n),
                    Span::new(start.start, self.prev_span().end),
                )))
            }
            // String literal pattern
            TokenKind::StringLit(s) => {
                let start = self.span();
                self.advance();
                Ok(Pattern::Literal(Expr::new(
                    ExprKind::StringLit(s),
                    Span::new(start.start, self.prev_span().end),
                )))
            }
            // Bool patterns
            TokenKind::True => {
                let start = self.span();
                self.advance();
                Ok(Pattern::Literal(Expr::new(
                    ExprKind::BoolLit(true),
                    Span::new(start.start, self.prev_span().end),
                )))
            }
            TokenKind::False => {
                let start = self.span();
                self.advance();
                Ok(Pattern::Literal(Expr::new(
                    ExprKind::BoolLit(false),
                    Span::new(start.start, self.prev_span().end),
                )))
            }
            // Nil literal pattern: `nil`
            TokenKind::Nil => {
                let start = self.span();
                self.advance();
                Ok(Pattern::Literal(Expr::new(
                    ExprKind::Nil,
                    Span::new(start.start, self.prev_span().end),
                )))
            }
            // `mut` modifier on binding pattern: `mut x` or `Ok(mut val)`
            TokenKind::Mut => {
                self.advance();
                let name = self.expect_ident()?;
                // Treat `mut name` as a mutable binding (same as Ident for AST purposes)
                Ok(Pattern::Ident(name))
            }
            // Tuple pattern: (Some(x), Some(y))
            TokenKind::LParen => {
                self.advance();
                let mut fields = Vec::new();
                while !self.check(TokenKind::RParen) && !self.at_eof() {
                    fields.push(PatternField {
                        name: None,
                        pattern: self.parse_pattern()?,
                    });
                    if !self.eat(TokenKind::Comma) {
                        break;
                    }
                }
                self.expect(TokenKind::RParen)?;
                Ok(Pattern::Variant {
                    name: String::new(), // anonymous tuple pattern
                    fields,
                })
            }
            // Ident — could be binding or variant
            TokenKind::Ident(name) => {
                self.advance();
                if self.eat(TokenKind::LParen) {
                    // Variant pattern: Ok(val), Err(msg)
                    let mut fields = Vec::new();
                    while !self.check(TokenKind::RParen) && !self.at_eof() {
                        let inner = self.parse_pattern()?;
                        fields.push(PatternField {
                            name: None,
                            pattern: inner,
                        });
                        if !self.eat(TokenKind::Comma) {
                            break;
                        }
                    }
                    self.expect(TokenKind::RParen)?;
                    Ok(Pattern::Variant { name, fields })
                } else {
                    Ok(Pattern::Ident(name))
                }
            }
            _ => Err(self.error(format!("expected pattern, found {}", self.peek_kind()))),
        }
    }

    // ── Type Parsing ─────────────────────────────────────────────────────

    fn parse_type(&mut self) -> Result<TypeExpr, ParseError> {
        let start = self.span();

        // Slice type: []T
        if self.check(TokenKind::LBracket) {
            self.advance();
            self.expect(TokenKind::RBracket)?;
            let element = self.parse_type()?;
            let span = Span::new(start.start, element.span.end);
            let mut ty = TypeExpr::new(TypeExprKind::Slice(Box::new(element)), span);
            // Postfix ?
            if self.eat(TokenKind::Question) {
                let span = Span::new(ty.span.start, self.prev_span().end);
                ty = TypeExpr::new(TypeExprKind::Optional(Box::new(ty)), span);
            }
            return Ok(ty);
        }

        // Record / row type: {a: T, b: U}  and tuple-style {T, U}
        if self.check(TokenKind::LBrace) {
            self.advance();
            let mut named: Vec<(String, TypeExpr)> = Vec::new();
            let mut types: Vec<TypeExpr> = Vec::new();
            let mut all_named = true;
            while !self.check(TokenKind::RBrace) && !self.at_eof() {
                if matches!(self.peek_kind(), TokenKind::Ident(_)) && self.peek_next_is_colon()
                {
                    let field = self.expect_ident()?;
                    self.expect(TokenKind::Colon)?;
                    named.push((field, self.parse_type()?));
                } else {
                    all_named = false;
                    types.push(self.parse_type()?);
                }
                if !self.eat(TokenKind::Comma) {
                    break;
                }
            }
            self.expect(TokenKind::RBrace)?;
            let span = Span::new(start.start, self.prev_span().end);
            // A record type keeps its shape as a tuple of field types: the type
            // layer has no anonymous-record variant, and adding one would ripple
            // through every exhaustive match on TypeExprKind for a construct the
            // manifest only uses in documentation positions. Field names are
            // therefore not preserved by the checker (they are in the source).
            let _ = all_named;
            let mut ty = if !named.is_empty() && types.is_empty() {
                TypeExpr::new(
                    TypeExprKind::Tuple(named.into_iter().map(|(_, t)| t).collect()),
                    span,
                )
            } else {
                TypeExpr::new(TypeExprKind::Tuple(types), span)
            };
            if self.eat(TokenKind::Question) {
                let span = Span::new(ty.span.start, self.prev_span().end);
                ty = TypeExpr::new(TypeExprKind::Optional(Box::new(ty)), span);
            }
            return Ok(ty);
        }

        // Tuple type: (T, U)
        if self.check(TokenKind::LParen) {
            self.advance();
            let mut types = Vec::new();
            while !self.check(TokenKind::RParen) && !self.at_eof() {
                types.push(self.parse_type()?);
                if !self.eat(TokenKind::Comma) {
                    break;
                }
            }
            self.expect(TokenKind::RParen)?;
            let span = Span::new(start.start, self.prev_span().end);
            let mut ty = TypeExpr::new(TypeExprKind::Tuple(types), span);
            if self.eat(TokenKind::Question) {
                let span = Span::new(ty.span.start, self.prev_span().end);
                ty = TypeExpr::new(TypeExprKind::Optional(Box::new(ty)), span);
            }
            return Ok(ty);
        }

        // Function type: fn(T) -> U
        if self.check(TokenKind::Fn) {
            self.advance();
            self.expect(TokenKind::LParen)?;
            let mut params = Vec::new();
            while !self.check(TokenKind::RParen) && !self.at_eof() {
                params.push(self.parse_type()?);
                if !self.eat(TokenKind::Comma) {
                    break;
                }
            }
            self.expect(TokenKind::RParen)?;
            // `fn()` — a parameter type with no return annotation means it
            // returns nothing; requiring `->` rejected the documented form.
            let return_type = if self.eat(TokenKind::Arrow) {
                self.parse_type()?
            } else {
                TypeExpr::new(
                    TypeExprKind::Named("unit".to_string()),
                    Span::new(self.prev_span().start, self.prev_span().end),
                )
            };
            let span = Span::new(start.start, return_type.span.end);
            return Ok(TypeExpr::new(
                TypeExprKind::Function {
                    params,
                    return_type: Box::new(return_type),
                },
                span,
            ));
        }

        // impl Trait — static dispatch trait constraint
        if self.check(TokenKind::Impl) {
            self.advance();
            let trait_name = self.expect_ident()?;
            let span = Span::new(start.start, self.prev_span().end);
            let mut ty = TypeExpr::new(TypeExprKind::ImplTrait(trait_name), span);
            if self.eat(TokenKind::Question) {
                let span = Span::new(ty.span.start, self.prev_span().end);
                ty = TypeExpr::new(TypeExprKind::Optional(Box::new(ty)), span);
            }
            return Ok(ty);
        }

        // dyn Trait — dynamic dispatch trait object
        if self.check(TokenKind::Dyn) {
            self.advance();
            let trait_name = self.expect_ident()?;
            let span = Span::new(start.start, self.prev_span().end);
            let mut ty = TypeExpr::new(TypeExprKind::DynTrait(trait_name), span);
            if self.eat(TokenKind::Question) {
                let span = Span::new(ty.span.start, self.prev_span().end);
                ty = TypeExpr::new(TypeExprKind::Optional(Box::new(ty)), span);
            }
            return Ok(ty);
        }

        // Integer literal as type arg (for Fresh<T, 300000> duration in ms)
        if let TokenKind::IntLit(n) = self.peek_kind().clone() {
            self.advance();
            let span = Span::new(start.start, self.prev_span().end);
            return Ok(TypeExpr::new(TypeExprKind::Named(n.to_string()), span));
        }

        // Named type, possibly generic: String, Result<T>, Map<K, V>
        let name = self.expect_ident()?;

        let mut ty = if self.eat(TokenKind::Lt) {
            let mut args = Vec::new();
            while !self.check(TokenKind::Gt) && !self.check_shr_as_gt() && !self.at_eof() {
                args.push(self.parse_type()?);
                if !self.eat(TokenKind::Comma) {
                    break;
                }
            }
            self.expect_gt()?;
            // Box<T> gets its own AST node for recursive type support
            if name == "Box" && args.len() == 1 {
                TypeExpr::new(
                    TypeExprKind::Boxed(Box::new(args.into_iter().next().unwrap())),
                    Span::new(start.start, self.prev_span().end),
                )
            } else {
                TypeExpr::new(
                    TypeExprKind::Generic { name, args },
                    Span::new(start.start, self.prev_span().end),
                )
            }
        } else {
            TypeExpr::new(
                TypeExprKind::Named(name),
                Span::new(start.start, self.prev_span().end),
            )
        };

        // Postfix optional: T?
        if self.eat(TokenKind::Question) {
            let span = Span::new(ty.span.start, self.prev_span().end);
            ty = TypeExpr::new(TypeExprKind::Optional(Box::new(ty)), span);
        }

        Ok(ty)
    }

    // ── Helpers ──────────────────────────────────────────────────────────

    /// True when the token after the current one is `:` — the lookahead the
    /// record-type parser uses to tell `{a: T}` from `{T, U}`.
    fn peek_next_is_colon(&self) -> bool {
        matches!(self.peek_kind_ahead(1), Some(TokenKind::Colon))
    }

    fn peek_kind(&self) -> &TokenKind {
        &self.tokens[self.pos].kind
    }

    fn span(&self) -> Span {
        self.tokens[self.pos].span
    }

    fn prev_span(&self) -> Span {
        if self.pos > 0 {
            self.tokens[self.pos - 1].span
        } else {
            self.tokens[0].span
        }
    }

    fn peek_ahead(&self, n: usize) -> Option<&Token> {
        self.tokens.get(self.pos + n)
    }

    fn peek_kind_ahead(&self, n: usize) -> Option<&TokenKind> {
        self.tokens.get(self.pos + n).map(|tok| &tok.kind)
    }

    fn at_eof(&self) -> bool {
        matches!(self.peek_kind(), TokenKind::Eof)
    }

    fn check(&self, kind: TokenKind) -> bool {
        *self.peek_kind() == kind
    }

    fn advance(&mut self) -> &Token {
        let tok = &self.tokens[self.pos];
        if !self.at_eof() {
            self.pos += 1;
        }
        tok
    }

    /// Consume token if it matches, return true. Otherwise false.
    fn eat(&mut self, kind: TokenKind) -> bool {
        if self.check(kind) {
            self.advance();
            true
        } else {
            false
        }
    }

    fn expect(&mut self, kind: TokenKind) -> Result<&Token, ParseError> {
        if *self.peek_kind() == kind {
            Ok(self.advance())
        } else {
            Err(self.error(format!("expected '{}', found '{}'", kind, self.peek_kind())))
        }
    }

    /// Check if the current token is `>>` (Shr), which can serve as `>` in
    /// generic type contexts (e.g., `Result<Vec<i64>>`).
    fn check_shr_as_gt(&self) -> bool {
        matches!(self.peek_kind(), TokenKind::Shr)
    }

    /// Expect a `>` token, but also accept `>>` (Shr) by splitting it: consume
    /// one `>` and leave the other for the parent generic to close.
    fn expect_gt(&mut self) -> Result<(), ParseError> {
        if self.check(TokenKind::Gt) {
            self.advance();
            Ok(())
        } else if matches!(self.peek_kind(), TokenKind::Shr) {
            // Split >> into > + >: replace current Shr token with Gt
            let span = self.tokens[self.pos].span;
            self.tokens[self.pos] = Token {
                kind: TokenKind::Gt,
                span: Span::new(span.start + 1, span.end),
            };
            // Don't advance — the remaining Gt will be consumed by the caller
            Ok(())
        } else {
            Err(self.error(format!("expected '>', found '{}'", self.peek_kind())))
        }
    }

    fn expect_ident(&mut self) -> Result<String, ParseError> {
        if let TokenKind::Ident(name) = self.peek_kind() {
            let name = name.clone();
            self.advance();
            Ok(name)
        } else if let TokenKind::Secret = self.peek_kind() {
            // `secret` is a privacy-qualifier keyword, but it's also used as an
            // ordinary field/param/var name (e.g. `secret: String`). The qualifier
            // form is parsed explicitly via check(TokenKind::Secret) elsewhere, so
            // in a name position we accept it as the identifier "secret".
            self.advance();
            Ok("secret".to_string())
        } else if let TokenKind::Private = self.peek_kind() {
            self.advance();
            Ok("private".to_string())
        } else if let Some(word) = keyword_as_identifier(self.peek_kind()) {
            // Contextual keywords: `type`, `return`, `await` and friends are
            // reserved words but also ordinary field / method / parameter names
            // in real API shapes (`type: String`, `fn await(self)`). In a NAME
            // position they are identifiers; the keyword reading is only chosen
            // where the grammar expects a construct.
            self.advance();
            Ok(word.to_string())
        } else {
            Err(self.error(format!("expected identifier, found '{}'", self.peek_kind())))
        }
    }

    fn error(&self, msg: impl Into<String>) -> ParseError {
        ParseError::new(msg, self.span())
    }
}

/// Treat a reserved word as an identifier when it appears in a NAME position.
///
/// `type`, `return`, `await` and the rest are keywords, but real API shapes use
/// them as field, method and parameter names (`type: String`, `fn await(self)`).
/// The grammar only needs the keyword reading where it expects a construct, so a
/// name position takes the textual form instead of failing.
fn keyword_as_identifier(kind: &TokenKind) -> Option<String> {
    let text = kind.to_string();
    let mut chars = text.chars();
    let first = chars.next()?;
    if !(first.is_ascii_alphabetic() || first == '_') {
        return None;
    }
    if !chars.all(|c| c.is_ascii_alphanumeric() || c == '_') {
        return None;
    }
    Some(text)
}

// ── Binding Power Table (Pratt) ──────────────────────────────────────────────

/// Returns (left_bp, right_bp) for infix binary operators.
/// Left-associative: left_bp < right_bp.
/// Right-associative: left_bp > right_bp.
fn infix_binding_power(op: &TokenKind) -> Option<(u8, u8)> {
    match op {
        // Logical OR (lowest)
        TokenKind::PipePipe => Some((3, 4)),
        // Logical AND
        TokenKind::AmpAmp => Some((5, 6)),
        // Bitwise OR
        TokenKind::Pipe => Some((7, 8)),
        // Bitwise XOR
        TokenKind::Caret => Some((9, 10)),
        // Bitwise AND
        TokenKind::Amp => Some((11, 12)),
        // Equality
        TokenKind::EqEq | TokenKind::BangEq => Some((13, 14)),
        // Comparison
        TokenKind::Lt | TokenKind::Gt | TokenKind::LtEq | TokenKind::GtEq => Some((15, 16)),
        // Range
        TokenKind::DotDot => Some((17, 18)),
        // Shift
        TokenKind::Shl | TokenKind::Shr => Some((19, 20)),
        // Additive
        TokenKind::Plus | TokenKind::Minus => Some((21, 22)),
        // Multiplicative
        TokenKind::Star | TokenKind::Slash | TokenKind::Percent => Some((23, 24)),
        // Power (right-associative)
        TokenKind::StarStar => Some((26, 25)),
        _ => None,
    }
}

fn compound_assign_op(op: &TokenKind) -> Option<BinOp> {
    match op {
        TokenKind::PlusEq => Some(BinOp::Add),
        TokenKind::MinusEq => Some(BinOp::Sub),
        TokenKind::StarEq => Some(BinOp::Mul),
        TokenKind::SlashEq => Some(BinOp::Div),
        TokenKind::PercentEq => Some(BinOp::Mod),
        TokenKind::StarStarEq => Some(BinOp::Pow),
        TokenKind::ShlEq => Some(BinOp::Shl),
        TokenKind::ShrEq => Some(BinOp::Shr),
        TokenKind::AmpEq => Some(BinOp::BitAnd),
        TokenKind::PipeEq => Some(BinOp::BitOr),
        TokenKind::CaretEq => Some(BinOp::BitXor),
        _ => None,
    }
}

// ── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::lexer;

    fn parse(source: &str) -> Program {
        let (tokens, lex_errors) = lexer::tokenize(source);
        assert!(lex_errors.is_empty(), "lex errors: {lex_errors:?}");
        Parser::parse(tokens).unwrap()
    }

    fn parse_err(source: &str) -> ParseError {
        let (tokens, _) = lexer::tokenize(source);
        Parser::parse(tokens).unwrap_err()
    }

    #[test]
    fn hello_nx() {
        let source = include_str!("../tests/fixtures/hello.tl");
        let program = parse(source);
        assert_eq!(program.items.len(), 1);

        let Item::Fn(ref func) = program.items[0] else {
            panic!("expected fn");
        };
        assert_eq!(func.name, "main");
        assert!(func.params.is_empty());
        assert!(func.return_type.is_none());
        assert_eq!(func.body.stmts.len(), 1);

        let StmtKind::Expr { ref expr } = func.body.stmts[0].kind else {
            panic!("expected expr stmt");
        };
        let ExprKind::Call {
            ref callee,
            ref args,
        } = expr.kind
        else {
            panic!("expected call, got {:?}", expr.kind);
        };
        let ExprKind::Ident(ref name) = callee.kind else {
            panic!("expected ident");
        };
        assert_eq!(name, "print");
        assert_eq!(args.len(), 1);
        let ExprKind::StringLit(ref s) = args[0].value.kind else {
            panic!("expected string");
        };
        assert_eq!(s, "hello from tallow");
    }

    #[test]
    fn fn_with_params_and_return() {
        let program = parse("fn add(a: i32, b: i32) -> i32 { a + b }");
        let Item::Fn(ref f) = program.items[0] else {
            panic!();
        };
        assert_eq!(f.name, "add");
        assert_eq!(f.params.len(), 2);
        assert_eq!(f.params[0].name, "a");
        assert_eq!(f.params[1].name, "b");

        // Return type
        let Some(ref ret) = f.return_type else {
            panic!("expected return type");
        };
        let TypeExprKind::Named(ref n) = ret.kind else {
            panic!();
        };
        assert_eq!(n, "i32");
    }

    #[test]
    fn let_stmt() {
        let program = parse("fn main() { let x: i32 = 42 }");
        let Item::Fn(ref f) = program.items[0] else {
            panic!();
        };
        let StmtKind::Let {
            ref name,
            ref ty,
            ref value,
        } = f.body.stmts[0].kind
        else {
            panic!();
        };
        assert_eq!(name, "x");
        assert!(ty.is_some());
        assert!(matches!(value.kind, ExprKind::IntLit(42)));
    }

    #[test]
    fn operator_precedence() {
        // 1 + 2 * 3 should parse as 1 + (2 * 3)
        let program = parse("fn main() { 1 + 2 * 3 }");
        let Item::Fn(ref f) = program.items[0] else {
            panic!();
        };
        let StmtKind::Expr { ref expr } = f.body.stmts[0].kind else {
            panic!();
        };
        let ExprKind::Binary {
            ref op,
            ref left,
            ref right,
        } = expr.kind
        else {
            panic!("expected binary, got {:?}", expr.kind);
        };
        assert_eq!(*op, BinOp::Add);
        assert!(matches!(left.kind, ExprKind::IntLit(1)));
        // RHS should be 2 * 3
        let ExprKind::Binary {
            op: ref inner_op,
            left: ref inner_left,
            right: ref inner_right,
        } = right.kind
        else {
            panic!();
        };
        assert_eq!(*inner_op, BinOp::Mul);
        assert!(matches!(inner_left.kind, ExprKind::IntLit(2)));
        assert!(matches!(inner_right.kind, ExprKind::IntLit(3)));
    }

    #[test]
    fn method_call_chain() {
        let program = parse("fn main() { x.foo().bar(1, 2) }");
        let Item::Fn(ref f) = program.items[0] else {
            panic!();
        };
        let StmtKind::Expr { ref expr } = f.body.stmts[0].kind else {
            panic!();
        };
        // Should be: MethodCall(MethodCall(Ident(x), "foo", []), "bar", [1, 2])
        let ExprKind::MethodCall {
            ref object,
            ref method,
            ref args,
        } = expr.kind
        else {
            panic!("expected method call, got {:?}", expr.kind);
        };
        assert_eq!(method, "bar");
        assert_eq!(args.len(), 2);
        let ExprKind::MethodCall {
            object: ref inner_obj,
            method: ref inner_method,
            ..
        } = object.kind
        else {
            panic!();
        };
        assert_eq!(inner_method, "foo");
        assert!(matches!(inner_obj.kind, ExprKind::Ident(_)));
    }

    #[test]
    fn try_operator() {
        let program = parse("fn main() { fetch(url)? }");
        let Item::Fn(ref f) = program.items[0] else {
            panic!();
        };
        let StmtKind::Expr { ref expr } = f.body.stmts[0].kind else {
            panic!();
        };
        assert!(matches!(expr.kind, ExprKind::Try(_)));
    }

    #[test]
    fn if_else_expr() {
        let program = parse("fn main() { if x > 0 { 1 } else { 2 } }");
        let Item::Fn(ref f) = program.items[0] else {
            panic!();
        };
        let StmtKind::Expr { ref expr } = f.body.stmts[0].kind else {
            panic!();
        };
        let ExprKind::If {
            ref else_branch, ..
        } = expr.kind
        else {
            panic!();
        };
        assert!(else_branch.is_some());
    }

    #[test]
    fn match_expr() {
        let program =
            parse("fn main() { match status { 200 -> ok() 404 -> not_found() _ -> unknown() } }");
        let Item::Fn(ref f) = program.items[0] else {
            panic!();
        };
        let StmtKind::Expr { ref expr } = f.body.stmts[0].kind else {
            panic!();
        };
        let ExprKind::Match { ref arms, .. } = expr.kind else {
            panic!();
        };
        assert_eq!(arms.len(), 3);
        assert!(matches!(arms[2].pattern, Pattern::Wildcard));
    }

    #[test]
    fn annotation_parsing() {
        let program = parse(
            r#"@legal(basis: .public_data, purpose: "test", personal_data: false) fn foo() { }"#,
        );
        let Item::Fn(ref f) = program.items[0] else {
            panic!();
        };
        assert_eq!(f.annotations.len(), 1);
        assert_eq!(f.annotations[0].name, "legal");
        assert_eq!(f.annotations[0].args.len(), 3);
        assert_eq!(f.annotations[0].args[0].name, "basis");
        // basis value should be DotIdent("public_data")
        assert!(matches!(
            f.annotations[0].args[0].value.kind,
            ExprKind::DotIdent(_)
        ));
    }

    #[test]
    fn struct_decl() {
        let program = parse("struct Config { host: String, port: u16, max_conn: u32 = 1000 }");
        let Item::Struct(ref s) = program.items[0] else {
            panic!();
        };
        assert_eq!(s.name, "Config");
        assert_eq!(s.fields.len(), 3);
        assert_eq!(s.fields[0].name, "host");
        assert!(s.fields[2].default.is_some());
    }

    #[test]
    fn enum_decl() {
        let program = parse("enum Status { Active, Inactive, Pending(reason: String) }");
        let Item::Enum(ref e) = program.items[0] else {
            panic!();
        };
        assert_eq!(e.name, "Status");
        assert_eq!(e.variants.len(), 3);
        assert!(e.variants[2].fields.len() == 1);
    }

    #[test]
    fn type_alias_with_qualifier() {
        let program = parse("type Email = private String");
        let Item::TypeAlias(ref t) = program.items[0] else {
            panic!();
        };
        assert_eq!(t.name, "Email");
        assert_eq!(t.qualifier, Some(TypeQualifier::Private));
    }

    #[test]
    fn generic_return_type() {
        let program = parse("fn fetch(url: URL) -> Result<String> { url }");
        let Item::Fn(ref f) = program.items[0] else {
            panic!();
        };
        let Some(ref ret) = f.return_type else {
            panic!();
        };
        let TypeExprKind::Generic { ref name, ref args } = ret.kind else {
            panic!();
        };
        assert_eq!(name, "Result");
        assert_eq!(args.len(), 1);
    }

    #[test]
    fn import_decl() {
        let program = parse("import tallow.http");
        let Item::Import(ref i) = program.items[0] else {
            panic!();
        };
        assert_eq!(i.path, vec!["tallow", "http"]);
    }

    #[test]
    fn for_loop() {
        let program = parse("fn main() { for i in items { print(i) } }");
        let Item::Fn(ref f) = program.items[0] else {
            panic!();
        };
        let StmtKind::For {
            ref binding,
            ref body,
            ..
        } = f.body.stmts[0].kind
        else {
            panic!();
        };
        assert_eq!(binding, "i");
        assert_eq!(body.stmts.len(), 1);
    }

    #[test]
    fn parse_error_message() {
        let err = parse_err("fn () {}");
        assert!(err.msg.contains("expected identifier"));
    }

    #[test]
    fn pub_at_item_start_gives_flat_namespace_hint() {
        let err = parse_err("pub fn main() { }");
        assert!(
            err.msg.contains("no visibility modifiers") && err.msg.contains("remove `pub`"),
            "expected the friendly `pub` hint, got: {}",
            err.msg
        );
    }

    #[test]
    fn pub_is_usable_as_an_identifier_after_keyword_removal() {
        // `pub` is no longer a keyword: it may appear as an ordinary name.
        let program = parse("fn main() { let pub = 1 }");
        assert_eq!(program.items.len(), 1);
    }

    #[test]
    fn string_interpolation() {
        let program = parse(r#"fn main() { let msg = "hello {name}" }"#);
        let Item::Fn(ref f) = program.items[0] else {
            panic!()
        };
        let StmtKind::Let { ref value, .. } = f.body.stmts[0].kind else {
            panic!()
        };
        assert!(matches!(value.kind, ExprKind::Interpolation(_)));
        if let ExprKind::Interpolation(ref parts) = value.kind {
            assert_eq!(parts.len(), 2); // "hello " + {name}
            assert!(matches!(&parts[0], StringPart::Lit(s) if s == "hello "));
            assert!(matches!(&parts[1], StringPart::Expr(_)));
        }
    }

    #[test]
    fn closure_single_param() {
        let program = parse("fn main() { let f = { x -> x } }");
        let Item::Fn(ref f) = program.items[0] else {
            panic!()
        };
        let StmtKind::Let { ref value, .. } = f.body.stmts[0].kind else {
            panic!()
        };
        assert!(matches!(value.kind, ExprKind::Closure { .. }));
        if let ExprKind::Closure { ref params, .. } = value.kind {
            assert_eq!(params.len(), 1);
            assert_eq!(params[0].name, "x");
        }
    }

    #[test]
    fn closure_typed_param() {
        let program = parse("fn main() { let f = { x: i32 -> x + 1 } }");
        let Item::Fn(ref f) = program.items[0] else {
            panic!()
        };
        let StmtKind::Let { ref value, .. } = f.body.stmts[0].kind else {
            panic!()
        };
        if let ExprKind::Closure { ref params, .. } = value.kind {
            assert_eq!(params[0].name, "x");
            assert!(params[0].ty.is_some());
        } else {
            panic!("expected closure");
        }
    }

    #[test]
    fn let_destructure() {
        let program = parse("fn main() { let (a, b, c) = some_fn() }");
        let Item::Fn(ref f) = program.items[0] else {
            panic!()
        };
        let StmtKind::LetDestructure { ref names, .. } = f.body.stmts[0].kind else {
            panic!("expected LetDestructure");
        };
        assert_eq!(names, &["a", "b", "c"]);
    }

    #[test]
    fn self_in_impl_method() {
        let program = parse(
            r#"
            struct Foo { x: i32 }
            impl Foo {
                fn get_x(self) -> i32 {
                    self.x
                }
            }
        "#,
        );
        assert_eq!(program.items.len(), 2);
        let Item::Impl(ref imp) = program.items[1] else {
            panic!()
        };
        assert_eq!(imp.target, "Foo");
        assert_eq!(imp.methods[0].name, "get_x");
        assert_eq!(imp.methods[0].params[0].name, "self");
    }

    #[test]
    fn compound_assign_desugar() {
        let program = parse(
            r#"
            fn main() {
                var x = 0
                x += 1
                x -= 2
                x *= 3
                x /= 4
                x %= 5
            }
        "#,
        );
        let Item::Fn(ref func) = program.items[0] else {
            panic!()
        };
        // Each compound assign desugars to Assign(x, Binary(x, op, rhs))
        // So we should have 6 statements: 1 var + 5 assigns
        assert_eq!(func.body.stmts.len(), 6);
    }

    #[test]
    fn while_let_parse() {
        let program = parse(
            r#"
            fn main() {
                while let Ok(v) = get() {
                    print(v)
                }
            }
        "#,
        );
        let Item::Fn(ref func) = program.items[0] else {
            panic!()
        };
        assert!(matches!(
            &func.body.stmts[0].kind,
            StmtKind::WhileLet { .. }
        ));
    }

    #[test]
    fn bail_if_parse() {
        let program = parse(
            r#"
            fn check(x: i32) -> Result<i32> {
                bail_if x < 0, "negative"
                Ok(x)
            }
        "#,
        );
        let Item::Fn(ref func) = program.items[0] else {
            panic!()
        };
        // bail_if desugars to an if/return, so first stmt is Expr(If {...})
        assert!(matches!(&func.body.stmts[0].kind, StmtKind::Expr { .. }));
    }

    #[test]
    fn power_operator_parse() {
        let program = parse(
            r#"
            fn main() {
                let x = 2 ** 10
            }
        "#,
        );
        let Item::Fn(ref func) = program.items[0] else {
            panic!()
        };
        if let StmtKind::Let { value, .. } = &func.body.stmts[0].kind {
            assert!(matches!(
                &value.kind,
                ExprKind::Binary { op: BinOp::Pow, .. }
            ));
        } else {
            panic!("expected let");
        }
    }

    #[test]
    fn shift_operators_parse() {
        let program = parse(
            r#"
            fn main() {
                let a = 1 << 8
                let b = 256 >> 4
            }
        "#,
        );
        let Item::Fn(ref func) = program.items[0] else {
            panic!()
        };
        if let StmtKind::Let { value, .. } = &func.body.stmts[0].kind {
            assert!(matches!(
                &value.kind,
                ExprKind::Binary { op: BinOp::Shl, .. }
            ));
        } else {
            panic!("expected let with shl");
        }
        if let StmtKind::Let { value, .. } = &func.body.stmts[1].kind {
            assert!(matches!(
                &value.kind,
                ExprKind::Binary { op: BinOp::Shr, .. }
            ));
        } else {
            panic!("expected let with shr");
        }
    }

    #[test]
    fn negative_pattern_parse() {
        let program = parse(
            r#"
            fn main() {
                match x {
                    -1 -> print("neg one")
                    0  -> print("zero")
                    _  -> print("other")
                }
            }
        "#,
        );
        let Item::Fn(ref func) = program.items[0] else {
            panic!()
        };
        // Just verify it parses without error
        assert_eq!(func.body.stmts.len(), 1);
    }

    #[test]
    fn generic_function_parse() {
        let program = parse(
            r#"
            fn first<T>(items: []T) -> T {
                items[0]
            }
        "#,
        );
        let Item::Fn(ref func) = program.items[0] else {
            panic!()
        };
        assert_eq!(func.name, "first");
        assert_eq!(func.type_params, vec!["T"]);
        assert_eq!(func.params.len(), 1);
    }

    #[test]
    fn generic_function_multiple_params() {
        let program = parse(
            r#"
            fn transform<K, V>(key: K, val: V) -> Map<K, V> {
                Map()
            }
        "#,
        );
        let Item::Fn(ref func) = program.items[0] else {
            panic!()
        };
        assert_eq!(func.type_params, vec!["K", "V"]);
        assert_eq!(func.params.len(), 2);
    }

    #[test]
    fn non_generic_function_no_type_params() {
        let program = parse(
            r#"
            fn add(a: i32, b: i32) -> i32 {
                a + b
            }
        "#,
        );
        let Item::Fn(ref func) = program.items[0] else {
            panic!()
        };
        assert!(func.type_params.is_empty());
    }

    #[test]
    fn generic_struct_parse() {
        let program = parse(
            r#"
            struct Cache<K, V> {
                data: Map<K, V>
            }
        "#,
        );
        let Item::Struct(ref s) = program.items[0] else {
            panic!()
        };
        assert_eq!(s.name, "Cache");
        assert_eq!(s.type_params, vec!["K", "V"]);
        assert_eq!(s.fields.len(), 1);
    }

    #[test]
    fn struct_default_value_parse() {
        let program = parse(
            r#"
            struct Config {
                host: String,
                port: u16,
                max_conn: u32 = 1000
            }
        "#,
        );
        let Item::Struct(ref s) = program.items[0] else {
            panic!()
        };
        assert_eq!(s.fields.len(), 3);
        assert!(s.fields[0].default.is_none());
        assert!(s.fields[1].default.is_none());
        assert!(s.fields[2].default.is_some());
    }

    #[test]
    fn generic_enum_parse() {
        let program = parse(
            r#"
            enum Result<T> {
                Ok(value: T),
                Err(msg: String)
            }
        "#,
        );
        let Item::Enum(ref e) = program.items[0] else {
            panic!()
        };
        assert_eq!(e.name, "Result");
        assert_eq!(e.type_params, vec!["T"]);
        assert_eq!(e.variants.len(), 2);
    }

    #[test]
    fn parse_import() {
        let program = parse("import tallow.http");
        assert!(matches!(program.items[0], Item::Import(_)));
        let Item::Import(ref i) = program.items[0] else {
            panic!()
        };
        assert_eq!(i.path, vec!["tallow", "http"]);
    }

    #[test]
    fn parse_type_alias_private() {
        let program = parse("type Email = private String");
        let Item::TypeAlias(ref ta) = program.items[0] else {
            panic!()
        };
        assert_eq!(ta.name, "Email");
        assert_eq!(ta.qualifier, Some(crate::ast::TypeQualifier::Private));
    }

    #[test]
    fn parse_type_alias_secret() {
        let program = parse("type Password = secret String");
        let Item::TypeAlias(ref ta) = program.items[0] else {
            panic!()
        };
        assert_eq!(ta.name, "Password");
        assert_eq!(ta.qualifier, Some(crate::ast::TypeQualifier::Secret));
    }

    #[test]
    fn parse_const_decl() {
        let program = parse(r#"const MAX: u32 = 100"#);
        let Item::Const(ref c) = program.items[0] else {
            panic!()
        };
        assert_eq!(c.name, "MAX");
        assert!(c.ty.is_some());
    }

    #[test]
    fn parse_impl_block() {
        let program = parse(
            r#"
            struct Foo { x: i32 }
            impl Foo {
                fn get_x(self) -> i32 { self.x }
                fn double(self) -> i32 { self.x * 2 }
            }
        "#,
        );
        assert!(matches!(program.items[1], Item::Impl(_)));
        let Item::Impl(ref imp) = program.items[1] else {
            panic!()
        };
        assert_eq!(imp.target, "Foo");
        assert_eq!(imp.methods.len(), 2);
    }

    #[test]
    fn parse_async_function() {
        let program = parse(r#"async fn fetch_data(url: String) -> String { url }"#);
        let Item::Fn(ref f) = program.items[0] else {
            panic!()
        };
        assert!(f.is_async);
        assert_eq!(f.name, "fetch_data");
    }

    #[test]
    fn parse_while_let() {
        let program = parse(
            r#"
            fn main() {
                while let Ok(v) = get_next() {
                    print(v)
                }
            }
        "#,
        );
        let Item::Fn(ref f) = program.items[0] else {
            panic!()
        };
        let stmt = &f.body.stmts[0];
        assert!(matches!(stmt.kind, StmtKind::WhileLet { .. }));
    }

    #[test]
    fn parse_match_with_patterns() {
        let program = parse(
            r#"
            fn main() {
                match x {
                    0 -> print("zero")
                    1 -> print("one")
                    _ -> print("other")
                }
            }
        "#,
        );
        let Item::Fn(ref f) = program.items[0] else {
            panic!()
        };
        let stmt = &f.body.stmts[0];
        if let StmtKind::Expr { expr } = &stmt.kind {
            if let ExprKind::Match { arms, .. } = &expr.kind {
                assert_eq!(arms.len(), 3);
            } else {
                panic!("expected match expression");
            }
        } else {
            panic!("expected expression statement");
        }
    }

    #[test]
    fn parse_closure() {
        let program = parse(
            r#"
            fn main() {
                let f = { x: i32, y: i32 -> x + y }
            }
        "#,
        );
        let Item::Fn(ref f) = program.items[0] else {
            panic!()
        };
        let stmt = &f.body.stmts[0];
        if let StmtKind::Let { value, .. } = &stmt.kind {
            assert!(matches!(value.kind, ExprKind::Closure { .. }));
        } else {
            panic!("expected let statement");
        }
    }

    #[test]
    fn parse_bail_desugars_to_return_err() {
        let program = parse(
            r#"
            fn main() {
                bail "error message"
            }
        "#,
        );
        let Item::Fn(ref f) = program.items[0] else {
            panic!()
        };
        // bail desugars to return Err(...)
        assert!(matches!(f.body.stmts[0].kind, StmtKind::Return(Some(_))));
    }

    // ── Additional parser tests ───────────────────────────────────────────

    #[test]
    fn parse_map_literal() {
        let program = parse(r#"fn main() { let m = {"a": 1, "b": 2} }"#);
        let Item::Fn(ref f) = program.items[0] else {
            panic!()
        };
        if let StmtKind::Let { ref value, .. } = f.body.stmts[0].kind {
            assert!(matches!(value.kind, ExprKind::MapLit(_)));
        } else {
            panic!("expected let");
        }
    }

    #[test]
    fn parse_empty_array() {
        let program = parse("fn main() { let a = [] }");
        let Item::Fn(ref f) = program.items[0] else {
            panic!()
        };
        if let StmtKind::Let { ref value, .. } = f.body.stmts[0].kind {
            if let ExprKind::Array(ref elems) = value.kind {
                assert_eq!(elems.len(), 0);
            } else {
                panic!("expected array");
            }
        }
    }

    #[test]
    fn parse_nested_field_access() {
        let program = parse("fn main() { let x = a.b.c }");
        let Item::Fn(ref f) = program.items[0] else {
            panic!()
        };
        if let StmtKind::Let { ref value, .. } = f.body.stmts[0].kind {
            assert!(matches!(value.kind, ExprKind::FieldAccess { .. }));
        } else {
            panic!("expected let");
        }
    }

    #[test]
    fn parse_index_expression() {
        let program = parse("fn main() { let x = arr[0] }");
        let Item::Fn(ref f) = program.items[0] else {
            panic!()
        };
        if let StmtKind::Let { ref value, .. } = f.body.stmts[0].kind {
            assert!(matches!(value.kind, ExprKind::Index { .. }));
        } else {
            panic!("expected let");
        }
    }

    #[test]
    fn parse_method_call_chain() {
        let program = parse(r#"fn main() { let x = "hello".trim().upper() }"#);
        let Item::Fn(ref f) = program.items[0] else {
            panic!()
        };
        if let StmtKind::Let { ref value, .. } = f.body.stmts[0].kind {
            assert!(matches!(value.kind, ExprKind::MethodCall { .. }));
        } else {
            panic!("expected let");
        }
    }

    #[test]
    fn parse_if_else_if_else() {
        let program = parse(
            r#"
            fn main() {
                if true { 1 } else if false { 2 } else { 3 }
            }
        "#,
        );
        let Item::Fn(ref f) = program.items[0] else {
            panic!()
        };
        if let StmtKind::Expr { ref expr } = f.body.stmts[0].kind {
            if let ExprKind::If {
                else_branch: Some(ElseBranch::ElseIf(_)),
                ..
            } = expr.kind
            {
                // Good — else if parsed correctly
            } else {
                panic!("expected if with else-if branch");
            }
        }
    }

    #[test]
    fn parse_for_range() {
        let program = parse("fn main() { for i in 0..10 { print(i) } }");
        let Item::Fn(ref f) = program.items[0] else {
            panic!()
        };
        assert!(matches!(f.body.stmts[0].kind, StmtKind::For { .. }));
    }

    #[test]
    fn parse_while_loop() {
        let program = parse("fn main() { while true { break } }");
        let Item::Fn(ref f) = program.items[0] else {
            panic!()
        };
        assert!(matches!(f.body.stmts[0].kind, StmtKind::While { .. }));
    }

    #[test]
    fn parse_loop_stmt() {
        let program = parse("fn main() { loop { break } }");
        let Item::Fn(ref f) = program.items[0] else {
            panic!()
        };
        assert!(matches!(f.body.stmts[0].kind, StmtKind::Loop { .. }));
    }

    #[test]
    fn parse_return_with_value() {
        let program = parse("fn f() -> i32 { return 42 }");
        let Item::Fn(ref f) = program.items[0] else {
            panic!()
        };
        assert!(matches!(f.body.stmts[0].kind, StmtKind::Return(Some(_))));
    }

    #[test]
    fn parse_return_without_value() {
        let program = parse("fn f() { return }");
        let Item::Fn(ref f) = program.items[0] else {
            panic!()
        };
        assert!(matches!(f.body.stmts[0].kind, StmtKind::Return(None)));
    }

    #[test]
    fn parse_cast_expression() {
        let program = parse("fn main() { let x = 42 as f64 }");
        let Item::Fn(ref f) = program.items[0] else {
            panic!()
        };
        if let StmtKind::Let { ref value, .. } = f.body.stmts[0].kind {
            assert!(matches!(value.kind, ExprKind::Cast { .. }));
        }
    }

    #[test]
    fn parse_try_expression() {
        let program = parse("fn f() -> Result<i32> { let x = something()?\n x }");
        let Item::Fn(ref f) = program.items[0] else {
            panic!()
        };
        if let StmtKind::Let { ref value, .. } = f.body.stmts[0].kind {
            assert!(matches!(value.kind, ExprKind::Try(_)));
        }
    }

    #[test]
    fn parse_string_interpolation() {
        let program = parse(r#"fn main() { let s = "hello {name}" }"#);
        let Item::Fn(ref f) = program.items[0] else {
            panic!()
        };
        if let StmtKind::Let { ref value, .. } = f.body.stmts[0].kind {
            assert!(matches!(value.kind, ExprKind::Interpolation(_)));
        }
    }

    #[test]
    fn parse_unary_not() {
        let program = parse("fn main() { let x = !true }");
        let Item::Fn(ref f) = program.items[0] else {
            panic!()
        };
        if let StmtKind::Let { ref value, .. } = f.body.stmts[0].kind {
            if let ExprKind::Unary { op, .. } = value.kind {
                assert_eq!(op, UnOp::Not);
            } else {
                panic!("expected unary");
            }
        }
    }

    #[test]
    fn parse_unary_neg() {
        let program = parse("fn main() { let x = -42 }");
        let Item::Fn(ref f) = program.items[0] else {
            panic!()
        };
        if let StmtKind::Let { ref value, .. } = f.body.stmts[0].kind {
            // -42 might parse as IntLit(-42) or Unary(Neg, IntLit(42))
            match &value.kind {
                ExprKind::IntLit(n) => assert!(*n < 0),
                ExprKind::Unary { op, .. } => assert_eq!(*op, UnOp::Neg),
                _ => panic!("expected neg literal or unary"),
            }
        }
    }

    #[test]
    fn parse_struct_literal() {
        let program = parse(r#"fn main() { let p = Point { x: 1, y: 2 } }"#);
        let Item::Fn(ref f) = program.items[0] else {
            panic!()
        };
        if let StmtKind::Let { ref value, .. } = f.body.stmts[0].kind {
            if let ExprKind::StructLit {
                ref name,
                ref fields,
                ..
            } = value.kind
            {
                assert_eq!(name, "Point");
                assert_eq!(fields.len(), 2);
            } else {
                panic!("expected struct literal");
            }
        }
    }

    #[test]
    fn parse_struct_spread() {
        let program = parse("fn main() { let p = Point { ...other, x: 1 } }");
        let Item::Fn(ref f) = program.items[0] else {
            panic!()
        };
        if let StmtKind::Let { ref value, .. } = f.body.stmts[0].kind {
            if let ExprKind::StructLit { spread, .. } = &value.kind {
                assert!(spread.is_some());
            } else {
                panic!("expected struct literal with spread");
            }
        }
    }

    #[test]
    fn parse_assign_statement() {
        let program = parse("fn main() { var x = 0\n x = 42 }");
        let Item::Fn(ref f) = program.items[0] else {
            panic!()
        };
        if let StmtKind::Expr { ref expr } = f.body.stmts[1].kind {
            assert!(matches!(expr.kind, ExprKind::Assign { .. }));
        }
    }

    #[test]
    fn parse_named_call_args() {
        let program = parse(r#"fn main() { fetch("url", timeout: 5) }"#);
        let Item::Fn(ref f) = program.items[0] else {
            panic!()
        };
        if let StmtKind::Expr { ref expr } = f.body.stmts[0].kind {
            if let ExprKind::Call { ref args, .. } = expr.kind {
                assert_eq!(args.len(), 2);
                assert_eq!(args[1].name.as_deref(), Some("timeout"));
            }
        }
    }

    #[test]
    fn parse_block_expression() {
        let program = parse("fn main() { let x = { let a = 1\n a + 2 } }");
        let Item::Fn(ref f) = program.items[0] else {
            panic!()
        };
        if let StmtKind::Let { ref value, .. } = f.body.stmts[0].kind {
            assert!(matches!(value.kind, ExprKind::Block(_)));
        }
    }

    #[test]
    fn parse_continue_stmt() {
        let program = parse("fn main() { for i in 0..10 { continue } }");
        let Item::Fn(ref f) = program.items[0] else {
            panic!()
        };
        if let StmtKind::For { ref body, .. } = f.body.stmts[0].kind {
            assert!(matches!(body.stmts[0].kind, StmtKind::Continue));
        }
    }

    #[test]
    fn parse_break_stmt() {
        let program = parse("fn main() { loop { break } }");
        let Item::Fn(ref f) = program.items[0] else {
            panic!()
        };
        if let StmtKind::Loop { ref body } = f.body.stmts[0].kind {
            assert!(matches!(body.stmts[0].kind, StmtKind::Break));
        }
    }

    // ── Extended Parser Tests ───────────────────────────────────────────

    #[test]
    fn parse_const_item() {
        let program = parse("const MAX = 100");
        assert!(matches!(&program.items[0], Item::Const(_)));
    }

    #[test]
    fn parse_enum_declaration() {
        let program = parse("enum Color { Red, Green, Blue }");
        assert!(matches!(&program.items[0], Item::Enum(_)));
    }

    #[test]
    fn parse_impl_with_method() {
        let program = parse(
            r#"
            struct Foo { x: i64 }
            impl Foo { fn get_x(self) -> i64 { self.x } }
        "#,
        );
        assert!(program.items.iter().any(|i| matches!(i, Item::Impl(_))));
    }

    #[test]
    fn parse_type_alias() {
        let program = parse("type Email = private String");
        assert!(matches!(&program.items[0], Item::TypeAlias { .. }));
    }

    #[test]
    fn parse_import_statement() {
        let program = parse("import tallow.http");
        assert!(matches!(&program.items[0], Item::Import(_)));
    }

    #[test]
    fn parse_legal_annotation() {
        let program = parse(
            r#"
            @legal(basis: .public_data, purpose: "test")
            fn scrape() { }
        "#,
        );
        let Item::Fn(ref f) = program.items[0] else {
            panic!()
        };
        assert!(!f.annotations.is_empty());
    }

    #[test]
    fn parse_agent_task_annotation() {
        let program = parse(
            r#"
            @agent_task(id: task_id, timeout: 60, can_write: false)
            fn research() { }
        "#,
        );
        let Item::Fn(ref f) = program.items[0] else {
            panic!()
        };
        assert!(f.annotations.iter().any(|a| a.name == "agent_task"));
    }

    #[test]
    fn parse_async_fn_decl() {
        let program = parse("async fn fetch_data() { }");
        let Item::Fn(ref f) = program.items[0] else {
            panic!()
        };
        assert!(f.is_async);
    }

    #[test]
    fn parse_generic_function() {
        let program = parse("fn first<T>(items: []T) -> T { items[0] }");
        let Item::Fn(ref f) = program.items[0] else {
            panic!()
        };
        assert_eq!(f.type_params.len(), 1);
        assert_eq!(f.type_params[0], "T");
    }

    #[test]
    fn parse_generic_struct() {
        let program = parse("struct Pair<A, B> { first: A, second: B }");
        let Item::Struct(ref s) = program.items[0] else {
            panic!()
        };
        assert_eq!(s.type_params.len(), 2);
    }

    #[test]
    fn parse_if_let_expression() {
        let program = parse(
            r#"
            fn main() {
                if let Ok(val) = compute() {
                    print(val)
                }
            }
        "#,
        );
        let Item::Fn(ref f) = program.items[0] else {
            panic!()
        };
        // The first statement should be an expression statement containing IfLet
        assert!(!f.body.stmts.is_empty());
    }

    #[test]
    fn parse_match_expression() {
        let program = parse(
            r#"
            fn main() {
                let x = 1
                x match {
                    1 -> print("one")
                    2 -> print("two")
                    _ -> print("other")
                }
            }
        "#,
        );
        let Item::Fn(ref f) = program.items[0] else {
            panic!()
        };
        assert!(f.body.stmts.len() >= 2);
    }

    #[test]
    fn parse_bail_if_statement() {
        let program = parse(
            r#"
            fn check(n: i64) {
                bail_if n < 0, "negative"
            }
        "#,
        );
        let Item::Fn(ref f) = program.items[0] else {
            panic!()
        };
        assert!(!f.body.stmts.is_empty());
    }

    #[test]
    fn parse_while_let_pattern() {
        let program = parse(
            r#"
            fn main() {
                while let Ok(val) = next() {
                    print(val)
                }
            }
        "#,
        );
        let Item::Fn(ref f) = program.items[0] else {
            panic!()
        };
        assert!(!f.body.stmts.is_empty());
    }

    #[test]
    fn parse_struct_with_defaults() {
        let program = parse("struct Config { port: u16 = 8080, debug: bool = false }");
        let Item::Struct(ref s) = program.items[0] else {
            panic!()
        };
        assert!(s.fields[0].default.is_some());
        assert!(s.fields[1].default.is_some());
    }

    #[test]
    fn parse_enum_with_data_variants() {
        let program = parse("enum Result { Ok(value: i64), Err(msg: String) }");
        let Item::Enum(ref e) = program.items[0] else {
            panic!()
        };
        assert_eq!(e.variants.len(), 2);
    }

    #[test]
    fn parse_multiple_annotations() {
        let program = parse(
            r#"
            @agent_task(id: task_id, timeout: 60)
            @legal(basis: .research, purpose: "test")
            fn research() { }
        "#,
        );
        let Item::Fn(ref f) = program.items[0] else {
            panic!()
        };
        assert_eq!(f.annotations.len(), 2);
    }

    #[test]
    fn parse_nested_generics() {
        let program = parse("fn process(items: []Result<i64>) { }");
        let Item::Fn(ref f) = program.items[0] else {
            panic!()
        };
        assert!(!f.params.is_empty());
    }

    #[test]
    fn parse_closure_expression() {
        let program = parse("fn main() { let f = { x: i64 -> x * 2 } }");
        let Item::Fn(ref f) = program.items[0] else {
            panic!()
        };
        assert!(!f.body.stmts.is_empty());
    }

    #[test]
    fn parse_return_expression() {
        let program = parse("fn add(a: i64, b: i64) -> i64 { return a + b }");
        let Item::Fn(ref f) = program.items[0] else {
            panic!()
        };
        assert!(matches!(&f.body.stmts[0].kind, StmtKind::Return(Some(_))));
    }

    // ── New Edge-Case Tests ──────────────────────────────────────────────

    // 1. Struct with four fields, two having defaults
    #[test]
    fn parse_struct_multiple_fields_with_defaults() {
        let program = parse(
            r#"
            struct Server {
                host:     String,
                port:     u16 = 8080,
                tls:      bool = false,
                max_conn: u32 = 1000
            }
        "#,
        );
        let Item::Struct(ref s) = program.items[0] else {
            panic!("expected struct")
        };
        assert_eq!(s.name, "Server");
        assert_eq!(s.fields.len(), 4);
        assert!(s.fields[0].default.is_none(), "host should have no default");
        assert!(
            s.fields[1].default.is_some(),
            "port should have default 8080"
        );
        assert!(
            s.fields[2].default.is_some(),
            "tls should have default false"
        );
        assert!(
            s.fields[3].default.is_some(),
            "max_conn should have default 1000"
        );
    }

    // 2. Enum with three variants: two unit, one with a data field
    #[test]
    fn parse_enum_mixed_variants() {
        let program = parse(
            r#"
            enum Status {
                Active,
                Inactive,
                Pending(reason: String)
            }
        "#,
        );
        let Item::Enum(ref e) = program.items[0] else {
            panic!("expected enum")
        };
        assert_eq!(e.name, "Status");
        assert_eq!(e.variants.len(), 3);
        assert_eq!(e.variants[0].name, "Active");
        assert!(e.variants[0].fields.is_empty());
        assert_eq!(e.variants[1].name, "Inactive");
        assert!(e.variants[1].fields.is_empty());
        assert_eq!(e.variants[2].name, "Pending");
        assert_eq!(e.variants[2].fields.len(), 1);
        assert_eq!(e.variants[2].fields[0].name, "reason");
    }

    // 3. Impl block with three methods
    #[test]
    fn parse_impl_multiple_methods() {
        let program = parse(
            r#"
            struct Point { x: f64, y: f64 }
            impl Point {
                fn new(x: f64, y: f64) -> Point { Point { x: x, y: y } }
                fn scale(self, factor: f64) -> Point { Point { x: self.x * factor, y: self.y * factor } }
                fn magnitude(self) -> f64 { self.x }
            }
        "#,
        );
        let Item::Impl(ref imp) = program.items[1] else {
            panic!("expected impl")
        };
        assert_eq!(imp.target, "Point");
        assert_eq!(imp.methods.len(), 3);
        assert_eq!(imp.methods[0].name, "new");
        assert_eq!(imp.methods[1].name, "scale");
        assert_eq!(imp.methods[2].name, "magnitude");
    }

    // 4. Const with explicit type annotation
    #[test]
    fn parse_const_with_explicit_type() {
        let program = parse("const MAX_CONNECTIONS: u32 = 100_000");
        let Item::Const(ref c) = program.items[0] else {
            panic!("expected const")
        };
        assert_eq!(c.name, "MAX_CONNECTIONS");
        assert!(c.ty.is_some());
        let ty = c.ty.as_ref().unwrap();
        assert!(matches!(ty.kind, TypeExprKind::Named(ref n) if n == "u32"));
        assert!(matches!(c.value.kind, ExprKind::IntLit(100_000)));
    }

    // 5. Type alias with private qualifier
    #[test]
    fn parse_type_alias_private_qualifier() {
        let program = parse("type Phone = private String");
        let Item::TypeAlias(ref ta) = program.items[0] else {
            panic!("expected type alias")
        };
        assert_eq!(ta.name, "Phone");
        assert_eq!(ta.qualifier, Some(TypeQualifier::Private));
        assert!(matches!(ta.ty.kind, TypeExprKind::Named(ref n) if n == "String"));
    }

    // 6. Type alias with secret qualifier
    #[test]
    fn parse_type_alias_secret_qualifier() {
        let program = parse("type APIKey = secret String");
        let Item::TypeAlias(ref ta) = program.items[0] else {
            panic!("expected type alias")
        };
        assert_eq!(ta.name, "APIKey");
        assert_eq!(ta.qualifier, Some(TypeQualifier::Secret));
    }

    // 7. Import with a three-segment dotted path
    #[test]
    fn parse_import_three_segment_path() {
        let program = parse("import tallow.crypto.pqc");
        let Item::Import(ref i) = program.items[0] else {
            panic!("expected import")
        };
        assert_eq!(i.path, vec!["tallow", "crypto", "pqc"]);
    }

    // 8. Multiple imports parsed in order
    #[test]
    fn parse_multiple_imports() {
        let program = parse("import tallow.http\nimport tallow.crypto\nimport tallow.log");
        assert_eq!(program.items.len(), 3);
        let Item::Import(ref a) = program.items[0] else {
            panic!()
        };
        let Item::Import(ref b) = program.items[1] else {
            panic!()
        };
        let Item::Import(ref c) = program.items[2] else {
            panic!()
        };
        assert_eq!(a.path, vec!["tallow", "http"]);
        assert_eq!(b.path, vec!["tallow", "crypto"]);
        assert_eq!(c.path, vec!["tallow", "log"]);
    }

    // 9. @legal annotation with all common fields
    #[test]
    fn parse_legal_annotation_full_args() {
        let program = parse(
            r#"
            @legal(
                basis: .public_data,
                purpose: "price monitoring",
                personal_data: false,
                retain_for: 30,
                robots_txt: .respect
            )
            fn scrape_prices() { }
        "#,
        );
        let Item::Fn(ref f) = program.items[0] else {
            panic!("expected fn")
        };
        assert_eq!(f.annotations.len(), 1);
        let ann = &f.annotations[0];
        assert_eq!(ann.name, "legal");
        // verify all five named args are present
        assert_eq!(ann.args.len(), 5);
        let names: Vec<&str> = ann.args.iter().map(|a| a.name.as_str()).collect();
        assert!(names.contains(&"basis"));
        assert!(names.contains(&"purpose"));
        assert!(names.contains(&"personal_data"));
        assert!(names.contains(&"retain_for"));
        assert!(names.contains(&"robots_txt"));
    }

    // 10. @agent_task with permission flags
    #[test]
    fn parse_agent_task_permission_flags() {
        let program = parse(
            r#"
            @agent_task(id: task_id, timeout: 120, can_write: false, can_spawn: false, memory_limit: 256)
            async fn run_agent() { }
        "#,
        );
        let Item::Fn(ref f) = program.items[0] else {
            panic!("expected fn")
        };
        assert!(f.is_async);
        let ann = f
            .annotations
            .iter()
            .find(|a| a.name == "agent_task")
            .unwrap();
        let arg_names: Vec<&str> = ann.args.iter().map(|a| a.name.as_str()).collect();
        assert!(arg_names.contains(&"can_write"));
        assert!(arg_names.contains(&"can_spawn"));
        assert!(arg_names.contains(&"memory_limit"));
    }

    // 11. Let destructure `let (a, b) = expr`
    #[test]
    fn parse_let_destructure_tuple() {
        let program = parse("fn main() { let (data, err) = parse(raw) }");
        let Item::Fn(ref f) = program.items[0] else {
            panic!("expected fn")
        };
        let stmt = &f.body.stmts[0];
        if let StmtKind::LetDestructure { ref names, .. } = stmt.kind {
            assert_eq!(names.len(), 2);
            assert_eq!(names[0], "data");
            assert_eq!(names[1], "err");
        } else {
            panic!("expected LetDestructure, got {:?}", stmt.kind);
        }
    }

    // 12. Let destructure with three names
    #[test]
    fn parse_let_destructure_three_names() {
        let program = parse("fn main() { let (a, b, c) = triple() }");
        let Item::Fn(ref f) = program.items[0] else {
            panic!()
        };
        let stmt = &f.body.stmts[0];
        if let StmtKind::LetDestructure { ref names, .. } = stmt.kind {
            assert_eq!(names.len(), 3);
            assert_eq!(names[2], "c");
        } else {
            panic!("expected LetDestructure");
        }
    }

    // 13. While-let with Err pattern
    #[test]
    fn parse_while_let_err_pattern() {
        let program = parse(
            r#"
            fn drain() {
                while let Err(msg) = try_pop() {
                    log(msg)
                }
            }
        "#,
        );
        let Item::Fn(ref f) = program.items[0] else {
            panic!()
        };
        assert!(matches!(f.body.stmts[0].kind, StmtKind::WhileLet { .. }));
    }

    // 14. Loop with break carrying a value (break is just a stmt here)
    #[test]
    fn parse_loop_with_break_and_continue() {
        let program = parse(
            r#"
            fn main() {
                loop {
                    if done { break }
                    continue
                }
            }
        "#,
        );
        let Item::Fn(ref f) = program.items[0] else {
            panic!()
        };
        let StmtKind::Loop { ref body } = f.body.stmts[0].kind else {
            panic!("expected loop");
        };
        // body has at least 2 stmts: if-break and continue
        assert!(body.stmts.len() >= 2);
        assert!(matches!(body.stmts[1].kind, StmtKind::Continue));
    }

    // 15. bail statement desugars to Return(Err(...))
    #[test]
    fn parse_bail_statement() {
        let program = parse(
            r#"
            fn validate(n: i64) -> Result<i64> {
                bail "too small"
                Ok(n)
            }
        "#,
        );
        let Item::Fn(ref f) = program.items[0] else {
            panic!()
        };
        // bail desugars to return Err(...)
        assert!(matches!(f.body.stmts[0].kind, StmtKind::Return(Some(_))));
    }

    // 16. bail_if with condition and message
    #[test]
    fn parse_bail_if_with_condition() {
        let program = parse(
            r#"
            fn check_range(n: i64) -> Result<i64> {
                bail_if n > 1000, "value exceeds maximum"
                Ok(n)
            }
        "#,
        );
        let Item::Fn(ref f) = program.items[0] else {
            panic!()
        };
        // bail_if desugars to if { return Err(...) }
        assert!(matches!(f.body.stmts[0].kind, StmtKind::Expr { .. }));
    }

    // 17. String interpolation with multiple expressions
    #[test]
    fn parse_string_interpolation_multiple_exprs() {
        let program =
            parse(r#"fn main() { let s = "fetched {count} items from {domain} in {ms}ms" }"#);
        let Item::Fn(ref f) = program.items[0] else {
            panic!()
        };
        if let StmtKind::Let { ref value, .. } = f.body.stmts[0].kind {
            if let ExprKind::Interpolation(ref parts) = value.kind {
                // Should have literal and expr segments totaling >= 4 parts
                assert!(
                    parts.len() >= 4,
                    "expected multiple interpolation parts, got {}",
                    parts.len()
                );
            } else {
                panic!("expected interpolation");
            }
        } else {
            panic!("expected let");
        }
    }

    // 18. Map literal with multiple key-value pairs
    #[test]
    fn parse_map_literal_multiple_pairs() {
        let program = parse(
            r#"fn main() { let h = {"Content-Type": "application/json", "Accept": "text/html", "X-Key": "v"} }"#,
        );
        let Item::Fn(ref f) = program.items[0] else {
            panic!()
        };
        if let StmtKind::Let { ref value, .. } = f.body.stmts[0].kind {
            if let ExprKind::MapLit(ref pairs) = value.kind {
                assert_eq!(pairs.len(), 3);
            } else {
                panic!("expected map literal");
            }
        } else {
            panic!("expected let");
        }
    }

    // 19. Struct literal with spread `...self`
    #[test]
    fn parse_struct_literal_self_spread() {
        let program = parse("fn main() { let p2 = Config { ...self, port: 9090 } }");
        let Item::Fn(ref f) = program.items[0] else {
            panic!()
        };
        if let StmtKind::Let { ref value, .. } = f.body.stmts[0].kind {
            if let ExprKind::StructLit {
                ref spread,
                ref fields,
                ..
            } = value.kind
            {
                assert!(spread.is_some(), "expected spread");
                assert_eq!(fields.len(), 1);
                assert_eq!(fields[0].name, "port");
            } else {
                panic!("expected struct literal");
            }
        } else {
            panic!("expected let");
        }
    }

    // 20. Cast expression with target type u8
    #[test]
    fn parse_cast_to_u8() {
        let program = parse("fn main() { let b = value as u8 }");
        let Item::Fn(ref f) = program.items[0] else {
            panic!()
        };
        if let StmtKind::Let { ref value, .. } = f.body.stmts[0].kind {
            if let ExprKind::Cast { ref ty, .. } = value.kind {
                assert!(matches!(ty.kind, TypeExprKind::Named(ref n) if n == "u8"));
            } else {
                panic!("expected cast");
            }
        } else {
            panic!("expected let");
        }
    }

    // 21. Try operator applied to a method call
    #[test]
    fn parse_try_on_method_call() {
        let program = parse(r#"fn f() -> Result<String> { let s = resp.text()? s }"#);
        let Item::Fn(ref f) = program.items[0] else {
            panic!()
        };
        if let StmtKind::Let { ref value, .. } = f.body.stmts[0].kind {
            assert!(matches!(value.kind, ExprKind::Try(_)));
        } else {
            panic!("expected let");
        }
    }

    // 22. Await expression on an async call
    #[test]
    fn parse_await_on_async_call() {
        let program = parse("async fn main() { let r = fetch_data().await }");
        let Item::Fn(ref f) = program.items[0] else {
            panic!()
        };
        if let StmtKind::Let { ref value, .. } = f.body.stmts[0].kind {
            assert!(matches!(value.kind, ExprKind::Await(_)));
        } else {
            panic!("expected let");
        }
    }

    // 23. Index expression with a non-zero literal
    #[test]
    fn parse_index_nonzero() {
        let program = parse("fn main() { let x = items[42] }");
        let Item::Fn(ref f) = program.items[0] else {
            panic!()
        };
        if let StmtKind::Let { ref value, .. } = f.body.stmts[0].kind {
            if let ExprKind::Index { ref index, .. } = value.kind {
                assert!(matches!(index.kind, ExprKind::IntLit(42)));
            } else {
                panic!("expected index");
            }
        } else {
            panic!("expected let");
        }
    }

    // 24. Bitwise NOT unary operator
    #[test]
    fn parse_unary_bitnot() {
        let program = parse("fn main() { let x = ~flags }");
        let Item::Fn(ref f) = program.items[0] else {
            panic!()
        };
        if let StmtKind::Let { ref value, .. } = f.body.stmts[0].kind {
            if let ExprKind::Unary { op, .. } = value.kind {
                assert_eq!(op, UnOp::BitNot);
            } else {
                panic!("expected unary bitnot");
            }
        } else {
            panic!("expected let");
        }
    }

    // 25. Nested if/else-if/else with three branches
    #[test]
    fn parse_triple_branch_if() {
        let program = parse(
            r#"
            fn classify(n: i64) -> String {
                if n > 100 { "big" } else if n > 10 { "medium" } else { "small" }
            }
        "#,
        );
        let Item::Fn(ref f) = program.items[0] else {
            panic!()
        };
        if let StmtKind::Expr { ref expr } = f.body.stmts[0].kind {
            // Top-level if should have an else-if branch
            assert!(
                matches!(
                    expr.kind,
                    ExprKind::If {
                        else_branch: Some(ElseBranch::ElseIf(_)),
                        ..
                    }
                ),
                "expected if with else-if branch"
            );
        } else {
            panic!("expected expression statement");
        }
    }

    // 26. Match with variant pattern binding
    #[test]
    fn parse_match_variant_binding() {
        let program = parse(
            r#"
            fn describe(s: Status) {
                s match {
                    Active          -> print("active")
                    Pending(reason) -> print(reason)
                    _               -> print("other")
                }
            }
        "#,
        );
        let Item::Fn(ref f) = program.items[0] else {
            panic!()
        };
        if let StmtKind::Expr { ref expr } = f.body.stmts[0].kind {
            if let ExprKind::Match { ref arms, .. } = expr.kind {
                assert_eq!(arms.len(), 3);
                // Third arm should be wildcard
                assert!(matches!(arms[2].pattern, Pattern::Wildcard));
            } else {
                panic!("expected match");
            }
        } else {
            panic!("expected expr stmt");
        }
    }

    // 27. For loop iterating over an identifier (not just range)
    #[test]
    fn parse_for_loop_over_collection() {
        let program = parse("fn main() { for item in items { process(item) } }");
        let Item::Fn(ref f) = program.items[0] else {
            panic!()
        };
        if let StmtKind::For {
            ref binding,
            ref iter,
            ..
        } = f.body.stmts[0].kind
        {
            assert_eq!(binding, "item");
            assert!(matches!(iter.kind, ExprKind::Ident(ref n) if n == "items"));
        } else {
            panic!("expected for stmt");
        }
    }

    // 28. Closure with multiple typed parameters
    #[test]
    fn parse_closure_multiple_typed_params() {
        let program = parse(r#"fn main() { let f = { a: i64, b: i64, c: i64 -> a + b + c } }"#);
        let Item::Fn(ref f) = program.items[0] else {
            panic!()
        };
        if let StmtKind::Let { ref value, .. } = f.body.stmts[0].kind {
            if let ExprKind::Closure { ref params, .. } = value.kind {
                assert_eq!(params.len(), 3);
                assert_eq!(params[0].name, "a");
                assert_eq!(params[1].name, "b");
                assert_eq!(params[2].name, "c");
                // all params should have type annotations
                assert!(params.iter().all(|p| p.ty.is_some()));
            } else {
                panic!("expected closure");
            }
        } else {
            panic!("expected let");
        }
    }

    // 29. Deep method call chain (four levels)
    #[test]
    fn parse_method_chain_deep() {
        let program = parse(r#"fn main() { let r = data.filter().map().flatten().collect() }"#);
        let Item::Fn(ref f) = program.items[0] else {
            panic!()
        };
        if let StmtKind::Let { ref value, .. } = f.body.stmts[0].kind {
            assert!(matches!(value.kind, ExprKind::MethodCall { .. }));
        } else {
            panic!("expected let");
        }
    }

    // 30. Field access chain three levels deep
    #[test]
    fn parse_field_chain_three_levels() {
        let program = parse("fn main() { let x = server.config.tls.enabled }");
        let Item::Fn(ref f) = program.items[0] else {
            panic!()
        };
        if let StmtKind::Let { ref value, .. } = f.body.stmts[0].kind {
            // Outermost should be FieldAccess
            if let ExprKind::FieldAccess { ref field, .. } = value.kind {
                assert_eq!(field, "enabled");
            } else {
                panic!("expected field access");
            }
        } else {
            panic!("expected let");
        }
    }

    // 31. Array literal containing struct literals
    #[test]
    fn parse_array_of_struct_literals() {
        let program =
            parse(r#"fn main() { let pts = [Point { x: 0, y: 0 }, Point { x: 1, y: 1 }] }"#);
        let Item::Fn(ref f) = program.items[0] else {
            panic!()
        };
        if let StmtKind::Let { ref value, .. } = f.body.stmts[0].kind {
            if let ExprKind::Array(ref elems) = value.kind {
                assert_eq!(elems.len(), 2);
                assert!(matches!(elems[0].kind, ExprKind::StructLit { .. }));
                assert!(matches!(elems[1].kind, ExprKind::StructLit { .. }));
            } else {
                panic!("expected array");
            }
        } else {
            panic!("expected let");
        }
    }

    // 32. Named function arguments with mixed named and positional
    #[test]
    fn parse_named_args_mixed() {
        let program =
            parse(r#"fn main() { fetch("https://example.com", timeout: 10, rotate_ip: true) }"#);
        let Item::Fn(ref f) = program.items[0] else {
            panic!()
        };
        if let StmtKind::Expr { ref expr } = f.body.stmts[0].kind {
            if let ExprKind::Call { ref args, .. } = expr.kind {
                assert_eq!(args.len(), 3);
                // first arg positional
                assert!(args[0].name.is_none());
                // second arg named "timeout"
                assert_eq!(args[1].name.as_deref(), Some("timeout"));
                // third arg named "rotate_ip"
                assert_eq!(args[2].name.as_deref(), Some("rotate_ip"));
            } else {
                panic!("expected call");
            }
        } else {
            panic!("expected expr stmt");
        }
    }

    // 33. Async function with return type
    #[test]
    fn parse_async_fn_with_return_type() {
        let program = parse("async fn connect(host: String) -> Result<Conn> { }");
        let Item::Fn(ref f) = program.items[0] else {
            panic!()
        };
        assert!(f.is_async);
        assert_eq!(f.name, "connect");
        assert_eq!(f.params.len(), 1);
        assert!(f.return_type.is_some());
    }

    // 34. Generic struct with single type param and methods
    #[test]
    fn parse_generic_struct_single_param() {
        let program = parse(
            r#"
            struct Queue<T> {
                items: []T,
                cap:   u32 = 256
            }
        "#,
        );
        let Item::Struct(ref s) = program.items[0] else {
            panic!("expected struct")
        };
        assert_eq!(s.name, "Queue");
        assert_eq!(s.type_params.len(), 1);
        assert_eq!(s.type_params[0], "T");
        assert_eq!(s.fields.len(), 2);
        assert!(s.fields[1].default.is_some());
    }

    // 35. Function returning optional type `T?`
    #[test]
    fn parse_fn_returning_optional() {
        let program = parse("fn find(id: u64) -> User? { nil }");
        let Item::Fn(ref f) = program.items[0] else {
            panic!()
        };
        assert_eq!(f.name, "find");
        let ret = f.return_type.as_ref().expect("expected return type");
        assert!(
            matches!(ret.kind, TypeExprKind::Optional(_)),
            "expected Optional return type, got {:?}",
            ret.kind
        );
    }

    // 36. Function with no params and no return type
    #[test]
    fn parse_fn_no_params_no_return() {
        let program = parse("fn init() { }");
        let Item::Fn(ref f) = program.items[0] else {
            panic!()
        };
        assert_eq!(f.name, "init");
        assert!(f.params.is_empty());
        assert!(f.return_type.is_none());
        assert!(!f.is_async);
    }

    // 37. Var declaration (mutable binding)
    #[test]
    fn parse_var_declaration() {
        let program = parse("fn main() { var count: i64 = 0 }");
        let Item::Fn(ref f) = program.items[0] else {
            panic!()
        };
        if let StmtKind::Var {
            ref name,
            ref ty,
            ref value,
        } = f.body.stmts[0].kind
        {
            assert_eq!(name, "count");
            assert!(ty.is_some());
            assert!(matches!(value.kind, ExprKind::IntLit(0)));
        } else {
            panic!("expected var statement, got {:?}", f.body.stmts[0].kind);
        }
    }

    // 38. Binary AND / OR operators
    #[test]
    fn parse_logical_and_or() {
        let program = parse("fn main() { let x = a && b\n let y = c || d }");
        let Item::Fn(ref f) = program.items[0] else {
            panic!()
        };
        if let StmtKind::Let { ref value, .. } = f.body.stmts[0].kind {
            assert!(matches!(
                value.kind,
                ExprKind::Binary { op: BinOp::And, .. }
            ));
        } else {
            panic!("expected let");
        }
        if let StmtKind::Let { ref value, .. } = f.body.stmts[1].kind {
            assert!(matches!(value.kind, ExprKind::Binary { op: BinOp::Or, .. }));
        } else {
            panic!("expected let");
        }
    }

    // 39. Nil literal in a let binding
    #[test]
    fn parse_nil_literal() {
        let program = parse("fn main() { let x = nil }");
        let Item::Fn(ref f) = program.items[0] else {
            panic!()
        };
        if let StmtKind::Let { ref value, .. } = f.body.stmts[0].kind {
            assert!(matches!(value.kind, ExprKind::Nil));
        } else {
            panic!("expected let");
        }
    }

    // 40. Boolean true/false literals
    #[test]
    fn parse_bool_literals() {
        let program = parse("fn main() { let a = true\n let b = false }");
        let Item::Fn(ref f) = program.items[0] else {
            panic!()
        };
        if let StmtKind::Let { ref value, .. } = f.body.stmts[0].kind {
            assert!(matches!(value.kind, ExprKind::BoolLit(true)));
        }
        if let StmtKind::Let { ref value, .. } = f.body.stmts[1].kind {
            assert!(matches!(value.kind, ExprKind::BoolLit(false)));
        }
    }

    // 41. Float literal in let binding
    #[test]
    fn parse_float_literal() {
        let program = parse("fn main() { let rate: f64 = 3.14 }");
        let Item::Fn(ref f) = program.items[0] else {
            panic!()
        };
        if let StmtKind::Let { ref value, .. } = f.body.stmts[0].kind {
            assert!(matches!(value.kind, ExprKind::FloatLit(_)));
        } else {
            panic!("expected let");
        }
    }

    // 42. Nested function calls as arguments
    #[test]
    fn parse_nested_call_as_arg() {
        let program = parse(r#"fn main() { process(parse(read_file("path"))) }"#);
        let Item::Fn(ref f) = program.items[0] else {
            panic!()
        };
        if let StmtKind::Expr { ref expr } = f.body.stmts[0].kind {
            if let ExprKind::Call { ref args, .. } = expr.kind {
                assert_eq!(args.len(), 1);
                // arg itself should be a Call
                assert!(matches!(args[0].value.kind, ExprKind::Call { .. }));
            } else {
                panic!("expected call");
            }
        }
    }

    // 43. Dot-ident annotation value (e.g. .public_data)
    #[test]
    fn parse_dot_ident_annotation_value() {
        let program = parse(
            r#"
            @legal(basis: .legitimate_interest, purpose: "analytics")
            fn collect() { }
        "#,
        );
        let Item::Fn(ref f) = program.items[0] else {
            panic!()
        };
        let ann = &f.annotations[0];
        let basis_arg = ann.args.iter().find(|a| a.name == "basis").unwrap();
        assert!(
            matches!(basis_arg.value.kind, ExprKind::DotIdent(ref s) if s == "legitimate_interest")
        );
    }

    // 44. Compound assignment operators desugar to Assign(Binary)
    #[test]
    fn parse_compound_assign_add() {
        let program = parse("fn main() { var x = 0\n x += 5 }");
        let Item::Fn(ref f) = program.items[0] else {
            panic!()
        };
        // x += 5 desugars to x = x + 5, which is Assign { target: x, value: Binary(Add, x, 5) }
        if let StmtKind::Expr { ref expr } = f.body.stmts[1].kind {
            assert!(matches!(expr.kind, ExprKind::Assign { .. }));
        } else {
            panic!("expected expr stmt for compound assign");
        }
    }

    // 45. Equality and inequality binary operators
    #[test]
    fn parse_eq_neq_operators() {
        let program = parse("fn main() { let a = x == 0\n let b = y != 0 }");
        let Item::Fn(ref f) = program.items[0] else {
            panic!()
        };
        if let StmtKind::Let { ref value, .. } = f.body.stmts[0].kind {
            assert!(matches!(value.kind, ExprKind::Binary { op: BinOp::Eq, .. }));
        }
        if let StmtKind::Let { ref value, .. } = f.body.stmts[1].kind {
            assert!(matches!(
                value.kind,
                ExprKind::Binary { op: BinOp::Neq, .. }
            ));
        }
    }

    // 46. Generic function with three type params
    #[test]
    fn parse_generic_function_three_params() {
        let program = parse("fn triple<A, B, C>(a: A, b: B, c: C) -> A { a }");
        let Item::Fn(ref f) = program.items[0] else {
            panic!()
        };
        assert_eq!(f.type_params.len(), 3);
        assert_eq!(f.type_params, vec!["A", "B", "C"]);
        assert_eq!(f.params.len(), 3);
    }

    // 47. Slice type in function parameter
    #[test]
    fn parse_slice_type_param() {
        let program = parse("fn sum(values: []i64) -> i64 { 0 }");
        let Item::Fn(ref f) = program.items[0] else {
            panic!()
        };
        assert_eq!(f.params.len(), 1);
        assert!(matches!(f.params[0].ty.kind, TypeExprKind::Slice(_)));
    }

    // 48. Tuple type in function return
    #[test]
    fn parse_tuple_return_type() {
        let program = parse("fn split(s: String) -> (String, String) { }");
        let Item::Fn(ref f) = program.items[0] else {
            panic!()
        };
        let ret = f.return_type.as_ref().expect("expected return type");
        if let TypeExprKind::Tuple(ref elems) = ret.kind {
            assert_eq!(elems.len(), 2);
        } else {
            panic!("expected tuple return type, got {:?}", ret.kind);
        }
    }

    // 49. String literal in a function call argument
    #[test]
    fn parse_string_literal_call_arg() {
        let program = parse(r#"fn main() { log("hello world") }"#);
        let Item::Fn(ref f) = program.items[0] else {
            panic!()
        };
        if let StmtKind::Expr { ref expr } = f.body.stmts[0].kind {
            if let ExprKind::Call { ref args, .. } = expr.kind {
                assert_eq!(args.len(), 1);
                assert!(matches!(args[0].value.kind, ExprKind::StringLit(_)));
            } else {
                panic!("expected call");
            }
        }
    }

    // 50. Trailing closure syntax on method call
    #[test]
    fn parse_trailing_closure_on_method() {
        let program = parse(
            r#"
            fn main() {
                let results = items.map { x -> x * 2 }
            }
        "#,
        );
        let Item::Fn(ref f) = program.items[0] else {
            panic!()
        };
        if let StmtKind::Let { ref value, .. } = f.body.stmts[0].kind {
            // .map { ... } should produce a MethodCall with closure arg
            if let ExprKind::MethodCall {
                ref method,
                ref args,
                ..
            } = value.kind
            {
                assert_eq!(method, "map");
                // The trailing closure becomes the sole argument
                assert_eq!(args.len(), 1);
                assert!(matches!(args[0].value.kind, ExprKind::Closure { .. }));
            } else {
                panic!(
                    "expected method call with trailing closure, got {:?}",
                    value.kind
                );
            }
        } else {
            panic!("expected let");
        }
    }

    // 51. Struct field access then method call
    #[test]
    fn parse_field_then_method_call() {
        let program = parse(r#"fn main() { let n = user.name.len() }"#);
        let Item::Fn(ref f) = program.items[0] else {
            panic!()
        };
        if let StmtKind::Let { ref value, .. } = f.body.stmts[0].kind {
            // user.name.len() — outermost is MethodCall(.len) on FieldAccess(.name)
            if let ExprKind::MethodCall {
                ref method,
                ref object,
                ..
            } = value.kind
            {
                assert_eq!(method, "len");
                assert!(matches!(object.kind, ExprKind::FieldAccess { .. }));
            } else {
                panic!("expected method call on field access");
            }
        } else {
            panic!("expected let");
        }
    }

    // 52. Index then method call (arr[0].process())
    #[test]
    fn parse_index_then_method() {
        let program = parse(r#"fn main() { let v = items[0].value() }"#);
        let Item::Fn(ref f) = program.items[0] else {
            panic!()
        };
        if let StmtKind::Let { ref value, .. } = f.body.stmts[0].kind {
            if let ExprKind::MethodCall {
                ref method,
                ref object,
                ..
            } = value.kind
            {
                assert_eq!(method, "value");
                assert!(matches!(object.kind, ExprKind::Index { .. }));
            } else {
                panic!("expected method call on index expr");
            }
        } else {
            panic!("expected let");
        }
    }

    // 53. Deeply nested generics: Map<String, Vec<Result<i64>>>
    #[test]
    fn parse_deeply_nested_generic_type() {
        let program = parse("fn nested(m: Map<String, []Result<i64>>) { }");
        let Item::Fn(ref f) = program.items[0] else {
            panic!()
        };
        assert_eq!(f.params.len(), 1);
        // Top-level type should be Generic { name: "Map", ... }
        assert!(
            matches!(f.params[0].ty.kind, TypeExprKind::Generic { ref name, .. } if name == "Map")
        );
    }

    // 54. Multiple top-level items parsed in order
    #[test]
    fn parse_multiple_top_level_items() {
        let program = parse(
            r#"
            const VERSION: String = "0.1.0"
            type Email = private String
            struct User { id: u64, email: Email }
            enum Role { Admin, Guest }
            fn main() { }
        "#,
        );
        assert_eq!(program.items.len(), 5);
        assert!(matches!(program.items[0], Item::Const(_)));
        assert!(matches!(program.items[1], Item::TypeAlias(_)));
        assert!(matches!(program.items[2], Item::Struct(_)));
        assert!(matches!(program.items[3], Item::Enum(_)));
        assert!(matches!(program.items[4], Item::Fn(_)));
    }

    // 55. Custom annotation with a named arg (unknown annotations parse generically)
    #[test]
    fn parse_custom_annotation_named_arg() {
        let program = parse(
            r#"
            @requires_scale(level: .high)
            fn main() { }
        "#,
        );
        let Item::Fn(ref f) = program.items[0] else {
            panic!()
        };
        assert_eq!(f.annotations.len(), 1);
        let ann = &f.annotations[0];
        assert_eq!(ann.name, "requires_scale");
        assert_eq!(ann.args.len(), 1);
        assert_eq!(ann.args[0].name, "level");
        assert!(matches!(ann.args[0].value.kind, ExprKind::DotIdent(ref s) if s == "high"));
    }

    // ── >> splitting for nested generics ────────────────────────────────

    #[test]
    fn parse_shr_split_in_nested_generic() {
        // >> should be split into > > when inside generic type args
        let program = parse("fn process(r: Result<Result<i64>>) { }");
        let Item::Fn(ref f) = program.items[0] else {
            panic!()
        };
        assert_eq!(f.params.len(), 1);
        // Outer type: Result<Result<i64>>
        if let TypeExprKind::Generic { ref name, ref args } = f.params[0].ty.kind {
            assert_eq!(name, "Result");
            assert_eq!(args.len(), 1);
            // Inner type: Result<i64>
            assert!(
                matches!(args[0].kind, TypeExprKind::Generic { ref name, .. } if name == "Result")
            );
        } else {
            panic!("expected Generic type");
        }
    }

    #[test]
    fn parse_triple_nested_generic() {
        let program = parse("fn deep(x: Map<String, Result<Option<i64>>>) { }");
        let Item::Fn(ref f) = program.items[0] else {
            panic!()
        };
        assert_eq!(f.params.len(), 1);
        assert!(
            matches!(f.params[0].ty.kind, TypeExprKind::Generic { ref name, .. } if name == "Map")
        );
    }

    #[test]
    fn parse_empty_fn_body() {
        let program = parse("fn noop() { }");
        let Item::Fn(ref f) = program.items[0] else {
            panic!()
        };
        assert_eq!(f.name, "noop");
        assert!(f.body.stmts.is_empty());
    }

    #[test]
    fn parse_fn_single_return() {
        let program = parse("fn answer() -> i32 { 42 }");
        let Item::Fn(ref f) = program.items[0] else {
            panic!()
        };
        assert_eq!(f.name, "answer");
        assert_eq!(f.body.stmts.len(), 1);
    }

    #[test]
    fn parse_let_with_explicit_type() {
        let program = parse("fn main() { let x: i64 = 42 }");
        let Item::Fn(ref f) = program.items[0] else {
            panic!()
        };
        assert_eq!(f.body.stmts.len(), 1);
    }

    #[test]
    fn parse_var_mutable_binding() {
        let program = parse("fn main() { var count = 0 }");
        let Item::Fn(ref f) = program.items[0] else {
            panic!()
        };
        assert_eq!(f.body.stmts.len(), 1);
    }

    #[test]
    fn parse_if_else_chain() {
        let program = parse("fn main() { if true { 1 } else if false { 2 } else { 3 } }");
        let Item::Fn(ref f) = program.items[0] else {
            panic!()
        };
        assert_eq!(f.body.stmts.len(), 1);
    }

    #[test]
    fn parse_match_with_wildcard() {
        let program = parse(r#"fn main() { match x { 1 -> "a" _ -> "b" } }"#);
        let Item::Fn(ref f) = program.items[0] else {
            panic!()
        };
        assert_eq!(f.body.stmts.len(), 1);
    }

    #[test]
    fn parse_for_range_loop() {
        let program = parse("fn main() { for i in 0..10 { print(i) } }");
        let Item::Fn(ref f) = program.items[0] else {
            panic!()
        };
        assert_eq!(f.body.stmts.len(), 1);
    }

    #[test]
    fn parse_for_in_array_loop() {
        let program = parse(r#"fn main() { for item in items { print(item) } }"#);
        let Item::Fn(ref f) = program.items[0] else {
            panic!()
        };
        assert_eq!(f.body.stmts.len(), 1);
    }

    #[test]
    fn parse_struct_two_fields_default() {
        let program = parse("struct Config { port: u16 = 8080, host: String }");
        let Item::Struct(ref s) = program.items[0] else {
            panic!()
        };
        assert_eq!(s.name, "Config");
        assert_eq!(s.fields.len(), 2);
    }

    #[test]
    fn parse_enum_with_payload() {
        let program = parse(r#"enum Status { Active, Pending(reason: String) }"#);
        let Item::Enum(ref e) = program.items[0] else {
            panic!()
        };
        assert_eq!(e.name, "Status");
        assert_eq!(e.variants.len(), 2);
    }

    #[test]
    fn parse_three_import_statements() {
        let program = parse("import tallow.http\nimport tallow.json\nimport tallow.crypto");
        assert_eq!(program.items.len(), 3);
    }

    #[test]
    fn parse_const_string_declaration() {
        let program = parse(r#"const VERSION = "0.1.0""#);
        let Item::Const(ref c) = program.items[0] else {
            panic!()
        };
        assert_eq!(c.name, "VERSION");
    }

    #[test]
    fn parse_native_fn_declaration() {
        // register #129: a body-less declaration is accepted; the body is empty
        // and the flag says the implementation is a link-time symbol.
        let program = parse("native fn hash(data: String) -> i64");
        let Item::Fn(ref f) = program.items[0] else {
            panic!("expected a function item")
        };
        assert!(f.is_native);
        assert!(f.body.stmts.is_empty());
        assert_eq!(f.name, "hash");
        assert_eq!(f.params.len(), 1);
        assert!(f.return_type.is_some());
    }

    #[test]
    fn parse_fn_named_native_still_parses() {
        // `native` is only a modifier when followed by `fn`.
        let program = parse("fn native() { }");
        let Item::Fn(ref f) = program.items[0] else {
            panic!("expected a function item")
        };
        assert!(!f.is_native);
        assert_eq!(f.name, "native");
    }

    #[test]
    fn parse_type_scoped_fn_name() {
        // `fn CAPTCHA.detect(...)` — the stdlib manifest's spelling for a
        // type-scoped free function; the runtime dispatches `Module.function`
        // by this exact name.
        let program = parse("native fn CAPTCHA.detect(html: String) -> CaptchaChallenge");
        let Item::Fn(ref f) = program.items[0] else {
            panic!("expected a function item");
        };
        assert_eq!(f.name, "CAPTCHA.detect");
        assert!(f.is_native);
    }

    #[test]
    fn parse_private_type_alias_email() {
        let program = parse("type Email = private String");
        let Item::TypeAlias(ref t) = program.items[0] else {
            panic!()
        };
        assert_eq!(t.name, "Email");
    }

    #[test]
    fn parse_secret_type_alias_apikey() {
        let program = parse("type APIKey = secret String");
        let Item::TypeAlias(ref t) = program.items[0] else {
            panic!()
        };
        assert_eq!(t.name, "APIKey");
    }

    #[test]
    fn parse_fn_multiple_params() {
        let program = parse("fn add(a: i32, b: i32, c: i32) -> i32 { a + b + c }");
        let Item::Fn(ref f) = program.items[0] else {
            panic!()
        };
        assert_eq!(f.params.len(), 3);
    }

    #[test]
    fn parse_fn_default_param_value() {
        // Default parameter values in decls must parse (`= expr` after the type).
        let program = parse("fn launch(headless: bool = true, retries: i32 = 0) -> i32 { 0 }");
        let Item::Fn(ref f) = program.items[0] else {
            panic!("expected fn")
        };
        assert_eq!(f.params.len(), 2);
    }

    #[test]
    fn parse_closure_no_params() {
        let program = parse("fn main() { let f = { 42 } }");
        let Item::Fn(ref f) = program.items[0] else {
            panic!()
        };
        assert_eq!(f.body.stmts.len(), 1);
    }

    #[test]
    fn parse_closure_two_params() {
        let program = parse("fn main() { let f = { a: i32, b: i32 -> a + b } }");
        let Item::Fn(ref f) = program.items[0] else {
            panic!()
        };
        assert_eq!(f.body.stmts.len(), 1);
    }

    #[test]
    fn parse_struct_instantiation() {
        let program = parse(r#"fn main() { let p = Point { x: 10, y: 20 } }"#);
        let Item::Fn(ref f) = program.items[0] else {
            panic!()
        };
        assert_eq!(f.body.stmts.len(), 1);
    }

    #[test]
    fn parse_method_chain_two() {
        let program = parse(r#"fn main() { let x = "hello".trim().len() }"#);
        let Item::Fn(ref f) = program.items[0] else {
            panic!()
        };
        assert_eq!(f.body.stmts.len(), 1);
    }

    #[test]
    fn parse_array_index_access() {
        let program = parse("fn main() { let x = arr[0] }");
        let Item::Fn(ref f) = program.items[0] else {
            panic!()
        };
        assert_eq!(f.body.stmts.len(), 1);
    }

    #[test]
    fn parse_string_interpolation_simple() {
        let program = parse(r#"fn main() { let msg = "hello {name}" }"#);
        let Item::Fn(ref f) = program.items[0] else {
            panic!()
        };
        assert_eq!(f.body.stmts.len(), 1);
    }

    #[test]
    fn parse_bail_if_with_message() {
        let program = parse(r#"fn check(x: i32) -> Result<i32> { bail_if x == 0, "zero" }"#);
        let Item::Fn(ref f) = program.items[0] else {
            panic!()
        };
        assert!(!f.body.stmts.is_empty());
    }

    #[test]
    fn parse_try_operator() {
        let program = parse("fn process() -> Result<i32> { let x = compute()? }");
        let Item::Fn(ref f) = program.items[0] else {
            panic!()
        };
        assert_eq!(f.body.stmts.len(), 1);
    }

    #[test]
    fn parse_while_let_ok_pattern() {
        let program = parse("fn main() { while let Ok(val) = next() { print(val) } }");
        let Item::Fn(ref f) = program.items[0] else {
            panic!()
        };
        assert_eq!(f.body.stmts.len(), 1);
    }

    #[test]
    fn parse_async_fn_declaration() {
        let program = parse("async fn fetch_data(url: String) -> Result<String> { Ok(url) }");
        let Item::Fn(ref f) = program.items[0] else {
            panic!()
        };
        assert!(f.is_async);
    }

    #[test]
    fn parse_compound_assign_plus_eq() {
        let program = parse("fn main() { var x = 0\n x += 1 }");
        let Item::Fn(ref f) = program.items[0] else {
            panic!()
        };
        assert_eq!(f.body.stmts.len(), 2);
    }

    #[test]
    fn parse_compound_assign_minus_eq() {
        let program = parse("fn main() { var x = 10\n x -= 3 }");
        let Item::Fn(ref f) = program.items[0] else {
            panic!()
        };
        assert_eq!(f.body.stmts.len(), 2);
    }

    #[test]
    fn parse_compound_assign_mul_eq() {
        let program = parse("fn main() { var x = 2\n x *= 5 }");
        let Item::Fn(ref f) = program.items[0] else {
            panic!()
        };
        assert_eq!(f.body.stmts.len(), 2);
    }

    #[test]
    fn parse_nested_match_arms() {
        let program = parse(r#"fn main() { match x { 1 -> "a" 2 -> "b" _ -> "c" } }"#);
        let Item::Fn(ref f) = program.items[0] else {
            panic!()
        };
        assert_eq!(f.body.stmts.len(), 1);
    }

    #[test]
    fn parse_map_literal_two_entries() {
        let program = parse(r#"fn main() { let m = {"a": 1, "b": 2} }"#);
        let Item::Fn(ref f) = program.items[0] else {
            panic!()
        };
        assert_eq!(f.body.stmts.len(), 1);
    }

    #[test]
    fn parse_array_literal_empty() {
        let program = parse("fn main() { let a = [] }");
        let Item::Fn(ref f) = program.items[0] else {
            panic!()
        };
        assert_eq!(f.body.stmts.len(), 1);
    }

    #[test]
    fn parse_method_chain_map_filter() {
        let program = parse(r#"fn main() { items.map { x -> x }.filter { y -> y > 0 } }"#);
        let Item::Fn(ref f) = program.items[0] else {
            panic!()
        };
        assert_eq!(f.body.stmts.len(), 1);
    }

    #[test]
    fn parse_struct_two_defaults() {
        let program = parse("struct Config { port: u16 = 8080, host: String = \"localhost\" }");
        let Item::Struct(ref s) = program.items[0] else {
            panic!()
        };
        assert_eq!(s.fields.len(), 2);
        assert!(s.fields[0].default.is_some());
        assert!(s.fields[1].default.is_some());
    }

    #[test]
    fn parse_enum_mixed_field_counts() {
        let program = parse("enum Shape { Circle(r: f64), Rect(w: f64, h: f64), Point }");
        let Item::Enum(ref e) = program.items[0] else {
            panic!()
        };
        assert_eq!(e.variants.len(), 3);
        assert_eq!(e.variants[0].fields.len(), 1);
        assert_eq!(e.variants[1].fields.len(), 2);
        assert_eq!(e.variants[2].fields.len(), 0);
    }

    #[test]
    fn parse_for_range_0_to_10() {
        let program = parse("fn main() { for i in 0..10 { print(i) } }");
        let Item::Fn(ref f) = program.items[0] else {
            panic!()
        };
        assert_eq!(f.body.stmts.len(), 1);
    }

    #[test]
    fn parse_while_let_ok_binding() {
        let program = parse("fn main() { while let Ok(v) = try_get() { print(v) } }");
        let Item::Fn(ref f) = program.items[0] else {
            panic!()
        };
        assert_eq!(f.body.stmts.len(), 1);
    }

    #[test]
    fn parse_if_let_with_else_branch() {
        let program =
            parse(r#"fn main() { if let Ok(v) = result { print(v) } else { print("err") } }"#);
        let Item::Fn(ref f) = program.items[0] else {
            panic!()
        };
        assert_eq!(f.body.stmts.len(), 1);
    }

    #[test]
    fn parse_three_imports() {
        let program = parse("import tallow.http\nimport tallow.crypto\nimport tallow.json");
        assert_eq!(program.items.len(), 3);
        assert!(matches!(program.items[0], Item::Import(_)));
    }

    #[test]
    fn parse_type_alias_private_email() {
        let program = parse("type Email = private String");
        let Item::TypeAlias(ref t) = program.items[0] else {
            panic!()
        };
        assert_eq!(t.name, "Email");
    }

    #[test]
    fn parse_type_alias_secret_token() {
        let program = parse("type Token = secret String");
        let Item::TypeAlias(ref t) = program.items[0] else {
            panic!()
        };
        assert_eq!(t.name, "Token");
    }

    #[test]
    fn parse_let_destructure_two_names() {
        let program = parse("fn main() { let (a, b) = get_pair() }");
        let Item::Fn(ref f) = program.items[0] else {
            panic!()
        };
        if let StmtKind::LetDestructure { names, .. } = &f.body.stmts[0].kind {
            assert_eq!(names.len(), 2);
        } else {
            panic!("expected LetDestructure");
        }
    }

    #[test]
    fn parse_closure_two_typed_params() {
        let program = parse("fn main() { let f = { x: i32, y: i32 -> x + y } }");
        let Item::Fn(ref f) = program.items[0] else {
            panic!()
        };
        assert_eq!(f.body.stmts.len(), 1);
    }

    #[test]
    fn parse_try_operator_postfix() {
        let program = parse("fn get() -> i64 { fetch(url)? }");
        let Item::Fn(ref f) = program.items[0] else {
            panic!()
        };
        assert_eq!(f.body.stmts.len(), 1);
    }

    // ── Trait Parsing Tests ─────────────────────────────────────────────

    #[test]
    fn trait_parse_basic() {
        let program = parse(
            r#"
            trait Display {
                fn to_string(self) -> String
            }
        "#,
        );
        let Item::Trait(ref t) = program.items[0] else {
            panic!("expected trait")
        };
        assert_eq!(t.name, "Display");
        assert_eq!(t.methods.len(), 1);
        assert_eq!(t.methods[0].name, "to_string");
        assert!(t.methods[0].return_type.is_some());
        assert!(!t.methods[0].has_default);
        assert!(t.methods[0].body.is_none());
    }

    #[test]
    fn trait_parse_impl_for_type() {
        let program = parse(
            r#"
            struct Point { x: i32, y: i32 }
            trait Display {
                fn to_string(self) -> String
            }
            impl Display for Point {
                fn to_string(self) -> String { "point" }
            }
        "#,
        );
        let Item::Impl(ref imp) = program.items[2] else {
            panic!("expected impl")
        };
        assert_eq!(imp.trait_name, Some("Display".to_string()));
        assert_eq!(imp.target, "Point");
        assert_eq!(imp.methods.len(), 1);
        assert_eq!(imp.methods[0].name, "to_string");
    }

    #[test]
    fn trait_parse_multiple_methods() {
        let program = parse(
            r#"
            trait Serializable {
                fn serialize(self) -> String
                fn size(self) -> i64
                fn name(self) -> String
            }
        "#,
        );
        let Item::Trait(ref t) = program.items[0] else {
            panic!("expected trait")
        };
        assert_eq!(t.name, "Serializable");
        assert_eq!(t.methods.len(), 3);
        assert_eq!(t.methods[0].name, "serialize");
        assert_eq!(t.methods[1].name, "size");
        assert_eq!(t.methods[2].name, "name");
    }

    #[test]
    fn trait_parse_with_type_params() {
        let program = parse(
            r#"
            trait Container<T> {
                fn get(self, index: i64) -> T
                fn len(self) -> i64
            }
        "#,
        );
        let Item::Trait(ref t) = program.items[0] else {
            panic!("expected trait")
        };
        assert_eq!(t.name, "Container");
        assert_eq!(t.type_params, vec!["T".to_string()]);
        assert_eq!(t.methods.len(), 2);
    }

    #[test]
    fn trait_ast_item_variant() {
        // Verify Item::Trait variant exists and has correct span
        let program = parse(
            r#"
            trait Hashable {
                fn hash(self) -> i64
            }
        "#,
        );
        assert!(matches!(program.items[0], Item::Trait(_)));
        let span = program.items[0].span();
        assert!(span.start < span.end);
    }

    #[test]
    fn trait_parse_inherent_impl_still_works() {
        // Ensure inherent impls (without trait) still work
        let program = parse(
            r#"
            struct Foo { x: i32 }
            impl Foo {
                fn get_x(self) -> i32 { self.x }
            }
        "#,
        );
        let Item::Impl(ref imp) = program.items[1] else {
            panic!("expected impl")
        };
        assert_eq!(imp.trait_name, None);
        assert_eq!(imp.target, "Foo");
    }

    #[test]
    fn trait_parse_default_method_body() {
        let program = parse(
            r#"
            trait Greet {
                fn greet(self) -> String { "hello" }
                fn name(self) -> String
            }
        "#,
        );
        let Item::Trait(ref t) = program.items[0] else {
            panic!("expected trait")
        };
        assert_eq!(t.methods.len(), 2);
        assert!(t.methods[0].has_default);
        assert!(t.methods[0].body.is_some());
        assert!(!t.methods[1].has_default);
        assert!(t.methods[1].body.is_none());
    }

    #[test]
    fn trait_parse_impl_trait_param_type() {
        let program = parse(
            r#"
            fn do_thing(s: impl Shape) -> i64 { 0 }
        "#,
        );
        let Item::Fn(ref f) = program.items[0] else {
            panic!("expected fn")
        };
        assert_eq!(f.params.len(), 1);
        assert!(matches!(f.params[0].ty.kind, TypeExprKind::ImplTrait(ref n) if n == "Shape"));
    }

    #[test]
    fn trait_parse_dyn_trait_param_type() {
        let program = parse(
            r#"
            fn do_thing(s: dyn Shape) -> i64 { 0 }
        "#,
        );
        let Item::Fn(ref f) = program.items[0] else {
            panic!("expected fn")
        };
        assert_eq!(f.params.len(), 1);
        assert!(matches!(f.params[0].ty.kind, TypeExprKind::DynTrait(ref n) if n == "Shape"));
    }
}
