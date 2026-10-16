//! Tallow Language Server Protocol (LSP) implementation.
//!
//! Provides IDE features for .tl files:
//! - Diagnostics (errors/warnings) on save/open
//! - Go-to-definition for functions, structs, enums
//! - Hover type information
//! - Document symbols (outline)
//! - Completion for keywords, builtins, and project symbols

use std::collections::HashMap;
use std::sync::RwLock;

use tower_lsp::jsonrpc::Result;
use tower_lsp::lsp_types::*;
use tower_lsp::{Client, LanguageServer, LspService, Server};

use crate::ast::*;
use crate::error::Severity;
use crate::lexer::Span;

// ── Document State ──────────────────────────────────────────────────────────

struct DocumentState {
    source: String,
    // Cached analysis results
    definitions: Vec<SymbolDef>,
}

#[derive(Debug, Clone)]
struct SymbolDef {
    name: String,
    kind: SymbolKind,
    span: Span,
    detail: String, // e.g. "fn add(a: i32, b: i32) -> i32"
}

// ── LSP Backend ─────────────────────────────────────────────────────────────

pub struct TallowLanguageServer {
    client: Client,
    documents: RwLock<HashMap<Url, DocumentState>>,
}

impl TallowLanguageServer {
    pub fn new(client: Client) -> Self {
        Self {
            client,
            documents: RwLock::new(HashMap::new()),
        }
    }

    /// Run the full analysis pipeline and publish diagnostics.
    async fn analyze(&self, uri: &Url, source: &str) {
        let mut lsp_diags = Vec::new();
        let mut definitions = Vec::new();

        // Phase 1: Lex
        let (tokens, lex_errors) = crate::lexer::tokenize(source);
        for err in &lex_errors {
            let (_line, _col) = err.span().line_col(source);
            lsp_diags.push(Diagnostic {
                range: span_to_range(&err.span(), source),
                severity: Some(DiagnosticSeverity::ERROR),
                code: None,
                source: Some("tallow".into()),
                message: format!("{err}"),
                related_information: None,
                tags: None,
                code_description: None,
                data: None,
            });
        }

        if lex_errors.is_empty() {
            // Phase 2: Parse with error recovery so ALL parse errors are
            // surfaced as diagnostics in one pass rather than just the first.
            let (program, parse_errors) = crate::parser::Parser::parse_recovering(tokens);

            for err in &parse_errors {
                lsp_diags.push(Diagnostic {
                    range: span_to_range(&err.span, source),
                    severity: Some(DiagnosticSeverity::ERROR),
                    code: None,
                    source: Some("tallow".into()),
                    message: format!("{err}"),
                    related_information: None,
                    tags: None,
                    code_description: None,
                    data: None,
                });
            }

            // Even with parse errors the program may contain partial items —
            // run the semantic passes on whatever was successfully parsed.
            {
                // Collect definitions for navigation
                definitions = collect_definitions(&program, source);

                // Phase 3: Type Check
                let (env, typeck_diags) = crate::typeck::TypeChecker::new(&program).check();

                // Phase 4: Legal Pass
                let (legal_diags, _browser_audit) = crate::legal_pass::LegalPass::new(&program, &env).check();

                // Phase 5: Privacy Pass
                let privacy_diags = crate::privacy_pass::PrivacyPass::new(&program, &env).check();

                // Phase 6: Agent Pass
                let agent_diags = crate::agent_pass::AgentPass::new(&program).check();

                // Convert all diagnostics
                for d in typeck_diags
                    .items
                    .iter()
                    .chain(legal_diags.items.iter())
                    .chain(privacy_diags.items.iter())
                    .chain(agent_diags.items.iter())
                {
                    lsp_diags.push(tallow_diag_to_lsp(d, source));
                }
            }
        }

        // Store document state
        if let Ok(mut docs) = self.documents.write() {
            docs.insert(
                uri.clone(),
                DocumentState {
                    source: source.to_string(),
                    definitions,
                },
            );
        }

        // Publish diagnostics
        self.client
            .publish_diagnostics(uri.clone(), lsp_diags, None)
            .await;
    }
}

#[tower_lsp::async_trait]
impl LanguageServer for TallowLanguageServer {
    async fn initialize(&self, _: InitializeParams) -> Result<InitializeResult> {
        Ok(InitializeResult {
            capabilities: ServerCapabilities {
                text_document_sync: Some(TextDocumentSyncCapability::Kind(
                    TextDocumentSyncKind::FULL,
                )),
                hover_provider: Some(HoverProviderCapability::Simple(true)),
                definition_provider: Some(OneOf::Left(true)),
                document_symbol_provider: Some(OneOf::Left(true)),
                completion_provider: Some(CompletionOptions {
                    trigger_characters: Some(vec![".".into(), ":".into()]),
                    ..Default::default()
                }),
                ..Default::default()
            },
            server_info: Some(ServerInfo {
                name: "tallow-lsp".into(),
                version: Some(env!("CARGO_PKG_VERSION").into()),
            }),
        })
    }

    async fn initialized(&self, _: InitializedParams) {
        self.client
            .log_message(MessageType::INFO, "Tallow LSP initialized")
            .await;
    }

    async fn shutdown(&self) -> Result<()> {
        Ok(())
    }

    // ── Document Sync ───────────────────────────────────────────────────

    async fn did_open(&self, params: DidOpenTextDocumentParams) {
        self.analyze(&params.text_document.uri, &params.text_document.text)
            .await;
    }

    async fn did_change(&self, params: DidChangeTextDocumentParams) {
        if let Some(change) = params.content_changes.into_iter().last() {
            self.analyze(&params.text_document.uri, &change.text)
                .await;
        }
    }

    async fn did_save(&self, params: DidSaveTextDocumentParams) {
        if let Some(text) = params.text {
            self.analyze(&params.text_document.uri, &text).await;
        }
    }

    async fn did_close(&self, params: DidCloseTextDocumentParams) {
        if let Ok(mut docs) = self.documents.write() {
            docs.remove(&params.text_document.uri);
        }
        // Clear diagnostics when file is closed
        self.client
            .publish_diagnostics(params.text_document.uri, vec![], None)
            .await;
    }

    // ── Hover ───────────────────────────────────────────────────────────

    async fn hover(&self, params: HoverParams) -> Result<Option<Hover>> {
        let uri = &params.text_document_position_params.text_document.uri;
        let pos = params.text_document_position_params.position;

        let docs = self.documents.read().unwrap();
        if let Some(doc) = docs.get(uri) {
            let offset = position_to_offset(&doc.source, pos);

            // Find the word at the cursor position
            let word = word_at_offset(&doc.source, offset);
            if word.is_empty() {
                return Ok(None);
            }

            // Look for matching definition
            for def in &doc.definitions {
                if def.name == word {
                    let hover_text = format!(
                        "```tallow\n{}\n```",
                        def.detail
                    );
                    return Ok(Some(Hover {
                        contents: HoverContents::Markup(MarkupContent {
                            kind: MarkupKind::Markdown,
                            value: hover_text,
                        }),
                        range: None,
                    }));
                }
            }

            // Check for keywords
            if let Some(info) = keyword_info(&word) {
                return Ok(Some(Hover {
                    contents: HoverContents::Markup(MarkupContent {
                        kind: MarkupKind::Markdown,
                        value: info.to_string(),
                    }),
                    range: None,
                }));
            }
        }

        Ok(None)
    }

    // ── Go to Definition ────────────────────────────────────────────────

    async fn goto_definition(
        &self,
        params: GotoDefinitionParams,
    ) -> Result<Option<GotoDefinitionResponse>> {
        let uri = &params.text_document_position_params.text_document.uri;
        let pos = params.text_document_position_params.position;

        let docs = self.documents.read().unwrap();
        if let Some(doc) = docs.get(uri) {
            let offset = position_to_offset(&doc.source, pos);
            let word = word_at_offset(&doc.source, offset);

            for def in &doc.definitions {
                if def.name == word {
                    let range = span_to_range(&def.span, &doc.source);
                    return Ok(Some(GotoDefinitionResponse::Scalar(Location {
                        uri: uri.clone(),
                        range,
                    })));
                }
            }
        }

        Ok(None)
    }

    // ── Document Symbols ────────────────────────────────────────────────

    async fn document_symbol(
        &self,
        params: DocumentSymbolParams,
    ) -> Result<Option<DocumentSymbolResponse>> {
        let uri = &params.text_document.uri;

        let docs = self.documents.read().unwrap();
        if let Some(doc) = docs.get(uri) {
            let symbols: Vec<SymbolInformation> = doc
                .definitions
                .iter()
                .map(|def| {
                    #[allow(deprecated)]
                    SymbolInformation {
                        name: def.name.clone(),
                        kind: def.kind,
                        tags: None,
                        deprecated: None,
                        location: Location {
                            uri: uri.clone(),
                            range: span_to_range(&def.span, &doc.source),
                        },
                        container_name: None,
                    }
                })
                .collect();

            return Ok(Some(DocumentSymbolResponse::Flat(symbols)));
        }

        Ok(None)
    }

    // ── Completion ──────────────────────────────────────────────────────

    async fn completion(
        &self,
        params: CompletionParams,
    ) -> Result<Option<CompletionResponse>> {
        let uri = &params.text_document_position.text_document.uri;
        let mut items = Vec::new();

        // Keywords
        let keywords = [
            "fn", "let", "var", "const", "struct", "enum", "impl", "match",
            "if", "else", "for", "while", "return", "import", "type",
            "true", "false", "nil", "async", "await", "in", "break",
            "continue", "bail", "bail_if", "print",
        ];
        for kw in &keywords {
            items.push(CompletionItem {
                label: kw.to_string(),
                kind: Some(CompletionItemKind::KEYWORD),
                ..Default::default()
            });
        }

        // Types
        let types = [
            "i8", "i16", "i32", "i64", "i128", "u8", "u16", "u32", "u64", "u128",
            "f32", "f64", "bool", "String", "Bytes", "Result", "Option",
        ];
        for ty in &types {
            items.push(CompletionItem {
                label: ty.to_string(),
                kind: Some(CompletionItemKind::TYPE_PARAMETER),
                ..Default::default()
            });
        }

        // Project symbols
        let docs = self.documents.read().unwrap();
        if let Some(doc) = docs.get(uri) {
            for def in &doc.definitions {
                items.push(CompletionItem {
                    label: def.name.clone(),
                    kind: Some(match def.kind {
                        SymbolKind::FUNCTION => CompletionItemKind::FUNCTION,
                        SymbolKind::STRUCT => CompletionItemKind::STRUCT,
                        SymbolKind::ENUM => CompletionItemKind::ENUM,
                        SymbolKind::CONSTANT => CompletionItemKind::CONSTANT,
                        _ => CompletionItemKind::VARIABLE,
                    }),
                    detail: Some(def.detail.clone()),
                    ..Default::default()
                });
            }
        }

        Ok(Some(CompletionResponse::Array(items)))
    }
}

// ── Helpers ─────────────────────────────────────────────────────────────────

fn span_to_range(span: &Span, source: &str) -> Range {
    let start = offset_to_position(source, span.start);
    let end = offset_to_position(source, span.end);
    Range { start, end }
}

fn offset_to_position(source: &str, offset: usize) -> Position {
    let mut line = 0u32;
    let mut col = 0u32;
    for (i, ch) in source.char_indices() {
        if i >= offset {
            break;
        }
        if ch == '\n' {
            line += 1;
            col = 0;
        } else {
            col += 1;
        }
    }
    Position { line, character: col }
}

fn position_to_offset(source: &str, pos: Position) -> usize {
    let mut line = 0u32;
    let mut col = 0u32;
    for (i, ch) in source.char_indices() {
        if line == pos.line && col == pos.character {
            return i;
        }
        if ch == '\n' {
            if line == pos.line {
                return i; // past end of line
            }
            line += 1;
            col = 0;
        } else {
            col += 1;
        }
    }
    source.len()
}

fn word_at_offset(source: &str, offset: usize) -> String {
    let bytes = source.as_bytes();
    if offset >= bytes.len() {
        return String::new();
    }

    // Scan backwards to find word start
    let mut start = offset;
    while start > 0 && is_ident_char(bytes[start - 1]) {
        start -= 1;
    }

    // Scan forwards to find word end
    let mut end = offset;
    while end < bytes.len() && is_ident_char(bytes[end]) {
        end += 1;
    }

    source[start..end].to_string()
}

fn is_ident_char(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'_'
}

fn collect_definitions(program: &Program, _source: &str) -> Vec<SymbolDef> {
    let mut defs = Vec::new();

    for item in &program.items {
        match item {
            Item::Fn(f) => {
                let params: Vec<String> = f
                    .params
                    .iter()
                    .map(|p| format!("{}: {}", p.name, format_type_expr(&p.ty)))
                    .collect();
                let ret = f
                    .return_type
                    .as_ref()
                    .map(|t| format!(" -> {}", format_type_expr(t)))
                    .unwrap_or_default();
                defs.push(SymbolDef {
                    name: f.name.clone(),
                    kind: SymbolKind::FUNCTION,
                    span: f.span,
                    detail: format!("fn {}({}){}", f.name, params.join(", "), ret),
                });
            }
            Item::Struct(s) => {
                let fields: Vec<String> = s
                    .fields
                    .iter()
                    .map(|f| format!("{}: {}", f.name, format_type_expr(&f.ty)))
                    .collect();
                defs.push(SymbolDef {
                    name: s.name.clone(),
                    kind: SymbolKind::STRUCT,
                    span: s.span,
                    detail: format!("struct {} {{ {} }}", s.name, fields.join(", ")),
                });
            }
            Item::Enum(e) => {
                let variants: Vec<String> = e.variants.iter().map(|v| v.name.clone()).collect();
                defs.push(SymbolDef {
                    name: e.name.clone(),
                    kind: SymbolKind::ENUM,
                    span: e.span,
                    detail: format!("enum {} {{ {} }}", e.name, variants.join(", ")),
                });
            }
            Item::Impl(imp) => {
                for method in &imp.methods {
                    let params: Vec<String> = method
                        .params
                        .iter()
                        .map(|p| format!("{}: {}", p.name, format_type_expr(&p.ty)))
                        .collect();
                    let ret = method
                        .return_type
                        .as_ref()
                        .map(|t| format!(" -> {}", format_type_expr(t)))
                        .unwrap_or_default();
                    defs.push(SymbolDef {
                        name: format!("{}.{}", imp.target, method.name),
                        kind: SymbolKind::METHOD,
                        span: method.span,
                        detail: format!(
                            "fn {}.{}({}){}",
                            imp.target,
                            method.name,
                            params.join(", "),
                            ret
                        ),
                    });
                }
            }
            Item::Const(c) => {
                defs.push(SymbolDef {
                    name: c.name.clone(),
                    kind: SymbolKind::CONSTANT,
                    span: c.span,
                    detail: format!("const {}", c.name),
                });
            }
            Item::TypeAlias(t) => {
                defs.push(SymbolDef {
                    name: t.name.clone(),
                    kind: SymbolKind::TYPE_PARAMETER,
                    span: t.span,
                    detail: format!("type {} = {}", t.name, format_type_expr(&t.ty)),
                });
            }
            Item::Import(_) => {}
            Item::Trait(t) => {
                defs.push(SymbolDef {
                    name: t.name.clone(),
                    kind: SymbolKind::INTERFACE,
                    span: t.span,
                    detail: format!("trait {} ({} methods)", t.name, t.methods.len()),
                });
                for method in &t.methods {
                    defs.push(SymbolDef {
                        name: format!("{}.{}", t.name, method.name),
                        kind: SymbolKind::METHOD,
                        span: method.span,
                        detail: format!("fn {}({})", method.name, method.params.iter().map(|p| p.name.clone()).collect::<Vec<_>>().join(", ")),
                    });
                }
            }
        }
    }

    defs
}

fn format_type_expr(ty: &TypeExpr) -> String {
    match &ty.kind {
        TypeExprKind::Named(name) => name.clone(),
        TypeExprKind::Slice(inner) => format!("[]{}", format_type_expr(inner)),
        TypeExprKind::Optional(inner) => format!("{}?", format_type_expr(inner)),
        TypeExprKind::Tuple(items) => {
            let parts: Vec<String> = items.iter().map(|i| format_type_expr(i)).collect();
            format!("({})", parts.join(", "))
        }
        TypeExprKind::Generic { name, args } => {
            let parts: Vec<String> = args.iter().map(|p| format_type_expr(p)).collect();
            format!("{}<{}>", name, parts.join(", "))
        }
        TypeExprKind::Function { params, return_type } => {
            let parts: Vec<String> = params.iter().map(|p| format_type_expr(p)).collect();
            format!("fn({}) -> {}", parts.join(", "), format_type_expr(return_type))
        }
        TypeExprKind::Boxed(inner) => format!("Box<{}>", format_type_expr(inner)),
        TypeExprKind::ImplTrait(name) => format!("impl {name}"),
        TypeExprKind::DynTrait(name) => format!("dyn {name}"),
    }
}

fn tallow_diag_to_lsp(d: &crate::error::Diagnostic, source: &str) -> Diagnostic {
    let severity = match d.severity {
        Severity::Error => DiagnosticSeverity::ERROR,
        Severity::Warning => DiagnosticSeverity::WARNING,
    };

    let mut message = d.msg.clone();
    if let Some(ref help) = d.help {
        message.push_str(&format!("\nhelp: {help}"));
    }

    Diagnostic {
        range: span_to_range(&d.span, source),
        severity: Some(severity),
        code: Some(NumberOrString::String(d.code.to_string())),
        source: Some("tallow".into()),
        message,
        related_information: None,
        tags: None,
        code_description: None,
        data: None,
    }
}

fn keyword_info(word: &str) -> Option<&'static str> {
    match word {
        "fn" => Some("**fn** — Declare a function\n\n```tallow\nfn name(params) -> ReturnType { body }\n```"),
        "let" => Some("**let** — Immutable variable binding\n\n```tallow\nlet x = 42\n```"),
        "var" => Some("**var** — Mutable variable binding\n\n```tallow\nvar count = 0\ncount = count + 1\n```"),
        "const" => Some("**const** — Compile-time constant\n\n```tallow\nconst MAX = 100\n```"),
        "struct" => Some("**struct** — Define a data structure\n\n```tallow\nstruct Point { x: f64, y: f64 }\n```"),
        "enum" => Some("**enum** — Define a tagged union\n\n```tallow\nenum Status { Active, Inactive, Pending(reason: String) }\n```"),
        "impl" => Some("**impl** — Implement methods on a type\n\n```tallow\nimpl Point { fn distance(self) -> f64 { ... } }\n```"),
        "match" => Some("**match** — Exhaustive pattern matching\n\n```tallow\nmatch value { 1 -> \"one\", _ -> \"other\" }\n```"),
        "for" => Some("**for** — Iterate over a collection or range\n\n```tallow\nfor item in items { ... }\nfor i in 0..10 { ... }\n```"),
        "while" => Some("**while** — Loop while condition is true\n\n```tallow\nwhile count < 10 { count = count + 1 }\n```"),
        "if" => Some("**if** — Conditional expression\n\n```tallow\nif condition { then_branch } else { else_branch }\n```"),
        "return" => Some("**return** — Early return from function"),
        "bail" => Some("**bail** — Return Err(...) from function\n\n```tallow\nbail \"something went wrong\"\n```"),
        "import" => Some("**import** — Import items from another module\n\n```tallow\nimport math\nimport models.Point\n```"),
        "async" => Some("**async** — Mark function as asynchronous"),
        "await" => Some("**await** — Await an async result"),
        "private" => Some("**private** — GDPR personal data type qualifier. Compiler-tracked, cannot be logged raw."),
        "secret" => Some("**secret** — Credential type qualifier. Zero-wiped on scope exit, never logged."),
        _ => None,
    }
}

// ── Server Entry Point ──────────────────────────────────────────────────────

pub async fn run_lsp_server() {
    let stdin = tokio::io::stdin();
    let stdout = tokio::io::stdout();

    let (service, socket) = LspService::new(|client| TallowLanguageServer::new(client));
    Server::new(stdin, stdout, socket).serve(service).await;
}
