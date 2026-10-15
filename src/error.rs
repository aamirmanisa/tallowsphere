use crate::lexer::Span;
use std::fmt;

// ── Compiler Diagnostic ──────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Severity {
    Error,
    Warning,
}

#[derive(Debug, Clone)]
pub struct Diagnostic {
    pub severity: Severity,
    pub code: &'static str,
    pub msg: String,
    pub span: Span,
    pub help: Option<String>,
}

impl Diagnostic {
    pub fn error(code: &'static str, msg: impl Into<String>, span: Span) -> Self {
        Self {
            severity: Severity::Error,
            code,
            msg: msg.into(),
            span,
            help: None,
        }
    }

    pub fn warning(code: &'static str, msg: impl Into<String>, span: Span) -> Self {
        Self {
            severity: Severity::Warning,
            code,
            msg: msg.into(),
            span,
            help: None,
        }
    }

    pub fn with_help(mut self, help: impl Into<String>) -> Self {
        self.help = Some(help.into());
        self
    }

    /// Format the diagnostic with source context.
    pub fn render(&self, source: &str, filename: &str) -> String {
        let (line, col) = self.span.line_col(source);
        let severity_str = match self.severity {
            Severity::Error => "error",
            Severity::Warning => "warning",
        };

        let source_line = source.lines().nth(line - 1).unwrap_or("");
        let pointer = " ".repeat(col - 1) + "^";

        let mut out = format!(
            "{severity_str}[{code}]: {msg}\n  --> {filename}:{line}:{col}\n   |\n{line:>3} | {source_line}\n   | {pointer}",
            code = self.code,
            msg = self.msg,
        );

        if let Some(ref help) = self.help {
            out.push_str(&format!("\n   = help: {help}"));
        }

        out
    }
}

impl fmt::Display for Diagnostic {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let severity_str = match self.severity {
            Severity::Error => "error",
            Severity::Warning => "warning",
        };
        write!(f, "{severity_str}[{}]: {}", self.code, self.msg)
    }
}

// ── Diagnostic Bag ───────────────────────────────────────────────────────────

/// Collects diagnostics from all compiler passes.
#[derive(Debug, Default)]
pub struct Diagnostics {
    pub items: Vec<Diagnostic>,
}

impl Diagnostics {
    pub fn new() -> Self {
        Self { items: Vec::new() }
    }

    pub fn error(&mut self, code: &'static str, msg: impl Into<String>, span: Span) {
        self.items.push(Diagnostic::error(code, msg, span));
    }

    pub fn warning(&mut self, code: &'static str, msg: impl Into<String>, span: Span) {
        self.items.push(Diagnostic::warning(code, msg, span));
    }

    pub fn push(&mut self, diag: Diagnostic) {
        self.items.push(diag);
    }

    pub fn has_errors(&self) -> bool {
        self.items
            .iter()
            .any(|d| d.severity == Severity::Error)
    }

    pub fn error_count(&self) -> usize {
        self.items
            .iter()
            .filter(|d| d.severity == Severity::Error)
            .count()
    }

    pub fn warning_count(&self) -> usize {
        self.items
            .iter()
            .filter(|d| d.severity == Severity::Warning)
            .count()
    }

    pub fn render_all(&self, source: &str, filename: &str) -> String {
        self.items
            .iter()
            .map(|d| d.render(source, filename))
            .collect::<Vec<_>>()
            .join("\n\n")
    }
}
