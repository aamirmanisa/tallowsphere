use std::fmt;

// ── Source Span ──────────────────────────────────────────────────────────────

/// Byte-offset span into the source text. Every token carries one.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct Span {
    /// Byte offset of the first character.
    pub start: usize,
    /// Byte offset one past the last character.
    pub end: usize,
}

impl Span {
    pub fn new(start: usize, end: usize) -> Self {
        Self { start, end }
    }

    /// Return the slice of source text this span covers.
    pub fn text<'a>(&self, source: &'a str) -> &'a str {
        &source[self.start..self.end]
    }

    /// Resolve to human-readable line:col (both 1-based).
    pub fn line_col(&self, source: &str) -> (usize, usize) {
        let mut line = 1;
        let mut col = 1;
        for (i, ch) in source.char_indices() {
            if i == self.start {
                break;
            }
            if ch == '\n' {
                line += 1;
                col = 1;
            } else {
                col += 1;
            }
        }
        (line, col)
    }
}

impl fmt::Debug for Span {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}..{}", self.start, self.end)
    }
}

// ── Token Kind ───────────────────────────────────────────────────────────────

#[derive(Clone, Debug, PartialEq)]
pub enum TokenKind {
    // ── Keywords ──
    Fn,
    Let,
    Var,
    Const,
    Struct,
    Enum,
    Impl,
    Trait,
    Match,
    If,
    Else,
    For,
    While,
    In,
    Return,
    Import,
    Async,
    Await,
    True,
    False,
    Nil,
    Type,
    SelfValue, // `self`
    Mut,
    As,
    Bail,
    BailIf,
    Break,
    Continue,
    Catch,
    Loop,
    Dyn,
    Defer,

    // ── Privacy qualifiers ──
    Private,
    Secret,

    // ── Literals ──
    IntLit(i128),
    FloatLit(f64),
    StringLit(String),
    /// First segment of an interpolated string: `"hello {` → StringStart("hello ")
    StringStart(String),
    /// Middle segment between interpolations: `} world {` → StringMid(" world ")
    StringMid(String),
    /// Final segment after last interpolation: `}!"` → StringEnd("!")
    StringEnd(String),

    // ── Identifiers ──
    Ident(String),

    // ── Delimiters ──
    LParen,   // (
    RParen,   // )
    LBrace,   // {
    RBrace,   // }
    LBracket, // [
    RBracket, // ]

    // ── Operators ──
    Plus,         // +
    Minus,        // -
    Star,         // *
    Slash,        // /
    Percent,      // %
    Eq,           // =
    EqEq,         // ==
    BangEq,       // !=
    Lt,           // <
    Gt,           // >
    LtEq,         // <=
    GtEq,         // >=
    Bang,         // !
    AmpAmp,       // &&
    PipePipe,     // ||
    Amp,          // &
    Pipe,         // |
    Caret,        // ^
    Tilde,        // ~
    StarStar,     // **
    Shl,          // <<
    Shr,          // >>
    PlusEq,       // +=
    MinusEq,      // -=
    StarEq,       // *=
    SlashEq,      // /=
    PercentEq,    // %=
    StarStarEq,   // **=
    ShlEq,        // <<=
    ShrEq,        // >>=
    AmpEq,        // &=
    PipeEq,       // |=
    CaretEq,      // ^=

    // ── Punctuation ──
    Dot,          // .
    DotDot,       // ..
    Comma,        // ,
    Colon,        // :
    ColonColon,   // ::
    Semi,         // ;
    Arrow,        // ->
    FatArrow,     // =>
    Question,     // ?
    At,           // @
    Hash,         // #
    Underscore,   // _ (as pattern)

    // ── Special ──
    Eof,
}

impl fmt::Display for TokenKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            TokenKind::Fn => write!(f, "fn"),
            TokenKind::Let => write!(f, "let"),
            TokenKind::Var => write!(f, "var"),
            TokenKind::Const => write!(f, "const"),
            TokenKind::Struct => write!(f, "struct"),
            TokenKind::Enum => write!(f, "enum"),
            TokenKind::Impl => write!(f, "impl"),
            TokenKind::Trait => write!(f, "trait"),
            TokenKind::Match => write!(f, "match"),
            TokenKind::If => write!(f, "if"),
            TokenKind::Else => write!(f, "else"),
            TokenKind::For => write!(f, "for"),
            TokenKind::While => write!(f, "while"),
            TokenKind::In => write!(f, "in"),
            TokenKind::Return => write!(f, "return"),
            TokenKind::Import => write!(f, "import"),
            TokenKind::Async => write!(f, "async"),
            TokenKind::Await => write!(f, "await"),
            TokenKind::True => write!(f, "true"),
            TokenKind::False => write!(f, "false"),
            TokenKind::Nil => write!(f, "nil"),
            TokenKind::Type => write!(f, "type"),
            TokenKind::SelfValue => write!(f, "self"),
            TokenKind::Mut => write!(f, "mut"),
            TokenKind::As => write!(f, "as"),
            TokenKind::Bail => write!(f, "bail"),
            TokenKind::BailIf => write!(f, "bail_if"),
            TokenKind::Break => write!(f, "break"),
            TokenKind::Continue => write!(f, "continue"),
            TokenKind::Catch => write!(f, "catch"),
            TokenKind::Loop => write!(f, "loop"),
            TokenKind::Dyn => write!(f, "dyn"),
            TokenKind::Defer => write!(f, "defer"),
            TokenKind::Private => write!(f, "private"),
            TokenKind::Secret => write!(f, "secret"),
            TokenKind::IntLit(n) => write!(f, "{n}"),
            TokenKind::FloatLit(n) => write!(f, "{n}"),
            TokenKind::StringLit(s) => write!(f, "\"{s}\""),
            TokenKind::StringStart(s) => write!(f, "\"{s}{{"),
            TokenKind::StringMid(s) => write!(f, "}}{s}{{"),
            TokenKind::StringEnd(s) => write!(f, "}}{s}\""),
            TokenKind::Ident(s) => write!(f, "{s}"),
            TokenKind::LParen => write!(f, "("),
            TokenKind::RParen => write!(f, ")"),
            TokenKind::LBrace => write!(f, "{{"),
            TokenKind::RBrace => write!(f, "}}"),
            TokenKind::LBracket => write!(f, "["),
            TokenKind::RBracket => write!(f, "]"),
            TokenKind::Plus => write!(f, "+"),
            TokenKind::Minus => write!(f, "-"),
            TokenKind::Star => write!(f, "*"),
            TokenKind::Slash => write!(f, "/"),
            TokenKind::Percent => write!(f, "%"),
            TokenKind::Eq => write!(f, "="),
            TokenKind::EqEq => write!(f, "=="),
            TokenKind::BangEq => write!(f, "!="),
            TokenKind::Lt => write!(f, "<"),
            TokenKind::Gt => write!(f, ">"),
            TokenKind::LtEq => write!(f, "<="),
            TokenKind::GtEq => write!(f, ">="),
            TokenKind::Bang => write!(f, "!"),
            TokenKind::AmpAmp => write!(f, "&&"),
            TokenKind::PipePipe => write!(f, "||"),
            TokenKind::Amp => write!(f, "&"),
            TokenKind::Pipe => write!(f, "|"),
            TokenKind::Caret => write!(f, "^"),
            TokenKind::Tilde => write!(f, "~"),
            TokenKind::StarStar => write!(f, "**"),
            TokenKind::Shl => write!(f, "<<"),
            TokenKind::Shr => write!(f, ">>"),
            TokenKind::PlusEq => write!(f, "+="),
            TokenKind::MinusEq => write!(f, "-="),
            TokenKind::StarEq => write!(f, "*="),
            TokenKind::SlashEq => write!(f, "/="),
            TokenKind::PercentEq => write!(f, "%="),
            TokenKind::StarStarEq => write!(f, "**="),
            TokenKind::ShlEq => write!(f, "<<="),
            TokenKind::ShrEq => write!(f, ">>="),
            TokenKind::AmpEq => write!(f, "&="),
            TokenKind::PipeEq => write!(f, "|="),
            TokenKind::CaretEq => write!(f, "^="),
            TokenKind::Dot => write!(f, "."),
            TokenKind::DotDot => write!(f, ".."),
            TokenKind::Comma => write!(f, ","),
            TokenKind::Colon => write!(f, ":"),
            TokenKind::ColonColon => write!(f, "::"),
            TokenKind::Semi => write!(f, ";"),
            TokenKind::Arrow => write!(f, "->"),
            TokenKind::FatArrow => write!(f, "=>"),
            TokenKind::Question => write!(f, "?"),
            TokenKind::At => write!(f, "@"),
            TokenKind::Hash => write!(f, "#"),
            TokenKind::Underscore => write!(f, "_"),
            TokenKind::Eof => write!(f, "EOF"),
        }
    }
}

// ── Token ────────────────────────────────────────────────────────────────────

#[derive(Clone, Debug, PartialEq)]
pub struct Token {
    pub kind: TokenKind,
    pub span: Span,
}

impl Token {
    pub fn new(kind: TokenKind, span: Span) -> Self {
        Self { kind, span }
    }
}

// ── Lexer Error ──────────────────────────────────────────────────────────────

#[derive(Debug, thiserror::Error)]
pub enum LexError {
    #[error("{msg}")]
    Error { msg: String, span: Span },
}

impl LexError {
    fn new(msg: impl Into<String>, span: Span) -> Self {
        LexError::Error {
            msg: msg.into(),
            span,
        }
    }

    pub fn span(&self) -> Span {
        match self {
            LexError::Error { span, .. } => *span,
        }
    }
}

// ── Lexer ────────────────────────────────────────────────────────────────────

pub struct Lexer<'src> {
    source: &'src str,
    bytes: &'src [u8],
    /// Current byte offset into source.
    pos: usize,
    /// Stack of brace depths for nested string interpolations.
    /// Non-empty means we're inside an interpolated expression.
    interp_stack: Vec<u32>,
    /// When true, the next token should resume scanning a string literal
    /// (after an interpolation's closing `}` was consumed).
    in_string_resume: bool,
}

impl<'src> Lexer<'src> {
    pub fn new(source: &'src str) -> Self {
        Self {
            source,
            bytes: source.as_bytes(),
            pos: 0,
            interp_stack: Vec::new(),
            in_string_resume: false,
        }
    }

    /// Tokenize the entire source, returning tokens + any errors.
    /// Continues past errors to report as many as possible.
    pub fn tokenize(mut self) -> (Vec<Token>, Vec<LexError>) {
        let mut tokens = Vec::new();
        let mut errors = Vec::new();

        loop {
            // If we're resuming a string after `}` closed an interpolation,
            // continue scanning the string body (don't skip whitespace).
            if self.in_string_resume {
                self.in_string_resume = false;
                match self.scan_string_continuation() {
                    Ok(tok) => tokens.push(tok),
                    Err(e) => errors.push(e),
                }
                continue;
            }

            self.skip_whitespace_and_comments();

            if self.is_at_end() {
                tokens.push(Token::new(TokenKind::Eof, Span::new(self.pos, self.pos)));
                break;
            }

            match self.next_token() {
                Ok(tok) => {
                    // Track brace depth inside interpolation expressions
                    if !self.interp_stack.is_empty() {
                        match &tok.kind {
                            TokenKind::LBrace => {
                                *self.interp_stack.last_mut().unwrap() += 1;
                            }
                            TokenKind::RBrace => {
                                let depth = self.interp_stack.last_mut().unwrap();
                                if *depth == 0 {
                                    // This `}` ends the interpolation — resume string
                                    self.interp_stack.pop();
                                    self.in_string_resume = true;
                                    continue; // don't emit the `}` token
                                } else {
                                    *depth -= 1;
                                }
                            }
                            _ => {}
                        }
                    }
                    tokens.push(tok);
                }
                Err(e) => {
                    errors.push(e);
                    // Skip the bad byte and keep going.
                    self.advance();
                }
            }
        }

        (tokens, errors)
    }

    // ── Core scanning ────────────────────────────────────────────────────

    fn next_token(&mut self) -> Result<Token, LexError> {
        let start = self.pos;
        let ch = self.peek().unwrap();

        // ── String literals ──
        if ch == b'"' {
            return self.scan_string();
        }

        // ── Single-quoted string literals (no interpolation, raw) ──
        if ch == b'\'' {
            return self.scan_single_quote_string();
        }

        // ── Number literals ──
        if ch.is_ascii_digit() {
            return self.scan_number();
        }

        // ── Identifiers and keywords ──
        if is_ident_start(ch) {
            return Ok(self.scan_ident_or_keyword());
        }

        // ── Operators and punctuation ──
        self.advance();
        let kind = match ch {
            b'(' => TokenKind::LParen,
            b')' => TokenKind::RParen,
            b'{' => TokenKind::LBrace,
            b'}' => TokenKind::RBrace,
            b'[' => TokenKind::LBracket,
            b']' => TokenKind::RBracket,
            b',' => TokenKind::Comma,
            b';' => TokenKind::Semi,
            b'~' => TokenKind::Tilde,
            b'?' => TokenKind::Question,
            b'#' => TokenKind::Hash,
            b'@' => TokenKind::At,
            b'+' => {
                if self.match_byte(b'=') { TokenKind::PlusEq } else { TokenKind::Plus }
            }
            b'*' => {
                if self.match_byte(b'*') {
                    if self.match_byte(b'=') { TokenKind::StarStarEq } else { TokenKind::StarStar }
                } else if self.match_byte(b'=') { TokenKind::StarEq } else { TokenKind::Star }
            }
            b'^' => {
                if self.match_byte(b'=') { TokenKind::CaretEq } else { TokenKind::Caret }
            }
            b'%' => {
                if self.match_byte(b'=') { TokenKind::PercentEq } else { TokenKind::Percent }
            }
            b'.' => {
                if self.match_byte(b'.') {
                    TokenKind::DotDot
                } else {
                    TokenKind::Dot
                }
            }
            b':' => {
                if self.match_byte(b':') {
                    TokenKind::ColonColon
                } else {
                    TokenKind::Colon
                }
            }
            b'-' => {
                if self.match_byte(b'>') {
                    TokenKind::Arrow
                } else if self.match_byte(b'=') {
                    TokenKind::MinusEq
                } else {
                    TokenKind::Minus
                }
            }
            b'=' => {
                if self.match_byte(b'>') {
                    TokenKind::FatArrow
                } else if self.match_byte(b'=') {
                    TokenKind::EqEq
                } else {
                    TokenKind::Eq
                }
            }
            b'!' => {
                if self.match_byte(b'=') {
                    TokenKind::BangEq
                } else {
                    TokenKind::Bang
                }
            }
            b'<' => {
                if self.match_byte(b'<') {
                    if self.match_byte(b'=') { TokenKind::ShlEq } else { TokenKind::Shl }
                } else if self.match_byte(b'=') {
                    TokenKind::LtEq
                } else {
                    TokenKind::Lt
                }
            }
            b'>' => {
                if self.match_byte(b'>') {
                    if self.match_byte(b'=') { TokenKind::ShrEq } else { TokenKind::Shr }
                } else if self.match_byte(b'=') {
                    TokenKind::GtEq
                } else {
                    TokenKind::Gt
                }
            }
            b'&' => {
                if self.match_byte(b'&') {
                    TokenKind::AmpAmp
                } else if self.match_byte(b'=') {
                    TokenKind::AmpEq
                } else {
                    TokenKind::Amp
                }
            }
            b'|' => {
                if self.match_byte(b'|') {
                    TokenKind::PipePipe
                } else if self.match_byte(b'=') {
                    TokenKind::PipeEq
                } else {
                    TokenKind::Pipe
                }
            }
            b'/' => {
                if self.match_byte(b'=') { TokenKind::SlashEq } else { TokenKind::Slash }
            } // Comments already stripped
            _ => {
                return Err(LexError::new(
                    format!("unexpected character: '{}'", ch as char),
                    Span::new(start, self.pos),
                ));
            }
        };

        Ok(Token::new(kind, Span::new(start, self.pos)))
    }

    // ── String scanning ──────────────────────────────────────────────────

    fn scan_string(&mut self) -> Result<Token, LexError> {
        let start = self.pos;
        self.advance(); // consume opening "

        // Check for triple-quoted string: """..."""
        if self.peek() == Some(b'"') && self.pos + 1 < self.bytes.len() && self.bytes[self.pos + 1] == b'"' {
            self.advance(); // second "
            self.advance(); // third "
            return self.scan_triple_quoted_string(start);
        }

        let mut value = String::new();

        loop {
            if self.is_at_end() {
                return Err(LexError::new(
                    "unterminated string literal",
                    Span::new(start, self.pos),
                ));
            }

            let ch = self.peek().unwrap();

            if ch == b'"' {
                self.advance(); // consume closing "
                break;
            }

            if ch == b'\\' {
                self.scan_escape(&mut value, start)?;
                continue;
            }

            // Interpolation: unescaped `{` starts an embedded expression
            if ch == b'{' {
                self.advance(); // consume '{'
                self.interp_stack.push(0); // track brace depth in the expression
                return Ok(Token::new(
                    TokenKind::StringStart(value),
                    Span::new(start, self.pos),
                ));
            }

            value.push(ch as char);
            self.advance();
        }

        Ok(Token::new(
            TokenKind::StringLit(value),
            Span::new(start, self.pos),
        ))
    }

    /// Scan a triple-quoted string: """..."""
    /// Supports interpolation and escape sequences, but also allows unescaped
    /// newlines and double quotes inside.
    fn scan_triple_quoted_string(&mut self, start: usize) -> Result<Token, LexError> {
        let mut value = String::new();

        loop {
            if self.is_at_end() {
                return Err(LexError::new(
                    "unterminated triple-quoted string",
                    Span::new(start, self.pos),
                ));
            }

            let ch = self.peek().unwrap();

            // Check for closing """
            if ch == b'"' && self.pos + 2 < self.bytes.len()
                && self.bytes[self.pos + 1] == b'"'
                && self.bytes[self.pos + 2] == b'"'
            {
                self.advance(); // first "
                self.advance(); // second "
                self.advance(); // third "
                break;
            }

            if ch == b'\\' {
                self.scan_escape(&mut value, start)?;
                continue;
            }

            // Interpolation inside triple-quoted strings
            if ch == b'{' {
                self.advance();
                self.interp_stack.push(0);
                return Ok(Token::new(
                    TokenKind::StringStart(value),
                    Span::new(start, self.pos),
                ));
            }

            value.push(ch as char);
            self.advance();
        }

        Ok(Token::new(
            TokenKind::StringLit(value),
            Span::new(start, self.pos),
        ))
    }

    /// Scan a single-quoted string literal: `'...'`
    /// No interpolation, no escape sequences — raw content between `'` delimiters.
    /// This enables embedding JS code with double quotes: `'document.querySelector("button")'`
    fn scan_single_quote_string(&mut self) -> Result<Token, LexError> {
        let start = self.pos;
        self.advance(); // consume opening '

        let mut value = String::new();

        loop {
            if self.is_at_end() {
                return Err(LexError::new(
                    "unterminated single-quoted string literal",
                    Span::new(start, self.pos),
                ));
            }

            let ch = self.peek().unwrap();

            if ch == b'\'' {
                self.advance(); // consume closing '
                break;
            }

            // Allow backslash-escaped single quote inside: \'
            if ch == b'\\' && self.pos + 1 < self.source.len() && self.source.as_bytes()[self.pos + 1] == b'\'' {
                self.advance(); // skip backslash
                value.push('\'');
                self.advance(); // skip the quote
                continue;
            }

            value.push(ch as char);
            self.advance();
        }

        Ok(Token::new(
            TokenKind::StringLit(value),
            Span::new(start, self.pos),
        ))
    }

    /// Continue scanning a string after an interpolation's `}` was consumed.
    /// Produces either `StringMid` (another `{` found) or `StringEnd` (closing `"` found).
    fn scan_string_continuation(&mut self) -> Result<Token, LexError> {
        let start = self.pos;
        let mut value = String::new();

        loop {
            if self.is_at_end() {
                return Err(LexError::new(
                    "unterminated string literal (in interpolation)",
                    Span::new(start, self.pos),
                ));
            }

            let ch = self.peek().unwrap();

            if ch == b'"' {
                self.advance(); // consume closing "
                return Ok(Token::new(
                    TokenKind::StringEnd(value),
                    Span::new(start, self.pos),
                ));
            }

            if ch == b'\\' {
                self.scan_escape(&mut value, start)?;
                continue;
            }

            // Another interpolation
            if ch == b'{' {
                self.advance(); // consume '{'
                self.interp_stack.push(0);
                return Ok(Token::new(
                    TokenKind::StringMid(value),
                    Span::new(start, self.pos),
                ));
            }

            value.push(ch as char);
            self.advance();
        }
    }

    /// Scan a single escape sequence, appending to `value`.
    fn scan_escape(&mut self, value: &mut String, string_start: usize) -> Result<(), LexError> {
        self.advance(); // consume backslash
        if self.is_at_end() {
            return Err(LexError::new(
                "unterminated escape sequence",
                Span::new(string_start, self.pos),
            ));
        }
        let escaped = self.peek().unwrap();
        self.advance();
        match escaped {
            b'n' => value.push('\n'),
            b't' => value.push('\t'),
            b'r' => value.push('\r'),
            b'\\' => value.push('\\'),
            b'"' => value.push('"'),
            b'0' => value.push('\0'),
            b'{' => value.push('{'),
            b'}' => value.push('}'),
            _ => {
                return Err(LexError::new(
                    format!("invalid escape: \\{}", escaped as char),
                    Span::new(self.pos - 2, self.pos),
                ));
            }
        }
        Ok(())
    }

    // ── Number scanning ──────────────────────────────────────────────────

    fn scan_number(&mut self) -> Result<Token, LexError> {
        let start = self.pos;

        // Check for 0x, 0b, 0o prefixes
        if self.peek() == Some(b'0') && self.pos + 1 < self.bytes.len() {
            match self.bytes[self.pos + 1] {
                b'x' | b'X' => return self.scan_hex(start),
                b'b' | b'B' => return self.scan_binary(start),
                b'o' | b'O' => return self.scan_octal(start),
                _ => {}
            }
        }

        // Decimal integer or float
        self.eat_digits();

        // Check for float: dot followed by digit (not `..` range)
        let is_float = self.peek() == Some(b'.')
            && self.pos + 1 < self.bytes.len()
            && self.bytes[self.pos + 1].is_ascii_digit();

        if is_float {
            self.advance(); // consume '.'
            self.eat_digits();

            // Scientific notation
            if matches!(self.peek(), Some(b'e' | b'E')) {
                self.advance();
                if matches!(self.peek(), Some(b'+' | b'-')) {
                    self.advance();
                }
                self.eat_digits();
            }

            let text: String = self.source[start..self.pos]
                .chars()
                .filter(|c| *c != '_')
                .collect();
            let val: f64 = text.parse().map_err(|_| {
                LexError::new("invalid float literal", Span::new(start, self.pos))
            })?;
            Ok(Token::new(
                TokenKind::FloatLit(val),
                Span::new(start, self.pos),
            ))
        } else {
            let text: String = self.source[start..self.pos]
                .chars()
                .filter(|c| *c != '_')
                .collect();
            let val: i128 = text.parse().map_err(|_| {
                LexError::new("invalid integer literal", Span::new(start, self.pos))
            })?;
            Ok(Token::new(
                TokenKind::IntLit(val),
                Span::new(start, self.pos),
            ))
        }
    }

    fn scan_hex(&mut self, start: usize) -> Result<Token, LexError> {
        self.advance(); // '0'
        self.advance(); // 'x'
        let digit_start = self.pos;
        while let Some(ch) = self.peek() {
            if ch.is_ascii_hexdigit() || ch == b'_' {
                self.advance();
            } else {
                break;
            }
        }
        if self.pos == digit_start {
            return Err(LexError::new(
                "expected hex digits after 0x",
                Span::new(start, self.pos),
            ));
        }
        let text: String = self.source[digit_start..self.pos]
            .chars()
            .filter(|c| *c != '_')
            .collect();
        let val = i128::from_str_radix(&text, 16).map_err(|_| {
            LexError::new("invalid hex literal", Span::new(start, self.pos))
        })?;
        Ok(Token::new(
            TokenKind::IntLit(val),
            Span::new(start, self.pos),
        ))
    }

    fn scan_binary(&mut self, start: usize) -> Result<Token, LexError> {
        self.advance(); // '0'
        self.advance(); // 'b'
        let digit_start = self.pos;
        while let Some(ch) = self.peek() {
            if ch == b'0' || ch == b'1' || ch == b'_' {
                self.advance();
            } else {
                break;
            }
        }
        if self.pos == digit_start {
            return Err(LexError::new(
                "expected binary digits after 0b",
                Span::new(start, self.pos),
            ));
        }
        let text: String = self.source[digit_start..self.pos]
            .chars()
            .filter(|c| *c != '_')
            .collect();
        let val = i128::from_str_radix(&text, 2).map_err(|_| {
            LexError::new("invalid binary literal", Span::new(start, self.pos))
        })?;
        Ok(Token::new(
            TokenKind::IntLit(val),
            Span::new(start, self.pos),
        ))
    }

    fn scan_octal(&mut self, start: usize) -> Result<Token, LexError> {
        self.advance(); // '0'
        self.advance(); // 'o'
        let digit_start = self.pos;
        while let Some(ch) = self.peek() {
            if (b'0'..=b'7').contains(&ch) || ch == b'_' {
                self.advance();
            } else {
                break;
            }
        }
        if self.pos == digit_start {
            return Err(LexError::new(
                "expected octal digits after 0o",
                Span::new(start, self.pos),
            ));
        }
        let text: String = self.source[digit_start..self.pos]
            .chars()
            .filter(|c| *c != '_')
            .collect();
        let val = i128::from_str_radix(&text, 8).map_err(|_| {
            LexError::new("invalid octal literal", Span::new(start, self.pos))
        })?;
        Ok(Token::new(
            TokenKind::IntLit(val),
            Span::new(start, self.pos),
        ))
    }

    /// Consume a run of ASCII digits and underscores.
    fn eat_digits(&mut self) {
        while let Some(ch) = self.peek() {
            if ch.is_ascii_digit() || ch == b'_' {
                self.advance();
            } else {
                break;
            }
        }
    }

    // ── Identifier / keyword scanning ────────────────────────────────────

    fn scan_ident_or_keyword(&mut self) -> Token {
        let start = self.pos;
        self.advance(); // first char already validated as ident_start

        while let Some(ch) = self.peek() {
            if is_ident_continue(ch) {
                self.advance();
            } else {
                break;
            }
        }

        let text = &self.source[start..self.pos];
        let kind = match text {
            "fn" => TokenKind::Fn,
            "let" => TokenKind::Let,
            "var" => TokenKind::Var,
            "const" => TokenKind::Const,
            "struct" => TokenKind::Struct,
            "enum" => TokenKind::Enum,
            "impl" => TokenKind::Impl,
            "trait" => TokenKind::Trait,
            "match" => TokenKind::Match,
            "if" => TokenKind::If,
            "else" => TokenKind::Else,
            "for" => TokenKind::For,
            "while" => TokenKind::While,
            "in" => TokenKind::In,
            "return" => TokenKind::Return,
            "import" => TokenKind::Import,
            "async" => TokenKind::Async,
            "await" => TokenKind::Await,
            "true" => TokenKind::True,
            "false" => TokenKind::False,
            "nil" => TokenKind::Nil,
            "type" => TokenKind::Type,
            "self" => TokenKind::SelfValue,
            "mut" => TokenKind::Mut,
            "as" => TokenKind::As,
            "bail" => TokenKind::Bail,
            "bail_if" => TokenKind::BailIf,
            "break" => TokenKind::Break,
            "continue" => TokenKind::Continue,
            "catch" => TokenKind::Catch,
            "loop" => TokenKind::Loop,
            "dyn" => TokenKind::Dyn,
            "defer" => TokenKind::Defer,
            "private" => TokenKind::Private,
            "secret" => TokenKind::Secret,
            "_" => TokenKind::Underscore,
            _ => TokenKind::Ident(text.to_string()),
        };

        Token::new(kind, Span::new(start, self.pos))
    }

    // ── Whitespace & comments ────────────────────────────────────────────

    fn skip_whitespace_and_comments(&mut self) {
        loop {
            // Skip whitespace
            while let Some(ch) = self.peek() {
                if ch.is_ascii_whitespace() {
                    self.advance();
                } else {
                    break;
                }
            }

            // Skip // line comments
            if self.peek() == Some(b'/') && self.peek_next() == Some(b'/') {
                while let Some(ch) = self.peek() {
                    if ch == b'\n' {
                        break;
                    }
                    self.advance();
                }
                continue; // re-check for more whitespace/comments
            }

            // Skip /* block comments */ (nestable)
            if self.peek() == Some(b'/') && self.peek_next() == Some(b'*') {
                self.advance(); // '/'
                self.advance(); // '*'
                let mut depth = 1u32;
                while depth > 0 && !self.is_at_end() {
                    if self.peek() == Some(b'/') && self.peek_next() == Some(b'*') {
                        self.advance();
                        self.advance();
                        depth += 1;
                    } else if self.peek() == Some(b'*') && self.peek_next() == Some(b'/') {
                        self.advance();
                        self.advance();
                        depth -= 1;
                    } else {
                        self.advance();
                    }
                }
                continue;
            }

            break;
        }
    }

    // ── Cursor helpers ───────────────────────────────────────────────────

    fn is_at_end(&self) -> bool {
        self.pos >= self.bytes.len()
    }

    fn peek(&self) -> Option<u8> {
        self.bytes.get(self.pos).copied()
    }

    fn peek_next(&self) -> Option<u8> {
        self.bytes.get(self.pos + 1).copied()
    }

    fn advance(&mut self) {
        if self.pos < self.bytes.len() {
            self.pos += 1;
        }
    }

    /// If the current byte matches `expected`, consume it and return true.
    fn match_byte(&mut self, expected: u8) -> bool {
        if self.peek() == Some(expected) {
            self.advance();
            true
        } else {
            false
        }
    }
}

// ── Character classification ─────────────────────────────────────────────────

fn is_ident_start(ch: u8) -> bool {
    ch.is_ascii_alphabetic() || ch == b'_'
}

fn is_ident_continue(ch: u8) -> bool {
    ch.is_ascii_alphanumeric() || ch == b'_'
}

// ── Convenience ──────────────────────────────────────────────────────────────

/// Tokenize source text. Returns (tokens, errors).
pub fn tokenize(source: &str) -> (Vec<Token>, Vec<LexError>) {
    // A `#!` line at byte 0 is the script's interpreter line, not program text
    // (`#!/usr/bin/env -S tallow`). Blank it instead of stripping it so every
    // span still indexes the original source, unchanged.
    if source.starts_with("#!") {
        let cut = source.find('\n').unwrap_or(source.len());
        let mut blanked = String::with_capacity(source.len());
        blanked.push_str(&" ".repeat(cut));
        blanked.push_str(&source[cut..]);
        return Lexer::new(&blanked).tokenize();
    }
    Lexer::new(source).tokenize()
}

// ── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn shebang_line_is_not_program_text() {
        let (tokens, errors) = tokenize("#!/usr/bin/env -S tallow\nfn main() { print(1) }\n");
        assert!(errors.is_empty(), "unexpected errors: {errors:?}");
        assert!(tokens.iter().any(|t| matches!(t.kind, TokenKind::Fn)));
        // Spans stay aligned with the original text: the `fn` still starts on line 2.
        let fn_tok = tokens
            .iter()
            .find(|t| matches!(t.kind, TokenKind::Fn))
            .expect("fn token");
        assert_eq!(fn_tok.span.start, 25); // the shebang line is 25 bytes incl. newline
    }

    /// Helper: tokenize and assert zero errors, return token kinds.
    fn kinds(source: &str) -> Vec<TokenKind> {
        let (tokens, errors) = tokenize(source);
        assert!(errors.is_empty(), "unexpected errors: {errors:?}");
        tokens.into_iter().map(|t| t.kind).collect()
    }

    #[test]
    fn hello_nx() {
        let source = include_str!("../tests/fixtures/hello.tl");
        let (tokens, errors) = tokenize(source);
        assert!(errors.is_empty(), "lex errors: {errors:?}");

        let expected = vec![
            TokenKind::Fn,
            TokenKind::Ident("main".into()),
            TokenKind::LParen,
            TokenKind::RParen,
            TokenKind::LBrace,
            TokenKind::Ident("print".into()),
            TokenKind::LParen,
            TokenKind::StringLit("hello from tallow".into()),
            TokenKind::RParen,
            TokenKind::RBrace,
            TokenKind::Eof,
        ];

        let got: Vec<TokenKind> = tokens.iter().map(|t| t.kind.clone()).collect();
        assert_eq!(got, expected);
    }

    #[test]
    fn keywords() {
        let k = kinds("fn let var const struct enum impl match if else for while in return");
        assert_eq!(
            k,
            vec![
                TokenKind::Fn,
                TokenKind::Let,
                TokenKind::Var,
                TokenKind::Const,
                TokenKind::Struct,
                TokenKind::Enum,
                TokenKind::Impl,
                TokenKind::Match,
                TokenKind::If,
                TokenKind::Else,
                TokenKind::For,
                TokenKind::While,
                TokenKind::In,
                TokenKind::Return,
                TokenKind::Eof,
            ]
        );
    }

    #[test]
    fn operators() {
        let k = kinds("+ - * / % == != <= >= -> =>");
        assert_eq!(
            k,
            vec![
                TokenKind::Plus,
                TokenKind::Minus,
                TokenKind::Star,
                TokenKind::Slash,
                TokenKind::Percent,
                TokenKind::EqEq,
                TokenKind::BangEq,
                TokenKind::LtEq,
                TokenKind::GtEq,
                TokenKind::Arrow,
                TokenKind::FatArrow,
                TokenKind::Eof,
            ]
        );
    }

    #[test]
    fn number_literals() {
        let k = kinds("42 100_000 0xFF 0b1010 0o77 3.14");
        assert_eq!(
            k,
            vec![
                TokenKind::IntLit(42),
                TokenKind::IntLit(100_000),
                TokenKind::IntLit(0xFF),
                TokenKind::IntLit(0b1010),
                TokenKind::IntLit(0o77),
                TokenKind::FloatLit(3.14),
                TokenKind::Eof,
            ]
        );
    }

    #[test]
    fn string_escapes() {
        let k = kinds(r#""hello\nworld""#);
        assert_eq!(
            k,
            vec![
                TokenKind::StringLit("hello\nworld".into()),
                TokenKind::Eof,
            ]
        );
    }

    #[test]
    fn comments_stripped() {
        let k = kinds("fn // this is a comment\nmain");
        assert_eq!(
            k,
            vec![TokenKind::Fn, TokenKind::Ident("main".into()), TokenKind::Eof]
        );
    }

    #[test]
    fn block_comments() {
        let k = kinds("fn /* block */ main");
        assert_eq!(
            k,
            vec![TokenKind::Fn, TokenKind::Ident("main".into()), TokenKind::Eof]
        );
    }

    #[test]
    fn nested_block_comments() {
        let k = kinds("fn /* outer /* inner */ still comment */ main");
        assert_eq!(
            k,
            vec![TokenKind::Fn, TokenKind::Ident("main".into()), TokenKind::Eof]
        );
    }

    #[test]
    fn annotation_tokens() {
        let k = kinds("@legal ( )");
        assert_eq!(
            k,
            vec![
                TokenKind::At,
                TokenKind::Ident("legal".into()),
                TokenKind::LParen,
                TokenKind::RParen,
                TokenKind::Eof,
            ]
        );
    }

    #[test]
    fn privacy_keywords() {
        let k = kinds("private secret");
        assert_eq!(
            k,
            vec![TokenKind::Private, TokenKind::Secret, TokenKind::Eof]
        );
    }

    #[test]
    fn dot_vs_dotdot() {
        let k = kinds("a.b 0..10");
        assert_eq!(
            k,
            vec![
                TokenKind::Ident("a".into()),
                TokenKind::Dot,
                TokenKind::Ident("b".into()),
                TokenKind::IntLit(0),
                TokenKind::DotDot,
                TokenKind::IntLit(10),
                TokenKind::Eof,
            ]
        );
    }

    #[test]
    fn span_positions() {
        let source = "fn main";
        let (tokens, _) = tokenize(source);
        // "fn" is at 0..2
        assert_eq!(tokens[0].span, Span::new(0, 2));
        assert_eq!(tokens[0].span.text(source), "fn");
        // "main" is at 3..7
        assert_eq!(tokens[1].span, Span::new(3, 7));
        assert_eq!(tokens[1].span.text(source), "main");
    }

    #[test]
    fn unterminated_string_reports_error() {
        let (_, errors) = tokenize("\"oops");
        assert_eq!(errors.len(), 1);
        assert!(errors[0].to_string().contains("unterminated"));
    }

    #[test]
    fn unexpected_char_reports_error() {
        let (_, errors) = tokenize("$");
        assert_eq!(errors.len(), 1);
        assert!(errors[0].to_string().contains("unexpected character"));
    }

    #[test]
    fn string_interpolation_simple() {
        let k = kinds(r#""hello {name}""#);
        assert_eq!(
            k,
            vec![
                TokenKind::StringStart("hello ".into()),
                TokenKind::Ident("name".into()),
                TokenKind::StringEnd(String::new()),
                TokenKind::Eof,
            ]
        );
    }

    #[test]
    fn string_interpolation_multiple() {
        let k = kinds(r#""a {x} b {y} c""#);
        assert_eq!(
            k,
            vec![
                TokenKind::StringStart("a ".into()),
                TokenKind::Ident("x".into()),
                TokenKind::StringMid(" b ".into()),
                TokenKind::Ident("y".into()),
                TokenKind::StringEnd(" c".into()),
                TokenKind::Eof,
            ]
        );
    }

    #[test]
    fn string_interpolation_expr() {
        let k = kinds(r#""count: {items.len()}""#);
        assert_eq!(
            k,
            vec![
                TokenKind::StringStart("count: ".into()),
                TokenKind::Ident("items".into()),
                TokenKind::Dot,
                TokenKind::Ident("len".into()),
                TokenKind::LParen,
                TokenKind::RParen,
                TokenKind::StringEnd(String::new()),
                TokenKind::Eof,
            ]
        );
    }

    #[test]
    fn string_no_interpolation() {
        // Plain string without { should still be StringLit
        let k = kinds(r#""hello world""#);
        assert_eq!(
            k,
            vec![TokenKind::StringLit("hello world".into()), TokenKind::Eof]
        );
    }

    #[test]
    fn string_escaped_brace() {
        // \{ should produce a literal { not interpolation
        let k = kinds(r#""hello \{name\}""#);
        assert_eq!(
            k,
            vec![
                TokenKind::StringLit("hello {name}".into()),
                TokenKind::Eof,
            ]
        );
    }

    #[test]
    fn compound_assignment_tokens() {
        let k = kinds("x += 1 -= 2 *= 3 /= 4 %= 5");
        assert!(k.contains(&TokenKind::PlusEq));
        assert!(k.contains(&TokenKind::MinusEq));
        assert!(k.contains(&TokenKind::StarEq));
        assert!(k.contains(&TokenKind::SlashEq));
        assert!(k.contains(&TokenKind::PercentEq));
    }

    // ── Extended Lexer Tests ────────────────────────────────────────────

    #[test]
    fn hex_literal() {
        let k = kinds("0xFF");
        assert_eq!(k, vec![TokenKind::IntLit(255), TokenKind::Eof]);
    }

    #[test]
    fn binary_literal() {
        let k = kinds("0b1010");
        assert_eq!(k, vec![TokenKind::IntLit(10), TokenKind::Eof]);
    }

    #[test]
    fn octal_literal() {
        let k = kinds("0o77");
        assert_eq!(k, vec![TokenKind::IntLit(63), TokenKind::Eof]);
    }

    #[test]
    fn underscore_in_number() {
        let k = kinds("1_000_000");
        assert_eq!(k, vec![TokenKind::IntLit(1_000_000), TokenKind::Eof]);
    }

    #[test]
    fn float_scientific_notation() {
        let k = kinds("1.5e10");
        assert_eq!(k, vec![TokenKind::FloatLit(1.5e10), TokenKind::Eof]);
    }

    #[test]
    fn float_scientific_with_sign() {
        let k = kinds("3.0e-2");
        assert_eq!(k, vec![TokenKind::FloatLit(3.0e-2), TokenKind::Eof]);
    }

    #[test]
    fn arrow_and_fat_arrow() {
        let k = kinds("-> =>");
        assert_eq!(k, vec![TokenKind::Arrow, TokenKind::FatArrow, TokenKind::Eof]);
    }

    #[test]
    fn question_mark_token() {
        let k = kinds("x?");
        assert!(k.contains(&TokenKind::Question));
    }

    #[test]
    fn at_symbol_token() {
        let k = kinds("@legal");
        assert!(k.contains(&TokenKind::At));
    }

    #[test]
    fn colon_colon_token() {
        let k = kinds("Foo::bar");
        assert!(k.contains(&TokenKind::ColonColon));
    }

    #[test]
    fn bitwise_operators() {
        let k = kinds("a & b | c ^ d ~ e");
        assert!(k.contains(&TokenKind::Amp));
        assert!(k.contains(&TokenKind::Pipe));
        assert!(k.contains(&TokenKind::Caret));
        assert!(k.contains(&TokenKind::Tilde));
    }

    #[test]
    fn shift_operators() {
        let k = kinds("a << 2 >> 3");
        assert!(k.contains(&TokenKind::Shl));
        assert!(k.contains(&TokenKind::Shr));
    }

    #[test]
    fn power_operator() {
        let k = kinds("2 ** 3");
        assert!(k.contains(&TokenKind::StarStar));
    }

    #[test]
    fn power_assign_operator() {
        let k = kinds("x **= 2");
        assert!(k.contains(&TokenKind::StarStarEq));
    }

    #[test]
    fn shift_assign_operators() {
        let k = kinds("x <<= 1 y >>= 2");
        assert!(k.contains(&TokenKind::ShlEq));
        assert!(k.contains(&TokenKind::ShrEq));
    }

    #[test]
    fn bitwise_assign_operators() {
        let k = kinds("x &= 1 y |= 2 z ^= 3");
        assert!(k.contains(&TokenKind::AmpEq));
        assert!(k.contains(&TokenKind::PipeEq));
        assert!(k.contains(&TokenKind::CaretEq));
    }

    #[test]
    fn logical_operators() {
        let k = kinds("a && b || c");
        assert!(k.contains(&TokenKind::AmpAmp));
        assert!(k.contains(&TokenKind::PipePipe));
    }

    #[test]
    fn all_bracket_types() {
        let k = kinds("()[]{}");
        assert_eq!(k, vec![
            TokenKind::LParen, TokenKind::RParen,
            TokenKind::LBracket, TokenKind::RBracket,
            TokenKind::LBrace, TokenKind::RBrace,
            TokenKind::Eof,
        ]);
    }

    #[test]
    fn keywords_control_flow() {
        let k = kinds("if else for while match return break continue loop");
        assert!(k.contains(&TokenKind::If));
        assert!(k.contains(&TokenKind::Else));
        assert!(k.contains(&TokenKind::For));
        assert!(k.contains(&TokenKind::While));
        assert!(k.contains(&TokenKind::Match));
        assert!(k.contains(&TokenKind::Return));
        assert!(k.contains(&TokenKind::Break));
        assert!(k.contains(&TokenKind::Continue));
        assert!(k.contains(&TokenKind::Loop));
    }

    #[test]
    fn keywords_declarations() {
        let k = kinds("fn let var const struct enum impl type import");
        assert!(k.contains(&TokenKind::Fn));
        assert!(k.contains(&TokenKind::Let));
        assert!(k.contains(&TokenKind::Var));
        assert!(k.contains(&TokenKind::Const));
        assert!(k.contains(&TokenKind::Struct));
        assert!(k.contains(&TokenKind::Enum));
        assert!(k.contains(&TokenKind::Impl));
        assert!(k.contains(&TokenKind::Type));
        assert!(k.contains(&TokenKind::Import));
    }

    #[test]
    fn keywords_async_await() {
        let k = kinds("async await");
        assert_eq!(k, vec![TokenKind::Async, TokenKind::Await, TokenKind::Eof]);
    }

    #[test]
    fn keywords_bail_bail_if_catch() {
        let k = kinds("bail bail_if catch");
        assert!(k.contains(&TokenKind::Bail));
        assert!(k.contains(&TokenKind::BailIf));
        assert!(k.contains(&TokenKind::Catch));
    }

    #[test]
    fn keywords_self_mut_as_in() {
        let k = kinds("self mut as in");
        assert!(k.contains(&TokenKind::SelfValue));
        assert!(k.contains(&TokenKind::Mut));
        assert!(k.contains(&TokenKind::As));
        assert!(k.contains(&TokenKind::In));
    }

    #[test]
    fn literals_true_false_nil() {
        let k = kinds("true false nil");
        assert_eq!(k, vec![TokenKind::True, TokenKind::False, TokenKind::Nil, TokenKind::Eof]);
    }

    #[test]
    fn underscore_as_pattern() {
        let k = kinds("_");
        assert_eq!(k, vec![TokenKind::Underscore, TokenKind::Eof]);
    }

    #[test]
    fn hash_token() {
        let k = kinds("#");
        assert!(k.contains(&TokenKind::Hash));
    }

    #[test]
    fn semicolon_token() {
        let k = kinds(";");
        assert_eq!(k, vec![TokenKind::Semi, TokenKind::Eof]);
    }

    #[test]
    fn string_with_newline_escape() {
        let k = kinds(r#""hello\nworld""#);
        assert_eq!(k, vec![TokenKind::StringLit("hello\nworld".into()), TokenKind::Eof]);
    }

    #[test]
    fn string_with_tab_escape() {
        let k = kinds(r#""hello\tworld""#);
        assert_eq!(k, vec![TokenKind::StringLit("hello\tworld".into()), TokenKind::Eof]);
    }

    #[test]
    fn string_with_backslash_escape() {
        let k = kinds(r#""path\\to""#);
        assert_eq!(k, vec![TokenKind::StringLit("path\\to".into()), TokenKind::Eof]);
    }

    #[test]
    fn string_with_quote_escape() {
        let k = kinds(r#""say \"hello\"""#);
        assert_eq!(k, vec![TokenKind::StringLit("say \"hello\"".into()), TokenKind::Eof]);
    }

    #[test]
    fn empty_string() {
        let k = kinds(r#""""#);
        assert_eq!(k, vec![TokenKind::StringLit("".into()), TokenKind::Eof]);
    }

    #[test]
    fn line_comment_at_end_of_line() {
        let k = kinds("let x = 5 // this is x\nlet y = 10");
        assert!(k.contains(&TokenKind::Let));
        assert!(k.contains(&TokenKind::IntLit(5)));
        assert!(k.contains(&TokenKind::IntLit(10)));
        // Comment text should not appear as token
        assert!(!k.iter().any(|t| matches!(t, TokenKind::Ident(s) if s == "this")));
    }

    #[test]
    fn identifier_with_underscores() {
        let k = kinds("my_variable _private __dunder");
        assert_eq!(k, vec![
            TokenKind::Ident("my_variable".into()),
            TokenKind::Ident("_private".into()),
            TokenKind::Ident("__dunder".into()),
            TokenKind::Eof,
        ]);
    }

    #[test]
    fn identifier_with_digits() {
        let k = kinds("var1 x2y z3");
        assert_eq!(k, vec![
            TokenKind::Ident("var1".into()),
            TokenKind::Ident("x2y".into()),
            TokenKind::Ident("z3".into()),
            TokenKind::Eof,
        ]);
    }

    #[test]
    fn multiple_dots_and_ranges() {
        let k = kinds("a.b 0..10");
        assert!(k.contains(&TokenKind::Dot));
        assert!(k.contains(&TokenKind::DotDot));
    }

    #[test]
    fn comma_separated_values() {
        let k = kinds("1, 2, 3");
        assert_eq!(k, vec![
            TokenKind::IntLit(1), TokenKind::Comma,
            TokenKind::IntLit(2), TokenKind::Comma,
            TokenKind::IntLit(3), TokenKind::Eof,
        ]);
    }

    #[test]
    fn colon_for_type_annotation() {
        let k = kinds("x: i64");
        assert!(k.contains(&TokenKind::Colon));
    }

    #[test]
    fn bang_and_bang_eq() {
        let k = kinds("!a != b");
        assert!(k.contains(&TokenKind::Bang));
        assert!(k.contains(&TokenKind::BangEq));
    }

    #[test]
    fn comparison_operators_complete() {
        let k = kinds("== != < > <= >=");
        assert_eq!(k, vec![
            TokenKind::EqEq, TokenKind::BangEq,
            TokenKind::Lt, TokenKind::Gt,
            TokenKind::LtEq, TokenKind::GtEq,
            TokenKind::Eof,
        ]);
    }

    #[test]
    fn zero_literal() {
        let k = kinds("0");
        assert_eq!(k, vec![TokenKind::IntLit(0), TokenKind::Eof]);
    }

    #[test]
    fn negative_float_literal() {
        // Lexer produces separate minus and float
        let k = kinds("-3.14");
        assert!(k.contains(&TokenKind::Minus));
        assert!(k.contains(&TokenKind::FloatLit(3.14)));
    }

    #[test]
    fn large_integer() {
        let k = kinds("99999999999999999999");
        assert_eq!(k, vec![TokenKind::IntLit(99999999999999999999), TokenKind::Eof]);
    }

    // ── New lexer coverage tests ──────────────────────────────────────────────

    // Each keyword produced individually so a typo in one cannot hide in a bulk check.

    #[test]
    fn keyword_fn_alone() {
        let k = kinds("fn");
        assert_eq!(k, vec![TokenKind::Fn, TokenKind::Eof]);
    }

    #[test]
    fn keyword_let_alone() {
        let k = kinds("let");
        assert_eq!(k, vec![TokenKind::Let, TokenKind::Eof]);
    }

    #[test]
    fn keyword_var_alone() {
        let k = kinds("var");
        assert_eq!(k, vec![TokenKind::Var, TokenKind::Eof]);
    }

    #[test]
    fn keyword_const_alone() {
        let k = kinds("const");
        assert_eq!(k, vec![TokenKind::Const, TokenKind::Eof]);
    }

    #[test]
    fn keyword_return_alone() {
        let k = kinds("return");
        assert_eq!(k, vec![TokenKind::Return, TokenKind::Eof]);
    }

    #[test]
    fn keyword_import_alone() {
        let k = kinds("import");
        assert_eq!(k, vec![TokenKind::Import, TokenKind::Eof]);
    }

    #[test]
    fn keyword_type_alone() {
        let k = kinds("type");
        assert_eq!(k, vec![TokenKind::Type, TokenKind::Eof]);
    }

    #[test]
    fn pub_is_plain_identifier() {
        // `pub` is not a Tallow keyword (no visibility modifiers in the
        // language). It lexes as an ordinary identifier; the parser emits a
        // friendly migration hint when it appears at item position.
        let k = kinds("pub");
        assert_eq!(k, vec![TokenKind::Ident("pub".to_string()), TokenKind::Eof]);
    }

    #[test]
    fn keyword_mut_alone() {
        let k = kinds("mut");
        assert_eq!(k, vec![TokenKind::Mut, TokenKind::Eof]);
    }

    // Operators produced one at a time to confirm no two-char lookahead mifire.

    #[test]
    fn operator_plus_alone() {
        let k = kinds("+");
        assert_eq!(k, vec![TokenKind::Plus, TokenKind::Eof]);
    }

    #[test]
    fn operator_minus_alone() {
        let k = kinds("-");
        assert_eq!(k, vec![TokenKind::Minus, TokenKind::Eof]);
    }

    #[test]
    fn operator_star_alone() {
        let k = kinds("*");
        assert_eq!(k, vec![TokenKind::Star, TokenKind::Eof]);
    }

    #[test]
    fn operator_slash_alone() {
        let k = kinds("/");
        assert_eq!(k, vec![TokenKind::Slash, TokenKind::Eof]);
    }

    #[test]
    fn operator_percent_alone() {
        let k = kinds("%");
        assert_eq!(k, vec![TokenKind::Percent, TokenKind::Eof]);
    }

    #[test]
    fn operator_eq_alone() {
        // bare `=` must not be consumed as `==`
        let k = kinds("=");
        assert_eq!(k, vec![TokenKind::Eq, TokenKind::Eof]);
    }

    #[test]
    fn operator_lt_alone() {
        let k = kinds("<");
        assert_eq!(k, vec![TokenKind::Lt, TokenKind::Eof]);
    }

    #[test]
    fn operator_gt_alone() {
        let k = kinds(">");
        assert_eq!(k, vec![TokenKind::Gt, TokenKind::Eof]);
    }

    // Compound assignment operators produced individually.

    #[test]
    fn compound_assign_plus_eq_alone() {
        let k = kinds("+=");
        assert_eq!(k, vec![TokenKind::PlusEq, TokenKind::Eof]);
    }

    #[test]
    fn compound_assign_minus_eq_alone() {
        let k = kinds("-=");
        assert_eq!(k, vec![TokenKind::MinusEq, TokenKind::Eof]);
    }

    #[test]
    fn compound_assign_star_eq_alone() {
        let k = kinds("*=");
        assert_eq!(k, vec![TokenKind::StarEq, TokenKind::Eof]);
    }

    #[test]
    fn compound_assign_slash_eq_alone() {
        let k = kinds("/=");
        assert_eq!(k, vec![TokenKind::SlashEq, TokenKind::Eof]);
    }

    #[test]
    fn compound_assign_percent_eq_alone() {
        let k = kinds("%=");
        assert_eq!(k, vec![TokenKind::PercentEq, TokenKind::Eof]);
    }

    // String interpolation — mid-segment is only produced when there is more than
    // one interpolation hole.  Verify the full token sequence for three holes.

    #[test]
    fn string_interpolation_three_holes() {
        // "a {x} b {y} c {z} d"
        let k = kinds(r#""a {x} b {y} c {z} d""#);
        assert_eq!(
            k,
            vec![
                TokenKind::StringStart("a ".into()),
                TokenKind::Ident("x".into()),
                TokenKind::StringMid(" b ".into()),
                TokenKind::Ident("y".into()),
                TokenKind::StringMid(" c ".into()),
                TokenKind::Ident("z".into()),
                TokenKind::StringEnd(" d".into()),
                TokenKind::Eof,
            ]
        );
    }

    // Interpolation at the very start of the string — empty StringStart prefix.

    #[test]
    fn string_interpolation_leading_hole() {
        // "{name} says hi"
        let k = kinds(r#""{name} says hi""#);
        assert_eq!(
            k,
            vec![
                TokenKind::StringStart("".into()),
                TokenKind::Ident("name".into()),
                TokenKind::StringEnd(" says hi".into()),
                TokenKind::Eof,
            ]
        );
    }

    // Interpolation at the very end — empty StringEnd suffix.

    #[test]
    fn string_interpolation_trailing_hole() {
        // "value: {n}"
        let k = kinds(r#""value: {n}""#);
        assert_eq!(
            k,
            vec![
                TokenKind::StringStart("value: ".into()),
                TokenKind::Ident("n".into()),
                TokenKind::StringEnd("".into()),
                TokenKind::Eof,
            ]
        );
    }

    // Underscore separators in number literals of various sizes.

    #[test]
    fn underscore_in_large_decimal() {
        let k = kinds("100_000_000");
        assert_eq!(k, vec![TokenKind::IntLit(100_000_000), TokenKind::Eof]);
    }

    #[test]
    fn underscore_in_hex_literal() {
        // 0xFF_FF should parse as 65535
        let k = kinds("0xFF_FF");
        assert_eq!(k, vec![TokenKind::IntLit(0xFFFF), TokenKind::Eof]);
    }

    // Zero in each supported base.

    #[test]
    fn zero_hex() {
        let k = kinds("0x0");
        assert_eq!(k, vec![TokenKind::IntLit(0), TokenKind::Eof]);
    }

    #[test]
    fn zero_binary() {
        let k = kinds("0b0");
        assert_eq!(k, vec![TokenKind::IntLit(0), TokenKind::Eof]);
    }

    #[test]
    fn zero_octal() {
        let k = kinds("0o0");
        assert_eq!(k, vec![TokenKind::IntLit(0), TokenKind::Eof]);
    }

    // Float with no fractional digits after the dot.

    #[test]
    fn float_with_trailing_dot() {
        // "1." is tokenized as IntLit(1) + Dot (not a float) — correct behavior
        // because trailing dot could be method call like `1.to_string()`
        let k = kinds("1.");
        assert_eq!(k, vec![TokenKind::IntLit(1), TokenKind::Dot, TokenKind::Eof]);
    }

    // Multi-line source: tokens on different lines are all collected.

    #[test]
    fn multiline_token_stream() {
        let src = "let a = 1\nlet b = 2\nlet c = 3";
        let k = kinds(src);
        // Three Let tokens, three Eq tokens, three int literals.
        assert_eq!(k.iter().filter(|t| **t == TokenKind::Let).count(), 3);
        assert_eq!(k.iter().filter(|t| **t == TokenKind::Eq).count(), 3);
        assert_eq!(k.iter().filter(|t| **t == TokenKind::IntLit(1)).count(), 1);
        assert_eq!(k.iter().filter(|t| **t == TokenKind::IntLit(2)).count(), 1);
        assert_eq!(k.iter().filter(|t| **t == TokenKind::IntLit(3)).count(), 1);
    }

    // Comment at very start of file — nothing before it, no tokens expected except Eof.

    #[test]
    fn comment_only_file() {
        let k = kinds("// entire file is a comment");
        assert_eq!(k, vec![TokenKind::Eof]);
    }

    // Multiple back-to-back line comments.

    #[test]
    fn multiple_line_comments() {
        let src = "// first\n// second\nlet x = 42";
        let k = kinds(src);
        assert!(k.contains(&TokenKind::Let));
        assert!(k.contains(&TokenKind::IntLit(42)));
        // Neither comment word should become an identifier.
        assert!(!k.iter().any(|t| matches!(t, TokenKind::Ident(s) if s == "first")));
        assert!(!k.iter().any(|t| matches!(t, TokenKind::Ident(s) if s == "second")));
    }

    // Ambiguous operator sequences: `>>=` must not be lexed as `>>` + `=`.

    #[test]
    fn shr_eq_not_split() {
        let k = kinds(">>=");
        assert_eq!(k, vec![TokenKind::ShrEq, TokenKind::Eof]);
    }

    #[test]
    fn shl_eq_not_split() {
        let k = kinds("<<=");
        assert_eq!(k, vec![TokenKind::ShlEq, TokenKind::Eof]);
    }

    // `**=` must not be `*` + `*=` or `**` + `=`.

    #[test]
    fn star_star_eq_not_split() {
        let k = kinds("**=");
        assert_eq!(k, vec![TokenKind::StarStarEq, TokenKind::Eof]);
    }

    // `->` must not be `-` + `>`.

    #[test]
    fn arrow_not_split() {
        let k = kinds("->");
        assert_eq!(k, vec![TokenKind::Arrow, TokenKind::Eof]);
    }

    // `=>` must not be `=` + `>`.

    #[test]
    fn fat_arrow_not_split() {
        let k = kinds("=>");
        assert_eq!(k, vec![TokenKind::FatArrow, TokenKind::Eof]);
    }

    // `..` must not be two `.` tokens, and `.` alone must not become `..`.

    #[test]
    fn dotdot_alone() {
        let k = kinds("..");
        assert_eq!(k, vec![TokenKind::DotDot, TokenKind::Eof]);
    }

    #[test]
    fn dot_alone() {
        let k = kinds(".");
        assert_eq!(k, vec![TokenKind::Dot, TokenKind::Eof]);
    }

    // `::` must not be two `:` tokens.

    #[test]
    fn colon_colon_alone() {
        let k = kinds("::");
        assert_eq!(k, vec![TokenKind::ColonColon, TokenKind::Eof]);
    }

    // Colon alone must not be consumed as `::`.

    #[test]
    fn colon_alone() {
        let k = kinds(":");
        assert_eq!(k, vec![TokenKind::Colon, TokenKind::Eof]);
    }

    // `&&` and `||` must not be produced as two `&` / `|` tokens.

    #[test]
    fn amp_amp_alone() {
        let k = kinds("&&");
        assert_eq!(k, vec![TokenKind::AmpAmp, TokenKind::Eof]);
    }

    #[test]
    fn pipe_pipe_alone() {
        let k = kinds("||");
        assert_eq!(k, vec![TokenKind::PipePipe, TokenKind::Eof]);
    }

    // Single `&` and `|` must not be consumed as `&&` / `||`.

    #[test]
    fn amp_alone() {
        let k = kinds("&");
        assert_eq!(k, vec![TokenKind::Amp, TokenKind::Eof]);
    }

    #[test]
    fn pipe_alone() {
        let k = kinds("|");
        assert_eq!(k, vec![TokenKind::Pipe, TokenKind::Eof]);
    }

    #[test]
    fn caret_alone() {
        let k = kinds("^");
        assert_eq!(k, vec![TokenKind::Caret, TokenKind::Eof]);
    }

    #[test]
    fn tilde_alone() {
        let k = kinds("~");
        assert_eq!(k, vec![TokenKind::Tilde, TokenKind::Eof]);
    }

    #[test]
    fn shl_alone() {
        let k = kinds("<<");
        assert_eq!(k, vec![TokenKind::Shl, TokenKind::Eof]);
    }

    #[test]
    fn shr_alone() {
        let k = kinds(">>");
        assert_eq!(k, vec![TokenKind::Shr, TokenKind::Eof]);
    }

    // `**` alone must not become `*` + `*`.

    #[test]
    fn star_star_alone() {
        let k = kinds("**");
        assert_eq!(k, vec![TokenKind::StarStar, TokenKind::Eof]);
    }

    // `?` isolated.

    #[test]
    fn question_alone() {
        let k = kinds("?");
        assert_eq!(k, vec![TokenKind::Question, TokenKind::Eof]);
    }

    // `@` isolated.

    #[test]
    fn at_alone() {
        let k = kinds("@");
        assert_eq!(k, vec![TokenKind::At, TokenKind::Eof]);
    }

    // `#` isolated (already has a test for the token name, this confirms exact sequence).

    #[test]
    fn hash_alone_exact() {
        let k = kinds("#");
        assert_eq!(k, vec![TokenKind::Hash, TokenKind::Eof]);
    }

    // Delimiter pairs verified as a precise sequence.

    #[test]
    fn paren_pair() {
        let k = kinds("()");
        assert_eq!(k, vec![TokenKind::LParen, TokenKind::RParen, TokenKind::Eof]);
    }

    #[test]
    fn bracket_pair() {
        let k = kinds("[]");
        assert_eq!(k, vec![TokenKind::LBracket, TokenKind::RBracket, TokenKind::Eof]);
    }

    #[test]
    fn brace_pair() {
        let k = kinds("{}");
        assert_eq!(k, vec![TokenKind::LBrace, TokenKind::RBrace, TokenKind::Eof]);
    }

    // `private` and `secret` are distinct keywords, not generic identifiers.

    #[test]
    fn private_keyword_alone() {
        let k = kinds("private");
        assert_eq!(k, vec![TokenKind::Private, TokenKind::Eof]);
    }

    #[test]
    fn secret_keyword_alone() {
        let k = kinds("secret");
        assert_eq!(k, vec![TokenKind::Secret, TokenKind::Eof]);
    }

    // Keywords that are prefixes of identifiers must NOT steal the ident.
    // e.g. "letter" starts with "let" but must be an Ident.

    #[test]
    fn keyword_prefix_is_ident() {
        let k = kinds("letter");
        assert_eq!(k, vec![TokenKind::Ident("letter".into()), TokenKind::Eof]);
    }

    #[test]
    fn keyword_fn_prefix_ident() {
        // "fnx" should be Ident, not Fn + Ident("x")
        let k = kinds("fnx");
        assert_eq!(k, vec![TokenKind::Ident("fnx".into()), TokenKind::Eof]);
    }

    // Whitespace-only source produces just Eof.

    #[test]
    fn whitespace_only_produces_eof() {
        let k = kinds("   \t  \n  ");
        assert_eq!(k, vec![TokenKind::Eof]);
    }

    // Empty source produces just Eof.

    #[test]
    fn empty_source_produces_eof() {
        let k = kinds("");
        assert_eq!(k, vec![TokenKind::Eof]);
    }

    // Semicolon in a statement context produces exactly Semi.

    #[test]
    fn semicolon_between_stmts() {
        let k = kinds("a; b");
        assert_eq!(
            k,
            vec![
                TokenKind::Ident("a".into()),
                TokenKind::Semi,
                TokenKind::Ident("b".into()),
                TokenKind::Eof,
            ]
        );
    }

    // Comma produces exactly Comma.

    #[test]
    fn comma_alone() {
        let k = kinds(",");
        assert_eq!(k, vec![TokenKind::Comma, TokenKind::Eof]);
    }

    // Float literal with no leading digit before the dot is NOT a valid Tallow float;
    // verify that `.5` is tokenised as Dot + IntLit(5) (or as the lexer actually handles
    // it) rather than silently producing a wrong FloatLit.

    #[test]
    fn dot_then_int_is_not_float() {
        let k = kinds(".5");
        // The lexer must not produce FloatLit(0.5) here — it must be Dot + IntLit(5).
        assert!(!k.contains(&TokenKind::FloatLit(0.5)),
            "bare `.5` should not lex as FloatLit(0.5); got {k:?}");
        assert!(k.contains(&TokenKind::Dot));
        assert!(k.contains(&TokenKind::IntLit(5)));
    }

    // `_` alone is the wildcard/underscore pattern token, not an identifier.

    #[test]
    fn underscore_alone_is_underscore_token() {
        let k = kinds("_");
        assert_eq!(k, vec![TokenKind::Underscore, TokenKind::Eof]);
    }

    // `_foo` is an identifier that starts with underscore (already covered by
    // identifier_with_underscores, but here we verify the *exact* single token).

    #[test]
    fn leading_underscore_ident() {
        let k = kinds("_foo");
        assert_eq!(k, vec![TokenKind::Ident("_foo".into()), TokenKind::Eof]);
    }

    // `self` is a keyword (SelfValue), not an Ident.

    #[test]
    fn self_keyword_alone() {
        let k = kinds("self");
        assert_eq!(k, vec![TokenKind::SelfValue, TokenKind::Eof]);
    }

    // `as` keyword alone.

    #[test]
    fn as_keyword_alone() {
        let k = kinds("as");
        assert_eq!(k, vec![TokenKind::As, TokenKind::Eof]);
    }

    // `in` keyword alone.

    #[test]
    fn in_keyword_alone() {
        let k = kinds("in");
        assert_eq!(k, vec![TokenKind::In, TokenKind::Eof]);
    }

    // `catch` keyword alone.

    #[test]
    fn catch_keyword_alone() {
        let k = kinds("catch");
        assert_eq!(k, vec![TokenKind::Catch, TokenKind::Eof]);
    }

    // `bail` and `bail_if` share a prefix — confirm they are distinct.

    #[test]
    fn bail_keyword_alone() {
        let k = kinds("bail");
        assert_eq!(k, vec![TokenKind::Bail, TokenKind::Eof]);
    }

    #[test]
    fn bail_if_keyword_alone() {
        let k = kinds("bail_if");
        assert_eq!(k, vec![TokenKind::BailIf, TokenKind::Eof]);
    }

    // Full `@agent_task` annotation prefix produces At + Ident.

    #[test]
    fn at_agent_task_annotation() {
        let k = kinds("@agent_task");
        assert_eq!(
            k,
            vec![
                TokenKind::At,
                TokenKind::Ident("agent_task".into()),
                TokenKind::Eof,
            ]
        );
    }

    // `async fn` together.

    #[test]
    fn async_fn_sequence() {
        let k = kinds("async fn");
        assert_eq!(k, vec![TokenKind::Async, TokenKind::Fn, TokenKind::Eof]);
    }

    // `await` alone.

    #[test]
    fn await_keyword_alone() {
        let k = kinds("await");
        assert_eq!(k, vec![TokenKind::Await, TokenKind::Eof]);
    }

    // `loop` alone.

    #[test]
    fn loop_keyword_alone() {
        let k = kinds("loop");
        assert_eq!(k, vec![TokenKind::Loop, TokenKind::Eof]);
    }

    // `break` alone.

    #[test]
    fn break_keyword_alone() {
        let k = kinds("break");
        assert_eq!(k, vec![TokenKind::Break, TokenKind::Eof]);
    }

    // `continue` alone.

    #[test]
    fn continue_keyword_alone() {
        let k = kinds("continue");
        assert_eq!(k, vec![TokenKind::Continue, TokenKind::Eof]);
    }

    // Very large float to exercise f64 precision boundary.

    #[test]
    fn very_large_float() {
        let k = kinds("1.7976931348623157e308");
        assert!(
            k.contains(&TokenKind::FloatLit(f64::MAX)),
            "expected FloatLit(f64::MAX); got {k:?}"
        );
    }

    // Integer literal `1` (the smallest non-zero value).

    #[test]
    fn one_integer() {
        let k = kinds("1");
        assert_eq!(k, vec![TokenKind::IntLit(1), TokenKind::Eof]);
    }

    // Empty string already tested; verify StringLit content is truly empty.

    #[test]
    fn empty_string_content() {
        let k = kinds(r#""""#);
        assert_eq!(
            k,
            vec![TokenKind::StringLit(String::new()), TokenKind::Eof]
        );
    }

    // `true` / `false` / `nil` are keywords, not identifiers.

    #[test]
    fn true_is_not_ident() {
        let k = kinds("true");
        assert_eq!(k, vec![TokenKind::True, TokenKind::Eof]);
        assert!(!k.iter().any(|t| matches!(t, TokenKind::Ident(s) if s == "true")));
    }

    #[test]
    fn false_is_not_ident() {
        let k = kinds("false");
        assert_eq!(k, vec![TokenKind::False, TokenKind::Eof]);
    }

    #[test]
    fn nil_is_not_ident() {
        let k = kinds("nil");
        assert_eq!(k, vec![TokenKind::Nil, TokenKind::Eof]);
    }

    // Operators that differ only by one character: ensure `!` and `!=` are distinct.

    #[test]
    fn bang_alone_is_bang_not_bang_eq() {
        let k = kinds("!");
        assert_eq!(k, vec![TokenKind::Bang, TokenKind::Eof]);
    }

    #[test]
    fn bang_eq_alone() {
        let k = kinds("!=");
        assert_eq!(k, vec![TokenKind::BangEq, TokenKind::Eof]);
    }

    // `==` alone.

    #[test]
    fn eq_eq_alone() {
        let k = kinds("==");
        assert_eq!(k, vec![TokenKind::EqEq, TokenKind::Eof]);
    }

    // `<=` alone.

    #[test]
    fn lt_eq_alone() {
        let k = kinds("<=");
        assert_eq!(k, vec![TokenKind::LtEq, TokenKind::Eof]);
    }

    // `>=` alone.

    #[test]
    fn gt_eq_alone() {
        let k = kinds(">=");
        assert_eq!(k, vec![TokenKind::GtEq, TokenKind::Eof]);
    }

    // Span test: verify the span of a float literal.

    #[test]
    fn span_of_float_literal() {
        let source = "3.14";
        let (tokens, _) = tokenize(source);
        assert_eq!(tokens[0].span, Span::new(0, 4));
        assert_eq!(tokens[0].span.text(source), "3.14");
    }

    // Span test: operator at an offset.

    #[test]
    fn span_of_operator_at_offset() {
        let source = "a + b";
        let (tokens, _) = tokenize(source);
        // tokens: Ident("a"), Plus, Ident("b"), Eof
        assert_eq!(tokens[1].kind, TokenKind::Plus);
        assert_eq!(tokens[1].span, Span::new(2, 3));
    }

    // Span test: string literal span includes surrounding quotes.

    #[test]
    fn span_of_string_literal() {
        let source = r#""hi""#;
        let (tokens, _) = tokenize(source);
        assert_eq!(tokens[0].kind, TokenKind::StringLit("hi".into()));
        assert_eq!(tokens[0].span, Span::new(0, 4));
    }

    // line_col helper: second line, first column.

    #[test]
    fn span_line_col_second_line() {
        let source = "fn\nmain";
        let (tokens, _) = tokenize(source);
        // "main" begins at byte 3
        let (line, col) = tokens[1].span.line_col(source);
        assert_eq!(line, 2);
        assert_eq!(col, 1);
    }

    // ── Additional coverage tests ───────────────────────────────────

    #[test]
    fn lex_underscore_in_number_literal() {
        let (tokens, errors) = tokenize("100_000");
        assert!(errors.is_empty());
        assert_eq!(tokens[0].kind, TokenKind::IntLit(100_000));
    }

    #[test]
    fn lex_hex_literal() {
        let (tokens, errors) = tokenize("0xFF");
        assert!(errors.is_empty());
        assert_eq!(tokens[0].kind, TokenKind::IntLit(255));
    }

    #[test]
    fn lex_empty_string() {
        let (tokens, errors) = tokenize(r#""""#);
        assert!(errors.is_empty());
        assert_eq!(tokens[0].kind, TokenKind::StringLit("".into()));
    }

    #[test]
    fn lex_multiline_comment() {
        let (tokens, errors) = tokenize("/* comment */ 42");
        assert!(errors.is_empty());
        assert_eq!(tokens[0].kind, TokenKind::IntLit(42));
    }

    #[test]
    fn lex_all_comparison_ops() {
        let (tokens, _) = tokenize("== != < > <= >=");
        assert_eq!(tokens[0].kind, TokenKind::EqEq);
        assert_eq!(tokens[1].kind, TokenKind::BangEq);
        assert_eq!(tokens[2].kind, TokenKind::Lt);
        assert_eq!(tokens[3].kind, TokenKind::Gt);
        assert_eq!(tokens[4].kind, TokenKind::LtEq);
        assert_eq!(tokens[5].kind, TokenKind::GtEq);
    }

    #[test]
    fn lex_arrow_operator() {
        let (tokens, _) = tokenize("->");
        assert_eq!(tokens[0].kind, TokenKind::Arrow);
    }

    #[test]
    fn lex_fat_arrow() {
        let (tokens, _) = tokenize("=>");
        assert_eq!(tokens[0].kind, TokenKind::FatArrow);
    }

    #[test]
    fn lex_dot_dot_range() {
        let (tokens, _) = tokenize("0..10");
        assert_eq!(tokens[0].kind, TokenKind::IntLit(0));
        assert_eq!(tokens[1].kind, TokenKind::DotDot);
        assert_eq!(tokens[2].kind, TokenKind::IntLit(10));
    }

    #[test]
    fn lex_question_mark() {
        let (tokens, _) = tokenize("result?");
        assert_eq!(tokens[0].kind, TokenKind::Ident("result".into()));
        assert_eq!(tokens[1].kind, TokenKind::Question);
    }

    #[test]
    fn lex_braces_and_brackets() {
        let (tokens, _) = tokenize("{ } [ ] ( )");
        assert_eq!(tokens[0].kind, TokenKind::LBrace);
        assert_eq!(tokens[1].kind, TokenKind::RBrace);
        assert_eq!(tokens[2].kind, TokenKind::LBracket);
        assert_eq!(tokens[3].kind, TokenKind::RBracket);
        assert_eq!(tokens[4].kind, TokenKind::LParen);
        assert_eq!(tokens[5].kind, TokenKind::RParen);
    }

    #[test]
    fn lex_keywords_fn_let_var() {
        let (tokens, _) = tokenize("fn let var");
        assert_eq!(tokens[0].kind, TokenKind::Fn);
        assert_eq!(tokens[1].kind, TokenKind::Let);
        assert_eq!(tokens[2].kind, TokenKind::Var);
    }

    #[test]
    fn lex_keywords_if_else_match() {
        let (tokens, _) = tokenize("if else match");
        assert_eq!(tokens[0].kind, TokenKind::If);
        assert_eq!(tokens[1].kind, TokenKind::Else);
        assert_eq!(tokens[2].kind, TokenKind::Match);
    }

    #[test]
    fn lex_keywords_for_while_loop() {
        let (tokens, _) = tokenize("for while loop");
        assert_eq!(tokens[0].kind, TokenKind::For);
        assert_eq!(tokens[1].kind, TokenKind::While);
        assert_eq!(tokens[2].kind, TokenKind::Loop);
    }

    #[test]
    fn lex_keywords_return_break_continue() {
        let (tokens, _) = tokenize("return break continue");
        assert_eq!(tokens[0].kind, TokenKind::Return);
        assert_eq!(tokens[1].kind, TokenKind::Break);
        assert_eq!(tokens[2].kind, TokenKind::Continue);
    }

    #[test]
    fn lex_float_literal() {
        let (tokens, _) = tokenize("3.14");
        assert!(matches!(tokens[0].kind, TokenKind::FloatLit(f) if (f - 3.14).abs() < 0.001));
    }

    #[test]
    fn lex_negative_int() {
        let (tokens, _) = tokenize("-42");
        assert_eq!(tokens[0].kind, TokenKind::Minus);
        assert_eq!(tokens[1].kind, TokenKind::IntLit(42));
    }

    #[test]
    fn lex_string_with_escapes() {
        let (tokens, _) = tokenize(r#""hello\nworld""#);
        assert!(matches!(&tokens[0].kind, TokenKind::StringLit(s) if s.contains('\n')));
    }

    #[test]
    fn lex_at_symbol_for_annotation() {
        let (tokens, _) = tokenize("@legal");
        assert_eq!(tokens[0].kind, TokenKind::At);
        assert_eq!(tokens[1].kind, TokenKind::Ident("legal".into()));
    }

    #[test]
    fn lex_double_star_power() {
        let (tokens, _) = tokenize("2 ** 10");
        assert_eq!(tokens[0].kind, TokenKind::IntLit(2));
        assert_eq!(tokens[1].kind, TokenKind::StarStar);
        assert_eq!(tokens[2].kind, TokenKind::IntLit(10));
    }
}
