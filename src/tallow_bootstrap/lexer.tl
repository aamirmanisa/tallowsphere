// ============================================================================
// Tallow Self-Hosting Lexer — Written in Tallow
// ============================================================================
// First step toward self-hosting: a lexer for the Tallow language written in
// Tallow itself. Produces the same token kinds as the Rust lexer (src/lexer.rs)
// and can lex its own source code.
// ============================================================================

// ── Token Kinds ─────────────────────────────────────────────────────────────

enum TokenKind {
    // Literals
    IntLit,
    FloatLit,
    StringLit,

    // Keywords
    Fn, Let, Var, Const,
    Struct, Enum, Impl, Trait,
    Match, If, Else,
    For, While, In,
    Import, Async, Await,
    True, False, Nil,
    Type, SelfValue, Mut,
    As, Bail, BailIf,
    Break, Continue, Catch, Loop,
    Private, Secret, Return,

    // Identifiers
    Ident,

    // Delimiters
    LParen, RParen,
    LBrace, RBrace,
    LBracket, RBracket,

    // Operators
    Plus, Minus, Star, Slash, Percent,
    Eq, EqEq, BangEq,
    Lt, Gt, LtEq, GtEq,
    Bang,
    AmpAmp, PipePipe,
    Amp, Pipe, Caret, Tilde,
    StarStar,
    Shl, Shr,
    PlusEq, MinusEq, StarEq, SlashEq, PercentEq,
    StarStarEq, ShlEq, ShrEq,
    AmpEq, PipeEq, CaretEq,

    // Punctuation
    Dot, DotDot,
    Comma, Colon, ColonColon,
    Semi, Arrow, FatArrow,
    Question, At, Hash,
    Underscore,

    // Special
    Eof,
    Error
}

// ── Token ───────────────────────────────────────────────────────────────────

struct Token {
    kind:  TokenKind,
    text:  String,
    line:  i32,
    col:   i32
}

// ── Scan result (for returning token + updated lexer from helpers) ──────────

struct ScanResult {
    lex:   Lexer,
    token: Token
}

// ── Lexer State ─────────────────────────────────────────────────────────────

struct Lexer {
    source: String,
    pos:    i32,
    line:   i32,
    col:    i32
}

// ── Constructor ─────────────────────────────────────────────────────────────

fn new_lexer(source: String) -> Lexer {
    Lexer {
        source: source,
        pos:    0,
        line:   1,
        col:    1
    }
}

// ── Helper: make a token ────────────────────────────────────────────────────

fn make_token(kind: TokenKind, text: String, line: i32, col: i32) -> Token {
    Token { kind: kind, text: text, line: line, col: col }
}

// ── Character classification ────────────────────────────────────────────────

fn is_digit(ch: String) -> bool {
    if ch == "0" { true }
    else if ch == "1" { true }
    else if ch == "2" { true }
    else if ch == "3" { true }
    else if ch == "4" { true }
    else if ch == "5" { true }
    else if ch == "6" { true }
    else if ch == "7" { true }
    else if ch == "8" { true }
    else if ch == "9" { true }
    else { false }
}

fn is_hex_digit(ch: String) -> bool {
    if is_digit(ch) { true }
    else if ch == "a" { true }
    else if ch == "b" { true }
    else if ch == "c" { true }
    else if ch == "d" { true }
    else if ch == "e" { true }
    else if ch == "f" { true }
    else if ch == "A" { true }
    else if ch == "B" { true }
    else if ch == "C" { true }
    else if ch == "D" { true }
    else if ch == "E" { true }
    else if ch == "F" { true }
    else { false }
}

fn is_ident_start(ch: String) -> bool {
    if ch == "_" { true }
    else { ch.is_alpha() }
}

fn is_ident_char(ch: String) -> bool {
    if ch == "_" { true }
    else if is_digit(ch) { true }
    else { ch.is_alpha() }
}

fn is_whitespace(ch: String) -> bool {
    if ch == " " { true }
    else if ch == "\t" { true }
    else if ch == "\n" { true }
    else if ch == "\r" { true }
    else { false }
}

// ── Lexer: peek / advance / helpers ─────────────────────────────────────────

fn lex_peek(lex: Lexer) -> String {
    if lex.pos >= lex.source.len { "" }
    else { lex.source[lex.pos] }
}

fn lex_peek_next(lex: Lexer) -> String {
    let next = lex.pos + 1
    if next >= lex.source.len { "" }
    else { lex.source[next] }
}

fn lex_at_end(lex: Lexer) -> bool {
    lex.pos >= lex.source.len
}

fn advance_lexer(lex: Lexer) -> Lexer {
    if lex.pos >= lex.source.len { lex }
    else {
        let ch = lex.source[lex.pos]
        if ch == "\n" {
            Lexer { ...lex, pos: lex.pos + 1, line: lex.line + 1, col: 1 }
        } else {
            Lexer { ...lex, pos: lex.pos + 1, col: lex.col + 1 }
        }
    }
}

// Build well-known single characters without embedded quotes in strings.
// We use single-quote strings to hold special chars: double-quote, braces.
fn quote_char() -> String {
    // single-quote string containing a double-quote character
    '"'
}

fn open_brace_char() -> String {
    '{'
}

fn close_brace_char() -> String {
    '}'
}

fn backslash_char() -> String {
    "\\"
}

// ── Skip whitespace and comments ────────────────────────────────────────────

fn skip_whitespace(lex: Lexer) -> Lexer {
    var l = lex
    var again = true
    while again {
        // Skip whitespace characters
        while !lex_at_end(l) && is_whitespace(lex_peek(l)) {
            l = advance_lexer(l)
        }

        // Skip line comments: //
        if !lex_at_end(l) && lex_peek(l) == "/" && lex_peek_next(l) == "/" {
            while !lex_at_end(l) && lex_peek(l) != "\n" {
                l = advance_lexer(l)
            }
            again = true
        } else if !lex_at_end(l) && lex_peek(l) == "/" && lex_peek_next(l) == "*" {
            // Skip block comments: /* ... */ (nestable)
            l = advance_lexer(l)
            l = advance_lexer(l)
            var depth = 1
            while depth > 0 && !lex_at_end(l) {
                if lex_peek(l) == "/" && lex_peek_next(l) == "*" {
                    l = advance_lexer(l)
                    l = advance_lexer(l)
                    depth = depth + 1
                } else if lex_peek(l) == "*" && lex_peek_next(l) == "/" {
                    l = advance_lexer(l)
                    l = advance_lexer(l)
                    depth = depth - 1
                } else {
                    l = advance_lexer(l)
                }
            }
            again = true
        } else {
            again = false
        }
    }
    l
}

// ── Keyword lookup ──────────────────────────────────────────────────────────

fn lookup_keyword(word: String) -> TokenKind {
    if word == "fn" { TokenKind.Fn }
    else if word == "let" { TokenKind.Let }
    else if word == 'var' { TokenKind.Var }
    else if word == 'return' { TokenKind.Return }
    else if word == "const" { TokenKind.Const }
    else if word == "struct" { TokenKind.Struct }
    else if word == "enum" { TokenKind.Enum }
    else if word == "impl" { TokenKind.Impl }
    else if word == "trait" { TokenKind.Trait }
    else if word == "match" { TokenKind.Match }
    else if word == "if" { TokenKind.If }
    else if word == "else" { TokenKind.Else }
    else if word == "for" { TokenKind.For }
    else if word == "while" { TokenKind.While }
    else if word == "in" { TokenKind.In }
    else if word == "import" { TokenKind.Import }
    else if word == "async" { TokenKind.Async }
    else if word == "await" { TokenKind.Await }
    else if word == "true" { TokenKind.True }
    else if word == "false" { TokenKind.False }
    else if word == "nil" { TokenKind.Nil }
    else if word == "type" { TokenKind.Type }
    else if word == "self" { TokenKind.SelfValue }
    else if word == "mut" { TokenKind.Mut }
    else if word == "as" { TokenKind.As }
    else if word == "bail" { TokenKind.Bail }
    else if word == "bail_if" { TokenKind.BailIf }
    else if word == "break" { TokenKind.Break }
    else if word == "continue" { TokenKind.Continue }
    else if word == "catch" { TokenKind.Catch }
    else if word == "loop" { TokenKind.Loop }
    else if word == "private" { TokenKind.Private }
    else if word == "secret" { TokenKind.Secret }
    else if word == "_" { TokenKind.Underscore }
    else { TokenKind.Ident }
}

// ── Main tokenize function ──────────────────────────────────────────────────

fn tokenize(source: String) -> []Token {
    var lex = new_lexer(source)
    var tokens = []
    let dq = quote_char()
    let ob = open_brace_char()
    let cb = close_brace_char()
    let bs = backslash_char()
    let sq = "'"

    var running = true
    while running {
        lex = skip_whitespace(lex)

        if lex_at_end(lex) {
            tokens = tokens.push(make_token(TokenKind.Eof, "", lex.line, lex.col))
            running = false
        } else {
            let ch = lex_peek(lex)
            let start_line = lex.line
            let start_col = lex.col

            // ── Double-quote string literal ──
            if ch == dq {
                var l2 = advance_lexer(lex)  // skip opening quote
                var str_text = ""
                var str_done = false
                while !str_done && !lex_at_end(l2) {
                    let sc = lex_peek(l2)
                    if sc == bs {
                        // Escape sequence
                        l2 = advance_lexer(l2)
                        if !lex_at_end(l2) {
                            let esc = lex_peek(l2)
                            if esc == "n" { str_text = str_text + "\n" }
                            else if esc == "t" { str_text = str_text + "\t" }
                            else if esc == "r" { str_text = str_text + "\r" }
                            else if esc == bs { str_text = str_text + bs }
                            else if esc == dq { str_text = str_text + dq }
                            else if esc == "0" { str_text = str_text + "\0" }
                            else if esc == ob { str_text = str_text + ob }
                            else if esc == cb { str_text = str_text + cb }
                            else { str_text = str_text + esc }
                            l2 = advance_lexer(l2)
                        }
                    } else if sc == dq {
                        l2 = advance_lexer(l2)  // consume closing quote
                        str_done = true
                    } else {
                        str_text = str_text + sc
                        l2 = advance_lexer(l2)
                    }
                }
                tokens = tokens.push(make_token(TokenKind.StringLit, str_text, start_line, start_col))
                lex = l2
            }
            // ── Single-quote string literal (raw) ──
            else if ch == sq {
                var l2 = advance_lexer(lex)  // skip opening quote
                var sq_text = ""
                var sq_done = false
                while !sq_done && !lex_at_end(l2) {
                    let sc = lex_peek(l2)
                    if sc == sq {
                        l2 = advance_lexer(l2)
                        sq_done = true
                    } else {
                        sq_text = sq_text + sc
                        l2 = advance_lexer(l2)
                    }
                }
                tokens = tokens.push(make_token(TokenKind.StringLit, sq_text, start_line, start_col))
                lex = l2
            }
            // ── Number literal ──
            else if is_digit(ch) {
                var l2 = lex
                var num_text = ""
                var has_dot = false

                // Check for 0x, 0b, 0o prefixes
                if ch == "0" {
                    let pn = lex_peek_next(l2)
                    if pn == "x" || pn == "X" {
                        num_text = num_text + lex_peek(l2)
                        l2 = advance_lexer(l2)
                        num_text = num_text + lex_peek(l2)
                        l2 = advance_lexer(l2)
                        // Hex digits
                        while !lex_at_end(l2) && (is_hex_digit(lex_peek(l2)) || lex_peek(l2) == "_") {
                            let hc = lex_peek(l2)
                            if hc != "_" {
                                num_text = num_text + hc
                            }
                            l2 = advance_lexer(l2)
                        }
                        tokens = tokens.push(make_token(TokenKind.IntLit, num_text, start_line, start_col))
                        lex = l2
                    } else if pn == "b" || pn == "B" {
                        num_text = num_text + lex_peek(l2)
                        l2 = advance_lexer(l2)
                        num_text = num_text + lex_peek(l2)
                        l2 = advance_lexer(l2)
                        // Binary digits
                        while !lex_at_end(l2) && (lex_peek(l2) == "0" || lex_peek(l2) == "1" || lex_peek(l2) == "_") {
                            let bc = lex_peek(l2)
                            if bc != "_" {
                                num_text = num_text + bc
                            }
                            l2 = advance_lexer(l2)
                        }
                        tokens = tokens.push(make_token(TokenKind.IntLit, num_text, start_line, start_col))
                        lex = l2
                    } else if pn == "o" || pn == "O" {
                        num_text = num_text + lex_peek(l2)
                        l2 = advance_lexer(l2)
                        num_text = num_text + lex_peek(l2)
                        l2 = advance_lexer(l2)
                        // Octal digits
                        while !lex_at_end(l2) && (is_digit(lex_peek(l2)) || lex_peek(l2) == "_") {
                            let oc = lex_peek(l2)
                            if oc != "_" {
                                num_text = num_text + oc
                            }
                            l2 = advance_lexer(l2)
                        }
                        tokens = tokens.push(make_token(TokenKind.IntLit, num_text, start_line, start_col))
                        lex = l2
                    } else {
                        // Regular decimal number starting with 0
                        let sr = scan_decimal(l2, start_line, start_col)
                        tokens = tokens.push(sr.token)
                        lex = sr.lex
                    }
                } else {
                    // Regular decimal number
                    let sr = scan_decimal(l2, start_line, start_col)
                        tokens = tokens.push(sr.token)
                        lex = sr.lex
                }
            }
            // ── Identifier or keyword ──
            else if is_ident_start(ch) {
                var l2 = lex
                var word = ""
                while !lex_at_end(l2) && is_ident_char(lex_peek(l2)) {
                    word = word + lex_peek(l2)
                    l2 = advance_lexer(l2)
                }
                let kind = lookup_keyword(word)
                tokens = tokens.push(make_token(kind, word, start_line, start_col))
                lex = l2
            }
            // ── Delimiters ──
            else if ch == "(" {
                tokens = tokens.push(make_token(TokenKind.LParen, "(", start_line, start_col))
                lex = advance_lexer(lex)
            }
            else if ch == ")" {
                tokens = tokens.push(make_token(TokenKind.RParen, ")", start_line, start_col))
                lex = advance_lexer(lex)
            }
            else if ch == ob {
                tokens = tokens.push(make_token(TokenKind.LBrace, ob, start_line, start_col))
                lex = advance_lexer(lex)
            }
            else if ch == cb {
                tokens = tokens.push(make_token(TokenKind.RBrace, cb, start_line, start_col))
                lex = advance_lexer(lex)
            }
            else if ch == "[" {
                tokens = tokens.push(make_token(TokenKind.LBracket, "[", start_line, start_col))
                lex = advance_lexer(lex)
            }
            else if ch == "]" {
                tokens = tokens.push(make_token(TokenKind.RBracket, "]", start_line, start_col))
                lex = advance_lexer(lex)
            }
            // ── Simple single-char punctuation ──
            else if ch == "," {
                tokens = tokens.push(make_token(TokenKind.Comma, ",", start_line, start_col))
                lex = advance_lexer(lex)
            }
            else if ch == ";" {
                tokens = tokens.push(make_token(TokenKind.Semi, ";", start_line, start_col))
                lex = advance_lexer(lex)
            }
            else if ch == "~" {
                tokens = tokens.push(make_token(TokenKind.Tilde, "~", start_line, start_col))
                lex = advance_lexer(lex)
            }
            else if ch == "?" {
                tokens = tokens.push(make_token(TokenKind.Question, "?", start_line, start_col))
                lex = advance_lexer(lex)
            }
            else if ch == "#" {
                tokens = tokens.push(make_token(TokenKind.Hash, "#", start_line, start_col))
                lex = advance_lexer(lex)
            }
            else if ch == "@" {
                tokens = tokens.push(make_token(TokenKind.At, "@", start_line, start_col))
                lex = advance_lexer(lex)
            }
            // ── Multi-character operators ──
            else if ch == "+" {
                lex = advance_lexer(lex)
                if !lex_at_end(lex) && lex_peek(lex) == "=" {
                    tokens = tokens.push(make_token(TokenKind.PlusEq, "+=", start_line, start_col))
                    lex = advance_lexer(lex)
                } else {
                    tokens = tokens.push(make_token(TokenKind.Plus, "+", start_line, start_col))
                }
            }
            else if ch == "-" {
                lex = advance_lexer(lex)
                if !lex_at_end(lex) && lex_peek(lex) == ">" {
                    tokens = tokens.push(make_token(TokenKind.Arrow, "->", start_line, start_col))
                    lex = advance_lexer(lex)
                } else if !lex_at_end(lex) && lex_peek(lex) == "=" {
                    tokens = tokens.push(make_token(TokenKind.MinusEq, "-=", start_line, start_col))
                    lex = advance_lexer(lex)
                } else {
                    tokens = tokens.push(make_token(TokenKind.Minus, "-", start_line, start_col))
                }
            }
            else if ch == "*" {
                lex = advance_lexer(lex)
                if !lex_at_end(lex) && lex_peek(lex) == "*" {
                    lex = advance_lexer(lex)
                    if !lex_at_end(lex) && lex_peek(lex) == "=" {
                        tokens = tokens.push(make_token(TokenKind.StarStarEq, "**=", start_line, start_col))
                        lex = advance_lexer(lex)
                    } else {
                        tokens = tokens.push(make_token(TokenKind.StarStar, "**", start_line, start_col))
                    }
                } else if !lex_at_end(lex) && lex_peek(lex) == "=" {
                    tokens = tokens.push(make_token(TokenKind.StarEq, "*=", start_line, start_col))
                    lex = advance_lexer(lex)
                } else {
                    tokens = tokens.push(make_token(TokenKind.Star, "*", start_line, start_col))
                }
            }
            else if ch == "/" {
                lex = advance_lexer(lex)
                if !lex_at_end(lex) && lex_peek(lex) == "=" {
                    tokens = tokens.push(make_token(TokenKind.SlashEq, "/=", start_line, start_col))
                    lex = advance_lexer(lex)
                } else {
                    tokens = tokens.push(make_token(TokenKind.Slash, "/", start_line, start_col))
                }
            }
            else if ch == "%" {
                lex = advance_lexer(lex)
                if !lex_at_end(lex) && lex_peek(lex) == "=" {
                    tokens = tokens.push(make_token(TokenKind.PercentEq, "%=", start_line, start_col))
                    lex = advance_lexer(lex)
                } else {
                    tokens = tokens.push(make_token(TokenKind.Percent, "%", start_line, start_col))
                }
            }
            else if ch == "=" {
                lex = advance_lexer(lex)
                if !lex_at_end(lex) && lex_peek(lex) == ">" {
                    tokens = tokens.push(make_token(TokenKind.FatArrow, "=>", start_line, start_col))
                    lex = advance_lexer(lex)
                } else if !lex_at_end(lex) && lex_peek(lex) == "=" {
                    tokens = tokens.push(make_token(TokenKind.EqEq, "==", start_line, start_col))
                    lex = advance_lexer(lex)
                } else {
                    tokens = tokens.push(make_token(TokenKind.Eq, "=", start_line, start_col))
                }
            }
            else if ch == "!" {
                lex = advance_lexer(lex)
                if !lex_at_end(lex) && lex_peek(lex) == "=" {
                    tokens = tokens.push(make_token(TokenKind.BangEq, "!=", start_line, start_col))
                    lex = advance_lexer(lex)
                } else {
                    tokens = tokens.push(make_token(TokenKind.Bang, "!", start_line, start_col))
                }
            }
            else if ch == "<" {
                lex = advance_lexer(lex)
                if !lex_at_end(lex) && lex_peek(lex) == "<" {
                    lex = advance_lexer(lex)
                    if !lex_at_end(lex) && lex_peek(lex) == "=" {
                        tokens = tokens.push(make_token(TokenKind.ShlEq, "<<=", start_line, start_col))
                        lex = advance_lexer(lex)
                    } else {
                        tokens = tokens.push(make_token(TokenKind.Shl, "<<", start_line, start_col))
                    }
                } else if !lex_at_end(lex) && lex_peek(lex) == "=" {
                    tokens = tokens.push(make_token(TokenKind.LtEq, "<=", start_line, start_col))
                    lex = advance_lexer(lex)
                } else {
                    tokens = tokens.push(make_token(TokenKind.Lt, "<", start_line, start_col))
                }
            }
            else if ch == ">" {
                lex = advance_lexer(lex)
                if !lex_at_end(lex) && lex_peek(lex) == ">" {
                    lex = advance_lexer(lex)
                    if !lex_at_end(lex) && lex_peek(lex) == "=" {
                        tokens = tokens.push(make_token(TokenKind.ShrEq, ">>=", start_line, start_col))
                        lex = advance_lexer(lex)
                    } else {
                        tokens = tokens.push(make_token(TokenKind.Shr, ">>", start_line, start_col))
                    }
                } else if !lex_at_end(lex) && lex_peek(lex) == "=" {
                    tokens = tokens.push(make_token(TokenKind.GtEq, ">=", start_line, start_col))
                    lex = advance_lexer(lex)
                } else {
                    tokens = tokens.push(make_token(TokenKind.Gt, ">", start_line, start_col))
                }
            }
            else if ch == "&" {
                lex = advance_lexer(lex)
                if !lex_at_end(lex) && lex_peek(lex) == "&" {
                    tokens = tokens.push(make_token(TokenKind.AmpAmp, "&&", start_line, start_col))
                    lex = advance_lexer(lex)
                } else if !lex_at_end(lex) && lex_peek(lex) == "=" {
                    tokens = tokens.push(make_token(TokenKind.AmpEq, "&=", start_line, start_col))
                    lex = advance_lexer(lex)
                } else {
                    tokens = tokens.push(make_token(TokenKind.Amp, "&", start_line, start_col))
                }
            }
            else if ch == "|" {
                lex = advance_lexer(lex)
                if !lex_at_end(lex) && lex_peek(lex) == "|" {
                    tokens = tokens.push(make_token(TokenKind.PipePipe, "||", start_line, start_col))
                    lex = advance_lexer(lex)
                } else if !lex_at_end(lex) && lex_peek(lex) == "=" {
                    tokens = tokens.push(make_token(TokenKind.PipeEq, "|=", start_line, start_col))
                    lex = advance_lexer(lex)
                } else {
                    tokens = tokens.push(make_token(TokenKind.Pipe, "|", start_line, start_col))
                }
            }
            else if ch == "^" {
                lex = advance_lexer(lex)
                if !lex_at_end(lex) && lex_peek(lex) == "=" {
                    tokens = tokens.push(make_token(TokenKind.CaretEq, "^=", start_line, start_col))
                    lex = advance_lexer(lex)
                } else {
                    tokens = tokens.push(make_token(TokenKind.Caret, "^", start_line, start_col))
                }
            }
            else if ch == "." {
                lex = advance_lexer(lex)
                if !lex_at_end(lex) && lex_peek(lex) == "." {
                    tokens = tokens.push(make_token(TokenKind.DotDot, "..", start_line, start_col))
                    lex = advance_lexer(lex)
                } else {
                    tokens = tokens.push(make_token(TokenKind.Dot, ".", start_line, start_col))
                }
            }
            else if ch == ":" {
                lex = advance_lexer(lex)
                if !lex_at_end(lex) && lex_peek(lex) == ":" {
                    tokens = tokens.push(make_token(TokenKind.ColonColon, "::", start_line, start_col))
                    lex = advance_lexer(lex)
                } else {
                    tokens = tokens.push(make_token(TokenKind.Colon, ":", start_line, start_col))
                }
            }
            else {
                // Unknown character — emit error token and advance
                tokens = tokens.push(make_token(TokenKind.Error, ch, start_line, start_col))
                lex = advance_lexer(lex)
            }
        }
    }

    tokens
}

// ── Helper: scan decimal number (integer or float) ──────────────────────────
// Returns a ScanResult containing the number token and updated lexer state.

fn scan_decimal(lex: Lexer, start_line: i32, start_col: i32) -> ScanResult {
    var l = lex
    var num_text = ""
    var has_dot = false

    // Eat digits and underscores
    while !lex_at_end(l) && (is_digit(lex_peek(l)) || lex_peek(l) == "_") {
        let dc = lex_peek(l)
        if dc != "_" {
            num_text = num_text + dc
        }
        l = advance_lexer(l)
    }

    // Check for float: dot followed by digit (not ..)
    if !lex_at_end(l) && lex_peek(l) == "." && lex_peek_next(l) != "." {
        let after = lex_peek_next(l)
        if is_digit(after) {
            has_dot = true
            num_text = num_text + "."
            l = advance_lexer(l)  // consume dot
            while !lex_at_end(l) && (is_digit(lex_peek(l)) || lex_peek(l) == "_") {
                let dc2 = lex_peek(l)
                if dc2 != "_" {
                    num_text = num_text + dc2
                }
                l = advance_lexer(l)
            }
            // Scientific notation
            if !lex_at_end(l) && (lex_peek(l) == "e" || lex_peek(l) == "E") {
                num_text = num_text + lex_peek(l)
                l = advance_lexer(l)
                if !lex_at_end(l) && (lex_peek(l) == "+" || lex_peek(l) == "-") {
                    num_text = num_text + lex_peek(l)
                    l = advance_lexer(l)
                }
                while !lex_at_end(l) && (is_digit(lex_peek(l)) || lex_peek(l) == "_") {
                    let dc3 = lex_peek(l)
                    if dc3 != "_" {
                        num_text = num_text + dc3
                    }
                    l = advance_lexer(l)
                }
            }
        }
    }

    let tok = if has_dot {
        make_token(TokenKind.FloatLit, num_text, start_line, start_col)
    } else {
        make_token(TokenKind.IntLit, num_text, start_line, start_col)
    }
    ScanResult { lex: l, token: tok }
}

// ── Token kind to string ────────────────────────────────────────────────────

fn kind_name(kind: TokenKind) -> String {
    match kind {
        Fn          -> "Fn"
        Let         -> "Let"
        Var         -> "Var"
        Const       -> "Const"
        Struct      -> "Struct"
        Enum        -> "Enum"
        Impl        -> "Impl"
        Trait       -> "Trait"
        Match       -> "Match"
        If          -> "If"
        Else        -> "Else"
        For         -> "For"
        While       -> "While"
        In          -> "In"
        Return      -> "Return"
        Import      -> "Import"
        Async       -> "Async"
        Await       -> "Await"
        True        -> "True"
        False       -> "False"
        Nil         -> "Nil"
        Type        -> "Type"
        SelfValue   -> "SelfValue"
        Mut         -> "Mut"
        As          -> "As"
        Bail        -> "Bail"
        BailIf      -> "BailIf"
        Break       -> "Break"
        Continue    -> "Continue"
        Catch       -> "Catch"
        Loop        -> "Loop"
        Private     -> "Private"
        Secret      -> "Secret"
        IntLit      -> "IntLit"
        FloatLit    -> "FloatLit"
        StringLit   -> "StringLit"
        Ident       -> "Ident"
        LParen      -> "LParen"
        RParen      -> "RParen"
        LBrace      -> "LBrace"
        RBrace      -> "RBrace"
        LBracket    -> "LBracket"
        RBracket    -> "RBracket"
        Plus        -> "Plus"
        Minus       -> "Minus"
        Star        -> "Star"
        Slash       -> "Slash"
        Percent     -> "Percent"
        Eq          -> "Eq"
        EqEq        -> "EqEq"
        BangEq      -> "BangEq"
        Lt          -> "Lt"
        Gt          -> "Gt"
        LtEq        -> "LtEq"
        GtEq        -> "GtEq"
        Bang        -> "Bang"
        AmpAmp      -> "AmpAmp"
        PipePipe    -> "PipePipe"
        Amp         -> "Amp"
        Pipe        -> "Pipe"
        Caret       -> "Caret"
        Tilde       -> "Tilde"
        StarStar    -> "StarStar"
        Shl         -> "Shl"
        Shr         -> "Shr"
        PlusEq      -> "PlusEq"
        MinusEq     -> "MinusEq"
        StarEq      -> "StarEq"
        SlashEq     -> "SlashEq"
        PercentEq   -> "PercentEq"
        StarStarEq  -> "StarStarEq"
        ShlEq       -> "ShlEq"
        ShrEq       -> "ShrEq"
        AmpEq       -> "AmpEq"
        PipeEq      -> "PipeEq"
        CaretEq     -> "CaretEq"
        Dot         -> "Dot"
        DotDot      -> "DotDot"
        Comma       -> "Comma"
        Colon       -> "Colon"
        ColonColon  -> "ColonColon"
        Semi        -> "Semi"
        Arrow       -> "Arrow"
        FatArrow    -> "FatArrow"
        Question    -> "Question"
        At          -> "At"
        Hash        -> "Hash"
        Underscore  -> "Underscore"
        Eof         -> "Eof"
        Error       -> "Error"
        _           -> "Unknown"
    }
}

// ── Pretty-print a token ────────────────────────────────────────────────────

fn format_token(tok: Token) -> String {
    let kn = kind_name(tok.kind)
    let ln = to_string(tok.line)
    let cl = to_string(tok.col)
    ln + ":" + cl + "  " + kn + "  " + tok.text
}

// ── Count tokens by kind ────────────────────────────────────────────────────

fn count_kind(tokens: []Token, target: String) -> i32 {
    var count = 0
    for tok in tokens {
        if kind_name(tok.kind) == target {
            count = count + 1
        }
    }
    count
}

// ============================================================================
// MAIN — Test the lexer by tokenizing sample programs
// ============================================================================

fn main() {
    print("=== Tallow Bootstrap Lexer ===")
    print("")

    // Test 1: Simple expression
    let src1 = "let x = 42 + 3.14"
    let toks1 = tokenize(src1)
    print("Test 1: simple expression")
    for tok in toks1 {
        print("  " + format_token(tok))
    }
    print("")

    // Test 2: Function definition (use single-quote to avoid brace interpolation)
    let src2 = 'fn add(a: i32, b: i32) -> i32 { a + b }'
    let toks2 = tokenize(src2)
    print("Test 2: function definition")
    for tok in toks2 {
        print("  " + format_token(tok))
    }
    print("")

    // Test 3: Struct
    let src3 = 'struct Point { x: f64, y: f64 }'
    let toks3 = tokenize(src3)
    print("Test 3: struct definition")
    for tok in toks3 {
        print("  " + format_token(tok))
    }
    print("")

    // Test 4: Comparison operators
    let src4 = "a == b && c != d || e <= f"
    let toks4 = tokenize(src4)
    print("Test 4: comparison operators")
    for tok in toks4 {
        print("  " + format_token(tok))
    }
    print("")

    // Test 5: All keywords
    let src5 = "fn let const struct enum impl trait match if else for while in import async await true false nil type self pub mut as bail bail_if break continue catch loop private secret"
    let toks5 = tokenize(src5)
    print("Test 5: all keywords")
    for tok in toks5 {
        print("  " + format_token(tok))
    }
    print("")

    // Test 6: Compound assignment operators
    let src6 = "+= -= *= /= %= **= <<= >>= &= |= ^="
    let toks6 = tokenize(src6)
    print("Test 6: compound assignments")
    for tok in toks6 {
        print("  " + format_token(tok))
    }
    print("")

    // Test 7: Comments are skipped
    let src7 = "let a = 1 // comment\nlet b = 2"
    let toks7 = tokenize(src7)
    print("Test 7: comment skipping")
    for tok in toks7 {
        print("  " + format_token(tok))
    }
    print("")

    // Test 8: Number formats
    let src8 = "42 3.14 100_000 2.5e10 0xff 0b1010"
    let toks8 = tokenize(src8)
    print("Test 8: number formats")
    for tok in toks8 {
        print("  " + format_token(tok))
    }
    print("")

    // Test 9: Arrow and fat arrow
    let src9 = "-> => .. :: . :"
    let toks9 = tokenize(src9)
    print("Test 9: punctuation pairs")
    for tok in toks9 {
        print("  " + format_token(tok))
    }
    print("")

    // Test 10: Mixed real-world-like code
    let src10 = 'let result = items.filter({ x -> x > 0 }).map({ x -> x * 2 })'
    let toks10 = tokenize(src10)
    print("Test 10: real-world expression")
    for tok in toks10 {
        print("  " + format_token(tok))
    }
    print("")

    // Summary
    let total = toks1.len + toks2.len + toks3.len + toks4.len + toks5.len + toks6.len + toks7.len + toks8.len + toks9.len + toks10.len
    print("Total tokens across all tests: " + to_string(total))
    print("")
    print("Token kind counts from test 2 (function):")
    print("  Fn:       " + to_string(count_kind(toks2, "Fn")))
    print("  Ident:    " + to_string(count_kind(toks2, "Ident")))
    print("  LParen:   " + to_string(count_kind(toks2, "LParen")))
    print("  Arrow:    " + to_string(count_kind(toks2, "Arrow")))
    print("  LBrace:   " + to_string(count_kind(toks2, "LBrace")))
    print("")
    print("Lexer bootstrap complete.")
}
