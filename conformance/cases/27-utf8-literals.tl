// UTF-8 in string literals must survive the lexer unchanged.
//
// Before this case existed the lexer pushed `byte as char`, decoding each byte
// of a multi-byte scalar as Latin-1: the em dash below reached stdout as
// "â€"" and every plane printed the same damage, so the suite could not see it.
fn main() {
    print("dash: —")
    print("café · 日本語 · Ω")
}
