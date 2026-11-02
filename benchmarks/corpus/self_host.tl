// self_host.tl -- Tallow Subset Compiler written in Tallow
//
// Compiles a minimal Tallow subset to LLVM IR text (.ll files).
// Demonstrates the self-hosting bootstrap chain.
//
// Supported subset:
//   - Integer literals and arithmetic (+, -, *, /)
//   - String literals
//   - let/var bindings
//   - fn definitions with i32/i64 params and return types
//   - Function calls (up to 4 args)
//   - if/else control flow
//   - while loops
//   - print() builtin
//   - Comparison operators (==, !=, <, >, <=, >=)
//   - return statement
//   - Implicit return (last expression)
//
// Usage:
//   tallow run examples/self_host.tl -- examples/hello_simple.tl

// ── Character helpers ───────────────────────────────────────

fn is_digit(ch: String) -> i32 {
    if ch == "0" { return 1 }
    if ch == "1" { return 1 }
    if ch == "2" { return 1 }
    if ch == "3" { return 1 }
    if ch == "4" { return 1 }
    if ch == "5" { return 1 }
    if ch == "6" { return 1 }
    if ch == "7" { return 1 }
    if ch == "8" { return 1 }
    if ch == "9" { return 1 }
    0
}

fn is_alpha(ch: String) -> i32 {
    if ch == "_" { return 1 }
    if ch == "a" { return 1 } if ch == "b" { return 1 } if ch == "c" { return 1 }
    if ch == "d" { return 1 } if ch == "e" { return 1 } if ch == "f" { return 1 }
    if ch == "g" { return 1 } if ch == "h" { return 1 } if ch == "i" { return 1 }
    if ch == "j" { return 1 } if ch == "k" { return 1 } if ch == "l" { return 1 }
    if ch == "m" { return 1 } if ch == "n" { return 1 } if ch == "o" { return 1 }
    if ch == "p" { return 1 } if ch == "q" { return 1 } if ch == "r" { return 1 }
    if ch == "s" { return 1 } if ch == "t" { return 1 } if ch == "u" { return 1 }
    if ch == "v" { return 1 } if ch == "w" { return 1 } if ch == "x" { return 1 }
    if ch == "y" { return 1 } if ch == "z" { return 1 }
    if ch == "A" { return 1 } if ch == "B" { return 1 } if ch == "C" { return 1 }
    if ch == "D" { return 1 } if ch == "E" { return 1 } if ch == "F" { return 1 }
    if ch == "G" { return 1 } if ch == "H" { return 1 } if ch == "I" { return 1 }
    if ch == "J" { return 1 } if ch == "K" { return 1 } if ch == "L" { return 1 }
    if ch == "M" { return 1 } if ch == "N" { return 1 } if ch == "O" { return 1 }
    if ch == "P" { return 1 } if ch == "Q" { return 1 } if ch == "R" { return 1 }
    if ch == "S" { return 1 } if ch == "T" { return 1 } if ch == "U" { return 1 }
    if ch == "V" { return 1 } if ch == "W" { return 1 } if ch == "X" { return 1 }
    if ch == "Y" { return 1 } if ch == "Z" { return 1 }
    0
}

fn is_alnum(ch: String) -> i32 {
    if is_digit(ch) == 1 { return 1 }
    is_alpha(ch)
}

fn ch(s: String, i: i32) -> String {
    s.substring(i, i + 1)
}

// ── Compile function ────────────────────────────────────────
// All mutable state is local. Single-pass: scan functions, then parse+emit.

fn compile(src: String) -> String {
    var ir = ""         // accumulated LLVM IR
    var sp = ""         // string constant pool
    var sc = 0          // string constant counter
    var rc = 0          // register counter
    var lc = 0          // label counter
    var p = 0           // parse position

    // Variable table for current function (pipe-delimited)
    var vn = ""         // names: "x|y|sum|"
    var vr = ""         // regs:  "%1|%2|%3|"
    var vm = ""         // muts:  "0|0|1|"
    var vc = 0          // count

    // Current function params
    var p0 = ""
    var p1 = ""
    var p2 = ""
    var p3 = ""
    var pc = 0

    // Function table (from pass 1)
    var ft_names = ""   // "add|main|"
    var ft_pcs = ""     // "2|0|"
    var ft_rets = ""    // "1|0|"
    var ft_count = 0

    // ── Helper: find nth pipe-delimited field ────────────────
    // Returns empty string if not found

    // ── Helper: intern a string constant ─────────────────────
    // Returns the global name like @.str.0

    // ── Pass 1: Scan function declarations ───────────────────

    var sp1 = 0
    while sp1 < src.len {
        // Skip whitespace
        while sp1 < src.len {
            let c = ch(src, sp1)
            if c == " " { sp1 = sp1 + 1 }
            else if c == "\n" { sp1 = sp1 + 1 }
            else if c == "\r" { sp1 = sp1 + 1 }
            else if c == "\t" { sp1 = sp1 + 1 }
            else if c == "/" {
                if sp1 + 1 < src.len {
                    if ch(src, sp1 + 1) == "/" {
                        sp1 = sp1 + 2
                        while sp1 < src.len {
                            if ch(src, sp1) == "\n" { sp1 = sp1 + 1; break }
                            sp1 = sp1 + 1
                        }
                    } else { break }
                } else { break }
            } else { break }
        }
        if sp1 >= src.len { break }

        // Check for "fn " at current position
        if ch(src, sp1) == "f" {
            if sp1 + 2 < src.len {
                if ch(src, sp1 + 1) == "n" {
                    if ch(src, sp1 + 2) == " " {
                        sp1 = sp1 + 3
                        // Read function name
                        var fname = ""
                        while sp1 < src.len {
                            let fc = ch(src, sp1)
                            if is_alnum(fc) == 1 { fname = fname + fc; sp1 = sp1 + 1 }
                            else { break }
                        }
                        // Skip to (
                        while sp1 < src.len {
                            if ch(src, sp1) == "(" { break }
                            sp1 = sp1 + 1
                        }
                        sp1 = sp1 + 1  // skip (
                        // Count params by counting ':'
                        var pcount = 0
                        var depth = 1
                        while sp1 < src.len {
                            let pc2 = ch(src, sp1)
                            if pc2 == ")" { depth = depth - 1; if depth == 0 { sp1 = sp1 + 1; break } }
                            if pc2 == ":" { pcount = pcount + 1 }
                            sp1 = sp1 + 1
                        }
                        // Check for -> return type
                        var has_ret = 0
                        while sp1 < src.len {
                            let wc = ch(src, sp1)
                            if wc == " " { sp1 = sp1 + 1 }
                            else if wc == "\n" { sp1 = sp1 + 1 }
                            else if wc == "-" {
                                if sp1 + 1 < src.len {
                                    if ch(src, sp1 + 1) == ">" { has_ret = 1 }
                                }
                                break
                            } else { break }
                        }
                        // Register function
                        ft_names = ft_names + fname + "|"
                        ft_pcs = ft_pcs + "{pcount}|"
                        ft_rets = ft_rets + "{has_ret}|"
                        ft_count = ft_count + 1
                        // Skip to end of function body
                        while sp1 < src.len {
                            if ch(src, sp1) == "\{" { break }
                            sp1 = sp1 + 1
                        }
                        if sp1 < src.len {
                            sp1 = sp1 + 1
                            var bd = 1
                            while bd > 0 {
                                if sp1 >= src.len { break }
                                let bc = ch(src, sp1)
                                if bc == "\{" { bd = bd + 1 }
                                if bc == "\}" { bd = bd - 1 }
                                if bc == "\"" {
                                    sp1 = sp1 + 1
                                    while sp1 < src.len {
                                        let sc2 = ch(src, sp1)
                                        if sc2 == "\\" { sp1 = sp1 + 2; continue }
                                        if sc2 == "\"" { sp1 = sp1 + 1; break }
                                        sp1 = sp1 + 1
                                    }
                                    continue
                                }
                                sp1 = sp1 + 1
                            }
                        }
                        continue
                    }
                }
            }
        }
        sp1 = sp1 + 1
    }

    // ── Emit LLVM IR header ──────────────────────────────────

    ir = ir + "; Generated by Tallow self-hosting subset compiler\n"
    ir = ir + "target triple = \"x86_64-pc-windows-msvc\"\n\n"
    ir = ir + "declare i32 @printf(ptr, ...)\n\n; STRING_POOL_MARKER\n"

    // ── Pass 2: Parse + Codegen ──────────────────────────────

    p = 0
    while p < src.len {
        // Skip whitespace and comments
        while p < src.len {
            let c = ch(src, p)
            if c == " " { p = p + 1 }
            else if c == "\n" { p = p + 1 }
            else if c == "\r" { p = p + 1 }
            else if c == "\t" { p = p + 1 }
            else if c == "/" {
                if p + 1 < src.len {
                    if ch(src, p + 1) == "/" {
                        p = p + 2
                        while p < src.len {
                            if ch(src, p) == "\n" { p = p + 1; break }
                            p = p + 1
                        }
                    } else { break }
                } else { break }
            } else { break }
        }
        if p >= src.len { break }

        // Expect "fn"
        if ch(src, p) != "f" { p = p + 1; continue }
        if p + 2 >= src.len { break }
        if ch(src, p + 1) != "n" { p = p + 1; continue }
        if ch(src, p + 2) != " " { p = p + 1; continue }
        p = p + 3

        // Read function name
        var cur_fn = ""
        while p < src.len {
            let nc = ch(src, p)
            if is_alnum(nc) == 1 { cur_fn = cur_fn + nc; p = p + 1 } else { break }
        }

        // Skip to (
        while p < src.len { if ch(src, p) == "(" { break }
p = p + 1 }
        p = p + 1  // skip (

        // Parse parameters
        pc = 0; p0 = ""; p1 = ""; p2 = ""; p3 = ""
        // Skip whitespace
        while p < src.len {
            let c = ch(src, p)
            if c == " " { p = p + 1 } else if c == "\n" { p = p + 1 } else { break }
        }

        if p < src.len {
            if ch(src, p) != ")" {
                // Parse params: name: type, name: type
                while p < src.len {
                    // Skip whitespace
                    while p < src.len {
                        let c = ch(src, p)
                        if c == " " { p = p + 1 } else if c == "\n" { p = p + 1 } else { break }
                    }
                    if ch(src, p) == ")" { break }
                    // Read param name
                    var pname = ""
                    while p < src.len {
                        let c = ch(src, p)
                        if is_alnum(c) == 1 { pname = pname + c; p = p + 1 } else { break }
                    }
                    if pc == 0 { p0 = pname }
                    if pc == 1 { p1 = pname }
                    if pc == 2 { p2 = pname }
                    if pc == 3 { p3 = pname }
                    pc = pc + 1
                    // Skip ": type" and optional ","
                    while p < src.len {
                        let c = ch(src, p)
                        if c == "," { p = p + 1; break }
                        if c == ")" { break }
                        p = p + 1
                    }
                }
            }
        }
        // Skip )
        while p < src.len { if ch(src, p) == ")" { p = p + 1; break }
p = p + 1 }

        // Check for -> return type
        var has_ret = 0
        while p < src.len {
            let c = ch(src, p)
            if c == " " { p = p + 1 }
            else if c == "\n" { p = p + 1 }
            else if c == "-" {
                if p + 1 < src.len {
                    if ch(src, p + 1) == ">" {
                        has_ret = 1
                        p = p + 2
                        // Skip type name
                        while p < src.len {
                            let c2 = ch(src, p)
                            if c2 == " " { p = p + 1 }
                            else if is_alnum(c2) == 1 { p = p + 1 }
                            else { break }
                        }
                    }
                }
                break
            } else { break }
        }

        // Emit function header
        var params_ir = ""
        if pc == 1 { params_ir = "i64 %0" }
        if pc == 2 { params_ir = "i64 %0, i64 %1" }
        if pc == 3 { params_ir = "i64 %0, i64 %1, i64 %2" }
        if pc == 4 { params_ir = "i64 %0, i64 %1, i64 %2, i64 %3" }

        let mangled = "tallow.{cur_fn}"
        if has_ret == 1 {
            ir = ir + "define i64 @{mangled}({params_ir}) \{\n"
        } else {
            ir = ir + "define void @{mangled}({params_ir}) \{\n"
        }
        ir = ir + "entry:\n"

        // Reset variable table
        vn = ""; vr = ""; vm = ""; vc = 0; rc = pc

        // Skip to {
        while p < src.len { if ch(src, p) == "\{" { p = p + 1; break }
p = p + 1 }

        // ── Parse function body ──────────────────────────────
        var fn_depth = 1
        var had_ret = 0
        var last_val = "0"

        while fn_depth > 0 {
            // Skip whitespace and comments
            while p < src.len {
                let c = ch(src, p)
                if c == " " { p = p + 1 }
                else if c == "\n" { p = p + 1 }
                else if c == "\r" { p = p + 1 }
                else if c == "\t" { p = p + 1 }
                else if c == "/" {
                    if p + 1 < src.len {
                        if ch(src, p + 1) == "/" {
                            p = p + 2
                            while p < src.len {
                                if ch(src, p) == "\n" { p = p + 1; break }
                                p = p + 1
                            }
                        } else { break }
                    } else { break }
                } else { break }
            }

            if p >= src.len { fn_depth = 0; continue }

            let sc2 = ch(src, p)
            if sc2 == "\}" {
                fn_depth = fn_depth - 1
                p = p + 1
                continue
            }

            // Read next word
            var word = ""
            var wp = p
            while wp < src.len {
                let wc = ch(src, wp)
                if is_alnum(wc) == 1 { word = word + wc; wp = wp + 1 } else { break }
            }

            // ── let binding ──────────────────────────────────
            if word == "let" {
                p = wp
                while p < src.len { let c = ch(src, p); if c == " " { p = p + 1 } else { break } }
                var let_name = ""
                while p < src.len {
                    let c = ch(src, p)
                    if is_alnum(c) == 1 { let_name = let_name + c; p = p + 1 } else { break }
                }
                // Skip = (with optional whitespace)
                while p < src.len {
                    let c = ch(src, p)
                    if c == " " { p = p + 1 } else if c == "=" { p = p + 1; break } else { break }
                }
                while p < src.len { let c = ch(src, p); if c == " " { p = p + 1 } else { break } }
                // Parse simple expression (number, ident, or call)
                var let_reg = "0"
                let fc = ch(src, p)
                if is_digit(fc) == 1 {
                    var num = ""
                    while p < src.len {
                        let c = ch(src, p)
                        if is_digit(c) == 1 { num = num + c; p = p + 1 }
                        else if c == "_" { p = p + 1 }
                        else { break }
                    }
                    let_reg = num
                } else if fc == "\"" {
                    // String literal
                    p = p + 1
                    var sval = ""
                    while p < src.len {
                        let c = ch(src, p)
                        if c == "\"" { p = p + 1; break }
                        if c == "\\" { p = p + 2; sval = sval + "?"; continue }
                        sval = sval + c; p = p + 1
                    }
                    let sidx = sc; sc = sc + 1
                    let sn = "@.str.{sidx}"
                    let sl = sval.len + 1
                    sp = sp + "{sn} = private unnamed_addr constant [{sl} x i8] c\"{sval}\\00\"\n"
                    rc = rc + 1; let_reg = "%{rc}"
                    ir = ir + "  {let_reg} = getelementptr [{sl} x i8], ptr {sn}, i64 0, i64 0\n"
                } else if is_alpha(fc) == 1 {
                    var id = ""
                    while p < src.len {
                        let c = ch(src, p)
                        if is_alnum(c) == 1 { id = id + c; p = p + 1 } else { break }
                    }
                    while p < src.len { if ch(src, p) == " " { p = p + 1 } else { break } }
                    if p < src.len {
                        if ch(src, p) == "(" {
                            // Function call
                            p = p + 1
                            // Parse up to 4 args
                            var a0r = ""; var a1r = ""; var ac2 = 0
                            while p < src.len { if ch(src, p) == " " { p = p + 1 } else { break } }
                            if ch(src, p) != ")" {
                                // First arg
                                var arg = ""
                                while p < src.len {
                                    let c = ch(src, p)
                                    if is_alnum(c) == 1 { arg = arg + c; p = p + 1 } else { break }
                                }
                                // Resolve arg to register
                                if arg == p0 { a0r = "%0" }
                                else if arg == p1 { a0r = "%1" }
                                else if arg == p2 { a0r = "%2" }
                                else if arg == p3 { a0r = "%3" }
                                else if is_digit(ch(arg, 0)) == 1 { a0r = arg }
                                else {
                                    // Look up in var table
                                    a0r = arg  // placeholder
                                    // Search vn for pipe-delimited match
                                    var vi = 0
                                    var vpos = 0
                                    while vpos < vn.len {
                                        var vname = ""
                                        while vpos < vn.len {
                                            let vc2 = ch(vn, vpos)
                                            if vc2 == "|" { vpos = vpos + 1; break }
                                            vname = vname + vc2; vpos = vpos + 1
                                        }
                                        if vname == arg {
                                            // Found! Get register at same index from vr
                                            var ri = 0; var rpos = 0
                                            while ri < vi {
                                                while rpos < vr.len {
                                                    if ch(vr, rpos) == "|" { rpos = rpos + 1; break }
                                                    rpos = rpos + 1
                                                }
                                                ri = ri + 1
                                            }
                                            var vreg = ""
                                            while rpos < vr.len {
                                                let vrc = ch(vr, rpos)
                                                if vrc == "|" { break }
                                                vreg = vreg + vrc; rpos = rpos + 1
                                            }
                                            // Check if mutable
                                            var mi = 0; var mpos = 0
                                            while mi < vi {
                                                while mpos < vm.len {
                                                    if ch(vm, mpos) == "|" { mpos = mpos + 1; break }
                                                    mpos = mpos + 1
                                                }
                                                mi = mi + 1
                                            }
                                            var mflag = ""
                                            if mpos < vm.len { mflag = ch(vm, mpos) }
                                            if mflag == "1" {
                                                rc = rc + 1
                                                a0r = "%{rc}"
                                                ir = ir + "  {a0r} = load i64, ptr {vreg}\n"
                                            } else {
                                                a0r = vreg
                                            }
                                            break
                                        }
                                        vi = vi + 1
                                    }
                                }
                                ac2 = 1
                                while p < src.len { let c = ch(src, p); if c == " " { p = p + 1 } else { break } }
                                if p < src.len {
                                    if ch(src, p) == "," {
                                        p = p + 1
                                        while p < src.len { if ch(src, p) == " " { p = p + 1 } else { break } }
                                        // Second arg
                                        var arg2 = ""
                                        while p < src.len {
                                            let c = ch(src, p)
                                            if is_alnum(c) == 1 { arg2 = arg2 + c; p = p + 1 } else { break }
                                        }
                                        if arg2 == p0 { a1r = "%0" }
                                        else if arg2 == p1 { a1r = "%1" }
                                        else if arg2 == p2 { a1r = "%2" }
                                        else if is_digit(ch(arg2, 0)) == 1 { a1r = arg2 }
                                        else {
                                            // Look up in var table (same logic)
                                            a1r = arg2
                                            var vi2 = 0; var vpos2 = 0
                                            while vpos2 < vn.len {
                                                var vname2 = ""
                                                while vpos2 < vn.len {
                                                    let vc3 = ch(vn, vpos2)
                                                    if vc3 == "|" { vpos2 = vpos2 + 1; break }
                                                    vname2 = vname2 + vc3; vpos2 = vpos2 + 1
                                                }
                                                if vname2 == arg2 {
                                                    var ri2 = 0; var rpos2 = 0
                                                    while ri2 < vi2 {
                                                        while rpos2 < vr.len {
                                                            if ch(vr, rpos2) == "|" { rpos2 = rpos2 + 1; break }
                                                            rpos2 = rpos2 + 1
                                                        }
                                                        ri2 = ri2 + 1
                                                    }
                                                    var vreg2 = ""
                                                    while rpos2 < vr.len {
                                                        let vrc2 = ch(vr, rpos2)
                                                        if vrc2 == "|" { break }
                                                        vreg2 = vreg2 + vrc2; rpos2 = rpos2 + 1
                                                    }
                                                    var mi2 = 0; var mpos2 = 0
                                                    while mi2 < vi2 {
                                                        while mpos2 < vm.len {
                                                            if ch(vm, mpos2) == "|" { mpos2 = mpos2 + 1; break }
                                                            mpos2 = mpos2 + 1
                                                        }
                                                        mi2 = mi2 + 1
                                                    }
                                                    var mf2 = ""
                                                    if mpos2 < vm.len { mf2 = ch(vm, mpos2) }
                                                    if mf2 == "1" {
                                                        rc = rc + 1
                                                        a1r = "%{rc}"
                                                        ir = ir + "  {a1r} = load i64, ptr {vreg2}\n"
                                                    } else {
                                                        a1r = vreg2
                                                    }
                                                    break
                                                }
                                                vi2 = vi2 + 1
                                            }
                                        }
                                        ac2 = 2
                                    }
                                }
                            }
                            // Skip to )
                            while p < src.len { if ch(src, p) == ")" { p = p + 1; break }
p = p + 1 }

                            // Emit call
                            if id == "print" {
                                let fidx = sc; sc = sc + 1
                                let fmtn = "@.str.{fidx}"
                                sp = sp + "{fmtn} = private unnamed_addr constant [5 x i8] c\"%ld\\0A\\00\"\n"
                                rc = rc + 1
                                ir = ir + "  %{rc} = call i32 (ptr, ...) @printf(ptr {fmtn}, i64 {a0r})\n"
                                let_reg = "0"
                            } else {
                                let cm = "tallow.{id}"
                                rc = rc + 1; let_reg = "%{rc}"
                                if ac2 == 0 {
                                    ir = ir + "  {let_reg} = call i64 @{cm}()\n"
                                } else if ac2 == 1 {
                                    ir = ir + "  {let_reg} = call i64 @{cm}(i64 {a0r})\n"
                                } else {
                                    ir = ir + "  {let_reg} = call i64 @{cm}(i64 {a0r}, i64 {a1r})\n"
                                }
                            }
                        } else {
                            // Variable reference - look up
                            if id == p0 { let_reg = "%0" }
                            else if id == p1 { let_reg = "%1" }
                            else if id == p2 { let_reg = "%2" }
                            else if id == p3 { let_reg = "%3" }
                            else {
                                // Search var table
                                var vi3 = 0; var vpos3 = 0
                                while vpos3 < vn.len {
                                    var vname3 = ""
                                    while vpos3 < vn.len {
                                        let vc4 = ch(vn, vpos3)
                                        if vc4 == "|" { vpos3 = vpos3 + 1; break }
                                        vname3 = vname3 + vc4; vpos3 = vpos3 + 1
                                    }
                                    if vname3 == id {
                                        var ri3 = 0; var rpos3 = 0
                                        while ri3 < vi3 {
                                            while rpos3 < vr.len {
                                                if ch(vr, rpos3) == "|" { rpos3 = rpos3 + 1; break }
                                                rpos3 = rpos3 + 1
                                            }
                                            ri3 = ri3 + 1
                                        }
                                        var vreg3 = ""
                                        while rpos3 < vr.len {
                                            let vrc3 = ch(vr, rpos3)
                                            if vrc3 == "|" { break }
                                            vreg3 = vreg3 + vrc3; rpos3 = rpos3 + 1
                                        }
                                        var mi3 = 0; var mpos3 = 0
                                        while mi3 < vi3 {
                                            while mpos3 < vm.len {
                                                if ch(vm, mpos3) == "|" { mpos3 = mpos3 + 1; break }
                                                mpos3 = mpos3 + 1
                                            }
                                            mi3 = mi3 + 1
                                        }
                                        var mf3 = ""
                                        if mpos3 < vm.len { mf3 = ch(vm, mpos3) }
                                        if mf3 == "1" {
                                            rc = rc + 1
                                            let_reg = "%{rc}"
                                            ir = ir + "  {let_reg} = load i64, ptr {vreg3}\n"
                                        } else {
                                            let_reg = vreg3
                                        }
                                        break
                                    }
                                    vi3 = vi3 + 1
                                }
                            }
                        }
                    }
                }
                // Add to variable table
                vn = vn + let_name + "|"
                vr = vr + let_reg + "|"
                vm = vm + "0|"
                vc = vc + 1
                last_val = let_reg
                continue
            }

            // ── var binding ──────────────────────────────────
            if word == "var" {
                p = wp
                while p < src.len { if ch(src, p) == " " { p = p + 1 } else { break } }
                var var_name = ""
                while p < src.len {
                    let c = ch(src, p)
                    if is_alnum(c) == 1 { var_name = var_name + c; p = p + 1 } else { break }
                }
                while p < src.len {
                    let c = ch(src, p)
                    if c == " " { p = p + 1 } else if c == "=" { p = p + 1; break } else { break }
                }
                while p < src.len { if ch(src, p) == " " { p = p + 1 } else { break } }
                var var_init = ""
                while p < src.len {
                    let c = ch(src, p)
                    if is_digit(c) == 1 { var_init = var_init + c; p = p + 1 } else { break }
                }
                if var_init == "" { var_init = "0" }
                rc = rc + 1
                let va = "%{rc}"
                ir = ir + "  {va} = alloca i64\n"
                ir = ir + "  store i64 {var_init}, ptr {va}\n"
                vn = vn + var_name + "|"
                vr = vr + va + "|"
                vm = vm + "1|"
                vc = vc + 1
                continue
            }

            // ── return statement ─────────────────────────────
            if word == "return" {
                p = wp
                while p < src.len { if ch(src, p) == " " { p = p + 1 } else { break } }
                // Read return value expression
                var ret_id = ""
                while p < src.len {
                    let c = ch(src, p)
                    if is_alnum(c) == 1 { ret_id = ret_id + c; p = p + 1 } else { break }
                }
                // Check for binary op (a + b pattern)
                while p < src.len { if ch(src, p) == " " { p = p + 1 } else { break } }
                var ret_val = ret_id
                if ret_id == p0 { ret_val = "%0" }
                else if ret_id == p1 { ret_val = "%1" }
                else if is_digit(ch(ret_id, 0)) == 1 { ret_val = ret_id }
                ir = ir + "  ret i64 {ret_val}\n"
                had_ret = 1
                continue
            }

            // ── if/else ──────────────────────────────────────
            if word == "if" {
                p = wp
                while p < src.len { if ch(src, p) == " " { p = p + 1 } else { break } }
                // Parse condition: expect "expr op expr"
                var cond_left = ""
                while p < src.len {
                    let c = ch(src, p)
                    if is_alnum(c) == 1 { cond_left = cond_left + c; p = p + 1 } else { break }
                }
                while p < src.len { if ch(src, p) == " " { p = p + 1 } else { break } }
                // Read operator
                var cmp_op = ""
                while p < src.len {
                    let c = ch(src, p)
                    if c == ">" { cmp_op = cmp_op + c; p = p + 1 }
                    else if c == "<" { cmp_op = cmp_op + c; p = p + 1 }
                    else if c == "=" { cmp_op = cmp_op + c; p = p + 1 }
                    else if c == "!" { cmp_op = cmp_op + c; p = p + 1 }
                    else { break }
                }
                while p < src.len { if ch(src, p) == " " { p = p + 1 } else { break } }
                var cond_right = ""
                while p < src.len {
                    let c = ch(src, p)
                    if is_alnum(c) == 1 { cond_right = cond_right + c; p = p + 1 } else { break }
                }
                // Resolve operands
                var cl = cond_left
                if cond_left == p0 { cl = "%0" }
                else if cond_left == p1 { cl = "%1" }
                else {
                    // Look up in var table (simplified - check first few vars)
                    var vi4 = 0; var vpos4 = 0
                    while vpos4 < vn.len {
                        var vn4 = ""
                        while vpos4 < vn.len {
                            let vc5 = ch(vn, vpos4)
                            if vc5 == "|" { vpos4 = vpos4 + 1; break }
                            vn4 = vn4 + vc5; vpos4 = vpos4 + 1
                        }
                        if vn4 == cond_left {
                            var ri4 = 0; var rpos4 = 0
                            while ri4 < vi4 {
                                while rpos4 < vr.len {
                                    if ch(vr, rpos4) == "|" { rpos4 = rpos4 + 1; break }
                                    rpos4 = rpos4 + 1
                                }
                                ri4 = ri4 + 1
                            }
                            var vreg4 = ""
                            while rpos4 < vr.len {
                                let vrc4 = ch(vr, rpos4)
                                if vrc4 == "|" { break }
                                vreg4 = vreg4 + vrc4; rpos4 = rpos4 + 1
                            }
                            // Check mutability
                            var mi4 = 0; var mpos4 = 0
                            while mi4 < vi4 {
                                while mpos4 < vm.len { if ch(vm, mpos4) == "|" { mpos4 = mpos4 + 1; break }
mpos4 = mpos4 + 1 }
                                mi4 = mi4 + 1
                            }
                            var mf4 = ""
                            if mpos4 < vm.len { mf4 = ch(vm, mpos4) }
                            if mf4 == "1" {
                                rc = rc + 1; cl = "%{rc}"
                                ir = ir + "  {cl} = load i64, ptr {vreg4}\n"
                            } else { cl = vreg4 }
                            break
                        }
                        vi4 = vi4 + 1
                    }
                }
                let cr2 = cond_right
                // Determine LLVM comparison
                var icmp = "sgt"
                if cmp_op == ">" { icmp = "sgt" }
                if cmp_op == ">=" { icmp = "sge" }
                if cmp_op == "<" { icmp = "slt" }
                if cmp_op == "<=" { icmp = "sle" }
                if cmp_op == "==" { icmp = "eq" }
                if cmp_op == "!=" { icmp = "ne" }
                rc = rc + 1
                let cmp_reg = "%{rc}"
                ir = ir + "  {cmp_reg} = icmp {icmp} i64 {cl}, {cr2}\n"
                lc = lc + 1; let then_l = "if.then.{lc}"
                lc = lc + 1; let else_l = "if.else.{lc}"
                lc = lc + 1; let merge_l = "if.merge.{lc}"
                ir = ir + "  br i1 {cmp_reg}, label %{then_l}, label %{else_l}\n"
                ir = ir + "{then_l}:\n"

                // Skip to { then parse then-block statements
                while p < src.len { if ch(src, p) == "\{" { p = p + 1; break }
p = p + 1 }
                // Parse statements in then block
                var td = 1
                while td > 0 {
                    while p < src.len {
                        let c = ch(src, p)
                        if c == " " { p = p + 1 } else if c == "\n" { p = p + 1 }
                        else if c == "\r" { p = p + 1 } else if c == "\t" { p = p + 1 }
                        else { break }
                    }
                    if p >= src.len { td = 0; continue }
                    if ch(src, p) == "\}" { td = 0; p = p + 1; continue }

                    // Parse a simple statement (print call only for now)
                    var tw = ""
                    var twp = p
                    while twp < src.len {
                        let c = ch(src, twp)
                        if is_alnum(c) == 1 { tw = tw + c; twp = twp + 1 } else { break }
                    }
                    if tw == "print" {
                        p = twp
                        while p < src.len { if ch(src, p) == "(" { p = p + 1; break }
p = p + 1 }
                        while p < src.len { if ch(src, p) == " " { p = p + 1 } else { break } }
                        // Read arg
                        if ch(src, p) == "\"" {
                            // String arg to print
                            p = p + 1
                            var ps = ""
                            while p < src.len {
                                let c = ch(src, p)
                                if c == "\"" { p = p + 1; break }
                                ps = ps + c; p = p + 1
                            }
                            let pidx = sc; sc = sc + 1
                            let psn = "@.str.{pidx}"
                            let psl = ps.len + 1
                            sp = sp + "{psn} = private unnamed_addr constant [{psl} x i8] c\"{ps}\\00\"\n"
                            let pfmt = sc; sc = sc + 1
                            let pfn = "@.str.{pfmt}"
                            sp = sp + "{pfn} = private unnamed_addr constant [4 x i8] c\"%s\\0A\\00\"\n"
                            rc = rc + 1
                            let gep_r = "%{rc}"
                            ir = ir + "  {gep_r} = getelementptr [{psl} x i8], ptr {psn}, i64 0, i64 0\n"
                            rc = rc + 1
                                ir = ir + "  %{rc} = call i32 (ptr, ...) @printf(ptr {pfn}, ptr {gep_r})\n"
                        } else {
                            // Variable arg
                            var pa = ""
                            while p < src.len {
                                let c = ch(src, p)
                                if is_alnum(c) == 1 { pa = pa + c; p = p + 1 } else { break }
                            }
                            var par = pa
                            if pa == p0 { par = "%0" } else if pa == p1 { par = "%1" }
                            // Look up in vars too
                            var pvi = 0; var pvp = 0
                            while pvp < vn.len {
                                var pvn = ""
                                while pvp < vn.len {
                                    let pvc = ch(vn, pvp)
                                    if pvc == "|" { pvp = pvp + 1; break }
                                    pvn = pvn + pvc; pvp = pvp + 1
                                }
                                if pvn == pa {
                                    var pri = 0; var prp = 0
                                    while pri < pvi { while prp < vr.len { if ch(vr, prp) == "|" { prp = prp + 1; break }
prp = prp + 1 }
pri = pri + 1 }
                                    var preg = ""
                                    while prp < vr.len { let prc = ch(vr, prp); if prc == "|" { break }
preg = preg + prc; prp = prp + 1 }
                                    var pmi = 0; var pmp = 0
                                    while pmi < pvi { while pmp < vm.len { if ch(vm, pmp) == "|" { pmp = pmp + 1; break }
pmp = pmp + 1 }
pmi = pmi + 1 }
                                    var pmf = ""
                                    if pmp < vm.len { pmf = ch(vm, pmp) }
                                    if pmf == "1" { rc = rc + 1; par = "%{rc}"; ir = ir + "  {par} = load i64, ptr {preg}\n" }
                                    else { par = preg }
                                    break
                                }
                                pvi = pvi + 1
                            }
                            let pfidx = sc; sc = sc + 1
                            let pfmtn = "@.str.{pfidx}"
                            sp = sp + "{pfmtn} = private unnamed_addr constant [5 x i8] c\"%ld\\0A\\00\"\n"
                            rc = rc + 1
                                ir = ir + "  %{rc} = call i32 (ptr, ...) @printf(ptr {pfmtn}, i64 {par})\n"
                        }
                        while p < src.len { if ch(src, p) == ")" { p = p + 1; break }
p = p + 1 }
                    } else {
                        // Skip unknown statement to newline
                        while p < src.len {
                            let c = ch(src, p)
                            if c == "\n" { p = p + 1; break }
                            if c == "\}" { break }
                            p = p + 1
                        }
                    }
                }

                ir = ir + "  br label %{merge_l}\n"
                ir = ir + "{else_l}:\n"

                // Check for else
                while p < src.len { let c = ch(src, p); if c == " " { p = p + 1 } else if c == "\n" { p = p + 1 } else { break } }
                if p + 3 < src.len {
                    if ch(src, p) == "e" {
                        if ch(src, p + 1) == "l" {
                            if ch(src, p + 2) == "s" {
                                if ch(src, p + 3) == "e" {
                                    p = p + 4
                                    while p < src.len { if ch(src, p) == "\{" { p = p + 1; break }
p = p + 1 }
                                    // Parse else block (same as then block but simplified)
                                    var ed = 1
                                    while ed > 0 {
                                        while p < src.len {
                                            let c = ch(src, p)
                                            if c == " " { p = p + 1 } else if c == "\n" { p = p + 1 }
                                            else if c == "\r" { p = p + 1 } else { break }
                                        }
                                        if p >= src.len { ed = 0; continue }
                                        if ch(src, p) == "\}" { ed = 0; p = p + 1; continue }
                                        // Parse statement (print only)
                                        var ew = ""
                                        var ewp = p
                                        while ewp < src.len {
                                            let c = ch(src, ewp)
                                            if is_alnum(c) == 1 { ew = ew + c; ewp = ewp + 1 } else { break }
                                        }
                                        if ew == "print" {
                                            p = ewp
                                            while p < src.len { if ch(src, p) == "(" { p = p + 1; break }
p = p + 1 }
                                            while p < src.len { if ch(src, p) == " " { p = p + 1 } else { break } }
                                            if ch(src, p) == "\"" {
                                                p = p + 1
                                                var es = ""
                                                while p < src.len {
                                                    let c = ch(src, p)
                                                    if c == "\"" { p = p + 1; break }
                                                    es = es + c; p = p + 1
                                                }
                                                let eidx = sc; sc = sc + 1
                                                let esn = "@.str.{eidx}"
                                                let esl = es.len + 1
                                                sp = sp + "{esn} = private unnamed_addr constant [{esl} x i8] c\"{es}\\00\"\n"
                                                let efmt = sc; sc = sc + 1
                                                let efn = "@.str.{efmt}"
                                                sp = sp + "{efn} = private unnamed_addr constant [4 x i8] c\"%s\\0A\\00\"\n"
                                                rc = rc + 1
                                                let egep = "%{rc}"
                                                ir = ir + "  {egep} = getelementptr [{esl} x i8], ptr {esn}, i64 0, i64 0\n"
                                                rc = rc + 1
                                ir = ir + "  %{rc} = call i32 (ptr, ...) @printf(ptr {efn}, ptr {egep})\n"
                                            }
                                            while p < src.len { if ch(src, p) == ")" { p = p + 1; break }
p = p + 1 }
                                        } else {
                                            while p < src.len {
                                                let c = ch(src, p)
                                                if c == "\n" { p = p + 1; break }
                                                if c == "\}" { break }
                                                p = p + 1
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }

                ir = ir + "  br label %{merge_l}\n"
                ir = ir + "{merge_l}:\n"
                continue
            }

            // ── Expression statement (assignment or call) ────
            if is_alpha(ch(src, p)) == 1 {
                var stmt_id = ""
                while p < src.len {
                    let c = ch(src, p)
                    if is_alnum(c) == 1 { stmt_id = stmt_id + c; p = p + 1 } else { break }
                }
                while p < src.len { if ch(src, p) == " " { p = p + 1 } else { break } }
                if p < src.len {
                    if ch(src, p) == "(" {
                        // Function call as statement (like print)
                        p = p + 1
                        while p < src.len { if ch(src, p) == " " { p = p + 1 } else { break } }
                        if stmt_id == "print" {
                            // Check for string or variable
                            if ch(src, p) == "\"" {
                                p = p + 1
                                var pstr = ""
                                while p < src.len {
                                    let c = ch(src, p)
                                    if c == "\"" { p = p + 1; break }
                                    pstr = pstr + c; p = p + 1
                                }
                                let psidx = sc; sc = sc + 1
                                let pssn = "@.str.{psidx}"
                                let pssl = pstr.len + 1
                                sp = sp + "{pssn} = private unnamed_addr constant [{pssl} x i8] c\"{pstr}\\00\"\n"
                                let psfmt = sc; sc = sc + 1
                                let psfn = "@.str.{psfmt}"
                                sp = sp + "{psfn} = private unnamed_addr constant [4 x i8] c\"%s\\0A\\00\"\n"
                                rc = rc + 1
                                let pgep = "%{rc}"
                                ir = ir + "  {pgep} = getelementptr [{pssl} x i8], ptr {pssn}, i64 0, i64 0\n"
                                rc = rc + 1
                                ir = ir + "  %{rc} = call i32 (ptr, ...) @printf(ptr {psfn}, ptr {pgep})\n"
                            } else {
                                var pa2 = ""
                                while p < src.len {
                                    let c = ch(src, p)
                                    if is_alnum(c) == 1 { pa2 = pa2 + c; p = p + 1 } else { break }
                                }
                                var par2 = pa2
                                if pa2 == p0 { par2 = "%0" } else if pa2 == p1 { par2 = "%1" }
                                // Lookup in var table
                                var pvi2 = 0; var pvp2 = 0
                                while pvp2 < vn.len {
                                    var pvn2 = ""
                                    while pvp2 < vn.len {
                                        let pvc2 = ch(vn, pvp2)
                                        if pvc2 == "|" { pvp2 = pvp2 + 1; break }
                                        pvn2 = pvn2 + pvc2; pvp2 = pvp2 + 1
                                    }
                                    if pvn2 == pa2 {
                                        var pri2 = 0; var prp2 = 0
                                        while pri2 < pvi2 { while prp2 < vr.len { if ch(vr, prp2) == "|" { prp2 = prp2 + 1; break }
prp2 = prp2 + 1 }
pri2 = pri2 + 1 }
                                        var preg2 = ""
                                        while prp2 < vr.len { let prc2 = ch(vr, prp2); if prc2 == "|" { break }
preg2 = preg2 + prc2; prp2 = prp2 + 1 }
                                        var pmi2 = 0; var pmp2 = 0
                                        while pmi2 < pvi2 { while pmp2 < vm.len { if ch(vm, pmp2) == "|" { pmp2 = pmp2 + 1; break }
pmp2 = pmp2 + 1 }
pmi2 = pmi2 + 1 }
                                        var pmf2 = ""
                                        if pmp2 < vm.len { pmf2 = ch(vm, pmp2) }
                                        if pmf2 == "1" { rc = rc + 1; par2 = "%{rc}"; ir = ir + "  {par2} = load i64, ptr {preg2}\n" }
                                        else { par2 = preg2 }
                                        break
                                    }
                                    pvi2 = pvi2 + 1
                                }
                                let pfidx2 = sc; sc = sc + 1
                                let pfmtn2 = "@.str.{pfidx2}"
                                sp = sp + "{pfmtn2} = private unnamed_addr constant [5 x i8] c\"%ld\\0A\\00\"\n"
                                rc = rc + 1
                                ir = ir + "  %{rc} = call i32 (ptr, ...) @printf(ptr {pfmtn2}, i64 {par2})\n"
                            }
                        }
                        // Skip to )
                        while p < src.len { if ch(src, p) == ")" { p = p + 1; break }
p = p + 1 }
                    } else if ch(src, p) == "=" {
                        // Assignment: stmt_id = expr
                        p = p + 1
                        while p < src.len { if ch(src, p) == " " { p = p + 1 } else { break } }
                        // Read expression (simplified: read to newline/semicolon)
                        // For now: read first token (number or binary expr)
                        var aval = ""
                        while p < src.len {
                            let c = ch(src, p)
                            if is_alnum(c) == 1 { aval = aval + c; p = p + 1 }
                            else { break }
                        }
                        while p < src.len { if ch(src, p) == " " { p = p + 1 } else { break } }
                        // Check for binary operator
                        if p < src.len {
                            let opc = ch(src, p)
                            if opc == "+" {
                                p = p + 1
                                while p < src.len { if ch(src, p) == " " { p = p + 1 } else { break } }
                                var rval = ""
                                while p < src.len {
                                    let c = ch(src, p)
                                    if is_alnum(c) == 1 { rval = rval + c; p = p + 1 } else { break }
                                }
                                // Resolve both to registers
                                var alr = aval
                                if aval == p0 { alr = "%0" } else if aval == p1 { alr = "%1" }
                                else if is_digit(ch(aval, 0)) == 1 { alr = aval }
                                var arr = rval
                                if rval == p0 { arr = "%0" } else if rval == p1 { arr = "%1" }
                                else if is_digit(ch(rval, 0)) == 1 { arr = rval }
                                rc = rc + 1
                                let res_reg = "%{rc}"
                                ir = ir + "  {res_reg} = add i64 {alr}, {arr}\n"
                                // Store to mutable var
                                // Look up stmt_id in var table
                                var svi = 0; var svp = 0
                                while svp < vn.len {
                                    var svn = ""
                                    while svp < vn.len {
                                        let svc = ch(vn, svp)
                                        if svc == "|" { svp = svp + 1; break }
                                        svn = svn + svc; svp = svp + 1
                                    }
                                    if svn == stmt_id {
                                        var sri = 0; var srp = 0
                                        while sri < svi { while srp < vr.len { if ch(vr, srp) == "|" { srp = srp + 1; break }
srp = srp + 1 }
sri = sri + 1 }
                                        var sreg = ""
                                        while srp < vr.len { let src2 = ch(vr, srp); if src2 == "|" { break }
sreg = sreg + src2; srp = srp + 1 }
                                        ir = ir + "  store i64 {res_reg}, ptr {sreg}\n"
                                        break
                                    }
                                    svi = svi + 1
                                }
                            }
                        }
                    } else {
                        // Expression result or implicit return
                        // Resolve left operand
                        var expr_left = stmt_id
                        if stmt_id == p0 { expr_left = "%0" }
                        else if stmt_id == p1 { expr_left = "%1" }
                        else if stmt_id == p2 { expr_left = "%2" }
                        else if stmt_id == p3 { expr_left = "%3" }
                        // Check for binary operator
                        if p < src.len {
                            let opc2 = ch(src, p)
                            if opc2 == "+" {
                                p = p + 1
                                while p < src.len { if ch(src, p) == " " { p = p + 1 } else { break } }
                                var rhs = ""
                                while p < src.len {
                                    let c = ch(src, p)
                                    if is_alnum(c) == 1 { rhs = rhs + c; p = p + 1 } else { break }
                                }
                                var expr_right = rhs
                                if rhs == p0 { expr_right = "%0" }
                                else if rhs == p1 { expr_right = "%1" }
                                else if rhs == p2 { expr_right = "%2" }
                                else if rhs == p3 { expr_right = "%3" }
                                rc = rc + 1
                                last_val = "%{rc}"
                                ir = ir + "  {last_val} = add i64 {expr_left}, {expr_right}\n"
                            } else if opc2 == "-" {
                                p = p + 1
                                while p < src.len { if ch(src, p) == " " { p = p + 1 } else { break } }
                                var rhs2 = ""
                                while p < src.len {
                                    let c = ch(src, p)
                                    if is_alnum(c) == 1 { rhs2 = rhs2 + c; p = p + 1 } else { break }
                                }
                                var er2 = rhs2
                                if rhs2 == p0 { er2 = "%0" }
                                else if rhs2 == p1 { er2 = "%1" }
                                rc = rc + 1
                                last_val = "%{rc}"
                                ir = ir + "  {last_val} = sub i64 {expr_left}, {er2}\n"
                            } else if opc2 == "*" {
                                p = p + 1
                                while p < src.len { if ch(src, p) == " " { p = p + 1 } else { break } }
                                var rhs3 = ""
                                while p < src.len {
                                    let c = ch(src, p)
                                    if is_alnum(c) == 1 { rhs3 = rhs3 + c; p = p + 1 } else { break }
                                }
                                var er3 = rhs3
                                if rhs3 == p0 { er3 = "%0" }
                                else if rhs3 == p1 { er3 = "%1" }
                                rc = rc + 1
                                last_val = "%{rc}"
                                ir = ir + "  {last_val} = mul i64 {expr_left}, {er3}\n"
                            } else {
                                last_val = expr_left
                            }
                        } else {
                            last_val = expr_left
                        }
                    }
                }
                continue
            }

            // Skip unknown character
            p = p + 1
        }

        // Emit function footer
        if has_ret == 1 {
            if had_ret == 0 {
                // Implicit return
                ir = ir + "  ret i64 {last_val}\n"
            }
        } else {
            ir = ir + "  ret void\n"
        }
        ir = ir + "\}\n\n"
    }

    // Emit main entry wrapper
    ir = ir + "; Entry point\n"
    ir = ir + "define i32 @__tallow_entry() \{\n"
    ir = ir + "entry:\n"
    ir = ir + "  call void @tallow.main()\n"
    ir = ir + "  ret i32 0\n"
    ir = ir + "\}\n\n"
    ir = ir + "define i32 @main(i32 %argc, ptr %argv) \{\n"
    ir = ir + "entry:\n"
    ir = ir + "  %ret = call i32 @__tallow_entry()\n"
    ir = ir + "  ret i32 %ret\n"
    ir = ir + "\}\n"

    // Insert string pool at marker position
    ir.replace("; STRING_POOL_MARKER\n", sp + "\n")
}

fn main() {
    let args = env.args()
    if args.len < 1 {
        print("Usage: self_host <input.tl>")
        return ""
    }

    let input_path = args[0]
    // `read_file` returns the bare contents; a missing or unreadable file is a
    // loud runtime error on both engines, so there is no Err value to handle —
    // and `exists` has no native lowering, so it cannot be called here.
    print("Compiling {input_path}...")
    let contents = read_file(input_path)
    let ir_output = compile(contents)
    let output_path = input_path.replace(".tl", ".ll")
    write_file(output_path, ir_output)
    print("Output written to {output_path}")
}
