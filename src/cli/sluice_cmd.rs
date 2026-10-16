//! `tallow sluice` — decide a cross-domain release plan against the boundary gate.
//!
//! The gate itself (`crate::sluice`) is pure: it opens no sockets, executes
//! nothing, and handles no credentials. This module is the read-only surface
//! over it — it reads a plan, asks the gate, and reports the verdict.
//!
//! # Scope, deliberately
//!
//! Read-only: `check`, `channels`, `explain`, `verify`. None of them writes.
//!
//! `release` is the one subcommand that writes, and it writes exactly two
//! things: the derivative under `--out`, and — only when `--kt-log` is given —
//! one receipt entry appended to that log. Operator decisions E1/E2/E3
//! (`artifacts/sluice-cross-domain-gate-2026-10-07/AGENT-INSTRUCTIONS.md`) are
//! recorded, and the caveat gate on the live release path is behind an opt-in
//! flag (`TALLOW_CAVEAT_GATE=enforce`) so nothing changes until it is asked
//! for.
//!
//! `verify` recomputes from disk: the receipt chain is re-parsed and re-checked, and given
//! re-verified by `KtLog::open`, the payload is recomputed from the plan, and a
//! derivative's sha256 is recomputed from the file (R-CLI-8).
//!
//! # Exit contract
//!
//! The tree's CLI uses only `{0, 1}`. `0` = ALLOW, `1` = DENY or a usage/IO
//! failure. The *meaning* is always in the verdict's `code`, never in the exit
//! number — so automation reads `code` and humans read the exit status.

use std::io::{IsTerminal, Read};
use std::path::{Path, PathBuf};

use crate::sluice::{
    ClockSource, DraftError, Released, Stage, TransferChannel, Verdict, Verified, check_json,
    parse_plan, release, verify,
};

const USAGE: &str = "\
tallow sluice <command>

  check    --plan <FILE|-> [--json]   decide a plan; exit 0 ALLOW / 1 DENY
  channels                            list the channel archetypes and their obligations
  explain  --plan <FILE|->            decide, with the stage trace on stderr
  release  --plan <FILE> --out <DIR> [--kt-log <FILE>] [--now-ms <N>] [--json]
                                      gate, re-hash the artifact FROM DISK, append the
                                      receipt, then write the derivative; one writer at
                                      a time per --kt-log (an exclusive lock, released
                                      on exit), and a wait past 10 s refuses instead of
                                      chaining onto a head another writer may have moved
  verify   --kt-log <FILE> [--plan <FILE>] [--derivative <FILE>] [--expect-tip <HASH>]
           [--segment-close <PAYLOAD|@FILE>] [--json]
                                      re-read from disk and recompute; with --expect-tip, also
                                      compare the recomputed head to an anchor held OUTSIDE the
                                      log — the only way a lost tail is detectable
                                      with --segment-close, also check a closing entry
                                      against the payload the record kept — the log stores
                                      only that payload's HASH, so the record is required
                                      input to verification, not an audit trail.
                                      with --plan, also require the plan's `continues` and
                                      the record's `prev_segment_close` to agree, so a
                                      segment the record calls a continuation while nothing
                                      else corroborates it is refused (A3 section 8)
  rotate   --kt-log <FILE> --expect-tip <HASH> --segment <N> [--prev-segment-close <HASH>]
           [--reason <TEXT>] [--json]
                                      close a segment: append the closing entry, then print
                                      the payload the record must keep VERBATIM. --expect-tip
                                      is required and must match the current head — a second
                                      rotate naming a stale head refuses, because nothing in
                                      the file tells a closed segment from an open one

Exit status is 0 for ALLOW and 1 for DENY or an error; the reason is always in
the verdict's `code`. `check`, `channels`, `explain` and `verify` never write.
`release` writes exactly two things: the derivative under --out, and one receipt
entry in --kt-log when one is given. `rotate` appends one entry — the segment's closing
one — and prints the payload to keep. `tallow version` (the top-level verb, not a `sluice` subcommand) prints the revision this
binary was
built from. An infrastructure failure (an unreadable
artifact, an unwritable directory) exits 1 with NO code, so automation cannot
mistake it for a boundary refusal.

Rendering: JSON when --json is given *or* when stdout is not a tty, so a piped
or redirected decision is machine-readable by default. The human table appears
only on a terminal.";

/// Entry point. `args` is everything after `sluice`; the return value is the
/// process exit status.
pub fn run_sluice_args(args: &[String]) -> i32 {
    match args.first().map(String::as_str) {
        Some("channels") => {
            print_channels();
            0
        }
        Some("check") => run_plan_command(&args[1..], false),
        Some("explain") => run_plan_command(&args[1..], true),
        Some("release") => run_release(&args[1..]),
        Some("verify") => run_verify(&args[1..]),
        Some("rotate") => run_rotate(&args[1..]),
        Some("--help") | Some("-h") | Some("help") | None => {
            println!("{USAGE}");
            0
        }
        Some(other) => {
            eprintln!("sluice: unknown command {other:?}\n\n{USAGE}");
            1
        }
    }
}

/// `check` and `explain` share everything except whether the stage trace is
/// printed, so they share one implementation.
fn run_plan_command(rest: &[String], trace: bool) -> i32 {
    let mut plan_arg: Option<String> = None;
    let mut as_json = false;
    let mut i = 0;
    while i < rest.len() {
        match rest[i].as_str() {
            "--plan" => {
                i += 1;
                match rest.get(i) {
                    Some(v) => plan_arg = Some(v.clone()),
                    None => {
                        eprintln!("sluice: --plan needs a value (a path, or - for stdin)");
                        return 1;
                    }
                }
            }
            "--json" => as_json = true,
            other => {
                eprintln!("sluice: unknown argument {other:?}\n\n{USAGE}");
                return 1;
            }
        }
        i += 1;
    }

    let Some(src) = plan_arg else {
        eprintln!("sluice: --plan <FILE|-> is required\n\n{USAGE}");
        return 1;
    };

    let text = match read_source(&src) {
        Ok(t) => t,
        Err(e) => {
            eprintln!("sluice: {e}");
            return 1;
        }
    };

    let verdict = check_json(&text);
    if trace {
        print_trace(&verdict);
    }
    // R-CLI-7: `--json` forces JSON, and a non-tty stdout defaults to JSON, so
    // a piped decision is machine-readable without asking. Piping never changes
    // the decision — only the rendering.
    render_verdict(&verdict, as_json);

    if verdict.is_allow() { 0 } else { 1 }
}

/// R-CLI-7: `--json` forces JSON, and a non-tty stdout defaults to JSON, so a
/// piped decision is machine-readable without asking. Piping never changes the
/// decision — only the rendering.
fn render_verdict(v: &Verdict, as_json: bool) {
    if as_json || !std::io::stdout().is_terminal() {
        match serde_json::to_string_pretty(v) {
            Ok(s) => println!("{s}"),
            Err(e) => eprintln!("sluice: cannot encode the verdict: {e}"),
        }
    } else {
        print_human(v);
    }
}

/// `-` reads stdin so a plan can be piped; anything else is a path. The gate
/// never creates a file, so a missing plan is an error, not an empty default.
fn read_source(src: &str) -> Result<String, String> {
    if src == "-" {
        let mut buf = String::new();
        std::io::stdin()
            .read_to_string(&mut buf)
            .map_err(|e| format!("cannot read the plan from stdin: {e}"))?;
        Ok(buf)
    } else {
        std::fs::read_to_string(src).map_err(|e| format!("cannot read plan '{src}': {e}"))
    }
}

fn print_human(v: &Verdict) {
    if v.is_allow() {
        println!("{}  marking={}", v.decision.as_str(), v.marking);
        println!("  {}", v.detail);
        if let Some(h) = &v.receipt_hash {
            println!("  receipt {h}");
        }
    } else {
        println!(
            "{}  {}  [{}]",
            v.decision.as_str(),
            v.code,
            v.stage.as_str()
        );
        println!("  {}", v.detail);
    }
}

/// The stage trace. `gate` short-circuits on the first refusal, so every stage
/// with a lower index than the deciding one necessarily **passed** — no extra
/// bookkeeping in the gate is needed to report that honestly.
fn print_trace(v: &Verdict) {
    let decided = v.stage.index();
    eprintln!("sluice: stage trace");
    for st in Stage::ORDER {
        let i = st.index();
        let (mark, note) = if i < decided {
            ("PASS", String::new())
        } else if i == decided {
            (v.decision.as_str(), format!("  {} — {}", v.code, v.detail))
        } else {
            ("—", "  not reached".to_string())
        };
        eprintln!("  {:<12} {:<5} {}{}", st.as_str(), mark, st.label(), note);
    }
}

fn print_channels() {
    let head = [
        "channel",
        "one-way",
        "inspected",
        "retention",
        "bulk",
        "requires",
        "research class",
    ];
    let rows: Vec<[String; 7]> = TransferChannel::ALL
        .iter()
        .map(|c| {
            [
                c.as_str().to_string(),
                yn(c.one_way()),
                yn(c.inspected()),
                c.retention().to_string(),
                yn(c.bulk_ok()),
                if c.requires().is_empty() {
                    "-".to_string()
                } else {
                    c.requires().join(", ")
                },
                c.source().to_string(),
            ]
        })
        .collect();

    let mut w: Vec<usize> = head.iter().map(|h| h.len()).collect();
    for r in &rows {
        for (i, cell) in r.iter().enumerate() {
            w[i] = w[i].max(cell.len());
        }
    }
    let line = |cells: &[String]| {
        cells
            .iter()
            .enumerate()
            .map(|(i, c)| format!("{c:<width$}", width = w[i]))
            .collect::<Vec<_>>()
            .join("  ")
    };

    println!(
        "{}",
        line(&head.iter().map(|h| h.to_string()).collect::<Vec<_>>())
    );
    println!(
        "{}",
        w.iter()
            .map(|x| "-".repeat(*x))
            .collect::<Vec<_>>()
            .join("  ")
    );
    for r in &rows {
        println!("{}", line(r));
    }

    println!();
    println!(
        "A non-bulk channel refuses any payload over {} bits (overridable per plan \
         with payload_cap_bits).",
        crate::sluice::DEFAULT_PAYLOAD_CAP_BITS
    );
}

fn yn(b: bool) -> String {
    if b { "yes".into() } else { "no".into() }
}

/// `release` is the only subcommand that writes anything.
fn run_release(rest: &[String]) -> i32 {
    let (mut plan_arg, mut out_arg, mut log_arg) = (None, None, None);
    let (mut now_ms, mut as_json) = (None, false);
    let mut i = 0;
    while i < rest.len() {
        match rest[i].as_str() {
            "--plan" => match rest.get(i + 1) {
                Some(v) => {
                    plan_arg = Some(v.clone());
                    i += 1;
                }
                None => {
                    eprintln!("sluice: --plan needs a value");
                    return 1;
                }
            },
            "--out" => match rest.get(i + 1) {
                Some(v) => {
                    out_arg = Some(v.clone());
                    i += 1;
                }
                None => {
                    eprintln!("sluice: --out needs a value (a directory)");
                    return 1;
                }
            },
            "--kt-log" => match rest.get(i + 1) {
                Some(v) => {
                    log_arg = Some(v.clone());
                    i += 1;
                }
                None => {
                    eprintln!("sluice: --kt-log needs a value (a file)");
                    return 1;
                }
            },
            "--now-ms" => match rest.get(i + 1).and_then(|v| v.parse::<u64>().ok()) {
                Some(v) => {
                    now_ms = Some(v);
                    i += 1;
                }
                None => {
                    eprintln!("sluice: --now-ms needs a non-negative integer");
                    return 1;
                }
            },
            "--json" => as_json = true,
            other => {
                eprintln!("sluice: unknown argument {other:?}\n\n{USAGE}");
                return 1;
            }
        }
        i += 1;
    }

    let (Some(src), Some(out)) = (plan_arg, out_arg) else {
        eprintln!("sluice: --plan <FILE> and --out <DIR> are required\n\n{USAGE}");
        return 1;
    };
    if src == "-" {
        // Not a limitation to work around: the release re-reads the artifact and
        // the receipt is bound to the bytes on disk, so stdin has no meaning here.
        eprintln!(
            "sluice: --plan - is not accepted for release; composing needs a path to re-read"
        );
        return 1;
    }

    let text = match read_source(&src) {
        Ok(t) => t,
        Err(e) => {
            eprintln!("sluice: {e}");
            return 1;
        }
    };
    let plan = match parse_plan(&text) {
        Ok(p) => p,
        Err(v) => {
            render_verdict(&v, as_json);
            return 1;
        }
    };

    match release(
        &plan,
        Path::new(&out),
        log_arg.as_deref().map(Path::new),
        now_ms,
    ) {
        Ok(r) => {
            render_released(&r, as_json);
            0
        }
        Err(DraftError::Denied(v)) => {
            render_verdict(&v, as_json);
            1
        }
        // A CODED error is a boundary refusal and is rendered exactly like any other deny — JSON
        // included. Only a codeless error is infrastructure, and R-CLI-12 reserves the no-code exit
        // for that, so automation cannot read "the disk was full" as "the boundary refused" — and
        // equally cannot read a refusal as a disk failure. (E14b: `deny.artifact-mismatch`, the one
        // code only `release` can emit, took this path as a bare text line and never reached JSON.)
        Err(other) => {
            match other.verdict() {
                Some(v) => render_verdict(&v, as_json),
                None => eprintln!("sluice: {other}"),
            }
            1
        }
    }
}

fn render_released(r: &Released, as_json: bool) {
    if as_json || !std::io::stdout().is_terminal() {
        match serde_json::to_string_pretty(r) {
            Ok(s) => println!("{s}"),
            Err(e) => eprintln!("sluice: cannot encode the release record: {e}"),
        }
        return;
    }
    println!("{}  wrote {}", r.decision.as_str(), r.derivative_path);
    println!("  marking            {}", r.marking);
    println!("  derivative sha256  {}", r.derivative_sha256);
    println!("  receipt            {}", r.receipt_hash);
    println!("  chained onto       {}", r.prev_hash);
    match (r.kt_seq, &r.kt_entry_hash) {
        (Some(seq), Some(h)) => println!("  kt log entry       seq {seq}  {h}"),
        _ => println!(
            "  kt log             none — no --kt-log, so the receipt is reported and not recorded"
        ),
    }
    // R-CLI-9's second clause, rendered where an operator will actually see it:
    // a reproducible receipt says so.
    match (r.receipt_timestamp, r.receipt_clock) {
        (Some(ts), Some(clock)) => println!(
            "  receipt time       {ts}  ({})",
            match clock {
                ClockSource::Supplied => "supplied via --now-ms, so this receipt is reproducible",
                ClockSource::System =>
                    "read from the system clock, so this receipt is unique to this run",
            }
        ),
        _ => println!("  receipt time       none — no receipt was written"),
    }
}

/// `verify` trusts nothing from the writing process: it re-reads the log and,
/// given a plan, recomputes the payload.
fn run_verify(rest: &[String]) -> i32 {
    let (mut log_arg, mut plan_arg, mut deriv_arg, mut tip_arg) = (None, None, None, None);
    let mut close_arg: Option<String> = None;
    let mut as_json = false;
    let mut i = 0;
    while i < rest.len() {
        match rest[i].as_str() {
            "--kt-log" => match rest.get(i + 1) {
                Some(v) => {
                    log_arg = Some(v.clone());
                    i += 1;
                }
                None => {
                    eprintln!("sluice: --kt-log needs a value");
                    return 1;
                }
            },
            "--plan" => match rest.get(i + 1) {
                Some(v) => {
                    plan_arg = Some(v.clone());
                    i += 1;
                }
                None => {
                    eprintln!("sluice: --plan needs a value");
                    return 1;
                }
            },
            "--derivative" => match rest.get(i + 1) {
                Some(v) => {
                    deriv_arg = Some(v.clone());
                    i += 1;
                }
                None => {
                    eprintln!("sluice: --derivative needs a value");
                    return 1;
                }
            },
            "--segment-close" => match rest.get(i + 1) {
                Some(v) => {
                    close_arg = Some(v.clone());
                    i += 1;
                }
                None => {
                    eprintln!(
                        "sluice: --segment-close needs the payload `rotate` printed (or @file)"
                    );
                    return 1;
                }
            },
            "--expect-tip" => match rest.get(i + 1) {
                Some(v) => {
                    tip_arg = Some(v.clone());
                    i += 1;
                }
                None => {
                    eprintln!("sluice: --expect-tip needs a value (a 64-character hex hash)");
                    return 1;
                }
            },
            "--json" => as_json = true,
            other => {
                eprintln!("sluice: unknown argument {other:?}\n\n{USAGE}");
                return 1;
            }
        }
        i += 1;
    }

    let Some(log) = log_arg else {
        eprintln!("sluice: --kt-log <FILE> is required\n\n{USAGE}");
        return 1;
    };
    if deriv_arg.is_some() && plan_arg.is_none() {
        eprintln!(
            "sluice: --derivative needs --plan — there is nothing to compare the file against"
        );
        return 1;
    }

    let plan = match plan_arg.as_deref() {
        None => None,
        Some(src) => match read_source(src) {
            Ok(t) => match parse_plan(&t) {
                Ok(p) => Some(p),
                Err(v) => {
                    render_verdict(&v, as_json);
                    return 1;
                }
            },
            Err(e) => {
                eprintln!("sluice: {e}");
                return 1;
            }
        },
    };

    let deriv = deriv_arg.as_deref().map(PathBuf::from);
    match verify(
        Path::new(&log),
        plan.as_ref(),
        deriv.as_deref(),
        tip_arg.as_deref(),
    ) {
        Ok(v) => {
            // The exit status must cover **every** check this command reports.
            // Reporting "the derivative does not match" and exiting 0 would
            // teach automation to ignore the report — so a mismatch in the
            // derivative fails the command just as a missing chain entry does.
            let ok = (v.matched_seq.is_some() || plan.is_none())
                && v.derivative_matches_plan != Some(false);
            // [R4] The record is required input: the log stores only the payload's hash, so a closing
            // entry can be checked only against the bytes the operator kept. A refusal here is an
            // exit 1, never a report — the same rule the chain itself follows.
            if let Some(raw) = close_arg.as_deref() {
                let payload = match raw.strip_prefix('@') {
                    Some(path) => match std::fs::read_to_string(path) {
                        Ok(text) => text,
                        Err(e) => {
                            eprintln!("sluice: cannot read {path}: {e}");
                            return 1;
                        }
                    },
                    None => raw.to_string(),
                };
                match crate::sluice::verify_segment_close(
                    std::path::Path::new(&log),
                    &payload,
                    plan.as_ref().and_then(|p| p.continues.as_deref()),
                ) {
                    Ok(c) => {
                        if as_json || !std::io::stdout().is_terminal() {
                            match serde_json::to_string_pretty(&c) {
                                Ok(s) => println!("{s}"),
                                Err(e) => eprintln!("sluice: cannot encode the check: {e}"),
                            }
                        } else {
                            println!(
                                "  closing entry verified: segment {} closed at {} receipt(s), tip {}",
                                c.segment, c.entries, c.last_receipt_hash
                            );
                        }
                    }
                    Err(e) => {
                        eprintln!("sluice: {e}");
                        return 1;
                    }
                }
            }
            render_verified(&v, as_json, plan.is_some());
            if ok { 0 } else { 1 }
        }
        Err(e) => {
            eprintln!("sluice: {e}");
            1
        }
    }
}

fn run_rotate(rest: &[String]) -> i32 {
    let (mut log_arg, mut tip_arg, mut seg_arg, mut prev_arg) = (None, None, None, None);
    let mut reason = String::from("manual");
    let mut as_json = false;
    let mut i = 0;
    while i < rest.len() {
        match rest[i].as_str() {
            "--kt-log" => match rest.get(i + 1) {
                Some(v) => {
                    log_arg = Some(v.clone());
                    i += 1;
                }
                None => {
                    eprintln!("sluice: --kt-log needs a value");
                    return 1;
                }
            },
            "--expect-tip" => match rest.get(i + 1) {
                Some(v) => {
                    tip_arg = Some(v.clone());
                    i += 1;
                }
                None => {
                    eprintln!("sluice: --expect-tip needs a value");
                    return 1;
                }
            },
            "--segment" => match rest.get(i + 1) {
                Some(v) => {
                    seg_arg = Some(v.clone());
                    i += 1;
                }
                None => {
                    eprintln!("sluice: --segment needs a value");
                    return 1;
                }
            },
            "--prev-segment-close" => match rest.get(i + 1) {
                Some(v) => {
                    prev_arg = Some(v.clone());
                    i += 1;
                }
                None => {
                    eprintln!("sluice: --prev-segment-close needs a value");
                    return 1;
                }
            },
            "--reason" => match rest.get(i + 1) {
                Some(v) => {
                    reason = v.clone();
                    i += 1;
                }
                None => {
                    eprintln!("sluice: --reason needs a value");
                    return 1;
                }
            },
            "--json" => as_json = true,
            other => {
                eprintln!("sluice: unknown argument {other:?}");
                return 1;
            }
        }
        i += 1;
    }
    let (Some(log), Some(tip), Some(seg)) = (log_arg, tip_arg, seg_arg) else {
        eprintln!("sluice rotate: --kt-log, --expect-tip and --segment are all required");
        return 1;
    };
    let segment: u64 = match seg.parse() {
        Ok(n) => n,
        Err(_) => {
            eprintln!("sluice rotate: --segment must be a number, got {seg:?}");
            return 1;
        }
    };
    match crate::sluice::rotate(
        std::path::Path::new(&log),
        Some(&tip),
        &reason,
        segment,
        prev_arg.as_deref(),
    ) {
        Ok(r) => {
            render_rotated(&r, as_json);
            0
        }
        Err(e) => {
            eprintln!("sluice: {e}");
            1
        }
    }
}

fn render_rotated(r: &crate::sluice::Rotated, as_json: bool) {
    if as_json || !std::io::stdout().is_terminal() {
        match serde_json::to_string_pretty(r) {
            Ok(s) => println!("{s}"),
            Err(e) => eprintln!("sluice: cannot encode the rotation: {e}"),
        }
        return;
    }
    println!(
        "segment {segment} closed at {entries} receipt(s)",
        segment = r.segment,
        entries = r.entries
    );
    println!("  last receipt   {}", r.last_receipt_hash);
    println!("  closing entry  {}", r.close_entry_hash);
    // The payload is printed because the record must carry it VERBATIM: [R4] the log stores only its hash.
    println!("  record this payload verbatim:");
    println!("  {}", r.close_payload);
}

fn render_verified(v: &Verified, as_json: bool, had_plan: bool) {
    if as_json || !std::io::stdout().is_terminal() {
        match serde_json::to_string_pretty(v) {
            Ok(s) => println!("{s}"),
            Err(e) => eprintln!("sluice: cannot encode the verification: {e}"),
        }
        return;
    }
    println!(
        "the receipt chain verifies: {} entr{}",
        v.entries,
        if v.entries == 1 { "y" } else { "ies" }
    );
    println!("  tip                {}", v.tip_hash);
    if let Some(a) = &v.tip_anchor {
        println!("  anchor             {a}  (matches the head, checked against an outside value)");
    }
    if had_plan {
        match (
            v.matched_seq,
            &v.matched_entry_hash,
            &v.recomputed_receipt_hash,
        ) {
            (Some(seq), Some(h), Some(r)) => {
                println!("  plan matched       seq {seq}  {h}");
                println!("  receipt            {r}");
            }
            _ => println!(
                "  plan matched       NO — no entry in this log commits to this plan's payload"
            ),
        }
    }
    if let Some(d) = &v.derivative_sha256 {
        println!("  derivative sha256  {d}");
        match v.derivative_matches_plan {
            Some(true) => println!("  derivative         matches the plan's sha256"),
            Some(false) => println!("  derivative         DOES NOT match the plan's sha256"),
            None => {}
        }
    }
}
